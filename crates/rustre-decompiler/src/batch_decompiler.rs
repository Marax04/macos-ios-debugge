//! `batch_decompiler.rs` — Batch decompilation of many functions.
//!
//! Features:
//! - Function prioritisation: entry points, exports, high call-count first
//! - Parallelism with Rayon
//! - Progress reporting (channel-based)
//! - Output aggregation into a `BatchResult`
//! - Per-function failure recovery

use crate::{
    DecompiledFunction, DecompilerDiagnostic, DecompilerError,
    DecompilerPipeline, DecompOptions, DecompStats, DiagnosticSeverity,
    FunctionNameGenerator,
    binary_entry::{detect_functions_in_load, load_binary},
};
use rayon::prelude::*;
use rustre_core::arch::Instruction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Instant;

// ─────────────────────────────────────────────────────────────────────────────
// FunctionPriority — prioritisation metadata
// ─────────────────────────────────────────────────────────────────────────────

/// Priority category for scheduling batch decompilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FunctionPriority {
    /// Entry point (main, `DllMain`, `WinMain`, …).
    EntryPoint = 100,
    /// Exported symbol.
    Export = 80,
    /// Called frequently (high in-degree in call graph).
    HighCallCount = 60,
    /// Referenced from data (e.g., vtable, function pointer).
    DataReferenced = 40,
    /// Normal function.
    Normal = 20,
    /// Dead code / unreachable.
    LowPriority = 0,
}

impl FunctionPriority {
    #[must_use] 
    pub const fn score(self) -> u32 {
        self as u32
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchFunction — input descriptor for one function
// ─────────────────────────────────────────────────────────────────────────────

/// Descriptor for a single function to be decompiled in a batch.
#[derive(Debug, Clone)]
pub struct BatchFunction {
    /// Start address of the function.
    pub address: u64,
    /// Optional symbolic name.
    pub name: Option<String>,
    /// Instructions to decompile.
    pub instructions: Vec<Instruction>,
    /// Priority (affects scheduling order).
    pub priority: FunctionPriority,
    /// How many times this function is called (used for ordering).
    pub call_count: u32,
    /// Whether this is an entry point.
    pub is_entry: bool,
    /// Whether this is an export.
    pub is_export: bool,
}

impl BatchFunction {
    #[must_use] 
    pub const fn new(address: u64, instructions: Vec<Instruction>) -> Self {
        Self {
            address,
            name: None,
            instructions,
            priority: FunctionPriority::Normal,
            call_count: 0,
            is_entry: false,
            is_export: false,
        }
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use] 
    pub const fn with_priority(mut self, p: FunctionPriority) -> Self {
        self.priority = p;
        self
    }

    #[must_use] 
    pub const fn entry_point(mut self) -> Self {
        self.is_entry = true;
        self.priority = FunctionPriority::EntryPoint;
        self
    }

    #[must_use] 
    pub fn export(mut self) -> Self {
        self.is_export = true;
        if self.priority < FunctionPriority::Export {
            self.priority = FunctionPriority::Export;
        }
        self
    }

    #[must_use] 
    pub fn with_call_count(mut self, count: u32) -> Self {
        self.call_count = count;
        if count >= 50 && self.priority < FunctionPriority::HighCallCount {
            self.priority = FunctionPriority::HighCallCount;
        }
        self
    }

    /// Compute a composite sort key (higher = decompile first).
    #[must_use] 
    pub fn sort_key(&self) -> u64 {
        u64::from(self.priority.score()) * 1_000_000 + u64::from(self.call_count)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProgressEvent — progress reporting
// ─────────────────────────────────────────────────────────────────────────────

/// A progress event emitted during batch decompilation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProgressEvent {
    /// Batch started.
    Started { total: usize },
    /// A function decompilation succeeded.
    FunctionDone {
        address: u64,
        name: String,
        elapsed_ms: u64,
    },
    /// A function decompilation failed.
    FunctionFailed {
        address: u64,
        error: String,
    },
    /// Batch completed.
    Completed {
        succeeded: usize,
        failed: usize,
        total_ms: u64,
    },
}

/// A channel for receiving progress events.
pub type ProgressReceiver = Receiver<ProgressEvent>;

// ─────────────────────────────────────────────────────────────────────────────
// FailurePolicy — how to handle per-function failures
// ─────────────────────────────────────────────────────────────────────────────

/// What to do when a single function fails to decompile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailurePolicy {
    /// Skip the failed function and continue with the rest.
    Skip,
    /// Emit a stub (placeholder pseudo-code) and continue.
    EmitStub,
    /// Abort the entire batch immediately.
    AbortBatch,
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchConfig — configuration for the batch decompiler
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for `BatchDecompiler`.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Number of Rayon threads (0 = use default thread pool).
    pub threads: usize,
    /// Per-function decompiler options.
    pub decompiler_opts: DecompOptions,
    /// What to do on per-function failure.
    pub failure_policy: FailurePolicy,
    /// Maximum functions to decompile (0 = unlimited).
    pub max_functions: usize,
    /// Whether to send progress events.
    pub enable_progress: bool,
    /// Minimum priority for a function to be included.
    pub min_priority: FunctionPriority,
    /// Phase 1 whole-project reconstruction: also emit per-source-file
    /// `<bucket>.c`/`<bucket>.h` files alongside the (always-written)
    /// per-function `sub_<addr>.c` files. Gated by `RUSTRE_BUCKET_BY_SOURCE`
    /// at the driver level (see `source_bucketing.rs`); default `false`
    /// leaves output byte-identical to before this field existed.
    pub bucket_by_source: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            threads: 0,
            decompiler_opts: DecompOptions::default(),
            failure_policy: FailurePolicy::Skip,
            max_functions: 0,
            enable_progress: false,
            min_priority: FunctionPriority::LowPriority,
            bucket_by_source: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchResult — aggregated output of a batch run
// ─────────────────────────────────────────────────────────────────────────────

/// The combined result of batch decompilation.
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct BatchResult {
    /// All successfully decompiled functions.
    pub functions: Vec<DecompiledFunction>,
    /// All diagnostics collected (including per-function errors).
    pub diagnostics: Vec<DecompilerDiagnostic>,
    /// Summary statistics.
    pub stats: DecompStats,
    /// Total wall-clock time in milliseconds.
    pub elapsed_ms: u64,
    /// Functions that could not be decompiled, keyed by address.
    pub failures: HashMap<u64, String>,
}

impl BatchResult {
    /// Number of successfully decompiled functions.
    #[must_use] 
    pub const fn success_count(&self) -> usize {
        self.functions.len()
    }

    /// Number of failed functions.
    #[must_use] 
    pub fn failure_count(&self) -> usize {
        self.failures.len()
    }

    /// Overall success rate (0.0 – 1.0).
    #[must_use] 
    pub fn success_rate(&self) -> f64 {
        let total = self.success_count() + self.failure_count();
        if total == 0 {
            return 1.0;
        }
        let s = f64::from(u32::try_from(self.success_count()).unwrap_or(u32::MAX));
        let t = f64::from(u32::try_from(total).unwrap_or(u32::MAX));
        s / t
    }

    /// Merge another `BatchResult` into this one.
    pub fn merge(&mut self, other: Self) {
        self.functions.extend(other.functions);
        self.diagnostics.extend(other.diagnostics);
        self.stats.functions_decompiled += other.stats.functions_decompiled;
        self.stats.functions_failed += other.stats.functions_failed;
        self.stats.total_time_ms += other.stats.total_time_ms;
        self.stats.variables_recovered += other.stats.variables_recovered;
        self.stats.call_sites_found += other.stats.call_sites_found;
        self.elapsed_ms += other.elapsed_ms;
        self.failures.extend(other.failures);
    }

    /// Return all functions sorted by address.
    #[must_use] 
    pub fn sorted_by_address(&self) -> Vec<&DecompiledFunction> {
        let mut v: Vec<&DecompiledFunction> = self.functions.iter().collect();
        v.sort_by_key(|f| f.address);
        v
    }

    /// Find a function by address.
    #[must_use] 
    pub fn function_at(&self, addr: u64) -> Option<&DecompiledFunction> {
        self.functions.iter().find(|f| f.address == addr)
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// FunctionPrioritiser — sorts functions before batch decompilation
// ─────────────────────────────────────────────────────────────────────────────

/// Sorts and filters a list of `BatchFunction`s according to priorities.
pub struct FunctionPrioritiser {
    min_priority: FunctionPriority,
}

impl FunctionPrioritiser {
    #[must_use] 
    pub const fn new(min_priority: FunctionPriority) -> Self {
        Self { min_priority }
    }

    /// Sort functions so high-priority ones come first.
    #[must_use] 
    pub fn sort(&self, mut funcs: Vec<BatchFunction>) -> Vec<BatchFunction> {
        // Filter by minimum priority.
        funcs.retain(|f| f.priority >= self.min_priority);
        // Sort descending by composite key.
        funcs.sort_by_key(|b| std::cmp::Reverse(b.sort_key()));
        funcs
    }

    /// Partition functions into entry-points, exports, and rest.
    #[must_use] 
    pub fn partition(
        funcs: &[BatchFunction],
    ) -> (Vec<&BatchFunction>, Vec<&BatchFunction>, Vec<&BatchFunction>) {
        let mut entries = Vec::new();
        let mut exports = Vec::new();
        let mut rest = Vec::new();
        for f in funcs {
            if f.is_entry {
                entries.push(f);
            } else if f.is_export {
                exports.push(f);
            } else {
                rest.push(f);
            }
        }
        (entries, exports, rest)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchDecompiler — the main batch engine
// ─────────────────────────────────────────────────────────────────────────────

/// Batch decompiler: decompiles many functions in priority order, optionally in parallel.
pub struct BatchDecompiler {
    pipeline: Arc<DecompilerPipeline>,
    config: BatchConfig,
    name_gen: Mutex<FunctionNameGenerator>,
}

impl BatchDecompiler {
    /// Create a new `BatchDecompiler` from a shared pipeline.
    #[must_use] 
    pub fn new(pipeline: Arc<DecompilerPipeline>, config: BatchConfig) -> Self {
        Self {
            pipeline,
            config,
            name_gen: Mutex::new(FunctionNameGenerator::new()),
        }
    }

    /// Run batch decompilation on the given functions.
    ///
    /// Returns a `BatchResult` and optionally a progress receiver.
    pub fn run(
        &self,
        functions: Vec<BatchFunction>,
    ) -> (BatchResult, Option<ProgressReceiver>) {
        let (tx, rx) = if self.config.enable_progress {
            let (s, r) = mpsc::channel();
            (Some(s), Some(r))
        } else {
            (None, None)
        };

        let prioritiser = FunctionPrioritiser::new(self.config.min_priority);
        let mut sorted = prioritiser.sort(functions);

        // Apply max_functions cap.
        if self.config.max_functions > 0 && sorted.len() > self.config.max_functions {
            sorted.truncate(self.config.max_functions);
        }

        let total = sorted.len();
        if let Some(ref sender) = tx {
            let _ = sender.send(ProgressEvent::Started { total });
        }

        let start = Instant::now();
        let result = self.run_parallel(sorted, tx.as_ref());
        let elapsed = start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);

        if let Some(ref sender) = tx {
            let _ = sender.send(ProgressEvent::Completed {
                succeeded: result.success_count(),
                failed: result.failure_count(),
                total_ms: elapsed,
            });
        }

        (result, rx)
    }

    /// Internal: run all functions in parallel using Rayon.
    fn run_parallel(
        &self,
        functions: Vec<BatchFunction>,
        tx: Option<&Sender<ProgressEvent>>,
    ) -> BatchResult {
        let pipeline = self.pipeline.clone();
        let _opts = self.config.decompiler_opts.clone();
        let failure_policy = self.config.failure_policy;

        // Names depend only on each function's address / symbolic name, so
        // precompute them all sequentially here (seeded from the persistent
        // `name_gen` field so its counter is carried across invocations).
        // This keeps the parallel region below free of any shared lock.
        let names: Vec<String> = {
            let mut ngen = self.name_gen.lock().clone();
            functions
                .iter()
                .map(|f| ngen.name_for(f.address, f.name.as_deref()))
                .collect()
        };

        // Parallel execution via Rayon. When `threads == 1` we fall back to
        // sequential iteration so callers can opt out of multithreading. When
        // `threads > 1` we build a local Rayon thread pool of that size and
        // install the parallel iterator inside it; `threads == 0` uses the
        // global default pool.
        let decompile_one = |(f, name): (BatchFunction, String)| -> Result<DecompiledFunction, (u64, DecompilerError)> {
            let t = Instant::now();
            let res = pipeline.run(f.address, &name, &f.instructions);
            let elapsed = t.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
            if let Some(tx) = tx {
                match &res {
                    Ok(func) => {
                        let _ = tx.send(ProgressEvent::FunctionDone {
                            address: f.address,
                            name: func.name.clone(),
                            elapsed_ms: elapsed,
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(ProgressEvent::FunctionFailed {
                            address: f.address,
                            error: e.to_string(),
                        });
                    }
                }
            }
            res.map_err(|e| (f.address, e))
        };

        let results: Vec<Result<DecompiledFunction, (u64, DecompilerError)>> = match self.config.threads.cmp(&1) {
            std::cmp::Ordering::Equal => {
                functions.into_iter().zip(names).map(&decompile_one).collect()
            }
            std::cmp::Ordering::Greater => {
                match rayon::ThreadPoolBuilder::new()
                    .num_threads(self.config.threads)
                    .build()
                {
                    Ok(pool) => pool.install(|| {
                        functions
                            .into_par_iter()
                            .zip(names.into_par_iter())
                            .map(&decompile_one)
                            .collect()
                    }),
                    Err(_) => functions
                        .into_par_iter()
                        .zip(names.into_par_iter())
                        .map(&decompile_one)
                        .collect(),
                }
            }
            std::cmp::Ordering::Less => functions
                .into_par_iter()
                .zip(names.into_par_iter())
                .map(&decompile_one)
                .collect(),
        };

        // Aggregate results.
        let mut batch = BatchResult::default();
        let mut abort = false;

        for result in results {
            if abort {
                break;
            }
            match result {
                Ok(func) => {
                    batch.stats.variables_recovered += func.variables.len() as u64;
                    batch.stats.call_sites_found += func.call_sites.len() as u64;
                    batch.stats.functions_decompiled += 1;
                    batch.functions.push(func);
                }
                Err((addr, err)) => {
                    batch.stats.functions_failed += 1;
                    let msg = err.to_string();
                    batch.failures.insert(addr, msg.clone());
                    batch.diagnostics.push(DecompilerDiagnostic {
                        severity: DiagnosticSeverity::Error,
                        address: Some(addr),
                        message: msg,
                        pass: None,
                    });

                    match failure_policy {
                        FailurePolicy::AbortBatch => {
                            abort = true;
                        }
                        FailurePolicy::EmitStub => {
                            let stub = DecompiledFunction::new(
                                addr,
                                format!("stub_{addr:#x}"),
                                format!("// DECOMPILATION FAILED: {err}"),
                            );
                            batch.functions.push(stub);
                        }
                        FailurePolicy::Skip => {}
                    }
                }
            }
        }

        batch
    }

    /// Decompile functions in chunks (useful for very large binaries to manage memory).
    pub fn run_chunked(&self, functions: &[BatchFunction], chunk_size: usize) -> BatchResult {
        let mut combined = BatchResult::default();
        let total_start = Instant::now();

        for chunk in functions.chunks(chunk_size) {
            let (chunk_result, _) = self.run(chunk.to_vec());
            combined.merge(chunk_result);
        }

        combined.elapsed_ms = total_start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        combined
    }

    /// Statistics about the configuration.
    pub fn describe(&self) -> String {
        format!(
            "BatchDecompiler {{ threads: {}, failure_policy: {:?}, max_fns: {} }}",
            if self.config.threads == 0 {
                std::thread::available_parallelism().map(std::num::NonZero::get).unwrap_or(1)
            } else {
                self.config.threads
            },
            self.config.failure_policy,
            self.config.max_functions,
        )
    }
}

/// Run the decompilation loop over a pre-filtered address list.
///
/// **Deliberately not called from production, and it must stay that way.**
/// This is the *unbounded* entry: it passes an empty `all_starts_sorted`, so
/// each function's linear sweep is capped only by the next symbol/export
/// rather than by the next known function entry. As the doc on
/// [`run_decompile_loop_bounded`] explains, that lets the sweep's
/// intra-procedural-forward-`jmp` rule walk a symbol-less thunk cluster as a
/// single function. The batch path (`:805`) therefore always passes real
/// bounds, and no call site passes `&[]`.
///
/// Kept as the unbounded reference entry; wiring it into the pipeline would be
/// a fidelity regression, not a cleanup. (A differential test against
/// `run_decompile_loop_bounded` would be vacuous — this is a one-line
/// delegation to it, not an independent algorithm.)
pub fn run_decompile_loop(
    load: &rustre_loader::RichLoadResult,
    filtered: &[u64],
    config: &BatchConfig,
) -> BatchResult {
    run_decompile_loop_bounded(load, filtered, config, &[])
}

/// Like [`run_decompile_loop`] but with the full sorted list of detected
/// function starts, so each function's linear sweep is hard-capped at the
/// next known function entry (not just the next symbol/export). Without
/// this, the sweep's intra-procedural-forward-`jmp` rule (see
/// `disassemble_function_x86_ext`) could walk a symbol-less thunk cluster
/// as one function: each stub is a detected call-target boundary, and that
/// boundary is the only evidence separating it from its neighbour.
/// Aggiunge a `load.symbols` i simboli del `.pdb` affiancato al binario.
///
/// Perche' (#5220): i nomi delle funzioni NON vengono da un `SymbolResolver` —
/// nel batch non ce n'e' nessuno — ma da `RichLoadResult.symbols`, che il loader
/// riempie coi simboli **dentro** il PE. I binari **Rust/MSVC** li tengono in un
/// `.pdb` separato, quindi restano senza nome: MISURATO, `sample3_rust` emette
/// **0 definizioni con nome vero su 213**, contro **46 su 49** di `sample6_c`.
/// Da li' le 4 funzioni classificate `NOT_EMITTED` dal misuratore di
/// comportamento (che cerca il nome di sorgente).
///
/// ⚠ **L'insidia**: nei build Rust/MSVC release il flusso dei simboli PUBBLICI
/// e' spesso **VUOTO** (`S_PUB32` ripulito). Senza il ripiego sui
/// `module_proc_symbols` il caricamento «riesce» e non produce **nulla** — un
/// NO-OP travestito. Lo stesso ripiego lo fa gia' la GUI
/// (`rustre-gui/src/analysis/engine.rs`).
///
/// Restituisce quanti simboli sono stati aggiunti (0 = nessun PDB, o PDB muto).
fn augment_symbols_from_pdb(
    load: &mut rustre_loader::RichLoadResult,
    binary_path: &std::path::Path,
) -> usize {
    let pdb_path = binary_path.with_extension("pdb");
    if !pdb_path.exists() {
        return 0;
    }
    let Ok(reader) = rustre_symbols_pdb::PdbReader::open(&pdb_path) else {
        return 0;
    };
    let noti: std::collections::HashSet<u64> = load.symbols.iter().map(|s| s.addr).collect();
    let mut nuovi: Vec<rustre_loader::SymbolInfo> = Vec::new();

    // ⚠ MISURATO (#5220): `reader.symbols()` NON e' vuoto per questi PDB, ma il
    // suo campo `address` **non e' una VA** — restituisce 0xC0, 0xC8, 0x3D08…
    // Usarlo produce 473 simboli che non combaciano con nessun inizio di
    // funzione: il caricamento «riesce» e non rinomina NULLA.
    // Serve la variante che espone `(segmento, offset)` e mappare a mano con la
    // tabella delle sezioni, esattamente come per i `module_proc_symbols`.
    let va_da_segmento = |segment: u16, offset: u32| -> Option<u64> {
        load.sections
            .get(usize::from(segment).wrapping_sub(1))
            .map(|sec| sec.virtual_addr + u64::from(offset))
    };

    // ⚠⚠ Gate #25 `RUSTRE_PDB_ONLY_EXEC` (default-ON, `=0` disabilita).
    //
    // I simboli PUBBLICI di un PDB non sono tutti codice: `__imp_GetLastError`
    // & co. sono gli SLOT IAT, cioe' DATI in `.idata`. Marcandoli
    // indiscriminatamente `"function"` li si consegna a
    // `detect_functions_in_load`, che disassembla il contenuto di un puntatore
    // come se fosse codice ed emette una funzione **inesistente**.
    // MISURATO: `sample3_rust` 60 file fantasma, `sample8_rust` 66 — **126 sul
    // corpus, e ZERO negli altri dieci bucket**, tutti con VA consecutivi a
    // passo 8 (la tabella IAT). Con `RUSTRE_PDB=0` sono **0**: e' il PDB a
    // introdurli. Compilano tutte, quindi nessuna metrica gcc le vedeva.
    //
    // ⚠ Il filtro e' costruito per NON poter fare danni se il presupposto e'
    // falso: se NESSUNA sezione dichiara il bit di esecuzione (un loader che
    // non popola `flags`), `filtro_attivo` e' false e il comportamento resta
    // quello di prima. Un filtro che scarta tutto quando non sa nulla sarebbe
    // molto peggio del difetto che ripara.
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    let filtro_attivo = gate_acceso("RUSTRE_PDB_ONLY_EXEC")
        && load
            .sections
            .iter()
            .any(|s| s.flags & IMAGE_SCN_MEM_EXECUTE != 0);
    let segmento_eseguibile = |segment: u16| -> bool {
        if !filtro_attivo {
            return true;
        }
        load.sections
            .get(usize::from(segment).wrapping_sub(1))
            .is_some_and(|sec| sec.flags & IMAGE_SCN_MEM_EXECUTE != 0)
    };

    for (segment, offset, name, _kind) in reader.symbols_with_segment() {
        if let Some(va) = va_da_segmento(segment, offset)
            && !noti.contains(&va)
            && segmento_eseguibile(segment)
        {
            nuovi.push(rustre_loader::SymbolInfo::new(name, va, "function", 0));
        }
    }

    // Ripiego SEMPRE tentato, non solo quando i pubblici mancano: nei build
    // Rust/MSVC release le funzioni del programma stanno negli `S_GPROC32` per
    // modulo, mentre il flusso pubblico porta soprattutto simboli di runtime
    // (`_fltused`, `type_info::vftable`). `segment` e' **1-based**.
    let visti: std::collections::HashSet<u64> = nuovi.iter().map(|s| s.addr).collect();
    for p in reader.module_proc_symbols() {
        // Stesso filtro del flusso pubblico: un `S_GPROC32` fuori da una
        // sezione eseguibile non e' un punto d'ingresso di codice. Lasciarlo
        // scoperto avrebbe riparato meta' del difetto e reso la misura
        // incomprensibile.
        if let Some(va) = va_da_segmento(p.segment, p.code_offset)
            && !noti.contains(&va)
            && !visti.contains(&va)
            && segmento_eseguibile(p.segment)
        {
            nuovi.push(rustre_loader::SymbolInfo::new(
                p.name,
                va,
                "function",
                u64::from(p.code_size),
            ));
        }
    }
    // Sonda: le VA calcolate vanno CONFRONTATE con gli inizi di funzione veri
    // (i file emessi si chiamano `sub_<VA>`). Se non combaciano, l'errore e'
    // nell'INDIRIZZO, non nel caricamento — e il resto sembrerebbe a posto.
    // Filtro per NOME, come `RUSTRE_DBG_HINTS`: dice se un simbolo atteso e'
    // fra quelli che il PDB ha davvero prodotto, distinguendo le due fonti.
    if let Ok(cercato) = std::env::var("RUSTRE_DBG_PDBNAME") {
        let pubblici = reader
            .symbols_with_segment()
            .into_iter()
            .filter(|(_, _, n, _)| n.contains(cercato.as_str()))
            .count();
        let moduli = reader
            .module_proc_symbols()
            .into_iter()
            .filter(|p| p.name.contains(cercato.as_str()))
            .count();
        let aggiunti: Vec<String> = nuovi
            .iter()
            .filter(|s| s.name.contains(cercato.as_str()))
            .map(|s| format!("{}@{:#x}", s.name, s.addr))
            .collect();
        eprintln!(
            "[pdbname] {cercato:?}: pubblici={pubblici} moduli={moduli} aggiunti={aggiunti:?}"
        );
    }
    if std::env::var("RUSTRE_DBG_PDB").is_ok_and(|v| v != "0") {
        for s in nuovi.iter().take(3) {
            eprintln!("[pdb] esempio: {} @ 0x{:X}", s.name, s.addr);
        }
        if let Some(sec) = load.sections.first() {
            eprintln!(
                "[pdb] sezione[0] {} virtual_addr=0x{:X} (base immagine 0x{:X})",
                sec.name, sec.virtual_addr, load.base_address
            );
        }
    }
    let n = nuovi.len();
    load.symbols.extend(nuovi);
    n
}

fn run_decompile_loop_bounded(
    load: &rustre_loader::RichLoadResult,
    filtered: &[u64],
    config: &BatchConfig,
    all_starts_sorted: &[u64],
) -> BatchResult {
    let start = Instant::now();
    let mut result = BatchResult::default();
    let pipeline_opts = config.decompiler_opts.clone();
    let failure_policy = config.failure_policy;

    // `RichLoadResult` is plain owned data (Strings / Vecs of POD structs),
    // so `&RichLoadResult` is Sync and can be shared across Rayon workers.
    // Decompile every address in parallel (honouring `config.threads`), then
    // aggregate sequentially below to preserve deterministic ordering and the
    // AbortBatch / EmitStub / Skip failure semantics.
    // Whole-image callee-arity map, computed ONCE before the parallel loop.
    // `callee_arities_for` is a whole-binary property (transitive call-graph
    // disassembly + fixpoint) that used to be recomputed per function — 85-88%
    // of decompile CPU on the large corpus binaries. Computing it up front and
    // sharing an IMMUTABLE `&ArityCache` with every Rayon worker is sound with
    // no locking at all (shared-nothing reads); a mutex-guarded incremental
    // cache would serialise the hottest path instead.
    let seeds: Vec<u64> = if all_starts_sorted.is_empty() {
        filtered.to_vec()
    } else {
        all_starts_sorted.to_vec()
    };
    // Escape hatch for A/B measurement and bisection: force the historical
    // per-function recompute.
    let no_cache = std::env::var_os("RUSTRE_NO_ARITY_CACHE").is_some();
    let cache_storage = if no_cache {
        None
    } else {
        Some(crate::binary_entry::image_callee_arities(
            load,
            &seeds,
            crate::binary_entry::x86_bits_for(load),
        ))
    };
    let arity_cache = cache_storage.as_ref();

    let decompile_one = |&addr: &u64| -> (u64, u64, Result<DecompiledFunction, DecompilerError>) {
        let t = Instant::now();
        let next_fn_start = match all_starts_sorted.binary_search(&(addr + 1)) {
            Ok(i) | Err(i) => all_starts_sorted.get(i).copied(),
        };
        let res = crate::binary_entry::decompile_function_in_load_cached(
            load,
            addr,
            pipeline_opts.clone(),
            next_fn_start,
            arity_cache,
        );
        let elapsed = t.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        (addr, elapsed, res)
    };

    let outcomes: Vec<(u64, u64, Result<DecompiledFunction, DecompilerError>)> =
        match config.threads.cmp(&1) {
            std::cmp::Ordering::Equal => filtered.iter().map(decompile_one).collect(),
            std::cmp::Ordering::Greater => {
                match rayon::ThreadPoolBuilder::new()
                    .num_threads(config.threads)
                    .build()
                {
                    Ok(pool) => {
                        pool.install(|| filtered.par_iter().map(decompile_one).collect())
                    }
                    Err(_) => filtered.par_iter().map(decompile_one).collect(),
                }
            }
            std::cmp::Ordering::Less => filtered.par_iter().map(decompile_one).collect(),
        };

    for (addr, elapsed, res) in outcomes {
        match res {
            Ok(func) => {
                result.stats.variables_recovered += func.variables.len() as u64;
                result.stats.call_sites_found += func.call_sites.len() as u64;
                result.stats.functions_decompiled += 1;
                result.stats.total_time_ms += elapsed;
                result.functions.push(func);
            }
            Err(e) => {
                result.stats.functions_failed += 1;
                let msg = e.to_string();
                result.failures.insert(addr, msg.clone());
                result.diagnostics.push(DecompilerDiagnostic {
                    severity: DiagnosticSeverity::Error,
                    address: Some(addr),
                    message: msg.clone(),
                    pass: None,
                });
                match failure_policy {
                    FailurePolicy::AbortBatch => break,
                    FailurePolicy::EmitStub => {
                        result.functions.push(DecompiledFunction::new(
                            addr,
                            format!("stub_{addr:#x}"),
                            format!("// DECOMPILATION FAILED: {msg}"),
                        ));
                    }
                    FailurePolicy::Skip => {}
                }
            }
        }
    }
    result.elapsed_ms = start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    result
}

/// Gate `RUSTRE_FNPTR_TABLE`, **opt-in**: materializza gli array di puntatori
/// a funzione.
///
/// Con `RUSTRE_HLIL_ADDROF` un oggetto `.rdata` viene definito coi BYTE
/// dell'immagine originale:
/// ```text
/// static uint8_t off_140004000[64] = { 0x50, 0x14, 0x00, 0x40, 0x01, ... };
/// ```
/// Le celle da 8 byte contengono `0x140001450, 0x140001460, ...` = indirizzi
/// del binario ORIGINALE. Il file LINKA e poi salta nel vuoto: si guadagna il
/// link e si perde l'esecuzione. Qui ogni cella che e' l'entry point ESATTO di
/// una funzione emessa diventa il suo NOME.
///
/// ⚠ Tre vincoli trovati LEGGENDO il codice, non ipotizzati:
/// 1. La decisione e' **per cella**: in `off_140004000` solo 4 celle su 8 sono
///    puntatori (le altre valgono 1,2,3,4). Una guardia «tutte le voci sono
///    entry point» rifiuterebbe proprio il caso da risolvere.
/// 2. Il nome NON e' `sub_X`: con `PDB` la funzione ha il nome vero (`add_fn`),
///    quindi serve la mappa indirizzo→nome EMESSO o il LINK_FAIL si sposta
///    invece di chiudersi.
/// 3. Non si puo' fare in `prepend_hlil_externs`, che gira per SINGOLA
///    funzione quando gli altri nomi non esistono ancora — solo qui, dove
///    `BatchResult` ha tutte le funzioni.
///
/// Il TIPO passa da `uint8_t[64]` a `uint64_t[8]`: gli usi restano validi
/// perche' accedono via `(__int64)&off_X + i*8`, cioe' l'indirizzo della base.
fn materialize_fnptr_tables(
    code: &str,
    names: &HashMap<u64, String>,
    enabled: bool,
) -> String {
    if !enabled || !code.contains("static uint8_t off_") {
        return code.to_string();
    }
    let mut out = String::with_capacity(code.len());
    for line in code.lines() {
        if let Some(nuova) = riscrivi_riga_fnptr(line, names) {
            out.push_str(&nuova);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// Riscrive UNA riga `static uint8_t off_X[N] = { ... };`, o `None` se la riga
/// non e' di quella forma o se nessuna cella e' una funzione emessa.
fn riscrivi_riga_fnptr(line: &str, names: &HashMap<u64, String>) -> Option<String> {
    let t = line.trim_start();
    let resto = t.strip_prefix("static uint8_t ")?;
    let (nome, resto) = resto.split_once('[')?;
    let (_len, resto) = resto.split_once("] = {")?;
    let corpo = resto.strip_suffix("};")?.trim();
    let mut byte: Vec<u8> = Vec::new();
    for tok in corpo.split(',') {
        let tok = tok.trim();
        let hex = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X"))?;
        byte.push(u8::from_str_radix(hex, 16).ok()?);
    }
    // Solo array di celle intere da 8 byte: una coda parziale non e' una cella.
    if byte.is_empty() || byte.len() % 8 != 0 {
        return None;
    }
    let mut celle: Vec<String> = Vec::new();
    let mut usate: Vec<&str> = Vec::new();
    let mut almeno_una = false;
    for chunk in byte.chunks(8) {
        let mut v = 0u64;
        for (i, b) in chunk.iter().enumerate() {
            v |= (*b as u64) << (8 * i);
        }
        // ⚠ #5990, REGRESSIONE MISURATA su sample7_cpp (gcc 7 -> 9): un nome
        // che inizia con `_` e' RISERVATO ALL'IMPLEMENTAZIONE (C99 7.1.3), e
        // spesso e' gia' dichiarato dagli header che il prelude tira dentro
        // (`__p__fmode` arriva da emmintrin.h -> mm_malloc.h). Dichiararlo noi
        // e' «conflicting types». Per quelle celle si lascia il numero: si
        // rinuncia al puntatore dove non e' sicuro, invece di rinunciare al
        // gate dove vale 72->12 e 77->11.
        let riservato = names.get(&v).is_some_and(|n| n.starts_with('_'));
        match names.get(&v).filter(|_| !riservato) {
            Some(fname) => {
                almeno_una = true;
                if !usate.contains(&fname.as_str()) {
                    usate.push(fname.as_str());
                }
                celle.push(format!("(uint64_t){fname}"));
            }
            None => celle.push(format!("0x{v:X}ULL")),
        }
    }
    if !almeno_una {
        return None;
    }
    // Le funzioni puntate NON sono chiamate da questo file, quindi non hanno
    // gia' una dichiarazione anticipata: va emessa qui o `gcc` non compila.
    let mut s = String::new();
    for f in &usate {
        s.push_str(&format!("extern __int64 {f}();\n"));
    }
    s.push_str(&format!(
        "static uint64_t {nome}[{}] = {{ {} }};",
        celle.len(),
        celle.join(", ")
    ));
    Some(s)
}

/// Gate `RUSTRE_NO_SELF_EXTERN`, **opt-in**: toglie `extern __int64 X;` quando
/// lo stesso file DEFINISCE `X` come funzione.
///
/// `extern __int64 X;` + `void X(...)` nello stesso file e' «`X` redeclared as
/// different kind of symbol» — dato contro funzione. Misurato su
/// `sample3_rust`: **60 dei 72 file in errore (83%)**.
///
/// ⚠ Il difetto e' LATENTE, non causato da `RUSTRE_PDB`: senza nomi veri la
/// dichiarazione e' `extern __int64 off_140015018;` e la definizione
/// `sub_140015018`, e non collidono. E' la **rinomina per indirizzo** di `PDB`
/// a portarle entrambe a `__imp_GetLastError` e a far emergere la collisione.
/// Per questo la riparazione va QUI, DOPO la rinomina — filtrare a monte in
/// `emit_callee_forward_decls` e' un no-op MISURATO (72 file prima e dopo).
fn drop_self_externs(code: &str, enabled: bool) -> String {
    if !enabled || !code.contains("extern __int64 ") {
        return code.to_string();
    }
    // I nomi DEFINITI come funzione in questo file: riga a livello 0 che
    // termina con `)` o `) {` e non e' una keyword di controllo.
    let mut definiti: Vec<&str> = Vec::new();
    for line in code.lines() {
        if line.starts_with(' ') || line.starts_with('\t') || line.starts_with('#') {
            continue;
        }
        let Some(par) = line.find('(') else { continue };
        let testa = &line[..par];
        let Some(nome) = testa.split(|c: char| !(c.is_alphanumeric() || c == '_')).last() else {
            continue;
        };
        if nome.is_empty() || matches!(nome, "if" | "while" | "for" | "switch" | "return") {
            continue;
        }
        // Una DEFINIZIONE, non una dichiarazione: la dichiarazione finisce `;`.
        let coda = line.trim_end();
        if coda.ends_with(';') {
            continue;
        }
        if !definiti.contains(&nome) {
            definiti.push(nome);
        }
    }
    if definiti.is_empty() {
        return code.to_string();
    }
    let mut out = String::with_capacity(code.len());
    for line in code.lines() {
        let togli = line
            .strip_prefix("extern __int64 ")
            .and_then(|r| r.strip_suffix(';'))
            .is_some_and(|n| definiti.contains(&n.trim()));
        if togli {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Gate `RUSTRE_DECL_RENAMED`, **opt-in**: dichiara i nomi che la rinomina di
/// `RUSTRE_PDB` introduce e che nessuno dichiara.
///
/// Con `PDB` il thunk di import diventa `HeapFree`/`GetLastError`/…, ma il
/// simbolo e' usato come INDIRIZZO (`*(__int64 *)HeapFree`) e non ha ne'
/// dichiarazione ne' definizione ⇒ «`HeapFree` undeclared». Sono **7 dei 12
/// errori residui** di `sample3_rust`.
///
/// ⚠ La forma cercata e' STRETTA di proposito — `*(__int64 *)NAME` e
/// `(__int64)NAME` — non «ogni identificatore sconosciuto»: una sonda larga
/// dichiarerebbe anche le variabili locali e i tipi, ed e' l'errore che in
/// questa sessione si e' gia' ripetuto quattro volte
/// (`rustre-sonda-rel32-troppo-larga`).
fn declare_renamed_imports(code: &str, enabled: bool) -> String {
    if !enabled {
        return code.to_string();
    }
    let mut candidati: Vec<String> = Vec::new();
    for pat in ["*(__int64 *)", "(__int64)"] {
        let mut i = 0usize;
        while let Some(rel) = code[i..].find(pat) {
            let at = i + rel + pat.len();
            i = at;
            // ⛔ #6000 REVOCATO E MISURATO: attraversare la `&` di
            // `(__int64)&NAME` per prendere anche i 4 bersagli rimasti ha
            // fatto **esplodere** gli errori — sample3_rust 9->28,
            // sample8_rust 11->27, sample7_cpp 7->**91**. Motivo: `&` precede
            // quasi sempre una VARIABILE LOCALE (`(__int64)&v3`), e
            // dichiararla `extern` collide con la locale stessa.
            // ⇒ QUINTA sonda troppo larga della sessione. NON riprovare senza
            // una guardia che distingua i locali (`v\d+`, `var_*`, `a\d+`).
            let resto = &code[at..];
            let fine = resto
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(resto.len());
            if fine == 0 {
                continue;
            }
            let nome = &resto[..fine];
            // Un identificatore, non un numero: `(__int64)0x15619C28B` no.
            if nome.starts_with(|c: char| c.is_ascii_digit()) {
                continue;
            }
            // ⚠ #5990: un nome che inizia con `_` e' RISERVATO
            // all'implementazione (C99 7.1.3) e spesso e' gia' dichiarato dagli
            // header del prelude ⇒ dichiararlo noi e' `conflicting types`. E'
            // la regressione gia' pagata su sample7_cpp con
            // `materialize_fnptr_tables`: qui la guardia c'e' PRIMA di
            // misurare, non dopo. I bersagli veri (`HeapFree`, `GetLastError`,
            // `SetLastError`, `HeapAlloc`) non iniziano con `_`.
            if nome.starts_with('_') {
                continue;
            }
            // Gia' noto al file? Allora non manca nulla.
            if code.contains(&format!("extern __int64 {nome};"))
                || code.contains(&format!("__int64 {nome}("))
                || code.contains(&format!("void {nome}("))
                || code.contains(&format!("{nome} ="))
                || code.contains(&format!("{nome};\n"))
            {
                continue;
            }
            if !candidati.iter().any(|c| c == nome) {
                candidati.push(nome.to_string());
            }
        }
    }
    if candidati.is_empty() {
        return code.to_string();
    }
    let mut out = String::with_capacity(code.len() + candidati.len() * 32);
    for n in &candidati {
        out.push_str(&format!("extern __int64 {n};\n"));
    }
    out.push_str(code);
    out
}

/// Gate `RUSTRE_SIMD_BODIES`, **opt-in**: definisce gli intrinseci SIMD che il
/// file CHIAMA ma nessuno definisce.
///
/// ⚠ Ha senso SOLO con `RUSTRE_SIMD_MNEMONIC`: senza, il nome e' la FAMIGLIA
/// (`cvt` copre sedici conversioni con semantiche anche opposte) e un corpo
/// unico sarebbe **confidently wrong** [[rustre-intrinseci-collassati]].
///
/// Le semantiche, dalle forme MISURATE nell'emesso:
/// - `cvtsi2sd(xmm, i)` → bit del `double` ottenuto dall'intero;
/// - `cvttsd2si(r, xmm)` → intero TRONCATO dai bit del `double`;
/// - `movhps(xmm, m)` → scrive la meta' ALTA di xmm. ⚠ Il modello rappresenta
///   xmm coi 64 bit BASSI, quindi per il valore modellato l'istruzione e'
///   **inerte**: `return dst`, NON `return m`. Restituire `m` sarebbe il
///   classico guadagno che fa linkare e sbaglia i numeri.
fn define_simd_bodies(code: &str, enabled: bool) -> String {
    if !enabled {
        return code.to_string();
    }
    let mut corpi = String::new();
    // Si definisce solo cio' che il file USA e nessuno DEFINISCE.
    let usa = |n: &str| code.contains(&format!("{n}(")) && !code.contains(&format!("static uint64_t {n}("))
        && !code.contains(&format!("static uint32_t {n}("));
    if usa("cvtsi2sd") {
        corpi.push_str(
            "static uint64_t cvtsi2sd(uint64_t dst, uint32_t src)\n{\n    double d = (double)(int)src;\n    uint64_t b;\n    memcpy(&b, &d, 8);\n    (void)dst;\n    return b;\n}\n",
        );
    }
    if usa("cvttsd2si") {
        corpi.push_str(
            "static uint32_t cvttsd2si(uint32_t dst, uint64_t src)\n{\n    double d;\n    memcpy(&d, &src, 8);\n    (void)dst;\n    return (uint32_t)(int)d;\n}\n",
        );
    }
    // ⚠ `punpcklqdq dst,src`: `dst.low = dst.low`, `dst.high = src.low` ⇒ per i
    // 64 bit BASSI modellati e' INERTE, come `movhps`.
    // ⛔ `punpckhqdq` NO: porta `dst.low = dst.high`, un valore che il modello
    // non traccia ⇒ definirlo `return dst` sarebbe confidently wrong. Stanno
    // nello STESSO ramo del lifter (`lift.rs:1843` e `:1847`), ma la semantica
    // e' diversa: verificata sull'ISA, non dedotta per analogia.
    if usa("punpcklqdq") {
        corpi.push_str(
            "static uint64_t punpcklqdq(uint64_t dst, uint64_t src)\n{\n    /* scrive solo la META' ALTA: inerte sui 64 bit bassi modellati */\n    (void)src;\n    return dst;\n}\n",
        );
    }
    if usa("movhps") {
        corpi.push_str(
            "static uint64_t movhps(uint64_t dst, uint64_t hi)\n{\n    /* scrive la META' ALTA: per i 64 bit bassi modellati e' inerte */\n    (void)hi;\n    return dst;\n}\n",
        );
    }
    // -- #7050: le ausiliarie NON-SIMD che il lifter emette e nessuno definisce.
    //
    // MISURATO sull'emesso di path B prima di scrivere una riga: 95 nomi
    // distinti non dichiarati, 2730 occorrenze, 577 file. `define_simd_bodies`
    // ne copriva QUATTRO. I nomi qui sotto sono i piu' frequenti fra quelli la
    // cui semantica e' rappresentabile ESATTAMENTE sul modello a 64 bit
    // scalari; gli altri sono esclusi apposta, elenco in fondo.
    //
    // Le forme sono lette dall'emesso, non dedotte:
    //   `bsf((uint32_t)v3)`      -> unaria
    //   `ucomi_cf(var_xmm0, var_xmm2)` -> binaria, e i `var_xmm*` sono
    //   dichiarati `uint64_t` e prodotti da `cvtsi2sd`, che restituisce i BIT
    //   di un `double`. Quindi il confronto va fatto su `double` via memcpy,
    //   coerente col corpo di `cvtsi2sd` qui sopra.

    // `bsf`/`bsr`: indice del bit meno/piu' significativo acceso.
    // ⚠ Con operando ZERO la ISA lascia la destinazione INVARIATA, ma il
    // lifter le ha modellate UNARIE — la destinazione non arriva fin qui e
    // nessun valore la puo' restituire. Si sceglie 0 e LO SI DICHIARA, come
    // per `repair_return_void_call`. E' l'unico punto inesatto di questo
    // blocco, e vale solo per un input che sui siti osservati e' gia' stato
    // escluso da un test precedente.
    if usa("bsf") {
        corpi.push_str(
            "static uint32_t bsf(uint32_t src)\n{\n    uint32_t i;\n    if (!src) return 0; /* ISA: dst invariata; qui non e' raggiungibile */\n    for (i = 0; i < 32; i++) if (src & (1u << i)) return i;\n    return 0;\n}\n",
        );
    }
    if usa("bsr") {
        corpi.push_str(
            "static uint32_t bsr(uint32_t src)\n{\n    int i;\n    if (!src) return 0; /* idem */\n    for (i = 31; i >= 0; i--) if (src & (1u << i)) return (uint32_t)i;\n    return 0;\n}\n",
        );
    }
    // `comi` e `ucomi` differiscono SOLO per quale NaN solleva l'eccezione
    // (segnalante contro silenziosa): il VALORE dei flag e' identico, quindi
    // condividono il corpo. Verificato sull'ISA, non per analogia col nome.
    for (nome, corpo) in [
        ("comi_cf", "a < b"),
        ("ucomi_cf", "a < b"),
        ("comi_zf", "a == b"),
        ("ucomi_zf", "a == b"),
        ("comi_pf", "!(a == a) || !(b == b)"),
        ("ucomi_pf", "!(a == a) || !(b == b)"),
    ] {
        if usa(nome) {
            corpi.push_str(&format!(
                "static uint32_t {nome}(uint64_t x, uint64_t y)\n{{\n    double a, b;\n    memcpy(&a, &x, 8);\n    memcpy(&b, &y, 8);\n    return ({corpo}) ? 1u : 0u;\n}}\n"
            ));
        }
    }
    // ⚠ CF/ZF su NaN: la ISA li mette ENTRAMBI a 1 quando il confronto e'
    // non ordinato, mentre in C `a < b` e `a == b` sono entrambi falsi. Il
    // caso e' quindi inesatto SOLO in presenza di NaN; si dichiara qui invece
    // di tacerlo, ed e' il motivo per cui `_pf` esiste come funzione a parte.

    // `mul_overflow(a, b)`: la moltiplicazione a 32 bit trabocca?
    // Forma osservata `mul_overflow((uint32_t)a1, 2)` ⇒ binaria a 32 bit.
    if usa("mul_overflow") {
        corpi.push_str(
            "static uint32_t mul_overflow(uint32_t a, uint32_t b)\n{\n    return (uint32_t)(((uint64_t)a * (uint64_t)b) >> 32) != 0;\n}\n",
        );
    }

    // ⛔ ESCLUSI DI PROPOSITO, e non per mancanza di tempo:
    // `cpuid_eax/ebx/ecx/edx` (204 occorrenze) — dipendono dalla CPU, nessun
    //   corpo e' «giusto» e uno inventato sarebbe confidently wrong;
    // `aesenc` (222), `packuswb`, `vpminuq`, `pcmpeqq` — leggono i 128 bit
    //   PIENI, che il modello a 64 bit bassi non rappresenta: e' esattamente
    //   la ragione per cui `punpckhqdq` e' escluso qui sopra;
    // `cvtsi2ss` (194) — la variante a PRECISIONE SINGOLA; il suo gemello a
    //   doppia e' definito, ma qui il valore va troncato a `float` e la forma
    //   emessa non dice se il modello lo tenga a 32 o 64 bit. Da misurare.
    // `pthread_mutex_unlock` (86) — funzione VERA: le manca una
    //   dichiarazione, non un corpo. Difetto diverso, rimedio diverso.
    if corpi.is_empty() {
        return code.to_string();
    }
    corpi + code
}

/// Gate `RUSTRE_RETURN_VOID_CALL`, **opt-in**: ripara `return free(x);`.
///
/// Nel binario e' una **tail call** (`jmp free`), ma `free` restituisce `void`
/// ⇒ `return free(x);` non compila («void value not ignored as it ought to be»)
/// e il file INTERO resta fuori dal link.
///
/// ⚠ Perche' vale la pena benche' siano **6 occorrenze in 5 file**: una di esse
/// e' nel file che definisce `emutls_destroy`, e quel file non compilando
/// lascia `emutls_destroy` esterna, che blocca `total_area` ⇒ **una casella
/// comportamentale**. E' il caso «raro per file, decisivo per comportamento»
/// [[rustre-var-rcl-non-vale]].
///
/// ⚠ Il valore restituito e' INVENTATO: dopo un `jmp free` il registro di
/// ritorno e' indefinito, quindi nessun valore specifico e' «giusto» — ma
/// `return free(x)` non e' compilabile affatto. Si sceglie 0 e lo si dichiara.
/// ⚠ STRETTO a `free` di proposito: l'elenco dei nomi `void` noti non e'
/// enumerabile, e una regola larga qui e' esattamente l'errore gia' pagato
/// cinque volte.
fn repair_return_void_call(code: &str, enabled: bool) -> String {
    if !enabled || !code.contains("return free(") {
        return code.to_string();
    }
    code.lines()
        .map(|line| {
            let t = line.trim_start();
            if let Some(resto) = t.strip_prefix("return free(")
                && let Some(arg) = resto.strip_suffix(");")
            {
                let ind = &line[..line.len() - t.len()];
                // `free` non restituisce nulla: la chiamata resta, il valore no.
                return format!("{ind}free({arg}); return 0; /* jmp free: valore di ritorno indefinito */");
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// Gate `RUSTRE_VOID_SELF_CAPTURE` (default-ON, `=0` disabilita): toglie la
/// cattura del valore di una chiamata RICORSIVA a una funzione `void`.
///
/// Misurato: `sample7_cpp/sub_140001600.hlil.c` definisce
/// `void _M_erase…clone__isra_0_(…)` e nel corpo fa
/// `v8 = <quella STESSA funzione>(a1);` ⇒ gcc «invalid use of void
/// expression». Il valore **non esiste**: la funzione non ne produce.
/// ✅ Verificato sul caso: `v8` e' riassegnata poche righe dopo e NON e' letta
/// nel mezzo, quindi togliere l'assegnamento non cambia nulla di osservabile.
///
/// ⚠⚠ Perche' questa NON e' la «regola larga sulle funzioni void» che
/// `repair_return_void_call` vieta esplicitamente (errore gia' pagato cinque
/// volte): li' servirebbe un ELENCO dei nomi `void`, che non e' enumerabile.
/// Qui il callee e' la funzione **definita nello stesso file**, e il file ne
/// dichiara la firma: la prova sta nel testo, e' **auto-verificante**. Non si
/// deduce nulla e non si consulta nessun database.
///
/// ⚠ STRETTA di proposito: solo `X = NOME(` con NOME **identico** al nome
/// definito, e solo se la definizione comincia con `void `. Una chiamata a
/// un'ALTRA funzione, o dentro una funzione non-`void`, resta intatta.
fn strip_recursive_void_capture(code: &str) -> String {
    if matches!(
        std::env::var("RUSTRE_VOID_SELF_CAPTURE").as_deref(),
        Ok("0") | Ok("false")
    ) {
        return code.to_string();
    }
    // ⚠ `is_word_char` di `lib.rs` e' PRIVATA: si ridefinisce qui invece di
    // allargarne la visibilita' — cambiare la visibilita' di una funzione di
    // un altro modulo per una passata locale e' gia' stato fatto e revocato
    // (gate #23). La semantica e' quella LETTA nel sorgente
    // (`lib.rs:2848`): alfanumerico ASCII oppure `_`.
    let parola = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    // La DEFINIZIONE: riga a colonna 0 che inizia con `void ` e non e' una
    // dichiarazione (`;`). Il nome e' l'ultimo identificatore prima di `(`.
    let mut nome: Option<&str> = None;
    for line in code.lines() {
        let Some(resto) = line.strip_prefix("void ") else { continue };
        if line.trim_end().ends_with(';') {
            continue; // dichiarazione, non definizione
        }
        let Some(open) = resto.find('(') else { continue };
        let testa = &resto[..open];
        let cand = testa.rsplit(|c: char| c == ' ' || c == '*').next().unwrap_or("");
        if !cand.is_empty() && cand.bytes().all(parola) {
            nome = Some(cand);
            break;
        }
    }
    let Some(nome) = nome else { return code.to_string() };
    let bersaglio = format!("{nome}(");
    code.lines()
        .map(|line| {
            let t = line.trim_start();
            // `X = NOME(` con X identificatore semplice.
            let Some((lhs, rhs)) = t.split_once(" = ") else { return line.to_string() };
            if !lhs.bytes().all(parola) || lhs.is_empty() || !rhs.starts_with(&bersaglio) {
                return line.to_string();
            }
            let indent = &line[..line.len() - t.len()];
            format!("{indent}{rhs}")
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// Gate `RUSTRE_TRAP_BODY`, **opt-in**: definisce `__trap__`.
///
/// `__trap__` e' un **marcatore del modello** per `ud2`/`int3`
/// (`rustre-il-hlil/src/hlil_structuring.rs:3932` avverte che NON e' una
/// variabile), ma nell'emesso finisce come `__trap__();` — una chiamata a una
/// funzione che non esiste, che tiene il file fuori dal link.
///
/// ⚠ NON e' uno stub arbitrario: `__builtin_trap()` ha **esattamente** la
/// semantica di `ud2` — non ritorna e termina il processo. Un `__trap__` inerte
/// sarebbe invece confidently wrong, perche' l'esecuzione proseguirebbe dove
/// l'originale si ferma.
fn define_trap_body(code: &str, enabled: bool) -> String {
    if !enabled || !code.contains("__trap__(") || code.contains("static void __trap__(") {
        return code.to_string();
    }
    "static void __trap__(void)\n{\n    __builtin_trap(); /* ud2/int3: non ritorna */\n}\n"
        .to_string()
        + code
}

// ⛔ #6060 REVOCATO E MISURATO: `drop_self_forward_decls` (gate
// `RUSTRE_DROP_SELF_PROTO`) toglieva la dichiarazione anticipata di un nome che
// il file stesso definisce, per riparare i `conflicting types` lasciati dalle
// rinomine. **Peggiora**: sample7_cpp gcc 3 -> 4 senza `HLIL_RESOLVE`, 7 -> 8
// con. Causa: in C una funzione DEFINITA PIU' AVANTI nel file ma CHIAMATA
// prima **richiede** la forward declaration; toglierla indiscriminatamente
// rompe quei casi. Una versione corretta dovrebbe togliere solo le
// dichiarazioni che PRECEDONO la definizione E hanno tipo DIVERSO.
// ⛔ #6070 REVOCATO E MISURATO — SECONDO tentativo sulla stessa classe.
// `drop_stale_protos` toglieva una forward declaration solo quando il file
// definisce lo stesso nome con un TIPO DI RITORNO DIVERSO (la versione
// indiscriminata, #6060, era gia' stata revocata). **Peggiora ANCH'ESSA**:
// sample7_cpp gcc 3 -> 4, e con `HLIL_RESOLVE`+`SKIP_PROTO` 7 -> 8.
// ⇒ DUE tentativi, due peggioramenti. Il mio modello di «quale riga e' una
// definizione» e' sbagliato in un punto che non ho isolato: probabilmente
// righe a colonna 0 che non sono definizioni (`} else if (…) {`, forme
// multi-riga). NON riprovare senza PRIMA verificare, su un file reale, quali
// righe la sonda classifica come definizione.
/// Write per-function `.c` files and `summary.json` to `out_dir`.
/// Gate `RUSTRE_IMP_SLOT` — rende gli slot della IAT col NOME dell'import.
///
/// Perche' esiste: `behavior.py` segnalava `off_14003B3E0`/`off_14003B408`
/// come DATA_NOT_EMITTED, bloccando `total_area`. Verificato col parsing PE:
/// non sono dati, sono **slot della IAT in `.idata`** (`CreateSemaphoreA` e
/// `GetCurrentProcess`). Materializzarne i byte sarebbe SBAGLIATO — il loader
/// ci scrive dentro l'indirizzo vero a runtime, quindi i byte del file sono un
/// segnaposto: linkerebbe e darebbe numeri sbagliati, cioe' peggio di un
/// LINK_FAIL. La forma corretta e' `__imp_<Nome>`, che il linker risolve.
///
/// ⚠ Raggio deliberatamente minimo. La stessa resa esiste gia' dentro
/// `resolve_symbols` (e funziona su path A), ma l'unico interruttore per
/// portarla su path B e' `RUSTRE_HLIL_RESOLVE`, che *insieme* agli import
/// rinomina verso il CRT e peggiora gcc 3→8. Qui si sostituisce SOLO il token
/// `off_<VA>` di un VA che e' uno slot IAT: nessun rename di funzione, nessuna
/// posizione di chiamata ⇒ la collisione col CRT e' impossibile per
/// costruzione, non per attenzione.
fn rename_import_slots(code: &str, imports: &HashMap<u64, String>, enabled: bool) -> String {
    if !enabled || imports.is_empty() || !(code.contains("off_") || code.contains("sub_")) {
        return code.to_string();
    }
    let mut out = String::with_capacity(code.len());
    let bytes = code.as_bytes();
    let mut i = 0;
    while i < code.len() {
        // Un `off_` preceduto da carattere identificatore non e' un token
        // nostro (il confine di parola vale anche qui).
        let inizio_token = i == 0 || !{
            let p = bytes[i - 1];
            p.is_ascii_alphanumeric() || p == b'_'
        };
        // ⚠ Anche `sub_`: misurato su sample7_cpp, **61 dei 77** riferimenti
        // `sub_XXXX` orfani cadono FUORI da `.text` — non sono funzioni. Fra
        // questi, `sub_14003B3D0`/`3D8`/`3E8`/`3F0` sono slot IAT di
        // `CloseHandle`/`CreateEventA`/`DeleteCriticalSection`/`DuplicateHandle`.
        // Il gate li mancava perche' cercava il token `off_`: la decisione era
        // presa sul NOME, mentre il fatto che conta e' l'INDIRIZZO. Estendere
        // al prefisso `sub_` non allarga il raggio — la guardia resta
        // l'appartenenza alla IAT, che e' un fatto del binario.
        if inizio_token && (code[i..].starts_with("off_") || code[i..].starts_with("sub_")) {
            let hex: String = code[i + 4..]
                .chars()
                .take_while(char::is_ascii_hexdigit)
                .collect();
            if !hex.is_empty()
                && let Ok(va) = u64::from_str_radix(&hex, 16)
                && let Some(nome) = imports.get(&va)
            {
                out.push_str("__imp_");
                out.push_str(nome);
                i += 4 + hex.len();
                continue;
            }
        }
        let ch = code[i..].chars().next().expect("indice valido");
        out.push(ch);
        i += ch.len_utf8();
    }
    // ⚠ MISURATO (gcc 3 -> 7): riscrivere il token dentro una FORWARD
    // DECLARATION `__int64 sub_X();` produce `__int64 __imp_Sleep();`, cioe'
    // dichiara lo slot IAT come FUNZIONE — ma `__imp_X` e' un DATO (il
    // puntatore), e gcc rifiuta: «redeclared as different kind of symbol».
    // La riga di dichiarazione va quindi resa nella forma DATO.
    out.lines()
        .map(|riga| {
            let t = riga.trim();
            // ⚠⚠ MISURATO (3rust 9 -> 10): cercare `__imp_` come SOTTOSTRINGA
            // tronca i nomi che lo CONTENGONO. `panic_unwind__imp__exception_cleanup`
            // e' una funzione Rust VERA, e `rfind` la riscriveva in
            // `extern __int64 __imp__exception_cleanup;`, inventando un simbolo
            // inesistente e perdendo il prefisso.
            // ⇒ L'identificatore deve COMINCIARE con `__imp_`, non contenerlo:
            // e' la regola del confine di parola applicata all'INIZIO del token.
            if let Some(nome) = t.strip_suffix("();") {
                let ident: String = nome
                    .chars()
                    .rev()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                if ident.starts_with("__imp_") && nome.ends_with(&ident) {
                    return format!("extern __int64 {ident};");
                }
            }
            riga.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
        + if out.ends_with('\n') { "\n" } else { "" }
}

/// Gate ACCESO di default, spegnibile con `NOME=0`.
///
/// ⚠ 2026-08-14, **decisione dell'utente**: i gate di emissione misurati
/// diventano il comportamento predefinito (file non compilabili sul corpus
/// 170 -> 34, path A byte-identico, #29 verde). Prima erano tutti opt-in.
///
/// La forma e' opt-OUT, non «sempre acceso»: `NOME=0` continua a spegnere il
/// singolo gate, quindi resta possibile misurare il braccio di controllo senza
/// ricompilare. Perdere quella possibilita' avrebbe reso non falsificabile
/// ogni misura futura.
fn gate_acceso(nome: &str) -> bool {
    !matches!(std::env::var(nome).as_deref(), Ok("0") | Ok("false"))
}

/// Nome che la funzione ha DAVVERO nel codice emesso, letto dalla sua riga di
/// firma (l'ultimo identificatore prima della `(` che apre i parametri).
///
/// Perche' serve (gate `RUSTRE_FNPTR_REALNAME`): `func.name` e il nome che
/// compare nel corpo **non coincidono sempre**. Per i metodi C++ il corpo porta
/// il qualificatore: `void shapes__Circle__area___const(uint64_t a1)` mentre
/// `func.name` e' `shapes__Circle__area`. `materialize_fnptr_tables` usa
/// `func.name`, quindi la tabella e il suo `extern` riferiscono un simbolo che
/// nessuno definisce ⇒ LINK_FAIL. Misurato: 85 definizioni col suffisso nel
/// solo `sample7_cpp`, e `shapes__Circle__area` fra i simboli mancanti di
/// `total_area`.
///
/// ⚠ Si legge il nome invece di rimuovere il suffisso: togliere `___const`
/// alla cieca fonderebbe l'overload const con quello non-const in un unico
/// identificatore — due funzioni omonime, difetto peggiore di quello curato.
fn nome_definizione(code: &str) -> Option<String> {
    for riga in code.lines() {
        // Le righe di controllo hanno la stessa forma `… (` di una firma.
        let t = riga.trim_start();
        if t.starts_with("if")
            || t.starts_with("while")
            || t.starts_with("for")
            || t.starts_with("switch")
            || t.starts_with("return")
            || t.starts_with("extern")
            || t.starts_with("static")
            || t.starts_with("//")
        {
            continue;
        }
        let Some(par) = riga.find('(') else { continue };
        if !riga.trim_end().ends_with(')') && !riga.contains(") {") && !riga.ends_with(')') {
            continue;
        }
        // ⚠ L'ultimo identificatore prima della `(`: un regex avido qui aveva
        // gia' catturato UNA lettera sola e prodotto una misura a zero.
        let prima = &riga[..par];
        let nome: String = prima
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        if nome.is_empty() || nome.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        // Una firma ha il nome preceduto da un tipo: se prima c'e' solo spazio
        // bianco la riga non e' una definizione.
        if prima[..prima.len() - nome.len()].trim().is_empty() {
            continue;
        }
        return Some(nome);
    }
    None
}

fn emit_batch_outputs(
    result: &mut BatchResult,
    binary_path: &Path,
    out_dir: &Path,
    config: &BatchConfig,
) -> Result<(), DecompilerError> {
    // Mappa indirizzo→nome EMESSO: e' l'unico punto del programma che la ha,
    // ed e' cio' che rende possibile l'array di puntatori a funzione.
    let realname = gate_acceso("RUSTRE_FNPTR_REALNAME");
    let nomi_per_va: HashMap<u64, String> = result
        .functions
        .iter()
        .map(|f| {
            // Col gate: il nome che il CORPO usa davvero, non quello che il
            // batch crede. Senza gate: comportamento di prima, invariato.
            let n = if realname {
                f.hlil_pseudo_code
                    .as_deref()
                    .and_then(nome_definizione)
                    .unwrap_or_else(|| f.name.clone())
            } else {
                f.name.clone()
            };
            (f.address, n)
        })
        .collect();
    let fnptr = gate_acceso("RUSTRE_FNPTR_TABLE");
    let noself = gate_acceso("RUSTRE_NO_SELF_EXTERN");
    let decl_ren = gate_acceso("RUSTRE_DECL_RENAMED");
    let simd_bodies = gate_acceso("RUSTRE_SIMD_BODIES");
    let ret_void = gate_acceso("RUSTRE_RETURN_VOID_CALL");
    let trap_body = gate_acceso("RUSTRE_TRAP_BODY");
    let imp_slot = gate_acceso("RUSTRE_IMP_SLOT");
    // Il binario si rilegge SOLO col gate acceso: a gate spento il costo e'
    // esattamente zero, cosi' il braccio di controllo resta quello di prima.
    let imports: HashMap<u64, String> = if imp_slot {
        crate::binary_entry::load_binary(binary_path).map_or_else(
            |_| HashMap::new(),
            |load| {
                load.imports
                    .iter()
                    .filter(|i| i.addr != 0 && !i.name.is_empty())
                    .map(|i| (i.addr, i.name.clone()))
                    .collect()
            },
        )
    } else {
        HashMap::new()
    };
    for func in &result.functions {
        let path = out_dir.join(format!("{:#x}.c", func.address).replace("0x", "sub_"));
        if let Err(e) = fs::write(&path, &func.pseudo_code) {
            result.diagnostics.push(DecompilerDiagnostic {
                severity: DiagnosticSeverity::Warning,
                address: Some(func.address),
                message: format!("write {}: {e}", path.display()),
                pass: None,
            });
        }
        // Experimental LLIL->MLIL->HLIL output (only present when
        // `DecompOptions.passes.hlil_experimental` was enabled) — written
        // as a sibling `.hlil.c` file, never overwriting the real
        // `pseudo_code` output above.
        if let Some(hlil) = &func.hlil_pseudo_code {
            let hlil_path =
                out_dir.join(format!("{:#x}.hlil.c", func.address).replace("0x", "sub_"));
            // ⚠ #28: si tocca SOLO path B. `pseudo_code` sopra e' scritto tale
            // e quale, quindi l'invarianza di path A e' strutturale, non un
            // controllo a posteriori.
            let hlil = materialize_fnptr_tables(hlil, &nomi_per_va, fnptr);
            let hlil = drop_self_externs(&hlil, noself);
            // DOPO `drop_self_externs`: quella toglie, questa aggiunge; se
            // girasse prima, l'extern appena messo verrebbe tolto.
            let hlil = declare_renamed_imports(&hlil, decl_ren);
            let hlil = define_simd_bodies(&hlil, simd_bodies);
            let hlil = repair_return_void_call(&hlil, ret_void);
            let hlil = strip_recursive_void_capture(&hlil);
            let hlil = define_trap_body(&hlil, trap_body);
            // ULTIMO fra i produttori: rinomina token che i passi precedenti
            // possono aver introdotto (`declare_renamed_imports` aggiunge
            // proprio righe `extern __int64 off_X;`), e non ne introduce di
            // nuovi da rinominare.
            let hlil = rename_import_slots(&hlil, &imports, imp_slot);
            // ⛔ REVOCATO — `RUSTRE_DROP_PROTO_DECLS`, effetto misurato ZERO.
            //
            // Avevo diagnosticato che `drop_conflicting_crt_forward_decls` non
            // girasse su path B (uno dei suoi due rami e' guardato da
            // `RUSTRE_HLIL_RESOLVE`, spento). Farlo girare qui in fondo NON ha
            // cambiato nulla: gcc 4 -> 4, `__int64 wcsnlen();` ancora presente.
            //
            // La diagnosi era SBAGLIATA. Il filtro decide correttamente di NON
            // togliere quella riga, perche' `has_published_prototype("wcsnlen")`
            // e' **falso**: il nome non e' nel database, benche' il prelude
            // `ida_defs.h` lo dichiari. ⇒ Il difetto e' nel DATABASE, non
            // nell'ordine delle passate.
            // ⚠ Avevo creduto il contrario perche' avevo visto la stringa
            // `"wcsnlen"` a `lib.rs:7425` e dedotto la funzione che la
            // conteneva — che e' `clamp_known_api_call_arity`, NON
            // `has_published_prototype`.
            if let Err(e) = fs::write(&hlil_path, &hlil) {
                result.diagnostics.push(DecompilerDiagnostic {
                    severity: DiagnosticSeverity::Warning,
                    address: Some(func.address),
                    message: format!("write {}: {e}", hlil_path.display()),
                    pass: None,
                });
            }
        }
    }
    // Reconstruction layer: what this binary is made of. Read from the image
    // bytes so it works on stripped binaries. Emitted as a nested object with
    // its own evidence — `language: null` means "no rule matched", never a
    // default guess (see `reconstruction::toolchain`).
    let toolchain = fs::read(binary_path)
        .ok()
        .map(|bytes| crate::reconstruction::toolchain::detect(&bytes));
    let summary = serde_json::json!({
        "binary_path": binary_path.display().to_string(),
        "out_dir": out_dir.display().to_string(),
        "toolchain": toolchain.as_ref().map(|t| serde_json::json!({
            "language": t.language.map(|l| l.id()),
            "toolchain": t.toolchain.map(|c| c.id()),
            "version": t.version.clone(),
            "markers": t.markers.iter().copied().collect::<Vec<_>>(),
            "explain": t.explain(),
        })),
        "functions_decompiled": result.stats.functions_decompiled,
        "functions_failed": result.stats.functions_failed,
        "elapsed_ms": result.elapsed_ms,
        "files": result.functions.iter().map(|f| serde_json::json!({
            "address": f.address, "name": f.name,
            "lines": f.line_count(), "confidence": f.confidence,
            // The score never travels without its reasons. `null` means the
            // number came from a placeholder path, NOT that nothing fired.
            "confidence_explain": f.confidence_explain,
            "confidence_silent_wrongness": f.confidence_silent_wrongness,
        })).collect::<Vec<_>>(),
        "failures": result.failures.iter().map(|(a, m)| {
            serde_json::json!({ "address": a, "error": m })
        }).collect::<Vec<_>>(),
    });
    let summary_path = out_dir.join("summary.json");
    if let Err(e) = fs::write(
        &summary_path,
        serde_json::to_vec_pretty(&summary)
            .map_err(|e| DecompilerError::Other(format!("serialize summary: {e}")))?,
    ) {
        result.diagnostics.push(DecompilerDiagnostic {
            severity: DiagnosticSeverity::Warning,
            address: None,
            message: format!("write summary {}: {e}", summary_path.display()),
            pass: None,
        });
    }

    // Phase 1 whole-project reconstruction, opt-in and strictly additive: the
    // per-function `sub_<addr>.c` files above are always written unchanged.
    // No DWARF/PDB resolver is wired into `BatchDecompiler` yet (see
    // `source_bucketing.rs` doc comment), so this only exercises the
    // call-graph fallback clustering today.
    if config.bucket_by_source {
        let vas: Vec<u64> = result.functions.iter().map(|f| f.address).collect();
        let plan = crate::source_bucketing::plan_buckets(&vas, None, None, None);
        let func_names: HashMap<u64, String> =
            result.functions.iter().map(|f| (f.address, f.name.clone())).collect();
        let pseudo_by_va: HashMap<u64, &str> =
            result.functions.iter().map(|f| (f.address, f.pseudo_code.as_str())).collect();
        for bucket in &plan.buckets {
            let c_path = out_dir.join(format!("{}.c", bucket.key));
            let mut body = String::new();
            body.push_str(&format!("#include \"{}.h\"\n\n", bucket.key));
            for &va in &bucket.functions {
                if let Some(code) = pseudo_by_va.get(&va) {
                    body.push_str(code);
                    body.push_str("\n\n");
                }
            }
            if let Err(e) = fs::write(&c_path, &body) {
                result.diagnostics.push(DecompilerDiagnostic {
                    severity: DiagnosticSeverity::Warning,
                    address: None,
                    message: format!("write {}: {e}", c_path.display()),
                    pass: None,
                });
            }
            let h_path = out_dir.join(format!("{}.h", bucket.key));
            // Prototypes are taken verbatim from each function's own emitted
            // definition, so the header can never disagree with the `.c` beside
            // it. The previous `__int64`-for-everything default did disagree —
            // it made every bucket uncompilable with `conflicting types for
            // '<fn>'` on any function whose recovered return type was not
            // `__int64` (measured: hundreds, including user functions).
            let header = crate::source_bucketing::emit_bucket_header_from_bodies(
                bucket,
                &func_names,
                &pseudo_by_va,
            );
            if let Err(e) = fs::write(&h_path, &header) {
                result.diagnostics.push(DecompilerDiagnostic {
                    severity: DiagnosticSeverity::Warning,
                    address: None,
                    message: format!("write {}: {e}", h_path.display()),
                    pass: None,
                });
            }
        }
    }
    Ok(())
}

impl BatchDecompiler {
    /// One-shot batch entry point: load `binary_path`, enumerate every
    /// detected function, decompile each, and write `<addr>.c` files plus
    /// `summary.json` under `out_dir`. Uses a single shared load result so
    /// disassembly does not re-read the file per function.
    ///
    /// `config` controls parallelism, failure handling, and per-function
    /// decompile options.
    /// # Errors
    /// Returns an error if the binary cannot be loaded, no functions are detected,
    /// or the output directory cannot be created.
    pub fn decompile_all_from_binary(
        binary_path: &Path,
        out_dir: &Path,
        config: &BatchConfig,
    ) -> Result<BatchResult, DecompilerError> {
        fs::create_dir_all(out_dir)
            .map_err(|e| DecompilerError::Other(format!("create_dir_all: {e}")))?;

        let mut load = load_binary(binary_path)?;
        // #5220: arricchisci i simboli col `.pdb` affiancato, se c'e'.
        // DEFAULT-ON dal 2026-08-14 (decisione dell'utente), spegnibile con
        // `RUSTRE_PDB=0`.
        //
        // ⚠ Questo gate cambia path A, e il commento precedente lo dichiarava
        // «violazione della REGOLA #28». La misura ha mostrato che non e' una
        // rinomina ma una SCOPERTA:
        //
        //   sample3_rust  path A  213 -> 458 funzioni  (245 file nuovi, 202 modificati)
        //   sample8_rust  path A  213 -> 464 funzioni  (251 file nuovi, 201 modificati)
        //
        // ⚠⚠ RETTIFICA (gate #25): quelle cifre CONTAVANO I FANTASMI. Dei 245
        // «nuovi» di sample3, **146 erano funzioni inesistenti** disassemblate
        // da slot IAT, e 152 dei 251 di sample8 — verificato col confine di
        // sezione: i rimossi hanno TUTTI VA >= 0x140015000 e i rimasti TUTTI
        // < 0x140014c2b, con ZERO sovrapposizioni.
        // ⇒ Il guadagno REALE del PDB e' **213 -> 312 = +99 funzioni** per
        // bucket, non +245. Resta un guadagno grosso (+46%), ma «piu' che
        // raddoppia» era falso e va detto qui, dove qualcuno lo rileggerebbe
        // come misura acquisita.
        //
        // Tenerlo spento per
        // preservare l'invarianza di path A significava rinunciare a meta' del
        // codice per proteggere una salvaguardia — che e' un mezzo, non il fine.
        //
        // #28 NON viene abbandonata, viene RIFORMULATA in modo che resti
        // falsificabile: **con `RUSTRE_PDB=0`, path A deve restare
        // byte-identico alla base storica**. Una salvaguardia che non puo' piu'
        // fallire non serve a niente.
        if gate_acceso("RUSTRE_PDB") {
            let added = augment_symbols_from_pdb(&mut load, binary_path);
            if std::env::var("RUSTRE_DBG_PDB").is_ok_and(|v| v != "0") {
                eprintln!(
                    "[pdb] {}: simboli aggiunti={added} (totale ora {})",
                    binary_path.display(),
                    load.symbols.len()
                );
            }
        }
        let load = load;
        let perf_det = crate::perf::scope(crate::perf::Stage::DetectFunctions);
    let boundaries = detect_functions_in_load(&load);
    drop(perf_det);
        if boundaries.is_empty() {
            return Err(DecompilerError::Other(format!(
                "no functions detected in {}",
                binary_path.display()
            )));
        }

        // Decompile each boundary through the shared single-function entry
        // point, then assemble a BatchResult. This keeps the batch and the
        // MCP `decompile.function` tool on a single code path.
        let entry_addr = load.entry_point;
        let export_addrs: std::collections::HashSet<u64> =
            load.exports.iter().map(|e| e.addr).collect();

        let mut filtered: Vec<u64> = Vec::with_capacity(boundaries.len());
        for fb in &boundaries {
            let addr = fb.start.as_u64();
            // Score against config.min_priority using the same rules as
            // BatchFunction so the caller's filter applies here too.
            let mut bf = BatchFunction::new(addr, Vec::new());
            if Some(addr) == entry_addr {
                bf = bf.entry_point();
            } else if export_addrs.contains(&addr) {
                bf = bf.export();
            }
            if bf.priority >= config.min_priority {
                filtered.push(addr);
            }
        }
        if config.max_functions > 0 && filtered.len() > config.max_functions {
            filtered.truncate(config.max_functions);
        }

        let all_starts_sorted: Vec<u64> = boundaries.iter().map(|b| b.start.as_u64()).collect();
        let mut result = run_decompile_loop_bounded(&load, &filtered, config, &all_starts_sorted);
        let perf_io = crate::perf::scope(crate::perf::Stage::EmitOutputs);
        emit_batch_outputs(&mut result, binary_path, out_dir, config)?;
        drop(perf_io);
        crate::perf::dump(&binary_path.display().to_string(), result.elapsed_ms);
        Ok(result)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallGraphBuilder — builds an approximate call graph for prioritisation
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a call graph from a set of functions and computes in-degrees
/// (how many times each function is called) to drive prioritisation.
pub struct CallGraphBuilder {
    /// edges: caller → [callee]
    pub edges: HashMap<u64, Vec<u64>>,
    /// `in_degree`: callee → count of callers
    pub in_degree: HashMap<u64, u32>,
}

impl CallGraphBuilder {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            edges: HashMap::new(),
            in_degree: HashMap::new(),
        }
    }

    /// Register a call from `caller` to `callee`.
    pub fn add_call(&mut self, caller: u64, call_target: u64) {
        self.edges.entry(caller).or_default().push(call_target);
        *self.in_degree.entry(call_target).or_insert(0) += 1;
    }

    /// Build from a list of (`caller_addr`, callees) pairs.
    #[must_use] 
    pub fn from_call_sites(sites: &[(u64, Vec<u64>)]) -> Self {
        let mut builder = Self::new();
        for (caller, callees) in sites {
            for &callee in callees {
                builder.add_call(*caller, callee);
            }
        }
        builder
    }

    /// Apply call-count information to a list of `BatchFunction`s.
    pub fn annotate(&self, funcs: &mut [BatchFunction]) {
        for f in funcs.iter_mut() {
            if let Some(&count) = self.in_degree.get(&f.address) {
                *f = f.clone().with_call_count(count);
            }
        }
    }

    /// Return the top N most-called function addresses.
    #[must_use] 
    pub fn top_n(&self, n: usize) -> Vec<(u64, u32)> {
        let mut pairs: Vec<(u64, u32)> = self.in_degree.iter().map(|(&a, &c)| (a, c)).collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }

    /// Number of unique call edges.
    #[must_use] 
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(std::vec::Vec::len).sum()
    }
}

impl Default for CallGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn void_ricorsiva_perde_la_cattura() {
        // La funzione definita nel file e' `void`, e assegna il valore della
        // chiamata a SE STESSA: quel valore non esiste.
        let code = "void f_erase(__int64 a1)\n{\n    uint64_t v8;\n    v8 = f_erase(a1);\n    v8 = 3;\n}\n";
        let out = strip_recursive_void_capture(code);
        assert!(out.contains("    f_erase(a1);"), "{out}");
        assert!(!out.contains("v8 = f_erase("), "{out}");
        assert!(out.contains("v8 = 3;"), "altre assegnazioni intatte: {out}");
    }

    #[test]
    fn void_chiamata_ad_altra_funzione_resta_intatta() {
        // ⚠ Il caso che tiene la regola stretta: `g` non e' la funzione
        // definita qui, e il suo tipo di ritorno NON e' noto da questo file.
        let code = "void f_erase(__int64 a1)\n{\n    uint64_t v8;\n    v8 = g(a1);\n}\n";
        assert_eq!(strip_recursive_void_capture(code), code);
    }

    #[test]
    fn funzione_non_void_resta_intatta() {
        // ⚠ Se la definizione non e' `void`, il valore ESISTE: non si tocca.
        let code = "__int64 f_erase(__int64 a1)\n{\n    uint64_t v8;\n    v8 = f_erase(a1);\n}\n";
        assert_eq!(strip_recursive_void_capture(code), code);
    }

    #[test]
    fn sort_key_ordering() {
        let entry = BatchFunction::new(0x1000, vec![]).entry_point();
        let normal = BatchFunction::new(0x2000, vec![]);
        let export = BatchFunction::new(0x3000, vec![]).export();
        assert!(entry.sort_key() > export.sort_key());
        assert!(export.sort_key() > normal.sort_key());
    }

    #[test]
    fn prioritiser_filters_low_priority() {
        let funcs = vec![
            BatchFunction::new(0x1000, vec![]).with_priority(FunctionPriority::LowPriority),
            BatchFunction::new(0x2000, vec![]).with_priority(FunctionPriority::Normal),
            BatchFunction::new(0x3000, vec![]).entry_point(),
        ];
        let prioritiser = FunctionPrioritiser::new(FunctionPriority::Normal);
        let sorted = prioritiser.sort(funcs);
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0].address, 0x3000); // entry point first
    }

    #[test]
    fn call_graph_in_degree() {
        let mut cg = CallGraphBuilder::new();
        cg.add_call(0x1000, 0x2000);
        cg.add_call(0x1000, 0x2000);
        cg.add_call(0x3000, 0x2000);
        assert_eq!(*cg.in_degree.get(&0x2000).unwrap(), 3);
    }

    #[test]
    fn call_graph_top_n() {
        let mut cg = CallGraphBuilder::new();
        cg.add_call(0x1000, 0xA000);
        cg.add_call(0x2000, 0xA000);
        cg.add_call(0x1000, 0xB000);
        let top = cg.top_n(1);
        assert_eq!(top[0].0, 0xA000);
        assert_eq!(top[0].1, 2);
    }

    #[test]
    fn batch_result_merge() {
        let mut a = BatchResult::default();
        a.stats.functions_decompiled = 5;
        let mut b = BatchResult::default();
        b.stats.functions_decompiled = 3;
        a.merge(b);
        assert_eq!(a.stats.functions_decompiled, 8);
    }

    #[test]
    fn batch_result_success_rate() {
        let mut r = BatchResult::default();
        r.stats.functions_decompiled = 8;
        r.failures.insert(0x1000, "err".to_string());
        r.failures.insert(0x2000, "err".to_string());
        // success_count() uses functions.len(), not stats
        // success_rate = 0 / (0 + 2) = 0.0
        assert!((r.success_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn prioritiser_partition() {
        let funcs = vec![
            BatchFunction::new(0x1000, vec![]).entry_point(),
            BatchFunction::new(0x2000, vec![]).export(),
            BatchFunction::new(0x3000, vec![]),
        ];
        let (entries, exports, rest) = FunctionPrioritiser::partition(&funcs);
        assert_eq!(entries.len(), 1);
        assert_eq!(exports.len(), 1);
        assert_eq!(rest.len(), 1);
    }

    // ---- RUSTRE_FNPTR_TABLE ---------------------------------------------

    fn nomi_finti() -> HashMap<u64, String> {
        let mut m = HashMap::new();
        m.insert(0x140001450u64, "add_fn".to_string());
        m.insert(0x140001460u64, "sub_fn".to_string());
        m
    }

    /// Il caso REALE di `off_140004000`: 4 celle sono puntatori, 4 no.
    /// E' il caso che una guardia «tutte le voci sono entry point»
    /// rifiuterebbe — per questo la decisione e' PER CELLA.
    #[test]
    fn fnptr_array_misto_puntatori_e_numeri() {
        let mut byte = String::new();
        for v in [0x140001450u64, 0x140001460, 3, 4] {
            for i in 0..8 {
                if !byte.is_empty() {
                    byte.push_str(", ");
                }
                byte.push_str(&format!("0x{:02X}", (v >> (8 * i)) as u8));
            }
        }
        let code = format!("static uint8_t off_140004000[32] = {{ {byte} }};
");
        let out = materialize_fnptr_tables(&code, &nomi_finti(), true);
        assert!(out.contains("static uint64_t off_140004000[4]"), "{out}");
        assert!(out.contains("(uint64_t)add_fn"), "{out}");
        assert!(out.contains("(uint64_t)sub_fn"), "{out}");
        // le celle NON funzione restano numeri, non vengono inventate
        assert!(out.contains("0x3ULL"), "{out}");
        assert!(out.contains("0x4ULL"), "{out}");
        // e le funzioni puntate vanno DICHIARATE, o gcc non compila
        assert!(out.contains("extern __int64 add_fn();"), "{out}");
    }

    #[test]
    fn realname_legge_il_nome_col_qualificatore() {
        // Il caso misurato: `func.name` e' `shapes__Circle__area`, il corpo
        // definisce `shapes__Circle__area___const`.
        let code = "void shapes__Circle__area___const(uint64_t a1)\n{\n    return;\n}\n";
        assert_eq!(
            nome_definizione(code).as_deref(),
            Some("shapes__Circle__area___const")
        );
    }

    #[test]
    fn realname_ignora_le_righe_di_controllo() {
        // `if (…)`/`while (…)` hanno la stessa forma di una firma: se le
        // prendesse, il nome della funzione diventerebbe `if`.
        let code = "extern __int64 pippo();\nstatic int x = 0;\nif (a1 != 0)\n__int64 vera_fn(int a1)\n{\n}\n";
        assert_eq!(nome_definizione(code).as_deref(), Some("vera_fn"));
    }

    #[test]
    fn realname_senza_firma_e_none() {
        assert_eq!(nome_definizione("    v1 = 2;\n"), None);
    }

    fn mappa_imp() -> HashMap<u64, String> {
        let mut m = HashMap::new();
        m.insert(0x14003B3E0, "CreateSemaphoreA".to_string());
        m.insert(0x14003B408, "GetCurrentProcess".to_string());
        m
    }

    #[test]
    fn imp_slot_rinomina_dichiarazione_e_uso() {
        let code = "extern __int64 off_14003B3E0;\nvoid f()\n{\n    v1 = *(__int64 *)(__int64)&off_14003B3E0;\n}\n";
        let out = rename_import_slots(code, &mappa_imp(), true);
        assert!(out.contains("extern __int64 __imp_CreateSemaphoreA;"), "{out}");
        assert!(out.contains("&__imp_CreateSemaphoreA"), "{out}");
        assert!(!out.contains("off_14003B3E0"), "{out}");
    }

    #[test]
    fn imp_slot_copre_anche_il_prefisso_sub() {
        // Misurato: gli slot IAT vengono a volte battezzati `sub_` perche'
        // l'emettitore li crede codice. La guardia e' l'INDIRIZZO, non il nome.
        let code = "__int64 sub_14003B3E0();\nvoid f()\n{\n    return sub_14003B3E0();\n}\n";
        let out = rename_import_slots(code, &mappa_imp(), true);
        assert!(out.contains("__imp_CreateSemaphoreA"), "{out}");
        assert!(!out.contains("sub_14003B3E0"), "{out}");
    }

    #[test]
    fn imp_slot_dichiarazione_diventa_dato_non_funzione() {
        // MISURATO (gcc 3 -> 7): `__int64 __imp_Sleep();` dichiara lo slot come
        // FUNZIONE, ma `__imp_X` e' il PUNTATORE ⇒ «redeclared as different
        // kind of symbol». La forward declaration va resa nella forma DATO.
        let code = "__int64 sub_14003B3E0();\nvoid f()\n{\n    v = sub_14003B3E0;\n}\n";
        let out = rename_import_slots(code, &mappa_imp(), true);
        assert!(
            out.contains("extern __int64 __imp_CreateSemaphoreA;"),
            "{out}"
        );
        assert!(!out.contains("__imp_CreateSemaphoreA();"), "{out}");
    }

    #[test]
    fn imp_slot_non_tronca_i_nomi_che_contengono_imp() {
        // MISURATO su sample3_rust (gcc 9 -> 10): `panic_unwind__imp__exception_cleanup`
        // e' una funzione Rust VERA il cui NOME contiene `__imp_`. Cercare la
        // sottostringa la riscriveva in `extern __int64 __imp__exception_cleanup;`,
        // perdendo il prefisso e inventando un simbolo inesistente.
        let code = "__int64 panic_unwind__imp__exception_cleanup();\n";
        assert_eq!(rename_import_slots(code, &mappa_imp(), true), code);
    }

    #[test]
    fn imp_slot_non_tocca_i_sub_che_sono_funzioni_vere() {
        // Un `sub_` che NON e' uno slot IAT resta intatto: senza questa
        // proprieta' il gate rinominerebbe funzioni vere.
        let code = "__int64 sub_140001480();\n";
        assert_eq!(rename_import_slots(code, &mappa_imp(), true), code);
    }

    #[test]
    fn imp_slot_spento_e_identico() {
        let code = "extern __int64 off_14003B3E0;\n";
        assert_eq!(rename_import_slots(code, &mappa_imp(), false), code);
    }

    #[test]
    fn imp_slot_lascia_stare_i_non_import() {
        // `off_140031D60` e' .rdata, non uno slot IAT: `EMIT_DATA` lo
        // materializza gia', toccarlo romperebbe quella definizione.
        let code = "static uint8_t off_140031D60[64] = { 0x40 };\n";
        assert_eq!(rename_import_slots(code, &mappa_imp(), true), code);
    }

    #[test]
    fn imp_slot_rispetta_il_confine_di_parola() {
        // `xoff_14003B3E0` non e' un token nostro: un match interno
        // produrrebbe `x__imp_...`, cioe' un identificatore inventato.
        let code = "__int64 xoff_14003B3E0 = 1;\n";
        assert_eq!(rename_import_slots(code, &mappa_imp(), true), code);
    }

    #[test]
    fn imp_slot_due_import_nello_stesso_file() {
        let code = "    a = off_14003B3E0;\n    b = off_14003B408;\n";
        let out = rename_import_slots(code, &mappa_imp(), true);
        assert_eq!(
            out,
            "    a = __imp_CreateSemaphoreA;\n    b = __imp_GetCurrentProcess;\n"
        );
    }

    /// Nessuna cella e' una funzione emessa ⇒ la riga NON si tocca.
    #[test]
    fn fnptr_array_senza_funzioni_invariato() {
        let code = "static uint8_t off_140005000[8] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
";
        let out = materialize_fnptr_tables(code, &nomi_finti(), true);
        assert_eq!(out.trim_end(), code.trim_end());
    }

    /// Gate spento ⇒ byte-identico. E' la garanzia di opt-in.
    #[test]
    fn fnptr_gate_spento_e_noop() {
        let code = "static uint8_t off_140004000[8] = { 0x50, 0x14, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00 };
";
        let out = materialize_fnptr_tables(code, &nomi_finti(), false);
        assert_eq!(out, code);
    }

    /// Una coda parziale non e' una cella: si rifiuta invece di indovinare.
    #[test]
    fn fnptr_lunghezza_non_multipla_di_8_rifiutata() {
        let code = "static uint8_t off_140004000[3] = { 0x50, 0x14, 0x00 };
";
        let out = materialize_fnptr_tables(code, &nomi_finti(), true);
        assert_eq!(out.trim_end(), code.trim_end());
    }

    // ---- RUSTRE_NO_SELF_EXTERN -------------------------------------------

    /// Il caso REALE di sample3_rust: stesso nome dichiarato DATO e definito
    /// FUNZIONE nello stesso file ⇒ «redeclared as different kind of symbol».
    #[test]
    fn self_extern_tolto_sul_caso_reale() {
        let code = "extern __int64 __imp_GetLastError;

void __imp_GetLastError(int64_t a1, uint64_t a2)
{
    return;
}
";
        let out = drop_self_externs(code, true);
        assert!(!out.contains("extern __int64 __imp_GetLastError;"), "{out}");
        assert!(out.contains("void __imp_GetLastError(int64_t a1, uint64_t a2)"), "{out}");
    }

    /// Un extern il cui nome NON e' definito qui deve restare: toglierlo
    /// spezzerebbe la compilazione invece di ripararla.
    #[test]
    fn self_extern_non_definito_resta() {
        let code = "extern __int64 off_140004000;

void f()
{
    g();
}
";
        let out = drop_self_externs(code, true);
        assert!(out.contains("extern __int64 off_140004000;"), "{out}");
    }

    /// Una DICHIARAZIONE di funzione (finisce con `;`) non e' una definizione:
    /// non deve far togliere l'extern.
    #[test]
    fn self_extern_dichiarazione_non_e_definizione() {
        let code = "extern __int64 sub_140001000;
__int64 sub_140001000();
void f()
{
    return;
}
";
        let out = drop_self_externs(code, true);
        assert!(out.contains("extern __int64 sub_140001000;"), "{out}");
    }

    /// Gate spento ⇒ byte-identico.
    #[test]
    fn self_extern_gate_spento_e_noop() {
        let code = "extern __int64 X;
void X()
{
}
";
        assert_eq!(drop_self_externs(code, false), code);
    }

    // ---- RUSTRE_DECL_RENAMED ---------------------------------------------

    /// Il caso REALE: `*(__int64 *)HeapFree` senza alcuna dichiarazione.
    #[test]
    fn decl_renamed_dichiara_il_caso_reale() {
        let code = "void f()
{
    return ((__int64 (*)())(*(__int64 *)HeapFree))();
}
";
        let out = declare_renamed_imports(code, true);
        assert!(out.starts_with("extern __int64 HeapFree;"), "{out}");
    }

    /// ⚠ Un nome RISERVATO (inizia con `_`) NON va dichiarato: e' la
    /// regressione gia' pagata su sample7_cpp con `__p__fmode`.
    #[test]
    fn decl_renamed_salta_i_nomi_riservati() {
        let code = "void f()
{
    v1 = *(__int64 *)_initterm_e;
}
";
        let out = declare_renamed_imports(code, true);
        assert!(!out.contains("extern __int64 _initterm_e;"), "{out}");
    }

    /// Un numero non e' un identificatore.
    #[test]
    fn decl_renamed_ignora_i_numeri() {
        let code = "void f()
{
    v1 = (__int64)0x15619C28B;
}
";
        let out = declare_renamed_imports(code, true);
        assert_eq!(out, code);
    }

    /// Se il file gia' definisce il nome, non serve dichiararlo.
    #[test]
    fn decl_renamed_non_ridichiara_il_definito() {
        let code = "void HeapFree()
{
    v1 = *(__int64 *)HeapFree;
}
";
        let out = declare_renamed_imports(code, true);
        assert!(!out.contains("extern __int64 HeapFree;"), "{out}");
    }

    /// Gate spento ⇒ byte-identico.
    #[test]
    fn decl_renamed_gate_spento_e_noop() {
        let code = "void f()
{
    v1 = *(__int64 *)HeapFree;
}
";
        assert_eq!(declare_renamed_imports(code, false), code);
    }
}
