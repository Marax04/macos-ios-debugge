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
    // ── #7980: SECONDA ONDATA — definire cio' che si e' gia' chiamato ──────
    //
    // ⚠ `gate_acceso` e' DEFAULT-ON (`!matches!(.., Ok("0")|Ok("false"))`):
    // questo blocco gira SEMPRE salvo `RUSTRE_SECONDA_ONDATA=0`. Scritto qui
    // perche' la prima misura confrontava due corse entrambe con l'ondata
    // accesa e le dava identiche — il gate sembrava inerte e non lo era.
    //
    // Path B recupera 6,3x i `case` di path A (7553 contro 1208 su rust3_O0) e
    // paga il vantaggio con riferimenti irrisolti: i rami freddi di uno switch
    // che rustc colloca DOPO un'altra funzione escono dall'estensione e sono
    // emessi come `sub_X()` verso un simbolo che nessuno definisce.
    //
    // ⚠ La cura ovvia — allungare la fine della funzione — e' ESCLUSA dal
    // codice, non per prudenza: `scan_cap` (`binary_entry.rs`) limita la
    // finestra al PROSSIMO INIZIO di funzione proprio perche' la camminata,
    // che prosegue oltre il primo `ret` per recuperare i corpi dei case,
    // altrimenti assorbirebbe la funzione seguente. Alzare quel tetto farebbe
    // inghiottire `sub_140034fc0` per intero.
    //
    // Qui si fa l'opposto, e non serve toccare ne' `scan_cap` ne' la
    // camminata: se il codice emesso CHIAMA un indirizzo come funzione, quello
    // stesso indirizzo viene DECOMPILATO come funzione. Generico per
    // costruzione — chiude la classe switch e ogni altra che lasci un
    // `sub_HEX` senza definizione.
    //
    // Limitato a poche ondate e a un tetto per ondata: una funzione nuova puo'
    // riferirne altre, e senza freno l'insieme cresce finche' c'e' immagine.
    if gate_acceso("RUSTRE_SECONDA_ONDATA") {
        // MISURATO: piu' ondate NON e' meglio. 3 ondate -> 17 irrisolti,
        // 8 ondate -> 32. Le ondate si ALIMENTANO: in una regione di dati
        // decodificata come codice ogni funzione aggiunta ne riferisce
        // altre a 1 byte di distanza. Il tetto e' quindi una scelta di
        // convergenza, non un limite di risorse.
        let max_ondate: usize = std::env::var("RUSTRE_ONDATE")
            .ok()
            .and_then(|v| v.parse().ok())
            // MISURATO su rust3_O0 — la risposta NON e' monotona:
            //   0->55  1->23  2->15  3->17  4->14  8->32
            // Default 2: vicino al minimo, meno file aggiunti di 3 e 4, e
            // il piu' lontano dal regime divergente. La differenza 15 vs 14
            // e' dentro l'oscillazione, non un guadagno.
            // Col criterio `.text` la successione CONVERGE e il ciclo esce da
            // solo (`mancanti.is_empty()`), quindi il tetto non e' piu' una
            // scelta di merito ma solo una rete di sicurezza. MISURATO: a 4
            // ondate restavano 4 residui su rust8_O0 e 2 su cpp_sample7_O2,
            // a 12 entrambi vanno a ZERO. Prima del criterio alzare il tetto
            // PEGGIORAVA (8 ondate -> 32 residui): e' il criterio, non il
            // tetto, ad aver cambiato il segno.
            .unwrap_or(16);
        const MAX_PER_ONDATA: usize = 512;
        // CRITERIO, non piu' un tetto scelto a mano. Partizionando il residuo
        // per regione si vede che i due bucket si comportano in modo OPPOSTO:
        //
        //   ondate   residuo   in `.idata`   in `.text`
        //     1        23          15            8
        //     2        15           9            6
        //     3        17          13            4
        //     4        14          10            4
        //
        // Il residuo VERO converge (8→6→4→4); tutta l'oscillazione che mi aveva
        // fatto concludere «piu' ondate e' peggio» stava in una sola regione —
        // e quella regione e' **`.idata`**, la tabella degli import
        // (`0x1400cc000..0x1400cdbec` in rust3_O0): non e' codice, e
        // disassemblata da' `imul $0x3D000066, 0x74(%rsi), %ebp`.
        //
        // Due filtri piu' ovvi FALSIFICATI dalla misura prima di arrivare qui:
        //  - densita' degli indirizzi: min 5 B fra i legittimi contro 1 B fra
        //    gli spuri, ma solo 2 spuri su 32 sotto i 4 B — avrebbe preso il 6%;
        //  - forma di chiamata: **55/55 e 32/32** compaiono come `sub_X(...)`,
        //    quindi non distingue nulla.
        let oracle = crate::binary_entry::DataOracle::from_load(load);
        let mut definiti: std::collections::HashSet<u64> =
            result.functions.iter().map(|f| f.address).collect();
        let mut totale = 0usize;
        for _ondata in 0..max_ondate {
            let mut mancanti: Vec<u64> = Vec::new();
            for f in &result.functions {
                let hlil = f.hlil_pseudo_code.as_deref().unwrap_or("");
                for testo in [f.pseudo_code.as_str(), hlil] {
                    let mut resto = testo;
                    while let Some(i) = resto.find("sub_") {
                        resto = &resto[i + 4..];
                        let hex: String =
                            resto.chars().take_while(char::is_ascii_hexdigit).collect();
                        if hex.len() >= 4
                            && let Ok(va) = u64::from_str_radix(&hex, 16)
                            && !definiti.contains(&va)
                            && !mancanti.contains(&va)
                        {
                            mancanti.push(va);
                        }
                    }
                }
            }
            mancanti.retain(|&va| {
                oracle.section_kind(va) == crate::binary_entry::SectionKind::Text
            });
            if mancanti.is_empty() {
                break;
            }
            mancanti.sort_unstable();
            mancanti.truncate(MAX_PER_ONDATA);
            for va in &mancanti {
                definiti.insert(*va);
            }
            let nuovi: Vec<(u64, u64, Result<DecompiledFunction, DecompilerError>)> =
                mancanti.par_iter().map(decompile_one).collect();
            let mut aggiunte = 0usize;
            for (_addr, elapsed, res) in nuovi {
                if let Ok(func) = res {
                    result.stats.functions_decompiled += 1;
                    result.stats.total_time_ms += elapsed;
                    result.functions.push(func);
                    aggiunte += 1;
                }
            }
            totale += aggiunte;
            if aggiunte == 0 {
                break;
            }
        }
        if std::env::var_os("RUSTRE_DBG_ONDATA").is_some() {
            eprintln!("[ondata] funzioni aggiunte={totale}");
        }
    }
    // ── #8040: la 2a ondata definisce cio' che `fn_starts` non conosce ─────
    //
    // #7980 emette le funzioni referenziate-ma-non-definite. Entrano pero'
    // nell'insieme emesso DOPO che `callee_arities_for` ha calcolato
    // `fn_starts` sullo sweep, quindi le tre passate `hlil_` di rinomina
    // (`rename_hlil_sub_symbols` e sorelle) non le vedono: il gate
    // `starts.contains_key(&va) || extra.contains(&va)` e' falso.
    //
    // Risultato misurato su `sample7_cpp` path B: la definizione e'
    // `void fn_14001aefe()` mentre il chiamante scrive `sub_14001AEFE()`.
    // Il linker non le unisce ⇒ LINK_FAIL.
    //
    // Causa provata per IDENTITA' DI INSIEME, non per cardinalita': due corse
    // con la sola `RUSTRE_ONDATE` che cambia danno 1118 e 1138 file; i casi
    // non spiegati dalle guardie erano 20; l'intersezione fra i due insiemi e'
    // **20 su 20**, con zero casi fuori.
    //
    // Qui la mappa e' letta dalla VERITA' DEL TESTO EMESSO — come la funzione
    // e' realmente definita — invece di ri-derivarla da `name_of`, che e' il
    // passaggio dove le due grafie divergono.
    //
    // Tocca SOLO `hlil_pseudo_code`: path A non puo' cambiare per costruzione.
    if !matches!(
        std::env::var("RUSTRE_ONDATA_NOMI").as_deref(),
        Ok("0") | Ok("false")
    ) {
        riconcilia_nomi_ondata(&mut result);
        // #8150, PROMOSSO a default-ON: misurato con generazione appaiata sullo
        // stesso albero. `code_as_data` di path B 157 -> 2, file con riferimenti
        // irrisolti 3366 -> 3173, azionabili 22 invariati, simboli dato definiti
        // 26061 invariati. 215 file cambiati, **215/215 compilano** e path A e'
        // intatto (0 file non-hlil diversi). Spegnibile con `RUSTRE_OFF_ONDATA=0`.
        if !matches!(
            std::env::var("RUSTRE_OFF_ONDATA").as_deref(),
            Ok("0") | Ok("false")
        ) {
            risolvi_off_ondata(&mut result);
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
/// #8840 - definisce le tabelle di puntatori a funzione che il testo di path A
/// indicizza ancora ma che nessuno definisce.
///
/// Cerca `extern __int64 off_HEX;` il cui simbolo compaia anche in posizione
/// di INDICE (`off_HEX[`) o con l'indirizzo preso (`&off_HEX`), legge i byte
/// dall'immagine e li interpreta come celle da 8 byte.
///
/// Definisce SOLO se OGNI cella risolve a una funzione emessa. Una cella non
/// risolta resterebbe un numero, cioe' un puntatore a memoria arbitraria: il
/// file linkerebbe e salterebbe nel vuoto. Meglio un LINK_FAIL rumoroso di un
/// salto silenzioso.
///
/// Emette anche le dichiarazioni anticipate delle funzioni puntate: non sono
/// chiamate da questo file, quindi nessun'altra passata le ha dichiarate.
fn definisci_tabelle_fnptr_a(
    code: &str,
    load: Option<&crate::RichLoadResult>,
    names: &HashMap<u64, String>,
) -> String {
    let Some(load) = load else { return code.to_string() };
    if !code.contains("extern __int64 off_") {
        return code.to_string();
    }
    let mut definizioni: Vec<String> = Vec::new();
    let mut risolti: Vec<String> = Vec::new();
    for line in code.lines() {
        let t = line.trim();
        let Some(resto) = t.strip_prefix("extern __int64 off_") else { continue };
        let Some(hex) = resto.strip_suffix(";") else { continue };
        if hex.is_empty() || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let nome = format!("off_{hex}");
        // Deve essere INDICIZZATA o avere l'indirizzo preso: un semplice uso
        // scalare non e' una tabella e non va inventato.
        if !code.contains(&format!("{nome}[")) && !code.contains(&format!("&{nome}")) {
            continue;
        }
        let Ok(va) = u64::from_str_radix(hex, 16) else { continue };
        let Some((base, slice)) = crate::binary_entry::slice_at_va(load, va) else { continue };
        let Some(off) = va.checked_sub(base).and_then(|d| usize::try_from(d).ok()) else {
            continue;
        };
        let Some(byte) = slice.get(off..) else { continue };
        // Celle finche' risolvono; ci si ferma alla prima che non risolve.
        let mut celle: Vec<String> = Vec::new();
        for chunk in byte.chunks(8) {
            if chunk.len() < 8 {
                break;
            }
            let mut v = 0u64;
            for (i, c) in chunk.iter().enumerate() {
                v |= u64::from(*c) << (8 * i);
            }
            // Un nome che inizia con `_` e' riservato all'implementazione e
            // spesso gia' dichiarato dagli header del prelude: dichiararlo e'
            // `conflicting types` (stessa ragione di #5990).
            match names.get(&v).filter(|n| !n.starts_with('_')) {
                Some(f) => celle.push(f.clone()),
                None => break,
            }
        }
        // Una cella sola non e' una tabella.
        if celle.len() < 2 {
            continue;
        }
        for f in &celle {
            let d = format!("__int64 {f}();");
            if !definizioni.contains(&d) && !code.contains(&d) {
                definizioni.push(d);
            }
        }
        let corpo = celle
            .iter()
            .map(|f| format!("(uint64_t){f}"))
            .collect::<Vec<_>>()
            .join(", ");
        definizioni.push(format!("uint64_t {nome}[{}] = {{ {corpo} }};", celle.len()));
        risolti.push(nome);
    }
    if definizioni.is_empty() {
        return code.to_string();
    }
    // La dichiarazione `extern` va TOLTA: `extern __int64 off_X;` accanto a
    // `uint64_t off_X[4]` e' `conflicting types`.
    let mut out = String::with_capacity(code.len() + 256);
    for d in &definizioni {
        out.push_str(d);
        out.push('\n');
    }
    for line in code.lines() {
        let t = line.trim();
        let togli = t
            .strip_prefix("extern __int64 ")
            .and_then(|r| r.strip_suffix(";"))
            .is_some_and(|n| risolti.iter().any(|r| r == n));
        if togli {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}
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
    // #7970 — un PARAMETRO non e' un simbolo globale non dichiarato.
    //
    // La guardia sopra esclude i nomi gia' dichiarati, definiti o assegnati.
    // NON esclude i **parametri**, che nella firma compaiono come
    // `uint64_t a1)` o `uint64_t a1,` — nessuno dei pattern cercati. Esito:
    //
    //     extern __int64 a1;                        <- spurio
    //     __int64 _Unwind_GetCFA(uint64_t a1) { return (*(__int64 *)a1); }
    //
    // Non rompe il link — il parametro fa OMBRA alla globale, quindi l'`extern`
    // resta inusato — ma **afferma il falso**: dice che esiste una variabile
    // globale con quel nome.
    //
    // MISURATO su sei bucket: **path B 125 file, path A ZERO** in ognuno.
    //   sample7_cpp 44 | cpp_sample7_O0 41 | rust3_O0 15
    //   go_sample9_O0 15 | sample5_cs 5 | csharp_O2 5
    // E' un divario di parita' con path A come ORACOLO di cio' che l'uscita
    // dovrebbe essere: non una stima, un comportamento gia' realizzato altrove.
    //
    // I nomi si leggono dalle righe di DEFINIZIONE (con `(`…`)` e senza `;`
    // finale): una dichiarazione non introduce parametri nel corpo.
    let parametri: std::collections::HashSet<String> = code
        .lines()
        .filter(|l| !l.trim_end().ends_with(';') && l.contains('(') && l.contains(')'))
        .filter_map(|l| l.split_once('(').and_then(|(_, r)| r.split_once(')')).map(|(a, _)| a))
        .flat_map(|args| {
            args.split(',').filter_map(|a| {
                a.trim()
                    .rsplit(|c: char| c.is_whitespace() || c == '*')
                    .next()
                    .filter(|w| !w.is_empty() && w.chars().all(|c| c.is_alphanumeric() || c == '_'))
                    .map(str::to_string)
            })
        })
        .collect();
    candidati.retain(|n| !parametri.contains(n));
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
    // ⚠ La guardia deve coprire OGNI tipo di ritorno che questa funzione emette,
    // altrimenti un corpo gia' presente verrebbe definito una seconda volta. I
    // corpi SIMD a 128 bit (#7200) ritornano `unsigned __int128`: senza questa
    // riga la protezione non scattava per loro.
    // #8670 - corrispondenza per PAROLA, non per sottostringa. Trovato dal
    // test `un_mnemonico_ignoto_non_riceve_un_corpo`: `vpmaxsd(` CONTIENE
    // `maxsd(`, quindi una funzione con AVX `vpmaxsd` riceveva il corpo di
    // `maxsd`, uno scalare su double - semantica diversa e per giunta
    // LINKABILE, cioe invisibile. Idem `mul_overflow` in `imul_overflow`.
    let inizio_parola = |s: &str, at: usize| -> bool {
        if at == 0 { return true; }
        let c = s.as_bytes()[at - 1];
        !c.is_ascii_alphanumeric() && c != b'_'
    };
    let usa = |n: &str| {
        let ago = format!("{n}(");
        code.match_indices(&ago).any(|(i, _)| inizio_parola(code, i))
            && !code.contains(&format!("static uint64_t {n}("))
            && !code.contains(&format!("static uint32_t {n}("))
            && !code.contains(&format!("static unsigned __int128 {n}("))
    };
    // ── #7200: i dieci helper SIMD a 128 bit ───────────────────────────
    // Semantica ISA verificata contro gli intrinseci SSE2 corrispondenti su
    // vettori pseudo-casuali. Larghezza `unsigned __int128` e NON `uint64_t`:
    // `packuswb` e `pshufd` con immediato 0xEE/0xF5 LEGGONO la meta' alta, che
    // un modello a 64 bit non rappresenta.
    // ⚠ Assunzione dichiarata: little-endian nel `memcpy` fra `__int128` e
    // array. Vera su x86-64, ma e' un'assunzione, non un teorema.
    // #8650: sei helper MANCANTI, semantica NON ambigua.
    // Misurato al round 1239: 23 mnemonici erano CHIAMATI e mai DEFINITI
    // (`external` al link, causa dei LINK_FAIL di rust3_O0). Questi sei
    // coprono 564 occorrenze sul corpus. Stessa assunzione little-endian
    // gia dichiarata sopra per i corpi #7200.
    // #8655: i tre emersi DOPO #8650 (erano nascosti dietro i primi quattro).
    // `psadbw` era gia' nella mappa intrinseci ma non fra gli helper: e' il
    // difetto delle DUE LISTE che divergono, round 1240.
    if usa("psadbw") {
        corpi.push_str(
            "static unsigned __int128 psadbw(unsigned __int128 dst, unsigned __int128 src)
{
    uint8_t a[16], b[16];
    uint16_t r[8];
    unsigned s0 = 0, s1 = 0;
    int i;
    memcpy(a, &dst, 16);
    memcpy(b, &src, 16);
    for (i = 0; i < 8; i++) s0 += (unsigned)(a[i] > b[i] ? a[i] - b[i] : b[i] - a[i]);
    for (i = 8; i < 16; i++) s1 += (unsigned)(a[i] > b[i] ? a[i] - b[i] : b[i] - a[i]);
    for (i = 0; i < 8; i++) r[i] = 0;
    r[0] = (uint16_t)s0;
    r[4] = (uint16_t)s1;
    memcpy(&dst, r, 16);
    return dst;
}
",
        );
    }
    // shld/shrd: spostamento a doppia precisione a 64 bit. Un conteggio 0
    // lascia dst INVARIATO (comportamento ISA), non produce uno shift di 64
    // che in C sarebbe indefinito.
    if usa("shld") {
        corpi.push_str(
            "static uint64_t shld(uint64_t dst, uint64_t src, int cnt)
{
    unsigned n = ((unsigned)cnt) & 63u;
    if (n == 0) return dst;
    return (uint64_t)((dst << n) | (src >> (64 - n)));
}
",
        );
    }
    if usa("shrd") {
        corpi.push_str(
            "static uint64_t shrd(uint64_t dst, uint64_t src, int cnt)
{
    unsigned n = ((unsigned)cnt) & 63u;
    if (n == 0) return dst;
    return (uint64_t)((dst >> n) | (src << (64 - n)));
}
",
        );
    }
    if usa("pminub") {
        corpi.push_str(
            "static unsigned __int128 pminub(unsigned __int128 dst, unsigned __int128 src)
{
    uint8_t a[16], b[16];
    int i;
    memcpy(a, &dst, 16);
    memcpy(b, &src, 16);
    for (i = 0; i < 16; i++) a[i] = (a[i] < b[i]) ? a[i] : b[i];
    memcpy(&dst, a, 16);
    return dst;
}
",
        );
    }
    if usa("packsswb") {
        corpi.push_str(
            "static unsigned __int128 packsswb(unsigned __int128 dst, unsigned __int128 src)
{
    int16_t a[8], b[8];
    int8_t r[16];
    int i, v;
    memcpy(a, &dst, 16);
    memcpy(b, &src, 16);
    for (i = 0; i < 8; i++) { v = a[i]; r[i] = (int8_t)(v > 127 ? 127 : (v < -128 ? -128 : v)); }
    for (i = 0; i < 8; i++) { v = b[i]; r[i + 8] = (int8_t)(v > 127 ? 127 : (v < -128 ? -128 : v)); }
    memcpy(&dst, r, 16);
    return dst;
}
",
        );
    }
    if usa("psllw") {
        corpi.push_str(
            "static unsigned __int128 psllw(unsigned __int128 dst, unsigned __int128 cnt)
{
    uint16_t a[8];
    unsigned long long n = (unsigned long long)cnt;
    int i;
    memcpy(a, &dst, 16);
    for (i = 0; i < 8; i++) a[i] = (n > 15) ? 0 : (uint16_t)(a[i] << n);
    memcpy(&dst, a, 16);
    return dst;
}
",
        );
    }
    if usa("psrlw") {
        corpi.push_str(
            "static unsigned __int128 psrlw(unsigned __int128 dst, unsigned __int128 cnt)
{
    uint16_t a[8];
    unsigned long long n = (unsigned long long)cnt;
    int i;
    memcpy(a, &dst, 16);
    for (i = 0; i < 8; i++) a[i] = (n > 15) ? 0 : (uint16_t)(a[i] >> n);
    memcpy(&dst, a, 16);
    return dst;
}
",
        );
    }
    if usa("psraw") {
        corpi.push_str(
            "static unsigned __int128 psraw(unsigned __int128 dst, unsigned __int128 cnt)
{
    int16_t a[8];
    unsigned long long n = (unsigned long long)cnt;
    int i;
    memcpy(a, &dst, 16);
    for (i = 0; i < 8; i++) { if (n > 15) a[i] = (int16_t)(a[i] < 0 ? -1 : 0); else a[i] = (int16_t)(a[i] >> n); }
    memcpy(&dst, a, 16);
    return dst;
}
",
        );
    }
    if usa("pinsrw") {
        corpi.push_str(
            "static unsigned __int128 pinsrw(unsigned __int128 dst, unsigned long long val, int sel)
{
    uint16_t a[8];
    memcpy(a, &dst, 16);
    a[sel & 7] = (uint16_t)val;
    memcpy(&dst, a, 16);
    return dst;
}
",
        );
    }
    if usa("pcmpeqb") {
        corpi.push_str(
            "static unsigned __int128 pcmpeqb(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint8_t a[16], b[16];\n    int i;\n    memcpy(a, &dst, 16);\n    memcpy(b, &src, 16);\n    for (i = 0; i < 16; i++) a[i] = (a[i] == b[i]) ? 0xFF : 0x00;\n    memcpy(&dst, a, 16);\n    return dst;\n}\n",
        );
    }
    if usa("pcmpeqw") {
        corpi.push_str(
            "static unsigned __int128 pcmpeqw(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint16_t a[8], b[8];\n    int i;\n    memcpy(a, &dst, 16);\n    memcpy(b, &src, 16);\n    for (i = 0; i < 8; i++) a[i] = (a[i] == b[i]) ? 0xFFFFu : 0x0000u;\n    memcpy(&dst, a, 16);\n    return dst;\n}\n",
        );
    }
    if usa("pcmpeqq") {
        corpi.push_str(
            "static unsigned __int128 pcmpeqq(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint64_t a[2], b[2];\n    int i;\n    memcpy(a, &dst, 16);\n    memcpy(b, &src, 16);\n    for (i = 0; i < 2; i++) a[i] = (a[i] == b[i]) ? ~(uint64_t)0 : (uint64_t)0;\n    memcpy(&dst, a, 16);\n    return dst;\n}\n",
        );
    }
    if usa("pcmpgtb") {
        corpi.push_str(
            "static unsigned __int128 pcmpgtb(unsigned __int128 dst, unsigned __int128 src)\n{\n    int8_t a[16], b[16];\n    int i;\n    memcpy(a, &dst, 16);\n    memcpy(b, &src, 16);\n    for (i = 0; i < 16; i++) a[i] = (a[i] > b[i]) ? (int8_t)0xFF : (int8_t)0x00;\n    memcpy(&dst, a, 16);\n    return dst;\n}\n",
        );
    }
    // #7310 — `pcmpgtw`/`pcmpgtd`: le corsie a 16 e 32 bit della famiglia che
    // finora aveva solo quella a 8 (`pcmpgtb`, sopra).
    //
    // Trovati da `behavior.py`, non da un inventario: il report della misura
    // del 2026-08-26 elenca `pcmpgtd: external` fra le cause di LINK_FAIL in
    // `rust3_O2`. Un'intrinseca senza corpo NON e' un errore di compilazione —
    // `-fsyntax-only` la accetta come dichiarazione implicita — quindi
    // `check.sh` era cieco: solo il LINK la vede.
    //
    // Uso misurato prima di aggiungerle (mai aggiungere corpi "per simmetria"):
    // `pcmpgtd` 74 occorrenze in `behav/out`, `pcmpgtw` 34. `pcmpgtq` ZERO ⇒
    // NON aggiunto, resterebbe codice morto (ed e' SSE4.2, altra famiglia).
    //
    // ⚠ Confronto con SEGNO per corsia, come la variante a 8 bit: `int16_t` e
    // `int32_t`, non le versioni senza segno. La maschera e' tutti-uno,
    // scritta come `~(int)0` per corsia per non dipendere dalla larghezza del
    // letterale.
    if usa("pcmpgtw") {
        corpi.push_str(
            "static unsigned __int128 pcmpgtw(unsigned __int128 dst, unsigned __int128 src)
{
    int16_t a[8], b[8];
    int i;
    memcpy(a, &dst, 16);
    memcpy(b, &src, 16);
    for (i = 0; i < 8; i++) a[i] = (a[i] > b[i]) ? (int16_t)0xFFFF : (int16_t)0x0000;
    memcpy(&dst, a, 16);
    return dst;
}
",
        );
    }
    if usa("pcmpgtd") {
        corpi.push_str(
            "static unsigned __int128 pcmpgtd(unsigned __int128 dst, unsigned __int128 src)
{
    int32_t a[4], b[4];
    int i;
    memcpy(a, &dst, 16);
    memcpy(b, &src, 16);
    for (i = 0; i < 4; i++) a[i] = (a[i] > b[i]) ? (int32_t)0xFFFFFFFF : (int32_t)0x00000000;
    memcpy(&dst, a, 16);
    return dst;
}
",
        );
    }
    if usa("pmovmskb") {
        corpi.push_str(
            "static uint32_t pmovmskb(uint32_t dst, unsigned __int128 src)\n{\n    uint8_t b[16];\n    uint32_t m = 0;\n    int i;\n    memcpy(b, &src, 16);\n    for (i = 0; i < 16; i++) if (b[i] & 0x80) m |= (uint32_t)1 << i;\n    (void)dst;\n    return m;\n}\n",
        );
    }
    if usa("pshufd") {
        corpi.push_str(
            "static unsigned __int128 pshufd(unsigned __int128 dst, unsigned __int128 src, int imm)\n{\n    uint32_t s[4], r[4];\n    unsigned __int128 out;\n    memcpy(s, &src, 16);\n    r[0] = s[imm & 3];\n    r[1] = s[(imm >> 2) & 3];\n    r[2] = s[(imm >> 4) & 3];\n    r[3] = s[(imm >> 6) & 3];\n    memcpy(&out, r, 16);\n    (void)dst;\n    return out;\n}\n",
        );
    }
    if usa("pshuflw") {
        corpi.push_str(
            "static unsigned __int128 pshuflw(unsigned __int128 dst, unsigned __int128 src, int imm)\n{\n    uint16_t s[8], r[8];\n    unsigned __int128 out;\n    int i;\n    memcpy(s, &src, 16);\n    r[0] = s[imm & 3];\n    r[1] = s[(imm >> 2) & 3];\n    r[2] = s[(imm >> 4) & 3];\n    r[3] = s[(imm >> 6) & 3];\n    for (i = 4; i < 8; i++) r[i] = s[i];\n    memcpy(&out, r, 16);\n    (void)dst;\n    return out;\n}\n",
        );
    }
    // #7840 - i tre membri MANCANTI della famiglia unpack.
    //
    // La serie c'era a meta': `punpcklbw` (byte) e `punpcklwd` (word) sono
    // definiti, `punpcklqdq` (quadword) pure, ma **`punpckldq` (doubleword) no**
    // — un buco in mezzo a una progressione regolare. E le varianti HIGH
    // mancavano tutte.
    //
    // Non e' teoria: `punpckldq: external` e' un BLOCCANTE misurato di
    // `total_area` e `string_map_demo` (6 righe LINK_FAIL). Uso nel corpus,
    // contato prima di scrivere:
    //
    //     punpckldq    19 occorrenze in 19 file
    //     punpckhbw    66 occorrenze in 52 file
    //     punpckhqdq   32 occorrenze in  8 file
    //     punpckhwd     0     punpckhdq   0   (non si aggiungono)
    //
    // Si aggiungono i tre USATI e non i due inutilizzati: definire cio' che
    // nessuno chiama e' il difetto che #7800 ha gia' pagato con +36 compile
    // failures.
    if usa("punpckldq") {
        corpi.push_str(
            "static unsigned __int128 punpckldq(unsigned __int128 dst, unsigned __int128 src)
{
    uint32_t d[4], s[4], r[4];
    unsigned __int128 out;
    int i;
    memcpy(d, &dst, 16);
    memcpy(s, &src, 16);
    for (i = 0; i < 2; i++) { r[2*i] = d[i]; r[2*i+1] = s[i]; }
    memcpy(&out, r, 16);
    return out;
}
",
        );
    }
    if usa("punpckhbw") {
        corpi.push_str(
            "static unsigned __int128 punpckhbw(unsigned __int128 dst, unsigned __int128 src)
{
    uint8_t d[16], s[16], r[16];
    unsigned __int128 out;
    int i;
    memcpy(d, &dst, 16);
    memcpy(s, &src, 16);
    for (i = 0; i < 8; i++) { r[2*i] = d[i+8]; r[2*i+1] = s[i+8]; }
    memcpy(&out, r, 16);
    return out;
}
",
        );
    }
    if usa("punpckhqdq") {
        corpi.push_str(
            "static unsigned __int128 punpckhqdq(unsigned __int128 dst, unsigned __int128 src)
{
    uint64_t d[2], s[2], r[2];
    unsigned __int128 out;
    memcpy(d, &dst, 16);
    memcpy(s, &src, 16);
    r[0] = d[1];
    r[1] = s[1];
    memcpy(&out, r, 16);
    return out;
}
",
        );
    }
    if usa("punpcklbw") {
        corpi.push_str(
            "static unsigned __int128 punpcklbw(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint8_t d[16], s[16], r[16];\n    unsigned __int128 out;\n    int i;\n    memcpy(d, &dst, 16);\n    memcpy(s, &src, 16);\n    for (i = 0; i < 8; i++) { r[2*i] = d[i]; r[2*i+1] = s[i]; }\n    memcpy(&out, r, 16);\n    return out;\n}\n",
        );
    }
    if usa("punpcklwd") {
        corpi.push_str(
            "static unsigned __int128 punpcklwd(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint16_t d[8], s[8], r[8];\n    unsigned __int128 out;\n    int i;\n    memcpy(d, &dst, 16);\n    memcpy(s, &src, 16);\n    for (i = 0; i < 4; i++) { r[2*i] = d[i]; r[2*i+1] = s[i]; }\n    memcpy(&out, r, 16);\n    return out;\n}\n",
        );
    }
    if usa("packuswb") {
        corpi.push_str(
            "static unsigned __int128 packuswb(unsigned __int128 dst, unsigned __int128 src)\n{\n    int16_t d[8], s[8];\n    uint8_t r[16];\n    unsigned __int128 out;\n    int i, v;\n    memcpy(d, &dst, 16);\n    memcpy(s, &src, 16);\n    for (i = 0; i < 8; i++) { v = d[i]; r[i] = (uint8_t)(v < 0 ? 0 : (v > 255 ? 255 : v)); }\n    for (i = 0; i < 8; i++) { v = s[i]; r[8 + i] = (uint8_t)(v < 0 ? 0 : (v > 255 ? 255 : v)); }\n    memcpy(&out, r, 16);\n    return out;\n}\n",
        );
    }
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
    // #8280: il FRATELLO CON SEGNO, emesso da lift.rs:5219 (gestore IMUL) e
    // mai definito da nessuno. 14 occorrenze in 8 file su path B, zero su A.
    // Non e in ida_defs.h: gcc -w lo prende per dichiarazione implicita e il
    // file "compila", ma il LINK fallisce - la cecita di check.sh in purezza.
    // OF per IMUL: il prodotto a doppia larghezza non entra nella larghezza
    // singola CON SEGNO (il fratello senza segno guarda la meta alta != 0).
    if usa("imul_overflow") {
        corpi.push_str(
            "static uint32_t imul_overflow(uint32_t a, uint32_t b)\n{\n    long long p = (long long)(int)a * (long long)(int)b;\n    return (uint32_t)(p != (long long)(int)p);\n}\n",
        );
    }

    // -- #7090: le ausiliarie che BLOCCANO IL LINK ------------------------
    //
    // Misurato al §136: dopo aver chiuso `runtime_panicIndex`, i bucket Go e
    // Rust continuano a fallire il link — ma per queste. Non e' piu' solo un
    // difetto di leggibilita' come sembrava al §115: `cvtss2sd`, `aesenc` e
    // `lfence` sono il PRIMO simbolo mancante di piu' bucket comportamentali.
    //
    // Si definisce, come sempre, solo cio' che il modello a 64 bit scalari
    // rappresenta ESATTAMENTE. Le vettoriali restano fuori (vedi in fondo).

    // Barriere di memoria: nessun valore, nessun effetto sul modello. Il corpo
    // vuoto non e' un'approssimazione — e' la semantica completa per tutto cio'
    // che questo IR rappresenta.
    for nome in ["lfence", "sfence", "mfence"] {
        if usa(nome) {
            corpi.push_str(&format!(
                "static void {nome}(void)\n{{\n    /* barriera: nessun effetto sui valori modellati */\n}}\n"
            ));
        }
    }

    // `tzcnt(src)`: zeri in coda. A differenza di `bsf` la ISA la DEFINISCE per
    // operando zero — restituisce la larghezza — quindi qui non c'e' nessuna
    // scelta arbitraria da dichiarare.
    if usa("tzcnt") {
        corpi.push_str(
            "static uint32_t tzcnt(uint32_t src)\n{\n    uint32_t i;\n    if (!src) return 32; /* la ISA lo definisce: larghezza dell'operando */\n    for (i = 0; i < 32; i++) if (src & (1u << i)) return i;\n    return 32;\n}\n",
        );
    }

    // Conversioni SCALARI fra precisioni. I `var_xmm*` sono `uint64_t` che
    // portano i BIT del valore, come gia' assunto da `cvtsi2sd`; qui si sta
    // dentro i 64 bit bassi, quindi la conversione e' esatta.
    // ⚠ `cvtsi2ss`/`cvtss2sd` scrivono un `float` nei 32 bit BASSI: il resto
    // del registro la ISA lo lascia invariato, ma il modello non lo traccia e
    // nessuno lo legge nelle forme osservate.
    if usa("cvtsi2ss") {
        corpi.push_str(
            "static uint64_t cvtsi2ss(uint64_t dst, uint32_t src)\n{\n    float f = (float)(int)src;\n    uint32_t b;\n    memcpy(&b, &f, 4);\n    (void)dst;\n    return (uint64_t)b;\n}\n",
        );
    }
    if usa("cvtss2sd") {
        corpi.push_str(
            "static uint64_t cvtss2sd(uint64_t dst, uint64_t src)\n{\n    uint32_t b32 = (uint32_t)src;\n    float f;\n    double d;\n    uint64_t o;\n    memcpy(&f, &b32, 4);\n    d = (double)f;\n    memcpy(&o, &d, 8);\n    (void)dst;\n    return o;\n}\n",
        );
    }
    if usa("cvtsd2ss") {
        corpi.push_str(
            "static uint64_t cvtsd2ss(uint64_t dst, uint64_t src)\n{\n    double d;\n    float f;\n    uint32_t b;\n    memcpy(&d, &src, 8);\n    f = (float)d;\n    memcpy(&b, &f, 4);\n    (void)dst;\n    return (uint64_t)b;\n}\n",
        );
    }

    if usa("psrld") {
        corpi.push_str(
            "static unsigned __int128 psrld(unsigned __int128 src, uint32_t cnt)\n{\n    unsigned __int128 out = 0;\n    int i;\n    for (i = 0; i < 4; i++) {\n        uint32_t d = (uint32_t)(src >> (i * 32));\n        uint32_t r = (cnt > 31) ? 0u : (d >> cnt);\n        out |= ((unsigned __int128)r) << (i * 32);\n    }\n    return out;\n}\n",
        );
    }
    if usa("pslld") {
        corpi.push_str(
            "static unsigned __int128 pslld(unsigned __int128 src, uint32_t cnt)\n{\n    unsigned __int128 out = 0;\n    int i;\n    for (i = 0; i < 4; i++) {\n        uint32_t d = (uint32_t)(src >> (i * 32));\n        uint32_t r = (cnt > 31) ? 0u : (d << cnt);\n        out |= ((unsigned __int128)r) << (i * 32);\n    }\n    return out;\n}\n",
        );
    }
    if usa("prefetcht0") {
        corpi.push_str(
            "static void prefetcht0(uint64_t addr)\n{\n    (void)addr;\n}\n",
        );
    }
    if usa("vpminuq") {
        corpi.push_str(
            "static unsigned __int128 vpminuq(unsigned __int128 dst, unsigned __int128 a, unsigned __int128 b)\n{\n    uint64_t a0 = (uint64_t)a, a1 = (uint64_t)(a >> 64);\n    uint64_t b0 = (uint64_t)b, b1 = (uint64_t)(b >> 64);\n    uint64_t r0 = (a0 < b0) ? a0 : b0;\n    uint64_t r1 = (a1 < b1) ? a1 : b1;\n    (void)dst;\n    return ((unsigned __int128)r1 << 64) | (unsigned __int128)r0;\n}\n",
        );
    }
    if usa("aesenc") {
        corpi.push_str(
            "static uint8_t rustre_aes_sbox_[256] = {\n0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,\n0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,\n0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,\n0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,\n0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,\n0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,\n0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,\n0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,\n0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,\n0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,\n0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,\n0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,\n0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,\n0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,\n0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,\n0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };\n\nstatic uint8_t rustre_aes_xt_(uint8_t x)\n{\n    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));\n}\n\nstatic unsigned __int128 aesenc(unsigned __int128 state, unsigned __int128 key)\n{\n    uint8_t a[16], b[16], o[16];\n    unsigned __int128 out = 0;\n    int i, c;\n    for (i = 0; i < 16; i++) a[i] = (uint8_t)(state >> (i * 8));\n    for (c = 0; c < 4; c++)\n        for (i = 0; i < 4; i++)\n            b[i + 4 * c] = rustre_aes_sbox_[a[i + 4 * ((c + i) & 3)]];\n    for (c = 0; c < 4; c++) {\n        uint8_t s0 = b[4*c], s1 = b[4*c+1], s2 = b[4*c+2], s3 = b[4*c+3];\n        o[4*c]   = (uint8_t)(rustre_aes_xt_(s0) ^ (rustre_aes_xt_(s1) ^ s1) ^ s2 ^ s3);\n        o[4*c+1] = (uint8_t)(s0 ^ rustre_aes_xt_(s1) ^ (rustre_aes_xt_(s2) ^ s2) ^ s3);\n        o[4*c+2] = (uint8_t)(s0 ^ s1 ^ rustre_aes_xt_(s2) ^ (rustre_aes_xt_(s3) ^ s3));\n        o[4*c+3] = (uint8_t)((rustre_aes_xt_(s0) ^ s0) ^ s1 ^ s2 ^ rustre_aes_xt_(s3));\n    }\n    for (i = 0; i < 16; i++) out |= ((unsigned __int128)o[i]) << (i * 8);\n    return out ^ key;\n}\n",
        );
    }
    // ── #7220: aritmetica in virgola mobile SCALARE ────────────────────
    // Il lift x86 mandava `divsd` su `LlilExpr::DivU` — divisione INTERA
    // sui bit di due IEEE-754. Corretto alla radice
    // (`rustre-arch-x86/src/lift.rs`), qui vivono i corpi che la stampa
    // chiama. Stessa tecnica dei tre helper di conversione gia' in
    // produzione: reinterpreta con `memcpy`, opera nel tipo giusto,
    // reinterpreta indietro.
    // ⚠ Solo SCALARI (SS/SD): le impacchettate (PS/PD) restano intere
    // finche' non hanno una resa per corsia.
    if usa("addsd") {
        corpi.push_str(
            "static uint64_t addsd(uint64_t a, uint64_t b)\n{\n    double x, y;\n    uint64_t r;\n    memcpy(&x, &a, 8);\n    memcpy(&y, &b, 8);\n    x = x + y;\n    memcpy(&r, &x, 8);\n    return r;\n}\n",
        );
    }
    if usa("addss") {
        corpi.push_str(
            "static uint64_t addss(uint64_t a, uint64_t b)\n{\n    float x, y;\n    uint32_t r;\n    memcpy(&x, &a, 4);\n    memcpy(&y, &b, 4);\n    x = x + y;\n    memcpy(&r, &x, 4);\n    /* ISA: l'operazione SCALARE non tocca le corsie alte della destinazione */\n    return (a & ~(uint64_t)0xFFFFFFFF) | (uint64_t)r;\n}\n",
        );
    }
    if usa("subsd") {
        corpi.push_str(
            "static uint64_t subsd(uint64_t a, uint64_t b)\n{\n    double x, y;\n    uint64_t r;\n    memcpy(&x, &a, 8);\n    memcpy(&y, &b, 8);\n    x = x - y;\n    memcpy(&r, &x, 8);\n    return r;\n}\n",
        );
    }
    if usa("subss") {
        corpi.push_str(
            "static uint64_t subss(uint64_t a, uint64_t b)\n{\n    float x, y;\n    uint32_t r;\n    memcpy(&x, &a, 4);\n    memcpy(&y, &b, 4);\n    x = x - y;\n    memcpy(&r, &x, 4);\n    /* ISA: l'operazione SCALARE non tocca le corsie alte della destinazione */\n    return (a & ~(uint64_t)0xFFFFFFFF) | (uint64_t)r;\n}\n",
        );
    }
    if usa("mulsd") {
        corpi.push_str(
            "static uint64_t mulsd(uint64_t a, uint64_t b)\n{\n    double x, y;\n    uint64_t r;\n    memcpy(&x, &a, 8);\n    memcpy(&y, &b, 8);\n    x = x * y;\n    memcpy(&r, &x, 8);\n    return r;\n}\n",
        );
    }
    if usa("mulss") {
        corpi.push_str(
            "static uint64_t mulss(uint64_t a, uint64_t b)\n{\n    float x, y;\n    uint32_t r;\n    memcpy(&x, &a, 4);\n    memcpy(&y, &b, 4);\n    x = x * y;\n    memcpy(&r, &x, 4);\n    /* ISA: l'operazione SCALARE non tocca le corsie alte della destinazione */\n    return (a & ~(uint64_t)0xFFFFFFFF) | (uint64_t)r;\n}\n",
        );
    }
    if usa("divsd") {
        corpi.push_str(
            "static uint64_t divsd(uint64_t a, uint64_t b)\n{\n    double x, y;\n    uint64_t r;\n    memcpy(&x, &a, 8);\n    memcpy(&y, &b, 8);\n    x = x / y;\n    memcpy(&r, &x, 8);\n    return r;\n}\n",
        );
    }
    if usa("divss") {
        corpi.push_str(
            "static uint64_t divss(uint64_t a, uint64_t b)\n{\n    float x, y;\n    uint32_t r;\n    memcpy(&x, &a, 4);\n    memcpy(&y, &b, 4);\n    x = x / y;\n    memcpy(&r, &x, 4);\n    /* ISA: l'operazione SCALARE non tocca le corsie alte della destinazione */\n    return (a & ~(uint64_t)0xFFFFFFFF) | (uint64_t)r;\n}\n",
        );
    }
    // ── #7250: aritmetica impacchettata, per CORSIA ────────────────────
    // L'avvolgimento e' quello del tipo della corsia (`uint8_t` ecc.), che
    // e' esattamente la semantica ISA: ogni corsia avvolge da sola e il
    // riporto non passa alla successiva.
    // ⚠ Little-endian assunto nel `memcpy`, come per gli altri corpi a 128 bit.
    if usa("paddb") {
        corpi.push_str(
            "static unsigned __int128 paddb(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint8_t a[16], b[16];\n    int i;\n    memcpy(a, &dst, 16);\n    memcpy(b, &src, 16);\n    /* per CORSIA: il riporto NON attraversa il confine */\n    for (i = 0; i < 16; i++) a[i] = (uint8_t)(a[i] + b[i]);\n    memcpy(&dst, a, 16);\n    return dst;\n}\n",
        );
    }
    if usa("paddw") {
        corpi.push_str(
            "static unsigned __int128 paddw(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint16_t a[8], b[8];\n    int i;\n    memcpy(a, &dst, 16);\n    memcpy(b, &src, 16);\n    /* per CORSIA: il riporto NON attraversa il confine */\n    for (i = 0; i < 8; i++) a[i] = (uint16_t)(a[i] + b[i]);\n    memcpy(&dst, a, 16);\n    return dst;\n}\n",
        );
    }
    if usa("paddd") {
        corpi.push_str(
            "static unsigned __int128 paddd(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint32_t a[4], b[4];\n    int i;\n    memcpy(a, &dst, 16);\n    memcpy(b, &src, 16);\n    /* per CORSIA: il riporto NON attraversa il confine */\n    for (i = 0; i < 4; i++) a[i] = (uint32_t)(a[i] + b[i]);\n    memcpy(&dst, a, 16);\n    return dst;\n}\n",
        );
    }
    if usa("paddq") {
        corpi.push_str(
            "static unsigned __int128 paddq(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint64_t a[2], b[2];\n    int i;\n    memcpy(a, &dst, 16);\n    memcpy(b, &src, 16);\n    /* per CORSIA: il riporto NON attraversa il confine */\n    for (i = 0; i < 2; i++) a[i] = (uint64_t)(a[i] + b[i]);\n    memcpy(&dst, a, 16);\n    return dst;\n}\n",
        );
    }
    if usa("psubb") {
        corpi.push_str(
            "static unsigned __int128 psubb(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint8_t a[16], b[16];\n    int i;\n    memcpy(a, &dst, 16);\n    memcpy(b, &src, 16);\n    /* per CORSIA: il riporto NON attraversa il confine */\n    for (i = 0; i < 16; i++) a[i] = (uint8_t)(a[i] - b[i]);\n    memcpy(&dst, a, 16);\n    return dst;\n}\n",
        );
    }
    if usa("psubw") {
        corpi.push_str(
            "static unsigned __int128 psubw(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint16_t a[8], b[8];\n    int i;\n    memcpy(a, &dst, 16);\n    memcpy(b, &src, 16);\n    /* per CORSIA: il riporto NON attraversa il confine */\n    for (i = 0; i < 8; i++) a[i] = (uint16_t)(a[i] - b[i]);\n    memcpy(&dst, a, 16);\n    return dst;\n}\n",
        );
    }
    if usa("psubd") {
        corpi.push_str(
            "static unsigned __int128 psubd(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint32_t a[4], b[4];\n    int i;\n    memcpy(a, &dst, 16);\n    memcpy(b, &src, 16);\n    /* per CORSIA: il riporto NON attraversa il confine */\n    for (i = 0; i < 4; i++) a[i] = (uint32_t)(a[i] - b[i]);\n    memcpy(&dst, a, 16);\n    return dst;\n}\n",
        );
    }
    if usa("psubq") {
        corpi.push_str(
            "static unsigned __int128 psubq(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint64_t a[2], b[2];\n    int i;\n    memcpy(a, &dst, 16);\n    memcpy(b, &src, 16);\n    /* per CORSIA: il riporto NON attraversa il confine */\n    for (i = 0; i < 2; i++) a[i] = (uint64_t)(a[i] - b[i]);\n    memcpy(&dst, a, 16);\n    return dst;\n}\n",
        );
    }
    // ── #7260: i dieci helper che l'inventario ha fatto affiorare ──────
    // Ognuno verificato differenzialmente contro l'intrinseca `_mm_*`
    // corrispondente su 20000 coppie di vettori pseudo-casuali piu' i casi
    // degeneri (operandi uguali, zeri, NaN in prima e seconda posizione,
    // ±0, conteggi 0/4/7/63/64/99, float fuori intervallo): 0 discrepanze.
    //
    // ⚠ L'inventario dei simboli mancanti NON e' una lista fissa: si
    // riforma a ogni cambio di emissione. `psrlq` era gia' un'intrinseca
    // senza corpo (`lift.rs:1916`) ed e' emerso solo quando la classe si e'
    // assottigliata. Va rifatto dopo ogni intervento.
    if usa("pcmpeqd") {
        corpi.push_str(
            "static unsigned __int128 pcmpeqd(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint32_t a[4], b[4];\n    int i;\n    memcpy(a, &dst, 16);\n    memcpy(b, &src, 16);\n    for (i = 0; i < 4; i++) a[i] = (a[i] == b[i]) ? 0xFFFFFFFFu : 0x00000000u;\n    memcpy(&dst, a, 16);\n    return dst;\n}\n",
        );
    }
    if usa("psrlq") {
        corpi.push_str(
            "static unsigned __int128 psrlq(unsigned __int128 dst, int imm)\n{\n    uint64_t a[2];\n    int i;\n    memcpy(a, &dst, 16);\n    for (i = 0; i < 2; i++) a[i] = (imm >= 64 || imm < 0) ? (uint64_t)0 : (a[i] >> imm);\n    memcpy(&dst, a, 16);\n    return dst;\n}\n",
        );
    }
    if usa("paddusw") {
        corpi.push_str(
            "static unsigned __int128 paddusw(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint16_t a[8], b[8];\n    uint32_t v;\n    int i;\n    memcpy(a, &dst, 16);\n    memcpy(b, &src, 16);\n    for (i = 0; i < 8; i++) { v = (uint32_t)a[i] + (uint32_t)b[i]; a[i] = (uint16_t)(v > 0xFFFFu ? 0xFFFFu : v); }\n    memcpy(&dst, a, 16);\n    return dst;\n}\n",
        );
    }
    if usa("pshufb") {
        corpi.push_str(
            "static unsigned __int128 pshufb(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint8_t d[16], s[16], r[16];\n    int i;\n    memcpy(d, &dst, 16);\n    memcpy(s, &src, 16);\n    for (i = 0; i < 16; i++) r[i] = (s[i] & 0x80) ? 0x00 : d[s[i] & 0x0F];\n    memcpy(&dst, r, 16);\n    return dst;\n}\n",
        );
    }
    if usa("cvtps2pd") {
        corpi.push_str(
            "static unsigned __int128 cvtps2pd(unsigned __int128 dst, unsigned __int128 src)\n{\n    float f[4];\n    double d[2];\n    unsigned __int128 out;\n    memcpy(f, &src, 16);\n    d[0] = (double)f[0];\n    d[1] = (double)f[1];\n    memcpy(&out, d, 16);\n    (void)dst;\n    return out;\n}\n",
        );
    }
    if usa("minsd") {
        corpi.push_str(
            "static unsigned __int128 minsd(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint64_t x, y;\n    double a, b;\n    x = (uint64_t)dst; y = (uint64_t)src;\n    memcpy(&a, &x, 8);\n    memcpy(&b, &y, 8);\n    x = (a < b) ? x : y;\n    return ((dst >> 64) << 64) | (unsigned __int128)x;\n}\n",
        );
    }
    if usa("maxsd") {
        corpi.push_str(
            "static unsigned __int128 maxsd(unsigned __int128 dst, unsigned __int128 src)\n{\n    uint64_t x, y;\n    double a, b;\n    x = (uint64_t)dst; y = (uint64_t)src;\n    memcpy(&a, &x, 8);\n    memcpy(&b, &y, 8);\n    x = (a > b) ? x : y;\n    return ((dst >> 64) << 64) | (unsigned __int128)x;\n}\n",
        );
    }
    if usa("pminsw") {
        corpi.push_str(
            "static unsigned __int128 pminsw(unsigned __int128 dst, unsigned __int128 src)\n{\n    int16_t a[8], b[8];\n    int i;\n    memcpy(a, &dst, 16);\n    memcpy(b, &src, 16);\n    for (i = 0; i < 8; i++) a[i] = (a[i] < b[i]) ? a[i] : b[i];\n    memcpy(&dst, a, 16);\n    return dst;\n}\n",
        );
    }
    if usa("popcnt") {
        corpi.push_str(
            "static uint64_t popcnt(uint64_t src)\n{\n    uint64_t n = 0;\n    int i;\n    for (i = 0; i < 64; i++) if ((src >> i) & 1) n++;\n    return n;\n}\n",
        );
    }
    if usa("cvttss2si") {
        corpi.push_str(
            "static uint32_t cvttss2si(uint32_t dst, unsigned __int128 src)\n{\n    float f;\n    uint32_t bits = (uint32_t)(uint64_t)src;\n    memcpy(&f, &bits, 4);\n    (void)dst;\n    if (!(f > -2147483649.0f && f < 2147483648.0f)) return 0x80000000u;\n    return (uint32_t)(int)f;\n}\n",
        );
    }
    // ⛔ ESCLUSI DI PROPOSITO, e non per mancanza di tempo:
    //
    // ⚠ AGGIORNATO (#7200): `aesenc`, `packuswb`, `vpminuq`, `pcmpeqq` erano
    //   esclusi qui con la motivazione «leggono i 128 bit PIENI, che il modello
    //   a 64 bit bassi non rappresenta». **Quella premessa non vale piu'**:
    //   nell'albero emesso i `var_xmm*` sono dichiarati `unsigned __int128` e
    //   caricati con `*(unsigned __int128 *)…`. Il modello e' a larghezza
    //   piena, quindi i quattro sono esattamente definibili e ora lo sono.
    //   Resta escluso `punpckhqdq`, per una ragione DIVERSA e ancora valida:
    //   porta `dst.low = dst.high`, e sui siti dove il chiamante e' ancora
    //   `uint64_t` quel valore non esiste.
    //
    // `cpuid_eax/ebx/ecx/edx` (204 occorrenze) — definibili solo con asm inline
    //   x86 che RIESEGUE CPUID (esatto: CPUID e' una funzione pura di (EAX,ECX)
    //   sullo stesso processore logico). Tenuti fuori PER ORA perche' le quattro
    //   chiamate separate non sono atomiche come l'istruzione originale: sulle
    //   foglie di topologia 0x0B/0x1F e sull'APIC ID iniziale in EBX della
    //   foglia 1 una migrazione di thread fra le quattro darebbe una quadrupla
    //   incoerente. Le foglie osservate nel corpus (1, 0x80000000, 0x80000001)
    //   non hanno il problema: da riprendere con la misura in mano.
    // `__readgsqword` (1276) — NON definibile in C portabile. Solo asm inline
    //   x86-64 + Windows (GS = TEB). Tenuto fuori per ora perche' molti siti
    //   passano un NON-offset (`__readgsqword(a1)`, `__readgsqword(off_…)`):
    //   un corpo fedele li fa FAULTARE, il che e' l'esito giusto — espone un
    //   difetto di lift a monte invece di nasconderlo — ma sposterebbe dei
    //   LINK_FAIL su CRASH. ⛔ `return 0` NON e' l'alternativa: renderebbe ogni
    //   `*(__int64 *)(result + 1)` a valle un deref di NULL che SEMBRA un bug
    //   di dati. Meglio il link rotto di un numero sbagliato.
    // `__thread_context` — stesso simbolo, grafia a operando di memoria; e' un
    //   DATO non definito, non una funzione. Rimedio diverso.
    //   Misurato: 2172 `extern`, ZERO definizioni, e usato solo come
    //   `*(__int64 *)(__thread_context + 16)` (confronto col limite di stack).
    //   ⇒ derivare `__readgsqword` da lui NON aggiusterebbe il link: sposterebbe
    //   il fallimento su un altro simbolo indefinito, inventando anche la base.
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
    // ── #8020: non riscrivere IN LOCO una dichiarazione finita dentro il corpo
    //
    // Questa passata trasforma `… X();` in `extern __int64 __imp_X;` **sul
    // posto**. Se la riga di partenza era gia' dentro il corpo — inserita li'
    // da una passata precedente — la forma dato eredita la posizione
    // sbagliata, e il risultato e' un `extern` a colonna 0 in mezzo agli
    // statement:
    //
    //     v9 = (__int64)&_gnu_exception_handler;
    //     extern __int64 __imp_SetUnhandledExceptionFilter;   <-- qui
    //
    // MISURATO su `runs/pathb_first`: **391 righe in 155 file**, 8 bucket;
    // path A **zero**. `gcc -std=gnu89` le accetta come estensione, quindi non
    // e' un fallimento di compilazione — e' codice non conforme a C89.
    //
    // ⚠ PRECONDIZIONE MISURATA: **391 su 391** sono DUPLICATI di una
    // dichiarazione identica gia' presente in TESTA allo stesso file; **zero**
    // sono uniche. Sopprimere quella interna non perde nulla.
    //
    // ⚠ Un primo tentativo (#8010) filtrava in `prepend_hlil_externs`: era
    // **inerte** (391 prima, 391 dopo) perche' quella funzione gira PRIMA di
    // questa. Ritirato — un predicato che no-oppa e' un bug.
    let mut prof: i32 = 0;
    let mut viste: std::collections::HashSet<String> = std::collections::HashSet::new();
    out.lines()
        .filter_map(|riga| {
            let t = riga.trim();
            let apre = i32::try_from(riga.matches('{').count()).unwrap_or(0);
            let chiude = i32::try_from(riga.matches('}').count()).unwrap_or(0);
            let dentro = prof > 0;
            prof += apre - chiude;
            let _ = dentro;
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
                    let decl = format!("extern __int64 {ident};");
                    // #8020: dentro il corpo e gia' dichiarata in testa ⇒ la
                    // riga sparisce invece di essere riscritta sul posto.
                    if dentro && viste.contains(&decl) {
                        // #8020b: la riga va SCARTATA, non svuotata. Svuotarla
                        // chiudeva il difetto di forma ma lasciava 391 righe
                        // bianche (misurato: vuote 1185 -> 1410 su sample7_cpp).
                        return None;
                    }
                    viste.insert(decl.clone());
                    return Some(decl);
                }
            }
            // #7790 - la DEFINIZIONE dello slot, che questa stessa passata
            // stava fabbricando contro il proprio docstring.
            //
            // Il commento sopra (riga ~1747) dice che materializzare i byte di
            // uno slot IAT «sarebbe SBAGLIATO — il loader ci scrive dentro
            // l'indirizzo vero a runtime, quindi i byte del file sono un
            // segnaposto: linkerebbe e darebbe numeri sbagliati, cioe' peggio
            // di un LINK_FAIL». Ed e' esattamente cio' che accadeva: la
            // riscrittura del token qui sopra trasforma
            //
            //     static uint8_t off_140099038[64] = { … };   (da `data_symbol_definitions`)
            // in
            //     static uint8_t __imp_NtWriteFile[64] = { … };
            //
            // cioe' DEFINISCE lo slot con i byte del file. Il link riesce, e il
            // programma legge l'RVA del nome invece dell'indirizzo della
            // funzione: un difetto che **nessuna metrica statica puo' vedere**.
            //
            // MISURATO: 557 definizioni, **557 usate** (100%), ognuna con
            // almeno una lettura `*(__int64 *)&__imp_X`. In path A: ZERO.
            //
            // La cura sta QUI e non altrove per una ragione d'ordine: la
            // definizione diventa dichiarazione nella STESSA riscrittura che
            // l'ha creata, quindi non esiste un istante in cui una lettura
            // resti senza simbolo. Toglierla prima, altrove, trasformerebbe un
            // difetto silenzioso in un LINK_FAIL nuovo.
            //
            // Le letture non si toccano: con `extern __int64 __imp_X;` la
            // forma `*(__int64 *)(__int64)&__imp_X` legge il valore che il
            // loader scrive, che e' il comportamento corretto.
            if let Some(resto) = t.strip_prefix("static uint8_t __imp_") {
                let ident: String = resto
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !ident.is_empty() && resto[ident.len()..].starts_with('[') {
                    return Some(format!("extern __int64 __imp_{ident};"));
                }
            }
            Some(riga.to_string())
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
    // #8840 - definisce su PATH A le tabelle di puntatori a funzione che il
    // testo indicizza ancora.
    //
    // I tre `dispatch` LINK_FAIL della misura 1300 sono bloccati da UN solo
    // simbolo: `off_140004000`, una tabella di puntatori letta come `v3[a1]` e
    // chiamata. `data_symbol_definitions` la esclude per la guardia #5700, che
    // rifiuta di definire le BASI DI TABELLA risolte - regola SOLIDA per le
    // tabelle di SALTO (voci rel32 relative alla base originale: in un array
    // locale puntano altrove) ma la cui premessa implicita e' che, risolto lo
    // switch, la base sia morta. Per una tabella di CHIAMATE la premessa non
    // vale: l'indicizzazione resta e il simbolo resta irrisolto.
    //
    // CONDIZIONE STRETTA, e non e' prudenza generica: definire una base
    // referenziata "e vediamo" trasformerebbe alcuni LINK_FAIL in codice che
    // LINKA e salta in memoria arbitraria - un difetto silenzioso al posto di
    // uno rumoroso. Si definisce SOLO se OGNI cella da 8 byte risolve a una
    // funzione emessa: allora la tabella e' corretta per costruzione.
    //
    // Stessa disciplina di #7800b (gli alias ICF): si emette solo per i
    // simboli che qualcuno usa davvero, non "tutti quelli che si possono".
    let fnptr_a = gate_acceso("RUSTRE_FNPTR_TABLE_A");
    let immagine_a = if fnptr_a {
        crate::binary_entry::load_binary(binary_path).ok()
    } else {
        None
    };
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
    // #7800 - gli alias ICF. Stessa disciplina degli import: il binario si
    // rilegge SOLO col gate acceso, cosi' a gate spento il costo e' zero e il
    // braccio di controllo resta byte-identico.
    let icf = gate_acceso("RUSTRE_ICF_ALIAS");
    // #7800b - l'alias si emette SOLO se qualcuno chiama quel nome.
    //
    // La v1 li emetteva tutti: 145 su `rust3_O0`, ma **solo 17 referenziati**.
    // I 128 inutili non erano innocui — misurato: compile failures 45 -> 81.
    // Due modi di rompere, entrambi provati con gcc:
    //
    //   `conflicting types for '_get_invalid_parameter_handler'`
    //        il nome e' gia' DICHIARATO dalle intestazioni (via <stdlib.h>,
    //        che <emmintrin.h> tira dentro);
    //   `multiple definition of '_get_invalid_parameter_handler'`
    //        il nome e' gia' DEFINITO dalla CRT — e allora il riferimento si
    //        risolveva gia' da solo, l'alias era puro danno.
    //
    // L'etichetta asm risolve il primo (compila) ma NON il secondo: definire un
    // simbolo che la libreria fornisce e' sbagliato comunque.
    //
    // ⇒ Il criterio giusto non e' «esiste un alias» ma «qualcuno lo chiama e
    // nessuno lo definisce». Se il nome e' referenziato e irrisolto, allora la
    // libreria NON lo fornisce (altrimenti il link passerebbe gia'), e l'alias
    // e' l'unica cosa che puo' chiuderlo. Precisione e sicurezza coincidono.
    let chiamati: std::collections::HashSet<String> = if icf {
        let mut s = std::collections::HashSet::new();
        for f in &result.functions {
            for testo in [
                f.pseudo_code.as_str(),
                f.hlil_pseudo_code.as_deref().unwrap_or(""),
            ] {
                for riga in testo.lines() {
                    let t = riga.trim_start();
                    // Una DICHIARAZIONE `__int64 nome();` e' proprio il segno
                    // che il nome serve e non e' definito qui.
                    if let Some(resto) = t.strip_suffix("();")
                        && let Some(nome) = resto.rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).next()
                        && !nome.is_empty()
                    {
                        s.insert(nome.to_string());
                    }
                }
            }
        }
        s
    } else {
        std::collections::HashSet::new()
    };
    let alias_per_va: HashMap<u64, Vec<String>> = if icf {
        crate::binary_entry::load_binary(binary_path)
            .map_or_else(|_| HashMap::new(), |load| {
                crate::binary_entry::alias_names_by_addr(&load)
            })
    } else {
        HashMap::new()
    };
    let path_b_unico = std::env::var("RUSTRE_PATH_B_UNICO").as_deref() == Ok("1");
    for func in &result.functions {
        let path = out_dir.join(format!("{:#x}.c", func.address).replace("0x", "sub_"));
        // #8160 - la scrittura del DELIVERABLE e' spostata DOPO il blocco path B,
        // perche' il testo di B esiste solo alla fine di quella catena. Con il gate
        // spento cio' che finisce in `sub_HEX.c` resta `func.pseudo_code`, byte per
        // byte come prima: lo spostamento da solo non cambia nulla.
        //
        // Gli ingressi della catena B sono definiti a 2262-2350, cioe' PRIMA di
        // questo ciclo: sono invarianti di ciclo, quindi spostare la catena non
        // cambia cio' che legge. Verificato riga per riga, non a campione.
        let mut testo_b: Option<String> = None;
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
            // #7800 - alias per i nomi che l'ICF ha fuso su questo indirizzo.
            //
            // Il linker fonde funzioni identiche: allo stesso indirizzo restano
            // piu' simboli COFF, la definizione viene emessa sotto UNO dei nomi
            // e i call site che usano l'ALTRO restano senza definizione ⇒
            // LINK_FAIL. `load.symbols` li conserva tutti; a perderli e'
            // `name_of`, che fa `.find(|s| s.addr == va)` e tiene il primo.
            //
            // La forma e' verificata con gcc PRIMA di scriverla:
            //     __int64 nome_alias(void) __attribute__((alias("nome_reale")));
            // compila, linka, ed esegue la funzione giusta su mingw.
            //
            // ⚠ Solo se il nome emesso e' fra quelli noti a quell'indirizzo:
            // altrimenti l'alias punterebbe a un simbolo che questo file non
            // definisce, trasformando un LINK_FAIL in un errore di
            // compilazione — peggio, non meglio.
            // #7890 - la RICORSIONE col nome grezzo: alias invece di rename.
            //
            // Caso misurato (`sample7_cpp/sub_140002950.hlil.c`): il file
            //   DEFINISCE   `void d_count_templates_scopes(uint64_t, uint64_t)`
            //   DICHIARA    `__int64 sub_140002950();`
            //   CHIAMA      `v2 = sub_140002950(a1, a2);`
            // cioe' chiama SE STESSO col nome grezzo ⇒ simbolo indefinito.
            //
            // La catena era CIRCOLARE: `rename_hlil_sub_symbols` non rinomina
            // perche' il bersaglio e' `void` e il sito ASSEGNA (rinominare
            // darebbe «void value not ignored»); `repair_return_void_call` non
            // ripara perche' il nome non e' ancora legato alla definizione.
            // Ognuna aspetta l'altra.
            //
            // L'alias rompe il circolo **senza toccare il sito di chiamata**,
            // che e' il punto: l'assegnazione non e' inventata — l'emittitore
            // la deriva dal codice macchina, che legge davvero `rax` dopo la
            // `call`. Cambiarla richiederebbe di sapere cosa contiene, cioe' un
            // dato che lo statico non ha.
            //
            // Forma verificata con gcc PRIMA di scriverla, nel caso REALE (con
            // la dichiarazione gia' presente nel testo e il bersaglio `void`):
            //     __int64 sub_140002950() __attribute__((alias("d_count_…")));
            // compila, assembla e linka; e le parentesi VUOTE sono necessarie —
            // un prototipo `(void)` rifiuterebbe la chiamata a due argomenti.
            let hlil = if icf
                && let Some(e) = nome_definizione(&hlil)
                && !e.starts_with("sub_")
            {
                let mut testa = String::new();
                // ⚠ Le due grafie COINCIDONO quando l'esadecimale non ha
                // lettere (`sub_140002950`), e senza dedup l'alias uscirebbe
                // DUE volte — una ridefinizione, cioe' un errore di
                // compilazione al posto di un LINK_FAIL. Trovato alla prima
                // corsa, non ragionandoci.
                let mut grafie = vec![
                    format!("sub_{:X}", func.address),
                    format!("sub_{:x}", func.address),
                ];
                grafie.dedup();
                for grafia in grafie {
                    if hlil.contains(&format!("__int64 {grafia}();"))
                        && !hlil.contains(&format!("{grafia}() __attribute__"))
                    {
                        testa.push_str(&format!(
                            "__int64 {grafia}() __attribute__((alias(\"{e}\")));
"
                        ));
                    }
                }
                if testa.is_empty() {
                    hlil
                } else {
                    testa.push_str(&hlil);
                    testa
                }
            } else {
                hlil
            };
            let hlil = match alias_per_va.get(&func.address) {
                Some(nomi) => {
                    let emesso = nome_definizione(&hlil);
                    match emesso {
                        Some(e) if nomi.iter().any(|n| n.as_str() == e.as_str()) => {
                            let mut testa = String::new();
                            for n in nomi
                                .iter()
                                .filter(|n| n.as_str() != e.as_str() && chiamati.contains(n.as_str()))
                            {
                                testa.push_str(&format!(
                                    "__int64 {n}(void) __attribute__((alias(\"{e}\")));
"
                                ));
                            }
                            testa.push_str(&hlil);
                            testa
                        }
                        _ => hlil,
                    }
                }
                None => hlil,
            };
            // #7750d - il thunk IAT risolto come lo risolve path A.
            //
            // ⚠ La POSIZIONE e' il fix, non la logica. Tre cablaggi in
            // `lib.rs` sono usciti INERTI (2548 -> 2548, misurato due volte) e
            // la sonda `RUSTRE_DBG_IAT` ha chiuso la questione in una corsa:
            // al punto della prima fase la passata vedeva 203 `__imp_` su
            // `rust3_O0` e ne trasformava **0**, perche' erano tutte
            // sottostringhe di nomi Rust (`core__num__imp__bignum__…`). Gli
            // slot IAT veri non esistevano ancora: li produce
            // `rename_import_slots`, QUI, in fase di scrittura.
            //
            // Regola: una passata che consuma una grafia va DOPO il suo
            // produttore, e il produttore si trova misurando, non leggendo.
            //
            // Trasformazione (oracolo: path A emette gia' `NtWriteFile();` per
            // lo stesso indirizzo e LINKA):
            //     ((__int64 (*)())(*(__int64 *)__imp_N))()  ->  N()
            // ⛔ #7750 REVOCATO — misurato DANNOSO, gate ora opt-in e SPENTO.
            //
            // La trasformazione funziona (2548 thunk -> 0, verificato) ma il
            // suo effetto complessivo e' NEGATIVO:
            //
            // | | prima | dopo |
            // |---|---|---|
            // | compile failures | 45 | **283** (+238) |
            // | objects linked | 22844 | 22606 (-238) |
            // | AGREE | 45/63 | **45/63** |
            //
            // Peggiorati **20 bucket su 20**. Causa: le CRT che ritornano
            // `void` - `return exit();` e simili non compilano.
            //
            // ⚠ Ma il difetto di METODO viene prima: la premessa era che il
            // nome nudo LINKI, dedotta dal fatto che path A emette
            // `NtWriteFile();`. **Mai verificata** — `behavior.py` misura path
            // B, quindi non avevo alcuna prova che quella forma linki. E
            // infatti no: dopo il fix i bloccanti passano da `__imp_NtWriteFile`
            // a `NtWriteFile`, cioe' cambiano NOME e restano.
            //
            // Un «oracolo» che non e' stato misurato non e' un oracolo.
            //
            // Il codice e i test restano: la trasformazione e' corretta in se'
            // e servira' quando ci sara' una vera risoluzione degli import
            // (dichiarazioni + libreria), non prima.
            // ⛔ #7750 SPENTO — due forme provate, **entrambe** dannose, e il
            // motivo e' lo stesso: manca la DICHIARAZIONE del nome.
            //
            // | forma | nome NON dichiarato | nome dichiarato (CRT) |
            // |---|---|---|
            // | `NAME()` | compila (dichiarazione implicita) | `too few arguments` |
            // | `((T(*)())NAME)()` | **`undeclared`** | compila |
            //
            // Misurato sul corpus, compile failures partendo da **45**:
            // la prima forma **283**, la seconda **957**. Provato con gcc, non
            // dedotto: un nome nudo usato come VALORE (e non come chiamata) non
            // gode della dichiarazione implicita di gnu89.
            //
            // ⚠ Ma la trasformazione FUNZIONA: dopo di essa i bloccanti
            // `__imp_NtWriteFile` &c. **spariscono** dall'elenco di
            // `accumulate`, e sotto emerge lo strato successivo (simboli Rust
            // non emessi). Il fronte non e' chiuso, e' **sbucciato**.
            //
            // Prerequisito mancante, ora esplicito: emettere una
            // DICHIARAZIONE per ogni import risolto. Finche' non c'e',
            // riscrivere la forma sposta il difetto invece di toglierlo.
            // #7760 - riacceso con l'ALIAS ASM, che toglie il prerequisito
            // invece di aggirarlo: la dichiarazione usa un nome NOSTRO
            // (`rustre_imp_X`) con `__asm__("X")`, quindi non puo' confliggere
            // con nessuna intestazione e il linker risolve `X` come sempre.
            // Verificato con gcc su CRT gia' dichiarata, WinAPI e NT: compila
            // E linka.
            let hlil = if matches!(
                std::env::var("RUSTRE_HLIL_IAT").as_deref(),
                Ok("0") | Ok("false")
            ) {
                hlil
            } else {
                crate::resolve_iat_thunks_hlil(&hlil)
            };
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
            // #8180, OPT-IN `RUSTRE_DECL_CONCORDA=1`: rete di riparazione, e sta
            // QUI perche' deve girare dopo OGNI produttore di dichiarazioni.
            let hlil = if std::env::var("RUSTRE_DECL_CONCORDA").as_deref() == Ok("1") {
                concorda_dichiarazioni(&hlil)
            } else {
                hlil
            };
            // #8250, OPT-IN `RUSTRE_HLIL_RETURN_FIX=1`: gli 823 `return;`
            // nudi in funzioni non-void. path A ne ha ZERO perche'
            // `text_pass!` scrive sempre `pseudo_code`; path B non vede
            // mai queste passate. Sta QUI, ultimo, per la stessa ragione
            // di #8180: una riparazione sintattica fuori posto no-oppa.
            //
            // Solo `fix_return_statement_consistency`, NON
            // `rewrite_bare_return_with_value`: quella cerca `rax`/`eax`
            // GREZZI e gira prima delle rinomine, qui sarebbe inerte.
            let hlil = if std::env::var("RUSTRE_HLIL_RETURN_FIX").as_deref() == Ok("1") {
                crate::fix_return_statement_consistency(&hlil)
            } else {
                hlil
            };
            // #8300: il terminatore di riga finale.
            //
            // MISURATO 29-08: path A emette 12558 file su 12558 SENZA newline
            // finale, path B 12558 su 12558 CON. In C89 - lo standard che
            // check.sh usa (-std=gnu89) - un sorgente che non termina con
            // newline e' comportamento indefinito.
            //
            // La causa non e' una passata: `lib.rs` ha 142 occorrenze di
            // `.join("\n")`, e `code.lines()` scarta il terminatore.
            // Correggerne una non basta: si normalizza QUI, all'unico punto
            // da cui il testo esce.
            // #8590: una funzione DEFINITA qui non va anche dichiarata.
            // Stesso punto e stessa ragione di #8500e: e' l'unico posto dove il
            // testo e' completo, e la dichiarazione da togliere e' emessa da una
            // passata diversa da quella che scrive la definizione.
            // #8920 - INCIDENTE 2026-08-31: `lib.rs` azzerato da un errore di
            // scrittura (Python tronca il file PRIMA di valutare l'argomento di
            // `write`; l'eccezione e' arrivata dopo). Backup piu' recente: 29-08,
            // e git non ha nulla di piu' fresco. Le tre funzioni
            // `drop_decl_when_defined`, `drop_dead_data_ptr_stores` e
            // `ripara_chiamate_a_dati` erano state aggiunte DOPO il 29-08 e non
            // sono recuperabili da nessuna fonte.
            //
            // Le chiamate sono SCABLATE. Costo sul comportamento predefinito:
            // ZERO - tutti e tre i gate erano opt-in (assente = spento), quindi il
            // ramo attivo era gia' l'`else`. Vanno riscritte; i commenti che ne
            // descrivono lo scopo sono rimasti apposta qui sotto.
            // #8500e - la riparazione dei riferimenti a dati va QUI, non in
            // `lib.rs`. La catena di path B ha DUE tratti: quello di `lib.rs`
            // finisce con l'annotazione `hlil_pseudo_code`, e da li' riparte
            // qui con `materialize_fnptr_tables` (che EMETTE la definizione
            // `static void *off_X[N]`), `declare_renamed_imports` e altre.
            // Cablata alla fine del primo tratto veniva scavalcata da tutte
            // queste - misurato: effetto ZERO.
            //
            // Questo e' l'unico punto da cui il testo esce, come dice il
            // commento qui sotto per la newline finale.
            // #8640 -- via i `V = (__int64)&off_X;` morti che restano dopo la
            // riscrittura dello switch: non fanno nulla e rendono il file non
            // linkabile. DOPO le passate che li rendono morti, mai prima.
            // #8920 - vedi sopra: scablate, gate opt-in, costo zero.
            let hlil = if hlil.ends_with('\n') { hlil } else { hlil + "\n" };
            if let Err(e) = fs::write(&hlil_path, &hlil) {
                result.diagnostics.push(DecompilerDiagnostic {
                    severity: DiagnosticSeverity::Warning,
                    address: Some(func.address),
                    message: format!("write {}: {e}", hlil_path.display()),
                    pass: None,
                });
            }
            // Il gemello `.hlil.c` continua a essere scritto ANCHE quando B e' il
            // deliverable: senza, il protocollo non potrebbe piu' misurare una
            // regressione della commutazione stessa.
            testo_b = Some(hlil);
        }
        // #8160 - scelta del deliverable.
        //
        // Misurato (`runs/ab_0828`, stesso albero, letture appaiate):
        //   comportamento   A 15/62 (24,2%)   B 47/62 (75,8%)   3,13x
        //   arita           A 120/135         B 124/135  (over 6 -> 2)
        //   firme duplicate A 4               B 0
        //   irrisolti az.   A 3476            B 22       (158x)
        //   simboli dato    A 8145            B 26061    (3,2x)
        //   cross-build     A 4/1688 (0,24%)  B 4/2083 (0,19%)
        //   code_as_data    A 0               B 2        <- l'unica a favore di A
        //
        // OPT-IN `RUSTRE_PATH_B_UNICO=1`, default OFF: cambia il DELIVERABLE, che e'
        // la decisione piu' invasiva possibile in questo crate.
        // #8840 - vedi il commento al gate: si definiscono le tabelle di
        // puntatori a funzione che il testo di A indicizza ancora.
        let testo_a = definisci_tabelle_fnptr_a(
            &func.pseudo_code,
            immagine_a.as_ref(),
            &nomi_per_va,
        );
        // #8900 - gli ALIAS ICF anche su path A.
        //
        // Il blocco che li emette esisteva ed era applicato SOLO a `hlil`:
        // occorrenze di `__attribute__((alias` su `pseudo_code` = ZERO.
        // Misurato su `cpp_sample7_O0` (path A): **0 alias emessi** e 36
        // riferimenti irrisolti dalle sole `operator new`/`operator delete`.
        //
        // La doppia grafia e' VOLUTA (#7880): la DEFINIZIONE porta la forma
        // tagliata alla `(` (un nome con `(args)` romperebbe i parser di
        // firma), i RIFERIMENTI quella completa coi tipi. L'alias asm e' il
        // ponte, e a path A mancava.
        //
        // La guardia di #7800b vale identica qui, e per fortuna: `chiamati`
        // e' costruito da ENTRAMBI i testi (`pseudo_code` E
        // `hlil_pseudo_code`), quindi copre gia' i nomi che path A chiama.
        // Emettere un alias per un nome NON chiamato non e' innocuo: la v1 di
        // #7800 lo fece e i compile failures passarono da 45 a 81.
        let testo_a = match (icf, alias_per_va.get(&func.address)) {
            (true, Some(nomi)) => match nome_definizione(&testo_a) {
                Some(e) if nomi.iter().any(|n| n.as_str() == e.as_str()) => {
                    let mut testa = String::new();
                    for n in nomi
                        .iter()
                        .filter(|n| n.as_str() != e.as_str() && chiamati.contains(n.as_str()))
                    {
                        testa.push_str(&format!(
                            "__int64 {n}(void) __attribute__((alias(\"{e}\")));
"
                        ));
                    }
                    if testa.is_empty() {
                        testo_a
                    } else {
                        testa.push_str(&testo_a);
                        testa
                    }
                }
                _ => testo_a,
            },
            _ => testo_a,
        };
        let deliverable: &str = match (&testo_b, path_b_unico) {
            (Some(t), true) => t.as_str(),
            _ => testo_a.as_str(),
        };
        // #8300: stesso terminatore per path A. Deroga CONSAPEVOLE a REGOLA
        // #28 (path A byte-identico): il cambiamento e' DELIBERATAMENTE
        // CONDIVISO e chiude un difetto che riguarda il 100% dei file di A.
        let deliverable_nl;
        let deliverable: &str = if deliverable.ends_with('\n') {
            deliverable
        } else {
            deliverable_nl = format!("{deliverable}\n");
            &deliverable_nl
        };
        if let Err(e) = fs::write(&path, deliverable) {
            result.diagnostics.push(DecompilerDiagnostic {
                severity: DiagnosticSeverity::Warning,
                address: Some(func.address),
                message: format!("write {}: {e}", path.display()),
                pass: None,
            });
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
    // #8700 - sonda a effetto ZERO (`RUSTRE_DBG_SRC`): quale SORGENTE ha
    // promosso ogni indirizzo a funzione. Serve a trovare chi crea i 115
    // ingressi CONTENUTI dentro altre funzioni (round 1265-1267): non hanno
    // prologo, non sono bersaglio di call, non stanno nei simboli ne in
    // .pdata. Cercare la riga nel sorgente e costato tre giri a vuoto; la
    // sonda chiede direttamente al rilevatore.
    if std::env::var("RUSTRE_DBG_SRC").is_ok_and(|v| v != "0") {
        for b in &boundaries {
            eprintln!("[src] {:#x} {:?} {:?}", b.start.0, b.source, b.confidence);
        }
    }
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
        // #7400 - scarta gli inizi di funzione CONTRADDETTI da `.pdata`.
        //
        // Un indirizzo strettamente dentro `(begin, end)` di una
        // `RUNTIME_FUNCTION`, senza esserne il `begin`, e' un blocco interno.
        // Registrarlo come inizio accorcia `scan_cap` dell ospite (che e' la
        // distanza dal prossimo inizio) e la **tronca**: misurato, una funzione
        // Go di ~300 istruzioni emessa in **5 righe**, col corpo vero finito in
        // un file a parte di 405 righe.
        //
        // Il filtro va QUI e non piu' a valle: sia `filtered` (quali funzioni
        // si emettono) sia `all_starts_sorted` (che produce `next_fn_start` e
        // quindi `scan_cap`) derivano da `boundaries` in questo stesso blocco.
        // Filtrando una volta si evita anche di lasciare lo spurio emesso con
        // dentro il corpo dell ospite, cioe' lo STESSO codice in due file.
        //
        // ⚠ Il `begin` non si scarta MAI: e' una funzione dichiarata dal
        // compilatore. E gli indirizzi FUORI da ogni range `.pdata` restano
        // intatti — la' il criterio e' muto (319/467/103 nei tre bucket
        // misurati), e le foglie senza unwind info stanno proprio li'.
        //
        // Taglia misurata: **762/55/18** inizi spuri ⇒ **753/38/17** funzioni
        // de-troncate (in Go il **53,6%** di quelle dichiarate in `.pdata`).
        let scarta_interni = !matches!(
            std::env::var("RUSTRE_PDATA_FILTER_STARTS").as_deref(),
            Ok("0") | Ok("false")
        );
        let boundaries: Vec<_> = if scarta_interni {
            boundaries
                .into_iter()
                .filter(|fb| !crate::binary_entry::pdata_is_interior(&load, fb.start.as_u64()))
                .collect()
        } else {
            boundaries
        };
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

    /// #8020b: una dichiarazione DUPLICATA che cade DENTRO il corpo non viene
    /// riscritta sul posto — sparisce.
    ///
    /// MISURATO su `runs/pathb_first`: **391 righe in 155 file** di path B
    /// avevano un `extern __int64 __imp_X;` a colonna 0 in mezzo agli
    /// statement (path A: zero). `gcc -std=gnu89` le accetta come estensione,
    /// quindi nessuna metrica di ricompilabilita' le vedeva.
    ///
    /// **391 su 391 erano duplicati** di una dichiarazione gia' in testa: la
    /// soppressione non perde nulla. Questo test fissa entrambe le meta' —
    /// quella in testa RESTA, quella nel corpo SPARISCE.
    #[test]
    fn imp_slot_duplicato_dentro_il_corpo_sparisce() {
        let code = "__int64 sub_14003B3E0();
void f()
{
    v = 1;
__int64 sub_14003B3E0();
    v = sub_14003B3E0;
}
";
        let out = rename_import_slots(code, &mappa_imp(), true);
        assert_eq!(
            out.matches("extern __int64 __imp_CreateSemaphoreA;").count(),
            1,
            "la copia in testa resta, quella nel corpo sparisce: {out}"
        );
        // e non lascia una riga bianca al suo posto
        assert!(!out.contains("

    v = sub"), "riga vuota residua: {out}");
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

#[cfg(test)]
mod test_7790_slot_iat_non_definito {
    use super::rename_import_slots;
    use std::collections::HashMap;

    fn mappa() -> HashMap<u64, String> {
        let mut m = HashMap::new();
        m.insert(0x140099038u64, "NtWriteFile".to_string());
        m
    }

    #[test]
    fn la_definizione_diventa_dichiarazione() {
        // Il difetto: la riscrittura del token trasformava la definizione dati
        // in una DEFINIZIONE dello slot IAT, che linka e da' il valore
        // sbagliato — contro il docstring della passata stessa.
        let c = "static uint8_t off_140099038[64] = { 0x01, 0x02 };\n";
        let o = rename_import_slots(c, &mappa(), true);
        assert_eq!(o.trim(), "extern __int64 __imp_NtWriteFile;", "{o}");
        assert!(!o.contains("static uint8_t"), "definizione sopravvissuta: {o}");
    }

    #[test]
    fn la_lettura_resta_intatta() {
        // Le letture non vanno toccate: con la dichiarazione, la forma legge
        // il valore che il loader scrive.
        let c = "    v5 = *(__int64 *)(__int64)&off_140099038;\n";
        let o = rename_import_slots(c, &mappa(), true);
        assert!(o.contains("&__imp_NtWriteFile"), "{o}");
    }

    #[test]
    fn un_array_che_NON_e_uno_slot_non_si_tocca() {
        // Un dato vero, non presente nella mappa degli import, resta definito:
        // toglierne la definizione lo trasformerebbe in un LINK_FAIL nuovo.
        let c = "static uint8_t off_140004000[64] = { 0x20 };\n";
        let o = rename_import_slots(c, &mappa(), true);
        assert_eq!(o, c, "un dato non-import e' stato toccato: {o}");
    }

    #[test]
    fn gate_spento_e_identita() {
        let c = "static uint8_t off_140099038[64] = { 0x01 };\n";
        assert_eq!(rename_import_slots(c, &mappa(), false), c);
    }
}

#[cfg(test)]
mod test_7840_unpack_mancanti {
    use super::define_simd_bodies;

    #[test]
    fn i_tre_usati_vengono_definiti() {
        for n in ["punpckldq", "punpckhbw", "punpckhqdq"] {
            let c = format!("__int64 f(void)\n{{\n    v = {n}(a, b);\n}}\n");
            let o = define_simd_bodies(&c, true);
            assert!(
                o.contains(&format!("static unsigned __int128 {n}(")),
                "{n} non definita: {o}"
            );
        }
    }

    #[test]
    fn cio_che_nessuno_usa_non_si_definisce() {
        // La regola pagata da #7800 (+36 compile failures per 128 definizioni
        // inutili): si definisce solo cio' che il file USA.
        let c = "__int64 f(void)\n{\n    v = punpckldq(a, b);\n}\n";
        let o = define_simd_bodies(c, true);
        assert!(!o.contains("punpckhbw("), "definita una helper non usata: {o}");
        assert!(!o.contains("punpckhqdq("), "{o}");
    }

    #[test]
    fn la_semantica_e_LOW_contro_HIGH() {
        // `punpckldq` prende le corsie BASSE, `punpckhqdq` le ALTE: se le due
        // fossero copiate l'una dall'altra il test lo vedrebbe.
        let c = "v = punpckldq(a, b); w = punpckhqdq(a, b);";
        let o = define_simd_bodies(c, true);
        assert!(o.contains("r[2*i] = d[i]; r[2*i+1] = s[i];"), "low sbagliata: {o}");
        assert!(o.contains("r[0] = d[1];"), "high sbagliata: {o}");
    }

    #[test]
    fn gate_spento_e_identita() {
        let c = "v = punpckldq(a, b);";
        assert_eq!(define_simd_bodies(c, false), c);
    }
}

/// Il tipo di ritorno e il nome sotto cui `testo` DEFINISCE la sua funzione,
/// letti dal testo emesso invece che ricostruiti.
///
/// Solo la grafia sintetica `fn_<hex>`: un nome reale non ha il difetto, e
/// restringere qui evita di toccare prototipi veri.
fn definizione_emessa(testo: &str) -> Option<(String, String)> {
    for l in testo.lines() {
        let t = l.trim_end();
        // Una DEFINIZIONE sta in colonna 0 e non termina con `;`.
        // Il filtro su `fn_` esclude da solo `if (...)`/`while (...)`, che
        // sono comunque indentati.
        if t.is_empty() || t.starts_with(char::is_whitespace) || !t.ends_with(')') {
            continue;
        }
        let Some(p) = t.find('(') else { continue };
        let testa = t[..p].trim();
        let Some(sp) = testa.rfind(char::is_whitespace) else { continue };
        let nome = testa[sp + 1..].trim_start_matches('*');
        let ret = testa[..sp].trim();
        if nome.starts_with("fn_")
            && nome.len() > 3
            && nome[3..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Some((ret.to_string(), nome.to_string()));
        }
    }
    None
}

/// #8180: fa concordare le dichiarazioni anticipate con la definizione.
///
/// Rete di riparazione SINTATTICA, e sta qui perche' deve girare **dopo ogni
/// produttore** (CLAUDE.md: una passata di riparazione che non gira per ultima
/// si annulla in silenzio).
///
/// Il difetto: piu' emettitori scrivono `__int64 NOME();` senza guardare cosa
/// c'e' gia' nello stesso file. `lib.rs:11661` documenta la stessa forma:
/// -- la stessa regola, di nuovo applicata da uno solo dei punti che ne hanno
/// bisogno. Inseguirli uno per uno ha gia' fallito una volta (#8170, inerte).
///
/// Misurato su `runs/pathb_unico` (prima volta che il testo di path B passa da
/// `check.sh`, che ha SEMPRE saltato i `.hlil.c`): 16 file su 12558 non
/// compilano, 10 con `conflicting types`:
///
///   riga  84:  void runtime_runFinalizers()        <- definizione
///   riga 539:  __int64 runtime_runFinalizers();    <- dichiarazione
///   riga  36:  int fn_14005a920();                 <- e due dichiarazioni
///   riga  39:  __int64 fn_14005a920();                che si contraddicono
///
/// La cura NON e' togliere la dichiarazione (servirebbe comunque se la
/// definizione viene dopo l'uso): e' farle dire il tipo GIUSTO, quello con cui
/// il file definisce -- o, se non c'e' definizione, quello della prima
/// dichiarazione. Stessa cura di #8150, dove avevo scritto `__int64` a caso e
/// rotto 22 file su 215.
fn concorda_dichiarazioni(testo: &str) -> String {
    if !testo.contains("();") {
        return testo.to_string();
    }
    let mut definito: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut primo_decl: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let scomponi = |t: &str| -> Option<(String, String)> {
        let p = t.find('(')?;
        let testa = t[..p].trim();
        let sp = testa.rfind(char::is_whitespace)?;
        let nome = testa[sp + 1..].trim_start_matches('*').trim();
        let ret = testa[..sp].trim();
        if nome.is_empty() || ret.is_empty() { return None; }
        if !nome.chars().all(|c| c.is_alphanumeric() || c == '_') { return None; }
        Some((nome.to_string(), ret.to_string()))
    };
    for l in testo.lines() {
        let t = l.trim();
        if l.starts_with(char::is_whitespace) { continue; }
        if t.ends_with("();") {
            if let Some((n, r)) = scomponi(t) {
                primo_decl.entry(n).or_insert(r);
            }
        } else {
            let s = t.trim_end_matches('{').trim();
            if s.ends_with(')') && let Some((n, r)) = scomponi(s) {
                definito.insert(n, r);
            }
        }
    }
    if definito.is_empty() && primo_decl.is_empty() {
        return testo.to_string();
    }
    let mut visti: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = String::with_capacity(testo.len());
    for l in testo.lines() {
        let t = l.trim();
        let mut riga = l.to_string();
        if !l.starts_with(char::is_whitespace) && t.ends_with("();") {
            if let Some((n, r)) = scomponi(t) {
                if !visti.insert(n.clone()) {
                    continue;
                }
                let giusto = definito.get(&n).or_else(|| primo_decl.get(&n));
                if let Some(g) = giusto && *g != r {
                    riga = format!("{g} {n}();");
                }
            }
        }
        out.push_str(&riga);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod test_concorda_dichiarazioni {
    use super::concorda_dichiarazioni;

    #[test]
    fn allinea_al_tipo_della_definizione() {
        let c = "__int64 f();\nvoid f()\n{\n    return;\n}\n";
        let o = concorda_dichiarazioni(c);
        assert!(o.contains("void f();"), "{o}");
        assert!(!o.contains("__int64 f();"), "{o}");
    }

    #[test]
    fn toglie_la_dichiarazione_duplicata() {
        let c = "int g();\n__int64 g();\nvoid h()\n{\n}\n";
        let o = concorda_dichiarazioni(c);
        assert_eq!(o.matches("g();").count(), 1, "{o}");
        assert!(o.contains("int g();"), "{o}");
    }

    #[test]
    fn non_tocca_un_file_gia_coerente() {
        let c = "__int64 k();\nvoid m()\n{\n    k();\n}\n";
        assert_eq!(concorda_dichiarazioni(c), c);
    }
}

/// #8150: risolve i riferimenti `off_<HEX>` che puntano a funzioni EMESSE.
///
/// Sorella di `riconcilia_nomi_ondata`, e per la stessa ragione sta QUI e non
/// nella pipeline per-funzione: l'insieme dei confini che la pipeline riceve e'
/// STALE. Misurato su sample5_cs: `callee_arities` 3006, `fn_starts` 3146,
/// definizioni davvero emesse **3300** -- 154 funzioni sono emesse dopo che
/// entrambi gli insiemi sono stati calcolati (la seconda ondata di
/// `run_decompile_loop_bounded`). Per questo #8140, che allargava i confini a
/// `fn_starts` dentro la passata, e' risultato INERTE: nemmeno `fn_starts` le
/// contiene. A livello batch l'insieme si legge dal TESTO EMESSO, che e'
/// l'unica fonte che non puo' essere in ritardo.
///
/// Misurato: 155 dei 157 `code_as_data` di path B sono `extern __int64
/// off_HEX;` il cui indirizzo e' definito come funzione nello stesso bucket
/// (75+74 nei due bucket C#, 3+3 nei due Rust, zero altrove).
///
/// La dichiarazione NON viene rimossa ma RISCRITTA come dichiarazione di
/// funzione: toglierla e basta lascerebbe un identificatore non dichiarato,
/// che e' un difetto diverso e non migliore.
fn risolvi_off_ondata(result: &mut BatchResult) {
    let def: std::collections::HashMap<u64, (String, String)> = result
        .functions
        .iter()
        .filter_map(|f| {
            let (ret, nome) = definizione_emessa(f.hlil_pseudo_code.as_deref()?)?;
            Some((f.address, (ret, nome)))
        })
        .collect();
    if def.is_empty() {
        return;
    }
    let parola = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    for f in &mut result.functions {
        let Some(testo) = f.hlil_pseudo_code.as_deref() else {
            continue;
        };
        if !testo.contains("off_") {
            continue;
        }
        let bytes = testo.as_bytes();
        let mut sost: Vec<(String, String, String)> = Vec::new();
        let mut i = 0usize;
        while let Some(rel) = testo[i..].find("off_") {
            let at = i + rel;
            let mut e = at + 4;
            while e < bytes.len() && bytes[e].is_ascii_hexdigit() {
                e += 1;
            }
            i = e;
            if e == at + 4
                || (at > 0 && parola(bytes[at - 1]))
                || (e < bytes.len() && parola(bytes[e]))
            {
                continue;
            }
            let tok = &testo[at..e];
            if sost.iter().any(|(t, _, _)| t == tok) {
                continue;
            }
            let Ok(va) = u64::from_str_radix(&testo[at + 4..e], 16) else {
                continue;
            };
            if let Some((ret, nome)) = def.get(&va) {
                sost.push((tok.to_string(), ret.clone(), nome.clone()));
            }
        }
        if sost.is_empty() {
            continue;
        }
        let mut nuovo = String::with_capacity(testo.len());
        for riga in testo.lines() {
            let t = riga.trim();
            let mut riga_out = riga.to_string();
            let mut era_dichiarazione = false;
            for (tok, ret, nome) in &sost {
                // La dichiarazione dato diventa dichiarazione di FUNZIONE, col
                // tipo di ritorno con cui la funzione e' DAVVERO definita. Averlo
                // scritto `__int64` a caso ha rotto 22 file su 215 con
                // `conflicting types`: la definizione nella stessa unita' di
                // traduzione dichiarava `void`.
                if t == format!("extern __int64 {tok};") {
                    riga_out = format!("{ret} {nome}();");
                    era_dichiarazione = true;
                    break;
                }
            }
            if !era_dichiarazione {
                for (tok, _ret, nome) in &sost {
                    riga_out = sostituisci_token(&riga_out, tok, nome, parola);
                }
            }
            nuovo.push_str(&riga_out);
            nuovo.push('\n');
        }
        f.hlil_pseudo_code = Some(nuovo);
    }
}

/// Sostituisce ogni occorrenza di `tok` come TOKEN INTERO in `riga`.
fn sostituisci_token(
    riga: &str,
    tok: &str,
    nuovo: &str,
    parola: impl Fn(u8) -> bool,
) -> String {
    if !riga.contains(tok) {
        return riga.to_string();
    }
    let b = riga.as_bytes();
    let mut out = String::with_capacity(riga.len());
    let mut i = 0usize;
    while let Some(rel) = riga[i..].find(tok) {
        let at = i + rel;
        let fine = at + tok.len();
        let bordo = (at == 0 || !parola(b[at - 1])) && (fine >= b.len() || !parola(b[fine]));
        out.push_str(&riga[i..at]);
        out.push_str(if bordo { nuovo } else { tok });
        i = fine;
    }
    out.push_str(&riga[i..]);
    out
}

/// Riconcilia la grafia `sub_<HEX>` dei riferimenti con quella `fn_<hex>`
/// sotto cui la funzione e' davvero definita.
///
/// Conservativa per costruzione — rinuncia quando rinominare potrebbe
/// trasformare un file che COMPILA e non linka in un file che non compila:
///  - chiamata ricorsiva esclusa (guardia #7620, gia' motivata a monte).
///
/// ⚠ Due guardie che avevo messo sono state RIMOSSE perche' la loro premessa
/// era falsa, e a smascherarla e' stato path A:
///
/// ```text
/// path A  sub_14001aefe.c   : void __fastcall sub_14001AEFE() { ... }
/// path A  sub_14001ae10.c   : __int64 sub_14001AEFE();
///                             if ((result != 0)) return sub_14001AEFE();
/// ```
///
/// Path A fa ESATTAMENTE la stessa cosa — dichiarazione `__int64`, definizione
/// `void`, valore usato — e **linka**, perche' le due stanno in unita' di
/// traduzione diverse e il linker C non confronta i tipi. Il caso `void` non e'
/// pericoloso: era la mia riscrittura del tipo di ritorno a PORTARE la
/// dichiarazione accanto alla definizione e a fabbricare il
/// "void value not ignored" che poi escludevo.
///
/// Rinominare e basta replica il comportamento di path A, che e' misurato
/// funzionante. L'unico caso in cui dichiarazione e definizione condividono
/// l'unita' di traduzione e' la chiamata ricorsiva, gia' esclusa sopra.
fn riconcilia_nomi_ondata(result: &mut BatchResult) {
    let def: std::collections::HashMap<u64, (String, String)> = result
        .functions
        .iter()
        .filter_map(|f| {
            let (ret, nome) = definizione_emessa(f.hlil_pseudo_code.as_deref()?)?;
            Some((f.address, (ret, nome)))
        })
        .collect();
    if def.is_empty() {
        return;
    }
    let parola = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    for f in &mut result.functions {
        let Some(testo) = f.hlil_pseudo_code.as_deref() else {
            continue;
        };
        if !testo.contains("sub_") {
            continue;
        }
        let mio = f.address;
        let bytes = testo.as_bytes();
        let mut sost: Vec<(String, String, String)> = Vec::new();
        let mut i = 0usize;
        while let Some(rel) = testo[i..].find("sub_") {
            let at = i + rel;
            let mut e = at + 4;
            while e < bytes.len() && bytes[e].is_ascii_hexdigit() {
                e += 1;
            }
            i = e;
            if e == at + 4
                || (at > 0 && parola(bytes[at - 1]))
                || (e < bytes.len() && parola(bytes[e]))
            {
                continue;
            }
            let token = &testo[at..e];
            if sost.iter().any(|(t, _, _)| t == token) {
                continue;
            }
            let Ok(va) = u64::from_str_radix(&testo[at + 4..e], 16) else {
                continue;
            };
            // Una chiamata RICORSIVA resta com'e': il bersaglio e' definito in
            // questo stesso testo e la firma non e' garantita combaciare.
            if va == mio {
                continue;
            }
            if let Some((ret, nome)) = def.get(&va) {
                sost.push((token.to_string(), nome.clone(), ret.clone()));
            }
        }
        if sost.is_empty() {
            continue;
        }
        let mut out = String::with_capacity(testo.len());
        for l in testo.lines() {
            let mut riga = l.to_string();
            for (tok, nome, _) in &sost {
                // #8200 - sostituzione per TOKEN INTERO, non per sottostringa.
                //
                // Qui c'era `riga.replace(tok, nome)` e, sopra, un `let t =
                // l.trim();` **mai usato**: il residuo di un controllo di confine
                // che avevo previsto e non avevo scritto. Il compilatore lo
                // segnalava come variabile inutilizzata, e il warning era il
                // marcatore del difetto, non un dettaglio di stile.
                //
                // Il difetto: `sub_14000100` e' un PREFISSO di `sub_140001000`.
                // Sostituendo il piu' corto per primo si corrompe il piu' lungo,
                // e il risultato compila -- e' la classe silenziosa.
                //
                // `sostituisci_token` esisteva gia' (la scrissi per #8150 poche
                // ore dopo, con i confini giusti): qui la si riusa invece di
                // riscrivere la stessa regola una seconda volta.
                riga = sostituisci_token(&riga, tok, nome, parola);
            }
            out.push_str(&riga);
            out.push('\n');
        }
        f.hlil_pseudo_code = Some(out);
    }
}


#[cfg(test)]
mod test_riconcilia_nomi_ondata {
    use super::{definizione_emessa, define_simd_bodies};

    #[test]
    fn legge_la_definizione_sintetica_e_il_suo_tipo() {
        // La DICHIARAZIONE in cima finisce con `;` e non deve vincere sulla
        // definizione: e' esattamente la forma dei file emessi da path B.
        let t = "__int64 __stack_chk_fail();\nvoid fn_14001aefe()\n{\n}\n";
        assert_eq!(
            definizione_emessa(t),
            Some(("void".to_string(), "fn_14001aefe".to_string()))
        );
    }

    #[test]
    fn un_nome_reale_non_e_un_bersaglio() {
        // Restringere a `fn_<hex>` e' cio' che impedisce di toccare prototipi
        // veri: qui non c'e' divergenza di grafia da riconciliare.
        let t = "uint64_t _pthread_wait(uint64_t a1)\n{\n}\n";
        assert_eq!(definizione_emessa(t), None);
    }

    #[test]
    fn le_intestazioni_di_controllo_non_sono_definizioni() {
        // `if (...)` termina con `)` come una definizione: se passasse, il
        // "nome" estratto sarebbe un pezzo della condizione.
        let t = "    if (fn_1234())\n    while (x)\n";
        assert_eq!(definizione_emessa(t), None);
    }

    #[test]
    fn il_tipo_e_quello_della_definizione_non_della_dichiarazione() {
        // Il caso che, sbagliato, sostituisce LINK_FAIL con "conflicting
        // types": il chiamante dichiarava `__int64`, la definizione dice
        // `uint64_t`. La dichiarazione va riscritta col tipo della DEFINIZIONE.
        let t = "uint64_t fn_140001000(uint64_t a1)\n{\n    return a1;\n}\n";
        let (ret, nome) = definizione_emessa(t).expect("definizione trovata");
        assert_eq!(nome, "fn_140001000");
        assert_eq!(ret, "uint64_t");
    }

    /// #8670 - INVARIANTE: ogni mnemonico che path B puo emettere come
    /// CHIAMATA deve avere un corpo, altrimenti resta `external` al link.
    ///
    /// Nasce dal round 1239: 23 mnemonici erano chiamati e mai definiti, e il
    /// difetto era invisibile a cinque metriche su sei. Il round 1244 ne ha
    /// poi trovati 137 con 222 967 occorrenze: la lista scritta a mano DIVERGE
    /// in silenzio dal produttore, e nulla se ne accorgeva.
    #[test]
    fn ogni_mnemonico_usato_ha_un_corpo() {
        const MISURATI: &[&str] = &[
            "pcmpeqb", "pcmpeqw", "pcmpeqd", "pcmpgtb", "pmovmskb", "pshufd",
            "pshuflw", "punpcklbw", "punpcklwd", "punpckldq", "punpcklqdq",
            "packuswb", "cvtsi2sd", "cvttsd2si", "paddb", "paddd", "paddq",
            "psrld", "pslld", "psrlq", "popcnt",
            "pminub", "packsswb", "psllw", "psrlw", "psraw", "pinsrw",
            "psadbw", "shld", "shrd",
        ];
        for m in MISURATI {
            let codice = format!("void f(void) {{ x = {m}(a, b); }}");
            let out = define_simd_bodies(&codice, true);
            let definito = out.contains(&format!("static")) 
                && out.matches(&format!("{m}(")).count() >= 2;
            assert!(definito, "il mnemonico {m} e CHIAMATO ma non riceve un corpo: al link resta external");
        }
    }

    /// Complemento: un nome NON previsto non deve ricevere un corpo. Senza
    /// questo, il test sopra passerebbe anche con una passata che definisce
    /// qualunque cosa - e definire un corpo che non si conosce e il difetto
    /// `confidently wrong` che il round 1245 ha evitato (vpmaxsd e AVX a 256
    /// bit: modellarlo a 128 renderebbe LINKABILE un calcolo sbagliato).
    #[test]
    fn un_mnemonico_ignoto_non_riceve_un_corpo() {
        let out = define_simd_bodies("void f(void) { x = vpmaxsd(a, b, c); }", true);
        assert!(!out.contains("static"), "vpmaxsd non deve ricevere un corpo");
    }
}
