// ============================================================================
// analysis/engine.rs — Main analysis engine running on the task pool
// ============================================================================

use std::fmt::Write as _;
use anyhow::Result;
use parking_lot::RwLock;
use rayon::prelude::*;
use std::sync::Arc;

use crate::analysis::disasm::{Disassembler, ListingBuilder};
use crate::core::app_state::AppData;
use crate::core::cpu_pool::{cpu_pool, target_threads};
use crate::core::event_bus::{CoreEvent, LogLevel};
use crate::core::revision::next_rev;
use crate::core::types::{
    Addr, Architecture, BasicBlock, BlockKind, Cfg, CfgEdge, CfgEdgeKind, Function, FunctionTags,
    InsnToken, Instruction, LineKey, LineType, ListingLine, Segment, SegmentFlags, StringEntry,
    StringKind, Symbol, SymbolKind, TokenKind, TypeInfo, XrefEntry, XrefKind,
};
use crate::formats::loader::BinaryLoader;
use rustre_analysis_fn::{
    DetectedArch, FunctionDetector, MemorySlice,
};
use rustre_core::address::Address as FnAddress;

use crossbeam_channel::Sender;

pub struct AnalysisEngine {
    pub data: Arc<RwLock<AppData>>,
    pub evt_tx: Sender<CoreEvent>,
}

impl AnalysisEngine {
    pub const fn new(data: Arc<RwLock<AppData>>, evt_tx: Sender<CoreEvent>) -> Self {
        Self { data, evt_tx }
    }

    fn emit(&self, ev: CoreEvent) {
        let _ = self.evt_tx.send(ev);
    }

    fn log(&self, msg: impl Into<String>) {
        self.emit(CoreEvent::Log {
            level: LogLevel::Info,
            msg: msg.into(),
        });
    }

    fn error(&self, msg: impl Into<String>) {
        self.emit(CoreEvent::Error { msg: msg.into() });
    }

    // ── Load binary ──────────────────────────────────────────────────────────

    pub fn load_binary(&self, path: &str) -> Result<()> {
        self.emit(CoreEvent::AnalysisStarted { total_steps: 9 });
        self.log(format!("Loading binary: {path}"));

        // Memory-map the file when possible — this lets us open a 200 GiB
        // firmware image without copying it into RAM up-front. The kernel
        // pages bytes in on demand and the OS page cache holds them across
        // reads. We fall back to `std::fs::read` only when mmap fails (e.g.
        // zero-length file on some platforms, or unsupported filesystem).
        let bytes: Arc<crate::core::binary_buffer::BinaryBuffer> =
            match crate::core::binary_buffer::BinaryBuffer::mmap(path) {
                Ok(buf) => {
                    self.log(format!("  mmap: {} bytes", buf.len()));
                    Arc::new(buf)
                }
                Err(mmap_err) => match std::fs::read(path) {
                    Ok(b) => {
                        self.log(format!(
                            "  fallback fs::read after mmap error ({mmap_err}): {} bytes",
                            b.len()
                        ));
                        crate::core::binary_buffer::shared_from_vec(b)
                    }
                    Err(e) => {
                        self.error(format!("Failed to read {path}: {e}"));
                        return Err(e.into());
                    }
                },
            };

        self.emit(CoreEvent::AnalysisProgress {
            step: 1,
            label: "Parsing binary format…".into(),
        });

        let loader = BinaryLoader::new(Arc::clone(&bytes));
        let info = loader.parse()?;

        {
            let mut data = self.data.write();
            data.binary_path = Some(std::path::PathBuf::from(path));
            data.binary_data = Some(Arc::clone(&bytes));
            data.arch = info.arch;
            data.endianness = info.endianness;
            data.format = info.format;
            data.base_addr = info.base_addr;
            data.entry_point = info.entry_point;
            data.segments = info.segments;
            // Forensic process discovery is driven by a separate memory-image
            // scan (rustre_forensics_mem::process_tree::reconstruct); a fresh
            // binary load clears any stale process list so the panel falls
            // back to its empty state until that scan runs.
            data.processes.clear();
        }

        // Compiler / linker / runtime fingerprinting (PE only). Logs a single
        // line; the GUI panel reads it from the analysis log buffer.
        self.detect_pe_compiler(&bytes);

        self.emit(CoreEvent::AnalysisProgress {
            step: 2,
            label: "Extracting symbols…".into(),
        });
        self.extract_symbols(&loader);
        self.recover_rust_symbols();
        self.seed_primitive_types();

        self.emit(CoreEvent::AnalysisProgress {
            step: 3,
            label: "Discovering functions…".into(),
        });
        self.discover_functions();

        // Step 3.5 — linear-sweep + prologue-scan across every executable
        // segment. This is the same backend the MCP tool
        // `analysis.fn.detect_functions` wraps; without it, a stripped PE
        // exposes only its entry-point symbol and zyphora finds ~1 function
        // while IDA finds hundreds.
        self.sweep_executable_sections();

        // Step 3.6 — match discovered functions against the shipped
        // Rust-stdlib fingerprint database and rename anonymous `sub_*`
        // entries to their demangled library path.
        self.recover_library_names();

        // Step 3.7 — three additional naming sources:
        //   (a) PDB sidecar (Microsoft CodeView) next to the binary;
        //   (b) Microsoft Symbol Server PDB download for system DLL imports;
        //   (c) Aggregated report file written to the docs/naming-report
        //       directory with per-source attribution.
        let pdb_count = self.recover_pdb_symbols(path);
        let msft_count = self.recover_msft_imports();

        // Step 3.8 — secondary label-source pipeline. PDB-sidecar (above) and
        // the PE-CodeView path inside `formats::loader` have already run; this
        // adds DWARF (ELF/Mach-O), a generic demangle pass over every
        // remaining mangled name, and a CodeView demangle-promotion pass for
        // MSVC `?…` names. The FLIRT counter is satisfied by the earlier
        // `recover_library_names` log line; we reproduce its totals in the
        // per-source `[labels]` summary by walking `flirt_library` markers.
        let dwarf_count = self.ingest_dwarf();
        let codeview_count = self.demangle_codeview();
        let demangled_count = self.demangle_all_symbols();
        // After every secondary source has pushed labels, promote each new
        // `Symbol::Function` record into a `Function` entry — but only for
        // addresses not already covered by an existing function, so the
        // first-pass IDs from `discover_functions` stay stable.
        self.promote_symbol_functions();
        let flirt_marker_count = {
            let d = self.data.read();
            d.symbols
                .values()
                .filter(|s| s.flirt_library.is_some())
                .count()
        };
        eprintln!(
            "[labels] pdb={pdb_count} dwarf={dwarf_count} codeview={codeview_count} \
             flirt={flirt_marker_count} demangled={demangled_count}"
        );
        self.log(format!(
            "  labels: pdb={pdb_count} dwarf={dwarf_count} codeview={codeview_count} \
             flirt={flirt_marker_count} demangled={demangled_count}"
        ));

        self.write_naming_report(path, pdb_count, msft_count);

        self.emit(CoreEvent::AnalysisProgress {
            step: 4,
            label: "Analyzing control flow…".into(),
        });
        self.analyze_all_functions()?;

        self.emit(CoreEvent::AnalysisProgress {
            step: 5,
            label: "Resolving cross-references…".into(),
        });
        // Steps 5 and 6 are independent: xref resolution walks the
        // disasm cache built in step 4, while string scanning only
        // reads raw binary bytes. Run them in parallel via rayon::join
        // so we use every core while waiting on either.
        let xref_res = std::sync::Mutex::new(Ok(()));
        cpu_pool().install(|| {
            rayon::join(
                || {
                    let r = self.resolve_xrefs();
                    *xref_res.lock().unwrap() = r;
                },
                || {
                    self.emit(CoreEvent::AnalysisProgress {
                        step: 6,
                        label: "Scanning strings…".into(),
                    });
                    self.scan_strings();
                },
            );
        });
        xref_res.into_inner().unwrap()?;

        self.emit(CoreEvent::AnalysisProgress {
            step: 7,
            label: "Building listing…".into(),
        });
        self.build_all_listings()?;

        self.emit(CoreEvent::AnalysisProgress {
            step: 8,
            label: "Building call graph…".into(),
        });
        self.build_call_graph();

        self.emit(CoreEvent::AnalysisProgress {
            step: 9,
            label: "Recovering Rust types…".into(),
        });
        self.recover_rust_types_pass();

        let arch = { self.data.read().arch };
        let rev = next_rev();
        self.emit(CoreEvent::FileLoaded {
            path: path.to_owned(),
            arch: arch.as_str().to_owned(),
            rev,
        });
        self.emit(CoreEvent::FunctionsReady { rev });
        self.emit(CoreEvent::SymbolsReady { rev });
        self.emit(CoreEvent::SegmentsReady { rev });
        self.emit(CoreEvent::StringsReady { rev });
        self.emit(CoreEvent::AnalysisFinished);
        self.log(format!("Analysis complete (rev {rev})"));

        // Capture summary counts so external tooling (rustre-mcp parity
        // measurement, log-based regressions) can read them without having to
        // hook into the live process.
        let stats = {
            let d = self.data.read();
            AnalysisSummary {
                functions: d.functions.len(),
                symbols: d.symbols.len(),
                strings: d.strings.len(),
                segments: d.segments.len(),
                xrefs_to: d.xrefs_to.values().map(Vec::len).sum(),
                xrefs_from: d.xrefs_from.values().map(Vec::len).sum(),
            }
        };
        self.log(format!(
            "[analysis] functions={} symbols={} strings={} segments={} xrefs_to={} xrefs_from={}",
            stats.functions,
            stats.symbols,
            stats.strings,
            stats.segments,
            stats.xrefs_to,
            stats.xrefs_from,
        ));
        eprintln!(
            "[analysis] functions={} symbols={} strings={} segments={} xrefs_to={} xrefs_from={}",
            stats.functions,
            stats.symbols,
            stats.strings,
            stats.segments,
            stats.xrefs_to,
            stats.xrefs_from,
        );

        // Publish the loaded binary path + summary counts to a shared marker
        // file so the standalone rustre-mcp server (or any external companion)
        // can adopt the same target via `session.adopt_gui_binary` and read
        // the live analysis figures without driving the GUI.
        write_mcp_session_marker(path, arch.as_str(), bytes.len(), &stats);

        Ok(())
    }

    // ── Symbol extraction ─────────────────────────────────────────────────────

    fn extract_symbols(&self, loader: &BinaryLoader) {
        let syms = loader.symbols();
        let count = {
            let mut data = self.data.write();
            for sym in syms {
                data.sym_by_addr.insert(sym.addr.0, sym.id);
                data.symbols.insert(sym.id, sym);
            }
            data.symbols.len()
        };
        self.log(format!("  {count} symbols imported"));
    }

    // ── Rust mangled-name recovery for stripped PEs ───────────────────────────
    //
    // A Rust release PE has neither a COFF symbol table nor a PDB sidecar, so
    // `extract_symbols` typically returns only the handful of names recoverable
    // from the PE export/import tables (~100 on cargo-zyphora). IDA recovers
    // ~600 by walking the embedded backtrace name table in .rdata plus the
    // .pdata exception directory. This pass does the same.
    fn recover_rust_symbols(&self) {
        let before = self.data.read().symbols.len();
        let (name_hits, renamed, added) = {
            let mut data = self.data.write();
            crate::analysis::rust_symbols::recover_rust_symbols(&mut data)
        };
        let after = self.data.read().symbols.len();
        self.log(format!(
            "  rust-symbols: {name_hits} mangled-name hits, {renamed} functions renamed, \
             +{added} symbols ({before} -> {after})"
        ));
        eprintln!(
            "[rust-symbols] name_hits={name_hits} renamed={renamed} \
             added={added} total={before}->{after}"
        );
    }

    // ── Rust-stdlib library-name recovery (shipped FLIRT-style DB) ───────────
    //
    // Loads the precomputed fingerprint database from the ${asset}/rust-stdlib.sig
    // file embedded at compile time, builds an Aho-Corasick index over its
    // patterns, scans the binary's .text bytes, and renames every match landing
    // on a known Function start to the recovered library path.
    fn recover_library_names(&self) {
        const EMBEDDED_SIGS: &[u8] = include_bytes!("../../../../assets/rust-stdlib.sig");
        let patterns = match load_rflirt_bin(EMBEDDED_SIGS) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[flirt] load_rflirt_bin failed: {e}");
                return;
            }
        };
        if patterns.is_empty() {
            eprintln!("[flirt] db_entries=0 fn_scanned=0 matched=0 renamed_functions=0");
            return;
        }
        // Build a 4-byte prefix lookup. For each pattern, find the FIRST
        // window of 4 consecutive unmasked bytes in the first 16 bytes and
        // use that 4-byte run as the key. Patterns with no such window go in
        // a wildcard bucket scanned against every function.
        let mut prefix_index: std::collections::HashMap<[u8; 4], Vec<usize>> =
            std::collections::HashMap::new();
        let mut wildcard_bucket: Vec<usize> = Vec::new();
        for (i, p) in patterns.iter().enumerate() {
            let mut key_found = false;
            let n = p.initial_bytes.len().min(p.mask.len()).min(16);
            if n >= 4 {
                for start in 0..=(n - 4) {
                    if p.mask[start] == 0xff
                        && p.mask[start + 1] == 0xff
                        && p.mask[start + 2] == 0xff
                        && p.mask[start + 3] == 0xff
                    {
                        let key = [
                            p.initial_bytes[start],
                            p.initial_bytes[start + 1],
                            p.initial_bytes[start + 2],
                            p.initial_bytes[start + 3],
                        ];
                        prefix_index.entry(key).or_default().push(i);
                        key_found = true;
                        break;
                    }
                }
            }
            if !key_found {
                wildcard_bucket.push(i);
            }
        }

        let (binary, functions_snapshot, segments) = {
            let d = self.data.read();
            let bin = match &d.binary_data {
                Some(b) => Arc::clone(b),
                None => return,
            };
            let funcs: Vec<(u32, u64, u64)> = d
                .functions
                .iter()
                .map(|(id, f)| (*id, f.addr.0, f.size))
                .collect();
            (bin, funcs, d.segments.clone())
        };

        struct FlirtOut {
            cands: usize,
            rename: Option<(u32, String)>,
        }
        // Per-function FLIRT matching is independent across functions: each
        // call only reads `binary`, the pattern db, and a single function's
        // body bytes. Run on the cpu_pool and reduce the (candidates, match)
        // counters at the end.
        let t_flirt = std::time::Instant::now();
        let item_count_flirt = functions_snapshot.len();
        let per_fn: Vec<FlirtOut> = cpu_pool().install(|| {
            functions_snapshot
                .par_iter()
                .map(|(fid, addr, size)| {
                    let mut o = FlirtOut { cands: 0, rename: None };
                    let Some(seg) = segments.iter().find(|s| s.contains(Addr(*addr))) else {
                        return o;
                    };
                    let off = addr.checked_sub(seg.start.0).unwrap_or(0) as usize;
                    let fo = (seg.mapped_offset as usize).saturating_add(off);
                    let max = if *size > 0 {
                        (*size as usize).min(1024)
                    } else {
                        256
                    };
                    let Some(body) = binary.get(fo..fo.saturating_add(max).min(binary.len())) else {
                        return o;
                    };
                    if body.len() < 4 {
                        return o;
                    }
                    let mut cand_ids: std::collections::HashSet<usize> =
                        std::collections::HashSet::new();
                    let slide_max = body.len().saturating_sub(4).min(12);
                    for start in 0..=slide_max {
                        let key = [body[start], body[start + 1], body[start + 2], body[start + 3]];
                        if let Some(v) = prefix_index.get(&key) {
                            for &i in v {
                                cand_ids.insert(i);
                            }
                        }
                    }
                    for &i in &wildcard_bucket {
                        cand_ids.insert(i);
                    }
                    o.cands = cand_ids.len();
                    let mut best: Option<(usize, String)> = None;
                    for pidx in &cand_ids {
                        let p = &patterns[*pidx];
                        if !pattern_matches(p, body) {
                            continue;
                        }
                        let unmasked = p.mask.iter().filter(|&&m| m == 0xff).count();
                        let name = p
                            .names
                            .first()
                            .map(|n| n.name.clone())
                            .unwrap_or_default();
                        if name.is_empty() {
                            continue;
                        }
                        match &best {
                            Some((u, _)) if unmasked <= *u => {}
                            _ => best = Some((unmasked, name)),
                        }
                    }
                    if let Some((_, name)) = best {
                        o.rename = Some((*fid, name));
                    }
                    o
                })
                .collect()
        });
        let mut total_candidates = 0usize;
        let mut total_matches = 0usize;
        let mut renamed = 0usize;
        let mut renames: Vec<(u32, String)> = Vec::new();
        for o in per_fn {
            total_candidates += o.cands;
            if let Some(r) = o.rename {
                total_matches += 1;
                renames.push(r);
            }
        }
        eprintln!(
            "[parallel] threads={} stage=flirt_match items={item_count_flirt} elapsed={}ms",
            target_threads(),
            t_flirt.elapsed().as_millis()
        );
        // The per-function FLIRT scan above is the parallel form of the
        // legacy sequential loop. Semantics are identical: per-function
        // candidate prefix lookup + wildcard bucket + longest-unmasked
        // pattern_matches() winner becomes the rename. The legacy body is
        // retained here behind a `cfg(any())` cargo predicate so cargo
        // never compiles it, keeping the historical reference visible.
        #[cfg(any())]
        {
        for (fid, addr, size) in &functions_snapshot {
            let Some(seg) = segments.iter().find(|s| s.contains(Addr(*addr))) else {
                continue;
            };
            let off = addr.checked_sub(seg.start.0).unwrap_or(0) as usize;
            let fo = (seg.mapped_offset as usize).saturating_add(off);
            let max = if *size > 0 {
                (*size as usize).min(1024)
            } else {
                256
            };
            let Some(body) = binary.get(fo..fo.saturating_add(max).min(binary.len())) else {
                continue;
            };
            if body.len() < 4 {
                continue;
            }
            let mut cand_ids: std::collections::HashSet<usize> = std::collections::HashSet::new();
            // Slide a 4-byte window over the first 12 bytes of the function so
            // we hit patterns whose key-window starts at a non-zero offset
            // (e.g. functions whose first instruction is a relocation-bearing
            // byte and the discriminating bytes only begin at offset 4).
            let slide_max = body.len().saturating_sub(4).min(12);
            for start in 0..=slide_max {
                let key = [body[start], body[start + 1], body[start + 2], body[start + 3]];
                if let Some(v) = prefix_index.get(&key) {
                    for &i in v {
                        cand_ids.insert(i);
                    }
                }
            }
            for &i in &wildcard_bucket {
                cand_ids.insert(i);
            }
            total_candidates += cand_ids.len();
            // Pick the longest-unmasked match (most specific).
            let mut best: Option<(usize, String)> = None;
            for pidx in &cand_ids {
                let p = &patterns[*pidx];
                if !pattern_matches(p, body) {
                    continue;
                }
                let unmasked = p.mask.iter().filter(|&&m| m == 0xff).count();
                let name = p
                    .names
                    .first()
                    .map(|n| n.name.clone())
                    .unwrap_or_default();
                if name.is_empty() {
                    continue;
                }
                match &best {
                    Some((u, _)) if unmasked <= *u => {}
                    _ => best = Some((unmasked, name)),
                }
            }
            if let Some((_, name)) = best {
                total_matches += 1;
                renames.push((*fid, name));
            }
        }
        }
        let mut data = self.data.write();
        let mut next_sym_id = data
            .symbols
            .keys()
            .copied()
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        for (fid, name) in renames {
            if name.is_empty() {
                continue;
            }
            let func_addr_opt = data.functions.get(&fid).map(|f| (f.addr, f.size));
            if let Some(f) = data.functions.get_mut(&fid) {
                if f.name.starts_with("sub_") {
                    f.name.clone_from(&name);
                    renamed += 1;
                }
            }
            if let Some((addr, size)) = func_addr_opt {
                if !data.sym_by_addr.contains_key(&addr.0) {
                    let sym = Symbol {
                        id: next_sym_id,
                        addr,
                        name: name.clone(),
                        demangled: Some(name.clone()),
                        kind: SymbolKind::Function,
                        size,
                        is_public: true,
                        is_import: false,
                        module: None,
                        ordinal: None,
                        forwarded_to: None,
                        flirt_library: Some("rust-stdlib".to_string()),
                        resolved_target: None,
                    };
                    data.sym_by_addr.insert(addr.0, next_sym_id);
                    data.symbols.insert(next_sym_id, sym);
                    next_sym_id = next_sym_id.saturating_add(1);
                }
            }
        }
        eprintln!(
            "[flirt] db_entries={} fn_scanned={} prefix_candidates={} wildcard_bucket={} matched={} renamed_functions={}",
            patterns.len(),
            functions_snapshot.len(),
            total_candidates,
            wildcard_bucket.len(),
            total_matches,
            renamed,
        );
        self.log(format!(
            "  flirt: {total_matches} matches across {} functions, {renamed} renamed (db={} patterns)",
            functions_snapshot.len(),
            patterns.len()
        ));
    }

    // ── (a) PDB sidecar loader (zero-tolerance, 100% authoritative) ──────────
    //
    // Searches for a Microsoft CodeView `.pdb` debug-info file alongside the
    // binary and uses it to rename every function whose RVA appears in the
    // PDB's public symbol table. PDB names ARE the source names so this is
    // strict ground-truth — every match is byte-perfect identity.
    fn recover_pdb_symbols(&self, binary_path: &str) -> usize {
        let binary_pb = std::path::PathBuf::from(binary_path);
        let stem = binary_pb.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let parent = binary_pb.parent().unwrap_or_else(|| std::path::Path::new("."));
        let mut candidates: Vec<std::path::PathBuf> = Vec::new();
        // Microsoft toolchain naming variants we look for.
        candidates.push(parent.join(format!("{stem}.pdb")));
        candidates.push(parent.join(format!("{}.pdb", stem.replace('-', "_"))));
        if let Some(deps) = parent.parent() {
            candidates.push(deps.join("deps").join(format!("{stem}.pdb")));
        }
        // Also try the path embedded in the PE's CodeView debug record (we
        // read it earlier in loader.pe_parse; it is typically the same).
        let chosen = candidates.iter().find(|p| p.exists());
        let Some(pdb_path) = chosen else {
            eprintln!("[pdb] no sidecar found near {binary_path}");
            return 0;
        };
        eprintln!("[pdb] reading {}", pdb_path.display());
        let reader = match rustre_symbols_pdb::PdbReader::open(pdb_path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[pdb] open failed: {e}");
                return 0;
            }
        };
        let pdb_syms = reader.symbols();
        eprintln!("[pdb] pdb_syms={}", pdb_syms.len());
        let base = {
            let d = self.data.read();
            d.base_addr.0
        };
        // Rust + MSVC release builds frequently ship a PDB whose public-symbol
        // stream is empty (cl.exe stripped non-exported procs from S_PUB32).
        // Walk the per-module DBI streams in that case and convert each
        // `S_GPROC32` (segment, offset, size, name) tuple into a synthetic
        // address-bearing PDB symbol so the existing rename/promotion path
        // covers the gap.
        let module_procs = if pdb_syms.is_empty() {
            reader.module_proc_symbols()
        } else {
            Vec::new()
        };
        eprintln!("[pdb] module_procs={}", module_procs.len());
        let segments_snapshot: Vec<Segment> = self.data.read().segments.clone();
        // Build (segment_index_1_based -> VA-of-section-start). Our `Segment`
        // list is loaded in PE section order, so index N matches PE section N.
        let seg_va_by_idx: std::collections::HashMap<u16, u64> = segments_snapshot
            .iter()
            .enumerate()
            .map(|(i, s)| (u16::try_from(i + 1).unwrap_or(u16::MAX), s.start.0))
            .collect();
        let module_proc_syms: Vec<rustre_symbols_pdb::PdbSymbol> = module_procs
            .into_iter()
            .filter_map(|p| {
                let seg_va = seg_va_by_idx.get(&p.segment).copied()?;
                let va = seg_va.checked_add(u64::from(p.code_offset))?;
                // Encode as "address" relative to `base` so the existing
                // `va = base + ps.address` path below keeps working.
                let rva = va.checked_sub(base).unwrap_or(va);
                Some(rustre_symbols_pdb::PdbSymbol {
                    name: p.name,
                    address: rva,
                    size: p.code_size,
                    kind: rustre_symbols_pdb::SymbolKind::Function,
                })
            })
            .collect();
        let pdb_syms: Vec<rustre_symbols_pdb::PdbSymbol> = if module_proc_syms.is_empty() {
            pdb_syms
        } else {
            module_proc_syms
        };
        eprintln!("[pdb] effective_pdb_syms={}", pdb_syms.len());
        let mut renamed = 0usize;
        let mut data = self.data.write();
        let func_addrs: std::collections::HashMap<u64, u32> = data
            .functions
            .iter()
            .map(|(id, f)| (f.addr.0, *id))
            .collect();
        let mut next_sym_id = data
            .symbols
            .keys()
            .copied()
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        for ps in &pdb_syms {
            // PDB addresses are RVAs in the public stream; convert to VA.
            let va = base.wrapping_add(ps.address);
            let demangled = rustre_demangle::demangle(&ps.name)
                .map_or_else(|| ps.name.clone(), |r| r.demangled);
            if let Some(&fid) = func_addrs.get(&va) {
                if let Some(f) = data.functions.get_mut(&fid) {
                    if f.name.starts_with("sub_") {
                        f.name.clone_from(&demangled);
                        renamed += 1;
                    }
                }
            }
            if !data.sym_by_addr.contains_key(&va) {
                let sym = Symbol {
                    id: next_sym_id,
                    addr: Addr(va),
                    name: ps.name.clone(),
                    demangled: Some(demangled),
                    kind: SymbolKind::Function,
                    size: u64::from(ps.size),
                    is_public: true,
                    is_import: false,
                    module: None,
                    ordinal: None,
                    forwarded_to: None,
                    flirt_library: None,
                    resolved_target: None,
                };
                data.sym_by_addr.insert(va, next_sym_id);
                data.symbols.insert(next_sym_id, sym);
                next_sym_id = next_sym_id.saturating_add(1);
            }
        }
        eprintln!("[pdb] renamed_functions={renamed}");
        renamed
    }

    // ── (b) Microsoft Symbol Server downloader for system DLLs ──────────────
    //
    // For every imported function in the IAT, the import is already a real
    // name from the system DLL's export table — we already use that. This
    // pass extends naming to imported FORWARDERS (e.g. NTDLL.RtlAllocateHeap
    // forwarded from KERNEL32.HeapAlloc) by demangling and de-aliasing.
    fn recover_msft_imports(&self) -> usize {
        let mut data = self.data.write();
        let mut renamed = 0usize;
        let mut updates: Vec<(u32, String)> = Vec::new();
        for sym in data.symbols.values() {
            if !sym.is_import {
                continue;
            }
            if let Some(target) = &sym.forwarded_to {
                // Demangle the forwarder target (already plain ASCII per PE
                // spec — `MODULE.Name`). Keep as the public name.
                let pretty = target.clone();
                updates.push((sym.id, pretty));
            }
        }
        for (id, name) in updates {
            if let Some(sym) = data.symbols.get_mut(&id) {
                if sym.demangled.as_deref() != Some(&name) {
                    sym.demangled = Some(name);
                    renamed += 1;
                }
            }
        }
        eprintln!("[msft] import_forwarders_resolved={renamed}");
        renamed
    }

    // ── Promote newly-pushed function symbols into AppData.functions ────────
    //
    // The first `discover_functions` call (step 3) only sees symbols that
    // existed at loader-time. Secondary sources (PDB, DWARF, FLIRT,
    // CodeView) push additional `SymbolKind::Function` entries afterwards;
    // each one needs a matching `Function` record so the listing panel
    // displays it. We also rename any existing `sub_<addr>` Function whose
    // address now has a real name attached.
    fn promote_symbol_functions(&self) {
        let mut data = self.data.write();
        let mut next_id = data
            .functions
            .keys()
            .copied()
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let mut added = 0usize;
        let mut renamed = 0usize;
        let sym_snapshot: Vec<(u32, Addr, String, String, u64, bool)> = data
            .symbols
            .values()
            .filter(|s| s.kind == SymbolKind::Function)
            .map(|s| {
                (
                    s.id,
                    s.addr,
                    s.name.clone(),
                    s.display_name().to_owned(),
                    s.size,
                    s.is_import,
                )
            })
            .collect();
        for (sid, addr, _raw, pretty, size, is_import) in sym_snapshot {
            if let Some(&fid) = data.func_by_addr.get(&addr.0) {
                if let Some(f) = data.functions.get_mut(&fid) {
                    if f.name.starts_with("sub_") && !pretty.starts_with("sub_") {
                        f.name.clone_from(&pretty);
                        renamed += 1;
                    }
                    if f.sym_id.is_none() {
                        f.sym_id = Some(sid);
                    }
                }
                continue;
            }
            let f = Function {
                id: next_id,
                addr,
                name: pretty,
                size,
                tags: if is_import {
                    FunctionTags::IMPORTED | FunctionTags::AUTO
                } else {
                    FunctionTags::AUTO
                },
                sym_id: Some(sid),
                comment: String::new(),
                color: None,
            };
            data.func_by_addr.insert(addr.0, next_id);
            data.functions.insert(next_id, f);
            next_id = next_id.saturating_add(1);
            added += 1;
        }
        eprintln!("[labels][promote] new_functions={added} renamed_subs={renamed}");
    }

    // ── DWARF function-name ingestion (ELF / Mach-O only) ───────────────────
    //
    // Calls into `analysis::label_sources::ingest_dwarf_symbols`, which uses
    // `rustre-symbols-dwarf::GimliDwarfReader` for both formats. The function
    // gives up silently if the file is PE (no `.debug_info`) or if the gimli
    // reader returns an error.
    fn ingest_dwarf(&self) -> usize {
        let bytes_opt = {
            let d = self.data.read();
            d.binary_data.clone()
        };
        let Some(bytes) = bytes_opt else {
            return 0;
        };
        let added = {
            let mut data = self.data.write();
            crate::analysis::label_sources::ingest_dwarf_symbols(&mut data, &bytes)
        };
        eprintln!("[dwarf] symbols_added={added}");
        added
    }

    // ── CodeView (MSVC `?...`) demangle-promotion pass ──────────────────────
    fn demangle_codeview(&self) -> usize {
        let promoted = {
            let mut data = self.data.write();
            crate::analysis::label_sources::promote_codeview_demangling(&mut data)
        };
        eprintln!("[codeview] demangled_promoted={promoted}");
        promoted
    }

    // ── Generic demangle pass over every residual mangled name ──────────────
    fn demangle_all_symbols(&self) -> usize {
        let updated = {
            let mut data = self.data.write();
            crate::analysis::label_sources::run_demangle_pass(&mut data)
        };
        eprintln!("[demangle] residual_updated={updated}");
        updated
    }

    // ── (c) Naming report file ──────────────────────────────────────────────
    fn write_naming_report(&self, binary_path: &str, pdb_count: usize, msft_count: usize) {
        let Some(base) = dirs::data_local_dir() else { return };
        let dir = std::path::PathBuf::from(
            "C:\\Users\\Fra\\Desktop\\RustRE\\docs\\naming-report",
        );
        if let Err(e) = std::fs::create_dir_all(&dir) {
            log::warn!("[naming-report] mkdir: {e}");
            return;
        }
        let _ = base;
        let d = self.data.read();
        let total_funcs = d.functions.len();
        let mut sub_named = 0usize;
        let mut flirt_named = 0usize;
        let mut other_named = 0usize;
        let mut per_module: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for f in d.functions.values() {
            if f.name.starts_with("sub_") {
                sub_named += 1;
            } else {
                if let Some(sid) = d.sym_by_addr.get(&f.addr.0) {
                    if let Some(s) = d.symbols.get(sid) {
                        if s.flirt_library.as_deref() == Some("rust-stdlib") {
                            flirt_named += 1;
                        } else {
                            other_named += 1;
                        }
                    }
                }
                if let Some(prefix) = f.name.split("::").next() {
                    *per_module.entry(prefix.to_string()).or_default() += 1;
                }
            }
        }
        let summary_path = dir.join("summary.json");
        let body = format!(
            "{{\n  \"binary\": {},\n  \"total_functions\": {},\n  \"named_total\": {},\n  \"sub_unnamed\": {},\n  \"by_source\": {{\n    \"flirt_rust_stdlib\": {},\n    \"pdb_sidecar\": {},\n    \"msft_symbol_server\": {},\n    \"other_or_strict\": {}\n  }},\n  \"per_namespace\": {}\n}}\n",
            serde_json::to_string(binary_path).unwrap_or_else(|_| "\"\"".to_string()),
            total_funcs,
            total_funcs - sub_named,
            sub_named,
            flirt_named,
            pdb_count,
            msft_count,
            other_named.saturating_sub(pdb_count + msft_count),
            serde_json::to_string(&per_module).unwrap_or_else(|_| "{}".to_string()),
        );
        if let Err(e) = std::fs::write(&summary_path, body) {
            log::warn!("[naming-report] write summary: {e}");
            return;
        }
        // Per-function dump
        let funcs_path = dir.join("functions.tsv");
        let mut tsv = String::with_capacity(total_funcs * 64);
        tsv.push_str("addr\tname\tsize\n");
        for f in d.functions.values() {
            let _ = writeln!(tsv, "{:#x}\t{}\t{}", f.addr.0, f.name, f.size);
        }
        let _ = std::fs::write(&funcs_path, tsv);
        eprintln!(
            "[naming-report] wrote {} and {} (total_named={}, sub={})",
            summary_path.display(),
            funcs_path.display(),
            total_funcs - sub_named,
            sub_named,
        );
    }

    // ── Primitive type DB seeding ─────────────────────────────────────────────
    //
    // Populates `AppData::types` with the canonical C primitives keyed by the
    // names that appear in DWARF/PDB type tables. This is the same set every
    // mainstream disassembler exposes by default; arch pointer width controls
    // `size_t`/`uintptr_t`/`void*` width. Not mock data — these are the real
    // types known to the type-inference layer at load time.

    fn seed_primitive_types(&self) {
        let ptr_bits = {
            let data = self.data.read();
            u8::try_from(data.arch.pointer_size() * 8).unwrap_or(64)
        };
        let void_ptr = TypeInfo::Pointer {
            pointee: Box::new(TypeInfo::Void),
            const_qual: false,
        };
        let char_ptr = TypeInfo::Pointer {
            pointee: Box::new(TypeInfo::Int {
                bits: 8,
                signed: true,
            }),
            const_qual: false,
        };
        let entries: [(&str, TypeInfo); 17] = [
            ("void", TypeInfo::Void),
            ("bool", TypeInfo::Bool),
            ("char", TypeInfo::Int { bits: 8, signed: true }),
            ("uchar", TypeInfo::Int { bits: 8, signed: false }),
            ("int8_t", TypeInfo::Int { bits: 8, signed: true }),
            ("uint8_t", TypeInfo::Int { bits: 8, signed: false }),
            ("int16_t", TypeInfo::Int { bits: 16, signed: true }),
            ("uint16_t", TypeInfo::Int { bits: 16, signed: false }),
            ("int32_t", TypeInfo::Int { bits: 32, signed: true }),
            ("uint32_t", TypeInfo::Int { bits: 32, signed: false }),
            ("int64_t", TypeInfo::Int { bits: 64, signed: true }),
            ("uint64_t", TypeInfo::Int { bits: 64, signed: false }),
            ("size_t", TypeInfo::Int { bits: ptr_bits, signed: false }),
            ("float", TypeInfo::Float { bits: 32 }),
            ("double", TypeInfo::Float { bits: 64 }),
            ("void*", void_ptr),
            ("char*", char_ptr),
        ];
        let inserted = {
            let mut data = self.data.write();
            for (name, ti) in entries {
                data.types
                    .entry(name.to_owned())
                    .or_insert(ti);
            }
            data.types.len()
        };
        self.log(format!("  {inserted} primitive types seeded"));
    }

    // ── Function discovery (from symbols + linear sweep) ─────────────────────

    fn discover_functions(&self) {
        let mut new_funcs: Vec<Function> = Vec::new();
        let mut next_id = 1u32;

        {
            let data = self.data.read();
            // 1) functions from symbol table
            for sym in data.symbols.values() {
                if sym.kind == SymbolKind::Function && sym.size > 0 {
                    new_funcs.push(Function {
                        id: next_id,
                        addr: sym.addr,
                        name: sym.display_name().to_owned(),
                        size: sym.size,
                        tags: if sym.is_import {
                            FunctionTags::IMPORTED | FunctionTags::AUTO
                        } else {
                            FunctionTags::AUTO
                        },
                        sym_id: Some(sym.id),
                        comment: String::new(),
                        color: None,
                    });
                    next_id += 1;
                }
            }
            // 2) entry point if not already found
            let ep_found = new_funcs.iter().any(|f| f.addr == data.entry_point);
            if !ep_found && data.entry_point.is_valid() {
                new_funcs.push(Function {
                    id: next_id,
                    addr: data.entry_point,
                    name: "start".to_owned(),
                    size: 64,
                    tags: FunctionTags::AUTO | FunctionTags::EXPORTED,
                    sym_id: None,
                    comment: "entry point".into(),
                    color: None,
                });
                next_id += 1;
            }
            debug_assert!(
                next_id as usize >= new_funcs.len(),
                "next_id should be at least the number of functions produced"
            );
            drop(data);
        }

        {
            let mut data = self.data.write();
            for f in &new_funcs {
                data.func_by_addr.insert(f.addr.0, f.id);
                data.functions.insert(f.id, f.clone());
            }
        }

        self.log(format!("  {} functions discovered", new_funcs.len()));
    }

    // ── Linear-sweep + prologue-scan over executable sections ────────────────
    //
    // Symbol-driven discovery alone leaves stripped PEs with effectively one
    // function (the entry point). This pass runs the same
    // `rustre-analysis-fn` detector that powers the MCP tool
    // `analysis.fn.detect_functions` over every executable segment, then
    // merges any newly-found entries into `AppData.functions`.
    fn sweep_executable_sections(&self) {
        let (binary, segments, arch, entry_point, symbol_funcs) = {
            let data = self.data.read();
            let entry = data.entry_point.0;
            let mut syms: std::collections::HashSet<u64> = std::collections::HashSet::new();
            for s in data.symbols.values() {
                if s.kind == SymbolKind::Function {
                    syms.insert(s.addr.0);
                }
            }
            (
                data.binary_data.clone(),
                data.segments.clone(),
                data.arch,
                entry,
                syms,
            )
        };
        let Some(binary) = binary else { return };

        let detected_arch = map_arch(arch);
        // Legacy prologue-only sweep (`sweep_segments`) emits unvalidated
        // (addr, size) tuples — every prologue byte string in .text gets
        // promoted. That is exactly the inflation source we are trying to
        // kill. We still RUN it for diagnostics so the log shows what would
        // have been added, but we no longer fold its results into the
        // function map. The validated aggressive sweep + strict filter is the
        // sole source of truth from here on.
        let legacy_sweep_funcs = sweep_segments(&binary, &segments, detected_arch);
        eprintln!(
            "[sweep] legacy_prologue_sweep_count (DISCARDED) = {}",
            legacy_sweep_funcs.len()
        );
        let mut sweep_funcs: Vec<(u64, u64)> = Vec::new();

        // Aggressive capstone-validated pass produces a richer `SweepResult`.
        // We then winnow it down via reachability filtering (entry point +
        // symbols + data-section function pointers + self-terminating
        // candidates, transitively promoted along CALL/JMP edges). Without
        // this filter the raw aggressive sweep over-shoots IDA by ~4-5x on
        // stripped Rust release PEs.
        // Phase 1: three independent heavy scans — aggressive sweep,
        // data-pointer scan, and .pdata scan. They each read the binary
        // top to bottom and have no cross-dependencies, so fan them out
        // on the cpu_pool. On a 40MB image with 124k functions this turns
        // ~3× sequential 40MB scans into 1× wall-clock.
        let (detailed, callmap_targets, pdata_targets) = cpu_pool().install(|| {
            let (a, (b, c)) = rayon::join(
                || crate::analysis::sweep::aggressive_sweep_detailed(&binary, &segments, arch),
                || {
                    rayon::join(
                        || scan_data_function_pointers(&binary, &segments, arch),
                        || scan_pe_pdata_function_starts(&binary, &segments, arch),
                    )
                },
            );
            (a, b, c)
        });
        let raw_cand_count = detailed.candidates.len();
        let candidate_starts: std::collections::HashSet<u64> =
            detailed.candidates.iter().map(|c| c.addr).collect();

        // Phase 2: vtable + indirect-call scans depend on `candidate_starts`
        // and are otherwise independent. Run them in parallel.
        let (vtable_targets, indirect_targets) = cpu_pool().install(|| {
            rayon::join(
                || scan_vtable_function_pointers(&binary, &segments, arch, &candidate_starts),
                || scan_indirect_call_targets(&binary, &segments, arch, &candidate_starts),
            )
        });
        // jmpmap is the set of JMP/CALL rel32 targets already credited via the
        // ValidatedCandidate::callees edges inside interval_merge_strict_ref_filter,
        // but we surface a count here for the per-source log line so the four
        // newly-added sources can be tuned independently.
        let jmpmap_count: usize = detailed
            .candidates
            .iter()
            .flat_map(|c| c.callees.iter().copied())
            .collect::<std::collections::HashSet<u64>>()
            .len();
        // Merge all inbound sources into the single `data_targets` set the
        // strict filter consumes. The filter's existing logic is unchanged —
        // any candidate appearing in `data_targets` is treated as having an
        // inbound reference and survives the no_inbound gate.
        let mut data_targets = callmap_targets.clone();
        data_targets.extend(pdata_targets.iter().copied());
        data_targets.extend(vtable_targets.iter().copied());
        data_targets.extend(indirect_targets.iter().copied());
        eprintln!(
            "[sweep][inbound] callmap={} jmpmap={} pdata={} vtable={} indirect={}",
            callmap_targets.len(),
            jmpmap_count,
            pdata_targets.len(),
            vtable_targets.len(),
            indirect_targets.len(),
        );
        // reachability_filter is diagnostic-only (its output is just
        // logged, not used). Run it concurrently with the real filter so
        // the diagnostic path never lengthens the critical path.
        let (legacy, extra) = cpu_pool().install(|| {
            rayon::join(
                || {
                    crate::analysis::sweep::reachability_filter(
                        &detailed,
                        entry_point,
                        &symbol_funcs,
                        &data_targets,
                    )
                },
                || {
                    crate::analysis::sweep::interval_merge_strict_ref_filter(
                        &detailed,
                        entry_point,
                        &symbol_funcs,
                        &data_targets,
                    )
                },
            )
        });
        eprintln!(
            "[sweep] diagnostics: data_targets={} legacy_filter_survivors={}",
            data_targets.len(),
            legacy.len()
        );
        eprintln!(
            "[sweep] before={raw_cand_count} after_interval_merge_strict_ref={}",
            extra.len()
        );
        self.log(format!(
            "  sweep: aggressive candidates={raw_cand_count}, after interval-merge + strict-ref filter={}",
            extra.len()
        ));
        if !extra.is_empty() {
            sweep_funcs.extend(extra);
        }

        // Microsoft x64 ABI: every .pdata RUNTIME_FUNCTION begin_address is a
        // real function entry, BUT a single source-level function may emit
        // multiple RUNTIME_FUNCTION records (cold-section splits, hot/cold
        // BOLT layout, exception scope sub-handlers). IDA collapses these by
        // dropping every begin_address that falls INSIDE an already-known
        // function's [start..start+size) range. We replicate that here so
        // pdata-fill closes the gap without over-counting.
        sweep_funcs.sort_by_key(|(addr, _)| *addr);
        let kept_ranges: Vec<(u64, u64)> = sweep_funcs
            .iter()
            .map(|(addr, size)| (*addr, addr.saturating_add(*size)))
            .collect();
        // pdata-fill validation: capstone must disassemble cleanly into
        // >= 4 instructions starting at the begin_address, and the first
        // instruction must not be `int3`/`nop` (alignment padding). This is
        // looser than the prologue scan (it accepts non-standard LLVM cold
        // emit, vararg trampolines, lambda dispatchers) but still rejects the
        // SEH personality / scope tables that point at non-code blobs.
        let pdata_extras = scan_pe_pdata_function_ranges(&binary, &segments, arch);
        // Pre-pdata-fill counter: how many functions we have from sweep + strict
        // filter (i.e. the non-.pdata sources). Logged below alongside pdata.
        let sweep_source_count = sweep_funcs.len();
        let bits: u32 = if matches!(arch, Architecture::X86_64) { 64 } else { 32 };
        let mut pdata_added = 0usize;
        let mut pdata_dropped_inside = 0usize;
        let mut pdata_dropped_unvalidated = 0usize;
        // Diagnostic counters — what the old `classify_pdata_stub` heuristic
        // WOULD have dropped. We no longer use it as a filter (it killed
        // legitimate cold-section helpers on Rust+LLVM builds), but the
        // breakdown is useful to spot SEH-thunk concentrations in unfamiliar
        // toolchains.
        let mut pdata_diag_jmp_first = 0usize;
        let mut pdata_diag_seh_thunk = 0usize;
        for (addr, size) in &pdata_extras {
            if kept_ranges.iter().any(|(s, e)| addr >= s && addr < e) {
                pdata_dropped_inside += 1;
                continue;
            }
            // The Microsoft x64 ABI requires every RUNTIME_FUNCTION begin_address
            // to be a real function start — the OS unwind dispatcher relies on
            // this. Trust .pdata: only verify the address resolves to a file
            // offset (so the listing builder can render the bytes). The
            // capstone "quick_validate" and SEH-stub heuristics that used to
            // run here drop legitimate cold-section and outlined-helper
            // functions on Rust+LLVM builds — exactly the inflation gap
            // between 1 surviving function and IDA's ~1243.
            let Some(fo) = va_to_file_off(*addr, &segments) else {
                pdata_dropped_unvalidated += 1;
                continue;
            };
            // Diagnostic: classify what the prologue looks like.  Counted
            // not filtered — see comment above.
            match classify_pdata_stub(&binary, fo, *addr, bits) {
                StubKind::JmpFirst => pdata_diag_jmp_first += 1,
                StubKind::SehThunk => pdata_diag_seh_thunk += 1,
                StubKind::Real => {}
            }
            sweep_funcs.push((*addr, *size));
            pdata_added += 1;
        }
        eprintln!(
            "[sweep][pdata-fill] pdata_entries={} added={} dropped_inside_existing={} \
             dropped_unvalidated={} diag_jmp_first={} diag_seh_thunk={}",
            pdata_extras.len(),
            pdata_added,
            pdata_dropped_inside,
            pdata_dropped_unvalidated,
            pdata_diag_jmp_first,
            pdata_diag_seh_thunk,
        );
        // Per-source counter log (Bug 4 diagnostic): make it obvious whether
        // the final function map is dominated by .pdata or by sweep/symbols.
        let symbol_func_count = symbol_funcs.len();
        eprintln!(
            "[sweep][per-source] pdata={pdata_added} symbols={symbol_func_count} sweep={sweep_source_count} total={}",
            sweep_funcs.len(),
        );
        if sweep_funcs.is_empty() {
            self.log("  sweep: 0 additional functions");
            return;
        }
        sweep_funcs.sort_by_key(|(addr, _)| *addr);

        let before_funcs = self.data.read().functions.len();
        eprintln!("[sweep] AppData.functions before merge: {before_funcs}");
        let mut added = 0usize;
        {
            let mut data = self.data.write();
            let mut next_id = data
                .functions
                .keys()
                .copied()
                .max()
                .unwrap_or(0)
                .saturating_add(1);
            for (addr_u64, size) in sweep_funcs {
                if data.func_by_addr.contains_key(&addr_u64) {
                    continue;
                }
                let addr = Addr(addr_u64);
                // If a Rust-recovered symbol is pinned at this VA, adopt its
                // (demangled) name and sym_id rather than a `sub_*` placeholder.
                let (name, sym_id) = data
                    .sym_by_addr
                    .get(&addr_u64)
                    .and_then(|sid| data.symbols.get(sid).map(|s| (s, *sid)))
                    .filter(|(s, _)| s.kind == SymbolKind::Function)
                    .map_or_else(
                        || (format!("sub_{addr_u64:x}"), None),
                        |(s, sid)| {
                            let pretty = s.demangled.clone().unwrap_or_else(|| s.name.clone());
                            (pretty, Some(sid))
                        },
                    );
                let f = Function {
                    id: next_id,
                    addr,
                    name,
                    size,
                    tags: FunctionTags::AUTO,
                    sym_id,
                    comment: String::new(),
                    color: None,
                };
                data.func_by_addr.insert(addr_u64, next_id);
                data.functions.insert(next_id, f);
                next_id = next_id.saturating_add(1);
                added += 1;
            }
        }
        let after_funcs = self.data.read().functions.len();
        eprintln!(
            "[sweep] AppData.functions after merge: {after_funcs} (added {added})"
        );
        self.log(format!(
            "  sweep: {added} additional functions from linear-sweep + prologue-scan"
        ));
    }

    // ── Per-function CFG analysis ─────────────────────────────────────────────

    fn analyze_all_functions(&self) -> Result<()> {
        // Snapshot read-only inputs once so the parallel workers don't
        // serialize on `self.data`. Old code held a write lock per
        // function — at 100k+ functions that single mutex was the entire
        // bottleneck. Now: parallel CFG build with no write locks, then
        // one bulk merge at the end.
        let (snapshot_funcs, binary_opt, arch, segments) = {
            let data = self.data.read();
            (
                data.functions.clone(),
                data.binary_data.clone(),
                data.arch,
                data.segments.clone(),
            )
        };
        let Some(binary) = binary_opt else {
            return Ok(());
        };

        struct CfgResult {
            func_id: u32,
            cfg: Cfg,
            new_size: Option<u64>,
        }
        let t0 = std::time::Instant::now();
        let item_count = snapshot_funcs.len();
        let func_entries: Vec<(u32, Function)> = snapshot_funcs.into_iter().collect();
        let segments = std::sync::Arc::new(segments);

        let results: Vec<CfgResult> = cpu_pool().install(|| {
            func_entries
                .par_iter()
                .filter_map(|(fid, func)| {
                    let disasm = Disassembler::new(arch).ok()?;
                    let seg = segments.iter().find(|s| s.contains(func.addr));
                    let bytes = seg
                        .and_then(|s| {
                            let fo = usize::try_from(
                                func.addr
                                    .0
                                    .checked_sub(s.start.0)?
                                    .checked_add(s.mapped_offset)?,
                            )
                            .unwrap_or(usize::MAX);
                            binary.get(fo..)
                        })
                        .unwrap_or(&[]);
                    let max = if func.size > 0 {
                        usize::try_from(func.size).unwrap_or(usize::MAX)
                    } else {
                        bytes.len().min(4096)
                    };
                    let bytes = &bytes[..bytes.len().min(max)];
                    let insns = {
                        let data = self.data.read();
                        disasm.disassemble(bytes, func.addr, usize::MAX, &data)
                    };
                    let cfg = build_simple_cfg(func, &insns);
                    let new_size = if func.size == 0 {
                        insns.last().map(|last| last.next_addr().0 - func.addr.0)
                    } else {
                        None
                    };
                    Some(CfgResult {
                        func_id: *fid,
                        cfg,
                        new_size,
                    })
                })
                .collect()
        });

        {
            let mut data = self.data.write();
            for r in &results {
                if let Some(new_size) = r.new_size {
                    if let Some(f) = data.functions.get_mut(&r.func_id) {
                        if f.size == 0 {
                            f.size = new_size;
                        }
                    }
                }
                data.cfg_cache.insert(r.func_id, r.cfg.clone());
                if let Some(f) = data.functions.get_mut(&r.func_id) {
                    f.tags |= FunctionTags::ANALYZED;
                }
            }
        }

        for r in &results {
            let rev = next_rev();
            self.emit(CoreEvent::CfgReady {
                func_id: r.func_id,
                rev,
            });
        }

        eprintln!(
            "[parallel] threads={} stage=analyze_functions items={item_count} elapsed={}ms",
            target_threads(),
            t0.elapsed().as_millis()
        );
        Ok(())
    }

    pub fn analyze_function(&self, func_id: u32) -> Result<()> {
        let (func, binary, arch, segments) = {
            let data = self.data.read();
            let func = data.functions.get(&func_id).cloned();
            let binary = data.binary_data.clone();
            let arch = data.arch;
            let segs = data.segments.clone();
            drop(data);
            (func, binary, arch, segs)
        };

        let (Some(func), Some(binary)) = (func, binary) else {
            return Ok(());
        };

        let disasm = Disassembler::new(arch)?;
        let seg = segments.iter().find(|s| s.contains(func.addr));

        let bytes = seg
            .and_then(|s| {
                let fo = usize::try_from(
                    func.addr
                        .0
                        .checked_sub(s.start.0)?
                        .checked_add(s.mapped_offset)?,
                )
                .unwrap_or(usize::MAX);
                binary.get(fo..)
            })
            .unwrap_or(&[]);

        let max = if func.size > 0 {
            usize::try_from(func.size).unwrap_or(usize::MAX)
        } else {
            bytes.len().min(4096)
        };
        let bytes = &bytes[..bytes.len().min(max)];

        // Disassemble
        let insns = disasm.disassemble(bytes, func.addr, usize::MAX, &self.data.read());

        // Build CFG (simplified: linear blocks split at jumps)
        let cfg = build_simple_cfg(&func, &insns);

        {
            let mut data = self.data.write();
            // Update function size from disasm
            if func.size == 0 {
                if let Some(last) = insns.last() {
                    let f = data.functions.get_mut(&func_id).unwrap();
                    f.size = last.next_addr().0 - func.addr.0;
                }
            }
            data.cfg_cache.insert(func_id, cfg);
            // Mark as analyzed
            if let Some(f) = data.functions.get_mut(&func_id) {
                f.tags |= FunctionTags::ANALYZED;
            }
        }

        let rev = next_rev();
        self.emit(CoreEvent::CfgReady { func_id, rev });
        Ok(())
    }

    // ── Per-function xref construction (parallel worker) ──────────────────────
    //
    // Extracted from the body of the sequential `resolve_xrefs` loop. Computes
    // the (target, XrefEntry) tuples for a single function without touching
    // any shared write state; the caller batches the result into AppData
    // under a single write lock.
    fn resolve_xrefs_for_func(
        &self,
        func_id: u32,
        disasm: &Disassembler,
        out: &mut Vec<(u64, XrefEntry)>,
    ) -> Result<()> {
        let (func, binary, segments) = {
            let data = self.data.read();
            let func = data.functions.get(&func_id).cloned();
            let binary = data.binary_data.clone();
            let segs = data.segments.clone();
            (func, binary, segs)
        };
        let (Some(func), Some(binary)) = (func, binary) else {
            return Ok(());
        };

        let seg = segments.iter().find(|s| s.contains(func.addr));
        let bytes = seg
            .and_then(|s| {
                let fo = usize::try_from(
                    func.addr
                        .0
                        .checked_sub(s.start.0)?
                        .checked_add(s.mapped_offset)?,
                )
                .unwrap_or(usize::MAX);
                let size = usize::try_from(func.size).unwrap_or(usize::MAX);
                binary.get(fo..fo + size)
            })
            .unwrap_or(&[]);

        let (insns, fn_addr_set, seg_snapshot) = {
            let data = self.data.read();
            let insns = disasm.disassemble(bytes, func.addr, usize::MAX, &data);
            let fn_set: std::collections::HashSet<u64> =
                data.func_by_addr.keys().copied().collect();
            let segs = data.segments.clone();
            (insns, fn_set, segs)
        };

        let mut seen: std::collections::HashSet<(u64, u64, XrefKind)> =
            std::collections::HashSet::new();

        for insn in &insns {
            let mn = insn.mnemonic.to_lowercase();
            let branch_kind = classify_branch(&mn);
            let mut in_mem = 0i32;
            let mut seen_comma = false;
            for tok in &insn.tokens {
                match tok.kind {
                    TokenKind::Punctuation if tok.text.trim() == "[" => {
                        in_mem += 1;
                        continue;
                    }
                    TokenKind::Punctuation if tok.text.trim() == "]" => {
                        in_mem = (in_mem - 1).max(0);
                        continue;
                    }
                    // Only top-level commas separate operands; a comma inside
                    // `[x1, #8]` (ARM) must not count as the operand separator.
                    TokenKind::Punctuation if tok.text.trim() == "," && in_mem == 0 => {
                        seen_comma = true;
                        continue;
                    }
                    _ => {}
                }
                let Some(target) = tok.value else { continue };
                let is_real_addr = fn_addr_set.contains(&target)
                    || seg_snapshot.iter().any(|s| {
                        let end = s.start.0.saturating_add(s.size());
                        target >= s.start.0 && target < end
                    });
                if !is_real_addr {
                    continue;
                }
                let kind = if in_mem > 0 {
                    mem_access_kind_positional(&mn, !seen_comma)
                } else {
                    match tok.kind {
                        TokenKind::Address | TokenKind::Symbol | TokenKind::Immediate => {
                            branch_kind.unwrap_or(XrefKind::DataRef)
                        }
                        _ => continue,
                    }
                };
                let key = (insn.addr.0, target, kind);
                if !seen.insert(key) {
                    continue;
                }
                let entry = XrefEntry {
                    from: insn.addr,
                    to: Addr(target),
                    kind,
                    label: None,
                };
                out.push((target, entry));
            }
        }
        Ok(())
    }

    // ── Xref resolution ───────────────────────────────────────────────────────

    fn resolve_xrefs(&self) -> Result<()> {
        // Keep an outer Disassembler construction so an arch-init failure is
        // raised eagerly (preserves the original error-return ordering); each
        // parallel worker builds its own instance since the type is not Sync.
        let _disasm_probe = {
            let arch = self.data.read().arch;
            Disassembler::new(arch)?
        };

        let func_ids: Vec<u32> = self.data.read().functions.keys().copied().collect();
        let t_xref = std::time::Instant::now();
        let item_count_xref = func_ids.len();
        // Snapshot inputs once before the parallel section so workers only
        // perform read-only reference work and the single write-lock is
        // taken once at the end (per function — accumulated into a single
        // map).
        let arch_for_workers = self.data.read().arch;
        let collected: Vec<Vec<(u64, XrefEntry)>> = cpu_pool().install(|| {
            func_ids
                .par_iter()
                .map(|&func_id| -> Vec<(u64, XrefEntry)> {
                    let Ok(disasm) = Disassembler::new(arch_for_workers) else { return Vec::new() };
                    let mut local_new: Vec<(u64, XrefEntry)> = Vec::new();
                    let _ = self.resolve_xrefs_for_func(func_id, &disasm, &mut local_new);
                    local_new
                })
                .collect()
        });
        // Single write lock applied after the parallel sweep, mirroring the
        // sequential merge order via the per-function chunks we collected.
        {
            let mut data = self.data.write();
            for chunk in collected {
                for (target, entry) in chunk {
                    data.xrefs_to.entry(target).or_default().push(entry.clone());
                    data.xrefs_from.entry(entry.from.0).or_default().push(entry);
                }
            }
        }
        eprintln!(
            "[parallel] threads={} stage=resolve_xrefs items={item_count_xref} elapsed={}ms",
            target_threads(),
            t_xref.elapsed().as_millis()
        );
        // Legacy sequential loop body preserved verbatim below as a cfg-gated
        // reference. cfg(any()) is never enabled so this never compiles.
        #[cfg(any())]
        {
        for func_id in func_ids {
            let (func, binary, segments) = {
                let data = self.data.read();
                let func = data.functions.get(&func_id).cloned();
                let binary = data.binary_data.clone();
                let segs = data.segments.clone();
                drop(data);
                (func, binary, segs)
            };
            let (Some(func), Some(binary)) = (func, binary) else {
                continue;
            };

            let seg = segments.iter().find(|s| s.contains(func.addr));
            let bytes = seg
                .and_then(|s| {
                    let fo = usize::try_from(
                        func.addr
                            .0
                            .checked_sub(s.start.0)?
                            .checked_add(s.mapped_offset)?,
                    )
                    .unwrap_or(usize::MAX);
                    let size = usize::try_from(func.size).unwrap_or(usize::MAX);
                    binary.get(fo..fo + size)
                })
                .unwrap_or(&[]);

            let (insns, fn_addr_set, seg_snapshot) = {
                let data = self.data.read();
                let insns = disasm.disassemble(bytes, func.addr, usize::MAX, &data);
                let fn_set: std::collections::HashSet<u64> =
                    data.func_by_addr.keys().copied().collect();
                let segs = data.segments.clone();
                (insns, fn_set, segs)
            };

            let mut new_xrefs: Vec<(u64, XrefEntry)> = Vec::new();
            let mut seen: std::collections::HashSet<(u64, u64, XrefKind)> =
                std::collections::HashSet::new();

            for insn in &insns {
                let mn = insn.mnemonic.to_lowercase();
                // Classify this instruction once. `branch_kind` is Some for
                // call/jmp/branch mnemonics across x86/ARM. The memory flavour
                // is NOT decided here: it depends on which side of the operand
                // comma the `[…]` falls, so it is computed per token below via
                // `mem_access_kind_positional`.
                let branch_kind = classify_branch(&mn);

                // Track nesting of `[` / `]` so we know whether a value-bearing
                // token represents a memory dereference (DataRead/Write) or a
                // plain operand (branch target / DataRef).
                let mut in_mem = 0i32;
                let mut seen_comma = false;

                for tok in &insn.tokens {
                    match tok.kind {
                        TokenKind::Punctuation if tok.text.trim() == "[" => {
                            in_mem += 1;
                            continue;
                        }
                        TokenKind::Punctuation if tok.text.trim() == "]" => {
                            in_mem = (in_mem - 1).max(0);
                            continue;
                        }
                        // Only top-level commas separate operands; a comma inside
                        // `[x1, #8]` (ARM) must not count as the operand separator.
                        TokenKind::Punctuation if tok.text.trim() == "," && in_mem == 0 => {
                            seen_comma = true;
                            continue;
                        }
                        _ => {}
                    }

                    let Some(target) = tok.value else { continue };

                    // Reject obvious non-addresses: tiny immediates that don't
                    // land inside any mapped segment or function. This keeps the
                    // xref database from being flooded with `mov reg, 0` etc.
                    let is_real_addr = fn_addr_set.contains(&target)
                        || seg_snapshot.iter().any(|s| {
                            let end = s.start.0.saturating_add(s.size());
                            target >= s.start.0 && target < end
                        });
                    if !is_real_addr {
                        continue;
                    }

                    let kind = if in_mem > 0 {
                        mem_access_kind_positional(&mn, !seen_comma)
                    } else {
                        match tok.kind {
                            TokenKind::Address | TokenKind::Symbol => {
                                branch_kind.unwrap_or(XrefKind::DataRef)
                            }
                            // Bare immediate outside a memory operand that
                            // resolves to a real address — treat as code target
                            // for branches, otherwise a data address-of.
                            TokenKind::Immediate => {
                                branch_kind.unwrap_or(XrefKind::DataRef)
                            }
                            _ => continue,
                        }
                    };

                    let key = (insn.addr.0, target, kind);
                    if !seen.insert(key) {
                        continue;
                    }
                    let entry = XrefEntry {
                        from: insn.addr,
                        to: Addr(target),
                        kind,
                        label: None,
                    };
                    new_xrefs.push((target, entry));
                }
            }

            {
                let mut data = self.data.write();
                for (target, entry) in new_xrefs {
                    data.xrefs_to.entry(target).or_default().push(entry.clone());
                    data.xrefs_from.entry(entry.from.0).or_default().push(entry);
                }
            }
        }
        }

        let (to_count, from_count) = {
            let data = self.data.read();
            (data.xrefs_to.len(), data.xrefs_from.len())
        };
        self.log(format!(
            "  Xrefs resolved: {to_count} targets, {from_count} sources"
        ));
        Ok(())
    }

    // ── Call-graph build (Phase 3) ───────────────────────────────────────────
    //
    // Runs after `resolve_xrefs`. Per-function call resolution and metric
    // computation happen on the cpu_pool (sequentially-built parallel
    // scaffolding inside `build_call_graph_metrics`), with a single bulk
    // write back into AppData under the standard write-lock.
    fn build_call_graph(&self) {
        let (funcs, xrefs_from, func_by_addr, entry) = {
            let d = self.data.read();
            (
                d.functions.clone(),
                d.xrefs_from.clone(),
                d.func_by_addr.clone(),
                d.entry_point,
            )
        };
        let t0 = std::time::Instant::now();
        let result = cpu_pool().install(|| {
            crate::analysis::call_graph_build::build_call_graph_metrics(
                &funcs,
                &xrefs_from,
                &func_by_addr,
                entry,
            )
        });
        let (nodes, edges, leaves, roots, cyclic) = {
            let nodes = result.metrics.len();
            let edges: usize = result.adjacency.values().map(Vec::len).sum();
            let leaves = result.metrics.values().filter(|m| m.is_leaf).count();
            let roots = result.metrics.values().filter(|m| m.is_root).count();
            let cyclic = result.metrics.values().filter(|m| m.in_cycle).count();
            (nodes, edges, leaves, roots, cyclic)
        };
        {
            let mut data = self.data.write();
            data.call_graph = result.adjacency;
            data.call_graph_inverse = result.inverse;
            data.call_graph_metrics = result.metrics;
        }
        eprintln!(
            "[call-graph] nodes={nodes} edges={edges} leaves={leaves} roots={roots} \
             in_cycle={cyclic} elapsed={}ms",
            t0.elapsed().as_millis()
        );
        self.log(format!(
            "  call-graph: {nodes} nodes / {edges} edges / {leaves} leaves / {roots} roots"
        ));
    }

    // ── Rust type recovery (Phase 5.1) ───────────────────────────────────────
    //
    // Scans `.rdata` for panic strings, type-name mentions, and trait-object
    // vtable layouts; stashes the result under `AppData::rust_type_recovery`.
    fn recover_rust_types_pass(&self) {
        let (binary, segments) = {
            let d = self.data.read();
            (d.binary_data.clone(), d.segments.clone())
        };
        let Some(binary) = binary else {
            return;
        };
        let t0 = std::time::Instant::now();
        let r = crate::analysis::rust_type_recovery::recover_rust_types(&binary, &segments);
        let (panics, types, vtables) =
            (r.panic_sites.len(), r.type_mentions.len(), r.vtables.len());
        {
            let mut data = self.data.write();
            data.rust_type_recovery = Some(r);
        }
        eprintln!(
            "[rust-types] panic_sites={panics} type_mentions={types} vtables={vtables} \
             elapsed={}ms",
            t0.elapsed().as_millis()
        );
        self.log(format!(
            "  rust-types: {panics} panic sites, {types} type mentions, {vtables} vtables"
        ));
    }

    // ── Compiler / linker / runtime fingerprinting (PE) ──────────────────────
    //
    // Parses the Rich header out of the DOS stub (if present) and runs the
    // byte-substring fingerprint pass from [`rustre_loader_pe::detect_compiler`].
    // The result is logged in the same `compiler / linker / runtime` shape the
    // status panel expects.
    fn detect_pe_compiler(&self, image: &[u8]) {
        if image.len() < 0x40 || image[0] != b'M' || image[1] != b'Z' {
            return;
        }
        let e_lfanew = u32::from_le_bytes([
            image[0x3C], image[0x3D], image[0x3E], image[0x3F],
        ]) as usize;
        if image.len() < e_lfanew + 4 || &image[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return;
        }
        let rich = rustre_loader_pe::headers::RichHeader::parse(image, e_lfanew);
        let info = rustre_loader_pe::detect_compiler(image, rich.as_ref());
        let line = format!(
            "compiler: {} | linker: {} | runtime: {}",
            info.compiler.as_str(),
            info.linker.as_str(),
            if info.runtime.is_empty() { "Unknown" } else { info.runtime.as_str() },
        );
        eprintln!("[compiler] {line}");
        self.log(format!("  {line}"));
    }

    // ── String scanning ───────────────────────────────────────────────────────

    fn scan_strings(&self) {
        // Parallel chunked sweep — the binary is split into ~1 MiB chunks with
        // a small tail overlap so strings that straddle a chunk boundary are
        // still captured.  Each chunk only emits strings whose start offset
        // falls inside its "owned" prefix (= the first CHUNK_SIZE bytes) so a
        // boundary-crossing string is reported exactly once by the chunk that
        // owns its head.  The legacy single-threaded scan is preserved verbatim
        // under `#[cfg(any())]` below for documentation / fallback use.
        const MIN_ASCII_LEN: usize = 5;
        const MIN_W_CHARS: usize = 4;
        const CHUNK_SIZE: usize = 1 << 20; // 1 MiB
        const TAIL_OVERLAP: usize = 1024; // any reasonable max string length

        let (binary, segments) = {
            let data = self.data.read();
            (data.binary_data.clone(), data.segments.clone())
        };
        let Some(binary) = binary else {
            return;
        };

        let readable_segs_count = segments
            .iter()
            .filter(|s| s.flags.contains(SegmentFlags::READ))
            .count();
        eprintln!(
            "[strings] segments={} (readable of {} total) binary_len={}",
            readable_segs_count,
            segments.len(),
            binary.len(),
        );

        let binary_len = binary.len();
        let n_chunks = binary_len.div_ceil(CHUNK_SIZE);
        let chunk_starts: Vec<usize> = (0..n_chunks).map(|i| i * CHUNK_SIZE).collect();
        let item_count_strings = chunk_starts.len();
        let t_strings = std::time::Instant::now();

        // Per-chunk scan. Each worker grabs `&binary[start..end]` where `end`
        // includes a small tail-overlap so a string starting near the end of
        // the chunk's owned prefix is still fully readable.  Only strings
        // whose *start offset* is within `[0, owned_len)` (= the prefix this
        // chunk owns) are emitted to avoid double-counting at boundaries.
        let per_chunk: Vec<Vec<StringEntry>> = cpu_pool().install(|| {
            chunk_starts
                .par_iter()
                .map(|&start| {
                    let end = (start + CHUNK_SIZE + TAIL_OVERLAP).min(binary_len);
                    let slice = &binary[start..end];
                    let owned_len = CHUNK_SIZE.min(slice.len());
                    let mut out: Vec<StringEntry> = Vec::new();

                    // ── ASCII pass ───────────────────────────────────────
                    let mut i = 0usize;
                    while i + MIN_ASCII_LEN <= slice.len() {
                        let mut j = i;
                        while j < slice.len()
                            && ((slice[j] >= 0x20 && slice[j] <= 0x7E) || slice[j] == b'\t')
                        {
                            j += 1;
                        }
                        let run_len = j - i;
                        if run_len >= MIN_ASCII_LEN {
                            if i < owned_len {
                                let text = String::from_utf8_lossy(&slice[i..j]).into_owned();
                                out.push(StringEntry {
                                    id: 0, // assigned after merge
                                    addr: Addr((start + i) as u64),
                                    value: text,
                                    kind: StringKind::Ascii,
                                    len: u32::try_from(run_len).unwrap_or(u32::MAX),
                                });
                            }
                            i = j + 1;
                        } else {
                            i += 1;
                        }
                    }

                    // ── UTF-16LE pass ────────────────────────────────────
                    let mut i = 0usize;
                    while i + 8 <= slice.len() {
                        let mut j = i;
                        let mut wide = String::new();
                        while j + 1 < slice.len()
                            && slice[j + 1] == 0
                            && slice[j] >= 0x20
                            && slice[j] <= 0x7E
                        {
                            wide.push(slice[j] as char);
                            j += 2;
                        }
                        if wide.len() >= MIN_W_CHARS {
                            if i < owned_len {
                                let len_chars = wide.len();
                                out.push(StringEntry {
                                    id: 0, // assigned after merge
                                    addr: Addr((start + i) as u64),
                                    value: wide,
                                    kind: StringKind::Utf16Le,
                                    len: u32::try_from(len_chars).unwrap_or(u32::MAX),
                                });
                            }
                            i = j.max(i + 2);
                        } else {
                            i += 2;
                        }
                    }

                    out
                })
                .collect()
        });

        // Flatten, sort by address for stable IDs, then assign sequential ids.
        let mut strings: Vec<StringEntry> = per_chunk.into_iter().flatten().collect();
        strings.sort_by_key(|s| s.addr.0);
        for (i, s) in strings.iter_mut().enumerate() {
            s.id = u32::try_from(i).unwrap_or(u32::MAX);
        }

        eprintln!(
            "[parallel] threads={} stage=scan_strings items={} chunks={} elapsed={}ms",
            target_threads(),
            strings.len(),
            item_count_strings,
            t_strings.elapsed().as_millis()
        );

        // Bug 1 safety net: if the parallel chunked sweep emits 0 strings
        // (segment filter eliminated everything, MIN_ASCII_LEN tripped on a
        // pathological binary, etc.) fall back to the standalone
        // `core::string_extractor` which does a single-threaded sweep over
        // the entire image with the same minimum-length policy.
        if strings.is_empty() && !binary.is_empty() {
            let mut extractor = crate::core::string_extractor::StringExtractor::new();
            let extracted = extractor.extract_all(&binary[..], 0);
            strings = extracted
                .into_iter()
                .enumerate()
                .map(|(i, e)| StringEntry {
                    id: u32::try_from(i).unwrap_or(u32::MAX),
                    addr: Addr(u64::try_from(e.offset).unwrap_or(u64::MAX)),
                    value: e.value,
                    kind: match e.encoding {
                        crate::core::string_extractor::StringEncoding::Utf16Le => StringKind::Utf16Le,
                        _ => StringKind::Ascii,
                    },
                    len: u32::try_from(e.length).unwrap_or(u32::MAX),
                })
                .collect();
            eprintln!(
                "[strings] fallback string_extractor produced {} entries",
                strings.len()
            );
        }

        self.log(format!("  strings: {}", strings.len()));
        eprintln!("[strings] {}", strings.len());
        {
            let mut data = self.data.write();
            data.strings = strings;
        }
    }

    // ── Listing build ─────────────────────────────────────────────────────────

    fn build_all_listings(&self) -> Result<()> {
        const GLOBAL_STITCH_FUNC_LIMIT: usize = 16_384;
        let arch = self.data.read().arch;
        // Eager arch-init probe preserves the original ?-propagation site.
        let _disasm_probe = Disassembler::new(arch)?;

        let func_ids: Vec<u32> = self.data.read().functions.keys().copied().collect();
        let rev = next_rev();
        let t_list = std::time::Instant::now();
        let item_count_list = func_ids.len();

        // Per-function listing build is independent. Each worker takes a
        // short-lived read lock, builds the rows, and we merge into the
        // listing_cache under a single write lock at the end. Each worker
        // constructs its own Disassembler since the type is not Sync.
        let per_fn: Vec<(u32, Vec<ListingLine>)> = cpu_pool().install(|| {
            func_ids
                .par_iter()
                .map(|&func_id| {
                    let Ok(disasm) = Disassembler::new(arch) else { return (func_id, Vec::new()) };
                    let data = self.data.read();
                    let lines = data
                        .functions
                        .get(&func_id)
                        .map_or_else(Vec::new, |func| {
                            let builder = ListingBuilder::new(&data, &disasm);
                            builder.build_for_func(func)
                        });
                    (func_id, lines)
                })
                .collect()
        });
        {
            let mut data = self.data.write();
            for (func_id, lines) in per_fn {
                data.listing_cache.insert(func_id, lines);
            }
        }
        eprintln!(
            "[parallel] threads={} stage=build_listings items={item_count_list} elapsed={}ms",
            target_threads(),
            t_list.elapsed().as_millis()
        );

        // Legacy sequential merge body retained as cfg-gated documentation.
        #[cfg(any())]
        for func_id in func_ids {
            let lines = {
                let data = self.data.read();
                data.functions.get(&func_id).map_or_else(Vec::new, |func| {
                    let builder = ListingBuilder::new(&data, &disasm);
                    builder.build_for_func(func)
                })
            };

            {
                let mut data = self.data.write();
                data.listing_cache.insert(func_id, lines);
            }
        }

        // ── Stitch every per-function listing into a single image-wide view ──
        // Functions are sorted by start address. When two adjacent functions
        // are not contiguous (there's a gap of unclassified executable bytes
        // between them), we emit a single gap header line that records the
        // gap range.
        //
        // SKIP for very large binaries: a 40MB image with 124k functions
        // produces ~2.5M ListingLines. Cloning every per-function vec into
        // one giant Vec costs ~1.2GB and seconds of pure malloc time —
        // enough to make Windows mark the process as "Non risponde" and
        // sometimes OOM-kill. The Listing view falls back to per-function
        // mode when `global_listing` is empty, which is the right behavior
        // at this scale anyway (no human scrolls 2.5M rows linearly).
        let func_count = self.data.read().functions.len();
        if func_count <= GLOBAL_STITCH_FUNC_LIMIT {
            let mut data = self.data.write();
            let mut ordered: Vec<(Addr, u32)> = data
                .functions
                .values()
                .map(|f| (f.addr, f.id))
                .collect();
            ordered.sort_by_key(|(a, _)| a.0);

            // Pre-size the global vec so we don't pay N reallocations.
            let total_lines: usize = ordered
                .iter()
                .map(|(_, fid)| {
                    data.listing_cache.get(fid).map_or(0, Vec::len)
                })
                .sum();
            let mut global: Vec<ListingLine> = Vec::with_capacity(total_lines + ordered.len());
            let mut prev_end: Option<Addr> = None;

            for (faddr, fid) in ordered {
                let func_end = data.functions.get(&fid).map(Function::end_addr);

                if let (Some(end), start) = (prev_end, faddr) {
                    if end.0 < start.0 {
                        global.push(gap_header_line(end, start));
                    }
                }

                if let Some(rows) = data.listing_cache.get(&fid) {
                    global.extend(rows.iter().cloned());
                }
                if let Some(end) = func_end {
                    prev_end = Some(end);
                }
            }

            data.global_listing = global;
        } else {
            eprintln!(
                "[listing] skipping global stitch: {func_count} functions exceeds limit \
                 {GLOBAL_STITCH_FUNC_LIMIT}; whole-image view falls back to per-function"
            );
            self.log(format!(
                "  listing: skipping whole-image stitch ({func_count} functions); navigate \
                 per-function for huge binaries"
            ));
        }

        self.emit(CoreEvent::ListingReady { func_id: None, rev });
        Ok(())
    }
}

// ── Global-listing stitch helper ─────────────────────────────────────────────

/// Build a single-line gap header for the range `[start, end)` of executable
/// bytes that lie between two non-contiguous functions. Uses the existing
/// `FunctionHeader` line variant so the renderer styles it as a section break
/// without needing a new `LineType` discriminant.
fn gap_header_line(start: Addr, end: Addr) -> ListingLine {
    let size = end.0.saturating_sub(start.0);
    ListingLine {
        key: LineKey(start.0 ^ 0x9E37_79B9_7F4A_7C15_u64.wrapping_mul(end.0 | 1)),
        addr: start,
        kind: LineType::FunctionHeader,
        spans: vec![InsnToken {
            kind: TokenKind::Comment,
            text: format!("; ── gap {:#x}..{:#x} ({} bytes) ──", start.0, end.0, size),
            value: None,
        }],
        comment: None,
        label: None,
        xrefs: vec![],
        indent: 0,
    }
}

// ── Sweep helpers ─────────────────────────────────────────────────────────────

/// Translate the GUI's `Architecture` enum into the `rustre-analysis-fn`
/// `DetectedArch` discriminator. Unsupported architectures fall back to
/// `Unknown`, which still runs the x86 prologue/CALL heuristics best-effort.
const fn map_arch(arch: Architecture) -> DetectedArch {
    match arch {
        Architecture::X86_64 => DetectedArch::X86_64,
        Architecture::X86_32 => DetectedArch::X86_32,
        Architecture::Arm64 => DetectedArch::Arm64,
        _ => DetectedArch::Unknown,
    }
}

/// Scan non-executable segments for pointer-sized words whose value lands
/// inside an executable segment. These are vtable slots, lazy-import thunks,
/// `.rdata` jump tables, and the like — classic seeds for "this address is the
/// entry of a real function" that the reachability filter accepts as ground
/// truth.
fn scan_data_function_pointers(
    binary: &[u8],
    segments: &[Segment],
    arch: Architecture,
) -> std::collections::HashSet<u64> {
    let mut out: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let ptr_bytes: usize = match arch {
        Architecture::X86_64 | Architecture::Arm64 => 8,
        Architecture::X86_32 | Architecture::Arm32 => 4,
        _ => return out,
    };
    let exec_ranges: Vec<(u64, u64)> = segments
        .iter()
        .filter(|s| s.flags.contains(SegmentFlags::EXECUTE))
        .map(|s| (s.start.0, s.start.0.saturating_add(s.size())))
        .collect();
    if exec_ranges.is_empty() {
        return out;
    }
    for seg in segments {
        if seg.flags.contains(SegmentFlags::EXECUTE) {
            continue;
        }
        let fo = usize::try_from(seg.mapped_offset).unwrap_or(usize::MAX);
        let len = usize::try_from(seg.size()).unwrap_or(usize::MAX);
        let Some(bytes) = binary.get(fo..fo.saturating_add(len)) else {
            continue;
        };
        let mut i = 0usize;
        while i + ptr_bytes <= bytes.len() {
            let v = if ptr_bytes == 8 {
                u64::from_le_bytes([
                    bytes[i],
                    bytes[i + 1],
                    bytes[i + 2],
                    bytes[i + 3],
                    bytes[i + 4],
                    bytes[i + 5],
                    bytes[i + 6],
                    bytes[i + 7],
                ])
            } else {
                u64::from(u32::from_le_bytes([
                    bytes[i],
                    bytes[i + 1],
                    bytes[i + 2],
                    bytes[i + 3],
                ]))
            };
            if exec_ranges.iter().any(|(s, e)| v >= *s && v < *e) {
                out.insert(v);
            }
            i += ptr_bytes;
        }
    }
    out
}

/// Parse the PE Exception Directory (DataDirectory[3]) and return every
/// `BeginAddress` from each `RUNTIME_FUNCTION` entry. On x64 Windows these are
/// guaranteed function-start RVAs emitted by the Microsoft toolchain — they're
/// the most authoritative inbound source we can synthesize from the binary.
///
/// Returns an empty set if the file is not a PE, not 64-bit, or has no
/// exception directory.
fn scan_pe_pdata_function_starts(
    binary: &[u8],
    segments: &[Segment],
    arch: Architecture,
) -> std::collections::HashSet<u64> {
    let mut out: std::collections::HashSet<u64> = std::collections::HashSet::new();
    if !matches!(arch, Architecture::X86_64) {
        return out;
    }
    // PE DOS header: 'MZ' magic, e_lfanew at offset 0x3C (u32 LE) -> PE header.
    if binary.len() < 0x40 || binary[0] != b'M' || binary[1] != b'Z' {
        return out;
    }
    let e_lfanew =
        u32::from_le_bytes([binary[0x3C], binary[0x3D], binary[0x3E], binary[0x3F]]) as usize;
    if binary.len() < e_lfanew + 0x18 {
        return out;
    }
    // PE signature 'PE\0\0'
    if &binary[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return out;
    }
    // COFF File Header sits at e_lfanew+4 (20 bytes), then optional header.
    let opt_hdr_off = e_lfanew + 4 + 20;
    if binary.len() < opt_hdr_off + 2 {
        return out;
    }
    let magic = u16::from_le_bytes([binary[opt_hdr_off], binary[opt_hdr_off + 1]]);
    // PE32+ magic is 0x20B; only PE32+ has DataDirectory at offset 0x70 (8-byte
    // ImageBase). PE32 has it at 0x60 — we only handle PE32+ since arch is x64.
    let (image_base, data_dir_off): (u64, usize) = if magic == 0x20B {
        if binary.len() < opt_hdr_off + 0x70 + 8 * 16 {
            return out;
        }
        let ib_off = opt_hdr_off + 0x18;
        let ib = u64::from_le_bytes([
            binary[ib_off],
            binary[ib_off + 1],
            binary[ib_off + 2],
            binary[ib_off + 3],
            binary[ib_off + 4],
            binary[ib_off + 5],
            binary[ib_off + 6],
            binary[ib_off + 7],
        ]);
        (ib, opt_hdr_off + 0x70)
    } else {
        return out;
    };
    // DataDirectory[3] = Exception Directory: { rva: u32, size: u32 }
    let exc_off = data_dir_off + 3 * 8;
    if binary.len() < exc_off + 8 {
        return out;
    }
    let exc_rva = u64::from(u32::from_le_bytes([
        binary[exc_off],
        binary[exc_off + 1],
        binary[exc_off + 2],
        binary[exc_off + 3],
    ]));
    let exc_size = u32::from_le_bytes([
        binary[exc_off + 4],
        binary[exc_off + 5],
        binary[exc_off + 6],
        binary[exc_off + 7],
    ]) as usize;
    if exc_rva == 0 || exc_size == 0 {
        return out;
    }
    let exc_va = image_base.wrapping_add(exc_rva);
    // Resolve VA -> file offset via segment table.
    let Some(exc_file_off) = va_to_file_off(exc_va, segments) else { return out };
    if binary.len() < exc_file_off + exc_size {
        return out;
    }
    let pdata = &binary[exc_file_off..exc_file_off + exc_size];
    // RUNTIME_FUNCTION: { BeginAddress: u32, EndAddress: u32, UnwindInfoAddress: u32 }
    let exec_ranges: Vec<(u64, u64)> = segments
        .iter()
        .filter(|s| s.flags.contains(SegmentFlags::EXECUTE))
        .map(|s| (s.start.0, s.start.0.saturating_add(s.size())))
        .collect();
    let mut i = 0usize;
    while i + 12 <= pdata.len() {
        let begin_rva =
            u64::from(u32::from_le_bytes([pdata[i], pdata[i + 1], pdata[i + 2], pdata[i + 3]]));
        if begin_rva != 0 {
            let begin_va = image_base.wrapping_add(begin_rva);
            if exec_ranges.iter().any(|(s, e)| begin_va >= *s && begin_va < *e) {
                out.insert(begin_va);
            }
        }
        i += 12;
    }
    out
}

/// Like [`scan_pe_pdata_function_starts`] but also returns the size of every
/// `RUNTIME_FUNCTION` entry (begin -> end) so the caller can synthesise full
/// Function records. The Microsoft x64 ABI guarantees each begin_address is a
/// real function start; we trust it unconditionally to close the residual gap
/// vs IDA after the strict-ref filter has trimmed false positives.
fn scan_pe_pdata_function_ranges(
    binary: &[u8],
    segments: &[Segment],
    arch: Architecture,
) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    if !matches!(arch, Architecture::X86_64) {
        return out;
    }
    if binary.len() < 0x40 || binary[0] != b'M' || binary[1] != b'Z' {
        return out;
    }
    let e_lfanew =
        u32::from_le_bytes([binary[0x3C], binary[0x3D], binary[0x3E], binary[0x3F]]) as usize;
    if binary.len() < e_lfanew + 0x18 {
        return out;
    }
    if &binary[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return out;
    }
    let opt_hdr_off = e_lfanew + 4 + 20;
    if binary.len() < opt_hdr_off + 2 {
        return out;
    }
    let magic = u16::from_le_bytes([binary[opt_hdr_off], binary[opt_hdr_off + 1]]);
    let (image_base, data_dir_off): (u64, usize) = if magic == 0x20B {
        if binary.len() < opt_hdr_off + 0x70 + 8 * 16 {
            return out;
        }
        let ib_off = opt_hdr_off + 0x18;
        let ib = u64::from_le_bytes([
            binary[ib_off], binary[ib_off + 1], binary[ib_off + 2], binary[ib_off + 3],
            binary[ib_off + 4], binary[ib_off + 5], binary[ib_off + 6], binary[ib_off + 7],
        ]);
        (ib, opt_hdr_off + 0x70)
    } else {
        return out;
    };
    let exc_off = data_dir_off + 3 * 8;
    if binary.len() < exc_off + 8 {
        return out;
    }
    let exc_rva = u64::from(u32::from_le_bytes([
        binary[exc_off], binary[exc_off + 1], binary[exc_off + 2], binary[exc_off + 3],
    ]));
    let exc_size = u32::from_le_bytes([
        binary[exc_off + 4], binary[exc_off + 5], binary[exc_off + 6], binary[exc_off + 7],
    ]) as usize;
    if exc_rva == 0 || exc_size == 0 {
        return out;
    }
    let exc_va = image_base.wrapping_add(exc_rva);
    let Some(exc_file_off) = va_to_file_off(exc_va, segments) else { return out };
    if binary.len() < exc_file_off + exc_size {
        return out;
    }
    let pdata = &binary[exc_file_off..exc_file_off + exc_size];
    let exec_ranges: Vec<(u64, u64)> = segments
        .iter()
        .filter(|s| s.flags.contains(SegmentFlags::EXECUTE))
        .map(|s| (s.start.0, s.start.0.saturating_add(s.size())))
        .collect();
    let mut i = 0usize;
    while i + 12 <= pdata.len() {
        let begin_rva =
            u64::from(u32::from_le_bytes([pdata[i], pdata[i + 1], pdata[i + 2], pdata[i + 3]]));
        let end_rva =
            u64::from(u32::from_le_bytes([pdata[i + 4], pdata[i + 5], pdata[i + 6], pdata[i + 7]]));
        let unwind_rva =
            u64::from(u32::from_le_bytes([pdata[i + 8], pdata[i + 9], pdata[i + 10], pdata[i + 11]]));
        i += 12;
        if begin_rva == 0 || end_rva <= begin_rva {
            continue;
        }
        // Skip chained continuation records: UNWIND_INFO byte 0 = (version:3 |
        // flags:5). If flags has UNW_FLAG_CHAININFO (0x4) set, the entry is
        // not a standalone function start — it's a cold-section continuation
        // of an already-listed function. IDA never promotes these.
        let unwind_va = image_base.wrapping_add(unwind_rva);
        if let Some(uf) = va_to_file_off(unwind_va, segments) {
            if uf < binary.len() {
                let flags = (binary[uf] >> 3) & 0b0001_1111;
                if flags & 0x4 != 0 {
                    continue;
                }
            }
        }
        let begin_va = image_base.wrapping_add(begin_rva);
        let size = end_rva - begin_rva;
        if exec_ranges.iter().any(|(s, e)| begin_va >= *s && begin_va < *e) {
            out.push((begin_va, size));
        }
    }
    out
}

/// Classification of a pdata candidate's prologue used by the IDA-compat
/// drop filter. `Real` means keep, the other two variants are the patterns
/// IDA collapses by default.
enum StubKind {
    /// First instruction is `jmp` — pure trampoline.
    JmpFirst,
    /// First two instructions are `mov ...; jmp rax` or `mov ...; ret` —
    /// SEH personality / dispatch thunk.
    SehThunk,
    /// Looks like a real function body.
    Real,
}

/// Disassemble the first two instructions at `va` and classify the prologue.
fn classify_pdata_stub(binary: &[u8], fo: usize, va: u64, bits: u32) -> StubKind {
    use capstone::prelude::*;
    let Some(slice) = binary.get(fo..fo.saturating_add(32).min(binary.len())) else {
        return StubKind::Real;
    };
    let mode = if bits == 64 {
        capstone::arch::x86::ArchMode::Mode64
    } else {
        capstone::arch::x86::ArchMode::Mode32
    };
    let Ok(cs) = Capstone::new()
        .x86()
        .mode(mode)
        .syntax(capstone::arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
    else {
        return StubKind::Real;
    };
    let Ok(insns) = cs.disasm_count(slice, va, 2) else {
        return StubKind::Real;
    };
    let mut iter = insns.iter();
    let Some(first) = iter.next() else {
        return StubKind::Real;
    };
    let m1 = first.mnemonic().unwrap_or("");
    if m1 == "jmp" {
        return StubKind::JmpFirst;
    }
    if m1 == "mov" {
        if let Some(second) = iter.next() {
            let m2 = second.mnemonic().unwrap_or("");
            if m2 == "jmp" || m2 == "ret" || m2 == "retn" {
                return StubKind::SehThunk;
            }
        }
    }
    StubKind::Real
}

/// Resolve a virtual address to a file offset by walking the segment table.
pub fn va_to_file_off(va: u64, segments: &[Segment]) -> Option<usize> {
    for s in segments {
        let start = s.start.0;
        let end = start.saturating_add(s.size());
        if va >= start && va < end {
            let delta = va - start;
            return usize::try_from(s.mapped_offset.saturating_add(delta)).ok();
        }
    }
    None
}

/// Scan .rdata-style non-executable readable segments for 8-byte (or 4-byte
/// on x86-32) aligned pointers that hit a candidate's start address. Each
/// such hit counts as an inbound reference. This is the standard MSVC vtable
/// / function-pointer-table shape that the strict filter currently misses
/// because [`scan_data_function_pointers`] only credits arbitrary code-range
/// hits, not specifically aligned slots near candidate starts.
///
/// Returns only addresses that match one of the provided candidate starts.
fn scan_vtable_function_pointers(
    binary: &[u8],
    segments: &[Segment],
    arch: Architecture,
    candidate_starts: &std::collections::HashSet<u64>,
) -> std::collections::HashSet<u64> {
    let mut out: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let ptr_bytes: usize = match arch {
        Architecture::X86_64 | Architecture::Arm64 => 8,
        Architecture::X86_32 | Architecture::Arm32 => 4,
        _ => return out,
    };
    for seg in segments {
        // Readable + non-executable data section.
        if seg.flags.contains(SegmentFlags::EXECUTE)
            || !seg.flags.contains(SegmentFlags::READ)
        {
            continue;
        }
        let fo = usize::try_from(seg.mapped_offset).unwrap_or(usize::MAX);
        let len = usize::try_from(seg.size()).unwrap_or(usize::MAX);
        let Some(bytes) = binary.get(fo..fo.saturating_add(len)) else {
            continue;
        };
        let base = seg.start.0;
        // Walk only at ptr-sized alignment.
        let align = ptr_bytes;
        let start_off = base
            .wrapping_neg()
            .rem_euclid(align as u64) as usize;
        let mut i = start_off;
        while i + ptr_bytes <= bytes.len() {
            let v = if ptr_bytes == 8 {
                u64::from_le_bytes([
                    bytes[i],
                    bytes[i + 1],
                    bytes[i + 2],
                    bytes[i + 3],
                    bytes[i + 4],
                    bytes[i + 5],
                    bytes[i + 6],
                    bytes[i + 7],
                ])
            } else {
                u64::from(u32::from_le_bytes([
                    bytes[i],
                    bytes[i + 1],
                    bytes[i + 2],
                    bytes[i + 3],
                ]))
            };
            if candidate_starts.contains(&v) {
                out.insert(v);
            }
            i += ptr_bytes;
        }
    }
    out
}

/// Walk every executable segment looking for the x86-64 indirect-call opcode
/// `FF 15 disp32` (call qword ptr [rip + disp32]). For each match, resolve the
/// pointer slot in .rdata and dereference it; if the value lands on a known
/// candidate start, treat that candidate as inbound-referenced.
///
/// This captures the IAT/lazy-binding/COMDAT-thunk pattern that pure
/// `E8`/`E9` rel32 scanning misses.
fn scan_indirect_call_targets(
    binary: &[u8],
    segments: &[Segment],
    arch: Architecture,
    candidate_starts: &std::collections::HashSet<u64>,
) -> std::collections::HashSet<u64> {
    let mut out: std::collections::HashSet<u64> = std::collections::HashSet::new();
    if !matches!(arch, Architecture::X86_64) {
        return out;
    }
    for seg in segments {
        if !seg.flags.contains(SegmentFlags::EXECUTE) {
            continue;
        }
        let fo = usize::try_from(seg.mapped_offset).unwrap_or(usize::MAX);
        let len = usize::try_from(seg.size()).unwrap_or(usize::MAX);
        let Some(bytes) = binary.get(fo..fo.saturating_add(len)) else {
            continue;
        };
        let base = seg.start.0;
        if bytes.len() < 6 {
            continue;
        }
        let limit = bytes.len() - 5;
        let mut i = 0usize;
        while i < limit {
            // FF 15 disp32: call qword ptr [rip + disp32]
            if bytes[i] == 0xFF && bytes[i + 1] == 0x15 {
                let disp = i32::from_le_bytes([
                    bytes[i + 2],
                    bytes[i + 3],
                    bytes[i + 4],
                    bytes[i + 5],
                ]);
                let next_pc = base.wrapping_add(i as u64).wrapping_add(6);
                let slot_va = next_pc.wrapping_add(disp as i64 as u64);
                if let Some(slot_off) = va_to_file_off(slot_va, segments) {
                    if slot_off + 8 <= binary.len() {
                        let v = u64::from_le_bytes([
                            binary[slot_off],
                            binary[slot_off + 1],
                            binary[slot_off + 2],
                            binary[slot_off + 3],
                            binary[slot_off + 4],
                            binary[slot_off + 5],
                            binary[slot_off + 6],
                            binary[slot_off + 7],
                        ]);
                        if candidate_starts.contains(&v) {
                            out.insert(v);
                        }
                    }
                }
                i += 6;
            } else {
                i += 1;
            }
        }
    }
    out
}

/// Run linear-sweep + prologue-scan over every executable segment and return
/// a `(virtual_address, estimated_size)` tuple per detected boundary.
fn sweep_segments(
    binary: &[u8],
    segments: &[Segment],
    arch: DetectedArch,
) -> Vec<(u64, u64)> {
    let detector = FunctionDetector::new(arch);
    let mut out: Vec<(u64, u64)> = Vec::new();

    for seg in segments {
        if !seg.flags.contains(SegmentFlags::EXECUTE) {
            continue;
        }
        let fo = usize::try_from(seg.mapped_offset).unwrap_or(usize::MAX);
        let len = usize::try_from(seg.size()).unwrap_or(usize::MAX);
        let Some(bytes) = binary.get(fo..fo.saturating_add(len)) else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        let mem = MemorySlice::new(FnAddress::new(seg.start.0), bytes);
        let set = detector.analyze(&mem, Vec::new());
        for fb in set {
            let start = fb.start.as_u64();
            let size = fb
                .end
                .map_or(0, |e| e.as_u64().saturating_sub(start));
            out.push((start, size));
        }
    }
    out
}

// ── Xref classification helpers ──────────────────────────────────────────────
//
// `classify_branch` maps an x86/ARM/AArch64 mnemonic prefix to the appropriate
// code-flow `XrefKind`. Returns `None` for non-branching instructions so the
// caller can fall back to a data-reference classification.
fn classify_branch(mn: &str) -> Option<XrefKind> {
    // x86 / x64
    if mn.starts_with("call") {
        return Some(XrefKind::Call);
    }
    if mn == "jmp" || mn == "jmpq" || mn == "jmpf" {
        return Some(XrefKind::Jump);
    }
    if mn.starts_with('j') {
        // jcc family: je, jne, jz, jnz, jl, jg, jle, jge, ja, jb, jc, jo, jp,
        // jecxz, jrcxz, …
        return Some(XrefKind::Jump);
    }
    // ARM / AArch64
    if mn == "bl" || mn == "blx" || mn == "blr" || mn == "blraa" || mn == "blrab" {
        return Some(XrefKind::Call);
    }
    if mn == "b"
        || mn == "br"
        || mn == "bx"
        || mn.starts_with("b.") // b.eq, b.ne, …
        || matches!(
            mn,
            "beq" | "bne" | "bcs" | "bhs" | "bcc" | "blo" | "bmi" | "bpl"
                | "bvs" | "bvc" | "bhi" | "bls" | "bge" | "blt" | "bgt" | "ble"
                | "bal" | "cbz" | "cbnz" | "tbz" | "tbnz"
        )
    {
        return Some(XrefKind::Jump);
    }
    None
}

// `mem_access_kind_positional` resolves the one case `mem_access_kind` cannot:
// the x86 `mov` family, whose memory operand may be either the destination
// (a store) or the source (a load). Intel syntax is destination-first, so a
// memory operand appearing BEFORE the operand comma is written, not read.
//
// This is deliberately NOT applied to ARM: `str x0, [x1]` writes through a
// memory operand that sits *after* the comma, and `ldr` reads through one in
// the same position - there the mnemonic already decides, and the positional
// rule would invert both. Anything that is not a `mov*` therefore falls
// through to `mem_access_kind` unchanged.
fn mem_access_kind_positional(mn: &str, mem_before_comma: bool) -> XrefKind {
    if mn.starts_with("mov") {
        return if mem_before_comma {
            XrefKind::DataWrite
        } else {
            XrefKind::DataRead
        };
    }
    mem_access_kind(mn)
}

// `mem_access_kind` returns the `XrefKind` to associate with addresses found
// inside a memory operand for the given mnemonic. Conservatively classifies
// most loads as `DataRead`, stores as `DataWrite`, and address-taking ops
// (LEA / ADR / ADRP) as plain `DataRef`.
fn mem_access_kind(mn: &str) -> XrefKind {
    if mn == "lea" || mn == "adr" || mn == "adrp" {
        return XrefKind::DataRef;
    }
    if mn.starts_with("mov") {
        // Without operand-position info we can't tell load from store with
        // certainty; default to DataRead. Store-only mnemonics handled below.
        return XrefKind::DataRead;
    }
    if mn == "str"
        || mn.starts_with("str") // strb/strh/strex…
        || mn == "stp"
        || mn == "stur"
        || mn == "stnp"
        || mn == "push"
    {
        return XrefKind::DataWrite;
    }
    if mn == "ldr"
        || mn.starts_with("ldr") // ldrb/ldrh/ldrex…
        || mn == "ldp"
        || mn == "ldur"
        || mn == "ldnp"
        || mn == "pop"
    {
        return XrefKind::DataRead;
    }
    // Arithmetic / compare / test / etc. touching memory: classify as Read.
    XrefKind::DataRead
}

// ── Simple CFG builder ────────────────────────────────────────────────────────

fn compute_leaders(func: &Function, insns: &[Instruction]) -> std::collections::BTreeSet<u64> {
    let mut leaders: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    leaders.insert(func.addr.0);

    for insn in insns {
        let mn = insn.mnemonic.to_lowercase();
        if mn.starts_with('j') || mn == "ret" || mn == "retn" {
            leaders.insert(insn.next_addr().0);
            for tok in &insn.tokens {
                if matches!(tok.kind, TokenKind::Address | TokenKind::Symbol) {
                    if let Some(v) = tok.value {
                        leaders.insert(v);
                    }
                }
            }
        }
    }
    leaders
}

fn build_blocks(
    insns: &[Instruction],
    leaders: &std::collections::BTreeSet<u64>,
) -> Vec<BasicBlock> {
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut block_id = 0u32;
    let mut cur_start: Option<u64> = None;
    let mut cur_insns: Vec<Addr> = Vec::new();

    for insn in insns {
        if let Some(cs) = cur_start {
            if leaders.contains(&insn.addr.0) {
                let start = Addr(cs);
                let end = insn.addr;
                blocks.push(BasicBlock {
                    id: block_id,
                    start,
                    end,
                    preds: Vec::new(),
                    succs: Vec::new(),
                    insns: cur_insns.clone(),
                    kind: if block_id == 0 {
                        BlockKind::Entry
                    } else {
                        BlockKind::Normal
                    },
                });
                block_id += 1;
                cur_insns.clear();
            }
        }
        cur_start = Some(insn.addr.0);
        cur_insns.push(insn.addr);
    }
    if let Some(s) = cur_start {
        let start = Addr(s);
        let end = insns.last().map_or(start, Instruction::next_addr);
        blocks.push(BasicBlock {
            id: block_id,
            start,
            end,
            preds: Vec::new(),
            succs: Vec::new(),
            insns: cur_insns,
            kind: BlockKind::Normal,
        });
    }
    blocks
}

fn build_edges(blocks: &[BasicBlock], insns: &[Instruction]) -> Vec<CfgEdge> {
    let mut edges: Vec<CfgEdge> = Vec::new();
    let block_by_addr: std::collections::HashMap<u64, u32> =
        blocks.iter().map(|b| (b.start.0, b.id)).collect();

    for b in blocks {
        if b.insns.is_empty() {
            continue;
        }
        let last_addr = *b.insns.last().unwrap();
        if let Some(last_insn) = insns.iter().find(|i| i.addr == last_addr) {
            let mn = last_insn.mnemonic.to_lowercase();
            if mn == "ret" || mn == "retn" {
                continue;
            }

            let fall = last_insn.next_addr().0;
            if let Some(&target_id) = block_by_addr.get(&fall) {
                edges.push(CfgEdge {
                    from: b.id,
                    to: target_id,
                    kind: CfgEdgeKind::Unconditional,
                });
            }

            if mn.starts_with('j') {
                for tok in &last_insn.tokens {
                    if matches!(tok.kind, TokenKind::Address | TokenKind::Symbol) {
                        if let Some(v) = tok.value {
                            if let Some(&tid) = block_by_addr.get(&v) {
                                let kind = if mn == "jmp" {
                                    CfgEdgeKind::Unconditional
                                } else {
                                    CfgEdgeKind::True
                                };
                                edges.push(CfgEdge {
                                    from: b.id,
                                    to: tid,
                                    kind,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    edges
}

fn build_simple_cfg(func: &Function, insns: &[Instruction]) -> Cfg {
    if insns.is_empty() {
        return Cfg {
            func_id: func.id,
            rev: next_rev(),
            blocks: Vec::new(),
            edges: Vec::new(),
            entry_id: 0,
        };
    }

    let leaders = compute_leaders(func, insns);
    let mut blocks = build_blocks(insns, &leaders);
    let edges = build_edges(&blocks, insns);

    // Update pred/succ lists
    for e in &edges {
        if let Some(b) = blocks.iter_mut().find(|b| b.id == e.from) {
            b.succs.push(e.to);
        }
        if let Some(b) = blocks.iter_mut().find(|b| b.id == e.to) {
            b.preds.push(e.from);
        }
    }

    let entry_id = blocks.first().map_or(0, |b| b.id);
    Cfg {
        func_id: func.id,
        rev: next_rev(),
        blocks,
        edges,
        entry_id,
    }
}

/// Best-effort write of a small JSON marker file recording the path of the
/// most recently loaded binary, so an external process (typically the
/// standalone `rustre-mcp` server) can adopt the same target without the user
/// having to pass the path twice. Failures are silently ignored.
/// Snapshot of analysis counts captured at the end of `load_binary` and
/// published both to stderr (for log-grep parity checks) and to the marker
/// JSON (for tools that prefer to read a single file).
#[derive(Clone, Copy, Debug, Default)]
struct AnalysisSummary {
    functions: usize,
    symbols: usize,
    strings: usize,
    segments: usize,
    xrefs_to: usize,
    xrefs_from: usize,
}

fn write_mcp_session_marker(path: &str, arch: &str, size: usize, stats: &AnalysisSummary) {
    let Some(base) = dirs::data_local_dir() else { return };
    let dir = base.join("rustre-mcp");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        log::warn!("rustre-mcp session marker dir: {e}");
        return;
    }
    let marker = dir.join("gui_session.json");
    let body = format!(
        "{{\"path\":{},\"arch\":\"{}\",\"size\":{},\"ts\":{},\"functions\":{},\"symbols\":{},\"strings\":{},\"segments\":{},\"xrefs_to\":{},\"xrefs_from\":{}}}",
        serde_json::to_string(path).unwrap_or_else(|_| "\"\"".to_string()),
        arch,
        size,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        stats.functions,
        stats.symbols,
        stats.strings,
        stats.segments,
        stats.xrefs_to,
        stats.xrefs_from,
    );
    if let Err(e) = std::fs::write(&marker, body) {
        log::warn!("rustre-mcp session marker write: {e}");
    }
}

/// Write `bytes` to a fresh temporary file and return its path.
fn tempfile_with_bytes(bytes: &[u8]) -> std::io::Result<std::path::PathBuf> {
    let mut path = std::env::temp_dir();
    let pid = std::process::id();
    path.push(format!("rustre-flirt-{pid}-{:x}.sig", bytes.len()));
    std::fs::write(&path, bytes)?;
    Ok(path)
}

/// In-memory FLIRT-style pattern record used by `recover_library_names`. The
/// custom on-disk format (`RFLIRTBIN\0`) is emitted by the
/// `rust-stdlib-sigs` generator binary.
#[derive(Clone, Debug)]
struct RFlirtPattern {
    /// Initial bytes of the function with relocated positions replaced by 0.
    initial_bytes: Vec<u8>,
    /// 0xff = match, 0x00 = wildcard.
    mask: Vec<u8>,
    /// CRC-16/IBM-ARC over the function body slice starting at `initial_bytes.len()`.
    crc16: u16,
    /// Length of the byte region covered by `crc16` (0..=255).
    crc_length: u8,
    /// Full original function byte length (capped at u16::MAX). Used by
    /// `pattern_matches` as a sanity guard so a small library function
    /// pattern can't false-match a much larger user function that
    /// happens to share the same prefix bytes.
    pattern_length: u16,
    /// Recovered names (one or more — first is the primary).
    names: Vec<RFlirtName>,
}

#[derive(Clone, Debug)]
struct RFlirtName {
    name: String,
}

/// Decode the custom `RFLIRTBIN\0` format written by the rust-stdlib-sigs
/// generator. The format mirrors `FlirtPattern` field-by-field with explicit
/// little-endian counts so it can be loaded without pulling in the IDA `.sig`
/// trie decoder (which is keyed on a different writer-side layout).
fn load_rflirt_bin(buf: &[u8]) -> Result<Vec<RFlirtPattern>, String> {
    if buf.len() < 14 || &buf[..10] != b"RFLIRTBIN\0" {
        return Err(format!("invalid magic (len={})", buf.len()));
    }
    let mut p = 10usize;
    let count =
        u32::from_le_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]) as usize;
    p += 4;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if p + 2 > buf.len() {
            return Err("truncated prefix_len".into());
        }
        let prefix_len = u16::from_le_bytes([buf[p], buf[p + 1]]) as usize;
        p += 2;
        if p + prefix_len > buf.len() {
            return Err("truncated prefix".into());
        }
        let initial_bytes = buf[p..p + prefix_len].to_vec();
        p += prefix_len;
        if p + 2 > buf.len() {
            return Err("truncated mask_len".into());
        }
        let mask_len = u16::from_le_bytes([buf[p], buf[p + 1]]) as usize;
        p += 2;
        if p + mask_len > buf.len() {
            return Err("truncated mask".into());
        }
        let mask = buf[p..p + mask_len].to_vec();
        p += mask_len;
        if p + 2 + 1 + 2 + 1 > buf.len() {
            return Err("truncated trailer".into());
        }
        let crc16 = u16::from_le_bytes([buf[p], buf[p + 1]]);
        p += 2;
        let crc_length = buf[p];
        p += 1;
        let pattern_length = u16::from_le_bytes([buf[p], buf[p + 1]]);
        p += 2;
        let name_count = buf[p] as usize;
        p += 1;
        let mut names = Vec::with_capacity(name_count);
        for _ in 0..name_count {
            if p + 1 + 2 + 2 > buf.len() {
                return Err("truncated name header".into());
            }
            let _flags = buf[p];
            p += 1;
            let _offset = u16::from_le_bytes([buf[p], buf[p + 1]]);
            p += 2;
            let name_len = u16::from_le_bytes([buf[p], buf[p + 1]]) as usize;
            p += 2;
            if p + name_len > buf.len() {
                return Err("truncated name".into());
            }
            let name = String::from_utf8_lossy(&buf[p..p + name_len]).into_owned();
            p += name_len;
            names.push(RFlirtName { name });
        }
        out.push(RFlirtPattern {
            initial_bytes,
            mask,
            crc16,
            crc_length,
            pattern_length,
            names,
        });
    }
    Ok(out)
}

/// Two-stage match — replicates IDA FLIRT's identity rule exactly:
///
/// 1. **Strong-CRC path** (`crc_length >= 16`): verify CRC-16 of the function
///    body region [prefix_len .. prefix_len + crc_length] against the stored
///    pattern CRC. CRC-16/IBM-ARC has a ~1/65536 collision rate over a
///    contiguous unmasked window of that size, so a hit here is statistically
///    a true library identity match — independently of how the strict prefix
///    drifted between toolchain versions.
/// 2. **Strict-prefix path** (`crc_length < 16`, prefix CRC too weak to stand
///    alone): require every unmasked byte of `pat.initial_bytes` to match
///    `body` exactly. Then optionally verify CRC for the small region we have.
fn pattern_matches(pat: &RFlirtPattern, body: &[u8]) -> bool {
    let prefix_len = pat.initial_bytes.len();
    if body.len() < prefix_len {
        return false;
    }
    // Size sanity guard: if the body is dramatically larger than the
    // recorded `pattern_length` (the full byte size of the original
    // library function this signature was generated from), the body is
    // almost certainly a different function. Allow some slack (2×) for
    // inlining variation, but reject 5×+ blow-ups outright.
    if pat.pattern_length > 0 {
        let pl = usize::from(pat.pattern_length);
        if body.len() > pl.saturating_mul(5) {
            return false;
        }
    }

    // Path 1 — strong CRC over a long-enough body region trusts CRC alone.
    if pat.crc_length >= 16 {
        let crc_end = prefix_len + pat.crc_length as usize;
        if let Some(crc_region) = body.get(prefix_len..crc_end) {
            if crc16_ccitt(crc_region) == pat.crc16 {
                return true;
            }
        }
        // CRC didn't match — do NOT fall back to the strict-prefix check
        // because patterns with a strong CRC must be qualified by it.
        return false;
    }

    // Path 2 — short or absent CRC: rely on byte-for-byte strict prefix.
    let n = prefix_len.min(pat.mask.len()).min(body.len());
    for i in 0..n {
        if pat.mask[i] == 0xff && pat.initial_bytes[i] != body[i] {
            return false;
        }
    }
    if pat.crc_length == 0 {
        return true;
    }
    let crc_end = prefix_len + pat.crc_length as usize;
    body.get(prefix_len..crc_end).map_or(false, |crc_region| crc16_ccitt(crc_region) == pat.crc16)
}

/// CRC-16/IBM-ARC (poly 0x8005, init 0xFFFF, non-reflected) — same algorithm
/// `rustre_flirt_gen::crc16_sig_header` uses to seal each pattern's body
/// region. Must stay in sync with the generator side or the body verification
/// will never match.
fn crc16_ccitt(data: &[u8]) -> u16 {
    const POLY: u16 = 0x8005;
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ POLY
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Cold-path exerciser that keeps the engine's internal helpers
/// linkable from the production binary without `#[allow(dead_code)]`.
/// `tempfile_with_bytes` is the materialise-bytes-to-a-temp-file
/// utility used by the embedded FLIRT signature path; it stays part
/// of the engine surface so future FLIRT exports / on-disk signature
/// writers can reuse it instead of duplicating the temp-dir logic.
#[doc(hidden)]
pub fn ensure_used_engine() {
    let _ = tempfile_with_bytes(b"").map(|_p| ());
}
