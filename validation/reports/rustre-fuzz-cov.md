# rustre-fuzz-cov

Coverage tracking library for the RustRE fuzzing suite. Supports DRcov (DynamoRIO/DrMemory), lcov `.info`, SanitizerCoverage PC-guard bitmaps, edge coverage, CMPLOG value pairs, corpus pruning, and a generic `CoverageDatabase`.

## Cargo.toml

- Package: `rustre-fuzz-cov` (workspace version/edition)
- Dependencies: `thiserror`, `serde`, `serde_json`, `serde_bytes = "0.11"`, `rayon`
- Note: `rustre-fuzz` is intentionally NOT a dep — this crate is consumed by it (the umbrella aggregator).
- Lints: `unsafe_code = "allow"` (this crate implements SanitizerCoverage `extern "C"` runtimes — `__sanitizer_cov_trace_pc_guard*`, block-coverage init/mark — which inherently require unsafe). `unused_must_use = "deny"`. Clippy `all`/`pedantic`/`nursery`/`cargo` warn.

## Modules (19)

- `casts` — checked numeric conversions (`usize_to_f64`, `u64_to_f64`, …)
- `block_coverage_tracker` — basic-block hit tracking runtime
- `coverage_diff`, `coverage_diff_reporter` — diff two runs / format reports
- `edge_coverage`, `edge_coverage_tracker` — (from,to) edge maps
- `coverage_feedback` — feedback for fuzzer scheduling
- `coverage_guide` — guided mutation hints
- `coverage_minimizer` — corpus minimization
- `coverage_persistence` — load/save coverage state
- `coverage_statistics` — aggregate stats
- `coverage_map_merger` — merge maps from multiple runs
- `lcov_export` — emit lcov `.info`
- `pt_integration` — Intel PT (Processor Trace) decode
- `qemu_tcg_cov` — QEMU TCG block edges
- `sancov_instrumentation` — SanitizerCoverage runtime (extern "C" entry points)
- `source_coverage_tracker`, `source_coverage_mapper` — addr→source line mapping

Total `pub fn` signatures across crate: **~729** (counted across 19 src files).

## Public API (lib.rs root)

### Error
- `enum CovError`: `Parse(String)`, `Io(String)`, `UnsupportedVersion(u32)`, `Overflow(String)`, `EmptyInput`. Uses `thiserror::Error`.

### DRcov v1 API
- `struct DrcovModule { id: u32, path: String, base: u64, end: u64, checksum: u32 }`
  - `new(id, path, base, end)`, `with_checksum(checksum)`, `size()`, `contains(addr)`, `to_offset(addr) -> Option<u64>`
- `struct DrcovEntry { module_id: u16, start: u32, size: u16 }`
  - `new`, `absolute_addr(&[DrcovModule]) -> Option<u64>`, `end_addr(...)`
- `struct DrcovFile { version: u32, flavor: String, modules: Vec<DrcovModule>, bbs: Vec<DrcovEntry> }`
  - `parse(&[u8]) -> Result<Self, CovError>` — parses text header + binary BB table (8-byte entries, LE: start u32, size u16, module_id u16)
  - `serialize() -> Vec<u8>` — DRcov v2 text + binary
  - `blocks_per_module() -> HashMap<u16, usize>`, `merge_bbs(&Self)`

### DRcov v2 API (richer parser)
- `struct DrcovHeader { version, flavor, module_count }` — `parse(&[u8]) -> Result<(Self, usize), CovError>` returns header + bytes consumed
- `struct DrcovBasicBlock { start: u32, size: u16, module_id: u16 }` — `parse_bb_table(&[u8])`, `absolute_addr(module_base)`
- `struct DrcovModuleV2 { id, base, end, entry, path }` — `parse_table(data, count)` (tab- or comma-separated; capped at 65536 entries to prevent OOM), `contains`, `size`
- `struct DrcovFileV2 { header, modules: Vec<DrcovModuleV2>, bbs: Vec<DrcovBasicBlock> }`
  - `load(&Path)`, `parse(&[u8])`, `absolute_bbs() -> Vec<(u64, u16)>`

### CoverageRun / Database
- `struct CoverageRun { name, bb_hits: HashMap<u64,u64>, timestamp: SystemTime, source: Option<String>, total_executions: u64 }`
  - `new`, `hit(addr)`, `hit_n(addr, count)`, `distinct_blocks`, `total_hits`, `singleton_blocks`, `merge`, `hot_blocks(threshold)`, `was_hit`, `density(total)`
- `struct CoverageDiff { only_in_a, only_in_b, in_both: Vec<u64> }` — `jaccard()`, `is_identical()`
- `struct CoverageStats { total_blocks, hit_blocks, coverage_pct, unique_blocks, max_hit_count, total_hits }`
- `struct CoverageDatabase { runs: Vec<CoverageRun> }`
  - `new`, `add_run`, `load_drcov(&Path) -> Result<CoverageRun, CovError>`
  - `diff(a, b)`, `stats(run, total_known_blocks)`, `aggregate`, `intersection`, `union_coverage`, `unique_runs`

### lcov
- `struct LcovRecord { source_file, test_name, functions, function_lines, line_hits, branch_hits, branch_found, lines_found, lines_hit }`
  - `line_coverage_pct`, `is_fully_covered`, `functions_hit`
- `struct LcovParser { records: Vec<LcovRecord> }`
  - `parse(&str) -> Result<(), CovError>` — handles TN/SF/FN/FNDA/DA/BRH/BRF/LF/LH and `end_of_record`
  - `total_lines_hit`, `aggregate_by_file`, `total_branch_hits`, `overall_line_coverage_pct`, `source_files`

### SanitizerCoverage
- `struct PcGuardBitmap { bits: Vec<u8> }` — `new(size)`, `from_bytes`, `record_hit(idx)` (saturating, out-of-range silently ignored), `coverage_count`, `density`, `merge` (saturating OR), `reset`, `hit_guards`, `hash` (FNV-1a), `new_bits_from`

### Edge coverage
- `struct EdgeCoverageMap` (BTreeMap-backed) — `new`, `record(from,to)`, `record_n`, `edge_count`, `total_traversals`, `has_edge`, `edge_hits`, `merge`, `hot_edges(threshold)`, `reset`, `successors(from)`

### CMPLOG
- `struct CmplogEntry { pc, lhs, rhs, size: u8, is_fn_hook }` — `new`, `is_equal`, `diff` (xor), `bit_diff` (popcount), `mask` (sized bitmask)
- `struct CmplogMap { entries }` — `new`, `record`, `clear`, `unequal_entries`, `unique_pcs`, `suggest_mutations` (rhs LE bytes for token guidance), `len`, `is_empty`

### Corpus pruning
- `struct CorpusPruner` — `new`, `prune<I: IntoIterator<Item=(usize, Vec<u64>)>>(inputs) -> Vec<usize>`
  - Greedy set-cover: pick input with most uncovered edges, until all edges covered. Returns sorted input IDs.

### Histogram
- `struct CoverageHistogram { buckets: BTreeMap<u64,u64> }` — `new`, `from_run(&CoverageRun)`, `total_blocks`, `max_bucket`, `median`, `mean`

## I/O Behavior

- **Inputs**: raw bytes (`&[u8]`), `&Path` for on-disk DRcov, `&str` for lcov text, `HashMap`/iterators for in-memory accumulation.
- **Outputs**: `Vec<u8>` for DRcov serialization, `Vec<u64>` block address lists, summary structs, all serde-serializable (`Serialize`/`Deserialize` on all public types).
- **Errors**: structured `CovError` with `From`-style messages — no panics in parse paths. Allocation caps on attacker-controlled counts (e.g. 65,536 modules max).
- **Safety**: numeric narrowings routed through `casts` module; saturating arithmetic on hit counters and module size; out-of-range bitmap indices silently dropped.
- **Concurrency**: `rayon` dep available (used in coverage_minimizer / parallel merging across runs).

## Behavior notes

- DRcov v1 (`DrcovFile`) and v2 (`DrcovFileV2`) coexist for backward compat. V2 supports the `entry` column and is the richer parser per spec §18.1.
- `CoverageDatabase::stats` treats `total_known_blocks == 0` as "unknown" — `coverage_pct` returns 0.0 to signal this; otherwise reports `hit/total * 100`.
- `PcGuardBitmap::merge` is a saturating OR-merge; `EdgeCoverageMap::merge` sums hit counts.
- `CmplogMap::suggest_mutations` emits the rhs side of unequal compares as little-endian byte tokens — feeds AFL-style dictionary-guided mutation.
- `CorpusPruner::prune` is greedy O(N·E) set-cover; deterministic output (sorted IDs).
- SanitizerCoverage runtime in `sancov_instrumentation` exposes `extern "C"` symbols (`__sanitizer_cov_trace_pc_guard`, `__sanitizer_cov_trace_pc_guard_init`) — why crate-wide `unsafe_code = "allow"` is justified.

## Testability

Highly testable: pure data-in/data-out parsers and accumulators with no global state in the lib.rs public surface (the sancov runtime side uses globals but is isolated to its own module). DRcov round-trip (`parse` → `serialize` → `parse`), lcov golden-file tests, CMPLOG mutation seed inspection, and `CorpusPruner` deterministic set-cover all unit-testable without external fixtures.
