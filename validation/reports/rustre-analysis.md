# rustre-analysis — Crate Analysis

## Purpose
Core **analysis-framework infrastructure** for RustRE. Provides:
- The `AnalysisPass` async trait + `AnalysisPipeline` / `PassRegistry` to register and run analyses.
- Pure data-structure modules: function/string/xref indexes, findings DB, cross-reference DB, in-memory analysis DB.
- A dependency-aware `PassScheduler` (topological sort + parallel groups).
- Concrete *built-in* passes that wrap deterministic byte-level algorithms: linear sweep prologue detection, x86-64 `CALL rel32` target scanner, recursive descent, string/xref recovery scaffolds.
- Interprocedural framework: CallGraph, BottomUp/TopDown summary propagation, recursion detection.
- Reporting: `BinaryAnalysisReport`, severity-scored findings, suite pipeline.
- Metrics: per-pass timing, regression detection, coverage stats.

It is the *coordination layer*, not a binary-format parser. Concrete file parsing is in `rustre-core`; concrete heavy analyses live in sister crates (`rustre-analysis-fn`, `-xref`, `-string`, `-cfg`, `-type`, `-typerecov`).

## Public Surface (Externally Verifiable Items)

The vast majority of items are framework structs/traits whose behaviour is *plumbing* (scheduling, registering, deduping). Below are the pieces with **ground-truth-testable** input→output semantics.

### `FunctionBoundaryAnalysis::scan_prologues(base: u64, bytes: &[u8]) -> Vec<FunctionBoundary>`
- **Input**: virtual base address, byte slice.
- **Output**: list of `{start, end=start, confidence, method=ProloguePattern}`.
- **Behavior**: scans `bytes` byte-by-byte; emits a candidate whenever the next bytes match one of three fixed x86-64 prologue signatures:
  - `55 48 89 E5` (push rbp; mov rbp, rsp) → confidence 80
  - `55 48 8B EC` → confidence 80
  - `48 83 EC` (sub rsp, imm8) → confidence 70
- After a match, `i` advances by 4 (or 3 for sub-rsp variant); else by 1.
- Cap: ≤ 1,048,576 results.
- **Ground truth**: trivially reproducible in Python (`re.finditer(rb"\x55\x48\x89\xE5|\x55\x48\x8B\xEC|\x48\x83\xEC", data)`) — addresses, count, and confidence must match.

### `FunctionBoundaryAnalysis::scan_call_targets(base: u64, bytes: &[u8]) -> Vec<u64>`
- **Input**: base VA, byte slice.
- **Output**: sorted, deduped list of `u64` call-target addresses.
- **Behavior**: for every offset `i` where `bytes[i] == 0xE8`, computes `target = base + i + 5 + sign_extend(i32_le(bytes[i+1..i+5]))` (with `wrapping_add_signed`). `i` advances by 1.
- Cap: ≤ 1,048,576.
- **Ground truth**: reproducible in Python with struct unpack of int32 LE; addresses must match exactly. Note: this is a naive sweep — will produce false positives mid-instruction. Verifiable property: *every* `0xE8` byte yields one target.

### `LinearSweepAnalyzer::sweep(base, bytes) -> Vec<FunctionBoundary>`
- Composes the two scans above; assigns confidence 90 if a call target lands on a prologue, else 75.
- Verifiable by composing the two ground-truths above.

### `compute_hash(data: &[u8]) -> u64` (analysis_cache)
- Stable 64-bit hash of `data` for cache-keying. Ground truth: hash is deterministic — same input ⇒ same output, different input ⇒ (almost always) different output. Algorithm-specific value can be pinned via snapshot test.

### Pure-data structural items (testable via construction/invariants, no external oracle)
- `AnalysisPipeline::register / find / remove / pass_count / pass_names` — list semantics; re-register replaces by name.
- `PassScheduler::schedule()` — **topological sort**; ground truth: classical Kahn's algorithm. Cycle ⇒ `Err`. Otherwise output must be a valid topological order respecting `dependencies`. External oracle: any Python/networkx topo sort.
- `PassScheduler::schedule_groups()` — Kahn's algorithm grouped by level. Ground truth: each successive group's `dependencies` are entirely within earlier groups.
- `AnalysisStats::record_result / record_error / avg_duration_ms / slowest_pass` — arithmetic on counters; trivially testable.
- `CrossReferenceDb::add / xrefs_to / xrefs_from / calls / call_targets / count` — multimap behaviour with `Vec`-deduped sorted targets.
- `FunctionIndex` / `StringIndex` / `XrefIndex` (in `analysis_index.rs`) — range/address lookup tables; expected invariants documented in struct docs.
- `AnalysisReport::build / total_functions / total_strings / summary` — pure aggregation.
- `serialize_call_graph` / `deserialize_call_graph` — round-trip property: deserialize(serialize(g)) ≡ g.
- `format_summary(&FunctionSummary) -> String` — formatting; snapshot-testable.
- `score_function(timings, budget_ms) -> Vec<FunctionScore>` — scoring formula over timings; snapshot/property-testable.
- `detect_regressions(...)` — compares two `MetricsReport`s vs thresholds; property-testable.

### Trait/runtime items (NOT externally verifiable — require full BinaryView)
- `AnalysisPass::run`, `AnalysisManager`, `BinaryAnalysisSuite::run`, `SuitePipeline`, `IncrementalAnalysis`, all *Pass impls (`LinearSweepPass`, `RecursiveDescentPass`, `StringRecoveryPass`, `XrefRecoveryPass`, `FunctionDetectionPass`, `CfgAnalysisPass`, `TypeRecoveryPass`, `CallingConventionPass`, `VtablePass`) — these wrap the deterministic scanners above but require a `BinaryView`. Tested indirectly via the leaf scanners.

## Existing MCP Tools
**None directly.** Grep of `rustre-mcp-tools/src/wire_tools.rs` shows zero references to `rustre_analysis::`. The MCP layer instead uses *sister* crates:
- `rustre_analysis_xref` (xref/callgraph tools)
- `rustre_analysis_fn` (function detection, pdata, no-return inference)
- `rustre_analysis_string` (string scanner)
- `rustre_analysis_type` / `rustre_analysis_typerecov` (type propagation, struct recovery)
- `rustre_analysis_cfg` (CFG/loop analysis)

So `rustre-analysis` is the *framework* crate, currently consumed by other workspace crates but **not directly exposed** via MCP. This is a known integration gap.

## Testable Functions (whitelist for the validator)
1. `FunctionBoundaryAnalysis::scan_prologues` — oracle: byte-pattern regex in Python.
2. `FunctionBoundaryAnalysis::scan_call_targets` — oracle: Python struct unpack of every `0xE8` offset.
3. `LinearSweepAnalyzer::sweep` — oracle: composition of (1) + (2), confidence bumped to 90 when target ∈ prologues.
4. `PassScheduler::schedule` — oracle: any independent topo-sort (Kahn) implementation; check cycle error.
5. `PassScheduler::schedule_groups` — oracle: level-by-level Kahn; verify dependency closure invariant.
6. `CrossReferenceDb` — property tests: `add` then `xrefs_to/from/calls/count/call_targets` round-trip.
7. `compute_hash` — determinism + snapshot of a fixed input.
8. `serialize_call_graph` / `deserialize_call_graph` — round-trip property.
9. `AnalysisStats` / `AnalysisReport::build` — aggregation arithmetic.

## Validator Strategy
**Two-track validation, both in-process Rust (no MCP path available):**

- **Track A — Byte-scanner oracles (highest value).** For `scan_prologues`, `scan_call_targets`, `sweep`: build synthetic byte buffers with known prologue placements and known `0xE8` rel32 patterns; assert exact equality of `(addr, confidence, method)` lists vs. a tiny hand-rolled Python (or pure-Rust) oracle. Also feed a real binary section (e.g. `.text` of `cargo-zyphora.exe`) and compare *counts* and a sampled subset of addresses against an external pattern-scan script — gives a ground-truth cross-check at scale.

- **Track B — Algorithmic-property tests.** For `PassScheduler::schedule[_groups]`, `CrossReferenceDb`, `serialize_call_graph`, `AnalysisStats`, `compute_hash`: use property-based tests (e.g. `proptest`) verifying invariants (topo order, multimap consistency, round-trip identity, sum equality, determinism). No external oracle needed — these are algorithmic correctness checks.

- **Out of scope for validator**: pass impls that require a full `BinaryView` (`LinearSweepPass::run` etc.). Their *cores* are already covered by Track A; the trait wrapping is plumbing.

- **Integration gap to flag**: this crate is not surfaced via MCP. If MCP-level validation is desired, recommend wiring a `rustre_analysis_pipeline_run` tool that exposes `AnalysisManager::run_pipeline` for a given binary URI — currently the only way to externally verify the orchestration layer.
