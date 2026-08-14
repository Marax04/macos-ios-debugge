# rustre-analysis-fn

## Purpose
Production-grade function-boundary detection for the RustRE Suite. Locates
function entry points (and tries to estimate ends) in raw binary memory by
combining: (1) architecture-specific prologue byte-pattern scanning
(x86-64, x86-32, ARM64), (2) direct CALL/BL target collection, (3) gap
analysis between known functions, and (4) authoritative anchors from
.pdata / eh_frame / ARM exidx / MachO function_starts / symbol tables.
Also exposes callgraph construction, callee enumeration, library FLIRT
mark propagation, classification, clustering, fingerprinting, no-return
detection, and stack frame analysis.

## Public functions (high-signal subset)

### `detect_functions(arch: DetectedArch, mem: &MemorySlice) -> FunctionBoundarySet`
- Input: architecture enum + (base_va, raw bytes) memory view.
- Output: set of `FunctionBoundary { start, end?, confidence, source, name? }` + `DetectionStats`.
- Behavior: runs prologue scan + call-target scan + gap analysis, merges by VA keeping highest confidence, estimates end via x86 RET/JMP / ARM64 RET/B scan (max 4096 bytes).
- Ground truth: count and start VAs comparable to IDA/Ghidra function list for the same .text section. Externally verifiable: known synthetic blob with N hand-placed `55 48 89 E5 ... C3` prologues must yield exactly N High-confidence entries.

### `detect_functions_at(arch, image_base: u64, bytes: &[u8]) -> FunctionBoundarySet`
- Same as above, shortcut constructor.
- Ground truth: identical to `detect_functions` for same inputs.

### `detect_functions_from_path(path) -> io::Result<(set, arch, image_base)>`
- Input: filesystem path to PE (or fallback raw).
- Output: detection set over the primary .text/executable section + inferred arch + PE image base.
- Behavior: parses PE via `rustre-loader-pe`, picks `.text` (or first IMAGE_SCN_MEM_EXECUTE section), rebases addresses to section virtual_address.
- Ground truth: for `cargo-zyphora.exe` should be in the ~1456-function ballpark IDA found.

### `detect_functions_from_path_segments(path, arch) -> io::Result<Vec<DetectedFunction>>`
- Like above but iterates EVERY executable segment and unions results, deduping by VA (highest confidence wins).
- Ground truth: superset of single-section variant; count must be >= single-section count.

### `x86_64_prologue_patterns() / x86_32_prologue_patterns() / arm64_prologue_patterns() -> Vec<ProloguePattern>`
- Input: none.
- Output: static catalog of byte patterns (with wildcard slots) + confidence + name.
- Ground truth: list lengths and pattern names stable; each `ProloguePattern::matches` deterministic.

### `ProloguePattern::matches(&self, bytes) -> bool`
- Input: candidate byte slice.
- Output: bool — pattern (with `None` wildcards) matches at offset 0.
- Ground truth: trivially verifiable with crafted byte arrays.

### `CallTargetCollector::collect / collect_x86_calls / collect_arm64_calls`
- Input: `MemorySlice` of executable bytes; collector pre-filtered to a VA range.
- Output: sorted, deduplicated `Vec<Address>` of CALL/BL targets.
- Behavior x86: scans for `E8 imm32`, target = next_pc + signed disp32. ARM64: 4-byte aligned, opcode `100101`, sign-extended 26-bit imm * 4 + pc.
- Ground truth: crafted `E8 xx xx xx xx` blob with known relative displacement must yield exact target VA. Independently computable in Python.

### `GapAnalyzer::find_gaps(known_starts, code_range, mem) -> Vec<AddressRange>`
- Returns ranges between consecutive known function starts (and edges) at least `min_gap_size` bytes long.
- Ground truth: deterministic — given sorted starts + range, the gap list is a pure arithmetic function.

### `GapAnalyzer::first_code_byte(gap, mem) -> Option<Address>`
- Skips leading 0x90/0xCC padding inside a gap; returns first non-padding byte VA.
- Ground truth: verifiable byte-by-byte.

### `FunctionDetector::estimate_end(start, mem) -> Option<Address>`
- Scans up to 4096 bytes forward for terminator (x86: C3/C2/CB/CA/EB/E9/HLT/JMP r/m or stray INT3; ARM64: RET / RETAA/RETAB / B).
- Output: exclusive end address.
- Ground truth: crafted "prologue + N bytes + C3" yields end == start + N + 1.

### `FunctionBoundarySet::{at, iter, high_confidence, sorted_by_address, count, named_count}`
- Pure container accessors over the detection result.

### Re-exports from submodules (semantic-only)
- `apply_library_marks(table, marks, ...)` — propagate FLIRT-derived "is library" flags across the function table; returns `LibraryPropagationStats`.
- `callgraph_from(...) -> CallGraphSlice`, `render_callgraph_dot{,_styled}` — build & emit GraphViz of caller->callee edges.
- `callees(...) -> Vec<CalleeRecord>` with `CalleeKind` (Direct/Indirect/Tail/Thunk-like).
- `strategies::*` — anchor parsers: `parse_pdata` (PE32+ .pdata RUNTIME_FUNCTION), `parse_eh_frame_fdes` (DWARF EH), `parse_arm_exidx`, `parse_macho_function_starts`, `boundaries_from_pdata`, `boundaries_from_symbols`, `find_extra_pdata_funcs` (leaf functions missing from .pdata), `recursive_descent_x86`, plus `StrategyEngine`, `ConfidenceLattice`, `CandidateEvidence`, `RuntimeFunction`, `FunctionSymbol`, `StrategyKind`.
- Each anchor parser has a binary-format spec → externally re-implementable in Python (e.g. pefile for .pdata; libunwind/elftools for eh_frame).

### `FunctionDetectionPass` (impl `rustre_analysis::AnalysisPass`)
- Async pass plugged into the analysis pipeline; `name() = "function_detection"`, `kind = LinearSweep`, `priority = 100`.

## Existing MCP tools (in `rustre-mcp-tools/src/wire_tools.rs`)
- `analysis_fn_detect_extra` — wraps `find_extra_pdata_funcs` + `parse_pdata` to surface leaf functions not present in PE .pdata.
- `analysis_fn_detect_functions_path` — path-based wrapper around `detect_functions` (PE).
- `analysis_xref_callees` — uses xref index + IAT thunks (consumes `callees` semantics).
- (Indirect users of the crate) `apply_library_marks` is invoked in several aggregate analysis tools; `detect_functions` is used inside an aggregate full-analysis tool.

Not directly exposed as MCP tools yet (gaps): `callgraph_from` / `render_callgraph_dot*`, `callees` standalone, `parse_eh_frame_fdes`, `parse_arm_exidx`, `parse_macho_function_starts`, `boundaries_from_symbols`, prologue-pattern enumeration, `GapAnalyzer` standalone, `noreturn_detector::*`, stack-frame analyzer, function classifier/cluster/fingerprint/similarity APIs.

## Testable functions (externally verifiable ground truth)
1. `ProloguePattern::matches` — pure byte compare with wildcards.
2. `CallTargetCollector::collect_x86_calls` — math (`pc + 5 + disp32`).
3. `CallTargetCollector::collect_arm64_calls` — math (`pc + sext(imm26)*4`).
4. `GapAnalyzer::find_gaps` — pure interval arithmetic over sorted addresses.
5. `GapAnalyzer::first_code_byte` — first byte not in {0x90, 0xCC}.
6. `FunctionDetector::estimate_end` — scan to first terminator opcode.
7. `detect_functions` on synthetic blob with known prologue/RET layout — exact count + addresses.
8. `detect_functions_from_path` on `cargo-zyphora.exe` — count in same order of magnitude as IDA baseline (1456); high-confidence subset should overlap heavily with IDA-named functions.
9. `strategies::parse_pdata` — re-parsable independently via Python `pefile` against the `.pdata` section.

## Validator strategy
- Unit-level: craft synthetic `Vec<u8>` blobs with hand-placed x86 prologues (`55 48 89 E5`), `E8` CALLs with computed displacements, NOP/INT3 padding, and `C3` terminators. Assert `detect_functions` returns the exact expected `FunctionBoundary` set (start VAs, confidence, source, estimated end). Verify CALL targets against Python-computed `next_pc + disp32`.
- Format-level: build a tiny PE in memory (or use a fixture) with a known `.pdata` table; cross-check `parse_pdata` and `boundaries_from_pdata` against `pefile`-derived RUNTIME_FUNCTION entries.
- Integration / ground truth: run `detect_functions_from_path` on `cargo-zyphora.exe`. Assert (a) returned count is within tolerance of the IDA baseline (1456 ± X%), (b) for every IDA-named function with a known VA, `set.at(va)` is `Some` with `Confidence >= Medium`. Use the existing IDA baseline memory file as the oracle.
- Determinism: re-run the same inputs N times and assert identical `FunctionBoundary` sequences (the API is `#[must_use]` and pure aside from `Instant` timing).
- Negative tests: empty slice → empty set; slice of pure `0x90` → no functions (after min_size filter); `min_target`/`max_target` window discards out-of-range CALL targets.
