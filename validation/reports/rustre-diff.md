# rustre-diff

## Overview
Binary diffing core for the RustRE workspace. Compares two binaries (or sets of function fingerprints) and classifies functions as Identical, Similar, Added, Removed, or Renamed. Provides multiple layers of diff: raw byte / hash, function-level, basic-block, instruction-level, structural (CFG), semantic, signature, patch detection/classification/generation, and bindiff-format export.

## Cargo.toml
- Name: `rustre-diff` v0.1.0, edition 2024
- Deps: `thiserror`, `serde`, `serde_json`, `hex`, `crc32fast`, `ahash`
- No external binary loader deps — purely operates on byte slices / fingerprints supplied by the caller.

## Modules (pub)
- `basic_block_diff` — BB-level diffs (BasicBlock, BasicBlockDiffer, BlockDiff, BlockMatch, BlockMatchKind)
- `binary_diff` — high-level binary-vs-binary diff orchestration
- `bindiff_engine` — engine analogous to zynamics BinDiff
- `bindiff_format` — serialize/deserialize bindiff results
- `diff_algorithm` — core diff algorithm primitives
- `diff_visualizer` — render diffs (text/HTML)
- `function_diff` — per-function diff records
- `function_hasher` — function-body hashing
- `function_matching` — FunctionMatcher, MatchScore (name/signature/content/cg), MatchingStrategy, NameHashMatch, CallgraphContextMatch, BbHashMatch, UnmatchedFunctions, MatchReport
- `instruction_diff` — DiffInstr, InstrDiff, InstrDiffEntry, InstrDiffKind, InstrDiffer, OperandDiff, operand_changes
- `patch_classifier`, `patch_detector`, `patch_diff`, `patch_generator` — patch lifecycle
- `semantic_diff` — semantics-aware diff
- `signature_diff` — signature comparison
- `structural`, `structural_diff` — CFG/structural diff (DiffFunction, DiffReport, StructuralDiffer, StructuralMatch, StructuralMatchKind, histogram_cosine, jaccard, ratio)

## Top-level API (lib.rs)

### Types
- `DiffError { EmptyInput(String), HashError(String), Other(String) }` — error enum.
- `FuncFingerprint { address: u64, name: String, size: usize, hash: u64, call_count, block_count, edge_count, bytes: Vec<u8> }` — function fingerprint.
  - `new(address, name, bytes) -> Self` — hashes bytes via FNV-1a, structural counts default 0.
  - `similarity(&self, other) -> f64` — 0.0..=1.0; identical hash short-circuits to 1.0, else 0.7*LCS + 0.3*size_ratio.
  - `Display`: `name@0xADDR sz=N`.
- `MatchKind { Identical, Similar, Added, Removed, Renamed }` — relation between two functions across binaries.
- `FuncMatch { primary: Option<FuncFingerprint>, secondary: Option<FuncFingerprint>, kind, similarity, confidence: u32 }`
  - constructors: `identical(a,b)`, `similar(a,b,sim)`, `renamed(a,b,sim)`, `added(b)`, `removed(a)`.
  - `is_changed() -> bool` — true unless Identical.
- `BinaryDiff { name_a, name_b, matches: Vec<FuncMatch>, total_functions_a/b, diff_time_ms }`
  - `new(name_a, name_b)`, `identical_count`, `added_count`, `removed_count`, `changed_count`, `similarity_ratio` (mean over paired matches).
- `DiffEngine { similarity_threshold: f64 }`
  - `new(threshold)`, `Default = 0.6`.
  - `diff(funcs_a: Vec<FuncFingerprint>, funcs_b: &[FuncFingerprint], name_a, name_b) -> Result<BinaryDiff, DiffError>`
  - Behavior: errors on both-empty input; Pass 1 indexes B by FNV hash (AHashMap, DoS-resistant) and pairs identical hashes; Pass 2 greedy similarity match for residue, classifies as Renamed if sim > 0.9 and names differ, else Similar; remaining A→Removed, remaining B→Added.
- `ChangeType { Added, Removed, Modified { similarity: f64 }, Unchanged }`
- `FunctionDiff { addr_a, addr_b, name_a, name_b, similarity, change_type }` with `display_name()`.
- `NamedBinaryDiff { functions: Vec<FunctionDiff>, overall_similarity: f64 }` with `added_count/removed_count/modified_count/unchanged_count`.
- `ExportEntry { name: Option<String>, ordinal: u32, address: u64 }`
- `ExportDiff { removed, added, moved: Vec<(ExportEntry, ExportEntry)>, unchanged }`; `is_clean()`.

### Free functions
- `simple_hash(data: &[u8]) -> u64` — FNV-1a 64-bit.
- `lcs_similarity(a, b) -> f64` — LCS-based byte similarity; capped at 512 bytes/side, score scaled by coverage of full inputs to avoid inflated similarity on truncation.
- `byte_histogram_similarity(a, b) -> f64` — Bhattacharyya coefficient over 256-bin byte histograms; O(n+m).
- `ngram_jaccard_similarity(a, b, n) -> f64` — n-gram Jaccard, n capped at 8, input capped at 4096 bytes/side, AHashSet for DoS safety.
- `combined_byte_similarity(a, b) -> f64` — 0.6*histogram + 0.4*4-gram Jaccard.
- `diff_by_name(map_a: &HashMap<String,Vec<u8>,S>, map_b) -> NamedBinaryDiff` — name-keyed pairing; uses `combined_byte_similarity`; sorts deterministically (Unchanged, Modified desc, Removed, Added); `overall_similarity = mean_sim * coverage`.
- `diff_exports(a: &[ExportEntry], b: &[ExportEntry]) -> ExportDiff` — keyed by name (or `@ordinal` for anonymous); same key + different address → moved; AHashMap-backed.

## Expected behavior summary
- Pure-data library: caller supplies fingerprints / byte buffers / export tables; no I/O, no parsing of executable formats.
- All similarity functions return values clamped to `[0.0, 1.0]`; identical short-circuit to 1.0; both-empty inputs return 1.0; one-empty returns 0.0.
- All maps over attacker-controlled bytes/strings use `ahash` to prevent collision DoS.
- `diff_by_name` and `diff_exports` produce deterministically sorted output.
- Errors only raised by `DiffEngine::diff` when both inputs are empty.

## Submodule counts (pub fn / const fn / async fn)
- lib.rs: 29
- structural_diff: 42, structural: 27
- function_matching: 25
- diff_visualizer: 22, diff_algorithm: 21, binary_diff: 21
- instruction_diff: 20, function_hasher: 20
- patch_generator: 19, bindiff_format: 19, bindiff_engine: 19
- basic_block_diff: 17
- signature_diff: 14
- semantic_diff: 13, patch_detector: 13, function_diff: 13
- patch_classifier: 10
- patch_diff: 2
- **Total pub fn: 366** across 19 source files.

## Testability
- Self-contained, no external services or binary inputs required.
- Extensive in-crate unit tests already in `lib.rs` (~30 tests covering hash, LCS, fingerprint, MatchKind, FuncMatch, BinaryDiff, DiffEngine paths).
- `tests/` directory present for integration tests.
- Verdict: **testable = true**.
