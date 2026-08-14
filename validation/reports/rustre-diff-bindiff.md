# rustre-diff-bindiff — Analysis

## Purpose
BinDiff-style binary diffing engine. Compares two stripped binaries by computing
per-function structural features (CFG topology hash, BB/instruction counts,
call edges, string/const refs, byte hash), then matches functions across the
two binaries through a 5-phase pipeline: exact byte hash, CFG hash, name
match, call-graph propagation, heuristic similarity (with optional Hungarian
assignment). Produces `DiffResult` and human/CSV/JSON/HTML reports.

Depends on `rustre-diff` and `rustre-core` (Address type). No I/O — pure
in-memory algorithms over caller-supplied feature snapshots.

## Public surface (lib.rs top-level)

### `CfgHasher` (zero-sized)
- `CfgHasher::hash_cfg(adjacency: &[(u32, Vec<u32>)]) -> u64`
  - In: CFG as list of (block_id, successor_ids).
  - Out: 64-bit structural hash (Weisfeiler-Lehman, 3 iter).
  - Behavior: address-invariant, node-numbering-invariant topology hash.
  - Ground truth: pure deterministic FNV-1a + WL. Reimplement in Python and
    compare. Property: isomorphic graphs (relabeled node ids) → equal hash.
- `CfgHasher::hash_linear(block_count: u32) -> u64`
  - In: chain length.
  - Out: FNV-1a hash of the integer sequence 0..block_count.
  - Ground truth: trivial Python FNV-1a reimplementation.
- `CfgHasher::wl_hash(adjacency, iterations: u32) -> u64`
  - Same as hash_cfg with configurable iteration count.
  - Property: monotonic — running k iterations on isomorphic graphs yields
    equal hash for any k.

### `FunctionFeatures` (struct + methods)
- `FunctionFeatures::new(address) -> Self` — zero/defaults init.
- `.similarity(&self, other) -> f32`
  - In: two feature records.
  - Out: weighted similarity in [0,1]:
    0.40·cfg_hash_eq + 0.20·bb_prox + 0.15·instr_prox + 0.10·edge_prox +
    0.10·loop + 0.05·string_jaccard.
  - Ground truth: feed crafted features → recompute weights in Python.
- `.can_match(&self, other) -> bool`
  - Out: false if bb_count or instr_count differ by >5×.
  - Ground truth: simple ratio check.

### `BinarySnapshot`
Holds path/arch/entry + HashMap<addr,FunctionFeatures> + petgraph call graph.
- `new(path)`, `add_function(features)`, `add_call(from, to)`,
  `function_count() -> usize`, `call_edge_count() -> usize`,
  `function_at(addr) -> Option<&FunctionFeatures>`,
  `call_targets(addr) -> Vec<u64>` (outgoing),
  `callers_of(addr) -> Vec<u64>` (incoming),
  `all_functions() -> impl Iterator`.
- Ground truth: build a small snapshot, assert add/lookup consistency,
  call edges round-trip via call_targets/callers_of.

### `MatchKind` (enum: ExactHash / CfgHash / CallGraphPropagation / NameMatch / ManualMatch / Heuristic)
- `is_reliable() -> bool` — true for ExactHash, NameMatch.
- `priority() -> u8` — fixed table {Exact:10, Name:9, Cfg:8, Manual:7, Propag:5, Heur:1}.
- `Display` impl returning the variant name.
- Ground truth: enumerate variants and check exact mapping.

### `FunctionMatch`
- `new(a, b, kind)` — default sim/conf = 1.0 if kind reliable else 0.0.
- `with_similarity(s) -> Self` (clamped to [0,1]).
- `is_identical() -> bool` (sim ≥ 0.99).
- `is_good_match() -> bool` (sim ≥ 0.75 AND conf ≥ 0.75).
- `quality_label() -> &'static str` (Identical/Good/Partial/Poor by thresholds 0.99/0.75/0.5).
- Ground truth: parametric table tests on (sim, conf).

### `DiffStats`
- internally constructed via `compute()`; exposes per-kind hashmap counts,
  matched/identical/good/partial/unmatched counts, average sim/conf.
- Ground truth: build matches synthetically, recompute expected counts.

### `DiffResult`
- Public fields snapshot_a/snapshot_b/function_matches/unmatched_a/unmatched_b/stats.
- `match_for_a(addr)`, `match_for_b(addr)` (linear search by address).
- `identical_functions()`, `changed_functions()` (filters).
- `top_matches_by_similarity(n) -> Vec<&FunctionMatch>` (sorted desc).
- `print_summary() -> String` (multi-line text).
- Ground truth: assemble result with known matches, check counts/iter/sort.

### `BinDiffer` (the engine)
- `new() / Default`, `with_min_similarity(s)`, `without_propagation()`.
- `match_by_exact_hash(a, b) -> Vec<FunctionMatch>` (byte_hash eq, only if unique on B).
- `match_by_cfg_hash(a, b, already_matched) -> Vec<FunctionMatch>` (cfg_hash eq, unique on B, conf=0.9).
- `match_by_name(a, b, already_matched) -> Vec<FunctionMatch>` (unique-name pairs, conf=1.0).
- `propagate_matches(&mut matches, a, b)` — BFS over CG, only propagates when both sides have exactly one callee.
- `match_by_similarity(a, b, already_matched) -> Vec<FunctionMatch>` (heuristic; biggest functions first; confidence from margin).
- `find_candidates(feat_a, b, excluded, top_n) -> Vec<(u64, f32)>`.
- `detailed_similarity(a, b) -> f32` = base + byte_hash_bonus(0.05) − cc_penalty(0.1 if cc ratio > 3).
- `diff(a, b) -> DiffResult` — runs all 5 phases in order.
- Ground truth: small hand-crafted snapshots → verify each phase's matches independently; final `diff` is a deterministic composition.

### `DiffReport`
- `new(result)`, `summary() / csv() / html() / json() -> String`,
  `diff_for_function(addr_a) -> Option<String>`.
- Ground truth: serialize and verify shape (CSV header line, JSON parses,
  HTML contains table rows = function_matches.len()).

### `FunctionInfo` (Hungarian-matcher view)
- `FunctionInfo::new(address) -> Self`, `From<&FunctionFeatures>`.
- Carries (addr, name, bytes_crc32, in_edges, out_edges, bb_count, md_index).
- `md_index` derived via prime-product on 8 small primes.
- Ground truth: reimplement md_index_from_features in Python and compare.

### Free function `similarity_score(a: &FunctionInfo, b: &FunctionInfo) -> f64`
- Four-component weighted score: 0.40·name_eq + 0.30·crc32_eq + 0.20·cfg_topology + 0.10·md_index.
- `cfg_topology_similarity` = mean of 3 ratio proximities on (in_edges,out_edges,bb_count).
- `md_index_similarity` = exp(-rel·ln(10)) where rel = |a-b|/avg.
- Ground truth: closed-form numeric formula → Python reimplementation.

### Sub-modules (also `pub mod`)
`callgraph_diff`, `instruction_diff`, `prime_product_hash`, `similarity_matrix`,
`hungarian_matcher`, `call_graph_diff`, `basic_block_diff`, `bb_matching`,
`function_matcher`, `basic_block_hasher`, `diff_reporter`.
(Detailed analysis of these modules is out of scope here — top-level lib.rs
already re-exposes the core engine.)

## Existing MCP tools
The MCP tool `diff_bindiff` registered in `rustre-mcp-tools/src/wire_tools.rs`
(line ~6119) **does not call this crate**: it dispatches to
`rustre_diff::DiffEngine` (sibling crate `rustre-diff`). As of this analysis,
no MCP wire tool exposes the `rustre-diff-bindiff` engine or its
`BinDiffer::diff` entry point. The crate is currently used internally / via
tests only.

## Validator strategy
1. Pure-math reimplementations in Python — `CfgHasher::hash_linear`,
   `hash_cfg`/`wl_hash`, `md_index_from_features`, `similarity_score`,
   `cfg_topology_similarity`, `md_index_similarity`, `FunctionFeatures::similarity`.
   Build Rust harness (small example crate or `cargo run --example`) that
   emits hashes/scores for fixed inputs; Python script computes same and asserts equality.
2. Invariant/property tests — feed an adjacency list and the same list with
   permuted block ids; assert WL hash is invariant. Linear chains of length n
   stable for fixed seeds.
3. Phase-isolation tests — craft two snapshots:
   - byte-identical functions → ExactHash matches exactly those pairs;
   - CFG-isomorphic but byte-different → CfgHash phase picks them up;
   - shared unique names → NameMatch picks them up;
   - chain of callees from matched seed → propagation reaches them.
4. Full-pipeline determinism — `BinDiffer::diff` on same inputs twice must
   yield identical match list (modulo stable ordering of HashMaps; rely on
   match counts and similarity sums).
5. Report serialization — JSON parses, CSV has correct row count, HTML
   contains `<tr>` count == matches.
