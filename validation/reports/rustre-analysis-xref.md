# rustre-analysis-xref

## Purpose
Cross-reference analysis for binary code: builds and queries a bidirectional database of code-to-code, code-to-data, import, string and type references. Provides byte-level x86/x64 scanners, xref graphs (with reachability, SCC, BFS, topo sort), filtering, JSON serialization, and a path-based bootstrap to scan a PE on disk. Layered on top of `rustre-loader-pe` and `rustre-core::address`.

## Modules
`call_graph_builder`, `call_hierarchy`, `data_flow_xrefs`, `data_xref`, `extract`, `global_xref_analysis`, `import_xref`, `indirect_call_resolver`, `string_xref`, `string_xref_finder`, `transitive_closure`, `xref_call_graph`, `xref_database`, `xref_graph`, `xref_heuristics`, `xref_index`, `xref_query`, `xref_query_engine`.

## Public Functions / Types (top-level surface)

### Top-level free functions
- **`xref_index_from_path(path) -> io::Result<XrefIndexDb>`**
  - Input: filesystem path to a PE file.
  - Output: populated xref index (or empty if not a PE / no exec section).
  - Behavior: reads file, locates `.text` (or first executable section), scans it byte-level, returns index keyed by VA.
  - Ground truth: load same PE in IDA Pro and compare call/jump xref counts to the `.text` section. Also: feeding a non-PE buffer must yield an empty index (total()==0).

- **`xref_index_from_bytes(data: &[u8]) -> XrefIndexDb`**
  - Input: raw bytes (expected PE image).
  - Output: same as above, in-memory variant.
  - Ground truth: identical to path variant for the same bytes.

- **`xrefs_to_in(db, addr) -> Vec<XrefRecord>`** / **`xrefs_from_in(db, addr) -> Vec<XrefRecord>`**
  - Input: explicit `&XrefDatabase` + u64 VA.
  - Output: vector of `{from_addr, to_addr, kind}` records for incoming/outgoing references.
  - Ground truth: compare counts/targets against IDA `Get xrefs to/from` at the same VA.

- **`xrefs_to(addr) / xrefs_from(addr)`** — thin wrappers over a global RwLock-protected `XrefDatabase`.
- **`global_xref_db() -> &RwLock<XrefDatabase>`** — accessor for that backing store.

### `XrefKind` enum
Variants: `CodeCall, CodeJump, CodeReturn, DataRead, DataWrite, DataAddress, DataPointer, ImportByName, ImportByOrdinal, StringRef, TypeRef, ThunkCall`.
Methods: `is_code()`, `is_data()`, `is_import()`, `all()`, `Display`.
Ground truth: `is_code/is_data/is_import` partition the variants per the doc semantics — can be exhaustively tested.

### `Xref` struct
Fields: `from: Address, to: Address, kind: XrefKind, instr_size: u8, tag: Option<String>`.
Constructors: `new`, `with_tag`. Helpers: `is_code`, `is_data`, `Display` (formats `0xFROM -> 0xTO [kind] "tag"`).
Ground truth: `Display` formatting deterministic; pure data record.

### `XrefFilter` (builder)
Methods: `new, with_kinds, from_range, to_range, with_tag_required, tag_contains, min_from, max_to, matches(&Xref) -> bool`.
Behavior: AND of all set predicates; pass-all when empty.
Ground truth: feed handcrafted Xrefs and assert `matches` truth table.

### `XrefDatabase`
- **Constructors**: `new`, `default`.
- **Insertion**: `add(Xref)`, plus convenience adders `add_call, add_jump, add_return, add_data_read, add_data_write, add_data_addr, add_data_pointer, add_import_by_name, add_import_by_ordinal, add_string_ref, add_type_ref, add_thunk`.
- **Queries (by addr)**: `xrefs_from, xrefs_to, callers_of, callees_of, jumpers_to, data_refs_to`.
- **Secondary indices**: `xrefs_to_import(name), xrefs_to_type(name), string_ref_sites(content), all_strings, all_import_names`.
- **Filtering**: `filter_from, filter_to, filter_all`.
- **Mutation**: `remove_from, remove_to, remove_exact`.
- **Stats**: `total_count, is_empty, callee_count, caller_count, is_leaf_function, hot_functions(top_n), all_targets, all_sources, all_call_targets`.
- **Bulk**: `iter_all, merge(other)`.
- **Serialization**: `to_json -> String`, `from_json(json) -> Result<Self, XrefError>` — roundtrip-safe.

Ground truth strategy:
- Build a database from a known sequence of `add_*` calls; assert exact counts and lookup results.
- `to_json`/`from_json` roundtrip must preserve every record (compare `iter_all` multisets).
- `hot_functions` must agree with a Python `collections.Counter` over the same inputs.

### `XrefGraph`
Constructors: `call_graph(db), code_graph(db), data_graph(db), full_graph(db), build(db, kinds)`.
Methods: `node_count, edge_count, successors, contains, reachable_from, is_reachable, strongly_connected_components (Tarjan), bfs_distances, all_nodes, in_degree, out_degree, topological_sort (Kahn — None on cycles)`.

Ground truth strategy:
- Hand-build a tiny DB (e.g., 4-node DAG, 3-node cycle); compare reachability, SCC partitions, BFS distances and topo sort against NetworkX in Python.
- `topological_sort` must return `None` iff the graph has a cycle (verifiable with NetworkX `is_directed_acyclic_graph`).

### `X86XrefScanner`
Fields: `code_range, data_ranges, pointer_size, scan_lea, detect_thunks, function_entries`.
Constructor: `new(code_range, pointer_size)`. Builders: `with_function_entries, add_data_range, without_lea, without_thunk_detection`.
Method: `scan_code(base, bytes, &mut db)` — walks bytes, emits CALL (E8), JMP (E9, optionally classified as ThunkCall at function entries), LEA, etc.

Ground truth strategy:
- Hand-assemble a few bytes: `E8 ?? ?? ?? ??` at offset 0 must add a CodeCall with computed target = base + 5 + signed disp32. Compare to manual Python decode.
- `E9` at a registered function entry → ThunkCall; elsewhere → CodeJump.

### `XrefError`
Variants: `UnknownKind(String), Json(serde_json::Error), InvalidAddress(String), EmptyDatabase, Io(io::Error)`. Standard `thiserror`.

### Re-exports
- From `extract`: `Region, RegionClass, RegionMap, XrefIndex, extract_all, extract_code_to_code, extract_code_to_data_riprel, extract_data_pointers`.
- From `xref_query`: `CallGraph, CallGraphMetrics, TransitiveClosure, XrefQueryEngine`.
- From `xref_index`: `XrefIndexStats, XrefEntry, XrefEntryKind, XrefIndexDb, add_xref_entry`.
- From `xref_database`: `XrefContext, XrefDb, XrefDbStats, XrefMerge, XrefQuery, XrefDbRecord, XrefType, XrefArch, build_xref_db_from_path`.

## Existing MCP Tools (in `rustre-mcp-tools/src/wire_tools.rs`)
- `analysis_xref_call_graph` (L129) — build call graph from raw code bytes.
- `analysis_xref_callees` (L312) — dedup direct Call targets at a call site.
- `trace_data_flow` (L376) — bounded forward/backward slice on xref graph.
- `analysis_xref_get_xrefs_to` (L531) — incoming xrefs at addr (bytes-scan).
- `analysis_xref_get_xrefs_from` (L590) — outgoing xrefs at addr (bytes-scan).
- `analysis_xref_to_path` (L698) — path-aware xrefs-to: load PE from path, scan all exec sections.
- `analysis_xref_from_path` (L757) — path-aware xrefs-from.
- `analysis_xref_call_graph_root_functions` (L831).
- `analysis_xref_string_ref_counts` (L883).
- `analysis_callgraph_path` (L7047), `analysis_callees_path` (L7200) — sibling tools that consume the same xref engine.

Note: the MCP layer goes through `BinaryXrefIndex` / `SimpleXref` / `SimpleXrefKind` (a thinner internal API, likely in submodules), not the top-level `XrefDatabase`. Both surfaces are publicly reachable from this crate.

## Testable Functions (high-confidence external ground truth)
1. **`XrefKind::is_code / is_data / is_import / all`** — pure enum partition.
2. **`Xref::Display` formatting** — deterministic string.
3. **`XrefFilter::matches`** — pure predicate, AND of components.
4. **`XrefDatabase` insert/query symmetry** — for any added xref X, X ∈ `xrefs_from(X.from)` and X ∈ `xrefs_to(X.to)`.
5. **`XrefDatabase::to_json` / `from_json` roundtrip** — multiset equality of `iter_all`.
6. **`XrefDatabase::hot_functions(n)`** — verify against `collections.Counter` over inputs.
7. **`XrefDatabase::callee_count / caller_count / is_leaf_function`** — count uniqueness.
8. **`XrefGraph::reachable_from / is_reachable / bfs_distances / topological_sort / strongly_connected_components`** — compare against NetworkX on small handcrafted graphs.
9. **`X86XrefScanner::scan_code`** for E8 (CALL rel32) and E9 (JMP rel32) — verify target = base + 5 + i32(disp) using Python `struct.unpack("<i", ...)`.
10. **`xref_index_from_bytes` on non-PE input** — must yield `total() == 0`.
11. **`xref_index_from_path` on nonexistent file** — must return `io::Error`.
12. **MCP `analysis_xref_to_path` vs IDA Pro** — for `cargo-zyphora.exe` baseline: pick a few known call sites in IDA, assert the tool returns matching from/to pairs.

## Validator Strategy
- **Unit-level (pure-Rust deterministic)**: drive `XrefDatabase` and `XrefGraph` from Rust test fixtures, snapshot results, and cross-check with Python (NetworkX for graph algos, Counter for hot_functions, struct/hashlib for byte decoding).
- **Scanner-level**: hand-craft minimal byte sequences (`E8 disp32`, `E9 disp32`, `48 8D 05 disp32` for RIP-rel LEA) at known base addresses; compute expected targets in Python; assert scan_code adds the right Xref records.
- **PE-level**: run `xref_index_from_path` on the `cargo-zyphora.exe` baseline; compare total xrefs and a handful of call-site xrefs against the IDA Pro ground truth in `memory/ida_baseline_cargo_zyphora.md`. Allow for known classification mismatches (Thunk vs Jump) but require target VAs to match.
- **MCP parity**: invoke `analysis_xref_to_path` / `analysis_xref_from_path` via the MCP server on the same binary and assert results match the in-process call to `xrefs_to_in` / `xrefs_from_in` on a freshly built index — proves the MCP wrapper doesn't lose/duplicate records.
- **Negative tests**: non-PE bytes → empty index; nonexistent path → io::Error; unknown XrefKind string in JSON → `XrefError::UnknownKind`.
