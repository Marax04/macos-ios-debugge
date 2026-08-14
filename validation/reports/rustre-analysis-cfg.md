# rustre-analysis-cfg

## Purpose
Control Flow Graph analysis library: builds basic blocks from LLIL instruction streams, computes dominator/post-dominator trees (Cooper-Harvey-Kennedy and Lengauer-Tarjan), detects natural loops and back edges, computes cyclomatic complexity, tests reducibility, emits Graphviz DOT, and supports jump-table decoding and CFG simplification.

## Public functions / types (top-level, from lib.rs)

### `analyze_cfg(instrs: &[(Address, LlilInstruction)]) -> ControlFlowGraph`
- Input: ordered list of (address, LLIL instruction) covering one function.
- Output: fully-analyzed CFG with blocks, edges, entry, dom tree, post-dom tree, natural loops.
- Behavior: 1) identifies leaders from branch/ret/jumpdest 2) builds basic blocks 3) builds edges (Unconditional/True/False/Fallthrough) 4) computes dom & post-dom 5) finds natural loops.
- Ground truth: for a synthetic LLIL sequence with known control structure (e.g. linear, if-then-else, simple loop), block count and edge count are predictable; verifiable against a hand-built networkx/python graph.

### `try_analyze_cfg(...) -> anyhow::Result<ControlFlowGraph>`
- Same as above but returns `Err(CfgError::EmptyCfg)` on empty input.
- Ground truth: empty slice => Err; single Ret => Ok with 1 block, 0 edges.

### `DominatorTree::compute(blocks, edges, entry) -> DominatorTree`
- Output: `idom` map (entry => None), `children`, dominance `frontiers`.
- Behavior: Cooper-Harvey-Kennedy iterative algorithm in RPO.
- Ground truth: For canonical graphs (diamond, loop), idom result is provable and matches networkx `immediate_dominators`.

### `DominatorTree::dominates(a,b) / strictly_dominates / dominated_by / dominance_frontier / depth`
- Pure queries on the precomputed tree.
- Ground truth: properties (reflexive, transitive, antisymmetric) testable; entry dominates all reachable nodes.

### `PostDominatorTree::compute(blocks, edges) -> PostDominatorTree`
- Output: idom + children on reversed CFG with virtual exit.
- Ground truth: exit node post-dominates every reachable block.

### `PostDominatorTree::post_dominates(a,b) -> bool`

### `find_natural_loops(cfg) -> Vec<NaturalLoop>`
- Output: list of `{header, back_edge_src, body, exits, is_innermost}`.
- Behavior: for each back-edge (target dominates source) collect body via reverse-BFS.
- Ground truth: For a graph with a single self-loop on B, returns one loop with header=B, body={B}.

### `natural_loops(cfg, dt) -> Vec<NaturalLoop>`
Same with externally-supplied dom tree.

### `find_back_edges(cfg, dt) -> Vec<(Address, Address)>`
Back-edges = edges where `to` dominates `from`.

### `is_reducible(cfg) -> bool`
True iff every back-edge target dominates its source. Verifiable by definition.

### `cyclomatic_complexity(cfg) -> u32`
McCabe formula `E - N + 2P`. Ground truth: linear function => 1; one if => 2; one if + one loop => 3.

### `cfg_to_dot(cfg) -> String`
Graphviz DOT serialization. Ground truth: parseable by graphviz; node count matches block count.

### `CfgDotPrinter::new() / print(cfg) -> String`
Configurable DOT printer.

### `CfgStats::compute(cfg) -> CfgStats`
Returns `{node_count, block_count, edge_count, loop_count, max_loop_depth, cyclomatic_complexity, entry_blocks, exit_blocks}`. Each field independently verifiable.

### `CfgStats::is_complex() -> bool`
True iff cyclomatic > 10.

### `ControlFlowGraph::{predecessors, successors, is_back_edge, dominates, post_dominates, immediate_dominator, dominance_frontier, reverse_post_order, post_order, reachable_from, block_count, edge_count, to_petgraph}`
Query helpers over the CFG. `reverse_post_order` reverse of `post_order`; `reachable_from(entry)` ⊆ all blocks.

### Re-exports from submodules (also public)
- `edges::{FlowEdge, FlowEdgeKind, classify_terminator, compute_leaders, split_basic_blocks}`
- `jump_table::{JumpTable, JumpTableConfig, JumpTableKind, SwitchBound, SwitchStatement, decode_absolute_table, decode_relative_table}` — decode switch tables from memory bytes; ground truth: synthesize a byte table of N u32 absolute targets => decoded equals input.
- `lengauer_tarjan::{LtDomTree, compute_lt}` — Lengauer-Tarjan dominators; ground truth: must agree with `DominatorTree::compute` on same CFG.
- `post_dominator::FullPostDomTree`
- `simplify::{CfgSimplifier, LoopNode, SimplifyResult, build_loop_nesting_forest, cfg_to_json, layout_cfg, BlockPosition}` — CFG simplification, loop nesting forest, JSON export, layout coords.

### Submodules with their own pub APIs (not re-exported at root)
- `loop_analysis` (`Cfg`, `DominatorTree::build`, `LoopTree::build`, `tarjan_sccs`) — used by MCP tools.
- `back_edge`, `cfg_algorithms`, `cfg_dominators`, `cfg_reconstruction`, `exception_cfg`, `irreducible_cfg`, `loop_detection`, `path_query`, `reducibility_analysis`, `cfg_loop_analyzer`, `cfg_simplifier`.

## Existing MCP tools (wire_tools.rs)
- `analysis_basic_blocks_path` — per-function basic blocks for a binary path.
- `analysis_fn_cfg_path` (`AnalysisFnCfgPathTool`) — build CFG for function at address in path.
- `analysis_dominators_path` (`AnalysisDominatorsPathTool`) — idom + dom_children via `loop_analysis::DominatorTree::build`.
- `analysis_loops_path` (`AnalysisLoopsPathTool`) — natural loops (header/body/back_edges/latches/exit_nodes/depth) + Tarjan SCCs.

Coverage gaps vs library: no MCP tool exposes `post_dominator`, `cyclomatic_complexity`, `is_reducible`, `find_back_edges`, `cfg_to_dot`, `CfgStats`, `jump_table` decoders, or `cfg_simplifier`/`layout_cfg`.

## Testable functions (synthetic LLIL → known result)
1. `analyze_cfg` — block/edge count on hand-crafted instruction streams.
2. `try_analyze_cfg` — empty input error.
3. `DominatorTree::compute` + `dominates` — diamond, nested loop.
4. `PostDominatorTree::compute` + `post_dominates`.
5. `find_natural_loops` — self-loop, while loop, nested loops.
6. `find_back_edges` — count = number of back edges in known CFG.
7. `is_reducible` — reducible CFG returns true; irreducible (two entries into a loop) returns false.
8. `cyclomatic_complexity` — straight line = 1; one branch = 2; one loop = 2; if + loop = 3.
9. `CfgStats::compute` — every field on hand-crafted CFG.
10. `cfg_to_dot` — output contains `digraph cfg` and N node lines.
11. `ControlFlowGraph::reverse_post_order` — entry first; rpo.reverse() == post_order.
12. `ControlFlowGraph::reachable_from(entry)` — equals block set for a connected CFG.
13. `to_petgraph` — node_count and edge_count match.
14. `compute_lt` (Lengauer-Tarjan) — idom result equals `DominatorTree::compute` on identical input.
15. `jump_table::decode_absolute_table` — synthesized byte buffer of N targets round-trips.

## Validator strategy
Build a small Rust test harness (or use existing tests under `tests/`) that constructs synthetic LLIL instruction vectors representing canonical CFG shapes (linear, if-then-else, while, do-while, nested loops, irreducible two-entry loop, switch with N targets). For each shape compute the expected ground truth in Python with `networkx` (immediate dominators, cyclomatic complexity = `e - n + 2`, natural loops via back-edge detection, SCCs) and compare via JSON dump. Cross-validate `compute_lt` vs `DominatorTree::compute` for algorithmic agreement, and `decode_absolute_table` by constructing little-endian u32/u64 byte arrays with chosen target values. Driver: run `try_analyze_cfg` on synthetic LLIL, serialize via `cfg_to_json`, diff against Python reference; assert error path on empty input.
