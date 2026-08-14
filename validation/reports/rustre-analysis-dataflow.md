# rustre-analysis-dataflow — Analysis Report

## Purpose
Classic data-flow analysis framework: worklist-based forward/backward fixpoint solver over abstract CFGs, plus concrete instances (live variables, reaching definitions, available expressions, very busy expressions), SSA scaffolding (dominators, dominance frontiers, phi insertion), constant propagation lattice, def-use / use-def chain builders, linear-scan register allocation primitives, and a small interprocedural skeleton. Also exposes two simple call-graph BFS slicers (`trace_callers_backward`, `trace_callees_forward`).

## Modules
`alias_analysis`, `cfg_dom`, `constant_propagation`, `constant_propagator`, `def_use`, `def_use_analysis`, `du_chains`, `live_ranges`, `pointer_analysis` (Andersen), `reaching_definitions`, `reaching_defs`, `ssa`, `ssa_optimizer`, `available_expressions`, `value_range`.

## Public API (lib.rs top-level — semantic descriptions)

### Framework
- **`WorklistAlgorithm::run(analysis, cfg)`**
  - in: a `DataFlowAnalysis` impl (direction + transfer + boundary) and a `Cfg<S>`
  - out: `DataFlowResult { in_facts, out_facts, iterations }`
  - behavior: iterate until fixpoint with join at merge points; bail with `NoConvergence` after 10000 iters
  - ground truth: for any monotone analysis, output must equal MOP solution on reducible CFGs; testable by hand-computed live/reaching sets on small CFGs.

- **`linear_cfg(stmts)`**: build straight-line CFG, one stmt per node. Verifiable by counting nodes/edges.

### Classic analyses (each is a `DataFlowAnalysis` impl)
- **`LiveVariableAnalysis`** — backward, may; `in = (out − def) ∪ use`. Ground truth: textbook hand-computed live sets.
- **`ReachingDefinitions`** — forward, may; `out = gen ∪ (in − kill_same_var)`. Ground truth: hand-computed reaching defs.
- **`AvailableExpressions { universe }`** — forward, must (join=intersection).
- **`VeryBusyExpressions { universe }`** — backward, must.

### Standalone tuple-based dataflow (no trait dispatch)
- **`compute_liveness(cfg_nodes: &[(bb_id, succs, gen, kill)]) -> HashMap<bb_id,(live_in,live_out)>`**
  - ground truth: hand-computable for any small CFG. Sorted/deduped output → deterministic.
- **`compute_reaching_defs(cfg_nodes)` -> same shape** — forward dual of liveness. Hand-verifiable.
- **`propagate_constants(assignments, uses) -> HashMap<var, LatticeValue>`** — meet of all constant assignments per variable; missing-but-used → Bottom. Ground truth: enumerate assignments, run `LatticeValue::meet` manually.

### SSA / dominators
- **`compute_dominators(n, successors, entry) -> Vec<usize>`** — idom per node. Ground truth: comparable against Cooper-Harvey-Kennedy or by transitive reachability test (a dominates b iff every path entry→b passes through a).
- **`compute_dominators_from_edges(...)`** — same, edge-list form.
- **`compute_dominance_frontiers(...)`** — DF(n) = set of nodes where n stops dominating. Hand-verifiable on small graphs.
- **`postorder(n, succ, entry) -> Vec<usize>`** — DFS postorder. Ground truth: trivial graph-traversal verifier in Python/networkx.
- **`insert_phi_nodes(...)`** — places φ-nodes per Cytron et al. Ground truth: must place φ at every node in iterated DF of each def site.

### LatticeValue (constant propagation)
- **`LatticeValue::{Top, Const(i64), Bottom}`** with `meet`, `is_const`, `as_const`. Pure algebra → trivially verifiable by truth table.

### Call-graph slicers
- **`trace_callers_backward(addr, hops, edges) -> BackwardTrace`** — BFS backward up to N hops over `(caller,callee)` edges.
- **`trace_callees_forward(addr, hops, edges) -> ForwardTrace`** — BFS forward.
  - ground truth: networkx BFS with cutoff=hops gives same visited node set.

### Chain builders
- **`ChainBuilder::build(cfg, rd_result)`** — produces `(DefUseChain, UseDefChain)` from reaching defs. Verifiable: every (def,use) pair must have a CFG path where var is not redefined.

### Re-exports from `du_chains`
`DefUseChains`, `LinearScan`, `LiveInterval`, `ProgramPoint`, `base_interference` — linear-scan register allocation building blocks.

### Interprocedural
- **`InterproceduralDataFlow::{register_function, compute_summaries, get_summary, set_summary}`** — bottom-up summary computation given a call order. Verifiable by running same analysis intraprocedurally on each function.

## Existing MCP tools (in `rustre-mcp-tools/src/wire_tools.rs`)
- `trace_data_flow` (line 368) — BFS slice on xref graph; **does NOT call this crate**, uses `rustre-analysis-xref` directly.
- `analysis_trace_data_flow_path` (line 3673) — path-accepting variant; same xref backend.

**Gap:** None of the dataflow primitives in this crate (liveness, reaching defs, dominators, DF, phi insertion, const-prop, def-use chains, linear-scan) are exposed via MCP. The two "trace_data_flow" tools are unrelated call-graph BFS that happens to share a name.

## Testable functions (good validator targets)
1. `compute_liveness` — hand-computed live sets on a 3-block CFG.
2. `compute_reaching_defs` — hand-computed RD sets.
3. `propagate_constants` — pure lattice meet, table-driven.
4. `compute_dominators` / `compute_dominators_from_edges` — compare vs networkx `immediate_dominators`.
5. `compute_dominance_frontiers` — compare vs networkx `dominance_frontiers`.
6. `postorder` — compare vs networkx DFS postorder.
7. `trace_callers_backward` / `trace_callees_forward` — compare vs networkx BFS with cutoff.
8. `LatticeValue::meet` — exhaustive truth table.
9. `WorklistAlgorithm::run` + `LiveVariableAnalysis` / `ReachingDefinitions` — textbook examples.
10. `ChainBuilder::build` — every produced edge must correspond to a def-clear path.

## Validator strategy
Build a Rust test harness (or cargo example) that exposes the above functions to Python via stdin/stdout JSON. Cross-check each function against an oracle:
- **networkx** for dominators, dominance frontiers, postorder, BFS slicers.
- **Hand-coded reference** in Python for liveness / reaching-defs / available-expressions / very-busy / const-prop lattice (these are short, ~30 LOC each).
- **Truth tables** for `LatticeValue::meet`.
- **Random CFGs** (reducible, generated with networkx) for fuzz-style equivalence checks on dominators/DF.
- Property: result of `compute_liveness` is order-independent — shuffle node list and assert equal output (deterministic sorted output makes this trivial).
