# rustre-decompiler-cfs — Analysis

## Purpose
Control-Flow Structuring (CFS) library implementing the DREAM / "No More Gotos"
algorithm. Takes a low-level CFG (list of `BasicBlock` with successor edges)
and produces a `StructuredAst` of high-level constructs (if / if-else,
while / do-while / for, switch, break / continue / return) plus leftover
`Goto` nodes when an edge is irreducible. Also exposes auxiliary data
structures: dominator tree, post-dominator tree, region tree, loop detector,
and several sub-modules (condition_recovery, goto_elimination, goto_reducer,
loop_detector, loop_structurer, switch_recovery, ast_postpass,
structural_regions, region_tree_builder, dream_algorithm).

It is a pure analysis crate (no I/O, no binary parsing). Inputs are
data-structure-only; outputs are serde-serializable.

## Public surface (lib.rs root)

### Types
- `BlockId(pub u32)` — block identifier; `Display` → `bb<n>`.
- `Statement` — enum: `Raw(String)`, `Assign { lhs, rhs }`, `Return(Option<String>)`, `Branch(String)`.
- `BasicBlock { id, stmts, successors }` — builder methods `new`, `with_stmts`, `with_successors`.
- `LoopKind` — `While | DoWhile | For`.
- `SwitchCase { value: Option<i64>, body }`.
- `StructuredNode` — enum: BasicBlock | Sequence | If | IfElse | Loop | Switch | Goto | Break | Continue | Return.
- `StructuredAst { entry, root, goto_count, loop_count }`.
- `StructureError` — EntryNotFound | EmptyCfg | DisconnectedEntry | Internal.
- `CfgGraph` (public struct, internal helpers are private).
- `ControlFlowStructurer { blocks }` — main engine.
- `CfsAlgorithm` — enum `Dream | Phoenix | Sailr | Structural` (Display).
- `Region` — IR-style enum (Sequence, IfThen, IfThenElse, While, DoWhile, For, Switch, SelfLoop, Block).
- `RegionTree`, `DomTree`, `PostDomTree`, `LoopDetector`, `NaturalLoop` (and likely more below line 1576).

### Public functions / methods (verified, observable behavior only)

| Name | Input (semantic) | Output (semantic) | Expected behavior | External ground truth |
|---|---|---|---|---|
| `BlockId::new(u32)` | block number | `BlockId` wrapping it | Construct id | Trivial; round-trip via `Display` → `"bb{n}"` |
| `BlockId::Display` | `BlockId(n)` | `"bb<n>"` string | Format | Python: `f"bb{n}"` |
| `BasicBlock::new(id)` | id | empty BasicBlock | Stmts and successors are empty vec | Field check |
| `BasicBlock::with_stmts(v)` | stmts list | BasicBlock | Stores stmts verbatim | Field check |
| `BasicBlock::with_successors(v)` | successor ids | BasicBlock | Stores successors verbatim | Field check |
| `StructuredNode::flatten()` | Structured tree | Equivalent tree with singleton Sequences collapsed | A `Sequence([x])` becomes `x`; idempotent | Compare structural equality after two flattens |
| `StructuredNode::goto_count()` | tree | usize | Counts all `Goto` leaves anywhere in the tree | Recursive Python count over serde JSON |
| `StructuredNode::node_count()` | tree | usize | Total nodes (Sequence counted once + children) | Recursive Python count over serde JSON |
| `ControlFlowStructurer::new(blocks)` | Vec<BasicBlock> | engine | Store blocks | — |
| `ControlFlowStructurer::structure(entry)` | entry BlockId | `Result<StructuredAst, StructureError>` | Build CFG, find back-edges, compute dominators, run DREAM → AST. `goto_count` = remaining Gotos in root; `loop_count` = number of back-edges detected | Reducible CFGs (linear, if, if-else, while, do-while, switch, nested) should have `goto_count == 0`; trivial loops yield `loop_count >= 1`; empty input → `EmptyCfg`; unknown entry → `EntryNotFound` |
| `scc_groups(&CfgGraph)` | cfg | `Vec<Vec<NodeIndex>>` | Tarjan SCC groups | Compare against `networkx.strongly_connected_components` on the same graph |
| `CfsAlgorithm::Display` | variant | `"DREAM"` / `"Phoenix"` / `"SAILR"` / `"Structural"` | String form | Exact match |
| `Region::block_ids()` | region | Vec<BlockId> | All block ids contained, in declaration order | Manual enumeration from constructor |
| `Region::is_loop()` | region | bool | true iff While/DoWhile/For/SelfLoop | Enum-variant check |
| `Region::depth()` | region | usize | Maximum nesting depth of structured constructs | Recursive Python count |
| `RegionTree::new / set_root / root / add_region / region_count / region_for_block` | trivial container ops | — | Insertion bookkeeping; `region_for_block` returns index of region containing a block | State-based |
| `DomTree::new / set_idom / idom / children / dominance_path / dominates` | dominator data | usize / path / bool | `dominance_path(b)` walks `idom` upward until fixed point, returns path; `dominates(a,b)` iff `a` appears in `dominance_path(b)` | Compare against `networkx.immediate_dominators` on same CFG |
| `PostDomTree::new / set_ipost_dom / ipost_dom / post_dominates` | post-dom data | bool | `post_dominates(a,b)` walks ipost_dom from b upward looking for a | Compare against networkx reversed-graph idom |
| `LoopDetector::new / add_back_edge` (and more below offset 1576) | back-edges | — | Records back-edges | State-based |

Modules (`ast_postpass`, `condition_recovery`, `dream_algorithm`,
`goto_elimination`, `goto_reducer`, `loop_detector`, `loop_structurer`,
`region_tree_builder`, `structural_regions`, `switch_recovery`) expose
additional public surface not enumerated here — the lib.rs file has 5256
lines total; this analysis covered the first 1576 (the core types + main
DREAM engine + Region/DomTree/PostDomTree/LoopDetector start).

## Existing MCP tools
None. Grep of `rustre-mcp-tools/src` for `cfs`, `rustre_decompiler_cfs`,
`decompiler-cfs`, `ControlFlowStructurer`, `StructuredAst` returns zero
matches. The crate is consumed only by `rustre-decompiler` (per Cargo.toml
comment). No MCP wire tool currently exposes its functionality.

## Testable functions (deterministic, pure, externally verifiable)
1. `BlockId::Display` round-trip
2. `StructuredNode::flatten` idempotence and singleton-Sequence collapse
3. `StructuredNode::goto_count` / `node_count` vs JSON-walker reference impl
4. `ControlFlowStructurer::structure` on canonical CFG shapes:
   - empty → `EmptyCfg`
   - missing entry → `EntryNotFound`
   - single return block → `goto_count == 0`, `loop_count == 0`
   - linear chain of N blocks → `goto_count == 0`
   - diamond if / if-else → `goto_count == 0`
   - while / do-while / self-loop → `loop_count >= 1`
   - 3-way switch with common join → `goto_count == 0`
   - nested if-in-loop, loop-in-loop → `loop_count >= 1/2`
5. `scc_groups` vs `networkx.strongly_connected_components`
6. `DomTree::dominates` / `dominance_path` vs `networkx.immediate_dominators`
7. `Region::block_ids`, `is_loop`, `depth` vs manual enumeration
8. `CfsAlgorithm::Display` exact strings
9. Serde JSON round-trip on `StructuredNode` / `StructuredAst` / `Region`

## Validator strategy
Build a Rust harness binary in `validation/` that:
1. Constructs the canonical CFG fixtures listed above as `Vec<BasicBlock>`
   (linear, if, if-else, while, do-while, self-loop, switch3, nested-if-in-loop,
   loop-in-loop, deep-chain, empty, missing-entry).
2. Calls `ControlFlowStructurer::structure(entry)` and serializes the resulting
   `StructuredAst` to JSON, alongside the input CFG (block list with edges).
3. A Python verifier loads each JSON pair and checks:
   - Error cases produce the right `StructureError` variant.
   - `goto_count` equals an independent recursive count of `Goto` nodes in the AST JSON.
   - `node_count` equals an independent recursive count.
   - `loop_count` equals the back-edge count computed independently by DFS on
     the input CFG (and cross-checked with `networkx.simple_cycles` / SCC size > 1).
   - For reducible fixtures `goto_count == 0`.
   - `flatten` is idempotent (re-serialize after a second flatten — but flatten
     is not exposed via the AST returned by `structure`; test via direct
     construction in the harness instead).
4. For `DomTree`: feed the harness fixture CFGs into the harness's
   dominator-computation entry (re-using `compute_dominators` indirectly is
   not possible since it is private — instead validate by structuring the
   CFG and confirming that `loop_count` and structuring decisions agree with
   networkx idom analysis run on the same CFG in Python).
5. For `scc_groups`: harness exposes a thin wrapper that builds `CfgGraph`
   from the same fixture and returns the SCC node-id partition; Python
   verifies against `networkx.strongly_connected_components`.
6. For serde round-trip: harness emits AST JSON, re-parses it via
   `serde_json::from_str` and asserts equality, exit non-zero on mismatch.

No binary I/O, no project state — all fixtures are in-process literals.
The validator is fully self-contained and reproducible.
