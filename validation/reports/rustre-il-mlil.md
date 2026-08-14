# rustre-il-mlil

## Purpose
Medium-Level IL (MLIL) for the RustRE decompiler pipeline. Sits above LLIL (low-level IL) and below the C-like
decompiler output. Provides: an MLIL AST (`MlilExpr`, `MlilInstruction`), an SSA form (`SsaVar`, phi placement,
SSA reconstruction), lifting from LLIL effects, a suite of optimization passes (constant folding, dead-store
elimination, copy propagation, trivial-phi elimination, strength reduction, algebraic simplification, redundant
load elimination, global value numbering), dataflow analyses (use-def chains, liveness, dominators, reaching
definitions), a lightweight type-inference / type-recovery pass, calling-convention DB, alias analysis,
verification, and serializers (text, DOT, JSON, C-like pseudocode).

## Public functions (semantic view)

### Lifting
- **effects_to_mlil(effects)** — input: a slice of LLIL/lift `Effect`s. output: a `Vec<MlilInstruction>`.
  Behavior: translates a flat effect list into MLIL instructions. Ground truth: number of MLIL instrs
  monotonic in number of side-effecting effects; deterministic for identical input.

### Optimization passes (mutate MlilFunction, return count of changes)
- **fold_mlil_expr(expr)** — input: one `MlilExpr`. output: `(MlilExpr, u32)` folded expression + change count.
  Ground truth: pure constants (`Add(Const(2),Const(3))` → `Const(5)`) reduce exactly; idempotent on a second call.
- **eliminate_dead_stores(func)** — removes stores whose result is never read. Ground truth: instr count
  decreases by exactly returned `u32`; second invocation returns 0.
- **propagate_copies(func)** — replaces uses of copy-defined vars with their source. Ground truth: idempotent;
  preserves observable semantics on test snapshots.
- **eliminate_trivial_phis(func)** — removes phi nodes with a single distinct incoming value. Ground truth:
  no remaining phi has all operands equal after running; idempotent.
- **eliminate_redundant_loads(func)** — removes loads that re-read the same address with no intervening store.
- **strength_reduce(func)** — replaces costly ops (e.g. `x*2` → `x<<1`, `x%2^k` → `x & mask`).
  Ground truth: `Mul(x, Const(2^k))` becomes `Shl(x, Const(k))`.
- **algebraic_simplify(func)** — applies identities (`x+0=x`, `x*1=x`, `x&x=x`, `x^x=0`, …).
- **global_value_numbering(func)** — GVN: collapses redundant equivalent expressions. Ground truth: idempotent;
  count of distinct value numbers ≤ count of instructions.

### Dataflow / analyses (read-only)
- **build_use_def_chains(func)** — `HashMap<SsaVar, Vec<UseDefEntry>>`. Ground truth: every SSA var has at
  most one def (SSA invariant); every use refers to a def reachable via CFG.
- **compute_liveness(func)** — per-block `BlockLiveness` (live-in, live-out). Ground truth: standard
  backward dataflow fixpoint — `live_out[B] = ∪ live_in[succ(B)]`.
- **compute_dominators(func)** — `HashMap<block_id, idom>`. Ground truth: entry block has itself or no idom;
  resulting tree is acyclic; verifiable against a reference Cooper-Harvey-Kennedy implementation.
- **compute_reaching_defs(func)** — per-block reaching definitions sets. Ground truth: standard forward
  dataflow fixpoint.
- **infer_types(func)** — assigns `InferredType` to each SSA var via constraint propagation. Ground truth:
  constants get their literal size/signedness; pointer arithmetic propagates pointer type.
- **collect_var_info(func)** — list of `MlilVarInfo`. Ground truth: count equals distinct SSA vars in func.
- **collect_constants(func)** — `Vec<u64>` of all integer literals appearing in the function.
  Ground truth: countable directly from MLIL text dump.
- **collect_call_sites(func)** — list of `CallSite` records. Ground truth: count equals number of `Call` MLIL
  instructions.
- **compute_stats(func)** — `MlilStats` (instr count, block count, phi count, …). Ground truth: each field
  matches a direct count over the function.

### Serializers (pure, deterministic)
- **mlil_function_to_text(func) → String** — human-readable dump.
- **mlil_function_to_dot(func) → String** — Graphviz DOT of the CFG. Ground truth: parseable by `graphviz`;
  node count == basic-block count.
- **mlil_function_to_json(func) → Result<String>** — compact JSON; `mlil_function_to_json_pretty` pretty.
  Ground truth: round-trips through `serde_json::from_str` to an equal `MlilFunctionSnapshot`.
- **snapshot_mlil_function(func) → MlilFunctionSnapshot** — serializable snapshot. Ground truth: round-trip
  via JSON preserves block IDs and instruction counts.
- **mlil_expr_to_c / mlil_instr_to_c / mlil_function_to_c** — C-like pseudocode. Ground truth: output is
  deterministic; matches golden snapshots; parentheses balanced.

### Pass infrastructure
- Trait **MlilPass** plus pass structs (`MlilConstantFoldingPass`, `MlilDeadStorePass`,
  `MlilPhiEliminationPass`, `MlilCopyPropagationPass`, `MlilStrengthReductionPass`,
  `MlilAlgebraicSimplifyPass`, `MlilRedundantLoadEliminationPass`, `MlilGvnPass`) and a
  **MlilPassManager** to run them. Ground truth: running the manager twice produces identical output the
  second time (fixpoint).

### Visitors
- **walk_expr(expr, visitor)**, **walk_function_instrs(func, visitor)** — generic traversal callbacks.
  Ground truth: a counting visitor returns the same totals as `compute_stats`.

### Builders
- `MlilExprBuilder`, `MlilInstrBuilder`, `MlilFunctionBuilder`, `MlilPassLifter` — fluent constructors for
  building MLIL from outside (testing, lifters).

## Existing MCP tools
None. `Grep` for `mlil` / `il_mlil` in `crates/rustre-mcp-tools/src` returned zero matches. This crate is
currently consumed only internally (by `rustre-decompiler` and similar) and is **not exposed via MCP**.

## Testable functions (high-value for external validation)
1. `fold_mlil_expr` — purely functional; constant arithmetic verifiable in Python.
2. `eliminate_dead_stores`, `propagate_copies`, `eliminate_trivial_phis`, `algebraic_simplify`,
   `strength_reduce`, `eliminate_redundant_loads`, `global_value_numbering` — idempotency property
   (running twice → second run returns 0 changes).
3. `compute_dominators` — verifiable against networkx `immediate_dominators`.
4. `compute_liveness`, `compute_reaching_defs` — verifiable against a reference Python dataflow.
5. `mlil_function_to_json` ↔ `snapshot_mlil_function` — JSON round-trip equality.
6. `mlil_function_to_dot` — Graphviz parseability + node count == block count.
7. `collect_constants`, `collect_call_sites`, `compute_stats` — counts directly checkable.

## Validator strategy
Build small synthetic `MlilFunction`s via `MlilFunctionBuilder` (and/or feed crafted LLIL `Effect` lists
through `effects_to_mlil`) and assert:
- **Algebraic / fold oracle** — compare `fold_mlil_expr` on `Add/Mul/Shl/And` over random constants against
  Python evaluation of the same expression (with proper wrap to the declared `Size`).
- **Idempotency oracle** — for every mutating optimization pass: run pass → record output → run pass
  again → expect `0` changes and an unchanged `snapshot_mlil_function`.
- **CFG oracles** — build a graph with known dominator tree, compare `compute_dominators` to
  `networkx.immediate_dominators` over a DOT-decoded graph; same for liveness via a textbook fixpoint
  reimplemented in Python.
- **Counting oracles** — `compute_stats`, `collect_constants`, `collect_call_sites` must agree with
  counts derived from `mlil_function_to_text` / JSON snapshot.
- **Serialization round-trip** — `from_str(to_json_pretty(f)) == snapshot(f)`.
- **DOT validity** — pipe `mlil_function_to_dot` to `pydot.graph_from_dot_data` and check parse success
  plus node count.

Since no MCP tool currently exposes this crate, validation must call the public API directly through a
thin Rust harness (e.g. an integration test binary) and dump JSON snapshots for the Python validator to
ingest.
