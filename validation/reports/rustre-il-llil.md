# rustre-il-llil

## Purpose
Production-grade Low-Level Intermediate Language (LLIL) for RustRE. Sits directly above raw machine instructions, architecture-independent. Lifts machine instructions to LLIL, builds CFGs, SSA, runs optimization passes, concrete interpreter, verifier, and bridges to MLIL.

## Public surface (selected, semantic)

### Expression constructors (smart-builders)
- `llil_reg(name, size) -> LlilExpr` — build a register-read expression of given size.
- `llil_load(addr, size) -> LlilExpr` — memory load expression.
- `llil_add/sub/and/or/xor/shl/shr(l, r, size) -> LlilExpr` — binary ALU exprs.
- `llil_cmp_eq/ne/slt(l, r) -> LlilExpr` — comparison exprs producing boolean.
- `llil_zx(expr, from, to) / llil_sx(...)` — zero/sign extension between sizes.
- `llil_flag(name) -> LlilExpr` — read CPU flag.

### Lifters (rustre-il-lift -> LLIL)
- `lift_ir_expr_to_llil(&IrExpr) -> LlilExpr` — convert generic IR expression into LLIL expression.
- `lift_effect_to_llil_instr(...) -> LlilInstruction` — convert IR effect to LLIL instr.
- `lifted_instr_to_llil(&LiftedInstr) -> Vec<LlilAnnotatedInstr>` — translate one lifted machine instr to a sequence of annotated LLIL instructions (preserves address & length).

### Function-level passes / analyses
- `liveness_analysis(&LlilFunction, &LlilCfg) -> HashMap<block_id, BlockLiveness>` — classic backward dataflow: returns in/out live registers per basic block. Externally verifiable against textbook liveness on a hand-written sample.
- `build_ssa(&LlilFunction) -> LlilSsaFunction` — convert function into SSA form with phi nodes at join points. Verifiable: each variable defined exactly once; phi count matches dominance-frontier expectations on known CFGs.

### Serialization / rendering
- `function_to_json / llil_function_to_json / llil_function_to_json_pretty(&LlilFunction) -> String` — serialize function to JSON. Round-trippable via `llil_snapshot_from_json`.
- `function_to_dot / llil_function_to_dot(&LlilFunction) -> String` — Graphviz DOT representation of CFG.
- `function_to_text(&LlilFunction) -> String` — human-readable disassembly-style listing.
- `snapshot_function(&LlilFunction) -> LlilFunctionSnapshot` — serializable snapshot struct.
- `llil_snapshot_from_json(&str) -> Result<LlilFunctionSnapshot>` — parse JSON back.

### Key types (exported)
- `Size`, `LlilRegister`, `LlilExpr`, `LlilInstruction`, `LlilAnnotatedInstr`
- `LlilBasicBlock`/`LlilBlock`, `LlilFunction`, `LlilBuilder`
- `LlilCfg`, `CfgEdge`, `DefSite`, `DefUseChains`, `BlockLiveness`
- Passes: `LlilConstantFolder`, `LlilCopyPropagation`, `LlilDeadCodeElimination`, `LlilNopElimination`, `LlilBranchSimplification`, `LlilBlockMerge`, `LlilStrengthReduction`, `CsePass`, `LlilPeepholeOptimizer`, `LlilPassManager`
- Interpreter: `LlilInterpreter`, `LlilConcreteInterpreter`, `LlilMachineState`, `InterpError`
- SIMD: `SimdReg128`, `SimdInstruction`, `SimdMachineState`
- SSA: `LlilSsaReg`, `PhiNode`, `SsaBlock`, `LlilSsaFunction`
- Verifier: `LlilVerifier`, `LlilVerifyError`, `LlilVerifyResult`
- Liveness: `LlilLivenessAnalysis`, `LivenessResult`, `InstrLiveness`
- Call graph: `FunctionCall`, `LlilCallGraph`

## Existing MCP tools
None. Grep over `crates/rustre-mcp-tools/src/` for `llil` / `il_llil` returns no matches. This crate is currently a library only, not exposed via MCP wire tools.

## Testable functions (deterministic, ground-truthable)
1. **Expression builders** (`llil_add`, `llil_xor`, `llil_cmp_eq`, `llil_zx`, `llil_sx`, ...): construct an expression, serialize via JSON, assert structural fields (op, size, operands). Trivial ground truth: byte-for-byte expected JSON.
2. **`function_to_json` <-> `llil_snapshot_from_json` round-trip**: build a function with `LlilBuilder`, serialize, deserialize, assert equivalence. Pure structural property.
3. **`function_to_dot`**: assert output is valid Graphviz with one node per basic block and edges matching CFG. Verifiable by counting `->` vs CFG edges.
4. **`liveness_analysis`**: on a hand-crafted function (e.g. `r1 = 1; r2 = r1 + 2; return r2`) the live-in of entry is empty, live-out at the use of r1 contains r1. Cross-check with manual textbook computation.
5. **`build_ssa`**: each register version is defined exactly once; number of phi nodes at a diamond CFG join = 1 per variable live across both branches.
6. **`LlilConcreteInterpreter`**: execute a simple straight-line program computing `(a + b) ^ c` and verify result matches Python `(a + b) ^ c` masked to size.
7. **Optimizer passes** (constant folding): build `r1 = 2 + 3`, run `LlilConstantFolder`, assert resulting instr is `r1 = 5`.

## Validator strategy
Library is not MCP-exposed, so validation must be in-crate (Rust integration tests under `tests/`) or via a thin harness binary.

Approach:
- **Property tests** for expression-builders: each builder produces an `LlilExpr` whose discriminant + size + operand count match the constructor contract. Serialize to JSON and snapshot.
- **Round-trip tests**: random-ish `LlilFunction` -> JSON -> snapshot -> compare structural snapshot equality.
- **Semantic oracle for interpreter**: build small LLIL programs implementing arithmetic, run `LlilConcreteInterpreter`, compare final register file against Python-computed reference values for arithmetic, bitwise, shifts, zero/sign-extension (mask to `Size`).
- **Liveness oracle**: hand-coded CFGs with known live-in/out sets (from textbook examples) compared against `liveness_analysis` output.
- **SSA invariant checks**: after `build_ssa`, walk instructions and assert (a) each SSA name has exactly one definition; (b) every use is dominated by its def; (c) phi placement matches dominance frontier (recomputed via petgraph).
- **DOT validation**: parse output with a tiny regex-based check that node and edge counts match `LlilCfg` node/edge counts.
- **No MCP wrapping needed initially**; if desired, expose `function_to_json`, `function_to_dot`, `build_ssa`, `liveness_analysis`, and `LlilConcreteInterpreter::run` as MCP tools later.
