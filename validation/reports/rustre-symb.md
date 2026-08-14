# rustre-symb

Symbolic execution core: types, expressions, state, and engines.

## Cargo.toml

- **name**: `rustre-symb`
- **version**: 0.1.0
- **edition**: 2024
- **license/description/repo/authors**: workspace inherited
- **dependencies**: `rustre-core` (path), `anyhow`, `thiserror`, `serde`, `serde_json` (all workspace)
- **features**: `subcrates` (gated re-exports of `rustre-symb-engine`, `rustre-symb-taint`, `rustre-symb-z3`)
- **lints**: workspace

## Module map (`src/lib.rs`)

Public modules:
`symbolic_memory_model`, `concolic`, `concolic_execution`, `concolic_executor`,
`constraint_propagator`, `explosion_mitigation`, `formula_simplifier`,
`memory_model`, `path_explorer`, `path_explosion`, `smt_formula`,
`vulnerability_finder`, `summary_cache`, `symbolic_execution_engine`,
`symbolic_value`, `symbolic_state`, `constraint_solver`.

Under `#[cfg(feature = "subcrates")]`: `registry` re-exports `SymbolicExecutor`, `TaintState`, `Z3Solver`.

## Public types

- `Unsat` — error returned when path condition becomes contradictory.
- `SymbolicError` — `UnknownInstruction`, `TypeMismatch`, `WidthMismatch`, `InvalidExtract`, `DivisionByZero`, `StateExplosion`, `UnsatisfiablePath`, `MemoryOutOfBounds`, `Unsat`, `SolverError`, `TypeError`, `UndefinedVariable`, `Other(anyhow)`.
- `SymType` — `Bool`, `BitVec(u32)`, `Pointer`, `Array { elem_ty, len }`.
- `SymExpr` — full AST: `ConstBv`, `ConstBool`, `Var`; arithmetic (`Add/Sub/Mul/UDiv/SDiv/URem/SRem`); bitwise (`And/Or/Xor/Not/Neg/Shl/LShr/AShr/Concat/Extract/ZExt/SExt`); comparison (`Eq/Ne/ULt/ULe/UGt/UGe/SLt/SLe/SGt/SGe`); boolean (`BoolAnd/BoolOr/BoolNot/Ite`); memory (`Load/Store`).
- `SymId = u64` — variable identifier.
- `SymbolicValue { id, ty, expr }` — named typed expression.
- `SymMemory { base, symbolic }` — concrete + symbolic memory maps.
- `PathConstraint { terms }` — conjunction of boolean exprs.
- `SymbolicState { registers, memory, path_condition, constraints, pc, depth, model }`.
- `SymExprSimplifier` — algebraic + constant-folding rewriter.

## Public free functions

- `eval_concrete<S>(expr, env: &HashMap<SymId,u64,S>) -> Option<u64>` — numeric-id env evaluator.
- `sym_add/sub/mul/and/or/xor/not` — constructors with constant folding.
- `expr_width(&SymExpr) -> u32` — best-effort width.

## `SymType` impl

- `const fn width(&self) -> Option<u32>` — `BitVec(w) → w`, `Pointer → 64`, else `None`.

## `SymExpr` impl (selected)

Constructors:
- `const fn bv(val, width)`, `const fn Const(val, width)`, `const fn constant(width, val)`
- `fn Symbol(id, width, name)` — yields `Var { name: "<name>_<id>", ty: BitVec(width) }`
- `const fn Ite(cond, then_, else_)`
- `fn var(name, ty)`
- `fn add_expr / sub_expr / and / or / xor / eq / ite / ugt / uge / extract`

Inspection:
- `fn bit_width(&self) -> u32`
- `const fn is_const(&self) -> bool`
- `const fn as_const_u64(&self) -> Option<u64>`
- `const fn as_const_bool(&self) -> Option<bool>`
- `fn simplify(&self) -> Self`
- `fn evaluate(&self, env: &HashMap<String,u64>) -> Option<u64>`

Operator overloads: `std::ops::Add` and `Sub` for `SymExpr`.

## `SymbolicValue` impl

- `const fn new(id, ty, expr) -> Self`

## `SymMemory` impl

- `fn new() -> Self`
- `fn store_concrete(&mut self, addr: u64, val: SymExpr)`
- `fn load_concrete(&self, addr: u64) -> SymExpr` (returns fresh `mem_<addr>` var on miss)
- `fn store_symbolic(&mut self, sym_id: u64, val: SymExpr)`
- `fn load_symbolic(&self, sym_id: u64) -> Option<&SymExpr>`

## `PathConstraint` impl

- `fn new()`, `fn add(&mut self, expr)`, `fn as_conjunction(&self) -> SymExpr`, `fn is_trivially_false(&self) -> bool`.

## `SymbolicState` impl

- `fn new()`
- `fn fork(&self, branch_cond) -> Self`
- `fn read_register(&self, name) -> SymExpr` (fresh 64-bit var on miss)
- `fn write_register(&mut self, name, val)`
- `fn add_path_condition(&mut self, cond)`, `fn add_constraint(&mut self, cond)`
- `fn is_path_infeasible(&self) -> bool`
- `fn all_constraints(&self) -> Vec<SymExpr>`
- `fn assume(&mut self, &SymExpr) -> Result<(), Unsat>` — simplifies, rejects trivial false.
- `fn is_satisfiable(&self) -> bool` — constant-fold conservative check.
- `fn get_model(&self) -> HashMap<String,u64>` — seeds vars with 0 witness.
- `fn fork_pair(&self, branch_cond) -> (Self, Self)`
- `fn merge(a, b, cond: &SymExpr) -> Self` — ITE-merges registers, ORs path conditions.

## `SymEngine` trait

```rust
pub trait SymEngine: Send + Sync {
    fn step(&mut self, instr: &Instruction, state: &mut SymbolicState)
        -> Result<Vec<SymbolicState>, SymbolicError>;
}
```

Returns 0 (terminate/infeasible), 1 (linear), or ≥2 (branch) successor states.

## `SymExprSimplifier` impl

- `const fn new() -> Self`
- `fn simplify(&self, expr: SymExpr) -> SymExpr`

Rules: `x^x=0`, `x&0=0`, `x&x=x`, `x|0=x`, `x|x=x`, `x+0=x`, `x-0=x`, `x-x=0`, `x*0=0`, `x*1=x`, `!!x=x`, `--x=x`, full constant folding (incl. `ZExt/SExt/Extract/Concat/UDiv/SDiv/URem/SRem`), `ITE(true/false,_,_)` collapse, `BoolAnd/Or` short-circuit on constants and on equal operands, `BoolNot` involution.

## Additional public items (later in file)

- `SymWidth` (`bits()`, `bytes()` const fns)
- `SpecSymExpr` (`width`, `is_concrete`, `eval_concrete`, `substitute`)
- `SymConstraint::assert / deny`
- Spec state helpers (`new`, `set_var`, `get_var`, `add_constraint`, `store_mem`, `load_mem`, `clone_state`).

## Testability

The crate is testable: it has a `tests/` directory and a rich pure-Rust API surface (constructors, simplifier, evaluator, state fork/merge) that is amenable to unit testing without external solvers. The optional Z3 path is gated behind the `subcrates` feature.
