# rustre-symb-z3

Z3 SMT solver backend per analisi simbolica RustRE. Modello pure-Rust con fallback ad eseguibile `z3` esterno.

## Cargo.toml

- **name**: `rustre-symb-z3` v0.1.0, edition 2024
- **dependencies**: `rustre-symb` (path), `anyhow`, `thiserror`, `serde`, `tokio`, `z3` (workspace)
- **lints**: workspace

## Moduli (`pub mod`)

`bitvector_theory`, `constraint_synthesizer`, `formula_cache`, `path_condition`, `path_condition_manager`, `path_explorer`, `quantifier_elim`, `simplifier`, `smt_lib_generator`, `symbolic_memory`, `symbolic_state`, `taint_constraint_tracker`, `theory_array`, `z3_expr_builder`, `z3_integration`, `z3_formula_builder`, `z3_solver_wrapper`, `z3_expression_simplifier`.

## Tipi pubblici principali (lib.rs)

- `SymId = u64`
- `enum SymExpr` — IR di espressioni simboliche bitvector (Const, Symbol, Add/Sub/Mul/UDiv/SDiv/URem/SRem/Neg, And/Or/Xor/Not, Shl/Shr/LShr/AShr/Rol/Ror, Eq/Ne/Lt/Le/Ult/Ule/Ugt/Uge/Slt/Sle/Sgt/Sge, ZeroExt/SignExt/Extract/Concat, Ite, MemVar/Store/Load, BoolVal/BoolAnd/BoolOr/BoolNot/BoolXor/BoolImplies, Forall/Exists)
- `enum SolverResult` — Sat / Unsat / Unknown(String)
- `enum SolverError` (thiserror) — ProcessSpawn / Io / Encoding / Unknown
- `struct CachedResult { result, model }`
- `struct SmtLib2Builder` — emettitore SMT-LIB2 incrementale
- `struct SmtLib2Parser` — parser di output (sat/unsat + model)
- `struct Z3Solver` — solver principale con cache, push/pop, timeout

## `pub fn` (lib.rs)

### `SymExpr`
- `bit_width(&self) -> usize`
- `var(id, bits, name) -> Self`
- `constant(val, bits) -> Self`
- `add/add_expr/sub/sub_expr/mul/udiv/sdiv/urem/srem(a,b) -> Self`
- `bv_and/bv_or/bv_xor/bv_not -> Self`
- `shl/lshr/ashr(a,b) -> Self`
- `eq/ne/ult/ule/ugt/uge/slt/sle(a,b) -> Self`
- `ite(cond,then,else_) -> Self`
- `zero_ext/sign_ext(inner,new_size) -> Self`
- `extract(inner,lo,hi) -> Self`
- `concat(parts) -> Self`
- `collect_symbols(&self) -> Vec<SymId>`

### `CachedResult`
- `model(&self) -> Option<&HashMap<SymId,u64>>`
- `result(&self) -> &SolverResult`

### `SmtLib2Builder`
- `new(logic) -> Self`
- `logic(&self) -> &str`
- `declare_symbols(&mut, &[SymExpr])`
- `assert_expr(&mut, &SymExpr)`
- `check_sat(&mut)`, `get_model(&mut)`, `get_value(&mut, &SymExpr)`
- `push(&mut)`, `pop(&mut)`, `set_timeout(&mut, ms)`
- `as_str(&self) -> &str`, `into_string(self) -> String`

### `SmtLib2Parser`
- `parse_check_sat(output) -> SolverResult`
- `parse_model(output) -> HashMap<String,u64>`

### Free functions
- `emit_smtlib2(&SymExpr) -> String`
- `eval_concrete<S: BuildHasher>(&SymExpr, &HashMap<SymId,u64,S>) -> Option<u64>` — evaluator concreto

### `Z3Solver`
- `new() -> Self`, `with_logic(logic) -> Self`, `default()`
- `set_timeout(&mut, ms)`
- `push(&mut)`, `pop(&mut)`, `assert(&mut, SymExpr)`, `reset(&mut)`
- `is_sat(&mut, &[SymExpr]) -> SolverResult`
- `check_sat(&mut) -> SolverResult`
- `get_model(&mut, &[SymExpr]) -> Option<HashMap<SymId,u64>>`
- `is_sat_concrete(&self, &[SymExpr]) -> bool`
- `prove_equivalent(&mut, &SymExpr, &SymExpr) -> bool`
- `find_input(&mut, &[SymExpr], &SymExpr, u64) -> Option<HashMap<SymId,u64>>`
- `eval(&self, &SymExpr, &HashMap<SymId,u64>) -> Option<u64>`
- `to_smtlib2(&self, &[SymExpr]) -> String`
- `cache_size(&self) -> usize`, `clear_cache(&mut)`, `cache_hit_rate(&self) -> f64`

## API estese nei sotto-moduli (selezione)

- `z3_solver_wrapper`: `enum SolveResult`, `enum ModelValue`, `struct Model`, `struct Z3SolverWrapper`, `struct SolverStats`, fn `check_sat(&[SymExpr])`, fn `check_sat_one(SymExpr)`
- `simplifier`: `struct SimplifyConfig`, `struct SimplifyStats`, `struct Simplifier`
- `constraint_synthesizer`: `enum SymExpr` (locale), `enum ConstraintOp`, `struct BinaryConstraint`, `enum ObjectiveFunction`, `struct SynthesisInput`, `struct SynthesisResult`, `struct Z3ConstraintBuilder`, `struct ConstraintSynthesizer`

## Testabilità

Crate testabile: directory `tests/` presente con `blitz.rs`, `blitz2.rs`. Backend funziona anche senza binario z3 (fallback heuristic via `eval_concrete`).
