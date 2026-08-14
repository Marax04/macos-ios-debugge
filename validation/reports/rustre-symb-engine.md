# rustre-symb-engine

Full symbolic execution engine layered on top of `rustre-symb`.

## Cargo.toml

- **name**: `rustre-symb-engine` v0.1.0, edition 2024
- **dependencies**: `rustre-symb` (path), `anyhow`, `thiserror`, `serde`, `petgraph`, `parking_lot`
- **lints**: workspace

## Moduli

`concolic_engine`, `exploit_finding`, `loop_summarizer`, `state_manager`, `path_condition_engine`, `path_manager`, `state_merger`, `path_explorer`, `symbolic_store`, `symbolic_memory`, `path_condition`, `symbolic_executor`. Root `lib.rs` riesporta API principali (~370KB, contiene anche LLIL/Sx interpreter).

## API pubblica principale (lib.rs)

### Errori e configurazione
- `enum EngineError` — `StateLimitReached`, `DepthLimitReached`, `Timeout`, `Symbolic`, `Other`.
- `enum SolverType` (Default), `enum ExplorationStrategy`.
- `struct ExecutorConfig` — limiti depth/state, strategia, solver.

### Worklist e stato
- `struct StateManager` — `new`, `push`, `pop(strategy)`, `prune_infeasible`, `len`, `is_empty`.
- `enum SymbolicAddress` — `from_expr`, `concrete_value`.

### Riassunti funzione
- `struct FunctionSummary` — `new(address)`, `apply(state)`.

### Rilevamento vulnerabilita
- `enum VulnFinding`.
- `struct VulnDetector` — `new`, `check_null_deref`, `check_buffer_overflow`, `check_integer_overflow`, `register_free`, `check_use_after_free`, `check_format_string`, `drain_findings`, `findings`.

### Raggiungibilita
- `struct ReachabilityQuery`, `struct ReachabilityResult` (`reachable(state)`).

### Executor principale
- `struct SymbolicExecutor` — `new(config)`, `with_default_config`, `seed(addr)`, `register_summary`, `step_once(stepper)`, `run(stepper)`, `check_reachability`, `apply_summary`, `concretize_address`, `stats`.
- `struct ExecutorStats`, `enum HaltReason`, `enum ExecStep`.

### IR simbolica e motore Sym
- `struct SymInstruction`, `enum SymOp`.
- `struct PathResult`, `struct ExecConfig`.
- `struct SymEngine` — `execute(program, initial)`, `step(instr, state)`.
- `struct PathExplorer` — `push_state`, `pop_next`, `explore(program)`.

### Interprete LiftedInstr
- `enum SpecEngineError`.
- `struct LiftedInstr` — `new(addr, mnemonic)`.
- `struct SymbolicInterpreterState` — `new`, `read_reg`, `write_reg`, `load`, `store`.
- `struct PathConstraint`.
- `struct SymbolicInterpreter` — `new`, `execute_block`.
- `trait ConstraintSolver`, `struct ConcreteEvaluator`.
- `struct SymbolicInput`, `struct SymbolicOutput`, `enum SymbolicEffect`.
- `struct SymbolicSummary` — `generate(name, instrs)`.

### Utility free-functions (in lib.rs)
- `check_satisfiable(constraints)`, `generate_concrete_input(state)`.
- `eval_expr(expr, state)`, `exec_llil_op(op, state)`, `run_block(ops, state)`.
- `explore_cfg(...)`.
- `simplify_constraints`, `has_contradiction`, `merge_states`.
- `format_path_conditions`, `expr_depth`, `expr_node_count`.

## Sotto-moduli (highlight)
- `symbolic_store`: `SymExpr`, `StoreEntry`, `ReadResult`, `SymbolicStore` (write_concrete/expr, symbolic_read, havoc_region/address, entries_in_range, entry_count).
- Altri moduli (`concolic_engine`, `path_*`, `state_*`, `symbolic_executor`, `symbolic_memory`, `loop_summarizer`, `exploit_finding`) espongono API analoghe; vedi sorgenti per dettagli.

## Testabilita
Tutti i 12 moduli contengono `#[cfg(test)]` con `#[test]` (totale >500 attributi conteggiati su mod+lib). La crate e testabile via `cargo test -p rustre-symb-engine`.
