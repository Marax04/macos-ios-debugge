# rustre-il-passes

## Package
- Name: `rustre-il-passes` v0.1.0 (edition 2024)
- Path: `crates/rustre-il-passes`
- Dependencies: `rustre-il`, `rustre-core`, `rustre-il-llil`, `serde`

## Purpose
Production-grade IL analysis and optimization pass framework. Passes operate on `LlilFunction` in-place and communicate results through a shared `PassContext`. A `PassManager` orchestrates ordered execution and convergence-based iteration.

## Modules
- `constant_propagation` — constant folding / propagation over LLIL.
- `interprocedural_passes` — cross-function analyses.
- `loop_analysis` — loop detection, headers, back-edges.
- `memory_access_patterns` — load/store pattern recognition.
- `optimization_pipeline` — pre-built pass pipelines.
- `pass_dependency_graph` — DAG of pass prerequisites/invalidations.
- `pass_metrics` — per-pass timing and counters.
- `switch_detection` — jump-table / switch recovery.
- `type_recovery_pass` — type constraint collection, solver, annotation.

## Core API (lib.rs)
- `struct PassStats { instrs_visited, instrs_modified, instrs_removed, const_folded, exprs_simplified, dead_removed }` — counters; `new()`, `merge(&Self)`.
- `struct PassContext { changed: bool, stats: PassStats, warnings: Vec<String> }` — shared mutable state threaded through a pass run.
- Public re-exports of LLIL types: `LlilFunction`, `LlilCfg`, `LlilExpr`, `LlilInstruction`, `LlilRegister`, `Size`, `Address`.

## Type Recovery API (type_recovery_pass.rs)
- Calling-convention constants: `SYSV_ARGS`, `MS_X64_ARGS`, `CALLEE_SAVED_SYSV`, `CALLER_SAVED_SYSV`.
- Heuristic thresholds: `DEFAULT_CONFIDENCE = 0.75`, `MAX_CONSTRAINTS_PER_VAR = 1024`, `MIN_POINTER_EVIDENCE = 1`, `MIN_FLOAT_EVIDENCE = 2`.
- `TypeConstraintBuilder`, `TypeConstraintCollector`, `TypeSolver`, `AnnotationMerger`, `TypeExporter`.
- `enum PropagatedType` — recovered type lattice values.
- `struct TypeConstraint`, `struct TypeStatistics`.

## I/O Behavior
- Input: an `LlilFunction` (mutable, in-place) and `PassContext`.
- Output: mutated function + updated `PassStats`, `warnings`, and `changed` flag.
- No filesystem or network I/O; pure in-memory analysis.
- Serialization opt-in via `serde` on stats/types for caller-side export.

## Pass Count
- ~266 `pub fn` items across 10 modules.
- 32 `pub fn` exported at lib root level.
- 10 type recovery `pub` items (struct/enum/const).

## Testability
- Embedded `#[cfg(test)]` modules in every source file (lib.rs has 137 test attributes alone).
- Pure in-memory APIs make unit testing trivial via synthetic `LlilFunction`.
- `testable: true`.
