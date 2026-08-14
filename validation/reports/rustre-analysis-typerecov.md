# rustre-analysis-typerecov — Analysis Report

## Purpose
Constraint-based **type recovery** pipeline for the RustRE platform.
Three-stage process:
1. Walk lifted IL and emit type constraints (equalities, pointer-of, field-access).
2. Unify constraints via union-find to assign concrete `RecoveredType` to each `TypeVar`.
3. Recover struct shapes (fields with offsets/sizes) from clustered field-access constraints.

Additionally maintains a per-address **function signature registry** (calling conv, return type, args) populated by the lifter and queried with confidence classification.

## Public API surface

### lib.rs — signature registry
- `register_function_signature(addr: u64, record: FunctionSignatureRecord)` — Store a function's recovered ABI keyed by VA. Idempotent (overwrites). **Verifiable**: round-trip — register then `infer_function_signature(addr)` returns matching values.
- `infer_function_signature(addr: u64) -> InferredSignature` — Look up a recovered signature; if absent returns all-Unknown with `Confidence::Low`. Confidence rules: `High` = cc known AND all args concrete; `Medium` = only cc known; `Low` = neither. **Verifiable**: deterministic confidence given known inputs.
- `_clear_function_signatures_for_test()` — test helper.

### type_constraint_generator.rs
- `TypeConstraintGenerator::new(pointer_width: u8)` / `new_64bit()` / `new_32bit()` — construct generator with given word size.
- `type_var_of(value: &IlValue) -> TypeVar` — return (creating if needed) a TypeVar for a given IL operand. **Verifiable**: same value → same var; new values → strictly increasing ids.
- `process(instr: &IlInstr)` / `process_all(instrs: &[IlInstr])` — emit constraints for the given IL instructions.
- `into_constraints() -> Vec<TypeConstraint>` / `constraints() -> &[TypeConstraint]` — accessor.
- `lookup(value: &IlValue) -> Option<TypeVar>` — read-only lookup.
- `filter_by_confidence(threshold: f32) -> Self` — drop constraints under confidence threshold.
- `equalities()` / `pointer_constraints()` / `field_accesses()` — filtered views by `ConstraintKind`. **Verifiable**: each returned constraint has expected kind.

### type_unifier.rs
- `TypeUnifier::new(var_count: u32)` — fresh union-find over N type variables.
- `solve(constraints: &[TypeConstraint]) -> Result<UnificationResult, UnifyError>` — run union-find. **Verifiable**: feeding `Eq(a,b)` and `Eq(b,c)` then `get(a)==get(c)`; conflicting size constraints → `UnifyError`.
- `UnificationResult::get(var) -> &RecoveredType` — resolved type for a var.
- `resolved_vars() -> Vec<TypeVar>` — vars with a concrete (non-Unknown) type.
- `pointers() -> Vec<(TypeVar, &RecoveredType)>` — vars known to be pointers.
- `unify_types(...)` — free function unify entry point.

### struct_recovery_engine.rs
- `StructRecoveryEngine::record(access: FieldAccess)` / `record_all(...)` — log a field access (base var, offset, size).
- `recover_structs_all() -> Vec<RecoveredStruct>` — derive struct layouts from accumulated accesses. **Verifiable**: feeding `(base=0, off=0, size=4)`, `(off=4, size=4)` yields one struct with two 4-byte fields at offsets 0 and 4.
- `recover_for(base_var: TypeVar) -> Option<RecoveredStruct>` — single base.
- `find_conflicts(base_var) -> Vec<FieldConflict>` — overlapping fields with different sizes/types.
- `RecoveredStruct::field_at(offset)`, `to_c_decl() -> String`, `is_union_candidate() -> bool`, `range() -> (u32,u32)`. **Verifiable**: `to_c_decl` returns parseable C `struct { … }`.
- `recover_structs(...)` — free function variant.
- `merge_structs(a, b) -> RecoveredStruct` — combine layouts. **Verifiable**: idempotent merge with self equals self.
- `StructRegistry` — `new/insert/get/all_structs/len/is_empty/names`.

### mem_access_scanner.rs (x86 specific)
- `typevar_for_register(reg: Register) -> Option<TypeVar>` — map iced-x86 reg to TypeVar. **Verifiable**: deterministic mapping; same reg → same var.
- `scan_memory_accesses_x86(...)` — scan x86 instructions, emit `FieldAccess` items.
- `scan_function_to_engine(...)` — scan a function and feed results to a `StructRecoveryEngine`. **Verifiable**: synthesizing an x86 instr with `[rdi+0x10]` access produces a FieldAccess at offset 0x10.

## Existing MCP tools (in rustre-mcp-tools/src/wire_tools.rs)
- `decompiler_recover_structs` — single function struct recovery, uses `mem_access_scanner::scan_function_to_engine`.
- `analysis_recover_structs_path` — cross-function aggregator over a binary path, uses same scanner + `RecoveredStruct`.
- `decompiler_stack_frame_report` / signature tool — uses `infer_function_signature` combined with decompiler vars.

## Testable functions (priority for validator)
1. `register_function_signature` + `infer_function_signature` — round-trip + confidence classification (Low/Medium/High).
2. `TypeConstraintGenerator::type_var_of` — determinism / monotonicity.
3. `TypeUnifier::solve` — transitive equality, pointer-of propagation, conflict → error.
4. `StructRecoveryEngine::recover_structs_all` — known accesses produce expected layout.
5. `RecoveredStruct::to_c_decl` — output contains expected field offsets/sizes.
6. `merge_structs` — idempotent merge.
7. `mem_access_scanner::scan_memory_accesses_x86` — synthetic x86 produces expected FieldAccess offsets.

## Validator strategy
Pure-Rust unit-style validator (no external ground truth needed — internal algebraic invariants are the oracle):
- **Signature registry**: register fixtures with varying `Option` fullness; assert `infer_function_signature` returns the documented confidence per rule.
- **Unifier**: build small `TypeConstraint` vectors directly; cross-check with a naive Python union-find reference (or pure assertions) — `Eq` transitivity, pointer-of width = `pointer_width`, contradictory sizes → `UnifyError`.
- **Struct recovery**: feed deterministic `FieldAccess` sequences; assert recovered field offsets/sizes match input; assert `to_c_decl` contains each field; assert `merge_structs(a,a) == a`.
- **mem_access_scanner**: assemble a handful of x86 instructions via `iced-x86` encoder with known displacements; decode, scan, assert resulting `FieldAccess.offset` equals the encoded displacement.
- Externally verifiable parts (union-find correctness, struct layout offsets) cross-checked with a 30-line Python reference impl.
