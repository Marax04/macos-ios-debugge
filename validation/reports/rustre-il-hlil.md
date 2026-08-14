# rustre-il-hlil

## Purpose
High-Level Intermediate Language (HLIL) for the RustRE suite. Provides the structured, C-like representation of decompiled code lifted from MLIL SSA form: typed expressions, structured statements (if/while/for/switch), variable recovery, control-flow structuring (loop detection, dominators, SCC), expression normalization/folding, dead-code removal, copy propagation, variable renaming, type annotation/checking, and C-style pretty printing. Depends on `rustre-il`, `rustre-il-mlil`, `rustre-core`.

## Public API surface

The crate exposes primarily a large data model (`HlilType`, `HlilVar`, `HlilExpr`, `HlilStatement`, `HlilFunction`, `HlilPrototype`, `SwitchCase`, `HlilInstruction`) plus pure transform / analysis free functions and builder structs. Below: the publicly-callable entry points with stable, externally-verifiable semantics.

### Type model — `HlilType`
- `i8/i16/i32/i64/u8/u16/u32/u64() -> HlilType` — constructors for signed/unsigned ints of fixed bit width. Verifiable: returned variant must be `Int{signed, bits}` with expected values.
- `ptr(pointee, bits) -> HlilType` — pointer-of constructor.
- `is_pointer() -> bool`, `is_integer() -> bool` — variant predicates.
- `byte_size() -> Option<u32>` — statically-known byte size. Verifiable: `u32 → Some(4)`, `u8 → Some(1)`, `ptr(_, 64) → Some(8)`, `Array{u8, Some(10)} → Some(10)`, `Struct/Unknown → None`.
- `Display` — formats as C type literal (`uint32_t`, `int8_t *`, `float`, ...).

### Variable / expression / statement models
- `HlilVar::new(name, ty)` / `param(name, ty)` — produce a non-SSA named typed variable; `is_param` flag set on `param`.
- `HlilExpr::expr_type() -> &HlilType` — return type of any expression node; comparisons/logical ops always `Bool`, `SizeOf` always `uint64_t`.
- `HlilExpr::is_const() -> Option<i64>` — extracts integer constant value.
- `HlilExpr::is_const_zero() -> bool` — true iff `Const{value:0,..}`.
- `HlilExpr::uses_var(&HlilVar) -> bool` — depth-bounded (512) tree walk; true iff var appears anywhere in expr.
- `HlilExpr::complexity() -> usize` — node-count complexity metric (depth-bounded).
- `HlilStatement::is_terminator() -> bool` — true for Return/Goto/Break/Continue.
- `HlilStatement::contains_return() -> bool` — recursive search for a Return.
- `HlilStatement::walk(&mut F)` — pre-order traversal.

### Function container — `HlilFunction`
- `new(address, name)` — empty void function at given address.
- `add_local(var)` — push a local.
- `all_statements()` — top-level body iterator.
- `calls_made() -> Vec<&HlilExpr>` — deep collection of `Call` expressions.
- `vars_used() -> Vec<&HlilVar>` — deep collection of variable refs.
- `print() -> String` — render function as C-like text using `CCodePrinter`.

### Pretty printing — `CCodePrinter`
- `new()` (default 4-space indent, no tabs).
- `print_type(&HlilType) -> String`, `print_expr(&HlilExpr) -> String`, `print_statement(&HlilStatement, indent) -> String`, `print_function(&HlilFunction) -> String` — deterministic C-style text.

### Lifting MLIL → HLIL
- `HlilLifter::new()` and `lift(&MlilFunction) -> HlilFunction` (around line 1721) — main entry that converts an MLIL function into structured HLIL.

### Optimisation / folding (free functions on `HlilExpr`/`HlilStatement`/`HlilFunction`)
- `fold_hlil_expr(expr) -> (HlilExpr, u32)` — constant folding pass; returns folded expr + number of rewrites. Verifiable: `Add(Const 2, Const 3)` folds to `Const 5` with count ≥ 1.
- `fold_hlil_stmt(stmt) -> (HlilStatement, u32)` — same, statement level.
- `fold_hlil_function(&mut HlilFunction) -> u32` — in-place fold over body, returns total rewrites.
- `inline_single_use_vars(&mut HlilFunction)` — inlines variables used exactly once.
- `propagate_hlil_copies(&mut HlilFunction) -> usize` — copy-propagation, returns count.
- `rename_variables(&mut HlilFunction, RenameStrategy)` — apply a naming strategy in place.
- `remove_unreachable_after_terminator(&mut Vec<HlilStatement>)` — drop statements after a terminator within the same block.
- `remove_empty_branches(&mut Vec<HlilStatement>)` — collapse empty if/else.
- `remove_dead_code_after_return(&mut Vec<HlilStatement>) -> usize` — like above for Return, returns count removed. Verifiable: `[Return, Assign]` becomes `[Return]`, returns 1.

### Pattern matching / matchers
- `match_expr_patterns(&HlilExpr) -> Vec<HlilPattern>`
- `match_stmt_patterns(&HlilStatement) -> Vec<HlilPattern>`
- `match_function_patterns(&HlilFunction) -> Vec<HlilPattern>`
- `HlilMatcher::new(...)`, `matches(stmts)`, `HlilMatcherSet::{new, register, match_all, matches_named}` — user-defined statement-list matchers.

### Stats / snapshot / utilities
- `hlil_stats(&HlilFunction) -> HlilStats` — aggregated function metrics.
- `walk_hlil_expr(&HlilExpr, &mut W: HlilExprWalker)` — visitor traversal.
- `count_hlil_expr_nodes(&HlilExpr) -> usize` — total AST nodes. Verifiable: `Const → 1`, `Add(Const,Const) → 3`.
- `snapshot_stmt(&HlilStatement) -> HlilStatementSnapshot`
- `snapshot_function(&HlilFunction) -> Result<String, serde_json::Error>` — JSON snapshot.
- `count_breaks_and_continues(&[HlilStatement]) -> (usize, usize)` — Verifiable by direct count on constructed inputs.
- `body_always_returns(&[HlilStatement]) -> bool` — Verifiable: `[Return]→true`, `[Assign]→false`, `[If(then=[Return], else=[Return])]→true`.
- `collect_goto_targets(&[HlilStatement]) -> Vec<Address>` — addresses of all `Goto`. Verifiable by constructed inputs.

### Control-flow structuring submodule (in body of `lib.rs` near 6361+)
- `tarjan_scc(&StructuringCfg) -> Vec<Vec<u32>>` — strongly-connected components. Verifiable against any reference Tarjan impl.
- `dominators(&StructuringCfg) -> HashMap<u32,u32>` — immediate-dominator map. Verifiable against textbook examples.
- `detect_natural_loops(&StructuringCfg) -> Vec<NaturalLoop>` — back-edge loop detection.
- `is_improper_loop(&StructuringCfg, &[u32]) -> bool` — multi-entry SCC check.
- `structure_function(&StructuringCfg) -> StructuredFunction` — full structuring.
- `count_gotos(&[HlilStatement]) -> usize` — Verifiable by counting `Goto` nodes.

### Submodule `hlil_optimization`
- `OptimizationResult::{unchanged, record_change, was_modified}` — result builder.
- `fold(&HlilExpr) -> HlilExpr` and `fold_instructions(&[HlilInstruction]) -> OptimizationResult` — constant folding on the flat-instruction view.
- `live_variables(&[HlilInstruction]) -> Vec<HashSet<String>>` — per-instruction live set. Verifiable on small straight-line inputs.
- Dead-code / unreachable / strength-reduction `eliminate`/`simplify`/`simplify_instructions`/`remove_instructions`.
- `OptimizationPipeline::{default_pipeline, minimal, optimize}` — pipeline runner.
- `expr_utils::{depth, leaf_count, is_simple, is_constant, is_variable}` — externally verifiable shape metrics. Verifiable: depth of `Const`=1, depth of `Add(Const,Const)`=2; `leaf_count(Add(Const,Const))`=2; `is_constant(Const)`=true.

### Submodule `hlil_variable_recovery`
- `VarType::{byte_width, is_pointer, is_integer, widen}` — verifiable shape predicates.
- `RecoveredVar::{new, param, record_usage, is_defined, is_read, is_dead, declaration}` — recovered var bookkeeping.
- `VariableRecovery::{new, recover, var_for_ssa, locals, params, dead_vars, untyped_vars, declarations_block, stats, ssa_debug_dump}` — SSA-based recovery pass.
- `recover_locals(...)` — top-level convenience function.

### Submodule `hlil_types`
- `HlilTypeQualified::{new, named, with_const, with_volatile, is_pointer, is_integer, byte_size}` — qualified types.
- `HlilPointerType::{simple, array_ptr, to_hlil_type, region_size}` — pointer wrappers; `region_size` verifiable for known element size × count.
- `HlilArrayType::{new, total_size, to_hlil_type}` — Verifiable: `new(u32, Some(4)).total_size() == Some(16)`.
- `HlilFunctionType::{void_fn, with_param, returning, variadic, no_return, arity, call_compat, to_hlil_type}` — builder + arity check.
- `TypeAnnotator::{new, annotate}` — annotates a function in place.
- `TypeChecker::{new, check, is_consistent}` — type-consistency check returning error count.
- `TypeRegistry::{new, intern, resolve, intern_fn, unify, query_expr, type_count, type_names, remove}` — interner/resolver.

### Submodule `hlil_expression_normalizer`
- `const_val() -> Option<i64>`, `is_pure() -> bool`, `complexity() -> usize`, `reduced() -> bool` — analysis predicates on normalized expressions.

## Existing MCP tools
None. Grep over `crates/rustre-mcp-tools` for `hlil` yields zero matches. HLIL is currently consumed only by the internal decompiler crate — no `wire_tools.rs` registrations expose it externally.

## Testable functions (high signal, externally verifiable)
1. `HlilType::byte_size` — closed-form table lookup; trivially comparable to expected u32.
2. `HlilType::{i8,...,u64,ptr}` constructors — verifiable by structural assertion.
3. `HlilExpr::is_const`, `is_const_zero` — trivial.
4. `HlilExpr::complexity` / `count_hlil_expr_nodes` — closed-form node-count, comparable to a Python AST walker.
5. `HlilStatement::is_terminator`, `contains_return`, `body_always_returns`, `count_breaks_and_continues`, `collect_goto_targets`, `remove_dead_code_after_return` — pure structural predicates, verifiable on constructed inputs against a Python reference.
6. `fold_hlil_expr` on closed constant expressions (e.g. `Add(Const 2, Const 3)`) — output must equal `Const 5`; verifiable against Python `eval`/integer arithmetic.
7. `expr_utils::{depth, leaf_count, is_simple, is_constant, is_variable}` — closed-form metrics verifiable by a Python AST walker.
8. `HlilArrayType::total_size`, `HlilPointerType::region_size`, `HlilFunctionType::{arity, call_compat}` — pure arithmetic / count, verifiable directly.
9. `structuring::tarjan_scc` and `structuring::dominators` — standard graph algorithms; verifiable against a Python reference (e.g. `networkx.strongly_connected_components`, classic Cooper-Harvey-Kennedy dominator algorithm).
10. `CCodePrinter::print_*` — deterministic string render; can be diffed against fixed golden strings for constructed HlilFunction inputs.
11. `HlilFunction::calls_made`, `vars_used` — countable, comparable to manual count on constructed inputs.

## Validator strategy
Because the crate has no MCP surface, validation must drive the API directly through a small Rust harness in `validation/` (or via existing crate `tests/`):

1. Build a tiny set of hand-constructed `HlilExpr` / `HlilStatement` / `HlilFunction` fixtures whose ground truth is computable in Python (node counts, constant fold results, byte sizes, break/continue counts, goto targets, body-always-returns).
2. For each fixture, call the public functions and assert against a Python-computed reference (e.g. `assert fold_hlil_expr(Add(Const 2, Const 3)).0 == Const 5`; `assert HlilType::u32().byte_size() == 4`).
3. For the graph algorithms (`tarjan_scc`, `dominators`), feed a small fixed CFG and compare to results from a Python reference (NetworkX, or a textbook dominator example) — bit-exact match on the structure.
4. For the pretty printer, freeze a few golden C-style strings produced from constructed `HlilFunction`s and treat them as regression oracles.
5. For lifting (`HlilLifter::lift`), validate end-to-end: lift an `MlilFunction` produced by `rustre-il-mlil` from a known fixture and assert the printed output contains expected tokens (function name, return type, key statements). This is partial ground truth (structural) since exact source recovery is non-deterministic.
6. Coverage report: enumerate every `pub fn` in this report and mark covered/uncovered.
