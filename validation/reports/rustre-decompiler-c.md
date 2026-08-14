# rustre-decompiler-c

## Purpose
Final stage of the decompiler pipeline: takes a structured AST (from `rustre-decompiler-cfs`)
plus a `TypeEnvironment` (from `rustre-decompiler-type`) and emits well-formatted C
pseudocode. Pure string-formatting/AST-to-text crate — no binary parsing, no I/O.

## Public API (semantic)

### Config / data types
- `IndentStyle` (enum: Spaces(n)|Tabs) + `make(level)` → indentation string of given depth.
- `BraceStyle` (KAndR|Allman).
- `ConstNotation` (Auto|Decimal|Hex|HexPrefixed).
- `VarNaming` (TypeBased|Raw|Sequential).
- `CFormat` — bundle of the above plus `emit_block_comments`, `emit_prototype`.
- `CStyleFlags` / `CStyle` — bitfield of style toggles + `max_line_length`.
- `EmitStats` — counters: goto/variable/lines/if/loop/switch.
- `DecompiledFunction { name, source_code, stats }` — the emitter result.
- `EmitError` — error enum.

### Function-shape types
- `FunctionParam::new(name, ty)`
- `FunctionSignature::new(name, return_type, params)` and `.as_c_declaration()` →
  one-line C prototype string `"<retTy> <name>(<ty> <p>, ...)"` (no semicolon).
  Ground truth: parseable by a C parser; semicolon-terminated form must end with `;`.
- `VarDecl::new(name, ty)` / `.with_init(s)` / `.as_c_declaration()` →
  `"<ty> <name>"` or `"<ty> <name> = <init>"`.

### Free functions
- `format_for_header(condition: &str) -> String`
  - Input: either a plain condition or `init;cond;step`.
  - Output: `"init; cond; step"` if 3 parts, else `"; <cond>; "`.
  - Ground truth: pure string transform, exact equality testable.
- `c_precedence_for_op(op: &str) -> CPrecedence`
  - Maps C binary operator strings to their standard precedence level.
  - Ground truth: known C precedence table (`||`=4, `&&`=5, `==`=9, `+`=12, `*`=13, …).

### CPrinter<'a>
- `CPrinter::new(fmt, env)` constructor.
- `emit_function(sig, local_vars, body) -> DecompiledFunction`
  - Input: signature, slice of var decls, structured AST root.
  - Output: full C function text with optional prototype, opening brace per style,
    locals block, body, closing `}`. `stats.lines` = line count; `stats.goto_count`
    propagated from AST.
  - Ground truth: output contains `sig.name`, return type, every param name,
    every local var name, expected control-flow keywords (`if`, `while`, `for`,
    `do`, `switch`, `case`, `default`, `goto label_N`, `break`, `continue`,
    `return`). Stats counts match a manual walk of the AST.
- `emit_expr(expr) -> String` — formats an `Expr` via the type emitter (fallback `<expr>`).
- `emit_const(value, width) -> String` — integer literal formatted per `ConstNotation`.
  Ground truth, deterministic per config:
    - Decimal: `format!("{value}")`.
    - Hex/HexPrefixed: `"0x{value:X}"`.
    - Auto + 0..=999: decimal; ≥1000: width-masked hex with `U` suffix; signed-negative i64 stays decimal.
- `emit_struct_def(&StructType) -> String` — `struct N { <ty> <field>;  /* offset: 0xX */ ... };`.
- `emit_var_decls(&[VarDecl]) -> String` — joined indented declarations.

### DecompFunctionBuilder
- Fluent builder: `new(name).return_type(ty).param(p).local(v).format(fmt).emit(body, env)`.
- Output: same `DecompiledFunction` as `CPrinter::emit_function`.

### CStatement (alternative AST)
- Variants: `Assign`, `DeclAssign`, `Return`, `ExprStmt`, `Break`, `Continue`, `Goto`,
  `Label`, `Block`, `If`, `While`, `DoWhile`, `For`, `Switch`, `Raw`.
- `render(indent) -> String` — recursive pretty-printer (4-space indent, guarded by
  `MAX_RENDER_DEPTH=256`).
- `referenced_vars() -> Vec<String>` — heuristic name extraction from `Assign`.

### CTypeDeclaration (associated emitters)
- `emit_struct(name, &[(ty, field)])` → `"struct N {\n    ty f;\n...};"`.
- `emit_typedef(alias, ty)` → `"typedef ty alias;"`.
- `emit_enum(name, &[(variant, value)])` → `"enum N {\n    V = n,\n...};"`.

### CFlowEmitter
- `new(indent)`, plus `emit_if`, `emit_if_else`, `emit_while`, `emit_do_while`,
  `emit_for`, `emit_switch` — render single control-flow constructs as strings.

### CMacroExpander
- `new()`, `define(name, expansion)`, `expand(code) -> String` (substring replace),
  `macro_count()`.

### CIncludeManager
- `new()`, `add_system(h)`, `add_local(h)`, `emit() -> String`
  (`#include <…>` then `#include "…"`), `count()`,
  `add_for_function(name)` — maps libc names → standard headers
  (malloc → stdlib.h; printf → stdio.h; strlen/memcpy → string.h; open/read → unistd.h).

### Other submodules (pub mod)
- `c_annotation`, `c_comment_gen`, `c_diff_emit`, `c_goto_removal`,
  `c_macro_detection`, `c_output_full`, `c_postprocess`, `c_printer`,
  `c_quality`, `c_recovery`, `c_simplifier`, `c_typeinfer`, `type_formatter`.
  (Helper modules around the main pipeline — not enumerated here.)

## Existing MCP tools
Grep of `rustre-mcp-tools/src/wire_tools.rs` for this crate's symbols finds only
one related tool name: `decompiler_core_batch_decompile` (line 1024).
None of the granular emitters (CPrinter / CFlowEmitter / CIncludeManager /
CMacroExpander / CTypeDeclaration / format_for_header / c_precedence_for_op /
emit_const / emit_struct_def) are exposed as MCP tools.

## Testable functions (high externally-verifiable signal)
1. `format_for_header` — pure string transform, exact-match assertions.
2. `c_precedence_for_op` — fixed table against the C standard precedence chart.
3. `FunctionSignature::as_c_declaration` — exact string with known name/type/params;
   variadic appends `, ...`.
4. `VarDecl::as_c_declaration` — exact string with/without initializer.
5. `CPrinter::emit_const` — deterministic mapping for each `ConstNotation` × `IntWidth`.
6. `CPrinter::emit_function` — must contain function name, return type, param names,
   local var names; `stats.goto_count` equals `body.goto_count()`; `stats.lines`
   equals `source_code.lines().count()`; brace style respected (Allman → `{` alone on a line).
7. `CPrinter::emit_struct_def` — output contains `struct <name> {`, each field's
   c-type and name, and `/* offset: 0xX */` matching the supplied offset.
8. `CStatement::render` — exact-string rendering for each leaf variant; nested
   `Block` indentation grows by 4 spaces per level; depth >256 yields placeholder.
9. `CTypeDeclaration::emit_struct / emit_typedef / emit_enum` — exact strings.
10. `CFlowEmitter::emit_if / emit_if_else / emit_while / emit_do_while / emit_for / emit_switch`
    — exact strings for given inputs.
11. `CMacroExpander::expand` — simple substring replacement; deterministic.
12. `CIncludeManager::emit` — sorted by insertion order, system-then-local;
    `add_for_function` mapping is a fixed table.

## Validator strategy
Pure formatter — no binary I/O. Validate by:
- **Golden-string tests**: feed constructed inputs (signatures, var decls,
  precedence ops, constants, struct types, CStatement trees) and assert
  exact-equal or substring-contains on the produced strings (mirroring the
  existing in-crate test suite but driven externally from the validation harness).
- **Cross-check against C standard**: precedence table from
  ISO/IEC 9899; `add_for_function` mapping against POSIX/libc header conventions.
- **Stat invariants**: for any AST `body`, build a function and assert
  `result.stats.lines == result.source_code.lines().count()`,
  `result.stats.goto_count == body.goto_count()`, and that
  `if_count/loop_count/switch_count` equal the count of those nodes obtained
  via a separate AST walk.
- **Round-trip with cfs**: feed a known CFG through `ControlFlowStructurer`
  then through `CPrinter`; assert the emitted source contains all expected
  control-flow keywords for that CFG shape.
- **Property tests**: random `CStatement` trees of depth ≤16 — `render` must
  produce a string whose brace-balance is zero and whose every line is indented
  by a multiple of 4 spaces.
