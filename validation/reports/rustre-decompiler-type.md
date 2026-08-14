# rustre-decompiler-type — Crate Analysis

## Purpose
Type-aware decompilation support: provides a decompiler type system (`DecompType`),
a per-variable type environment, an expression emitter that rewrites raw
pointer-arithmetic into typed C-like accesses (`ptr->field`, `arr[i]`, `*ptr`),
and a type-driven variable renamer. Also exposes submodules for struct
recovery, pointer analysis (Andersen PTA), array detection, type propagation /
unification / reconstruction / recovery heuristics, aggregate recovery, and C
layout reasoning.

Sits between `rustre-decompiler-expr` (IR expressions) and the higher-level
decompiler / type-recovery pipelines. No cyclic dependency with
`rustre-decompiler` (one-way: decompiler depends on this crate).

## Public surface (top-level `lib.rs`)

### `DecompType` (enum)
Variants: `Void, Bool, Int(IntWidth), Float32, Float64, Ptr(Box<Self>),
Array(Box<Self>, u64), Struct(Box<StructType>), FnPtr{ret,params}, CStr,
Enum{name,variants,backing}, Unknown`.

Public methods:

- **`byte_size() -> Option<u64>`**
  - In: `&self`
  - Out: byte size assuming 8-byte pointers, `None` for `Unknown`
  - Behavior: standard C sizeof for each variant; arrays = elem_size × n; structs
    return `total_size`.
  - Ground truth: trivially verifiable — `Int(I32).byte_size()==Some(4)`,
    `Ptr(_)==Some(8)`, `Array(I32,10)==Some(40)`, `Float64==Some(8)`,
    `Enum{backing:U16}==Some(2)`.

- **`byte_size_with_ptr_width(ptr_width: u8) -> Option<u64>`**
  - Same, but `Ptr/FnPtr/CStr` use given pointer width (4 or 8).
  - Ground truth: `Ptr(Void).byte_size_with_ptr_width(4)==Some(4)`.

- **`is_pointer() -> bool`**: true iff `Ptr | CStr | FnPtr`.

- **`pointee() -> Option<&Self>`**: returns inner type for `Ptr`, else None.

- **`c_name() -> String`**: C-like rendering ("int32_t", "int32_t *",
  "int32_t[10]", "struct Foo", "char *", "enum Bar", "void *" for Unknown).
  - Ground truth: pure formatting — exact string compare.

- **`name_prefix() -> &'static str`**: short identifier prefix used in renaming
  (`b_`, `i`/`u`, `p_`, `sz_`, `f_`, `arr_`, `s_`, `pfn_`, `e_`, `v_`).

### `StructField` / `StructType`
- `StructField::new(offset, name, ty)`
- `StructType::new(name, fields, total_size)`
- `StructType::field_at(offset) -> Option<&StructField>`: returns field whose
  `[offset, offset+size)` contains the byte offset (skips zero-sized fields).
- `StructType::field_exact(offset) -> Option<&StructField>`: exact-offset match.
  - Ground truth: build struct {value@0 i32, next@8 ptr}, query 0/4/8 → expected
    field name or None.

### `TypeEnvironment`
- `new()`, `set(var, ty)`, `get(var) -> Option<&DecompType>`
- `add_struct(StructType)`, `struct_named(name) -> Option<&StructType>`
- `resolve_struct(&DecompType) -> Option<&StructType>` (inline struct only).
- Behavior: simple `HashMap` store; ground truth = round-trip set/get equality.

### `TypeError` (enum)
`UnknownVar`, `Mismatch`, `DerefNonPointer`, `NoFieldAtOffset`, `ZeroElemSize`.

### `TypedExprEmitter<'a>`
- `new(env, ptr_size) -> Self` (ptr_size currently unused but stored).
- `emit(&Expr) -> Result<String, TypeError>` — renders an `Expr` (from
  `rustre-decompiler-expr`) into a C-like string, applying these rewrites:
  - `var + const_offset` where var is `Ptr<Struct>` → `var->field_name` if
    `field_exact(offset)` hits, or first-field for offset 0.
  - `var + 0` → `*var`.
  - `base + index * elem_size` (also `<<` shift) where elem_size matches the
    pointee size → `base[index]`.
  - `*ptr` rendered as `*ptr`, with `TypeError::DerefNonPointer` if non-pointer.
  - `FieldAccess{base, offset}` → `base->name` / `base.name` if struct known;
    `NoFieldAtOffset` error if struct known but offset missing; else
    `FIELD(base, 0xN)` fallback.
  - `Const(v, w)` → decimal if 0..1000 else hex with U/ULL suffix per width.
  - Cast, neg, addr-of, calls, ternary, phi all rendered.
- Ground truth: small constructed `Expr` trees → expected exact string
  (tests in-file already demonstrate: `node+8 → "node->next"`, `arr+i*4 →
  "arr[i]"`, `*p → "*p"`, `foo(1,x)`).

### `TypeAwareRenamer`
- `new()`, `reset()`
- `rename(&DecompType) -> String`: type-derived prefix + monotonically
  increasing counter per prefix (e.g. `i0, i1`, `p_node_0`, `sz_0`, `b_0`).
- `rename_with_hint(hint, ty)`: preserves names starting with `arg`/`param`,
  else delegates to `rename`.
- `rename_all(&[(String, DecompType)]) -> HashMap<String,String>`: bulk map.
- `rename_variables(code, env) -> String`: rewrites a C-like source string,
  replacing `var_N` identifiers using `env`-driven types when known, else
  heuristics: `malloc(`/`new ` LHS → `ptr_N`; `++`/`--` operands → `i,j,k,...`;
  fallback `var_N → v_N`. Whole-word substitution; longest-first to avoid
  `var_10` matching inside `var_100`.
- Ground truth: rename increments counter; reset clears; prefixes follow
  documented table.

### `TypeQualifier(u8)` (bitflags)
Constants `NONE/CONST/VOLATILE/RESTRICT`; predicates `is_const/is_volatile/
is_restrict`; builders `with_const/with_volatile/with_restrict`;
`qualifier_string()` returns space-joined keywords in canonical order.
- Ground truth: pure bit math + string compare.

### Submodules (also `pub`)
`array_detector`, `c_type_layout`, `pointer_analysis`, `struct_recovery`,
`type_printer_advanced`, `type_propagation`, `type_propagator`,
`type_reconstruction`, `type_recovery_engine`, `type_recovery_heuristics`,
`type_unification`, `type_flow_lattice`, `aggregate_recovery`, `andersen_pta`.
Each exposes its own pub API (not enumerated here — out of scope for top-level
ground-truth validation; deeper analyzers, not pure functions).

## Existing MCP tools
Only one wired in `rustre-mcp-tools/src/wire_tools.rs`:

- **`struct_field_at_path`** → builds a `struct_recovery::RecoveredStruct` from
  the function's stack-variable layout, calls `field_at(offset)`, returns
  field/size/type/name. Inputs: `binary_path`, `addr`, `offset`. Source tag:
  `rustre_decompiler_type::struct_recovery::RecoveredStruct::field_at`.

Nothing else from this crate is exposed: `DecompType`, `TypedExprEmitter`,
`TypeAwareRenamer`, `TypeQualifier`, `TypeEnvironment`, and most submodules
(`andersen_pta`, `pointer_analysis`, `type_propagation`, `type_unification`,
`type_flow_lattice`, `aggregate_recovery`, `array_detector`, `c_type_layout`,
`type_printer_advanced`, `type_recovery_engine/heuristics`,
`type_reconstruction`) have **no direct MCP wrapper**.

## Validator strategy
Pure, deterministic, no external binary needed for the top-level API. Build
small fixtures and assert exact outputs:

1. **`byte_size` / `byte_size_with_ptr_width`** — table-driven: pair each
   `DecompType` variant with its expected C sizeof; verify also against
   independently computed `sum(field.size)` for structs and `elem*n` for arrays.
2. **`c_name`** — golden string compare per variant.
3. **`StructType::field_at` / `field_exact`** — fixture struct with known
   layout; query offsets inside, on boundary, and past end.
4. **`TypedExprEmitter::emit`** — build canonical `Expr` patterns
   (`ptr+const`, `ptr+i*size`, `ptr+0`, `*ptr`, `Cast`, `Call`, `Ternary`,
   `FieldAccess`) and assert exact emitted string; verify `DerefNonPointer`
   raises on non-pointer var; verify `NoFieldAtOffset` raises on bad offset
   into known struct.
5. **`TypeAwareRenamer`** — assert prefix table, counter increments per type
   bucket, `reset` semantics, `rename_with_hint` preservation of `arg*`/`param*`.
6. **`rename_variables`** — feed a small C snippet using `var_0 = malloc(8); for(var_1=0; var_1<10; ++var_1) ...` and assert `var_0 → ptr_0`, `var_1 → i`.
7. **`TypeQualifier`** — exhaustive bit combos vs predicates + `qualifier_string`.

Cross-check ground truth externally: byte sizes match a tiny C reference
table (`sizeof(int32_t)==4`, etc.); rendered C names match the same C grammar.
For the MCP tool `struct_field_at_path` validation requires a real binary +
known stack layout (out of scope for pure-fn validator; integration test).
