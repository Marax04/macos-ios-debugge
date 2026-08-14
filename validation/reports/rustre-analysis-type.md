# rustre-analysis-type

## Purpose
Type recovery and propagation for stripped binaries. Collects type constraints
from instruction operands (and ABI / library signatures), unifies type variables
via union-find, then walks the call graph propagating argument and return-value
types across function boundaries. Also provides struct layout recovery, a vtable
analyzer, a C++ type recovery module, and a built-in Win32/CRT signature
database (25 functions) plus a generic builtin catalog.

Modules: `constraints`, `inference`, `lattice`, `primitive_types`, `propagation`,
`struct_builder`, `struct_layout_recovery`, `type_inference_engine`,
`type_inference_full`, `type_propagation`, `vtable`, `cpp_type_recovery`,
`interprocedural`, `builtin_catalog`.

## Public functions / types (lib.rs surface)

### `TypeFact` (enum) + `impl`
- **What**: abstract domain — `Sized(n)`, `Pointer`, `Array`, `Struct{fields}`,
  `SignedInt(n)`, `UnsignedInt(n)`, `Float(n)`, `Bool`, `Char`, `Unknown`.
- `byte_size() -> Option<usize>`: byte size if statically known. Ground truth:
  `UnsignedInt(4).byte_size() == Some(4)`; `Array{element: u32, len: 3}` → 12;
  `Pointer/Struct/Unknown` → `None`.
- `is_known() -> bool`: true iff not `Unknown`.
- `join(&self, &other) -> TypeFact`: lattice **meet** ("most specific")
  with `Unknown` as top. Commutative, idempotent. Ground truth:
  `Sized(4) ⊓ SignedInt(4) = SignedInt(4)`; `x ⊓ x = x`;
  `Unknown ⊓ t = t`; incompatible → `Unknown`.

### `TypeConstraint` (enum)
Constraint kinds: `HasType`, `Equal`, `Deref{ptr,pointee}`, `Add/Sub/Bitwise`,
`IsCondition`, `ReturnOf`, `ArgumentOf`.

### `TypeInferenceEngine`
- `new()` / `default()` — empty engine.
- `fresh() -> TypeVar` — allocate a fresh integer-id type variable.
- `var_for(name) -> TypeVar` — get-or-create var keyed by program-variable name.
- `add_constraint(c)` — record a constraint.
- `solve() -> Result<HashMap<u32, TypeFact>, TypeError>` — run union-find
  unification, return assignment per var-id. **Verifiable**: feed
  `HasType(v0, SignedInt(4))` + `Equal(v0, v1)` → both v0 and v1 map to
  `SignedInt(4)`. With `Deref{ptr:p, pointee:x}` + `HasType(x, UnsignedInt(4))`
  → `p` maps to `Pointer(UnsignedInt(4))`.
- `type_of(name, &assignment) -> Result<TypeFact, TypeError>` — resolve named
  variable; `UnknownVariable` if not registered.
- `all_types(&assignment) -> impl Iterator<(&str, &TypeFact)>`.

### `TypeEnvironment`
- `new`/`default`, `set(name, fact)`, `get(name) -> &TypeFact`,
  `merge(&other)` — combine envs by joining types per name; arg vector grows
  to max length; return types joined.

### `CallGraph`
- `new`, `add_function(name)`, `add_call(from, to)`,
  `topological_order() -> Vec<String>` — iterative DFS post-order (callee
  before caller). Ground truth: for `A->B->C`, order is `[C, B, A]`.

### `TypePropagator`
- `new(call_graph)`, `set_initial_env(fn, env)`, `propagate()` — bottom-up
  fixed-point (capped at 100 iters) where each callee's known return type is
  joined into the caller's slot for that callee and into the caller's
  return type. `env_for(fn) -> Option<TypeEnvironment>`.

### `TypedInstr` / `InstrKind` + `collect_constraints(engine, instrs)`
- Toy instruction model (`Assign/Const/Load/Store/Add/Sub/Branch/Call/Return`).
- `collect_constraints` translates each instr into the corresponding
  `TypeConstraint` and feeds the engine. Ground truth: a `Const{dst:"x",
  bytes:4, signed:true}` produces `HasType(var_for("x"), SignedInt(4))`.

### `FieldAccess` + `StructRecovery::recover(accesses) -> HashMap<String, TypeFact>`
- Given observed `(base, offset, access_size)` tuples, produces one
  `TypeFact::Struct{fields:[(offset, Sized(size)),...]}` per base, sorted by
  offset, deduped. Ground truth: feeding `(base:"o", off:0, sz:4)` and
  `(off:8, sz:8)` → `Struct{fields: [(0, Sized(4)), (8, Sized(8))]}`.

### Library signatures
- `CallingConvention` enum (MicrosoftX64, SysVAmd64, StdCall32, CDecl32,
  Variadic).
- `ParamInfo{name, ty}`, `FunctionSignature{name, dll, params, return_type,
  calling_convention, is_variadic}` with `arity()` and `param_type(idx)`.
- `WinApiTypeDb::lookup(name, dll)`, `lookup_by_name(name)`,
  `all_signatures()` — static DB of **25 signatures** (CreateFileA, ReadFile,
  WriteFile, VirtualAlloc/Free/Protect, CreateThread, WaitForSingleObject,
  CloseHandle, GetProcAddress, LoadLibraryA, HeapAlloc, HeapFree, memcpy,
  memset, malloc, free, strlen, strcpy, strcmp, printf, fopen, fread, fwrite,
  fclose). Case-insensitive name/dll lookup. **Verifiable**:
  `lookup_by_name("strlen")` returns sig with 1 param `s: *char`, return
  `UnsignedInt(8)`, MicrosoftX64; `lookup_by_name("printf").is_variadic ==
  true`; `all_signatures().len() == 25`.
- `LibraryTypeImporter` + `PropagatedTypeFact{call_site, param_index, fact,
  source_function}` — propagate library signatures to call-sites.
- `win_types` consts: `DWORD=4, BOOL=4, HANDLE=8, SIZE_T=8, OVERLAPPED=32,
  FILE_PTR=8`.

### Re-exports
- `builtin_catalog::{list_builtin_types, lookup_builtin_type, BuiltinField,
  TypeRecord}` — generic (non-Win32) catalog of known types.
- `lattice::{RefinementCell, TypeClass, TypeLevel}`.

## Existing MCP tools (wire_tools.rs)
- `type_query` (line 2956) — query the type DB.
- `type_inspect` (line 3000) — inspect a specific type.
- `type_apply_batch` (line 3037) — bulk type application.
- `TypeInferTool` (line 2908) — `infer_types_path`-style inference entry
  (the path-based variant is registered around line 3141 / 3621 via
  `InferTypesPathTool`, backed by `rustre_analysis_typerecov`).
- `TypePropagatePathTool` / `type_propagate_path` (line 3237) — runs
  `rustre_analysis_type::type_propagation::TypePropagator` over a binary on
  disk; returns propagated signatures per function.
- Note: `rustre-analysis-typerecov` (separate sibling crate) is used for
  per-function signature inference and struct recovery scans.

## Externally verifiable functions (validator targets)
1. `TypeFact::byte_size` — fixed table of `(variant, expected_size)`.
2. `TypeFact::join` — commutativity, idempotence, refinement rules
   (`Sized(n) ⊓ X = X` when `X.byte_size()==Some(n)`).
3. `TypeInferenceEngine::solve` — golden constraint-set → expected assignment
   (Equal, HasType, Deref combinations).
4. `CallGraph::topological_order` — given a DAG, callee precedes caller for
   every edge.
5. `StructRecovery::recover` — synthetic accesses → expected ordered struct.
6. `WinApiTypeDb` — exact count (25), case-insensitive lookup, every entry has
   well-formed `(name, dll, arity, return_type, calling_convention)`; spot
   checks (`strlen`/`printf`/`CreateFileA`) match the documented Win32 ABI.
7. `win_types` constants — match published Windows SDK widths on x64.
8. `TypePropagator::propagate` — toy two-function call graph with a known
   callee return type → caller env reflects it after `propagate()`.
9. `collect_constraints` — for each `InstrKind`, assert the expected
   `TypeConstraint` is appended to the engine.

## Validator strategy
Pure unit-style oracle: build small in-memory inputs (constraints, instr
streams, call graphs, field accesses) and compare the crate's outputs against
hand-computed expected values. No binary I/O required. For `WinApiTypeDb`, the
oracle is the published Win32 ABI (sizes from `win_types` and standard MS
docs); assert exact arity, return-type variant, and calling convention for
all 25 entries. For `TypeFact::join`, run a property-style sweep over
finite enum samples to verify commutativity (`a.join(&b)==b.join(&a)`) and
idempotence. For `TypePropagator`, build a 2–3 node call graph and check that
known callee return types reach the caller env. For the integration tools
(`type_propagate_path`, `infer_types_path`), use a small known binary
(e.g. `cargo-zyphora.exe`) and assert the response shape + at least one
expected propagated signature for an imported CRT/Win32 function.
