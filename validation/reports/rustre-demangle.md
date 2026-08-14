# rustre-demangle

## Purpose
Multi-ABI symbol demangler. Decodes mangled linker symbols emitted by GCC/Clang
(Itanium C++ ABI), MSVC (C++), Rust (legacy `_ZN…E` and v0 `_R…`), Swift
(`$s` / `$S` / `_T0`), D, Go, and Objective-C, returning human-readable
function/type names plus structured metadata (namespace, class, args, return
type, symbol kind).

Dependencies: `cpp_demangle` (Itanium), `rustc-demangle` (Rust).

## Public functions / types (semantic)

### Top-level free functions

- **`demangle(s: &str) -> Option<DemanglingResult>`**
  - in: a single mangled symbol string
  - out: `Some(DemanglingResult{original, demangled, abi, namespace, class, function, args, return_type})` if any ABI recognises it, else `None`
  - behaviour: builds an `AutoDemangler` and dispatches to the first demangler whose `detect()` matches
  - ground truth: comparable to `c++filt`, `rustc-demangle` crate, `swift demangle`, `undname.exe`

- **`batch_demangle<S: AsRef<str>>(symbols: &[S]) -> Vec<DemangleResult>`**
  - in: slice of mangled symbols
  - out: vector of `DemangleResult` (one per input, language + symbol kind classified)
  - ground truth: per-element equivalence with `demangle()` / external tools

- **`batch_demangle_parallel<S: AsRef<str>>(symbols: &[S]) -> Vec<DemangleResult>`**
  - same as above but uses rayon; result must be identical to sequential version

- **`is_constructor(mangled: &str) -> bool`** — true iff Itanium symbol contains `C1`/`C2`/`C3` complete/base/allocating ctor encoding. Verifiable: any `_ZN…C[123]E…` should return true.
- **`is_destructor(mangled: &str) -> bool`** — true iff Itanium contains `D0`/`D1`/`D2`. Verifiable on `_ZN…D[012]E…`.
- **`is_vtable(mangled: &str) -> bool`** — `mangled.starts_with("_ZTV")`.
- **`is_typeinfo(mangled: &str) -> bool`** — starts with `_ZTI` or `_ZTS`.
- **`standard_substitution(code: &str) -> Option<&'static str>`** — maps Itanium std-substitution codes (`St`,`Sa`,`Sb`,`Ss`,`Si`,`So`,`Sd`) to readable names. Verifiable via Itanium ABI spec table.
- **`msvc_calling_convention(code: u8) -> CallingConvention`** — maps an MSVC encoding byte (`A`..`R`) to one of `Cdecl/Pascal/Thiscall/Stdcall/Fastcall/Vectorcall/Clrcall`. Verifiable from MSVC mangling spec.
- **`demangle_msvc_rtti(mangled: &str) -> Option<String>`** — decodes `??_R[0-4]…` RTTI symbols into "RTTI <kind>: <typename>". Verifiable with `undname`.
- **`normalize_type(ty: &str) -> String`** — canonicalises a type string (whitespace/qualifier normalisation); idempotent.

### Demangler trait + per-ABI implementors
`trait Demangler { fn detect(&self, &str)->bool; fn demangle(&self, &str)->Option<DemanglingResult>; }`

Concrete types: `ItaniumDemangler`, `MsvcDemangler`, `RustDemangler`,
`SwiftDemangler`, `DDemangler`, `ItaniumNativeDemangler`, `RustV0Demangler`,
`Demangler2`, `ObjCDemangler`, `AutoDemangler` (composite), `BulkDemangler`,
`SymbolCache`, `DemanglerCache`.

Each implementor:
- `detect`: cheap prefix check (e.g. `_Z`, `?`, `_R`, `$s`)
- `demangle`: returns full structured `DemanglingResult` or `None`

### Enums
`ManglingAbi`, `MangleLanguage`, `SymbolKind`, `CallingConvention`,
`MsvcRttiKind`, `Verbosity`.

### Structs
`DemangleOptions`, `DemanglingResult`, `DemangleResult`, `DemangledSymbol`,
`SwiftSymbol`, `SymbolClassifier`, `DemangleFilter`, `DemanglerStats`,
`DemanglerBenchmark`, `BulkDemangler`.

## Existing MCP tools (rustre-mcp-tools/src/wire_tools.rs)

- `symbols_demangle_auto`  → `rustre_demangle::demangle`
- `symbols_demangle_rust`  → `RustDemangler::demangle`
- `symbols_demangle_msvc`  → `MsvcDemangler::demangle`
- `symbols_demangle_itanium` → `ItaniumDemangler::demangle`
- `symbols_demangle_swift` → `SwiftDemangler::demangle`

All accept `{mangled: string}` and return `{mangled, demangled}`.

## Testable functions (externally verifiable)

1. `demangle` / `symbols_demangle_auto` — oracle: `c++filt`, `rustc-demangle` CLI, `swift demangle`, `undname.exe`.
2. `RustDemangler::demangle` / `symbols_demangle_rust` — oracle: `rustfilt` / the `rustc-demangle` reference crate.
3. `ItaniumDemangler::demangle` / `symbols_demangle_itanium` — oracle: `c++filt -n`.
4. `MsvcDemangler::demangle` / `symbols_demangle_msvc` — oracle: Windows `undname.exe`.
5. `SwiftDemangler::demangle` / `symbols_demangle_swift` — oracle: `swift demangle`.
6. `is_constructor`, `is_destructor`, `is_vtable`, `is_typeinfo` — oracle: regex over Itanium ABI spec on a curated symbol corpus.
7. `standard_substitution` — oracle: static table from Itanium ABI §5.1.4.
8. `msvc_calling_convention` — oracle: MSVC mangling spec table.
9. `demangle_msvc_rtti` — oracle: `undname.exe` on `??_R*` symbols.
10. `batch_demangle` / `batch_demangle_parallel` — oracle: per-element equivalence with `demangle`; equivalence between sequential and parallel batch.

## Validator strategy

1. Build a fixture corpus of mangled symbols across all five ABIs:
   - Rust: harvest from `cargo-zyphora.exe` (1456 fns available in IDA baseline) and from any cdylib in the workspace.
   - Itanium/MSVC/Swift: small curated lists from the ABI specs + known compiler output samples.
2. For each MCP tool, call it on every fixture symbol and capture `{mangled, demangled}`.
3. Compare against an external oracle:
   - Rust → `rustc-demangle` crate used as a Python-callable reference via a tiny helper binary, OR the existing IDA Pro baseline names.
   - Itanium → `c++filt` (mingw or WSL).
   - MSVC → `undname.exe` (ships with MSVC).
   - Swift → `swift demangle` if available; else skip with a warning.
4. Equivalence rule: exact string match after `normalize_type` on both sides; mismatches logged with diff. Score = matches/total per ABI.
5. Pure boolean helpers (`is_constructor`/`is_destructor`/`is_vtable`/`is_typeinfo`) tested with a hand-labelled truth table.
6. `standard_substitution` and `msvc_calling_convention` checked by exhaustive enumeration against the spec tables.
7. `batch_demangle_parallel` validated by asserting element-wise equality with `batch_demangle` over the same corpus (determinism check).
