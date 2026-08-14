# rustre-loader-dotnet

Crate: `rustre-loader-dotnet` v0.1.0 (edition 2024)
Path: `crates/rustre-loader-dotnet`

## Purpose

Loader for .NET / CIL PE binaries in the RustRE workspace. Detects PE files
with a non-zero CLR Runtime Header (data directory index 14) or a `BSJB`
metadata signature, and exposes ECMA-335 metadata, IL method bodies, the
CIL instruction set, strong-name signatures, NGen native images, managed
resources, and PDB type information.

## Dependencies

- `rustre-core` (workspace) — `Loader`, `LoaderInput`, `BinaryView`,
  `Memory`, `Segment`, `Architecture`, `Address`, `Endian`, `CoreError`,
  `async_trait`.
- `goblin` — PE parsing utilities.
- `thiserror` — error derives.
- `serde` / `serde_json` — serializable metadata structures.
- `bitflags` — `DotnetAssemblyFlags`, `CorFlags`.
- `tokio` (full) — async `Loader` trait implementation.

## Modules

| Module | Role |
|---|---|
| `lib` | Top-level loader, CLR header detection, ECMA-335 table rows, `TypeSig` / `MethodSig`, method-body parser, `DotnetLoader: Loader`, `DotnetArch: Architecture`. |
| `cil_decoder` | Streaming CIL instruction decoder (used by `DotnetArch::disassemble`). |
| `cil_disasm` | Higher-level CIL disassembly helpers. |
| `dotnet_header_parser` | CLR / metadata root header parsing. |
| `dotnet_assembly_loader` | Assembly-level loading orchestrator. |
| `dotnet_type_loader` | TypeDef / TypeRef extraction. |
| `dotnet_type_system` | Reconstructed CLR type system (classes, interfaces, fields). |
| `dotnet_method_loader` | MethodDef + IL body collection. |
| `il_method_loader` | IL opcode table, `MethodHeader`, `LocalVarSig`, `ExceptionHandler`, `IlInstruction`. Re-exported at crate root. |
| `metadata_tables` | `#~` tables-stream decode (all 64 table slots, coded-index sizing). |
| `managed_resources` | `.mresource` parsing. |
| `resources_section_parser` | `.resources` section / `ResourceManager` parsing. |
| `ngen_analysis` | NGen native-image inspection. |
| `pe_clr_header` | `IMAGE_COR20_HEADER`, `ClrFlags`, VTable fixups, entry-point classification. |
| `pdb_type_reader` | PDB type stream reading for .NET. |
| `strongname` | Strong-name signature parsing, `PublicKeyToken`, `StrongNameVerifier`, `AssemblyIdentity`, `GacResolver`. |

## Public API surface

`pub fn` / `pub async fn` count across all modules: **246** (rg over
`src/**/*.rs`). Public types (structs/enums/traits) are present in every
module; key crate-root re-exports come from `il_method_loader`:
`CilOpcode`, `ExceptionHandler`, `IlError`, `IlInstruction`,
`IlMethodLoader`, `LocalVarSig`, `MethodHeader`, `Operand`, `OperandType`,
`build_opcode_table`, and `ExceptionClauseType as IlExceptionClauseType`.

### Top-level (`lib.rs`)

- Detection
  - `pub fn has_clr_header(data: &[u8]) -> bool` — manual PE walk to read
    data-directory 14 in both PE32 and PE32+; deliberately bypasses
    `goblin::pe::PE::parse` to accept minimal/spec-conformant .NET PEs.
  - `pub fn is_dotnet(data: &[u8]) -> bool` — scans for `BSJB`.
- Loader
  - `pub struct DotnetLoader` implementing `rustre_core::Loader`:
    - `name() -> "dotnet"`.
    - `can_load(&LoaderInput)`: `has_clr_header || BSJB`.
    - `async load(LoaderInput) -> Result<LoadResult, CoreError>`: builds a
      single `Memory` segment (`READ|EXECUTE`) at the base hint (default
      `0x00400000`), `Endian::Little`, 64-bit `BinaryView` with `DotnetArch`.
    - `async find_nested` returns `vec![]`.
- Architecture
  - `pub struct DotnetArch` implementing `Architecture` (name `"cil"`,
    pointer size 8, little-endian). `disassemble` delegates to
    `cil_decoder::CilDecoder` and falls back to a single-byte `"???"`
    instruction. `get_branches`, `registers`, `calling_conventions`
    return empty vectors.
- Header / metadata types
  - `ClrHeader::parse(&[u8]) -> Option<Self>`, `is_mixed_mode`,
    `framework_version`, `has_strong_name`.
  - `PeOptHeader::parse(data, opt_hdr_off) -> Option<Self>` — handles
    PE32 (0x10B) and PE32+ (0x20B).
  - `PeSectionHeader::parse`, `rva_to_offset`; free fn
    `parse_pe_sections(data, pe_off)` and `rva_to_file_offset(rva, &[…])`.
  - `DotnetFile::is_valid_dotnet`, `DotnetFile::parse_metadata_header` —
    parses BSJB header, version string, stream headers; populates module
    name and MVID via `#Strings` / `#~` / `#GUID`; returns
    `DotnetLoaderError::NotDotnet` / `TruncatedStream`.
  - `DotnetFile::stream(name)`.
- ECMA-335 row types: `ModuleRow`, `TypeRefRow`, `TypeDefRow` (with
  `is_interface`/`is_abstract`/`is_sealed`/`is_nested_public`), `FieldRow`,
  `MethodDefRow` (`is_abstract`/`is_virtual`/`is_static`/`is_public`/
  `is_constructor`), `ParamRow`, `InterfaceImplRow`, `MemberRefRow`,
  `ConstantRow`, `CustomAttributeRow`, `AssemblyRow` (+ `version_string`),
  `AssemblyRefRow` (+ `version_string`), `NestedClassRow`,
  `GenericParamRow`.
- Signatures
  - `enum TypeSig` (Void/Bool/…/Object, ValueType/Class(token), Array,
    GenericInst, Ptr, ByRef, Var, MVar, Pinned, Unknown).
  - `struct MethodSig { calling_conv, generic_param_count, ret_type, params }`.
  - `pub fn read_compressed_uint(blob, &mut offset)` — ECMA compressed
    unsigned int (1/2/4-byte encoding).
  - `pub const fn decode_type_def_or_ref(coded) -> u32` — coded index →
    raw metadata token (tables 0x02/0x01/0x1B).
  - `pub fn read_type_sig(blob, &mut offset) -> TypeSig`.
  - `pub fn read_method_sig(blob) -> MethodSig`.
- Strings
  - `pub fn read_string_heap(heap, idx) -> &str`.
  - `pub fn resolve_type_name(token, type_defs, type_refs, strings) -> String`.
  - `pub fn cil_type_name(sig, type_defs, strings) -> String`.
  - `pub fn cil_type_name_full(sig, type_defs, type_refs, strings) -> String`.
- Method body
  - `struct MethodBody { is_fat, max_stack, code, local_var_sig_tok, exception_handlers }`.
  - `struct ExceptionClause` (try/handler offsets/lengths,
    class-token-or-filter-offset).
  - `enum ExceptionClauseType { Catch, Filter, Finally, Fault, Unknown(u32) }`
    with `from_u32`.
  - `pub fn parse_method_body(data, offset) -> Result<MethodBody, DotnetLoaderError>` —
    handles tiny (1-byte, `(byte>>2)` code length) and fat (12-byte) headers,
    extra sections (exception clauses), `TruncatedStream` on bounds, and
    `InvalidMethodBody(rva)` for malformed headers.

### Errors

`pub enum DotnetLoaderError`:
`NotDotnet`, `InvalidMetadata`, `TruncatedStream`, `InvalidMethodBody(u32)`,
`UnresolvableRva(u32)`, `ParseError(String)`. `thiserror`-derived `Display`.

### Flags & versions

- `pub struct DotnetRuntimeVersion { major: u16, minor: u16 }` (`Display`
  prints `vMAJOR.MINOR`).
- `bitflags! pub struct DotnetAssemblyFlags : u32`: `IL_ONLY`,
  `REQUIRES_32BIT`, `STRONG_NAME_SIGNED`, `NATIVE_ENTRYPOINT`, `PREFER_32BIT`.
- `bitflags! pub struct CorFlags : u32` — raw `IMAGE_COR20_HEADER.Flags`
  bits (`IL_ONLY`, `REQUIRES_32BIT_PROCESS`, `STRONG_NAME_SIGNED`,
  `NATIVE_ENTRY_POINT`, `TRACK_DEBUG_DATA`, `PREFER_32BIT_PROCESS`).
- `pub struct DotnetMetadata { version, assembly_flags, is_dll, mvid,
  module_name, assembly_name, cor_flags }` + `mock`, `is_pure_il`,
  `is_strong_named`, `Display`.
- `pub struct DotnetStream { name, offset, size }` (+ `Display`).

### Other modules (high level)

- `pe_clr_header` — `ClrHeaderError`, `ClrFlags(u32)`, `ClrDataDirectory`,
  `ClrEntryPoint` enum, `VTableFixup`.
- `metadata_tables` — full `#~` decode of all 64 tables.
- `il_method_loader` — opcode table builder, fat/tiny header parser,
  exception-handler tables, `LocalVarSig`, `IlInstruction`, `Operand`,
  `OperandType`.
- `cil_decoder` / `cil_disasm` — instruction streaming (used by
  `DotnetArch::disassemble`).
- `strongname` — `StrongNameError`, `StrongNameSignature`,
  `PublicKeyToken([u8; 8])`, `StrongNameVerifier`, `AssemblyIdentity`,
  `GacResolver`.
- `resources_section_parser` — `ResourcesError`, `ResourceTypeCode`,
  `ResourceValue`, `ResourceEntry`, `ResourcesSectionParser`,
  `ResourceManagerInfo`.
- `managed_resources` — `.mresource` parser.
- `ngen_analysis` — native-image / NGen header analysis.
- `pdb_type_reader` — PDB-side type lookup.
- `dotnet_assembly_loader`, `dotnet_method_loader`, `dotnet_type_loader`,
  `dotnet_type_system`, `dotnet_header_parser` — higher-level loaders
  that drive the primitives above.

## I/O behavior

- Input: `&[u8]` of a PE file (or a raw .NET metadata blob containing
  `BSJB`). The async `DotnetLoader::load` takes a `LoaderInput` (data +
  URI + hints) and clones the bytes into the resulting `BinaryView`'s
  `Memory` segment.
- Detection priority: PE CLR data directory (index 14) first; BSJB
  signature scan as a fallback for non-PE inputs.
- Output: `LoadResult` wrapping a `BinaryView` with one R/X segment at
  the base-address hint (default `0x00400000`), `DotnetArch`,
  `Endian::Little`, 64-bit pointer width, and the input URI.
- No filesystem I/O. No nested-binary discovery
  (`find_nested` returns `vec![]`).
- Error paths surface through `DotnetLoaderError` (parser layer) and
  `CoreError` (loader trait layer); parsers are bounds-checked and
  return `TruncatedStream` rather than panicking.

## Testability

- Pure parsing entry points (`ClrHeader::parse`, `PeOptHeader::parse`,
  `parse_pe_sections`, `rva_to_file_offset`, `DotnetFile::parse_metadata_header`,
  `parse_method_body`, `read_compressed_uint`, `read_type_sig`,
  `read_method_sig`, `read_string_heap`, `resolve_type_name`,
  `cil_type_name[_full]`, `decode_type_def_or_ref`) are sync, allocate
  only `Vec`/`String`, and depend solely on input byte slices — directly
  unit-testable with hand-crafted buffers.
- `DotnetMetadata::mock()` is provided explicitly for tests.
- `DotnetLoader::{can_load, load}` is async; `tokio` (`full`) is in both
  `[dependencies]` and `[dev-dependencies]`, so integration tests can
  use `#[tokio::test]`.
- `Architecture` impl is testable via the public `Architecture` trait
  from `rustre-core`.

**Testable: yes.**
