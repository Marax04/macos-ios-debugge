# rustre-dotnet-edit

## Purpose
dnSpy-style .NET assembly editor. Provides high-level editing of CLR PE assemblies: type/method/field rename, method body (CIL) patching, custom-attribute injection, resource editing, flag mutation, IL instruction insert/delete, type/method/field add/remove, strong-name stripping, assembly merging, signing, and re-serialization back to PE.

## Cargo.toml summary
- name: `rustre-dotnet-edit`, version 0.1.0, edition 2024
- Workspace-managed lints, license, description, etc.
- Runtime deps: `anyhow`, `thiserror`, `serde`, internal `rustre-dotnet`, `rustre-dotnet-metadata`
- Dev-deps: `serde_json`
- Integration tests present: `tests/blitz.rs`, `tests/blitz2.rs`

## Modules (public)
`assembly_patcher`, `assembly_signer`, `assembly_merger`, `cil_injector`, `cil_optimizer`, `cil_patcher`, `dotnet_patcher`, `il_editor_extended`, `il_recompile`, `metadata_editor`, `method_body_editor`, `resource_editor`, `strong_name_editor`, `type_injector`.

## Core API (lib.rs)

### Error type
- `enum EditError` with variants `TypeNotFound`, `MethodNotFound{type,method}`, `FieldNotFound{type,field}`, `NoMethodBody`, `InvalidIlOffset(u32)`, `InvalidFlags(u32)`, `ResourceNotFound`, `Custom(String)`. Implements `Display` and `std::error::Error`.

### Resources
- `struct ManagedResource { name: String, flags: u32, data: Vec<u8> }`
  - `fn new(name, data) -> Self` — embedded resource, default flag = public
  - `const fn is_public(&self) -> bool`

### IL patch ops
- `enum IlPatch` (serde): `Replace{offset,instruction}`, `InsertBefore{offset,instructions}`, `InsertAfter{...}`, `Remove{offset}`, `ReplaceRange{start,end,instructions}`, `Prepend{instructions}`, `Append{instructions}` (append inserts before terminal `ret`).
  - `fn apply(&self, &mut Vec<CilInstruction>) -> Result<()>` — mutates list; errors if offset not found.

### Descriptors for additions
- `struct NewTypeDescriptor { name, namespace, flags, base_type_name, interfaces }`
  - `fn public_class(name, namespace)` — flags = public sealed class
  - `fn public_interface(name, namespace)` — flags = public abstract interface
- `struct NewMethodDescriptor { name, flags, impl_flags, return_type_sig, param_types, param_names, body }`
  - `fn static_void(name)` / `fn instance_void(name)` — convenience ctors with `ret`-only body
  - `fn encode_sig() -> Vec<u8>` — emits ECMA-335 §II.23.2.1 method sig blob (calling-conv byte + param count + return sig + params); param count clamped to 255.
- `struct NewFieldDescriptor { name, flags, type_sig }`
  - `fn public_field(name, element_type)` / `fn public_static(name, element_type)`

### Modifications
- `enum Modification` — exhaustive list of mutation kinds: `RenameType`, `RenameMethod`, `RenameField`, `PatchMethodBody`, `PatchIl`, `AddCustomAttribute`, `Change{Method,Field,Type}Flags`, `AddType`, `RemoveType`, `AddMethod`, `RemoveMethod`, `AddField`, `RemoveField`, `ReplaceResource`, `AddResource`, `RemoveResource`, `SetAssemblyVersion{major,minor,build,revision}`, `StripStrongName`.

### Transactional editing
- `struct EditTransaction` (reversible batch)
  - `fn new()`, `fn add(Modification)`, `fn apply(self, &mut AssemblyEditor) -> Result<()>` (snapshots editor state), `fn rollback(self, &mut AssemblyEditor) -> Result<()>` (restores snapshot or truncates log), `const fn len/is_empty`.

### Strong-name stripping
- `struct SignatureStripper`
  - `fn strip(&mut [u8]) -> Result<()>` — clears CorFlags.StrongNameSigned bit and zeroes the StrongNameSignature data-directory blob in a raw PE. Internally walks MZ→PE→COFF→optional header (supports PE32 / PE32+) and CLI header.

### AssemblyEditor (main facade)
- `struct AssemblyEditor { assembly: AssemblyFile, modifications, /* private mutable tables, raw bytes */ }`
  - `fn new(AssemblyFile) -> Self`
  - `fn from_bytes(Vec<u8>) -> Result<Self>` — parses PE → metadata reader.
  - Public mutators (each constructs a `Modification` and applies):
    - `fn rename_type(&mut, old, new) -> Result<()>`
    - `fn rename_method(&mut, type_name, old, new) -> Result<()>`
    - `fn rename_field(&mut, type_name, old, new) -> Result<()>`
    - `fn patch_method_body(&mut, type_name, method_name, &[CilInstruction]) -> Result<()>`
    - `fn patch_il(&mut, type_name, method_name, Vec<IlPatch>) -> Result<()>`
    - `fn add_custom_attribute(&mut, target, attr_type, Vec<u8>) -> Result<()>`
    - `fn change_method_flags(&mut, type_name, method_name, flags: u32) -> Result<()>`
    - `fn change_field_flags(&mut, type_name, field_name, flags: u32) -> Result<()>`
  - Queries:
    - `const fn modification_count(&self) -> usize`
    - `fn current_types(&self) -> Vec<DotnetType>` — snapshot of edited metadata as high-level types.
  - Output:
    - `fn serialize_to_bytes(&self) -> Result<Vec<u8>>` — returns PE bytes; if raw PE present, strips strong name and returns it; if any pending metadata modification is present, returns an error (re-serialization of edited metadata into the original PE is not yet implemented). If no raw bytes, returns a synthesised metadata-root blob.

### Free functions
- `fn encode_instructions(&[CilInstruction]) -> Vec<u8>` — encodes a list of CIL instructions into a method-body byte stream with tiny-format header when < 64 bytes, otherwise a fat header (max_stack=8, init locals). Supports a broad opcode subset (ret/ldnull/ldc.i4.*, ldc.i8/r4/r8, ldarg/ldloc/stloc, arithmetic, dup/pop/throw, call/jmp/callvirt/newobj, ldstr, br[.s]/brfalse/brtrue, switch, ldfld/stfld/ldsfld/stsfld, box/newarr/castclass/isinst, ldlen, endfinally, ceq/cgt/clt); unknown opcodes emit `nop`. Short branches encoded as signed-byte relative offsets per ECMA-335 §III.1.7.2.

## Submodule pub fn counts (from grep `pub (fn|const fn|async fn|unsafe fn)`)
- `lib.rs`: 129
- `il_editor_extended.rs`: 56
- `metadata_editor.rs`: 55
- `type_injector.rs`: 44
- `resource_editor.rs`: 41
- `cil_injector.rs`: 36
- `il_recompile.rs`: 33
- `dotnet_patcher.rs`: 29
- `method_body_editor.rs`: 29
- `assembly_patcher.rs`: 26
- `assembly_signer.rs`: 23
- `strong_name_editor.rs`: 23
- `assembly_merger.rs`: 21
- `cil_optimizer.rs`: 18
- `cil_patcher.rs`: 12

Total pub fn across the crate: **575**.

## Expected behavior
- All mutators validate target existence in the live metadata tables; missing types/methods/fields yield descriptive `anyhow::Error`s wrapping `EditError`-style messages.
- Mutations are recorded in a `Modification` log on the editor; `EditTransaction` snapshots the entire mutable-table state pre-apply for full rollback.
- `IlPatch` operates on `Vec<CilInstruction>`; offset matches are against the `offset` field of each instruction (not list index). `Append` is `ret`-aware.
- `SignatureStripper::strip` is PE-format aware (PE32 and PE32+), uses section table to translate RVA→file offset, and is checked-arithmetic safe.
- `serialize_to_bytes` refuses to silently drop edits — it currently errors when the user has pending modifications and a raw PE source, signalling that full re-emission is unimplemented.
- `encode_instructions` produces a valid ECMA-335 method body header (tiny vs fat) but the opcode table is a documented subset; unrecognized opcodes degrade to `nop`.

## Testability
- The crate ships its own integration tests (`tests/blitz.rs`, `tests/blitz2.rs`) and `serde_json` dev-dep.
- Pure-Rust, no FFI or external runtime; `SignatureStripper`, `IlPatch::apply`, `encode_instructions`, descriptor helpers, and `EditTransaction` are all directly unit-testable without a real assembly.
- `AssemblyEditor::from_bytes` requires a valid managed PE for end-to-end tests; `AssemblyEditor::new(AssemblyFile)` can be driven from synthesised metadata via `rustre-dotnet-metadata::build_test_metadata_blob` and `AssemblyFile::from_metadata`.

testable: **true**.
