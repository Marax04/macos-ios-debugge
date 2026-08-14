# rustre-pe-editor

PE binary editing library: patch sections, modify imports/exports/resources, edit header fields, encrypt/decrypt sections (XOR/RC4), and scaffold PE Authenticode signing.

## Cargo.toml

- **name**: `rustre-pe-editor` v0.1.0, edition 2024
- **dependencies**: `rustre-pe-tools` (path), `thiserror`, `serde`, `parking_lot`

## Modules (lib.rs)

- `certificate_editor`, `import_editor`, `overlay_editor`
- `pe_patcher`, `pe_import_editor`, `pe_resource_editor`
- `pe_section_editor`, `pe_surgeon`, `resource_editor`, `section_editor`
- `pe_header_editor`, `pe_certificate_table`, `pe_debug_directory`

## Public API (root)

### Error type
- `enum EditError`: `Pe(PeError)`, `SectionNotFound(String)`, `PatchOutOfBounds{offset,len,file_size}`, `InvalidAlignment`, `CryptoError`, `ImportError`, `ExportError`, `ResourceError`, `SignError`, `Io`.

### Patch / PatchSet
- `struct Patch { offset, original, replacement, description }`
  - `Patch::simple(offset, replacement, desc)`, `Patch::verified(...)`, `len()`, `is_empty()`, `has_verification()`
- `struct PatchSet { patches, name }`
  - `new(name)`, `add(patch)`, `len()`, `is_empty()`, `total_bytes()`

### SectionEditor
- `mod section_chars`: CODE, INITIALIZED_DATA, UNINITIALIZED_DATA, MEM_DISCARDABLE, MEM_EXECUTE, MEM_READ, MEM_WRITE.
- `struct SectionEdit { name, new_characteristics, append_bytes, prepend_bytes, zero_out }`
  - `set_chars(name, chars)`, `zero(name)`
- `struct SectionEditor` (`new(Vec<u8>) -> Result`)
  - `rename_section(old, new)`, `set_characteristics(name, chars)`, `zero_section(name)`, `read_section(name) -> &[u8]`, `write_into_section(name, off, bytes)`, `into_bytes()`, `bytes()`.

### ImportEditor
- `struct ImportEntry { dll, name, ordinal, hint }`
  - `named(dll, name, hint)`, `ordinal(dll, ord)`, `is_named()`, `display()`
- `struct ImportEditor`
  - `new()`, `add_import(entry)`, `remove_dll(name)`, `pending_additions()`, `pending_removals()`, `additions()`, `removals()`, `apply(&mut Vec<u8>) -> Result<usize>`, `clear()`.

### ExportEditor
- `struct ExportEdit { name, ordinal, rva, remove }`
  - `add(name, ord, rva)`, `remove(name)`
- `struct ExportEditor`
  - `new(dll_name)`, `add_export(name, ord, rva)`, `remove_export(name)`, `pending_count()`, `additions()`, `removals()`, `dll_name()`, `clear()`.

### ResourceEditor
- `enum ResourceType { Id(u16), Name(String) }`
- `mod resource_types`: RT_CURSOR, RT_BITMAP, RT_ICON, RT_MENU, RT_DIALOG, RT_STRING, RT_VERSION, RT_MANIFEST.
- `struct ResourceEntry { resource_type, id, language, data }`
  - `new(rt, id, lang, data)`, `manifest(data)`, `len()`, `is_empty()`
- `struct ResourceEditor`
  - `new()`, `add_resource(entry)`, `remove_resource(rt, id)`, `pending_additions()`, `pending_removals()`, `additions()`, `clear()`, `total_data_size()`.

### Crypto
- `fn xor_section(data: &mut [u8], key: &[u8])` — panics on empty key.
- `struct Rc4`: `new(key)`, `next_byte()`, `process(&mut [u8])`.

### Signing scaffold
- `struct CertificateHeader { dw_length, w_revision, w_certificate_type }`
  - `new(payload_len)`, `to_bytes() -> [u8;8]`
- `struct PeSigningScaffold`
  - `new(payload)`, `build_certificate_blob() -> Vec<u8>`, `inject(&mut Vec<u8>) -> Result`, `payload_len()`.

### Header fields
- `enum HeaderField`: MajorLinkerVersion, MinorLinkerVersion, MajorOsVersion, MinorOsVersion, MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion, Win32VersionValue, SizeOfStackReserve/Commit, SizeOfHeapReserve/Commit, Subsystem, DllCharacteristics.

### PeEditor (main type)
- `struct PeEditor { data, applied_patches, edit_log }`
  - `new(data: Vec<u8>) -> Result`
  - `apply_patch(Patch)`, `apply_patchset(PatchSet)`
  - `nop_range(off, len)`, `int3_range(off, len)`
  - `write_bytes(off, &[u8])`, `read_bytes(off, len) -> &[u8]`
  - `patch_entry_point(new_ep_rva)`, `zero_checksum()`
  - (additional methods continue beyond line 1463)

## I/O Model

- **Input**: in-memory `Vec<u8>` PE buffers (no direct file I/O at root API; uses `std::io::Error` via `EditError::Io` for submodules).
- **Output**: mutated `Vec<u8>` buffers returned via `into_bytes()` / `bytes()` or appended in place (e.g., `ImportEditor::apply`, `PeSigningScaffold::inject`).
- **Parsing**: validates input via `rustre_pe_tools::PeFile::parse` on constructor.
- **Serialization**: most public types derive `Serialize`/`Deserialize` (serde-friendly patch sets).
- **Thread-safety**: `PeEditor` uses `parking_lot::RwLock` for the edit log.

## Testability

The crate exposes pure in-memory APIs operating on `Vec<u8>` PE buffers with deterministic results — fully testable without filesystem dependencies. Constructors validate input via `PeFile::parse`, and all mutating operations return `Result<_, EditError>` enabling unit testing of both happy paths and error paths (out-of-bounds, missing sections, malformed headers). Crypto primitives (`xor_section`, `Rc4`) are deterministic and easily round-trip testable.

**testable: true**
