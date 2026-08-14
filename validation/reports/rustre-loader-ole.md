# rustre-loader-ole

Loader for OLE2 / Compound File Binary (CFB) documents (Office legacy `.doc`,
`.xls`, `.ppt`, `.msi`, embedded objects, RTF wrappers, OOXML containers).

- **Crate**: `rustre-loader-ole` v0.1.0 (edition 2024)
- **Magic**: `D0 CF 11 E0 A1 B1 1A E1`
- **Dependencies**: `rustre-core`, `serde`, `serde_json`, `thiserror`, `tokio`

## Modules

`fat`, `office`, `ole_parser`, `ole_stream_analyzer`, `ole_streams`,
`ole_macro_analyzer`, `ole_vba_extractor`, `ole_property_reader`,
`ole_stream_parser`, `ole_directory_walker`, `ooxml_extractor`,
`ooxml_relationship_parser`, `rtf_parser`, `security`, `vba`,
`vba_extractor`, `vba_stream_extractor`.

## Public API (top-level `lib.rs`)

### Detection / constants

| Item | Signature | Purpose |
|---|---|---|
| `is_ole` | `fn(&[u8]) -> bool` | Magic check |
| `OLE_MAGIC` | `[u8;8]` (private) | OLE2 signature |
| `FREE_SECT` / `ENDOFCHAIN` / `FATSECT` / `DIFSECT` | `pub const u32` | CFB special sector IDs |

### Errors

- `OleError`: `InvalidMagic`, `TruncatedHeader`, `ParseError(String)`, `UnsupportedVersion(u16)`
- `CfbError`: `InvalidMagic`, `InvalidVersion(u16)`, `TruncatedData`, `InvalidSector(u32)`, `InvalidDirectoryEntry`, `StreamTooLarge`, `Other(String)` — convertible to `OleError`.

### Header & directory types

- `OleSectorSize` enum (`Regular=512`, `Mini=64`) + `as_usize`.
- `OleHeader { minor_version, dll_version, sector_size, dir_sector_count, fat_sector_count, first_dir_sector, mini_fat_count, first_mini_fat }`
  - `parse(&[u8]) -> Result<Self, OleError>`
  - `sector_size_bytes() -> u32`
- `OleDirectoryEntry { name, entry_type, color, child_sid, left_sid, right_sid, start_sector, size, created, modified }`
  - `parse(&[u8], off: usize) -> Result<Self, OleError>`
  - `is_storage / is_stream / is_root`
- `OleFile { header, directory }`
  - `parse(&[u8]) -> Result<Self, OleError>`
  - `find_entry(name) -> Option<&OleDirectoryEntry>`
  - `streams() -> Vec<&OleDirectoryEntry>`
  - `root() -> Option<&OleDirectoryEntry>`

### Architecture / Loader trait

- `OleArch` implements `rustre_core::arch::Architecture` (name `"ole"`, 4-byte ptr, little endian, stub disassembly = single-byte `"data"`).
- `OleLoader` implements `rustre_core::Loader`:
  - `name() -> "ole"`
  - `can_load(&LoaderInput) -> bool`  (via `is_ole`)
  - `async load(LoaderInput) -> Result<LoadResult, CoreError>` — builds a single READ segment at `hints.base_address` (default 0) and returns a `BinaryView`.
  - `async find_nested(&LoaderInput) -> Result<Vec<NestedBinary>, CoreError>` — currently `Ok(vec![])`.

### Stream discovery

- `OleStream { name, size: u32, start_sector: u32 }`
- `OleDirectoryReader::new()` + `list_streams(&[u8]) -> Result<Vec<OleStream>, OleError>` — flat scan of first dir sector.

### Macro extraction

- `OleMacro { stream_name, start_sector, raw_preview: Vec<u8>, code_excerpt: String }`
- `OleMacroExtractor::new()` + `extract_macros(&[u8]) -> Vec<OleMacro>` — finds streams whose name starts with `VBA/` (or equals `vbaproject`); reads up to 4096 bytes from start sector and extracts printable ASCII runs (≥4 chars).

### Full CFBF reader (`CfbReader`)

Conforms to MS-CFB; supports v3 (512-byte) and v4 (4096-byte) sectors; mini-stream always 64-byte.

Fields: `sector_size`, `mini_sector_size`, `fat: Vec<u32>`, `mini_fat: Vec<u32>`, `dir_entries: Vec<CfbDirEntry>`, `mini_stream_start: u32`, `mini_stream_cutoff: u32`.

Methods:
- `parse(Vec<u8>) -> Result<Self, CfbError>` — magic, header, DIFAT chain, FAT, mini-FAT, directory chain.
- `read_stream(&CfbDirEntry) -> Result<Vec<u8>, CfbError>` — auto-routes to mini-stream vs regular FAT based on `mini_stream_cutoff`.
- `find_entry(path: &str) -> Option<&CfbDirEntry>` — hierarchical search (`VBA/Module1`), strips optional `Root Entry/`, falls back to flat name match.
- `list_all() -> Vec<(String, &CfbDirEntry)>` — full path enumeration.
- `root_entry() -> Option<&CfbDirEntry>`, `dir_entry_count() -> usize`, `get_dir_entry(sid: u32) -> Option<&CfbDirEntry>`.

`CfbDirEntry { name, entry_type, color: bool, left_sibling, right_sibling, child, clsid: [u8;16], state_bits, created, modified, start_sector, size }` with `is_root/is_storage/is_stream/is_empty`.

### Re-exports (`rtf_parser`)

`CLSID_EQUATION_EDITOR`, `CLSID_PACKAGE`, `Cve201711882Result`,
`EmbeddedShellcode`, `OleObject`, `OleObjectType`, `RtfError`, `RtfLexer`,
`RtfParser`, `RtfStats`, `RtfToken`.

## I/O

- **Input**: in-memory `&[u8]` / `Vec<u8>` (no fs I/O at the library layer; `LoaderInput.data` carries bytes); RTF parser consumes text.
- **Output**: pure-Rust parsed structs (`OleFile`, `CfbReader`, `Vec<OleStream>`, `Vec<OleMacro>`); `LoadResult` with a `BinaryView` for the engine; no stdout/files written.
- **Async surface**: only the two `Loader` trait methods (`load`, `find_nested`); everything else is sync.

## Testability

Extensive in-crate unit tests already cover header parse, sector sizing, directory entries, `OleFile`, loader trait, `OleDirectoryReader`, `OleMacroExtractor`, plus error display variants. Pure-byte-slice API → trivially testable without fixtures (helpers `make_ole_header` / `make_dir_entry` in tests show pattern). The CFBF reader, RTF parser, OOXML extractor, VBA modules expose similarly self-contained constructors.

Path: `C:\Users\Fra\Desktop\RustRE\crates\rustre-loader-ole\src\lib.rs`
