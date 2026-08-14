# rustre-symbols-codeview

CodeView debug format parser. Supports CV 4.0/7.0 symbol records, type records (TPI), PDB 7.0 stream layout, CV8 line tables, source file tables, and a `SymbolProvider` implementation.

## Cargo.toml

```toml
[package]
name = "rustre-symbols-codeview"
version = "0.1.0"
edition = "2024"
license.workspace = true
description.workspace = true
repository.workspace = true
readme.workspace = true
keywords.workspace = true
categories.workspace = true
authors.workspace = true

[dependencies]
rustre-symbols = { path = "../rustre-symbols" }
anyhow = { workspace = true }
serde = { workspace = true }
thiserror = { workspace = true }

[lints]
workspace = true
```

## Module map (`src/lib.rs`)

- `casts` — narrowing helpers
- `codeview_parser` — high-level parser entry points
- `cv_function_info` — function metadata
- `cv_lineinfo` — line-number info
- `cv_stream_parser` — PDB stream parser
- `cv_symbol_records` — symbol record types
- `cv_symbols` — symbol structures
- `cv_type_records` — type record types
- `cv_types` — type structures
- `codeview_type_parser` — TPI parser
- `codeview_symbol_parser` — symbol parser
- `pdb_tpi_reader` — PDB TPI stream reader
- `codeview_types` — shared type aliases

## Public API (from `lib.rs`)

### Errors

- `enum CodeViewError`: `InvalidSignature(u32)`, `UnsupportedVersion(u32)`, `RecordTooShort`, `TruncatedStream`, `InvalidRecord`, `TypeIndexOob(u32)`, `StringOffsetOob(u32)`, `Parse(String)`.

### Signatures / kinds

- `enum CvSignature` { Cv41, Cv50, Cv70, Pdb70, Cv8 }
  - `pub fn from_bytes(b: &[u8]) -> Option<Self>`
  - `pub const fn as_str(&self) -> &'static str`
- `enum CvSymKind` (u16-repr): Pub32, GProc32, LProc32, RegRel32, GData32, LData32, Label32, Thunk32, Block32, End, Local, Compile3, InlineSite, InlineSiteEnd, Unknown.
  - `pub const fn from_u16(v: u16) -> Self`
  - `pub const fn is_named_address(&self) -> bool`
  - `pub const fn is_function(&self) -> bool`
  - `pub const fn is_data(&self) -> bool`
- `enum CvTypeKind` (u16-repr): Modifier, Pointer, Array, Class, Structure, Union, Enum, Procedure, MFunction, Arglist, FieldList, Bitfield, Member, Enumerate, Unknown.
  - `pub const fn from_u16(v: u16) -> Self`
- `enum Cv8SubsectionKind`: Symbols, Lines, StringTable, FileChecksums, FrameData, InlineeLines, CrossScopeImports, CrossScopeExports, Unknown(u32).
  - `pub const fn from_u32(v: u32) -> Self`
- `enum CodeViewMagic` { Cv41, Cv50, Cv70 } — constants `CV41_TAG`, `CV50_TAG`, `CV70_TAG`.
  - `pub fn detect(data: &[u8]) -> Option<Self>`
  - `pub const fn label(&self) -> &'static str`

### Records

- `struct CvSymbol { kind, offset, segment, name, type_index, flags }`
  - `pub const fn is_function(&self) -> bool`
  - `pub const fn is_data(&self) -> bool`
- `struct CvTypeRecord { kind, index, name, size, count, underlying_type, return_type, arg_types }`
  - `pub const fn is_aggregate(&self) -> bool`
  - `pub const fn is_callable(&self) -> bool`
- `struct CvLineEntry { offset, line_start, is_statement }`
- `struct CvSourceFile { name_offset, name, checksum }`
- `struct Cv8LineBlock { code_offset, segment, code_len, file_index, lines }`

### Parsers

- `pub fn parse_cv_symbols(data: &[u8]) -> Result<Vec<CvSymbol>, CodeViewError>`
- `pub fn parse_cv_type_records(data: &[u8]) -> Result<Vec<CvTypeRecord>, CodeViewError>`
- `pub fn parse_cv8_lines(data: &[u8]) -> Result<Vec<Cv8LineBlock>, CodeViewError>`
- `pub fn primitive_type(index: u32) -> TypeInfo`

### Type table

- `struct CvTypeTable`
  - `pub fn new() -> Self`
  - `pub fn from_records(records: Vec<CvTypeRecord>) -> Self`
  - `pub fn from_bytes(data: &[u8]) -> Result<Self, CodeViewError>`
  - `pub fn lookup(&self, index: u32) -> Option<&CvTypeRecord>`
  - `pub fn records(&self) -> &[CvTypeRecord]`
  - `pub const fn len(&self) -> usize`
  - `pub const fn is_empty(&self) -> bool`
  - `pub fn to_type_info(&self, index: u32) -> TypeInfo`

### String table

- `struct CvStringTable`
  - `pub fn from_bytes(data: &[u8]) -> Self`
  - `pub fn get(&self, offset: u32) -> &str`
  - `pub const fn len(&self) -> usize`
  - `pub const fn is_empty(&self) -> bool`

### Debug section

- `struct CvDebugSection { symbols, line_blocks, string_table, source_files }`
  - `pub fn parse(data: &[u8]) -> Result<Self, CodeViewError>`

### SymbolProvider

- `struct CodeViewProvider` implementing `rustre_symbols::SymbolProvider`.
  - `pub fn from_bytes(data: &[u8], image_base: u64) -> Result<Self, CodeViewError>`
  - `pub fn from_debug_section(data: &[u8], image_base: u64) -> Result<Self, CodeViewError>`
  - `pub fn with_type_table(self, table: CvTypeTable) -> Self`
  - `pub fn raw_symbols(&self) -> &[CvSymbol]`
  - `pub const fn type_table(&self) -> &CvTypeTable`
  - `pub const fn symbol_count(&self) -> usize`
  - `pub fn functions(&self) -> Vec<&Symbol>`
  - `pub fn data_symbols(&self) -> Vec<&Symbol>`
  - `pub fn symbols_sorted(&self) -> Vec<Symbol>`
  - `pub fn symbols_with_prefix(&self, prefix: &str) -> Vec<Symbol>`
  - `pub fn resolve_type(&self, index: u32) -> TypeInfo`
  - SymbolProvider: `name`, `lookup_name`, `lookup_address`, `lookup_nearest`, `all_symbols`, `all_functions`, `source_line_for_address`.

### Filter / test builders

- `struct CvSymbolFilter`
  - `pub const fn new(symbols: Vec<CvSymbol>) -> Self`
  - `pub fn by_kind(self, kind: CvSymKind) -> Self`
  - `pub fn name_contains(self, substr: &str) -> Self`
  - `pub fn in_segment(self, seg: u16) -> Self`
  - `pub fn into_symbols(self) -> Vec<CvSymbol>`
  - `pub const fn count(&self) -> usize`
- `pub fn build_test_gproc32(name, offset, seg, type_index) -> Vec<u8>`
- `pub fn build_test_lproc32(name, offset) -> Vec<u8>`
- `pub fn build_test_pub32(name, offset) -> Vec<u8>`
- `pub fn build_test_gdata32(name, offset, type_index) -> Vec<u8>`

## Notes

- `CvTypeTable::to_type_info` for aggregates without LF_FIELDLIST data is a lossy fallback: field offsets are computed by integer division of struct size by member count and field types are `TypeInfo::Unknown`. Use the LF_FIELDLIST parser when available.
- Additional public items live in the submodules (`codeview_parser`, `codeview_symbol_parser`, `codeview_type_parser`, `pdb_tpi_reader`, `cv_*`); only the root `lib.rs` API is enumerated here.
- Testable: yes — pure parsing functions plus `build_test_*` helpers make unit testing possible without PDB files.
