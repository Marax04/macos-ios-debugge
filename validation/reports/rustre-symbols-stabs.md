# rustre-symbols-stabs

STABS debug format parser for ELF `.stab` / `.stabstr` sections (legacy Unix/GCC).
Supports `N_FUN`, `N_GSYM`, `N_STSYM`, `N_SO`, `N_SOL`, `N_SLINE`, `N_LSYM`, `N_RSYM`,
`N_PSYM`, type descriptor parsing, struct/union/enum reconstruction, and line-number tables.

## Cargo.toml

- **name**: `rustre-symbols-stabs` v0.1.0, edition 2024
- **dependencies**: `rustre-symbols`, `rustre-core`, `serde`, `thiserror`, `anyhow`, `goblin`
- **dev-dependencies**: `serde_json`
- Workspace inherits: license, description, repository, readme, keywords, categories, authors, lints

## Modules

`stabs_cfparser`, `stabs_complete`, `stabs_full_parser`, `stabs_line_info`, `stabs_lineinfo`,
`stabs_reconstruct`, `stabs_type_reconstructor`, `stabs_types`, `xcoff_stabs`, `stabs_parser`,
`stabs_type_decoder`, `stabs_to_dwarf`, `stabs_type_parser`, `stabs_scope_tracker`,
`stabs_source_mapper`, `stabs_type_resolver`, `stabs_to_dwarf_converter`.

## Public API (lib.rs)

### Error

- `enum StabsError` — `InvalidRecord(usize)`, `StringTable(String)`, `Parse(String)`, `TypeParse(String)`.

### `StabType` (enum, repr(u8))

Canonical `n_type` codes (`NUndf`=0x00 … `NNblcs`=0xF8, `Unknown`=0xFF).

- `pub const fn from_u8(v: u8) -> Self`
- `pub const fn is_symbol(&self) -> bool`
- `pub const fn is_source_file(&self) -> bool`
- `pub const fn is_line_number(&self) -> bool`
- `pub const fn is_scope_bracket(&self) -> bool`
- `pub const fn category(&self) -> &'static str`
- `pub const fn name_for(b: u8) -> Option<&'static str>` — `N_`-prefixed canonical name
- `pub fn name(&self) -> &'static str`
- Implements `Display`.

### `StabRecord` (12-byte on-disk record)

Fields: `strx: u32`, `stab_type: StabType`, `other: u8`, `desc: u16`, `value: u32`, `string: String`.

- `pub fn parse_all(stab_data: &[u8], stabstr: &[u8]) -> Vec<Self>` (little-endian)
- `pub fn parse_all_be(stab_data: &[u8], stabstr: &[u8]) -> Vec<Self>` (big-endian)
- `pub fn symbol_name(&self) -> &str`
- `pub fn type_descriptor(&self) -> &str`
- `pub const fn has_string(&self) -> bool`
- Implements `Display`.

### `StabTypeCode` (enum)

Type descriptor codes: `Function`, `GlobalFunction`, `GlobalVar`, `StaticVar`, `RegisterVar`,
`Parameter`, `Typedef`, `Tag`, `VarArray`, `Other(char)`.

- `pub const fn from_char(c: char) -> Self`
- Implements `Display`.

### `StabsTypeParser`

Minimal type descriptor parser producing `rustre_symbols::TypeInfo`.

- `pub fn new() -> Self` — preloads GCC primitive type indices
- `pub fn register(&mut self, type_num: String, info: TypeInfo)`
- `pub fn lookup(&self, type_num: &str) -> Option<&TypeInfo>`
- `pub fn len(&self) -> usize`
- `pub fn is_empty(&self) -> bool`
- `pub fn parse_descriptor(&self, desc: &str) -> Result<TypeInfo, StabsError>` — handles `(n,m)`, `*T`, `ar...`, `s...`, `e...`
- Implements `Default`.

### Line tables

- `struct LineEntry { address: u64, line: u32, file: String }` + `Display`.
- `struct LineNumberTable` (default empty):
  - `pub fn new()`, `pub fn add(LineEntry)`, `pub fn sort()`
  - `pub fn lookup(&self, addr: u64) -> Option<&LineEntry>` — binary search
  - `pub const fn len()`, `pub const fn is_empty()`, `pub fn entries() -> &[LineEntry]`

### Function metadata

- `struct FunctionInfo { name, address: u64, source_file, locals: Vec<LocalVarInfo>, parameters: Vec<ParameterInfo>, start_line: u32 }` + `Display`.
- `struct LocalVarInfo { name, fp_offset: i32, type_desc }`.
- `struct ParameterInfo { name, offset: i32, type_desc }`.

### `StabsParser` (high-level)

Builds functions, globals, line tables from records.

- `pub fn new() -> Self`
- `pub fn process(&mut self, records: &[StabRecord], image_base: u64) -> Result<(), StabsError>`
- `pub fn functions(&self) -> &[FunctionInfo]`
- `pub fn globals(&self) -> &[Symbol]`
- `pub const fn line_table(&self) -> &LineNumberTable`
- `pub fn all_symbols(&self) -> Vec<Symbol>`
- `pub const fn type_parser(&self) -> &StabsTypeParser`
- `pub const fn type_parser_mut(&mut self) -> &mut StabsTypeParser`
- Implements `Default`.

### `StabsProvider` — `SymbolProvider` impl

- `pub fn from_records(records: &[StabRecord], image_base: u64) -> Self`
- `pub fn from_bytes(stab_data: &[u8], stabstr: &[u8], image_base: u64) -> Self`
- `pub const fn symbol_count(&self) -> usize`
- `pub const fn source_map_len(&self) -> usize`
- `pub fn symbols_sorted(&self) -> Vec<Symbol>`
- `pub fn symbols_of_kind(&self, kind: SymKind) -> Vec<Symbol>`
- `pub fn symbols_with_prefix(&self, prefix: &str) -> Vec<Symbol>`
- `SymbolProvider`: `name`, `lookup_name`, `lookup_address`, `lookup_nearest`, `all_symbols`, `all_functions`, `source_line_for_address`.

### `StabsStringTable`

- `pub fn new()`, `Default`
- `pub fn intern(&mut self, s: &str) -> u32`
- `pub fn get(&self, offset: u32) -> &str`
- `pub fn as_bytes(&self) -> &[u8]`
- `pub const fn len()`, `pub const fn is_empty()`

### `StabsType` (alt enum, no `N_` prefix)

Variants `GSYM`, `FNAME`, `FUN`, `STSYM`, … `LENG`, `Unknown`.

- `pub const fn from_u8(v: u8) -> Self`
- Implements `Display`.

### `StabsEntry`

Raw 12-byte entry: `n_strx: u32`, `n_type: u8`, `n_other: u8`, `n_desc: i16`, `n_value: u32`, `string_value: String`.

- `pub const fn stabs_type(&self) -> StabsType`
- `pub fn symbol_name(&self) -> &str`
- `pub fn type_descriptor(&self) -> &str`
- Implements `Display`.

### `StabsLowParser`

- `pub fn parse(stab_data: &[u8], stabstr_data: &[u8]) -> anyhow::Result<Vec<StabsEntry>>`
- `pub fn parse_from_elf(elf_data: &[u8]) -> anyhow::Result<Vec<StabsEntry>>` — goblin-based section locator

### Extraction results

- `struct StabsFunction { name, addr: u32, source_file: Option<String> }` + `Display`.
- `struct StabsLine { addr: u32, line_no: u16, function: Option<String> }` + `Display`.

## Notes

- All major types derive `Serialize`/`Deserialize` for JSON dumping.
- Dev-dep `serde_json` indicates serialization round-trip tests are feasible.
- Both LE and BE record parsing supported.
- Multiple module names suggest several parallel implementations (full/cf/complete/reconstruct).
