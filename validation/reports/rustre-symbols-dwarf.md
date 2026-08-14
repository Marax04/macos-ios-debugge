# rustre-symbols-dwarf

DWARF debug-information reader implemented as a pure-Rust parser. Parses `.debug_info`, `.debug_abbrev`, `.debug_str`, `.debug_line`, `.debug_ranges` from ELF (Mach-O planned) binaries. Supports DWARF 4/5 compilation units, subprograms, variables, parameters, base/pointer/typedef/struct/union/array types, line program state machine, and location expressions.

## Cargo.toml

- **name**: `rustre-symbols-dwarf` v0.1.0, edition 2024
- **dependencies**: `rustre-symbols` (path), `thiserror`, `serde`, `gimli`, `object` (workspace)
- **dev-dependencies**: `serde_json`
- Lints: workspace; license/description/repo/readme/keywords/categories/authors inherited

## Public modules

`casts`, `dwarf_abbrev`, `dwarf_call_frame`, `dwarf_expression_evaluator`, `dwarf_line_program`, `dwarf_location_expr`, `dwarf_type_decoder`, `dwarf_type_parser`, `dwarf_type_reader`, `dwarf_unwind`, `line_program`, `location_expr`, `split_dwarf`, `type_units`.

## Public API (lib.rs)

### Error / Result
- `enum DwarfError`: `Io(io::Error)`, `UnsupportedFormat`, `MalformedDwarf`, `SectionMissing(String)`, `UnexpectedEof`
- `type Result<T> = std::result::Result<T, DwarfError>`

### Data types (Serialize/Deserialize)
- `enum DwarfLocation`: `Register(u32)`, `MemoryOffset { register, offset }`, `Constant(u64)`, `Unknown`
- `struct DwarfVariable { name, type_name, location }`
- `struct DwarfFunction { name, low_pc, high_pc, parameters, return_type }`
- `struct DwarfType { name, byte_size, tag }`
- `enum DwarfTypeTag`: `Base`, `Pointer`, `Typedef`, `Struct`, `Union`, `Array`, `Other`
- `struct LineEntry { address, file, line, column }`

### `DwarfReader`
- `pub fn open(path: &Path) -> Result<Self>` — read ELF from disk and parse DWARF sections.
- `pub fn from_bytes(raw: &[u8]) -> Result<Self>` — parse from in-memory ELF.
- `pub const fn from_sections(sections: HashMap<String, Vec<u8>>) -> Self` — build from pre-extracted sections (testing).
- `pub fn functions(&self) -> Vec<DwarfFunction>` — all `DW_TAG_subprogram` entries.
- `pub fn variables(&self) -> Vec<DwarfVariable>` — top-level variables/parameters.
- `pub fn types(&self) -> Vec<DwarfType>` — all type DIEs.
- `pub fn line_info(&self) -> Vec<LineEntry>` — rows from the `.debug_line` state machine.

## Notable submodule API highlights

- `type_units`: `TypeUnitHeader`, `parse_type_unit_header`, `TypeUnit`, `TypeSignatureIndex`, `find_type_by_signature`.
- `split_dwarf`: `SplitDwarfError`, `DwoSection`, `DwoFile`, `SkeletonUnit`, `DwpEntry`, `DwpPackage`, `DwoResolver`, `resolve_dwo_path`.
- `location_expr`: `ExprError`, `dw_op_name`, `LocationResult`, `LocationPiece` (and an expression evaluator across `dwarf_expression_evaluator`).
- `dwarf_call_frame` / `dwarf_unwind`: CFI/unwind-info parsing.
- `dwarf_line_program` / `line_program`: alternate line-program implementations.
- `dwarf_type_*`: type DIE decoding/parsing/reading helpers.
- `casts`: numeric cast helpers.

## Notes

- Two `unsafe` blocks are documented in `lib.rs` (gimli `Dwarf<EndianSlice<'static>>` lifetime forging over an owned `Box<[u8]>` buffer; drop order enforced).
- Workspace lint `unsafe_code = "warn"` is acknowledged with `#![allow(unsafe_code)]` at crate scope.
- ELF support is little-endian only (32/64-bit). Mach-O extraction not yet implemented in the in-tree section extractor.

## Testability

Yes — testable. `from_bytes` and `from_sections` allow unit tests without disk I/O; an in-file `#[cfg(test)] mod tests` constructs synthetic abbrev/DIE/line-program bytes via helpers (`abbrev_entry`, `encode_uleb`, `encode_sleb`). `serde_json` is a dev-dependency for serialization round-trips.
