# rustre-hex-template

Binary templates (010 Editor-style) over `rustre-hex::HexBuffer`. Parses raw
bytes into typed, structured `ParsedStruct` trees using declarative templates,
with conditional fields, repeats, expression evaluation, struct extraction,
diffing, export, and a library of built-in format templates.

## Cargo.toml

- Name: `rustre-hex-template` v0.1.0, edition 2024
- Deps: `rustre-hex` (path), `thiserror`, `serde`, `serde_json`, `serde-big-array`
- Workspace lints inherited.

## Modules (`src/lib.rs`)

- `builtin_templates` — collection of pre-built templates registered at startup.
- `template_library` — registry / lookup of templates by name.
- `template_auto_detect` — magic-byte / heuristic format detection.
- `template_composition` — combine and nest sub-templates.
- `template_engine` — top-level apply/parse driver.
- `template_stdlib` — standard library types (with `StdlibError`).
- `template_compiler` — compile textual or structured template definitions.
- `struct_extractor` — extract sub-structs from a parsed tree.
- `template_type_system` — `TypeKind`, `TypeSize`, `Endianness`, `ScalarKind`,
  `StructField`, `BitfieldMember`, `EnumVariant`, `TemplateType`, `TypeRegistry`,
  `StructLayout`; helpers `type_alignment`, `align_offset`, `uint_le/be`,
  `sint_le/be`.
- `template_interpreter` — runtime evaluation of compiled templates.
- `template_expression_eval` — expression evaluator for repeat/condition exprs.

## Public API surface

- Free `pub fn` (top-level, file-scope): **75**
  - lib.rs: 65 · type_system: 5 · compiler: 3 · struct_extractor: 1 · engine: 1
- Method `pub fn` (in `impl`/`trait` blocks): ~303 across all modules.

### Core types (`lib.rs`)

- `enum TemplateError` — `Field`, `Hex(HexError)`, `Condition`, `Serde`,
  `NotFound`, `RecursionLimit`, `FieldRef`.
- `enum Expr` — boolean condition AST over previously-parsed fields:
  `Eq/Ne/Gt/Lt(name, u64)`, `And/Or(Box<Expr>, Box<Expr>)`.
  - `Expr::eval(&self, ctx: &HashMap<String,u64>) -> Result<bool, TemplateError>`.
- `struct Template` — template definition (fields, sub-templates).
- `struct TemplateField` — single parsed field (name, type, offset, value).
- `struct ParsedStruct` — tree of parsed fields produced by applying a template.
- `struct TemplateResult` — output of `apply_*` helpers.
- `struct TemplateStats` — counts/sizes of a template.
- `enum ExportFormat` — for `export_fields`.
- `enum DiffEntry` / `struct FieldDiff` — diff outputs.

### Key free functions (lib.rs)

- `builtin_templates() -> HashMap<String, Template>` — full registry of built-ins.
- `auto_select_template(data: &[u8]) -> Option<Template>` — magic-byte detection.
- `apply_pe_template(data: &[u8]) -> Result<TemplateResult, TemplateError>` —
  convenience PE driver.
- `flatten_parsed(parsed: &ParsedStruct) -> Vec<TemplateField>`.
- `diff_parsed(left, right: &ParsedStruct) -> Vec<DiffEntry>`.
- `diff_parsed_structs(left, right: &ParsedStruct) -> Vec<FieldDiff>`.
- `find_field_by_path(...) -> Option<&TemplateField>`.
- `find_fields_by_name(...) -> Vec<&TemplateField>`.
- `fields_in_range(fields, start, len) -> Vec<&TemplateField>`.
- `template_stats(t: &Template) -> TemplateStats`.
- `export_fields(fields: &[TemplateField], format: ExportFormat) -> String`.

### Built-in template constructors

Each `template_*()` returns `Template`. Format coverage includes:

- Executables: `pe_optional_header`, `pe32plus_optional_header`,
  `pe_section_header`, `pe_import_descriptor`, `pe_export_directory`,
  `pe_tls_directory64`, `pe_debug_directory`, `pe_debug_dir`,
  `pe_load_config`, `pe_rich_header`, `coff_file_header`, `coff_reloc`,
  `coff_reloc_v2`, `coff_string_table`, `ne_header`.
- ELF: `elf32_ehdr`, `elf64_ehdr`, `elf32_phdr`, `elf64_phdr`,
  `elf32_shdr`, `elf64_shdr`, `elf32_sym`, `elf32_sym2`,
  `elf64_sym`, `elf64_sym_v2`, `elf64_rel`, `elf64_rela`,
  `elf64_rela_v2`, `elf64_dyn`, `elf_nhdr`.
- Mach-O: `macho32`, `macho64`, `macho_load_command`, `macho_segment64`,
  `macho_fat_header`, `macho_fat_arch`.
- Containers/media: `zip_local_file_header`, `zip_eocd`, `gif89a`,
  `bmp_header`, `jpeg_jfif`, `jpeg_dqt`, `png_chunk`, `riff_chunk`, `wav`,
  `mp4_box`, `aiff_header`.
- Misc: `dwarf_cie`, `dwarf_fde`, `dotnet_metadata_sig`, `dex_header`,
  `oat_magic`, `wasm_section`, `java_class_header`.

### Type system module (`template_type_system`)

- `TypeKind`, `TypeSize`, `Endianness`, `ScalarKind`, `TemplateType`,
  `TypeRegistry`, `StructLayout`, `StructField`, `BitfieldMember`,
  `EnumVariant`.
- `type_alignment(&TypeKind) -> usize`, `align_offset(off, align) -> usize`.
- Convenience constructors: `uint_le(bytes)`, `uint_be(bytes)`,
  `sint_le(bytes)`, `sint_be(bytes)`.

### Stdlib module

- `enum StdlibError` — error variants for stdlib operations.

## I/O & behavior

- **Input**: raw byte slices `&[u8]` and/or `rustre_hex::HexBuffer`; a
  `Template` (constructed from a built-in or user-defined).
- **Processing**: linear walk over fields; reads typed values via
  `rustre-hex` (`DataType`, `Encoding`, `TypedValue`); evaluates `Expr`
  conditions against a map of prior `u64`-coerced field values; resolves
  repeats via expression eval; recursion bounded (`RecursionLimit`).
- **Output**: `ParsedStruct` tree of named `TemplateField`s with offsets and
  typed values; helpers flatten, diff, locate by name/path/range, and export
  (multiple `ExportFormat`s).
- **Auto-detection**: `auto_select_template` inspects magic bytes to pick a
  built-in template; `apply_pe_template` is a one-shot PE convenience.
- **Errors**: all fallible APIs return `Result<_, TemplateError>` (or
  `StdlibError` in the stdlib module). Underlying `HexError` is wrapped.

## Tests

- `tests/blitz.rs`, `tests/blitz2.rs` — integration tests covering apply,
  parse, diff, and built-in templates. Crate is testable via `cargo test
  -p rustre-hex-template`.

## Notes

- `serde` derives throughout enable JSON serialization of templates and
  parsed trees (used by `export_fields`).
- `serde-big-array` is pulled in for large fixed-size arrays in built-in
  format headers.
