# rustre-symbols

Unified symbol types, providers and infrastructure (spec §7: cross-format symbol unification across PDB, DWARF, CodeView, STABS, FLIRT, PE/ELF tables).

## Cargo.toml

- **package**: `rustre-symbols` v0.1.0, edition 2024
- **license / description / repository / readme / keywords / categories / authors**: inherited from workspace
- **dependencies**:
  - `parking_lot`, `serde`, `serde_json`, `thiserror`, `anyhow` (workspace)
  - `regex = "1"`
  - `rustre-loader-pe` (path: `../rustre-loader-pe`)
- **dev-dependencies**: `tempfile` (workspace)
- **lints**: workspace
- **Note**: sub-crate path-deps removed to break workspace cycle. The `rustre-symbols-*` provider sub-crates depend UP on this crate for shared `SymbolProvider`/`Symbol` types. Consumers depend on each sub-crate directly.

## Module map (`src/lib.rs`)

Public modules:
- `codeview_provider`, `dwarf_provider`, `elf_provider`, `pdb_provider`, `stabs_provider`
- `symbol_cross_ref`, `symbol_demangler`, `symbol_merger`, `symbol_resolution`
- `symbol_table_builder`, `symbol_exporter`, `symbol_importer`, `symbol_search`
- `symbol_versioning`, `symbol_address_resolver`, `symbol_enrichment`
- `pdb_discovery` (re-export: `discover_pdb_for_binary`)
- `backends` (descriptor registry for wired sub-crates)

## Public API (lib.rs)

### Error type
- `enum SymbolError`: `NotFound`, `AddressNotFound`, `Duplicate`, `Parse`, `Io`, `Other` (impl `From<anyhow::Error>`)

### Enums / taxonomy
- **Legacy low-level**: `SymKind` (Function, Data, Label, Section, File, Type, Namespace, TLS, IFunc, Common, Unknown)
- `SymbolBinding` (Local, Global, Weak, GnuUnique); alias `SymVisibility = SymbolBinding`
- `SymbolVisibility` (Default, Hidden, Protected, Internal)
- `LegacySymbolSource` (Export, Import, Debug, Synthetic, User)
- **Spec §7**: `SymbolKind` (Function, Variable, Label, Thunk, Import, Export, Section, Module, Namespace)
- `SymbolSource` (Pdb, Dwarf, CodeView, Stabs, Flirt, Manual, Inferred, Import, Export, Elf, Pe, Ai) — with `priority() -> u8`
- `ConflictStrategy` (PreferDebug, PreferExport, KeepFirst, KeepLast, KeepAll)

### Core records
- `struct Symbol` (low-level canonical): `id, name, demangled_name, address, size, kind, binding, visibility, section_index, file_offset, source, source_file, source_line, ordinal, tags`
  - `new`, `display_name`, `end_address`, `contains`, `is_function`, `is_data`, `set_demangled`, `add_tag`, `function_boundary`
- `struct UnifiedSymbol` (spec §7): `name, demangled_name, address, size, kind, source, is_external, module, type_id`
  - `new`, `display_name`, `end_address`
- `struct FunctionBoundary { start, end, name }`: `new`, `size`, `contains`, `overlaps`
- `enum TypeInfo` (Void, Bool, Int, Float, Pointer, Array, Struct, Enum, Function, Named, Unknown)
- `struct StructField { name, offset, type_info }`
- `struct SourceLocation { file, line, column }`

### Trait
- `trait SymbolProvider: Send + Sync + Debug`
  - `name`, `lookup_name`, `lookup_address`, `lookup_nearest`, `all_symbols`, `all_functions`, `source_line_for_address`

### Containers
- `struct SymbolTable` — provider aggregator with address cache
  - `new`, `add_provider`, `lookup_name`, `lookup_address`, `lookup_nearest`, `all_symbols`, `provider_count`, `clear_cache`, `stats`
- `struct InMemorySymbolProvider` — simple `Vec<Symbol>` backend implementing `SymbolProvider`
  - `new`, `add`, `len`, `is_empty`, `remove_by_name`, `sort_by_address`, `rename`
- `struct SymbolFilter` — fluent builder
  - `new`, `address_min`, `address_max`, `address_range`, `kinds`, `name_prefix`, `sources`, `section_index`, `max`, `apply`
- `struct AddressToSymbolMap` — sorted binary-search reverse lookup
  - `new`, `from_symbols`, `insert`, `sort`, `lookup_exact`, `lookup_floor`, `len`, `is_empty`, `all_symbols`
- `struct SymbolCache` — bounded LRU
  - `new`, `insert`, `get`, `len`, `is_empty`, `clear`, `capacity`
- `struct SymbolStore` — BTreeMap<addr,Vec<Symbol>> + name index
  - `new`, `insert` (errors on dup), `upsert`, `remove`, `find_by_addr`, `find_by_name`, `find_by_prefix`, `find_in_range`, `rename`, `merge`, `len`, `is_empty`, `iter`, `stats`, `get_floor`, `export_as_map`, `export_as_csv`
- `struct UnifiedSymbolTable` (spec §7) — BTreeMap<addr,Vec<UnifiedSymbol>> + name index
  - `new`, `add`, `remove`, `lookup_addr`, `lookup_addr_all`, `lookup_name`, `find_by_prefix`, `find_in_range`, `nearest_below`, `rename`, `len`, `is_empty`, `iter_by_address`, `merge`, `add_or_upgrade`
- `struct ExportTable`: `from_symbols`, `exports`, `by_ordinal`, `by_name`, `len`, `is_empty`
- `struct ImportTable`: `from_symbols`, `imports`, `by_name`, `len`, `is_empty`, `grouped_by_module`
- `struct SectionSymbols`: `from_symbols`, `in_section`, `section_count`
- `struct SymbolStats { functions, data, labels, sections, files, types, tls, ifunc, common, unknown, total }`: `from_symbols`, `from_symbols_iter`

### Resolution / merging / export
- `struct SymbolConflictResolver`: `new(strategy)`, `resolve`
- `struct SymbolResolver`: `new`, `add_provider`, `resolve_name`, `resolve_address`, `resolve_nearest`, `all_symbols`, `provider_count`
- `struct DebugSymbolMerger`: `new`, `merge`, `finish`, `len`, `is_empty`
- `struct SymbolExporter` (associated fns): `to_json` (Result), `to_csv`, `to_idc` (IDA IDC script), `to_map`

### Backends registry (`mod backends`)
- `struct BackendDescriptor { crate_name, format, provider_type }`
- `fn registry() -> Vec<BackendDescriptor>` — enumerates wired sub-crates: `rustre-symbols-codeview`, `-dwarf`, `-pdb`, `-stabs`

### Re-exports
- `pub use pdb_discovery::discover_pdb_for_binary;`
- `pub use std::path::Path;`

## Submodules (high level)

Each `*_provider.rs` (`codeview`, `dwarf`, `elf`, `pdb`, `stabs`) implements `SymbolProvider` for its respective debug format. Additional infrastructure modules: `symbol_demangler` (`DemanglerPipeline`), `symbol_merger`, `symbol_resolution`, `symbol_table_builder`, `symbol_exporter`, `symbol_importer`, `symbol_search`, `symbol_versioning`, `symbol_address_resolver`, `symbol_enrichment`, `symbol_cross_ref`, `pdb_discovery`.

## Notes

- The crate truncated reading at line 1670 of ~2870 in `lib.rs`; this report documents the principal public surface. Remaining content includes `SyntheticSymbolGen`, `DemanglerPipeline`, and trait re-exports / tests (per the module-level rustdoc summary at top of file).
- Testable: the crate exposes constructors (`new`/`default`) and pure functions (`apply`, `resolve`, `from_symbols`, exporters) suited for unit testing without binaries; provider modules require fixtures.
