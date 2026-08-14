# rustre-symbols-pdb — Crate Analysis

## Purpose
Pure-Rust reader for Microsoft PDB (Program Database) files. Parses the MSF v7 container, the PDB Info / DBI / TPI / GSI / PSI streams and per-module CodeView symbol sub-streams to expose symbols (functions / data / labels / thunks), modules, types, line-info, OMAP RVA translation, and PDB GUID/Age metadata. Used by RustRE to recover names for stripped PE binaries that ship a sibling `.pdb`.

## Top-level public API (lib.rs — main façade)

### Types
- `PdbError` (enum) — error variants (BadMagic, UnsupportedVersion, StreamOutOfRange, CorruptData, StreamTooShort, Io).
- `SymbolKind` — Function / Data / Label / Thunk.
- `PdbSymbol { name, address, size, kind }` — flat symbol record (address is the raw section-relative offset from the PUB32/PROC32 record).
- `TypeKind` — Struct/Union/Enum/Primitive/Pointer/Array/Function.
- `PdbType { name, kind, size }` — TPI record.
- `PdbModule { name, object_file, stream_index }` — DBI module-info entry.
- `PdbModuleProc { name, segment, code_offset, code_size }` — per-module S_*PROC32 record.
- `PdbGuid { data: [u8;16] }` + `to_string_fmt()` — `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` GUID rendering.
- `PdbAge(u32)`.
- `PdbStreamInfo { version, signature, age, guid }`.
- `ResolvedSymbol`, `PdbPublicSymbol`.

### Public functions / methods

| Function | Inputs | Output | Behavior | Verifiable ground truth |
|---|---|---|---|---|
| `PdbReader::open(path)` | filesystem path to a `.pdb` | `Result<PdbReader>` | Reads file, parses MSF v7 superblock and stream directory | A valid Microsoft PDB returns Ok; junk bytes return `BadMagic` |
| `PdbReader::from_bytes(raw)` | byte slice | `Result<PdbReader>` | Same as `open` but in-memory | Same |
| `PdbReader::guid()` | self | `PdbGuid` | Returns 16-byte signature GUID from PDB Info stream | Equal to GUID printed by `llvm-pdbutil dump --summary file.pdb` |
| `PdbReader::age()` | self | `PdbAge` | Returns Age counter from PDB Info stream | Equal to llvm-pdbutil age |
| `PdbReader::symbols()` | self | `Vec<PdbSymbol>` | Walks global symbol stream parsing S_PUB32/S_GPROC32/S_LPROC32/S_GDATA32/S_LDATA32/S_LABEL32/S_THUNK32 | Names and section-relative offsets equal to `llvm-pdbutil dump --globals --publics` |
| `PdbReader::symbols_with_segment()` | self | `Vec<(segment, offset, name, kind)>` | Same as `symbols` but keeps 1-based PE section index for VA lift | Section indices ∈ 1..=#PE sections |
| `PdbReader::types()` | self | `Vec<PdbType>` | Parses TPI stream (LF_STRUCTURE/CLASS/UNION/ENUM/POINTER/ARRAY/PROCEDURE + primitives) | Count and named types match llvm-pdbutil `dump --types` |
| `PdbReader::modules()` | self | `Vec<PdbModule>` | Returns DBI module-info entries (compiland name + object file) | Equal to llvm-pdbutil `dump --modules` |
| `PdbReader::module_proc_symbols()` | self | `Vec<PdbModuleProc>` | Walks every per-module symbol sub-stream extracting S_GPROC32/S_LPROC32/S_*PROC32_ID/S_THUNK32 — the path that recovers Rust release-build function names | Names should be superset of `llvm-pdbutil dump --module-syms` proc records |
| `PdbGuid::to_string_fmt()` | self | `String` | Formats as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` | Length is always 38; matches GUID printed by Microsoft tooling |
| `PdbStreamReader::parse_pdb_info(bytes)` | raw PDB bytes | `Option<PdbStreamInfo>` | Reads stream 1 fields (version/signature/age/guid) without building full reader | Equal to llvm-pdbutil summary |
| `PdbStreamReader::parse_named_stream_map(bytes)` (in pdb_stream_parser) | bytes | `HashMap<name, idx>` | Returns named stream table from Info stream | `/names`, `/LinkInfo` indices match llvm-pdbutil named streams |
| `PdbPublicSymbolScanner::scan_public_symbols(bytes)` | raw PDB bytes | `Vec<PdbPublicSymbol>` | Stand-alone scanner enumerating S_PUB32 records in the public symbol stream | Count equals `llvm-pdbutil dump --publics` |
| `resolve_name_for_address(pdb_bytes, section_table, va)` | bytes + PE section table + VA | `Option<ResolvedSymbol>` | Looks up the symbol whose lifted VA equals `va` | Returns same name IDA Pro shows at that VA |

### Submodule public surface (selected)
- `build_info::parse_build_info(stream)` → `Vec<BuildInfo>` (compiler invocations, args, source paths).
- `global_symbols::parse_global_symbols(data)` → `Vec<GlobalSymbol>` (richer S_PUB32/GDATA32 parser with flags).
- `gsi_stream::GsiHashTable`, `PsiStream` — GSI/PSI hash-bucket parsers.
- `line_info::parse_line_info(...)`, `line_info::lookup_line(records, rva)` — C13 line records and address→source line lookup.
- `module_symbols::parse_module_symbols(data)` → `ModuleSymbols` (procs, locals, frame layout, lexical blocks, inline sites); `collect_proc_names`, `find_proc_at`, `param_count`.
- `pdb_dbi_reader::DbiReader`, `pdb_dbi_stream::parse_module_info`, `parse_section_contributions`, `parse_section_map`, `parse_source_file_table`, `scan_module_compile_flags`.
- `pdb_gsi::collect_all_pub_symbols(sym_data)`, `collect_global_data`, `gsi_summary`, `GlobalSymbolIndex`, `PublicSymbolIndex`.
- `pdb_line_info::split_c13_subsections`, `parse_file_checksums`, `parse_lines_subsection`, `parse_inline_lines`, `LineInfoDatabase`.
- `pdb_omap::translate_rva(raw, rva)` — apply OMAP_FROM_SRC to map pre-rebase RVA → final RVA.
- `pdb_publics_reader::PublicsReader`, `parse_sym_records`.
- `pdb_source_lines::SourceLinesReader`.
- `pdb_stream_parser::MsfParser`, `MsfSummary`, `PdbInfoStream`, `parse_named_stream_map`.
- `pdb_symbol_info::parse_module_info`, `parse_section_contribs`, `ProcSymbol`, S_* CodeView record-type constants.
- `pdb_type_info`, `tpi_types`, `type_info` — TPI leaf/primitive helpers.
- `section_contributions` — DBI section-contribution table.
- `stream_reader` — generic MSF stream byte reader.

## Existing MCP tools (in `rustre-mcp-tools/src/wire_tools.rs`)
- `symbols_pdb_load` (`SymbolsPdbLoadTool`, line ~2738) — locates the sibling `.pdb` for a PE on disk, resolves every PDB symbol to its final image VA (lifting `S_PROC32` segment+offset through the PE section table and PDB OMAP), returns a `{va → name}` map. Used as the canonical naming source for stripped Rust release builds.
- `decompile_function_path` (line ~2422) — internal helper `build_pdb_symbol_map` reuses `PdbReader::open` + `PdbPublicSymbolScanner::scan_public_symbols` + `module_proc_symbols` to rewrite `sub_<HEX>` placeholders in decompiled output with PDB names.
- `analyze_full` flow (line ~4818) — sibling PDB merge using `PdbReader` and `SymbolKind::{Function,Thunk}` filtering to feed the function detector.

No dedicated MCP tools wrap: `types()`, `modules()`, `build_info`, `line_info`/`pdb_line_info` (source line lookup), `pdb_omap::translate_rva`, `gsi_summary`. These are exposed only indirectly through aggregate tools.

## Testable functions (externally verifiable ground truth)

Given a real Microsoft-produced PDB (e.g. `cargo-zyphora.pdb`) and `llvm-pdbutil` / IDA as oracle:

1. `PdbStreamReader::parse_pdb_info(bytes).guid/age/signature` ⇔ `llvm-pdbutil dump --summary file.pdb` (GUID, Age, Signature).
2. `PdbReader::guid().to_string_fmt()` ⇔ same GUID string Microsoft `mspdbcmf` / IDA shows.
3. `PdbReader::symbols()` count and per-record (name, section-relative offset) ⇔ `llvm-pdbutil dump --publics --globals` records.
4. `PdbPublicSymbolScanner::scan_public_symbols(bytes)` count ⇔ `llvm-pdbutil dump --publics` symbol count.
5. `PdbReader::modules()` list ⇔ `llvm-pdbutil dump --modules`.
6. `PdbReader::module_proc_symbols()` set of `(name, segment, code_offset, code_size)` ⇔ union of all `llvm-pdbutil dump --module-syms` S_GPROC32/S_LPROC32 records. For the IDA baseline (`cargo-zyphora.exe`, 1456 funcs / 395 named), the lifted VAs must include the 395 IDA names.
7. `PdbReader::types()` count and Struct/Enum names ⇔ `llvm-pdbutil dump --types` named records.
8. `pdb_omap::translate_rva(raw, rva)` ⇔ `llvm-pdbutil dump --section-headers --omap-from-src`.
9. `line_info::lookup_line(records, rva)` ⇔ `llvm-pdbutil dump --lines` mapping for that RVA.
10. `pdb_stream_parser::parse_named_stream_map` ⇔ named-stream table printed by `llvm-pdbutil dump --string-table`.
11. `pdb_symbol_is_sane` — unit-testable in isolation against a fixed table of accepted / rejected names (already covered).
12. `PdbGuid::to_string_fmt` — pure string-formatting; verifiable with hand-computed test vector.

## Validator strategy
Use the existing IDA baseline `cargo-zyphora.exe` + sibling `cargo-zyphora.pdb` as ground truth. Cross-check rustre-symbols-pdb outputs against two independent oracles:

1. **llvm-pdbutil** (`dump --summary --publics --globals --modules --module-syms --types --lines --omap-from-src`) — parse its text output and compare:
   - GUID / Age / Signature exact match.
   - Public-symbol set: name-set equality (sorted), and per-name section-relative offset equality.
   - Module list: name-set equality.
   - Proc-symbol set from `module_proc_symbols()` ⊇ llvm-pdbutil `--module-syms` S_*PROC32 records (allow our parser to also pick up `_ID` variants llvm may filter).
   - Type record count parity within ±1% (we drop unsupported leaves).
2. **IDA Pro baseline** (already captured in MEMORY): the 395 named functions in `cargo-zyphora.exe` must all appear in the lifted-VA map produced by `symbols_pdb_load`. If fewer, fail with a list of missing names.
3. **Self-consistency / round-trip**: for every `PdbPublicSymbol` returned, its (segment, offset) must be a valid PE section + offset (segment ≤ number of sections, offset < section virtual size).
4. **Negative tests**: feed random bytes / truncated PDB / wrong magic → must return `PdbError::BadMagic` or `StreamTooShort`, never panic.

Pure-formatting helpers (`PdbGuid::to_string_fmt`, `primitive_type_name/size`, `pdb_symbol_is_sane`) get standalone vector tests independent of any oracle.
