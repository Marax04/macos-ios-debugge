# rustre-loader-pe — Crate Analysis

## Purpose
Enterprise-grade Portable Executable (PE/PE+) loader and parser. Takes raw PE bytes and extracts every standard PE structure: DOS+Rich+COFF+optional headers, 16 data directories (imports/exports/relocs/TLS/exceptions/load_config/resources/debug/security/.NET CLR), section table, Authenticode signature, overlay, entropy, ASCII/UTF-16 strings, compiler/linker fingerprint, imphash, and FLIRT auto-naming. Implements the `Loader` trait from rustre-core to produce a `BinaryView` (Memory + Segments). Built on `goblin` for top-level parse plus hand-written parsers for richer detail.

## Public functions (semantic view)

### Top-level entry point
- **`PeInfo::parse(data: &[u8]) -> Result<PeInfo, String>`**
  - Input: raw PE file bytes.
  - Output: structured PeInfo with machine, subsystem, image_base, entry_point, sections, imports/exports, relocations, TLS, exceptions, load_config, resources, debug info, Authenticode certs, .NET summary, overlay, entropy, Rich header.
  - Ground truth: cross-check against `pefile` (Python) or `LIEF` on the same binary — every field (machine code, entry RVA, section count, import DLL names) is independently verifiable.

### Hashing / fingerprinting (`pe_imphash`)
- **`md5_hex(data: &[u8]) -> String`** — MD5 hex digest. GT: `hashlib.md5(data).hexdigest()`.
- **`sha256_hex(data: &[u8]) -> String`** — SHA256 hex digest. GT: `hashlib.sha256(data).hexdigest()`.
- **`normalise_dll_name(dll: &str) -> String`** — lowercase, strip `.dll`/`.ocx`/`.sys`. GT: trivial reimplementation in Python.
- **`normalise_function_name(name: &str) -> String`** — canonical lowercase function name for imphash. GT: trivial.
- **`make_entry(dll, func) -> String`** — `"dll.func"` joined for imphash list. GT: trivial; ultimate GT vs pefile.get_imphash().

### Entropy (`entropy`)
- **`shannon_entropy(data: &[u8]) -> f64`** — Shannon entropy in bits/byte (0..8). GT: `scipy.stats.entropy(counts, base=2)`.
- **`byte_histogram(data) -> [u32;256]`** — frequency of each byte. GT: `collections.Counter`.
- **`most_common_byte(data) -> (u8, u32)`** — argmax+count of histogram. GT: trivial.
- **`chi_squared(data) -> f64`** — χ² vs uniform. GT: `scipy.stats.chisquare`.
- **`looks_packed(data) -> bool`** — entropy threshold heuristic. GT: compare to known-packed UPX sample (true) and ASCII text (false).
- **`analyze_sections(data, sections) -> Vec<SectionEntropy>`** — per-section entropy summary. GT: per-section entropy from LIEF.

### String scanning (`strings`)
- **`scan_ascii(data, min_len) -> Vec<ExtractedString>`** — ASCII runs of printable chars ≥ min_len. GT: GNU `strings -a -n N`.
- **`scan_utf16le(data, min_len) -> Vec<ExtractedString>`** — UTF-16LE runs. GT: `strings -el -n N`.
- **`scan_strings(data, options) -> Vec<ExtractedString>`** — combined scan. GT: union of above.
- **`scan_section(...)`** — same but bounded to one section.
- **`classify_string(s) -> Option<InterestingCategory>`** — tags URL/path/registry/etc. GT: regex-based oracle.
- **`is_printable_ascii / is_printable_utf16`** — pure predicates. GT: trivial.

### Imports (`imports`)
- **`rva_to_file_offset(rva, sections) -> Option<usize>`** — translate RVA to file offset using section table. GT: `pefile.get_offset_from_rva`.
- **`parse_import_table_32 / parse_import_table_64(data, sections, dir_va, size, image_base) -> Vec<ImportedFunction>`** — full ILT/IAT walk. GT: `pefile.DIRECTORY_ENTRY_IMPORT`.
- **`parse_delay_imports(...)`** — delay-load descriptors. GT: `pefile.DIRECTORY_ENTRY_DELAY_IMPORT`.
- **`parse_bound_imports(data, offset) -> Vec<BoundImportEntry>`** — bound import table. GT: `pefile.DIRECTORY_ENTRY_BOUND_IMPORT`.
- **`looks_like_forward(export_data) -> bool`** — heuristic for forwarded export string. GT: contains `'.'` and ASCII.

### Exports (`exports`)
- **`parse_export_table(data, sections, dir_va, size, image_base) -> Vec<ExportedSymbol>`** — by-name+ordinal, forwarders. GT: `pefile.DIRECTORY_ENTRY_EXPORT`.

### Relocations (`relocations`)
- **`parse_relocation_directory(data, sections, va, size) -> Vec<RelocationBlock>`** — 13 reloc types. GT: `pefile.DIRECTORY_ENTRY_BASERELOC`.
- **`apply_relocations(...)`** — rebase image. GT: compare with LIEF rebasing.

### TLS (`tls`)
- **`parse_tls_32 / parse_tls_64(...) -> Option<TlsInfo>`** — TLS directory + callbacks VAs. GT: `pefile.DIRECTORY_ENTRY_TLS`.

### Resources (`resources`)
- **`parse_version_resource(data) -> VersionInfo`** — VS_VERSIONINFO. GT: `pefile.FileInfo`.
- **`parse_manifest_resource(data) -> String`** — application manifest XML. GT: raw RT_MANIFEST blob.
- **`parse_string_table(data, block_id)`** / **`parse_message_table`** — Win32 string/message tables.
- **`reconstruct_ico(...)` / `reconstruct_bmp(...)`** — produce valid ICO/BMP from RT_ICON / RT_BITMAP. GT: parse output with PIL.
- **`find_version_info / find_manifest / find_all_strings / find_all_icons / find_all_message_tables`** — convenience finders on rsrc data.

### Debug (`debug_dir`)
- **`parse_debug_directory(data, sections, va, size) -> Vec<DebugDirectoryEntry>`** — all 11 types. GT: `pefile.DIRECTORY_ENTRY_DEBUG`.
- **`extract_codeview_info(...)` -> Option<CodeViewInfo>** — RSDS PDB GUID+age+path. GT: matches PDB GUID printed by `dumpbin /pdbpath`.
- **`detect_dotnet(...)`** — .NET presence flag from debug.

### Overlay / Authenticode (`overlay`)
- **`detect_sfx_kind(bytes) -> SfxKind`** — SFX archive detection (7z/Zip/RAR/NSIS/InnoSetup) from magic bytes. GT: magic byte tables.
- **`parse_security_directory(data, va, size) -> Vec<WinCertificate>`** — WIN_CERTIFICATE blobs. GT: `signtool verify` or `osslsigncode`.
- **`find_overlay_offset(...)`** — byte offset of bytes past last section. GT: `last_section.raw_offset + raw_size`.

### Compiler detect (`compiler_detect`)
- **`detect_compiler(image, rich) -> CompilerInfo`** — heuristic compiler/linker identification from Rich header + strings. GT: known compiler outputs (Rust binary -> rustc, MSVC binary -> MSVC).

### .NET (`dotnet`)
- **`parse_dotnet(data, sections, va, size) -> Option<DotNetInfo>`** — CLR header + metadata root. GT: `dnSpy`/`ildasm`.

### Load config (`load_config`)
- **`parse_cfg_function_table(...)`** — CFG function RVAs. GT: dumpbin /loadconfig.
- **`parse_safe_seh_handlers(...)`** — SafeSEH handler list (32-bit). GT: dumpbin /loadconfig.

### TLS-callback deep analysis (`pe_tls_callbacks`)
- **`known_tls_patterns() / match_tls_patterns / classify_by_patterns`** — pattern-match TLS callback prologues. GT: regression test on labelled samples.
- **`detect_anti_debug_in_callback(cb)` -> TlsAntiDebugResult** — checks for anti-debug API patterns. GT: hand-labelled samples.
- **`validate_tls_directory(tls) -> Vec<String>`** — sanity warnings. GT: malformed test fixtures.
- **`read_cstring(data, offset) -> Option<String>`** — utility. GT: trivial.
- **`byte_entropy(data) -> f64`** — Shannon entropy (duplicate of entropy::shannon_entropy). GT: same as above.

### FLIRT auto-naming (`flirt_autoname`)
- **`baseline_packs() -> Vec<SignaturePack>`** — bundled signature packs.
- **`scan_executable_segments(scanner, mem) -> Vec<FlirtMatch>`** — scan code sections with FLIRT scanner.
- **`apply_default_packs(mem) -> (Vec<ResolvedRename>, ResolveStats)`** — convenience.
- **`apply_packs(packs, mem)`** — apply specific packs. GT: rename count vs known libstd matches.

### Casts (`casts`)
- Numeric saturating conversions (`usize_to_f64`, `u64_to_usize`, etc.). GT: trivial bounds tests.

### lib.rs misc
- **`classify_import(name) -> ImportCategory`** — tags Win32 API into categories (file/network/crypto/process). GT: oracle table of well-known APIs.
- **`PeInfo` accessors**: `imports_from_dll`, `export_by_name`, `export_by_ordinal`, `imports_dll`, `has_tls_callbacks`, `is_signed`, `pdb_path`, `relocation_count`, `has_relocations`, `manifest_xml`, `security_score`, `section_names`, `find_section`, `forwarded_exports`, `entry_points`, `rva_to_offset`. All pure derived queries — GT: re-derive from PeInfo dump.
- **`SectionInfo`** methods: `va_range`, `is_code`, `is_writable`, `is_readable`, `mapped_size`. GT: bit-test characteristics.

### `Loader` trait impl
- **`PeLoader`** implements `Loader::load(input) -> BinaryView` — produces memory/segments. GT: segment VA/size matches sections.

## Existing MCP tools
No MCP tool is named `loader_pe_*` directly. PE-specific tools that route through this crate:
- `patch_pe_security_summary` (line 1890 of wire_tools.rs) — reads dll_characteristics via PeInfo.
- `patch_pe_set_security` (line 2160) — patches dll_characteristics.
- PE parsing is invoked indirectly inside generic tools (`binary_info`, `triage_analyze`, `analyze_imports`, `analyze_exports`, `analyze_strings`) via `rustre_loader_pe::PeInfo::parse(data)` calls (lines 4009, 4061, 4103, 4138, 4308, 4320, 4620).
- FLIRT auto-naming is exposed through `flirt_apply_auto` which calls `rustre_loader_pe::flirt_autoname` (lines 1128, 1305).

So most loader-pe functionality is reachable via MCP but not via dedicated `loader_pe_*` tools — verification must go through `binary_info` / `analyze_imports` / `analyze_exports` / `analyze_strings` / `triage_analyze` / `patch_pe_security_summary` / `flirt_apply_auto`.

## Testable functions (high-value, externally verifiable)
1. `pe_imphash::md5_hex`, `sha256_hex` — Python hashlib.
2. `entropy::shannon_entropy`, `byte_histogram`, `chi_squared` — scipy/Counter.
3. `strings::scan_ascii`, `scan_utf16le` — GNU strings.
4. `PeInfo::parse` fields (machine, subsystem, image_base, entry_rva, section names+VAs+sizes, import DLL list, export names+ordinals, pdb_path, dll_characteristics, timestamp) — pefile / LIEF.
5. `imports::rva_to_file_offset` — pefile.get_offset_from_rva.
6. `exports::parse_export_table` — pefile.DIRECTORY_ENTRY_EXPORT.
7. `relocations::parse_relocation_directory` — pefile.DIRECTORY_ENTRY_BASERELOC count.
8. `overlay::find_overlay_offset`, `detect_sfx_kind` — magic bytes oracle.
9. `debug_dir::extract_codeview_info` — dumpbin /headers PDB GUID.
10. `compiler_detect::detect_compiler` — labelled-corpus oracle.

## Validator strategy
Build a Python harness that, for each test PE (clean MSVC exe, Rust exe, .NET assembly, packed UPX exe, signed Windows DLL):
1. Parse with `pefile`+`LIEF` to produce ground-truth JSON (machine, image_base, entry RVA, sections [name, VA, vsize, raw_off, raw_size, chars], imports `[(dll,func), ...]`, exports `[(name,ord,addr), ...]`, pdb GUID+path+age, dll_characteristics, timestamp, has_tls, tls_callbacks count, has_relocations + reloc count, signed bool, dotnet bool).
2. Invoke RustRE either by calling `PeInfo::parse` via a tiny Rust test binary (`cargo test --package rustre-loader-pe -- dump_json`) or via MCP tools (`binary_info`, `analyze_imports`, `analyze_exports`, `triage_analyze`, `patch_pe_security_summary`) and capture JSON.
3. Diff the two JSON blobs field-by-field with tolerant matching (case-insensitive DLL names, sorted import lists). Report mismatches.
4. For hashing/entropy: compute on raw section bytes with `hashlib` / `scipy.stats.entropy(counts, base=2)` and compare to RustRE outputs (entropy within 1e-6).
5. For strings: run GNU `strings -a -n 6` and `strings -el -n 6`; require RustRE output ⊇ GNU set (RustRE may find more in UTF-16 islands).
6. For imphash: compare with `pefile.get_imphash()` exactly.
7. Maintain a labelled corpus with known compiler tags (rustc/MSVC/MinGW/Go) and assert `detect_compiler` predicts the correct one ≥ 90% of samples.
