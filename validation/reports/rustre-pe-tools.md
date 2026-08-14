# rustre-pe-tools

PE (Portable Executable) format analysis library: imports/exports, sections, resources, signatures, overlays, checksums, DLL characteristics, Rich header, security features.

## Cargo.toml

- **name**: `rustre-pe-tools`
- **version**: 0.1.0
- **edition**: 2024
- **dependencies**: `rustre-core` (path `../rustre-core`), `thiserror`, `serde`, `serde_json`, `parking_lot`, `bitflags`

## Module map (`src/lib.rs`)

```
cff_editor                  - CFF in-memory PE editor
import_analysis             - import classification, profiling, API sequences
pe_manifest_parser          - RT_MANIFEST / side-by-side parser (alias: manifest_parser)
pe_anomaly_detector
pe_anomaly_scanner
pe_overlay_analyzer         - overlay/SFX/polyglot detection
pe_overlay_extractor
pe_patcher                  - NOP/JMP/byte patches
pe_rebuild                  - OEP detection, IAT fixup, import rebuild
pe_sign_checker             - Authenticode / WIN_CERTIFICATE / ASN.1 TLV
pe_statistics               - section entropy, API classification, string scan
pe_validation               - structural + semantic validation rules
resource_parser             - PE resource directory, VS_VERSION_INFO
pe_checksum_calculator      - imagehlp-style checksum
pe_rich_header              - Rich header decode + product-ID mapping
```

## Top-level API (`lib.rs`)

### Errors
- `enum PeError`: `NotPe(u16)`, `TooShort{needed,got}`, `InvalidHeader(String)`, `SectionNotFound(String)`, `ImportTableCorrupt`, `ExportTableCorrupt`, `ResourceNotFound(String)`, `Io(io::Error)`, `Serde(serde_json::Error)`

### Enums / flags
- `PeMachine`: I386, Amd64, Arm, Arm64, Mips32, Riscv32, Riscv64, Ia64, Unknown
  - `from_value(u16) -> Self`, `to_value() -> u16`, `pointer_size() -> usize`, `is_64bit() -> bool`, `to_core_mode() -> rustre_core::arch_mode::Mode`
- `PeSubsystem`: Native, WindowsGui, WindowsCui, PosixCui, EfiApplication, EfiBootDriver, EfiRuntimeDriver, Xbox, Unknown
  - `from_value`, `to_value`, `is_console`, `is_efi`
- `DllCharacteristics(pub u16)` — constants `HIGH_ENTROPY_VA`, `DYNAMIC_BASE`, `FORCE_INTEGRITY`, `NX_COMPAT`, `NO_ISOLATION`, `NO_SEH`, `NO_BIND`, `APPCONTAINER`, `WDM_DRIVER`, `GUARD_CF`, `TERMINAL_SERVER_AWARE`. Predicates: `has_aslr`, `has_high_entropy_va`, `has_nx`, `has_cfg`, `no_seh`, `force_integrity`, `is_appcontainer`, `flag_names()`.

### Structs
- `PeSection { name, virtual_address, virtual_size, raw_offset, raw_size, characteristics, data }`
  - `is_executable/writable/readable/discardable/contains_initialized_data/contains_code`, `entropy() -> f64`, `is_likely_packed()`, `byte_histogram()`, `most_common_byte()`, `count_byte(u8)`, `permission_string() -> "rwx"`
- `PeImport { dll, name, ordinal, hint, iat_rva }`
- `PeExport { name, ordinal, rva, forwarder }`
- `DataDir { rva, size }` + `is_present()`
- `mod data_dir_index`: EXPORT, IMPORT, RESOURCE, EXCEPTION, SECURITY, BASERELOC, DEBUG, TLS, LOAD_CONFIG, BOUND_IMPORT, IAT, DELAY_IMPORT, COM_DESCRIPTOR
- `RichEntry { product_id, build_number, count }`
- `RichHeader { xor_key, entries }` — `parse(&[u8]) -> Option<Self>`

### `PeFile` (main type)
Fields: `machine, subsystem, image_base, entry_point, is_dll, is_64bit, time_stamp, checksum, dll_characteristics, sections, imports, exports, data_dirs, overlay, rich_header`.

I/O:
- **Input**: raw PE bytes `&[u8]`.
- **Output**: parsed structures, or JSON via `to_json()`.

Methods:
- `parse(data: &[u8]) -> Result<Self, PeError>`
- `parse_imports(&mut self, data: &[u8]) -> Result<(), PeError>`
- `parse_exports(&mut self, data: &[u8]) -> Result<(), PeError>`
- `section_by_name(name) -> Option<&PeSection>`
- `section_at_rva(rva) -> Option<&PeSection>`
- `rva_to_offset(rva) -> Option<usize>`
- `arch_mode() -> rustre_core::arch_mode::Mode`
- `imports_by_dll() -> HashMap<String, Vec<&PeImport>>`
- `has_aslr/has_nx/has_cfg`
- `overall_entropy() -> f64`, `size() -> usize`
- `to_json() -> Result<String, PeError>`
- `data_dir(i) -> Option<DataDir>`, `section_names() -> Vec<&str>`
- `is_dotnet/is_signed/has_relocations/has_tls`
- `highest_entropy_section() -> Option<&PeSection>`
- `packed_sections() -> Vec<&PeSection>`
- `verify_checksum(raw) -> Option<bool>`
- `security_summary() -> SecuritySummary`
- `imports_from_dll(frag)`, `find_exports(frag)`, `find_imports(frag)`
- `import_count() -> usize`, `imported_dlls() -> Vec<&str>`

### Security summary
- `AslrFlags { aslr, high_entropy_va }`
- `ProtectionFlags { nx, cfg, no_seh }`
- `IntegrityFlags { force_integrity, appcontainer, is_signed }`
- `RuntimeFlags { has_tls, is_dotnet }`
- `SecuritySummary { aslr, protection, integrity, runtime }` + `score() -> u32` (0–10)

### Free functions
- `compute_entropy(data: &[u8]) -> f64` — Shannon entropy
- `compute_pe_checksum(data: &[u8]) -> u32` — imagehlp-compatible

## Submodule highlights

- **resource_parser**: `ResourceError`, `ResourceId`, `ResourceData`, `ResourceEntry`, `ResourceDirectory`; `walk_resources(dir, F)`, `extract_resource_by_type(...)`, `parse_version_info(&[u8]) -> Result<VersionInfo, ResourceError>` (with `FixedFileInfo`, `StringTable`).
- **pe_validation**: `ValidationError`, `ValidationFailure`, `Severity`, `Finding`, `ValidationRule`, `StructuralIntegrity`, `SemanticValidity`, `ValidationReport`, `PeValidator`.
- **pe_statistics**: `SectionEntropy`, `ApiCategory`, `classify_api(&str)`, `StringCategory`, `ClassifiedString`, `StringEncoding`, `classify_string`, `extract_ascii_strings(data, min_len)`, `extract_utf16le_strings(data, min_len)`, `SizeBreakdown`, `PeStatistics`, `PeStatisticsAnalyzer<'a>`.
- **pe_sign_checker**: `SignError`, `WinCertificate`, `TlvNode`, `decode_oid(&[u8]) -> String`, `known_oid_name(&str)`, `ChainCert`, `CertChain`, `SignerInfo`, `CounterSign`, `AuthenticodeInfo`, `SignCheckResult`, `PeSignChecker`, `compute_pe_hash_sha256_approx(&[u8]) -> Vec<u8>`.
- **pe_overlay_extractor**: `OverlayKind`, `Overlay`, `OverlayError`, `PeOverlayExtractor`, `extract_overlay(&[u8]) -> Result<Overlay, OverlayError>`.
- **pe_checksum_calculator**: `ChecksumResult`, `ChecksumError`, `PeChecksumCalculator`, `calculate_checksum(&[u8])`, `calculate_checksum_file(&Path)`, `ChecksumStats`.
- **pe_rich_header**: `ProductId`, `RichEntry`, `RichError`, `PeRichHeader`, `decode_rich_header(&[u8]) -> Result<PeRichHeader, RichError>`, `RichHeaderAnalyzer`.
- **cff_editor**: `CffError`, `EditableImport`, `EditableExport`, `ResourceEntry`, `EditableSection`, `PeEditor`.
- **pe_manifest_parser**: `ManifestError`, `ExecutionLevel`, `DpiAwareness`, `AssemblyDependency`, `SupportedOs`, `ParsedManifest`, `ManifestParser<'a>`, `parse_manifest_xml(&str) -> ParsedManifest`.
- **pe_anomaly_scanner**: `Severity`, `PeAnomaly`, `ScanResult`, `PeAnomalyScanner<'a>`, `pe_checksum(data, offset)`, `scan_pe(&[u8]) -> Option<ScanResult>`.
- **pe_rebuild**: `RebuildError`, `OepHint`, `IatPatch`, `ImportSpec`, `ImportEntry`, `RebuildStats`, `PeRebuilder`.
- **pe_overlay_analyzer**: `OverlayKind`, `SfxPattern`, `builtin_sfx_patterns()`, `PolyglotDetect`, `Overlay`, `OverlayInfo`, `PeOverlayAnalyzer`, `find_overlay_start`, `find_embedded_pe_offsets`, `estimate_pe_size`, `compute_entropy`, `is_all_zeros`, `byte_histogram`, `most_frequent_byte`.
- **import_analysis**: `ImportError`, `ImportCategory`, `ImportEntry`, `ImportProfile`, `ImportsTimeline`, `ApiSequence`, `ApiCallGraph`, `ImportAnalyzer`.
- **pe_patcher**: `PatchError`, `NopPatch`, `JmpPatch`, `BytePatch`, `PatchKind`, `PatchEntry`, `PatchList`, `ApplyStats`, `PatchApplier`.

## I/O summary

- **Inputs**: raw byte slices `&[u8]` (PE image bytes); occasionally `&Path` (`calculate_checksum_file`); XML strings (`parse_manifest_xml`).
- **Outputs**: typed structs (Serde `Serialize`/`Deserialize`-ready), `Result<_, PeError|...>`, JSON via `PeFile::to_json()`.
- **State**: pure parsing — no global state; `parking_lot::RwLock` only used internally for some analyzers.

## Testability

Pure-Rust, no-FFI, no-network, deterministic. Has a `tests/` directory. Easy to feed crafted byte buffers; `PeFile::parse` plus `parse_imports`/`parse_exports` make round-trip unit tests straightforward.
