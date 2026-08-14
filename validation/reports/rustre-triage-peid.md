# rustre-triage-peid

PE packer/compiler identification via PEiD-style byte signatures, plus extended PE triage utilities (sections, imports, overlays, anomalies, Rich header, entry point analysis).

## Cargo.toml

- name: `rustre-triage-peid`, version `0.1.0`, edition 2024
- features:
  - `default = []`
  - `network` (reserved for future HTTP signature downloading; stubbed)
- dependencies: `rustre-triage` (path), `thiserror`, `serde`, `serde_json`, `rayon`
- workspace lints

## Modules

- `peid_db` — main signature DB (`PeidDb`, `PeidSignature`, `PeidMatch`, `extract_version`)
- `peid_signature_matcher` — pattern matcher (`PeidMatcher`, `PatternAccelerator`, `parse_peid_database`, `parse_signature_bytes`, `match_at_offset`, `match_signature`, `builtin_signatures`)
- `peid_extended` — EP / section / import / chained signatures (`EpSignature`, `SectionSignature`, `ImportSignature`, `SignatureChain`, `PeidExtended`, `PeidMatchResult`, `MatchSource`, `SignatureCategory`, `ChainLogic`, `SectionMatchMode`)
- `peid_deep_scan` — multi-layer packing / embedded executables (`PeidDeepScanner`, `DeepScanResult`, `PackerVersion`, `ProtectedCodeRegion`, `EmbeddedExecutable`, `EmbeddedFormat`, `PackingLayer`, `MultiPackLayer`, `UnpackingHint`, `UnpackDifficulty`)
- `userdb_parser` — PEiD `userdb.txt` format (`parse_userdb`, `parse_pattern_string`, `parse_byte_token`, `parse_inline`, `to_userdb_text`, `dedup_signatures`, `merge_signatures`, `UserdbDatabase`, `ParsedSignature`, `UserdbError`)
- `signature_updater` — DB versioning/diff (`SignatureUpdater`, `UpdaterConfig`, `SignatureSource`, `SourceFormat`, `KNOWN_SOURCES`, `DbVersion`, `ChangelogEntry`, `LocalDatabaseState`, `UpdateResult`, `DiffSummary`, `UpdaterError`)
- `linker_detector` — linker/Rich header detection (`LinkerDetector`, `LinkerDb`, `LinkerSignature`, `LinkerKind`, `CompilerVersion`, `DetectedLinker`, `RichHeader`, `RichHeaderAnalyzer`, `RichEntry`)
- `compiler_detector` — compiler family heuristics (`CompilerDetector`, `CompilerInfo`, `CompilerReport`, `CompilerFamily`)
- `section_analyzer` — section profiling/anomalies (`SectionAnalyzer`, `analyze_sections`, `has_high_entropy_sections`, `high_entropy_section_names`, `shannon_entropy`, `RawSection`, `SectionProfile`, `SectionReport`, `SectionAnomaly`, `AnomalyKind`, `Verdict`, `AnalyzerConfig`, constants `HIGH_ENTROPY_THRESHOLD`, `VIRT_RAW_RATIO_THRESHOLD`)
- `pe_anomaly_detector` — PE structural anomaly checks (`PeAnomalyDetector`, `Anomaly`, `AnomalyReport`, `AnomalyType`, `AnomalySeverity`)
- `import_fingerprinter` — imphash / malware import patterns (`ImportFingerprintEngine`, `ImportEntry`, `ImportHash`, `ImportFingerprint`, `MalwareImportPattern`, `ImportCluster`, `FingerprintSummary`)
- `overlay_extractor` — overlay (`OverlayExtractor`, `OverlayInfo`, `OverlayRegion`, `OverlayKind`, `OverlayExtractorConfig`, `SectionBoundary`, `ZipEocd`, `check_certificate_overlay`, `CertificateCheckResult`, `bulk_overlay_stats`, `BulkOverlayResult`, `OverlayError`)
- `ep_analyzer` — entry point heuristics (`EpAnalyzer`, `EpCharacteristics`, `EpPattern`, `EpReport`, `EpVerdict`, `TailJumpDetector`, `TailJump`, `TailJumpKind`, `PushPopAnalyzer`, `PushPopProfile`, `OverlayInfo`, `OverlayDetector`, `full_ep_analysis`, `shannon_entropy`, `byte_diversity`, `opcode_diversity`, `code_density`, `is_iat_thunk`, `is_frame_setup`, `has_long_jump`)

## Crate root (`lib.rs`)

### Types

- `enum PeidError` — `InvalidPattern(String)`, `EmptyData`
- `enum PeidCategory` — `Packer | Protector | Compiler | Linker | Installer | Runtime | Other | Unknown`; `pub const fn label(&self) -> &'static str`
- `struct PeidSignature { name, version: String, pattern: Vec<Option<u8>>, ep_only: bool, category: PeidCategory }`
  - `pub fn matches(&self, data: &[u8], offset: usize) -> bool`
  - `pub fn confidence(&self) -> f32`
- `struct PeidMatch { signature_name, version: String, offset: usize, ep_only: bool, confidence: f32, category: PeidCategory }`
- `struct ScanOptions { max_matches, min_pattern_length: usize, ep_only_strict, scan_sections: bool }` (impl `Default`)
- `struct PeidDatabase { pub sigs: Vec<PeidSignature> }` — `new()` preloads 175+ built-in signatures (UPX, ASPack, MSVC/GCC/Clang/Delphi/Borland/Watcom/Intel/TCC/Open64, Go, Rust, .NET/.NET Core, PyInstaller/Nuitka/cx_Freeze/PyPy, Nim/Zig/V, AutoIT/AHK, NSIS/InnoSetup/WiX/InstallShield/Wise, MPRESS/PEtite/PECompact/NsPack/nPack/KKrunchy/PEBundle/FSG/Packman/aPACK/AHpack/Exe32Pack/WinUpack/BeRoEXEPacker/MKFPack/MEW/RLPack/ExeSax/NSPack/Upack...)
- `struct PeidScanner` — high-level scanner over `PeidDatabase`
- `struct Detection`, `struct TriageReport` — top-level triage result types

### Functions / constants

- `pub fn parse_peid_pattern(s: &str) -> Result<Vec<Option<u8>>, PeidError>` — parses `"60 BE ?? ?? 8D BE"` style strings
- `pub fn parse_peid_database(content: &str) -> Vec<PeidSignature>` — parse a userdb-format text blob
- `pub static BUILTIN_PEID_SIGS: &str` — embedded userdb text

## Testable

Yes — the crate has a `tests/` directory and ample pure functions (pattern parsing, byte matching, entropy, confidence scoring, userdb parse/merge/dedup, builtin DB size) that can be unit-tested without external binaries.
