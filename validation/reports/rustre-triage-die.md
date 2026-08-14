# rustre-triage-die

Detect-It-Easy (DIE) style file format, packer, protector, and compiler detection for PE binaries.

## Cargo.toml

- **name**: `rustre-triage-die`
- **version**: 0.1.0
- **edition**: 2024
- **license/description/repo/keywords/categories/authors**: inherited from workspace

### Dependencies
- `rustre-triage` (path `../rustre-triage`) — provides `FileKind`, `TriageError`
- `thiserror` (workspace) — error derives
- `serde` (workspace) — Serialize/Deserialize on conditions and results
- `serde_json` (workspace) — JSON serialization of detections

### Lints
- `workspace = true`

## Module map (`lib.rs`)

Public submodules:
- `die_extended`, `die_scanner`, `heuristic_detector`, `rule_db_extended`
- `scanner`, `signature_db`, `die_signature_db`, `detector_engine`
- `die_signatures`, `die_database`, `packer_detector`, `die_script_engine`
- `compiler_detector`, `packer_signature_db`, `overlay_analyzer`
- `entropy_based_classifier`

## Public API (root)

### Constants

- `pub const BUILTIN_RULES: &str` — embedded YAML rule database covering 25+ known
  formats (packers UPX/MPRESS/ASPack/PECompact/MEW/FSG/PESpin; protectors Themida/
  VMProtect/Enigma/Obsidium; compilers MSVC x86/x64, GCC/MinGW, Clang, Delphi,
  .NET, .NET AOT; tools PyInstaller/Py2Exe/cx_Freeze/AutoIt; installers
  NSIS/Inno/WiX/InstallShield). Schema documented inline.

### Types

- `pub enum DieCondition` — atomic detection condition. Variants:
  - `SectionName(String)` — PE section name present
  - `SectionCount { min: u8, max: u8 }` — inclusive range
  - `BytePattern { offset: usize, hex: String }` — hex pattern (`??` wildcard) at/after offset
  - `EntryPointHex(String)` — hex pattern at PE entry point
  - `EntropyRange { section: usize, min: f32, max: f32 }` — Shannon entropy of section
  - `ImportPresent { dll: String, func: String }` — case-insensitive import lookup
  - `ImportCount { min: u16, max: u16 }`
  - `ExportPresent(String)` — case-sensitive export name
  - `SubsystemType(u16)` — PE Subsystem field (2=GUI, 3=Console)
  - `StringPresent(String)` — UTF-8 substring search
  - `MachineType(u16)` — COFF Machine (0x8664/0x014c/0xAA64)
  - `OverlayPresent` — bytes after last section
  - `ResourcePresent(String)` — resource type name (UTF-16LE, case-insensitive)
  - `Dotnet` — non-zero CLR data directory
  - `Manifest` — RT_MANIFEST resource

- `pub enum RuleCondition` — boolean combinator: `All(Vec<DieCondition>)`,
  `Any(Vec<DieCondition>)`, `Not(Box<DieCondition>)`.

- `pub struct DieScanner` — stateless scanner over `BUILTIN_RULES`.
  - `pub const fn new() -> Self`
  - `pub fn scan(&self, data: &[u8]) -> Vec<Detection>` — evaluates all built-in rules; returns matches sorted by confidence descending.

- `pub enum DieError` — error type (thiserror).
- `pub enum DetectKind` — taxonomy (Compiler, Packer, Protector, Installer, Tool, ...).
- `pub struct Detection { kind, name, version, confidence, description }`.
- `pub struct DieResult` — aggregated scan output.
- `pub struct DieRule` — single rule descriptor for ad-hoc rule sets.
- `pub struct DieDatabase` — collection of `DieRule`s.
- `pub struct DieDetector` — raw byte-anchor detector (alternative to `DieScanner`).
- `pub struct DieMatchResult` — output of `DieDetector`.
- `pub struct DieSignatureEntry` and `pub enum SigCheck` — typed signature DB items.
- `pub struct DieSignatureDatabase` — typed signature database.

### Free functions

- `pub fn read_pe_sections(data: &[u8]) -> Vec<(String, f32)>` — section name + Shannon entropy of raw bytes; caps section count at 96.
- `pub fn compute_entropy(data: &[u8]) -> f32` — Shannon entropy (bits/byte).
- `pub fn get_entry_point_bytes(data: &[u8]) -> Vec<u8>` — up to 16 bytes at the PE entry point (PE32 and PE32+).
- `pub fn check_imports(data: &[u8], dll: &str, func: &str) -> bool` — case-insensitive import directory walk (ILT and IAT).
- `pub fn find_bytes(data: &[u8], hex_pattern: &str) -> Option<usize>` — wildcard-aware hex pattern search (`??` matches any byte).
- `pub fn match_condition(cond: &DieCondition, data: &[u8]) -> bool` — evaluate a single condition.
- `pub fn match_rule_condition(rc: &RuleCondition, data: &[u8]) -> bool` — evaluate a boolean combinator.

## Internals (non-public, noteworthy)

PE parsing helpers `locate_pe`, `read_section_count`, `pe_subsystem`, `pe_machine`,
`has_overlay`, `has_dotnet`, `has_manifest`, `has_resource_type`,
`rva_to_file_offset`, `read_cstr`, `check_ilt_for_func`, `count_ilt_entries`,
`count_imports`, `check_exports` implement defensive PE32/PE32+ parsing with
saturating arithmetic and bounded loops to harden against attacker-controlled
header values. The YAML parser for `BUILTIN_RULES` is hand-written (no
`serde_yaml` dependency) and tolerates inline maps for multi-field conditions.

## Testability

- All root functions are pure (input `&[u8]` → value), no I/O or globals — directly unit-testable with synthetic PE buffers.
- `DieScanner::new()` + `.scan(&[u8])` is a single entry point usable in integration tests.
- `BUILTIN_RULES` is exposed so tests can re-parse or extend the rule set.
- No external services, no async — suitable for property-based and fuzz testing.
