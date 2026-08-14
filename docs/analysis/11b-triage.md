# Triage Crate Group Analysis

**Crates covered:** `rustre-triage`, `rustre-triage-die`, `rustre-triage-entropy`,
`rustre-triage-peid`, `rustre-triage-yara`

**Date:** 2026-07-02

---

## 1. Group Overview

The five triage crates form a layered static-analysis stack that classifies
a binary, assigns a threat score, and produces a structured JSON report — all
without executing the target.  The dependency graph is:

```
rustre-triage          (coordinator, defines shared types)
    ├── rustre-triage-die       (Detect-It-Easy style detection)
    ├── rustre-triage-entropy   (Shannon entropy analysis)
    ├── rustre-triage-peid      (PEiD pattern matching)
    └── rustre-triage-yara      (YARA-like rule engine)
```

`rustre-triage` owns `TriageResult`, `ThreatLevel`, and the pipeline
orchestration.  The sub-crates are independent engines that can be used
standalone or slotted into the pipeline as `PipelineStage` implementations.

---

## 2. `rustre-triage` — Triage Coordinator

### 2.1 Purpose

Quick automated analysis to classify a binary, compute hashes, measure entropy,
detect packers and suspicious strings, and assign an initial threat score
(0–100) with a qualitative `ThreatLevel`.  Acts as the entry point consumed
by `rustre-mcp-server` through `triage_core_run_pipeline`.

### 2.2 Dependencies

| Crate | Role |
|---|---|
| `rustre-pe-tools` | `PeFile`, `compute_entropy` |
| `rustre-loader-pe` | PE parsing backend |
| `rustre-crypto-id` | `BinaryCryptoHit`, constant-scan stage |
| `sha2` / `md-5` | Hash computation |
| `serde` / `serde_json` | Report serialization |
| `thiserror` | Typed errors |

### 2.3 Public API (lib.rs)

| Item | Kind | Description |
|---|---|---|
| `TriageError` | `enum` | `TooSmall`, `Pe`, `Io`, `Other` |
| `FileKind` | `enum` | 13 variants: `Pe32`, `Pe64`, `Elf32`, `Elf64`, `MachO`, `Apk`, `Dex`, `Zip`, `Pdf`, `Doc`, `Exe`, `Dll`, `Sys`, `Unknown` |
| `ThreatLevel` | `enum` | `Clean` → `Informational` → `Low` → `Medium` → `High` → `Critical` |
| `TriageIndicator` | `struct` | Named finding with `threat_level`, `category`, `evidence` |
| `TriageResult` | `struct` | Accumulates all findings; has `add_indicator`, `is_malicious`, `to_report`, `to_json` |
| `TriageReport` | `struct` | Flat JSON view with `all_strings` and `crypto_hits` |
| `ExtractedString` | `struct` | Printable string with offset and encoding |
| `SuspiciousString` | `struct` | String with reason/category |
| `detect_file_kind` | `fn` | Magic-byte classifier |
| `compute_sha256` / `compute_md5` | `fn` | Hash helpers |

`TriageResult::add_indicator` implements the scoring formula:

```rust
let delta: u8 = match indicator.threat_level {
    ThreatLevel::Clean         => 0,
    ThreatLevel::Informational => 2,
    ThreatLevel::Low           => 10,
    ThreatLevel::Medium        => 20,
    ThreatLevel::High          => 35,
    ThreatLevel::Critical      => 50,
};
self.score = self.score.saturating_add(delta).min(100);
```

### 2.4 Internal Modules

| Module | Role |
|---|---|
| `triage_pipeline` | `PipelineStage` trait + `TriagePipeline` orchestrator |
| `file_classifier` | Magic-byte → `FileKind` mapping |
| `heuristic_engine` | Rule-based heuristics (API suspicious-ness, etc.) |
| `score_aggregator` | Combines per-stage scores |
| `rapid_classifier` | Fast pre-check before deep analysis |
| `analyzer_registry` | Registry of named analyzer functions |
| `pe_triage_extended` | PE-specific checks (sections, imports, overlay) |
| `static_analysis_triage` | String + import scanning |
| `findcrypt` | Delegates to `rustre-crypto-id` |
| `mitre_mapper` | Maps indicator categories to ATT&CK technique IDs |
| `malware_classification` | Family/type classification |
| `family_db` | Known-family database |
| `triage_report` | Report formatting helpers |

### 2.5 Pipeline Architecture (`triage_pipeline.rs`)

```
PipelineStage trait (Send + Sync)
  ├── fn name() -> &'static str
  ├── fn run(data, &mut TriageResult) -> StageOutput
  └── fn applicable(FileKind) -> bool   // default: true

TriagePipeline
  ├── stages: Vec<Box<dyn PipelineStage>>
  ├── fn new() -> Self
  ├── fn default_pipeline() -> Self     // registers all built-in stages
  ├── fn add_stage(Box<dyn PipelineStage>)
  └── fn run(&[u8]) -> Result<PipelineRunResult, TriageError>
```

Built-in stages registered by `default_pipeline()`:

| Stage | What it does |
|---|---|
| `FileKindStage` | Sets `result.file_kind` from magic bytes |
| `EntropyStage` | Flags overall entropy above threshold |
| `PackerDetectionStage` | Searches for UPX!, `UPX0`/`UPX1`, MPRESS sections |
| `StringAnalysisStage` | Extracts suspicious strings (URLs, IPs, paths, APIs) |
| `AntiAnalysisStage` | Detects `IsDebuggerPresent`, `NtQueryInformationProcess`, etc. |
| `ShellcodeDetectionStage` | Heuristic shellcode patterns |
| `CryptoConstantScanStage` | `rustre_crypto_id::scan_binary_for_crypto_constants` |
| `AllStringExtractionStage` | Full ASCII+UTF-16 string extraction into `result.all_strings` |
| `CompilerDetectionStage` | Sets `result.compiler_hint` |

### 2.6 Completeness

**COMPLETE.** No `todo!` or `unimplemented!` calls. All stages have inline unit
tests covering entropy flagging, packer detection, URL strings, anti-analysis
APIs, and the pipeline summary. The `all_strings` + `crypto_hits` fields were a
known gap (noted in field doc-comments) and are now wired.

---

## 3. `rustre-triage-die` — Detect-It-Easy Style Detection

### 3.1 Purpose

Replicates Detect-It-Easy (DIE) packer/protector/compiler identification using
two complementary detection layers: a YAML structured-rule DSL evaluated against
PE headers/sections/imports, and a byte-pattern engine for EP and full-file
matching.

### 3.2 Dependencies

| Crate | Role |
|---|---|
| `rustre-triage` | `FileKind`, `TriageError` |
| `serde` / `serde_json` | Rule/result serialization |
| `thiserror` | Typed errors |

No external packer-detection library; all logic is native Rust.

### 3.3 Public API (lib.rs)

| Item | Kind | Description |
|---|---|---|
| `DieCondition` | `enum` | 14 condition variants (see below) |
| `RuleCondition` | `enum` | `All`, `Any`, `Not` combinators over `DieCondition` |
| `BUILTIN_RULES` | `const &str` | Embedded YAML rule database (25+ rules) |
| `DieDetector` | `struct` | Parses YAML rules and evaluates them |
| `DetectKind` | `enum` | `Compiler`, `Packer`, `Protector`, `Installer`, `Tool` |
| `Detection` | `struct` | Match result with name/version/confidence |
| `DieError` | `enum` | Parse and evaluation errors |

`DieCondition` variants:

| Variant | Checks |
|---|---|
| `SectionName(String)` | PE section with given name exists |
| `SectionCount { min, max }` | Section count in range |
| `BytePattern { offset, hex }` | Hex bytes (with `??` wildcards) at offset |
| `EntryPointHex(String)` | Bytes at PE entry point |
| `EntropyRange { section, min, max }` | Section entropy in range |
| `ImportPresent { dll, func }` | Import present (case-insensitive) |
| `ImportCount { min, max }` | Import count in range |
| `ExportPresent(String)` | Named export present |
| `SubsystemType(u16)` | PE subsystem field |
| `StringPresent(String)` | Raw string in file bytes |
| `MachineType(u16)` | COFF machine field |
| `OverlayPresent` | Data past last section |
| `ResourcePresent(String)` | Named resource type |
| `Dotnet` | CLR data directory non-zero |
| `Manifest` | RT_MANIFEST resource |

### 3.4 Internal Modules

| Module | Role |
|---|---|
| `die_scanner` | `DieScanner` + `DieRuleEngine` — EP-aware, per-rule EP control, rich `DieReport` (~24 rules) |
| `rule_db_extended` | `ExtendedRuleDb` — 200+ entries, `Platform` flags, `DieRuleEntry` |
| `scanner` | Alternative `DieScanner` (SignatureDb + DieDetector combined) |
| `signature_db` | Binary pattern signature store |
| `die_signature_db` | Second signature database variant |
| `die_signatures` | Static signature definitions |
| `die_database` | Persistent signature database |
| `die_script_engine` | Lightweight script rule evaluator |
| `detector_engine` | High-level orchestration (`DetectorEngine`) |
| `die_extended` | Extended detection results with metadata |
| `compiler_detector` | Compiler fingerprinting (MSVC, GCC, Clang, Rust, Go, etc.) |
| `packer_detector` | Packer-specific heuristics |
| `packer_signature_db` | Packer-only signature subset |
| `overlay_analyzer` | Bytes-after-last-section analysis |
| `entropy_based_classifier` | Entropy-assisted detection |
| `heuristic_detector` | General heuristics fallback |

Two scanner implementations exist with different rule schemas:
- `die_scanner::DieScanner` uses `DieRuleEngine` with `builtin_rules()` (~24 rules); supports `ep_only`, `unpacked_only`, `platform` per rule.
- `scanner::DieScanner` uses `SignatureDb + DieDetector`; intended for the larger `rule_db_extended::EXTENDED_RULES` (~200 entries).

The YAML `BUILTIN_RULES` embedded in `lib.rs` covers UPX 3.x/4.x, MPRESS, ASPack, PECompact, MEW, Themida/WinLicense, VMProtect, MSVC, GCC/MinGW, Clang, Go, Rust, .NET, Delphi, NSIS, InnoSetup, and more.

### 3.5 Completeness

**COMPLETE.** No stubs found. The dual-scanner architecture is intentional (documented in `die_scanner.rs` doc-comment). Rule count in `BUILTIN_RULES` is ~25; `ExtendedRuleDb` reaches ~200. Integration with `rustre-triage`'s pipeline requires a wrapper `PipelineStage` (not present in this crate — expected to live in the MCP server layer).

---

## 4. `rustre-triage-entropy` — Shannon Entropy Analysis

### 4.1 Purpose

Computes Shannon entropy at multiple granularities (whole file, per-PE-section,
fixed-size chunks) to detect packed, encrypted, or compressed regions.
Provides visualization data structures for heatmaps and entropy profiles.

### 4.2 Dependencies

| Crate | Role |
|---|---|
| `rustre-triage` | `TriageError` (indirect, via type aliases) |
| `rustre-pe-tools` | Section table parsing |
| `rustre-crypto-id` | Crypto algorithm identification |
| `serde` / `serde-big-array` | Serialization incl. large arrays |
| `thiserror` | Typed errors |

### 4.3 Public API (lib.rs)

| Item | Kind | Description |
|---|---|---|
| `shannon_entropy(data: &[u8]) -> f64` | `fn` | H = -Σ p·log₂(p), returns 0.0–8.0 |
| `EntropyError` | `enum` | `EmptyInput`, `InvalidChunk` |
| `EntropyRating` | `enum` | `VeryLow` (<1.0) / `Low` / `Medium` / `High` / `VeryHigh` (≥7.0) |
| `SectionEntropy` | `struct` | name, entropy, size, offset, rating; `is_packed()`, `is_encrypted()` |
| `EntropyResult` | `struct` | overall + per-section + per-chunk; `packed_sections()`, `max_chunk_entropy()` |
| `EntropyAnalyzer` | `struct` | chunk-based analyzer; `analyze(data)` → `EntropyResult` |

`SectionEntropy` thresholds:

```rust
pub fn is_packed(&self) -> bool  { self.entropy > 7.0 }
pub fn is_encrypted(&self) -> bool { self.entropy > 7.5 }
```

### 4.4 Internal Modules

| Module | Role |
|---|---|
| `shannon` | Core Shannon formula variants |
| `section_entropy` | PE section table parsing + `HighEntropyBlock` detection |
| `section_entropy_analyzer` | Orchestrates per-section analysis |
| `byte_histogram` | 256-bucket byte frequency histogram |
| `histogram_analysis` | Chi-squared uniformity test, mode analysis |
| `classify` | Threshold-based region classifier |
| `anomaly` | Statistical anomaly detection |
| `randomness` | NIST-style randomness indicators |
| `compression_detector` | Compression magic byte detection |
| `compression_oracle` | Heuristic compression vs encryption disambiguation |
| `packer_detector` | Entropy-profile-based packer hints |
| `packer_entropy_profile` | Per-packer entropy profiles (UPX, MPRESS, Themida) |
| `packer_identifier` | Maps profiles to packer names |
| `entropy_heuristics` | Combined heuristic rules |
| `file_entropy_report` | `FileEntropyReport` — full per-file result |
| `entropy_viz_data` | Data model for visualization |
| `entropy_visualization` | ASCII/text entropy graph |
| `entropy_visualizer` | Higher-level visualizer |
| `heatmap_data` | 2-D heatmap data structure |
| `visual_entropy_map` | Colour-mapped entropy output |
| `casts` | Safe numeric casts (`usize_to_f64`, `f64_to_f32`, etc.) |

The `casts` module is noteworthy: it provides `#[inline(always)]` checked
conversions that replaced previous `as` casts to satisfy clippy
`cast_precision_loss` / `cast_possible_truncation` lints.

### 4.5 Completeness

**COMPLETE.** No stubs. The module count (21) is high relative to the surface
area; many secondary modules (`entropy_visualizer`, `visual_entropy_map`,
`heatmap_data`) are data-carrying types without network or OS dependencies.
Unit tests exist in `section_entropy` and `shannon`.

---

## 5. `rustre-triage-peid` — PEiD Signature Matching

### 5.1 Purpose

Identifies known packers, compilers, protectors, and runtimes in PE binaries
using the PEiD byte-pattern signature format.  Includes a built-in database
of 300+ signatures, a userdb.txt parser for community databases, an entry-point
analyzer, and a stub network updater.

### 5.2 Dependencies

| Crate | Role |
|---|---|
| `rustre-triage` | `TriageError` |
| `rayon` | Parallel signature scanning |
| `serde` / `serde_json` | Signature and result serialization |
| `thiserror` | Typed errors |

Optional `network` feature (disabled by default): reserved for future
`reqwest`/`ureq` integration in `signature_updater`.

### 5.3 Public API (lib.rs)

| Item | Kind | Description |
|---|---|---|
| `PeidError` | `enum` | `InvalidPattern`, `EmptyData` |
| `PeidCategory` | `enum` | `Packer`, `Protector`, `Compiler`, `Linker`, `Installer`, `Runtime`, `Other`, `Unknown` |
| `PeidSignature` | `struct` | name, version, `Vec<Option<u8>>` pattern, `ep_only`, category; `matches(data, offset)`, `confidence() -> f32` |
| `PeidMatch` | `struct` | signature_name, version, offset, ep_only, confidence, category |
| `ScanOptions` | `struct` | max_matches, ep_only_strict, scan_sections, min_pattern_length |
| `make_sig` / `b()` / `wc()` | `fn` | Internal helpers (fixed byte `Some(v)`, wildcard `None`) |

`PeidSignature::confidence()` formula:

```rust
let specificity = fixed_bytes as f32 / len as f32;
let length_bonus = (len as f32 / 64.0).min(1.0);
0.5f32.mul_add(specificity, 0.5 * length_bonus).min(1.0)
```

### 5.4 Internal Modules

| Module | Role |
|---|---|
| `peid_db` | `PeidDb` — 300+ built-in signatures; `scan(data, ep_offset)`, `scan_ep(data, ep_offset)` |
| `peid_signature_matcher` | Pattern matching engine |
| `userdb_parser` | Parses community `userdb.txt` files |
| `ep_analyzer` | Entry-point detection and validation |
| `linker_detector` | Linker fingerprinting from PE rich header |
| `compiler_detector` | Compiler identification (MSVC, GCC, Clang, Rust, Go, Delphi, etc.) |
| `section_analyzer` | Section name + characteristic fingerprinting |
| `overlay_extractor` | Extracts and categorizes overlay data |
| `pe_anomaly_detector` | Header anomaly detection (mismatched sizes, invalid offsets) |
| `peid_extended` | Extended result type with multi-layer hits |
| `peid_deep_scan` | Multi-pass deep scan combining all sub-analyzers |
| `signature_updater` | Network downloader (STUB, `#[cfg(feature = "network")]`) |

**Gap — network updater:**

```rust
// signature_updater.rs
/// Download raw text from a URL (requires a network-capable runtime).
/// This is a stub — in a real implementation, use reqwest or ureq.
#[cfg(feature = "network")]
// Stub: would use reqwest::blocking::get(url).
```

The `network` feature is declared in `Cargo.toml` but `reqwest`/`ureq` are not
in `[dependencies]`; the download path is never compiled in a default build.
All other modules are functional.

### 5.5 Completeness

**PARTIAL** (network updating stub).  Core scanning (built-in db + userdb.txt)
is complete. The `network` feature is a planned extension, not a regression.
Rayon parallelism is wired in `peid_db::PeidDb::scan`.

---

## 6. `rustre-triage-yara` — YARA-like Rule Engine

### 6.1 Purpose

A pure-Rust YARA-compatible rule engine: text/hex/regex string matching,
boolean conditions, metadata, tags, PE module integration, and a stack-based
bytecode VM backed by Aho-Corasick for multi-pattern acceleration.

### 6.2 Dependencies

| Crate | Role |
|---|---|
| `rustre-triage` | Shared triage types |
| `anyhow` | Error propagation in `rule_compiler` |
| `thiserror` | Typed VM/scanner errors |
| `serde` / `serde_json` | Rule/match serialization |

No `yara-sys` / `yara` C bindings — fully native implementation.

### 6.3 Public API (lib.rs)

| Item | Kind | Description |
|---|---|---|
| `YaraRule` | `struct` | Legacy rule: name + `Vec<Pattern>` (kept for compatibility) |
| `Pattern` | `enum` | `Hex(Vec<u8>)` or `Text(String)` |
| `YaraMatch` | `struct` | Legacy match: rule_name, pattern_index, offset |
| `scan_data(rules, data)` | `fn` | Non-overlapping legacy scan |
| `YaraError` | `enum` | `EmptyPattern`, `DuplicateRule`, `Other` |
| `YaraTriageRule` | `struct` | Extended rule with strings, condition_all, metadata, tags |
| `YaraTriageMatch` | `struct` | Extended match with metadata, tags, severity |
| `YaraTriageEngine` | `struct` | Manages `YaraTriageRule` set; `add_rule`, `scan` |

`scan_data` uses non-overlapping semantics (advances by `needle.len()` after
match) to prevent O(n·m) output growth on large inputs.

### 6.4 Internal Modules

| Module | Role |
|---|---|
| `yara_vm` | Stack-based bytecode VM; `YaraOpcode`, `YaraVm`, `AhoCorasick`, `CompiledRule`, `MatchContext` |
| `rule_compiler` | Tokenizer + AST + compiler: `YaraToken`, `YaraAst`, `RuleCompiler` |
| `yara_scanner` | `YaraScanner` — rayon parallel, file/buffer/memory targets, `ScanStats` |
| `yara_cache` | LRU rule cache |
| `yara_ruleset_manager` | Load/save/update rule sets |
| `yara_rule_optimizer` | Dead-string elimination, pattern deduplication |
| `rule_optimizer` | Alternative optimizer (string interning) |
| `yara_module_pe` | PE module: section table, imports, exports for condition context |
| `yara_performance_profiler` | Per-rule timing and hit-rate tracking |
| `yara_match_reporter` | Structured match report formatting |
| `match_report` | `MatchReport` aggregate type |
| `verdict` | `Verdict` enum: `Clean` / `Suspicious` / `Malicious` |
| `family_classifier` | Maps rule tags to malware family names |
| `ioc_extractor` | Extracts IPs, URLs, hashes from matches |
| `yara_threat_intel` | Threat intelligence enrichment |
| `yara_threat_tagger` | Auto-tag rules from pattern content |

The VM opcode set (`yara_vm::YaraOpcode`):

```
Literals:  PushInt, PushBool, PushFilesize, PushEntrypoint
Strings:   StringMatch, StringCount, StringAt, StringIn
Arithmetic: AddInt, SubInt, MulInt, DivInt, ModInt
Boolean:   And, Or, Not
Compare:   Eq, NEq, Lt, Le, Gt, Ge
Control:   Jump, JumpIfFalse, Halt
```

Aho-Corasick is used to accelerate multi-pattern search; `MatchContext` carries
string match tables so the VM does not re-scan for each opcode.

### 6.5 Completeness

**COMPLETE.** No stubs. The legacy `YaraRule`/`scan_data` API is preserved for
backward compatibility alongside the extended `YaraTriageEngine`. The rule
compiler supports the full YARA token set including `HexString` with wildcards,
`RegexString`, `for`/`of`/`them` operators, and all comparison tokens. The
`anyhow` dependency in `rule_compiler` (vs `thiserror` elsewhere) is the only
minor inconsistency.

---

## 7. Cross-Cutting Analysis

### 7.1 Dependency Matrix

| Crate | rustre-triage | rustre-pe-tools | rustre-crypto-id | rayon | anyhow |
|---|:---:|:---:|:---:|:---:|:---:|
| rustre-triage | — | yes | yes | — | — |
| rustre-triage-die | yes | — | — | — | — |
| rustre-triage-entropy | yes | yes | yes | — | — |
| rustre-triage-peid | yes | — | — | yes | — |
| rustre-triage-yara | yes | — | — | — | yes |

### 7.2 Completeness Summary

| Crate | Status | Stubs / Gaps |
|---|---|---|
| `rustre-triage` | **Complete** | None |
| `rustre-triage-die` | **Complete** | None; dual-scanner intentional |
| `rustre-triage-entropy` | **Complete** | None |
| `rustre-triage-peid` | **Partial** | `signature_updater` network path is a stub behind `network` feature (no HTTP dep) |
| `rustre-triage-yara` | **Complete** | None; `anyhow` inconsistency in `rule_compiler` |

### 7.3 Integration Points with MCP Server

The MCP server (`rustre-mcp-server`) consumes this group primarily through
`rustre-triage`:

- `triage_core_run_pipeline` → `TriagePipeline::default_pipeline().run(data)`
- `triage_core_extract_strings` → `AllStringExtractionStage` result in `TriageResult::all_strings`
- `triage_core_crypto_scan` → `CryptoConstantScanStage` result in `TriageResult::crypto_hits`

The sub-crates (`die`, `entropy`, `peid`, `yara`) are **not yet wired** as
`PipelineStage` implementations inside `rustre-triage`. Each has its own
scanning API but no `impl PipelineStage for ...` bridge. Wiring them would
require adapter types in either `rustre-triage` or the MCP server.

### 7.4 Known Architectural Tensions

1. **Dual DIE scanners** — `rustre-triage-die` has two `DieScanner` structs in
   separate modules with incompatible rule schemas. The `die_scanner` module
   is the canonical EP-aware implementation; `scanner` is an alternative.
   Callers must pick one explicitly.

2. **PEiD type duplication** — `PeidSignature` is defined twice: once in
   `lib.rs` (with `Vec<Option<u8>> pattern` and `ep_only`) and again in
   `peid_db.rs` (with `bytes` and `at_ep`). The `peid_db` variant is the
   production one; the `lib.rs` variant appears to be a simplified API copy.

3. **No `todo!`/`unimplemented!`** — confirmed via workspace grep; all branches
   return real values or propagate errors.

4. **Missing `PipelineStage` bridges** — to fully integrate `die`, `entropy`,
   `peid`, and `yara` into the default pipeline, each needs a thin
   `PipelineStage` wrapper. This is the main extension gap for the group.

### 7.5 IDA Pro Comparison Relevance

| IDA capability | Covered by | Status |
|---|---|---|
| Packer/compiler ID (DIE-style) | `rustre-triage-die` | Complete |
| Entropy analysis | `rustre-triage-entropy` | Complete |
| PEiD signatures | `rustre-triage-peid` | Complete (no network update) |
| YARA scanning | `rustre-triage-yara` | Complete |
| Crypto constant detection | `rustre-triage` + `rustre-crypto-id` | Complete (wired) |
| Threat scoring | `rustre-triage` | Complete |
| Family classification | `rustre-triage-yara::family_classifier` | Present |
| MITRE ATT&CK mapping | `rustre-triage::mitre_mapper` | Present |
