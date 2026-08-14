# rustre-yara-rules

YARA rule management, compilation, validation, testing, generation, and detection rule libraries (APT, packers, ransomware) on top of `rustre-yara`.

## Cargo.toml

- **name**: `rustre-yara-rules`
- **version**: 0.1.0
- **edition**: 2024
- **license/description/repository/readme/keywords/categories/authors**: workspace
- **dependencies**: `rustre-yara` (path `../rustre-yara`), `anyhow`, `serde`, `serde_json`, `parking_lot`, `sha2`
- **lints**: workspace

## Public modules (`lib.rs`)

`casts`, `builtin_rules`, `rule_compiler`, `rule_db`, `rule_generator`, `rule_metadata`, `rule_repository`, `rule_testing`, `rule_validator`, `sync`, `rule_optimizer_pass`, `rule_coverage_tracker`, `apt_detection_rules`, `packer_detection_rules`, `ransomware_rules`.

### lib.rs (crate root)
- Types: `YaraRepoError`, `Result<T>`, `RuleSource`, `RuleMeta`, `RuleCategory`, `Severity`, `CompiledRuleSet`, `Match`, `StringMatch`, `SyncReport`, `RepoStats`, `RuleRepository`, `RuleFilter`.
- Fn: `popular_public_sources() -> Vec<RuleSource>`.

### casts.rs
Saturating numeric cast helpers:
- `usize_to_f64`, `u64_to_f64`, `f64_to_u32_sat`, `i32_to_u8_sat`, `usize_to_i32_sat`, `usize_to_u32_sat`, `u64_to_u8_sat`, `u128_to_u64_sat`.

### builtin_rules.rs
- Types: `RuleCategory`, `BuiltinRule`, `BuiltinRuleIndex`.
- Fn: `all_builtin_rules()`, `rules_by_category(cat)`, `builtin_source_all()`, `builtin_source_for_category(cat)`.

### rule_compiler.rs
Internal YARA-like compiler/executor.
- Types: `CompilerError`, `CompilerResult<T>`, `StringModifiers`, `PatternKind`, `CompiledPattern`, `Condition`, `OrdOp`, `YaraRule`, `StringHit`, `RuleMatch`, `RuleCompiler`, `RuleExecutor`.

### rule_db.rs
- Types: `RuleDbSeverity`, `RuleEntry`, `DbMatch`, `RuleDb`.
- Fn: `builtin_rules() -> Vec<RuleEntry>`.

### rule_generator.rs
- Types: `GeneratorOptions`, `CandidatePattern`, `GeneratedRule`, `RuleGenerator`, `CorpusTester`, `CorpusTestResult`.

### rule_metadata.rs
- Types: `TlpLevel`, `MitreAttack`, `ExternalReference`, `FamilyTag`, `RuleMetadata`, `HistoryEntry`, `IssueSeverity`, `ValidationIssue`, `MetadataBuilder`, `MetadataStore`, `MetadataStats`.
- Fn: `validate_metadata(meta) -> Vec<ValidationIssue>`, `parse_metadata_from_yara(rule_text, source_name) -> Option<RuleMetadata>`.

### rule_repository.rs
- Types: `Tlp`, `RuleMetadata`, `RepoEntry`, `RepositoryVersion`, `RuleFilter`, `RuleRepository`, `RepositoryStats`.

### rule_testing.rs
- Types: `SampleLabel`, `TestSample`, `SampleTestResult`, `TestVerdict`, `CorpusTestReport`, `TesterConfig`, `RuleTester`, `BenchmarkResult`, `RuleQualityScore`, `CorpusBuilder`, `FalsePositiveAnalysis`, `RuleTestSuite`.
- Fn: `benchmark_rule(...)`, `compute_quality_score(...)`, `analyze_false_positives(...)`, `estimate_fp_rate(rule_text, benign_samples)`, `estimate_detection_rate(rule_text, malicious_samples)`, `load_corpus_from_paths(...)`.

### rule_validator.rs
- Types: `FindingSeverity`, `ValidationFinding`, `ValidationResult`, `ValidatorOptions`, `RuleValidator`, `BatchValidationReport`.

### rule_coverage_tracker.rs
- Types: `SampleCoverage`, `RuleCoverage`, `CoverageGap`, `OverallCoverageStats`, `RuleCoverageTracker`.

### rule_optimizer_pass.rs
- Types: `PassResult`, `OptimizationPass` (trait), `AnchorFastStringPass`, `DeadStringRemovalPass`, `ConditionFoldPass`, `FilesizeBoundsPass`, `HexNormalizerPass`, `RuleOptimizerPass`.

### sync.rs
Pulls rules from upstream sources and parses `.yar` files.
- Types: `RuleSyncConfig`, `SyncResult`, `ParsedRuleFile`, `RuleSyncEngine`, `RuleFileIndex`, `RuleCache`.
- Fn: `sync_rules(config)`, `parse_rule_files_from_dir(dir)`, `parse_yar_file(path)`, `parse_yar_text(text, path)`, `popular_sources()`.

### apt_detection_rules.rs
- Types: `AptGroup`, `AptConfidence`, `AptRule`, `AptRules`.
- Static: `APT_RULE_TEXTS: &[&str]`.

### packer_detection_rules.rs
- Types: `PackerFamily`, `PackerRule`, `PackerRules`.
- Static: `PACKER_RULE_TEXTS: &[&str]`.
- Fn: `known_packer_strings() -> HashMap<&'static str, PackerFamily>`.

### ransomware_rules.rs
- Types: `RuleMetadata`, `YaraRuleText`, `RuleSet`, `RansomwareRules`.
- Static: `RANSOMWARE_RULE_TEXTS: &[&str]`.

## Testability
Pure-Rust crate with no IO-blocking required for compile/validate/optimize/test logic; `tests/` directory present. Builds standalone given workspace deps. Testable.
