# rustre-yara

Pure-Rust YARA-compatible rule engine for the RustRE Suite. Provides rule
parsing, pattern matching (text, hex, regex, xor, wide, nocase, fullword),
condition evaluation, scanning, ELF module support, match correlation and
directory scan reporting.

## Cargo.toml

- name: `rustre-yara`
- version: `0.1.0`
- edition: `2024`
- license/description/repository/keywords/categories/authors: workspace
- lints: workspace

### Dependencies (workspace)

serde, serde_json, thiserror, anyhow, petgraph, sha2, tokio, tracing,
regex, hex, rayon, aho-corasick, bitflags.

## Modules (`pub mod`)

- `condition_eval`
- `match_correlator`
- `module_elf`
- `rule_compiler`
- `rule_language`
- `rule_optimizer`
- `rule_parser`
- `scan_context`
- `scanner_engine`
- `yara_integration`
- `yara_condition_evaluator`
- `yara_compiler`
- `yara_module_elf`
- `yara_scanner`

## Public Error type

- `enum YaraError { ParseError{line,message}, CompileError, ScanError,
  UnknownIdentifier, TypeError }` — implements `Display` + `Error`.

## Selected public functions

### `lib.rs` (top-level)

Rule model / accessors:

- `YaraRule::new(name) -> Self`
- `YaraRule::get_meta(&self, key) -> Option<&YaraMetaValue>`
- `YaraRule::description(&self) -> Option<String>`
- `YaraRule::author(&self) -> Option<String>`
- `YaraRule::date(&self) -> Option<String>`
- `YaraRuleSet::new() -> Self`
- `YaraRuleSet::add_rule(&mut self, rule)`
- `YaraRuleSet::rule_by_name(&self, name) -> Option<&YaraRule>`

Pattern matching primitives:

- `match_hex(pattern: &[HexToken], data: &[u8]) -> Vec<usize>`
- `match_text(text, modifiers: &StringModifiers, data) -> Vec<usize>`
- `match_nocase(text, data) -> Vec<usize>`
- `match_wide(text, data) -> Vec<usize>`
- `match_xor(text, xor_min, xor_max, data) -> Vec<(usize,u8)>`
- `check_fullword(data, offset, len) -> bool`

Parser:

- `parse(input) -> Result<YaraRuleSet, YaraError>`
- `parse_rule(input) -> Result<YaraRule, YaraError>`
- `parse_meta_section(body) -> Result<Vec<YaraMeta>, YaraError>`
- `parse_strings_section(body) -> Result<Vec<YaraString>, YaraError>`
- `parse_condition_section(body) -> Result<YaraCondition, YaraError>`
- `parse_hex_pattern(input) -> Result<Vec<HexToken>, YaraError>`
- `parse_string_modifiers(tokens: &[&str]) -> StringModifiers`

Scan context:

- `ScanContext::new(data) -> Self`
- `ScanContext::string_count(&self, id) -> usize`
- `ScanContext::string_offset(&self, id, nth) -> Option<u64>`
- `ScanContext::string_matched(&self, id) -> bool`

Scanner / evaluator:

- `Scanner::from_rules_text(text) -> Result<Self, YaraError>`
- `Scanner::scan(&self, data) -> Result<Vec<YaraMatch>, YaraError>`
- `Scanner::scan_with_base(&self, data, base) -> Result<Vec<YaraMatch>, YaraError>`
- `Scanner::evaluate_rule(&self, rule, ctx) -> Result<bool, YaraError>`
- `Scanner::collect_string_matches<'a>(&self, rule, data) -> ScanContext<'a>`
- `eval_condition(cond, ctx) -> Result<bool, YaraError>`
- `eval_expr(expr, ctx) -> Result<i64, YaraError>`

Reporting / triage:

- `YaraScanReport::new(...)` and `::from_tags(tags)`
- `YaraScanReport::to_json(&self) -> serde_json::Value`
- `YaraScanReport::first_pattern_offset/has_tag/all_tags/severity`
- `YaraScanSummary::new(...)`, `severity`, `to_markdown`, `to_json`
- `scan_directory(...)`
- `filter_interesting(...)`
- `total_matches(reports) -> usize`
- `filter_by_severity(...)`
- `summary(reports) -> String`

### `rule_parser.rs`

- `pub fn parse_rules(src: &str) -> Result<Vec<YaraRule>, YaraError>`
- `pub fn parse_rule(src: &str) -> Result<YaraRule, YaraError>`

### `yara_module_elf.rs`

- `pub fn parse_elf32(data: &[u8]) -> Result<ElfModuleData, ElfParseError>`
- `pub fn parse_elf64(data: &[u8]) -> Result<ElfModuleData, ElfParseError>`

### `match_correlator.rs`

- `pub fn compute_stats(results: &[FileScanResult], correlation: &CorrelationResult) -> CorrelationStats`

## Testability

The crate exposes pure functions over `&[u8]` / `&str` inputs and returns
deterministic `Result<_, YaraError>` values, making it directly unit-testable
without I/O. `scan_directory` is the only filesystem-bound entry point.
