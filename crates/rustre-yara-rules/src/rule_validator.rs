//! `rule_validator` — YARA rule validation: syntax check, performance analysis
//! (high-entropy strings, pathological regexes), false-positive rate estimation,
//! and logic analysis.

use serde::{Deserialize, Serialize};

use crate::Result;

// ── Severity ──────────────────────────────────────────────────────────────────

/// Severity of a validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info     => write!(f, "INFO"),
            Self::Warning  => write!(f, "WARN"),
            Self::Error    => write!(f, "ERROR"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ── Finding ───────────────────────────────────────────────────────────────────

/// A single validation finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationFinding {
    pub severity: FindingSeverity,
    pub code: String,
    pub rule_name: String,
    pub string_id: Option<String>,
    pub message: String,
    pub suggestion: Option<String>,
    pub line: Option<usize>,
}

impl ValidationFinding {
    fn new(
        sev: FindingSeverity,
        code: impl Into<String>,
        rule: impl Into<String>,
        msg: impl Into<String>,
    ) -> Self {
        Self {
            severity: sev,
            code: code.into(),
            rule_name: rule.into(),
            string_id: None,
            message: msg.into(),
            suggestion: None,
            line: None,
        }
    }

    fn with_string(mut self, id: impl Into<String>) -> Self {
        self.string_id = Some(id.into());
        self
    }

    fn with_suggestion(mut self, s: impl Into<String>) -> Self {
        self.suggestion = Some(s.into());
        self
    }
}

// ── Validation result ─────────────────────────────────────────────────────────

/// Complete validation result for a single rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub rule_name: String,
    pub is_valid: bool,
    pub findings: Vec<ValidationFinding>,
    /// Estimated false-positive rate per 1 GB of random data (0.0–1.0).
    pub fp_rate_estimate: f64,
    /// Estimated relative scan cost (higher = slower).
    pub perf_score: u32,
    /// Overall quality score 0–100.
    pub quality_score: u8,
}

impl ValidationResult {
    fn new(name: impl Into<String>) -> Self {
        Self {
            rule_name: name.into(),
            is_valid: true,
            findings: Vec::new(),
            fp_rate_estimate: 0.0,
            perf_score: 0,
            quality_score: 100,
        }
    }

    fn add_finding(&mut self, f: ValidationFinding) {
        if f.severity == FindingSeverity::Error || f.severity == FindingSeverity::Critical {
            self.is_valid = false;
        }
        self.findings.push(f);
    }

    fn error_count(&self) -> usize {
        self.findings.iter().filter(|f| {
            f.severity == FindingSeverity::Error || f.severity == FindingSeverity::Critical
        }).count()
    }

    fn warning_count(&self) -> usize {
        self.findings.iter().filter(|f| f.severity == FindingSeverity::Warning).count()
    }

    fn compute_quality_score(&mut self) {
        let base: i32 = 100;
        let deductions =
            (crate::casts::usize_to_i32_sat(self.error_count()).saturating_mul(30)) +
            (crate::casts::usize_to_i32_sat(self.warning_count()).saturating_mul(10)) +
            i32::from(self.fp_rate_estimate > 0.01) * 20 +
            i32::from(self.perf_score > 1000) * 15;
        self.quality_score = crate::casts::i32_to_u8_sat((base - deductions).max(0));
    }
}

// ── Validator ─────────────────────────────────────────────────────────────────

/// Validation options.
#[derive(Debug, Clone)]
pub struct ValidatorOptions {
    /// Minimum string length (shorter strings increase FP rate).
    pub min_string_len: usize,
    /// Maximum regex complexity before flagging as a performance risk.
    pub max_regex_nodes: usize,
    /// Whether to run logic analysis (dead conditions, etc.).
    pub check_logic: bool,
    /// Whether to estimate false-positive rates.
    pub estimate_fp: bool,
    /// Minimum number of distinguishing strings required per rule.
    pub min_strings: usize,
}

impl Default for ValidatorOptions {
    fn default() -> Self {
        Self {
            min_string_len: 4,
            max_regex_nodes: 500,
            check_logic: true,
            estimate_fp: true,
            min_strings: 1,
        }
    }
}

/// Multi-rule YARA validator.
pub struct RuleValidator {
    options: ValidatorOptions,
}

impl RuleValidator {
    #[must_use] 
    pub fn new() -> Self {
        Self::with_options(ValidatorOptions::default())
    }

    #[must_use] 
    pub const fn with_options(options: ValidatorOptions) -> Self {
        Self { options }
    }

    /// Validate a single YARA rule from source text.
    ///
    /// # Errors
    /// Currently infallible; the `Result` is reserved for future syntax
    /// failures surfaced by the underlying parser.
    pub fn validate_source(&self, source: &str) -> Result<ValidationResult> {
        // Parse out the rule name
        let name = extract_first_rule_name(source).unwrap_or_else(|| "unknown".to_string());
        let mut result = ValidationResult::new(&name);

        // 1. Syntax check
        Self::check_syntax(source, &mut result);

        // 2. String quality checks
        self.check_strings(source, &mut result);

        // 3. Regex performance
        self.check_regex_performance(source, &mut result);

        // 4. High-entropy string detection
        Self::check_entropy_strings(source, &mut result);

        // 5. Logic analysis
        if self.options.check_logic {
            Self::check_logic(source, &mut result);
        }

        // 6. FP rate estimation
        if self.options.estimate_fp {
            result.fp_rate_estimate = Self::estimate_fp_rate(source);
        }

        // 7. Performance score
        result.perf_score = Self::estimate_perf_score(source);

        // 8. Quality score
        result.compute_quality_score();

        Ok(result)
    }

    /// Validate multiple rules from a source file.
    ///
    /// # Errors
    /// Propagates the error of [`Self::validate_source`] for any contained rule.
    pub fn validate_file(&self, source: &str) -> Result<Vec<ValidationResult>> {
        let rules = split_rules(source);
        rules.iter().map(|r| self.validate_source(r)).collect()
    }

    // ── Syntax check ──────────────────────────────────────────────────────────

    fn check_syntax(source: &str, result: &mut ValidationResult) {
        // Check for basic structural requirements
        if !source.contains("rule ") {
            result.add_finding(ValidationFinding::new(
                FindingSeverity::Critical,
                "SYN001",
                &result.rule_name,
                "No 'rule' keyword found",
            ));
        }
        if !source.contains("condition:") {
            result.add_finding(ValidationFinding::new(
                FindingSeverity::Error,
                "SYN002",
                &result.rule_name,
                "Missing 'condition:' section",
            ).with_suggestion("Add a 'condition:' block with at least 'any of them'"));
        }
        // Balanced braces
        let open = source.chars().filter(|&c| c == '{').count();
        let close = source.chars().filter(|&c| c == '}').count();
        if open != close {
            result.add_finding(ValidationFinding::new(
                FindingSeverity::Error,
                "SYN003",
                &result.rule_name,
                format!("Unbalanced braces: {open} open, {close} close"),
            ));
        }
        // Missing meta section (warning only)
        if !source.contains("meta:") {
            result.add_finding(ValidationFinding::new(
                FindingSeverity::Info,
                "META001",
                &result.rule_name,
                "No 'meta:' section — consider adding author/date/description",
            ));
        }
        // Check for missing author
        if source.contains("meta:") && !source.contains("author") {
            result.add_finding(ValidationFinding::new(
                FindingSeverity::Info,
                "META002",
                &result.rule_name,
                "No 'author' metadata field",
            ));
        }
    }

    // ── String quality ─────────────────────────────────────────────────────────

    fn check_strings(&self, source: &str, result: &mut ValidationResult) {
        let string_defs = extract_string_defs(source);
        let min_len = self.options.min_string_len;
        let min_strings = self.options.min_strings;

        if string_defs.is_empty() {
            // Rules with no strings are valid but unusual
            result.add_finding(ValidationFinding::new(
                FindingSeverity::Info,
                "STR000",
                &result.rule_name,
                "No string definitions — condition-only rule",
            ));
            return;
        }

        if string_defs.len() < min_strings {
            result.add_finding(ValidationFinding::new(
                FindingSeverity::Warning,
                "STR001",
                &result.rule_name,
                format!("Only {} string(s) defined; {} recommended", string_defs.len(), min_strings),
            ));
        }

        for (id, value) in &string_defs {
            let clean_value = value.trim_matches('"').trim_matches('{').trim_matches('}').trim();

            // Short string warning
            if clean_value.len() < min_len && !value.starts_with('{') {
                result.add_finding(ValidationFinding::new(
                    FindingSeverity::Warning,
                    "STR002",
                    &result.rule_name,
                    format!("String '{}' is very short ({} chars) — high FP risk", id, clean_value.len()),
                ).with_string(id).with_suggestion("Use at least 6-byte strings for low FP rates"));
            }

            // All-null or all-zero hex pattern
            if value.starts_with('{') && is_all_zeros(clean_value) {
                result.add_finding(ValidationFinding::new(
                    FindingSeverity::Error,
                    "STR003",
                    &result.rule_name,
                    format!("String '{id}' is all zeros/wildcards — always matches"),
                ).with_string(id));
            }

            // Detect common generic strings that cause high FP
            if is_generic_string(clean_value) {
                result.add_finding(ValidationFinding::new(
                    FindingSeverity::Warning,
                    "STR004",
                    &result.rule_name,
                    format!("String '{id}' contains a generic pattern ('{clean_value}') that may produce many FP"),
                ).with_string(id));
            }

            // Wide string without modifiers warning
            if clean_value.contains("\\x00") && !value.contains("wide") {
                result.add_finding(ValidationFinding::new(
                    FindingSeverity::Info,
                    "STR005",
                    &result.rule_name,
                    format!("String '{id}' looks like a wide string but lacks 'wide' modifier"),
                ).with_string(id).with_suggestion("Add 'wide' modifier"));
            }
        }
    }

    // ── Regex performance ─────────────────────────────────────────────────────

    fn check_regex_performance(&self, source: &str, result: &mut ValidationResult) {
        for (id, value) in extract_string_defs(source) {
            if !value.starts_with('/') { continue; }
            let regex = value.trim_matches('/');

            // Backtracking catastrophe patterns
            if has_catastrophic_backtracking(regex) {
                result.add_finding(ValidationFinding::new(
                    FindingSeverity::Error,
                    "RE001",
                    &result.rule_name,
                    format!("Regex '{id}' has catastrophic backtracking risk (nested quantifiers)"),
                ).with_string(&id).with_suggestion("Avoid patterns like (a+)+ or (a|b)*c"));
            }

            // Very broad dot-star patterns
            if regex.contains(".*") || regex.contains(".+") {
                result.add_finding(ValidationFinding::new(
                    FindingSeverity::Warning,
                    "RE002",
                    &result.rule_name,
                    format!("Regex '{id}' uses .* or .+ — may be slow on large files"),
                ).with_string(&id));
            }

            // Estimate regex node count
            let node_count = estimate_regex_complexity(regex);
            if node_count > self.options.max_regex_nodes {
                result.add_finding(ValidationFinding::new(
                    FindingSeverity::Warning,
                    "RE003",
                    &result.rule_name,
                    format!("Regex '{id}' is complex (~{node_count} nodes); consider simplification"),
                ).with_string(&id));
            }
        }
    }

    // ── Entropy strings ────────────────────────────────────────────────────────

    fn check_entropy_strings(source: &str, result: &mut ValidationResult) {
        for (id, value) in extract_string_defs(source) {
            if !value.starts_with('{') { continue; }
            let bytes = parse_hex_string(&value);
            if bytes.len() < 8 { continue; }
            let entropy = shannon_entropy(&bytes);
            if entropy > 7.2 {
                result.add_finding(ValidationFinding::new(
                    FindingSeverity::Info,
                    "ENT001",
                    &result.rule_name,
                    format!("Hex string '{id}' has high entropy ({entropy:.2}) — may be a packed/encrypted signature"),
                ).with_string(&id));
            }
        }
    }

    // ── Logic analysis ────────────────────────────────────────────────────────

    fn check_logic(source: &str, result: &mut ValidationResult) {
        let condition = extract_condition(source);

        // Trivially true condition
        if condition.trim() == "true" {
            result.add_finding(ValidationFinding::new(
                FindingSeverity::Error,
                "LOG001",
                &result.rule_name,
                "Condition is trivially 'true' — matches every file",
            ));
        }

        // Unused strings
        let string_defs = extract_string_defs(source);
        for (id, _) in &string_defs {
            let bare_id = id.trim_start_matches('$');
            if !condition.contains(id) && !condition.contains(bare_id)
                && !condition.contains("any of them")
                && !condition.contains("all of them")
                && !condition.contains("none of them")
                && !condition.contains("any of ($")
                && !condition.contains("of them")
            {
                result.add_finding(ValidationFinding::new(
                    FindingSeverity::Warning,
                    "LOG002",
                    &result.rule_name,
                    format!("String '{id}' defined but not referenced in condition"),
                ).with_string(id));
            }
        }

        // Filesize = 0 is suspicious
        if condition.contains("filesize == 0") || condition.contains("filesize = 0") {
            result.add_finding(ValidationFinding::new(
                FindingSeverity::Warning,
                "LOG003",
                &result.rule_name,
                "Condition requires filesize == 0 — only matches empty files",
            ));
        }

        // Very large filesize limit
        if condition.contains("filesize >") {
            result.add_finding(ValidationFinding::new(
                FindingSeverity::Info,
                "LOG004",
                &result.rule_name,
                "Condition uses filesize constraint — ensure the limit is intentional",
            ));
        }
    }

    // ── FP rate estimation ────────────────────────────────────────────────────

    fn estimate_fp_rate(source: &str) -> f64 {
        let defs = extract_string_defs(source);
        if defs.is_empty() { return 0.0; }

        // Estimate probability that a random 1 GB file contains any of the strings.
        // For a literal of length L, P ≈ 1 - (1 - 1/256^L)^N where N = 1e9 - L + 1.
        let mut total_fp = 0.0f64;
        for (_, value) in &defs {
            let clean = value.trim_matches('"');
            let len = if value.starts_with('"') {
                clean.len()
            } else if value.starts_with('{') {
                parse_hex_string(value).len()
            } else {
                continue;
            };
            if len == 0 { total_fp += 1.0; continue; }
            // Cap the exponent at 38 (≈ 256^-38 is below f64 min positive normal).
            // Casting len directly to i32 would wrap for len > i32::MAX; use min() first.
            let exp = i32::try_from(len.min(38)).unwrap_or(38);
            let prob_per_byte = (256f64).powi(-exp);
            let n = 1_000_000_000f64;
            let fp = 1.0 - (1.0 - prob_per_byte).powf(n);
            total_fp = total_fp.max(fp);
        }
        total_fp.min(1.0)
    }

    // ── Performance score ─────────────────────────────────────────────────────

    fn estimate_perf_score(source: &str) -> u32 {
        let defs = extract_string_defs(source);
        let mut score = 0u32;
        for (_, value) in &defs {
            if value.starts_with('/') {
                score += crate::casts::usize_to_u32_sat(estimate_regex_complexity(value.trim_matches('/')));
            } else if value.starts_with('"') {
                let len = value.trim_matches('"').len();
                score += if len < 4 { 100 } else if len < 8 { 20 } else { 5 };
            } else if value.starts_with('{') {
                let bytes = parse_hex_string(value);
                score += if bytes.is_empty() { 50 } else { 10 };
            }
        }
        score
    }
}

impl Default for RuleValidator {
    fn default() -> Self { Self::new() }
}

// ── Batch validator ───────────────────────────────────────────────────────────

/// Validate a collection of rules and produce an aggregate summary.
pub struct BatchValidationReport {
    pub results: Vec<ValidationResult>,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub warnings: usize,
    pub high_fp_rules: Vec<String>,
    pub slow_rules: Vec<String>,
}

impl BatchValidationReport {
    #[must_use] 
    pub fn build(results: Vec<ValidationResult>) -> Self {
        let total = results.len();
        let passed = results.iter().filter(|r| r.is_valid).count();
        let failed = total - passed;
        let warnings = results.iter().flat_map(|r| &r.findings)
            .filter(|f| f.severity == FindingSeverity::Warning)
            .count();
        let high_fp_rules = results.iter()
            .filter(|r| r.fp_rate_estimate > 0.001)
            .map(|r| r.rule_name.clone())
            .collect();
        let slow_rules = results.iter()
            .filter(|r| r.perf_score > 500)
            .map(|r| r.rule_name.clone())
            .collect();
        Self { results, total, passed, failed, warnings, high_fp_rules, slow_rules }
    }

    #[must_use] 
    pub fn validate_all(validator: &RuleValidator, sources: &[(String, String)]) -> Self {
        let results = sources.iter()
            .filter_map(|(_, src)| validator.validate_source(src).ok())
            .collect();
        Self::build(results)
    }
}

// ── Analysis helpers ──────────────────────────────────────────────────────────

fn extract_first_rule_name(source: &str) -> Option<String> {
    let bytes = source.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        if pos + 5 < bytes.len() && &bytes[pos..pos + 4] == b"rule" && bytes[pos + 4].is_ascii_whitespace() {
            pos += 5;
            while pos < bytes.len() && bytes[pos].is_ascii_whitespace() { pos += 1; }
            let start = pos;
            while pos < bytes.len() && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_') {
                pos += 1;
            }
            if pos > start {
                return Some(String::from_utf8_lossy(&bytes[start..pos]).to_string());
            }
        } else {
            pos += 1;
        }
    }
    None
}

fn extract_string_defs(source: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut in_strings = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed == "strings:" { in_strings = true; continue; }
        if trimmed == "condition:" || trimmed == "meta:" { in_strings = false; }
        if !in_strings { continue; }
        if trimmed.starts_with('$')
            && let Some(eq) = trimmed.find('=') {
                let id = trimmed[..eq].trim().to_string();
                let value = trimmed[eq + 1..].trim().to_string();
                result.push((id, value));
            }
    }
    result
}

fn extract_condition(source: &str) -> String {
    let mut in_condition = false;
    let mut lines = Vec::new();
    let mut depth = 0i32;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed == "condition:" { in_condition = true; continue; }
        if in_condition {
            for c in trimmed.chars() {
                if c == '{' { depth += 1; }
                if c == '}' { depth -= 1; }
            }
            if depth < 0 { break; }
            lines.push(trimmed.to_string());
        }
    }
    lines.join(" ")
}

fn split_rules(source: &str) -> Vec<String> {
    let mut rules = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    let mut in_rule = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("rule ") && depth == 0 {
            if !current.is_empty() && in_rule {
                rules.push(current.clone());
                current.clear();
            }
            in_rule = true;
        }
        if in_rule {
            for c in line.chars() {
                if c == '{' { depth += 1; }
                if c == '}' { depth -= 1; }
            }
            current.push_str(line);
            current.push('\n');
            if depth == 0 && in_rule && !current.trim().is_empty() {
                rules.push(current.clone());
                current.clear();
                in_rule = false;
            }
        }
    }
    if !current.is_empty() && in_rule {
        rules.push(current);
    }
    rules
}

fn is_all_zeros(hex: &str) -> bool {
    hex.split_whitespace().all(|b| b == "00" || b == "??" || b == "0" || b.is_empty())
}

fn is_generic_string(value: &str) -> bool {
    const GENERIC: &[&str] = &[
        "This program cannot be run in DOS mode",
        "!This Program",
        "PE\x00\x00",
        "MZ",
        ".text",
        ".data",
        "kernel32.dll",
        "KERNEL32",
        ".exe",
        ".dll",
    ];
    GENERIC.iter().any(|g| value.contains(g))
}

fn has_catastrophic_backtracking(regex: &str) -> bool {
    // Detect nested quantifiers: `(X+)+`, `(X*)+`, `(X+)*` — the shape that
    // makes a backtracking engine try exponentially many splits.
    //
    // ⚠ The scan used to run `for i in 0..len.saturating_sub(4)`, which cannot
    // reach the pattern it is looking for. The smallest input that exhibits the
    // defect is `(a+)+b`: the inner `+` sits at index 2 and `len - 4` is also 2,
    // so the loop stopped one index short and returned false. The detector was
    // therefore blind to its own canonical example — `test_catastrophic_
    // backtracking_detection` asserted exactly that case and had been failing.
    //
    // Three bytes are inspected per position, so the last valid start is
    // `len - 3`; the bound is `len - 2` because the range is exclusive.
    let bytes = regex.as_bytes();
    for i in 0..bytes.len().saturating_sub(2) {
        let inner_quantifier = matches!(bytes[i], b'+' | b'*' | b'?');
        let closes_group = bytes[i + 1] == b')';
        let outer_quantifier = matches!(bytes[i + 2], b'+' | b'*');
        if inner_quantifier && closes_group && outer_quantifier {
            return true;
        }
    }
    false
}

fn estimate_regex_complexity(regex: &str) -> usize {
    // Rough heuristic: count operators
    regex.chars().map(|c| match c {
        '|' => 10,
        '*' | '+' | '?' => 5,
        '[' => 8,
        '{' => 6,
        '(' => 4,
        '.' => 3,
        _ => 1,
    }).sum()
}

fn parse_hex_string(value: &str) -> Vec<u8> {
    let inner = value.trim().trim_start_matches('{').trim_end_matches('}');
    let mut result = Vec::new();
    for tok in inner.split_whitespace() {
        if tok == "??" || tok.contains('?') { continue; }
        if tok.len() == 2
            && let Ok(b) = u8::from_str_radix(tok, 16) {
                result.push(b);
            }
    }
    result
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = crate::casts::usize_to_f64(data.len());
    let mut h = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(c) / len;
            h -= p * p.log2();
        }
    }
    h.clamp(0.0, 8.0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_RULE: &str = r#"
rule good_rule {
    meta:
        author = "Test"
        date = "2024-01-01"
    strings:
        $a = "MalwareSignature12345"
        $b = { DE AD BE EF CA FE BA BE }
    condition:
        any of them
}
"#;

    const BAD_RULE: &str = r#"
rule bad_rule {
    strings:
        $a = "MZ"
    condition:
        $a
}
"#;

    #[test]
    fn test_good_rule_passes() {
        let v = RuleValidator::new();
        let result = v.validate_source(GOOD_RULE).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.error_count(), 0);
    }

    #[test]
    fn test_short_string_warning() {
        let v = RuleValidator::new();
        let result = v.validate_source(BAD_RULE).unwrap();
        // Should have short string warning and generic string warning
        let has_str_warn = result.findings.iter().any(|f| {
            f.code == "STR002" || f.code == "STR004"
        });
        assert!(has_str_warn, "expected string quality warning");
    }

    #[test]
    fn test_missing_condition() {
        let src = "rule no_cond {\n    strings:\n        $a = \"test\"\n}";
        let v = RuleValidator::new();
        let result = v.validate_source(src).unwrap();
        assert!(!result.is_valid);
    }

    #[test]
    fn test_catastrophic_backtracking_detection() {
        assert!(has_catastrophic_backtracking("(a+)+b"));
        assert!(!has_catastrophic_backtracking("abc.*def"));
    }

    #[test]
    fn test_fp_rate_long_string() {
        let v = RuleValidator::new();
        let src = r#"rule fp_test {
    strings:
        $a = "ThisIsAVeryLongAndUniqueMalwareString"
    condition:
        $a
}"#;
        let result = v.validate_source(src).unwrap();
        assert!(result.fp_rate_estimate < 0.001, "long string should have low FP rate");
    }
}
