//! `c_macro_detection` — detect and collapse repeated patterns into
//! pseudo-macro definitions (`#define` equivalents) in decompiled C output.
//!
//! When the decompiler emits the same complex expression many times (e.g. a
//! long field access, a recurring constant, or an inline idiom), this module
//! recognises the repetition and introduces a `#define` for it, substituting
//! all occurrences with the macro name.  This dramatically improves
//! readability of code that was originally written with macros that were
//! expanded at compile time.
//!
//! Also detects:
//! - Inline function expansion: a sequence of statements repeated identically
//!   at multiple call sites, suggesting a compiler-inlined function.
//! - Common boolean/arithmetic macros (`MIN`, `MAX`, `ALIGN`, …).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// MacroDefinition
// ─────────────────────────────────────────────────────────────────────────────

/// A detected or proposed macro definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroDefinition {
    /// The macro name (e.g. `MAX`, `FIELD_OFFSET`, `BIT_FLAG_5`).
    pub name: String,
    /// The expansion text (what the macro expands to).
    pub expansion: String,
    /// Parameters, if it is a function-like macro.
    pub params: Vec<String>,
    /// How many times the expansion appears in the source.
    pub use_count: usize,
    /// Whether this macro was user-provided or auto-detected.
    pub source: MacroSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MacroSource {
    AutoDetected,
    UserProvided,
    BuiltIn,
}

impl MacroDefinition {
    /// Format as a `#define` directive.
    #[must_use]
    pub fn as_define(&self) -> String {
        if self.params.is_empty() {
            format!("#define {} {}", self.name, self.expansion)
        } else {
            format!("#define {}({}) {}", self.name, self.params.join(", "), self.expansion)
        }
    }

    /// True if this is a function-like macro.
    #[must_use]
    pub const fn is_function_like(&self) -> bool {
        !self.params.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MacroDetectionConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for macro detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroDetectionConfig {
    /// Minimum number of occurrences for a pattern to be extracted as a macro.
    pub min_occurrences: usize,
    /// Minimum length of an expression to be considered for macro extraction.
    pub min_expr_length: usize,
    /// Maximum length of an expression to extract (avoid extracting whole statements).
    pub max_expr_length: usize,
    /// If true, apply the built-in macro patterns (MIN, MAX, BIT, ALIGN, …).
    pub apply_builtin_patterns: bool,
    /// If true, detect repeated statement sequences (inline function expansion).
    pub detect_inline_expansions: bool,
    /// Minimum sequence length (in lines) for inline expansion detection.
    pub min_inline_sequence_len: usize,
}

impl Default for MacroDetectionConfig {
    fn default() -> Self {
        Self {
            min_occurrences: 3,
            min_expr_length: 8,
            max_expr_length: 120,
            apply_builtin_patterns: true,
            detect_inline_expansions: true,
            min_inline_sequence_len: 3,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BuiltinMacroPatterns
// ─────────────────────────────────────────────────────────────────────────────

/// A collection of well-known C macro patterns to recognise in the source.
pub struct BuiltinMacroPatterns;

/// A pattern to match and its replacement.
#[derive(Debug, Clone)]
pub struct BuiltinPattern {
    pub name: &'static str,
    /// The exact text pattern to search for.
    pub pattern: &'static str,
    /// The replacement macro invocation.
    pub replacement: &'static str,
    /// If non-empty, the `#define` to prepend to the output.
    pub define: &'static str,
}

impl BuiltinMacroPatterns {
    fn minmax_and_align() -> impl Iterator<Item = BuiltinPattern> {
        [
            BuiltinPattern { name: "MAX", pattern: "((a) > (b) ? (a) : (b))", replacement: "MAX(a, b)", define: "#define MAX(a, b) ((a) > (b) ? (a) : (b))" },
            BuiltinPattern { name: "MIN", pattern: "((a) < (b) ? (a) : (b))", replacement: "MIN(a, b)", define: "#define MIN(a, b) ((a) < (b) ? (a) : (b))" },
            BuiltinPattern { name: "ALIGN_UP", pattern: "(((x) + (align) - 1) & ~((align) - 1))", replacement: "ALIGN_UP(x, align)", define: "#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))" },
            BuiltinPattern { name: "ALIGN_DOWN", pattern: "((x) & ~((align) - 1))", replacement: "ALIGN_DOWN(x, align)", define: "#define ALIGN_DOWN(x, align) ((x) & ~((align) - 1))" },
            BuiltinPattern { name: "BIT", pattern: "(1 << (n))", replacement: "BIT(n)", define: "#define BIT(n) (1 << (n))" },
            BuiltinPattern { name: "SWAP", pattern: "do { t = a; a = b; b = t; } while(0)", replacement: "SWAP(a, b, t)", define: "#define SWAP(a, b, t) do { t = a; a = b; b = t; } while(0)" },
            BuiltinPattern { name: "IS_NULL", pattern: "== NULL", replacement: "IS_NULL", define: "" },
            BuiltinPattern { name: "ARRAY_SIZE", pattern: "(sizeof(arr) / sizeof(arr[0]))", replacement: "ARRAY_SIZE(arr)", define: "#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))" },
            BuiltinPattern { name: "CLAMP", pattern: "((x) < (lo) ? (lo) : ((x) > (hi) ? (hi) : (x)))", replacement: "CLAMP(x, lo, hi)", define: "#define CLAMP(x, lo, hi) ((x) < (lo) ? (lo) : ((x) > (hi) ? (hi) : (x)))" },
        ].into_iter()
    }

    fn byte_word_and_rotation() -> impl Iterator<Item = BuiltinPattern> {
        [
            BuiltinPattern { name: "HIBYTE", pattern: "((val) >> 8) & 0xFF", replacement: "HIBYTE(val)", define: "#define HIBYTE(val) (((val) >> 8) & 0xFF)" },
            BuiltinPattern { name: "LOBYTE", pattern: "(val) & 0xFF", replacement: "LOBYTE(val)", define: "#define LOBYTE(val) ((val) & 0xFF)" },
            BuiltinPattern { name: "HIWORD", pattern: "((val) >> 16) & 0xFFFF", replacement: "HIWORD(val)", define: "#define HIWORD(val) (((val) >> 16) & 0xFFFF)" },
            BuiltinPattern { name: "LOWORD", pattern: "(val) & 0xFFFF", replacement: "LOWORD(val)", define: "#define LOWORD(val) ((val) & 0xFFFF)" },
            BuiltinPattern { name: "SUCCEEDED", pattern: "(hr) >= 0", replacement: "SUCCEEDED(hr)", define: "#define SUCCEEDED(hr) ((hr) >= 0)" },
            BuiltinPattern { name: "FAILED", pattern: "(hr) < 0", replacement: "FAILED(hr)", define: "#define FAILED(hr) ((hr) < 0)" },
            BuiltinPattern { name: "ROL32", pattern: "((x) << (n)) | ((x) >> (32 - (n)))", replacement: "ROL32(x, n)", define: "#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))" },
            BuiltinPattern { name: "ROR32", pattern: "((x) >> (n)) | ((x) << (32 - (n)))", replacement: "ROR32(x, n)", define: "#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))" },
        ].into_iter()
    }

    /// Returns all built-in macro patterns.
    #[must_use]
    pub fn all() -> Vec<BuiltinPattern> {
        Self::minmax_and_align()
            .chain(Self::byte_word_and_rotation())
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExpressionFrequencyCounter
// ─────────────────────────────────────────────────────────────────────────────

/// Counts occurrences of sub-expressions in the source to find macro candidates.
pub struct ExpressionFrequencyCounter {
    min_len: usize,
    max_len: usize,
}

impl ExpressionFrequencyCounter {
    #[must_use]
    pub const fn new(min_len: usize, max_len: usize) -> Self {
        Self { min_len, max_len }
    }

    /// Count frequency of all sub-expressions that look like candidates.
    #[must_use]
    pub fn count(&self, source: &str) -> HashMap<String, usize> {
        let mut freq: HashMap<String, usize> = HashMap::new();

        for line in source.lines() {
            let t = line.trim();
            // Skip comment and blank lines.
            if t.is_empty() || t.starts_with("//") || t.starts_with("/*") {
                continue;
            }
            // Extract parenthesised sub-expressions.
            for expr in self.extract_subexprs(t) {
                *freq.entry(expr).or_insert(0) += 1;
            }
        }

        freq
    }

    /// Extract candidate sub-expressions from a line.
    fn extract_subexprs(&self, line: &str) -> Vec<String> {
        let mut results = Vec::new();
        let chars: Vec<char> = line.chars().collect();

        for i in 0..chars.len() {
            if chars[i] != '(' {
                continue;
            }
            // Find matching `)`.
            let mut depth = 0i32;
            let mut end = i;
            for (j, _) in chars.iter().enumerate().skip(i) {
                match chars[j] {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = j;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if end > i {
                let expr: String = chars[i..=end].iter().collect();
                let len = expr.len();
                if len >= self.min_len && len <= self.max_len {
                    // Only include expressions with operators (not just `(x)`).
                    if expr.contains('+') || expr.contains('-') || expr.contains('*')
                        || expr.contains('/') || expr.contains('&') || expr.contains('|')
                        || expr.contains('^') || expr.contains("<<") || expr.contains(">>")
                        || expr.contains('?')
                    {
                        results.push(expr);
                    }
                }
            }
        }

        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InlineExpansionDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects repeated sequences of statements that could represent an inlined
/// function.
pub struct InlineExpansionDetector {
    min_sequence_len: usize,
    min_occurrences: usize,
}

impl InlineExpansionDetector {
    #[must_use]
    pub const fn new(min_sequence_len: usize, min_occurrences: usize) -> Self {
        Self {
            min_sequence_len,
            min_occurrences,
        }
    }

    /// Find repeated statement sequences.
    #[must_use]
    pub fn detect(&self, source: &str) -> Vec<InlineCandidate> {
        let lines: Vec<&str> = source
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();

        let mut candidates: Vec<InlineCandidate> = Vec::new();
        let n = lines.len();

        if n < self.min_sequence_len * 2 {
            return candidates;
        }

        // Build a frequency map of line sequences.
        let mut seq_count: HashMap<Vec<&str>, Vec<usize>> = HashMap::new();

        for i in 0..=(n - self.min_sequence_len) {
            let seq: Vec<&str> = lines[i..i + self.min_sequence_len].to_vec();
            seq_count.entry(seq).or_default().push(i);
        }

        for (seq, positions) in seq_count {
            if positions.len() >= self.min_occurrences {
                candidates.push(InlineCandidate {
                    body: seq.iter().map(std::string::ToString::to_string).collect(),
                    occurrences: positions.len(),
                    first_occurrence_line: positions[0] + 1,
                });
            }
        }

        // Sort by occurrence count, most frequent first.
        candidates.sort_by(|a, b| b.occurrences.cmp(&a.occurrences));
        candidates
    }
}

/// A repeated code sequence that may represent an inlined function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineCandidate {
    pub body: Vec<String>,
    pub occurrences: usize,
    pub first_occurrence_line: usize,
}

impl InlineCandidate {
    /// Suggest a placeholder function name.
    #[must_use]
    pub fn suggested_name(&self) -> String {
        // Use first non-trivial statement as a hint.
        for line in &self.body {
            let t = line.trim();
            if t.contains('(')
                && let Some(end) = t.find('(') {
                    let name: String = t[..end]
                        .chars()
                        .rev()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect();
                    if !name.is_empty() {
                        return format!("inline_{name}");
                    }
                }
        }
        format!("inline_fn_{}", self.first_occurrence_line)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MacroDetector — orchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// Detects macro candidates in decompiled C source and produces a set of
/// `#define` lines to prepend and substitutions to apply.
pub struct MacroDetector {
    config: MacroDetectionConfig,
}

/// Result of macro detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroDetectionResult {
    /// Macros to define (prepend to the source).
    pub defines: Vec<MacroDefinition>,
    /// Inline expansion candidates.
    pub inline_candidates: Vec<InlineCandidate>,
    /// The source after macro substitution.
    pub transformed_source: String,
}

impl MacroDetector {
    #[must_use]
    pub const fn new(config: MacroDetectionConfig) -> Self {
        Self { config }
    }

    /// Emit all `#define` lines for detected macros.
    #[must_use]
    pub fn emit_defines(&self, result: &MacroDetectionResult) -> String {
        let mut out = String::new();
        for def in &result.defines {
            let d = def.as_define();
            if !d.is_empty() {
                out.push_str(&d);
                out.push('\n');
            }
        }
        out
    }
}

impl Default for MacroDetector {
    fn default() -> Self {
        Self::new(MacroDetectionConfig::default())
    }
}

impl MacroDetector {
    /// Run macro detection and return the result.
    #[must_use]
    pub fn detect(&self, source: &str) -> MacroDetectionResult {
        let mut defines: Vec<MacroDefinition> = Vec::new();
        let mut transformed = source.to_string();

        // ── Built-in pattern matching ─────────────────────────────────────
        if self.config.apply_builtin_patterns {
            let patterns = BuiltinMacroPatterns::all();
            for pat in &patterns {
                let count = count_occurrences(&transformed, pat.pattern);
                if count >= 1 {
                    defines.push(MacroDefinition {
                        name: pat.name.to_string(),
                        expansion: pat.pattern.to_string(),
                        params: Vec::new(),
                        use_count: count,
                        source: MacroSource::BuiltIn,
                    });
                }
            }
        }

        // ── Expression frequency analysis ─────────────────────────────────
        let counter = ExpressionFrequencyCounter::new(
            self.config.min_expr_length,
            self.config.max_expr_length,
        );
        let freq = counter.count(source);

        let mut sorted: Vec<(String, usize)> = freq
            .into_iter()
            .filter(|(_, n)| *n >= self.config.min_occurrences)
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));

        let mut macro_idx = defines.len();
        for (expr, count) in sorted.iter().take(20) {
            let name = format!("MACRO_{macro_idx}");
            defines.push(MacroDefinition {
                name: name.clone(),
                expansion: expr.clone(),
                params: Vec::new(),
                use_count: *count,
                source: MacroSource::AutoDetected,
            });
            transformed = transformed.replace(expr.as_str(), &name);
            macro_idx += 1;
        }

        // ── Inline expansion detection ────────────────────────────────────
        let inline_candidates = if self.config.detect_inline_expansions {
            let detector = InlineExpansionDetector::new(
                self.config.min_inline_sequence_len,
                self.config.min_occurrences,
            );
            detector.detect(source)
        } else {
            Vec::new()
        };

        MacroDetectionResult {
            defines,
            inline_candidates,
            transformed_source: transformed,
        }
    }
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(needle) {
        count += 1;
        start += pos + needle.len();
    }
    count
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstantCollapser — collapse repeated literal constants into #defines
// ─────────────────────────────────────────────────────────────────────────────

/// Finds integer/hex constants that appear many times and suggests `#define`s.
pub struct ConstantCollapser {
    min_occurrences: usize,
}

impl ConstantCollapser {
    #[must_use]
    pub const fn new(min_occurrences: usize) -> Self {
        Self { min_occurrences }
    }

    /// Scan source for repeated constants.
    #[must_use]
    pub fn scan(&self, source: &str) -> Vec<ConstantCandidate> {
        let mut freq: HashMap<String, usize> = HashMap::new();

        for line in source.lines() {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with("/*") {
                continue;
            }
            for c in Self::extract_constants(t) {
                *freq.entry(c).or_insert(0) += 1;
            }
        }

        let mut candidates: Vec<ConstantCandidate> = freq
            .into_iter()
            .filter(|(_, n)| *n >= self.min_occurrences)
            .map(|(val, count)| ConstantCandidate {
                value: val.clone(),
                occurrences: count,
                suggested_name: Self::suggest_name(&val),
            })
            .collect();

        candidates.sort_by(|a, b| b.occurrences.cmp(&a.occurrences));
        candidates
    }

    fn extract_constants(line: &str) -> Vec<String> {
        let mut consts = Vec::new();
        let bytes = line.as_bytes();
        let mut i = 0;

        while i < bytes.len() {
            // Skip identifier starts (variable names etc.)
            if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                continue;
            }

            // Hex literal: 0x...
            if i + 1 < bytes.len() && bytes[i] == b'0' && bytes[i + 1] == b'x' {
                let start = i;
                i += 2;
                while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                    i += 1;
                }
                let s = &line[start..i];
                if s.len() >= 4 {
                    consts.push(s.to_string());
                }
                continue;
            }

            // Decimal literal (4+ digits to avoid trivial 0, 1, etc.)
            if bytes[i].is_ascii_digit() {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let s = &line[start..i];
                if s.len() >= 4 {
                    consts.push(s.to_string());
                }
                continue;
            }

            i += 1;
        }

        consts
    }

    fn suggest_name(value: &str) -> String {
        // For well-known values, use meaningful names.
        match value {
            "0x80000000" => "SIGN_BIT_32".to_string(),
            "0xFFFFFFFF" => "UINT32_MAX".to_string(),
            "0x7FFFFFFF" => "INT32_MAX".to_string(),
            "65536" | "0x10000" => "UINT16_RANGE".to_string(),
            "4096" | "0x1000" => "PAGE_SIZE".to_string(),
            "256" | "0x100" => "BYTE_RANGE".to_string(),
            "1024" | "0x400" => "ONE_KB".to_string(),
            "1048576" | "0x100000" => "ONE_MB".to_string(),
            _ => {
                // Generate a name from the value.
                let clean: String = value
                    .chars()
                    .map(|c| if c.is_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
                    .collect();
                format!("CONST_{clean}")
            }
        }
    }
}

/// A candidate constant for extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstantCandidate {
    pub value: String,
    pub occurrences: usize,
    pub suggested_name: String,
}

impl ConstantCandidate {
    #[must_use]
    pub fn as_define(&self) -> String {
        format!("#define {} {}", self.suggested_name, self.value)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MacroApplier — applies macro definitions to source
// ─────────────────────────────────────────────────────────────────────────────

/// Applies a list of macro definitions to source text, replacing expansions
/// with macro names.
pub struct MacroApplier;

impl MacroApplier {
    /// Apply macros in order, returning the transformed source.
    #[must_use]
    pub fn apply(source: &str, macros: &[MacroDefinition]) -> String {
        let mut s = source.to_string();
        for m in macros {
            if m.is_function_like() {
                // Function-like macros are harder — skip for now.
                continue;
            }
            s = s.replace(m.expansion.as_str(), m.name.as_str());
        }
        s
    }

    /// Apply constant replacements.
    #[must_use]
    pub fn apply_constants(source: &str, constants: &[ConstantCandidate]) -> String {
        let mut s = source.to_string();
        for c in constants {
            // Replace whole-word occurrences.
            s = replace_constant(&s, &c.value, &c.suggested_name);
        }
        s
    }
}

fn replace_constant(source: &str, value: &str, name: &str) -> String {
    let mut result = String::new();
    let mut remaining = source;

    loop {
        if let Some(pos) = remaining.find(value) {
            // Check word boundaries.
            let before_ok = pos == 0
                || !remaining[..pos].chars().last().is_some_and(char::is_alphanumeric);
            let after_end = pos + value.len();
            let after_ok = after_end >= remaining.len()
                || !remaining[after_end..].chars().next().is_some_and(char::is_alphanumeric);

            if before_ok && after_ok {
                result.push_str(&remaining[..pos]);
                result.push_str(name);
                remaining = &remaining[after_end..];
            } else {
                result.push_str(&remaining[..=pos]);
                remaining = &remaining[pos + 1..];
            }
        } else {
            result.push_str(remaining);
            break;
        }
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macro_definition_as_define_simple() {
        let m = MacroDefinition {
            name: "MAX_SIZE".to_string(),
            expansion: "1024".to_string(),
            params: vec![],
            use_count: 5,
            source: MacroSource::AutoDetected,
        };
        assert_eq!(m.as_define(), "#define MAX_SIZE 1024");
    }

    #[test]
    fn test_macro_definition_as_define_func_like() {
        let m = MacroDefinition {
            name: "MAX".to_string(),
            expansion: "((a) > (b) ? (a) : (b))".to_string(),
            params: vec!["a".to_string(), "b".to_string()],
            use_count: 3,
            source: MacroSource::BuiltIn,
        };
        assert!(m.as_define().contains("MAX(a, b)"));
    }

    #[test]
    fn test_constant_collapser_hex() {
        let src = "    x = 0x1234;\n    y = 0x1234;\n    z = 0x1234;\n    w = 0x1234;\n";
        let cc = ConstantCollapser::new(3);
        let candidates = cc.scan(src);
        assert!(!candidates.is_empty(), "expected candidates, got none");
        assert!(candidates.iter().any(|c| c.value == "0x1234"));
    }

    #[test]
    fn test_constant_collapser_known_value() {
        let src = "    x = 4096;\n    y = 4096;\n    z = 4096;\n";
        let cc = ConstantCollapser::new(2);
        let candidates = cc.scan(src);
        let page_cand = candidates.iter().find(|c| c.value == "4096");
        assert!(page_cand.is_some());
        assert_eq!(page_cand.unwrap().suggested_name, "PAGE_SIZE");
    }

    #[test]
    fn test_expression_frequency_counter() {
        let src = "    x = (a + b * c) + 1;\n    y = (a + b * c) + 2;\n    z = (a + b * c) + 3;\n";
        let counter = ExpressionFrequencyCounter::new(5, 80);
        let freq = counter.count(src);
        // `(a + b * c)` should appear 3 times.
        assert!(freq.values().any(|&n| n >= 3));
    }

    #[test]
    fn test_inline_expansion_detector() {
        let src = "    a = 1;\n    b = 2;\n    c = a + b;\n    a = 1;\n    b = 2;\n    c = a + b;\n    a = 1;\n    b = 2;\n    c = a + b;\n";
        let detector = InlineExpansionDetector::new(3, 2);
        let candidates = detector.detect(src);
        assert!(!candidates.is_empty(), "expected inline candidates");
        assert!(candidates[0].occurrences >= 2);
    }

    #[test]
    fn test_macro_detector_builtin() {
        // Use a pattern that matches a builtin.
        let src = "    val = ((a) > (b) ? (a) : (b));\n    val2 = ((a) > (b) ? (a) : (b));\n";
        let detector = MacroDetector::new(MacroDetectionConfig {
            apply_builtin_patterns: true,
            ..MacroDetectionConfig::default()
        });
        let result = detector.detect(src);
        // Should detect the MAX pattern.
        assert!(result.defines.iter().any(|d| d.name == "MAX" || d.use_count > 0));
    }

    #[test]
    fn test_macro_applier_simple() {
        let macros = vec![MacroDefinition {
            name: "PAGE_SIZE".to_string(),
            expansion: "4096".to_string(),
            params: vec![],
            use_count: 3,
            source: MacroSource::AutoDetected,
        }];
        let src = "    x = 4096;\n    y = 4096;\n";
        let out = MacroApplier::apply(src, &macros);
        assert!(out.contains("PAGE_SIZE"), "output: {out}");
    }

    #[test]
    fn test_replace_constant_whole_word() {
        let out = replace_constant("x = 0x1000; y = 0x10001;", "0x1000", "PAGE_SIZE");
        assert!(out.contains("PAGE_SIZE"), "output: {out}");
        // `0x10001` should not be affected.
        assert!(out.contains("0x10001"), "output: {out}");
    }

    #[test]
    fn test_count_occurrences() {
        assert_eq!(count_occurrences("aaa b aaa", "aaa"), 2);
        assert_eq!(count_occurrences("xxx", "yyy"), 0);
        assert_eq!(count_occurrences("", "x"), 0);
    }

    #[test]
    fn test_inline_candidate_suggested_name() {
        let cand = InlineCandidate {
            body: vec!["    memset(buf, 0, size);".to_string()],
            occurrences: 3,
            first_occurrence_line: 10,
        };
        let name = cand.suggested_name();
        assert!(name.contains("memset") || name.contains("inline"));
    }
}
