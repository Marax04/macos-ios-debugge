//! `sanitizer_detector` — Detect sanitizer functions in tainted code paths.
//!
//! Provides [`SanitizerDetector`] which recognises calls that remove or reduce
//! taint (validation, escaping, bounds-checking, encoding, hashing) and
//! [`SanitizerPattern`] which describes a single sanitizer rule.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{TaintId, TaintLocation, taint_bits};

// ─── SanitizerKind ───────────────────────────────────────────────────────────

/// The category of sanitization performed by a function.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SanitizerKind {
    /// HTML / XML entity escaping (e.g. `htmlspecialchars`).
    HtmlEscape,
    /// SQL query parameterisation or escaping.
    SqlEscape,
    /// Shell / command-line argument escaping.
    ShellEscape,
    /// Path normalisation and traversal removal.
    PathNormalise,
    /// Integer bounds / range check (returns bool or panics on violation).
    BoundsCheck,
    /// Cryptographic hash (one-way; removes concrete-value meaning but not taint by default).
    CryptoHash,
    /// Encoding that preserves data but removes dangerous characters.
    Encoding,
    /// Custom user-defined sanitizer.
    Custom(String),
    /// General input validation (returns bool).
    Validation,
    /// String length limit enforcement.
    LengthLimit,
    /// Null / empty check.
    NullCheck,
    /// Whitelist / allowlist filter.
    Whitelist,
    /// Regular-expression validation.
    RegexValidation,
}

impl SanitizerKind {
    /// Whether this kind of sanitizer fully removes taint (conservative: only
    /// whitelist, escaping, and bounds checks do).
    #[must_use]
    pub fn fully_removes_taint(&self) -> bool {
        matches!(
            self,
            Self::HtmlEscape
                | Self::SqlEscape
                | Self::ShellEscape
                | Self::PathNormalise
                | Self::BoundsCheck
                | Self::Whitelist
                | Self::RegexValidation
        )
    }

    /// Human-readable label.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::HtmlEscape => "html-escape",
            Self::SqlEscape => "sql-escape",
            Self::ShellEscape => "shell-escape",
            Self::PathNormalise => "path-normalise",
            Self::BoundsCheck => "bounds-check",
            Self::CryptoHash => "crypto-hash",
            Self::Encoding => "encoding",
            Self::Custom(s) => s.as_str(),
            Self::Validation => "validation",
            Self::LengthLimit => "length-limit",
            Self::NullCheck => "null-check",
            Self::Whitelist => "whitelist",
            Self::RegexValidation => "regex-validation",
        }
    }
}

// ─── SanitizerEffect ─────────────────────────────────────────────────────────

/// Describes what a sanitizer does to a taint mask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SanitizerEffect {
    /// Clear all taint from the return value / output argument.
    ClearAll,
    /// Clear specific source bits.
    ClearBits(TaintId),
    /// Reduce taint to a lower-risk subset (mask stays but risk is lower).
    ReduceRisk,
    /// The sanitizer is conditional: clears taint only if the function
    /// returns a non-zero / true value.
    ConditionalClear,
}

// ─── SanitizerPattern ────────────────────────────────────────────────────────

/// A single sanitizer rule matching one or more function names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizerPattern {
    /// Function names this rule matches (exact).
    pub names: Vec<String>,
    /// Name prefixes this rule matches.
    pub prefixes: Vec<String>,
    /// Category of sanitization.
    pub kind: SanitizerKind,
    /// Effect on the taint mask of the return value.
    pub effect: SanitizerEffect,
    /// Which argument positions carry the sanitized output (by pointer, 0-based).
    /// Empty means only the return value is sanitized.
    pub out_args: Vec<usize>,
    /// Which argument positions are the tainted inputs (0-based).
    pub in_args: Vec<usize>,
    /// Human-readable description.
    pub description: String,
    /// Confidence that this is a real sanitizer (0–100).
    pub confidence: u8,
}

impl SanitizerPattern {
    /// Create a minimal pattern for a single function name.
    #[must_use]
    pub fn for_function(
        name: impl Into<String>,
        kind: SanitizerKind,
        effect: SanitizerEffect,
    ) -> Self {
        let n = name.into();
        let desc = format!("sanitizer: {}", n);
        Self {
            names: vec![n],
            prefixes: Vec::new(),
            kind,
            effect,
            out_args: Vec::new(),
            in_args: vec![0],
            description: desc,
            confidence: 80,
        }
    }

    /// Create a prefix-based pattern (e.g. `safe_`, `escape_`).
    #[must_use]
    pub fn for_prefix(
        prefix: impl Into<String>,
        kind: SanitizerKind,
        effect: SanitizerEffect,
    ) -> Self {
        let p = prefix.into();
        let desc = format!("sanitizer prefix: {}", p);
        Self {
            names: Vec::new(),
            prefixes: vec![p],
            kind,
            effect,
            out_args: Vec::new(),
            in_args: vec![0],
            description: desc,
            confidence: 50,
        }
    }

    /// Set the list of input argument positions.
    #[must_use]
    pub fn with_in_args(mut self, args: Vec<usize>) -> Self {
        self.in_args = args;
        self
    }

    /// Set the list of output argument positions.
    #[must_use]
    pub fn with_out_args(mut self, args: Vec<usize>) -> Self {
        self.out_args = args;
        self
    }

    /// Set confidence.
    #[must_use]
    pub fn with_confidence(mut self, c: u8) -> Self {
        self.confidence = c;
        self
    }

    /// Check whether this pattern matches a given function name.
    #[must_use]
    pub fn matches(&self, function_name: &str) -> bool {
        if self.names.iter().any(|n| n == function_name) {
            return true;
        }
        self.prefixes.iter().any(|p| function_name.starts_with(p.as_str()))
    }
}

// ─── SanitizerMatch ──────────────────────────────────────────────────────────

/// The result of matching a function call against the pattern database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizerMatch {
    /// Name of the matched function.
    pub function_name: String,
    /// The matching pattern.
    pub pattern: SanitizerPattern,
    /// Taint mask on the inputs at match time.
    pub input_taint: TaintId,
    /// Address of the call instruction.
    pub call_addr: u64,
}

impl SanitizerMatch {
    /// Whether this match fully removes taint.
    #[must_use]
    pub fn removes_taint(&self) -> bool {
        self.pattern.kind.fully_removes_taint()
            && matches!(
                self.pattern.effect,
                SanitizerEffect::ClearAll | SanitizerEffect::ClearBits(_)
            )
    }

    /// Compute the resulting taint mask after applying the sanitizer effect.
    #[must_use]
    pub fn resulting_taint(&self) -> TaintId {
        match &self.pattern.effect {
            SanitizerEffect::ClearAll => taint_bits::NONE,
            SanitizerEffect::ClearBits(mask) => self.input_taint & !mask,
            SanitizerEffect::ReduceRisk => self.input_taint,
            SanitizerEffect::ConditionalClear => self.input_taint,
        }
    }
}

// ─── SanitizerDetector ───────────────────────────────────────────────────────

/// Detects sanitizer calls by matching against a pattern database.
///
/// Usage:
/// ```ignore
/// let mut det = SanitizerDetector::with_builtins();
/// if let Some(m) = det.check_call("htmlspecialchars", &[user_taint], 0x1000) {
///     // apply m.resulting_taint() to the return register
/// }
/// ```
#[derive(Debug, Clone)]
pub struct SanitizerDetector {
    /// All registered sanitizer patterns.
    patterns: Vec<SanitizerPattern>,
    /// Cache: function name → pattern index.
    exact_cache: HashMap<String, usize>,
    /// Addresses of call sites that were identified as sanitizers.
    sanitizer_call_sites: HashSet<u64>,
    /// All matches observed so far, in order.
    history: Vec<SanitizerMatch>,
    /// Whether to apply conservative mode: even `ReduceRisk` sanitizers clear taint.
    pub conservative: bool,
}

impl SanitizerDetector {
    /// Create an empty detector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
            exact_cache: HashMap::new(),
            sanitizer_call_sites: HashSet::new(),
            history: Vec::new(),
            conservative: false,
        }
    }

    /// Create a detector pre-loaded with the built-in pattern database.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut d = Self::new();
        d.load_builtins();
        d
    }

    /// Register a pattern.
    pub fn add_pattern(&mut self, p: SanitizerPattern) {
        // Pre-populate exact cache.
        for name in &p.names {
            let idx = self.patterns.len();
            self.exact_cache.insert(name.clone(), idx);
        }
        self.patterns.push(p);
    }

    /// Load built-in sanitizer patterns for common C, C++, PHP, and Python functions.
    pub fn load_builtins(&mut self) {
        // ── HTML escaping ───────────────────────────────────────────────────
        for name in &[
            "htmlspecialchars",
            "htmlentities",
            "html_escape",
            "escape_html",
            "cgi_escape",
            "HtmlEncode",
            "AntiXssEncoder.HtmlEncode",
        ] {
            self.add_pattern(SanitizerPattern::for_function(
                *name,
                SanitizerKind::HtmlEscape,
                SanitizerEffect::ClearAll,
            ).with_confidence(90));
        }

        // ── SQL escaping ────────────────────────────────────────────────────
        for name in &[
            "mysql_real_escape_string",
            "sqlite3_mprintf",
            "PQescapeStringConn",
            "PDO::quote",
            "sqliteBinder",
            "escape_sql",
            "SqlEscapeString",
        ] {
            self.add_pattern(SanitizerPattern::for_function(
                *name,
                SanitizerKind::SqlEscape,
                SanitizerEffect::ClearAll,
            ).with_confidence(95));
        }

        // ── Shell escaping ──────────────────────────────────────────────────
        for name in &[
            "escapeshellarg",
            "escapeshellcmd",
            "shlex_quote",
            "shell_escape",
            "g_shell_quote",
        ] {
            self.add_pattern(SanitizerPattern::for_function(
                *name,
                SanitizerKind::ShellEscape,
                SanitizerEffect::ClearAll,
            ).with_confidence(90));
        }

        // ── Path normalisation ──────────────────────────────────────────────
        for name in &[
            "realpath",
            "canonicalize_path",
            "normalize_path",
            "abspath",
            "os.path.realpath",
            "Path::canonicalize",
        ] {
            self.add_pattern(SanitizerPattern::for_function(
                *name,
                SanitizerKind::PathNormalise,
                SanitizerEffect::ClearAll,
            ).with_confidence(75));
        }

        // ── Bounds checks ───────────────────────────────────────────────────
        for name in &[
            "check_bounds",
            "validate_length",
            "assert_size",
            "range_check",
            "clamp",
            "std::clamp",
        ] {
            self.add_pattern(SanitizerPattern::for_function(
                *name,
                SanitizerKind::BoundsCheck,
                SanitizerEffect::ConditionalClear,
            ).with_confidence(60));
        }

        // ── Encoding ────────────────────────────────────────────────────────
        for name in &[
            "base64_encode",
            "url_encode",
            "urlencode",
            "percent_encode",
            "xml_escape",
            "json_encode",
        ] {
            self.add_pattern(SanitizerPattern::for_function(
                *name,
                SanitizerKind::Encoding,
                SanitizerEffect::ReduceRisk,
            ).with_confidence(70));
        }

        // ── Crypto hash (reduces meaning but not taint by default) ──────────
        for name in &["sha256", "sha512", "md5", "bcrypt", "scrypt", "argon2id"] {
            self.add_pattern(SanitizerPattern::for_function(
                *name,
                SanitizerKind::CryptoHash,
                SanitizerEffect::ReduceRisk,
            ).with_confidence(50));
        }

        // ── Validation ──────────────────────────────────────────────────────
        for name in &[
            "is_valid_email",
            "is_valid_url",
            "is_numeric",
            "validate_input",
            "check_input",
            "sanitize",
            "sanitize_input",
            "filter_var",
            "validate",
        ] {
            self.add_pattern(SanitizerPattern::for_function(
                *name,
                SanitizerKind::Validation,
                SanitizerEffect::ConditionalClear,
            ).with_confidence(70));
        }

        // ── Prefix-based ────────────────────────────────────────────────────
        self.add_pattern(
            SanitizerPattern::for_prefix("safe_", SanitizerKind::Custom("safe_prefix".into()), SanitizerEffect::ClearAll)
                .with_confidence(40),
        );
        self.add_pattern(
            SanitizerPattern::for_prefix("escape_", SanitizerKind::HtmlEscape, SanitizerEffect::ClearAll)
                .with_confidence(45),
        );
        self.add_pattern(
            SanitizerPattern::for_prefix("validate_", SanitizerKind::Validation, SanitizerEffect::ConditionalClear)
                .with_confidence(40),
        );
        self.add_pattern(
            SanitizerPattern::for_prefix("sanitize_", SanitizerKind::Custom("sanitize_prefix".into()), SanitizerEffect::ClearAll)
                .with_confidence(45),
        );
    }

    /// Check whether a function call at `call_addr` is a sanitizer.
    ///
    /// `arg_taints` is the taint mask of each argument (index 0 = first arg).
    /// Returns `Some(SanitizerMatch)` when the function is recognised.
    pub fn check_call(
        &mut self,
        function_name: &str,
        arg_taints: &[TaintId],
        call_addr: u64,
    ) -> Option<SanitizerMatch> {
        // Compute union of input taints across all tracked input positions
        let input_taint: TaintId = arg_taints
            .iter()
            .fold(taint_bits::NONE, |acc, &t| acc | t);

        // Try exact cache first
        if let Some(&idx) = self.exact_cache.get(function_name) {
            let pattern = self.patterns[idx].clone();
            let m = SanitizerMatch {
                function_name: function_name.to_string(),
                pattern,
                input_taint,
                call_addr,
            };
            self.sanitizer_call_sites.insert(call_addr);
            self.history.push(m.clone());
            return Some(m);
        }

        // Linear scan for prefix patterns
        for pattern in &self.patterns {
            if pattern.names.is_empty() && pattern.matches(function_name) {
                let m = SanitizerMatch {
                    function_name: function_name.to_string(),
                    pattern: pattern.clone(),
                    input_taint,
                    call_addr,
                };
                self.sanitizer_call_sites.insert(call_addr);
                self.history.push(m.clone());
                return Some(m);
            }
        }

        None
    }

    /// Whether the call at `addr` was previously identified as a sanitizer.
    #[must_use]
    pub fn is_sanitizer_call_site(&self, addr: u64) -> bool {
        self.sanitizer_call_sites.contains(&addr)
    }

    /// All sanitizer matches observed so far.
    #[must_use]
    pub fn history(&self) -> &[SanitizerMatch] {
        &self.history
    }

    /// Number of distinct sanitizer call sites seen.
    #[must_use]
    pub fn call_site_count(&self) -> usize {
        self.sanitizer_call_sites.len()
    }

    /// All registered patterns.
    #[must_use]
    pub fn patterns(&self) -> &[SanitizerPattern] {
        &self.patterns
    }

    /// Find all patterns of a given kind.
    #[must_use]
    pub fn patterns_by_kind(&self, kind: &SanitizerKind) -> Vec<&SanitizerPattern> {
        self.patterns.iter().filter(|p| &p.kind == kind).collect()
    }

    /// Clear the match history and call-site registry.
    pub fn reset_history(&mut self) {
        self.history.clear();
        self.sanitizer_call_sites.clear();
    }

    /// Compute the effective taint mask of a function's return value given
    /// the argument taints. Returns the modified taint if it is a sanitizer,
    /// or `None` if not recognised.
    #[must_use]
    pub fn effective_return_taint(
        &self,
        function_name: &str,
        arg_taints: &[TaintId],
    ) -> Option<TaintId> {
        let input: TaintId = arg_taints.iter().fold(taint_bits::NONE, |a, &t| a | t);

        // Check exact cache
        if let Some(&idx) = self.exact_cache.get(function_name) {
            let m = SanitizerMatch {
                function_name: function_name.to_string(),
                pattern: self.patterns[idx].clone(),
                input_taint: input,
                call_addr: 0,
            };
            let result = if self.conservative && matches!(m.pattern.effect, SanitizerEffect::ReduceRisk) {
                taint_bits::NONE
            } else {
                m.resulting_taint()
            };
            return Some(result);
        }

        for p in &self.patterns {
            if p.names.is_empty() && p.matches(function_name) {
                let m = SanitizerMatch {
                    function_name: function_name.to_string(),
                    pattern: p.clone(),
                    input_taint: input,
                    call_addr: 0,
                };
                let result = if self.conservative && matches!(m.pattern.effect, SanitizerEffect::ReduceRisk) {
                    taint_bits::NONE
                } else {
                    m.resulting_taint()
                };
                return Some(result);
            }
        }

        None
    }

    /// Apply the sanitizer effect to a set of locations in a mutable taint map.
    /// Returns the number of locations cleared.
    pub fn apply_to_locations(
        &self,
        function_name: &str,
        locations: &mut HashMap<TaintLocation, TaintId>,
        arg_locations: &[TaintLocation],
    ) -> usize {
        // Look up by exact cache first, then fall back to a linear pattern scan.
        let idx: usize = if let Some(&cached) = self.exact_cache.get(function_name) {
            cached
        } else if let Some((i, _)) = self
            .patterns
            .iter()
            .enumerate()
            .find(|(_, p)| p.names.is_empty() && p.matches(function_name))
        {
            i
        } else {
            return 0;
        };

        let pattern = &self.patterns[idx];
        let mut cleared = 0;

        for loc in arg_locations {
            if let Some(taint) = locations.get_mut(loc) {
                let new_taint = match &pattern.effect {
                    SanitizerEffect::ClearAll => taint_bits::NONE,
                    SanitizerEffect::ClearBits(mask) => *taint & !mask,
                    SanitizerEffect::ReduceRisk | SanitizerEffect::ConditionalClear => *taint,
                };
                if new_taint != *taint {
                    *taint = new_taint;
                    cleared += 1;
                }
            }
        }

        cleared
    }

    /// Generate a summary of which sanitizers were called during analysis.
    #[must_use]
    pub fn summary(&self) -> SanitizerSummary {
        let mut by_kind: HashMap<String, usize> = HashMap::new();
        let mut total_taint_cleared: u64 = 0;
        for m in &self.history {
            *by_kind.entry(m.pattern.kind.label().to_string()).or_insert(0) += 1;
            if m.removes_taint() {
                total_taint_cleared += 1;
            }
        }
        SanitizerSummary {
            total_matches: self.history.len(),
            unique_call_sites: self.sanitizer_call_sites.len(),
            matches_by_kind: by_kind,
            total_taint_cleared,
        }
    }
}

impl Default for SanitizerDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─── SanitizerSummary ────────────────────────────────────────────────────────

/// Summary statistics for a completed taint analysis with sanitizer detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizerSummary {
    /// Total number of sanitizer matches across all calls.
    pub total_matches: usize,
    /// Number of unique call-site addresses identified as sanitizers.
    pub unique_call_sites: usize,
    /// Match counts broken down by sanitizer kind label.
    pub matches_by_kind: HashMap<String, usize>,
    /// Number of matches that fully removed taint.
    pub total_taint_cleared: u64,
}

impl SanitizerSummary {
    /// Whether any sanitizers were detected.
    #[must_use]
    pub fn any_detected(&self) -> bool {
        self.total_matches > 0
    }

    /// The most-used sanitizer kind (by label).
    #[must_use]
    pub fn dominant_kind(&self) -> Option<&str> {
        self.matches_by_kind
            .iter()
            .max_by_key(|(_, v)| *v)
            .map(|(k, _)| k.as_str())
    }
}

// ─── SanitizerRegistry ───────────────────────────────────────────────────────

/// A shareable, serialisable registry of sanitizer patterns that can be loaded
/// from a TOML / JSON config file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SanitizerRegistry {
    pub patterns: Vec<SanitizerPattern>,
}

impl SanitizerRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a [`SanitizerDetector`] from this registry.
    #[must_use]
    pub fn into_detector(self) -> SanitizerDetector {
        let mut d = SanitizerDetector::new();
        for p in self.patterns {
            d.add_pattern(p);
        }
        d
    }

    /// Add a pattern to the registry.
    pub fn add(&mut self, p: SanitizerPattern) {
        self.patterns.push(p);
    }

    /// Number of patterns in the registry.
    #[must_use]
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Returns `true` if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Find all patterns that match a given function name.
    #[must_use]
    pub fn matching_patterns(&self, name: &str) -> Vec<&SanitizerPattern> {
        self.patterns.iter().filter(|p| p.matches(name)).collect()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_html_escape() {
        let mut det = SanitizerDetector::with_builtins();
        let m = det.check_call("htmlspecialchars", &[taint_bits::USER_INPUT], 0x1000);
        assert!(m.is_some());
        let m = m.unwrap();
        assert_eq!(m.kind_label(), "html-escape");
        assert_eq!(m.resulting_taint(), taint_bits::NONE);
    }

    #[test]
    fn test_builtin_sql_escape() {
        let mut det = SanitizerDetector::with_builtins();
        let m = det.check_call("mysql_real_escape_string", &[taint_bits::NETWORK], 0x2000);
        assert!(m.is_some());
        assert_eq!(m.unwrap().resulting_taint(), taint_bits::NONE);
    }

    #[test]
    fn test_prefix_safe() {
        let mut det = SanitizerDetector::with_builtins();
        let m = det.check_call("safe_printf", &[taint_bits::USER_INPUT], 0x3000);
        assert!(m.is_some());
    }

    #[test]
    fn test_prefix_escape() {
        let mut det = SanitizerDetector::with_builtins();
        let m = det.check_call("escape_user_input", &[taint_bits::NETWORK], 0x4000);
        assert!(m.is_some());
    }

    #[test]
    fn test_unknown_function_no_match() {
        let mut det = SanitizerDetector::with_builtins();
        let m = det.check_call("sprintf", &[taint_bits::USER_INPUT], 0x5000);
        assert!(m.is_none());
    }

    #[test]
    fn test_history_grows() {
        let mut det = SanitizerDetector::with_builtins();
        det.check_call("htmlspecialchars", &[taint_bits::USER_INPUT], 0x100);
        det.check_call("mysql_real_escape_string", &[taint_bits::FILE], 0x200);
        assert_eq!(det.history().len(), 2);
    }

    #[test]
    fn test_call_site_tracking() {
        let mut det = SanitizerDetector::with_builtins();
        det.check_call("htmlspecialchars", &[taint_bits::USER_INPUT], 0xDEAD);
        assert!(det.is_sanitizer_call_site(0xDEAD));
        assert!(!det.is_sanitizer_call_site(0xBEEF));
    }

    #[test]
    fn test_effective_return_taint_clear_all() {
        let det = SanitizerDetector::with_builtins();
        let t = det.effective_return_taint("htmlspecialchars", &[taint_bits::USER_INPUT]);
        assert_eq!(t, Some(taint_bits::NONE));
    }

    #[test]
    fn test_summary() {
        let mut det = SanitizerDetector::with_builtins();
        det.check_call("htmlspecialchars", &[taint_bits::USER_INPUT], 0x10);
        det.check_call("htmlentities", &[taint_bits::NETWORK], 0x20);
        let s = det.summary();
        assert_eq!(s.total_matches, 2);
        assert_eq!(s.unique_call_sites, 2);
        assert!(s.any_detected());
    }

    #[test]
    fn test_reset_history() {
        let mut det = SanitizerDetector::with_builtins();
        det.check_call("htmlspecialchars", &[taint_bits::USER_INPUT], 0x10);
        det.reset_history();
        assert!(det.history().is_empty());
        assert!(!det.is_sanitizer_call_site(0x10));
    }

    #[test]
    fn test_sanitizer_kind_fully_removes_taint() {
        assert!(SanitizerKind::HtmlEscape.fully_removes_taint());
        assert!(SanitizerKind::SqlEscape.fully_removes_taint());
        assert!(!SanitizerKind::CryptoHash.fully_removes_taint());
        assert!(!SanitizerKind::Encoding.fully_removes_taint());
    }

    #[test]
    fn test_clear_bits_effect() {
        let mask = taint_bits::USER_INPUT | taint_bits::NETWORK;
        let m = SanitizerMatch {
            function_name: "custom_san".to_string(),
            pattern: SanitizerPattern::for_function(
                "custom_san",
                SanitizerKind::Custom("x".into()),
                SanitizerEffect::ClearBits(taint_bits::USER_INPUT),
            ),
            input_taint: mask,
            call_addr: 0,
        };
        let result = m.resulting_taint();
        assert_eq!(result & taint_bits::USER_INPUT, 0);
        assert_ne!(result & taint_bits::NETWORK, 0);
    }

    #[test]
    fn test_registry_into_detector() {
        let mut reg = SanitizerRegistry::new();
        reg.add(SanitizerPattern::for_function(
            "my_san",
            SanitizerKind::Validation,
            SanitizerEffect::ClearAll,
        ));
        assert_eq!(reg.len(), 1);
        let mut det = reg.into_detector();
        let m = det.check_call("my_san", &[taint_bits::FILE], 0x999);
        assert!(m.is_some());
    }

    #[test]
    fn test_patterns_by_kind() {
        let det = SanitizerDetector::with_builtins();
        let html = det.patterns_by_kind(&SanitizerKind::HtmlEscape);
        assert!(!html.is_empty());
        let sql = det.patterns_by_kind(&SanitizerKind::SqlEscape);
        assert!(!sql.is_empty());
    }
}

// ─── helper on SanitizerMatch ─────────────────────────────────────────────────

impl SanitizerMatch {
    /// Shorthand label for the kind.
    #[must_use]
    pub fn kind_label(&self) -> &str {
        self.pattern.kind.label()
    }
}
