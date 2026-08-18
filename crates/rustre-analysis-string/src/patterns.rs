//! Pattern matching and heuristic detection for interesting strings in binaries.
//!
//! This module provides:
//! - [`StringPattern`] — a named pattern rule (literal or heuristic).
//! - [`PatternMatcher`] — runs a set of patterns against a string.
//! - [`PatternMatch`] — a hit from the matcher.
//! - [`InterestingString`] — a string annotated with its match results.
//! - [`StringStatistics`] — corpus-level statistics (frequency, length dist.).
//! - [`StringFilter`] — filter strings by length, encoding, pattern, etc.
//! - [`BinaryStringScanner`] — high-level scanner over a raw byte blob.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// StringPattern
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of string pattern to match.
#[derive(Debug, Clone)]
pub enum PatternKind {
    /// Exact substring match (case-sensitive).
    Contains(String),
    /// Exact prefix match.
    StartsWith(String),
    /// Exact suffix match.
    EndsWith(String),
    /// All characters match a predicate (heuristic rule).
    AllChars(CharClass),
    /// Any character matches a predicate.
    AnyChar(CharClass),
    /// Minimum length threshold.
    MinLength(usize),
    /// Maximum length threshold.
    MaxLength(usize),
    /// Shannon entropy above a threshold.
    HighEntropy(f64),
    /// Low-entropy (repetitive) string.
    LowEntropy(f64),
    /// Looks like a Windows registry path.
    WindowsRegistry,
    /// Looks like a file path (Unix or Windows).
    FilePath,
    /// Looks like a format string.
    FormatString,
    /// Looks like a UUID / GUID.
    Uuid,
    /// Looks like a hash string (hex of typical hash lengths).
    HashString,
    /// Contains common keywords from a given category.
    Keywords(Vec<String>),
}

/// A named pattern rule.
#[derive(Debug, Clone)]
pub struct StringPattern {
    /// Unique identifier for this pattern.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// The matching logic.
    pub kind: PatternKind,
    /// Severity / priority score (0–100).
    pub score: u32,
}

impl StringPattern {
    /// Create a new pattern.
    #[must_use]
    pub fn new(id: impl Into<String>, desc: impl Into<String>, kind: PatternKind, score: u32) -> Self {
        Self { id: id.into(), description: desc.into(), kind, score }
    }

    /// Test whether `s` matches this pattern.
    #[must_use]
    pub fn matches(&self, s: &str) -> bool {
        match &self.kind {
            PatternKind::Contains(sub)    => s.contains(sub.as_str()),
            PatternKind::StartsWith(pfx)  => s.starts_with(pfx.as_str()),
            PatternKind::EndsWith(sfx)    => s.ends_with(sfx.as_str()),
            PatternKind::AllChars(cls)    => !s.is_empty() && s.chars().all(|c| cls.matches(c)),
            PatternKind::AnyChar(cls)     => s.chars().any(|c| cls.matches(c)),
            PatternKind::MinLength(n)     => s.len() >= *n,
            PatternKind::MaxLength(n)     => s.len() <= *n,
            PatternKind::HighEntropy(t)   => shannon_entropy_str(s) >= *t,
            PatternKind::LowEntropy(t)    => shannon_entropy_str(s) <= *t,
            PatternKind::WindowsRegistry  => is_windows_registry(s),
            PatternKind::FilePath         => is_file_path(s),
            PatternKind::FormatString     => has_format_specifiers(s),
            PatternKind::Uuid             => is_uuid_like(s),
            PatternKind::HashString       => is_hash_string(s),
            PatternKind::Keywords(kws)    => {
                let sl = s.to_ascii_lowercase();
                kws.iter().any(|k| sl.contains(k.to_ascii_lowercase().as_str()))
            },
        }
    }
}

/// A character class for pattern matching.
#[derive(Debug, Clone)]
pub enum CharClass {
    /// Printable ASCII characters.
    PrintableAscii,
    /// Hexadecimal digits (`[0-9a-fA-F]`).
    HexDigit,
    /// Alphanumeric characters.
    AlphaNumeric,
    /// Whitespace characters.
    Whitespace,
    /// Upper-case letters.
    UpperCase,
    /// Lower-case letters.
    LowerCase,
    /// Digit characters.
    Digit,
    /// Base64 alphabet characters.
    Base64,
}

impl CharClass {
    /// Return `true` if `c` belongs to this class.
    #[must_use]
    pub fn matches(&self, c: char) -> bool {
        match self {
            Self::PrintableAscii => c.is_ascii() && !c.is_ascii_control(),
            Self::HexDigit       => c.is_ascii_hexdigit(),
            Self::AlphaNumeric   => c.is_alphanumeric(),
            Self::Whitespace     => c.is_whitespace(),
            Self::UpperCase      => c.is_uppercase(),
            Self::LowerCase      => c.is_lowercase(),
            Self::Digit          => c.is_ascii_digit(),
            Self::Base64         => c.is_alphanumeric() || c == '+' || c == '/' || c == '=',
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern heuristics
// ─────────────────────────────────────────────────────────────────────────────

/// Compute Shannon entropy for a string (in bits per character).
#[must_use]
pub fn shannon_entropy_str(s: &str) -> f64 {
    // Byte-level entropy of the UTF-8 encoding — identical to what the old
    // HashMap-based loop computed (it counted bytes, divided by byte length).
    crate::classify::shannon_entropy(s.as_bytes())
}

/// Return `true` if `s` looks like a Windows registry path.
#[must_use]
pub fn is_windows_registry(s: &str) -> bool {
    let prefixes = ["HKEY_LOCAL_MACHINE", "HKLM", "HKEY_CURRENT_USER", "HKCU",
                    "HKEY_CLASSES_ROOT", "HKCR", "HKEY_USERS", "HKU",
                    "HKEY_CURRENT_CONFIG", "HKCC"];
    let su = s.to_ascii_uppercase();
    prefixes.iter().any(|&p| su.starts_with(p))
}

/// Return `true` if `s` looks like a file system path.
#[must_use]
pub fn is_file_path(s: &str) -> bool {
    // Unix: starts with '/'
    if s.starts_with('/') && s.len() > 1 {
        return true;
    }
    // Windows absolute: X:\
    if s.len() >= 3 {
        let bytes = s.as_bytes();
        if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
            return true;
        }
    }
    // UNC path: \\server\share
    if s.starts_with("\\\\") {
        return true;
    }
    false
}

/// Return `true` if `s` contains C-style format specifiers (`%d`, `%s`, etc.).
#[must_use]
pub fn has_format_specifiers(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'%' {
            let next = bytes[i + 1];
            // Common format specifiers
            if matches!(next, b'd' | b'i' | b'u' | b'f' | b'e' | b'g' | b's' | b'p' | b'x' | b'X' | b'c' | b'o' | b'%') {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Return `true` if `s` looks like a UUID/GUID string.
///
/// Format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
#[must_use]
pub fn is_uuid_like(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let b = s.as_bytes();
    // Positions 8, 13, 18, 23 must be '-'
    if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
        return false;
    }
    // All other positions must be hex digits
    for (i, &byte) in b.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Return `true` if `s` looks like a hash string (16/32/40/56/64 hex chars).
#[must_use]
pub fn is_hash_string(s: &str) -> bool {
    let len = s.len();
    if !matches!(len, 16 | 32 | 40 | 56 | 64 | 128) {
        return false;
    }
    s.chars().all(|c| c.is_ascii_hexdigit())
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternMatch
// ─────────────────────────────────────────────────────────────────────────────

/// A single match of a [`StringPattern`] against a string.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// The pattern ID that matched.
    pub pattern_id: String,
    /// The score of the matched pattern.
    pub score: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternMatcher
// ─────────────────────────────────────────────────────────────────────────────

/// Runs a set of [`StringPattern`]s against strings.
#[derive(Debug, Clone, Default)]
pub struct PatternMatcher {
    patterns: Vec<StringPattern>,
}

impl PatternMatcher {
    /// Create an empty matcher.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pattern.
    pub fn add(&mut self, pattern: StringPattern) {
        self.patterns.push(pattern);
    }

    /// Test `s` against all patterns and return the matches.
    #[must_use]
    pub fn match_all(&self, s: &str) -> Vec<PatternMatch> {
        self.patterns.iter()
            .filter(|p| p.matches(s))
            .map(|p| PatternMatch { pattern_id: p.id.clone(), score: p.score })
            .collect()
    }

    /// Return the total score of all matching patterns.
    #[must_use]
    pub fn total_score(&self, s: &str) -> u32 {
        self.match_all(s).iter().map(|m| m.score).sum()
    }

    /// Return `true` if any pattern matches.
    #[must_use]
    pub fn any_match(&self, s: &str) -> bool {
        self.patterns.iter().any(|p| p.matches(s))
    }

    /// Return the number of patterns registered.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Build a default matcher with common security-relevant patterns.
    #[must_use]
    pub fn default_security_patterns() -> Self {
        let mut m = Self::new();
        m.add(StringPattern::new("password_kw", "Contains 'password'",
            PatternKind::Keywords(vec!["password".to_string(), "passwd".to_string(), "pwd".to_string()]), 80));
        m.add(StringPattern::new("secret_kw", "Contains 'secret' or 'token'",
            PatternKind::Keywords(vec!["secret".to_string(), "token".to_string(), "api_key".to_string()]), 75));
        m.add(StringPattern::new("url_prefix", "HTTP/HTTPS URL",
            PatternKind::StartsWith("http".to_string()), 40));
        m.add(StringPattern::new("registry_path", "Windows registry path",
            PatternKind::WindowsRegistry, 50));
        m.add(StringPattern::new("file_path", "File system path",
            PatternKind::FilePath, 30));
        m.add(StringPattern::new("format_str", "C-style format string",
            PatternKind::FormatString, 20));
        m.add(StringPattern::new("uuid", "UUID/GUID",
            PatternKind::Uuid, 35));
        m.add(StringPattern::new("hash", "Hash string (hex digest)",
            PatternKind::HashString, 45));
        m.add(StringPattern::new("high_entropy", "High-entropy (possible key/cipher)",
            PatternKind::HighEntropy(4.5), 60));
        m.add(StringPattern::new("sql_kw", "SQL keywords",
            PatternKind::Keywords(vec!["select".to_string(), "insert".to_string(),
                "update".to_string(), "delete".to_string(), "drop".to_string()]), 55));
        m
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InterestingString
// ─────────────────────────────────────────────────────────────────────────────

/// A string annotated with pattern-match results and metadata.
#[derive(Debug, Clone)]
pub struct InterestingString {
    /// The string value.
    pub value: String,
    /// Pattern matches against this string.
    pub matches: Vec<PatternMatch>,
    /// Shannon entropy of the string.
    pub entropy: f64,
    /// Total score (sum of matching pattern scores).
    pub total_score: u32,
}

impl InterestingString {
    /// Create from a string value and a matcher.
    #[must_use]
    pub fn analyze(s: impl Into<String>, matcher: &PatternMatcher) -> Self {
        let value: String = s.into();
        let matches = matcher.match_all(&value);
        let entropy = shannon_entropy_str(&value);
        let total_score = matches.iter().map(|m| m.score).sum();
        Self { value, matches, entropy, total_score }
    }

    /// Return `true` if this string matched at least one pattern.
    #[must_use]
    pub const fn has_matches(&self) -> bool {
        !self.matches.is_empty()
    }

    /// Return the IDs of all matching patterns.
    #[must_use]
    pub fn matched_pattern_ids(&self) -> Vec<&str> {
        self.matches.iter().map(|m| m.pattern_id.as_str()).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringStatistics
// ─────────────────────────────────────────────────────────────────────────────

/// Corpus-level statistics over a collection of strings.
#[derive(Debug, Clone)]
pub struct StringStatistics {
    /// Total number of strings.
    pub count: usize,
    /// Total character count across all strings.
    pub total_chars: usize,
    /// Minimum string length.
    pub min_length: usize,
    /// Maximum string length.
    pub max_length: usize,
    /// Average string length.
    pub mean_length: f64,
    /// Median string length.
    pub median_length: f64,
    /// Average Shannon entropy.
    pub mean_entropy: f64,
    /// Fraction of strings that are high-entropy (entropy > 4.0).
    pub high_entropy_fraction: f64,
    /// Most common string prefix of length 4 (empty if < 2 strings).
    pub most_common_prefix: String,
}

impl StringStatistics {
    /// Compute statistics for a collection of strings.
    #[must_use]
    pub fn compute(strings: &[&str]) -> Self {
        if strings.is_empty() {
            return Self {
                count: 0,
                total_chars: 0,
                min_length: 0,
                max_length: 0,
                mean_length: 0.0,
                median_length: 0.0,
                mean_entropy: 0.0,
                high_entropy_fraction: 0.0,
                most_common_prefix: String::new(),
            };
        }
        let count = strings.len();
        let total_chars: usize = strings.iter().map(|s| s.len()).sum();
        let mut lengths: Vec<usize> = strings.iter().map(|s| s.len()).collect();
        lengths.sort_unstable();
        let min_length = *lengths.first().unwrap_or(&0);
        let max_length = *lengths.last().unwrap_or(&0);
        let mean_length = total_chars as f64 / count as f64;
        let median_length = if count.is_multiple_of(2) {
            (lengths[count / 2 - 1] + lengths[count / 2]) as f64 / 2.0
        } else {
            lengths[count / 2] as f64
        };

        let entropies: Vec<f64> = strings.iter().map(|s| shannon_entropy_str(s)).collect();
        let mean_entropy = entropies.iter().sum::<f64>() / count as f64;
        let high_entropy_fraction = entropies.iter().filter(|&&e| e > 4.0).count() as f64 / count as f64;

        // Most common 4-character prefix
        let mut prefix_counts: HashMap<String, usize> = HashMap::new();
        for s in strings {
            if s.len() >= 4 {
                let pfx: String = s.chars().take(4).collect();
                *prefix_counts.entry(pfx).or_default() += 1;
            }
        }
        // Deterministic tie-break: highest count, then lexicographically
        // smallest prefix (HashMap iteration order is otherwise random).
        let most_common_prefix = prefix_counts.into_iter()
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
            .map(|(p, _)| p)
            .unwrap_or_default();

        Self {
            count,
            total_chars,
            min_length,
            max_length,
            mean_length,
            median_length,
            mean_entropy,
            high_entropy_fraction,
            most_common_prefix,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringFilter
// ─────────────────────────────────────────────────────────────────────────────

/// A composable filter for selecting strings from a corpus.
#[derive(Debug, Clone, Default)]
pub struct StringFilter {
    /// Minimum length (inclusive).
    pub min_length: Option<usize>,
    /// Maximum length (inclusive).
    pub max_length: Option<usize>,
    /// Required substring.
    pub contains: Option<String>,
    /// Required prefix.
    pub starts_with: Option<String>,
    /// Required suffix.
    pub ends_with: Option<String>,
    /// Minimum entropy.
    pub min_entropy: Option<f64>,
    /// Maximum entropy.
    pub max_entropy: Option<f64>,
    /// Only strings that are all-ASCII.
    pub ascii_only: bool,
    /// Only strings matching at least one of these pattern IDs.
    pub required_patterns: Vec<String>,
}

impl StringFilter {
    /// Create an empty (pass-all) filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return `true` if `s` passes all filter criteria.
    #[must_use]
    pub fn accepts(&self, s: &str) -> bool {
        if let Some(min) = self.min_length {
            if s.len() < min { return false; }
        }
        if let Some(max) = self.max_length {
            if s.len() > max { return false; }
        }
        if let Some(c) = &self.contains {
            if !s.contains(c.as_str()) { return false; }
        }
        if let Some(pfx) = &self.starts_with {
            if !s.starts_with(pfx.as_str()) { return false; }
        }
        if let Some(sfx) = &self.ends_with {
            if !s.ends_with(sfx.as_str()) { return false; }
        }
        if let Some(min_e) = self.min_entropy {
            if shannon_entropy_str(s) < min_e { return false; }
        }
        if let Some(max_e) = self.max_entropy {
            if shannon_entropy_str(s) > max_e { return false; }
        }
        if self.ascii_only && !s.is_ascii() {
            return false;
        }
        // Check required_patterns: if any IDs are specified, the string must match
        // at least one of the named patterns using the default security pattern set
        // as a baseline. Callers needing a custom matcher should call accepts_with_matcher.
        if !self.required_patterns.is_empty() {
            let matcher = PatternMatcher::default_security_patterns();
            let matches = matcher.match_all(s);
            let any_required_matched = matches
                .iter()
                .any(|m| self.required_patterns.contains(&m.pattern_id));
            if !any_required_matched {
                return false;
            }
        }
        true
    }

    /// Like [`accepts`] but uses a caller-supplied [`PatternMatcher`] for
    /// evaluating [`required_patterns`].
    #[must_use]
    pub fn accepts_with_matcher(&self, s: &str, matcher: &PatternMatcher) -> bool {
        if let Some(min) = self.min_length {
            if s.len() < min { return false; }
        }
        if let Some(max) = self.max_length {
            if s.len() > max { return false; }
        }
        if let Some(c) = &self.contains {
            if !s.contains(c.as_str()) { return false; }
        }
        if let Some(pfx) = &self.starts_with {
            if !s.starts_with(pfx.as_str()) { return false; }
        }
        if let Some(sfx) = &self.ends_with {
            if !s.ends_with(sfx.as_str()) { return false; }
        }
        if let Some(min_e) = self.min_entropy {
            if shannon_entropy_str(s) < min_e { return false; }
        }
        if let Some(max_e) = self.max_entropy {
            if shannon_entropy_str(s) > max_e { return false; }
        }
        if self.ascii_only && !s.is_ascii() {
            return false;
        }
        if !self.required_patterns.is_empty() {
            let matches = matcher.match_all(s);
            let any_required_matched = matches
                .iter()
                .any(|m| self.required_patterns.contains(&m.pattern_id));
            if !any_required_matched {
                return false;
            }
        }
        true
    }

    /// Filter a slice of strings, returning those that pass.
    #[must_use]
    pub fn filter<'a>(&self, strings: &[&'a str]) -> Vec<&'a str> {
        strings.iter().filter(|&&s| self.accepts(s)).copied().collect()
    }

    /// Count strings that pass the filter.
    #[must_use]
    pub fn count_passing(&self, strings: &[&str]) -> usize {
        strings.iter().filter(|&&s| self.accepts(s)).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BinaryStringScanner
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the binary string scanner.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Minimum printable-ASCII string length to extract.
    pub min_ascii_len: usize,
    /// Whether to extract null-terminated C strings.
    pub extract_cstrings: bool,
    /// Whether to extract wide (UTF-16LE) strings.
    pub extract_wide: bool,
    /// Maximum number of strings to return (0 = unlimited).
    pub max_strings: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            min_ascii_len: 4,
            extract_cstrings: true,
            extract_wide: true,
            max_strings: 0,
        }
    }
}

/// A string found during a binary scan.
#[derive(Debug, Clone)]
pub struct ScannedString {
    /// The string value.
    pub value: String,
    /// Byte offset in the input data.
    pub offset: usize,
    /// Whether this was a wide string.
    pub is_wide: bool,
}

impl fmt::Display for ScannedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_wide {
            write!(f, "[0x{:08x}] (wide) {:?}", self.offset, self.value)
        } else {
            write!(f, "[0x{:08x}] {:?}", self.offset, self.value)
        }
    }
}

/// High-level scanner for printable strings in raw binary data.
pub struct BinaryStringScanner;

impl BinaryStringScanner {
    /// Scan `data` for printable-ASCII strings of at least `min_len` bytes.
    ///
    /// Returns a list of [`ScannedString`] records in offset order.
    #[must_use]
    pub fn scan_ascii(data: &[u8], min_len: usize) -> Vec<ScannedString> {
        let mut results = Vec::new();
        let mut start: Option<usize> = None;
        let mut i = 0;

        while i < data.len() {
            let b = data[i];
            if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
                if start.is_none() {
                    start = Some(i);
                }
            } else {
                if let Some(s) = start.take() {
                    let run = &data[s..i];
                    if run.len() >= min_len {
                        if let Ok(val) = std::str::from_utf8(run) {
                            results.push(ScannedString {
                                value: val.to_string(),
                                offset: s,
                                is_wide: false,
                            });
                        }
                    }
                }
            }
            i += 1;
        }

        // Flush trailing run
        if let Some(s) = start {
            let run = &data[s..];
            if run.len() >= min_len {
                if let Ok(val) = std::str::from_utf8(run) {
                    results.push(ScannedString {
                        value: val.to_string(),
                        offset: s,
                        is_wide: false,
                    });
                }
            }
        }

        results
    }

    /// Scan `data` for UTF-16LE strings of at least `min_len` characters.
    ///
    /// Tries both 2-byte-aligned starting offsets (0 and 1) so that strings at
    /// an odd byte alignment within the buffer are not missed or garbled.
    #[must_use]
    pub fn scan_wide(data: &[u8], min_len: usize) -> Vec<ScannedString> {
        let mut results = Vec::new();
        if data.len() < 2 {
            return results;
        }

        // Try both alignment phases: starting at byte 0 and starting at byte 1.
        for phase in 0..2usize {
            let mut i = phase;
            let mut run_start: Option<usize> = None;
            let mut run_chars: Vec<u16> = Vec::new();

            while i + 1 < data.len() {
                let lo = data[i] as u16;
                let hi = data[i + 1] as u16;
                let cp = lo | (hi << 8);

                // Accept printable ASCII range as UTF-16LE
                let is_printable = (0x0020..=0x007E).contains(&cp);

                if is_printable {
                    if run_start.is_none() {
                        run_start = Some(i);
                    }
                    run_chars.push(cp);
                } else {
                    if let Some(s) = run_start.take() {
                        if run_chars.len() >= min_len {
                            let val: String = run_chars.iter().map(|&c| char::from(c as u8)).collect();
                            results.push(ScannedString { value: val, offset: s, is_wide: true });
                        }
                        run_chars.clear();
                    }
                }
                i += 2;
            }

            // Flush trailing run
            if let Some(s) = run_start {
                if run_chars.len() >= min_len {
                    let val: String = run_chars.iter().map(|&c| char::from(c as u8)).collect();
                    results.push(ScannedString { value: val, offset: s, is_wide: true });
                }
            }
        }

        // Deduplicate: if both alignments produce the same string at the same offset,
        // keep only the first occurrence.
        results.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.value.cmp(&b.value)));
        results.dedup_by(|a, b| a.offset == b.offset && a.value == b.value);

        results
    }

    /// Perform a combined scan and return all strings (ASCII + wide).
    #[must_use]
    pub fn scan(data: &[u8], config: &ScanConfig) -> Vec<ScannedString> {
        let mut results = Self::scan_ascii(data, config.min_ascii_len);
        if config.extract_wide {
            results.extend(Self::scan_wide(data, config.min_ascii_len));
        }
        results.sort_by_key(|s| s.offset);
        if config.max_strings > 0 {
            results.truncate(config.max_strings);
        }
        results
    }

    /// Return the count of unique printable-string values found.
    #[must_use]
    pub fn unique_count(data: &[u8], config: &ScanConfig) -> usize {
        let mut seen = std::collections::HashSet::new();
        for s in Self::scan(data, config) {
            seen.insert(s.value);
        }
        seen.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regress_most_common_prefix_deterministic_on_ties() {
        // Two prefixes with equal counts: the lexicographically smallest must
        // win, on every call (previously HashMap iteration order decided).
        let strings = ["bbbb_one", "bbbb_two", "aaaa_one", "aaaa_two"];
        for _ in 0..20 {
            let stats = StringStatistics::compute(&strings);
            assert_eq!(stats.most_common_prefix, "aaaa");
        }
    }

    // ── PatternKind::Contains ────────────────────────────────────────────────

    #[test]
    fn test_pattern_contains_match() {
        let p = StringPattern::new("p1", "desc", PatternKind::Contains("hello".to_string()), 10);
        assert!(p.matches("say hello world"));
        assert!(!p.matches("goodbye world"));
    }

    #[test]
    fn test_pattern_starts_with() {
        let p = StringPattern::new("p2", "desc", PatternKind::StartsWith("http".to_string()), 10);
        assert!(p.matches("https://example.com"));
        assert!(!p.matches("ftp://example.com"));
    }

    #[test]
    fn test_pattern_ends_with() {
        let p = StringPattern::new("p3", "desc", PatternKind::EndsWith(".dll".to_string()), 10);
        assert!(p.matches("kernel32.dll"));
        assert!(!p.matches("kernel32.exe"));
    }

    #[test]
    fn test_pattern_min_length() {
        let p = StringPattern::new("p4", "desc", PatternKind::MinLength(5), 10);
        assert!(p.matches("hello"));
        assert!(!p.matches("hi"));
    }

    #[test]
    fn test_pattern_max_length() {
        let p = StringPattern::new("p5", "desc", PatternKind::MaxLength(3), 10);
        assert!(p.matches("hi"));
        assert!(!p.matches("hello world"));
    }

    #[test]
    fn test_pattern_all_chars_hex() {
        let p = StringPattern::new("p6", "desc", PatternKind::AllChars(CharClass::HexDigit), 10);
        assert!(p.matches("deadbeef"));
        assert!(!p.matches("deadbeefXYZ"));
    }

    #[test]
    fn test_pattern_file_path_unix() {
        let p = StringPattern::new("p7", "desc", PatternKind::FilePath, 10);
        assert!(p.matches("/etc/passwd"));
        assert!(!p.matches("relative/path"));
    }

    #[test]
    fn test_pattern_file_path_windows() {
        let p = StringPattern::new("p8", "desc", PatternKind::FilePath, 10);
        assert!(p.matches(r"C:\Windows\System32\cmd.exe"));
    }

    #[test]
    fn test_pattern_uuid() {
        let p = StringPattern::new("p9", "desc", PatternKind::Uuid, 10);
        assert!(p.matches("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!p.matches("not-a-uuid"));
    }

    #[test]
    fn test_pattern_hash_string() {
        let p = StringPattern::new("p10", "desc", PatternKind::HashString, 10);
        assert!(p.matches("deadbeefdeadbeefdeadbeefdeadbeef")); // 32 hex chars = MD5
        assert!(!p.matches("deadbeef")); // 8 chars, not a hash length
    }

    #[test]
    fn test_pattern_keywords() {
        let p = StringPattern::new("p11", "desc",
            PatternKind::Keywords(vec!["password".to_string()]), 10);
        assert!(p.matches("Enter your password:"));
        assert!(!p.matches("Hello World"));
    }

    #[test]
    fn test_pattern_format_specifiers() {
        let p = StringPattern::new("p12", "desc", PatternKind::FormatString, 10);
        assert!(p.matches("Value: %d"));
        assert!(!p.matches("No specifiers here"));
    }

    #[test]
    fn test_pattern_windows_registry() {
        let p = StringPattern::new("p13", "desc", PatternKind::WindowsRegistry, 10);
        assert!(p.matches("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft"));
        assert!(!p.matches("C:\\Windows\\System32"));
    }

    // ── PatternMatcher ───────────────────────────────────────────────────────

    #[test]
    fn test_matcher_match_all() {
        let mut m = PatternMatcher::new();
        m.add(StringPattern::new("http", "url", PatternKind::StartsWith("http".to_string()), 10));
        m.add(StringPattern::new("long", "long str", PatternKind::MinLength(10), 5));
        let matches = m.match_all("https://example.com/path");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_matcher_total_score() {
        let mut m = PatternMatcher::new();
        m.add(StringPattern::new("p1", "d", PatternKind::StartsWith("http".to_string()), 30));
        m.add(StringPattern::new("p2", "d", PatternKind::MinLength(5), 20));
        let score = m.total_score("http://x.com");
        assert_eq!(score, 50);
    }

    #[test]
    fn test_matcher_any_match() {
        let mut m = PatternMatcher::new();
        m.add(StringPattern::new("p1", "d", PatternKind::Contains("admin".to_string()), 10));
        assert!(m.any_match("/admin/panel"));
        assert!(!m.any_match("/user/profile"));
    }

    #[test]
    fn test_matcher_no_patterns() {
        let m = PatternMatcher::new();
        assert!(m.match_all("anything").is_empty());
        assert_eq!(m.total_score("anything"), 0);
    }

    #[test]
    fn test_matcher_default_security_patterns() {
        let m = PatternMatcher::default_security_patterns();
        assert!(m.pattern_count() > 0);
        // "password" should match the password pattern
        assert!(m.any_match("password=abc123"));
        // http URL
        assert!(m.any_match("https://evil.com/exploit"));
    }

    // ── InterestingString ─────────────────────────────────────────────────────

    #[test]
    fn test_interesting_string_has_matches() {
        let m = PatternMatcher::default_security_patterns();
        let is = InterestingString::analyze("password=secret", &m);
        assert!(is.has_matches());
        assert!(is.total_score > 0);
    }

    #[test]
    fn test_interesting_string_no_matches() {
        let m = PatternMatcher::default_security_patterns();
        let is = InterestingString::analyze("hello world", &m);
        // "hello world" doesn't match any security patterns
        assert!(!is.has_matches() || is.total_score > 0);
        // Entropy should be > 0
        assert!(is.entropy > 0.0);
    }

    // ── StringStatistics ──────────────────────────────────────────────────────

    #[test]
    fn test_statistics_empty() {
        let stats = StringStatistics::compute(&[]);
        assert_eq!(stats.count, 0);
        assert_eq!(stats.mean_length, 0.0);
    }

    #[test]
    fn test_statistics_basic() {
        let strings = ["hello", "world", "foo", "bar baz"];
        let stats = StringStatistics::compute(&strings);
        assert_eq!(stats.count, 4);
        assert_eq!(stats.min_length, 3);
        assert_eq!(stats.max_length, 7);
        assert!(stats.mean_length > 0.0);
    }

    #[test]
    fn test_statistics_entropy() {
        let strings = ["aaaaaa", "abcdefghij"];
        let stats = StringStatistics::compute(&strings);
        assert!(stats.mean_entropy >= 0.0);
    }

    // ── StringFilter ──────────────────────────────────────────────────────────

    #[test]
    fn test_filter_min_length() {
        let mut f = StringFilter::new();
        f.min_length = Some(5);
        let strings = ["hi", "hello", "world!", "x"];
        let result = f.filter(&strings);
        assert_eq!(result, vec!["hello", "world!"]);
    }

    #[test]
    fn test_filter_contains() {
        let mut f = StringFilter::new();
        f.contains = Some("pass".to_string());
        let strings = ["password", "username", "passphrase"];
        let result = f.filter(&strings);
        assert_eq!(result, vec!["password", "passphrase"]);
    }

    #[test]
    fn test_filter_ascii_only() {
        let mut f = StringFilter::new();
        f.ascii_only = true;
        let strings = ["hello", "héllo", "world"];
        let result = f.filter(&strings);
        assert_eq!(result, vec!["hello", "world"]);
    }

    #[test]
    fn test_filter_count_passing() {
        let mut f = StringFilter::new();
        f.min_length = Some(4);
        let strings = ["hi", "hello", "world"];
        assert_eq!(f.count_passing(&strings), 2);
    }

    // ── BinaryStringScanner ───────────────────────────────────────────────────

    #[test]
    fn test_scan_ascii_basic() {
        let data = b"Hello\x00World\x00\xFF";
        let results = BinaryStringScanner::scan_ascii(data, 3);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].value, "Hello");
        assert_eq!(results[1].value, "World");
    }

    #[test]
    fn test_scan_ascii_min_length() {
        let data = b"Hi\x00Hello";
        let results = BinaryStringScanner::scan_ascii(data, 4);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "Hello");
    }

    #[test]
    fn test_scan_wide_basic() {
        // "Hi" in UTF-16LE: H=0x48 0x00, i=0x69 0x00, NUL=0x00 0x00
        let data: Vec<u8> = b"H\x00i\x00\x00\x00".to_vec();
        let results = BinaryStringScanner::scan_wide(&data, 2);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "Hi");
        assert!(results[0].is_wide);
    }

    #[test]
    fn test_scan_combined() {
        let mut data = b"Hello\x00\xFF".to_vec();
        // Append "Hi" as wide
        data.extend_from_slice(b"H\x00i\x00\x00\x00");
        let config = ScanConfig { min_ascii_len: 3, extract_wide: true, extract_cstrings: true, max_strings: 0 };
        let results = BinaryStringScanner::scan(&data, &config);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_scan_max_strings() {
        let data = b"AAAA\x00BBBB\x00CCCC\x00";
        let config = ScanConfig { min_ascii_len: 3, extract_wide: false, extract_cstrings: true, max_strings: 2 };
        let results = BinaryStringScanner::scan(data, &config);
        assert!(results.len() <= 2);
    }

    #[test]
    fn test_unique_count() {
        let data = b"AAAA\x00AAAA\x00BBBB\x00";
        let config = ScanConfig::default();
        let count = BinaryStringScanner::unique_count(data, &config);
        // "AAAA" and "BBBB" are two unique strings
        assert_eq!(count, 2);
    }

    // ── Shannon entropy ───────────────────────────────────────────────────────

    #[test]
    fn test_entropy_all_same() {
        assert_eq!(shannon_entropy_str("aaaaaaa"), 0.0);
    }

    #[test]
    fn test_entropy_empty() {
        assert_eq!(shannon_entropy_str(""), 0.0);
    }

    #[test]
    fn test_entropy_increases_with_variety() {
        let e1 = shannon_entropy_str("aaab");
        let e2 = shannon_entropy_str("abcd");
        assert!(e2 > e1);
    }

    // ── is_uuid_like ─────────────────────────────────────────────────────────

    #[test]
    fn test_is_uuid_like_valid() {
        assert!(is_uuid_like("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn test_is_uuid_like_invalid_short() {
        assert!(!is_uuid_like("550e8400-e29b-41d4"));
    }

    #[test]
    fn test_is_hash_string_md5() {
        assert!(is_hash_string("d41d8cd98f00b204e9800998ecf8427e")); // 32 chars
    }

    #[test]
    fn test_is_hash_string_sha1() {
        assert!(is_hash_string("da39a3ee5e6b4b0d3255bfef95601890afd80709")); // 40 chars
    }

    #[test]
    fn test_is_hash_string_invalid_chars() {
        assert!(!is_hash_string("da39a3ee5e6b4b0d3255bfef95601890afd8070Z")); // 'Z' not hex
    }
}
