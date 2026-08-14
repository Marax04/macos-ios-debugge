//! `rustre-triage-yara`
//!
//! YARA-like rule engine for file triage —" scan raw binary data using
//! flexible string-matching rules.

pub mod family_classifier;
pub mod ioc_extractor;
pub mod match_report;
pub mod rule_optimizer;
pub mod scanner;
pub mod rule_compiler;
pub mod verdict;
pub mod yara_threat_intel;
pub mod yara_vm;
pub mod yara_module_pe;
pub mod yara_performance_profiler;
pub mod yara_scanner;
pub mod yara_cache;
pub mod yara_match_reporter;
pub mod yara_rule_optimizer;
pub mod yara_ruleset_manager;
pub mod yara_threat_tagger;

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Compatibility re-exports / kept types from the original stub
// ---------------------------------------------------------------------------

/// A legacy YARA rule definition (kept for backwards compatibility).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct YaraRule {
    /// Rule name.
    pub name: String,
    /// Patterns this rule looks for.
    pub patterns: Vec<Pattern>,
}

/// A pattern used by a legacy [`YaraRule`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Pattern {
    /// Match exact byte sequence.
    Hex(Vec<u8>),
    /// Match UTF-8 text string.
    Text(String),
}

/// A legacy match result produced by [`scan_data`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct YaraMatch {
    /// Name of the matching rule.
    pub rule_name: String,
    /// Index of the matching pattern inside the rule.
    pub pattern_index: usize,
    /// File offset where the match was found.
    pub offset: usize,
}

impl fmt::Display for YaraMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Rule '{}' pattern#{} @ offset {:#x}",
            self.rule_name, self.pattern_index, self.offset
        )
    }
}

/// Scan `data` against a slice of legacy [`YaraRule`]s.
///
/// Each pattern is searched with non-overlapping semantics: after a match at
/// offset `i` the search advances by `needle.len()` rather than one byte,
/// preventing O(nÂ·m) output growth on large inputs.
#[must_use]
pub fn scan_data(rules: &[YaraRule], data: &[u8]) -> Vec<YaraMatch> {
    let mut matches = Vec::new();

    for rule in rules {
        for (idx, pattern) in rule.patterns.iter().enumerate() {
            let needle: Vec<u8> = match pattern {
                Pattern::Hex(b) => b.clone(),
                Pattern::Text(s) => s.as_bytes().to_vec(),
            };
            if needle.is_empty() {
                continue;
            }
            let mut i = 0;
            while i + needle.len() <= data.len() {
                if &data[i..i + needle.len()] == needle.as_slice() {
                    matches.push(YaraMatch {
                        rule_name: rule.name.clone(),
                        pattern_index: idx,
                        offset: i,
                    });
                    // Advance by needle length to avoid O(nÂ·m) overlapping output
                    i += needle.len();
                } else {
                    i += 1;
                }
            }
        }
    }

    matches
}

// ---------------------------------------------------------------------------
// YaraError
// ---------------------------------------------------------------------------

/// Errors from triage YARA operations.
#[derive(Debug, Error)]
pub enum YaraError {
    /// A rule string is empty.
    #[error("empty pattern in rule '{0}'")]
    EmptyPattern(String),
    /// Rule name conflicts with an existing rule.
    #[error("duplicate rule name: '{0}'")]
    DuplicateRule(String),
    /// Generic error.
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// YaraTriageRule
// ---------------------------------------------------------------------------

/// An extended triage rule with metadata, severity, and boolean conditions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraTriageRule {
    /// Unique rule name.
    pub name: String,
    /// Named string patterns: `(identifier, byte_sequence)`.
    pub strings: Vec<(String, Vec<u8>)>,
    /// If `true`, ALL strings must match; if `false`, ANY match fires the rule.
    pub condition_all: bool,
    /// Human-readable description.
    pub description: String,
    /// Arbitrary keyâ†'value metadata.
    pub metadata: HashMap<String, String>,
    /// Classification tags (e.g. `["malware", "trojan"]`).
    pub tags: Vec<String>,
}

impl YaraTriageRule {
    /// Create a new rule.
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            strings: Vec::new(),
            condition_all: false,
            description: description.into(),
            metadata: HashMap::new(),
            tags: Vec::new(),
        }
    }

    /// Add a named string pattern.
    pub fn add_string(&mut self, id: impl Into<String>, pattern: impl Into<Vec<u8>>) {
        self.strings.push((id.into(), pattern.into()));
    }

    /// Add metadata.
    pub fn add_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Add a tag.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }
}

impl fmt::Display for YaraTriageRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rule {} [{}] ({} strings, condition_all={})",
            self.name,
            self.tags.join(", "),
            self.strings.len(),
            self.condition_all
        )
    }
}

// ---------------------------------------------------------------------------
// YaraTriageMatch
// ---------------------------------------------------------------------------

/// A match produced by the triage YARA engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraTriageMatch {
    /// Name of the rule that matched.
    pub rule_name: String,
    /// Strings that matched: `(identifier, file_offset)`.
    pub matched_strings: Vec<(String, u64)>,
    /// Rule description.
    pub description: String,
    /// Severity tag from rule metadata, if present.
    pub severity: String,
}

impl fmt::Display for YaraTriageMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MATCH '{}' severity={} ({} strings)",
            self.rule_name,
            self.severity,
            self.matched_strings.len()
        )
    }
}

// ---------------------------------------------------------------------------
// YaraTriageEngine
// ---------------------------------------------------------------------------

/// The YARA-like triage scan engine.
#[derive(Clone)]
pub struct YaraTriageEngine {
    rules: Vec<YaraTriageRule>,
}

impl YaraTriageEngine {
    /// Create an empty engine.
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule to the engine.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::DuplicateRule`] if a rule with the same name already
    /// exists.
    pub fn add_rule(&mut self, rule: YaraTriageRule) -> Result<(), YaraError> {
        if self.rules.iter().any(|r| r.name == rule.name) {
            return Err(YaraError::DuplicateRule(rule.name));
        }
        self.rules.push(rule);
        Ok(())
    }

    /// Scan `data` starting at virtual offset 0 using [`scan_with_offset`].
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<YaraTriageMatch> {
        self.scan_with_offset(data, 0)
    }

    /// Scan `data` and translate file offsets to virtual addresses by adding
    /// `base_offset`.
    #[must_use]
    pub fn scan_with_offset(&self, data: &[u8], base_offset: u64) -> Vec<YaraTriageMatch> {
        let mut results = Vec::new();

        for rule in &self.rules {
            // Find all matches for each string in the rule
            let mut string_matches: Vec<(String, u64)> = Vec::new();

            for (id, pattern) in &rule.strings {
                if pattern.is_empty() {
                    continue;
                }
                for offset in 0..data.len() {
                    if offset + pattern.len() <= data.len()
                        && &data[offset..offset + pattern.len()] == pattern.as_slice()
                    {
                        string_matches.push((id.clone(), base_offset.saturating_add(offset as u64)));
                    }
                }
            }

            // Apply condition
            let fires = if rule.strings.is_empty() {
                // No strings â†' always fires
                true
            } else if rule.condition_all {
                // All named strings must appear at least once
                rule.strings
                    .iter()
                    .all(|(id, _)| string_matches.iter().any(|(m_id, _)| m_id == id))
            } else {
                // Any string match fires
                !string_matches.is_empty()
            };

            if fires {
                let severity = rule
                    .metadata
                    .get("severity")
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                results.push(YaraTriageMatch {
                    rule_name: rule.name.clone(),
                    matched_strings: string_matches,
                    description: rule.description.clone(),
                    severity,
                });
            }
        }

        results
    }

    /// Return the number of rules loaded.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Build an engine pre-loaded with default malware-detection rules.
    #[must_use]
    pub fn load_default_rules() -> Self {
        let mut engine = Self::new();

        let mut add = |rule: YaraTriageRule| {
            let _ = engine.add_rule(rule);
        };

        // ---- UPX packer detection -------------------------------------------
        let mut r = YaraTriageRule::new("UPX_Packer", "UPX executable packer detected");
        r.add_string("s0", b"UPX0".as_slice());
        r.add_string("s1", b"UPX1".as_slice());
        r.add_meta("severity", "medium");
        r.add_tag("packer");
        add(r);

        // ---- Suspicious WinAPI strings --------------------------------------
        let mut r = YaraTriageRule::new("SuspiciousWinAPI", "Suspicious Windows API calls found");
        r.add_string("virtualalloc", b"VirtualAlloc".as_slice());
        r.add_string("writeprocess", b"WriteProcessMemory".as_slice());
        r.condition_all = false;
        r.add_meta("severity", "high");
        r.add_tag("suspicious");
        add(r);

        // ---- ELF magic ------------------------------------------------------
        let mut r = YaraTriageRule::new("ELF_Magic", "ELF binary detected");
        r.add_string("magic", b"\x7FELF".as_slice());
        r.add_meta("severity", "info");
        r.add_tag("format");
        add(r);

        // ---- MZ magic -------------------------------------------------------
        let mut r = YaraTriageRule::new("PE_Magic", "PE/MZ binary detected");
        r.add_string("magic", b"MZ".as_slice());
        r.add_meta("severity", "info");
        r.add_tag("format");
        add(r);

        // ---- Mimikatz strings -----------------------------------------------
        let mut r = YaraTriageRule::new("Mimikatz", "Mimikatz credential dump tool");
        r.add_string("s0", b"mimikatz".as_slice());
        r.add_string("s1", b"sekurlsa".as_slice());
        r.condition_all = false;
        r.add_meta("severity", "critical");
        r.add_tag("credential-theft");
        add(r);

        // ---- Metasploit meterpreter -----------------------------------------
        let mut r = YaraTriageRule::new("Meterpreter", "Metasploit meterpreter payload");
        r.add_string("s0", b"meterpreter".as_slice());
        r.add_meta("severity", "critical");
        r.add_tag("rat");
        add(r);

        // ---- Network connectivity -------------------------------------------
        let mut r = YaraTriageRule::new("NetworkActivity", "Network-related API calls");
        r.add_string("s0", b"WSAStartup".as_slice());
        r.add_string("s1", b"connect".as_slice());
        r.condition_all = false;
        r.add_meta("severity", "medium");
        r.add_tag("network");
        add(r);

        // ---- Registry persistence -------------------------------------------
        let mut r = YaraTriageRule::new("RegistryPersistence", "Registry-based persistence");
        r.add_string("s0", b"RegSetValueEx".as_slice());
        r.add_string("s1", b"CurrentVersion\\Run".as_slice());
        r.condition_all = false;
        r.add_meta("severity", "high");
        r.add_tag("persistence");
        add(r);

        // ---- Crypto strings --------------------------------------------------
        let mut r = YaraTriageRule::new("CryptoStrings", "Cryptographic constants or API usage");
        r.add_string("aes", b"AES".as_slice());
        r.add_string("rsa", b"RSA".as_slice());
        r.condition_all = false;
        r.add_meta("severity", "low");
        r.add_tag("crypto");
        add(r);

        // ---- AntiDebug patterns ---------------------------------------------
        let mut r = YaraTriageRule::new("AntiDebug", "Anti-debugging techniques detected");
        r.add_string("s0", b"IsDebuggerPresent".as_slice());
        r.add_string("s1", b"CheckRemoteDebuggerPresent".as_slice());
        r.add_string("s2", b"NtQueryInformationProcess".as_slice());
        r.condition_all = false;
        r.add_meta("severity", "medium");
        r.add_tag("anti-analysis");
        add(r);

        // ---- Ransomware keywords --------------------------------------------
        let mut r = YaraTriageRule::new("RansomwareKeywords", "Ransomware-related strings");
        r.add_string("s0", b"bitcoin".as_slice());
        r.add_string("s1", b"decrypt".as_slice());
        r.add_string("s2", b"ransom".as_slice());
        r.condition_all = false;
        r.add_meta("severity", "critical");
        r.add_tag("ransomware");
        add(r);

        engine
    }
}

impl Default for YaraTriageEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for YaraTriageEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "YaraTriageEngine({} rules)", self.rules.len())
    }
}

// ---------------------------------------------------------------------------
// StringModifiers —" YARA-like string modifiers
// ---------------------------------------------------------------------------

/// Modifiers that control how a pattern is matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringModifiers {
    /// Case-insensitive matching.
    pub nocase: bool,
    /// Match UTF-16LE wide strings (null-interleaved).
    pub wide: bool,
    /// Match plain ASCII (default, always on unless only `wide` is set).
    pub ascii: bool,
    /// Whole-word matching (must be preceded/followed by non-alphanum).
    pub fullword: bool,
    /// XOR-decode the pattern before matching.
    pub xor: bool,
    /// XOR range (inclusive); `None` = 0x01—"0xFF.
    pub xor_range: Option<(u8, u8)>,
    /// The string is base64-encoded in the file.
    pub base64: bool,
}

impl Default for StringModifiers {
    fn default() -> Self {
        Self {
            nocase: false,
            wide: false,
            ascii: true,
            fullword: false,
            xor: false,
            xor_range: None,
            base64: false,
        }
    }
}

impl StringModifiers {
    /// Create plain ASCII modifiers.
    #[must_use]
    pub fn ascii() -> Self {
        Self::default()
    }

    /// Create wide (UTF-16LE) modifiers.
    #[must_use]
    pub fn wide() -> Self {
        Self {
            wide: true,
            ascii: false,
            ..Self::default()
        }
    }

    /// Create nocase modifiers.
    #[must_use]
    pub fn nocase() -> Self {
        Self {
            nocase: true,
            ..Self::default()
        }
    }

    /// Create fullword modifiers.
    #[must_use]
    pub fn fullword() -> Self {
        Self {
            fullword: true,
            ..Self::default()
        }
    }

    /// Create XOR modifiers covering the full 0x01—"0xFF range.
    #[must_use]
    pub fn xor_full() -> Self {
        Self {
            xor: true,
            xor_range: Some((0x01, 0xFF)),
            ..Self::default()
        }
    }

    /// The effective XOR range (1-based low, high).
    #[must_use]
    pub fn effective_xor_range(&self) -> (u8, u8) {
        self.xor_range.unwrap_or((0x01, 0xFF))
    }
}

// ---------------------------------------------------------------------------
// PatternKind
// ---------------------------------------------------------------------------

/// Specifies how a YARA-like pattern is expressed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternKind {
    /// Hex bytes with optional wildcards (`None` = wildcard).
    Hex(Vec<Option<u8>>),
    /// Literal UTF-8 text string.
    Text(String),
    /// Regular expression (applied to raw bytes).
    Regex(String),
}

impl PatternKind {
    /// Parse a hex pattern string like `"60 BE ?? 8D"`.
    ///
    /// # Errors
    /// Returns a string description if any token cannot be parsed.
    pub fn parse_hex(s: &str) -> Result<Self, String> {
        let mut bytes = Vec::new();
        for token in s.split_whitespace() {
            if token == "??" || token == "?" {
                bytes.push(None);
            } else {
                let v = u8::from_str_radix(token, 16)
                    .map_err(|_| format!("invalid hex token: '{token}'"))?;
                bytes.push(Some(v));
            }
        }
        Ok(Self::Hex(bytes))
    }
}

// ---------------------------------------------------------------------------
// NamedPattern
// ---------------------------------------------------------------------------

/// A named pattern used inside an [`EnhancedYaraRule`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedPattern {
    /// Identifier like `$s1`.
    pub id: String,
    /// The pattern itself.
    pub kind: PatternKind,
    /// Modifiers controlling matching behaviour.
    pub modifiers: StringModifiers,
}

impl NamedPattern {
    /// Create a plain ASCII text pattern.
    #[must_use]
    pub fn text(id: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: PatternKind::Text(text.into()),
            modifiers: StringModifiers::default(),
        }
    }

    /// Create a hex pattern.
    #[must_use]
    pub fn hex(id: impl Into<String>, bytes: Vec<Option<u8>>) -> Self {
        Self {
            id: id.into(),
            kind: PatternKind::Hex(bytes),
            modifiers: StringModifiers::default(),
        }
    }

    /// Create a regex pattern.
    #[must_use]
    pub fn regex(id: impl Into<String>, pattern: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: PatternKind::Regex(pattern.into()),
            modifiers: StringModifiers::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Ordering —" serializable replacement for std::cmp::Ordering
// ---------------------------------------------------------------------------

/// A serializable ordering comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrdOp {
    /// Less than.
    Less,
    /// Greater than.
    Greater,
    /// Equal to.
    Equal,
}

impl OrdOp {
    /// Compare `lhs` with `rhs` using this operator.
    #[must_use]
    pub const fn compare(&self, lhs: u64, rhs: u64) -> bool {
        match self {
            Self::Less => lhs < rhs,
            Self::Greater => lhs > rhs,
            Self::Equal => lhs == rhs,
        }
    }
}

// ---------------------------------------------------------------------------
// YaraCondition
// ---------------------------------------------------------------------------

/// A condition that can be evaluated against scan results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum YaraCondition {
    /// Always true.
    True,
    /// Always false.
    False,
    /// All string patterns must match at least once.
    All,
    /// Any string pattern matches.
    Any,
    /// No string patterns match.
    None,
    /// A specific named string must match (`$s1`).
    StringMatch(String),
    /// A named string must match at least `n` times (`#s1 > n`).
    StringCount(String, u32),
    /// A named string must match at a specific offset (`$s1 at 0x100`).
    StringAtOffset(String, u64),
    /// A named string must match within a byte range (`$s1 in (lo..hi)`).
    StringInRange(String, u64, u64),
    /// Logical NOT.
    Not(Box<YaraCondition>),
    /// Logical AND.
    And(Box<YaraCondition>, Box<YaraCondition>),
    /// Logical OR.
    Or(Box<YaraCondition>, Box<YaraCondition>),
    /// File-size comparison (`filesize > n`).
    FileSize(OrdOp, u64),
    /// Entry point equality (`entrypoint == addr`).
    EntryPoint(u64),
    /// At least `n` of the listed named strings must match.
    AtLeast(u32, Vec<String>),
    /// For exactly `n` strings satisfying a sub-condition.
    For(u32, Box<YaraCondition>),
}

impl YaraCondition {
    /// Evaluate this condition given:
    /// - `matches`: map of pattern-id â†' list of `(offset, matched_bytes)`.
    /// - `data_len`: total file length in bytes.
    /// - `ep_offset`: optional entry-point offset.
    #[must_use]
    pub fn evaluate(
        &self,
        matches: &HashMap<String, Vec<(u64, Vec<u8>)>>,
        data_len: u64,
        ep_offset: Option<u64>,
    ) -> bool {
        match self {
            Self::True => true,
            Self::False => false,
            Self::All => matches.values().all(|v| !v.is_empty()),
            Self::Any => matches.values().any(|v| !v.is_empty()),
            Self::None => matches.values().all(|v| v.is_empty()),

            Self::StringMatch(id) => matches.get(id).is_some_and(|v| !v.is_empty()),

            Self::StringCount(id, min_count) => {
                let count = u32::try_from(matches.get(id).map_or(0, Vec::len)).unwrap_or(u32::MAX);
                count >= *min_count
            }

            Self::StringAtOffset(id, target_offset) => matches.get(id).is_some_and(|hits| {
                hits.iter().any(|(off, _)| off == target_offset)
            }),

            Self::StringInRange(id, lo, hi) => matches.get(id).is_some_and(|hits| {
                hits.iter().any(|(off, _)| off >= lo && off <= hi)
            }),

            Self::Not(inner) => !inner.evaluate(matches, data_len, ep_offset),

            Self::And(left, right) => {
                left.evaluate(matches, data_len, ep_offset)
                    && right.evaluate(matches, data_len, ep_offset)
            }

            Self::Or(left, right) => {
                left.evaluate(matches, data_len, ep_offset)
                    || right.evaluate(matches, data_len, ep_offset)
            }

            Self::FileSize(op, threshold) => op.compare(data_len, *threshold),

            Self::EntryPoint(addr) => ep_offset.is_some_and(|ep| ep == *addr),

            Self::AtLeast(min_count, ids) => {
                let n_matched = u32::try_from(
                    ids.iter()
                        .filter(|id| matches.get(*id).is_some_and(|v| !v.is_empty()))
                        .count()
                ).unwrap_or(u32::MAX);
                n_matched >= *min_count
            }

            Self::For(n, inner) => {
                // Count how many named strings satisfy the inner condition when
                // evaluated individually.  We evaluate the inner cond in a
                // context where only one pattern at a time is populated.
                let count = u32::try_from(
                    matches
                        .iter()
                        .filter(|(id, hits)| {
                            if hits.is_empty() {
                                return false;
                            }
                            let single: HashMap<String, Vec<(u64, Vec<u8>)>> =
                                std::iter::once(((*id).clone(), (*hits).clone())).collect();
                            inner.evaluate(&single, data_len, ep_offset)
                        })
                        .count()
                ).unwrap_or(u32::MAX);
                count >= *n
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EnhancedYaraRule
// ---------------------------------------------------------------------------

/// An enhanced YARA rule with full condition support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedYaraRule {
    /// Unique rule name.
    pub name: String,
    /// Classification tags.
    pub tags: Vec<String>,
    /// Metadata keyâ†'value.
    pub meta: HashMap<String, String>,
    /// Named patterns.
    pub strings: Vec<NamedPattern>,
    /// The condition to evaluate.
    pub condition: YaraCondition,
}

impl EnhancedYaraRule {
    /// Create a minimal rule that fires when any string matches.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            tags: Vec::new(),
            meta: HashMap::new(),
            strings: Vec::new(),
            condition: YaraCondition::Any,
        }
    }

    /// Add a named pattern.
    pub fn add_pattern(&mut self, p: NamedPattern) {
        self.strings.push(p);
    }

    /// Add metadata.
    pub fn add_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.meta.insert(key.into(), value.into());
    }

    /// Add a tag.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }
}

impl fmt::Display for EnhancedYaraRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rule {} [{}] ({} strings)",
            self.name,
            self.tags.join(", "),
            self.strings.len()
        )
    }
}

// ---------------------------------------------------------------------------
// StringMatchDetail / EnhancedYaraMatch
// ---------------------------------------------------------------------------

/// Detail about a single string pattern that matched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringMatchDetail {
    /// The pattern identifier (e.g. `$s1`).
    pub pattern_id: String,
    /// All offsets at which the pattern matched.
    pub offsets: Vec<u64>,
    /// The actual bytes matched at each offset.
    pub matched_bytes: Vec<Vec<u8>>,
}

/// Result of an enhanced YARA scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedYaraMatch {
    /// Name of the matched rule.
    pub rule_name: String,
    /// Tags from the matched rule.
    pub tags: Vec<String>,
    /// Metadata from the matched rule.
    pub meta: HashMap<String, String>,
    /// Detailed string match information.
    pub string_matches: Vec<StringMatchDetail>,
}

// ---------------------------------------------------------------------------
// Pattern-matching helpers
// ---------------------------------------------------------------------------

/// Search `data` for all occurrences of a literal byte pattern, returning
/// `(offset, matched_bytes)` pairs.
fn find_literal(data: &[u8], needle: &[u8]) -> Vec<(u64, Vec<u8>)> {
    if needle.is_empty() {
        return Vec::new();
    }
    let mut results = Vec::new();
    let limit = data.len().saturating_sub(needle.len()) + 1;
    'outer: for i in 0..limit {
        for (j, &nb) in needle.iter().enumerate() {
            if data[i + j] != nb {
                continue 'outer;
            }
        }
        results.push((u64::try_from(i).unwrap_or(u64::MAX), data[i..i + needle.len()].to_vec()));
    }
    results
}

/// Find a hex pattern (with `None` wildcards) in `data`.
#[must_use]
pub fn find_hex_pattern(data: &[u8], pattern: &[Option<u8>]) -> Vec<(u64, Vec<u8>)> {
    if pattern.is_empty() {
        return Vec::new();
    }
    let plen = pattern.len();
    let mut results = Vec::new();
    let limit = data.len().saturating_sub(plen) + 1;
    'outer: for i in 0..limit {
        for (j, pb) in pattern.iter().enumerate() {
            if let Some(expected) = pb && data[i + j] != *expected {
                continue 'outer;
            }
        }
        results.push((u64::try_from(i).unwrap_or(u64::MAX), data[i..i + plen].to_vec()));
    }
    results
}

/// Find a text pattern in `data` with modifier support.
///
/// Supports:
/// - `nocase`: case-insensitive matching.
/// - `wide`: UTF-16LE encoding search.
/// - `fullword`: whole-word boundary enforcement.
/// - `xor`: try all XOR keys in the specified range.
#[must_use]
pub fn find_text_pattern(data: &[u8], text: &str, mods: &StringModifiers) -> Vec<(u64, Vec<u8>)> {
    let mut all_hits: Vec<(u64, Vec<u8>)> = Vec::new();

    if mods.xor {
        let (lo, hi) = mods.effective_xor_range();
        let needle = text.as_bytes();
        for key in lo..=hi {
            let xored: Vec<u8> = needle.iter().map(|&b| b ^ key).collect();
            let hits = if mods.nocase {
                find_nocase(data, &xored)
            } else {
                find_literal(data, &xored)
            };
            let filtered = if mods.fullword {
                hits.into_iter()
                    .filter(|(off, matched)| is_fullword(data, *off as usize, matched.len()))
                    .collect()
            } else {
                hits
            };
            all_hits.extend(filtered);
        }
        return all_hits;
    }

    if mods.ascii || (!mods.wide) {
        let hits = if mods.nocase {
            find_nocase(data, text.as_bytes())
        } else {
            find_literal(data, text.as_bytes())
        };
        let filtered: Vec<_> = if mods.fullword {
            hits.into_iter()
                .filter(|(off, matched)| is_fullword(data, *off as usize, matched.len()))
                .collect()
        } else {
            hits
        };
        all_hits.extend(filtered);
    }

    if mods.wide {
        let wide = to_wide(text);
        let hits = if mods.nocase {
            find_nocase_wide(data, text)
        } else {
            find_literal(data, &wide)
        };
        let filtered: Vec<_> = if mods.fullword {
            hits.into_iter()
                .filter(|(off, matched)| is_fullword_wide(data, *off as usize, matched.len()))
                .collect()
        } else {
            hits
        };
        all_hits.extend(filtered);
    }

    all_hits
}

/// Find a regex pattern in `data` (simple hand-rolled subset: `.`, `*`, `+`, `?`,
///
/// `^`, `$`, character classes `[...]`, alternation `|`).
/// For non-trivial regexes this uses a naive backtracking engine over bytes.
///
/// Returns `(offset, matched_bytes)` for every non-overlapping match.
#[must_use]
pub fn find_regex_pattern(data: &[u8], regex_str: &str) -> Vec<(u64, Vec<u8>)> {
    // We implement a small NFA-based engine that handles:
    // . (any byte), * (0+), + (1+), ? (0 or 1), [abc] / [^abc],
    // ^ (anchored to start), $ (anchored to end), | (alternation).
    let Ok(atoms) = compile_regex(regex_str) else {
        return Vec::new();
    };

    let anchored_start = regex_str.starts_with('^');
    let anchored_end = regex_str.ends_with('$') && !regex_str.ends_with("\\$");

    let mut results = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        if let Some(end) = nfa_match(&atoms, data, i) {
            if anchored_end && end != data.len() {
                i += 1;
                continue;
            }
            results.push((u64::try_from(i).unwrap_or(u64::MAX), data[i..end].to_vec()));
            // Advance past this match (avoid zero-length infinite loop)
            i = if end > i { end } else { i + 1 };
        } else {
            i += 1;
        }
        if anchored_start {
            break;
        }
    }
    results
}

// ---------------------------------------------------------------------------
// RuleEngine
// ---------------------------------------------------------------------------

/// The enhanced YARA rule engine.
#[derive(Clone)]
pub struct RuleEngine {
    rules: Vec<EnhancedYaraRule>,
}

impl RuleEngine {
    /// Create a new, empty engine.
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule to the engine.
    pub fn add_rule(&mut self, rule: EnhancedYaraRule) {
        self.rules.push(rule);
    }

    /// Scan `data` with no entry-point context.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<EnhancedYaraMatch> {
        self.scan_with_ep(data, None)
    }

    /// Scan `data` providing an optional entry-point offset.
    #[must_use]
    pub fn scan_with_ep(&self, data: &[u8], ep_offset: Option<u64>) -> Vec<EnhancedYaraMatch> {
        let data_len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let mut results = Vec::new();

        for rule in &self.rules {
            // Run all patterns and collect hits.
            let mut all_matches: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
            let mut detail_list: Vec<StringMatchDetail> = Vec::new();

            for np in &rule.strings {
                let hits = run_named_pattern(np, data);
                all_matches.insert(np.id.clone(), hits.clone());

                let offsets: Vec<u64> = hits.iter().map(|(off, _)| *off).collect();
                let matched_bytes: Vec<Vec<u8>> =
                    hits.into_iter().map(|(_, bytes)| bytes).collect();
                detail_list.push(StringMatchDetail {
                    pattern_id: np.id.clone(),
                    offsets,
                    matched_bytes,
                });
            }

            if rule.condition.evaluate(&all_matches, data_len, ep_offset) {
                results.push(EnhancedYaraMatch {
                    rule_name: rule.name.clone(),
                    tags: rule.tags.clone(),
                    meta: rule.meta.clone(),
                    string_matches: detail_list,
                });
            }
        }

        results
    }

    /// Return the number of loaded rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Load a set of pre-built malware-detection enhanced rules.
    #[must_use]
    pub fn load_builtin_rules() -> Self {
        let mut engine = Self::new();

        // â"€â"€ UPX â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut r = EnhancedYaraRule::new("UPX_Packer_Enhanced");
        r.add_pattern(NamedPattern::text("$s0", "UPX0"));
        r.add_pattern(NamedPattern::text("$s1", "UPX1"));
        r.condition = YaraCondition::Any;
        r.add_meta("author", "rustre");
        r.add_meta("severity", "medium");
        r.add_tag("packer");
        engine.add_rule(r);

        // â"€â"€ Mimikatz â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut r = EnhancedYaraRule::new("Mimikatz_Strings");
        r.add_pattern(NamedPattern::text("$mimi", "mimikatz"));
        r.add_pattern(NamedPattern::text("$sekur", "sekurlsa"));
        r.condition = YaraCondition::Any;
        r.add_meta("severity", "critical");
        r.add_tag("credential-theft");
        engine.add_rule(r);

        // â"€â"€ VMProtect â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut r = EnhancedYaraRule::new("VMProtect_Marker");
        r.add_pattern(NamedPattern::text("$s0", ".vmp0"));
        r.add_pattern(NamedPattern::text("$s1", ".vmp1"));
        r.condition = YaraCondition::Any;
        r.add_meta("severity", "high");
        r.add_tag("protector");
        engine.add_rule(r);

        // â"€â"€ Ransomware patterns â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut r = EnhancedYaraRule::new("Ransomware_IOC");
        r.add_pattern(NamedPattern::text("$btc", "bitcoin"));
        r.add_pattern(NamedPattern::text("$ext", ".locked"));
        r.add_pattern(NamedPattern::text("$key", "decrypt"));
        r.condition = YaraCondition::AtLeast(
            2,
            vec!["$btc".to_string(), "$ext".to_string(), "$key".to_string()],
        );
        r.add_meta("severity", "critical");
        r.add_tag("ransomware");
        engine.add_rule(r);

        // â"€â"€ Shellcode NtAllocateVirtualMemory â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut r = EnhancedYaraRule::new("Shellcode_Alloc");
        r.add_pattern(NamedPattern::hex(
            "$alloc",
            vec![Some(0x48), Some(0x83), Some(0xEC), None, Some(0xE8)],
        ));
        r.condition = YaraCondition::StringMatch("$alloc".to_string());
        r.add_meta("severity", "medium");
        r.add_tag("shellcode");
        engine.add_rule(r);

        // â"€â"€ AntiDebug â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut r = EnhancedYaraRule::new("AntiDebug_APIs");
        r.add_pattern(NamedPattern::text("$isdbg", "IsDebuggerPresent"));
        r.add_pattern(NamedPattern::text("$ntqip", "NtQueryInformationProcess"));
        r.add_pattern(NamedPattern::text("$crdbg", "CheckRemoteDebuggerPresent"));
        r.condition = YaraCondition::Any;
        r.add_meta("severity", "medium");
        r.add_tag("anti-analysis");
        engine.add_rule(r);

        // â"€â"€ Process injection â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut r = EnhancedYaraRule::new("Process_Injection");
        r.add_pattern(NamedPattern::text("$va", "VirtualAllocEx"));
        r.add_pattern(NamedPattern::text("$wpm", "WriteProcessMemory"));
        r.add_pattern(NamedPattern::text("$crt", "CreateRemoteThread"));
        r.condition = YaraCondition::AtLeast(
            2,
            vec!["$va".to_string(), "$wpm".to_string(), "$crt".to_string()],
        );
        r.add_meta("severity", "high");
        r.add_tag("injection");
        engine.add_rule(r);

        // â"€â"€ Network C2 â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut r = EnhancedYaraRule::new("NetworkC2");
        r.add_pattern(NamedPattern::text("$ws", "WSAStartup"));
        r.add_pattern(NamedPattern::text("$conn", "connect"));
        r.add_pattern(NamedPattern::text("$send", "send"));
        r.condition = YaraCondition::AtLeast(
            2,
            vec!["$ws".to_string(), "$conn".to_string(), "$send".to_string()],
        );
        r.add_meta("severity", "high");
        r.add_tag("network");
        r.add_tag("c2");
        engine.add_rule(r);

        // â"€â"€ MZ header â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut r = EnhancedYaraRule::new("PE_MZ_Header");
        r.add_pattern(NamedPattern::hex("$mz", vec![Some(0x4D), Some(0x5A)]));
        r.condition = YaraCondition::StringAtOffset("$mz".to_string(), 0);
        r.add_meta("severity", "info");
        r.add_tag("format");
        r.add_tag("pe");
        engine.add_rule(r);

        // â"€â"€ ELF magic â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut r = EnhancedYaraRule::new("ELF_Magic_Enhanced");
        r.add_pattern(NamedPattern::hex(
            "$elf",
            vec![Some(0x7F), Some(0x45), Some(0x4C), Some(0x46)],
        ));
        r.condition = YaraCondition::StringAtOffset("$elf".to_string(), 0);
        r.add_meta("severity", "info");
        r.add_tag("format");
        r.add_tag("elf");
        engine.add_rule(r);

        // â"€â"€ Large file (> 100MB suspicious) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut r = EnhancedYaraRule::new("LargeFile_Suspicious");
        r.condition = YaraCondition::FileSize(OrdOp::Greater, 100 * 1024 * 1024);
        r.add_meta("severity", "low");
        r.add_tag("anomaly");
        engine.add_rule(r);

        // â"€â"€ Crypto key material indicators â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut r = EnhancedYaraRule::new("Crypto_Key_Material");
        r.add_pattern(NamedPattern::text("$aes", "AES256"));
        r.add_pattern(NamedPattern::text("$rsa", "RSA-2048"));
        r.add_pattern(NamedPattern::hex(
            "$aes_sbox",
            vec![Some(0x63), Some(0x7c), Some(0x77), Some(0x7b), Some(0xf2)],
        ));
        r.condition = YaraCondition::Any;
        r.add_meta("severity", "low");
        r.add_tag("crypto");
        engine.add_rule(r);

        // â"€â"€ PowerShell download cradle â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut r = EnhancedYaraRule::new("PowerShell_Cradle");
        r.add_pattern(NamedPattern::text("$dl", "DownloadString"));
        r.add_pattern(NamedPattern::text("$iex", "IEX"));
        r.add_pattern(NamedPattern::text("$bypass", "Bypass"));
        r.condition = YaraCondition::AtLeast(
            2,
            vec!["$dl".to_string(), "$iex".to_string(), "$bypass".to_string()],
        );
        r.add_meta("severity", "high");
        r.add_tag("powershell");
        r.add_tag("downloader");
        engine.add_rule(r);

        // â"€â"€ Obfuscated base64 strings â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        let mut r = EnhancedYaraRule::new("Base64_Obfuscation");
        r.add_pattern(NamedPattern::text("$b64", "TVqQAAMAAAAEAAAA")); // MZ base64
        r.condition = YaraCondition::StringMatch("$b64".to_string());
        r.add_meta("severity", "medium");
        r.add_tag("obfuscation");
        engine.add_rule(r);

        engine
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RuleEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RuleEngine({} rules)", self.rules.len())
    }
}

// ---------------------------------------------------------------------------
// Internal: run a NamedPattern against data
// ---------------------------------------------------------------------------

fn run_named_pattern(np: &NamedPattern, data: &[u8]) -> Vec<(u64, Vec<u8>)> {
    match &np.kind {
        PatternKind::Hex(bytes) => find_hex_pattern(data, bytes),
        PatternKind::Text(text) => find_text_pattern(data, text, &np.modifiers),
        PatternKind::Regex(re) => find_regex_pattern(data, re),
    }
}

// ---------------------------------------------------------------------------
// Internal: text-matching helpers
// ---------------------------------------------------------------------------

fn to_wide(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for b in s.bytes() {
        out.push(b);
        out.push(0x00);
    }
    out
}

const fn is_word_boundary(b: u8) -> bool {
    !b.is_ascii_alphanumeric() && b != b'_'
}

fn is_fullword(data: &[u8], offset: usize, len: usize) -> bool {
    let before_ok = if offset == 0 {
        true
    } else {
        is_word_boundary(data[offset - 1])
    };
    let after_ok = if offset + len >= data.len() {
        true
    } else {
        is_word_boundary(data[offset + len])
    };
    before_ok && after_ok
}

fn is_fullword_wide(data: &[u8], offset: usize, len: usize) -> bool {
    // Wide chars are 2-byte sequences; check 2 bytes before and after
    let before_ok = if offset < 2 {
        true
    } else {
        is_word_boundary(data[offset - 2])
    };
    let after_ok = if offset + len + 1 >= data.len() {
        true
    } else {
        is_word_boundary(data[offset + len])
    };
    before_ok && after_ok
}

fn find_nocase(data: &[u8], needle: &[u8]) -> Vec<(u64, Vec<u8>)> {
    if needle.is_empty() {
        return Vec::new();
    }
    let needle_lower: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
    let limit = data.len().saturating_sub(needle.len()) + 1;
    let mut results = Vec::new();
    'outer: for i in 0..limit {
        for (j, &nb) in needle_lower.iter().enumerate() {
            if data[i + j].to_ascii_lowercase() != nb {
                continue 'outer;
            }
        }
        results.push((u64::try_from(i).unwrap_or(u64::MAX), data[i..i + needle.len()].to_vec()));
    }
    results
}

fn find_nocase_wide(data: &[u8], text: &str) -> Vec<(u64, Vec<u8>)> {
    // Build lowercase wide pattern and scan
    let wide_lower: Vec<u8> = {
        let mut out = Vec::new();
        for b in text.bytes() {
            out.push(b.to_ascii_lowercase());
            out.push(0x00);
        }
        out
    };
    let plen = wide_lower.len();
    let limit = data.len().saturating_sub(plen) + 1;
    let mut results = Vec::new();
    'outer: for i in 0..limit {
        for (j, &nb) in wide_lower.iter().enumerate() {
            let db = if j.is_multiple_of(2) {
                data[i + j].to_ascii_lowercase()
            } else {
                data[i + j]
            };
            if db != nb {
                continue 'outer;
            }
        }
        results.push((u64::try_from(i).unwrap_or(u64::MAX), data[i..i + plen].to_vec()));
    }
    results
}

// ---------------------------------------------------------------------------
// Minimal regex compiler / NFA matcher
// ---------------------------------------------------------------------------

/// A compiled regex atom for the mini NFA engine.
#[derive(Debug, Clone)]
enum RegexAtom {
    /// Match any single byte.
    Any,
    /// Match a literal byte.
    Literal(u8),
    /// Match a byte in (or not in) a character class.
    Class { chars: Vec<u8>, negated: bool },
    /// Zero-or-more repetition of an atom.
    Star(Box<RegexAtom>),
    /// One-or-more repetition.
    Plus(Box<RegexAtom>),
    /// Zero-or-one repetition.
    Optional(Box<RegexAtom>),
    /// Alternation: try left, then right.
    Alt(Vec<Vec<RegexAtom>>),
}

/// Compile a simple regex string into a list of atoms.
fn compile_regex(re: &str) -> Result<Vec<RegexAtom>, String> {
    // Strip anchors
    let s = re.trim_start_matches('^').trim_end_matches('$');
    parse_regex_atoms(s.as_bytes())
}

fn parse_regex_atoms(input: &[u8]) -> Result<Vec<RegexAtom>, String> {
    let mut atoms: Vec<RegexAtom> = Vec::new();
    let mut i = 0;

    while i < input.len() {
        let ch = input[i];
        if ch == b'|' {
            // Alternation: split here
            let left = atoms.clone();
            let right = parse_regex_atoms(&input[i + 1..])?;
            let alt = RegexAtom::Alt(vec![left, right]);
            return Ok(vec![alt]);
        }
        let atom = match ch {
            b'.' => {
                i += 1;
                RegexAtom::Any
            }
            b'[' => {
                // character class
                let mut j = i + 1;
                let negated = j < input.len() && input[j] == b'^';
                if negated {
                    j += 1;
                }
                let mut chars = Vec::new();
                while j < input.len() && input[j] != b']' {
                    if j + 2 < input.len() && input[j + 1] == b'-' && input[j + 2] != b']' {
                        let lo = input[j];
                        let hi = input[j + 2];
                        for c in lo..=hi {
                            chars.push(c);
                        }
                        j += 3;
                    } else {
                        chars.push(input[j]);
                        j += 1;
                    }
                }
                i = j + 1; // skip ']'
                RegexAtom::Class { chars, negated }
            }
            b'\\' if i + 1 < input.len() => {
                let next = input[i + 1];
                i += 2;
                match next {
                    b'd' => RegexAtom::Class {
                        chars: (b'0'..=b'9').collect(),
                        negated: false,
                    },
                    b'w' => {
                        let mut wchars: Vec<u8> = (b'a'..=b'z').collect();
                        wchars.extend(b'A'..=b'Z');
                        wchars.extend(b'0'..=b'9');
                        wchars.push(b'_');
                        RegexAtom::Class {
                            chars: wchars,
                            negated: false,
                        }
                    }
                    b's' => RegexAtom::Class {
                        chars: vec![b' ', b'\t', b'\n', b'\r', 0x0C, 0x0B],
                        negated: false,
                    },
                    _ => RegexAtom::Literal(next),
                }
            }
            _ => {
                i += 1;
                RegexAtom::Literal(ch)
            }
        };

        // Check for quantifiers
        let quantified = if i < input.len() {
            match input[i] {
                b'*' => {
                    i += 1;
                    RegexAtom::Star(Box::new(atom))
                }
                b'+' => {
                    i += 1;
                    RegexAtom::Plus(Box::new(atom))
                }
                b'?' => {
                    i += 1;
                    RegexAtom::Optional(Box::new(atom))
                }
                _ => atom,
            }
        } else {
            atom
        };

        atoms.push(quantified);
    }

    Ok(atoms)
}

/// Try to match the compiled atoms at position `start` in `data`.
/// Returns the end position (exclusive) if successful, else `None`.
fn nfa_match(atoms: &[RegexAtom], data: &[u8], start: usize) -> Option<usize> {
    nfa_match_atoms(atoms, 0, data, start)
}

fn atom_matches(atom: &RegexAtom, b: u8) -> bool {
    match atom {
        RegexAtom::Any => true,
        RegexAtom::Literal(v) => *v == b,
        RegexAtom::Class { chars, negated } => {
            let found = chars.contains(&b);
            if *negated { !found } else { found } } _ => false, } }  fn nfa_match_atoms(atoms: &[RegexAtom], atom_idx: usize, data: &[u8], pos: usize) -> Option<usize> { if atom_idx >= atoms.len() { return Some(pos); } let atom = &atoms[atom_idx]; match atom { RegexAtom::Alt(branches) => { for branch in branches { if let Some(end) = nfa_match_atoms(branch, 0, data, pos)
                && let Some(final_end) = nfa_match_atoms(atoms, atom_idx + 1, data, end)
            {
                // After matching this branch, continue with remaining atoms
                return Some(final_end);
            } }
            None
        }
        RegexAtom::Star(inner) => {
            // Greedy: match as many single-char repetitions as possible, then backtrack.
            // Use a single-atom NFA probe so nested quantifiers are handled correctly.
            let mut positions = vec![pos];
            let mut cur = pos;
            while cur < data.len() {
                let single = std::slice::from_ref(inner.as_ref());
                if nfa_match_atoms(single, 0, data, cur).is_some_and(|end| end == cur + 1) {
                    cur += 1;
                    positions.push(cur);
                } else {
                    break;
                }
            }
            for &try_pos in positions.iter().rev() {
                if let Some(end) = nfa_match_atoms(atoms, atom_idx + 1, data, try_pos) {
                    return Some(end);
                }
            }
            None
        }
        RegexAtom::Plus(inner) => {
            // Must match at least one occurrence before behaving like Star.
            let single = std::slice::from_ref(inner.as_ref());
            if pos >= data.len() || nfa_match_atoms(single, 0, data, pos).is_none_or(|end| end != pos + 1) {
                return None;
            }
            let mut cur = pos + 1;
            let mut positions = vec![cur];
            while cur < data.len() {
                if nfa_match_atoms(single, 0, data, cur).is_some_and(|end| end == cur + 1) {
                    cur += 1;
                    positions.push(cur);
                } else {
                    break;
                }
            }
            for &try_pos in positions.iter().rev() {
                if let Some(end) = nfa_match_atoms(atoms, atom_idx + 1, data, try_pos) {
                    return Some(end);
                }
            }
            None
        }
        RegexAtom::Optional(inner) => {
            // Try consuming one character via NFA probe, then try skipping.
            let single = std::slice::from_ref(inner.as_ref());
            if pos < data.len()
                && nfa_match_atoms(single, 0, data, pos).is_some_and(|end| end == pos + 1)
                && let Some(end) = nfa_match_atoms(atoms, atom_idx + 1, data, pos + 1)
            {
                return Some(end);
            }
            nfa_match_atoms(atoms, atom_idx + 1, data, pos)
        }
        RegexAtom::Any | RegexAtom::Literal(_) | RegexAtom::Class { .. } => {
            if pos >= data.len() {
                return None;
            }
            if atom_matches(atom, data[pos]) {
                nfa_match_atoms(atoms, atom_idx + 1, data, pos + 1)
            } else {
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// YaraFamilyMatch —" result type for YaraTriageDatabase
// ---------------------------------------------------------------------------

/// A match produced by the [`YaraTriageDatabase`] scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraFamilyMatch {
    /// Name of the matching malware family or threat category.
    pub family: String,
    /// Short description of what was detected.
    pub description: String,
    /// Severity tag: `"critical"`, `"high"`, `"medium"`, or `"low"`.
    pub severity: String,
    /// The pattern that triggered the match.
    pub matched_pattern: String,
    /// File offset of the first match of the triggering pattern.
    pub offset: u64,
}

impl fmt::Display for YaraFamilyMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} @ 0x{:x} —  {}",
            self.severity.to_uppercase(),
            self.family,
            self.offset,
            self.description
        )
    }
}

// ---------------------------------------------------------------------------
// YaraTriageDatabase —" built-in malware family pattern database
// ---------------------------------------------------------------------------

/// A built-in database of 15+ malware-family patterns.
///
/// Each entry is a simple byte/string check (no full YARA parsing needed).
/// Patterns are matched case-sensitively against the raw file bytes.
///
/// # Example
///
/// ```rust,ignore
/// let db = YaraTriageDatabase::new();
/// for m in db.scan(file_bytes) {
///     println!("{}", m);
/// }
/// ```
pub struct YaraTriageDatabase {
    // User-added entries appended at runtime
    custom: Vec<CustomFamilyEntry>,
}

/// A single built-in database entry (uses `'static` refs for zero-copy storage).
struct YaraFamilyEntry {
    family: &'static str,
    description: &'static str,
    severity: &'static str,
    /// OR-list of patterns: the first matching pattern produces the result.
    patterns: &'static [&'static [u8]],
}

/// A user-supplied custom database entry added via [`YaraTriageDatabase::add_custom`].
#[derive(Debug, Clone)]
pub struct CustomFamilyEntry {
    /// Malware family name.
    pub family: String,
    /// Short human-readable description.
    pub description: String,
    /// Severity tag (`"critical"`, `"high"`, `"medium"`, `"low"`, `"info"`).
    pub severity: String,
    /// OR-list of byte patterns; the first matching pattern fires the entry.
    pub patterns: Vec<Vec<u8>>,
}

/// All built-in entries.
static YARA_DB_ENTRIES: &[YaraFamilyEntry] = &[
    // â"€â"€ Credential theft â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    YaraFamilyEntry {
        family: "Mimikatz",
        description: "Mimikatz credential dump tool —  can extract Windows passwords",
        severity: "critical",
        patterns: &[b"sekurlsa", b"kerberos::list", b"mimikatz"],
    },
    // â"€â"€ Remote-access trojans / C2 â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    YaraFamilyEntry {
        family: "Cobalt Strike Beacon",
        description: "Cobalt Strike beacon or malleable C2 artifact",
        severity: "critical",
        patterns: &[
            b"beacon.dll",
            b"ReflectiveDll",
            b"MZ\x90\x00\x03\x00\x00\x00\x04",
        ],
    },
    YaraFamilyEntry {
        family: "Meterpreter",
        description: "Metasploit meterpreter payload",
        severity: "critical",
        patterns: &[b"metsrv.dll", b"stdapi_", b"meterpreter"],
    },
    YaraFamilyEntry {
        family: "Generic RAT",
        description: "Generic remote-access trojan strings detected",
        severity: "high",
        patterns: &[
            b"RemoteAdmin",
            b"keylogger",
            b"GetKeyState",
            b"SetWindowsHookEx",
        ],
    },
    // â"€â"€ Ransomware â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    YaraFamilyEntry {
        family: "WannaCry",
        description: "WannaCry ransomware artefacts —  tasksche.exe and .wnry extension",
        severity: "critical",
        patterns: &[b"tasksche.exe", b".wnry", b"WNcry@2ol7"],
    },
    YaraFamilyEntry {
        family: "Emotet",
        description: "Emotet banking trojan / dropper",
        severity: "critical",
        patterns: &[b"Emotet", b"heodo", b"geodo"],
    },
    YaraFamilyEntry {
        family: "Locky ransomware",
        description: "Locky ransomware extension and note strings",
        severity: "critical",
        patterns: &[b".locky", b"_HOWDO_text.html", b".zepto"],
    },
    YaraFamilyEntry {
        family: "Ryuk ransomware",
        description: "Ryuk ransomware note or marker strings",
        severity: "critical",
        patterns: &[b"RyukReadMe", b"UNIQUE_ID_DO_NOT_REMOVE", b"ryuk"],
    },
    // â"€â"€ Exploit / shellcode â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    YaraFamilyEntry {
        family: "Generic shellcode",
        description: "Possible shellcode: LoadLibraryA + GetProcAddress pattern",
        severity: "high",
        patterns: &[b"LoadLibraryA", b"GetProcAddress"],
    },
    // â"€â"€ Loaders / droppers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    YaraFamilyEntry {
        family: "PowerShell cradle",
        description: "PowerShell IEX/DownloadString download-and-execute cradle",
        severity: "high",
        patterns: &[b"IEX (New-Object", b"IEX(New-Object", b"DownloadString"],
    },
    YaraFamilyEntry {
        family: "Base64-embedded PE",
        description: "Base64-encoded MZ header —  in-memory loader / dropper",
        severity: "high",
        patterns: &[b"TVqQAAMAAAAEAAAA"],
    },
    // â"€â"€ Banking trojans â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    YaraFamilyEntry {
        family: "TrickBot",
        description: "TrickBot banking trojan module name or config marker",
        severity: "critical",
        patterns: &[b"trickbot", b"trick_steal", b"pwgrab"],
    },
    YaraFamilyEntry {
        family: "Dridex",
        description: "Dridex / Bugat banking trojan",
        severity: "critical",
        patterns: &[b"dridex", b"bugat"],
    },
    // â"€â"€ Rootkits / Bootkits â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    YaraFamilyEntry {
        family: "ZeroAccess rootkit",
        description: "ZeroAccess rootkit strings",
        severity: "critical",
        patterns: &[b"ZeroAccess", b"max++"],
    },
    // â"€â"€ Information stealers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    YaraFamilyEntry {
        family: "RedLine Stealer",
        description: "RedLine information stealer",
        severity: "critical",
        patterns: &[b"RedLine", b"redline_stealer"],
    },
    YaraFamilyEntry {
        family: "AgentTesla",
        description: "AgentTesla keylogger / stealer",
        severity: "critical",
        patterns: &[b"AgentTesla", b"agent_tesla"],
    },
];

impl YaraTriageDatabase {
    /// Create a database pre-loaded with all built-in family patterns.
    #[must_use]
    pub const fn new() -> Self {
        Self { custom: Vec::new() }
    }

    /// Total number of entries (built-in + custom).
    #[must_use]
    pub fn entry_count(&self) -> usize {
        YARA_DB_ENTRIES.len() + self.custom.len()
    }

    /// Add a custom entry to the database so callers can extend detection coverage.
    ///
    /// `patterns` is an OR-list of byte sequences; the first that matches fires
    /// the entry.  At least one non-empty pattern must be supplied.
    pub fn add_custom(
        &mut self,
        family: impl Into<String>,
        description: impl Into<String>,
        severity: impl Into<String>,
        patterns: Vec<Vec<u8>>,
    ) {
        self.custom.push(CustomFamilyEntry {
            family: family.into(),
            description: description.into(),
            severity: severity.into(),
            patterns,
        });
    }

    /// Scan `data` against every entry in the database and return all matches.
    ///
    /// Matches are returned in database order (built-in first, then custom).
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<YaraFamilyMatch> {
        let mut results: Vec<YaraFamilyMatch> = Vec::new();

        // Helper: scan one built-in (static) entry.
        let process_builtin = |entry: &YaraFamilyEntry, results: &mut Vec<YaraFamilyMatch>| {
            for &pattern in entry.patterns {
                if pattern.is_empty() {
                    continue;
                }
                if let Some(off) = data.windows(pattern.len()).position(|w| w == pattern) {
                    results.push(YaraFamilyMatch {
                        family: entry.family.to_string(),
                        description: entry.description.to_string(),
                        severity: entry.severity.to_string(),
                        matched_pattern: String::from_utf8_lossy(pattern).into_owned(),
                        offset: u64::try_from(off).unwrap_or(u64::MAX),
                    });
                    return;
                }
            }
        };

        // Helper: scan one custom (owned) entry.
        let process_custom = |entry: &CustomFamilyEntry, results: &mut Vec<YaraFamilyMatch>| {
            for pattern in &entry.patterns {
                if pattern.is_empty() {
                    continue;
                }
                if let Some(off) = data.windows(pattern.len()).position(|w| w == pattern.as_slice()) {
                    results.push(YaraFamilyMatch {
                        family: entry.family.clone(),
                        description: entry.description.clone(),
                        severity: entry.severity.clone(),
                        matched_pattern: String::from_utf8_lossy(pattern).into_owned(),
                        offset: u64::try_from(off).unwrap_or(u64::MAX),
                    });
                    return;
                }
            }
        };

        for entry in YARA_DB_ENTRIES {
            process_builtin(entry, &mut results);
        }
        for entry in &self.custom {
            process_custom(entry, &mut results);
        }

        results
    }
}

impl Default for YaraTriageDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for YaraTriageDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "YaraTriageDatabase({} entries)", self.entry_count())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // â"€â"€ Legacy scan_data â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_legacy_scan_hex_match() {
        let rule = YaraRule {
            name: "PE".to_string(),
            patterns: vec![Pattern::Hex(vec![0x4D, 0x5A])],
        };
        let data = b"MZ\x00\x00";
        let matches = scan_data(&[rule], data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 0);
    }

    #[test]
    fn test_legacy_scan_text_match() {
        let rule = YaraRule {
            name: "UPX".to_string(),
            patterns: vec![Pattern::Text("UPX!".to_string())],
        };
        let data = b"header UPX! footer";
        let matches = scan_data(&[rule], data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 7);
    }

    #[test]
    fn test_legacy_scan_no_match() {
        let rule = YaraRule {
            name: "X".to_string(),
            patterns: vec![Pattern::Hex(vec![0xDE, 0xAD])],
        };
        let data = b"AABBCCDD";
        let matches = scan_data(&[rule], data);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_legacy_scan_multiple_occurrences() {
        let rule = YaraRule {
            name: "R".to_string(),
            patterns: vec![Pattern::Hex(vec![0xFF])],
        };
        let data = b"\xFF\x00\xFF\x00\xFF";
        let matches = scan_data(&[rule], data);
        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn test_legacy_scan_original_test() {
        let rule = YaraRule {
            name: "SuspiciousPE".to_string(),
            patterns: vec![
                Pattern::Hex(vec![0x7f, b'E', b'L', b'F']),
                Pattern::Text("UPX!".to_string()),
            ],
        };
        let target_data = b"Some prefix bytes \x7fELF and some suffix with UPX! inside.";
        let matches = scan_data(&[rule], target_data);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].rule_name, "SuspiciousPE");
        assert_eq!(matches[0].offset, 18);
        assert_eq!(matches[1].offset, 44);
    }

    #[test]
    fn test_legacy_scan_empty_pattern_skipped() {
        let rule = YaraRule {
            name: "empty".to_string(),
            patterns: vec![Pattern::Hex(vec![])],
        };
        let matches = scan_data(&[rule], b"data");
        assert!(matches.is_empty());
    }

    // â"€â"€ YaraMatch display â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_yara_match_display() {
        let m = YaraMatch {
            rule_name: "TestRule".to_string(),
            pattern_index: 2,
            offset: 0x100,
        };
        let s = m.to_string();
        assert!(s.contains("TestRule"));
        assert!(s.contains("0x100"));
    }

    // â"€â"€ YaraError â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_yara_error_empty_pattern() {
        let e = YaraError::EmptyPattern("my_rule".into());
        assert!(e.to_string().contains("my_rule"));
    }

    #[test]
    fn test_yara_error_duplicate_rule() {
        let e = YaraError::DuplicateRule("dup_rule".into());
        assert!(e.to_string().contains("dup_rule"));
    }

    #[test]
    fn test_yara_error_other() {
        let e = YaraError::Other("something broke".into());
        assert!(e.to_string().contains("something broke"));
    }

    // â"€â"€ YaraTriageRule â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_triage_rule_new() {
        let r = YaraTriageRule::new("test", "A test rule");
        assert_eq!(r.name, "test");
        assert!(!r.condition_all);
        assert!(r.strings.is_empty());
        assert!(r.tags.is_empty());
    }

    #[test]
    fn test_triage_rule_add_string() {
        let mut r = YaraTriageRule::new("r", "desc");
        r.add_string("s0", b"MZ".as_slice());
        assert_eq!(r.strings.len(), 1);
    }

    #[test]
    fn test_triage_rule_add_meta() {
        let mut r = YaraTriageRule::new("r", "desc");
        r.add_meta("severity", "high");
        assert_eq!(r.metadata["severity"], "high");
    }

    #[test]
    fn test_triage_rule_add_tag() {
        let mut r = YaraTriageRule::new("r", "desc");
        r.add_tag("malware");
        assert_eq!(r.tags[0], "malware");
    }

    #[test]
    fn test_triage_rule_display() {
        let mut r = YaraTriageRule::new("my_rule", "desc");
        r.add_tag("tag1");
        let s = r.to_string();
        assert!(s.contains("my_rule"));
        assert!(s.contains("tag1"));
    }

    // â"€â"€ YaraTriageMatch â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_triage_match_display() {
        let m = YaraTriageMatch {
            rule_name: "TestRule".into(),
            matched_strings: vec![("s0".to_string(), 0x100)],
            description: "desc".into(),
            severity: "high".into(),
        };
        let s = m.to_string();
        assert!(s.contains("TestRule"));
        assert!(s.contains("high"));
    }

    // â"€â"€ YaraTriageEngine â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_engine_new_empty() {
        let e = YaraTriageEngine::new();
        assert_eq!(e.rule_count(), 0);
    }

    #[test]
    fn test_engine_add_rule() {
        let mut e = YaraTriageEngine::new();
        e.add_rule(YaraTriageRule::new("r1", "desc")).unwrap();
        assert_eq!(e.rule_count(), 1);
    }

    #[test]
    fn test_engine_duplicate_rule_error() {
        let mut e = YaraTriageEngine::new();
        e.add_rule(YaraTriageRule::new("dup", "desc")).unwrap();
        let err = e.add_rule(YaraTriageRule::new("dup", "desc2"));
        assert!(matches!(err, Err(YaraError::DuplicateRule(_))));
    }

    #[test]
    fn test_engine_scan_any_match() {
        let mut e = YaraTriageEngine::new();
        let mut r = YaraTriageRule::new("HasMZ", "Detects MZ magic");
        r.add_string("mz", b"MZ".as_slice());
        e.add_rule(r).unwrap();

        let data = b"MZExtraData";
        let hits = e.scan(data);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_name, "HasMZ");
    }

    #[test]
    fn test_engine_scan_all_condition_fail() {
        let mut e = YaraTriageEngine::new();
        let mut r = YaraTriageRule::new("Both", "Needs both strings");
        r.add_string("s0", b"AAA".as_slice());
        r.add_string("s1", b"BBB".as_slice());
        r.condition_all = true;
        e.add_rule(r).unwrap();

        // Only s0 present
        let hits = e.scan(b"AAAData");
        assert!(hits.is_empty());
    }

    #[test]
    fn test_engine_scan_all_condition_pass() {
        let mut e = YaraTriageEngine::new();
        let mut r = YaraTriageRule::new("Both", "Needs both");
        r.add_string("s0", b"AAA".as_slice());
        r.add_string("s1", b"BBB".as_slice());
        r.condition_all = true;
        e.add_rule(r).unwrap();

        let hits = e.scan(b"AAADataBBBMore");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_engine_scan_no_strings_always_fires() {
        let mut e = YaraTriageEngine::new();
        let r = YaraTriageRule::new("AlwaysFire", "No strings");
        e.add_rule(r).unwrap();
        let hits = e.scan(b"anydata");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_engine_scan_with_offset() {
        let mut e = YaraTriageEngine::new();
        let mut r = YaraTriageRule::new("R", "desc");
        r.add_string("s0", b"XX".as_slice());
        e.add_rule(r).unwrap();

        let data = b"  XX  ";
        let hits = e.scan_with_offset(data, 0x1000);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched_strings[0].1, 0x1002);
    }

    #[test]
    fn test_engine_load_default_rules() {
        let e = YaraTriageEngine::load_default_rules();
        assert!(e.rule_count() >= 10);
    }

    #[test]
    fn test_engine_default_rules_detect_upx() {
        let e = YaraTriageEngine::load_default_rules();
        let data = b"MZStuff UPX0 section";
        let hits = e.scan(data);
        assert!(hits.iter().any(|h| h.rule_name == "UPX_Packer"));
    }

    #[test]
    fn test_engine_default_rules_detect_mimikatz() {
        let e = YaraTriageEngine::load_default_rules();
        let data = b"sekurlsa::logonpasswords mimikatz output";
        let hits = e.scan(data);
        assert!(hits.iter().any(|h| h.rule_name == "Mimikatz"));
    }

    #[test]
    fn test_engine_default_rules_detect_antidebug() {
        let e = YaraTriageEngine::load_default_rules();
        let data = b"CallsIsDebuggerPresent to detect analysis";
        let hits = e.scan(data);
        assert!(hits.iter().any(|h| h.rule_name == "AntiDebug"));
    }

    #[test]
    fn test_engine_severity_in_match() {
        let mut e = YaraTriageEngine::new();
        let mut r = YaraTriageRule::new("SevRule", "desc");
        r.add_string("s0", b"token".as_slice());
        r.add_meta("severity", "critical");
        e.add_rule(r).unwrap();

        let hits = e.scan(b"some token here");
        assert_eq!(hits[0].severity, "critical");
    }

    #[test]
    fn test_engine_debug() {
        let e = YaraTriageEngine::new();
        assert!(format!("{e:?}").contains("YaraTriageEngine"));
    }

    #[test]
    fn test_engine_default() {
        let e = YaraTriageEngine::default();
        assert_eq!(e.rule_count(), 0);
    }

    #[test]
    fn test_engine_ransomware_keywords() {
        let e = YaraTriageEngine::load_default_rules();
        let data = b"Pay bitcoin to decrypt files ransom note";
        let hits = e.scan(data);
        assert!(hits.iter().any(|h| h.rule_name == "RansomwareKeywords"));
    }

    // â"€â"€ StringModifiers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_modifiers_default() {
        let m = StringModifiers::default();
        assert!(m.ascii);
        assert!(!m.nocase);
        assert!(!m.wide);
        assert!(!m.xor);
    }

    #[test]
    fn test_modifiers_nocase() {
        let m = StringModifiers::nocase();
        assert!(m.nocase);
        assert!(m.ascii);
    }

    #[test]
    fn test_modifiers_wide() {
        let m = StringModifiers::wide();
        assert!(m.wide);
        assert!(!m.ascii);
    }

    #[test]
    fn test_modifiers_xor_full_range() {
        let m = StringModifiers::xor_full();
        assert!(m.xor);
        assert_eq!(m.effective_xor_range(), (0x01, 0xFF));
    }

    #[test]
    fn test_modifiers_custom_xor_range() {
        let m = StringModifiers {
            xor: true,
            xor_range: Some((0x10, 0x20)),
            ..StringModifiers::default()
        };
        assert_eq!(m.effective_xor_range(), (0x10, 0x20));
    }

    // â"€â"€ PatternKind â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_pattern_kind_parse_hex_ok() {
        let p = PatternKind::parse_hex("60 BE ?? 8D").unwrap();
        assert_eq!(
            p,
            PatternKind::Hex(vec![Some(0x60), Some(0xBE), None, Some(0x8D)])
        );
    }

    #[test]
    fn test_pattern_kind_parse_hex_error() {
        let r = PatternKind::parse_hex("ZZ");
        assert!(r.is_err());
    }

    #[test]
    fn test_pattern_kind_text_variant() {
        let p = PatternKind::Text("hello".to_string());
        assert_eq!(p, PatternKind::Text("hello".to_string()));
    }

    #[test]
    fn test_pattern_kind_regex_variant() {
        let p = PatternKind::Regex("he.lo".to_string());
        assert_eq!(p, PatternKind::Regex("he.lo".to_string()));
    }

    // â"€â"€ NamedPattern â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_named_pattern_text() {
        let np = NamedPattern::text("$s1", "hello");
        assert_eq!(np.id, "$s1");
        assert_eq!(np.kind, PatternKind::Text("hello".to_string()));
    }

    #[test]
    fn test_named_pattern_hex() {
        let np = NamedPattern::hex("$h1", vec![Some(0x60), None]);
        assert_eq!(np.id, "$h1");
        assert_eq!(np.kind, PatternKind::Hex(vec![Some(0x60), None]));
    }

    #[test]
    fn test_named_pattern_regex() {
        let np = NamedPattern::regex("$r1", "he.lo");
        assert_eq!(np.id, "$r1");
        assert_eq!(np.kind, PatternKind::Regex("he.lo".to_string()));
    }

    // â"€â"€ find_hex_pattern â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_find_hex_exact() {
        let data = b"\x60\xBE\xAB\xCD";
        let pattern = vec![Some(0x60), Some(0xBE), Some(0xAB)];
        let hits = find_hex_pattern(data, &pattern);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 0);
    }

    #[test]
    fn test_find_hex_wildcard() {
        let data = b"\x60\xFF\xAB";
        let pattern = vec![Some(0x60), None, Some(0xAB)];
        let hits = find_hex_pattern(data, &pattern);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_find_hex_no_match() {
        let data = b"\x61\xBE\xAB";
        let pattern = vec![Some(0x60), Some(0xBE)];
        let hits = find_hex_pattern(data, &pattern);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_find_hex_empty_pattern() {
        let data = b"\x60\xBE";
        let hits = find_hex_pattern(data, &[]);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_find_hex_multiple_matches() {
        let data = b"\xAA\xBB\xAA\xBB\xAA\xBB";
        let pattern = vec![Some(0xAA), Some(0xBB)];
        let hits = find_hex_pattern(data, &pattern);
        assert_eq!(hits.len(), 3);
    }

    // â"€â"€ find_text_pattern â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_find_text_plain() {
        let data = b"hello world hello";
        let mods = StringModifiers::default();
        let hits = find_text_pattern(data, "hello", &mods);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_find_text_nocase() {
        let data = b"Hello HELLO hello";
        let mods = StringModifiers::nocase();
        let hits = find_text_pattern(data, "hello", &mods);
        assert_eq!(hits.len(), 3);
    }

    #[test]
    fn test_find_text_wide() {
        // "AB" in UTF-16LE: 41 00 42 00
        let data: Vec<u8> = vec![0x41, 0x00, 0x42, 0x00, 0xFF, 0xFF];
        let mods = StringModifiers::wide();
        let hits = find_text_pattern(&data, "AB", &mods);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_find_text_fullword_match() {
        let data = b"foo bar baz";
        let mods = StringModifiers::fullword();
        let hits = find_text_pattern(data, "bar", &mods);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_find_text_fullword_no_match() {
        let data = b"foobarfoo";
        let mods = StringModifiers::fullword();
        let hits = find_text_pattern(data, "bar", &mods);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_find_text_xor() {
        // XOR "AB" with key 0x10 = 0x51 0x52
        let data: Vec<u8> = vec![0x51, 0x52, 0x00];
        let mods = StringModifiers {
            xor: true,
            xor_range: Some((0x10, 0x10)),
            ..StringModifiers::default()
        };
        let hits = find_text_pattern(&data, "AB", &mods);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_find_text_no_match() {
        let data = b"some data without the needle";
        let mods = StringModifiers::default();
        let hits = find_text_pattern(data, "ZZZZ", &mods);
        assert!(hits.is_empty());
    }

    // â"€â"€ find_regex_pattern â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_find_regex_literal() {
        let data = b"hello world";
        let hits = find_regex_pattern(data, "world");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 6);
    }

    #[test]
    fn test_find_regex_dot() {
        let data = b"abc";
        let hits = find_regex_pattern(data, "a.c");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_find_regex_star() {
        let data = b"ac";
        let hits = find_regex_pattern(data, "ab*c");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_find_regex_plus_match() {
        let data = b"abbc";
        let hits = find_regex_pattern(data, "ab+c");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_find_regex_plus_no_match() {
        let data = b"ac";
        let hits = find_regex_pattern(data, "ab+c");
        assert!(hits.is_empty());
    }

    #[test]
    fn test_find_regex_optional() {
        let data = b"ac";
        let hits = find_regex_pattern(data, "ab?c");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_find_regex_char_class() {
        let data = b"cat bat";
        let hits = find_regex_pattern(data, "[cb]at");
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_find_regex_anchored_start() {
        let data = b"hello world";
        let hits = find_regex_pattern(data, "^hello");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 0);
    }

    #[test]
    fn test_find_regex_anchored_start_no_match() {
        let data = b"xhello";
        let hits = find_regex_pattern(data, "^hello");
        assert!(hits.is_empty());
    }

    #[test]
    fn test_find_regex_no_match() {
        let data = b"hello";
        let hits = find_regex_pattern(data, "xyz");
        assert!(hits.is_empty());
    }

    // â"€â"€ YaraCondition::evaluate â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_condition_true() {
        let m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        assert!(YaraCondition::True.evaluate(&m, 100, None));
    }

    #[test]
    fn test_condition_false() {
        let m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        assert!(!YaraCondition::False.evaluate(&m, 100, None));
    }

    #[test]
    fn test_condition_all_pass() {
        let mut m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        m.insert("$s1".to_string(), vec![(0, b"A".to_vec())]);
        m.insert("$s2".to_string(), vec![(1, b"B".to_vec())]);
        assert!(YaraCondition::All.evaluate(&m, 100, None));
    }

    #[test]
    fn test_condition_all_fail() {
        let mut m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        m.insert("$s1".to_string(), vec![(0, b"A".to_vec())]);
        m.insert("$s2".to_string(), vec![]);
        assert!(!YaraCondition::All.evaluate(&m, 100, None));
    }

    #[test]
    fn test_condition_any_pass() {
        let mut m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        m.insert("$s1".to_string(), vec![]);
        m.insert("$s2".to_string(), vec![(0, b"X".to_vec())]);
        assert!(YaraCondition::Any.evaluate(&m, 100, None));
    }

    #[test]
    fn test_condition_any_fail() {
        let mut m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        m.insert("$s1".to_string(), vec![]);
        assert!(!YaraCondition::Any.evaluate(&m, 100, None));
    }

    #[test]
    fn test_condition_none() {
        let mut m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        m.insert("$s1".to_string(), vec![]);
        assert!(YaraCondition::None.evaluate(&m, 100, None));
    }

    #[test]
    fn test_condition_string_match() {
        let mut m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        m.insert("$s1".to_string(), vec![(5, b"AB".to_vec())]);
        assert!(YaraCondition::StringMatch("$s1".to_string()).evaluate(&m, 100, None));
    }

    #[test]
    fn test_condition_string_count() {
        let mut m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        m.insert(
            "$s1".to_string(),
            vec![(0, b"A".to_vec()), (5, b"A".to_vec()), (10, b"A".to_vec())],
        );
        assert!(YaraCondition::StringCount("$s1".to_string(), 3).evaluate(&m, 100, None));
        assert!(!YaraCondition::StringCount("$s1".to_string(), 4).evaluate(&m, 100, None));
    }

    #[test]
    fn test_condition_string_at_offset() {
        let mut m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        m.insert("$s1".to_string(), vec![(0x100, b"MZ".to_vec())]);
        assert!(YaraCondition::StringAtOffset("$s1".to_string(), 0x100).evaluate(&m, 200, None));
        assert!(!YaraCondition::StringAtOffset("$s1".to_string(), 0x200).evaluate(&m, 200, None));
    }

    #[test]
    fn test_condition_string_in_range() {
        let mut m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        m.insert("$s1".to_string(), vec![(50, b"X".to_vec())]);
        assert!(YaraCondition::StringInRange("$s1".to_string(), 0, 100).evaluate(&m, 200, None));
        assert!(!YaraCondition::StringInRange("$s1".to_string(), 60, 100).evaluate(&m, 200, None));
    }

    #[test]
    fn test_condition_not() {
        let m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        let cond = YaraCondition::Not(Box::new(YaraCondition::False));
        assert!(cond.evaluate(&m, 100, None));
    }

    #[test]
    fn test_condition_and() {
        let m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        let cond = YaraCondition::And(Box::new(YaraCondition::True), Box::new(YaraCondition::True));
        assert!(cond.evaluate(&m, 100, None));
        let cond_fail = YaraCondition::And(
            Box::new(YaraCondition::True),
            Box::new(YaraCondition::False),
        );
        assert!(!cond_fail.evaluate(&m, 100, None));
    }

    #[test]
    fn test_condition_or() {
        let m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        let cond = YaraCondition::Or(
            Box::new(YaraCondition::False),
            Box::new(YaraCondition::True),
        );
        assert!(cond.evaluate(&m, 100, None));
    }

    #[test]
    fn test_condition_filesize_greater() {
        let m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        assert!(YaraCondition::FileSize(OrdOp::Greater, 50).evaluate(&m, 100, None));
        assert!(!YaraCondition::FileSize(OrdOp::Greater, 100).evaluate(&m, 100, None));
    }

    #[test]
    fn test_condition_filesize_equal() {
        let m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        assert!(YaraCondition::FileSize(OrdOp::Equal, 100).evaluate(&m, 100, None));
    }

    #[test]
    fn test_condition_filesize_less() {
        let m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        assert!(YaraCondition::FileSize(OrdOp::Less, 200).evaluate(&m, 100, None));
    }

    #[test]
    fn test_condition_entrypoint_match() {
        let m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        assert!(YaraCondition::EntryPoint(0x1000).evaluate(&m, 100, Some(0x1000)));
        assert!(!YaraCondition::EntryPoint(0x2000).evaluate(&m, 100, Some(0x1000)));
    }

    #[test]
    fn test_condition_atleast() {
        let mut m: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        m.insert("$s1".to_string(), vec![(0, b"A".to_vec())]);
        m.insert("$s2".to_string(), vec![(5, b"B".to_vec())]);
        m.insert("$s3".to_string(), vec![]);
        let ids = vec!["$s1".to_string(), "$s2".to_string(), "$s3".to_string()];
        assert!(YaraCondition::AtLeast(2, ids.clone()).evaluate(&m, 100, None));
        assert!(!YaraCondition::AtLeast(3, ids).evaluate(&m, 100, None));
    }

    // â"€â"€ EnhancedYaraRule â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_enhanced_rule_new() {
        let r = EnhancedYaraRule::new("MyRule");
        assert_eq!(r.name, "MyRule");
        assert!(r.strings.is_empty());
    }

    #[test]
    fn test_enhanced_rule_add_pattern() {
        let mut r = EnhancedYaraRule::new("R");
        r.add_pattern(NamedPattern::text("$s1", "test"));
        assert_eq!(r.strings.len(), 1);
    }

    #[test]
    fn test_enhanced_rule_display() {
        let mut r = EnhancedYaraRule::new("TestRule");
        r.add_tag("malware");
        let s = r.to_string();
        assert!(s.contains("TestRule"));
    }

    // â"€â"€ RuleEngine â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_rule_engine_new() {
        let e = RuleEngine::new();
        assert_eq!(e.rule_count(), 0);
    }

    #[test]
    fn test_rule_engine_add_rule() {
        let mut e = RuleEngine::new();
        e.add_rule(EnhancedYaraRule::new("r1"));
        assert_eq!(e.rule_count(), 1);
    }

    #[test]
    fn test_rule_engine_scan_text_match() {
        let mut e = RuleEngine::new();
        let mut r = EnhancedYaraRule::new("FindMZ");
        r.add_pattern(NamedPattern::text("$mz", "MZ"));
        r.condition = YaraCondition::StringMatch("$mz".to_string());
        e.add_rule(r);

        let data = b"MZSomeData";
        let hits = e.scan(data);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_name, "FindMZ");
    }

    #[test]
    fn test_rule_engine_scan_hex_wildcard() {
        let mut e = RuleEngine::new();
        let mut r = EnhancedYaraRule::new("UPXLike");
        r.add_pattern(NamedPattern::hex(
            "$upx",
            vec![
                Some(0x60),
                Some(0xBE),
                None,
                None,
                None,
                None,
                Some(0x8D),
                Some(0xBE),
            ],
        ));
        r.condition = YaraCondition::StringMatch("$upx".to_string());
        e.add_rule(r);

        let data = vec![0x60u8, 0xBE, 0x11, 0x22, 0x33, 0x44, 0x8D, 0xBE];
        let hits = e.scan(&data);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_rule_engine_scan_no_match() {
        let mut e = RuleEngine::new();
        let mut r = EnhancedYaraRule::new("NotFound");
        r.add_pattern(NamedPattern::text("$x", "ZZZZ"));
        r.condition = YaraCondition::StringMatch("$x".to_string());
        e.add_rule(r);

        let hits = e.scan(b"hello world");
        assert!(hits.is_empty());
    }

    #[test]
    fn test_rule_engine_scan_with_ep() {
        let mut e = RuleEngine::new();
        let mut r = EnhancedYaraRule::new("EPMatch");
        r.condition = YaraCondition::EntryPoint(0x1000);
        e.add_rule(r);

        let hits = e.scan_with_ep(b"data", Some(0x1000));
        assert_eq!(hits.len(), 1);

        let misses = e.scan_with_ep(b"data", Some(0x2000));
        assert!(misses.is_empty());
    }

    #[test]
    fn test_rule_engine_filesize_condition() {
        let mut e = RuleEngine::new();
        let mut r = EnhancedYaraRule::new("BigFile");
        r.condition = YaraCondition::FileSize(OrdOp::Greater, 4);
        e.add_rule(r);

        let hits = e.scan(b"hello world");
        assert_eq!(hits.len(), 1);

        let misses = e.scan(b"hi");
        assert!(misses.is_empty());
    }

    #[test]
    fn test_rule_engine_string_count_condition() {
        let mut e = RuleEngine::new();
        let mut r = EnhancedYaraRule::new("MultiMatch");
        r.add_pattern(NamedPattern::text("$a", "aa"));
        r.condition = YaraCondition::StringCount("$a".to_string(), 3);
        e.add_rule(r);

        let hits = e.scan(b"aa xx aa yy aa zz");
        assert_eq!(hits.len(), 1);

        let misses = e.scan(b"aa xx aa");
        assert!(misses.is_empty());
    }

    #[test]
    fn test_rule_engine_atleast_condition() {
        let mut e = RuleEngine::new();
        let mut r = EnhancedYaraRule::new("TwoOf");
        r.add_pattern(NamedPattern::text("$a", "aaa"));
        r.add_pattern(NamedPattern::text("$b", "bbb"));
        r.add_pattern(NamedPattern::text("$c", "ccc"));
        r.condition = YaraCondition::AtLeast(
            2,
            vec!["$a".to_string(), "$b".to_string(), "$c".to_string()],
        );
        e.add_rule(r);

        let hits = e.scan(b"aaa bbb nothing");
        assert_eq!(hits.len(), 1);

        let misses = e.scan(b"aaa nothing");
        assert!(misses.is_empty());
    }

    #[test]
    fn test_rule_engine_builtin_rules() {
        let e = RuleEngine::load_builtin_rules();
        assert!(e.rule_count() >= 10);
    }

    #[test]
    fn test_rule_engine_builtin_upx() {
        let e = RuleEngine::load_builtin_rules();
        let data = b"MZ header UPX0 section UPX1 section";
        let hits = e.scan(data);
        assert!(hits.iter().any(|h| h.rule_name == "UPX_Packer_Enhanced"));
    }

    #[test]
    fn test_rule_engine_builtin_mz_at_offset_zero() {
        let e = RuleEngine::load_builtin_rules();
        let mut data = vec![0x4D, 0x5A]; // MZ
        data.extend_from_slice(b"\x00\x00\x00");
        let hits = e.scan(&data);
        assert!(hits.iter().any(|h| h.rule_name == "PE_MZ_Header"));
    }

    #[test]
    fn test_rule_engine_builtin_elf_at_offset_zero() {
        let e = RuleEngine::load_builtin_rules();
        let data = b"\x7fELF\x02\x01\x01\x00";
        let hits = e.scan(data);
        assert!(hits.iter().any(|h| h.rule_name == "ELF_Magic_Enhanced"));
    }

    #[test]
    fn test_rule_engine_builtin_process_injection() {
        let e = RuleEngine::load_builtin_rules();
        let data = b"VirtualAllocEx WriteProcessMemory CreateRemoteThread";
        let hits = e.scan(data);
        assert!(hits.iter().any(|h| h.rule_name == "Process_Injection"));
    }

    #[test]
    fn test_rule_engine_builtin_mimikatz() {
        let e = RuleEngine::load_builtin_rules();
        let data = b"sekurlsa::logonpasswords mimikatz 2.x";
        let hits = e.scan(data);
        assert!(hits.iter().any(|h| h.rule_name == "Mimikatz_Strings"));
    }

    #[test]
    fn test_rule_engine_debug() {
        let e = RuleEngine::new();
        assert!(format!("{e:?}").contains("RuleEngine"));
    }

    #[test]
    fn test_rule_engine_default() {
        let e = RuleEngine::default();
        assert_eq!(e.rule_count(), 0);
    }

    #[test]
    fn test_string_match_detail_offsets() {
        let mut e = RuleEngine::new();
        let mut r = EnhancedYaraRule::new("Multi");
        r.add_pattern(NamedPattern::text("$x", "AA"));
        r.condition = YaraCondition::StringMatch("$x".to_string());
        e.add_rule(r);

        let hits = e.scan(b"AA xx AA yy AA");
        assert_eq!(hits.len(), 1);
        let detail = &hits[0].string_matches[0];
        assert_eq!(detail.pattern_id, "$x");
        assert_eq!(detail.offsets.len(), 3);
    }

    #[test]
    fn test_enhanced_match_meta_propagation() {
        let mut e = RuleEngine::new();
        let mut r = EnhancedYaraRule::new("MetaTest");
        r.add_meta("author", "test-author");
        r.condition = YaraCondition::True;
        e.add_rule(r);

        let hits = e.scan(b"anything");
        assert_eq!(hits[0].meta["author"], "test-author");
    }

    #[test]
    fn test_enhanced_match_tags_propagation() {
        let mut e = RuleEngine::new();
        let mut r = EnhancedYaraRule::new("TagTest");
        r.add_tag("malware");
        r.add_tag("trojan");
        r.condition = YaraCondition::True;
        e.add_rule(r);

        let hits = e.scan(b"anything");
        assert!(hits[0].tags.contains(&"malware".to_string()));
        assert!(hits[0].tags.contains(&"trojan".to_string()));
    }

    // â"€â"€ Regex escape sequences â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_regex_digit_class() {
        let data = b"abc123def";
        let hits = find_regex_pattern(data, r"\d+");
        assert!(!hits.is_empty());
    }

    #[test]
    fn test_regex_word_class() {
        let data = b"hello 123 world";
        let hits = find_regex_pattern(data, r"\w+");
        assert!(!hits.is_empty());
    }

    // â"€â"€ find_literal helper â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_find_literal_multiple() {
        let data = b"abcabcabc";
        let hits = find_literal(data, b"abc");
        assert_eq!(hits.len(), 3);
    }

    #[test]
    fn test_find_literal_empty_needle() {
        let hits = find_literal(b"data", b"");
        assert!(hits.is_empty());
    }

    // â"€â"€ to_wide helper â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_to_wide_converts_correctly() {
        let wide = to_wide("AB");
        assert_eq!(wide, vec![0x41, 0x00, 0x42, 0x00]);
    }

    // â"€â"€ is_word_boundary â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_word_boundary_space() {
        assert!(is_word_boundary(b' '));
    }

    #[test]
    fn test_word_boundary_alnum_not() {
        assert!(!is_word_boundary(b'a'));
        assert!(!is_word_boundary(b'Z'));
        assert!(!is_word_boundary(b'5'));
    }
}

