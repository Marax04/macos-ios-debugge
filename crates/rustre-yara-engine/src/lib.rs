//! `rustre-yara-engine`
//!
//! Pure-Rust YARA-compatible rule matching engine (no FFI to libyara needed).

pub mod condition_evaluator;
pub mod distributed_scan;
pub mod match_context;
pub mod module_pe;
pub mod performance_profiler;
pub mod rule_compiler;
pub mod scan_engine;
pub mod string_matcher;
pub mod string_modifier_engine;
pub mod yara_vm;
pub mod rule_parser_ext;
pub mod string_match_engine;
pub mod condition_expr_eval;

use std::collections::HashMap;
use std::fmt;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Module-private cast helpers — isolate lossy numeric conversions used for
// statistics/heuristics where precision loss is acceptable.
#[inline]
fn usize_to_f64(v: usize) -> f64 {
    let lo = f64::from(u32::try_from(v & 0xFFFF_FFFF).unwrap_or(u32::MAX));
    let hi = f64::from(u32::try_from(v >> 32).unwrap_or(u32::MAX));
    hi.mul_add(4_294_967_296.0, lo)
}
#[inline]
fn u64_to_f64(v: u64) -> f64 {
    let lo = f64::from(u32::try_from(v & 0xFFFF_FFFF).unwrap_or(u32::MAX));
    let hi = f64::from(u32::try_from(v >> 32).unwrap_or(u32::MAX));
    hi.mul_add(4_294_967_296.0, lo)
}

// â"€â"€ Error â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Error)]
pub enum YaraError {
    #[error("parse error at line {line}: {message}")]
    ParseError { line: usize, message: String },
    #[error("compile error: {0}")]
    CompileError(String),
    #[error("rule not found: {0}")]
    RuleNotFound(String),
    #[error("scan error: {0}")]
    ScanError(String),
    #[error("regex error: {0}")]
    RegexError(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// â"€â"€ String types â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A YARA string definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraString {
    /// The identifier, e.g. `$a`.
    pub identifier: String,
    /// The string value/pattern.
    pub value: StringValue,
    /// Modifier flags.
    pub modifiers: StringModifiers,
}

impl fmt::Display for YaraString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {}", self.identifier, self.value)
    }
}

/// The value of a YARA string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StringValue {
    /// Plain text pattern.
    Text(String),
    /// Hex pattern with optional wildcards.
    Hex(Vec<HexToken>),
    /// Regular expression pattern.
    Regex(String),
}

impl fmt::Display for StringValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(s) => write!(f, "\"{s}\""),
            Self::Hex(tokens) => {
                write!(f, "{{ ")?;
                for t in tokens {
                    write!(f, "{t} ")?;
                }
                write!(f, "}}")
            }
            Self::Regex(r) => write!(f, "/{r}/"),
        }
    }
}

/// A single token in a hex pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HexToken {
    /// Exact byte value.
    Byte(u8),
    /// Wildcard `??`.
    Wildcard,
    /// Masked byte `AB & mask`.
    MaskedByte(u8, u8),
    /// Jump `[n]` or `[min-max]`.
    Jump(u32, Option<u32>),
    /// Alternatives `(AA | BB)`.
    Alternative(Vec<Vec<Self>>),
}

impl fmt::Display for HexToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Byte(b) => write!(f, "{b:02X}"),
            Self::Wildcard => write!(f, "??"),
            Self::MaskedByte(b, m) => write!(f, "{b:02X}&{m:02X}"),
            Self::Jump(min, max) => {
                if let Some(max) = max {
                    write!(f, "[{min}-{max}]")
                } else {
                    write!(f, "[{min}]")
                }
            }
            Self::Alternative(_) => write!(f, "(...)"),
        }
    }
}

bitflags::bitflags! {
    /// Modifier flags for a YARA string.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct StringModifiers: u16 {
        /// No modifiers.
        const NONE     = 0;
        /// Case-insensitive matching.
        const NOCASE   = 0x0001;
        /// Match wide (UTF-16LE) strings.
        const WIDE     = 0x0002;
        /// Match ASCII strings.
        const ASCII    = 0x0004;
        /// Full-word matching.
        const FULLWORD = 0x0008;
        /// Private string (not reported).
        const PRIVATE  = 0x0010;
        /// Base64-encoded strings.
        const BASE64   = 0x0020;
    }
}

// â"€â"€ Conditions â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A YARA rule condition expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    /// Always true.
    True,
    /// Always false.
    False,
    /// All strings must match.
    All,
    /// Any string must match.
    Any,
    /// No string must match.
    None,
    /// A specific string must match: `$identifier`.
    StringMatch(String),
    /// Match count of a string: `#identifier`.
    StringCount(String),
    /// String at a specific offset: `$a at 0`.
    StringAt(String, u64),
    /// String within a range: `$a in (0..100)`.
    StringIn(String, u64, u64),
    /// File-size comparison: `filesize > 100`.
    FileSize(CompOp, u64),
    /// Entry point condition.
    EntryPoint,
    /// Logical AND of two conditions.
    And(Box<Self>, Box<Self>),
    /// Logical OR of two conditions.
    Or(Box<Self>, Box<Self>),
    /// Logical NOT of a condition.
    Not(Box<Self>),
    /// Universal quantifier over all strings.
    ForAll(Box<Self>),
    /// Integer at a specific offset.
    IntAt(u64),
}

/// Comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompOp {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Less than.
    Lt,
    /// Less than or equal.
    Le,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Ge,
}

impl fmt::Display for CompOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eq => write!(f, "=="),
            Self::Ne => write!(f, "!="),
            Self::Lt => write!(f, "<"),
            Self::Le => write!(f, "<="),
            Self::Gt => write!(f, ">"),
            Self::Ge => write!(f, ">="),
        }
    }
}

// â"€â"€ Rule â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A compiled YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    /// Rule name.
    pub name: String,
    /// Rule namespace.
    pub namespace: String,
    /// Tags associated with the rule.
    pub tags: Vec<String>,
    /// Meta key-value pairs.
    pub meta: HashMap<String, MetaValue>,
    /// String definitions.
    pub strings: Vec<YaraString>,
    /// The condition expression.
    pub condition: Condition,
}

impl YaraRule {
    /// Create a new rule with the given name.
    #[must_use]
    pub fn new(name: String) -> Self {
        Self {
            name,
            namespace: "default".to_string(),
            tags: vec![],
            meta: HashMap::new(),
            strings: vec![],
            condition: Condition::True,
        }
    }

    /// Add a tag to this rule.
    #[must_use]
    pub fn with_tag(mut self, tag: String) -> Self {
        self.tags.push(tag);
        self
    }

    /// Add a meta entry to this rule.
    #[must_use]
    pub fn with_meta(mut self, key: String, value: MetaValue) -> Self {
        self.meta.insert(key, value);
        self
    }

    /// Add a string definition to this rule.
    #[must_use]
    pub fn with_string(mut self, s: YaraString) -> Self {
        self.strings.push(s);
        self
    }

    /// Set the condition for this rule.
    #[must_use]
    pub fn with_condition(mut self, condition: Condition) -> Self {
        self.condition = condition;
        self
    }
}

impl fmt::Display for YaraRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rule {} {{ strings: {} condition: ... }}",
            self.name,
            self.strings.len()
        )
    }
}

/// A metadata value in a YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetaValue {
    /// String metadata.
    String(String),
    /// Integer metadata.
    Int(i64),
    /// Boolean metadata.
    Bool(bool),
}

impl fmt::Display for MetaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => write!(f, "\"{s}\""),
            Self::Int(i) => write!(f, "{i}"),
            Self::Bool(b) => write!(f, "{b}"),
        }
    }
}

// â"€â"€ Match results â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A string match location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringMatch {
    /// The string identifier that matched.
    pub identifier: String,
    /// The byte offset in the data where the match starts.
    pub offset: u64,
    /// The length of the matched data.
    pub length: usize,
    /// The raw bytes that matched.
    pub matched_data: Vec<u8>,
}

impl fmt::Display for StringMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at {:#x} len={}",
            self.identifier, self.offset, self.length
        )
    }
}

/// A rule match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    /// The name of the rule that matched.
    pub rule_name: String,
    /// The namespace of the rule.
    pub namespace: String,
    /// Tags from the matched rule.
    pub tags: Vec<String>,
    /// Meta from the matched rule.
    pub meta: HashMap<String, MetaValue>,
    /// All string matches from this rule.
    pub string_matches: Vec<StringMatch>,
}

impl fmt::Display for RuleMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MATCH rule={} strings={}",
            self.rule_name,
            self.string_matches.len()
        )
    }
}

// â"€â"€ Scanner â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// YARA scanner —" applies rules to data.
pub struct YaraScanner {
    rules: RwLock<Vec<YaraRule>>,
}

impl YaraScanner {
    /// Create a new, empty scanner.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rules: RwLock::new(vec![]),
        }
    }

    /// Add a rule to this scanner.
    pub fn add_rule(&self, rule: YaraRule) {
        self.rules.write().push(rule);
    }

    /// Return the number of loaded rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.read().len()
    }

    /// Scan data against all loaded rules.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<RuleMatch> {
        let rules: Vec<YaraRule> = self.rules.read().clone();
        let mut results = Vec::new();
        for rule in &rules {
            // Find all string matches for this rule.
            let mut all_matches: HashMap<String, Vec<StringMatch>> = HashMap::new();
            for ys in &rule.strings {
                let matches = match &ys.value {
                    StringValue::Text(pat) => {
                        Self::find_text_matches(pat, ys.modifiers, data, &ys.identifier)
                    }
                    StringValue::Hex(tokens) => Self::find_hex_matches(tokens, data, &ys.identifier),
                    StringValue::Regex(pat) => Self::find_regex_matches(pat, data, &ys.identifier),
                };
                all_matches.insert(ys.identifier.clone(), matches);
            }
            if Self::evaluate_condition(&rule.condition, data, &all_matches) {
                let string_matches: Vec<StringMatch> =
                    all_matches.into_values().flatten().collect();
                results.push(RuleMatch {
                    rule_name: rule.name.clone(),
                    namespace: rule.namespace.clone(),
                    tags: rule.tags.clone(),
                    meta: rule.meta.clone(),
                    string_matches,
                });
            }
        }
        results
    }

    /// Scan and return only rule names that matched.
    #[must_use]
    pub fn scan_names(&self, data: &[u8]) -> Vec<String> {
        self.scan(data).into_iter().map(|m| m.rule_name).collect()
    }

    /// Find all text matches in `data`, honouring `NOCASE` and `WIDE`.
    fn find_text_matches(
        pattern: &str,
        modifiers: StringModifiers,
        data: &[u8],
        identifier: &str,
    ) -> Vec<StringMatch> {
        let mut results = Vec::new();

        if modifiers.contains(StringModifiers::WIDE) {
            // Encode the pattern as UTF-16LE for wide matching.
            let wide: Vec<u8> = pattern.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let wide_matches = if modifiers.contains(StringModifiers::NOCASE) {
                // For NOCASE wide, compare byte-level case-insensitively on the ASCII bytes.
                find_all_nocase(&wide, data)
            } else {
                find_all_bytes(&wide, data)
            };
            for offset in wide_matches {
                if modifiers.contains(StringModifiers::FULLWORD)
                    && !is_fullword(data, offset, wide.len(), true)
                {
                    continue;
                }
                results.push(StringMatch {
                    identifier: identifier.to_string(),
                    offset: offset as u64,
                    length: wide.len(),
                    matched_data: data[offset..offset + wide.len()].to_vec(),
                });
            }
        }

        // ASCII matching (default, or explicit ASCII modifier).
        let do_ascii = modifiers.contains(StringModifiers::ASCII)
            || !modifiers.contains(StringModifiers::WIDE);

        if do_ascii {
            let pat_bytes = pattern.as_bytes();
            let offsets = if modifiers.contains(StringModifiers::NOCASE) {
                find_all_nocase(pat_bytes, data)
            } else {
                find_all_bytes(pat_bytes, data)
            };
            for offset in offsets {
                if modifiers.contains(StringModifiers::FULLWORD)
                    && !is_fullword(data, offset, pat_bytes.len(), false)
                {
                    continue;
                }
                results.push(StringMatch {
                    identifier: identifier.to_string(),
                    offset: offset as u64,
                    length: pat_bytes.len(),
                    matched_data: data[offset..offset + pat_bytes.len()].to_vec(),
                });
            }
        }

        results
    }

    /// Find all hex pattern matches in `data`.
    fn find_hex_matches(
        tokens: &[HexToken],
        data: &[u8],
        identifier: &str,
    ) -> Vec<StringMatch> {
        let mut results = Vec::new();
        for start in 0..data.len() {
            if let Some(end) = match_hex_tokens(tokens, data, start) {
                results.push(StringMatch {
                    identifier: identifier.to_string(),
                    offset: start as u64,
                    length: end - start,
                    matched_data: data[start..end].to_vec(),
                });
            }
        }
        results
    }

    /// Find matches using the `regex` crate against the byte slice.
    fn find_regex_matches(pattern: &str, data: &[u8], identifier: &str) -> Vec<StringMatch> {
        // Build a byte-level regex from the pattern.
        let Ok(re) = regex::bytes::Regex::new(pattern) else { return vec![]; };
        let mut results = Vec::new();
        for m in re.find_iter(data) {
            results.push(StringMatch {
                identifier: identifier.to_string(),
                offset: m.start() as u64,
                length: m.len(),
                matched_data: m.as_bytes().to_vec(),
            });
        }
        results
    }

    /// Recursively evaluate a condition.
    fn evaluate_condition(
        condition: &Condition,
        data: &[u8],
        matches: &HashMap<String, Vec<StringMatch>>,
    ) -> bool {
        match condition {
            Condition::True => true,
            Condition::False => false,
            Condition::All => matches.values().all(|v| !v.is_empty()),
            Condition::Any => matches.values().any(|v| !v.is_empty()),
            Condition::None => matches.values().all(std::vec::Vec::is_empty),
            Condition::StringMatch(id) => matches.get(id).is_some_and(|v| !v.is_empty()),
            Condition::StringCount(id) => {
                let bare = id.trim_start_matches('#');
                matches.get(bare).map_or(0, Vec::len) > 0
            }
            Condition::StringAt(id, offset) => matches
                .get(id)
                .is_some_and(|v| v.iter().any(|m| m.offset == *offset)),
            Condition::StringIn(id, lo, hi) => matches
                .get(id)
                .is_some_and(|v| v.iter().any(|m| m.offset >= *lo && m.offset <= *hi)),
            Condition::FileSize(op, size) => {
                let fs = data.len() as u64;
                match op {
                    CompOp::Eq => fs == *size,
                    CompOp::Ne => fs != *size,
                    CompOp::Lt => fs < *size,
                    CompOp::Le => fs <= *size,
                    CompOp::Gt => fs > *size,
                    CompOp::Ge => fs >= *size,
                }
            }
            Condition::EntryPoint => {
                // Check for a simple PE/ELF magic at offset 0 (stub).
                data.len() >= 2 && (data[0] == 0x4D && data[1] == 0x5A)
            }
            Condition::And(a, b) => {
                Self::evaluate_condition(a, data, matches)
                    && Self::evaluate_condition(b, data, matches)
            }
            Condition::Or(a, b) => {
                Self::evaluate_condition(a, data, matches)
                    || Self::evaluate_condition(b, data, matches)
            }
            Condition::Not(inner) => !Self::evaluate_condition(inner, data, matches),
            Condition::ForAll(inner) => {
                // Universal quantifier: the inner condition must hold when evaluated
                // against every individual string in the rule's string set.
                // Build a singleton match map for each string and AND the results.
                if matches.is_empty() {
                    // No strings defined — vacuously true (YARA semantics).
                    return true;
                }
                for (id, string_matches) in matches {
                    let mut single: HashMap<String, Vec<StringMatch>> = HashMap::new();
                    single.insert(id.clone(), string_matches.clone());
                    if !Self::evaluate_condition(inner, data, &single) {
                        return false;
                    }
                }
                true
            }
            Condition::IntAt(offset) => {
                let off = usize::try_from(*offset).unwrap_or(usize::MAX);
                off.checked_add(4).is_some_and(|end| end <= data.len())
            }
        }
    }
}

impl Default for YaraScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for YaraScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "YaraScanner({} rules)", self.rules.read().len())
    }
}

// â"€â"€ Helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Find all starting offsets of `needle` in `haystack` (exact match).
fn find_all_bytes(needle: &[u8], haystack: &[u8]) -> Vec<usize> {
    if needle.is_empty() {
        return vec![];
    }
    let mut results = Vec::new();
    let mut start = 0;
    while start + needle.len() <= haystack.len() {
        if haystack[start..start + needle.len()] == *needle {
            results.push(start);
        }
        start += 1;
    }
    results
}

/// Find all starting offsets of `needle` in `haystack` (case-insensitive ASCII).
fn find_all_nocase(needle: &[u8], haystack: &[u8]) -> Vec<usize> {
    if needle.is_empty() {
        return vec![];
    }
    let needle_lower: Vec<u8> = needle.iter().map(u8::to_ascii_lowercase).collect();
    let mut results = Vec::new();
    for start in 0..haystack.len().saturating_sub(needle.len() - 1) {
        let slice: Vec<u8> = haystack[start..start + needle.len()]
            .iter()
            .map(u8::to_ascii_lowercase)
            .collect();
        if slice == needle_lower {
            results.push(start);
        }
    }
    results
}

/// Check if a match at `offset` with `len` is a full word (preceded/followed by non-alnum).
fn is_fullword(data: &[u8], offset: usize, len: usize, wide: bool) -> bool {
    let before_ok = if offset == 0 {
        true
    } else if wide {
        // For UTF-16LE, the byte immediately before the match (at offset - 1) is the
        // high byte of the preceding UTF-16 code unit. For ASCII-range characters that
        // byte is 0x00, meaning the low byte (at offset - 2) is the actual character.
        // We check the high byte first: if it is non-zero the preceding code unit is
        // outside the ASCII range and cannot be a word character.
        let high_prev = data[offset - 1];
        if high_prev != 0x00 {
            true // non-ASCII code unit before — not a word char
        } else if offset >= 2 {
            let low_prev = data[offset - 2];
            !low_prev.is_ascii_alphanumeric() && low_prev != b'_'
        } else {
            true
        }
    } else {
        let prev = data[offset - 1];
        !prev.is_ascii_alphanumeric() && prev != b'_'
    };
    let after = offset + len;
    let after_ok = if after >= data.len() {
        true
    } else {
        let next = data[after];
        !next.is_ascii_alphanumeric() && next != b'_'
    };
    before_ok && after_ok
}

/// Attempt to match `tokens` starting at `pos` in `data`.
/// Returns `Some(end)` if matched (end is exclusive), or `None`.
fn match_hex_tokens(tokens: &[HexToken], data: &[u8], pos: usize) -> Option<usize> {
    match_hex_tokens_at(tokens, 0, data, pos)
}

/// Inner recursive helper that carries the current token index explicitly,
/// avoiding fragile pointer-identity comparisons.
fn match_hex_tokens_at(tokens: &[HexToken], idx: usize, data: &[u8], cursor: usize) -> Option<usize> {
    if idx >= tokens.len() {
        return Some(cursor);
    }
    if cursor > data.len() {
        return None;
    }
    match &tokens[idx] {
        HexToken::Byte(b) => {
            if cursor >= data.len() || data[cursor] != *b {
                return None;
            }
            match_hex_tokens_at(tokens, idx + 1, data, cursor + 1)
        }
        HexToken::Wildcard => {
            if cursor >= data.len() {
                return None;
            }
            match_hex_tokens_at(tokens, idx + 1, data, cursor + 1)
        }
        HexToken::MaskedByte(b, m) => {
            if cursor >= data.len() || (data[cursor] & m) != (b & m) {
                return None;
            }
            match_hex_tokens_at(tokens, idx + 1, data, cursor + 1)
        }
        HexToken::Jump(min, max) => {
            let min = *min as usize;
            let max = max.map_or(min, |v| v as usize);
            // Use ascending order to find the leftmost (smallest) successful match,
            // consistent with YARA's leftmost-match semantics.
            for jump in min..=max {
                if cursor + jump > data.len() {
                    break;
                }
                if let Some(end) = match_hex_tokens_at(tokens, idx + 1, data, cursor + jump) {
                    return Some(end);
                }
            }
            None
        }
        HexToken::Alternative(alts) => {
            for alt in alts {
                // Try this alternative followed by the rest of the token stream.
                if let Some(mid) = match_hex_tokens_at(alt, 0, data, cursor)
                    && let Some(end) = match_hex_tokens_at(tokens, idx + 1, data, mid) {
                        return Some(end);
                    }
            }
            None
        }
    }
}

// â"€â"€ Parser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Simple YARA rule text parser (subset of YARA syntax).
pub struct YaraParser;

impl YaraParser {
    /// Create a new parser.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse a single rule from text.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError`] if syntax is invalid.
    pub fn parse_rule(&self, text: &str) -> Result<YaraRule, YaraError> {
        let text = text.trim();
        let after_rule = text
            .strip_prefix("rule ")
            .ok_or_else(|| YaraError::ParseError { line: 1, message: "expected 'rule'".to_string() })?;

        let name_end = after_rule
            .find(|c: char| c.is_whitespace() || c == '{')
            .ok_or_else(|| YaraError::ParseError { line: 1, message: "expected rule name".to_string() })?;
        let name = after_rule[..name_end].trim().to_string();
        if name.is_empty() {
            return Err(YaraError::ParseError { line: 1, message: "empty rule name".to_string() });
        }

        let rest_of_header = &after_rule[name_end..];
        let (tags, body_start) = Self::parse_rule_header(rest_of_header)?;
        let body_str = &rest_of_header[body_start + 1..];
        let close_brace = body_str.rfind('}').ok_or_else(|| YaraError::ParseError {
            line: 1, message: "expected '}' to close rule body".to_string(),
        })?;
        let body = &body_str[..close_brace];

        let mut rule = YaraRule::new(name);
        rule.tags = tags;
        Self::apply_meta_section(body, &mut rule);
        Self::apply_strings_section(body, &mut rule);
        if let Some(cond_start) = body.find("condition:") {
            let cond_body = &body[cond_start + 10..].trim();
            rule.condition = parse_condition_text(cond_body);
        }
        Ok(rule)
    }

    fn parse_rule_header(rest: &str) -> Result<(Vec<String>, usize), YaraError> {
        let mut tags = Vec::new();
        let body_start = if let Some(colon_pos) = rest.find(':') {
            let brace_pos = rest.find('{').ok_or_else(|| YaraError::ParseError {
                line: 1, message: "expected '{' after rule header".to_string(),
            })?;
            if colon_pos < brace_pos {
                for tag in rest[colon_pos + 1..brace_pos].split_whitespace() {
                    tags.push(tag.to_string());
                }
            }
            brace_pos
        } else {
            rest.find('{').ok_or_else(|| YaraError::ParseError {
                line: 1, message: "expected '{' to begin rule body".to_string(),
            })?
        };
        Ok((tags, body_start))
    }

    fn apply_meta_section(body: &str, rule: &mut YaraRule) {
        let Some(meta_start) = body.find("meta:") else { return; };
        let meta_body_start = meta_start + 5;
        let meta_end = body[meta_body_start..]
            .find("strings:")
            .or_else(|| body[meta_body_start..].find("condition:"))
            .map_or(body.len(), |p| meta_body_start + p);
        for line in body[meta_body_start..meta_end].lines() {
            let line = line.trim();
            if line.is_empty() { continue; }
            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim().to_string();
                let val_raw = line[eq_pos + 1..].trim();
                let meta_val = if val_raw.starts_with('"') && val_raw.ends_with('"') {
                    MetaValue::String(val_raw[1..val_raw.len() - 1].to_string())
                } else if val_raw == "true" {
                    MetaValue::Bool(true)
                } else if val_raw == "false" {
                    MetaValue::Bool(false)
                } else if let Ok(n) = val_raw.parse::<i64>() {
                    MetaValue::Int(n)
                } else {
                    MetaValue::String(val_raw.to_string())
                };
                rule.meta.insert(key, meta_val);
            }
        }
    }

    fn apply_strings_section(body: &str, rule: &mut YaraRule) {
        let Some(strings_start) = body.find("strings:") else { return; };
        let strings_body_start = strings_start + 8;
        let strings_end = body[strings_body_start..]
            .find("condition:")
            .map_or(body.len(), |p| strings_body_start + p);
        for line in body[strings_body_start..strings_end].lines() {
            let line = line.trim();
            if line.is_empty() || !line.starts_with('$') { continue; }
            if let Some(eq_pos) = line.find('=') {
                let identifier = line[..eq_pos].trim().to_string();
                let val_raw = line[eq_pos + 1..].trim();
                let (value, modifiers) = parse_string_value(val_raw);
                rule.strings.push(YaraString { identifier, value, modifiers });
            }
        }
    }

    /// Parse multiple rules from text.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError`] if any rule is invalid.
    pub fn parse_rules(&self, text: &str) -> Result<Vec<YaraRule>, YaraError> {
        let mut rules = Vec::new();
        // Split on `rule ` keyword boundaries.
        let mut remaining = text;
        while let Some(rule_pos) = remaining.find("rule ") {
            remaining = &remaining[rule_pos..];
            // Find the matching closing brace.
            let mut depth = 0i32;
            let mut end = 0;
            for (i, ch) in remaining.char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if end == 0 {
                return Err(YaraError::ParseError {
                    line: 0,
                    message: "unmatched braces".to_string(),
                });
            }
            let rule_text = &remaining[..end];
            rules.push(self.parse_rule(rule_text)?);
            remaining = &remaining[end..];
        }
        Ok(rules)
    }
}

impl Default for YaraParser {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for YaraParser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "YaraParser")
    }
}

// â"€â"€ Parser helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

fn parse_string_value(raw: &str) -> (StringValue, StringModifiers) {
    let mut modifiers = StringModifiers::NONE;
    if let Some(stripped) = raw.strip_prefix('"') {
        // Text string.
        let close = stripped.find('"').unwrap_or(stripped.len());
        let text = stripped[..close].to_string();
        let after = stripped.get(close + 1..).unwrap_or("");
        for word in after.split_whitespace() {
            match word {
                "nocase" => modifiers |= StringModifiers::NOCASE,
                "wide" => modifiers |= StringModifiers::WIDE,
                "ascii" => modifiers |= StringModifiers::ASCII,
                "fullword" => modifiers |= StringModifiers::FULLWORD,
                _ => {}
            }
        }
        (StringValue::Text(text), modifiers)
    } else if raw.starts_with('{') {
        // Hex pattern.
        let close = raw.find('}').unwrap_or(raw.len() - 1);
        let hex_content = &raw[1..close];
        let tokens = parse_hex_tokens(hex_content);
        (StringValue::Hex(tokens), modifiers)
    } else if let Some(stripped) = raw.strip_prefix('/') {
        // Regex: `stripped` is `raw` without the leading `/`.
        // Find the closing `/` within `stripped`; the pattern is everything before it.
        let close = stripped.rfind('/').unwrap_or(stripped.len());
        let pattern = stripped[..close].to_string();
        (StringValue::Regex(pattern), modifiers)
    } else {
        (StringValue::Text(raw.to_string()), modifiers)
    }
}

fn parse_hex_tokens(content: &str) -> Vec<HexToken> {
    let mut tokens = Vec::new();
    let mut chars = content.split_whitespace();
    for tok in chars.by_ref() {
        if tok == "??" {
            tokens.push(HexToken::Wildcard);
        } else if tok.len() == 2
            && let Ok(b) = u8::from_str_radix(tok, 16)
        {
            tokens.push(HexToken::Byte(b));
        }
    }
    tokens
}

fn parse_condition_text(text: &str) -> Condition {
    let text = text.trim();
    match text {
        "true" => Condition::True,
        "false" => Condition::False,
        "any of them" => Condition::Any,
        "all of them" => Condition::All,
        "none of them" => Condition::None,
        s if s.starts_with("filesize") => parse_filesize_condition(s).unwrap_or(Condition::True),
        s if s.starts_with('$') => Condition::StringMatch(s.to_string()),
        s if s.contains(" or ") => {
            let parts: Vec<&str> = s.rsplitn(2, " or ").collect();
            Condition::Or(
                Box::new(parse_condition_text(parts[1])),
                Box::new(parse_condition_text(parts[0])),
            )
        }
        s if s.contains(" and ") => {
            let parts: Vec<&str> = s.rsplitn(2, " and ").collect();
            Condition::And(
                Box::new(parse_condition_text(parts[1])),
                Box::new(parse_condition_text(parts[0])),
            )
        }
        s if s.starts_with("not ") => Condition::Not(Box::new(parse_condition_text(&s[4..]))),
        _ => Condition::True,
    }
}

fn parse_filesize_condition(text: &str) -> Option<Condition> {
    let text = text.trim();
    let ops = [
        (">=", CompOp::Ge),
        ("<=", CompOp::Le),
        ("!=", CompOp::Ne),
        (">", CompOp::Gt),
        ("<", CompOp::Lt),
        ("==", CompOp::Eq),
    ];
    for (sym, op) in &ops {
        if let Some(rest) = text.strip_prefix("filesize") {
            let rest = rest.trim();
            if let Some(val_str) = rest.strip_prefix(sym)
                && let Ok(n) = val_str.trim().parse::<u64>()
            {
                return Some(Condition::FileSize(*op, n));
            }
        }
    }
    None
}

// â"€â"€ yara-x engine â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
//
// Â§22 —" Complete YARA scanning engine wrapping yara-x.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// â"€â"€ YaraRuleDefinition â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A YARA rule definition with source text and metadata.
///
/// This is separate from [`YaraRule`] (the pure-Rust parsed form).
/// `YaraRuleDefinition` is specifically used by the `yara-x`—"backed engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleDefinition {
    /// Unique identifier (user-chosen, not necessarily the YARA rule name).
    pub id: String,
    /// Rule name extracted from the YARA source.
    pub name: String,
    /// Namespace the rule will be compiled into.
    pub namespace: String,
    /// Optional tags (not parsed from source; set programmatically).
    pub tags: Vec<String>,
    /// Optional metadata key/value pairs (not parsed from source; set programmatically).
    pub meta: HashMap<String, String>,
    /// Raw YARA source text.
    pub source: String,
}

impl YaraRuleDefinition {
    /// Create a new rule definition from a source string.
    /// The `name` field is populated by [`YaraRuleDefinition::parse_name_from_source`].
    #[must_use]
    pub fn new(id: impl Into<String>, source: impl Into<String>) -> Self {
        let id = id.into();
        let source = source.into();
        let name = Self::parse_name_from_source(&source).unwrap_or_else(|| id.clone());
        Self {
            id,
            name,
            namespace: "default".to_string(),
            tags: vec![],
            meta: HashMap::new(),
            source,
        }
    }

    /// Extract the rule name from a YARA source string.
    ///
    /// Looks for the pattern `rule <NAME>` and returns `<NAME>`.
    #[must_use]
    pub fn parse_name_from_source(src: &str) -> Option<String> {
        for line in src.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("rule ") {
                // Take everything up to the first whitespace, '{', or ':'
                let name: String = rest
                    .chars()
                    .take_while(|&c| !c.is_whitespace() && c != '{' && c != ':')
                    .collect();
                if !name.is_empty() {
                    return Some(name);
                }
            }
        }
        None
    }

    /// Set the namespace for this rule definition.
    #[must_use]
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = ns.into();
        self
    }

    /// Add a tag to this rule definition.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Add a meta entry to this rule definition.
    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.meta.insert(key.into(), value.into());
        self
    }
}

impl fmt::Display for YaraRuleDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "YaraRuleDefinition(id={}, name={})", self.id, self.name)
    }
}

// â"€â"€ YaraRuleSet â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A mutable collection of YARA rule definitions that can be compiled.
///
/// Rules are stored as source text and compiled on demand via [`YaraRuleSet::compile`].
pub struct YaraRuleSet {
    /// All rule definitions added to this set.
    pub rules: Vec<YaraRuleDefinition>,
    /// Compiled yara-x rules (populated by [`YaraRuleSet::compile`]).
    pub compiled: Option<yara_x::Rules>,
}

impl fmt::Debug for YaraRuleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "YaraRuleSet(rules={}, compiled={})",
            self.rules.len(),
            self.compiled.is_some()
        )
    }
}

impl YaraRuleSet {
    /// Create an empty rule set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rules: Vec::new(),
            compiled: None,
        }
    }

    /// Add a single YARA rule from its source text.
    ///
    /// The rule is appended with an auto-generated ID of the form `rule_<N>`.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError`] if the source is empty.
    pub fn add_rule(&mut self, source: &str) -> Result<(), YaraError> {
        if source.trim().is_empty() {
            return Err(YaraError::ParseError {
                line: 0,
                message: "empty rule source".to_string(),
            });
        }
        let id = format!("rule_{}", self.rules.len());
        self.rules.push(YaraRuleDefinition::new(id, source));
        // Invalidate any previously compiled output.
        self.compiled = None;
        Ok(())
    }

    /// Load all YARA rules from a file.
    ///
    /// Returns the number of rules parsed from the file.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError`] if the file cannot be read or contains no rules.
    pub fn add_file(&mut self, path: &Path) -> Result<u32, YaraError> {
        let source = std::fs::read_to_string(path)?;
        let parser = YaraParser::new();
        // Use the text parser to count how many `rule` blocks exist.
        let parsed = parser.parse_rules(&source)?;
        let count = u32::try_from(parsed.len()).unwrap_or(u32::MAX);
        // Add the entire file as a single source block; yara-x handles multi-rule sources.
        if !source.trim().is_empty() {
            let id = format!(
                "file_{}",
                path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
            );
            self.rules.push(YaraRuleDefinition::new(id, source));
            self.compiled = None;
        }
        Ok(count)
    }

    /// Recursively load all `.yar` and `.yara` files from a directory.
    ///
    /// Returns the total number of rules loaded across all files.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError`] if the directory cannot be walked.
    pub fn add_directory(&mut self, dir: &Path) -> Result<u32, YaraError> {
        let mut total = 0u32;
        self.walk_dir_for_rules(dir, &mut total)?;
        Ok(total)
    }

    fn walk_dir_for_rules(&mut self, dir: &Path, total: &mut u32) -> Result<(), YaraError> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                self.walk_dir_for_rules(&path, total)?;
            } else if let Some(ext) = path.extension().and_then(|e| e.to_str())
                && (ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara"))
            {
                *total += self.add_file(&path)?;
            }
        }
        Ok(())
    }

    /// Compile all loaded rules using yara-x.
    ///
    /// After this call, [`YaraRuleSet::compiled`] contains the compiled rules
    /// and a [`YaraScanner`] can be constructed.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError`] if compilation fails.
    pub fn compile(&mut self) -> Result<(), YaraError> {
        let mut compiler = yara_x::Compiler::new();
        for rule_def in &self.rules {
            compiler
                .add_source(rule_def.source.as_str())
                .map_err(|e| YaraError::CompileError(e.to_string()))?;
        }
        let rules = compiler.build();
        self.compiled = Some(rules);
        Ok(())
    }

    /// Return the number of rule definitions in this set.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.rules.len()
    }

    /// Return `true` if no rule definitions have been added.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Return `true` if the rule set has been compiled.
    #[must_use]
    pub const fn is_compiled(&self) -> bool {
        self.compiled.is_some()
    }
}

impl Default for YaraRuleSet {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€ PatternMatch / YaraMatch â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single pattern (string) match within a YARA rule match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    /// The pattern identifier, e.g. `$a`.
    pub identifier: String,
    /// Byte offset in the scanned data where the match begins.
    pub offset: u64,
    /// Length of the matched bytes.
    pub length: u32,
    /// Raw bytes that were matched (up to 64 bytes, truncated for large matches).
    pub data: Vec<u8>,
}

impl fmt::Display for PatternMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ {:#010x} len={}",
            self.identifier, self.offset, self.length
        )
    }
}

/// A yara-x rule match, returned by [`YaraEngineScanner`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    /// Name of the rule that matched.
    pub rule_name: String,
    /// Namespace of the matched rule.
    pub namespace: String,
    /// Tags declared on the matched rule.
    pub tags: Vec<String>,
    /// Metadata key/value pairs from the matched rule.
    pub meta: HashMap<String, String>,
    /// All pattern matches within this rule match.
    pub patterns: Vec<PatternMatch>,
}

impl fmt::Display for YaraMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "YaraMatch(rule={}, ns={}, patterns={})",
            self.rule_name,
            self.namespace,
            self.patterns.len()
        )
    }
}

// â"€â"€ YaraEngineScanner â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A yara-x—"backed YARA scanner.
///
/// Constructed from a compiled [`YaraRuleSet`] via [`YaraEngineScanner::new`].
///
/// Holds the compiled rules behind an [`Arc`] so it can be cheaply cloned and
/// shared across threads.
pub struct YaraEngineScanner {
    rules: Arc<yara_x::Rules>,
}

impl fmt::Debug for YaraEngineScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "YaraEngineScanner")
    }
}

impl YaraEngineScanner {
    /// Create a new scanner from a (possibly uncompiled) [`YaraRuleSet`].
    ///
    /// If the rule set is not yet compiled this method compiles it first.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError`] if compilation fails.
    pub fn new(ruleset: &mut YaraRuleSet) -> Result<Self, YaraError> {
        if ruleset.compiled.is_none() {
            ruleset.compile()?;
        }
        let rules = ruleset.compiled.take().ok_or_else(|| {
            YaraError::CompileError("compiled rules missing after compile()".into())
        })?;
        Ok(Self {
            rules: Arc::new(rules),
        })
    }

    /// Scan a byte slice and return all matching rules.
    #[must_use]
    pub fn scan_bytes(&self, data: &[u8]) -> Vec<YaraMatch> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        scanner
            .scan(data)
            .map_or_else(|_| vec![], |r| Self::convert_results(&r))
    }

    /// Scan a file on disk and return all matching rules.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError`] if the file cannot be read.
    pub fn scan_file(&self, path: &Path) -> Result<Vec<YaraMatch>, YaraError> {
        let data = std::fs::read(path)?;
        Ok(self.scan_bytes(&data))
    }

    /// Walk a directory and scan every file, returning a map of path â†' matches.
    ///
    /// Files that cannot be read are silently skipped.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError`] if the directory cannot be read.
    pub fn scan_directory(
        &self,
        dir: &Path,
    ) -> Result<HashMap<PathBuf, Vec<YaraMatch>>, YaraError> {
        let mut results: HashMap<PathBuf, Vec<YaraMatch>> = HashMap::new();
        self.walk_scan(dir, &mut results)?;
        Ok(results)
    }

    fn walk_scan(
        &self,
        dir: &Path,
        out: &mut HashMap<PathBuf, Vec<YaraMatch>>,
    ) -> Result<(), YaraError> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                self.walk_scan(&path, out)?;
            } else {
                const MAX_SCAN_FILE_SIZE: u64 = 64 * 1024 * 1024;
                let too_large = entry
                    .metadata()
                    .map_or(true, |m| m.len() > MAX_SCAN_FILE_SIZE);
                if too_large {
                    continue;
                }
                if let Ok(data) = std::fs::read(&path) {
                    let matches = self.scan_bytes(&data);
                    if !matches.is_empty() {
                        out.insert(path, matches);
                    }
                }
            }
        }
        Ok(())
    }

    /// Scan a running process by PID.
    ///
    /// # Errors
    ///
    /// Always returns an error stub because process scanning requires elevated
    /// OS privileges and platform-specific implementation.
    pub fn scan_process(&self, _pid: u32) -> Result<Vec<YaraMatch>, YaraError> {
        Err(YaraError::ScanError(
            "process scanning requires elevated privileges and is not yet implemented".to_string(),
        ))
    }

    /// Return a clone of the inner `Arc<yara_x::Rules>` for sharing.
    #[must_use]
    pub fn rules_arc(&self) -> Arc<yara_x::Rules> {
        Arc::clone(&self.rules)
    }

    // â"€â"€ internal helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn convert_results(results: &yara_x::ScanResults<'_, '_>) -> Vec<YaraMatch> {
        let mut out = Vec::new();
        for rule in results.matching_rules() {
            let mut patterns = Vec::new();
            for pattern in rule.patterns() {
                for m in pattern.matches() {
                    let range = m.range();
                    let offset = range.start as u64;
                    let length = u32::try_from(range.end - range.start).unwrap_or(u32::MAX);
                    let data = m.data().iter().take(64).copied().collect();
                    patterns.push(PatternMatch {
                        identifier: pattern.identifier().to_string(),
                        offset,
                        length,
                        data,
                    });
                }
            }

            // Collect metadata as String/String pairs.
            let mut meta: HashMap<String, String> = HashMap::new();
            for (key, value) in rule.metadata() {
                let val_str = match value {
                    yara_x::MetaValue::Integer(i) => i.to_string(),
                    yara_x::MetaValue::Float(fl) => fl.to_string(),
                    yara_x::MetaValue::Bool(b) => b.to_string(),
                    yara_x::MetaValue::String(s) => s.to_string(),
                    yara_x::MetaValue::Bytes(b) => b
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<Vec<_>>()
                        .join(" "),
                };
                meta.insert(key.to_string(), val_str);
            }

            let tags: Vec<String> = rule.tags().map(|t| t.identifier().to_string()).collect();

            out.push(YaraMatch {
                rule_name: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                tags,
                meta,
                patterns,
            });
        }
        out
    }
}

// â"€â"€ YaraRuleRepository â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A named, enable/disable rule repository that compiles to a [`YaraEngineScanner`].
///
/// Rules are stored as `(name, source)` pairs.  Individual rules can be
/// toggled on or off before compiling, which is useful for managing large
/// collections of detection rules where only a subset is relevant for a
/// particular analysis task.
pub struct YaraRuleRepository {
    /// All rules as `(name, source)` pairs.
    rules: Vec<(String, String)>,
    /// Set of rule names that are currently enabled.
    enabled: HashSet<String>,
}

impl fmt::Debug for YaraRuleRepository {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "YaraRuleRepository(total={}, enabled={})",
            self.rules.len(),
            self.enabled.len()
        )
    }
}

impl YaraRuleRepository {
    /// Create a new, empty repository.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            enabled: HashSet::new(),
        }
    }

    /// Add a named rule to the repository.
    ///
    /// The rule is **enabled** by default.
    /// Returns `&mut Self` for method chaining.
    pub fn add(&mut self, name: impl Into<String>, source: impl Into<String>) -> &mut Self {
        let name = name.into();
        self.enabled.insert(name.clone());
        self.rules.push((name, source.into()));
        self
    }

    /// Enable a previously disabled rule by name.
    pub fn enable(&mut self, name: &str) -> &mut Self {
        self.enabled.insert(name.to_string());
        self
    }

    /// Disable a rule by name so it is not included when compiling.
    pub fn disable(&mut self, name: &str) -> &mut Self {
        self.enabled.remove(name);
        self
    }

    /// Return `true` if the named rule exists in this repository.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.rules.iter().any(|(n, _)| n == name)
    }

    /// Return the total number of rules (both enabled and disabled).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.rules.len()
    }

    /// Return `true` if the repository contains no rules.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Return the number of currently enabled rules.
    #[must_use]
    pub fn enabled_count(&self) -> usize {
        self.enabled.len()
    }

    /// Compile all **enabled** rules and return a [`YaraEngineScanner`].
    ///
    /// # Errors
    ///
    /// Returns [`YaraError`] if no rules are enabled or if compilation fails.
    pub fn compile_enabled(&self) -> Result<YaraEngineScanner, YaraError> {
        let mut ruleset = YaraRuleSet::new();
        for (name, source) in &self.rules {
            if self.enabled.contains(name.as_str()) {
                ruleset.add_rule(source)?;
            }
        }
        if ruleset.is_empty() {
            return Err(YaraError::CompileError(
                "no enabled rules to compile".to_string(),
            ));
        }
        YaraEngineScanner::new(&mut ruleset)
    }

    /// Return a pre-populated repository containing 10 built-in malware
    /// detection rules covering common indicators.
    ///
    /// All rules are enabled by default.
    #[must_use]
    pub fn builtin_rules() -> Self {
        let mut repo = Self::new();
        Self::add_file_magic_rules(&mut repo);
        Self::add_malware_indicator_rules(&mut repo);
        Self::add_advanced_threat_rules(&mut repo);
        repo
    }

    fn add_file_magic_rules(repo: &mut Self) {
        repo.add(
            "MZ_header",
            r#"rule MZ_header {
    meta:
        description = "Detects PE (Windows executable) files by MZ magic header"
        author      = "rustre-yara-engine"
        severity    = "info"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0 and filesize > 0
}"#,
        );

        // â"€â"€ 2. ELF header —" Linux/Unix executable detection â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        repo.add(
            "ELF_header",
            r#"rule ELF_header {
    meta:
        description = "Detects ELF (Linux/Unix executable) files by magic header"
        author      = "rustre-yara-engine"
        severity    = "info"
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf at 0
}"#,
        );

    }

    fn add_malware_indicator_rules(repo: &mut Self) {
        repo.add(
            "Suspicious_strings",
            r#"rule Suspicious_strings {
    meta:
        description = "Detects common malware-associated strings"
        author      = "rustre-yara-engine"
        severity    = "medium"
    strings:
        $cmd         = "cmd.exe"           nocase
        $ps          = "powershell"        nocase
        $ps_enc      = "-EncodedCommand"   nocase
        $ps_bypass   = "bypass"            nocase
        $ps_nop      = "-nop"              nocase
        $ps_noprof   = "-NoProfile"        nocase
        $wscript     = "wscript.exe"       nocase
        $cscript     = "cscript.exe"       nocase
        $regsvr      = "regsvr32.exe"      nocase
        $mshta       = "mshta.exe"         nocase
        $rundll      = "rundll32.exe"      nocase
        $certutil    = "certutil"          nocase
        $b64_decode  = "FromBase64String"  nocase
        $b64_enc     = "ToBase64String"    nocase
        $invoke_exp  = "Invoke-Expression" nocase
        $iex         = "IEX("             nocase
        $download    = "DownloadString("  nocase
        $webclient   = "WebClient"         nocase
    condition:
        2 of them
}"#,
        );

        // â"€â"€ 4. Shellcode patterns —" common x86/x64 shellcode signatures â"€â"€â"€â"€â"€â"€â"€
        repo.add(
            "Shellcode_patterns",
            r#"rule Shellcode_patterns {
    meta:
        description = "Detects common x86/x64 shellcode sequences"
        author      = "rustre-yara-engine"
        severity    = "high"
    strings:
        // x86 GetPC stub (call $+5 / pop)
        $getpc_call   = { E8 00 00 00 00 }
        // x64 NOP sled (8+ consecutive NOPs)
        $nop_sled     = { 90 90 90 90 90 90 90 90 }
        // Common shellcode prologue (push ebp ; mov ebp,esp)
        $prologue     = { 55 8B EC }
        // VirtualAlloc marker often seen in shellcode loaders
        $valloc       = "VirtualAlloc" nocase
        // LoadLibrary common stub
        $loadlib      = "LoadLibraryA" nocase
        // Null-padded string common in shellcode "cmd\x00"
        $cmd_null     = { 63 6D 64 00 }
        // INT3 breakpoint sled (debugger trap)
        $int3_sled    = { CC CC CC CC CC CC CC CC }
        // Egg hunter pattern
        $egg          = { 90 50 90 50 }
    condition:
        any of them
}"#,
        );

        // â"€â"€ 5. Network IOC —" raw IP/domain indicator patterns â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        repo.add(
            "Network_IOC",
            r#"rule Network_IOC {
    meta:
        description = "Detects hard-coded IP addresses and suspicious domain patterns"
        author      = "rustre-yara-engine"
        severity    = "medium"
    strings:
        // Common C2 infrastructure indicators
        $loopback      = "127.0.0.1"
        $private_10    = /10\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        $private_192   = /192\.168\.\d{1,3}\.\d{1,3}/
        // Suspicious TLDs often used in malware
        $tld_tk        = /[a-z0-9\-]+\.tk[\/\s"']/  nocase
        $tld_ru        = /[a-z0-9\-]+\.ru[\/\s"']/  nocase
        $tld_cc        = /[a-z0-9\-]+\.cc[\/\s"']/  nocase
        // Raw socket / connect patterns
        $connect       = "connect("  nocase
        $socket        = "socket("   nocase
        $recv          = "recv("     nocase
        $send          = "send("     nocase
        // Common C2 communication strings
        $http_get      = "GET /"     nocase
        $http_post     = "POST /"    nocase
        $user_agent    = "User-Agent" nocase
    condition:
        2 of them
}"#,
        );

        // â"€â"€ 6. Packed executable —" high entropy / UPX markers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        repo.add(
            "UPX_packed",
            r#"rule UPX_packed {
    meta:
        description = "Detects UPX-packed executables"
        author      = "rustre-yara-engine"
        severity    = "low"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX!"
        $upx3 = { 55 50 58 21 }
    condition:
        any of them
}"#,
        );

    }

    fn add_advanced_threat_rules(repo: &mut Self) {
        repo.add(
            "Ransomware_strings",
            r#"rule Ransomware_strings {
    meta:
        description = "Detects common ransomware-related strings"
        author      = "rustre-yara-engine"
        severity    = "critical"
    strings:
        $ransom1  = "your files have been encrypted"  nocase
        $ransom2  = "bitcoin"                          nocase
        $ransom3  = ".onion"                           nocase
        $ransom4  = "decrypt"                          nocase
        $ransom5  = "CryptEncrypt"                     nocase
        $ransom6  = "CryptGenKey"                      nocase
        $ransom7  = "readme_how_to_decrypt"            nocase
        $ransom8  = "HOW_TO_RECOVER"                   nocase
        $vss      = "vssadmin delete shadows"          nocase
        $bcdedit  = "bcdedit /set {default}"           nocase
    condition:
        2 of them
}"#,
        );

        // â"€â"€ 8. Anti-analysis —" debugger/VM evasion techniques â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        repo.add(
            "Anti_analysis",
            r#"rule Anti_analysis {
    meta:
        description = "Detects common anti-analysis and evasion techniques"
        author      = "rustre-yara-engine"
        severity    = "medium"
    strings:
        $isdbg      = "IsDebuggerPresent"  nocase
        $chkrmt     = "CheckRemoteDebuggerPresent" nocase
        $ntqsi      = "NtQuerySystemInformation" nocase
        $ntqip      = "NtQueryInformationProcess" nocase
        $sleep      = "SleepEx"           nocase
        $vmware     = "VMware"            nocase
        $vbox       = "VirtualBox"        nocase
        $vbox2      = "VBOX"              nocase
        $wine       = "wine_get_version"  nocase
        $sandboxie  = "SbieDll"           nocase
        $olly       = "OLLYDBG"           nocase
        $x64dbg     = "x64dbg"            nocase
    condition:
        2 of them
}"#,
        );

        // â"€â"€ 9. Credential harvesting patterns â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        repo.add(
            "Credential_harvest",
            r#"rule Credential_harvest {
    meta:
        description = "Detects credential-harvesting related API calls and strings"
        author      = "rustre-yara-engine"
        severity    = "high"
    strings:
        $lsass       = "lsass"                  nocase
        $sekurlsa    = "sekurlsa"               nocase
        $mimikatz    = "mimikatz"               nocase
        $wce         = "wce.exe"                nocase
        $samropen    = "SamrOpenUser"           nocase
        $nltest      = "nltest"                 nocase
        $credman     = "CredEnumerate"          nocase
        $vaultcli    = "VaultOpenVault"         nocase
        $ntlm        = "NTLMv2"                 nocase
        $logon_sess  = "LogonSessionData"       nocase
    condition:
        2 of them
}"#,
        );

        // â"€â"€ 10. Persistence mechanisms â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        repo.add(
            "Persistence",
            r#"rule Persistence {
    meta:
        description = "Detects common persistence mechanism strings"
        author      = "rustre-yara-engine"
        severity    = "high"
    strings:
        $run_key    = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"  nocase
        $schtasks   = "schtasks"           nocase
        $sc_create  = "sc create"          nocase
        $at_cmd     = "at.exe"             nocase
        $startup    = "Startup"            nocase
        $autorun    = "AUTORUN.INF"        nocase
        $wmi_sub    = "__EventFilter"      nocase
        $reg_add    = "reg add"            nocase
        $inf_file   = "INF\\Setup"         nocase
        $appinit    = "AppInit_DLLs"       nocase
    condition:
        2 of them
}"#,
        );
    }
}

impl Default for YaraRuleRepository {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    // â"€â"€ Text matching â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_text_match_basic() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("TestRule".to_string())
            .with_string(YaraString {
                identifier: "$s".to_string(),
                value: StringValue::Text("hello".to_string()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$s".to_string()));
        scanner.add_rule(rule);
        let names = scanner.scan_names(b"say hello world");
        assert_eq!(names, vec!["TestRule"]);
    }

    #[test]
    fn test_text_no_match() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("NoMatch".to_string())
            .with_string(YaraString {
                identifier: "$s".to_string(),
                value: StringValue::Text("absent".to_string()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$s".to_string()));
        scanner.add_rule(rule);
        assert!(scanner.scan_names(b"nothing here").is_empty());
    }

    #[test]
    fn test_text_match_nocase() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("Nocase".to_string())
            .with_string(YaraString {
                identifier: "$s".to_string(),
                value: StringValue::Text("HELLO".to_string()),
                modifiers: StringModifiers::NOCASE,
            })
            .with_condition(Condition::StringMatch("$s".to_string()));
        scanner.add_rule(rule);
        assert!(!scanner.scan_names(b"say hello world").is_empty());
    }

    #[test]
    fn test_text_match_wide() {
        let scanner = YaraScanner::new();
        let wide_data: Vec<u8> = "AB".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let rule = YaraRule::new("Wide".to_string())
            .with_string(YaraString {
                identifier: "$s".to_string(),
                value: StringValue::Text("AB".to_string()),
                modifiers: StringModifiers::WIDE,
            })
            .with_condition(Condition::StringMatch("$s".to_string()));
        scanner.add_rule(rule);
        assert!(!scanner.scan_names(&wide_data).is_empty());
    }

    #[test]
    fn test_multiple_text_matches_offset() {
        let _scanner = YaraScanner::new();
        let matches = YaraScanner::find_text_matches("aa", StringModifiers::NONE, b"aaaaaa", "$x");
        assert_eq!(matches.len(), 5);
    }

    // â"€â"€ Hex matching â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_hex_match_exact() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("Hex".to_string())
            .with_string(YaraString {
                identifier: "$h".to_string(),
                value: StringValue::Hex(vec![HexToken::Byte(0xDE), HexToken::Byte(0xAD)]),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$h".to_string()));
        scanner.add_rule(rule);
        assert!(!scanner.scan_names(&[0x00, 0xDE, 0xAD, 0xFF]).is_empty());
    }

    #[test]
    fn test_hex_match_wildcard() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("HexWild".to_string())
            .with_string(YaraString {
                identifier: "$h".to_string(),
                value: StringValue::Hex(vec![
                    HexToken::Byte(0xDE),
                    HexToken::Wildcard,
                    HexToken::Byte(0xBE),
                ]),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$h".to_string()));
        scanner.add_rule(rule);
        assert!(!scanner.scan_names(&[0xDE, 0x00, 0xBE]).is_empty());
        assert!(scanner.scan_names(&[0xDE, 0x00, 0xFF]).is_empty());
    }

    #[test]
    fn test_hex_match_masked_byte() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("Masked".to_string())
            .with_string(YaraString {
                identifier: "$h".to_string(),
                value: StringValue::Hex(vec![HexToken::MaskedByte(0xA0, 0xF0)]),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$h".to_string()));
        scanner.add_rule(rule);
        // 0xAB & 0xF0 == 0xA0 -> match
        assert!(!scanner.scan_names(&[0xAB]).is_empty());
        // 0xBB & 0xF0 == 0xB0 != 0xA0 -> no match
        assert!(scanner.scan_names(&[0xBB]).is_empty());
    }

    #[test]
    fn test_hex_no_match() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("HexNoMatch".to_string())
            .with_string(YaraString {
                identifier: "$h".to_string(),
                value: StringValue::Hex(vec![HexToken::Byte(0xFF)]),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringMatch("$h".to_string()));
        scanner.add_rule(rule);
        assert!(scanner.scan_names(b"abcde").is_empty());
    }

    // â"€â"€ Condition evaluation â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_condition_true() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("Always".to_string()).with_condition(Condition::True);
        scanner.add_rule(rule);
        assert!(!scanner.scan_names(b"anything").is_empty());
    }

    #[test]
    fn test_condition_false() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("Never".to_string()).with_condition(Condition::False);
        scanner.add_rule(rule);
        assert!(scanner.scan_names(b"anything").is_empty());
    }

    #[test]
    fn test_condition_all_of_them() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("AllOf".to_string())
            .with_string(YaraString {
                identifier: "$a".to_string(),
                value: StringValue::Text("foo".to_string()),
                modifiers: StringModifiers::NONE,
            })
            .with_string(YaraString {
                identifier: "$b".to_string(),
                value: StringValue::Text("bar".to_string()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::All);
        scanner.add_rule(rule);
        assert!(!scanner.scan_names(b"foobar").is_empty());
        assert!(scanner.scan_names(b"foo only").is_empty());
    }

    #[test]
    fn test_condition_any_of_them() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("AnyOf".to_string())
            .with_string(YaraString {
                identifier: "$a".to_string(),
                value: StringValue::Text("foo".to_string()),
                modifiers: StringModifiers::NONE,
            })
            .with_string(YaraString {
                identifier: "$b".to_string(),
                value: StringValue::Text("bar".to_string()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::Any);
        scanner.add_rule(rule);
        assert!(!scanner.scan_names(b"foo only").is_empty());
        assert!(scanner.scan_names(b"nothing").is_empty());
    }

    #[test]
    fn test_condition_none_of_them() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("NoneOf".to_string())
            .with_string(YaraString {
                identifier: "$a".to_string(),
                value: StringValue::Text("bad".to_string()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::None);
        scanner.add_rule(rule);
        assert!(!scanner.scan_names(b"good data").is_empty());
        assert!(scanner.scan_names(b"bad data").is_empty());
    }

    #[test]
    fn test_condition_and() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("And".to_string())
            .with_string(YaraString {
                identifier: "$a".to_string(),
                value: StringValue::Text("foo".to_string()),
                modifiers: StringModifiers::NONE,
            })
            .with_string(YaraString {
                identifier: "$b".to_string(),
                value: StringValue::Text("bar".to_string()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::And(
                Box::new(Condition::StringMatch("$a".to_string())),
                Box::new(Condition::StringMatch("$b".to_string())),
            ));
        scanner.add_rule(rule);
        assert!(!scanner.scan_names(b"foobar").is_empty());
        assert!(scanner.scan_names(b"foo").is_empty());
    }

    #[test]
    fn test_condition_or() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("Or".to_string())
            .with_string(YaraString {
                identifier: "$a".to_string(),
                value: StringValue::Text("foo".to_string()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::Or(
                Box::new(Condition::StringMatch("$a".to_string())),
                Box::new(Condition::False),
            ));
        scanner.add_rule(rule);
        assert!(!scanner.scan_names(b"foo").is_empty());
    }

    #[test]
    fn test_condition_not() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("Not".to_string())
            .with_condition(Condition::Not(Box::new(Condition::False)));
        scanner.add_rule(rule);
        assert!(!scanner.scan_names(b"anything").is_empty());
    }

    #[test]
    fn test_condition_string_at() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("At".to_string())
            .with_string(YaraString {
                identifier: "$a".to_string(),
                value: StringValue::Text("MZ".to_string()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringAt("$a".to_string(), 0));
        scanner.add_rule(rule);
        assert!(!scanner.scan_names(b"MZother").is_empty());
        assert!(scanner.scan_names(b"xxMZ").is_empty());
    }

    #[test]
    fn test_condition_filesize() {
        let scanner = YaraScanner::new();
        let rule =
            YaraRule::new("Size".to_string()).with_condition(Condition::FileSize(CompOp::Ge, 4));
        scanner.add_rule(rule);
        assert!(!scanner.scan_names(b"hello").is_empty());
        assert!(scanner.scan_names(b"hi").is_empty());
    }

    #[test]
    fn test_condition_string_in() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("InRange".to_string())
            .with_string(YaraString {
                identifier: "$a".to_string(),
                value: StringValue::Text("X".to_string()),
                modifiers: StringModifiers::NONE,
            })
            .with_condition(Condition::StringIn("$a".to_string(), 0, 5));
        scanner.add_rule(rule);
        assert!(!scanner.scan_names(b"abXde").is_empty());
        assert!(scanner.scan_names(b"abcdefX").is_empty());
    }

    #[test]
    fn test_rule_count() {
        let scanner = YaraScanner::new();
        assert_eq!(scanner.rule_count(), 0);
        scanner.add_rule(YaraRule::new("A".to_string()));
        assert_eq!(scanner.rule_count(), 1);
    }

    #[test]
    fn test_scan_returns_meta_and_tags() {
        let scanner = YaraScanner::new();
        let rule = YaraRule::new("Tagged".to_string())
            .with_tag("malware".to_string())
            .with_meta("author".to_string(), MetaValue::String("test".to_string()))
            .with_condition(Condition::True);
        scanner.add_rule(rule);
        let results = scanner.scan(b"data");
        assert_eq!(results.len(), 1);
        assert!(results[0].tags.contains(&"malware".to_string()));
    }

    // â"€â"€ Parser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_parser_simple_rule() {
        let parser = YaraParser::new();
        let rule_text = r#"rule SimpleRule {
            strings:
                $a = "hello"
            condition:
                $a
        }"#;
        let rule = parser.parse_rule(rule_text).unwrap();
        assert_eq!(rule.name, "SimpleRule");
        assert_eq!(rule.strings.len(), 1);
    }

    #[test]
    fn test_parser_multi_rules() {
        let parser = YaraParser::new();
        let text = r"rule A { condition: true }
rule B { condition: false }";
        let rules = parser.parse_rules(text).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "A");
        assert_eq!(rules[1].name, "B");
    }

    #[test]
    fn test_parser_tags() {
        let parser = YaraParser::new();
        let text = r"rule Tagged : malware packer { condition: true }";
        let rule = parser.parse_rule(text).unwrap();
        assert!(rule.tags.contains(&"malware".to_string()));
        assert!(rule.tags.contains(&"packer".to_string()));
    }

    #[test]
    fn test_parser_meta() {
        let parser = YaraParser::new();
        let text = r#"rule WithMeta {
            meta:
                description = "test rule"
                version = 1
            condition: true
        }"#;
        let rule = parser.parse_rule(text).unwrap();
        assert!(rule.meta.contains_key("description"));
    }

    #[test]
    fn test_parser_hex_string() {
        let parser = YaraParser::new();
        let text = r"rule HexRule {
            strings:
                $h = { DE AD BE EF }
            condition:
                $h
        }";
        let rule = parser.parse_rule(text).unwrap();
        assert_eq!(rule.strings.len(), 1);
        assert!(matches!(rule.strings[0].value, StringValue::Hex(_)));
    }

    #[test]
    fn test_parser_invalid_missing_keyword() {
        let parser = YaraParser::new();
        assert!(parser.parse_rule("not a rule").is_err());
    }

    #[test]
    fn test_parser_empty_name_error() {
        let parser = YaraParser::new();
        assert!(parser.parse_rule("rule { condition: true }").is_err());
    }

    // â"€â"€ Display / Debug â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_display_rule() {
        let rule = YaraRule::new("R".to_string());
        assert!(rule.to_string().contains('R'));
    }

    #[test]
    fn test_display_meta_value() {
        assert_eq!(MetaValue::String("x".to_string()).to_string(), "\"x\"");
        assert_eq!(MetaValue::Int(42).to_string(), "42");
        assert_eq!(MetaValue::Bool(true).to_string(), "true");
    }

    #[test]
    fn test_display_compop() {
        assert_eq!(CompOp::Ge.to_string(), ">=");
        assert_eq!(CompOp::Lt.to_string(), "<");
    }

    #[test]
    fn test_display_string_match() {
        let m = StringMatch {
            identifier: "$a".to_string(),
            offset: 0x10,
            length: 4,
            matched_data: vec![],
        };
        assert!(m.to_string().contains("0x10"));
    }

    #[test]
    fn test_display_rule_match() {
        let rm = RuleMatch {
            rule_name: "R".to_string(),
            namespace: "default".to_string(),
            tags: vec![],
            meta: HashMap::new(),
            string_matches: vec![],
        };
        assert!(rm.to_string().contains("MATCH"));
    }

    #[test]
    fn test_scanner_debug() {
        let s = YaraScanner::new();
        assert!(format!("{s:?}").contains("YaraScanner"));
    }

    #[test]
    fn test_parser_debug() {
        let p = YaraParser::new();
        assert_eq!(format!("{p:?}"), "YaraParser");
    }

    #[test]
    fn test_find_all_bytes_overlapping() {
        let offsets = find_all_bytes(b"aa", b"aaaa");
        assert_eq!(offsets, vec![0, 1, 2]);
    }

    #[test]
    fn test_find_all_nocase() {
        let offsets = find_all_nocase(b"AB", b"aAbBaB");
        assert!(!offsets.is_empty());
    }

    // â"€â"€ YaraRuleDefinition â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_rule_definition_parse_name() {
        let src = r"rule MyMalware : trojan { condition: true }";
        let name = YaraRuleDefinition::parse_name_from_source(src);
        assert_eq!(name, Some("MyMalware".to_string()));
    }

    #[test]
    fn test_rule_definition_parse_name_no_tags() {
        let src = r"rule SimpleRule { condition: true }";
        let name = YaraRuleDefinition::parse_name_from_source(src);
        assert_eq!(name, Some("SimpleRule".to_string()));
    }

    #[test]
    fn test_rule_definition_parse_name_multiline() {
        let src = "rule MultiLine\n{\n  condition: true\n}";
        let name = YaraRuleDefinition::parse_name_from_source(src);
        assert_eq!(name, Some("MultiLine".to_string()));
    }

    #[test]
    fn test_rule_definition_parse_name_absent() {
        let name = YaraRuleDefinition::parse_name_from_source("not a yara file");
        assert!(name.is_none());
    }

    #[test]
    fn test_rule_definition_new_uses_parsed_name() {
        let src = r"rule DetectMZ { condition: true }";
        let def = YaraRuleDefinition::new("my_id", src);
        assert_eq!(def.name, "DetectMZ");
        assert_eq!(def.id, "my_id");
    }

    #[test]
    fn test_rule_definition_new_fallback_id() {
        let src = "not_a_rule";
        let def = YaraRuleDefinition::new("fallback_id", src);
        assert_eq!(def.name, "fallback_id");
    }

    #[test]
    fn test_rule_definition_namespace_default() {
        let def = YaraRuleDefinition::new("id", "rule X { condition: true }");
        assert_eq!(def.namespace, "default");
    }

    #[test]
    fn test_rule_definition_with_namespace() {
        let def =
            YaraRuleDefinition::new("id", "rule X { condition: true }").with_namespace("malware");
        assert_eq!(def.namespace, "malware");
    }

    #[test]
    fn test_rule_definition_with_tag() {
        let def = YaraRuleDefinition::new("id", "rule X { condition: true }").with_tag("trojan");
        assert!(def.tags.contains(&"trojan".to_string()));
    }

    #[test]
    fn test_rule_definition_with_meta() {
        let def =
            YaraRuleDefinition::new("id", "rule X { condition: true }").with_meta("author", "test");
        assert_eq!(def.meta.get("author").map(String::as_str), Some("test"));
    }

    #[test]
    fn test_rule_definition_display() {
        let def = YaraRuleDefinition::new("my_id", "rule Foo { condition: true }");
        let s = def.to_string();
        assert!(s.contains("my_id"));
        assert!(s.contains("Foo"));
    }

    // â"€â"€ YaraRuleSet â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_ruleset_new_empty() {
        let rs = YaraRuleSet::new();
        assert!(rs.is_empty());
        assert!(!rs.is_compiled());
    }

    #[test]
    fn test_ruleset_add_rule() {
        let mut rs = YaraRuleSet::new();
        rs.add_rule("rule A { condition: true }").unwrap();
        assert_eq!(rs.len(), 1);
    }

    #[test]
    fn test_ruleset_add_rule_empty_error() {
        let mut rs = YaraRuleSet::new();
        assert!(rs.add_rule("   ").is_err());
    }

    #[test]
    fn test_ruleset_add_multiple_rules() {
        let mut rs = YaraRuleSet::new();
        rs.add_rule("rule A { condition: true }").unwrap();
        rs.add_rule("rule B { condition: false }").unwrap();
        assert_eq!(rs.len(), 2);
    }

    #[test]
    fn test_ruleset_compile_basic() {
        let mut rs = YaraRuleSet::new();
        rs.add_rule("rule AlwaysTrue { condition: true }").unwrap();
        assert!(rs.compile().is_ok());
        assert!(rs.is_compiled());
    }

    #[test]
    fn test_ruleset_default() {
        let rs = YaraRuleSet::default();
        assert!(rs.is_empty());
    }

    // â"€â"€ PatternMatch / YaraMatch display â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_pattern_match_display() {
        let pm = PatternMatch {
            identifier: "$a".to_string(),
            offset: 0x1000,
            length: 4,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let s = pm.to_string();
        assert!(s.contains("$a"));
        assert!(s.contains("0x00001000"));
    }

    #[test]
    fn test_yara_match_display() {
        let ym = YaraMatch {
            rule_name: "TestRule".to_string(),
            namespace: "default".to_string(),
            tags: vec![],
            meta: HashMap::new(),
            patterns: vec![],
        };
        let s = ym.to_string();
        assert!(s.contains("TestRule"));
    }

    // â"€â"€ YaraEngineScanner â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_engine_scanner_new_compiles() {
        let mut rs = YaraRuleSet::new();
        rs.add_rule("rule AlwaysTrue { condition: true }").unwrap();
        let scanner = YaraEngineScanner::new(&mut rs);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_engine_scanner_scan_bytes_match() {
        let mut rs = YaraRuleSet::new();
        rs.add_rule(
            r"rule HasMZ {
            strings:
                $mz = { 4D 5A }
            condition:
                $mz at 0
        }",
        )
        .unwrap();
        let scanner = YaraEngineScanner::new(&mut rs).unwrap();
        let mut data = vec![0x4D, 0x5A];
        data.extend_from_slice(b"PE content here");
        let matches = scanner.scan_bytes(&data);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].rule_name, "HasMZ");
    }

    #[test]
    fn test_engine_scanner_scan_bytes_no_match() {
        let mut rs = YaraRuleSet::new();
        rs.add_rule(
            r"rule HasMZ {
            strings:
                $mz = { 4D 5A }
            condition:
                $mz at 0
        }",
        )
        .unwrap();
        let scanner = YaraEngineScanner::new(&mut rs).unwrap();
        let matches = scanner.scan_bytes(b"no pe here");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_engine_scanner_scan_bytes_pattern_data() {
        let mut rs = YaraRuleSet::new();
        rs.add_rule(
            r#"rule FindHello {
            strings:
                $h = "hello"
            condition:
                $h
        }"#,
        )
        .unwrap();
        let scanner = YaraEngineScanner::new(&mut rs).unwrap();
        let matches = scanner.scan_bytes(b"say hello world");
        assert!(!matches.is_empty());
        let m = &matches[0];
        assert!(!m.patterns.is_empty());
        assert_eq!(m.patterns[0].identifier, "$h");
        assert_eq!(m.patterns[0].offset, 4);
        assert_eq!(m.patterns[0].length, 5);
    }

    #[test]
    fn test_engine_scanner_scan_process_stub() {
        let mut rs = YaraRuleSet::new();
        rs.add_rule("rule X { condition: true }").unwrap();
        let scanner = YaraEngineScanner::new(&mut rs).unwrap();
        assert!(scanner.scan_process(1234).is_err());
    }

    #[test]
    fn test_engine_scanner_rules_arc_cloneable() {
        let mut rs = YaraRuleSet::new();
        rs.add_rule("rule X { condition: true }").unwrap();
        let scanner = YaraEngineScanner::new(&mut rs).unwrap();
        let arc1 = scanner.rules_arc();
        let arc2 = scanner.rules_arc();
        assert!(Arc::ptr_eq(&arc1, &arc2));
    }

    #[test]
    fn test_engine_scanner_debug() {
        let mut rs = YaraRuleSet::new();
        rs.add_rule("rule X { condition: true }").unwrap();
        let scanner = YaraEngineScanner::new(&mut rs).unwrap();
        let s = format!("{scanner:?}");
        assert!(s.contains("YaraEngineScanner"));
    }

    // â"€â"€ YaraRuleRepository â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_repository_new_empty() {
        let repo = YaraRuleRepository::new();
        assert!(repo.is_empty());
        assert_eq!(repo.enabled_count(), 0);
    }

    #[test]
    fn test_repository_add_enables_by_default() {
        let mut repo = YaraRuleRepository::new();
        repo.add("test", "rule T { condition: true }");
        assert_eq!(repo.len(), 1);
        assert_eq!(repo.enabled_count(), 1);
        assert!(repo.contains("test"));
    }

    #[test]
    fn test_repository_disable_enable() {
        let mut repo = YaraRuleRepository::new();
        repo.add("r1", "rule R1 { condition: true }");
        repo.disable("r1");
        assert_eq!(repo.enabled_count(), 0);
        repo.enable("r1");
        assert_eq!(repo.enabled_count(), 1);
    }

    #[test]
    fn test_repository_compile_enabled_single() {
        let mut repo = YaraRuleRepository::new();
        repo.add("r1", "rule R1 { condition: true }");
        let scanner = repo.compile_enabled();
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_repository_compile_enabled_empty_error() {
        let repo = YaraRuleRepository::new();
        let result = repo.compile_enabled();
        assert!(result.is_err());
    }

    #[test]
    fn test_repository_compile_disabled_all_error() {
        let mut repo = YaraRuleRepository::new();
        repo.add("r1", "rule R1 { condition: true }");
        repo.disable("r1");
        let result = repo.compile_enabled();
        assert!(result.is_err());
    }

    #[test]
    fn test_repository_compile_only_enabled() {
        let mut repo = YaraRuleRepository::new();
        repo.add("enabled_rule", "rule EnabledRule { condition: true }");
        repo.add("disabled_rule", "rule DisabledRule { condition: true }");
        repo.disable("disabled_rule");
        let scanner = repo.compile_enabled().unwrap();
        // Both rules match "true" condition; only the enabled one should scan.
        let matches = scanner.scan_bytes(b"anything");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "EnabledRule");
    }

    #[test]
    fn test_repository_default() {
        let repo = YaraRuleRepository::default();
        assert!(repo.is_empty());
    }

    #[test]
    fn test_repository_debug() {
        let repo = YaraRuleRepository::new();
        let s = format!("{repo:?}");
        assert!(s.contains("YaraRuleRepository"));
    }

    // â"€â"€ builtin_rules â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_builtin_rules_count() {
        let repo = YaraRuleRepository::builtin_rules();
        assert_eq!(repo.len(), 10);
        assert_eq!(repo.enabled_count(), 10);
    }

    #[test]
    fn test_builtin_rules_compiles() {
        let repo = YaraRuleRepository::builtin_rules();
        let scanner = repo.compile_enabled();
        assert!(
            scanner.is_ok(),
            "builtin rules must compile: {:?}",
            scanner.err()
        );
    }

    #[test]
    fn test_builtin_mz_header_detects_pe() {
        let repo = YaraRuleRepository::builtin_rules();
        let scanner = repo.compile_enabled().unwrap();
        let mut pe = vec![0x4D, 0x5A]; // MZ
        pe.extend_from_slice(&[0u8; 128]);
        let matches = scanner.scan_bytes(&pe);
        let names: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        assert!(
            names.contains(&"MZ_header"),
            "MZ_header should match PE data: {names:?}"
        );
    }

    #[test]
    fn test_builtin_elf_header_detects_elf() {
        let repo = YaraRuleRepository::builtin_rules();
        let scanner = repo.compile_enabled().unwrap();
        let elf = vec![0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        let matches = scanner.scan_bytes(&elf);
        let names: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        assert!(
            names.contains(&"ELF_header"),
            "ELF_header should match ELF data: {names:?}"
        );
    }

    #[test]
    fn test_builtin_suspicious_strings_detects_powershell() {
        let repo = YaraRuleRepository::builtin_rules();
        let scanner = repo.compile_enabled().unwrap();
        let data = b"powershell -EncodedCommand AAAA";
        let matches = scanner.scan_bytes(data);
        let names: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        assert!(
            names.contains(&"Suspicious_strings"),
            "Suspicious_strings should fire on powershell: {names:?}"
        );
    }

    #[test]
    fn test_builtin_upx_packed_detects_upx() {
        let repo = YaraRuleRepository::builtin_rules();
        let scanner = repo.compile_enabled().unwrap();
        let data = b"UPX0UPX1some packed content";
        let matches = scanner.scan_bytes(data);
        let names: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        assert!(
            names.contains(&"UPX_packed"),
            "UPX_packed should fire: {names:?}"
        );
    }

    #[test]
    fn test_builtin_ransomware_detects_bitcoin() {
        let repo = YaraRuleRepository::builtin_rules();
        let scanner = repo.compile_enabled().unwrap();
        let data = b"Your files have been encrypted. Pay bitcoin to recover them.";
        let matches = scanner.scan_bytes(data);
        let names: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        assert!(
            names.contains(&"Ransomware_strings"),
            "Ransomware_strings should fire: {names:?}"
        );
    }

    #[test]
    fn test_builtin_anti_analysis_detects_vbox() {
        let repo = YaraRuleRepository::builtin_rules();
        let scanner = repo.compile_enabled().unwrap();
        let data = b"IsDebuggerPresent VirtualBox check failed";
        let matches = scanner.scan_bytes(data);
        let names: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        assert!(
            names.contains(&"Anti_analysis"),
            "Anti_analysis should fire: {names:?}"
        );
    }

    #[test]
    fn test_builtin_persistence_detects_run_key() {
        let repo = YaraRuleRepository::builtin_rules();
        let scanner = repo.compile_enabled().unwrap();
        let data = b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run schtasks /create";
        let matches = scanner.scan_bytes(data);
        let names: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        assert!(
            names.contains(&"Persistence"),
            "Persistence should fire: {names:?}"
        );
    }

    #[test]
    fn test_builtin_network_ioc_detects_socket() {
        let repo = YaraRuleRepository::builtin_rules();
        let scanner = repo.compile_enabled().unwrap();
        let data = b"connect( socket( send( recv(";
        let matches = scanner.scan_bytes(data);
        let names: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        assert!(
            names.contains(&"Network_IOC"),
            "Network_IOC should fire: {names:?}"
        );
    }

    #[test]
    fn test_builtin_shellcode_detects_nop_sled() {
        let repo = YaraRuleRepository::builtin_rules();
        let scanner = repo.compile_enabled().unwrap();
        let mut data = vec![0x90u8; 16]; // NOP sled
        data.extend_from_slice(b"shell payload");
        let matches = scanner.scan_bytes(&data);
        let names: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        assert!(
            names.contains(&"Shellcode_patterns"),
            "Shellcode_patterns should fire on NOP sled: {names:?}"
        );
    }

    #[test]
    fn test_builtin_credential_harvest_detects_mimikatz() {
        let repo = YaraRuleRepository::builtin_rules();
        let scanner = repo.compile_enabled().unwrap();
        let data = b"mimikatz sekurlsa::logonpasswords";
        let matches = scanner.scan_bytes(data);
        let names: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        assert!(
            names.contains(&"Credential_harvest"),
            "Credential_harvest should fire on mimikatz: {names:?}"
        );
    }
}

// â"€â"€ Async scanning support â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Convenience alias for a region identifier that originated from a
/// file-system path. Re-exported here so async callers can reach
/// [`std::path::PathBuf`] without an extra import line.
pub type AsyncRegionPath = std::path::PathBuf;

/// Result of an asynchronous scan over multiple regions.
#[derive(Debug, Clone)]
pub struct AsyncScanResult {
    /// Region identifier (file path or address range string).
    pub region_id: String,
    /// All rule matches found in this region.
    pub matches: Vec<YaraMatch>,
}

impl AsyncScanResult {
    /// Create a new async scan result.
    #[must_use]
    pub fn new(region_id: impl Into<String>, matches: Vec<YaraMatch>) -> Self {
        Self {
            region_id: region_id.into(),
            matches,
        }
    }

    /// Return `true` if this region produced any matches.
    #[must_use]
    pub const fn has_matches(&self) -> bool {
        !self.matches.is_empty()
    }

    /// Return the total number of pattern matches across all rules.
    #[must_use]
    pub fn total_patterns(&self) -> usize {
        self.matches.iter().map(|m| m.patterns.len()).sum()
    }
}

impl std::fmt::Display for AsyncScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AsyncScanResult(region={}, rules={}, patterns={})",
            self.region_id,
            self.matches.len(),
            self.total_patterns()
        )
    }
}

/// Configuration for async scanning.
#[derive(Debug, Clone)]
pub struct AsyncScanConfig {
    /// Maximum number of concurrent scanning tasks.
    pub max_concurrency: usize,
    /// Skip regions larger than this size (0 = no limit).
    pub max_region_size: usize,
    /// Skip regions smaller than this size.
    pub min_region_size: usize,
}

impl Default for AsyncScanConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 4,
            max_region_size: 0,
            min_region_size: 1,
        }
    }
}

impl AsyncScanConfig {
    /// Create a new config with the given concurrency limit.
    #[must_use]
    pub fn with_concurrency(mut self, n: usize) -> Self {
        self.max_concurrency = n.max(1);
        self
    }

    /// Set the maximum region size to scan.
    #[must_use]
    pub const fn with_max_region_size(mut self, sz: usize) -> Self {
        self.max_region_size = sz;
        self
    }

    /// Set the minimum region size to scan.
    #[must_use]
    pub const fn with_min_region_size(mut self, sz: usize) -> Self {
        self.min_region_size = sz;
        self
    }

    /// Return `true` if a region of the given size should be scanned.
    #[must_use]
    pub const fn should_scan(&self, size: usize) -> bool {
        if size < self.min_region_size {
            return false;
        }
        if self.max_region_size > 0 && size > self.max_region_size {
            return false;
        }
        true
    }
}

// â"€â"€ External symbol / module support â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// An external symbol that can be passed to yara-x to influence rule conditions.
/// Corresponds to yara-x's external variables (e.g. `pe.*`, `elf.*`, `math.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalSymbol {
    /// Symbol name (e.g. `"pe.is_pe"`, `"file_size"`).
    pub name: String,
    /// Symbol value.
    pub value: ExternalSymbolValue,
}

/// The value of an external symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExternalSymbolValue {
    /// Boolean value.
    Bool(bool),
    /// Integer value.
    Int(i64),
    /// Float value.
    Float(f64),
    /// String value.
    Str(String),
}

impl ExternalSymbol {
    /// Create a boolean symbol.
    #[must_use]
    pub fn bool(name: impl Into<String>, value: bool) -> Self {
        Self {
            name: name.into(),
            value: ExternalSymbolValue::Bool(value),
        }
    }

    /// Create an integer symbol.
    #[must_use]
    pub fn int(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: name.into(),
            value: ExternalSymbolValue::Int(value),
        }
    }

    /// Create a float symbol.
    #[must_use]
    pub fn float(name: impl Into<String>, value: f64) -> Self {
        Self {
            name: name.into(),
            value: ExternalSymbolValue::Float(value),
        }
    }

    /// Create a string symbol.
    #[must_use]
    pub fn str(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: ExternalSymbolValue::Str(value.into()),
        }
    }
}

impl fmt::Display for ExternalSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            ExternalSymbolValue::Bool(b) => write!(f, "{}={}", self.name, b),
            ExternalSymbolValue::Int(i) => write!(f, "{}={}", self.name, i),
            ExternalSymbolValue::Float(fl) => write!(f, "{}={:.4}", self.name, fl),
            ExternalSymbolValue::Str(s) => write!(f, "{}=\"{}\"", self.name, s),
        }
    }
}

/// Built-in PE module external symbols derived from a PE byte slice.
#[derive(Debug, Clone, Default)]
pub struct PeModuleSymbols {
    /// Whether the data is a valid PE file.
    pub is_pe: bool,
    /// Whether the PE is a 64-bit executable.
    pub is_64bit: bool,
    /// File size in bytes.
    pub file_size: u64,
    /// Number of sections.
    pub number_of_sections: u32,
    /// Entry point RVA.
    pub entry_point: u64,
    /// Import DLL names found.
    pub import_dlls: Vec<String>,
    /// Exported function names found.
    pub exports: Vec<String>,
    /// Section names found.
    pub sections: Vec<String>,
}

impl PeModuleSymbols {
    /// Analyse `data` and populate PE module symbols.
    ///
    /// This is a lightweight parser that detects the MZ/PE headers and reads
    /// basic fields without full PE parsing.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut sym = Self {
            file_size: data.len() as u64,
            ..Self::default()
        };

        if data.len() < 64 {
            return sym;
        }
        // Check MZ magic.
        if data[0] != 0x4D || data[1] != 0x5A {
            return sym;
        }
        // Read e_lfanew (offset 0x3C).
        let e_lfanew =
            u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        if e_lfanew + 24 > data.len() {
            return sym;
        }
        // Check PE signature.
        if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return sym;
        }
        sym.is_pe = true;

        // Machine type (offset PE + 4).
        let machine = u16::from_le_bytes([data[e_lfanew + 4], data[e_lfanew + 5]]);
        sym.is_64bit = machine == 0x8664; // IMAGE_FILE_MACHINE_AMD64

        // Number of sections (offset PE + 6).
        sym.number_of_sections =
            u32::from(u16::from_le_bytes([data[e_lfanew + 6], data[e_lfanew + 7]]));

        // Entry point RVA (offset PE + 0x28).
        if e_lfanew + 0x2C <= data.len() {
            sym.entry_point = u64::from(u32::from_le_bytes([
                data[e_lfanew + 0x28],
                data[e_lfanew + 0x29],
                data[e_lfanew + 0x2A],
                data[e_lfanew + 0x2B],
            ]));
        }

        sym
    }

    /// Convert to a list of [`ExternalSymbol`]s usable with yara-x.
    #[must_use]
    pub fn to_external_symbols(&self) -> Vec<ExternalSymbol> {
        vec![
            ExternalSymbol::bool("pe.is_pe", self.is_pe),
            ExternalSymbol::bool("pe.is_64bit", self.is_64bit),
            ExternalSymbol::int(
                "file_size",
                i64::try_from(self.file_size).unwrap_or(i64::MAX),
            ),
            ExternalSymbol::int("pe.number_of_sections", i64::from(self.number_of_sections)),
            ExternalSymbol::int(
                "pe.entry_point",
                i64::try_from(self.entry_point).unwrap_or(i64::MAX),
            ),
            ExternalSymbol::int(
                "pe.number_of_imports",
                i64::try_from(self.import_dlls.len()).unwrap_or(i64::MAX),
            ),
            ExternalSymbol::int(
                "pe.number_of_exports",
                i64::try_from(self.exports.len()).unwrap_or(i64::MAX),
            ),
        ]
    }
}

/// ELF module symbols derived from an ELF byte slice.
#[derive(Debug, Clone, Default)]
pub struct ElfModuleSymbols {
    /// Whether the data is a valid ELF file.
    pub is_elf: bool,
    /// ELF class (1 = 32-bit, 2 = 64-bit).
    pub elf_class: u8,
    /// ELF machine type.
    pub machine: u16,
    /// Entry point virtual address.
    pub entry_point: u64,
    /// File size.
    pub file_size: u64,
    /// Number of program headers.
    pub program_header_count: u16,
    /// Number of section headers.
    pub section_header_count: u16,
}

impl ElfModuleSymbols {
    /// Analyse `data` and populate ELF module symbols.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut sym = Self {
            file_size: data.len() as u64,
            ..Self::default()
        };

        if data.len() < 52 {
            return sym;
        }
        // Check ELF magic: 0x7F 'E' 'L' 'F'
        if data[0] != 0x7F || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
            return sym;
        }
        sym.is_elf = true;
        sym.elf_class = data[4];

        let is_64 = sym.elf_class == 2;
        let le = data[5] == 1; // little-endian

        let read_u16 = |off: usize| -> u16 {
            if le {
                u16::from_le_bytes([data[off], data[off + 1]])
            } else {
                u16::from_be_bytes([data[off], data[off + 1]])
            }
        };
        let read_u64_le = |off: usize| -> u64 {
            u64::from_le_bytes([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
                data[off + 4],
                data[off + 5],
                data[off + 6],
                data[off + 7],
            ])
        };
        let read_u32_le = |off: usize| -> u32 {
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        };

        sym.machine = read_u16(18);

        if is_64 && data.len() >= 64 {
            sym.entry_point = read_u64_le(24);
            sym.program_header_count = read_u16(56);
            sym.section_header_count = read_u16(60);
        } else if !is_64 && data.len() >= 52 {
            sym.entry_point = u64::from(read_u32_le(24));
            sym.program_header_count = read_u16(44);
            sym.section_header_count = read_u16(48);
        }

        sym
    }

    /// Convert to a list of [`ExternalSymbol`]s.
    #[must_use]
    pub fn to_external_symbols(&self) -> Vec<ExternalSymbol> {
        vec![
            ExternalSymbol::bool("elf.is_elf", self.is_elf),
            ExternalSymbol::int("elf.class", i64::from(self.elf_class)),
            ExternalSymbol::int("elf.machine", i64::from(self.machine)),
            ExternalSymbol::int(
                "elf.entry_point",
                i64::try_from(self.entry_point).unwrap_or(i64::MAX),
            ),
            ExternalSymbol::int(
                "file_size",
                i64::try_from(self.file_size).unwrap_or(i64::MAX),
            ),
            ExternalSymbol::int(
                "elf.number_of_segments",
                i64::from(self.program_header_count),
            ),
            ExternalSymbol::int(
                "elf.number_of_sections",
                i64::from(self.section_header_count),
            ),
        ]
    }
}

/// Compute the Shannon entropy of a byte slice (math module stub).
///
/// Returns a float in `[0.0, 8.0]`.
#[must_use]
pub fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = usize_to_f64(data.len());
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = u64_to_f64(count) / n;
            entropy = p.mul_add(-p.log2(), entropy);
        }
    }
    entropy
}

/// Math module symbols derived from a byte slice.
#[derive(Debug, Clone)]
pub struct MathModuleSymbols {
    /// Shannon entropy of the entire buffer.
    pub entropy: f64,
    /// Shannon entropy of the first 256 bytes.
    pub entropy_head: f64,
    /// Mean byte value.
    pub mean: f64,
    /// Number of bytes in the buffer.
    pub size: usize,
}

impl MathModuleSymbols {
    /// Compute math module symbols for `data`.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        let entropy = compute_entropy(data);
        let head = &data[..data.len().min(256)];
        let entropy_head = compute_entropy(head);
        let mean = if data.is_empty() {
            0.0
        } else {
            data.iter().map(|&b| f64::from(b)).sum::<f64>() / usize_to_f64(data.len())
        };
        Self {
            entropy,
            entropy_head,
            mean,
            size: data.len(),
        }
    }

    /// Convert to a list of [`ExternalSymbol`]s.
    #[must_use]
    pub fn to_external_symbols(&self) -> Vec<ExternalSymbol> {
        vec![
            ExternalSymbol::float("math.entropy", self.entropy),
            ExternalSymbol::float("math.entropy_head", self.entropy_head),
            ExternalSymbol::float("math.mean", self.mean),
            ExternalSymbol::int("file_size", i64::try_from(self.size).unwrap_or(i64::MAX)),
        ]
    }
}

// â"€â"€ CompiledRuleCache â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A cache that maps a rule source hash to compiled [`yara_x::Rules`].
///
/// Avoids recompiling the same rule set on every invocation.
pub struct CompiledRuleCache {
    inner: std::sync::RwLock<HashMap<u64, Arc<yara_x::Rules>>>,
}

impl CompiledRuleCache {
    /// Create a new empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Compute a cheap 64-bit hash of the given rule sources.
    #[must_use]
    pub fn hash_sources(sources: &[&str]) -> u64 {
        use std::hash::{Hash, Hasher};
        struct FxHasher64(u64);
        impl FxHasher64 {
            const fn new() -> Self {
                Self(0xcbf2_9ce4_8422_2325)
            }
        }
        impl Hasher for FxHasher64 {
            fn write(&mut self, bytes: &[u8]) {
                for &b in bytes {
                    self.0 ^= u64::from(b);
                    self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
                }
            }
            fn finish(&self) -> u64 {
                self.0
            }
        }
        let mut h = FxHasher64::new();
        for src in sources {
            src.hash(&mut h);
            0u8.hash(&mut h);
        }
        h.finish()
    }

    /// Look up compiled rules by hash.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn get(&self, hash: u64) -> Option<Arc<yara_x::Rules>> {
        self.inner.read().unwrap().get(&hash).cloned()
    }

    /// Insert compiled rules into the cache.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn insert(&self, hash: u64, rules: Arc<yara_x::Rules>) {
        self.inner.write().unwrap().insert(hash, rules);
    }

    /// Clear the entire cache.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn clear(&self) {
        self.inner.write().unwrap().clear();
    }

    /// Return the number of cached rule sets.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    /// Return `true` if the cache is empty.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }

    /// Get or compile rules from the given sources, caching the result.
    ///
    /// If a compiled version already exists in the cache it is returned
    /// immediately; otherwise the sources are compiled and the result is stored.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError`] if compilation fails.
    pub fn get_or_compile(&self, sources: &[&str]) -> Result<Arc<yara_x::Rules>, YaraError> {
        let hash = Self::hash_sources(sources);
        if let Some(rules) = self.get(hash) {
            return Ok(rules);
        }
        // Compile.
        let mut compiler = yara_x::Compiler::new();
        for &src in sources {
            compiler
                .add_source(src)
                .map_err(|e| YaraError::CompileError(e.to_string()))?;
        }
        let rules = Arc::new(compiler.build());
        self.insert(hash, Arc::clone(&rules));
        Ok(rules)
    }
}

impl Default for CompiledRuleCache {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CompiledRuleCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CompiledRuleCache(len={})", self.len())
    }
}

// â"€â"€ Process memory scanning stub â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Description of a process memory region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRegion {
    /// Base address of the region.
    pub base: u64,
    /// Size in bytes.
    pub size: usize,
    /// Human-readable protection flags (e.g. `"r-x"`, `"rwx"`).
    pub protection: String,
    /// Module name if known.
    pub module: Option<String>,
}

impl ProcessRegion {
    /// Create a new process region descriptor.
    #[must_use]
    pub fn new(base: u64, size: usize, protection: impl Into<String>) -> Self {
        Self {
            base,
            size,
            protection: protection.into(),
            module: None,
        }
    }

    /// Attach a module name.
    #[must_use]
    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.module = Some(module.into());
        self
    }
}

impl fmt::Display for ProcessRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{:016x}..+0x{:x} [{}]{}",
            self.base,
            self.size,
            self.protection,
            self.module
                .as_deref()
                .map(|m| format!(" <{m}>"))
                .unwrap_or_default()
        )
    }
}

/// Result of scanning a single process region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionScanResult {
    /// The region that was scanned.
    pub region: ProcessRegion,
    /// Matches found in this region.
    pub matches: Vec<YaraMatch>,
}

impl RegionScanResult {
    /// Return `true` if any rules matched.
    #[must_use]
    pub const fn has_matches(&self) -> bool {
        !self.matches.is_empty()
    }
}

/// A multi-region process scanner that applies YARA rules to each region
/// independently and merges the results.
pub struct ProcessScanner {
    scanner: YaraEngineScanner,
}

impl ProcessScanner {
    /// Create a new process scanner from a compiled rule set.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError`] if compilation fails.
    pub fn new(ruleset: &mut YaraRuleSet) -> Result<Self, YaraError> {
        Ok(Self {
            scanner: YaraEngineScanner::new(ruleset)?,
        })
    }

    /// Scan a list of pre-read memory regions.
    ///
    /// Each `(region, data)` pair is scanned independently; regions that produce
    /// no matches are omitted from the result.
    #[must_use]
    pub fn scan_regions(&self, regions: &[(ProcessRegion, Vec<u8>)]) -> Vec<RegionScanResult> {
        regions
            .iter()
            .filter_map(|(region, data)| {
                let matches = self.scanner.scan_bytes(data);
                if matches.is_empty() {
                    None
                } else {
                    Some(RegionScanResult {
                        region: region.clone(),
                        matches,
                    })
                }
            })
            .collect()
    }

    /// Scan a single region of bytes.
    #[must_use]
    pub fn scan_region(&self, region: &ProcessRegion, data: &[u8]) -> RegionScanResult {
        RegionScanResult {
            region: region.clone(),
            matches: self.scanner.scan_bytes(data),
        }
    }

    /// Return a reference to the underlying engine scanner.
    #[must_use]
    pub const fn engine_scanner(&self) -> &YaraEngineScanner {
        &self.scanner
    }
}

// â"€â"€ Extended tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod extended_tests {
    use super::*;

    // â"€â"€ ExternalSymbol â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_external_symbol_bool_display() {
        let s = ExternalSymbol::bool("pe.is_pe", true);
        assert!(s.to_string().contains("pe.is_pe"));
        assert!(s.to_string().contains("true"));
    }

    #[test]
    fn test_external_symbol_int_display() {
        let s = ExternalSymbol::int("file_size", 1024);
        assert!(s.to_string().contains("file_size"));
        assert!(s.to_string().contains("1024"));
    }

    #[test]
    fn test_external_symbol_float_display() {
        let s = ExternalSymbol::float("math.entropy", 7.5);
        assert!(s.to_string().contains("math.entropy"));
    }

    #[test]
    fn test_external_symbol_str_display() {
        let s = ExternalSymbol::str("pe.name", "test.exe");
        assert!(s.to_string().contains("test.exe"));
    }

    // â"€â"€ PeModuleSymbols â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_pe_symbols_detects_mz() {
        let mut pe = vec![0x4D, 0x5A]; // MZ
        pe.extend_from_slice(&[0u8; 0x3C - 2]); // pad to offset 0x3C
        pe.push(0x40); // e_lfanew = 0x40
        pe.push(0x00);
        pe.push(0x00);
        pe.push(0x00);
        pe.extend_from_slice(&[0u8; 0x40 - 0x40]); // up to offset 0x40
        pe.extend_from_slice(b"PE\0\0"); // PE signature at 0x40
        pe.extend_from_slice(&[0x64, 0x86]); // machine = AMD64 â†' 0x8664 LE
        pe.extend_from_slice(&[0x03, 0x00]); // 3 sections
        pe.extend_from_slice(&[0u8; 0x28 - 10]); // pad to entry point field
        pe.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]); // entry point RVA = 0x1000
        let syms = PeModuleSymbols::from_bytes(&pe);
        assert!(syms.is_pe);
        assert_eq!(syms.file_size, pe.len() as u64);
    }

    #[test]
    fn test_pe_symbols_not_pe_for_elf() {
        let data = &[0x7F, b'E', b'L', b'F', 2, 1, 1, 0];
        let syms = PeModuleSymbols::from_bytes(data);
        assert!(!syms.is_pe);
    }

    #[test]
    fn test_pe_symbols_to_external_symbols_count() {
        let syms = PeModuleSymbols::default();
        let ext = syms.to_external_symbols();
        assert!(ext.len() >= 5);
    }

    // â"€â"€ ElfModuleSymbols â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_elf_symbols_detects_elf() {
        let mut data = vec![0x7F, b'E', b'L', b'F'];
        data.push(2); // 64-bit
        data.push(1); // little-endian
        data.push(1); // ELF version
        data.push(0); // OS/ABI
        data.extend_from_slice(&[0u8; 8]); // padding
        data.extend_from_slice(&[2, 0]); // type = ET_EXEC
        data.extend_from_slice(&[0x3E, 0x00]); // machine = x86-64
        data.extend_from_slice(&[1, 0, 0, 0]); // ELF version
        data.extend_from_slice(&[0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // entry point
        data.extend_from_slice(&[0u8; 4 + 4 + 2 + 2 + 2]); // phoff, shoff, flags, ehsize, phentsize
        data.extend_from_slice(&[3, 0]); // phnum = 3
        data.extend_from_slice(&[0, 0, 4, 0]); // shentsize, shnum
        let syms = ElfModuleSymbols::from_bytes(&data);
        assert!(syms.is_elf);
        assert_eq!(syms.elf_class, 2);
        assert_eq!(syms.machine, 0x003E);
    }

    #[test]
    fn test_elf_symbols_not_elf() {
        let data = &[0x4D, 0x5A, 0, 0];
        let syms = ElfModuleSymbols::from_bytes(data);
        assert!(!syms.is_elf);
    }

    #[test]
    fn test_elf_symbols_to_external_symbols() {
        let syms = ElfModuleSymbols::from_bytes(&[0x7F, b'E', b'L', b'F']);
        let ext = syms.to_external_symbols();
        assert!(ext.iter().any(|s| s.name.contains("elf.is_elf")));
    }

    // â"€â"€ MathModuleSymbols â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_math_entropy_all_zeros() {
        let data = vec![0u8; 256];
        let syms = MathModuleSymbols::from_bytes(&data);
        assert!((syms.entropy - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_math_entropy_uniform() {
        let data: Vec<u8> = (0u8..=255).collect();
        let syms = MathModuleSymbols::from_bytes(&data);
        assert!((syms.entropy - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_math_mean() {
        let data = vec![0u8, 255];
        let syms = MathModuleSymbols::from_bytes(&data);
        assert!((syms.mean - 127.5).abs() < 0.01);
    }

    #[test]
    fn test_math_entropy_empty() {
        let syms = MathModuleSymbols::from_bytes(&[]);
        assert!((syms.entropy - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_compute_entropy_single_value() {
        let data = vec![0xAAu8; 1000];
        let e = compute_entropy(&data);
        assert!((e - 0.0).abs() < 1e-9);
    }

    // â"€â"€ CompiledRuleCache â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_cache_empty_on_creation() {
        let cache = CompiledRuleCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_get_or_compile() {
        let cache = CompiledRuleCache::new();
        let sources = &["rule A { condition: true }"];
        let r1 = cache.get_or_compile(sources).unwrap();
        let r2 = cache.get_or_compile(sources).unwrap();
        assert_eq!(cache.len(), 1);
        // Both should point to the same compiled rules.
        assert!(Arc::ptr_eq(&r1, &r2));
    }

    #[test]
    fn test_cache_different_sources_different_entries() {
        let cache = CompiledRuleCache::new();
        cache
            .get_or_compile(&["rule A { condition: true }"])
            .unwrap();
        cache
            .get_or_compile(&["rule B { condition: false }"])
            .unwrap();
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_cache_clear() {
        let cache = CompiledRuleCache::new();
        cache
            .get_or_compile(&["rule A { condition: true }"])
            .unwrap();
        assert!(!cache.is_empty());
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_hash_deterministic() {
        let sources = &["rule A { condition: true }", "rule B { condition: false }"];
        let h1 = CompiledRuleCache::hash_sources(sources);
        let h2 = CompiledRuleCache::hash_sources(sources);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_cache_hash_different_for_different_sources() {
        let h1 = CompiledRuleCache::hash_sources(&["rule A { condition: true }"]);
        let h2 = CompiledRuleCache::hash_sources(&["rule B { condition: true }"]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_cache_debug() {
        let cache = CompiledRuleCache::new();
        let s = format!("{cache:?}");
        assert!(s.contains("CompiledRuleCache"));
    }

    // â"€â"€ AsyncScanConfig â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_async_config_default() {
        let cfg = AsyncScanConfig::default();
        assert_eq!(cfg.max_concurrency, 4);
        assert_eq!(cfg.min_region_size, 1);
    }

    #[test]
    fn test_async_config_should_scan() {
        let cfg = AsyncScanConfig::default()
            .with_min_region_size(10)
            .with_max_region_size(1000);
        assert!(!cfg.should_scan(5));
        assert!(cfg.should_scan(500));
        assert!(!cfg.should_scan(2000));
    }

    #[test]
    fn test_async_scan_result_has_matches() {
        let r = AsyncScanResult::new("region1", vec![]);
        assert!(!r.has_matches());
    }

    #[test]
    fn test_async_scan_result_display() {
        let r = AsyncScanResult::new("test_region", vec![]);
        let s = r.to_string();
        assert!(s.contains("test_region"));
    }

    // â"€â"€ ProcessRegion / ProcessScanner â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_process_region_display() {
        let r = ProcessRegion::new(0x1000, 0x1000, "r-x").with_module("ntdll.dll");
        let s = r.to_string();
        assert!(s.contains("1000"));
        assert!(s.contains("r-x"));
        assert!(s.contains("ntdll.dll"));
    }

    #[test]
    fn test_process_region_no_module() {
        let r = ProcessRegion::new(0x2000, 0x500, "rw-");
        let s = r.to_string();
        assert!(!s.contains('<'));
    }

    #[test]
    fn test_process_scanner_scan_regions_empty() {
        let mut rs = YaraRuleSet::new();
        rs.add_rule("rule AlwaysTrue { condition: true }").unwrap();
        let scanner = ProcessScanner::new(&mut rs).unwrap();
        // Empty data returns no matches because yara-x needs some data to match.
        let regions: Vec<(ProcessRegion, Vec<u8>)> = vec![];
        let results = scanner.scan_regions(&regions);
        assert!(results.is_empty());
    }

    #[test]
    fn test_process_scanner_scan_region_with_match() {
        let mut rs = YaraRuleSet::new();
        rs.add_rule(
            r"rule FindMZ {
            strings: $mz = { 4D 5A }
            condition: $mz at 0
        }",
        )
        .unwrap();
        let scanner = ProcessScanner::new(&mut rs).unwrap();
        let region = ProcessRegion::new(0x1000, 8, "r--");
        let data = vec![0x4D, 0x5A, 0, 0, 0, 0, 0, 0];
        let result = scanner.scan_region(&region, &data);
        assert!(result.has_matches());
        assert_eq!(result.matches[0].rule_name, "FindMZ");
    }

    #[test]
    fn test_process_scanner_filters_empty_regions() {
        let mut rs = YaraRuleSet::new();
        rs.add_rule(
            r"rule FindMZ {
            strings: $mz = { 4D 5A }
            condition: $mz at 0
        }",
        )
        .unwrap();
        let scanner = ProcessScanner::new(&mut rs).unwrap();
        let pe_data = vec![0x4D, 0x5A, 0, 0, 0, 0, 0, 0];
        let no_match_data = vec![0x00u8; 8];
        let regions = vec![
            (ProcessRegion::new(0x1000, 8, "r--"), pe_data),
            (ProcessRegion::new(0x2000, 8, "r--"), no_match_data),
        ];
        let results = scanner.scan_regions(&regions);
        // Only the first region should appear (the second has no matches).
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].region.base, 0x1000);
    }

    // â"€â"€ RegionScanResult â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_region_scan_result_has_matches_false() {
        let r = RegionScanResult {
            region: ProcessRegion::new(0x1000, 100, "r--"),
            matches: vec![],
        };
        assert!(!r.has_matches());
    }
}

