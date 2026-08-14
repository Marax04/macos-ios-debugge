// rustre-yara-rules/src/rule_compiler.rs
//! Pure-Rust YARA rule parser and compiler.
//!
//! Parses YARA rule syntax and compiles rules to an IR that can be executed
//! against byte slices without any external YARA library dependency.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum CompilerError {
    Parse(String),
    UnknownIdentifier(String),
    InvalidCondition(String),
    InvalidModifier(String),
    InvalidHex(String),
    InvalidRegex(String),
    EmptyRule,
}

impl std::fmt::Display for CompilerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(s) => write!(f, "parse error: {s}"),
            Self::UnknownIdentifier(s) => write!(f, "unknown identifier: {s}"),
            Self::InvalidCondition(s) => write!(f, "invalid condition: {s}"),
            Self::InvalidModifier(s) => write!(f, "invalid modifier: {s}"),
            Self::InvalidHex(s) => write!(f, "invalid hex: {s}"),
            Self::InvalidRegex(s) => write!(f, "invalid regex: {s}"),
            Self::EmptyRule => write!(f, "empty rule"),
        }
    }
}

pub type CompilerResult<T> = Result<T, CompilerError>;

// ─── String modifiers ─────────────────────────────────────────────────────────

/// Bit positions inside [`StringModifiers::bits`].
const MOD_NOCASE: u8 = 1 << 0;
const MOD_WIDE: u8 = 1 << 1;
const MOD_ASCII: u8 = 1 << 2;
const MOD_FULLWORD: u8 = 1 << 3;
const MOD_XOR: u8 = 1 << 4;
const MOD_BASE64: u8 = 1 << 5;

/// Modifiers that alter how a string pattern is matched.
///
/// Stored as a packed bitfield (one bit per modifier) so the struct stays small
/// and avoids `clippy::struct_excessive_bools`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringModifiers {
    bits: u8,
}

impl StringModifiers {
    const fn flag(self, mask: u8) -> bool {
        (self.bits & mask) != 0
    }
    const fn set_flag(&mut self, mask: u8, v: bool) {
        if v { self.bits |= mask; } else { self.bits &= !mask; }
    }

    #[must_use] pub const fn nocase(self) -> bool { self.flag(MOD_NOCASE) }
    #[must_use] pub const fn wide(self) -> bool { self.flag(MOD_WIDE) }
    #[must_use] pub const fn ascii(self) -> bool { self.flag(MOD_ASCII) }
    #[must_use] pub const fn fullword(self) -> bool { self.flag(MOD_FULLWORD) }
    #[must_use] pub const fn xor(self) -> bool { self.flag(MOD_XOR) }
    #[must_use] pub const fn base64(self) -> bool { self.flag(MOD_BASE64) }

    pub const fn set_nocase(&mut self, v: bool) { self.set_flag(MOD_NOCASE, v); }
    pub const fn set_wide(&mut self, v: bool) { self.set_flag(MOD_WIDE, v); }
    pub const fn set_ascii(&mut self, v: bool) { self.set_flag(MOD_ASCII, v); }
    pub const fn set_fullword(&mut self, v: bool) { self.set_flag(MOD_FULLWORD, v); }
    pub const fn set_xor(&mut self, v: bool) { self.set_flag(MOD_XOR, v); }
    pub const fn set_base64(&mut self, v: bool) { self.set_flag(MOD_BASE64, v); }

    /// Parse a whitespace-separated list of YARA string modifiers.
    ///
    /// # Errors
    /// Returns [`CompilerError::InvalidModifier`] if a token is not a recognised
    /// modifier name.
    pub fn parse(s: &str) -> CompilerResult<Self> {
        let mut m = Self::default();
        m.set_ascii(true);
        for token in s.split_whitespace() {
            match token {
                "nocase" => m.set_nocase(true),
                "wide" => m.set_wide(true),
                "ascii" => m.set_ascii(true),
                "fullword" => m.set_fullword(true),
                "xor" => m.set_xor(true),
                "base64" => m.set_base64(true),
                other if !other.is_empty() => {
                    return Err(CompilerError::InvalidModifier(other.to_string()));
                }
                _ => {}
            }
        }
        Ok(m)
    }
}

// ─── Pattern kinds ────────────────────────────────────────────────────────────

/// A single compiled pattern in a YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternKind {
    /// Literal byte sequence (parsed from text or hex string).
    Bytes(Vec<u8>),
    /// Hex pattern with optional wildcards (`None` = any byte).
    Hex(Vec<Option<u8>>),
    /// Simple regex (handled by our mini engine).
    Regex(String),
}

/// A named, compiled pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPattern {
    pub id: String,
    pub kind: PatternKind,
    pub modifiers: StringModifiers,
}

impl CompiledPattern {
    /// Find all `(offset, matched_bytes)` pairs in `data`.
    #[must_use] 
    pub fn find_all(&self, data: &[u8]) -> Vec<(u64, Vec<u8>)> {
        match &self.kind {
            PatternKind::Bytes(needle) => {
                let mut hits = Vec::new();
                if self.modifiers.nocase() {
                    hits.extend(find_nocase(data, needle));
                } else {
                    hits.extend(find_literal(data, needle));
                }
                if self.modifiers.wide() {
                    let wide = to_wide_bytes(needle);
                    if self.modifiers.nocase() {
                        hits.extend(find_nocase(data, &wide));
                    } else {
                        hits.extend(find_literal(data, &wide));
                    }
                }
                if self.modifiers.fullword() {
                    hits.retain(|(off, matched)| {
                        is_fullword(data, usize::try_from(*off).unwrap_or(usize::MAX), matched.len())
                    });
                }
                if self.modifiers.xor() {
                    for key in 1u8..=255u8 {
                        let xored: Vec<u8> = needle.iter().map(|&b| b ^ key).collect();
                        let extra = if self.modifiers.nocase() {
                            find_nocase(data, &xored)
                        } else {
                            find_literal(data, &xored)
                        };
                        hits.extend(extra);
                    }
                }
                hits
            }
            PatternKind::Hex(pattern) => find_hex(data, pattern),
            PatternKind::Regex(re) => find_regex(data, re),
        }
    }
}

// ─── Condition AST ────────────────────────────────────────────────────────────

/// Condition expression AST node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    True,
    False,
    /// Any of the named strings matched.
    AnyOf(Vec<String>),
    /// All of the named strings matched.
    AllOf(Vec<String>),
    /// A specific named string matched.
    StringMatch(String),
    /// File size comparison: `filesize < N`.
    FileSize {
        op: OrdOp,
        value: u64,
    },
    /// NOT combinator.
    Not(Box<Self>),
    /// AND combinator.
    And(Box<Self>, Box<Self>),
    /// OR combinator.
    Or(Box<Self>, Box<Self>),
    /// At least N of the listed strings matched.
    AtLeast {
        n: u32,
        ids: Vec<String>,
    },
    /// String matched at a specific offset.
    AtOffset {
        id: String,
        offset: u64,
    },
    /// PE magic check (uint16(0) == 0x5A4D).
    PeMagic,
    /// ELF magic check.
    ElfMagic,
    /// uint16 read at offset equals value.
    Uint16At {
        offset: usize,
        value: u16,
    },
    /// uint32 read at offset equals value.
    Uint32At {
        offset: usize,
        value: u32,
    },
    /// String count comparison: #id >= n.
    Count {
        id: String,
        op: OrdOp,
        n: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrdOp {
    Lt,
    Le,
    Eq,
    Ge,
    Gt,
}

impl OrdOp {
    #[must_use] 
    pub const fn eval(&self, lhs: u64, rhs: u64) -> bool {
        match self {
            Self::Lt => lhs < rhs,
            Self::Le => lhs <= rhs,
            Self::Eq => lhs == rhs,
            Self::Ge => lhs >= rhs,
            Self::Gt => lhs > rhs,
        }
    }
}

impl Condition {
    /// Evaluate the condition against match results.
    #[must_use] 
    pub fn evaluate(&self, hits: &HashMap<String, Vec<(u64, Vec<u8>)>>, data: &[u8]) -> bool {
        let data_len = data.len() as u64;
        match self {
            Self::True => true,
            Self::False => false,

            Self::AnyOf(ids) => ids
                .iter()
                .any(|id| hits.get(id).is_some_and(|v| !v.is_empty())),

            Self::AllOf(ids) => ids
                .iter()
                .all(|id| hits.get(id).is_some_and(|v| !v.is_empty())),

            Self::StringMatch(id) => hits.get(id).is_some_and(|v| !v.is_empty()),

            Self::FileSize { op, value } => op.eval(data_len, *value),

            Self::Not(inner) => !inner.evaluate(hits, data),

            Self::And(a, b) => a.evaluate(hits, data) && b.evaluate(hits, data),

            Self::Or(a, b) => a.evaluate(hits, data) || b.evaluate(hits, data),

            Self::AtLeast { n, ids } => {
                let count = crate::casts::usize_to_u32_sat(
                    ids.iter()
                        .filter(|id| hits.get(*id).is_some_and(|v| !v.is_empty()))
                        .count(),
                );
                count >= *n
            }

            Self::AtOffset { id, offset } => hits
                .get(id)
                .is_some_and(|v| v.iter().any(|(off, _)| off == offset)),

            Self::PeMagic => data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A,

            Self::ElfMagic => {
                data.len() >= 4
                    && data[0] == 0x7F
                    && data[1] == 0x45
                    && data[2] == 0x4C
                    && data[3] == 0x46
            }

            Self::Uint16At { offset, value } => {
                let off = *offset;
                if off + 2 > data.len() {
                    return false;
                }
                let v = u16::from_le_bytes([data[off], data[off + 1]]);
                v == *value
            }

            Self::Uint32At { offset, value } => {
                let off = *offset;
                if off + 4 > data.len() {
                    return false;
                }
                let v =
                    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
                v == *value
            }

            Self::Count { id, op, n } => {
                let count = crate::casts::usize_to_u32_sat(hits.get(id).map_or(0, std::vec::Vec::len));
                op.eval(u64::from(count), u64::from(*n))
            }
        }
    }
}

// ─── YaraRule ─────────────────────────────────────────────────────────────────

/// A fully parsed and compiled YARA rule ready for execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    pub patterns: Vec<CompiledPattern>,
    pub condition: Condition,
}

impl YaraRule {
    /// Execute this rule against `data`.
    /// Returns a [`RuleMatch`] if the condition evaluates to `true`.
    #[must_use] 
    pub fn execute(&self, data: &[u8]) -> Option<RuleMatch> {
        // Collect all pattern hits
        let mut hits: HashMap<String, Vec<(u64, Vec<u8>)>> = HashMap::new();
        for pat in &self.patterns {
            let found = pat.find_all(data);
            hits.insert(pat.id.clone(), found);
        }

        if self.condition.evaluate(&hits, data) {
            let mut string_hits = Vec::new();
            for (id, offsets) in &hits {
                if !offsets.is_empty() {
                    string_hits.push(StringHit {
                        id: id.clone(),
                        offsets: offsets.iter().map(|(o, _)| *o).collect(),
                        data: offsets.iter().map(|(_, d)| d.clone()).collect(),
                    });
                }
            }
            Some(RuleMatch {
                rule_name: self.name.clone(),
                namespace: self.namespace.clone(),
                tags: self.tags.clone(),
                meta: self.meta.clone(),
                string_hits,
            })
        } else {
            None
        }
    }
}

/// A per-pattern hit inside a [`RuleMatch`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringHit {
    pub id: String,
    pub offsets: Vec<u64>,
    pub data: Vec<Vec<u8>>,
}

/// Result of a successful rule execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    pub string_hits: Vec<StringHit>,
}

impl RuleMatch {
    /// Severity from the `meta` block, defaulting to `"medium"`.
    #[must_use] 
    pub fn severity(&self) -> &str {
        self.meta
            .get("severity")
            .map_or("medium", std::string::String::as_str)
    }

    /// Total count of all string hits across all patterns.
    #[must_use] 
    pub fn total_hits(&self) -> usize {
        self.string_hits.iter().map(|h| h.offsets.len()).sum()
    }
}

// ─── Compiler ─────────────────────────────────────────────────────────────────

/// Parses raw YARA rule text and compiles it to [`YaraRule`].
pub struct RuleCompiler;

impl RuleCompiler {
    /// Parse a single YARA rule from text.
    ///
    /// # Errors
    /// Returns a [`CompilerError`] if the input is empty, malformed, or
    /// references unknown strings/modifiers.
    pub fn compile(text: &str) -> CompilerResult<YaraRule> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(CompilerError::EmptyRule);
        }

        // Extract rule name and tags from the header line
        let (name, namespace, tags, body_start) = parse_rule_header(trimmed)?;
        let body = &trimmed[body_start..];

        // Split into meta / strings / condition sections
        let (meta, patterns, condition_text) = split_sections(body);
        let compiled_patterns = parse_strings_section(&patterns)?;
        let condition = parse_condition(&condition_text, &compiled_patterns)?;

        Ok(YaraRule {
            name,
            namespace,
            tags,
            meta,
            patterns: compiled_patterns,
            condition,
        })
    }

    /// Parse and compile multiple rules from a text blob.
    #[must_use] 
    pub fn compile_all(text: &str) -> Vec<CompilerResult<YaraRule>> {
        split_rules(text)
            .into_iter()
            .map(Self::compile)
            .collect()
    }

    /// Parse all rules, silently ignoring errors.
    #[must_use] 
    pub fn compile_best_effort(text: &str) -> Vec<YaraRule> {
        Self::compile_all(text).into_iter().flatten().collect()
    }
}

// ─── Rule executor ────────────────────────────────────────────────────────────

/// Holds a compiled set of rules and can scan byte slices against them.
pub struct RuleExecutor {
    rules: Vec<YaraRule>,
}

impl RuleExecutor {
    #[must_use] 
    pub const fn new(rules: Vec<YaraRule>) -> Self {
        Self { rules }
    }

    /// Scan `data` and return all matching rules.
    #[must_use] 
    pub fn scan(&self, data: &[u8]) -> Vec<RuleMatch> {
        self.rules.iter().filter_map(|r| r.execute(data)).collect()
    }

    /// Scan and return only matches at or above the given severity.
    #[must_use] 
    pub fn scan_severity(&self, data: &[u8], min_severity: &str) -> Vec<RuleMatch> {
        let min_score = severity_to_score(min_severity);
        self.scan(data)
            .into_iter()
            .filter(|m| severity_to_score(m.severity()) >= min_score)
            .collect()
    }

    /// Number of loaded rules.
    #[must_use] 
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Compile from text and create an executor.
    #[must_use] 
    pub fn from_text(text: &str) -> Self {
        Self::new(RuleCompiler::compile_best_effort(text))
    }
}

fn severity_to_score(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

// ─── Parsing helpers ──────────────────────────────────────────────────────────

fn split_rules(text: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut depth = 0usize;
    let mut start: Option<usize> = None;

    for (i, ch) in text.char_indices() {
        if ch == '{' {
            if depth == 0 && start.is_none() {
                // find the beginning of this rule
                let before = &text[..i];
                let rule_start = before.rfind('\n').map_or(0, |p| p + 1);
                start = Some(rule_start);
            }
            depth += 1;
        } else if ch == '}' && depth > 0 {
            depth -= 1;
            if depth == 0
                && let Some(s) = start.take() {
                    result.push(&text[s..=i]);
                }
        }
    }
    result
}

fn parse_rule_header(text: &str) -> CompilerResult<(String, String, Vec<String>, usize)> {
    // Find first line with "rule "
    let line_end = text.find('{').unwrap_or(text.len());
    let header = &text[..line_end];

    let mut name = String::new();
    let mut namespace = "default".to_string();
    let mut tags = Vec::new();

    // namespace:RuleName
    let rule_token = header
        .split_whitespace()
        .skip_while(|&w| w != "rule" && w != "private")
        .nth(if header.contains("private rule") {
            2
        } else {
            1
        })
        .unwrap_or("")
        .trim_end_matches(':');

    if let Some(colon) = rule_token.find(':') {
        namespace = rule_token[..colon].to_string();
        name.push_str(&rule_token[colon + 1..]);
    } else {
        name.push_str(rule_token);
    }

    // Tags after the rule name: "rule Foo : tag1 tag2 {"
    if let Some(colon_pos) = header.rfind(':') {
        // ensure this colon is after the rule name (not in namespace prefix)
        if header[colon_pos + 1..]
            .trim_start()
            .starts_with(|c: char| c.is_alphabetic())
        {
            for tok in header[colon_pos + 1..].split_whitespace() {
                tags.push(tok.to_string());
            }
        }
    }

    let body_start = text
        .find('{')
        .ok_or_else(|| CompilerError::Parse("no opening brace".to_string()))?;
    Ok((name, namespace, tags, body_start + 1))
}

fn split_sections(body: &str) -> (HashMap<String, String>, String, String) {
    let mut meta = HashMap::new();
    let mut strings = String::new();
    let mut condition = String::new();

    let mut current_section = "";
    for line in body.lines() {
        let trimmed = line.trim();
        match trimmed {
            "meta:" => {
                current_section = "meta";
                continue;
            }
            "strings:" => {
                current_section = "strings";
                continue;
            }
            "condition:" => {
                current_section = "condition";
                continue;
            }
            "}" => continue,
            _ => {}
        }
        match current_section {
            "meta" => {
                if let Some(eq) = trimmed.find('=') {
                    let key = trimmed[..eq].trim().to_string();
                    let val = trimmed[eq + 1..].trim().trim_matches('"').to_string();
                    meta.insert(key, val);
                }
            }
            "strings" => {
                strings.push_str(trimmed);
                strings.push('\n');
            }
            "condition" => {
                condition.push_str(trimmed);
                condition.push(' ');
            }
            _ => {}
        }
    }

    (meta, strings, condition.trim().to_string())
}

fn parse_strings_section(text: &str) -> CompilerResult<Vec<CompiledPattern>> {
    let mut patterns = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('$') {
            continue;
        }
        // $id = "text" [modifiers]
        // $id = { hex } [modifiers]
        // $id = /regex/ [modifiers]
        if let Some(eq_pos) = trimmed.find('=') {
            let id = trimmed[..eq_pos].trim().to_string();
            let rest = trimmed[eq_pos + 1..].trim();

            let (kind, modifier_str) = if let Some(__stripped) = rest.strip_prefix('"') {
                // text string
                if let Some(end) = __stripped.find('"') {
                    let literal = &rest[1..=end];
                    let mods_str = &rest[end + 2..].trim();
                    (PatternKind::Bytes(literal.as_bytes().to_vec()), *mods_str)
                } else {
                    continue;
                }
            } else if rest.starts_with('{') {
                // hex string
                if let Some(end) = rest.find('}') {
                    let hex_content = &rest[1..end];
                    let bytes = parse_hex_string(hex_content)?;
                    let mods_str = &rest[end + 1..].trim();
                    (PatternKind::Hex(bytes), *mods_str)
                } else {
                    continue;
                }
            } else if let Some(__stripped) = rest.strip_prefix('/') {
                // regex
                if let Some(end) = __stripped.find('/') {
                    let regex_content = &rest[1..=end];
                    let mods_str = &rest[end + 2..].trim();
                    (PatternKind::Regex(regex_content.to_string()), *mods_str)
                } else {
                    continue;
                }
            } else {
                continue;
            };

            let modifiers = StringModifiers::parse(modifier_str)?;
            patterns.push(CompiledPattern {
                id,
                kind,
                modifiers,
            });
        }
    }
    Ok(patterns)
}

fn parse_hex_string(s: &str) -> CompilerResult<Vec<Option<u8>>> {
    let mut result = Vec::new();
    let tokens: Vec<&str> = s.split_whitespace().collect();
    for tok in tokens {
        if tok == "??" || tok == "?" {
            result.push(None);
        } else if tok.contains('?') {
            // Nibble-level wildcard: e.g. "A?" or "?B"
            let hi = tok.chars().next().unwrap_or('0');
            let lo = tok.chars().nth(1).unwrap_or('0');
            if hi == '?' && lo == '?' {
                result.push(None);
            } else {
                // partial wildcard — treat as full byte for simplicity
                let hex = format!(
                    "{}{}",
                    if hi == '?' { '0' } else { hi },
                    if lo == '?' { '0' } else { lo }
                );
                let byte = u8::from_str_radix(&hex, 16)
                    .map_err(|_| CompilerError::InvalidHex(tok.to_string()))?;
                result.push(Some(byte));
            }
        } else if tok.len() == 2 {
            let byte = u8::from_str_radix(tok, 16)
                .map_err(|_| CompilerError::InvalidHex(tok.to_string()))?;
            result.push(Some(byte));
        }
        // skip group separators like `[1-4]` for now
    }
    Ok(result)
}

fn parse_condition(text: &str, patterns: &[CompiledPattern]) -> CompilerResult<Condition> {
    parse_condition_inner(text, patterns, 0)
}

fn parse_condition_inner(
    text: &str,
    patterns: &[CompiledPattern],
    depth: u32,
) -> CompilerResult<Condition> {
    const MAX_DEPTH: u32 = 64;
    if depth > MAX_DEPTH {
        return Err(CompilerError::InvalidCondition(
            "condition nesting depth exceeded maximum (64)".to_string(),
        ));
    }
    let t = text.trim().to_lowercase();

    // Short-circuit common cases first
    if t == "any of them" {
        let ids: Vec<String> = patterns.iter().map(|p| p.id.clone()).collect();
        return Ok(Condition::AnyOf(ids));
    }
    if t == "all of them" {
        let ids: Vec<String> = patterns.iter().map(|p| p.id.clone()).collect();
        return Ok(Condition::AllOf(ids));
    }
    if t == "none of them" {
        let ids: Vec<String> = patterns.iter().map(|p| p.id.clone()).collect();
        let any = Condition::AnyOf(ids);
        return Ok(Condition::Not(Box::new(any)));
    }
    if t == "true" {
        return Ok(Condition::True);
    }
    if t == "false" {
        return Ok(Condition::False);
    }

    // PE/ELF magic helpers
    if t.contains("uint16(0) == 0x5a4d") || t.contains("uint16(0)==0x5a4d") {
        // Full condition may include AND/OR — for now return PeMagic
        // (in a full compiler we would recurse into sub-expressions)
        return Ok(Condition::PeMagic);
    }
    if t.contains("uint32(0) == 0x464c457f") {
        return Ok(Condition::ElfMagic);
    }

    // "N of them"
    if let Some(n) = parse_n_of_them(text, patterns) {
        return Ok(n);
    }

    // "2 of ($s1, $s2, ...)"
    if let Some(c) = parse_n_of_set(text) {
        return Ok(c);
    }

    // filesize comparisons
    if let Some(c) = parse_filesize(text) {
        return Ok(c);
    }

    // Boolean NOT
    if let Some(inner) = t.strip_prefix("not ") {
        let c = parse_condition_inner(inner, patterns, depth + 1)?;
        return Ok(Condition::Not(Box::new(c)));
    }

    // AND / OR (simple two-term, left-associative, ignoring parentheses)
    if let Some(pos) = find_top_level_op(text, " and ") {
        let left = parse_condition_inner(&text[..pos], patterns, depth + 1)?;
        let right = parse_condition_inner(&text[pos + 5..], patterns, depth + 1)?;
        return Ok(Condition::And(Box::new(left), Box::new(right)));
    }
    if let Some(pos) = find_top_level_op(text, " or ") {
        let left = parse_condition_inner(&text[..pos], patterns, depth + 1)?;
        let right = parse_condition_inner(&text[pos + 4..], patterns, depth + 1)?;
        return Ok(Condition::Or(Box::new(left), Box::new(right)));
    }

    // Named string reference: $identifier
    let t_orig = text.trim();
    if t_orig.starts_with('$') {
        let id = t_orig
            .split_whitespace()
            .next()
            .unwrap_or(t_orig)
            .to_string();
        return Ok(Condition::StringMatch(id));
    }

    // Fallback: if any patterns exist, return AnyOf
    if !patterns.is_empty() {
        let ids: Vec<String> = patterns.iter().map(|p| p.id.clone()).collect();
        return Ok(Condition::AnyOf(ids));
    }

    Ok(Condition::True)
}

fn parse_n_of_them(text: &str, patterns: &[CompiledPattern]) -> Option<Condition> {
    let t = text.trim().to_lowercase();
    // "N of them"
    let mut parts = t.split_whitespace();
    let n_str = parts.next()?;
    let n: u32 = n_str.parse().ok()?;
    let of = parts.next()?;
    let them = parts.next()?;
    if of != "of" || them != "them" {
        return None;
    }
    let ids: Vec<String> = patterns.iter().map(|p| p.id.clone()).collect();
    Some(Condition::AtLeast { n, ids })
}

fn parse_n_of_set(text: &str) -> Option<Condition> {
    // "2 of ($s1, $s2)"
    let t = text.trim();
    let mut iter = t.splitn(2, " of (");
    let n_str = iter.next()?.trim();
    let rest = iter.next()?.trim();
    let n: u32 = n_str.parse().ok()?;
    let ids_part = rest.trim_end_matches(')');
    let ids: Vec<String> = ids_part
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| s.starts_with('$'))
        .collect();
    if ids.is_empty() {
        return None;
    }
    Some(Condition::AtLeast { n, ids })
}

fn parse_filesize(text: &str) -> Option<Condition> {
    let t = text.trim().to_lowercase();
    if !t.starts_with("filesize") {
        return None;
    }
    let rest = t["filesize".len()..].trim();
    let (op, num_str) = if let Some(r) = rest.strip_prefix("< ") {
        (OrdOp::Lt, r.trim())
    } else if let Some(r) = rest.strip_prefix("<= ") {
        (OrdOp::Le, r.trim())
    } else if let Some(r) = rest.strip_prefix("== ") {
        (OrdOp::Eq, r.trim())
    } else if let Some(r) = rest.strip_prefix(">= ") {
        (OrdOp::Ge, r.trim())
    } else if let Some(r) = rest.strip_prefix("> ") {
        (OrdOp::Gt, r.trim())
    } else {
        return None;
    };

    let num: u64 = if let Some(stripped) = num_str.strip_suffix("mb") {
        stripped.trim().parse::<u64>().ok()?.saturating_mul(1024 * 1024)
    } else if let Some(stripped) = num_str.strip_suffix("kb") {
        stripped.trim().parse::<u64>().ok()?.saturating_mul(1024)
    } else if let Some(__stripped) = num_str.strip_prefix("0x") {
        u64::from_str_radix(__stripped, 16).ok()?
    } else {
        num_str.parse().ok()?
    };

    Some(Condition::FileSize { op, value: num })
}

fn find_top_level_op(text: &str, op: &str) -> Option<usize> {
    let lower = text.to_lowercase();
    let mut depth = 0usize;
    let bytes = lower.as_bytes();
    let op_bytes = op.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'(' {
            depth += 1;
        } else if bytes[i] == b')' && depth > 0 {
            depth -= 1;
        }
        if depth == 0 && bytes[i..].starts_with(op_bytes) {
            return Some(i);
        }
    }
    None
}

// ─── Low-level matchers ───────────────────────────────────────────────────────

fn find_literal(data: &[u8], needle: &[u8]) -> Vec<(u64, Vec<u8>)> {
    if needle.is_empty() || data.len() < needle.len() {
        return Vec::new();
    }
    let mut results = Vec::new();
    for i in 0..=(data.len() - needle.len()) {
        if &data[i..i + needle.len()] == needle {
            results.push((i as u64, needle.to_vec()));
        }
    }
    results
}

fn find_nocase(data: &[u8], needle: &[u8]) -> Vec<(u64, Vec<u8>)> {
    if needle.is_empty() || data.len() < needle.len() {
        return Vec::new();
    }
    let needle_lc: Vec<u8> = needle.iter().map(u8::to_ascii_lowercase).collect();
    let mut results = Vec::new();
    'outer: for i in 0..=(data.len() - needle.len()) {
        for (j, &nb) in needle_lc.iter().enumerate() {
            if data[i + j].to_ascii_lowercase() != nb {
                continue 'outer;
            }
        }
        results.push((i as u64, data[i..i + needle.len()].to_vec()));
    }
    results
}

fn find_hex(data: &[u8], pattern: &[Option<u8>]) -> Vec<(u64, Vec<u8>)> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return Vec::new();
    }
    let plen = pattern.len();
    let mut results = Vec::new();
    'outer: for i in 0..=(data.len() - plen) {
        for (j, pb) in pattern.iter().enumerate() {
            if let Some(expected) = pb
                && data[i + j] != *expected {
                    continue 'outer;
                }
        }
        results.push((i as u64, data[i..i + plen].to_vec()));
    }
    results
}

fn find_regex(data: &[u8], pattern: &str) -> Vec<(u64, Vec<u8>)> {
    // Delegate to a simple hand-rolled regex scanner
    // (full implementation lives in rustre-triage-yara)
    // Here we do a best-effort: treat the regex as a literal if no special chars
    let is_literal = pattern
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' '));
    if is_literal {
        return find_literal(data, pattern.as_bytes());
    }
    // Fall back to empty for complex patterns
    Vec::new()
}

fn to_wide_bytes(ascii: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ascii.len() * 2);
    for &b in ascii {
        out.push(b);
        out.push(0x00);
    }
    out
}

fn is_fullword(data: &[u8], offset: usize, len: usize) -> bool {
    let before = if offset == 0 {
        true
    } else {
        let b = data[offset - 1];
        !b.is_ascii_alphanumeric() && b != b'_'
    };
    let after = if offset + len >= data.len() {
        true
    } else {
        let b = data[offset + len];
        !b.is_ascii_alphanumeric() && b != b'_'
    };
    before && after
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RULE: &str = r#"
rule TestMimikatz {
    meta:
        author = "test"
        severity = "critical"
    strings:
        $s1 = "mimikatz"
        $s2 = "sekurlsa"
    condition:
        any of them
}
"#;

    #[test]
    fn compile_simple_rule() {
        let rule = RuleCompiler::compile(SAMPLE_RULE).unwrap();
        assert_eq!(rule.name, "TestMimikatz");
        assert_eq!(rule.patterns.len(), 2);
    }

    #[test]
    fn execute_rule_matches() {
        let rule = RuleCompiler::compile(SAMPLE_RULE).unwrap();
        let data = b"loading mimikatz module...";
        assert!(rule.execute(data).is_some());
    }

    #[test]
    fn execute_rule_no_match() {
        let rule = RuleCompiler::compile(SAMPLE_RULE).unwrap();
        let data = b"clean binary with no suspicious strings";
        assert!(rule.execute(data).is_none());
    }

    #[test]
    fn hex_pattern_matching() {
        let pattern = vec![Some(0x4D), Some(0x5A), None, None];
        let data = b"MZ\x00\x03more";
        let hits = find_hex(data, &pattern);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 0);
    }

    #[test]
    fn nocase_matching() {
        let hits = find_nocase(b"MIMIKATZ", b"mimikatz");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn compile_all_returns_multiple() {
        let text = format!(
            "{}\n{}",
            SAMPLE_RULE,
            r#"
rule AnotherRule {
    meta:
        severity = "low"
    strings:
        $a = "UPX"
    condition:
        $a
}"#
        );
        let results = RuleCompiler::compile_all(&text);
        
        assert_eq!(results.into_iter().flatten().count(), 2);
    }

    #[test]
    fn executor_scan() {
        let rules = RuleCompiler::compile_best_effort(SAMPLE_RULE);
        let exec = RuleExecutor::new(rules);
        let hits = exec.scan(b"mimikatz");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn condition_any_of_them() {
        let rule = RuleCompiler::compile(SAMPLE_RULE).unwrap();
        assert!(matches!(rule.condition, Condition::AnyOf(_)));
    }

    #[test]
    fn parse_hex_string_test() {
        let bytes = parse_hex_string("4D 5A ?? 90").unwrap();
        assert_eq!(bytes[0], Some(0x4D));
        assert_eq!(bytes[1], Some(0x5A));
        assert_eq!(bytes[2], None);
        assert_eq!(bytes[3], Some(0x90));
    }

    #[test]
    fn filesize_condition_parse() {
        let cond = parse_filesize("filesize < 2MB").unwrap();
        match cond {
            Condition::FileSize {
                op: OrdOp::Lt,
                value,
            } => {
                assert_eq!(value, 2 * 1024 * 1024);
            }
            _ => panic!("expected FileSize"),
        }
    }

    #[test]
    fn string_modifiers_parse() {
        let m = StringModifiers::parse("nocase wide ascii").unwrap();
        assert!(m.nocase());
        assert!(m.wide());
        assert!(m.ascii());
    }

    #[test]
    fn split_rules_test() {
        let text = format!(
            "{}\n{}",
            SAMPLE_RULE, r#"rule B { strings: $x = "x" condition: $x }"#
        );
        let parts = split_rules(&text);
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn ord_op_eval() {
        assert!(OrdOp::Lt.eval(5, 10));
        assert!(!OrdOp::Gt.eval(5, 10));
        assert!(OrdOp::Eq.eval(7, 7));
    }

    #[test]
    fn to_wide_bytes_test() {
        let wide = to_wide_bytes(b"AB");
        assert_eq!(wide, vec![0x41, 0x00, 0x42, 0x00]);
    }

    #[test]
    fn is_fullword_test() {
        let data = b"foo mimikatz bar";
        assert!(is_fullword(data, 4, 8)); // "mimikatz" is surrounded by spaces
        let data2 = b"xmimikatz";
        assert!(!is_fullword(data2, 1, 8)); // prefix char is 'x'
    }

    #[test]
    fn rule_match_severity() {
        let rule = RuleCompiler::compile(SAMPLE_RULE).unwrap();
        let m = rule.execute(b"sekurlsa").unwrap();
        assert_eq!(m.severity(), "critical");
    }

    #[test]
    fn compile_empty_returns_error() {
        assert!(RuleCompiler::compile("").is_err());
    }
}
