//! `rustre-yara`
//!
//! Pure-Rust YARA-compatible rule engine for the `RustRE` Suite.
//!
//! Provides rule parsing, pattern matching, and scanning capabilities
//! compatible with the YARA rule language.

pub mod condition_eval;
pub mod match_correlator;
pub mod module_elf;
pub mod rule_compiler;
pub mod rule_language;
pub mod rule_optimizer;
pub mod rule_parser;
pub mod scan_context;
pub mod scanner_engine;
pub mod yara_integration;
pub mod yara_condition_evaluator;
pub mod yara_compiler;
pub mod yara_module_elf;
pub mod yara_scanner;

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as FmtWrite;

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Error type
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum YaraError {
    ParseError { line: usize, message: String },
    CompileError(String),
    ScanError(String),
    UnknownIdentifier(String),
    TypeError(String),
}

impl fmt::Display for YaraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseError { line, message } => {
                write!(f, "parse error at line {line}: {message}")
            }
            Self::CompileError(msg) => write!(f, "compilation error: {msg}"),
            Self::ScanError(msg) => write!(f, "scan error: {msg}"),
            Self::UnknownIdentifier(id) => write!(f, "unknown identifier: {id}"),
            Self::TypeError(msg) => write!(f, "type error: {msg}"),
        }
    }
}

impl std::error::Error for YaraError {}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// String modifiers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Encoding and case modifiers for a YARA string definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringEncodingOpts {
    pub nocase: bool,
    pub wide: bool,
    pub ascii: bool,
}

impl Default for StringEncodingOpts {
    fn default() -> Self {
        Self {
            nocase: false,
            wide: false,
            ascii: true,
        }
    }
}

/// Output and access-control modifiers for a YARA string definition.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StringOutputOpts {
    pub fullword: bool,
    pub private: bool,
    pub base64: bool,
}

/// All modifiers that can be applied to a YARA string definition.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Default)]
pub struct StringModifiers {
    /// Encoding and case options (`nocase`, `wide`, `ascii`).
    pub encoding: StringEncodingOpts,
    /// Output/visibility options (`fullword`, `private`, `base64`).
    pub output: StringOutputOpts,
    /// XOR range `(min, max)`.  `None` means no XOR.
    pub xor: Option<(u8, u8)>,
}

impl StringModifiers {
    /// Whether case-insensitive matching is enabled.
    #[inline]
    #[must_use]
    pub const fn nocase(&self) -> bool {
        self.encoding.nocase
    }
    /// Whether wide (UTF-16 LE) matching is enabled.
    #[inline]
    #[must_use]
    pub const fn wide(&self) -> bool {
        self.encoding.wide
    }
    /// Whether ASCII matching is enabled.
    #[inline]
    #[must_use]
    pub const fn ascii(&self) -> bool {
        self.encoding.ascii
    }
    /// Whether fullword matching is required.
    #[inline]
    #[must_use]
    pub const fn fullword(&self) -> bool {
        self.output.fullword
    }
    /// Whether the string is private (excluded from match output).
    #[inline]
    #[must_use]
    pub const fn is_private(&self) -> bool {
        self.output.private
    }
    /// Whether `base64` encoding is applied.
    #[inline]
    #[must_use]
    pub const fn base64(&self) -> bool {
        self.output.base64
    }
}

// Convenience field-access shims so existing code compiles without change.
impl StringModifiers {
    #[doc(hidden)]
    #[inline]
    pub const fn nocase_mut(&mut self) -> &mut bool {
        &mut self.encoding.nocase
    }
    #[doc(hidden)]
    #[inline]
    pub const fn wide_mut(&mut self) -> &mut bool {
        &mut self.encoding.wide
    }
    #[doc(hidden)]
    #[inline]
    pub const fn ascii_mut(&mut self) -> &mut bool {
        &mut self.encoding.ascii
    }
    #[doc(hidden)]
    #[inline]
    pub const fn fullword_mut(&mut self) -> &mut bool {
        &mut self.output.fullword
    }
    #[doc(hidden)]
    #[inline]
    pub const fn private_mut(&mut self) -> &mut bool {
        &mut self.output.private
    }
    #[doc(hidden)]
    #[inline]
    pub const fn base64_mut(&mut self) -> &mut bool {
        &mut self.output.base64
    }
}


// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Hex pattern tokens
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexToken {
    /// Exact byte value.
    Byte(u8),
    /// `??` —" any single byte.
    Wildcard,
    /// `?X` or `X?` —" one nibble is wildcarded.  `(value, mask)` where mask
    /// has `0x0F` or `0xF0` set for the wildcard nibble.
    Masked(u8, u8),
    /// `[n-m]` —" jump of between n and m bytes.
    Jump(u32, u32),
    /// `(AA BB | CC DD)` —" alternation of byte sequences.
    Alternation(Vec<Vec<Self>>),
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// YARA pattern
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone)]
pub enum YaraPattern {
    Text(String),
    Hex(Vec<HexToken>),
    Regex(String),
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// YARA string definition
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone)]
pub struct YaraString {
    pub identifier: String,
    pub pattern: YaraPattern,
    pub modifiers: StringModifiers,
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Metadata
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone)]
pub struct YaraMeta {
    pub key: String,
    pub value: YaraMetaValue,
}

#[derive(Debug, Clone)]
pub enum YaraMetaValue {
    String(String),
    Integer(i64),
    Bool(bool),
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Condition AST
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

#[derive(Debug, Clone)]
pub enum ForTarget {
    AllStrings,
    AnyStrings,
    StringSet(Vec<String>),
    Count(Box<YaraExpr>),
}

#[derive(Debug, Clone)]
pub enum YaraExpr {
    Integer(i64),
    Float(f64),
    Bool(bool),
    String(String),
    Identifier(String),
    At,
    FileSize,
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Div(Box<Self>, Box<Self>),
    Mod(Box<Self>, Box<Self>),
    BitAnd(Box<Self>, Box<Self>),
    BitOr(Box<Self>, Box<Self>),
    BitXor(Box<Self>, Box<Self>),
    BitNot(Box<Self>),
    Shl(Box<Self>, Box<Self>),
    Shr(Box<Self>, Box<Self>),
    Neg(Box<Self>),
    FuncCall(String, Vec<Self>),
}

#[derive(Debug, Clone)]
pub enum YaraCondition {
    True,
    False,
    Any,
    All,
    None_,
    StringMatch(String),
    StringMatchAt(String, Box<YaraExpr>),
    StringMatchIn(String, Box<YaraExpr>, Box<YaraExpr>),
    StringCount(String),
    StringOffset(String, Option<Box<YaraExpr>>),
    StringLength(String, Option<Box<YaraExpr>>),
    For(Box<YaraExpr>, ForTarget, Box<Self>),
    Not(Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Comparison(Box<YaraExpr>, CmpOp, Box<YaraExpr>),
    Expr(Box<YaraExpr>),
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// YaraRule
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone)]
pub struct YaraRule {
    pub name: String,
    pub tags: Vec<String>,
    pub meta: Vec<YaraMeta>,
    pub strings: Vec<YaraString>,
    pub condition: YaraCondition,
    pub is_private: bool,
    pub is_global: bool,
}

impl YaraRule {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            tags: Vec::new(),
            meta: Vec::new(),
            strings: Vec::new(),
            condition: YaraCondition::False,
            is_private: false,
            is_global: false,
        }
    }

    #[must_use]
    pub fn get_meta(&self, key: &str) -> Option<&YaraMetaValue> {
        self.meta.iter().find(|m| m.key == key).map(|m| &m.value)
    }

    #[must_use]
    pub fn description(&self) -> Option<String> {
        match self.get_meta("description")? {
            YaraMetaValue::String(s) => Some(s.clone()),
            _ => None,
        }
    }

    #[must_use]
    pub fn author(&self) -> Option<String> {
        match self.get_meta("author")? {
            YaraMetaValue::String(s) => Some(s.clone()),
            _ => None,
        }
    }

    #[must_use]
    pub fn date(&self) -> Option<String> {
        match self.get_meta("date")? {
            YaraMetaValue::String(s) => Some(s.clone()),
            _ => None,
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// YaraRuleSet
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone, Default)]
pub struct YaraRuleSet {
    pub rules: Vec<YaraRule>,
    pub imports: Vec<String>,
}

impl YaraRuleSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: YaraRule) {
        self.rules.push(rule);
    }

    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    #[must_use]
    pub fn rule_by_name(&self, name: &str) -> Option<&YaraRule> {
        self.rules.iter().find(|r| r.name == name)
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// StringMatcher
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

pub struct StringMatcher;

impl StringMatcher {
    /// Returns all offsets in `data` where `pattern` matches.
    #[must_use]
    pub fn match_hex(pattern: &[HexToken], data: &[u8]) -> Vec<usize> {
        let mut results = Vec::new();
        if data.is_empty() || pattern.is_empty() {
            return results;
        }
        for start in 0..data.len() {
            if Self::hex_match_at(pattern, data, start) {
                results.push(start);
            }
        }
        results
    }

    /// Recursive hex pattern match at a given offset in `data`.
    fn hex_match_at(pattern: &[HexToken], data: &[u8], mut pos: usize) -> bool {
        for (idx, token) in pattern.iter().enumerate() {
            match token {
                HexToken::Byte(b) => {
                    if pos >= data.len() || data[pos] != *b {
                        return false;
                    }
                    pos += 1;
                }
                HexToken::Wildcard => {
                    if pos >= data.len() {
                        return false;
                    }
                    pos += 1;
                }
                HexToken::Masked(value, mask) => {
                    if pos >= data.len() {
                        return false;
                    }
                    if !Self::match_masked_byte(*value, *mask, data[pos]) {
                        return false;
                    }
                    pos += 1;
                }
                HexToken::Jump(min, max) => {
                    let rest = &pattern[idx + 1..];
                    let min = *min as usize;
                    let max = *max as usize;
                    for skip in min..=max {
                        let new_pos = pos + skip;
                        if new_pos > data.len() {
                            break;
                        }
                        if Self::hex_match_at(rest, data, new_pos) {
                            return true;
                        }
                    }
                    return false;
                }
                HexToken::Alternation(alts) => {
                    let rest = &pattern[idx + 1..];
                    for alt in alts {
                        // Try matching this alternative followed by the rest
                        let mut combined = alt.clone();
                        combined.extend_from_slice(rest);
                        if Self::hex_match_at(&combined, data, pos) {
                            return true;
                        }
                    }
                    return false;
                }
            }
        }
        true
    }

    /// Returns the total length consumed by a hex pattern when it matches
    /// at a given offset (needed for match length reporting).
    fn hex_match_len(pattern: &[HexToken], data: &[u8], pos: usize) -> usize {
        Self::hex_match_len_inner(pattern, data, pos).unwrap_or(0)
    }

    fn hex_match_len_inner(pattern: &[HexToken], data: &[u8], mut pos: usize) -> Option<usize> {
        let start = pos;
        for (idx, token) in pattern.iter().enumerate() {
            match token {
                HexToken::Byte(_) | HexToken::Wildcard | HexToken::Masked(_, _) => {
                    if pos >= data.len() {
                        return None;
                    }
                    pos += 1;
                }
                HexToken::Jump(min, max) => {
                    let rest = &pattern[idx + 1..];
                    for skip in (*min as usize)..=(*max as usize) {
                        let new_pos = pos + skip;
                        if new_pos > data.len() {
                            break;
                        }
                        if let Some(end) = Self::hex_match_len_inner(rest, data, new_pos) {
                            return Some(new_pos - start + end);
                        }
                    }
                    return None;
                }
                HexToken::Alternation(alts) => {
                    let rest = &pattern[idx + 1..];
                    for alt in alts {
                        let mut combined = alt.clone();
                        combined.extend_from_slice(rest);
                        if let Some(end) = Self::hex_match_len_inner(&combined, data, pos) {
                            return Some(pos - start + end);
                        }
                    }
                    return None;
                }
            }
        }
        Some(pos - start)
    }

    /// Find all occurrences of a text string, respecting modifiers.
    #[must_use]
    pub fn match_text(text: &str, modifiers: &StringModifiers, data: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();

        // XOR matching takes priority when enabled
        if let Some((xor_min, xor_max)) = modifiers.xor {
            let xor_hits = Self::match_xor(text, xor_min, xor_max, data);
            offsets.extend(xor_hits.into_iter().map(|(off, _)| off));
            return offsets;
        }

        // Wide (UTF-16 LE) matching
        if modifiers.wide() {
            let wide_offsets = Self::match_wide(text, data);
            for off in wide_offsets {
                // wide characters are 2 bytes each; use stride-2 length for fullword check
                if modifiers.fullword() && !Self::check_fullword(data, off, text.len() * 2) {
                    continue;
                }
                offsets.push(off);
            }
        }

        // ASCII matching (default)
        if modifiers.ascii() || (!modifiers.wide()) {
            let ascii_offsets = if modifiers.nocase() {
                Self::match_nocase(text, data)
            } else {
                Self::match_bytes(text.as_bytes(), data)
            };
            for off in ascii_offsets {
                if modifiers.fullword() && !Self::check_fullword(data, off, text.len()) {
                    continue;
                }
                offsets.push(off);
            }
        }

        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }

    /// Find all byte-exact occurrences of `needle` in `haystack`.
    fn match_bytes(needle: &[u8], haystack: &[u8]) -> Vec<usize> {
        if needle.is_empty() || haystack.len() < needle.len() {
            return Vec::new();
        }
        let mut result = Vec::new();
        'outer: for start in 0..=(haystack.len() - needle.len()) {
            for (i, &b) in needle.iter().enumerate() {
                if haystack[start + i] != b {
                    continue 'outer;
                }
            }
            result.push(start);
        }
        result
    }

    /// Case-insensitive ASCII search.
    #[must_use]
    pub fn match_nocase(text: &str, data: &[u8]) -> Vec<usize> {
        let needle: Vec<u8> = text.bytes().map(|b| b.to_ascii_lowercase()).collect();
        if needle.is_empty() || data.len() < needle.len() {
            return Vec::new();
        }
        let mut result = Vec::new();
        'outer: for start in 0..=(data.len() - needle.len()) {
            for (i, &nb) in needle.iter().enumerate() {
                if data[start + i].to_ascii_lowercase() != nb {
                    continue 'outer;
                }
            }
            result.push(start);
        }
        result
    }

    /// Find occurrences of `text` encoded as UTF-16 LE in `data`.
    #[must_use]
    pub fn match_wide(text: &str, data: &[u8]) -> Vec<usize> {
        let wide: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        Self::match_bytes(&wide, data)
    }

    /// Find occurrences of `text` XOR-encoded with any key in `[xor_min, xor_max]`.
    /// Returns `(offset, key)` pairs.
    #[must_use]
    pub fn match_xor(text: &str, xor_min: u8, xor_max: u8, data: &[u8]) -> Vec<(usize, u8)> {
        let needle = text.as_bytes();
        if needle.is_empty() || data.len() < needle.len() {
            return Vec::new();
        }
        let mut result = Vec::new();
        let min = xor_min.min(xor_max);
        let max = xor_min.max(xor_max);
        for key in min..=max {
            'outer: for start in 0..=(data.len() - needle.len()) {
                for (i, &nb) in needle.iter().enumerate() {
                    if data[start + i] ^ key != nb {
                        continue 'outer;
                    }
                }
                result.push((start, key));
            }
        }
        result.sort_unstable_by_key(|&(off, _)| off);
        result
    }

    /// Returns `true` if the byte at `offset..offset+len` is bounded by
    /// non-word characters (or file start/end).
    #[must_use]
    pub fn check_fullword(data: &[u8], offset: usize, len: usize) -> bool {
        let before_ok = if offset == 0 {
            true
        } else {
            !data[offset - 1].is_ascii_alphanumeric() && data[offset - 1] != b'_'
        };
        let end = offset + len;
        let after_ok = if end >= data.len() {
            true
        } else {
            !data[end].is_ascii_alphanumeric() && data[end] != b'_'
        };
        before_ok && after_ok
    }

    /// Returns `true` if `data_byte` matches the nibble mask pattern:
    /// `(data_byte & mask) == (value & mask)`.
    #[must_use]
    pub const fn match_masked_byte(value: u8, mask: u8, data_byte: u8) -> bool {
        (data_byte & mask) == (value & mask)
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// YaraParser —" recursive-descent parser
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

pub struct YaraParser;

impl YaraParser {
    /// Parse a complete YARA rule file (may contain multiple rules).
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::ParseError`] if the input is syntactically invalid.
    ///
    /// # Panics
    ///
    /// Panics if an opening brace `{` is not found after being expected by the
    /// parser (internal invariant violation in malformed input).
    pub fn parse(input: &str) -> Result<YaraRuleSet, YaraError> {
        let mut ruleset = YaraRuleSet::new();
        let mut remaining = input;
        let mut line_offset = 1usize;

        loop {
            let trimmed = remaining.trim_start();
            if trimmed.is_empty() {
                break;
            }
            // Count lines consumed by whitespace at start
            let ws_len = remaining.len() - trimmed.len();
            line_offset += remaining[..ws_len].chars().filter(|&c| c == '\n').count();
            remaining = trimmed;

            // Handle imports
            if remaining.starts_with("import") {
                let end = remaining.find('\n').unwrap_or(remaining.len());
                remaining = &remaining[end..];
                continue;
            }

            // Parse optional private/global modifiers
            let mut is_private = false;
            let mut is_global = false;
            let mut cursor = remaining;
            loop {
                let ws = cursor.trim_start();
                let ws_consumed = cursor.len() - ws.len();
                line_offset += cursor[..ws_consumed].chars().filter(|&c| c == '\n').count();
                cursor = ws;
                if cursor.starts_with("private ") || cursor.starts_with("private\t") {
                    is_private = true;
                    cursor = cursor["private".len()..].trim_start();
                } else if cursor.starts_with("global ") || cursor.starts_with("global\t") {
                    is_global = true;
                    cursor = cursor["global".len()..].trim_start();
                } else {
                    break;
                }
            }

            if !cursor.starts_with("rule") {
                return Err(YaraError::ParseError {
                    line: line_offset,
                    message: format!(
                        "expected 'rule' keyword, found: {}",
                        &cursor[..cursor.len().min(20)]
                    ),
                });
            }
            cursor = cursor["rule".len()..].trim_start();

            // Rule name
            let name_end = cursor
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .unwrap_or(cursor.len());
            if name_end == 0 {
                return Err(YaraError::ParseError {
                    line: line_offset,
                    message: "expected rule name".to_string(),
                });
            }
            let name = cursor[..name_end].to_string();
            cursor = cursor[name_end..].trim_start();

            // Optional tags: rule Foo : tag1 tag2 {
            let mut tags = Vec::new();
            if cursor.starts_with(':') {
                cursor = cursor[1..].trim_start();
                while !cursor.is_empty() && !cursor.starts_with('{') {
                    let end = cursor
                        .find(|c: char| !c.is_alphanumeric() && c != '_')
                        .unwrap_or(cursor.len());
                    if end == 0 {
                        break;
                    }
                    tags.push(cursor[..end].to_string());
                    cursor = cursor[end..].trim_start();
                }
            }

            // Opening brace
            if !cursor.starts_with('{') {
                return Err(YaraError::ParseError {
                    line: line_offset,
                    message: format!("expected '{{' for rule '{name}'"),
                });
            }
            // Find the matching closing brace
            let body_start = cursor.find('{').unwrap();
            let body = Self::extract_braced(cursor).ok_or_else(|| YaraError::ParseError {
                line: line_offset,
                message: format!("unclosed '{{' in rule '{name}'"),
            })?;
            let consumed = body_start + body.len() + 2; // +2 for { and }
            remaining = &cursor[consumed..];
            line_offset += cursor[..consumed].chars().filter(|&c| c == '\n').count();

            let meta = Self::parse_meta_section(body)?;
            let strings = Self::parse_strings_section(body)?;
            let condition = Self::parse_condition_section(body)?;

            let mut rule = YaraRule::new(name);
            rule.tags = tags;
            rule.meta = meta;
            rule.strings = strings;
            rule.condition = condition;
            rule.is_private = is_private;
            rule.is_global = is_global;
            ruleset.add_rule(rule);
        }
        Ok(ruleset)
    }

    /// Extract the content between the first `{` and its matching `}`.
    fn extract_braced(s: &str) -> Option<&str> {
        let mut depth = 0usize;
        let mut start = None;
        let mut chars = s.char_indices();
        for (i, c) in chars.by_ref() {
            match c {
                '{' => {
                    depth += 1;
                    if depth == 1 {
                        start = Some(i + 1);
                    }
                }
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&s[start?..i]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Parse a single rule (wraps `parse` for convenience).
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::ParseError`] if the input is syntactically invalid
    /// or contains no rules.
    pub fn parse_rule(input: &str) -> Result<YaraRule, YaraError> {
        let mut ruleset = Self::parse(input)?;
        if ruleset.rules.is_empty() {
            return Err(YaraError::ParseError {
                line: 1,
                message: "no rule found in input".to_string(),
            });
        }
        Ok(ruleset.rules.remove(0))
    }

    /// Parse the `meta:` section from a rule body.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::ParseError`] if any meta entry is malformed.
    pub fn parse_meta_section(body: &str) -> Result<Vec<YaraMeta>, YaraError> {
        let section = Self::extract_section(body, "meta");
        let Some(section) = section else {
            return Ok(Vec::new());
        };
        let mut result = Vec::new();
        for line in section.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let eq = line.find('=').ok_or_else(|| YaraError::ParseError {
                line: 0,
                message: format!("invalid meta entry: {line}"),
            })?;
            let key = line[..eq].trim().to_string();
            let val_str = line[eq + 1..].trim();
            let value = Self::parse_meta_value(val_str);
            result.push(YaraMeta { key, value });
        }
        Ok(result)
    }

    fn parse_meta_value(s: &str) -> YaraMetaValue {
        if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
            return YaraMetaValue::String(s[1..s.len() - 1].to_string());
        }
        if s == "true" {
            return YaraMetaValue::Bool(true);
        }
        if s == "false" {
            return YaraMetaValue::Bool(false);
        }
        if let Ok(n) = s.parse::<i64>() {
            return YaraMetaValue::Integer(n);
        }
        YaraMetaValue::String(s.to_string())
    }

    /// Parse the `strings:` section from a rule body.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::ParseError`] if a string definition is malformed.
    ///
    /// # Panics
    ///
    /// Panics if a closing brace `}` is not found in a hex string that was
    /// confirmed to contain one (internal invariant).
    pub fn parse_strings_section(body: &str) -> Result<Vec<YaraString>, YaraError> {
        let section = Self::extract_section(body, "strings");
        let Some(section) = section else {
            return Ok(Vec::new());
        };
        let mut result = Vec::new();
        let mut lines = section.lines();
        while let Some(raw_line) = lines.next() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            let eq = line.find('=').ok_or_else(|| YaraError::ParseError {
                line: 0,
                message: format!("invalid string definition: {line}"),
            })?;
            let ident = line[..eq].trim().to_string();
            let rhs = line[eq + 1..].trim();

            let (pattern, modifiers) = if rhs.starts_with('{') {
                // Hex pattern —" may span multiple lines
                let mut hex_src = rhs.to_string();
                while !hex_src.contains('}') {
                    match lines.next() {
                        Some(l) => {
                            hex_src.push('\n');
                            hex_src.push_str(l);
                        }
                        None => {
                            return Err(YaraError::ParseError {
                                line: 0,
                                message: "unclosed hex pattern".to_string(),
                            });
                        }
                    }
                }
                let close = hex_src.find('}').unwrap();
                let hex_inner = &hex_src[1..close];
                let mods_str = hex_src[close + 1..].trim();
                let tokens: Vec<&str> = mods_str.split_whitespace().collect();
                let mods = Self::parse_string_modifiers(&tokens);
                (YaraPattern::Hex(Self::parse_hex_pattern(hex_inner)?), mods)
            } else if let Some(rhs_after_slash) = rhs.strip_prefix('/') {
                // Regex pattern
                let end = rhs_after_slash.find('/').map(|i| i + 1);
                let end = end.ok_or_else(|| YaraError::ParseError {
                    line: 0,
                    message: "unclosed regex pattern".to_string(),
                })?;
                let regex_str = rhs[1..end].to_string();
                let after = rhs[end + 1..].trim();
                let tokens: Vec<&str> = after.split_whitespace().collect();
                let mods = Self::parse_string_modifiers(&tokens);
                (YaraPattern::Regex(regex_str), mods)
            } else if rhs.starts_with('"') {
                // Text string —" find closing quote (handle escaped quotes)
                let (text, rest) =
                    Self::parse_quoted_string(rhs).ok_or_else(|| YaraError::ParseError {
                        line: 0,
                        message: format!("unclosed string literal: {rhs}"),
                    })?;
                let tokens: Vec<&str> = rest.split_whitespace().collect();
                let mods = Self::parse_string_modifiers(&tokens);
                (YaraPattern::Text(text), mods)
            } else {
                return Err(YaraError::ParseError {
                    line: 0,
                    message: format!("unrecognised pattern: {rhs}"),
                });
            };

            result.push(YaraString {
                identifier: ident,
                pattern,
                modifiers,
            });
        }
        Ok(result)
    }

    /// Parse a `"..."` string, returning `(content, remainder)`.
    fn parse_quoted_string(s: &str) -> Option<(String, &str)> {
        if !s.starts_with('"') {
            return None;
        }
        let mut out = String::new();
        let mut chars = s[1..].char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => return Some((out, &s[i + 2..])),
                '\\' => match chars.next()?.1 {
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    other => {
                        out.push('\\');
                        out.push(other);
                    }
                },
                other => out.push(other),
            }
        }
        None
    }

    /// Parse the `condition:` section from a rule body.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::ParseError`] if the condition section is missing or
    /// contains a syntax error.
    pub fn parse_condition_section(body: &str) -> Result<YaraCondition, YaraError> {
        let section = Self::extract_section(body, "condition");
        let section = match section {
            Some(s) => s.trim(),
            None => {
                return Err(YaraError::ParseError {
                    line: 0,
                    message: "missing 'condition:' section".to_string(),
                });
            }
        };
        Self::parse_condition_expr(section)
    }

    /// Extract the text of a named section (e.g. `meta:`, `strings:`, `condition:`)
    /// from a rule body (the text between the outer `{` and `}`).
    fn extract_section<'a>(body: &'a str, name: &str) -> Option<&'a str> {
        let marker = format!("{name}:");
        let start = body.find(marker.as_str())?;
        let after = &body[start + marker.len()..];
        // Section ends at the next `name:` keyword or end of body.
        let sections = ["meta:", "strings:", "condition:"];
        let mut end = after.len();
        for other in &sections {
            if *other == marker.as_str() {
                continue;
            }
            if let Some(pos) = after.find(other)
                && pos < end
            {
                end = pos;
            }
        }
        Some(&after[..end])
    }

    /// Parse a hex pattern string like `55 8B ?? [0-4] (AA | BB CC)`.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::ParseError`] if the hex pattern is malformed.
    ///
    /// # Panics
    ///
    /// Panics if an ASCII hex digit cannot be converted to its numeric value
    /// (internal invariant —" only called after `is_ascii_hexdigit` check).
    pub fn parse_hex_pattern(input: &str) -> Result<Vec<HexToken>, YaraError> {
        let mut tokens = Vec::new();
        let mut chars = input.chars().peekable();
        while let Some(&c) = chars.peek() {
            match c {
                ' ' | '\t' | '\r' | '\n' => {
                    chars.next();
                }
                '[' => {
                    chars.next(); // consume '['
                    let mut range_str = String::new();
                    for rc in chars.by_ref() {
                        if rc == ']' {
                            break;
                        }
                        range_str.push(rc);
                    }
                    let range_str = range_str.trim();
                    if let Some(dash) = range_str.find('-') {
                        let min_str = range_str[..dash].trim();
                        let max_str = range_str[dash + 1..].trim();
                        let min: u32 = min_str.parse().map_err(|_| YaraError::ParseError {
                            line: 0,
                            message: format!("invalid jump range min: {min_str}"),
                        })?;
                        let max: u32 = max_str.parse().map_err(|_| YaraError::ParseError {
                            line: 0,
                            message: format!("invalid jump range max: {max_str}"),
                        })?;
                        tokens.push(HexToken::Jump(min, max));
                    } else {
                        let n: u32 = range_str.parse().map_err(|_| YaraError::ParseError {
                            line: 0,
                            message: format!("invalid jump value: {range_str}"),
                        })?;
                        tokens.push(HexToken::Jump(n, n));
                    }
                }
                '(' => {
                    chars.next();
                    let alt_tok = Self::parse_hex_alternation(&mut chars)?;
                    tokens.push(alt_tok);
                }
                '?' => {
                    chars.next(); // first '?'
                    if chars.peek() == Some(&'?') {
                        chars.next(); // second '?'
                        tokens.push(HexToken::Wildcard);
                    } else {
                        // ?X —" low nibble known, high nibble wildcard
                        let lo = match chars.next() {
                            Some(h) if h.is_ascii_hexdigit() => {
                                u8::try_from(h.to_digit(16).unwrap()).unwrap_or(0)
                            }
                            _ => {
                                return Err(YaraError::ParseError {
                                    line: 0,
                                    message: "expected hex digit after '?'".to_string(),
                                });
                            }
                        };
                        // value has the known low nibble; mask keeps the low nibble
                        tokens.push(HexToken::Masked(lo, 0x0F));
                    }
                }
                h if h.is_ascii_hexdigit() => {
                    chars.next();
                    let hi = u8::try_from(h.to_digit(16).unwrap()).unwrap_or(0);
                    match chars.peek() {
                        Some(&'?') => {
                            chars.next(); // consume '?'
                            // X? —" high nibble known, low nibble wildcard
                            let value = hi << 4;
                            let mask = 0xF0u8;
                            tokens.push(HexToken::Masked(value, mask));
                        }
                        Some(&lo_c) if lo_c.is_ascii_hexdigit() => {
                            chars.next();
                            let lo = u8::try_from(lo_c.to_digit(16).unwrap()).unwrap_or(0);
                            tokens.push(HexToken::Byte((hi << 4) | lo));
                        }
                        _ => {
                            return Err(YaraError::ParseError {
                                line: 0,
                                message: format!("incomplete hex byte starting with '{h}'"),
                            });
                        }
                    }
                }
                other => {
                    return Err(YaraError::ParseError {
                        line: 0,
                        message: format!("unexpected character in hex pattern: '{other}'"),
                    });
                }
            }
        }
        Ok(tokens)
    }

    fn parse_hex_alternation(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<HexToken, YaraError> {
        let mut alt_src = String::new();
        let mut depth = 1usize;
        for rc in chars.by_ref() {
            match rc {
                '(' => { depth += 1; alt_src.push(rc); }
                ')' => {
                    depth -= 1;
                    if depth == 0 { break; }
                    alt_src.push(rc);
                }
                _ => alt_src.push(rc),
            }
        }
        let alternatives: Result<Vec<Vec<HexToken>>, YaraError> = alt_src
            .split('|')
            .map(|arm| Self::parse_hex_pattern(arm.trim()))
            .collect();
        Ok(HexToken::Alternation(alternatives?))
    }

    /// Parse modifier keywords from a slice of tokens.
    #[must_use]
    pub fn parse_string_modifiers(tokens: &[&str]) -> StringModifiers {
        let mut mods = StringModifiers::default();
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "nocase" => mods.encoding.nocase = true,
                "wide" => mods.encoding.wide = true,
                "ascii" => mods.encoding.ascii = true,
                "fullword" => mods.output.fullword = true,
                "private" => mods.output.private = true,
                "base64" => mods.output.base64 = true,
                "xor" => {
                    // Optional range: xor(0x01-0xff) or just xor
                    // Check for parenthesised range in next token
                    if i + 1 < tokens.len() {
                        let next = tokens[i + 1];
                        if next.starts_with('(') {
                            let inner = next.trim_matches(|c| c == '(' || c == ')');
                            if let Some(dash) = inner.find('-') {
                                let lo = u8::from_str_radix(
                                    inner[..dash].trim().trim_start_matches("0x"),
                                    16,
                                )
                                .unwrap_or(0);
                                let hi = u8::from_str_radix(
                                    inner[dash + 1..].trim().trim_start_matches("0x"),
                                    16,
                                )
                                .unwrap_or(255);
                                mods.xor = Some((lo, hi));
                                i += 1;
                            } else {
                                mods.xor = Some((0, 255));
                            }
                        } else {
                            mods.xor = Some((0, 255));
                        }
                    } else {
                        mods.xor = Some((0, 255));
                    }
                }
                _ => {}
            }
            i += 1;
        }
        mods
    }

    // â"€â"€ Condition expression parser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn parse_condition_expr(input: &str) -> Result<YaraCondition, YaraError> {
        let input = input.trim();
        // OR is lowest precedence
        Self::parse_or_expr(input)
    }

    fn parse_or_expr(input: &str) -> Result<YaraCondition, YaraError> {
        // Split on top-level " or "
        if let Some((left, right)) = Self::split_top_level(input, " or ") {
            let l = Self::parse_or_expr(left.trim())?;
            let r = Self::parse_or_expr(right.trim())?;
            return Ok(YaraCondition::Or(Box::new(l), Box::new(r)));
        }
        Self::parse_and_expr(input)
    }

    fn parse_and_expr(input: &str) -> Result<YaraCondition, YaraError> {
        if let Some((left, right)) = Self::split_top_level(input, " and ") {
            let l = Self::parse_and_expr(left.trim())?;
            let r = Self::parse_and_expr(right.trim())?;
            return Ok(YaraCondition::And(Box::new(l), Box::new(r)));
        }
        Self::parse_not_expr(input)
    }

    fn parse_not_expr(input: &str) -> Result<YaraCondition, YaraError> {
        if let Some(rest) = input.strip_prefix("not ") {
            let inner = Self::parse_not_expr(rest.trim())?;
            return Ok(YaraCondition::Not(Box::new(inner)));
        }
        Self::parse_primary_condition(input)
    }

    fn parse_primary_condition(input: &str) -> Result<YaraCondition, YaraError> {
        let input = input.trim();

        // Parenthesised sub-expression
        if input.starts_with('(')
            && input.ends_with(')')
            && let Some(inner) = Self::extract_braced_parens(input)
        {
            return Self::parse_condition_expr(inner);
        }

        match input {
            "true" => return Ok(YaraCondition::True),
            "false" => return Ok(YaraCondition::False),
            "any of them" => return Ok(YaraCondition::Any),
            "all of them" => return Ok(YaraCondition::All),
            "none of them" => return Ok(YaraCondition::None_),
            _ => {}
        }

        // String count: #str (bare, no comparison/whitespace)
        if input.starts_with('#') && !input.contains(' ') {
            let ident = input.trim().to_string();
            return Ok(YaraCondition::StringCount(ident[1..].to_string()));
        }

        // Comparison: expr OP expr
        for op_str in &[" == ", " != ", " <= ", " >= ", " < ", " > "] {
            if let Some((lhs_s, rhs_s)) = Self::split_top_level(input, op_str) {
                let op = match op_str.trim() {
                    "==" => CmpOp::Eq,
                    "!=" => CmpOp::Ne,
                    "<=" => CmpOp::Le,
                    ">=" => CmpOp::Ge,
                    "<" => CmpOp::Lt,
                    ">" => CmpOp::Gt,
                    _ => unreachable!(),
                };
                let lhs = Self::parse_expr(lhs_s.trim())?;
                let rhs = Self::parse_expr(rhs_s.trim())?;
                return Ok(YaraCondition::Comparison(Box::new(lhs), op, Box::new(rhs)));
            }
        }

        // String match: $str
        if input.starts_with('$') && !input.contains(' ') {
            return Ok(YaraCondition::StringMatch(input.to_string()));
        }

        // $str at offset
        if input.starts_with('$') {
            if let Some(at_pos) = Self::split_top_level(input, " at ") {
                let ident = at_pos.0.trim().to_string();
                let offset_expr = Self::parse_expr(at_pos.1.trim())?;
                return Ok(YaraCondition::StringMatchAt(ident, Box::new(offset_expr)));
            }
            // $str in (start..end)
            if let Some(in_pos) = Self::split_top_level(input, " in ") {
                let ident = in_pos.0.trim().to_string();
                let range_str = in_pos.1.trim().trim_matches(|c| c == '(' || c == ')');
                if let Some(dot2) = range_str.find("..") {
                    let start_expr = Self::parse_expr(range_str[..dot2].trim())?;
                    let end_expr = Self::parse_expr(range_str[dot2 + 2..].trim())?;
                    return Ok(YaraCondition::StringMatchIn(
                        ident,
                        Box::new(start_expr),
                        Box::new(end_expr),
                    ));
                }
            }
            return Ok(YaraCondition::StringMatch(input.to_string()));
        }

        // for N of them : (cond)
        if input.starts_with("for ") {
            return Self::parse_for_condition(input);
        }

        // Fallthrough: treat as expression
        let expr = Self::parse_expr(input)?;
        Ok(YaraCondition::Expr(Box::new(expr)))
    }

    fn parse_for_condition(input: &str) -> Result<YaraCondition, YaraError> {
        // for <expr> of <target> : (<cond>)
        let rest = input["for ".len()..].trim();
        let colon = rest.rfind(':').ok_or_else(|| YaraError::ParseError {
            line: 0,
            message: format!("expected ':' in for-expression: {input}"),
        })?;
        let of_part = rest[..colon].trim();
        let cond_part = rest[colon + 1..]
            .trim()
            .trim_matches(|c| c == '(' || c == ')');

        let of_idx = of_part.find(" of ").ok_or_else(|| YaraError::ParseError {
            line: 0,
            message: format!("expected 'of' in for-expression: {input}"),
        })?;
        let quantifier = of_part[..of_idx].trim();
        let target_str = of_part[of_idx + 4..].trim();

        let target = match target_str {
            "them" => ForTarget::AllStrings,
            s if s.starts_with('(') => {
                let inner = s.trim_matches(|c| c == '(' || c == ')');
                let ids: Vec<String> = inner.split(',').map(|id| id.trim().to_string()).collect();
                ForTarget::StringSet(ids)
            }
            _ => ForTarget::AllStrings,
        };

        let count_expr = Self::parse_expr(quantifier)?;
        let cond = Self::parse_condition_expr(cond_part)?;

        Ok(YaraCondition::For(
            Box::new(count_expr),
            target,
            Box::new(cond),
        ))
    }

    /// Parse a numeric/string expression.
    fn parse_expr(input: &str) -> Result<YaraExpr, YaraError> {
        let input = input.trim();
        // Arithmetic: lowest precedence is +/-
        if let Some((l, r)) = Self::split_top_level(input, " + ") {
            return Ok(YaraExpr::Add(
                Box::new(Self::parse_expr(l.trim())?),
                Box::new(Self::parse_expr(r.trim())?),
            ));
        }
        if let Some((l, r)) = Self::split_top_level(input, " - ") {
            return Ok(YaraExpr::Sub(
                Box::new(Self::parse_expr(l.trim())?),
                Box::new(Self::parse_expr(r.trim())?),
            ));
        }
        // * / %
        if let Some((l, r)) = Self::split_top_level(input, " * ") {
            return Ok(YaraExpr::Mul(
                Box::new(Self::parse_expr(l.trim())?),
                Box::new(Self::parse_expr(r.trim())?),
            ));
        }
        if let Some((l, r)) = Self::split_top_level(input, " / ") {
            return Ok(YaraExpr::Div(
                Box::new(Self::parse_expr(l.trim())?),
                Box::new(Self::parse_expr(r.trim())?),
            ));
        }
        if let Some((l, r)) = Self::split_top_level(input, " % ") {
            return Ok(YaraExpr::Mod(
                Box::new(Self::parse_expr(l.trim())?),
                Box::new(Self::parse_expr(r.trim())?),
            ));
        }
        // Unary negation
        if let Some(rest) = input.strip_prefix('-') {
            let inner = Self::parse_expr(rest.trim())?;
            return Ok(YaraExpr::Neg(Box::new(inner)));
        }
        // Parenthesised
        if input.starts_with('(')
            && input.ends_with(')')
            && let Some(inner) = Self::extract_braced_parens(input)
        {
            return Self::parse_expr(inner);
        }
        // Keywords
        match input {
            "filesize" => return Ok(YaraExpr::FileSize),
            "entrypoint" => return Ok(YaraExpr::At),
            "true" => return Ok(YaraExpr::Bool(true)),
            "false" => return Ok(YaraExpr::Bool(false)),
            _ => {}
        }
        // Hex literal
        if input.starts_with("0x") || input.starts_with("0X") {
            let n = i64::from_str_radix(&input[2..], 16).map_err(|_| YaraError::ParseError {
                line: 0,
                message: format!("invalid hex literal: {input}"),
            })?;
            return Ok(YaraExpr::Integer(n));
        }
        // Integer literal
        if let Ok(n) = input.parse::<i64>() {
            return Ok(YaraExpr::Integer(n));
        }
        // Float literal
        if let Ok(f) = input.parse::<f64>() {
            return Ok(YaraExpr::Float(f));
        }
        // String count: #str
        if input.starts_with('#') {
            return Ok(YaraExpr::Identifier(input.to_string()));
        }
        // String offset: @str
        if input.starts_with('@') {
            return Ok(YaraExpr::Identifier(input.to_string()));
        }
        // String length: !str
        if input.starts_with('!') {
            return Ok(YaraExpr::Identifier(input.to_string()));
        }
        // String reference: $str
        if input.starts_with('$') {
            return Ok(YaraExpr::Identifier(input.to_string()));
        }
        // Quoted string
        if input.starts_with('"')
            && let Some((s, _)) = Self::parse_quoted_string(input)
        {
            return Ok(YaraExpr::String(s));
        }
        // Identifier or function call
        if input.contains('(') {
            let paren = input.find('(').unwrap();
            let func_name = input[..paren].to_string();
            let args_str = input[paren + 1..].trim_end_matches(')');
            let args: Result<Vec<YaraExpr>, YaraError> = if args_str.trim().is_empty() {
                Ok(Vec::new())
            } else {
                args_str
                    .split(',')
                    .map(|a| Self::parse_expr(a.trim()))
                    .collect()
            };
            return Ok(YaraExpr::FuncCall(func_name, args?));
        }
        Ok(YaraExpr::Identifier(input.to_string()))
    }

    /// Split `input` at the first top-level (paren-depth 0) occurrence of
    /// `needle`, returning `(before, after)`.
    fn split_top_level<'a>(input: &'a str, needle: &str) -> Option<(&'a str, &'a str)> {
        let needle_bytes = needle.as_bytes();
        let input_bytes = input.as_bytes();
        let mut depth_paren = 0i32;
        let mut depth_bracket = 0i32;
        let mut i = 0usize;
        while i + needle_bytes.len() <= input_bytes.len() {
            match input_bytes[i] {
                b'(' => depth_paren += 1,
                b')' => depth_paren -= 1,
                b'[' => depth_bracket += 1,
                b']' => depth_bracket -= 1,
                _ => {}
            }
            if depth_paren == 0
                && depth_bracket == 0
                && &input_bytes[i..i + needle_bytes.len()] == needle_bytes
            {
                return Some((&input[..i], &input[i + needle.len()..]));
            }
            i += 1;
        }
        None
    }

    /// Extract the content of `(...)`, assuming the string starts with `(`.
    fn extract_braced_parens(s: &str) -> Option<&str> {
        let mut depth = 0usize;
        let mut start = None;
        for (i, c) in s.char_indices() {
            match c {
                '(' => {
                    depth += 1;
                    if depth == 1 {
                        start = Some(i + 1);
                    }
                }
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&s[start?..i]);
                    }
                }
                _ => {}
            }
        }
        None
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Match results
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone)]
pub struct StringMatch {
    pub identifier: String,
    pub offset: u64,
    pub length: usize,
    pub data: Vec<u8>,
    pub xor_key: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub rule_name: String,
    pub tags: Vec<String>,
    pub meta: Vec<YaraMeta>,
    pub strings: Vec<StringMatch>,
    pub namespace: String,
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ScanContext
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

pub struct ScanContext<'a> {
    pub data: &'a [u8],
    pub base_address: u64,
    pub filesize: u64,
    /// identifier (without `$`) -> sorted list of byte offsets
    pub string_matches: HashMap<String, Vec<u64>>,
}

impl<'a> ScanContext<'a> {
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        let filesize = data.len() as u64;
        Self {
            data,
            base_address: 0,
            filesize,
            string_matches: HashMap::new(),
        }
    }

    #[must_use]
    pub const fn with_base(mut self, base: u64) -> Self {
        self.base_address = base;
        self
    }

    /// Number of times string `id` matched (id without `$` or `#`).
    pub fn string_count(&self, id: &str) -> usize {
        self.string_matches.get(id).map_or(0, Vec::len)
    }

    /// Offset of the nth match for string `id` (0-indexed).
    #[must_use]
    pub fn string_offset(&self, id: &str, nth: usize) -> Option<u64> {
        self.string_matches.get(id)?.get(nth).copied()
    }

    /// Whether string `id` matched at least once.
    #[must_use]
    pub fn string_matched(&self, id: &str) -> bool {
        self.string_matches.get(id).is_some_and(|v| !v.is_empty())
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// YaraScanner
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

pub struct YaraScanner {
    pub rules: YaraRuleSet,
}

impl YaraScanner {
    #[must_use]
    pub const fn new(rules: YaraRuleSet) -> Self {
        Self { rules }
    }

    /// Create a scanner from YARA rule text.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::ParseError`] if the text is not valid YARA syntax.
    pub fn from_rules_text(text: &str) -> Result<Self, YaraError> {
        let ruleset = YaraParser::parse(text)?;
        Ok(Self::new(ruleset))
    }

    /// Scan `data` against all rules and return all matching rules.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError`] if condition evaluation fails.
    pub fn scan(&self, data: &[u8]) -> Result<Vec<YaraMatch>, YaraError> {
        self.scan_with_base(data, 0)
    }

    /// Scan with an explicit base address.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError`] if condition evaluation fails.
    pub fn scan_with_base(&self, data: &[u8], base: u64) -> Result<Vec<YaraMatch>, YaraError> {
        let mut matches = Vec::new();
        for rule in &self.rules.rules {
            if rule.is_private {
                continue;
            }
            let ctx = self.collect_string_matches(rule, data).with_base(base);
            if self.evaluate_rule(rule, &ctx)? {
                let string_matches = Self::build_string_matches(rule, &ctx, data);
                matches.push(YaraMatch {
                    rule_name: rule.name.clone(),
                    tags: rule.tags.clone(),
                    meta: rule.meta.clone(),
                    strings: string_matches,
                    namespace: String::new(),
                });
            }
        }
        Ok(matches)
    }

    fn build_string_matches(
        rule: &YaraRule,
        ctx: &ScanContext<'_>,
        data: &[u8],
    ) -> Vec<StringMatch> {
        let mut out = Vec::new();
        for ys in &rule.strings {
            if ys.modifiers.is_private() {
                continue;
            }
            let bare_id = ys.identifier.trim_start_matches('$');
            if let Some(offsets) = ctx.string_matches.get(bare_id) {
                for &off in offsets {
                    let off_usize = usize::try_from(off).unwrap_or(usize::MAX);
                    let len = match &ys.pattern {
                        YaraPattern::Text(t) => t.len(),
                        YaraPattern::Hex(tokens) => {
                            StringMatcher::hex_match_len(tokens, data, off_usize)
                        }
                        YaraPattern::Regex(r) => r.len(), // approx
                    };
                    let end = (off_usize + len).min(data.len());
                    let matched_data = data[off_usize..end].to_vec();
                    out.push(StringMatch {
                        identifier: ys.identifier.clone(),
                        offset: off,
                        length: len,
                        data: matched_data,
                        xor_key: None,
                    });
                }
            }
        }
        out
    }

    /// Evaluate whether `rule` matches within `ctx`.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError`] if condition evaluation encounters an unknown
    /// identifier or type error.
    pub fn evaluate_rule(&self, rule: &YaraRule, ctx: &ScanContext<'_>) -> Result<bool, YaraError> {
        Self::eval_condition(&rule.condition, ctx)
    }

    /// Collect all string matches for every string in `rule`.
    #[must_use]
    pub fn collect_string_matches<'a>(&self, rule: &YaraRule, data: &'a [u8]) -> ScanContext<'a> {
        let mut ctx = ScanContext::new(data);
        for ys in &rule.strings {
            let bare_id = ys.identifier.trim_start_matches('$').to_string();
            let offsets: Vec<u64> = match &ys.pattern {
                YaraPattern::Text(text) => StringMatcher::match_text(text, &ys.modifiers, data)
                    .into_iter()
                    .map(|o| o as u64)
                    .collect(),
                YaraPattern::Hex(tokens) => StringMatcher::match_hex(tokens, data)
                    .into_iter()
                    .map(|o| o as u64)
                    .collect(),
                YaraPattern::Regex(_regex_str) => {
                    // Regex matching: simple literal interpretation for now.
                    // Real regex support would require a regex engine, but we
                    // treat the regex as a literal text pattern as a best-effort
                    // without external deps.
                    Vec::new()
                }
            };
            ctx.string_matches.insert(bare_id, offsets);
        }
        ctx
    }

    /// Evaluate a `YaraCondition` against a `ScanContext`.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError`] if expression evaluation fails.
    pub fn eval_condition(cond: &YaraCondition, ctx: &ScanContext<'_>) -> Result<bool, YaraError> {
        match cond {
            YaraCondition::True => Ok(true),
            YaraCondition::False => Ok(false),

            YaraCondition::Any => Ok(ctx.string_matches.values().any(|v| !v.is_empty())),

            YaraCondition::All => Ok(ctx.string_matches.values().all(|v| !v.is_empty())),

            YaraCondition::None_ => Ok(ctx.string_matches.values().all(Vec::is_empty)),

            YaraCondition::StringMatch(id) => {
                let bare = id.trim_start_matches('$');
                Ok(ctx.string_matched(bare))
            }

            YaraCondition::StringMatchAt(id, offset_expr) => {
                let bare = id.trim_start_matches('$');
                let target = u64::try_from(Self::eval_expr(offset_expr, ctx)?).unwrap_or(u64::MAX);
                Ok(ctx
                    .string_matches
                    .get(bare)
                    .is_some_and(|v| v.contains(&target)))
            }

            YaraCondition::StringMatchIn(id, start_expr, end_expr) => {
                let bare = id.trim_start_matches('$');
                let start = u64::try_from(Self::eval_expr(start_expr, ctx)?).unwrap_or(u64::MAX);
                let end = u64::try_from(Self::eval_expr(end_expr, ctx)?).unwrap_or(u64::MAX);
                Ok(ctx
                    .string_matches
                    .get(bare)
                    .is_some_and(|v| v.iter().any(|&o| o >= start && o < end)))
            }

            YaraCondition::StringCount(id) => {
                // Evaluates to integer; truthy when > 0
                let bare = id.trim_start_matches('#');
                Ok(ctx.string_count(bare) > 0)
            }

            YaraCondition::StringOffset(id, idx_expr) => {
                let bare = id.trim_start_matches('@');
                let idx = match idx_expr {
                    Some(e) => usize::try_from(Self::eval_expr(e, ctx)?).unwrap_or(0),
                    None => 0,
                };
                Ok(ctx.string_offset(bare, idx).is_some())
            }

            YaraCondition::StringLength(id, idx_expr) => {
                let bare = id.trim_start_matches('!');
                let idx = match idx_expr {
                    Some(e) => usize::try_from(Self::eval_expr(e, ctx)?).unwrap_or(0),
                    None => 0,
                };
                Ok(ctx.string_offset(bare, idx).is_some())
            }

            YaraCondition::Not(inner) => Ok(!Self::eval_condition(inner, ctx)?),

            YaraCondition::And(left, right) => {
                Ok(Self::eval_condition(left, ctx)? && Self::eval_condition(right, ctx)?)
            }

            YaraCondition::Or(left, right) => {
                Ok(Self::eval_condition(left, ctx)? || Self::eval_condition(right, ctx)?)
            }

            YaraCondition::Comparison(lhs, op, rhs) => {
                let l = Self::eval_expr(lhs, ctx)?;
                let r = Self::eval_expr(rhs, ctx)?;
                Ok(match op {
                    CmpOp::Eq => l == r,
                    CmpOp::Ne => l != r,
                    CmpOp::Lt => l < r,
                    CmpOp::Gt => l > r,
                    CmpOp::Le => l <= r,
                    CmpOp::Ge => l >= r,
                })
            }

            YaraCondition::For(count_expr, target, inner_cond) => {
                let required = usize::try_from(Self::eval_expr(count_expr, ctx)?).unwrap_or(0);
                let ids: Vec<String> = match target {
                    ForTarget::AllStrings | ForTarget::AnyStrings => {
                        ctx.string_matches.keys().cloned().collect()
                    }
                    ForTarget::StringSet(ids) => ids
                        .iter()
                        .map(|s| s.trim_start_matches('$').to_string())
                        .collect(),
                    ForTarget::Count(_) => ctx.string_matches.keys().cloned().collect(),
                };
                let mut satisfied = 0usize;
                for id in &ids {
                    // Build a sub-context with only this string's matches
                    let mut sub_ctx = ScanContext::new(ctx.data);
                    sub_ctx.base_address = ctx.base_address;
                    sub_ctx.filesize = ctx.filesize;
                    if let Some(offsets) = ctx.string_matches.get(id) {
                        sub_ctx.string_matches.insert(id.clone(), offsets.clone());
                    }
                    if Self::eval_condition(inner_cond, &sub_ctx)? {
                        satisfied += 1;
                    }
                }
                Ok(satisfied >= required)
            }

            YaraCondition::Expr(expr) => {
                let v = Self::eval_expr(expr, ctx)?;
                Ok(v != 0)
            }
        }
    }

    /// Evaluate a `YaraExpr` to an `i64`.
    ///
    /// # Errors
    ///
    /// Returns [`YaraError::UnknownIdentifier`] if an identifier cannot be
    /// resolved, or [`YaraError::ScanError`] for arithmetic errors.
    pub fn eval_expr(expr: &YaraExpr, ctx: &ScanContext<'_>) -> Result<i64, YaraError> {
        match expr {
            YaraExpr::Integer(n) => Ok(*n),
            YaraExpr::Float(_) => Err(YaraError::ScanError("float cannot be used where integer expected".into())),
            YaraExpr::Bool(b) => Ok(i64::from(*b)),
            YaraExpr::String(_) => Ok(0),
            YaraExpr::FileSize => Ok(ctx.filesize.cast_signed()),
            YaraExpr::At => Ok(ctx.base_address.cast_signed()),

            YaraExpr::Identifier(id) => {
                if id == "filesize" {
                    return Ok(ctx.filesize.cast_signed());
                }
                if id == "entrypoint" {
                    return Ok(ctx.base_address.cast_signed());
                }
                // String count: #str
                if let Some(bare) = id.strip_prefix('#') {
                    return Ok(i64::try_from(ctx.string_count(bare)).unwrap_or(i64::MAX));
                }
                // String offset: @str or @str[n]
                if let Some(stripped) = id.strip_prefix('@') {
                    let bare = stripped.split('[').next().unwrap_or(stripped);
                    return Ok(ctx.string_offset(bare, 0).unwrap_or(0).cast_signed());
                }
                // String length: !str
                if id.starts_with('!') {
                    return Ok(0); // length not tracked in this impl
                }
                Err(YaraError::UnknownIdentifier(id.clone()))
            }

            YaraExpr::Add(l, r) => Ok(Self::eval_expr(l, ctx)? + Self::eval_expr(r, ctx)?),
            YaraExpr::Sub(l, r) => Ok(Self::eval_expr(l, ctx)? - Self::eval_expr(r, ctx)?),
            YaraExpr::Mul(l, r) => Ok(Self::eval_expr(l, ctx)? * Self::eval_expr(r, ctx)?),
            YaraExpr::Div(l, r) => {
                let divisor = Self::eval_expr(r, ctx)?;
                if divisor == 0 {
                    return Err(YaraError::ScanError("division by zero".to_string()));
                }
                Ok(Self::eval_expr(l, ctx)? / divisor)
            }
            YaraExpr::Mod(l, r) => {
                let divisor = Self::eval_expr(r, ctx)?;
                if divisor == 0 {
                    return Err(YaraError::ScanError("modulo by zero".to_string()));
                }
                Ok(Self::eval_expr(l, ctx)? % divisor)
            }
            YaraExpr::BitAnd(l, r) => Ok(Self::eval_expr(l, ctx)? & Self::eval_expr(r, ctx)?),
            YaraExpr::BitOr(l, r) => Ok(Self::eval_expr(l, ctx)? | Self::eval_expr(r, ctx)?),
            YaraExpr::BitXor(l, r) => Ok(Self::eval_expr(l, ctx)? ^ Self::eval_expr(r, ctx)?),
            YaraExpr::BitNot(inner) => Ok(!Self::eval_expr(inner, ctx)?),
            YaraExpr::Shl(l, r) => {
                let shift = Self::eval_expr(r, ctx)?;
                Ok(Self::eval_expr(l, ctx)? << shift)
            }
            YaraExpr::Shr(l, r) => {
                let shift = Self::eval_expr(r, ctx)?;
                Ok(Self::eval_expr(l, ctx)? >> shift)
            }
            YaraExpr::Neg(inner) => Ok(-Self::eval_expr(inner, ctx)?),
            YaraExpr::FuncCall(name, _args) => {
                Err(YaraError::UnknownIdentifier(format!("function: {name}")))
            }
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    // â"€â"€ HexToken parsing â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_hex_parse_exact_bytes() {
        let tokens = YaraParser::parse_hex_pattern("55 8B EC").unwrap();
        assert_eq!(
            tokens,
            vec![
                HexToken::Byte(0x55),
                HexToken::Byte(0x8B),
                HexToken::Byte(0xEC),
            ]
        );
    }

    #[test]
    fn test_hex_parse_wildcard() {
        let tokens = YaraParser::parse_hex_pattern("55 8B ?? 45").unwrap();
        assert_eq!(
            tokens,
            vec![
                HexToken::Byte(0x55),
                HexToken::Byte(0x8B),
                HexToken::Wildcard,
                HexToken::Byte(0x45),
            ]
        );
    }

    #[test]
    fn test_hex_parse_jump_range() {
        let tokens = YaraParser::parse_hex_pattern("55 [0-4] 90").unwrap();
        assert_eq!(
            tokens,
            vec![
                HexToken::Byte(0x55),
                HexToken::Jump(0, 4),
                HexToken::Byte(0x90),
            ]
        );
    }

    #[test]
    fn test_hex_parse_masked_high_nibble() {
        // "4?" —" high nibble 4, low nibble wildcard
        let tokens = YaraParser::parse_hex_pattern("4?").unwrap();
        assert_eq!(tokens, vec![HexToken::Masked(0x40, 0xF0)]);
    }

    #[test]
    fn test_hex_parse_alternation() {
        let tokens = YaraParser::parse_hex_pattern("(AA | BB)").unwrap();
        match &tokens[0] {
            HexToken::Alternation(alts) => {
                assert_eq!(alts.len(), 2);
                assert_eq!(alts[0], vec![HexToken::Byte(0xAA)]);
                assert_eq!(alts[1], vec![HexToken::Byte(0xBB)]);
            }
            other => panic!("expected alternation, got {other:?}"),
        }
    }

    // â"€â"€ StringMatcher::match_hex â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_match_hex_exact() {
        let pattern = vec![
            HexToken::Byte(0x55),
            HexToken::Byte(0x8B),
            HexToken::Byte(0xEC),
        ];
        let data = &[0x00, 0x55, 0x8B, 0xEC, 0xFF];
        let offsets = StringMatcher::match_hex(&pattern, data);
        assert_eq!(offsets, vec![1]);
    }

    #[test]
    fn test_match_hex_wildcard() {
        let pattern = vec![
            HexToken::Byte(0xAA),
            HexToken::Wildcard,
            HexToken::Byte(0xBB),
        ];
        let data = &[0xAA, 0x99, 0xBB, 0xAA, 0x00, 0xBB];
        let offsets = StringMatcher::match_hex(&pattern, data);
        assert_eq!(offsets, vec![0, 3]);
    }

    #[test]
    fn test_match_hex_jump() {
        // pattern: 0x55 [0-2] 0x90 —" matches 0x55 followed by 0—"2 bytes then 0x90
        let pattern = vec![
            HexToken::Byte(0x55),
            HexToken::Jump(0, 2),
            HexToken::Byte(0x90),
        ];
        let data = &[0x55, 0x90, 0x00, 0x55, 0xFF, 0x90];
        let offsets = StringMatcher::match_hex(&pattern, data);
        assert!(offsets.contains(&0), "should match at 0 (jump 0)");
        assert!(offsets.contains(&3), "should match at 3 (jump 2)");
    }

    // â"€â"€ StringMatcher::match_text â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_match_text_simple_ascii() {
        let mods = StringModifiers::default();
        let data = b"hello world hello";
        let offsets = StringMatcher::match_text("hello", &mods, data);
        assert_eq!(offsets, vec![0, 12]);
    }

    #[test]
    fn test_match_nocase() {
        let data = b"Hello HELLO hello";
        let offsets = StringMatcher::match_nocase("hello", data);
        assert_eq!(offsets, vec![0, 6, 12]);
    }

    #[test]
    fn test_match_wide_utf16() {
        // "AB" in UTF-16 LE: 0x41 0x00 0x42 0x00
        let data: &[u8] = &[0x41, 0x00, 0x42, 0x00, 0x43, 0x00];
        let offsets = StringMatcher::match_wide("AB", data);
        assert_eq!(offsets, vec![0]);
    }

    #[test]
    fn test_match_xor_obfuscated() {
        // "hello" XOR 0x01 â†' each byte shifted by 1
        let key = 0x01u8;
        let plain = b"hello";
        let xored: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let data = xored.as_slice();
        let hits = StringMatcher::match_xor("hello", 0x00, 0x10, data);
        assert!(!hits.is_empty(), "should find XOR match");
        assert!(hits.iter().any(|&(off, k)| off == 0 && k == key));
    }

    #[test]
    fn test_check_fullword_bounded() {
        let data = b"hello world";
        // "hello" at offset 0 is bounded by start and space
        assert!(StringMatcher::check_fullword(data, 0, 5));
        // "ello" at offset 1 is NOT fullword (preceded by 'h')
        assert!(!StringMatcher::check_fullword(data, 1, 4));
    }

    #[test]
    fn test_match_masked_byte() {
        // High nibble 0x4, low nibble wildcard: mask = 0xF0, value = 0x40
        // Should match 0x40..0x4F
        assert!(StringMatcher::match_masked_byte(0x40, 0xF0, 0x4A));
        assert!(!StringMatcher::match_masked_byte(0x40, 0xF0, 0x5A));
    }

    // â"€â"€ YaraParser â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_parse_minimal_rule_with_text_string() {
        let src = r#"
            rule test_rule {
                strings:
                    $a = "hello"
                condition:
                    $a
            }
        "#;
        let ruleset = YaraParser::parse(src).unwrap();
        assert_eq!(ruleset.rule_count(), 1);
        let rule = &ruleset.rules[0];
        assert_eq!(rule.name, "test_rule");
        assert_eq!(rule.strings.len(), 1);
        assert_eq!(rule.strings[0].identifier, "$a");
        match &rule.strings[0].pattern {
            YaraPattern::Text(t) => assert_eq!(t, "hello"),
            other => panic!("expected Text pattern, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_hex_pattern_rule() {
        let src = r"
            rule hex_rule {
                strings:
                    $a = { 55 8B EC }
                condition:
                    $a
            }
        ";
        let rule = YaraParser::parse_rule(src).unwrap();
        assert_eq!(rule.strings.len(), 1);
        match &rule.strings[0].pattern {
            YaraPattern::Hex(tokens) => {
                assert_eq!(
                    tokens,
                    &[
                        HexToken::Byte(0x55),
                        HexToken::Byte(0x8B),
                        HexToken::Byte(0xEC),
                    ]
                );
            }
            other => panic!("expected Hex pattern, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_meta_section() {
        let body = r#"
            meta:
                author = "Alice"
                score = 42
                is_malware = true
            condition:
                true
        "#;
        let meta = YaraParser::parse_meta_section(body).unwrap();
        assert_eq!(meta.len(), 3);
        assert_eq!(meta[0].key, "author");
        matches!(&meta[0].value, YaraMetaValue::String(s) if s == "Alice");
        matches!(&meta[1].value, YaraMetaValue::Integer(42));
        matches!(&meta[2].value, YaraMetaValue::Bool(true));
    }

    // â"€â"€ YaraScanner â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_scan_finds_match_text_string() {
        let src = r#"
            rule find_hello {
                strings:
                    $greet = "hello"
                condition:
                    $greet
            }
        "#;
        let scanner = YaraScanner::from_rules_text(src).unwrap();
        let data = b"some data with hello inside";
        let matches = scanner.scan(data).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "find_hello");
    }

    #[test]
    fn test_scan_no_match_when_string_absent() {
        let src = r#"
            rule find_xyz {
                strings:
                    $s = "xyz_not_present"
                condition:
                    $s
            }
        "#;
        let scanner = YaraScanner::from_rules_text(src).unwrap();
        let data = b"this data does not contain the pattern";
        let matches = scanner.scan(data).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_any_of_them() {
        let src = r#"
            rule any_test {
                strings:
                    $a = "alpha"
                    $b = "beta"
                condition:
                    any of them
            }
        "#;
        let scanner = YaraScanner::from_rules_text(src).unwrap();
        let data = b"only beta here";
        let matches = scanner.scan(data).unwrap();
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_scan_all_of_them() {
        let src = r#"
            rule all_test {
                strings:
                    $a = "foo"
                    $b = "bar"
                condition:
                    all of them
            }
        "#;
        let scanner = YaraScanner::from_rules_text(src).unwrap();
        // Only one string present
        let data_partial = b"only foo here";
        assert!(scanner.scan(data_partial).unwrap().is_empty());
        // Both strings present
        let data_both = b"foo and bar";
        assert_eq!(scanner.scan(data_both).unwrap().len(), 1);
    }

    #[test]
    fn test_scan_string_count_condition() {
        // Build the rule programmatically to test count-based condition
        let mut rule = YaraRule::new("count_rule");
        rule.strings.push(YaraString {
            identifier: "$a".to_string(),
            pattern: YaraPattern::Text("hello".to_string()),
            modifiers: StringModifiers::default(),
        });
        // condition: #a > 2
        rule.condition = YaraCondition::Comparison(
            Box::new(YaraExpr::Identifier("#a".to_string())),
            CmpOp::Gt,
            Box::new(YaraExpr::Integer(2)),
        );
        let mut ruleset = YaraRuleSet::new();
        ruleset.add_rule(rule);
        let scanner = YaraScanner::new(ruleset);
        let data_two = b"hello hello";
        assert!(
            scanner.scan(data_two).unwrap().is_empty(),
            "2 hits is not > 2"
        );
        let data_three = b"hello hello hello";
        assert_eq!(scanner.scan(data_three).unwrap().len(), 1);
    }

    #[test]
    fn test_scan_filesize_condition() {
        let mut rule = YaraRule::new("size_rule");
        rule.condition = YaraCondition::Comparison(
            Box::new(YaraExpr::FileSize),
            CmpOp::Gt,
            Box::new(YaraExpr::Integer(10)),
        );
        let mut ruleset = YaraRuleSet::new();
        ruleset.add_rule(rule);
        let scanner = YaraScanner::new(ruleset);
        assert!(scanner.scan(b"short").unwrap().is_empty());
        assert_eq!(scanner.scan(b"longer than ten bytes").unwrap().len(), 1);
    }

    #[test]
    fn test_evaluate_rule_false_when_string_missing() {
        let mut rule = YaraRule::new("no_match");
        rule.strings.push(YaraString {
            identifier: "$s".to_string(),
            pattern: YaraPattern::Text("MISSING".to_string()),
            modifiers: StringModifiers::default(),
        });
        rule.condition = YaraCondition::StringMatch("$s".to_string());
        let scanner = YaraScanner::new(YaraRuleSet::new());
        let ctx = ScanContext::new(b"no match here");
        assert!(!scanner.evaluate_rule(&rule, &ctx).unwrap());
    }

    #[test]
    fn test_yara_match_string_matches_populated() {
        let src = r#"
            rule populated {
                strings:
                    $marker = "MARKER"
                condition:
                    $marker
            }
        "#;
        let scanner = YaraScanner::from_rules_text(src).unwrap();
        let data = b"data with MARKER inside";
        let matches = scanner.scan(data).unwrap();
        assert_eq!(matches.len(), 1);
        let m = &matches[0];
        assert!(!m.strings.is_empty());
        assert_eq!(m.strings[0].identifier, "$marker");
        assert_eq!(m.strings[0].offset, 10);
    }

    #[test]
    fn test_yara_rule_description_from_meta() {
        let mut rule = YaraRule::new("described_rule");
        rule.meta.push(YaraMeta {
            key: "description".to_string(),
            value: YaraMetaValue::String("Detects evil things".to_string()),
        });
        assert_eq!(rule.description(), Some("Detects evil things".to_string()));
        assert_eq!(rule.author(), None);
    }

    #[test]
    fn test_rule_author_and_date_meta() {
        let src = r#"
            rule meta_test {
                meta:
                    author = "Bob"
                    date = "2024-01-01"
                    description = "test rule"
                condition:
                    true
            }
        "#;
        let rule = YaraParser::parse_rule(src).unwrap();
        assert_eq!(rule.author(), Some("Bob".to_string()));
        assert_eq!(rule.date(), Some("2024-01-01".to_string()));
        assert_eq!(rule.description(), Some("test rule".to_string()));
    }

    #[test]
    fn test_ruleset_rule_by_name() {
        let mut rs = YaraRuleSet::new();
        rs.add_rule(YaraRule::new("alpha"));
        rs.add_rule(YaraRule::new("beta"));
        assert!(rs.rule_by_name("alpha").is_some());
        assert!(rs.rule_by_name("gamma").is_none());
    }

    #[test]
    fn test_scan_and_or_conditions() {
        // rule matching (foo AND bar) OR baz
        let mut rule = YaraRule::new("logic_test");
        rule.strings.push(YaraString {
            identifier: "$foo".to_string(),
            pattern: YaraPattern::Text("foo".to_string()),
            modifiers: StringModifiers::default(),
        });
        rule.strings.push(YaraString {
            identifier: "$bar".to_string(),
            pattern: YaraPattern::Text("bar".to_string()),
            modifiers: StringModifiers::default(),
        });
        rule.strings.push(YaraString {
            identifier: "$baz".to_string(),
            pattern: YaraPattern::Text("baz".to_string()),
            modifiers: StringModifiers::default(),
        });
        rule.condition = YaraCondition::Or(
            Box::new(YaraCondition::And(
                Box::new(YaraCondition::StringMatch("$foo".to_string())),
                Box::new(YaraCondition::StringMatch("$bar".to_string())),
            )),
            Box::new(YaraCondition::StringMatch("$baz".to_string())),
        );
        let mut rs = YaraRuleSet::new();
        rs.add_rule(rule);
        let scanner = YaraScanner::new(rs);
        // "foo bar" â†' AND branch matches
        assert_eq!(scanner.scan(b"foo bar").unwrap().len(), 1);
        // "baz only" â†' OR branch matches
        assert_eq!(scanner.scan(b"baz only").unwrap().len(), 1);
        // "neither" â†' no match
        assert!(scanner.scan(b"neither").unwrap().is_empty());
    }

    #[test]
    fn test_hex_match_in_larger_buffer() {
        let pattern = YaraParser::parse_hex_pattern("DE AD BE EF").unwrap();
        let mut data = vec![0u8; 128];
        data[64] = 0xDE;
        data[65] = 0xAD;
        data[66] = 0xBE;
        data[67] = 0xEF;
        let offsets = StringMatcher::match_hex(&pattern, &data);
        assert_eq!(offsets, vec![64]);
    }

    #[test]
    fn test_string_modifiers_default_ascii_true() {
        let mods = StringModifiers::default();
        assert!(mods.ascii());
        assert!(!mods.nocase());
        assert!(!mods.wide());
        assert!(!mods.fullword());
        assert!(!mods.is_private());
        assert!(mods.xor.is_none());
    }

    #[test]
    fn test_parse_string_modifiers_nocase_wide() {
        let tokens = &["nocase", "wide"];
        let mods = YaraParser::parse_string_modifiers(tokens);
        assert!(mods.nocase());
        assert!(mods.wide());
    }

    #[test]
    fn test_error_display() {
        let e = YaraError::ParseError {
            line: 5,
            message: "oops".to_string(),
        };
        assert_eq!(e.to_string(), "parse error at line 5: oops");
        let e2 = YaraError::UnknownIdentifier("foo".to_string());
        assert_eq!(e2.to_string(), "unknown identifier: foo");
    }
}

// ────────────────────────────────────────────────────────────────────────────
// YaraConfig
// ────────────────────────────────────────────────────────────────────────────

/// Runtime configuration that controls scanner behaviour.
#[derive(Debug, Clone)]
pub struct YaraConfig {
    /// Maximum time allowed for a single scan in milliseconds.
    /// 0 means no limit.
    pub timeout_ms: u32,
    /// Maximum number of string matches stored per rule (0 = unlimited).
    pub max_strings: u32,
    /// When `true` the scanner is permitted to read process virtual memory
    /// rather than a file buffer.  Requires elevated privileges on most
    /// platforms.
    pub scan_process_memory: bool,
}

impl Default for YaraConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 60_000,
            max_strings: 1_000,
            scan_process_memory: false,
        }
    }
}

impl YaraConfig {
    /// Create a new config with sensible defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the scan timeout in milliseconds and return `self` for chaining.
    #[must_use]
    pub const fn with_timeout(mut self, ms: u32) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Set the maximum number of string matches and return `self`.
    #[must_use]
    pub const fn with_max_strings(mut self, n: u32) -> Self {
        self.max_strings = n;
        self
    }

    /// Enable or disable process-memory scanning.
    #[must_use]
    pub const fn with_process_memory(mut self, enabled: bool) -> Self {
        self.scan_process_memory = enabled;
        self
    }

    /// Returns `true` when a timeout limit is configured.
    #[must_use]
    pub const fn has_timeout(&self) -> bool {
        self.timeout_ms > 0
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Severity
// ────────────────────────────────────────────────────────────────────────────

/// Severity classification derived from YARA rule tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// No matches, or tags indicate informational rules only.
    Info,
    /// At least one match tagged as low-severity (e.g. `"suspicious"`).
    Low,
    /// At least one match tagged as medium-severity (e.g. `"packer"`).
    Medium,
    /// At least one match tagged as high-severity (e.g. `"malware"`).
    High,
    /// At least one match tagged as critical (e.g. `"ransomware"`, `"exploit"`).
    Critical,
}

impl Severity {
    /// Return a human-readable label for this severity.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    /// Derive a `Severity` from a slice of tag strings.
    /// Higher-severity tags take precedence.
    #[must_use]
    pub fn from_tags(tags: &[String]) -> Self {
        let mut result = Self::Info;
        for tag in tags {
            let s = match tag.to_lowercase().as_str() {
                "ransomware" | "exploit" | "rootkit" | "critical" => Self::Critical,
                "malware" | "trojan" | "backdoor" | "high" => Self::High,
                "packer" | "protector" | "obfuscated" | "medium" => Self::Medium,
                "suspicious" | "low" | "greyware" => Self::Low,
                _ => Self::Info,
            };
            if s > result {
                result = s;
            }
        }
        result
    }
}

// ────────────────────────────────────────────────────────────────────────────
// YaraMatch improvements
// ────────────────────────────────────────────────────────────────────────────

impl YaraMatch {
    /// Serialise this match to a `serde_json::Value` map.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let strings: Vec<serde_json::Value> = self
            .strings
            .iter()
            .map(|sm| {
                serde_json::json!({
                    "identifier": sm.identifier,
                    "offset": sm.offset,
                    "length": sm.length,
                    "data_hex": sm.data.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
                    "xor_key": sm.xor_key,
                })
            })
            .collect();

        let meta: Vec<serde_json::Value> = self
            .meta
            .iter()
            .map(|m| {
                let val = match &m.value {
                    YaraMetaValue::String(s) => serde_json::Value::String(s.clone()),
                    YaraMetaValue::Integer(n) => serde_json::json!(n),
                    YaraMetaValue::Bool(b) => serde_json::Value::Bool(*b),
                };
                serde_json::json!({ "key": m.key, "value": val })
            })
            .collect();

        serde_json::json!({
            "rule_name": self.rule_name,
            "namespace": self.namespace,
            "tags": self.tags,
            "meta": meta,
            "strings": strings,
        })
    }

    /// Return the byte offset of the first matched pattern string, or `None`
    /// if no pattern strings were captured.
    #[must_use]
    pub fn first_pattern_offset(&self) -> Option<u64> {
        self.strings.iter().map(|s| s.offset).min()
    }

    /// Return `true` when this match has a tag whose value equals `tag`
    /// (case-insensitive).
    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        let lower = tag.to_lowercase();
        self.tags.iter().any(|t| t.to_lowercase() == lower)
    }

    /// Collect all tags across this match's tags list.
    #[must_use]
    pub fn all_tags(&self) -> &[String] {
        &self.tags
    }

    /// Return the severity of this match based on its tags.
    #[must_use]
    pub fn severity(&self) -> Severity {
        Severity::from_tags(&self.tags)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// YaraScanReport
// ────────────────────────────────────────────────────────────────────────────

/// Aggregated result for scanning a single artifact.
#[derive(Debug, Clone)]
pub struct YaraScanReport {
    /// Path of the scanned file, if available.
    pub file_path: Option<String>,
    /// Wall-clock time the scan took in milliseconds.
    pub scan_time_ms: u64,
    /// All rule matches found during the scan.
    pub matches: Vec<YaraMatch>,
    /// Total number of rules evaluated during the scan.
    pub total_rules_evaluated: u32,
    /// Number of rules that produced at least one match.
    pub matched_rule_count: u32,
}

impl YaraScanReport {
    /// Create a new scan report.
    #[must_use]
    pub fn new(
        file_path: Option<String>,
        scan_time_ms: u64,
        matches: Vec<YaraMatch>,
        total_rules_evaluated: u32,
    ) -> Self {
        let matched_rule_count = u32::try_from(matches.len()).unwrap_or(u32::MAX);
        Self {
            file_path,
            scan_time_ms,
            matches,
            total_rules_evaluated,
            matched_rule_count,
        }
    }

    /// Derive the overall severity of the report from the highest-severity
    /// match found.
    #[must_use]
    pub fn severity(&self) -> Severity {
        self.matches
            .iter()
            .map(YaraMatch::severity)
            .max()
            .unwrap_or(Severity::Info)
    }

    /// Return `true` when no rules matched.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.matches.is_empty()
    }

    /// Format the report as a Markdown document suitable for human review.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        let path = self.file_path.as_deref().unwrap_or("<buffer>");

        out.push_str("# YARA Scan Report\n\n");
        let _ = writeln!(out, "**File:** `{path}`");
        let _ = writeln!(out, "**Scan time:** {} ms", self.scan_time_ms);
        let _ = writeln!(out, "**Rules evaluated:** {}", self.total_rules_evaluated);
        let _ = writeln!(out, "**Rules matched:** {}", self.matched_rule_count);
        let _ = writeln!(out, "**Severity:** {}\n", self.severity().label());

        if self.matches.is_empty() {
            out.push_str("No matches found.\n");
            return out;
        }

        out.push_str("## Matches\n\n");
        for (i, m) in self.matches.iter().enumerate() {
            let _ = writeln!(out, "### {}. `{}`\n", i + 1, m.rule_name);
            if !m.tags.is_empty() {
                let _ = writeln!(out, "**Tags:** {}\n", m.tags.join(", "));
            }
            for meta in &m.meta {
                let val = match &meta.value {
                    YaraMetaValue::String(s) => format!("`\"{s}\"`"),
                    YaraMetaValue::Integer(n) => format!("`{n}`"),
                    YaraMetaValue::Bool(b) => format!("`{b}`"),
                };
                let _ = writeln!(out, "- **{}**: {}", meta.key, val);
            }
            if !m.strings.is_empty() {
                out.push_str("\n**Matched strings:**\n\n");
                out.push_str("| Identifier | Offset | Length | Hex Preview |\n");
                out.push_str("|---|---|---|---|\n");
                for sm in &m.strings {
                    let preview: String = sm
                        .data
                        .iter()
                        .take(16)
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let _ = writeln!(
                        out,
                        "| `{}` | 0x{:08x} | {} | `{}` |",
                        sm.identifier, sm.offset, sm.length, preview
                    );
                }
            }
            out.push('\n');
        }
        out
    }

    /// Serialise the report to JSON.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "file_path": self.file_path,
            "scan_time_ms": self.scan_time_ms,
            "total_rules_evaluated": self.total_rules_evaluated,
            "matched_rule_count": self.matched_rule_count,
            "severity": self.severity().label(),
            "matches": self.matches.iter().map(YaraMatch::to_json).collect::<Vec<_>>(),
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ScanBatch
// ────────────────────────────────────────────────────────────────────────────

/// Utilities for scanning a whole directory tree.
pub struct ScanBatch;

impl ScanBatch {
    /// Walk `dir` recursively, scan each regular file with `scanner`, and
    /// return a vector of `(path, report)` pairs.
    ///
    /// Files that cannot be read are silently skipped.
    #[must_use]
    pub fn scan_directory(
        dir: &std::path::Path,
        scanner: &YaraScanner,
    ) -> Vec<(std::path::PathBuf, YaraScanReport)> {
        let mut results = Vec::new();
        Self::walk(dir, scanner, &mut results);
        results
    }

    fn walk(
        dir: &std::path::Path,
        scanner: &YaraScanner,
        acc: &mut Vec<(std::path::PathBuf, YaraScanReport)>,
    ) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                Self::walk(&path, scanner, acc);
            } else if path.is_file() {
                let Ok(data) = std::fs::read(&path) else { continue };
                let t0 = std::time::Instant::now();
                let matches = scanner.scan(&data).unwrap_or_default();
                let elapsed = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
                let total = u32::try_from(scanner.rules.rule_count()).unwrap_or(u32::MAX);
                let report = YaraScanReport::new(
                    Some(path.to_string_lossy().into_owned()),
                    elapsed,
                    matches,
                    total,
                );
                acc.push((path, report));
            }
        }
    }

    /// Filter a slice of `(path, report)` pairs, keeping only those where at
    /// least one rule matched.
    #[must_use]
    pub fn filter_interesting(
        reports: &[(std::path::PathBuf, YaraScanReport)],
    ) -> Vec<&(std::path::PathBuf, YaraScanReport)> {
        reports.iter().filter(|(_, r)| !r.is_clean()).collect()
    }

    /// Return the total number of matches across all reports.
    #[must_use]
    pub fn total_matches(reports: &[(std::path::PathBuf, YaraScanReport)]) -> usize {
        reports.iter().map(|(_, r)| r.matches.len()).sum()
    }

    /// Return all reports whose overall severity is at least `min_severity`.
    #[must_use]
    pub fn filter_by_severity(
        reports: &[(std::path::PathBuf, YaraScanReport)],
        min_severity: Severity,
    ) -> Vec<&(std::path::PathBuf, YaraScanReport)> {
        reports
            .iter()
            .filter(|(_, r)| r.severity() >= min_severity)
            .collect()
    }

    /// Produce a compact summary string listing the match counts per file.
    #[must_use]
    pub fn summary(reports: &[(std::path::PathBuf, YaraScanReport)]) -> String {
        let mut lines = Vec::new();
        for (path, report) in reports {
            if !report.is_clean() {
                lines.push(format!(
                    "{}: {} match(es) [{}]",
                    path.display(),
                    report.matched_rule_count,
                    report.severity().label()
                ));
            }
        }
        if lines.is_empty() {
            "No matches found in any scanned file.".to_string()
        } else {
            lines.join("\n")
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Additional tests for new types
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod new_tests {
    use super::*;

    // ── YaraConfig ──────────────────────────────────────────────────────────

    #[test]
    fn yara_config_default_values() {
        let cfg = YaraConfig::default();
        assert_eq!(cfg.timeout_ms, 60_000);
        assert_eq!(cfg.max_strings, 1_000);
        assert!(!cfg.scan_process_memory);
        assert!(cfg.has_timeout());
    }

    #[test]
    fn yara_config_builder_chain() {
        let cfg = YaraConfig::new()
            .with_timeout(5_000)
            .with_max_strings(500)
            .with_process_memory(true);
        assert_eq!(cfg.timeout_ms, 5_000);
        assert_eq!(cfg.max_strings, 500);
        assert!(cfg.scan_process_memory);
    }

    #[test]
    fn yara_config_zero_timeout_has_no_limit() {
        let cfg = YaraConfig::new().with_timeout(0);
        assert!(!cfg.has_timeout());
    }

    // ── Severity ────────────────────────────────────────────────────────────

    #[test]
    fn severity_from_tags_empty() {
        let s = Severity::from_tags(&[]);
        assert_eq!(s, Severity::Info);
    }

    #[test]
    fn severity_from_tags_critical() {
        let tags = vec!["ransomware".to_string(), "packer".to_string()];
        assert_eq!(Severity::from_tags(&tags), Severity::Critical);
    }

    #[test]
    fn severity_from_tags_high() {
        let tags = vec!["malware".to_string()];
        assert_eq!(Severity::from_tags(&tags), Severity::High);
    }

    #[test]
    fn severity_from_tags_medium() {
        let tags = vec!["packer".to_string()];
        assert_eq!(Severity::from_tags(&tags), Severity::Medium);
    }

    #[test]
    fn severity_from_tags_low() {
        let tags = vec!["suspicious".to_string()];
        assert_eq!(Severity::from_tags(&tags), Severity::Low);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_labels() {
        assert_eq!(Severity::Info.label(), "INFO");
        assert_eq!(Severity::Low.label(), "LOW");
        assert_eq!(Severity::Medium.label(), "MEDIUM");
        assert_eq!(Severity::High.label(), "HIGH");
        assert_eq!(Severity::Critical.label(), "CRITICAL");
    }

    // ── YaraMatch improvements ───────────────────────────────────────────────

    fn make_match(rule: &str, tags: Vec<&str>) -> YaraMatch {
        YaraMatch {
            rule_name: rule.to_string(),
            tags: tags.iter().map(std::string::ToString::to_string).collect(),
            meta: Vec::new(),
            strings: Vec::new(),
            namespace: String::new(),
        }
    }

    #[test]
    fn yara_match_has_tag_found() {
        let m = make_match("r", vec!["malware", "packer"]);
        assert!(m.has_tag("malware"));
        assert!(m.has_tag("MALWARE")); // case insensitive
    }

    #[test]
    fn yara_match_has_tag_not_found() {
        let m = make_match("r", vec!["packer"]);
        assert!(!m.has_tag("ransomware"));
    }

    #[test]
    fn yara_match_first_pattern_offset_none_when_no_strings() {
        let m = make_match("r", vec![]);
        assert_eq!(m.first_pattern_offset(), None);
    }

    #[test]
    fn yara_match_first_pattern_offset_returns_min() {
        let mut m = make_match("r", vec![]);
        m.strings.push(StringMatch {
            identifier: "$a".to_string(),
            offset: 100,
            length: 4,
            data: vec![0u8; 4],
            xor_key: None,
        });
        m.strings.push(StringMatch {
            identifier: "$b".to_string(),
            offset: 42,
            length: 4,
            data: vec![0u8; 4],
            xor_key: None,
        });
        assert_eq!(m.first_pattern_offset(), Some(42));
    }

    #[test]
    fn yara_match_to_json_structure() {
        let m = make_match("test_rule", vec!["packer"]);
        let json = m.to_json();
        assert_eq!(json["rule_name"], "test_rule");
        assert!(json["tags"].is_array());
        assert!(json["strings"].is_array());
    }

    #[test]
    fn yara_match_severity_derived_from_tags() {
        let m = make_match("r", vec!["trojan"]);
        assert_eq!(m.severity(), Severity::High);
    }

    // ── YaraScanReport ───────────────────────────────────────────────────────

    #[test]
    fn scan_report_clean_when_no_matches() {
        let r = YaraScanReport::new(None, 10, vec![], 5);
        assert!(r.is_clean());
        assert_eq!(r.severity(), Severity::Info);
    }

    #[test]
    fn scan_report_not_clean_with_matches() {
        let m = make_match("r", vec!["malware"]);
        let r = YaraScanReport::new(Some("test.exe".to_string()), 50, vec![m], 10);
        assert!(!r.is_clean());
        assert_eq!(r.matched_rule_count, 1);
        assert_eq!(r.severity(), Severity::High);
    }

    #[test]
    fn scan_report_to_markdown_clean() {
        let r = YaraScanReport::new(Some("clean.exe".into()), 5, vec![], 3);
        let md = r.to_markdown();
        assert!(md.contains("clean.exe"));
        assert!(md.contains("No matches found"));
    }

    #[test]
    fn scan_report_to_markdown_with_matches() {
        let m = make_match("detect_upx", vec!["packer"]);
        let r = YaraScanReport::new(Some("packed.exe".into()), 20, vec![m], 5);
        let md = r.to_markdown();
        assert!(md.contains("detect_upx"));
        assert!(md.contains("MEDIUM"));
    }

    #[test]
    fn scan_report_to_json_structure() {
        let r = YaraScanReport::new(None, 0, vec![], 0);
        let j = r.to_json();
        assert!(j["matches"].is_array());
        assert_eq!(j["severity"], "INFO");
    }

    // ── ScanBatch ────────────────────────────────────────────────────────────

    #[test]
    fn scan_batch_filter_interesting_empty() {
        let reports: Vec<(std::path::PathBuf, YaraScanReport)> = vec![];
        let interesting = ScanBatch::filter_interesting(&reports);
        assert!(interesting.is_empty());
    }

    #[test]
    fn scan_batch_filter_interesting_keeps_matches() {
        let m = make_match("r", vec![]);
        let path = std::path::PathBuf::from("file.exe");
        let report = YaraScanReport::new(None, 0, vec![m], 1);
        let reports = vec![(path, report)];
        let interesting = ScanBatch::filter_interesting(&reports);
        assert_eq!(interesting.len(), 1);
    }

    #[test]
    fn scan_batch_filter_interesting_excludes_clean() {
        let path = std::path::PathBuf::from("clean.bin");
        let report = YaraScanReport::new(None, 0, vec![], 5);
        let reports = vec![(path, report)];
        let interesting = ScanBatch::filter_interesting(&reports);
        assert!(interesting.is_empty());
    }

    #[test]
    fn scan_batch_total_matches_sums_across_reports() {
        let m1 = make_match("r1", vec![]);
        let m2 = make_match("r2", vec![]);
        let m3 = make_match("r3", vec![]);
        let reports = vec![
            (
                std::path::PathBuf::from("a"),
                YaraScanReport::new(None, 0, vec![m1, m2], 10),
            ),
            (
                std::path::PathBuf::from("b"),
                YaraScanReport::new(None, 0, vec![m3], 10),
            ),
        ];
        assert_eq!(ScanBatch::total_matches(&reports), 3);
    }

    #[test]
    fn scan_batch_filter_by_severity() {
        let low = make_match("low_rule", vec!["suspicious"]);
        let high = make_match("high_rule", vec!["malware"]);
        let reports = vec![
            (
                std::path::PathBuf::from("a"),
                YaraScanReport::new(None, 0, vec![low], 5),
            ),
            (
                std::path::PathBuf::from("b"),
                YaraScanReport::new(None, 0, vec![high], 5),
            ),
        ];
        let high_only = ScanBatch::filter_by_severity(&reports, Severity::High);
        assert_eq!(high_only.len(), 1);
    }

    #[test]
    fn scan_batch_summary_no_matches() {
        let reports = vec![(
            std::path::PathBuf::from("clean.exe"),
            YaraScanReport::new(None, 0, vec![], 5),
        )];
        let s = ScanBatch::summary(&reports);
        assert!(s.contains("No matches"));
    }

    #[test]
    fn scan_batch_summary_with_matches() {
        let m = make_match("rule1", vec!["packer"]);
        let reports = vec![(
            std::path::PathBuf::from("packed.exe"),
            YaraScanReport::new(None, 0, vec![m], 5),
        )];
        let s = ScanBatch::summary(&reports);
        assert!(s.contains("packed.exe"));
        assert!(s.contains("MEDIUM"));
    }
}
