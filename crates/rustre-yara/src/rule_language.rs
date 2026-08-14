//! YARA rule language AST.
//!
//! Defines the full abstract syntax tree for YARA rules: declarations,
//! metadata sections, string declarations with modifiers, and condition
//! expressions.  Provides a simple recursive-descent parser for rule text.

use std::collections::HashMap;
use std::fmt;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleLangError {
    UnexpectedToken { line: usize, found: String, expected: &'static str },
    UnterminatedString(usize),
    InvalidEscape { line: usize, ch: char },
    DuplicateIdentifier(String),
    UnknownModifier(String),
    EmptyCondition,
}

impl fmt::Display for RuleLangError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedToken { line, found, expected } => {
                write!(f, "line {line}: unexpected {found:?}, expected {expected}")
            }
            Self::UnterminatedString(line) => write!(f, "line {line}: unterminated string"),
            Self::InvalidEscape { line, ch } => {
                write!(f, "line {line}: invalid escape \\{ch}")
            }
            Self::DuplicateIdentifier(id) => write!(f, "duplicate identifier: {id}"),
            Self::UnknownModifier(m) => write!(f, "unknown string modifier: {m}"),
            Self::EmptyCondition => write!(f, "rule has an empty condition"),
        }
    }
}

pub type LangResult<T> = Result<T, RuleLangError>;

// ── String modifiers ──────────────────────────────────────────────────────────

/// Modifiers that can be applied to a YARA string declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringMod {
    /// Encoding options: nocase, wide, ascii.
    pub encoding: crate::StringEncodingOpts,
    /// Output options: fullword, private, base64.
    pub output: crate::StringOutputOpts,
    /// Whether the `xor` modifier is present.
    pub xor: bool,
    /// Whether the `base64wide` modifier is present.
    pub base64wide: bool,
    /// XOR key range [min, max], only valid when `xor` is true.
    pub xor_range: Option<(u8, u8)>,
}

impl Default for StringMod {
    fn default() -> Self {
        Self {
            encoding: crate::StringEncodingOpts { nocase: false, wide: false, ascii: false },
            output: crate::StringOutputOpts::default(),
            xor: false,
            base64wide: false,
            xor_range: None,
        }
    }
}

impl StringMod {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a modifier name.
    ///
    /// # Errors
    ///
    /// Returns [`RuleLangError::UnknownModifier`] for unrecognised modifier names.
    pub fn apply(&mut self, name: &str) -> LangResult<()> {
        match name {
            "nocase" => self.encoding.nocase = true,
            "wide" => self.encoding.wide = true,
            "ascii" => self.encoding.ascii = true,
            "fullword" => self.output.fullword = true,
            "xor" => self.xor = true,
            "base64" => self.output.base64 = true,
            "base64wide" => self.base64wide = true,
            "private" => self.output.private = true,
            _ => return Err(RuleLangError::UnknownModifier(name.to_owned())),
        }
        Ok(())
    }

    /// Returns a keyword list for display.
    #[must_use]
    pub fn keywords(&self) -> Vec<&'static str> {
        let mut kw = Vec::new();
        if self.encoding.nocase { kw.push("nocase"); }
        if self.encoding.wide { kw.push("wide"); }
        if self.encoding.ascii { kw.push("ascii"); }
        if self.output.fullword { kw.push("fullword"); }
        if self.xor { kw.push("xor"); }
        if self.output.base64 { kw.push("base64"); }
        if self.base64wide { kw.push("base64wide"); }
        if self.output.private { kw.push("private"); }
        kw
    }
}

impl fmt::Display for StringMod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.keywords().join(" "))
    }
}

// ── Hex token (for hex strings) ───────────────────────────────────────────────

/// One token in a hex string pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexToken {
    /// A concrete byte value.
    Byte(u8),
    /// A wildcard (`?`).
    Wildcard,
    /// A nibble wildcard — high or low nibble fixed.
    NibbleLow(u8),
    NibbleHigh(u8),
    /// Jump: {n} or {n-m}.
    Jump(u32, Option<u32>),
    /// Alternative group: `(AA | BB)`.
    Alt(Vec<Vec<Self>>),
}

impl fmt::Display for HexToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Byte(b) => write!(f, "{b:02X}"),
            Self::Wildcard => write!(f, "??"),
            Self::NibbleLow(n) => write!(f, "?{n:X}"),
            Self::NibbleHigh(n) => write!(f, "{n:X}?"),
            Self::Jump(min, None) => write!(f, "{{{min}}}"),
            Self::Jump(min, Some(max)) => write!(f, "{{{min}-{max}}}"),
            Self::Alt(alts) => {
                let strs: Vec<String> = alts
                    .iter()
                    .map(|a| a.iter().map(std::string::ToString::to_string).collect::<String>())
                    .collect();
                write!(f, "({})", strs.join(" | "))
            }
        }
    }
}

// ── String declaration ────────────────────────────────────────────────────────

/// The content of a YARA string declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringContent {
    /// A text string literal.
    Text(String),
    /// A hex byte pattern.
    Hex(Vec<HexToken>),
    /// A regular expression.
    Regex(String),
}

impl fmt::Display for StringContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(s) => write!(f, "\"{s}\""),
            Self::Hex(tokens) => {
                let inner: String = tokens.iter().map(std::string::ToString::to_string).collect::<Vec<_>>().join(" ");
                write!(f, "{{ {inner} }}")
            }
            Self::Regex(r) => write!(f, "/{r}/"),
        }
    }
}

/// One string declaration in the `strings:` section.
#[derive(Debug, Clone)]
pub struct StringDecl {
    /// Identifier including the `$` prefix.
    pub id: String,
    pub content: StringContent,
    pub modifiers: StringMod,
}

impl StringDecl {
    #[must_use]
    pub fn new(id: impl Into<String>, content: StringContent) -> Self {
        Self { id: id.into(), content, modifiers: StringMod::new() }
    }

    #[must_use]
    pub const fn with_modifiers(mut self, mods: StringMod) -> Self {
        self.modifiers = mods;
        self
    }
}

impl fmt::Display for StringDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {}", self.id, self.content)?;
        let kw = self.modifiers.keywords();
        if !kw.is_empty() {
            write!(f, " {}", kw.join(" "))?;
        }
        Ok(())
    }
}

// ── Condition expression AST ──────────────────────────────────────────────────

/// A literal value in a condition expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Int(i64),
    Float(f64),
    Bool(bool),
    Str(String),
}

impl fmt::Display for Literal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(n) => write!(f, "{n}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Str(s) => write!(f, "\"{s}\""),
        }
    }
}

/// Binary operator in a condition expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    And, Or,
    Eq, Ne, Lt, Le, Gt, Ge,
    Add, Sub, Mul, Div, Mod,
    BitAnd, BitOr, BitXor, Shl, Shr,
    Contains, IContains, Matches,
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::And => "and", Self::Or => "or",
            Self::Eq => "==", Self::Ne => "!=",
            Self::Lt => "<", Self::Le => "<=",
            Self::Gt => ">", Self::Ge => ">=",
            Self::Add => "+", Self::Sub => "-",
            Self::Mul => "*", Self::Div => "\\",
            Self::Mod => "%",
            Self::BitAnd => "&", Self::BitOr => "|",
            Self::BitXor => "^", Self::Shl => "<<", Self::Shr => ">>",
            Self::Contains => "contains", Self::IContains => "icontains",
            Self::Matches => "matches",
        };
        write!(f, "{s}")
    }
}

/// Unary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Not,
    Neg,
    BitNot,
}

impl fmt::Display for UnOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Not => write!(f, "not"),
            Self::Neg => write!(f, "-"),
            Self::BitNot => write!(f, "~"),
        }
    }
}

/// Quantifier for `for … of` expressions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Quantifier {
    All,
    Any,
    None,
    Count(u64),
    Percent(u64),
}

impl fmt::Display for Quantifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => write!(f, "all"),
            Self::Any => write!(f, "any"),
            Self::None => write!(f, "none"),
            Self::Count(n) => write!(f, "{n}"),
            Self::Percent(p) => write!(f, "{p}%"),
        }
    }
}

/// A node in the condition expression AST.
#[derive(Debug, Clone, PartialEq)]
pub enum CondExpr {
    Literal(Literal),
    Identifier(String),
    StringRef(String),
    StringCount(String),
    StringOffset(String, Option<Box<Self>>),
    StringLength(String, Option<Box<Self>>),
    Binary(Box<Self>, BinOp, Box<Self>),
    Unary(UnOp, Box<Self>),
    /// `for <qty> of (<strings>) : (<expr>)`
    ForOf {
        quantity: Quantifier,
        strings: StringSet,
        body: Option<Box<Self>>,
    },
    /// `for <qty> <identifier> in (<expr>) : (<expr>)`
    ForIn {
        quantity: Quantifier,
        variable: String,
        iterable: Box<Self>,
        body: Box<Self>,
    },
    /// `(<expr>)` — parenthesised.
    Paren(Box<Self>),
    /// `filesize`, `entrypoint`, `at <addr>`, etc.
    Keyword(String),
}

/// A set of string identifiers used in `for … of`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringSet {
    /// All strings (`them`).
    All,
    /// Explicit list (`($a, $b, …)`).
    List(Vec<String>),
    /// Wildcard prefix (`($prefix*)`).
    Wildcard(String),
}

// ── Meta value ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaValue {
    Int(i64),
    Bool(bool),
    Str(String),
}

impl fmt::Display for MetaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(n) => write!(f, "{n}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Str(s) => write!(f, "\"{s}\""),
        }
    }
}

// ── Rule declaration ──────────────────────────────────────────────────────────

/// A tag attached to a rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleTag(pub String);

/// Complete YARA rule AST node.
#[derive(Debug, Clone)]
pub struct RuleDecl {
    pub name: String,
    pub tags: Vec<RuleTag>,
    pub is_private: bool,
    pub is_global: bool,
    pub meta: Vec<(String, MetaValue)>,
    pub strings: Vec<StringDecl>,
    pub condition: CondExpr,
}

impl RuleDecl {
    #[must_use]
    pub fn new(name: impl Into<String>, condition: CondExpr) -> Self {
        Self {
            name: name.into(),
            tags: Vec::new(),
            is_private: false,
            is_global: false,
            meta: Vec::new(),
            strings: Vec::new(),
            condition,
        }
    }

    /// Returns the meta value for `key`, if present.
    #[must_use]
    pub fn meta_value(&self, key: &str) -> Option<&MetaValue> {
        self.meta.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Returns `true` if the rule declares the string `$id`.
    #[must_use]
    pub fn has_string(&self, id: &str) -> bool {
        self.strings.iter().any(|s| s.id == id)
    }

    /// Materialise the rule metadata as a `HashMap`, keeping only the last
    /// occurrence of each key (matching YARA's semantics for duplicate meta
    /// declarations).
    #[must_use]
    pub fn meta_map(&self) -> HashMap<String, MetaValue> {
        let mut m = HashMap::with_capacity(self.meta.len());
        for (k, v) in &self.meta {
            m.insert(k.clone(), v.clone());
        }
        m
    }
}

impl fmt::Display for RuleDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_private { write!(f, "private ")?; }
        if self.is_global { write!(f, "global ")?; }
        write!(f, "rule {}", self.name)?;
        if !self.tags.is_empty() {
            let tags: Vec<&str> = self.tags.iter().map(|t| t.0.as_str()).collect();
            write!(f, " : {}", tags.join(" "))?;
        }
        writeln!(f, " {{")?;
        if !self.meta.is_empty() {
            writeln!(f, "  meta:")?;
            for (k, v) in &self.meta {
                writeln!(f, "    {k} = {v}")?;
            }
        }
        if !self.strings.is_empty() {
            writeln!(f, "  strings:")?;
            for s in &self.strings {
                writeln!(f, "    {s}")?;
            }
        }
        writeln!(f, "  condition:")?;
        writeln!(f, "    <condition>")?;
        writeln!(f, "}}")
    }
}

// ── YaraAst ──────────────────────────────────────────────────────────────────

/// A complete parsed YARA source file containing one or more rules.
#[derive(Debug, Default, Clone)]
pub struct YaraAst {
    pub rules: Vec<RuleDecl>,
    /// Top-level import declarations.
    pub imports: Vec<String>,
    /// Top-level include paths.
    pub includes: Vec<String>,
}

impl YaraAst {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: RuleDecl) {
        self.rules.push(rule);
    }

    #[must_use]
    pub fn rule_by_name(&self, name: &str) -> Option<&RuleDecl> {
        self.rules.iter().find(|r| r.name == name)
    }

    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ── Tokeniser ────────────────────────────────────────────────────────────────

const YARA_KEYWORDS: &[&str] = &[
    "rule", "private", "global", "meta", "strings", "condition",
    "and", "or", "not", "true", "false", "import", "include",
    "for", "of", "in", "all", "any", "none", "them",
    "filesize", "entrypoint", "at", "contains",
    "icontains", "matches", "wide", "ascii", "nocase",
    "fullword", "xor", "base64", "base64wide",
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    StringLit(String),
    IntLit(i64),
    LBrace, RBrace, LParen, RParen, LBracket, RBracket,
    Colon, Eq, Comma, Asterisk, Dollar,
    Keyword(String),
    StringId(String),
    Unknown(char),
    Eof,
}

struct Lexer<'a> {
    src: &'a str,
    pos: usize,
    line: usize,
}

impl<'a> Lexer<'a> {
    const fn new(src: &'a str) -> Self {
        Self { src, pos: 0, line: 1 }
    }

    fn peek(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    fn advance(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        if ch == '\n' { self.line += 1; }
        Some(ch)
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            while self.peek().is_some_and(char::is_whitespace) {
                self.advance();
            }
            if self.src[self.pos..].starts_with("//") {
                while self.peek().is_some_and(|c| c != '\n') {
                    self.advance();
                }
            } else if self.src[self.pos..].starts_with("/*") {
                self.pos += 2;
                while self.pos + 1 < self.src.len() {
                    if self.src[self.pos..].starts_with("*/") {
                        self.pos += 2;
                        break;
                    }
                    if self.peek() == Some('\n') { self.line += 1; }
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    fn next_token(&mut self) -> (Token, usize) {
        self.skip_whitespace_and_comments();
        let line = self.line;
        let Some(ch) = self.peek() else { return (Token::Eof, line); };

        if ch == '$' {
            self.advance();
            let start = self.pos;
            while self.peek().is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '*') {
                self.advance();
            }
            // A bare `$` (with no identifier suffix) is the anonymous-string
            // reference used inside `for` quantifiers; emit `Dollar` for that
            // case, and `StringId` otherwise.
            if self.pos == start {
                return (Token::Dollar, line);
            }
            return (Token::StringId(self.src[start..self.pos].to_owned()), line);
        }

        if ch == '"' {
            self.advance();
            let mut s = String::new();
            loop {
                match self.advance() {
                    None | Some('"') => break,
                    Some('\\') => {
                        match self.advance() {
                            Some('n') => s.push('\n'),
                            Some('t') => s.push('\t'),
                            Some('\\') => s.push('\\'),
                            Some('"') => s.push('"'),
                            Some(c) => s.push(c),
                            None => break,
                        }
                    }
                    Some(c) => s.push(c),
                }
            }
            return (Token::StringLit(s), line);
        }

        if ch.is_ascii_digit() || (ch == '-' && self.src[self.pos + 1..].chars().next().is_some_and(|c| c.is_ascii_digit())) {
            let start = self.pos;
            self.advance();
            while self.peek().is_some_and(|c| c.is_ascii_hexdigit() || c == 'x' || c == 'X') {
                self.advance();
            }
            let s = &self.src[start..self.pos];
            let n = if s.starts_with("0x") || s.starts_with("0X") {
                i64::from_str_radix(&s[2..], 16).unwrap_or(0)
            } else {
                s.parse().unwrap_or(0)
            };
            return (Token::IntLit(n), line);
        }

        if ch.is_alphabetic() || ch == '_' {
            let start = self.pos;
            while self.peek().is_some_and(|c| c.is_alphanumeric() || c == '_') {
                self.advance();
            }
            let word = &self.src[start..self.pos];
            if YARA_KEYWORDS.contains(&word) {
                return (Token::Keyword(word.to_owned()), line);
            }
            return (Token::Ident(word.to_owned()), line);
        }

        self.advance();
        let tok = match ch {
            '{' => Token::LBrace, '}' => Token::RBrace,
            '(' => Token::LParen, ')' => Token::RParen,
            '[' => Token::LBracket, ']' => Token::RBracket,
            ':' => Token::Colon, '=' => Token::Eq,
            ',' => Token::Comma, '*' => Token::Asterisk,
            _ => Token::Unknown(ch),
        };
        (tok, line)
    }
}

// ── Minimal parser ────────────────────────────────────────────────────────────

/// Parses a YARA source text into a [`YaraAst`].
///
/// This is a structural parser — it identifies rule boundaries, meta, strings
/// and condition sections but does not fully parse condition expressions
/// (those are left as an opaque `CondExpr::Keyword`).
pub struct RuleParser {
    tokens: Vec<(Token, usize)>,
    cursor: usize,
}

impl RuleParser {
    /// Parse a YARA source text into a [`YaraAst`].
    ///
    /// # Errors
    ///
    /// Returns a [`RuleLangError`] if the source contains invalid YARA syntax.
    pub fn parse(src: &str) -> LangResult<YaraAst> {
        let mut lexer = Lexer::new(src);
        let mut tokens = Vec::new();
        loop {
            let tok = lexer.next_token();
            let done = tok.0 == Token::Eof;
            tokens.push(tok);
            if done { break; }
        }
        let mut p = Self { tokens, cursor: 0 };
        p.parse_file()
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.cursor).map_or(&Token::Eof, |(t, _)| t)
    }

    fn line(&self) -> usize {
        self.tokens.get(self.cursor).map_or(0, |(_, l)| *l)
    }

    fn advance(&mut self) -> &Token {
        let t = &self.tokens[self.cursor].0;
        self.cursor += 1;
        t
    }

    fn expect_ident(&mut self) -> LangResult<String> {
        let line = self.line();
        match self.advance().clone() {
            Token::Ident(s) | Token::Keyword(s) => Ok(s),
            other => Err(RuleLangError::UnexpectedToken {
                line,
                found: format!("{other:?}"),
                expected: "identifier",
            }),
        }
    }

    /// Parse the meta section after the `meta:` keyword has been consumed.
    fn parse_meta_section(&mut self) -> Vec<(String, MetaValue)> {
        let mut meta = Vec::new();
        loop {
            match self.peek().clone() {
                Token::Keyword(ref k) if k == "strings" || k == "condition" => break,
                Token::Ident(key) | Token::Keyword(key) => {
                    self.advance();
                    if matches!(self.peek(), Token::Eq) { self.advance(); }
                    let val = match self.peek().clone() {
                        Token::StringLit(s) => { self.advance(); MetaValue::Str(s) }
                        Token::IntLit(n) => { self.advance(); MetaValue::Int(n) }
                        Token::Keyword(ref b) if b == "true" => { self.advance(); MetaValue::Bool(true) }
                        Token::Keyword(ref b) if b == "false" => { self.advance(); MetaValue::Bool(false) }
                        _ => MetaValue::Str(String::new()),
                    };
                    meta.push((key, val));
                }
                _ => break,
            }
        }
        meta
    }

    /// Consume tokens until the closing `}` of a condition block.
    fn skip_condition_body(&mut self) {
        let mut depth = 0usize;
        loop {
            match self.peek().clone() {
                Token::LBrace => { depth += 1; self.advance(); }
                Token::RBrace if depth == 0 => break,
                Token::RBrace => { depth -= 1; self.advance(); }
                Token::Eof => break,
                _ => { self.advance(); }
            }
        }
    }

    fn parse_file(&mut self) -> LangResult<YaraAst> {
        let mut ast = YaraAst::new();
        loop {
            match self.peek().clone() {
                Token::Eof => break,
                Token::Keyword(ref k) if k == "import" => {
                    self.advance();
                    if let Token::StringLit(s) = self.advance().clone() {
                        ast.imports.push(s);
                    }
                }
                Token::Keyword(ref k) if k == "include" => {
                    self.advance();
                    if let Token::StringLit(s) = self.advance().clone() {
                        ast.includes.push(s);
                    }
                }
                _ => {
                    // Try to parse a rule
                    let rule = self.parse_rule()?;
                    ast.add_rule(rule);
                }
            }
        }
        Ok(ast)
    }

    fn parse_rule(&mut self) -> LangResult<RuleDecl> {
        let mut is_private = false;
        let mut is_global = false;

        // Optional modifiers
        loop {
            match self.peek().clone() {
                Token::Keyword(ref k) if k == "private" => { self.advance(); is_private = true; }
                Token::Keyword(ref k) if k == "global" => { self.advance(); is_global = true; }
                _ => break,
            }
        }

        let line = self.line();
        match self.advance().clone() {
            Token::Keyword(ref k) if k == "rule" => {}
            other => return Err(RuleLangError::UnexpectedToken {
                line, found: format!("{other:?}"), expected: "rule",
            }),
        }

        let name = self.expect_ident()?;
        let mut tags = Vec::new();

        // Optional `: tag1 tag2`
        if matches!(self.peek(), Token::Colon) {
            self.advance();
            while let Token::Ident(t) | Token::Keyword(t) = self.peek().clone() {
                self.advance(); tags.push(RuleTag(t));
            }
        }

        // `{`
        let line = self.line();
        if !matches!(self.peek(), Token::LBrace) {
            return Err(RuleLangError::UnexpectedToken { line, found: format!("{:?}", self.peek()), expected: "{" });
        }
        self.advance();

        let mut meta = Vec::new();
        let mut strings = Vec::new();
        let condition = CondExpr::Keyword("true".to_owned());

        loop {
            match self.peek().clone() {
                Token::RBrace | Token::Eof => { self.advance(); break; }
                Token::Keyword(ref k) if k == "meta" => {
                    self.advance();
                    if matches!(self.peek(), Token::Colon) { self.advance(); }
                    meta = self.parse_meta_section();
                }
                Token::Keyword(ref k) if k == "strings" => {
                    self.advance();
                    if matches!(self.peek(), Token::Colon) { self.advance(); }
                    while let Token::StringId(id) = self.peek().clone() {
                        self.advance();
                        let id_full = format!("${id}");
                        if matches!(self.peek(), Token::Eq) { self.advance(); }
                        let content = match self.peek().clone() {
                            Token::StringLit(s) => { self.advance(); StringContent::Text(s) }
                            _ => StringContent::Text(String::new()),
                        };
                        strings.push(StringDecl::new(id_full, content));
                    }
                }
                Token::Keyword(ref k) if k == "condition" => {
                    self.advance();
                    if matches!(self.peek(), Token::Colon) { self.advance(); }
                    self.skip_condition_body();
                }
                _ => { self.advance(); }
            }
        }

        let mut rule = RuleDecl::new(name, condition);
        rule.is_private = is_private;
        rule.is_global = is_global;
        rule.tags = tags;
        rule.meta = meta;
        rule.strings = strings;
        Ok(rule)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let src = r#"
rule my_rule {
  meta:
    author = "Alice"
    version = 1
  strings:
    $a = "badstring"
  condition:
    $a
}
"#;
        let ast = RuleParser::parse(src).unwrap();
        assert_eq!(ast.rule_count(), 1);
        let rule = &ast.rules[0];
        assert_eq!(rule.name, "my_rule");
        assert!(rule.has_string("$a"));
        assert_eq!(rule.meta_value("author"), Some(&MetaValue::Str("Alice".to_owned())));
    }

    #[test]
    fn test_parse_tags() {
        let src = r"rule tagged : malware pe { condition: true }";
        let ast = RuleParser::parse(src).unwrap();
        assert_eq!(ast.rules[0].tags.len(), 2);
    }

    #[test]
    fn test_parse_import() {
        let src = r#"import "pe" rule r { condition: true }"#;
        let ast = RuleParser::parse(src).unwrap();
        assert_eq!(ast.imports, vec!["pe".to_owned()]);
    }

    #[test]
    fn test_string_mod_keywords() {
        let mut m = StringMod::new();
        m.apply("nocase").unwrap();
        m.apply("wide").unwrap();
        assert!(m.encoding.nocase);
        assert!(m.encoding.wide);
        assert!(m.keywords().contains(&"nocase"));
        assert!(m.apply("xyz").is_err());
    }

    #[test]
    fn test_hex_token_display() {
        let tok = HexToken::Jump(3, Some(10));
        assert_eq!(tok.to_string(), "{3-10}");
        let tok2 = HexToken::Wildcard;
        assert_eq!(tok2.to_string(), "??");
    }

    #[test]
    fn test_rule_display() {
        let rule = RuleDecl::new("test", CondExpr::Literal(Literal::Bool(true)));
        let s = rule.to_string();
        assert!(s.contains("rule test"));
    }
}
