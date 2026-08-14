//! YARA rule parser: tokenizer and AST construction.
//!
//! Parses YARA rule syntax into [`YaraRule`] trees containing strings,
//! metadata, tags, and condition AST nodes.

use std::collections::HashMap;
use std::fmt;

use crate::YaraError;

mod compiler_ast;
pub use compiler_ast::*;

pub use std::str::Chars;

// ─── YaraMetaValue ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum YaraMetaValue {
    Str(String),
    Int(i64),
    Bool(bool),
}

impl fmt::Display for YaraMetaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Str(s) => write!(f, "{s:?}"),
            Self::Int(i) => write!(f, "{i}"),
            Self::Bool(b) => write!(f, "{b}"),
        }
    }
}

// ─── StringModifiers ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringModifiers {
    /// Encoding options: nocase, wide, ascii.
    pub encoding: crate::StringEncodingOpts,
    /// Output options: fullword, private, base64.
    pub output: crate::StringOutputOpts,
    /// Whether the `xor` modifier is present.
    pub xor: bool,
}

impl Default for StringModifiers {
    fn default() -> Self {
        Self {
            encoding: crate::StringEncodingOpts { nocase: false, wide: false, ascii: false },
            output: crate::StringOutputOpts::default(),
            xor: false,
        }
    }
}

impl fmt::Display for StringModifiers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut mods = Vec::new();
        if self.encoding.ascii { mods.push("ascii"); }
        if self.encoding.wide { mods.push("wide"); }
        if self.encoding.nocase { mods.push("nocase"); }
        if self.output.fullword { mods.push("fullword"); }
        if self.output.private { mods.push("private"); }
        if self.xor { mods.push("xor"); }
        if self.output.base64 { mods.push("base64"); }
        write!(f, "{}", mods.join(" "))
    }
}

// ─── YaraStringKind ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum YaraStringKind {
    /// Plain text string: `"hello"`
    Text(String),
    /// Hex pattern: `{ 60 E8 ?? ?? }`
    Hex(Vec<HexByte>),
    /// Regular expression: `/pattern/flags`
    Regex(String, String),
}

/// A byte in a hex pattern: fixed or wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexByte {
    /// Fixed byte value.
    Fixed(u8),
    /// Wildcard `??`.
    Wildcard,
    /// Nibble wildcard `?x` or `x?`.
    NibbleHi(u8),
    NibbleLo(u8),
    /// Jump [n-m].
    Jump(u32, u32),
}

// ─── YaraString ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraString {
    pub identifier: String,
    pub kind: YaraStringKind,
    pub modifiers: StringModifiers,
}

impl YaraString {
    #[must_use] 
    pub const fn new(identifier: String, kind: YaraStringKind, modifiers: StringModifiers) -> Self {
        Self {
            identifier,
            kind,
            modifiers,
        }
    }

    /// True if this is a plain text string.
    #[must_use] 
    pub const fn is_text(&self) -> bool {
        matches!(self.kind, YaraStringKind::Text(_))
    }

    /// True if this is a hex pattern.
    #[must_use] 
    pub const fn is_hex(&self) -> bool {
        matches!(self.kind, YaraStringKind::Hex(_))
    }

    /// True if this is a regex.
    #[must_use] 
    pub const fn is_regex(&self) -> bool {
        matches!(self.kind, YaraStringKind::Regex(_, _))
    }
}

// ─── Condition AST ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Condition {
    /// Boolean literal.
    Bool(bool),
    /// Integer literal.
    Int(i64),
    /// String literal for comparison.
    Str(String),
    /// Reference to a string by identifier (e.g. `$a`).
    StringRef(String),
    /// Reference to a string set (e.g. `$a*`).
    StringWildcard(String),
    /// Filesize keyword.
    Filesize,
    /// Entrypoint keyword.
    Entrypoint,
    /// Not expression.
    Not(Box<Self>),
    /// Binary boolean.
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    /// Comparison operators.
    Eq(Box<Self>, Box<Self>),
    Ne(Box<Self>, Box<Self>),
    Lt(Box<Self>, Box<Self>),
    Le(Box<Self>, Box<Self>),
    Gt(Box<Self>, Box<Self>),
    Ge(Box<Self>, Box<Self>),
    /// Arithmetic.
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    Div(Box<Self>, Box<Self>),
    Mod(Box<Self>, Box<Self>),
    /// `N of ($a, $b, ...)` or `any of them` or `all of them`.
    Of {
        count: Box<Self>,
        set: StringSet,
    },
    /// `$a at 0x100`.
    At(Box<Self>, Box<Self>),
    /// `$a in (0..100)`.
    In(Box<Self>, Box<Self>, Box<Self>),
    /// `$a matches /regex/`.
    Matches(Box<Self>, String),
    /// `for N of S : (condition)`.
    For {
        count: Box<Self>,
        set: StringSet,
        body: Box<Self>,
    },
    /// Module function call: `pe.entry_point`.
    ModuleField(String, String),
    /// Module function call with args.
    ModuleCall(String, String, Vec<Self>),
    /// `defined $a`.
    Defined(Box<Self>),
}

/// A set of strings referred to in a quantifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringSet {
    Them,
    List(Vec<String>),
    Wildcard(String),
}

// ─── YaraRule ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct YaraRule {
    pub name: String,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, YaraMetaValue>,
    pub strings: Vec<YaraString>,
    pub condition: Condition,
    pub global: bool,
    pub private: bool,
}

impl YaraRule {
    #[must_use] 
    pub fn new(name: String) -> Self {
        Self {
            name,
            tags: Vec::new(),
            metadata: HashMap::new(),
            strings: Vec::new(),
            condition: Condition::Bool(true),
            global: false,
            private: false,
        }
    }
}

// ─── Token ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Token {
    // Keywords
    Rule,
    Global,
    Private,
    Meta,
    Strings,
    Condition,
    Import,
    And,
    Or,
    Not,
    All,
    Any,
    None,
    Of,
    Them,
    For,
    In,
    At,
    Matches,
    Contains,
    IContains,
    Startswith,
    EndsWith,
    True,
    False,
    Filesize,
    Entrypoint,
    Defined,
    // Literals
    Ident(String),
    StringLit(String),
    HexLit(String),
    RegexLit(String, String),
    IntLit(i64),
    HexIntLit(u64),
    StringIdent(String), // $foo
    // Operators
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    // Punctuation
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBrack,
    RBrack,
    Colon,
    Comma,
    DotDot,
    Dot,
    Hash,
    // End
    Eof,
}

// ─── Lexer ────────────────────────────────────────────────────────────────────

struct Lexer<'a> {
    src: &'a str,
    pos: usize,
    line: usize,
}

impl<'a> Lexer<'a> {
    const fn new(src: &'a str) -> Self {
        Self {
            src,
            pos: 0,
            line: 1,
        }
    }

    /// Returns the remaining unread source as an owned string.
    pub fn source_snapshot(mut self) -> String {
        // Best-effort: if the source looks like a brace-terminated hex pattern,
        // route through `read_hex_pattern` for canonicalisation; otherwise
        // return the original source.
        if self.src.trim_end().ends_with('}') && let Ok(s) = self.read_hex_pattern() {
            return s;
        }
        self.src.to_string()
    }

    fn peek(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    fn advance(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        if ch == '\n' {
            self.line += 1;
        }
        Some(ch)
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            // Skip whitespace
            while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
                self.advance();
            }
            // Skip line comments // ...
            if self.src[self.pos..].starts_with("//") {
                while !matches!(self.peek(), None | Some('\n')) {
                    self.advance();
                }
                continue;
            }
            // Skip block comments /* ... */
            if self.src[self.pos..].starts_with("/*") {
                self.pos += 2;
                while self.pos < self.src.len() && !self.src[self.pos..].starts_with("*/") {
                    // Advance by char length to avoid splitting multi-byte UTF-8 codepoints
                    if let Some(ch) = self.src[self.pos..].chars().next() {
                        if ch == '\n' {
                            self.line += 1;
                        }
                        self.pos += ch.len_utf8();
                    } else {
                        break;
                    }
                }
                if self.src[self.pos..].starts_with("*/") {
                    self.pos += 2;
                }
                continue;
            }
            break;
        }
    }

    fn read_string(&mut self) -> Result<String, YaraError> {
        let mut s = String::new();
        loop {
            match self.advance() {
                None => {
                    return Err(YaraError::ParseError {
                        line: self.line,
                        message: "unterminated string".into(),
                    });
                }
                Some('"') => return Ok(s),
                Some('\\') => match self.advance() {
                    Some('n') => s.push('\n'),
                    Some('t') => s.push('\t'),
                    Some('\\') => s.push('\\'),
                    Some('"') => s.push('"'),
                    Some('x') => {
                        let h = self.read_hex_byte().unwrap_or(0);
                        s.push(h as char);
                    }
                    Some(c) => {
                        s.push('\\');
                        s.push(c);
                    }
                    None => {
                        return Err(YaraError::ParseError {
                            line: self.line,
                            message: "unexpected EOF in string escape".into(),
                        });
                    }
                },
                Some(c) => s.push(c),
            }
        }
    }

    fn read_hex_byte(&mut self) -> Option<u8> {
        let h1 = self.advance()?.to_digit(16)?;
        let h2 = self.advance()?.to_digit(16)?;
        Some(u8::try_from(h1 * 16 + h2).unwrap_or(0))
    }

    fn read_hex_pattern(&mut self) -> Result<String, YaraError> {
        let mut s = String::new();
        loop {
            self.skip_whitespace_and_comments();
            match self.peek() {
                None => {
                    return Err(YaraError::ParseError {
                        line: self.line,
                        message: "unterminated hex pattern".into(),
                    });
                }
                Some('}') => {
                    self.advance();
                    return Ok(s);
                }
                Some(c) => {
                    s.push(c);
                    self.advance();
                }
            }
        }
    }

    fn read_regex(&mut self) -> Result<(String, String), YaraError> {
        let mut pat = String::new();
        loop {
            match self.advance() {
                None => {
                    return Err(YaraError::ParseError {
                        line: self.line,
                        message: "unterminated regex".into(),
                    });
                }
                Some('/') => break,
                Some('\\') => {
                    pat.push('\\');
                    if let Some(c) = self.advance() {
                        pat.push(c);
                    }
                }
                Some(c) => pat.push(c),
            }
        }
        // Read flags
        let mut flags = String::new();
        while matches!(self.peek(), Some('i' | 's' | 'm')) {
            flags.push(self.advance().unwrap());
        }
        Ok((pat, flags))
    }

    fn read_number(&mut self, first: char) -> Token {
        let mut s = String::from(first);
        while matches!(
            self.peek(),
            Some('0'..='9' | 'x' | 'a'..='f' | 'A'..='F' | 'K' | 'M' | 'G')
        ) {
            s.push(self.advance().unwrap());
        }
        if (s.starts_with("0x") || s.starts_with("0X")) && let Ok(v) = u64::from_str_radix(&s[2..], 16) {
            return Token::HexIntLit(v);
        }
        // Handle KB/MB/GB suffixes
        let (num_str, mult) = if s.ends_with("KB") {
            (&s[..s.len() - 2], 1024i64)
        } else if s.ends_with("MB") {
            (&s[..s.len() - 2], 1024 * 1024)
        } else if s.ends_with("GB") {
            (&s[..s.len() - 2], 1024 * 1024 * 1024)
        } else {
            (s.as_str(), 1)
        };
        num_str.parse::<i64>().map_or(Token::IntLit(0), |v| Token::IntLit(v.saturating_mul(mult)))
    }

    fn read_ident(&mut self, first: char) -> Token {
        let mut s = String::from(first);
        while matches!(self.peek(), Some('a'..='z' | 'A'..='Z' | '0'..='9' | '_')) {
            s.push(self.advance().unwrap());
        }
        match s.as_str() {
            "rule" => Token::Rule,
            "global" => Token::Global,
            "private" => Token::Private,
            "meta" => Token::Meta,
            "strings" => Token::Strings,
            "condition" => Token::Condition,
            "import" => Token::Import,
            "and" => Token::And,
            "or" => Token::Or,
            "not" => Token::Not,
            "all" => Token::All,
            "any" => Token::Any,
            "none" => Token::None,
            "of" => Token::Of,
            "them" => Token::Them,
            "for" => Token::For,
            "in" => Token::In,
            "at" => Token::At,
            "matches" => Token::Matches,
            "contains" => Token::Contains,
            "icontains" => Token::IContains,
            "startswith" => Token::Startswith,
            "endswith" => Token::EndsWith,
            "true" => Token::True,
            "false" => Token::False,
            "filesize" => Token::Filesize,
            "entrypoint" => Token::Entrypoint,
            "defined" => Token::Defined,
            _ => Token::Ident(s),
        }
    }

    fn next_token(&mut self) -> Result<Token, YaraError> {
        self.skip_whitespace_and_comments();
        let Some(ch) = self.advance() else { return Ok(Token::Eof) };
        match ch {
            '{' => Ok(Token::LBrace),
            '}' => Ok(Token::RBrace),
            '(' => Ok(Token::LParen),
            ')' => Ok(Token::RParen),
            '[' => Ok(Token::LBrack),
            ']' => Ok(Token::RBrack),
            ':' => Ok(Token::Colon),
            ',' => Ok(Token::Comma),
            '.' => {
                if self.peek() == Some('.') {
                    self.advance();
                    Ok(Token::DotDot)
                } else {
                    Ok(Token::Dot)
                }
            }
            '#' => Ok(Token::Hash),
            '+' => Ok(Token::Plus),
            '-' => Ok(Token::Minus),
            '*' => Ok(Token::Star),
            '/' if self.peek().is_none() => Ok(Token::Slash),
            '%' => Ok(Token::Percent),
            '=' => {
                if self.peek() == Some('=') { self.advance(); }
                Ok(Token::Eq)
            }
            '!' => {
                if self.peek() == Some('=') {
                    self.advance();
                    Ok(Token::Ne)
                } else {
                    Err(YaraError::ParseError {
                        line: self.line,
                        message: "unexpected '!'".into(),
                    })
                }
            }
            '<' => {
                if self.peek() == Some('=') {
                    self.advance();
                    Ok(Token::Le)
                } else {
                    Ok(Token::Lt)
                }
            }
            '>' => {
                if self.peek() == Some('=') {
                    self.advance();
                    Ok(Token::Ge)
                } else {
                    Ok(Token::Gt)
                }
            }
            '"' => Ok(Token::StringLit(self.read_string()?)),
            '/' => {
                let (pat, flags) = self.read_regex()?;
                Ok(Token::RegexLit(pat, flags))
            }
            '$' => {
                let mut s = String::new();
                while matches!(
                    self.peek(),
                    Some('a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '*')
                ) {
                    s.push(self.advance().unwrap());
                }
                Ok(Token::StringIdent(s))
            }
            '0'..='9' => Ok(self.read_number(ch)),
            'a'..='z' | 'A'..='Z' | '_' => Ok(self.read_ident(ch)),
            c => Err(YaraError::ParseError {
                line: self.line,
                message: format!("unexpected character: {c:?}"),
            }),
        }
    }

    fn tokenize_all(&mut self) -> Result<Vec<(usize, Token)>, YaraError> {
        let mut tokens = Vec::new();
        loop {
            let line = self.line;
            let tok = self.next_token()?;
            let done = tok == Token::Eof;
            tokens.push((line, tok));
            if done {
                break;
            }
        }
        Ok(tokens)
    }
}

// ─── Parser ───────────────────────────────────────────────────────────────────

pub struct YaraParser {
    tokens: Vec<(usize, Token)>,
    pos: usize,
}

impl YaraParser {
    const fn new(tokens: Vec<(usize, Token)>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        self.tokens
            .get(self.pos)
            .map_or(&Token::Eof, |(_, t)| t)
    }

    fn peek_ahead(&self, n: usize) -> &Token {
        self.tokens
            .get(self.pos + n)
            .map_or(&Token::Eof, |(_, t)| t)
    }

    fn line(&self) -> usize {
        self.tokens.get(self.pos).map_or(0, |(l, _)| *l)
    }

    fn advance(&mut self) -> &Token {
        let t = self
            .tokens
            .get(self.pos)
            .map_or(&Token::Eof, |(_, t)| t);
        self.pos += 1;
        t
    }

    fn expect(&mut self, expected: &Token) -> Result<(), YaraError> {
        if self.peek() == expected {
            self.advance();
            Ok(())
        } else {
            Err(YaraError::ParseError {
                line: self.line(),
                message: format!("expected {expected:?}, got {:?}", self.peek()),
            })
        }
    }

    fn parse_rules(&mut self) -> Result<Vec<YaraRule>, YaraError> {
        let mut rules = Vec::new();
        while *self.peek() != Token::Eof {
            // Skip import statements
            if *self.peek() == Token::Import {
                self.advance();
                self.advance(); // module name
                continue;
            }
            rules.push(self.parse_rule()?);
        }
        Ok(rules)
    }

    fn parse_rule(&mut self) -> Result<YaraRule, YaraError> {
        let mut global = false;
        let mut private = false;

        loop {
            match self.peek() {
                Token::Global => {
                    self.advance();
                    global = true;
                }
                Token::Private => {
                    self.advance();
                    private = true;
                }
                _ => break,
            }
        }

        self.expect(&Token::Rule)?;
        let name = match self.advance().clone() {
            Token::Ident(s) => s,
            t => {
                return Err(YaraError::ParseError {
                    line: self.line(),
                    message: format!("expected rule name, got {t:?}"),
                });
            }
        };

        let mut rule = YaraRule::new(name);
        rule.global = global;
        rule.private = private;

        // Optional tags
        if *self.peek() == Token::Colon {
            self.advance();
            while let Token::Ident(_) = self.peek() {
                if let Token::Ident(tag) = self.advance().clone() {
                    rule.tags.push(tag);
                }
            }
        }

        self.expect(&Token::LBrace)?;

        // Sections
        loop {
            match self.peek() {
                Token::Meta => {
                    self.advance();
                    self.expect(&Token::Colon)?;
                    self.parse_meta(&mut rule)?;
                }
                Token::Strings => {
                    self.advance();
                    self.expect(&Token::Colon)?;
                    self.parse_strings(&mut rule)?;
                }
                Token::Condition => {
                    self.advance();
                    self.expect(&Token::Colon)?;
                    rule.condition = self.parse_condition()?;
                }
                Token::RBrace => {
                    self.advance();
                    break;
                }
                Token::Eof => break,
                t => {
                    return Err(YaraError::ParseError {
                        line: self.line(),
                        message: format!("unexpected token in rule body: {t:?}"),
                    });
                }
            }
        }

        Ok(rule)
    }

    fn parse_meta(&mut self, rule: &mut YaraRule) -> Result<(), YaraError> {
        while let Token::Ident(_) = self.peek() {
            let Token::Ident(key) = self.advance().clone() else { break };
            self.expect(&Token::Eq)?;
            let val = match self.advance().clone() {
                Token::StringLit(s) => YaraMetaValue::Str(s),
                Token::IntLit(v) => YaraMetaValue::Int(v),
                Token::True => YaraMetaValue::Bool(true),
                Token::False => YaraMetaValue::Bool(false),
                t => {
                    return Err(YaraError::ParseError {
                        line: self.line(),
                        message: format!("unexpected meta value: {t:?}"),
                    });
                }
            };
            rule.metadata.insert(key, val);
        }
        Ok(())
    }

    fn parse_strings(&mut self, rule: &mut YaraRule) -> Result<(), YaraError> {
        while let Token::StringIdent(_) = self.peek() {
            let Token::StringIdent(ident) = self.advance().clone() else { break };
            self.expect(&Token::Eq)?;

            let (kind, mods) = match self.peek().clone() {
                Token::StringLit(_) => {
                    if let Token::StringLit(s) = self.advance().clone() {
                        let mods = self.parse_string_modifiers();
                        (YaraStringKind::Text(s), mods)
                    } else {
                        unreachable!()
                    }
                }
                Token::LBrace => {
                    self.advance();
                    // Parse hex bytes inline
                    let bytes = self.parse_hex_bytes();
                    // Record canonical hex literal via a fresh lexer for round-trip checks.
                    let hex_repr: String = bytes
                        .iter()
                        .map(|b| match b {
                            HexByte::Fixed(v) => format!("{v:02x}"),
                            HexByte::Wildcard => "??".to_string(),
                            HexByte::NibbleHi(v) => format!("?{v:x}"),
                            HexByte::NibbleLo(v) => format!("{v:x}?"),
                            HexByte::Jump(lo, hi) => format!("[{lo}-{hi}]"),
                        })
                        .collect::<Vec<_>>()
                        .join(" ");
                    let lex = Lexer::new(&hex_repr);
                    let hex_token = Token::HexLit(lex.source_snapshot());
                    debug_assert!(matches!(hex_token, Token::HexLit(_)));
                    (YaraStringKind::Hex(bytes), StringModifiers::default())
                }
                Token::RegexLit(_, _) => {
                    if let Token::RegexLit(pat, flags) = self.advance().clone() {
                        let mods = self.parse_string_modifiers();
                        (YaraStringKind::Regex(pat, flags), mods)
                    } else {
                        unreachable!()
                    }
                }
                t => {
                    return Err(YaraError::ParseError {
                        line: self.line(),
                        message: format!("unexpected string value: {t:?}"),
                    });
                }
            };

            rule.strings
                .push(YaraString::new(format!("${ident}"), kind, mods));
        }
        Ok(())
    }

    fn parse_hex_bytes(&mut self) -> Vec<HexByte> {
        let mut bytes = Vec::new();
        loop {
            match self.peek().clone() {
                Token::RBrace => { self.advance(); break; }
                Token::HexIntLit(v) => {
                    self.advance();
                    bytes.push(HexByte::Fixed(u8::try_from(v).unwrap_or(0)));
                }
                Token::IntLit(v) => {
                    self.advance();
                    bytes.push(HexByte::Fixed(u8::try_from(v).unwrap_or(0)));
                }
                Token::Eof => break,
                _ => { self.advance(); bytes.push(HexByte::Wildcard); }
            }
        }
        bytes
    }

    fn parse_string_modifiers(&mut self) -> StringModifiers {
        let mut mods = StringModifiers::default();
        while let Token::Ident(s) = self.peek().clone() {
            match s.as_str() {
                "nocase" => mods.encoding.nocase = true,
                "wide" => mods.encoding.wide = true,
                "ascii" => mods.encoding.ascii = true,
                "fullword" => mods.output.fullword = true,
                "private" => mods.output.private = true,
                "xor" => mods.xor = true,
                "base64" => mods.output.base64 = true,
                _ => break,
            }
            self.advance();
        }
        mods
    }

    fn parse_condition(&mut self) -> Result<Condition, YaraError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Condition, YaraError> {
        let mut left = self.parse_and()?;
        while *self.peek() == Token::Or {
            self.advance();
            let right = self.parse_and()?;
            left = Condition::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Condition, YaraError> {
        let mut left = self.parse_not()?;
        while *self.peek() == Token::And {
            self.advance();
            let right = self.parse_not()?;
            left = Condition::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Condition, YaraError> {
        if *self.peek() == Token::Not {
            self.advance();
            let inner = self.parse_not()?;
            return Ok(Condition::Not(Box::new(inner)));
        }
        self.parse_compare()
    }

    fn parse_compare(&mut self) -> Result<Condition, YaraError> {
        let left = self.parse_add()?;
        let op = self.peek().clone();
        match op {
            Token::Eq => {
                self.advance();
                let right = self.parse_add()?;
                Ok(Condition::Eq(Box::new(left), Box::new(right)))
            }
            Token::Ne => {
                self.advance();
                let right = self.parse_add()?;
                Ok(Condition::Ne(Box::new(left), Box::new(right)))
            }
            Token::Lt => {
                self.advance();
                let right = self.parse_add()?;
                Ok(Condition::Lt(Box::new(left), Box::new(right)))
            }
            Token::Le => {
                self.advance();
                let right = self.parse_add()?;
                Ok(Condition::Le(Box::new(left), Box::new(right)))
            }
            Token::Gt => {
                self.advance();
                let right = self.parse_add()?;
                Ok(Condition::Gt(Box::new(left), Box::new(right)))
            }
            Token::Ge => {
                self.advance();
                let right = self.parse_add()?;
                Ok(Condition::Ge(Box::new(left), Box::new(right)))
            }
            Token::At => {
                self.advance();
                let off = self.parse_add()?;
                Ok(Condition::At(Box::new(left), Box::new(off)))
            }
            Token::In => {
                self.advance();
                self.expect(&Token::LParen)?;
                let lo = self.parse_add()?;
                self.expect(&Token::DotDot)?;
                let hi = self.parse_add()?;
                self.expect(&Token::RParen)?;
                Ok(Condition::In(Box::new(left), Box::new(lo), Box::new(hi)))
            }
            Token::Matches => {
                self.advance();
                if let Token::RegexLit(pat, _) = self.advance().clone() {
                    Ok(Condition::Matches(Box::new(left), pat))
                } else {
                    Err(YaraError::ParseError {
                        line: self.line(),
                        message: "expected regex after matches".into(),
                    })
                }
            }
            _ => Ok(left),
        }
    }

    fn parse_add(&mut self) -> Result<Condition, YaraError> {
        let mut left = self.parse_primary()?;
        loop {
            match self.peek() {
                Token::Plus => {
                    self.advance();
                    let r = self.parse_primary()?;
                    left = Condition::Add(Box::new(left), Box::new(r));
                }
                Token::Minus => {
                    self.advance();
                    let r = self.parse_primary()?;
                    left = Condition::Sub(Box::new(left), Box::new(r));
                }
                _ => break,
            }
        }
        Ok(left)
    }

    fn parse_primary(&mut self) -> Result<Condition, YaraError> {
        match self.peek().clone() {
            Token::LParen => {
                self.advance();
                let inner = self.parse_condition()?;
                self.expect(&Token::RParen)?;
                Ok(inner)
            }
            Token::True => { self.advance(); Ok(Condition::Bool(true)) }
            Token::False => { self.advance(); Ok(Condition::Bool(false)) }
            Token::IntLit(v) if !matches!(self.peek_ahead(1), Token::Of) => {
                self.advance(); Ok(Condition::Int(v))
            }
            Token::HexIntLit(v) if !matches!(self.peek_ahead(1), Token::Of) => {
                self.advance(); Ok(Condition::Int(i64::try_from(v).unwrap_or(i64::MAX)))
            }
            Token::StringLit(s) => { self.advance(); Ok(Condition::Str(s)) }
            Token::Filesize => { self.advance(); Ok(Condition::Filesize) }
            Token::Entrypoint => { self.advance(); Ok(Condition::Entrypoint) }
            Token::Defined => {
                self.advance();
                self.expect(&Token::LParen)?;
                let inner = self.parse_condition()?;
                self.expect(&Token::RParen)?;
                Ok(Condition::Defined(Box::new(inner)))
            }
            Token::StringIdent(s) => { self.advance(); Ok(Condition::StringRef(format!("${s}"))) }
            Token::Hash => {
                self.advance();
                if let Token::StringIdent(s) = self.peek().clone() {
                    self.advance();
                    Ok(Condition::StringRef(format!("#{s}")))
                } else {
                    Ok(Condition::Int(0))
                }
            }
            Token::Any => { self.advance(); self.expect(&Token::Of)?; Ok(Condition::Of { count: Box::new(Condition::Int(1)), set: self.parse_string_set()? }) }
            Token::All => { self.advance(); self.expect(&Token::Of)?; Ok(Condition::Of { count: Box::new(Condition::Int(-1)), set: self.parse_string_set()? }) }
            Token::None => { self.advance(); self.expect(&Token::Of)?; Ok(Condition::Of { count: Box::new(Condition::Int(0)), set: self.parse_string_set()? }) }
            Token::IntLit(_) | Token::HexIntLit(_) => self.parse_numeric_quantifier(),
            Token::Ident(s) => self.parse_ident_expr(s),
            t => Err(YaraError::ParseError {
                line: self.line(),
                message: format!("unexpected token in condition: {t:?}"),
            }),
        }
    }

    fn parse_numeric_quantifier(&mut self) -> Result<Condition, YaraError> {
        let n = self.parse_add()?;
        if *self.peek() == Token::Of {
            self.advance();
            let set = self.parse_string_set()?;
            Ok(Condition::Of { count: Box::new(n), set })
        } else {
            Ok(n)
        }
    }

    fn parse_ident_expr(&mut self, s: String) -> Result<Condition, YaraError> {
        self.advance();
        if *self.peek() == Token::Dot {
            self.advance();
            if let Token::Ident(field) = self.advance().clone() {
                if *self.peek() == Token::LParen {
                    self.advance();
                    let mut args = Vec::new();
                    while *self.peek() != Token::RParen && *self.peek() != Token::Eof {
                        args.push(self.parse_condition()?);
                        if *self.peek() == Token::Comma { self.advance(); }
                    }
                    self.expect(&Token::RParen)?;
                    return Ok(Condition::ModuleCall(s, field, args));
                }
                return Ok(Condition::ModuleField(s, field));
            }
        }
        Ok(Condition::ModuleField(s, String::new()))
    }

    fn parse_string_set(&mut self) -> Result<StringSet, YaraError> {
        match self.peek().clone() {
            Token::Them => {
                self.advance();
                Ok(StringSet::Them)
            }
            Token::LParen => {
                self.advance();
                let mut list = Vec::new();
                while *self.peek() != Token::RParen && *self.peek() != Token::Eof {
                    if let Token::StringIdent(s) = self.advance().clone() {
                        list.push(format!("${s}"));
                    }
                    if *self.peek() == Token::Comma {
                        self.advance();
                    }
                }
                self.expect(&Token::RParen)?;
                Ok(StringSet::List(list))
            }
            _ => Err(YaraError::ParseError {
                line: self.line(),
                message: "expected 'them' or string set".into(),
            }),
        }
    }
}

// ─── Public parse API ─────────────────────────────────────────────────────────

/// Parse one or more YARA rules from source text.
///
/// # Errors
///
/// Returns a [`YaraError`] if the source contains invalid YARA syntax.
pub fn parse_rules(src: &str) -> Result<Vec<YaraRule>, YaraError> {
    let mut lexer = Lexer::new(src);
    let tokens = lexer.tokenize_all()?;
    let mut parser = YaraParser::new(tokens);
    parser.parse_rules()
}

/// Parse a single YARA rule.
///
/// # Errors
///
/// Returns a [`YaraError`] if the source contains invalid YARA syntax or no rule is found.
pub fn parse_rule(src: &str) -> Result<YaraRule, YaraError> {
    let mut rules = parse_rules(src)?;
    rules.pop().ok_or_else(|| YaraError::ParseError {
        line: 0,
        message: "no rule found".into(),
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let src = r#"
rule test_rule {
    strings:
        $a = "hello"
    condition:
        $a
}
"#;
        let rules = parse_rules(src).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "test_rule");
    }

    #[test]
    fn test_parse_rule_name() {
        let src = r"rule my_rule { condition: true }";
        let r = parse_rule(src).unwrap();
        assert_eq!(r.name, "my_rule");
    }

    #[test]
    fn test_parse_true_condition() {
        let src = r"rule r { condition: true }";
        let r = parse_rule(src).unwrap();
        assert_eq!(r.condition, Condition::Bool(true));
    }

    #[test]
    fn test_parse_false_condition() {
        let src = r"rule r { condition: false }";
        let r = parse_rule(src).unwrap();
        assert_eq!(r.condition, Condition::Bool(false));
    }

    #[test]
    fn test_parse_not_condition() {
        let src = r"rule r { condition: not true }";
        let r = parse_rule(src).unwrap();
        assert!(matches!(r.condition, Condition::Not(_)));
    }

    #[test]
    fn test_parse_and_condition() {
        let src = r"rule r { condition: true and false }";
        let r = parse_rule(src).unwrap();
        assert!(matches!(r.condition, Condition::And(_, _)));
    }

    #[test]
    fn test_parse_or_condition() {
        let src = r"rule r { condition: true or false }";
        let r = parse_rule(src).unwrap();
        assert!(matches!(r.condition, Condition::Or(_, _)));
    }

    #[test]
    fn test_parse_filesize() {
        let src = r"rule r { condition: filesize > 100 }";
        let r = parse_rule(src).unwrap();
        assert!(matches!(r.condition, Condition::Gt(_, _)));
    }

    #[test]
    fn test_parse_string_text() {
        let src = r#"rule r { strings: $a = "test" condition: $a }"#;
        let r = parse_rule(src).unwrap();
        assert_eq!(r.strings.len(), 1);
        assert!(r.strings[0].is_text());
    }

    #[test]
    fn test_parse_string_wide_nocase() {
        let src = r#"rule r { strings: $a = "test" wide nocase condition: $a }"#;
        let r = parse_rule(src).unwrap();
        assert!(r.strings[0].modifiers.encoding.wide);
        assert!(r.strings[0].modifiers.encoding.nocase);
    }

    #[test]
    fn test_parse_metadata() {
        let src = r#"rule r { meta: author = "alice" version = 1 condition: true }"#;
        let r = parse_rule(src).unwrap();
        assert_eq!(
            r.metadata.get("author"),
            Some(&YaraMetaValue::Str("alice".to_string()))
        );
        assert_eq!(r.metadata.get("version"), Some(&YaraMetaValue::Int(1)));
    }

    #[test]
    fn test_parse_tags() {
        let src = r"rule r : malware packer { condition: true }";
        let r = parse_rule(src).unwrap();
        assert!(r.tags.contains(&"malware".to_string()));
        assert!(r.tags.contains(&"packer".to_string()));
    }

    #[test]
    fn test_parse_global_rule() {
        let src = r"global rule r { condition: true }";
        let r = parse_rule(src).unwrap();
        assert!(r.global);
    }

    #[test]
    fn test_parse_private_rule() {
        let src = r"private rule r { condition: true }";
        let r = parse_rule(src).unwrap();
        assert!(r.private);
    }

    #[test]
    fn test_parse_any_of_them() {
        let src = r#"rule r { strings: $a = "a" $b = "b" condition: any of them }"#;
        let r = parse_rule(src).unwrap();
        assert!(matches!(
            r.condition,
            Condition::Of {
                set: StringSet::Them,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_all_of_them() {
        let src = r#"rule r { strings: $a = "a" condition: all of them }"#;
        let r = parse_rule(src).unwrap();
        assert!(matches!(
            r.condition,
            Condition::Of {
                set: StringSet::Them,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_module_field() {
        let src = r"rule r { condition: pe.entry_point }";
        let r = parse_rule(src).unwrap();
        assert!(
            matches!(r.condition, Condition::ModuleField(ref m, ref f) if m == "pe" && f == "entry_point")
        );
    }

    #[test]
    fn test_parse_string_ref_condition() {
        let src = r#"rule r { strings: $a = "x" condition: $a }"#;
        let r = parse_rule(src).unwrap();
        assert!(matches!(r.condition, Condition::StringRef(_)));
    }

    #[test]
    fn test_parse_multiple_rules() {
        let src = r"
rule r1 { condition: true }
rule r2 { condition: false }
";
        let rules = parse_rules(src).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_parse_arithmetic_condition() {
        let src = r"rule r { condition: filesize + 10 > 100 }";
        let r = parse_rule(src).unwrap();
        assert!(matches!(r.condition, Condition::Gt(_, _)));
    }

    #[test]
    fn test_parse_comment_skipped() {
        let src = r"
// this is a comment
rule r { condition: true /* block */ }
";
        let r = parse_rule(src).unwrap();
        assert_eq!(r.name, "r");
    }

    #[test]
    fn test_parse_empty_string_set() {
        let src = r#"rule r { strings: $a = "x" condition: $a }"#;
        let r = parse_rule(src).unwrap();
        assert_eq!(r.strings.len(), 1);
    }

    #[test]
    fn test_parse_entrypoint() {
        let src = r"rule r { condition: entrypoint == 0 }";
        let r = parse_rule(src).unwrap();
        assert!(matches!(r.condition, Condition::Eq(_, _)));
    }

    #[test]
    fn test_parse_int_literal() {
        let src = r"rule r { condition: 42 == 42 }";
        let r = parse_rule(src).unwrap();
        assert!(matches!(r.condition, Condition::Eq(_, _)));
    }

    #[test]
    fn test_parse_hex_int_literal() {
        let src = r"rule r { condition: 0x100 > 0 }";
        let r = parse_rule(src).unwrap();
        assert!(matches!(r.condition, Condition::Gt(_, _)));
    }

    #[test]
    fn test_string_modifiers_display() {
        let m = StringModifiers {
            encoding: crate::StringEncodingOpts { ascii: true, wide: true, nocase: false },
            ..StringModifiers::default()
        };
        let s = m.to_string();
        assert!(s.contains("ascii") && s.contains("wide"));
    }

    #[test]
    fn test_parse_bad_rule_name() {
        let src = r"rule { condition: true }";
        assert!(parse_rule(src).is_err());
    }
}
