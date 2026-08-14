//! Extended YARA rule compiler: parse rule text → AST → bytecode emission.
//!
//! Provides a complete parse-to-bytecode pipeline that is separate from the
//! existing `rule_compiler` module.  Introduces `RuleCompiler`, `RuleAst`,
//! `CompiledRule`, and `BytecodeEmitter`.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Lexer tokens ─────────────────────────────────────────────────────────────

/// A lexer token for YARA rule source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Rule,
    Strings,
    Condition,
    Meta,
    Import,
    Include,
    Global,
    Private,
    Not,
    And,
    Or,
    All,
    Any,
    Of,
    In,
    Them,
    At,
    For,
    EntryPoint,
    Filesize,
    True,
    False,
    Ident(String),
    StringIdent(String),   // $name
    StringCount(String),   // #name
    StringOffset(String),  // @name
    IntLiteral(i64),
    HexLiteral(u64),
    StringLiteral(String),
    RegexLiteral(String),
    HexPattern(Vec<u8>),
    LBrace,
    RBrace,
    LParen,
    RParen,
    Colon,
    Comma,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    DotDot,
    Slash,
    Asterisk,
    Plus,
    Minus,
    Percent,
    Newline,
    Eof,
    Unknown(char),
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── Lexer ────────────────────────────────────────────────────────────────────

/// Tokenises YARA rule source text.
pub struct Lexer<'a> {
    src: &'a str,
    pos: usize,
    pub line: usize,
}

impl<'a> Lexer<'a> {
    #[must_use] 
    pub const fn new(src: &'a str) -> Self {
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

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() { self.advance(); } else { break; }
        }
    }

    fn skip_line_comment(&mut self) {
        while let Some(c) = self.advance() {
            if c == '\n' { break; }
        }
    }

    fn skip_block_comment(&mut self) {
        while self.pos + 1 < self.src.len() {
            if &self.src[self.pos..self.pos + 2] == "*/" {
                self.pos += 2;
                break;
            }
            self.advance();
        }
    }

    fn read_ident(&mut self, first: char) -> String {
        let mut s = String::from(first);
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' { s.push(c); self.advance(); } else { break; }
        }
        s
    }

    fn read_string_literal(&mut self) -> String {
        let mut s = String::new();
        while let Some(c) = self.advance() {
            match c {
                '"' => break,
                '\\' => {
                    if let Some(esc) = self.advance() {
                        match esc {
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            '"' => s.push('"'),
                            '\\' => s.push('\\'),
                            'x' => {
                                let h1 = self.advance().unwrap_or('0');
                                let h2 = self.advance().unwrap_or('0');
                                if let Ok(b) = u8::from_str_radix(&format!("{h1}{h2}"), 16) {
                                    s.push(b as char);
                                }
                            }
                            other => { s.push('\\'); s.push(other); }
                        }
                    }
                }
                other => s.push(other),
            }
        }
        s
    }

    fn read_regex_literal(&mut self) -> String {
        let mut s = String::new();
        while let Some(c) = self.advance() {
            if c == '/' { break; }
            if c == '\\' {
                if let Some(nc) = self.advance() { s.push('\\'); s.push(nc); }
            } else {
                s.push(c);
            }
        }
        s
    }

    fn read_number(&mut self, first: char) -> Token {
        let mut s = String::from(first);
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == '_' { s.push(c); self.advance(); } else { break; }
        }
        let clean: String = s.chars().filter(|&c| c != '_').collect();
        clean.parse::<i64>().map_or(Token::Unknown('?'), Token::IntLiteral)
    }

    /// Return the next token.
    ///
    /// # Panics
    /// Panics if the lexer advances past end-of-input (unreachable in practice).
    pub fn next_token(&mut self) -> Token {
        loop {
            self.skip_whitespace();
            match self.peek() {
                None => return Token::Eof,
                Some('/') => {
                    self.advance();
                    if self.peek() == Some('/') {
                        self.advance();
                        self.skip_line_comment();
                        continue;
                    }
                    if self.peek() == Some('*') {
                        self.advance();
                        self.skip_block_comment();
                        continue;
                    }
                    let _ = self.read_regex_literal();
                    return Token::Slash;
                }
                _ => break,
            }
        }
        let ch = self.advance().unwrap();
        match ch {
            '{' => Token::LBrace,
            '}' => Token::RBrace,
            '(' => Token::LParen,
            ')' => Token::RParen,
            ':' => Token::Colon,
            ',' => Token::Comma,
            '=' if self.peek() == Some('=') => { self.advance(); Token::Eq }
            '=' => Token::Eq,
            '!' if self.peek() == Some('=') => { self.advance(); Token::Ne }
            '<' if self.peek() == Some('=') => { self.advance(); Token::Le }
            '<' => Token::Lt,
            '>' if self.peek() == Some('=') => { self.advance(); Token::Ge }
            '>' => Token::Gt,
            '.' if self.peek() == Some('.') => { self.advance(); Token::DotDot }
            '*' => Token::Asterisk,
            '+' => Token::Plus,
            '-' if self.peek().is_some_and(|c| c.is_ascii_digit()) => {
                if let Token::IntLiteral(n) = self.read_number('0') {
                    Token::IntLiteral(-n)
                } else { Token::Minus }
            }
            '-' => Token::Minus,
            '%' => Token::Percent,
            '"' => Token::StringLiteral(self.read_string_literal()),
            '/' => Token::RegexLiteral(self.read_regex_literal()),
            '$' => {
                let id = self.read_ident('$');
                Token::StringIdent(id)
            }
            '#' => {
                let id = self.read_ident('#');
                Token::StringCount(id)
            }
            '@' => {
                let id = self.read_ident('@');
                Token::StringOffset(id)
            }
            '0' if self.peek() == Some('x') || self.peek() == Some('X') => {
                self.advance();
                let mut s = String::new();
                while let Some(c) = self.peek() {
                    if c.is_ascii_hexdigit() { s.push(c); self.advance(); } else { break; }
                }
                Token::HexLiteral(u64::from_str_radix(&s, 16).unwrap_or(0))
            }
            d if d.is_ascii_digit() => self.read_number(d),
            c if c.is_alphabetic() || c == '_' => {
                let ident = self.read_ident(c);
                match ident.as_str() {
                    "rule" => Token::Rule,
                    "strings" => Token::Strings,
                    "condition" => Token::Condition,
                    "meta" => Token::Meta,
                    "import" => Token::Import,
                    "include" => Token::Include,
                    "global" => Token::Global,
                    "private" => Token::Private,
                    "not" => Token::Not,
                    "and" => Token::And,
                    "or" => Token::Or,
                    "all" => Token::All,
                    "any" => Token::Any,
                    "of" => Token::Of,
                    "in" => Token::In,
                    "them" => Token::Them,
                    "at" => Token::At,
                    "for" => Token::For,
                    "entrypoint" => Token::EntryPoint,
                    "filesize" => Token::Filesize,
                    "true" => Token::True,
                    "false" => Token::False,
                    _ => Token::Ident(ident),
                }
            }
            other => Token::Unknown(other),
        }
    }

    /// Collect all tokens until EOF.
    pub fn tokenize(&mut self) -> Vec<Token> {
        let mut tokens = Vec::new();
        loop {
            let t = self.next_token();
            let done = t == Token::Eof;
            tokens.push(t);
            if done { break; }
        }
        tokens
    }
}

// ─── RuleAst ──────────────────────────────────────────────────────────────────

/// AST representation of a YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleAst {
    pub name: String,
    pub global: bool,
    pub private: bool,
    pub tags: Vec<String>,
    pub meta: HashMap<String, AstMetaValue>,
    pub strings: Vec<AstString>,
    pub condition: AstCondition,
}

/// A metadata value in an AST.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AstMetaValue {
    Str(String),
    Int(i64),
    Bool(bool),
}

impl fmt::Display for AstMetaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Str(s) => write!(f, "{s:?}"),
            Self::Int(n) => write!(f, "{n}"),
            Self::Bool(b) => write!(f, "{b}"),
        }
    }
}

bitflags::bitflags! {
    /// Boolean modifier flags for a YARA string definition.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AstStringFlags: u8 {
        const NOCASE   = 1 << 0;
        const WIDE     = 1 << 1;
        const ASCII    = 1 << 2;
        const FULLWORD = 1 << 3;
        const PRIVATE  = 1 << 4;
        const BASE64   = 1 << 5;
    }
}

/// A string definition in an AST.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstString {
    pub id: String,
    pub value: AstStringValue,
    pub modifiers: AstStringFlags,
}

impl AstString {
    /// Returns `true` if the `nocase` modifier is set.
    #[must_use] pub const fn nocase(&self) -> bool { self.modifiers.contains(AstStringFlags::NOCASE) }
    /// Returns `true` if the `wide` modifier is set.
    #[must_use] pub const fn wide(&self) -> bool { self.modifiers.contains(AstStringFlags::WIDE) }
    /// Returns `true` if the `ascii` modifier is set.
    #[must_use] pub const fn ascii(&self) -> bool { self.modifiers.contains(AstStringFlags::ASCII) }
    /// Returns `true` if the `fullword` modifier is set.
    #[must_use] pub const fn fullword(&self) -> bool { self.modifiers.contains(AstStringFlags::FULLWORD) }
    /// Returns `true` if the `private` modifier is set.
    #[must_use] pub const fn private(&self) -> bool { self.modifiers.contains(AstStringFlags::PRIVATE) }
    /// Returns `true` if the `base64` modifier is set.
    #[must_use] pub const fn base64(&self) -> bool { self.modifiers.contains(AstStringFlags::BASE64) }
}

/// The value of a YARA string in the AST.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AstStringValue {
    Text(String),
    Hex(Vec<u8>),
    Regex(String),
}

/// A condition expression in the AST.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AstCondition {
    True,
    False,
    All,
    Any,
    None,
    EntryPoint,
    Filesize(AstCompOp, i64),
    StringMatch(String),
    StringCount(String, AstCompOp, i64),
    StringAt(String, i64),
    StringIn(String, i64, i64),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Not(Box<Self>),
    For(i64, String, Box<Self>),
    IntAt(i64),
}

/// Comparison operator in the AST.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AstCompOp { Eq, Ne, Lt, Le, Gt, Ge }

impl fmt::Display for AstCompOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self { Self::Eq=>"==", Self::Ne=>"!=", Self::Lt=>"<", Self::Le=>"<=", Self::Gt=>">", Self::Ge=>">=" })
    }
}

// ─── Bytecode ─────────────────────────────────────────────────────────────────

/// A single bytecode instruction emitted by the compiler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Bytecode {
    /// Match all strings in the rule.
    MatchAll,
    /// Match any string.
    MatchAny,
    /// Match a specific string by identifier.
    MatchString(String),
    /// Check string count against a constant.
    CheckCount(String, AstCompOp, i64),
    /// Check string at offset.
    CheckAt(String, i64),
    /// Check string in range.
    CheckIn(String, i64, i64),
    /// Check filesize against constant.
    CheckFilesize(AstCompOp, i64),
    /// Check entry point.
    CheckEntryPoint,
    /// Logical AND.
    And,
    /// Logical OR.
    Or,
    /// Logical NOT.
    Not,
    /// Push true literal.
    PushTrue,
    /// Push false literal.
    PushFalse,
}

// ─── CompiledRule ─────────────────────────────────────────────────────────────

/// A fully compiled YARA rule ready for matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledRule {
    pub name: String,
    pub global: bool,
    pub private: bool,
    pub tags: Vec<String>,
    pub meta: HashMap<String, AstMetaValue>,
    /// The compiled string patterns.
    pub strings: Vec<AstString>,
    /// Bytecode for the condition.
    pub bytecode: Vec<Bytecode>,
    /// Estimated complexity score (rough instruction count).
    pub complexity: usize,
}

impl CompiledRule {
    /// Returns `true` if this rule has any string patterns.
    #[must_use] 
    pub const fn has_strings(&self) -> bool { !self.strings.is_empty() }
    /// Returns `true` if the condition is trivially true.
    #[must_use] 
    pub fn is_trivial(&self) -> bool {
        matches!(self.bytecode.as_slice(), [Bytecode::PushTrue])
    }
}

impl fmt::Display for CompiledRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CompiledRule({}, strings={}, ops={}, complexity={})",
            self.name, self.strings.len(), self.bytecode.len(), self.complexity
        )
    }
}

// ─── BytecodeEmitter ─────────────────────────────────────────────────────────

/// Emits bytecode from a condition AST.
pub struct BytecodeEmitter;

impl BytecodeEmitter {
    #[must_use] 
    pub const fn new() -> Self { Self }

    /// Emit bytecode for a condition into `out`.
    pub fn emit(cond: &AstCondition, out: &mut Vec<Bytecode>) {
        match cond {
            AstCondition::True => out.push(Bytecode::PushTrue),
            AstCondition::False => out.push(Bytecode::PushFalse),
            AstCondition::All => out.push(Bytecode::MatchAll),
            AstCondition::Any => out.push(Bytecode::MatchAny),
            AstCondition::None => {
                out.push(Bytecode::MatchAny);
                out.push(Bytecode::Not);
            }
            AstCondition::EntryPoint => out.push(Bytecode::CheckEntryPoint),
            AstCondition::Filesize(op, n) => out.push(Bytecode::CheckFilesize(*op, *n)),
            AstCondition::StringMatch(id) => out.push(Bytecode::MatchString(id.clone())),
            AstCondition::StringCount(id, op, n) => out.push(Bytecode::CheckCount(id.clone(), *op, *n)),
            AstCondition::StringAt(id, off) => out.push(Bytecode::CheckAt(id.clone(), *off)),
            AstCondition::StringIn(id, lo, hi) => out.push(Bytecode::CheckIn(id.clone(), *lo, *hi)),
            AstCondition::And(a, b) => {
                Self::emit(a, out);
                Self::emit(b, out);
                out.push(Bytecode::And);
            }
            AstCondition::Or(a, b) => {
                Self::emit(a, out);
                Self::emit(b, out);
                out.push(Bytecode::Or);
            }
            AstCondition::Not(inner) => {
                Self::emit(inner, out);
                out.push(Bytecode::Not);
            }
            AstCondition::For(n, set, inner) => {
                // Simplified: emit inner condition and MatchAll/Any based on n.
                let _ = (n, set);
                Self::emit(inner, out);
            }
            AstCondition::IntAt(off) => {
                out.push(Bytecode::CheckAt("$int".to_string(), *off));
            }
        }
    }

    /// Instance-method wrapper for [`Self::emit`]; enables the emitter to be
    /// held as a field and wired in via `&self` call sites.
    pub fn emit_rule(&self, cond: &AstCondition, out: &mut Vec<Bytecode>) {
        Self::emit(cond, out);
    }
}

impl Default for BytecodeEmitter {
    fn default() -> Self { Self::new() }
}

// ─── RuleCompiler ─────────────────────────────────────────────────────────────

/// Compiles YARA rule source text to [`CompiledRule`]s.
pub struct RuleCompiler {
    emitter: BytecodeEmitter,
}

impl RuleCompiler {
    /// Create a new compiler.
    #[must_use] 
    pub const fn new() -> Self {
        Self { emitter: BytecodeEmitter::new() }
    }

    /// Compile a single YARA rule from source text.
    ///
    /// # Errors
    /// Returns `Err(String)` if the source text is not a valid YARA rule.
    pub fn compile(&self, src: &str) -> Result<CompiledRule, String> {
        let ast = Self::parse_rule(src)?;
        let mut bytecode = Vec::new();
        self.emitter.emit_rule(&ast.condition, &mut bytecode);
        let complexity = bytecode.len() + ast.strings.len();
        Ok(CompiledRule {
            name: ast.name,
            global: ast.global,
            private: ast.private,
            tags: ast.tags,
            meta: ast.meta,
            strings: ast.strings,
            bytecode,
            complexity,
        })
    }

    /// Parse multiple rules from source text.
    #[must_use] 
    pub fn compile_all(&self, src: &str) -> Vec<Result<CompiledRule, String>> {
        let mut results = Vec::new();
        let mut remaining = src;
        while let Some(pos) = remaining.find("rule ") {
            remaining = &remaining[pos..];
            let end = Self::find_rule_end(remaining);
            results.push(self.compile(&remaining[..end]));
            remaining = &remaining[end..];
        }
        results
    }

    fn find_rule_end(src: &str) -> usize {
        let mut depth = 0i32;
        let mut pos = 0;
        for (i, ch) in src.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 { pos = i + 1; break; }
                }
                _ => {}
            }
        }
        if pos == 0 { src.len() } else { pos }
    }

    /// Parse a rule source string into a [`RuleAst`].
    fn parse_rule(src: &str) -> Result<RuleAst, String> {
        let src = src.trim();
        let mut global = false;
        let mut private = false;
        let mut rest = src;

        // Consume optional modifiers.
        if let Some(r) = rest.strip_prefix("global") {
            global = true;
            rest = r.trim_start();
        }
        if let Some(r) = rest.strip_prefix("private") {
            private = true;
            rest = r.trim_start();
        }

        let rest = rest.strip_prefix("rule").ok_or("expected 'rule' keyword")?.trim_start();
        let name_end = rest.find(|c: char| !c.is_alphanumeric() && c != '_').unwrap_or(rest.len());
        let name = rest[..name_end].to_string();
        if name.is_empty() { return Err("empty rule name".into()); }

        let rest = &rest[name_end..];
        let (tags, rest) = Self::parse_tags(rest);

        let body_start = rest.find('{').ok_or("expected '{' to open rule body")? + 1;
        let body_end = rest.rfind('}').ok_or("expected '}' to close rule body")?;
        let body = &rest[body_start..body_end];

        let meta = Self::parse_meta_section(body);
        let strings = Self::parse_strings_section(body);
        let condition = Self::parse_condition_section(body);

        Ok(RuleAst { name, global, private, tags, meta, strings, condition })
    }

    fn parse_tags(src: &str) -> (Vec<String>, &str) {
        let src = src.trim_start();
        if let Some(colon_pos) = src.find(':')
            && let Some(brace_pos) = src.find('{')
                && colon_pos < brace_pos {
                    let tag_str = &src[colon_pos + 1..brace_pos];
                    let tags = tag_str.split_whitespace().map(std::string::ToString::to_string).collect();
                    return (tags, &src[brace_pos..]);
                }
        (vec![], src)
    }

    fn parse_meta_section(body: &str) -> HashMap<String, AstMetaValue> {
        let mut map = HashMap::new();
        if let Some(start) = body.find("meta:") {
            let after = &body[start + 5..];
            let end = after.find("strings:").or_else(|| after.find("condition:")).unwrap_or(after.len());
            for line in after[..end].lines() {
                let line = line.trim();
                if let Some(eq) = line.find('=') {
                    let key = line[..eq].trim().to_string();
                    let val = line[eq + 1..].trim();
                    let mv = if val.starts_with('"') && val.ends_with('"') {
                        AstMetaValue::Str(val[1..val.len()-1].to_string())
                    } else if val == "true" {
                        AstMetaValue::Bool(true)
                    } else if val == "false" {
                        AstMetaValue::Bool(false)
                    } else if let Ok(n) = val.parse::<i64>() {
                        AstMetaValue::Int(n)
                    } else {
                        AstMetaValue::Str(val.to_string())
                    };
                    if !key.is_empty() { map.insert(key, mv); }
                }
            }
        }
        map
    }

    fn parse_strings_section(body: &str) -> Vec<AstString> {
        let mut strings = Vec::new();
        if let Some(start) = body.find("strings:") {
            let after = &body[start + 8..];
            let end = after.find("condition:").unwrap_or(after.len());
            for line in after[..end].lines() {
                let line = line.trim();
                if !line.starts_with('$') { continue; }
                if let Some(eq) = line.find('=') {
                    let id = line[..eq].trim().to_string();
                    let val_raw = line[eq + 1..].trim();
                    let (value, modifiers) = Self::parse_string_value(val_raw);
                    strings.push(AstString { id, value, modifiers });
                }
            }
        }
        strings
    }

    fn parse_string_value(raw: &str) -> (AstStringValue, AstStringFlags) {
        let mut flags = AstStringFlags::empty();
        let value = raw.strip_prefix('"').map_or_else(
            || {
                if raw.starts_with('{') {
                    let close = raw.find('}').unwrap_or(raw.len() - 1);
                    let bytes: Vec<u8> = raw[1..close].split_whitespace()
                        .filter_map(|h| u8::from_str_radix(h, 16).ok())
                        .collect();
                    AstStringValue::Hex(bytes)
                } else {
                    raw.strip_prefix('/').map_or_else(
                        || AstStringValue::Text(raw.to_string()),
                        |s| {
                            let close = s.rfind('/').map_or(raw.len() - 1, |p| p + 1);
                            AstStringValue::Regex(raw[1..close].to_string())
                        },
                    )
                }
            },
            |stripped| {
                let close = stripped.find('"').map_or(raw.len() - 1, |p| p + 1);
                let text = raw[1..close].to_string();
                let mods = &raw[close + 1..];
                for m in mods.split_whitespace() {
                    match m {
                        "nocase"   => flags |= AstStringFlags::NOCASE,
                        "wide"     => flags |= AstStringFlags::WIDE,
                        "ascii"    => flags |= AstStringFlags::ASCII,
                        "fullword" => flags |= AstStringFlags::FULLWORD,
                        _ => {}
                    }
                }
                AstStringValue::Text(text)
            },
        );
        (value, flags)
    }

    fn parse_condition_section(body: &str) -> AstCondition {
        if let Some(start) = body.find("condition:") {
            let cond_text = body[start + 10..].trim();
            return Self::parse_condition_expr(cond_text);
        }
        AstCondition::True
    }

    fn parse_condition_expr(text: &str) -> AstCondition {
        let text = text.trim();
        if text == "true" { return AstCondition::True; }
        if text == "false" { return AstCondition::False; }
        if text == "any of them" { return AstCondition::Any; }
        if text == "all of them" { return AstCondition::All; }
        if text == "none of them" { return AstCondition::None; }
        if text == "entrypoint" { return AstCondition::EntryPoint; }
        if let Some(stripped) = text.strip_prefix("filesize") {
            let rest = stripped.trim();
            let (op, val) = Self::parse_comp_op_val(rest);
            return AstCondition::Filesize(op, val);
        }
        if let Some(stripped) = text.strip_prefix("not ") {
            return AstCondition::Not(Box::new(Self::parse_condition_expr(stripped)));
        }
        if let Some(pos) = text.rfind(" or ") {
            return AstCondition::Or(
                Box::new(Self::parse_condition_expr(&text[..pos])),
                Box::new(Self::parse_condition_expr(&text[pos + 4..])),
            );
        }
        if let Some(pos) = text.rfind(" and ") {
            return AstCondition::And(
                Box::new(Self::parse_condition_expr(&text[..pos])),
                Box::new(Self::parse_condition_expr(&text[pos + 5..])),
            );
        }
        if text.starts_with('$') {
            return AstCondition::StringMatch(text.to_string());
        }
        if text.starts_with('#') {
            let parts: Vec<&str> = text.splitn(2, ' ').collect();
            if parts.len() == 2 {
                let (op, val) = Self::parse_comp_op_val(parts[1]);
                return AstCondition::StringCount(parts[0].to_string(), op, val);
            }
        }
        AstCondition::True
    }

    fn parse_comp_op_val(text: &str) -> (AstCompOp, i64) {
        let ops = [(">=", AstCompOp::Ge), ("<=", AstCompOp::Le), ("!=", AstCompOp::Ne),
                   (">", AstCompOp::Gt), ("<", AstCompOp::Lt), ("==", AstCompOp::Eq)];
        for (sym, op) in &ops {
            if let Some(rest) = text.trim().strip_prefix(sym) {
                let n = rest.trim().parse::<i64>().unwrap_or(0);
                return (*op, n);
            }
        }
        (AstCompOp::Eq, 0)
    }
}

impl Default for RuleCompiler {
    fn default() -> Self { Self::new() }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_RULE: &str = r#"
rule TestRule {
    meta:
        description = "A test rule"
        version = 1
    strings:
        $s1 = "hello" nocase
        $s2 = { DE AD BE EF }
    condition:
        $s1 or $s2
}
"#;

    #[test]
    fn test_compile_simple_rule() {
        let c = RuleCompiler::new();
        let r = c.compile(SIMPLE_RULE).unwrap();
        assert_eq!(r.name, "TestRule");
        assert_eq!(r.strings.len(), 2);
        assert!(!r.bytecode.is_empty());
    }

    #[test]
    fn test_meta_parsed() {
        let c = RuleCompiler::new();
        let r = c.compile(SIMPLE_RULE).unwrap();
        assert!(r.meta.contains_key("description"));
        assert!(r.meta.contains_key("version"));
    }

    #[test]
    fn test_string_nocase() {
        let c = RuleCompiler::new();
        let r = c.compile(SIMPLE_RULE).unwrap();
        let s1 = r.strings.iter().find(|s| s.id == "$s1").unwrap();
        assert!(s1.nocase());
    }

    #[test]
    fn test_hex_string() {
        let c = RuleCompiler::new();
        let r = c.compile(SIMPLE_RULE).unwrap();
        let s2 = r.strings.iter().find(|s| s.id == "$s2").unwrap();
        assert!(matches!(s2.value, AstStringValue::Hex(_)));
    }

    #[test]
    fn test_condition_or() {
        let c = RuleCompiler::new();
        let r = c.compile(SIMPLE_RULE).unwrap();
        // Or condition emits two child ops + BoolOr.
        assert!(r.bytecode.iter().any(|op| matches!(op, Bytecode::Or)));
    }

    #[test]
    fn test_lexer_basic() {
        let mut lex = Lexer::new("rule Foo { condition: true }");
        let tokens = lex.tokenize();
        assert!(tokens.contains(&Token::Rule));
        assert!(tokens.contains(&Token::True));
    }

    #[test]
    fn test_lexer_string_literal() {
        let mut lex = Lexer::new(r#""hello world""#);
        let t = lex.next_token();
        assert_eq!(t, Token::StringLiteral("hello world".to_string()));
    }

    #[test]
    fn test_compile_filesize_condition() {
        let src = r"rule Big { condition: filesize > 1024 }";
        let c = RuleCompiler::new();
        let r = c.compile(src).unwrap();
        assert!(r.bytecode.iter().any(|op| matches!(op, Bytecode::CheckFilesize(AstCompOp::Gt, 1024))));
    }

    #[test]
    fn test_global_rule() {
        let src = "global rule G { condition: any of them }";
        let c = RuleCompiler::new();
        let r = c.compile(src).unwrap();
        assert!(r.global);
    }

    #[test]
    fn test_complexity_non_zero() {
        let c = RuleCompiler::new();
        let r = c.compile(SIMPLE_RULE).unwrap();
        assert!(r.complexity > 0);
    }
}
