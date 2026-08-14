use anyhow::{Result, anyhow};

// ── AST nodes ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum YaraToken {
    Rule,
    Condition,
    Strings,
    Meta,
    LBrace,
    RBrace,
    Colon,
    Assign,
    And,
    Or,
    Not,
    All,
    Any,
    Of,
    Them,
    In,
    At,
    For,
    Identifier(String),
    StringId(String),     // $name
    StringCount(String),  // #name
    StringOffset(String), // @name
    StringLength(String), // !name
    HexString(Vec<HexByte>),
    TextString(String),
    RegexString(String),
    IntLit(i64),
    FloatLit(f64),
    BoolLit(bool),
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Dot,
    Star,
    Plus,
    Minus,
    Slash,
    Percent,
    Eq,
    NEq,
    Lt,
    Le,
    Gt,
    Ge,
    Tilde,
    Caret,
    Amp,
    Pipe,
    Lshift,
    Rshift,
    Contains,
    IContains,
    StartsWith,
    EndsWith,
    Matches,
    Private,
    Global,
    Nocase,
    Wide,
    Ascii,
    Fullword,
    Base64,
    Xor,
    Eof,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HexByte {
    Literal(u8),
    Wildcard,
    Nibble(Option<u8>, Option<u8>),
    Jump(Option<u32>, Option<u32>),
    Alt(Vec<Vec<Self>>),
}

// ── Lexer ──────────────────────────────────────────────────────────────────────

pub struct YaraLexer<'a> {
    input: &'a str,
    pos: usize,
    line: usize,
    col: usize,
}

impl<'a> YaraLexer<'a> {
    #[must_use]
    pub const fn new(input: &'a str) -> Self {
        Self { input, pos: 0, line: 1, col: 1 }
    }

    fn peek(&self) -> Option<char> { self.input[self.pos..].chars().next() }
    fn advance(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        if c == '\n' { self.line += 1; self.col = 1; } else { self.col += 1; }
        Some(c)
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            match self.peek() {
                Some(' ' | '\t' | '\r' | '\n') => { self.advance(); }
                Some('/') if self.input.as_bytes().get(self.pos + 1) == Some(&b'/') => {
                    while self.peek() != Some('\n') && self.peek().is_some() { self.advance(); }
                }
                Some('/') if self.input.as_bytes().get(self.pos + 1) == Some(&b'*') => {
                    self.advance(); self.advance();
                    while self.pos + 1 < self.input.len() {
                        if self.peek() == Some('*') && self.input[self.pos+1..].starts_with('/') {
                            self.advance(); self.advance(); break;
                        }
                        self.advance();
                    }
                }
                _ => break,
            }
        }
    }

    fn read_identifier(&mut self, first: char) -> String {
        let mut s = String::from(first);
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' { s.push(c); self.advance(); } else { break; }
        }
        s
    }

    fn read_string(&mut self) -> Result<String> {
        let mut s = String::new();
        loop {
            match self.advance() {
                Some('"') => return Ok(s),
                Some('\\') => {
                    match self.advance() {
                        Some('n') => s.push('\n'),
                        Some('t') => s.push('\t'),
                        Some('r') => s.push('\r'),
                        Some('\\') => s.push('\\'),
                        Some('"') => s.push('"'),
                        Some('x') => {
                            let h1 = self.advance().ok_or_else(|| anyhow!("unterminated \\x escape"))?;
                            let h2 = self.advance().ok_or_else(|| anyhow!("unterminated \\x escape"))?;
                            let n = u8::from_str_radix(&format!("{h1}{h2}"), 16)
                                .map_err(|_| anyhow!("invalid \\x hex digits: {h1:?}{h2:?}"))?;
                            s.push(n as char);
                        }
                        _ => return Err(anyhow!("invalid escape")),
                    }
                }
                Some(c) => s.push(c),
                None => return Err(anyhow!("unterminated string")),
            }
        }
    }

    fn read_hex_string(&mut self) -> Vec<HexByte> {
        let mut bytes = Vec::new();
        loop {
            match self.peek() {
                Some('}') => { self.advance(); break; }
                Some(' ' | '\t' | '\n' | '\r') => { self.advance(); }
                Some('?') => {
                    self.advance();
                    if self.peek() == Some('?') {
                        self.advance(); bytes.push(HexByte::Wildcard);
                    } else {
                        let lo = self.advance().and_then(|c| c.to_digit(16).map(|d| u8::try_from(d).unwrap_or(15)));
                        bytes.push(HexByte::Nibble(None, lo));
                    }
                }
                Some('[') => {
                    self.advance();
                    let min = self.read_decimal_opt();
                    if self.peek() == Some('-') { self.advance(); }
                    let max = self.read_decimal_opt();
                    if self.peek() == Some(']') { self.advance(); }
                    bytes.push(HexByte::Jump(min, max));
                }
                Some(c) if c.is_ascii_hexdigit() => {
                    let hi = u8::try_from(c.to_digit(16).unwrap_or(0)).unwrap_or(0);
                    self.advance();
                    let lo = self.peek().and_then(|c| c.to_digit(16).map(|d| u8::try_from(d).unwrap_or(15)));
                    if lo.is_some() { self.advance(); }
                    bytes.push(HexByte::Literal((hi << 4) | lo.unwrap_or(0)));
                }
                _ => break,
            }
        }
        bytes
    }

    fn read_decimal_opt(&mut self) -> Option<u32> {
        let mut s = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() { s.push(c); self.advance(); } else { break; }
        }
        s.parse().ok()
    }

    /// Tokenize the input into a sequence of [`YaraToken`]s.
    ///
    /// # Errors
    /// Returns an error if the input contains an invalid string escape or
    /// an unterminated string literal.
    ///
    /// # Panics
    /// Does not panic in practice; the `unwrap` on `advance()` is guarded by
    /// the preceding `is_none()` check.
    pub fn tokenize(&mut self) -> Result<Vec<YaraToken>> {
        let mut tokens = Vec::new();
        // Context flag: set when the previous emitted token is `=` following
        // a `$id` (string definition assignment). In that context, `{ ... }`
        // is a hex-string pattern and `/ ... /` is a regex pattern, rather
        // than a brace/slash token.
        let mut expect_pattern = false;
        loop {
            self.skip_whitespace_and_comments();
            if self.peek().is_none() { tokens.push(YaraToken::Eof); break; }
            let c = self.advance().unwrap();
            // Handle pattern-context before falling through to ordinary token
            // dispatch so that `{` / `/` produce HexString / RegexString.
            if expect_pattern {
                match c {
                    '{' => {
                        let hex = self.read_hex_string();
                        tokens.push(YaraToken::HexString(hex));
                        expect_pattern = false;
                        continue;
                    }
                    '/' => {
                        let mut r = String::new();
                        while let Some(ch) = self.advance() {
                            if ch == '/' { break; }
                            r.push(ch);
                        }
                        tokens.push(YaraToken::RegexString(r));
                        expect_pattern = false;
                        continue;
                    }
                    _ => {}
                }
                // expect_pattern is recomputed at the end of the loop based
                // on (tok, prev) so no explicit reset is required here.
            }
            let tok = match c {
                '{' => YaraToken::LBrace,
                '}' => YaraToken::RBrace,
                '(' => YaraToken::LParen,
                ')' => YaraToken::RParen,
                '[' => YaraToken::LBracket,
                ']' => YaraToken::RBracket,
                ':' => YaraToken::Colon,
                '=' if self.peek() == Some('=') => { self.advance(); YaraToken::Eq }
                '=' => YaraToken::Assign,
                '!' if self.peek() == Some('=') => { self.advance(); YaraToken::NEq }
                '!' => {
                    let mut id = String::new();
                    while let Some(c) = self.peek() {
                        if c.is_alphanumeric() || c == '_' { id.push(c); self.advance(); } else { break; }
                    }
                    YaraToken::StringLength(id)
                }
                '<' if self.peek() == Some('=') => { self.advance(); YaraToken::Le }
                '<' if self.peek() == Some('<') => { self.advance(); YaraToken::Lshift }
                '<' => YaraToken::Lt,
                '>' if self.peek() == Some('=') => { self.advance(); YaraToken::Ge }
                '>' if self.peek() == Some('>') => { self.advance(); YaraToken::Rshift }
                '>' => YaraToken::Gt,
                '+' => YaraToken::Plus,
                '-' => YaraToken::Minus,
                '*' => YaraToken::Star,
                '/' => YaraToken::Slash,
                '%' => YaraToken::Percent,
                '~' => YaraToken::Tilde,
                '^' => YaraToken::Caret,
                '&' => YaraToken::Amp,
                '|' => YaraToken::Pipe,
                ',' => YaraToken::Comma,
                '.' => YaraToken::Dot,
                '"' => YaraToken::TextString(self.read_string()?),
                '$' => {
                    let mut id = String::new();
                    while let Some(c) = self.peek() {
                        if c.is_alphanumeric() || c == '_' || c == '*' { id.push(c); self.advance(); } else { break; }
                    }
                    YaraToken::StringId(id)
                }
                '#' => {
                    let mut id = String::new();
                    while let Some(c) = self.peek() {
                        if c.is_alphanumeric() || c == '_' { id.push(c); self.advance(); } else { break; }
                    }
                    YaraToken::StringCount(id)
                }
                '@' => {
                    let mut id = String::new();
                    while let Some(c) = self.peek() {
                        if c.is_alphanumeric() || c == '_' { id.push(c); self.advance(); } else { break; }
                    }
                    YaraToken::StringOffset(id)
                }
                c if c.is_alphabetic() || c == '_' => {
                    let id = self.read_identifier(c);
                    match id.as_str() {
                        "rule" => YaraToken::Rule,
                        "condition" => YaraToken::Condition,
                        "strings" => YaraToken::Strings,
                        "meta" => YaraToken::Meta,
                        "and" => YaraToken::And,
                        "or" => YaraToken::Or,
                        "not" => YaraToken::Not,
                        "all" => YaraToken::All,
                        "any" => YaraToken::Any,
                        "of" => YaraToken::Of,
                        "them" => YaraToken::Them,
                        "in" => YaraToken::In,
                        "at" => YaraToken::At,
                        "for" => YaraToken::For,
                        "private" => YaraToken::Private,
                        "global" => YaraToken::Global,
                        "nocase" => YaraToken::Nocase,
                        "wide" => YaraToken::Wide,
                        "ascii" => YaraToken::Ascii,
                        "fullword" => YaraToken::Fullword,
                        "base64" => YaraToken::Base64,
                        "xor" => YaraToken::Xor,
                        "contains" => YaraToken::Contains,
                        "icontains" => YaraToken::IContains,
                        "startswith" => YaraToken::StartsWith,
                        "endswith" => YaraToken::EndsWith,
                        "matches" => YaraToken::Matches,
                        "true" => YaraToken::BoolLit(true),
                        "false" => YaraToken::BoolLit(false),
                        _ => YaraToken::Identifier(id),
                    }
                }
                c if c.is_ascii_digit() => {
                    let mut s = String::from(c);
                    while let Some(d) = self.peek() {
                        if d.is_ascii_digit() { s.push(d); self.advance(); } else { break; }
                    }
                    if self.peek() == Some('.') {
                        s.push('.'); self.advance();
                        while let Some(d) = self.peek() {
                            if d.is_ascii_digit() { s.push(d); self.advance(); } else { break; }
                        }
                        YaraToken::FloatLit(s.parse().unwrap_or(0.0))
                    } else {
                        YaraToken::IntLit(s.parse().unwrap_or(0))
                    }
                }
                _ => return Err(anyhow!("unexpected character '{}' at line {}", c, self.line)),
            };
            // After `$id =` we expect a string pattern (text/hex/regex). Flag
            // this so the next `{` or `/` is lexed as HexString/RegexString.
            expect_pattern = matches!(tok, YaraToken::Assign)
                && matches!(tokens.last(), Some(YaraToken::StringId(_)));
            tokens.push(tok);
        }
        Ok(tokens)
    }
}

// ── AST ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct YaraRule {
    pub name: String,
    pub tags: Vec<String>,
    pub is_private: bool,
    pub is_global: bool,
    pub meta: Vec<(String, MetaValue)>,
    pub strings: Vec<YaraStringDef>,
    pub condition: Expr,
}

#[derive(Debug, Clone)]
pub enum MetaValue {
    String(String),
    Int(i64),
    Bool(bool),
}

#[derive(Debug, Clone)]
pub struct YaraStringDef {
    pub id: String,
    pub pattern: YaraPattern,
    pub modifiers: StringModifiers,
}

#[derive(Debug, Clone, Default)]
pub struct StringModifiers {
    pub nocase: bool,
    pub wide: bool,
    pub ascii: bool,
    pub fullword: bool,
    pub base64: bool,
    pub xor: bool,
    pub xor_range: Option<(u8, u8)>,
    pub private: bool,
}


#[derive(Debug, Clone)]
pub enum YaraPattern {
    Text(String),
    Hex(Vec<HexByte>),
    Regex(String),
}

#[derive(Debug, Clone)]
pub enum Expr {
    Bool(bool),
    Int(i64),
    Float(f64),
    StringMatch(String),
    StringCount(String),
    StringOffset(String, Box<Self>),
    StringLength(String, Box<Self>),
    BinOp(Box<Self>, BinOp, Box<Self>),
    UnOp(UnOp, Box<Self>),
    AllOf(StringSet),
    AnyOf(StringSet),
    CountOf(StringSet, Box<Self>),
    ForIn(Box<Self>, StringSet, Box<Self>),
    FunctionCall(String, Vec<Self>),
    Identifier(String),
    FieldAccess(Box<Self>, String),
    Index(Box<Self>, Box<Self>),
}

#[derive(Debug, Clone)]
pub enum BinOp {
    And, Or, Add, Sub, Mul, Div, Mod, Eq, NEq, Lt, Le, Gt, Ge,
    BitAnd, BitOr, BitXor, Lshift, Rshift, Contains, IContains, StartsWith, EndsWith, Matches,
}

#[derive(Debug, Clone)]
pub enum UnOp { Not, Neg, BitNot }

#[derive(Debug, Clone)]
pub enum StringSet {
    Them,
    Named(Vec<String>),
}

// ── Compiled rule ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub name: String,
    pub is_private: bool,
    pub is_global: bool,
    pub meta: Vec<(String, MetaValue)>,
    pub string_matchers: Vec<CompiledStringMatcher>,
    pub condition_bytecode: Vec<CondInstr>,
}

#[derive(Debug, Clone)]
pub struct CompiledStringMatcher {
    pub id: String,
    pub matcher_type: MatcherType,
    pub nocase: bool,
    pub fullword: bool,
    pub xor_variants: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum MatcherType {
    Literal(Vec<u8>),
    Regex(String),
    Hex(Vec<HexByte>),
    WideText(Vec<u8>),
}

#[derive(Debug, Clone)]
pub enum CondInstr {
    PushBool(bool),
    PushInt(i64),
    PushStringMatched(usize),
    PushStringCount(usize),
    PushStringOffset(usize),
    And,
    Or,
    Not,
    Add,
    Sub,
    Mul,
    Div,
    Eq,
    NEq,
    Lt,
    Le,
    Gt,
    Ge,
    AllOf(Vec<usize>),
    AnyOf(Vec<usize>),
    Halt,
}

/// Compile YARA rules from source text.
///
/// # Errors
/// Returns an error if the source text contains lexer or parser errors.
pub fn compile_rules(source: &str) -> Result<Vec<CompiledRule>> {
    let mut lexer = YaraLexer::new(source);
    let tokens = lexer.tokenize()?;
    let mut parser = YaraParser::new(tokens);
    let rules = parser.parse()?;
    Ok(rules.iter().map(compile_rule).collect())
}

fn compile_rule(rule: &YaraRule) -> CompiledRule {
    let mut matchers = Vec::new();
    for sd in &rule.strings {
        let matcher_type = match &sd.pattern {
            YaraPattern::Text(s) => {
                if sd.modifiers.wide {
                    let wide: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
                    MatcherType::WideText(wide)
                } else {
                    MatcherType::Literal(s.as_bytes().to_vec())
                }
            }
            YaraPattern::Hex(h) => MatcherType::Hex(h.clone()),
            YaraPattern::Regex(r) => MatcherType::Regex(r.clone()),
        };
        let xor_variants = if sd.modifiers.xor {
            if let Some((lo, hi)) = sd.modifiers.xor_range { (lo..=hi).collect() } else { (0u8..=255u8).collect() }
        } else { vec![] };
        matchers.push(CompiledStringMatcher {
            id: sd.id.clone(),
            matcher_type,
            nocase: sd.modifiers.nocase,
            fullword: sd.modifiers.fullword,
            xor_variants,
        });
    }
    CompiledRule {
        name: rule.name.clone(),
        is_private: rule.is_private,
        is_global: rule.is_global,
        meta: rule.meta.clone(),
        string_matchers: matchers,
        condition_bytecode: vec![CondInstr::PushBool(true), CondInstr::Halt],
    }
}

// ── Parser (stub) ─────────────────────────────────────────────────────────────

pub struct YaraParser {
    tokens: Vec<YaraToken>,
    pos: usize,
}

impl YaraParser {
    #[must_use]
    pub fn new(mut tokens: Vec<YaraToken>) -> Self {
        // Ensure there is always at least one token so that peek/advance never
        // index an empty slice (panic-on-input).
        if tokens.is_empty() {
            tokens.push(YaraToken::Eof);
        }
        Self { tokens, pos: 0 }
    }
    fn peek(&self) -> &YaraToken {
        // tokens is guaranteed non-empty (tokenizer always appends Eof), but
        // guard with saturating_sub to avoid a panic if constructed directly
        // with an empty token list.
        let last = self.tokens.len().saturating_sub(1);
        &self.tokens[self.pos.min(last)]
    }
    fn advance(&mut self) -> &YaraToken {
        let last = self.tokens.len().saturating_sub(1);
        let idx = self.pos.min(last);
        let t = &self.tokens[idx];
        if self.pos < last { self.pos += 1; }
        t
    }

    /// Parse all rules from the token stream.
    ///
    /// # Errors
    /// Returns an error if any rule fails to parse.
    pub fn parse(&mut self) -> Result<Vec<YaraRule>> {
        let mut rules = Vec::new();
        while *self.peek() != YaraToken::Eof {
            rules.push(self.parse_rule()?);
        }
        Ok(rules)
    }

    fn parse_rule(&mut self) -> Result<YaraRule> {
        let mut is_private = false;
        let mut is_global = false;
        if *self.peek() == YaraToken::Private { self.advance(); is_private = true; }
        if *self.peek() == YaraToken::Global { self.advance(); is_global = true; }
        if *self.peek() != YaraToken::Rule { return Err(anyhow!("expected 'rule'")); }
        self.advance();
        let YaraToken::Identifier(name) = self.advance().clone() else { return Err(anyhow!("expected rule name")); };
        let mut tags = Vec::new();
        if *self.peek() == YaraToken::Colon {
            self.advance();
            while let YaraToken::Identifier(t) = self.peek().clone() { tags.push(t); self.advance(); }
        }
        if *self.peek() != YaraToken::LBrace { return Err(anyhow!("expected '{{'")); }
        self.advance();
        let mut meta = Vec::new();
        let mut strings = Vec::new();
        let condition;
        loop {
            match self.peek().clone() {
                YaraToken::Meta => { self.advance(); self.advance(); meta = self.parse_meta(); }
                YaraToken::Strings => { self.advance(); self.advance(); strings = self.parse_strings(); }
                YaraToken::Condition => { self.advance(); self.advance(); condition = self.parse_expr()?; break; }
                YaraToken::RBrace | YaraToken::Eof => { condition = Expr::Bool(true); break; }
                _ => { self.advance(); }
            }
        }
        while *self.peek() != YaraToken::RBrace && *self.peek() != YaraToken::Eof { self.advance(); }
        self.advance();
        Ok(YaraRule { name, tags, is_private, is_global, meta, strings, condition })
    }

    fn parse_meta(&mut self) -> Vec<(String, MetaValue)> {
        let mut meta = Vec::new();
        while let YaraToken::Identifier(k) = self.peek().clone() {
            self.advance();
            if *self.peek() == YaraToken::Assign { self.advance(); }
            let v = match self.advance().clone() {
                YaraToken::TextString(s) => MetaValue::String(s),
                YaraToken::IntLit(n) => MetaValue::Int(n),
                YaraToken::BoolLit(b) => MetaValue::Bool(b),
                _ => MetaValue::String(String::new()),
            };
            meta.push((k, v));
        }
        meta
    }

    fn parse_strings(&mut self) -> Vec<YaraStringDef> {
        let mut defs = Vec::new();
        while let YaraToken::StringId(id) = self.peek().clone() {
            self.advance();
            if *self.peek() == YaraToken::Assign { self.advance(); }
            let pattern = match self.advance().clone() {
                YaraToken::TextString(s) => YaraPattern::Text(s),
                YaraToken::HexString(h) => YaraPattern::Hex(h),
                YaraToken::RegexString(r) => YaraPattern::Regex(r),
                _ => YaraPattern::Text(String::new()),
            };
            let mut modifiers = StringModifiers::default();
            loop {
                match self.peek().clone() {
                    YaraToken::Nocase => { self.advance(); modifiers.nocase = true; }
                    YaraToken::Wide => { self.advance(); modifiers.wide = true; }
                    YaraToken::Ascii => { self.advance(); modifiers.ascii = true; }
                    YaraToken::Fullword => { self.advance(); modifiers.fullword = true; }
                    YaraToken::Base64 => { self.advance(); modifiers.base64 = true; }
                    YaraToken::Xor => { self.advance(); modifiers.xor = true; }
                    YaraToken::Private => { self.advance(); modifiers.private = true; }
                    _ => break,
                }
            }
            defs.push(YaraStringDef { id, pattern, modifiers });
        }
        defs
    }

    fn parse_expr(&mut self) -> Result<Expr> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut left = self.parse_and()?;
        while *self.peek() == YaraToken::Or {
            self.advance();
            let right = self.parse_and()?;
            left = Expr::BinOp(Box::new(left), BinOp::Or, Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut left = self.parse_not()?;
        while *self.peek() == YaraToken::And {
            self.advance();
            let right = self.parse_not()?;
            left = Expr::BinOp(Box::new(left), BinOp::And, Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr> {
        // Iterative rather than recursive to prevent stack overflow on inputs
        // with deeply nested `not not not ...` chains from untrusted rule text.
        let mut not_depth = 0usize;
        while *self.peek() == YaraToken::Not {
            not_depth += 1;
            if not_depth > 256 {
                return Err(anyhow!("too many nested 'not' operators (depth > 256)"));
            }
            self.advance();
        }
        let mut expr = self.parse_primary()?;
        for _ in 0..not_depth {
            expr = Expr::UnOp(UnOp::Not, Box::new(expr));
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        match self.advance().clone() {
            YaraToken::BoolLit(b) => Ok(Expr::Bool(b)),
            YaraToken::IntLit(n) => Ok(Expr::Int(n)),
            YaraToken::FloatLit(f) => Ok(Expr::Float(f)),
            YaraToken::StringId(s) => Ok(Expr::StringMatch(s)),
            YaraToken::StringCount(s) => Ok(Expr::StringCount(s)),
            YaraToken::LParen => { let e = self.parse_expr()?; self.advance(); Ok(e) }
            YaraToken::All => { self.advance(); Ok(Expr::AllOf(StringSet::Them)) }
            YaraToken::Any => { self.advance(); Ok(Expr::AnyOf(StringSet::Them)) }
            _ => Ok(Expr::Bool(true)),
        }
    }
}
