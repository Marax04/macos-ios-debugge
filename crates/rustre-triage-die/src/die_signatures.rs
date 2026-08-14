//! DIE Signature DSL parser and JavaScript-like condition evaluator.
//!
//! Implements a Detect-It-Easy style signature engine that parses a custom
//! DSL for file-format detection. Signatures can inspect PE/ELF/Mach-O header
//! bytes, section entropy, import tables, and raw byte patterns through a
//! JavaScript-inspired condition syntax.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Token / Lexer
// ---------------------------------------------------------------------------

/// Lexer token for the DIE DSL.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// Integer literal.
    Int(i64),
    /// Floating-point literal.
    Float(f64),
    /// String literal (content without surrounding quotes).
    Str(String),
    /// Boolean literal.
    Bool(bool),
    /// Identifier (variable or function name).
    Ident(String),
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `&&`
    And,
    /// `||`
    Or,
    /// `!`
    Not,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `.`
    Dot,
    /// `,`
    Comma,
    /// `+`
    Plus,
    /// `-`
    Minus,
    /// `*`
    Star,
    /// `/`
    Slash,
    /// `%`
    Percent,
    /// `&` (bitwise AND)
    BitAnd,
    /// `|` (bitwise OR)
    BitOr,
    /// `^` (bitwise XOR)
    BitXor,
    /// `>>` (shift right)
    Shr,
    /// `<<` (shift left)
    Shl,
    /// End of input.
    Eof,
}

/// Lexer that converts a source string into a stream of [`Token`]s.
pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    /// Create a lexer over `src`.
    pub fn new(src: &'a str) -> Self {
        Self {
            src: src.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let ch = self.src.get(self.pos).copied();
        self.pos += 1;
        ch
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            // Skip whitespace.
            while self.peek().map_or(false, |c| c.is_ascii_whitespace()) {
                self.advance();
            }
            // Skip `//` line comments.
            if self.src.get(self.pos..self.pos + 2) == Some(b"//") {
                while self.peek().map_or(false, |c| c != b'\n') {
                    self.advance();
                }
                continue;
            }
            // Skip `/* */` block comments.
            if self.src.get(self.pos..self.pos + 2) == Some(b"/*") {
                self.pos += 2;
                loop {
                    if self.src.get(self.pos..self.pos + 2) == Some(b"*/") {
                        self.pos += 2;
                        break;
                    }
                    if self.advance().is_none() {
                        break;
                    }
                }
                continue;
            }
            break;
        }
    }

    /// Return the next token without consuming it.
    pub fn peek_token(&mut self) -> Token {
        let saved = self.pos;
        let tok = self.next_token();
        self.pos = saved;
        tok
    }

    /// Consume and return the next token.
    pub fn next_token(&mut self) -> Token {
        self.skip_whitespace_and_comments();
        let ch = match self.peek() {
            None => return Token::Eof,
            Some(c) => c,
        };

        match ch {
            b'0'..=b'9' => self.lex_number(),
            b'"' | b'\'' => self.lex_string(ch),
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => self.lex_ident(),
            b'=' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Token::Eq
                } else {
                    Token::Ident("=".to_string())
                }
            }
            b'!' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Token::Ne
                } else {
                    Token::Not
                }
            }
            b'<' => {
                self.advance();
                if self.peek() == Some(b'<') {
                    self.advance();
                    Token::Shl
                } else if self.peek() == Some(b'=') {
                    self.advance();
                    Token::Le
                } else {
                    Token::Lt
                }
            }
            b'>' => {
                self.advance();
                if self.peek() == Some(b'>') {
                    self.advance();
                    Token::Shr
                } else if self.peek() == Some(b'=') {
                    self.advance();
                    Token::Ge
                } else {
                    Token::Gt
                }
            }
            b'&' => {
                self.advance();
                if self.peek() == Some(b'&') {
                    self.advance();
                    Token::And
                } else {
                    Token::BitAnd
                }
            }
            b'|' => {
                self.advance();
                if self.peek() == Some(b'|') {
                    self.advance();
                    Token::Or
                } else {
                    Token::BitOr
                }
            }
            b'^' => {
                self.advance();
                Token::BitXor
            }
            b'(' => {
                self.advance();
                Token::LParen
            }
            b')' => {
                self.advance();
                Token::RParen
            }
            b'[' => {
                self.advance();
                Token::LBracket
            }
            b']' => {
                self.advance();
                Token::RBracket
            }
            b'.' => {
                self.advance();
                Token::Dot
            }
            b',' => {
                self.advance();
                Token::Comma
            }
            b'+' => {
                self.advance();
                Token::Plus
            }
            b'-' => {
                self.advance();
                Token::Minus
            }
            b'*' => {
                self.advance();
                Token::Star
            }
            b'/' => {
                self.advance();
                Token::Slash
            }
            b'%' => {
                self.advance();
                Token::Percent
            }
            _ => {
                self.advance();
                Token::Eof
            }
        }
    }

    fn lex_number(&mut self) -> Token {
        let start = self.pos;
        let mut is_float = false;
        let mut is_hex = false;

        // Hex prefix `0x`
        if self.src.get(self.pos..self.pos + 2) == Some(b"0x")
            || self.src.get(self.pos..self.pos + 2) == Some(b"0X")
        {
            self.pos += 2;
            is_hex = true;
            while self.peek().map_or(false, |c| c.is_ascii_hexdigit()) {
                self.advance();
            }
        } else {
            while self.peek().map_or(false, |c| c.is_ascii_digit()) {
                self.advance();
            }
            if self.peek() == Some(b'.') {
                is_float = true;
                self.advance();
                while self.peek().map_or(false, |c| c.is_ascii_digit()) {
                    self.advance();
                }
            }
        }

        let raw = std::str::from_utf8(&self.src[start..self.pos]).unwrap_or("0");
        if is_hex {
            let hex_part = raw.trim_start_matches("0x").trim_start_matches("0X");
            Token::Int(i64::from_str_radix(hex_part, 16).unwrap_or(0))
        } else if is_float {
            Token::Float(raw.parse().unwrap_or(0.0))
        } else {
            Token::Int(raw.parse().unwrap_or(0))
        }
    }

    fn lex_string(&mut self, quote: u8) -> Token {
        self.advance(); // consume opening quote
        let mut s = String::new();
        loop {
            match self.advance() {
                None | Some(b'\n') => break,
                Some(b) if b == quote => break,
                Some(b'\\') => {
                    match self.advance() {
                        Some(b'n') => s.push('\n'),
                        Some(b't') => s.push('\t'),
                        Some(b'r') => s.push('\r'),
                        Some(b'\\') => s.push('\\'),
                        Some(b'\'') => s.push('\''),
                        Some(b'"') => s.push('"'),
                        Some(b'x') => {
                            // Hex escape: \xNN
                            let hi = self.advance().unwrap_or(b'0');
                            let lo = self.advance().unwrap_or(b'0');
                            let hex = [hi, lo];
                            if let Ok(hx) = std::str::from_utf8(&hex) {
                                if let Ok(v) = u8::from_str_radix(hx, 16) {
                                    s.push(v as char);
                                }
                            }
                        }
                        Some(c) => s.push(c as char),
                        None => break,
                    }
                }
                Some(b) => s.push(b as char),
            }
        }
        Token::Str(s)
    }

    fn lex_ident(&mut self) -> Token {
        let start = self.pos;
        while self
            .peek()
            .map_or(false, |c| c.is_ascii_alphanumeric() || c == b'_')
        {
            self.advance();
        }
        let raw = std::str::from_utf8(&self.src[start..self.pos]).unwrap_or("");
        match raw {
            "true" => Token::Bool(true),
            "false" => Token::Bool(false),
            _ => Token::Ident(raw.to_string()),
        }
    }

    /// Tokenise the entire source into a `Vec<Token>`.
    pub fn tokenize(src: &str) -> Vec<Token> {
        let mut lex = Lexer {
            src: src.as_bytes(),
            pos: 0,
        };
        let mut tokens = Vec::new();
        loop {
            let t = lex.next_token();
            let done = t == Token::Eof;
            tokens.push(t);
            if done {
                break;
            }
        }
        tokens
    }
}

// ---------------------------------------------------------------------------
// Value – the runtime type used in condition evaluation
// ---------------------------------------------------------------------------

/// A runtime value in the DIE DSL evaluator.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Boolean.
    Bool(bool),
    /// Integer (fits any signed or unsigned 64-bit).
    Int(i64),
    /// Floating-point.
    Float(f64),
    /// String.
    Str(String),
    /// Null / undefined.
    Null,
}

impl Value {
    /// Coerce to boolean: `0`, `""`, `Null`, and `false` are falsy.
    pub fn truthy(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::Int(n) => *n != 0,
            Value::Float(f) => *f != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::Null => false,
        }
    }

    /// Coerce to i64.
    pub fn as_int(&self) -> i64 {
        match self {
            Value::Bool(b) => i64::from(*b),
            Value::Int(n) => *n,
            Value::Float(f) => *f as i64,
            Value::Str(s) => s.parse().unwrap_or(0),
            Value::Null => 0,
        }
    }

    /// Coerce to f64.
    pub fn as_float(&self) -> f64 {
        match self {
            Value::Bool(b) => f64::from(*b),
            Value::Int(n) => *n as f64,
            Value::Float(f) => *f,
            Value::Str(s) => s.parse().unwrap_or(0.0),
            Value::Null => 0.0,
        }
    }

    /// Coerce to string.
    pub fn as_str(&self) -> String {
        match self {
            Value::Bool(b) => b.to_string(),
            Value::Int(n) => n.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Str(s) => s.clone(),
            Value::Null => String::new(),
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// MatchContext – file-level inspection surface exposed to conditions
// ---------------------------------------------------------------------------

/// The file type being inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileFormat {
    Pe,
    Elf,
    MachO,
    Unknown,
}

/// Context passed to condition evaluation.
///
/// Provides accessors for raw bytes, PE/ELF/Mach-O header fields, section
/// tables, and computed properties like entropy.
pub struct MatchContext<'a> {
    /// Raw file bytes.
    pub data: &'a [u8],
    /// Detected file format.
    pub format: FileFormat,
    /// Pre-computed section entropy table: `(section_index → entropy)`.
    pub section_entropy: Vec<f32>,
    /// Section names in order.
    pub section_names: Vec<String>,
    /// Number of PE sections (0 for non-PE files).
    pub section_count: usize,
    /// Detected machine type (from PE COFF header).
    pub machine_type: u16,
    /// Optional header subsystem.
    pub subsystem: u16,
    /// Import table: `dll_name → [function_names]`.
    pub imports: HashMap<String, Vec<String>>,
    /// Export function names.
    pub exports: Vec<String>,
    /// Entry-point bytes (up to 32).
    pub ep_bytes: Vec<u8>,
    /// Overlay size in bytes.
    pub overlay_size: usize,
    /// True if .NET CLR header is present.
    pub is_dotnet: bool,
}

impl<'a> MatchContext<'a> {
    /// Construct a minimal context for a raw byte slice.
    pub fn new(data: &'a [u8]) -> Self {
        let format = detect_format(data);
        Self {
            data,
            format,
            section_entropy: Vec::new(),
            section_names: Vec::new(),
            section_count: 0,
            machine_type: 0,
            subsystem: 0,
            imports: HashMap::new(),
            exports: Vec::new(),
            ep_bytes: Vec::new(),
            overlay_size: 0,
            is_dotnet: false,
        }
    }

    /// Read `len` bytes from the file at `offset`.  Returns an empty slice if
    /// out of bounds.
    pub fn read_bytes(&self, offset: usize, len: usize) -> &[u8] {
        let end = (offset + len).min(self.data.len());
        if offset >= self.data.len() {
            return &[];
        }
        &self.data[offset..end]
    }

    /// Read a u8 at `offset`.
    pub fn read_u8(&self, offset: usize) -> Option<u8> {
        self.data.get(offset).copied()
    }

    /// Read a little-endian u16 at `offset`.
    pub fn read_u16_le(&self, offset: usize) -> Option<u16> {
        if offset + 2 > self.data.len() {
            return None;
        }
        Some(u16::from_le_bytes([self.data[offset], self.data[offset + 1]]))
    }

    /// Read a little-endian u32 at `offset`.
    pub fn read_u32_le(&self, offset: usize) -> Option<u32> {
        if offset + 4 > self.data.len() {
            return None;
        }
        Some(u32::from_le_bytes(
            self.data[offset..offset + 4].try_into().unwrap_or([0; 4]),
        ))
    }

    /// Check if the file contains the given byte pattern starting at `offset`.
    pub fn matches_at(&self, offset: usize, pattern: &[u8]) -> bool {
        if offset + pattern.len() > self.data.len() {
            return false;
        }
        &self.data[offset..offset + pattern.len()] == pattern
    }

    /// Check if the file contains the given byte sequence anywhere.
    pub fn contains(&self, pattern: &[u8]) -> bool {
        self.data.windows(pattern.len()).any(|w| w == pattern)
    }

    /// Check if the file contains the given string.
    pub fn contains_str(&self, s: &str) -> bool {
        self.contains(s.as_bytes())
    }

    /// Returns the entropy of section `i`, or 0.0 if out of range.
    pub fn section_entropy(&self, i: usize) -> f32 {
        self.section_entropy.get(i).copied().unwrap_or(0.0)
    }

    /// Returns the name of section `i`, or empty string.
    pub fn section_name(&self, i: usize) -> &str {
        self.section_names.get(i).map_or("", String::as_str)
    }

    /// Check if a named section exists.
    pub fn has_section(&self, name: &str) -> bool {
        self.section_names.iter().any(|n| n == name)
    }

    /// Check if the import table contains `dll!func` (case-insensitive).
    pub fn has_import(&self, dll: &str, func: &str) -> bool {
        let dll_lower = dll.to_lowercase();
        let func_lower = func.to_lowercase();
        for (d, funcs) in &self.imports {
            if d.to_lowercase().contains(&dll_lower) {
                if funcs
                    .iter()
                    .any(|f| f.to_lowercase().contains(&func_lower))
                {
                    return true;
                }
            }
        }
        false
    }

    /// Total number of imported functions.
    pub fn import_count(&self) -> usize {
        self.imports.values().map(|v| v.len()).sum()
    }
}

fn detect_format(data: &[u8]) -> FileFormat {
    if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
        return FileFormat::Pe;
    }
    if data.len() >= 4 && data[0] == 0x7F && data[1] == b'E' && data[2] == b'L' && data[3] == b'F'
    {
        return FileFormat::Elf;
    }
    if data.len() >= 4 {
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if matches!(magic, 0xFEED_FACE | 0xCEFA_EDFE | 0xFEED_FACF | 0xCFFE_EDFE) {
            return FileFormat::MachO;
        }
        // Fat binary
        if magic == 0xCAFE_BABE {
            return FileFormat::MachO;
        }
    }
    FileFormat::Unknown
}

// ---------------------------------------------------------------------------
// AST Nodes
// ---------------------------------------------------------------------------

/// A condition expression node.
#[derive(Debug, Clone)]
pub enum Expr {
    /// Boolean literal.
    Bool(bool),
    /// Integer literal.
    Int(i64),
    /// Float literal.
    Float(f64),
    /// String literal.
    Str(String),
    /// Variable reference or function call with no arguments.
    Var(String),
    /// Function call: `name(args…)`.
    Call(String, Vec<Expr>),
    /// Method call: `receiver.method(args…)`.
    MethodCall(Box<Expr>, String, Vec<Expr>),
    /// Field access: `receiver.field`.
    Field(Box<Expr>, String),
    /// Index: `expr[index]`.
    Index(Box<Expr>, Box<Expr>),
    /// Unary `!`.
    Not(Box<Expr>),
    /// Binary comparison.
    Cmp(Box<Expr>, CmpOp, Box<Expr>),
    /// Logical `&&`.
    And(Box<Expr>, Box<Expr>),
    /// Logical `||`.
    Or(Box<Expr>, Box<Expr>),
    /// Arithmetic operation.
    Arith(Box<Expr>, ArithOp, Box<Expr>),
}

/// Comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// Arithmetic / bitwise operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parser for the DIE condition DSL.
pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    /// Create a parser over the given token stream.
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    /// Parse `src` directly into an [`Expr`].
    pub fn parse_str(src: &str) -> Result<Expr, String> {
        let tokens = Lexer::tokenize(src);
        let mut p = Self::new(tokens);
        p.parse_expr()
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        let tok = self.tokens.get(self.pos).cloned().unwrap_or(Token::Eof);
        self.pos += 1;
        tok
    }

    fn expect_ident(&mut self) -> Result<String, String> {
        match self.advance() {
            Token::Ident(s) => Ok(s),
            other => Err(format!("expected identifier, got {other:?}")),
        }
    }

    /// Parse a full expression (entry point).
    pub fn parse_expr(&mut self) -> Result<Expr, String> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_and()?;
        while *self.peek() == Token::Or {
            self.advance();
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_cmp()?;
        while *self.peek() == Token::And {
            self.advance();
            let right = self.parse_cmp()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_cmp(&mut self) -> Result<Expr, String> {
        let left = self.parse_bitor()?;
        let op = match self.peek() {
            Token::Eq => CmpOp::Eq,
            Token::Ne => CmpOp::Ne,
            Token::Lt => CmpOp::Lt,
            Token::Le => CmpOp::Le,
            Token::Gt => CmpOp::Gt,
            Token::Ge => CmpOp::Ge,
            _ => return Ok(left),
        };
        self.advance();
        let right = self.parse_bitor()?;
        Ok(Expr::Cmp(Box::new(left), op, Box::new(right)))
    }

    fn parse_bitor(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_bitxor()?;
        while *self.peek() == Token::BitOr {
            self.advance();
            let right = self.parse_bitxor()?;
            left = Expr::Arith(Box::new(left), ArithOp::BitOr, Box::new(right));
        }
        Ok(left)
    }

    fn parse_bitxor(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_bitand()?;
        while *self.peek() == Token::BitXor {
            self.advance();
            let right = self.parse_bitand()?;
            left = Expr::Arith(Box::new(left), ArithOp::BitXor, Box::new(right));
        }
        Ok(left)
    }

    fn parse_bitand(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_shift()?;
        while *self.peek() == Token::BitAnd {
            self.advance();
            let right = self.parse_shift()?;
            left = Expr::Arith(Box::new(left), ArithOp::BitAnd, Box::new(right));
        }
        Ok(left)
    }

    fn parse_shift(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_add()?;
        loop {
            let op = match self.peek() {
                Token::Shl => ArithOp::Shl,
                Token::Shr => ArithOp::Shr,
                _ => break,
            };
            self.advance();
            let right = self.parse_add()?;
            left = Expr::Arith(Box::new(left), op, Box::new(right));
        }
        Ok(left)
    }

    fn parse_add(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_mul()?;
        loop {
            let op = match self.peek() {
                Token::Plus => ArithOp::Add,
                Token::Minus => ArithOp::Sub,
                _ => break,
            };
            self.advance();
            let right = self.parse_mul()?;
            left = Expr::Arith(Box::new(left), op, Box::new(right));
        }
        Ok(left)
    }

    fn parse_mul(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Token::Star => ArithOp::Mul,
                Token::Slash => ArithOp::Div,
                Token::Percent => ArithOp::Mod,
                _ => break,
            };
            self.advance();
            let right = self.parse_unary()?;
            left = Expr::Arith(Box::new(left), op, Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, String> {
        if *self.peek() == Token::Not {
            self.advance();
            let expr = self.parse_postfix()?;
            return Ok(Expr::Not(Box::new(expr)));
        }
        if *self.peek() == Token::Minus {
            self.advance();
            let expr = self.parse_postfix()?;
            return Ok(Expr::Arith(
                Box::new(Expr::Int(0)),
                ArithOp::Sub,
                Box::new(expr),
            ));
        }
        self.parse_postfix()
    }

    fn parse_postfix(&mut self) -> Result<Expr, String> {
        let mut expr = self.parse_primary()?;
        loop {
            match self.peek().clone() {
                Token::Dot => {
                    self.advance();
                    let name = self.expect_ident()?;
                    if *self.peek() == Token::LParen {
                        self.advance();
                        let args = self.parse_args()?;
                        expr = Expr::MethodCall(Box::new(expr), name, args);
                    } else {
                        expr = Expr::Field(Box::new(expr), name);
                    }
                }
                Token::LBracket => {
                    self.advance();
                    let idx = self.parse_expr()?;
                    if *self.peek() == Token::RBracket {
                        self.advance();
                    }
                    expr = Expr::Index(Box::new(expr), Box::new(idx));
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.advance() {
            Token::Bool(b) => Ok(Expr::Bool(b)),
            Token::Int(n) => Ok(Expr::Int(n)),
            Token::Float(f) => Ok(Expr::Float(f)),
            Token::Str(s) => Ok(Expr::Str(s)),
            Token::Ident(name) => {
                if *self.peek() == Token::LParen {
                    self.advance();
                    let args = self.parse_args()?;
                    Ok(Expr::Call(name, args))
                } else {
                    Ok(Expr::Var(name))
                }
            }
            Token::LParen => {
                let inner = self.parse_expr()?;
                if *self.peek() == Token::RParen {
                    self.advance();
                }
                Ok(inner)
            }
            other => Err(format!("unexpected token in primary: {other:?}")),
        }
    }

    fn parse_args(&mut self) -> Result<Vec<Expr>, String> {
        let mut args = Vec::new();
        while *self.peek() != Token::RParen && *self.peek() != Token::Eof {
            args.push(self.parse_expr()?);
            if *self.peek() == Token::Comma {
                self.advance();
            } else {
                break;
            }
        }
        if *self.peek() == Token::RParen {
            self.advance();
        }
        Ok(args)
    }
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

/// Evaluates a parsed [`Expr`] against a [`MatchContext`].
pub struct Evaluator;

impl Evaluator {
    /// Evaluate `expr` in the given `ctx`.
    pub fn eval(expr: &Expr, ctx: &MatchContext<'_>) -> Value {
        match expr {
            Expr::Bool(b) => Value::Bool(*b),
            Expr::Int(n) => Value::Int(*n),
            Expr::Float(f) => Value::Float(*f),
            Expr::Str(s) => Value::Str(s.clone()),
            Expr::Var(name) => Self::eval_var(name, ctx),
            Expr::Call(name, args) => Self::eval_call(name, args, ctx),
            Expr::Not(inner) => Value::Bool(!Self::eval(inner, ctx).truthy()),
            Expr::And(a, b) => {
                let av = Self::eval(a, ctx);
                if !av.truthy() {
                    return Value::Bool(false);
                }
                let bv = Self::eval(b, ctx);
                Value::Bool(bv.truthy())
            }
            Expr::Or(a, b) => {
                let av = Self::eval(a, ctx);
                if av.truthy() {
                    return Value::Bool(true);
                }
                let bv = Self::eval(b, ctx);
                Value::Bool(bv.truthy())
            }
            Expr::Cmp(a, op, b) => {
                let av = Self::eval(a, ctx);
                let bv = Self::eval(b, ctx);
                Value::Bool(Self::eval_cmp(&av, *op, &bv))
            }
            Expr::Arith(a, op, b) => {
                let av = Self::eval(a, ctx);
                let bv = Self::eval(b, ctx);
                Self::eval_arith(&av, *op, &bv)
            }
            Expr::MethodCall(recv, method, args) => {
                let rv = Self::eval(recv, ctx);
                Self::eval_method(&rv, method, args, ctx)
            }
            Expr::Field(recv, field) => {
                let rv = Self::eval(recv, ctx);
                Self::eval_field(&rv, field, ctx)
            }
            Expr::Index(recv, idx) => {
                let rv = Self::eval(recv, ctx);
                let iv = Self::eval(idx, ctx);
                Self::eval_index(&rv, &iv, ctx)
            }
        }
    }

    fn eval_var(name: &str, ctx: &MatchContext<'_>) -> Value {
        match name {
            "pe" | "PE" => Value::Str("pe".to_string()),
            "elf" | "ELF" => Value::Str("elf".to_string()),
            "macho" | "MACHO" => Value::Str("macho".to_string()),
            "section_count" | "sectionCount" => Value::Int(ctx.section_count as i64),
            "machine" => Value::Int(i64::from(ctx.machine_type)),
            "subsystem" => Value::Int(i64::from(ctx.subsystem)),
            "file_size" | "fileSize" => Value::Int(ctx.data.len() as i64),
            "is_dotnet" | "isDotNet" => Value::Bool(ctx.is_dotnet),
            "overlay_size" | "overlaySize" => Value::Int(ctx.overlay_size as i64),
            _ => Value::Null,
        }
    }

    fn eval_call(name: &str, args: &[Expr], ctx: &MatchContext<'_>) -> Value {
        match name {
            "contains" | "findString" => {
                if let Some(a) = args.first() {
                    let s = Self::eval(a, ctx).as_str();
                    Value::Bool(ctx.contains_str(&s))
                } else {
                    Value::Bool(false)
                }
            }
            "byte" | "readByte" => {
                let off = args
                    .first()
                    .map(|a| Self::eval(a, ctx).as_int() as usize)
                    .unwrap_or(0);
                Value::Int(i64::from(ctx.read_u8(off).unwrap_or(0)))
            }
            "word" | "readWord" => {
                let off = args
                    .first()
                    .map(|a| Self::eval(a, ctx).as_int() as usize)
                    .unwrap_or(0);
                Value::Int(i64::from(ctx.read_u16_le(off).unwrap_or(0)))
            }
            "dword" | "readDword" => {
                let off = args
                    .first()
                    .map(|a| Self::eval(a, ctx).as_int() as usize)
                    .unwrap_or(0);
                Value::Int(i64::from(ctx.read_u32_le(off).unwrap_or(0)))
            }
            "sectionEntropy" | "section_entropy" => {
                let idx = args
                    .first()
                    .map(|a| Self::eval(a, ctx).as_int() as usize)
                    .unwrap_or(0);
                Value::Float(f64::from(ctx.section_entropy(idx)))
            }
            "sectionName" | "section_name" => {
                let idx = args
                    .first()
                    .map(|a| Self::eval(a, ctx).as_int() as usize)
                    .unwrap_or(0);
                Value::Str(ctx.section_name(idx).to_string())
            }
            "hasSection" | "has_section" => {
                if let Some(a) = args.first() {
                    let s = Self::eval(a, ctx).as_str();
                    Value::Bool(ctx.has_section(&s))
                } else {
                    Value::Bool(false)
                }
            }
            "hasImport" | "has_import" => {
                let dll = args
                    .first()
                    .map(|a| Self::eval(a, ctx).as_str())
                    .unwrap_or_default();
                let func = args
                    .get(1)
                    .map(|a| Self::eval(a, ctx).as_str())
                    .unwrap_or_default();
                Value::Bool(ctx.has_import(&dll, &func))
            }
            "importCount" | "import_count" => Value::Int(ctx.import_count() as i64),
            "ep_byte" | "epByte" => {
                let off = args
                    .first()
                    .map(|a| Self::eval(a, ctx).as_int() as usize)
                    .unwrap_or(0);
                Value::Int(i64::from(ctx.ep_bytes.get(off).copied().unwrap_or(0)))
            }
            _ => Value::Null,
        }
    }

    fn eval_cmp(a: &Value, op: CmpOp, b: &Value) -> bool {
        // String comparison
        if let (Value::Str(sa), Value::Str(sb)) = (a, b) {
            return match op {
                CmpOp::Eq => sa == sb,
                CmpOp::Ne => sa != sb,
                CmpOp::Lt => sa < sb,
                CmpOp::Le => sa <= sb,
                CmpOp::Gt => sa > sb,
                CmpOp::Ge => sa >= sb,
            };
        }
        // Numeric comparison
        let fa = a.as_float();
        let fb = b.as_float();
        match op {
            CmpOp::Eq => (fa - fb).abs() < f64::EPSILON,
            CmpOp::Ne => (fa - fb).abs() >= f64::EPSILON,
            CmpOp::Lt => fa < fb,
            CmpOp::Le => fa <= fb,
            CmpOp::Gt => fa > fb,
            CmpOp::Ge => fa >= fb,
        }
    }

    fn eval_arith(a: &Value, op: ArithOp, b: &Value) -> Value {
        let ia = a.as_int();
        let ib = b.as_int();
        let result = match op {
            ArithOp::Add => ia.wrapping_add(ib),
            ArithOp::Sub => ia.wrapping_sub(ib),
            ArithOp::Mul => ia.wrapping_mul(ib),
            ArithOp::Div => {
                if ib == 0 {
                    return Value::Null;
                }
                ia / ib
            }
            ArithOp::Mod => {
                if ib == 0 {
                    return Value::Null;
                }
                ia % ib
            }
            ArithOp::BitAnd => ia & ib,
            ArithOp::BitOr => ia | ib,
            ArithOp::BitXor => ia ^ ib,
            ArithOp::Shl => ia.wrapping_shl(ib.clamp(0, 63) as u32),
            ArithOp::Shr => ia.wrapping_shr(ib.clamp(0, 63) as u32),
        };
        Value::Int(result)
    }

    fn eval_method(recv: &Value, method: &str, args: &[Expr], ctx: &MatchContext<'_>) -> Value {
        match method {
            "contains" => {
                let needle = args
                    .first()
                    .map(|a| Self::eval(a, ctx).as_str())
                    .unwrap_or_default();
                let haystack = recv.as_str();
                Value::Bool(haystack.contains(&needle))
            }
            "startsWith" | "starts_with" => {
                let prefix = args
                    .first()
                    .map(|a| Self::eval(a, ctx).as_str())
                    .unwrap_or_default();
                Value::Bool(recv.as_str().starts_with(&prefix))
            }
            "endsWith" | "ends_with" => {
                let suffix = args
                    .first()
                    .map(|a| Self::eval(a, ctx).as_str())
                    .unwrap_or_default();
                Value::Bool(recv.as_str().ends_with(&suffix))
            }
            "toLowerCase" | "to_lower" => Value::Str(recv.as_str().to_lowercase()),
            "toUpperCase" | "to_upper" => Value::Str(recv.as_str().to_uppercase()),
            "length" | "len" => Value::Int(recv.as_str().len() as i64),
            _ => Value::Null,
        }
    }

    fn eval_field(recv: &Value, field: &str, ctx: &MatchContext<'_>) -> Value {
        match (recv, field) {
            (Value::Str(s), "length") if s == "pe" || s == "elf" => {
                Value::Int(ctx.section_count as i64)
            }
            _ => Value::Null,
        }
    }

    fn eval_index(recv: &Value, idx: &Value, _ctx: &MatchContext<'_>) -> Value {
        match recv {
            Value::Str(s) => {
                let i = idx.as_int();
                if i < 0 {
                    return Value::Null;
                }
                Value::Int(i64::from(
                    s.as_bytes().get(i as usize).copied().unwrap_or(0),
                ))
            }
            _ => Value::Null,
        }
    }
}

// ---------------------------------------------------------------------------
// DieSignature – high level wrapper tying a condition to metadata
// ---------------------------------------------------------------------------

/// A compiled DIE signature with pre-parsed condition expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DieSignature {
    /// Display name of the detected tool/compiler/packer.
    pub name: String,
    /// Version string.
    pub version: Option<String>,
    /// Category tag (e.g. "Packer", "Protector", "Compiler").
    pub category: String,
    /// Confidence score 0–100.
    pub confidence: u8,
    /// Original source condition string.
    pub condition_src: String,
    /// Target file format.
    pub target_format: Option<FileFormat>,
}

impl DieSignature {
    /// Create a new signature from a condition source string.
    pub fn new(
        name: impl Into<String>,
        category: impl Into<String>,
        condition_src: impl Into<String>,
        confidence: u8,
    ) -> Self {
        Self {
            name: name.into(),
            version: None,
            category: category.into(),
            confidence,
            condition_src: condition_src.into(),
            target_format: None,
        }
    }

    /// Evaluate this signature against `ctx`.  Returns `true` if the condition
    /// matches.
    pub fn matches(&self, ctx: &MatchContext<'_>) -> bool {
        // Format guard
        if let Some(fmt) = self.target_format {
            if ctx.format != fmt && ctx.format != FileFormat::Unknown {
                return false;
            }
        }
        match Parser::parse_str(&self.condition_src) {
            Ok(expr) => Evaluator::eval(&expr, ctx).truthy(),
            Err(_) => false,
        }
    }
}

impl fmt::Display for DieSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} {:?} ({}%)",
            self.category, self.name, self.version, self.confidence
        )
    }
}

// ---------------------------------------------------------------------------
// DieSignatureEngine – runs all signatures
// ---------------------------------------------------------------------------

/// Detection result from the signature engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigEngineHit {
    /// Matched signature name.
    pub name: String,
    /// Category.
    pub category: String,
    /// Version string.
    pub version: Option<String>,
    /// Confidence.
    pub confidence: u8,
    /// The condition that matched.
    pub condition: String,
}

/// Engine that evaluates a collection of [`DieSignature`]s against file data.
pub struct DieSignatureEngine {
    signatures: Vec<DieSignature>,
    min_confidence: u8,
}

impl DieSignatureEngine {
    /// Create an empty engine.
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
            min_confidence: 0,
        }
    }

    /// Set minimum confidence threshold for reported hits.
    pub fn set_min_confidence(&mut self, min: u8) {
        self.min_confidence = min;
    }

    /// Add a signature.
    pub fn add_signature(&mut self, sig: DieSignature) {
        self.signatures.push(sig);
    }

    /// Load a set of built-in signatures.
    pub fn load_builtins(&mut self) {
        let sigs: &[(&str, &str, &str, u8)] = &[
            ("UPX 3.x", "Packer", "hasSection(\"UPX0\") && hasSection(\"UPX1\")", 95),
            ("UPX 4.x", "Packer", "hasSection(\"UPX0\") && hasSection(\"UPX1\") && contains(\"UPX!\")", 97),
            ("MPRESS", "Packer", "hasSection(\".MPRESS1\")", 90),
            ("ASPack", "Packer", "hasSection(\".aspack\")", 90),
            ("PECompact", "Packer", "contains(\"PECompact2\")", 88),
            ("Themida", "Protector", "hasSection(\".themida\")", 93),
            ("VMProtect 2", "Protector", "hasSection(\".vmp0\")", 92),
            ("VMProtect 3", "Protector", "hasSection(\".vmp1\")", 92),
            ("Enigma", "Protector", "contains(\".enigma1\")", 88),
            ("NSIS", "Installer", "contains(\"Nullsoft\")", 85),
            ("InnoSetup", "Installer", "contains(\"Inno Setup\")", 90),
            ("PyInstaller", "Tool", "contains(\"MEI\")", 90),
            ("AutoIt", "Tool", "contains(\"AU3!EA\")", 93),
            ("GCC/MinGW", "Compiler", "contains(\"MinGW\")", 82),
            ("MSVC", "Compiler", "contains(\"Rich\")", 65),
            ("Delphi", "Compiler", "contains(\"Borland\")", 87),
            ("Rust", "Compiler", "contains(\"rustc\")", 85),
        ];
        for &(name, cat, cond, conf) in sigs {
            self.add_signature(DieSignature::new(name, cat, cond, conf));
        }
    }

    /// Scan `data` against all registered signatures.
    pub fn scan(&self, ctx: &MatchContext<'_>) -> Vec<SigEngineHit> {
        self.signatures
            .iter()
            .filter(|sig| sig.confidence >= self.min_confidence && sig.matches(ctx))
            .map(|sig| SigEngineHit {
                name: sig.name.clone(),
                category: sig.category.clone(),
                version: sig.version.clone(),
                confidence: sig.confidence,
                condition: sig.condition_src.clone(),
            })
            .collect()
    }

    /// Number of loaded signatures.
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

impl Default for DieSignatureEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DieSignatureEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DieSignatureEngine({} sigs, min_conf={})",
            self.signatures.len(),
            self.min_confidence
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lexer_basic() {
        let tokens = Lexer::tokenize("1 + 2 == 3");
        assert!(tokens.contains(&Token::Int(1)));
        assert!(tokens.contains(&Token::Plus));
        assert!(tokens.contains(&Token::Eq));
    }

    #[test]
    fn test_lexer_hex() {
        let tokens = Lexer::tokenize("0x4D5A");
        assert!(tokens.contains(&Token::Int(0x4D5A)));
    }

    #[test]
    fn test_parser_simple_eq() {
        let expr = Parser::parse_str("1 == 1").unwrap();
        let data = b"MZ";
        let ctx = MatchContext::new(data);
        assert!(Evaluator::eval(&expr, &ctx).truthy());
    }

    #[test]
    fn test_parser_and() {
        let expr = Parser::parse_str("true && false").unwrap();
        let ctx = MatchContext::new(b"");
        assert!(!Evaluator::eval(&expr, &ctx).truthy());
    }

    #[test]
    fn test_eval_contains() {
        let expr = Parser::parse_str("contains(\"UPX0\")").unwrap();
        let data = b"UPX0 some data UPX1";
        let ctx = MatchContext::new(data);
        assert!(Evaluator::eval(&expr, &ctx).truthy());
    }

    #[test]
    fn test_engine_builtin_upx() {
        let mut eng = DieSignatureEngine::new();
        eng.load_builtins();
        let data = b"\x4D\x5A UPX0 UPX1 stub data";
        let ctx = MatchContext {
            data,
            format: FileFormat::Pe,
            section_names: vec!["UPX0".to_string(), "UPX1".to_string()],
            section_count: 2,
            section_entropy: vec![7.8, 7.5],
            machine_type: 0x8664,
            subsystem: 3,
            imports: HashMap::new(),
            exports: Vec::new(),
            ep_bytes: Vec::new(),
            overlay_size: 0,
            is_dotnet: false,
        };
        let hits = eng.scan(&ctx);
        assert!(hits.iter().any(|h| h.name.contains("UPX")));
    }
}
