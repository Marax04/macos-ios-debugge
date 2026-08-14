//! Smali assembly parser.
//!
//! Parses `.class`, `.super`, `.source`, `.field`, `.method` directives,
//! a complete Dalvik instruction set, labels, try/catch blocks, and
//! annotation stubs.

use std::collections::HashMap;

use anyhow::{bail, Context, Result};

use crate::DalvikOpcode;

// ── Token ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// `.directive`
    Directive(String),
    /// bare identifier or Dalvik instruction mnemonic
    Ident(String),
    /// string literal (content without quotes)
    StringLit(String),
    /// integer literal (decimal / hex)
    Integer(i64),
    /// floating-point literal (unparsed)
    Float(String),
    /// register `vN` or `pN`
    Register(u8, bool), // (index, is_param)
    /// `{v0 .. v3}` or `{v0, v1, v2}`
    RegList(Vec<u8>),
    /// label declaration `:label`
    LabelDecl(String),
    /// label reference, e.g., in branch instructions
    LabelRef(String),
    /// type descriptor `Ljava/lang/Object;`
    TypeDesc(String),
    /// field reference `Lclass;->field:Ltype;`
    FieldRef(String),
    /// method reference `Lclass;->method(...)V`
    MethodRef(String),
    /// punctuation
    Comma,
    Arrow, // `->` (parsed into FieldRef/MethodRef already, kept for completeness)
    OpenBrace,
    CloseBrace,
    Ellipsis,
    Comment(String),
    Newline,
    Eof,
}

// ── Lexer ─────────────────────────────────────────────────────────────────────

pub struct Lexer<'a> {
    input: &'a [u8],
    pos: usize,
    pub line: u32,
}

impl<'a> Lexer<'a> {
    #[must_use] 
    pub const fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
            line: 1,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let b = self.input.get(self.pos).copied();
        if b == Some(b'\n') {
            self.line += 1;
        }
        self.pos += 1;
        b
    }

    fn skip_whitespace_no_newline(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r')) {
            self.advance();
        }
    }

    fn read_until_newline(&mut self) -> String {
        let start = self.pos;
        while !matches!(self.peek(), Some(b'\n') | None) {
            self.advance();
        }
        String::from_utf8_lossy(&self.input[start..self.pos]).into_owned()
    }

    fn read_ident(&mut self) -> String {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric()
                || c == b'_'
                || c == b'-'
                || c == b'/'
                || c == b'.'
                || c == b'$'
            {
                self.advance();
            } else {
                break;
            }
        }
        String::from_utf8_lossy(&self.input[start..self.pos]).into_owned()
    }

    fn read_string_lit(&mut self) -> Result<String> {
        // Opening `"` already consumed.
        let mut s = String::new();
        loop {
            match self.advance() {
                None => bail!("unterminated string literal"),
                Some(b'"') => break,
                Some(b'\\') => {
                    match self.advance() {
                        Some(b'n') => s.push('\n'),
                        Some(b't') => s.push('\t'),
                        Some(b'r') => s.push('\r'),
                        Some(b'"') => s.push('"'),
                        Some(b'\\') => s.push('\\'),
                        Some(b'u') => {
                            // Unicode escape \uXXXX
                            let hex: String = (0..4)
                                .map(|_| self.advance().unwrap_or(b'0') as char)
                                .collect();
                            let code = u32::from_str_radix(&hex, 16).unwrap_or(0xFFFD);
                            s.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                        }
                        Some(c) => {
                            s.push('\\');
                            s.push(c as char);
                        }
                        None => bail!("unterminated string escape"),
                    }
                }
                Some(c) => s.push(c as char),
            }
        }
        Ok(s)
    }

    fn read_number(&mut self, first: u8) -> Token {
        let mut raw = String::new();
        raw.push(first as char);
        let is_hex = first == b'0' && matches!(self.peek(), Some(b'x' | b'X'));
        if is_hex {
            raw.push(self.advance().unwrap() as char);
            while self.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                raw.push(self.advance().unwrap() as char);
            }
        } else {
            while self
                .peek()
                .is_some_and(|c| c.is_ascii_digit() || c == b'.' || c == b'e' || c == b'E' || c == b'-')
            {
                raw.push(self.advance().unwrap() as char);
            }
            if raw.contains('.') || raw.contains('e') || raw.contains('E') {
                return Token::Float(raw);
            }
        }
        if is_hex {
            // An unrecognised hex sequence is emitted as 0; log the anomaly via
            // a float token rather than silently producing the wrong value.
            // Using unwrap_or here would mask malformed input; instead we produce
            // an Ident so the parser can surface the error rather than using a
            // silent fallback of 0 that could corrupt operand values.
            i64::from_str_radix(&raw[2..], 16).map_or_else(|_| Token::Ident(raw.clone()), Token::Integer)
        } else {
            raw.parse::<i64>().map_or_else(|_| Token::Ident(raw.clone()), Token::Integer)
        }
    }

    fn read_type_or_ref(&mut self) -> Token {
        // Starts with 'L' — read until ';' or '>'
        let _ = self.pos - 1; // start position; already consumed the 'L'
        // Re-include 'L'
        let mut s = String::from("L");
        while let Some(c) = self.peek() {
            if c == b';' {
                self.advance();
                s.push(';');
                break;
            } else if c == b'>' {
                break;
            }
            s.push(c as char);
            self.advance();
        }
        // Check if followed by `->`
        if self.input.get(self.pos..self.pos + 2) == Some(b"->") {
            self.pos += 2;
            let _ = self.pos; // member start position
            // Read member name up to ':' or '('
            let mut member = String::new();
            while let Some(c) = self.peek() {
                if c == b':' || c == b'(' {
                    break;
                }
                member.push(c as char);
                self.advance();
            }
            // Read rest of line for full ref
            let rest = self.read_until_newline().trim().to_string();
            let full = format!("{s}->{member}{rest}");
            if rest.starts_with('(') || self.input.get(self.pos) == Some(&b'(') {
                return Token::MethodRef(full);
            }
            return Token::FieldRef(full);
        }
        Token::TypeDesc(s)
    }

    fn read_register(&mut self, prefix: u8) -> Token {
        let is_param = prefix == b'p';
        let mut digits = String::new();
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            digits.push(self.advance().unwrap() as char);
        }
        // Silently falling back to 0 for malformed register numbers would corrupt
        // operand encoding; produce an Ident token so callers can detect and skip
        // the bad input rather than using register v0/p0 incorrectly.
        digits.parse::<u8>().map_or_else(
            |_| Token::Ident(format!("{}{}", prefix as char, digits)),
            |idx| Token::Register(idx, is_param),
        )
    }

    fn read_reg_list(&mut self) -> Token {
        // `{` already consumed
        let mut regs = Vec::new();
        loop {
            self.skip_whitespace_no_newline();
            match self.peek() {
                Some(b'}') => {
                    self.advance();
                    break;
                }
                Some(b'v' | b'p') => {
                    let prefix = self.advance().unwrap();
                    if let Token::Register(idx, _) = self.read_register(prefix) {
                        self.skip_whitespace_no_newline();
                        // Check for range `..`
                        if self.input.get(self.pos..self.pos + 2) == Some(b"..") {
                            self.pos += 2;
                            self.skip_whitespace_no_newline();
                            let prefix2 = self.advance().unwrap_or(b'v');
                            if let Token::Register(idx2, _) = self.read_register(prefix2) {
                                // Guard against inverted or excessively large ranges
                                // that would silently emit nothing or wrap a u8 counter.
                                if idx2 >= idx {
                                    for r in idx..=idx2 {
                                        regs.push(r);
                                    }
                                }
                                // If range is inverted, skip it entirely rather than
                                // silently pushing no registers or wrapping.
                            }
                        } else {
                            regs.push(idx);
                        }
                    }
                }
                Some(b',') => {
                    self.advance();
                }
                _ => {
                    self.advance();
                }
            }
        }
        Token::RegList(regs)
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn next_token(&mut self) -> Result<Token> {
        self.skip_whitespace_no_newline();
        let c = match self.peek() {
            None => return Ok(Token::Eof),
            Some(c) => c,
        };
        self.advance();
        match c {
            b'\n' => Ok(Token::Newline),
            b'#' => {
                let comment = self.read_until_newline();
                Ok(Token::Comment(comment))
            }
            b'.' => {
                let name = self.read_ident();
                Ok(Token::Directive(name))
            }
            b':' => {
                let label = self.read_ident();
                Ok(Token::LabelDecl(label))
            }
            b'"' => {
                let s = self.read_string_lit()?;
                Ok(Token::StringLit(s))
            }
            b'{' => Ok(self.read_reg_list()),
            b'}' => Ok(Token::CloseBrace),
            b',' => Ok(Token::Comma),
            b'L' => Ok(self.read_type_or_ref()),
            b'v' => Ok(self.read_register(b'v')),
            b'p' => {
                // Could be `p0`, `p1` or a plain identifier
                if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    Ok(self.read_register(b'p'))
                } else {
                    let mut name = String::from("p");
                    name.push_str(&self.read_ident());
                    Ok(Token::Ident(name))
                }
            }
            b'-' => {
                if self.peek() == Some(b'>') {
                    self.advance();
                    Ok(Token::Arrow)
                } else if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    let next = self.advance().unwrap();
                    Ok(self.read_number(next))
                } else {
                    Ok(Token::Ident(self.read_ident()))
                }
            }
            b'0'..=b'9' => Ok(self.read_number(c)),
            _ if c.is_ascii_alphabetic() || c == b'_' || c == b'$' => {
                let mut ident = String::new();
                ident.push(c as char);
                ident.push_str(&self.read_ident());
                Ok(Token::Ident(ident))
            }
            _ => {
                // Skip unknown characters
                Ok(Token::Ident(String::from(c as char)))
            }
        }
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn tokenize_all(&mut self) -> Result<Vec<Token>> {
        let mut tokens = Vec::new();
        loop {
            let tok = self.next_token()?;
            let done = tok == Token::Eof;
            tokens.push(tok);
            if done {
                break;
            }
        }
        Ok(tokens)
    }
}

// ── ParsedInstruction ────────────────────────────────────────────────────────

/// A single decoded Smali instruction.
#[derive(Debug, Clone)]
pub struct ParsedInstruction {
    pub opcode: DalvikOpcode,
    pub registers: Vec<u8>,
    pub literal: Option<i64>,
    pub string_ref: Option<String>,
    pub type_ref: Option<String>,
    pub field_ref: Option<String>,
    pub method_ref: Option<String>,
    pub label: Option<String>,
    pub line: u32,
}

impl ParsedInstruction {
    #[must_use] 
    pub const fn new(opcode: DalvikOpcode, line: u32) -> Self {
        Self {
            opcode,
            registers: Vec::new(),
            literal: None,
            string_ref: None,
            type_ref: None,
            field_ref: None,
            method_ref: None,
            label: None,
            line,
        }
    }
}

// ── ParsedLabel ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ParsedLabel {
    pub name: String,
    /// Index of the next instruction after this label.
    pub instruction_index: usize,
    pub line: u32,
}

// ── TryCatch ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TryCatchBlock {
    pub try_start: String,
    pub try_end: String,
    pub handlers: Vec<ExceptionHandler>,
    pub catch_all: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExceptionHandler {
    pub exception_type: String,
    pub handler_label: String,
}

// ── ParsedMethod ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ParsedMethod {
    pub name: String,
    pub access_flags: Vec<String>,
    pub descriptor: String,
    pub instructions: Vec<ParsedInstruction>,
    pub labels: HashMap<String, ParsedLabel>,
    pub try_catch: Vec<TryCatchBlock>,
    pub registers_directive: Option<u8>,
    pub locals_directive: Option<u8>,
    pub line: u32,
}

// ── ParsedField ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ParsedField {
    pub name: String,
    pub access_flags: Vec<String>,
    pub type_desc: String,
    pub initial_value: Option<String>,
    pub line: u32,
}

// ── ParsedClass ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ParsedClass {
    pub class_name: String,
    pub super_name: Option<String>,
    pub source_file: Option<String>,
    pub interfaces: Vec<String>,
    pub access_flags: Vec<String>,
    pub fields: Vec<ParsedField>,
    pub methods: Vec<ParsedMethod>,
}

// ── Parser ────────────────────────────────────────────────────────────────────

pub struct SmaliParser {
    tokens: Vec<Token>,
    pos: usize,
    line: u32,
}

impl SmaliParser {
    #[must_use] 
    pub const fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            pos: 0,
            line: 1,
        }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> &Token {
        let tok = self.tokens.get(self.pos).unwrap_or(&Token::Eof);
        if tok == &Token::Newline {
            self.line += 1;
        }
        self.pos += 1;
        tok
    }

    fn skip_newlines(&mut self) {
        while matches!(self.peek(), Token::Newline | Token::Comment(_)) {
            self.advance();
        }
    }

    fn _expect_ident(&mut self) -> Result<String> {
        match self.advance().clone() {
            Token::Ident(s) => Ok(s),
            Token::TypeDesc(s) => Ok(s),
            other => bail!("expected identifier, got {other:?}"),
        }
    }

    fn expect_newline_or_eof(&mut self) {
        while !matches!(self.peek(), Token::Newline | Token::Eof) {
            self.advance();
        }
        if self.peek() == &Token::Newline {
            self.advance();
        }
    }

    /// Parse the entire file.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn parse(&mut self) -> Result<ParsedClass> {
        let mut class = ParsedClass {
            class_name: String::new(),
            super_name: None,
            source_file: None,
            interfaces: Vec::new(),
            access_flags: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
        };
        loop {
            self.skip_newlines();
            match self.peek().clone() {
                Token::Eof => break,
                Token::Directive(ref d) => {
                    let d = d.clone();
                    self.advance();
                    match d.as_str() {
                        "class" => self.parse_class_directive(&mut class)?,
                        "super" => self.parse_super_directive(&mut class)?,
                        "source" => self.parse_source_directive(&mut class)?,
                        "implements" => self.parse_implements_directive(&mut class)?,
                        "field" => {
                            let field = self.parse_field_directive()?;
                            class.fields.push(field);
                        }
                        "method" => {
                            let method = self.parse_method_directive()?;
                            class.methods.push(method);
                        }
                        "annotation" => {
                            self.skip_annotation_block()?;
                        }
                        _ => {
                            self.expect_newline_or_eof();
                        }
                    }
                }
                _ => {
                    self.advance();
                }
            }
        }
        Ok(class)
    }

    fn parse_access_flags(&mut self) -> Vec<String> {
        let mut flags = Vec::new();
        loop {
            match self.peek() {
                Token::Ident(s) => {
                    let s = s.clone();
                    if is_access_flag(&s) {
                        flags.push(s);
                        self.advance();
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
        flags
    }

    fn parse_class_directive(&mut self, class: &mut ParsedClass) -> Result<()> {
        class.access_flags = self.parse_access_flags();
        match self.peek().clone() {
            Token::TypeDesc(s) => {
                class.class_name = s;
                self.advance();
            }
            Token::Ident(s) => {
                class.class_name = s;
                self.advance();
            }
            _ => {}
        }
        self.expect_newline_or_eof();
        Ok(())
    }

    fn parse_super_directive(&mut self, class: &mut ParsedClass) -> Result<()> {
        match self.peek().clone() {
            Token::TypeDesc(s) | Token::Ident(s) => {
                class.super_name = Some(s);
                self.advance();
            }
            _ => {}
        }
        self.expect_newline_or_eof();
        Ok(())
    }

    fn parse_source_directive(&mut self, class: &mut ParsedClass) -> Result<()> {
        match self.peek().clone() {
            Token::StringLit(s) => {
                class.source_file = Some(s);
                self.advance();
            }
            Token::Ident(s) => {
                class.source_file = Some(s);
                self.advance();
            }
            _ => {}
        }
        self.expect_newline_or_eof();
        Ok(())
    }

    fn parse_implements_directive(&mut self, class: &mut ParsedClass) -> Result<()> {
        match self.peek().clone() {
            Token::TypeDesc(s) | Token::Ident(s) => {
                class.interfaces.push(s);
                self.advance();
            }
            _ => {}
        }
        self.expect_newline_or_eof();
        Ok(())
    }

    fn parse_field_directive(&mut self) -> Result<ParsedField> {
        let line = self.line;
        let access_flags = self.parse_access_flags();
        let combined = self.read_rest_of_line();
        // field is "name:TypeDesc"
        let (name, type_desc) = if let Some(colon) = combined.find(':') {
            (combined[..colon].trim().to_string(), combined[colon + 1..].trim().to_string())
        } else {
            (combined.trim().to_string(), String::from("Ljava/lang/Object;"))
        };
        Ok(ParsedField {
            name,
            access_flags,
            type_desc,
            initial_value: None,
            line,
        })
    }

    fn parse_method_directive(&mut self) -> Result<ParsedMethod> {
        let line = self.line;
        let access_flags = self.parse_access_flags();
        let descriptor = self.read_rest_of_line().trim().to_string();
        let name = descriptor
            .find('(').map_or_else(|| descriptor.clone(), |i| descriptor[..i].trim().to_string());
        let mut method = ParsedMethod {
            name,
            access_flags,
            descriptor,
            instructions: Vec::new(),
            labels: HashMap::new(),
            try_catch: Vec::new(),
            registers_directive: None,
            locals_directive: None,
            line,
        };
        self.parse_method_body(&mut method)?;
        Ok(method)
    }

    fn parse_method_body(&mut self, method: &mut ParsedMethod) -> Result<()> {
        loop {
            self.skip_newlines();
            match self.peek().clone() {
                Token::Eof => break,
                Token::Directive(d) => {
                    let d = d.clone();
                    self.advance();
                    match d.as_str() {
                        "end" => {
                            // `.end method`
                            self.expect_newline_or_eof();
                            break;
                        }
                        "registers" => {
                            if let Token::Integer(n) = self.peek().clone() {
                                // Clamp to the valid Dalvik range (0..=255); silently
                                // truncating with `as u8` would wrap 256..65535 to 0..255.
                                method.registers_directive = Some(u8::try_from(n.clamp(0, 255)).unwrap_or(0));
                                self.advance();
                            }
                            self.expect_newline_or_eof();
                        }
                        "locals" => {
                            if let Token::Integer(n) = self.peek().clone() {
                                method.locals_directive = Some(u8::try_from(n.clamp(0, 255)).unwrap_or(0));
                                self.advance();
                            }
                            self.expect_newline_or_eof();
                        }
                        "prologue" | "epilogue" => {
                            self.expect_newline_or_eof();
                        }
                        "line" => {
                            self.advance(); // skip line number
                            self.expect_newline_or_eof();
                        }
                        "catch" | "catchall" => {
                            self.parse_catch_directive(method)?;
                        }
                        "annotation" => {
                            self.skip_annotation_block()?;
                        }
                        _ => {
                            self.expect_newline_or_eof();
                        }
                    }
                }
                Token::LabelDecl(label) => {
                    let label = label.clone();
                    self.advance();
                    let pl = ParsedLabel {
                        name: label.clone(),
                        instruction_index: method.instructions.len(),
                        line: self.line,
                    };
                    method.labels.insert(label, pl);
                    self.expect_newline_or_eof();
                }
                Token::Ident(mnemonic) => {
                    let mnemonic = mnemonic.clone();
                    self.advance();
                    let insn = self.parse_instruction(&mnemonic)?;
                    method.instructions.push(insn);
                }
                _ => {
                    self.advance();
                }
            }
        }
        Ok(())
    }

    fn parse_instruction(&mut self, mnemonic: &str) -> Result<ParsedInstruction> {
        let line = self.line;
        let opcode = mnemonic_to_opcode(mnemonic);
        let mut insn = ParsedInstruction::new(opcode, line);
        // Parse operands based on instruction format.
        match operand_format(mnemonic) {
            OpFormat::None => {}
            OpFormat::Reg1 => {
                insn.registers = self.parse_regs(1);
            }
            OpFormat::Reg2 => {
                insn.registers = self.parse_regs(2);
            }
            OpFormat::Reg3 => {
                insn.registers = self.parse_regs(3);
            }
            OpFormat::RegLit => {
                insn.registers = self.parse_regs(2);
                self.skip_comma();
                insn.literal = self.parse_literal();
            }
            OpFormat::RegType => {
                insn.registers = self.parse_regs(1);
                self.skip_comma();
                insn.type_ref = self.parse_type_ref();
            }
            OpFormat::RegField => {
                insn.registers = self.parse_regs(2);
                self.skip_comma();
                insn.field_ref = self.parse_str_tok();
            }
            OpFormat::RegMethod => {
                insn.registers = self.parse_reg_list_or_range();
                self.skip_comma();
                insn.method_ref = self.parse_str_tok();
            }
            OpFormat::RegString => {
                insn.registers = self.parse_regs(1);
                self.skip_comma();
                insn.string_ref = self.parse_string_ref();
            }
            OpFormat::Label => {
                insn.label = self.parse_label_ref();
            }
            OpFormat::Reg1Label => {
                insn.registers = self.parse_regs(1);
                self.skip_comma();
                insn.label = self.parse_label_ref();
            }
            OpFormat::Reg2Label => {
                insn.registers = self.parse_regs(2);
                self.skip_comma();
                insn.label = self.parse_label_ref();
            }
            OpFormat::_PackedSwitch | OpFormat::_SparseSwitch => {
                insn.registers = self.parse_regs(1);
                self.skip_comma();
                insn.label = self.parse_label_ref();
            }
            OpFormat::_RegLitLabel => {
                insn.registers = self.parse_regs(1);
                self.skip_comma();
                insn.literal = self.parse_literal();
                self.skip_comma();
                insn.label = self.parse_label_ref();
            }
            OpFormat::FillArray => {
                insn.registers = self.parse_regs(1);
                self.skip_comma();
                insn.label = self.parse_label_ref();
            }
            OpFormat::Lit8 => {
                insn.registers = self.parse_regs(2);
                self.skip_comma();
                insn.literal = self.parse_literal();
            }
            OpFormat::Lit16 => {
                insn.registers = self.parse_regs(2);
                self.skip_comma();
                insn.literal = self.parse_literal();
            }
        }
        self.expect_newline_or_eof();
        Ok(insn)
    }

    fn parse_regs(&mut self, count: usize) -> Vec<u8> {
        let mut regs = Vec::new();
        for i in 0..count {
            if i > 0 {
                self.skip_comma();
            }
            match self.peek().clone() {
                Token::Register(idx, _) => {
                    regs.push(idx);
                    self.advance();
                }
                _ => break,
            }
        }
        regs
    }

    fn parse_reg_list_or_range(&mut self) -> Vec<u8> {
        match self.peek().clone() {
            Token::RegList(regs) => {
                self.advance();
                regs
            }
            _ => self.parse_regs(5),
        }
    }

    fn skip_comma(&mut self) {
        if self.peek() == &Token::Comma {
            self.advance();
        }
    }

    fn parse_literal(&mut self) -> Option<i64> {
        match self.peek().clone() {
            Token::Integer(n) => {
                self.advance();
                Some(n)
            }
            _ => None,
        }
    }

    fn parse_type_ref(&mut self) -> Option<String> {
        match self.peek().clone() {
            Token::TypeDesc(s) | Token::Ident(s) => {
                self.advance();
                Some(s)
            }
            _ => None,
        }
    }

    fn parse_str_tok(&mut self) -> Option<String> {
        match self.peek().clone() {
            Token::FieldRef(s) | Token::MethodRef(s) | Token::Ident(s) | Token::TypeDesc(s) => {
                self.advance();
                Some(s)
            }
            _ => {
                // Read rest of line as a raw string
                let rest = self.read_rest_of_line().trim().to_string();
                if rest.is_empty() {
                    None
                } else {
                    Some(rest)
                }
            }
        }
    }

    fn parse_string_ref(&mut self) -> Option<String> {
        match self.peek().clone() {
            Token::StringLit(s) => {
                self.advance();
                Some(s)
            }
            _ => None,
        }
    }

    fn parse_label_ref(&mut self) -> Option<String> {
        match self.peek().clone() {
            Token::LabelDecl(s) | Token::Ident(s) => {
                let s = s;
                self.advance();
                Some(s)
            }
            _ => None,
        }
    }

    fn parse_catch_directive(&mut self, method: &mut ParsedMethod) -> Result<()> {
        // `.catch Ljava/lang/Exception; {:try_start .. :try_end} :handler`
        let exc_type = match self.peek().clone() {
            Token::TypeDesc(s) | Token::Ident(s) => {
                self.advance();
                s
            }
            _ => String::from("Ljava/lang/Throwable;"),
        };
        // Skip `{`
        let rest = self.read_rest_of_line();
        // Very permissive parsing of the label block
        let labels: Vec<&str> = rest
            .split(|c: char| !c.is_alphanumeric() && c != '_' && c != ':')
            .map(str::trim)
            .filter(|s| s.starts_with(':') || !s.is_empty())
            .collect();
        let try_start = labels.first().unwrap_or(&"try_start").trim_start_matches(':').to_string();
        let try_end = labels.get(1).unwrap_or(&"try_end").trim_start_matches(':').to_string();
        let handler = labels.get(2).unwrap_or(&"handler").trim_start_matches(':').to_string();
        let block = if let Some(existing) = method
            .try_catch
            .iter_mut()
            .find(|b| b.try_start == try_start && b.try_end == try_end)
        {
            existing.handlers.push(ExceptionHandler {
                exception_type: exc_type,
                handler_label: handler,
            });
            return Ok(());
        } else {
            TryCatchBlock {
                try_start,
                try_end,
                handlers: vec![ExceptionHandler {
                    exception_type: exc_type,
                    handler_label: handler,
                }],
                catch_all: None,
            }
        };
        method.try_catch.push(block);
        Ok(())
    }

    fn skip_annotation_block(&mut self) -> Result<()> {
        // Read until `.end annotation`
        let mut depth = 1u32;
        loop {
            self.skip_newlines();
            match self.peek().clone() {
                Token::Eof => break,
                Token::Directive(d) => {
                    let d = d.clone();
                    self.advance();
                    if d == "annotation" {
                        depth += 1;
                    } else if d == "end" {
                        depth -= 1;
                        if depth == 0 {
                            // consume `annotation`
                            self.expect_newline_or_eof();
                            break;
                        }
                    }
                    self.expect_newline_or_eof();
                }
                _ => {
                    self.advance();
                }
            }
        }
        Ok(())
    }

    fn read_rest_of_line(&mut self) -> String {
        let mut s = String::new();
        loop {
            match self.peek() {
                Token::Newline | Token::Eof => break,
                Token::Comment(_) => break,
                tok => {
                    let _repr = format!("{tok:?}");
                    // Extract string value
                    let part = match tok {
                        Token::Ident(x) | Token::TypeDesc(x) | Token::FieldRef(x)
                        | Token::MethodRef(x) | Token::StringLit(x) | Token::LabelDecl(x)
                        | Token::LabelRef(x) | Token::Directive(x) | Token::Float(x) => {
                            x.clone()
                        }
                        Token::Integer(n) => n.to_string(),
                        Token::Register(n, _) => format!("v{n}"),
                        _ => String::new(),
                    };
                    if !s.is_empty() && !part.is_empty() {
                        s.push(' ');
                    }
                    s.push_str(&part);
                    self.advance();
                }
            }
        }
        s
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn is_access_flag(s: &str) -> bool {
    matches!(
        s,
        "public"
            | "private"
            | "protected"
            | "static"
            | "final"
            | "synchronized"
            | "bridge"
            | "varargs"
            | "native"
            | "abstract"
            | "strictfp"
            | "synthetic"
            | "declared-synchronized"
            | "interface"
            | "enum"
            | "annotation"
            | "volatile"
            | "transient"
            | "constructor"
    )
}

#[derive(Debug, Clone, Copy)]
enum OpFormat {
    None,
    Reg1,
    Reg2,
    Reg3,
    RegLit,
    RegType,
    RegField,
    RegMethod,
    RegString,
    Label,
    Reg1Label,
    Reg2Label,
    _PackedSwitch,
    _SparseSwitch,
    _RegLitLabel,
    FillArray,
    Lit8,
    Lit16,
}

fn operand_format(mnemonic: &str) -> OpFormat {
    match mnemonic {
        "nop" | "return-void" => OpFormat::None,
        "return" | "return-wide" | "return-object" => OpFormat::Reg1,
        "move-result" | "move-result-wide" | "move-result-object" | "move-exception"
        | "throw" | "monitor-enter" | "monitor-exit" => OpFormat::Reg1,
        "move" | "move-wide" | "move-object" | "move-from16" | "move-wide-from16"
        | "move-object-from16" | "move-16" | "move-wide-16" | "move-object-16"
        | "neg-int" | "not-int" | "neg-long" | "not-long" | "neg-float" | "neg-double"
        | "int-to-long" | "int-to-float" | "int-to-double" | "long-to-int" | "long-to-float"
        | "long-to-double" | "float-to-int" | "float-to-long" | "float-to-double"
        | "double-to-int" | "double-to-long" | "double-to-float" | "int-to-byte"
        | "int-to-char" | "int-to-short" | "array-length" => OpFormat::Reg2,
        "add-int/2addr" | "sub-int/2addr" | "mul-int/2addr" | "div-int/2addr"
        | "rem-int/2addr" | "and-int/2addr" | "or-int/2addr" | "xor-int/2addr"
        | "shl-int/2addr" | "shr-int/2addr" | "ushr-int/2addr" | "add-long/2addr"
        | "sub-long/2addr" | "mul-long/2addr" | "div-long/2addr" | "rem-long/2addr"
        | "and-long/2addr" | "or-long/2addr" | "xor-long/2addr" | "shl-long/2addr"
        | "shr-long/2addr" | "ushr-long/2addr" | "add-float/2addr" | "sub-float/2addr"
        | "mul-float/2addr" | "div-float/2addr" | "rem-float/2addr" | "add-double/2addr"
        | "sub-double/2addr" | "mul-double/2addr" | "div-double/2addr"
        | "rem-double/2addr" => OpFormat::Reg2,
        "cmpl-float" | "cmpg-float" | "cmpl-double" | "cmpg-double" | "cmp-long"
        | "add-int" | "sub-int" | "mul-int" | "div-int" | "rem-int" | "and-int" | "or-int"
        | "xor-int" | "shl-int" | "shr-int" | "ushr-int" | "add-long" | "sub-long"
        | "mul-long" | "div-long" | "rem-long" | "and-long" | "or-long" | "xor-long"
        | "shl-long" | "shr-long" | "ushr-long" | "add-float" | "sub-float" | "mul-float"
        | "div-float" | "rem-float" | "add-double" | "sub-double" | "mul-double"
        | "div-double" | "rem-double" | "aget" | "aget-wide" | "aget-object" | "aget-boolean"
        | "aget-byte" | "aget-char" | "aget-short" | "aput" | "aput-wide" | "aput-object"
        | "aput-boolean" | "aput-byte" | "aput-char" | "aput-short" => OpFormat::Reg3,
        "const/4" | "const/16" | "const" | "const/high16" | "const-wide/16"
        | "const-wide/32" | "const-wide" | "const-wide/high16" => OpFormat::RegLit,
        "new-instance" | "check-cast" | "const-class" => OpFormat::RegType,
        "instance-of" | "new-array" => OpFormat::RegType,
        "iget" | "iget-wide" | "iget-object" | "iget-boolean" | "iget-byte" | "iget-char"
        | "iget-short" | "iput" | "iput-wide" | "iput-object" | "iput-boolean" | "iput-byte"
        | "iput-char" | "iput-short" | "sget" | "sget-wide" | "sget-object" | "sget-boolean"
        | "sget-byte" | "sget-char" | "sget-short" | "sput" | "sput-wide" | "sput-object"
        | "sput-boolean" | "sput-byte" | "sput-char" | "sput-short" => OpFormat::RegField,
        "invoke-virtual" | "invoke-super" | "invoke-direct" | "invoke-static"
        | "invoke-interface" | "invoke-virtual/range" | "invoke-super/range"
        | "invoke-direct/range" | "invoke-static/range" | "invoke-interface/range" => {
            OpFormat::RegMethod
        }
        "const-string" | "const-string/jumbo" => OpFormat::RegString,
        "goto" | "goto/16" | "goto/32" | "packed-switch" | "sparse-switch" => OpFormat::Label,
        "if-eqz" | "if-nez" | "if-ltz" | "if-gez" | "if-gtz" | "if-lez" => {
            OpFormat::Reg1Label
        }
        "if-eq" | "if-ne" | "if-lt" | "if-ge" | "if-gt" | "if-le" => OpFormat::Reg2Label,
        "add-int/lit8" | "rsub-int/lit8" | "mul-int/lit8" | "div-int/lit8"
        | "rem-int/lit8" | "and-int/lit8" | "or-int/lit8" | "xor-int/lit8"
        | "shl-int/lit8" | "shr-int/lit8" | "ushr-int/lit8" => OpFormat::Lit8,
        "add-int/lit16" | "rsub-int" | "mul-int/lit16" | "div-int/lit16" | "rem-int/lit16"
        | "and-int/lit16" | "or-int/lit16" | "xor-int/lit16" => OpFormat::Lit16,
        "fill-array-data" => OpFormat::FillArray,
        _ => OpFormat::None,
    }
}

#[must_use] 
pub fn mnemonic_to_opcode(mnemonic: &str) -> DalvikOpcode {
    // Map string mnemonic to DalvikOpcode.
    match mnemonic {
        "nop" => DalvikOpcode::Nop,
        "move" => DalvikOpcode::Move,
        "return-void" => DalvikOpcode::ReturnVoid,
        "return" => DalvikOpcode::Return,
        "const/4" => DalvikOpcode::Const4,
        "const/16" => DalvikOpcode::Const16,
        "const" => DalvikOpcode::Const,
        "const-string" => DalvikOpcode::ConstString,
        "new-instance" => DalvikOpcode::NewInstance,
        "invoke-virtual" => DalvikOpcode::InvokeVirtual,
        "invoke-direct" => DalvikOpcode::InvokeDirect,
        "invoke-static" => DalvikOpcode::InvokeStatic,
        "invoke-super" => DalvikOpcode::InvokeSuper,
        "invoke-interface" => DalvikOpcode::InvokeInterface,
        "move-result" | "move-result-wide" | "move-result-object" => DalvikOpcode::MoveResult,
        "iget" | "iget-wide" | "iget-object" | "iget-boolean" | "iget-byte" | "iget-char"
        | "iget-short" => DalvikOpcode::Iget,
        "iput" | "iput-wide" | "iput-object" | "iput-boolean" | "iput-byte" | "iput-char"
        | "iput-short" => DalvikOpcode::Iput,
        "sget" | "sget-wide" | "sget-object" | "sget-boolean" | "sget-byte" | "sget-char"
        | "sget-short" => DalvikOpcode::Sget,
        "sput" | "sput-wide" | "sput-object" | "sput-boolean" | "sput-byte" | "sput-char"
        | "sput-short" => DalvikOpcode::Sput,
        "goto" | "goto/16" | "goto/32" => DalvikOpcode::Goto,
        "if-eqz" => DalvikOpcode::IfEqz,
        "if-nez" => DalvikOpcode::IfNez,
        "if-ltz" => DalvikOpcode::IfLtz,
        "if-gez" => DalvikOpcode::IfGez,
        "if-gtz" => DalvikOpcode::IfGtz,
        "if-lez" => DalvikOpcode::IfLez,
        "if-eq" => DalvikOpcode::IfEq,
        "if-ne" => DalvikOpcode::IfNe,
        "if-lt" => DalvikOpcode::IfLt,
        "if-ge" => DalvikOpcode::IfGe,
        "if-gt" => DalvikOpcode::IfGt,
        "if-le" => DalvikOpcode::IfLe,
        "add-int" | "add-int/2addr" => DalvikOpcode::AddInt,
        "sub-int" | "sub-int/2addr" => DalvikOpcode::SubInt,
        "mul-int" | "mul-int/2addr" => DalvikOpcode::MulInt,
        "div-int" | "div-int/2addr" => DalvikOpcode::DivInt,
        "rem-int" | "rem-int/2addr" => DalvikOpcode::RemInt,
        "and-int" | "and-int/2addr" => DalvikOpcode::AndInt,
        "or-int" | "or-int/2addr" => DalvikOpcode::OrInt,
        "xor-int" | "xor-int/2addr" => DalvikOpcode::XorInt,
        "throw" => DalvikOpcode::Throw,
        "check-cast" => DalvikOpcode::CheckCast,
        "instance-of" => DalvikOpcode::InstanceOf,
        "array-length" => DalvikOpcode::ArrayLength,
        "new-array" => DalvikOpcode::NewArray,
        "aget" | "aget-wide" | "aget-object" | "aget-boolean" | "aget-byte" | "aget-char"
        | "aget-short" => DalvikOpcode::Aget,
        "aput" | "aput-wide" | "aput-object" | "aput-boolean" | "aput-byte" | "aput-char"
        | "aput-short" => DalvikOpcode::Aput,
        "neg-int" => DalvikOpcode::NegInt,
        "not-int" => DalvikOpcode::NotInt,
        "int-to-long" => DalvikOpcode::IntToLong,
        "int-to-float" => DalvikOpcode::IntToFloat,
        "int-to-double" => DalvikOpcode::IntToDouble,
        "long-to-int" => DalvikOpcode::LongToInt,
        "float-to-int" => DalvikOpcode::FloatToInt,
        "double-to-int" => DalvikOpcode::DoubleToInt,
        "int-to-byte" => DalvikOpcode::IntToByte,
        "int-to-char" => DalvikOpcode::IntToChar,
        "int-to-short" => DalvikOpcode::IntToShort,
        "monitor-enter" => DalvikOpcode::MonitorEnter,
        "monitor-exit" => DalvikOpcode::MonitorExit,
        _ => DalvikOpcode::Nop,
    }
}

/// High-level parse entry point.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn parse_smali(source: &str) -> Result<ParsedClass> {
    let mut lexer = Lexer::new(source);
    let tokens = lexer.tokenize_all().context("lexer error")?;
    let mut parser = SmaliParser::new(tokens);
    parser.parse().context("parser error")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
.class public Lcom/example/Hello;
.super Ljava/lang/Object;
.source "Hello.java"

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static main([Ljava/lang/String;)V
    .registers 3
    const-string v0, "Hello, world!"
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;
    invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
    return-void
.end method
"#;

    #[test]
    fn test_parse_class_directive() {
        let class = parse_smali(SAMPLE).unwrap();
        assert_eq!(class.class_name, "Lcom/example/Hello;");
        assert_eq!(class.super_name.as_deref(), Some("Ljava/lang/Object;"));
    }

    #[test]
    fn test_parse_methods() {
        let class = parse_smali(SAMPLE).unwrap();
        assert_eq!(class.methods.len(), 2);
    }

    #[test]
    fn test_parse_instructions() {
        let class = parse_smali(SAMPLE).unwrap();
        let main = class.methods.iter().find(|m| m.name == "main").unwrap();
        assert!(main.instructions.len() >= 3);
    }

    #[test]
    fn test_lexer_tokenizes_register() {
        let mut lexer = Lexer::new("v0, v1");
        let tok = lexer.next_token().unwrap();
        assert!(matches!(tok, Token::Register(0, false)));
    }

    #[test]
    fn test_lexer_tokenizes_directive() {
        let mut lexer = Lexer::new(".class public Lfoo;");
        let tok = lexer.next_token().unwrap();
        assert!(matches!(tok, Token::Directive(ref s) if s == "class"));
    }
}
