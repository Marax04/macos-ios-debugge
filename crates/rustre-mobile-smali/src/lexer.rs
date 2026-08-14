//! `lexer` — Tokenizer for the Smali assembly language.
//!
//! Smali is the human-readable format for Dalvik bytecode used by the JADX /
//! smali / baksmali toolchain.  This module converts a raw Smali source file
//! (or a single method body) into a flat list of `Token`s.
//!
//! # Token categories
//!
//! | Category | Examples |
//! |----------|---------|
//! | Directive | `.class`, `.method`, `.field`, `.end method` |
//! | Keyword | `public`, `static`, `final`, `synchronized` |
//! | Opcode | `invoke-virtual`, `iget-object`, `const/4`, … |
//! | Register | `v0`–`v255`, `p0`–`p255` |
//! | Label | `:cond_0`, `:goto_1`, `:try_start_0` |
//! | TypeDesc | `Ljava/lang/String;`, `[I`, `[[B` |
//! | FieldRef | `Lcom/Foo;->bar:I` |
//! | MethodRef | `Lcom/Foo;->bar()V` |
//! | IntLiteral | `0x1F`, `-42`, `42L` |
//! | FloatLiteral | `3.14f`, `-0.5` |
//! | StringLiteral | `"hello\n"` |
//! | Comment | `# ...` |
//! | Newline | implicit line terminator |

use super::SmaliError;

// ─────────────────────────────────────────────────────────────────────────────
// Token types
// ─────────────────────────────────────────────────────────────────────────────

/// A single lexical token produced by the Smali lexer.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Token {
    // ── Structural ────────────────────────────────────────────────────────────
    /// A directive like `.class`, `.method`, `.end method`, `.implements`.
    Directive(String),
    /// A keyword access modifier: `public`, `private`, `static`, `final`, etc.
    Keyword(String),
    /// A Dalvik opcode mnemonic: `invoke-virtual`, `const/4`, etc.
    Opcode(String),

    // ── Identifiers / references ──────────────────────────────────────────────
    /// A register: `v0`..`v255` or `p0`..`p255`.
    Register(u16, RegisterKind),
    /// A jump/switch label: `:cond_0`, `:goto_1`, `:packed_switch_0`.
    Label(String),
    /// A Smali type descriptor: `Ljava/lang/Object;`, `[I`, `V`.
    TypeDesc(String),
    /// A field reference: `Lcom/Foo;->name:Ljava/lang/String;`.
    FieldRef(String),
    /// A method reference: `Lcom/Foo;->name(IZ)V`.
    MethodRef(String),
    /// A plain identifier (class name component, etc.).
    Ident(String),

    // ── Literals ─────────────────────────────────────────────────────────────
    /// An integer literal (decimal or hex with optional `L` suffix).
    IntLiteral(i64),
    /// A floating-point literal.
    FloatLiteral(f64),
    /// A string literal (with escape sequences resolved).
    StringLiteral(String),
    /// A `null` literal.
    NullLiteral,

    // ── Punctuation ───────────────────────────────────────────────────────────
    /// `,`
    Comma,
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `->`
    Arrow,
    /// `:`  (type separator in field refs, not label prefix)
    Colon,
    /// `..`  (range in `{v0 .. v3}`)
    DotDot,

    // ── Meta ──────────────────────────────────────────────────────────────────
    /// A line comment (`# …`).
    Comment(String),
    /// Logical line separator (newline).
    Newline,
    /// End of file.
    Eof,
}

/// Whether a register is a `v` (local) or `p` (parameter) register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RegisterKind {
    Local,
    Param,
}

/// A `Token` together with its source location.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Spanned {
    pub token: Token,
    pub line: u32,
    pub col: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Keyword / directive / access-modifier tables
// ─────────────────────────────────────────────────────────────────────────────

const DIRECTIVES: &[&str] = &[
    "class",
    "super",
    "source",
    "implements",
    "field",
    "method",
    "end method",
    "annotation",
    "end annotation",
    "subannotation",
    "end subannotation",
    "param",
    "end param",
    "registers",
    "locals",
    "prologue",
    "epilogue",
    "packed-switch",
    "end packed-switch",
    "sparse-switch",
    "end sparse-switch",
    "array-data",
    "end array-data",
    "catch",
    "catchall",
    "line",
    "restart local",
    "local",
    "end local",
    "throws",
];

const ACCESS_KEYWORDS: &[&str] = &[
    "public",
    "private",
    "protected",
    "static",
    "final",
    "synchronized",
    "native",
    "abstract",
    "interface",
    "enum",
    "annotation",
    "constructor",
    "bridge",
    "system",
    "declared-synchronized",
    "volatile",
    "transient",
    "varargs",
    "synthetic",
];

// ─────────────────────────────────────────────────────────────────────────────
// Lexer
// ─────────────────────────────────────────────────────────────────────────────

/// Smali source lexer.
pub struct Lexer<'a> {
    src: &'a str,
    pos: usize,
    line: u32,
    col: u32,
}

impl<'a> Lexer<'a> {
    /// Create a new `Lexer` over a source string.
    #[must_use]
    pub const fn new(src: &'a str) -> Self {
        Lexer {
            src,
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    /// Tokenize the entire source and return all spanned tokens.
    ///
    /// # Errors
    ///
    /// Returns [`SmaliError`] if a token cannot be lexed (e.g. an unterminated
    /// string literal or invalid escape sequence).
    pub fn tokenize(&mut self) -> Result<Vec<Spanned>, SmaliError> {
        // Heuristic: average token length ~6 bytes for smali source.
        let mut tokens = Vec::with_capacity(self.src.len() / 6 + 16);
        loop {
            self.skip_whitespace_no_newline();
            if self.pos >= self.src.len() {
                tokens.push(self.spanned(Token::Eof));
                break;
            }
            let ch = self.current_char();
            let tok = match ch {
                '\n' => {
                    self.advance();
                    self.line += 1;
                    self.col = 1;
                    Token::Newline
                }
                '#' => {
                    // Comments are stripped: consume to end of line and emit
                    // no token (the trailing newline is handled next iteration).
                    let _ = self.lex_comment();
                    continue;
                }
                '"' => self.lex_string()?,
                '.' => self.lex_directive_or_float(),
                ':' => self.lex_label_or_colon(),
                '{' => {
                    self.advance();
                    Token::LBrace
                }
                '}' => {
                    self.advance();
                    Token::RBrace
                }
                '(' => {
                    self.advance();
                    Token::LParen
                }
                ')' => {
                    self.advance();
                    Token::RParen
                }
                ',' => {
                    self.advance();
                    Token::Comma
                }
                '-' if self.peek_ahead() == Some('>') => {
                    self.advance();
                    self.advance();
                    Token::Arrow
                }
                '-' | '+' | '0'..='9' => self.lex_number()?,
                'L' => self.lex_type_or_ident(),
                '[' => self.lex_array_type(),
                'v' | 'p' if self.is_register_start() => self.lex_register()?,
                _ => self.lex_keyword_or_opcode_or_ident(),
            };
            tokens.push(self.spanned(tok));
        }
        Ok(tokens)
    }

    // ─── low-level helpers ─────────────────────────────────────────────────

    fn current_char(&self) -> char {
        self.src[self.pos..].chars().next().unwrap_or('\0')
    }

    fn peek_ahead(&self) -> Option<char> {
        let mut iter = self.src[self.pos..].chars();
        iter.next();
        iter.next()
    }

    fn advance(&mut self) {
        if let Some(c) = self.src[self.pos..].chars().next() {
            self.pos += c.len_utf8();
            if c == '\n' {
                // handled at call site
            } else {
                self.col += 1;
            }
        }
    }

    const fn spanned(&self, token: Token) -> Spanned {
        Spanned {
            token,
            line: self.line,
            col: self.col,
        }
    }

    fn skip_whitespace_no_newline(&mut self) {
        while self.pos < self.src.len() {
            let c = self.current_char();
            if c == ' ' || c == '\t' || c == '\r' {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn is_register_start(&self) -> bool {
        let rest = &self.src[self.pos..];
        let mut chars = rest.chars();
        let first = chars.next().unwrap_or('\0');
        let second = chars.next().unwrap_or('\0');
        (first == 'v' || first == 'p') && second.is_ascii_digit()
    }

    fn read_while<F: Fn(char) -> bool>(&mut self, pred: F) -> &'a str {
        let start = self.pos;
        while self.pos < self.src.len() && pred(self.current_char()) {
            self.advance();
        }
        &self.src[start..self.pos]
    }

    // ─── comment ────────────────────────────────────────────────────────────

    fn lex_comment(&mut self) -> Token {
        let start = self.pos;
        while self.pos < self.src.len() && self.current_char() != '\n' {
            self.advance();
        }
        Token::Comment(self.src[start..self.pos].to_owned())
    }

    // ─── string literal ─────────────────────────────────────────────────────

    fn lex_string(&mut self) -> Result<Token, SmaliError> {
        self.advance(); // consume opening "
        let mut s = String::new();
        loop {
            if self.pos >= self.src.len() {
                return Err(SmaliError::ParseError("unterminated string".to_owned()));
            }
            let c = self.current_char();
            self.advance();
            match c {
                '"' => break,
                '\\' => {
                    if self.pos >= self.src.len() {
                        return Err(SmaliError::ParseError("unterminated escape".to_owned()));
                    }
                    let esc = self.current_char();
                    self.advance();
                    s.push(match esc {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        '"' => '"',
                        '\\' => '\\',
                        '0' => '\0',
                        'u' => {
                            // \uXXXX
                            let hex: String = (0..4)
                                .map(|_| {
                                    let ch = self.current_char();
                                    self.advance();
                                    ch
                                })
                                .collect();
                            let code = u32::from_str_radix(&hex, 16).map_err(|_| {
                                SmaliError::ParseError(format!("invalid unicode escape \\u{hex}"))
                            })?;
                            char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER)
                        }
                        other => other,
                    });
                }
                _ => s.push(c),
            }
        }
        Ok(Token::StringLiteral(s))
    }

    // ─── directive ──────────────────────────────────────────────────────────

    fn lex_directive_or_float(&mut self) -> Token {
        let start = self.pos;
        self.advance(); // consume '.'

        // Check for `..` (range)
        if self.current_char() == '.' {
            self.advance();
            return Token::DotDot;
        }

        // Read the first directive word (no embedded spaces).
        let name_start = self.pos;
        while self.pos < self.src.len() {
            let c = self.current_char();
            if c.is_alphanumeric() || c == '-' || c == '_' {
                self.advance();
            } else {
                break;
            }
        }
        let mut name = self.src[name_start..self.pos].to_owned();

        // Some directives are two words (e.g. `end method`, `restart local`).
        // Only consume a following word if it forms a known two-word directive,
        // so we don't greedily swallow operands such as `public` after `.class`.
        if self.current_char() == ' ' {
            let save_pos = self.pos;
            self.advance(); // consume the single separating space
            let word2_start = self.pos;
            while self.pos < self.src.len() {
                let c = self.current_char();
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    self.advance();
                } else {
                    break;
                }
            }
            let candidate = format!("{} {}", name, &self.src[word2_start..self.pos]);
            if DIRECTIVES.iter().any(|&d| d == candidate) {
                name = candidate;
            } else {
                // Not a two-word directive; rewind so the second word is
                // tokenized independently.
                self.pos = save_pos;
            }
        }

        // Check if this matches a known directive.
        if DIRECTIVES.iter().any(|&d| d == name) {
            return Token::Directive(name);
        }

        // Otherwise try to parse as a float (e.g. `.5`).
        let fragment = &self.src[start..self.pos];
        if let Ok(f) = fragment.parse::<f64>() {
            return Token::FloatLiteral(f);
        }

        // Unknown directive — still return as Directive so the parser can handle it.
        Token::Directive(name)
    }

    // ─── label / colon ──────────────────────────────────────────────────────

    fn lex_label_or_colon(&mut self) -> Token {
        let next = self.peek_ahead();
        self.advance(); // consume ':'
        if next.is_some_and(|c| c.is_alphabetic() || c == '_') {
            // Label: `:name`
            let start = self.pos;
            while self.pos < self.src.len() {
                let c = self.current_char();
                if c.is_alphanumeric() || c == '_' || c == '-' {
                    self.advance();
                } else {
                    break;
                }
            }
            let label = format!(":{}", &self.src[start..self.pos]);
            Token::Label(label)
        } else {
            Token::Colon
        }
    }

    // ─── number ─────────────────────────────────────────────────────────────

    fn lex_number(&mut self) -> Result<Token, SmaliError> {
        let start = self.pos;
        // Optional sign.
        if self.current_char() == '-' || self.current_char() == '+' {
            self.advance();
        }
        let is_hex = self.current_char() == '0' && self.src[self.pos + 1..].starts_with('x');
        if is_hex {
            self.advance(); // 0
            self.advance(); // x
            self.read_while(|c| c.is_ascii_hexdigit() || c == '_');
        } else {
            self.read_while(|c| c.is_ascii_digit() || c == '_');
        }

        // Check for float suffix: `.123` or `f`/`F`
        let is_float = !is_hex
            && (self.current_char() == '.'
                || self.current_char() == 'f'
                || self.current_char() == 'F');

        if is_float {
            if self.current_char() == '.' {
                self.advance();
                self.read_while(|c| c.is_ascii_digit());
            }
            if self.current_char() == 'f' || self.current_char() == 'F' {
                self.advance();
            }
            let s: String = self.src[start..self.pos]
                .chars()
                .filter(|&c| c != '_')
                .collect();
            let s = s.trim_end_matches(['f', 'F']);
            return s
                .parse::<f64>()
                .map(Token::FloatLiteral)
                .map_err(|_| SmaliError::ParseError(format!("bad float: {s}")));
        }

        // Optional 'L' long suffix.
        if self.current_char() == 'L' {
            self.advance();
        }

        let raw: String = self.src[start..self.pos]
            .chars()
            .filter(|&c| c != '_' && c != 'L')
            .collect();

        let value = if raw.starts_with("0x") || raw.starts_with("-0x") || raw.starts_with("+0x") {
            let (neg, hex) = if raw.starts_with('-') {
                (true, &raw[3..])
            } else if raw.starts_with('+') {
                (false, &raw[3..])
            } else {
                (false, &raw[2..])
            };
            i64::from_str_radix(hex, 16)
                .map(|v| if neg { -v } else { v })
                .map_err(|_| SmaliError::ParseError(format!("bad hex: {raw}")))?
        } else {
            raw.parse::<i64>()
                .map_err(|_| SmaliError::ParseError(format!("bad int: {raw}")))?
        };
        Ok(Token::IntLiteral(value))
    }

    // ─── type descriptor ────────────────────────────────────────────────────

    fn lex_type_or_ident(&mut self) -> Token {
        let start = self.pos;
        // Read up to ';' for object types.
        while self.pos < self.src.len() {
            let c = self.current_char();
            if c == ';' {
                self.advance();
                break;
            }
            if c == ' ' || c == '\t' || c == '\n' || c == ',' || c == ')' {
                break;
            }
            self.advance();
        }
        let s = self.src[start..self.pos].to_owned();
        if s.starts_with('L') && s.ends_with(';') {
            Token::TypeDesc(s)
        } else {
            Token::Ident(s)
        }
    }

    // ─── array type ─────────────────────────────────────────────────────────

    fn lex_array_type(&mut self) -> Token {
        let start = self.pos;
        while self.pos < self.src.len() {
            let c = self.current_char();
            if c == ' ' || c == '\t' || c == '\n' || c == ',' || c == ')' || c == '{' || c == '}' {
                break;
            }
            if c == ';' {
                self.advance();
                break;
            }
            self.advance();
        }
        Token::TypeDesc(self.src[start..self.pos].to_owned())
    }

    // ─── register ───────────────────────────────────────────────────────────

    fn lex_register(&mut self) -> Result<Token, SmaliError> {
        let kind = if self.current_char() == 'v' {
            RegisterKind::Local
        } else {
            RegisterKind::Param
        };
        self.advance(); // consume 'v' or 'p'
        let num_str = self.read_while(|c| c.is_ascii_digit());
        let num = num_str
            .parse::<u16>()
            .map_err(|_| SmaliError::InvalidReg(0))?;
        Ok(Token::Register(num, kind))
    }

    // ─── keyword / opcode / ident ────────────────────────────────────────────

    fn lex_keyword_or_opcode_or_ident(&mut self) -> Token {
        let start = self.pos;
        while self.pos < self.src.len() {
            let c = self.current_char();
            // `<` and `>` are allowed so special method names like `<init>`
            // and `<clinit>` lex as a single identifier; `$` covers synthetic
            // member names.
            if c.is_alphanumeric()
                || c == '-'
                || c == '_'
                || c == '/'
                || c == '<'
                || c == '>'
                || c == '$'
            {
                self.advance();
            } else {
                break;
            }
        }
        // Guard against non-advancing iterations: if the current character is
        // not part of an identifier (e.g. a stray symbol), consume it as a
        // single-character ident so `tokenize` always makes progress and never
        // loops forever building empty tokens.
        if self.pos == start && self.pos < self.src.len() {
            self.advance();
        }
        let word = &self.src[start..self.pos];

        if word == "null" {
            return Token::NullLiteral;
        }
        if ACCESS_KEYWORDS.contains(&word) {
            return Token::Keyword(word.to_owned());
        }
        // Known Dalvik mnemonic (covers single-word opcodes like `nop`,
        // `move`, `return-void`, etc.).
        if crate::disassembler::OPCODE_TABLE
            .iter()
            .any(|d| d.mnemonic == word)
        {
            return Token::Opcode(word.to_owned());
        }
        // Heuristic for opcode variants not in the table: contain `-` or `/`
        // and don't end with `;`.
        if (word.contains('-') || word.contains('/')) && !word.ends_with(';') {
            return Token::Opcode(word.to_owned());
        }
        Token::Ident(word.to_owned())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// High-level API
// ─────────────────────────────────────────────────────────────────────────────

/// Tokenize a Smali source string, discarding comment tokens.
///
/// # Errors
///
/// Returns [`SmaliError`] if any token cannot be lexed (e.g. an unterminated
/// string or invalid escape).
pub fn tokenize(src: &str) -> Result<Vec<Spanned>, SmaliError> {
    let mut lexer = Lexer::new(src);
    let mut tokens = lexer.tokenize()?;
    tokens.retain(|s| !matches!(s.token, Token::Comment(_)));
    Ok(tokens)
}

/// Tokenize and return only the token kinds (without location info).
///
/// # Errors
///
/// Returns [`SmaliError`] if any token cannot be lexed.
pub fn tokenize_flat(src: &str) -> Result<Vec<Token>, SmaliError> {
    Ok(tokenize(src)?.into_iter().map(|s| s.token).collect())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(src: &str) -> Vec<Token> {
        tokenize_flat(src).expect("tokenize")
    }

    #[test]
    fn test_lex_directive() {
        let tokens = tok(".class public Lcom/example/Foo;\n");
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::Directive(d) if d == "class"))
        );
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::Keyword(k) if k == "public"))
        );
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::TypeDesc(d) if d == "Lcom/example/Foo;"))
        );
    }

    #[test]
    fn test_lex_register_v() {
        let tokens = tok("move v0, v1\n");
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::Register(0, RegisterKind::Local)))
        );
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::Register(1, RegisterKind::Local)))
        );
    }

    #[test]
    fn test_lex_register_p() {
        let tokens = tok("return p0\n");
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::Register(0, RegisterKind::Param)))
        );
    }

    #[test]
    fn test_lex_label() {
        let tokens = tok(":cond_0\n");
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::Label(l) if l == ":cond_0"))
        );
    }

    #[test]
    fn test_lex_string_simple() {
        let tokens = tok("const-string v0, \"hello world\"\n");
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::StringLiteral(s) if s == "hello world"))
        );
    }

    #[test]
    fn test_lex_string_escape() {
        let tokens = tok("const-string v0, \"line1\\nline2\"\n");
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::StringLiteral(s) if s.contains('\n')))
        );
    }

    #[test]
    fn test_lex_integer_hex() {
        let tokens = tok("const v0, 0x1F\n");
        assert!(tokens.iter().any(|t| matches!(t, Token::IntLiteral(0x1F))));
    }

    #[test]
    fn test_lex_integer_negative() {
        let tokens = tok("const/16 v0, -1\n");
        assert!(tokens.iter().any(|t| matches!(t, Token::IntLiteral(-1))));
    }

    #[test]
    fn test_lex_comment_stripped() {
        let tokens = tok("# this is a comment\nnop\n");
        assert!(!tokens.iter().any(|t| matches!(t, Token::Comment(_))));
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::Opcode(op) if op == "nop"))
        );
    }

    #[test]
    fn test_lex_null() {
        let tokens = tok("const/4 v0, null\n");
        assert!(tokens.iter().any(|t| matches!(t, Token::NullLiteral)));
    }

    #[test]
    fn test_lex_array_type() {
        let tokens = tok("check-cast v0, [B\n");
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::TypeDesc(d) if d == "[B"))
        );
    }

    #[test]
    fn test_lex_comma_and_braces() {
        let tokens =
            tok("invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V\n");
        assert!(tokens.iter().any(|t| matches!(t, Token::LBrace)));
        assert!(tokens.iter().any(|t| matches!(t, Token::RBrace)));
        assert!(tokens.iter().any(|t| matches!(t, Token::Comma)));
        assert!(tokens.iter().any(|t| matches!(t, Token::Arrow)));
    }

    #[test]
    fn test_lex_end_method() {
        let tokens = tok(".end method\n");
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::Directive(d) if d == "end method"))
        );
    }

    #[test]
    fn test_lex_spanned_line_numbers() {
        let spanned =
            tokenize(".class public Lcom/Foo;\n.super Ljava/lang/Object;\n").expect("tokenize");
        let has_second_line = spanned.iter().any(|s| s.line == 2);
        assert!(has_second_line);
    }

    #[test]
    fn test_lex_empty_source() {
        let tokens = tok("");
        assert!(tokens.iter().any(|t| matches!(t, Token::Eof)));
    }

    #[test]
    fn test_lex_return_void() {
        let tokens = tok("return-void\n");
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::Opcode(op) if op == "return-void"))
        );
    }

    #[test]
    fn test_lex_method_header() {
        let src = ".method public static foo(ILjava/lang/String;)Z\n";
        let tokens = tok(src);
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::Directive(d) if d == "method"))
        );
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::Keyword(k) if k == "public"))
        );
        assert!(
            tokens
                .iter()
                .any(|t| matches!(t, Token::Keyword(k) if k == "static"))
        );
    }
}
