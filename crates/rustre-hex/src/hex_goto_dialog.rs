//! Go-to-address dialog logic for the hex editor: expression parsing,
//! offset resolution, and history management — no GUI dependencies.

use std::collections::VecDeque;
use std::fmt;
use std::num::ParseIntError;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GotoError {
    /// The expression string was empty.
    EmptyExpression,
    /// A token could not be parsed.
    InvalidToken(String),
    /// Integer literal was out of range.
    Overflow,
    /// Division by zero in expression.
    DivisionByZero,
    /// The resolved offset is past the end of the buffer.
    OutOfRange { offset: usize, buffer_len: usize },
    /// A named symbol could not be resolved.
    UnknownSymbol(String),
}

impl fmt::Display for GotoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyExpression => write!(f, "expression is empty"),
            Self::InvalidToken(t) => write!(f, "invalid token: {t}"),
            Self::Overflow => write!(f, "integer literal is out of range"),
            Self::DivisionByZero => write!(f, "division by zero"),
            Self::OutOfRange { offset, buffer_len } => {
                write!(f, "offset {offset:#x} is past buffer end {buffer_len:#x}")
            }
            Self::UnknownSymbol(s) => write!(f, "unknown symbol: {s}"),
        }
    }
}

impl std::error::Error for GotoError {}

impl From<ParseIntError> for GotoError {
    fn from(_e: ParseIntError) -> Self {
        Self::Overflow
    }
}

// ── GotoMode ─────────────────────────────────────────────────────────────────

/// How the offset in a [`GotoTarget`] is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum GotoMode {
    /// Absolute byte offset from the start of the buffer.
    #[default]
    Absolute,
    /// Offset relative to the current cursor position.
    RelativeToCursor,
    /// Offset relative to the end of the buffer.
    RelativeToEnd,
}


impl fmt::Display for GotoMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── GotoTarget ────────────────────────────────────────────────────────────────

/// A resolved navigation target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GotoTarget {
    /// The raw expression that produced this target.
    pub expression: String,
    /// The resolved absolute offset.
    pub absolute_offset: usize,
    /// The mode that was used for resolution.
    pub mode: GotoMode,
}

impl GotoTarget {
    #[must_use]
    pub fn new(expression: impl Into<String>, offset: usize, mode: GotoMode) -> Self {
        Self {
            expression: expression.into(),
            absolute_offset: offset,
            mode,
        }
    }
}

impl fmt::Display for GotoTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} → {:#010x} ({})",
            self.expression, self.absolute_offset, self.mode
        )
    }
}

// ── Tokenizer ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Number(i64),
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    LParen,
    RParen,
    Symbol(String),
}

fn tokenize(s: &str) -> Result<Vec<Token>, GotoError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(GotoError::EmptyExpression);
    }

    let mut tokens = Vec::new();
    let mut chars = s.chars().peekable();

    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' => {
                chars.next();
            }
            '+' => {
                chars.next();
                tokens.push(Token::Plus);
            }
            '-' => {
                chars.next();
                tokens.push(Token::Minus);
            }
            '*' => {
                chars.next();
                tokens.push(Token::Star);
            }
            '/' => {
                chars.next();
                tokens.push(Token::Slash);
            }
            '%' => {
                chars.next();
                tokens.push(Token::Percent);
            }
            '(' => {
                chars.next();
                tokens.push(Token::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(Token::RParen);
            }
            '0' if matches!(chars.clone().nth(1), Some('x' | 'X')) => {
                chars.next(); // '0'
                chars.next(); // 'x'
                let mut hex = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_hexdigit() || c == '_' {
                        if c != '_' { hex.push(c); }
                        chars.next();
                    } else { break; }
                }
                let n = i64::from_str_radix(&hex, 16).map_err(|_| GotoError::Overflow)?;
                tokens.push(Token::Number(n));
            }
            c if c.is_ascii_digit() => {
                let mut num = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_digit() || c == '_' {
                        if c != '_' { num.push(c); }
                        chars.next();
                    } else { break; }
                }
                let n: i64 = num.parse().map_err(|_| GotoError::Overflow)?;
                tokens.push(Token::Number(n));
            }
            c if c.is_alphabetic() || c == '_' => {
                let _ = c;
                let mut sym = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_alphanumeric() || c == '_' {
                        sym.push(c);
                        chars.next();
                    } else { break; }
                }
                tokens.push(Token::Symbol(sym));
            }
            other => {
                return Err(GotoError::InvalidToken(other.to_string()));
            }
        }
    }

    Ok(tokens)
}

// ── Recursive-descent parser ──────────────────────────────────────────────────

struct Parser<'a, F> {
    tokens: &'a [Token],
    pos: usize,
    symbol_resolver: &'a F,
}

impl<'a, F: Fn(&str) -> Option<u64>> Parser<'a, F> {
    const fn new(tokens: &'a [Token], resolver: &'a F) -> Self {
        Self {
            tokens,
            pos: 0,
            symbol_resolver: resolver,
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn consume(&mut self) -> Option<&Token> {
        let t = self.tokens.get(self.pos);
        self.pos += 1;
        t
    }

    fn parse_expr(&mut self) -> Result<i64, GotoError> {
        self.parse_additive()
    }

    fn parse_additive(&mut self) -> Result<i64, GotoError> {
        let mut lhs = self.parse_multiplicative()?;
        loop {
            match self.peek() {
                Some(Token::Plus) => {
                    self.consume();
                    lhs = lhs.saturating_add(self.parse_multiplicative()?);
                }
                Some(Token::Minus) => {
                    self.consume();
                    lhs = lhs.saturating_sub(self.parse_multiplicative()?);
                }
                _ => break,
            }
        }
        Ok(lhs)
    }

    fn parse_multiplicative(&mut self) -> Result<i64, GotoError> {
        let mut lhs = self.parse_unary()?;
        loop {
            match self.peek() {
                Some(Token::Star) => {
                    self.consume();
                    lhs = lhs.saturating_mul(self.parse_unary()?);
                }
                Some(Token::Slash) => {
                    self.consume();
                    let rhs = self.parse_unary()?;
                    if rhs == 0 {
                        return Err(GotoError::DivisionByZero);
                    }
                    lhs /= rhs;
                }
                Some(Token::Percent) => {
                    self.consume();
                    let rhs = self.parse_unary()?;
                    if rhs == 0 {
                        return Err(GotoError::DivisionByZero);
                    }
                    lhs %= rhs;
                }
                _ => break,
            }
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<i64, GotoError> {
        match self.peek() {
            Some(Token::Minus) => {
                self.consume();
                Ok(-self.parse_primary()?)
            }
            Some(Token::Plus) => {
                self.consume();
                self.parse_primary()
            }
            _ => self.parse_primary(),
        }
    }

    fn parse_primary(&mut self) -> Result<i64, GotoError> {
        match self.peek().cloned() {
            Some(Token::Number(n)) => {
                self.consume();
                Ok(n)
            }
            Some(Token::LParen) => {
                self.consume();
                let v = self.parse_expr()?;
                if matches!(self.peek(), Some(Token::RParen)) {
                    self.consume();
                }
                Ok(v)
            }
            Some(Token::Symbol(ref name)) => {
                let name = name.clone();
                self.consume();
                (self.symbol_resolver)(&name)
                    .map(u64::cast_signed)
                    .ok_or(GotoError::UnknownSymbol(name))
            }
            Some(other) => Err(GotoError::InvalidToken(format!("{other:?}"))),
            None => Err(GotoError::InvalidToken("unexpected end of expression".into())),
        }
    }
}

// ── parse_address_expression ──────────────────────────────────────────────────

/// Parse an address expression and resolve it to an absolute byte offset.
///
/// Supported syntax:
/// - Decimal literals: `1024`
/// - Hex literals: `0x400`
/// - Underscore separators: `0x0040_0000`
/// - Arithmetic: `+`, `-`, `*`, `/`, `%`, unary `-`
/// - Parentheses: `(base + 0x10) * 2`
/// - Named symbols resolved via `symbol_resolver`
///
/// The `mode` parameter controls how the expression is interpreted relative to
/// `cursor` and `buffer_len`.
///
/// # Errors
///
/// Returns [`GotoError`] if the expression is syntactically invalid, refers to an unknown
/// symbol, or resolves to an offset outside `buffer_len`.
pub fn parse_address_expression<F>(
    expr: &str,
    mode: GotoMode,
    cursor: usize,
    buffer_len: usize,
    symbol_resolver: F,
) -> Result<GotoTarget, GotoError>
where
    F: Fn(&str) -> Option<u64>,
{
    let tokens = tokenize(expr)?;
    let mut parser = Parser::new(&tokens, &symbol_resolver);
    let value = parser.parse_expr()?;

    let absolute: usize = match mode {
        GotoMode::Absolute => {
            if value < 0 {
                return Err(GotoError::OutOfRange {
                    offset: 0,
                    buffer_len,
                });
            }
            usize::try_from(value).unwrap_or(usize::MAX)
        }
        GotoMode::RelativeToCursor => {
            let signed = i64::try_from(cursor)
                .unwrap_or(i64::MAX)
                .saturating_add(value);
            if signed < 0 {
                0
            } else {
                usize::try_from(signed).unwrap_or(usize::MAX)
            }
        }
        GotoMode::RelativeToEnd => {
            let signed = i64::try_from(buffer_len)
                .unwrap_or(i64::MAX)
                .saturating_add(value);
            if signed < 0 {
                0
            } else {
                usize::try_from(signed).unwrap_or(usize::MAX)
            }
        }
    };

    if absolute > buffer_len {
        return Err(GotoError::OutOfRange {
            offset: absolute,
            buffer_len,
        });
    }

    Ok(GotoTarget::new(expr.trim(), absolute, mode))
}

// ── History ───────────────────────────────────────────────────────────────────

const DEFAULT_HISTORY_CAPACITY: usize = 50;

/// Maintains a bounded history of successfully navigated expressions.
#[derive(Debug, Clone)]
pub struct GotoHistory {
    entries: VecDeque<String>,
    capacity: usize,
}

impl GotoHistory {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity.max(1)),
            capacity: capacity.max(1),
        }
    }

    #[must_use]
    pub fn default_capacity() -> Self {
        Self::new(DEFAULT_HISTORY_CAPACITY)
    }

    /// Push a new expression.  Deduplicates: moves existing entry to front.
    pub fn push(&mut self, expr: impl Into<String>) {
        let expr = expr.into();
        // Remove any existing duplicate.
        self.entries.retain(|e| e != &expr);
        if self.entries.len() >= self.capacity {
            self.entries.pop_back();
        }
        self.entries.push_front(expr);
    }

    /// Iterate from newest to oldest.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(String::as_str)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the most recently pushed expression.
    #[must_use]
    pub fn latest(&self) -> Option<&str> {
        self.entries.front().map(String::as_str)
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ── HexGotoDialog ─────────────────────────────────────────────────────────────

/// The model layer for a "go to address" dialog.
///
/// Combines expression parsing, mode selection, out-of-range validation, and
/// navigation history.  The caller is responsible for rendering.
pub struct HexGotoDialog {
    /// Current text in the expression input field.
    pub expression: String,
    /// Selected navigation mode.
    pub mode: GotoMode,
    /// Navigation history (most-recent first).
    pub history: GotoHistory,
    /// Buffer length used for range validation.
    buffer_len: usize,
    /// Current cursor position used for relative navigation.
    cursor: usize,
    /// Last successful target (after a successful `navigate()` call).
    last_target: Option<GotoTarget>,
}

impl HexGotoDialog {
    /// Create a new dialog for a buffer of `buffer_len` bytes with the cursor
    /// at `cursor`.
    #[must_use]
    pub fn new(buffer_len: usize, cursor: usize) -> Self {
        Self {
            expression: String::new(),
            mode: GotoMode::default(),
            history: GotoHistory::default_capacity(),
            buffer_len,
            cursor,
            last_target: None,
        }
    }

    /// Update the dialog when the editor state changes.
    pub const fn update_context(&mut self, buffer_len: usize, cursor: usize) {
        self.buffer_len = buffer_len;
        self.cursor = cursor;
    }

    /// Resolve the current expression string using the supplied symbol resolver.
    ///
    /// On success, records the expression in history and stores the target.
    ///
    /// # Errors
    ///
    /// Returns a [`GotoError`] if expression parsing or resolution fails.
    pub fn navigate<F>(&mut self, symbol_resolver: F) -> Result<GotoTarget, GotoError>
    where
        F: Fn(&str) -> Option<u64>,
    {
        let target = parse_address_expression(
            &self.expression,
            self.mode,
            self.cursor,
            self.buffer_len,
            symbol_resolver,
        )?;
        self.history.push(self.expression.trim());
        self.last_target = Some(target.clone());
        Ok(target)
    }

    /// Navigate without a symbol resolver (treats all symbol references as unknown).
    ///
    /// # Errors
    ///
    /// Returns a [`GotoError`] if expression parsing or resolution fails.
    pub fn navigate_simple(&mut self) -> Result<GotoTarget, GotoError> {
        self.navigate(|_| None)
    }

    /// The last successfully resolved [`GotoTarget`], if any.
    #[must_use]
    pub const fn last_target(&self) -> Option<&GotoTarget> {
        self.last_target.as_ref()
    }

    /// Load a history entry into the expression field.
    pub fn recall(&mut self, expr: &str) {
        self.expression.clear();
        self.expression.push_str(expr);
    }

    /// Clear the expression field.
    pub fn clear_expression(&mut self) {
        self.expression.clear();
    }
}

impl fmt::Debug for HexGotoDialog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HexGotoDialog")
            .field("expression", &self.expression)
            .field("mode", &self.mode)
            .field("buffer_len", &self.buffer_len)
            .field("cursor", &self.cursor)
            .field("history", &self.history)
            .field("last_target", &self.last_target)
            .finish()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn no_sym(_: &str) -> Option<u64> {
        None
    }

    #[test]
    fn parse_decimal() {
        let t = parse_address_expression("1024", GotoMode::Absolute, 0, 4096, no_sym).unwrap();
        assert_eq!(t.absolute_offset, 1024);
    }

    #[test]
    fn parse_hex_literal() {
        let t = parse_address_expression("0x400", GotoMode::Absolute, 0, 0x10000, no_sym).unwrap();
        assert_eq!(t.absolute_offset, 0x400);
    }

    #[test]
    fn parse_hex_with_underscores() {
        let t =
            parse_address_expression("0x0040_0000", GotoMode::Absolute, 0, 0x1000_0000, no_sym)
                .unwrap();
        assert_eq!(t.absolute_offset, 0x0040_0000);
    }

    #[test]
    fn parse_addition() {
        let t =
            parse_address_expression("0x100 + 0x200", GotoMode::Absolute, 0, 0x1000, no_sym)
                .unwrap();
        assert_eq!(t.absolute_offset, 0x300);
    }

    #[test]
    fn parse_subtraction() {
        let t =
            parse_address_expression("0x300 - 0x100", GotoMode::Absolute, 0, 0x1000, no_sym)
                .unwrap();
        assert_eq!(t.absolute_offset, 0x200);
    }

    #[test]
    fn parse_multiplication() {
        let t = parse_address_expression("4 * 64", GotoMode::Absolute, 0, 1000, no_sym).unwrap();
        assert_eq!(t.absolute_offset, 256);
    }

    #[test]
    fn parse_division() {
        let t = parse_address_expression("512 / 2", GotoMode::Absolute, 0, 1000, no_sym).unwrap();
        assert_eq!(t.absolute_offset, 256);
    }

    #[test]
    fn division_by_zero_error() {
        let r = parse_address_expression("10 / 0", GotoMode::Absolute, 0, 1000, no_sym);
        assert_eq!(r.unwrap_err(), GotoError::DivisionByZero);
    }

    #[test]
    fn parse_parentheses() {
        let t =
            parse_address_expression("(0x10 + 0x20) * 2", GotoMode::Absolute, 0, 1000, no_sym)
                .unwrap();
        assert_eq!(t.absolute_offset, 0x60);
    }

    #[test]
    fn relative_to_cursor() {
        let t =
            parse_address_expression("+0x10", GotoMode::RelativeToCursor, 0x100, 0x1000, no_sym)
                .unwrap();
        assert_eq!(t.absolute_offset, 0x110);
    }

    #[test]
    fn relative_to_cursor_negative() {
        let t =
            parse_address_expression("-0x10", GotoMode::RelativeToCursor, 0x100, 0x1000, no_sym)
                .unwrap();
        assert_eq!(t.absolute_offset, 0xF0);
    }

    #[test]
    fn relative_to_end() {
        let t =
            parse_address_expression("-0x10", GotoMode::RelativeToEnd, 0, 0x1000, no_sym).unwrap();
        assert_eq!(t.absolute_offset, 0xFF0);
    }

    #[test]
    fn out_of_range_error() {
        let r = parse_address_expression("0xFFFF", GotoMode::Absolute, 0, 0x100, no_sym);
        assert!(matches!(r.unwrap_err(), GotoError::OutOfRange { .. }));
    }

    #[test]
    fn symbol_resolver_used() {
        let t = parse_address_expression(
            "main + 0x10",
            GotoMode::Absolute,
            0,
            0x10000,
            |s| if s == "main" { Some(0x1000) } else { None },
        )
        .unwrap();
        assert_eq!(t.absolute_offset, 0x1010);
    }

    #[test]
    fn unknown_symbol_error() {
        let r = parse_address_expression("unknown_fn", GotoMode::Absolute, 0, 0x10000, no_sym);
        assert!(matches!(r.unwrap_err(), GotoError::UnknownSymbol(_)));
    }

    #[test]
    fn empty_expression_error() {
        let r = parse_address_expression("  ", GotoMode::Absolute, 0, 100, no_sym);
        assert_eq!(r.unwrap_err(), GotoError::EmptyExpression);
    }

    #[test]
    fn history_deduplicates() {
        let mut h = GotoHistory::new(10);
        h.push("0x100");
        h.push("0x200");
        h.push("0x100");
        assert_eq!(h.len(), 2);
        assert_eq!(h.latest(), Some("0x100"));
    }

    #[test]
    fn history_capacity_evicts_oldest() {
        let mut h = GotoHistory::new(3);
        h.push("a");
        h.push("b");
        h.push("c");
        h.push("d");
        assert_eq!(h.len(), 3);
        assert!(!h.iter().any(|e| e == "a"));
    }

    #[test]
    fn dialog_navigate_records_history() {
        let mut dlg = HexGotoDialog::new(0x10000, 0x1000);
        dlg.expression = "0x2000".into();
        let t = dlg.navigate_simple().unwrap();
        assert_eq!(t.absolute_offset, 0x2000);
        assert_eq!(dlg.history.latest(), Some("0x2000"));
    }

    #[test]
    fn dialog_navigate_out_of_range() {
        let mut dlg = HexGotoDialog::new(0x100, 0);
        dlg.expression = "0x200".into();
        assert!(dlg.navigate_simple().is_err());
    }
}
