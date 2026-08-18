//! PDF object parser — parse PDF syntax tokens and build a typed [`PdfObject`]
//! tree.  Supports all PDF value types: booleans, integers, reals, names,
//! strings, arrays, dictionaries, streams, indirect references, and null.

use std::collections::HashMap;
use std::fmt;

// ─── PdfParseError ────────────────────────────────────────────────────────────

/// Errors from the PDF object parser.
#[derive(Debug, Clone)]
pub enum PdfParseError {
    UnexpectedEnd,
    UnexpectedByte(u8, usize),
    InvalidEscape(u8),
    InvalidHexNibble(u8),
    UnclosedString,
    UnclosedArray,
    UnclosedDict,
    MalformedIndirectRef,
    Custom(String),
}

impl fmt::Display for PdfParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd => write!(f, "unexpected end of data"),
            Self::UnexpectedByte(b, pos) => write!(f, "unexpected byte {b:#04x} at {pos}"),
            Self::InvalidEscape(b) => write!(f, "invalid escape \\{}", *b as char),
            Self::InvalidHexNibble(b) => write!(f, "invalid hex nibble {b:#04x}"),
            Self::UnclosedString => write!(f, "unclosed string literal"),
            Self::UnclosedArray => write!(f, "unclosed array"),
            Self::UnclosedDict => write!(f, "unclosed dictionary"),
            Self::MalformedIndirectRef => write!(f, "malformed indirect reference"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

// ─── PdfDict ──────────────────────────────────────────────────────────────────

/// An ordered PDF dictionary.
#[derive(Debug, Clone, Default)]
pub struct PdfDict {
    pub entries: Vec<(String, PdfObject)>,
}

impl PdfDict {
    /// Create an empty dictionary.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a key.
    pub fn set(&mut self, key: impl Into<String>, value: PdfObject) {
        let key = key.into();
        if let Some(e) = self.entries.iter_mut().find(|(k, _)| *k == key) {
            e.1 = value;
        } else {
            self.entries.push((key, value));
        }
    }

    /// Get a value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&PdfObject> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Get value as integer.
    #[must_use]
    pub fn get_int(&self, key: &str) -> Option<i64> {
        match self.get(key)? {
            PdfObject::Integer(n) => Some(*n),
            _ => None,
        }
    }

    /// Get value as name string.
    #[must_use]
    pub fn get_name(&self, key: &str) -> Option<&str> {
        match self.get(key)? {
            PdfObject::Name(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Get value as array.
    #[must_use]
    pub fn get_array(&self, key: &str) -> Option<&Vec<PdfObject>> {
        match self.get(key)? {
            PdfObject::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Returns `true` if the key is present.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.iter().any(|(k, _)| k == key)
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the dictionary is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Convert to a `HashMap` for fast random access.
    #[must_use]
    pub fn to_map(&self) -> HashMap<String, &PdfObject> {
        self.entries.iter().map(|(k, v)| (k.clone(), v)).collect()
    }
}

impl fmt::Display for PdfDict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<<")
        // abbreviated display
    }
}

// ─── PdfStream ────────────────────────────────────────────────────────────────

/// A PDF stream object: dictionary + raw byte data.
#[derive(Debug, Clone)]
pub struct PdfStream {
    pub dict: PdfDict,
    /// Raw (un-decoded) stream bytes.
    pub data: Vec<u8>,
}

impl PdfStream {
    /// Create a new stream.
    #[must_use]
    pub const fn new(dict: PdfDict, data: Vec<u8>) -> Self {
        Self { dict, data }
    }

    /// Declared `/Length` value from the stream dictionary.
    #[must_use]
    pub fn declared_length(&self) -> Option<usize> {
        self.dict.get_int("Length").map(|n| n as usize)
    }

    /// Filter name, if any (first `/Filter` name).
    #[must_use]
    pub fn filter_name(&self) -> Option<&str> {
        self.dict.get_name("Filter")
    }

    /// Returns `true` if this stream has a `FlateDecode` filter.
    #[must_use]
    pub fn is_flate_encoded(&self) -> bool {
        self.filter_name() == Some("FlateDecode")
    }
}

// ─── PdfObject ────────────────────────────────────────────────────────────────

/// A parsed PDF object.
#[derive(Debug, Clone)]
pub enum PdfObject {
    Null,
    Boolean(bool),
    Integer(i64),
    Real(f64),
    Name(String),
    String(Vec<u8>),
    Array(Vec<PdfObject>),
    Dictionary(PdfDict),
    Stream(PdfStream),
    Indirect { obj_num: u32, generation: u32 },
}

impl PdfObject {
    /// Returns the integer value, if this is `Integer`.
    #[must_use]
    pub const fn as_int(&self) -> Option<i64> {
        match self {
            Self::Integer(n) => Some(*n),
            _ => None,
        }
    }

    /// Returns the name string, if this is `Name`.
    #[must_use]
    pub const fn as_name(&self) -> Option<&str> {
        match self {
            Self::Name(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Returns the bytes, if this is `String`.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::String(b) => Some(b),
            _ => None,
        }
    }

    /// Returns the dictionary, if this is `Dictionary` or `Stream`.
    #[must_use]
    pub const fn as_dict(&self) -> Option<&PdfDict> {
        match self {
            Self::Dictionary(d) => Some(d),
            Self::Stream(s) => Some(&s.dict),
            _ => None,
        }
    }

    /// Returns the array, if this is `Array`.
    #[must_use]
    pub const fn as_array(&self) -> Option<&Vec<PdfObject>> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Returns `true` if this is `Null`.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Type name string for display.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Boolean(_) => "boolean",
            Self::Integer(_) => "integer",
            Self::Real(_) => "real",
            Self::Name(_) => "name",
            Self::String(_) => "string",
            Self::Array(_) => "array",
            Self::Dictionary(_) => "dictionary",
            Self::Stream(_) => "stream",
            Self::Indirect { .. } => "indirect-ref",
        }
    }
}

impl fmt::Display for PdfObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "null"),
            Self::Boolean(b) => write!(f, "{b}"),
            Self::Integer(n) => write!(f, "{n}"),
            Self::Real(v) => write!(f, "{v}"),
            Self::Name(s) => write!(f, "/{s}"),
            Self::String(b) => write!(f, "({})", String::from_utf8_lossy(b)),
            Self::Array(_) => write!(f, "[...]"),
            Self::Dictionary(_) => write!(f, "<<...>>"),
            Self::Stream(_) => write!(f, "stream"),
            Self::Indirect { obj_num, generation } => write!(f, "{obj_num} {generation} R"),
        }
    }
}

// ─── PdfObjectParser ─────────────────────────────────────────────────────────

/// A stateful PDF object parser operating on a byte slice.
pub struct PdfObjectParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> PdfObjectParser<'a> {
    /// Create a new parser starting at byte `0`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Create a parser positioned at `offset`.
    #[must_use]
    pub const fn at(data: &'a [u8], offset: usize) -> Self {
        Self { data, pos: offset }
    }

    /// Current byte position.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Parse the next PDF value from the current position.
    pub fn parse_value(&mut self) -> Result<PdfObject, PdfParseError> {
        self.skip_whitespace_and_comments();
        if self.pos >= self.data.len() {
            return Ok(PdfObject::Null);
        }
        match self.data[self.pos] {
            b'n' => self.parse_keyword("null", PdfObject::Null),
            b't' => self.parse_keyword("true", PdfObject::Boolean(true)),
            b'f' => self.parse_keyword("false", PdfObject::Boolean(false)),
            b'/' => self.parse_name(),
            b'(' => self.parse_literal_string(),
            b'<' if self.data.get(self.pos + 1) == Some(&b'<') => self.parse_dict_or_stream(),
            b'<' => self.parse_hex_string(),
            b'[' => self.parse_array(),
            b if b.is_ascii_digit() || b == b'-' || b == b'+' || b == b'.' => {
                self.parse_number_or_ref()
            }
            other => Err(PdfParseError::UnexpectedByte(other, self.pos)),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let b = self.data.get(self.pos).copied();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    fn skip_whitespace_and_comments(&mut self) {
        while self.pos < self.data.len() {
            match self.data[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' | 0x00 | 0x0C => {
                    self.pos += 1;
                }
                b'%' => {
                    // Comment: skip to end of line.
                    while self.pos < self.data.len() && self.data[self.pos] != b'\n' {
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
    }

    fn parse_keyword(&mut self, keyword: &str, value: PdfObject) -> Result<PdfObject, PdfParseError> {
        let end = self.pos + keyword.len();
        if end > self.data.len() {
            return Err(PdfParseError::UnexpectedEnd);
        }
        self.pos = end;
        Ok(value)
    }

    fn parse_name(&mut self) -> Result<PdfObject, PdfParseError> {
        self.pos += 1; // skip '/'
        let mut name = Vec::new();
        while self.pos < self.data.len() {
            let b = self.data[self.pos];
            if b == b'#' && self.pos + 2 < self.data.len() {
                let hi = hex_nibble(self.data[self.pos + 1])
                    .ok_or(PdfParseError::InvalidHexNibble(self.data[self.pos + 1]))?;
                let lo = hex_nibble(self.data[self.pos + 2])
                    .ok_or(PdfParseError::InvalidHexNibble(self.data[self.pos + 2]))?;
                name.push((hi << 4) | lo);
                self.pos += 3;
            } else if is_delimiter(b) || is_whitespace(b) {
                break;
            } else {
                name.push(b);
                self.pos += 1;
            }
        }
        let s = String::from_utf8_lossy(&name).into_owned();
        Ok(PdfObject::Name(s))
    }

    fn parse_literal_string(&mut self) -> Result<PdfObject, PdfParseError> {
        self.pos += 1; // skip '('
        let mut out = Vec::new();
        let mut depth = 1i32;
        loop {
            let b = match self.advance() {
                Some(b) => b,
                None => return Err(PdfParseError::UnclosedString),
            };
            match b {
                b'\\' => {
                    let next = self.advance().ok_or(PdfParseError::UnexpectedEnd)?;
                    let escaped = match next {
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'b' => 0x08,
                        b'f' => 0x0C,
                        b'(' => b'(',
                        b')' => b')',
                        b'\\' => b'\\',
                        b'\n' | b'\r' => continue,
                        d if d.is_ascii_digit() => {
                            let mut octal = (d - b'0') as u32;
                            for _ in 0..2 {
                                if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                                    let c = self.advance().unwrap();
                                    octal = octal * 8 + (c - b'0') as u32;
                                }
                            }
                            (octal & 0xFF) as u8
                        }
                        _ => next,
                    };
                    out.push(escaped);
                }
                b'(' => {
                    depth += 1;
                    out.push(b);
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    out.push(b);
                }
                _ => out.push(b),
            }
        }
        Ok(PdfObject::String(out))
    }

    fn parse_hex_string(&mut self) -> Result<PdfObject, PdfParseError> {
        self.pos += 1; // skip '<'
        let mut out = Vec::new();
        loop {
            self.skip_whitespace_and_comments();
            match self.peek() {
                None => return Err(PdfParseError::UnclosedString),
                Some(b'>') => {
                    self.pos += 1;
                    break;
                }
                Some(hi_byte) => {
                    self.pos += 1;
                    let hi = hex_nibble(hi_byte)
                        .ok_or(PdfParseError::InvalidHexNibble(hi_byte))?;
                    self.skip_whitespace_and_comments();
                    let lo = match self.peek() {
                        Some(b'>') | None => 0,
                        Some(lo_byte) => {
                            self.pos += 1;
                            hex_nibble(lo_byte)
                                .ok_or(PdfParseError::InvalidHexNibble(lo_byte))?
                        }
                    };
                    out.push((hi << 4) | lo);
                }
            }
        }
        Ok(PdfObject::String(out))
    }

    fn parse_array(&mut self) -> Result<PdfObject, PdfParseError> {
        self.pos += 1; // skip '['
        let mut elements = Vec::new();
        loop {
            self.skip_whitespace_and_comments();
            if self.pos >= self.data.len() {
                return Err(PdfParseError::UnclosedArray);
            }
            if self.data[self.pos] == b']' {
                self.pos += 1;
                break;
            }
            elements.push(self.parse_value()?);
        }
        Ok(PdfObject::Array(elements))
    }

    fn parse_dict_or_stream(&mut self) -> Result<PdfObject, PdfParseError> {
        self.pos += 2; // skip '<<'
        let mut dict = PdfDict::new();
        loop {
            self.skip_whitespace_and_comments();
            if self.pos + 1 < self.data.len() && &self.data[self.pos..self.pos + 2] == b">>" {
                self.pos += 2;
                break;
            }
            if self.pos >= self.data.len() {
                return Err(PdfParseError::UnclosedDict);
            }
            // Parse key (must be a name).
            let key_obj = self.parse_value()?;
            let key = match key_obj {
                PdfObject::Name(k) => k,
                _ => continue,
            };
            let value = self.parse_value()?;
            dict.set(key, value);
        }

        // Check for stream keyword.
        self.skip_whitespace_and_comments();
        if self.data.get(self.pos..self.pos + 6) == Some(b"stream") {
            self.pos += 6;
            // Skip newline after "stream".
            if self.data.get(self.pos) == Some(&b'\r') {
                self.pos += 1;
            }
            if self.data.get(self.pos) == Some(&b'\n') {
                self.pos += 1;
            }
            let length = dict.get_int("Length").unwrap_or(0) as usize;
            let end = (self.pos + length).min(self.data.len());
            let data = self.data[self.pos..end].to_vec();
            self.pos = end;
            return Ok(PdfObject::Stream(PdfStream::new(dict, data)));
        }

        Ok(PdfObject::Dictionary(dict))
    }

    fn parse_number_or_ref(&mut self) -> Result<PdfObject, PdfParseError> {
        let start = self.pos;
        // Consume the first number token.
        let is_negative = self.data[self.pos] == b'-';
        let is_positive = self.data[self.pos] == b'+';
        if is_negative || is_positive {
            self.pos += 1;
        }
        let has_dot = self.consume_digits_and_dot();
        if has_dot {
            let s = std::str::from_utf8(&self.data[start..self.pos]).unwrap_or("0");
            let v: f64 = s.parse().unwrap_or(0.0);
            return Ok(PdfObject::Real(v));
        }

        let n1: i64 = std::str::from_utf8(&self.data[start..self.pos])
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);

        // Look ahead for indirect ref: `n gen R`
        let saved = self.pos;
        self.skip_whitespace_and_comments();
        if self.pos < self.data.len() && self.data[self.pos].is_ascii_digit() {
            let gen_start = self.pos;
            self.consume_digits_only();
            let n2: u32 = std::str::from_utf8(&self.data[gen_start..self.pos])
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);
            self.skip_whitespace_and_comments();
            if self.data.get(self.pos) == Some(&b'R') {
                self.pos += 1;
                return Ok(PdfObject::Indirect {
                    obj_num: n1 as u32,
                    generation: n2,
                });
            }
            self.pos = saved;
        } else {
            self.pos = saved;
        }

        Ok(PdfObject::Integer(n1))
    }

    fn consume_digits_and_dot(&mut self) -> bool {
        let mut has_dot = false;
        while self.pos < self.data.len() {
            let b = self.data[self.pos];
            if b.is_ascii_digit() {
                self.pos += 1;
            } else if b == b'.' && !has_dot {
                has_dot = true;
                self.pos += 1;
            } else {
                break;
            }
        }
        has_dot
    }

    fn consume_digits_only(&mut self) {
        while self.pos < self.data.len() && self.data[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
    }
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

const fn is_delimiter(b: u8) -> bool {
    matches!(b, b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%')
}

const fn is_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x00 | 0x0C)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &[u8]) -> PdfObject {
        PdfObjectParser::new(s).parse_value().unwrap()
    }

    #[test]
    fn test_parse_null() {
        assert!(parse(b"null").is_null());
    }

    #[test]
    fn test_parse_bool_true() {
        assert_eq!(parse(b"true"), PdfObject::Boolean(true));
    }

    #[test]
    fn test_parse_bool_false() {
        assert_eq!(parse(b"false"), PdfObject::Boolean(false));
    }

    #[test]
    fn test_parse_integer() {
        assert_eq!(parse(b"42").as_int(), Some(42));
        assert_eq!(parse(b"-7").as_int(), Some(-7));
    }

    #[test]
    fn test_parse_real() {
        let obj = parse(b"3.14");
        if let PdfObject::Real(v) = obj {
            assert!((v - 3.14).abs() < 0.001);
        } else {
            panic!("expected Real");
        }
    }

    #[test]
    fn test_parse_name() {
        let obj = parse(b"/Type");
        assert_eq!(obj.as_name(), Some("Type"));
    }

    #[test]
    fn test_parse_literal_string() {
        let obj = parse(b"(hello world)");
        assert_eq!(obj.as_bytes(), Some(b"hello world".as_slice()));
    }

    #[test]
    fn test_parse_hex_string() {
        let obj = parse(b"<48656c6c6f>");
        assert_eq!(obj.as_bytes(), Some(b"Hello".as_slice()));
    }

    #[test]
    fn test_parse_array() {
        let obj = parse(b"[1 2 3]");
        let arr = obj.as_array().unwrap();
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn test_parse_dict() {
        let obj = parse(b"<</Type /Page /Count 2>>");
        let dict = obj.as_dict().unwrap();
        assert_eq!(dict.get_name("Type"), Some("Page"));
        assert_eq!(dict.get_int("Count"), Some(2));
    }

    #[test]
    fn test_parse_indirect_ref() {
        let obj = parse(b"1 0 R");
        if let PdfObject::Indirect { obj_num, generation } = obj {
            assert_eq!(obj_num, 1);
            assert_eq!(generation, 0);
        } else {
            panic!("expected Indirect");
        }
    }

    #[test]
    fn test_parse_stream() {
        let data = b"<</Length 5>>\nstream\nhello\nendstream";
        let mut p = PdfObjectParser::new(data);
        let obj = p.parse_value().unwrap();
        if let PdfObject::Stream(s) = obj {
            assert_eq!(s.data, b"hello");
        } else {
            panic!("expected Stream");
        }
    }

    #[test]
    fn test_pdf_dict_methods() {
        let mut d = PdfDict::new();
        d.set("Foo", PdfObject::Integer(99));
        assert!(d.contains_key("Foo"));
        assert_eq!(d.get_int("Foo"), Some(99));
        assert_eq!(d.len(), 1);
    }
}

impl PartialEq for PdfObject {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::Boolean(a), Self::Boolean(b)) => a == b,
            (Self::Integer(a), Self::Integer(b)) => a == b,
            (Self::Name(a), Self::Name(b)) => a == b,
            (Self::String(a), Self::String(b)) => a == b,
            (
                Self::Indirect { obj_num: o1, generation: g1 },
                Self::Indirect { obj_num: o2, generation: g2 },
            ) => o1 == o2 && g1 == g2,
            _ => false,
        }
    }
}
