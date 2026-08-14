//! STABS type-descriptor parser.
//!
//! Parses the type-descriptor strings embedded in STABS `N_LSYM`, `N_GSYM`, and
//! `N_FUN` entries.  The STABS type language is a compact textual notation
//! used by GCC / classic Unix toolchains.
//!
//! Supported descriptors
//! ─────────────────────
//! - Numeric type references: `(file,id)` and bare integers.
//! - Built-in range / scalar types: `r`, `b` (bool), `w` (wchar_t).
//! - Pointer: `*<type>`.
//! - Array: `a<index_type>;<element_type>`.
//! - Struct / union: `s<size>{<field>…}` / `u<size>{<field>…}`.
//! - Function: `f<return_type>`.
//! - Void: `v`.
//! - Type alias / forward: `=`.
//! - Enumeration: `e{<name>:<value>,…;}`.

use std::collections::HashMap;
use std::fmt;
use std::num::ParseIntError;

// ── TypeId ────────────────────────────────────────────────────────────────────

/// A STABS type identifier: either a simple number or a (file, id) pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeId {
    /// Single numeric id: `42`
    Simple(u32),
    /// Cross-file reference: `(1,5)`
    CrossFile {
        /// File index.
        file: u32,
        /// Type id within the file.
        id: u32,
    },
}

impl fmt::Display for TypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Simple(n) => write!(f, "{n}"),
            Self::CrossFile { file, id } => write!(f, "({file},{id})"),
        }
    }
}

// ── StabsType ─────────────────────────────────────────────────────────────────

/// A parsed STABS type.
#[derive(Debug, Clone)]
pub enum StabsType {
    /// `v` — void / no type.
    Void,
    /// Built-in range type (e.g. `int`, `char`).  The range bounds are in
    /// bytes as they appear in the STABS string.
    Range {
        /// Base type the range refers to.
        type_id: TypeId,
        /// Lower bound.
        lo: i64,
        /// Upper bound.
        hi: i64,
    },
    /// Boolean built-in.
    Bool,
    /// Pointer to another type.
    Pointer(Box<StabsType>),
    /// Array: index range `[lo, hi]` and element type.
    Array {
        /// Lower index bound.
        index_lo: i64,
        /// Upper index bound.
        index_hi: i64,
        /// Element type.
        element: Box<StabsType>,
    },
    /// Struct with named fields.
    Struct {
        /// Total size in bytes.
        size_bytes: u32,
        /// Member fields.
        fields: Vec<StabsField>,
    },
    /// Union with named fields.
    Union {
        /// Total size in bytes.
        size_bytes: u32,
        /// Member fields.
        fields: Vec<StabsField>,
    },
    /// Enumeration.
    Enum {
        /// `(name, value)` enumerator pairs.
        variants: Vec<(String, i64)>,
    },
    /// Function returning `ret`.
    Function(Box<StabsType>),
    /// Forward reference or alias to another type id.
    Alias(TypeId),
    /// Type not recognised by this parser (raw descriptor preserved).
    Unknown(String),
}

impl fmt::Display for StabsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Void => write!(f, "void"),
            Self::Bool => write!(f, "bool"),
            Self::Range { type_id, lo, hi } => {
                write!(f, "range({type_id},{lo},{hi})")
            }
            Self::Pointer(inner) => write!(f, "*{inner}"),
            Self::Array { index_lo, index_hi, element } => {
                write!(f, "[{index_lo}..{index_hi}]{element}")
            }
            Self::Struct { size_bytes, fields } => {
                write!(f, "struct<{size_bytes}>[{}]", fields.len())
            }
            Self::Union { size_bytes, fields } => {
                write!(f, "union<{size_bytes}>[{}]", fields.len())
            }
            Self::Enum { variants } => write!(f, "enum[{}]", variants.len()),
            Self::Function(ret) => write!(f, "fn()->{ret}"),
            Self::Alias(id) => write!(f, "alias({id})"),
            Self::Unknown(s) => write!(f, "?{s}"),
        }
    }
}

// ── StabsField ────────────────────────────────────────────────────────────────

/// A field within a struct or union descriptor.
#[derive(Debug, Clone)]
pub struct StabsField {
    /// Field name.
    pub name: String,
    /// Field type.
    pub ty: StabsType,
    /// Bit offset from the struct start.
    pub bit_offset: u32,
    /// Bit size (0 = not specified / use type size).
    pub bit_size: u32,
}

// ── ParseError ────────────────────────────────────────────────────────────────

/// Errors produced by the STABS type parser.
#[derive(Debug, Clone)]
pub enum ParseError {
    /// The input string was empty.
    EmptyDescriptor,
    /// An integer in the descriptor could not be parsed.
    InvalidInteger(String),
    /// A structural delimiter was expected but not found.
    UnexpectedEnd {
        /// What the parser was expecting.
        expected: &'static str,
    },
    /// An unknown leading byte was encountered.
    UnknownKind(char),
    /// A cross-file reference `(n,m)` was malformed.
    MalformedCrossRef(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDescriptor => write!(f, "empty type descriptor"),
            Self::InvalidInteger(s) => write!(f, "invalid integer: {s}"),
            Self::UnexpectedEnd { expected } => {
                write!(f, "unexpected end of descriptor, expected {expected}")
            }
            Self::UnknownKind(c) => write!(f, "unknown type kind '{c}'"),
            Self::MalformedCrossRef(s) => write!(f, "malformed cross-ref: {s}"),
        }
    }
}

impl From<ParseIntError> for ParseError {
    fn from(e: ParseIntError) -> Self {
        Self::InvalidInteger(e.to_string())
    }
}

// ── Parser internals ──────────────────────────────────────────────────────────

struct Cursor<'a> {
    src: &'a str,
    pos: usize,
    /// Recursive-descent nesting depth, bounded by [`MAX_PARSE_DEPTH`].
    depth: u32,
}

/// Maximum nesting depth accepted by the recursive type parser.
const MAX_PARSE_DEPTH: u32 = 100;

impl<'a> Cursor<'a> {
    fn new(src: &'a str) -> Self {
        Self { src, pos: 0, depth: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    fn advance(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    fn expect_char(&mut self, c: char) -> Result<(), ParseError> {
        match self.advance() {
            Some(got) if got == c => Ok(()),
            _ => Err(ParseError::UnexpectedEnd { expected: "specific char" }),
        }
    }

    fn remaining(&self) -> &str {
        &self.src[self.pos..]
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.src.len()
    }

    /// Consume digits and return the string.
    fn take_digits(&mut self) -> &str {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == '-' {
                self.advance();
            } else {
                break;
            }
        }
        &self.src[start..self.pos]
    }

    /// Consume an i64.
    fn parse_i64(&mut self) -> Result<i64, ParseError> {
        let s = self.take_digits();
        s.parse::<i64>().map_err(|_| ParseError::InvalidInteger(s.to_owned()))
    }

    /// Consume a u32.
    fn parse_u32(&mut self) -> Result<u32, ParseError> {
        let s = self.take_digits();
        s.parse::<u32>().map_err(|_| ParseError::InvalidInteger(s.to_owned()))
    }

    /// Parse a TypeId: either `(n,m)` or a bare integer.
    fn parse_type_id(&mut self) -> Result<TypeId, ParseError> {
        if self.peek() == Some('(') {
            self.advance(); // '('
            let file = self.parse_u32()?;
            self.expect_char(',')?;
            let id = self.parse_u32()?;
            self.expect_char(')')?;
            Ok(TypeId::CrossFile { file, id })
        } else {
            Ok(TypeId::Simple(self.parse_u32()?))
        }
    }

    /// Parse an identifier until a non-identifier character.
    fn parse_ident(&mut self) -> String {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' {
                self.advance();
            } else {
                break;
            }
        }
        self.src[start..self.pos].to_owned()
    }
}

// ── Recursive descent ─────────────────────────────────────────────────────────

fn parse_type(cur: &mut Cursor<'_>) -> Result<StabsType, ParseError> {
    if cur.depth >= MAX_PARSE_DEPTH {
        return Ok(StabsType::Unknown(String::from("depth limit")));
    }
    cur.depth += 1;
    let out = parse_type_inner(cur);
    cur.depth -= 1;
    out
}

fn parse_type_inner(cur: &mut Cursor<'_>) -> Result<StabsType, ParseError> {
    if cur.is_empty() {
        return Err(ParseError::EmptyDescriptor);
    }

    // Skip a leading type-id + '=' alias assignment.
    // e.g. "1=r1;0;127;"
    let saved_pos = cur.pos;
    if cur.peek().map_or(false, |c| c.is_ascii_digit() || c == '(') {
        let _id = cur.parse_type_id()?;
        if cur.peek() == Some('=') {
            cur.advance(); // consume '='
            // Now parse the actual definition.
        } else {
            // Just a bare type reference — treat as alias.
            let id = match cur.src[saved_pos..cur.pos].trim() {
                s if s.starts_with('(') => {
                    let mut c2 = Cursor { src: &cur.src[saved_pos..cur.pos], pos: 0, depth: 0 };
                    c2.parse_type_id()?
                }
                s => TypeId::Simple(s.parse::<u32>().map_err(|_| {
                    ParseError::InvalidInteger(s.to_owned())
                })?),
            };
            return Ok(StabsType::Alias(id));
        }
    }

    let kind = match cur.peek() {
        Some(c) => c,
        None => return Err(ParseError::EmptyDescriptor),
    };

    match kind {
        'v' => {
            cur.advance();
            Ok(StabsType::Void)
        }
        'b' => {
            cur.advance();
            Ok(StabsType::Bool)
        }
        'r' => {
            // range type: r<type_id>;<lo>;<hi>;
            cur.advance();
            let type_id = cur.parse_type_id()?;
            cur.expect_char(';')?;
            let lo = cur.parse_i64()?;
            cur.expect_char(';')?;
            let hi = cur.parse_i64()?;
            // Optional trailing ';'
            if cur.peek() == Some(';') {
                cur.advance();
            }
            Ok(StabsType::Range { type_id, lo, hi })
        }
        '*' => {
            cur.advance();
            let inner = parse_type(cur)?;
            Ok(StabsType::Pointer(Box::new(inner)))
        }
        'a' => {
            // array: a<index_type>;<element_type>
            cur.advance();
            // Index type is typically a range type.
            let _idx_type = parse_type(cur)?;
            // After the index type there is normally a ';' then the element
            // type — but for the canonical GCC form `ar(0,1);0;9;(0,1)` the 'r'
            // arm has already eaten that separator as its own optional trailing
            // ';'. Treat it as optional (as stabs_full_parser does) so real
            // array descriptors parse instead of erroring out.
            if cur.peek() == Some(';') {
                cur.advance();
            }
            let elem = parse_type(cur)?;
            // Best-effort index bounds.
            let (lo, hi) = match &_idx_type {
                StabsType::Range { lo, hi, .. } => (*lo, *hi),
                _ => (0, 0),
            };
            Ok(StabsType::Array {
                index_lo: lo,
                index_hi: hi,
                element: Box::new(elem),
            })
        }
        's' | 'u' => {
            let is_struct = kind == 's';
            cur.advance();
            let size_bytes = cur.parse_u32()?;
            let fields = parse_fields(cur)?;
            if is_struct {
                Ok(StabsType::Struct { size_bytes, fields })
            } else {
                Ok(StabsType::Union { size_bytes, fields })
            }
        }
        'e' => {
            cur.advance();
            let variants = parse_enum_variants(cur)?;
            Ok(StabsType::Enum { variants })
        }
        'f' => {
            cur.advance();
            let ret = parse_type(cur)?;
            Ok(StabsType::Function(Box::new(ret)))
        }
        c => {
            // Consume the rest as unknown.
            cur.advance();
            let rest = format!("{c}{}", cur.remaining());
            cur.pos = cur.src.len();
            Ok(StabsType::Unknown(rest))
        }
    }
}

/// Parse struct/union fields: `name:type,bit_offset,bit_size;` repeated until `;`.
fn parse_fields(cur: &mut Cursor<'_>) -> Result<Vec<StabsField>, ParseError> {
    let mut fields = Vec::new();
    // Fields end at the terminating ';' of the struct.
    while let Some(c) = cur.peek() {
        if c == ';' {
            cur.advance();
            break;
        }
        let name = cur.parse_ident();
        cur.expect_char(':')?;
        let ty = parse_type(cur)?;
        cur.expect_char(',')?;
        let bit_offset = cur.parse_u32()?;
        cur.expect_char(',')?;
        let bit_size = cur.parse_u32()?;
        cur.expect_char(';')?;
        fields.push(StabsField { name, ty, bit_offset, bit_size });
    }
    Ok(fields)
}

/// Parse `name:value,` pairs until `;`.
fn parse_enum_variants(cur: &mut Cursor<'_>) -> Result<Vec<(String, i64)>, ParseError> {
    let mut variants = Vec::new();
    while let Some(c) = cur.peek() {
        if c == ';' {
            cur.advance();
            break;
        }
        let name = cur.parse_ident();
        cur.expect_char(':')?;
        let value = cur.parse_i64()?;
        if cur.peek() == Some(',') {
            cur.advance();
        }
        variants.push((name, value));
    }
    Ok(variants)
}

// ── Public API: parse_type_descriptor ────────────────────────────────────────

/// Parse a STABS type descriptor string and return the corresponding
/// [`StabsType`].
///
/// ```rust
/// use rustre_symbols_stabs::stabs_type_parser::parse_type_descriptor;
/// let ty = parse_type_descriptor("*r1;0;255;").unwrap();
/// println!("{ty}");
/// ```
pub fn parse_type_descriptor(s: &str) -> Result<StabsType, ParseError> {
    if s.is_empty() {
        return Err(ParseError::EmptyDescriptor);
    }
    let mut cur = Cursor::new(s);
    parse_type(&mut cur)
}

// ── StabsTypeParser ───────────────────────────────────────────────────────────

/// Stateful parser that accumulates a type table indexed by [`TypeId`].
///
/// Usage pattern:
/// 1. Feed each STABS string (the part after `name:`) via [`StabsTypeParser::feed`].
/// 2. Query the type table via [`StabsTypeParser::lookup`].
pub struct StabsTypeParser {
    /// Accumulated type table.
    table: HashMap<String, StabsType>,
    /// Count of successfully parsed descriptors.
    parsed_count: usize,
    /// Count of descriptors that failed to parse.
    error_count: usize,
}

impl StabsTypeParser {
    /// Create a new, empty type parser.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
            parsed_count: 0,
            error_count: 0,
        }
    }

    /// Feed a raw STABS symbol value string (the part after the colon in
    /// `name:descriptor`).  The `key` is used to index the result.
    pub fn feed(&mut self, key: impl Into<String>, descriptor: &str) -> Result<(), ParseError> {
        let ty = parse_type_descriptor(descriptor)?;
        self.table.insert(key.into(), ty);
        self.parsed_count += 1;
        Ok(())
    }

    /// Feed a descriptor, silently ignoring parse errors (they are counted).
    pub fn feed_lossy(&mut self, key: impl Into<String>, descriptor: &str) {
        match parse_type_descriptor(descriptor) {
            Ok(ty) => {
                self.table.insert(key.into(), ty);
                self.parsed_count += 1;
            }
            Err(_) => {
                self.error_count += 1;
            }
        }
    }

    /// Look up a type by its string key.
    #[must_use]
    pub fn lookup(&self, key: &str) -> Option<&StabsType> {
        self.table.get(key)
    }

    /// Total types in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Returns `true` when the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Number of successfully parsed descriptors.
    #[must_use]
    pub const fn parsed_count(&self) -> usize {
        self.parsed_count
    }

    /// Number of descriptors that failed to parse.
    #[must_use]
    pub const fn error_count(&self) -> usize {
        self.error_count
    }

    /// Iterator over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &StabsType)> {
        self.table.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Drain all pointer types from the table and return them.
    pub fn drain_pointers(&mut self) -> Vec<(String, StabsType)> {
        let ptrs: Vec<String> = self
            .table
            .iter()
            .filter(|(_, v)| matches!(v, StabsType::Pointer(_)))
            .map(|(k, _)| k.clone())
            .collect();
        ptrs.into_iter()
            .filter_map(|k| self.table.remove(&k).map(|v| (k, v)))
            .collect()
    }
}

impl Default for StabsTypeParser {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_type_descriptor ─────────────────────────────────────────────────

    #[test]
    fn parse_void() {
        let t = parse_type_descriptor("v").unwrap();
        assert!(matches!(t, StabsType::Void));
    }

    #[test]
    fn parse_bool() {
        let t = parse_type_descriptor("b").unwrap();
        assert!(matches!(t, StabsType::Bool));
    }

    #[test]
    fn parse_range() {
        let t = parse_type_descriptor("r1;0;127;").unwrap();
        if let StabsType::Range { lo, hi, .. } = t {
            assert_eq!(lo, 0);
            assert_eq!(hi, 127);
        } else {
            panic!("expected Range, got {t}");
        }
    }

    #[test]
    fn parse_pointer() {
        let t = parse_type_descriptor("*v").unwrap();
        assert!(matches!(t, StabsType::Pointer(_)));
    }

    #[test]
    fn parse_nested_pointer() {
        let t = parse_type_descriptor("**v").unwrap();
        if let StabsType::Pointer(inner) = &t {
            assert!(matches!(**inner, StabsType::Pointer(_)));
        } else {
            panic!("outer not pointer");
        }
    }

    #[test]
    fn parse_function() {
        let t = parse_type_descriptor("fv").unwrap();
        assert!(matches!(t, StabsType::Function(_)));
    }

    #[test]
    fn parse_enum() {
        let t = parse_type_descriptor("eA:0,B:1,C:2;").unwrap();
        if let StabsType::Enum { variants } = t {
            assert_eq!(variants.len(), 3);
            assert_eq!(variants[0], ("A".to_owned(), 0));
            assert_eq!(variants[2], ("C".to_owned(), 2));
        } else {
            panic!("expected Enum");
        }
    }

    #[test]
    fn parse_empty_returns_error() {
        assert!(parse_type_descriptor("").is_err());
    }

    #[test]
    fn parse_alias() {
        // Bare number is an alias.
        let t = parse_type_descriptor("5").unwrap();
        assert!(matches!(t, StabsType::Alias(TypeId::Simple(5))));
    }

    // ── TypeId display ────────────────────────────────────────────────────────

    #[test]
    fn type_id_display_simple() {
        assert_eq!(TypeId::Simple(42).to_string(), "42");
    }

    #[test]
    fn type_id_display_cross() {
        assert_eq!(
            TypeId::CrossFile { file: 1, id: 5 }.to_string(),
            "(1,5)"
        );
    }

    // ── StabsTypeParser ───────────────────────────────────────────────────────

    #[test]
    fn parser_feed_and_lookup() {
        let mut p = StabsTypeParser::new();
        p.feed("int", "r1;0;2147483647;").unwrap();
        assert!(p.lookup("int").is_some());
        assert_eq!(p.parsed_count(), 1);
        assert_eq!(p.error_count(), 0);
    }

    #[test]
    fn parser_feed_lossy_bad() {
        let mut p = StabsTypeParser::new();
        p.feed_lossy("bad", "");
        assert_eq!(p.error_count(), 1);
        assert_eq!(p.parsed_count(), 0);
    }

    #[test]
    fn parser_len() {
        let mut p = StabsTypeParser::new();
        p.feed("a", "v").unwrap();
        p.feed("b", "b").unwrap();
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn parser_drain_pointers() {
        let mut p = StabsTypeParser::new();
        p.feed("ptr", "*v").unwrap();
        p.feed("void", "v").unwrap();
        let ptrs = p.drain_pointers();
        assert_eq!(ptrs.len(), 1);
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn parser_iter() {
        let mut p = StabsTypeParser::new();
        p.feed("x", "v").unwrap();
        p.feed("y", "b").unwrap();
        let count = p.iter().count();
        assert_eq!(count, 2);
    }

    // ── StabsType display ─────────────────────────────────────────────────────

    #[test]
    fn stabs_type_display_void() {
        assert_eq!(StabsType::Void.to_string(), "void");
    }

    #[test]
    fn stabs_type_display_pointer() {
        let t = StabsType::Pointer(Box::new(StabsType::Void));
        assert_eq!(t.to_string(), "*void");
    }

    #[test]
    fn stabs_type_display_range() {
        let t = StabsType::Range {
            type_id: TypeId::Simple(1),
            lo: 0,
            hi: 255,
        };
        assert!(t.to_string().contains("255"));
    }
}
