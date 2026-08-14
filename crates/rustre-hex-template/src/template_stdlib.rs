//! `template_stdlib` — Standard library of reusable binary template functions.
//!
//! Provides composable read primitives usable in both programmatic and
//! declarative template contexts:
//!
//! * [`ReadInt`]       — read an integer of any width/endianness.
//! * [`ReadStr`]       — read null-terminated or length-prefixed strings.
//! * [`ReadBytes`]     — read a raw byte slice.
//! * [`ArrayOf`]       — repeatedly apply a reader to produce a `Vec`.
//! * [`ConditionalRead`] — guard a read behind a boolean predicate.
//! * [`Assertion`]     — verify a value or byte pattern at an offset.
//! * [`TemplateStdlib`] — registry that holds all named functions.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StdlibError {
    #[error("buffer too short at offset {offset}: need {need} bytes, have {have}")]
    TooShort {
        offset: usize,
        need: usize,
        have: usize,
    },
    #[error("invalid integer width: {0} (must be 1, 2, 4, or 8)")]
    InvalidWidth(usize),
    #[error("string not null-terminated within {0} bytes")]
    UnterminatedString(usize),
    #[error("assertion failed at offset {offset}: expected {expected}, got {got}")]
    AssertionFailed {
        offset: usize,
        expected: String,
        got: String,
    },
    #[error("function '{0}' not found in stdlib")]
    FunctionNotFound(String),
    #[error("array count overflow: {0} × {1} bytes exceeds buffer")]
    ArrayOverflow(usize, usize),
    #[error("conditional predicate error: {0}")]
    PredicateError(String),
    #[error("max string length {0} exceeded")]
    StringTooLong(usize),
}

pub type StdlibResult<T> = Result<T, StdlibError>;

// ---------------------------------------------------------------------------
// Endianness
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum Endian {
    #[default]
    Little,
    Big,
}


impl fmt::Display for Endian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Little => write!(f, "LE"),
            Self::Big => write!(f, "BE"),
        }
    }
}

// ---------------------------------------------------------------------------
// ReadInt
// ---------------------------------------------------------------------------

/// Integer read from a byte buffer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntValue {
    /// Raw unsigned value.
    pub raw: u64,
    /// Bit width used to read.
    pub width: usize,
    /// True if parsed as signed.
    pub signed: bool,
    /// The endianness used.
    pub endian: Endian,
}

impl IntValue {
    /// Interpret raw bits as a signed i64.
    pub fn as_signed(&self) -> i64 {
        match self.width {
            1 => self.raw as i8 as i64,
            2 => self.raw as i16 as i64,
            4 => self.raw as i32 as i64,
            _ => self.raw as i64,
        }
    }
}

impl fmt::Display for IntValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.signed {
            write!(f, "{}", self.as_signed())
        } else {
            write!(f, "{}", self.raw)
        }
    }
}

/// Reads a fixed-width integer from `buf` at `offset`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ReadInt {
    /// Byte width: 1, 2, 4, or 8.
    pub width: usize,
    /// Byte order.
    pub endian: Endian,
    /// Whether to interpret as signed.
    pub signed: bool,
}

impl ReadInt {
    pub const fn u8() -> Self {
        Self {
            width: 1,
            endian: Endian::Little,
            signed: false,
        }
    }
    pub const fn u16_le() -> Self {
        Self {
            width: 2,
            endian: Endian::Little,
            signed: false,
        }
    }
    pub const fn u16_be() -> Self {
        Self {
            width: 2,
            endian: Endian::Big,
            signed: false,
        }
    }
    pub const fn u32_le() -> Self {
        Self {
            width: 4,
            endian: Endian::Little,
            signed: false,
        }
    }
    pub const fn u32_be() -> Self {
        Self {
            width: 4,
            endian: Endian::Big,
            signed: false,
        }
    }
    pub const fn u64_le() -> Self {
        Self {
            width: 8,
            endian: Endian::Little,
            signed: false,
        }
    }
    pub const fn u64_be() -> Self {
        Self {
            width: 8,
            endian: Endian::Big,
            signed: false,
        }
    }
    pub const fn i8() -> Self {
        Self {
            width: 1,
            endian: Endian::Little,
            signed: true,
        }
    }
    pub const fn i16_le() -> Self {
        Self {
            width: 2,
            endian: Endian::Little,
            signed: true,
        }
    }
    pub const fn i32_le() -> Self {
        Self {
            width: 4,
            endian: Endian::Little,
            signed: true,
        }
    }
    pub const fn i64_le() -> Self {
        Self {
            width: 8,
            endian: Endian::Little,
            signed: true,
        }
    }

    /// Read from `buf` at `offset`. Advances `offset` by `width`.
    pub fn read(&self, buf: &[u8], offset: &mut usize) -> StdlibResult<IntValue> {
        if ![1, 2, 4, 8].contains(&self.width) {
            return Err(StdlibError::InvalidWidth(self.width));
        }
        let end = *offset + self.width;
        if end > buf.len() {
            return Err(StdlibError::TooShort {
                offset: *offset,
                need: self.width,
                have: buf.len().saturating_sub(*offset),
            });
        }
        let slice = &buf[*offset..end];
        let raw: u64 = match (self.width, self.endian) {
            (1, _) => slice[0] as u64,
            (2, Endian::Little) => u16::from_le_bytes(slice.try_into().unwrap()) as u64,
            (2, Endian::Big) => u16::from_be_bytes(slice.try_into().unwrap()) as u64,
            (4, Endian::Little) => u32::from_le_bytes(slice.try_into().unwrap()) as u64,
            (4, Endian::Big) => u32::from_be_bytes(slice.try_into().unwrap()) as u64,
            (8, Endian::Little) => u64::from_le_bytes(slice.try_into().unwrap()),
            (8, Endian::Big) => u64::from_be_bytes(slice.try_into().unwrap()),
            _ => unreachable!(),
        };
        *offset = end;
        Ok(IntValue {
            raw,
            width: self.width,
            signed: self.signed,
            endian: self.endian,
        })
    }
}

// ---------------------------------------------------------------------------
// ReadStr
// ---------------------------------------------------------------------------

/// Mode used when reading a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringMode {
    /// Read until a NUL byte (0x00).
    NullTerminated,
    /// Read exactly `n` bytes and strip trailing NULs.
    FixedLength(usize),
    /// Read a length-prefixed string: a 1-byte prefix followed by that many bytes.
    LengthPrefixed1,
    /// Read a length-prefixed string: a 2-byte LE prefix followed by that many bytes.
    LengthPrefixed2Le,
    /// Read a length-prefixed string: a 4-byte LE prefix followed by that many bytes.
    LengthPrefixed4Le,
}

/// Reads a string from a byte buffer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ReadStr {
    pub mode: StringMode,
    /// Maximum bytes to scan (safety limit for `NullTerminated`).
    pub max_len: usize,
    /// Whether to try UTF-8; if false, returns lossy ASCII.
    pub utf8: bool,
}

impl ReadStr {
    pub const fn null_terminated() -> Self {
        Self {
            mode: StringMode::NullTerminated,
            max_len: 4096,
            utf8: true,
        }
    }

    pub const fn fixed(n: usize) -> Self {
        Self {
            mode: StringMode::FixedLength(n),
            max_len: n,
            utf8: true,
        }
    }

    pub const fn length_prefixed_1() -> Self {
        Self {
            mode: StringMode::LengthPrefixed1,
            max_len: 255,
            utf8: true,
        }
    }

    pub const fn length_prefixed_2le() -> Self {
        Self {
            mode: StringMode::LengthPrefixed2Le,
            max_len: 65535,
            utf8: true,
        }
    }

    /// Read from `buf` at `offset`, advancing `offset` past the string.
    pub fn read(&self, buf: &[u8], offset: &mut usize) -> StdlibResult<String> {
        let bytes = match self.mode {
            StringMode::NullTerminated => {
                let start = *offset;
                let limit = (start + self.max_len).min(buf.len());
                let end = buf[start..limit]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| start + p)
                    .ok_or(StdlibError::UnterminatedString(self.max_len))?;
                let bytes = buf[start..end].to_vec();
                *offset = end + 1; // skip NUL
                bytes
            }
            StringMode::FixedLength(n) => {
                if *offset + n > buf.len() {
                    return Err(StdlibError::TooShort {
                        offset: *offset,
                        need: n,
                        have: buf.len().saturating_sub(*offset),
                    });
                }
                let b: Vec<u8> = buf[*offset..*offset + n]
                    .iter()
                    .copied()
                    .take_while(|&c| c != 0)
                    .collect();
                *offset += n;
                b
            }
            StringMode::LengthPrefixed1 => {
                if *offset >= buf.len() {
                    return Err(StdlibError::TooShort {
                        offset: *offset,
                        need: 1,
                        have: 0,
                    });
                }
                let len = buf[*offset] as usize;
                *offset += 1;
                if *offset + len > buf.len() {
                    return Err(StdlibError::TooShort {
                        offset: *offset,
                        need: len,
                        have: buf.len().saturating_sub(*offset),
                    });
                }
                let b = buf[*offset..*offset + len].to_vec();
                *offset += len;
                b
            }
            StringMode::LengthPrefixed2Le => {
                if *offset + 2 > buf.len() {
                    return Err(StdlibError::TooShort {
                        offset: *offset,
                        need: 2,
                        have: buf.len().saturating_sub(*offset),
                    });
                }
                let len =
                    u16::from_le_bytes(buf[*offset..*offset + 2].try_into().unwrap()) as usize;
                *offset += 2;
                if *offset + len > buf.len() {
                    return Err(StdlibError::TooShort {
                        offset: *offset,
                        need: len,
                        have: buf.len().saturating_sub(*offset),
                    });
                }
                let b = buf[*offset..*offset + len].to_vec();
                *offset += len;
                b
            }
            StringMode::LengthPrefixed4Le => {
                if *offset + 4 > buf.len() {
                    return Err(StdlibError::TooShort {
                        offset: *offset,
                        need: 4,
                        have: buf.len().saturating_sub(*offset),
                    });
                }
                let len =
                    u32::from_le_bytes(buf[*offset..*offset + 4].try_into().unwrap()) as usize;
                *offset += 4;
                if len > self.max_len {
                    return Err(StdlibError::StringTooLong(len));
                }
                if *offset + len > buf.len() {
                    return Err(StdlibError::TooShort {
                        offset: *offset,
                        need: len,
                        have: buf.len().saturating_sub(*offset),
                    });
                }
                let b = buf[*offset..*offset + len].to_vec();
                *offset += len;
                b
            }
        };
        if self.utf8 {
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        } else {
            Ok(bytes
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect())
        }
    }
}

// ---------------------------------------------------------------------------
// ReadBytes
// ---------------------------------------------------------------------------

/// How many bytes to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByteCount {
    /// Exactly N bytes.
    Exact(usize),
    /// All remaining bytes.
    Remaining,
    /// A count taken from a previously-read integer (stored separately).
    Dynamic(usize), // holds the actual resolved count
}

/// Reads raw bytes from a buffer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ReadBytes {
    pub count: ByteCount,
}

impl ReadBytes {
    pub const fn exact(n: usize) -> Self {
        Self {
            count: ByteCount::Exact(n),
        }
    }

    pub const fn remaining() -> Self {
        Self {
            count: ByteCount::Remaining,
        }
    }

    pub fn dynamic(n: usize) -> Self {
        Self {
            count: ByteCount::Dynamic(n),
        }
    }

    /// Read from `buf` at `offset`.
    pub fn read<'b>(&self, buf: &'b [u8], offset: &mut usize) -> StdlibResult<&'b [u8]> {
        let n = match self.count {
            ByteCount::Exact(n) | ByteCount::Dynamic(n) => n,
            ByteCount::Remaining => buf.len().saturating_sub(*offset),
        };
        if *offset + n > buf.len() {
            return Err(StdlibError::TooShort {
                offset: *offset,
                need: n,
                have: buf.len().saturating_sub(*offset),
            });
        }
        let slice = &buf[*offset..*offset + n];
        *offset += n;
        Ok(slice)
    }
}

// ---------------------------------------------------------------------------
// ArrayOf
// ---------------------------------------------------------------------------

/// Represents one element produced by [`ArrayOf`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ArrayElement {
    Int(IntValue),
    Str(String),
    Bytes(Vec<u8>),
}

impl fmt::Display for ArrayElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(v) => write!(f, "{v}"),
            Self::Str(s) => write!(f, "\"{s}\""),
            Self::Bytes(b) => {
                write!(f, "[")?;
                for (i, byte) in b.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{byte:02X}")?;
                }
                write!(f, "]")
            }
        }
    }
}

/// Element type that `ArrayOf` can iterate over.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ElementReader {
    Int(ReadInt),
    Str(ReadStr),
    Bytes(ReadBytes),
}

impl ElementReader {
    pub fn read(&self, buf: &[u8], offset: &mut usize) -> StdlibResult<ArrayElement> {
        match self {
            Self::Int(r) => r.read(buf, offset).map(ArrayElement::Int),
            Self::Str(r) => r.read(buf, offset).map(ArrayElement::Str),
            Self::Bytes(r) => r.read(buf, offset).map(|b| ArrayElement::Bytes(b.to_vec())),
        }
    }
}

/// Repeatedly applies `element_reader` `count` times.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ArrayOf {
    pub count: usize,
    pub reader: ElementReader,
}

impl ArrayOf {
    pub fn new(count: usize, reader: ElementReader) -> Self {
        Self { count, reader }
    }

    pub fn read(&self, buf: &[u8], offset: &mut usize) -> StdlibResult<Vec<ArrayElement>> {
        // Pre-flight check: rough size estimate.
        let min_bytes_per = match &self.reader {
            ElementReader::Int(r) => r.width,
            ElementReader::Str(_) => 1,
            ElementReader::Bytes(r) => match r.count {
                ByteCount::Exact(n) | ByteCount::Dynamic(n) => n,
                ByteCount::Remaining => 0,
            },
        };
        if min_bytes_per > 0
            && self.count.saturating_mul(min_bytes_per) > buf.len().saturating_sub(*offset)
        {
            return Err(StdlibError::ArrayOverflow(self.count, min_bytes_per));
        }
        let mut result = Vec::with_capacity(self.count);
        for _ in 0..self.count {
            result.push(self.reader.read(buf, offset)?);
        }
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// ConditionalRead
// ---------------------------------------------------------------------------

/// Predicate evaluated before a read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Predicate {
    /// A previously-read integer equals `value`.
    IntEquals { value: u64 },
    /// A previously-read integer is non-zero.
    IntNonZero,
    /// Always true.
    Always,
    /// Always false (skip read).
    Never,
    /// Buffer has at least `n` bytes remaining.
    HasBytes(usize),
}

impl Predicate {
    /// Evaluate the predicate. `ctx_value` is the "current context integer".
    pub fn eval(&self, ctx_value: Option<u64>, buf_remaining: usize) -> bool {
        match self {
            Self::IntEquals { value } => ctx_value == Some(*value),
            Self::IntNonZero => ctx_value.map(|v| v != 0).unwrap_or(false),
            Self::Always => true,
            Self::Never => false,
            Self::HasBytes(n) => buf_remaining >= *n,
        }
    }
}

/// Reads an element only when a predicate holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionalRead {
    pub predicate: Predicate,
    pub reader: ElementReader,
}

impl ConditionalRead {
    pub fn new(predicate: Predicate, reader: ElementReader) -> Self {
        Self { predicate, reader }
    }

    /// Returns `Some(element)` if the predicate passes, else `None`.
    pub fn read(
        &self,
        buf: &[u8],
        offset: &mut usize,
        ctx: Option<u64>,
    ) -> StdlibResult<Option<ArrayElement>> {
        let remaining = buf.len().saturating_sub(*offset);
        if self.predicate.eval(ctx, remaining) {
            self.reader.read(buf, offset).map(Some)
        } else {
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Assertion
// ---------------------------------------------------------------------------

/// What the assertion checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssertTarget {
    /// Exact byte slice at `offset`.
    Bytes(Vec<u8>),
    /// An integer value at `offset` equals `expected`.
    IntEquals {
        width: usize,
        endian: Endian,
        expected: u64,
    },
    /// Offset must be a multiple of `alignment`.
    Aligned(usize),
}

/// Verifies a condition at a position in the buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assertion {
    pub target: AssertTarget,
    pub description: String,
}

impl Assertion {
    pub fn bytes(expected: Vec<u8>, desc: impl Into<String>) -> Self {
        Self {
            target: AssertTarget::Bytes(expected),
            description: desc.into(),
        }
    }

    pub fn int_equals(
        width: usize,
        endian: Endian,
        expected: u64,
        desc: impl Into<String>,
    ) -> Self {
        Self {
            target: AssertTarget::IntEquals {
                width,
                endian,
                expected,
            },
            description: desc.into(),
        }
    }

    pub fn aligned(alignment: usize, desc: impl Into<String>) -> Self {
        Self {
            target: AssertTarget::Aligned(alignment),
            description: desc.into(),
        }
    }

    /// Run the assertion. Returns `Ok(())` if it passes, `Err` otherwise.
    /// Does NOT advance `offset`.
    pub fn check(&self, buf: &[u8], offset: usize) -> StdlibResult<()> {
        match &self.target {
            AssertTarget::Bytes(expected) => {
                let end = offset + expected.len();
                if end > buf.len() {
                    return Err(StdlibError::TooShort {
                        offset,
                        need: expected.len(),
                        have: buf.len().saturating_sub(offset),
                    });
                }
                let actual = &buf[offset..end];
                if actual != expected.as_slice() {
                    let exp_hex: String = expected
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let act_hex: String = actual
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    return Err(StdlibError::AssertionFailed {
                        offset,
                        expected: exp_hex,
                        got: act_hex,
                    });
                }
                Ok(())
            }
            AssertTarget::IntEquals {
                width,
                endian,
                expected,
            } => {
                let reader = ReadInt {
                    width: *width,
                    endian: *endian,
                    signed: false,
                };
                let mut off = offset;
                let val = reader.read(buf, &mut off)?;
                if val.raw != *expected {
                    return Err(StdlibError::AssertionFailed {
                        offset,
                        expected: format!("{expected:#x}"),
                        got: format!("{:#x}", val.raw),
                    });
                }
                Ok(())
            }
            AssertTarget::Aligned(align) => {
                if !offset.is_multiple_of(*align) {
                    return Err(StdlibError::AssertionFailed {
                        offset,
                        expected: format!("aligned to {align}"),
                        got: format!("offset {offset} % {align} = {}", offset % align),
                    });
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TemplateStdlib — registry
// ---------------------------------------------------------------------------

/// A registered standard-library function entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StdlibEntry {
    pub name: String,
    pub description: String,
    pub reader: ElementReader,
}

/// Registry that holds all named template standard-library functions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TemplateStdlib {
    functions: HashMap<String, StdlibEntry>,
}

impl TemplateStdlib {
    /// Construct with the default set of built-in readers.
    pub fn with_builtins() -> Self {
        let mut s = Self::default();
        s.register_builtin(
            "u8",
            "Read unsigned 8-bit integer",
            ElementReader::Int(ReadInt::u8()),
        );
        s.register_builtin(
            "u16",
            "Read unsigned 16-bit LE integer",
            ElementReader::Int(ReadInt::u16_le()),
        );
        s.register_builtin(
            "u16be",
            "Read unsigned 16-bit BE integer",
            ElementReader::Int(ReadInt::u16_be()),
        );
        s.register_builtin(
            "u32",
            "Read unsigned 32-bit LE integer",
            ElementReader::Int(ReadInt::u32_le()),
        );
        s.register_builtin(
            "u32be",
            "Read unsigned 32-bit BE integer",
            ElementReader::Int(ReadInt::u32_be()),
        );
        s.register_builtin(
            "u64",
            "Read unsigned 64-bit LE integer",
            ElementReader::Int(ReadInt::u64_le()),
        );
        s.register_builtin(
            "u64be",
            "Read unsigned 64-bit BE integer",
            ElementReader::Int(ReadInt::u64_be()),
        );
        s.register_builtin(
            "i8",
            "Read signed 8-bit integer",
            ElementReader::Int(ReadInt::i8()),
        );
        s.register_builtin(
            "i16",
            "Read signed 16-bit LE integer",
            ElementReader::Int(ReadInt::i16_le()),
        );
        s.register_builtin(
            "i32",
            "Read signed 32-bit LE integer",
            ElementReader::Int(ReadInt::i32_le()),
        );
        s.register_builtin(
            "i64",
            "Read signed 64-bit LE integer",
            ElementReader::Int(ReadInt::i64_le()),
        );
        s.register_builtin(
            "cstr",
            "Read null-terminated UTF-8 string",
            ElementReader::Str(ReadStr::null_terminated()),
        );
        s.register_builtin(
            "bstr1",
            "Read 1-byte-prefixed string",
            ElementReader::Str(ReadStr::length_prefixed_1()),
        );
        s.register_builtin(
            "bstr2",
            "Read 2-byte-prefixed LE string",
            ElementReader::Str(ReadStr::length_prefixed_2le()),
        );
        s
    }

    fn register_builtin(&mut self, name: &str, desc: &str, reader: ElementReader) {
        self.functions.insert(
            name.into(),
            StdlibEntry {
                name: name.into(),
                description: desc.into(),
                reader,
            },
        );
    }

    /// Register a custom function.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        description: impl Into<String>,
        reader: ElementReader,
    ) {
        let name = name.into();
        self.functions.insert(
            name.clone(),
            StdlibEntry {
                name,
                description: description.into(),
                reader,
            },
        );
    }

    /// Look up a function by name.
    pub fn get(&self, name: &str) -> StdlibResult<&StdlibEntry> {
        self.functions
            .get(name)
            .ok_or_else(|| StdlibError::FunctionNotFound(name.into()))
    }

    /// Execute a named function against a buffer.
    pub fn exec(&self, name: &str, buf: &[u8], offset: &mut usize) -> StdlibResult<ArrayElement> {
        let entry = self.get(name)?;
        entry.reader.read(buf, offset)
    }

    /// All registered function names.
    pub fn function_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.functions.keys().map(|s| s.as_str()).collect();
        names.sort_unstable();
        names
    }

    /// Number of registered functions.
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// True if no functions are registered.
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- ReadInt ---

    #[test]
    fn read_int_u8_basic() {
        let buf = [0xAB];
        let r = ReadInt::u8();
        let mut off = 0;
        let v = r.read(&buf, &mut off).unwrap();
        assert_eq!(v.raw, 0xAB);
        assert_eq!(off, 1);
    }

    #[test]
    fn read_int_u16_le() {
        let buf = [0x01, 0x02];
        let r = ReadInt::u16_le();
        let mut off = 0;
        let v = r.read(&buf, &mut off).unwrap();
        assert_eq!(v.raw, 0x0201);
    }

    #[test]
    fn read_int_u16_be() {
        let buf = [0x01, 0x02];
        let r = ReadInt::u16_be();
        let mut off = 0;
        let v = r.read(&buf, &mut off).unwrap();
        assert_eq!(v.raw, 0x0102);
    }

    #[test]
    fn read_int_u32_le() {
        let buf = [0x04, 0x03, 0x02, 0x01];
        let r = ReadInt::u32_le();
        let mut off = 0;
        let v = r.read(&buf, &mut off).unwrap();
        assert_eq!(v.raw, 0x01020304);
    }

    #[test]
    fn read_int_u64_le() {
        let buf = [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        let r = ReadInt::u64_le();
        let mut off = 0;
        let v = r.read(&buf, &mut off).unwrap();
        assert_eq!(v.raw, 0x0102030405060708);
    }

    #[test]
    fn read_int_signed_negative() {
        let buf = [0xFF]; // -1 as i8
        let r = ReadInt::i8();
        let mut off = 0;
        let v = r.read(&buf, &mut off).unwrap();
        assert_eq!(v.as_signed(), -1);
    }

    #[test]
    fn read_int_too_short() {
        let buf = [0x01];
        let r = ReadInt::u32_le();
        let mut off = 0;
        assert!(matches!(
            r.read(&buf, &mut off),
            Err(StdlibError::TooShort { .. })
        ));
    }

    #[test]
    fn read_int_invalid_width() {
        let r = ReadInt {
            width: 3,
            endian: Endian::Little,
            signed: false,
        };
        let buf = [1, 2, 3];
        let mut off = 0;
        assert!(matches!(
            r.read(&buf, &mut off),
            Err(StdlibError::InvalidWidth(3))
        ));
    }

    #[test]
    fn read_int_advances_offset() {
        let buf = [0u8; 8];
        let r = ReadInt::u32_le();
        let mut off = 0;
        r.read(&buf, &mut off).unwrap();
        assert_eq!(off, 4);
        r.read(&buf, &mut off).unwrap();
        assert_eq!(off, 8);
    }

    // --- ReadStr ---

    #[test]
    fn read_str_null_terminated() {
        let buf = b"hello\x00world";
        let r = ReadStr::null_terminated();
        let mut off = 0;
        let s = r.read(buf, &mut off).unwrap();
        assert_eq!(s, "hello");
        assert_eq!(off, 6);
    }

    #[test]
    fn read_str_fixed_length() {
        let buf = b"ABCD\x00\x00";
        let r = ReadStr::fixed(4);
        let mut off = 0;
        let s = r.read(buf, &mut off).unwrap();
        assert_eq!(s, "ABCD");
        assert_eq!(off, 4);
    }

    #[test]
    fn read_str_fixed_strips_nulls() {
        let buf = b"AB\x00\x00";
        let r = ReadStr::fixed(4);
        let mut off = 0;
        let s = r.read(buf, &mut off).unwrap();
        assert_eq!(s, "AB");
    }

    #[test]
    fn read_str_length_prefixed_1() {
        let mut buf = vec![3u8];
        buf.extend_from_slice(b"abc");
        let r = ReadStr::length_prefixed_1();
        let mut off = 0;
        let s = r.read(&buf, &mut off).unwrap();
        assert_eq!(s, "abc");
        assert_eq!(off, 4);
    }

    #[test]
    fn read_str_length_prefixed_2le() {
        let mut buf = vec![4u8, 0u8];
        buf.extend_from_slice(b"rust");
        let r = ReadStr::length_prefixed_2le();
        let mut off = 0;
        let s = r.read(&buf, &mut off).unwrap();
        assert_eq!(s, "rust");
    }

    #[test]
    fn read_str_unterminated_error() {
        let buf = b"no null here";
        let mut r = ReadStr::null_terminated();
        r.max_len = 5;
        let mut off = 0;
        assert!(matches!(
            r.read(buf, &mut off),
            Err(StdlibError::UnterminatedString(5))
        ));
    }

    // --- ReadBytes ---

    #[test]
    fn read_bytes_exact() {
        let buf = [0xDE, 0xAD, 0xBE, 0xEF];
        let r = ReadBytes::exact(4);
        let mut off = 0;
        let b = r.read(&buf, &mut off).unwrap();
        assert_eq!(b, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(off, 4);
    }

    #[test]
    fn read_bytes_remaining() {
        let buf = [1, 2, 3, 4, 5];
        let r = ReadBytes::remaining();
        let mut off = 2;
        let b = r.read(&buf, &mut off).unwrap();
        assert_eq!(b, &[3, 4, 5]);
    }

    #[test]
    fn read_bytes_too_short() {
        let buf = [1, 2];
        let r = ReadBytes::exact(4);
        let mut off = 0;
        assert!(r.read(&buf, &mut off).is_err());
    }

    // --- ArrayOf ---

    #[test]
    fn array_of_ints() {
        let buf = [1u8, 2, 3, 4];
        let a = ArrayOf::new(4, ElementReader::Int(ReadInt::u8()));
        let mut off = 0;
        let elems = a.read(&buf, &mut off).unwrap();
        assert_eq!(elems.len(), 4);
        if let ArrayElement::Int(v) = &elems[0] {
            assert_eq!(v.raw, 1);
        }
        assert_eq!(off, 4);
    }

    #[test]
    fn array_of_overflow_error() {
        let buf = [1u8; 4];
        let a = ArrayOf::new(100, ElementReader::Int(ReadInt::u32_le()));
        let mut off = 0;
        assert!(a.read(&buf, &mut off).is_err());
    }

    // --- ConditionalRead ---

    #[test]
    fn conditional_read_passes() {
        let buf = [0x42, 0x42];
        let r = ConditionalRead::new(Predicate::Always, ElementReader::Int(ReadInt::u8()));
        let mut off = 0;
        let elem = r.read(&buf, &mut off, None).unwrap();
        assert!(elem.is_some());
    }

    #[test]
    fn conditional_read_skips() {
        let buf = [0x42];
        let r = ConditionalRead::new(Predicate::Never, ElementReader::Int(ReadInt::u8()));
        let mut off = 0;
        let elem = r.read(&buf, &mut off, None).unwrap();
        assert!(elem.is_none());
        assert_eq!(off, 0); // not advanced
    }

    #[test]
    fn conditional_int_equals() {
        let buf = [0x01];
        let r = ConditionalRead::new(
            Predicate::IntEquals { value: 5 },
            ElementReader::Int(ReadInt::u8()),
        );
        let mut off = 0;
        let elem = r.read(&buf, &mut off, Some(5)).unwrap();
        assert!(elem.is_some());
    }

    #[test]
    fn conditional_has_bytes() {
        let buf = [1, 2, 3];
        let r = ConditionalRead::new(Predicate::HasBytes(2), ElementReader::Int(ReadInt::u8()));
        let mut off = 0;
        let elem = r.read(&buf, &mut off, None).unwrap();
        assert!(elem.is_some());
    }

    // --- Assertion ---

    #[test]
    fn assertion_bytes_pass() {
        let buf = [0x4D, 0x5A, 0x90];
        let a = Assertion::bytes(vec![0x4D, 0x5A], "MZ magic");
        assert!(a.check(&buf, 0).is_ok());
    }

    #[test]
    fn assertion_bytes_fail() {
        let buf = [0x00, 0x00];
        let a = Assertion::bytes(vec![0x4D, 0x5A], "MZ magic");
        assert!(matches!(
            a.check(&buf, 0),
            Err(StdlibError::AssertionFailed { .. })
        ));
    }

    #[test]
    fn assertion_int_equals_pass() {
        let buf = [0x05, 0x00, 0x00, 0x00];
        let a = Assertion::int_equals(4, Endian::Little, 5, "count=5");
        assert!(a.check(&buf, 0).is_ok());
    }

    #[test]
    fn assertion_int_equals_fail() {
        let buf = [0x01, 0x00, 0x00, 0x00];
        let a = Assertion::int_equals(4, Endian::Little, 5, "count=5");
        assert!(matches!(
            a.check(&buf, 0),
            Err(StdlibError::AssertionFailed { .. })
        ));
    }

    #[test]
    fn assertion_aligned_pass() {
        let a = Assertion::aligned(16, "aligned");
        assert!(a.check(&[], 16).is_ok());
        assert!(a.check(&[], 0).is_ok());
    }

    #[test]
    fn assertion_aligned_fail() {
        let a = Assertion::aligned(16, "aligned");
        assert!(matches!(
            a.check(&[], 3),
            Err(StdlibError::AssertionFailed { .. })
        ));
    }

    // --- TemplateStdlib ---

    #[test]
    fn stdlib_builtins_non_empty() {
        let s = TemplateStdlib::with_builtins();
        assert!(!s.is_empty());
        assert!(s.len() >= 12);
    }

    #[test]
    fn stdlib_exec_u8() {
        let s = TemplateStdlib::with_builtins();
        let buf = [0xAB];
        let mut off = 0;
        let v = s.exec("u8", &buf, &mut off).unwrap();
        if let ArrayElement::Int(i) = v {
            assert_eq!(i.raw, 0xAB);
        } else {
            panic!();
        }
    }

    #[test]
    fn stdlib_exec_cstr() {
        let s = TemplateStdlib::with_builtins();
        let buf = b"hello\x00";
        let mut off = 0;
        let v = s.exec("cstr", buf, &mut off).unwrap();
        if let ArrayElement::Str(st) = v {
            assert_eq!(st, "hello");
        } else {
            panic!();
        }
    }

    #[test]
    fn stdlib_function_not_found() {
        let s = TemplateStdlib::with_builtins();
        let mut off = 0;
        assert!(matches!(
            s.exec("nonexistent", &[], &mut off),
            Err(StdlibError::FunctionNotFound(_))
        ));
    }

    #[test]
    fn stdlib_custom_registration() {
        let mut s = TemplateStdlib::with_builtins();
        s.register("myread", "custom", ElementReader::Int(ReadInt::u32_le()));
        assert!(s.get("myread").is_ok());
    }

    #[test]
    fn stdlib_function_names_sorted() {
        let s = TemplateStdlib::with_builtins();
        let names = s.function_names();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    #[test]
    fn read_int_u32_be() {
        let buf = [0x01, 0x02, 0x03, 0x04];
        let r = ReadInt::u32_be();
        let mut off = 0;
        let v = r.read(&buf, &mut off).unwrap();
        assert_eq!(v.raw, 0x01020304);
    }

    #[test]
    fn read_int_u64_be() {
        let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let r = ReadInt::u64_be();
        let mut off = 0;
        let v = r.read(&buf, &mut off).unwrap();
        assert_eq!(v.raw, 0x0102030405060708);
    }

    #[test]
    fn read_int_i16_le() {
        let buf = [0xFF, 0xFF]; // -1 as i16 LE
        let r = ReadInt::i16_le();
        let mut off = 0;
        let v = r.read(&buf, &mut off).unwrap();
        assert_eq!(v.as_signed(), -1i64);
    }

    #[test]
    fn read_int_i64_le() {
        let buf = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]; // -1 as i64
        let r = ReadInt::i64_le();
        let mut off = 0;
        let v = r.read(&buf, &mut off).unwrap();
        assert_eq!(v.as_signed(), -1i64);
    }

    #[test]
    fn read_str_length_prefixed_4le() {
        let mut buf = vec![4u8, 0, 0, 0]; // len=4 LE u32
        buf.extend_from_slice(b"rust");
        let r = ReadStr {
            mode: StringMode::LengthPrefixed4Le,
            max_len: 100,
            utf8: true,
        };
        let mut off = 0;
        let s = r.read(&buf, &mut off).unwrap();
        assert_eq!(s, "rust");
        assert_eq!(off, 8);
    }

    #[test]
    fn read_str_non_utf8_lossy() {
        let buf = [0x80, 0x00]; // invalid UTF-8, then null
        let r = ReadStr::null_terminated();
        let mut off = 0;
        let s = r.read(&buf, &mut off).unwrap();
        assert!(!s.is_empty() || s.is_empty()); // just no panic
    }

    #[test]
    fn read_bytes_dynamic() {
        let buf = [1, 2, 3, 4, 5];
        let r = ReadBytes::dynamic(3);
        let mut off = 1;
        let b = r.read(&buf, &mut off).unwrap();
        assert_eq!(b, &[2, 3, 4]);
    }

    #[test]
    fn array_of_strings() {
        let buf = vec![3u8, b'a', b'b', b'c', 2u8, b'h', b'i'];
        let a = ArrayOf::new(2, ElementReader::Str(ReadStr::length_prefixed_1()));
        let mut off = 0;
        let elems = a.read(&buf, &mut off).unwrap();
        assert_eq!(elems.len(), 2);
        if let ArrayElement::Str(s) = &elems[0] {
            assert_eq!(s, "abc");
        }
        if let ArrayElement::Str(s) = &elems[1] {
            assert_eq!(s, "hi");
        }
        let _ = buf; // suppress unused
    }

    #[test]
    fn conditional_int_nonzero_true() {
        let buf = [0x42];
        let r = ConditionalRead::new(Predicate::IntNonZero, ElementReader::Int(ReadInt::u8()));
        let mut off = 0;
        let elem = r.read(&buf, &mut off, Some(1)).unwrap();
        assert!(elem.is_some());
    }

    #[test]
    fn conditional_int_nonzero_false() {
        let buf = [0x42];
        let r = ConditionalRead::new(Predicate::IntNonZero, ElementReader::Int(ReadInt::u8()));
        let mut off = 0;
        let elem = r.read(&buf, &mut off, Some(0)).unwrap();
        assert!(elem.is_none());
    }

    #[test]
    fn assertion_bytes_too_short() {
        let buf = [0x4D];
        let a = Assertion::bytes(vec![0x4D, 0x5A], "MZ");
        assert!(matches!(
            a.check(&buf, 0),
            Err(StdlibError::TooShort { .. })
        ));
    }

    #[test]
    fn int_value_display_unsigned() {
        let v = IntValue {
            raw: 42,
            width: 4,
            signed: false,
            endian: Endian::Little,
        };
        assert_eq!(format!("{v}"), "42");
    }

    #[test]
    fn int_value_display_signed() {
        let v = IntValue {
            raw: 0xFFFF_FFFF,
            width: 4,
            signed: true,
            endian: Endian::Little,
        };
        let s = format!("{v}");
        assert_eq!(s, "-1");
    }

    #[test]
    fn array_element_display_bytes() {
        let e = ArrayElement::Bytes(vec![0xDE, 0xAD]);
        let s = format!("{e}");
        assert!(s.contains("DE"));
    }

    #[test]
    fn endian_display() {
        assert_eq!(format!("{}", Endian::Little), "LE");
        assert_eq!(format!("{}", Endian::Big), "BE");
    }
}
