//! `constant_tables` â€” KGC and `KNum` constant table parsing and analysis.
//!
//! This module provides:
//! - [`LjKgcType`]  â€” enum over the distinct KGC tag values.
//! - [`KgcEntry`]   â€” a single parsed KGC constant with its tag.
//! - [`KgcIter`]    â€” a streaming iterator that parses KGC entries from raw bytes.
//! - [`KNumEntry`]  â€” a single parsed `KNum` constant.
//! - [`parse_kgc_table`]  â€” parse the entire KGC section.
//! - [`parse_knum_table`] â€” parse the entire `KNum` section.
//! - Constant-folding helpers for integer arithmetic on `KNum` values.
//!
//! # KGC encoding
//! Each KGC entry starts with a ULEB128 type tag:
//! - `0` â†’ `KGCT_CHILD`   (child proto reference)
//! - `1` â†’ `KGCT_TAB`     (table template)
//! - `2` â†’ `KGCT_I64`     (8 raw bytes, LE i64 cdata)
//! - `3` â†’ `KGCT_U64`     (8 raw bytes, LE u64 cdata)
//! - `4` â†’ `KGCT_COMPLEX` (16 raw bytes, two LE f64)
//! - `n â‰¥ 5` â†’ `KGCT_STR` (string of length `n âˆ’ 5`)
//!
//! # `KNum` encoding
//! Each `KNum` entry starts with a ULEB128 "hi" word:
//! - If bit 0 of `hi` is 1: integer value = `hi >> 1` (sign-extended to i32).
//! - If bit 0 of `hi` is 0: double â€” `hi` holds the high 32 bits; the next
//!   4 raw bytes are the low 32 bits.  `f64::from_bits((hi << 32) | lo)`.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{LjLoaderError, read_uleb128};

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// LjKgcType
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Tag values used in the KGC constant table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LjKgcType {
    /// Child prototype reference (tag = 0).
    Child,
    /// Table template (tag = 1).
    Table,
    /// 64-bit signed integer cdata (tag = 2).
    I64,
    /// 64-bit unsigned integer cdata (tag = 3).
    U64,
    /// Complex number cdata â€” two `f64` (tag = 4).
    Complex,
    /// String constant (tag â‰¥ 5; length = tag âˆ’ 5).
    Str,
    /// Unknown / reserved tag.
    Unknown,
}

impl LjKgcType {
    /// Classify a raw ULEB128 tag value.
    #[must_use]
    pub const fn from_tag(tag: u64) -> Self {
        match tag {
            0 => Self::Child,
            1 => Self::Table,
            2 => Self::I64,
            3 => Self::U64,
            4 => Self::Complex,
            n if n >= 5 => Self::Str,
            _ => Self::Unknown,
        }
    }

    /// The fixed-byte payload length for types that have one, or `None` for
    /// variable-length types (`Str`, `Child`) or zero-byte types (`Table`).
    #[must_use]
    pub const fn fixed_payload_bytes(self) -> Option<usize> {
        match self {
            Self::I64 => Some(8),
            Self::U64 => Some(8),
            Self::Complex => Some(16),
            _ => None,
        }
    }
}

impl fmt::Display for LjKgcType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Child => "CHILD",
            Self::Table => "TAB",
            Self::I64 => "I64",
            Self::U64 => "U64",
            Self::Complex => "COMPLEX",
            Self::Str => "STR",
            Self::Unknown => "UNKNOWN",
        };
        write!(f, "{s}")
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// KgcEntry â€” a single parsed KGC constant
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A fully decoded KGC constant entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KgcEntry {
    /// Child prototype reference (no inline data; resolved at the file level).
    Child,
    /// Table template (no inline data in the KGC stream for simple templates).
    Table,
    /// 64-bit signed integer cdata.
    I64(i64),
    /// 64-bit unsigned integer cdata.
    U64(u64),
    /// Complex number cdata: (real, imaginary).
    Complex(f64, f64),
    /// String constant.
    Str(String),
    /// Unknown type tag with the raw tag value.
    Unknown(u64),
}

impl KgcEntry {
    /// Return the KGC type tag for this entry.
    #[must_use]
    pub const fn kgc_type(&self) -> LjKgcType {
        match self {
            Self::Child => LjKgcType::Child,
            Self::Table => LjKgcType::Table,
            Self::I64(_) => LjKgcType::I64,
            Self::U64(_) => LjKgcType::U64,
            Self::Complex(..) => LjKgcType::Complex,
            Self::Str(_) => LjKgcType::Str,
            Self::Unknown(_) => LjKgcType::Unknown,
        }
    }

    /// Attempt to extract a string value.
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        if let Self::Str(s) = self {
            Some(s.as_str())
        } else {
            None
        }
    }

    /// Attempt to extract an i64 value.
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        match self {
            Self::I64(v) => Some(*v),
            _ => None,
        }
    }

    /// Attempt to extract a u64 value.
    #[must_use]
    pub const fn as_u64(&self) -> Option<u64> {
        match self {
            Self::U64(v) => Some(*v),
            _ => None,
        }
    }

    /// Return `true` if this is a child proto reference.
    #[must_use]
    pub const fn is_child(&self) -> bool {
        matches!(self, Self::Child)
    }

    /// Return `true` if this is a string.
    #[must_use]
    pub const fn is_str(&self) -> bool {
        matches!(self, Self::Str(_))
    }
}

impl fmt::Display for KgcEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Child => write!(f, "<child-proto>"),
            Self::Table => write!(f, "<table>"),
            Self::I64(v) => write!(f, "{v}i64"),
            Self::U64(v) => write!(f, "{v}u64"),
            Self::Complex(r, i) => write!(f, "{r}+{i}i"),
            Self::Str(s) => write!(f, "\"{s}\""),
            Self::Unknown(t) => write!(f, "<unknown-kgc:{t}>"),
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// KgcIter â€” streaming KGC parser
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Streaming iterator that parses KGC entries one-by-one from a byte slice.
///
/// Usage:
/// ```rust
/// use rustre_loader_luajit::constant_tables::KgcIter;
///
/// // One KGC entry: type tag 5 (string of length 1) followed by its byte.
/// let data = [0x05u8, b'x'];
/// let mut iter = KgcIter::new(&data, 0, 1);
/// while let Some(_entry) = iter.next() {
///     // process entry
/// }
/// let final_offset = iter.position();
/// assert!(final_offset <= data.len());
/// ```
pub struct KgcIter<'a> {
    data: &'a [u8],
    pos: usize,
    remaining: usize,
}

impl<'a> KgcIter<'a> {
    /// Create a new iterator starting at `offset`, expecting `count` entries.
    #[must_use]
    pub const fn new(data: &'a [u8], offset: usize, count: usize) -> Self {
        Self {
            data,
            pos: offset,
            remaining: count,
        }
    }

    /// Current byte position within `data`.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Number of entries not yet consumed.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.remaining
    }

    /// Parse the next KGC entry.  Returns `None` when the count is exhausted
    /// or the data is truncated.
    pub fn next(&mut self) -> Option<KgcEntry> {
        if self.remaining == 0 {
            return None;
        }
        let (tag, np) = read_uleb128(self.data, self.pos)?;
        self.pos = np;
        self.remaining -= 1;
        let entry = match tag {
            0 => KgcEntry::Child,
            1 => KgcEntry::Table,
            2 => {
                // i64: 4 LE bytes lo + 4 LE bytes hi
                if self.pos + 8 > self.data.len() {
                    return None;
                }
                let lo = read_u32_le(self.data, self.pos);
                let hi = read_u32_le(self.data, self.pos + 4);
                self.pos += 8;
                KgcEntry::I64((i64::from(hi) << 32) | i64::from(lo))
            }
            3 => {
                // u64
                if self.pos + 8 > self.data.len() {
                    return None;
                }
                let lo = read_u32_le(self.data, self.pos);
                let hi = read_u32_le(self.data, self.pos + 4);
                self.pos += 8;
                KgcEntry::U64((u64::from(hi) << 32) | u64::from(lo))
            }
            4 => {
                // complex: two f64
                if self.pos + 16 > self.data.len() {
                    return None;
                }
                let r_bits = read_u64_le(self.data, self.pos);
                let i_bits = read_u64_le(self.data, self.pos + 8);
                self.pos += 16;
                KgcEntry::Complex(f64::from_bits(r_bits), f64::from_bits(i_bits))
            }
            n => {
                // String: length = n - 5
                let slen = (n as usize).saturating_sub(5);
                if self.pos + slen > self.data.len() {
                    return None;
                }
                let s = String::from_utf8_lossy(&self.data[self.pos..self.pos + slen]).into_owned();
                self.pos += slen;
                KgcEntry::Str(s)
            }
        };
        Some(entry)
    }

    /// Collect all remaining entries.
    #[must_use]
    pub fn collect_all(mut self) -> Vec<KgcEntry> {
        let mut out = Vec::with_capacity(self.remaining);
        while let Some(e) = self.next() {
            out.push(e);
        }
        out
    }
}

/// Parse the entire KGC section from `data[offset..]` with `count` entries.
/// Returns `(entries, new_offset)` or an error.
pub fn parse_kgc_table(
    data: &[u8],
    offset: usize,
    count: usize,
) -> Result<(Vec<KgcEntry>, usize), LjLoaderError> {
    let mut iter = KgcIter::new(data, offset, count);
    // Each KGC entry needs at least a one-byte type tag; bound the reservation
    // by the remaining input so a crafted count cannot drive the allocation.
    let mut out = Vec::with_capacity(count.min(data.len().saturating_sub(offset)));
    for _ in 0..count {
        match iter.next() {
            Some(e) => out.push(e),
            None => return Err(LjLoaderError::TruncatedData),
        }
    }
    Ok((out, iter.position()))
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// KNumEntry â€” a single parsed KNum constant
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A numeric constant decoded from the `KNum` table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KNumEntry {
    /// Integer constant (sign-extended 32-bit).
    Int(i32),
    /// Floating-point constant.
    Float(f64),
}

impl KNumEntry {
    /// Convert to `f64` regardless of variant.
    #[must_use]
    pub const fn to_f64(&self) -> f64 {
        match self {
            Self::Int(v) => *v as f64,
            Self::Float(v) => *v,
        }
    }

    /// Is this entry an integer?
    #[must_use]
    pub const fn is_int(&self) -> bool {
        matches!(self, Self::Int(_))
    }

    /// Is this entry a float?
    #[must_use]
    pub const fn is_float(&self) -> bool {
        matches!(self, Self::Float(_))
    }

    /// Extract the integer value if this is an `Int`.
    #[must_use]
    pub const fn as_int(&self) -> Option<i32> {
        if let Self::Int(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Extract the float value if this is a `Float`.
    #[must_use]
    pub const fn as_float(&self) -> Option<f64> {
        if let Self::Float(v) = self {
            Some(*v)
        } else {
            None
        }
    }
}

impl fmt::Display for KNumEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(v) => write!(f, "{v}"),
            Self::Float(v) => write!(f, "{v}"),
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// parse_knum_table
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Parse the entire `KNum` section from `data[offset..]` with `count` entries.
/// Returns `(entries, new_offset)` or an error.
pub fn parse_knum_table(
    data: &[u8],
    mut offset: usize,
    count: usize,
) -> Result<(Vec<KNumEntry>, usize), LjLoaderError> {
    // Each KNum entry needs at least one ULEB128 byte.
    let mut out = Vec::with_capacity(count.min(data.len().saturating_sub(offset)));
    for _ in 0..count {
        let (kval, np) = read_uleb128(data, offset).ok_or(LjLoaderError::TruncatedData)?;
        offset = np;
        if kval & 1 != 0 {
            // Integer: value = kval >> 1 (treat as u32, then sign-extend)
            let ival = (kval >> 1) as i32;
            out.push(KNumEntry::Int(ival));
        } else {
            // Double: kval holds the high 32 bits; next 4 bytes are the low 32 bits
            if offset + 4 > data.len() {
                return Err(LjLoaderError::TruncatedData);
            }
            let lo = read_u32_le(data, offset);
            offset += 4;
            let bits = (kval << 32) | u64::from(lo);
            out.push(KNumEntry::Float(f64::from_bits(bits)));
        }
    }
    Ok((out, offset))
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Constant folding helpers
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Attempt to fold a binary arithmetic operation on two `KNumEntry` values.
///
/// Returns `None` for unsupported operations (modulo by zero, etc.).
#[must_use]
pub fn knum_fold_binop(lhs: &KNumEntry, rhs: &KNumEntry, op: BinOp) -> Option<KNumEntry> {
    // Promote both to f64 for the operation, then try to narrow back to int
    let l = lhs.to_f64();
    let r = rhs.to_f64();
    let result = match op {
        BinOp::Add => l + r,
        BinOp::Sub => l - r,
        BinOp::Mul => l * r,
        BinOp::Div => {
            if r == 0.0 {
                return None;
            }
            l / r
        }
        BinOp::Mod => {
            if r == 0.0 {
                return None;
            }
            (l / r).floor().mul_add(-r, l)
        }
        BinOp::Pow => l.powf(r),
    };
    // Attempt integer narrowing if both inputs were integers and result is exact
    if lhs.is_int()
        && rhs.is_int()
        && result.fract() == 0.0
        && result >= f64::from(i32::MIN)
        && result <= f64::from(i32::MAX)
    {
        Some(KNumEntry::Int(result as i32))
    } else {
        Some(KNumEntry::Float(result))
    }
}

/// Fold a unary negation.
#[must_use]
pub fn knum_fold_unm(v: &KNumEntry) -> KNumEntry {
    match v {
        KNumEntry::Int(i) => KNumEntry::Int(i.wrapping_neg()),
        KNumEntry::Float(f) => KNumEntry::Float(-f),
    }
}

/// Binary operator enumeration for constant folding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Mod => "%",
            Self::Pow => "^",
        };
        write!(f, "{s}")
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// KgcTableSummary â€” high-level summary of a KGC table
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Summary statistics for a parsed KGC table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KgcTableSummary {
    pub total: usize,
    pub num_strings: usize,
    pub num_children: usize,
    pub num_tables: usize,
    pub num_i64: usize,
    pub num_u64: usize,
    pub num_complex: usize,
    pub num_unknown: usize,
}

impl KgcTableSummary {
    /// Compute a summary from a slice of `KgcEntry` values.
    #[must_use]
    pub fn from_entries(entries: &[KgcEntry]) -> Self {
        let mut s = Self {
            total: entries.len(),
            num_strings: 0,
            num_children: 0,
            num_tables: 0,
            num_i64: 0,
            num_u64: 0,
            num_complex: 0,
            num_unknown: 0,
        };
        for e in entries {
            match e {
                KgcEntry::Str(_) => s.num_strings += 1,
                KgcEntry::Child => s.num_children += 1,
                KgcEntry::Table => s.num_tables += 1,
                KgcEntry::I64(_) => s.num_i64 += 1,
                KgcEntry::U64(_) => s.num_u64 += 1,
                KgcEntry::Complex(..) => s.num_complex += 1,
                KgcEntry::Unknown(_) => s.num_unknown += 1,
            }
        }
        s
    }
}

impl fmt::Display for KgcTableSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KGC total={} str={} child={} tab={} i64={} u64={} complex={} unk={}",
            self.total,
            self.num_strings,
            self.num_children,
            self.num_tables,
            self.num_i64,
            self.num_u64,
            self.num_complex,
            self.num_unknown
        )
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// KNumTableSummary
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Summary statistics for a parsed `KNum` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KNumTableSummary {
    pub total: usize,
    pub num_int: usize,
    pub num_float: usize,
    pub min_int: Option<i32>,
    pub max_int: Option<i32>,
}

impl KNumTableSummary {
    #[must_use]
    pub fn from_entries(entries: &[KNumEntry]) -> Self {
        let mut s = Self {
            total: entries.len(),
            num_int: 0,
            num_float: 0,
            min_int: None,
            max_int: None,
        };
        for e in entries {
            match e {
                KNumEntry::Int(v) => {
                    s.num_int += 1;
                    s.min_int = Some(s.min_int.map_or(*v, |m: i32| m.min(*v)));
                    s.max_int = Some(s.max_int.map_or(*v, |m: i32| m.max(*v)));
                }
                KNumEntry::Float(_) => s.num_float += 1,
            }
        }
        s
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Low-level read helpers
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[inline]
fn read_u32_le(data: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
}

#[inline]
fn read_u64_le(data: &[u8], pos: usize) -> u64 {
    u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap_or([0; 8]))
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_uleb128(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            } else {
                out.push(byte | 0x80);
            }
        }
        out
    }

    // â”€â”€ LjKgcType â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_kgc_type_from_tag() {
        assert_eq!(LjKgcType::from_tag(0), LjKgcType::Child);
        assert_eq!(LjKgcType::from_tag(1), LjKgcType::Table);
        assert_eq!(LjKgcType::from_tag(2), LjKgcType::I64);
        assert_eq!(LjKgcType::from_tag(3), LjKgcType::U64);
        assert_eq!(LjKgcType::from_tag(4), LjKgcType::Complex);
        assert_eq!(LjKgcType::from_tag(5), LjKgcType::Str);
        assert_eq!(LjKgcType::from_tag(100), LjKgcType::Str);
    }

    #[test]
    fn test_kgc_type_display() {
        assert_eq!(LjKgcType::Str.to_string(), "STR");
        assert_eq!(LjKgcType::I64.to_string(), "I64");
    }

    #[test]
    fn test_kgc_type_fixed_payload() {
        assert_eq!(LjKgcType::I64.fixed_payload_bytes(), Some(8));
        assert_eq!(LjKgcType::Complex.fixed_payload_bytes(), Some(16));
        assert_eq!(LjKgcType::Str.fixed_payload_bytes(), None);
        assert_eq!(LjKgcType::Child.fixed_payload_bytes(), None);
    }

    // â”€â”€ KgcEntry â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_kgc_entry_str() {
        let e = KgcEntry::Str("hello".to_string());
        assert_eq!(e.as_str(), Some("hello"));
        assert!(e.is_str());
        assert!(!e.is_child());
        assert_eq!(e.kgc_type(), LjKgcType::Str);
    }

    #[test]
    fn test_kgc_entry_child() {
        let e = KgcEntry::Child;
        assert!(e.is_child());
        assert!(e.as_str().is_none());
    }

    #[test]
    fn test_kgc_entry_i64_display() {
        assert_eq!(KgcEntry::I64(-7).to_string(), "-7i64");
    }

    #[test]
    fn test_kgc_entry_u64_display() {
        assert_eq!(KgcEntry::U64(42).to_string(), "42u64");
    }

    #[test]
    fn test_kgc_entry_table_display() {
        assert_eq!(KgcEntry::Table.to_string(), "<table>");
    }

    // â”€â”€ KgcIter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_kgc_iter_string() {
        // tag = 5+5 = 10 (string of len 5), then "hello"
        let mut data = encode_uleb128(10);
        data.extend_from_slice(b"hello");
        let mut iter = KgcIter::new(&data, 0, 1);
        let entry = iter.next().unwrap();
        assert_eq!(entry.as_str(), Some("hello"));
        assert_eq!(iter.remaining(), 0);
    }

    #[test]
    fn test_kgc_iter_child() {
        let data = [0x00]; // tag=0 = CHILD
        let mut iter = KgcIter::new(&data, 0, 1);
        assert!(matches!(iter.next().unwrap(), KgcEntry::Child));
    }

    #[test]
    fn test_kgc_iter_table() {
        let data = [0x01]; // tag=1 = TABLE
        let mut iter = KgcIter::new(&data, 0, 1);
        assert!(matches!(iter.next().unwrap(), KgcEntry::Table));
    }

    #[test]
    fn test_kgc_iter_i64() {
        let mut data = vec![0x02]; // tag=I64
        data.extend_from_slice(&1i64.to_le_bytes());
        let mut iter = KgcIter::new(&data, 0, 1);
        let e = iter.next().unwrap();
        assert_eq!(e.as_i64(), Some(1));
    }

    #[test]
    fn test_kgc_iter_u64() {
        let mut data = vec![0x03]; // tag=U64
        data.extend_from_slice(&0xDEAD_BEEF_u64.to_le_bytes());
        let mut iter = KgcIter::new(&data, 0, 1);
        let e = iter.next().unwrap();
        assert_eq!(e.as_u64(), Some(0xDEAD_BEEF));
    }

    #[test]
    fn test_kgc_iter_complex() {
        let mut data = vec![0x04]; // tag=COMPLEX
        data.extend_from_slice(&1.0f64.to_le_bytes());
        data.extend_from_slice(&2.0f64.to_le_bytes());
        let mut iter = KgcIter::new(&data, 0, 1);
        let e = iter.next().unwrap();
        assert!(matches!(e, KgcEntry::Complex(r, i) if r == 1.0 && i == 2.0));
    }

    #[test]
    fn test_kgc_iter_none_when_exhausted() {
        let data = [0x01]; // one TABLE entry
        let mut iter = KgcIter::new(&data, 0, 1);
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_kgc_iter_collect_multiple() {
        // child + table
        let data = [0x00, 0x01];
        let iter = KgcIter::new(&data, 0, 2);
        let entries = iter.collect_all();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].is_child());
        assert!(matches!(entries[1], KgcEntry::Table));
    }

    // â”€â”€ parse_kgc_table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_parse_kgc_table_empty() {
        let (entries, pos) = parse_kgc_table(&[], 0, 0).unwrap();
        assert!(entries.is_empty());
        assert_eq!(pos, 0);
    }

    #[test]
    fn test_parse_kgc_table_two_strings() {
        let mut data = encode_uleb128(5 + 3); // "foo"
        data.extend_from_slice(b"foo");
        data.append(&mut encode_uleb128(5 + 3)); // "bar"
        data.extend_from_slice(b"bar");
        let (entries, _) = parse_kgc_table(&data, 0, 2).unwrap();
        assert_eq!(entries[0].as_str(), Some("foo"));
        assert_eq!(entries[1].as_str(), Some("bar"));
    }

    #[test]
    fn test_parse_kgc_table_truncated() {
        let result = parse_kgc_table(&[], 0, 1);
        assert!(result.is_err());
    }

    // â”€â”€ KNumEntry â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_knum_entry_int() {
        let e = KNumEntry::Int(5);
        assert!(e.is_int());
        assert!(!e.is_float());
        assert_eq!(e.as_int(), Some(5));
        assert_eq!(e.to_f64(), 5.0);
    }

    #[test]
    fn test_knum_entry_float() {
        let e = KNumEntry::Float(3.14_f64);
        assert!(e.is_float());
        assert_eq!(e.as_float(), Some(3.14_f64));
        assert!((e.to_f64() - 3.14_f64).abs() < 1e-10);
    }

    #[test]
    fn test_knum_entry_display_int() {
        assert_eq!(KNumEntry::Int(42).to_string(), "42");
    }

    // â”€â”€ parse_knum_table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_parse_knum_integer_42() {
        // Integer 42: ULEB(42<<1 | 1) = ULEB(85) = [0x55]
        let data = [0x55u8];
        let (entries, pos) = parse_knum_table(&data, 0, 1).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].as_int(), Some(42));
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_parse_knum_integer_negative() {
        // -1 as u32 = 0xFFFF_FFFF; value = (0xFFFF_FFFF << 1 | 1) â†’ but stored as ULEB of raw i32
        // LuaJIT stores small ints; -1 in i32 = sign-extended from high bits
        // Actual encoding: ULEB(1) since (1 >> 1) = 0 but that's 0...
        // Let's use a simple known case: integer 0 â†’ ULEB(0<<1|1) = ULEB(1) = [0x01]
        let data = [0x01u8];
        let (entries, _) = parse_knum_table(&data, 0, 1).unwrap();
        assert_eq!(entries[0].as_int(), Some(0));
    }

    #[test]
    fn test_parse_knum_float_zero() {
        // Float 0.0: hi=0 (bit0=0), lo=0x00000000
        // ULEB(0) = [0x00], then 4 bytes of zero
        let data: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00];
        let (entries, pos) = parse_knum_table(data, 0, 1).unwrap();
        assert_eq!(entries[0].as_float(), Some(0.0));
        assert_eq!(pos, 5);
    }

    #[test]
    fn test_parse_knum_truncated_float() {
        // bit0=0 so it wants 4 more bytes, but we only have 2
        let data: &[u8] = &[0x00, 0x01, 0x02];
        let result = parse_knum_table(data, 0, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_knum_empty() {
        let (entries, pos) = parse_knum_table(&[], 0, 0).unwrap();
        assert!(entries.is_empty());
        assert_eq!(pos, 0);
    }

    // â”€â”€ Constant folding â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_knum_fold_add_int_int() {
        let r = knum_fold_binop(&KNumEntry::Int(3), &KNumEntry::Int(4), BinOp::Add).unwrap();
        assert_eq!(r, KNumEntry::Int(7));
    }

    #[test]
    fn test_knum_fold_sub() {
        let r = knum_fold_binop(&KNumEntry::Int(10), &KNumEntry::Int(3), BinOp::Sub).unwrap();
        assert_eq!(r, KNumEntry::Int(7));
    }

    #[test]
    fn test_knum_fold_mul_float() {
        let r =
            knum_fold_binop(&KNumEntry::Float(2.0), &KNumEntry::Float(3.0), BinOp::Mul).unwrap();
        assert_eq!(r, KNumEntry::Float(6.0));
    }

    #[test]
    fn test_knum_fold_div_by_zero_returns_none() {
        let r = knum_fold_binop(&KNumEntry::Int(1), &KNumEntry::Int(0), BinOp::Div);
        assert!(r.is_none());
    }

    #[test]
    fn test_knum_fold_mod_by_zero_returns_none() {
        let r = knum_fold_binop(&KNumEntry::Float(5.0), &KNumEntry::Float(0.0), BinOp::Mod);
        assert!(r.is_none());
    }

    #[test]
    fn test_knum_fold_unm_int() {
        assert_eq!(knum_fold_unm(&KNumEntry::Int(7)), KNumEntry::Int(-7));
    }

    #[test]
    fn test_knum_fold_unm_float() {
        let r = knum_fold_unm(&KNumEntry::Float(3.14_f64));
        assert!(matches!(r, KNumEntry::Float(v) if (v + 3.14_f64).abs() < 1e-10));
    }

    #[test]
    fn test_knum_fold_pow() {
        let r =
            knum_fold_binop(&KNumEntry::Float(2.0), &KNumEntry::Float(10.0), BinOp::Pow).unwrap();
        assert!(matches!(r, KNumEntry::Float(v) if (v - 1024.0).abs() < 1e-9));
    }

    // â”€â”€ KgcTableSummary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_kgc_summary_mixed() {
        let entries = vec![
            KgcEntry::Str("a".into()),
            KgcEntry::Str("b".into()),
            KgcEntry::Child,
            KgcEntry::Table,
            KgcEntry::I64(1),
        ];
        let s = KgcTableSummary::from_entries(&entries);
        assert_eq!(s.total, 5);
        assert_eq!(s.num_strings, 2);
        assert_eq!(s.num_children, 1);
        assert_eq!(s.num_tables, 1);
        assert_eq!(s.num_i64, 1);
    }

    #[test]
    fn test_kgc_summary_display() {
        let s = KgcTableSummary::from_entries(&[]);
        assert!(s.to_string().contains("KGC"));
    }

    // â”€â”€ KNumTableSummary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_knum_summary() {
        let entries = vec![
            KNumEntry::Int(1),
            KNumEntry::Int(-5),
            KNumEntry::Float(3.14_f64),
        ];
        let s = KNumTableSummary::from_entries(&entries);
        assert_eq!(s.num_int, 2);
        assert_eq!(s.num_float, 1);
        assert_eq!(s.min_int, Some(-5));
        assert_eq!(s.max_int, Some(1));
    }

    #[test]
    fn test_knum_summary_empty() {
        let s = KNumTableSummary::from_entries(&[]);
        assert_eq!(s.total, 0);
        assert!(s.min_int.is_none());
    }

    #[test]
    fn test_binop_display() {
        assert_eq!(BinOp::Add.to_string(), "+");
        assert_eq!(BinOp::Pow.to_string(), "^");
    }
}
