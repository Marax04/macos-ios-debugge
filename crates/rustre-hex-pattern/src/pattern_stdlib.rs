//! `pattern_stdlib` — Advanced built-in types for the pattern language.
//!
//! Provides: extended integer types (be/le int128), IEEE 754 special handling,
//! float16/bfloat16, packed BCD, struct helpers (padding, alignment,
//! version-conditional fields), arrays with sentinels (null-terminated,
//! length-prefixed, element-counted), tagged unions, and named bitfields.

use std::fmt;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// StdlibError
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum StdlibError {
    #[error("buffer too short: need {need} bytes at offset {offset}, have {have}")]
    BufferTooShort {
        offset: usize,
        need: usize,
        have: usize,
    },
    #[error("BCD digit out of range at nibble {nibble}: value {value}")]
    BcdDigitRange { nibble: usize, value: u8 },
    #[error("array sentinel not found starting at offset {offset}")]
    SentinelNotFound { offset: usize },
    #[error("union tag {tag} not matched by any variant")]
    UnmatchedUnionTag { tag: u64 },
    #[error("field '{field}': {reason}")]
    Field { field: String, reason: String },
    #[error("version condition: {0}")]
    Version(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// 128-bit integers
// ─────────────────────────────────────────────────────────────────────────────

/// Read a little-endian unsigned 128-bit integer.
#[must_use]
pub fn read_le_u128(data: &[u8], offset: usize) -> Result<u128, StdlibError> {
    check_bounds(data, offset, 16)?;
    let bytes: [u8; 16] = data[offset..offset + 16].try_into().unwrap();
    Ok(u128::from_le_bytes(bytes))
}

/// Read a big-endian unsigned 128-bit integer.
#[must_use]
pub fn read_be_u128(data: &[u8], offset: usize) -> Result<u128, StdlibError> {
    check_bounds(data, offset, 16)?;
    let bytes: [u8; 16] = data[offset..offset + 16].try_into().unwrap();
    Ok(u128::from_be_bytes(bytes))
}

/// Read a little-endian signed 128-bit integer.
#[must_use]
pub fn read_le_i128(data: &[u8], offset: usize) -> Result<i128, StdlibError> {
    read_le_u128(data, offset).map(|v| v as i128)
}

/// Read a big-endian signed 128-bit integer.
#[must_use]
pub fn read_be_i128(data: &[u8], offset: usize) -> Result<i128, StdlibError> {
    read_be_u128(data, offset).map(|v| v as i128)
}

// ─────────────────────────────────────────────────────────────────────────────
// Float16 / BFloat16
// ─────────────────────────────────────────────────────────────────────────────

/// An IEEE 754 half-precision (float16) value.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Float16(pub u16);

impl Float16 {
    /// Parse from two bytes (little-endian).
    #[must_use]
    pub fn from_le_bytes(data: &[u8], offset: usize) -> Result<Self, StdlibError> {
        check_bounds(data, offset, 2)?;
        let v = u16::from_le_bytes([data[offset], data[offset + 1]]);
        Ok(Self(v))
    }

    /// Parse from two bytes (big-endian).
    #[must_use]
    pub fn from_be_bytes(data: &[u8], offset: usize) -> Result<Self, StdlibError> {
        check_bounds(data, offset, 2)?;
        let v = u16::from_be_bytes([data[offset], data[offset + 1]]);
        Ok(Self(v))
    }

    /// Convert to f32.
    #[must_use]
    pub fn to_f32(self) -> f32 {
        let bits = self.0 as u32;
        let sign = (bits >> 15) & 1;
        let exp = (bits >> 10) & 0x1F;
        let mantissa = bits & 0x3FF;

        if exp == 0 {
            // Subnormal
            let val = (mantissa as f32) / (1024.0 * 16384.0);
            if sign == 1 { -val } else { val }
        } else if exp == 31 {
            // Inf / NaN
            if mantissa == 0 {
                if sign == 1 { f32::NEG_INFINITY } else { f32::INFINITY }
            } else {
                f32::NAN
            }
        } else {
            let e = exp as i32 - 15 + 127;
            let bits32 = (sign << 31) | ((e as u32) << 23) | (mantissa << 13);
            f32::from_bits(bits32)
        }
    }

    #[must_use]
    pub const fn is_nan(self) -> bool {
        let exp = (self.0 >> 10) & 0x1F;
        let mantissa = self.0 & 0x3FF;
        exp == 31 && mantissa != 0
    }

    #[must_use]
    pub const fn is_infinite(self) -> bool {
        let exp = (self.0 >> 10) & 0x1F;
        let mantissa = self.0 & 0x3FF;
        exp == 31 && mantissa == 0
    }
}

impl fmt::Display for Float16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self.to_f32();
        write!(f, "{v}")
    }
}

/// A Google `BFloat16` value (truncated float32).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct BFloat16(pub u16);

impl BFloat16 {
    #[must_use]
    pub fn from_le_bytes(data: &[u8], offset: usize) -> Result<Self, StdlibError> {
        check_bounds(data, offset, 2)?;
        let v = u16::from_le_bytes([data[offset], data[offset + 1]]);
        Ok(Self(v))
    }

    #[must_use]
    pub fn from_be_bytes(data: &[u8], offset: usize) -> Result<Self, StdlibError> {
        check_bounds(data, offset, 2)?;
        let v = u16::from_be_bytes([data[offset], data[offset + 1]]);
        Ok(Self(v))
    }

    /// Expand `BFloat16` to f32 by appending 16 zero bits.
    #[must_use]
    pub const fn to_f32(self) -> f32 {
        let bits32 = (self.0 as u32) << 16;
        f32::from_bits(bits32)
    }
}

impl fmt::Display for BFloat16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_f32())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IEEE 754 special values
// ─────────────────────────────────────────────────────────────────────────────

/// Detailed classification of an IEEE 754 float32.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ieee754Class {
    Zero,
    Subnormal,
    Normal,
    Infinite,
    NaN { signaling: bool },
}

/// Classify a raw f32 bit pattern.
#[must_use]
pub const fn classify_f32_bits(bits: u32) -> Ieee754Class {
    let exp = (bits >> 23) & 0xFF;
    let mantissa = bits & 0x7FFFFF;
    match exp {
        0 if mantissa == 0 => Ieee754Class::Zero,
        0 => Ieee754Class::Subnormal,
        0xFF if mantissa == 0 => Ieee754Class::Infinite,
        0xFF => Ieee754Class::NaN {
            signaling: (mantissa >> 22) == 0,
        },
        _ => Ieee754Class::Normal,
    }
}

/// Read f32 and classify it.
pub fn read_f32_classified(
    data: &[u8],
    offset: usize,
    little_endian: bool,
) -> Result<(f32, Ieee754Class), StdlibError> {
    check_bounds(data, offset, 4)?;
    let bits = if little_endian {
        u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
    } else {
        u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap())
    };
    Ok((f32::from_bits(bits), classify_f32_bits(bits)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Packed BCD
// ─────────────────────────────────────────────────────────────────────────────

/// A packed binary-coded decimal number.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackedBcd {
    pub digits: Vec<u8>,
    pub negative: bool,
}

impl PackedBcd {
    /// Parse `n` bytes of packed BCD starting at `offset`.
    /// Each byte encodes two decimal digits (high nibble = tens).
    pub fn parse(data: &[u8], offset: usize, n: usize) -> Result<Self, StdlibError> {
        check_bounds(data, offset, n)?;
        let mut digits = Vec::with_capacity(n * 2);
        for (i, &byte) in data[offset..offset + n].iter().enumerate() {
            let hi = byte >> 4;
            let lo = byte & 0x0F;
            // Check for sign nibble (0xD = negative, 0xC/0xF = positive)
            if i == n - 1 && (lo == 0xC || lo == 0xD || lo == 0xF) {
                digits.push(hi);
                return Ok(Self {
                    digits,
                    negative: lo == 0xD,
                });
            }
            if hi > 9 {
                return Err(StdlibError::BcdDigitRange {
                    nibble: i * 2,
                    value: hi,
                });
            }
            if lo > 9 {
                return Err(StdlibError::BcdDigitRange {
                    nibble: i * 2 + 1,
                    value: lo,
                });
            }
            digits.push(hi);
            digits.push(lo);
        }
        Ok(Self {
            digits,
            negative: false,
        })
    }

    /// Convert to a decimal string.
    #[must_use]
    pub fn to_string_repr(&self) -> String {
        let digits: String = self.digits.iter().map(|&d| (b'0' + d) as char).collect();
        if self.negative {
            format!("-{digits}")
        } else {
            digits
        }
    }

    /// Convert to i64 (may overflow for very long BCD numbers).
    #[must_use]
    pub fn to_i64(&self) -> i64 {
        let mut v = 0i64;
        for &d in &self.digits {
            v = v * 10 + d as i64;
        }
        if self.negative { -v } else { v }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Struct helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Compute padding needed to align `offset` to `alignment`.
#[must_use]
pub const fn padding_to_align(offset: usize, alignment: usize) -> usize {
    if alignment == 0 || alignment == 1 {
        return 0;
    }
    let rem = offset % alignment;
    if rem == 0 { 0 } else { alignment - rem }
}

/// Advance `offset` to the next aligned position.
#[must_use]
pub fn align_offset(offset: usize, alignment: usize) -> usize {
    offset + padding_to_align(offset, alignment)
}

/// Version-conditional field: returns `true` if the field should be parsed
/// given `file_version >= required_version`.
#[must_use]
pub const fn version_has_field(file_version: u32, required_version: u32) -> bool {
    file_version >= required_version
}

// ─────────────────────────────────────────────────────────────────────────────
// Sentinel arrays
// ─────────────────────────────────────────────────────────────────────────────

/// Read a null-terminated string (up to `max_len` bytes).
pub fn read_cstring(
    data: &[u8],
    offset: usize,
    max_len: usize,
) -> Result<(Vec<u8>, usize), StdlibError> {
    let limit = (offset + max_len).min(data.len());
    for i in offset..limit {
        if data[i] == 0x00 {
            return Ok((data[offset..i].to_vec(), i + 1));
        }
    }
    Err(StdlibError::SentinelNotFound { offset })
}

/// Read a UTF-16 null-terminated string (little-endian).
pub fn read_wstring(
    data: &[u8],
    offset: usize,
    max_chars: usize,
) -> Result<(String, usize), StdlibError> {
    let mut chars = vec![];
    let mut pos = offset;
    for _ in 0..max_chars {
        check_bounds(data, pos, 2)?;
        let codeunit = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        if codeunit == 0 {
            break;
        }
        chars.push(codeunit);
    }
    let s = String::from_utf16_lossy(&chars).to_owned();
    Ok((s, pos))
}

/// Read a length-prefixed byte array.
/// `length_size` is the size of the length field in bytes (1, 2, or 4).
pub fn read_length_prefixed(
    data: &[u8],
    offset: usize,
    length_size: usize,
    little_endian: bool,
) -> Result<(Vec<u8>, usize), StdlibError> {
    check_bounds(data, offset, length_size)?;
    let len = match length_size {
        1 => data[offset] as usize,
        2 => {
            let bytes = &data[offset..offset + 2];
            if little_endian {
                u16::from_le_bytes(bytes.try_into().unwrap()) as usize
            } else {
                u16::from_be_bytes(bytes.try_into().unwrap()) as usize
            }
        }
        4 => {
            let bytes = &data[offset..offset + 4];
            if little_endian {
                u32::from_le_bytes(bytes.try_into().unwrap()) as usize
            } else {
                u32::from_be_bytes(bytes.try_into().unwrap()) as usize
            }
        }
        _ => {
            return Err(StdlibError::Field {
                field: "length_size".to_string(),
                reason: format!("unsupported length_size {length_size}"),
            })
        }
    };
    let data_start = offset + length_size;
    check_bounds(data, data_start, len)?;
    Ok((data[data_start..data_start + len].to_vec(), data_start + len))
}

/// Read a fixed-count element array. Returns offsets for each element start.
#[must_use]
pub fn element_counted_offsets(
    start: usize,
    count: usize,
    element_size: usize,
) -> Vec<usize> {
    (0..count).map(|i| start + i * element_size).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tagged unions
// ─────────────────────────────────────────────────────────────────────────────

/// A union variant descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnionVariant {
    pub tag_value: u64,
    pub name: String,
    pub size: usize,
    pub description: String,
}

/// A tagged union definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaggedUnion {
    pub name: String,
    pub tag_offset: usize,
    pub tag_size: usize,
    pub variants: Vec<UnionVariant>,
}

impl TaggedUnion {
    /// Resolve which variant matches the tag at `tag_offset` in `data`.
    pub fn resolve<'a>(
        &'a self,
        data: &[u8],
        base_offset: usize,
        little_endian: bool,
    ) -> Result<&'a UnionVariant, StdlibError> {
        let abs = base_offset + self.tag_offset;
        check_bounds(data, abs, self.tag_size)?;

        let tag = match self.tag_size {
            1 => data[abs] as u64,
            2 => {
                let b = &data[abs..abs + 2];
                if little_endian {
                    u16::from_le_bytes(b.try_into().unwrap()) as u64
                } else {
                    u16::from_be_bytes(b.try_into().unwrap()) as u64
                }
            }
            4 => {
                let b = &data[abs..abs + 4];
                if little_endian {
                    u32::from_le_bytes(b.try_into().unwrap()) as u64
                } else {
                    u32::from_be_bytes(b.try_into().unwrap()) as u64
                }
            }
            8 => {
                let b = &data[abs..abs + 8];
                if little_endian {
                    u64::from_le_bytes(b.try_into().unwrap())
                } else {
                    u64::from_be_bytes(b.try_into().unwrap())
                }
            }
            _ => {
                return Err(StdlibError::Field {
                    field: "tag".to_string(),
                    reason: format!("unsupported tag_size {}", self.tag_size),
                })
            }
        };

        self.variants
            .iter()
            .find(|v| v.tag_value == tag)
            .ok_or(StdlibError::UnmatchedUnionTag { tag })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Named bitfields
// ─────────────────────────────────────────────────────────────────────────────

/// A single named bit or bit-range within an integer field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitfieldEntry {
    pub name: String,
    pub bit_start: u8,
    pub bit_end: u8, // inclusive
    pub description: String,
}

impl BitfieldEntry {
    /// Extract this field's value from a raw integer.
    #[must_use]
    pub const fn extract_u64(&self, raw: u64) -> u64 {
        let mask = if self.bit_end >= 63 {
            u64::MAX
        } else {
            (1u64 << (self.bit_end - self.bit_start + 1)) - 1
        };
        (raw >> self.bit_start) & mask
    }

    /// Number of bits this field spans.
    #[must_use]
    pub const fn width(&self) -> u8 {
        self.bit_end - self.bit_start + 1
    }
}

/// A named bitfield definition (collection of bit entries over one integer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitfieldDef {
    pub name: String,
    pub total_bits: u8,
    pub entries: Vec<BitfieldEntry>,
}

impl BitfieldDef {
    /// Decode all fields from `raw`.
    #[must_use]
    pub fn decode(&self, raw: u64) -> Vec<(String, u64)> {
        self.entries
            .iter()
            .map(|e| (e.name.clone(), e.extract_u64(raw)))
            .collect()
    }

    /// Pretty-print all fields.
    #[must_use]
    pub fn format(&self, raw: u64) -> String {
        let decoded = self.decode(raw);
        let lines: Vec<String> = decoded
            .iter()
            .map(|(name, val)| format!("  {name} = {val:#b} ({val})"))
            .collect();
        format!("{} {{\n{}\n}}", self.name, lines.join("\n"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StdlibRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// A registry of known bitfield and union definitions.
#[derive(Debug, Default)]
pub struct StdlibRegistry {
    pub bitfields: std::collections::HashMap<String, BitfieldDef>,
    pub unions: std::collections::HashMap<String, TaggedUnion>,
}

impl StdlibRegistry {
    #[must_use]
    pub fn new() -> Self {
        let mut reg = Self::default();
        reg.register_builtins();
        reg
    }

    pub fn register_bitfield(&mut self, def: BitfieldDef) {
        self.bitfields.insert(def.name.clone(), def);
    }

    pub fn register_union(&mut self, def: TaggedUnion) {
        self.unions.insert(def.name.clone(), def);
    }

    fn register_builtins(&mut self) {
        // PE characteristics flags
        self.register_bitfield(BitfieldDef {
            name: "PeCharacteristics".to_string(),
            total_bits: 16,
            entries: vec![
                BitfieldEntry {
                    name: "RELOCS_STRIPPED".to_string(),
                    bit_start: 0,
                    bit_end: 0,
                    description: "Relocation info stripped".to_string(),
                },
                BitfieldEntry {
                    name: "EXECUTABLE".to_string(),
                    bit_start: 1,
                    bit_end: 1,
                    description: "File is executable".to_string(),
                },
                BitfieldEntry {
                    name: "DLL".to_string(),
                    bit_start: 13,
                    bit_end: 13,
                    description: "File is a DLL".to_string(),
                },
            ],
        });

        // ELF e_type union
        self.register_union(TaggedUnion {
            name: "ElfType".to_string(),
            tag_offset: 0,
            tag_size: 2,
            variants: vec![
                UnionVariant { tag_value: 0, name: "ET_NONE".to_string(), size: 0, description: "Unknown".to_string() },
                UnionVariant { tag_value: 1, name: "ET_REL".to_string(), size: 0, description: "Relocatable".to_string() },
                UnionVariant { tag_value: 2, name: "ET_EXEC".to_string(), size: 0, description: "Executable".to_string() },
                UnionVariant { tag_value: 3, name: "ET_DYN".to_string(), size: 0, description: "Shared object".to_string() },
                UnionVariant { tag_value: 4, name: "ET_CORE".to_string(), size: 0, description: "Core file".to_string() },
            ],
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const fn check_bounds(data: &[u8], offset: usize, need: usize) -> Result<(), StdlibError> {
    if offset + need > data.len() {
        Err(StdlibError::BufferTooShort {
            offset,
            need,
            have: data.len(),
        })
    } else {
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_u128_le() {
        let mut data = vec![0u8; 16];
        data[0] = 0x01;
        let v = read_le_u128(&data, 0).unwrap();
        assert_eq!(v, 1u128);
    }

    #[test]
    fn float16_to_f32() {
        // 1.0 in float16 = 0x3C00
        let f = Float16(0x3C00).to_f32();
        assert!((f - 1.0f32).abs() < 1e-6);
    }

    #[test]
    fn bfloat16_to_f32() {
        // 1.0 in bfloat16 = 0x3F80
        let b = BFloat16(0x3F80).to_f32();
        assert!((b - 1.0f32).abs() < 1e-6);
    }

    #[test]
    fn packed_bcd_parse() {
        let data = [0x12u8, 0x34, 0x56];
        let bcd = PackedBcd::parse(&data, 0, 3).unwrap();
        assert_eq!(bcd.to_string_repr(), "123456");
        assert_eq!(bcd.to_i64(), 123456);
    }

    #[test]
    fn cstring_read() {
        let data = b"hello\x00world";
        let (s, next) = read_cstring(data, 0, 100).unwrap();
        assert_eq!(s, b"hello");
        assert_eq!(next, 6);
    }

    #[test]
    fn length_prefixed_read() {
        let data = [0x03u8, 0xAA, 0xBB, 0xCC, 0x00];
        let (bytes, next) = read_length_prefixed(&data, 0, 1, true).unwrap();
        assert_eq!(bytes, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(next, 4);
    }

    #[test]
    fn bitfield_extract() {
        let flags_def = BitfieldDef {
            name: "Flags".to_string(),
            total_bits: 8,
            entries: vec![
                BitfieldEntry { name: "A".to_string(), bit_start: 0, bit_end: 0, description: String::new() },
                BitfieldEntry { name: "B".to_string(), bit_start: 1, bit_end: 2, description: String::new() },
            ],
        };
        let decoded = flags_def.decode(0b00000111);
        assert_eq!(decoded[0], ("A".to_string(), 1));
        assert_eq!(decoded[1], ("B".to_string(), 3));
    }

    #[test]
    fn align_offset_test() {
        assert_eq!(align_offset(5, 4), 8);
        assert_eq!(align_offset(8, 4), 8);
        assert_eq!(align_offset(0, 16), 0);
    }

    #[test]
    fn ieee754_classify() {
        assert_eq!(classify_f32_bits(0), Ieee754Class::Zero);
        assert_eq!(classify_f32_bits(f32::INFINITY.to_bits()), Ieee754Class::Infinite);
        assert_eq!(classify_f32_bits(f32::NAN.to_bits()), Ieee754Class::NaN { signaling: false });
    }
}
