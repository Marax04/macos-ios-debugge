//! `CodeView` type information parser.
//!
//! Parses `CodeView` type records from a TPI (Type Information) stream.
//! Handles `LF_STRUCTURE`, `LF_CLASS`, `LF_UNION`, `LF_ENUM`,
//! `LF_PROCEDURE`, `LF_MFUNCTION`, `LF_POINTER`, `LF_ARRAY`,
//! `LF_MODIFIER`, `LF_BITFIELD`, `LF_ARGLIST`, and `LF_FIELDLIST`
//! leaf records, plus `LF_MEMBER` and `LF_ENUMERATE` sub-records.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::{read_u16, read_u32};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Why [`CodeViewTypeParser::parse_stream`] stopped consuming a stream.
///
/// `parse_stream` is deliberately tolerant — real-world TPI streams are
/// truncated or padded — so it returns a record count rather than an error.
/// This records *why* it stopped so callers can tell "50 records" from
/// "50 records then the stream went bad".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeStreamStop {
    /// The whole payload was consumed cleanly.
    Complete,
    /// Fewer than 4 bytes of trailing data remained (alignment padding).
    TrailingBytes { remaining: usize },
    /// A record declared a length below the 2-byte leaf-kind minimum.
    BadRecordLength { offset: usize, len: usize },
    /// A record declared a length running past the end of the buffer.
    Truncated { offset: usize, needed: usize, available: usize },
}

// ---------------------------------------------------------------------------
// Numeric leaf decoder
// ---------------------------------------------------------------------------

/// Decode a `CodeView` numeric leaf at `data[off..]`.
///
/// Returns `(value_as_u64, bytes_consumed)`.
#[must_use] 
pub fn decode_numeric_leaf(data: &[u8], off: usize) -> Option<(u64, usize)> {
    if off >= data.len() {
        return None;
    }
    let tag = read_u16(data, off);
    if tag < 0x8000 {
        // Value is inline in the tag itself.
        return Some((u64::from(tag), 2));
    }
    match tag {
        0x8000 => {
            // LF_CHAR — 1-byte signed
            let v = crate::casts::u8_as_i8(data.get(off + 2).copied()?);
            Some((crate::casts::i8_sext_u64(v), 3))
        }
        0x8001 => {
            // LF_SHORT — 2-byte signed
            if off + 4 > data.len() {
                return None;
            }
            let v = i16::from_le_bytes([data[off + 2], data[off + 3]]);
            Some((crate::casts::i16_sext_u64(v), 4))
        }
        0x8002 => {
            // LF_USHORT — 2-byte unsigned
            if off + 4 > data.len() {
                return None;
            }
            let v = u16::from_le_bytes([data[off + 2], data[off + 3]]);
            Some((u64::from(v), 4))
        }
        0x8003 => {
            // LF_LONG — 4-byte signed
            if off + 6 > data.len() {
                return None;
            }
            let v = i32::from_le_bytes(data[off + 2..off + 6].try_into().ok()?);
            Some((crate::casts::i32_sext_u64(v), 6))
        }
        0x8004 => {
            // LF_ULONG — 4-byte unsigned
            if off + 6 > data.len() {
                return None;
            }
            let v = u32::from_le_bytes(data[off + 2..off + 6].try_into().ok()?);
            Some((u64::from(v), 6))
        }
        0x8009 => {
            // LF_QUADWORD — 8-byte signed
            if off + 10 > data.len() {
                return None;
            }
            let v = i64::from_le_bytes(data[off + 2..off + 10].try_into().ok()?);
            Some((crate::casts::i64_as_u64(v), 10))
        }
        0x800A => {
            // LF_UQUADWORD — 8-byte unsigned
            if off + 10 > data.len() {
                return None;
            }
            let v = u64::from_le_bytes(data[off + 2..off + 10].try_into().ok()?);
            Some((v, 10))
        }
        // Fixed-width leaves we do not decode a value for, but whose length we
        // must consume exactly — skipping only 2 bytes resumes mid-value and
        // desynchronizes the rest of the record.
        0x8005 => (off + 6 <= data.len()).then_some((0, 6)),    // LF_REAL32
        0x8006 => (off + 10 <= data.len()).then_some((0, 10)),  // LF_REAL64
        0x8007 => (off + 12 <= data.len()).then_some((0, 12)),  // LF_REAL80
        0x8008 => (off + 18 <= data.len()).then_some((0, 18)),  // LF_REAL128
        0x800B | 0x800C => (off + 18 <= data.len()).then_some((0, 18)), // LF_(U)OCTWORD
        0x800D => (off + 8 <= data.len()).then_some((0, 8)),    // LF_REAL48
        0x800F => {
            // LF_VARSTRING: [tag:u16][len:u16][bytes]
            if off + 4 > data.len() { return None; }
            let n = u16::from_le_bytes(data[off + 2..off + 4].try_into().ok()?) as usize;
            (off + 4 + n <= data.len()).then_some((0, 4 + n))
        }
        _ => None, // unrecognized numeric tag — length unknown
    }
}

// ---------------------------------------------------------------------------
// CvFieldMember — a single struct/union/class member from LF_FIELDLIST
// ---------------------------------------------------------------------------

/// A field member decoded from an `LF_FIELDLIST` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvFieldMember {
    /// Attribute (access flags: public=3, protected=2, private=1).
    pub attr: u16,
    /// Type index of the member's type.
    pub type_index: u32,
    /// Byte offset within the parent aggregate.
    pub offset: u64,
    /// Member name.
    pub name: String,
}

/// An enum enumerator decoded from an `LF_FIELDLIST` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvEnumerator {
    /// Attribute (usually access flags).
    pub attr: u16,
    /// Numeric value of this enumerator.
    pub value: u64,
    /// Enumerator name.
    pub name: String,
}

// ---------------------------------------------------------------------------
// CvTypeLeaf — parsed leaf type record
// ---------------------------------------------------------------------------

/// A fully parsed `CodeView` type leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CvTypeLeaf {
    /// `LF_STRUCTURE` / `LF_CLASS` — a struct or class.
    Structure {
        member_count: u16,
        property: u16,
        field_list_index: u32,
        derived_index: u32,
        vshape_index: u32,
        size: u64,
        name: String,
        unique_name: String,
    },
    /// `LF_UNION` — a union.
    Union {
        member_count: u16,
        property: u16,
        field_list_index: u32,
        size: u64,
        name: String,
        unique_name: String,
    },
    /// `LF_ENUM` — an enumeration.
    Enum {
        member_count: u16,
        property: u16,
        underlying_type: u32,
        field_list_index: u32,
        name: String,
        unique_name: String,
    },
    /// `LF_PROCEDURE` — a procedure (free function) type.
    Procedure {
        return_type: u32,
        calling_convention: u8,
        func_attr: u8,
        param_count: u16,
        arglist_index: u32,
    },
    /// `LF_MFUNCTION` — a member function.
    MFunction {
        return_type: u32,
        class_index: u32,
        this_type: u32,
        calling_convention: u8,
        func_attr: u8,
        param_count: u16,
        arglist_index: u32,
        this_adjust: i32,
    },
    /// `LF_POINTER` — a pointer type.
    Pointer {
        target_type: u32,
        attributes: u32,
    },
    /// `LF_ARRAY` — an array type.
    Array {
        element_type: u32,
        index_type: u32,
        size: u64,
        name: String,
    },
    /// `LF_MODIFIER` — a type modifier (const/volatile/unaligned).
    Modifier {
        modified_type: u32,
        modifier_flags: u16,
    },
    /// `LF_BITFIELD` — a bitfield type.
    Bitfield {
        base_type: u32,
        length: u8,
        position: u8,
    },
    /// `LF_ARGLIST` — argument-type list.
    Arglist {
        arg_types: Vec<u32>,
    },
    /// `LF_FIELDLIST` — field descriptor list (members and enumerators).
    FieldList {
        members: Vec<CvFieldMember>,
        enumerators: Vec<CvEnumerator>,
    },
    /// Any other leaf type (raw bytes stored for debugging).
    Unknown {
        leaf_kind: u16,
        raw: Vec<u8>,
    },
}

impl CvTypeLeaf {
    /// Returns a brief human-readable kind tag.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Structure { .. } => "LF_STRUCTURE",
            Self::Union { .. } => "LF_UNION",
            Self::Enum { .. } => "LF_ENUM",
            Self::Procedure { .. } => "LF_PROCEDURE",
            Self::MFunction { .. } => "LF_MFUNCTION",
            Self::Pointer { .. } => "LF_POINTER",
            Self::Array { .. } => "LF_ARRAY",
            Self::Modifier { .. } => "LF_MODIFIER",
            Self::Bitfield { .. } => "LF_BITFIELD",
            Self::Arglist { .. } => "LF_ARGLIST",
            Self::FieldList { .. } => "LF_FIELDLIST",
            Self::Unknown { .. } => "LF_UNKNOWN",
        }
    }

    /// Returns the name if this leaf has one.
    #[must_use]
    pub const fn name(&self) -> Option<&str> {
        match self {
            Self::Structure { name, .. }
            | Self::Union { name, .. }
            | Self::Enum { name, .. }
            | Self::Array { name, .. } => Some(name.as_str()),
            _ => None,
        }
    }

    /// Returns `true` if this is an aggregate type (struct/class/union).
    #[must_use]
    pub const fn is_aggregate(&self) -> bool {
        matches!(self, Self::Structure { .. } | Self::Union { .. })
    }

    /// Returns `true` if this is a forward reference (unnamed / size 0).
    #[must_use]
    pub fn is_forward_ref(&self) -> bool {
        match self {
            Self::Structure { property, .. }
            | Self::Union { property, .. }
            | Self::Enum { property, .. } => property & 0x80 != 0,
            _ => false,
        }
    }

    /// For `LF_POINTER`, returns the pointer size in bytes based on attributes.
    #[must_use]
    pub fn pointer_size(&self) -> Option<u8> {
        if let Self::Pointer { attributes, .. } = self {
            // CV_ptrtype lives in attribute bits 0-4; bits 5-7 are ptr_mode
            // (where 4 is CV_PTR_MODE_PMEM, not a 64-bit pointer).
            let ptr_type = attributes & 0x1F;
            Some(match ptr_type {
                0..=3 => 2,
                10 => 4,
                11 => 6,
                12 => 8,
                _ => 4,
            })
        } else {
            None
        }
    }
}

impl std::fmt::Display for CvTypeLeaf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Structure { name, size, .. } => {
                write!(f, "struct '{name}' size={size}")
            }
            Self::Union { name, size, .. } => write!(f, "union '{name}' size={size}"),
            Self::Enum { name, member_count, .. } => {
                write!(f, "enum '{name}' count={member_count}")
            }
            Self::Procedure {
                return_type,
                param_count,
                ..
            } => write!(f, "proc ret={return_type:#x} params={param_count}"),
            Self::Pointer { target_type, .. } => write!(f, "ptr->{target_type:#x}"),
            _ => write!(f, "{}", self.kind_str()),
        }
    }
}

// ---------------------------------------------------------------------------
// ParsedTypeRecord
// ---------------------------------------------------------------------------

/// A type record from the TPI stream with its assigned type index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedTypeRecord {
    /// TPI type index (starts at 0x1000 for user types).
    pub type_index: u32,
    /// The parsed leaf.
    pub leaf: CvTypeLeaf,
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

fn read_cstring(data: &[u8], off: usize) -> (String, usize) {
    if off >= data.len() {
        return (String::new(), 0);
    }
    let slice = &data[off..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    let s = String::from_utf8_lossy(&slice[..end]).into_owned();
    (s, end + 1) // +1 for the NUL
}

const fn align4(off: usize) -> usize {
    (off + 3) & !3
}

// ---------------------------------------------------------------------------
// Leaf parsers
// ---------------------------------------------------------------------------

fn parse_structure_or_class(data: &[u8]) -> CvTypeLeaf {
    // [count:u16][property:u16][field_list:u32][derived:u32][vshape:u32]
    // [size: numeric leaf][name\0][unique_name\0]
    if data.len() < 16 {
        return CvTypeLeaf::Unknown {
            leaf_kind: 0x1004,
            raw: data.to_vec(),
        };
    }
    let member_count = read_u16(data, 0);
    let property = read_u16(data, 2);
    let field_list_index = read_u32(data, 4);
    let derived_index = read_u32(data, 8);
    let vshape_index = read_u32(data, 12);
    let (size, size_bytes) = decode_numeric_leaf(data, 16).unwrap_or((0, 2));
    let name_off = 16 + size_bytes;
    let (name, name_bytes) = read_cstring(data, name_off);
    let unique_off = name_off + name_bytes;
    let (unique_name, _) = read_cstring(data, unique_off);
    CvTypeLeaf::Structure {
        member_count,
        property,
        field_list_index,
        derived_index,
        vshape_index,
        size,
        name,
        unique_name,
    }
}

fn parse_union(data: &[u8]) -> CvTypeLeaf {
    // [count:u16][property:u16][field_list:u32][size: numeric leaf][name\0][unique_name\0]
    if data.len() < 8 {
        return CvTypeLeaf::Unknown {
            leaf_kind: 0x1006,
            raw: data.to_vec(),
        };
    }
    let member_count = read_u16(data, 0);
    let property = read_u16(data, 2);
    let field_list_index = read_u32(data, 4);
    let (size, size_bytes) = decode_numeric_leaf(data, 8).unwrap_or((0, 2));
    let name_off = 8 + size_bytes;
    let (name, name_bytes) = read_cstring(data, name_off);
    let (unique_name, _) = read_cstring(data, name_off + name_bytes);
    CvTypeLeaf::Union {
        member_count,
        property,
        field_list_index,
        size,
        name,
        unique_name,
    }
}

fn parse_enum_leaf(data: &[u8]) -> CvTypeLeaf {
    // [count:u16][property:u16][underlying_type:u32][field_list:u32][name\0][unique_name\0]
    if data.len() < 12 {
        return CvTypeLeaf::Unknown {
            leaf_kind: 0x1007,
            raw: data.to_vec(),
        };
    }
    let member_count = read_u16(data, 0);
    let property = read_u16(data, 2);
    let underlying_type = read_u32(data, 4);
    let field_list_index = read_u32(data, 8);
    let (name, name_bytes) = read_cstring(data, 12);
    let (unique_name, _) = read_cstring(data, 12 + name_bytes);
    CvTypeLeaf::Enum {
        member_count,
        property,
        underlying_type,
        field_list_index,
        name,
        unique_name,
    }
}

fn parse_procedure(data: &[u8]) -> CvTypeLeaf {
    // [return_type:u32][calling_conv:u8][func_attr:u8][param_count:u16][arglist:u32]
    if data.len() < 12 {
        return CvTypeLeaf::Unknown {
            leaf_kind: 0x1008,
            raw: data.to_vec(),
        };
    }
    CvTypeLeaf::Procedure {
        return_type: read_u32(data, 0),
        calling_convention: data[4],
        func_attr: data[5],
        param_count: read_u16(data, 6),
        arglist_index: read_u32(data, 8),
    }
}

fn parse_mfunction(data: &[u8]) -> CvTypeLeaf {
    // [return:u32][class:u32][this:u32][call:u8][attr:u8][count:u16][arglist:u32][this_adj:i32]
    if data.len() < 24 {
        return CvTypeLeaf::Unknown {
            leaf_kind: 0x1009,
            raw: data.to_vec(),
        };
    }
    let this_adjust = i32::from_le_bytes(data[20..24].try_into().unwrap_or([0; 4]));
    CvTypeLeaf::MFunction {
        return_type: read_u32(data, 0),
        class_index: read_u32(data, 4),
        this_type: read_u32(data, 8),
        calling_convention: data[12],
        func_attr: data[13],
        param_count: read_u16(data, 14),
        arglist_index: read_u32(data, 16),
        this_adjust,
    }
}

fn parse_pointer(data: &[u8]) -> CvTypeLeaf {
    // [type:u32][attributes:u32]
    CvTypeLeaf::Pointer {
        target_type: read_u32(data, 0),
        attributes: if data.len() >= 8 { read_u32(data, 4) } else { 0 },
    }
}

fn parse_array_leaf(data: &[u8]) -> CvTypeLeaf {
    // [element_type:u32][index_type:u32][size: numeric leaf][name\0]
    if data.len() < 8 {
        return CvTypeLeaf::Unknown {
            leaf_kind: 0x1003,
            raw: data.to_vec(),
        };
    }
    let element_type = read_u32(data, 0);
    let index_type = read_u32(data, 4);
    let (size, size_bytes) = decode_numeric_leaf(data, 8).unwrap_or((0, 2));
    let (name, _) = read_cstring(data, 8 + size_bytes);
    CvTypeLeaf::Array {
        element_type,
        index_type,
        size,
        name,
    }
}

fn parse_modifier(data: &[u8]) -> CvTypeLeaf {
    // [modified_type:u32][flags:u16]
    CvTypeLeaf::Modifier {
        modified_type: read_u32(data, 0),
        modifier_flags: if data.len() >= 6 { read_u16(data, 4) } else { 0 },
    }
}

fn parse_bitfield(data: &[u8]) -> CvTypeLeaf {
    // [base_type:u32][length:u8][position:u8]
    if data.len() < 6 {
        return CvTypeLeaf::Unknown {
            leaf_kind: 0x1205,
            raw: data.to_vec(),
        };
    }
    CvTypeLeaf::Bitfield {
        base_type: read_u32(data, 0),
        length: data[4],
        position: data[5],
    }
}

fn parse_arglist(data: &[u8]) -> CvTypeLeaf {
    // [count:u32][type_index × count]
    if data.len() < 4 {
        return CvTypeLeaf::Arglist { arg_types: vec![] };
    }
    let count_raw = read_u32(data, 0);
    // Cap count to what the buffer can actually hold to avoid huge allocations.
    let max_possible = (data.len().saturating_sub(4)) / 4;
    let count = (count_raw as usize).min(max_possible);
    let mut arg_types = Vec::with_capacity(count);
    for i in 0..count {
        let off = 4 + i * 4; // safe: count <= max_possible so off+4 <= data.len()
        arg_types.push(read_u32(data, off));
    }
    CvTypeLeaf::Arglist { arg_types }
}

fn parse_fieldlist(data: &[u8]) -> CvTypeLeaf {
    let mut members = Vec::new();
    let mut enumerators = Vec::new();
    let mut pos = 0usize;

    while pos + 2 <= data.len() {
        // LF_PAD bytes are single bytes 0xF0..=0xFF; reading them as a u16 leaf
        // yields a bogus code and truncates the list.
        let b = data[pos];
        if b >= 0xF0 {
            let pad = (b & 0x0F) as usize;
            if pad == 0 { break; }
            pos += pad;
            continue;
        }
        let leaf = read_u16(data, pos);
        match leaf {
            0x150D => {
                // LF_MEMBER: [attr:u16][type:u32][offset: numeric leaf][name\0]
                if pos + 8 > data.len() {
                    break;
                }
                let attr = read_u16(data, pos + 2);
                let type_index = read_u32(data, pos + 4);
                // An unrecognized numeric tag has an unknown length; skipping a
                // guessed 2 bytes would desync every later member.
                let Some((offset, offset_bytes)) = decode_numeric_leaf(data, pos + 8) else { break };
                let name_off = pos + 8 + offset_bytes;
                let (name, name_bytes) = read_cstring(data, name_off);
                members.push(CvFieldMember {
                    attr,
                    type_index,
                    offset,
                    name,
                });
                pos = align4(name_off + name_bytes);
            }
            0x1502 => {
                // LF_ENUMERATE: [attr:u16][value: numeric leaf][name\0]
                if pos + 4 > data.len() {
                    break;
                }
                let attr = read_u16(data, pos + 2);
                let Some((value, val_bytes)) = decode_numeric_leaf(data, pos + 4) else { break };
                let name_off = pos + 4 + val_bytes;
                let (name, name_bytes) = read_cstring(data, name_off);
                enumerators.push(CvEnumerator { attr, value, name });
                pos = align4(name_off + name_bytes);
            }
            0x1400 => {
                // LF_BCLASS: [attr:u16][type:u32][offset: numeric leaf]
                // The first entry of every derived C++ class — falling through
                // to `break` here dropped the whole member list.
                if pos + 8 > data.len() { break; }
                let Some((_, off_bytes)) = decode_numeric_leaf(data, pos + 8) else { break };
                pos = align4(pos + 8 + off_bytes);
            }
            0x1401 | 0x1402 => {
                // LF_VBCLASS / LF_IVBCLASS:
                // [attr:u16][btype:u32][vbptr:u32][vbpoff: num][vbind: num]
                if pos + 12 > data.len() { break; }
                let Some((_, a)) = decode_numeric_leaf(data, pos + 12) else { break };
                let Some((_, b2)) = decode_numeric_leaf(data, pos + 12 + a) else { break };
                pos = align4(pos + 12 + a + b2);
            }
            0x1409 => {
                // LF_VFUNCTAB: [pad:u16][type:u32]
                if pos + 8 > data.len() { break; }
                pos = align4(pos + 8);
            }
            0x150E => {
                // LF_STMEMBER: [attr:u16][type:u32][name ]
                if pos + 8 > data.len() { break; }
                let (_, name_bytes) = read_cstring(data, pos + 8);
                pos = align4(pos + 8 + name_bytes);
            }
            0x150F => {
                // LF_METHOD: [count:u16][mlist:u32][name ]
                if pos + 8 > data.len() { break; }
                let (_, name_bytes) = read_cstring(data, pos + 8);
                pos = align4(pos + 8 + name_bytes);
            }
            0x1511 => {
                // LF_ONEMETHOD: [attr:u16][type:u32]([vbaseoff:u32])[name ]
                // The vbaseoff word is present only for introducing virtuals
                // (attr mprop field, bits 2-4, == 4 or 6).
                if pos + 8 > data.len() { break; }
                let attr = read_u16(data, pos + 2);
                let mprop = (attr >> 2) & 0x7;
                let extra = usize::from(mprop == 4 || mprop == 6) * 4;
                if pos + 8 + extra > data.len() { break; }
                let (_, name_bytes) = read_cstring(data, pos + 8 + extra);
                pos = align4(pos + 8 + extra + name_bytes);
            }
            0x1510 => {
                // LF_NESTTYPE: [pad:u16][type:u32][name ]
                if pos + 8 > data.len() { break; }
                let (_, name_bytes) = read_cstring(data, pos + 8);
                pos = align4(pos + 8 + name_bytes);
            }
            0x1404 => {
                // LF_INDEX: continuation record. Following it needs the caller's
                // record table, which this function does not have, so stop here
                // rather than recursing blindly.
                break;
            }
            _ => break,
        }
    }

    CvTypeLeaf::FieldList {
        members,
        enumerators,
    }
}

// ---------------------------------------------------------------------------
// CodeViewTypeParser
// ---------------------------------------------------------------------------

/// Stateful parser for a `CodeView` TPI (type information) stream.
///
/// Feed raw TPI payload bytes (after any stream header) via
/// `parse_stream()`. Alternatively, parse individual records with
/// `parse_one()`.
#[derive(Debug, Default)]
pub struct CodeViewTypeParser {
    /// Parsed records, ordered by type index.
    records: Vec<ParsedTypeRecord>,
    /// Fast index: `type_index` → position in `records`.
    index_map: HashMap<u32, usize>,
    /// Next TPI index to assign (starts at 0x1000).
    next_index: u32,
    /// Why the last `parse_stream` call stopped.
    stop_reason: Option<TypeStreamStop>,
}

impl CodeViewTypeParser {
    /// Create a new parser ready to accept TPI stream bytes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            index_map: HashMap::new(),
            next_index: 0x1000,
            stop_reason: None,
        }
    }

    /// Create a parser that assigns type indices starting at `start_index`.
    ///
    /// The TPI header's `TypeIndexBegin` is not always 0x1000 (a type server or
    /// precompiled header can reserve low indices), and hardcoding 0x1000 then
    /// numbers every record too low. Values below 0x1000 are reserved for
    /// primitives and are clamped up to 0x1000.
    #[must_use]
    pub fn with_start_index(start_index: u32) -> Self {
        Self {
            records: Vec::new(),
            index_map: HashMap::new(),
            next_index: start_index.max(0x1000),
            stop_reason: None,
        }
    }

    /// Parse an entire TPI stream payload (bytes immediately after the
    /// stream header).
    ///
    /// Fills `self.records` and returns the number of records parsed.
    ///
    /// Parsing is tolerant: a malformed or truncated record ends the scan and
    /// the records read so far are kept. Call [`Self::stop_reason`] to find
    /// out whether the stream was consumed completely — the record count
    /// alone cannot distinguish a 50-record stream from a 50,000-record
    /// stream truncated after the 50th.
    pub fn parse_stream(&mut self, data: &[u8]) -> usize {
        let mut pos = 0usize;
        let start = self.records.len();

        let stop = loop {
            if pos == data.len() {
                break TypeStreamStop::Complete;
            }
            if pos + 4 > data.len() {
                break TypeStreamStop::TrailingBytes {
                    remaining: data.len() - pos,
                };
            }
            let record_len = read_u16(data, pos) as usize;
            if record_len < 2 {
                break TypeStreamStop::BadRecordLength {
                    offset: pos,
                    len: record_len,
                };
            }
            let record_end = pos + 2 + record_len;
            if record_end > data.len() {
                break TypeStreamStop::Truncated {
                    offset: pos,
                    needed: record_end,
                    available: data.len(),
                };
            }
            let leaf_kind = read_u16(data, pos + 2);
            let body = data.get(pos + 4..record_end).unwrap_or_default();
            let leaf = Self::parse_leaf(leaf_kind, body);
            let type_index = self.next_index;
            self.next_index = self.next_index.saturating_add(1);
            let idx = self.records.len();
            self.index_map.insert(type_index, idx);
            self.records.push(ParsedTypeRecord { type_index, leaf });
            pos = record_end;
        };
        self.stop_reason = Some(stop);

        self.records.len() - start
    }

    /// Why the last [`Self::parse_stream`] call stopped, or `None` if it has
    /// never been called.
    ///
    /// Anything other than [`TypeStreamStop::Complete`] means the tail of the
    /// stream was not decoded and type-index lookups into it will miss.
    #[must_use]
    pub const fn stop_reason(&self) -> Option<TypeStreamStop> {
        self.stop_reason
    }

    /// Parse a single leaf given its `leaf_kind` tag and payload body.
    fn parse_leaf(leaf_kind: u16, body: &[u8]) -> CvTypeLeaf {
        match leaf_kind {
            0x1004 | 0x1005 => parse_structure_or_class(body),
            0x1006 => parse_union(body),
            0x1007 => parse_enum_leaf(body),
            0x1008 => parse_procedure(body),
            0x1009 => parse_mfunction(body),
            0x1002 => parse_pointer(body),
            0x1003 => parse_array_leaf(body),
            0x1001 => parse_modifier(body),
            0x1205 => parse_bitfield(body),
            0x1201 => parse_arglist(body),
            0x1203 => parse_fieldlist(body),
            _ => CvTypeLeaf::Unknown {
                leaf_kind,
                raw: body.to_vec(),
            },
        }
    }

    /// Look up a record by its TPI type index.
    #[must_use]
    pub fn lookup(&self, type_index: u32) -> Option<&ParsedTypeRecord> {
        self.index_map
            .get(&type_index)
            .and_then(|&pos| self.records.get(pos))
    }

    /// All parsed records.
    #[must_use]
    pub fn records(&self) -> &[ParsedTypeRecord] {
        &self.records
    }

    /// Number of records parsed.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if no records have been parsed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Find all struct/class records by name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Vec<&ParsedTypeRecord> {
        self.records
            .iter()
            .filter(|r| r.leaf.name() == Some(name))
            .collect()
    }

    /// All struct/class/union records (not forward refs).
    #[must_use]
    pub fn aggregate_types(&self) -> Vec<&ParsedTypeRecord> {
        self.records
            .iter()
            .filter(|r| r.leaf.is_aggregate() && !r.leaf.is_forward_ref())
            .collect()
    }

    /// All forward reference records.
    #[must_use]
    pub fn forward_refs(&self) -> Vec<&ParsedTypeRecord> {
        self.records
            .iter()
            .filter(|r| r.leaf.is_forward_ref())
            .collect()
    }

    /// Resolve a forward reference to its concrete definition.
    ///
    /// Returns the first non-forward-ref record with the same name, or `None`.
    #[must_use]
    pub fn resolve_forward_ref(&self, fwd: &ParsedTypeRecord) -> Option<&ParsedTypeRecord> {
        let name = fwd.leaf.name()?;
        self.records
            .iter()
            .find(|r| r.type_index != fwd.type_index && r.leaf.name() == Some(name) && !r.leaf.is_forward_ref())
    }

    /// Build a summary map: `name → size` for all non-forward-ref aggregates.
    #[must_use]
    pub fn size_map(&self) -> HashMap<String, u64> {
        let mut map = HashMap::new();
        for rec in self.aggregate_types() {
            let size = match &rec.leaf {
                CvTypeLeaf::Structure { size, name, .. }
                | CvTypeLeaf::Union { size, name, .. } => Some((name.clone(), *size)),
                _ => None,
            };
            if let Some((name, sz)) = size
                && !name.is_empty() {
                    map.insert(name, sz);
                }
        }
        map
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_structure_record(name: &str, size: u16) -> Vec<u8> {
        // Build an LF_STRUCTURE payload:
        // [count:u16=0][property:u16=0][field_list:u32=0][derived:u32=0][vshape:u32=0]
        // [size: inline u16][name\0][unique_name\0]
        let mut body = vec![0u8; 16]; // count+property+field+derived+vshape
        body.extend_from_slice(&size.to_le_bytes()); // inline numeric leaf
        body.extend_from_slice(name.as_bytes());
        body.push(0); // NUL
        body.push(0); // unique_name = empty
        // Wrap in a record: [len:u16][leaf:u16][body]
        let leaf: u16 = 0x1005; // LF_STRUCTURE
        let len = crate::casts::usize_to_u16(2 + body.len());
        let mut rec = Vec::new();
        rec.extend_from_slice(&len.to_le_bytes());
        rec.extend_from_slice(&leaf.to_le_bytes());
        rec.extend_from_slice(&body);
        rec
    }

    #[test]
    fn parse_structure_record() {
        let data = build_structure_record("MyStruct", 64);
        let mut parser = CodeViewTypeParser::new();
        let count = parser.parse_stream(&data);
        assert_eq!(count, 1);
        let rec = parser.lookup(0x1000).unwrap();
        match &rec.leaf {
            CvTypeLeaf::Structure { name, size, .. } => {
                assert_eq!(name, "MyStruct");
                assert_eq!(*size, 64);
            }
            other => panic!("expected Structure, got {other:?}"),
        }
    }

    #[test]
    fn parse_multiple_records() {
        let mut data = build_structure_record("Foo", 8);
        data.extend(build_structure_record("Bar", 16));
        let mut parser = CodeViewTypeParser::new();
        let count = parser.parse_stream(&data);
        assert_eq!(count, 2);
        assert_eq!(parser.find_by_name("Foo").len(), 1);
        assert_eq!(parser.find_by_name("Bar").len(), 1);
    }

    #[test]
    fn pointer_size_32bit() {
        let leaf = CvTypeLeaf::Pointer {
            target_type: 0x74,
            attributes: 10, // CV_PTR_NEAR32
        };
        assert_eq!(leaf.pointer_size(), Some(4));
    }

    #[test]
    fn pointer_size_64bit() {
        let leaf = CvTypeLeaf::Pointer {
            target_type: 0x74,
            attributes: 12, // CV_PTR_64
        };
        assert_eq!(leaf.pointer_size(), Some(8));
    }

    #[test]
    fn decode_numeric_leaf_inline() {
        // Value < 0x8000 is stored directly in the u16 tag.
        let data = [0x40u8, 0x00u8]; // value = 0x0040 = 64
        let (v, bytes) = decode_numeric_leaf(&data, 0).unwrap();
        assert_eq!(v, 64);
        assert_eq!(bytes, 2);
    }

    #[test]
    fn decode_numeric_leaf_ulong() {
        // LF_ULONG (0x8004) followed by 4-byte LE u32.
        let mut data = vec![0x04u8, 0x80u8]; // LF_ULONG tag
        data.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let (v, bytes) = decode_numeric_leaf(&data, 0).unwrap();
        assert_eq!(v, 0xDEAD_BEEF);
        assert_eq!(bytes, 6);
    }

    #[test]
    fn aggregate_types_excludes_forward_refs() {
        // Build a forward-reference record (property bit 7 set).
        let leaf: u16 = 0x1005;
        let mut body = vec![0u8; 16];
        body[2] = 0x80; // property |= 0x80 = forward-ref
        body.extend_from_slice(&[0x00, 0x00]); // size = 0
        body.extend_from_slice(b"FwdRef\0\0");
        let len = crate::casts::usize_to_u16(2 + body.len());
        let mut data = vec![];
        data.extend_from_slice(&len.to_le_bytes());
        data.extend_from_slice(&leaf.to_le_bytes());
        data.extend_from_slice(&body);

        let mut parser = CodeViewTypeParser::new();
        parser.parse_stream(&data);
        assert_eq!(parser.aggregate_types().len(), 0);
        assert_eq!(parser.forward_refs().len(), 1);
    }

    #[test]
    fn size_map() {
        let mut data = build_structure_record("Alpha", 32);
        data.extend(build_structure_record("Beta", 48));
        let mut parser = CodeViewTypeParser::new();
        parser.parse_stream(&data);
        let map = parser.size_map();
        assert_eq!(map.get("Alpha"), Some(&32u64));
        assert_eq!(map.get("Beta"), Some(&48u64));
    }
}
