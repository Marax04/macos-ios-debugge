//! `CodeView` type information parser.
//!
//! Parses `CodeView` type records from a TPI (Type Information) stream.
//! Handles `LF_STRUCTURE`, `LF_CLASS`, `LF_UNION`, `LF_ENUM`,
//! `LF_PROCEDURE`, `LF_MFUNCTION`, `LF_POINTER`, `LF_ARRAY`,
//! `LF_MODIFIER`, `LF_BITFIELD`, `LF_ARGLIST`, and `LF_FIELDLIST`
//! leaf records, plus `LF_MEMBER` and `LF_ENUMERATE` sub-records.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use super::{read_u16, read_u32};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors produced by the `CodeView` type parser.
#[derive(Debug)]
pub enum TypeParseError {
    /// The buffer is too short to contain a complete record.
    BufferTooShort {
        /// Number of bytes required to finish the read.
        needed: usize,
        /// Number of bytes actually available.
        available: usize,
    },
    /// A type index referenced by a record is outside the known range.
    TypeIndexOob(u32),
    /// A numeric leaf value that should fit in a `u32` was too large.
    NumericOverflow,
    /// A string was not valid UTF-8.
    Utf8(std::str::Utf8Error),
}

impl std::fmt::Display for TypeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooShort { needed, available } => {
                write!(f, "buffer too short: need {needed}, have {available}")
            }
            Self::TypeIndexOob(idx) => write!(f, "type index {idx:#x} out of range"),
            Self::NumericOverflow => write!(f, "numeric leaf overflow"),
            Self::Utf8(e) => write!(f, "UTF-8 error: {e}"),
        }
    }
}

impl std::error::Error for TypeParseError {}

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
            let v = super::casts::u8_as_i8(data.get(off + 2).copied()?);
            Some((super::casts::i8_sext_u64(v), 3))
        }
        0x8001 => {
            // LF_SHORT — 2-byte signed
            if off + 4 > data.len() {
                return None;
            }
            let v = i16::from_le_bytes([data[off + 2], data[off + 3]]);
            Some((super::casts::i16_sext_u64(v), 4))
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
            Some((super::casts::i32_sext_u64(v), 6))
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
            Some((super::casts::i64_as_u64(v), 10))
        }
        0x800A => {
            // LF_UQUADWORD — 8-byte unsigned
            if off + 10 > data.len() {
                return None;
            }
            let v = u64::from_le_bytes(data[off + 2..off + 10].try_into().ok()?);
            Some((v, 10))
        }
        _ => Some((0, 2)), // unknown numeric tag — skip
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
        /// Number of members in the aggregate.
        member_count: u16,
        /// Property bitfield (packed, fwdref, nested, ...).
        property: u16,
        /// Type index of the `LF_FIELDLIST` describing the members.
        field_list_index: u32,
        /// Type index of the derivation list (0 if none).
        derived_index: u32,
        /// Type index of the vtable shape (0 if none).
        vshape_index: u32,
        /// Size of the aggregate in bytes.
        size: u64,
        /// Type name.
        name: String,
        /// Decorated (mangled) unique name, if present.
        unique_name: String,
    },
    /// `LF_UNION` — a union.
    Union {
        /// Number of members in the union.
        member_count: u16,
        /// Property bitfield (packed, fwdref, nested, ...).
        property: u16,
        /// Type index of the `LF_FIELDLIST` describing the members.
        field_list_index: u32,
        /// Size of the union in bytes.
        size: u64,
        /// Type name.
        name: String,
        /// Decorated (mangled) unique name, if present.
        unique_name: String,
    },
    /// `LF_ENUM` — an enumeration.
    Enum {
        /// Number of enumerators.
        member_count: u16,
        /// Property bitfield (packed, fwdref, nested, ...).
        property: u16,
        /// Type index of the underlying integer type.
        underlying_type: u32,
        /// Type index of the `LF_FIELDLIST` holding the enumerators.
        field_list_index: u32,
        /// Type name.
        name: String,
        /// Decorated (mangled) unique name, if present.
        unique_name: String,
    },
    /// `LF_PROCEDURE` — a procedure (free function) type.
    Procedure {
        /// Type index of the return type.
        return_type: u32,
        /// Calling convention (`CV_call_e`).
        calling_convention: u8,
        /// Function attributes (cxxreturnudt, ctor, ...).
        func_attr: u8,
        /// Number of parameters.
        param_count: u16,
        /// Type index of the `LF_ARGLIST` parameter list.
        arglist_index: u32,
    },
    /// `LF_MFUNCTION` — a member function.
    MFunction {
        /// Type index of the return type.
        return_type: u32,
        /// Type index of the containing class.
        class_index: u32,
        /// Type index of the `this` pointer type (0 for static).
        this_type: u32,
        /// Calling convention (`CV_call_e`).
        calling_convention: u8,
        /// Function attributes (cxxreturnudt, ctor, ...).
        func_attr: u8,
        /// Number of parameters (excluding `this`).
        param_count: u16,
        /// Type index of the `LF_ARGLIST` parameter list.
        arglist_index: u32,
        /// `this` pointer adjustment for multiple inheritance.
        this_adjust: i32,
    },
    /// `LF_POINTER` — a pointer type.
    Pointer {
        /// Type index of the pointee type.
        target_type: u32,
        /// Pointer attributes (kind, mode, size, const/volatile flags).
        attributes: u32,
    },
    /// `LF_ARRAY` — an array type.
    Array {
        /// Type index of the element type.
        element_type: u32,
        /// Type index of the indexing type (usually an integer).
        index_type: u32,
        /// Total array size in bytes.
        size: u64,
        /// Optional array type name.
        name: String,
    },
    /// `LF_MODIFIER` — a type modifier (const/volatile/unaligned).
    Modifier {
        /// Type index of the type being modified.
        modified_type: u32,
        /// Modifier bitfield: const=1, volatile=2, unaligned=4.
        modifier_flags: u16,
    },
    /// `LF_BITFIELD` — a bitfield type.
    Bitfield {
        /// Type index of the underlying integer type.
        base_type: u32,
        /// Width of the bitfield in bits.
        length: u8,
        /// Starting bit position within the underlying type.
        position: u8,
    },
    /// `LF_ARGLIST` — argument-type list.
    Arglist {
        /// Type indices of the arguments, in order.
        arg_types: Vec<u32>,
    },
    /// `LF_FIELDLIST` — field descriptor list (members and enumerators).
    FieldList {
        /// Data members decoded from the list.
        members: Vec<CvFieldMember>,
        /// Enum enumerators decoded from the list.
        enumerators: Vec<CvEnumerator>,
    },
    /// Any other leaf type (raw bytes stored for debugging).
    Unknown {
        /// The raw `LF_*` leaf kind value.
        leaf_kind: u16,
        /// The undecoded record bytes.
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
            let ptr_mode = (attributes >> 5) & 0x7;
            Some(if ptr_mode == 4 { 8 } else { 4 })
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
    /// TPI type index (starts at the parser's index base, 0x1000 by default).
    pub type_index: u32,
    /// The parsed leaf.
    pub leaf: CvTypeLeaf,
    /// Byte offset of this record within the stream passed to `parse_stream`.
    ///
    /// Recorded where it is known — at the point the record is consumed —
    /// rather than reconstructed afterwards by a second scan that has to guess
    /// how far the parser advanced. `TpiReader` used to do exactly that guess.
    pub stream_offset: usize,
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
        let leaf = read_u16(data, pos);
        match leaf {
            0x150D => {
                // LF_MEMBER: [attr:u16][type:u32][offset: numeric leaf][name\0]
                if pos + 8 > data.len() {
                    break;
                }
                let attr = read_u16(data, pos + 2);
                let type_index = read_u32(data, pos + 4);
                let (offset, offset_bytes) = decode_numeric_leaf(data, pos + 8).unwrap_or((0, 2));
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
                let (value, val_bytes) = decode_numeric_leaf(data, pos + 4).unwrap_or((0, 2));
                let name_off = pos + 4 + val_bytes;
                let (name, name_bytes) = read_cstring(data, name_off);
                enumerators.push(CvEnumerator { attr, value, name });
                pos = align4(name_off + name_bytes);
            }
            0x0001..=0x00FF => {
                // LF_PAD* — padding bytes; low nibble is the pad length.
                let pad = (leaf & 0x0F) as usize;
                if pad == 0 {
                    break;
                }
                pos += pad;
            }
            // Sub-records that carry no data-member payload but MUST be
            // skipped (not break-ed) so LF_MEMBERs after them are kept —
            // real C++ fieldlists open with base classes / vtables / methods.
            0x1400 => {
                // LF_BCLASS: [attr:u16][base_type:u32][offset: numeric]
                if pos + 8 > data.len() {
                    break;
                }
                let (_, nb) = decode_numeric_leaf(data, pos + 8).unwrap_or((0, 2));
                pos = align4(pos + 8 + nb);
            }
            0x1401 | 0x1402 => {
                // LF_VBCLASS / LF_IVBCLASS:
                // [attr:u16][btype:u32][vbtype:u32][vbpoff: numeric][vboff: numeric]
                if pos + 12 > data.len() {
                    break;
                }
                let (_, n1) = decode_numeric_leaf(data, pos + 12).unwrap_or((0, 2));
                let (_, n2) = decode_numeric_leaf(data, pos + 12 + n1).unwrap_or((0, 2));
                pos = align4(pos + 12 + n1 + n2);
            }
            0x1404 | 0x1409 => {
                // LF_INDEX (continuation) / LF_VFUNCTAB: [pad:u16][type:u32]
                if pos + 8 > data.len() {
                    break;
                }
                pos += 8;
            }
            0x150E..=0x1510 => {
                // LF_STMEMBER / LF_METHOD / LF_NESTTYPE:
                // [attr-or-count:u16][type-or-mlist:u32][name\0]
                if pos + 8 > data.len() {
                    break;
                }
                let (_, name_bytes) = read_cstring(data, pos + 8);
                pos = align4(pos + 8 + name_bytes);
            }
            0x1511 => {
                // LF_ONEMETHOD: [attr:u16][type:u32][vbaseoff:u32 if
                // introducing-virtual][name\0]; mprop = (attr >> 2) & 7,
                // 4 (intro) / 6 (pure intro) carry the vbaseoff.
                if pos + 8 > data.len() {
                    break;
                }
                let attr = read_u16(data, pos + 2);
                let mprop = (attr >> 2) & 0x7;
                let extra = if mprop == 4 || mprop == 6 { 4 } else { 0 };
                let (_, name_bytes) = read_cstring(data, pos + 8 + extra);
                pos = align4(pos + 8 + extra + name_bytes);
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
}

impl CodeViewTypeParser {
    /// Create a new parser ready to accept TPI stream bytes, numbering types
    /// from the usual `0x1000`.
    #[must_use]
    pub fn new() -> Self {
        Self::with_index_base(0x1000)
    }

    /// Create a parser that numbers the first record `base`.
    ///
    /// A TPI header declares `type_index_min`, and it is not always `0x1000` —
    /// an IPI stream, or a TPI produced by an incremental link, can start
    /// higher. Hardcoding `0x1000` does not fail loudly: it renumbers every
    /// type, so a lookup by the index the PDB itself uses either finds nothing
    /// or, when the stream is long enough, finds a completely unrelated type
    /// and reports it as the answer.
    #[must_use]
    pub fn with_index_base(base: u32) -> Self {
        Self {
            records: Vec::new(),
            index_map: HashMap::new(),
            next_index: base,
        }
    }

    /// The index that will be assigned to the next record parsed.
    #[must_use]
    pub const fn next_index(&self) -> u32 {
        self.next_index
    }

    /// Parse an entire TPI stream payload (bytes immediately after the
    /// stream header).
    ///
    /// Fills `self.records` and returns the number of records parsed.
    pub fn parse_stream(&mut self, data: &[u8]) -> usize {
        let mut pos = 0usize;
        let start = self.records.len();

        while pos + 4 <= data.len() {
            let record_len = read_u16(data, pos) as usize;
            if record_len < 2 {
                break;
            }
            let record_end = pos + 2 + record_len;
            if record_end > data.len() {
                break;
            }
            let leaf_kind = read_u16(data, pos + 2);
            let body = &data[pos + 4..record_end];
            let leaf = Self::parse_leaf(leaf_kind, body);
            let type_index = self.next_index;
            self.next_index = self.next_index.saturating_add(1);
            let idx = self.records.len();
            self.index_map.insert(type_index, idx);
            self.records.push(ParsedTypeRecord { type_index, leaf, stream_offset: pos });
            pos = record_end;
        }

        self.records.len() - start
    }

    /// Parse a single leaf given its `leaf_kind` tag and payload body.
    fn parse_leaf(leaf_kind: u16, body: &[u8]) -> CvTypeLeaf {
        match leaf_kind {
            // 0x10xx = legacy leaf era; 0x15xx = modern MSVC leaves (identical
            // layouts, adding unique_name) — real PDBs emit the 0x15xx codes.
            0x1004 | 0x1005 | 0x1504 | 0x1505 => parse_structure_or_class(body),
            0x1006 | 0x1506 => parse_union(body),
            0x1007 | 0x1507 => parse_enum_leaf(body),
            0x1008 => parse_procedure(body),
            0x1009 => parse_mfunction(body),
            0x1002 => parse_pointer(body),
            0x1003 | 0x1503 => parse_array_leaf(body),
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
// Evaluator bridge — import parsed CodeView structs into the expression
// evaluator's TypeSystem (accurate offsets/types from LF_FIELDLIST).
// ---------------------------------------------------------------------------

/// Map a `CodeView` member type index to an evaluator primitive type name.
///
/// Maps by width and signedness. Returns `None` for member types that don't
/// map to a scalar primitive (nested aggregates, unknown) — those members
/// are skipped.
fn member_primitive_name(type_index: u32) -> Option<&'static str> {
    use rustre_symbols::TypeInfo;
    // NOTE: TypeInfo widths are in BITS.
    match super::primitive_type(type_index) {
        TypeInfo::Int { width, signed } => Some(match (width, signed) {
            (8, true) => "i8", (8, false) => "u8",
            (16, true) => "i16", (16, false) => "u16",
            (32, true) => "i32", (32, false) => "u32",
            (64, true) => "i64", _ => "u64",
        }),
        TypeInfo::Float { width: 32 } => Some("f32"),
        TypeInfo::Float { .. } => Some("f64"),
        TypeInfo::Pointer { .. } => Some("u64"),
        _ => None,
    }
}

/// Register every `LF_STRUCTURE` the parser resolved into `ts`.
///
/// Uses accurate `LF_FIELDLIST` member offsets/types via
/// `TypeSystem::define_struct`, so `((Name*)p)->field` resolves in the
/// expression evaluator. Members whose type doesn't map to a scalar
/// primitive are skipped. Returns the number of structs registered.
#[must_use]
pub fn import_structs_into(
    parser: &CodeViewTypeParser,
    ts: &mut crate::expression_evaluator::TypeSystem,
) -> usize {
    use crate::expression_evaluator::{StructField, TypeId};
    // Pass 1: forward-declare every aggregate (name + `Name*` pointer) so that
    // self/mutually-referential pointer members can resolve `Target*` in pass 2.
    let mut ids: std::collections::HashMap<u32, TypeId> = std::collections::HashMap::new();
    for rec in parser.records() {
        if let Some((name, _)) = aggregate_at(parser, rec.type_index) {
            let id = ts.forward_declare_struct(name);
            ids.insert(rec.type_index, id);
        }
    }
    // Pass 2: resolve members and fill each aggregate's fields.
    let mut count = 0;
    for rec in parser.records() {
        let Some((_, fl_index)) = aggregate_at(parser, rec.type_index) else { continue };
        let Some(&sid) = ids.get(&rec.type_index) else { continue };
        let Some(fl) = parser.lookup(fl_index) else { continue };
        let CvTypeLeaf::FieldList { members, .. } = &fl.leaf else { continue };
        let mut fields = Vec::new();
        for m in members {
            if let Some(ty) = resolve_member_type(parser, ts, &ids, m.type_index) {
                fields.push(StructField { name: m.name.clone(), ty, offset: m.offset });
            }
        }
        if !fields.is_empty() {
            ts.set_struct_fields(sid, fields);
            count += 1;
        }
    }
    count
}

/// Resolve a member's field type to an evaluator `TypeId`: a scalar primitive,
/// a (forward-declared) aggregate, an array of a resolvable element, or a
/// pointer to an aggregate (typed `Target*`) / plain `u64`.
fn resolve_member_type(
    parser: &CodeViewTypeParser,
    ts: &mut crate::expression_evaluator::TypeSystem,
    ids: &std::collections::HashMap<u32, crate::expression_evaluator::TypeId>,
    type_index: u32,
) -> Option<crate::expression_evaluator::TypeId> {
    if let Some(p) = member_primitive_name(type_index) {
        return ts.lookup_name(p);
    }
    if let Some(&id) = ids.get(&type_index) {
        return Some(id); // nested struct / union
    }
    if let Some((elem_index, total_size)) = array_at(parser, type_index) {
        let elem_ty = member_primitive_name(elem_index)
            .and_then(|p| ts.lookup_name(p))
            .or_else(|| ids.get(&elem_index).copied())?;
        let esz = ts.size_of(elem_ty).unwrap_or(1).max(1);
        return Some(ts.array_of(elem_ty, total_size / esz));
    }
    if let Some(target) = pointer_target_at(parser, type_index) {
        if let Some((tname, _)) = aggregate_at(parser, target) {
            return ts.lookup_name(&format!("{tname}*")); // forward-declared in pass 1
        }
        return ts.lookup_name("u64");
    }
    if let Some(base) = enum_underlying_at(parser, type_index) {
        // An enum member reads as its base integer type.
        return member_primitive_name(base).and_then(|p| ts.lookup_name(p));
    }
    if let Some((base, position, length)) = bitfield_at(parser, type_index) {
        // A bitfield member: `length` bits at `position` within its base int.
        let base_ty = member_primitive_name(base).and_then(|p| ts.lookup_name(p))?;
        return Some(ts.bitfield_of(base_ty, position, length));
    }
    None
}

/// The (name, `field_list_index`) of an aggregate (struct/class or union) at
/// `index`, if that record is one. Unions are imported like structs — a union's
/// members sit at offset 0, which the `LF_FIELDLIST` already reports, so field
/// reads work correctly.
fn aggregate_at(parser: &CodeViewTypeParser, index: u32) -> Option<(&str, u32)> {
    match &parser.lookup(index)?.leaf {
        CvTypeLeaf::Structure { name, field_list_index, .. }
        | CvTypeLeaf::Union { name, field_list_index, .. } => Some((name, *field_list_index)),
        _ => None,
    }
}

/// `(element_type_index, total_size_bytes)` if `index` is an `LF_ARRAY`.
fn array_at(parser: &CodeViewTypeParser, index: u32) -> Option<(u32, u64)> {
    match &parser.lookup(index)?.leaf {
        CvTypeLeaf::Array { element_type, size, .. } => Some((*element_type, *size)),
        _ => None,
    }
}

/// The pointee type index if `index` is an `LF_POINTER`.
fn pointer_target_at(parser: &CodeViewTypeParser, index: u32) -> Option<u32> {
    match &parser.lookup(index)?.leaf {
        CvTypeLeaf::Pointer { target_type, .. } => Some(*target_type),
        _ => None,
    }
}

/// The underlying (base) type index if `index` is an `LF_ENUM` — an enum member
/// reads as its base integer type.
fn enum_underlying_at(parser: &CodeViewTypeParser, index: u32) -> Option<u32> {
    match &parser.lookup(index)?.leaf {
        CvTypeLeaf::Enum { underlying_type, .. } => Some(*underlying_type),
        _ => None,
    }
}

/// `(base_type_index, position_bit, length_bits)` if `index` is an `LF_BITFIELD`.
fn bitfield_at(parser: &CodeViewTypeParser, index: u32) -> Option<(u32, u8, u8)> {
    match &parser.lookup(index)?.leaf {
        CvTypeLeaf::Bitfield { base_type, position, length } => Some((*base_type, *position, *length)),
        _ => None,
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
        let len = super::super::casts::usize_to_u16(2 + body.len());
        let mut rec = Vec::new();
        rec.extend_from_slice(&len.to_le_bytes());
        rec.extend_from_slice(&leaf.to_le_bytes());
        rec.extend_from_slice(&body);
        rec
    }

    // Build an LF_MEMBER sub-record, zero-padded to a 4-byte boundary (the
    // fieldlist parser align4's past the padding after each member).
    fn build_member(type_index: u32, offset: u16, name: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0x150Du16.to_le_bytes()); // LF_MEMBER
        b.extend_from_slice(&3u16.to_le_bytes());       // attr = public
        b.extend_from_slice(&type_index.to_le_bytes());
        b.extend_from_slice(&offset.to_le_bytes());      // inline numeric leaf (<0x8000)
        b.extend_from_slice(name.as_bytes());
        b.push(0);
        while b.len() % 4 != 0 { b.push(0); }
        b
    }

    fn wrap_record(leaf: u16, body: &[u8]) -> Vec<u8> {
        let len = super::super::casts::usize_to_u16(2 + body.len());
        let mut rec = len.to_le_bytes().to_vec();
        rec.extend_from_slice(&leaf.to_le_bytes());
        rec.extend_from_slice(body);
        rec
    }

    #[test]
    fn import_structs_into_registers_accurate_fields() {
        // FIELDLIST (index 0x1000) with two i32 members x@0, y@4.
        let mut fl_body = build_member(0x74, 0, "x"); // 0x74 = T_INT4 (i32)
        fl_body.extend(build_member(0x74, 4, "y"));
        let mut stream = wrap_record(0x1203, &fl_body); // LF_FIELDLIST
        // STRUCTURE (index 0x1001) "Point", size 8, referencing field_list 0x1000.
        let mut st_body = Vec::new();
        st_body.extend_from_slice(&2u16.to_le_bytes());        // member_count
        st_body.extend_from_slice(&0u16.to_le_bytes());        // property
        st_body.extend_from_slice(&0x1000u32.to_le_bytes());   // field_list_index
        st_body.extend_from_slice(&0u32.to_le_bytes());        // derived
        st_body.extend_from_slice(&0u32.to_le_bytes());        // vshape
        st_body.extend_from_slice(&8u16.to_le_bytes());        // size (inline numeric)
        st_body.extend_from_slice(b"Point\0");
        st_body.push(0);                                       // unique_name = empty
        stream.extend(wrap_record(0x1004, &st_body));          // LF_STRUCTURE

        let mut parser = CodeViewTypeParser::new();
        assert_eq!(parser.parse_stream(&stream), 2, "two type records");

        let mut ts = crate::expression_evaluator::TypeSystem::with_primitives();
        let n = import_structs_into(&parser, &mut ts);
        assert_eq!(n, 1, "one struct imported");

        // The struct + its named pointer are registered with ACCURATE offsets.
        let point = ts.lookup_name("Point").expect("Point registered");
        assert!(ts.lookup_name("Point*").is_some(), "Point* pointer registered");
        assert_eq!(ts.struct_field(point, "x").unwrap().offset, 0, "x @0");
        assert_eq!(ts.struct_field(point, "y").unwrap().offset, 4, "y @4 (from LF_FIELDLIST, not a lossy stride)");
    }

    #[test]
    fn import_structs_into_handles_nested_struct_members() {
        // Inner (fieldlist 0x1000, struct 0x1001) { i32 v @0 }
        // Outer (fieldlist 0x1002, struct 0x1003) { Inner inner @0; i32 tag @4 }
        let inner_fl = build_member(0x74, 0, "v");
        let mut stream = wrap_record(0x1203, &inner_fl); // 0x1000
        let mut inner_st = Vec::new();
        inner_st.extend_from_slice(&1u16.to_le_bytes());
        inner_st.extend_from_slice(&0u16.to_le_bytes());
        inner_st.extend_from_slice(&0x1000u32.to_le_bytes());
        inner_st.extend_from_slice(&0u32.to_le_bytes());
        inner_st.extend_from_slice(&0u32.to_le_bytes());
        inner_st.extend_from_slice(&4u16.to_le_bytes());
        inner_st.extend_from_slice(b"Inner\0"); inner_st.push(0);
        stream.extend(wrap_record(0x1004, &inner_st)); // 0x1001

        // Outer field list: member "inner" of type 0x1001 (Inner) @0, "tag" i32 @4.
        let mut outer_fl = build_member(0x1001, 0, "inner");
        outer_fl.extend(build_member(0x74, 4, "tag"));
        stream.extend(wrap_record(0x1203, &outer_fl)); // 0x1002
        let mut outer_st = Vec::new();
        outer_st.extend_from_slice(&2u16.to_le_bytes());
        outer_st.extend_from_slice(&0u16.to_le_bytes());
        outer_st.extend_from_slice(&0x1002u32.to_le_bytes());
        outer_st.extend_from_slice(&0u32.to_le_bytes());
        outer_st.extend_from_slice(&0u32.to_le_bytes());
        outer_st.extend_from_slice(&8u16.to_le_bytes());
        outer_st.extend_from_slice(b"Outer\0"); outer_st.push(0);
        stream.extend(wrap_record(0x1004, &outer_st)); // 0x1003

        let mut parser = CodeViewTypeParser::new();
        parser.parse_stream(&stream);
        let mut ts = crate::expression_evaluator::TypeSystem::with_primitives();
        let n = import_structs_into(&parser, &mut ts);
        assert_eq!(n, 2, "both Inner and Outer registered");

        let outer = ts.lookup_name("Outer").expect("Outer");
        // The nested-struct member resolves to the Inner type; tag is i32 @4.
        assert_eq!(ts.struct_field(outer, "inner").unwrap().offset, 0, "inner @0");
        assert_eq!(ts.struct_field(outer, "tag").unwrap().offset, 4, "tag @4");
        let inner_ty = ts.struct_field(outer, "inner").unwrap().ty;
        assert_eq!(ts.lookup_name("Inner"), Some(inner_ty), "inner member typed as Inner");
    }

    #[test]
    fn import_structs_into_handles_bitfield_members() {
        // LF_BITFIELD (0x1000): base u32 (0x75), length 3, position 0.
        let mut bf = 0x75u32.to_le_bytes().to_vec(); // base_type
        bf.push(3);  // length
        bf.push(0);  // position
        let mut stream = wrap_record(0x1205, &bf); // BITFIELD 0x1000
        stream.extend(wrap_record(0x1203, &build_member(0x1000, 0, "f"))); // FIELDLIST 0x1001
        let mut st = Vec::new();
        st.extend_from_slice(&1u16.to_le_bytes());
        st.extend_from_slice(&0u16.to_le_bytes());
        st.extend_from_slice(&0x1001u32.to_le_bytes());
        st.extend_from_slice(&0u32.to_le_bytes());
        st.extend_from_slice(&0u32.to_le_bytes());
        st.extend_from_slice(&4u16.to_le_bytes());
        st.extend_from_slice(b"B\0"); st.push(0);
        stream.extend(wrap_record(0x1004, &st)); // STRUCTURE 0x1002

        let mut parser = CodeViewTypeParser::new();
        parser.parse_stream(&stream);
        let mut ts = crate::expression_evaluator::TypeSystem::with_primitives();
        assert_eq!(import_structs_into(&parser, &mut ts), 1, "B registered");
        let b = ts.lookup_name("B").expect("B");
        // The bitfield member's type is a Bitfield (size = its u32 base = 4).
        let f_ty = ts.struct_field(b, "f").expect("f field").ty;
        assert_eq!(ts.size_of(f_ty), Some(4), "bitfield storage is u32 (4 bytes)");
        assert!(matches!(ts.get(f_ty), Some(crate::expression_evaluator::TypeKind::Bitfield { length: 3, position: 0, .. })));
    }

    #[test]
    fn import_structs_into_handles_enum_members() {
        // LF_ENUM (0x1000): underlying u32 (0x75). Struct S { E e@0 }.
        let mut en = 0u16.to_le_bytes().to_vec();       // count
        en.extend_from_slice(&0u16.to_le_bytes());       // property
        en.extend_from_slice(&0x75u32.to_le_bytes());    // underlying_type = T_UINT4
        en.extend_from_slice(&0u32.to_le_bytes());       // field_list
        en.extend_from_slice(b"E\0"); en.push(0);
        let mut stream = wrap_record(0x1007, &en);       // ENUM 0x1000
        stream.extend(wrap_record(0x1203, &build_member(0x1000, 0, "e"))); // FIELDLIST 0x1001
        let mut st = Vec::new();
        st.extend_from_slice(&1u16.to_le_bytes());
        st.extend_from_slice(&0u16.to_le_bytes());
        st.extend_from_slice(&0x1001u32.to_le_bytes());
        st.extend_from_slice(&0u32.to_le_bytes());
        st.extend_from_slice(&0u32.to_le_bytes());
        st.extend_from_slice(&4u16.to_le_bytes());
        st.extend_from_slice(b"S\0"); st.push(0);
        stream.extend(wrap_record(0x1004, &st));         // STRUCTURE 0x1002

        let mut parser = CodeViewTypeParser::new();
        parser.parse_stream(&stream);
        let mut ts = crate::expression_evaluator::TypeSystem::with_primitives();
        assert_eq!(import_structs_into(&parser, &mut ts), 1, "S registered");
        let s = ts.lookup_name("S").expect("S");
        // The enum member reads as its u32 base type (4 bytes).
        assert_eq!(ts.size_of(ts.struct_field(s, "e").unwrap().ty), Some(4), "enum member e is u32-sized");
    }

    #[test]
    fn import_structs_into_handles_array_members() {
        // LF_ARRAY (0x1000): u32[3] (element 0x75, size 12).
        let mut arr = Vec::new();
        arr.extend_from_slice(&0x75u32.to_le_bytes()); // element_type = T_UINT4
        arr.extend_from_slice(&0x22u32.to_le_bytes()); // index_type (ignored)
        arr.extend_from_slice(&12u16.to_le_bytes());   // size (inline numeric)
        arr.push(0);                                   // name = empty
        let mut stream = wrap_record(0x1003, &arr);    // ARRAY 0x1000
        // FIELDLIST (0x1001): member "arr" of type 0x1000 @0.
        let fl = build_member(0x1000, 0, "arr");
        stream.extend(wrap_record(0x1203, &fl));       // 0x1001
        // STRUCTURE (0x1002) "Buf" { arr } size 12.
        let mut st = Vec::new();
        st.extend_from_slice(&1u16.to_le_bytes());
        st.extend_from_slice(&0u16.to_le_bytes());
        st.extend_from_slice(&0x1001u32.to_le_bytes());
        st.extend_from_slice(&0u32.to_le_bytes());
        st.extend_from_slice(&0u32.to_le_bytes());
        st.extend_from_slice(&12u16.to_le_bytes());
        st.extend_from_slice(b"Buf\0"); st.push(0);
        stream.extend(wrap_record(0x1004, &st));       // 0x1002

        let mut parser = CodeViewTypeParser::new();
        parser.parse_stream(&stream);
        let mut ts = crate::expression_evaluator::TypeSystem::with_primitives();
        assert_eq!(import_structs_into(&parser, &mut ts), 1, "Buf registered");
        let buf = ts.lookup_name("Buf").expect("Buf");
        let arr_field = ts.struct_field(buf, "arr").expect("arr field");
        assert_eq!(arr_field.offset, 0, "arr @0");
        // The array field type is u32[3] → 12 bytes.
        assert_eq!(ts.size_of(arr_field.ty), Some(12), "arr is u32[3] = 12 bytes");
    }

    #[test]
    fn import_structs_into_handles_self_referential_pointer() {
        // struct Node { i32 val@0; Node* next@8; } — self-referential.
        // FIELDLIST 0x1000 references POINTER 0x1002 which targets Node 0x1001.
        let mut fl = build_member(0x74, 0, "val");
        fl.extend(build_member(0x1002, 8, "next")); // Node* (fwd)
        let mut stream = wrap_record(0x1203, &fl); // 0x1000
        let mut node = Vec::new();
        node.extend_from_slice(&2u16.to_le_bytes());
        node.extend_from_slice(&0u16.to_le_bytes());
        node.extend_from_slice(&0x1000u32.to_le_bytes());
        node.extend_from_slice(&0u32.to_le_bytes());
        node.extend_from_slice(&0u32.to_le_bytes());
        node.extend_from_slice(&16u16.to_le_bytes());
        node.extend_from_slice(b"Node\0"); node.push(0);
        stream.extend(wrap_record(0x1004, &node)); // Node 0x1001
        let mut ptr = 0x1001u32.to_le_bytes().to_vec(); // POINTER -> Node
        ptr.extend_from_slice(&0u32.to_le_bytes());
        stream.extend(wrap_record(0x1002, &ptr)); // 0x1002

        let mut parser = CodeViewTypeParser::new();
        parser.parse_stream(&stream);
        let mut ts = crate::expression_evaluator::TypeSystem::with_primitives();
        assert_eq!(import_structs_into(&parser, &mut ts), 1, "Node registered");
        let node_ty = ts.lookup_name("Node").expect("Node");
        // The self-referential `next` member is typed Node* (forward-declared).
        let next_ty = ts.struct_field(node_ty, "next").expect("next field").ty;
        assert_eq!(ts.lookup_name("Node*"), Some(next_ty), "next typed Node*");
        assert_eq!(ts.struct_field(node_ty, "val").unwrap().offset, 0, "val @0");
        assert_eq!(ts.struct_field(node_ty, "next").unwrap().offset, 8, "next @8");
    }

    #[test]
    fn import_structs_into_handles_pointer_to_struct_members() {
        // Point (fl 0x1000, struct 0x1001) { i32 x@0 }
        // POINTER->Point (0x1002)
        // Container (fl 0x1003, struct 0x1004) { Point* p @0 }
        let mut stream = wrap_record(0x1203, &build_member(0x74, 0, "x")); // 0x1000
        let mut pt = Vec::new();
        pt.extend_from_slice(&1u16.to_le_bytes());
        pt.extend_from_slice(&0u16.to_le_bytes());
        pt.extend_from_slice(&0x1000u32.to_le_bytes());
        pt.extend_from_slice(&0u32.to_le_bytes());
        pt.extend_from_slice(&0u32.to_le_bytes());
        pt.extend_from_slice(&4u16.to_le_bytes());
        pt.extend_from_slice(b"Point\0"); pt.push(0);
        stream.extend(wrap_record(0x1004, &pt)); // Point 0x1001
        // LF_POINTER (0x1002): [target_type:u32][attributes:u32]
        let mut ptr = 0x1001u32.to_le_bytes().to_vec();
        ptr.extend_from_slice(&0u32.to_le_bytes());
        stream.extend(wrap_record(0x1002, &ptr)); // 0x1002
        // Container fieldlist + struct.
        stream.extend(wrap_record(0x1203, &build_member(0x1002, 0, "p"))); // 0x1003
        let mut ct = Vec::new();
        ct.extend_from_slice(&1u16.to_le_bytes());
        ct.extend_from_slice(&0u16.to_le_bytes());
        ct.extend_from_slice(&0x1003u32.to_le_bytes());
        ct.extend_from_slice(&0u32.to_le_bytes());
        ct.extend_from_slice(&0u32.to_le_bytes());
        ct.extend_from_slice(&8u16.to_le_bytes());
        ct.extend_from_slice(b"Container\0"); ct.push(0);
        stream.extend(wrap_record(0x1004, &ct)); // Container 0x1004

        let mut parser = CodeViewTypeParser::new();
        parser.parse_stream(&stream);
        let mut ts = crate::expression_evaluator::TypeSystem::with_primitives();
        assert_eq!(import_structs_into(&parser, &mut ts), 2, "Point + Container");
        let cont = ts.lookup_name("Container").expect("Container");
        // The 'p' member is typed as Point* (pointee is the registered Point).
        let p_ty = ts.struct_field(cont, "p").expect("p field").ty;
        assert_eq!(ts.lookup_name("Point*"), Some(p_ty), "p member typed Point*");
    }

    #[test]
    fn import_structs_into_handles_unions() {
        // union U { u32 i @0; f32 f @0; } — both members at offset 0.
        let mut fl = build_member(0x75, 0, "i");   // T_UINT4 -> u32
        fl.extend(build_member(0x40, 0, "f"));     // T_REAL32 -> f32
        let mut stream = wrap_record(0x1203, &fl); // FIELDLIST 0x1000
        // LF_UNION (0x1006): [count:u16][property:u16][field_list:u32][size:numeric][name\0][unique\0]
        let mut u = Vec::new();
        u.extend_from_slice(&2u16.to_le_bytes());
        u.extend_from_slice(&0u16.to_le_bytes());
        u.extend_from_slice(&0x1000u32.to_le_bytes());
        u.extend_from_slice(&4u16.to_le_bytes());
        u.extend_from_slice(b"U\0"); u.push(0);
        stream.extend(wrap_record(0x1006, &u)); // UNION 0x1001

        let mut parser = CodeViewTypeParser::new();
        parser.parse_stream(&stream);
        let mut ts = crate::expression_evaluator::TypeSystem::with_primitives();
        assert_eq!(import_structs_into(&parser, &mut ts), 1, "union registered");
        let uty = ts.lookup_name("U").expect("U");
        assert_eq!(ts.struct_field(uty, "i").unwrap().offset, 0, "union member i @0");
        assert_eq!(ts.struct_field(uty, "f").unwrap().offset, 0, "union member f @0");
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
            attributes: 0x0400, // near32 mode
        };
        assert_eq!(leaf.pointer_size(), Some(4));
    }

    #[test]
    fn pointer_size_64bit() {
        let leaf = CvTypeLeaf::Pointer {
            target_type: 0x74,
            attributes: (4 << 5), // ptr_mode=4 → 64-bit
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
        let len = super::super::casts::usize_to_u16(2 + body.len());
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
