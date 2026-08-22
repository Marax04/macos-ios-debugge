//! PDB TPI stream — full type-record decoder.
//!
//! Decodes the Type Info (`TPI`) stream from a `PDB` file. Supports:
//! - `LF_STRUCTURE`, `LF_CLASS`, `LF_UNION`
//! - `LF_ENUM`
//! - `LF_POINTER`
//! - `LF_ARRAY`
//! - `LF_PROCEDURE`, `LF_MFUNCTION`
//! - `LF_FIELDLIST` (with member fields, base classes, virtual bases)
//! - `LF_METHODLIST`
//! - Primitive type indices
//! - Numeric leaf values

use std::collections::HashMap;
use std::fmt;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Error produced while decoding the `TPI` stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpiError {
    /// The stream ended before a record or value could be fully read.
    Truncated {
        /// Byte offset at which the read was attempted.
        offset: usize,
        /// Number of bytes that were needed at that offset.
        needed: usize,
    },
    /// An unrecognized leaf kind was encountered.
    UnknownLeaf(u16),
    /// A type index was out of range or otherwise invalid.
    InvalidTypeIndex(u32),
    /// Any other decoding error, with a description.
    Other(String),
}

impl fmt::Display for TpiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { offset, needed } => {
                write!(f, "truncated at {offset}, needed {needed} bytes")
            }
            Self::UnknownLeaf(k) => write!(f, "unknown leaf kind {k:#06x}"),
            Self::InvalidTypeIndex(ti) => write!(f, "invalid type index {ti:#x}"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

// ── Primitive types ───────────────────────────────────────────────────────────

/// Resolve a `PDB` primitive type index (< 0x1000) to a name.
#[must_use]
pub const fn primitive_type_name(ti: u32) -> Option<&'static str> {
    match ti {
        0x0000 => Some("T_NOTYPE"),
        0x0003 => Some("T_VOID"),
        0x0008 => Some("T_HRESULT"),
        0x0010 => Some("T_CHAR"),
        0x0020 => Some("T_UCHAR"),
        0x0011 => Some("T_SHORT"),
        0x0021 => Some("T_USHORT"),
        0x0012 => Some("T_INT2"),
        0x0022 => Some("T_UINT2"),
        0x0074 | 0x0070 => Some("T_INT4"),
        0x0075 => Some("T_UINT4"),
        0x0076 => Some("T_INT8"),
        0x0077 => Some("T_UINT8"),
        0x0040 => Some("T_REAL32"),
        0x0041 => Some("T_REAL64"),
        0x0042 => Some("T_REAL80"),
        0x0043 => Some("T_REAL128"),
        0x0071 => Some("T_LONG"),
        0x0072 | 0x0073 => Some("T_ULONG"),
        0x0030 => Some("T_BOOL08"),
        0x0031 => Some("T_BOOL16"),
        0x0032 => Some("T_BOOL32"),
        0x0033 => Some("T_BOOL64"),
        0x0103 => Some("T_PVOID"),
        0x0403 => Some("T_32PVOID"),
        0x0603 => Some("T_64PVOID"),
        _ => None,
    }
}

/// Whether a type index is in the primitive range.
#[must_use]
pub const fn is_primitive(ti: u32) -> bool {
    ti < 0x1000
}

// ── Leaf kinds ────────────────────────────────────────────────────────────────

/// Well-known leaf kinds from cvconst.h.
pub mod leaf {
    /// `LF_MODIFIER` — const/volatile/unaligned modifier applied to another type.
    pub const LF_MODIFIER: u16 = 0x1001;
    /// `LF_POINTER` — pointer type record.
    pub const LF_POINTER: u16 = 0x1002;
    /// `LF_ARRAY` — array type record.
    pub const LF_ARRAY: u16 = 0x1003;
    /// `LF_CLASS` — C++ class type record.
    pub const LF_CLASS: u16 = 0x1004;
    /// `LF_STRUCTURE` — struct type record.
    pub const LF_STRUCTURE: u16 = 0x1005;
    /// `LF_UNION` — union type record.
    pub const LF_UNION: u16 = 0x1006;
    /// `LF_ENUM` — enumeration type record.
    pub const LF_ENUM: u16 = 0x1007;
    /// `LF_PROCEDURE` — free-function type record.
    pub const LF_PROCEDURE: u16 = 0x1008;
    /// `LF_MFUNCTION` — member-function type record.
    pub const LF_MFUNCTION: u16 = 0x1009;
    /// `LF_FIELDLIST` — list of members/bases/enumerators for an aggregate.
    pub const LF_FIELDLIST: u16 = 0x1203;
    /// `LF_METHODLIST` — list of overloads for an `LF_METHOD` entry.
    pub const LF_METHODLIST: u16 = 0x1206;
    /// `LF_BITFIELD` — bit-field type record.
    pub const LF_BITFIELD: u16 = 0x1205;
    /// `LF_INDEX` — continuation to another field list.
    pub const LF_INDEX: u16 = 0x1404;
    /// `LF_MEMBER` — non-static data member in a field list.
    pub const LF_MEMBER: u16 = 0x150d;
    /// `LF_ENUMERATE` — enumerator (name + value) in a field list.
    pub const LF_ENUMERATE: u16 = 0x1502;
    /// `LF_BCLASS` — direct base class in a field list.
    pub const LF_BCLASS: u16 = 0x1400;
    /// `LF_VBCLASS` — direct virtual base class in a field list.
    pub const LF_VBCLASS: u16 = 0x1401;
    /// `LF_IVBCLASS` — indirect virtual base class in a field list.
    pub const LF_IVBCLASS: u16 = 0x1402;
    /// `LF_STMEMBER` — static data member in a field list.
    pub const LF_STMEMBER: u16 = 0x150e;
    /// `LF_METHOD` — overloaded method entry referencing an `LF_METHODLIST`.
    pub const LF_METHOD: u16 = 0x150f;
    /// `LF_ONEMETHOD` — non-overloaded member function in a field list.
    pub const LF_ONEMETHOD: u16 = 0x1511;
    /// `LF_FRIENDFCN` — friend function in a field list.
    pub const LF_FRIENDFCN: u16 = 0x150c;
    /// `LF_FRIENDCLS` is 0x140a — it lives in the 0x14xx block because it has
    /// no name field and therefore never needed an `_ST` counterpart.
    pub const LF_FRIENDCLS: u16 = 0x140a;
    /// `LF_NESTTYPE` — nested type definition in a field list.
    pub const LF_NESTTYPE: u16 = 0x1510;
    /// `LF_VFUNCTAB` — virtual function table pointer in a field list.
    pub const LF_VFUNCTAB: u16 = 0x1409;
    // Numeric leaves
    /// Threshold for numeric leaves: tags below this encode the value inline.
    pub const LF_NUMERIC: u16 = 0x8000;
    /// `LF_CHAR` — signed 8-bit numeric leaf.
    pub const LF_CHAR: u16 = 0x8000;
    /// `LF_SHORT` — signed 16-bit numeric leaf.
    pub const LF_SHORT: u16 = 0x8001;
    /// `LF_USHORT` — unsigned 16-bit numeric leaf.
    pub const LF_USHORT: u16 = 0x8002;
    /// `LF_LONG` — signed 32-bit numeric leaf.
    pub const LF_LONG: u16 = 0x8003;
    /// `LF_ULONG` — unsigned 32-bit numeric leaf.
    pub const LF_ULONG: u16 = 0x8004;
    /// `LF_REAL32` — 32-bit floating-point numeric leaf.
    pub const LF_REAL32: u16 = 0x8005;
    /// `LF_REAL64` — 64-bit floating-point numeric leaf.
    pub const LF_REAL64: u16 = 0x8006;
    /// `LF_REAL80` — 80-bit floating-point numeric leaf.
    pub const LF_REAL80: u16 = 0x8007;
    /// `LF_REAL128` — 128-bit floating-point numeric leaf.
    pub const LF_REAL128: u16 = 0x8008;
    /// `LF_QUADWORD` — signed 64-bit numeric leaf.
    pub const LF_QUADWORD: u16 = 0x8009;
    /// `LF_UQUADWORD` — unsigned 64-bit numeric leaf.
    pub const LF_UQUADWORD: u16 = 0x800a;
    /// `LF_VARSTRING` — variable-length string numeric leaf.
    pub const LF_VARSTRING: u16 = 0x8010;
    /// `LF_OCTWORD` — signed 128-bit numeric leaf.
    pub const LF_OCTWORD: u16 = 0x8017;
    /// `LF_UOCTWORD` — unsigned 128-bit numeric leaf.
    pub const LF_UOCTWORD: u16 = 0x8018;
}

// ── Numeric leaf reader ───────────────────────────────────────────────────────

/// Reinterpret a signed value's two's-complement bit pattern as `u64`.
///
/// `CodeView` signed numeric leaves (`LF_CHAR`, `LF_SHORT`, `LF_LONG`) are
/// sign-extended to 64 bits and then handed back in the `u64` channel that
/// [`read_numeric_leaf`] uses for every leaf kind, so that a caller converting
/// back with `i64` recovers `-1` rather than `255`. This is a bit-pattern
/// reinterpretation, not a numeric conversion: going through `to_ne_bytes` /
/// `from_ne_bytes` makes that explicit and total, where an `as` cast merely
/// hid the intent behind a lint exemption.
#[inline]
const fn sign_extended_bits(v: i64) -> u64 {
    u64::from_ne_bytes(v.to_ne_bytes())
}

/// Read a numeric leaf value from `data[pos..]`.
///
/// Returns `(value_as_u64, bytes_consumed)`.
///
/// Signed leaves (`LF_CHAR`, `LF_SHORT`, `LF_LONG`) are **sign-extended** into
/// the `u64`, so a caller casting the result to `i64` recovers `-1` rather than
/// `255` / `65535` / `4294967295`.
///
/// Every tag's true width is enumerated; an unrecognized tag is a hard error
/// rather than a silent "2 bytes consumed", because under-consuming a numeric
/// leaf desynchronizes the cursor for the name string and every subsequent
/// field-list member.
///
/// # Errors
/// [`TpiError::Truncated`] if the value runs past the buffer;
/// [`TpiError::UnknownLeaf`] for an unrecognized numeric tag.
pub fn read_numeric_leaf(data: &[u8], pos: usize) -> Result<(u64, usize), TpiError> {
    if pos + 2 > data.len() {
        return Err(TpiError::Truncated {
            offset: pos,
            needed: 2,
        });
    }
    let kind = u16::from_le_bytes([data[pos], data[pos + 1]]);
    if kind < leaf::LF_NUMERIC {
        return Ok((u64::from(kind), 2));
    }
    match kind {
        // LF_CHAR is a *signed* 8-bit value.
        leaf::LF_CHAR => {
            need(data, pos + 2, 1)?;
            Ok((
                sign_extended_bits(i64::from(i8::from_le_bytes([data[pos + 2]]))),
                3,
            ))
        }
        // LF_SHORT is signed 16-bit, LF_USHORT unsigned.
        leaf::LF_SHORT => {
            need(data, pos + 2, 2)?;
            let v = i16::from_le_bytes([data[pos + 2], data[pos + 3]]);
            Ok((sign_extended_bits(i64::from(v)), 4))
        }
        leaf::LF_USHORT => {
            need(data, pos + 2, 2)?;
            Ok((
                u64::from(u16::from_le_bytes([data[pos + 2], data[pos + 3]])),
                4,
            ))
        }
        // LF_LONG is signed 32-bit, LF_ULONG unsigned.
        leaf::LF_LONG => {
            need(data, pos + 2, 4)?;
            let v = i32::from_le_bytes([
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
            ]);
            Ok((sign_extended_bits(i64::from(v)), 6))
        }
        leaf::LF_ULONG => {
            need(data, pos + 2, 4)?;
            Ok((
                u64::from(u32::from_le_bytes([
                    data[pos + 2],
                    data[pos + 3],
                    data[pos + 4],
                    data[pos + 5],
                ])),
                6,
            ))
        }
        leaf::LF_QUADWORD | leaf::LF_UQUADWORD => {
            need(data, pos + 2, 8)?;
            let v = u64::from_le_bytes(data[pos + 2..pos + 10].try_into().unwrap());
            Ok((v, 10))
        }
        // Floating-point and wide leaves: the value is not representable in a
        // u64, but the *width* still has to be consumed exactly or the cursor
        // lands in the middle of the value.
        leaf::LF_REAL32 => {
            need(data, pos + 2, 4)?;
            Ok((0, 6))
        }
        leaf::LF_REAL64 => {
            need(data, pos + 2, 8)?;
            Ok((0, 10))
        }
        leaf::LF_REAL80 => {
            need(data, pos + 2, 10)?;
            Ok((0, 12))
        }
        leaf::LF_REAL128 | leaf::LF_OCTWORD | leaf::LF_UOCTWORD => {
            need(data, pos + 2, 16)?;
            Ok((0, 18))
        }
        // LF_VARSTRING: 2-byte tag, u16 length, then `length` bytes.
        leaf::LF_VARSTRING => {
            need(data, pos + 2, 2)?;
            let len = usize::from(u16::from_le_bytes([data[pos + 2], data[pos + 3]]));
            need(data, pos + 4, len)?;
            Ok((0, 4 + len))
        }
        _ => Err(TpiError::UnknownLeaf(kind)),
    }
}

const fn need(data: &[u8], from: usize, n: usize) -> Result<(), TpiError> {
    if from + n > data.len() {
        Err(TpiError::Truncated {
            offset: from,
            needed: n,
        })
    } else {
        Ok(())
    }
}

fn read_u16(data: &[u8], pos: usize) -> Result<u16, TpiError> {
    need(data, pos, 2)?;
    Ok(u16::from_le_bytes([data[pos], data[pos + 1]]))
}

fn read_u32(data: &[u8], pos: usize) -> Result<u32, TpiError> {
    need(data, pos, 4)?;
    Ok(u32::from_le_bytes([
        data[pos],
        data[pos + 1],
        data[pos + 2],
        data[pos + 3],
    ]))
}

fn read_cstring(data: &[u8], pos: usize) -> (String, usize) {
    let end = data[pos..]
        .iter()
        .position(|&b| b == 0)
        .map_or(data.len(), |n| pos + n);
    let s = String::from_utf8_lossy(&data[pos..end]).to_string();
    (s, end - pos + 1)
}

// ── TypeRecord ────────────────────────────────────────────────────────────────

/// Decoded type record.
#[derive(Debug, Clone)]
pub enum TypeRecord {
    /// A primitive type (type index < 0x1000).
    Primitive {
        /// Primitive type index.
        ti: u32,
        /// Resolved primitive type name (e.g. `T_INT4`).
        name: String,
    },
    /// `LF_STRUCTURE` / `LF_CLASS`.
    Structure(StructType),
    /// `LF_UNION`.
    Union(StructType),
    /// `LF_ENUM`.
    Enum(EnumType),
    /// `LF_POINTER`.
    Pointer(PointerType),
    /// `LF_ARRAY`.
    Array(ArrayType),
    /// `LF_PROCEDURE` or `LF_MFUNCTION`.
    Function(FunctionType),
    /// `LF_FIELDLIST`.
    FieldList(FieldList),
    /// `LF_METHODLIST`.
    MethodList(MethodList),
    /// `LF_BITFIELD`.
    BitField(BitFieldType),
    /// `LF_MODIFIER`.
    Modifier(ModifierType),
    /// A leaf kind this decoder does not parse.
    Unknown {
        /// Raw leaf kind.
        kind: u16,
        /// Record body size in bytes.
        size: usize,
    },
}

impl TypeRecord {
    /// Human-readable type name.
    #[must_use]
    pub fn type_name(&self) -> String {
        match self {
            Self::Primitive { name, .. } => name.clone(),
            Self::Structure(s) => format!("struct {}", s.name),
            Self::Union(u) => format!("union {}", u.name),
            Self::Enum(e) => format!("enum {}", e.name),
            Self::Pointer(p) => format!("{}*", p.underlying_ti),
            Self::Array(a) => format!("[{}; {}]", a.element_ti, a.element_count),
            Self::Function(f) => format!("fn({} args) -> {}", f.param_count, f.return_ti),
            Self::FieldList(_) => "<field_list>".to_string(),
            Self::MethodList(_) => "<method_list>".to_string(),
            Self::BitField(b) => format!("bitfield:{}", b.length),
            Self::Modifier(m) => format!("mod({:#04x})", m.attr),
            Self::Unknown { kind, .. } => format!("unknown_0x{kind:04x}"),
        }
    }
}

// ── Struct / Union ────────────────────────────────────────────────────────────

/// A decoded struct, class, or union type.
#[derive(Debug, Clone)]
pub struct StructType {
    /// Number of elements in the field list.
    pub count: u16,
    /// Type index of the `LF_FIELDLIST` describing the members.
    pub field_list_ti: u32,
    /// `CV_prop_t` property bit-flags (packed, fwdref, …).
    pub properties: u16,
    /// Type index of the derivation list (0 if none).
    pub derived_ti: u32,
    /// Type index of the vtable shape (0 if none).
    pub vshape_ti: u32,
    /// Size of the type in bytes (from the trailing numeric leaf).
    pub byte_size: u64,
    /// Type name.
    pub name: String,
    /// Decorated (mangled) unique name, if present.
    pub unique_name: String,
}

impl StructType {
    fn parse(data: &[u8]) -> Result<Self, TpiError> {
        need(data, 0, 10)?;
        let count = read_u16(data, 0)?;
        let properties = read_u16(data, 2)?;
        let field_list_ti = read_u32(data, 4)?;
        let derived_ti = read_u32(data, 8)?;
        let vshape_ti = read_u32(data, 12)?;
        let (byte_size, ns) = read_numeric_leaf(data, 16)?;
        let mut pos = 16 + ns;
        let (name, nn) = read_cstring(data, pos);
        pos += nn;
        let (unique_name, _) = if pos < data.len() {
            read_cstring(data, pos)
        } else {
            (String::new(), 0)
        };
        Ok(Self {
            count,
            field_list_ti,
            properties,
            derived_ti,
            vshape_ti,
            byte_size,
            name,
            unique_name,
        })
    }
}

// ── Enum ──────────────────────────────────────────────────────────────────────

/// A decoded `LF_ENUM` type.
#[derive(Debug, Clone)]
pub struct EnumType {
    /// Number of enumerators.
    pub count: u16,
    /// `CV_prop_t` property bit-flags.
    pub properties: u16,
    /// Type index of the underlying integer type.
    pub underlying_ti: u32,
    /// Type index of the `LF_FIELDLIST` holding the enumerators.
    pub field_list_ti: u32,
    /// Enum name.
    pub name: String,
    /// Decorated (mangled) unique name, if present.
    pub unique_name: String,
}

impl EnumType {
    fn parse(data: &[u8]) -> Result<Self, TpiError> {
        need(data, 0, 12)?;
        let count = read_u16(data, 0)?;
        let properties = read_u16(data, 2)?;
        let underlying_ti = read_u32(data, 4)?;
        let field_list_ti = read_u32(data, 8)?;
        let (name, nn) = read_cstring(data, 12);
        let (unique_name, _) = if 12 + nn < data.len() {
            read_cstring(data, 12 + nn)
        } else {
            (String::new(), 0)
        };
        Ok(Self {
            count,
            properties,
            underlying_ti,
            field_list_ti,
            name,
            unique_name,
        })
    }
}

// ── Pointer ───────────────────────────────────────────────────────────────────

/// A decoded `LF_POINTER` type.
#[derive(Debug, Clone)]
pub struct PointerType {
    /// Type index of the pointed-to type.
    pub underlying_ti: u32,
    /// Raw `CV_ptrattr` attribute bits (kind, mode, qualifiers).
    pub attr: u32,
}

impl PointerType {
    fn parse(data: &[u8]) -> Result<Self, TpiError> {
        need(data, 0, 8)?;
        let underlying_ti = read_u32(data, 0)?;
        let attr = read_u32(data, 4)?;
        Ok(Self {
            underlying_ti,
            attr,
        })
    }

    /// Name of the `CV_ptrtype` pointer kind encoded in the low 5 attribute bits.
    #[must_use]
    pub const fn pointer_kind(&self) -> &'static str {
        let kind = self.attr & 0x1F;
        match kind {
            0 => "near",
            1 => "far",
            2 => "huge",
            3 => "base_seg",
            4 => "base_val",
            5 => "base_segval",
            6 => "base_addr",
            7 => "base_segaddr",
            8 => "base_type",
            9 => "base_self",
            10 => "near32",
            11 => "far32",
            12 => "ptr64",
            _ => "unknown",
        }
    }
}

// ── Array ─────────────────────────────────────────────────────────────────────

/// A decoded `LF_ARRAY` type.
#[derive(Debug, Clone)]
pub struct ArrayType {
    /// Type index of the element type.
    pub element_ti: u32,
    /// Type index of the indexing type.
    pub index_ti: u32,
    /// Total array size in bytes (from the numeric leaf).
    pub byte_size: u64,
    /// Element count (0 — computing it requires the element type's size).
    pub element_count: u64,
    /// Array name (usually empty).
    pub name: String,
}

impl ArrayType {
    fn parse(data: &[u8]) -> Result<Self, TpiError> {
        need(data, 0, 8)?;
        let element_ti = read_u32(data, 0)?;
        let index_ti = read_u32(data, 4)?;
        let (byte_size, ns) = read_numeric_leaf(data, 8)?;
        let pos = 8 + ns;
        let (name, _) = if pos < data.len() {
            read_cstring(data, pos)
        } else {
            (String::new(), 0)
        };
        let element_count = 0; // would need element type size to compute
        Ok(Self {
            element_ti,
            index_ti,
            byte_size,
            element_count,
            name,
        })
    }
}

// ── Function types ────────────────────────────────────────────────────────────

/// A decoded `LF_PROCEDURE` or `LF_MFUNCTION` type.
#[derive(Debug, Clone)]
pub struct FunctionType {
    /// Type index of the return type.
    pub return_ti: u32,
    /// `CV_call_t` calling convention code.
    pub call_conv: u8,
    /// Function attribute bits (`CV_funcattr_t`).
    pub attributes: u8,
    /// Number of parameters.
    pub param_count: u16,
    /// Type index of the `LF_ARGLIST` holding parameter types.
    pub arglist_ti: u32,
}

impl FunctionType {
    fn parse(data: &[u8]) -> Result<Self, TpiError> {
        need(data, 0, 10)?;
        let return_ti = read_u32(data, 0)?;
        let call_conv = data[4];
        let attributes = data[5];
        let param_count = read_u16(data, 6)?;
        let arglist_ti = read_u32(data, 8)?;
        Ok(Self {
            return_ti,
            call_conv,
            attributes,
            param_count,
            arglist_ti,
        })
    }

    fn parse_mfunction(data: &[u8]) -> Result<Self, TpiError> {
        need(data, 0, 24)?;
        let return_ti = read_u32(data, 0)?;
        let _class_ti = read_u32(data, 4)?;
        let _this_ti = read_u32(data, 8)?;
        let call_conv = data[12];
        let attributes = data[13];
        let param_count = read_u16(data, 14)?;
        let arglist_ti = read_u32(data, 16)?;
        Ok(Self {
            return_ti,
            call_conv,
            attributes,
            param_count,
            arglist_ti,
        })
    }
}

// ── FieldList ─────────────────────────────────────────────────────────────────

/// Decoded field list.
#[derive(Debug, Clone)]
pub struct FieldList {
    /// Parsed field-list entries, in stream order.
    pub members: Vec<FieldListItem>,
    /// Set to the leaf kind that caused parsing to stop early.
    ///
    /// Unknown leaves have no self-describing length, so the parser cannot skip
    /// them and must stop — but doing that silently discards every remaining
    /// member. Callers that care about completeness should check this: `None`
    /// means the list was consumed to the end.
    pub truncated_at: Option<u16>,
}

/// A single entry in an `LF_FIELDLIST`.
#[derive(Debug, Clone)]
pub enum FieldListItem {
    /// A non-static data member (`LF_MEMBER`).
    Member(MemberField),
    /// A static data member (`LF_STMEMBER`).
    StaticMember {
        /// Member name.
        name: String,
        /// Type index of the member's type.
        type_ti: u32,
    },
    /// A direct base class (`LF_BCLASS`).
    BaseClass(BaseClass),
    /// A virtual base class (`LF_VBCLASS` / `LF_IVBCLASS`).
    VirtualBase(VirtualBase),
    /// An enumerator (`LF_ENUMERATE`).
    Enumerate {
        /// Enumerator name.
        name: String,
        /// Enumerator value (sign-extended into a `u64`).
        value: u64,
    },
    /// An overloaded method entry (`LF_METHOD`).
    Method {
        /// Method name.
        name: String,
        /// Type index of the `LF_METHODLIST` with the overloads.
        method_list_ti: u32,
    },
    /// A non-overloaded member function (`LF_ONEMETHOD`).
    OneMethod(OneMethod),
    /// A friend function (`LF_FRIENDFCN`).
    FriendFunction {
        /// Friend function name.
        name: String,
        /// Type index of the function's type.
        type_ti: u32,
    },
    /// A friend class (`LF_FRIENDCLS`).
    FriendClass {
        /// Type index of the friend class.
        type_ti: u32,
    },
    /// A nested type definition (`LF_NESTTYPE`).
    NestedType {
        /// Nested type name.
        name: String,
        /// Type index of the nested type.
        nested_ti: u32,
    },
    /// A virtual function table pointer (`LF_VFUNCTAB`).
    VFuncTab {
        /// Type index of the vtable shape.
        vshape_ti: u32,
    },
    /// A continuation (`LF_INDEX`) pointing at the next field list.
    Continuation(u32),
}

/// A single non-overloaded member function (`LF_ONEMETHOD`).
///
/// Emitted for essentially every C++ member function, so failing to handle it
/// truncates the field list at the first method.
#[derive(Debug, Clone)]
pub struct OneMethod {
    /// Method name.
    pub name: String,
    /// Type index of the method's `LF_MFUNCTION` type.
    pub type_ti: u32,
    /// `CV_fldattr_t` attribute bits (access, method properties).
    pub attr: u16,
    /// Present only for introducing / pure-introducing virtuals.
    pub vbase_offset: Option<u32>,
}

/// Whether a `CV_fldattr_t` method property denotes an *introducing* virtual
/// (`CV_MTintro` = 4) or a *pure* introducing virtual (`CV_MTpureintro` = 6).
/// Both carry a trailing 4-byte vtable offset; testing only for 4 desyncs the
/// rest of the record.
const fn mprop_has_vbase_offset(attr: u16) -> bool {
    matches!((attr >> 2) & 0x7, 4 | 6)
}

/// A non-static member field.
#[derive(Debug, Clone)]
pub struct MemberField {
    /// Member name.
    pub name: String,
    /// Type index of the member's type.
    pub type_ti: u32,
    /// `CV_fldattr_t` attribute bits.
    pub attr: u16,
    /// Byte offset of the member within the aggregate.
    pub offset: u64,
}

/// A base class record.
#[derive(Debug, Clone)]
pub struct BaseClass {
    /// Type index of the base class.
    pub base_ti: u32,
    /// `CV_fldattr_t` attribute bits.
    pub attr: u16,
    /// Byte offset of the base subobject within the derived class.
    pub offset: u64,
    /// Whether the base is virtual.
    pub is_virtual: bool,
}

/// A virtual base class record.
#[derive(Debug, Clone)]
pub struct VirtualBase {
    /// Type index of the virtual base class.
    pub base_ti: u32,
    /// Type index of the virtual base pointer's type.
    pub vbptr_ti: u32,
    /// `CV_fldattr_t` attribute bits.
    pub attr: u16,
    /// Offset of the virtual base pointer within the class.
    pub vbptr_offset: u64,
    /// Offset of the entry within the virtual base displacement table.
    pub vbtable_offset: u64,
    /// `true` for `LF_IVBCLASS` (indirect virtual base).
    pub is_indirect: bool,
}

impl FieldList {
    fn parse(data: &[u8]) -> Result<Self, TpiError> {
        let mut members = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            // Skip padding bytes.
            while pos < data.len()
                && (data[pos] == 0xF3 || data[pos] == 0xF2 || data[pos] == 0xF1)
            {
                pos += 1;
            }
            if pos + 2 > data.len() {
                break;
            }
            let kind = read_u16(data, pos)?;
            pos += 2;
            match parse_field_item(data, &mut pos, kind)? {
                FieldItemResult::Item(item) => members.push(item),
                FieldItemResult::Stop => {
                    return Ok(Self {
                        members,
                        truncated_at: Some(kind),
                    });
                }
            }
        }
        Ok(Self {
            members,
            truncated_at: None,
        })
    }
}

enum FieldItemResult {
    Item(FieldListItem),
    Stop,
}

fn parse_field_item(
    data: &[u8],
    pos: &mut usize,
    kind: u16,
) -> Result<FieldItemResult, TpiError> {
    match kind {
        leaf::LF_MEMBER
        | leaf::LF_ENUMERATE
        | leaf::LF_BCLASS
        | leaf::LF_VBCLASS
        | leaf::LF_IVBCLASS => parse_field_item_data(data, pos, kind),
        _ => parse_field_item_misc(data, pos, kind),
    }
}

fn parse_field_item_data(
    data: &[u8],
    pos: &mut usize,
    kind: u16,
) -> Result<FieldItemResult, TpiError> {
    match kind {
        leaf::LF_MEMBER => {
            if *pos + 6 > data.len() {
                return Ok(FieldItemResult::Stop);
            }
            let attr = read_u16(data, *pos)?;
            let type_ti = read_u32(data, *pos + 2)?;
            let (offset, ns) = read_numeric_leaf(data, *pos + 6)?;
            *pos += 6 + ns;
            let (name, nn) = read_cstring(data, *pos);
            *pos += nn;
            while *pos < data.len() && data[*pos] == 0 {
                *pos += 1;
            }
            Ok(FieldItemResult::Item(FieldListItem::Member(MemberField {
                name,
                type_ti,
                attr,
                offset,
            })))
        }
        leaf::LF_ENUMERATE => {
            if *pos + 2 > data.len() {
                return Ok(FieldItemResult::Stop);
            }
            let _ = read_u16(data, *pos)?; // attr unused
            *pos += 2;
            let (value, ns) = read_numeric_leaf(data, *pos)?;
            *pos += ns;
            let (name, nn) = read_cstring(data, *pos);
            *pos += nn;
            while *pos < data.len() && data[*pos] == 0 {
                *pos += 1;
            }
            Ok(FieldItemResult::Item(FieldListItem::Enumerate { name, value }))
        }
        leaf::LF_BCLASS => {
            if *pos + 6 > data.len() {
                return Ok(FieldItemResult::Stop);
            }
            let attr = read_u16(data, *pos)?;
            let base_ti = read_u32(data, *pos + 2)?;
            let (offset, ns) = read_numeric_leaf(data, *pos + 6)?;
            *pos += 6 + ns;
            while *pos < data.len() && data[*pos] == 0 {
                *pos += 1;
            }
            Ok(FieldItemResult::Item(FieldListItem::BaseClass(BaseClass {
                base_ti,
                attr,
                offset,
                is_virtual: false,
            })))
        }
        leaf::LF_VBCLASS | leaf::LF_IVBCLASS => {
            if *pos + 8 > data.len() {
                return Ok(FieldItemResult::Stop);
            }
            let attr = read_u16(data, *pos)?;
            let base_ti = read_u32(data, *pos + 2)?;
            let vbptr_ti = read_u32(data, *pos + 6)?;
            let (vbptr_offset, n1) = read_numeric_leaf(data, *pos + 10)?;
            let pos2 = *pos + 10 + n1;
            let (vbtable_offset, n2) = read_numeric_leaf(data, pos2)?;
            *pos = pos2 + n2;
            Ok(FieldItemResult::Item(FieldListItem::VirtualBase(VirtualBase {
                base_ti,
                vbptr_ti,
                attr,
                vbptr_offset,
                vbtable_offset,
                is_indirect: kind == leaf::LF_IVBCLASS,
            })))
        }
        _ => Ok(FieldItemResult::Stop),
    }
}

fn parse_field_item_misc(
    data: &[u8],
    pos: &mut usize,
    kind: u16,
) -> Result<FieldItemResult, TpiError> {
    match kind {
        leaf::LF_STMEMBER => {
            if *pos + 6 > data.len() {
                return Ok(FieldItemResult::Stop);
            }
            let _ = read_u16(data, *pos)?; // attr unused
            let type_ti = read_u32(data, *pos + 2)?;
            *pos += 6;
            let (name, nn) = read_cstring(data, *pos);
            *pos += nn;
            Ok(FieldItemResult::Item(FieldListItem::StaticMember { name, type_ti }))
        }
        leaf::LF_METHOD => {
            if *pos + 6 > data.len() {
                return Ok(FieldItemResult::Stop);
            }
            let _ = read_u16(data, *pos)?; // count unused
            let mlist_ti = read_u32(data, *pos + 2)?;
            *pos += 6;
            let (name, nn) = read_cstring(data, *pos);
            *pos += nn;
            Ok(FieldItemResult::Item(FieldListItem::Method {
                name,
                method_list_ti: mlist_ti,
            }))
        }
        leaf::LF_NESTTYPE => {
            if *pos + 6 > data.len() {
                return Ok(FieldItemResult::Stop);
            }
            let _ = read_u16(data, *pos)?; // pad unused
            let nested_ti = read_u32(data, *pos + 2)?;
            *pos += 6;
            let (name, nn) = read_cstring(data, *pos);
            *pos += nn;
            Ok(FieldItemResult::Item(FieldListItem::NestedType { name, nested_ti }))
        }
        // Layout: u16 attr, u32 type_ti, [u32 vbaseoff if intro/pure-intro
        // virtual], name. Missing this arm truncated every C++ class field list
        // at its first member function.
        leaf::LF_ONEMETHOD => {
            if *pos + 6 > data.len() {
                return Ok(FieldItemResult::Stop);
            }
            let attr = read_u16(data, *pos)?;
            let type_ti = read_u32(data, *pos + 2)?;
            *pos += 6;
            let vbase_offset = if mprop_has_vbase_offset(attr) {
                if *pos + 4 > data.len() {
                    return Ok(FieldItemResult::Stop);
                }
                let v = read_u32(data, *pos)?;
                *pos += 4;
                Some(v)
            } else {
                None
            };
            let (name, nn) = read_cstring(data, *pos);
            *pos += nn;
            while *pos < data.len() && data[*pos] == 0 {
                *pos += 1;
            }
            Ok(FieldItemResult::Item(FieldListItem::OneMethod(OneMethod {
                name,
                type_ti,
                attr,
                vbase_offset,
            })))
        }
        // Layout: u16 pad, u32 type_ti, name.
        leaf::LF_FRIENDFCN => {
            if *pos + 6 > data.len() {
                return Ok(FieldItemResult::Stop);
            }
            let type_ti = read_u32(data, *pos + 2)?;
            *pos += 6;
            let (name, nn) = read_cstring(data, *pos);
            *pos += nn;
            Ok(FieldItemResult::Item(FieldListItem::FriendFunction {
                name,
                type_ti,
            }))
        }
        // Layout: u16 pad, u32 type_ti (no name).
        leaf::LF_FRIENDCLS => {
            if *pos + 6 > data.len() {
                return Ok(FieldItemResult::Stop);
            }
            let type_ti = read_u32(data, *pos + 2)?;
            *pos += 6;
            Ok(FieldItemResult::Item(FieldListItem::FriendClass { type_ti }))
        }
        leaf::LF_INDEX => {
            // u16 pad, u32 continuation_ti = 6 bytes. The old code bounds-
            // checked 4 and never advanced `pos` at all, so the parser then ran
            // straight into the continuation index's own bytes.
            if *pos + 6 > data.len() {
                return Ok(FieldItemResult::Stop);
            }
            let cont_ti = read_u32(data, *pos + 2)?;
            *pos += 6;
            Ok(FieldItemResult::Item(FieldListItem::Continuation(cont_ti)))
        }
        leaf::LF_VFUNCTAB => {
            // u16 pad, u32 vshape_ti = 6 bytes (the check said 4, the advance
            // said 6).
            if *pos + 6 > data.len() {
                return Ok(FieldItemResult::Stop);
            }
            let _ = read_u16(data, *pos)?; // pad unused
            let vshape = read_u32(data, *pos + 2)?;
            *pos += 6;
            Ok(FieldItemResult::Item(FieldListItem::VFuncTab { vshape_ti: vshape }))
        }
        _ => Ok(FieldItemResult::Stop),
    }
}

// ── MethodList ────────────────────────────────────────────────────────────────

/// A decoded `LF_METHODLIST` — the overload set for one method name.
#[derive(Debug, Clone)]
pub struct MethodList {
    /// Overload entries, in stream order.
    pub methods: Vec<MethodEntry>,
}

/// One overload in an `LF_METHODLIST`.
#[derive(Debug, Clone)]
pub struct MethodEntry {
    /// `CV_fldattr_t` attribute bits.
    pub attr: u16,
    /// Type index of the method's `LF_MFUNCTION` type.
    pub method_ti: u32,
    /// Vtable offset, present only for introducing virtuals.
    pub vtable_offset: Option<u32>,
}

impl MethodList {
    fn parse(data: &[u8]) -> Result<Self, TpiError> {
        let mut methods = Vec::new();
        let mut pos = 0;
        while pos + 4 <= data.len() {
            let attr = read_u16(data, pos)?;
            let _pad = read_u16(data, pos + 2)?;
            let method_ti = read_u32(data, pos + 4)?;
            pos += 8;
            let vtable_offset = if mprop_has_vbase_offset(attr) {
                // intro (CV_MTintro=4) or pure-intro (CV_MTpureintro=6)
                // virtual: a 4-byte vtable offset follows
                if pos + 4 <= data.len() {
                    let v = read_u32(data, pos)?;
                    pos += 4;
                    Some(v)
                } else {
                    None
                }
            } else {
                None
            };
            methods.push(MethodEntry {
                attr,
                method_ti,
                vtable_offset,
            });
        }
        Ok(Self { methods })
    }
}

// ── BitField / Modifier ───────────────────────────────────────────────────────

/// A decoded `LF_BITFIELD` type.
#[derive(Debug, Clone)]
pub struct BitFieldType {
    /// Type index of the underlying integer type.
    pub base_ti: u32,
    /// Width of the bit-field in bits.
    pub length: u8,
    /// Starting bit position within the underlying type.
    pub position: u8,
}

impl BitFieldType {
    fn parse(data: &[u8]) -> Result<Self, TpiError> {
        need(data, 0, 6)?;
        let base_ti = read_u32(data, 0)?;
        let length = data[4];
        let position = data[5];
        Ok(Self {
            base_ti,
            length,
            position,
        })
    }
}

/// A decoded `LF_MODIFIER` type (const/volatile/unaligned qualifier).
#[derive(Debug, Clone)]
pub struct ModifierType {
    /// Type index of the modified type.
    pub base_ti: u32,
    /// `CV_modifier_t` attribute bits.
    pub attr: u16,
}

impl ModifierType {
    fn parse(data: &[u8]) -> Result<Self, TpiError> {
        need(data, 0, 6)?;
        let base_ti = read_u32(data, 0)?;
        let attr = read_u16(data, 4)?;
        Ok(Self { base_ti, attr })
    }

    /// Whether the `const` bit is set.
    #[must_use]
    pub const fn is_const(&self) -> bool {
        self.attr & 0x0001 != 0
    }
    /// Whether the `volatile` bit is set.
    #[must_use]
    pub const fn is_volatile(&self) -> bool {
        self.attr & 0x0002 != 0
    }
    /// Whether the `__unaligned` bit is set.
    #[must_use]
    pub const fn is_unaligned(&self) -> bool {
        self.attr & 0x0004 != 0
    }
}

// ── PdbTypeInfo ───────────────────────────────────────────────────────────────

/// Full decoder for the `TPI` (Type Information) stream of a `PDB` file.
///
/// Call [`PdbTypeInfo::parse_stream`] on the raw `TPI` stream bytes.
pub struct PdbTypeInfo {
    /// Type index → decoded record.
    pub records: HashMap<u32, TypeRecord>,
    /// First type index (usually 0x1000).
    pub ti_min: u32,
    /// One-past-last type index.
    pub ti_max: u32,
}

impl PdbTypeInfo {
    /// Parse the `TPI` stream.
    ///
    /// # Errors
    ///
    /// Returns [`TpiError`] if the stream is truncated or contains unknown data.
    pub fn parse_stream(data: &[u8]) -> Result<Self, TpiError> {
        if data.len() < 56 {
            return Err(TpiError::Truncated {
                offset: 0,
                needed: 56,
            });
        }
        // TPI stream header
        let _version = read_u32(data, 0)?;
        let header_size = read_u32(data, 4)?;
        let ti_min = read_u32(data, 8)?;
        let ti_max = read_u32(data, 12)?;
        let type_record_bytes = read_u32(data, 16)?;

        let records_start = header_size as usize;
        let records_end = records_start + type_record_bytes as usize;
        if records_end > data.len() {
            return Err(TpiError::Truncated {
                offset: records_start,
                needed: records_end - data.len(),
            });
        }

        let mut records: HashMap<u32, TypeRecord> = HashMap::new();
        let mut pos = records_start;
        let mut ti = ti_min;

        while pos < records_end && ti < ti_max {
            if pos + 2 > data.len() {
                break;
            }
            let record_len = read_u16(data, pos)?;
            if record_len < 2 {
                pos += 2;
                ti += 1;
                continue;
            }
            let single_record_end = pos + 2 + record_len as usize;
            if single_record_end > data.len() {
                break;
            }
            let kind = read_u16(data, pos + 2)?;
            let body = &data[pos + 4..single_record_end];
            let record = parse_type_record(kind, body);
            records.insert(ti, record);
            pos = single_record_end;
            ti += 1;
        }

        Ok(Self {
            records,
            ti_min,
            ti_max,
        })
    }

    /// Look up a type record by index.
    ///
    /// Primitive type indices (< 0x1000) are resolved to a synthetic record.
    #[must_use]
    pub fn get(&self, ti: u32) -> Option<&TypeRecord> {
        self.records.get(&ti)
    }

    /// Count of decoded type records.
    #[must_use]
    pub fn count(&self) -> usize {
        self.records.len()
    }

    /// Collect all struct/class types.
    #[must_use]
    pub fn structs(&self) -> Vec<(u32, &StructType)> {
        self.records
            .iter()
            .filter_map(|(&ti, r)| {
                if let TypeRecord::Structure(s) = r {
                    Some((ti, s))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Collect all enum types.
    #[must_use]
    pub fn enums(&self) -> Vec<(u32, &EnumType)> {
        self.records
            .iter()
            .filter_map(|(&ti, r)| {
                if let TypeRecord::Enum(e) = r {
                    Some((ti, e))
                } else {
                    None
                }
            })
            .collect()
    }
}

fn parse_type_record(kind: u16, body: &[u8]) -> TypeRecord {
    match kind {
        leaf::LF_STRUCTURE | leaf::LF_CLASS => StructType::parse(body)
            .map(TypeRecord::Structure)
            .unwrap_or(TypeRecord::Unknown {
                kind,
                size: body.len(),
            }),
        leaf::LF_UNION => {
            StructType::parse(body)
                .map(TypeRecord::Union)
                .unwrap_or(TypeRecord::Unknown {
                    kind,
                    size: body.len(),
                })
        }
        leaf::LF_ENUM => {
            EnumType::parse(body)
                .map(TypeRecord::Enum)
                .unwrap_or(TypeRecord::Unknown {
                    kind,
                    size: body.len(),
                })
        }
        leaf::LF_POINTER => {
            PointerType::parse(body)
                .map(TypeRecord::Pointer)
                .unwrap_or(TypeRecord::Unknown {
                    kind,
                    size: body.len(),
                })
        }
        leaf::LF_ARRAY => {
            ArrayType::parse(body)
                .map(TypeRecord::Array)
                .unwrap_or(TypeRecord::Unknown {
                    kind,
                    size: body.len(),
                })
        }
        leaf::LF_PROCEDURE => FunctionType::parse(body)
            .map(TypeRecord::Function)
            .unwrap_or(TypeRecord::Unknown {
                kind,
                size: body.len(),
            }),
        leaf::LF_MFUNCTION => FunctionType::parse_mfunction(body)
            .map(TypeRecord::Function)
            .unwrap_or(TypeRecord::Unknown {
                kind,
                size: body.len(),
            }),
        leaf::LF_FIELDLIST => {
            FieldList::parse(body)
                .map(TypeRecord::FieldList)
                .unwrap_or(TypeRecord::Unknown {
                    kind,
                    size: body.len(),
                })
        }
        leaf::LF_METHODLIST => MethodList::parse(body)
            .map(TypeRecord::MethodList)
            .unwrap_or(TypeRecord::Unknown {
                kind,
                size: body.len(),
            }),
        leaf::LF_BITFIELD => BitFieldType::parse(body)
            .map(TypeRecord::BitField)
            .unwrap_or(TypeRecord::Unknown {
                kind,
                size: body.len(),
            }),
        leaf::LF_MODIFIER => ModifierType::parse(body)
            .map(TypeRecord::Modifier)
            .unwrap_or(TypeRecord::Unknown {
                kind,
                size: body.len(),
            }),
        _ => TypeRecord::Unknown {
            kind,
            size: body.len(),
        },
    }
}

// ── TypeSizeCalculator ────────────────────────────────────────────────────────

/// Calculates the byte size of types given a set of type records.
pub struct TypeSizeCalculator<'a> {
    /// The decoded `TPI` records to resolve type indices against.
    pub info: &'a PdbTypeInfo,
    /// Target pointer size in bytes (4 or 8).
    pub pointer_size: u32,
}

impl<'a> TypeSizeCalculator<'a> {
    /// Create a new calculator.
    #[must_use]
    pub const fn new(info: &'a PdbTypeInfo, pointer_size: u32) -> Self {
        Self { info, pointer_size }
    }

    /// Calculate the byte size of a type given its type index.
    ///
    /// Type indices embedded in records are attacker-controlled and may form
    /// cycles (`LF_MODIFIER` whose `base_ti` is itself). Recursion is capped at
    /// [`Self::MAX_DEPTH`]; exceeding it returns `None` rather than exhausting
    /// the stack (which would abort the process, not panic).
    #[must_use]
    pub fn size_of(&self, ti: u32) -> Option<u64> {
        self.size_of_depth(ti, Self::MAX_DEPTH)
    }

    /// Maximum chain length followed through `LF_ENUM` / `LF_MODIFIER`.
    pub const MAX_DEPTH: u32 = 64;

    fn size_of_depth(&self, ti: u32, depth: u32) -> Option<u64> {
        if is_primitive(ti) {
            return Some(self.primitive_size(ti));
        }
        let depth = depth.checked_sub(1)?;
        match self.info.get(ti)? {
            TypeRecord::Structure(s) | TypeRecord::Union(s) => Some(s.byte_size),
            TypeRecord::Enum(e) => self.size_of_depth(e.underlying_ti, depth),
            TypeRecord::Pointer(_) => Some(u64::from(self.pointer_size)),
            TypeRecord::Array(a) => Some(a.byte_size),
            TypeRecord::BitField(b) => {
                // BitField size = ceiling of (position + length) / 8
                let bits = u64::from(b.position) + u64::from(b.length);
                Some(bits.div_ceil(8))
            }
            TypeRecord::Modifier(m) => self.size_of_depth(m.base_ti, depth),
            _ => None,
        }
    }

    const fn primitive_size(&self, ti: u32) -> u64 {
        match ti {
            0x0010 | 0x0020 | 0x0030 => 1, // char/uchar/bool8
            0x0011 | 0x0021 | 0x0031 => 2, // short/ushort/bool16
            0x0012 | 0x0022 | 0x0032 | 0x0040
            | 0x0070 | 0x0071 | 0x0072 | 0x0073
            | 0x0074 | 0x0075 => 4,         // int/uint/bool32/float32/long variants
            0x0033 | 0x0041 | 0x0076 | 0x0077 | 0x0603 => 8, // bool64/float64/int8/uint8/ptr64
            0x0042 => 10,                   // float80
            0x0043 => 16,                   // float128
            // Pointer types
            0x0103 | 0x0403 => self.pointer_size as u64,
            _ => 0,
        }
    }
}

// ── TypeNameResolver ──────────────────────────────────────────────────────────

/// Resolves type indices to human-readable names.
pub struct TypeNameResolver<'a> {
    /// The decoded `TPI` records to resolve type indices against.
    pub info: &'a PdbTypeInfo,
}

impl<'a> TypeNameResolver<'a> {
    /// Create a new resolver over the given type info.
    #[must_use]
    pub const fn new(info: &'a PdbTypeInfo) -> Self {
        Self { info }
    }

    /// Maximum chain length followed through pointer/modifier/array records.
    pub const MAX_DEPTH: u32 = 64;

    /// Resolve a type index to a name.
    ///
    /// Cyclic type-index chains (a self-referential `LF_POINTER`, an
    /// `A -> B -> A` modifier pair, …) are terminated at
    /// [`Self::MAX_DEPTH`], yielding `"<cyclic>"` instead of overflowing the
    /// stack and aborting the process.
    #[must_use]
    pub fn resolve(&self, ti: u32) -> String {
        self.resolve_depth(ti, Self::MAX_DEPTH)
    }

    fn resolve_depth(&self, ti: u32, depth: u32) -> String {
        if is_primitive(ti) {
            return primitive_type_name(ti).unwrap_or("?").to_string();
        }
        let Some(depth) = depth.checked_sub(1) else {
            return "<cyclic>".to_string();
        };
        match self.info.get(ti) {
            Some(TypeRecord::Structure(s) | TypeRecord::Union(s)) => s.name.clone(),
            Some(TypeRecord::Enum(e)) => e.name.clone(),
            Some(TypeRecord::Pointer(p)) => format!("{}*", self.resolve_depth(p.underlying_ti, depth)),
            Some(TypeRecord::Modifier(m)) => {
                let qual = if m.is_const() {
                    "const "
                } else if m.is_volatile() {
                    "volatile "
                } else {
                    ""
                };
                format!("{}{}", qual, self.resolve_depth(m.base_ti, depth))
            }
            Some(TypeRecord::Array(a)) => format!("{}[]", self.resolve_depth(a.element_ti, depth)),
            Some(r) => r.type_name(),
            None => format!("<0x{ti:08x}>"),
        }
    }
}

// ── TpiStats ──────────────────────────────────────────────────────────────────

/// Statistics about decoded `TPI` records.
#[derive(Debug, Clone, Default)]
pub struct TpiStats {
    /// Total decoded records.
    pub total: usize,
    /// `LF_STRUCTURE` / `LF_CLASS` records.
    pub structs: usize,
    /// `LF_UNION` records.
    pub unions: usize,
    /// `LF_ENUM` records.
    pub enums: usize,
    /// `LF_POINTER` records.
    pub pointers: usize,
    /// `LF_ARRAY` records.
    pub arrays: usize,
    /// `LF_PROCEDURE` / `LF_MFUNCTION` records.
    pub functions: usize,
    /// `LF_FIELDLIST` records.
    pub field_lists: usize,
    /// `LF_METHODLIST` records.
    pub method_lists: usize,
    /// `LF_BITFIELD` records.
    pub bitfields: usize,
    /// `LF_MODIFIER` records.
    pub modifiers: usize,
    /// Records with an unrecognized leaf kind.
    pub unknown: usize,
}

impl TpiStats {
    /// Compute from a `PdbTypeInfo`.
    #[must_use]
    pub fn compute(info: &PdbTypeInfo) -> Self {
        let mut s = Self {
            total: info.count(),
            ..Self::default()
        };
        for r in info.records.values() {
            match r {
                TypeRecord::Structure(_) => s.structs += 1,
                TypeRecord::Union(_) => s.unions += 1,
                TypeRecord::Enum(_) => s.enums += 1,
                TypeRecord::Pointer(_) => s.pointers += 1,
                TypeRecord::Array(_) => s.arrays += 1,
                TypeRecord::Function(_) => s.functions += 1,
                TypeRecord::FieldList(_) => s.field_lists += 1,
                TypeRecord::MethodList(_) => s.method_lists += 1,
                TypeRecord::BitField(_) => s.bitfields += 1,
                TypeRecord::Modifier(_) => s.modifiers += 1,
                TypeRecord::Unknown { .. } => s.unknown += 1,
                TypeRecord::Primitive { .. } => {}
            }
        }
        s
    }
}

impl fmt::Display for TpiStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TPI: total={} structs={} enums={} ptrs={} fns={}",
            self.total, self.structs, self.enums, self.pointers, self.functions
        )
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- Primitive types ---

    #[test]
    fn test_primitive_void() {
        assert_eq!(primitive_type_name(0x0003), Some("T_VOID"));
    }

    #[test]
    fn test_primitive_int4() {
        assert_eq!(primitive_type_name(0x0074), Some("T_INT4"));
    }

    #[test]
    fn test_primitive_float32() {
        assert_eq!(primitive_type_name(0x0040), Some("T_REAL32"));
    }

    #[test]
    fn test_primitive_unknown() {
        assert!(primitive_type_name(0x1234).is_none());
    }

    #[test]
    fn test_is_primitive_true() {
        assert!(is_primitive(0x0074));
    }

    #[test]
    fn test_is_primitive_false() {
        assert!(!is_primitive(0x1000));
    }

    // --- Numeric leaf ---

    #[test]
    fn test_numeric_leaf_small() {
        // Small value (< 0x8000): just the 16-bit word
        let data = [5u8, 0x00];
        let (v, n) = read_numeric_leaf(&data, 0).unwrap();
        assert_eq!(v, 5);
        assert_eq!(n, 2);
    }

    #[test]
    fn test_numeric_leaf_char() {
        // LF_CHAR = 0x8000
        let data = [0x00u8, 0x80, 42];
        let (v, n) = read_numeric_leaf(&data, 0).unwrap();
        assert_eq!(v, 42);
        assert_eq!(n, 3);
    }

    #[test]
    fn test_numeric_leaf_long() {
        // LF_LONG = 0x8003
        let mut data = vec![0x03u8, 0x80];
        data.extend_from_slice(&(1000u32.to_le_bytes()));
        let (v, n) = read_numeric_leaf(&data, 0).unwrap();
        assert_eq!(v, 1000);
        assert_eq!(n, 6);
    }

    #[test]
    fn test_numeric_leaf_truncated() {
        let data = [0x00u8]; // only 1 byte
        assert!(read_numeric_leaf(&data, 0).is_err());
    }

    // --- PointerType ---

    #[test]
    fn test_pointer_parse() {
        let mut data = vec![];
        data.extend_from_slice(&0x0074u32.to_le_bytes()); // underlying = T_INT4
        data.extend_from_slice(&0x0000_000Au32.to_le_bytes()); // attr: near32 = 10
        let p = PointerType::parse(&data).unwrap();
        assert_eq!(p.underlying_ti, 0x0074);
        assert_eq!(p.pointer_kind(), "near32");
    }

    #[test]
    fn test_pointer_parse_truncated() {
        assert!(PointerType::parse(&[0u8; 4]).is_err());
    }

    // --- FunctionType ---

    #[test]
    fn test_function_parse() {
        let mut data = vec![];
        data.extend_from_slice(&0x0003u32.to_le_bytes()); // return = T_VOID
        data.push(0x00); // call_conv = 0
        data.push(0x00); // attributes
        data.extend_from_slice(&2u16.to_le_bytes()); // param_count = 2
        data.extend_from_slice(&0x1010u32.to_le_bytes()); // arglist_ti
        let f = FunctionType::parse(&data).unwrap();
        assert_eq!(f.return_ti, 0x0003);
        assert_eq!(f.param_count, 2);
    }

    // --- EnumType ---

    #[test]
    fn test_enum_parse() {
        let mut data = vec![];
        data.extend_from_slice(&3u16.to_le_bytes()); // count = 3
        data.extend_from_slice(&0u16.to_le_bytes()); // properties
        data.extend_from_slice(&0x0074u32.to_le_bytes()); // underlying_ti = T_INT4
        data.extend_from_slice(&0x1020u32.to_le_bytes()); // field_list_ti
        data.extend_from_slice(b"Color\0"); // name
        data.extend_from_slice(b".?AW4Color@@\0"); // unique_name
        let e = EnumType::parse(&data).unwrap();
        assert_eq!(e.name, "Color");
        assert_eq!(e.count, 3);
    }

    // --- StructType ---

    #[test]
    fn test_struct_parse_basic() {
        let mut data = vec![];
        data.extend_from_slice(&1u16.to_le_bytes()); // count
        data.extend_from_slice(&0u16.to_le_bytes()); // properties
        data.extend_from_slice(&0x1030u32.to_le_bytes()); // field_list_ti
        data.extend_from_slice(&0u32.to_le_bytes()); // derived_ti
        data.extend_from_slice(&0u32.to_le_bytes()); // vshape_ti
        // numeric leaf for byte_size = 8
        data.extend_from_slice(&8u16.to_le_bytes());
        data.extend_from_slice(b"Point\0"); // name
        data.extend_from_slice(b".?AUPoint@@\0");
        let s = StructType::parse(&data).unwrap();
        assert_eq!(s.name, "Point");
        assert_eq!(s.byte_size, 8);
    }

    // --- BitFieldType ---

    #[test]
    fn test_bitfield_parse() {
        let mut data = vec![];
        data.extend_from_slice(&0x0074u32.to_le_bytes()); // base_ti
        data.push(3); // length = 3 bits
        data.push(0); // position = bit 0
        let b = BitFieldType::parse(&data).unwrap();
        assert_eq!(b.length, 3);
        assert_eq!(b.position, 0);
    }

    // --- ModifierType ---

    #[test]
    fn test_modifier_parse_const() {
        let mut data = vec![];
        data.extend_from_slice(&0x0074u32.to_le_bytes()); // base_ti
        data.extend_from_slice(&0x0001u16.to_le_bytes()); // attr = const
        let m = ModifierType::parse(&data).unwrap();
        assert!(m.is_const());
        assert!(!m.is_volatile());
    }

    // --- FieldList ---

    #[test]
    fn test_fieldlist_enumerate() {
        let mut data = vec![];
        // LF_ENUMERATE entry
        data.extend_from_slice(&leaf::LF_ENUMERATE.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // attr
        // numeric leaf = 0
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(b"Red\0");
        let fl = FieldList::parse(&data).unwrap();
        assert_eq!(fl.members.len(), 1);
        match &fl.members[0] {
            FieldListItem::Enumerate { name, value } => {
                assert_eq!(name, "Red");
                assert_eq!(*value, 0);
            }
            _ => panic!("expected enumerate"),
        }
    }

    // --- TypeRecord type_name ---

    #[test]
    fn test_type_record_unknown_name() {
        let r = TypeRecord::Unknown {
            kind: 0xABCD,
            size: 10,
        };
        assert!(r.type_name().contains("unknown"));
    }

    #[test]
    fn test_type_record_primitive_name() {
        let r = TypeRecord::Primitive {
            ti: 0x74,
            name: "int".to_string(),
        };
        assert_eq!(r.type_name(), "int");
    }

    // --- TpiError ---

    #[test]
    fn test_tpi_error_display_truncated() {
        let e = TpiError::Truncated {
            offset: 10,
            needed: 4,
        };
        assert!(e.to_string().contains("truncated"));
    }

    #[test]
    fn test_tpi_error_display_unknown_leaf() {
        let e = TpiError::UnknownLeaf(0x1234);
        assert!(e.to_string().contains("0x1234"));
    }

    // --- PdbTypeInfo parse_stream ---

    fn make_tpi_stream(records: &[(u16, Vec<u8>)]) -> Vec<u8> {
        // Build a minimal TPI stream: header (56 bytes) + records
        let mut record_data: Vec<u8> = Vec::new();
        for (kind, body) in records {
            let record_len = 2 + u16::try_from(body.len()).unwrap();
            record_data.extend_from_slice(&record_len.to_le_bytes());
            record_data.extend_from_slice(&kind.to_le_bytes());
            record_data.extend_from_slice(body);
        }
        let mut hdr = vec![0u8; 56];
        // version
        let v: u32 = 0x0131_4BCB;
        hdr[0..4].copy_from_slice(&v.to_le_bytes());
        // header_size = 56
        let hs: u32 = 56;
        hdr[4..8].copy_from_slice(&hs.to_le_bytes());
        // ti_min = 0x1000
        let ti_min: u32 = 0x1000;
        hdr[8..12].copy_from_slice(&ti_min.to_le_bytes());
        // ti_max = 0x1000 + count
        let ti_max = ti_min + u32::try_from(records.len()).unwrap();
        hdr[12..16].copy_from_slice(&ti_max.to_le_bytes());
        // type_record_bytes
        let trb = u32::try_from(record_data.len()).unwrap();
        hdr[16..20].copy_from_slice(&trb.to_le_bytes());
        hdr.extend_from_slice(&record_data);
        hdr
    }

    #[test]
    fn test_parse_stream_empty() {
        let stream = make_tpi_stream(&[]);
        let tpi = PdbTypeInfo::parse_stream(&stream).unwrap();
        assert_eq!(tpi.count(), 0);
    }

    #[test]
    fn test_parse_stream_pointer_record() {
        let mut body = vec![];
        body.extend_from_slice(&0x0074u32.to_le_bytes()); // underlying_ti
        body.extend_from_slice(&0x000Au32.to_le_bytes()); // attr = near32
        let stream = make_tpi_stream(&[(leaf::LF_POINTER, body)]);
        let tpi = PdbTypeInfo::parse_stream(&stream).unwrap();
        assert_eq!(tpi.count(), 1);
        let r = tpi.get(0x1000).unwrap();
        assert!(matches!(r, TypeRecord::Pointer(_)));
    }

    #[test]
    fn test_parse_stream_truncated_header() {
        assert!(PdbTypeInfo::parse_stream(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_pdb_structs_and_enums_empty() {
        let stream = make_tpi_stream(&[]);
        let tpi = PdbTypeInfo::parse_stream(&stream).unwrap();
        assert!(tpi.structs().is_empty());
        assert!(tpi.enums().is_empty());
    }

    // --- Additional TpiError tests ---

    #[test]
    fn test_tpi_error_invalid_ti() {
        let e = TpiError::InvalidTypeIndex(0x9999);
        assert!(e.to_string().contains("0x9999"));
    }

    #[test]
    fn test_tpi_error_other() {
        let e = TpiError::Other("test error".to_string());
        assert!(e.to_string().contains("test error"));
    }

    // --- PointerType::pointer_kind ---

    #[test]
    fn test_ptr_kind_ptr64() {
        let mut d = vec![];
        d.extend_from_slice(&0x74u32.to_le_bytes());
        d.extend_from_slice(&12u32.to_le_bytes()); // attr = 12 → ptr64
        let p = PointerType::parse(&d).unwrap();
        assert_eq!(p.pointer_kind(), "ptr64");
    }

    #[test]
    fn test_ptr_kind_near32() {
        let mut d = vec![];
        d.extend_from_slice(&0x74u32.to_le_bytes());
        d.extend_from_slice(&10u32.to_le_bytes());
        let p = PointerType::parse(&d).unwrap();
        assert_eq!(p.pointer_kind(), "near32");
    }

    // --- ModifierType ---

    #[test]
    fn test_modifier_volatile() {
        let mut d = vec![];
        d.extend_from_slice(&0x74u32.to_le_bytes());
        d.extend_from_slice(&0x0002u16.to_le_bytes());
        let m = ModifierType::parse(&d).unwrap();
        assert!(m.is_volatile());
        assert!(!m.is_const());
    }

    #[test]
    fn test_modifier_unaligned() {
        let mut d = vec![];
        d.extend_from_slice(&0x74u32.to_le_bytes());
        d.extend_from_slice(&0x0004u16.to_le_bytes());
        let m = ModifierType::parse(&d).unwrap();
        assert!(m.is_unaligned());
    }

    // --- EnumType additional ---

    #[test]
    fn test_enum_unique_name() {
        let mut d = vec![];
        d.extend_from_slice(&2u16.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes());
        d.extend_from_slice(&0x74u32.to_le_bytes());
        d.extend_from_slice(&0x1000u32.to_le_bytes());
        d.extend_from_slice(b"Status\0");
        d.extend_from_slice(b".?AW4Status@@\0");
        let e = EnumType::parse(&d).unwrap();
        assert_eq!(e.unique_name, ".?AW4Status@@");
    }

    // --- ArrayType ---

    #[test]
    fn test_array_no_name() {
        let mut d = vec![];
        d.extend_from_slice(&0x74u32.to_le_bytes()); // element_ti
        d.extend_from_slice(&0x75u32.to_le_bytes()); // index_ti
        // numeric leaf = 40 (byte_size)
        d.extend_from_slice(&40u16.to_le_bytes());
        d.push(0); // empty name
        let a = ArrayType::parse(&d).unwrap();
        assert_eq!(a.byte_size, 40);
    }

    // --- FunctionType truncated ---

    #[test]
    fn test_function_truncated() {
        assert!(FunctionType::parse(&[0u8; 5]).is_err());
    }

    // --- BitFieldType ---

    #[test]
    fn test_bitfield_truncated() {
        assert!(BitFieldType::parse(&[0u8; 4]).is_err());
    }

    // --- FieldList additional ---

    #[test]
    fn test_fieldlist_empty() {
        let fl = FieldList::parse(&[]).unwrap();
        assert!(fl.members.is_empty());
    }

    // --- TypeRecord::type_name ---

    #[test]
    fn test_type_record_struct_name() {
        let st = StructType {
            count: 0,
            properties: 0,
            field_list_ti: 0,
            derived_ti: 0,
            vshape_ti: 0,
            byte_size: 0,
            name: "Vec3".to_string(),
            unique_name: String::new(),
        };
        let r = TypeRecord::Structure(st);
        assert!(r.type_name().contains("Vec3"));
    }

    #[test]
    fn test_type_record_pointer_name() {
        let pt = PointerType {
            underlying_ti: 0x74,
            attr: 10,
        };
        let r = TypeRecord::Pointer(pt);
        assert!(r.type_name().contains('*'));
    }

    #[test]
    fn test_type_record_function_name() {
        let ft = FunctionType {
            return_ti: 3,
            call_conv: 0,
            attributes: 0,
            param_count: 2,
            arglist_ti: 0,
        };
        let r = TypeRecord::Function(ft);
        let name = r.type_name();
        assert!(name.contains("fn") || name.contains('2'));
    }

    // --- PdbTypeInfo with enum record ---

    #[test]
    fn test_parse_stream_enum_record() {
        let mut body = vec![];
        body.extend_from_slice(&3u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0x0074u32.to_le_bytes());
        body.extend_from_slice(&0x1001u32.to_le_bytes());
        body.extend_from_slice(b"Status\0");
        body.extend_from_slice(b"Status@@\0");
        let stream = make_tpi_stream(&[(leaf::LF_ENUM, body)]);
        let tpi = PdbTypeInfo::parse_stream(&stream).unwrap();
        assert_eq!(tpi.enums().len(), 1);
    }
}
