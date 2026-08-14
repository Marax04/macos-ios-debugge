//! `PDB` `TPI` (Type Info) stream types — extended leaf kind support.
//!
//! Provides a complete `LeafKind` enum, `TpiRecord` parser, `TypeIndex`,
//! and a `TypeDb` for resolving type indices.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── TypeIndex ─────────────────────────────────────────────────────────────────

/// A `PDB` type index (TI). TIs below 0x1000 are "primitive" types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TypeIndex(pub u32);

impl TypeIndex {
    /// First non-primitive (user-defined) type index.
    pub const FIRST_USER: u32 = 0x1000;

    /// Wrap a raw `u32` type index.
    #[must_use]
    pub const fn new(ti: u32) -> Self {
        Self(ti)
    }
    /// Whether this TI is in the primitive range (< 0x1000).
    #[must_use]
    pub const fn is_primitive(&self) -> bool {
        self.0 < Self::FIRST_USER
    }
    /// The raw `u32` value of this type index.
    #[must_use]
    pub const fn as_u32(&self) -> u32 {
        self.0
    }

    /// Describe a primitive type index.
    #[must_use]
    pub const fn primitive_name(&self) -> Option<&'static str> {
        match self.0 {
            0x0000 => Some("T_NOTYPE"),
            0x0003 => Some("T_VOID"),
            0x0008 => Some("T_HRESULT"),
            0x0010 => Some("T_CHAR"),
            0x0020 => Some("T_SHORT"),
            0x0022 => Some("T_INT4"),
            0x0023 => Some("T_UINT4"),
            0x0024 => Some("T_LONG"),
            0x0025 => Some("T_ULONG"),
            0x0030 => Some("T_REAL32"),
            0x0040 => Some("T_REAL64"),
            0x0068 => Some("T_INT8"),
            0x0069 => Some("T_UINT8"),
            0x0070 => Some("T_RCHAR"), // char8_t / unsigned char
            0x0071 => Some("T_WCHAR"),
            0x007a => Some("T_CHAR16"),
            0x007b => Some("T_CHAR32"),
            0x0400 => Some("T_32PVOID"),
            0x0603 => Some("T_64PVOID"),
            _ => None,
        }
    }
}

impl std::fmt::Display for TypeIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_primitive() {
            write!(
                f,
                "TI({:#06x}/{})",
                self.0,
                self.primitive_name().unwrap_or("T_?")
            )
        } else {
            write!(f, "TI({:#x})", self.0)
        }
    }
}

// ── LeafKind ──────────────────────────────────────────────────────────────────

/// `CodeView` leaf type codes as they appear in the `TPI` stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum LeafKind {
    // Fundamental / numeric leaves (0x8000+)
    /// `LF_CHAR` — signed 8-bit numeric leaf.
    Char = 0x8000,
    /// `LF_SHORT` — signed 16-bit numeric leaf.
    Short = 0x8001,
    /// `LF_USHORT` — unsigned 16-bit numeric leaf.
    UShort = 0x8002,
    /// `LF_LONG` — signed 32-bit numeric leaf.
    Long = 0x8003,
    /// `LF_ULONG` — unsigned 32-bit numeric leaf.
    ULong = 0x8004,
    /// `LF_REAL32` — 32-bit floating-point numeric leaf.
    Real32 = 0x8005,
    /// `LF_REAL64` — 64-bit floating-point numeric leaf.
    Real64 = 0x8006,
    /// `LF_REAL80` — 80-bit floating-point numeric leaf.
    Real80 = 0x8007,
    /// `LF_REAL128` — 128-bit floating-point numeric leaf.
    Real128 = 0x8008,
    /// `LF_QUADWORD` — signed 64-bit numeric leaf.
    Quadword = 0x8009,
    /// `LF_UQUADWORD` — unsigned 64-bit numeric leaf.
    UQuadword = 0x800A,
    /// `LF_REAL48` — 48-bit floating-point numeric leaf.
    Real48 = 0x800B,
    /// `LF_COMPLEX32` — 32-bit complex numeric leaf.
    Complex32 = 0x800C,
    /// `LF_COMPLEX64` — 64-bit complex numeric leaf.
    Complex64 = 0x800D,
    /// `LF_COMPLEX80` — 80-bit complex numeric leaf.
    Complex80 = 0x800E,
    /// `LF_COMPLEX128` — 128-bit complex numeric leaf.
    Complex128 = 0x800F,
    /// `LF_VARSTRING` — variable-length string numeric leaf.
    Varstring = 0x8010,
    /// `LF_OCTWORD` — signed 128-bit numeric leaf.
    Octword = 0x8017,
    /// `LF_UOCTWORD` — unsigned 128-bit numeric leaf.
    UOctword = 0x8018,

    // Type leaves (0x1000+)
    /// `LF_MODIFIER` — const/volatile/unaligned modifier.
    Modifier = 0x1001,
    /// `LF_POINTER` — pointer type.
    Pointer = 0x1002,
    /// `LF_ARRAY` — array type.
    Array = 0x1003,
    /// `LF_CLASS` — C++ class type.
    Class = 0x1004,
    /// `LF_STRUCTURE` — struct type.
    Structure = 0x1005,
    /// `LF_UNION` — union type.
    Union = 0x1006,
    /// `LF_ENUM` — enumeration type.
    Enum = 0x1007,
    /// `LF_PROCEDURE` — free-function type.
    Procedure = 0x1008,
    /// `LF_MFUNCTION` — member-function type.
    MFunction = 0x1009,
    /// `LF_ARGLIST` — argument type-index list for a procedure.
    ArgList = 0x100A,
    /// `LF_FIELDLIST` — member/base/enumerator list for an aggregate.
    FieldList = 0x100C,
    /// `LF_BITFIELD` — bit-field type.
    Bitfield = 0x100D,
    /// `LF_METHODLIST` — overload list for a method entry.
    Methodlist = 0x100F,
    /// `LF_DIMARRAY` — multi-dimensional array type.
    DimArray = 0x1015,
    /// `LF_PRECOMP` — precompiled-types reference.
    PreComp = 0x1016,
    /// `LF_ALIAS` — type alias (typedef).
    Alias = 0x100E,
    /// `LF_BARRAY` — basic array type.
    Barray = 0x1011,
    /// `LF_SKIP` — padding/skipped record.
    Skipped = 0x1012,

    // Member / field leaves (0x1400+)
    /// `LF_VFUNCTAB` — virtual function table pointer in a field list.
    Vfunctab = 0x1409,
    /// `LF_ENUMERATE` — enumerator (name + value) in a field list.
    Enumerate = 0x1502,
    /// Alternate id for an array leaf in the 0x1500 block.
    Array2 = 0x1503,
    /// Alternate id for a class leaf in the 0x1500 block.
    Class2 = 0x1504,
    /// Alternate id for a structure leaf in the 0x1500 block.
    Structure2 = 0x1505,
    /// Alternate id for a union leaf in the 0x1500 block.
    Union2 = 0x1506,
    /// Alternate id for an enum leaf in the 0x1500 block.
    Enum2 = 0x1507,
    /// Alternate id for a procedure leaf in the 0x1500 block.
    Procedure2 = 0x1508,
    /// Alternate id for a member-function leaf in the 0x1500 block.
    MFunction2 = 0x1509,
    /// `LF_COBOL0` — COBOL type record.
    Cobol0 = 0x100B,

    // 16-bit member leaves (0x0200+)
    /// `LF_MEMBER` — non-static data member in a field list.
    Member = 0x150D,
    /// `LF_STMEMBER` — static data member in a field list.
    StaticMember = 0x150E,
    /// `LF_METHOD` — overloaded method entry in a field list.
    Method = 0x150F,
    /// `LF_NESTTYPE` — nested type definition in a field list.
    NestedType = 0x1510,
    /// Base class entry in a field list.
    BaseClass = 0x1512,
    /// Virtual base class entry in a field list.
    VBaseClass = 0x1513,
    /// Indirect virtual base class entry in a field list.
    IVBaseClass = 0x1514,
    /// Virtual function offset entry in a field list.
    VFuncOff = 0x1516,
    /// `LF_TYPESERVER2` — external type-server (PDB) reference.
    TypeServer2 = 0x1515,
    /// Extended nested-type entry (`LF_NESTTYPEEX`-style).
    NestType = 0x1517,
    /// Member-modification entry (`LF_MEMBERMODIFY`-style).
    MemberMod = 0x1518,

    // Modifier leaves
    // NOTE: Modifier2 originally used 0x1001, which collides with Modifier
    // (the canonical CodeView leaf id). The collision broke compilation;
    // we reassign Modifier2 to a free synthetic id outside the official
    // CodeView range. Callers that need the canonical id should use
    // [`LeafKind::Modifier`] instead.
    /// Synthetic alternate modifier leaf id (see NOTE above — not a canonical `CodeView` id).
    Modifier2 = 0x1F01,

    // Unknown leaf
    /// Any leaf code not recognized by [`LeafKind::from_u16`].
    Unknown = 0xFFFF,
}

impl LeafKind {
    /// Map a raw leaf code to a `LeafKind`, or [`LeafKind::Unknown`].
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x8000 => Self::Char,
            0x8001 => Self::Short,
            0x8002 => Self::UShort,
            0x8003 => Self::Long,
            0x8004 => Self::ULong,
            0x8005 => Self::Real32,
            0x8006 => Self::Real64,
            0x8009 => Self::Quadword,
            0x800A => Self::UQuadword,
            0x1001 => Self::Modifier,
            0x1002 => Self::Pointer,
            0x1003 => Self::Array,
            0x1004 => Self::Class,
            0x1005 => Self::Structure,
            0x1006 => Self::Union,
            0x1007 => Self::Enum,
            0x1008 => Self::Procedure,
            0x1009 => Self::MFunction,
            0x100A => Self::ArgList,
            0x100C => Self::FieldList,
            0x100D => Self::Bitfield,
            0x100F => Self::Methodlist,
            0x150D => Self::Member,
            0x150E => Self::StaticMember,
            0x150F => Self::Method,
            0x1510 => Self::NestedType,
            0x1512 => Self::BaseClass,
            0x1513 => Self::VBaseClass,
            0x1502 => Self::Enumerate,
            0x1504 => Self::Class2,
            0x1505 => Self::Structure2,
            0x1506 => Self::Union2,
            0x1507 => Self::Enum2,
            0x1508 => Self::Procedure2,
            0x1509 => Self::MFunction2,
            0x1515 => Self::TypeServer2,
            0x1516 => Self::VFuncOff,
            0x1517 => Self::NestType,
            _ => Self::Unknown,
        }
    }

    /// Whether this leaf is a class/struct/union aggregate.
    #[must_use]
    pub const fn is_aggregate(&self) -> bool {
        matches!(
            self,
            Self::Class
                | Self::Structure
                | Self::Union
                | Self::Class2
                | Self::Structure2
                | Self::Union2
        )
    }

    /// Whether this leaf is a numeric leaf (0x8000..=0x8018).
    #[must_use]
    pub const fn is_numeric(&self) -> bool {
        (*self as u16) >= 0x8000 && (*self as u16) <= 0x8018
    }
}

impl std::fmt::Display for LeafKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LF_{self:?}")
    }
}

// ── TpiHeader ─────────────────────────────────────────────────────────────────

/// `PDB` `TPI` stream header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpiHeader {
    /// Stream version (V80 = 20040203).
    pub version: u32,
    /// Header size in bytes (records start here).
    pub header_size: u32,
    /// First type index in the stream (usually 0x1000).
    pub type_index_begin: u32,
    /// One-past-last type index.
    pub type_index_end: u32,
    /// Total size of the type-record data in bytes.
    pub type_record_bytes: u32,
    /// Stream index of the TPI hash stream.
    pub hash_stream_index: u16,
    /// Stream index of the auxiliary (padding) hash stream.
    pub id_stream_index: u16,
    /// Size of a hash key in bytes.
    pub hash_key_size: u32,
    /// Number of hash buckets.
    pub num_hash_buckets: u32,
    /// Offset of the hash value buffer within the hash stream.
    pub hash_value_buffer_offset: i32,
    /// Length of the hash value buffer in bytes.
    pub hash_value_buffer_length: u32,
    /// Offset of the index offset buffer within the hash stream.
    pub index_offset_buffer_offset: i32,
    /// Length of the index offset buffer in bytes.
    pub index_offset_buffer_length: u32,
    /// Offset of the hash adjustment buffer within the hash stream.
    pub hash_adj_buffer_offset: i32,
    /// Length of the hash adjustment buffer in bytes.
    pub hash_adj_buffer_length: u32,
}

impl TpiHeader {
    /// On-disk size of the header in bytes.
    pub const SERIALIZED_SIZE: usize = 56;
    /// Expected `version` for a V80 TPI stream.
    pub const EXPECTED_VERSION: u32 = 20_040_203;

    /// Deserialize from a 56-byte slice.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SERIALIZED_SIZE {
            return None;
        }
        let r = |off: usize| -> u32 {
            let bytes: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0u8; 4]);
            u32::from_le_bytes(bytes)
        };
        let r16 = |off: usize| -> u16 {
            let bytes: [u8; 2] = data[off..off + 2].try_into().unwrap_or([0u8; 2]);
            u16::from_le_bytes(bytes)
        };
        let ri = |off: usize| -> i32 {
            let bytes: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0u8; 4]);
            i32::from_le_bytes(bytes)
        };
        Some(Self {
            version: r(0),
            header_size: r(4),
            type_index_begin: r(8),
            type_index_end: r(12),
            type_record_bytes: r(16),
            hash_stream_index: r16(20),
            id_stream_index: r16(22),
            hash_key_size: r(24),
            num_hash_buckets: r(28),
            hash_value_buffer_offset: ri(32),
            hash_value_buffer_length: r(36),
            index_offset_buffer_offset: ri(40),
            index_offset_buffer_length: r(44),
            hash_adj_buffer_offset: ri(48),
            hash_adj_buffer_length: r(52),
        })
    }

    /// Number of type records declared by the header.
    #[must_use]
    pub const fn type_count(&self) -> u32 {
        self.type_index_end.saturating_sub(self.type_index_begin)
    }
}

// ── TpiRecord ─────────────────────────────────────────────────────────────────

/// A parsed `TPI` type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpiRecord {
    /// Type index assigned to this record.
    pub type_index: TypeIndex,
    /// Leaf kind of the record.
    pub kind: LeafKind,
    /// Parsed type-specific payload.
    pub data: TpiTypeData,
}

impl TpiRecord {
    /// Build a record from its parts.
    #[must_use]
    pub const fn new(ti: TypeIndex, kind: LeafKind, data: TpiTypeData) -> Self {
        Self {
            type_index: ti,
            kind,
            data,
        }
    }

    /// Parse a `TPI` record from raw bytes at `pos`.
    /// Returns `(record, bytes_consumed)`.
    #[must_use]
    pub fn parse(data: &[u8], pos: usize, ti: TypeIndex) -> Option<(Self, usize)> {
        if pos + 4 > data.len() {
            return None;
        }
        let length = u16::from_le_bytes(data[pos..pos + 2].try_into().ok()?) as usize;
        let leaf_code = u16::from_le_bytes(data[pos + 2..pos + 4].try_into().ok()?);
        let kind = LeafKind::from_u16(leaf_code);
        let payload = data.get(pos + 4..pos + 2 + length)?;
        let type_data = TpiTypeData::parse(kind, payload);
        let record = Self::new(ti, kind, type_data);
        Some((record, 2 + length))
    }

    /// Name carried by this record's payload, if the leaf kind has one.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match &self.data {
            TpiTypeData::Struct(s) => Some(&s.name),
            TpiTypeData::Enum(e) => Some(&e.name),
            // Pointer records have no name in the PDB stream — the const/volatile
            // qualifiers belong to the synthesized C-style spelling instead.
            TpiTypeData::Pointer(p) => {
                debug_assert!(p.pointee_ti.0 != u32::MAX, "pointer with sentinel pointee");
                None
            }
            TpiTypeData::Member(m) => Some(&m.name),
            TpiTypeData::Enumerator(e) => Some(&e.name),
            TpiTypeData::NestedType(n) => Some(&n.name),
            _ => None,
        }
    }
}

// ── TpiTypeData ───────────────────────────────────────────────────────────────

/// The type-specific payload of a `TPI` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TpiTypeData {
    /// Struct/class payload (`LF_STRUCTURE` / `LF_CLASS`).
    Struct(StructData),
    /// Enum payload (`LF_ENUM`).
    Enum(EnumData),
    /// Pointer payload (`LF_POINTER`).
    Pointer(PointerData),
    /// Array payload (`LF_ARRAY`).
    Array(ArrayData),
    /// Free-function payload (`LF_PROCEDURE`).
    Procedure(ProcedureData),
    /// Member-function payload (`LF_MFUNCTION`).
    MFunction(MFunctionData),
    /// Modifier payload (`LF_MODIFIER`).
    Modifier(ModifierData),
    /// Bit-field payload (`LF_BITFIELD`).
    Bitfield(BitfieldData),
    /// Field-list payload as member type indices (`LF_FIELDLIST`).
    FieldList(Vec<TypeIndex>),
    /// Data-member payload (`LF_MEMBER`).
    Member(MemberData),
    /// Enumerator payload (`LF_ENUMERATE`).
    Enumerator(EnumeratorData),
    /// Nested-type payload (`LF_NESTTYPE`).
    NestedType(NestedTypeData),
    /// Argument-list payload as type indices (`LF_ARGLIST`).
    ArgList(Vec<TypeIndex>),
    /// Unparsed raw payload bytes.
    Raw(Vec<u8>),
    /// No payload (record too short or empty).
    Empty,
}

impl TpiTypeData {
    fn parse(kind: LeafKind, payload: &[u8]) -> Self {
        match kind {
            LeafKind::Structure | LeafKind::Class | LeafKind::Structure2 | LeafKind::Class2 => {
                Self::Struct(StructData::parse(payload))
            }
            LeafKind::Enum | LeafKind::Enum2 => Self::Enum(EnumData::parse(payload)),
            LeafKind::Pointer => Self::Pointer(PointerData::parse(payload)),
            LeafKind::Array | LeafKind::Array2 => Self::Array(ArrayData::parse(payload)),
            LeafKind::Procedure | LeafKind::Procedure2 => {
                Self::Procedure(ProcedureData::parse(payload))
            }
            LeafKind::MFunction | LeafKind::MFunction2 => {
                Self::MFunction(MFunctionData::parse(payload))
            }
            LeafKind::Modifier | LeafKind::Modifier2 => {
                Self::Modifier(ModifierData::parse(payload))
            }
            LeafKind::Bitfield => Self::Bitfield(BitfieldData::parse(payload)),
            LeafKind::Member => Self::Member(MemberData::parse(payload)),
            LeafKind::Enumerate => Self::Enumerator(EnumeratorData::parse(payload)),
            LeafKind::NestedType | LeafKind::NestType => {
                Self::NestedType(NestedTypeData::parse(payload))
            }
            LeafKind::FieldList => {
                // Simplified: store raw bytes.
                Self::Raw(payload.to_vec())
            }
            LeafKind::ArgList => {
                // Parse as count + type indices.
                if payload.len() >= 4 {
                    let count =
                        u32::from_le_bytes(payload[0..4].try_into().unwrap_or([0; 4])) as usize;
                    let mut args = Vec::new();
                    for i in 0..count {
                        let off = 4 + i * 4;
                        if off + 4 <= payload.len() {
                            let ti = u32::from_le_bytes(
                                payload[off..off + 4].try_into().unwrap_or([0; 4]),
                            );
                            args.push(TypeIndex::new(ti));
                        }
                    }
                    Self::ArgList(args)
                } else {
                    Self::Empty
                }
            }
            _ => Self::Raw(payload.to_vec()),
        }
    }
}

// ── Struct / field data ───────────────────────────────────────────────────────

/// Payload of an `LF_STRUCTURE` / `LF_CLASS` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructData {
    /// Struct/class name.
    pub name: String,
    /// Number of elements in the field list.
    pub member_count: u16,
    /// Size in bytes (0 if not decoded).
    pub size: u32,
    /// Type index of the `LF_FIELDLIST` describing the members.
    pub field_list_ti: TypeIndex,
    /// Whether this is a forward reference (`fwdref` property bit).
    pub is_forward_ref: bool,
}

impl StructData {
    fn parse(data: &[u8]) -> Self {
        if data.len() < 8 {
            return Self {
                name: String::new(),
                member_count: 0,
                size: 0,
                field_list_ti: TypeIndex::new(0),
                is_forward_ref: false,
            };
        }
        let member_count = u16::from_le_bytes(data[0..2].try_into().unwrap_or([0; 2]));
        let props = u16::from_le_bytes(data[2..4].try_into().unwrap_or([0; 2]));
        let is_forward_ref = (props & 0x80) != 0;
        let field_list_ti =
            TypeIndex::new(u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4])));
        // Size is encoded as a numeric leaf at data[8+]; compute its byte width
        // so the name offset is correct for all leaf widths (2–10 bytes).
        let name_off = if data.len() >= 10 {
            let kind = u16::from_le_bytes([data[8], data[9]]);
            8 + if kind < 0x8000 {
                2 // value fits inline in the 2-byte kind field
            } else {
                match kind {
                    0x8000 => 3,  // LF_CHAR
                    0x8001 | 0x8002 => 4,  // LF_SHORT / LF_USHORT
                    0x8003 | 0x8004 => 6,  // LF_LONG / LF_ULONG
                    0x8009 | 0x800a => 10, // LF_QUADWORD / LF_UQUADWORD
                    _ => 2,
                }
            }
        } else {
            14
        };
        let name = extract_z_string(data, name_off);
        Self {
            name,
            member_count,
            size: 0,
            field_list_ti,
            is_forward_ref,
        }
    }
}

/// Payload of an `LF_ENUM` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumData {
    /// Enum name.
    pub name: String,
    /// Number of enumerators.
    pub member_count: u16,
    /// Type index of the underlying integer type.
    pub underlying_ti: TypeIndex,
    /// Type index of the `LF_FIELDLIST` holding the enumerators.
    pub field_list_ti: TypeIndex,
}

impl EnumData {
    fn parse(data: &[u8]) -> Self {
        if data.len() < 12 {
            return Self {
                name: String::new(),
                member_count: 0,
                underlying_ti: TypeIndex::new(0x22),
                field_list_ti: TypeIndex::new(0),
            };
        }
        let member_count = u16::from_le_bytes(data[0..2].try_into().unwrap_or([0; 2]));
        let underlying_ti =
            TypeIndex::new(u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4])));
        let field_list_ti =
            TypeIndex::new(u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4])));
        let name = extract_z_string(data, 12);
        Self {
            name,
            member_count,
            underlying_ti,
            field_list_ti,
        }
    }
}

/// Payload of an `LF_POINTER` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerData {
    /// Type index of the pointed-to type.
    pub pointee_ti: TypeIndex,
    /// `CV_ptrtype` pointer kind (low 5 attribute bits).
    pub pointer_type: u8,
    /// Whether the pointer itself is `const`.
    pub is_const: bool,
    /// Whether the pointer itself is `volatile`.
    pub is_volatile: bool,
}

impl PointerData {
    fn parse(data: &[u8]) -> Self {
        if data.len() < 8 {
            return Self {
                pointee_ti: TypeIndex::new(0x3),
                pointer_type: 0,
                is_const: false,
                is_volatile: false,
            };
        }
        let pointee_ti =
            TypeIndex::new(u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4])));
        let attr = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]));
        let pointer_type = (attr & 0x1f) as u8;
        let is_const = (attr >> 10) & 1 != 0;
        let is_volatile = (attr >> 11) & 1 != 0;
        Self {
            pointee_ti,
            pointer_type,
            is_const,
            is_volatile,
        }
    }
}

/// Payload of an `LF_ARRAY` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArrayData {
    /// Type index of the element type.
    pub element_ti: TypeIndex,
    /// Type index of the indexing type.
    pub index_ti: TypeIndex,
    /// Total size in bytes (0 if not decoded).
    pub size: u32,
}

impl ArrayData {
    fn parse(data: &[u8]) -> Self {
        if data.len() < 8 {
            return Self {
                element_ti: TypeIndex::new(0),
                index_ti: TypeIndex::new(0x22),
                size: 0,
            };
        }
        let element_ti =
            TypeIndex::new(u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4])));
        let index_ti = TypeIndex::new(u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4])));
        Self {
            element_ti,
            index_ti,
            size: 0,
        }
    }
}

/// Payload of an `LF_PROCEDURE` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcedureData {
    /// Type index of the return type.
    pub return_ti: TypeIndex,
    /// `CV_call_t` calling convention code.
    pub call_conv: u8,
    /// Number of parameters.
    pub arg_count: u16,
    /// Type index of the `LF_ARGLIST` holding parameter types.
    pub arg_list_ti: TypeIndex,
}

impl ProcedureData {
    fn parse(data: &[u8]) -> Self {
        if data.len() < 12 {
            return Self {
                return_ti: TypeIndex::new(3),
                call_conv: 0,
                arg_count: 0,
                arg_list_ti: TypeIndex::new(0),
            };
        }
        let return_ti = TypeIndex::new(u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4])));
        let call_conv = data[4];
        let arg_count = u16::from_le_bytes(data[6..8].try_into().unwrap_or([0; 2]));
        let arg_list_ti =
            TypeIndex::new(u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4])));
        Self {
            return_ti,
            call_conv,
            arg_count,
            arg_list_ti,
        }
    }
}

/// Payload of an `LF_MFUNCTION` (member function) record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MFunctionData {
    /// Type index of the return type.
    pub return_ti: TypeIndex,
    /// Type index of the containing class.
    pub class_ti: TypeIndex,
    /// Type index of the `this` pointer type (0 for static methods).
    pub this_ti: TypeIndex,
    /// `CV_call_t` calling convention code.
    pub call_conv: u8,
    /// Number of parameters.
    pub param_count: u16,
    /// Type index of the `LF_ARGLIST` holding parameter types.
    pub arg_list_ti: TypeIndex,
}

impl MFunctionData {
    fn parse(data: &[u8]) -> Self {
        if data.len() < 20 {
            return Self {
                return_ti: TypeIndex::new(3),
                class_ti: TypeIndex::new(0),
                this_ti: TypeIndex::new(0),
                call_conv: 0,
                param_count: 0,
                arg_list_ti: TypeIndex::new(0),
            };
        }
        Self {
            return_ti: TypeIndex::new(u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]))),
            class_ti: TypeIndex::new(u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]))),
            this_ti: TypeIndex::new(u32::from_le_bytes(data[8..12].try_into().unwrap_or([0; 4]))),
            call_conv: data[12],
            param_count: u16::from_le_bytes(data[14..16].try_into().unwrap_or([0; 2])),
            arg_list_ti: TypeIndex::new(u32::from_le_bytes(
                data[16..20].try_into().unwrap_or([0; 4]),
            )),
        }
    }
}

/// Payload of an `LF_MODIFIER` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModifierData {
    /// Type index of the modified type.
    pub modified_ti: TypeIndex,
    /// Whether the `const` bit is set.
    pub is_const: bool,
    /// Whether the `volatile` bit is set.
    pub is_volatile: bool,
    /// Whether the `__unaligned` bit is set.
    pub is_unaligned: bool,
}

impl ModifierData {
    fn parse(data: &[u8]) -> Self {
        if data.len() < 6 {
            return Self {
                modified_ti: TypeIndex::new(0),
                is_const: false,
                is_volatile: false,
                is_unaligned: false,
            };
        }
        let modified_ti =
            TypeIndex::new(u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4])));
        let flags = u16::from_le_bytes(data[4..6].try_into().unwrap_or([0; 2]));
        Self {
            modified_ti,
            is_const: (flags & 1) != 0,
            is_volatile: (flags & 2) != 0,
            is_unaligned: (flags & 4) != 0,
        }
    }
}

/// Payload of an `LF_BITFIELD` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitfieldData {
    /// Type index of the underlying integer type.
    pub base_ti: TypeIndex,
    /// Width of the bit-field in bits.
    pub bit_length: u8,
    /// Starting bit position within the underlying type.
    pub bit_offset: u8,
}

impl BitfieldData {
    fn parse(data: &[u8]) -> Self {
        if data.len() < 6 {
            return Self {
                base_ti: TypeIndex::new(0x22),
                bit_length: 1,
                bit_offset: 0,
            };
        }
        let base_ti = TypeIndex::new(u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4])));
        Self {
            base_ti,
            bit_length: data[4],
            bit_offset: data[5],
        }
    }
}

/// Payload of an `LF_MEMBER` (data member) record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberData {
    /// Member name.
    pub name: String,
    /// Type index of the member's type.
    pub type_ti: TypeIndex,
    /// Byte offset within the aggregate (0 if not decoded).
    pub offset: u32,
    /// Whether the member is static.
    pub is_static: bool,
}

impl MemberData {
    fn parse(data: &[u8]) -> Self {
        if data.len() < 8 {
            return Self {
                name: String::new(),
                type_ti: TypeIndex::new(0),
                offset: 0,
                is_static: false,
            };
        }
        let type_ti = TypeIndex::new(u32::from_le_bytes(data[2..6].try_into().unwrap_or([0; 4])));
        let name = extract_z_string(data, 8);
        Self {
            name,
            type_ti,
            offset: 0,
            is_static: false,
        }
    }
}

/// Payload of an `LF_ENUMERATE` (enumerator) record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumeratorData {
    /// Enumerator name.
    pub name: String,
    /// Enumerator value (0 if not decoded).
    pub value: i64,
}

impl EnumeratorData {
    fn parse(data: &[u8]) -> Self {
        let name = extract_z_string(data, 4);
        Self { name, value: 0 }
    }
}

/// Payload of an `LF_NESTTYPE` (nested type) record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestedTypeData {
    /// Nested type name.
    pub name: String,
    /// Type index of the nested type.
    pub nested_ti: TypeIndex,
}

impl NestedTypeData {
    fn parse(data: &[u8]) -> Self {
        if data.len() < 6 {
            return Self {
                name: String::new(),
                nested_ti: TypeIndex::new(0),
            };
        }
        let nested_ti = TypeIndex::new(u32::from_le_bytes(data[2..6].try_into().unwrap_or([0; 4])));
        let name = extract_z_string(data, 6);
        Self { name, nested_ti }
    }
}

fn extract_z_string(data: &[u8], off: usize) -> String {
    if off >= data.len() {
        return String::new();
    }
    let end = data[off..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(data.len() - off);
    String::from_utf8_lossy(&data[off..off + end]).to_string()
}

// ── TypeDb ────────────────────────────────────────────────────────────────────

/// A database mapping type indices to parsed `TPI` records.
#[derive(Debug, Default)]
pub struct TypeDb {
    /// Type index → parsed record.
    pub records: HashMap<u32, TpiRecord>,
    /// Type name → type index, for name lookups.
    pub name_to_ti: HashMap<String, u32>,
}

impl TypeDb {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a record, indexing it by type index and (if named) by name.
    pub fn insert(&mut self, record: TpiRecord) {
        if let Some(name) = record.name().map(std::string::ToString::to_string) {
            self.name_to_ti.insert(name, record.type_index.as_u32());
        }
        self.records.insert(record.type_index.as_u32(), record);
    }

    /// Look up a record by type index; primitives always return `None`.
    #[must_use]
    pub fn get(&self, ti: TypeIndex) -> Option<&TpiRecord> {
        if ti.is_primitive() {
            return None;
        }
        self.records.get(&ti.as_u32())
    }

    /// Look up a record by type name.
    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<&TpiRecord> {
        let ti = self.name_to_ti.get(name)?;
        self.records.get(ti)
    }

    /// Number of records in the database.
    #[must_use]
    pub fn count(&self) -> usize {
        self.records.len()
    }

    /// Iterate over struct/class records.
    pub fn iter_structs(&self) -> impl Iterator<Item = &TpiRecord> {
        self.records.values().filter(|r| {
            matches!(
                r.kind,
                LeafKind::Structure | LeafKind::Class | LeafKind::Structure2 | LeafKind::Class2
            )
        })
    }

    /// Iterate over enum records.
    pub fn iter_enums(&self) -> impl Iterator<Item = &TpiRecord> {
        self.records
            .values()
            .filter(|r| matches!(r.kind, LeafKind::Enum | LeafKind::Enum2))
    }

    /// Iterate over pointer records.
    pub fn iter_pointers(&self) -> impl Iterator<Item = &TpiRecord> {
        self.records
            .values()
            .filter(|r| r.kind == LeafKind::Pointer)
    }

    /// Parse a `TPI` record stream and populate this database.
    pub fn load_from_bytes(&mut self, data: &[u8], first_ti: u32) {
        let mut pos = 0usize;
        let mut ti_counter = first_ti;
        while pos < data.len() {
            let ti = TypeIndex::new(ti_counter);
            match TpiRecord::parse(data, pos, ti) {
                Some((record, consumed)) => {
                    pos += consumed;
                    ti_counter += 1;
                    self.insert(record);
                }
                None => break,
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TypeIndex ─────────────────────────────────────────────────────────────

    #[test]
    fn test_ti_primitive() {
        assert!(TypeIndex::new(0x0003).is_primitive());
        assert!(!TypeIndex::new(0x1000).is_primitive());
    }

    #[test]
    fn test_ti_primitive_name() {
        assert_eq!(TypeIndex::new(0x0003).primitive_name(), Some("T_VOID"));
        assert_eq!(TypeIndex::new(0x0022).primitive_name(), Some("T_INT4"));
        assert_eq!(TypeIndex::new(0xFFFF).primitive_name(), None);
    }

    #[test]
    fn test_ti_display_primitive() {
        let s = TypeIndex::new(0x0003).to_string();
        assert!(s.contains("T_VOID"));
    }

    #[test]
    fn test_ti_display_user() {
        let s = TypeIndex::new(0x1234).to_string();
        assert!(s.contains("0x1234"));
    }

    // ── LeafKind ──────────────────────────────────────────────────────────────

    #[test]
    fn test_leafkind_from_u16_structure() {
        assert_eq!(LeafKind::from_u16(0x1005), LeafKind::Structure);
    }

    #[test]
    fn test_leafkind_from_u16_class() {
        assert_eq!(LeafKind::from_u16(0x1004), LeafKind::Class);
    }

    #[test]
    fn test_leafkind_from_u16_enum() {
        assert_eq!(LeafKind::from_u16(0x1007), LeafKind::Enum);
    }

    #[test]
    fn test_leafkind_from_u16_pointer() {
        assert_eq!(LeafKind::from_u16(0x1002), LeafKind::Pointer);
    }

    #[test]
    fn test_leafkind_from_u16_procedure() {
        assert_eq!(LeafKind::from_u16(0x1008), LeafKind::Procedure);
    }

    #[test]
    fn test_leafkind_from_u16_mfunction() {
        assert_eq!(LeafKind::from_u16(0x1009), LeafKind::MFunction);
    }

    #[test]
    fn test_leafkind_from_u16_bitfield() {
        assert_eq!(LeafKind::from_u16(0x100D), LeafKind::Bitfield);
    }

    #[test]
    fn test_leafkind_from_u16_member() {
        assert_eq!(LeafKind::from_u16(0x150D), LeafKind::Member);
    }

    #[test]
    fn test_leafkind_from_u16_enumerate() {
        assert_eq!(LeafKind::from_u16(0x1502), LeafKind::Enumerate);
    }

    #[test]
    fn test_leafkind_from_u16_modifier() {
        assert_eq!(LeafKind::from_u16(0x1001), LeafKind::Modifier);
    }

    #[test]
    fn test_leafkind_from_u16_unknown() {
        assert_eq!(LeafKind::from_u16(0xDEAD), LeafKind::Unknown);
    }

    #[test]
    fn test_leafkind_is_aggregate() {
        assert!(LeafKind::Structure.is_aggregate());
        assert!(LeafKind::Class.is_aggregate());
        assert!(LeafKind::Union.is_aggregate());
        assert!(!LeafKind::Pointer.is_aggregate());
    }

    #[test]
    fn test_leafkind_is_numeric() {
        assert!(LeafKind::Char.is_numeric());
        assert!(LeafKind::Real64.is_numeric());
        assert!(!LeafKind::Structure.is_numeric());
    }

    #[test]
    fn test_leafkind_display() {
        let s = LeafKind::Structure.to_string();
        assert!(s.contains("Structure"));
    }

    // ── TpiHeader ─────────────────────────────────────────────────────────────

    #[test]
    fn test_tpi_header_too_short() {
        assert!(TpiHeader::from_bytes(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_tpi_header_parse() {
        let mut data = vec![0u8; 56];
        // Write version.
        data[0..4].copy_from_slice(&20_040_203_u32.to_le_bytes());
        // header_size = 56.
        data[4..8].copy_from_slice(&56u32.to_le_bytes());
        // type_index_begin = 0x1000.
        data[8..12].copy_from_slice(&0x1000u32.to_le_bytes());
        // type_index_end = 0x1100.
        data[12..16].copy_from_slice(&0x1100u32.to_le_bytes());
        let h = TpiHeader::from_bytes(&data).unwrap();
        assert_eq!(h.version, 20_040_203);
        assert_eq!(h.type_index_begin, 0x1000);
        assert_eq!(h.type_count(), 0x100);
    }

    // ── PointerData ───────────────────────────────────────────────────────────

    #[test]
    fn test_pointer_data_parse() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&0x1005u32.to_le_bytes()); // pointee = struct
        let p = PointerData::parse(&data);
        assert_eq!(p.pointee_ti.as_u32(), 0x1005);
        assert!(!p.is_const);
    }

    #[test]
    fn test_pointer_data_const() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        let attr = 1u32 << 10; // is_const
        data[4..8].copy_from_slice(&attr.to_le_bytes());
        let p = PointerData::parse(&data);
        assert!(p.is_const);
    }

    // ── TypeDb ────────────────────────────────────────────────────────────────

    #[test]
    fn test_typedb_insert_and_count() {
        let mut db = TypeDb::new();
        let r = TpiRecord::new(
            TypeIndex::new(0x1000),
            LeafKind::Pointer,
            TpiTypeData::Pointer(PointerData {
                pointee_ti: TypeIndex::new(3),
                pointer_type: 0,
                is_const: false,
                is_volatile: false,
            }),
        );
        db.insert(r);
        assert_eq!(db.count(), 1);
    }

    #[test]
    fn test_typedb_get() {
        let mut db = TypeDb::new();
        let ti = TypeIndex::new(0x1001);
        db.insert(TpiRecord::new(ti, LeafKind::Pointer, TpiTypeData::Empty));
        assert!(db.get(ti).is_some());
        assert!(db.get(TypeIndex::new(0x9999)).is_none());
    }

    #[test]
    fn test_typedb_primitive_returns_none() {
        let db = TypeDb::new();
        assert!(db.get(TypeIndex::new(0x0003)).is_none());
    }

    #[test]
    fn test_typedb_iter_structs() {
        let mut db = TypeDb::new();
        db.insert(TpiRecord::new(
            TypeIndex::new(0x1000),
            LeafKind::Structure,
            TpiTypeData::Struct(StructData {
                name: "Foo".into(),
                member_count: 0,
                size: 0,
                field_list_ti: TypeIndex::new(0),
                is_forward_ref: false,
            }),
        ));
        db.insert(TpiRecord::new(
            TypeIndex::new(0x1001),
            LeafKind::Pointer,
            TpiTypeData::Empty,
        ));
        assert_eq!(db.iter_structs().count(), 1);
    }

    #[test]
    fn test_typedb_iter_enums() {
        let mut db = TypeDb::new();
        db.insert(TpiRecord::new(
            TypeIndex::new(0x1000),
            LeafKind::Enum,
            TpiTypeData::Enum(EnumData {
                name: "Color".into(),
                member_count: 3,
                underlying_ti: TypeIndex::new(0x22),
                field_list_ti: TypeIndex::new(0),
            }),
        ));
        assert_eq!(db.iter_enums().count(), 1);
    }

    #[test]
    fn test_typedb_get_by_name() {
        let mut db = TypeDb::new();
        db.insert(TpiRecord::new(
            TypeIndex::new(0x1000),
            LeafKind::Structure,
            TpiTypeData::Struct(StructData {
                name: "MyStruct".into(),
                member_count: 2,
                size: 16,
                field_list_ti: TypeIndex::new(0),
                is_forward_ref: false,
            }),
        ));
        let r = db.get_by_name("MyStruct");
        assert!(r.is_some());
    }
}
