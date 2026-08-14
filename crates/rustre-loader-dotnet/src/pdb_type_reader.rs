// pdb_type_reader.rs — PDB TPI/IPI stream type record parser
// Implements Microsoft PDB format type parsing as described in
// llvm-pdbutil / cvdump documentation and CVINFO.H definitions.

use std::collections::HashMap;
use std::fmt;

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdbTypeError {
    TruncatedData { offset: usize, needed: usize, have: usize },
    InvalidSignature { expected: u32, got: u32 },
    UnknownLeafKind(u16),
    InvalidUtf8 { offset: usize },
    IndexOutOfRange { index: u32, max: u32 },
    InvalidStream,
    NullTerminatorMissing,
}

impl fmt::Display for PdbTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedData { offset, needed, have } =>
                write!(f, "truncated at offset {offset}: needed {needed} bytes, have {have}"),
            Self::InvalidSignature { expected, got } =>
                write!(f, "invalid TPI signature: expected 0x{expected:08X}, got 0x{got:08X}"),
            Self::UnknownLeafKind(k) =>
                write!(f, "unknown leaf kind 0x{k:04X}"),
            Self::InvalidUtf8 { offset } =>
                write!(f, "invalid UTF-8 at offset {offset}"),
            Self::IndexOutOfRange { index, max } =>
                write!(f, "type index {index} out of range (max {max})"),
            Self::InvalidStream => write!(f, "invalid stream structure"),
            Self::NullTerminatorMissing => write!(f, "null terminator missing in string"),
        }
    }
}

impl std::error::Error for PdbTypeError {}

// ── Type index ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeIndex(pub u32);

impl fmt::Display for TypeIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "T{:#06X}", self.0)
    }
}

impl TypeIndex {
    pub const VOID: Self = Self(0x0003);
    pub const HRESULT: Self = Self(0x0008);
    pub const BOOL8: Self = Self(0x0030);
    pub const CHAR: Self = Self(0x0070);
    pub const WCHAR: Self = Self(0x0071);
    pub const INT1: Self = Self(0x0068);
    pub const UINT1: Self = Self(0x0069);
    pub const INT2: Self = Self(0x0072);
    pub const UINT2: Self = Self(0x0073);
    pub const INT4: Self = Self(0x0074);
    pub const UINT4: Self = Self(0x0075);
    pub const INT8: Self = Self(0x0076);
    pub const UINT8: Self = Self(0x0077);
    pub const FLOAT32: Self = Self(0x0040);
    pub const FLOAT64: Self = Self(0x0041);
    pub const FLOAT80: Self = Self(0x0042);

    #[must_use] 
    pub const fn is_builtin(self) -> bool { self.0 < 0x1000 }

    #[must_use] 
    pub const fn builtin_name(self) -> Option<&'static str> {
        match self.0 {
            0x0003 => Some("void"),
            0x0008 => Some("HRESULT"),
            0x0030 => Some("bool"),
            0x0068 => Some("int8_t"),
            0x0069 => Some("uint8_t"),
            0x0070 => Some("char"),
            0x0071 => Some("wchar_t"),
            0x0072 => Some("short"),
            0x0073 => Some("unsigned short"),
            0x0074 => Some("int"),
            0x0075 => Some("unsigned int"),
            0x0076 => Some("int64_t"),
            0x0077 => Some("uint64_t"),
            0x0040 => Some("float"),
            0x0041 => Some("double"),
            0x0042 => Some("long double"),
            _ => None,
        }
    }
}

// ── Primitive types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimitiveKind {
    Void,
    Bool,
    Char,
    WChar,
    RChar,   // char32_t
    I8, U8,
    I16, U16,
    I32, U32,
    I64, U64,
    I128, U128,
    Float32,
    Float64,
    Float80,
    Float128,
    HResult,
    Unknown(u32),
}

impl PrimitiveKind {
    #[must_use] 
    pub const fn from_index(idx: u32) -> Self {
        let base = idx & 0xFF;
        match base {
            0x00 => Self::Unknown(idx),
            0x03 => Self::Void,
            0x08 => Self::HResult,
            0x10 | 0x68 => Self::I8,
            0x11 | 0x69 => Self::U8,
            0x20 | 0x72 => Self::I16,
            0x21 | 0x73 => Self::U16,
            0x30 => Self::Bool,
            0x40 => Self::Float32,
            0x41 => Self::Float64,
            0x42 => Self::Float80,
            0x43 => Self::Float128,
            0x70 => Self::Char,
            0x71 => Self::WChar,
            0x74 => Self::I32,
            0x75 => Self::U32,
            0x76 => Self::I64,
            0x77 => Self::U64,
            0x78 => Self::I128,
            0x79 => Self::U128,
            0x7c => Self::RChar,
            _ => Self::Unknown(idx),
        }
    }

    #[must_use] 
    pub const fn byte_size(&self) -> Option<usize> {
        match self {
            Self::Void => Some(0),
            Self::Bool | Self::I8 | Self::U8 | Self::Char => Some(1),
            Self::WChar | Self::I16 | Self::U16 => Some(2),
            Self::RChar | Self::I32 | Self::U32 | Self::Float32 => Some(4),
            Self::I64 | Self::U64 | Self::Float64 => Some(8),
            Self::Float80 => Some(10),
            Self::I128 | Self::U128 | Self::Float128 => Some(16),
            Self::HResult => Some(4),
            Self::Unknown(_) => None,
        }
    }
}

// ── Calling conventions ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConv {
    NearC,      // 0x00
    FarC,       // 0x01
    NearPascal, // 0x02
    FarPascal,  // 0x03
    NearFast,   // 0x04
    FarFast,    // 0x05
    NearStd,    // 0x07
    FarStd,     // 0x08
    NearSys,    // 0x09
    FarSys,     // 0x0A
    ThisCall,   // 0x0B
    MipsCall,   // 0x0C
    Generic,    // 0x0D
    AlphaCall,  // 0x0E
    PpcCall,    // 0x0F
    SHCall,     // 0x10
    ArmCall,    // 0x11
    Am33Call,   // 0x12
    TriCall,    // 0x13
    Sh5Call,    // 0x14
    M32RCall,   // 0x15
    ClrCall,    // 0x16
    Inline,     // 0x17
    NearVec,    // 0x18
    Unknown(u8),
}

impl CallingConv {
    #[must_use] 
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Self::NearC,
            0x01 => Self::FarC,
            0x02 => Self::NearPascal,
            0x03 => Self::FarPascal,
            0x04 => Self::NearFast,
            0x05 => Self::FarFast,
            0x07 => Self::NearStd,
            0x08 => Self::FarStd,
            0x09 => Self::NearSys,
            0x0A => Self::FarSys,
            0x0B => Self::ThisCall,
            0x0C => Self::MipsCall,
            0x0D => Self::Generic,
            0x0E => Self::AlphaCall,
            0x0F => Self::PpcCall,
            0x10 => Self::SHCall,
            0x11 => Self::ArmCall,
            0x12 => Self::Am33Call,
            0x13 => Self::TriCall,
            0x14 => Self::Sh5Call,
            0x15 => Self::M32RCall,
            0x16 => Self::ClrCall,
            0x17 => Self::Inline,
            0x18 => Self::NearVec,
            other => Self::Unknown(other),
        }
    }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::NearC | Self::FarC => "__cdecl",
            Self::NearPascal | Self::FarPascal => "__pascal",
            Self::NearFast | Self::FarFast => "__fastcall",
            Self::NearStd | Self::FarStd => "__stdcall",
            Self::NearSys | Self::FarSys => "__syscall",
            Self::ThisCall => "__thiscall",
            Self::ClrCall => "__clrcall",
            Self::Inline => "__inline",
            Self::NearVec => "__vectorcall",
            _ => "??",
        }
    }
}

// ── Field ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbField {
    pub name: String,
    pub type_index: TypeIndex,
    pub offset: Option<u32>,
    pub is_static: bool,
    pub is_bitfield: bool,
    pub bit_offset: u8,
    pub bit_size: u8,
}

// ── Enumerator ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enumerator {
    pub name: String,
    pub value: i64,
}

// ── Method entry ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodEntry {
    pub name: String,
    pub type_index: TypeIndex,
    pub vtable_offset: Option<u32>,
    pub is_virtual: bool,
    pub is_static: bool,
    pub is_intro: bool,
    pub is_pure: bool,
}

// ── PdbType ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdbType {
    Primitive(PrimitiveKind),
    Pointer {
        pointee: TypeIndex,
        size: u8,
        is_lvalue_ref: bool,
        is_rvalue_ref: bool,
        is_const: bool,
        is_volatile: bool,
    },
    Array {
        element_type: TypeIndex,
        index_type: TypeIndex,
        byte_size: u64,
        dimensions: Vec<u64>,
    },
    Class {
        name: String,
        unique_name: Option<String>,
        size: u64,
        fields: Vec<PdbField>,
        methods: Vec<MethodEntry>,
        base_classes: Vec<TypeIndex>,
        is_struct: bool,
        is_forward_ref: bool,
    },
    Union {
        name: String,
        unique_name: Option<String>,
        size: u64,
        fields: Vec<PdbField>,
        is_forward_ref: bool,
    },
    Enum {
        name: String,
        unique_name: Option<String>,
        underlying_type: TypeIndex,
        enumerators: Vec<Enumerator>,
        is_forward_ref: bool,
    },
    Function {
        return_type: TypeIndex,
        calling_conv: CallingConv,
        param_count: u16,
        param_types: Vec<TypeIndex>,
        is_variadic: bool,
    },
    MemberFunction {
        return_type: TypeIndex,
        class_type: TypeIndex,
        this_type: TypeIndex,
        calling_conv: CallingConv,
        param_count: u16,
        param_types: Vec<TypeIndex>,
        this_adjustment: i32,
    },
    Typedef {
        name: String,
        underlying_type: TypeIndex,
    },
    Modifier {
        modified_type: TypeIndex,
        is_const: bool,
        is_volatile: bool,
        is_unaligned: bool,
    },
    VTableShape {
        vfptr_count: u16,
    },
    BitField {
        underlying_type: TypeIndex,
        length: u8,
        position: u8,
    },
    Unknown {
        leaf_kind: u16,
        raw: Vec<u8>,
    },
}

impl PdbType {
    #[must_use] 
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Primitive(_) => "Primitive",
            Self::Pointer { .. } => "Pointer",
            Self::Array { .. } => "Array",
            Self::Class { is_struct: false, .. } => "Class",
            Self::Class { is_struct: true, .. } => "Struct",
            Self::Union { .. } => "Union",
            Self::Enum { .. } => "Enum",
            Self::Function { .. } => "Function",
            Self::MemberFunction { .. } => "MemberFunction",
            Self::Typedef { .. } => "Typedef",
            Self::Modifier { .. } => "Modifier",
            Self::VTableShape { .. } => "VTableShape",
            Self::BitField { .. } => "BitField",
            Self::Unknown { .. } => "Unknown",
        }
    }

    #[must_use] 
    pub fn byte_size(&self) -> Option<u64> {
        match self {
            Self::Class { size, .. } | Self::Union { size, .. } => Some(*size),
            Self::Array { byte_size, .. } => Some(*byte_size),
            Self::Primitive(p) => p.byte_size().map(|s| s as u64),
            Self::Pointer { size, .. } => Some(u64::from(*size)),
            _ => None,
        }
    }
}

impl fmt::Display for PdbType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Primitive(p) => write!(f, "{p:?}"),
            Self::Pointer { pointee, is_const, .. } => {
                if *is_const { write!(f, "const {pointee} *") }
                else { write!(f, "{pointee} *") }
            }
            Self::Class { name, is_struct, .. } => {
                write!(f, "{} {}", if *is_struct { "struct" } else { "class" }, name)
            }
            Self::Union { name, .. } => write!(f, "union {name}"),
            Self::Enum { name, .. } => write!(f, "enum {name}"),
            Self::Typedef { name, .. } => write!(f, "typedef {name}"),
            Self::Array { element_type, byte_size, .. } =>
                write!(f, "{element_type}[{byte_size} bytes]"),
            Self::Function { return_type, calling_conv, param_count, .. } =>
                write!(f, "{} {} ({}...)", return_type, calling_conv.name(), param_count),
            _ => write!(f, "{}", self.type_name()),
        }
    }
}

// ── Leaf kind constants (CodeView) ───────────────────────────────────────────

const LF_POINTER:         u16 = 0x1002;
const LF_ARRAY:           u16 = 0x1503;
const LF_CLASS:           u16 = 0x1504;
const LF_STRUCTURE:       u16 = 0x1505;
const LF_UNION:           u16 = 0x1506;
const LF_ENUM:            u16 = 0x1507;
const LF_PROCEDURE:       u16 = 0x1008;
const LF_MFUNCTION:       u16 = 0x1009;
const LF_VTSHAPE:         u16 = 0x000A;
const LF_MODIFIER:        u16 = 0x1001;
const LF_BITFIELD:        u16 = 0x1205;
const LF_FIELDLIST:       u16 = 0x1203;
const LF_ARGLIST:         u16 = 0x1201;
const LF_MEMBER:          u16 = 0x150D;
const LF_STMEMBER:        u16 = 0x150E;
const LF_METHOD:          u16 = 0x150F;
const LF_ONEMETHOD:       u16 = 0x1511;
const LF_ENUMERATE:       u16 = 0x1502;
const LF_NESTTYPE:        u16 = 0x1510;
const LF_BCLASS:          u16 = 0x1400;
const LF_VBCLASS:         u16 = 0x1401;
const LF_CLASS2:          u16 = 0x1608;
const LF_STRUCTURE2:      u16 = 0x1609;
const LF_UNION2:          u16 = 0x160A;
const LF_ENUM2:           u16 = 0x160B;

// Numeric leaves
const LF_CHAR_LEAF:       u16 = 0x8000;
const LF_SHORT:           u16 = 0x8001;
const LF_USHORT:          u16 = 0x8002;
const LF_LONG:            u16 = 0x8003;
const LF_ULONG:           u16 = 0x8004;
const LF_QUADWORD:        u16 = 0x8009;
const LF_UQUADWORD:       u16 = 0x800A;
const LF_REAL32:          u16 = 0x8005;
const LF_REAL64:          u16 = 0x8006;

// ── Numeric value reader ─────────────────────────────────────────────────────

/// Read a `CodeView` numeric leaf value at `pos`. Returns (`value_as_i64`, `bytes_consumed`).
fn read_numeric(data: &[u8], pos: usize) -> Result<(i64, usize), PdbTypeError> {
    ensure_len(data, pos, 2)?;
    let leaf = u16::from_le_bytes([data[pos], data[pos + 1]]);
    if leaf < 0x8000 {
        // Value is the leaf itself (< 0x8000 means direct unsigned value)
        return Ok((i64::from(leaf), 2));
    }
    match leaf {
        LF_CHAR_LEAF => {
            ensure_len(data, pos + 2, 1)?;
            Ok((i64::from(data[pos + 2] as i8), 3))
        }
        LF_SHORT => {
            ensure_len(data, pos + 2, 2)?;
            Ok((i64::from(i16::from_le_bytes([data[pos+2], data[pos+3]])), 4))
        }
        LF_USHORT => {
            ensure_len(data, pos + 2, 2)?;
            Ok((i64::from(u16::from_le_bytes([data[pos+2], data[pos+3]])), 4))
        }
        LF_LONG => {
            ensure_len(data, pos + 2, 4)?;
            Ok((i64::from(i32::from_le_bytes([data[pos+2], data[pos+3], data[pos+4], data[pos+5]])), 6))
        }
        LF_ULONG => {
            ensure_len(data, pos + 2, 4)?;
            Ok((i64::from(u32::from_le_bytes([data[pos+2], data[pos+3], data[pos+4], data[pos+5]])), 6))
        }
        LF_QUADWORD => {
            ensure_len(data, pos + 2, 8)?;
            let v = i64::from_le_bytes(data[pos+2..pos+10].try_into().unwrap());
            Ok((v, 10))
        }
        LF_UQUADWORD => {
            ensure_len(data, pos + 2, 8)?;
            let v = u64::from_le_bytes(data[pos+2..pos+10].try_into().unwrap()) as i64;
            Ok((v, 10))
        }
        LF_REAL32 => {
            ensure_len(data, pos + 2, 4)?;
            let v = f32::from_le_bytes(data[pos+2..pos+6].try_into().unwrap());
            Ok((v as i64, 6))
        }
        LF_REAL64 => {
            ensure_len(data, pos + 2, 8)?;
            let v = f64::from_le_bytes(data[pos+2..pos+10].try_into().unwrap());
            Ok((v as i64, 10))
        }
        _ => Err(PdbTypeError::UnknownLeafKind(leaf)),
    }
}

const fn ensure_len(data: &[u8], offset: usize, needed: usize) -> Result<(), PdbTypeError> {
    // saturating_add: offset + needed must not wrap around on adversarial input
    if data.len() < offset.saturating_add(needed) {
        Err(PdbTypeError::TruncatedData { offset, needed, have: data.len().saturating_sub(offset) })
    } else {
        Ok(())
    }
}

fn rd16(data: &[u8], pos: usize) -> Result<u16, PdbTypeError> {
    ensure_len(data, pos, 2)?;
    Ok(u16::from_le_bytes([data[pos], data[pos+1]]))
}

fn rd32(data: &[u8], pos: usize) -> Result<u32, PdbTypeError> {
    ensure_len(data, pos, 4)?;
    Ok(u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]))
}

fn rd32i(data: &[u8], pos: usize) -> Result<i32, PdbTypeError> {
    ensure_len(data, pos, 4)?;
    Ok(i32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]))
}

/// Read a null-terminated UTF-8 string; returns (string, `bytes_consumed_including_null`).
fn read_cstr(data: &[u8], pos: usize) -> Result<(String, usize), PdbTypeError> {
    let start = pos;
    let mut p = pos;
    while p < data.len() && data[p] != 0 {
        p += 1;
    }
    if p >= data.len() {
        return Err(PdbTypeError::NullTerminatorMissing);
    }
    let s = std::str::from_utf8(&data[start..p])
        .map_err(|_| PdbTypeError::InvalidUtf8 { offset: start })?;
    Ok((s.to_string(), p - start + 1))
}

// ── Field list parser ─────────────────────────────────────────────────────────

fn parse_field_list(data: &[u8]) -> Result<(Vec<PdbField>, Vec<MethodEntry>, Vec<Enumerator>, Vec<TypeIndex>), PdbTypeError> {
    let mut fields = Vec::new();
    let mut methods = Vec::new();
    let mut enumerators = Vec::new();
    let mut base_classes = Vec::new();
    let mut pos = 0usize;

    while pos + 2 <= data.len() {
        // align to 4 bytes (pad bytes are 0xF1..0xF4)
        while pos < data.len() && matches!(data[pos], 0xF1..=0xF4) { pos += 1; }
        if pos + 2 > data.len() { break; }

        let leaf = rd16(data, pos)?;
        match leaf {
            LF_MEMBER => {
                // attributes (2), type (4), offset_numeric, name
                ensure_len(data, pos + 2, 6)?;
                let attr = rd16(data, pos + 2)?;
                let type_idx = TypeIndex(rd32(data, pos + 4)?);
                let (offset_val, off_sz) = read_numeric(data, pos + 8)?;
                let name_pos = pos + 8 + off_sz;
                let (name, name_sz) = read_cstr(data, name_pos)?;
                let is_static = (attr & 0x18) == 0x08;
                fields.push(PdbField {
                    name,
                    type_index: type_idx,
                    offset: if is_static { None } else { Some(offset_val as u32) },
                    is_static,
                    is_bitfield: false,
                    bit_offset: 0,
                    bit_size: 0,
                });
                pos = name_pos + name_sz;
            }
            LF_STMEMBER => {
                ensure_len(data, pos + 2, 6)?;
                let type_idx = TypeIndex(rd32(data, pos + 4)?);
                let (name, name_sz) = read_cstr(data, pos + 8)?;
                fields.push(PdbField {
                    name,
                    type_index: type_idx,
                    offset: None,
                    is_static: true,
                    is_bitfield: false,
                    bit_offset: 0,
                    bit_size: 0,
                });
                pos = pos + 8 + name_sz;
            }
            LF_ENUMERATE => {
                ensure_len(data, pos + 2, 4)?;
                let (val, val_sz) = read_numeric(data, pos + 4)?;
                let (name, name_sz) = read_cstr(data, pos + 4 + val_sz)?;
                enumerators.push(Enumerator { name, value: val });
                pos = pos + 4 + val_sz + name_sz;
            }
            LF_ONEMETHOD => {
                ensure_len(data, pos + 2, 6)?;
                let attr = rd16(data, pos + 2)?;
                let type_idx = TypeIndex(rd32(data, pos + 4)?);
                let mut name_pos = pos + 8;
                let mut vtable_offset = None;
                // mprop: bits 2..4 of attr
                let mprop = (attr >> 2) & 0x7;
                if mprop == 4 || mprop == 6 {
                    // has vtable offset
                    ensure_len(data, name_pos, 4)?;
                    vtable_offset = Some(rd32(data, name_pos)?);
                    name_pos += 4;
                }
                let (name, name_sz) = read_cstr(data, name_pos)?;
                let is_virtual = mprop >= 4;
                let is_pure = mprop == 5 || mprop == 7;
                let is_intro = mprop == 4 || mprop == 6;
                methods.push(MethodEntry {
                    name,
                    type_index: type_idx,
                    vtable_offset,
                    is_virtual,
                    is_static: mprop == 2,
                    is_intro,
                    is_pure,
                });
                pos = name_pos + name_sz;
            }
            LF_BCLASS | LF_VBCLASS => {
                ensure_len(data, pos + 2, 6)?;
                let base_idx = TypeIndex(rd32(data, pos + 4)?);
                base_classes.push(base_idx);
                let (_, off_sz) = read_numeric(data, pos + 8)?;
                pos = pos + 8 + off_sz;
                if leaf == LF_VBCLASS {
                    let (_, vb_sz) = read_numeric(data, pos)?;
                    pos += vb_sz;
                }
            }
            LF_NESTTYPE => {
                ensure_len(data, pos + 2, 6)?;
                let (name, name_sz) = read_cstr(data, pos + 8)?;
                pos = pos + 8 + name_sz;
                let _ = name;
            }
            LF_METHOD => {
                // LF_METHOD: overloaded method group. Layout:
                //   u16 leaf, u16 count, u32 mList (LF_METHODLIST index), cstr name.
                // We record a single placeholder MethodEntry for the group so
                // the overload set is visible to consumers; per-overload
                // details live in the referenced LF_METHODLIST.
                ensure_len(data, pos + 2, 6)?;
                let count = rd16(data, pos + 2)?;
                let mlist_idx = TypeIndex(rd32(data, pos + 4)?);
                let (name, name_sz) = read_cstr(data, pos + 8)?;
                for _ in 0..count.max(1) {
                    methods.push(MethodEntry {
                        name: name.clone(),
                        type_index: mlist_idx,
                        vtable_offset: None,
                        is_virtual: false,
                        is_static: false,
                        is_intro: false,
                        is_pure: false,
                    });
                }
                pos = pos + 8 + name_sz;
            }
            _ => { break; }
        }
        // 4-byte alignment
        pos = (pos + 3) & !3;
    }

    Ok((fields, methods, enumerators, base_classes))
}

// ── Arg list parser ───────────────────────────────────────────────────────────

fn parse_arglist(data: &[u8]) -> Result<(Vec<TypeIndex>, bool), PdbTypeError> {
    ensure_len(data, 0, 4)?;
    let count = rd32(data, 0)? as usize;
    // Cap pre-allocation by remaining bytes: each arg index is 4 bytes.
    let mut args = Vec::with_capacity(count.min(data.len().saturating_sub(4) / 4));
    let mut is_variadic = false;
    for i in 0..count {
        let off = 4 + i * 4;
        ensure_len(data, off, 4)?;
        let idx = TypeIndex(rd32(data, off)?);
        if idx.0 == 0x0003 && i + 1 == count {
            // T_VOID as last arg is actually ellipsis in some PDB versions
        }
        if idx.0 == 0x0000 {
            is_variadic = true;
        } else {
            args.push(idx);
        }
    }
    Ok((args, is_variadic))
}

// ── TPI stream header ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TpiHeader {
    pub version: u32,
    pub header_size: u32,
    pub type_index_begin: u32,
    pub type_index_end: u32,
    pub type_record_bytes: u32,
    pub hash_stream_index: u16,
    pub hash_aux_stream_index: u16,
    pub hash_key_size: u32,
    pub num_hash_buckets: u32,
}

impl TpiHeader {
    const VERSION_V80: u32 = 20040203;

    pub fn parse(data: &[u8]) -> Result<Self, PdbTypeError> {
        ensure_len(data, 0, 56)?;
        let version = rd32(data, 0)?;
        // Accept known versions
        if version != Self::VERSION_V80 && version != 19990903 && version != 19991203 {
            // Accept anyway for robustness
        }
        Ok(Self {
            version,
            header_size: rd32(data, 4)?,
            type_index_begin: rd32(data, 8)?,
            type_index_end: rd32(data, 12)?,
            type_record_bytes: rd32(data, 16)?,
            hash_stream_index: rd16(data, 20)?,
            hash_aux_stream_index: rd16(data, 22)?,
            hash_key_size: rd32(data, 24)?,
            num_hash_buckets: rd32(data, 28)?,
        })
    }
}

// ── PDB type reader ──────────────────────────────────────────────────────────

pub struct PdbTypeReader {
    types: HashMap<TypeIndex, PdbType>,
    header: TpiHeader,
    // cache for field lists and arg lists
    field_lists: HashMap<TypeIndex, (Vec<PdbField>, Vec<MethodEntry>, Vec<Enumerator>, Vec<TypeIndex>)>,
    arg_lists: HashMap<TypeIndex, (Vec<TypeIndex>, bool)>,
}

impl PdbTypeReader {
    /// Parse a TPI stream (the raw bytes of stream 2 in a PDB MSF).
    pub fn parse_tpi_stream(stream_data: &[u8]) -> Result<Self, PdbTypeError> {
        let header = TpiHeader::parse(stream_data)?;
        let header_end = header.header_size as usize;
        ensure_len(stream_data, header_end, header.type_record_bytes as usize)?;
        let records = &stream_data[header_end..header_end + header.type_record_bytes as usize];

        let mut reader = Self {
            types: HashMap::new(),
            header: header.clone(),
            field_lists: HashMap::new(),
            arg_lists: HashMap::new(),
        };

        let mut pos = 0usize;
        let mut current_idx = header.type_index_begin;

        while pos + 4 <= records.len() {
            let record_len = rd16(records, pos)? as usize;
            if record_len < 2 { break; }
            let leaf_kind = rd16(records, pos + 2)?;
            let body = &records[pos + 4..pos + 2 + record_len];

            let tidx = TypeIndex(current_idx);

            match leaf_kind {
                LF_FIELDLIST => {
                    let (fields, methods, enums, bases) = parse_field_list(body)?;
                    reader.field_lists.insert(tidx, (fields, methods, enums, bases));
                    reader.types.insert(tidx, PdbType::Unknown { leaf_kind, raw: body.to_vec() });
                }
                LF_ARGLIST => {
                    let (args, variadic) = parse_arglist(body)?;
                    reader.arg_lists.insert(tidx, (args, variadic));
                    reader.types.insert(tidx, PdbType::Unknown { leaf_kind, raw: body.to_vec() });
                }
                LF_MODIFIER => {
                    if body.len() >= 6 {
                        let modified = TypeIndex(rd32(body, 0)?);
                        let attr = rd16(body, 4)?;
                        reader.types.insert(tidx, PdbType::Modifier {
                            modified_type: modified,
                            is_const: (attr & 1) != 0,
                            is_volatile: (attr & 2) != 0,
                            is_unaligned: (attr & 4) != 0,
                        });
                    }
                }
                LF_POINTER => {
                    if body.len() >= 8 {
                        let pointee = TypeIndex(rd32(body, 0)?);
                        let attr = rd32(body, 4)?;
                        let ptrsize_attr = (attr >> 13) & 0x1F;
                        let sz: u8 = if ptrsize_attr == 10 { 8 } else { 4 };
                        let is_lvalue = (attr & (1 << 20)) != 0;
                        let is_rvalue = (attr & (1 << 21)) != 0;
                        reader.types.insert(tidx, PdbType::Pointer {
                            pointee,
                            size: sz,
                            is_lvalue_ref: is_lvalue,
                            is_rvalue_ref: is_rvalue,
                            is_const: false,
                            is_volatile: false,
                        });
                    }
                }
                LF_ARRAY => {
                    if body.len() >= 8 {
                        let elem = TypeIndex(rd32(body, 0)?);
                        let idx_type = TypeIndex(rd32(body, 4)?);
                        let (sz, _) = read_numeric(body, 8)?;
                        reader.types.insert(tidx, PdbType::Array {
                            element_type: elem,
                            index_type: idx_type,
                            byte_size: sz as u64,
                            dimensions: vec![sz as u64],
                        });
                    }
                }
                LF_CLASS | LF_STRUCTURE | LF_CLASS2 | LF_STRUCTURE2 => {
                    let is_struct = leaf_kind == LF_STRUCTURE || leaf_kind == LF_STRUCTURE2;
                    if body.len() >= 20 {
                        let _count = rd16(body, 0)?;
                        let prop = rd16(body, 2)?;
                        let field_list_idx = TypeIndex(rd32(body, 4)?);
                        let _derived = rd32(body, 8)?;
                        let _vshape = rd32(body, 12)?;
                        let (size_val, sz_bytes) = read_numeric(body, 16)?;
                        let name_pos = 16 + sz_bytes;
                        let (name, name_sz) = read_cstr(body, name_pos)?;
                        let unique_name = if (prop & 0x200) != 0 {
                            let (un, _) = read_cstr(body, name_pos + name_sz).unwrap_or_default();
                            Some(un)
                        } else { None };
                        let is_forward_ref = (prop & 0x80) != 0;
                        let (fields, methods, _, bases) = reader.field_lists
                            .get(&field_list_idx)
                            .cloned()
                            .unwrap_or_default();
                        reader.types.insert(tidx, PdbType::Class {
                            name,
                            unique_name,
                            size: size_val as u64,
                            fields,
                            methods,
                            base_classes: bases,
                            is_struct,
                            is_forward_ref,
                        });
                    }
                }
                LF_UNION | LF_UNION2 => {
                    if body.len() >= 12 {
                        let _count = rd16(body, 0)?;
                        let prop = rd16(body, 2)?;
                        let field_list_idx = TypeIndex(rd32(body, 4)?);
                        let (size_val, sz_bytes) = read_numeric(body, 8)?;
                        let name_pos = 8 + sz_bytes;
                        let (name, name_sz) = read_cstr(body, name_pos)?;
                        let unique_name = if (prop & 0x200) != 0 {
                            let (un, _) = read_cstr(body, name_pos + name_sz).unwrap_or_default();
                            Some(un)
                        } else { None };
                        let is_forward_ref = (prop & 0x80) != 0;
                        let (fields, _, _, _) = reader.field_lists
                            .get(&field_list_idx)
                            .cloned()
                            .unwrap_or_default();
                        reader.types.insert(tidx, PdbType::Union {
                            name, unique_name, size: size_val as u64,
                            fields, is_forward_ref,
                        });
                    }
                }
                LF_ENUM | LF_ENUM2 => {
                    if body.len() >= 12 {
                        let _count = rd16(body, 0)?;
                        let prop = rd16(body, 2)?;
                        let underlying = TypeIndex(rd32(body, 4)?);
                        let field_list_idx = TypeIndex(rd32(body, 8)?);
                        let (name, name_sz) = read_cstr(body, 12)?;
                        let unique_name = if (prop & 0x200) != 0 {
                            let (un, _) = read_cstr(body, 12 + name_sz).unwrap_or_default();
                            Some(un)
                        } else { None };
                        let is_forward_ref = (prop & 0x80) != 0;
                        let (_, _, enums, _) = reader.field_lists
                            .get(&field_list_idx)
                            .cloned()
                            .unwrap_or_default();
                        reader.types.insert(tidx, PdbType::Enum {
                            name, unique_name, underlying_type: underlying,
                            enumerators: enums, is_forward_ref,
                        });
                    }
                }
                LF_PROCEDURE => {
                    if body.len() >= 12 {
                        let ret = TypeIndex(rd32(body, 0)?);
                        let cc = CallingConv::from_u8(body[4]);
                        let param_count = rd16(body, 6)?;
                        let arglist_idx = TypeIndex(rd32(body, 8)?);
                        let (params, variadic) = reader.arg_lists
                            .get(&arglist_idx)
                            .cloned()
                            .unwrap_or_default();
                        reader.types.insert(tidx, PdbType::Function {
                            return_type: ret,
                            calling_conv: cc,
                            param_count,
                            param_types: params,
                            is_variadic: variadic,
                        });
                    }
                }
                LF_MFUNCTION => {
                    if body.len() >= 28 {
                        let ret = TypeIndex(rd32(body, 0)?);
                        let class_type = TypeIndex(rd32(body, 4)?);
                        let this_type = TypeIndex(rd32(body, 8)?);
                        let cc = CallingConv::from_u8(body[12]);
                        let param_count = rd16(body, 14)?;
                        let arglist_idx = TypeIndex(rd32(body, 16)?);
                        let this_adj = rd32i(body, 24)?;
                        let (params, _variadic) = reader.arg_lists
                            .get(&arglist_idx)
                            .cloned()
                            .unwrap_or_default();
                        reader.types.insert(tidx, PdbType::MemberFunction {
                            return_type: ret,
                            class_type,
                            this_type,
                            calling_conv: cc,
                            param_count,
                            param_types: params,
                            this_adjustment: this_adj,
                        });
                    }
                }
                LF_VTSHAPE => {
                    if body.len() >= 2 {
                        let count = rd16(body, 0)?;
                        reader.types.insert(tidx, PdbType::VTableShape { vfptr_count: count });
                    }
                }
                LF_BITFIELD => {
                    if body.len() >= 6 {
                        let under = TypeIndex(rd32(body, 0)?);
                        let length = body[4];
                        let position = body[5];
                        reader.types.insert(tidx, PdbType::BitField {
                            underlying_type: under,
                            length,
                            position,
                        });
                    }
                }
                _ => {
                    reader.types.insert(tidx, PdbType::Unknown { leaf_kind, raw: body.to_vec() });
                }
            }

            pos += 2 + record_len;
            current_idx += 1;
        }

        Ok(reader)
    }

    #[must_use] 
    pub fn resolve_type(&self, idx: TypeIndex) -> Option<&PdbType> {
        if idx.is_builtin() {
            return None; // caller should use TypeIndex::builtin_name
        }
        self.types.get(&idx)
    }

    #[must_use] 
    pub fn type_count(&self) -> usize { self.types.len() }

    #[must_use] 
    pub const fn header(&self) -> &TpiHeader { &self.header }

    pub fn iter_types(&self) -> impl Iterator<Item = (TypeIndex, &PdbType)> {
        self.types.iter().map(|(k, v)| (*k, v))
    }

    #[must_use] 
    pub fn find_by_name(&self, name: &str) -> Vec<(TypeIndex, &PdbType)> {
        self.types.iter().filter(|(_, t)| match t {
            PdbType::Class { name: n, .. } |
            PdbType::Union { name: n, .. } |
            PdbType::Enum { name: n, .. } |
            PdbType::Typedef { name: n, .. } => n == name,
            _ => false,
        }).map(|(k, v)| (*k, v)).collect()
    }

    #[must_use] 
    pub fn all_classes(&self) -> Vec<(TypeIndex, &PdbType)> {
        self.types.iter().filter(|(_, t)| matches!(t, PdbType::Class { .. }))
            .map(|(k, v)| (*k, v)).collect()
    }

    #[must_use] 
    pub fn all_enums(&self) -> Vec<(TypeIndex, &PdbType)> {
        self.types.iter().filter(|(_, t)| matches!(t, PdbType::Enum { .. }))
            .map(|(k, v)| (*k, v)).collect()
    }

    /// Walk pointer/modifier chain to the underlying concrete type.
    #[must_use] 
    pub fn strip_modifiers(&self, mut idx: TypeIndex) -> TypeIndex {
        for _ in 0..32 {
            match self.types.get(&idx) {
                Some(PdbType::Modifier { modified_type, .. }) => { idx = *modified_type; }
                Some(PdbType::Pointer { pointee, .. }) => { idx = *pointee; }
                _ => break,
            }
        }
        idx
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tpi_header(type_index_begin: u32, type_record_bytes: u32) -> Vec<u8> {
        let mut h = vec![0u8; 56];
        // version = V80
        h[0..4].copy_from_slice(&20040203u32.to_le_bytes());
        h[4..8].copy_from_slice(&56u32.to_le_bytes());   // header_size
        h[8..12].copy_from_slice(&type_index_begin.to_le_bytes());
        h[12..16].copy_from_slice(&(type_index_begin).to_le_bytes()); // end (0 records)
        h[16..20].copy_from_slice(&type_record_bytes.to_le_bytes());
        h[20..22].copy_from_slice(&0xFFFFu16.to_le_bytes()); // no hash stream
        h[22..24].copy_from_slice(&0xFFFFu16.to_le_bytes());
        h[24..28].copy_from_slice(&4u32.to_le_bytes());   // hash key size
        h[28..32].copy_from_slice(&4096u32.to_le_bytes()); // num_hash_buckets
        h
    }

    #[test]
    fn test_tpi_header_parse() {
        let data = make_tpi_header(0x1000, 0);
        let h = TpiHeader::parse(&data).unwrap();
        assert_eq!(h.version, 20040203);
        assert_eq!(h.type_index_begin, 0x1000);
        assert_eq!(h.header_size, 56);
    }

    #[test]
    fn test_empty_tpi_stream() {
        let data = make_tpi_header(0x1000, 0);
        let reader = PdbTypeReader::parse_tpi_stream(&data).unwrap();
        assert_eq!(reader.type_count(), 0);
    }

    #[test]
    fn test_read_numeric_small() {
        let data = [0x2A, 0x00];
        let (v, sz) = read_numeric(&data, 0).unwrap();
        assert_eq!(v, 0x2A);
        assert_eq!(sz, 2);
    }

    #[test]
    fn test_read_numeric_ulong() {
        let mut data = vec![0x04u8, 0x80]; // LF_ULONG
        data.extend_from_slice(&42u32.to_le_bytes());
        let (v, sz) = read_numeric(&data, 0).unwrap();
        assert_eq!(v, 42);
        assert_eq!(sz, 6);
    }

    #[test]
    fn test_read_cstr() {
        let data = b"hello\x00world";
        let (s, sz) = read_cstr(data, 0).unwrap();
        assert_eq!(s, "hello");
        assert_eq!(sz, 6);
    }

    #[test]
    fn test_type_index_builtin() {
        assert!(TypeIndex::VOID.is_builtin());
        assert!(TypeIndex::FLOAT32.is_builtin());
        assert!(!TypeIndex(0x1000).is_builtin());
    }

    #[test]
    fn test_type_index_builtin_name() {
        assert_eq!(TypeIndex::VOID.builtin_name(), Some("void"));
        assert_eq!(TypeIndex::FLOAT32.builtin_name(), Some("float"));
        assert_eq!(TypeIndex::FLOAT64.builtin_name(), Some("double"));
        assert_eq!(TypeIndex(0x1234).builtin_name(), None);
    }

    #[test]
    fn test_primitive_kind_from_index() {
        assert_eq!(PrimitiveKind::from_index(0x0074), PrimitiveKind::I32);
        assert_eq!(PrimitiveKind::from_index(0x0041), PrimitiveKind::Float64);
        assert_eq!(PrimitiveKind::from_index(0x0003), PrimitiveKind::Void);
    }

    #[test]
    fn test_calling_conv() {
        assert_eq!(CallingConv::from_u8(0x07).name(), "__stdcall");
        assert_eq!(CallingConv::from_u8(0x0B).name(), "__thiscall");
        assert_eq!(CallingConv::from_u8(0x16).name(), "__clrcall");
    }

    #[test]
    fn test_primitive_size() {
        assert_eq!(PrimitiveKind::I32.byte_size(), Some(4));
        assert_eq!(PrimitiveKind::Float64.byte_size(), Some(8));
        assert_eq!(PrimitiveKind::Void.byte_size(), Some(0));
    }

    #[test]
    fn test_pdb_type_display_pointer() {
        let t = PdbType::Pointer {
            pointee: TypeIndex(0x0074),
            size: 8,
            is_lvalue_ref: false,
            is_rvalue_ref: false,
            is_const: false,
            is_volatile: false,
        };
        let s = format!("{t}");
        assert!(s.contains('*'));
    }

    #[test]
    fn test_pdb_type_display_class() {
        let t = PdbType::Class {
            name: "MyClass".to_string(),
            unique_name: None,
            size: 16,
            fields: vec![],
            methods: vec![],
            base_classes: vec![],
            is_struct: false,
            is_forward_ref: false,
        };
        assert_eq!(format!("{t}"), "class MyClass");
        assert_eq!(t.byte_size(), Some(16));
    }

    #[test]
    fn test_find_by_name_empty() {
        let data = make_tpi_header(0x1000, 0);
        let reader = PdbTypeReader::parse_tpi_stream(&data).unwrap();
        assert!(reader.find_by_name("Foo").is_empty());
    }

    #[test]
    fn test_arglist_parse() {
        let mut data = vec![];
        data.extend_from_slice(&2u32.to_le_bytes()); // count
        data.extend_from_slice(&0x0074u32.to_le_bytes()); // int
        data.extend_from_slice(&0x0041u32.to_le_bytes()); // double
        let (args, variadic) = parse_arglist(&data).unwrap();
        assert_eq!(args.len(), 2);
        assert!(!variadic);
        assert_eq!(args[0], TypeIndex(0x0074));
    }

    #[test]
    fn test_strip_modifiers_builtin() {
        let data = make_tpi_header(0x1000, 0);
        let reader = PdbTypeReader::parse_tpi_stream(&data).unwrap();
        let stripped = reader.strip_modifiers(TypeIndex::INT4);
        assert_eq!(stripped, TypeIndex::INT4);
    }

    #[test]
    fn test_ensure_len_ok() {
        let data = [1u8; 8];
        assert!(ensure_len(&data, 0, 8).is_ok());
        assert!(ensure_len(&data, 4, 4).is_ok());
    }

    #[test]
    fn test_ensure_len_err() {
        let data = [1u8; 4];
        let e = ensure_len(&data, 2, 4);
        assert!(e.is_err());
    }

    #[test]
    fn test_type_name_variants() {
        let t = PdbType::VTableShape { vfptr_count: 3 };
        assert_eq!(t.type_name(), "VTableShape");
        let t2 = PdbType::BitField { underlying_type: TypeIndex(0x74), length: 3, position: 0 };
        assert_eq!(t2.type_name(), "BitField");
    }
}
