//! `cv_type_records` — `CodeView` type record decoder.
//!
//! Decodes `LF_POINTER`, `LF_ARRAY`, `LF_STRUCTURE`, `LF_CLASS`, `LF_UNION`, `LF_ENUM`,
//! `LF_PROCEDURE`, `LF_MFUNCTION`, `LF_ARGLIST`, `LF_FIELDLIST`, `LF_MEMBER`,
//! `LF_STMEMBER`, `LF_ENUMERATE`, `LF_NESTTYPE`, `LF_ONEMETHOD`, `LF_METHOD`,
//! `LF_BCLASS`, `LF_VBCLASS`, `LF_MODIFIER`, `LF_BITFIELD`, `LF_VTSHAPE`,
//! `LF_LABEL`, `LF_DIMARRAY`, and primitive type indices.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::CodeViewError;

// ---------------------------------------------------------------------------
// Leaf kind constants (LF_*)
// ---------------------------------------------------------------------------

pub mod lf {
    pub const MODIFIER_16T: u16 = 0x0001;
    pub const POINTER_16T: u16 = 0x0002;
    pub const ARRAY_16T: u16 = 0x0003;
    pub const CLASS_16T: u16 = 0x0004;
    pub const STRUCTURE_16T: u16 = 0x0005;
    pub const UNION_16T: u16 = 0x0006;
    pub const ENUM_16T: u16 = 0x0007;
    pub const PROCEDURE_16T: u16 = 0x0008;
    pub const MFUNCTION_16T: u16 = 0x0009;
    pub const VTSHAPE: u16 = 0x000A;
    pub const COBOL0_16T: u16 = 0x000B;
    pub const LABEL: u16 = 0x000E;
    pub const NULL: u16 = 0x000F;

    pub const MODIFIER: u16 = 0x1001;
    pub const POINTER: u16 = 0x1002;
    pub const ARRAY: u16 = 0x1003;
    pub const CLASS: u16 = 0x1004;
    pub const STRUCTURE: u16 = 0x1005;
    pub const UNION: u16 = 0x1006;
    pub const ENUM: u16 = 0x1007;
    pub const PROCEDURE: u16 = 0x1008;
    pub const MFUNCTION: u16 = 0x1009;
    pub const COBOL0: u16 = 0x100A;
    pub const BARRAY: u16 = 0x100B;
    pub const DIMARRAY: u16 = 0x100C;
    pub const VFTPATH: u16 = 0x100D;
    pub const PRECOMP: u16 = 0x100E;
    pub const ENDPRECOMP: u16 = 0x100F;
    pub const OEM: u16 = 0x1010;
    pub const TYPESERVER: u16 = 0x1012;
    pub const ENUMERATE: u16 = 0x1502;
    pub const ARRAY_ST: u16 = 0x1503;

    // Field list members
    pub const BCLASS: u16 = 0x1400;
    pub const VBCLASS: u16 = 0x1401;
    pub const IVBCLASS: u16 = 0x1402;
    pub const INDEX: u16 = 0x1404;
    pub const VFUNCTAB: u16 = 0x1409;
    // Modern (non-_ST) field-list leaves. The legacy 0x1405..0x140E block is
    // the *_ST (Pascal-string) form, which modern PDBs never emit; using those
    // codes here silently dropped every struct/class member.
    pub const FRIENDFCN: u16 = 0x150C;
    pub const MEMBER: u16 = 0x150D;
    pub const STMEMBER: u16 = 0x150E;
    pub const METHOD: u16 = 0x150F;
    pub const NESTTYPE: u16 = 0x1510;
    pub const ONEMETHOD: u16 = 0x1511;
    pub const NESTTYPEEX: u16 = 0x1512;
    pub const VFUNCOFF: u16 = 0x1513;
    pub const MEMBERMODIFY: u16 = 0x1514;
    pub const FRIENDCLS: u16 = 0x140A;

    // LF_FIELDLIST
    pub const FIELDLIST: u16 = 0x1203;

    pub const ARGLIST: u16 = 0x1201;
    pub const BITFIELD: u16 = 0x1205;

    // TI_VOID and primitives are below 0x1000
    pub const SIMPLE_TYPES_MAX: u32 = 0x1000;
}

// ---------------------------------------------------------------------------
// Primitive type decoder
// ---------------------------------------------------------------------------

/// Simple type (type index < 0x1000) mode bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrimitiveMode {
    Direct = 0,
    Near16Ptr = 1,
    Far16Ptr = 2,
    Huge16Ptr = 3,
    Near32Ptr = 4,
    Far32Ptr = 5,
    Near64Ptr = 6,
    Near128Ptr = 7,
}

impl PrimitiveMode {
    #[must_use] 
    pub const fn from_u32(v: u32) -> Self {
        match (v >> 8) & 0xF {
            1 => Self::Near16Ptr, 2 => Self::Far16Ptr,
            3 => Self::Huge16Ptr, 4 => Self::Near32Ptr, 5 => Self::Far32Ptr,
            6 => Self::Near64Ptr, 7 => Self::Near128Ptr,
            // 0 (Direct) plus anything outside 1..=7 maps to Direct.
            _ => Self::Direct,
        }
    }
    #[must_use] 
    pub const fn is_pointer(&self) -> bool { !matches!(self, Self::Direct) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrimitiveKind {
    NoType,
    Void,
    Bool8, Bool16, Bool32, Bool64,
    Int8, Int16, Int32, Int64, Int128,
    Uint8, Uint16, Uint32, Uint64, Uint128,
    Float32, Float64, Float80, Float128,
    Complex32, Complex64, Complex80, Complex128,
    Char8, Char16, Char32, WChar,
    Hresult,
    Unknown(u32),
}

impl PrimitiveKind {
    #[must_use] 
    pub const fn from_type_idx(ti: u32) -> Self {
        // Indices >= 0x1000 are LF_ records, not primitives; masking them into
        // this table would decode real type records as primitives.
        if ti >= lf::SIMPLE_TYPES_MAX { return Self::Unknown(ti); }
        let kind = ti & 0xFF;
        match kind {
            0x00 => Self::NoType,
            0x03 => Self::Void,
            0x30 => Self::Bool8,
            0x31 => Self::Bool16,
            0x32 => Self::Bool32,
            0x33 => Self::Bool64,
            // Per cvinfo.h. The legacy 0x1x/0x2x block is T_CHAR/T_SHORT/T_LONG/
            // T_QUAD and unsigned peers; the 0x6x-0x7x block is the explicitly
            // sized T_INT1..T_UINT16 family.
            0x10 | 0x68 => Self::Int8,
            0x11 | 0x72 => Self::Int16,
            0x12 | 0x74 => Self::Int32,
            0x13 | 0x6A | 0x76 => Self::Int64,
            0x14 | 0x78 => Self::Int128,
            0x20 | 0x69 => Self::Uint8,
            0x21 | 0x73 => Self::Uint16,
            0x22 | 0x75 => Self::Uint32,
            0x23 | 0x6B | 0x77 => Self::Uint64,
            0x24 | 0x79 => Self::Uint128,
            0x40 => Self::Float32,
            0x41 => Self::Float64,
            0x42 => Self::Float80,
            0x43 => Self::Float128,
            0x50 => Self::Complex32,
            0x51 => Self::Complex64,
            0x52 => Self::Complex80,
            0x53 => Self::Complex128,
            0x70 => Self::Char8,
            0x71 => Self::WChar,
            0x7A => Self::Char16,
            0x7B => Self::Char32,
            0x08 => Self::Hresult,
            _ => Self::Unknown(ti),
        }
    }
    #[must_use] 
    pub const fn byte_size(&self) -> Option<u32> {
        match self {
            Self::Bool8 | Self::Int8 | Self::Uint8 | Self::Char8 => Some(1),
            Self::Bool16 | Self::Int16 | Self::Uint16 | Self::Char16 | Self::WChar => Some(2),
            Self::Bool32 | Self::Int32 | Self::Uint32 | Self::Float32 | Self::Char32 | Self::Hresult => Some(4),
            Self::Bool64 | Self::Int64 | Self::Uint64 | Self::Float64 => Some(8),
            Self::Int128 | Self::Uint128 | Self::Float128 => Some(16),
            Self::Float80 => Some(10),
            Self::Void | Self::NoType => Some(0),
            _ => None,
        }
    }
}

impl fmt::Display for PrimitiveKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Void => "void", Self::Bool8 => "bool", Self::Int8 => "int8_t",
            Self::Int16 => "int16_t", Self::Int32 => "int32_t", Self::Int64 => "int64_t",
            Self::Uint8 => "uint8_t", Self::Uint16 => "uint16_t", Self::Uint32 => "uint32_t",
            Self::Uint64 => "uint64_t", Self::Float32 => "float", Self::Float64 => "double",
            Self::Char8 => "char", Self::WChar => "wchar_t", _ => "unknown",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// CV numeric leaf decoder
// ---------------------------------------------------------------------------

/// Read a `CodeView` "numeric leaf" (variable-length integer).
/// Returns (`value_as_i64`, `bytes_consumed`).
#[must_use] 
pub fn read_numeric_leaf(data: &[u8]) -> Option<(i64, usize)> {
    if data.is_empty() { return None; }
    let first = u16::from_le_bytes(data.get(0..2).map(|b| [b[0], b[1]])?);
    if first < 0x8000 {
        return Some((i64::from(first), 2));
    }
    match first {
        0x8000 => { // LF_CHAR
            Some((i64::from(crate::casts::u8_as_i8(*data.get(2)?)), 3))
        }
        0x8001 => { // LF_SHORT
            let v = i16::from_le_bytes(data.get(2..4)?.try_into().ok()?);
            Some((i64::from(v), 4))
        }
        0x8002 => { // LF_USHORT
            let v = u16::from_le_bytes(data.get(2..4)?.try_into().ok()?);
            Some((i64::from(v), 4))
        }
        0x8003 => { // LF_LONG
            let v = i32::from_le_bytes(data.get(2..6)?.try_into().ok()?);
            Some((i64::from(v), 6))
        }
        0x8004 => { // LF_ULONG
            let v = u32::from_le_bytes(data.get(2..6)?.try_into().ok()?);
            Some((i64::from(v), 6))
        }
        0x8009 => { // LF_QUADWORD
            let v = i64::from_le_bytes(data.get(2..10)?.try_into().ok()?);
            Some((v, 10))
        }
        0x800A => { // LF_UQUADWORD
            let v = crate::casts::u64_as_i64(u64::from_le_bytes(data.get(2..10)?.try_into().ok()?));
            Some((v, 10))
        }
        _ => Some((0, 2)),
    }
}

// ---------------------------------------------------------------------------
// Type record structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfModifier {
    pub modified_type: u32,
    pub is_const: bool,
    pub is_volatile: bool,
    pub is_unaligned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfPointer {
    pub referent_type: u32,
    pub attr: u32,
}

impl LfPointer {
    #[must_use] 
    pub const fn pointer_kind(&self) -> u8 { (self.attr & 0x1F) as u8 }
    #[must_use] 
    pub const fn pointer_mode(&self) -> u8 { ((self.attr >> 5) & 0x7) as u8 }
    #[must_use] 
    pub const fn is_const(&self) -> bool { (self.attr >> 10) & 1 != 0 }
    #[must_use] 
    pub const fn is_volatile(&self) -> bool { (self.attr >> 11) & 1 != 0 }
    #[must_use] 
    pub const fn is_unaligned(&self) -> bool { (self.attr >> 12) & 1 != 0 }
    #[must_use] 
    pub const fn is_restrict(&self) -> bool { (self.attr >> 13) & 1 != 0 }
    #[must_use] 
    pub const fn byte_size(&self) -> u8 {
        // CV_ptrtype: NEAR/FAR/HUGE 16-bit are 0..=3, NEAR32 = 10, FAR32 = 11
        // (16:32 seg:off), PTR_64 = 12, NEAR128 = 13.
        match self.pointer_kind() {
            0..=3 => 2,
            10 => 4,
            11 => 6,
            12 => 8,
            13 => 16,
            _ => 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfArray {
    pub element_type: u32,
    pub index_type: u32,
    pub byte_size: i64,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfStructure {
    pub num_members: u16,
    pub property: u16,
    pub field_type: u32,
    pub derived_type: u32,
    pub vshape_type: u32,
    pub byte_size: i64,
    pub name: String,
    pub unique_name: Option<String>,
}

pub type LfClass = LfStructure;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfUnion {
    pub num_members: u16,
    pub property: u16,
    pub field_type: u32,
    pub byte_size: i64,
    pub name: String,
    pub unique_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfEnum {
    pub num_elements: u16,
    pub property: u16,
    pub underlying_type: u32,
    pub field_type: u32,
    pub name: String,
    pub unique_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfProcedure {
    pub return_type: u32,
    pub calling_convention: u8,
    pub func_attrs: u8,
    pub num_params: u16,
    pub arg_list_type: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMFunction {
    pub return_type: u32,
    pub class_type: u32,
    pub this_type: u32,
    pub calling_convention: u8,
    pub func_attrs: u8,
    pub num_params: u16,
    pub arg_list_type: u32,
    pub this_adjustment: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfArgList {
    pub arg_types: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfBitfield {
    pub base_type: u32,
    pub length: u8,
    pub position: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMember {
    pub attrs: u16,
    pub field_type: u32,
    pub offset: i64,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfStMember {
    pub attrs: u16,
    pub field_type: u32,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfEnumerate {
    pub attrs: u16,
    pub value: i64,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfNestType {
    pub attrs: u16,
    pub nested_type: u32,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfOneMethod {
    pub attrs: u16,
    pub method_type: u32,
    pub vbase_off: Option<u32>,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodListEntry {
    pub attrs: u16,
    pub method_type: u32,
    pub vbase_off: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMethod {
    pub count: u16,
    pub method_list_type: u32,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfBClass {
    pub attrs: u16,
    pub base_class_type: u32,
    pub offset: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfVBClass {
    pub attrs: u16,
    pub direct_vb_type: u32,
    pub vb_ptr_type: u32,
    pub vb_ptr_off: i64,
    pub vb_index: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfVFuncTab {
    pub vptr_type: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfVtShape {
    pub count: u16,
    pub descriptors: Vec<u8>,
}

/// A field list entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldListEntry {
    Member(LfMember),
    StMember(LfStMember),
    Enumerate(LfEnumerate),
    NestType(LfNestType),
    OneMethod(LfOneMethod),
    Method(LfMethod),
    BClass(LfBClass),
    VBClass(LfVBClass),
    IVBClass(LfVBClass),
    VFuncTab(LfVFuncTab),
    Index { continued_type: u32 },
    Unknown { leaf: u16 },
}

/// A decoded `CodeView` type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeRecord {
    Modifier(LfModifier),
    Pointer(LfPointer),
    Array(LfArray),
    Structure(LfStructure),
    Class(LfClass),
    Union(LfUnion),
    Enum(LfEnum),
    Procedure(LfProcedure),
    MFunction(LfMFunction),
    ArgList(LfArgList),
    Bitfield(LfBitfield),
    FieldList(Vec<FieldListEntry>),
    VtShape(LfVtShape),
    Primitive { type_index: u32, kind: PrimitiveKind, mode: PrimitiveMode },
    Unknown { leaf: u16 },
}

impl TypeRecord {
    #[must_use] 
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Structure(s) | Self::Class(s) => Some(&s.name),
            Self::Union(u) => Some(&u.name),
            Self::Enum(e) => Some(&e.name),
            _ => None,
        }
    }

    #[must_use] 
    pub fn byte_size(&self) -> Option<u64> {
        match self {
            Self::Structure(s) | Self::Class(s) => Some(crate::casts::i64_as_u64(s.byte_size)),
            Self::Union(u) => Some(crate::casts::i64_as_u64(u.byte_size)),
            Self::Array(a) => Some(crate::casts::i64_as_u64(a.byte_size)),
            Self::Pointer(p) => Some(u64::from(p.byte_size())),
            Self::Primitive { kind, mode, .. } => {
                if mode.is_pointer() { Some(8) }
                else { kind.byte_size().map(u64::from) }
            }
            _ => None,
        }
    }

    #[must_use] 
    pub const fn is_aggregate(&self) -> bool {
        matches!(self, Self::Structure(_) | Self::Class(_) | Self::Union(_))
    }
}

// ---------------------------------------------------------------------------
// Read helpers
// ---------------------------------------------------------------------------

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_nul_str(data: &[u8], off: usize) -> (String, usize) {
    if off >= data.len() { return (String::new(), off); }
    let end = data[off..].iter().position(|&b| b == 0).unwrap_or(data.len() - off);
    let s = String::from_utf8_lossy(&data[off..off + end]).into_owned();
    (s, off + end + 1)
}

// ---------------------------------------------------------------------------
// Main type record decoder
// ---------------------------------------------------------------------------

/// Decode a single `CodeView` type record body given its `leaf` kind and raw `data`.
///
/// # Errors
/// Returns [`CodeViewError::TruncatedStream`] when `data` is shorter than the
/// leaf-specific minimum header.
pub fn decode_type_record(leaf: u16, data: &[u8]) -> Result<TypeRecord, CodeViewError> {
    match leaf {
        lf::MODIFIER => decode_modifier(data),
        lf::POINTER => decode_pointer(data),
        lf::ARRAY | lf::ARRAY_ST => decode_array(data),
        lf::STRUCTURE | lf::STRUCTURE_16T => decode_structure(data, false),
        lf::CLASS | lf::CLASS_16T => decode_structure(data, true),
        lf::UNION | lf::UNION_16T => decode_union(data),
        lf::ENUM | lf::ENUM_16T => decode_enum(data),
        lf::PROCEDURE | lf::PROCEDURE_16T => decode_procedure(data),
        lf::MFUNCTION | lf::MFUNCTION_16T => decode_mfunction(data),
        lf::ARGLIST => decode_arglist(data),
        lf::BITFIELD => decode_bitfield(data),
        lf::FIELDLIST => Ok(decode_fieldlist(data)),
        lf::VTSHAPE => decode_vtshape(data),
        _ => Ok(TypeRecord::Unknown { leaf }),
    }
}

fn decode_modifier(data: &[u8]) -> Result<TypeRecord, CodeViewError> {
    if data.len() < 6 { return Err(CodeViewError::TruncatedStream); }
    let modified_type = read_u32(data, 0).unwrap();
    let attrs = read_u16(data, 4).unwrap();
    Ok(TypeRecord::Modifier(LfModifier {
        modified_type,
        is_const: (attrs & 1) != 0,
        is_volatile: (attrs & 2) != 0,
        is_unaligned: (attrs & 4) != 0,
    }))
}

fn decode_pointer(data: &[u8]) -> Result<TypeRecord, CodeViewError> {
    if data.len() < 8 { return Err(CodeViewError::TruncatedStream); }
    let referent_type = read_u32(data, 0).unwrap();
    let attr = read_u32(data, 4).unwrap();
    Ok(TypeRecord::Pointer(LfPointer { referent_type, attr }))
}

fn decode_array(data: &[u8]) -> Result<TypeRecord, CodeViewError> {
    if data.len() < 8 { return Err(CodeViewError::TruncatedStream); }
    let element_type = read_u32(data, 0).unwrap();
    let index_type = read_u32(data, 4).unwrap();
    let (byte_size, consumed) = read_numeric_leaf(&data[8..]).ok_or(CodeViewError::InvalidRecord)?;
    let (name, _) = read_nul_str(data, 8 + consumed);
    Ok(TypeRecord::Array(LfArray { element_type, index_type, byte_size, name }))
}

fn decode_structure(data: &[u8], is_class: bool) -> Result<TypeRecord, CodeViewError> {
    if data.len() < 16 { return Err(CodeViewError::TruncatedStream); }
    let num_members = read_u16(data, 0).unwrap();
    let property = read_u16(data, 2).unwrap();
    let field_type = read_u32(data, 4).unwrap();
    let derived_type = read_u32(data, 8).unwrap();
    let vshape_type = read_u32(data, 12).unwrap();
    let (byte_size, consumed) = read_numeric_leaf(&data[16..]).ok_or(CodeViewError::InvalidRecord)?;
    let (name, mut pos) = read_nul_str(data, 16 + consumed);
    let unique_name = if (property & 0x200) != 0 {
        let (un, np) = read_nul_str(data, pos);
        pos = np;
        Some(un)
    } else { None };
    debug_assert!(pos <= data.len(), "structure decode consumed past end of buffer");
    let record = LfStructure { num_members, property, field_type, derived_type, vshape_type, byte_size, name, unique_name };
    if is_class { Ok(TypeRecord::Class(record)) } else { Ok(TypeRecord::Structure(record)) }
}

fn decode_union(data: &[u8]) -> Result<TypeRecord, CodeViewError> {
    if data.len() < 8 { return Err(CodeViewError::TruncatedStream); }
    let num_members = read_u16(data, 0).unwrap();
    let property = read_u16(data, 2).unwrap();
    let field_type = read_u32(data, 4).unwrap();
    let (byte_size, consumed) = read_numeric_leaf(&data[8..]).ok_or(CodeViewError::InvalidRecord)?;
    let (name, pos) = read_nul_str(data, 8 + consumed);
    let unique_name = if (property & 0x200) != 0 {
        let (un, end) = read_nul_str(data, pos);
        debug_assert!(end <= data.len(), "union decode consumed past end of buffer");
        Some(un)
    } else { None };
    let _ = pos;
    Ok(TypeRecord::Union(LfUnion { num_members, property, field_type, byte_size, name, unique_name }))
}

fn decode_enum(data: &[u8]) -> Result<TypeRecord, CodeViewError> {
    if data.len() < 12 { return Err(CodeViewError::TruncatedStream); }
    let num_elements = read_u16(data, 0).unwrap();
    let property = read_u16(data, 2).unwrap();
    let underlying_type = read_u32(data, 4).unwrap();
    let field_type = read_u32(data, 8).unwrap();
    let (name, pos) = read_nul_str(data, 12);
    let unique_name = if (property & 0x200) != 0 {
        let (un, end) = read_nul_str(data, pos);
        debug_assert!(end <= data.len(), "enum decode consumed past end of buffer");
        Some(un)
    } else { None };
    let _ = pos;
    Ok(TypeRecord::Enum(LfEnum { num_elements, property, underlying_type, field_type, name, unique_name }))
}

fn decode_procedure(data: &[u8]) -> Result<TypeRecord, CodeViewError> {
    if data.len() < 12 { return Err(CodeViewError::TruncatedStream); }
    Ok(TypeRecord::Procedure(LfProcedure {
        return_type: read_u32(data, 0).unwrap(),
        calling_convention: data[4],
        func_attrs: data[5],
        num_params: read_u16(data, 6).unwrap(),
        arg_list_type: read_u32(data, 8).unwrap(),
    }))
}

fn decode_mfunction(data: &[u8]) -> Result<TypeRecord, CodeViewError> {
    if data.len() < 24 { return Err(CodeViewError::TruncatedStream); }
    Ok(TypeRecord::MFunction(LfMFunction {
        return_type: read_u32(data, 0).unwrap(),
        class_type: read_u32(data, 4).unwrap(),
        this_type: read_u32(data, 8).unwrap(),
        calling_convention: data[12],
        func_attrs: data[13],
        num_params: read_u16(data, 14).unwrap(),
        arg_list_type: read_u32(data, 16).unwrap(),
        this_adjustment: i32::from_le_bytes(data[20..24].try_into().unwrap_or([0;4])),
    }))
}

fn decode_arglist(data: &[u8]) -> Result<TypeRecord, CodeViewError> {
    if data.len() < 4 { return Err(CodeViewError::TruncatedStream); }
    let count = read_u32(data, 0).unwrap() as usize;
    // Cap the reservation against the buffer: the count is attacker-controlled
    // and the loop below can never yield more than this many elements anyway.
    let max = data.len().saturating_sub(4) / 4;
    let mut args = Vec::with_capacity(count.min(max));
    for i in 0..count {
        let off = 4 + i * 4;
        if off + 4 > data.len() { break; }
        args.push(read_u32(data, off).unwrap());
    }
    Ok(TypeRecord::ArgList(LfArgList { arg_types: args }))
}

fn decode_bitfield(data: &[u8]) -> Result<TypeRecord, CodeViewError> {
    if data.len() < 6 { return Err(CodeViewError::TruncatedStream); }
    Ok(TypeRecord::Bitfield(LfBitfield {
        base_type: read_u32(data, 0).unwrap(),
        length: data[4],
        position: data[5],
    }))
}

fn decode_field_entry(leaf: u16, data: &[u8], pos: &mut usize) -> Option<FieldListEntry> {
    match leaf {
        lf::MEMBER => {
            if *pos + 6 > data.len() { return None; }
            let attrs = read_u16(data, *pos).unwrap();
            let field_type = read_u32(data, *pos + 2).unwrap();
            *pos += 6;
            let (offset, consumed) = read_numeric_leaf(&data[*pos..]).unwrap_or((0, 2));
            *pos += consumed;
            let (name, np) = read_nul_str(data, *pos);
            *pos = np;
            Some(FieldListEntry::Member(LfMember { attrs, field_type, offset, name }))
        }
        lf::STMEMBER => {
            if *pos + 6 > data.len() { return None; }
            let attrs = read_u16(data, *pos).unwrap();
            let field_type = read_u32(data, *pos + 2).unwrap();
            *pos += 6;
            let (name, np) = read_nul_str(data, *pos);
            *pos = np;
            Some(FieldListEntry::StMember(LfStMember { attrs, field_type, name }))
        }
        lf::ENUMERATE => {
            if *pos + 2 > data.len() { return None; }
            let attrs = read_u16(data, *pos).unwrap();
            *pos += 2;
            let (value, consumed) = read_numeric_leaf(&data[*pos..]).unwrap_or((0, 2));
            *pos += consumed;
            let (name, np) = read_nul_str(data, *pos);
            *pos = np;
            Some(FieldListEntry::Enumerate(LfEnumerate { attrs, value, name }))
        }
        lf::NESTTYPE | lf::NESTTYPEEX => {
            if *pos + 6 > data.len() { return None; }
            let attrs = read_u16(data, *pos).unwrap();
            let nested_type = read_u32(data, *pos + 2).unwrap();
            *pos += 6;
            let (name, np) = read_nul_str(data, *pos);
            *pos = np;
            Some(FieldListEntry::NestType(LfNestType { attrs, nested_type, name }))
        }
        lf::BCLASS => {
            if *pos + 6 > data.len() { return None; }
            let attrs = read_u16(data, *pos).unwrap();
            let base_class_type = read_u32(data, *pos + 2).unwrap();
            *pos += 6;
            let (offset, consumed) = read_numeric_leaf(&data[*pos..]).unwrap_or((0, 2));
            *pos += consumed;
            Some(FieldListEntry::BClass(LfBClass { attrs, base_class_type, offset }))
        }
        lf::VBCLASS | lf::IVBCLASS => {
            // attrs(2) + direct_vb_type(4) + vb_ptr_type(4) = 10 bytes read below.
            if *pos + 10 > data.len() { return None; }
            let attrs = read_u16(data, *pos).unwrap();
            let direct_vb_type = read_u32(data, *pos + 2).unwrap();
            let vb_ptr_type = read_u32(data, *pos + 6).unwrap();
            *pos += 10;
            let (vb_ptr_off, c1) = read_numeric_leaf(&data[*pos..]).unwrap_or((0, 2));
            *pos += c1;
            let (vb_index, c2) = read_numeric_leaf(&data[*pos..]).unwrap_or((0, 2));
            *pos += c2;
            let entry = LfVBClass { attrs, direct_vb_type, vb_ptr_type, vb_ptr_off, vb_index };
            Some(if leaf == lf::VBCLASS {
                FieldListEntry::VBClass(entry)
            } else {
                FieldListEntry::IVBClass(entry)
            })
        }
        lf::VFUNCTAB => {
            if *pos + 4 > data.len() { return None; }
            let vptr_type = read_u32(data, *pos).unwrap();
            *pos += 4;
            Some(FieldListEntry::VFuncTab(LfVFuncTab { vptr_type }))
        }
        lf::INDEX => {
            if *pos + 4 > data.len() { return None; }
            let _ = read_u16(data, *pos).unwrap(); // pad
            let continued_type = read_u32(data, *pos + 2).unwrap();
            *pos += 6;
            Some(FieldListEntry::Index { continued_type })
        }
        lf::ONEMETHOD => decode_one_method(data, pos),
        lf::METHOD => decode_method(data, pos),
        _ => None,
    }
}

fn decode_one_method(data: &[u8], pos: &mut usize) -> Option<FieldListEntry> {
    if *pos + 6 > data.len() { return None; }
    let attrs = read_u16(data, *pos).unwrap();
    let method_type = read_u32(data, *pos + 2).unwrap();
    *pos += 6;
    let intro = (attrs >> 2) & 0x7;
    let vbase_off = if intro == 4 || intro == 6 {
        if *pos + 4 <= data.len() {
            let v = read_u32(data, *pos).unwrap();
            *pos += 4;
            Some(v)
        } else { None }
    } else { None };
    let (name, np) = read_nul_str(data, *pos);
    *pos = np;
    Some(FieldListEntry::OneMethod(LfOneMethod { attrs, method_type, vbase_off, name }))
}

fn decode_method(data: &[u8], pos: &mut usize) -> Option<FieldListEntry> {
    if *pos + 6 > data.len() { return None; }
    let count = read_u16(data, *pos).unwrap();
    let method_list_type = read_u32(data, *pos + 2).unwrap();
    *pos += 6;
    let (name, np) = read_nul_str(data, *pos);
    *pos = np;
    Some(FieldListEntry::Method(LfMethod { count, method_list_type, name }))
}

fn decode_fieldlist(data: &[u8]) -> TypeRecord {
    let mut pos = 0usize;
    let mut entries = Vec::new();
    while pos + 2 <= data.len() {
        // Align to 4 bytes
        let align_rem = pos % 4;
        if align_rem != 0 {
            pos += 4 - align_rem;
            if pos >= data.len() { break; }
        }
        if pos + 2 > data.len() { break; }
        // Explicit LF_PAD bytes (0xF0..=0xFF) encode their own skip length.
        let b = data[pos];
        if b >= 0xF0 {
            let skip = (b & 0x0F) as usize;
            if skip == 0 { break; }
            pos += skip;
            continue;
        }
        let leaf = read_u16(data, pos).unwrap();
        pos += 2;
        if let Some(entry) = decode_field_entry(leaf, data, &mut pos) {
            entries.push(entry);
        } else {
            // The entry length is not recoverable, so we cannot resynchronize.
            // Always record the loss so it is visible to the caller.
            entries.push(FieldListEntry::Unknown { leaf });
            break;
        }
    }
    TypeRecord::FieldList(entries)
}

fn decode_vtshape(data: &[u8]) -> Result<TypeRecord, CodeViewError> {
    if data.len() < 2 { return Err(CodeViewError::TruncatedStream); }
    let count = read_u16(data, 0).unwrap();
    let desc_bytes = (count as usize).div_ceil(2);
    let descriptors = data.get(2..2 + desc_bytes).unwrap_or(&[]).to_vec();
    Ok(TypeRecord::VtShape(LfVtShape { count, descriptors }))
}

// ---------------------------------------------------------------------------
// Type table
// ---------------------------------------------------------------------------

/// A table of decoded type records indexed by type index.
#[derive(Debug, Default)]
pub struct TypeTable {
    pub records: BTreeMap<u32, TypeRecord>,
    pub start_index: u32,
}

impl TypeTable {
    #[must_use] 
    pub const fn new(start_index: u32) -> Self {
        Self { records: BTreeMap::new(), start_index }
    }

    #[must_use] 
    pub fn get(&self, ti: u32) -> Option<&TypeRecord> {
        if ti < lf::SIMPLE_TYPES_MAX {
            return None; // caller handles primitives
        }
        self.records.get(&ti)
    }

    pub fn insert(&mut self, ti: u32, rec: TypeRecord) {
        self.records.insert(ti, rec);
    }

    #[must_use] 
    pub fn len(&self) -> usize { self.records.len() }
    #[must_use] 
    pub fn is_empty(&self) -> bool { self.records.is_empty() }

    /// Resolve a type's display name recursively (limited depth).
    #[must_use] 
    pub fn type_name(&self, ti: u32, depth: u32) -> String {
        if depth > 8 { return format!("T_{ti:#X}"); }
        if ti < lf::SIMPLE_TYPES_MAX {
            let kind = PrimitiveKind::from_type_idx(ti);
            let mode = PrimitiveMode::from_u32(ti);
            let base = kind.to_string();
            return if mode.is_pointer() { format!("{base}*") } else { base };
        }
        match self.records.get(&ti) {
            None => format!("T_{ti:#X}"),
            Some(TypeRecord::Structure(s) | TypeRecord::Class(s)) => s.name.clone(),
            Some(TypeRecord::Union(u)) => u.name.clone(),
            Some(TypeRecord::Enum(e)) => e.name.clone(),
            Some(TypeRecord::Pointer(p)) => {
                format!("{}*", self.type_name(p.referent_type, depth + 1))
            }
            Some(TypeRecord::Modifier(m)) => {
                let base = self.type_name(m.modified_type, depth + 1);
                let mut mods = String::new();
                if m.is_const { mods.push_str("const "); }
                if m.is_volatile { mods.push_str("volatile "); }
                format!("{mods}{base}")
            }
            Some(TypeRecord::Array(a)) => {
                format!("{}[]", self.type_name(a.element_type, depth + 1))
            }
            Some(TypeRecord::Procedure(_)) => "<proc>".into(),
            Some(TypeRecord::MFunction(_)) => "<mfn>".into(),
            Some(r) => format!("{r:?}").chars().take(24).collect(),
        }
    }

    /// Get all named aggregate types (struct/class/union).
    pub fn named_aggregates(&self) -> impl Iterator<Item = (u32, &str)> {
        self.records.iter().filter_map(|(&ti, rec)| {
            rec.name().map(|n| (ti, n))
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vbclass_truncated_no_panic() {
        // LF_VBCLASS entry inside an LF_FIELDLIST with only 8 payload bytes
        // after the leaf tag: previously the bounds check allowed 8 bytes but
        // the decoder read 10 (attrs:2 + direct_vb_type:4 + vb_ptr_type:4),
        // panicking on unwrap. Must now decode without panicking.
        for extra in 0..10usize {
            let mut body = vec![];
            body.extend_from_slice(&lf::VBCLASS.to_le_bytes());
            body.extend(std::iter::repeat_n(0u8, extra));
            // FIELDLIST decode must not panic on any truncation length.
            let _ = decode_type_record(lf::FIELDLIST, &body);
        }
    }

    #[test]
    fn test_vbclass_full_decodes() {
        let mut body = vec![];
        body.extend_from_slice(&lf::VBCLASS.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes()); // attrs
        body.extend_from_slice(&0x1234u32.to_le_bytes()); // direct_vb_type
        body.extend_from_slice(&0x5678u32.to_le_bytes()); // vb_ptr_type
        body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // two small numeric leaves
        let rec = decode_type_record(lf::FIELDLIST, &body).unwrap();
        if let TypeRecord::FieldList(fl) = rec {
            assert_eq!(fl.len(), 1);
            match &fl[0] {
                FieldListEntry::VBClass(v) => {
                    assert_eq!(v.direct_vb_type, 0x1234);
                    assert_eq!(v.vb_ptr_type, 0x5678);
                }
                other => panic!("expected VBClass, got {other:?}"),
            }
        } else {
            panic!("expected FieldList");
        }
    }

    #[test]
    fn test_primitive_kind() {
        assert_eq!(PrimitiveKind::from_type_idx(0x74), PrimitiveKind::Int32);
        assert_eq!(PrimitiveKind::from_type_idx(0x75), PrimitiveKind::Uint32);
        assert_eq!(PrimitiveKind::from_type_idx(0x40), PrimitiveKind::Float32);
        assert_eq!(PrimitiveKind::Int32.byte_size(), Some(4));
        assert_eq!(PrimitiveKind::Float64.byte_size(), Some(8));
    }

    #[test]
    fn test_numeric_leaf_small() {
        let data = [0x05u8, 0x00]; // value = 5
        let (v, consumed) = read_numeric_leaf(&data).unwrap();
        assert_eq!(v, 5);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_numeric_leaf_ulong() {
        let mut data = vec![0x04u8, 0x80]; // LF_ULONG
        data.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let (v, consumed) = read_numeric_leaf(&data).unwrap();
        assert_eq!(v, i64::from(0xDEAD_BEEFu32));
        assert_eq!(consumed, 6);
    }

    #[test]
    fn test_decode_modifier() {
        let mut data = vec![0u8; 6];
        data[0..4].copy_from_slice(&0x1074u32.to_le_bytes()); // int32_t
        data[4..6].copy_from_slice(&1u16.to_le_bytes()); // const
        let rec = decode_type_record(lf::MODIFIER, &data).unwrap();
        if let TypeRecord::Modifier(m) = rec {
            assert!(m.is_const);
            assert!(!m.is_volatile);
            assert_eq!(m.modified_type, 0x1074);
        } else { panic!(); }
    }

    #[test]
    fn test_decode_procedure() {
        let mut data = vec![0u8; 12];
        data[0..4].copy_from_slice(&0x74u32.to_le_bytes()); // return = int
        data[4] = 0x40; // __cdecl
        data[6..8].copy_from_slice(&2u16.to_le_bytes()); // 2 params
        data[8..12].copy_from_slice(&0x1202u32.to_le_bytes()); // arglist type
        let rec = decode_type_record(lf::PROCEDURE, &data).unwrap();
        if let TypeRecord::Procedure(p) = rec {
            assert_eq!(p.num_params, 2);
            assert_eq!(p.calling_convention, 0x40);
        } else { panic!(); }
    }

    #[test]
    fn test_decode_arglist() {
        let mut data = vec![0u8; 4 + 8];
        data[0..4].copy_from_slice(&2u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x74u32.to_le_bytes());
        data[8..12].copy_from_slice(&0x75u32.to_le_bytes());
        let rec = decode_type_record(lf::ARGLIST, &data).unwrap();
        if let TypeRecord::ArgList(a) = rec {
            assert_eq!(a.arg_types, vec![0x74, 0x75]);
        } else { panic!(); }
    }

    #[test]
    fn test_type_table_name_resolution() {
        let mut tbl = TypeTable::new(0x1000);
        tbl.insert(0x1000, TypeRecord::Structure(LfStructure {
            num_members: 0, property: 0, field_type: 0, derived_type: 0, vshape_type: 0,
            byte_size: 16, name: "MyStruct".into(), unique_name: None,
        }));
        tbl.insert(0x1001, TypeRecord::Pointer(LfPointer {
            referent_type: 0x1000,
            attr: 0x0A, // near32 pointer
        }));
        assert_eq!(tbl.type_name(0x1000, 0), "MyStruct");
        assert_eq!(tbl.type_name(0x1001, 0), "MyStruct*");
    }

    #[test]
    fn test_fieldlist_enumerate() {
        // Build LF_FIELDLIST with one LF_ENUMERATE entry
        let mut data = Vec::new();
        let leaf = lf::ENUMERATE;
        data.extend_from_slice(&leaf.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // attrs
        // numeric leaf: value = 42
        data.extend_from_slice(&42u16.to_le_bytes());
        data.extend_from_slice(b"FOO\0");
        let rec = decode_type_record(lf::FIELDLIST, &data).unwrap();
        if let TypeRecord::FieldList(entries) = rec {
            assert_eq!(entries.len(), 1);
            if let FieldListEntry::Enumerate(e) = &entries[0] {
                assert_eq!(e.name, "FOO");
                assert_eq!(e.value, 42);
            } else { panic!("expected Enumerate"); }
        } else { panic!("expected FieldList"); }
    }
}
