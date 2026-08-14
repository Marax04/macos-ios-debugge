//! `cv_type_records` — `CodeView` type record decoder.
//!
//! Decodes `LF_POINTER`, `LF_ARRAY`, `LF_STRUCTURE`, `LF_CLASS`, `LF_UNION`, `LF_ENUM`,
//! `LF_PROCEDURE`, `LF_MFUNCTION`, `LF_ARGLIST`, `LF_FIELDLIST`, `LF_MEMBER`,
//! `LF_STMEMBER`, `LF_ENUMERATE`, `LF_NESTTYPE`, `LF_ONEMETHOD`, `LF_METHOD`,
//! `LF_BCLASS`, `LF_VBCLASS`, `LF_MODIFIER`, `LF_BITFIELD`, `LF_VTSHAPE`,
//! `LF_LABEL`, `LF_DIMARRAY`, and primitive type indices.
//!
//! # Status: main entry point unused (as of 2026-07-21)
//!
//! [`decode_type_record`] (and everything it calls, including
//! `decode_arglist`) has no external caller anywhere in the crate or in
//! `rustre-mcp-tools` — only its own `#[cfg(test)]` module exercises it. The
//! live PDB type path uses [`super::codeview_type_parser`] instead. Only
//! `read_numeric_leaf` from this file is genuinely live (used by
//! `cv_symbol_records.rs`). See `ENHANCEMENT_LOG.md` iters 230/232/233.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::CodeViewError;

// ---------------------------------------------------------------------------
// Leaf kind constants (LF_*)
// ---------------------------------------------------------------------------

/// `CodeView` leaf kind constants (`LF_*` record tags).
pub mod lf {
    /// `LF_MODIFIER_16t` — legacy 16-bit const/volatile modifier record.
    pub const MODIFIER_16T: u16 = 0x0001;
    /// `LF_POINTER_16t` — legacy 16-bit pointer type record.
    pub const POINTER_16T: u16 = 0x0002;
    /// `LF_ARRAY_16t` — legacy 16-bit array type record.
    pub const ARRAY_16T: u16 = 0x0003;
    /// `LF_CLASS_16t` — legacy 16-bit C++ class record.
    pub const CLASS_16T: u16 = 0x0004;
    /// `LF_STRUCTURE_16t` — legacy 16-bit struct record.
    pub const STRUCTURE_16T: u16 = 0x0005;
    /// `LF_UNION_16t` — legacy 16-bit union record.
    pub const UNION_16T: u16 = 0x0006;
    /// `LF_ENUM_16t` — legacy 16-bit enum record.
    pub const ENUM_16T: u16 = 0x0007;
    /// `LF_PROCEDURE_16t` — legacy 16-bit function type record.
    pub const PROCEDURE_16T: u16 = 0x0008;
    /// `LF_MFUNCTION_16t` — legacy 16-bit member-function type record.
    pub const MFUNCTION_16T: u16 = 0x0009;
    /// `LF_VTSHAPE` — virtual function table shape descriptor.
    pub const VTSHAPE: u16 = 0x000A;
    /// `LF_COBOL0_16t` — legacy COBOL type record (unused here).
    pub const COBOL0_16T: u16 = 0x000B;
    /// `LF_LABEL` — code label type (near/far addressing mode).
    pub const LABEL: u16 = 0x000E;
    /// `LF_NULL` — empty/placeholder leaf.
    pub const NULL: u16 = 0x000F;

    /// `LF_MODIFIER` — const/volatile/unaligned modifier applied to another type.
    pub const MODIFIER: u16 = 0x1001;
    /// `LF_POINTER` — pointer type (referent type index + attribute word).
    pub const POINTER: u16 = 0x1002;
    /// `LF_ARRAY` — array type (element type, index type, byte size, name).
    pub const ARRAY: u16 = 0x1003;
    /// `LF_CLASS` — C++ class definition (field list, vshape, size, name).
    pub const CLASS: u16 = 0x1004;
    /// `LF_STRUCTURE` — struct definition (same layout as `LF_CLASS`).
    pub const STRUCTURE: u16 = 0x1005;
    /// `LF_UNION` — union definition (field list, size, name).
    pub const UNION: u16 = 0x1006;
    /// `LF_ENUM` — enum definition (underlying type + enumerator field list).
    pub const ENUM: u16 = 0x1007;
    /// `LF_PROCEDURE` — non-member function type (return, convention, args).
    pub const PROCEDURE: u16 = 0x1008;
    /// `LF_MFUNCTION` — C++ member-function type (adds class/this types).
    pub const MFUNCTION: u16 = 0x1009;
    /// `LF_COBOL0` — COBOL type record (not decoded).
    pub const COBOL0: u16 = 0x100A;
    /// `LF_BARRAY` — basic-array type (not decoded).
    pub const BARRAY: u16 = 0x100B;
    /// `LF_DIMARRAY` — multi-dimensional array type (not decoded).
    pub const DIMARRAY: u16 = 0x100C;
    /// `LF_VFTPATH` — virtual function table path (not decoded).
    pub const VFTPATH: u16 = 0x100D;
    /// `LF_PRECOMP` — precompiled-types reference (not decoded).
    pub const PRECOMP: u16 = 0x100E;
    /// `LF_ENDPRECOMP` — end of precompiled types marker (not decoded).
    pub const ENDPRECOMP: u16 = 0x100F;
    /// `LF_OEM` — OEM-defined type (not decoded).
    pub const OEM: u16 = 0x1010;
    /// `LF_TYPESERVER` — reference to an external type-server PDB.
    pub const TYPESERVER: u16 = 0x1012;
    /// `LF_ENUMERATE` — a single enumerator (name + value) inside a field list.
    pub const ENUMERATE: u16 = 0x1502;
    /// `LF_ARRAY_ST` — array type with length-prefixed (`ST`) name.
    pub const ARRAY_ST: u16 = 0x1503;

    // Field list members
    /// `LF_BCLASS` — direct (non-virtual) base class in a field list.
    pub const BCLASS: u16 = 0x1400;
    /// `LF_VBCLASS` — direct virtual base class in a field list.
    pub const VBCLASS: u16 = 0x1401;
    /// `LF_IVBCLASS` — indirect virtual base class in a field list.
    pub const IVBCLASS: u16 = 0x1402;
    /// `LF_FRIENDFCN` — friend function entry in a field list.
    pub const FRIENDFCN: u16 = 0x1403;
    /// `LF_INDEX` — continuation link to another field list record.
    pub const INDEX: u16 = 0x1404;
    /// `LF_MEMBER` — non-static data member (type, offset, name).
    pub const MEMBER: u16 = 0x1405;
    /// `LF_STMEMBER` — static data member (type, name; no offset).
    pub const STMEMBER: u16 = 0x1406;
    /// `LF_METHOD` — overloaded method group referencing an `LF_METHODLIST`.
    pub const METHOD: u16 = 0x1407;
    /// `LF_NESTTYPE` — nested type declaration inside a class/struct.
    pub const NESTTYPE: u16 = 0x1408;
    /// `LF_VFUNCTAB` — virtual function table pointer member.
    pub const VFUNCTAB: u16 = 0x1409;
    /// `LF_FRIENDCLS` — friend class entry in a field list.
    pub const FRIENDCLS: u16 = 0x140A;
    /// `LF_ONEMETHOD` — non-overloaded method (attrs, type, optional vbase offset).
    pub const ONEMETHOD: u16 = 0x140B;
    /// `LF_VFUNCOFF` — virtual function offset entry.
    pub const VFUNCOFF: u16 = 0x140C;
    /// `LF_NESTTYPEEX` — nested type with attributes (extended `LF_NESTTYPE`).
    pub const NESTTYPEEX: u16 = 0x140D;
    /// `LF_MEMBERMODIFY` — member access modification in a derived class.
    pub const MEMBERMODIFY: u16 = 0x140E;

    /// `LF_FIELDLIST` — container record holding class/struct/enum members.
    pub const FIELDLIST: u16 = 0x1203;

    /// `LF_ARGLIST` — function argument list (count + type indices).
    pub const ARGLIST: u16 = 0x1201;
    /// `LF_BITFIELD` — bitfield member type (base type, bit length, bit position).
    pub const BITFIELD: u16 = 0x1205;

    /// First non-primitive type index; indices below this are simple/primitive types.
    pub const SIMPLE_TYPES_MAX: u32 = 0x1000;
}

// ---------------------------------------------------------------------------
// Primitive type decoder
// ---------------------------------------------------------------------------

/// Simple type (type index < 0x1000) mode bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrimitiveMode {
    /// Direct value (not a pointer).
    Direct = 0,
    /// 16-bit near pointer to the primitive.
    Near16Ptr = 1,
    /// 16:16 far pointer to the primitive.
    Far16Ptr = 2,
    /// 16:16 huge pointer to the primitive.
    Huge16Ptr = 3,
    /// 32-bit near pointer to the primitive.
    Near32Ptr = 4,
    /// 16:32 far pointer to the primitive.
    Far32Ptr = 5,
    /// 64-bit near pointer to the primitive.
    Near64Ptr = 6,
    /// 128-bit near pointer to the primitive.
    Near128Ptr = 7,
}

impl PrimitiveMode {
    /// Extract the mode bits (bits 8..12) from a simple type index.
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
    /// Returns true when the mode denotes any pointer form (not [`Self::Direct`]).
    #[must_use]
    pub const fn is_pointer(&self) -> bool { !matches!(self, Self::Direct) }
}

/// Base kind of a simple (primitive) `CodeView` type index (`T_*` values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrimitiveKind {
    /// `T_NOTYPE` — no type / uncharacterized.
    NoType,
    /// `T_VOID` — the `void` type.
    Void,
    /// 8-bit boolean (`T_BOOL08`).
    Bool8,
    /// 16-bit boolean (`T_BOOL16`).
    Bool16,
    /// 32-bit boolean (`T_BOOL32`).
    Bool32,
    /// 64-bit boolean (`T_BOOL64`).
    Bool64,
    /// Signed 8-bit integer (`T_INT1`/`T_CHAR`).
    Int8,
    /// Signed 16-bit integer (`T_INT2`/`T_SHORT`).
    Int16,
    /// Signed 32-bit integer (`T_INT4`/`T_LONG`).
    Int32,
    /// Signed 64-bit integer (`T_INT8`/`T_QUAD`).
    Int64,
    /// Signed 128-bit integer (`T_INT16`).
    Int128,
    /// Unsigned 8-bit integer (`T_UINT1`/`T_UCHAR`).
    Uint8,
    /// Unsigned 16-bit integer (`T_UINT2`/`T_USHORT`).
    Uint16,
    /// Unsigned 32-bit integer (`T_UINT4`/`T_ULONG`).
    Uint32,
    /// Unsigned 64-bit integer (`T_UINT8`/`T_UQUAD`).
    Uint64,
    /// Unsigned 128-bit integer (`T_UINT16`).
    Uint128,
    /// 32-bit IEEE float (`T_REAL32`).
    Float32,
    /// 64-bit IEEE float (`T_REAL64`).
    Float64,
    /// 80-bit x87 extended float (`T_REAL80`).
    Float80,
    /// 128-bit float (`T_REAL128`).
    Float128,
    /// 32-bit complex (`T_CPLX32`).
    Complex32,
    /// 64-bit complex (`T_CPLX64`).
    Complex64,
    /// 80-bit complex (`T_CPLX80`).
    Complex80,
    /// 128-bit complex (`T_CPLX128`).
    Complex128,
    /// 8-bit character (`T_RCHAR`/`T_CHAR8`).
    Char8,
    /// UTF-16 character (`T_CHAR16`).
    Char16,
    /// UTF-32 character (`T_CHAR32`).
    Char32,
    /// Wide character `wchar_t` (`T_WCHAR`).
    WChar,
    /// Windows `HRESULT` (`T_HRESULT`).
    Hresult,
    /// Unrecognized primitive; carries the raw type index.
    Unknown(u32),
}

impl PrimitiveKind {
    /// Decode the primitive kind from the low byte of a simple type index.
    #[must_use]
    pub const fn from_type_idx(ti: u32) -> Self {
        let kind = ti & 0xFF;
        match kind {
            0x00 => Self::NoType,
            0x03 => Self::Void,
            0x30 => Self::Bool8,
            0x31 => Self::Bool16,
            0x32 => Self::Bool32,
            0x33 => Self::Bool64,
            0x10 | 0x68 => Self::Int8,
            0x11 | 0x69 => Self::Int16,
            0x12 | 0x74 => Self::Int32,
            0x13 | 0x76 => Self::Int64,
            0x14 => Self::Int128,
            0x20 | 0x78 => Self::Uint8,
            0x21 | 0x79 => Self::Uint16,
            0x22 | 0x75 => Self::Uint32,
            0x23 | 0x77 => Self::Uint64,
            0x24 => Self::Uint128,
            0x40 => Self::Float32,
            0x41 => Self::Float64,
            0x42 => Self::Float80,
            0x43 => Self::Float128,
            0x50 => Self::Complex32,
            0x51 => Self::Complex64,
            0x52 => Self::Complex80,
            0x53 => Self::Complex128,
            0x60 | 0x70 => Self::Char8,
            0x61 => Self::WChar,
            0x62 => Self::Char16,
            0x63 => Self::Char32,
            0x08 => Self::Hresult,
            _ => Self::Unknown(ti),
        }
    }
    /// Size of the primitive in bytes, or `None` when unknown.
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
            Some((i64::from(super::casts::u8_as_i8(*data.get(2)?)), 3))
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
            let v = super::casts::u64_as_i64(u64::from_le_bytes(data.get(2..10)?.try_into().ok()?));
            Some((v, 10))
        }
        _ => Some((0, 2)),
    }
}

// ---------------------------------------------------------------------------
// Type record structures
// ---------------------------------------------------------------------------

/// `LF_MODIFIER` — const/volatile/unaligned qualifier wrapping another type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfModifier {
    /// Type index of the type being modified.
    pub modified_type: u32,
    /// `const` qualifier present.
    pub is_const: bool,
    /// `volatile` qualifier present.
    pub is_volatile: bool,
    /// `__unaligned` qualifier present.
    pub is_unaligned: bool,
}

/// `LF_POINTER` — pointer type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfPointer {
    /// Type index of the pointed-to type.
    pub referent_type: u32,
    /// Raw pointer attribute bitfield (kind, mode, qualifier flags).
    pub attr: u32,
}

impl LfPointer {
    /// Pointer kind (attr bits 0..5): near/far/32-bit/64-bit, etc.
    #[must_use]
    pub const fn pointer_kind(&self) -> u8 { (self.attr & 0x1F) as u8 }
    /// Pointer mode (attr bits 5..8): plain pointer, reference, pointer-to-member.
    #[must_use]
    pub const fn pointer_mode(&self) -> u8 { ((self.attr >> 5) & 0x7) as u8 }
    /// `const` pointer flag (attr bit 10).
    #[must_use]
    pub const fn is_const(&self) -> bool { (self.attr >> 10) & 1 != 0 }
    /// `volatile` pointer flag (attr bit 11).
    #[must_use]
    pub const fn is_volatile(&self) -> bool { (self.attr >> 11) & 1 != 0 }
    /// `__unaligned` pointer flag (attr bit 12).
    #[must_use]
    pub const fn is_unaligned(&self) -> bool { (self.attr >> 12) & 1 != 0 }
    /// `restrict` pointer flag (attr bit 13).
    #[must_use]
    pub const fn is_restrict(&self) -> bool { (self.attr >> 13) & 1 != 0 }
    /// Pointer size in bytes inferred from the pointer kind (2, 4 or 8).
    #[must_use]
    pub const fn byte_size(&self) -> u8 {
        match self.pointer_kind() {
            0..=3 => 2,
            10 | 11 | 13 => 8,
            // 4, 5, 12 are the 32-bit pointer kinds; treat anything else as 32-bit too.
            _ => 4,
        }
    }
}

/// `LF_ARRAY` — array type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfArray {
    /// Type index of the array element type.
    pub element_type: u32,
    /// Type index of the indexing type (usually an integer primitive).
    pub index_type: u32,
    /// Total array size in bytes (from the numeric leaf).
    pub byte_size: i64,
    /// Array type name (often empty).
    pub name: String,
}

/// `LF_STRUCTURE` / `LF_CLASS` — aggregate type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfStructure {
    /// Number of members in the field list.
    pub num_members: u16,
    /// Property bitfield (bit 7 = forward ref, bit 9 = has unique name, ...).
    pub property: u16,
    /// Type index of the `LF_FIELDLIST` describing the members.
    pub field_type: u32,
    /// Type index of the derivation list (0 if none).
    pub derived_type: u32,
    /// Type index of the `LF_VTSHAPE` for this class (0 if none).
    pub vshape_type: u32,
    /// Size of an instance in bytes (from the numeric leaf).
    pub byte_size: i64,
    /// Display name of the struct/class.
    pub name: String,
    /// Mangled unique name, present when property bit 9 is set.
    pub unique_name: Option<String>,
}

/// `LF_CLASS` shares the exact layout of `LF_STRUCTURE`.
pub type LfClass = LfStructure;

/// `LF_UNION` — union type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfUnion {
    /// Number of members in the field list.
    pub num_members: u16,
    /// Property bitfield (same layout as [`LfStructure::property`]).
    pub property: u16,
    /// Type index of the `LF_FIELDLIST` describing the members.
    pub field_type: u32,
    /// Size of the union in bytes.
    pub byte_size: i64,
    /// Display name of the union.
    pub name: String,
    /// Mangled unique name, present when property bit 9 is set.
    pub unique_name: Option<String>,
}

/// `LF_ENUM` — enumeration type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfEnum {
    /// Number of enumerators.
    pub num_elements: u16,
    /// Property bitfield (same layout as [`LfStructure::property`]).
    pub property: u16,
    /// Type index of the underlying integer type.
    pub underlying_type: u32,
    /// Type index of the `LF_FIELDLIST` holding the `LF_ENUMERATE` entries.
    pub field_type: u32,
    /// Display name of the enum.
    pub name: String,
    /// Mangled unique name, present when property bit 9 is set.
    pub unique_name: Option<String>,
}

/// `LF_PROCEDURE` — non-member function type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfProcedure {
    /// Type index of the return type.
    pub return_type: u32,
    /// Calling convention code (`CV_call_e`, e.g. 0x00 = near C).
    pub calling_convention: u8,
    /// Function attribute flags (`CV_funcattr_t`).
    pub func_attrs: u8,
    /// Number of parameters.
    pub num_params: u16,
    /// Type index of the `LF_ARGLIST` record.
    pub arg_list_type: u32,
}

/// `LF_MFUNCTION` — C++ member-function type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMFunction {
    /// Type index of the return type.
    pub return_type: u32,
    /// Type index of the containing class.
    pub class_type: u32,
    /// Type index of the `this` pointer type (0 for static methods).
    pub this_type: u32,
    /// Calling convention code (`CV_call_e`).
    pub calling_convention: u8,
    /// Function attribute flags (`CV_funcattr_t`).
    pub func_attrs: u8,
    /// Number of parameters (excluding `this`).
    pub num_params: u16,
    /// Type index of the `LF_ARGLIST` record.
    pub arg_list_type: u32,
    /// Adjustment applied to `this` before the call (for multiple inheritance).
    pub this_adjustment: i32,
}

/// `LF_ARGLIST` — function argument type list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfArgList {
    /// Type indices of the arguments, in declaration order.
    pub arg_types: Vec<u32>,
}

/// `LF_BITFIELD` — bitfield member type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfBitfield {
    /// Type index of the underlying integer type.
    pub base_type: u32,
    /// Width of the bitfield in bits.
    pub length: u8,
    /// Starting bit position within the underlying type.
    pub position: u8,
}

/// `LF_MEMBER` — non-static data member in a field list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMember {
    /// Member attribute bitfield (`CV_fldattr_t`: access, method properties).
    pub attrs: u16,
    /// Type index of the member's type.
    pub field_type: u32,
    /// Byte offset of the member within the aggregate.
    pub offset: i64,
    /// Member name.
    pub name: String,
}

/// `LF_STMEMBER` — static data member in a field list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfStMember {
    /// Member attribute bitfield (`CV_fldattr_t`).
    pub attrs: u16,
    /// Type index of the member's type.
    pub field_type: u32,
    /// Member name.
    pub name: String,
}

/// `LF_ENUMERATE` — single enumerator (name/value pair) in a field list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfEnumerate {
    /// Attribute bitfield (`CV_fldattr_t`).
    pub attrs: u16,
    /// Enumerator value (decoded from the numeric leaf).
    pub value: i64,
    /// Enumerator name.
    pub name: String,
}

/// `LF_NESTTYPE` / `LF_NESTTYPEEX` — nested type declared inside a class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfNestType {
    /// Attribute bitfield (zero for plain `LF_NESTTYPE`).
    pub attrs: u16,
    /// Type index of the nested type.
    pub nested_type: u32,
    /// Name of the nested type as declared in the class.
    pub name: String,
}

/// `LF_ONEMETHOD` — a non-overloaded method in a field list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfOneMethod {
    /// Attribute bitfield (`CV_fldattr_t`; bits 2..5 hold the method property).
    pub attrs: u16,
    /// Type index of the method's `LF_MFUNCTION`.
    pub method_type: u32,
    /// Vtable offset, present only for introducing virtual methods.
    pub vbase_off: Option<u32>,
    /// Method name.
    pub name: String,
}

/// One entry inside an `LF_METHODLIST` (an overload of a method group).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodListEntry {
    /// Attribute bitfield (`CV_fldattr_t`).
    pub attrs: u16,
    /// Type index of this overload's `LF_MFUNCTION`.
    pub method_type: u32,
    /// Vtable offset, present only for introducing virtual methods.
    pub vbase_off: Option<u32>,
}

/// `LF_METHOD` — overloaded method group in a field list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMethod {
    /// Number of overloads in the method list.
    pub count: u16,
    /// Type index of the `LF_METHODLIST` record.
    pub method_list_type: u32,
    /// Method name shared by all overloads.
    pub name: String,
}

/// `LF_BCLASS` — direct (non-virtual) base class in a field list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfBClass {
    /// Attribute bitfield (`CV_fldattr_t`).
    pub attrs: u16,
    /// Type index of the base class.
    pub base_class_type: u32,
    /// Byte offset of the base subobject within the derived class.
    pub offset: i64,
}

/// `LF_VBCLASS` / `LF_IVBCLASS` — (indirect) virtual base class in a field list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfVBClass {
    /// Attribute bitfield (`CV_fldattr_t`).
    pub attrs: u16,
    /// Type index of the virtual base class.
    pub direct_vb_type: u32,
    /// Type index of the virtual base pointer type.
    pub vb_ptr_type: u32,
    /// Offset of the virtual base pointer from the address point.
    pub vb_ptr_off: i64,
    /// Index into the virtual base displacement table.
    pub vb_index: i64,
}

/// `LF_VFUNCTAB` — virtual function table pointer member in a field list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfVFuncTab {
    /// Type index of the vtable pointer type.
    pub vptr_type: u32,
}

/// `LF_VTSHAPE` — virtual function table shape descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfVtShape {
    /// Number of vtable slots described.
    pub count: u16,
    /// Packed 4-bit descriptors, two slots per byte.
    pub descriptors: Vec<u8>,
}

/// A field list entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldListEntry {
    /// `LF_MEMBER` — non-static data member.
    Member(LfMember),
    /// `LF_STMEMBER` — static data member.
    StMember(LfStMember),
    /// `LF_ENUMERATE` — enumerator name/value.
    Enumerate(LfEnumerate),
    /// `LF_NESTTYPE`/`LF_NESTTYPEEX` — nested type declaration.
    NestType(LfNestType),
    /// `LF_ONEMETHOD` — non-overloaded method.
    OneMethod(LfOneMethod),
    /// `LF_METHOD` — overloaded method group.
    Method(LfMethod),
    /// `LF_BCLASS` — direct base class.
    BClass(LfBClass),
    /// `LF_VBCLASS` — direct virtual base class.
    VBClass(LfVBClass),
    /// `LF_IVBCLASS` — indirect virtual base class.
    IVBClass(LfVBClass),
    /// `LF_VFUNCTAB` — vtable pointer member.
    VFuncTab(LfVFuncTab),
    /// `LF_INDEX` — continuation link to another field list record.
    Index {
        /// Type index of the continuation `LF_FIELDLIST`.
        continued_type: u32,
    },
    /// Unrecognized field-list leaf; decoding stops here.
    Unknown {
        /// Raw leaf kind that was not recognized.
        leaf: u16,
    },
}

/// A decoded `CodeView` type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeRecord {
    /// `LF_MODIFIER` — const/volatile/unaligned qualifier.
    Modifier(LfModifier),
    /// `LF_POINTER` — pointer type.
    Pointer(LfPointer),
    /// `LF_ARRAY` — array type.
    Array(LfArray),
    /// `LF_STRUCTURE` — struct definition.
    Structure(LfStructure),
    /// `LF_CLASS` — C++ class definition.
    Class(LfClass),
    /// `LF_UNION` — union definition.
    Union(LfUnion),
    /// `LF_ENUM` — enum definition.
    Enum(LfEnum),
    /// `LF_PROCEDURE` — non-member function type.
    Procedure(LfProcedure),
    /// `LF_MFUNCTION` — member-function type.
    MFunction(LfMFunction),
    /// `LF_ARGLIST` — function argument type list.
    ArgList(LfArgList),
    /// `LF_BITFIELD` — bitfield member type.
    Bitfield(LfBitfield),
    /// `LF_FIELDLIST` — decoded list of aggregate members.
    FieldList(Vec<FieldListEntry>),
    /// `LF_VTSHAPE` — vtable shape descriptor.
    VtShape(LfVtShape),
    /// Simple/primitive type (type index below 0x1000).
    Primitive {
        /// Raw simple type index.
        type_index: u32,
        /// Decoded base kind.
        kind: PrimitiveKind,
        /// Decoded pointer mode.
        mode: PrimitiveMode,
    },
    /// Leaf kind not handled by [`decode_type_record`].
    Unknown {
        /// Raw leaf kind.
        leaf: u16,
    },
}

impl TypeRecord {
    /// Display name of the record for named aggregates (struct/class/union/enum).
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Structure(s) | Self::Class(s) => Some(&s.name),
            Self::Union(u) => Some(&u.name),
            Self::Enum(e) => Some(&e.name),
            _ => None,
        }
    }

    /// Size of an instance of this type in bytes, when it can be determined.
    #[must_use]
    pub fn byte_size(&self) -> Option<u64> {
        match self {
            Self::Structure(s) | Self::Class(s) => Some(super::casts::i64_as_u64(s.byte_size)),
            Self::Union(u) => Some(super::casts::i64_as_u64(u.byte_size)),
            Self::Array(a) => Some(super::casts::i64_as_u64(a.byte_size)),
            Self::Pointer(p) => Some(u64::from(p.byte_size())),
            Self::Primitive { kind, mode, .. } => {
                if mode.is_pointer() { Some(8) }
                else { kind.byte_size().map(u64::from) }
            }
            _ => None,
        }
    }

    /// Returns true for struct/class/union records.
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
    // `count` is raw and untrusted (up to ~4.29B) — cap the allocation hint
    // to what `data` could actually hold (4 bytes/entry) so a corrupted or
    // adversarial record can't request a huge up-front allocation; the
    // loop below already bails via `break` once the buffer runs out, so
    // this only changes the allocation, not the actual parsed result.
    let max_possible = (data.len().saturating_sub(4)) / 4;
    let mut args = Vec::with_capacity(count.min(max_possible));
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
            if *pos + 8 > data.len() { return None; }
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
        let leaf = read_u16(data, pos).unwrap();
        pos += 2;
        if let Some(entry) = decode_field_entry(leaf, data, &mut pos) {
            entries.push(entry);
        } else {
            if !matches!(leaf, lf::MEMBER | lf::STMEMBER | lf::ENUMERATE
                | lf::NESTTYPE | lf::NESTTYPEEX | lf::BCLASS | lf::VBCLASS
                | lf::IVBCLASS | lf::VFUNCTAB | lf::INDEX
                | lf::ONEMETHOD | lf::METHOD)
            {
                entries.push(FieldListEntry::Unknown { leaf });
            }
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
    /// Decoded records keyed by type index.
    pub records: BTreeMap<u32, TypeRecord>,
    /// First type index of the stream (TPI header `TypeIndexBegin`, usually 0x1000).
    pub start_index: u32,
}

impl TypeTable {
    /// Create an empty table whose first type index is `start_index`.
    #[must_use]
    pub const fn new(start_index: u32) -> Self {
        Self { records: BTreeMap::new(), start_index }
    }

    /// Look up a record by type index; primitives (< 0x1000) return `None`.
    #[must_use]
    pub fn get(&self, ti: u32) -> Option<&TypeRecord> {
        if ti < lf::SIMPLE_TYPES_MAX {
            return None; // caller handles primitives
        }
        self.records.get(&ti)
    }

    /// Insert (or replace) the record at type index `ti`.
    pub fn insert(&mut self, ti: u32, rec: TypeRecord) {
        self.records.insert(ti, rec);
    }

    /// Number of stored records.
    #[must_use]
    pub fn len(&self) -> usize { self.records.len() }
    /// Returns true when no records are stored.
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
    fn test_decode_arglist_with_huge_declared_count_does_not_over_allocate() {
        // `count` claims ~4.29B entries but the buffer only has room for 2 —
        // the fix caps `Vec::with_capacity` to what `data` can actually
        // hold, so this must return only the 2 real entries instead of
        // attempting a multi-GB allocation.
        let mut data = vec![0u8; 4 + 8];
        data[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
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
