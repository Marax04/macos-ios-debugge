//! Full `CodeView` type record parser — LF_* records from TPI/IPI streams.
//!
//! Supports all major `CodeView` 4.x / 7.0 / CV8 type leaf kinds needed for
//! complete type reconstruction from PDB type streams.
//!
//! # Status: not wired into the live pipeline (as of 2026-07-21)
//!
//! The actual live PDB type-loading path (`debug.load_types`) goes through
//! [`super::codeview_type_parser::CodeViewTypeParser`] via
//! [`super::pdb_tpi_reader`], not this module. This file is `pub` and has its
//! own passing test suite, but grepping the crate and its primary consumer
//! (`rustre-mcp-tools`) finds zero external callers of anything defined here.
//! Kept for now pending a decision on whether to remove it (flagged, not
//! deleted, in `ENHANCEMENT_LOG.md` iters 230/232/233) — do not assume code
//! here is exercised by anything other than its own `#[cfg(test)]` module.

use super::CodeViewError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Type index
// ---------------------------------------------------------------------------

/// A 32-bit `CodeView` type index. Values < 0x1000 are built-in primitive types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct TypeIndex(pub u32);

impl TypeIndex {
    /// Returns `true` if this is a primitive (built-in) type index (< 0x1000).
    #[inline]
    #[must_use]
    pub const fn is_primitive(self) -> bool {
        self.0 < 0x1000
    }

    /// Decode the simple type mode (pointer size / indirection) from bits 8-11.
    #[inline]
    #[must_use]
    pub const fn pointer_mode(self) -> u8 {
        ((self.0 >> 8) & 0xf) as u8
    }

    /// Decode the simple type code from bits 0-7.
    #[inline]
    #[must_use]
    pub const fn simple_type(self) -> u8 {
        (self.0 & 0xff) as u8
    }
}

impl std::fmt::Display for TypeIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "T#{:#010x}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Leaf kind constants (LF_*)
// ---------------------------------------------------------------------------

/// `CodeView` type-record leaf kind constants (`LF_*`) as they appear in the
/// 2-byte kind field of each TPI/IPI record.
#[allow(non_upper_case_globals)]
pub mod lf {
    /// `LF_MODIFIER` — const/volatile/unaligned modifier applied to a type.
    pub const LF_MODIFIER:    u16 = 0x1001;
    /// `LF_POINTER` — pointer (or reference / pointer-to-member) type.
    pub const LF_POINTER:     u16 = 0x1002;
    /// `LF_ARRAY` — array type with element type, index type and byte length.
    pub const LF_ARRAY:       u16 = 0x1003;
    /// `LF_CLASS` — C++ class definition (or forward reference).
    pub const LF_CLASS:       u16 = 0x1004;
    /// `LF_STRUCTURE` — struct definition (or forward reference).
    pub const LF_STRUCTURE:   u16 = 0x1005;
    /// `LF_UNION` — union definition (or forward reference).
    pub const LF_UNION:       u16 = 0x1006;
    /// `LF_ENUM` — enumeration definition.
    pub const LF_ENUM:        u16 = 0x1007;
    /// `LF_PROCEDURE` — non-member function type.
    pub const LF_PROCEDURE:   u16 = 0x1008;
    /// `LF_MFUNCTION` — member function type (includes class/this info).
    pub const LF_MFUNCTION:   u16 = 0x1009;
    /// `LF_VTSHAPE` — virtual function table shape descriptor.
    pub const LF_VTSHAPE:     u16 = 0x000a;
    /// `LF_BITFIELD` — bitfield member type (underlying type, bit position/length).
    pub const LF_BITFIELD:    u16 = 0x1205;
    /// `LF_FIELDLIST` — list of members of a class/struct/union/enum.
    pub const LF_FIELDLIST:   u16 = 0x1203;
    /// `LF_ARGLIST` — function argument type-index list.
    pub const LF_ARGLIST:     u16 = 0x1201;
    /// `LF_METHODLIST` — list of overloads for an `LF_METHOD` group.
    pub const LF_METHODLIST:  u16 = 0x1206;
    /// `LF_DIMARRAY` — multi-dimensional array type.
    pub const LF_DIMARRAY:    u16 = 0x1508;
    /// `LF_PRECOMP` — reference to types from a precompiled header.
    pub const LF_PRECOMP:     u16 = 0x1509;
    /// `LF_ALIAS` — type alias (typedef).
    pub const LF_ALIAS:       u16 = 0x150a;
    /// `LF_BCLASS` — direct (non-virtual) base class member.
    pub const LF_BCLASS:      u16 = 0x1400;
    /// `LF_VBCLASS` — direct virtual base class member.
    pub const LF_VBCLASS:     u16 = 0x1401;
    /// `LF_IVBCLASS` — indirect virtual base class member.
    pub const LF_IVBCLASS:    u16 = 0x1402;
    /// `LF_MEMBER` — non-static data member with offset.
    pub const LF_MEMBER:      u16 = 0x150d;
    /// `LF_STMEMBER` — static data member.
    pub const LF_STMEMBER:    u16 = 0x150e;
    /// `LF_METHOD` — overloaded method group (points to a method list).
    pub const LF_METHOD:      u16 = 0x150f;
    /// `LF_NESTTYPE` — nested type definition inside a class.
    pub const LF_NESTTYPE:    u16 = 0x1510;
    /// `LF_ONEMETHOD` — single non-overloaded method.
    pub const LF_ONEMETHOD:   u16 = 0x1511;
    /// `LF_ENUMERATE` — one enumerator (name + value) in an enum field list.
    pub const LF_ENUMERATE:   u16 = 0x1502;
    /// `LF_INDEX` — continuation reference to another field list.
    pub const LF_INDEX:       u16 = 0x1404;
    /// `LF_VFUNCTAB` — virtual function table pointer member.
    pub const LF_VFUNCTAB:    u16 = 0x1409;
    /// `LF_VFUNCOFF` — virtual function table pointer at a non-zero offset.
    pub const LF_VFUNCOFF:    u16 = 0x140b;
    /// `LF_TYPESERVER2` — reference to an external PDB type server.
    pub const LF_TYPESERVER2: u16 = 0x1515;
    /// `LF_FUNC_ID` — function ID record (IPI stream).
    pub const LF_FUNC_ID:     u16 = 0x1601;
    /// `LF_MFUNC_ID` — member function ID record (IPI stream).
    pub const LF_MFUNC_ID:    u16 = 0x1602;
    /// `LF_BUILDINFO` — build info record (tool/paths/args, IPI stream).
    pub const LF_BUILDINFO:   u16 = 0x1603;
    /// `LF_STRING_ID` — string ID record (IPI stream).
    pub const LF_STRING_ID:   u16 = 0x1605;
    /// `LF_UDT_SRC_LINE` — source file/line where a UDT is defined (IPI stream).
    pub const LF_UDT_SRC_LINE: u16 = 0x1606;
    // numeric leaves
    /// Numeric leaf: signed 8-bit value follows.
    pub const LF_CHAR:        u16 = 0x8000;
    /// Numeric leaf: signed 16-bit value follows.
    pub const LF_SHORT:       u16 = 0x8001;
    /// Numeric leaf: unsigned 16-bit value follows.
    pub const LF_USHORT:      u16 = 0x8002;
    /// Numeric leaf: signed 32-bit value follows.
    pub const LF_LONG:        u16 = 0x8003;
    /// Numeric leaf: unsigned 32-bit value follows.
    pub const LF_ULONG:       u16 = 0x8004;
    /// Numeric leaf: 32-bit IEEE float value follows.
    pub const LF_REAL32:      u16 = 0x8005;
    /// Numeric leaf: 64-bit IEEE double value follows.
    pub const LF_REAL64:      u16 = 0x8006;
    /// Numeric leaf: signed 64-bit value follows.
    pub const LF_QUADWORD:    u16 = 0x8009;
    /// Numeric leaf: unsigned 64-bit value follows.
    pub const LF_UQUADWORD:   u16 = 0x800a;
}

// ---------------------------------------------------------------------------
// Calling convention
// ---------------------------------------------------------------------------

/// Calling convention codes used in `LF_PROCEDURE` / `LF_MFUNCTION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CallingConvention {
    /// Near C (`__cdecl`, caller cleans stack).
    NearC       = 0x00,
    /// Far C (16-bit far `__cdecl`).
    FarC        = 0x01,
    /// Near Pascal (callee cleans stack, left-to-right args).
    NearPascal  = 0x02,
    /// Far Pascal.
    FarPascal   = 0x03,
    /// Near fastcall (first args in registers).
    NearFastcall= 0x04,
    /// Far fastcall.
    FarFastcall = 0x05,
    /// Near stdcall (`__stdcall`, callee cleans stack).
    NearStdcall = 0x07,
    /// Far stdcall.
    FarStdcall  = 0x08,
    /// Near syscall.
    NearSyscall = 0x09,
    /// Far syscall.
    FarSyscall  = 0x0a,
    /// `__thiscall` — `this` pointer passed in a register (ECX on x86).
    Thiscall    = 0x0b,
    /// Near MSVC fastcall variant.
    NearMsfastcall = 0x0c,
    /// Far MSVC fastcall variant.
    FarMsfastcall  = 0x0d,
    /// CLR call (managed code).
    NearClrcall    = 0x16,
    /// Unrecognized calling-convention code.
    Unknown     = 0xff,
}

impl CallingConvention {
    /// Decode a raw calling-convention byte; unknown codes map to [`Self::Unknown`].
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Self::NearC,
            0x01 => Self::FarC,
            0x02 => Self::NearPascal,
            0x03 => Self::FarPascal,
            0x04 => Self::NearFastcall,
            0x05 => Self::FarFastcall,
            0x07 => Self::NearStdcall,
            0x08 => Self::FarStdcall,
            0x09 => Self::NearSyscall,
            0x0a => Self::FarSyscall,
            0x0b => Self::Thiscall,
            0x0c => Self::NearMsfastcall,
            0x0d => Self::FarMsfastcall,
            0x16 => Self::NearClrcall,
            _    => Self::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// CV type property flags
// ---------------------------------------------------------------------------

/// Property flags shared by `LF_CLASS/LF_STRUCTURE/LF_UNION/LF_ENUM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CvTypeProps(pub u16);

impl CvTypeProps {
    /// True if the structure is packed (no compiler-inserted padding).
    #[must_use]
    pub const fn is_packed(self)          -> bool { self.0 & 0x0001 != 0 }
    /// True if the type has constructors or destructors.
    #[must_use]
    pub const fn has_constructor(self)    -> bool { self.0 & 0x0002 != 0 }
    /// True if the type has overloaded operators.
    #[must_use]
    pub const fn has_overloaded_ops(self) -> bool { self.0 & 0x0004 != 0 }
    /// True if this type is nested within another type.
    #[must_use]
    pub const fn is_nested(self)          -> bool { self.0 & 0x0008 != 0 }
    /// True if the type contains nested type definitions.
    #[must_use]
    pub const fn contains_nested(self)    -> bool { self.0 & 0x0010 != 0 }
    /// True if the type has an overloaded assignment operator.
    #[must_use]
    pub const fn has_overloaded_assign(self) -> bool { self.0 & 0x0020 != 0 }
    /// True if the type has casting methods (conversion operators).
    #[must_use]
    pub const fn has_cast_ops(self)       -> bool { self.0 & 0x0040 != 0 }
    /// True if this record is a forward reference (declaration without body).
    #[must_use]
    pub const fn is_forward_ref(self)     -> bool { self.0 & 0x0080 != 0 }
    /// True if this is a scoped definition (e.g. declared inside a function).
    #[must_use]
    pub const fn is_scoped(self)          -> bool { self.0 & 0x0100 != 0 }
    /// True if a decorated (unique) name follows the regular name in the record.
    #[must_use]
    pub const fn has_unique_name(self)    -> bool { self.0 & 0x0200 != 0 }
    /// True if the class is `final` / cannot be used as a base class.
    #[must_use]
    pub const fn is_sealed(self)          -> bool { self.0 & 0x0400 != 0 }
    /// Homogeneous floating-point aggregate kind (bits 11-12, ARM ABI).
    #[must_use]
    pub const fn hfa(self)                -> u8   { ((self.0 >> 11) & 3) as u8 }
    /// True if this is a compiler-intrinsic type (e.g. `__m128`).
    #[must_use]
    pub const fn is_intrinsic(self)       -> bool { self.0 & 0x2000 != 0 }
    /// MoCOM UDT kind (bits 14-15: none/ref/value/interface).
    #[must_use]
    pub const fn mocom(self)              -> u8   { ((self.0 >> 14) & 3) as u8 }
}

// ---------------------------------------------------------------------------
// Field attribute (member access + method properties)
// ---------------------------------------------------------------------------

/// Field attribute bitfield (`CV_fldattr_t`) carrying member access level and
/// method properties for class members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FieldAttr(pub u16);

impl FieldAttr {
    /// Access protection (bits 0-1): 1 = private, 2 = protected, 3 = public.
    #[must_use]
    pub const fn access(self) -> u8      { (self.0 & 3) as u8 }
    /// Method properties (bits 2-4): vanilla/virtual/static/friend/intro/purevirt/pureintro.
    #[must_use]
    pub const fn mprop(self) -> u8       { ((self.0 >> 2) & 7) as u8 }
    /// True if this is a compiler-generated function present in the source.
    #[must_use]
    pub const fn is_pseudo(self) -> bool { self.0 & 0x0020 != 0 }
    /// True if the class cannot be inherited from.
    #[must_use]
    pub const fn no_inherit(self) -> bool{ self.0 & 0x0040 != 0 }
    /// True if the class cannot be constructed.
    #[must_use]
    pub const fn no_construct(self) -> bool { self.0 & 0x0080 != 0 }
    /// True if this member is compiler-generated but not present in the source.
    #[must_use]
    pub const fn is_compiler_generated(self) -> bool { self.0 & 0x0100 != 0 }
    /// True if the method is `final` (cannot be overridden).
    #[must_use]
    pub const fn is_sealed(self) -> bool { self.0 & 0x0200 != 0 }
}

// ---------------------------------------------------------------------------
// Pointer attributes
// ---------------------------------------------------------------------------

/// Pointer attribute bitfield from `LF_POINTER` (pointer kind, mode, size and
/// cv-qualifiers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PointerAttr(pub u32);

impl PointerAttr {
    /// Pointer kind (bits 0-4), e.g. near32 = 0x0a, 64-bit = 0x0c.
    #[must_use]
    pub const fn ptr_type(self) -> u8         { (self.0 & 0x1f) as u8 }
    /// Pointer mode (bits 5-7): 0 = plain, 1 = reference, 2 = ptr-to-data-member, 3 = ptr-to-method, 4 = rvalue ref.
    #[must_use]
    pub const fn ptr_mode(self) -> u8         { ((self.0 >> 5) & 7) as u8 }
    /// True for a 0:32 flat pointer.
    #[must_use]
    pub const fn is_flat32(self) -> bool      { self.0 & 0x0100 != 0 }
    /// True if the pointer itself is `volatile`.
    #[must_use]
    pub const fn is_volatile(self) -> bool    { self.0 & 0x0200 != 0 }
    /// True if the pointer itself is `const`.
    #[must_use]
    pub const fn is_const(self) -> bool       { self.0 & 0x0400 != 0 }
    /// True if the pointer is `__unaligned`.
    #[must_use]
    pub const fn is_unaligned(self) -> bool   { self.0 & 0x0800 != 0 }
    /// True if the pointer is `__restrict`.
    #[must_use]
    pub const fn is_restrict(self) -> bool    { self.0 & 0x1000 != 0 }
    /// Pointer size in bytes (bits 13-18).
    #[must_use]
    pub const fn size(self) -> u8             { ((self.0 >> 13) & 0x3f) as u8 }
    /// True for a MoCOM (WinRT/managed) pointer.
    #[must_use]
    pub const fn is_mocom(self) -> bool       { self.0 & 0x0008_0000 != 0 }
    /// True for an lvalue reference (`&`).
    #[must_use]
    pub const fn is_lvalue_ref(self) -> bool  { self.0 & 0x0010_0000 != 0 }
    /// True for an rvalue reference (`&&`).
    #[must_use]
    pub const fn is_rvalue_ref(self) -> bool  { self.0 & 0x0020_0000 != 0 }
}

// ---------------------------------------------------------------------------
// Vtable shape entries
// ---------------------------------------------------------------------------

/// One 4-bit descriptor in an `LF_VTSHAPE` record describing a vtable slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum VtabShapeEntry {
    /// 16-bit near function pointer.
    Near      = 0x00,
    /// 16:16 far function pointer.
    Far       = 0x01,
    /// Thin (address-of-thunk) entry.
    Thin      = 0x02,
    /// Address-point displacement to outermost class.
    Outer     = 0x03,
    /// Far pointer to metaclass descriptor.
    Meta      = 0x04,
    /// 32-bit near function pointer.
    Near32    = 0x05,
    /// 16:32 far function pointer.
    Far32     = 0x06,
    /// Unrecognized slot descriptor.
    Unknown   = 0xff,
}

impl VtabShapeEntry {
    /// Decode one 4-bit vtable-shape descriptor; unknown values map to [`Self::Unknown`].
    #[must_use]
    pub const fn from_nibble(n: u8) -> Self {
        match n & 0xf {
            0x00 => Self::Near,
            0x01 => Self::Far,
            0x02 => Self::Thin,
            0x03 => Self::Outer,
            0x04 => Self::Meta,
            0x05 => Self::Near32,
            0x06 => Self::Far32,
            _    => Self::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// Individual type record structs
// ---------------------------------------------------------------------------

/// `LF_POINTER` (0x1002)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfPointer {
    /// Type index of the pointed-to type.
    pub referent: TypeIndex,
    /// Pointer attribute bitfield (kind, mode, size, cv-qualifiers).
    pub attr: PointerAttr,
    /// For member pointers: the containing class type index.
    pub containing_class: Option<TypeIndex>,
}

/// `LF_ARRAY` (0x1003)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfArray {
    /// Type index of the array element type.
    pub element_type: TypeIndex,
    /// Type index of the indexing type (usually an integer primitive).
    pub index_type: TypeIndex,
    /// Length in bytes (numeric leaf decoded).
    pub length_bytes: u64,
    /// Array type name (often empty).
    pub name: String,
}

/// `LF_CLASS` / `LF_STRUCTURE` (0x1004/0x1005)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfClass {
    /// True if the record was `LF_STRUCTURE`, false for `LF_CLASS`.
    pub is_struct: bool,
    /// Number of elements in the field list.
    pub count: u16,
    /// Type property flags (packed, forward-ref, unique name, ...).
    pub props: CvTypeProps,
    /// Type index of the `LF_FIELDLIST` describing the members.
    pub field_list: TypeIndex,
    /// Type index of the derivation list (usually 0).
    pub derived: TypeIndex,
    /// Type index of the vtable shape (`LF_VTSHAPE`), or 0.
    pub vtable: TypeIndex,
    /// Size of an instance in bytes (numeric leaf decoded).
    pub size: u64,
    /// Class/struct name.
    pub name: String,
    /// Decorated (mangled) unique name, present when `props.has_unique_name()`.
    pub unique_name: Option<String>,
}

/// `LF_UNION` (0x1006)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfUnion {
    /// Number of elements in the field list.
    pub count: u16,
    /// Type property flags (packed, forward-ref, unique name, ...).
    pub props: CvTypeProps,
    /// Type index of the `LF_FIELDLIST` describing the members.
    pub field_list: TypeIndex,
    /// Size of an instance in bytes (numeric leaf decoded).
    pub size: u64,
    /// Union name.
    pub name: String,
    /// Decorated (mangled) unique name, present when `props.has_unique_name()`.
    pub unique_name: Option<String>,
}

/// `LF_ENUM` (0x1007)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfEnum {
    /// Number of enumerators.
    pub count: u16,
    /// Type property flags.
    pub props: CvTypeProps,
    /// Type index of the underlying integer type.
    pub underlying: TypeIndex,
    /// Type index of the `LF_FIELDLIST` holding the `LF_ENUMERATE` entries.
    pub field_list: TypeIndex,
    /// Enum name.
    pub name: String,
    /// Decorated (mangled) unique name, present when `props.has_unique_name()`.
    pub unique_name: Option<String>,
}

/// `LF_PROCEDURE` (0x1008)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfProcedure {
    /// Type index of the return type.
    pub return_type: TypeIndex,
    /// Calling convention.
    pub calling_conv: CallingConvention,
    /// Function attribute byte (cxxreturnudt, ctor, ctorvbase flags).
    pub func_attr: u8,
    /// Number of parameters.
    pub param_count: u16,
    /// Type index of the `LF_ARGLIST` with the parameter types.
    pub arg_list: TypeIndex,
}

/// `LF_MFUNCTION` (0x1009) — member function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMFunction {
    /// Type index of the return type.
    pub return_type: TypeIndex,
    /// Type index of the containing class.
    pub class_type: TypeIndex,
    /// Type index of the `this` pointer type (0 for static methods).
    pub this_type: TypeIndex,
    /// Calling convention.
    pub calling_conv: CallingConvention,
    /// Function attribute byte.
    pub func_attr: u8,
    /// Number of parameters (excluding `this`).
    pub param_count: u16,
    /// Type index of the `LF_ARGLIST` with the parameter types.
    pub arg_list: TypeIndex,
    /// Adjustment added to `this` before the call (multiple inheritance).
    pub this_adjust: i32,
}

/// `LF_VTSHAPE` (0x000a) — virtual function table shape
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfVtShape {
    /// Number of vtable slots described.
    pub count: u16,
    /// Per-slot 4-bit descriptors, decoded.
    pub entries: Vec<VtabShapeEntry>,
}

/// `LF_BITFIELD` (0x1205)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfBitfield {
    /// Type index of the underlying integer type.
    pub underlying: TypeIndex,
    /// Width of the bitfield in bits.
    pub length: u8,
    /// Starting bit position within the underlying type.
    pub position: u8,
}

/// `LF_ARGLIST` (0x1201) — function argument list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfArgList {
    /// Type indices of the argument types, in order.
    pub args: Vec<TypeIndex>,
}

/// One entry in `LF_METHODLIST`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodListEntry {
    /// Field attributes (access level, method properties).
    pub attr: FieldAttr,
    /// Type index of the method's `LF_MFUNCTION`.
    pub method_type: TypeIndex,
    /// `VTable` slot offset (only for virtual methods).
    pub vbase_offset: Option<u32>,
}

/// `LF_METHODLIST` (0x1206)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMethodList {
    /// Overload entries for one method group.
    pub methods: Vec<MethodListEntry>,
}

/// `LF_DIMARRAY` (0x1508) — dimensioned array
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfDimArray {
    /// Type index of the element type.
    pub underlying: TypeIndex,
    /// Type index of the dimension information record.
    pub dim_info: TypeIndex,
    /// Array name.
    pub name: String,
}

/// `LF_PRECOMP` (0x1509) — precompiled type header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfPrecomp {
    /// First type index included from the precompiled types.
    pub start_index: TypeIndex,
    /// Number of type indices included.
    pub count: u32,
    /// Signature used to match the precompiled types.
    pub signature: u32,
    /// Name of the precompiled-header module.
    pub name: String,
}

/// `LF_ALIAS` (0x150a) — type alias (typedef)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfAlias {
    /// Type index of the aliased (underlying) type.
    pub underlying: TypeIndex,
    /// Alias (typedef) name.
    pub name: String,
}

/// `LF_BCLASS` (0x1400) — base class
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfBClass {
    /// Field attributes (access level).
    pub attr: FieldAttr,
    /// Type index of the base class.
    pub base_type: TypeIndex,
    /// Offset of the base class subobject within the derived class.
    pub offset: u64,
}

/// `LF_VBCLASS` / `LF_IVBCLASS` (0x1401/0x1402) — virtual base class
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfVBClass {
    /// True for `LF_IVBCLASS` (indirect virtual base).
    pub is_indirect: bool,
    /// Field attributes (access level).
    pub attr: FieldAttr,
    /// Type index of the virtual base class.
    pub base_type: TypeIndex,
    /// Type index of the virtual base pointer type.
    pub vbptr_type: TypeIndex,
    /// Offset of the virtual base pointer within the class.
    pub vbptr_offset: u64,
    /// Index into the virtual base displacement table.
    pub vtable_index: u64,
}

/// `LF_MEMBER` (0x150d) — data member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMember {
    /// Field attributes (access level).
    pub attr: FieldAttr,
    /// Type index of the member's type.
    pub field_type: TypeIndex,
    /// Byte offset of the member within the containing type.
    pub offset: u64,
    /// Member name.
    pub name: String,
}

/// `LF_STMEMBER` (0x150e) — static data member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfStMember {
    /// Field attributes (access level).
    pub attr: FieldAttr,
    /// Type index of the member's type.
    pub field_type: TypeIndex,
    /// Member name.
    pub name: String,
}

/// `LF_METHOD` (0x150f) — overloaded method group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMethod {
    /// Number of overloads in the method list.
    pub count: u16,
    /// Type index of the `LF_METHODLIST` with the overloads.
    pub method_list: TypeIndex,
    /// Method name.
    pub name: String,
}

/// `LF_NESTTYPE` (0x1510) — nested type definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfNestType {
    /// Type index of the nested type.
    pub nested_type: TypeIndex,
    /// Name of the nested type as seen inside the enclosing class.
    pub name: String,
}

/// `LF_ONEMETHOD` (0x1511) — single non-overloaded method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfOneMethod {
    /// Field attributes (access level, method properties).
    pub attr: FieldAttr,
    /// Type index of the method's `LF_MFUNCTION`.
    pub method_type: TypeIndex,
    /// `VTable` slot offset (only for introducing virtual methods).
    pub vbase_offset: Option<u32>,
    /// Method name.
    pub name: String,
}

/// `LF_ENUMERATE` (0x1502) — enumerator value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfEnumerate {
    /// Field attributes (access level).
    pub attr: FieldAttr,
    /// Enumerator value (signed numeric leaf decoded).
    pub value: i64,
    /// Enumerator name.
    pub name: String,
}

/// `LF_INDEX` (0x1404) — continuation reference in a field list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfIndex {
    /// Type index of the continuation `LF_FIELDLIST`.
    pub next_index: TypeIndex,
}

/// `LF_MODIFIER` (0x1001)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfModifier {
    /// Type index of the type being modified.
    pub modified_type: TypeIndex,
    /// True if the `const` qualifier is applied.
    pub is_const: bool,
    /// True if the `volatile` qualifier is applied.
    pub is_volatile: bool,
    /// True if the `__unaligned` qualifier is applied.
    pub is_unaligned: bool,
}

/// `LF_FUNC_ID` (0x1601)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfFuncId {
    /// ID of the enclosing scope (0 for global scope).
    pub scope_id: TypeIndex,
    /// Type index of the function's `LF_PROCEDURE`.
    pub func_type: TypeIndex,
    /// Function name.
    pub name: String,
}

/// `LF_STRING_ID` (0x1605)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfStringId {
    /// ID of a sub-string list record (0 if none).
    pub id: TypeIndex,
    /// The string value.
    pub value: String,
}

/// `LF_UDT_SRC_LINE` (0x1606)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfUdtSrcLine {
    /// Type index of the UDT this record describes.
    pub udt: TypeIndex,
    /// String ID of the source file name.
    pub src_file: TypeIndex,
    /// 1-based line number of the UDT definition.
    pub line: u32,
}

// ---------------------------------------------------------------------------
// FieldList contents
// ---------------------------------------------------------------------------

/// A parsed field-list member (one entry in `LF_FIELDLIST`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldListEntry {
    /// Direct base class (`LF_BCLASS`).
    BClass(LfBClass),
    /// (Indirect) virtual base class (`LF_VBCLASS`/`LF_IVBCLASS`).
    VBClass(LfVBClass),
    /// Non-static data member (`LF_MEMBER`).
    Member(LfMember),
    /// Static data member (`LF_STMEMBER`).
    StMember(LfStMember),
    /// Overloaded method group (`LF_METHOD`).
    Method(LfMethod),
    /// Nested type definition (`LF_NESTTYPE`).
    NestType(LfNestType),
    /// Single non-overloaded method (`LF_ONEMETHOD`).
    OneMethod(LfOneMethod),
    /// Enumerator (`LF_ENUMERATE`).
    Enumerate(LfEnumerate),
    /// Virtual function table pointer (`LF_VFUNCTAB`); carries the vfptr type index.
    VFuncTab(TypeIndex),
    /// Virtual function table pointer at a non-zero offset (`LF_VFUNCOFF`).
    VFuncOff {
        /// Field attributes.
        attr: FieldAttr,
        /// Byte offset of the vtable pointer within the class.
        offset: u32,
        /// Type index of the vtable pointer type.
        method_type: TypeIndex,
    },
    /// Continuation reference to another field list (`LF_INDEX`).
    Index(LfIndex),
}

/// A fully parsed field list.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LfFieldList {
    /// Parsed field-list entries, in record order.
    pub entries: Vec<FieldListEntry>,
}

// ---------------------------------------------------------------------------
// Top-level type record enum
// ---------------------------------------------------------------------------

/// The union of all parsed `CodeView` type records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeRecord {
    /// `LF_MODIFIER` — cv-qualified type.
    Modifier(LfModifier),
    /// `LF_POINTER` — pointer/reference type.
    Pointer(LfPointer),
    /// `LF_ARRAY` — array type.
    Array(LfArray),
    /// `LF_CLASS` / `LF_STRUCTURE` — class or struct.
    Class(LfClass),
    /// `LF_UNION` — union.
    Union(LfUnion),
    /// `LF_ENUM` — enumeration.
    Enum(LfEnum),
    /// `LF_PROCEDURE` — non-member function type.
    Procedure(LfProcedure),
    /// `LF_MFUNCTION` — member function type.
    MFunction(LfMFunction),
    /// `LF_VTSHAPE` — vtable shape.
    VtShape(LfVtShape),
    /// `LF_BITFIELD` — bitfield member type.
    Bitfield(LfBitfield),
    /// `LF_ARGLIST` — argument type list.
    ArgList(LfArgList),
    /// `LF_FIELDLIST` — member list.
    FieldList(LfFieldList),
    /// `LF_METHODLIST` — method overload list.
    MethodList(LfMethodList),
    /// `LF_DIMARRAY` — dimensioned array.
    DimArray(LfDimArray),
    /// `LF_PRECOMP` — precompiled type header reference.
    Precomp(LfPrecomp),
    /// `LF_ALIAS` — typedef.
    Alias(LfAlias),
    /// `LF_FUNC_ID` — function ID (IPI).
    FuncId(LfFuncId),
    /// `LF_STRING_ID` — string ID (IPI).
    StringId(LfStringId),
    /// `LF_UDT_SRC_LINE` — UDT source location (IPI).
    UdtSrcLine(LfUdtSrcLine),
    /// Unrecognized leaf kind; raw payload preserved.
    Unknown {
        /// The raw `LF_*` leaf kind value.
        kind: u16,
        /// The undecoded record payload.
        data: Vec<u8>,
    },
}

impl TypeRecord {
    /// Returns the human-readable name of this record type.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Modifier(_)   => "LF_MODIFIER",
            Self::Pointer(_)    => "LF_POINTER",
            Self::Array(_)      => "LF_ARRAY",
            Self::Class(c) if c.is_struct => "LF_STRUCTURE",
            Self::Class(_)      => "LF_CLASS",
            Self::Union(_)      => "LF_UNION",
            Self::Enum(_)       => "LF_ENUM",
            Self::Procedure(_)  => "LF_PROCEDURE",
            Self::MFunction(_)  => "LF_MFUNCTION",
            Self::VtShape(_)    => "LF_VTSHAPE",
            Self::Bitfield(_)   => "LF_BITFIELD",
            Self::ArgList(_)    => "LF_ARGLIST",
            Self::FieldList(_)  => "LF_FIELDLIST",
            Self::MethodList(_) => "LF_METHODLIST",
            Self::DimArray(_)   => "LF_DIMARRAY",
            Self::Precomp(_)    => "LF_PRECOMP",
            Self::Alias(_)      => "LF_ALIAS",
            Self::FuncId(_)     => "LF_FUNC_ID",
            Self::StringId(_)   => "LF_STRING_ID",
            Self::UdtSrcLine(_) => "LF_UDT_SRC_LINE",
            Self::Unknown { .. } => "LF_UNKNOWN",
        }
    }
}

// ---------------------------------------------------------------------------
// Type database
// ---------------------------------------------------------------------------

/// A fully parsed TPI/IPI stream containing all type records indexed by `TypeIndex`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TypeDatabase {
    /// Minimum type index (usually 0x1000).
    pub min_index: u32,
    /// All records in order; record at position i has index (`min_index` + i).
    pub records: Vec<TypeRecord>,
    /// Forward-reference resolution map: forward-ref index → definition index.
    pub fwd_ref_map: HashMap<u32, u32>,
}

impl TypeDatabase {
    /// Look up a type record by index, resolving forward references.
    #[must_use]
    pub fn get(&self, idx: TypeIndex) -> Option<&TypeRecord> {
        if idx.is_primitive() {
            return None;
        }
        let pos = idx.0.checked_sub(self.min_index)? as usize;
        let rec = self.records.get(pos)?;
        // Follow forward-reference chain if needed
        if let Some(&def_idx) = self.fwd_ref_map.get(&idx.0) {
            let def_pos = def_idx.checked_sub(self.min_index)? as usize;
            return self.records.get(def_pos);
        }
        Some(rec)
    }

    /// Return the total number of type records.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Return true if the database is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Iterate over all (`TypeIndex`, `TypeRecord`) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (TypeIndex, &TypeRecord)> {
        self.records.iter().enumerate().map(|(i, r)| {
            (TypeIndex(self.min_index + super::casts::usize_to_u32(i)), r)
        })
    }

    /// Build the forward-reference map by scanning all class/union/enum records.
    pub fn build_fwd_ref_map(&mut self) {
        let mut name_to_def: HashMap<String, u32> = HashMap::new();
        // First pass: collect all non-forward-ref UDT definitions
        for (ti, rec) in self.iter() {
            let (name, is_fwd) = match rec {
                TypeRecord::Class(c)  => (Some(c.name.as_str()), c.props.is_forward_ref()),
                TypeRecord::Union(u)  => (Some(u.name.as_str()), u.props.is_forward_ref()),
                TypeRecord::Enum(e)   => (Some(e.name.as_str()), e.props.is_forward_ref()),
                _ => (None, false),
            };
            if let Some(name) = name
                && !is_fwd && !name.is_empty() {
                    name_to_def.insert(name.to_owned(), ti.0);
                }
        }
        // Second pass: match forward refs to definitions
        let mut fwd_map = HashMap::new();
        for (ti, rec) in self.iter() {
            let (name, is_fwd) = match rec {
                TypeRecord::Class(c)  => (Some(c.name.as_str()), c.props.is_forward_ref()),
                TypeRecord::Union(u)  => (Some(u.name.as_str()), u.props.is_forward_ref()),
                TypeRecord::Enum(e)   => (Some(e.name.as_str()), e.props.is_forward_ref()),
                _ => (None, false),
            };
            if let (Some(name), true) = (name, is_fwd)
                && let Some(&def_idx) = name_to_def.get(name) {
                    fwd_map.insert(ti.0, def_idx);
                }
        }
        self.fwd_ref_map = fwd_map;
    }
}

// ---------------------------------------------------------------------------
// Binary reader helpers
// ---------------------------------------------------------------------------

/// Minimal cursor over a byte slice for parsing type records.
pub struct TypeReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> TypeReader<'a> {
    /// Create a reader positioned at the start of `data`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Number of unread bytes remaining.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Current byte position within the buffer.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Peek at the next little-endian u16 without advancing; `None` if fewer than 2 bytes remain.
    #[must_use]
    pub fn peek_u16(&self) -> Option<u16> {
        if self.remaining() < 2 { return None; }
        Some(u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]))
    }

    /// Read one byte and advance.
    ///
    /// # Errors
    /// Returns [`CodeViewError::RecordTooShort`] if no bytes remain.
    pub fn read_u8(&mut self) -> Result<u8, CodeViewError> {
        if self.remaining() < 1 {
            return Err(CodeViewError::RecordTooShort);
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// Read a little-endian u16 and advance.
    ///
    /// # Errors
    /// Returns [`CodeViewError::RecordTooShort`] if fewer than 2 bytes remain.
    pub fn read_u16(&mut self) -> Result<u16, CodeViewError> {
        if self.remaining() < 2 {
            return Err(CodeViewError::RecordTooShort);
        }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// Read a little-endian u32 and advance.
    ///
    /// # Errors
    /// Returns [`CodeViewError::RecordTooShort`] if fewer than 4 bytes remain.
    pub fn read_u32(&mut self) -> Result<u32, CodeViewError> {
        if self.remaining() < 4 {
            return Err(CodeViewError::RecordTooShort);
        }
        let v = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    /// Read a little-endian i32 and advance.
    ///
    /// # Errors
    /// Returns [`CodeViewError::RecordTooShort`] if fewer than 4 bytes remain.
    pub fn read_i32(&mut self) -> Result<i32, CodeViewError> {
        self.read_u32().map(super::casts::u32_as_i32)
    }

    /// Read a little-endian u64 and advance.
    ///
    /// # Errors
    /// Returns [`CodeViewError::RecordTooShort`] if fewer than 8 bytes remain.
    pub fn read_u64(&mut self) -> Result<u64, CodeViewError> {
        if self.remaining() < 8 {
            return Err(CodeViewError::RecordTooShort);
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(buf))
    }

    /// Read a 32-bit [`TypeIndex`] and advance.
    ///
    /// # Errors
    /// Returns [`CodeViewError::RecordTooShort`] if fewer than 4 bytes remain.
    pub fn read_type_index(&mut self) -> Result<TypeIndex, CodeViewError> {
        self.read_u32().map(TypeIndex)
    }

    /// Read a null-terminated C string.
    ///
    /// # Errors
    /// Returns [`CodeViewError::Parse`] if the string is not terminated within
    /// the remaining buffer.
    pub fn read_cstring(&mut self) -> Result<String, CodeViewError> {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        if self.pos >= self.data.len() {
            return Err(CodeViewError::Parse("unterminated string".into()));
        }
        let s = std::str::from_utf8(&self.data[start..self.pos])
            .unwrap_or("<invalid utf8>")
            .to_owned();
        self.pos += 1; // consume null
        Ok(s)
    }

    /// Read the variable-length numeric leaf and return the value as u64.
    ///
    /// # Errors
    /// Returns [`CodeViewError::Parse`] for unknown leaf tags or
    /// [`CodeViewError::RecordTooShort`] when the buffer is exhausted.
    pub fn read_numeric_leaf(&mut self) -> Result<u64, CodeViewError> {
        let leaf = self.read_u16()?;
        if leaf < 0x8000 {
            // immediate value encoded in the leaf itself
            return Ok(u64::from(leaf));
        }
        match leaf {
            lf::LF_CHAR      => Ok(u64::from(self.read_u8()?)),
            lf::LF_SHORT     => Ok(super::casts::i16_sext_u64(super::casts::u16_as_i16(self.read_u16()?))),
            lf::LF_USHORT    => Ok(u64::from(self.read_u16()?)),
            lf::LF_LONG      => Ok(super::casts::i32_sext_u64(super::casts::u32_as_i32(self.read_u32()?))),
            lf::LF_ULONG     => Ok(u64::from(self.read_u32()?)),
            lf::LF_QUADWORD | lf::LF_UQUADWORD => Ok(self.read_u64()?),
            lf::LF_REAL32    => {
                let bits = self.read_u32()?;
                Ok(super::casts::f32_to_u64_sat(f32::from_bits(bits)))
            }
            lf::LF_REAL64    => {
                let bits = self.read_u64()?;
                Ok(super::casts::f64_to_u64_sat(f64::from_bits(bits)))
            }
            other => Err(CodeViewError::Parse(format!("unknown numeric leaf {other:#06x}"))),
        }
    }

    /// Read numeric leaf as signed i64.
    ///
    /// # Errors
    /// Returns [`CodeViewError::Parse`] for unknown leaf tags or
    /// [`CodeViewError::RecordTooShort`] when the buffer is exhausted.
    pub fn read_numeric_leaf_signed(&mut self) -> Result<i64, CodeViewError> {
        let leaf = self.peek_u16().ok_or(CodeViewError::RecordTooShort)?;
        if leaf < 0x8000 {
            self.pos += 2;
            return Ok(i64::from(leaf));
        }
        match self.read_u16()? {
            lf::LF_CHAR      => Ok(i64::from(super::casts::u8_as_i8(self.read_u8()?))),
            lf::LF_SHORT     => Ok(i64::from(super::casts::u16_as_i16(self.read_u16()?))),
            lf::LF_USHORT    => Ok(i64::from(self.read_u16()?)),
            // Split, not shared: `LF_ULONG` is unsigned, so sign-extending it
            // turns any value with the top bit set negative. `read_numeric_leaf`
            // above already keeps the two apart — this arm was the odd one out.
            lf::LF_LONG      => Ok(i64::from(super::casts::u32_as_i32(self.read_u32()?))),
            lf::LF_ULONG     => Ok(i64::from(self.read_u32()?)),
            lf::LF_QUADWORD | lf::LF_UQUADWORD => Ok(super::casts::u64_as_i64(self.read_u64()?)),
            other => Err(CodeViewError::Parse(format!("unknown numeric leaf {other:#06x}"))),
        }
    }

    /// Align the current position to a 4-byte boundary.
    pub const fn align4(&mut self) {
        let rem = self.pos % 4;
        if rem != 0 {
            self.pos += 4 - rem;
        }
    }

    /// Consume all remaining bytes.
    pub fn consume_rest(&mut self) -> &'a [u8] {
        let rest = &self.data[self.pos..];
        self.pos = self.data.len();
        rest
    }
}

// ---------------------------------------------------------------------------
// Field list parser
// ---------------------------------------------------------------------------

fn parse_field_list(data: &[u8]) -> Result<LfFieldList, CodeViewError> {
    let mut r = TypeReader::new(data);
    let mut entries = Vec::new();

    while r.remaining() > 1 {
        let kind = r.read_u16()?;
        let entry = match kind {
            lf::LF_BCLASS => {
                let attr = FieldAttr(r.read_u16()?);
                let base_type = r.read_type_index()?;
                let offset = r.read_numeric_leaf()?;
                r.align4();
                FieldListEntry::BClass(LfBClass { attr, base_type, offset })
            }
            lf::LF_VBCLASS | lf::LF_IVBCLASS => {
                let is_indirect = kind == lf::LF_IVBCLASS;
                let attr = FieldAttr(r.read_u16()?);
                let base_type = r.read_type_index()?;
                let vbptr_type = r.read_type_index()?;
                let vbptr_offset = r.read_numeric_leaf()?;
                let vtable_index = r.read_numeric_leaf()?;
                r.align4();
                FieldListEntry::VBClass(LfVBClass {
                    is_indirect, attr, base_type, vbptr_type, vbptr_offset, vtable_index,
                })
            }
            lf::LF_MEMBER => {
                let attr = FieldAttr(r.read_u16()?);
                let field_type = r.read_type_index()?;
                let offset = r.read_numeric_leaf()?;
                let name = r.read_cstring()?;
                r.align4();
                FieldListEntry::Member(LfMember { attr, field_type, offset, name })
            }
            lf::LF_STMEMBER => {
                let attr = FieldAttr(r.read_u16()?);
                let field_type = r.read_type_index()?;
                let name = r.read_cstring()?;
                r.align4();
                FieldListEntry::StMember(LfStMember { attr, field_type, name })
            }
            lf::LF_METHOD => {
                let count = r.read_u16()?;
                let method_list = r.read_type_index()?;
                let name = r.read_cstring()?;
                r.align4();
                FieldListEntry::Method(LfMethod { count, method_list, name })
            }
            lf::LF_NESTTYPE => {
                let _reserved = r.read_u16()?;
                let nested_type = r.read_type_index()?;
                let name = r.read_cstring()?;
                r.align4();
                FieldListEntry::NestType(LfNestType { nested_type, name })
            }
            lf::LF_ONEMETHOD => {
                let attr = FieldAttr(r.read_u16()?);
                let method_type = r.read_type_index()?;
                let mprop = attr.mprop();
                let vbase_offset = if mprop == 4 || mprop == 6 {
                    Some(r.read_u32()?)
                } else {
                    None
                };
                let name = r.read_cstring()?;
                r.align4();
                FieldListEntry::OneMethod(LfOneMethod { attr, method_type, vbase_offset, name })
            }
            lf::LF_ENUMERATE => {
                let attr = FieldAttr(r.read_u16()?);
                let value = r.read_numeric_leaf_signed()?;
                let name = r.read_cstring()?;
                r.align4();
                FieldListEntry::Enumerate(LfEnumerate { attr, value, name })
            }
            lf::LF_VFUNCTAB => {
                let _pad = r.read_u16()?;
                let vfptr_type = r.read_type_index()?;
                FieldListEntry::VFuncTab(vfptr_type)
            }
            lf::LF_VFUNCOFF => {
                let attr = FieldAttr(r.read_u16()?);
                let offset = r.read_u32()?;
                let method_type = r.read_type_index()?;
                FieldListEntry::VFuncOff { attr, offset, method_type }
            }
            lf::LF_INDEX => {
                let _pad = r.read_u16()?;
                let next_index = r.read_type_index()?;
                FieldListEntry::Index(LfIndex { next_index })
            }
            _ => {
                // Unknown field list entry; skip rest to avoid corruption
                break;
            }
        };
        entries.push(entry);
    }

    Ok(LfFieldList { entries })
}

// ---------------------------------------------------------------------------
// Main type record parser
// ---------------------------------------------------------------------------

fn parse_modifier_leaf(r: &mut TypeReader<'_>) -> Result<TypeRecord, CodeViewError> {
    let modified_type = r.read_type_index()?;
    let flags = r.read_u16()?;
    Ok(TypeRecord::Modifier(LfModifier {
        modified_type,
        is_const:     flags & 1 != 0,
        is_volatile:  flags & 2 != 0,
        is_unaligned: flags & 4 != 0,
    }))
}

fn parse_pointer_leaf(r: &mut TypeReader<'_>) -> Result<TypeRecord, CodeViewError> {
    let referent = r.read_type_index()?;
    let attr = PointerAttr(r.read_u32()?);
    let containing_class = if attr.ptr_mode() == 2 || attr.ptr_mode() == 3 {
        Some(r.read_type_index()?)
    } else {
        None
    };
    Ok(TypeRecord::Pointer(LfPointer { referent, attr, containing_class }))
}

fn parse_array_leaf(r: &mut TypeReader<'_>) -> Result<TypeRecord, CodeViewError> {
    let element_type = r.read_type_index()?;
    let index_type   = r.read_type_index()?;
    let length_bytes = r.read_numeric_leaf()?;
    let name         = r.read_cstring()?;
    Ok(TypeRecord::Array(LfArray { element_type, index_type, length_bytes, name }))
}

fn parse_class_leaf(r: &mut TypeReader<'_>, is_struct: bool) -> Result<TypeRecord, CodeViewError> {
    let count      = r.read_u16()?;
    let props      = CvTypeProps(r.read_u16()?);
    let field_list = r.read_type_index()?;
    let derived    = r.read_type_index()?;
    let vtable     = r.read_type_index()?;
    let size       = r.read_numeric_leaf()?;
    let name       = r.read_cstring()?;
    let unique_name = if props.has_unique_name() {
        Some(r.read_cstring()?)
    } else {
        None
    };
    Ok(TypeRecord::Class(LfClass {
        is_struct, count, props, field_list, derived, vtable, size, name, unique_name,
    }))
}

fn parse_union_leaf(r: &mut TypeReader<'_>) -> Result<TypeRecord, CodeViewError> {
    let count      = r.read_u16()?;
    let props      = CvTypeProps(r.read_u16()?);
    let field_list = r.read_type_index()?;
    let size       = r.read_numeric_leaf()?;
    let name       = r.read_cstring()?;
    let unique_name = if props.has_unique_name() {
        Some(r.read_cstring()?)
    } else {
        None
    };
    Ok(TypeRecord::Union(LfUnion { count, props, field_list, size, name, unique_name }))
}

fn parse_enum_leaf(r: &mut TypeReader<'_>) -> Result<TypeRecord, CodeViewError> {
    let count      = r.read_u16()?;
    let props      = CvTypeProps(r.read_u16()?);
    let underlying = r.read_type_index()?;
    let field_list = r.read_type_index()?;
    let name       = r.read_cstring()?;
    let unique_name = if props.has_unique_name() {
        Some(r.read_cstring()?)
    } else {
        None
    };
    Ok(TypeRecord::Enum(LfEnum { count, props, underlying, field_list, name, unique_name }))
}

fn parse_procedure_leaf(r: &mut TypeReader<'_>) -> Result<TypeRecord, CodeViewError> {
    let return_type  = r.read_type_index()?;
    let calling_conv = CallingConvention::from_u8(r.read_u8()?);
    let func_attr    = r.read_u8()?;
    let param_count  = r.read_u16()?;
    let arg_list     = r.read_type_index()?;
    Ok(TypeRecord::Procedure(LfProcedure { return_type, calling_conv, func_attr, param_count, arg_list }))
}

fn parse_mfunction_leaf(r: &mut TypeReader<'_>) -> Result<TypeRecord, CodeViewError> {
    let return_type  = r.read_type_index()?;
    let class_type   = r.read_type_index()?;
    let this_type    = r.read_type_index()?;
    let calling_conv = CallingConvention::from_u8(r.read_u8()?);
    let func_attr    = r.read_u8()?;
    let param_count  = r.read_u16()?;
    let arg_list     = r.read_type_index()?;
    let this_adjust  = r.read_i32()?;
    Ok(TypeRecord::MFunction(LfMFunction {
        return_type, class_type, this_type, calling_conv, func_attr,
        param_count, arg_list, this_adjust,
    }))
}

fn parse_vtshape_leaf(r: &mut TypeReader<'_>) -> Result<TypeRecord, CodeViewError> {
    let count = r.read_u16()?;
    let mut entries = Vec::with_capacity(count as usize);
    // Each byte encodes two entries (4 bits each)
    let bytes_needed = (count as usize).div_ceil(2);
    for _ in 0..bytes_needed {
        let b = r.read_u8()?;
        entries.push(VtabShapeEntry::from_nibble(b & 0xf));
        if entries.len() < count as usize {
            entries.push(VtabShapeEntry::from_nibble((b >> 4) & 0xf));
        }
    }
    Ok(TypeRecord::VtShape(LfVtShape { count, entries }))
}

/// Parse a single type record from the given byte slice (does not include the
/// 2-byte `length` prefix; the caller already stripped it).
///
/// # Errors
/// Returns [`CodeViewError::RecordTooShort`] when the buffer is shorter than
/// the leaf-specific header, or [`CodeViewError::Parse`] for malformed
/// numeric leaves and strings.
pub fn parse_type_record(data: &[u8]) -> Result<TypeRecord, CodeViewError> {
    if data.len() < 2 {
        return Err(CodeViewError::RecordTooShort);
    }
    let kind = u16::from_le_bytes([data[0], data[1]]);
    let mut r = TypeReader::new(&data[2..]);

    let rec = match kind {
        lf::LF_MODIFIER => parse_modifier_leaf(&mut r)?,
        lf::LF_POINTER => parse_pointer_leaf(&mut r)?,
        lf::LF_ARRAY => parse_array_leaf(&mut r)?,
        lf::LF_CLASS | lf::LF_STRUCTURE => parse_class_leaf(&mut r, kind == lf::LF_STRUCTURE)?,
        lf::LF_UNION => parse_union_leaf(&mut r)?,
        lf::LF_ENUM => parse_enum_leaf(&mut r)?,
        lf::LF_PROCEDURE => parse_procedure_leaf(&mut r)?,
        lf::LF_MFUNCTION => parse_mfunction_leaf(&mut r)?,
        lf::LF_VTSHAPE => parse_vtshape_leaf(&mut r)?,
        lf::LF_BITFIELD => {
            let underlying = r.read_type_index()?;
            let length     = r.read_u8()?;
            let position   = r.read_u8()?;
            TypeRecord::Bitfield(LfBitfield { underlying, length, position })
        }
        lf::LF_ARGLIST => {
            let count = r.read_u32()?;
            // `count` is a raw, untrusted u32 (up to ~4.29B) straight from
            // the record — feeding it into `Vec::with_capacity` directly
            // would let a corrupted/adversarial record request a huge
            // allocation before a single element is actually read. Cap by
            // what the remaining buffer could possibly hold (4 bytes per
            // type index); the read loop below still exits via `?` on the
            // real, likely-smaller count if data runs out first.
            let max_possible = r.remaining() / 4;
            let mut args = Vec::with_capacity((count as usize).min(max_possible));
            for _ in 0..count {
                args.push(r.read_type_index()?);
            }
            TypeRecord::ArgList(LfArgList { args })
        }
        lf::LF_FIELDLIST => {
            let fl = parse_field_list(r.consume_rest())?;
            TypeRecord::FieldList(fl)
        }
        lf::LF_METHODLIST => {
            let mut methods = Vec::new();
            while r.remaining() >= 6 {
                let attr        = FieldAttr(r.read_u16()?);
                let _pad        = r.read_u16()?;
                let method_type = r.read_type_index()?;
                let mprop = attr.mprop();
                let vbase_offset = if mprop == 4 || mprop == 6 {
                    Some(r.read_u32()?)
                } else {
                    None
                };
                methods.push(MethodListEntry { attr, method_type, vbase_offset });
            }
            TypeRecord::MethodList(LfMethodList { methods })
        }
        lf::LF_DIMARRAY => {
            let underlying = r.read_type_index()?;
            let dim_info   = r.read_type_index()?;
            let name       = r.read_cstring()?;
            TypeRecord::DimArray(LfDimArray { underlying, dim_info, name })
        }
        lf::LF_PRECOMP => {
            let start_index = TypeIndex(r.read_u32()?);
            let count       = r.read_u32()?;
            let signature   = r.read_u32()?;
            let name        = r.read_cstring()?;
            TypeRecord::Precomp(LfPrecomp { start_index, count, signature, name })
        }
        lf::LF_ALIAS => {
            let underlying = r.read_type_index()?;
            let name       = r.read_cstring()?;
            TypeRecord::Alias(LfAlias { underlying, name })
        }
        lf::LF_FUNC_ID => {
            let scope_id   = r.read_type_index()?;
            let func_type  = r.read_type_index()?;
            let name       = r.read_cstring()?;
            TypeRecord::FuncId(LfFuncId { scope_id, func_type, name })
        }
        lf::LF_STRING_ID => {
            let id    = r.read_type_index()?;
            let value = r.read_cstring()?;
            TypeRecord::StringId(LfStringId { id, value })
        }
        lf::LF_UDT_SRC_LINE => {
            let udt      = r.read_type_index()?;
            let src_file = r.read_type_index()?;
            let line     = r.read_u32()?;
            TypeRecord::UdtSrcLine(LfUdtSrcLine { udt, src_file, line })
        }
        _ => {
            TypeRecord::Unknown { kind, data: r.consume_rest().to_vec() }
        }
    };
    Ok(rec)
}

// ---------------------------------------------------------------------------
// Stream parser
// ---------------------------------------------------------------------------

/// Parse an entire TPI/IPI stream into a [`TypeDatabase`].
///
/// The stream begins with a 56-byte header (which the caller may have already
/// stripped), or we can detect the header by the version field.
///
/// # Errors
/// Returns [`CodeViewError::RecordTooShort`] when the buffer is shorter than
/// the declared header.
pub fn parse_type_stream(data: &[u8]) -> Result<TypeDatabase, CodeViewError> {
    if data.len() < 8 {
        return Err(CodeViewError::RecordTooShort);
    }

    // TPI stream header v80: version(4) + header_size(4) + min_index(4) + max_index(4) + ...
    let version    = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let header_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    if version != 0x0131_ca0b && version != 0x0131_ca0c {
        // Unknown TPI version — try to parse as raw records
        return parse_raw_type_records(data, 0x1000);
    }
    if data.len() < header_size {
        return Err(CodeViewError::RecordTooShort);
    }
    let min_index = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let _max_index = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let records_data = &data[header_size..];
    parse_raw_type_records(records_data, min_index)
}

fn parse_raw_type_records(data: &[u8], min_index: u32) -> Result<TypeDatabase, CodeViewError> {
    let mut pos = 0;
    let mut records = Vec::new();

    while pos + 2 <= data.len() {
        let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if len < 2 {
            break;
        }
        if pos + len > data.len() {
            return Err(CodeViewError::RecordTooShort);
        }
        let rec_data = &data[pos..pos + len];
        pos += len;
        // Align to 4-byte boundary
        let aligned = (pos + 3) & !3;
        pos = aligned.min(data.len());

        match parse_type_record(rec_data) {
            Ok(rec) => records.push(rec),
            Err(_) => {
                // Store as unknown to preserve index numbering
                records.push(TypeRecord::Unknown {
                    kind: if rec_data.len() >= 2 {
                        u16::from_le_bytes([rec_data[0], rec_data[1]])
                    } else {
                        0
                    },
                    data: rec_data.to_vec(),
                });
            }
        }
    }

    let mut db = TypeDatabase { min_index, records, fwd_ref_map: HashMap::new() };
    db.build_fwd_ref_map();
    Ok(db)
}

// ---------------------------------------------------------------------------
// Pretty-printer
// ---------------------------------------------------------------------------

/// Format a type record as a human-readable string (C-like syntax).
#[must_use]
pub fn format_type(db: &TypeDatabase, idx: TypeIndex, name: Option<&str>) -> String {
    if idx.is_primitive() {
        return format_primitive(idx);
    }
    db.get(idx).map_or_else(
        || format!("<unknown T#{:#x}>", idx.0),
        |rec| format_record(db, rec, name),
    )
}

fn format_primitive(idx: TypeIndex) -> String {
    match idx.0 {
        0x0000 => "void".into(),
        0x0003 => "void*".into(),
        0x0008 | 0x0074 => "__int8".into(),
        0x0010 | 0x0070 => "char".into(),
        0x0020 => "unsigned char".into(),
        0x0068 => "char8_t".into(),
        0x0071 => "wchar_t".into(),
        0x0072 => "char16_t".into(),
        0x0073 => "char32_t".into(),
        0x0075 => "unsigned __int8".into(),
        0x0076 => "short".into(),
        0x0077 => "unsigned short".into(),
        0x0078 => "long".into(),
        0x0079 => "unsigned long".into(),
        0x007a => "__int64".into(),
        0x007b => "unsigned __int64".into(),
        0x007c => "__int128".into(),
        0x007d => "unsigned __int128".into(),
        0x0040 => "float".into(),
        0x0041 => "double".into(),
        0x0042 => "long double".into(),
        0x0030 => "bool".into(),
        _ => format!("<prim {:#06x}>", idx.0),
    }
}

fn format_record(db: &TypeDatabase, rec: &TypeRecord, name: Option<&str>) -> String {
    let n = name.unwrap_or("");
    match rec {
        TypeRecord::Pointer(p) => {
            let inner = format_type(db, p.referent, None);
            if p.attr.is_const() {
                format!("const {inner}* {n}")
            } else {
                format!("{inner}* {n}")
            }
        }
        TypeRecord::Array(a) => {
            let elem = format_type(db, a.element_type, None);
            format!("{} {}[{}]", elem, n, a.length_bytes)
        }
        TypeRecord::Class(c) => {
            let kw = if c.is_struct { "struct" } else { "class" };
            if c.props.is_forward_ref() {
                format!("{} {}", kw, c.name)
            } else {
                format!("{} {} /* {} bytes */", kw, c.name, c.size)
            }
        }
        TypeRecord::Union(u) => {
            if u.props.is_forward_ref() {
                format!("union {}", u.name)
            } else {
                format!("union {} /* {} bytes */", u.name, u.size)
            }
        }
        TypeRecord::Enum(e) => format!("enum {}", e.name),
        TypeRecord::Procedure(p) => {
            let ret = format_type(db, p.return_type, None);
            format!("{} (*)() /* {} params */", ret, p.param_count)
        }
        TypeRecord::Bitfield(b) => {
            let base = format_type(db, b.underlying, None);
            format!("{} {}:{}", base, n, b.length)
        }
        TypeRecord::Alias(a) => {
            let base = format_type(db, a.underlying, None);
            format!("typedef {} {}", base, a.name)
        }
        TypeRecord::Modifier(m) => {
            let base = format_type(db, m.modified_type, None);
            let mut quals = String::new();
            if m.is_const     { quals.push_str("const "); }
            if m.is_volatile  { quals.push_str("volatile "); }
            if m.is_unaligned { quals.push_str("__unaligned "); }
            format!("{quals}{base}")
        }
        _ => rec.kind_name().to_owned(),
    }
}

#[cfg(test)]
mod numeric_leaf_tests {
    use super::*;

    /// `LF_ULONG` is UNSIGNED: it must not be sign-extended.
    ///
    /// `read_numeric_leaf` (the u64 twin, right above) handles the two tags
    /// separately — `LF_LONG` sign-extended, `LF_ULONG` zero-extended. The
    /// signed reader collapsed them into one arm, `LF_LONG | LF_ULONG =>
    /// u32_as_i32(..)`, so an unsigned value with the top bit set came back
    /// negative.
    ///
    /// This reader supplies the value of `LF_ENUMERATE`, i.e. enum constants.
    /// High bitmasks are exactly where this bites: `0x8000_0000` read as
    /// -2147483648 and `0xFFFF_FFFF` as -1. Both are values a debugger prints
    /// next to a name, so the number is simply wrong on screen.
    #[test]
    fn an_unsigned_long_numeric_leaf_is_not_sign_extended() {
        fn signed_leaf(tag: u16, payload: &[u8]) -> i64 {
            let mut data = tag.to_le_bytes().to_vec();
            data.extend_from_slice(payload);
            TypeReader::new(&data).read_numeric_leaf_signed().expect("leaf parses")
        }

        // LF_ULONG: unsigned, so the full 32-bit range stays positive.
        assert_eq!(signed_leaf(lf::LF_ULONG, &0x8000_0000u32.to_le_bytes()), 2_147_483_648);
        assert_eq!(signed_leaf(lf::LF_ULONG, &0xFFFF_FFFFu32.to_le_bytes()), 4_294_967_295);
        assert_eq!(signed_leaf(lf::LF_ULONG, &7u32.to_le_bytes()), 7);

        // LF_LONG: signed, and must KEEP sign-extending — the fix must not
        // simply swap one wrong answer for another.
        assert_eq!(signed_leaf(lf::LF_LONG, &0xFFFF_FFFFu32.to_le_bytes()), -1);
        assert_eq!(signed_leaf(lf::LF_LONG, &0x8000_0000u32.to_le_bytes()), -2_147_483_648);

        // The narrower signed/unsigned pairs were already distinct; pin them
        // so the same collapse cannot be reintroduced one size down.
        assert_eq!(signed_leaf(lf::LF_SHORT, &0xFFFFu16.to_le_bytes()), -1);
        assert_eq!(signed_leaf(lf::LF_USHORT, &0xFFFFu16.to_le_bytes()), 65_535);
        assert_eq!(signed_leaf(lf::LF_CHAR, &[0xFF]), -1);

        // Values below 0x8000 are the leaf itself, not a tag.
        assert_eq!(signed_leaf(0x7FFF, &[]), 0x7FFF);
        assert_eq!(signed_leaf(0, &[]), 0);
    }

    /// The two readers must agree wherever both can represent the answer.
    ///
    /// They are two implementations of one encoding, which is the shape that
    /// hid this defect: the unsigned one was right and the signed one wrong,
    /// and nothing compared them.
    #[test]
    fn the_signed_and_unsigned_leaf_readers_agree_on_non_negative_values() {
        for (tag, payload) in [
            (lf::LF_USHORT, vec![0xFF, 0xFF]),
            (lf::LF_ULONG, 0x8000_0000u32.to_le_bytes().to_vec()),
            (lf::LF_ULONG, 0xFFFF_FFFFu32.to_le_bytes().to_vec()),
            (lf::LF_ULONG, 42u32.to_le_bytes().to_vec()),
        ] {
            let mut data = tag.to_le_bytes().to_vec();
            data.extend_from_slice(&payload);
            let unsigned = TypeReader::new(&data).read_numeric_leaf().expect("leaf parses");
            let signed = TypeReader::new(&data).read_numeric_leaf_signed().expect("leaf parses");
            assert_eq!(
                i64::try_from(unsigned).expect("fits in i64"),
                signed,
                "the two readers disagree on tag {tag:#06x}"
            );
        }
    }
}

#[cfg(test)]
mod arglist_allocation_tests {
    use super::*;

    #[test]
    fn parse_arglist_with_huge_declared_count_does_not_over_allocate() {
        // `count` claims ~4.29B entries but the record body only has room
        // for 2 real ones — before the fix, `Vec::with_capacity(count as
        // usize)` would attempt a ~17GB up-front allocation for a
        // corrupted/adversarial record. `parse_type_record` strips the
        // leading 2-byte `kind`, so `data` here is just the LF_ARGLIST body:
        // [count:u32][type_index * count].
        let mut data = vec![0u8; 2 + 4 + 8];
        data[0..2].copy_from_slice(&lf::LF_ARGLIST.to_le_bytes());
        data[2..6].copy_from_slice(&u32::MAX.to_le_bytes());
        data[6..10].copy_from_slice(&0x74u32.to_le_bytes());
        data[10..14].copy_from_slice(&0x75u32.to_le_bytes());
        // The real count (u32::MAX) exceeds what's available, so the read
        // loop legitimately errors out once the buffer is exhausted — the
        // point of this test is that we get here at all without an abort
        // from an oversized allocation attempt.
        let result = parse_type_record(&data);
        assert!(result.is_err(), "expected a graceful TruncatedStream/RecordTooShort error, not a panic/abort");
    }
}
