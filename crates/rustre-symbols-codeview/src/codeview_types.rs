//! Full `CodeView` type record parser — LF_* records from TPI/IPI streams.
//!
//! Supports all major `CodeView` 4.x / 7.0 / CV8 type leaf kinds needed for
//! complete type reconstruction from PDB type streams.

use crate::CodeViewError;
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

#[allow(non_upper_case_globals)]
pub mod lf {
    pub const LF_MODIFIER:    u16 = 0x1001;
    pub const LF_POINTER:     u16 = 0x1002;
    pub const LF_ARRAY:       u16 = 0x1003;
    pub const LF_CLASS:       u16 = 0x1004;
    pub const LF_STRUCTURE:   u16 = 0x1005;
    pub const LF_UNION:       u16 = 0x1006;
    pub const LF_ENUM:        u16 = 0x1007;
    pub const LF_PROCEDURE:   u16 = 0x1008;
    pub const LF_MFUNCTION:   u16 = 0x1009;
    pub const LF_VTSHAPE:     u16 = 0x000a;
    pub const LF_BITFIELD:    u16 = 0x1205;
    pub const LF_FIELDLIST:   u16 = 0x1203;
    pub const LF_ARGLIST:     u16 = 0x1201;
    pub const LF_METHODLIST:  u16 = 0x1206;
    pub const LF_DIMARRAY:    u16 = 0x1508;
    pub const LF_PRECOMP:     u16 = 0x1509;
    pub const LF_ALIAS:       u16 = 0x150a;
    pub const LF_BCLASS:      u16 = 0x1400;
    pub const LF_VBCLASS:     u16 = 0x1401;
    pub const LF_IVBCLASS:    u16 = 0x1402;
    pub const LF_MEMBER:      u16 = 0x150d;
    pub const LF_STMEMBER:    u16 = 0x150e;
    pub const LF_METHOD:      u16 = 0x150f;
    pub const LF_NESTTYPE:    u16 = 0x1510;
    pub const LF_ONEMETHOD:   u16 = 0x1511;
    pub const LF_ENUMERATE:   u16 = 0x1502;
    pub const LF_INDEX:       u16 = 0x1404;
    pub const LF_VFUNCTAB:    u16 = 0x1409;
    pub const LF_VFUNCOFF:    u16 = 0x140b;
    pub const LF_TYPESERVER2: u16 = 0x1515;
    pub const LF_FUNC_ID:     u16 = 0x1601;
    pub const LF_MFUNC_ID:    u16 = 0x1602;
    pub const LF_BUILDINFO:   u16 = 0x1603;
    pub const LF_STRING_ID:   u16 = 0x1605;
    pub const LF_UDT_SRC_LINE: u16 = 0x1606;
    // numeric leaves
    pub const LF_CHAR:        u16 = 0x8000;
    pub const LF_SHORT:       u16 = 0x8001;
    pub const LF_USHORT:      u16 = 0x8002;
    pub const LF_LONG:        u16 = 0x8003;
    pub const LF_ULONG:       u16 = 0x8004;
    pub const LF_REAL32:      u16 = 0x8005;
    pub const LF_REAL64:      u16 = 0x8006;
    pub const LF_QUADWORD:    u16 = 0x8009;
    pub const LF_UQUADWORD:   u16 = 0x800a;
}

// ---------------------------------------------------------------------------
// Calling convention
// ---------------------------------------------------------------------------

/// Calling convention codes used in `LF_PROCEDURE` / `LF_MFUNCTION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CallingConvention {
    NearC       = 0x00,
    FarC        = 0x01,
    NearPascal  = 0x02,
    FarPascal   = 0x03,
    NearFastcall= 0x04,
    FarFastcall = 0x05,
    NearStdcall = 0x07,
    FarStdcall  = 0x08,
    NearSyscall = 0x09,
    FarSyscall  = 0x0a,
    Thiscall    = 0x0b,
    NearMsfastcall = 0x0c,
    FarMsfastcall  = 0x0d,
    NearClrcall    = 0x16,
    Unknown     = 0xff,
}

impl CallingConvention {
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
    #[must_use] 
    pub const fn is_packed(self)          -> bool { self.0 & 0x0001 != 0 }
    #[must_use] 
    pub const fn has_constructor(self)    -> bool { self.0 & 0x0002 != 0 }
    #[must_use] 
    pub const fn has_overloaded_ops(self) -> bool { self.0 & 0x0004 != 0 }
    #[must_use] 
    pub const fn is_nested(self)          -> bool { self.0 & 0x0008 != 0 }
    #[must_use] 
    pub const fn contains_nested(self)    -> bool { self.0 & 0x0010 != 0 }
    #[must_use] 
    pub const fn has_overloaded_assign(self) -> bool { self.0 & 0x0020 != 0 }
    #[must_use] 
    pub const fn has_cast_ops(self)       -> bool { self.0 & 0x0040 != 0 }
    #[must_use] 
    pub const fn is_forward_ref(self)     -> bool { self.0 & 0x0080 != 0 }
    #[must_use] 
    pub const fn is_scoped(self)          -> bool { self.0 & 0x0100 != 0 }
    #[must_use] 
    pub const fn has_unique_name(self)    -> bool { self.0 & 0x0200 != 0 }
    #[must_use] 
    pub const fn is_sealed(self)          -> bool { self.0 & 0x0400 != 0 }
    #[must_use] 
    pub const fn hfa(self)                -> u8   { ((self.0 >> 11) & 3) as u8 }
    #[must_use] 
    pub const fn is_intrinsic(self)       -> bool { self.0 & 0x2000 != 0 }
    #[must_use] 
    pub const fn mocom(self)              -> u8   { ((self.0 >> 14) & 3) as u8 }
}

// ---------------------------------------------------------------------------
// Field attribute (member access + method properties)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FieldAttr(pub u16);

impl FieldAttr {
    #[must_use] 
    pub const fn access(self) -> u8      { (self.0 & 3) as u8 }
    #[must_use] 
    pub const fn mprop(self) -> u8       { ((self.0 >> 2) & 7) as u8 }
    #[must_use] 
    pub const fn is_pseudo(self) -> bool { self.0 & 0x0020 != 0 }
    #[must_use] 
    pub const fn no_inherit(self) -> bool{ self.0 & 0x0040 != 0 }
    #[must_use] 
    pub const fn no_construct(self) -> bool { self.0 & 0x0080 != 0 }
    #[must_use] 
    pub const fn is_compiler_generated(self) -> bool { self.0 & 0x0100 != 0 }
    #[must_use] 
    pub const fn is_sealed(self) -> bool { self.0 & 0x0200 != 0 }
}

// ---------------------------------------------------------------------------
// Pointer attributes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PointerAttr(pub u32);

impl PointerAttr {
    #[must_use] 
    pub const fn ptr_type(self) -> u8         { (self.0 & 0x1f) as u8 }
    #[must_use] 
    pub const fn ptr_mode(self) -> u8         { ((self.0 >> 5) & 7) as u8 }
    #[must_use] 
    pub const fn is_flat32(self) -> bool      { self.0 & 0x0100 != 0 }
    #[must_use] 
    pub const fn is_volatile(self) -> bool    { self.0 & 0x0200 != 0 }
    #[must_use] 
    pub const fn is_const(self) -> bool       { self.0 & 0x0400 != 0 }
    #[must_use] 
    pub const fn is_unaligned(self) -> bool   { self.0 & 0x0800 != 0 }
    #[must_use] 
    pub const fn is_restrict(self) -> bool    { self.0 & 0x1000 != 0 }
    #[must_use] 
    pub const fn size(self) -> u8             { ((self.0 >> 13) & 0x3f) as u8 }
    #[must_use] 
    pub const fn is_mocom(self) -> bool       { self.0 & 0x0008_0000 != 0 }
    #[must_use] 
    pub const fn is_lvalue_ref(self) -> bool  { self.0 & 0x0010_0000 != 0 }
    #[must_use] 
    pub const fn is_rvalue_ref(self) -> bool  { self.0 & 0x0020_0000 != 0 }
}

// ---------------------------------------------------------------------------
// Vtable shape entries
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum VtabShapeEntry {
    Near      = 0x00,
    Far       = 0x01,
    Thin      = 0x02,
    Outer     = 0x03,
    Meta      = 0x04,
    Near32    = 0x05,
    Far32     = 0x06,
    Unknown   = 0xff,
}

impl VtabShapeEntry {
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
    pub referent: TypeIndex,
    pub attr: PointerAttr,
    /// For member pointers: the containing class type index.
    pub containing_class: Option<TypeIndex>,
}

/// `LF_ARRAY` (0x1003)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfArray {
    pub element_type: TypeIndex,
    pub index_type: TypeIndex,
    /// Length in bytes (numeric leaf decoded).
    pub length_bytes: u64,
    pub name: String,
}

/// `LF_CLASS` / `LF_STRUCTURE` (0x1004/0x1005)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfClass {
    pub is_struct: bool,
    pub count: u16,
    pub props: CvTypeProps,
    pub field_list: TypeIndex,
    pub derived: TypeIndex,
    pub vtable: TypeIndex,
    pub size: u64,
    pub name: String,
    pub unique_name: Option<String>,
}

/// `LF_UNION` (0x1006)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfUnion {
    pub count: u16,
    pub props: CvTypeProps,
    pub field_list: TypeIndex,
    pub size: u64,
    pub name: String,
    pub unique_name: Option<String>,
}

/// `LF_ENUM` (0x1007)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfEnum {
    pub count: u16,
    pub props: CvTypeProps,
    pub underlying: TypeIndex,
    pub field_list: TypeIndex,
    pub name: String,
    pub unique_name: Option<String>,
}

/// `LF_PROCEDURE` (0x1008)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfProcedure {
    pub return_type: TypeIndex,
    pub calling_conv: CallingConvention,
    pub func_attr: u8,
    pub param_count: u16,
    pub arg_list: TypeIndex,
}

/// `LF_MFUNCTION` (0x1009) — member function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMFunction {
    pub return_type: TypeIndex,
    pub class_type: TypeIndex,
    pub this_type: TypeIndex,
    pub calling_conv: CallingConvention,
    pub func_attr: u8,
    pub param_count: u16,
    pub arg_list: TypeIndex,
    pub this_adjust: i32,
}

/// `LF_VTSHAPE` (0x000a) — virtual function table shape
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfVtShape {
    pub count: u16,
    pub entries: Vec<VtabShapeEntry>,
}

/// `LF_BITFIELD` (0x1205)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfBitfield {
    pub underlying: TypeIndex,
    pub length: u8,
    pub position: u8,
}

/// `LF_ARGLIST` (0x1201) — function argument list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfArgList {
    pub args: Vec<TypeIndex>,
}

/// One entry in `LF_METHODLIST`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodListEntry {
    pub attr: FieldAttr,
    pub method_type: TypeIndex,
    /// `VTable` slot offset (only for virtual methods).
    pub vbase_offset: Option<u32>,
}

/// `LF_METHODLIST` (0x1206)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMethodList {
    pub methods: Vec<MethodListEntry>,
}

/// `LF_DIMARRAY` (0x1508) — dimensioned array
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfDimArray {
    pub underlying: TypeIndex,
    pub dim_info: TypeIndex,
    pub name: String,
}

/// `LF_PRECOMP` (0x1509) — precompiled type header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfPrecomp {
    pub start_index: TypeIndex,
    pub count: u32,
    pub signature: u32,
    pub name: String,
}

/// `LF_ALIAS` (0x150a) — type alias (typedef)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfAlias {
    pub underlying: TypeIndex,
    pub name: String,
}

/// `LF_BCLASS` (0x1400) — base class
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfBClass {
    pub attr: FieldAttr,
    pub base_type: TypeIndex,
    pub offset: u64,
}

/// `LF_VBCLASS` / `LF_IVBCLASS` (0x1401/0x1402) — virtual base class
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfVBClass {
    pub is_indirect: bool,
    pub attr: FieldAttr,
    pub base_type: TypeIndex,
    pub vbptr_type: TypeIndex,
    pub vbptr_offset: u64,
    pub vtable_index: u64,
}

/// `LF_MEMBER` (0x150d) — data member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMember {
    pub attr: FieldAttr,
    pub field_type: TypeIndex,
    pub offset: u64,
    pub name: String,
}

/// `LF_STMEMBER` (0x150e) — static data member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfStMember {
    pub attr: FieldAttr,
    pub field_type: TypeIndex,
    pub name: String,
}

/// `LF_METHOD` (0x150f) — overloaded method group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMethod {
    pub count: u16,
    pub method_list: TypeIndex,
    pub name: String,
}

/// `LF_NESTTYPE` (0x1510) — nested type definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfNestType {
    pub nested_type: TypeIndex,
    pub name: String,
}

/// `LF_ONEMETHOD` (0x1511) — single non-overloaded method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfOneMethod {
    pub attr: FieldAttr,
    pub method_type: TypeIndex,
    pub vbase_offset: Option<u32>,
    pub name: String,
}

/// `LF_ENUMERATE` (0x1502) — enumerator value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfEnumerate {
    pub attr: FieldAttr,
    pub value: i64,
    pub name: String,
}

/// `LF_INDEX` (0x1404) — continuation reference in a field list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfIndex {
    pub next_index: TypeIndex,
}

/// `LF_MODIFIER` (0x1001)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfModifier {
    pub modified_type: TypeIndex,
    pub is_const: bool,
    pub is_volatile: bool,
    pub is_unaligned: bool,
}

/// `LF_FUNC_ID` (0x1601)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfFuncId {
    pub scope_id: TypeIndex,
    pub func_type: TypeIndex,
    pub name: String,
}

/// `LF_STRING_ID` (0x1605)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfStringId {
    pub id: TypeIndex,
    pub value: String,
}

/// `LF_UDT_SRC_LINE` (0x1606)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfUdtSrcLine {
    pub udt: TypeIndex,
    pub src_file: TypeIndex,
    pub line: u32,
}

// ---------------------------------------------------------------------------
// FieldList contents
// ---------------------------------------------------------------------------

/// A parsed field-list member (one entry in `LF_FIELDLIST`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldListEntry {
    BClass(LfBClass),
    VBClass(LfVBClass),
    Member(LfMember),
    StMember(LfStMember),
    Method(LfMethod),
    NestType(LfNestType),
    OneMethod(LfOneMethod),
    Enumerate(LfEnumerate),
    VFuncTab(TypeIndex),
    VFuncOff { attr: FieldAttr, offset: u32, method_type: TypeIndex },
    Index(LfIndex),
}

/// A fully parsed field list.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LfFieldList {
    pub entries: Vec<FieldListEntry>,
}

// ---------------------------------------------------------------------------
// Top-level type record enum
// ---------------------------------------------------------------------------

/// The union of all parsed `CodeView` type records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeRecord {
    Modifier(LfModifier),
    Pointer(LfPointer),
    Array(LfArray),
    Class(LfClass),
    Union(LfUnion),
    Enum(LfEnum),
    Procedure(LfProcedure),
    MFunction(LfMFunction),
    VtShape(LfVtShape),
    Bitfield(LfBitfield),
    ArgList(LfArgList),
    FieldList(LfFieldList),
    MethodList(LfMethodList),
    DimArray(LfDimArray),
    Precomp(LfPrecomp),
    Alias(LfAlias),
    FuncId(LfFuncId),
    StringId(LfStringId),
    UdtSrcLine(LfUdtSrcLine),
    Unknown { kind: u16, data: Vec<u8> },
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
            (TypeIndex(self.min_index + crate::casts::usize_to_u32(i)), r)
        })
    }

    /// Build the forward-reference map by scanning all class/union/enum records.
    pub fn build_fwd_ref_map(&mut self) {
        /// Key a UDT by its `unique_name` when the record carries one; the
        /// decorated name is unambiguous across namespaces and template
        /// instantiations, where the plain name collides.
        fn key<'a>(name: &'a str, unique: Option<&'a String>) -> &'a str {
            unique.map_or(name, String::as_str)
        }
        fn udt_key(rec: &TypeRecord) -> Option<(&str, bool)> {
            match rec {
                TypeRecord::Class(c) => {
                    Some((key(&c.name, c.unique_name.as_ref()), c.props.is_forward_ref()))
                }
                TypeRecord::Union(u) => {
                    Some((key(&u.name, u.unique_name.as_ref()), u.props.is_forward_ref()))
                }
                TypeRecord::Enum(e) => {
                    Some((key(&e.name, e.unique_name.as_ref()), e.props.is_forward_ref()))
                }
                _ => None,
            }
        }

        // First pass: collect all non-forward-ref UDT definitions
        let mut name_to_def: HashMap<String, u32> = HashMap::new();
        for (ti, rec) in self.iter() {
            if let Some((name, false)) = udt_key(rec)
                && !name.is_empty()
            {
                name_to_def.insert(name.to_owned(), ti.0);
            }
        }
        // Second pass: match forward refs to definitions
        let mut fwd_map = HashMap::new();
        for (ti, rec) in self.iter() {
            if let Some((name, true)) = udt_key(rec)
                && let Some(&def_idx) = name_to_def.get(name)
            {
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
    #[must_use] 
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[must_use] 
    pub const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    #[must_use] 
    pub const fn position(&self) -> usize {
        self.pos
    }

    #[must_use] 
    pub fn peek_u16(&self) -> Option<u16> {
        if self.remaining() < 2 { return None; }
        Some(u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]))
    }

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

    /// # Errors
    /// Returns [`CodeViewError::RecordTooShort`] if fewer than 4 bytes remain.
    pub fn read_i32(&mut self) -> Result<i32, CodeViewError> {
        self.read_u32().map(crate::casts::u32_as_i32)
    }

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
        // Lossy (per-byte U+FFFD) rather than a whole-string placeholder:
        // real PDBs carry mangled/codepage-encoded names, and collapsing them
        // all to one literal makes distinct types compare equal.
        let s = String::from_utf8_lossy(
            self.data
                .get(start..self.pos)
                .unwrap_or_default(),
        )
        .into_owned();
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
            lf::LF_SHORT     => Ok(crate::casts::i16_sext_u64(crate::casts::u16_as_i16(self.read_u16()?))),
            lf::LF_USHORT    => Ok(u64::from(self.read_u16()?)),
            lf::LF_LONG      => Ok(crate::casts::i32_sext_u64(crate::casts::u32_as_i32(self.read_u32()?))),
            lf::LF_ULONG     => Ok(u64::from(self.read_u32()?)),
            lf::LF_QUADWORD | lf::LF_UQUADWORD => Ok(self.read_u64()?),
            lf::LF_REAL32    => {
                let bits = self.read_u32()?;
                Ok(crate::casts::f32_to_u64_sat(f32::from_bits(bits)))
            }
            lf::LF_REAL64    => {
                let bits = self.read_u64()?;
                Ok(crate::casts::f64_to_u64_sat(f64::from_bits(bits)))
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
            lf::LF_CHAR      => Ok(i64::from(crate::casts::u8_as_i8(self.read_u8()?))),
            lf::LF_SHORT     => Ok(i64::from(crate::casts::u16_as_i16(self.read_u16()?))),
            lf::LF_USHORT    => Ok(i64::from(self.read_u16()?)),
            lf::LF_LONG | lf::LF_ULONG => Ok(i64::from(crate::casts::u32_as_i32(self.read_u32()?))),
            lf::LF_QUADWORD | lf::LF_UQUADWORD => Ok(crate::casts::u64_as_i64(self.read_u64()?)),
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
            // Cap the reservation against the buffer: `count` is file-declared
            // and a 4-byte record can otherwise request a 16 GiB allocation.
            let max = r.remaining() / 4;
            let mut args = Vec::with_capacity((count as usize).min(max));
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
    format_type_depth(db, idx, name, 0)
}

/// Maximum type-graph depth before [`format_type`] bails out. A
/// self-referential TPI record would otherwise recurse until the stack is
/// exhausted, which aborts the process uncatchably.
const MAX_FORMAT_DEPTH: u32 = 16;

fn format_type_depth(
    db: &TypeDatabase,
    idx: TypeIndex,
    name: Option<&str>,
    depth: u32,
) -> String {
    if depth > MAX_FORMAT_DEPTH {
        return "<recursion limit>".into();
    }
    if idx.is_primitive() {
        return format_primitive(idx);
    }
    match db.get(idx) {
        None => format!("<unknown T#{:#x}>", idx.0),
        Some(rec) => format_record(db, rec, name, depth),
    }
}

fn format_primitive(idx: TypeIndex) -> String {
    // Pointer-mode bits [10:8]: non-zero means "pointer to the base type".
    let mode = (idx.0 >> 8) & 0x7;
    let base = idx.0 & 0xFF;
    let base_name: String = match base {
        0x00 => "<notype>".into(),
        0x03 => "void".into(),
        0x08 => "bool".into(),
        0x10 => "char".into(),
        0x20 => "unsigned char".into(),
        0x68 => "__int8".into(),
        0x69 => "unsigned __int8".into(),
        0x70 => "char".into(),
        0x71 => "wchar_t".into(),
        0x72 => "short".into(),
        0x73 => "unsigned short".into(),
        0x74 => "int".into(),
        0x75 => "unsigned int".into(),
        0x76 => "__int64".into(),
        0x77 => "unsigned __int64".into(),
        0x78 => "__int128".into(),
        0x79 => "unsigned __int128".into(),
        0x7a => "char16_t".into(),
        0x7b => "char32_t".into(),
        0x30 => "bool".into(),
        0x40 => "float".into(),
        0x41 => "double".into(),
        0x42 => "long double".into(),
        _ => return format!("<prim {:#06x}>", idx.0),
    };
    if mode == 0 { base_name } else { format!("{base_name}*") }
}

fn format_record(db: &TypeDatabase, rec: &TypeRecord, name: Option<&str>, depth: u32) -> String {
    let n = name.unwrap_or("");
    match rec {
        TypeRecord::Pointer(p) => {
            let inner = format_type_depth(db, p.referent, None, depth + 1);
            if p.attr.is_const() {
                format!("const {inner}* {n}")
            } else {
                format!("{inner}* {n}")
            }
        }
        TypeRecord::Array(a) => {
            let elem = format_type_depth(db, a.element_type, None, depth + 1);
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
            let ret = format_type_depth(db, p.return_type, None, depth + 1);
            format!("{} (*)() /* {} params */", ret, p.param_count)
        }
        TypeRecord::Bitfield(b) => {
            let base = format_type_depth(db, b.underlying, None, depth + 1);
            format!("{} {}:{}", base, n, b.length)
        }
        TypeRecord::Alias(a) => {
            let base = format_type_depth(db, a.underlying, None, depth + 1);
            format!("typedef {} {}", base, a.name)
        }
        TypeRecord::Modifier(m) => {
            let base = format_type_depth(db, m.modified_type, None, depth + 1);
            let mut quals = String::new();
            if m.is_const     { quals.push_str("const "); }
            if m.is_volatile  { quals.push_str("volatile "); }
            if m.is_unaligned { quals.push_str("__unaligned "); }
            format!("{quals}{base}")
        }
        _ => rec.kind_name().to_owned(),
    }
}
