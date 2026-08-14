//! `CodeView` type records.
//!
//! Full parsing of all `LF_` leaf types from the `.debug$T` or `TPI` stream.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Leaf type codes (LF_*)
// ─────────────────────────────────────────────────────────────────────────────

/// `CodeView` leaf type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum LeafKind {
    // Primitive/simple
    /// `LF_MODIFIER` — const/volatile/unaligned qualifier record.
    Modifier = 0x1001,
    /// `LF_POINTER` — pointer type record.
    Pointer = 0x1002,
    /// `LF_ARRAY` — array type record.
    Array = 0x1003,
    /// `LF_CLASS` — C++ class definition record.
    Class = 0x1004,
    /// `LF_STRUCTURE` — struct definition record.
    Structure = 0x1005,
    /// `LF_UNION` — union definition record.
    Union = 0x1006,
    /// `LF_ENUM` — enum definition record.
    Enum = 0x1007,
    /// `LF_PROCEDURE` — non-member function type record.
    Procedure = 0x1008,
    /// `LF_MFUNCTION` — member-function type record.
    MFunction = 0x1009,
    /// `LF_COBOL0` — COBOL type record.
    Cobol0 = 0x100A,
    /// `LF_BARRAY` — basic-array type record.
    Barray = 0x100B,
    /// `LF_LABEL` — code label type record.
    Label = 0x100C,
    /// `LF_NULL` — empty/placeholder leaf.
    Null = 0x100D,
    /// `LF_NOTTRAN` — type not translated by cvpack.
    NotTran = 0x100E,
    /// `LF_DIMARRAY` — multi-dimensional array record.
    DimArray = 0x100F,
    /// `LF_VFTPATH` — virtual function table path record.
    VFTPath = 0x1010,
    // Field list members
    /// `LF_FIELDLIST` — container holding aggregate member records.
    FieldList = 0x1203,
    /// `LF_BCLASS` — direct (non-virtual) base class.
    BClass = 0x1400,
    /// `LF_VBCLASS` — direct virtual base class.
    VBClass = 0x1401,
    /// `LF_IVBCLASS` — indirect virtual base class.
    IVBClass = 0x1402,
    /// `LF_FRIENDFCN` — friend function entry.
    FriendFcn = 0x1403,
    /// `LF_INDEX` — continuation link to another field list.
    Index = 0x1404,
    /// `LF_MEMBER` — non-static data member.
    Member = 0x1405,
    /// `LF_STMEMBER` — static data member.
    STMember = 0x1406,
    /// `LF_METHOD` — overloaded method group.
    Method = 0x1407,
    /// `LF_NESTTYPE` — nested type declaration.
    NestType = 0x1408,
    /// `LF_VFUNCTAB` — vtable pointer member.
    VFuncTab = 0x1409,
    /// `LF_FRIENDCLS` — friend class entry.
    FriendCls = 0x140A,
    /// `LF_ONEMETHOD` — non-overloaded method.
    OneMethod = 0x140B,
    /// `LF_VFUNCOFF` — virtual function offset entry.
    VFuncOff = 0x140C,
    /// `LF_NESTTYPEEX` — nested type with attributes.
    NestTypeEx = 0x140D,
    /// `LF_MEMBERMODIFY` — member access modification.
    MemberModify = 0x140E,
    /// `LF_MANAGED` — managed (CLR) type reference.
    Managed = 0x140F,
    // Numeric leaves
    /// `LF_CHAR` — 8-bit signed numeric leaf.
    Char = 0x8000,
    /// `LF_SHORT` — 16-bit signed numeric leaf.
    Short = 0x8001,
    /// `LF_USHORT` — 16-bit unsigned numeric leaf.
    UShort = 0x8002,
    /// `LF_LONG` — 32-bit signed numeric leaf.
    Long_ = 0x8003,
    /// `LF_ULONG` — 32-bit unsigned numeric leaf.
    ULong = 0x8004,
    /// `LF_REAL32` — 32-bit float numeric leaf.
    Real32 = 0x8005,
    /// `LF_REAL64` — 64-bit float numeric leaf.
    Real64 = 0x8006,
    /// `LF_REAL80` — 80-bit float numeric leaf.
    Real80 = 0x8007,
    /// `LF_REAL128` — 128-bit float numeric leaf.
    Real128 = 0x8008,
    /// `LF_QUADWORD` — 64-bit signed numeric leaf.
    Quadword = 0x8009,
    /// `LF_UQUADWORD` — 64-bit unsigned numeric leaf.
    UQuadword = 0x800A,
    /// `LF_REAL48` — 48-bit float numeric leaf.
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
}

impl LeafKind {
    /// Decode a raw leaf tag into a [`LeafKind`] (common subset only).
    #[must_use]
    pub const fn from_u16(v: u16) -> Option<Self> {
        // Just a few common ones for demo purposes
        Some(match v {
            0x1001 => Self::Modifier,
            0x1002 => Self::Pointer,
            0x1003 => Self::Array,
            0x1004 => Self::Class,
            0x1005 => Self::Structure,
            0x1006 => Self::Union,
            0x1007 => Self::Enum,
            0x1008 => Self::Procedure,
            0x1009 => Self::MFunction,
            0x1203 => Self::FieldList,
            0x1400 => Self::BClass,
            0x1401 => Self::VBClass,
            0x1405 => Self::Member,
            0x1406 => Self::STMember,
            0x1407 => Self::Method,
            0x1408 => Self::NestType,
            0x140B => Self::OneMethod,
            _ => return None,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Type index
// ─────────────────────────────────────────────────────────────────────────────

/// A `CodeView` type index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TypeIndex(pub u32);

impl TypeIndex {
    /// Returns true if this is a "simple" (primitive) type index (< 0x1000).
    #[must_use]
    pub const fn is_simple(self) -> bool {
        self.0 < 0x1000
    }

    /// Returns true if this is a nil/void type.
    #[must_use]
    pub const fn is_void(self) -> bool {
        self.0 == 0x0003
    }
}

impl fmt::Display for TypeIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "T#{:#06x}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pointer record
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Pointer addressing kind from an `LF_POINTER` attribute (`CV_ptrtype_e`).
pub enum PtrKind {
    /// 16-bit near pointer.
    Near16,
    /// 16:16 far pointer.
    Far16,
    /// 16:16 huge pointer.
    Huge16,
    /// Based pointer (relative to a base value/segment).
    Based,
    /// 32-bit near pointer.
    Near32,
    /// 16:32 far pointer.
    Far32,
    /// 64-bit pointer.
    Ptr64,
    /// 128-bit pointer.
    Near128,
}

/// Pointer mode from an `LF_POINTER` attribute (`CV_ptrmode_e`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtrMode {
    /// Plain pointer (`T*`).
    Ptr,
    /// L-value reference (`T&`).
    LValueRef,
    /// Pointer to data member (`T C::*`).
    PointerToMember,
    /// Pointer to member function (`R (C::*)(...)`).
    PointerToMemberFunction,
    /// R-value reference (`T&&`).
    RValueRef,
}

/// `LF_POINTER` — pointer type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfPointer {
    /// Type index of the pointed-to type.
    pub referent: TypeIndex,
    /// Addressing kind (near32, ptr64, ...).
    pub kind: PtrKind,
    /// Pointer mode (pointer, reference, pointer-to-member).
    pub mode: PtrMode,
    /// Flags: bit 0 = flat32, bit 1 = volatile, bit 2 = const, bit 3 = unaligned, bit 4 = restrict.
    pub flags: u8,
    /// Pointer size in bytes.
    pub size: u8,
}

impl LfPointer {
    /// 0:32 flat-address pointer flag (bit 0).
    #[must_use]
    pub const fn is_flat32(&self) -> bool { self.flags & 0x01 != 0 }
    /// `volatile` pointer flag (bit 1).
    #[must_use]
    pub const fn is_volatile(&self) -> bool { self.flags & 0x02 != 0 }
    /// `const` pointer flag (bit 2).
    #[must_use]
    pub const fn is_const(&self) -> bool { self.flags & 0x04 != 0 }
    /// `__unaligned` pointer flag (bit 3).
    #[must_use]
    pub const fn is_unaligned(&self) -> bool { self.flags & 0x08 != 0 }
    /// `restrict` pointer flag (bit 4).
    #[must_use]
    pub const fn is_restrict(&self) -> bool { self.flags & 0x10 != 0 }
}

// ─────────────────────────────────────────────────────────────────────────────
// Array record
// ─────────────────────────────────────────────────────────────────────────────

/// `LF_ARRAY` — array type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfArray {
    /// Type index of the element type.
    pub element_type: TypeIndex,
    /// Type index of the indexing type (usually an integer primitive).
    pub index_type: TypeIndex,
    /// Total array size in bytes.
    pub byte_size: u64,
    /// Optional array type name.
    pub name: Option<String>,
}

impl LfArray {
    /// Infer element count if element size is known.
    #[must_use]
    pub const fn count(&self, element_size: u64) -> Option<u64> {
        self.byte_size.checked_div(element_size)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Class / Structure / Union records
// ─────────────────────────────────────────────────────────────────────────────

/// `LF_CLASS` / `LF_STRUCTURE` / `LF_UNION` — aggregate type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfClass {
    /// Number of members in the field list.
    pub count: u16,
    /// Type index of the `LF_FIELDLIST` describing the members.
    pub field_list: TypeIndex,
    /// Type index of the derivation list (0 if none).
    pub derived_from: TypeIndex,
    /// Type index of the `LF_VTSHAPE` (0 if none).
    pub vshape: TypeIndex,
    /// Size of an instance in bytes.
    pub byte_size: u64,
    /// Display name.
    pub name: String,
    /// Mangled unique name, if emitted.
    pub unique_name: Option<String>,
    /// Flags: bit 0 = `forward_ref`, bit 1 = scoped, bit 2 = packed, bit 3 = `has_ctor`,
    /// bit 4 = `has_overloaded_ops`, bit 5 = nested, bit 6 = `has_nested`, bit 7 = intrinsic.
    pub flags: u8,
}

impl LfClass {
    /// Create an empty (zero-sized, no-member) class record with `name`.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            count: 0,
            field_list: TypeIndex(0),
            derived_from: TypeIndex(0),
            vshape: TypeIndex(0),
            byte_size: 0,
            name: name.into(),
            unique_name: None,
            flags: 0,
        }
    }

    /// Forward reference (declaration only, no definition) — flag bit 0.
    #[must_use]
    pub const fn is_forward_ref(&self) -> bool { self.flags & 0x01 != 0 }
    /// Scoped definition (e.g. declared inside a function) — flag bit 1.
    #[must_use]
    pub const fn is_scoped(&self) -> bool { self.flags & 0x02 != 0 }
    /// Structure is packed — flag bit 2.
    #[must_use]
    pub const fn is_packed(&self) -> bool { self.flags & 0x04 != 0 }
    /// Has constructors/destructors — flag bit 3.
    #[must_use]
    pub const fn has_ctor(&self) -> bool { self.flags & 0x08 != 0 }
    /// Has overloaded operators — flag bit 4.
    #[must_use]
    pub const fn has_overloaded_ops(&self) -> bool { self.flags & 0x10 != 0 }
    /// Is itself a nested type — flag bit 5.
    #[must_use]
    pub const fn is_nested(&self) -> bool { self.flags & 0x20 != 0 }
    /// Contains nested type definitions — flag bit 6.
    #[must_use]
    pub const fn has_nested(&self) -> bool { self.flags & 0x40 != 0 }
    /// Compiler intrinsic type (e.g. `__m128`) — flag bit 7.
    #[must_use]
    pub const fn is_intrinsic(&self) -> bool { self.flags & 0x80 != 0 }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enum record
// ─────────────────────────────────────────────────────────────────────────────

/// `LF_ENUM` — enumeration type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfEnum {
    /// Number of enumerators.
    pub count: u16,
    /// Type index of the underlying integer type.
    pub underlying_type: TypeIndex,
    /// Type index of the `LF_FIELDLIST` holding the enumerators.
    pub field_list: TypeIndex,
    /// Display name.
    pub name: String,
    /// Mangled unique name, if emitted.
    pub unique_name: Option<String>,
    /// Forward reference (declaration only).
    pub is_forward_ref: bool,
    /// Scoped enum (`enum class`).
    pub is_scoped: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Procedure / MFunction records
// ─────────────────────────────────────────────────────────────────────────────

/// `LF_PROCEDURE` — non-member function type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfProcedure {
    /// Type index of the return type.
    pub return_type: TypeIndex,
    /// Calling convention code (`CV_call_e`).
    pub calling_conv: u8,
    /// Function attribute flags (`CV_funcattr_t`).
    pub attributes: u8,
    /// Number of parameters.
    pub param_count: u16,
    /// Type index of the argument list record.
    pub arg_list: TypeIndex,
}

/// `LF_MFUNCTION` — C++ member-function type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMFunction {
    /// Type index of the return type.
    pub return_type: TypeIndex,
    /// Type index of the containing class.
    pub class_type: TypeIndex,
    /// Type index of the `this` pointer type (nil for static methods).
    pub this_type: TypeIndex,
    /// Calling convention code (`CV_call_e`).
    pub calling_conv: u8,
    /// Function attribute flags (`CV_funcattr_t`).
    pub attributes: u8,
    /// Number of parameters (excluding `this`).
    pub param_count: u16,
    /// Type index of the argument list record.
    pub arg_list: TypeIndex,
    /// Adjustment applied to `this` before the call (multiple inheritance).
    pub this_adjust: i32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Field list members
// ─────────────────────────────────────────────────────────────────────────────

/// `LF_MEMBER` — non-static data member in a field list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMember {
    /// Type index of the member's type.
    pub field_type: TypeIndex,
    /// Byte offset within the aggregate.
    pub offset: u64,
    /// Member name.
    pub name: String,
    /// C++ access level.
    pub access: AccessKind,
}

/// `LF_STMEMBER` — static data member in a field list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfSTMember {
    /// Type index of the member's type.
    pub field_type: TypeIndex,
    /// Member name.
    pub name: String,
    /// C++ access level.
    pub access: AccessKind,
}

/// `LF_METHOD` — overloaded method group in a field list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMethod {
    /// Number of overloads.
    pub count: u16,
    /// Type index of the `LF_METHODLIST` record.
    pub method_list: TypeIndex,
    /// Method name shared by all overloads.
    pub name: String,
}

/// `LF_NESTTYPE` — nested type declaration inside a class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfNestType {
    /// Type index of the nested type.
    pub nested_type: TypeIndex,
    /// Declared name of the nested type.
    pub name: String,
}

/// `LF_ONEMETHOD` — non-overloaded method in a field list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfOneMethod {
    /// Type index of the method's `LF_MFUNCTION`.
    pub method_type: TypeIndex,
    /// Vtable offset, present for introducing virtual methods.
    pub vtable_offset: Option<i32>,
    /// Method name.
    pub name: String,
    /// C++ access level.
    pub access: AccessKind,
    /// Method property (virtual/static/intro/...).
    pub method_kind: MethodKind,
}

/// `LF_BCLASS` — direct (non-virtual) base class in a field list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfBClass {
    /// Type index of the base class.
    pub base_type: TypeIndex,
    /// Byte offset of the base subobject in the derived class.
    pub offset: u64,
    /// C++ access level of the inheritance.
    pub access: AccessKind,
}

/// `LF_VBCLASS` / `LF_IVBCLASS` — (indirect) virtual base class in a field list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfVBClass {
    /// Type index of the virtual base class.
    pub base_type: TypeIndex,
    /// Type index of the virtual base pointer type.
    pub vbptr_type: TypeIndex,
    /// Offset of the virtual base pointer from the address point.
    pub vb_ptr_offset: u64,
    /// Index into the virtual base displacement table.
    pub vb_index_offset: u64,
    /// C++ access level of the inheritance.
    pub access: AccessKind,
    /// True for `LF_IVBCLASS` (indirect virtual base).
    pub is_indirect: bool,
}

/// `LF_METHODLIST` — list of overloads referenced by an `LF_METHOD`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMethodList {
    /// The overload entries, in declaration order.
    pub methods: Vec<LfMethodListEntry>,
}

/// One overload entry inside an `LF_METHODLIST`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMethodListEntry {
    /// Type index of this overload's `LF_MFUNCTION`.
    pub method_type: TypeIndex,
    /// C++ access level.
    pub access: AccessKind,
    /// Method property (virtual/static/intro/...).
    pub kind: MethodKind,
    /// Vtable offset, present for introducing virtual methods.
    pub vtable_offset: Option<i32>,
}

/// C++ member access level (`CV_access_e`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessKind {
    /// No access specified.
    None,
    /// `private` access.
    Private,
    /// `protected` access.
    Protected,
    /// `public` access.
    Public,
}

/// Method property (`CV_methodprop_e`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MethodKind {
    /// Ordinary non-virtual method.
    Vanilla,
    /// Virtual method (overriding an existing slot).
    Virtual,
    /// Static method.
    Static,
    /// Friend function.
    Friend,
    /// Introducing virtual method (defines a new vtable slot).
    Intro,
    /// Pure virtual method.
    PureVirtual,
    /// Pure introducing virtual method.
    PureIntro,
}

// ─────────────────────────────────────────────────────────────────────────────
// Modifier record
// ─────────────────────────────────────────────────────────────────────────────

/// `LF_MODIFIER` — const/volatile/unaligned qualifier wrapping another type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfModifier {
    /// Type index of the type being modified.
    pub modified_type: TypeIndex,
    /// `const` qualifier present.
    pub is_const: bool,
    /// `volatile` qualifier present.
    pub is_volatile: bool,
    /// `__unaligned` qualifier present.
    pub is_unaligned: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// CvTypeRecord — unified enum
// ─────────────────────────────────────────────────────────────────────────────

/// A single `CodeView` type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CvTypeRecord {
    /// `LF_MODIFIER` — const/volatile/unaligned qualifier.
    Modifier(LfModifier),
    /// `LF_POINTER` — pointer type.
    Pointer(LfPointer),
    /// `LF_ARRAY` — array type.
    Array(LfArray),
    /// `LF_CLASS` — C++ class definition.
    Class(LfClass),
    /// `LF_STRUCTURE` — struct definition (same payload as class).
    Structure(LfClass),
    /// `LF_UNION` — union definition (same payload as class).
    Union(LfClass),
    /// `LF_ENUM` — enum definition.
    Enum(LfEnum),
    /// `LF_PROCEDURE` — non-member function type.
    Procedure(LfProcedure),
    /// `LF_MFUNCTION` — member-function type.
    MFunction(LfMFunction),
    /// `LF_MEMBER` — non-static data member.
    Member(LfMember),
    /// `LF_STMEMBER` — static data member.
    STMember(LfSTMember),
    /// `LF_METHOD` — overloaded method group.
    Method(LfMethod),
    /// `LF_NESTTYPE` — nested type declaration.
    NestType(LfNestType),
    /// `LF_ONEMETHOD` — non-overloaded method.
    OneMethod(LfOneMethod),
    /// `LF_METHODLIST` — method overload list.
    MethodList(LfMethodList),
    /// `LF_BCLASS` — direct base class.
    BClass(LfBClass),
    /// `LF_VBCLASS`/`LF_IVBCLASS` — virtual base class.
    VBClass(LfVBClass),
    /// Unrecognized leaf; raw bytes are preserved.
    Unknown {
        /// Raw leaf kind tag.
        leaf_kind: u16,
        /// Undecoded record payload.
        data: Vec<u8>,
    },
}

impl CvTypeRecord {
    /// Returns a short kind tag string.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Modifier(_) => "LF_MODIFIER",
            Self::Pointer(_) => "LF_POINTER",
            Self::Array(_) => "LF_ARRAY",
            Self::Class(_) => "LF_CLASS",
            Self::Structure(_) => "LF_STRUCTURE",
            Self::Union(_) => "LF_UNION",
            Self::Enum(_) => "LF_ENUM",
            Self::Procedure(_) => "LF_PROCEDURE",
            Self::MFunction(_) => "LF_MFUNCTION",
            Self::Member(_) => "LF_MEMBER",
            Self::STMember(_) => "LF_STMEMBER",
            Self::Method(_) => "LF_METHOD",
            Self::NestType(_) => "LF_NESTTYPE",
            Self::OneMethod(_) => "LF_ONEMETHOD",
            Self::MethodList(_) => "LF_METHODLIST",
            Self::BClass(_) => "LF_BCLASS",
            Self::VBClass(_) => "LF_VBCLASS",
            Self::Unknown { .. } => "LF_UNKNOWN",
        }
    }

    /// Return the name of the type, if available.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Class(c) | Self::Structure(c) | Self::Union(c) => Some(&c.name),
            Self::Enum(e) => Some(&e.name),
            Self::Member(m) => Some(&m.name),
            Self::STMember(s) => Some(&s.name),
            Self::Method(m) => Some(&m.name),
            Self::NestType(n) => Some(&n.name),
            Self::OneMethod(m) => Some(&m.name),
            _ => None,
        }
    }

    /// Returns true if this is a forward reference.
    #[must_use]
    pub const fn is_forward_ref(&self) -> bool {
        match self {
            Self::Class(c) | Self::Structure(c) | Self::Union(c) => c.is_forward_ref(),
            Self::Enum(e) => e.is_forward_ref,
            _ => false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CvTypeDb
// ─────────────────────────────────────────────────────────────────────────────

/// Database mapping [`TypeIndex`] → [`CvTypeRecord`].
#[derive(Debug, Default)]
pub struct CvTypeDb {
    records: HashMap<TypeIndex, CvTypeRecord>,
    by_name: HashMap<String, TypeIndex>,
    min_type_index: u32,
}

impl CvTypeDb {
    /// Create an empty database (first allocatable index is 0x1000).
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            by_name: HashMap::new(),
            min_type_index: 0x1000,
        }
    }

    /// Insert a type record with an explicit index.
    pub fn insert(&mut self, idx: TypeIndex, rec: CvTypeRecord) {
        if let Some(name) = rec.name() {
            self.by_name.insert(name.to_string(), idx);
        }
        self.records.insert(idx, rec);
    }

    /// Allocate the next sequential type index and insert.
    #[must_use]
    pub fn push(&mut self, rec: CvTypeRecord) -> TypeIndex {
        let idx = TypeIndex(self.next_index());
        self.insert(idx, rec);
        idx
    }

    fn next_index(&self) -> u32 {
        let max = self
            .records
            .keys()
            .map(|i| i.0)
            .max()
            .unwrap_or(self.min_type_index - 1);
        max + 1
    }

    /// Look up a record by type index.
    #[must_use]
    pub fn get(&self, idx: &TypeIndex) -> Option<&CvTypeRecord> {
        self.records.get(idx)
    }

    /// Look up the most recently inserted record with the given name.
    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<(&TypeIndex, &CvTypeRecord)> {
        let idx = self.by_name.get(name)?;
        self.records.get(idx).map(|r| (idx, r))
    }

    /// Number of stored records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }
    /// Returns true when no records are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Iterate over all (index, record) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&TypeIndex, &CvTypeRecord)> {
        self.records.iter()
    }

    /// Find all type indices with the given name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Vec<TypeIndex> {
        self.records
            .iter()
            .filter(|(_, r)| r.name() == Some(name))
            .map(|(k, _)| *k)
            .collect()
    }

    /// Resolve forward references: returns true if `idx` is a forward ref.
    #[must_use]
    pub fn is_forward_ref(&self, idx: &TypeIndex) -> bool {
        self.records
            .get(idx)
            .is_some_and(CvTypeRecord::is_forward_ref)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_class(name: &str, fwd: bool) -> CvTypeRecord {
        let mut c = LfClass::new(name);
        if fwd { c.flags |= 0x01; }
        CvTypeRecord::Class(c)
    }

    fn make_struct(name: &str) -> CvTypeRecord {
        CvTypeRecord::Structure(LfClass::new(name))
    }

    fn make_enum(name: &str) -> CvTypeRecord {
        CvTypeRecord::Enum(LfEnum {
            count: 0,
            underlying_type: TypeIndex(0),
            field_list: TypeIndex(0),
            name: name.to_string(),
            unique_name: None,
            is_forward_ref: false,
            is_scoped: false,
        })
    }

    // --- TypeIndex ---

    #[test]
    fn type_index_simple() {
        assert!(TypeIndex(0x0010).is_simple());
        assert!(!TypeIndex(0x1000).is_simple());
    }

    #[test]
    fn type_index_void() {
        assert!(TypeIndex(0x0003).is_void());
    }

    #[test]
    fn type_index_display() {
        let s = format!("{}", TypeIndex(0x1234));
        assert!(s.contains("1234"));
    }

    // --- LeafKind ---

    #[test]
    fn leaf_kind_from_u16_pointer() {
        assert_eq!(LeafKind::from_u16(0x1002), Some(LeafKind::Pointer));
    }

    #[test]
    fn leaf_kind_from_u16_unknown() {
        assert_eq!(LeafKind::from_u16(0xFFFF), None);
    }

    // --- LfArray ---

    #[test]
    fn lfarray_count() {
        let a = LfArray {
            element_type: TypeIndex(0),
            index_type: TypeIndex(0),
            byte_size: 40,
            name: None,
        };
        assert_eq!(a.count(4), Some(10));
    }

    #[test]
    fn lfarray_count_zero_size() {
        let a = LfArray {
            element_type: TypeIndex(0),
            index_type: TypeIndex(0),
            byte_size: 0,
            name: None,
        };
        assert_eq!(a.count(0), None);
    }

    // --- CvTypeRecord ---

    #[test]
    fn type_record_kind_str_class() {
        assert_eq!(make_class("Foo", false).kind_str(), "LF_CLASS");
    }

    #[test]
    fn type_record_name_class() {
        assert_eq!(make_class("Foo", false).name(), Some("Foo"));
    }

    #[test]
    fn type_record_name_enum() {
        assert_eq!(make_enum("Color").name(), Some("Color"));
    }

    #[test]
    fn type_record_is_forward_ref() {
        assert!(make_class("Fwd", true).is_forward_ref());
    }

    #[test]
    fn type_record_pointer_no_name() {
        let ptr = CvTypeRecord::Pointer(LfPointer {
            referent: TypeIndex(0),
            kind: PtrKind::Ptr64,
            mode: PtrMode::Ptr,
            flags: 0,
            size: 8,
        });
        assert!(ptr.name().is_none());
    }

    // --- CvTypeDb ---

    #[test]
    fn db_insert_get() {
        let mut db = CvTypeDb::new();
        db.insert(TypeIndex(0x1000), make_class("Foo", false));
        assert!(db.get(&TypeIndex(0x1000)).is_some());
    }

    #[test]
    fn db_len() {
        let mut db = CvTypeDb::new();
        let _ = db.push(make_class("A", false));
        let _ = db.push(make_struct("B"));
        assert_eq!(db.len(), 2);
    }

    #[test]
    fn db_is_empty() {
        let db = CvTypeDb::new();
        assert!(db.is_empty());
    }

    #[test]
    fn db_get_by_name() {
        let mut db = CvTypeDb::new();
        let _ = db.push(make_enum("MyEnum"));
        let found = db.get_by_name("MyEnum");
        assert!(found.is_some());
    }

    #[test]
    fn db_get_by_name_missing() {
        let db = CvTypeDb::new();
        assert!(db.get_by_name("NoSuch").is_none());
    }

    #[test]
    fn db_find_by_name() {
        let mut db = CvTypeDb::new();
        let _ = db.push(make_class("Widget", false));
        let indices = db.find_by_name("Widget");
        assert_eq!(indices.len(), 1);
    }

    #[test]
    fn db_is_forward_ref() {
        let mut db = CvTypeDb::new();
        let idx = db.push(make_class("Incomplete", true));
        assert!(db.is_forward_ref(&idx));
    }

    #[test]
    fn db_push_sequential_indices() {
        let mut db = CvTypeDb::new();
        let i1 = db.push(make_class("A", false));
        let i2 = db.push(make_class("B", false));
        assert!(i2.0 > i1.0);
    }

    #[test]
    fn member_record_name() {
        let m = CvTypeRecord::Member(LfMember {
            field_type: TypeIndex(0),
            offset: 0,
            name: "x".into(),
            access: AccessKind::Public,
        });
        assert_eq!(m.name(), Some("x"));
    }

    #[test]
    fn method_list_entry() {
        let ml = LfMethodList {
            methods: vec![LfMethodListEntry {
                method_type: TypeIndex(0x1000),
                access: AccessKind::Public,
                kind: MethodKind::Virtual,
                vtable_offset: Some(0),
            }],
        };
        assert_eq!(ml.methods.len(), 1);
        assert_eq!(ml.methods[0].kind, MethodKind::Virtual);
    }

    #[test]
    fn lf_class_new() {
        let c = LfClass::new("Test");
        assert_eq!(c.name, "Test");
        assert!(!c.is_forward_ref());
    }

    #[test]
    fn bclass_record() {
        let b = LfBClass {
            base_type: TypeIndex(0x1005),
            offset: 0,
            access: AccessKind::Public,
        };
        assert_eq!(b.base_type, TypeIndex(0x1005));
    }
}
