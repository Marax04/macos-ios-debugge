//! `metadata_tables` — Strongly-typed .NET CLI metadata table definitions (ECMA-335).
//!
//! This module is a **distinct, higher-fidelity layer** from the flat raw-integer
//! row types defined in `lib.rs` (`MetadataTables`, `TypeDefRow`, etc.).
//!
//! ## Relationship to `lib.rs` row types
//!
//! | Concern | `lib.rs` | `metadata_tables` |
//! |---------|----------|-------------------|
//! | Flag fields | bare `u32`/`u16` | newtype wrappers (`TypeAttributes`, `FieldAttributes`, …) |
//! | Table indices | bare `u32` | `TableIndex` (null-safe, 1-based) |
//! | Heap offsets | bare `u32` | `StringIndex`, `BlobIndex`, `GuidIndex` |
//! | Coded indices | bare `u32` | enums (`TypeDefOrRef`, `MemberRefParent`, …) |
//! | Container | `MetadataTables` | `MetadataTableStore` |
//!
//! The rest of the crate currently operates on the simpler `lib.rs` types.
//! `metadata_tables` is intentionally kept separate as the planned migration
//! target for a future pass that introduces full type safety across the
//! metadata layer.  Do **not** merge or delete — the coded-index enums,
//! `TableId`, and `MetadataTablesHeader::parse` are unique here.
//!
//! Defines all 45 metadata tables as row structs with proper field types,
//! along with table indices, coded index types, and a unified `MetadataTable`
//! enum for dispatch.

use std::collections::HashMap;
use std::fmt;

// ── Index types ───────────────────────────────────────────────────────────────

/// A 1-based row index into a single metadata table.
/// Index 0 means "null" / not present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TableIndex(pub u32);

impl TableIndex {
    pub const NULL: Self = Self(0);

    #[inline]
    pub fn is_null(self) -> bool { self.0 == 0 }

    /// Convert to a 0-based array index, returning `None` for null.
    #[inline]
    pub fn to_index(self) -> Option<usize> {
        if self.0 == 0 { None } else { Some((self.0 - 1) as usize) }
    }
}

impl fmt::Display for TableIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// Heap offset into the `#Strings` heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] pub struct StringIndex(pub u32);
/// Heap offset into the `#GUID` heap (1-based GUID index).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] pub struct GuidIndex(pub u32);
/// Heap offset into the `#Blob` heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] pub struct BlobIndex(pub u32);
/// Heap offset into the `#US` (user strings) heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] pub struct UserStringIndex(pub u32);

// ── Coded index types ─────────────────────────────────────────────────────────

/// ECMA-335 §II.24.2.6 coded index: TypeDefOrRef
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeDefOrRef {
    TypeDef(TableIndex),
    TypeRef(TableIndex),
    TypeSpec(TableIndex),
}

/// ECMA-335 coded index: HasConstant
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HasConstant {
    Field(TableIndex),
    Param(TableIndex),
    Property(TableIndex),
}

/// ECMA-335 coded index: HasCustomAttribute
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HasCustomAttribute {
    MethodDef(TableIndex),
    Field(TableIndex),
    TypeRef(TableIndex),
    TypeDef(TableIndex),
    Param(TableIndex),
    InterfaceImpl(TableIndex),
    MemberRef(TableIndex),
    Module(TableIndex),
    Permission(TableIndex),
    Property(TableIndex),
    Event(TableIndex),
    StandAloneSig(TableIndex),
    ModuleRef(TableIndex),
    TypeSpec(TableIndex),
    Assembly(TableIndex),
    AssemblyRef(TableIndex),
    File(TableIndex),
    ExportedType(TableIndex),
    ManifestResource(TableIndex),
    GenericParam(TableIndex),
    GenericParamConstraint(TableIndex),
    MethodSpec(TableIndex),
}

/// ECMA-335 coded index: HasFieldMarshal
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HasFieldMarshal {
    Field(TableIndex),
    Param(TableIndex),
}

/// ECMA-335 coded index: HasDeclSecurity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HasDeclSecurity {
    TypeDef(TableIndex),
    MethodDef(TableIndex),
    Assembly(TableIndex),
}

/// ECMA-335 coded index: MemberRefParent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemberRefParent {
    TypeDef(TableIndex),
    TypeRef(TableIndex),
    ModuleRef(TableIndex),
    MethodDef(TableIndex),
    TypeSpec(TableIndex),
}

/// ECMA-335 coded index: HasSemantics
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HasSemantics {
    Event(TableIndex),
    Property(TableIndex),
}

/// ECMA-335 coded index: MethodDefOrRef
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MethodDefOrRef {
    MethodDef(TableIndex),
    MemberRef(TableIndex),
}

/// ECMA-335 coded index: MemberForwarded
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemberForwarded {
    Field(TableIndex),
    MethodDef(TableIndex),
}

/// ECMA-335 coded index: Implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Implementation {
    File(TableIndex),
    AssemblyRef(TableIndex),
    ExportedType(TableIndex),
}

/// ECMA-335 coded index: CustomAttributeType
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CustomAttributeType {
    MethodDef(TableIndex),
    MemberRef(TableIndex),
}

/// ECMA-335 coded index: ResolutionScope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolutionScope {
    Module(TableIndex),
    ModuleRef(TableIndex),
    AssemblyRef(TableIndex),
    TypeRef(TableIndex),
}

/// ECMA-335 coded index: TypeOrMethodDef
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeOrMethodDef {
    TypeDef(TableIndex),
    MethodDef(TableIndex),
}

// ── Table 0x00: Module ────────────────────────────────────────────────────────

/// ECMA-335 §II.22.30 — Module table row.
#[derive(Debug, Clone)]
pub struct ModuleRow {
    /// Module generation (reserved, must be 0).
    pub generation: u16,
    /// Module name (index into `#Strings`).
    pub name: StringIndex,
    /// Module GUID (index into `#GUID`).
    pub mv_id: GuidIndex,
    /// Enc ID (index into `#GUID`, reserved).
    pub enc_id: GuidIndex,
    /// Enc base ID (index into `#GUID`, reserved).
    pub enc_base_id: GuidIndex,
}

// ── Table 0x01: TypeRef ───────────────────────────────────────────────────────

/// ECMA-335 §II.22.38 — TypeRef table row.
#[derive(Debug, Clone)]
pub struct TypeRefRow {
    /// Resolution scope coded index.
    pub resolution_scope: ResolutionScope,
    /// Type name.
    pub type_name: StringIndex,
    /// Type namespace (may be empty/null).
    pub type_namespace: StringIndex,
}

// ── Table 0x02: TypeDef ───────────────────────────────────────────────────────

/// ECMA-335 §II.22.37 — TypeDef flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeAttributes(pub u32);

impl TypeAttributes {
    pub const VISIBILITY_MASK: u32     = 0x0000_0007;
    pub const NOT_PUBLIC: u32          = 0x0000_0000;
    pub const PUBLIC: u32              = 0x0000_0001;
    pub const NESTED_PUBLIC: u32       = 0x0000_0002;
    pub const NESTED_PRIVATE: u32      = 0x0000_0003;
    pub const NESTED_FAMILY: u32       = 0x0000_0004;
    pub const NESTED_ASSEMBLY: u32     = 0x0000_0005;
    pub const NESTED_FAM_AND_ASSEM: u32 = 0x0000_0006;
    pub const NESTED_FAM_OR_ASSEM: u32 = 0x0000_0007;
    pub const LAYOUT_MASK: u32         = 0x0000_0018;
    pub const AUTO_LAYOUT: u32         = 0x0000_0000;
    pub const SEQUENTIAL_LAYOUT: u32   = 0x0000_0008;
    pub const EXPLICIT_LAYOUT: u32     = 0x0000_0010;
    pub const CLASS_SEMANTICS_MASK: u32 = 0x0000_0020;
    pub const CLASS: u32               = 0x0000_0000;
    pub const INTERFACE: u32           = 0x0000_0020;
    pub const ABSTRACT: u32            = 0x0000_0080;
    pub const SEALED: u32              = 0x0000_0100;
    pub const SPECIAL_NAME: u32        = 0x0000_0400;
    pub const RT_SPECIAL_NAME: u32     = 0x0000_0800;
    pub const IMPORT: u32              = 0x0000_1000;
    pub const SERIALIZABLE: u32        = 0x0000_2000;
    pub const BEFORE_FIELD_INIT: u32   = 0x0010_0000;
    pub const FORWARDER: u32           = 0x0020_0000;

    pub fn is_public(self) -> bool { (self.0 & Self::VISIBILITY_MASK) == Self::PUBLIC }
    pub fn is_interface(self) -> bool { (self.0 & Self::CLASS_SEMANTICS_MASK) != 0 }
    pub fn is_abstract(self) -> bool { self.0 & Self::ABSTRACT != 0 }
    pub fn is_sealed(self) -> bool { self.0 & Self::SEALED != 0 }
    pub fn is_nested(self) -> bool {
        let v = self.0 & Self::VISIBILITY_MASK;
        (Self::NESTED_PUBLIC..=Self::NESTED_FAM_OR_ASSEM).contains(&v)
    }
}

/// ECMA-335 §II.22.37 — TypeDef table row.
#[derive(Debug, Clone)]
pub struct TypeDefRow {
    pub flags: TypeAttributes,
    pub type_name: StringIndex,
    pub type_namespace: StringIndex,
    /// Extends: coded index TypeDefOrRef.
    pub extends: Option<TypeDefOrRef>,
    /// First field row (TableIndex into Field table).
    pub field_list: TableIndex,
    /// First method row (TableIndex into MethodDef table).
    pub method_list: TableIndex,
}

// ── Table 0x04: Field ─────────────────────────────────────────────────────────

/// ECMA-335 §II.22.15 — Field flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldAttributes(pub u16);

impl FieldAttributes {
    pub const ACCESS_MASK: u16    = 0x0007;
    pub const PRIVATE_SCOPE: u16  = 0x0000;
    pub const PRIVATE: u16        = 0x0001;
    pub const FAM_AND_ASSEM: u16  = 0x0002;
    pub const ASSEMBLY: u16       = 0x0003;
    pub const FAMILY: u16         = 0x0004;
    pub const FAM_OR_ASSEM: u16   = 0x0005;
    pub const PUBLIC: u16         = 0x0006;
    pub const STATIC: u16         = 0x0010;
    pub const INIT_ONLY: u16      = 0x0020;
    pub const LITERAL: u16        = 0x0040;
    pub const NOT_SERIALIZED: u16 = 0x0080;
    pub const SPECIAL_NAME: u16   = 0x0200;
    pub const PINVOKE_IMPL: u16   = 0x2000;
    pub const RT_SPECIAL_NAME: u16 = 0x0400;
    pub const HAS_FIELD_MARSHAL: u16  = 0x1000;
    pub const HAS_DEFAULT: u16    = 0x8000;
    pub const HAS_FIELD_RVA: u16  = 0x0100;

    pub fn is_public(self) -> bool { (self.0 & Self::ACCESS_MASK) == Self::PUBLIC }
    pub fn is_static(self) -> bool { self.0 & Self::STATIC != 0 }
    pub fn is_literal(self) -> bool { self.0 & Self::LITERAL != 0 }
}

/// ECMA-335 §II.22.15 — Field table row.
#[derive(Debug, Clone)]
pub struct FieldRow {
    pub flags: FieldAttributes,
    pub name: StringIndex,
    pub signature: BlobIndex,
}

// ── Table 0x06: MethodDef ─────────────────────────────────────────────────────

/// ECMA-335 method implementation flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodImplAttributes(pub u16);

impl MethodImplAttributes {
    pub const CODE_TYPE_MASK: u16 = 0x0003;
    pub const IL: u16             = 0x0000;
    pub const NATIVE: u16         = 0x0001;
    pub const OPT_IL: u16         = 0x0002;
    pub const RUNTIME: u16        = 0x0003;
    pub const MANAGED_MASK: u16   = 0x0004;
    pub const UNMANAGED: u16      = 0x0004;
    pub const MANAGED: u16        = 0x0000;
    pub const FORWARD_REF: u16    = 0x0010;
    pub const PRESERVE_SIG: u16   = 0x0080;
    pub const INTERNAL_CALL: u16  = 0x1000;
    pub const SYNCHRONIZED: u16   = 0x0020;
    pub const NO_INLINING: u16    = 0x0008;
    pub const MAX_METHOD_IMPL_VAL: u16 = 0xFFFF;

    pub fn is_il(self) -> bool { (self.0 & Self::CODE_TYPE_MASK) == Self::IL }
    pub fn is_native(self) -> bool { (self.0 & Self::CODE_TYPE_MASK) == Self::NATIVE }
}

/// ECMA-335 method attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodAttributes(pub u16);

impl MethodAttributes {
    pub const ACCESS_MASK: u16      = 0x0007;
    pub const MEMBER_ACCESS_MASK: u16 = 0x0007;
    pub const PRIVATE_SCOPE: u16    = 0x0000;
    pub const PRIVATE: u16          = 0x0001;
    pub const FAM_AND_ASSEM: u16    = 0x0002;
    pub const ASSEM: u16            = 0x0003;
    pub const FAMILY: u16           = 0x0004;
    pub const FAM_OR_ASSEM: u16     = 0x0005;
    pub const PUBLIC: u16           = 0x0006;
    pub const STATIC: u16           = 0x0010;
    pub const FINAL: u16            = 0x0020;
    pub const VIRTUAL: u16          = 0x0040;
    pub const HIDE_BY_SIG: u16      = 0x0080;
    pub const VTABLE_LAYOUT_MASK: u16 = 0x0100;
    pub const REUSE_SLOT: u16       = 0x0000;
    pub const NEW_SLOT: u16         = 0x0100;
    pub const STRICT: u16           = 0x0200;
    pub const ABSTRACT: u16         = 0x0400;
    pub const SPECIAL_NAME: u16     = 0x0800;
    pub const PINVOKE_IMPL: u16     = 0x2000;
    pub const RT_SPECIAL_NAME: u16  = 0x1000;
    pub const HAS_SECURITY: u16     = 0x4000;
    pub const REQUIRE_SEC_OBJECT: u16 = 0x8000;

    pub fn is_public(self) -> bool { (self.0 & Self::ACCESS_MASK) == Self::PUBLIC }
    pub fn is_static(self) -> bool { self.0 & Self::STATIC != 0 }
    pub fn is_virtual(self) -> bool { self.0 & Self::VIRTUAL != 0 }
    pub fn is_abstract(self) -> bool { self.0 & Self::ABSTRACT != 0 }
}

/// ECMA-335 §II.22.26 — MethodDef table row.
#[derive(Debug, Clone)]
pub struct MethodDefRow {
    /// RVA of the method body (0 for abstract/extern).
    pub rva: u32,
    pub impl_flags: MethodImplAttributes,
    pub flags: MethodAttributes,
    pub name: StringIndex,
    pub signature: BlobIndex,
    pub param_list: TableIndex,
}

// ── Table 0x08: Param ─────────────────────────────────────────────────────────

/// ECMA-335 §II.22.33 — Param table row.
#[derive(Debug, Clone)]
pub struct ParamRow {
    pub flags: u16,
    pub sequence: u16,
    pub name: StringIndex,
}

// ── Table 0x09: InterfaceImpl ─────────────────────────────────────────────────

/// ECMA-335 §II.22.23 — InterfaceImpl table row.
#[derive(Debug, Clone)]
pub struct InterfaceImplRow {
    pub class: TableIndex,
    pub interface: TypeDefOrRef,
}

// ── Table 0x0A: MemberRef ─────────────────────────────────────────────────────

/// ECMA-335 §II.22.25 — MemberRef table row.
#[derive(Debug, Clone)]
pub struct MemberRefRow {
    pub class: MemberRefParent,
    pub name: StringIndex,
    pub signature: BlobIndex,
}

// ── Table 0x0B: Constant ──────────────────────────────────────────────────────

/// ECMA-335 §II.22.9 — Constant element types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConstantType {
    Boolean   = 0x02,
    Char      = 0x03,
    I1        = 0x04,
    U1        = 0x05,
    I2        = 0x06,
    U2        = 0x07,
    I4        = 0x08,
    U4        = 0x09,
    I8        = 0x0A,
    U8        = 0x0B,
    R4        = 0x0C,
    R8        = 0x0D,
    String    = 0x0E,
    Class     = 0x12,
}

impl ConstantType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x02 => Some(Self::Boolean),  0x03 => Some(Self::Char),
            0x04 => Some(Self::I1),       0x05 => Some(Self::U1),
            0x06 => Some(Self::I2),       0x07 => Some(Self::U2),
            0x08 => Some(Self::I4),       0x09 => Some(Self::U4),
            0x0A => Some(Self::I8),       0x0B => Some(Self::U8),
            0x0C => Some(Self::R4),       0x0D => Some(Self::R8),
            0x0E => Some(Self::String),   0x12 => Some(Self::Class),
            _ => None,
        }
    }
}

/// ECMA-335 §II.22.9 — Constant table row.
#[derive(Debug, Clone)]
pub struct ConstantRow {
    pub type_: ConstantType,
    pub parent: HasConstant,
    pub value: BlobIndex,
}

// ── Table 0x0C: CustomAttribute ───────────────────────────────────────────────

/// ECMA-335 §II.22.10 — CustomAttribute table row.
#[derive(Debug, Clone)]
pub struct CustomAttributeRow {
    pub parent: HasCustomAttribute,
    pub type_: CustomAttributeType,
    pub value: BlobIndex,
}

// ── Table 0x0D: FieldMarshal ──────────────────────────────────────────────────

/// ECMA-335 §II.22.17 — FieldMarshal table row.
#[derive(Debug, Clone)]
pub struct FieldMarshalRow {
    pub parent: HasFieldMarshal,
    pub native_type: BlobIndex,
}

// ── Table 0x0E: DeclSecurity ──────────────────────────────────────────────────

/// ECMA-335 §II.22.11 — DeclSecurity table row.
#[derive(Debug, Clone)]
pub struct DeclSecurityRow {
    pub action: u16,
    pub parent: HasDeclSecurity,
    pub permission_set: BlobIndex,
}

// ── Table 0x0F: ClassLayout ───────────────────────────────────────────────────

/// ECMA-335 §II.22.8 — ClassLayout table row.
#[derive(Debug, Clone)]
pub struct ClassLayoutRow {
    pub packing_size: u16,
    pub class_size: u32,
    pub parent: TableIndex,
}

// ── Table 0x10: FieldLayout ───────────────────────────────────────────────────

/// ECMA-335 §II.22.16 — FieldLayout table row.
#[derive(Debug, Clone)]
pub struct FieldLayoutRow {
    pub offset: u32,
    pub field: TableIndex,
}

// ── Table 0x11: StandAloneSig ─────────────────────────────────────────────────

/// ECMA-335 §II.22.36 — StandAloneSig table row.
#[derive(Debug, Clone)]
pub struct StandAloneSigRow {
    pub signature: BlobIndex,
}

// ── Table 0x12: EventMap ──────────────────────────────────────────────────────

/// ECMA-335 §II.22.12 — EventMap table row.
#[derive(Debug, Clone)]
pub struct EventMapRow {
    pub parent: TableIndex,
    pub event_list: TableIndex,
}

// ── Table 0x14: Event ─────────────────────────────────────────────────────────

/// ECMA-335 §II.22.13 — Event table row.
#[derive(Debug, Clone)]
pub struct EventRow {
    pub event_flags: u16,
    pub name: StringIndex,
    pub event_type: Option<TypeDefOrRef>,
}

// ── Table 0x15: PropertyMap ───────────────────────────────────────────────────

/// ECMA-335 §II.22.35 — PropertyMap table row.
#[derive(Debug, Clone)]
pub struct PropertyMapRow {
    pub parent: TableIndex,
    pub property_list: TableIndex,
}

// ── Table 0x17: Property ──────────────────────────────────────────────────────

/// ECMA-335 §II.22.34 — Property table row.
#[derive(Debug, Clone)]
pub struct PropertyRow {
    pub flags: u16,
    pub name: StringIndex,
    pub type_: BlobIndex,
}

// ── Table 0x18: MethodSemantics ───────────────────────────────────────────────

/// ECMA-335 §II.22.28 — MethodSemantics flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodSemanticsAttributes(pub u16);

impl MethodSemanticsAttributes {
    pub const SETTER: u16      = 0x0001;
    pub const GETTER: u16      = 0x0002;
    pub const OTHER: u16       = 0x0004;
    pub const ADD_ON: u16      = 0x0008;
    pub const REMOVE_ON: u16   = 0x0010;
    pub const FIRE: u16        = 0x0020;
}

/// ECMA-335 §II.22.28 — MethodSemantics table row.
#[derive(Debug, Clone)]
pub struct MethodSemanticsRow {
    pub semantics: MethodSemanticsAttributes,
    pub method: TableIndex,
    pub association: HasSemantics,
}

// ── Table 0x19: MethodImpl ────────────────────────────────────────────────────

/// ECMA-335 §II.22.27 — MethodImpl table row.
#[derive(Debug, Clone)]
pub struct MethodImplRow {
    pub class: TableIndex,
    pub method_body: MethodDefOrRef,
    pub method_declaration: MethodDefOrRef,
}

// ── Table 0x1A: ModuleRef ─────────────────────────────────────────────────────

/// ECMA-335 §II.22.31 — ModuleRef table row.
#[derive(Debug, Clone)]
pub struct ModuleRefRow {
    pub name: StringIndex,
}

// ── Table 0x1B: TypeSpec ──────────────────────────────────────────────────────

/// ECMA-335 §II.22.39 — TypeSpec table row.
#[derive(Debug, Clone)]
pub struct TypeSpecRow {
    pub signature: BlobIndex,
}

// ── Table 0x1C: ImplMap ───────────────────────────────────────────────────────

/// ECMA-335 §II.22.22 — PInvoke mapping flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PInvokeAttributes(pub u16);

impl PInvokeAttributes {
    pub const NO_MANGLE: u16                = 0x0001;
    pub const CHAR_SET_MASK: u16            = 0x0006;
    pub const CHAR_SET_NOT_SPEC: u16        = 0x0000;
    pub const CHAR_SET_ANSI: u16            = 0x0002;
    pub const CHAR_SET_UNICODE: u16         = 0x0004;
    pub const CHAR_SET_AUTO: u16            = 0x0006;
    pub const SUPPORTS_LAST_ERROR: u16      = 0x0040;
    pub const CALL_CONV_MASK: u16           = 0x0700;
    pub const CALL_CONV_WINAPI: u16         = 0x0100;
    pub const CALL_CONV_CDECL: u16          = 0x0200;
    pub const CALL_CONV_STDCALL: u16        = 0x0300;
    pub const CALL_CONV_THISCALL: u16       = 0x0400;
    pub const CALL_CONV_FASTCALL: u16       = 0x0500;
}

/// ECMA-335 §II.22.22 — ImplMap table row.
#[derive(Debug, Clone)]
pub struct ImplMapRow {
    pub mapping_flags: PInvokeAttributes,
    pub member_forwarded: MemberForwarded,
    pub import_name: StringIndex,
    pub import_scope: TableIndex,
}

// ── Table 0x1D: FieldRva ──────────────────────────────────────────────────────

/// ECMA-335 §II.22.18 — FieldRva table row.
#[derive(Debug, Clone)]
pub struct FieldRvaRow {
    pub rva: u32,
    pub field: TableIndex,
}

// ── Table 0x20: Assembly ──────────────────────────────────────────────────────

/// ECMA-335 hash algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AssemblyHashAlgorithm {
    None   = 0x0000,
    Md5    = 0x8003,
    Sha1   = 0x8004,
    Sha256 = 0x800C,
    Sha384 = 0x800D,
    Sha512 = 0x800E,
}

impl AssemblyHashAlgorithm {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0x8003 => Self::Md5,  0x8004 => Self::Sha1,
            0x800C => Self::Sha256, 0x800D => Self::Sha384,
            0x800E => Self::Sha512, _ => Self::None,
        }
    }
}

/// ECMA-335 §II.22.2 — Assembly flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssemblyFlags(pub u32);

impl AssemblyFlags {
    pub const PUBLIC_KEY: u32              = 0x0001;
    pub const RETARGETABLE: u32            = 0x0100;
    pub const DISABLE_JIT_COMPILE_OPTIMIZER: u32 = 0x4000;
    pub const ENABLE_JIT_COMPILE_TRACKING: u32   = 0x8000;
    pub const CONTENT_TYPE_MASK: u32       = 0x0E00;
    pub const CONTENT_TYPE_DEFAULT: u32    = 0x0000;
    pub const CONTENT_TYPE_WINDOWS_RUNTIME: u32 = 0x0200;
}

/// ECMA-335 §II.22.2 — Assembly table row.
#[derive(Debug, Clone)]
pub struct AssemblyRow {
    pub hash_alg_id: AssemblyHashAlgorithm,
    pub major_version: u16,
    pub minor_version: u16,
    pub build_number: u16,
    pub revision_number: u16,
    pub flags: AssemblyFlags,
    pub public_key: BlobIndex,
    pub name: StringIndex,
    pub locale: StringIndex,
}

// ── Table 0x21: AssemblyProcessor ────────────────────────────────────────────

/// ECMA-335 §II.22.4 — AssemblyProcessor table row.
#[derive(Debug, Clone)]
pub struct AssemblyProcessorRow {
    pub processor: u32,
}

// ── Table 0x22: AssemblyOS ────────────────────────────────────────────────────

/// ECMA-335 §II.22.3 — AssemblyOS table row.
#[derive(Debug, Clone)]
pub struct AssemblyOsRow {
    pub os_platform_id: u32,
    pub os_major_version: u32,
    pub os_minor_version: u32,
}

// ── Table 0x23: AssemblyRef ───────────────────────────────────────────────────

/// ECMA-335 §II.22.5 — AssemblyRef table row.
#[derive(Debug, Clone)]
pub struct AssemblyRefRow {
    pub major_version: u16,
    pub minor_version: u16,
    pub build_number: u16,
    pub revision_number: u16,
    pub flags: AssemblyFlags,
    pub public_key_or_token: BlobIndex,
    pub name: StringIndex,
    pub locale: StringIndex,
    pub hash_value: BlobIndex,
}

// ── Table 0x24: AssemblyRefProcessor ─────────────────────────────────────────

/// ECMA-335 §II.22.7 — AssemblyRefProcessor table row.
#[derive(Debug, Clone)]
pub struct AssemblyRefProcessorRow {
    pub processor: u32,
    pub assembly_ref: TableIndex,
}

// ── Table 0x25: AssemblyRefOS ─────────────────────────────────────────────────

/// ECMA-335 §II.22.6 — AssemblyRefOS table row.
#[derive(Debug, Clone)]
pub struct AssemblyRefOsRow {
    pub os_platform_id: u32,
    pub os_major_version: u32,
    pub os_minor_version: u32,
    pub assembly_ref: TableIndex,
}

// ── Table 0x26: File ──────────────────────────────────────────────────────────

/// ECMA-335 §II.22.19 — File flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileAttributes(pub u32);

impl FileAttributes {
    pub const CONTAINS_METADATA: u32    = 0x0000;
    pub const CONTAINS_NO_METADATA: u32 = 0x0001;
}

/// ECMA-335 §II.22.19 — File table row.
#[derive(Debug, Clone)]
pub struct FileRow {
    pub flags: FileAttributes,
    pub name: StringIndex,
    pub hash_value: BlobIndex,
}

// ── Table 0x27: ExportedType ──────────────────────────────────────────────────

/// ECMA-335 §II.22.14 — ExportedType table row.
#[derive(Debug, Clone)]
pub struct ExportedTypeRow {
    pub flags: TypeAttributes,
    pub type_def_id: u32,
    pub type_name: StringIndex,
    pub type_namespace: StringIndex,
    pub implementation: Implementation,
}

// ── Table 0x28: ManifestResource ─────────────────────────────────────────────

/// ECMA-335 §II.22.24 — ManifestResource table row.
#[derive(Debug, Clone)]
pub struct ManifestResourceRow {
    pub offset: u32,
    pub flags: u32,
    pub name: StringIndex,
    pub implementation: Option<Implementation>,
}

// ── Table 0x29: NestedClass ───────────────────────────────────────────────────

/// ECMA-335 §II.22.32 — NestedClass table row.
#[derive(Debug, Clone)]
pub struct NestedClassRow {
    pub nested_class: TableIndex,
    pub enclosing_class: TableIndex,
}

// ── Table 0x2A: GenericParam ──────────────────────────────────────────────────

/// ECMA-335 §II.22.20 — Generic parameter variance/constraints flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenericParamAttributes(pub u16);

impl GenericParamAttributes {
    pub const VARIANCE_MASK: u16              = 0x0003;
    pub const NONE: u16                       = 0x0000;
    pub const COVARIANT: u16                  = 0x0001;
    pub const CONTRAVARIANT: u16              = 0x0002;
    pub const SPECIAL_CONSTRAINT_MASK: u16    = 0x001C;
    pub const REFERENCE_TYPE_CONSTRAINT: u16  = 0x0004;
    pub const NOT_NULLABLE_VALUE_TYPE: u16    = 0x0008;
    pub const DEFAULT_CONSTRUCTOR_CONSTRAINT: u16 = 0x0010;
}

/// ECMA-335 §II.22.20 — GenericParam table row.
#[derive(Debug, Clone)]
pub struct GenericParamRow {
    pub number: u16,
    pub flags: GenericParamAttributes,
    pub owner: TypeOrMethodDef,
    pub name: StringIndex,
}

// ── Table 0x2B: MethodSpec ────────────────────────────────────────────────────

/// ECMA-335 §II.22.29 — MethodSpec table row.
#[derive(Debug, Clone)]
pub struct MethodSpecRow {
    pub method: MethodDefOrRef,
    pub instantiation: BlobIndex,
}

// ── Table 0x2C: GenericParamConstraint ───────────────────────────────────────

/// ECMA-335 §II.22.21 — GenericParamConstraint table row.
#[derive(Debug, Clone)]
pub struct GenericParamConstraintRow {
    pub owner: TableIndex,
    pub constraint: TypeDefOrRef,
}

// ── Table ID enumeration ──────────────────────────────────────────────────────

/// ECMA-335 table IDs for all 45 defined tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TableId {
    Module               = 0x00,
    TypeRef              = 0x01,
    TypeDef              = 0x02,
    FieldPtr             = 0x03,
    Field                = 0x04,
    MethodPtr            = 0x05,
    MethodDef            = 0x06,
    ParamPtr             = 0x07,
    Param                = 0x08,
    InterfaceImpl        = 0x09,
    MemberRef            = 0x0A,
    Constant             = 0x0B,
    CustomAttribute      = 0x0C,
    FieldMarshal         = 0x0D,
    DeclSecurity         = 0x0E,
    ClassLayout          = 0x0F,
    FieldLayout          = 0x10,
    StandAloneSig        = 0x11,
    EventMap             = 0x12,
    EventPtr             = 0x13,
    Event                = 0x14,
    PropertyMap          = 0x15,
    PropertyPtr          = 0x16,
    Property             = 0x17,
    MethodSemantics      = 0x18,
    MethodImpl           = 0x19,
    ModuleRef            = 0x1A,
    TypeSpec             = 0x1B,
    ImplMap              = 0x1C,
    FieldRva             = 0x1D,
    EncLog               = 0x1E,
    EncMap               = 0x1F,
    Assembly             = 0x20,
    AssemblyProcessor    = 0x21,
    AssemblyOs           = 0x22,
    AssemblyRef          = 0x23,
    AssemblyRefProcessor = 0x24,
    AssemblyRefOs        = 0x25,
    File                 = 0x26,
    ExportedType         = 0x27,
    ManifestResource     = 0x28,
    NestedClass          = 0x29,
    GenericParam         = 0x2A,
    MethodSpec           = 0x2B,
    GenericParamConstraint = 0x2C,
}

impl TableId {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Module),           0x01 => Some(Self::TypeRef),
            0x02 => Some(Self::TypeDef),          0x03 => Some(Self::FieldPtr),
            0x04 => Some(Self::Field),            0x05 => Some(Self::MethodPtr),
            0x06 => Some(Self::MethodDef),        0x07 => Some(Self::ParamPtr),
            0x08 => Some(Self::Param),            0x09 => Some(Self::InterfaceImpl),
            0x0A => Some(Self::MemberRef),        0x0B => Some(Self::Constant),
            0x0C => Some(Self::CustomAttribute),  0x0D => Some(Self::FieldMarshal),
            0x0E => Some(Self::DeclSecurity),     0x0F => Some(Self::ClassLayout),
            0x10 => Some(Self::FieldLayout),      0x11 => Some(Self::StandAloneSig),
            0x12 => Some(Self::EventMap),         0x13 => Some(Self::EventPtr),
            0x14 => Some(Self::Event),            0x15 => Some(Self::PropertyMap),
            0x16 => Some(Self::PropertyPtr),      0x17 => Some(Self::Property),
            0x18 => Some(Self::MethodSemantics),  0x19 => Some(Self::MethodImpl),
            0x1A => Some(Self::ModuleRef),        0x1B => Some(Self::TypeSpec),
            0x1C => Some(Self::ImplMap),          0x1D => Some(Self::FieldRva),
            0x1E => Some(Self::EncLog),           0x1F => Some(Self::EncMap),
            0x20 => Some(Self::Assembly),         0x21 => Some(Self::AssemblyProcessor),
            0x22 => Some(Self::AssemblyOs),       0x23 => Some(Self::AssemblyRef),
            0x24 => Some(Self::AssemblyRefProcessor), 0x25 => Some(Self::AssemblyRefOs),
            0x26 => Some(Self::File),             0x27 => Some(Self::ExportedType),
            0x28 => Some(Self::ManifestResource), 0x29 => Some(Self::NestedClass),
            0x2A => Some(Self::GenericParam),     0x2B => Some(Self::MethodSpec),
            0x2C => Some(Self::GenericParamConstraint),
            _ => None,
        }
    }

    /// Number of bits needed to encode a coded index that includes this table.
    pub fn tag_bits(tables: &[Self]) -> u32 {
        let mut bits = 0u32;
        let mut n = tables.len() as u32;
        while n > 1 { bits += 1; n >>= 1; }
        bits
    }
}

// ── MetadataTablesHeader ──────────────────────────────────────────────────────

/// Decoded `#~` / `#-` stream header (ECMA-335 §II.24.2.6).
#[derive(Debug, Clone)]
pub struct MetadataTablesHeader {
    pub reserved: u32,
    pub major_version: u8,
    pub minor_version: u8,
    pub heap_sizes: u8,
    pub reserved2: u8,
    /// Bitmask of tables present (bit N = table N present).
    pub valid: u64,
    /// Bitmask of tables sorted by a key column.
    pub sorted: u64,
    /// Row counts for each present table, in table-ID order.
    pub row_counts: Vec<(TableId, u32)>,
}

impl MetadataTablesHeader {
    /// Return `true` if heap offsets for the given heap are wide (4 bytes).
    pub fn string_heap_wide(&self) -> bool { self.heap_sizes & 0x01 != 0 }
    pub fn guid_heap_wide(&self)   -> bool { self.heap_sizes & 0x02 != 0 }
    pub fn blob_heap_wide(&self)   -> bool { self.heap_sizes & 0x04 != 0 }

    /// Parse from a byte slice at `offset`.
    pub fn parse(data: &[u8], offset: usize) -> Option<(Self, usize)> {
        if offset + 24 > data.len() { return None; }
        let read_u32 = |o: usize| -> u32 {
            u32::from_le_bytes(data[o..o+4].try_into().unwrap_or([0;4]))
        };
        let read_u64 = |o: usize| -> u64 {
            u64::from_le_bytes(data[o..o+8].try_into().unwrap_or([0;8]))
        };

        let reserved     = read_u32(offset);
        let major        = data[offset + 4];
        let minor        = data[offset + 5];
        let heap_sizes   = data[offset + 6];
        let reserved2    = data[offset + 7];
        let valid        = read_u64(offset + 8);
        let sorted       = read_u64(offset + 16);

        let mut pos = offset + 24;
        let mut row_counts = Vec::with_capacity(valid.count_ones() as usize);
        for i in 0..64u8 {
            if valid & (1u64 << i) != 0 {
                if pos + 4 > data.len() { return None; }
                let rows = read_u32(pos);
                pos += 4;
                if let Some(id) = TableId::from_u8(i) {
                    row_counts.push((id, rows));
                } else {
                    row_counts.push((TableId::Module, rows)); // placeholder for unknown
                }
            }
        }

        Some((Self { reserved, major_version: major, minor_version: minor,
                     heap_sizes, reserved2, valid, sorted, row_counts }, pos))
    }

    /// Row count for `table`, or 0 if not present.
    pub fn row_count(&self, table: TableId) -> u32 {
        self.row_counts.iter().find(|(t,_)| *t == table).map_or(0, |(_,n)| *n)
    }
}

// ── MetadataTableStore ────────────────────────────────────────────────────────

/// Container holding parsed rows for all metadata tables.
#[derive(Debug, Default)]
pub struct MetadataTableStore {
    pub module:                Vec<ModuleRow>,
    pub type_ref:              Vec<TypeRefRow>,
    pub type_def:              Vec<TypeDefRow>,
    pub field:                 Vec<FieldRow>,
    pub method_def:            Vec<MethodDefRow>,
    pub param:                 Vec<ParamRow>,
    pub interface_impl:        Vec<InterfaceImplRow>,
    pub member_ref:            Vec<MemberRefRow>,
    pub constant:              Vec<ConstantRow>,
    pub custom_attribute:      Vec<CustomAttributeRow>,
    pub field_marshal:         Vec<FieldMarshalRow>,
    pub decl_security:         Vec<DeclSecurityRow>,
    pub class_layout:          Vec<ClassLayoutRow>,
    pub field_layout:          Vec<FieldLayoutRow>,
    pub stand_alone_sig:       Vec<StandAloneSigRow>,
    pub event_map:             Vec<EventMapRow>,
    pub event:                 Vec<EventRow>,
    pub property_map:          Vec<PropertyMapRow>,
    pub property:              Vec<PropertyRow>,
    pub method_semantics:      Vec<MethodSemanticsRow>,
    pub method_impl:           Vec<MethodImplRow>,
    pub module_ref:            Vec<ModuleRefRow>,
    pub type_spec:             Vec<TypeSpecRow>,
    pub impl_map:              Vec<ImplMapRow>,
    pub field_rva:             Vec<FieldRvaRow>,
    pub assembly:              Vec<AssemblyRow>,
    pub assembly_processor:    Vec<AssemblyProcessorRow>,
    pub assembly_os:           Vec<AssemblyOsRow>,
    pub assembly_ref:          Vec<AssemblyRefRow>,
    pub assembly_ref_processor: Vec<AssemblyRefProcessorRow>,
    pub assembly_ref_os:       Vec<AssemblyRefOsRow>,
    pub file:                  Vec<FileRow>,
    pub exported_type:         Vec<ExportedTypeRow>,
    pub manifest_resource:     Vec<ManifestResourceRow>,
    pub nested_class:          Vec<NestedClassRow>,
    pub generic_param:         Vec<GenericParamRow>,
    pub method_spec:           Vec<MethodSpecRow>,
    pub generic_param_constraint: Vec<GenericParamConstraintRow>,
}

impl MetadataTableStore {
    pub fn new() -> Self { Self::default() }

    /// Return the number of TypeDef rows.
    pub fn type_count(&self) -> usize { self.type_def.len() }
    /// Return the number of MethodDef rows.
    pub fn method_count(&self) -> usize { self.method_def.len() }
    /// Return the number of Field rows.
    pub fn field_count(&self) -> usize { self.field.len() }
    /// Return the number of AssemblyRef rows.
    pub fn assembly_ref_count(&self) -> usize { self.assembly_ref.len() }

    /// Lookup a TypeDef row by 1-based index.
    pub fn type_def(&self, idx: TableIndex) -> Option<&TypeDefRow> {
        idx.to_index().and_then(|i| self.type_def.get(i))
    }
    /// Lookup a MethodDef row by 1-based index.
    pub fn method_def(&self, idx: TableIndex) -> Option<&MethodDefRow> {
        idx.to_index().and_then(|i| self.method_def.get(i))
    }
    /// Lookup a Field row by 1-based index.
    pub fn field(&self, idx: TableIndex) -> Option<&FieldRow> {
        idx.to_index().and_then(|i| self.field.get(i))
    }

    /// Return all fields belonging to a TypeDef (using field_list range).
    pub fn fields_for_type(&self, type_idx: TableIndex) -> Vec<(TableIndex, &FieldRow)> {
        let td = match self.type_def(type_idx) { Some(t) => t, None => return vec![] };
        let start = td.field_list.0 as usize;
        let end = self.type_def.get(type_idx.0 as usize)
            .map_or(self.field.len() + 1, |next_td| next_td.field_list.0 as usize);
        (start..end.min(self.field.len() + 1))
            .filter_map(|i| {
                let idx = TableIndex(i as u32);
                self.field(idx).map(|f| (idx, f))
            })
            .collect()
    }

    /// Return all methods belonging to a TypeDef (using method_list range).
    pub fn methods_for_type(&self, type_idx: TableIndex) -> Vec<(TableIndex, &MethodDefRow)> {
        let td = match self.type_def(type_idx) { Some(t) => t, None => return vec![] };
        let start = td.method_list.0 as usize;
        let end = self.type_def.get(type_idx.0 as usize)
            .map_or(self.method_def.len() + 1, |next_td| next_td.method_list.0 as usize);
        (start..end.min(self.method_def.len() + 1))
            .filter_map(|i| {
                let idx = TableIndex(i as u32);
                self.method_def(idx).map(|m| (idx, m))
            })
            .collect()
    }

    /// Return all CustomAttribute rows for a given parent token kind.
    pub fn custom_attributes_for_method(&self, method_idx: TableIndex)
        -> Vec<&CustomAttributeRow>
    {
        self.custom_attribute.iter().filter(|ca| {
            matches!(ca.parent, HasCustomAttribute::MethodDef(i) if i == method_idx)
        }).collect()
    }

    /// Return all InterfaceImpl rows for a class.
    pub fn interfaces_for_type(&self, type_idx: TableIndex) -> Vec<&InterfaceImplRow> {
        self.interface_impl.iter().filter(|ii| ii.class == type_idx).collect()
    }

    /// Return all NestedClass rows where enclosing == `enc`.
    pub fn nested_types_of(&self, enc: TableIndex) -> Vec<TableIndex> {
        self.nested_class.iter()
            .filter(|nc| nc.enclosing_class == enc)
            .map(|nc| nc.nested_class)
            .collect()
    }

    /// Return all GenericParam rows owned by a TypeDef.
    pub fn generic_params_for_type(&self, type_idx: TableIndex) -> Vec<&GenericParamRow> {
        self.generic_param.iter().filter(|gp| {
            matches!(gp.owner, TypeOrMethodDef::TypeDef(i) if i == type_idx)
        }).collect()
    }

    /// Build a map from field RVA to field index.
    pub fn field_rva_map(&self) -> HashMap<u32, TableIndex> {
        self.field_rva.iter().map(|r| (r.rva, r.field)).collect()
    }

    /// Build a map from method RVA to method index.
    pub fn method_rva_map(&self) -> HashMap<u32, TableIndex> {
        self.method_def.iter().enumerate()
            .filter(|(_, m)| m.rva != 0)
            .map(|(i, m)| (m.rva, TableIndex((i + 1) as u32)))
            .collect()
    }
}

// ── TableStats ────────────────────────────────────────────────────────────────

/// Summary statistics for a loaded metadata store.
#[derive(Debug, Clone, Default)]
pub struct TableStats {
    pub type_defs: usize,
    pub method_defs: usize,
    pub fields: usize,
    pub type_refs: usize,
    pub member_refs: usize,
    pub custom_attributes: usize,
    pub assembly_refs: usize,
    pub generic_params: usize,
    pub method_specs: usize,
}

impl TableStats {
    pub fn from_store(store: &MetadataTableStore) -> Self {
        Self {
            type_defs:         store.type_def.len(),
            method_defs:       store.method_def.len(),
            fields:            store.field.len(),
            type_refs:         store.type_ref.len(),
            member_refs:       store.member_ref.len(),
            custom_attributes: store.custom_attribute.len(),
            assembly_refs:     store.assembly_ref.len(),
            generic_params:    store.generic_param.len(),
            method_specs:      store.method_spec.len(),
        }
    }
}

impl fmt::Display for TableStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "TypeDef={} MethodDef={} Field={} TypeRef={} MemberRef={} \
             CustomAttr={} AssemblyRef={} GenericParam={} MethodSpec={}",
            self.type_defs, self.method_defs, self.fields,
            self.type_refs, self.member_refs, self.custom_attributes,
            self.assembly_refs, self.generic_params, self.method_specs)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_index_null() {
        assert!(TableIndex::NULL.is_null());
        assert_eq!(TableIndex::NULL.to_index(), None);
    }

    #[test]
    fn table_index_non_null() {
        let idx = TableIndex(1);
        assert!(!idx.is_null());
        assert_eq!(idx.to_index(), Some(0));
    }

    #[test]
    fn type_attributes_public() {
        let a = TypeAttributes(TypeAttributes::PUBLIC);
        assert!(a.is_public());
        assert!(!a.is_interface());
    }

    #[test]
    fn type_attributes_interface() {
        let a = TypeAttributes(TypeAttributes::INTERFACE);
        assert!(a.is_interface());
    }

    #[test]
    fn method_attributes_virtual_public() {
        let a = MethodAttributes(MethodAttributes::PUBLIC | MethodAttributes::VIRTUAL);
        assert!(a.is_public());
        assert!(a.is_virtual());
        assert!(!a.is_static());
    }

    #[test]
    fn field_attributes_static_literal() {
        let a = FieldAttributes(FieldAttributes::STATIC | FieldAttributes::LITERAL | FieldAttributes::PUBLIC);
        assert!(a.is_static());
        assert!(a.is_literal());
        assert!(a.is_public());
    }

    #[test]
    fn table_id_roundtrip() {
        for id in [TableId::Module, TableId::TypeDef, TableId::MethodDef,
                   TableId::Assembly, TableId::GenericParam, TableId::MethodSpec] {
            assert_eq!(TableId::from_u8(id as u8), Some(id));
        }
    }

    #[test]
    fn table_id_unknown() {
        assert_eq!(TableId::from_u8(0xFF), None);
    }

    #[test]
    fn store_empty() {
        let store = MetadataTableStore::new();
        assert_eq!(store.type_count(), 0);
        assert_eq!(store.method_count(), 0);
    }

    #[test]
    fn table_stats_from_empty_store() {
        let store = MetadataTableStore::default();
        let stats = TableStats::from_store(&store);
        assert_eq!(stats.type_defs, 0);
    }

    #[test]
    fn constant_type_roundtrip() {
        assert_eq!(ConstantType::from_u8(0x08), Some(ConstantType::I4));
        assert_eq!(ConstantType::from_u8(0x0E), Some(ConstantType::String));
        assert_eq!(ConstantType::from_u8(0xFF), None);
    }

    #[test]
    fn assembly_hash_alg_from_u32() {
        assert_eq!(AssemblyHashAlgorithm::from_u32(0x8004), AssemblyHashAlgorithm::Sha1);
        assert_eq!(AssemblyHashAlgorithm::from_u32(0x0000), AssemblyHashAlgorithm::None);
    }

    #[test]
    fn generic_param_flags() {
        let f = GenericParamAttributes(GenericParamAttributes::COVARIANT);
        assert_eq!(f.0 & GenericParamAttributes::VARIANCE_MASK, GenericParamAttributes::COVARIANT);
    }

    #[test]
    fn method_semantics_flags() {
        let f = MethodSemanticsAttributes(MethodSemanticsAttributes::GETTER);
        assert_eq!(f.0, 0x0002);
    }

    #[test]
    fn table_stats_display() {
        let s = TableStats::default();
        let txt = s.to_string();
        assert!(txt.contains("TypeDef=0"));
    }

    #[test]
    fn store_field_rva_map_empty() {
        let store = MetadataTableStore::default();
        assert!(store.field_rva_map().is_empty());
    }
}
