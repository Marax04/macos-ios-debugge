//! `CodeView` type records.
//!
//! Data model for the `LF_` leaf types found in a `.debug$T` or `TPI` stream.
//!
//! This module defines the record types and predicates only; it contains no
//! byte-level parser. To obtain records from bytes, use
//! [`crate::parse_cv_type_records`] or
//! [`crate::codeview_types::parse_type_record`] and map into this model.

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
    Modifier = 0x1001,
    Pointer = 0x1002,
    Array = 0x1003,
    Class = 0x1004,
    Structure = 0x1005,
    Union = 0x1006,
    Enum = 0x1007,
    Procedure = 0x1008,
    MFunction = 0x1009,
    Cobol0 = 0x100A,
    Barray = 0x100B,
    Label = 0x100C,
    Null = 0x100D,
    NotTran = 0x100E,
    DimArray = 0x100F,
    VFTPath = 0x1010,
    // Field list members
    FieldList = 0x1203,
    BClass = 0x1400,   // base class
    VBClass = 0x1401,  // virtual base class
    IVBClass = 0x1402, // indirect virtual base class
    FriendFcn = 0x1403,
    Index = 0x1404,
    Member = 0x1405,
    STMember = 0x1406, // static member
    Method = 0x1407,
    NestType = 0x1408,
    VFuncTab = 0x1409,
    FriendCls = 0x140A,
    OneMethod = 0x140B,
    VFuncOff = 0x140C,
    NestTypeEx = 0x140D,
    MemberModify = 0x140E,
    Managed = 0x140F,
    // Numeric leaves
    Char = 0x8000,
    Short = 0x8001,
    UShort = 0x8002,
    Long_ = 0x8003,
    ULong = 0x8004,
    Real32 = 0x8005,
    Real64 = 0x8006,
    Real80 = 0x8007,
    Real128 = 0x8008,
    Quadword = 0x8009,
    UQuadword = 0x800A,
    Real48 = 0x800B,
    Complex32 = 0x800C,
    Complex64 = 0x800D,
    Complex80 = 0x800E,
    Complex128 = 0x800F,
    Varstring = 0x8010,
}

impl LeafKind {
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
pub enum PtrKind {
    Near16,
    Far16,
    Huge16,
    Based,
    Near32,
    Far32,
    Ptr64,
    Near128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtrMode {
    Ptr,
    LValueRef,
    PointerToMember,
    PointerToMemberFunction,
    RValueRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfPointer {
    pub referent: TypeIndex,
    pub kind: PtrKind,
    pub mode: PtrMode,
    /// Flags: bit 0 = flat32, bit 1 = volatile, bit 2 = const, bit 3 = unaligned, bit 4 = restrict.
    pub flags: u8,
    pub size: u8,
}

impl LfPointer {
    #[must_use]
    pub const fn is_flat32(&self) -> bool { self.flags & 0x01 != 0 }
    #[must_use]
    pub const fn is_volatile(&self) -> bool { self.flags & 0x02 != 0 }
    #[must_use]
    pub const fn is_const(&self) -> bool { self.flags & 0x04 != 0 }
    #[must_use]
    pub const fn is_unaligned(&self) -> bool { self.flags & 0x08 != 0 }
    #[must_use]
    pub const fn is_restrict(&self) -> bool { self.flags & 0x10 != 0 }
}

// ─────────────────────────────────────────────────────────────────────────────
// Array record
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfArray {
    pub element_type: TypeIndex,
    pub index_type: TypeIndex,
    pub byte_size: u64,
    pub name: Option<String>,
}

impl LfArray {
    /// Infer element count if element size is known.
    #[must_use]
    pub const fn count(&self, element_size: u64) -> Option<u64> {
        if element_size == 0 {
            None
        } else {
            Some(self.byte_size / element_size)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Class / Structure / Union records
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfClass {
    pub count: u16,
    pub field_list: TypeIndex,
    pub derived_from: TypeIndex,
    pub vshape: TypeIndex,
    pub byte_size: u64,
    pub name: String,
    pub unique_name: Option<String>,
    /// Flags: bit 0 = `forward_ref`, bit 1 = scoped, bit 2 = packed, bit 3 = `has_ctor`,
    /// bit 4 = `has_overloaded_ops`, bit 5 = nested, bit 6 = `has_nested`, bit 7 = intrinsic.
    pub flags: u8,
}

impl LfClass {
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

    #[must_use]
    pub const fn is_forward_ref(&self) -> bool { self.flags & 0x01 != 0 }
    #[must_use]
    pub const fn is_scoped(&self) -> bool { self.flags & 0x02 != 0 }
    #[must_use]
    pub const fn is_packed(&self) -> bool { self.flags & 0x04 != 0 }
    #[must_use]
    pub const fn has_ctor(&self) -> bool { self.flags & 0x08 != 0 }
    #[must_use]
    pub const fn has_overloaded_ops(&self) -> bool { self.flags & 0x10 != 0 }
    #[must_use]
    pub const fn is_nested(&self) -> bool { self.flags & 0x20 != 0 }
    #[must_use]
    pub const fn has_nested(&self) -> bool { self.flags & 0x40 != 0 }
    #[must_use]
    pub const fn is_intrinsic(&self) -> bool { self.flags & 0x80 != 0 }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enum record
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfEnum {
    pub count: u16,
    pub underlying_type: TypeIndex,
    pub field_list: TypeIndex,
    pub name: String,
    pub unique_name: Option<String>,
    pub is_forward_ref: bool,
    pub is_scoped: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Procedure / MFunction records
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfProcedure {
    pub return_type: TypeIndex,
    pub calling_conv: u8,
    pub attributes: u8,
    pub param_count: u16,
    pub arg_list: TypeIndex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMFunction {
    pub return_type: TypeIndex,
    pub class_type: TypeIndex,
    pub this_type: TypeIndex,
    pub calling_conv: u8,
    pub attributes: u8,
    pub param_count: u16,
    pub arg_list: TypeIndex,
    pub this_adjust: i32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Field list members
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMember {
    pub field_type: TypeIndex,
    pub offset: u64,
    pub name: String,
    pub access: AccessKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfSTMember {
    pub field_type: TypeIndex,
    pub name: String,
    pub access: AccessKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMethod {
    pub count: u16,
    pub method_list: TypeIndex,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfNestType {
    pub nested_type: TypeIndex,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfOneMethod {
    pub method_type: TypeIndex,
    pub vtable_offset: Option<i32>,
    pub name: String,
    pub access: AccessKind,
    pub method_kind: MethodKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfBClass {
    pub base_type: TypeIndex,
    pub offset: u64,
    pub access: AccessKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfVBClass {
    pub base_type: TypeIndex,
    pub vbptr_type: TypeIndex,
    pub vb_ptr_offset: u64,
    pub vb_index_offset: u64,
    pub access: AccessKind,
    pub is_indirect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMethodList {
    pub methods: Vec<LfMethodListEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfMethodListEntry {
    pub method_type: TypeIndex,
    pub access: AccessKind,
    pub kind: MethodKind,
    pub vtable_offset: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessKind {
    None,
    Private,
    Protected,
    Public,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MethodKind {
    Vanilla,
    Virtual,
    Static,
    Friend,
    Intro,
    PureVirtual,
    PureIntro,
}

// ─────────────────────────────────────────────────────────────────────────────
// Modifier record
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfModifier {
    pub modified_type: TypeIndex,
    pub is_const: bool,
    pub is_volatile: bool,
    pub is_unaligned: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// CvTypeRecord — unified enum
// ─────────────────────────────────────────────────────────────────────────────

/// A single `CodeView` type record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CvTypeRecord {
    Modifier(LfModifier),
    Pointer(LfPointer),
    Array(LfArray),
    Class(LfClass),
    Structure(LfClass),
    Union(LfClass),
    Enum(LfEnum),
    Procedure(LfProcedure),
    MFunction(LfMFunction),
    Member(LfMember),
    STMember(LfSTMember),
    Method(LfMethod),
    NestType(LfNestType),
    OneMethod(LfOneMethod),
    MethodList(LfMethodList),
    BClass(LfBClass),
    VBClass(LfVBClass),
    Unknown { leaf_kind: u16, data: Vec<u8> },
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

    #[must_use]
    pub fn get(&self, idx: &TypeIndex) -> Option<&CvTypeRecord> {
        self.records.get(idx)
    }

    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<(&TypeIndex, &CvTypeRecord)> {
        let idx = self.by_name.get(name)?;
        self.records.get(idx).map(|r| (idx, r))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Iterate over all (index, record) pairs.
    #[must_use]
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
