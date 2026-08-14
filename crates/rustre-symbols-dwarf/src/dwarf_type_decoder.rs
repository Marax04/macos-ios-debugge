//! DWARF type decoder — decodes all `DW_TAG`_* type entries from DWARF debug info.
//!
//! Provides:
//! - `DwarfTypeDecoder` — top-level decoder
//! - `CompositeType`    — struct, class, union
//! - `SubroutineType`   — function/method type
//! - `BaseType`         — built-in primitive
//! - `ArrayType`        — array type
//! - `EnumerationType`  — enum
//! - `TypedefType`      — typedef alias
//!
//! # Parallel implementations
//!
//! This crate ships more than one type-tree implementation: see also `dwarf_type_parser` and `dwarf_type_reader`.
//! None of them is wired into [`crate::DwarfReader`], which uses its own
//! inline copy, so each carries an independent bug set and a fix applied
//! here does not propagate. Pick one deliberately and stay on it.

use std::collections::HashMap;
use std::fmt;

// ── DWARF constants (subset) ──────────────────────────────────────────────────

/// DWARF tag constants.
pub mod tag {
    /// `DW_TAG_base_type` (0x24).
    pub const DW_TAG_BASE_TYPE: u16 = 0x24;
    /// `DW_TAG_pointer_type` (0x0f).
    pub const DW_TAG_POINTER_TYPE: u16 = 0x0F;
    /// `DW_TAG_reference_type` (0x10).
    pub const DW_TAG_REFERENCE_TYPE: u16 = 0x10;
    /// `DW_TAG_rvalue_reference_type` (0x42).
    pub const DW_TAG_RVALUE_REF_TYPE: u16 = 0x42;
    /// `DW_TAG_const_type` (0x26).
    pub const DW_TAG_CONST_TYPE: u16 = 0x26;
    /// `DW_TAG_volatile_type` (0x35).
    pub const DW_TAG_VOLATILE_TYPE: u16 = 0x35;
    /// `DW_TAG_restrict_type` (0x37).
    pub const DW_TAG_RESTRICT_TYPE: u16 = 0x37;
    /// `DW_TAG_typedef` (0x16).
    pub const DW_TAG_TYPEDEF: u16 = 0x16;
    /// `DW_TAG_array_type` (0x01).
    pub const DW_TAG_ARRAY_TYPE: u16 = 0x01;
    /// `DW_TAG_subrange_type` (0x21).
    pub const DW_TAG_SUBRANGE_TYPE: u16 = 0x21;
    /// `DW_TAG_structure_type` (0x13).
    pub const DW_TAG_STRUCTURE_TYPE: u16 = 0x13;
    /// `DW_TAG_class_type` (0x02).
    pub const DW_TAG_CLASS_TYPE: u16 = 0x02;
    /// `DW_TAG_union_type` (0x17).
    pub const DW_TAG_UNION_TYPE: u16 = 0x17;
    /// `DW_TAG_enumeration_type` (0x04).
    pub const DW_TAG_ENUMERATION_TYPE: u16 = 0x04;
    /// `DW_TAG_enumerator` (0x28).
    pub const DW_TAG_ENUMERATOR: u16 = 0x28;
    /// `DW_TAG_member` (0x0d).
    pub const DW_TAG_MEMBER: u16 = 0x0D;
    /// `DW_TAG_inheritance` (0x1c).
    pub const DW_TAG_INHERITANCE: u16 = 0x1C;
    /// `DW_TAG_subprogram` (0x2e).
    pub const DW_TAG_SUBPROGRAM: u16 = 0x2E;
    /// `DW_TAG_subroutine_type` (0x15).
    pub const DW_TAG_SUBROUTINE_TYPE: u16 = 0x15;
    /// `DW_TAG_formal_parameter` (0x05).
    pub const DW_TAG_FORMAL_PARAMETER: u16 = 0x05;
    /// `DW_TAG_unspecified_parameters` (0x18).
    pub const DW_TAG_UNSPECIFIED_PARAMS: u16 = 0x18;
    /// `DW_TAG_namespace` (0x39).
    pub const DW_TAG_NAMESPACE: u16 = 0x39;
    /// `DW_TAG_template_type_parameter` (0x2f).
    pub const DW_TAG_TEMPLATE_TYPE_PARAM: u16 = 0x2F;
    /// `DW_TAG_atomic_type` (0x47).
    pub const DW_TAG_ATOMIC_TYPE: u16 = 0x47;
    /// `DW_TAG_immutable_type` (0x4b).
    pub const DW_TAG_IMMUTABLE_TYPE: u16 = 0x4B;
    /// `DW_TAG_ptr_to_member_type` (0x1f).
    pub const DW_TAG_PTR_TO_MEMBER_TYPE: u16 = 0x1F;
    /// `DW_TAG_set_type` (0x20).
    ///
    /// This was 0x11, which is `DW_TAG_compile_unit` — the value this crate's
    /// own `lib.rs` assigns to `DW_TAG_COMPILE_UNIT`.  A consumer of this
    /// public constant would have classified every compile-unit DIE as a Pascal
    /// set type.  The neighbouring constants in this same table bracket the
    /// correct value: `DW_TAG_ptr_to_member_type` is 0x1F and
    /// `DW_TAG_subrange_type` is 0x21.
    pub const DW_TAG_SET_TYPE: u16 = 0x20;
    /// `DW_TAG_string_type` (0x12).
    pub const DW_TAG_STRING_TYPE: u16 = 0x12;
    /// `DW_TAG_file_type` (0x29).
    pub const DW_TAG_FILE_TYPE: u16 = 0x29;
    /// `DW_TAG_unspecified_type` (0x3b).
    pub const DW_TAG_UNSPECIFIED_TYPE: u16 = 0x3B;
}

/// DWARF encoding for base types (`DW_ATE`_*).
pub mod encoding {
    /// No encoding / void (0x00).
    pub const DW_ATE_VOID: u8 = 0x00;
    /// `DW_ATE_address` (0x01).
    pub const DW_ATE_ADDRESS: u8 = 0x01;
    /// `DW_ATE_boolean` (0x02).
    pub const DW_ATE_BOOLEAN: u8 = 0x02;
    /// `DW_ATE_complex_float` (0x03).
    pub const DW_ATE_COMPLEX_FLOAT: u8 = 0x03;
    /// `DW_ATE_float` (0x04).
    pub const DW_ATE_FLOAT: u8 = 0x04;
    /// `DW_ATE_signed` (0x05).
    pub const DW_ATE_SIGNED: u8 = 0x05;
    /// `DW_ATE_signed_char` (0x06).
    pub const DW_ATE_SIGNED_CHAR: u8 = 0x06;
    /// `DW_ATE_unsigned` (0x07).
    pub const DW_ATE_UNSIGNED: u8 = 0x07;
    /// `DW_ATE_unsigned_char` (0x08).
    pub const DW_ATE_UNSIGNED_CHAR: u8 = 0x08;
    /// `DW_ATE_imaginary_float` (0x09).
    pub const DW_ATE_IMAGINARY_FLOAT: u8 = 0x09;
    /// `DW_ATE_packed_decimal` (0x0a).
    pub const DW_ATE_PACKED_DECIMAL: u8 = 0x0a;
    /// `DW_ATE_numeric_string` (0x0b).
    pub const DW_ATE_NUMERIC_STRING: u8 = 0x0b;
    /// `DW_ATE_edited` (0x0c).
    pub const DW_ATE_EDITED: u8 = 0x0c;
    /// `DW_ATE_signed_fixed` (0x0d).
    pub const DW_ATE_SIGNED_FIXED: u8 = 0x0d;
    /// `DW_ATE_unsigned_fixed` (0x0e).
    pub const DW_ATE_UNSIGNED_FIXED: u8 = 0x0e;
    /// `DW_ATE_decimal_float` (0x0f).
    pub const DW_ATE_DECIMAL_FLOAT: u8 = 0x0f;
    /// `DW_ATE_UTF` (0x10).
    pub const DW_ATE_UTF: u8 = 0x10;
}

/// DWARF attribute tag.
pub mod attr {
    /// `DW_AT_name` (0x03).
    pub const DW_AT_NAME: u16 = 0x03;
    /// `DW_AT_byte_size` (0x0b).
    pub const DW_AT_BYTE_SIZE: u16 = 0x0b;
    /// `DW_AT_bit_offset` (0x0c).
    pub const DW_AT_BIT_OFFSET: u16 = 0x0c;
    /// `DW_AT_bit_size` (0x0d).
    pub const DW_AT_BIT_SIZE: u16 = 0x0d;
    /// `DW_AT_encoding` (0x3e).
    pub const DW_AT_ENCODING: u16 = 0x3e;
    /// `DW_AT_type` (0x49).
    pub const DW_AT_TYPE: u16 = 0x49;
    /// `DW_AT_external` (0x3f).
    pub const DW_AT_EXTERNAL: u16 = 0x3f;
    /// `DW_AT_count` (0x37).
    pub const DW_AT_COUNT: u16 = 0x37;
    /// `DW_AT_lower_bound` (0x22).
    pub const DW_AT_LOWER_BOUND: u16 = 0x22;
    /// `DW_AT_upper_bound` (0x2f).
    pub const DW_AT_UPPER_BOUND: u16 = 0x2f;
    /// `DW_AT_data_member_location` (0x38).
    pub const DW_AT_DATA_MEMBER_LOCATION: u16 = 0x38;
    /// `DW_AT_accessibility` (0x32).
    pub const DW_AT_ACCESSIBILITY: u16 = 0x32;
    /// `DW_AT_virtuality` (0x4c).
    pub const DW_AT_VIRTUALITY: u16 = 0x4c;
    /// `DW_AT_declaration` (0x3c).
    pub const DW_AT_DECLARATION: u16 = 0x3c;
}

// ── Die — simplified DIE representation ──────────────────────────────────────

/// Simplified DWARF DIE representation.
#[derive(Debug, Clone, Default)]
pub struct Die {
    /// DIE offset within `.debug_info`.
    pub offset: u64,
    /// `DW_TAG_*` value.
    pub tag: u16,
    /// `DW_AT_name`.
    pub name: Option<String>,
    /// `DW_AT_byte_size`.
    pub byte_size: Option<u64>,
    /// `DW_AT_encoding` (`DW_ATE_*`).
    pub encoding: Option<u8>,
    /// `DW_AT_type` → referenced DIE offset.
    pub type_ref: Option<u64>,
    /// `DW_AT_bit_size`.
    pub bit_size: Option<u64>,
    /// `DW_AT_bit_offset`.
    pub bit_offset: Option<u64>,
    /// `DW_AT_data_member_location`.
    pub data_member_location: Option<u64>,
    /// `DW_AT_const_value` (enumerator value).
    pub const_value: Option<i64>,
    /// `DW_AT_lower_bound` (array subrange).
    pub lower_bound: Option<u64>,
    /// `DW_AT_upper_bound` (array subrange).
    pub upper_bound: Option<u64>,
    /// `DW_AT_count` (array subrange).
    pub count: Option<u64>,
    /// `DW_AT_accessibility` (1=public, 2=protected, 3=private).
    pub accessibility: Option<u8>,
    /// `DW_AT_declaration` — true for forward declarations.
    pub declaration: bool,
    /// Child DIEs (members, enumerators, parameters, subranges).
    pub children: Vec<Self>,
}

impl Die {
    /// Create a minimal DIE with a tag and offset.
    #[must_use]
    pub fn new(offset: u64, tag: u16) -> Self {
        Self {
            offset,
            tag,
            ..Default::default()
        }
    }
}

// ── Decoded type variants ─────────────────────────────────────────────────────

/// A decoded DWARF type.
#[derive(Debug, Clone)]
pub enum DwarfType {
    /// `DW_TAG_base_type` primitive.
    Base(BaseType),
    /// `DW_TAG_pointer_type`.
    Pointer(PointerType),
    /// `DW_TAG_reference_type` / `DW_TAG_rvalue_reference_type`.
    Reference(ReferenceType),
    /// `DW_TAG_const_type` qualifier.
    Const(ConstType),
    /// `DW_TAG_volatile_type` qualifier.
    Volatile(VolatileType),
    /// `DW_TAG_typedef` alias.
    Typedef(TypedefType),
    /// `DW_TAG_array_type`.
    Array(ArrayType),
    /// `DW_TAG_structure_type`.
    Structure(CompositeType),
    /// `DW_TAG_class_type`.
    Class(CompositeType),
    /// `DW_TAG_union_type`.
    Union(CompositeType),
    /// `DW_TAG_enumeration_type`.
    Enumeration(EnumerationType),
    /// `DW_TAG_subroutine_type`.
    Subroutine(SubroutineType),
    /// `DW_TAG_ptr_to_member_type`.
    PtrToMember(PtrToMemberType),
    /// `DW_TAG_unspecified_type`.
    Unspecified {
        /// Name of the unspecified type (e.g. `decltype(nullptr)`).
        name: String,
    },
    /// Any other tag not handled above.
    Unknown {
        /// The raw `DW_TAG_*` value.
        tag: u16,
        /// Optional `DW_AT_name`.
        name: Option<String>,
    },
}

impl DwarfType {
    /// Human-readable C-style type name.
    #[must_use]
    pub fn c_name(&self) -> String {
        match self {
            Self::Base(b) => b.c_name(),
            Self::Pointer(_) => "void*".to_string(),
            Self::Reference(_) => "void&".to_string(),
            Self::Const(c) => format!("const {}", c.underlying_name()),
            Self::Volatile(v) => format!("volatile {}", v.underlying_name()),
            Self::Typedef(t) => t.name.clone(),
            Self::Array(a) => a.element_type_name(),
            Self::Structure(s) => format!("struct {}", s.name),
            Self::Class(c) => format!("class {}", c.name),
            Self::Union(u) => format!("union {}", u.name),
            Self::Enumeration(e) => format!("enum {}", e.name),
            Self::Subroutine(_) => "fn(...)".to_string(),
            Self::PtrToMember(_) => "<ptr-to-member>".to_string(),
            Self::Unspecified { name } => name.clone(),
            Self::Unknown { tag, name } => name
                .as_deref()
                .unwrap_or(&format!("unknown_tag_{tag:#06x}"))
                .to_string(),
        }
    }

    /// DIE tag for this type.
    #[must_use]
    pub const fn tag(&self) -> u16 {
        match self {
            Self::Base(_) => tag::DW_TAG_BASE_TYPE,
            Self::Pointer(_) => tag::DW_TAG_POINTER_TYPE,
            Self::Reference(_) => tag::DW_TAG_REFERENCE_TYPE,
            Self::Const(_) => tag::DW_TAG_CONST_TYPE,
            Self::Volatile(_) => tag::DW_TAG_VOLATILE_TYPE,
            Self::Typedef(_) => tag::DW_TAG_TYPEDEF,
            Self::Array(_) => tag::DW_TAG_ARRAY_TYPE,
            Self::Structure(_) => tag::DW_TAG_STRUCTURE_TYPE,
            Self::Class(_) => tag::DW_TAG_CLASS_TYPE,
            Self::Union(_) => tag::DW_TAG_UNION_TYPE,
            Self::Enumeration(_) => tag::DW_TAG_ENUMERATION_TYPE,
            Self::Subroutine(_) => tag::DW_TAG_SUBROUTINE_TYPE,
            Self::PtrToMember(_) => tag::DW_TAG_PTR_TO_MEMBER_TYPE,
            Self::Unspecified { .. } => tag::DW_TAG_UNSPECIFIED_TYPE,
            Self::Unknown { tag: t, .. } => *t,
        }
    }
}

impl fmt::Display for DwarfType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.c_name())
    }
}

// ── BaseType ──────────────────────────────────────────────────────────────────

/// A DWARF base type (`DW_TAG_BASE_TYPE`).
#[derive(Debug, Clone)]
pub struct BaseType {
    /// `DW_AT_name` of the base type.
    pub name: String,
    /// `DW_AT_byte_size`.
    pub byte_size: u64,
    /// `DW_AT_encoding` (`DW_ATE_*`).
    pub encoding: u8,
}

impl BaseType {
    /// C-style name for the base type.
    #[must_use]
    pub fn c_name(&self) -> String {
        match self.encoding {
            encoding::DW_ATE_VOID => "void".to_string(),
            encoding::DW_ATE_BOOLEAN => "bool".to_string(),
            encoding::DW_ATE_FLOAT => match self.byte_size {
                4 => "float".to_string(),
                8 => "double".to_string(),
                16 => "long double".to_string(),
                _ => self.name.clone(),
            },
            encoding::DW_ATE_SIGNED => match self.byte_size {
                1 => "int8_t".to_string(),
                2 => "int16_t".to_string(),
                4 => "int32_t".to_string(),
                8 => "int64_t".to_string(),
                _ => self.name.clone(),
            },
            encoding::DW_ATE_UNSIGNED => match self.byte_size {
                1 => "uint8_t".to_string(),
                2 => "uint16_t".to_string(),
                4 => "uint32_t".to_string(),
                8 => "uint64_t".to_string(),
                _ => self.name.clone(),
            },
            encoding::DW_ATE_SIGNED_CHAR | encoding::DW_ATE_UNSIGNED_CHAR => "char".to_string(),
            _ => self.name.clone(),
        }
    }

    /// Whether this is a floating-point type.
    #[must_use]
    pub const fn is_float(&self) -> bool {
        self.encoding == encoding::DW_ATE_FLOAT
    }

    /// Whether this is a signed integer type.
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        matches!(
            self.encoding,
            encoding::DW_ATE_SIGNED | encoding::DW_ATE_SIGNED_CHAR
        )
    }
}

// ── PointerType / ReferenceType ───────────────────────────────────────────────

/// A pointer type (`DW_TAG_pointer_type`).
#[derive(Debug, Clone)]
pub struct PointerType {
    /// `DW_AT_type` DIE offset of the pointee; `None` = `void*`.
    pub pointee_offset: Option<u64>,
    /// Pointer size in bytes.
    pub byte_size: u64,
}

/// A C++ reference type (`DW_TAG_reference_type` / `DW_TAG_rvalue_reference_type`).
#[derive(Debug, Clone)]
pub struct ReferenceType {
    /// `DW_AT_type` DIE offset of the referent.
    pub pointee_offset: Option<u64>,
    /// True for rvalue references (`&&`).
    pub is_rvalue: bool,
}

impl PointerType {
    /// Whether this is a `void*` (no pointee DIE).
    #[must_use]
    pub const fn is_void_ptr(&self) -> bool {
        self.pointee_offset.is_none()
    }
}

// ── ConstType / VolatileType ──────────────────────────────────────────────────

/// A `const` qualifier (`DW_TAG_const_type`).
#[derive(Debug, Clone)]
pub struct ConstType {
    /// `DW_AT_type` DIE offset of the qualified type.
    pub underlying_offset: Option<u64>,
}

impl ConstType {
    /// Human-readable name of the qualified type.
    #[must_use]
    pub fn underlying_name(&self) -> String {
        self.underlying_offset
            .map_or_else(|| "const void".to_string(), |o| format!("const <type@{o:#x}>"))
    }
}

/// A `volatile` qualifier (`DW_TAG_volatile_type`).
#[derive(Debug, Clone)]
pub struct VolatileType {
    /// `DW_AT_type` DIE offset of the qualified type.
    pub underlying_offset: Option<u64>,
}

impl VolatileType {
    /// Human-readable name of the qualified type.
    #[must_use]
    pub fn underlying_name(&self) -> String {
        self.underlying_offset
            .map_or_else(|| "void".to_string(), |o| format!("<type@{o:#x}>"))
    }
}

// ── TypedefType ───────────────────────────────────────────────────────────────

/// A typedef alias (`DW_TAG_typedef`).
#[derive(Debug, Clone)]
pub struct TypedefType {
    /// Typedef name (`DW_AT_name`).
    pub name: String,
    /// `DW_AT_type` DIE offset of the aliased type.
    pub underlying_offset: Option<u64>,
}

// ── ArrayType ────────────────────────────────────────────────────────────────

/// An array type (`DW_TAG_array_type`).
#[derive(Debug, Clone)]
pub struct ArrayType {
    /// `DW_AT_type` DIE offset of the element type.
    pub element_type_offset: Option<u64>,
    /// One entry per `DW_TAG_subrange_type` child.
    pub dimensions: Vec<ArrayDimension>,
}

/// One array dimension from a `DW_TAG_subrange_type` DIE.
#[derive(Debug, Clone)]
pub struct ArrayDimension {
    /// `DW_AT_lower_bound` (defaults to 0).
    pub lower_bound: u64,
    /// `DW_AT_upper_bound`, inclusive.
    pub upper_bound: Option<u64>,
    /// `DW_AT_count` element count.
    pub count: Option<u64>,
}

impl ArrayType {
    /// Human-readable element-type reference.
    #[must_use]
    pub fn element_type_name(&self) -> String {
        self.element_type_offset
            .map_or_else(|| "void".to_string(), |off| format!("<type@{off:#x}>"))
    }

    /// Total element count (product of all dimension counts).
    #[must_use]
    pub fn total_elements(&self) -> Option<u64> {
        if self.dimensions.is_empty() {
            return None;
        }
        let mut total = 1u64;
        for dim in &self.dimensions {
            let n = dim
                .count
                .or_else(|| dim.upper_bound.map(|ub| ub - dim.lower_bound + 1))?;
            total = total.checked_mul(n)?;
        }
        Some(total)
    }
}

// ── CompositeType ─────────────────────────────────────────────────────────────

/// Decoded struct, class, or union.
#[derive(Debug, Clone)]
pub struct CompositeType {
    /// Type name (`DW_AT_name`), `<anon>` if unnamed.
    pub name: String,
    /// `DW_AT_byte_size`.
    pub byte_size: u64,
    /// `DW_TAG_member` children.
    pub members: Vec<TypeMember>,
    /// `DW_TAG_inheritance` children (C++ base classes).
    pub base_classes: Vec<InheritanceEntry>,
    /// `DW_AT_declaration` — true for forward declarations.
    pub is_declaration: bool,
}

/// A data member of a composite type (`DW_TAG_member`).
#[derive(Debug, Clone)]
pub struct TypeMember {
    /// Member name.
    pub name: String,
    /// `DW_AT_type` DIE offset of the member type.
    pub type_offset: Option<u64>,
    /// `DW_AT_data_member_location` byte offset.
    pub byte_offset: u64,
    /// `DW_AT_bit_size` for bitfields.
    pub bit_size: Option<u64>,
    /// `DW_AT_bit_offset` for bitfields.
    pub bit_offset: Option<u64>,
    /// Member access level.
    pub accessibility: Accessibility,
}

/// A C++ base-class record (`DW_TAG_inheritance`).
#[derive(Debug, Clone)]
pub struct InheritanceEntry {
    /// `DW_AT_type` DIE offset of the base class.
    pub base_type_offset: Option<u64>,
    /// `DW_AT_data_member_location` byte offset of the base subobject.
    pub byte_offset: u64,
    /// Inheritance access level.
    pub accessibility: Accessibility,
}

/// C++ access level from `DW_AT_accessibility`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accessibility {
    /// `DW_ACCESS_public` (1).
    Public = 1,
    /// `DW_ACCESS_protected` (2).
    Protected = 2,
    /// `DW_ACCESS_private` (3).
    Private = 3,
    /// Absent or unrecognized value.
    Unknown = 0,
}

impl Accessibility {
    /// Convert a raw `DW_AT_accessibility` value.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Public,
            2 => Self::Protected,
            3 => Self::Private,
            _ => Self::Unknown,
        }
    }

    /// C++ keyword for this access level.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Protected => "protected",
            Self::Private => "private",
            Self::Unknown => "<unknown>",
        }
    }
}

// ── EnumerationType ───────────────────────────────────────────────────────────

/// An enum type (`DW_TAG_enumeration_type`).
#[derive(Debug, Clone)]
pub struct EnumerationType {
    /// Enum name (`DW_AT_name`), `<anon>` if unnamed.
    pub name: String,
    /// `DW_AT_type` DIE offset of the underlying integer type.
    pub underlying_type_offset: Option<u64>,
    /// `DW_AT_byte_size`.
    pub byte_size: u64,
    /// `DW_TAG_enumerator` children.
    pub enumerators: Vec<Enumerator>,
}

/// A single enum value (`DW_TAG_enumerator`).
#[derive(Debug, Clone)]
pub struct Enumerator {
    /// Enumerator name.
    pub name: String,
    /// `DW_AT_const_value`.
    pub value: i64,
}

// ── SubroutineType ────────────────────────────────────────────────────────────

/// A function/method type (`DW_TAG_subroutine_type`).
#[derive(Debug, Clone)]
pub struct SubroutineType {
    /// `DW_AT_type` DIE offset of the return type; `None` = `void`.
    pub return_type_offset: Option<u64>,
    /// `DW_TAG_formal_parameter` children.
    pub parameters: Vec<Parameter>,
    /// True if a `DW_TAG_unspecified_parameters` child is present (`...`).
    pub is_variadic: bool,
}

/// A formal parameter (`DW_TAG_formal_parameter`).
#[derive(Debug, Clone)]
pub struct Parameter {
    /// Parameter name, if named.
    pub name: Option<String>,
    /// `DW_AT_type` DIE offset of the parameter type.
    pub type_offset: Option<u64>,
}

// ── PtrToMemberType ───────────────────────────────────────────────────────────

/// A C++ pointer-to-member type (`DW_TAG_ptr_to_member_type`).
#[derive(Debug, Clone)]
pub struct PtrToMemberType {
    /// `DW_AT_containing_type` DIE offset of the owning class.
    pub containing_type_offset: Option<u64>,
    /// `DW_AT_type` DIE offset of the member type.
    pub member_type_offset: Option<u64>,
}

// ── DwarfTypeDecoder ──────────────────────────────────────────────────────────

/// Decodes DWARF type DIEs from a pre-parsed DIE tree.
///
/// Instantiate with a flat list of DIEs (including children),
/// then call [`DwarfTypeDecoder::decode_all`].
pub struct DwarfTypeDecoder {
    /// Decoded types keyed by DIE offset.
    pub types: HashMap<u64, DwarfType>,
}

impl DwarfTypeDecoder {
    /// Create an empty decoder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            types: HashMap::new(),
        }
    }

    /// Decode all type DIEs from a flat list.
    ///
    /// Each top-level DIE is decoded according to its tag.
    pub fn decode_all(&mut self, dies: &[Die]) {
        for die in dies {
            let ty = self.decode_die(die);
            self.types.insert(die.offset, ty);
        }
    }

    /// Decode a single DIE into a [`DwarfType`].
    #[must_use]
    pub fn decode_die(&self, die: &Die) -> DwarfType {
        match die.tag {
            tag::DW_TAG_BASE_TYPE => DwarfType::Base(decode_base_type(die)),
            tag::DW_TAG_POINTER_TYPE => DwarfType::Pointer(decode_pointer_type(die)),
            tag::DW_TAG_REFERENCE_TYPE => DwarfType::Reference(ReferenceType {
                pointee_offset: die.type_ref,
                is_rvalue: false,
            }),
            tag::DW_TAG_RVALUE_REF_TYPE => DwarfType::Reference(ReferenceType {
                pointee_offset: die.type_ref,
                is_rvalue: true,
            }),
            tag::DW_TAG_CONST_TYPE => DwarfType::Const(ConstType {
                underlying_offset: die.type_ref,
            }),
            tag::DW_TAG_VOLATILE_TYPE => DwarfType::Volatile(VolatileType {
                underlying_offset: die.type_ref,
            }),
            tag::DW_TAG_TYPEDEF => DwarfType::Typedef(TypedefType {
                name: die.name.clone().unwrap_or_else(|| "<anon>".to_string()),
                underlying_offset: die.type_ref,
            }),
            tag::DW_TAG_ARRAY_TYPE => DwarfType::Array(decode_array_type(die)),
            tag::DW_TAG_STRUCTURE_TYPE => DwarfType::Structure(decode_composite(die)),
            tag::DW_TAG_CLASS_TYPE => DwarfType::Class(decode_composite(die)),
            tag::DW_TAG_UNION_TYPE => DwarfType::Union(decode_composite(die)),
            tag::DW_TAG_ENUMERATION_TYPE => DwarfType::Enumeration(decode_enumeration(die)),
            tag::DW_TAG_SUBROUTINE_TYPE => DwarfType::Subroutine(decode_subroutine(die)),
            tag::DW_TAG_PTR_TO_MEMBER_TYPE => DwarfType::PtrToMember(PtrToMemberType {
                containing_type_offset: None,
                member_type_offset: die.type_ref,
            }),
            tag::DW_TAG_UNSPECIFIED_TYPE => DwarfType::Unspecified {
                name: die
                    .name
                    .clone()
                    .unwrap_or_else(|| "<unspecified>".to_string()),
            },
            t => DwarfType::Unknown {
                tag: t,
                name: die.name.clone(),
            },
        }
    }

    /// Look up a decoded type by DIE offset.
    #[must_use]
    pub fn get(&self, offset: u64) -> Option<&DwarfType> {
        self.types.get(&offset)
    }

    /// Count of decoded types.
    #[must_use]
    pub fn count(&self) -> usize {
        self.types.len()
    }

    /// Collect all base types.
    #[must_use]
    pub fn base_types(&self) -> Vec<(u64, &BaseType)> {
        self.types
            .iter()
            .filter_map(|(&off, t)| {
                if let DwarfType::Base(b) = t {
                    Some((off, b))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Collect all composite types (struct/class/union).
    #[must_use]
    pub fn composite_types(&self) -> Vec<(u64, &CompositeType)> {
        self.types
            .iter()
            .filter_map(|(&off, t)| match t {
                DwarfType::Structure(c) | DwarfType::Class(c) | DwarfType::Union(c) => {
                    Some((off, c))
                }
                _ => None,
            })
            .collect()
    }

    /// Resolve the chain of type references starting at `offset` to a base name.
    ///
    /// Follows typedef, const, volatile, and pointer chains.
    #[must_use]
    pub fn resolve_name(&self, offset: u64) -> String {
        let mut current = offset;
        let mut depth = 0;
        loop {
            depth += 1;
            if depth > 32 {
                return "<cycle>".to_string();
            }
            match self.types.get(&current) {
                Some(DwarfType::Typedef(t)) => match t.underlying_offset {
                    Some(next) => {
                        current = next;
                    }
                    None => return t.name.clone(),
                },
                Some(DwarfType::Const(c)) => match c.underlying_offset {
                    Some(next) => {
                        current = next;
                    }
                    None => return "const void".to_string(),
                },
                Some(DwarfType::Pointer(_)) => return "void*".to_string(),
                Some(ty) => return ty.c_name(),
                None => return format!("<unresolved@{current:#x}>"),
            }
        }
    }
}

impl Default for DwarfTypeDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Decode helpers ────────────────────────────────────────────────────────────

fn decode_base_type(die: &Die) -> BaseType {
    BaseType {
        name: die.name.clone().unwrap_or_else(|| "?".to_string()),
        byte_size: die.byte_size.unwrap_or(0),
        encoding: die.encoding.unwrap_or(0),
    }
}

fn decode_pointer_type(die: &Die) -> PointerType {
    PointerType {
        pointee_offset: die.type_ref,
        byte_size: die.byte_size.unwrap_or(8),
    }
}

fn decode_array_type(die: &Die) -> ArrayType {
    let element_type_offset = die.type_ref;
    let dimensions = die
        .children
        .iter()
        .filter(|d| d.tag == tag::DW_TAG_SUBRANGE_TYPE)
        .map(|d| ArrayDimension {
            lower_bound: d.lower_bound.unwrap_or(0),
            upper_bound: d.upper_bound,
            count: d.count,
        })
        .collect();
    ArrayType {
        element_type_offset,
        dimensions,
    }
}

fn decode_composite(die: &Die) -> CompositeType {
    let name = die.name.clone().unwrap_or_else(|| "<anon>".to_string());
    let byte_size = die.byte_size.unwrap_or(0);
    let is_declaration = die.declaration;

    let mut members = Vec::new();
    let mut base_classes = Vec::new();

    for child in &die.children {
        match child.tag {
            tag::DW_TAG_MEMBER => {
                members.push(TypeMember {
                    name: child.name.clone().unwrap_or_else(|| "<anon>".to_string()),
                    type_offset: child.type_ref,
                    byte_offset: child.data_member_location.unwrap_or(0),
                    bit_size: child.bit_size,
                    bit_offset: child.bit_offset,
                    accessibility: child
                        .accessibility
                        .map_or(Accessibility::Public, Accessibility::from_u8),
                });
            }
            tag::DW_TAG_INHERITANCE => {
                base_classes.push(InheritanceEntry {
                    base_type_offset: child.type_ref,
                    byte_offset: child.data_member_location.unwrap_or(0),
                    accessibility: child
                        .accessibility
                        .map_or(Accessibility::Public, Accessibility::from_u8),
                });
            }
            _ => {}
        }
    }

    CompositeType {
        name,
        byte_size,
        members,
        base_classes,
        is_declaration,
    }
}

fn decode_enumeration(die: &Die) -> EnumerationType {
    let name = die.name.clone().unwrap_or_else(|| "<anon>".to_string());
    let byte_size = die.byte_size.unwrap_or(4);
    let underlying_type_offset = die.type_ref;
    let enumerators = die
        .children
        .iter()
        .filter(|d| d.tag == tag::DW_TAG_ENUMERATOR)
        .map(|d| Enumerator {
            name: d.name.clone().unwrap_or_default(),
            value: d.const_value.unwrap_or(0),
        })
        .collect();
    EnumerationType {
        name,
        underlying_type_offset,
        byte_size,
        enumerators,
    }
}

fn decode_subroutine(die: &Die) -> SubroutineType {
    let return_type_offset = die.type_ref;
    let mut parameters = Vec::new();
    let mut is_variadic = false;
    for child in &die.children {
        match child.tag {
            tag::DW_TAG_FORMAL_PARAMETER => {
                parameters.push(Parameter {
                    name: child.name.clone(),
                    type_offset: child.type_ref,
                });
            }
            tag::DW_TAG_UNSPECIFIED_PARAMS => {
                is_variadic = true;
            }
            _ => {}
        }
    }
    SubroutineType {
        return_type_offset,
        parameters,
        is_variadic,
    }
}

// ── DwarfTypeIndex ────────────────────────────────────────────────────────────

/// Quick-access index for looking up types by name.
#[derive(Debug, Default)]
pub struct DwarfTypeIndex {
    by_name: std::collections::HashMap<String, Vec<u64>>,
}

impl DwarfTypeIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the index from a decoder.
    #[must_use]
    pub fn from_decoder(dec: &DwarfTypeDecoder) -> Self {
        let mut idx = Self::new();
        for (&off, ty) in &dec.types {
            let name = ty.c_name();
            idx.by_name.entry(name).or_default().push(off);
        }
        idx
    }

    /// Lookup offsets by name.
    #[must_use]
    pub fn lookup(&self, name: &str) -> &[u64] {
        self.by_name.get(name).map_or(&[], std::vec::Vec::as_slice)
    }

    /// Number of unique type names.
    #[must_use]
    pub fn unique_names(&self) -> usize {
        self.by_name.len()
    }
}

// ── DwarfTypePrinter ──────────────────────────────────────────────────────────

/// Renders DWARF types to C-style declarations.
pub struct DwarfTypePrinter<'a> {
    decoder: &'a DwarfTypeDecoder,
}

impl<'a> DwarfTypePrinter<'a> {
    /// Create a printer over a decoder.
    #[must_use]
    pub const fn new(decoder: &'a DwarfTypeDecoder) -> Self {
        Self { decoder }
    }

    /// Render a struct type as a C declaration.
    #[must_use]
    pub fn print_struct(&self, ct: &CompositeType) -> String {
        use std::fmt::Write as _;
        let mut out = format!("struct {} {{\n", ct.name);
        for m in &ct.members {
            let type_str = m
                .type_offset
                .and_then(|off| self.decoder.get(off))
                .map_or_else(|| "void".to_string(), DwarfType::c_name);
            writeln!(
                out,
                "  {} {}; // offset={}",
                type_str, m.name, m.byte_offset
            )
            .expect("writing to String never fails");
        }
        out.push_str("};");
        out
    }

    /// Render an enum type as a C declaration.
    #[must_use]
    pub fn print_enum(&self, et: &EnumerationType) -> String {
        use std::fmt::Write as _;
        let mut out = format!("enum {} {{\n", et.name);
        for e in &et.enumerators {
            writeln!(out, "  {} = {},", e.name, e.value).expect("writing to String never fails");
        }
        out.push_str("};");
        out
    }

    /// Render a subroutine type as a C function pointer declaration.
    #[must_use]
    pub fn print_subroutine(&self, st: &SubroutineType) -> String {
        let ret = st
            .return_type_offset
            .and_then(|off| self.decoder.get(off))
            .map_or_else(|| "void".to_string(), DwarfType::c_name);
        let params: Vec<String> = st
            .parameters
            .iter()
            .map(|p| {
                let ty = p
                    .type_offset
                    .and_then(|off| self.decoder.get(off))
                    .map_or_else(|| "void".to_string(), DwarfType::c_name);
                p.name.as_deref().map(|n| format!("{ty} {n}")).unwrap_or(ty)
            })
            .collect();
        let variadic = if st.is_variadic { ", ..." } else { "" };
        format!("{ret}(*)({}{})", params.join(", "), variadic)
    }
}

// ── DwarfTypeStats ────────────────────────────────────────────────────────────

/// Statistics about the decoded DWARF types.
#[derive(Debug, Clone, Default)]
pub struct DwarfTypeStats {
    /// Number of `DW_TAG_base_type` entries.
    pub base_types: usize,
    /// Number of `DW_TAG_pointer_type` entries.
    pub pointers: usize,
    /// Number of `DW_TAG_array_type` entries.
    pub arrays: usize,
    /// Number of `DW_TAG_structure_type` entries.
    pub structs: usize,
    /// Number of `DW_TAG_union_type` entries.
    pub unions: usize,
    /// Number of `DW_TAG_enumeration_type` entries.
    pub enums: usize,
    /// Number of `DW_TAG_typedef` entries.
    pub typedefs: usize,
    /// Number of `DW_TAG_subroutine_type` entries.
    pub subroutines: usize,
    /// Everything else (qualifiers, references, unknown tags).
    pub other: usize,
}

impl DwarfTypeStats {
    /// Compute from a decoder.
    #[must_use]
    pub fn compute(dec: &DwarfTypeDecoder) -> Self {
        let mut s = Self::default();
        for ty in dec.types.values() {
            match ty {
                DwarfType::Base(_) => s.base_types += 1,
                DwarfType::Pointer(_) => s.pointers += 1,
                DwarfType::Array(_) => s.arrays += 1,
                DwarfType::Structure(_) => s.structs += 1,
                DwarfType::Union(_) => s.unions += 1,
                DwarfType::Enumeration(_) => s.enums += 1,
                DwarfType::Typedef(_) => s.typedefs += 1,
                DwarfType::Subroutine(_) => s.subroutines += 1,
                _ => s.other += 1,
            }
        }
        s
    }

    /// Total type count.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.base_types
            + self.pointers
            + self.arrays
            + self.structs
            + self.unions
            + self.enums
            + self.typedefs
            + self.subroutines
            + self.other
    }
}

// ── DwarfSizeEstimator ────────────────────────────────────────────────────────

/// Estimates sizes for DWARF types where `DW_AT_BYTE_SIZE` is absent.
pub struct DwarfSizeEstimator {
    /// ABI pointer size in bytes.
    pub pointer_size: u64,
}

impl DwarfSizeEstimator {
    /// Create an estimator with the given ABI pointer size.
    #[must_use]
    pub const fn new(pointer_size: u64) -> Self {
        Self { pointer_size }
    }

    /// Estimate size of a type.
    #[must_use]
    pub fn estimate(&self, ty: &DwarfType, dec: &DwarfTypeDecoder) -> u64 {
        match ty {
            DwarfType::Base(b) => b.byte_size,
            DwarfType::Pointer(_) | DwarfType::Reference(_) => self.pointer_size,
            DwarfType::Const(_) | DwarfType::Volatile(_) => {
                let off = match ty {
                    DwarfType::Const(c) => c.underlying_offset,
                    DwarfType::Volatile(v) => v.underlying_offset,
                    _ => unreachable!(),
                };
                off.and_then(|o| dec.get(o))
                    .map_or(0, |t| self.estimate(t, dec))
            }
            DwarfType::Structure(c) | DwarfType::Class(c) | DwarfType::Union(c) => c.byte_size,
            DwarfType::Enumeration(e) => e.byte_size,
            DwarfType::Array(a) => {
                let elem_size = a
                    .element_type_offset
                    .and_then(|o| dec.get(o))
                    .map_or(1, |t| self.estimate(t, dec));
                a.total_elements().unwrap_or(0) * elem_size
            }
            DwarfType::Typedef(t) => t
                .underlying_offset
                .and_then(|o| dec.get(o))
                .map_or(0, |t| self.estimate(t, dec)),
            _ => 0,
        }
    }
}

// ── DwarfDependencyGraph ──────────────────────────────────────────────────────

/// Tracks type-dependency relationships (e.g., struct → pointer → base type).
#[derive(Debug, Default)]
pub struct DwarfDependencyGraph {
    /// `type_offset` → list of directly referenced type offsets
    deps: HashMap<u64, Vec<u64>>,
}

impl DwarfDependencyGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the dependency graph from a decoder.
    #[must_use]
    pub fn build(dec: &DwarfTypeDecoder) -> Self {
        let mut g = Self::new();
        for (&off, ty) in &dec.types {
            let mut refs = Vec::new();
            match ty {
                DwarfType::Pointer(p) => {
                    if let Some(o) = p.pointee_offset {
                        refs.push(o);
                    }
                }
                DwarfType::Const(c) => {
                    if let Some(o) = c.underlying_offset {
                        refs.push(o);
                    }
                }
                DwarfType::Volatile(v) => {
                    if let Some(o) = v.underlying_offset {
                        refs.push(o);
                    }
                }
                DwarfType::Typedef(t) => {
                    if let Some(o) = t.underlying_offset {
                        refs.push(o);
                    }
                }
                DwarfType::Array(a) => {
                    if let Some(o) = a.element_type_offset {
                        refs.push(o);
                    }
                }
                DwarfType::Structure(s) | DwarfType::Class(s) | DwarfType::Union(s) => {
                    for m in &s.members {
                        if let Some(o) = m.type_offset {
                            refs.push(o);
                        }
                    }
                }
                DwarfType::Subroutine(sub) => {
                    if let Some(o) = sub.return_type_offset {
                        refs.push(o);
                    }
                    for p in &sub.parameters {
                        if let Some(o) = p.type_offset {
                            refs.push(o);
                        }
                    }
                }
                _ => {}
            }
            g.deps.insert(off, refs);
        }
        g
    }

    /// Direct dependencies of a type.
    #[must_use]
    pub fn dependencies(&self, offset: u64) -> &[u64] {
        self.deps.get(&offset).map_or(&[], std::vec::Vec::as_slice)
    }

    /// Number of type nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.deps.len()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn int32_die(offset: u64) -> Die {
        let mut d = Die::new(offset, tag::DW_TAG_BASE_TYPE);
        d.name = Some("int".to_string());
        d.byte_size = Some(4);
        d.encoding = Some(encoding::DW_ATE_SIGNED);
        d
    }

    fn float_die(offset: u64) -> Die {
        let mut d = Die::new(offset, tag::DW_TAG_BASE_TYPE);
        d.name = Some("float".to_string());
        d.byte_size = Some(4);
        d.encoding = Some(encoding::DW_ATE_FLOAT);
        d
    }

    // --- BaseType ---

    #[test]
    fn test_base_type_int32() {
        let die = int32_die(0x10);
        let bt = decode_base_type(&die);
        assert_eq!(bt.c_name(), "int32_t");
        assert!(!bt.is_float());
        assert!(bt.is_signed());
    }

    #[test]
    fn test_base_type_float() {
        let die = float_die(0x20);
        let bt = decode_base_type(&die);
        assert_eq!(bt.c_name(), "float");
        assert!(bt.is_float());
    }

    #[test]
    fn test_base_type_bool() {
        let mut d = Die::new(0, tag::DW_TAG_BASE_TYPE);
        d.name = Some("bool".to_string());
        d.byte_size = Some(1);
        d.encoding = Some(encoding::DW_ATE_BOOLEAN);
        let bt = decode_base_type(&d);
        assert_eq!(bt.c_name(), "bool");
    }

    #[test]
    fn test_base_type_uint64() {
        let mut d = Die::new(0, tag::DW_TAG_BASE_TYPE);
        d.name = Some("long long unsigned".to_string());
        d.byte_size = Some(8);
        d.encoding = Some(encoding::DW_ATE_UNSIGNED);
        let bt = decode_base_type(&d);
        assert_eq!(bt.c_name(), "uint64_t");
    }

    // --- PointerType ---

    #[test]
    fn test_pointer_void() {
        let d = Die::new(0, tag::DW_TAG_POINTER_TYPE);
        let pt = decode_pointer_type(&d);
        assert!(pt.is_void_ptr());
    }

    #[test]
    fn test_pointer_to_int() {
        let mut d = Die::new(0, tag::DW_TAG_POINTER_TYPE);
        d.type_ref = Some(0x10);
        let pt = decode_pointer_type(&d);
        assert!(!pt.is_void_ptr());
        assert_eq!(pt.pointee_offset, Some(0x10));
    }

    // --- ArrayType ---

    #[test]
    fn test_array_type_simple() {
        let mut d = Die::new(0, tag::DW_TAG_ARRAY_TYPE);
        d.type_ref = Some(0x10);
        let mut sub = Die::new(1, tag::DW_TAG_SUBRANGE_TYPE);
        sub.lower_bound = Some(0);
        sub.upper_bound = Some(9);
        d.children = vec![sub];
        let at = decode_array_type(&d);
        assert_eq!(at.total_elements(), Some(10));
    }

    #[test]
    fn test_array_type_no_dims() {
        let d = Die::new(0, tag::DW_TAG_ARRAY_TYPE);
        let at = decode_array_type(&d);
        assert_eq!(at.total_elements(), None);
    }

    #[test]
    fn test_array_with_count() {
        let mut d = Die::new(0, tag::DW_TAG_ARRAY_TYPE);
        d.type_ref = Some(0x20);
        let mut sub = Die::new(1, tag::DW_TAG_SUBRANGE_TYPE);
        sub.count = Some(5);
        d.children = vec![sub];
        let at = decode_array_type(&d);
        assert_eq!(at.total_elements(), Some(5));
    }

    // --- CompositeType ---

    #[test]
    fn test_struct_empty() {
        let mut d = Die::new(0, tag::DW_TAG_STRUCTURE_TYPE);
        d.name = Some("Point".to_string());
        d.byte_size = Some(8);
        let ct = decode_composite(&d);
        assert_eq!(ct.name, "Point");
        assert_eq!(ct.byte_size, 8);
        assert!(ct.members.is_empty());
    }

    #[test]
    fn test_struct_with_member() {
        let mut d = Die::new(0, tag::DW_TAG_STRUCTURE_TYPE);
        d.name = Some("Rect".to_string());
        d.byte_size = Some(16);
        let mut m = Die::new(1, tag::DW_TAG_MEMBER);
        m.name = Some("x".to_string());
        m.type_ref = Some(0x10);
        m.data_member_location = Some(0);
        d.children = vec![m];
        let ct = decode_composite(&d);
        assert_eq!(ct.members.len(), 1);
        assert_eq!(ct.members[0].name, "x");
    }

    #[test]
    fn test_struct_with_base_class() {
        let mut d = Die::new(0, tag::DW_TAG_CLASS_TYPE);
        d.name = Some("Derived".to_string());
        d.byte_size = Some(16);
        let mut inh = Die::new(1, tag::DW_TAG_INHERITANCE);
        inh.type_ref = Some(0x50);
        inh.data_member_location = Some(0);
        inh.accessibility = Some(1); // public
        d.children = vec![inh];
        let ct = decode_composite(&d);
        assert_eq!(ct.base_classes.len(), 1);
        assert_eq!(ct.base_classes[0].accessibility, Accessibility::Public);
    }

    // --- EnumerationType ---

    #[test]
    fn test_enum_simple() {
        let mut d = Die::new(0, tag::DW_TAG_ENUMERATION_TYPE);
        d.name = Some("Color".to_string());
        d.byte_size = Some(4);
        let mut e1 = Die::new(1, tag::DW_TAG_ENUMERATOR);
        e1.name = Some("Red".to_string());
        e1.const_value = Some(0);
        let mut e2 = Die::new(2, tag::DW_TAG_ENUMERATOR);
        e2.name = Some("Green".to_string());
        e2.const_value = Some(1);
        d.children = vec![e1, e2];
        let et = decode_enumeration(&d);
        assert_eq!(et.name, "Color");
        assert_eq!(et.enumerators.len(), 2);
        assert_eq!(et.enumerators[0].name, "Red");
    }

    // --- SubroutineType ---

    #[test]
    fn test_subroutine_no_params() {
        let d = Die::new(0, tag::DW_TAG_SUBROUTINE_TYPE);
        let st = decode_subroutine(&d);
        assert!(st.parameters.is_empty());
        assert!(!st.is_variadic);
    }

    #[test]
    fn test_subroutine_with_params() {
        let mut d = Die::new(0, tag::DW_TAG_SUBROUTINE_TYPE);
        d.type_ref = Some(0x10); // return type
        let mut p = Die::new(1, tag::DW_TAG_FORMAL_PARAMETER);
        p.name = Some("arg0".to_string());
        p.type_ref = Some(0x10);
        let va = Die::new(2, tag::DW_TAG_UNSPECIFIED_PARAMS);
        d.children = vec![p, va];
        let st = decode_subroutine(&d);
        assert_eq!(st.parameters.len(), 1);
        assert!(st.is_variadic);
    }

    // --- DwarfTypeDecoder ---

    #[test]
    fn test_decoder_decode_all() {
        let mut dec = DwarfTypeDecoder::new();
        dec.decode_all(&[int32_die(0x100), float_die(0x200)]);
        assert_eq!(dec.count(), 2);
    }

    #[test]
    fn test_decoder_get() {
        let mut dec = DwarfTypeDecoder::new();
        dec.decode_all(&[int32_die(0x100)]);
        assert!(dec.get(0x100).is_some());
        assert!(dec.get(0xFFFF).is_none());
    }

    #[test]
    fn test_decoder_base_types() {
        let mut dec = DwarfTypeDecoder::new();
        dec.decode_all(&[int32_die(0x100), float_die(0x200)]);
        let bts = dec.base_types();
        assert_eq!(bts.len(), 2);
    }

    #[test]
    fn test_decoder_resolve_name_base() {
        let mut dec = DwarfTypeDecoder::new();
        dec.decode_all(&[int32_die(0x100)]);
        let name = dec.resolve_name(0x100);
        assert_eq!(name, "int32_t");
    }

    #[test]
    fn test_decoder_resolve_name_typedef() {
        let mut dec = DwarfTypeDecoder::new();
        dec.decode_all(&[int32_die(0x100)]);
        let mut td = Die::new(0x200, tag::DW_TAG_TYPEDEF);
        td.name = Some("MyInt".to_string());
        td.type_ref = Some(0x100);
        dec.decode_all(&[td]);
        let name = dec.resolve_name(0x200);
        assert_eq!(name, "int32_t");
    }

    #[test]
    fn test_decoder_resolve_unresolved() {
        let dec = DwarfTypeDecoder::new();
        let name = dec.resolve_name(0xDEAD);
        assert!(
            name.contains("0xdead") || name.contains("unresolved") || name.contains("0xDEAD"),
            "got: {name}"
        );
    }

    #[test]
    fn test_decoder_composite_types() {
        let mut dec = DwarfTypeDecoder::new();
        let mut d = Die::new(0x300, tag::DW_TAG_STRUCTURE_TYPE);
        d.name = Some("Foo".to_string());
        d.byte_size = Some(8);
        dec.decode_all(&[d]);
        let cts = dec.composite_types();
        assert_eq!(cts.len(), 1);
        assert_eq!(cts[0].1.name, "Foo");
    }

    // --- DwarfType::tag ---

    #[test]
    fn test_dwarf_type_tag_base() {
        let t = DwarfType::Base(BaseType {
            name: "int".to_string(),
            byte_size: 4,
            encoding: 5,
        });
        assert_eq!(t.tag(), tag::DW_TAG_BASE_TYPE);
    }

    #[test]
    fn test_dwarf_type_tag_pointer() {
        let t = DwarfType::Pointer(PointerType {
            pointee_offset: None,
            byte_size: 8,
        });
        assert_eq!(t.tag(), tag::DW_TAG_POINTER_TYPE);
    }

    // --- Accessibility ---

    #[test]
    fn test_accessibility_public() {
        assert_eq!(Accessibility::from_u8(1), Accessibility::Public);
        assert_eq!(Accessibility::Public.name(), "public");
    }

    #[test]
    fn test_accessibility_private() {
        assert_eq!(Accessibility::Private.name(), "private");
    }

    #[test]
    fn test_accessibility_unknown() {
        assert_eq!(Accessibility::from_u8(99), Accessibility::Unknown);
    }

    // --- Additional DwarfType tests ---

    #[test]
    fn test_dwarf_type_reference() {
        let mut d = Die::new(0x10, tag::DW_TAG_REFERENCE_TYPE);
        d.type_ref = Some(0x20);
        let mut dec = DwarfTypeDecoder::new();
        dec.decode_all(&[d]);
        let t = dec.get(0x10).unwrap();
        assert_eq!(t.tag(), tag::DW_TAG_REFERENCE_TYPE);
    }

    #[test]
    fn test_dwarf_type_rvalue_ref() {
        let mut d = Die::new(0x10, tag::DW_TAG_RVALUE_REF_TYPE);
        d.type_ref = Some(0x20);
        let mut dec = DwarfTypeDecoder::new();
        dec.decode_all(&[d]);
        let t = dec.get(0x10).unwrap();
        if let DwarfType::Reference(r) = t {
            assert!(r.is_rvalue);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_dwarf_type_const() {
        let d = Die::new(0x10, tag::DW_TAG_CONST_TYPE);
        let mut dec = DwarfTypeDecoder::new();
        dec.decode_all(&[d]);
        let t = dec.get(0x10).unwrap();
        assert_eq!(t.tag(), tag::DW_TAG_CONST_TYPE);
    }

    #[test]
    fn test_dwarf_type_volatile() {
        let d = Die::new(0x10, tag::DW_TAG_VOLATILE_TYPE);
        let mut dec = DwarfTypeDecoder::new();
        dec.decode_all(&[d]);
        let t = dec.get(0x10).unwrap();
        assert_eq!(t.tag(), tag::DW_TAG_VOLATILE_TYPE);
    }

    #[test]
    fn test_dwarf_type_typedef() {
        let mut d = Die::new(0x30, tag::DW_TAG_TYPEDEF);
        d.name = Some("size_t".to_string());
        d.type_ref = Some(0x10);
        let mut dec = DwarfTypeDecoder::new();
        dec.decode_all(&[d]);
        let t = dec.get(0x30).unwrap();
        assert!(matches!(t, DwarfType::Typedef(td) if td.name == "size_t"));
    }

    #[test]
    fn test_dwarf_type_union() {
        let mut d = Die::new(0x40, tag::DW_TAG_UNION_TYPE);
        d.name = Some("Data".to_string());
        d.byte_size = Some(8);
        let mut dec = DwarfTypeDecoder::new();
        dec.decode_all(&[d]);
        let t = dec.get(0x40).unwrap();
        assert_eq!(t.tag(), tag::DW_TAG_UNION_TYPE);
        assert!(matches!(t, DwarfType::Union(_)));
    }

    #[test]
    fn test_dwarf_type_unknown() {
        let d = Die::new(0x50, 0xFFF0);
        let mut dec = DwarfTypeDecoder::new();
        dec.decode_all(&[d]);
        let t = dec.get(0x50).unwrap();
        assert!(matches!(t, DwarfType::Unknown { .. }));
    }

    // --- Pointer void/non-void ---

    #[test]
    fn test_pointer_non_void() {
        let p = PointerType {
            pointee_offset: Some(0x10),
            byte_size: 8,
        };
        assert!(!p.is_void_ptr());
    }

    // --- ConstType / VolatileType underlying ---

    #[test]
    fn test_const_underlying_some() {
        let c = ConstType {
            underlying_offset: Some(0x10),
        };
        assert!(c.underlying_name().contains("0x10"));
    }

    #[test]
    fn test_const_underlying_none() {
        let c = ConstType {
            underlying_offset: None,
        };
        assert_eq!(c.underlying_name(), "const void");
    }

    #[test]
    fn test_volatile_underlying_some() {
        let v = VolatileType {
            underlying_offset: Some(0x20),
        };
        assert!(v.underlying_name().contains("0x20"));
    }

    // --- ArrayType::element_type_name ---

    #[test]
    fn test_array_element_type_name_some() {
        let a = ArrayType {
            element_type_offset: Some(0x10),
            dimensions: vec![],
        };
        assert!(a.element_type_name().contains("0x10"));
    }

    #[test]
    fn test_array_element_type_name_none() {
        let a = ArrayType {
            element_type_offset: None,
            dimensions: vec![],
        };
        assert_eq!(a.element_type_name(), "void");
    }

    // --- CompositeType declaration flag ---

    #[test]
    fn test_struct_declaration_flag() {
        let mut d = Die::new(0, tag::DW_TAG_STRUCTURE_TYPE);
        d.name = Some("Fwd".to_string());
        d.declaration = true;
        let ct = decode_composite(&d);
        assert!(ct.is_declaration);
    }

    // --- DwarfType::c_name variations ---

    #[test]
    fn test_c_name_enum() {
        let t = DwarfType::Enumeration(EnumerationType {
            name: "Color".to_string(),
            underlying_type_offset: None,
            byte_size: 4,
            enumerators: vec![],
        });
        assert_eq!(t.c_name(), "enum Color");
    }

    #[test]
    fn test_c_name_subroutine() {
        let t = DwarfType::Subroutine(SubroutineType {
            return_type_offset: None,
            parameters: vec![],
            is_variadic: false,
        });
        assert_eq!(t.c_name(), "fn(...)");
    }
}
