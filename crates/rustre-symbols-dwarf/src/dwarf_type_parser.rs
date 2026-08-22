//! `dwarf_type_parser` — complete DWARF type reconstruction.
//!
//! Parses all relevant `DW_TAG`_ type entries from a DWARF DIE tree and builds
//! a richly-typed representation with forward-reference resolution.
//!
//! # Parallel implementations
//!
//! This crate ships more than one type-tree implementation: see also `dwarf_type_decoder` and `dwarf_type_reader`.
//! None of them is wired into [`crate::DwarfReader`], which uses its own
//! inline copy, so each carries an independent bug set and a fix applied
//! here does not propagate. Pick one deliberately and stay on it.

use std::collections::HashMap;

// ── DW_TAG constants ──────────────────────────────────────────────────────────

/// `DW_TAG_base_type` (0x24).
pub const DW_TAG_BASE_TYPE: u64 = 0x24;
/// `DW_TAG_pointer_type` (0x0f).
pub const DW_TAG_POINTER_TYPE: u64 = 0x0f;
/// `DW_TAG_reference_type` (0x10).
pub const DW_TAG_REFERENCE_TYPE: u64 = 0x10;
/// `DW_TAG_rvalue_reference_type` (0x42).
pub const DW_TAG_RVALUE_REFERENCE_TYPE: u64 = 0x42;
/// `DW_TAG_array_type` (0x01).
pub const DW_TAG_ARRAY_TYPE: u64 = 0x01;
/// `DW_TAG_subrange_type` (0x21).
pub const DW_TAG_SUBRANGE_TYPE: u64 = 0x21;
/// `DW_TAG_structure_type` (0x13).
pub const DW_TAG_STRUCTURE_TYPE: u64 = 0x13;
/// `DW_TAG_union_type` (0x17).
pub const DW_TAG_UNION_TYPE: u64 = 0x17;
/// `DW_TAG_class_type` (0x02).
pub const DW_TAG_CLASS_TYPE: u64 = 0x02;
/// `DW_TAG_member` (0x0d).
pub const DW_TAG_MEMBER: u64 = 0x0d;
/// `DW_TAG_enumeration_type` (0x04).
pub const DW_TAG_ENUMERATION_TYPE: u64 = 0x04;
/// `DW_TAG_enumerator` (0x28).
pub const DW_TAG_ENUMERATOR: u64 = 0x28;
/// `DW_TAG_subroutine_type` (0x15).
pub const DW_TAG_SUBROUTINE_TYPE: u64 = 0x15;
/// `DW_TAG_formal_parameter` (0x05).
pub const DW_TAG_FORMAL_PARAMETER: u64 = 0x05;
/// `DW_TAG_typedef` (0x16).
pub const DW_TAG_TYPEDEF: u64 = 0x16;
/// `DW_TAG_const_type` (0x26).
pub const DW_TAG_CONST_TYPE: u64 = 0x26;
/// `DW_TAG_volatile_type` (0x35).
pub const DW_TAG_VOLATILE_TYPE: u64 = 0x35;
/// `DW_TAG_restrict_type` (0x37).
pub const DW_TAG_RESTRICT_TYPE: u64 = 0x37;
/// `DW_TAG_atomic_type` (0x47).
pub const DW_TAG_ATOMIC_TYPE: u64 = 0x47;
/// `DW_TAG_inheritance` (0x1c).
pub const DW_TAG_INHERITANCE: u64 = 0x1c;
/// `DW_TAG_template_type_parameter` (0x2f).
pub const DW_TAG_TEMPLATE_TYPE_PARAM: u64 = 0x2f;
/// `DW_TAG_template_value_parameter` (0x30).
pub const DW_TAG_TEMPLATE_VALUE_PARAM: u64 = 0x30;
/// `DW_TAG_unspecified_type` (0x3b).
pub const DW_TAG_UNSPECIFIED_TYPE: u64 = 0x3b;

// ── DW_AT constants ───────────────────────────────────────────────────────────

/// `DW_AT_name` (0x03).
pub const DW_AT_NAME: u64 = 0x03;
/// `DW_AT_type` (0x49).
pub const DW_AT_TYPE: u64 = 0x49;
/// `DW_AT_byte_size` (0x0b).
pub const DW_AT_BYTE_SIZE: u64 = 0x0b;
/// `DW_AT_bit_size` (0x0d).
pub const DW_AT_BIT_SIZE: u64 = 0x0d;
/// `DW_AT_bit_offset` (0x0c).
pub const DW_AT_BIT_OFFSET: u64 = 0x0c;
/// `DW_AT_data_member_location` (0x38).
pub const DW_AT_DATA_MEMBER_LOCATION: u64 = 0x38;
/// `DW_AT_encoding` (0x3e).
pub const DW_AT_ENCODING: u64 = 0x3e;
/// `DW_AT_count` (0x37).
pub const DW_AT_COUNT: u64 = 0x37;
/// `DW_AT_lower_bound` (0x22).
pub const DW_AT_LOWER_BOUND: u64 = 0x22;
/// `DW_AT_upper_bound` (0x2f).
pub const DW_AT_UPPER_BOUND: u64 = 0x2f;
/// `DW_AT_const_value` (0x1c).
pub const DW_AT_CONST_VALUE: u64 = 0x1c;
/// `DW_AT_virtuality` (0x4c).
pub const DW_AT_VIRTUALITY: u64 = 0x4c;
/// `DW_AT_declaration` (0x3c).
pub const DW_AT_DECLARATION: u64 = 0x3c;
/// `DW_AT_specification` (0x47).
pub const DW_AT_SPECIFICATION: u64 = 0x47;
/// `DW_AT_abstract_origin` (0x31).
pub const DW_AT_ABSTRACT_ORIGIN: u64 = 0x31;
/// `DW_AT_external` (0x3f).
pub const DW_AT_EXTERNAL: u64 = 0x3f;
/// `DW_AT_accessibility` (0x32).
pub const DW_AT_ACCESSIBILITY: u64 = 0x32;
/// `DW_AT_byte_stride` (0x51).
pub const DW_AT_BYTE_STRIDE: u64 = 0x51;
/// `DW_AT_sibling` (0x01).
pub const DW_AT_SIBLING: u64 = 0x01;
/// `DW_AT_containing_type` (0x1d).
pub const DW_AT_CONTAINING_TYPE: u64 = 0x1d;

// ── DW_ATE encoding values ────────────────────────────────────────────────────

/// Base-type encoding decoded from a `DW_ATE_*` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BaseEncoding {
    /// No encoding / void.
    Void,
    /// `DW_ATE_address`.
    Address,
    /// `DW_ATE_boolean`.
    Boolean,
    /// `DW_ATE_float`.
    Float,
    /// `DW_ATE_signed`.
    Signed,
    /// `DW_ATE_signed_char`.
    SignedChar,
    /// `DW_ATE_unsigned`.
    Unsigned,
    /// `DW_ATE_unsigned_char`.
    UnsignedChar,
    /// `DW_ATE_imaginary_float`.
    ImaginaryFloat,
    /// `DW_ATE_packed_decimal`.
    PackedDecimal,
    /// `DW_ATE_numeric_string`.
    NumericString,
    /// `DW_ATE_edited`.
    Edited,
    /// `DW_ATE_signed_fixed`.
    SignedFixed,
    /// `DW_ATE_unsigned_fixed`.
    UnsignedFixed,
    /// `DW_ATE_decimal_float`.
    DecimalFloat,
    /// `DW_ATE_UTF`.
    Utf,
    /// `DW_ATE_UCS`.
    Ucs,
    /// `DW_ATE_ASCII`.
    Ascii,
    /// `DW_ATE_complex_float`.
    Complex,
    /// Unrecognized `DW_ATE_*` value, preserved verbatim.
    Unknown(u64),
}

impl BaseEncoding {
    /// Convert a raw `DW_ATE_*` value.
    #[must_use]
    pub const fn from_dw_ate(v: u64) -> Self {
        match v {
            0x01 => Self::Address,
            0x02 => Self::Boolean,
            0x03 => Self::Complex,
            0x04 => Self::Float,
            0x05 => Self::Signed,
            0x06 => Self::SignedChar,
            0x07 => Self::Unsigned,
            0x08 => Self::UnsignedChar,
            0x09 => Self::ImaginaryFloat,
            0x0a => Self::PackedDecimal,
            0x0b => Self::NumericString,
            0x0c => Self::Edited,
            0x0d => Self::SignedFixed,
            0x0e => Self::UnsignedFixed,
            0x0f => Self::DecimalFloat,
            0x10 => Self::Utf,
            0x11 => Self::Ucs,
            0x12 => Self::Ascii,
            _ => Self::Unknown(v),
        }
    }
}

// ── Type representation ───────────────────────────────────────────────────────

/// A unique offset within the DWARF .`debug_info` section.
pub type TypeRef = u64;

/// A struct/union/class member.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TypeMember {
    /// Member name (`DW_AT_name`).
    pub name: String,
    /// `DW_AT_type` DIE offset of the member type.
    pub type_ref: TypeRef,
    /// `DW_AT_data_member_location` byte offset.
    pub byte_offset: u64,
    /// `DW_AT_bit_offset` for bitfields.
    pub bit_offset: Option<u64>,
    /// `DW_AT_bit_size` for bitfields.
    pub bit_size: Option<u64>,
    /// `DW_AT_accessibility`: 1=public, 2=protected, 3=private.
    pub accessibility: u8,
}

/// An enumerator value.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Enumerator {
    /// Enumerator name (`DW_AT_name`).
    pub name: String,
    /// `DW_AT_const_value`.
    pub value: i64,
}

/// A base-class inheritance record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BaseClass {
    /// `DW_AT_type` DIE offset of the base class.
    pub type_ref: TypeRef,
    /// `DW_AT_data_member_location` byte offset of the base subobject.
    pub byte_offset: u64,
    /// `DW_AT_virtuality`: 0=none, 1=virtual, `2=pure_virtual`.
    pub virtuality: u8,
    /// `DW_AT_accessibility`: 1=public, 2=protected, 3=private.
    pub accessibility: u8,
}

/// A subroutine parameter.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SubroutineParam {
    /// Parameter name, if named.
    pub name: Option<String>,
    /// `DW_AT_type` DIE offset of the parameter type.
    pub type_ref: TypeRef,
}

/// A template type parameter.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TemplateParam {
    /// Template parameter name.
    pub name: String,
    /// `DW_AT_type` DIE offset of the bound type.
    pub type_ref: TypeRef,
}

/// The full type kind.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TypeKind {
    /// `DW_TAG_base_type`
    Base {
        /// `DW_AT_encoding` classification.
        encoding: BaseEncoding,
        /// `DW_AT_byte_size`.
        byte_size: u64,
    },
    /// `DW_TAG_pointer_type`
    Pointer {
        /// `DW_AT_type` DIE offset of the pointee (0 if absent).
        pointee: TypeRef,
    },
    /// `DW_TAG_reference_type`
    Reference {
        /// `DW_AT_type` DIE offset of the referent (0 if absent).
        pointee: TypeRef,
    },
    /// `DW_TAG_rvalue_reference_type`
    RvalueReference {
        /// `DW_AT_type` DIE offset of the referent (0 if absent).
        pointee: TypeRef,
    },
    /// `DW_TAG_array_type`
    Array {
        /// `DW_AT_type` DIE offset of the element type.
        element_type: TypeRef,
        /// Element count; None = unbounded.
        count: Option<u64>,
        /// Per-element stride in bytes, if the subrange carries one.
        stride: Option<u64>,
    },
    /// `DW_TAG_structure_type` / `DW_TAG_class_type` / `DW_TAG_union_type`
    Composite {
        /// True for `DW_TAG_union_type`.
        is_union: bool,
        /// True for `DW_TAG_class_type`.
        is_class: bool,
        /// `DW_AT_byte_size`.
        byte_size: u64,
        /// `DW_TAG_member` children.
        members: Vec<TypeMember>,
        /// `DW_TAG_inheritance` children.
        base_classes: Vec<BaseClass>,
        /// `DW_TAG_template_type_parameter` children.
        template_params: Vec<TemplateParam>,
        /// True if this is a forward declaration.
        is_declaration: bool,
    },
    /// `DW_TAG_enumeration_type`
    Enum {
        /// `DW_AT_type` DIE offset of the underlying integer type.
        underlying_type: TypeRef,
        /// `DW_AT_byte_size`.
        byte_size: u64,
        /// `DW_TAG_enumerator` children.
        enumerators: Vec<Enumerator>,
    },
    /// `DW_TAG_subroutine_type`
    Subroutine {
        /// `DW_AT_type` DIE offset of the return type; `None` = void.
        return_type: Option<TypeRef>,
        /// `DW_TAG_formal_parameter` children.
        params: Vec<SubroutineParam>,
        /// True if a `DW_TAG_unspecified_parameters` child is present.
        is_variadic: bool,
    },
    /// `DW_TAG_typedef`
    Typedef {
        /// `DW_AT_type` DIE offset of the aliased type.
        aliased: TypeRef,
    },
    /// `DW_TAG_const_type`
    Const {
        /// `DW_AT_type` DIE offset of the qualified type.
        inner: TypeRef,
    },
    /// `DW_TAG_volatile_type`
    Volatile {
        /// `DW_AT_type` DIE offset of the qualified type.
        inner: TypeRef,
    },
    /// `DW_TAG_restrict_type`
    Restrict {
        /// `DW_AT_type` DIE offset of the qualified type.
        inner: TypeRef,
    },
    /// `DW_TAG_atomic_type`
    Atomic {
        /// `DW_AT_type` DIE offset of the qualified type.
        inner: TypeRef,
    },
    /// `DW_TAG_unspecified_type` (e.g. `void`)
    Unspecified,
}

/// A fully parsed DWARF type.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DwarfType {
    /// DIE offset (unique key).
    pub offset: TypeRef,
    /// Optional name.
    pub name: Option<String>,
    /// Type classification.
    pub kind: TypeKind,
}

impl DwarfType {
    /// Return a human-readable C-like display name.
    #[must_use]
    pub fn display_name(&self) -> String {
        match &self.kind {
            TypeKind::Base { encoding, byte_size } => {
                let enc = match encoding {
                    BaseEncoding::Signed => match byte_size {
                        1 => "int8_t",
                        2 => "int16_t",
                        4 => "int32_t",
                        8 => "int64_t",
                        _ => "int",
                    },
                    BaseEncoding::Unsigned | BaseEncoding::UnsignedChar => match byte_size {
                        1 => "uint8_t",
                        2 => "uint16_t",
                        4 => "uint32_t",
                        8 => "uint64_t",
                        _ => "unsigned",
                    },
                    BaseEncoding::Float => match byte_size {
                        4 => "float",
                        8 => "double",
                        _ => "long double",
                    },
                    BaseEncoding::Boolean => "bool",
                    BaseEncoding::SignedChar => "char",
                    _ => "/*base*/",
                };
                self.name.as_deref().unwrap_or(enc).to_owned()
            }
            TypeKind::Pointer { .. } => format!(
                "{}*",
                self.name.as_deref().unwrap_or("T")
            ),
            TypeKind::Typedef { .. } => self.name.clone().unwrap_or_else(|| "typedef".into()),
            TypeKind::Composite { is_union, is_class, .. } => {
                let kw = if *is_union { "union" } else if *is_class { "class" } else { "struct" };
                format!("{} {}", kw, self.name.as_deref().unwrap_or("<anon>"))
            }
            TypeKind::Enum { .. } => format!("enum {}", self.name.as_deref().unwrap_or("<anon>")),
            TypeKind::Unspecified => "void".into(),
            _ => self.name.clone().unwrap_or_else(|| "T".into()),
        }
    }
}

// ── Flat attribute map (simplified DIE representation) ────────────────────────

/// A minimal DIE abstraction carrying only type-relevant attributes.
#[derive(Debug, Default)]
pub struct TypeDie {
    /// `DW_TAG_*` value.
    pub tag: u64,
    /// DIE offset within `.debug_info`.
    pub offset: u64,
    /// `DW_AT_name`.
    pub name: Option<String>,
    /// `DW_AT_type` → referenced DIE offset.
    pub type_ref: Option<TypeRef>,
    /// `DW_AT_byte_size`.
    pub byte_size: Option<u64>,
    /// `DW_AT_bit_size`.
    pub bit_size: Option<u64>,
    /// `DW_AT_bit_offset`.
    pub bit_offset: Option<u64>,
    /// `DW_AT_data_member_location`.
    pub data_member_location: Option<u64>,
    /// `DW_AT_encoding` (`DW_ATE_*`).
    pub encoding: Option<u64>,
    /// `DW_AT_count` (array subrange).
    pub count: Option<u64>,
    /// `DW_AT_lower_bound` (array subrange).
    pub lower_bound: Option<u64>,
    /// `DW_AT_upper_bound` (array subrange).
    pub upper_bound: Option<u64>,
    /// `DW_AT_const_value` (enumerator value).
    pub const_value: Option<i64>,
    /// `DW_AT_virtuality`.
    pub virtuality: Option<u64>,
    /// `DW_AT_declaration` — true for forward declarations.
    pub is_declaration: bool,
    /// `DW_AT_accessibility`.
    pub accessibility: Option<u64>,
    /// Child DIEs (members, enumerators, parameters, subranges).
    pub children: Vec<Self>,
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Convert a `TypeDie` tree into `DwarfType` entries.
#[must_use] 
pub fn collect_types_from_dies(dies: &[TypeDie]) -> Vec<DwarfType> {
    let mut out = Vec::new();
    for die in dies {
        if let Some(t) = die_to_type(die) {
            out.push(t);
        }
        // Recurse for nested types (anonymous structs, etc.)
        out.extend(collect_types_from_dies(&die.children));
    }
    out
}

fn die_to_type(die: &TypeDie) -> Option<DwarfType> {
    let kind = match die.tag {
        DW_TAG_BASE_TYPE => TypeKind::Base {
            encoding: BaseEncoding::from_dw_ate(die.encoding.unwrap_or(0)),
            byte_size: die.byte_size.unwrap_or(0),
        },
        DW_TAG_POINTER_TYPE => TypeKind::Pointer {
            pointee: die.type_ref.unwrap_or(0),
        },
        DW_TAG_REFERENCE_TYPE => TypeKind::Reference {
            pointee: die.type_ref.unwrap_or(0),
        },
        DW_TAG_RVALUE_REFERENCE_TYPE => TypeKind::RvalueReference {
            pointee: die.type_ref.unwrap_or(0),
        },
        DW_TAG_ARRAY_TYPE => {
            let (count, stride) = array_info_from_children(&die.children);
            TypeKind::Array {
                element_type: die.type_ref.unwrap_or(0),
                count,
                stride,
            }
        }
        DW_TAG_STRUCTURE_TYPE | DW_TAG_CLASS_TYPE | DW_TAG_UNION_TYPE => {
            let is_union = die.tag == DW_TAG_UNION_TYPE;
            let is_class = die.tag == DW_TAG_CLASS_TYPE;
            let (members, base_classes, template_params) = composite_children(&die.children);
            TypeKind::Composite {
                is_union,
                is_class,
                byte_size: die.byte_size.unwrap_or(0),
                members,
                base_classes,
                template_params,
                is_declaration: die.is_declaration,
            }
        }
        DW_TAG_ENUMERATION_TYPE => {
            let enumerators = enum_children(&die.children);
            TypeKind::Enum {
                underlying_type: die.type_ref.unwrap_or(0),
                byte_size: die.byte_size.unwrap_or(4),
                enumerators,
            }
        }
        DW_TAG_SUBROUTINE_TYPE => {
            let (params, is_variadic) = subroutine_children(&die.children);
            TypeKind::Subroutine {
                return_type: die.type_ref,
                params,
                is_variadic,
            }
        }
        DW_TAG_TYPEDEF => TypeKind::Typedef {
            aliased: die.type_ref.unwrap_or(0),
        },
        DW_TAG_CONST_TYPE => TypeKind::Const { inner: die.type_ref.unwrap_or(0) },
        DW_TAG_VOLATILE_TYPE => TypeKind::Volatile { inner: die.type_ref.unwrap_or(0) },
        DW_TAG_RESTRICT_TYPE => TypeKind::Restrict { inner: die.type_ref.unwrap_or(0) },
        DW_TAG_ATOMIC_TYPE => TypeKind::Atomic { inner: die.type_ref.unwrap_or(0) },
        DW_TAG_UNSPECIFIED_TYPE => TypeKind::Unspecified,
        _ => return None,
    };
    Some(DwarfType {
        offset: die.offset,
        name: die.name.clone(),
        kind,
    })
}

fn array_info_from_children(children: &[TypeDie]) -> (Option<u64>, Option<u64>) {
    let mut count = None;
    let mut stride = None;
    for child in children {
        if child.tag == DW_TAG_SUBRANGE_TYPE {
            count = child.count.or_else(|| {
                child.upper_bound.and_then(|ub| {
                    let lb = child.lower_bound.unwrap_or(0);
                    ub.checked_sub(lb).and_then(|diff| diff.checked_add(1))
                })
            });
            // DWARF allows the subrange to carry its own byte_size; treat
            // that as the per-element stride when present.
            if stride.is_none() {
                stride = child.byte_size;
            }
        }
    }
    (count, stride)
}

fn composite_children(
    children: &[TypeDie],
) -> (Vec<TypeMember>, Vec<BaseClass>, Vec<TemplateParam>) {
    let mut members = Vec::new();
    let mut base_classes = Vec::new();
    let mut template_params = Vec::new();

    for child in children {
        match child.tag {
            DW_TAG_MEMBER => {
                members.push(TypeMember {
                    name: child.name.clone().unwrap_or_default(),
                    type_ref: child.type_ref.unwrap_or(0),
                    byte_offset: child.data_member_location.unwrap_or(0),
                    bit_offset: child.bit_offset,
                    bit_size: child.bit_size,
                    accessibility: child.accessibility.unwrap_or(1) as u8,
                });
            }
            DW_TAG_INHERITANCE => {
                base_classes.push(BaseClass {
                    type_ref: child.type_ref.unwrap_or(0),
                    byte_offset: child.data_member_location.unwrap_or(0),
                    virtuality: child.virtuality.unwrap_or(0) as u8,
                    accessibility: child.accessibility.unwrap_or(1) as u8,
                });
            }
            DW_TAG_TEMPLATE_TYPE_PARAM => {
                template_params.push(TemplateParam {
                    name: child.name.clone().unwrap_or_default(),
                    type_ref: child.type_ref.unwrap_or(0),
                });
            }
            _ => {}
        }
    }
    (members, base_classes, template_params)
}

fn enum_children(children: &[TypeDie]) -> Vec<Enumerator> {
    children
        .iter()
        .filter(|c| c.tag == DW_TAG_ENUMERATOR)
        .map(|c| Enumerator {
            name: c.name.clone().unwrap_or_default(),
            value: c.const_value.unwrap_or(0),
        })
        .collect()
}

fn subroutine_children(children: &[TypeDie]) -> (Vec<SubroutineParam>, bool) {
    let mut params = Vec::new();
    let mut is_variadic = false;
    for child in children {
        if child.tag == DW_TAG_FORMAL_PARAMETER {
            params.push(SubroutineParam {
                name: child.name.clone(),
                type_ref: child.type_ref.unwrap_or(0),
            });
        } else if child.tag == 0x18 {
            // DW_TAG_unspecified_parameters
            is_variadic = true;
        }
    }
    (params, is_variadic)
}

// ── Forward-reference resolver ────────────────────────────────────────────────

/// A type database with forward-reference resolution.
pub struct TypeDatabase {
    /// Parsed types keyed by DIE offset.
    pub types: HashMap<TypeRef, DwarfType>,
}

impl TypeDatabase {
    /// Build from a flat list of parsed types.
    #[must_use]
    pub fn build(types: Vec<DwarfType>) -> Self {
        let mut db = Self { types: HashMap::new() };
        for t in types {
            db.types.insert(t.offset, t);
        }
        db
    }

    /// Resolve a type reference to its `DwarfType`, following typedef chains.
    #[must_use]
    pub fn resolve(&self, type_ref: TypeRef) -> Option<&DwarfType> {
        let t = self.types.get(&type_ref)?;
        match &t.kind {
            TypeKind::Typedef { aliased } => self.resolve(*aliased).or(Some(t)),
            TypeKind::Const { inner } | TypeKind::Volatile { inner } | TypeKind::Restrict { inner } => {
                self.resolve(*inner).or(Some(t))
            }
            _ => Some(t),
        }
    }

    /// Compute the byte size of a type (best-effort).
    #[must_use]
    pub fn size_of(&self, type_ref: TypeRef, ptr_size: u64) -> u64 {
        let Some(t) = self.types.get(&type_ref) else { return 0 };
        match &t.kind {
            TypeKind::Base { byte_size, .. } => *byte_size,
            TypeKind::Pointer { .. } | TypeKind::Reference { .. } | TypeKind::RvalueReference { .. } => ptr_size,
            TypeKind::Composite { byte_size, .. } => *byte_size,
            TypeKind::Enum { byte_size, .. } => *byte_size,
            TypeKind::Array { element_type, count, .. } => {
                let elem_size = self.size_of(*element_type, ptr_size);
                count.unwrap_or(0) * elem_size
            }
            TypeKind::Typedef { aliased } => self.size_of(*aliased, ptr_size),
            TypeKind::Const { inner } | TypeKind::Volatile { inner } | TypeKind::Restrict { inner } => {
                self.size_of(*inner, ptr_size)
            }
            _ => 0,
        }
    }

    /// Look up by name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&DwarfType> {
        self.types.values().find(|t| t.name.as_deref() == Some(name))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_base_die(offset: u64, name: &str, encoding: u64, size: u64) -> TypeDie {
        TypeDie {
            tag: DW_TAG_BASE_TYPE,
            offset,
            name: Some(name.into()),
            encoding: Some(encoding),
            byte_size: Some(size),
            ..Default::default()
        }
    }

    fn make_ptr_die(offset: u64, pointee: u64) -> TypeDie {
        TypeDie {
            tag: DW_TAG_POINTER_TYPE,
            offset,
            type_ref: Some(pointee),
            byte_size: Some(8),
            ..Default::default()
        }
    }

    #[test]
    fn test_base_type_int() {
        let die = make_base_die(0x10, "int", 0x05, 4);
        let types = collect_types_from_dies(&[die]);
        assert_eq!(types.len(), 1);
        if let TypeKind::Base { encoding, byte_size } = &types[0].kind {
            assert_eq!(*byte_size, 4);
            assert!(matches!(encoding, BaseEncoding::Signed));
        } else {
            panic!("expected Base");
        }
    }

    #[test]
    fn test_pointer_type() {
        let die = make_ptr_die(0x20, 0x10);
        let types = collect_types_from_dies(&[die]);
        assert_eq!(types.len(), 1);
        if let TypeKind::Pointer { pointee } = &types[0].kind {
            assert_eq!(*pointee, 0x10);
        } else {
            panic!("expected Pointer");
        }
    }

    #[test]
    fn test_struct_type() {
        let member = TypeDie {
            tag: DW_TAG_MEMBER,
            offset: 0x31,
            name: Some("x".into()),
            type_ref: Some(0x10),
            data_member_location: Some(0),
            ..Default::default()
        };
        let die = TypeDie {
            tag: DW_TAG_STRUCTURE_TYPE,
            offset: 0x30,
            name: Some("Point".into()),
            byte_size: Some(8),
            children: vec![member],
            ..Default::default()
        };
        let types = collect_types_from_dies(&[die]);
        assert!(!types.is_empty());
        let point_type = types.iter().find(|t| t.name.as_deref() == Some("Point")).unwrap();
        if let TypeKind::Composite { members, byte_size, .. } = &point_type.kind {
            assert_eq!(*byte_size, 8);
            assert_eq!(members.len(), 1);
            assert_eq!(members[0].name, "x");
        } else {
            panic!("expected Composite");
        }
    }

    #[test]
    fn test_enum_type() {
        let e1 = TypeDie {
            tag: DW_TAG_ENUMERATOR,
            offset: 0x41,
            name: Some("RED".into()),
            const_value: Some(0),
            ..Default::default()
        };
        let e2 = TypeDie {
            tag: DW_TAG_ENUMERATOR,
            offset: 0x42,
            name: Some("GREEN".into()),
            const_value: Some(1),
            ..Default::default()
        };
        let die = TypeDie {
            tag: DW_TAG_ENUMERATION_TYPE,
            offset: 0x40,
            name: Some("Color".into()),
            byte_size: Some(4),
            children: vec![e1, e2],
            ..Default::default()
        };
        let types = collect_types_from_dies(&[die]);
        let color = types.iter().find(|t| t.name.as_deref() == Some("Color")).unwrap();
        if let TypeKind::Enum { enumerators, .. } = &color.kind {
            assert_eq!(enumerators.len(), 2);
            assert_eq!(enumerators[0].name, "RED");
        } else {
            panic!("expected Enum");
        }
    }

    #[test]
    fn test_typedef() {
        let die = TypeDie {
            tag: DW_TAG_TYPEDEF,
            offset: 0x50,
            name: Some("size_t".into()),
            type_ref: Some(0x10),
            ..Default::default()
        };
        let types = collect_types_from_dies(&[die]);
        assert_eq!(types.len(), 1);
        if let TypeKind::Typedef { aliased } = &types[0].kind {
            assert_eq!(*aliased, 0x10);
        } else {
            panic!("expected Typedef");
        }
    }

    #[test]
    fn test_type_database_resolve() {
        let base = DwarfType {
            offset: 0x10,
            name: Some("int".into()),
            kind: TypeKind::Base { encoding: BaseEncoding::Signed, byte_size: 4 },
        };
        let typedef = DwarfType {
            offset: 0x50,
            name: Some("int32_t".into()),
            kind: TypeKind::Typedef { aliased: 0x10 },
        };
        let db = TypeDatabase::build(vec![base, typedef]);
        let resolved = db.resolve(0x50).unwrap();
        assert!(matches!(resolved.kind, TypeKind::Base { .. }));
    }

    #[test]
    fn test_size_of_base() {
        let base = DwarfType {
            offset: 0x10,
            name: Some("double".into()),
            kind: TypeKind::Base { encoding: BaseEncoding::Float, byte_size: 8 },
        };
        let db = TypeDatabase::build(vec![base]);
        assert_eq!(db.size_of(0x10, 8), 8);
    }

    #[test]
    fn test_size_of_pointer() {
        let ptr = DwarfType {
            offset: 0x20,
            name: None,
            kind: TypeKind::Pointer { pointee: 0 },
        };
        let db = TypeDatabase::build(vec![ptr]);
        assert_eq!(db.size_of(0x20, 8), 8);
        assert_eq!(db.size_of(0x20, 4), 4);
    }

    #[test]
    fn test_display_name_struct() {
        let t = DwarfType {
            offset: 0,
            name: Some("Foo".into()),
            kind: TypeKind::Composite {
                is_union: false,
                is_class: false,
                byte_size: 4,
                members: vec![],
                base_classes: vec![],
                template_params: vec![],
                is_declaration: false,
            },
        };
        assert_eq!(t.display_name(), "struct Foo");
    }

    #[test]
    fn test_const_type() {
        let die = TypeDie {
            tag: DW_TAG_CONST_TYPE,
            offset: 0x60,
            type_ref: Some(0x10),
            ..Default::default()
        };
        let types = collect_types_from_dies(&[die]);
        assert_eq!(types.len(), 1);
        assert!(matches!(types[0].kind, TypeKind::Const { .. }));
    }

    #[test]
    fn test_array_with_subrange() {
        let subrange = TypeDie {
            tag: DW_TAG_SUBRANGE_TYPE,
            offset: 0x71,
            upper_bound: Some(9),
            ..Default::default()
        };
        let die = TypeDie {
            tag: DW_TAG_ARRAY_TYPE,
            offset: 0x70,
            type_ref: Some(0x10),
            children: vec![subrange],
            ..Default::default()
        };
        let types = collect_types_from_dies(&[die]);
        if let TypeKind::Array { count, .. } = &types[0].kind {
            assert_eq!(*count, Some(10)); // 0..=9
        } else {
            panic!("expected Array");
        }
    }
}
