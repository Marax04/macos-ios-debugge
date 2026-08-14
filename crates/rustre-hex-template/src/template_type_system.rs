//! `template_type_system` — Extended type system for hex templates.
//!
//! Defines a rich [`TemplateType`] hierarchy (distinct from the simpler enum in
//! `lib.rs`) including alignment rules, size computation, pointer types, and
//! bitfield layouts used by the template interpreter and expression evaluator.

use std::fmt;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// TypeSize
// ─────────────────────────────────────────────────────────────────────────────

/// The size of a type — either statically known or dynamically determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeSize {
    /// Exact byte size known at parse time.
    Fixed(usize),
    /// Size is encoded in a field referenced by name.
    DynField,
    /// Size is not known until the value is read (e.g. null-terminated string).
    Unknown,
}

impl TypeSize {
    /// Returns the fixed size, or `None` for dynamic/unknown types.
    #[must_use]
    pub const fn fixed(self) -> Option<usize> {
        match self {
            Self::Fixed(n) => Some(n),
            _ => None,
        }
    }

    /// Returns `true` for `Fixed` variants.
    #[must_use]
    pub const fn is_fixed(self) -> bool {
        matches!(self, Self::Fixed(_))
    }
}

impl fmt::Display for TypeSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fixed(n) => write!(f, "{n}"),
            Self::DynField => write!(f, "<dynamic>"),
            Self::Unknown => write!(f, "<unknown>"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Endianness
// ─────────────────────────────────────────────────────────────────────────────

/// Byte order for multi-byte scalar types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Endianness {
    /// Little-endian (x86, ARM LE).
    #[default]
    Little,
    /// Big-endian (network order, MIPS BE).
    Big,
}

impl fmt::Display for Endianness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Little => write!(f, "LE"),
            Self::Big => write!(f, "BE"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScalarKind
// ─────────────────────────────────────────────────────────────────────────────

/// The fundamental kind of a scalar template type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScalarKind {
    /// Unsigned integer.
    UInt,
    /// Signed integer.
    SInt,
    /// IEEE-754 floating point.
    Float,
    /// Raw byte blob.
    Bytes,
    /// NUL-terminated C string.
    CStr,
    /// Length-prefixed string with a given prefix size in bytes.
    LenPrefixStr { prefix_bytes: u8 },
    /// Wide (UTF-16) NUL-terminated string.
    WStr,
    /// GUID (16 bytes, displayed in {XXXX-...} format).
    Guid,
}

impl fmt::Display for ScalarKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UInt => write!(f, "uint"),
            Self::SInt => write!(f, "sint"),
            Self::Float => write!(f, "float"),
            Self::Bytes => write!(f, "bytes"),
            Self::CStr => write!(f, "cstr"),
            Self::LenPrefixStr { prefix_bytes } => write!(f, "lpstr({prefix_bytes})"),
            Self::WStr => write!(f, "wstr"),
            Self::Guid => write!(f, "guid"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeKind
// ─────────────────────────────────────────────────────────────────────────────

/// Discriminant for the extended template type system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeKind {
    /// A primitive scalar with a fixed or variable byte width.
    Scalar {
        kind: ScalarKind,
        byte_width: TypeSize,
        endianness: Endianness,
    },
    /// A pointer — reads `pointer_size` bytes as an address.
    Pointer {
        pointer_size: u8,
        endianness: Endianness,
        /// Name of the type that the pointer points to (for display / navigation).
        pointee_type: String,
    },
    /// An enum: read a scalar, then map the value to a named variant.
    Enum {
        underlying: Box<TypeKind>,
        variants: Vec<EnumVariant>,
    },
    /// A bit field: read a parent scalar, extract a subset of bits.
    Bitfield {
        parent: Box<TypeKind>,
        fields: Vec<BitfieldMember>,
    },
    /// A fixed-size array `[T; N]`.
    Array {
        element: Box<TypeKind>,
        count: usize,
    },
    /// A variable-length array whose count is taken from a previously-parsed field.
    DynArray {
        element: Box<TypeKind>,
        count_field: String,
    },
    /// A struct composed of named fields.
    Struct {
        name: String,
        fields: Vec<StructField>,
    },
    /// A union where all members start at the same offset.
    Union {
        name: String,
        members: Vec<StructField>,
    },
    /// An opaque blob of a fixed number of bytes — displayed as hex.
    OpaqueBytes(usize),
    /// A padding field — bytes to skip without interpretation.
    Padding(usize),
}

impl TypeKind {
    /// Compute the byte size of this type where statically determinable.
    #[must_use]
    pub fn size(&self) -> TypeSize {
        match self {
            Self::Scalar { byte_width, .. } => *byte_width,
            Self::Pointer { pointer_size, .. } => TypeSize::Fixed(*pointer_size as usize),
            Self::Enum { underlying, .. } => underlying.size(),
            Self::Bitfield { parent, .. } => parent.size(),
            Self::Array { element, count } => match element.size() {
                TypeSize::Fixed(n) => TypeSize::Fixed(n * count),
                _ => TypeSize::Unknown,
            },
            Self::DynArray { .. } => TypeSize::DynField,
            Self::Struct { fields, .. } => {
                let mut total = 0usize;
                for f in fields {
                    match f.ty.size() {
                        TypeSize::Fixed(n) => total += n,
                        _ => return TypeSize::Unknown,
                    }
                }
                TypeSize::Fixed(total)
            }
            Self::Union { members, .. } => {
                let mut max = 0usize;
                for m in members {
                    match m.ty.size() {
                        TypeSize::Fixed(n) => max = max.max(n),
                        _ => return TypeSize::Unknown,
                    }
                }
                TypeSize::Fixed(max)
            }
            Self::OpaqueBytes(n) => TypeSize::Fixed(*n),
            Self::Padding(n) => TypeSize::Fixed(*n),
        }
    }

    /// Returns `true` if this type's size is statically known.
    #[must_use]
    pub fn is_fixed_size(&self) -> bool {
        self.size().is_fixed()
    }

    /// Whether this type is a scalar integer (signed or unsigned).
    #[must_use]
    pub fn is_integer(&self) -> bool {
        matches!(
            self,
            Self::Scalar {
                kind: ScalarKind::UInt | ScalarKind::SInt,
                ..
            }
        )
    }

    /// Whether this type is a pointer.
    #[must_use]
    pub fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer { .. })
    }

    /// Whether this type is a struct.
    #[must_use]
    pub fn is_struct(&self) -> bool {
        matches!(self, Self::Struct { .. })
    }
}

impl fmt::Display for TypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scalar { kind, byte_width, endianness } => {
                write!(f, "{kind}{byte_width}{endianness}")
            }
            Self::Pointer { pointer_size, pointee_type, endianness } => {
                write!(f, "*{pointee_type}({pointer_size}B,{endianness})")
            }
            Self::Enum { underlying, .. } => write!(f, "enum({underlying})"),
            Self::Bitfield { parent, fields } => {
                write!(f, "bitfield({parent}, {} members)", fields.len())
            }
            Self::Array { element, count } => write!(f, "[{element}; {count}]"),
            Self::DynArray { element, count_field } => {
                write!(f, "[{element}; @{count_field}]")
            }
            Self::Struct { name, .. } => write!(f, "struct {name}"),
            Self::Union { name, .. } => write!(f, "union {name}"),
            Self::OpaqueBytes(n) => write!(f, "opaque[{n}]"),
            Self::Padding(n) => write!(f, "pad[{n}]"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EnumVariant / BitfieldMember / StructField
// ─────────────────────────────────────────────────────────────────────────────

/// An enum variant mapping a numeric discriminant to a name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumVariant {
    /// Variant name.
    pub name: String,
    /// Numeric discriminant value.
    pub value: u64,
    /// Optional description.
    pub description: String,
}

impl EnumVariant {
    /// Create a simple variant.
    #[must_use]
    pub fn new(name: impl Into<String>, value: u64) -> Self {
        Self {
            name: name.into(),
            value,
            description: String::new(),
        }
    }

    /// Create a variant with a description.
    #[must_use]
    pub fn with_desc(name: impl Into<String>, value: u64, desc: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value,
            description: desc.into(),
        }
    }
}

/// A member of a bit-field layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitfieldMember {
    /// Member name.
    pub name: String,
    /// Zero-based start bit (LSB = 0).
    pub start_bit: u8,
    /// Number of bits.
    pub bit_count: u8,
    /// Optional comment.
    pub comment: String,
}

impl BitfieldMember {
    /// Create a bitfield member.
    #[must_use]
    pub fn new(name: impl Into<String>, start_bit: u8, bit_count: u8) -> Self {
        Self {
            name: name.into(),
            start_bit,
            bit_count,
            comment: String::new(),
        }
    }

    /// Extract this member's value from a raw integer.
    #[must_use]
    pub fn extract(&self, raw: u64) -> u64 {
        let mask = if self.bit_count >= 64 {
            u64::MAX
        } else {
            (1u64 << self.bit_count) - 1
        };
        (raw >> self.start_bit) & mask
    }

    /// Insert `val` into `raw` at this member's bit position.
    #[must_use]
    pub fn insert(&self, raw: u64, val: u64) -> u64 {
        let mask = if self.bit_count >= 64 {
            u64::MAX
        } else {
            (1u64 << self.bit_count) - 1
        };
        let cleared = raw & !(mask << self.start_bit);
        cleared | ((val & mask) << self.start_bit)
    }
}

/// A field within a struct or union type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructField {
    /// Field name.
    pub name: String,
    /// Field type.
    pub ty: Box<TypeKind>,
    /// Optional explicit byte offset within the struct.
    pub offset: Option<usize>,
    /// Comment / documentation.
    pub comment: String,
}

impl StructField {
    /// Create a field with sequential placement.
    #[must_use]
    pub fn new(name: impl Into<String>, ty: TypeKind) -> Self {
        Self {
            name: name.into(),
            ty: Box::new(ty),
            offset: None,
            comment: String::new(),
        }
    }

    /// Create a field at an explicit offset.
    #[must_use]
    pub fn at_offset(name: impl Into<String>, ty: TypeKind, offset: usize) -> Self {
        Self {
            name: name.into(),
            ty: Box::new(ty),
            offset: Some(offset),
            comment: String::new(),
        }
    }

    /// Add a comment.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = comment.into();
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// type_alignment
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the natural alignment of a type in bytes.
///
/// The alignment rules follow the C ABI convention:
/// - Scalars align to their own size (up to 8).
/// - Structs and unions align to the maximum alignment of their members.
/// - Arrays align to the alignment of their element type.
/// - Pointers align to their pointer size.
/// - Bitfields align to the parent type's alignment.
/// - Opaque blobs and padding use 1-byte alignment.
#[must_use]
pub fn type_alignment(ty: &TypeKind) -> usize {
    match ty {
        TypeKind::Scalar { byte_width, .. } => match byte_width {
            TypeSize::Fixed(n) => (*n).min(8).max(1),
            _ => 1,
        },
        TypeKind::Pointer { pointer_size, .. } => *pointer_size as usize,
        TypeKind::Enum { underlying, .. } => type_alignment(underlying),
        TypeKind::Bitfield { parent, .. } => type_alignment(parent),
        TypeKind::Array { element, .. } => type_alignment(element),
        TypeKind::DynArray { element, .. } => type_alignment(element),
        TypeKind::Struct { fields, .. } | TypeKind::Union { members: fields, .. } => fields
            .iter()
            .map(|f| type_alignment(&f.ty))
            .max()
            .unwrap_or(1),
        TypeKind::OpaqueBytes(_) | TypeKind::Padding(_) => 1,
    }
}

/// Align `offset` up to `alignment`.
#[must_use]
pub fn align_offset(offset: usize, alignment: usize) -> usize {
    if alignment == 0 {
        return offset;
    }
    (offset + alignment - 1) & !(alignment - 1)
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateType (extended)
// ─────────────────────────────────────────────────────────────────────────────

/// A fully-described template type including its [`TypeKind`], alignment, and
/// human-readable name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateType {
    /// Human-readable type name (e.g. `"DWORD"`, `"PDB_GUID"`, `"ELF_HEADER"`).
    pub name: String,
    /// Detailed type description.
    pub kind: TypeKind,
    /// Override alignment (0 = use natural alignment from [`type_alignment`]).
    pub alignment_override: usize,
    /// Comment / documentation string.
    pub comment: String,
}

impl TemplateType {
    /// Create a named template type with automatic alignment.
    #[must_use]
    pub fn new(name: impl Into<String>, kind: TypeKind) -> Self {
        Self {
            name: name.into(),
            kind,
            alignment_override: 0,
            comment: String::new(),
        }
    }

    /// Create with an explicit alignment override.
    #[must_use]
    pub fn with_alignment(mut self, align: usize) -> Self {
        self.alignment_override = align;
        self
    }

    /// Attach a comment.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = comment.into();
        self
    }

    /// Return the effective alignment (override or natural).
    #[must_use]
    pub fn alignment(&self) -> usize {
        if self.alignment_override > 0 {
            self.alignment_override
        } else {
            type_alignment(&self.kind)
        }
    }

    /// Return the size of this type.
    #[must_use]
    pub fn size(&self) -> TypeSize {
        self.kind.size()
    }

    /// Returns `true` if the size is statically known.
    #[must_use]
    pub fn is_fixed_size(&self) -> bool {
        self.kind.is_fixed_size()
    }
}

impl fmt::Display for TemplateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} :: {} (align={})", self.name, self.kind, self.alignment())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// A registry mapping type names to [`TemplateType`] definitions.
///
/// Used by the interpreter to look up named types referenced in struct fields
/// and template expressions.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TypeRegistry {
    types: std::collections::HashMap<String, TemplateType>,
}

impl TypeRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry pre-populated with common primitive aliases.
    #[must_use]
    pub fn with_primitives() -> Self {
        let mut r = Self::new();
        // Unsigned integers (little-endian)
        r.register(TemplateType::new("BYTE", uint_le(1)));
        r.register(TemplateType::new("WORD", uint_le(2)));
        r.register(TemplateType::new("DWORD", uint_le(4)));
        r.register(TemplateType::new("QWORD", uint_le(8)));
        // Signed integers (little-endian)
        r.register(TemplateType::new("CHAR", sint_le(1)));
        r.register(TemplateType::new("SHORT", sint_le(2)));
        r.register(TemplateType::new("LONG", sint_le(4)));
        r.register(TemplateType::new("LONGLONG", sint_le(8)));
        // Big-endian variants
        r.register(TemplateType::new("U16BE", uint_be(2)));
        r.register(TemplateType::new("U32BE", uint_be(4)));
        r.register(TemplateType::new("U64BE", uint_be(8)));
        // Floats
        r.register(TemplateType::new(
            "FLOAT",
            TypeKind::Scalar {
                kind: ScalarKind::Float,
                byte_width: TypeSize::Fixed(4),
                endianness: Endianness::Little,
            },
        ));
        r.register(TemplateType::new(
            "DOUBLE",
            TypeKind::Scalar {
                kind: ScalarKind::Float,
                byte_width: TypeSize::Fixed(8),
                endianness: Endianness::Little,
            },
        ));
        // Strings
        r.register(TemplateType::new(
            "CSTR",
            TypeKind::Scalar {
                kind: ScalarKind::CStr,
                byte_width: TypeSize::Unknown,
                endianness: Endianness::Little,
            },
        ));
        r.register(TemplateType::new(
            "WSTR",
            TypeKind::Scalar {
                kind: ScalarKind::WStr,
                byte_width: TypeSize::Unknown,
                endianness: Endianness::Little,
            },
        ));
        // GUID
        r.register(TemplateType::new(
            "GUID",
            TypeKind::Scalar {
                kind: ScalarKind::Guid,
                byte_width: TypeSize::Fixed(16),
                endianness: Endianness::Little,
            },
        ));
        // Pointers
        r.register(TemplateType::new(
            "PTR32",
            TypeKind::Pointer {
                pointer_size: 4,
                endianness: Endianness::Little,
                pointee_type: "void".to_string(),
            },
        ));
        r.register(TemplateType::new(
            "PTR64",
            TypeKind::Pointer {
                pointer_size: 8,
                endianness: Endianness::Little,
                pointee_type: "void".to_string(),
            },
        ));
        r
    }

    /// Register a type, replacing any existing entry with the same name.
    pub fn register(&mut self, ty: TemplateType) {
        self.types.insert(ty.name.clone(), ty);
    }

    /// Look up a type by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&TemplateType> {
        self.types.get(name)
    }

    /// Remove a type by name.
    pub fn remove(&mut self, name: &str) -> Option<TemplateType> {
        self.types.remove(name)
    }

    /// All registered type names, sorted.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.types.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Number of registered types.
    #[must_use]
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Returns `true` if no types are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Compute the total size of a struct type, respecting alignment.
    ///
    /// Returns `None` if any field has an unknown size.
    #[must_use]
    pub fn struct_layout(&self, fields: &[StructField]) -> Option<StructLayout> {
        let mut offset = 0usize;
        let mut field_offsets = Vec::with_capacity(fields.len());
        let mut max_align = 1usize;
        for field in fields {
            let align = type_alignment(&field.ty);
            max_align = max_align.max(align);
            let field_off = if let Some(explicit) = field.offset {
                explicit
            } else {
                align_offset(offset, align)
            };
            let size = field.ty.size().fixed()?;
            field_offsets.push((field.name.clone(), field_off, size));
            offset = field_off + size;
        }
        let total = align_offset(offset, max_align);
        Some(StructLayout {
            field_offsets,
            total_size: total,
            alignment: max_align,
        })
    }
}

/// Result of computing the layout of a struct type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructLayout {
    /// `(field_name, byte_offset, byte_size)` for each field.
    pub field_offsets: Vec<(String, usize, usize)>,
    /// Total size of the struct including trailing alignment padding.
    pub total_size: usize,
    /// Alignment requirement of the struct.
    pub alignment: usize,
}

impl StructLayout {
    /// Return the offset of a named field.
    #[must_use]
    pub fn offset_of(&self, name: &str) -> Option<usize> {
        self.field_offsets
            .iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, off, _)| *off)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Primitive constructors
// ─────────────────────────────────────────────────────────────────────────────

/// Create an unsigned little-endian scalar of `bytes` bytes.
#[must_use]
pub fn uint_le(bytes: usize) -> TypeKind {
    TypeKind::Scalar {
        kind: ScalarKind::UInt,
        byte_width: TypeSize::Fixed(bytes),
        endianness: Endianness::Little,
    }
}

/// Create an unsigned big-endian scalar of `bytes` bytes.
#[must_use]
pub fn uint_be(bytes: usize) -> TypeKind {
    TypeKind::Scalar {
        kind: ScalarKind::UInt,
        byte_width: TypeSize::Fixed(bytes),
        endianness: Endianness::Big,
    }
}

/// Create a signed little-endian scalar of `bytes` bytes.
#[must_use]
pub fn sint_le(bytes: usize) -> TypeKind {
    TypeKind::Scalar {
        kind: ScalarKind::SInt,
        byte_width: TypeSize::Fixed(bytes),
        endianness: Endianness::Little,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_size_fixed() {
        let ty = uint_le(4);
        assert_eq!(ty.size(), TypeSize::Fixed(4));
        assert!(ty.is_fixed_size());
    }

    #[test]
    fn test_array_size_fixed() {
        let ty = TypeKind::Array {
            element: Box::new(uint_le(2)),
            count: 8,
        };
        assert_eq!(ty.size(), TypeSize::Fixed(16));
    }

    #[test]
    fn test_struct_size() {
        let fields = vec![
            StructField::new("a", uint_le(1)),
            StructField::new("b", uint_le(4)),
        ];
        let ty = TypeKind::Struct {
            name: "S".to_string(),
            fields,
        };
        // 1 (a) + 3 (pad) + 4 (b) = 8
        assert_eq!(ty.size(), TypeSize::Fixed(5)); // no padding in TypeKind::size
    }

    #[test]
    fn test_type_alignment_scalar() {
        assert_eq!(type_alignment(&uint_le(1)), 1);
        assert_eq!(type_alignment(&uint_le(2)), 2);
        assert_eq!(type_alignment(&uint_le(4)), 4);
        assert_eq!(type_alignment(&uint_le(8)), 8);
    }

    #[test]
    fn test_type_alignment_pointer() {
        let ptr = TypeKind::Pointer {
            pointer_size: 8,
            endianness: Endianness::Little,
            pointee_type: "void".to_string(),
        };
        assert_eq!(type_alignment(&ptr), 8);
    }

    #[test]
    fn test_align_offset() {
        assert_eq!(align_offset(0, 4), 0);
        assert_eq!(align_offset(1, 4), 4);
        assert_eq!(align_offset(5, 8), 8);
        assert_eq!(align_offset(8, 8), 8);
    }

    #[test]
    fn test_bitfield_member_extract() {
        let m = BitfieldMember::new("flags", 4, 4);
        assert_eq!(m.extract(0xF0), 0xF);
        assert_eq!(m.extract(0x30), 0x3);
    }

    #[test]
    fn test_bitfield_member_insert() {
        let m = BitfieldMember::new("f", 4, 4);
        let result = m.insert(0x00, 0xA);
        assert_eq!(result, 0xA0);
    }

    #[test]
    fn test_registry_with_primitives() {
        let reg = TypeRegistry::with_primitives();
        assert!(reg.get("DWORD").is_some());
        assert!(reg.get("GUID").is_some());
        assert!(reg.get("PTR64").is_some());
        assert!(!reg.is_empty());
    }

    #[test]
    fn test_registry_struct_layout() {
        let reg = TypeRegistry::with_primitives();
        let fields = vec![
            StructField::new("a", uint_le(1)),
            StructField::new("b", uint_le(4)),
            StructField::new("c", uint_le(2)),
        ];
        let layout = reg.struct_layout(&fields).unwrap();
        assert_eq!(layout.offset_of("a"), Some(0));
        // b at offset 4 (4-byte aligned)
        assert_eq!(layout.offset_of("b"), Some(4));
        // c at offset 8
        assert_eq!(layout.offset_of("c"), Some(8));
    }

    #[test]
    fn test_template_type_display() {
        let tt = TemplateType::new("MyDword", uint_le(4));
        let s = format!("{tt}");
        assert!(s.contains("MyDword"));
        assert!(s.contains("align=4"));
    }

    #[test]
    fn test_enum_variant_new() {
        let v = EnumVariant::new("OK", 0);
        assert_eq!(v.name, "OK");
        assert_eq!(v.value, 0);
        assert!(v.description.is_empty());
    }

    #[test]
    fn test_type_size_display() {
        assert_eq!(TypeSize::Fixed(4).to_string(), "4");
        assert_eq!(TypeSize::DynField.to_string(), "<dynamic>");
        assert_eq!(TypeSize::Unknown.to_string(), "<unknown>");
    }
}
