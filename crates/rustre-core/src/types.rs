//! Serialisable, analysis-layer type system for the `RustRE` platform.
//!
//! This module is the **analysis/storage** layer for type information.  It is
//! intentionally distinct from [`type_system_full`], which is the
//! **decompiler/recovery** layer.  The split exists because the two layers have
//! different requirements:
//!
//! | Concern | This module (`types`) | `type_system_full` |
//! |---------|----------------------|-------------------|
//! | Purpose | Persistent, serialisable type store for analysis passes | Thread-safe type system for decompilation and type recovery |
//! | `TypeKind` variants | Closed set incl. Union, Typedef, Opaque | Richer: adds qualifiers (Const/Volatile/Atomic/Restrict), Var, FlexArray, Intrinsic, Forward |
//! | Thread safety | `&mut self` methods, no internal lock | `RwLock`-wrapped; all methods take `&self` |
//! | Serde | `Serialize`/`Deserialize` on all public types | No serde on `TypeSystem` |
//! | Pre-populated built-ins | Yes — IDs 1–31 are reserved primitives | Via `populate_builtins()` |
//! | Extra utilities | — | `TypeLayout`, `TypePrinter`, `DwarfTypeImporter`, `PdbTypeImporter` |
//!
//! Use **this module** when you need to serialise/deserialise type information
//! (e.g. project save/load, MCP export).  Use [`type_system_full`] when you
//! need type inference, C-style printing, or layout computation.
//!
//! Key types exported by this module:
//! - [`TypeId`] — stable numeric identity for a type definition.
//! - [`TypeKind`] — the recursive, serde-compatible type descriptor.
//! - [`TypeDef`] — a registered type with id + kind + metadata.
//! - [`TypeStore`] — the central registry, indexed by both id and name.
//! - [`StructField`] — a named field inside a struct type.
//! - [`EnumMember`] — a discriminant/value pair for an enum type.
//! - [`FunctionSignature`] — a full function type including parameter names.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// TypeId
// ─────────────────────────────────────────────────────────────────────────────

/// A stable, globally-unique identifier for a type definition.
///
/// IDs are allocated by [`TypeStore`] using an atomic counter.  The value `0`
/// is reserved as the "invalid" sentinel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct TypeId(pub u32);

impl TypeId {
    /// The invalid / null sentinel.
    pub const INVALID: Self = Self(0);

    /// Create a `TypeId` from a raw value.
    #[must_use]
    pub const fn from_raw(v: u32) -> Self {
        Self(v)
    }

    /// Return the raw `u32`.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Return `true` if this is a valid (non-zero) id.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

impl fmt::Display for TypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TypeId({})", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Calling convention name type
// ─────────────────────────────────────────────────────────────────────────────

/// Well-known calling convention identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallConvId {
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    Vectorcall,
    SysVAmd64,
    Win64,
    Aapcs,
    Aapcs64,
    MipsO32,
    RiscVLp64,
    Custom(String),
}

impl fmt::Display for CallConvId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cdecl => write!(f, "__cdecl"),
            Self::Stdcall => write!(f, "__stdcall"),
            Self::Fastcall => write!(f, "__fastcall"),
            Self::Thiscall => write!(f, "__thiscall"),
            Self::Vectorcall => write!(f, "__vectorcall"),
            Self::SysVAmd64 => write!(f, "System V AMD64"),
            Self::Win64 => write!(f, "Windows x64"),
            Self::Aapcs => write!(f, "AAPCS"),
            Self::Aapcs64 => write!(f, "AAPCS64"),
            Self::MipsO32 => write!(f, "MIPS O32"),
            Self::RiscVLp64 => write!(f, "RISC-V LP64"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StructField
// ─────────────────────────────────────────────────────────────────────────────

/// A named field at a fixed byte offset within a struct or union.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructField {
    /// Field name.
    pub name: String,
    /// Byte offset from the start of the parent type.
    pub offset: u32,
    /// The type of this field (by id).
    pub type_id: TypeId,
    /// Bit offset within the storage unit (for bitfields; 0 for normal fields).
    pub bit_offset: u8,
    /// Width in bits (for bitfields; 0 means "full storage unit").
    pub bit_width: u8,
    /// `true` if this field is a bitfield.
    pub is_bitfield: bool,
    /// Optional comment / annotation.
    pub comment: Option<String>,
}

impl StructField {
    /// Construct a normal (non-bitfield) field.
    #[must_use]
    pub fn new(name: impl Into<String>, offset: u32, type_id: TypeId) -> Self {
        Self {
            name: name.into(),
            offset,
            type_id,
            bit_offset: 0,
            bit_width: 0,
            is_bitfield: false,
            comment: None,
        }
    }

    /// Construct a bitfield.
    #[must_use]
    pub fn bitfield(
        name: impl Into<String>,
        offset: u32,
        type_id: TypeId,
        bit_offset: u8,
        bit_width: u8,
    ) -> Self {
        Self {
            name: name.into(),
            offset,
            type_id,
            bit_offset,
            bit_width,
            is_bitfield: true,
            comment: None,
        }
    }

    /// Attach a comment.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EnumMember
// ─────────────────────────────────────────────────────────────────────────────

/// A single named variant of an enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnumMember {
    /// The variant name.
    pub name: String,
    /// The discriminant value.
    pub value: i64,
    /// Optional comment.
    pub comment: Option<String>,
}

impl EnumMember {
    /// Construct a member without a comment.
    #[must_use]
    pub fn new(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: name.into(),
            value,
            comment: None,
        }
    }

    /// Attach a comment.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionParameter
// ─────────────────────────────────────────────────────────────────────────────

/// A single parameter in a function signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionParam {
    /// Parameter name (may be empty if unnamed).
    pub name: String,
    /// Type of this parameter.
    pub type_id: TypeId,
    /// `true` if this is the variadic tail (`...`).
    pub is_variadic_rest: bool,
}

impl FunctionParam {
    /// Construct a named parameter.
    #[must_use]
    pub fn new(name: impl Into<String>, type_id: TypeId) -> Self {
        Self {
            name: name.into(),
            type_id,
            is_variadic_rest: false,
        }
    }

    /// Construct an unnamed parameter.
    #[must_use]
    pub fn unnamed(type_id: TypeId) -> Self {
        Self::new("", type_id)
    }
}

/// A complete function type signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSignature {
    /// Return type.
    pub ret: TypeId,
    /// Ordered list of parameters.
    pub params: Vec<FunctionParam>,
    /// `true` if the function accepts a variadic argument list.
    pub variadic: bool,
    /// Calling convention.
    pub calling_convention: Option<CallConvId>,
}

impl FunctionSignature {
    /// Construct a minimal signature with only a return type.
    #[must_use]
    pub const fn new(ret: TypeId) -> Self {
        Self {
            ret,
            params: Vec::new(),
            variadic: false,
            calling_convention: None,
        }
    }

    /// Add a parameter.
    #[must_use]
    pub fn with_param(mut self, param: FunctionParam) -> Self {
        self.params.push(param);
        self
    }

    /// Mark as variadic.
    #[must_use]
    pub const fn variadic(mut self) -> Self {
        self.variadic = true;
        self
    }

    /// Set calling convention.
    #[must_use]
    pub fn with_cc(mut self, cc: CallConvId) -> Self {
        self.calling_convention = Some(cc);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeKind — the recursive type descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Integer width and signedness.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IntType {
    /// Width in bits (1, 8, 16, 32, 64, 128, …).
    pub bits: u16,
    /// `true` for signed, `false` for unsigned.
    pub signed: bool,
}

impl IntType {
    /// Construct a signed integer of `bits` width.
    #[must_use]
    pub const fn signed(bits: u16) -> Self {
        Self { bits, signed: true }
    }

    /// Construct an unsigned integer of `bits` width.
    #[must_use]
    pub const fn unsigned(bits: u16) -> Self {
        Self {
            bits,
            signed: false,
        }
    }

    /// Byte width (rounded up).
    #[must_use]
    pub const fn bytes(&self) -> usize {
        (self.bits as usize).div_ceil(8)
    }
}

impl fmt::Display for IntType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.signed {
            write!(f, "i{}", self.bits)
        } else {
            write!(f, "u{}", self.bits)
        }
    }
}

/// Float precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FloatKind {
    /// IEEE 754 binary16 (half precision).
    F16,
    /// IEEE 754 binary32 (single precision).
    F32,
    /// IEEE 754 binary64 (double precision).
    F64,
    /// x87 80-bit extended precision.
    F80,
    /// IEEE 754 binary128 (quad precision).
    F128,
}

impl FloatKind {
    /// Byte width.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::F16 => 2,
            Self::F32 => 4,
            Self::F64 => 8,
            Self::F80 => 10,
            Self::F128 => 16,
        }
    }
}

impl fmt::Display for FloatKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::F16 => write!(f, "f16"),
            Self::F32 => write!(f, "f32"),
            Self::F64 => write!(f, "f64"),
            Self::F80 => write!(f, "f80"),
            Self::F128 => write!(f, "f128"),
        }
    }
}

/// The structural classification of a type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeKind {
    /// Void (zero-width, no value).
    Void,
    /// Boolean (`_Bool`, `bool`).
    Bool,
    /// Signed or unsigned integer.
    Integer(IntType),
    /// Floating-point value.
    Float(FloatKind),
    /// Raw pointer to another type.
    Pointer {
        /// Type being pointed to.
        pointee: TypeId,
        /// Pointer width in bytes (4 or 8).
        width: u8,
        /// `true` if the pointer is `const`-qualified.
        is_const: bool,
        /// `true` if the pointer is `volatile`-qualified.
        is_volatile: bool,
    },
    /// A fixed-length array `[T; N]`.
    Array {
        /// Element type.
        element: TypeId,
        /// Number of elements.
        count: u64,
    },
    /// A C-style struct (or C++ class layout).
    Struct {
        /// Declared name.
        name: String,
        /// Ordered fields.
        fields: Vec<StructField>,
        /// Total declared size in bytes (may include trailing padding).
        size: u32,
        /// Alignment requirement in bytes.
        align: u32,
        /// `true` if this is a C++ class (`struct` with methods / vtable).
        is_class: bool,
    },
    /// A C-style union.
    Union {
        /// Declared name.
        name: String,
        /// All members (may share storage).
        members: Vec<StructField>,
        /// Size in bytes.
        size: u32,
    },
    /// An enumeration.
    Enum {
        /// Declared name.
        name: String,
        /// The underlying integer type.
        underlying: TypeId,
        /// Named values.
        members: Vec<EnumMember>,
    },
    /// A function pointer / function type.
    Function(FunctionSignature),
    /// A `typedef` alias for another type.
    Typedef {
        /// Alias name.
        name: String,
        /// The aliased type.
        target: TypeId,
    },
    /// An opaque / forward-declared type whose definition is not yet known.
    Opaque {
        /// Name.
        name: String,
        /// Known size in bytes (may be zero if truly unknown).
        size: u32,
    },
}

impl TypeKind {
    /// Return the byte size of the type for a given pointer width, or `None` if
    /// the size is not statically known (e.g. opaque types with `size == 0`).
    #[must_use]
    pub fn byte_size(&self, ptr_width: usize) -> Option<usize> {
        match self {
            Self::Void | Self::Function(_) | Self::Typedef { .. } => Some(0),
            Self::Bool => Some(1),
            Self::Integer(i) => Some(i.bytes()),
            Self::Float(f) => Some(f.bytes()),
            // Use the stored width if non-zero, otherwise fall back to the
            // platform pointer width supplied by the caller.
            Self::Pointer { width, .. } => {
                let w = if *width > 0 {
                    *width as usize
                } else {
                    ptr_width
                };
                Some(w)
            }
            Self::Array { count, .. } => Some(usize::try_from(*count).unwrap_or(usize::MAX)), // element size unknown without store
            Self::Struct { size, .. } | Self::Union { size, .. } => Some(*size as usize),
            Self::Enum { .. } => Some(4), // assume int-sized unless underlying resolves differently
            Self::Opaque { size, .. } => {
                if *size == 0 {
                    None
                } else {
                    Some(*size as usize)
                }
            }
        }
    }

    /// Return `true` if this type is the `void` type.
    #[must_use]
    pub const fn is_void(&self) -> bool {
        matches!(self, Self::Void)
    }

    /// Return `true` if this is a pointer type.
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer { .. })
    }

    /// Return `true` if this is any integral type (integer, bool, enum).
    #[must_use]
    pub const fn is_integral(&self) -> bool {
        matches!(self, Self::Integer(_) | Self::Bool | Self::Enum { .. })
    }

    /// Return `true` if this is a floating-point type.
    #[must_use]
    pub const fn is_float(&self) -> bool {
        matches!(self, Self::Float(_))
    }

    /// Return `true` if this is a composite type (struct or union).
    #[must_use]
    pub const fn is_composite(&self) -> bool {
        matches!(self, Self::Struct { .. } | Self::Union { .. })
    }

    /// A short tag string for display.
    #[must_use]
    pub const fn kind_tag(&self) -> &'static str {
        match self {
            Self::Void => "void",
            Self::Bool => "bool",
            Self::Integer(_) => "int",
            Self::Float(_) => "float",
            Self::Pointer { .. } => "ptr",
            Self::Array { .. } => "array",
            Self::Struct { .. } => "struct",
            Self::Union { .. } => "union",
            Self::Enum { .. } => "enum",
            Self::Function(_) => "fn",
            Self::Typedef { .. } => "typedef",
            Self::Opaque { .. } => "opaque",
        }
    }
}

impl fmt::Display for TypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Void => write!(f, "void"),
            Self::Bool => write!(f, "bool"),
            Self::Integer(i) => write!(f, "{i}"),
            Self::Float(fl) => write!(f, "{fl}"),
            Self::Pointer {
                is_const,
                is_volatile,
                ..
            } => {
                if *is_const {
                    write!(f, "const ")?;
                }
                if *is_volatile {
                    write!(f, "volatile ")?;
                }
                write!(f, "*<type>")
            }
            Self::Array { count, .. } => write!(f, "[<type>; {count}]"),
            Self::Struct { name, .. } => write!(f, "struct {name}"),
            Self::Union { name, .. } => write!(f, "union {name}"),
            Self::Enum { name, .. } => write!(f, "enum {name}"),
            Self::Function(_) => write!(f, "fn(...)"),
            Self::Typedef { name, .. } => write!(f, "typedef {name}"),
            Self::Opaque { name, .. } => write!(f, "opaque {name}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeDef — a registered type with identity and metadata
// ─────────────────────────────────────────────────────────────────────────────

/// A fully registered type definition held in [`TypeStore`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDef {
    /// Unique stable identifier.
    pub id: TypeId,
    /// The type's structural classification.
    pub kind: TypeKind,
    /// Optional user-visible comment.
    pub comment: Option<String>,
    /// Source of this type (e.g. `"PDB"`, `"DWARF"`, `"User"`).
    pub source: Option<String>,
}

impl TypeDef {
    /// Create a new type definition without comment or source.
    #[must_use]
    pub const fn new(id: TypeId, kind: TypeKind) -> Self {
        Self {
            id,
            kind,
            comment: None,
            source: None,
        }
    }

    /// Attach a comment.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Attach a source tag.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeStore — the central type registry
// ─────────────────────────────────────────────────────────────────────────────

/// Central registry for all type definitions in an analysis session.
///
/// Types are stored by [`TypeId`].  Named types (struct, union, enum, typedef,
/// opaque) are also indexed by their declared name.
///
/// The store pre-populates a set of built-in primitive types at construction
/// time; these have IDs in the range `[1, 32)`.
#[derive(Debug)]
pub struct TypeStore {
    /// All definitions, keyed by id.
    by_id: HashMap<TypeId, TypeDef>,
    /// Named types (struct/union/enum/typedef/opaque) keyed by name.
    by_name: HashMap<String, TypeId>,
    /// Monotonic id counter.
    next_id: Arc<AtomicU32>,
}

impl TypeStore {
    // Well-known primitive type IDs.
    pub const VOID_ID: TypeId = TypeId::from_raw(1);
    pub const BOOL_ID: TypeId = TypeId::from_raw(2);
    pub const U8_ID: TypeId = TypeId::from_raw(3);
    pub const U16_ID: TypeId = TypeId::from_raw(4);
    pub const U32_ID: TypeId = TypeId::from_raw(5);
    pub const U64_ID: TypeId = TypeId::from_raw(6);
    pub const U128_ID: TypeId = TypeId::from_raw(7);
    pub const I8_ID: TypeId = TypeId::from_raw(8);
    pub const I16_ID: TypeId = TypeId::from_raw(9);
    pub const I32_ID: TypeId = TypeId::from_raw(10);
    pub const I64_ID: TypeId = TypeId::from_raw(11);
    pub const I128_ID: TypeId = TypeId::from_raw(12);
    pub const F16_ID: TypeId = TypeId::from_raw(13);
    pub const F32_ID: TypeId = TypeId::from_raw(14);
    pub const F64_ID: TypeId = TypeId::from_raw(15);
    pub const F80_ID: TypeId = TypeId::from_raw(16);
    pub const F128_ID: TypeId = TypeId::from_raw(17);
    // IDs 18–31 are reserved for future built-ins.
    const FIRST_USER_ID: u32 = 32;

    /// Create a store pre-populated with built-in primitive types.
    #[must_use]
    pub fn new() -> Self {
        let mut store = Self {
            by_id: HashMap::new(),
            by_name: HashMap::new(),
            next_id: Arc::new(AtomicU32::new(Self::FIRST_USER_ID)),
        };
        store.insert_builtin(Self::VOID_ID, TypeKind::Void);
        store.insert_builtin(Self::BOOL_ID, TypeKind::Bool);
        store.insert_builtin(Self::U8_ID, TypeKind::Integer(IntType::unsigned(8)));
        store.insert_builtin(Self::U16_ID, TypeKind::Integer(IntType::unsigned(16)));
        store.insert_builtin(Self::U32_ID, TypeKind::Integer(IntType::unsigned(32)));
        store.insert_builtin(Self::U64_ID, TypeKind::Integer(IntType::unsigned(64)));
        store.insert_builtin(Self::U128_ID, TypeKind::Integer(IntType::unsigned(128)));
        store.insert_builtin(Self::I8_ID, TypeKind::Integer(IntType::signed(8)));
        store.insert_builtin(Self::I16_ID, TypeKind::Integer(IntType::signed(16)));
        store.insert_builtin(Self::I32_ID, TypeKind::Integer(IntType::signed(32)));
        store.insert_builtin(Self::I64_ID, TypeKind::Integer(IntType::signed(64)));
        store.insert_builtin(Self::I128_ID, TypeKind::Integer(IntType::signed(128)));
        store.insert_builtin(Self::F16_ID, TypeKind::Float(FloatKind::F16));
        store.insert_builtin(Self::F32_ID, TypeKind::Float(FloatKind::F32));
        store.insert_builtin(Self::F64_ID, TypeKind::Float(FloatKind::F64));
        store.insert_builtin(Self::F80_ID, TypeKind::Float(FloatKind::F80));
        store.insert_builtin(Self::F128_ID, TypeKind::Float(FloatKind::F128));
        store
    }

    fn insert_builtin(&mut self, id: TypeId, kind: TypeKind) {
        self.by_id.insert(id, TypeDef::new(id, kind));
    }

    /// Allocate a new unique `TypeId`.
    #[must_use]
    pub fn alloc_id(&self) -> TypeId {
        TypeId::from_raw(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Register a `TypeDef`.  Overwrites any existing definition with the same id.
    ///
    /// Named types (struct/union/enum/typedef/opaque) are also indexed by name.
    pub fn register(&mut self, def: TypeDef) {
        // Index by name for named types.
        match &def.kind {
            TypeKind::Struct { name, .. }
            | TypeKind::Union { name, .. }
            | TypeKind::Enum { name, .. }
            | TypeKind::Typedef { name, .. }
            | TypeKind::Opaque { name, .. } => {
                self.by_name.insert(name.clone(), def.id);
            }
            _ => {}
        }
        self.by_id.insert(def.id, def);
    }

    /// Define a new type and assign it the next available id.
    ///
    /// Returns the allocated `TypeId`.
    pub fn define(&mut self, kind: TypeKind) -> TypeId {
        let id = self.alloc_id();
        self.register(TypeDef::new(id, kind));
        id
    }

    /// Look up a type by its `TypeId`.
    #[must_use]
    pub fn get(&self, id: TypeId) -> Option<&TypeDef> {
        self.by_id.get(&id)
    }

    /// Look up a type by its declared name (struct/union/enum/typedef/opaque).
    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<&TypeDef> {
        let id = self.by_name.get(name)?;
        self.by_id.get(id)
    }

    /// Resolve a `TypeId` through `Typedef` aliases until a non-typedef is found.
    ///
    /// Stops after `max_depth` steps to prevent infinite loops from circular
    /// typedef graphs (which should not occur in valid programs but might in
    /// malformed type information).
    #[must_use]
    pub fn resolve_typedef(&self, id: TypeId, max_depth: usize) -> TypeId {
        let mut current = id;
        for _ in 0..max_depth {
            match self.by_id.get(&current) {
                Some(def) => {
                    if let TypeKind::Typedef { target, .. } = &def.kind {
                        current = *target;
                    } else {
                        break;
                    }
                }
                None => break,
            }
        }
        current
    }

    /// Compute the byte size of a type.
    ///
    /// For types whose size depends on pointer width (e.g. `Pointer`), pass
    /// `ptr_width` in bytes (4 or 8).
    ///
    /// Returns `None` for opaque types or types not found in the store.
    #[must_use]
    pub fn byte_size(&self, id: TypeId, ptr_width: usize) -> Option<usize> {
        let resolved = self.resolve_typedef(id, 16);
        let def = self.by_id.get(&resolved)?;
        match &def.kind {
            TypeKind::Pointer { width, .. } => {
                let w = if *width > 0 {
                    *width as usize
                } else {
                    ptr_width
                };
                Some(w)
            }
            TypeKind::Array { element, count } => self
                .byte_size(*element, ptr_width)
                .map(|elem_sz| elem_sz * usize::try_from(*count).unwrap_or(usize::MAX)),
            other => other.byte_size(ptr_width),
        }
    }

    /// Remove a type definition by id.  Returns the removed definition if it existed.
    pub fn remove(&mut self, id: TypeId) -> Option<TypeDef> {
        let def = self.by_id.remove(&id)?;
        match &def.kind {
            TypeKind::Struct { name, .. }
            | TypeKind::Union { name, .. }
            | TypeKind::Enum { name, .. }
            | TypeKind::Typedef { name, .. }
            | TypeKind::Opaque { name, .. } => {
                self.by_name.remove(name.as_str());
            }
            _ => {}
        }
        Some(def)
    }

    /// Total number of type definitions (including built-ins).
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Return `true` if the store contains only built-ins.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over all type definitions.
    pub fn iter(&self) -> impl Iterator<Item = &TypeDef> {
        self.by_id.values()
    }

    /// All registered names (for named types).
    #[must_use]
    pub fn all_names(&self) -> Vec<&str> {
        self.by_name.keys().map(String::as_str).collect()
    }
}

impl Default for TypeStore {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_store_has_builtins() {
        let store = TypeStore::new();
        assert!(store.get(TypeStore::VOID_ID).is_some());
        assert!(store.get(TypeStore::U64_ID).is_some());
        assert!(store.get(TypeStore::F64_ID).is_some());
        let u32_def = store.get(TypeStore::U32_ID).unwrap();
        assert_eq!(u32_def.kind.byte_size(8).unwrap(), 4);
    }

    #[test]
    fn define_struct_and_lookup() {
        let mut store = TypeStore::new();
        let x_field = StructField::new("x", 0, TypeStore::I32_ID);
        let y_field = StructField::new("y", 4, TypeStore::I32_ID);
        let id = store.define(TypeKind::Struct {
            name: "Point2D".into(),
            fields: vec![x_field, y_field],
            size: 8,
            align: 4,
            is_class: false,
        });
        assert!(id.is_valid());
        let def = store.get_by_name("Point2D").unwrap();
        assert_eq!(def.id, id);
        if let TypeKind::Struct { size, .. } = &def.kind {
            assert_eq!(*size, 8);
        } else {
            panic!("expected struct");
        }
    }

    #[test]
    fn define_enum_and_lookup() {
        let mut store = TypeStore::new();
        let id = store.define(TypeKind::Enum {
            name: "Color".into(),
            underlying: TypeStore::U32_ID,
            members: vec![
                EnumMember::new("Red", 0),
                EnumMember::new("Green", 1),
                EnumMember::new("Blue", 2),
            ],
        });
        let def = store.get_by_name("Color").unwrap();
        assert_eq!(def.id, id);
        if let TypeKind::Enum { members, .. } = &def.kind {
            assert_eq!(members.len(), 3);
            assert_eq!(members[1].value, 1);
        } else {
            panic!("expected enum");
        }
    }

    #[test]
    fn define_pointer_and_size() {
        let mut store = TypeStore::new();
        let ptr_id = store.define(TypeKind::Pointer {
            pointee: TypeStore::U8_ID,
            width: 8,
            is_const: true,
            is_volatile: false,
        });
        assert_eq!(store.byte_size(ptr_id, 8), Some(8));
        assert_eq!(store.byte_size(ptr_id, 4), Some(8)); // uses stored width, not ptr_width
    }

    #[test]
    fn define_array_byte_size() {
        let mut store = TypeStore::new();
        let arr_id = store.define(TypeKind::Array {
            element: TypeStore::U32_ID,
            count: 10,
        });
        // Array byte size = count * element_size
        assert_eq!(store.byte_size(arr_id, 8), Some(40));
    }

    #[test]
    fn typedef_resolution() {
        let mut store = TypeStore::new();
        let alias_id = store.define(TypeKind::Typedef {
            name: "uint32_t".into(),
            target: TypeStore::U32_ID,
        });
        let resolved = store.resolve_typedef(alias_id, 8);
        assert_eq!(resolved, TypeStore::U32_ID);
    }

    #[test]
    fn remove_type() {
        let mut store = TypeStore::new();
        let id = store.define(TypeKind::Opaque {
            name: "HANDLE".into(),
            size: 8,
        });
        assert!(store.get_by_name("HANDLE").is_some());
        let removed = store.remove(id);
        assert!(removed.is_some());
        assert!(store.get(id).is_none());
        assert!(store.get_by_name("HANDLE").is_none());
    }

    #[test]
    fn function_signature_builder() {
        let sig = FunctionSignature::new(TypeStore::I32_ID)
            .with_param(FunctionParam::new("argc", TypeStore::I32_ID))
            .with_param(FunctionParam::unnamed(TypeStore::U64_ID))
            .variadic()
            .with_cc(CallConvId::Cdecl);
        assert_eq!(sig.params.len(), 2);
        assert!(sig.variadic);
        assert_eq!(
            sig.calling_convention.as_ref().unwrap().to_string(),
            "__cdecl"
        );
    }

    #[test]
    fn int_type_bytes() {
        assert_eq!(IntType::signed(32).bytes(), 4);
        assert_eq!(IntType::unsigned(128).bytes(), 16);
        assert_eq!(IntType::signed(1).bytes(), 1);
    }

    #[test]
    fn float_kind_bytes() {
        assert_eq!(FloatKind::F32.bytes(), 4);
        assert_eq!(FloatKind::F80.bytes(), 10);
        assert_eq!(FloatKind::F128.bytes(), 16);
    }

    #[test]
    fn type_kind_display() {
        let t = TypeKind::Struct {
            name: "Foo".into(),
            fields: vec![],
            size: 0,
            align: 1,
            is_class: false,
        };
        assert_eq!(t.to_string(), "struct Foo");
        assert_eq!(TypeKind::Void.to_string(), "void");
    }

    #[test]
    fn struct_field_bitfield() {
        let bf =
            StructField::bitfield("flags", 0, TypeStore::U32_ID, 0, 3).with_comment("first 3 bits");
        assert!(bf.is_bitfield);
        assert_eq!(bf.bit_width, 3);
        assert_eq!(bf.comment.as_deref(), Some("first 3 bits"));
    }

    #[test]
    fn type_id_validity() {
        assert!(!TypeId::INVALID.is_valid());
        assert!(TypeId::from_raw(1).is_valid());
    }

    #[test]
    fn type_store_all_names() {
        let mut store = TypeStore::new();
        store.define(TypeKind::Opaque {
            name: "FILE".into(),
            size: 0,
        });
        store.define(TypeKind::Opaque {
            name: "DIR".into(),
            size: 0,
        });
        let names = store.all_names();
        assert!(names.contains(&"FILE"));
        assert!(names.contains(&"DIR"));
    }
}
