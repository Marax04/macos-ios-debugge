//! Decompiler/recovery-layer type system for `rustre-core`.
//!
//! This module is the **decompiler/type-recovery** layer for type information.
//! It is intentionally distinct from [`types`], which is the
//! **analysis/storage** layer.  See [`types`] for a comparison table of the
//! two modules.
//!
//! Use **this module** when you need type inference (type variables via
//! [`TypeKind::Var`]), C qualifier wrappers (`Const`/`Volatile`/`Atomic`/
//! `Restrict`), layout computation ([`TypeLayout`]), C-style printing
//! ([`TypePrinter`]), or DWARF/PDB import stubs.
//!
//! Provides [`TypeId`], [`TypeKind`], [`TypeSystem`] (define/lookup/resolve/merge),
//! [`TypeLayout`] (size/alignment/padding), [`TypePrinter`] (C-style output),
//! [`DwarfTypeImporter`] and [`PdbTypeImporter`] stubs.

use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;

/// Re-export of [`std::sync::Arc`] for downstream consumers who want to wrap a
/// [`TypeSystem`] in a shared handle without depending on `std::sync` directly.
pub use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// TypeId
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque identifier for a type in a [`TypeSystem`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeId(u32);

impl TypeId {
    /// Create a `TypeId` from a raw integer (for tests / serialization).
    #[must_use]
    pub const fn from_raw(v: u32) -> Self {
        Self(v)
    }

    /// Return the raw integer value.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Sentinel value representing "no type / unknown".
    pub const UNKNOWN: Self = Self(0);
}

impl fmt::Display for TypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "T{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Primitive kinds
// ─────────────────────────────────────────────────────────────────────────────

/// Integer width and signedness.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IntInfo {
    pub bits: u32,
    pub signed: bool,
}

impl IntInfo {
    #[must_use]
    pub const fn new(bits: u32, signed: bool) -> Self {
        Self { bits, signed }
    }
    #[must_use]
    pub const fn byte_size(&self) -> u64 {
        (self.bits as u64).div_ceil(8)
    }
}

/// Float width.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FloatInfo {
    pub bits: u32,
}

impl FloatInfo {
    #[must_use]
    pub const fn new(bits: u32) -> Self {
        Self { bits }
    }
    #[must_use]
    pub const fn byte_size(&self) -> u64 {
        (self.bits as u64).div_ceil(8)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Struct / union / enum helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A field in a struct or union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDef {
    pub name: String,
    pub type_id: TypeId,
    /// Byte offset from the start of the containing type.  `None` means unknown.
    pub offset: Option<u64>,
    /// Bit offset within the byte for bit-fields.  `None` for normal fields.
    pub bit_offset: Option<u32>,
    /// Bit-field width.  `None` for normal fields.
    pub bit_width: Option<u32>,
}

impl FieldDef {
    pub fn new(name: impl Into<String>, type_id: TypeId, offset: Option<u64>) -> Self {
        Self {
            name: name.into(),
            type_id,
            offset,
            bit_offset: None,
            bit_width: None,
        }
    }

    pub fn bit_field(
        name: impl Into<String>,
        type_id: TypeId,
        byte_offset: Option<u64>,
        bit_offset: u32,
        bit_width: u32,
    ) -> Self {
        Self {
            name: name.into(),
            type_id,
            offset: byte_offset,
            bit_offset: Some(bit_offset),
            bit_width: Some(bit_width),
        }
    }
}

/// A member of an enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumVariant {
    pub name: String,
    pub value: i64,
}

impl EnumVariant {
    pub fn new(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }
}

/// A function parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamDef {
    pub name: Option<String>,
    pub type_id: TypeId,
}

impl ParamDef {
    pub fn named(name: impl Into<String>, type_id: TypeId) -> Self {
        Self {
            name: Some(name.into()),
            type_id,
        }
    }
    #[must_use]
    pub const fn unnamed(type_id: TypeId) -> Self {
        Self {
            name: None,
            type_id,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeKind
// ─────────────────────────────────────────────────────────────────────────────

/// The structural kind of a type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeKind {
    /// `void`
    Void,
    /// `bool` / `_Bool`
    Bool,
    /// Signed/unsigned integer of given width.
    Int(IntInfo),
    /// IEEE floating-point number.
    Float(FloatInfo),
    /// Pointer to another type (optionally const).
    Pointer {
        pointee: TypeId,
        bits: u32,
        is_const: bool,
    },
    /// Fixed-length array.
    Array { elem: TypeId, count: u64 },
    /// Variable-length / unknown-length array (C99 VLA placeholder).
    FlexArray { elem: TypeId },
    /// `struct`
    Struct {
        name: Option<String>,
        fields: Vec<FieldDef>,
        size_hint: Option<u64>,
    },
    /// `union`
    Union {
        name: Option<String>,
        members: Vec<FieldDef>,
    },
    /// `enum`
    Enum {
        name: Option<String>,
        underlying: TypeId,
        variants: Vec<EnumVariant>,
    },
    /// Function type (for function pointers and prototypes).
    Function {
        ret: TypeId,
        params: Vec<ParamDef>,
        variadic: bool,
        calling_conv: Option<String>,
    },
    /// `typedef` alias — the underlying type is accessible via the type system.
    Typedef { name: String, aliased: TypeId },
    /// An unresolved forward-declaration or opaque type.
    Forward { name: String },
    /// A compiler-generated intrinsic type (e.g., `__m128`, `__int128`).
    Intrinsic { name: String, size: u64, align: u64 },
    /// Const-qualified wrapper.
    Const(TypeId),
    /// Volatile-qualified wrapper.
    Volatile(TypeId),
    /// Atomic-qualified wrapper (`_Atomic`).
    Atomic(TypeId),
    /// Restrict-qualified pointer.
    Restrict(TypeId),
    /// A type variable (used internally during type recovery/unification).
    Var(u32),
}

impl TypeKind {
    /// Returns `true` if this is a primitive (non-composite) type.
    #[must_use]
    pub const fn is_primitive(&self) -> bool {
        matches!(
            self,
            Self::Void | Self::Bool | Self::Int(_) | Self::Float(_)
        )
    }

    /// Returns `true` if this is an integer or boolean.
    #[must_use]
    pub const fn is_integer_like(&self) -> bool {
        matches!(self, Self::Bool | Self::Int(_) | Self::Enum { .. })
    }

    /// Returns `true` if this is a floating-point type.
    #[must_use]
    pub const fn is_float(&self) -> bool {
        matches!(self, Self::Float(_))
    }

    /// Returns `true` if this type represents a pointer.
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer { .. })
    }

    /// Returns `true` if this is a composite type (struct/union/array).
    #[must_use]
    pub const fn is_composite(&self) -> bool {
        matches!(
            self,
            Self::Struct { .. } | Self::Union { .. } | Self::Array { .. }
        )
    }

    /// Returns `true` if this is a function type.
    #[must_use]
    pub const fn is_function(&self) -> bool {
        matches!(self, Self::Function { .. })
    }

    /// Unwrap a typedef, returning the immediately aliased [`TypeId`].
    #[must_use]
    pub const fn typedef_aliased(&self) -> Option<TypeId> {
        if let Self::Typedef { aliased, .. } = self {
            Some(*aliased)
        } else {
            None
        }
    }

    /// Return the name of a named type (struct/union/enum/typedef/forward).
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Struct { name, .. } | Self::Union { name, .. } | Self::Enum { name, .. } => {
                name.as_deref()
            }
            Self::Typedef { name, .. } | Self::Forward { name } | Self::Intrinsic { name, .. } => {
                Some(name.as_str())
            }
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeDef — a named entry in the type system
// ─────────────────────────────────────────────────────────────────────────────

/// An entry in the type system: a [`TypeId`] bound to a [`TypeKind`] and an
/// optional source name.
#[derive(Debug, Clone)]
pub struct TypeEntry {
    pub id: TypeId,
    pub kind: TypeKind,
    /// Original name from source (DWARF/PDB), if any.
    pub source_name: Option<String>,
    /// Whether this type was recovered by analysis (vs. imported from debug info).
    pub is_recovered: bool,
}

impl TypeEntry {
    #[must_use]
    pub const fn new(id: TypeId, kind: TypeKind) -> Self {
        Self {
            id,
            kind,
            source_name: None,
            is_recovered: false,
        }
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.source_name = Some(name.into());
        self
    }

    #[must_use]
    pub const fn as_recovered(mut self) -> Self {
        self.is_recovered = true;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeSystem
// ─────────────────────────────────────────────────────────────────────────────

/// Central store for type information associated with one binary view.
///
/// Thread-safe: wraps an `RwLock` internally.
#[derive(Debug)]
pub struct TypeSystem {
    inner: RwLock<TypeSystemInner>,
}

#[derive(Debug)]
struct TypeSystemInner {
    entries: HashMap<TypeId, TypeEntry>,
    by_name: HashMap<String, TypeId>,
    next_id: u32,
}

impl TypeSystemInner {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            by_name: HashMap::new(),
            next_id: 1, // 0 = UNKNOWN
        }
    }

    const fn alloc_id(&mut self) -> TypeId {
        let id = TypeId::from_raw(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("TypeSystem exhausted all u32 type IDs");
        id
    }
}

impl TypeSystem {
    /// Create an empty type system.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(TypeSystemInner::new()),
        }
    }

    /// Define a new type with the given kind.  Returns its [`TypeId`].
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn define(&self, kind: TypeKind) -> TypeId {
        let mut inner = self.inner.write().unwrap();
        let id = inner.alloc_id();
        let name = kind.name().map(str::to_owned);
        let entry = TypeEntry::new(id, kind);
        if let Some(n) = name {
            inner.by_name.insert(n, id);
        }
        inner.entries.insert(id, entry);
        id
    }

    /// Define a named type.  Returns its [`TypeId`].
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn define_named(&self, kind: TypeKind, name: impl Into<String>) -> TypeId {
        let name = name.into();
        let mut inner = self.inner.write().unwrap();
        let id = inner.alloc_id();
        let entry = TypeEntry::new(id, kind).with_name(name.clone());
        inner.by_name.insert(name, id);
        inner.entries.insert(id, entry);
        id
    }

    /// Look up a type by its [`TypeId`].
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn lookup(&self, id: TypeId) -> Option<TypeEntry> {
        self.inner.read().unwrap().entries.get(&id).cloned()
    }

    /// Look up a type by name.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn lookup_by_name(&self, name: &str) -> Option<TypeEntry> {
        let inner = self.inner.read().unwrap();
        inner
            .by_name
            .get(name)
            .and_then(|id| inner.entries.get(id))
            .cloned()
    }

    /// Resolve a typedef chain, returning the ultimate concrete [`TypeId`].
    ///
    /// Stops at non-typedef types, qualified wrappers (const/volatile/atomic/restrict),
    /// or the first unresolved id.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn resolve(&self, mut id: TypeId) -> TypeId {
        let inner = self.inner.read().unwrap();
        let mut visited = std::collections::HashSet::new();
        loop {
            if !visited.insert(id) {
                break; // cycle guard
            }
            match inner.entries.get(&id).map(|e| &e.kind) {
                Some(TypeKind::Typedef { aliased, .. }) => id = *aliased,
                Some(
                    TypeKind::Const(inner_id)
                    | TypeKind::Volatile(inner_id)
                    | TypeKind::Atomic(inner_id)
                    | TypeKind::Restrict(inner_id),
                ) => id = *inner_id,
                _ => break,
            }
        }
        id
    }

    /// Merge `other` into `self`.  Types from `other` are re-assigned new IDs in
    /// `self`; a mapping from old → new IDs is returned.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn merge(&self, other: &Self) -> HashMap<TypeId, TypeId> {
        // Snapshot the entries under the read lock, then release it before
        // calling `define` (which takes a write lock on `self`).
        let snapshot: Vec<(TypeId, TypeKind)> = {
            let other_inner = other.inner.read().unwrap();
            other_inner
                .entries
                .iter()
                .map(|(id, entry)| (*id, entry.kind.clone()))
                .collect()
        };
        let mut map = HashMap::new();
        for (old_id, kind) in snapshot {
            let new_id = self.define(kind);
            map.insert(old_id, new_id);
        }
        map
    }

    /// Return the total number of defined types.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().entries.len()
    }

    /// Returns `true` if no types are defined.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().entries.is_empty()
    }

    /// Return all type IDs defined so far, in an unspecified order.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn all_ids(&self) -> Vec<TypeId> {
        self.inner.read().unwrap().entries.keys().copied().collect()
    }

    /// Update the kind of an existing type (used during type refinement).
    ///
    /// Returns `false` if `id` does not exist.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn update_kind(&self, id: TypeId, kind: TypeKind) -> bool {
        let mut inner = self.inner.write().unwrap();
        if let Some(entry) = inner.entries.get_mut(&id) {
            entry.kind = kind;
            true
        } else {
            false
        }
    }

    /// Remove a type by id.  Returns `true` if it existed.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn remove(&self, id: TypeId) -> bool {
        let mut inner = self.inner.write().unwrap();
        if inner.entries.remove(&id).is_some() {
            inner.by_name.retain(|_, v| *v != id);
            true
        } else {
            false
        }
    }

    /// Pre-populate with C built-in types.  Returns a map of well-known names to IDs.
    pub fn populate_builtins(&self) -> HashMap<&'static str, TypeId> {
        let mut m = HashMap::new();
        let defs: &[(&'static str, TypeKind)] = &[
            ("void", TypeKind::Void),
            ("bool", TypeKind::Bool),
            ("char", TypeKind::Int(IntInfo::new(8, true))),
            ("uchar", TypeKind::Int(IntInfo::new(8, false))),
            ("short", TypeKind::Int(IntInfo::new(16, true))),
            ("ushort", TypeKind::Int(IntInfo::new(16, false))),
            ("int", TypeKind::Int(IntInfo::new(32, true))),
            ("uint", TypeKind::Int(IntInfo::new(32, false))),
            ("long", TypeKind::Int(IntInfo::new(64, true))),
            ("ulong", TypeKind::Int(IntInfo::new(64, false))),
            ("llong", TypeKind::Int(IntInfo::new(64, true))),
            ("ullong", TypeKind::Int(IntInfo::new(64, false))),
            ("i8", TypeKind::Int(IntInfo::new(8, true))),
            ("u8", TypeKind::Int(IntInfo::new(8, false))),
            ("i16", TypeKind::Int(IntInfo::new(16, true))),
            ("u16", TypeKind::Int(IntInfo::new(16, false))),
            ("i32", TypeKind::Int(IntInfo::new(32, true))),
            ("u32", TypeKind::Int(IntInfo::new(32, false))),
            ("i64", TypeKind::Int(IntInfo::new(64, true))),
            ("u64", TypeKind::Int(IntInfo::new(64, false))),
            ("i128", TypeKind::Int(IntInfo::new(128, true))),
            ("u128", TypeKind::Int(IntInfo::new(128, false))),
            ("float", TypeKind::Float(FloatInfo::new(32))),
            ("double", TypeKind::Float(FloatInfo::new(64))),
            ("ldouble", TypeKind::Float(FloatInfo::new(80))),
        ];
        for (name, kind) in defs {
            let id = self.define_named(kind.clone(), *name);
            m.insert(*name, id);
        }
        m
    }
}

impl Default for TypeSystem {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeLayout
// ─────────────────────────────────────────────────────────────────────────────

/// Computed layout information for a type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeLayout {
    /// Size in bytes (may be 0 for void/incomplete types).
    pub size: u64,
    /// Required alignment in bytes.
    pub align: u64,
    /// Padding bytes appended at the end to satisfy alignment.
    pub tail_padding: u64,
}

impl TypeLayout {
    /// Compute layout for a given kind, using the pointer-width for pointer types.
    ///
    /// Uses the System V AMD64 ABI rules as a baseline.
    pub fn compute(kind: &TypeKind, ptr_bits: u32, ts: &TypeSystem) -> Self {
        match kind {
            TypeKind::Bool => Self {
                size: 1,
                align: 1,
                tail_padding: 0,
            },
            TypeKind::Int(i) => {
                let sz = i.byte_size();
                Self {
                    size: sz,
                    align: sz.min(16),
                    tail_padding: 0,
                }
            }
            TypeKind::Float(f) => {
                let sz = f.byte_size();
                let align = if f.bits == 80 { 16 } else { sz };
                Self {
                    size: sz,
                    align,
                    tail_padding: 0,
                }
            }
            TypeKind::Pointer { bits, .. } => {
                let sz = u64::from(*bits).div_ceil(8);
                Self {
                    size: sz,
                    align: sz,
                    tail_padding: 0,
                }
            }
            TypeKind::Array { elem, count } => {
                let elem_layout = ts.lookup(ts.resolve(*elem)).map_or(
                    Self {
                        size: 1,
                        align: 1,
                        tail_padding: 0,
                    },
                    |e| Self::compute(&e.kind, ptr_bits, ts),
                );
                // Use saturating_mul to avoid overflow when count is adversarially large.
                let size = elem_layout.size.saturating_mul(*count);
                Self {
                    size,
                    align: elem_layout.align,
                    tail_padding: 0,
                }
            }
            TypeKind::Struct {
                fields, size_hint, ..
            } => {
                if let Some(hint) = size_hint {
                    return Self {
                        size: *hint,
                        align: 1,
                        tail_padding: 0,
                    };
                }
                Self::compute_struct_layout(fields, ptr_bits, ts)
            }
            TypeKind::Union { members, .. } => Self::compute_union_layout(members, ptr_bits, ts),
            TypeKind::Enum { underlying, .. } => ts.lookup(*underlying).map_or(
                Self {
                    size: 4,
                    align: 4,
                    tail_padding: 0,
                },
                |e| Self::compute(&e.kind, ptr_bits, ts),
            ),
            TypeKind::Function { .. } => {
                let sz = u64::from(ptr_bits).div_ceil(8);
                Self {
                    size: sz,
                    align: sz,
                    tail_padding: 0,
                }
            }
            TypeKind::Typedef { aliased, .. }
            | TypeKind::Const(aliased)
            | TypeKind::Volatile(aliased)
            | TypeKind::Atomic(aliased)
            | TypeKind::Restrict(aliased) => ts.lookup(*aliased).map_or(
                Self {
                    size: 0,
                    align: 1,
                    tail_padding: 0,
                },
                |e| Self::compute(&e.kind, ptr_bits, ts),
            ),
            TypeKind::Intrinsic { size, align, .. } => Self {
                size: *size,
                align: *align,
                tail_padding: 0,
            },
            TypeKind::FlexArray { elem } => {
                let elem_layout = ts.lookup(ts.resolve(*elem)).map_or(
                    Self {
                        size: 1,
                        align: 1,
                        tail_padding: 0,
                    },
                    |e| Self::compute(&e.kind, ptr_bits, ts),
                );
                Self {
                    size: 0,
                    align: elem_layout.align,
                    tail_padding: 0,
                }
            }
            TypeKind::Void | TypeKind::Forward { .. } | TypeKind::Var(_) => Self {
                size: 0,
                align: 1,
                tail_padding: 0,
            },
        }
    }

    fn compute_struct_layout(fields: &[FieldDef], ptr_bits: u32, ts: &TypeSystem) -> Self {
        let mut offset: u64 = 0;
        let mut max_align: u64 = 1;
        for field in fields {
            let fk = ts.lookup(ts.resolve(field.type_id));
            let fl = fk.map_or(
                Self {
                    size: 0,
                    align: 1,
                    tail_padding: 0,
                },
                |e| Self::compute(&e.kind, ptr_bits, ts),
            );
            let align = fl.align.max(1);
            max_align = max_align.max(align);
            // Align current offset.
            let pad = (align - (offset % align)) % align;
            offset += pad + fl.size;
        }
        // Tail padding.
        let tail_pad = if max_align > 0 {
            (max_align - (offset % max_align)) % max_align
        } else {
            0
        };
        Self {
            size: offset + tail_pad,
            align: max_align,
            tail_padding: tail_pad,
        }
    }

    fn compute_union_layout(members: &[FieldDef], ptr_bits: u32, ts: &TypeSystem) -> Self {
        let mut max_size: u64 = 0;
        let mut max_align: u64 = 1;
        for member in members {
            let fk = ts.lookup(ts.resolve(member.type_id));
            let fl = fk.map_or(
                Self {
                    size: 0,
                    align: 1,
                    tail_padding: 0,
                },
                |e| Self::compute(&e.kind, ptr_bits, ts),
            );
            max_size = max_size.max(fl.size);
            max_align = max_align.max(fl.align);
        }
        let tail_pad = if max_align > 0 {
            (max_align - (max_size % max_align)) % max_align
        } else {
            0
        };
        Self {
            size: max_size + tail_pad,
            align: max_align,
            tail_padding: tail_pad,
        }
    }

    /// Returns the effective size including tail padding.
    #[must_use]
    pub const fn padded_size(&self) -> u64 {
        self.size
    }

    /// Returns `true` if this is a zero-size type.
    #[must_use]
    pub const fn is_zst(&self) -> bool {
        self.size == 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypePrinter
// ─────────────────────────────────────────────────────────────────────────────

/// Prints types in a C-like notation.
pub struct TypePrinter<'a> {
    ts: &'a TypeSystem,
    /// Whether to expand typedefs.
    pub expand_typedefs: bool,
    /// Whether to add `const`/`volatile` qualifiers.
    pub show_qualifiers: bool,
    /// Whether to print struct/union inline or just by name.
    pub inline_composite: bool,
}

impl<'a> TypePrinter<'a> {
    pub const fn new(ts: &'a TypeSystem) -> Self {
        Self {
            ts,
            expand_typedefs: false,
            show_qualifiers: true,
            inline_composite: false,
        }
    }

    /// Print a type as a C declaration.
    ///
    /// Returns the declarator base and any suffix (for arrays/function pointers).
    #[must_use]
    pub fn print(&self, id: TypeId) -> String {
        self.print_inner(id, None)
    }

    /// Print a type with a variable name embedded (e.g., `int foo`, `int (*fp)()`).
    #[must_use]
    pub fn print_decl(&self, id: TypeId, name: &str) -> String {
        self.print_inner(id, Some(name))
    }

    fn suffix(vn: &str) -> String {
        if vn.is_empty() {
            String::new()
        } else {
            format!(" {vn}")
        }
    }

    fn print_int(i: &IntInfo, vn: &str) -> String {
        let base = match (i.bits, i.signed) {
            (8, true) => "int8_t",
            (8, false) => "uint8_t",
            (16, true) => "int16_t",
            (16, false) => "uint16_t",
            (32, true) => "int32_t",
            (32, false) => "uint32_t",
            (64, true) => "int64_t",
            (64, false) => "uint64_t",
            (128, true) => "__int128",
            (128, false) => "unsigned __int128",
            (n, true) => return format!("int{n}_t{}", Self::suffix(vn)),
            (n, false) => return format!("uint{n}_t{}", Self::suffix(vn)),
        };
        format!("{base}{}", Self::suffix(vn))
    }

    fn print_pointer(&self, pointee: TypeId, bits: u32, is_const: bool, vn: &str) -> String {
        let qual = if is_const { "const " } else { "" };
        let width = match bits {
            0 | 64 => String::new(),
            n => format!(" /* {n}-bit */"),
        };
        let ptr_str = if vn.is_empty() {
            format!("{qual}*{width}")
        } else {
            format!("{qual}*{width}{vn}")
        };
        let inner = self.print_inner(pointee, None);
        format!("{inner} {ptr_str}")
    }

    fn print_struct(&self, name: Option<&String>, fields: &[FieldDef], vn: &str) -> String {
        use std::fmt::Write as _;
        if let Some(n) = name
            && !self.inline_composite
        {
            return format!("struct {n}{}", Self::suffix(vn));
        }
        let mut s = "struct {\n".to_string();
        for f in fields {
            let _ = writeln!(s, "  {} {};", self.print(f.type_id), f.name);
        }
        s.push('}');
        if !vn.is_empty() {
            s.push(' ');
            s.push_str(vn);
        }
        s
    }

    fn print_union(&self, name: Option<&String>, members: &[FieldDef], vn: &str) -> String {
        use std::fmt::Write as _;
        if let Some(n) = name
            && !self.inline_composite
        {
            return format!("union {n}{}", Self::suffix(vn));
        }
        let mut s = "union {\n".to_string();
        for m in members {
            let _ = writeln!(s, "  {} {};", self.print(m.type_id), m.name);
        }
        s.push('}');
        if !vn.is_empty() {
            s.push(' ');
            s.push_str(vn);
        }
        s
    }

    fn print_enum(name: Option<&String>, variants: &[EnumVariant], vn: &str) -> String {
        use std::fmt::Write as _;
        if let Some(n) = name {
            return format!("enum {n}{}", Self::suffix(vn));
        }
        let mut s = "enum { ".to_string();
        for (i, v) in variants.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            let _ = write!(s, "{} = {}", v.name, v.value);
        }
        s.push_str(" }");
        if !vn.is_empty() {
            s.push(' ');
            s.push_str(vn);
        }
        s
    }

    fn print_function(
        &self,
        ret: TypeId,
        params: &[ParamDef],
        variadic: bool,
        calling_conv: Option<&str>,
        vn: &str,
    ) -> String {
        let ret_str = self.print(ret);
        let cc = calling_conv.unwrap_or("");
        let cc_str = if cc.is_empty() {
            String::new()
        } else {
            format!("{cc} ")
        };
        let params_str = params
            .iter()
            .map(|p| self.print(p.type_id))
            .chain(if variadic {
                Some("...".to_string())
            } else {
                None
            })
            .collect::<Vec<_>>()
            .join(", ");
        if vn.is_empty() {
            format!("{ret_str} ({cc_str}*)({params_str})")
        } else {
            format!("{ret_str} {cc_str}{vn}({params_str})")
        }
    }

    fn print_inner(&self, id: TypeId, var_name: Option<&str>) -> String {
        let Some(entry) = self.ts.lookup(id) else {
            return format!("<unknown T{}>", id.raw());
        };
        let vn = var_name.unwrap_or("");
        match &entry.kind {
            TypeKind::Void => format!("void{}", Self::suffix(vn)),
            TypeKind::Bool => format!("bool{}", Self::suffix(vn)),
            TypeKind::Int(i) => Self::print_int(i, vn),
            TypeKind::Float(f) => {
                let base = match f.bits {
                    64 => "double",
                    80 => "long double",
                    _ => "float",
                };
                format!("{base}{}", Self::suffix(vn))
            }
            TypeKind::Pointer {
                pointee,
                bits,
                is_const,
            } => self.print_pointer(*pointee, *bits, *is_const, vn),
            TypeKind::Array { elem, count } => {
                let inner = self.print_inner(*elem, None);
                if vn.is_empty() {
                    format!("{inner}[{count}]")
                } else {
                    format!("{inner} {vn}[{count}]")
                }
            }
            TypeKind::Struct { name, fields, .. } => self.print_struct(name.as_ref(), fields, vn),
            TypeKind::Union { name, members, .. } => self.print_union(name.as_ref(), members, vn),
            TypeKind::Enum { name, variants, .. } => Self::print_enum(name.as_ref(), variants, vn),
            TypeKind::Function {
                ret,
                params,
                variadic,
                calling_conv,
            } => self.print_function(*ret, params, *variadic, calling_conv.as_deref(), vn),
            TypeKind::Typedef { name, aliased } => {
                if self.expand_typedefs {
                    let inner = self.print_inner(*aliased, None);
                    format!("{inner}{}", Self::suffix(vn))
                } else {
                    format!("{name}{}", Self::suffix(vn))
                }
            }
            TypeKind::Forward { name } => {
                format!("/* forward */ {name}{}", Self::suffix(vn))
            }
            TypeKind::Const(inner_id) => {
                if self.show_qualifiers {
                    let inner = self.print_inner(*inner_id, None);
                    format!("const {inner}{}", Self::suffix(vn))
                } else {
                    self.print_inner(*inner_id, var_name)
                }
            }
            TypeKind::Volatile(inner_id) => {
                if self.show_qualifiers {
                    let inner = self.print_inner(*inner_id, None);
                    format!("volatile {inner}{}", Self::suffix(vn))
                } else {
                    self.print_inner(*inner_id, var_name)
                }
            }
            TypeKind::Atomic(inner_id) => {
                let inner = self.print_inner(*inner_id, None);
                format!("_Atomic({inner}){}", Self::suffix(vn))
            }
            TypeKind::Restrict(inner_id) => {
                let inner = self.print_inner(*inner_id, None);
                format!("{inner} restrict{}", Self::suffix(vn))
            }
            TypeKind::Intrinsic { name, .. } => {
                format!("{name}{}", Self::suffix(vn))
            }
            TypeKind::FlexArray { elem } => {
                let inner = self.print(*elem);
                format!("{inner}[]")
            }
            TypeKind::Var(n) => format!("?T{n}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DwarfTypeImporter
// ─────────────────────────────────────────────────────────────────────────────

/// Stub DWARF type importer.  In a full implementation this would parse
/// `.debug_info` DIEs and populate the type system.
pub struct DwarfTypeImporter {
    pointer_bits: u32,
}

impl DwarfTypeImporter {
    #[must_use]
    pub const fn new(pointer_bits: u32) -> Self {
        Self { pointer_bits }
    }

    /// Import a simulated DWARF type record into `ts`.
    ///
    /// In production this would iterate over `gimli::DebuggingInformationEntry`s.
    pub fn import_basic_types(&self, ts: &TypeSystem) -> HashMap<&'static str, TypeId> {
        ts.populate_builtins()
    }

    /// Import a struct from a simplified description.
    pub fn import_struct(
        &self,
        ts: &TypeSystem,
        name: &str,
        fields: Vec<(String, TypeId, u64)>, // (name, type_id, byte_offset)
    ) -> TypeId {
        let field_defs: Vec<FieldDef> = fields
            .into_iter()
            .map(|(n, t, off)| FieldDef::new(n, t, Some(off)))
            .collect();
        ts.define(TypeKind::Struct {
            name: Some(name.to_owned()),
            fields: field_defs,
            size_hint: None,
        })
    }

    /// Return the configured pointer width.
    #[must_use]
    pub const fn pointer_bits(&self) -> u32 {
        self.pointer_bits
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PdbTypeImporter
// ─────────────────────────────────────────────────────────────────────────────

/// Stub PDB type importer.  In production this would parse the TPI/IPI streams.
pub struct PdbTypeImporter {
    pointer_bits: u32,
}

impl PdbTypeImporter {
    #[must_use]
    pub const fn new(pointer_bits: u32) -> Self {
        Self { pointer_bits }
    }

    /// Import built-in MS types into the type system.
    pub fn import_primitives(&self, ts: &TypeSystem) -> HashMap<&'static str, TypeId> {
        ts.populate_builtins()
    }

    /// Import a COM/C++ style class record.
    pub fn import_class(
        &self,
        ts: &TypeSystem,
        name: &str,
        fields: Vec<(String, TypeId, u64)>,
        size: u64,
    ) -> TypeId {
        let field_defs: Vec<FieldDef> = fields
            .into_iter()
            .map(|(n, t, off)| FieldDef::new(n, t, Some(off)))
            .collect();
        ts.define(TypeKind::Struct {
            name: Some(name.to_owned()),
            fields: field_defs,
            size_hint: Some(size),
        })
    }

    /// Return the configured pointer width.
    #[must_use]
    pub const fn pointer_bits(&self) -> u32 {
        self.pointer_bits
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> TypeSystem {
        TypeSystem::new()
    }

    // ── TypeId ────────────────────────────────────────────────────────────────

    #[test]
    fn type_id_from_raw_roundtrip() {
        let id = TypeId::from_raw(42);
        assert_eq!(id.raw(), 42);
    }

    #[test]
    fn type_id_unknown_is_zero() {
        assert_eq!(TypeId::UNKNOWN.raw(), 0);
    }

    #[test]
    fn type_id_display() {
        let id = TypeId::from_raw(7);
        assert_eq!(id.to_string(), "T7");
    }

    #[test]
    fn type_id_ordering() {
        let a = TypeId::from_raw(1);
        let b = TypeId::from_raw(2);
        assert!(a < b);
    }

    // ── IntInfo / FloatInfo ───────────────────────────────────────────────────

    #[test]
    fn int_info_byte_size() {
        assert_eq!(IntInfo::new(8, true).byte_size(), 1);
        assert_eq!(IntInfo::new(16, false).byte_size(), 2);
        assert_eq!(IntInfo::new(32, true).byte_size(), 4);
        assert_eq!(IntInfo::new(64, false).byte_size(), 8);
        assert_eq!(IntInfo::new(128, true).byte_size(), 16);
    }

    #[test]
    fn float_info_byte_size() {
        assert_eq!(FloatInfo::new(32).byte_size(), 4);
        assert_eq!(FloatInfo::new(64).byte_size(), 8);
        assert_eq!(FloatInfo::new(80).byte_size(), 10);
    }

    // ── TypeKind predicates ───────────────────────────────────────────────────

    #[test]
    fn type_kind_is_primitive() {
        assert!(TypeKind::Void.is_primitive());
        assert!(TypeKind::Bool.is_primitive());
        assert!(TypeKind::Int(IntInfo::new(32, true)).is_primitive());
        assert!(TypeKind::Float(FloatInfo::new(64)).is_primitive());
        let ts = ts();
        let void_id = ts.define(TypeKind::Void);
        assert!(
            !TypeKind::Pointer {
                pointee: void_id,
                bits: 64,
                is_const: false
            }
            .is_primitive()
        );
    }

    #[test]
    fn type_kind_is_integer_like() {
        assert!(TypeKind::Bool.is_integer_like());
        assert!(TypeKind::Int(IntInfo::new(8, false)).is_integer_like());
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        assert!(
            TypeKind::Enum {
                name: None,
                underlying: int_id,
                variants: vec![]
            }
            .is_integer_like()
        );
        assert!(!TypeKind::Float(FloatInfo::new(32)).is_integer_like());
    }

    #[test]
    fn type_kind_is_pointer() {
        let ts = ts();
        let void_id = ts.define(TypeKind::Void);
        assert!(
            TypeKind::Pointer {
                pointee: void_id,
                bits: 64,
                is_const: false
            }
            .is_pointer()
        );
        assert!(!TypeKind::Void.is_pointer());
    }

    #[test]
    fn type_kind_is_composite() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        assert!(
            TypeKind::Struct {
                name: None,
                fields: vec![],
                size_hint: None
            }
            .is_composite()
        );
        assert!(
            TypeKind::Union {
                name: None,
                members: vec![]
            }
            .is_composite()
        );
        assert!(
            TypeKind::Array {
                elem: int_id,
                count: 4
            }
            .is_composite()
        );
        assert!(!TypeKind::Void.is_composite());
    }

    #[test]
    fn type_kind_is_function() {
        let ts = ts();
        let void_id = ts.define(TypeKind::Void);
        assert!(
            TypeKind::Function {
                ret: void_id,
                params: vec![],
                variadic: false,
                calling_conv: None
            }
            .is_function()
        );
        assert!(!TypeKind::Void.is_function());
    }

    #[test]
    fn type_kind_name() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let sk = TypeKind::Struct {
            name: Some("Foo".into()),
            fields: vec![],
            size_hint: None,
        };
        assert_eq!(sk.name(), Some("Foo"));
        let td = TypeKind::Typedef {
            name: "MyInt".into(),
            aliased: int_id,
        };
        assert_eq!(td.name(), Some("MyInt"));
        assert_eq!(TypeKind::Void.name(), None);
    }

    // ── TypeSystem define / lookup ────────────────────────────────────────────

    #[test]
    fn type_system_define_and_lookup() {
        let ts = ts();
        let id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        assert!(id != TypeId::UNKNOWN);
        let entry = ts.lookup(id).unwrap();
        assert_eq!(entry.kind, TypeKind::Int(IntInfo::new(32, true)));
    }

    #[test]
    fn type_system_lookup_missing_returns_none() {
        let ts = ts();
        assert!(ts.lookup(TypeId::from_raw(9999)).is_none());
    }

    #[test]
    fn type_system_define_named_and_lookup_by_name() {
        let ts = ts();
        let id = ts.define_named(
            TypeKind::Struct {
                name: Some("Point".into()),
                fields: vec![],
                size_hint: None,
            },
            "Point",
        );
        let e = ts.lookup_by_name("Point").unwrap();
        assert_eq!(e.id, id);
    }

    #[test]
    fn type_system_len() {
        let ts = ts();
        assert_eq!(ts.len(), 0);
        ts.define(TypeKind::Void);
        ts.define(TypeKind::Bool);
        assert_eq!(ts.len(), 2);
    }

    #[test]
    fn type_system_all_ids() {
        let ts = ts();
        let a = ts.define(TypeKind::Void);
        let b = ts.define(TypeKind::Bool);
        let ids = ts.all_ids();
        assert!(ids.contains(&a));
        assert!(ids.contains(&b));
    }

    #[test]
    fn type_system_remove() {
        let ts = ts();
        let id = ts.define(TypeKind::Void);
        assert!(ts.remove(id));
        assert!(!ts.remove(id)); // already removed
        assert!(ts.lookup(id).is_none());
    }

    // ── TypeSystem resolve ────────────────────────────────────────────────────

    #[test]
    fn resolve_non_typedef_returns_self() {
        let ts = ts();
        let id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        assert_eq!(ts.resolve(id), id);
    }

    #[test]
    fn resolve_typedef_chain() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let td1 = ts.define(TypeKind::Typedef {
            name: "MyInt".into(),
            aliased: int_id,
        });
        let td2 = ts.define(TypeKind::Typedef {
            name: "MyInt2".into(),
            aliased: td1,
        });
        assert_eq!(ts.resolve(td2), int_id);
    }

    #[test]
    fn resolve_const_qualifier() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let cid = ts.define(TypeKind::Const(int_id));
        assert_eq!(ts.resolve(cid), int_id);
    }

    #[test]
    fn resolve_unknown_returns_self() {
        let ts = ts();
        assert_eq!(ts.resolve(TypeId::UNKNOWN), TypeId::UNKNOWN);
    }

    // ── TypeSystem merge ──────────────────────────────────────────────────────

    #[test]
    fn merge_copies_types() {
        let ts1 = ts();
        let ts2 = ts();
        let id_a = ts1.define(TypeKind::Void);
        let id_b = ts1.define(TypeKind::Bool);
        let map = ts2.merge(&ts1);
        assert_eq!(ts2.len(), 2);
        assert!(map.contains_key(&id_a));
        assert!(map.contains_key(&id_b));
    }

    // ── TypeSystem update_kind ────────────────────────────────────────────────

    #[test]
    fn update_kind_works() {
        let ts = ts();
        let id = ts.define(TypeKind::Forward {
            name: "FooBar".into(),
        });
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, false)));
        let updated = ts.update_kind(
            id,
            TypeKind::Typedef {
                name: "FooBar".into(),
                aliased: int_id,
            },
        );
        assert!(updated);
        let entry = ts.lookup(id).unwrap();
        assert!(matches!(entry.kind, TypeKind::Typedef { .. }));
    }

    #[test]
    fn update_kind_missing_returns_false() {
        let ts = ts();
        assert!(!ts.update_kind(TypeId::from_raw(9999), TypeKind::Void));
    }

    // ── TypeLayout ────────────────────────────────────────────────────────────

    #[test]
    fn layout_void_is_zero() {
        let ts = ts();
        let l = TypeLayout::compute(&TypeKind::Void, 64, &ts);
        assert_eq!(l.size, 0);
        assert!(l.is_zst());
    }

    #[test]
    fn layout_bool() {
        let ts = ts();
        let l = TypeLayout::compute(&TypeKind::Bool, 64, &ts);
        assert_eq!(l.size, 1);
        assert_eq!(l.align, 1);
    }

    #[test]
    fn layout_int32() {
        let ts = ts();
        let l = TypeLayout::compute(&TypeKind::Int(IntInfo::new(32, true)), 64, &ts);
        assert_eq!(l.size, 4);
        assert_eq!(l.align, 4);
    }

    #[test]
    fn layout_float64() {
        let ts = ts();
        let l = TypeLayout::compute(&TypeKind::Float(FloatInfo::new(64)), 64, &ts);
        assert_eq!(l.size, 8);
        assert_eq!(l.align, 8);
    }

    #[test]
    fn layout_pointer_64bit() {
        let ts = ts();
        let void_id = ts.define(TypeKind::Void);
        let l = TypeLayout::compute(
            &TypeKind::Pointer {
                pointee: void_id,
                bits: 64,
                is_const: false,
            },
            64,
            &ts,
        );
        assert_eq!(l.size, 8);
        assert_eq!(l.align, 8);
    }

    #[test]
    fn layout_array() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let l = TypeLayout::compute(
            &TypeKind::Array {
                elem: int_id,
                count: 4,
            },
            64,
            &ts,
        );
        assert_eq!(l.size, 16);
    }

    #[test]
    fn layout_struct_alignment() {
        let ts = ts();
        let char_id = ts.define(TypeKind::Int(IntInfo::new(8, true)));
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let fields = vec![
            FieldDef::new("c", char_id, Some(0)),
            FieldDef::new("i", int_id, None),
        ];
        let l = TypeLayout::compute(
            &TypeKind::Struct {
                name: None,
                fields,
                size_hint: None,
            },
            64,
            &ts,
        );
        // char(1) + 3 pad + int(4) = 8, tail_pad=0
        assert_eq!(l.size, 8);
        assert_eq!(l.align, 4);
    }

    #[test]
    fn layout_union() {
        let ts = ts();
        let i8_id = ts.define(TypeKind::Int(IntInfo::new(8, true)));
        let i32_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let members = vec![
            FieldDef::new("b", i8_id, Some(0)),
            FieldDef::new("i", i32_id, Some(0)),
        ];
        let l = TypeLayout::compute(
            &TypeKind::Union {
                name: None,
                members,
            },
            64,
            &ts,
        );
        assert!(l.size >= 4);
        assert_eq!(l.align, 4);
    }

    #[test]
    fn layout_padded_size() {
        let ts = ts();
        let l = TypeLayout::compute(&TypeKind::Int(IntInfo::new(32, true)), 64, &ts);
        assert_eq!(l.padded_size(), 4);
    }

    // ── TypePrinter ───────────────────────────────────────────────────────────

    #[test]
    fn printer_void() {
        let ts = ts();
        let id = ts.define(TypeKind::Void);
        let p = TypePrinter::new(&ts);
        assert_eq!(p.print(id), "void");
    }

    #[test]
    fn printer_int32() {
        let ts = ts();
        let id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let p = TypePrinter::new(&ts);
        assert_eq!(p.print(id), "int32_t");
    }

    #[test]
    fn printer_float32() {
        let ts = ts();
        let id = ts.define(TypeKind::Float(FloatInfo::new(32)));
        let p = TypePrinter::new(&ts);
        assert_eq!(p.print(id), "float");
    }

    #[test]
    fn printer_pointer() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let ptr_id = ts.define(TypeKind::Pointer {
            pointee: int_id,
            bits: 64,
            is_const: false,
        });
        let p = TypePrinter::new(&ts);
        let s = p.print(ptr_id);
        assert!(s.contains("int32_t"));
        assert!(s.contains('*'));
    }

    #[test]
    fn printer_const_pointer() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let ptr_id = ts.define(TypeKind::Pointer {
            pointee: int_id,
            bits: 64,
            is_const: true,
        });
        let p = TypePrinter::new(&ts);
        let s = p.print(ptr_id);
        assert!(s.contains("const"));
    }

    #[test]
    fn printer_array() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let arr_id = ts.define(TypeKind::Array {
            elem: int_id,
            count: 10,
        });
        let p = TypePrinter::new(&ts);
        let s = p.print(arr_id);
        assert!(s.contains("[10]"));
    }

    #[test]
    fn printer_typedef() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let td_id = ts.define(TypeKind::Typedef {
            name: "size_t".into(),
            aliased: int_id,
        });
        let p = TypePrinter::new(&ts);
        assert_eq!(p.print(td_id), "size_t");
    }

    #[test]
    fn printer_const_qualifier() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let cid = ts.define(TypeKind::Const(int_id));
        let p = TypePrinter::new(&ts);
        let s = p.print(cid);
        assert!(s.contains("const"));
    }

    #[test]
    fn printer_decl_with_name() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let p = TypePrinter::new(&ts);
        let s = p.print_decl(int_id, "count");
        assert_eq!(s, "int32_t count");
    }

    #[test]
    fn printer_struct_named() {
        let ts = ts();
        let sid = ts.define(TypeKind::Struct {
            name: Some("Node".into()),
            fields: vec![],
            size_hint: None,
        });
        let p = TypePrinter::new(&ts);
        assert_eq!(p.print(sid), "struct Node");
    }

    #[test]
    fn printer_enum_named() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let eid = ts.define(TypeKind::Enum {
            name: Some("Color".into()),
            underlying: int_id,
            variants: vec![],
        });
        let p = TypePrinter::new(&ts);
        assert_eq!(p.print(eid), "enum Color");
    }

    // ── DwarfTypeImporter ─────────────────────────────────────────────────────

    #[test]
    fn dwarf_importer_basic_types() {
        let ts = ts();
        let imp = DwarfTypeImporter::new(64);
        let map = imp.import_basic_types(&ts);
        assert!(map.contains_key("void"));
        assert!(map.contains_key("int"));
        assert!(map.contains_key("float"));
    }

    #[test]
    fn dwarf_importer_struct() {
        let ts = ts();
        let imp = DwarfTypeImporter::new(64);
        let builtins = imp.import_basic_types(&ts);
        let int_id = builtins["int"];
        let sid = imp.import_struct(
            &ts,
            "Point",
            vec![("x".into(), int_id, 0), ("y".into(), int_id, 4)],
        );
        let e = ts.lookup(sid).unwrap();
        assert!(matches!(e.kind, TypeKind::Struct { .. }));
    }

    #[test]
    fn dwarf_importer_pointer_bits() {
        let imp = DwarfTypeImporter::new(32);
        assert_eq!(imp.pointer_bits(), 32);
    }

    // ── PdbTypeImporter ───────────────────────────────────────────────────────

    #[test]
    fn pdb_importer_primitives() {
        let ts = ts();
        let imp = PdbTypeImporter::new(64);
        let map = imp.import_primitives(&ts);
        assert!(map.contains_key("double"));
        assert!(map.contains_key("u64"));
    }

    #[test]
    fn pdb_importer_class() {
        let ts = ts();
        let imp = PdbTypeImporter::new(64);
        let builtins = imp.import_primitives(&ts);
        let i32_id = builtins["i32"];
        let cid = imp.import_class(&ts, "MyClass", vec![("val".into(), i32_id, 0)], 8);
        let e = ts.lookup(cid).unwrap();
        assert!(matches!(
            e.kind,
            TypeKind::Struct {
                size_hint: Some(8),
                ..
            }
        ));
    }

    #[test]
    fn pdb_importer_pointer_bits() {
        let imp = PdbTypeImporter::new(64);
        assert_eq!(imp.pointer_bits(), 64);
    }

    // ── populate_builtins ─────────────────────────────────────────────────────

    #[test]
    fn builtins_populates_standard_types() {
        let ts = ts();
        let map = ts.populate_builtins();
        assert!(map.contains_key("void"));
        assert!(map.contains_key("bool"));
        assert!(map.contains_key("char"));
        assert!(map.contains_key("float"));
        assert!(map.contains_key("double"));
        assert!(ts.len() >= 20);
    }

    #[test]
    fn builtins_lookup_by_name() {
        let ts = ts();
        ts.populate_builtins();
        let e = ts.lookup_by_name("uint").unwrap();
        assert!(matches!(
            e.kind,
            TypeKind::Int(IntInfo {
                bits: 32,
                signed: false
            })
        ));
    }

    // ── EnumVariant / FieldDef / ParamDef ─────────────────────────────────────

    #[test]
    fn enum_variant_values() {
        let v = EnumVariant::new("RED", 0);
        assert_eq!(v.name, "RED");
        assert_eq!(v.value, 0);
    }

    #[test]
    fn field_def_no_offset() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let f = FieldDef::new("x", int_id, None);
        assert!(f.offset.is_none());
        assert!(f.bit_offset.is_none());
    }

    #[test]
    fn field_def_bit_field() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, false)));
        let f = FieldDef::bit_field("flags", int_id, Some(0), 0, 3);
        assert_eq!(f.bit_width, Some(3));
        assert_eq!(f.bit_offset, Some(0));
    }

    #[test]
    fn param_def_named_unnamed() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let named = ParamDef::named("count", int_id);
        let unnamed = ParamDef::unnamed(int_id);
        assert!(named.name.is_some());
        assert!(unnamed.name.is_none());
    }

    // ── TypeEntry ─────────────────────────────────────────────────────────────

    #[test]
    fn type_entry_recovered_flag() {
        let ts = ts();
        let id = ts.define(TypeKind::Void);
        let entry = TypeEntry::new(id, TypeKind::Void).as_recovered();
        assert!(entry.is_recovered);
    }

    #[test]
    fn type_entry_with_name() {
        let ts = ts();
        let id = ts.define(TypeKind::Void);
        let entry = TypeEntry::new(id, TypeKind::Void).with_name("my_void");
        assert_eq!(entry.source_name.as_deref(), Some("my_void"));
    }

    // ── Function type ─────────────────────────────────────────────────────────

    #[test]
    fn function_type_variadic() {
        let ts = ts();
        let void_id = ts.define(TypeKind::Void);
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let fid = ts.define(TypeKind::Function {
            ret: void_id,
            params: vec![ParamDef::named("fmt", int_id)],
            variadic: true,
            calling_conv: Some("cdecl".into()),
        });
        let e = ts.lookup(fid).unwrap();
        assert!(matches!(e.kind, TypeKind::Function { variadic: true, .. }));
    }

    #[test]
    fn printer_function_type() {
        let ts = ts();
        let void_id = ts.define(TypeKind::Void);
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        assert_ne!(void_id, int_id, "distinct type IDs allocated");
        let fid = ts.define(TypeKind::Function {
            ret: int_id,
            params: vec![ParamDef::unnamed(int_id)],
            variadic: false,
            calling_conv: None,
        });
        let p = TypePrinter::new(&ts);
        let s = p.print_decl(fid, "add");
        assert!(s.contains("add"));
        assert!(s.contains("int32_t"));
    }

    // ── Intrinsic type ────────────────────────────────────────────────────────

    #[test]
    fn intrinsic_type_layout() {
        let ts = ts();
        let l = TypeLayout::compute(
            &TypeKind::Intrinsic {
                name: "__m128".into(),
                size: 16,
                align: 16,
            },
            64,
            &ts,
        );
        assert_eq!(l.size, 16);
        assert_eq!(l.align, 16);
    }

    // ── Atomic / Restrict / Volatile ──────────────────────────────────────────

    #[test]
    fn atomic_wrapper_resolves() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let aid = ts.define(TypeKind::Atomic(int_id));
        assert_eq!(ts.resolve(aid), int_id);
    }

    #[test]
    fn volatile_wrapper_resolves() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let vid = ts.define(TypeKind::Volatile(int_id));
        assert_eq!(ts.resolve(vid), int_id);
    }

    #[test]
    fn restrict_wrapper_resolves() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let rid = ts.define(TypeKind::Restrict(int_id));
        assert_eq!(ts.resolve(rid), int_id);
    }

    // ── FlexArray ─────────────────────────────────────────────────────────────

    #[test]
    fn flex_array_layout_zero_size() {
        let ts = ts();
        let int_id = ts.define(TypeKind::Int(IntInfo::new(32, true)));
        let l = TypeLayout::compute(&TypeKind::FlexArray { elem: int_id }, 64, &ts);
        assert_eq!(l.size, 0);
    }
}
