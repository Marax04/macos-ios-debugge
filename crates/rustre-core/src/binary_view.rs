//! Loader-facing binary view with serde-compatible sub-stores.
//!
//! This module is the **loader / persistence** layer for a binary view.  It is
//! intentionally distinct from [`binary_view_impl`], which is the
//! **builder / production** layer.  The split exists because the two layers
//! have different requirements:
//!
//! | Concern | This module (`binary_view`) | `binary_view_impl` |
//! |---------|----------------------------|-------------------|
//! | Purpose | Lightweight view used by loaders and integration tests | Feature-complete view with builder, rename, conflict detection |
//! | Construction | Direct `BinaryView::new(...)` | `BinaryViewBuilder` fluent API |
//! | Serde | All sub-stores derive `Serialize`/`Deserialize` | No serde — runtime-only |
//! | Threading | `parking_lot::RwLock` on each field | Owned fields (no internal lock) |
//! | `FunctionTable` rename | `add_function` only | `rename()` with name-index update |
//! | `PatchSet` | Applies/reverts to `Memory` | Conflict detection, `force_apply`, `export_diff` |
//! | `CommentStore` | Address → single `Comment` | Address → multiple comments via `CommentId` |
//! | `BookmarkSet` | Label-deduplicated list | `BookmarkId`-keyed, coloured |
//!
//! Use **this module** when writing a [`crate::loader::Loader`] or when you
//! need serialisable in-memory state.  Use [`binary_view_impl`] for all
//! analyst-facing code that needs renaming, conflict detection, or rich APIs.

use crate::address::{Address, AddressRange};
use crate::errors::CoreError;
use crate::ids::ViewId;
use crate::permissions::Permissions;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────────────────
// Memory & Segment
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub range: AddressRange,
    pub permissions: Permissions,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Memory {
    pub segments: Vec<Segment>,
}

impl Memory {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    pub fn add_segment(&mut self, segment: Segment) {
        self.segments.push(segment);
    }

    /// Performs the operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn read(&self, addr: Address, buf: &mut [u8]) -> Result<(), CoreError> {
        let mut read_bytes = 0;
        let total_len = buf.len();

        while read_bytes < total_len {
            let current_addr = match addr.0.checked_add(read_bytes as u64) {
                Some(v) => Address(v),
                None => return Err(CoreError::SegmentFault { address: u64::MAX }),
            };
            let mut chunk_read = false;
            for seg in &self.segments {
                if seg.range.contains(current_addr) {
                    let offset_in_seg =
                        usize::try_from(current_addr.0 - seg.range.start.0).unwrap_or(usize::MAX);
                    let remaining_in_seg = seg.data.len().saturating_sub(offset_in_seg);
                    if remaining_in_seg > 0 {
                        let to_read = std::cmp::min(total_len - read_bytes, remaining_in_seg);
                        buf[read_bytes..read_bytes + to_read]
                            .copy_from_slice(&seg.data[offset_in_seg..offset_in_seg + to_read]);
                        read_bytes += to_read;
                        chunk_read = true;
                        break;
                    }
                }
            }
            if !chunk_read {
                return Err(CoreError::SegmentFault {
                    address: current_addr.0,
                });
            }
        }
        Ok(())
    }

    /// Performs the operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn write(&mut self, addr: Address, buf: &[u8]) -> Result<(), CoreError> {
        let mut written_bytes = 0;
        let total_len = buf.len();

        while written_bytes < total_len {
            let current_addr = addr + written_bytes as u64;
            let mut chunk_written = false;
            for seg in &mut self.segments {
                if seg.range.contains(current_addr) {
                    if !seg.permissions.is_writable() {
                        return Err(CoreError::PermissionDenied {
                            address: current_addr.0,
                            message: "write permission denied".to_string(),
                        });
                    }
                    let offset_in_seg =
                        usize::try_from(current_addr.0 - seg.range.start.0).unwrap_or(usize::MAX);
                    let remaining_in_seg = seg.data.len().saturating_sub(offset_in_seg);
                    if remaining_in_seg > 0 {
                        let to_write = std::cmp::min(total_len - written_bytes, remaining_in_seg);
                        seg.data[offset_in_seg..offset_in_seg + to_write]
                            .copy_from_slice(&buf[written_bytes..written_bytes + to_write]);
                        written_bytes += to_write;
                        chunk_written = true;
                        break;
                    }
                }
            }
            if !chunk_written {
                return Err(CoreError::SegmentFault {
                    address: current_addr.0,
                });
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BinaryView
// ─────────────────────────────────────────────────────────────────────────────

pub struct BinaryView {
    pub id: ViewId,
    pub uri: String,
    pub arch: std::sync::Arc<dyn crate::arch::Architecture>,
    pub endian: crate::endian::Endian,
    pub bits: u32,
    pub entry_points: Vec<Address>,
    pub mem: RwLock<Memory>,
    pub symbols: RwLock<SymbolTable>,
    pub types: RwLock<TypeSystem>,
    pub functions: RwLock<FunctionTable>,
    pub xrefs: RwLock<XrefIndex>,
    pub patches: RwLock<PatchSet>,
    pub comments: RwLock<CommentStore>,
    pub bookmarks: RwLock<BookmarkSet>,
    pub plugins: RwLock<PluginContext>,
    pub graph: RwLock<KnowledgeGraph>,
}

impl BinaryView {
    pub fn new(
        id: ViewId,
        uri: String,
        arch: std::sync::Arc<dyn crate::arch::Architecture>,
        endian: crate::endian::Endian,
        bits: u32,
        entry_points: Vec<Address>,
        mem: Memory,
    ) -> Self {
        Self {
            id,
            uri,
            arch,
            endian,
            bits,
            entry_points,
            mem: RwLock::new(mem),
            symbols: RwLock::new(SymbolTable::new()),
            types: RwLock::new(TypeSystem::new()),
            functions: RwLock::new(FunctionTable::new()),
            xrefs: RwLock::new(XrefIndex::new()),
            patches: RwLock::new(PatchSet::new()),
            comments: RwLock::new(CommentStore::new()),
            bookmarks: RwLock::new(BookmarkSet::new()),
            plugins: RwLock::new(PluginContext::new()),
            graph: RwLock::new(KnowledgeGraph::new()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. SymbolTable
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a symbol by its role in the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolKind {
    /// An executable function entry point.
    Function,
    /// A statically-allocated data object.
    Data,
    /// A thunk / trampoline stub.
    Thunk,
    /// An imported symbol (extern / IAT entry).
    Import,
    /// An exported symbol.
    Export,
    /// An arbitrary named location (label).
    Label,
}

impl std::fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Function => write!(f, "Function"),
            Self::Data => write!(f, "Data"),
            Self::Thunk => write!(f, "Thunk"),
            Self::Import => write!(f, "Import"),
            Self::Export => write!(f, "Export"),
            Self::Label => write!(f, "Label"),
        }
    }
}

/// Origin / provenance of a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolSource {
    /// Extracted from a PDB debug file.
    Pdb,
    /// Extracted from DWARF debug information.
    Dwarf,
    /// Derived from the binary's export table.
    Export,
    /// Manually added by the analyst.
    User,
    /// Matched by a FLIRT pattern.
    Flirt,
    /// Suggested by an AI / heuristic analysis pass.
    AiSuggested,
}

impl std::fmt::Display for SymbolSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pdb => write!(f, "PDB"),
            Self::Dwarf => write!(f, "DWARF"),
            Self::Export => write!(f, "Export"),
            Self::User => write!(f, "User"),
            Self::Flirt => write!(f, "FLIRT"),
            Self::AiSuggested => write!(f, "AI"),
        }
    }
}

/// A single named symbol in a binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    /// Raw (mangled) name as it appears in the binary.
    pub name: String,
    /// Demangled / human-readable name, if available.
    pub demangled: Option<String>,
    /// Address of the symbol.
    pub address: Address,
    /// Symbol kind.
    pub kind: SymbolKind,
    /// Where the symbol came from.
    pub source: SymbolSource,
}

impl Symbol {
    /// Create a new symbol with explicit fields.
    pub fn new(
        name: impl Into<String>,
        address: Address,
        kind: SymbolKind,
        source: SymbolSource,
    ) -> Self {
        Self {
            name: name.into(),
            demangled: None,
            address,
            kind,
            source,
        }
    }

    /// Attach a demangled name to this symbol.
    #[must_use]
    pub fn with_demangled(mut self, demangled: impl Into<String>) -> Self {
        self.demangled = Some(demangled.into());
        self
    }

    /// Returns the best available display name (demangled, falling back to raw).
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.demangled.as_deref().unwrap_or(&self.name)
    }
}

/// An indexed, address-keyed store for symbols.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SymbolTable {
    /// Symbols keyed by address.  Multiple symbols may share one address.
    by_address: HashMap<u64, Vec<Symbol>>,
    /// Symbols keyed by raw name for fast name lookups.
    by_name: HashMap<String, Vec<Symbol>>,
}

impl SymbolTable {
    /// Create an empty symbol table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a symbol.  Duplicate entries (same name + address) are silently
    /// ignored to keep the table idempotent on repeated loads.
    pub fn add_symbol(&mut self, sym: Symbol) {
        // Deduplicate by (name, address).
        let addr_entry = self.by_address.entry(sym.address.as_u64()).or_default();
        if !addr_entry.iter().any(|s| s.name == sym.name) {
            addr_entry.push(sym.clone());
        }
        let name_entry = self.by_name.entry(sym.name.clone()).or_default();
        if !name_entry.iter().any(|s| s.address == sym.address) {
            name_entry.push(sym);
        }
    }

    /// Return all symbols located at exactly `addr`.
    pub fn get_symbol_at(&self, addr: Address) -> &[Symbol] {
        self.by_address
            .get(&addr.as_u64())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Return all symbols whose raw name matches `name`.
    pub fn get_symbols_by_name(&self, name: &str) -> &[Symbol] {
        self.by_name
            .get(name)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Iterate over every symbol in the table (order is unspecified).
    pub fn iter_symbols(&self) -> impl Iterator<Item = &Symbol> {
        self.by_address.values().flat_map(|v| v.iter())
    }

    /// Total number of distinct symbols.
    pub fn len(&self) -> usize {
        self.by_address.values().map(Vec::len).sum()
    }

    /// Return `true` if the table has no symbols.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove all symbols at `addr`.  Returns the symbols that were removed.
    pub fn remove_at(&mut self, addr: Address) -> Vec<Symbol> {
        let removed = self.by_address.remove(&addr.as_u64()).unwrap_or_default();
        for sym in &removed {
            if let Some(v) = self.by_name.get_mut(&sym.name) {
                v.retain(|s| s.address != addr);
                if v.is_empty() {
                    self.by_name.remove(&sym.name);
                }
            }
        }
        removed
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. TypeSystem
// ─────────────────────────────────────────────────────────────────────────────

/// Primitive scalar types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrimitiveKind {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    Bool,
}

impl PrimitiveKind {
    /// Byte width of the primitive.
    #[must_use]
    pub const fn byte_size(&self) -> usize {
        match self {
            Self::U8 | Self::I8 | Self::Bool => 1,
            Self::U16 | Self::I16 => 2,
            Self::U32 | Self::I32 | Self::F32 => 4,
            Self::U64 | Self::I64 | Self::F64 => 8,
        }
    }

    /// Whether the type is a signed integer.
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        matches!(self, Self::I8 | Self::I16 | Self::I32 | Self::I64)
    }

    /// Whether the type is a floating-point.
    #[must_use]
    pub const fn is_float(&self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }
}

impl std::fmt::Display for PrimitiveKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::U8 => write!(f, "u8"),
            Self::U16 => write!(f, "u16"),
            Self::U32 => write!(f, "u32"),
            Self::U64 => write!(f, "u64"),
            Self::I8 => write!(f, "i8"),
            Self::I16 => write!(f, "i16"),
            Self::I32 => write!(f, "i32"),
            Self::I64 => write!(f, "i64"),
            Self::F32 => write!(f, "f32"),
            Self::F64 => write!(f, "f64"),
            Self::Bool => write!(f, "bool"),
        }
    }
}

/// A named field within a struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructField {
    /// Field name.
    pub name: String,
    /// Byte offset from the start of the struct.
    pub offset: usize,
    /// The field's type.
    pub ty: TypeKind,
}

impl StructField {
    /// Construct a struct field.
    pub fn new(name: impl Into<String>, offset: usize, ty: TypeKind) -> Self {
        Self {
            name: name.into(),
            offset,
            ty,
        }
    }
}

/// A single variant in an enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumVariant {
    /// Variant name.
    pub name: String,
    /// Discriminant value.
    pub value: i64,
}

impl EnumVariant {
    /// Construct an enum variant.
    pub fn new(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }
}

/// Recursive type descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeKind {
    /// A built-in scalar.
    Primitive(PrimitiveKind),
    /// A raw pointer to another type.
    Pointer(Box<Self>),
    /// A fixed-length array.
    Array { element: Box<Self>, count: usize },
    /// A C-style struct / record.
    Struct {
        name: String,
        fields: Vec<StructField>,
    },
    /// A C-style enum.
    Enum {
        name: String,
        variants: Vec<EnumVariant>,
    },
    /// A function pointer / signature.
    FunctionType { ret: Box<Self>, params: Vec<Self> },
    /// The absence of a value (`void`).
    Void,
}

impl TypeKind {
    /// Attempt to compute the in-memory byte size of the type.
    /// Returns `None` for types whose size is target-dependent or unknown.
    #[must_use]
    pub fn byte_size(&self, pointer_width: usize) -> Option<usize> {
        match self {
            Self::Void => Some(0),
            Self::Primitive(p) => Some(p.byte_size()),
            Self::Pointer(_) | Self::FunctionType { .. } => Some(pointer_width / 8),
            Self::Array { element, count } => element
                .byte_size(pointer_width)
                .and_then(|s| s.checked_mul(*count)),
            Self::Struct { fields, .. } => fields
                .iter()
                .map(|f| f.ty.byte_size(pointer_width).map(|sz| f.offset + sz))
                .try_fold(0usize, |acc, item| item.map(|b| acc.max(b))),
            Self::Enum { .. } => Some(4), // default int-sized
        }
    }

    /// Return `true` if this is the `Void` type.
    #[must_use]
    pub const fn is_void(&self) -> bool {
        matches!(self, Self::Void)
    }

    /// Return `true` if this is a pointer.
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer(_))
    }
}

impl std::fmt::Display for TypeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Void => write!(f, "void"),
            Self::Primitive(p) => write!(f, "{p}"),
            Self::Pointer(inner) => write!(f, "*{inner}"),
            Self::Array { element, count } => write!(f, "[{element}; {count}]"),
            Self::Struct { name, .. } => write!(f, "struct {name}"),
            Self::Enum { name, .. } => write!(f, "enum {name}"),
            Self::FunctionType { ret, params } => {
                write!(f, "fn(")?;
                for (i, p) in params.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{p}")?;
                }
                write!(f, ") -> {ret}")
            }
        }
    }
}

/// A named, registered type entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeEntry {
    /// The canonical name of this type.
    pub name: String,
    /// The type descriptor.
    pub kind: TypeKind,
    /// Optional doc comment / description.
    pub comment: Option<String>,
}

impl TypeEntry {
    /// Create a type entry without a comment.
    pub fn new(name: impl Into<String>, kind: TypeKind) -> Self {
        Self {
            name: name.into(),
            kind,
            comment: None,
        }
    }

    /// Attach a comment to this entry.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }
}

/// Central registry for all type definitions in a binary view.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeSystem {
    entries: HashMap<String, TypeEntry>,
}

impl TypeSystem {
    /// Create an empty type system.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a type entry.  Overwrites any existing entry with the same name.
    pub fn add_type(&mut self, entry: TypeEntry) {
        self.entries.insert(entry.name.clone(), entry);
    }

    /// Look up a type by its canonical name.
    #[must_use]
    pub fn get_type(&self, name: &str) -> Option<&TypeEntry> {
        self.entries.get(name)
    }

    /// Resolve a `TypeKind` that may be a named reference, following aliases.
    /// Currently only returns the kind itself; alias resolution can be layered on top.
    #[must_use]
    pub const fn resolve<'a>(&'a self, kind: &'a TypeKind) -> &'a TypeKind {
        kind
    }

    /// Look up or create a primitive type, returning a clone of its `TypeKind`.
    #[must_use]
    pub const fn primitive_type(&self, prim: PrimitiveKind) -> TypeKind {
        TypeKind::Primitive(prim)
    }

    /// Total number of registered types.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if no types are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all registered types.
    pub fn iter_types(&self) -> impl Iterator<Item = &TypeEntry> {
        self.entries.values()
    }

    /// Remove a type by name, returning it if it existed.
    pub fn remove_type(&mut self, name: &str) -> Option<TypeEntry> {
        self.entries.remove(name)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. FunctionTable
// ─────────────────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Miscellaneous function attributes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FunctionFlags: u32 {
        /// Function has no return.
        const NO_RETURN     = 1 << 0;
        /// Function is variadic.
        const VARIADIC      = 1 << 1;
        /// Function is inlined at some call sites.
        const INLINED       = 1 << 2;
        /// Function has been user-confirmed / verified.
        const CONFIRMED     = 1 << 3;
        /// Function was automatically discovered.
        const AUTO_FOUND    = 1 << 4;
        /// Function is a constructor.
        const CONSTRUCTOR   = 1 << 5;
        /// Function is a destructor.
        const DESTRUCTOR    = 1 << 6;
        /// Function is virtual.
        const VIRTUAL       = 1 << 7;
        /// Function is pure-virtual (has no body).
        const PURE_VIRTUAL  = 1 << 8;
    }
}

impl Default for FunctionFlags {
    fn default() -> Self {
        Self::empty()
    }
}

impl Serialize for FunctionFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.bits())
    }
}

impl<'de> Deserialize<'de> for FunctionFlags {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bits = u32::deserialize(deserializer)?;
        Ok(Self::from_bits_truncate(bits))
    }
}

/// A function definition registered in the binary view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDef {
    /// Address of the first instruction.
    pub address: Address,
    /// Address past the last byte of the function body (exclusive end).
    pub end_address: Option<Address>,
    /// Human-readable name.
    pub name: String,
    /// Type signature in textual form (e.g. `int __cdecl foo(int, char*)`).
    pub prototype: Option<String>,
    /// Calling convention name (e.g. `"__cdecl"`, `"fastcall"`).
    pub calling_convention: Option<String>,
    /// `true` if this function is a thunk / trampoline.
    pub is_thunk: bool,
    /// `true` if the function was imported from a known library.
    pub is_library: bool,
    /// Name of the library that contributed the identification, when known
    /// (e.g. `"msvcrt"`, `"libstd"`).  Set by feature K propagation.
    #[serde(default)]
    pub library_origin: Option<String>,
    /// Miscellaneous flags.
    pub flags: FunctionFlags,
}

impl FunctionDef {
    /// Construct a minimal function definition.
    pub fn new(address: Address, name: impl Into<String>) -> Self {
        Self {
            address,
            end_address: None,
            name: name.into(),
            prototype: None,
            calling_convention: None,
            is_thunk: false,
            is_library: false,
            library_origin: None,
            flags: FunctionFlags::empty(),
        }
    }

    /// Set the exclusive end address.
    #[must_use]
    pub const fn with_end(mut self, end: Address) -> Self {
        self.end_address = Some(end);
        self
    }

    /// Attach a prototype string.
    #[must_use]
    pub fn with_prototype(mut self, proto: impl Into<String>) -> Self {
        self.prototype = Some(proto.into());
        self
    }

    /// Set the calling convention.
    #[must_use]
    pub fn with_calling_convention(mut self, cc: impl Into<String>) -> Self {
        self.calling_convention = Some(cc.into());
        self
    }

    /// Set flags.
    #[must_use]
    pub const fn with_flags(mut self, flags: FunctionFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Byte size of the function body, if end address is known.
    #[must_use]
    pub fn byte_size(&self) -> Option<u64> {
        self.end_address
            .map(|end| end.as_u64().saturating_sub(self.address.as_u64()))
    }

    /// Return `true` if `addr` falls within `[address, end_address)`.
    #[must_use]
    pub fn contains(&self, addr: Address) -> bool {
        if addr < self.address {
            return false;
        }
        self.end_address.is_some_and(|end| addr < end)
    }
}

/// Address-indexed table of all known functions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionTable {
    /// Indexed by entry address (u64).
    by_address: HashMap<u64, FunctionDef>,
    /// Indexed by name for fast lookups.
    by_name: HashMap<String, Vec<u64>>,
}

impl FunctionTable {
    /// Create an empty function table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a function definition.
    pub fn add_function(&mut self, func: FunctionDef) {
        let addr = func.address.as_u64();
        // Update name index.
        let name_entry = self.by_name.entry(func.name.clone()).or_default();
        if !name_entry.contains(&addr) {
            name_entry.push(addr);
        }
        self.by_address.insert(addr, func);
    }

    /// Look up the function that starts at exactly `addr`.
    #[must_use]
    pub fn get_function_at(&self, addr: Address) -> Option<&FunctionDef> {
        self.by_address.get(&addr.as_u64())
    }

    /// Look up all functions whose name matches `name`.
    #[must_use]
    pub fn get_function_by_name(&self, name: &str) -> Vec<&FunctionDef> {
        self.by_name
            .get(name)
            .map(|addrs| {
                addrs
                    .iter()
                    .filter_map(|a| self.by_address.get(a))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return all functions whose body spans the given range.
    #[must_use]
    pub fn functions_in_range(&self, range: AddressRange) -> Vec<&FunctionDef> {
        self.by_address
            .values()
            .filter(|f| {
                // Include any function whose start is within the range.
                range.contains(f.address)
            })
            .collect()
    }

    /// Iterate over all function definitions (order unspecified).
    pub fn iter_functions(&self) -> impl Iterator<Item = &FunctionDef> {
        self.by_address.values()
    }

    /// Number of known functions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    /// Return `true` if no functions are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    /// Remove the function starting at `addr`.
    pub fn remove_function(&mut self, addr: Address) -> Option<FunctionDef> {
        let func = self.by_address.remove(&addr.as_u64())?;
        if let Some(addrs) = self.by_name.get_mut(&func.name) {
            addrs.retain(|a| *a != addr.as_u64());
            if addrs.is_empty() {
                self.by_name.remove(&func.name);
            }
        }
        Some(func)
    }

    /// Mark the function at `addr` as a library function originating from
    /// `lib_name`. Idempotent: re-marking the same function with the same lib
    /// is a no-op; re-marking with a different lib overwrites the recorded
    /// origin. Returns `true` if a function was found and updated.
    pub fn mark_library(&mut self, addr: Address, lib_name: impl Into<String>) -> bool {
        match self.by_address.get_mut(&addr.as_u64()) {
            Some(f) => {
                f.is_library = true;
                f.library_origin = Some(lib_name.into());
                true
            }
            None => false,
        }
    }

    /// Number of functions currently classified as library code.
    #[must_use]
    pub fn count_library(&self) -> usize {
        self.by_address.values().filter(|f| f.is_library).count()
    }

    /// Number of functions not classified as library code (i.e. user code).
    #[must_use]
    pub fn count_user(&self) -> usize {
        self.by_address.values().filter(|f| !f.is_library).count()
    }

    /// Iterate over functions classified as library code.
    pub fn iter_library(&self) -> impl Iterator<Item = &FunctionDef> {
        self.by_address.values().filter(|f| f.is_library)
    }

    /// Iterate over functions not classified as library code.
    pub fn iter_user(&self) -> impl Iterator<Item = &FunctionDef> {
        self.by_address.values().filter(|f| !f.is_library)
    }

    /// Group library-function counts by their `library_origin` value.
    /// Functions with no origin recorded but `is_library == true` are
    /// counted under the empty-string key.
    #[must_use]
    pub fn library_breakdown(&self) -> HashMap<String, usize> {
        let mut out: HashMap<String, usize> = HashMap::new();
        for f in self.by_address.values().filter(|f| f.is_library) {
            let key = f.library_origin.clone().unwrap_or_default();
            *out.entry(key).or_insert(0) += 1;
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. XrefIndex
// ─────────────────────────────────────────────────────────────────────────────

/// The semantic type of a cross-reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum XrefKind {
    /// A direct or indirect `call` instruction.
    CodeCall,
    /// A `jmp` or conditional branch targeting the destination.
    CodeJump,
    /// A memory read referencing the destination address.
    DataRead,
    /// A memory write referencing the destination address.
    DataWrite,
    /// An address-taken reference (e.g. `lea rax, [sym]`).
    DataAddr,
}

impl std::fmt::Display for XrefKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CodeCall => write!(f, "Call"),
            Self::CodeJump => write!(f, "Jump"),
            Self::DataRead => write!(f, "DataRead"),
            Self::DataWrite => write!(f, "DataWrite"),
            Self::DataAddr => write!(f, "DataAddr"),
        }
    }
}

/// A single directional cross-reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Xref {
    /// Address of the referencing instruction / data.
    pub from_addr: Address,
    /// Address being referenced.
    pub to_addr: Address,
    /// Semantic category.
    pub kind: XrefKind,
}

impl Xref {
    /// Construct a new cross-reference.
    #[must_use]
    pub const fn new(from_addr: Address, to_addr: Address, kind: XrefKind) -> Self {
        Self {
            from_addr,
            to_addr,
            kind,
        }
    }
}

/// Bi-directional cross-reference index.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct XrefIndex {
    /// `from → [to, ...]`
    outgoing: HashMap<u64, Vec<Xref>>,
    /// `to → [from, ...]`
    incoming: HashMap<u64, Vec<Xref>>,
}

impl XrefIndex {
    /// Create an empty cross-reference index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a cross-reference.  Duplicate entries are silently ignored.
    pub fn add_xref(&mut self, xref: Xref) {
        let from = xref.from_addr.as_u64();
        let to = xref.to_addr.as_u64();

        let out = self.outgoing.entry(from).or_default();
        if !out.contains(&xref) {
            out.push(xref.clone());
        }
        let inc = self.incoming.entry(to).or_default();
        if !inc.contains(&xref) {
            inc.push(xref);
        }
    }

    /// Return all xrefs that originate at `from_addr`.
    pub fn xrefs_from(&self, from_addr: Address) -> &[Xref] {
        self.outgoing
            .get(&from_addr.as_u64())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Return all xrefs that point to `to_addr`.
    pub fn xrefs_to(&self, to_addr: Address) -> &[Xref] {
        self.incoming
            .get(&to_addr.as_u64())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Return addresses of all sites that *call* `callee` (kind == `CodeCall`).
    #[must_use]
    pub fn callers_of(&self, callee: Address) -> Vec<Address> {
        self.xrefs_to(callee)
            .iter()
            .filter(|x| x.kind == XrefKind::CodeCall)
            .map(|x| x.from_addr)
            .collect()
    }

    /// Return addresses of all functions / targets *called by* `caller`.
    #[must_use]
    pub fn callees_of(&self, caller: Address) -> Vec<Address> {
        self.xrefs_from(caller)
            .iter()
            .filter(|x| x.kind == XrefKind::CodeCall)
            .map(|x| x.to_addr)
            .collect()
    }

    /// Total number of recorded cross-references.
    pub fn len(&self) -> usize {
        self.outgoing.values().map(Vec::len).sum()
    }

    /// Return `true` if no xrefs are recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove all xrefs originating from `from_addr`.
    pub fn remove_xrefs_from(&mut self, from_addr: Address) {
        if let Some(xrefs) = self.outgoing.remove(&from_addr.as_u64()) {
            for xref in &xrefs {
                if let Some(inc) = self.incoming.get_mut(&xref.to_addr.as_u64()) {
                    inc.retain(|x| x.from_addr != from_addr);
                    if inc.is_empty() {
                        self.incoming.remove(&xref.to_addr.as_u64());
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. PatchSet
// ─────────────────────────────────────────────────────────────────────────────

/// A serializable representation of `SystemTime` as seconds-since-UNIX-epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp {
    /// Seconds since the UNIX epoch (1970-01-01 00:00:00 UTC).
    pub secs: u64,
    /// Sub-second nanoseconds.
    pub nanos: u32,
}

impl Timestamp {
    /// Create a timestamp from a `SystemTime`.
    #[must_use]
    pub fn from_system_time(t: SystemTime) -> Self {
        t.duration_since(UNIX_EPOCH)
            .map_or(Self { secs: 0, nanos: 0 }, |d| Self {
                secs: d.as_secs(),
                nanos: d.subsec_nanos(),
            })
    }

    /// Convert back to `SystemTime`.
    #[must_use]
    pub fn to_system_time(self) -> SystemTime {
        UNIX_EPOCH + Duration::new(self.secs, self.nanos)
    }

    /// Current wall-clock time as a `Timestamp`.
    #[must_use]
    pub fn now() -> Self {
        Self::from_system_time(SystemTime::now())
    }
}

/// A binary patch: records the original and replacement bytes at an address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    /// Start address of the patched region.
    pub address: Address,
    /// Bytes present in the original binary.
    pub original_bytes: Vec<u8>,
    /// Replacement bytes to apply.
    pub new_bytes: Vec<u8>,
    /// Human-readable reason / annotation.
    pub reason: Option<String>,
    /// When the patch was created.
    pub created_at: Timestamp,
}

impl Patch {
    /// Construct a new patch.
    #[must_use]
    pub fn new(address: Address, original: Vec<u8>, replacement: Vec<u8>) -> Self {
        Self {
            address,
            original_bytes: original,
            new_bytes: replacement,
            reason: None,
            created_at: Timestamp::now(),
        }
    }

    /// Attach a reason string.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Number of bytes affected.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.new_bytes.len().max(self.original_bytes.len())
    }
}

/// An ordered collection of patches, indexed by start address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatchSet {
    patches: HashMap<u64, Patch>,
}

impl PatchSet {
    /// Create an empty patch set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace the patch at the given address.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_patch(&mut self, patch: Patch) -> Result<(), CoreError> {
        if patch.new_bytes.is_empty() {
            return Err(CoreError::InvalidInput {
                message: "patch replacement bytes must not be empty".into(),
            });
        }
        self.patches.insert(patch.address.as_u64(), patch);
        Ok(())
    }

    /// Return the patch exactly at `addr`, if any.
    #[must_use]
    pub fn patches_at(&self, addr: Address) -> Option<&Patch> {
        self.patches.get(&addr.as_u64())
    }

    /// Iterate over all patches.
    pub fn iter_patches(&self) -> impl Iterator<Item = &Patch> {
        self.patches.values()
    }

    /// Apply all patches to the provided `Memory`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn apply_to_memory(&self, mem: &mut Memory) -> Result<(), CoreError> {
        for patch in self.patches.values() {
            mem.write(patch.address, &patch.new_bytes)?;
        }
        Ok(())
    }

    /// Revert all patches in `Memory` to the stored original bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn unapply_from_memory(&self, mem: &mut Memory) -> Result<(), CoreError> {
        for patch in self.patches.values() {
            mem.write(patch.address, &patch.original_bytes)?;
        }
        Ok(())
    }

    /// Number of patches.
    #[must_use]
    pub fn len(&self) -> usize {
        self.patches.len()
    }

    /// Return `true` if there are no patches.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    /// Remove and return the patch at `addr`.
    pub fn remove_patch(&mut self, addr: Address) -> Option<Patch> {
        self.patches.remove(&addr.as_u64())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. CommentStore
// ─────────────────────────────────────────────────────────────────────────────

/// A comment attached to a specific address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comment {
    /// The comment body.
    pub text: String,
    /// `true` if the comment should appear at every location that references
    /// this address (repeatable comment, à la IDA Pro).
    pub repeatable: bool,
    /// Optional author identifier.
    pub author: Option<String>,
    /// When the comment was created or last modified.
    pub modified_at: Timestamp,
}

impl Comment {
    /// Create a simple, non-repeatable comment.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            repeatable: false,
            author: None,
            modified_at: Timestamp::now(),
        }
    }

    /// Make this a repeatable comment.
    #[must_use]
    pub const fn repeatable(mut self) -> Self {
        self.repeatable = true;
        self
    }

    /// Attach an author tag.
    #[must_use]
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }
}

/// Address-indexed comment store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommentStore {
    comments: HashMap<u64, Comment>,
}

impl CommentStore {
    /// Create an empty comment store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace the comment at `addr`.
    pub fn add_comment(&mut self, addr: Address, comment: Comment) {
        self.comments.insert(addr.as_u64(), comment);
    }

    /// Return the comment at `addr`, if present.
    #[must_use]
    pub fn get_comment(&self, addr: Address) -> Option<&Comment> {
        self.comments.get(&addr.as_u64())
    }

    /// Remove the comment at `addr`.  Returns the removed comment if it existed.
    pub fn remove_comment(&mut self, addr: Address) -> Option<Comment> {
        self.comments.remove(&addr.as_u64())
    }

    /// Iterate over `(address, comment)` pairs.
    pub fn iter_comments(&self) -> impl Iterator<Item = (Address, &Comment)> {
        self.comments.iter().map(|(k, v)| (Address::new(*k), v))
    }

    /// Number of comments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.comments.len()
    }

    /// Return `true` if there are no comments.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.comments.is_empty()
    }

    /// Update the text of an existing comment in-place.
    pub fn update_text(&mut self, addr: Address, text: impl Into<String>) -> bool {
        if let Some(c) = self.comments.get_mut(&addr.as_u64()) {
            c.text = text.into();
            c.modified_at = Timestamp::now();
            true
        } else {
            false
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. BookmarkSet
// ─────────────────────────────────────────────────────────────────────────────

/// A named, coloured bookmark pinned to an address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bookmark {
    /// The bookmarked address.
    pub address: Address,
    /// An optional human-readable label.
    pub label: Option<String>,
    /// Packed ARGB color (0xAARRGGBB).  Defaults to 0.
    pub color: u32,
}

impl Bookmark {
    /// Create a minimal bookmark with no label and default color.
    #[must_use]
    pub const fn new(address: Address) -> Self {
        Self {
            address,
            label: None,
            color: 0,
        }
    }

    /// Attach a label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set the ARGB color.
    #[must_use]
    pub const fn with_color(mut self, color: u32) -> Self {
        self.color = color;
        self
    }
}

/// An ordered set of bookmarks, keyed by address.
/// Multiple bookmarks may exist at a single address (e.g. with different labels).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BookmarkSet {
    /// Address → list of bookmarks at that address.
    bookmarks: HashMap<u64, Vec<Bookmark>>,
}

impl BookmarkSet {
    /// Create an empty bookmark set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a bookmark.  Duplicates (same address + label) are silently ignored.
    pub fn add_bookmark(&mut self, bm: Bookmark) {
        let entry = self.bookmarks.entry(bm.address.as_u64()).or_default();
        let label = bm.label.clone();
        if !entry.iter().any(|b| b.label == label) {
            entry.push(bm);
        }
    }

    /// Remove bookmarks at `addr` with the given optional label.
    /// If `label` is `None`, all bookmarks at `addr` are removed.
    pub fn remove_bookmark(&mut self, addr: Address, label: Option<&str>) {
        if let Some(entry) = self.bookmarks.get_mut(&addr.as_u64()) {
            match label {
                None => entry.clear(),
                Some(lbl) => entry.retain(|b| b.label.as_deref() != Some(lbl)),
            }
            if entry.is_empty() {
                self.bookmarks.remove(&addr.as_u64());
            }
        }
    }

    /// Return all bookmarks at `addr`.
    pub fn get_bookmarks_at(&self, addr: Address) -> &[Bookmark] {
        self.bookmarks
            .get(&addr.as_u64())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Iterate over all bookmarks.
    pub fn iter_bookmarks(&self) -> impl Iterator<Item = &Bookmark> {
        self.bookmarks.values().flat_map(|v| v.iter())
    }

    /// Total number of bookmarks.
    pub fn len(&self) -> usize {
        self.bookmarks.values().map(Vec::len).sum()
    }

    /// Return `true` if there are no bookmarks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. PluginContext
// ─────────────────────────────────────────────────────────────────────────────

/// A key-value store for plugin-specific state.
///
/// Values are stored as raw `Vec<u8>` blobs.  Plugins are responsible for
/// serialising and deserialising their own data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginContext {
    store: HashMap<String, Vec<u8>>,
}

impl PluginContext {
    /// Create an empty plugin context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a key-value pair.  Overwrites any existing value for `key`.
    pub fn set(&mut self, key: impl Into<String>, value: Vec<u8>) {
        self.store.insert(key.into(), value);
    }

    /// Retrieve the stored bytes for `key`.
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.store.get(key).map(Vec::as_slice)
    }

    /// Remove a key-value pair.  Returns the removed value if it existed.
    pub fn remove(&mut self, key: &str) -> Option<Vec<u8>> {
        self.store.remove(key)
    }

    /// Return `true` if `key` is present.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.store.contains_key(key)
    }

    /// Number of stored entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Return `true` if the context is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// Iterate over `(key, value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.store.iter().map(|(k, v)| (k.as_str(), v.as_slice()))
    }

    /// Convenience: store a UTF-8 string value.
    pub fn set_str(&mut self, key: impl Into<String>, value: &str) {
        self.store.insert(key.into(), value.as_bytes().to_vec());
    }

    /// Convenience: retrieve a stored value as a UTF-8 string.
    #[must_use]
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.store
            .get(key)
            .and_then(|b| std::str::from_utf8(b).ok())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. KnowledgeGraph (lightweight, in-memory)
// ─────────────────────────────────────────────────────────────────────────────

/// A lightweight, in-memory annotation store for arbitrary metadata.
///
/// Unlike the DB-backed `rustre_graph::KnowledgeGraph`, this structure lives
/// entirely in memory and serialises to JSON-strings keyed by an arbitrary tag.
/// It is intended for fast read/write of analyst notes, AI-generated insights,
/// and tool-specific metadata that does not warrant a full graph edge.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnowledgeGraph {
    /// Annotations keyed by an arbitrary tag string.
    /// Values are stored as serialized JSON text (a `String`) to remain
    /// independent of the `serde_json` crate at this layer.
    annotations: HashMap<String, String>,
}

impl KnowledgeGraph {
    /// Create an empty knowledge graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store an annotation under `tag`.  The `value` is an arbitrary
    /// JSON-serializable string (typically produced by `serde_json::to_string`
    /// in the caller, but any `String` is accepted).
    pub fn annotate(&mut self, tag: impl Into<String>, value: impl Into<String>) {
        self.annotations.insert(tag.into(), value.into());
    }

    /// Retrieve the annotation stored under `tag`.
    pub fn get_annotation(&self, tag: &str) -> Option<&str> {
        self.annotations.get(tag).map(String::as_str)
    }

    /// Remove the annotation stored under `tag`.  Returns it if it existed.
    pub fn remove_annotation(&mut self, tag: &str) -> Option<String> {
        self.annotations.remove(tag)
    }

    /// Return `true` if an annotation exists under `tag`.
    #[must_use]
    pub fn has_annotation(&self, tag: &str) -> bool {
        self.annotations.contains_key(tag)
    }

    /// Number of stored annotations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.annotations.len()
    }

    /// Return `true` if there are no annotations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.annotations.is_empty()
    }

    /// Iterate over `(tag, value)` pairs.
    pub fn iter_annotations(&self) -> impl Iterator<Item = (&str, &str)> {
        self.annotations
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Merge all annotations from `other` into `self`.
    /// Entries in `other` overwrite conflicting entries in `self`.
    pub fn merge_from(&mut self, other: &Self) {
        for (tag, value) in &other.annotations {
            self.annotations.insert(tag.clone(), value.clone());
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Memory ────────────────────────────────────────────────────────────────

    #[test]
    fn test_memory_read_write() {
        let mut mem = Memory::new();
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
            permissions: Permissions::READ | Permissions::WRITE,
            data: vec![0; 0x1000],
        });

        let write_data = b"Hello, World!";
        mem.write(Address::new(0x1010), write_data).unwrap();

        let mut read_data = vec![0; write_data.len()];
        mem.read(Address::new(0x1010), &mut read_data).unwrap();
        assert_eq!(read_data, write_data);

        // Out-of-bounds writes and reads must error.
        assert!(mem.write(Address::new(0x2000), b"out").is_err());
        assert!(mem.read(Address::new(0x1FFF), &mut [0; 2]).is_err());
    }

    #[test]
    fn test_memory_write_permission_denied() {
        let mut mem = Memory::new();
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0x4000), Address::new(0x5000)),
            permissions: Permissions::READ,
            data: vec![0xCC; 0x1000],
        });
        assert!(mem.write(Address::new(0x4000), b"x").is_err());
    }

    // ── SymbolTable ───────────────────────────────────────────────────────────

    #[test]
    fn test_symbol_table_add_and_lookup() {
        let mut tbl = SymbolTable::new();
        assert!(tbl.is_empty());

        let sym = Symbol::new(
            "main",
            Address::new(0x1000),
            SymbolKind::Function,
            SymbolSource::User,
        )
        .with_demangled("main");
        tbl.add_symbol(sym);

        assert_eq!(tbl.len(), 1);
        assert!(!tbl.is_empty());

        let by_addr = tbl.get_symbol_at(Address::new(0x1000));
        assert_eq!(by_addr.len(), 1);
        assert_eq!(by_addr[0].name, "main");
        assert_eq!(by_addr[0].display_name(), "main");

        let by_name = tbl.get_symbols_by_name("main");
        assert_eq!(by_name.len(), 1);
        assert_eq!(by_name[0].address, Address::new(0x1000));
    }

    #[test]
    fn test_symbol_table_deduplication() {
        let mut tbl = SymbolTable::new();
        let sym = Symbol::new(
            "sub_1234",
            Address::new(0x1234),
            SymbolKind::Function,
            SymbolSource::Flirt,
        );
        tbl.add_symbol(sym.clone());
        tbl.add_symbol(sym);
        assert_eq!(tbl.len(), 1);
    }

    #[test]
    fn test_symbol_table_remove() {
        let mut tbl = SymbolTable::new();
        tbl.add_symbol(Symbol::new(
            "alpha",
            Address::new(0xAA),
            SymbolKind::Label,
            SymbolSource::User,
        ));
        tbl.add_symbol(Symbol::new(
            "beta",
            Address::new(0xBB),
            SymbolKind::Data,
            SymbolSource::Dwarf,
        ));

        let removed = tbl.remove_at(Address::new(0xAA));
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].name, "alpha");
        assert_eq!(tbl.len(), 1);
        assert!(tbl.get_symbols_by_name("alpha").is_empty());
    }

    #[test]
    fn test_symbol_iter() {
        let mut tbl = SymbolTable::new();
        for i in 0u64..5 {
            tbl.add_symbol(Symbol::new(
                format!("sym_{i}"),
                Address::new(i * 0x10),
                SymbolKind::Function,
                SymbolSource::Export,
            ));
        }
        assert_eq!(tbl.iter_symbols().count(), 5);
    }

    // ── TypeSystem ────────────────────────────────────────────────────────────

    #[test]
    fn test_type_system_primitives() {
        let ts = TypeSystem::new();
        let u32_ty = ts.primitive_type(PrimitiveKind::U32);
        assert_eq!(u32_ty.byte_size(64).unwrap(), 4);
        assert!(!u32_ty.is_void());
        assert!(!u32_ty.is_pointer());
    }

    #[test]
    fn test_type_system_struct() {
        let mut ts = TypeSystem::new();
        let entry = TypeEntry::new(
            "Point",
            TypeKind::Struct {
                name: "Point".into(),
                fields: vec![
                    StructField::new("x", 0, TypeKind::Primitive(PrimitiveKind::I32)),
                    StructField::new("y", 4, TypeKind::Primitive(PrimitiveKind::I32)),
                ],
            },
        )
        .with_comment("A 2D integer point");

        ts.add_type(entry);
        assert_eq!(ts.len(), 1);

        let got = ts.get_type("Point").unwrap();
        assert_eq!(got.comment.as_deref(), Some("A 2D integer point"));

        // Byte size: max(offset + size) = max(0+4, 4+4) = 8
        assert_eq!(got.kind.byte_size(64).unwrap(), 8);
    }

    #[test]
    fn test_type_system_pointer() {
        let ptr = TypeKind::Pointer(Box::new(TypeKind::Primitive(PrimitiveKind::U8)));
        assert_eq!(ptr.byte_size(64).unwrap(), 8);
        assert_eq!(ptr.byte_size(32).unwrap(), 4);
        assert!(ptr.is_pointer());
    }

    #[test]
    fn test_type_system_array() {
        let arr = TypeKind::Array {
            element: Box::new(TypeKind::Primitive(PrimitiveKind::U32)),
            count: 10,
        };
        assert_eq!(arr.byte_size(64).unwrap(), 40);
    }

    #[test]
    fn test_type_system_enum() {
        let mut ts = TypeSystem::new();
        let entry = TypeEntry::new(
            "Direction",
            TypeKind::Enum {
                name: "Direction".into(),
                variants: vec![
                    EnumVariant::new("North", 0),
                    EnumVariant::new("South", 1),
                    EnumVariant::new("East", 2),
                    EnumVariant::new("West", 3),
                ],
            },
        );
        ts.add_type(entry);
        assert!(ts.get_type("Direction").is_some());
        let removed = ts.remove_type("Direction");
        assert!(removed.is_some());
        assert!(ts.is_empty());
    }

    #[test]
    fn test_type_display() {
        assert_eq!(TypeKind::Void.to_string(), "void");
        assert_eq!(TypeKind::Primitive(PrimitiveKind::U64).to_string(), "u64");
        let ptr = TypeKind::Pointer(Box::new(TypeKind::Primitive(PrimitiveKind::I8)));
        assert_eq!(ptr.to_string(), "*i8");
    }

    // ── FunctionTable ─────────────────────────────────────────────────────────

    #[test]
    fn test_function_table_basic() {
        let mut ft = FunctionTable::new();
        assert!(ft.is_empty());

        let func = FunctionDef::new(Address::new(0x4000), "do_work")
            .with_end(Address::new(0x4080))
            .with_calling_convention("__cdecl")
            .with_flags(FunctionFlags::CONFIRMED);

        ft.add_function(func);
        assert_eq!(ft.len(), 1);

        let found = ft.get_function_at(Address::new(0x4000)).unwrap();
        assert_eq!(found.name, "do_work");
        assert_eq!(found.byte_size().unwrap(), 0x80);
        assert!(found.contains(Address::new(0x4010)));
        assert!(!found.contains(Address::new(0x4080)));
    }

    #[test]
    fn test_function_table_lookup_by_name() {
        let mut ft = FunctionTable::new();
        ft.add_function(FunctionDef::new(Address::new(0x100), "init"));
        ft.add_function(FunctionDef::new(Address::new(0x200), "init"));

        let results = ft.get_function_by_name("init");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_function_table_range_query() {
        let mut ft = FunctionTable::new();
        for i in 0u64..10 {
            ft.add_function(
                FunctionDef::new(Address::new(0x1000 + i * 0x100), format!("fn_{i}"))
                    .with_end(Address::new(0x1000 + i * 0x100 + 0x80)),
            );
        }
        let range = AddressRange::new(Address::new(0x1000), Address::new(0x1500));
        let in_range = ft.functions_in_range(range);
        assert_eq!(in_range.len(), 5); // fn_0 .. fn_4
    }

    #[test]
    fn test_function_table_remove() {
        let mut ft = FunctionTable::new();
        ft.add_function(FunctionDef::new(Address::new(0xDEAD), "target"));
        let removed = ft.remove_function(Address::new(0xDEAD));
        assert!(removed.is_some());
        assert!(ft.is_empty());
        assert!(ft.get_function_by_name("target").is_empty());
    }

    #[test]
    fn test_function_table_mark_library() {
        let mut ft = FunctionTable::new();
        ft.add_function(FunctionDef::new(Address::new(0x1000), "strlen"));
        ft.add_function(FunctionDef::new(Address::new(0x2000), "user_fn"));

        assert_eq!(ft.count_library(), 0);
        assert_eq!(ft.count_user(), 2);

        assert!(ft.mark_library(Address::new(0x1000), "msvcrt"));
        // Idempotent re-mark
        assert!(ft.mark_library(Address::new(0x1000), "msvcrt"));
        // Unknown address returns false
        assert!(!ft.mark_library(Address::new(0xDEAD), "msvcrt"));

        let f = ft.get_function_at(Address::new(0x1000)).unwrap();
        assert!(f.is_library);
        assert_eq!(f.library_origin.as_deref(), Some("msvcrt"));

        assert_eq!(ft.count_library(), 1);
        assert_eq!(ft.count_user(), 1);

        let lib_names: Vec<&str> = ft.iter_library().map(|f| f.name.as_str()).collect();
        assert_eq!(lib_names, vec!["strlen"]);

        let breakdown = ft.library_breakdown();
        assert_eq!(breakdown.get("msvcrt").copied(), Some(1));
    }

    // ── XrefIndex ─────────────────────────────────────────────────────────────

    #[test]
    fn test_xref_index_add_and_query() {
        let mut idx = XrefIndex::new();
        assert!(idx.is_empty());

        idx.add_xref(Xref::new(
            Address::new(0x1000),
            Address::new(0x2000),
            XrefKind::CodeCall,
        ));
        idx.add_xref(Xref::new(
            Address::new(0x1008),
            Address::new(0x2000),
            XrefKind::CodeCall,
        ));
        idx.add_xref(Xref::new(
            Address::new(0x1010),
            Address::new(0x3000),
            XrefKind::DataRead,
        ));

        assert_eq!(idx.len(), 3);

        let from_1000 = idx.xrefs_from(Address::new(0x1000));
        assert_eq!(from_1000.len(), 1);

        let to_2000 = idx.xrefs_to(Address::new(0x2000));
        assert_eq!(to_2000.len(), 2);

        let callers = idx.callers_of(Address::new(0x2000));
        assert_eq!(callers.len(), 2);

        let callees_from_1000 = idx.callees_of(Address::new(0x1000));
        assert_eq!(callees_from_1000.len(), 1);
        assert_eq!(callees_from_1000[0], Address::new(0x2000));
    }

    #[test]
    fn test_xref_deduplication() {
        let mut idx = XrefIndex::new();
        let x = Xref::new(Address::new(0xA), Address::new(0xB), XrefKind::CodeJump);
        idx.add_xref(x.clone());
        idx.add_xref(x);
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn test_xref_remove_from() {
        let mut idx = XrefIndex::new();
        idx.add_xref(Xref::new(
            Address::new(0x10),
            Address::new(0x20),
            XrefKind::DataAddr,
        ));
        idx.add_xref(Xref::new(
            Address::new(0x30),
            Address::new(0x20),
            XrefKind::DataRead,
        ));
        idx.remove_xrefs_from(Address::new(0x10));

        assert_eq!(idx.len(), 1);
        // The incoming index for 0x20 should still have the 0x30 entry.
        assert_eq!(idx.xrefs_to(Address::new(0x20)).len(), 1);
    }

    // ── PatchSet ──────────────────────────────────────────────────────────────

    #[test]
    fn test_patchset_apply_and_unapply() {
        let mut mem = Memory::new();
        mem.add_segment(Segment {
            range: AddressRange::new(Address::new(0), Address::new(0x100)),
            permissions: Permissions::READ | Permissions::WRITE,
            data: vec![0xCC; 0x100],
        });

        let patch = Patch::new(
            Address::new(0x10),
            vec![0xCC, 0xCC, 0xCC],
            vec![0x90, 0x90, 0x90],
        )
        .with_reason("NOP sled");

        let mut ps = PatchSet::new();
        ps.add_patch(patch).unwrap();
        assert_eq!(ps.len(), 1);

        ps.apply_to_memory(&mut mem).unwrap();
        let mut buf = [0u8; 3];
        mem.read(Address::new(0x10), &mut buf).unwrap();
        assert_eq!(buf, [0x90, 0x90, 0x90]);

        ps.unapply_from_memory(&mut mem).unwrap();
        mem.read(Address::new(0x10), &mut buf).unwrap();
        assert_eq!(buf, [0xCC, 0xCC, 0xCC]);
    }

    #[test]
    fn test_patchset_empty_bytes_rejected() {
        let mut ps = PatchSet::new();
        let bad = Patch::new(Address::new(0), vec![0xFF], vec![]);
        assert!(ps.add_patch(bad).is_err());
    }

    #[test]
    fn test_patchset_remove() {
        let mut ps = PatchSet::new();
        ps.add_patch(Patch::new(Address::new(0x50), vec![0xAA], vec![0xBB]))
            .unwrap();
        let removed = ps.remove_patch(Address::new(0x50));
        assert!(removed.is_some());
        assert!(ps.is_empty());
    }

    // ── CommentStore ──────────────────────────────────────────────────────────

    #[test]
    fn test_comment_store() {
        let mut cs = CommentStore::new();
        assert!(cs.is_empty());

        let c = Comment::new("entry point")
            .repeatable()
            .with_author("analyst");
        cs.add_comment(Address::new(0x1000), c);

        assert_eq!(cs.len(), 1);
        let got = cs.get_comment(Address::new(0x1000)).unwrap();
        assert_eq!(got.text, "entry point");
        assert!(got.repeatable);
        assert_eq!(got.author.as_deref(), Some("analyst"));

        cs.update_text(Address::new(0x1000), "updated text");
        assert_eq!(
            cs.get_comment(Address::new(0x1000)).unwrap().text,
            "updated text"
        );

        let removed = cs.remove_comment(Address::new(0x1000));
        assert!(removed.is_some());
        assert!(cs.is_empty());
    }

    #[test]
    fn test_comment_iter() {
        let mut cs = CommentStore::new();
        for i in 0u64..3 {
            cs.add_comment(Address::new(i * 0x10), Comment::new(format!("c{i}")));
        }
        assert_eq!(cs.iter_comments().count(), 3);
    }

    // ── BookmarkSet ───────────────────────────────────────────────────────────

    #[test]
    fn test_bookmark_set_add_remove() {
        let mut bs = BookmarkSet::new();
        assert!(bs.is_empty());

        bs.add_bookmark(
            Bookmark::new(Address::new(0x5000))
                .with_label("start")
                .with_color(0x00FF_0000),
        );
        bs.add_bookmark(Bookmark::new(Address::new(0x5000)).with_label("alt"));

        assert_eq!(bs.len(), 2);
        assert_eq!(bs.get_bookmarks_at(Address::new(0x5000)).len(), 2);

        bs.remove_bookmark(Address::new(0x5000), Some("start"));
        assert_eq!(bs.len(), 1);

        bs.remove_bookmark(Address::new(0x5000), None);
        assert!(bs.is_empty());
    }

    #[test]
    fn test_bookmark_dedup_by_label() {
        let mut bs = BookmarkSet::new();
        bs.add_bookmark(Bookmark::new(Address::new(0xAB)).with_label("lbl"));
        bs.add_bookmark(Bookmark::new(Address::new(0xAB)).with_label("lbl"));
        assert_eq!(bs.len(), 1);
    }

    #[test]
    fn test_bookmark_iter() {
        let mut bs = BookmarkSet::new();
        bs.add_bookmark(Bookmark::new(Address::new(0x1)));
        bs.add_bookmark(Bookmark::new(Address::new(0x2)));
        assert_eq!(bs.iter_bookmarks().count(), 2);
    }

    // ── PluginContext ─────────────────────────────────────────────────────────

    #[test]
    fn test_plugin_context() {
        let mut ctx = PluginContext::new();
        assert!(ctx.is_empty());

        ctx.set("my_plugin.version", b"1.0.0".to_vec());
        assert!(ctx.contains_key("my_plugin.version"));
        assert_eq!(ctx.get("my_plugin.version").unwrap(), b"1.0.0");

        ctx.set_str("my_plugin.mode", "debug");
        assert_eq!(ctx.get_str("my_plugin.mode").unwrap(), "debug");

        assert_eq!(ctx.len(), 2);
        ctx.remove("my_plugin.version");
        assert_eq!(ctx.len(), 1);
        assert!(!ctx.contains_key("my_plugin.version"));
    }

    #[test]
    fn test_plugin_context_iter() {
        let mut ctx = PluginContext::new();
        ctx.set("k1", vec![1]);
        ctx.set("k2", vec![2]);
        ctx.set("k3", vec![3]);
        assert_eq!(ctx.iter().count(), 3);
    }

    // ── KnowledgeGraph ────────────────────────────────────────────────────────

    #[test]
    fn test_knowledge_graph_annotate() {
        let mut kg = KnowledgeGraph::new();
        assert!(kg.is_empty());

        kg.annotate("ai.summary", r#"{"confidence":0.9}"#);
        kg.annotate("analyst.note", "Likely crypto routine");

        assert_eq!(kg.len(), 2);
        assert!(kg.has_annotation("ai.summary"));
        assert_eq!(
            kg.get_annotation("ai.summary").unwrap(),
            r#"{"confidence":0.9}"#
        );

        kg.remove_annotation("analyst.note");
        assert_eq!(kg.len(), 1);
        assert!(!kg.has_annotation("analyst.note"));
    }

    #[test]
    fn test_knowledge_graph_merge() {
        let mut kg1 = KnowledgeGraph::new();
        kg1.annotate("shared", "from_kg1");
        kg1.annotate("only_in_kg1", "value");

        let mut kg2 = KnowledgeGraph::new();
        kg2.annotate("shared", "from_kg2");
        kg2.annotate("only_in_kg2", "value");

        kg1.merge_from(&kg2);
        // "shared" should be overwritten by kg2's value.
        assert_eq!(kg1.get_annotation("shared").unwrap(), "from_kg2");
        assert!(kg1.has_annotation("only_in_kg1"));
        assert!(kg1.has_annotation("only_in_kg2"));
        assert_eq!(kg1.len(), 3);
    }

    #[test]
    fn test_knowledge_graph_iter() {
        let mut kg = KnowledgeGraph::new();
        kg.annotate("a", "1");
        kg.annotate("b", "2");
        assert_eq!(kg.iter_annotations().count(), 2);
    }

    // ── Integration: BinaryView construction ─────────────────────────────────

    #[test]
    fn test_binary_view_fields_accessible() {
        // Verify that the view compiles and all field locks are accessible.
        // We use a DummyArch defined locally for this test only.
        use crate::arch::{
            Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
        };
        use crate::endian::Endian;
        use crate::errors::CoreError as CE;
        use std::sync::Arc;

        #[derive(Debug)]
        struct DummyArch2;
        impl Architecture for DummyArch2 {
            fn name(&self) -> &'static str {
                "dummy2"
            }
            fn pointer_size(&self) -> usize {
                8
            }
            fn endian(&self) -> Endian {
                Endian::Little
            }
            fn disassemble(&self, address: Address, _bytes: &[u8]) -> Result<Instruction, CE> {
                Ok(Instruction {
                    address,
                    size: 1,
                    mnemonic: "nop".into(),
                    operands: String::new(),
                    operand_list: vec![],
                    flags: InstrFlags::NONE,
                    bytes: vec![0x90],
                    comment: None,
                })
            }
            fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
                vec![]
            }
            fn registers(&self) -> Vec<RegisterInfo> {
                vec![]
            }
            fn calling_conventions(&self) -> Vec<CallingConvention> {
                vec![]
            }
        }

        let id = ViewId::from_raw(42);
        let arch = Arc::new(DummyArch2);
        let mem = Memory::new();
        let view = BinaryView::new(
            id,
            "test://dummy".into(),
            arch,
            Endian::Little,
            64,
            vec![],
            mem,
        );

        // Insert a symbol and verify via lock.
        {
            let mut syms = view.symbols.write();
            syms.add_symbol(Symbol::new(
                "_start",
                Address::new(0),
                SymbolKind::Export,
                SymbolSource::Export,
            ));
        }
        {
            let len = view.symbols.read().len();
            assert_eq!(len, 1);
        }

        // Insert a comment.
        {
            let mut cs = view.comments.write();
            cs.add_comment(Address::new(0), Comment::new("entry"));
        }
        {
            let len = view.comments.read().len();
            assert_eq!(len, 1);
        }

        // Annotate the knowledge graph.
        {
            let mut kg = view.graph.write();
            kg.annotate("test.tag", "test_value");
        }
        {
            let _kg = view.graph.read();
        }
    }

    // ── Timestamp ─────────────────────────────────────────────────────────────

    #[test]
    fn test_timestamp_round_trip() {
        let now = Timestamp::now();
        let sys = now.to_system_time();
        let back = Timestamp::from_system_time(sys);
        assert_eq!(now, back);
    }

    // ── PrimitiveKind helpers ─────────────────────────────────────────────────

    #[test]
    fn test_primitive_kind_properties() {
        assert_eq!(PrimitiveKind::U8.byte_size(), 1);
        assert_eq!(PrimitiveKind::U64.byte_size(), 8);
        assert!(PrimitiveKind::I32.is_signed());
        assert!(!PrimitiveKind::U32.is_signed());
        assert!(PrimitiveKind::F64.is_float());
        assert!(!PrimitiveKind::I64.is_float());
    }

    // ── SymbolKind / SymbolSource display ────────────────────────────────────

    #[test]
    fn test_symbol_kind_display() {
        assert_eq!(SymbolKind::Function.to_string(), "Function");
        assert_eq!(SymbolKind::Import.to_string(), "Import");
        assert_eq!(SymbolSource::Pdb.to_string(), "PDB");
        assert_eq!(SymbolSource::AiSuggested.to_string(), "AI");
    }

    // ── XrefKind display ─────────────────────────────────────────────────────

    #[test]
    fn test_xref_kind_display() {
        assert_eq!(XrefKind::CodeCall.to_string(), "Call");
        assert_eq!(XrefKind::DataWrite.to_string(), "DataWrite");
    }
}
