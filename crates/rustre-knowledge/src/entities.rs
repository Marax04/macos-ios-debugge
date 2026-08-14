//! `entities` — Core knowledge-graph entity types.
//!
//! Defines the canonical entity records stored by the knowledge graph:
//! [`Symbol`], [`Function`], [`TypeDef`], [`Comment`], [`Xref`], [`Patch`],
//! [`Bookmark`], [`Trace`], and [`Tag`].
//!
//! All entities are addressable by an [`EntityId`] (UUID) and most carry an
//! [`Address`] (a target-memory virtual address). Records are designed to be
//! serializable, comparable, and cheap to clone.

use std::collections::BTreeMap;
use std::fmt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Primitive aliases
// ---------------------------------------------------------------------------

/// A target-memory virtual address.
pub type Address = u64;

/// A byte length.
pub type ByteLen = u64;

// ---------------------------------------------------------------------------
// EntityId
// ---------------------------------------------------------------------------

/// Stable, unique identifier for any knowledge-graph entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntityId(pub Uuid);

impl EntityId {
    /// Generate a fresh random identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wrap an existing UUID.
    #[must_use]
    pub const fn from_uuid(u: Uuid) -> Self {
        Self(u)
    }

    /// Inner UUID value.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for EntityId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// EntityKind
// ---------------------------------------------------------------------------

/// Discriminant naming the entity table an [`EntityId`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EntityKind {
    /// A [`Symbol`].
    Symbol,
    /// A [`Function`].
    Function,
    /// A [`TypeDef`].
    Type,
    /// A [`Comment`].
    Comment,
    /// An [`Xref`].
    Xref,
    /// A [`Patch`].
    Patch,
    /// A [`Bookmark`].
    Bookmark,
    /// A [`Trace`].
    Trace,
    /// A [`Tag`].
    Tag,
}

impl EntityKind {
    /// Human-readable lowercase name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Symbol => "symbol",
            Self::Function => "function",
            Self::Type => "type",
            Self::Comment => "comment",
            Self::Xref => "xref",
            Self::Patch => "patch",
            Self::Bookmark => "bookmark",
            Self::Trace => "trace",
            Self::Tag => "tag",
        }
    }
}

impl fmt::Display for EntityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// Symbol
// ---------------------------------------------------------------------------

/// Visibility / linkage class for a [`Symbol`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolScope {
    /// Local to the current translation unit.
    Local,
    /// Visible to the entire module.
    Module,
    /// Globally exported.
    Global,
    /// Imported from another module.
    Import,
    /// Exported to other modules.
    Export,
}

/// A named address: variable, label, imported function, etc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    /// Unique identifier.
    pub id: EntityId,
    /// Address this symbol resolves to.
    pub address: Address,
    /// Display name.
    pub name: String,
    /// Optional length in bytes (for data symbols).
    pub size: Option<ByteLen>,
    /// Visibility / linkage.
    pub scope: SymbolScope,
    /// Optional originating module.
    pub module: Option<String>,
}

impl Symbol {
    /// Create a new symbol with a fresh [`EntityId`].
    #[must_use]
    pub fn new(address: Address, name: impl Into<String>, scope: SymbolScope) -> Self {
        Self {
            id: EntityId::new(),
            address,
            name: name.into(),
            size: None,
            scope,
            module: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Function
// ---------------------------------------------------------------------------

/// A recovered function record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Function {
    /// Unique identifier.
    pub id: EntityId,
    /// Entry-point address.
    pub entry: Address,
    /// One past the last byte of the function (exclusive end).
    pub end: Address,
    /// Display name.
    pub name: String,
    /// Optional calling convention identifier (e.g. "stdcall").
    pub calling_convention: Option<String>,
    /// Optional return type token.
    pub return_type: Option<String>,
    /// Whether the function is marked as a thunk.
    pub is_thunk: bool,
    /// Whether the function is known to never return.
    pub no_return: bool,
}

impl Function {
    /// Create a new function with a fresh [`EntityId`].
    #[must_use]
    pub fn new(entry: Address, end: Address, name: impl Into<String>) -> Self {
        Self {
            id: EntityId::new(),
            entry,
            end,
            name: name.into(),
            calling_convention: None,
            return_type: None,
            is_thunk: false,
            no_return: false,
        }
    }

    /// Inclusive size in bytes.
    #[must_use]
    pub const fn size(&self) -> ByteLen {
        self.end.saturating_sub(self.entry)
    }

    /// `true` if `addr` falls within `[entry, end)`.
    #[must_use]
    pub const fn contains(&self, addr: Address) -> bool {
        addr >= self.entry && addr < self.end
    }
}

// ---------------------------------------------------------------------------
// TypeDef
// ---------------------------------------------------------------------------

/// Category of a [`TypeDef`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TypeKind {
    /// A primitive scalar type.
    Primitive,
    /// A C-style struct.
    Struct,
    /// A C-style union.
    Union,
    /// An enumeration.
    Enum,
    /// A pointer to another type.
    Pointer,
    /// An array of another type.
    Array,
    /// A function-pointer signature.
    FunctionPointer,
    /// A typedef alias.
    Typedef,
}

/// A recovered or user-defined type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeDef {
    /// Unique identifier.
    pub id: EntityId,
    /// Type kind.
    pub kind: TypeKind,
    /// Display name.
    pub name: String,
    /// Size in bytes, when known.
    pub size: Option<ByteLen>,
    /// Encoded definition body (e.g. C-like or JSON).
    pub definition: String,
}

impl TypeDef {
    /// Create a new type definition with a fresh [`EntityId`].
    #[must_use]
    pub fn new(kind: TypeKind, name: impl Into<String>, definition: impl Into<String>) -> Self {
        Self {
            id: EntityId::new(),
            kind,
            name: name.into(),
            size: None,
            definition: definition.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Comment
// ---------------------------------------------------------------------------

/// Where a comment is anchored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CommentScope {
    /// Inline at an instruction address.
    Instruction,
    /// On the function as a whole (header / docstring).
    Function,
    /// On a type definition.
    Type,
    /// On a data location.
    Data,
}

/// A user-authored or imported comment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comment {
    /// Unique identifier.
    pub id: EntityId,
    /// Comment anchor.
    pub scope: CommentScope,
    /// Address or owning-entity address.
    pub address: Address,
    /// Author identifier.
    pub author: String,
    /// Comment text.
    pub text: String,
}

impl Comment {
    /// Create a new comment with a fresh [`EntityId`].
    #[must_use]
    pub fn new(
        scope: CommentScope,
        address: Address,
        author: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            id: EntityId::new(),
            scope,
            address,
            author: author.into(),
            text: text.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Xref
// ---------------------------------------------------------------------------

/// Kind of cross-reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum XrefKind {
    /// A direct call.
    Call,
    /// An indirect / computed call.
    CallIndirect,
    /// An unconditional jump.
    Jump,
    /// A conditional jump.
    JumpConditional,
    /// A data read.
    Read,
    /// A data write.
    Write,
    /// An address-of / pointer reference.
    AddressOf,
}

/// A cross-reference from one address to another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Xref {
    /// Unique identifier.
    pub id: EntityId,
    /// Source address.
    pub from: Address,
    /// Destination address.
    pub to: Address,
    /// Reference kind.
    pub kind: XrefKind,
}

impl Xref {
    /// Create a new xref with a fresh [`EntityId`].
    #[must_use]
    pub fn new(from: Address, to: Address, kind: XrefKind) -> Self {
        Self {
            id: EntityId::new(),
            from,
            to,
            kind,
        }
    }
}

// ---------------------------------------------------------------------------
// Patch
// ---------------------------------------------------------------------------

/// A binary patch applied at an address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Patch {
    /// Unique identifier.
    pub id: EntityId,
    /// Target address.
    pub address: Address,
    /// Original bytes (for revert).
    pub original: Vec<u8>,
    /// Patched bytes.
    pub patched: Vec<u8>,
    /// Optional human description.
    pub description: Option<String>,
    /// `true` if the patch is currently applied (vs. staged).
    pub applied: bool,
}

impl Patch {
    /// Create a new patch with a fresh [`EntityId`].
    #[must_use]
    pub fn new(address: Address, original: Vec<u8>, patched: Vec<u8>) -> Self {
        Self {
            id: EntityId::new(),
            address,
            original,
            patched,
            description: None,
            applied: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Bookmark
// ---------------------------------------------------------------------------

/// A user-saved location of interest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bookmark {
    /// Unique identifier.
    pub id: EntityId,
    /// Target address.
    pub address: Address,
    /// Short title.
    pub title: String,
    /// Optional detailed note.
    pub note: Option<String>,
}

impl Bookmark {
    /// Create a new bookmark with a fresh [`EntityId`].
    #[must_use]
    pub fn new(address: Address, title: impl Into<String>) -> Self {
        Self {
            id: EntityId::new(),
            address,
            title: title.into(),
            note: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Trace
// ---------------------------------------------------------------------------

/// A single execution-trace sample (instruction or basic-block hit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trace {
    /// Unique identifier.
    pub id: EntityId,
    /// Address that was executed.
    pub address: Address,
    /// Monotonic timestamp / sequence number.
    pub timestamp: u64,
    /// Owning thread id, if any.
    pub thread_id: Option<u32>,
    /// Optional symbolic context (register snapshot key, etc.).
    pub context: Option<String>,
}

impl Trace {
    /// Create a new trace sample with a fresh [`EntityId`].
    #[must_use]
    pub fn new(address: Address, timestamp: u64) -> Self {
        Self {
            id: EntityId::new(),
            address,
            timestamp,
            thread_id: None,
            context: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tag
// ---------------------------------------------------------------------------

/// A free-form label attached to another entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tag {
    /// Unique identifier.
    pub id: EntityId,
    /// Tagged entity id.
    pub target: EntityId,
    /// Tagged entity kind (denormalised for lookups).
    pub target_kind: EntityKind,
    /// Tag key (e.g. "category").
    pub key: String,
    /// Tag value (e.g. "crypto").
    pub value: String,
}

impl Tag {
    /// Create a new tag with a fresh [`EntityId`].
    #[must_use]
    pub fn new(
        target: EntityId,
        target_kind: EntityKind,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            id: EntityId::new(),
            target,
            target_kind,
            key: key.into(),
            value: value.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// EntitySnapshot
// ---------------------------------------------------------------------------

/// A complete, serialisable snapshot of every entity table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitySnapshot {
    /// All symbols, keyed by id.
    pub symbols: BTreeMap<EntityId, Symbol>,
    /// All functions, keyed by id.
    pub functions: BTreeMap<EntityId, Function>,
    /// All type definitions, keyed by id.
    pub types: BTreeMap<EntityId, TypeDef>,
    /// All comments, keyed by id.
    pub comments: BTreeMap<EntityId, Comment>,
    /// All xrefs, keyed by id.
    pub xrefs: BTreeMap<EntityId, Xref>,
    /// All patches, keyed by id.
    pub patches: BTreeMap<EntityId, Patch>,
    /// All bookmarks, keyed by id.
    pub bookmarks: BTreeMap<EntityId, Bookmark>,
    /// All traces, keyed by id.
    pub traces: BTreeMap<EntityId, Trace>,
    /// All tags, keyed by id.
    pub tags: BTreeMap<EntityId, Tag>,
}

impl EntitySnapshot {
    /// Create an empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total entity count across every table.
    #[must_use]
    pub fn total_entities(&self) -> usize {
        self.symbols.len()
            + self.functions.len()
            + self.types.len()
            + self.comments.len()
            + self.xrefs.len()
            + self.patches.len()
            + self.bookmarks.len()
            + self.traces.len()
            + self.tags.len()
    }

    /// `true` if every table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_entities() == 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_id_unique() {
        let a = EntityId::new();
        let b = EntityId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn function_contains_addr() {
        let f = Function::new(0x1000, 0x1100, "f");
        assert!(f.contains(0x1080));
        assert!(!f.contains(0x1100));
        assert_eq!(f.size(), 0x100);
    }

    #[test]
    fn entity_kind_name() {
        assert_eq!(EntityKind::Symbol.name(), "symbol");
        assert_eq!(EntityKind::Function.name(), "function");
        assert_eq!(EntityKind::Xref.name(), "xref");
    }

    #[test]
    fn snapshot_counts() {
        let mut s = EntitySnapshot::new();
        assert!(s.is_empty());
        let sym = Symbol::new(0x10, "foo", SymbolScope::Global);
        s.symbols.insert(sym.id, sym);
        assert_eq!(s.total_entities(), 1);
        assert!(!s.is_empty());
    }
}
