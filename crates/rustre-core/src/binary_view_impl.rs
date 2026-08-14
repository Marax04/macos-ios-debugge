//! Builder / production binary view with feature-complete sub-stores.
//!
//! This module is the **builder / production** layer for a binary view.  It is
//! intentionally distinct from [`binary_view`], which is the **loader /
//! persistence** layer.  See [`binary_view`] for a comparison table of the
//! two modules.
//!
//! Use **this module** for all analyst-facing code that needs the full API
//! (rename, conflict detection, `BinaryViewBuilder`, etc.).
//!
//! This module extends the lightweight skeleton in [`binary_view`] with
//! production-quality implementations of every sub-system:
//!
//! | Type | Role |
//! |------|------|
//! | [`BinaryUri`] | Typed, scheme-aware binary location |
//! | [`ArchHandle`] | Reference-counted architecture handle |
//! | [`FunctionTable`] | add/remove/rename/list/find_at with dual index |
//! | [`TypeSystem`] | define/lookup/resolve with alias tracking |
//! | [`XrefIndex`] | add/query/remove with bi-directional maps |
//! | [`PatchSet`] | apply/revert/list with conflict detection |
//! | [`CommentStore`] | set/get/list comments by address |
//! | [`BookmarkSet`] | coloured bookmarks keyed by address |
//! | [`BinaryViewBuilder`] | builder for constructing `BinaryView` |

use crate::address::{Address, AddressRange};
use crate::arch::Architecture;
use crate::endian::Endian;
use crate::errors::{CoreError, Result};
use crate::ids::ViewId;
use std::collections::HashMap;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// BinaryUri
// ─────────────────────────────────────────────────────────────────────────────

/// A scheme-aware URI that identifies a binary's location.
///
/// Examples:
/// - `file:///path/to/binary.exe`
/// - `process://1234/notepad.exe`
/// - `remote://host:4444/target`
/// - `embedded://parent.bin/offset/0x4000`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BinaryUri {
    /// Full URI string.
    pub uri: String,
    /// Parsed scheme (everything before `://`).
    pub scheme: String,
    /// Path component (everything after `://`).
    pub path: String,
}

impl BinaryUri {
    /// Parse a URI string.
    ///
    /// If no scheme is present the whole string is treated as a file path and
    /// the scheme `"file"` is assumed.
    pub fn parse(uri: impl Into<String>) -> Self {
        let uri = uri.into();
        if let Some(pos) = uri.find("://") {
            let scheme = uri[..pos].to_lowercase();
            let path = uri[pos + 3..].to_owned();
            Self { uri, scheme, path }
        } else {
            Self {
                scheme: "file".to_owned(),
                path: uri.clone(),
                uri,
            }
        }
    }

    /// Convenience: create a `file://` URI from a filesystem path.
    pub fn file(path: impl Into<String>) -> Self {
        let path = path.into();
        Self {
            uri: format!("file://{path}"),
            scheme: "file".to_owned(),
            path,
        }
    }

    /// Convenience: create a `process://` URI from a PID.
    pub fn process(pid: u32, name: impl Into<String>) -> Self {
        let name = name.into();
        let uri = format!("process://{pid}/{name}");
        Self {
            scheme: "process".to_owned(),
            path: format!("{pid}/{name}"),
            uri,
        }
    }

    /// Return `true` if the URI refers to a local file.
    #[must_use]
    pub fn is_file(&self) -> bool {
        self.scheme == "file"
    }

    /// Return `true` if the URI refers to a live process.
    #[must_use]
    pub fn is_process(&self) -> bool {
        self.scheme == "process"
    }

    /// Return the URI as a plain string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.uri
    }
}

impl std::fmt::Display for BinaryUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.uri)
    }
}

impl From<&str> for BinaryUri {
    fn from(s: &str) -> Self {
        Self::parse(s)
    }
}

impl From<String> for BinaryUri {
    fn from(s: String) -> Self {
        Self::parse(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArchHandle
// ─────────────────────────────────────────────────────────────────────────────

/// A reference-counted, named handle to an [`Architecture`] implementation.
///
/// `ArchHandle` wraps `Arc<dyn Architecture>` and provides ergonomic accessors
/// and display formatting so callers need not dereference the trait object.
#[derive(Clone)]
pub struct ArchHandle {
    inner: Arc<dyn Architecture>,
}

impl ArchHandle {
    /// Wrap an existing `Arc<dyn Architecture>`.
    #[must_use]
    pub fn new(arch: Arc<dyn Architecture>) -> Self {
        Self { inner: arch }
    }

    /// Access the underlying architecture.
    #[must_use]
    pub fn arch(&self) -> &dyn Architecture {
        self.inner.as_ref()
    }

    /// Return the architecture name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Pointer width in bytes.
    #[must_use]
    pub fn pointer_size(&self) -> usize {
        self.inner.pointer_size()
    }

    /// Return the endianness.
    #[must_use]
    pub fn endian(&self) -> Endian {
        self.inner.endian()
    }

    /// Clone the inner `Arc`.
    #[must_use]
    pub fn arc(&self) -> Arc<dyn Architecture> {
        Arc::clone(&self.inner)
    }
}

impl std::fmt::Debug for ArchHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ArchHandle({})", self.inner.name())
    }
}

impl std::fmt::Display for ArchHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionTable
// ─────────────────────────────────────────────────────────────────────────────

/// Attributes of a function definition in the view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionEntry {
    /// Entry-point virtual address.
    pub address: Address,
    /// Exclusive end address, if known.
    pub end_address: Option<Address>,
    /// Human-readable name.
    pub name: String,
    /// Optional type prototype string.
    pub prototype: Option<String>,
    /// Optional calling convention name.
    pub calling_convention: Option<String>,
    /// Whether the function is a thunk/trampoline.
    pub is_thunk: bool,
    /// Whether the function was imported from a library.
    pub is_library: bool,
}

impl FunctionEntry {
    /// Create a minimal entry.
    #[must_use]
    pub fn new(address: Address, name: impl Into<String>) -> Self {
        Self {
            address,
            end_address: None,
            name: name.into(),
            prototype: None,
            calling_convention: None,
            is_thunk: false,
            is_library: false,
        }
    }

    /// Set the exclusive end address.
    #[must_use]
    pub const fn with_end(mut self, end: Address) -> Self {
        self.end_address = Some(end);
        self
    }

    /// Set the prototype string.
    #[must_use]
    pub fn with_prototype(mut self, p: impl Into<String>) -> Self {
        self.prototype = Some(p.into());
        self
    }

    /// Return `true` if `addr` falls within `[address, end_address)`.
    #[must_use]
    pub fn contains_addr(&self, addr: Address) -> bool {
        if addr < self.address {
            return false;
        }
        self.end_address.is_some_and(|end| addr < end)
    }

    /// Byte size of the function body (requires `end_address`).
    #[must_use]
    pub fn byte_size(&self) -> Option<u64> {
        self.end_address
            .map(|end| end.as_u64().saturating_sub(self.address.as_u64()))
    }
}

/// Address-indexed, name-indexed function registry for a `BinaryView`.
///
/// Maintains two maps for O(1) lookups by address and `O(n_name)` lookups by
/// name.  Names are not required to be unique across addresses.
#[derive(Debug, Default)]
pub struct FunctionTable {
    by_addr: HashMap<u64, FunctionEntry>,
    by_name: HashMap<String, Vec<u64>>,
}

impl FunctionTable {
    /// Create an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a function entry.
    pub fn add(&mut self, entry: FunctionEntry) {
        let addr = entry.address.as_u64();
        // Remove old name-index entry if the function already existed.
        if let Some(old) = self.by_addr.get(&addr)
            && let Some(addrs) = self.by_name.get_mut(&old.name)
        {
            addrs.retain(|a| *a != addr);
            if addrs.is_empty() {
                self.by_name.remove(&old.name);
            }
        }
        let name_slot = self.by_name.entry(entry.name.clone()).or_default();
        if !name_slot.contains(&addr) {
            name_slot.push(addr);
        }
        self.by_addr.insert(addr, entry);
    }

    /// Remove the function starting at `addr`. Returns the removed entry.
    pub fn remove(&mut self, addr: Address) -> Option<FunctionEntry> {
        let entry = self.by_addr.remove(&addr.as_u64())?;
        if let Some(addrs) = self.by_name.get_mut(&entry.name) {
            addrs.retain(|a| *a != addr.as_u64());
            if addrs.is_empty() {
                self.by_name.remove(&entry.name);
            }
        }
        Some(entry)
    }

    /// Rename the function at `addr` to `new_name`.
    ///
    /// Returns `Err` if no function is registered at that address.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn rename(&mut self, addr: Address, new_name: impl Into<String>) -> Result<()> {
        let new_name = new_name.into();
        let raw = addr.as_u64();
        let entry = self
            .by_addr
            .get_mut(&raw)
            .ok_or_else(|| CoreError::InvalidAddress {
                message: format!("no function at {addr:#x}"),
            })?;

        // Remove from old name index.
        if let Some(addrs) = self.by_name.get_mut(&entry.name) {
            addrs.retain(|a| *a != raw);
            if addrs.is_empty() {
                self.by_name.remove(&entry.name.clone());
            }
        }
        entry.name.clone_from(&new_name);
        self.by_name.entry(new_name).or_default().push(raw);
        Ok(())
    }

    /// Return the function starting at exactly `addr`.
    #[must_use]
    pub fn find_at(&self, addr: Address) -> Option<&FunctionEntry> {
        self.by_addr.get(&addr.as_u64())
    }

    /// Return all functions whose name matches `name`.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Vec<&FunctionEntry> {
        self.by_name
            .get(name)
            .map(|addrs| addrs.iter().filter_map(|a| self.by_addr.get(a)).collect())
            .unwrap_or_default()
    }

    /// Find the function whose body contains `addr`.
    #[must_use]
    pub fn find_containing(&self, addr: Address) -> Option<&FunctionEntry> {
        self.by_addr.values().find(|e| e.contains_addr(addr))
    }

    /// Return all functions in `range` (by start address).
    #[must_use]
    pub fn list_in_range(&self, range: AddressRange) -> Vec<&FunctionEntry> {
        self.by_addr
            .values()
            .filter(|e| range.contains(e.address))
            .collect()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &FunctionEntry> {
        self.by_addr.values()
    }

    /// Number of registered functions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_addr.len()
    }

    /// Return `true` if no functions are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_addr.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.by_addr.clear();
        self.by_name.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeSystem
// ─────────────────────────────────────────────────────────────────────────────

/// A named, versioned type definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeDefinition {
    /// Canonical name of this type.
    pub name: String,
    /// Size in bytes, if statically known.
    pub size: Option<usize>,
    /// Source of the definition.
    pub source: TypeSource,
    /// Optional human-readable comment.
    pub comment: Option<String>,
    /// Alias target (the canonical name of the type this aliases).
    pub alias_of: Option<String>,
}

/// Where a type definition originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeSource {
    /// Manually defined by the analyst.
    User,
    /// Imported from PDB debug information.
    Pdb,
    /// Imported from DWARF debug information.
    Dwarf,
    /// Inferred by an analysis pass.
    Inferred,
    /// Built-in / primitive.
    BuiltIn,
}

impl TypeDefinition {
    /// Create a minimal user-defined type.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            size: None,
            source: TypeSource::User,
            comment: None,
            alias_of: None,
        }
    }

    /// Attach a comment.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Set the byte size.
    #[must_use]
    pub const fn with_size(mut self, size: usize) -> Self {
        self.size = Some(size);
        self
    }

    /// Set the source.
    #[must_use]
    pub const fn with_source(mut self, source: TypeSource) -> Self {
        self.source = source;
        self
    }

    /// Make this definition an alias of another named type.
    #[must_use]
    pub fn alias_of(mut self, target: impl Into<String>) -> Self {
        self.alias_of = Some(target.into());
        self
    }

    /// Return `true` if this entry is a type alias.
    #[must_use]
    pub const fn is_alias(&self) -> bool {
        self.alias_of.is_some()
    }
}

/// Central registry of named type definitions for a binary view.
///
/// Supports define/lookup/resolve (alias following) and iteration.
#[derive(Debug, Default)]
pub struct TypeSystem {
    types: HashMap<String, TypeDefinition>,
}

impl TypeSystem {
    /// Create an empty type system.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or replace a type definition.
    pub fn define(&mut self, def: TypeDefinition) {
        self.types.insert(def.name.clone(), def);
    }

    /// Look up a type by its canonical name.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<&TypeDefinition> {
        self.types.get(name)
    }

    /// Resolve a type name, following aliases up to `max_depth` levels.
    ///
    /// Returns the final non-alias definition, or `None` if a link in the chain
    /// is missing.  Returns `Err` if the alias chain is longer than `max_depth`
    /// (possible cycle).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    ///
    /// # Panics
    ///
    /// Panics if an internal invariant is violated.
    pub fn resolve<'a>(
        &'a self,
        name: &str,
        max_depth: usize,
    ) -> std::result::Result<Option<&'a TypeDefinition>, CoreError> {
        let mut current = name;
        for _ in 0..max_depth {
            match self.types.get(current) {
                None => return Ok(None),
                Some(def) if def.alias_of.is_none() => return Ok(Some(def)),
                Some(def) => current = def.alias_of.as_deref().unwrap(),
            }
        }
        Err(CoreError::analysis(format!(
            "alias chain for '{name}' exceeds depth {max_depth}"
        )))
    }

    /// Remove a type by name. Returns the removed entry.
    pub fn remove(&mut self, name: &str) -> Option<TypeDefinition> {
        self.types.remove(name)
    }

    /// Iterate over all type definitions.
    pub fn iter(&self) -> impl Iterator<Item = &TypeDefinition> {
        self.types.values()
    }

    /// Number of registered types.
    #[must_use]
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Return `true` if no types are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Return all type names (sorted for determinism).
    #[must_use]
    pub fn all_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.types.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Return all types from the given `source`.
    #[must_use]
    pub fn by_source(&self, source: TypeSource) -> Vec<&TypeDefinition> {
        self.types.values().filter(|d| d.source == source).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XrefIndex
// ─────────────────────────────────────────────────────────────────────────────

/// Semantic category of a cross-reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XrefKind {
    /// A `call` instruction (direct or indirect).
    Call,
    /// A `jmp` / conditional branch.
    Jump,
    /// A data read (load from address).
    DataRead,
    /// A data write (store to address).
    DataWrite,
    /// An address-of reference (`lea` / pointer).
    DataAddr,
}

impl std::fmt::Display for XrefKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Call => write!(f, "call"),
            Self::Jump => write!(f, "jump"),
            Self::DataRead => write!(f, "data-read"),
            Self::DataWrite => write!(f, "data-write"),
            Self::DataAddr => write!(f, "data-addr"),
        }
    }
}

/// A single directed cross-reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct XrefEntry {
    /// Address of the referencing instruction / data.
    pub from: Address,
    /// Address being referenced.
    pub to: Address,
    /// Semantic category.
    pub kind: XrefKind,
    /// `true` if the reference target was statically determined (not indirect).
    pub certain: bool,
}

impl XrefEntry {
    /// Create a certain (statically known) xref.
    #[must_use]
    pub const fn certain(from: Address, to: Address, kind: XrefKind) -> Self {
        Self {
            from,
            to,
            kind,
            certain: true,
        }
    }

    /// Create an uncertain (heuristic / indirect) xref.
    #[must_use]
    pub const fn uncertain(from: Address, to: Address, kind: XrefKind) -> Self {
        Self {
            from,
            to,
            kind,
            certain: false,
        }
    }
}

/// Bidirectional cross-reference index.
#[derive(Debug, Default)]
pub struct XrefIndex {
    /// `from_addr → [xref]`
    outgoing: HashMap<u64, Vec<XrefEntry>>,
    /// `to_addr → [xref]`
    incoming: HashMap<u64, Vec<XrefEntry>>,
}

impl XrefIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a cross-reference.  Duplicate entries are silently ignored.
    pub fn add(&mut self, xref: XrefEntry) {
        let from = xref.from.as_u64();
        let to = xref.to.as_u64();

        let out = self.outgoing.entry(from).or_default();
        if !out.contains(&xref) {
            out.push(xref.clone());
        }
        let inc = self.incoming.entry(to).or_default();
        if !inc.contains(&xref) {
            inc.push(xref);
        }
    }

    /// Return all xrefs originating at `from`.
    #[must_use]
    pub fn from(&self, from: Address) -> &[XrefEntry] {
        self.outgoing
            .get(&from.as_u64())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Return all xrefs targeting `to`.
    #[must_use]
    pub fn to(&self, to: Address) -> &[XrefEntry] {
        self.incoming
            .get(&to.as_u64())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Return addresses of all callers of `callee`.
    #[must_use]
    pub fn callers_of(&self, callee: Address) -> Vec<Address> {
        self.to(callee)
            .iter()
            .filter(|x| x.kind == XrefKind::Call)
            .map(|x| x.from)
            .collect()
    }

    /// Return addresses of all callees invoked by `caller`.
    #[must_use]
    pub fn callees_of(&self, caller: Address) -> Vec<Address> {
        self.from(caller)
            .iter()
            .filter(|x| x.kind == XrefKind::Call)
            .map(|x| x.to)
            .collect()
    }

    /// Remove all xrefs originating at `from`.
    pub fn remove_from(&mut self, from: Address) {
        if let Some(xrefs) = self.outgoing.remove(&from.as_u64()) {
            for x in &xrefs {
                if let Some(inc) = self.incoming.get_mut(&x.to.as_u64()) {
                    inc.retain(|e| e.from != from);
                    if inc.is_empty() {
                        self.incoming.remove(&x.to.as_u64());
                    }
                }
            }
        }
    }

    /// Remove all xrefs targeting `to`.
    pub fn remove_to(&mut self, to: Address) {
        if let Some(xrefs) = self.incoming.remove(&to.as_u64()) {
            for x in &xrefs {
                if let Some(out) = self.outgoing.get_mut(&x.from.as_u64()) {
                    out.retain(|e| e.to != to);
                    if out.is_empty() {
                        self.outgoing.remove(&x.from.as_u64());
                    }
                }
            }
        }
    }

    /// Total number of recorded xrefs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.outgoing.values().map(Vec::len).sum()
    }

    /// Return `true` if no xrefs are recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over all xrefs.
    pub fn iter(&self) -> impl Iterator<Item = &XrefEntry> {
        self.outgoing.values().flat_map(|v| v.iter())
    }

    /// Return only certain xrefs.
    #[must_use]
    pub fn certain_xrefs(&self) -> Vec<&XrefEntry> {
        self.iter().filter(|x| x.certain).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchSet
// ─────────────────────────────────────────────────────────────────────────────

/// A single binary patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchEntry {
    /// Start address of the patched region.
    pub address: u64,
    /// Bytes present before the patch was applied.
    pub original: Vec<u8>,
    /// Replacement bytes.
    pub patched: Vec<u8>,
    /// Human-readable annotation.
    pub annotation: Option<String>,
    /// Whether the patch is currently applied to the memory image.
    pub applied: bool,
}

impl PatchEntry {
    /// Create a new, unapplied patch.
    #[must_use]
    pub const fn new(address: u64, original: Vec<u8>, patched: Vec<u8>) -> Self {
        Self {
            address,
            original,
            patched,
            annotation: None,
            applied: false,
        }
    }

    /// Attach an annotation string.
    #[must_use]
    pub fn with_annotation(mut self, ann: impl Into<String>) -> Self {
        self.annotation = Some(ann.into());
        self
    }

    /// Byte length of the patch (size of the patched region).
    #[must_use]
    pub fn len(&self) -> usize {
        self.patched.len().max(self.original.len())
    }

    /// Return `true` if the patch covers zero bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Error type for patch conflicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchConflict {
    /// Address of the conflicting region.
    pub address: u64,
    /// Name or description of the conflicting patch.
    pub conflict_with: String,
}

impl std::fmt::Display for PatchConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "patch conflict at {:#x} with '{}'",
            self.address, self.conflict_with
        )
    }
}

/// Ordered collection of binary patches with apply/revert semantics.
///
/// Patches are keyed by start address.  Overlapping patches are rejected with
/// a [`PatchConflict`] error.
#[derive(Debug, Default)]
pub struct PatchSet {
    patches: HashMap<u64, PatchEntry>,
}

impl PatchSet {
    /// Create an empty patch set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a patch.
    ///
    /// # Errors
    /// Returns `Err(PatchConflict)` if the patch byte-range overlaps with an
    /// existing patch.
    pub fn apply(&mut self, patch: PatchEntry) -> std::result::Result<(), PatchConflict> {
        let start = patch.address;
        // Saturate to u64::MAX on overflow so the range check below is conservative.
        let end = start.saturating_add(patch.len() as u64);
        for (addr, existing) in &self.patches {
            let ex_start = *addr;
            let ex_end = ex_start.saturating_add(existing.len() as u64);
            if start < ex_end && end > ex_start {
                return Err(PatchConflict {
                    address: start,
                    conflict_with: existing
                        .annotation
                        .clone()
                        .unwrap_or_else(|| format!("{ex_start:#x}")),
                });
            }
        }
        self.patches.insert(start, patch);
        Ok(())
    }

    /// Force-insert a patch, replacing any overlapping existing patch.
    pub fn force_apply(&mut self, patch: PatchEntry) {
        let start = patch.address;
        // Saturate to u64::MAX on overflow so the range check below is conservative.
        let end = start.saturating_add(patch.len() as u64);
        self.patches.retain(|&addr, existing| {
            let ex_end = addr.saturating_add(existing.len() as u64);
            !(start < ex_end && end > addr)
        });
        self.patches.insert(start, patch);
    }

    /// Revert (remove) the patch at `address`. Returns the removed entry.
    pub fn revert(&mut self, address: u64) -> Option<PatchEntry> {
        self.patches.remove(&address)
    }

    /// Return the patch at `address`, if any.
    #[must_use]
    pub fn get(&self, address: u64) -> Option<&PatchEntry> {
        self.patches.get(&address)
    }

    /// Iterate over all patches in address order.
    #[must_use]
    pub fn list(&self) -> Vec<&PatchEntry> {
        let mut patches: Vec<&PatchEntry> = self.patches.values().collect();
        patches.sort_by_key(|p| p.address);
        patches
    }

    /// Number of registered patches.
    #[must_use]
    pub fn len(&self) -> usize {
        self.patches.len()
    }

    /// Return `true` if no patches are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    /// Clear all patches.
    pub fn clear(&mut self) {
        self.patches.clear();
    }

    /// Export as a binary diff: a sequence of `(address, original, patched)` tuples.
    #[must_use]
    pub fn export_diff(&self) -> Vec<(u64, Vec<u8>, Vec<u8>)> {
        let mut result: Vec<(u64, Vec<u8>, Vec<u8>)> = self
            .patches
            .values()
            .map(|p| (p.address, p.original.clone(), p.patched.clone()))
            .collect();
        result.sort_by_key(|(addr, _, _)| *addr);
        result
    }

    /// Apply a patch byte range to a raw byte slice in-place.
    ///
    /// `buf_base` is the virtual address of `buf[0]`.
    pub fn apply_to_buf(&self, buf: &mut [u8], buf_base: u64) {
        let Some(buf_end) = buf_base.checked_add(buf.len() as u64) else { return };
        for patch in self.patches.values() {
            let p_start = patch.address;
            let Some(p_end) = p_start.checked_add(patch.patched.len() as u64) else { continue };
            if p_end <= buf_base || p_start >= buf_end {
                continue;
            }
            let copy_start = p_start.max(buf_base);
            let copy_end = p_end.min(buf_end);
            // These subtractions are bounded by the range checks above, but
            // usize::try_from can only fail on 32-bit targets with very large
            // addresses. Skip rather than panic.
            let (Ok(src_off), Ok(dst_off), Ok(len)) = (
                usize::try_from(copy_start - p_start),
                usize::try_from(copy_start - buf_base),
                usize::try_from(copy_end - copy_start),
            ) else {
                continue;
            };
            if let (Some(dst_end), Some(src_end)) =
                (dst_off.checked_add(len), src_off.checked_add(len))
                && dst_end <= buf.len() && src_end <= patch.patched.len() {
                    buf[dst_off..dst_end]
                        .copy_from_slice(&patch.patched[src_off..src_end]);
                }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CommentStore
// ─────────────────────────────────────────────────────────────────────────────

/// A comment attached to a virtual address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentEntry {
    /// The comment text.
    pub text: String,
    /// Optional author identifier.
    pub author: Option<String>,
    /// Whether this is a "repeatable" comment (shown at all referencing sites).
    pub repeatable: bool,
}

impl CommentEntry {
    /// Create a plain, non-repeatable comment.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            author: None,
            repeatable: false,
        }
    }

    /// Make this comment repeatable.
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

/// Unique identifier for a stored comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommentId(u64);

/// Address-indexed comment store.
#[derive(Debug, Default)]
pub struct CommentStore {
    /// `id → (address, entry)`.
    entries: HashMap<CommentId, (u64, CommentEntry)>,
    /// `address → [id]` for fast per-address lookup.
    by_addr: HashMap<u64, Vec<CommentId>>,
    /// Monotonic counter for ID generation.
    next_id: u64,
}

impl CommentStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a comment at `address`. Returns the assigned `CommentId`.
    pub fn set(&mut self, address: u64, entry: CommentEntry) -> CommentId {
        let id = CommentId(self.next_id);
        self.next_id += 1;
        self.by_addr.entry(address).or_default().push(id);
        self.entries.insert(id, (address, entry));
        id
    }

    /// Convenience: add a plain text comment.
    pub fn set_text(&mut self, address: u64, text: impl Into<String>) -> CommentId {
        self.set(address, CommentEntry::new(text))
    }

    /// Return all `(CommentId, entry)` pairs at `address`.
    #[must_use]
    pub fn get(&self, address: u64) -> Vec<(CommentId, &CommentEntry)> {
        self.by_addr
            .get(&address)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.entries.get(id).map(|(_, e)| (*id, e)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return the comment entry for a specific `CommentId`.
    #[must_use]
    pub fn get_by_id(&self, id: CommentId) -> Option<(u64, &CommentEntry)> {
        self.entries.get(&id).map(|(a, e)| (*a, e))
    }

    /// Remove the comment with `id`. Returns `true` if it was present.
    pub fn remove(&mut self, id: CommentId) -> bool {
        if let Some((addr, _)) = self.entries.remove(&id) {
            if let Some(ids) = self.by_addr.get_mut(&addr) {
                ids.retain(|i| *i != id);
                if ids.is_empty() {
                    self.by_addr.remove(&addr);
                }
            }
            true
        } else {
            false
        }
    }

    /// Remove all comments at `address`.
    pub fn remove_all_at(&mut self, address: u64) {
        if let Some(ids) = self.by_addr.remove(&address) {
            for id in ids {
                self.entries.remove(&id);
            }
        }
    }

    /// Iterate over all `(address, CommentId, entry)` triples.
    pub fn list(&self) -> impl Iterator<Item = (u64, CommentId, &CommentEntry)> {
        self.entries
            .iter()
            .map(|(id, (addr, entry))| (*addr, *id, entry))
    }

    /// Total number of stored comments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if no comments are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BookmarkSet
// ─────────────────────────────────────────────────────────────────────────────

/// Colour for a bookmark annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct BookmarkColor(pub u32); // ARGB packed

impl BookmarkColor {
    /// Red bookmark.
    pub const RED: Self = Self(0xFF_FF_00_00);
    /// Green bookmark.
    pub const GREEN: Self = Self(0xFF_00_FF_00);
    /// Blue bookmark.
    pub const BLUE: Self = Self(0xFF_00_00_FF);
    /// Yellow bookmark.
    pub const YELLOW: Self = Self(0xFF_FF_FF_00);
    /// Default (no color — transparent).
    pub const NONE: Self = Self(0);
}

/// Unique identifier for a bookmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BookmarkId(u64);

/// A named, coloured bookmark pinned to a virtual address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookmarkEntry {
    /// The bookmarked virtual address.
    pub address: u64,
    /// Human-readable label.
    pub label: String,
    /// ARGB colour.
    pub color: BookmarkColor,
}

impl BookmarkEntry {
    /// Create a plain bookmark with default color.
    #[must_use]
    pub fn new(address: u64, label: impl Into<String>) -> Self {
        Self {
            address,
            label: label.into(),
            color: BookmarkColor::NONE,
        }
    }

    /// Set the bookmark color.
    #[must_use]
    pub const fn with_color(mut self, color: BookmarkColor) -> Self {
        self.color = color;
        self
    }
}

/// Indexed collection of bookmarks.
#[derive(Debug, Default)]
pub struct BookmarkSet {
    entries: HashMap<BookmarkId, BookmarkEntry>,
    by_addr: HashMap<u64, Vec<BookmarkId>>,
    next_id: u64,
}

impl BookmarkSet {
    /// Create an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a bookmark. Returns the assigned `BookmarkId`.
    pub fn insert(&mut self, entry: BookmarkEntry) -> BookmarkId {
        let id = BookmarkId(self.next_id);
        self.next_id += 1;
        self.by_addr.entry(entry.address).or_default().push(id);
        self.entries.insert(id, entry);
        id
    }

    /// Remove a bookmark by `id`. Returns `true` if it was present.
    pub fn remove(&mut self, id: BookmarkId) -> bool {
        if let Some(entry) = self.entries.remove(&id) {
            if let Some(ids) = self.by_addr.get_mut(&entry.address) {
                ids.retain(|i| *i != id);
                if ids.is_empty() {
                    self.by_addr.remove(&entry.address);
                }
            }
            true
        } else {
            false
        }
    }

    /// Return all `(BookmarkId, entry)` pairs at `address`.
    #[must_use]
    pub fn at(&self, address: u64) -> Vec<(BookmarkId, &BookmarkEntry)> {
        self.by_addr
            .get(&address)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.entries.get(id).map(|e| (*id, e)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Look up a bookmark by `id`.
    #[must_use]
    pub fn get(&self, id: BookmarkId) -> Option<&BookmarkEntry> {
        self.entries.get(&id)
    }

    /// Iterate over all bookmarks.
    pub fn iter(&self) -> impl Iterator<Item = (BookmarkId, &BookmarkEntry)> {
        self.entries.iter().map(|(&id, entry)| (id, entry))
    }

    /// Total number of bookmarks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if no bookmarks are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BinaryViewBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Builder for constructing a fully initialised `BinaryViewFull`.
///
/// `BinaryViewFull` is a richer view type defined alongside the builder that
/// bundles all sub-systems together.
#[derive(Debug, Default)]
pub struct BinaryViewBuilder {
    id: Option<ViewId>,
    uri: Option<BinaryUri>,
    arch: Option<Arc<dyn Architecture>>,
    endian: Option<Endian>,
    bits: Option<u32>,
    entry_points: Vec<Address>,
}

impl BinaryViewBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the view ID.
    #[must_use]
    pub const fn id(mut self, id: ViewId) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the URI.
    #[must_use]
    pub fn uri(mut self, uri: impl Into<BinaryUri>) -> Self {
        self.uri = Some(uri.into());
        self
    }

    /// Set the architecture.
    #[must_use]
    pub fn arch(mut self, arch: Arc<dyn Architecture>) -> Self {
        self.arch = Some(arch);
        self
    }

    /// Set the endianness.
    #[must_use]
    pub const fn endian(mut self, endian: Endian) -> Self {
        self.endian = Some(endian);
        self
    }

    /// Set the pointer width in bits.
    #[must_use]
    pub const fn bits(mut self, bits: u32) -> Self {
        self.bits = Some(bits);
        self
    }

    /// Add an entry point address.
    #[must_use]
    pub fn entry_point(mut self, addr: Address) -> Self {
        self.entry_points.push(addr);
        self
    }

    /// Build a `BinaryViewFull`.
    ///
    /// # Errors
    /// Returns `Err` if required fields (id, uri, arch) are missing.
    pub fn build(self) -> Result<BinaryViewFull> {
        let id = self
            .id
            .ok_or_else(|| CoreError::invalid_input("BinaryViewBuilder: id is required"))?;
        let uri = self
            .uri
            .ok_or_else(|| CoreError::invalid_input("BinaryViewBuilder: uri is required"))?;
        let arch = self
            .arch
            .ok_or_else(|| CoreError::invalid_input("BinaryViewBuilder: arch is required"))?;
        let endian = self.endian.unwrap_or(Endian::Little);
        let bits = self.bits.unwrap_or(64);

        Ok(BinaryViewFull {
            id,
            uri,
            arch: ArchHandle::new(arch),
            endian,
            bits,
            entry_points: self.entry_points,
            functions: FunctionTable::new(),
            types: TypeSystem::new(),
            xrefs: XrefIndex::new(),
            patches: PatchSet::new(),
            comments: CommentStore::new(),
            bookmarks: BookmarkSet::new(),
        })
    }
}

/// A fully-featured binary view that owns all analysis sub-systems.
#[derive(Debug)]
pub struct BinaryViewFull {
    /// View identifier.
    pub id: ViewId,
    /// URI of the binary.
    pub uri: BinaryUri,
    /// Architecture handle.
    pub arch: ArchHandle,
    /// Byte order.
    pub endian: Endian,
    /// Pointer width in bits.
    pub bits: u32,
    /// Known entry point addresses.
    pub entry_points: Vec<Address>,
    /// Function table.
    pub functions: FunctionTable,
    /// Type system.
    pub types: TypeSystem,
    /// Cross-reference index.
    pub xrefs: XrefIndex,
    /// Patch set.
    pub patches: PatchSet,
    /// Comment store.
    pub comments: CommentStore,
    /// Bookmark set.
    pub bookmarks: BookmarkSet,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::{
        Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
    };
    use crate::errors::CoreError as CE;
    use crate::ids::ViewId;

    // ── Stub architecture ─────────────────────────────────────────────────────

    #[derive(Debug)]
    struct DummyArch;

    impl Architecture for DummyArch {
        fn name(&self) -> &'static str {
            "stub"
        }
        fn pointer_size(&self) -> usize {
            8
        }
        fn endian(&self) -> Endian {
            Endian::Little
        }
        fn disassemble(
            &self,
            address: Address,
            _bytes: &[u8],
        ) -> std::result::Result<Instruction, CE> {
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
        fn get_branches(&self, _: &Instruction) -> Vec<BranchInfo> {
            vec![]
        }
        fn registers(&self) -> Vec<RegisterInfo> {
            vec![]
        }
        fn calling_conventions(&self) -> Vec<CallingConvention> {
            vec![]
        }
    }

    // ── BinaryUri ─────────────────────────────────────────────────────────────

    #[test]
    fn binary_uri_parse_with_scheme() {
        let u = BinaryUri::parse("file:///tmp/foo.exe");
        assert_eq!(u.scheme, "file");
        assert_eq!(u.path, "/tmp/foo.exe");
        assert!(u.is_file());
    }

    #[test]
    fn binary_uri_parse_no_scheme_treated_as_file() {
        let u = BinaryUri::parse("/etc/passwd");
        assert_eq!(u.scheme, "file");
        assert!(u.is_file());
    }

    #[test]
    fn binary_uri_process_scheme() {
        let u = BinaryUri::process(1234, "notepad.exe");
        assert!(u.is_process());
        assert!(u.uri.contains("1234"));
    }

    #[test]
    fn binary_uri_display() {
        let u = BinaryUri::file("/usr/bin/ls");
        assert_eq!(u.to_string(), "file:///usr/bin/ls");
    }

    #[test]
    fn binary_uri_from_string() {
        let u: BinaryUri = "process://99/target".into();
        assert_eq!(u.scheme, "process");
    }

    // ── ArchHandle ────────────────────────────────────────────────────────────

    #[test]
    fn arch_handle_basic() {
        let h = ArchHandle::new(Arc::new(DummyArch));
        assert_eq!(h.name(), "stub");
        assert_eq!(h.pointer_size(), 8);
        assert_eq!(h.endian(), Endian::Little);
    }

    #[test]
    fn arch_handle_arc_clone() {
        let h = ArchHandle::new(Arc::new(DummyArch));
        let arc = h.arc();
        assert_eq!(arc.name(), "stub");
    }

    #[test]
    fn arch_handle_display() {
        let h = ArchHandle::new(Arc::new(DummyArch));
        assert_eq!(format!("{h}"), "stub");
    }

    // ── FunctionTable ─────────────────────────────────────────────────────────

    #[test]
    fn function_table_add_and_find_at() {
        let mut ft = FunctionTable::new();
        ft.add(FunctionEntry::new(Address::new(0x1000), "main").with_end(Address::new(0x1100)));
        assert_eq!(ft.len(), 1);
        assert_eq!(ft.find_at(Address::new(0x1000)).unwrap().name, "main");
    }

    #[test]
    fn function_table_find_by_name() {
        let mut ft = FunctionTable::new();
        ft.add(FunctionEntry::new(Address::new(0x100), "init"));
        ft.add(FunctionEntry::new(Address::new(0x200), "init"));
        assert_eq!(ft.find_by_name("init").len(), 2);
    }

    #[test]
    fn function_table_remove() {
        let mut ft = FunctionTable::new();
        ft.add(FunctionEntry::new(Address::new(0xDEAD), "target"));
        assert!(ft.remove(Address::new(0xDEAD)).is_some());
        assert!(ft.is_empty());
        assert!(ft.find_by_name("target").is_empty());
    }

    #[test]
    fn function_table_rename() {
        let mut ft = FunctionTable::new();
        ft.add(FunctionEntry::new(Address::new(0x100), "old"));
        ft.rename(Address::new(0x100), "new").unwrap();
        assert!(ft.find_by_name("old").is_empty());
        assert_eq!(ft.find_by_name("new").len(), 1);
    }

    #[test]
    fn function_table_rename_nonexistent_errors() {
        let mut ft = FunctionTable::new();
        assert!(ft.rename(Address::new(0xBEEF), "x").is_err());
    }

    #[test]
    fn function_table_find_containing() {
        let mut ft = FunctionTable::new();
        ft.add(FunctionEntry::new(Address::new(0x1000), "fn").with_end(Address::new(0x1100)));
        assert!(ft.find_containing(Address::new(0x1050)).is_some());
        assert!(ft.find_containing(Address::new(0x2000)).is_none());
    }

    #[test]
    fn function_table_list_in_range() {
        let mut ft = FunctionTable::new();
        for i in 0u64..10 {
            ft.add(FunctionEntry::new(
                Address::new(0x1000 + i * 0x100),
                format!("fn_{i}"),
            ));
        }
        let range = AddressRange::new(Address::new(0x1000), Address::new(0x1500));
        assert_eq!(ft.list_in_range(range).len(), 5);
    }

    #[test]
    fn function_entry_byte_size() {
        let e = FunctionEntry::new(Address::new(0x100), "f").with_end(Address::new(0x180));
        assert_eq!(e.byte_size(), Some(0x80));
    }

    #[test]
    fn function_table_replace_updates_name_index() {
        let mut ft = FunctionTable::new();
        ft.add(FunctionEntry::new(Address::new(0x100), "first"));
        // Replace with a different name.
        ft.add(FunctionEntry::new(Address::new(0x100), "second"));
        assert!(ft.find_by_name("first").is_empty());
        assert_eq!(ft.find_by_name("second").len(), 1);
    }

    // ── TypeSystem ────────────────────────────────────────────────────────────

    #[test]
    fn type_system_define_and_lookup() {
        let mut ts = TypeSystem::new();
        ts.define(TypeDefinition::new("MyStruct").with_size(16));
        assert_eq!(ts.lookup("MyStruct").unwrap().size, Some(16));
    }

    #[test]
    fn type_system_remove() {
        let mut ts = TypeSystem::new();
        ts.define(TypeDefinition::new("X"));
        assert!(ts.remove("X").is_some());
        assert!(ts.is_empty());
    }

    #[test]
    fn type_system_resolve_alias() {
        let mut ts = TypeSystem::new();
        ts.define(TypeDefinition::new("Alias").alias_of("Target"));
        ts.define(TypeDefinition::new("Target").with_size(8));
        let resolved = ts.resolve("Alias", 5).unwrap().unwrap();
        assert_eq!(resolved.name, "Target");
    }

    #[test]
    fn type_system_resolve_missing_chain() {
        let mut ts = TypeSystem::new();
        ts.define(TypeDefinition::new("A").alias_of("B")); // B not defined
        assert!(ts.resolve("A", 5).unwrap().is_none());
    }

    #[test]
    fn type_system_resolve_cycle_detected() {
        let mut ts = TypeSystem::new();
        ts.define(TypeDefinition::new("A").alias_of("B"));
        ts.define(TypeDefinition::new("B").alias_of("A"));
        assert!(ts.resolve("A", 3).is_err());
    }

    #[test]
    fn type_system_by_source() {
        let mut ts = TypeSystem::new();
        ts.define(TypeDefinition::new("P1").with_source(TypeSource::Pdb));
        ts.define(TypeDefinition::new("P2").with_source(TypeSource::Pdb));
        ts.define(TypeDefinition::new("D1").with_source(TypeSource::Dwarf));
        assert_eq!(ts.by_source(TypeSource::Pdb).len(), 2);
        assert_eq!(ts.by_source(TypeSource::Dwarf).len(), 1);
    }

    #[test]
    fn type_system_all_names_sorted() {
        let mut ts = TypeSystem::new();
        ts.define(TypeDefinition::new("Z"));
        ts.define(TypeDefinition::new("A"));
        ts.define(TypeDefinition::new("M"));
        let names = ts.all_names();
        assert_eq!(names, vec!["A", "M", "Z"]);
    }

    // ── XrefIndex ─────────────────────────────────────────────────────────────

    #[test]
    fn xref_index_add_and_query() {
        let mut idx = XrefIndex::new();
        idx.add(XrefEntry::certain(
            Address::new(0x100),
            Address::new(0x200),
            XrefKind::Call,
        ));
        idx.add(XrefEntry::certain(
            Address::new(0x150),
            Address::new(0x200),
            XrefKind::Call,
        ));
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.callers_of(Address::new(0x200)).len(), 2);
        assert_eq!(idx.callees_of(Address::new(0x100)).len(), 1);
    }

    #[test]
    fn xref_index_deduplication() {
        let mut idx = XrefIndex::new();
        let x = XrefEntry::certain(Address::new(0xA), Address::new(0xB), XrefKind::Jump);
        idx.add(x.clone());
        idx.add(x);
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn xref_index_remove_from() {
        let mut idx = XrefIndex::new();
        idx.add(XrefEntry::certain(
            Address::new(0x10),
            Address::new(0x20),
            XrefKind::Call,
        ));
        idx.add(XrefEntry::certain(
            Address::new(0x30),
            Address::new(0x20),
            XrefKind::Call,
        ));
        idx.remove_from(Address::new(0x10));
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.to(Address::new(0x20)).len(), 1);
    }

    #[test]
    fn xref_index_remove_to() {
        let mut idx = XrefIndex::new();
        idx.add(XrefEntry::certain(
            Address::new(0x10),
            Address::new(0x20),
            XrefKind::DataRead,
        ));
        idx.remove_to(Address::new(0x20));
        assert!(idx.is_empty());
        assert!(idx.from(Address::new(0x10)).is_empty());
    }

    #[test]
    fn xref_kind_display() {
        assert_eq!(XrefKind::Call.to_string(), "call");
        assert_eq!(XrefKind::DataAddr.to_string(), "data-addr");
    }

    #[test]
    fn xref_certain_filter() {
        let mut idx = XrefIndex::new();
        idx.add(XrefEntry::certain(
            Address::new(0x1),
            Address::new(0x2),
            XrefKind::Call,
        ));
        idx.add(XrefEntry::uncertain(
            Address::new(0x3),
            Address::new(0x4),
            XrefKind::Jump,
        ));
        assert_eq!(idx.certain_xrefs().len(), 1);
    }

    // ── PatchSet ──────────────────────────────────────────────────────────────

    #[test]
    fn patch_set_apply_and_list() {
        let mut ps = PatchSet::new();
        ps.apply(PatchEntry::new(0x1000, vec![0xAA; 4], vec![0xBB; 4]))
            .unwrap();
        assert_eq!(ps.len(), 1);
        assert_eq!(ps.list()[0].address, 0x1000);
    }

    #[test]
    fn patch_set_revert() {
        let mut ps = PatchSet::new();
        ps.apply(PatchEntry::new(0x1000, vec![0xAA], vec![0xBB]))
            .unwrap();
        assert!(ps.revert(0x1000).is_some());
        assert!(ps.is_empty());
    }

    #[test]
    fn patch_set_conflict_detection() {
        let mut ps = PatchSet::new();
        ps.apply(PatchEntry::new(0x1000, vec![0xAA; 8], vec![0xBB; 8]))
            .unwrap();
        let result = ps.apply(PatchEntry::new(0x1004, vec![0xCC; 4], vec![0xDD; 4]));
        assert!(result.is_err());
    }

    #[test]
    fn patch_set_force_apply_removes_conflicts() {
        let mut ps = PatchSet::new();
        ps.apply(PatchEntry::new(0x1000, vec![0xAA; 8], vec![0xBB; 8]))
            .unwrap();
        ps.force_apply(PatchEntry::new(0x1000, vec![0xCC; 8], vec![0xDD; 8]));
        assert_eq!(ps.len(), 1);
        assert_eq!(ps.get(0x1000).unwrap().patched, vec![0xDD; 8]);
    }

    #[test]
    fn patch_set_apply_to_buf() {
        let mut ps = PatchSet::new();
        ps.apply(PatchEntry::new(0x1002, vec![], vec![0xFF, 0xFF]))
            .unwrap();
        let mut buf = vec![0u8; 8];
        ps.apply_to_buf(&mut buf, 0x1000);
        assert_eq!(buf[2], 0xFF);
        assert_eq!(buf[3], 0xFF);
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn patch_set_export_diff() {
        let mut ps = PatchSet::new();
        ps.apply(PatchEntry::new(0x100, vec![0xAA], vec![0xBB]))
            .unwrap();
        let diff = ps.export_diff();
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].0, 0x100);
    }

    // ── CommentStore ──────────────────────────────────────────────────────────

    #[test]
    fn comment_store_set_and_get() {
        let mut cs = CommentStore::new();
        let id = cs.set_text(0x1000, "entry point");
        let comments = cs.get(0x1000);
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].1.text, "entry point");
        assert_eq!(cs.get_by_id(id).unwrap().1.text, "entry point");
    }

    #[test]
    fn comment_store_remove_by_id() {
        let mut cs = CommentStore::new();
        let id = cs.set_text(0x1000, "x");
        assert!(cs.remove(id));
        assert!(cs.get(0x1000).is_empty());
    }

    #[test]
    fn comment_store_remove_all_at() {
        let mut cs = CommentStore::new();
        cs.set_text(0x1000, "a");
        cs.set_text(0x1000, "b");
        cs.remove_all_at(0x1000);
        assert!(cs.is_empty());
    }

    #[test]
    fn comment_store_multiple_at_same_address() {
        let mut cs = CommentStore::new();
        cs.set_text(0xABCD, "first");
        cs.set_text(0xABCD, "second");
        assert_eq!(cs.get(0xABCD).len(), 2);
    }

    #[test]
    fn comment_entry_builder() {
        let c = CommentEntry::new("note")
            .repeatable()
            .with_author("analyst");
        assert!(c.repeatable);
        assert_eq!(c.author.as_deref(), Some("analyst"));
    }

    #[test]
    fn comment_store_list() {
        let mut cs = CommentStore::new();
        cs.set_text(0x100, "c1");
        cs.set_text(0x200, "c2");
        assert_eq!(cs.list().count(), 2);
    }

    // ── BookmarkSet ───────────────────────────────────────────────────────────

    #[test]
    fn bookmark_set_insert_and_at() {
        let mut bs = BookmarkSet::new();
        let id =
            bs.insert(BookmarkEntry::new(0x1234, "interesting").with_color(BookmarkColor::RED));
        let found = bs.at(0x1234);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1.label, "interesting");
        assert_eq!(found[0].0, id);
    }

    #[test]
    fn bookmark_set_remove() {
        let mut bs = BookmarkSet::new();
        let id = bs.insert(BookmarkEntry::new(0x5678, "bm"));
        assert!(bs.remove(id));
        assert!(bs.is_empty());
    }

    #[test]
    fn bookmark_set_remove_nonexistent() {
        let mut bs = BookmarkSet::new();
        assert!(!bs.remove(BookmarkId(99)));
    }

    #[test]
    fn bookmark_color_constants() {
        assert_eq!(BookmarkColor::RED.0, 0xFF_FF_00_00);
        assert_eq!(BookmarkColor::NONE.0, 0);
    }

    #[test]
    fn bookmark_set_iter() {
        let mut bs = BookmarkSet::new();
        bs.insert(BookmarkEntry::new(0x1, "a"));
        bs.insert(BookmarkEntry::new(0x2, "b"));
        assert_eq!(bs.iter().count(), 2);
    }

    // ── BinaryViewBuilder ─────────────────────────────────────────────────────

    #[test]
    fn builder_success() {
        let view = BinaryViewBuilder::new()
            .id(ViewId::from_raw(1))
            .uri(BinaryUri::file("/tmp/test"))
            .arch(Arc::new(DummyArch))
            .bits(64)
            .endian(Endian::Little)
            .entry_point(Address::new(0x1000))
            .build()
            .unwrap();
        assert_eq!(view.bits, 64);
        assert_eq!(view.entry_points.len(), 1);
        assert_eq!(view.arch.name(), "stub");
    }

    #[test]
    fn builder_missing_id_errors() {
        let result = BinaryViewBuilder::new()
            .uri(BinaryUri::file("/tmp/x"))
            .arch(Arc::new(DummyArch))
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_missing_uri_errors() {
        let result = BinaryViewBuilder::new()
            .id(ViewId::from_raw(1))
            .arch(Arc::new(DummyArch))
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_missing_arch_errors() {
        let result = BinaryViewBuilder::new()
            .id(ViewId::from_raw(1))
            .uri(BinaryUri::file("/tmp/x"))
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_defaults_endian_and_bits() {
        let view = BinaryViewBuilder::new()
            .id(ViewId::from_raw(2))
            .uri(BinaryUri::file("/tmp/y"))
            .arch(Arc::new(DummyArch))
            .build()
            .unwrap();
        assert_eq!(view.endian, Endian::Little);
        assert_eq!(view.bits, 64);
    }

    #[test]
    fn view_full_sub_systems_accessible() {
        let mut view = BinaryViewBuilder::new()
            .id(ViewId::from_raw(3))
            .uri(BinaryUri::file("/tmp/z"))
            .arch(Arc::new(DummyArch))
            .build()
            .unwrap();

        view.functions
            .add(FunctionEntry::new(Address::new(0x100), "main"));
        view.types
            .define(TypeDefinition::new("MyType").with_size(4));
        view.xrefs.add(XrefEntry::certain(
            Address::new(0x10),
            Address::new(0x20),
            XrefKind::Call,
        ));
        view.patches
            .apply(PatchEntry::new(0x500, vec![0xAA], vec![0xBB]))
            .unwrap();
        view.comments.set_text(0x100, "start");
        view.bookmarks.insert(BookmarkEntry::new(0x100, "entry"));

        assert_eq!(view.functions.len(), 1);
        assert_eq!(view.types.len(), 1);
        assert_eq!(view.xrefs.len(), 1);
        assert_eq!(view.patches.len(), 1);
        assert_eq!(view.comments.len(), 1);
        assert_eq!(view.bookmarks.len(), 1);
    }

    // ── PatchConflict display ─────────────────────────────────────────────────

    #[test]
    fn patch_conflict_display() {
        let c = PatchConflict {
            address: 0x1000,
            conflict_with: "patch_a".into(),
        };
        assert!(c.to_string().contains("0x1000"));
        assert!(c.to_string().contains("patch_a"));
    }

    // ── TypeDefinition ────────────────────────────────────────────────────────

    #[test]
    fn type_definition_is_alias() {
        let plain = TypeDefinition::new("Foo");
        let aliased = TypeDefinition::new("Bar").alias_of("Foo");
        assert!(!plain.is_alias());
        assert!(aliased.is_alias());
    }

    #[test]
    fn type_definition_with_comment() {
        let t = TypeDefinition::new("X").with_comment("docs");
        assert_eq!(t.comment.as_deref(), Some("docs"));
    }
}
