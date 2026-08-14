//! Patch management, comment storage, and bookmark tracking for binary views.
//!
//! This module provides three independent stores that can be embedded in any
//! analysis context:
//!
//! - [`PatchSet`] — byte-level patches applied to a binary image, grouped by
//!   address and carrying provenance metadata (reason, author, timestamp).
//! - [`CommentStore`] — address-keyed comments, supporting multiple comments
//!   per address, authors, and timestamps.
//! - [`BookmarkSet`] — named bookmarks with optional colour tags and descriptions,
//!   indexed by address for fast lookup and range queries.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the current Unix timestamp in seconds, falling back to 0 on error.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchKind
// ─────────────────────────────────────────────────────────────────────────────

/// Describes the semantic intent of a binary patch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatchKind {
    /// Replace bytes at the target address with NOP instructions.
    Nop,
    /// Unconditional relative/absolute jump inserted at the target address.
    Redirect {
        /// Destination address of the redirect.
        target: u64,
    },
    /// Arbitrary byte replacement with no further semantic meaning.
    RawBytes,
    /// A function has been inlined at this call site.
    Inline,
    /// A constant value has been hard-coded over a computed expression.
    ConstantFold {
        /// The folded value as a big-endian byte string.
        value: Vec<u8>,
    },
    /// An anti-debug or anti-analysis trick has been neutralised.
    AntiDebugBypass,
    /// License / serial check has been bypassed.
    LicensePatch,
    /// Crash / assertion removed.
    CrashFix,
    /// User-defined patch kind.
    Custom(String),
}

impl PatchKind {
    /// Short human-readable label used in display and serialisation.
    #[must_use]
    pub const fn label(&self) -> &str {
        match self {
            Self::Nop => "nop",
            Self::Redirect { .. } => "redirect",
            Self::RawBytes => "raw",
            Self::Inline => "inline",
            Self::ConstantFold { .. } => "const-fold",
            Self::AntiDebugBypass => "anti-debug",
            Self::LicensePatch => "license",
            Self::CrashFix => "crash-fix",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Returns `true` if this patch kind is entirely reversible (original bytes
    /// are preserved in the [`Patch`] itself).
    #[must_use]
    pub const fn is_reversible(&self) -> bool {
        // All patch kinds store original bytes, so they're all reversible.
        true
    }
}

impl fmt::Display for PatchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Redirect { target } => write!(f, "redirect → 0x{target:x}"),
            Self::ConstantFold { value } => {
                write!(f, "const-fold(0x")?;
                for b in value {
                    write!(f, "{b:02x}")?;
                }
                write!(f, ")")
            }
            Self::Custom(s) => write!(f, "custom:{s}"),
            other => write!(f, "{}", other.label()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Patch
// ─────────────────────────────────────────────────────────────────────────────

/// A single binary patch record: maps an address range to replacement bytes.
///
/// The original bytes are always preserved so that the patch can be reverted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Patch {
    /// Virtual address of the first patched byte.
    pub address: u64,
    /// Bytes that were at `address` before the patch was applied.
    pub original: Vec<u8>,
    /// Replacement bytes that were written.
    pub patched: Vec<u8>,
    /// Semantic classification of this patch.
    pub kind: PatchKind,
    /// Free-text rationale for the patch.
    pub reason: String,
    /// Author identifier (username, tool name, …).
    pub author: String,
    /// Unix timestamp (seconds) when the patch was created.
    pub created_at: u64,
    /// `true` once the patch bytes have been committed to the binary image.
    pub applied: bool,
    /// Optional patch group name, used for batch enable/disable operations.
    pub group: Option<String>,
}

impl Patch {
    /// Create a new patch with auto-populated timestamp and default fields.
    #[must_use]
    pub fn new(address: u64, original: Vec<u8>, patched: Vec<u8>, kind: PatchKind) -> Self {
        Self {
            address,
            original,
            patched,
            kind,
            reason: String::new(),
            author: String::new(),
            created_at: now_secs(),
            applied: false,
            group: None,
        }
    }

    /// Attach a human-readable reason.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    /// Attach an author identifier.
    #[must_use]
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    /// Assign this patch to a named group.
    #[must_use]
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }

    /// Returns the number of bytes covered by this patch.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patched.len()
    }

    /// Returns `true` if this patch covers zero bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patched.is_empty()
    }

    /// Exclusive end address of the patched region.
    #[must_use]
    pub const fn end_address(&self) -> u64 {
        self.address.saturating_add(self.patched.len() as u64)
    }

    /// Returns `true` if `addr` falls within the patched address range.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.address && addr < self.end_address()
    }

    /// Returns `true` if the original and patched bytes differ at every byte
    /// that falls within `[start, end)`.
    #[must_use]
    pub const fn overlaps(&self, start: u64, end: u64) -> bool {
        start < self.end_address() && end > self.address
    }

    /// Return the bytes that should be read at `[addr, addr+len)` if this
    /// patch is active, blending original/patched as appropriate.
    ///
    /// Returns `None` if the requested range does not overlap this patch.
    #[must_use]
    pub fn read_patched(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        // Cap allocation to avoid memory exhaustion from untrusted `len`.
        const MAX_READ_LEN: usize = 64 * 1024 * 1024; // 64 MiB
        if !self.overlaps(addr, addr.saturating_add(len as u64)) {
            return None;
        }
        let len = len.min(MAX_READ_LEN);
        let mut out = Vec::with_capacity(len);
        for i in 0..len as u64 {
            let target = addr + i;
            if target >= self.address && target < self.end_address() {
                let idx = usize::try_from(target - self.address).unwrap_or(usize::MAX);
                out.push(*self.patched.get(idx).unwrap_or(&0));
            } else {
                // Outside the patched range: fall back to the preserved
                // original bytes at the equivalent offset relative to the
                // patch's start address. If the offset is out of bounds,
                // there is no source byte available, so stop blending.
                let rel = target.cast_signed() - self.address.cast_signed();
                let idx = usize::try_from(rel).ok();
                match idx.and_then(|i| self.original.get(i)) {
                    Some(b) => out.push(*b),
                    None => return Some(out),
                }
            }
        }
        Some(out)
    }
}

impl fmt::Display for Patch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Patch[0x{:x}+{} {} by {}]",
            self.address,
            self.patched.len(),
            self.kind,
            if self.author.is_empty() {
                "anon"
            } else {
                &self.author
            }
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchSet
// ─────────────────────────────────────────────────────────────────────────────

/// The ID type for a [`Patch`] within a [`PatchSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PatchId(pub u64);

impl fmt::Display for PatchId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "patch#{}", self.0)
    }
}

/// A collection of [`Patch`] records indexed by address and by ID.
///
/// The set keeps a sorted secondary index (via [`BTreeMap`]) on addresses so
/// that range queries and overlap detection are efficient.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatchSet {
    patches: HashMap<PatchId, Patch>,
    /// Sorted map: `address → Vec<PatchId>` for range queries.
    by_address: BTreeMap<u64, Vec<PatchId>>,
    next_id: u64,
}

impl PatchSet {
    /// Create an empty patch set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            patches: HashMap::new(),
            by_address: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Insert a patch and return its assigned [`PatchId`].
    ///
    /// The patch's `applied` field is left unchanged; callers must explicitly
    /// call [`apply`](Self::apply) to mark it as committed.
    pub fn insert(&mut self, patch: Patch) -> PatchId {
        let id = PatchId(self.next_id);
        self.next_id += 1;
        let addr = patch.address;
        self.patches.insert(id, patch);
        self.by_address.entry(addr).or_default().push(id);
        id
    }

    /// Remove the patch with the given `id`, returning it if present.
    pub fn remove(&mut self, id: PatchId) -> Option<Patch> {
        let patch = self.patches.remove(&id)?;
        let ids = self.by_address.get_mut(&patch.address)?;
        ids.retain(|&x| x != id);
        if ids.is_empty() {
            self.by_address.remove(&patch.address);
        }
        Some(patch)
    }

    /// Retrieve an immutable reference to a patch by its ID.
    #[must_use]
    pub fn get(&self, id: PatchId) -> Option<&Patch> {
        self.patches.get(&id)
    }

    /// Retrieve a mutable reference to a patch by its ID.
    pub fn get_mut(&mut self, id: PatchId) -> Option<&mut Patch> {
        self.patches.get_mut(&id)
    }

    /// Mark a patch as applied (bytes committed to the image).
    pub fn apply(&mut self, id: PatchId) -> bool {
        if let Some(p) = self.patches.get_mut(&id) {
            p.applied = true;
            true
        } else {
            false
        }
    }

    /// Mark a patch as unapplied (reverted to original bytes).
    pub fn revert(&mut self, id: PatchId) -> bool {
        if let Some(p) = self.patches.get_mut(&id) {
            p.applied = false;
            true
        } else {
            false
        }
    }

    /// Returns all patch IDs whose address range overlaps `[start, end)`.
    #[must_use]
    pub fn overlapping(&self, start: u64, end: u64) -> Vec<PatchId> {
        let mut result = Vec::new();
        // Walk the BTreeMap from addresses that could overlap: any address < end.
        for (&addr, ids) in self.by_address.range(..end) {
            for &pid in ids {
                if let Some(p) = self.patches.get(&pid)
                    && p.overlaps(start, end)
                {
                    result.push(pid);
                }
                // If we haven't found the patch yet, addr is stale — skip.
                _ = addr; // suppress unused-variable lint
            }
        }
        result
    }

    /// Returns all patches at exactly the given address.
    #[must_use]
    pub fn at(&self, addr: u64) -> Vec<&Patch> {
        self.by_address
            .get(&addr)
            .map(|ids| ids.iter().filter_map(|id| self.patches.get(id)).collect())
            .unwrap_or_default()
    }

    /// Returns all patches in the given group.
    #[must_use]
    pub fn in_group<'a>(&'a self, group: &str) -> Vec<(PatchId, &'a Patch)> {
        self.patches
            .iter()
            .filter(|(_, p)| p.group.as_deref() == Some(group))
            .map(|(&id, p)| (id, p))
            .collect()
    }

    /// Enable all patches in a group (set `applied = true`).
    pub fn apply_group(&mut self, group: &str) {
        let ids: Vec<PatchId> = self
            .patches
            .iter()
            .filter(|(_, p)| p.group.as_deref() == Some(group))
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            self.apply(id);
        }
    }

    /// Disable all patches in a group (set `applied = false`).
    pub fn revert_group(&mut self, group: &str) {
        let ids: Vec<PatchId> = self
            .patches
            .iter()
            .filter(|(_, p)| p.group.as_deref() == Some(group))
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            self.revert(id);
        }
    }

    /// Returns an iterator over all `(PatchId, &Patch)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (PatchId, &Patch)> {
        self.patches.iter().map(|(&id, p)| (id, p))
    }

    /// Returns an iterator over all applied patches.
    pub fn iter_applied(&self) -> impl Iterator<Item = (PatchId, &Patch)> {
        self.patches
            .iter()
            .filter(|(_, p)| p.applied)
            .map(|(&id, p)| (id, p))
    }

    /// Returns the number of patches in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.patches.len()
    }

    /// Returns `true` if there are no patches.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    /// Returns the total number of bytes affected by *applied* patches.
    #[must_use]
    pub fn applied_byte_count(&self) -> usize {
        self.patches
            .values()
            .filter(|p| p.applied)
            .map(|p| p.patched.len())
            .sum()
    }

    /// Returns all group names used by patches in this set.
    #[must_use]
    pub fn all_groups(&self) -> Vec<String> {
        let mut groups: Vec<String> = self
            .patches
            .values()
            .filter_map(|p| p.group.as_deref().map(str::to_owned))
            .collect();
        groups.sort();
        groups.dedup();
        groups
    }

    /// Merge `other` into this set; new IDs are re-allocated to avoid
    /// conflicts.  Returns a mapping from old `PatchId` → new `PatchId`.
    pub fn merge(&mut self, other: &Self) -> HashMap<PatchId, PatchId> {
        let mut id_map = HashMap::new();
        for (&old_id, patch) in &other.patches {
            let new_id = self.insert(patch.clone());
            id_map.insert(old_id, new_id);
        }
        id_map
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Comment
// ─────────────────────────────────────────────────────────────────────────────

/// A single comment attached to an address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comment {
    /// The comment body.
    pub text: String,
    /// Identifies who or what created this comment.
    pub author: String,
    /// Unix timestamp (seconds) when the comment was created.
    pub created_at: u64,
    /// `true` if this comment should appear repeatedly on every instruction
    /// within the enclosing function (e.g., a function-level note).
    pub repeatable: bool,
    /// Optional colour tag for UI theming.
    pub color: Option<u32>,
}

impl Comment {
    /// Create a simple one-liner comment.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            author: String::new(),
            created_at: now_secs(),
            repeatable: false,
            color: None,
        }
    }

    /// Create a comment with author metadata.
    #[must_use]
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    /// Mark this comment as repeatable.
    #[must_use]
    pub const fn repeatable(mut self) -> Self {
        self.repeatable = true;
        self
    }

    /// Attach a colour tag (RGBA packed as 0xRRGGBBAA).
    #[must_use]
    pub const fn with_color(mut self, color: u32) -> Self {
        self.color = Some(color);
        self
    }
}

impl fmt::Display for Comment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.author.is_empty() {
            write!(f, "{}", self.text)
        } else {
            write!(f, "[{}] {}", self.author, self.text)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CommentStore
// ─────────────────────────────────────────────────────────────────────────────

/// The ID type for a [`Comment`] within a [`CommentStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommentId(pub u64);

impl fmt::Display for CommentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cmt#{}", self.0)
    }
}

/// Stores comments keyed by virtual address.
///
/// Multiple comments per address are supported; the most recent comment at an
/// address can be retrieved via [`latest_at`](Self::latest_at).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommentStore {
    comments: HashMap<CommentId, (u64, Comment)>,
    /// `address → [CommentId]` sorted by insertion order.
    by_address: HashMap<u64, Vec<CommentId>>,
    next_id: u64,
}

impl CommentStore {
    /// Create an empty comment store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            comments: HashMap::new(),
            by_address: HashMap::new(),
            next_id: 1,
        }
    }

    /// Append a comment at the given address and return its ID.
    pub fn add(&mut self, address: u64, comment: Comment) -> CommentId {
        let id = CommentId(self.next_id);
        self.next_id += 1;
        self.by_address.entry(address).or_default().push(id);
        self.comments.insert(id, (address, comment));
        id
    }

    /// Append a plain-text comment using one-liner API.
    pub fn add_text(&mut self, address: u64, text: impl Into<String>) -> CommentId {
        self.add(address, Comment::new(text))
    }

    /// Retrieve a comment by its ID.
    #[must_use]
    pub fn get(&self, id: CommentId) -> Option<&Comment> {
        self.comments.get(&id).map(|(_, c)| c)
    }

    /// Mutable access to a comment by ID.
    pub fn get_mut(&mut self, id: CommentId) -> Option<&mut Comment> {
        self.comments.get_mut(&id).map(|(_, c)| c)
    }

    /// Returns all comments at a given address, in insertion order.
    #[must_use]
    pub fn at(&self, address: u64) -> Vec<(CommentId, &Comment)> {
        self.by_address
            .get(&address)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.comments.get(id).map(|(_, c)| (*id, c)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return the most recently added comment at an address, if any.
    #[must_use]
    pub fn latest_at(&self, address: u64) -> Option<(CommentId, &Comment)> {
        self.by_address
            .get(&address)
            .and_then(|ids| ids.last())
            .and_then(|id| self.comments.get(id).map(|(_, c)| (*id, c)))
    }

    /// Remove a comment by ID, returning it.
    pub fn remove(&mut self, id: CommentId) -> Option<Comment> {
        let (addr, cmt) = self.comments.remove(&id)?;
        if let Some(ids) = self.by_address.get_mut(&addr) {
            ids.retain(|&x| x != id);
            if ids.is_empty() {
                self.by_address.remove(&addr);
            }
        }
        Some(cmt)
    }

    /// Remove all comments at a specific address.
    pub fn remove_all_at(&mut self, address: u64) -> Vec<Comment> {
        let ids = self.by_address.remove(&address).unwrap_or_default();
        ids.into_iter()
            .filter_map(|id| self.comments.remove(&id).map(|(_, c)| c))
            .collect()
    }

    /// Returns all repeatable comments in the store.
    #[must_use]
    pub fn repeatable_comments(&self) -> Vec<(u64, CommentId, &Comment)> {
        self.comments
            .iter()
            .filter(|(_, (_, c))| c.repeatable)
            .map(|(&id, (addr, c))| (*addr, id, c))
            .collect()
    }

    /// Addresses that have at least one comment.
    #[must_use]
    pub fn commented_addresses(&self) -> Vec<u64> {
        let mut addrs: Vec<u64> = self.by_address.keys().copied().collect();
        addrs.sort_unstable();
        addrs
    }

    /// Total number of comments in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.comments.len()
    }

    /// Returns `true` if the store has no comments.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.comments.is_empty()
    }

    /// Search comments by substring (case-insensitive).
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<(u64, CommentId, &Comment)> {
        let q = query.to_lowercase();
        self.comments
            .iter()
            .filter(|(_, (_, c))| c.text.to_lowercase().contains(&q))
            .map(|(&id, (addr, c))| (*addr, id, c))
            .collect()
    }

    /// Returns an iterator over all `(address, id, &Comment)` triples.
    pub fn iter(&self) -> impl Iterator<Item = (u64, CommentId, &Comment)> {
        self.comments.iter().map(|(&id, (addr, c))| (*addr, id, c))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bookmark
// ─────────────────────────────────────────────────────────────────────────────

/// Predefined palette colours for bookmarks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BookmarkColor {
    /// Default (no special colour).
    #[default]
    Default,
    Red,
    Orange,
    Yellow,
    Green,
    Cyan,
    Blue,
    Purple,
    Pink,
    /// Arbitrary RGBA value (0xRRGGBBAA).
    Custom(u32),
}

impl BookmarkColor {
    /// Returns the RGBA representation of the colour.
    #[must_use]
    pub const fn as_rgba(self) -> u32 {
        match self {
            Self::Default => 0xCCCC_CCFF,
            Self::Red => 0xFF44_44FF,
            Self::Orange => 0xFF88_00FF,
            Self::Yellow => 0xFFDD_00FF,
            Self::Green => 0x44CC_44FF,
            Self::Cyan => 0x00CC_CCFF,
            Self::Blue => 0x4488_FFFF,
            Self::Purple => 0x9944_CCFF,
            Self::Pink => 0xFF66_AAFF,
            Self::Custom(v) => v,
        }
    }
}

impl fmt::Display for BookmarkColor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => write!(f, "default"),
            Self::Custom(v) => write!(f, "#{v:08x}"),
            other => write!(f, "{other:?}"),
        }
    }
}

/// A single bookmark pinned to a virtual address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bookmark {
    /// Virtual address of the bookmark.
    pub address: u64,
    /// Short user-supplied label.
    pub label: String,
    /// Longer description or note.
    pub description: String,
    /// Display colour.
    pub color: BookmarkColor,
    /// Unix timestamp when the bookmark was created.
    pub created_at: u64,
    /// Author identifier.
    pub author: String,
    /// Optional category tag for grouping bookmarks.
    pub category: Option<String>,
}

impl Bookmark {
    /// Create a minimal bookmark.
    pub fn new(address: u64, label: impl Into<String>) -> Self {
        Self {
            address,
            label: label.into(),
            description: String::new(),
            color: BookmarkColor::Default,
            created_at: now_secs(),
            author: String::new(),
            category: None,
        }
    }

    /// Set the description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the colour.
    #[must_use]
    pub const fn with_color(mut self, color: BookmarkColor) -> Self {
        self.color = color;
        self
    }

    /// Set the author.
    #[must_use]
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    /// Set the category tag.
    #[must_use]
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }
}

impl fmt::Display for Bookmark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bookmark[0x{:x} \"{}\"]", self.address, self.label)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BookmarkSet
// ─────────────────────────────────────────────────────────────────────────────

/// The ID type for a [`Bookmark`] within a [`BookmarkSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BookmarkId(pub u64);

impl fmt::Display for BookmarkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bm#{}", self.0)
    }
}

/// A collection of bookmarks indexed by address and by label.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BookmarkSet {
    bookmarks: HashMap<BookmarkId, Bookmark>,
    by_address: BTreeMap<u64, Vec<BookmarkId>>,
    by_label: HashMap<String, BookmarkId>,
    next_id: u64,
}

impl BookmarkSet {
    /// Create an empty bookmark set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bookmarks: HashMap::new(),
            by_address: BTreeMap::new(),
            by_label: HashMap::new(),
            next_id: 1,
        }
    }

    /// Insert a bookmark, optionally overwriting an existing bookmark with the
    /// same label.  Returns the assigned [`BookmarkId`].
    pub fn insert(&mut self, bookmark: Bookmark) -> BookmarkId {
        // If a bookmark with the same label exists, remove it first.
        if let Some(old_id) = self.by_label.get(&bookmark.label).copied() {
            self.remove(old_id);
        }
        let id = BookmarkId(self.next_id);
        self.next_id += 1;
        let addr = bookmark.address;
        let label = bookmark.label.clone();
        self.bookmarks.insert(id, bookmark);
        self.by_address.entry(addr).or_default().push(id);
        self.by_label.insert(label, id);
        id
    }

    /// Remove a bookmark by ID, returning it if present.
    pub fn remove(&mut self, id: BookmarkId) -> Option<Bookmark> {
        let bm = self.bookmarks.remove(&id)?;
        if let Some(ids) = self.by_address.get_mut(&bm.address) {
            ids.retain(|&x| x != id);
            if ids.is_empty() {
                self.by_address.remove(&bm.address);
            }
        }
        self.by_label.remove(&bm.label);
        Some(bm)
    }

    /// Retrieve a bookmark by its ID.
    #[must_use]
    pub fn get(&self, id: BookmarkId) -> Option<&Bookmark> {
        self.bookmarks.get(&id)
    }

    /// Look up a bookmark by its label.
    #[must_use]
    pub fn by_label(&self, label: &str) -> Option<(BookmarkId, &Bookmark)> {
        self.by_label
            .get(label)
            .and_then(|&id| self.bookmarks.get(&id).map(|b| (id, b)))
    }

    /// Returns all bookmarks at a given address.
    #[must_use]
    pub fn at(&self, address: u64) -> Vec<(BookmarkId, &Bookmark)> {
        self.by_address
            .get(&address)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.bookmarks.get(id).map(|b| (*id, b)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns all bookmarks in the range `[start, end)`.
    #[must_use]
    pub fn in_range(&self, start: u64, end: u64) -> Vec<(BookmarkId, &Bookmark)> {
        self.by_address
            .range(start..end)
            .flat_map(|(_, ids)| {
                ids.iter()
                    .filter_map(|id| self.bookmarks.get(id).map(|b| (*id, b)))
            })
            .collect()
    }

    /// Returns all bookmarks in a given category.
    #[must_use]
    pub fn in_category<'a>(&'a self, category: &str) -> Vec<(BookmarkId, &'a Bookmark)> {
        self.bookmarks
            .iter()
            .filter(|(_, b)| b.category.as_deref() == Some(category))
            .map(|(&id, b)| (id, b))
            .collect()
    }

    /// Returns all category names present in this set.
    #[must_use]
    pub fn all_categories(&self) -> Vec<String> {
        let mut cats: Vec<String> = self
            .bookmarks
            .values()
            .filter_map(|b| b.category.as_deref().map(str::to_owned))
            .collect();
        cats.sort();
        cats.dedup();
        cats
    }

    /// Returns all bookmark labels in address order.
    #[must_use]
    pub fn labels_sorted(&self) -> Vec<String> {
        self.by_address
            .values()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.bookmarks.get(id).map(|b| b.label.clone()))
            .collect()
    }

    /// Returns the total number of bookmarks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bookmarks.len()
    }

    /// Returns `true` if the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bookmarks.is_empty()
    }

    /// Returns an iterator over all `(BookmarkId, &Bookmark)` pairs in
    /// arbitrary order.
    pub fn iter(&self) -> impl Iterator<Item = (BookmarkId, &Bookmark)> {
        self.bookmarks.iter().map(|(&id, b)| (id, b))
    }

    /// Returns an iterator over bookmarks in ascending address order.
    pub fn iter_sorted(&self) -> impl Iterator<Item = (BookmarkId, &Bookmark)> {
        self.by_address
            .values()
            .flat_map(|ids| ids.iter())
            .filter_map(move |id| self.bookmarks.get(id).map(|b| (*id, b)))
    }

    /// Search bookmarks by label or description substring (case-insensitive).
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<(BookmarkId, &Bookmark)> {
        let q = query.to_lowercase();
        self.bookmarks
            .iter()
            .filter(|(_, b)| {
                b.label.to_lowercase().contains(&q) || b.description.to_lowercase().contains(&q)
            })
            .map(|(&id, b)| (id, b))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PatchKind ─────────────────────────────────────────────────────────────

    #[test]
    fn patch_kind_label() {
        assert_eq!(PatchKind::Nop.label(), "nop");
        assert_eq!(PatchKind::RawBytes.label(), "raw");
        assert_eq!(PatchKind::Custom("foo".into()).label(), "foo");
    }

    #[test]
    fn patch_kind_display() {
        let redirect = PatchKind::Redirect { target: 0x1234 };
        assert!(redirect.to_string().contains("0x1234"));
        let cf = PatchKind::ConstantFold {
            value: vec![0xDE, 0xAD],
        };
        assert!(cf.to_string().contains("dead"));
    }

    // ── Patch ─────────────────────────────────────────────────────────────────

    #[test]
    fn patch_contains_and_overlaps() {
        let p = Patch::new(0x1000, vec![0x90, 0x90], vec![0xCC, 0xCC], PatchKind::Nop);
        assert!(p.contains(0x1000));
        assert!(p.contains(0x1001));
        assert!(!p.contains(0x1002));
        assert!(p.overlaps(0x0FFF, 0x1002));
        assert!(!p.overlaps(0x1002, 0x1010));
    }

    #[test]
    fn patch_read_patched() {
        let p = Patch::new(0x1000, vec![0x90, 0x90], vec![0xCC, 0xCC], PatchKind::Nop);
        let out = p.read_patched(0x1000, 2).unwrap();
        assert_eq!(out, vec![0xCC, 0xCC]);
        assert!(p.read_patched(0x2000, 4).is_none());
    }

    #[test]
    fn patch_display() {
        let p = Patch::new(0x4000, vec![0x90], vec![0xCC], PatchKind::Nop).with_author("alice");
        let s = p.to_string();
        assert!(s.contains("0x4000"));
        assert!(s.contains("alice"));
    }

    // ── PatchSet ──────────────────────────────────────────────────────────────

    #[test]
    fn patch_set_insert_remove() {
        let mut ps = PatchSet::new();
        let p = Patch::new(0x1000, vec![0x90], vec![0xCC], PatchKind::Nop);
        let id = ps.insert(p);
        assert_eq!(ps.len(), 1);
        let removed = ps.remove(id).unwrap();
        assert_eq!(removed.address, 0x1000);
        assert_eq!(ps.len(), 0);
    }

    #[test]
    fn patch_set_apply_revert() {
        let mut ps = PatchSet::new();
        let id = ps.insert(Patch::new(0x2000, vec![0x90], vec![0xCC], PatchKind::Nop));
        assert!(!ps.get(id).unwrap().applied);
        ps.apply(id);
        assert!(ps.get(id).unwrap().applied);
        ps.revert(id);
        assert!(!ps.get(id).unwrap().applied);
    }

    #[test]
    fn patch_set_overlapping() {
        let mut ps = PatchSet::new();
        let p1 = Patch::new(0x1000, vec![0x90, 0x90], vec![0xCC, 0xCC], PatchKind::Nop);
        let p2 = Patch::new(0x2000, vec![0x90], vec![0xCC], PatchKind::Nop);
        ps.insert(p1);
        ps.insert(p2);
        let hits = ps.overlapping(0x0FFF, 0x1002);
        assert_eq!(hits.len(), 1);
        let all = ps.overlapping(0x0000, 0x3000);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn patch_set_groups() {
        let mut ps = PatchSet::new();
        let id1 = ps.insert(
            Patch::new(0x1000, vec![0x90], vec![0xCC], PatchKind::Nop).with_group("layer1"),
        );
        let _id2 = ps.insert(
            Patch::new(0x2000, vec![0x90], vec![0xCC], PatchKind::Nop).with_group("layer2"),
        );
        ps.apply_group("layer1");
        assert!(ps.get(id1).unwrap().applied);
        let grps = ps.all_groups();
        assert_eq!(grps.len(), 2);
    }

    #[test]
    fn patch_set_merge() {
        let mut ps1 = PatchSet::new();
        let mut ps2 = PatchSet::new();
        ps1.insert(Patch::new(0x1000, vec![0x90], vec![0xCC], PatchKind::Nop));
        ps2.insert(Patch::new(0x2000, vec![0x90], vec![0xCC], PatchKind::Nop));
        ps1.merge(&ps2);
        assert_eq!(ps1.len(), 2);
    }

    // ── CommentStore ──────────────────────────────────────────────────────────

    #[test]
    fn comment_store_basic() {
        let mut cs = CommentStore::new();
        let id = cs.add_text(0x1000, "hello world");
        assert_eq!(cs.len(), 1);
        let cmt = cs.get(id).unwrap();
        assert_eq!(cmt.text, "hello world");
    }

    #[test]
    fn comment_store_multiple_at_address() {
        let mut cs = CommentStore::new();
        cs.add_text(0x1000, "first");
        cs.add_text(0x1000, "second");
        let cmts = cs.at(0x1000);
        assert_eq!(cmts.len(), 2);
        let latest = cs.latest_at(0x1000).unwrap();
        assert_eq!(latest.1.text, "second");
    }

    #[test]
    fn comment_store_remove_all_at() {
        let mut cs = CommentStore::new();
        cs.add_text(0x1000, "a");
        cs.add_text(0x1000, "b");
        cs.add_text(0x2000, "c");
        let removed = cs.remove_all_at(0x1000);
        assert_eq!(removed.len(), 2);
        assert_eq!(cs.len(), 1);
    }

    #[test]
    fn comment_store_search() {
        let mut cs = CommentStore::new();
        cs.add_text(0x1000, "jump target");
        cs.add_text(0x2000, "check return value");
        let results = cs.search("return");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn comment_store_repeatable() {
        let mut cs = CommentStore::new();
        cs.add(0x1000, Comment::new("note").repeatable());
        cs.add_text(0x2000, "plain");
        let rep = cs.repeatable_comments();
        assert_eq!(rep.len(), 1);
    }

    // ── BookmarkSet ───────────────────────────────────────────────────────────

    #[test]
    fn bookmark_set_insert_lookup() {
        let mut bs = BookmarkSet::new();
        let bm = Bookmark::new(0x1000, "entry_point").with_color(BookmarkColor::Green);
        let id = bs.insert(bm);
        assert_eq!(bs.len(), 1);
        let found = bs.by_label("entry_point").unwrap();
        assert_eq!(found.0, id);
    }

    #[test]
    fn bookmark_set_label_dedup() {
        let mut bs = BookmarkSet::new();
        bs.insert(Bookmark::new(0x1000, "marker"));
        bs.insert(Bookmark::new(0x2000, "marker")); // replaces
        assert_eq!(bs.len(), 1);
        assert_eq!(bs.by_label("marker").unwrap().1.address, 0x2000);
    }

    #[test]
    fn bookmark_set_range_query() {
        let mut bs = BookmarkSet::new();
        bs.insert(Bookmark::new(0x1000, "a"));
        bs.insert(Bookmark::new(0x2000, "b"));
        bs.insert(Bookmark::new(0x3000, "c"));
        let hits = bs.in_range(0x1000, 0x2500);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn bookmark_set_categories() {
        let mut bs = BookmarkSet::new();
        bs.insert(Bookmark::new(0x1000, "fn1").with_category("functions"));
        bs.insert(Bookmark::new(0x2000, "str1").with_category("strings"));
        bs.insert(Bookmark::new(0x3000, "fn2").with_category("functions"));
        let fns = bs.in_category("functions");
        assert_eq!(fns.len(), 2);
        let cats = bs.all_categories();
        assert_eq!(cats, ["functions", "strings"]);
    }

    #[test]
    fn bookmark_set_search() {
        let mut bs = BookmarkSet::new();
        bs.insert(Bookmark::new(0x1000, "main_entry").with_description("program entry point"));
        bs.insert(Bookmark::new(0x2000, "exit_handler").with_description("entry/exit shim"));
        let results = bs.search("entry");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn bookmark_color_rgba() {
        assert_eq!(BookmarkColor::Red.as_rgba(), 0xFF44_44FF);
        assert_eq!(BookmarkColor::Custom(0xAABB_CCDD).as_rgba(), 0xAABB_CCDD);
    }
}
