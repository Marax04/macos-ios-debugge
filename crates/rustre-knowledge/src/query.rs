//! `query` — Read-only query helpers over an [`EntitySnapshot`].
//!
//! These functions deliberately work on a borrowed snapshot rather than the
//! store itself, so they compose with [`KnowledgeStore::query`] and with
//! ad-hoc replays.
//!
//! [`KnowledgeStore::query`]: crate::store::KnowledgeStore::query

use crate::entities::{
    Address, Bookmark, Comment, CommentScope, EntityId, EntityKind, EntitySnapshot,
    Function, Patch, Symbol, Tag, Trace, TypeDef, Xref, XrefKind,
};

// ---------------------------------------------------------------------------
// Symbol queries
// ---------------------------------------------------------------------------

/// Find a symbol whose `address` matches exactly.
#[must_use]
pub fn find_symbol_by_addr(snap: &EntitySnapshot, addr: Address) -> Option<&Symbol> {
    snap.symbols.values().find(|s| s.address == addr)
}

/// Find a symbol by exact `name` match.
#[must_use]
pub fn find_symbol_by_name<'a>(snap: &'a EntitySnapshot, name: &str) -> Option<&'a Symbol> {
    snap.symbols.values().find(|s| s.name == name)
}

/// All symbols in `[lo, hi)`.
#[must_use]
pub fn symbols_in_range(snap: &EntitySnapshot, lo: Address, hi: Address) -> Vec<&Symbol> {
    snap.symbols.values().filter(|s| s.address >= lo && s.address < hi).collect()
}

// ---------------------------------------------------------------------------
// Function queries
// ---------------------------------------------------------------------------

/// Find the function whose entry point equals `entry`.
#[must_use]
pub fn find_function_by_entry(snap: &EntitySnapshot, entry: Address) -> Option<&Function> {
    snap.functions.values().find(|f| f.entry == entry)
}

/// Find the function that contains `addr` (entry ≤ addr < end).
#[must_use]
pub fn function_containing(snap: &EntitySnapshot, addr: Address) -> Option<&Function> {
    snap.functions.values().find(|f| f.contains(addr))
}

/// All functions whose entry falls inside `[lo, hi)`.
#[must_use]
pub fn functions_in_range(snap: &EntitySnapshot, lo: Address, hi: Address) -> Vec<&Function> {
    snap.functions.values().filter(|f| f.entry >= lo && f.entry < hi).collect()
}

// ---------------------------------------------------------------------------
// Type queries
// ---------------------------------------------------------------------------

/// Find a type definition by exact name.
#[must_use]
pub fn find_type_by_name<'a>(snap: &'a EntitySnapshot, name: &str) -> Option<&'a TypeDef> {
    snap.types.values().find(|t| t.name == name)
}

// ---------------------------------------------------------------------------
// Comment queries
// ---------------------------------------------------------------------------

/// All comments at `addr` (any scope).
#[must_use]
pub fn comments_at(snap: &EntitySnapshot, addr: Address) -> Vec<&Comment> {
    snap.comments.values().filter(|c| c.address == addr).collect()
}

/// All comments at `addr` of the given scope.
#[must_use]
pub fn comments_at_scope(snap: &EntitySnapshot, addr: Address, scope: CommentScope) -> Vec<&Comment> {
    snap.comments.values().filter(|c| c.address == addr && c.scope == scope).collect()
}

// ---------------------------------------------------------------------------
// Xref queries
// ---------------------------------------------------------------------------

/// All cross-references that target `addr`.
#[must_use]
pub fn xrefs_to(snap: &EntitySnapshot, addr: Address) -> Vec<&Xref> {
    snap.xrefs.values().filter(|x| x.to == addr).collect()
}

/// All cross-references originating at `addr`.
#[must_use]
pub fn xrefs_from(snap: &EntitySnapshot, addr: Address) -> Vec<&Xref> {
    snap.xrefs.values().filter(|x| x.from == addr).collect()
}

/// All cross-references of a given kind.
#[must_use]
pub fn xrefs_of_kind(snap: &EntitySnapshot, kind: XrefKind) -> Vec<&Xref> {
    snap.xrefs.values().filter(|x| x.kind == kind).collect()
}

// ---------------------------------------------------------------------------
// Patch / Bookmark / Trace / Tag queries
// ---------------------------------------------------------------------------

/// All patches at `addr`.
#[must_use]
pub fn patches_at(snap: &EntitySnapshot, addr: Address) -> Vec<&Patch> {
    snap.patches.values().filter(|p| p.address == addr).collect()
}

/// All currently-applied patches.
#[must_use]
pub fn applied_patches(snap: &EntitySnapshot) -> Vec<&Patch> {
    snap.patches.values().filter(|p| p.applied).collect()
}

/// All bookmarks at `addr`.
#[must_use]
pub fn bookmarks_at(snap: &EntitySnapshot, addr: Address) -> Vec<&Bookmark> {
    snap.bookmarks.values().filter(|b| b.address == addr).collect()
}

/// All trace samples whose `timestamp` lies in `[lo, hi)`.
#[must_use]
pub fn traces_in_window(snap: &EntitySnapshot, lo: u64, hi: u64) -> Vec<&Trace> {
    snap.traces.values().filter(|t| t.timestamp >= lo && t.timestamp < hi).collect()
}

/// All trace samples that hit `addr`.
#[must_use]
pub fn traces_at(snap: &EntitySnapshot, addr: Address) -> Vec<&Trace> {
    snap.traces.values().filter(|t| t.address == addr).collect()
}

/// All tags attached to a specific entity.
#[must_use]
pub fn tags_for(snap: &EntitySnapshot, target: EntityId) -> Vec<&Tag> {
    snap.tags.values().filter(|t| t.target == target).collect()
}

/// All tags with a given key.
#[must_use]
pub fn tags_with_key<'a>(snap: &'a EntitySnapshot, key: &str) -> Vec<&'a Tag> {
    snap.tags.values().filter(|t| t.key == key).collect()
}

/// Convenience: count entities by kind.
#[must_use]
pub fn count(snap: &EntitySnapshot, kind: EntityKind) -> usize {
    match kind {
        EntityKind::Symbol => snap.symbols.len(),
        EntityKind::Function => snap.functions.len(),
        EntityKind::Type => snap.types.len(),
        EntityKind::Comment => snap.comments.len(),
        EntityKind::Xref => snap.xrefs.len(),
        EntityKind::Patch => snap.patches.len(),
        EntityKind::Bookmark => snap.bookmarks.len(),
        EntityKind::Trace => snap.traces.len(),
        EntityKind::Tag => snap.tags.len(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::{
        Bookmark, Comment, CommentScope, Function, Patch, Symbol, SymbolScope, Tag, Trace,
        TypeDef, TypeKind, Xref, XrefKind,
    };

    fn seed() -> EntitySnapshot {
        let mut snap = EntitySnapshot::new();
        let s1 = Symbol::new(0x1000, "main", SymbolScope::Global);
        let s2 = Symbol::new(0x2000, "helper", SymbolScope::Local);
        let f1 = Function::new(0x1000, 0x1100, "main");
        let f2 = Function::new(0x2000, 0x2080, "helper");
        let ty = TypeDef::new(TypeKind::Struct, "Foo", "struct Foo {}");
        let cm = Comment::new(CommentScope::Instruction, 0x1004, "u", "hi");
        let xr = Xref::new(0x1004, 0x2000, XrefKind::Call);
        let pt = Patch::new(0x1010, vec![0x90], vec![0xCC]);
        let bm = Bookmark::new(0x1020, "look here");
        let tr = Trace::new(0x1000, 100);
        let tag = Tag::new(s1.id, EntityKind::Symbol, "category", "entry");
        snap.symbols.insert(s1.id, s1);
        snap.symbols.insert(s2.id, s2);
        snap.functions.insert(f1.id, f1);
        snap.functions.insert(f2.id, f2);
        snap.types.insert(ty.id, ty);
        snap.comments.insert(cm.id, cm);
        snap.xrefs.insert(xr.id, xr);
        snap.patches.insert(pt.id, pt);
        snap.bookmarks.insert(bm.id, bm);
        snap.traces.insert(tr.id, tr);
        snap.tags.insert(tag.id, tag);
        snap
    }

    #[test]
    fn symbol_lookups() {
        let snap = seed();
        assert!(find_symbol_by_addr(&snap, 0x1000).is_some());
        assert!(find_symbol_by_name(&snap, "helper").is_some());
        assert_eq!(symbols_in_range(&snap, 0, 0x1500).len(), 1);
    }

    #[test]
    fn function_lookups() {
        let snap = seed();
        assert!(find_function_by_entry(&snap, 0x1000).is_some());
        let f = function_containing(&snap, 0x1050).unwrap();
        assert_eq!(f.name, "main");
        assert_eq!(functions_in_range(&snap, 0, 0x10_000).len(), 2);
    }

    #[test]
    fn xref_and_comment_lookups() {
        let snap = seed();
        assert_eq!(xrefs_to(&snap, 0x2000).len(), 1);
        assert_eq!(xrefs_from(&snap, 0x1004).len(), 1);
        assert_eq!(xrefs_of_kind(&snap, XrefKind::Call).len(), 1);
        assert_eq!(comments_at(&snap, 0x1004).len(), 1);
        assert_eq!(comments_at_scope(&snap, 0x1004, CommentScope::Instruction).len(), 1);
    }

    #[test]
    fn aux_lookups() {
        let snap = seed();
        assert_eq!(patches_at(&snap, 0x1010).len(), 1);
        assert_eq!(applied_patches(&snap).len(), 0);
        assert_eq!(bookmarks_at(&snap, 0x1020).len(), 1);
        assert_eq!(traces_in_window(&snap, 0, 200).len(), 1);
        assert_eq!(traces_at(&snap, 0x1000).len(), 1);
        assert_eq!(tags_with_key(&snap, "category").len(), 1);
    }

    #[test]
    fn count_by_kind() {
        let snap = seed();
        assert_eq!(count(&snap, EntityKind::Symbol), 2);
        assert_eq!(count(&snap, EntityKind::Function), 2);
        assert_eq!(count(&snap, EntityKind::Tag), 1);
    }

    #[test]
    fn tags_for_target() {
        let snap = seed();
        let sym = find_symbol_by_addr(&snap, 0x1000).unwrap();
        assert_eq!(tags_for(&snap, sym.id).len(), 1);
    }
}
