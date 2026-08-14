//! `xref_index` — Fast cross-reference index for binary analysis.
//!
//! Provides [`XrefIndex`], [`XrefEntry`], and [`XrefKind`] (local lightweight version),
//! plus [`add_xref`] and [`xrefs_to`] free functions.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

// ── XrefKind (local lightweight) ──────────────────────────────────────────────

/// The kind of a cross-reference in the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum XrefEntryKind {
    /// Direct or indirect CALL.
    Call,
    /// Unconditional or conditional jump.
    Jump,
    /// Data-section pointer to this address.
    DataPointer,
    /// LEA / MOV-immediate taking address of this location.
    DataAddress,
    /// Read from this address.
    DataRead,
    /// Write to this address.
    DataWrite,
    /// Interned string literal referenced here.
    StringRef,
    /// Import-by-name stub reference.
    Import,
    /// Thunk / tail-call forwarding.
    Thunk,
    /// Type-level reference (vtable, RTTI).
    TypeRef,
}

impl XrefEntryKind {
    #[must_use]
    pub const fn is_code_flow(self) -> bool {
        matches!(self, Self::Call | Self::Jump | Self::Thunk)
    }

    #[must_use]
    pub const fn is_data(self) -> bool {
        matches!(
            self,
            Self::DataPointer | Self::DataAddress | Self::DataRead | Self::DataWrite
        )
    }

    /// All variants in canonical order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Call,
            Self::Jump,
            Self::DataPointer,
            Self::DataAddress,
            Self::DataRead,
            Self::DataWrite,
            Self::StringRef,
            Self::Import,
            Self::Thunk,
            Self::TypeRef,
        ]
    }
}

impl fmt::Display for XrefEntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Call => "Call",
            Self::Jump => "Jump",
            Self::DataPointer => "DataPointer",
            Self::DataAddress => "DataAddress",
            Self::DataRead => "DataRead",
            Self::DataWrite => "DataWrite",
            Self::StringRef => "StringRef",
            Self::Import => "Import",
            Self::Thunk => "Thunk",
            Self::TypeRef => "TypeRef",
        };
        f.write_str(s)
    }
}

// ── XrefEntry ─────────────────────────────────────────────────────────────────

/// A single cross-reference record stored in the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrefEntry {
    /// Source address (the instruction / data location making the reference).
    pub from: u64,
    /// Target address (what is being referenced).
    pub to: u64,
    /// Kind of reference.
    pub kind: XrefEntryKind,
    /// Instruction size in bytes at `from` (0 for data xrefs).
    pub instr_size: u8,
    /// Optional human-readable tag (import name, string content, type name, …).
    pub tag: Option<String>,
}

impl XrefEntry {
    /// Create a new xref without a tag.
    #[must_use]
    pub const fn new(from: u64, to: u64, kind: XrefEntryKind, instr_size: u8) -> Self {
        Self { from, to, kind, instr_size, tag: None }
    }

    /// Create a new xref with a tag.
    #[must_use]
    pub fn with_tag(
        from: u64,
        to: u64,
        kind: XrefEntryKind,
        instr_size: u8,
        tag: impl Into<String>,
    ) -> Self {
        Self { from, to, kind, instr_size, tag: Some(tag.into()) }
    }

    /// Whether this xref transfers code execution.
    #[must_use]
    pub const fn is_code_flow(&self) -> bool {
        self.kind.is_code_flow()
    }

    /// Whether this is a data xref.
    #[must_use]
    pub const fn is_data(&self) -> bool {
        self.kind.is_data()
    }
}

impl fmt::Display for XrefEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x} -> {:#010x} [{}]", self.from, self.to, self.kind)?;
        if let Some(tag) = &self.tag {
            write!(f, " \"{tag}\"")?;
        }
        Ok(())
    }
}

// ── IndexStats ────────────────────────────────────────────────────────────────

/// Statistics snapshot from an [`XrefIndex`].
#[derive(Debug, Clone)]
pub struct IndexStats {
    pub total_entries: usize,
    pub unique_sources: usize,
    pub unique_targets: usize,
    pub by_kind: HashMap<String, usize>,
    pub call_count: usize,
    pub jump_count: usize,
    pub data_count: usize,
}

impl IndexStats {
    #[must_use]
    pub fn format_report(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(s, "Total xrefs    : {}", self.total_entries);
        let _ = writeln!(s, "Unique sources : {}", self.unique_sources);
        let _ = writeln!(s, "Unique targets : {}", self.unique_targets);
        let _ = writeln!(s, "Calls          : {}", self.call_count);
        let _ = writeln!(s, "Jumps          : {}", self.jump_count);
        let _ = writeln!(s, "Data refs      : {}", self.data_count);
        let mut kinds: Vec<(&String, &usize)> = self.by_kind.iter().collect();
        kinds.sort_unstable_by_key(|(k, _)| k.as_str());
        for (k, v) in kinds {
            let _ = writeln!(s, "  {k:20} {v}");
        }
        s
    }
}

// ── XrefIndex ─────────────────────────────────────────────────────────────────

/// A bidirectional, multi-kind cross-reference index.
///
/// Designed for fast lookup in both directions (from-address and to-address),
/// with secondary indices for kind, string, and import lookups.
///
/// All addresses are raw `u64` values; the index is architecture-agnostic.
#[derive(Debug, Default)]
pub struct XrefIndex {
    /// Primary forward index: from → list of xrefs.
    from_idx: HashMap<u64, Vec<XrefEntry>>,
    /// Primary reverse index: to → list of xrefs.
    to_idx: HashMap<u64, Vec<XrefEntry>>,
    /// Secondary kind index: kind → set of (from, to) pairs.
    kind_idx: HashMap<XrefEntryKind, HashSet<(u64, u64)>>,
    /// String content → set of from-addresses.
    string_idx: HashMap<String, HashSet<u64>>,
    /// Import name → set of from-addresses.
    import_idx: HashMap<String, HashSet<u64>>,
    /// Type name → set of from-addresses.
    type_idx: HashMap<String, HashSet<u64>>,
    /// Total entry count.
    total: usize,
}

impl XrefIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Insertion ─────────────────────────────────────────────────────────────

    /// Add a raw [`XrefEntry`] to the index.
    pub fn add(&mut self, entry: XrefEntry) {
        // Update secondary string/import/type indices
        if entry.kind == XrefEntryKind::StringRef
            && let Some(tag) = &entry.tag {
                self.string_idx.entry(tag.clone()).or_default().insert(entry.from);
            }
        if entry.kind == XrefEntryKind::Import
            && let Some(tag) = &entry.tag {
                self.import_idx.entry(tag.clone()).or_default().insert(entry.from);
            }
        if entry.kind == XrefEntryKind::TypeRef
            && let Some(tag) = &entry.tag {
                self.type_idx.entry(tag.clone()).or_default().insert(entry.from);
            }
        self.kind_idx.entry(entry.kind).or_default().insert((entry.from, entry.to));
        self.from_idx.entry(entry.from).or_default().push(entry.clone());
        self.to_idx.entry(entry.to).or_default().push(entry);
        self.total += 1;
    }

    /// Convenience: add a CALL xref.
    pub fn add_call(&mut self, from: u64, to: u64, instr_size: u8) {
        self.add(XrefEntry::new(from, to, XrefEntryKind::Call, instr_size));
    }

    /// Convenience: add a JUMP xref.
    pub fn add_jump(&mut self, from: u64, to: u64, instr_size: u8) {
        self.add(XrefEntry::new(from, to, XrefEntryKind::Jump, instr_size));
    }

    /// Convenience: add a data-pointer xref.
    pub fn add_data_pointer(&mut self, from: u64, to: u64) {
        self.add(XrefEntry::new(from, to, XrefEntryKind::DataPointer, 0));
    }

    /// Convenience: add a data-read xref.
    pub fn add_data_read(&mut self, from: u64, to: u64) {
        self.add(XrefEntry::new(from, to, XrefEntryKind::DataRead, 0));
    }

    /// Convenience: add a data-write xref.
    pub fn add_data_write(&mut self, from: u64, to: u64) {
        self.add(XrefEntry::new(from, to, XrefEntryKind::DataWrite, 0));
    }

    /// Convenience: add a string-ref xref.
    pub fn add_string_ref(&mut self, from: u64, to: u64, content: impl Into<String>) {
        self.add(XrefEntry::with_tag(from, to, XrefEntryKind::StringRef, 0, content));
    }

    /// Convenience: add an import-stub xref.
    pub fn add_import(&mut self, from: u64, to: u64, name: impl Into<String>) {
        self.add(XrefEntry::with_tag(from, to, XrefEntryKind::Import, 0, name));
    }

    /// Convenience: add a thunk xref.
    pub fn add_thunk(&mut self, from: u64, to: u64, instr_size: u8) {
        self.add(XrefEntry::new(from, to, XrefEntryKind::Thunk, instr_size));
    }

    /// Convenience: add a type-ref xref.
    pub fn add_type_ref(&mut self, from: u64, to: u64, type_name: impl Into<String>) {
        self.add(XrefEntry::with_tag(from, to, XrefEntryKind::TypeRef, 0, type_name));
    }

    // ── Lookup ────────────────────────────────────────────────────────────────

    /// All xrefs originating at `from`.
    #[must_use]
    pub fn xrefs_from(&self, from: u64) -> &[XrefEntry] {
        self.from_idx.get(&from).map_or(&[], Vec::as_slice)
    }

    /// All xrefs pointing to `to`.
    #[must_use]
    pub fn xrefs_to(&self, to: u64) -> &[XrefEntry] {
        self.to_idx.get(&to).map_or(&[], Vec::as_slice)
    }

    /// All xrefs of a specific `kind`.
    ///
    /// `kind_idx` dedups `(from, to)` pairs, but `from_idx` may hold multiple
    /// distinct [`XrefEntry`]s for the same `(from, to, kind)` triple (e.g. a
    /// duplicate `add_call` for the same call site during re-analysis/merge).
    /// We iterate the deduped pairs but collect *all* matching entries per
    /// pair, so the result stays consistent with `total()`/`xrefs_from()`.
    ///
    /// `kind_idx`'s pair set is a `HashSet`, so pairs are sorted before
    /// iterating: otherwise the returned order (and thus any report built
    /// directly from it) would depend on hash iteration order, which is not
    /// stable across runs/processes.
    #[must_use]
    pub fn xrefs_of_kind(&self, kind: XrefEntryKind) -> Vec<&XrefEntry> {
        self.kind_idx.get(&kind).map_or(Vec::new(), |pairs| {
            let mut sorted_pairs: Vec<(u64, u64)> = pairs.iter().copied().collect();
            sorted_pairs.sort_unstable();
            sorted_pairs
                .into_iter()
                .flat_map(|(from, to)| {
                    self.from_idx
                        .get(&from)
                        .into_iter()
                        .flat_map(move |v| v.iter().filter(move |e| e.kind == kind && e.to == to))
                })
                .collect()
        })
    }

    /// CALL callers of `to` (addresses that call this function).
    #[must_use]
    pub fn callers_of(&self, to: u64) -> Vec<u64> {
        self.xrefs_to(to)
            .iter()
            .filter(|e| e.kind == XrefEntryKind::Call)
            .map(|e| e.from)
            .collect()
    }

    /// CALL callees from `from` (addresses this function calls).
    #[must_use]
    pub fn callees_of(&self, from: u64) -> Vec<u64> {
        self.xrefs_from(from)
            .iter()
            .filter(|e| e.kind == XrefEntryKind::Call)
            .map(|e| e.to)
            .collect()
    }

    /// Addresses that reference the given string content.
    #[must_use]
    pub fn string_refs(&self, content: &str) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .string_idx
            .get(content)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        v.sort_unstable();
        v
    }

    /// Addresses that reference the given import name.
    #[must_use]
    pub fn import_refs(&self, name: &str) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .import_idx
            .get(name)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        v.sort_unstable();
        v
    }

    /// All known string literals in the index, sorted lexicographically for
    /// deterministic output (iteration order of the backing `HashMap` is not
    /// stable across runs).
    #[must_use]
    pub fn all_strings(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.string_idx.keys().map(String::as_str).collect();
        v.sort_unstable();
        v
    }

    /// All known import names in the index, sorted lexicographically for
    /// deterministic output (iteration order of the backing `HashMap` is not
    /// stable across runs).
    #[must_use]
    pub fn all_imports(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.import_idx.keys().map(String::as_str).collect();
        v.sort_unstable();
        v
    }

    // ── Removal ───────────────────────────────────────────────────────────────

    /// Remove all xrefs originating at `from`. Returns count removed.
    pub fn remove_from(&mut self, from: u64) -> usize {
        let removed = self.from_idx.remove(&from).map_or(0, |v| v.len());
        if removed > 0 {
            for v in self.to_idx.values_mut() {
                v.retain(|e| e.from != from);
            }
            self.to_idx.retain(|_, v| !v.is_empty());
            self.rebuild_secondary();
            self.total = self.total.saturating_sub(removed);
        }
        removed
    }

    /// Remove all xrefs pointing to `to`. Returns count removed.
    pub fn remove_to(&mut self, to: u64) -> usize {
        let removed = self.to_idx.remove(&to).map_or(0, |v| v.len());
        if removed > 0 {
            for v in self.from_idx.values_mut() {
                v.retain(|e| e.to != to);
            }
            self.from_idx.retain(|_, v| !v.is_empty());
            self.rebuild_secondary();
            self.total = self.total.saturating_sub(removed);
        }
        removed
    }

    fn rebuild_secondary(&mut self) {
        self.kind_idx.clear();
        self.string_idx.clear();
        self.import_idx.clear();
        self.type_idx.clear();
        for entry in self.from_idx.values().flat_map(|v| v.iter()) {
            self.kind_idx.entry(entry.kind).or_default().insert((entry.from, entry.to));
            if entry.kind == XrefEntryKind::StringRef
                && let Some(tag) = &entry.tag {
                    self.string_idx.entry(tag.clone()).or_default().insert(entry.from);
                }
            if entry.kind == XrefEntryKind::Import
                && let Some(tag) = &entry.tag {
                    self.import_idx.entry(tag.clone()).or_default().insert(entry.from);
                }
            if entry.kind == XrefEntryKind::TypeRef
                && let Some(tag) = &entry.tag {
                    self.type_idx.entry(tag.clone()).or_default().insert(entry.from);
                }
        }
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    /// Total xref count.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.total
    }

    /// Number of unique source addresses.
    #[must_use]
    pub fn unique_sources(&self) -> usize {
        self.from_idx.len()
    }

    /// Number of unique target addresses.
    #[must_use]
    pub fn unique_targets(&self) -> usize {
        self.to_idx.len()
    }

    /// Whether the index is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Compute statistics snapshot.
    #[must_use]
    pub fn stats(&self) -> IndexStats {
        let mut by_kind: HashMap<String, usize> = HashMap::new();
        let mut call_count = 0usize;
        let mut jump_count = 0usize;
        let mut data_count = 0usize;
        for entry in self.from_idx.values().flat_map(|v| v.iter()) {
            *by_kind.entry(entry.kind.to_string()).or_insert(0) += 1;
            match entry.kind {
                XrefEntryKind::Call | XrefEntryKind::Thunk => call_count += 1,
                XrefEntryKind::Jump => jump_count += 1,
                XrefEntryKind::DataPointer
                | XrefEntryKind::DataAddress
                | XrefEntryKind::DataRead
                | XrefEntryKind::DataWrite => data_count += 1,
                XrefEntryKind::StringRef | XrefEntryKind::Import | XrefEntryKind::TypeRef => {}
            }
        }
        IndexStats {
            total_entries: self.total,
            unique_sources: self.unique_sources(),
            unique_targets: self.unique_targets(),
            by_kind,
            call_count,
            jump_count,
            data_count,
        }
    }

    /// Most-called targets (top N by call-xref count).
    #[must_use]
    pub fn hot_targets(&self, top_n: usize) -> Vec<(u64, usize)> {
        let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
        for entry in self.from_idx.values().flat_map(|v| v.iter()) {
            if entry.kind == XrefEntryKind::Call {
                *counts.entry(entry.to).or_insert(0) += 1;
            }
        }
        let mut list: Vec<(u64, usize)> = counts.into_iter().collect();
        list.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        list.truncate(top_n);
        list
    }

    /// Iterate over all entries.
    pub fn iter_all(&self) -> impl Iterator<Item = &XrefEntry> {
        self.from_idx.values().flat_map(|v| v.iter())
    }

    /// Merge another index into this one.
    pub fn merge(&mut self, other: Self) {
        for entry in other.from_idx.into_values().flatten() {
            self.add(entry);
        }
    }

    /// Build a fully-populated index in a **single** linear scan over `code`.
    ///
    /// This is the persistent-index counterpart to the per-query linear scans
    /// callers used to perform: scan the code section once, bucket every
    /// detected xref into the bidirectional maps, then answer all subsequent
    /// `xrefs_to` / `xrefs_from` queries in O(1) (plus result size).
    ///
    /// Currently recognises direct `CALL rel32` (`E8`) and near `JMP rel32`
    /// (`E9`) — the same shapes scanned by
    /// [`crate::extract::extract_code_to_code`].
    #[must_use]
    pub fn build(code_base: u64, code: &[u8]) -> Self {
        let mut idx = Self::new();
        let mut i = 0usize;
        while i + 5 <= code.len() {
            let op = code[i];
            if op == 0xE8 || op == 0xE9 {
                let rel = i32::from_le_bytes([
                    code[i + 1], code[i + 2], code[i + 3], code[i + 4],
                ]);
                let Some(src) = code_base.checked_add(i as u64) else {
                    i += 1;
                    continue;
                };
                let Some(next_ip) = src.checked_add(5) else {
                    i += 1;
                    continue;
                };
                let target = next_ip.wrapping_add_signed(i64::from(rel));
                if op == 0xE8 {
                    idx.add_call(src, target, 5);
                } else {
                    idx.add_jump(src, target, 5);
                }
                i += 5;
            } else {
                i += 1;
            }
        }
        idx
    }
}

// ── Free functions ─────────────────────────────────────────────────────────────

/// Add an xref entry to the index.
pub fn add_xref(index: &mut XrefIndex, entry: XrefEntry) {
    index.add(entry);
}

/// Return all xrefs pointing to `to`.
#[must_use]
pub fn xrefs_to(index: &XrefIndex, to: u64) -> &[XrefEntry] {
    index.xrefs_to(to)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xrefs_of_kind_counts_duplicate_from_to_entries() {
        // Two distinct `add()` calls for the *same* (from, to, kind) triple
        // (e.g. re-analysis emitting the call xref twice with different
        // instr_size). `kind_idx` dedups the (from, to) pair, but
        // `xrefs_of_kind` must still surface both underlying entries so it
        // stays consistent with `total()`/`xrefs_from()`.
        let mut idx = XrefIndex::new();
        idx.add(XrefEntry::new(0x1000, 0x2000, XrefEntryKind::Call, 5));
        idx.add(XrefEntry::new(0x1000, 0x2000, XrefEntryKind::Call, 6));

        assert_eq!(idx.total(), 2);
        assert_eq!(idx.xrefs_from(0x1000).len(), 2);
        assert_eq!(
            idx.xrefs_of_kind(XrefEntryKind::Call).len(),
            2,
            "xrefs_of_kind must not silently drop duplicate (from, to) entries"
        );
    }

    // Regression: xrefs_of_kind/string_refs/import_refs/all_strings/
    // all_imports must return a stable order across repeated calls
    // (previously leaked HashMap/HashSet iteration order).
    #[test]
    fn test_index_queries_are_deterministic() {
        let mut idx = XrefIndex::new();
        idx.add(XrefEntry::new(0x3000, 0x1000, XrefEntryKind::Call, 5));
        idx.add(XrefEntry::new(0x1000, 0x2000, XrefEntryKind::Call, 5));
        idx.add(XrefEntry::new(0x2000, 0x4000, XrefEntryKind::Call, 5));
        idx.add(XrefEntry::with_tag(0x1000, 0x5000, XrefEntryKind::StringRef, 0, "zeta"));
        idx.add(XrefEntry::with_tag(0x1010, 0x5010, XrefEntryKind::StringRef, 0, "alpha"));
        idx.add(XrefEntry::with_tag(0x1000, 0x6000, XrefEntryKind::Import, 0, "Zeta32"));
        idx.add(XrefEntry::with_tag(0x1010, 0x6010, XrefEntryKind::Import, 0, "Alpha32"));

        let of_kind1: Vec<(u64, u64)> = idx
            .xrefs_of_kind(XrefEntryKind::Call)
            .iter()
            .map(|e| (e.from, e.to))
            .collect();
        let strings1 = idx.string_refs("zeta");
        let all_strings1 = idx.all_strings();
        let all_imports1 = idx.all_imports();
        for _ in 0..5 {
            let again: Vec<(u64, u64)> = idx
                .xrefs_of_kind(XrefEntryKind::Call)
                .iter()
                .map(|e| (e.from, e.to))
                .collect();
            assert_eq!(again, of_kind1);
            assert_eq!(idx.string_refs("zeta"), strings1);
            assert_eq!(idx.all_strings(), all_strings1);
            assert_eq!(idx.all_imports(), all_imports1);
        }
        let mut sorted_strings = all_strings1.clone();
        sorted_strings.sort_unstable();
        assert_eq!(all_strings1, sorted_strings);
        let mut sorted_imports = all_imports1.clone();
        sorted_imports.sort_unstable();
        assert_eq!(all_imports1, sorted_imports);
    }

    #[test]
    fn test_entry_kind_is_code_flow() {
        assert!(XrefEntryKind::Call.is_code_flow());
        assert!(XrefEntryKind::Jump.is_code_flow());
        assert!(!XrefEntryKind::DataRead.is_code_flow());
    }

    #[test]
    fn test_entry_kind_is_data() {
        assert!(XrefEntryKind::DataRead.is_data());
        assert!(!XrefEntryKind::Call.is_data());
    }

    #[test]
    fn test_entry_kind_display() {
        assert_eq!(XrefEntryKind::Call.to_string(), "Call");
        assert_eq!(XrefEntryKind::StringRef.to_string(), "StringRef");
    }

    #[test]
    fn test_entry_new() {
        let e = XrefEntry::new(0x1000, 0x2000, XrefEntryKind::Call, 5);
        assert_eq!(e.from, 0x1000);
        assert_eq!(e.to, 0x2000);
        assert!(e.tag.is_none());
    }

    #[test]
    fn test_entry_with_tag() {
        let e = XrefEntry::with_tag(0x1000, 0x2000, XrefEntryKind::Import, 0, "LoadLibraryA");
        assert_eq!(e.tag.as_deref(), Some("LoadLibraryA"));
    }

    #[test]
    fn test_entry_display() {
        let e = XrefEntry::new(0x1000, 0x2000, XrefEntryKind::Call, 5);
        let s = e.to_string();
        assert!(s.contains("0x00001000"));
        assert!(s.contains("Call"));
    }

    #[test]
    fn test_index_add_and_lookup() {
        let mut idx = XrefIndex::new();
        idx.add_call(0x1000, 0x2000, 5);
        assert_eq!(idx.total(), 1);
        assert_eq!(idx.xrefs_from(0x1000).len(), 1);
        assert_eq!(idx.xrefs_to(0x2000).len(), 1);
    }

    #[test]
    fn test_index_callers() {
        let mut idx = XrefIndex::new();
        idx.add_call(0x1000, 0x3000, 5);
        idx.add_call(0x2000, 0x3000, 5);
        let callers = idx.callers_of(0x3000);
        assert_eq!(callers.len(), 2);
        assert!(callers.contains(&0x1000));
        assert!(callers.contains(&0x2000));
    }

    #[test]
    fn test_index_callees() {
        let mut idx = XrefIndex::new();
        idx.add_call(0x1000, 0x3000, 5);
        idx.add_call(0x1000, 0x4000, 5);
        let callees = idx.callees_of(0x1000);
        assert_eq!(callees.len(), 2);
    }

    #[test]
    fn test_index_string_refs() {
        let mut idx = XrefIndex::new();
        idx.add_string_ref(0x1000, 0x5000, "hello world");
        idx.add_string_ref(0x2000, 0x5000, "hello world");
        let refs = idx.string_refs("hello world");
        assert_eq!(refs.len(), 2);
    }

    #[test]
    fn test_index_import_refs() {
        let mut idx = XrefIndex::new();
        idx.add_import(0x1000, 0x6000, "CreateFileA");
        let refs = idx.import_refs("CreateFileA");
        assert_eq!(refs.len(), 1);
    }

    #[test]
    fn test_index_all_strings() {
        let mut idx = XrefIndex::new();
        idx.add_string_ref(0x1000, 0x5000, "foo");
        idx.add_string_ref(0x2000, 0x6000, "bar");
        let strs = idx.all_strings();
        assert_eq!(strs.len(), 2);
    }

    #[test]
    fn test_index_remove_from() {
        let mut idx = XrefIndex::new();
        idx.add_call(0x1000, 0x2000, 5);
        idx.add_call(0x1000, 0x3000, 5);
        let n = idx.remove_from(0x1000);
        assert_eq!(n, 2);
        assert_eq!(idx.total(), 0);
    }

    #[test]
    fn test_index_remove_to() {
        let mut idx = XrefIndex::new();
        idx.add_call(0x1000, 0x9000, 5);
        idx.add_call(0x2000, 0x9000, 5);
        let n = idx.remove_to(0x9000);
        assert_eq!(n, 2);
        assert_eq!(idx.total(), 0);
    }

    #[test]
    fn test_index_stats() {
        let mut idx = XrefIndex::new();
        idx.add_call(0x1000, 0x2000, 5);
        idx.add_jump(0x1005, 0x1010, 2);
        idx.add_data_read(0x1010, 0x4000);
        let stats = idx.stats();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.call_count, 1);
        assert_eq!(stats.jump_count, 1);
        assert_eq!(stats.data_count, 1);
    }

    #[test]
    fn test_index_hot_targets() {
        let mut idx = XrefIndex::new();
        idx.add_call(0x1000, 0x9000, 5);
        idx.add_call(0x2000, 0x9000, 5);
        idx.add_call(0x3000, 0x9000, 5);
        idx.add_call(0x4000, 0x8000, 5);
        let hot = idx.hot_targets(2);
        assert_eq!(hot[0], (0x9000, 3));
    }

    #[test]
    fn test_index_merge() {
        let mut a = XrefIndex::new();
        a.add_call(0x1000, 0x2000, 5);
        let mut b = XrefIndex::new();
        b.add_call(0x3000, 0x4000, 5);
        a.merge(b);
        assert_eq!(a.total(), 2);
    }

    #[test]
    fn test_add_xref_free_fn() {
        let mut idx = XrefIndex::new();
        let e = XrefEntry::new(0x1, 0x2, XrefEntryKind::Jump, 2);
        add_xref(&mut idx, e);
        assert_eq!(idx.total(), 1);
    }

    #[test]
    fn test_xrefs_to_free_fn() {
        let mut idx = XrefIndex::new();
        idx.add_call(0x1000, 0x7000, 5);
        let refs = xrefs_to(&idx, 0x7000);
        assert_eq!(refs.len(), 1);
    }

    #[test]
    fn test_index_is_empty() {
        let idx = XrefIndex::new();
        assert!(idx.is_empty());
    }

    #[test]
    fn test_index_unique_counts() {
        let mut idx = XrefIndex::new();
        idx.add_call(0x1000, 0x2000, 5);
        idx.add_call(0x1000, 0x3000, 5); // same source, 2 targets
        assert_eq!(idx.unique_sources(), 1);
        assert_eq!(idx.unique_targets(), 2);
    }

    #[test]
    fn test_index_all_imports() {
        let mut idx = XrefIndex::new();
        idx.add_import(0x1000, 0x5000, "malloc");
        idx.add_import(0x2000, 0x6000, "free");
        let imports = idx.all_imports();
        assert_eq!(imports.len(), 2);
    }

    #[test]
    fn test_xrefs_of_kind_distinct_targets_from_same_source() {
        // Regression: a single `from` with multiple same-kind xrefs to
        // different targets must each be reported individually, not
        // collapsed onto the first entry found for that `from`.
        let mut idx = XrefIndex::new();
        idx.add_call(0x1000, 0x2000, 5);
        idx.add_call(0x1000, 0x3000, 5);
        idx.add_call(0x1000, 0x4000, 5);
        let mut targets: Vec<u64> = idx
            .xrefs_of_kind(XrefEntryKind::Call)
            .iter()
            .map(|e| e.to)
            .collect();
        targets.sort_unstable();
        assert_eq!(targets, vec![0x2000, 0x3000, 0x4000]);
    }

    #[test]
    fn test_entry_kind_all() {
        let all = XrefEntryKind::all();
        assert!(!all.is_empty());
        assert!(all.contains(&XrefEntryKind::Call));
    }

    #[test]
    fn test_build_one_shot_scan_populates_bidirectional_maps() {
        // E8 call rel32 at 0: next=0x1005, rel=+0x10 -> 0x1015.
        // E9 jmp  rel32 at 5: next=0x100A, rel=-0x10 -> 0xFFA.
        let mut code = vec![0xE8, 0x10, 0x00, 0x00, 0x00];
        code.extend_from_slice(&[0xE9]);
        code.extend_from_slice(&(-0x10i32).to_le_bytes());
        let idx = XrefIndex::build(0x1000, &code);
        assert_eq!(idx.total(), 2);
        // Reverse lookup: call target has the call source.
        assert_eq!(idx.xrefs_to(0x1015).len(), 1);
        assert_eq!(idx.xrefs_to(0x1015)[0].from, 0x1000);
        assert_eq!(idx.xrefs_to(0x1015)[0].kind, XrefEntryKind::Call);
        // Forward lookup: jump source has the jump.
        assert_eq!(idx.xrefs_from(0x1005).len(), 1);
        assert_eq!(idx.xrefs_from(0x1005)[0].to, 0xFFA);
        assert_eq!(idx.xrefs_from(0x1005)[0].kind, XrefEntryKind::Jump);
    }

    #[test]
    fn test_stats_format_report() {
        let mut idx = XrefIndex::new();
        idx.add_call(0x1000, 0x2000, 5);
        let stats = idx.stats();
        let report = stats.format_report();
        assert!(report.contains("Total xrefs"));
        assert!(report.contains("Calls"));
    }
}
