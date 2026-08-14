//! Trace bookmark management.
//!
//! Add/remove/list bookmarks at trace positions, categorize bookmarks (function
//! entry, interesting write, anomaly), search by category/label, import/export
//! bookmarks, bookmark diff between sessions.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{Address, NavError};

// ── BookmarkCategory ──────────────────────────────────────────────────────────

/// Category tag for a bookmark.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BookmarkCategory {
    /// Marks the entry to a function.
    FunctionEntry,
    /// Marks an interesting or suspicious memory write.
    InterestingWrite,
    /// Marks a detected anomaly (e.g. unexpected branch, null deref).
    Anomaly,
    /// Marks a crash or fault point.
    Crash,
    /// User-defined label.
    UserLabel(String),
    /// Generic / uncategorized.
    Generic,
}

impl BookmarkCategory {
    /// Return a short string identifier for the category.
    #[must_use]
    pub const fn tag(&self) -> &str {
        match self {
            Self::FunctionEntry => "fn_entry",
            Self::InterestingWrite => "interesting_write",
            Self::Anomaly => "anomaly",
            Self::Crash => "crash",
            Self::UserLabel(s) => s.as_str(),
            Self::Generic => "generic",
        }
    }

    /// Construct from a tag string.
    #[must_use]
    pub fn from_tag(s: &str) -> Self {
        match s {
            "fn_entry" => Self::FunctionEntry,
            "interesting_write" => Self::InterestingWrite,
            "anomaly" => Self::Anomaly,
            "crash" => Self::Crash,
            "generic" => Self::Generic,
            other => Self::UserLabel(other.to_string()),
        }
    }

    /// Returns `true` if this is the given simple category.
    #[must_use]
    pub const fn is_function_entry(&self) -> bool { matches!(self, Self::FunctionEntry) }

    /// Returns `true` if this is an anomaly.
    #[must_use]
    pub const fn is_anomaly(&self) -> bool { matches!(self, Self::Anomaly) }
}

impl std::fmt::Display for BookmarkCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.tag())
    }
}

// ── Bookmark ──────────────────────────────────────────────────────────────────

/// A named, categorized position in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    /// Unique identifier (label).
    pub label: String,
    /// Trace index.
    pub trace_idx: usize,
    /// Program counter at this position.
    pub pc: Address,
    /// Category.
    pub category: BookmarkCategory,
    /// Optional free-text note.
    pub note: String,
    /// User-defined color (for UI rendering), stored as RGBA u32.
    pub color: u32,
    /// Thread ID at this point.
    pub tid: u32,
    /// Sequence number (order within the session).
    pub seq: u32,
}

impl Bookmark {
    /// Create a new generic bookmark.
    #[must_use]
    pub fn new(label: impl Into<String>, trace_idx: usize, pc: Address) -> Self {
        Self {
            label: label.into(),
            trace_idx,
            pc,
            category: BookmarkCategory::Generic,
            note: String::new(),
            color: 0xFFFF_FFFF,
            tid: 0,
            seq: 0,
        }
    }

    /// Set the category.
    #[must_use]
    pub fn with_category(mut self, cat: BookmarkCategory) -> Self {
        self.category = cat;
        self
    }

    /// Attach a note.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = note.into();
        self
    }

    /// Set the RGBA color.
    #[must_use]
    pub const fn with_color(mut self, rgba: u32) -> Self {
        self.color = rgba;
        self
    }

    /// Set the thread ID.
    #[must_use]
    pub const fn with_tid(mut self, tid: u32) -> Self {
        self.tid = tid;
        self
    }
}

impl std::fmt::Display for Bookmark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] idx={} pc=0x{:x} cat={}", self.label, self.trace_idx, self.pc, self.category)
    }
}

// ── BookmarkQuery ─────────────────────────────────────────────────────────────

/// Query parameters for searching bookmarks.
#[derive(Debug, Clone, Default)]
pub struct BookmarkQuery {
    /// Filter by category (None = any category).
    pub category: Option<BookmarkCategory>,
    /// Filter by label substring.
    pub label_contains: Option<String>,
    /// Filter by trace index range [min, max] (inclusive).
    pub idx_range: Option<(usize, usize)>,
    /// Filter by PC range.
    pub pc_range: Option<(Address, Address)>,
    /// Filter by thread ID.
    pub tid: Option<u32>,
    /// Maximum number of results.
    pub limit: Option<usize>,
}

impl BookmarkQuery {
    /// Create an empty query (matches everything).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by category.
    #[must_use]
    pub fn category(mut self, cat: BookmarkCategory) -> Self {
        self.category = Some(cat);
        self
    }

    /// Filter by label substring.
    #[must_use]
    pub fn label(mut self, s: impl Into<String>) -> Self {
        self.label_contains = Some(s.into());
        self
    }

    /// Filter by trace index range.
    #[must_use]
    pub const fn idx_range(mut self, min: usize, max: usize) -> Self {
        self.idx_range = Some((min, max));
        self
    }

    /// Limit results.
    #[must_use]
    pub const fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Test whether `bm` matches this query.
    #[must_use]
    pub fn matches(&self, bm: &Bookmark) -> bool {
        if let Some(ref cat) = self.category
            && &bm.category != cat {
                return false;
            }
        if let Some(ref sub) = self.label_contains
            && !bm.label.contains(sub.as_str()) {
                return false;
            }
        if let Some((min, max)) = self.idx_range
            && (bm.trace_idx < min || bm.trace_idx > max) {
                return false;
            }
        if let Some((lo, hi)) = self.pc_range
            && (bm.pc < lo || bm.pc > hi) {
                return false;
            }
        if let Some(tid) = self.tid
            && bm.tid != tid {
                return false;
            }
        true
    }
}

// ── BookmarkSet ───────────────────────────────────────────────────────────────

/// An ordered, serializable set of bookmarks for one session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BookmarkSet {
    pub session_name: String,
    pub bookmarks: Vec<Bookmark>,
}

impl BookmarkSet {
    /// Create a new set.
    #[must_use]
    pub fn new(session_name: impl Into<String>) -> Self {
        Self { session_name: session_name.into(), bookmarks: Vec::new() }
    }

    /// Add a bookmark.
    pub fn add(&mut self, bm: Bookmark) {
        self.bookmarks.push(bm);
    }

    /// Number of bookmarks.
    #[must_use]
    pub const fn len(&self) -> usize { self.bookmarks.len() }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.bookmarks.is_empty() }

    /// All labels.
    #[must_use]
    pub fn labels(&self) -> Vec<&str> {
        self.bookmarks.iter().map(|b| b.label.as_str()).collect()
    }

    /// Find bookmark by exact label.
    #[must_use]
    pub fn find_by_label(&self, label: &str) -> Option<&Bookmark> {
        self.bookmarks.iter().find(|b| b.label == label)
    }

    /// Serialize to JSON (using std only via a simple hand-rolled format).
    #[must_use]
    pub fn to_json(&self) -> String {
        let entries: Vec<String> = self.bookmarks.iter().map(|b| {
            format!(
                r#"{{"label":"{}","trace_idx":{},"pc":{},"category":"{}","note":"{}","tid":{}}}"#,
                b.label.replace('"', "\\\""),
                b.trace_idx, b.pc, b.category.tag(),
                b.note.replace('"', "\\\""), b.tid
            )
        }).collect();
        format!(r#"{{"session":"{}","bookmarks":[{}]}}"#,
            self.session_name.replace('"', "\\\""),
            entries.join(",")
        )
    }

    /// Compute a diff between `self` and `other`.
    /// Returns (`only_in_self`, `only_in_other`, `in_both_by_label`).
    #[must_use]
    pub fn diff<'a>(&'a self, other: &'a Self) -> BookmarkDiff<'a> {
        let self_labels: std::collections::HashSet<&str> =
            self.bookmarks.iter().map(|b| b.label.as_str()).collect();
        let other_labels: std::collections::HashSet<&str> =
            other.bookmarks.iter().map(|b| b.label.as_str()).collect();

        let only_in_self = self.bookmarks.iter()
            .filter(|b| !other_labels.contains(b.label.as_str())).collect();
        let only_in_other = other.bookmarks.iter()
            .filter(|b| !self_labels.contains(b.label.as_str())).collect();
        let in_both = self.bookmarks.iter()
            .filter(|b| other_labels.contains(b.label.as_str())).collect();

        BookmarkDiff { only_in_self, only_in_other, in_both }
    }
}

/// Result of diffing two bookmark sets.
#[derive(Debug)]
pub struct BookmarkDiff<'a> {
    pub only_in_self: Vec<&'a Bookmark>,
    pub only_in_other: Vec<&'a Bookmark>,
    pub in_both: Vec<&'a Bookmark>,
}

impl BookmarkDiff<'_> {
    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "BookmarkDiff: only_in_a={} only_in_b={} shared={}",
            self.only_in_self.len(), self.only_in_other.len(), self.in_both.len()
        )
    }
}

// ── BookmarkManager ───────────────────────────────────────────────────────────

/// Full bookmark manager for a trace session.
pub struct BookmarkManager {
    /// Bookmarks indexed by label.
    store: HashMap<String, Bookmark>,
    /// Sequence counter.
    next_seq: u32,
    /// Session name.
    pub session_name: String,
}

impl BookmarkManager {
    /// Create a new manager.
    #[must_use]
    pub fn new(session_name: impl Into<String>) -> Self {
        Self { store: HashMap::new(), next_seq: 0, session_name: session_name.into() }
    }

    /// Add a bookmark; returns its assigned sequence number.
    ///
    /// If a bookmark with this label already exists, it is replaced.
    pub fn add(&mut self, mut bm: Bookmark) -> u32 {
        let seq = self.next_seq;
        self.next_seq += 1;
        bm.seq = seq;
        self.store.insert(bm.label.clone(), bm);
        seq
    }

    /// Add a bookmark at a trace position with a given category.
    pub fn add_at(
        &mut self,
        label: impl Into<String>,
        trace_idx: usize,
        pc: Address,
        category: BookmarkCategory,
        note: impl Into<String>,
    ) -> u32 {
        let bm = Bookmark::new(label, trace_idx, pc)
            .with_category(category)
            .with_note(note);
        self.add(bm)
    }

    /// Remove a bookmark by label.
    ///
    /// # Errors
    /// Returns `NavError::BookmarkNotFound` if not found.
    pub fn remove(&mut self, label: &str) -> Result<Bookmark, NavError> {
        self.store.remove(label).ok_or_else(|| NavError::BookmarkNotFound(label.to_string()))
    }

    /// Get a bookmark by label.
    #[must_use]
    pub fn get(&self, label: &str) -> Option<&Bookmark> {
        self.store.get(label)
    }

    /// Number of bookmarks.
    #[must_use]
    pub fn len(&self) -> usize { self.store.len() }

    /// Returns `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.store.is_empty() }

    /// All bookmarks sorted by trace index.
    #[must_use]
    pub fn sorted_by_idx(&self) -> Vec<&Bookmark> {
        let mut v: Vec<&Bookmark> = self.store.values().collect();
        v.sort_by_key(|b| b.trace_idx);
        v
    }

    /// All bookmarks sorted by sequence number.
    #[must_use]
    pub fn sorted_by_seq(&self) -> Vec<&Bookmark> {
        let mut v: Vec<&Bookmark> = self.store.values().collect();
        v.sort_by_key(|b| b.seq);
        v
    }

    /// Search bookmarks with a query.
    #[must_use]
    pub fn search(&self, query: &BookmarkQuery) -> Vec<&Bookmark> {
        let mut results: Vec<&Bookmark> = self.store.values()
            .filter(|b| query.matches(b))
            .collect();
        results.sort_by_key(|b| b.trace_idx);
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }
        results
    }

    /// Find the nearest bookmark at or after `trace_idx`.
    #[must_use]
    pub fn next_after(&self, trace_idx: usize) -> Option<&Bookmark> {
        self.store.values()
            .filter(|b| b.trace_idx > trace_idx)
            .min_by_key(|b| b.trace_idx)
    }

    /// Find the nearest bookmark before `trace_idx`.
    #[must_use]
    pub fn prev_before(&self, trace_idx: usize) -> Option<&Bookmark> {
        self.store.values()
            .filter(|b| b.trace_idx < trace_idx)
            .max_by_key(|b| b.trace_idx)
    }

    /// All bookmarks in a given category.
    #[must_use]
    pub fn by_category(&self, cat: &BookmarkCategory) -> Vec<&Bookmark> {
        self.search(&BookmarkQuery::new().category(cat.clone()))
    }

    /// Export to a `BookmarkSet`.
    #[must_use]
    pub fn export(&self) -> BookmarkSet {
        let mut set = BookmarkSet::new(&self.session_name);
        let mut sorted = self.sorted_by_seq();
        sorted.sort_by_key(|b| b.seq);
        for bm in sorted {
            set.add(bm.clone());
        }
        set
    }

    /// Import from a `BookmarkSet`, replacing all existing bookmarks.
    pub fn import(&mut self, set: &BookmarkSet) {
        self.store.clear();
        self.next_seq = 0;
        for bm in &set.bookmarks {
            self.add(bm.clone());
        }
    }

    /// Merge bookmarks from another manager (duplicates resolved by keeping higher seq).
    pub fn merge(&mut self, other: &Self) {
        for (label, bm) in &other.store {
            self.store.entry(label.clone()).and_modify(|existing| {
                if bm.seq > existing.seq {
                    *existing = bm.clone();
                }
            }).or_insert_with(|| bm.clone());
        }
    }

    /// Rename a bookmark label.
    ///
    /// # Errors
    /// Returns `NavError::BookmarkNotFound` if the old label does not exist.
    pub fn rename_label(&mut self, old: &str, new: impl Into<String>) -> Result<(), NavError> {
        let mut bm = self.remove(old)?;
        bm.label = new.into();
        self.store.insert(bm.label.clone(), bm);
        Ok(())
    }

    /// Update the note on an existing bookmark.
    ///
    /// # Errors
    /// Returns `NavError::BookmarkNotFound` if the label does not exist.
    pub fn update_note(&mut self, label: &str, note: impl Into<String>) -> Result<(), NavError> {
        let bm = self.store.get_mut(label)
            .ok_or_else(|| NavError::BookmarkNotFound(label.to_string()))?;
        bm.note = note.into();
        Ok(())
    }

    /// Count bookmarks per category.
    #[must_use]
    pub fn category_counts(&self) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for bm in self.store.values() {
            *counts.entry(bm.category.tag().to_string()).or_insert(0) += 1;
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get() {
        let mut mgr = BookmarkManager::new("test");
        mgr.add_at("entry", 10, 0x1000, BookmarkCategory::FunctionEntry, "func start");
        let bm = mgr.get("entry").unwrap();
        assert_eq!(bm.trace_idx, 10);
        assert_eq!(bm.pc, 0x1000);
        assert!(bm.category.is_function_entry());
    }

    #[test]
    fn test_remove() {
        let mut mgr = BookmarkManager::new("t");
        mgr.add_at("x", 5, 0x500, BookmarkCategory::Generic, "");
        assert!(mgr.remove("x").is_ok());
        assert!(mgr.remove("x").is_err());
    }

    #[test]
    fn test_search_by_category() {
        let mut mgr = BookmarkManager::new("t");
        mgr.add_at("a", 1, 0x100, BookmarkCategory::Anomaly, "");
        mgr.add_at("b", 2, 0x200, BookmarkCategory::FunctionEntry, "");
        let q = BookmarkQuery::new().category(BookmarkCategory::Anomaly);
        let results = mgr.search(&q);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].label, "a");
    }

    #[test]
    fn test_next_after_prev_before() {
        let mut mgr = BookmarkManager::new("t");
        mgr.add_at("early", 5, 0x500, BookmarkCategory::Generic, "");
        mgr.add_at("late", 50, 0x5000, BookmarkCategory::Generic, "");
        let next = mgr.next_after(10).unwrap();
        assert_eq!(next.label, "late");
        let prev = mgr.prev_before(40).unwrap();
        assert_eq!(prev.label, "early");
    }

    #[test]
    fn test_export_import() {
        let mut mgr = BookmarkManager::new("s1");
        mgr.add_at("bm1", 10, 0x100, BookmarkCategory::Crash, "crash here");
        let set = mgr.export();
        assert_eq!(set.bookmarks.len(), 1);
        let mut mgr2 = BookmarkManager::new("s2");
        mgr2.import(&set);
        assert!(mgr2.get("bm1").is_some());
    }

    #[test]
    fn test_bookmark_set_diff() {
        let mut s1 = BookmarkSet::new("a");
        s1.add(Bookmark::new("x", 1, 0x100));
        s1.add(Bookmark::new("shared", 5, 0x500));
        let mut s2 = BookmarkSet::new("b");
        s2.add(Bookmark::new("y", 2, 0x200));
        s2.add(Bookmark::new("shared", 5, 0x500));
        let diff = s1.diff(&s2);
        assert_eq!(diff.only_in_self.len(), 1);
        assert_eq!(diff.only_in_other.len(), 1);
        assert_eq!(diff.in_both.len(), 1);
    }

    #[test]
    fn test_category_counts() {
        let mut mgr = BookmarkManager::new("t");
        mgr.add_at("a", 1, 0x1, BookmarkCategory::Anomaly, "");
        mgr.add_at("b", 2, 0x2, BookmarkCategory::Anomaly, "");
        mgr.add_at("c", 3, 0x3, BookmarkCategory::FunctionEntry, "");
        let counts = mgr.category_counts();
        assert_eq!(counts["anomaly"], 2);
        assert_eq!(counts["fn_entry"], 1);
    }

    #[test]
    fn test_bookmark_set_to_json() {
        let mut set = BookmarkSet::new("sess");
        set.add(Bookmark::new("pt1", 100, 0xDEAD));
        let json = set.to_json();
        assert!(json.contains("pt1"));
        assert!(json.contains("sess"));
    }
}
