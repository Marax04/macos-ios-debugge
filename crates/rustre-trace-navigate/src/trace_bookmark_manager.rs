//! `trace_bookmark_manager` — Rich bookmark management for execution traces.
//!
//! Provides [`TraceBookmarkManager`] which extends the basic `BookmarkStore`
//! with categories, tags, search, import/export, and navigation history.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{Address, Bookmark, BookmarkStore, NavError};

// ─── BookmarkPosition ────────────────────────────────────────────────────────

/// The position a bookmark refers to, supporting both index-based and address-based references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BookmarkPosition {
    /// A specific trace index.
    TraceIndex(usize),
    /// An instruction address (will be resolved to the nearest trace index).
    Address(Address),
    /// Both a trace index and a PC address.
    Both { trace_idx: usize, pc: Address },
}

impl BookmarkPosition {
    /// Extract the trace index if available.
    #[must_use]
    pub const fn trace_idx(&self) -> Option<usize> {
        match self {
            Self::TraceIndex(i) | Self::Both { trace_idx: i, .. } => Some(*i),
            Self::Address(_) => None,
        }
    }

    /// Extract the address if available.
    #[must_use]
    pub const fn address(&self) -> Option<Address> {
        match self {
            Self::Address(a) | Self::Both { pc: a, .. } => Some(*a),
            Self::TraceIndex(_) => None,
        }
    }
}

impl std::fmt::Display for BookmarkPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TraceIndex(i) => write!(f, "idx={i}"),
            Self::Address(a) => write!(f, "pc=0x{a:x}"),
            Self::Both { trace_idx, pc } => write!(f, "idx={trace_idx} pc=0x{pc:x}"),
        }
    }
}

// ─── BookmarkCategory ────────────────────────────────────────────────────────

/// Category of a bookmark.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BookmarkCategory {
    /// Marks the start of a function.
    FunctionEntry,
    /// Marks the return of a function.
    FunctionReturn,
    /// Marks a call site of interest.
    CallSite,
    /// Marks a crash or exception point.
    CrashSite,
    /// Marks a security-relevant sink.
    SecuritySink,
    /// User-defined analysis note.
    AnalysisNote,
    /// Marks a loop entry.
    LoopHead,
    /// Marks a branch of interest.
    BranchPoint,
    /// Temporary / scratch bookmark.
    Scratch,
    /// Custom category.
    Custom(String),
}

impl BookmarkCategory {
    /// Short label.
    #[must_use]
    pub const fn label(&self) -> &str {
        match self {
            Self::FunctionEntry => "fn_entry",
            Self::FunctionReturn => "fn_return",
            Self::CallSite => "call_site",
            Self::CrashSite => "crash",
            Self::SecuritySink => "security",
            Self::AnalysisNote => "note",
            Self::LoopHead => "loop",
            Self::BranchPoint => "branch",
            Self::Scratch => "scratch",
            Self::Custom(s) => s.as_str(),
        }
    }
}

// ─── TraceBookmark ───────────────────────────────────────────────────────────

/// A rich bookmark combining name, position, category, tags and note.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBookmark {
    /// Unique name.
    pub name: String,
    /// Position in the trace.
    pub position: BookmarkPosition,
    /// Category.
    pub category: BookmarkCategory,
    /// Free-form tags.
    pub tags: HashSet<String>,
    /// Optional analyst note.
    pub note: Option<String>,
    /// Colour hint for the UI (e.g. `"red"`, `"#ff0000"`).
    pub colour: Option<String>,
    /// Whether this bookmark is pinned (will not be deleted by bulk clears).
    pub pinned: bool,
    /// Creation timestamp (Unix seconds, if available).
    pub created_at: Option<u64>,
}

impl TraceBookmark {
    /// Create a minimal bookmark.
    #[must_use]
    pub fn new(name: impl Into<String>, position: BookmarkPosition) -> Self {
        Self {
            name: name.into(),
            position,
            category: BookmarkCategory::AnalysisNote,
            tags: HashSet::new(),
            note: None,
            colour: None,
            pinned: false,
            created_at: None,
        }
    }

    /// Set the category.
    #[must_use]
    pub fn with_category(mut self, cat: BookmarkCategory) -> Self {
        self.category = cat;
        self
    }

    /// Add a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.insert(tag.into());
        self
    }

    /// Set a note.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Set a colour hint.
    #[must_use]
    pub fn with_colour(mut self, colour: impl Into<String>) -> Self {
        self.colour = Some(colour.into());
        self
    }

    /// Pin this bookmark.
    #[must_use]
    pub const fn pinned(mut self) -> Self {
        self.pinned = true;
        self
    }

    /// Whether this bookmark has the given tag.
    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }

    /// One-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let tags = if self.tags.is_empty() {
            String::new()
        } else {
            let mut t: Vec<&str> = self.tags.iter().map(String::as_str).collect();
            t.sort_unstable();
            format!(" [{}]", t.join(", "))
        };
        let note = self
            .note
            .as_deref()
            .map_or(String::new(), |n| format!(" — {n}"));
        format!(
            "{} ({}) {}{}{}",
            self.name,
            self.category.label(),
            self.position,
            tags,
            note
        )
    }
}

impl std::fmt::Display for TraceBookmark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ─── BookmarkQuery ───────────────────────────────────────────────────────────

/// Filter for searching bookmarks.
#[derive(Debug, Clone, Default)]
pub struct BookmarkQuery {
    /// Only return bookmarks with this category.
    pub category: Option<BookmarkCategory>,
    /// Only return bookmarks that have all of these tags.
    pub required_tags: Vec<String>,
    /// Only return bookmarks whose name contains this substring.
    pub name_contains: Option<String>,
    /// Only return bookmarks within this trace index range.
    pub trace_range: Option<(usize, usize)>,
    /// Only return bookmarks at this PC address.
    pub at_addr: Option<Address>,
    /// Only return pinned bookmarks.
    pub pinned_only: bool,
}

impl BookmarkQuery {
    /// Match a bookmark against this query.
    #[must_use]
    pub fn matches(&self, bm: &TraceBookmark) -> bool {
        if let Some(ref cat) = self.category
            && &bm.category != cat {
                return false;
            }
        for tag in &self.required_tags {
            if !bm.has_tag(tag) {
                return false;
            }
        }
        if let Some(ref sub) = self.name_contains
            && !bm.name.contains(sub.as_str()) {
                return false;
            }
        if let Some((lo, hi)) = self.trace_range
            && let Some(idx) = bm.position.trace_idx()
            && (idx < lo || idx > hi) {
                return false;
            }
        if let Some(addr) = self.at_addr {
            match bm.position.address() {
                Some(a) if a == addr => {}
                _ => return false,
            }
        }
        if self.pinned_only && !bm.pinned {
            return false;
        }
        true
    }
}

// ─── TraceBookmarkManager ────────────────────────────────────────────────────

/// Manages a rich set of bookmarks for an execution trace.
///
/// Extends `BookmarkStore` with:
/// - Categories and tags
/// - Search / filter
/// - Sequential navigation (next/previous)
/// - Group operations (clear by category, export subset)
/// - Import / export as JSON
/// - Navigation trail (recently visited bookmarks)
pub struct TraceBookmarkManager {
    /// Internal store: name → `TraceBookmark`.
    inner: HashMap<String, TraceBookmark>,
    /// Navigation trail (recently visited bookmark names, newest last).
    trail: Vec<String>,
    /// Maximum trail length.
    max_trail: usize,
    /// Current bookmark name (last navigated to).
    current: Option<String>,
}

impl TraceBookmarkManager {
    /// Create an empty manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
            trail: Vec::new(),
            max_trail: 64,
            current: None,
        }
    }

    /// Create with a custom trail length.
    #[must_use]
    pub fn with_trail_capacity(cap: usize) -> Self {
        Self {
            inner: HashMap::new(),
            trail: Vec::new(),
            max_trail: cap,
            current: None,
        }
    }

    // ── CRUD ───────────────────────────────────────────────────────────────

    /// Insert or replace a bookmark.
    pub fn insert(&mut self, bm: TraceBookmark) {
        self.inner.insert(bm.name.clone(), bm);
    }

    /// Get a bookmark by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&TraceBookmark> {
        self.inner.get(name)
    }

    /// Get a mutable reference to a bookmark.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut TraceBookmark> {
        self.inner.get_mut(name)
    }

    /// Remove a bookmark by name.
    ///
    /// # Errors
    /// [`NavError::BookmarkNotFound`] if not present.
    pub fn remove(&mut self, name: &str) -> Result<TraceBookmark, NavError> {
        self.inner
            .remove(name)
            .ok_or_else(|| NavError::BookmarkNotFound(name.to_owned()))
    }

    /// Number of bookmarks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the manager is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// All bookmark names.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.inner.keys().map(String::as_str).collect()
    }

    // ── Search ─────────────────────────────────────────────────────────────

    /// Search bookmarks matching a query.
    #[must_use]
    pub fn search(&self, query: &BookmarkQuery) -> Vec<&TraceBookmark> {
        let mut results: Vec<&TraceBookmark> =
            self.inner.values().filter(|b| query.matches(b)).collect();
        // Sort by trace index (ascending), bookmarks without an index go last.
        results.sort_by_key(|b| b.position.trace_idx().unwrap_or(usize::MAX));
        results
    }

    /// All bookmarks sorted by trace index.
    #[must_use]
    pub fn sorted_by_idx(&self) -> Vec<&TraceBookmark> {
        let mut v: Vec<&TraceBookmark> = self.inner.values().collect();
        v.sort_by_key(|b| b.position.trace_idx().unwrap_or(usize::MAX));
        v
    }

    /// All bookmarks with a specific category.
    #[must_use]
    pub fn by_category(&self, cat: &BookmarkCategory) -> Vec<&TraceBookmark> {
        self.inner
            .values()
            .filter(|b| &b.category == cat)
            .collect()
    }

    /// All bookmarks with a specific tag.
    #[must_use]
    pub fn by_tag(&self, tag: &str) -> Vec<&TraceBookmark> {
        self.inner
            .values()
            .filter(|b| b.has_tag(tag))
            .collect()
    }

    /// All pinned bookmarks.
    #[must_use]
    pub fn pinned(&self) -> Vec<&TraceBookmark> {
        self.inner.values().filter(|b| b.pinned).collect()
    }

    // ── Navigation ─────────────────────────────────────────────────────────

    /// Navigate to a named bookmark: records in the trail and sets it as current.
    ///
    /// # Errors
    /// [`NavError::BookmarkNotFound`] if not present.
    pub fn navigate_to(&mut self, name: &str) -> Result<&TraceBookmark, NavError> {
        if !self.inner.contains_key(name) {
            return Err(NavError::BookmarkNotFound(name.to_owned()));
        }
        // Update trail
        if self.trail.len() >= self.max_trail {
            self.trail.remove(0);
        }
        self.trail.push(name.to_owned());
        self.current = Some(name.to_owned());
        Ok(&self.inner[name])
    }

    /// Navigate to the next bookmark (by trace index) after `after_idx`.
    #[must_use]
    pub fn next_bookmark_after(&self, after_idx: usize) -> Option<&TraceBookmark> {
        self.sorted_by_idx()
            .into_iter()
            .find(|b| b.position.trace_idx().is_some_and(|i| i > after_idx))
    }

    /// Navigate to the previous bookmark (by trace index) before `before_idx`.
    #[must_use]
    pub fn prev_bookmark_before(&self, before_idx: usize) -> Option<&TraceBookmark> {
        self.sorted_by_idx()
            .into_iter()
            .rev()
            .find(|b| b.position.trace_idx().is_some_and(|i| i < before_idx))
    }

    /// The current (most recently navigated) bookmark.
    #[must_use]
    pub fn current(&self) -> Option<&TraceBookmark> {
        self.current.as_deref().and_then(|n| self.inner.get(n))
    }

    /// Navigation trail (names of recently visited bookmarks, oldest first).
    #[must_use]
    pub fn trail(&self) -> &[String] {
        &self.trail
    }

    /// Step back in the trail: returns the previous entry.
    #[must_use]
    pub fn trail_back(&mut self) -> Option<&TraceBookmark> {
        let trail_len = self.trail.len();
        if trail_len < 2 {
            return None;
        }
        self.trail.pop(); // remove current
        let prev = self.trail.last()?.clone();
        self.current = Some(prev.clone());
        self.inner.get(&prev)
    }

    // ── Group operations ───────────────────────────────────────────────────

    /// Remove all non-pinned bookmarks in a given category.
    pub fn clear_category(&mut self, cat: &BookmarkCategory) {
        self.inner
            .retain(|_, b| &b.category != cat || b.pinned);
    }

    /// Remove all non-pinned scratch bookmarks.
    pub fn clear_scratch(&mut self) {
        self.clear_category(&BookmarkCategory::Scratch);
    }

    /// Remove all non-pinned bookmarks outside a trace index range.
    pub fn retain_range(&mut self, lo: usize, hi: usize) {
        self.inner.retain(|_, b| {
            if b.pinned {
                return true;
            }
            b.position
                .trace_idx()
                .is_none_or(|i| i >= lo && i <= hi)
        });
    }

    /// Add a tag to all bookmarks matching a query.
    pub fn tag_matching(&mut self, query: &BookmarkQuery, tag: impl Into<String>) {
        let tag = tag.into();
        let names: Vec<String> = self
            .inner
            .values()
            .filter(|b| query.matches(b))
            .map(|b| b.name.clone())
            .collect();
        for name in names {
            if let Some(b) = self.inner.get_mut(&name) {
                b.tags.insert(tag.clone());
            }
        }
    }

    // ── Import / Export ────────────────────────────────────────────────────

    /// Export all bookmarks to a JSON string.
    ///
    /// # Errors
    /// Returns a JSON error string (not `Err`) if serialisation fails.
    #[must_use]
    pub fn export_json(&self) -> String {
        let bms: Vec<&TraceBookmark> = self.inner.values().collect();
        serde_json::to_string_pretty(&bms).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }

    /// Import bookmarks from a JSON string, merging into the existing store.
    ///
    /// # Errors
    /// Returns the parse error if the JSON is invalid.
    pub fn import_json(&mut self, json: &str) -> Result<usize, serde_json::Error> {
        let bms: Vec<TraceBookmark> = serde_json::from_str(json)?;
        let n = bms.len();
        for bm in bms {
            self.inner.insert(bm.name.clone(), bm);
        }
        Ok(n)
    }

    // ── Sync with basic BookmarkStore ──────────────────────────────────────

    /// Convert all bookmarks with a `Both` or `TraceIndex` position to a `BookmarkStore`.
    #[must_use]
    pub fn to_bookmark_store(&self) -> BookmarkStore {
        let mut store = BookmarkStore::new();
        for bm in self.inner.values() {
            if let Some(idx) = bm.position.trace_idx() {
                let pc = bm.position.address().unwrap_or(0);
                let mut b = Bookmark::new(&bm.name, idx, pc);
                if let Some(ref note) = bm.note {
                    b = b.with_note(note);
                }
                store.insert(b);
            }
        }
        store
    }

    /// Import from a `BookmarkStore`, using `AnalysisNote` as the category.
    pub fn from_bookmark_store(&mut self, store: &BookmarkStore) {
        for bm in store.sorted_by_idx() {
            let pos = BookmarkPosition::Both {
                trace_idx: bm.idx,
                pc: bm.pc,
            };
            let mut tb = TraceBookmark::new(&bm.name, pos);
            if let Some(ref note) = bm.note {
                tb = tb.with_note(note);
            }
            self.inner.insert(tb.name.clone(), tb);
        }
    }

    /// Statistics summary.
    #[must_use]
    pub fn stats(&self) -> BookmarkStats {
        let mut by_category: HashMap<String, usize> = HashMap::new();
        let mut tag_set: HashSet<String> = HashSet::new();
        for bm in self.inner.values() {
            *by_category
                .entry(bm.category.label().to_string())
                .or_insert(0) += 1;
            for tag in &bm.tags {
                tag_set.insert(tag.clone());
            }
        }
        BookmarkStats {
            total: self.inner.len(),
            pinned: self.inner.values().filter(|b| b.pinned).count(),
            by_category,
            unique_tags: tag_set,
        }
    }
}

impl Default for TraceBookmarkManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─── BookmarkStats ───────────────────────────────────────────────────────────

/// Summary statistics about the bookmark set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkStats {
    /// Total number of bookmarks.
    pub total: usize,
    /// Number of pinned bookmarks.
    pub pinned: usize,
    /// Counts by category label.
    pub by_category: HashMap<String, usize>,
    /// All unique tags across all bookmarks.
    pub unique_tags: HashSet<String>,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bm(name: &str, idx: usize) -> TraceBookmark {
        TraceBookmark::new(name, BookmarkPosition::TraceIndex(idx))
    }

    #[test]
    fn test_insert_and_get() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.insert(make_bm("start", 0));
        assert!(mgr.get("start").is_some());
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn test_remove_existing() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.insert(make_bm("a", 10));
        assert!(mgr.remove("a").is_ok());
        assert!(mgr.get("a").is_none());
    }

    #[test]
    fn test_remove_missing() {
        let mut mgr = TraceBookmarkManager::new();
        let r = mgr.remove("nonexistent");
        assert!(r.is_err());
    }

    #[test]
    fn test_navigate_to() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.insert(make_bm("main", 50));
        let r = mgr.navigate_to("main");
        assert!(r.is_ok());
        assert_eq!(mgr.trail().len(), 1);
        assert_eq!(mgr.current().unwrap().name, "main");
    }

    #[test]
    fn test_navigate_to_unknown() {
        let mut mgr = TraceBookmarkManager::new();
        assert!(mgr.navigate_to("ghost").is_err());
    }

    #[test]
    fn test_sorted_by_idx() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.insert(make_bm("z", 100));
        mgr.insert(make_bm("a", 10));
        mgr.insert(make_bm("m", 50));
        let sorted = mgr.sorted_by_idx();
        assert_eq!(sorted[0].name, "a");
        assert_eq!(sorted[1].name, "m");
        assert_eq!(sorted[2].name, "z");
    }

    #[test]
    fn test_next_after() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.insert(make_bm("b1", 10));
        mgr.insert(make_bm("b2", 20));
        let next = mgr.next_bookmark_after(10);
        assert_eq!(next.unwrap().name, "b2");
    }

    #[test]
    fn test_prev_before() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.insert(make_bm("b1", 10));
        mgr.insert(make_bm("b2", 20));
        let prev = mgr.prev_bookmark_before(20);
        assert_eq!(prev.unwrap().name, "b1");
    }

    #[test]
    fn test_by_category() {
        let mut mgr = TraceBookmarkManager::new();
        let bm = TraceBookmark::new("fn", BookmarkPosition::TraceIndex(5))
            .with_category(BookmarkCategory::FunctionEntry);
        mgr.insert(bm);
        mgr.insert(make_bm("note", 10));
        let fns = mgr.by_category(&BookmarkCategory::FunctionEntry);
        assert_eq!(fns.len(), 1);
    }

    #[test]
    fn test_by_tag() {
        let mut mgr = TraceBookmarkManager::new();
        let bm = TraceBookmark::new("tagged", BookmarkPosition::TraceIndex(1))
            .with_tag("vuln");
        mgr.insert(bm);
        mgr.insert(make_bm("plain", 2));
        let tagged = mgr.by_tag("vuln");
        assert_eq!(tagged.len(), 1);
    }

    #[test]
    fn test_search_by_name_contains() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.insert(make_bm("main_entry", 0));
        mgr.insert(make_bm("helper_fn", 5));
        let q = BookmarkQuery { name_contains: Some("main".into()), ..Default::default() };
        let results = mgr.search(&q);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_clear_scratch() {
        let mut mgr = TraceBookmarkManager::new();
        let scratch = TraceBookmark::new("tmp", BookmarkPosition::TraceIndex(1))
            .with_category(BookmarkCategory::Scratch);
        let pinned_scratch = TraceBookmark::new("keep", BookmarkPosition::TraceIndex(2))
            .with_category(BookmarkCategory::Scratch)
            .pinned();
        mgr.insert(scratch);
        mgr.insert(pinned_scratch);
        mgr.clear_scratch();
        assert!(mgr.get("tmp").is_none());
        assert!(mgr.get("keep").is_some());
    }

    #[test]
    fn test_export_import_json() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.insert(make_bm("a", 1));
        mgr.insert(make_bm("b", 2));
        let json = mgr.export_json();
        let mut mgr2 = TraceBookmarkManager::new();
        let n = mgr2.import_json(&json).unwrap();
        assert_eq!(n, 2);
        assert!(mgr2.get("a").is_some());
    }

    #[test]
    fn test_to_bookmark_store() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.insert(TraceBookmark::new(
            "x",
            BookmarkPosition::Both { trace_idx: 5, pc: 0x1234 },
        ));
        let store = mgr.to_bookmark_store();
        assert!(store.get("x").is_some());
    }

    #[test]
    fn test_trail_back() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.insert(make_bm("a", 1));
        mgr.insert(make_bm("b", 2));
        mgr.navigate_to("a").unwrap();
        mgr.navigate_to("b").unwrap();
        let prev = mgr.trail_back();
        assert_eq!(prev.unwrap().name, "a");
    }

    #[test]
    fn test_stats() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.insert(make_bm("a", 1));
        let pinned = TraceBookmark::new("p", BookmarkPosition::TraceIndex(2)).pinned();
        mgr.insert(pinned);
        let stats = mgr.stats();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.pinned, 1);
    }

    #[test]
    fn test_retain_range() {
        let mut mgr = TraceBookmarkManager::new();
        mgr.insert(make_bm("early", 1));
        mgr.insert(make_bm("mid", 50));
        mgr.insert(make_bm("late", 200));
        mgr.retain_range(10, 100);
        assert!(mgr.get("early").is_none());
        assert!(mgr.get("mid").is_some());
        assert!(mgr.get("late").is_none());
    }
}
