//! `hex_bookmarks` — Named bookmarks, range annotations, and groups.
//!
//! Provides a `BookmarkManager` that stores named bookmarks with colour and
//! notes, range annotations, bookmark groups, JSON export/import, automatic
//! bookmark generation from pattern matches, and knowledge-graph integration.

use std::collections::HashMap;
use std::ops::Range;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Color
// ─────────────────────────────────────────────────────────────────────────────

/// An RGB colour tag for a bookmark or annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BookmarkColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl BookmarkColor {
    pub const RED: Self = Self { r: 220, g: 50, b: 50 };
    pub const GREEN: Self = Self { r: 50, g: 200, b: 80 };
    pub const BLUE: Self = Self { r: 50, g: 80, b: 220 };
    pub const YELLOW: Self = Self { r: 240, g: 200, b: 30 };
    pub const CYAN: Self = Self { r: 30, g: 200, b: 220 };
    pub const MAGENTA: Self = Self { r: 200, g: 50, b: 200 };
    pub const ORANGE: Self = Self { r: 240, g: 140, b: 30 };
    pub const WHITE: Self = Self { r: 240, g: 240, b: 240 };

    #[must_use]
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// Return the ANSI 256-colour escape code approximation.
    #[must_use]
    pub fn ansi_fg(&self) -> String {
        format!("\x1b[38;2;{};{};{}m", self.r, self.g, self.b)
    }

    #[must_use]
    pub fn ansi_bg(&self) -> String {
        format!("\x1b[48;2;{};{};{}m", self.r, self.g, self.b)
    }
}

impl std::fmt::Display for BookmarkColor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{:02X}{:02X}{:02X}", self.r, self.g, self.b)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bookmark
// ─────────────────────────────────────────────────────────────────────────────

/// A unique identifier for a bookmark.
pub type BookmarkId = u64;

/// A point bookmark (single offset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    pub id: BookmarkId,
    pub name: String,
    pub offset: usize,
    pub color: BookmarkColor,
    pub note: String,
    pub group: Option<String>,
    /// Tags for knowledge-graph integration.
    pub tags: Vec<String>,
    pub created_at: u64,
}

impl Bookmark {
    fn new(id: BookmarkId, name: impl Into<String>, offset: usize) -> Self {
        Self {
            id,
            name: name.into(),
            offset,
            color: BookmarkColor::YELLOW,
            note: String::new(),
            group: None,
            tags: vec![],
            created_at: timestamp_secs(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RangeAnnotation
// ─────────────────────────────────────────────────────────────────────────────

/// Kind of range annotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnnotationKind {
    /// Generic highlighted range.
    Highlight,
    /// Marks a struct field.
    StructField { type_name: String },
    /// Marks suspicious / interesting content.
    Note,
    /// Marks a known bad / malicious section.
    Warning,
    /// Pattern match result.
    PatternMatch { pattern_name: String },
}

/// An annotation spanning a byte range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeAnnotation {
    pub id: BookmarkId,
    pub name: String,
    pub range: Range<usize>,
    pub color: BookmarkColor,
    pub note: String,
    pub kind: AnnotationKind,
    pub group: Option<String>,
    pub tags: Vec<String>,
    pub created_at: u64,
}

impl RangeAnnotation {
    fn new(
        id: BookmarkId,
        name: impl Into<String>,
        range: Range<usize>,
        kind: AnnotationKind,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            range,
            color: BookmarkColor::CYAN,
            note: String::new(),
            kind,
            group: None,
            tags: vec![],
            created_at: timestamp_secs(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BookmarkGroup
// ─────────────────────────────────────────────────────────────────────────────

/// A named group of bookmarks and annotations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkGroup {
    pub name: String,
    pub color: BookmarkColor,
    pub description: String,
    pub visible: bool,
}

impl BookmarkGroup {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            color: BookmarkColor::WHITE,
            description: String::new(),
            visible: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Auto-bookmark rule
// ─────────────────────────────────────────────────────────────────────────────

/// Rule for automatically creating bookmarks when a byte pattern matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoBookmarkRule {
    pub name: String,
    pub pattern: Vec<u8>,
    /// Optional wildcard mask (0x00 = wildcard, 0xff = exact).
    pub mask: Option<Vec<u8>>,
    pub label_template: String,
    pub color: BookmarkColor,
    pub group: Option<String>,
    pub create_range: Option<usize>,
}

impl AutoBookmarkRule {
    /// Create a simple exact-match rule.
    #[must_use]
    pub fn exact(name: impl Into<String>, pattern: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            pattern,
            mask: None,
            label_template: "<name>@<offset:#010x>".to_owned(),
            color: BookmarkColor::ORANGE,
            group: None,
            create_range: None,
        }
    }

    /// Check whether the pattern matches at a given position in `data`.
    #[must_use]
    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.pattern.len() > data.len() {
            return false;
        }
        for (i, &pb) in self.pattern.iter().enumerate() {
            let mask = self.mask.as_ref().map_or(0xff, |m| m.get(i).copied().unwrap_or(0xff));
            if data[offset + i] & mask != pb & mask {
                return false;
            }
        }
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BookmarkManager
// ─────────────────────────────────────────────────────────────────────────────

/// Central manager for all bookmarks, annotations, and groups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkManager {
    bookmarks: HashMap<BookmarkId, Bookmark>,
    annotations: HashMap<BookmarkId, RangeAnnotation>,
    groups: HashMap<String, BookmarkGroup>,
    auto_rules: Vec<AutoBookmarkRule>,
    next_id: BookmarkId,
}

impl Default for BookmarkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BookmarkManager {
    /// Create a new empty manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bookmarks: HashMap::new(),
            annotations: HashMap::new(),
            groups: HashMap::new(),
            auto_rules: vec![],
            next_id: 1,
        }
    }

    const fn alloc_id(&mut self) -> BookmarkId {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    // ── Bookmark CRUD ────────────────────────────────────────────────────────

    /// Add a named bookmark at `offset`.
    pub fn add_bookmark(&mut self, name: impl Into<String>, offset: usize) -> BookmarkId {
        let id = self.alloc_id();
        self.bookmarks.insert(id, Bookmark::new(id, name, offset));
        id
    }

    /// Remove a bookmark by id.
    pub fn remove_bookmark(&mut self, id: BookmarkId) -> bool {
        self.bookmarks.remove(&id).is_some()
    }

    /// Get a bookmark by id.
    #[must_use]
    pub fn get_bookmark(&self, id: BookmarkId) -> Option<&Bookmark> {
        self.bookmarks.get(&id)
    }

    /// Get a mutable bookmark by id.
    pub fn get_bookmark_mut(&mut self, id: BookmarkId) -> Option<&mut Bookmark> {
        self.bookmarks.get_mut(&id)
    }

    /// All bookmarks sorted by offset.
    #[must_use]
    pub fn bookmarks_sorted(&self) -> Vec<&Bookmark> {
        let mut v: Vec<&Bookmark> = self.bookmarks.values().collect();
        v.sort_by_key(|b| b.offset);
        v
    }

    /// Bookmarks in a given group.
    #[must_use]
    pub fn bookmarks_in_group(&self, group: &str) -> Vec<&Bookmark> {
        self.bookmarks
            .values()
            .filter(|b| b.group.as_deref() == Some(group))
            .collect()
    }

    /// Find bookmarks near an offset (within `radius` bytes).
    #[must_use]
    pub fn bookmarks_near(&self, offset: usize, radius: usize) -> Vec<&Bookmark> {
        self.bookmarks
            .values()
            .filter(|b| b.offset.abs_diff(offset) <= radius)
            .collect()
    }

    // ── Annotation CRUD ──────────────────────────────────────────────────────

    /// Add a range annotation.
    pub fn add_annotation(
        &mut self,
        name: impl Into<String>,
        range: Range<usize>,
        kind: AnnotationKind,
    ) -> BookmarkId {
        let id = self.alloc_id();
        self.annotations
            .insert(id, RangeAnnotation::new(id, name, range, kind));
        id
    }

    /// Remove an annotation by id.
    pub fn remove_annotation(&mut self, id: BookmarkId) -> bool {
        self.annotations.remove(&id).is_some()
    }

    /// Get annotation by id.
    #[must_use]
    pub fn get_annotation(&self, id: BookmarkId) -> Option<&RangeAnnotation> {
        self.annotations.get(&id)
    }

    /// Annotations that overlap a given offset.
    #[must_use]
    pub fn annotations_at(&self, offset: usize) -> Vec<&RangeAnnotation> {
        self.annotations
            .values()
            .filter(|a| a.range.contains(&offset))
            .collect()
    }

    /// All annotations sorted by range start.
    #[must_use]
    pub fn annotations_sorted(&self) -> Vec<&RangeAnnotation> {
        let mut v: Vec<&RangeAnnotation> = self.annotations.values().collect();
        v.sort_by_key(|a| a.range.start);
        v
    }

    // ── Group management ─────────────────────────────────────────────────────

    /// Create or update a group.
    pub fn upsert_group(&mut self, group: BookmarkGroup) {
        self.groups.insert(group.name.clone(), group);
    }

    /// Remove a group (does not remove its bookmarks).
    pub fn remove_group(&mut self, name: &str) -> bool {
        self.groups.remove(name).is_some()
    }

    #[must_use]
    pub fn get_group(&self, name: &str) -> Option<&BookmarkGroup> {
        self.groups.get(name)
    }

    #[must_use]
    pub fn group_names(&self) -> Vec<&str> {
        self.groups.keys().map(std::string::String::as_str).collect()
    }

    // ── Auto-rules ───────────────────────────────────────────────────────────

    /// Register an auto-bookmark rule.
    pub fn add_auto_rule(&mut self, rule: AutoBookmarkRule) {
        self.auto_rules.push(rule);
    }

    /// Run all auto-rules against `data` and create bookmarks for matches.
    pub fn apply_auto_rules(&mut self, data: &[u8]) -> usize {
        let rules = std::mem::take(&mut self.auto_rules);
        let mut count = 0usize;
        for rule in &rules {
            let mut offset = 0usize;
            while offset + rule.pattern.len() <= data.len() {
                if rule.matches_at(data, offset) {
                    let label = rule
                        .label_template
                        .replace("<name>", &rule.name)
                        .replace("<offset:#010x>", &format!("{offset:#010x}"));

                    if let Some(range_len) = rule.create_range {
                        let id = self.add_annotation(
                            &label,
                            offset..offset + range_len,
                            AnnotationKind::PatternMatch {
                                pattern_name: rule.name.clone(),
                            },
                        );
                        if let Some(ann) = self.annotations.get_mut(&id) {
                            ann.color = rule.color;
                            ann.group.clone_from(&rule.group);
                        }
                    } else {
                        let id = self.add_bookmark(&label, offset);
                        if let Some(bm) = self.bookmarks.get_mut(&id) {
                            bm.color = rule.color;
                            bm.group.clone_from(&rule.group);
                        }
                    }

                    count += 1;
                    offset += rule.pattern.len();
                } else {
                    offset += 1;
                }
            }
        }
        self.auto_rules = rules;
        count
    }

    // ── Tag / search ─────────────────────────────────────────────────────────

    /// Find bookmarks by tag.
    #[must_use]
    pub fn bookmarks_by_tag(&self, tag: &str) -> Vec<&Bookmark> {
        self.bookmarks
            .values()
            .filter(|b| b.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Find annotations by tag.
    #[must_use]
    pub fn annotations_by_tag(&self, tag: &str) -> Vec<&RangeAnnotation> {
        self.annotations
            .values()
            .filter(|a| a.tags.iter().any(|t| t == tag))
            .collect()
    }

    // ── Jump navigation ──────────────────────────────────────────────────────

    /// Next bookmark offset after `current`.
    #[must_use]
    pub fn next_bookmark_after(&self, current: usize) -> Option<usize> {
        self.bookmarks_sorted()
            .into_iter()
            .find(|b| b.offset > current)
            .map(|b| b.offset)
    }

    /// Previous bookmark offset before `current`.
    #[must_use]
    pub fn prev_bookmark_before(&self, current: usize) -> Option<usize> {
        self.bookmarks_sorted()
            .into_iter()
            .rev()
            .find(|b| b.offset < current)
            .map(|b| b.offset)
    }

    // ── Export / Import ──────────────────────────────────────────────────────

    /// Export all bookmarks and annotations to JSON.
    ///
    /// # Errors
    ///
    /// Returns a [`serde_json::Error`] if serialization fails.
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Import from JSON, merging with existing state.
    ///
    /// # Errors
    ///
    /// Returns a [`serde_json::Error`] if deserialization fails.
    pub fn import_json(&mut self, json: &str) -> Result<usize, serde_json::Error> {
        let other: Self = serde_json::from_str(json)?;
        let mut count = 0usize;
        for (_id, bm) in other.bookmarks {
            let new_id = self.alloc_id();
            let mut bm = bm;
            bm.id = new_id;
            self.bookmarks.insert(new_id, bm);
            count += 1;
        }
        for (_id, ann) in other.annotations {
            let new_id = self.alloc_id();
            let mut ann = ann;
            ann.id = new_id;
            self.annotations.insert(new_id, ann);
            count += 1;
        }
        for (name, grp) in other.groups {
            self.groups.entry(name).or_insert(grp);
        }
        Ok(count)
    }

    /// Clear all bookmarks, annotations, and groups.
    pub fn clear(&mut self) {
        self.bookmarks.clear();
        self.annotations.clear();
        self.groups.clear();
    }

    /// Total bookmark count.
    #[must_use]
    pub fn bookmark_count(&self) -> usize {
        self.bookmarks.len()
    }

    /// Total annotation count.
    #[must_use]
    pub fn annotation_count(&self) -> usize {
        self.annotations.len()
    }

    // ── Knowledge-graph integration ──────────────────────────────────────────

    /// Build a simplified edge list for the knowledge graph.
    /// Returns `(source_label, target_label, relationship)` triples.
    #[must_use]
    pub fn knowledge_graph_edges(&self) -> Vec<(String, String, String)> {
        let mut edges = vec![];

        // Bookmarks → groups
        for bm in self.bookmarks.values() {
            if let Some(grp) = &bm.group {
                edges.push((
                    format!("bookmark:{}", bm.name),
                    format!("group:{grp}"),
                    "belongs_to".to_string(),
                ));
            }
        }

        // Annotations → groups
        for ann in self.annotations.values() {
            if let Some(grp) = &ann.group {
                edges.push((
                    format!("annotation:{}", ann.name),
                    format!("group:{grp}"),
                    "belongs_to".to_string(),
                ));
            }
        }

        // Tag relationships
        for bm in self.bookmarks.values() {
            for tag in &bm.tags {
                edges.push((
                    format!("bookmark:{}", bm.name),
                    format!("tag:{tag}"),
                    "tagged".to_string(),
                ));
            }
        }

        edges
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn timestamp_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_retrieve_bookmark() {
        let mut mgr = BookmarkManager::new();
        let id = mgr.add_bookmark("entry_point", 0x1000);
        let bm = mgr.get_bookmark(id).unwrap();
        assert_eq!(bm.offset, 0x1000);
        assert_eq!(bm.name, "entry_point");
    }

    #[test]
    fn remove_bookmark() {
        let mut mgr = BookmarkManager::new();
        let id = mgr.add_bookmark("test", 0x00);
        assert!(mgr.remove_bookmark(id));
        assert!(mgr.get_bookmark(id).is_none());
    }

    #[test]
    fn range_annotation_lookup() {
        let mut mgr = BookmarkManager::new();
        mgr.add_annotation("header", 0..64, AnnotationKind::Highlight);
        let hits = mgr.annotations_at(32);
        assert_eq!(hits.len(), 1);
        let misses = mgr.annotations_at(100);
        assert!(misses.is_empty());
    }

    #[test]
    fn json_roundtrip() {
        let mut mgr = BookmarkManager::new();
        mgr.add_bookmark("a", 0x100);
        mgr.add_annotation("b", 0x200..0x300, AnnotationKind::Note);
        let json = mgr.export_json().unwrap();
        let mut mgr2 = BookmarkManager::new();
        let count = mgr2.import_json(&json).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn auto_rule_match() {
        let mut mgr = BookmarkManager::new();
        let rule = AutoBookmarkRule::exact("MZ", b"MZ".to_vec());
        mgr.add_auto_rule(rule);
        let data = b"\x00\x00MZ\x90\x00MZ";
        let n = mgr.apply_auto_rules(data);
        assert_eq!(n, 2);
        assert_eq!(mgr.bookmark_count(), 2);
    }

    #[test]
    fn navigation() {
        let mut mgr = BookmarkManager::new();
        mgr.add_bookmark("a", 0x100);
        mgr.add_bookmark("b", 0x200);
        mgr.add_bookmark("c", 0x300);
        assert_eq!(mgr.next_bookmark_after(0x150), Some(0x200));
        assert_eq!(mgr.prev_bookmark_before(0x250), Some(0x200));
    }
}
