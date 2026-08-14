//! Hex bookmark manager.
//!
//! Maintains a collection of named, coloured bookmarks over a binary buffer.
//! Bookmarks can be single offsets or contiguous ranges.
//!
//! # Key types
//!
//! * [`HexBookmarkManager`] — owns the bookmark registry.
//! * [`HexBookmark`] — a single named bookmark (point or range).
//! * [`BookmarkColor`] — 24-bit RGB colour tag.
//! * [`BookmarkRange`] — a half-open byte range `[start, end)`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ── BookmarkColor ─────────────────────────────────────────────────────────────

/// A 24-bit RGB colour used to visually distinguish bookmarks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BookmarkColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl BookmarkColor {
    // Pre-defined palette.
    pub const RED: Self = Self { r: 0xFF, g: 0x44, b: 0x44 };
    pub const GREEN: Self = Self { r: 0x44, g: 0xFF, b: 0x44 };
    pub const BLUE: Self = Self { r: 0x44, g: 0x44, b: 0xFF };
    pub const YELLOW: Self = Self { r: 0xFF, g: 0xFF, b: 0x00 };
    pub const CYAN: Self = Self { r: 0x00, g: 0xFF, b: 0xFF };
    pub const MAGENTA: Self = Self { r: 0xFF, g: 0x00, b: 0xFF };
    pub const ORANGE: Self = Self { r: 0xFF, g: 0xA5, b: 0x00 };
    pub const WHITE: Self = Self { r: 0xFF, g: 0xFF, b: 0xFF };
    pub const GREY: Self = Self { r: 0x80, g: 0x80, b: 0x80 };

    /// Create from a 0xRRGGBB integer.
    #[must_use]
    pub const fn from_u32(rgb: u32) -> Self {
        Self {
            r: ((rgb >> 16) & 0xFF) as u8,
            g: ((rgb >> 8) & 0xFF) as u8,
            b: (rgb & 0xFF) as u8,
        }
    }

    /// Convert to a 0xRRGGBB integer.
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        ((self.r as u32) << 16) | ((self.g as u32) << 8) | (self.b as u32)
    }

    /// Hex string `"#RRGGBB"`.
    #[must_use]
    pub fn to_hex_string(self) -> String {
        format!("#{:02X}{:02X}{:02X}", self.r, self.g, self.b)
    }

    /// Parse `"#RRGGBB"` or `"RRGGBB"`.
    #[must_use]
    pub fn parse_hex(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches('#');
        if s.len() != 6 {
            return None;
        }
        let r = u8::from_str_radix(&s[0..2], 16).ok()?;
        let g = u8::from_str_radix(&s[2..4], 16).ok()?;
        let b = u8::from_str_radix(&s[4..6], 16).ok()?;
        Some(Self { r, g, b })
    }

    /// Perceived luminance (0.0–1.0) for contrast decisions.
    #[must_use]
    pub fn luminance(self) -> f32 {
        0.114f32.mul_add(f32::from(self.b), 0.299f32.mul_add(f32::from(self.r), 0.587 * f32::from(self.g))) / 255.0
    }

    /// Whether white foreground text would be readable on this background.
    #[must_use]
    pub fn needs_dark_text(self) -> bool {
        self.luminance() > 0.5
    }
}

impl fmt::Display for BookmarkColor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex_string())
    }
}

impl Default for BookmarkColor {
    fn default() -> Self {
        Self::YELLOW
    }
}

// ── BookmarkRange ─────────────────────────────────────────────────────────────

/// A contiguous half-open byte range `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BookmarkRange {
    /// Inclusive start offset.
    pub start: usize,
    /// Exclusive end offset.
    pub end: usize,
}

impl BookmarkRange {
    /// Create a range covering a single byte.
    #[must_use]
    pub const fn single(offset: usize) -> Self {
        Self { start: offset, end: offset + 1 }
    }

    /// Create a range from `start` with `len` bytes.
    #[must_use]
    pub const fn from_len(start: usize, len: usize) -> Self {
        Self { start, end: start + len }
    }

    /// Number of bytes covered.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// True when the range covers zero bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start >= self.end
    }

    /// True when `offset` is inside this range.
    #[must_use]
    pub const fn contains(self, offset: usize) -> bool {
        offset >= self.start && offset < self.end
    }

    /// True when the two ranges overlap.
    #[must_use]
    pub const fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// True when `other` is entirely contained within this range.
    #[must_use]
    pub const fn includes(self, other: Self) -> bool {
        self.start <= other.start && self.end >= other.end
    }
}

impl fmt::Display for BookmarkRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:#010x}, {:#010x})", self.start, self.end)
    }
}

// ── HexBookmark ───────────────────────────────────────────────────────────────

/// A named bookmark over a byte range with an optional colour and comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexBookmark {
    /// Unique identifier within a manager.
    pub id: u64,
    /// Human-readable name.
    pub name: String,
    /// The byte range this bookmark spans.
    pub range: BookmarkRange,
    /// Display colour.
    pub color: BookmarkColor,
    /// Optional longer description.
    pub comment: Option<String>,
    /// Arbitrary user-defined tag list.
    pub tags: Vec<String>,
}

impl HexBookmark {
    /// Create a minimal named bookmark at a single offset.
    #[must_use]
    pub fn at_offset(id: u64, name: impl Into<String>, offset: usize) -> Self {
        Self {
            id,
            name: name.into(),
            range: BookmarkRange::single(offset),
            color: BookmarkColor::default(),
            comment: None,
            tags: Vec::new(),
        }
    }

    /// Create a named bookmark spanning a range.
    #[must_use]
    pub fn over_range(id: u64, name: impl Into<String>, range: BookmarkRange) -> Self {
        Self {
            id,
            name: name.into(),
            range,
            color: BookmarkColor::default(),
            comment: None,
            tags: Vec::new(),
        }
    }

    /// True if this bookmark covers a single byte.
    #[must_use]
    pub const fn is_point(&self) -> bool {
        self.range.len() == 1
    }

    /// True if a given `offset` falls inside this bookmark's range.
    #[must_use]
    pub const fn covers(&self, offset: usize) -> bool {
        self.range.contains(offset)
    }

    /// Builder: set colour.
    #[must_use]
    pub const fn with_color(mut self, color: BookmarkColor) -> Self {
        self.color = color;
        self
    }

    /// Builder: set comment.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Builder: add a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

impl fmt::Display for HexBookmark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} @ {} ({})", self.id, self.name, self.range, self.color)?;
        if let Some(c) = &self.comment {
            write!(f, " — {c}")?;
        }
        Ok(())
    }
}

// ── BookmarkError ─────────────────────────────────────────────────────────────

/// Errors produced by [`HexBookmarkManager`].
#[derive(Debug, thiserror::Error)]
pub enum BookmarkError {
    #[error("bookmark not found: id={0}")]
    NotFound(u64),
    #[error("duplicate bookmark name: {0}")]
    DuplicateName(String),
    #[error("empty range for bookmark {0}")]
    EmptyRange(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

// ── HexBookmarkManager ────────────────────────────────────────────────────────

/// Manages a collection of named, coloured bookmarks over a binary buffer.
pub struct HexBookmarkManager {
    /// All bookmarks by ID.
    bookmarks: HashMap<u64, HexBookmark>,
    /// Index: offset → set of bookmark IDs covering that offset.
    /// Populated lazily / explicitly.
    next_id: u64,
    /// Insertion order for deterministic display.
    order: Vec<u64>,
}

impl Default for HexBookmarkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HexBookmarkManager {
    /// Create an empty manager.
    #[must_use]
    pub fn new() -> Self {
        Self { bookmarks: HashMap::new(), next_id: 1, order: Vec::new() }
    }

    // ── Adding ────────────────────────────────────────────────────────────────

    /// Add a bookmark at a single offset.  Returns the assigned ID.
    ///
    /// # Errors
    ///
    /// Returns [`BookmarkError::DuplicateName`] if a bookmark with the same name exists.
    pub fn add_at_offset(
        &mut self,
        name: impl Into<String>,
        offset: usize,
    ) -> Result<u64, BookmarkError> {
        let name = name.into();
        self.check_duplicate_name(&name)?;
        let id = self.allocate_id();
        let bm = HexBookmark::at_offset(id, name, offset);
        self.insert(bm);
        Ok(id)
    }

    /// Add a bookmark over a range.  Returns the assigned ID.
    ///
    /// # Errors
    ///
    /// Returns [`BookmarkError::EmptyRange`] or [`BookmarkError::DuplicateName`] on failure.
    pub fn add_over_range(
        &mut self,
        name: impl Into<String>,
        range: BookmarkRange,
    ) -> Result<u64, BookmarkError> {
        let name = name.into();
        if range.is_empty() {
            return Err(BookmarkError::EmptyRange(name));
        }
        self.check_duplicate_name(&name)?;
        let id = self.allocate_id();
        let bm = HexBookmark::over_range(id, name, range);
        self.insert(bm);
        Ok(id)
    }

    /// Add a pre-built bookmark (its ID will be overwritten).
    ///
    /// # Errors
    ///
    /// Returns [`BookmarkError::EmptyRange`] or [`BookmarkError::DuplicateName`] on failure.
    pub fn add(&mut self, mut bm: HexBookmark) -> Result<u64, BookmarkError> {
        if bm.range.is_empty() {
            return Err(BookmarkError::EmptyRange(bm.name));
        }
        self.check_duplicate_name(&bm.name)?;
        let id = self.allocate_id();
        bm.id = id;
        self.insert(bm);
        Ok(id)
    }

    // ── Updating ──────────────────────────────────────────────────────────────

    /// Rename a bookmark.
    ///
    /// # Errors
    ///
    /// Returns [`BookmarkError::DuplicateName`] or [`BookmarkError::NotFound`] on failure.
    pub fn rename(&mut self, id: u64, new_name: impl Into<String>) -> Result<(), BookmarkError> {
        let new_name = new_name.into();
        self.check_duplicate_name(&new_name)?;
        let bm = self.bookmarks.get_mut(&id).ok_or(BookmarkError::NotFound(id))?;
        bm.name = new_name;
        Ok(())
    }

    /// Change the colour of a bookmark.
    ///
    /// # Errors
    ///
    /// Returns [`BookmarkError::NotFound`] if no bookmark with `id` exists.
    pub fn set_color(&mut self, id: u64, color: BookmarkColor) -> Result<(), BookmarkError> {
        let bm = self.bookmarks.get_mut(&id).ok_or(BookmarkError::NotFound(id))?;
        bm.color = color;
        Ok(())
    }

    /// Set the comment on a bookmark.
    ///
    /// # Errors
    ///
    /// Returns [`BookmarkError::NotFound`] if no bookmark with `id` exists.
    pub fn set_comment(&mut self, id: u64, comment: impl Into<String>) -> Result<(), BookmarkError> {
        let bm = self.bookmarks.get_mut(&id).ok_or(BookmarkError::NotFound(id))?;
        bm.comment = Some(comment.into());
        Ok(())
    }

    /// Add a tag to a bookmark.
    ///
    /// # Errors
    ///
    /// Returns [`BookmarkError::NotFound`] if no bookmark with `id` exists.
    pub fn add_tag(&mut self, id: u64, tag: impl Into<String>) -> Result<(), BookmarkError> {
        let bm = self.bookmarks.get_mut(&id).ok_or(BookmarkError::NotFound(id))?;
        let t = tag.into();
        if !bm.tags.contains(&t) {
            bm.tags.push(t);
        }
        Ok(())
    }

    // ── Removing ──────────────────────────────────────────────────────────────

    /// Remove a bookmark by ID.
    ///
    /// # Errors
    ///
    /// Returns [`BookmarkError::NotFound`] if no bookmark with `id` exists.
    pub fn remove(&mut self, id: u64) -> Result<HexBookmark, BookmarkError> {
        let bm = self.bookmarks.remove(&id).ok_or(BookmarkError::NotFound(id))?;
        self.order.retain(|&i| i != id);
        Ok(bm)
    }

    /// Remove all bookmarks.
    pub fn clear(&mut self) {
        self.bookmarks.clear();
        self.order.clear();
    }

    // ── Querying ──────────────────────────────────────────────────────────────

    /// Total number of bookmarks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bookmarks.len()
    }

    /// True when there are no bookmarks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bookmarks.is_empty()
    }

    /// All bookmarks in insertion order.
    #[must_use]
    pub fn all(&self) -> Vec<&HexBookmark> {
        self.order.iter().filter_map(|id| self.bookmarks.get(id)).collect()
    }

    /// Look up a bookmark by ID.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&HexBookmark> {
        self.bookmarks.get(&id)
    }

    /// Find bookmarks by exact name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Vec<&HexBookmark> {
        self.bookmarks.values().filter(|b| b.name == name).collect()
    }

    /// All bookmarks covering a given `offset`.
    #[must_use]
    pub fn at_offset(&self, offset: usize) -> Vec<&HexBookmark> {
        self.bookmarks.values().filter(|b| b.covers(offset)).collect()
    }

    /// All bookmarks whose range overlaps `[start, end)`.
    #[must_use]
    pub fn overlapping_range(&self, range: BookmarkRange) -> Vec<&HexBookmark> {
        self.bookmarks
            .values()
            .filter(|b| b.range.overlaps(range))
            .collect()
    }

    /// Bookmarks that have a specific colour.
    #[must_use]
    pub fn by_color(&self, color: BookmarkColor) -> Vec<&HexBookmark> {
        self.bookmarks.values().filter(|b| b.color == color).collect()
    }

    /// Bookmarks carrying a specific tag.
    #[must_use]
    pub fn by_tag(&self, tag: &str) -> Vec<&HexBookmark> {
        self.bookmarks.values().filter(|b| b.tags.iter().any(|t| t == tag)).collect()
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    /// Export all bookmarks to JSON.
    ///
    /// # Errors
    ///
    /// Returns [`BookmarkError::Serialization`] if JSON serialization fails.
    pub fn to_json(&self) -> Result<String, BookmarkError> {
        let all: Vec<&HexBookmark> = self.all();
        serde_json::to_string_pretty(&all)
            .map_err(|e| BookmarkError::Serialization(e.to_string()))
    }

    /// Import bookmarks from JSON (appends to existing set).
    ///
    /// # Errors
    ///
    /// Returns [`BookmarkError::Serialization`] if JSON deserialization fails.
    pub fn from_json(&mut self, json: &str) -> Result<usize, BookmarkError> {
        let bms: Vec<HexBookmark> =
            serde_json::from_str(json).map_err(|e| BookmarkError::Serialization(e.to_string()))?;
        let count = bms.len();
        for bm in bms {
            let _ = self.add(bm);
        }
        Ok(count)
    }

    // ── Private ───────────────────────────────────────────────────────────────

    const fn allocate_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn insert(&mut self, bm: HexBookmark) {
        let id = bm.id;
        self.order.push(id);
        self.bookmarks.insert(id, bm);
    }

    fn check_duplicate_name(&self, name: &str) -> Result<(), BookmarkError> {
        if self.bookmarks.values().any(|b| b.name == name) {
            return Err(BookmarkError::DuplicateName(name.to_owned()));
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_at_offset() {
        let mut mgr = HexBookmarkManager::new();
        let id = mgr.add_at_offset("main", 0x100).unwrap();
        assert_eq!(id, 1);
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn test_add_over_range() {
        let mut mgr = HexBookmarkManager::new();
        let range = BookmarkRange::from_len(0x10, 8);
        let id = mgr.add_over_range("header", range).unwrap();
        let bm = mgr.get(id).unwrap();
        assert_eq!(bm.range.start, 0x10);
        assert_eq!(bm.range.len(), 8);
    }

    #[test]
    fn test_duplicate_name_rejected() {
        let mut mgr = HexBookmarkManager::new();
        mgr.add_at_offset("foo", 0).unwrap();
        assert!(matches!(
            mgr.add_at_offset("foo", 1),
            Err(BookmarkError::DuplicateName(_))
        ));
    }

    #[test]
    fn test_empty_range_rejected() {
        let mut mgr = HexBookmarkManager::new();
        let range = BookmarkRange { start: 5, end: 5 };
        assert!(matches!(
            mgr.add_over_range("empty", range),
            Err(BookmarkError::EmptyRange(_))
        ));
    }

    #[test]
    fn test_remove_bookmark() {
        let mut mgr = HexBookmarkManager::new();
        let id = mgr.add_at_offset("x", 0).unwrap();
        mgr.remove(id).unwrap();
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_remove_not_found() {
        let mut mgr = HexBookmarkManager::new();
        assert!(matches!(mgr.remove(99), Err(BookmarkError::NotFound(99))));
    }

    #[test]
    fn test_at_offset() {
        let mut mgr = HexBookmarkManager::new();
        mgr.add_over_range("r", BookmarkRange::from_len(10, 5)).unwrap();
        assert_eq!(mgr.at_offset(12).len(), 1);
        assert_eq!(mgr.at_offset(20).len(), 0);
    }

    #[test]
    fn test_overlapping_range() {
        let mut mgr = HexBookmarkManager::new();
        mgr.add_over_range("a", BookmarkRange::from_len(0, 10)).unwrap();
        mgr.add_over_range("b", BookmarkRange::from_len(20, 10)).unwrap();
        let hits = mgr.overlapping_range(BookmarkRange::from_len(5, 5));
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_by_color() {
        let mut mgr = HexBookmarkManager::new();
        let id1 = mgr.add_at_offset("a", 0).unwrap();
        let id2 = mgr.add_at_offset("b", 1).unwrap();
        mgr.set_color(id1, BookmarkColor::RED).unwrap();
        mgr.set_color(id2, BookmarkColor::BLUE).unwrap();
        assert_eq!(mgr.by_color(BookmarkColor::RED).len(), 1);
        assert_eq!(mgr.by_color(BookmarkColor::GREEN).len(), 0);
    }

    #[test]
    fn test_by_tag() {
        let mut mgr = HexBookmarkManager::new();
        let id = mgr.add_at_offset("a", 0).unwrap();
        mgr.add_tag(id, "important").unwrap();
        assert_eq!(mgr.by_tag("important").len(), 1);
        assert_eq!(mgr.by_tag("other").len(), 0);
    }

    #[test]
    fn test_rename() {
        let mut mgr = HexBookmarkManager::new();
        let id = mgr.add_at_offset("old", 0).unwrap();
        mgr.rename(id, "new").unwrap();
        assert_eq!(mgr.get(id).unwrap().name, "new");
    }

    #[test]
    fn test_rename_duplicate_rejected() {
        let mut mgr = HexBookmarkManager::new();
        let id1 = mgr.add_at_offset("a", 0).unwrap();
        let _id2 = mgr.add_at_offset("b", 1).unwrap();
        assert!(matches!(mgr.rename(id1, "b"), Err(BookmarkError::DuplicateName(_))));
    }

    #[test]
    fn test_set_comment() {
        let mut mgr = HexBookmarkManager::new();
        let id = mgr.add_at_offset("x", 0).unwrap();
        mgr.set_comment(id, "my note").unwrap();
        assert_eq!(mgr.get(id).unwrap().comment.as_deref(), Some("my note"));
    }

    #[test]
    fn test_all_insertion_order() {
        let mut mgr = HexBookmarkManager::new();
        let id1 = mgr.add_at_offset("first", 0).unwrap();
        let id2 = mgr.add_at_offset("second", 1).unwrap();
        let all = mgr.all();
        assert_eq!(all[0].id, id1);
        assert_eq!(all[1].id, id2);
    }

    #[test]
    fn test_clear() {
        let mut mgr = HexBookmarkManager::new();
        mgr.add_at_offset("a", 0).unwrap();
        mgr.clear();
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_json_roundtrip() {
        let mut mgr = HexBookmarkManager::new();
        let id = mgr.add_over_range("test", BookmarkRange::from_len(0x50, 16)).unwrap();
        mgr.set_color(id, BookmarkColor::CYAN).unwrap();
        let json = mgr.to_json().unwrap();
        let mut mgr2 = HexBookmarkManager::new();
        let n = mgr2.from_json(&json).unwrap();
        assert_eq!(n, 1);
        let bm = mgr2.find_by_name("test")[0];
        assert_eq!(bm.color, BookmarkColor::CYAN);
        assert_eq!(bm.range.start, 0x50);
    }

    #[test]
    fn test_bookmark_display() {
        let bm = HexBookmark::at_offset(1, "entry", 0x400000)
            .with_color(BookmarkColor::RED)
            .with_comment("entrypoint");
        let s = format!("{bm}");
        assert!(s.contains("entry"));
        assert!(s.contains("entrypoint"));
    }

    #[test]
    fn test_color_hex_roundtrip() {
        let c = BookmarkColor::from_u32(0xFF8800);
        assert_eq!(c.to_hex_string(), "#FF8800");
        let parsed = BookmarkColor::parse_hex("#FF8800").unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn test_color_luminance() {
        assert!(BookmarkColor::WHITE.luminance() > 0.9);
        assert!(BookmarkColor::from_u32(0x000000).luminance() < 0.1);
    }

    #[test]
    fn test_bookmark_range_contains() {
        let r = BookmarkRange::from_len(10, 5);
        assert!(r.contains(10));
        assert!(r.contains(14));
        assert!(!r.contains(15));
    }

    #[test]
    fn test_bookmark_range_overlaps() {
        let a = BookmarkRange::from_len(0, 10);
        let b = BookmarkRange::from_len(5, 10);
        let c = BookmarkRange::from_len(10, 5);
        assert!(a.overlaps(b));
        assert!(!a.overlaps(c));
    }

    #[test]
    fn test_bookmark_range_includes() {
        let outer = BookmarkRange::from_len(0, 20);
        let inner = BookmarkRange::from_len(5, 5);
        assert!(outer.includes(inner));
        assert!(!inner.includes(outer));
    }

    #[test]
    fn test_bookmark_is_point() {
        let bm = HexBookmark::at_offset(1, "pt", 0x100);
        assert!(bm.is_point());
        let bm2 = HexBookmark::over_range(2, "rng", BookmarkRange::from_len(0, 4));
        assert!(!bm2.is_point());
    }
}
