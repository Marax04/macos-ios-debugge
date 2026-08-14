//! Hex editor selection management: single and multi-range selections,
//! selection modes, extension, and clipboard-ready serialisation.

use std::fmt;
use std::ops::Range;

// ── SelectionMode ─────────────────────────────────────────────────────────────

/// How the selection grows when the user extends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum SelectionMode {
    /// Standard byte-range selection (contiguous).
    #[default]
    Normal,
    /// Column (rectangular) selection: not yet supported at the model layer
    /// (reserved for future renderer integration).
    Column,
    /// Each nibble is selectable independently.
    Nibble,
}


impl fmt::Display for SelectionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── SelectionRange ────────────────────────────────────────────────────────────

/// A half-open byte range `[start, end)` within the hex buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionRange {
    /// Inclusive start offset.
    pub start: usize,
    /// Exclusive end offset.
    pub end: usize,
}

impl SelectionRange {
    /// Create a new range.  `start` and `end` are normalised so `start <= end`.
    #[must_use]
    pub const fn new(a: usize, b: usize) -> Self {
        if a <= b {
            Self { start: a, end: b }
        } else {
            Self { start: b, end: a }
        }
    }

    /// Create a zero-length "cursor" range at `offset`.
    #[must_use]
    pub const fn cursor(offset: usize) -> Self {
        Self {
            start: offset,
            end: offset,
        }
    }

    /// Number of bytes in the selection (`end - start`).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Returns `true` when the selection is empty (cursor position only).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Returns `true` when `offset` falls within `[start, end)`.
    #[must_use]
    pub const fn contains(&self, offset: usize) -> bool {
        offset >= self.start && offset < self.end
    }

    /// Returns `true` if this range overlaps with `other`.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Merge two overlapping or adjacent ranges into one.
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }

    /// Convert to a standard `Range<usize>`.
    #[must_use]
    pub const fn as_range(&self) -> Range<usize> {
        self.start..self.end
    }

    /// Clamp the range so it fits within `[0, max_offset)`.
    #[must_use]
    pub fn clamped(&self, max_offset: usize) -> Self {
        Self {
            start: self.start.min(max_offset),
            end: self.end.min(max_offset),
        }
    }
}

impl fmt::Display for SelectionRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:#x}..{:#x}] ({} bytes)", self.start, self.end, self.len())
    }
}

impl From<Range<usize>> for SelectionRange {
    fn from(r: Range<usize>) -> Self {
        Self::new(r.start, r.end)
    }
}

// ── HexSelection ─────────────────────────────────────────────────────────────

/// Complete selection state for a hex editor view.
///
/// Supports a primary selection and up to `MAX_EXTRA` additional selections
/// (e.g. from multi-select operations or column mode).
///
/// The *anchor* is fixed while the user extends the selection; the *cursor* is
/// the moving end.
pub struct HexSelection {
    /// Anchor offset (the fixed end of the selection).
    anchor: usize,
    /// Cursor offset (the moving end).
    cursor: usize,
    /// Selection mode.
    mode: SelectionMode,
    /// Additional independent selection ranges (multi-select).
    extra: Vec<SelectionRange>,
    /// Maximum buffer length (used for clamping).
    buffer_len: usize,
}

impl HexSelection {
    /// Create a new selection with cursor and anchor at `offset`.
    #[must_use]
    pub const fn new(buffer_len: usize) -> Self {
        Self {
            anchor: 0,
            cursor: 0,
            mode: SelectionMode::Normal,
            extra: Vec::new(),
            buffer_len,
        }
    }

    // ── Accessors ────────────────────────────────────────────────────────────

    /// The primary selection range `[min(anchor,cursor), max(anchor,cursor))`.
    #[must_use]
    pub const fn primary(&self) -> SelectionRange {
        SelectionRange::new(self.anchor, self.cursor)
    }

    /// The cursor (moving) offset.
    #[must_use]
    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    /// The anchor (fixed) offset.
    #[must_use]
    pub const fn anchor(&self) -> usize {
        self.anchor
    }

    /// Current selection mode.
    #[must_use]
    pub const fn mode(&self) -> SelectionMode {
        self.mode
    }

    /// Returns `true` if the primary selection is empty (cursor == anchor).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.primary().is_empty()
    }

    /// Returns `true` if there are any additional selections.
    #[must_use]
    pub const fn has_extra(&self) -> bool {
        !self.extra.is_empty()
    }

    /// Number of bytes in the primary selection.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.primary().len()
    }

    // ── Mutation ──────────────────────────────────────────────────────────────

    /// Move the cursor to `offset` without extending the selection (clears anchor).
    pub fn set_cursor(&mut self, offset: usize) {
        let offset = offset.min(self.buffer_len);
        self.cursor = offset;
        self.anchor = offset;
        self.extra.clear();
    }

    /// Set the anchor to `offset` and start a selection.
    ///
    /// Also moves the cursor to `offset` so that subsequent calls to
    /// `extend_selection(delta)` produce a selection starting at the anchor.
    pub fn set_anchor(&mut self, offset: usize) {
        let off = offset.min(self.buffer_len);
        self.anchor = off;
        self.cursor = off;
    }

    /// Move the cursor to `offset`, extending the selection from the anchor.
    pub fn extend_cursor(&mut self, offset: usize) {
        self.cursor = offset.min(self.buffer_len);
    }

    /// Change the selection mode.
    pub const fn set_mode(&mut self, mode: SelectionMode) {
        self.mode = mode;
    }

    /// Update the buffer length (after insert/delete operations).
    pub fn update_buffer_len(&mut self, new_len: usize) {
        self.buffer_len = new_len;
        self.cursor = self.cursor.min(new_len);
        self.anchor = self.anchor.min(new_len);
        for r in &mut self.extra {
            *r = r.clamped(new_len);
        }
    }

    // ── Extension helpers ─────────────────────────────────────────────────────

    /// Extend the selection by `delta` bytes (positive = forward, negative = backward).
    pub fn extend_selection(&mut self, delta: isize) {
        let delta64 = i64::try_from(delta).unwrap_or(if delta > 0 { i64::MAX } else { i64::MIN });
        let new_cursor = usize::try_from(
            (i64::try_from(self.cursor).unwrap_or(i64::MAX) + delta64)
                .clamp(0, i64::try_from(self.buffer_len).unwrap_or(i64::MAX))
                .cast_unsigned(),
        )
        .unwrap_or(self.buffer_len);
        self.cursor = new_cursor;
    }

    /// Select all bytes in the buffer.
    pub fn select_all(&mut self) {
        self.anchor = 0;
        self.cursor = self.buffer_len;
        self.extra.clear();
    }

    /// Select the range `[start, end)`.
    pub fn select_range(&mut self, start: usize, end: usize) {
        let start = start.min(self.buffer_len);
        let end = end.min(self.buffer_len);
        self.anchor = start;
        self.cursor = end;
        self.extra.clear();
    }

    /// Add an extra (multi-select) range without affecting the primary selection.
    pub fn add_extra(&mut self, range: SelectionRange) {
        let clamped = range.clamped(self.buffer_len);
        if !clamped.is_empty() {
            self.extra.push(clamped);
        }
    }

    /// Remove all extra selections.
    pub fn clear_extra(&mut self) {
        self.extra.clear();
    }

    /// Collapse the selection to a single cursor at `offset`.
    pub fn collapse(&mut self, offset: usize) {
        let offset = offset.min(self.buffer_len);
        self.anchor = offset;
        self.cursor = offset;
        self.extra.clear();
    }

    // ── Query helpers ─────────────────────────────────────────────────────────

    /// Returns `true` if `offset` falls within any selection (primary or extra).
    #[must_use]
    pub fn is_selected(&self, offset: usize) -> bool {
        if !self.is_empty() && self.primary().contains(offset) {
            return true;
        }
        self.extra.iter().any(|r| r.contains(offset))
    }

    /// Return all selection ranges (primary first, then extra), merged where
    /// they overlap.
    #[must_use]
    pub fn all_ranges_merged(&self) -> Vec<SelectionRange> {
        let mut ranges: Vec<SelectionRange> = Vec::new();
        let primary = self.primary();
        if !primary.is_empty() {
            ranges.push(primary);
        }
        ranges.extend_from_slice(&self.extra);
        merge_ranges(ranges)
    }

    /// Total number of selected bytes across all ranges.
    #[must_use]
    pub fn total_selected_bytes(&self) -> usize {
        self.all_ranges_merged().iter().map(SelectionRange::len).sum()
    }

    /// Extract the selected bytes from `data`.
    ///
    /// Returns up to 256 KiB to avoid memory issues on huge selections.
    #[must_use]
    pub fn extract_bytes<'a>(&self, data: &'a [u8]) -> Vec<&'a [u8]> {
        const MAX_BYTES: usize = 256 * 1024;
        let mut extracted: Vec<&'a [u8]> = Vec::new();
        let mut remaining = MAX_BYTES;

        for range in self.all_ranges_merged() {
            if remaining == 0 {
                break;
            }
            let end = range.end.min(data.len());
            let start = range.start.min(end);
            let slice_len = (end - start).min(remaining);
            extracted.push(&data[start..start + slice_len]);
            remaining = remaining.saturating_sub(slice_len);
        }
        extracted
    }

    // ── Clipboard helpers ─────────────────────────────────────────────────────

    /// Render the primary selection as an uppercase hex string with spaces.
    #[must_use]
    pub fn primary_as_hex(&self, data: &[u8]) -> String {
        let r = self.primary().clamped(data.len());
        if r.is_empty() {
            return String::new();
        }
        data[r.as_range()]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Render the primary selection as printable ASCII (`.` for non-printable).
    #[must_use]
    pub fn primary_as_ascii(&self, data: &[u8]) -> String {
        let r = self.primary().clamped(data.len());
        if r.is_empty() {
            return String::new();
        }
        data[r.as_range()]
            .iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect()
    }

    // ── Navigation helpers ────────────────────────────────────────────────────

    /// Move cursor (and anchor) forward by one byte, clamped to buffer length.
    pub fn move_right(&mut self) {
        let new = (self.cursor + 1).min(self.buffer_len);
        self.cursor = new;
        self.anchor = new;
    }

    /// Move cursor (and anchor) backward by one byte, clamped to 0.
    pub const fn move_left(&mut self) {
        let new = self.cursor.saturating_sub(1);
        self.cursor = new;
        self.anchor = new;
    }

    /// Move cursor (and anchor) forward by `cols` bytes (next row).
    pub fn move_down(&mut self, cols: usize) {
        let new = (self.cursor + cols).min(self.buffer_len);
        self.cursor = new;
        self.anchor = new;
    }

    /// Move cursor (and anchor) backward by `cols` bytes (previous row).
    pub const fn move_up(&mut self, cols: usize) {
        let new = self.cursor.saturating_sub(cols);
        self.cursor = new;
        self.anchor = new;
    }

    /// Move cursor (and anchor) to start of current row.
    pub const fn move_home(&mut self, cols: usize) {
        if cols == 0 {
            return;
        }
        let col = self.cursor % cols;
        self.cursor -= col;
        self.anchor = self.cursor;
    }

    /// Move cursor (and anchor) to end of current row.
    pub fn move_end(&mut self, cols: usize) {
        if cols == 0 {
            return;
        }
        let col = self.cursor % cols;
        let new = (self.cursor + (cols - 1 - col)).min(self.buffer_len);
        self.cursor = new;
        self.anchor = new;
    }
}

impl fmt::Debug for HexSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HexSelection {{ anchor={:#x}, cursor={:#x}, mode={}, extra={}, buf={} }}",
            self.anchor,
            self.cursor,
            self.mode,
            self.extra.len(),
            self.buffer_len
        )
    }
}

// ── Merge utility ─────────────────────────────────────────────────────────────

/// Merge a list of [`SelectionRange`]s, combining overlapping or adjacent ones.
#[must_use]
pub fn merge_ranges(mut ranges: Vec<SelectionRange>) -> Vec<SelectionRange> {
    if ranges.len() <= 1 {
        return ranges;
    }
    ranges.sort_by_key(|r| r.start);
    let mut merged: Vec<SelectionRange> = Vec::new();
    let mut current = ranges[0];
    for r in ranges.into_iter().skip(1) {
        if r.start <= current.end {
            current = current.merge(&r);
        } else {
            merged.push(current);
            current = r;
        }
    }
    merged.push(current);
    merged
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_starts_empty() {
        let sel = HexSelection::new(100);
        assert!(sel.is_empty());
        assert_eq!(sel.len(), 0);
    }

    #[test]
    fn set_cursor_clears_selection() {
        let mut sel = HexSelection::new(100);
        sel.select_range(10, 20);
        sel.set_cursor(5);
        assert!(sel.is_empty());
        assert_eq!(sel.cursor(), 5);
    }

    #[test]
    fn extend_selection_forward() {
        let mut sel = HexSelection::new(100);
        sel.set_anchor(10);
        sel.extend_selection(20);
        assert_eq!(sel.primary().start, 10);
        assert_eq!(sel.primary().end, 30);
    }

    #[test]
    fn extend_selection_backward() {
        let mut sel = HexSelection::new(100);
        sel.set_cursor(50);
        sel.set_anchor(50);
        sel.extend_selection(-10);
        let p = sel.primary();
        assert_eq!(p.start, 40);
        assert_eq!(p.end, 50);
    }

    #[test]
    fn select_all_covers_buffer() {
        let mut sel = HexSelection::new(256);
        sel.select_all();
        assert_eq!(sel.primary().start, 0);
        assert_eq!(sel.primary().end, 256);
    }

    #[test]
    fn is_selected_primary() {
        let mut sel = HexSelection::new(100);
        sel.select_range(10, 20);
        assert!(sel.is_selected(10));
        assert!(sel.is_selected(15));
        assert!(!sel.is_selected(20)); // exclusive end
        assert!(!sel.is_selected(9));
    }

    #[test]
    fn is_selected_extra() {
        let mut sel = HexSelection::new(100);
        sel.add_extra(SelectionRange::new(50, 60));
        assert!(sel.is_selected(55));
        assert!(!sel.is_selected(45));
    }

    #[test]
    fn total_selected_bytes_multi_range() {
        let mut sel = HexSelection::new(100);
        sel.select_range(0, 10);
        sel.add_extra(SelectionRange::new(20, 30));
        assert_eq!(sel.total_selected_bytes(), 20);
    }

    #[test]
    fn merge_overlapping_ranges() {
        let a = SelectionRange::new(0, 10);
        let b = SelectionRange::new(5, 15);
        let merged = merge_ranges(vec![a, b]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].start, 0);
        assert_eq!(merged[0].end, 15);
    }

    #[test]
    fn merge_non_overlapping_ranges() {
        let a = SelectionRange::new(0, 5);
        let b = SelectionRange::new(10, 15);
        let merged = merge_ranges(vec![a, b]);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn extract_bytes_from_selection() {
        let mut sel = HexSelection::new(10);
        sel.select_range(2, 5);
        let data: Vec<u8> = (0u8..10).collect();
        let slices = sel.extract_bytes(&data);
        assert_eq!(slices.len(), 1);
        assert_eq!(slices[0], &[2, 3, 4]);
    }

    #[test]
    fn primary_as_hex() {
        let mut sel = HexSelection::new(4);
        sel.select_range(0, 4);
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(sel.primary_as_hex(&data), "DE AD BE EF");
    }

    #[test]
    fn primary_as_ascii_replaces_non_printable() {
        let mut sel = HexSelection::new(4);
        sel.select_range(0, 4);
        let data = vec![b'A', 0x00, b'Z', 0xFF];
        assert_eq!(sel.primary_as_ascii(&data), "A.Z.");
    }

    #[test]
    fn selection_range_contains() {
        let r = SelectionRange::new(10, 20);
        assert!(r.contains(10));
        assert!(r.contains(19));
        assert!(!r.contains(20));
        assert!(!r.contains(9));
    }

    #[test]
    fn selection_range_overlaps() {
        let a = SelectionRange::new(0, 10);
        let b = SelectionRange::new(5, 15);
        let c = SelectionRange::new(10, 20);
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn move_navigation() {
        let mut sel = HexSelection::new(100);
        sel.set_cursor(10);
        sel.move_right();
        assert_eq!(sel.cursor(), 11);
        sel.move_left();
        assert_eq!(sel.cursor(), 10);
        sel.move_down(16);
        assert_eq!(sel.cursor(), 26);
        sel.move_up(16);
        assert_eq!(sel.cursor(), 10);
    }

    #[test]
    fn move_left_clamps_at_zero() {
        let mut sel = HexSelection::new(100);
        sel.set_cursor(0);
        sel.move_left();
        assert_eq!(sel.cursor(), 0);
    }

    #[test]
    fn update_buffer_len_clamps_offsets() {
        let mut sel = HexSelection::new(1000);
        sel.select_range(800, 900);
        sel.update_buffer_len(500);
        let p = sel.primary();
        assert!(p.end <= 500);
    }

    #[test]
    fn clamped_range() {
        let r = SelectionRange::new(10, 50);
        let c = r.clamped(30);
        assert_eq!(c.end, 30);
    }

    #[test]
    fn collapse_clears_selection() {
        let mut sel = HexSelection::new(100);
        sel.select_range(0, 50);
        sel.add_extra(SelectionRange::new(60, 70));
        sel.collapse(25);
        assert!(sel.is_empty());
        assert!(!sel.has_extra());
        assert_eq!(sel.cursor(), 25);
    }
}
