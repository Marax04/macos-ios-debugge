//! `comparison_view` — Side-by-side hex comparison of two files.
//!
//! Provides a split view for two buffers, synchronised scrolling, diff
//! highlighting (added/changed/removed), jump-to-next/prev difference, and
//! selective merge (copy bytes from right to left).

use std::fmt::Write as FmtWrite;
use std::ops::Range;

use serde::{Deserialize, Serialize};

const fn cast_usize_f64(n: usize) -> f64 { n as f64 }

// ─────────────────────────────────────────────────────────────────────────────
// DiffEntry (lightweight, re-defined here to avoid cross-crate dep)
// ─────────────────────────────────────────────────────────────────────────────

/// How a byte differs between left and right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByteDiff {
    Equal,
    LeftOnly,
    RightOnly,
    Changed { left: u8, right: u8 },
}

impl ByteDiff {
    #[must_use]
    pub const fn is_different(&self) -> bool {
        !matches!(self, Self::Equal)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ComparisonBuffer
// ─────────────────────────────────────────────────────────────────────────────

/// A pair of compared buffers with pre-computed diff.
#[derive(Debug)]
pub struct ComparisonBuffer {
    pub left: Vec<u8>,
    pub right: Vec<u8>,
    pub diffs: Vec<ByteDiff>,
    /// Offsets where differences start (contiguous groups merged).
    pub diff_regions: Vec<Range<usize>>,
}

impl ComparisonBuffer {
    /// Create and compute diff for two buffers.
    #[must_use]
    pub fn new(left: Vec<u8>, right: Vec<u8>) -> Self {
        let len = left.len().max(right.len());
        let diffs: Vec<ByteDiff> = (0..len)
            .map(|i| match (left.get(i), right.get(i)) {
                (Some(&lb), Some(&rb)) if lb == rb => ByteDiff::Equal,
                (Some(&lb), Some(&rb)) => ByteDiff::Changed { left: lb, right: rb },
                (Some(_), None) => ByteDiff::LeftOnly,
                (None, Some(_)) => ByteDiff::RightOnly,
                (None, None) => ByteDiff::Equal,
            })
            .collect();

        let diff_regions = compute_diff_regions(&diffs);

        Self { left, right, diffs, diff_regions }
    }

    /// Total length (max of both).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.diffs.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.diffs.is_empty()
    }

    /// Number of differing bytes.
    #[must_use]
    pub fn diff_count(&self) -> usize {
        self.diffs.iter().filter(|d| d.is_different()).count()
    }

    /// Number of differing regions.
    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.diff_regions.len()
    }

    /// Get the left byte at offset (or 0 if out of range).
    #[must_use]
    pub fn left_byte(&self, offset: usize) -> Option<u8> {
        self.left.get(offset).copied()
    }

    /// Get the right byte at offset.
    #[must_use]
    pub fn right_byte(&self, offset: usize) -> Option<u8> {
        self.right.get(offset).copied()
    }

    /// Merge bytes from right into left for the given range.
    /// Returns the number of bytes merged.
    pub fn merge_right_to_left(&mut self, range: Range<usize>) -> usize {
        let mut count = 0usize;
        for i in range {
            if i < self.right.len() {
                let rb = self.right[i];
                if i < self.left.len() {
                    self.left[i] = rb;
                } else {
                    while self.left.len() < i {
                        self.left.push(0);
                    }
                    self.left.push(rb);
                }
                count += 1;
            }
        }
        // Recompute diffs
        *self = Self::new(std::mem::take(&mut self.left), self.right.clone());
        count
    }

    /// Merge bytes from left into right for the given range.
    pub fn merge_left_to_right(&mut self, range: Range<usize>) -> usize {
        let mut count = 0usize;
        for i in range {
            if i < self.left.len() {
                let lb = self.left[i];
                if i < self.right.len() {
                    self.right[i] = lb;
                } else {
                    while self.right.len() < i {
                        self.right.push(0);
                    }
                    self.right.push(lb);
                }
                count += 1;
            }
        }
        *self = Self::new(self.left.clone(), std::mem::take(&mut self.right));
        count
    }
}

fn compute_diff_regions(diffs: &[ByteDiff]) -> Vec<Range<usize>> {
    let mut regions = vec![];
    let mut in_diff = false;
    let mut start = 0usize;

    for (i, d) in diffs.iter().enumerate() {
        if d.is_different() && !in_diff {
            start = i;
            in_diff = true;
        } else if !d.is_different() && in_diff {
            regions.push(start..i);
            in_diff = false;
        }
    }
    if in_diff {
        regions.push(start..diffs.len());
    }
    regions
}

// ─────────────────────────────────────────────────────────────────────────────
// ComparisonViewState
// ─────────────────────────────────────────────────────────────────────────────

/// Colour palette for the comparison view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonPalette {
    pub equal_bg: (u8, u8, u8),
    pub changed_left_bg: (u8, u8, u8),
    pub changed_right_bg: (u8, u8, u8),
    pub left_only_bg: (u8, u8, u8),
    pub right_only_bg: (u8, u8, u8),
    pub selected_bg: (u8, u8, u8),
}

impl Default for ComparisonPalette {
    fn default() -> Self {
        Self {
            equal_bg: (30, 30, 30),
            changed_left_bg: (100, 40, 40),
            changed_right_bg: (40, 80, 40),
            left_only_bg: (120, 30, 30),
            right_only_bg: (30, 120, 30),
            selected_bg: (80, 80, 200),
        }
    }
}

/// The full state of a comparison view.
#[derive(Debug)]
pub struct ComparisonViewState {
    pub buf: ComparisonBuffer,
    /// Current scroll offset (byte position of top-left).
    pub scroll_offset: usize,
    /// Bytes per row.
    pub bytes_per_row: usize,
    /// Number of visible rows.
    pub visible_rows: usize,
    /// Sync scrolling: if true, both panes scroll together.
    pub sync_scroll: bool,
    /// Independent scroll offsets for left/right if sync is off.
    pub left_scroll: usize,
    pub right_scroll: usize,
    /// Current diff region cursor (for jump-to-next/prev).
    pub current_diff: usize,
    /// Currently selected range (for selective merge).
    pub selection: Option<Range<usize>>,
    pub palette: ComparisonPalette,
    /// Label for the left file.
    pub left_label: String,
    /// Label for the right file.
    pub right_label: String,
}

impl ComparisonViewState {
    /// Create a new comparison view.
    pub fn new(
        left: Vec<u8>,
        right: Vec<u8>,
        left_label: impl Into<String>,
        right_label: impl Into<String>,
    ) -> Self {
        Self {
            buf: ComparisonBuffer::new(left, right),
            scroll_offset: 0,
            bytes_per_row: 16,
            visible_rows: 24,
            sync_scroll: true,
            left_scroll: 0,
            right_scroll: 0,
            current_diff: 0,
            selection: None,
            palette: ComparisonPalette::default(),
            left_label: left_label.into(),
            right_label: right_label.into(),
        }
    }

    // ── Navigation ───────────────────────────────────────────────────────────

    /// Jump to the next differing region. Returns the new offset or `None`.
    pub fn jump_next_diff(&mut self) -> Option<usize> {
        let regions = &self.buf.diff_regions;
        if regions.is_empty() {
            return None;
        }
        self.current_diff = (self.current_diff + 1) % regions.len();
        let offset = regions[self.current_diff].start;
        self.scroll_to(offset);
        Some(offset)
    }

    /// Jump to the previous differing region.
    pub fn jump_prev_diff(&mut self) -> Option<usize> {
        let regions = &self.buf.diff_regions;
        if regions.is_empty() {
            return None;
        }
        if self.current_diff == 0 {
            self.current_diff = regions.len() - 1;
        } else {
            self.current_diff -= 1;
        }
        let offset = regions[self.current_diff].start;
        self.scroll_to(offset);
        Some(offset)
    }

    /// Jump directly to a specific diff region index.
    pub fn jump_to_diff(&mut self, index: usize) -> Option<usize> {
        let region = self.buf.diff_regions.get(index)?;
        let off = region.start;
        self.current_diff = index;
        self.scroll_to(off);
        Some(off)
    }

    /// Scroll to ensure `offset` is visible.
    pub const fn scroll_to(&mut self, offset: usize) {
        let row = offset / self.bytes_per_row;
        let visible = self.visible_rows;
        let current_top = self.scroll_offset / self.bytes_per_row;
        let current_bottom = current_top + visible;

        if row < current_top || row >= current_bottom {
            // Place the row in the middle of the viewport
            let new_top = row.saturating_sub(visible / 2);
            self.scroll_offset = new_top * self.bytes_per_row;
        }

        if self.sync_scroll {
            self.left_scroll = self.scroll_offset;
            self.right_scroll = self.scroll_offset;
        }
    }

    /// Scroll by `delta` rows (positive = down, negative = up).
    pub fn scroll_by(&mut self, delta: i32) {
        let bpr = self.bytes_per_row;
        if delta >= 0 {
            let d = usize::try_from(delta).unwrap_or(0) * bpr;
            self.scroll_offset = (self.scroll_offset + d)
                .min(self.buf.len().saturating_sub(1) / bpr * bpr);
        } else {
            let d = usize::try_from(-delta).unwrap_or(0) * bpr;
            self.scroll_offset = self.scroll_offset.saturating_sub(d);
        }

        if self.sync_scroll {
            self.left_scroll = self.scroll_offset;
            self.right_scroll = self.scroll_offset;
        }
    }

    // ── Selection & merge ────────────────────────────────────────────────────

    /// Set the byte selection range.
    #[must_use]
    pub const fn current_diff_index(&self) -> usize {
        self.current_diff
    }

    pub const fn set_selection(&mut self, range: Range<usize>) {
        self.selection = Some(range);
    }

    /// Merge selected bytes from right to left.
    pub fn merge_selection_right_to_left(&mut self) -> usize {
        if let Some(sel) = self.selection.clone() {
            self.buf.merge_right_to_left(sel)
        } else {
            0
        }
    }

    /// Merge selected bytes from left to right.
    pub fn merge_selection_left_to_right(&mut self) -> usize {
        if let Some(sel) = self.selection.clone() {
            self.buf.merge_left_to_right(sel)
        } else {
            0
        }
    }

    /// Merge a specific diff region (right → left).
    pub fn merge_region_right_to_left(&mut self, region_index: usize) -> Option<usize> {
        let range = self.buf.diff_regions.get(region_index)?.clone();
        Some(self.buf.merge_right_to_left(range))
    }

    // ── Rendering ────────────────────────────────────────────────────────────

    /// Render the comparison view as an ANSI string.
    #[must_use]
    pub fn render_ansi(&self) -> String {
        let mut out = String::new();

        // Header
        let sep = "─".repeat(self.bytes_per_row * 3 + 12);
        writeln!(out, "LEFT: {}  |  RIGHT: {}", self.left_label, self.right_label).unwrap();
        writeln!(out, "{sep}").unwrap();

        let start_row = self.scroll_offset / self.bytes_per_row;
        let bpr = self.bytes_per_row;
        let total_len = self.buf.len();

        for row in start_row..start_row + self.visible_rows {
            let offset = row * bpr;
            if offset >= total_len {
                break;
            }
            let end = (offset + bpr).min(total_len);

            // Offset column
            write!(out, "\x1b[33m{offset:08X}\x1b[0m  ").unwrap();

            // Left hex side
            for i in offset..end {
                let (color, byte_val) = self.left_cell_color(i);
                let ansi = format!("\x1b[48;2;{};{};{}m", color.0, color.1, color.2);
                let bv = byte_val.map_or_else(|| "  ".to_string(), |b| format!("{b:02X}"));
                write!(out, "{ansi}{bv}\x1b[0m ").unwrap();
            }
            // Pad incomplete row
            for _ in (end - offset)..bpr {
                out.push_str("   ");
            }

            out.push_str("  |  ");

            // Right hex side
            for i in offset..end {
                let (color, byte_val) = self.right_cell_color(i);
                let ansi = format!("\x1b[48;2;{};{};{}m", color.0, color.1, color.2);
                let bv = byte_val.map_or_else(|| "  ".to_string(), |b| format!("{b:02X}"));
                write!(out, "{ansi}{bv}\x1b[0m ").unwrap();
            }

            out.push('\n');
        }

        // Footer
        write!(out, "{sep}\n{} diff regions, {} changed bytes\n",
            self.buf.region_count(),
            self.buf.diff_count()
        ).unwrap();

        out
    }

    fn left_cell_color(&self, offset: usize) -> ((u8, u8, u8), Option<u8>) {
        let selected = self.selection.as_ref().is_some_and(|r| r.contains(&offset));
        if selected {
            return (self.palette.selected_bg, self.buf.left_byte(offset));
        }
        let diff = self.buf.diffs.get(offset).copied().unwrap_or(ByteDiff::Equal);
        let color = match diff {
            ByteDiff::Equal | ByteDiff::RightOnly => self.palette.equal_bg,
            ByteDiff::Changed { .. } => self.palette.changed_left_bg,
            ByteDiff::LeftOnly => self.palette.left_only_bg,
        };
        (color, self.buf.left_byte(offset))
    }

    fn right_cell_color(&self, offset: usize) -> ((u8, u8, u8), Option<u8>) {
        let selected = self.selection.as_ref().is_some_and(|r| r.contains(&offset));
        if selected {
            return (self.palette.selected_bg, self.buf.right_byte(offset));
        }
        let diff = self.buf.diffs.get(offset).copied().unwrap_or(ByteDiff::Equal);
        let color = match diff {
            ByteDiff::Equal | ByteDiff::LeftOnly => self.palette.equal_bg,
            ByteDiff::Changed { .. } => self.palette.changed_right_bg,
            ByteDiff::RightOnly => self.palette.right_only_bg,
        };
        (color, self.buf.right_byte(offset))
    }

    // ── Stats ────────────────────────────────────────────────────────────────

    /// Similarity ratio (0.0–1.0).
    #[must_use]
    pub fn similarity(&self) -> f64 {
        let total = self.buf.len();
        if total == 0 {
            return 1.0;
        }
        let equal = self.buf.diffs.iter().filter(|d| **d == ByteDiff::Equal).count();
        cast_usize_f64(equal) / cast_usize_f64(total)
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} regions | {} bytes differ | {:.1}% similar",
            self.buf.region_count(),
            self.buf.diff_count(),
            self.similarity() * 100.0
        )
    }

    /// All diff regions.
    #[must_use]
    pub fn diff_regions(&self) -> &[Range<usize>] {
        &self.buf.diff_regions
    }

    /// Get left buffer (for export after merge).
    #[must_use]
    pub fn left_buffer(&self) -> &[u8] {
        &self.buf.left
    }

    /// Get right buffer.
    #[must_use]
    pub fn right_buffer(&self) -> &[u8] {
        &self.buf.right
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_view(left: &[u8], right: &[u8]) -> ComparisonViewState {
        ComparisonViewState::new(
            left.to_vec(),
            right.to_vec(),
            "left.bin",
            "right.bin",
        )
    }

    #[test]
    fn identical_files() {
        let data = b"ABCDEFGH";
        let view = make_view(data, data);
        assert_eq!(view.buf.diff_count(), 0);
        assert_eq!(view.buf.region_count(), 0);
        assert!((view.similarity() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn single_byte_diff() {
        let left = b"AAABBBCCC";
        let mut right = left.to_vec();
        right[4] = b'X';
        let view = make_view(left, &right);
        assert_eq!(view.buf.diff_count(), 1);
        assert_eq!(view.buf.region_count(), 1);
        assert!(matches!(view.buf.diffs[4], ByteDiff::Changed { left: b'B', right: b'X' }));
    }

    #[test]
    fn jump_next_diff() {
        let left = b"AAXAAAAXAA";
        let right = b"AAAAAAAAAA";
        let mut view = make_view(left, right);
        let off = view.jump_next_diff();
        assert!(off.is_some());
    }

    #[test]
    fn merge_right_to_left() {
        let left = b"AAAA";
        let right = b"BBBB";
        let mut view = make_view(left, right);
        view.set_selection(1..3);
        let merged = view.merge_selection_right_to_left();
        assert_eq!(merged, 2);
        assert_eq!(view.buf.left[1], b'B');
        assert_eq!(view.buf.left[2], b'B');
        assert_eq!(view.buf.left[0], b'A'); // unchanged
    }

    #[test]
    fn scroll_to_centers_offset() {
        let data: Vec<u8> = vec![0u8; 1000];
        let mut view = make_view(&data, &data);
        view.bytes_per_row = 16;
        view.visible_rows = 10;
        view.scroll_to(512);
        // Offset should now be visible
        let top = view.scroll_offset;
        let bottom = top + view.bytes_per_row * view.visible_rows;
        assert!(512 >= top && 512 < bottom);
    }

    #[test]
    fn summary_string() {
        let left = b"hello";
        let right = b"hellx";
        let view = make_view(left, right);
        let s = view.summary();
        assert!(s.contains("1 regions"));
    }
}
