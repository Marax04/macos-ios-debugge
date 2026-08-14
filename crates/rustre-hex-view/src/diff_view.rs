//! `diff_view` — Side-by-side binary diff view for the hex viewer.
//!
//! # Key types
//! * [`DiffView`]      — manages two buffers and their diff state.
//! * [`DiffEntry`]     — a single contiguous changed region.
//! * [`ChangeType`]    — unchanged / modified / inserted / deleted.
//! * [`DiffRenderer`]  — formats the diff for display (text / ANSI).
//! * [`DiffHighlight`] — per-byte highlight instruction.
//! * [`DiffNavigator`] — stateful cursor over diff entries.

use std::collections::VecDeque;
use std::fmt;
use std::ops::Range;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DiffError {
    #[error("buffer A is empty")]
    EmptyA,
    #[error("buffer B is empty")]
    EmptyB,
    #[error("invalid range {start}..{end}")]
    InvalidRange { start: usize, end: usize },
    #[error("no diff computed yet; call compute_diff() first")]
    NoDiff,
    #[error("navigator index {0} out of range")]
    IndexOutOfRange(usize),
}

pub type DiffResult<T> = Result<T, DiffError>;

// ---------------------------------------------------------------------------
// ChangeType
// ---------------------------------------------------------------------------

/// Classification of a contiguous changed region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChangeType {
    /// Bytes are identical in both buffers.
    Unchanged,
    /// Bytes exist in both buffers but differ.
    Modified,
    /// Bytes exist only in buffer B (inserted).
    Inserted,
    /// Bytes exist only in buffer A (deleted).
    Deleted,
}

impl fmt::Display for ChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unchanged => write!(f, "="),
            Self::Modified => write!(f, "~"),
            Self::Inserted => write!(f, "+"),
            Self::Deleted => write!(f, "-"),
        }
    }
}

impl ChangeType {
    /// Returns the conventional one-character sigil.
    #[must_use]
    pub const fn sigil(self) -> char {
        match self {
            Self::Unchanged => ' ',
            Self::Modified => '~',
            Self::Inserted => '+',
            Self::Deleted => '-',
        }
    }

    /// True if this entry represents any kind of change.
    #[must_use]
    pub const fn is_changed(self) -> bool {
        !matches!(self, Self::Unchanged)
    }

    /// ANSI escape colour for terminal rendering.
    #[must_use]
    pub const fn ansi_color(self) -> &'static str {
        match self {
            Self::Unchanged => "\x1b[0m",
            Self::Modified => "\x1b[33m", // yellow
            Self::Inserted => "\x1b[32m", // green
            Self::Deleted => "\x1b[31m",  // red
        }
    }
}

// ---------------------------------------------------------------------------
// DiffEntry
// ---------------------------------------------------------------------------

/// A single contiguous region in the diff result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffEntry {
    /// Byte range in buffer A (`None` for pure insertions).
    pub range_a: Option<Range<usize>>,
    /// Byte range in buffer B (`None` for pure deletions).
    pub range_b: Option<Range<usize>>,
    /// Classification of this region.
    pub change_type: ChangeType,
    /// Actual bytes from A (empty for insertions / unchanged when not stored).
    pub bytes_a: Vec<u8>,
    /// Actual bytes from B (empty for deletions).
    pub bytes_b: Vec<u8>,
}

impl DiffEntry {
    /// Length of the A side (0 for pure insertions).
    #[must_use]
    pub fn len_a(&self) -> usize {
        self.range_a.as_ref().map_or(0, |r| r.end - r.start)
    }

    /// Length of the B side (0 for pure deletions).
    #[must_use]
    pub fn len_b(&self) -> usize {
        self.range_b.as_ref().map_or(0, |r| r.end - r.start)
    }

    /// True if this entry is actually identical on both sides.
    #[must_use]
    pub fn is_unchanged(&self) -> bool {
        self.change_type == ChangeType::Unchanged
    }
}

impl fmt::Display for DiffEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = self
            .range_a
            .as_ref().map_or_else(|| "-".into(), |r| format!("{:#x}..{:#x}", r.start, r.end));
        let b = self
            .range_b
            .as_ref().map_or_else(|| "-".into(), |r| format!("{:#x}..{:#x}", r.start, r.end));
        write!(f, "[{}] A:{} B:{}", self.change_type, a, b)
    }
}

// ---------------------------------------------------------------------------
// DiffHighlight — per-byte coloring instruction
// ---------------------------------------------------------------------------

/// Rendering hint for a single byte position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffHighlight {
    /// Buffer (A = false, B = true) this highlight applies to.
    pub is_b: bool,
    /// Byte offset within its buffer.
    pub offset: usize,
    /// Change classification.
    pub change_type: ChangeType,
}

impl DiffHighlight {
    #[must_use]
    pub const fn new(is_b: bool, offset: usize, change_type: ChangeType) -> Self {
        Self {
            is_b,
            offset,
            change_type,
        }
    }
}

// ---------------------------------------------------------------------------
// DiffAlgorithm — simple linear scan (LCS-based extension can be plugged in)
// ---------------------------------------------------------------------------

/// Strategy used by [`DiffView::compute_diff`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffAlgorithm {
    /// Byte-by-byte linear comparison (fast, no reordering).
    Linear,
    /// Myers diff algorithm for minimal edit script.
    Myers,
}

// ---------------------------------------------------------------------------
// Core diff computation — linear strategy
// ---------------------------------------------------------------------------

fn linear_diff(buf_a: &[u8], buf_b: &[u8]) -> Vec<DiffEntry> {
    let len = buf_a.len().max(buf_b.len());
    let mut entries: Vec<DiffEntry> = Vec::new();
    let mut pos = 0usize;

    while pos < len {
        let ba = buf_a.get(pos).copied();
        let bb = buf_b.get(pos).copied();
        let ct = match (ba, bb) {
            (Some(lhs), Some(rhs)) if lhs == rhs => ChangeType::Unchanged,
            (Some(_), Some(_)) => ChangeType::Modified,
            (None, Some(_)) => ChangeType::Inserted,
            (Some(_), None) => ChangeType::Deleted,
            (None, None) => break,
        };

        // Merge run of same type.
        let start = pos;
        while pos < len {
            let ba2 = buf_a.get(pos).copied();
            let bb2 = buf_b.get(pos).copied();
            let ct2 = match (ba2, bb2) {
                (Some(lhs), Some(rhs)) if lhs == rhs => ChangeType::Unchanged,
                (Some(_), Some(_)) => ChangeType::Modified,
                (None, Some(_)) => ChangeType::Inserted,
                (Some(_), None) => ChangeType::Deleted,
                (None, None) => break,
            };
            if ct2 != ct {
                break;
            }
            pos += 1;
        }

        let end_a = pos.min(buf_a.len());
        let end_b = pos.min(buf_b.len());
        let ra = if start < buf_a.len() {
            Some(start..end_a)
        } else {
            None
        };
        let rb = if start < buf_b.len() {
            Some(start..end_b)
        } else {
            None
        };
        let bytes_a = ra
            .as_ref()
            .map(|range| buf_a[range.clone()].to_vec())
            .unwrap_or_default();
        let bytes_b = rb
            .as_ref()
            .map(|range| buf_b[range.clone()].to_vec())
            .unwrap_or_default();
        entries.push(DiffEntry {
            range_a: ra,
            range_b: rb,
            change_type: ct,
            bytes_a,
            bytes_b,
        });
    }
    entries
}

// Minimal Myers diff.
fn myers_diff(buf_a: &[u8], buf_b: &[u8]) -> Vec<DiffEntry> {
    // For large inputs fall back to linear to keep compile size manageable.
    if buf_a.len() + buf_b.len() > 65536 {
        return linear_diff(buf_a, buf_b);
    }
    // Simple Myers implementation: build edit graph, then trace back.
    let len_a = buf_a.len() as i64;
    let len_b = buf_b.len() as i64;
    let max_d = len_a + len_b;
    if max_d == 0 {
        return Vec::new();
    }
    let offset = max_d;
    let size = (2 * max_d + 1) as usize;
    let mut endpoints: Vec<i64> = vec![0; size];
    let mut trace: Vec<Vec<i64>> = Vec::new();

    'outer: for depth in 0..=max_d {
        trace.push(endpoints.clone());
        let mut diag = -depth;
        while diag <= depth {
            let idx = (diag + offset) as usize;
            let mut xx = if diag == -depth
                || (diag != depth
                    && endpoints[(diag - 1 + offset) as usize]
                        < endpoints[(diag + 1 + offset) as usize])
            {
                endpoints[(diag + 1 + offset) as usize]
            } else {
                endpoints[(diag - 1 + offset) as usize] + 1
            };
            let mut yy = xx - diag;
            while xx < len_a && yy < len_b && buf_a[xx as usize] == buf_b[yy as usize] {
                xx += 1;
                yy += 1;
            }
            endpoints[idx] = xx;
            if xx >= len_a && yy >= len_b {
                break 'outer;
            }
            diag += 2;
        }
    }

    // Backtrack to produce operations.
    let mut ops: Vec<(char, usize, usize)> = Vec::new();
    let mut xx = len_a;
    let mut yy = len_b;
    for (depth_idx, snap) in trace.iter().enumerate().rev() {
        let depth = depth_idx as i64;
        let diag = xx - yy;
        let lower = if diag - 1 + offset >= 0 {
            snap.get((diag - 1 + offset) as usize).copied().unwrap_or(i64::MIN)
        } else {
            i64::MIN
        };
        let upper = snap.get((diag + 1 + offset) as usize).copied().unwrap_or(i64::MIN);
        let prev_k = if diag == -depth || (diag != depth && lower < upper) {
            diag + 1
        } else {
            diag - 1
        };
        let prev_x = snap.get((prev_k + offset) as usize).copied().unwrap_or(0);
        let prev_y = prev_x - prev_k;
        // Snakes: walk diagonal back from (xx,yy) to (prev_x, prev_y) skipping the single edit step.
        while xx > prev_x && yy > prev_y {
            ops.push(('=', (xx - 1) as usize, (yy - 1) as usize));
            xx -= 1;
            yy -= 1;
        }
        if depth > 0 {
            if xx > prev_x {
                // Deletion from A
                ops.push(('-', (xx - 1) as usize, 0));
            } else if yy > prev_y {
                // Insertion from B
                ops.push(('+', 0, (yy - 1) as usize));
            }
        }
        xx = prev_x;
        yy = prev_y;
        if xx <= 0 && yy <= 0 {
            break;
        }
    }
    ops.reverse();

    // Convert ops to DiffEntries (merge adjacent same-type).
    let mut entries: Vec<DiffEntry> = Vec::new();
    for (op, ai, bi) in ops {
        let ct = match op {
            '=' => ChangeType::Unchanged,
            '+' => ChangeType::Inserted,
            '-' => ChangeType::Deleted,
            _ => ChangeType::Modified,
        };
        let (ra, rb) = match ct {
            ChangeType::Inserted => (None, Some(bi..bi + 1)),
            ChangeType::Deleted => (Some(ai..ai + 1), None),
            _ => (Some(ai..ai + 1), Some(bi..bi + 1)),
        };
        let bytes_a = ra
            .as_ref()
            .and_then(|range| buf_a.get(range.clone()))
            .unwrap_or(&[])
            .to_vec();
        let bytes_b = rb
            .as_ref()
            .and_then(|range| buf_b.get(range.clone()))
            .unwrap_or(&[])
            .to_vec();
        // Merge with last entry if same type.
        if let Some(last) = entries.last_mut() && last.change_type == ct {
            if let (Some(la), Some(ra2)) = (&mut last.range_a, &ra) {
                if la.end == ra2.start {
                    la.end = ra2.end;
                    last.bytes_a.extend_from_slice(&bytes_a);
                }
            } else if last.range_a.is_none() && ra.is_none() && let (Some(lb), Some(rb2)) = (&mut last.range_b, &rb) && lb.end == rb2.start {
                // both insertions — extend b range
                lb.end = rb2.end;
                last.bytes_b.extend_from_slice(&bytes_b);
                continue;
            }
            if let (Some(lb), Some(rb2)) = (&mut last.range_b, &rb) {
                if lb.end == rb2.start {
                    lb.end = rb2.end;
                    last.bytes_b.extend_from_slice(&bytes_b);
                    continue;
                }
            } else if last.range_b.is_none() && rb.is_none() && let (Some(la), Some(ra2)) = (&mut last.range_a, &ra) && la.end == ra2.start {
                la.end = ra2.end;
                last.bytes_a.extend_from_slice(&bytes_a);
                continue;
            }
        }
        entries.push(DiffEntry {
            range_a: ra,
            range_b: rb,
            change_type: ct,
            bytes_a,
            bytes_b,
        });
    }
    entries
}

// ---------------------------------------------------------------------------
// DiffView
// ---------------------------------------------------------------------------

/// Side-by-side binary diff view.
///
/// Holds two byte buffers (A and B), a computed list of [`DiffEntry`] values,
/// and statistics about the differences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffView {
    /// Buffer A (original / left).
    pub buf_a: Vec<u8>,
    /// Buffer B (modified / right).
    pub buf_b: Vec<u8>,
    /// Computed diff entries (populated after [`compute_diff`]).
    pub entries: Vec<DiffEntry>,
    /// Algorithm used for the last diff.
    pub algorithm: DiffAlgorithm,
    /// Number of bytes that changed.
    pub changed_bytes: usize,
    /// Number of bytes that are the same.
    pub unchanged_bytes: usize,
}

impl DiffView {
    /// Create a new `DiffView` from two byte slices.
    pub fn new(a: impl Into<Vec<u8>>, b: impl Into<Vec<u8>>) -> Self {
        Self {
            buf_a: a.into(),
            buf_b: b.into(),
            entries: Vec::new(),
            algorithm: DiffAlgorithm::Linear,
            changed_bytes: 0,
            unchanged_bytes: 0,
        }
    }

    /// Replace buffer A and invalidate the diff.
    pub fn set_a(&mut self, a: impl Into<Vec<u8>>) {
        self.buf_a = a.into();
        self.entries.clear();
    }

    /// Replace buffer B and invalidate the diff.
    pub fn set_b(&mut self, b: impl Into<Vec<u8>>) {
        self.buf_b = b.into();
        self.entries.clear();
    }

    /// Compute (or recompute) the diff.
    pub fn compute_diff(&mut self, algorithm: DiffAlgorithm) {
        self.algorithm = algorithm;
        self.entries = match algorithm {
            DiffAlgorithm::Linear => linear_diff(&self.buf_a, &self.buf_b),
            DiffAlgorithm::Myers => myers_diff(&self.buf_a, &self.buf_b),
        };
        self.recalculate_stats();
    }

    fn recalculate_stats(&mut self) {
        self.changed_bytes = 0;
        self.unchanged_bytes = 0;
        for e in &self.entries {
            match e.change_type {
                ChangeType::Unchanged => self.unchanged_bytes += e.len_a(),
                _ => self.changed_bytes += e.len_a().max(e.len_b()),
            }
        }
    }

    /// Returns changed entries only.
    #[must_use]
    pub fn changed_entries(&self) -> Vec<&DiffEntry> {
        self.entries
            .iter()
            .filter(|e| e.change_type.is_changed())
            .collect()
    }

    /// Similarity ratio: unchanged / total bytes (0.0 – 1.0).
    #[must_use]
    pub fn similarity(&self) -> f64 {
        let total = self.changed_bytes + self.unchanged_bytes;
        if total == 0 {
            return 1.0;
        }
        self.unchanged_bytes as f64 / total as f64
    }

    /// Generate per-byte highlight instructions for buffer A.
    #[must_use]
    pub fn highlights_a(&self) -> Vec<DiffHighlight> {
        let mut out = Vec::new();
        for e in &self.entries {
            if let Some(r) = &e.range_a {
                for off in r.clone() {
                    out.push(DiffHighlight::new(false, off, e.change_type));
                }
            }
        }
        out
    }

    /// Generate per-byte highlight instructions for buffer B.
    #[must_use]
    pub fn highlights_b(&self) -> Vec<DiffHighlight> {
        let mut out = Vec::new();
        for e in &self.entries {
            if let Some(r) = &e.range_b {
                for off in r.clone() {
                    out.push(DiffHighlight::new(true, off, e.change_type));
                }
            }
        }
        out
    }

    /// Look up the change type at a specific offset in buffer A.
    #[must_use]
    pub fn change_at_a(&self, offset: usize) -> Option<ChangeType> {
        self.entries
            .iter()
            .find(|e| {
                e.range_a
                    .as_ref()
                    .is_some_and(|r| r.contains(&offset))
            })
            .map(|e| e.change_type)
    }

    /// Look up the change type at a specific offset in buffer B.
    #[must_use]
    pub fn change_at_b(&self, offset: usize) -> Option<ChangeType> {
        self.entries
            .iter()
            .find(|e| {
                e.range_b
                    .as_ref()
                    .is_some_and(|r| r.contains(&offset))
            })
            .map(|e| e.change_type)
    }
}

// ---------------------------------------------------------------------------
// DiffRenderer
// ---------------------------------------------------------------------------

/// Rendering options for the diff view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderOptions {
    /// Number of bytes per row.
    pub bytes_per_row: usize,
    /// Whether to include an ASCII column.
    pub show_ascii: bool,
    /// Whether to use ANSI colour escapes.
    pub ansi_colors: bool,
    /// Whether to omit unchanged rows from output.
    pub hide_unchanged: bool,
    /// How many context rows around changes to include when `hide_unchanged = true`.
    pub context_rows: usize,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            bytes_per_row: 16,
            show_ascii: true,
            ansi_colors: false,
            hide_unchanged: false,
            context_rows: 2,
        }
    }
}

/// Formats a `DiffView` for display.
#[derive(Debug, Clone, Default)]
pub struct DiffRenderer {
    pub options: RenderOptions,
}

impl DiffRenderer {
    #[must_use]
    pub const fn new(options: RenderOptions) -> Self {
        Self { options }
    }

    /// Render the diff as a string.
    pub fn render(&self, view: &DiffView) -> DiffResult<String> {
        if view.entries.is_empty() && (!view.buf_a.is_empty() || !view.buf_b.is_empty()) {
            return Err(DiffError::NoDiff);
        }
        let mut out = String::new();
        let bpr = self.options.bytes_per_row;
        let len = view.buf_a.len().max(view.buf_b.len());
        let mut row = 0;
        let mut offset = 0;
        while offset < len {
            let end = (offset + bpr).min(len);
            let ct_a = view.change_at_a(offset).unwrap_or(ChangeType::Unchanged);
            let ct_b = view.change_at_b(offset).unwrap_or(ChangeType::Unchanged);
            let is_changed = ct_a.is_changed() || ct_b.is_changed();
            if self.options.hide_unchanged && !is_changed {
                offset = end;
                row += 1;
                continue;
            }
            let color_a = if self.options.ansi_colors {
                ct_a.ansi_color()
            } else {
                ""
            };
            let reset = if self.options.ansi_colors {
                "\x1b[0m"
            } else {
                ""
            };
            // A side.
            let hex_a: Vec<String> = (offset..end)
                .map(|i| {
                    view.buf_a
                        .get(i)
                        .map_or("  ".into(), |b| format!("{b:02X}"))
                })
                .collect();
            // B side.
            let color_b = if self.options.ansi_colors {
                ct_b.ansi_color()
            } else {
                ""
            };
            let hex_b: Vec<String> = (offset..end)
                .map(|i| {
                    view.buf_b
                        .get(i)
                        .map_or("  ".into(), |b| format!("{b:02X}"))
                })
                .collect();
            let sigil = if is_changed { ct_a.sigil() } else { ' ' };
            out.push_str(&format!(
                "{row:04} {offset:08X}  {color_a}{:<47}{reset}  {sigil}  {color_b}{:<47}{reset}\n",
                hex_a.join(" "),
                hex_b.join(" ")
            ));
            offset = end;
            row += 1;
        }
        Ok(out)
    }

    /// Render a summary line.
    #[must_use]
    pub fn render_summary(&self, view: &DiffView) -> String {
        format!(
            "Diff: {} changed bytes, {} unchanged, similarity {:.1}%",
            view.changed_bytes,
            view.unchanged_bytes,
            view.similarity() * 100.0
        )
    }
}

// ---------------------------------------------------------------------------
// DiffNavigator
// ---------------------------------------------------------------------------

/// Stateful cursor over the changed entries in a `DiffView`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffNavigator {
    /// Indices into the parent diff's `entries` vec that are changed.
    changed_indices: Vec<usize>,
    /// Current position.
    cursor: usize,
    /// History of visited positions (for go-back).
    history: VecDeque<usize>,
}

impl DiffNavigator {
    /// Build a navigator from a computed `DiffView`.
    pub fn from_view(view: &DiffView) -> DiffResult<Self> {
        if view.entries.is_empty() && (!view.buf_a.is_empty() || !view.buf_b.is_empty()) {
            return Err(DiffError::NoDiff);
        }
        let changed_indices: Vec<usize> = view
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.change_type.is_changed())
            .map(|(i, _)| i)
            .collect();
        Ok(Self {
            changed_indices,
            cursor: 0,
            history: VecDeque::with_capacity(64),
        })
    }

    /// Total number of changed regions.
    #[must_use]
    pub const fn total_changes(&self) -> usize {
        self.changed_indices.len()
    }

    /// Current cursor position (0-based).
    #[must_use]
    pub const fn position(&self) -> usize {
        self.cursor
    }

    /// Move to the next changed entry.  Returns the index into `view.entries`.
    pub fn next(&mut self) -> Option<usize> {
        if self.changed_indices.is_empty() {
            return None;
        }
        self.history.push_back(self.cursor);
        if self.history.len() > 128 {
            self.history.pop_front();
        }
        self.cursor = (self.cursor + 1) % self.changed_indices.len();
        Some(self.changed_indices[self.cursor])
    }

    /// Move to the previous changed entry.
    pub fn prev(&mut self) -> Option<usize> {
        if self.changed_indices.is_empty() {
            return None;
        }
        self.history.push_back(self.cursor);
        if self.history.len() > 128 {
            self.history.pop_front();
        }
        self.cursor = self
            .cursor
            .checked_sub(1)
            .unwrap_or(self.changed_indices.len() - 1);
        Some(self.changed_indices[self.cursor])
    }

    /// Jump to a specific changed entry by index.
    pub fn goto(&mut self, index: usize) -> DiffResult<usize> {
        if index >= self.changed_indices.len() {
            return Err(DiffError::IndexOutOfRange(index));
        }
        self.history.push_back(self.cursor);
        self.cursor = index;
        Ok(self.changed_indices[self.cursor])
    }

    /// Go back to the previous cursor position.
    pub fn back(&mut self) -> Option<usize> {
        let prev = self.history.pop_back()?;
        self.cursor = prev;
        Some(self.changed_indices[self.cursor])
    }

    /// Seek to the first change.
    pub const fn first(&mut self) {
        self.cursor = 0;
    }

    /// Seek to the last change.
    pub const fn last(&mut self) {
        if !self.changed_indices.is_empty() {
            self.cursor = self.changed_indices.len() - 1;
        }
    }

    /// Returns `true` if there are no changes to navigate.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.changed_indices.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- ChangeType ---

    #[test]
    fn change_type_display() {
        assert_eq!(format!("{}", ChangeType::Modified), "~");
        assert_eq!(format!("{}", ChangeType::Inserted), "+");
        assert_eq!(format!("{}", ChangeType::Deleted), "-");
        assert_eq!(format!("{}", ChangeType::Unchanged), "=");
    }

    #[test]
    fn change_type_sigil() {
        assert_eq!(ChangeType::Unchanged.sigil(), ' ');
        assert_eq!(ChangeType::Inserted.sigil(), '+');
        assert_eq!(ChangeType::Deleted.sigil(), '-');
        assert_eq!(ChangeType::Modified.sigil(), '~');
    }

    #[test]
    fn change_type_is_changed() {
        assert!(!ChangeType::Unchanged.is_changed());
        assert!(ChangeType::Modified.is_changed());
        assert!(ChangeType::Inserted.is_changed());
        assert!(ChangeType::Deleted.is_changed());
    }

    #[test]
    fn change_type_ansi_color_non_empty() {
        assert!(!ChangeType::Modified.ansi_color().is_empty());
    }

    // --- linear_diff ---

    #[test]
    fn linear_diff_identical_buffers() {
        let a = vec![1u8, 2, 3, 4];
        let b = vec![1u8, 2, 3, 4];
        let entries = linear_diff(&a, &b);
        assert!(
            entries
                .iter()
                .all(|e| e.change_type == ChangeType::Unchanged)
        );
    }

    #[test]
    fn linear_diff_all_modified() {
        let a = vec![0u8; 4];
        let b = vec![0xFFu8; 4];
        let entries = linear_diff(&a, &b);
        assert!(
            entries
                .iter()
                .any(|e| e.change_type == ChangeType::Modified)
        );
    }

    #[test]
    fn linear_diff_b_longer_inserted() {
        let a = vec![1u8, 2];
        let b = vec![1u8, 2, 3, 4];
        let entries = linear_diff(&a, &b);
        assert!(
            entries
                .iter()
                .any(|e| e.change_type == ChangeType::Inserted)
        );
    }

    #[test]
    fn linear_diff_a_longer_deleted() {
        let a = vec![1u8, 2, 3, 4];
        let b = vec![1u8, 2];
        let entries = linear_diff(&a, &b);
        assert!(entries.iter().any(|e| e.change_type == ChangeType::Deleted));
    }

    #[test]
    fn linear_diff_empty_both() {
        let entries = linear_diff(&[], &[]);
        assert!(entries.is_empty());
    }

    // --- DiffView ---

    #[test]
    fn diff_view_similarity_identical() {
        let mut v = DiffView::new(vec![1, 2, 3], vec![1, 2, 3]);
        v.compute_diff(DiffAlgorithm::Linear);
        assert!((v.similarity() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn diff_view_similarity_different() {
        let mut v = DiffView::new(vec![0u8; 8], vec![0xFFu8; 8]);
        v.compute_diff(DiffAlgorithm::Linear);
        assert!(v.similarity() < 1.0);
    }

    #[test]
    fn diff_view_set_a_clears_entries() {
        let mut v = DiffView::new(vec![1, 2, 3], vec![1, 2, 3]);
        v.compute_diff(DiffAlgorithm::Linear);
        assert!(!v.entries.is_empty());
        v.set_a(vec![4, 5]);
        assert!(v.entries.is_empty());
    }

    #[test]
    fn diff_view_set_b_clears_entries() {
        let mut v = DiffView::new(vec![1], vec![2]);
        v.compute_diff(DiffAlgorithm::Linear);
        v.set_b(vec![3]);
        assert!(v.entries.is_empty());
    }

    #[test]
    fn diff_view_changed_entries() {
        let mut v = DiffView::new(vec![0u8, 0, 1, 0], vec![0u8, 0, 2, 0]);
        v.compute_diff(DiffAlgorithm::Linear);
        assert!(!v.changed_entries().is_empty());
    }

    #[test]
    fn diff_view_change_at_a() {
        let mut v = DiffView::new(vec![0u8, 0xFF, 0], vec![0u8, 0x00, 0]);
        v.compute_diff(DiffAlgorithm::Linear);
        let ct = v.change_at_a(1);
        assert_eq!(ct, Some(ChangeType::Modified));
    }

    #[test]
    fn diff_view_change_at_b() {
        let mut v = DiffView::new(vec![0u8, 0xFF, 0], vec![0u8, 0x00, 0]);
        v.compute_diff(DiffAlgorithm::Linear);
        assert!(v.change_at_b(1).is_some());
    }

    #[test]
    fn diff_view_highlights_a_populated() {
        let mut v = DiffView::new(vec![0u8; 4], vec![0xFFu8; 4]);
        v.compute_diff(DiffAlgorithm::Linear);
        assert!(!v.highlights_a().is_empty());
    }

    #[test]
    fn diff_view_highlights_b_populated() {
        let mut v = DiffView::new(vec![0u8; 4], vec![0xFFu8; 4]);
        v.compute_diff(DiffAlgorithm::Linear);
        assert!(!v.highlights_b().is_empty());
    }

    #[test]
    fn diff_view_myers_algorithm() {
        let mut v = DiffView::new(vec![1, 2, 3, 4], vec![1, 3, 4, 5]);
        v.compute_diff(DiffAlgorithm::Myers);
        assert!(!v.entries.is_empty());
    }

    // --- DiffRenderer ---

    #[test]
    fn renderer_no_diff_error() {
        let v = DiffView::new(vec![1, 2, 3], vec![1, 2, 4]);
        let r = DiffRenderer::default();
        // entries empty and buf non-empty → error
        assert!(r.render(&v).is_err());
    }

    #[test]
    fn renderer_produces_output() {
        let mut v = DiffView::new(vec![0u8; 32], vec![0xFFu8; 32]);
        v.compute_diff(DiffAlgorithm::Linear);
        let r = DiffRenderer::default();
        let out = r.render(&v).unwrap();
        assert!(!out.is_empty());
    }

    #[test]
    fn renderer_summary_contains_similarity() {
        let mut v = DiffView::new(vec![1, 2, 3], vec![1, 2, 3]);
        v.compute_diff(DiffAlgorithm::Linear);
        let r = DiffRenderer::default();
        let s = r.render_summary(&v);
        assert!(s.contains("100.0%"));
    }

    #[test]
    fn renderer_hide_unchanged() {
        let a: Vec<u8> = (0..64).collect();
        let mut b = a.clone();
        b[32] = 0xFF;
        let mut v = DiffView::new(a, b);
        v.compute_diff(DiffAlgorithm::Linear);
        let opts = RenderOptions {
            hide_unchanged: true,
            ..Default::default()
        };
        let r = DiffRenderer::new(opts);
        let full_opts = RenderOptions::default();
        let r2 = DiffRenderer::new(full_opts);
        let out1 = r.render(&v).unwrap();
        let out2 = r2.render(&v).unwrap();
        assert!(out1.len() < out2.len());
    }

    // --- DiffNavigator ---

    #[test]
    fn navigator_from_empty_view() {
        let v = DiffView::new(vec![], vec![]);
        let nav = DiffNavigator::from_view(&v).unwrap();
        assert!(nav.is_empty());
    }

    #[test]
    fn navigator_no_diff_error() {
        let v = DiffView::new(vec![1, 2], vec![3, 4]);
        assert!(matches!(
            DiffNavigator::from_view(&v),
            Err(DiffError::NoDiff)
        ));
    }

    #[test]
    fn navigator_next_wraps() {
        let mut v = DiffView::new(vec![0u8; 4], vec![0xFFu8; 4]);
        v.compute_diff(DiffAlgorithm::Linear);
        let mut nav = DiffNavigator::from_view(&v).unwrap();
        let n = nav.total_changes();
        for _ in 0..n + 2 {
            nav.next();
        }
        assert!(nav.position() < n);
    }

    #[test]
    fn navigator_prev_wraps() {
        let mut v = DiffView::new(vec![0u8; 4], vec![0xFFu8; 4]);
        v.compute_diff(DiffAlgorithm::Linear);
        let mut nav = DiffNavigator::from_view(&v).unwrap();
        nav.prev();
        assert!(nav.position() < nav.total_changes());
    }

    #[test]
    fn navigator_goto_valid() {
        let mut v = DiffView::new(vec![0u8; 8], vec![0xFFu8; 8]);
        v.compute_diff(DiffAlgorithm::Linear);
        let mut nav = DiffNavigator::from_view(&v).unwrap();
        let result = nav.goto(0);
        assert!(result.is_ok());
    }

    #[test]
    fn navigator_goto_out_of_range() {
        let mut v = DiffView::new(vec![0u8; 4], vec![0xFFu8; 4]);
        v.compute_diff(DiffAlgorithm::Linear);
        let mut nav = DiffNavigator::from_view(&v).unwrap();
        assert!(matches!(
            nav.goto(9999),
            Err(DiffError::IndexOutOfRange(9999))
        ));
    }

    #[test]
    fn navigator_first_last() {
        let mut v = DiffView::new(vec![0, 1, 0, 1], vec![1, 0, 1, 0]);
        v.compute_diff(DiffAlgorithm::Linear);
        let mut nav = DiffNavigator::from_view(&v).unwrap();
        nav.last();
        let pos_last = nav.position();
        nav.first();
        assert_eq!(nav.position(), 0);
        assert!(pos_last >= nav.position());
    }

    #[test]
    fn diff_entry_display() {
        let e = DiffEntry {
            range_a: Some(0..4),
            range_b: Some(0..4),
            change_type: ChangeType::Modified,
            bytes_a: vec![0; 4],
            bytes_b: vec![1; 4],
        };
        let s = format!("{e}");
        assert!(s.contains('~'));
    }

    #[test]
    fn diff_highlight_new() {
        let h = DiffHighlight::new(true, 42, ChangeType::Inserted);
        assert!(h.is_b);
        assert_eq!(h.offset, 42);
        assert_eq!(h.change_type, ChangeType::Inserted);
    }

    #[test]
    fn diff_view_identical_similarity_one() {
        let mut v = DiffView::new(vec![0xAA; 256], vec![0xAA; 256]);
        v.compute_diff(DiffAlgorithm::Linear);
        assert!((v.similarity() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn diff_view_entirely_replaced() {
        let mut v = DiffView::new(vec![0u8; 16], vec![0xFFu8; 16]);
        v.compute_diff(DiffAlgorithm::Linear);
        assert_eq!(v.similarity(), 0.0);
    }

    #[test]
    fn diff_view_empty_buffers() {
        let mut v = DiffView::new(vec![], vec![]);
        v.compute_diff(DiffAlgorithm::Linear);
        assert!(v.entries.is_empty());
        assert!((v.similarity() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn renderer_ansi_colors() {
        let mut v = DiffView::new(vec![0u8; 8], vec![0xFFu8; 8]);
        v.compute_diff(DiffAlgorithm::Linear);
        let opts = RenderOptions {
            ansi_colors: true,
            ..Default::default()
        };
        let r = DiffRenderer::new(opts);
        let out = r.render(&v).unwrap();
        assert!(out.contains("\x1b["));
    }

    #[test]
    fn diff_entry_len_a_len_b() {
        let e = DiffEntry {
            range_a: Some(0..4),
            range_b: Some(0..8),
            change_type: ChangeType::Modified,
            bytes_a: vec![0; 4],
            bytes_b: vec![1; 8],
        };
        assert_eq!(e.len_a(), 4);
        assert_eq!(e.len_b(), 8);
    }

    #[test]
    fn diff_entry_no_range_len_zero() {
        let e = DiffEntry {
            range_a: None,
            range_b: Some(0..4),
            change_type: ChangeType::Inserted,
            bytes_a: vec![],
            bytes_b: vec![0; 4],
        };
        assert_eq!(e.len_a(), 0);
        assert_eq!(e.len_b(), 4);
    }

    #[test]
    fn navigator_back_on_empty() {
        let v = DiffView::new(vec![], vec![]);
        let mut nav = DiffNavigator::from_view(&v).unwrap();
        assert!(nav.back().is_none());
    }

    #[test]
    fn diff_algorithm_linear_and_myers_both_work() {
        let a = vec![1u8, 2, 3, 4, 5];
        let b = vec![1u8, 9, 3, 4, 5];
        let mut v1 = DiffView::new(a.clone(), b.clone());
        let mut v2 = DiffView::new(a, b);
        v1.compute_diff(DiffAlgorithm::Linear);
        v2.compute_diff(DiffAlgorithm::Myers);
        assert!(!v1.entries.is_empty());
        assert!(!v2.entries.is_empty());
    }

    #[test]
    fn render_options_default_bytes_per_row() {
        let opts = RenderOptions::default();
        assert_eq!(opts.bytes_per_row, 16);
    }

    #[test]
    fn navigator_total_changes_on_no_changes() {
        let mut v = DiffView::new(vec![1, 2, 3], vec![1, 2, 3]);
        v.compute_diff(DiffAlgorithm::Linear);
        let nav = DiffNavigator::from_view(&v).unwrap();
        assert_eq!(nav.total_changes(), 0);
        assert!(nav.is_empty());
    }
}
