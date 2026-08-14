//! `hex_diff` — Diff two byte buffers and present the result for hex view rendering.
//!
//! Provides [`HexDiff`], [`DiffRegion`], [`DiffKind`], and the core function
//! [`diff_buffers`].

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// DiffKind
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of change a diff region represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    /// Bytes present in both buffers but with different values.
    Changed,
    /// Bytes present only in the left (original) buffer.
    LeftOnly,
    /// Bytes present only in the right (modified) buffer.
    RightOnly,
}

impl fmt::Display for DiffKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Changed => write!(f, "changed"),
            Self::LeftOnly => write!(f, "left-only"),
            Self::RightOnly => write!(f, "right-only"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffRegion
// ─────────────────────────────────────────────────────────────────────────────

/// A contiguous region of differences between two buffers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffRegion {
    /// Byte offset where this region starts (in the left buffer for
    /// `Changed`/`LeftOnly`, in the right buffer for `RightOnly`).
    pub offset: usize,
    /// Length of the region in bytes (in its owning buffer).
    pub len: usize,
    /// Classification of this region.
    pub kind: DiffKind,
    /// Raw bytes from the left buffer for this region (may be empty).
    pub left_bytes: Vec<u8>,
    /// Raw bytes from the right buffer for this region (may be empty).
    pub right_bytes: Vec<u8>,
}

impl DiffRegion {
    /// Create a new diff region.
    #[must_use]
    pub fn new(
        offset: usize,
        kind: DiffKind,
        left_bytes: Vec<u8>,
        right_bytes: Vec<u8>,
    ) -> Self {
        let len = match kind {
            DiffKind::Changed => left_bytes.len().max(right_bytes.len()),
            DiffKind::LeftOnly => left_bytes.len(),
            DiffKind::RightOnly => right_bytes.len(),
        };
        Self {
            offset,
            len,
            kind,
            left_bytes,
            right_bytes,
        }
    }

    /// Return the byte range covered in the left buffer.
    #[must_use]
    pub const fn left_range(&self) -> std::ops::Range<usize> {
        self.offset..self.offset + self.left_bytes.len()
    }

    /// Return the byte range covered in the right buffer.
    #[must_use]
    pub const fn right_range(&self) -> std::ops::Range<usize> {
        self.offset..self.offset + self.right_bytes.len()
    }

    /// Return the entropy difference between left and right bytes (|`H_l` - `H_r`|).
    #[must_use]
    pub fn entropy_delta(&self) -> f64 {
        let hl = byte_entropy(&self.left_bytes);
        let hr = byte_entropy(&self.right_bytes);
        (hl - hr).abs()
    }
}

impl fmt::Display for DiffRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DiffRegion(offset={:#x}, len={}, kind={})",
            self.offset, self.len, self.kind
        )
    }
}

/// Compute the Shannon entropy of a byte slice.
fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts.iter().fold(0.0_f64, |acc, &c| {
        if c == 0 {
            acc
        } else {
            let p = f64::from(c) / n;
            p.mul_add(-p.log2(), acc)
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// diff_buffers
// ─────────────────────────────────────────────────────────────────────────────

/// Diff `left` and `right` byte slices and return all differing regions.
///
/// The algorithm is a simple linear scan:
/// - Bytes at the same offset that differ are marked `Changed`.
/// - Extra bytes in the longer buffer are marked `LeftOnly` or `RightOnly`.
/// - Adjacent changed bytes are merged into a single `DiffRegion`.
#[must_use]
pub fn diff_buffers(left: &[u8], right: &[u8]) -> Vec<DiffRegion> {
    let min_len = left.len().min(right.len());
    let mut regions: Vec<DiffRegion> = Vec::new();

    // Scan the common prefix for changed bytes.
    let mut i = 0;
    while i < min_len {
        if left[i] == right[i] {
            i += 1;
        } else {
            // Extend until bytes match again.
            let start = i;
            while i < min_len && left[i] != right[i] {
                i += 1;
            }
            let left_bytes = left[start..i].to_vec();
            let right_bytes = right[start..i].to_vec();
            regions.push(DiffRegion::new(
                start,
                DiffKind::Changed,
                left_bytes,
                right_bytes,
            ));
        }
    }

    // Extra bytes in left (longer left buffer).
    if left.len() > right.len() {
        let tail = &left[min_len..];
        regions.push(DiffRegion::new(
            min_len,
            DiffKind::LeftOnly,
            tail.to_vec(),
            vec![],
        ));
    }

    // Extra bytes in right (longer right buffer).
    if right.len() > left.len() {
        let tail = &right[min_len..];
        regions.push(DiffRegion::new(
            min_len,
            DiffKind::RightOnly,
            vec![],
            tail.to_vec(),
        ));
    }

    regions
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffSummary
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics about a diff operation.
#[derive(Debug, Clone, Default)]
pub struct DiffSummary {
    /// Number of `Changed` regions.
    pub changed_regions: usize,
    /// Total changed bytes.
    pub changed_bytes: usize,
    /// Bytes present only in left.
    pub left_only_bytes: usize,
    /// Bytes present only in right.
    pub right_only_bytes: usize,
    /// Total bytes in the left buffer.
    pub left_total: usize,
    /// Total bytes in the right buffer.
    pub right_total: usize,
}

impl DiffSummary {
    /// Compute a summary from a slice of diff regions and buffer sizes.
    #[must_use]
    pub fn from_regions(regions: &[DiffRegion], left_len: usize, right_len: usize) -> Self {
        let mut s = Self {
            left_total: left_len,
            right_total: right_len,
            ..Self::default()
        };
        for r in regions {
            match r.kind {
                DiffKind::Changed => {
                    s.changed_regions += 1;
                    s.changed_bytes += r.left_bytes.len();
                }
                DiffKind::LeftOnly => s.left_only_bytes += r.left_bytes.len(),
                DiffKind::RightOnly => s.right_only_bytes += r.right_bytes.len(),
            }
        }
        s
    }

    /// Percentage of left bytes that changed (0.0–100.0).
    #[must_use]
    pub fn change_percent(&self) -> f64 {
        if self.left_total == 0 {
            return 0.0;
        }
        (self.changed_bytes as f64 / self.left_total as f64) * 100.0
    }

    /// Return `true` when there are no differences at all.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.changed_bytes == 0 && self.left_only_bytes == 0 && self.right_only_bytes == 0
    }
}

impl fmt::Display for DiffSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DiffSummary(changed={}, left_only={}, right_only={}, {:.1}%)",
            self.changed_bytes,
            self.left_only_bytes,
            self.right_only_bytes,
            self.change_percent()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexDiff
// ─────────────────────────────────────────────────────────────────────────────

/// High-level diff engine that stores both buffers and the computed regions.
pub struct HexDiff {
    /// Left (original) buffer.
    pub left: Vec<u8>,
    /// Right (modified) buffer.
    pub right: Vec<u8>,
    /// Computed diff regions.
    pub regions: Vec<DiffRegion>,
    /// Summary statistics.
    pub summary: DiffSummary,
}

impl HexDiff {
    /// Create a new `HexDiff` by comparing `left` and `right`.
    #[must_use]
    pub fn new(left: Vec<u8>, right: Vec<u8>) -> Self {
        let regions = diff_buffers(&left, &right);
        let summary = DiffSummary::from_regions(&regions, left.len(), right.len());
        Self {
            left,
            right,
            regions,
            summary,
        }
    }

    /// Return `true` if the two buffers are identical.
    #[must_use]
    pub fn is_identical(&self) -> bool {
        self.summary.is_identical()
    }

    /// Return all regions of a specific kind.
    #[must_use]
    pub fn regions_of_kind(&self, kind: DiffKind) -> Vec<&DiffRegion> {
        self.regions.iter().filter(|r| r.kind == kind).collect()
    }

    /// Return regions that overlap the given byte range `[start, end)`.
    #[must_use]
    pub fn regions_in_range(&self, start: usize, end: usize) -> Vec<&DiffRegion> {
        self.regions
            .iter()
            .filter(|r| r.offset < end && r.offset + r.len > start)
            .collect()
    }

    /// Render a side-by-side diff summary as a multi-line string.
    #[must_use]
    pub fn render_summary(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "Left:  {} bytes", self.left.len());
        let _ = writeln!(out, "Right: {} bytes", self.right.len());
        let _ = writeln!(out, "Regions: {}", self.regions.len());
        let _ = writeln!(out, "{}", self.summary);
        out
    }

    /// Build a per-byte change bitmap.  Each element is `true` when the byte
    /// at that offset in the longer buffer differs.
    #[must_use]
    pub fn change_bitmap(&self) -> Vec<bool> {
        let max_len = self.left.len().max(self.right.len());
        let mut bitmap = vec![false; max_len];
        for r in &self.regions {
            let end = (r.offset + r.len).min(max_len);
            for b in &mut bitmap[r.offset..end] {
                *b = true;
            }
        }
        bitmap
    }

    /// Return all offsets where the left and right buffers differ.
    #[must_use]
    pub fn changed_offsets(&self) -> Vec<usize> {
        self.change_bitmap()
            .into_iter()
            .enumerate()
            .filter_map(|(i, changed)| if changed { Some(i) } else { None })
            .collect()
    }

    /// Recompute the diff (useful after modifying `self.left` or `self.right`).
    pub fn recompute(&mut self) {
        self.regions = diff_buffers(&self.left, &self.right);
        self.summary =
            DiffSummary::from_regions(&self.regions, self.left.len(), self.right.len());
    }

    /// Patch the left buffer by applying all `Changed` regions from the right.
    ///
    /// This produces the same bytes as `right` for all changed positions,
    /// leaving `LeftOnly` tails unchanged.
    #[must_use]
    pub fn apply_changes_to_left(&self) -> Vec<u8> {
        let mut result = self.left.clone();
        for r in &self.regions {
            if r.kind == DiffKind::Changed {
                let end = (r.offset + r.right_bytes.len()).min(result.len());
                let copy_len = end - r.offset;
                result[r.offset..end].copy_from_slice(&r.right_bytes[..copy_len]);
            }
        }
        result
    }
}

impl fmt::Debug for HexDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HexDiff")
            .field("left_len", &self.left.len())
            .field("right_len", &self.right.len())
            .field("regions", &self.regions.len())
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Alignment-based diff
// ─────────────────────────────────────────────────────────────────────────────

/// Return only the changed regions that are aligned to `alignment`-byte
/// boundaries.  Useful for generating diff overlays that match hex display rows.
#[must_use]
pub fn aligned_diff_regions(
    left: &[u8],
    right: &[u8],
    alignment: usize,
) -> Vec<DiffRegion> {
    assert!(alignment > 0, "alignment must be > 0");
    let raw = diff_buffers(left, right);
    // Snap each region's offset down to the nearest alignment boundary and its
    // end up to the next boundary.
    let mut snapped: Vec<DiffRegion> = raw
        .into_iter()
        .map(|mut r| {
            let snapped_start = (r.offset / alignment) * alignment;
            let end = r.offset + r.len;
            let snapped_end = end.div_ceil(alignment) * alignment;
            let snapped_end = snapped_end.min(left.len().max(right.len()));
            let new_len = snapped_end.saturating_sub(snapped_start);
            r.offset = snapped_start;
            r.len = new_len;
            r
        })
        .collect();
    // Merge overlapping snapped regions.
    snapped.sort_by_key(|r| r.offset);
    let mut merged: Vec<DiffRegion> = Vec::new();
    for r in snapped {
        if let Some(last) = merged.last_mut()
            && r.offset < last.offset + last.len {
                let new_end = (last.offset + last.len).max(r.offset + r.len);
                last.len = new_end - last.offset;
                continue;
            }
        merged.push(r);
    }
    merged
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_identical_buffers() {
        let left = vec![1u8, 2, 3, 4];
        let right = vec![1u8, 2, 3, 4];
        let regions = diff_buffers(&left, &right);
        assert!(regions.is_empty());
    }

    #[test]
    fn diff_single_change() {
        let left = vec![0u8, 1, 2, 3];
        let right = vec![0u8, 9, 2, 3];
        let regions = diff_buffers(&left, &right);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].kind, DiffKind::Changed);
        assert_eq!(regions[0].offset, 1);
        assert_eq!(regions[0].left_bytes, vec![1]);
        assert_eq!(regions[0].right_bytes, vec![9]);
    }

    #[test]
    fn diff_left_longer() {
        let left = vec![0u8, 1, 2, 3, 4, 5];
        let right = vec![0u8, 1, 2, 3];
        let regions = diff_buffers(&left, &right);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].kind, DiffKind::LeftOnly);
        assert_eq!(regions[0].left_bytes, vec![4, 5]);
    }

    #[test]
    fn diff_right_longer() {
        let left = vec![0u8, 1];
        let right = vec![0u8, 1, 2, 3, 4];
        let regions = diff_buffers(&left, &right);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].kind, DiffKind::RightOnly);
        assert_eq!(regions[0].right_bytes, vec![2, 3, 4]);
    }

    #[test]
    fn diff_multiple_changed_regions() {
        let left = vec![0u8, 1, 2, 3, 4, 5];
        let right = vec![0u8, 9, 2, 9, 4, 5];
        let regions = diff_buffers(&left, &right);
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].offset, 1);
        assert_eq!(regions[1].offset, 3);
    }

    #[test]
    fn hex_diff_is_identical() {
        let d = HexDiff::new(vec![1, 2, 3], vec![1, 2, 3]);
        assert!(d.is_identical());
    }

    #[test]
    fn hex_diff_not_identical() {
        let d = HexDiff::new(vec![1, 2, 3], vec![1, 9, 3]);
        assert!(!d.is_identical());
    }

    #[test]
    fn hex_diff_change_bitmap() {
        let d = HexDiff::new(vec![0, 1, 2, 3], vec![0, 9, 2, 9]);
        let bm = d.change_bitmap();
        assert!(!bm[0]);
        assert!(bm[1]);
        assert!(!bm[2]);
        assert!(bm[3]);
    }

    #[test]
    fn hex_diff_changed_offsets() {
        let d = HexDiff::new(vec![0, 1, 2, 3], vec![0, 9, 2, 9]);
        let offs = d.changed_offsets();
        assert_eq!(offs, vec![1, 3]);
    }

    #[test]
    fn hex_diff_apply_changes_to_left() {
        let left = vec![0u8, 1, 2, 3];
        let right = vec![0u8, 9, 2, 9];
        let d = HexDiff::new(left.clone(), right.clone());
        let patched = d.apply_changes_to_left();
        assert_eq!(patched, right);
    }

    #[test]
    fn hex_diff_render_summary_contains_bytes() {
        let d = HexDiff::new(vec![0u8; 16], vec![0u8; 16]);
        let s = d.render_summary();
        assert!(s.contains("16 bytes"));
    }

    #[test]
    fn diff_summary_change_percent() {
        let left = vec![0u8, 1, 2, 3];
        let right = vec![0u8, 9, 2, 9];
        let regions = diff_buffers(&left, &right);
        let summary = DiffSummary::from_regions(&regions, left.len(), right.len());
        assert!((summary.change_percent() - 50.0).abs() < 0.1);
    }

    #[test]
    fn diff_summary_is_identical_when_no_changes() {
        let s = DiffSummary::default();
        assert!(s.is_identical());
    }

    #[test]
    fn diff_kind_display() {
        assert_eq!(DiffKind::Changed.to_string(), "changed");
        assert_eq!(DiffKind::LeftOnly.to_string(), "left-only");
        assert_eq!(DiffKind::RightOnly.to_string(), "right-only");
    }

    #[test]
    fn diff_region_display() {
        let r = DiffRegion::new(0x10, DiffKind::Changed, vec![0xAA], vec![0xBB]);
        let s = r.to_string();
        assert!(s.contains("0x10"));
    }

    #[test]
    fn regions_in_range() {
        let left = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
        let right = vec![0u8, 9, 2, 9, 4, 5, 6, 7];
        let d = HexDiff::new(left, right);
        let in_range = d.regions_in_range(0, 3);
        assert_eq!(in_range.len(), 1);
        assert_eq!(in_range[0].offset, 1);
    }

    #[test]
    fn regions_of_kind() {
        let left = vec![0u8, 1, 2, 3, 4];
        let right = vec![0u8, 9, 2, 3];
        let d = HexDiff::new(left, right);
        let changed = d.regions_of_kind(DiffKind::Changed);
        let left_only = d.regions_of_kind(DiffKind::LeftOnly);
        assert_eq!(changed.len(), 1);
        assert_eq!(left_only.len(), 1);
    }

    #[test]
    fn hex_diff_recompute() {
        let mut d = HexDiff::new(vec![1, 2, 3], vec![1, 2, 3]);
        assert!(d.is_identical());
        d.right[1] = 9;
        d.recompute();
        assert!(!d.is_identical());
    }

    #[test]
    fn aligned_diff_snaps_to_row() {
        let left = vec![0u8; 32];
        let mut right = vec![0u8; 32];
        right[5] = 1;
        right[20] = 1;
        let regions = aligned_diff_regions(&left, &right, 16);
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].offset, 0);
        assert_eq!(regions[1].offset, 16);
    }

    #[test]
    fn byte_entropy_uniform() {
        let data: Vec<u8> = (0..=255u8).collect();
        let e = byte_entropy(&data);
        assert!((e - 8.0).abs() < 0.01);
    }

    #[test]
    fn byte_entropy_constant() {
        let data = vec![0xAAu8; 64];
        let e = byte_entropy(&data);
        assert_eq!(e, 0.0);
    }
}
