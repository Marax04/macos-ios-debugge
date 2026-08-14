//! Hex diff mode — compare two binary regions side by side.
//!
//! Key types:
//! - [`HexDiff`] — compare two regions and produce a diff.
//! - [`DiffEntry`] — (offset, `a_bytes`, `b_bytes`) for each changed position.
//! - [`DiffHighlight`] — per-byte status: Same / Changed / Added / Deleted.
//! - [`DiffStats`] — summary statistics.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Write as FmtWrite;

const fn cast_u64_f64(n: u64) -> f64 { n as f64 }

// ---------------------------------------------------------------------------
// DiffHighlight
// ---------------------------------------------------------------------------

/// Per-byte diff status when comparing two regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffHighlight {
    /// Byte is identical in both regions.
    Same,
    /// Byte exists in both but has a different value.
    Changed,
    /// Byte is only present in region B (inserted).
    Added,
    /// Byte is only present in region A (deleted).
    Deleted,
}

impl DiffHighlight {
    /// Single-character ASCII symbol for terminal output.
    #[must_use]
    pub const fn symbol(self) -> char {
        match self {
            Self::Same => ' ',
            Self::Changed => '~',
            Self::Added => '+',
            Self::Deleted => '-',
        }
    }

    /// ANSI colour for terminal rendering.
    #[must_use]
    pub const fn ansi_color(self) -> &'static str {
        match self {
            Self::Same => "",
            Self::Changed => "\x1b[33m", // yellow
            Self::Added => "\x1b[32m",   // green
            Self::Deleted => "\x1b[31m", // red
        }
    }

    /// Returns `true` if the byte represents a difference.
    #[must_use]
    pub const fn is_different(self) -> bool {
        !matches!(self, Self::Same)
    }
}

impl fmt::Display for DiffHighlight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Same => write!(f, "Same"),
            Self::Changed => write!(f, "Changed"),
            Self::Added => write!(f, "Added"),
            Self::Deleted => write!(f, "Deleted"),
        }
    }
}

// ---------------------------------------------------------------------------
// DiffEntry
// ---------------------------------------------------------------------------

/// A single entry in a binary diff: the offset and byte values from each side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    /// Byte offset (relative to the start of the compared region).
    pub offset: u64,
    /// Byte value from region A (`None` if A is shorter here).
    pub a_byte: Option<u8>,
    /// Byte value from region B (`None` if B is shorter here).
    pub b_byte: Option<u8>,
    /// Computed highlight status.
    pub highlight: DiffHighlight,
}

impl DiffEntry {
    /// Build a [`DiffEntry`] from two optional bytes.
    #[must_use]
    pub const fn new(offset: u64, a: Option<u8>, b: Option<u8>) -> Self {
        let highlight = match (a, b) {
            (Some(av), Some(bv)) if av == bv => DiffHighlight::Same,
            (Some(_), Some(_)) => DiffHighlight::Changed,
            (Some(_), None) => DiffHighlight::Deleted,
            (None, Some(_)) => DiffHighlight::Added,
            (None, None) => DiffHighlight::Same,
        };
        Self {
            offset,
            a_byte: a,
            b_byte: b,
            highlight,
        }
    }

    /// Returns `true` if this entry is different.
    #[must_use]
    pub const fn is_diff(&self) -> bool {
        self.highlight.is_different()
    }
}

impl fmt::Display for DiffEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = self.a_byte.map_or_else(|| "--".to_string(), |b| format!("{b:02X}"));
        let b = self.b_byte.map_or_else(|| "--".to_string(), |b| format!("{b:02X}"));
        write!(
            f,
            "{:#010x}  {a} {}  {b}",
            self.offset,
            self.highlight.symbol()
        )
    }
}

// ---------------------------------------------------------------------------
// DiffStats
// ---------------------------------------------------------------------------

/// Summary statistics for a binary diff.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiffStats {
    /// Total bytes in the longer region.
    pub total_bytes: u64,
    /// Number of bytes that are identical.
    pub same_count: u64,
    /// Number of bytes that changed (both present, different value).
    pub changed_count: u64,
    /// Number of bytes only in region A (deleted).
    pub deleted_count: u64,
    /// Number of bytes only in region B (added).
    pub added_count: u64,
}

impl DiffStats {
    /// Total number of differing bytes.
    #[must_use]
    pub const fn diff_count(&self) -> u64 {
        self.changed_count + self.deleted_count + self.added_count
    }

    /// Fraction of bytes that are different (0.0 – 1.0).
    #[must_use]
    pub fn change_ratio(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        cast_u64_f64(self.diff_count()) / cast_u64_f64(self.total_bytes)
    }

    /// Returns `true` if both regions are identical.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.diff_count() == 0
    }

    /// Similarity score in [0.0, 1.0] (1.0 = identical).
    #[must_use]
    pub fn similarity(&self) -> f64 {
        1.0 - self.change_ratio()
    }
}

impl fmt::Display for DiffStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DiffStats {{ total={}, same={}, changed={}, added={}, deleted={}, ratio={:.1}% }}",
            self.total_bytes,
            self.same_count,
            self.changed_count,
            self.added_count,
            self.deleted_count,
            self.change_ratio() * 100.0
        )
    }
}

// ---------------------------------------------------------------------------
// HexDiff
// ---------------------------------------------------------------------------

/// Compares two byte regions and produces a flat list of [`DiffEntry`]s.
pub struct HexDiff {
    pub entries: Vec<DiffEntry>,
    pub stats: DiffStats,
}

impl HexDiff {
    /// Compare `a` and `b`, producing one [`DiffEntry`] per byte position.
    #[must_use]
    pub fn compare(a: &[u8], b: &[u8]) -> Self {
        let len = a.len().max(b.len());
        let mut entries = Vec::with_capacity(len);
        let mut stats = DiffStats {
            total_bytes: u64::try_from(len).unwrap_or(u64::MAX),
            ..Default::default()
        };

        for i in 0..len {
            let av = a.get(i).copied();
            let bv = b.get(i).copied();
            let entry = DiffEntry::new(u64::try_from(i).unwrap_or(u64::MAX), av, bv);
            match entry.highlight {
                DiffHighlight::Same => stats.same_count += 1,
                DiffHighlight::Changed => stats.changed_count += 1,
                DiffHighlight::Deleted => stats.deleted_count += 1,
                DiffHighlight::Added => stats.added_count += 1,
            }
            entries.push(entry);
        }

        Self { entries, stats }
    }

    /// Return only the differing entries.
    #[must_use]
    pub fn diff_entries(&self) -> Vec<&DiffEntry> {
        self.entries.iter().filter(|e| e.is_diff()).collect()
    }

    /// Return entries in a specific offset range.
    #[must_use]
    pub fn in_range(&self, start: u64, end: u64) -> Vec<&DiffEntry> {
        self.entries
            .iter()
            .filter(|e| e.offset >= start && e.offset < end)
            .collect()
    }

    /// Render a side-by-side diff to a string, 16 bytes per row.
    #[must_use]
    pub fn render_side_by_side(&self, bytes_per_row: usize) -> String {
        let bpr = bytes_per_row.max(1);
        let mut out = String::new();
        let header = format!(
            "{:<10}  {:<width$}  {:<width$}  {}\n",
            "OFFSET",
            "REGION A",
            "REGION B",
            "FLAGS",
            width = bpr * 3,
        );
        out.push_str(&header);
        out.push_str(&"-".repeat(header.len()));
        out.push('\n');

        for row_entries in self.entries.chunks(bpr) {
            let off = row_entries[0].offset;
            let a_hex: Vec<String> = row_entries
                .iter()
                .map(|e| e.a_byte.map_or_else(|| "--".to_string(), |b| format!("{b:02X}")))
                .collect();
            let b_hex: Vec<String> = row_entries
                .iter()
                .map(|e| e.b_byte.map_or_else(|| "--".to_string(), |b| format!("{b:02X}")))
                .collect();
            let flags: String = row_entries.iter().map(|e| e.highlight.symbol()).collect();

            writeln!(out,
                "{off:#010x}  {:<width$}  {:<width$}  {flags}",
                a_hex.join(" "),
                b_hex.join(" "),
                width = bpr * 3 - 1
            ).unwrap();
        }
        out
    }

    /// Render a compact unified-diff style output (only changed rows).
    #[must_use]
    pub fn render_compact(&self, bytes_per_row: usize) -> String {
        let bpr = bytes_per_row.max(1);
        let mut out = String::new();
        for row_entries in self.entries.chunks(bpr) {
            let has_diff = row_entries.iter().any(DiffEntry::is_diff);
            if !has_diff {
                continue;
            }
            let off = row_entries[0].offset;
            writeln!(out, "@ {off:#010x}").unwrap();
            let a_hex: Vec<String> = row_entries
                .iter()
                .map(|e| e.a_byte.map_or_else(|| "--".to_string(), |b| format!("{b:02X}")))
                .collect();
            let b_hex: Vec<String> = row_entries
                .iter()
                .map(|e| e.b_byte.map_or_else(|| "--".to_string(), |b| format!("{b:02X}")))
                .collect();
            writeln!(out, "- {}", a_hex.join(" ")).unwrap();
            writeln!(out, "+ {}", b_hex.join(" ")).unwrap();
        }
        out
    }

    /// Build a per-byte highlight map: `offset → DiffHighlight`.
    #[must_use]
    pub fn highlight_map(&self) -> std::collections::HashMap<u64, DiffHighlight> {
        self.entries
            .iter()
            .map(|e| (e.offset, e.highlight))
            .collect()
    }

    /// Number of diff entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if both regions are identical.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stats.is_identical()
    }
}

impl fmt::Debug for HexDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HexDiff {{ entries: {}, stats: {} }}",
            self.entries.len(),
            self.stats
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_diff_identical() {
        let a = vec![1u8, 2, 3, 4];
        let d = HexDiff::compare(&a, &a);
        assert!(d.stats.is_identical());
        assert_eq!(d.stats.same_count, 4);
        assert!(d.is_empty());
    }

    #[test]
    fn test_hex_diff_one_change() {
        let a = vec![1u8, 2, 3, 4];
        let b = vec![1u8, 9, 3, 4];
        let d = HexDiff::compare(&a, &b);
        assert_eq!(d.stats.changed_count, 1);
        assert_eq!(d.stats.same_count, 3);
    }

    #[test]
    fn test_hex_diff_b_longer() {
        let a = vec![1u8, 2];
        let b = vec![1u8, 2, 3, 4];
        let d = HexDiff::compare(&a, &b);
        assert_eq!(d.stats.added_count, 2);
    }

    #[test]
    fn test_hex_diff_a_longer() {
        let a = vec![1u8, 2, 3, 4];
        let b = vec![1u8, 2];
        let d = HexDiff::compare(&a, &b);
        assert_eq!(d.stats.deleted_count, 2);
    }

    #[test]
    fn test_hex_diff_all_different() {
        let a = vec![0xAAu8; 4];
        let b = vec![0x55u8; 4];
        let d = HexDiff::compare(&a, &b);
        assert_eq!(d.stats.changed_count, 4);
    }

    #[test]
    fn test_hex_diff_empty_inputs() {
        let d = HexDiff::compare(&[], &[]);
        assert_eq!(d.stats.total_bytes, 0);
        assert!(d.is_empty());
    }

    #[test]
    fn test_hex_diff_one_empty() {
        let d = HexDiff::compare(&[1, 2, 3], &[]);
        assert_eq!(d.stats.deleted_count, 3);
    }

    #[test]
    fn test_diff_stats_change_ratio() {
        let a = vec![0u8; 10];
        let mut b = a.clone();
        b[0] = 1;
        let d = HexDiff::compare(&a, &b);
        assert!((d.stats.change_ratio() - 0.1).abs() < 1e-9);
    }

    #[test]
    fn test_diff_stats_similarity() {
        let a = vec![0u8; 10];
        let d = HexDiff::compare(&a, &a);
        assert!((d.stats.similarity() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_diff_entries_filter() {
        let a = vec![1u8, 2, 3];
        let b = vec![1u8, 9, 3];
        let d = HexDiff::compare(&a, &b);
        let diffs = d.diff_entries();
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].offset, 1);
    }

    #[test]
    fn test_diff_in_range() {
        let a = vec![0u8; 16];
        let mut b = vec![0u8; 16];
        b[5] = 0xFF;
        b[10] = 0xFF;
        let d = HexDiff::compare(&a, &b);
        let in_range = d.in_range(4, 8);
        assert_eq!(in_range.len(), 4);
        assert!(in_range.iter().any(|e| e.is_diff()));
    }

    #[test]
    fn test_render_side_by_side() {
        let a = vec![0xAAu8; 4];
        let b = vec![0x55u8; 4];
        let d = HexDiff::compare(&a, &b);
        let out = d.render_side_by_side(4);
        assert!(out.contains("OFFSET"));
        assert!(out.contains("AA"));
        assert!(out.contains("55"));
    }

    #[test]
    fn test_render_compact_only_changed() {
        let a = vec![0u8; 32];
        let mut b = a.clone();
        b[16] = 0xFF;
        let d = HexDiff::compare(&a, &b);
        let out = d.render_compact(16);
        // Should only contain rows with differences.
        let line_count = out.lines().count();
        assert!(line_count > 0);
        assert!(!out.is_empty());
    }

    #[test]
    fn test_highlight_map() {
        let a = vec![1u8, 2, 3];
        let b = vec![1u8, 9, 3];
        let d = HexDiff::compare(&a, &b);
        let map = d.highlight_map();
        assert_eq!(map[&0], DiffHighlight::Same);
        assert_eq!(map[&1], DiffHighlight::Changed);
        assert_eq!(map[&2], DiffHighlight::Same);
    }

    #[test]
    fn test_diff_entry_display() {
        let e = DiffEntry::new(0x10, Some(0xAA), Some(0xBB));
        let s = e.to_string();
        assert!(s.contains("0x00000010"));
        assert!(s.contains("AA"));
        assert!(s.contains("BB"));
    }

    #[test]
    fn test_diff_highlight_symbol() {
        assert_eq!(DiffHighlight::Same.symbol(), ' ');
        assert_eq!(DiffHighlight::Changed.symbol(), '~');
        assert_eq!(DiffHighlight::Added.symbol(), '+');
        assert_eq!(DiffHighlight::Deleted.symbol(), '-');
    }

    #[test]
    fn test_diff_highlight_display() {
        assert_eq!(DiffHighlight::Changed.to_string(), "Changed");
    }

    #[test]
    fn test_diff_stats_display() {
        let s = DiffStats::default();
        let out = s.to_string();
        assert!(out.contains("DiffStats"));
    }

    #[test]
    fn test_hex_diff_debug() {
        let d = HexDiff::compare(&[1u8, 2], &[1u8, 3]);
        let s = format!("{d:?}");
        assert!(s.contains("HexDiff"));
    }
}
