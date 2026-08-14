//! Coverage diff reporting.
//!
//! Compares two coverage snapshots (bitmaps, LCOV data, or source-level
//! `FileCoverage` maps) and produces a structured diff showing which edges /
//! lines were added, removed, or changed between two fuzzing runs.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ─── DiffKind ─────────────────────────────────────────────────────────────────

/// What happened to a line or edge between `before` and `after`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffKind {
    /// Newly covered (was 0 hits before, > 0 after).
    Added,
    /// No longer covered (was > 0 before, 0 after).
    Removed,
    /// Hit count increased.
    Increased,
    /// Hit count decreased.
    Decreased,
    /// Unchanged.
    Unchanged,
}

impl DiffKind {
    /// Returns `true` if this represents a change.
    #[must_use]
    pub const fn is_changed(self) -> bool {
        !matches!(self, Self::Unchanged)
    }

    /// Short label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Added => "+",
            Self::Removed => "-",
            Self::Increased => "↑",
            Self::Decreased => "↓",
            Self::Unchanged => "=",
        }
    }
}

// ─── DiffEntry (edge-level) ───────────────────────────────────────────────────

/// A single edge-level diff entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    /// Bitmap index.
    pub index: u32,
    /// Hits in the `before` snapshot.
    pub before_hits: u8,
    /// Hits in the `after` snapshot.
    pub after_hits: u8,
    /// Nature of the change.
    pub kind: DiffKind,
}

impl DiffEntry {
    const fn classify(before: u8, after: u8) -> DiffKind {
        match (before, after) {
            (0, a) if a > 0 => DiffKind::Added,
            (b, 0) if b > 0 => DiffKind::Removed,
            (b, a) if a > b => DiffKind::Increased,
            (b, a) if a < b => DiffKind::Decreased,
            _ => DiffKind::Unchanged,
        }
    }
}

// ─── LineDiffEntry (source-level) ────────────────────────────────────────────

/// A single source-line diff entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineDiffEntry {
    /// Source file path.
    pub file: PathBuf,
    /// 1-based line number.
    pub line: u32,
    /// Hit count before.
    pub before_hits: u64,
    /// Hit count after.
    pub after_hits: u64,
    /// Nature of the change.
    pub kind: DiffKind,
}

impl LineDiffEntry {
    const fn classify(before: u64, after: u64) -> DiffKind {
        match (before, after) {
            (0, a) if a > 0 => DiffKind::Added,
            (b, 0) if b > 0 => DiffKind::Removed,
            (b, a) if a > b => DiffKind::Increased,
            (b, a) if a < b => DiffKind::Decreased,
            _ => DiffKind::Unchanged,
        }
    }
}

// ─── CoverageDiff ─────────────────────────────────────────────────────────────

/// The complete diff between two coverage snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageDiff {
    /// Edge-level diff entries (only changed entries).
    pub edge_diffs: Vec<DiffEntry>,
    /// Source-line level diff entries (only changed entries).
    pub line_diffs: Vec<LineDiffEntry>,
    /// Total edges compared.
    pub total_edges: usize,
    /// Edges added (new coverage).
    pub added_edges: usize,
    /// Edges removed (regressed).
    pub removed_edges: usize,
    /// Edges with increased hit counts.
    pub increased_edges: usize,
    /// Edges with decreased hit counts.
    pub decreased_edges: usize,
    /// Total source lines compared.
    pub total_lines: usize,
    /// Added source lines.
    pub added_lines: usize,
    /// Removed source lines.
    pub removed_lines: usize,
    /// Label for the before snapshot.
    pub before_label: String,
    /// Label for the after snapshot.
    pub after_label: String,
}

impl CoverageDiff {
    /// Net edge gain = added - removed.
    #[must_use]
    pub fn net_edge_gain(&self) -> i64 {
        i64::try_from(self.added_edges).unwrap_or(i64::MAX) - i64::try_from(self.removed_edges).unwrap_or(i64::MAX)
    }

    /// Net line gain.
    #[must_use]
    pub fn net_line_gain(&self) -> i64 {
        i64::try_from(self.added_lines).unwrap_or(i64::MAX) - i64::try_from(self.removed_lines).unwrap_or(i64::MAX)
    }

    /// Returns `true` if the `after` snapshot strictly covers more edges.
    #[must_use]
    pub fn is_improvement(&self) -> bool {
        self.net_edge_gain() > 0
    }

    /// Returns `true` if the `after` snapshot covers fewer edges (regression).
    #[must_use]
    pub const fn is_regression(&self) -> bool {
        self.removed_edges > self.added_edges
    }

    /// One-line text summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Diff [{} → {}]: edges +{} -{} net={} | lines +{} -{} net={}",
            self.before_label,
            self.after_label,
            self.added_edges,
            self.removed_edges,
            self.net_edge_gain(),
            self.added_lines,
            self.removed_lines,
            self.net_line_gain(),
        )
    }

    /// Entries of a specific kind.
    #[must_use]
    pub fn edge_diffs_of_kind(&self, kind: DiffKind) -> Vec<&DiffEntry> {
        self.edge_diffs.iter().filter(|e| e.kind == kind).collect()
    }

    /// Line diff entries of a specific kind.
    #[must_use]
    pub fn line_diffs_of_kind(&self, kind: DiffKind) -> Vec<&LineDiffEntry> {
        self.line_diffs.iter().filter(|e| e.kind == kind).collect()
    }
}

// ─── CoverageDiffReporter ─────────────────────────────────────────────────────

/// Produces `CoverageDiff` from two bitmap or source-coverage snapshots.
pub struct CoverageDiffReporter {
    /// Label for the before snapshot.
    pub before_label: String,
    /// Label for the after snapshot.
    pub after_label: String,
    /// Whether to include `Unchanged` entries (default: false).
    pub include_unchanged: bool,
}

impl Default for CoverageDiffReporter {
    fn default() -> Self {
        Self {
            before_label: "before".to_string(),
            after_label: "after".to_string(),
            include_unchanged: false,
        }
    }
}

impl CoverageDiffReporter {
    /// Create a reporter with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom labels.
    #[must_use]
    pub fn with_labels(before: impl Into<String>, after: impl Into<String>) -> Self {
        Self {
            before_label: before.into(),
            after_label: after.into(),
            include_unchanged: false,
        }
    }

    /// Diff two raw bitmaps.
    ///
    /// # Errors
    /// Returns an error string if both bitmaps are empty.
    #[must_use] 
    pub fn diff_bitmaps(&self, before: &[u8], after: &[u8]) -> CoverageDiff {
        let len = before.len().max(after.len());
        let mut edge_diffs = Vec::new();
        let mut added = 0;
        let mut removed = 0;
        let mut increased = 0;
        let mut decreased = 0;

        for i in 0..len {
            let b = before.get(i).copied().unwrap_or(0);
            let a = after.get(i).copied().unwrap_or(0);
            let kind = DiffEntry::classify(b, a);
            if !self.include_unchanged && kind == DiffKind::Unchanged {
                continue;
            }
            match kind {
                DiffKind::Added => added += 1,
                DiffKind::Removed => removed += 1,
                DiffKind::Increased => increased += 1,
                DiffKind::Decreased => decreased += 1,
                DiffKind::Unchanged => {}
            }
            edge_diffs.push(DiffEntry { index: crate::casts::usize_to_u32(i), before_hits: b, after_hits: a, kind });
        }

        CoverageDiff {
            edge_diffs,
            line_diffs: Vec::new(),
            total_edges: len,
            added_edges: added,
            removed_edges: removed,
            increased_edges: increased,
            decreased_edges: decreased,
            total_lines: 0,
            added_lines: 0,
            removed_lines: 0,
            before_label: self.before_label.clone(),
            after_label: self.after_label.clone(),
        }
    }

    /// Diff two source-level file maps.
    ///
    /// `before` and `after` map `"file:line"` → `hit_count`.
    #[must_use] 
    pub fn diff_source_maps(
        &self,
        before: &HashMap<(PathBuf, u32), u64>,
        after: &HashMap<(PathBuf, u32), u64>,
    ) -> CoverageDiff {
        let all_keys: HashSet<(PathBuf, u32)> = before.keys()
            .chain(after.keys())
            .cloned()
            .collect();

        let mut line_diffs = Vec::new();
        let mut added = 0;
        let mut removed = 0;

        for (file, lineno) in &all_keys {
            let b = before.get(&(file.clone(), *lineno)).copied().unwrap_or(0);
            let a = after.get(&(file.clone(), *lineno)).copied().unwrap_or(0);
            let kind = LineDiffEntry::classify(b, a);
            if !self.include_unchanged && kind == DiffKind::Unchanged {
                continue;
            }
            match kind {
                DiffKind::Added => added += 1,
                DiffKind::Removed => removed += 1,
                _ => {}
            }
            line_diffs.push(LineDiffEntry {
                file: file.clone(),
                line: *lineno,
                before_hits: b,
                after_hits: a,
                kind,
            });
        }

        line_diffs.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));

        CoverageDiff {
            edge_diffs: Vec::new(),
            line_diffs,
            total_edges: 0,
            added_edges: 0,
            removed_edges: 0,
            increased_edges: 0,
            decreased_edges: 0,
            total_lines: all_keys.len(),
            added_lines: added,
            removed_lines: removed,
            before_label: self.before_label.clone(),
            after_label: self.after_label.clone(),
        }
    }

    /// Produce a text report from a `CoverageDiff`.
    #[must_use]
    pub fn format_text(&self, diff: &CoverageDiff) -> String {
        let mut out = String::new();
        out.push_str(&diff.summary());
        out.push('\n');
        if !diff.edge_diffs.is_empty() {
            out.push_str("\nEdge changes:\n");
            for e in &diff.edge_diffs {
                if e.kind == DiffKind::Unchanged { continue; }
                let _ = writeln!(
                    out,
                    "  {} edge[{}]: {} → {}",
                    e.kind.label(), e.index, e.before_hits, e.after_hits,
                );
            }
        }
        if !diff.line_diffs.is_empty() {
            out.push_str("\nLine changes:\n");
            for l in &diff.line_diffs {
                if l.kind == DiffKind::Unchanged { continue; }
                let _ = writeln!(
                    out,
                    "  {} {}:{} {} → {}",
                    l.kind.label(),
                    l.file.display(), l.line,
                    l.before_hits, l.after_hits,
                );
            }
        }
        out
    }

    /// Group line diffs by file.
    #[must_use]
    pub fn diffs_by_file(diff: &CoverageDiff) -> BTreeMap<String, Vec<&LineDiffEntry>> {
        let mut by_file: BTreeMap<String, Vec<&LineDiffEntry>> = BTreeMap::new();
        for e in &diff.line_diffs {
            by_file.entry(e.file.to_string_lossy().into_owned())
                .or_default()
                .push(e);
        }
        by_file
    }
}

// ─── RegressionAnalyzer ──────────────────────────────────────────────────────

/// Analyses a sequence of diffs to detect coverage regressions.
pub struct RegressionAnalyzer {
    diffs: Vec<CoverageDiff>,
}

impl RegressionAnalyzer {
    /// Create an empty analyzer.
    #[must_use]
    pub const fn new() -> Self {
        Self { diffs: Vec::new() }
    }

    /// Add a diff to the sequence.
    pub fn add_diff(&mut self, diff: CoverageDiff) {
        self.diffs.push(diff);
    }

    /// Return indices of diffs that represent regressions.
    #[must_use]
    pub fn regression_indices(&self) -> Vec<usize> {
        self.diffs.iter().enumerate()
            .filter(|(_, d)| d.is_regression())
            .map(|(i, _)| i)
            .collect()
    }

    /// Cumulative net edge gain over the entire sequence.
    #[must_use]
    pub fn cumulative_net_gain(&self) -> i64 {
        self.diffs.iter().map(CoverageDiff::net_edge_gain).sum()
    }

    /// Returns `true` if coverage strictly grew monotonically.
    #[must_use]
    pub fn is_monotone_growth(&self) -> bool {
        self.diffs.iter().all(|d| d.net_edge_gain() >= 0)
    }
}

impl Default for RegressionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reporter() -> CoverageDiffReporter {
        CoverageDiffReporter::with_labels("run1", "run2")
    }

    #[test]
    fn diff_added_edges() {
        let before = vec![0u8, 0, 0];
        let after = vec![1u8, 0, 1];
        let diff = reporter().diff_bitmaps(&before, &after);
        assert_eq!(diff.added_edges, 2);
        assert_eq!(diff.removed_edges, 0);
    }

    #[test]
    fn diff_removed_edges() {
        let before = vec![1u8, 1, 0];
        let after = vec![0u8, 0, 0];
        let diff = reporter().diff_bitmaps(&before, &after);
        assert_eq!(diff.removed_edges, 2);
        assert_eq!(diff.added_edges, 0);
        assert!(diff.is_regression());
    }

    #[test]
    fn diff_increased() {
        let before = vec![1u8, 0];
        let after = vec![5u8, 0];
        let diff = reporter().diff_bitmaps(&before, &after);
        assert_eq!(diff.increased_edges, 1);
    }

    #[test]
    fn net_gain_positive() {
        let before = vec![0u8; 4];
        let after = vec![1u8, 1, 0, 0];
        let diff = reporter().diff_bitmaps(&before, &after);
        assert_eq!(diff.net_edge_gain(), 2);
        assert!(diff.is_improvement());
    }

    #[test]
    fn edge_diff_label() {
        assert_eq!(DiffKind::Added.label(), "+");
        assert_eq!(DiffKind::Removed.label(), "-");
    }

    #[test]
    fn format_text_contains_summary() {
        let before = vec![0u8, 1];
        let after = vec![1u8, 0];
        let diff = reporter().diff_bitmaps(&before, &after);
        let text = reporter().format_text(&diff);
        assert!(text.contains("run1"));
    }

    #[test]
    fn source_map_diff() {
        let mut before = HashMap::new();
        before.insert((PathBuf::from("a.rs"), 1u32), 5u64);
        let mut after = HashMap::new();
        after.insert((PathBuf::from("a.rs"), 1u32), 5u64);
        after.insert((PathBuf::from("a.rs"), 2u32), 3u64);
        let diff = reporter().diff_source_maps(&before, &after);
        assert_eq!(diff.added_lines, 1);
        assert_eq!(diff.removed_lines, 0);
    }

    #[test]
    fn regression_analyzer() {
        let mut ra = RegressionAnalyzer::new();
        let before = vec![1u8, 1, 0];
        let after = vec![0u8, 0, 0];
        let diff = reporter().diff_bitmaps(&before, &after);
        ra.add_diff(diff);
        assert!(!ra.is_monotone_growth());
        assert_eq!(ra.regression_indices(), vec![0]);
    }

    #[test]
    fn monotone_growth() {
        let mut ra = RegressionAnalyzer::new();
        for i in 1..4u8 {
            let before = vec![i - 1];
            let after = vec![i];
            let diff = reporter().diff_bitmaps(&before, &after);
            ra.add_diff(diff);
        }
        assert!(ra.is_monotone_growth());
    }

    #[test]
    fn diffs_by_file() {
        let before = HashMap::new();
        let mut after = HashMap::new();
        after.insert((PathBuf::from("a.rs"), 1u32), 1u64);
        after.insert((PathBuf::from("b.rs"), 5u32), 2u64);
        let diff = reporter().diff_source_maps(&before, &after);
        let by_file = CoverageDiffReporter::diffs_by_file(&diff);
        assert_eq!(by_file.len(), 2);
    }
}
