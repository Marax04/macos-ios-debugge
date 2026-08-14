//! `diff_reporter` — Build structured diff reports from function match results.
//!
//! Aggregates `MatchResult` lists into a `DiffReport` that quantifies change
//! coverage, produces per-function `FunctionPair` entries, and provides
//! histogram/summary helpers for downstream rendering or export.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::function_matcher::{MatchKind, MatchResult, SimilarityScore};

// ── ChangeStatus ──────────────────────────────────────────────────────────────

/// Per-function change classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChangeStatus {
    /// Function exists in both binaries and is byte-for-byte identical.
    Unchanged,
    /// Exists in both; constants changed but structure is the same.
    ConstantsChanged,
    /// Exists in both; minor structural changes.
    MinorChanges,
    /// Exists in both; substantial restructuring.
    MajorChanges,
    /// Present in A but not in B.
    RemovedInB,
    /// Present in B but not in A (new function).
    AddedInB,
    /// Match is uncertain / below threshold.
    Unknown,
}

impl std::fmt::Display for ChangeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl ChangeStatus {
    /// Derive status from a `MatchKind` and detailed similarity.
    #[must_use]
    pub fn from_match(kind: MatchKind, score: &SimilarityScore) -> Self {
        match kind {
            MatchKind::Identical => Self::Unchanged,
            MatchKind::NearIdentical => {
                // Near-identical but sequence changed → constants likely flipped.
                if score.sequence >= 0.95 {
                    Self::ConstantsChanged
                } else {
                    Self::MinorChanges
                }
            }
            MatchKind::HighSimilarity => Self::MinorChanges,
            MatchKind::ModerateSimilarity | MatchKind::WeakSimilarity => Self::MajorChanges,
            MatchKind::Unmatched         => Self::Unknown,
        }
    }
}

// ── FunctionPair ──────────────────────────────────────────────────────────────

/// A matched (or unmatched) function pair entry in the diff report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionPair {
    /// Virtual address in binary A, or `None` if this function was added.
    pub offset_a: Option<u64>,
    /// Virtual address in binary B, or `None` if this function was removed.
    pub offset_b: Option<u64>,
    /// Name from binary A.
    pub name_a: Option<String>,
    /// Name from binary B.
    pub name_b: Option<String>,
    /// Change classification.
    pub status: ChangeStatus,
    /// Similarity score, or `None` for unmatched entries.
    pub score: Option<SimilarityScore>,
    /// Human-readable change summary.
    pub summary: String,
}

impl FunctionPair {
    /// Create from a `MatchResult`.
    #[must_use]
    pub fn from_match(m: &MatchResult) -> Self {
        let status = ChangeStatus::from_match(m.kind, &m.score);
        let summary = build_summary(status, &m.score, m.offset_a, m.offset_b);
        Self {
            offset_a: Some(m.offset_a),
            offset_b: Some(m.offset_b),
            name_a: m.name_a.clone(),
            name_b: m.name_b.clone(),
            status,
            score: Some(m.score),
            summary,
        }
    }

    /// Create an "added in B" entry (no match in A).
    #[must_use]
    pub fn added(offset_b: u64, name_b: Option<String>) -> Self {
        Self {
            offset_a: None,
            offset_b: Some(offset_b),
            name_a: None,
            name_b,
            status: ChangeStatus::AddedInB,
            score: None,
            summary: format!("New function at 0x{offset_b:X}"),
        }
    }

    /// Create a "removed in B" entry (no match in B).
    #[must_use]
    pub fn removed(offset_a: u64, name_a: Option<String>) -> Self {
        Self {
            offset_a: Some(offset_a),
            offset_b: None,
            name_a,
            name_b: None,
            status: ChangeStatus::RemovedInB,
            score: None,
            summary: format!("Removed function at 0x{offset_a:X}"),
        }
    }

    /// Returns `true` if the function was unchanged.
    #[must_use]
    pub fn is_unchanged(&self) -> bool {
        self.status == ChangeStatus::Unchanged
    }

    /// Returns `true` if this is a new or removed function.
    #[must_use]
    pub const fn is_new_or_removed(&self) -> bool {
        matches!(self.status, ChangeStatus::AddedInB | ChangeStatus::RemovedInB)
    }
}

fn usize_to_f32(x: usize) -> f32 {
    f32::from(u16::try_from(x).unwrap_or(u16::MAX))
}

fn f32_to_u32(x: f32) -> u32 {
    if x <= 0.0 {
        0
    } else if x >= f32::from(u16::MAX) {
        u32::from(u16::MAX)
    } else {
        x as u32
    }
}

fn build_summary(
    status: ChangeStatus,
    score: &SimilarityScore,
    offset_a: u64,
    offset_b: u64,
) -> String {
    match status {
        ChangeStatus::Unchanged =>
            format!("Identical: 0x{offset_a:X} ↔ 0x{offset_b:X}"),
        ChangeStatus::ConstantsChanged =>
            format!("Constants changed: 0x{offset_a:X} → 0x{offset_b:X} (seq={:.2})", score.sequence),
        ChangeStatus::MinorChanges =>
            format!("Minor changes: 0x{offset_a:X} → 0x{offset_b:X} (combined={:.2})", score.combined),
        ChangeStatus::MajorChanges =>
            format!("Major changes: 0x{offset_a:X} → 0x{offset_b:X} (combined={:.2})", score.combined),
        _ =>
            format!("0x{offset_a:X} ↔ 0x{offset_b:X}"),
    }
}

// ── DiffStats ─────────────────────────────────────────────────────────────────

/// Aggregate statistics for a diff report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffStats {
    /// Total functions in A.
    pub total_a: usize,
    /// Total functions in B.
    pub total_b: usize,
    /// Functions matched (any similarity).
    pub matched: usize,
    /// Functions identical.
    pub identical: usize,
    /// Functions with constants-only changes.
    pub constants_changed: usize,
    /// Minor structural changes.
    pub minor_changes: usize,
    /// Major structural changes.
    pub major_changes: usize,
    /// Functions removed.
    pub removed: usize,
    /// Functions added.
    pub added: usize,
    /// Mean similarity score for matched functions.
    pub mean_similarity: f32,
}

impl DiffStats {
    /// Overall similarity ratio [0.0, 1.0].
    #[must_use]
    pub fn similarity_ratio(&self) -> f32 {
        if self.total_a == 0 && self.total_b == 0 {
            return 1.0;
        }
        let denominator = usize_to_f32(self.total_a.max(self.total_b));
        usize_to_f32(self.identical) / denominator
    }

    /// Percentage of functions with any form of change.
    #[must_use]
    pub fn changed_pct(&self) -> f32 {
        let changed = self.minor_changes + self.major_changes + self.constants_changed;
        if self.matched == 0 { return 0.0; }
        (usize_to_f32(changed) / usize_to_f32(self.matched)) * 100.0
    }
}

// ── DiffReport ────────────────────────────────────────────────────────────────

/// Full diff report between binary A and binary B.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    /// Binary A path or identifier.
    pub label_a: String,
    /// Binary B path or identifier.
    pub label_b: String,
    /// All function pair entries.
    pub pairs: Vec<FunctionPair>,
    /// Aggregate statistics.
    pub stats: DiffStats,
}

impl DiffReport {
    /// Iterate pairs with a specific status.
    #[must_use]
    pub fn pairs_with_status(&self, status: ChangeStatus) -> Vec<&FunctionPair> {
        self.pairs.iter().filter(|p| p.status == status).collect()
    }

    /// Histogram: change status → count.
    #[must_use]
    pub fn status_histogram(&self) -> HashMap<ChangeStatus, usize> {
        let mut m: HashMap<ChangeStatus, usize> = HashMap::new();
        for p in &self.pairs {
            *m.entry(p.status).or_insert(0) += 1;
        }
        m
    }

    /// Similarity histogram: floor-to-10% buckets (0.0, 0.1, …, 1.0) → count.
    #[must_use]
    pub fn similarity_histogram(&self) -> HashMap<u32, usize> {
        let mut m: HashMap<u32, usize> = HashMap::new();
        for p in &self.pairs {
            if let Some(s) = &p.score {
                let bucket = f32_to_u32((s.combined * 10.0).floor());
                *m.entry(bucket).or_insert(0) += 1;
            }
        }
        m
    }

    /// Returns the top-N most-changed functions (lowest similarity first).
    #[must_use]
    pub fn most_changed(&self, n: usize) -> Vec<&FunctionPair> {
        let mut matched: Vec<&FunctionPair> = self.pairs.iter()
            .filter(|p| p.score.is_some() && !p.is_unchanged())
            .collect();
        matched.sort_by(|a, b| {
            let sa = a.score.as_ref().map_or(0.0, |s| s.combined);
            let sb = b.score.as_ref().map_or(0.0, |s| s.combined);
            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
        });
        matched.into_iter().take(n).collect()
    }

    /// Returns a brief text summary.
    #[must_use]
    pub fn text_summary(&self) -> String {
        format!(
            "Diff {} vs {}: {} pairs, {}% changed, {:.1}% similarity",
            self.label_a,
            self.label_b,
            self.pairs.len(),
            f32_to_u32(self.stats.changed_pct()),
            self.stats.similarity_ratio() * 100.0,
        )
    }
}

// ── DiffReporter ─────────────────────────────────────────────────────────────

/// Builds `DiffReport` from match results and unmatched function lists.
pub struct DiffReporter {
    /// Label for binary A.
    pub label_a: String,
    /// Label for binary B.
    pub label_b: String,
    /// Whether to include identical (unchanged) functions in the report.
    pub include_unchanged: bool,
}

impl Default for DiffReporter {
    fn default() -> Self {
        Self::new("binary_a", "binary_b")
    }
}

impl DiffReporter {
    /// Create a reporter for two named binaries.
    #[must_use]
    pub fn new(label_a: impl Into<String>, label_b: impl Into<String>) -> Self {
        Self {
            label_a: label_a.into(),
            label_b: label_b.into(),
            include_unchanged: true,
        }
    }

    /// Exclude unchanged functions from the report output.
    #[must_use]
    pub const fn excluding_unchanged(mut self) -> Self {
        self.include_unchanged = false;
        self
    }

    /// Build a full `DiffReport`.
    ///
    /// * `matches` — output of `FunctionMatcher::match_functions`
    /// * `unmatched_a` — `(offset, name)` for functions in A with no match
    /// * `unmatched_b` — `(offset, name)` for functions in B with no match
    /// * `total_a` / `total_b` — total function counts for statistics
    #[must_use]
    pub fn build(
        &self,
        matches: &[MatchResult],
        unmatched_a: &[(u64, Option<String>)],
        unmatched_b: &[(u64, Option<String>)],
        total_a: usize,
        total_b: usize,
    ) -> DiffReport {
        let mut pairs: Vec<FunctionPair> = Vec::new();

        let mut identical = 0usize;
        let mut constants_changed = 0usize;
        let mut minor_changes = 0usize;
        let mut major_changes = 0usize;
        let mut score_sum = 0.0f32;
        let mut score_count = 0usize;

        for m in matches {
            let pair = FunctionPair::from_match(m);
            match pair.status {
                ChangeStatus::Unchanged => identical += 1,
                ChangeStatus::ConstantsChanged => constants_changed += 1,
                ChangeStatus::MinorChanges => minor_changes += 1,
                ChangeStatus::MajorChanges => major_changes += 1,
                _ => {}
            }
            score_sum += m.score.combined;
            score_count += 1;
            if self.include_unchanged || pair.status != ChangeStatus::Unchanged {
                pairs.push(pair);
            }
        }

        let removed = unmatched_a.len();
        let added = unmatched_b.len();

        for (off, name) in unmatched_a {
            pairs.push(FunctionPair::removed(*off, name.clone()));
        }
        for (off, name) in unmatched_b {
            pairs.push(FunctionPair::added(*off, name.clone()));
        }

        let mean_similarity = if score_count > 0 { score_sum / usize_to_f32(score_count) } else { 0.0 };

        let stats = DiffStats {
            total_a,
            total_b,
            matched: matches.len(),
            identical,
            constants_changed,
            minor_changes,
            major_changes,
            removed,
            added,
            mean_similarity,
        };

        DiffReport { label_a: self.label_a.clone(), label_b: self.label_b.clone(), pairs, stats }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::function_matcher::MatchKind;

    fn make_match(offset_a: u64, offset_b: u64, combined: f32, kind: MatchKind) -> MatchResult {
        let seq = combined;
        let score = SimilarityScore::from_components(seq, seq, seq, seq);
        MatchResult {
            offset_a, offset_b,
            name_a: Some(format!("fn_a_{offset_a:X}")),
            name_b: Some(format!("fn_b_{offset_b:X}")),
            score,
            kind,
        }
    }

    fn build_simple_report() -> DiffReport {
        let matches = vec![
            make_match(0x1000, 0x2000, 1.0, MatchKind::Identical),
            make_match(0x1100, 0x2100, 0.92, MatchKind::NearIdentical),
            make_match(0x1200, 0x2200, 0.75, MatchKind::HighSimilarity),
            make_match(0x1300, 0x2300, 0.62, MatchKind::ModerateSimilarity),
        ];
        let unmatched_a = vec![(0x1400u64, Some("removed_fn".into()))];
        let unmatched_b = vec![(0x2500u64, Some("new_fn".into()))];
        let r = DiffReporter::new("v1.exe", "v2.exe");
        r.build(&matches, &unmatched_a, &unmatched_b, 5, 5)
    }

    #[test]
    fn test_report_pair_count() {
        let report = build_simple_report();
        assert_eq!(report.pairs.len(), 6); // 4 matches + 1 removed + 1 added
    }

    #[test]
    fn test_stats_identical_count() {
        let report = build_simple_report();
        assert_eq!(report.stats.identical, 1);
    }

    #[test]
    fn test_stats_removed_added() {
        let report = build_simple_report();
        assert_eq!(report.stats.removed, 1);
        assert_eq!(report.stats.added, 1);
    }

    #[test]
    fn test_similarity_ratio() {
        let report = build_simple_report();
        assert!((report.stats.similarity_ratio() - 0.2).abs() < 0.01);
    }

    #[test]
    fn test_status_histogram_has_unchanged() {
        let report = build_simple_report();
        let h = report.status_histogram();
        assert!(h.get(&ChangeStatus::Unchanged).copied().unwrap_or(0) >= 1);
    }

    #[test]
    fn test_similarity_histogram_buckets() {
        let report = build_simple_report();
        let h = report.similarity_histogram();
        // combined score 1.0 → bucket 10
        assert!(h.contains_key(&10));
    }

    #[test]
    fn test_most_changed_order() {
        let report = build_simple_report();
        let mc = report.most_changed(3);
        // All returned entries should have scores, sorted by ascending combined.
        let scores: Vec<f32> = mc.iter().filter_map(|p| p.score.map(|s| s.combined)).collect();
        for w in scores.windows(2) {
            assert!(w[0] <= w[1]);
        }
    }

    #[test]
    fn test_pairs_with_status_removed() {
        let report = build_simple_report();
        let removed = report.pairs_with_status(ChangeStatus::RemovedInB);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].offset_a, Some(0x1400));
    }

    #[test]
    fn test_pairs_with_status_added() {
        let report = build_simple_report();
        let added = report.pairs_with_status(ChangeStatus::AddedInB);
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].offset_b, Some(0x2500));
    }

    #[test]
    fn test_excluding_unchanged() {
        let matches = vec![make_match(0x1000, 0x2000, 1.0, MatchKind::Identical)];
        let r = DiffReporter::new("a", "b").excluding_unchanged();
        let report = r.build(&matches, &[], &[], 1, 1);
        assert!(report.pairs_with_status(ChangeStatus::Unchanged).is_empty());
    }

    #[test]
    fn test_text_summary_non_empty() {
        let report = build_simple_report();
        assert!(!report.text_summary().is_empty());
    }

    #[test]
    fn test_change_status_from_match_identical() {
        let s = SimilarityScore::from_components(1.0, 1.0, 1.0, 1.0);
        assert_eq!(ChangeStatus::from_match(MatchKind::Identical, &s), ChangeStatus::Unchanged);
    }

    #[test]
    fn test_function_pair_removed() {
        let p = FunctionPair::removed(0xDEAD, Some("old_fn".into()));
        assert!(p.is_new_or_removed());
        assert!(p.offset_b.is_none());
    }

    #[test]
    fn test_function_pair_added() {
        let p = FunctionPair::added(0xBEEF, None);
        assert!(p.is_new_or_removed());
        assert!(p.offset_a.is_none());
    }

    #[test]
    fn test_stats_changed_pct() {
        let report = build_simple_report();
        // 3 changed out of 4 matched
        let pct = report.stats.changed_pct();
        assert!(pct > 50.0 && pct <= 100.0);
    }
}
