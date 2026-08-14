//! Coverage diff — computes differences between two coverage snapshots,
//! identifies new/lost edges, regressions, and produces delta reports.

use serde::{Deserialize, Serialize};
pub use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DiffError {
    #[error("mismatched coverage sizes: {0} vs {1}")]
    SizeMismatch(usize, usize),
    #[error("empty coverage snapshot")]
    EmptySnapshot,
    #[error("serialization error: {0}")]
    Serialization(String),
}

// ─── Edge ─────────────────────────────────────────────────────────────────────

/// A directed control-flow edge (from → to).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Edge {
    pub from: u64,
    pub to: u64,
}

impl Edge {
    #[must_use]
    pub const fn new(from: u64, to: u64) -> Self {
        Self { from, to }
    }
}

// ─── CoverageSnapshot ─────────────────────────────────────────────────────────

/// A coverage snapshot: set of edges with hit counts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageSnapshot {
    /// Edge hit counts.
    pub edges: HashMap<Edge, u64>,
    /// Name/label for this snapshot.
    pub name: String,
    /// Number of total executions this snapshot represents.
    pub run_count: u64,
}

impl CoverageSnapshot {
    /// Create a new snapshot.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            edges: HashMap::new(),
            name: name.into(),
            run_count: 1,
        }
    }

    /// Record a hit for an edge.
    pub fn record(&mut self, from: u64, to: u64) {
        *self.edges.entry(Edge::new(from, to)).or_insert(0) += 1;
    }

    /// Total hit count across all edges.
    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.edges.values().sum()
    }

    /// All covered edges.
    #[must_use]
    pub fn covered_edges(&self) -> HashSet<Edge> {
        self.edges.keys().copied().collect()
    }
}

// ─── NewEdges ─────────────────────────────────────────────────────────────────

/// Edges present in snapshot B but not in snapshot A.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewEdges {
    pub edges: Vec<Edge>,
    /// Hit counts in the new snapshot.
    #[serde(with = "edge_hits_serde")]
    pub hit_counts: HashMap<Edge, u64>,
}

impl NewEdges {
    /// Total hit count for all new edges.
    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.hit_counts.values().sum()
    }

    /// Whether any new edges were found.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }
}

// ─── LostEdges ────────────────────────────────────────────────────────────────

/// Edges present in snapshot A but missing from snapshot B.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LostEdges {
    pub edges: Vec<Edge>,
    /// Hit counts in the old snapshot (before loss).
    #[serde(with = "edge_hits_serde")]
    pub old_hit_counts: HashMap<Edge, u64>,
}

mod edge_hits_serde {
    use super::Edge;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    pub fn serialize<S: Serializer>(map: &HashMap<Edge, u64>, s: S) -> Result<S::Ok, S::Error> {
        let v: Vec<(Edge, u64)> = map.iter().map(|(&k, &v)| (k, v)).collect();
        v.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<HashMap<Edge, u64>, D::Error> {
        let v: Vec<(Edge, u64)> = Vec::deserialize(d)?;
        Ok(v.into_iter().collect())
    }
}

impl LostEdges {
    /// Whether any edges were lost.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }
}

// ─── CoverageRegression ───────────────────────────────────────────────────────

/// A coverage regression: edges that were previously covered but are now missing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageRegression {
    /// Lost edges that indicate a regression.
    pub lost: LostEdges,
    /// New edges that compensate (may not be related to lost).
    pub new: NewEdges,
    /// Net edge change (positive = coverage increased).
    pub net_edge_delta: i64,
    /// Whether this qualifies as a hard regression (lost > gained).
    pub is_regression: bool,
}

impl CoverageRegression {
    /// Compute from lost/new edge sets.
    #[must_use]
    pub fn compute(lost: LostEdges, new: NewEdges) -> Self {
        let net = crate::usize_to_i64_sat(new.edges.len()) - crate::usize_to_i64_sat(lost.edges.len());
        let is_regression = lost.edges.len() > new.edges.len();
        Self {
            lost,
            new,
            net_edge_delta: net,
            is_regression,
        }
    }
}

// ─── DiffReport ───────────────────────────────────────────────────────────────

/// Summary diff report between two coverage snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub snapshot_a: String,
    pub snapshot_b: String,
    pub edges_a: usize,
    pub edges_b: usize,
    pub new_edges: NewEdges,
    pub lost_edges: LostEdges,
    pub common_edges: usize,
    pub regression: CoverageRegression,
    /// Percentage of A's edges still covered in B.
    pub retention_pct: f64,
    /// Percentage of B's edges that are new relative to A.
    pub new_pct: f64,
}

impl DiffReport {
    /// Human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Coverage diff '{}' -> '{}': +{} new, -{} lost, {} common ({:.1}% retention)",
            self.snapshot_a,
            self.snapshot_b,
            self.new_edges.edges.len(),
            self.lost_edges.edges.len(),
            self.common_edges,
            self.retention_pct * 100.0,
        )
    }
}

// ─── CoverageDiff ────────────────────────────────────────────────────────────

/// Computes the difference between two coverage snapshots.
#[derive(Debug, Default)]
pub struct CoverageDiff;

impl CoverageDiff {
    /// Create a new `CoverageDiff` instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compute diff between snapshot A (baseline) and snapshot B (new).
    ///
    /// # Errors
    /// Returns `DiffError` if the snapshots cannot be compared.
    pub fn diff(
        &self,
        a: &CoverageSnapshot,
        b: &CoverageSnapshot,
    ) -> Result<DiffReport, DiffError> {
        let set_a = a.covered_edges();
        let set_b = b.covered_edges();

        let new_edge_set: Vec<Edge> = set_b.difference(&set_a).copied().collect();
        let lost_edge_set: Vec<Edge> = set_a.difference(&set_b).copied().collect();
        let common = set_a.intersection(&set_b).count();

        let new_hit_counts: HashMap<Edge, u64> = new_edge_set
            .iter()
            .filter_map(|e| b.edges.get(e).map(|&h| (*e, h)))
            .collect();
        let old_hit_counts: HashMap<Edge, u64> = lost_edge_set
            .iter()
            .filter_map(|e| a.edges.get(e).map(|&h| (*e, h)))
            .collect();

        let new_edges = NewEdges {
            edges: new_edge_set,
            hit_counts: new_hit_counts,
        };
        let lost_edges = LostEdges {
            edges: lost_edge_set,
            old_hit_counts,
        };
        let retention = if set_a.is_empty() {
            1.0
        } else {
            crate::usize_to_f64(common) / crate::usize_to_f64(set_a.len())
        };
        let new_pct = if set_b.is_empty() {
            0.0
        } else {
            crate::usize_to_f64(new_edges.edges.len()) / crate::usize_to_f64(set_b.len())
        };
        let regression = CoverageRegression::compute(lost_edges.clone(), new_edges.clone());

        Ok(DiffReport {
            snapshot_a: a.name.clone(),
            snapshot_b: b.name.clone(),
            edges_a: set_a.len(),
            edges_b: set_b.len(),
            new_edges,
            lost_edges,
            common_edges: common,
            regression,
            retention_pct: retention,
            new_pct,
        })
    }

    /// Whether the diff between A and B represents a regression.
    #[must_use] 
    pub fn is_regression(&self, a: &CoverageSnapshot, b: &CoverageSnapshot) -> bool {
        self.diff(a, b)
            .is_ok_and(|r| r.regression.is_regression)
    }
}

// ─── DeltaExporter ────────────────────────────────────────────────────────────

/// Exports coverage diff results in various formats.
#[derive(Debug, Default)]
pub struct DeltaExporter;

impl DeltaExporter {
    /// Export diff as a simple text report.
    #[must_use]
    pub fn to_text(report: &DiffReport) -> String {
        let mut out = report.summary();
        out.push('\n');
        if !report.new_edges.is_empty() {
            out.push_str("NEW EDGES:\n");
            let mut sorted = report.new_edges.edges.clone();
            sorted.sort();
            for e in &sorted {
                let hits = report.new_edges.hit_counts.get(e).copied().unwrap_or(0);
                writeln!(out,
                    "  0x{:016x} -> 0x{:016x} (hits: {})",
                    e.from, e.to, hits
                ).ok();
            }
        }
        if !report.lost_edges.is_empty() {
            out.push_str("LOST EDGES:\n");
            let mut sorted = report.lost_edges.edges.clone();
            sorted.sort();
            for e in &sorted {
                let hits = report
                    .lost_edges
                    .old_hit_counts
                    .get(e)
                    .copied()
                    .unwrap_or(0);
                writeln!(out,
                    "  0x{:016x} -> 0x{:016x} (was hits: {})",
                    e.from, e.to, hits
                ).ok();
            }
        }
        out
    }

    /// Export diff as JSON string.
    ///
    /// # Errors
    /// Returns `DiffError::Serialization` if JSON serialization fails.
    pub fn to_json(report: &DiffReport) -> Result<String, DiffError> {
        serde_json::to_string_pretty(report).map_err(|e| DiffError::Serialization(e.to_string()))
    }

    /// Export as a sorted edge list for easy diffing.
    #[must_use]
    pub fn to_edge_list(snapshot: &CoverageSnapshot) -> Vec<String> {
        let mut edges: Vec<_> = snapshot.edges.iter().collect();
        edges.sort_by_key(|(e, _)| *(*e));
        edges
            .iter()
            .map(|(e, h)| format!("0x{:016x}->0x{:016x}:{}", e.from, e.to, *h))
            .collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(name: &str, edges: &[(u64, u64)]) -> CoverageSnapshot {
        let mut s = CoverageSnapshot::new(name);
        for &(from, to) in edges {
            s.record(from, to);
        }
        s
    }

    // ── CoverageSnapshot ────────────────────────────────────────────────────

    #[test]
    fn test_snapshot_record() {
        let mut s = CoverageSnapshot::new("test");
        s.record(0x1000, 0x2000);
        s.record(0x1000, 0x2000);
        assert_eq!(*s.edges.get(&Edge::new(0x1000, 0x2000)).unwrap(), 2);
    }

    #[test]
    fn test_snapshot_total_hits() {
        let s = snap("a", &[(1, 2), (3, 4), (5, 6)]);
        assert_eq!(s.total_hits(), 3);
    }

    #[test]
    fn test_snapshot_covered_edges() {
        let s = snap("a", &[(1, 2), (3, 4)]);
        assert_eq!(s.covered_edges().len(), 2);
    }

    // ── NewEdges / LostEdges ────────────────────────────────────────────────

    #[test]
    fn test_new_edges_empty() {
        let ne = NewEdges::default();
        assert!(ne.is_empty());
        assert_eq!(ne.total_hits(), 0);
    }

    #[test]
    fn test_lost_edges_empty() {
        let le = LostEdges::default();
        assert!(le.is_empty());
    }

    // ── CoverageDiff ─────────────────────────────────────────────────────────

    #[test]
    fn test_diff_new_edges() {
        let a = snap("a", &[(1, 2)]);
        let b = snap("b", &[(1, 2), (3, 4)]);
        let diff = CoverageDiff::new().diff(&a, &b).unwrap();
        assert_eq!(diff.new_edges.edges.len(), 1);
        assert_eq!(diff.new_edges.edges[0], Edge::new(3, 4));
    }

    #[test]
    fn test_diff_lost_edges() {
        let a = snap("a", &[(1, 2), (3, 4)]);
        let b = snap("b", &[(1, 2)]);
        let diff = CoverageDiff::new().diff(&a, &b).unwrap();
        assert_eq!(diff.lost_edges.edges.len(), 1);
        assert_eq!(diff.lost_edges.edges[0], Edge::new(3, 4));
    }

    #[test]
    fn test_diff_common_edges() {
        let a = snap("a", &[(1, 2), (3, 4)]);
        let b = snap("b", &[(1, 2), (5, 6)]);
        let diff = CoverageDiff::new().diff(&a, &b).unwrap();
        assert_eq!(diff.common_edges, 1);
    }

    #[test]
    fn test_diff_identical_no_change() {
        let a = snap("a", &[(1, 2), (3, 4)]);
        let b = snap("b", &[(1, 2), (3, 4)]);
        let diff = CoverageDiff::new().diff(&a, &b).unwrap();
        assert!(diff.new_edges.is_empty());
        assert!(diff.lost_edges.is_empty());
    }

    #[test]
    fn test_diff_retention_full() {
        let a = snap("a", &[(1, 2), (3, 4)]);
        let b = snap("b", &[(1, 2), (3, 4), (5, 6)]);
        let diff = CoverageDiff::new().diff(&a, &b).unwrap();
        assert!((diff.retention_pct - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_diff_is_regression_true() {
        let a = snap("a", &[(1, 2), (3, 4), (5, 6)]);
        let b = snap("b", &[(1, 2)]);
        assert!(CoverageDiff::new().is_regression(&a, &b));
    }

    #[test]
    fn test_diff_is_regression_false() {
        let a = snap("a", &[(1, 2)]);
        let b = snap("b", &[(1, 2), (3, 4)]);
        assert!(!CoverageDiff::new().is_regression(&a, &b));
    }

    #[test]
    fn test_diff_net_delta_positive() {
        let a = snap("a", &[(1, 2)]);
        let b = snap("b", &[(1, 2), (3, 4), (5, 6)]);
        let diff = CoverageDiff::new().diff(&a, &b).unwrap();
        assert!(diff.regression.net_edge_delta > 0);
    }

    #[test]
    fn test_diff_empty_a() {
        let a = CoverageSnapshot::new("empty");
        let b = snap("b", &[(1, 2)]);
        let diff = CoverageDiff::new().diff(&a, &b).unwrap();
        assert_eq!(diff.new_edges.edges.len(), 1);
    }

    // ── CoverageRegression ──────────────────────────────────────────────────

    #[test]
    fn test_regression_compute_is_regression() {
        let lost = LostEdges {
            edges: vec![Edge::new(1, 2), Edge::new(3, 4)],
            old_hit_counts: HashMap::new(),
        };
        let new = NewEdges {
            edges: vec![Edge::new(5, 6)],
            hit_counts: HashMap::new(),
        };
        let reg = CoverageRegression::compute(lost, new);
        assert!(reg.is_regression);
        assert_eq!(reg.net_edge_delta, -1);
    }

    #[test]
    fn test_regression_compute_not_regression() {
        let lost = LostEdges {
            edges: vec![],
            old_hit_counts: HashMap::new(),
        };
        let new = NewEdges {
            edges: vec![Edge::new(1, 2)],
            hit_counts: HashMap::new(),
        };
        let reg = CoverageRegression::compute(lost, new);
        assert!(!reg.is_regression);
    }

    // ── DeltaExporter ───────────────────────────────────────────────────────

    #[test]
    fn test_exporter_text_contains_summary() {
        let a = snap("baseline", &[(1, 2)]);
        let b = snap("new_build", &[(1, 2), (3, 4)]);
        let report = CoverageDiff::new().diff(&a, &b).unwrap();
        let text = DeltaExporter::to_text(&report);
        assert!(text.contains("baseline"));
        assert!(text.contains("new_build"));
    }

    #[test]
    fn test_exporter_json() {
        let a = snap("a", &[(1, 2)]);
        let b = snap("b", &[(3, 4)]);
        let report = CoverageDiff::new().diff(&a, &b).unwrap();
        let json = DeltaExporter::to_json(&report).unwrap();
        assert!(json.contains("snapshot_a"));
    }

    #[test]
    fn test_exporter_edge_list_sorted() {
        let s = snap("s", &[(3, 4), (1, 2)]);
        let list = DeltaExporter::to_edge_list(&s);
        assert_eq!(list.len(), 2);
        // First entry should be smaller address
        assert!(list[0].contains("0x0000000000000001"));
    }

    // ── DiffReport ──────────────────────────────────────────────────────────

    #[test]
    fn test_report_summary_format() {
        let a = snap("v1", &[(1, 2)]);
        let b = snap("v2", &[(1, 2), (3, 4)]);
        let r = CoverageDiff::new().diff(&a, &b).unwrap();
        let s = r.summary();
        assert!(s.contains("v1"));
        assert!(s.contains("v2"));
        assert!(s.contains("+1 new"));
    }

    // ── Additional coverage ─────────────────────────────────────────────────

    #[test]
    fn test_snapshot_total_hits_after_multiple_records() {
        let mut s = CoverageSnapshot::new("m");
        s.record(0, 1);
        s.record(0, 1);
        s.record(0, 1);
        assert_eq!(s.total_hits(), 3);
    }

    #[test]
    fn test_diff_new_edges_hit_count() {
        let a = snap("a", &[]);
        let mut b = CoverageSnapshot::new("b");
        b.record(5, 6);
        b.record(5, 6);
        let diff = CoverageDiff::new().diff(&a, &b).unwrap();
        let edge = Edge::new(5, 6);
        assert_eq!(*diff.new_edges.hit_counts.get(&edge).unwrap(), 2);
    }

    #[test]
    fn test_diff_lost_edges_old_hit_count() {
        let mut a = CoverageSnapshot::new("a");
        a.record(5, 6);
        a.record(5, 6);
        a.record(5, 6);
        let b = snap("b", &[]);
        let diff = CoverageDiff::new().diff(&a, &b).unwrap();
        let edge = Edge::new(5, 6);
        assert_eq!(*diff.lost_edges.old_hit_counts.get(&edge).unwrap(), 3);
    }

    #[test]
    fn test_diff_new_pct() {
        let a = snap("a", &[]);
        let b = snap("b", &[(1, 2), (3, 4)]);
        let diff = CoverageDiff::new().diff(&a, &b).unwrap();
        assert!((diff.new_pct - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_edge_ordering() {
        let e1 = Edge::new(1, 2);
        let e2 = Edge::new(1, 3);
        assert!(e1 < e2);
    }

    #[test]
    fn test_exporter_text_new_edges_section() {
        let a = snap("old", &[]);
        let b = snap("new", &[(0x100, 0x200)]);
        let r = CoverageDiff::new().diff(&a, &b).unwrap();
        let text = DeltaExporter::to_text(&r);
        assert!(text.contains("NEW EDGES"));
    }

    #[test]
    fn test_exporter_text_lost_edges_section() {
        let a = snap("old", &[(0x100, 0x200)]);
        let b = snap("new", &[]);
        let r = CoverageDiff::new().diff(&a, &b).unwrap();
        let text = DeltaExporter::to_text(&r);
        assert!(text.contains("LOST EDGES"));
    }

    #[test]
    fn test_new_edges_total_hits() {
        let mut ne = NewEdges::default();
        ne.hit_counts.insert(Edge::new(1, 2), 5);
        ne.hit_counts.insert(Edge::new(3, 4), 3);
        assert_eq!(ne.total_hits(), 8);
    }

    #[test]
    fn test_edge_new() {
        let e = Edge::new(10, 20);
        assert_eq!(e.from, 10);
        assert_eq!(e.to, 20);
    }

    #[test]
    fn test_regression_net_delta_zero() {
        let lost = LostEdges {
            edges: vec![Edge::new(1, 2)],
            old_hit_counts: HashMap::new(),
        };
        let new = NewEdges {
            edges: vec![Edge::new(3, 4)],
            hit_counts: HashMap::new(),
        };
        let r = CoverageRegression::compute(lost, new);
        assert_eq!(r.net_edge_delta, 0);
    }
}
