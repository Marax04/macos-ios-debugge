//! Differential coverage — compare coverage between runs, identify regressions,
//! highlight paths reached only with malicious/benign inputs.

use std::collections::HashSet;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::coverage_map::CoverageMap;

// ─── Run labels ───────────────────────────────────────────────────────────────

/// The class of inputs used to generate a coverage run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InputClass {
    Benign,
    Malicious,
    Fuzzer,
    Regression,
    Custom(String),
}

impl std::fmt::Display for InputClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Benign => write!(f, "benign"),
            Self::Malicious => write!(f, "malicious"),
            Self::Fuzzer => write!(f, "fuzzer"),
            Self::Regression => write!(f, "regression"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

/// Metadata for one labeled coverage run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunDescriptor {
    pub run_id: u64,
    pub label: String,
    pub input_class: InputClass,
    pub input_count: usize,
    pub timestamp: Option<u64>,
    pub notes: Option<String>,
}

// ─── Differential result ──────────────────────────────────────────────────────

/// Addresses only covered by run A (not in run B).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub run_a: RunDescriptor,
    pub run_b: RunDescriptor,
    /// BBs covered in A but not B.
    pub only_in_a: Vec<u64>,
    /// BBs covered in B but not A.
    pub only_in_b: Vec<u64>,
    /// BBs covered in both.
    pub in_both: Vec<u64>,
    /// Hit-count differences for shared BBs: (addr, `hits_a`, `hits_b`).
    pub hit_count_diffs: Vec<(u64, u64, u64)>,
}

impl DiffResult {
    /// Jaccard similarity index (intersection/union).
    #[must_use] 
    pub fn jaccard(&self) -> f64 {
        let intersection = self.in_both.len();
        let union = self.only_in_a.len() + self.only_in_b.len() + intersection;
        if union == 0 { 1.0 } else { crate::usize_to_f64(intersection) / crate::usize_to_f64(union) }
    }

    /// Format a compact summary.
    #[must_use] 
    pub fn summary(&self) -> String {
        let mut out = String::new();
        writeln!(out, "Differential Coverage: '{}' vs '{}'", self.run_a.label, self.run_b.label).ok();
        writeln!(out, "  Only in {}: {} BBs", self.run_a.label, self.only_in_a.len()).ok();
        writeln!(out, "  Only in {}: {} BBs", self.run_b.label, self.only_in_b.len()).ok();
        writeln!(out, "  In both  : {} BBs", self.in_both.len()).ok();
        writeln!(out, "  Jaccard  : {:.3}", self.jaccard()).ok();
        out
    }

    /// Human-readable detail report.
    #[must_use] 
    pub fn detail_report(&self, max_addrs: usize) -> String {
        let mut out = self.summary();
        writeln!(out).ok();

        if !self.only_in_a.is_empty() {
            writeln!(out, "═ Unique to '{}' ({}) ═", self.run_a.label, self.only_in_a.len()).ok();
            for &addr in self.only_in_a.iter().take(max_addrs) {
                writeln!(out, "  {addr:#018x}").ok();
            }
            if self.only_in_a.len() > max_addrs {
                writeln!(out, "  ... and {} more", self.only_in_a.len() - max_addrs).ok();
            }
            writeln!(out).ok();
        }

        if !self.only_in_b.is_empty() {
            writeln!(out, "═ Unique to '{}' ({}) ═", self.run_b.label, self.only_in_b.len()).ok();
            for &addr in self.only_in_b.iter().take(max_addrs) {
                writeln!(out, "  {addr:#018x}").ok();
            }
            if self.only_in_b.len() > max_addrs {
                writeln!(out, "  ... and {} more", self.only_in_b.len() - max_addrs).ok();
            }
            writeln!(out).ok();
        }

        if !self.hit_count_diffs.is_empty() {
            writeln!(out, "═ Hit count differences (top 10) ═").ok();
            let mut diffs = self.hit_count_diffs.clone();
            diffs.sort_by_key(|(_, a, b)| {
                let a = crate::u64_to_i64_sat(*a);
                let b = crate::u64_to_i64_sat(*b);
                -(a - b).abs()
            });
            for (addr, ha, hb) in diffs.iter().take(10) {
                let delta: i64 = crate::u64_to_i64_sat(*hb) - crate::u64_to_i64_sat(*ha);
                let sign = if delta > 0 { "+" } else { "" };
                writeln!(out, "  {addr:#018x}  {ha} → {hb}  ({sign}{delta})").ok();
            }
        }

        out
    }
}

// ─── Differential engine ──────────────────────────────────────────────────────

/// Computes differential coverage between two `CoverageMap`s.
#[must_use] 
pub fn diff_coverage(
    cov_a: &CoverageMap,
    desc_a: RunDescriptor,
    cov_b: &CoverageMap,
    desc_b: RunDescriptor,
) -> DiffResult {
    let set_a: HashSet<u64> = cov_a.bbs.iter().filter(|(_, r)| r.covered).map(|(&k, _)| k).collect();
    let set_b: HashSet<u64> = cov_b.bbs.iter().filter(|(_, r)| r.covered).map(|(&k, _)| k).collect();

    let mut only_in_a: Vec<u64> = set_a.difference(&set_b).copied().collect();
    let mut only_in_b: Vec<u64> = set_b.difference(&set_a).copied().collect();
    let mut in_both: Vec<u64> = set_a.intersection(&set_b).copied().collect();

    only_in_a.sort_unstable();
    only_in_b.sort_unstable();
    in_both.sort_unstable();

    let mut hit_count_diffs = Vec::new();
    for &addr in &in_both {
        let ha = cov_a.bbs.get(&addr).map_or(0, |r| r.total_hits);
        let hb = cov_b.bbs.get(&addr).map_or(0, |r| r.total_hits);
        if ha != hb {
            hit_count_diffs.push((addr, ha, hb));
        }
    }

    DiffResult { run_a: desc_a, run_b: desc_b, only_in_a, only_in_b, in_both, hit_count_diffs }
}

// ─── Regression detector ──────────────────────────────────────────────────────

/// A coverage regression: BBs that were covered in a baseline run but not
/// in the new run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageRegression {
    pub regressed_bbs: Vec<u64>,
    pub baseline_label: String,
    pub new_label: String,
    pub severity: RegressionSeverity,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegressionSeverity {
    /// < 1% of BBs lost.
    Minor,
    /// 1–5% of BBs lost.
    Moderate,
    /// > 5% of BBs lost.
    Major,
}

impl std::fmt::Display for RegressionSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Minor => write!(f, "minor"),
            Self::Moderate => write!(f, "moderate"),
            Self::Major => write!(f, "MAJOR"),
        }
    }
}

/// Detect coverage regressions between a baseline and a newer run.
pub fn detect_regression(
    baseline: &CoverageMap,
    baseline_label: impl Into<String>,
    new_run: &CoverageMap,
    new_label: impl Into<String>,
) -> CoverageRegression {
    let baseline_label = baseline_label.into();
    let new_label = new_label.into();

    let baseline_set: HashSet<u64> = baseline.bbs.iter().filter(|(_, r)| r.covered).map(|(&k, _)| k).collect();
    let new_set: HashSet<u64> = new_run.bbs.iter().filter(|(_, r)| r.covered).map(|(&k, _)| k).collect();

    let mut regressed_bbs: Vec<u64> = baseline_set.difference(&new_set).copied().collect();
    regressed_bbs.sort_unstable();

    let regressed_pct = if baseline_set.is_empty() {
        0.0
    } else {
        crate::usize_to_f64(regressed_bbs.len()) / crate::usize_to_f64(baseline_set.len()) * 100.0
    };

    let severity = if regressed_pct < 1.0 {
        RegressionSeverity::Minor
    } else if regressed_pct < 5.0 {
        RegressionSeverity::Moderate
    } else {
        RegressionSeverity::Major
    };

    let notes = vec![
        format!("Baseline: {} covered BBs", baseline_set.len()),
        format!("New run : {} covered BBs", new_set.len()),
        format!("Regressed: {} BBs ({regressed_pct:.1}%)", regressed_bbs.len()),
    ];

    CoverageRegression { regressed_bbs, baseline_label, new_label, severity, notes }
}

// ─── Malicious vs benign analysis ────────────────────────────────────────────

/// Result of comparing malicious vs benign input coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousVsBenignAnalysis {
    /// BBs only reached by malicious inputs.
    pub malicious_only: Vec<u64>,
    /// BBs only reached by benign inputs.
    pub benign_only: Vec<u64>,
    /// BBs reached by both.
    pub common: Vec<u64>,
    /// Total malicious-specific coverage percentage.
    pub malicious_exclusive_pct: f64,
    /// Heuristic risk score (0.0 – 100.0).
    pub risk_score: f64,
    pub risk_notes: Vec<String>,
}

/// Analyze which code paths are exclusively triggered by malicious vs benign inputs.
#[must_use] 
pub fn analyze_malicious_vs_benign(
    malicious: &CoverageMap,
    benign: &CoverageMap,
) -> MaliciousVsBenignAnalysis {
    let mal_set: HashSet<u64> = malicious.bbs.iter().filter(|(_, r)| r.covered).map(|(&k, _)| k).collect();
    let ben_set: HashSet<u64> = benign.bbs.iter().filter(|(_, r)| r.covered).map(|(&k, _)| k).collect();

    let mut malicious_only: Vec<u64> = mal_set.difference(&ben_set).copied().collect();
    let mut benign_only: Vec<u64> = ben_set.difference(&mal_set).copied().collect();
    let mut common: Vec<u64> = mal_set.intersection(&ben_set).copied().collect();

    malicious_only.sort_unstable();
    benign_only.sort_unstable();
    common.sort_unstable();

    let total = mal_set.len().max(1);
    let malicious_exclusive_pct = crate::usize_to_f64(malicious_only.len()) / crate::usize_to_f64(total) * 100.0;

    // Risk score heuristic: percentage of code uniquely triggered by malicious input
    let risk_score = malicious_exclusive_pct.min(100.0);

    let mut risk_notes = Vec::new();
    if malicious_exclusive_pct > 30.0 {
        risk_notes.push(format!(
            "HIGH: {malicious_exclusive_pct:.0}% of malicious-input coverage is exclusive — significant attack surface not exercised by normal usage."
        ));
    } else if malicious_exclusive_pct > 10.0 {
        risk_notes.push(format!(
            "MODERATE: {:.0}% exclusive malicious coverage — review the {} exclusive BBs for error handling and boundary checks.",
            malicious_exclusive_pct, malicious_only.len()
        ));
    } else {
        risk_notes.push("LOW: malicious and benign inputs cover similar code paths.".into());
    }

    if !benign_only.is_empty() {
        risk_notes.push(format!(
            "{} BBs are only reached by benign inputs — these code paths may be underrepresented in fuzz testing.",
            benign_only.len()
        ));
    }

    MaliciousVsBenignAnalysis { malicious_only, benign_only, common, malicious_exclusive_pct, risk_score, risk_notes }
}

// ─── Multi-run timeline ───────────────────────────────────────────────────────

/// Tracks coverage evolution across an ordered series of runs.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CoverageTimeline {
    pub entries: Vec<TimelineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub run_id: u64,
    pub label: String,
    pub total_covered_bbs: usize,
    pub new_bbs: usize,
    pub lost_bbs: usize,
    pub cumulative_bbs: usize,
}

impl CoverageTimeline {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    /// Add a new run to the timeline.
    pub fn add_run(&mut self, run_id: u64, label: impl Into<String>, current: &HashSet<u64>, previous: Option<&HashSet<u64>>) {
        let label = label.into();
        let total_covered_bbs = current.len();
        let (new_bbs, lost_bbs) = previous.map_or_else(
            || (total_covered_bbs, 0),
            |prev| {
                let new = current.difference(prev).count();
                let lost = prev.difference(current).count();
                (new, lost)
            },
        );
        let cumulative_bbs = self.entries.last().map_or(0, |e| e.cumulative_bbs) + new_bbs;
        self.entries.push(TimelineEntry { run_id, label, total_covered_bbs, new_bbs, lost_bbs, cumulative_bbs });
    }

    /// Format the timeline as a table.
    #[must_use] 
    pub fn format_table(&self) -> String {
        let mut out = String::new();
        writeln!(out, "{:<6} {:<20} {:<12} {:<10} {:<10} {:<12}", "Run", "Label", "Covered BBs", "New", "Lost", "Cumulative").ok();
        writeln!(out, "{}", "-".repeat(72)).ok();
        for e in &self.entries {
            writeln!(out, "{:<6} {:<20} {:<12} {:<10} {:<10} {:<12}",
                e.run_id, &e.label[..e.label.len().min(20)],
                e.total_covered_bbs, e.new_bbs, e.lost_bbs, e.cumulative_bbs).ok();
        }
        out
    }

    /// Return run IDs where a regression occurred (`lost_bbs` > 0).
    #[must_use] 
    pub fn regressions(&self) -> Vec<u64> {
        self.entries.iter().filter(|e| e.lost_bbs > 0).map(|e| e.run_id).collect()
    }

    /// Export as JSON.
    #[must_use] 
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

// ─── Cross-run similarity matrix ─────────────────────────────────────────────

/// Compute a pairwise Jaccard similarity matrix for a set of runs.
#[must_use] 
pub fn similarity_matrix(runs: &[(u64, &CoverageMap)]) -> Vec<Vec<f64>> {
    let sets: Vec<std::collections::HashSet<u64>> = runs.iter().map(|(_, cov)| {
        cov.bbs.iter().filter(|(_, r)| r.covered).map(|(&k, _)| k).collect()
    }).collect();

    let n = sets.len();
    let mut matrix = vec![vec![0.0f64; n]; n];
    for i in 0..n {
        matrix[i][i] = 1.0;
        for j in (i + 1)..n {
            let inter = sets[i].intersection(&sets[j]).count();
            let union = sets[i].union(&sets[j]).count();
            let sim = if union == 0 { 1.0 } else { crate::usize_to_f64(inter) / crate::usize_to_f64(union) };
            matrix[i][j] = sim;
            matrix[j][i] = sim;
        }
    }
    matrix
}

/// Format a similarity matrix as a table.
#[must_use] 
pub fn format_similarity_matrix(runs: &[(u64, &CoverageMap)], matrix: &[Vec<f64>]) -> String {
    let mut out = String::new();
    let labels: Vec<String> = runs.iter().map(|(id, _)| format!("run{id}")).collect();
    // Header
    write!(out, "{:>10}", "").ok();
    for lbl in &labels { write!(out, " {:>8}", &lbl[..lbl.len().min(8)]).ok(); }
    writeln!(out).ok();
    for (i, row) in matrix.iter().enumerate() {
        write!(out, "{:>10}", &labels[i][..labels[i].len().min(10)]).ok();
        for &v in row { write!(out, " {v:>8.3}").ok(); }
        writeln!(out).ok();
    }
    out
}

// ─── Seed ranking by unique coverage ─────────────────────────────────────────

/// Rank seeds by unique coverage contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedRanking {
    pub seed_id: u64,
    pub unique_bbs: usize,
    pub total_bbs: usize,
    pub unique_ratio: f64,
}

/// Compute unique coverage contribution for each seed, given a set of runs.
///
/// # Panics
/// Panics if an expected BB address is missing from the coverage map (internal inconsistency).
#[must_use]
pub fn rank_seeds_by_unique_coverage(cov: &CoverageMap) -> Vec<SeedRanking> {
    // Collect all seed IDs
    let all_seeds: std::collections::HashSet<u64> = cov.bbs.values()
        .flat_map(|r| r.per_seed.keys().copied())
        .collect();

    let mut rankings: Vec<SeedRanking> = all_seeds.iter().map(|&seed_id| {
        let seed_bbs: std::collections::HashSet<u64> = cov.bbs.iter()
            .filter(|(_, r)| r.per_seed.contains_key(&seed_id))
            .map(|(&addr, _)| addr)
            .collect();
        let total = seed_bbs.len();

        // Unique: covered by this seed but not by any other
        let unique = seed_bbs.iter().filter(|&&addr| {
            let rec = cov.bbs.get(&addr).unwrap();
            rec.per_seed.len() == 1 && rec.per_seed.contains_key(&seed_id)
        }).count();

        let ratio = if total == 0 { 0.0 } else { crate::usize_to_f64(unique) / crate::usize_to_f64(total) };
        SeedRanking { seed_id, unique_bbs: unique, total_bbs: total, unique_ratio: ratio }
    }).collect();

    rankings.sort_by_key(|b| std::cmp::Reverse(b.unique_bbs));
    rankings
}

/// Compute the "coverage gain curve" for a series of runs in order.
///
/// Returns (`run_id`, `cumulative_covered_bbs`) pairs.
#[must_use] 
pub fn coverage_gain_curve(runs_in_order: &[(u64, &CoverageMap)]) -> Vec<(u64, usize)> {
    let mut global: HashSet<u64> = HashSet::new();
    runs_in_order.iter().map(|(id, cov)| {
        for (&addr, rec) in &cov.bbs {
            if rec.covered { global.insert(addr); }
        }
        (*id, global.len())
    }).collect()
}

/// Find the "saturation point" — the run index at which new coverage gains
/// drop below a given threshold (delta < `min_delta` new BBs).
#[must_use] 
pub fn find_saturation_point(curve: &[(u64, usize)], min_delta: usize) -> Option<u64> {
    for window in curve.windows(2) {
        let delta = window[1].1.saturating_sub(window[0].1);
        if delta < min_delta {
            return Some(window[1].0);
        }
    }
    None
}

/// Format seed rankings as a table.
#[must_use] 
pub fn format_seed_rankings(rankings: &[SeedRanking]) -> String {
    let mut out = String::new();
    writeln!(out, "{:<10} {:<12} {:<12} {:<10}", "Seed ID", "Unique BBs", "Total BBs", "Ratio").ok();
    writeln!(out, "{}", "-".repeat(46)).ok();
    for r in rankings {
        writeln!(out, "{:<10} {:<12} {:<12} {:.3}", r.seed_id, r.unique_bbs, r.total_bbs, r.unique_ratio).ok();
    }
    out
}

// ─── Coverage regression reporter ────────────────────────────────────────────

/// Format a regression report as human-readable text.
#[must_use] 
pub fn format_regression_report(reg: &CoverageRegression) -> String {
    let mut out = String::new();
    writeln!(out, "Coverage Regression Report").ok();
    writeln!(out, "  Baseline : {}", reg.baseline_label).ok();
    writeln!(out, "  New run  : {}", reg.new_label).ok();
    writeln!(out, "  Severity : {}", reg.severity).ok();
    writeln!(out, "  Lost BBs : {}", reg.regressed_bbs.len()).ok();
    writeln!(out).ok();
    for note in &reg.notes {
        writeln!(out, "  {note}").ok();
    }
    if !reg.regressed_bbs.is_empty() {
        writeln!(out).ok();
        writeln!(out, "  Regressed basic blocks:").ok();
        for &addr in reg.regressed_bbs.iter().take(20) {
            writeln!(out, "    {addr:#018x}").ok();
        }
        if reg.regressed_bbs.len() > 20 {
            writeln!(out, "    ... and {} more", reg.regressed_bbs.len() - 20).ok();
        }
    }
    out
}

// ─── Input class profile ─────────────────────────────────────────────────────

/// A statistical profile of the coverage triggered by one input class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputClassProfile {
    pub input_class: InputClass,
    pub total_bbs: usize,
    pub unique_bbs: usize,
    pub shared_bbs: usize,
    pub unique_ratio: f64,
    pub top_exclusive_addrs: Vec<u64>,
}

impl InputClassProfile {
    /// Build a profile comparing this class against all others combined.
    #[must_use] 
    pub fn build(class: InputClass, class_cov: &CoverageMap, other_cov: &CoverageMap) -> Self {
        let class_set: HashSet<u64> = class_cov.bbs.iter().filter(|(_, r)| r.covered).map(|(&a, _)| a).collect();
        let other_set: HashSet<u64> = other_cov.bbs.iter().filter(|(_, r)| r.covered).map(|(&a, _)| a).collect();

        let unique: HashSet<u64> = class_set.difference(&other_set).copied().collect();
        let shared = class_set.intersection(&other_set).count();
        let unique_ratio = if class_set.is_empty() { 0.0 } else { crate::usize_to_f64(unique.len()) / crate::usize_to_f64(class_set.len()) };

        let mut top: Vec<u64> = unique.into_iter().collect();
        top.sort_unstable();
        top.truncate(20);

        Self {
            input_class: class,
            total_bbs: class_set.len(),
            unique_bbs: top.len(),
            shared_bbs: shared,
            unique_ratio,
            top_exclusive_addrs: top,
        }
    }
}

impl std::fmt::Display for InputClassProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Input class: {}", self.input_class)?;
        writeln!(f, "  Total BBs  : {}", self.total_bbs)?;
        writeln!(f, "  Unique BBs : {} ({:.1}%)", self.unique_bbs, self.unique_ratio * 100.0)?;
        writeln!(f, "  Shared BBs : {}", self.shared_bbs)?;
        if !self.top_exclusive_addrs.is_empty() {
            writeln!(f, "  Exclusive addresses (top 5):")?;
            for &addr in self.top_exclusive_addrs.iter().take(5) {
                writeln!(f, "    {addr:#018x}")?;
            }
        }
        Ok(())
    }
}

// ─── Differential edge coverage ──────────────────────────────────────────────

/// Compare edge coverage between two runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeDiffResult {
    pub only_in_a: Vec<(u64, u64)>,
    pub only_in_b: Vec<(u64, u64)>,
    pub in_both: Vec<(u64, u64)>,
}

/// Compute edge-level differential coverage.
#[must_use] 
pub fn diff_edge_coverage(
    cov_a: &CoverageMap,
    cov_b: &CoverageMap,
) -> EdgeDiffResult {
    let edges_a: HashSet<(u64, u64)> = cov_a.edges.iter()
        .filter(|(_, r)| r.total_hits > 0)
        .map(|(k, _)| (k.src, k.dst))
        .collect();
    let edges_b: HashSet<(u64, u64)> = cov_b.edges.iter()
        .filter(|(_, r)| r.total_hits > 0)
        .map(|(k, _)| (k.src, k.dst))
        .collect();

    let mut only_in_a: Vec<(u64, u64)> = edges_a.difference(&edges_b).copied().collect();
    let mut only_in_b: Vec<(u64, u64)> = edges_b.difference(&edges_a).copied().collect();
    let mut in_both: Vec<(u64, u64)> = edges_a.intersection(&edges_b).copied().collect();

    only_in_a.sort_unstable();
    only_in_b.sort_unstable();
    in_both.sort_unstable();

    EdgeDiffResult { only_in_a, only_in_b, in_both }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cov(addrs: &[(u64, u64)]) -> CoverageMap {
        let mut cov = CoverageMap::new();
        for &(addr, hits) in addrs {
            cov.record_bb(addr, 1, hits);
        }
        cov
    }

    fn run_desc(id: u64, label: &str, class: InputClass) -> RunDescriptor {
        RunDescriptor { run_id: id, label: label.into(), input_class: class, input_count: 1, timestamp: None, notes: None }
    }

    #[test]
    fn test_diff_basic() {
        let a = make_cov(&[(0x1000, 5), (0x2000, 3)]);
        let b = make_cov(&[(0x1000, 2), (0x3000, 1)]);
        let result = diff_coverage(&a, run_desc(1, "A", InputClass::Benign), &b, run_desc(2, "B", InputClass::Malicious));
        assert!(result.only_in_a.contains(&0x2000));
        assert!(result.only_in_b.contains(&0x3000));
        assert!(result.in_both.contains(&0x1000));
    }

    #[test]
    fn test_jaccard() {
        let a = make_cov(&[(0x1000, 1), (0x2000, 1)]);
        let b = make_cov(&[(0x1000, 1), (0x3000, 1)]);
        let result = diff_coverage(&a, run_desc(1, "A", InputClass::Benign), &b, run_desc(2, "B", InputClass::Benign));
        // intersection=1, union=3 → 0.333
        assert!((result.jaccard() - 1.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_regression_detection() {
        let baseline = make_cov(&[(0x1000, 1), (0x2000, 1), (0x3000, 1)]);
        let new_run = make_cov(&[(0x1000, 1)]); // lost 0x2000 and 0x3000
        let reg = detect_regression(&baseline, "v1.0", &new_run, "v1.1");
        assert_eq!(reg.regressed_bbs.len(), 2);
        assert!(reg.regressed_bbs.contains(&0x2000));
        assert_eq!(reg.severity, RegressionSeverity::Major);
    }

    #[test]
    fn test_malicious_vs_benign() {
        let malicious = make_cov(&[(0x1000, 5), (0x5000, 3), (0x6000, 1)]);
        let benign = make_cov(&[(0x1000, 2), (0x2000, 1)]);
        let analysis = analyze_malicious_vs_benign(&malicious, &benign);
        assert!(analysis.malicious_only.contains(&0x5000));
        assert!(analysis.benign_only.contains(&0x2000));
        assert!(analysis.common.contains(&0x1000));
        assert!(analysis.risk_score > 0.0);
    }

    #[test]
    fn test_timeline() {
        let mut tl = CoverageTimeline::new();
        let run1: HashSet<u64> = [0x1000, 0x2000, 0x3000].into_iter().collect();
        let run2: HashSet<u64> = [0x1000, 0x2000, 0x4000].into_iter().collect();
        tl.add_run(1, "run1", &run1, None);
        tl.add_run(2, "run2", &run2, Some(&run1));
        assert_eq!(tl.entries[1].new_bbs, 1);   // 0x4000 is new
        assert_eq!(tl.entries[1].lost_bbs, 1);   // 0x3000 is lost
        assert_eq!(tl.regressions(), vec![2]);
    }

    #[test]
    fn test_no_regression() {
        let baseline = make_cov(&[(0x1000, 1)]);
        let new_run = make_cov(&[(0x1000, 1), (0x2000, 1)]);
        let reg = detect_regression(&baseline, "base", &new_run, "new");
        assert_eq!(reg.regressed_bbs.len(), 0);
        assert_eq!(reg.severity, RegressionSeverity::Minor);
    }
}
