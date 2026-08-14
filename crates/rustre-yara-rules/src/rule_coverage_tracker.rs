//! `rule_coverage_tracker` — Track which YARA rules matched which samples,
//! compute per-rule and per-sample coverage metrics, and identify gaps.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

// ── SampleCoverage ─────────────────────────────────────────────────────────────

/// Coverage record for a single sample (file or memory buffer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleCoverage {
    /// Unique identifier for this sample (e.g. SHA-256 hex).
    pub sample_id: String,
    /// Optional file path.
    pub path: Option<String>,
    /// Ids of rules that matched this sample.
    pub matched_rule_ids: Vec<String>,
    /// Total number of string matches across all rules.
    pub total_string_matches: usize,
    /// Timestamp when this sample was scanned.
    pub scanned_at: SystemTime,
    /// Size of the sample in bytes.
    pub size_bytes: u64,
    /// Whether this sample is considered malicious (ground-truth label).
    pub is_malicious: Option<bool>,
}

impl SampleCoverage {
    /// Create a new sample coverage record.
    #[must_use]
    pub fn new(sample_id: impl Into<String>, size_bytes: u64) -> Self {
        Self {
            sample_id: sample_id.into(),
            path: None,
            matched_rule_ids: Vec::new(),
            total_string_matches: 0,
            scanned_at: SystemTime::now(),
            size_bytes,
            is_malicious: None,
        }
    }

    /// Return `true` if at least one rule matched this sample.
    #[must_use]
    pub const fn has_matches(&self) -> bool {
        !self.matched_rule_ids.is_empty()
    }

    /// Number of rules that matched.
    #[must_use]
    pub const fn match_count(&self) -> usize {
        self.matched_rule_ids.len()
    }
}

// ── RuleCoverage ──────────────────────────────────────────────────────────────

/// Coverage statistics for a single YARA rule across all scanned samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCoverage {
    /// Rule identifier.
    pub rule_id: String,
    /// Rule name.
    pub rule_name: String,
    /// Total number of samples scanned.
    pub total_samples_scanned: u64,
    /// Number of samples on which this rule matched.
    pub samples_matched: u64,
    /// Number of samples on which this rule did NOT match (miss).
    pub samples_missed: u64,
    /// True-positive count (matched malicious samples).
    pub true_positives: u64,
    /// False-positive count (matched benign samples).
    pub false_positives: u64,
    /// True-negative count (did not match benign samples).
    pub true_negatives: u64,
    /// False-negative count (did not match malicious samples).
    pub false_negatives: u64,
    /// Ids of samples this rule matched (capped at `max_tracked` entries).
    pub matched_sample_ids: Vec<String>,
    /// Ids of samples this rule missed that had ground-truth malicious labels.
    pub missed_malicious_sample_ids: Vec<String>,
    /// When this coverage record was last updated.
    pub last_updated: SystemTime,
}

impl RuleCoverage {
    /// Create a new, zeroed coverage record.
    #[must_use]
    pub fn new(rule_id: impl Into<String>, rule_name: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.into(),
            rule_name: rule_name.into(),
            total_samples_scanned: 0,
            samples_matched: 0,
            samples_missed: 0,
            true_positives: 0,
            false_positives: 0,
            true_negatives: 0,
            false_negatives: 0,
            matched_sample_ids: Vec::new(),
            missed_malicious_sample_ids: Vec::new(),
            last_updated: SystemTime::now(),
        }
    }

    /// Detection rate: matched / total (0.0 if no samples scanned).
    #[must_use]
    pub fn detection_rate(&self) -> f64 {
        if self.total_samples_scanned == 0 {
            return 0.0;
        }
        crate::casts::u64_to_f64(self.samples_matched) / crate::casts::u64_to_f64(self.total_samples_scanned)
    }

    /// Precision: TP / (TP + FP).
    #[must_use]
    pub fn precision(&self) -> f64 {
        let denom = self.true_positives + self.false_positives;
        if denom == 0 {
            return 0.0;
        }
        crate::casts::u64_to_f64(self.true_positives) / crate::casts::u64_to_f64(denom)
    }

    /// Recall: TP / (TP + FN).
    #[must_use]
    pub fn recall(&self) -> f64 {
        let denom = self.true_positives + self.false_negatives;
        if denom == 0 {
            return 0.0;
        }
        crate::casts::u64_to_f64(self.true_positives) / crate::casts::u64_to_f64(denom)
    }

    /// F1 score: harmonic mean of precision and recall.
    #[must_use]
    pub fn f1_score(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r < f64::EPSILON {
            return 0.0;
        }
        2.0 * p * r / (p + r)
    }

    /// Return `true` if this rule has never matched any sample.
    #[must_use]
    pub const fn is_unused(&self) -> bool {
        self.samples_matched == 0
    }

    /// Return `true` if this rule matches more than `threshold` fraction of
    /// benign samples (potential noisy rule).
    #[must_use]
    pub fn is_noisy(&self, threshold: f64) -> bool {
        let benign_total = self.true_negatives + self.false_positives;
        if benign_total == 0 {
            return false;
        }
        let fp_rate = crate::casts::u64_to_f64(self.false_positives) / crate::casts::u64_to_f64(benign_total);
        fp_rate > threshold
    }
}

// ── CoverageGap ───────────────────────────────────────────────────────────────

/// Represents a gap in coverage — samples that no rule matched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageGap {
    /// Ids of samples with no rule matches.
    pub uncovered_sample_ids: Vec<String>,
    /// Total number of uncovered samples.
    pub count: usize,
    /// Fraction of all scanned samples that are uncovered (0.0–1.0).
    pub gap_fraction: f64,
}

// ── OverallCoverageStats ──────────────────────────────────────────────────────

/// Aggregate coverage statistics across all rules and samples.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OverallCoverageStats {
    /// Total number of samples scanned.
    pub total_samples: u64,
    /// Samples covered by at least one rule.
    pub covered_samples: u64,
    /// Samples not covered by any rule.
    pub uncovered_samples: u64,
    /// Fraction of samples covered (0.0–1.0).
    pub coverage_fraction: f64,
    /// Total number of rules tracked.
    pub total_rules: usize,
    /// Number of unused rules (zero matches).
    pub unused_rules: usize,
    /// Number of rules considered noisy (high false-positive rate).
    pub noisy_rules: usize,
    /// Average detection rate across all rules.
    pub avg_detection_rate: f64,
    /// Average F1 score across rules that have ground-truth data.
    pub avg_f1_score: f64,
}

// ── RuleCoverageTracker ───────────────────────────────────────────────────────

/// Central tracker that aggregates match events from YARA scans and computes
/// per-rule and overall coverage metrics.
pub struct RuleCoverageTracker {
    /// Per-rule coverage records, keyed by `rule_id`.
    rule_coverage: BTreeMap<String, RuleCoverage>,
    /// Per-sample coverage records, keyed by `sample_id`.
    sample_coverage: BTreeMap<String, SampleCoverage>,
    /// Set of all rule ids that have been registered.
    registered_rules: HashSet<String>,
    /// Maximum number of matched sample ids to store per rule.
    max_tracked_per_rule: usize,
    /// Noise threshold for flagging rules (FP rate above which = noisy).
    pub noise_threshold: f64,
}

impl RuleCoverageTracker {
    /// Create a new tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rule_coverage: BTreeMap::new(),
            sample_coverage: BTreeMap::new(),
            registered_rules: HashSet::new(),
            max_tracked_per_rule: 200,
            noise_threshold: 0.05,
        }
    }

    /// Register a rule by id and name (required before recording hits).
    pub fn register_rule(&mut self, rule_id: impl Into<String>, rule_name: impl Into<String>) {
        let id = rule_id.into();
        let name = rule_name.into();
        self.registered_rules.insert(id.clone());
        self.rule_coverage
            .entry(id.clone())
            .or_insert_with(|| RuleCoverage::new(&id, &name));
    }

    /// Register multiple rules at once from a slice of (`rule_id`, `rule_name`).
    pub fn register_rules(&mut self, rules: &[(impl AsRef<str>, impl AsRef<str>)]) {
        for (id, name) in rules {
            self.register_rule(id.as_ref(), name.as_ref());
        }
    }

    // ── Recording hits ────────────────────────────────────────────────────────

    /// Record a complete scan result: for each rule that matched, increment
    /// its counters; for every registered rule that did NOT match, increment
    /// its miss counter.
    ///
    /// `matched_rule_ids` — set of rule ids that fired on this sample.
    /// `sample_id` — opaque identifier for the sample (e.g. hash or filename).
    /// `size_bytes` — size of the sample.
    /// `is_malicious` — optional ground-truth label.
    /// `string_matches` — optional per-rule string match counts.
    pub fn record_scan(
        &mut self,
        sample_id: impl Into<String>,
        size_bytes: u64,
        matched_rule_ids: &[impl AsRef<str>],
        is_malicious: Option<bool>,
        string_matches: Option<&HashMap<String, usize>>,
    ) {
        let sid = sample_id.into();
        let matched_set: HashSet<String> =
            matched_rule_ids.iter().map(|s| s.as_ref().to_owned()).collect();

        let total_string_matches: usize = string_matches
            .map_or(0, |m| m.values().sum());

        // Update sample coverage.
        let sample = self.sample_coverage.entry(sid.clone()).or_insert_with(|| {
            let mut s = SampleCoverage::new(&sid, size_bytes);
            s.is_malicious = is_malicious;
            s
        });
        for rid in &matched_set {
            if !sample.matched_rule_ids.contains(rid) {
                sample.matched_rule_ids.push(rid.clone());
            }
        }
        sample.total_string_matches += total_string_matches;

        // Update per-rule coverage.
        let registered = self.registered_rules.clone();
        for rule_id in registered {
            let matched = matched_set.contains(&rule_id);
            let cov = self.rule_coverage.entry(rule_id.clone()).or_insert_with(|| {
                RuleCoverage::new(&rule_id, &rule_id)
            });

            cov.total_samples_scanned += 1;
            cov.last_updated = SystemTime::now();

            if matched {
                cov.samples_matched += 1;
                if cov.matched_sample_ids.len() < self.max_tracked_per_rule {
                    cov.matched_sample_ids.push(sid.clone());
                }
                match is_malicious {
                    Some(true) => cov.true_positives += 1,
                    Some(false) => cov.false_positives += 1,
                    None => {}
                }
            } else {
                cov.samples_missed += 1;
                match is_malicious {
                    Some(false) => cov.true_negatives += 1,
                    Some(true) => {
                        cov.false_negatives += 1;
                        if cov.missed_malicious_sample_ids.len() < self.max_tracked_per_rule {
                            cov.missed_malicious_sample_ids.push(sid.clone());
                        }
                    }
                    None => {}
                }
            }
        }
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// Get the coverage record for a specific rule.
    #[must_use]
    pub fn rule_coverage(&self, rule_id: &str) -> Option<&RuleCoverage> {
        self.rule_coverage.get(rule_id)
    }

    /// Get the sample coverage for a specific sample.
    #[must_use]
    pub fn sample_coverage(&self, sample_id: &str) -> Option<&SampleCoverage> {
        self.sample_coverage.get(sample_id)
    }

    /// Iterate over all rule coverage records sorted by `rule_id`.
    pub fn all_rule_coverages(&self) -> impl Iterator<Item = &RuleCoverage> {
        self.rule_coverage.values()
    }

    /// Return all rules sorted by detection rate descending.
    #[must_use]
    pub fn rules_by_detection_rate(&self) -> Vec<&RuleCoverage> {
        let mut v: Vec<&RuleCoverage> = self.rule_coverage.values().collect();
        v.sort_unstable_by(|a, b| {
            b.detection_rate()
                .partial_cmp(&a.detection_rate())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v
    }

    /// Return all rules sorted by F1 score descending.
    #[must_use]
    pub fn rules_by_f1(&self) -> Vec<&RuleCoverage> {
        let mut v: Vec<&RuleCoverage> = self.rule_coverage.values().collect();
        v.sort_unstable_by(|a, b| {
            b.f1_score()
                .partial_cmp(&a.f1_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v
    }

    /// Return rules that have never matched any sample.
    #[must_use]
    pub fn unused_rules(&self) -> Vec<&RuleCoverage> {
        self.rule_coverage.values().filter(|r| r.is_unused()).collect()
    }

    /// Return rules with a false-positive rate exceeding [`Self::noise_threshold`].
    #[must_use]
    pub fn noisy_rules(&self) -> Vec<&RuleCoverage> {
        let threshold = self.noise_threshold;
        self.rule_coverage
            .values()
            .filter(|r| r.is_noisy(threshold))
            .collect()
    }

    /// Compute the coverage gap (samples not covered by any rule).
    #[must_use]
    pub fn coverage_gap(&self) -> CoverageGap {
        let uncovered: Vec<String> = self
            .sample_coverage
            .values()
            .filter(|s| !s.has_matches())
            .map(|s| s.sample_id.clone())
            .collect();

        let total = self.sample_coverage.len();
        let count = uncovered.len();
        let gap_fraction = if total == 0 {
            0.0
        } else {
            crate::casts::usize_to_f64(count) / crate::casts::usize_to_f64(total)
        };

        CoverageGap {
            uncovered_sample_ids: uncovered,
            count,
            gap_fraction,
        }
    }

    /// Compute overall coverage statistics.
    #[must_use]
    pub fn overall_stats(&self) -> OverallCoverageStats {
        let total_samples = self.sample_coverage.len() as u64;
        let covered_samples = self
            .sample_coverage
            .values()
            .filter(|s| s.has_matches())
            .count() as u64;
        let uncovered_samples = total_samples - covered_samples;
        let coverage_fraction = if total_samples == 0 {
            0.0
        } else {
            crate::casts::u64_to_f64(covered_samples) / crate::casts::u64_to_f64(total_samples)
        };

        let total_rules = self.rule_coverage.len();
        let unused_rules = self.rule_coverage.values().filter(|r| r.is_unused()).count();
        let noisy_rules = self.noisy_rules().len();

        let avg_detection_rate = if total_rules == 0 {
            0.0
        } else {
            let sum: f64 = self.rule_coverage.values().map(RuleCoverage::detection_rate).sum();
            sum / crate::casts::usize_to_f64(total_rules)
        };

        // F1 only meaningful for rules with ground-truth data.
        let f1_rules: Vec<f64> = self
            .rule_coverage
            .values()
            .filter(|r| r.true_positives + r.false_positives + r.true_negatives + r.false_negatives > 0)
            .map(RuleCoverage::f1_score)
            .collect();
        let avg_f1_score = if f1_rules.is_empty() {
            0.0
        } else {
            f1_rules.iter().sum::<f64>() / crate::casts::usize_to_f64(f1_rules.len())
        };

        OverallCoverageStats {
            total_samples,
            covered_samples,
            uncovered_samples,
            coverage_fraction,
            total_rules,
            unused_rules,
            noisy_rules,
            avg_detection_rate,
            avg_f1_score,
        }
    }

    // ── Reports ───────────────────────────────────────────────────────────────

    /// Generate a human-readable coverage report.
    #[must_use]
    pub fn report(&self) -> String {
        use std::fmt::Write as _;
        let stats = self.overall_stats();
        let mut out = String::new();
        let _ = write!(
            out,
            "YARA Rule Coverage Report\n\
             =========================\n\
             Samples scanned   : {}\n\
             Samples covered   : {} ({:.1}%)\n\
             Samples uncovered : {}\n\
             Rules tracked     : {}\n\
             Unused rules      : {}\n\
             Noisy rules       : {}\n\
             Avg detection rate: {:.1}%\n\
             Avg F1 score      : {:.3}\n\n",
            stats.total_samples,
            stats.covered_samples,
            stats.coverage_fraction * 100.0,
            stats.uncovered_samples,
            stats.total_rules,
            stats.unused_rules,
            stats.noisy_rules,
            stats.avg_detection_rate * 100.0,
            stats.avg_f1_score,
        );

        out.push_str("Top 10 Rules by Detection Rate:\n");
        for cov in self.rules_by_detection_rate().iter().take(10) {
            let _ = writeln!(
                out,
                "  {:<40} rate={:.1}% f1={:.3} tp={} fp={}",
                cov.rule_id,
                cov.detection_rate() * 100.0,
                cov.f1_score(),
                cov.true_positives,
                cov.false_positives,
            );
        }

        if !self.unused_rules().is_empty() {
            out.push_str("\nUnused Rules:\n");
            for cov in self.unused_rules() {
                let _ = writeln!(out, "  {}", cov.rule_id);
            }
        }

        out
    }

    // ── Merge ─────────────────────────────────────────────────────────────────

    /// Merge another tracker's data into this one.
    ///
    /// Rule and sample coverage counters are added together.
    pub fn merge(&mut self, other: &Self) {
        for (id, other_cov) in &other.rule_coverage {
            let cov = self.rule_coverage.entry(id.clone()).or_insert_with(|| {
                RuleCoverage::new(&other_cov.rule_id, &other_cov.rule_name)
            });
            cov.total_samples_scanned += other_cov.total_samples_scanned;
            cov.samples_matched += other_cov.samples_matched;
            cov.samples_missed += other_cov.samples_missed;
            cov.true_positives += other_cov.true_positives;
            cov.false_positives += other_cov.false_positives;
            cov.true_negatives += other_cov.true_negatives;
            cov.false_negatives += other_cov.false_negatives;
            for sid in &other_cov.matched_sample_ids {
                if cov.matched_sample_ids.len() < self.max_tracked_per_rule
                    && !cov.matched_sample_ids.contains(sid)
                {
                    cov.matched_sample_ids.push(sid.clone());
                }
            }
        }

        for (sid, other_sample) in &other.sample_coverage {
            self.sample_coverage
                .entry(sid.clone())
                .or_insert_with(|| other_sample.clone());
        }

        for id in &other.registered_rules {
            self.registered_rules.insert(id.clone());
        }
    }

    /// Reset all coverage counters while keeping rule registrations.
    pub fn reset_counts(&mut self) {
        for cov in self.rule_coverage.values_mut() {
            cov.total_samples_scanned = 0;
            cov.samples_matched = 0;
            cov.samples_missed = 0;
            cov.true_positives = 0;
            cov.false_positives = 0;
            cov.true_negatives = 0;
            cov.false_negatives = 0;
            cov.matched_sample_ids.clear();
            cov.missed_malicious_sample_ids.clear();
        }
        self.sample_coverage.clear();
    }
}

impl Default for RuleCoverageTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tracker() -> RuleCoverageTracker {
        let mut t = RuleCoverageTracker::new();
        t.register_rule("rule1", "DetectMalware1");
        t.register_rule("rule2", "DetectMalware2");
        t
    }

    #[test]
    fn register_and_record_basic() {
        let mut t = make_tracker();
        t.record_scan("sample1", 1024, &["rule1"], Some(true), None);
        let cov = t.rule_coverage("rule1").unwrap();
        assert_eq!(cov.samples_matched, 1);
        assert_eq!(cov.true_positives, 1);
    }

    #[test]
    fn miss_increments_correctly() {
        let mut t = make_tracker();
        t.record_scan("sample1", 1024, &["rule1"], Some(true), None);
        let cov = t.rule_coverage("rule2").unwrap();
        assert_eq!(cov.samples_missed, 1);
        assert_eq!(cov.false_negatives, 1);
    }

    #[test]
    fn detection_rate_correct() {
        let mut t = make_tracker();
        t.record_scan("s1", 100, &["rule1"], None, None);
        t.record_scan("s2", 100, &[] as &[&str], None, None);
        let cov = t.rule_coverage("rule1").unwrap();
        assert!((cov.detection_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn precision_and_recall() {
        let mut t = make_tracker();
        t.record_scan("s1", 100, &["rule1"], Some(true), None);
        t.record_scan("s2", 100, &["rule1"], Some(false), None);
        t.record_scan("s3", 100, &[] as &[&str], Some(true), None);
        let cov = t.rule_coverage("rule1").unwrap();
        assert!((cov.precision() - 0.5).abs() < f64::EPSILON);
        assert!((cov.recall() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn f1_score_zero_with_no_data() {
        let t = make_tracker();
        let cov = t.rule_coverage("rule1").unwrap();
        assert!(cov.f1_score().abs() < f64::EPSILON);
    }

    #[test]
    fn coverage_gap_found() {
        let mut t = make_tracker();
        t.record_scan("s1", 100, &["rule1"], None, None);
        t.record_scan("s2", 100, &[] as &[&str], None, None);
        let gap = t.coverage_gap();
        assert_eq!(gap.count, 1);
        assert_eq!(gap.uncovered_sample_ids[0], "s2");
    }

    #[test]
    fn overall_stats_counts_unused() {
        let mut t = make_tracker();
        t.record_scan("s1", 100, &["rule1"], None, None);
        let stats = t.overall_stats();
        assert_eq!(stats.unused_rules, 1); // rule2 never matched
        assert_eq!(stats.total_rules, 2);
    }

    #[test]
    fn is_unused_true_when_no_matches() {
        let t = make_tracker();
        let cov = t.rule_coverage("rule1").unwrap();
        assert!(cov.is_unused());
    }

    #[test]
    fn noisy_rule_detected() {
        let mut t = make_tracker();
        t.noise_threshold = 0.4;
        t.record_scan("s1", 100, &["rule1"], Some(false), None);
        t.record_scan("s2", 100, &["rule1"], Some(false), None);
        t.record_scan("s3", 100, &[] as &[&str], Some(false), None);
        let noisy = t.noisy_rules();
        assert!(!noisy.is_empty());
    }

    #[test]
    fn merge_combines_counts() {
        let mut t1 = make_tracker();
        let mut t2 = make_tracker();
        t1.record_scan("s1", 100, &["rule1"], Some(true), None);
        t2.record_scan("s2", 100, &["rule1"], Some(true), None);
        t1.merge(&t2);
        let cov = t1.rule_coverage("rule1").unwrap();
        assert_eq!(cov.samples_matched, 2);
    }

    #[test]
    fn reset_clears_counts() {
        let mut t = make_tracker();
        t.record_scan("s1", 100, &["rule1"], None, None);
        t.reset_counts();
        let cov = t.rule_coverage("rule1").unwrap();
        assert_eq!(cov.total_samples_scanned, 0);
        assert_eq!(cov.samples_matched, 0);
    }

    #[test]
    fn sample_coverage_tracked() {
        let mut t = make_tracker();
        t.record_scan("s1", 512, &["rule1", "rule2"], None, None);
        let sc = t.sample_coverage("s1").unwrap();
        assert_eq!(sc.match_count(), 2);
        assert_eq!(sc.size_bytes, 512);
    }

    #[test]
    fn rules_by_detection_rate_descending() {
        let mut t = make_tracker();
        t.record_scan("s1", 100, &["rule1"], None, None);
        t.record_scan("s2", 100, &["rule1"], None, None);
        // rule2 matches 0
        let sorted = t.rules_by_detection_rate();
        assert_eq!(sorted[0].rule_id, "rule1");
    }
}
