//! `result_aggregator` — merge results from parallel tasks, resolve conflicts,
//! compute consensus scores, track provenance, and generate combined reports.
//!
//! All types are `std`-only; no external crate dependencies.

use std::collections::HashMap;
use std::fmt;

use rustre_agent::casts::usize_to_f64;

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregatorError {
    EmptyInputs,
    ConflictUnresolvable { key: String },
    InvalidWeight { key: String },
    MissingProvenance(String),
}

impl fmt::Display for AggregatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInputs => write!(f, "no inputs provided for aggregation"),
            Self::ConflictUnresolvable { key } => {
                write!(f, "conflict for '{key}' could not be resolved")
            }
            Self::InvalidWeight { key } => write!(f, "invalid weight for source '{key}'"),
            Self::MissingProvenance(id) => write!(f, "provenance missing for finding '{id}'"),
        }
    }
}

// ── Finding ───────────────────────────────────────────────────────────────────

/// A single finding emitted by a task.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Unique identifier for this finding.
    pub id: String,
    /// Semantic category (e.g. "vulnerability", "symbol", "string", "xref").
    pub category: String,
    /// Human-readable description.
    pub description: String,
    /// Optional address in the binary.
    pub address: Option<u64>,
    /// Confidence score in [0.0, 1.0].
    pub confidence: f64,
    /// Raw evidence blob.
    pub evidence: Option<Vec<u8>>,
    /// Arbitrary key-value metadata.
    pub metadata: HashMap<String, String>,
    /// Source task identifier.
    pub source_task: String,
}

impl Finding {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        category: impl Into<String>,
        description: impl Into<String>,
        confidence: f64,
        source_task: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            category: category.into(),
            description: description.into(),
            address: None,
            confidence: confidence.clamp(0.0, 1.0),
            evidence: None,
            metadata: HashMap::new(),
            source_task: source_task.into(),
        }
    }

    #[must_use]
    pub const fn at_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    #[must_use]
    pub fn with_evidence(mut self, data: Vec<u8>) -> Self {
        self.evidence = Some(data);
        self
    }

    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), val.into());
        self
    }
}

// ── ProvenanceEntry ───────────────────────────────────────────────────────────

/// Tracks where a finding came from (which tasks and in what order).
#[derive(Debug, Clone)]
pub struct ProvenanceEntry {
    pub finding_id: String,
    /// Ordered list of (`task_id`, confidence) pairs that contributed this finding.
    pub contributors: Vec<(String, f64)>,
    pub merged_at_step: usize,
}

impl ProvenanceEntry {
    #[must_use]
    pub fn new(finding_id: impl Into<String>, step: usize) -> Self {
        Self {
            finding_id: finding_id.into(),
            contributors: Vec::new(),
            merged_at_step: step,
        }
    }

    pub fn add_contributor(&mut self, task_id: impl Into<String>, confidence: f64) {
        self.contributors.push((task_id.into(), confidence));
    }

    /// Number of distinct tasks that produced this finding.
    #[must_use]
    pub const fn contributor_count(&self) -> usize {
        self.contributors.len()
    }
}

// ── ProvenanceMap ─────────────────────────────────────────────────────────────

/// A collection of provenance entries indexed by finding id.
#[derive(Debug, Default, Clone)]
pub struct ProvenanceMap {
    entries: HashMap<String, ProvenanceEntry>,
    merge_step: usize,
}

impl ProvenanceMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `task_id` produced `finding_id` with `confidence`.
    pub fn record(
        &mut self,
        finding_id: impl Into<String>,
        task_id: impl Into<String>,
        confidence: f64,
    ) {
        let fid = finding_id.into();
        let entry = self
            .entries
            .entry(fid.clone())
            .or_insert_with(|| ProvenanceEntry::new(fid, self.merge_step));
        entry.add_contributor(task_id, confidence);
    }

    pub const fn advance_step(&mut self) {
        self.merge_step += 1;
    }

    #[must_use]
    pub fn get(&self, finding_id: &str) -> Option<&ProvenanceEntry> {
        self.entries.get(finding_id)
    }

    /// Return all finding ids that were contributed by more than one task.
    #[must_use]
    pub fn corroborated_findings(&self) -> Vec<&str> {
        self.entries
            .values()
            .filter(|e| e.contributor_count() > 1)
            .map(|e| e.finding_id.as_str())
            .collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── ConsensusScore ────────────────────────────────────────────────────────────

/// Aggregated confidence score for a merged finding.
#[derive(Debug, Clone)]
pub struct ConsensusScore {
    pub finding_id: String,
    /// Weighted average confidence across all contributing tasks.
    pub weighted_confidence: f64,
    /// Unweighted (arithmetic) average.
    pub mean_confidence: f64,
    /// Highest individual confidence from any single task.
    pub max_confidence: f64,
    /// Number of tasks that reported this finding.
    pub vote_count: usize,
}

impl ConsensusScore {
    #[must_use]
    pub fn from_contributions(
        finding_id: impl Into<String>,
        contributions: &[(f64, f64)], // (weight, confidence)
    ) -> Self {
        let fid = finding_id.into();
        if contributions.is_empty() {
            return Self {
                finding_id: fid,
                weighted_confidence: 0.0,
                mean_confidence: 0.0,
                max_confidence: 0.0,
                vote_count: 0,
            };
        }
        let total_weight: f64 = contributions.iter().map(|(w, _)| w).sum();
        let weighted_confidence = if total_weight > 0.0 {
            contributions
                .iter()
                .map(|(w, c)| w * c)
                .sum::<f64>()
                / total_weight
        } else {
            0.0
        };
        let mean_confidence =
            contributions.iter().map(|(_, c)| c).sum::<f64>() / usize_to_f64(contributions.len());
        let max_confidence = contributions
            .iter()
            .map(|(_, c)| *c)
            .fold(0.0_f64, f64::max);
        Self {
            finding_id: fid,
            weighted_confidence,
            mean_confidence,
            max_confidence,
            vote_count: contributions.len(),
        }
    }

    /// Returns true if consensus confidence exceeds the threshold.
    #[must_use]
    pub fn confident(&self, threshold: f64) -> bool {
        self.weighted_confidence >= threshold
    }
}

// ── ConflictResolutionPolicy ──────────────────────────────────────────────────

/// Strategy for resolving conflicting findings at the same address or with the same id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolutionPolicy {
    /// Keep the finding with the highest confidence.
    HighestConfidence,
    /// Keep all findings (no deduplication).
    KeepAll,
    /// Keep the finding from the first (highest-priority) task.
    FirstWins,
    /// Keep the finding from the last task.
    LastWins,
    /// Merge findings: combine descriptions, take max confidence.
    Merge,
}

// ── FindingMerger ─────────────────────────────────────────────────────────────

/// Merges findings from multiple tasks using a chosen conflict resolution policy.
pub struct FindingMerger {
    policy: ConflictResolutionPolicy,
    /// Source weights: `task_id` → weight multiplier.
    weights: HashMap<String, f64>,
}

impl FindingMerger {
    #[must_use]
    pub fn new(policy: ConflictResolutionPolicy) -> Self {
        Self {
            policy,
            weights: HashMap::new(),
        }
    }

    pub fn set_weight(&mut self, task_id: impl Into<String>, weight: f64) {
        self.weights.insert(task_id.into(), weight.max(0.0));
    }

    #[must_use]
    pub fn weight_for(&self, task_id: &str) -> f64 {
        self.weights.get(task_id).copied().unwrap_or(1.0)
    }

    /// Merge a flat list of findings from multiple tasks.
    /// Findings are grouped by `id`; within each group, the policy is applied.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    #[must_use]
    pub fn merge(&self, findings: Vec<Finding>) -> Vec<Finding> {
        match self.policy {
            ConflictResolutionPolicy::KeepAll => findings,
            ConflictResolutionPolicy::HighestConfidence => {
                Self::dedup_by(findings, |group| {
                    group
                        .into_iter()
                        .max_by(|a, b| {
                            let wa = self.weight_for(&a.source_task) * a.confidence;
                            let wb = self.weight_for(&b.source_task) * b.confidence;
                            wa.partial_cmp(&wb).unwrap_or(std::cmp::Ordering::Equal)
                        })
                        .unwrap()
                })
            }
            ConflictResolutionPolicy::FirstWins => {
                Self::dedup_by(findings, |mut group| {
                    group.swap(0, 0); // already first
                    group.remove(0)
                })
            }
            ConflictResolutionPolicy::LastWins => {
                Self::dedup_by(findings, |mut group| {
                    group.pop().unwrap()
                })
            }
            ConflictResolutionPolicy::Merge => {
                Self::dedup_by(findings, |group| {
                    let mut merged = group[0].clone();
                    for other in &group[1..] {
                        if other.confidence > merged.confidence {
                            merged.confidence = other.confidence;
                        }
                        // Append description from other if different.
                        if !merged.description.contains(&other.description) {
                            merged.description = format!(
                                "{}; {}",
                                merged.description, other.description
                            );
                        }
                        // Merge metadata.
                        for (k, v) in &other.metadata {
                            merged.metadata.entry(k.clone()).or_insert_with(|| v.clone());
                        }
                    }
                    merged
                })
            }
        }
    }

    fn dedup_by(
        findings: Vec<Finding>,
        reducer: impl Fn(Vec<Finding>) -> Finding,
    ) -> Vec<Finding> {
        let mut groups: Vec<(String, Vec<Finding>)> = Vec::new();
        let mut idx: HashMap<String, usize> = HashMap::new();
        for f in findings {
            if let Some(&pos) = idx.get(&f.id) {
                groups[pos].1.push(f);
            } else {
                idx.insert(f.id.clone(), groups.len());
                let id = f.id.clone();
                groups.push((id, vec![f]));
            }
        }
        groups
            .into_iter()
            .map(|(_, group)| reducer(group))
            .collect()
    }
}

// ── AggregatedResult ──────────────────────────────────────────────────────────

/// The merged output of multiple parallel tasks.
#[derive(Debug, Default, Clone)]
pub struct AggregatedResult {
    pub run_id: String,
    pub findings: Vec<Finding>,
    pub consensus_scores: Vec<ConsensusScore>,
    pub provenance: ProvenanceMap,
    pub task_count: usize,
    /// Per-task summary: `task_id` → (succeeded, `finding_count`, `elapsed_ms`).
    pub task_summaries: Vec<TaskSummary>,
    pub errors: Vec<(String, String)>, // (task_id, error_message)
}

#[derive(Debug, Clone)]
pub struct TaskSummary {
    pub task_id: String,
    pub succeeded: bool,
    pub finding_count: usize,
    pub elapsed_ms: u64,
}

impl AggregatedResult {
    #[must_use]
    pub fn new(run_id: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn findings_by_category(&self, category: &str) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.category == category)
            .collect()
    }

    #[must_use]
    pub fn findings_above_confidence(&self, threshold: f64) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.confidence >= threshold)
            .collect()
    }

    #[must_use]
    pub const fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.task_count == 0 {
            return 0.0;
        }
        let ok = self.task_summaries.iter().filter(|s| s.succeeded).count();
        usize_to_f64(ok) / usize_to_f64(self.task_count)
    }
}

// ── CombinedReport ────────────────────────────────────────────────────────────

/// Formatted combined report from aggregated results.
#[derive(Debug, Clone)]
pub struct CombinedReport {
    pub run_id: String,
    pub title: String,
    pub sections: Vec<ReportSection>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ReportSection {
    pub heading: String,
    pub lines: Vec<String>,
}

impl ReportSection {
    #[must_use]
    pub fn new(heading: impl Into<String>) -> Self {
        Self {
            heading: heading.into(),
            lines: Vec::new(),
        }
    }
    pub fn push(&mut self, line: impl Into<String>) {
        self.lines.push(line.into());
    }
}

impl CombinedReport {
    #[must_use]
    pub fn new(run_id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            title: title.into(),
            sections: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn add_section(&mut self, section: ReportSection) {
        self.sections.push(section);
    }

    pub fn set_meta(&mut self, key: impl Into<String>, val: impl Into<String>) {
        self.metadata.insert(key.into(), val.into());
    }

    /// Render the report as a human-readable string.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        writeln!(out, "=== {} ===", self.title).unwrap();
        writeln!(out, "Run ID: {}", self.run_id).unwrap();
        for (k, v) in &self.metadata {
            writeln!(out, "{k}: {v}").unwrap();
        }
        writeln!(out).unwrap();
        for section in &self.sections {
            writeln!(out, "--- {} ---", section.heading).unwrap();
            for line in &section.lines {
                writeln!(out, "  {line}").unwrap();
            }
            writeln!(out).unwrap();
        }
        out
    }
}

// ── ResultAggregator ──────────────────────────────────────────────────────────

/// Collects task outputs and builds an `AggregatedResult`.
pub struct ResultAggregator {
    run_id: String,
    merger: FindingMerger,
    confidence_threshold: f64,
    /// Collected (`task_id`, findings, `elapsed_ms`, error).
    tasks: Vec<(String, Vec<Finding>, u64, Option<String>)>,
}

impl ResultAggregator {
    #[must_use]
    pub fn new(
        run_id: impl Into<String>,
        policy: ConflictResolutionPolicy,
        confidence_threshold: f64,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            merger: FindingMerger::new(policy),
            confidence_threshold: confidence_threshold.clamp(0.0, 1.0),
            tasks: Vec::new(),
        }
    }

    pub fn set_source_weight(&mut self, task_id: impl Into<String>, weight: f64) {
        self.merger.set_weight(task_id, weight);
    }

    /// Record findings from a successful task.
    pub fn add_task_result(
        &mut self,
        task_id: impl Into<String>,
        findings: Vec<Finding>,
        elapsed_ms: u64,
    ) {
        self.tasks
            .push((task_id.into(), findings, elapsed_ms, None));
    }

    /// Record a task failure.
    pub fn add_task_error(
        &mut self,
        task_id: impl Into<String>,
        error: impl Into<String>,
        elapsed_ms: u64,
    ) {
        self.tasks
            .push((task_id.into(), Vec::new(), elapsed_ms, Some(error.into())));
    }

    /// Run the aggregation and return the merged result.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn aggregate(&self) -> Result<AggregatedResult, AggregatorError> {
        let mut result = AggregatedResult::new(self.run_id.clone());
        result.task_count = self.tasks.len();

        if self.tasks.is_empty() {
            return Err(AggregatorError::EmptyInputs);
        }

        let mut all_findings: Vec<Finding> = Vec::new();
        let mut prov = ProvenanceMap::new();

        for (task_id, findings, elapsed_ms, error) in &self.tasks {
            if let Some(err) = error {
                result.errors.push((task_id.clone(), err.clone()));
                result.task_summaries.push(TaskSummary {
                    task_id: task_id.clone(),
                    succeeded: false,
                    finding_count: 0,
                    elapsed_ms: *elapsed_ms,
                });
                continue;
            }

            result.task_summaries.push(TaskSummary {
                task_id: task_id.clone(),
                succeeded: true,
                finding_count: findings.len(),
                elapsed_ms: *elapsed_ms,
            });

            for f in findings {
                prov.record(f.id.clone(), task_id.clone(), f.confidence);
                all_findings.push(f.clone());
            }
            prov.advance_step();
        }

        // Merge findings according to policy.
        let merged = self.merger.merge(all_findings);

        // Compute consensus scores for merged findings.
        let mut consensus: Vec<ConsensusScore> = Vec::new();
        for f in &merged {
            if let Some(prov_entry) = prov.get(&f.id) {
                let contributions: Vec<(f64, f64)> = prov_entry
                    .contributors
                    .iter()
                    .map(|(tid, conf)| (self.merger.weight_for(tid), *conf))
                    .collect();
                consensus.push(ConsensusScore::from_contributions(
                    f.id.clone(),
                    &contributions,
                ));
            }
        }

        result.findings = merged;
        result.consensus_scores = consensus;
        result.provenance = prov;
        Ok(result)
    }

    /// Build a formatted combined report from the aggregated result.
    #[must_use]
    pub fn build_report(
        &self,
        result: &AggregatedResult,
    ) -> CombinedReport {
        let mut report = CombinedReport::new(result.run_id.clone(), "Combined RE Analysis Report");
        report.set_meta("task_count", result.task_count.to_string());
        report.set_meta(
            "success_rate",
            format!("{:.1}%", result.success_rate() * 100.0),
        );
        report.set_meta("finding_count", result.findings.len().to_string());

        // Summary section.
        let mut summary = ReportSection::new("Summary");
        summary.push(format!("Tasks executed: {}", result.task_count));
        summary.push(format!("Findings: {}", result.findings.len()));
        summary.push(format!(
            "Errors: {}",
            result.errors.len()
        ));
        summary.push(format!(
            "Success rate: {:.1}%",
            result.success_rate() * 100.0
        ));
        report.add_section(summary);

        // Findings by category.
        let mut categories: Vec<String> = result
            .findings
            .iter()
            .map(|f| f.category.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        categories.sort();

        for cat in &categories {
            let mut sec = ReportSection::new(format!("Findings: {cat}"));
            let cat_findings = result.findings_by_category(cat);
            for f in &cat_findings {
                let addr = f
                    .address
                    .map_or_else(|| "N/A".to_string(), |a| format!("{a:#x}"));
                sec.push(format!(
                    "[{:.2}] {} @ {} — {}",
                    f.confidence, f.id, addr, f.description
                ));
            }
            report.add_section(sec);
        }

        // High-confidence findings.
        let high = result.findings_above_confidence(self.confidence_threshold);
        if !high.is_empty() {
            let mut sec = ReportSection::new(format!(
                "High-Confidence Findings (≥{:.0}%)",
                self.confidence_threshold * 100.0
            ));
            for f in &high {
                sec.push(format!("{} — {:.2} confidence", f.id, f.confidence));
            }
            report.add_section(sec);
        }

        // Corroborated findings.
        let corroborated = result.provenance.corroborated_findings();
        if !corroborated.is_empty() {
            let mut sec = ReportSection::new("Corroborated Findings (multiple sources)");
            for fid in &corroborated {
                sec.push(format!("  {fid}"));
            }
            report.add_section(sec);
        }

        // Error section.
        if !result.errors.is_empty() {
            let mut sec = ReportSection::new("Task Errors");
            for (tid, err) in &result.errors {
                sec.push(format!("{tid}: {err}"));
            }
            report.add_section(sec);
        }

        report
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(id: &str, cat: &str, conf: f64, task: &str) -> Finding {
        Finding::new(id, cat, format!("desc for {id}"), conf, task)
    }

    // ── Finding ───────────────────────────────────────────────────────────────

    #[test]
    fn finding_clamps_confidence() {
        let f = Finding::new("f1", "vuln", "d", 2.5, "t");
        assert!(f.confidence <= 1.0);
    }

    #[test]
    fn finding_at_address() {
        let f = Finding::new("f1", "c", "d", 0.9, "t").at_address(0x1000);
        assert_eq!(f.address, Some(0x1000));
    }

    #[test]
    fn finding_with_meta() {
        let f = Finding::new("f1", "c", "d", 0.8, "t").with_meta("key", "val");
        assert_eq!(f.metadata.get("key").map(String::as_str), Some("val"));
    }

    // ── ProvenanceMap ─────────────────────────────────────────────────────────

    #[test]
    fn provenance_records_contributor() {
        let mut p = ProvenanceMap::new();
        p.record("f1", "task-a", 0.9);
        p.record("f1", "task-b", 0.8);
        let e = p.get("f1").unwrap();
        assert_eq!(e.contributor_count(), 2);
    }

    #[test]
    fn provenance_corroborated() {
        let mut p = ProvenanceMap::new();
        p.record("f1", "t1", 0.9);
        p.record("f1", "t2", 0.8);
        p.record("f2", "t1", 0.7);
        let c = p.corroborated_findings();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0], "f1");
    }

    // ── ConsensusScore ────────────────────────────────────────────────────────

    #[test]
    fn consensus_equal_weights() {
        let contributions = vec![(1.0, 0.8), (1.0, 0.6)];
        let s = ConsensusScore::from_contributions("f1", &contributions);
        assert!((s.weighted_confidence - 0.7).abs() < 1e-9);
        assert!((s.mean_confidence - 0.7).abs() < 1e-9);
        assert_eq!(s.vote_count, 2);
    }

    #[test]
    fn consensus_weighted() {
        let contributions = vec![(2.0, 0.9), (1.0, 0.6)];
        let s = ConsensusScore::from_contributions("f1", &contributions);
        // (2*0.9 + 1*0.6) / 3 = 0.8
        assert!((s.weighted_confidence - 0.8).abs() < 1e-9);
    }

    #[test]
    fn consensus_empty() {
        let s = ConsensusScore::from_contributions("f1", &[]);
        assert_eq!(s.vote_count, 0);
        assert!(s.weighted_confidence.abs() < f64::EPSILON);
    }

    #[test]
    fn consensus_confident() {
        let s = ConsensusScore::from_contributions("f1", &[(1.0, 0.85)]);
        assert!(s.confident(0.8));
        assert!(!s.confident(0.9));
    }

    // ── FindingMerger ─────────────────────────────────────────────────────────

    #[test]
    fn merger_keep_all() {
        let m = FindingMerger::new(ConflictResolutionPolicy::KeepAll);
        let f1 = make_finding("f1", "vuln", 0.9, "t1");
        let f2 = make_finding("f1", "vuln", 0.7, "t2"); // same id
        let merged = m.merge(vec![f1, f2]);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn merger_highest_confidence() {
        let m = FindingMerger::new(ConflictResolutionPolicy::HighestConfidence);
        let f1 = make_finding("f1", "vuln", 0.9, "t1");
        let f2 = make_finding("f1", "vuln", 0.7, "t2");
        let merged = m.merge(vec![f1, f2]);
        assert_eq!(merged.len(), 1);
        assert!((merged[0].confidence - 0.9).abs() < 1e-9);
    }

    #[test]
    fn merger_first_wins() {
        let m = FindingMerger::new(ConflictResolutionPolicy::FirstWins);
        let f1 = make_finding("f1", "vuln", 0.5, "t1");
        let f2 = make_finding("f1", "vuln", 0.9, "t2");
        let merged = m.merge(vec![f1, f2]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].source_task, "t1");
    }

    #[test]
    fn merger_last_wins() {
        let m = FindingMerger::new(ConflictResolutionPolicy::LastWins);
        let f1 = make_finding("f1", "vuln", 0.5, "t1");
        let f2 = make_finding("f1", "vuln", 0.9, "t2");
        let merged = m.merge(vec![f1, f2]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].source_task, "t2");
    }

    #[test]
    fn merger_merge_policy() {
        let m = FindingMerger::new(ConflictResolutionPolicy::Merge);
        let f1 = make_finding("f1", "vuln", 0.6, "t1");
        let f2 = make_finding("f1", "vuln", 0.9, "t2");
        let merged = m.merge(vec![f1, f2]);
        assert_eq!(merged.len(), 1);
        // Merge takes max confidence.
        assert!((merged[0].confidence - 0.9).abs() < 1e-9);
    }

    #[test]
    fn merger_dedup_distinct_ids() {
        let m = FindingMerger::new(ConflictResolutionPolicy::HighestConfidence);
        let f1 = make_finding("f1", "vuln", 0.9, "t1");
        let f2 = make_finding("f2", "sym", 0.8, "t2");
        let merged = m.merge(vec![f1, f2]);
        assert_eq!(merged.len(), 2);
    }

    // ── ResultAggregator ──────────────────────────────────────────────────────

    #[test]
    fn aggregator_empty_fails() {
        let agg = ResultAggregator::new("r1", ConflictResolutionPolicy::HighestConfidence, 0.7);
        let err = agg.aggregate().unwrap_err();
        assert_eq!(err, AggregatorError::EmptyInputs);
    }

    #[test]
    fn aggregator_single_task() {
        let mut agg =
            ResultAggregator::new("r1", ConflictResolutionPolicy::HighestConfidence, 0.7);
        agg.add_task_result(
            "task-a",
            vec![make_finding("f1", "vuln", 0.9, "task-a")],
            100,
        );
        let result = agg.aggregate().unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.task_count, 1);
        assert!(!result.has_errors());
    }

    #[test]
    fn aggregator_merges_two_tasks() {
        let mut agg = ResultAggregator::new("r1", ConflictResolutionPolicy::HighestConfidence, 0.5);
        agg.add_task_result(
            "t1",
            vec![
                make_finding("f1", "vuln", 0.9, "t1"),
                make_finding("f2", "sym", 0.8, "t1"),
            ],
            100,
        );
        agg.add_task_result(
            "t2",
            vec![
                make_finding("f1", "vuln", 0.7, "t2"), // duplicate id
                make_finding("f3", "str", 0.6, "t2"),
            ],
            80,
        );
        let result = agg.aggregate().unwrap();
        // f1 deduped to highest confidence, f2 and f3 unique = 3 total
        assert_eq!(result.findings.len(), 3);
    }

    #[test]
    fn aggregator_error_task() {
        let mut agg = ResultAggregator::new("r1", ConflictResolutionPolicy::KeepAll, 0.5);
        agg.add_task_result("t1", vec![make_finding("f1", "v", 0.9, "t1")], 50);
        agg.add_task_error("t2", "connection refused", 10);
        let result = agg.aggregate().unwrap();
        assert!(result.has_errors());
        assert_eq!(result.errors[0].0, "t2");
        assert_eq!(result.task_count, 2);
    }

    #[test]
    fn aggregator_provenance_tracked() {
        let mut agg = ResultAggregator::new("r1", ConflictResolutionPolicy::KeepAll, 0.5);
        agg.add_task_result(
            "t1",
            vec![make_finding("f1", "v", 0.9, "t1")],
            50,
        );
        agg.add_task_result(
            "t2",
            vec![make_finding("f1", "v", 0.8, "t2")],
            40,
        );
        let result = agg.aggregate().unwrap();
        let corr = result.provenance.corroborated_findings();
        assert!(corr.contains(&"f1"));
    }

    #[test]
    fn aggregator_success_rate() {
        let mut agg = ResultAggregator::new("r1", ConflictResolutionPolicy::KeepAll, 0.5);
        agg.add_task_result("t1", vec![], 10);
        agg.add_task_error("t2", "err", 5);
        let result = agg.aggregate().unwrap();
        assert!((result.success_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn report_renders_without_panic() {
        let mut agg = ResultAggregator::new("run-1", ConflictResolutionPolicy::HighestConfidence, 0.6);
        agg.add_task_result(
            "analyzer",
            vec![
                make_finding("v1", "vulnerability", 0.9, "analyzer"),
                make_finding("s1", "symbol", 0.75, "analyzer"),
            ],
            200,
        );
        agg.add_task_error("scanner", "timeout", 1000);
        let result = agg.aggregate().unwrap();
        let report = agg.build_report(&result);
        let rendered = report.render();
        assert!(rendered.contains("Combined RE Analysis Report"));
        assert!(rendered.contains("run-1"));
        assert!(rendered.contains("vulnerability") || rendered.contains("symbol"));
    }

    #[test]
    fn combined_report_sections() {
        let mut report = CombinedReport::new("r", "Test Report");
        let mut sec = ReportSection::new("Section A");
        sec.push("line 1");
        sec.push("line 2");
        report.add_section(sec);
        let rendered = report.render();
        assert!(rendered.contains("Section A"));
        assert!(rendered.contains("line 1"));
        assert!(rendered.contains("line 2"));
    }
}
