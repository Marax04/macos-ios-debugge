// rustre-yara-rules/src/rule_testing.rs
// YARA rule testing framework: corpus-based testing, false-positive detection,
// performance benchmarking, and quality scoring.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::{RuleMeta, Severity};

// ─── Test Sample ─────────────────────────────────────────────────────────────

/// Classification label for a test sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SampleLabel {
    /// Should match the rule under test (true positive).
    Malicious,
    /// Should NOT match the rule under test (benign/clean).
    Benign,
    /// Unknown — collect match data but do not score.
    Unknown,
}

impl SampleLabel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malicious => "malicious",
            Self::Benign => "benign",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for SampleLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single test sample used in a rule corpus test.
#[derive(Debug, Clone)]
pub struct TestSample {
    /// Human-readable name or file path.
    pub name: String,
    /// Raw bytes of the sample.
    pub data: Vec<u8>,
    /// Expected classification.
    pub label: SampleLabel,
    /// Optional SHA-256 hex hash (used for deduplication).
    pub sha256: Option<String>,
    /// Optional family tag for grouping.
    pub family: Option<String>,
}

impl TestSample {
    /// Create a new in-memory sample.
    #[must_use]
    pub fn new(name: impl Into<String>, data: Vec<u8>, label: SampleLabel) -> Self {
        Self {
            name: name.into(),
            data,
            label,
            sha256: None,
            family: None,
        }
    }

    /// Create a sample from a file path.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read.
    pub fn from_file(path: &Path, label: SampleLabel) -> anyhow::Result<Self> {
        let data = std::fs::read(path)?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        Ok(Self::new(name, data, label))
    }

    /// Compute a simple FNV-based "hash" for quick comparison (not crypto-grade).
    #[must_use]
    pub fn fast_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in &self.data {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }

    /// Return the size in bytes.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.data.len()
    }
}

// ─── Test Result Per Sample ───────────────────────────────────────────────────

/// Outcome of testing one rule against one sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleTestResult {
    /// Sample name.
    pub sample_name: String,
    /// Expected label.
    pub expected: String,
    /// Whether the rule matched.
    pub matched: bool,
    /// Number of string matches found.
    pub match_count: usize,
    /// Offsets of first few matches (up to 8).
    pub match_offsets: Vec<u64>,
    /// Scan duration.
    pub scan_duration_us: u64,
    /// True positive / false positive / true negative / false negative classification.
    pub verdict: TestVerdict,
}

/// TP/FP/TN/FN classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestVerdict {
    /// Malicious sample matched the rule — correct detection.
    TruePositive,
    /// Benign sample matched the rule — false alarm.
    FalsePositive,
    /// Benign sample did not match — correct non-detection.
    TrueNegative,
    /// Malicious sample did not match — missed detection.
    FalseNegative,
    /// Unknown sample — collected but not scored.
    Informational,
}

impl TestVerdict {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TruePositive => "TP",
            Self::FalsePositive => "FP",
            Self::TrueNegative => "TN",
            Self::FalseNegative => "FN",
            Self::Informational => "INFO",
        }
    }
}

impl std::fmt::Display for TestVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Corpus Test Report ───────────────────────────────────────────────────────

/// Aggregated result from running a rule against a full corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusTestReport {
    /// Rule ID that was tested.
    pub rule_id: String,
    /// Rule name.
    pub rule_name: String,
    /// Per-sample results.
    pub sample_results: Vec<SampleTestResult>,
    /// Total true positives.
    pub true_positives: usize,
    /// Total false positives.
    pub false_positives: usize,
    /// Total true negatives.
    pub true_negatives: usize,
    /// Total false negatives.
    pub false_negatives: usize,
    /// Total informational (unknown) samples.
    pub informational: usize,
    /// Detection rate in `[0.0, 1.0]`.
    pub detection_rate: f64,
    /// False positive rate in `[0.0, 1.0]`.
    pub fp_rate: f64,
    /// F1 score.
    pub f1_score: f64,
    /// Total corpus scan time.
    pub total_scan_time_ms: u64,
    /// Quality score in `[0.0, 100.0]`.
    pub quality_score: f64,
}

impl CorpusTestReport {
    /// Compute derived metrics from the raw TP/FP/TN/FN counts.
    fn compute_metrics(&mut self) {
        let positives = self.true_positives + self.false_negatives;
        let negatives = self.true_negatives + self.false_positives;

        self.detection_rate = if positives == 0 {
            0.0
        } else {
            crate::casts::usize_to_f64(self.true_positives) / crate::casts::usize_to_f64(positives)
        };

        self.fp_rate = if negatives == 0 {
            0.0
        } else {
            crate::casts::usize_to_f64(self.false_positives) / crate::casts::usize_to_f64(negatives)
        };

        // F1 = 2 * TP / (2*TP + FP + FN)
        let denom = 2 * self.true_positives + self.false_positives + self.false_negatives;
        self.f1_score = if denom == 0 {
            0.0
        } else {
            2.0 * crate::casts::usize_to_f64(self.true_positives) / crate::casts::usize_to_f64(denom)
        };

        // Quality score: balanced combination of detection rate and inverse FP rate.
        // Higher detection rate and lower FP rate → higher quality.
        let inv_fp = 1.0 - self.fp_rate;
        self.quality_score = self.detection_rate.mul_add(0.6, inv_fp * 0.4) * 100.0;
    }

    /// Return a summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Rule '{}': DR={:.1}% FPR={:.1}% F1={:.3} Quality={:.1}/100 (TP={} FP={} TN={} FN={})",
            self.rule_name,
            self.detection_rate * 100.0,
            self.fp_rate * 100.0,
            self.f1_score,
            self.quality_score,
            self.true_positives,
            self.false_positives,
            self.true_negatives,
            self.false_negatives,
        )
    }

    /// Return `true` if the rule passes basic quality thresholds.
    #[must_use]
    pub fn passes_quality_threshold(&self, min_dr: f64, max_fpr: f64) -> bool {
        self.detection_rate >= min_dr && self.fp_rate <= max_fpr
    }

    /// Return only false positive samples.
    #[must_use]
    pub fn false_positive_samples(&self) -> Vec<&SampleTestResult> {
        self.sample_results
            .iter()
            .filter(|r| r.verdict == TestVerdict::FalsePositive)
            .collect()
    }

    /// Return only false negative samples.
    #[must_use]
    pub fn false_negative_samples(&self) -> Vec<&SampleTestResult> {
        self.sample_results
            .iter()
            .filter(|r| r.verdict == TestVerdict::FalseNegative)
            .collect()
    }
}

// ─── Rule Tester ──────────────────────────────────────────────────────────────

/// Configuration for the rule tester.
#[derive(Debug, Clone)]
pub struct TesterConfig {
    /// Minimum detection rate to pass.
    pub min_detection_rate: f64,
    /// Maximum false positive rate to pass.
    pub max_fp_rate: f64,
    /// Maximum scan time per sample (microseconds). 0 = no limit.
    pub max_scan_time_us: u64,
    /// Number of benchmark iterations per sample.
    pub benchmark_iterations: u32,
    /// Whether to skip samples larger than this (bytes). 0 = no limit.
    pub max_sample_size: usize,
}

impl Default for TesterConfig {
    fn default() -> Self {
        Self {
            min_detection_rate: 0.80,
            max_fp_rate: 0.01,
            max_scan_time_us: 500_000, // 500 ms
            benchmark_iterations: 3,
            max_sample_size: 64 * 1024 * 1024, // 64 MB
        }
    }
}

/// Corpus-based YARA rule tester.
pub struct RuleTester {
    config: TesterConfig,
    corpus: Vec<TestSample>,
}

impl RuleTester {
    /// Create a new tester with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: TesterConfig::default(),
            corpus: Vec::new(),
        }
    }

    /// Create a tester with custom configuration.
    #[must_use]
    pub const fn with_config(config: TesterConfig) -> Self {
        Self {
            config,
            corpus: Vec::new(),
        }
    }

    /// Add a sample to the corpus.
    pub fn add_sample(&mut self, sample: TestSample) {
        self.corpus.push(sample);
    }

    /// Add multiple samples at once.
    pub fn add_samples(&mut self, samples: impl IntoIterator<Item = TestSample>) {
        self.corpus.extend(samples);
    }

    /// Load all samples from a directory. Files in `malicious_dir` are labeled
    /// `Malicious`; files in `benign_dir` are labeled `Benign`.
    ///
    /// # Errors
    /// Returns an error if either directory cannot be read.
    pub fn load_corpus_from_dirs(
        &mut self,
        malicious_dir: &Path,
        benign_dir: &Path,
    ) -> anyhow::Result<usize> {
        let mut count = 0usize;
        for dir_label in [(malicious_dir, SampleLabel::Malicious), (benign_dir, SampleLabel::Benign)] {
            let (dir, label) = dir_label;
            if !dir.exists() {
                continue;
            }
            for entry in std::fs::read_dir(dir)?.flatten() {
                let path = entry.path();
                if path.is_file()
                    && let Ok(sample) = TestSample::from_file(&path, label)
                        && (self.config.max_sample_size == 0
                            || sample.size() <= self.config.max_sample_size)
                        {
                            self.corpus.push(sample);
                            count += 1;
                        }
            }
        }
        Ok(count)
    }

    /// Clear the corpus.
    pub fn clear_corpus(&mut self) {
        self.corpus.clear();
    }

    /// Return the number of samples in the corpus.
    #[must_use]
    pub const fn corpus_size(&self) -> usize {
        self.corpus.len()
    }

    /// Run the rule against all corpus samples and return a [`CorpusTestReport`].
    ///
    /// Uses a simple byte-pattern scanner since we do not link `libyara` directly.
    #[must_use]
    pub fn test_rule(&self, rule_text: &str, meta: &RuleMeta) -> CorpusTestReport {
        let patterns = extract_hex_patterns(rule_text);
        let string_patterns = extract_string_patterns(rule_text);

        let mut report = CorpusTestReport {
            rule_id: meta.rule_id.clone(),
            rule_name: meta.name.clone(),
            sample_results: Vec::with_capacity(self.corpus.len()),
            true_positives: 0,
            false_positives: 0,
            true_negatives: 0,
            false_negatives: 0,
            informational: 0,
            detection_rate: 0.0,
            fp_rate: 0.0,
            f1_score: 0.0,
            total_scan_time_ms: 0,
            quality_score: 0.0,
        };

        let mut total_time = Duration::ZERO;

        for sample in &self.corpus {
            if self.config.max_sample_size > 0 && sample.size() > self.config.max_sample_size {
                continue;
            }
            let start = Instant::now();
            let (matched, match_count, match_offsets) =
                scan_sample(&sample.data, &patterns, &string_patterns);
            let elapsed = start.elapsed();
            total_time += elapsed;
            let scan_us = crate::casts::u128_to_u64_sat(elapsed.as_micros());

            let verdict = match (sample.label, matched) {
                (SampleLabel::Malicious, true) => TestVerdict::TruePositive,
                (SampleLabel::Benign, true) => TestVerdict::FalsePositive,
                (SampleLabel::Benign, false) => TestVerdict::TrueNegative,
                (SampleLabel::Malicious, false) => TestVerdict::FalseNegative,
                (SampleLabel::Unknown, _) => TestVerdict::Informational,
            };

            match verdict {
                TestVerdict::TruePositive => report.true_positives += 1,
                TestVerdict::FalsePositive => report.false_positives += 1,
                TestVerdict::TrueNegative => report.true_negatives += 1,
                TestVerdict::FalseNegative => report.false_negatives += 1,
                TestVerdict::Informational => report.informational += 1,
            }

            report.sample_results.push(SampleTestResult {
                sample_name: sample.name.clone(),
                expected: sample.label.as_str().to_string(),
                matched,
                match_count,
                match_offsets,
                scan_duration_us: scan_us,
                verdict,
            });
        }

        report.total_scan_time_ms = crate::casts::u128_to_u64_sat(total_time.as_millis());
        report.compute_metrics();
        report
    }

    /// Test a rule against a single sample (quick API).
    #[must_use]
    pub fn test_single(
        &self,
        rule_text: &str,
        sample: &TestSample,
    ) -> SampleTestResult {
        let patterns = extract_hex_patterns(rule_text);
        let string_patterns = extract_string_patterns(rule_text);

        let start = Instant::now();
        let (matched, match_count, match_offsets) =
            scan_sample(&sample.data, &patterns, &string_patterns);
        let elapsed = start.elapsed();

        let verdict = match (sample.label, matched) {
            (SampleLabel::Malicious, true) => TestVerdict::TruePositive,
            (SampleLabel::Benign, true) => TestVerdict::FalsePositive,
            (SampleLabel::Benign, false) => TestVerdict::TrueNegative,
            (SampleLabel::Malicious, false) => TestVerdict::FalseNegative,
            (SampleLabel::Unknown, _) => TestVerdict::Informational,
        };

        SampleTestResult {
            sample_name: sample.name.clone(),
            expected: sample.label.as_str().to_string(),
            matched,
            match_count,
            match_offsets,
            scan_duration_us: crate::casts::u128_to_u64_sat(elapsed.as_micros()),
            verdict,
        }
    }
}

impl Default for RuleTester {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Performance Benchmark ────────────────────────────────────────────────────

/// Result of benchmarking a rule against a set of samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Rule name.
    pub rule_name: String,
    /// Number of samples scanned per iteration.
    pub sample_count: usize,
    /// Total bytes scanned per iteration.
    pub total_bytes: usize,
    /// Number of iterations run.
    pub iterations: u32,
    /// Mean scan time per iteration (milliseconds).
    pub mean_ms: f64,
    /// Minimum scan time across iterations (milliseconds).
    pub min_ms: f64,
    /// Maximum scan time across iterations (milliseconds).
    pub max_ms: f64,
    /// Throughput in MB/s.
    pub throughput_mbps: f64,
    /// Whether the rule stays within the time budget.
    pub passes_time_budget: bool,
}

/// Benchmark a rule against the provided samples.
#[must_use]
pub fn benchmark_rule(
    rule_text: &str,
    rule_name: &str,
    samples: &[TestSample],
    iterations: u32,
    budget_ms: f64,
) -> BenchmarkResult {
    let patterns = extract_hex_patterns(rule_text);
    let string_patterns = extract_string_patterns(rule_text);
    let total_bytes: usize = samples.iter().map(TestSample::size).sum();
    let sample_count = samples.len();
    let iters = iterations.max(1);

    let mut times_ms = Vec::with_capacity(iters as usize);
    for _ in 0..iters {
        let start = Instant::now();
        for s in samples {
            let _ = scan_sample(&s.data, &patterns, &string_patterns);
        }
        times_ms.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    let mean_ms = times_ms.iter().sum::<f64>() / f64::from(iters);
    let min_ms = times_ms.iter().copied().fold(f64::INFINITY, f64::min);
    let max_ms = times_ms.iter().copied().fold(0.0_f64, f64::max);

    let throughput_mbps = if mean_ms > 0.0 {
        (crate::casts::usize_to_f64(total_bytes) / (1024.0 * 1024.0)) / (mean_ms / 1000.0)
    } else {
        f64::INFINITY
    };

    BenchmarkResult {
        rule_name: rule_name.to_string(),
        sample_count,
        total_bytes,
        iterations: iters,
        mean_ms,
        min_ms,
        max_ms,
        throughput_mbps,
        passes_time_budget: mean_ms <= budget_ms,
    }
}

// ─── Quality Scoring ──────────────────────────────────────────────────────────

/// Detailed quality dimensions for a YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleQualityScore {
    /// Rule ID.
    pub rule_id: String,
    /// Rule name.
    pub rule_name: String,
    /// Detection efficacy score `[0–40]`.
    pub detection_score: f64,
    /// Specificity (low FP) score `[0–30]`.
    pub specificity_score: f64,
    /// Performance score `[0–15]`.
    pub performance_score: f64,
    /// Metadata completeness score `[0–15]`.
    pub metadata_score: f64,
    /// Total quality score `[0–100]`.
    pub total_score: f64,
    /// Human-readable grade: A/B/C/D/F.
    pub grade: char,
    /// List of improvement recommendations.
    pub recommendations: Vec<String>,
}

impl RuleQualityScore {
    /// Compute the total score and grade from the component scores.
    fn finalize(&mut self) {
        self.total_score =
            self.detection_score + self.specificity_score + self.performance_score + self.metadata_score;
        self.grade = match crate::casts::f64_to_u32_sat(self.total_score) {
            90..=100 => 'A',
            80..=89 => 'B',
            70..=79 => 'C',
            60..=69 => 'D',
            _ => 'F',
        };
    }
}

/// Compute a quality score for a rule given its corpus test report and benchmark.
#[must_use]
pub fn compute_quality_score(
    meta: &RuleMeta,
    report: &CorpusTestReport,
    benchmark: Option<&BenchmarkResult>,
) -> RuleQualityScore {
    let mut score = RuleQualityScore {
        rule_id: meta.rule_id.clone(),
        rule_name: meta.name.clone(),
        detection_score: 0.0,
        specificity_score: 0.0,
        performance_score: 0.0,
        metadata_score: 0.0,
        total_score: 0.0,
        grade: 'F',
        recommendations: Vec::new(),
    };

    // Detection score (0–40): weighted combination of DR and F1.
    score.detection_score = report.detection_rate.mul_add(24.0, report.f1_score * 16.0);
    if report.detection_rate < 0.5 {
        score.recommendations.push(
            "Low detection rate — add more pattern variants from known samples.".to_string(),
        );
    }

    // Specificity score (0–30): based on inverse FP rate.
    let inv_fpr = 1.0 - report.fp_rate;
    score.specificity_score = inv_fpr * 30.0;
    if report.fp_rate > 0.05 {
        score.recommendations.push(
            "High false positive rate — narrow conditions or add negative conditions.".to_string(),
        );
    }

    // Performance score (0–15): based on throughput if available.
    if let Some(bm) = benchmark {
        let perf_ratio = (bm.throughput_mbps / 500.0_f64).min(1.0); // 500 MB/s is top score
        score.performance_score = perf_ratio * 15.0;
        if bm.throughput_mbps < 10.0 {
            score.recommendations.push(
                "Very slow scan throughput — simplify hex patterns or reduce string count.".to_string(),
            );
        }
    } else {
        // No benchmark available — award neutral score.
        score.performance_score = 7.5;
    }

    // Metadata score (0–15): completeness of rule metadata.
    let mut md_score = 0.0_f64;
    if meta.author.is_empty() {
        score.recommendations.push("Missing author in metadata.".to_string());
    } else {
        md_score += 3.0;
    }
    if meta.description.is_empty() {
        score.recommendations.push("Missing description in metadata.".to_string());
    } else {
        md_score += 3.0;
    }
    if !meta.date.is_empty() {
        md_score += 2.0;
    }
    if meta.tags.is_empty() {
        score.recommendations.push("No tags — add relevant family/category tags.".to_string());
    } else {
        md_score += 3.0;
    }
    // Severity weighting: critical/high rules get a bonus.
    if matches!(meta.severity, Severity::Critical | Severity::High) {
        md_score += 4.0;
    } else {
        md_score += 2.0;
    }
    score.metadata_score = md_score.min(15.0);

    score.finalize();
    score
}

// ─── Corpus Builder ───────────────────────────────────────────────────────────

/// Helper for building a diverse test corpus programmatically.
pub struct CorpusBuilder {
    samples: Vec<TestSample>,
}

impl CorpusBuilder {
    /// Create an empty builder.
    #[must_use]
    pub const fn new() -> Self {
        Self { samples: Vec::new() }
    }

    /// Add a raw malicious sample.
    pub fn add_malicious(&mut self, name: impl Into<String>, data: Vec<u8>) -> &mut Self {
        self.samples.push(TestSample::new(name, data, SampleLabel::Malicious));
        self
    }

    /// Add a raw benign sample.
    pub fn add_benign(&mut self, name: impl Into<String>, data: Vec<u8>) -> &mut Self {
        self.samples.push(TestSample::new(name, data, SampleLabel::Benign));
        self
    }

    /// Add a synthetic MZ/PE header as a benign sample.
    pub fn add_generic_pe_benign(&mut self) -> &mut Self {
        let mut data = vec![0x4D, 0x5A, 0x90, 0x00]; // MZ magic
        data.extend_from_slice(&[0u8; 508]); // filler to 512 bytes
        self.add_benign("generic_pe_benign.exe", data)
    }

    /// Add a random-bytes sample as benign.
    pub fn add_random_benign(&mut self, size: usize, seed: u64) -> &mut Self {
        let data = pseudo_random_bytes(size, seed);
        self.add_benign(format!("random_{size}b"), data)
    }

    /// Add a sample that contains specific bytes (useful for positive testing).
    pub fn add_with_bytes(
        &mut self,
        name: impl Into<String>,
        prefix: &[u8],
        payload: &[u8],
        suffix: &[u8],
        label: SampleLabel,
    ) -> &mut Self {
        let mut data = Vec::with_capacity(prefix.len() + payload.len() + suffix.len());
        data.extend_from_slice(prefix);
        data.extend_from_slice(payload);
        data.extend_from_slice(suffix);
        self.samples.push(TestSample::new(name, data, label));
        self
    }

    /// Load samples from a directory, applying `label` to all files.
    ///
    /// # Errors
    /// Returns an error if the directory cannot be read.
    pub fn add_from_dir(&mut self, dir: &Path, label: SampleLabel) -> anyhow::Result<usize> {
        let mut count = 0;
        for entry in std::fs::read_dir(dir)?.flatten() {
            let path = entry.path();
            if path.is_file()
                && let Ok(sample) = TestSample::from_file(&path, label) {
                    self.samples.push(sample);
                    count += 1;
                }
        }
        Ok(count)
    }

    /// Build the corpus and return the samples.
    #[must_use]
    pub fn build(self) -> Vec<TestSample> {
        self.samples
    }
}

impl Default for CorpusBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── False Positive Analysis ──────────────────────────────────────────────────

/// Analysis of false positive patterns to help diagnose over-matching rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveAnalysis {
    /// Total FP samples.
    pub fp_count: usize,
    /// Distribution of FP sample sizes (small < 1KB, medium 1–100KB, large > 100KB).
    pub size_distribution: HashMap<String, usize>,
    /// Most common strings found in FP samples (top 10).
    pub common_strings: Vec<String>,
    /// Patterns that appear to trigger FPs most often.
    pub triggering_patterns: Vec<String>,
    /// Suggestions for reducing FPs.
    pub suggestions: Vec<String>,
}

/// Analyse false positives in a corpus test report.
#[must_use]
pub fn analyze_false_positives(
    report: &CorpusTestReport,
    corpus: &[TestSample],
) -> FalsePositiveAnalysis {
    let fp_names: std::collections::HashSet<&str> = report
        .false_positive_samples()
        .iter()
        .map(|r| r.sample_name.as_str())
        .collect();

    let fp_samples: Vec<&TestSample> = corpus
        .iter()
        .filter(|s| fp_names.contains(s.name.as_str()))
        .collect();

    let mut size_dist = HashMap::new();
    for s in &fp_samples {
        let bucket = if s.size() < 1024 {
            "small_<1KB"
        } else if s.size() < 102_400 {
            "medium_1-100KB"
        } else {
            "large_>100KB"
        };
        *size_dist.entry(bucket.to_string()).or_insert(0) += 1;
    }

    // Extract printable strings from FP samples (quick approximation).
    let mut string_freq: HashMap<String, usize> = HashMap::new();
    for s in &fp_samples {
        for chunk in s.data.windows(6) {
            if chunk.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
                let st = String::from_utf8_lossy(chunk).to_string();
                *string_freq.entry(st).or_insert(0) += 1;
            }
        }
    }
    let mut common_strings: Vec<(String, usize)> = string_freq.into_iter().collect();
    common_strings.sort_by(|a, b| b.1.cmp(&a.1));
    let common_strings: Vec<String> = common_strings
        .into_iter()
        .take(10)
        .map(|(s, _)| s)
        .collect();

    let mut suggestions = Vec::new();
    if report.fp_rate > 0.1 {
        suggestions.push(
            "Very high FPR: consider adding `uint16(0) == 0x5A4D` PE magic check.".to_string(),
        );
        suggestions.push(
            "Add `filesize` condition to restrict to expected file size range.".to_string(),
        );
    }
    if !fp_samples.iter().all(|s| s.size() < 1024) {
        suggestions.push(
            "FPs span multiple size ranges; add size-based conditions.".to_string(),
        );
    }
    suggestions.push(
        "Use `all of them` instead of `any of them` to require multiple string matches."
            .to_string(),
    );

    FalsePositiveAnalysis {
        fp_count: fp_samples.len(),
        size_distribution: size_dist,
        common_strings,
        triggering_patterns: Vec::new(), // populated by caller with rule introspection
        suggestions,
    }
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Extract hex byte patterns from YARA rule text (best-effort).
fn extract_hex_patterns(rule_text: &str) -> Vec<Vec<u8>> {
    let mut patterns = Vec::new();
    let mut i = 0;
    let bytes = rule_text.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'{' {
            // Find matching close brace.
            if let Some(end) = bytes[i..].iter().position(|&b| b == b'}') {
                let hex_str = &rule_text[i + 1..i + end];
                if let Some(pat) = parse_hex_pattern(hex_str)
                    && !pat.is_empty() {
                        patterns.push(pat);
                    }
                i += end + 1;
                continue;
            }
        }
        i += 1;
    }
    patterns
}

/// Parse a hex pattern string like `"DE AD BE EF ?? 00"` into bytes.
/// Returns `None` if the pattern is empty or malformed.
fn parse_hex_pattern(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let tokens: Vec<&str> = s.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }
    for tok in &tokens {
        if *tok == "??" || *tok == "?" {
            out.push(0x00); // wildcard encoded as 0 (simplification)
        } else if tok.len() == 2
            && let Ok(b) = u8::from_str_radix(tok, 16) {
                out.push(b);
            }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Extract ASCII string literals from a YARA rule.
fn extract_string_patterns(rule_text: &str) -> Vec<Vec<u8>> {
    let mut patterns = Vec::new();
    let chars = rule_text.char_indices();
    for (i, ch) in chars {
        if ch == '"' {
            let start = i + 1;
            let mut end = start;
            for (j, c) in rule_text[start..].char_indices() {
                if c == '"' {
                    end = start + j;
                    break;
                }
            }
            if end > start {
                let s = &rule_text[start..end];
                if !s.is_empty() && s.len() >= 3 {
                    patterns.push(s.as_bytes().to_vec());
                }
            }
        }
    }
    patterns
}

/// Check if any of the patterns appear in the data.
/// Returns `(matched, match_count, match_offsets)`.
fn scan_sample(
    data: &[u8],
    hex_patterns: &[Vec<u8>],
    string_patterns: &[Vec<u8>],
) -> (bool, usize, Vec<u64>) {
    let mut total_matches = 0usize;
    let mut offsets = Vec::new();

    for pat in hex_patterns.iter().chain(string_patterns.iter()) {
        if pat.is_empty() {
            continue;
        }
        for (idx, window) in data.windows(pat.len()).enumerate() {
            // Wildcard bytes (0x00 in our encoding) always match.
            let matches = window.iter().zip(pat.iter()).all(|(d, p)| *p == 0 || *d == *p);
            if matches {
                total_matches += 1;
                if offsets.len() < 8 {
                    offsets.push(idx as u64);
                }
            }
        }
    }

    (total_matches > 0, total_matches, offsets)
}

/// Generate pseudo-random bytes using a simple LCG for testing.
fn pseudo_random_bytes(size: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..size)
        .map(|_| {
            state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            crate::casts::u64_to_u8_sat(state >> 33)
        })
        .collect()
}

// ─── Test Suite ───────────────────────────────────────────────────────────────

/// A named collection of test cases that exercise a specific rule.
#[derive(Debug)]
pub struct RuleTestSuite {
    /// Suite name.
    pub name: String,
    /// Rule text under test.
    pub rule_text: String,
    /// Expected results per named test case.
    pub cases: Vec<(String, TestSample, bool)>,
}

impl RuleTestSuite {
    /// Create a new suite.
    #[must_use]
    pub fn new(name: impl Into<String>, rule_text: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            rule_text: rule_text.into(),
            cases: Vec::new(),
        }
    }

    /// Add a test case.
    pub fn add_case(
        &mut self,
        case_name: impl Into<String>,
        sample: TestSample,
        should_match: bool,
    ) {
        self.cases.push((case_name.into(), sample, should_match));
    }

    /// Run all cases and return pass/fail per case.
    #[must_use]
    pub fn run(&self) -> Vec<(String, bool, bool)> {
        let hex_pats = extract_hex_patterns(&self.rule_text);
        let str_pats = extract_string_patterns(&self.rule_text);
        self.cases
            .iter()
            .map(|(name, sample, expected)| {
                let (matched, _, _) = scan_sample(&sample.data, &hex_pats, &str_pats);
                let passed = matched == *expected;
                (name.clone(), passed, matched)
            })
            .collect()
    }

    /// Return the number of passing cases.
    #[must_use]
    pub fn passing_count(&self) -> usize {
        self.run().iter().filter(|(_, p, _)| *p).count()
    }

    /// Return the number of failing cases.
    #[must_use]
    pub fn failing_count(&self) -> usize {
        self.run().iter().filter(|(_, p, _)| !*p).count()
    }

    /// Return `true` if all cases pass.
    #[must_use]
    pub fn all_pass(&self) -> bool {
        self.failing_count() == 0
    }
}

// ─── Corpus-level false-positive rate estimation ──────────────────────────────

/// Estimate the false-positive rate of a rule against a benign dataset.
///
/// `benign_samples` should be representative clean files.
#[must_use]
pub fn estimate_fp_rate(rule_text: &str, benign_samples: &[TestSample]) -> f64 {
    if benign_samples.is_empty() {
        return 0.0;
    }
    let hex_pats = extract_hex_patterns(rule_text);
    let str_pats = extract_string_patterns(rule_text);
    let fp_count = benign_samples
        .iter()
        .filter(|s| scan_sample(&s.data, &hex_pats, &str_pats).0)
        .count();
    crate::casts::usize_to_f64(fp_count) / crate::casts::usize_to_f64(benign_samples.len())
}

/// Estimate the detection rate of a rule against a malicious dataset.
#[must_use]
pub fn estimate_detection_rate(rule_text: &str, malicious_samples: &[TestSample]) -> f64 {
    if malicious_samples.is_empty() {
        return 0.0;
    }
    let hex_pats = extract_hex_patterns(rule_text);
    let str_pats = extract_string_patterns(rule_text);
    let tp_count = malicious_samples
        .iter()
        .filter(|s| scan_sample(&s.data, &hex_pats, &str_pats).0)
        .count();
    crate::casts::usize_to_f64(tp_count) / crate::casts::usize_to_f64(malicious_samples.len())
}

// ─── PathBuf corpus loader ────────────────────────────────────────────────────

/// Load a corpus from a list of (path, label) pairs.
///
/// # Errors
/// Returns an error if any file cannot be read.
pub fn load_corpus_from_paths(
    paths: &[(PathBuf, SampleLabel)],
) -> anyhow::Result<Vec<TestSample>> {
    let mut samples = Vec::new();
    for (path, label) in paths {
        let data = std::fs::read(path)?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        samples.push(TestSample::new(name, data, *label));
    }
    Ok(samples)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_hex_patterns() {
        let rule = r"
rule Test { strings: $a = { DE AD BE EF } condition: $a }
";
        let pats = extract_hex_patterns(rule);
        assert!(!pats.is_empty());
        assert_eq!(pats[0], vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_scan_sample_finds_pattern() {
        let data = vec![0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        let patterns = vec![vec![0xDE, 0xAD, 0xBE, 0xEF]];
        let (matched, count, offsets) = scan_sample(&data, &patterns, &[]);
        assert!(matched);
        assert_eq!(count, 1);
        assert_eq!(offsets[0], 1);
    }

    #[test]
    fn test_scan_sample_no_match() {
        let data = vec![0x00, 0x01, 0x02, 0x03];
        let patterns = vec![vec![0xDE, 0xAD]];
        let (matched, _, _) = scan_sample(&data, &patterns, &[]);
        assert!(!matched);
    }

    #[test]
    fn test_corpus_builder() {
        let mut builder = CorpusBuilder::new();
        builder.add_malicious("mal", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        builder.add_benign("clean", vec![0x00, 0x01]);
        builder.add_random_benign(128, 42);
        let corpus = builder.build();
        assert_eq!(corpus.len(), 3);
    }

    #[test]
    fn test_rule_tester_basic() {
        let mut tester = RuleTester::new();
        let mut builder = CorpusBuilder::new();
        builder.add_malicious("mal", vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00]);
        builder.add_benign("clean", vec![0x00, 0x01, 0x02, 0x03]);
        for s in builder.build() {
            tester.add_sample(s);
        }
        let meta = RuleMeta {
            rule_id: "test:TestRule".to_string(),
            name: "TestRule".to_string(),
            namespace: "test".to_string(),
            author: "tester".to_string(),
            date: "2025-01-01".to_string(),
            description: "Test rule".to_string(),
            tags: vec!["test".to_string()],
            category: crate::RuleCategory::Unknown,
            severity: Severity::Medium,
            hash: "deadbeef".to_string(),
            file_path: "test.yar".to_string(),
            enabled: true,
            source_name: "test".to_string(),
        };
        let rule = r"rule TestRule { strings: $a = { DE AD BE EF } condition: $a }";
        let report = tester.test_rule(rule, &meta);
        assert_eq!(report.true_positives, 1);
        assert_eq!(report.true_negatives, 1);
        assert!(report.quality_score > 0.0);
    }

    #[test]
    fn test_benchmark_rule() {
        let samples: Vec<TestSample> = vec![
            TestSample::new("s1", [0xDE, 0xAD].repeat(128), SampleLabel::Malicious),
        ];
        let rule = r"rule Test { strings: $a = { DE AD } condition: $a }";
        let bm = benchmark_rule(rule, "Test", &samples, 2, 1000.0);
        assert_eq!(bm.iterations, 2);
        assert!(bm.sample_count == 1);
    }

    #[test]
    fn test_pseudo_random_bytes() {
        let bytes = pseudo_random_bytes(16, 0xDEAD_BEEF);
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn test_estimate_fp_rate_zero() {
        let samples = vec![TestSample::new("clean", vec![0x00; 32], SampleLabel::Benign)];
        let rule = r"rule T { strings: $a = { DE AD } condition: $a }";
        let rate = estimate_fp_rate(rule, &samples);
        assert!(rate.abs() < f64::EPSILON);
    }

    #[test]
    fn test_rule_test_suite() {
        let rule = r"rule T { strings: $a = { CA FE BA BE } condition: $a }";
        let mut suite = RuleTestSuite::new("cafe_suite", rule);
        suite.add_case("hit", TestSample::new("hit", vec![0xCA, 0xFE, 0xBA, 0xBE], SampleLabel::Malicious), true);
        suite.add_case("miss", TestSample::new("miss", vec![0x00; 8], SampleLabel::Benign), false);
        assert!(suite.all_pass());
    }
}
