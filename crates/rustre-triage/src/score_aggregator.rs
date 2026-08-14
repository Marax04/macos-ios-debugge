// rustre-triage/src/score_aggregator.rs
//! Multi-source score aggregation for triage.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Float-to-integer helpers (cast-free) ─────────────────────────────────────

/// Extract the integer floor of `v` as `u8` without any float-to-integer cast.
/// Valid for `v` in `[0.0, 127.0]`; values outside that range are clamped.
/// Uses successive-subtraction of powers of two — no precision loss on integers.
fn floor_f64_to_u8(v: f64) -> u8 {
    let mut rem = v.clamp(0.0_f64, 127.0_f64);
    let mut out = 0u8;
    for (thr, bit) in [
        (64.0_f64, 64u8),
        (32.0, 32),
        (16.0, 16),
        (8.0, 8),
        (4.0, 4),
        (2.0, 2),
        (1.0, 1),
    ] {
        if rem >= thr {
            rem -= thr;
            out += bit;
        }
    }
    out
}

// ─── Per-analyzer score ───────────────────────────────────────────────────────

/// The analyzer that produced a score contribution.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnalyzerKind {
    /// Shannon entropy analysis.
    Entropy,
    /// YARA rule matching.
    Yara,
    /// Import table analysis.
    Imports,
    /// String heuristics.
    Strings,
    /// Packer detection.
    Packer,
    /// Signature / certificate check.
    Signature,
    /// Network indicators.
    Network,
    /// Script behavior patterns.
    Script,
    /// ELF/Mach-O structural checks.
    BinaryStructure,
    /// Custom / user-defined analyzer.
    Custom(String),
}

impl AnalyzerKind {
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Entropy => "entropy",
            Self::Yara => "yara",
            Self::Imports => "imports",
            Self::Strings => "strings",
            Self::Packer => "packer",
            Self::Signature => "signature",
            Self::Network => "network",
            Self::Script => "script",
            Self::BinaryStructure => "binary_structure",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl std::fmt::Display for AnalyzerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A raw score contribution from one analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageScore {
    /// The analyzer that produced this score.
    pub kind: AnalyzerKind,
    /// Raw score 0–100.
    pub raw: u8,
    /// Weight applied during aggregation (0.0–2.0).
    pub weight: f64,
    /// Human-readable reason for the score.
    pub reason: String,
    /// Confidence in this score (0.0–1.0).
    pub confidence: f64,
    /// Individual contributing signals.
    pub signals: Vec<ScoreSignal>,
}

impl TriageScore {
    /// Create a new score with default weight 1.0 and confidence 1.0.
    pub fn new(kind: AnalyzerKind, raw: u8, reason: impl Into<String>) -> Self {
        Self {
            kind,
            raw,
            weight: 1.0,
            reason: reason.into(),
            confidence: 1.0,
            signals: Vec::new(),
        }
    }

    #[must_use]
    pub const fn with_weight(mut self, w: f64) -> Self {
        self.weight = w;
        self
    }
    #[must_use]
    pub const fn with_confidence(mut self, c: f64) -> Self {
        // NaN-safe clamp: `f64::clamp` propagates NaN and `is_nan()` is not
        // available in a const fn. A NaN confidence would poison the aggregated
        // score, since arithmetic propagates it and comparisons all turn false.
        self.confidence = if c >= 1.0 {
            1.0
        } else if c > 0.0 {
            c
        } else {
            0.0
        };
        self
    }

    pub fn add_signal(&mut self, s: ScoreSignal) {
        self.signals.push(s);
    }

    /// Weighted contribution to aggregate score.
    #[must_use]
    pub fn weighted(&self) -> f64 {
        f64::from(self.raw) * self.weight * self.confidence
    }
}

// ─── Score signal ─────────────────────────────────────────────────────────────

/// A single contributing signal to a score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreSignal {
    pub name: String,
    pub value: f64,
    pub description: String,
}

impl ScoreSignal {
    pub fn new(name: impl Into<String>, value: f64, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value,
            description: description.into(),
        }
    }
}

// ─── Threshold policy ─────────────────────────────────────────────────────────

/// Thresholds for mapping an aggregate score to a threat label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdPolicy {
    /// Score below this → Clean.
    pub clean_max: u8,
    /// Score from `clean_max+1` to `suspicious_max` → Suspicious.
    pub suspicious_max: u8,
    /// Score above `suspicious_max` → Malicious.
    pub malicious_min: u8,
}

impl Default for ThresholdPolicy {
    fn default() -> Self {
        Self {
            clean_max: 19,
            suspicious_max: 59,
            malicious_min: 60,
        }
    }
}

impl ThresholdPolicy {
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            clean_max: 9,
            suspicious_max: 39,
            malicious_min: 40,
        }
    }
    #[must_use]
    pub const fn lenient() -> Self {
        Self {
            clean_max: 29,
            suspicious_max: 69,
            malicious_min: 70,
        }
    }

    #[must_use]
    pub const fn classify(&self, score: u8) -> &'static str {
        if score <= self.clean_max {
            "clean"
        } else if score <= self.suspicious_max {
            "suspicious"
        } else {
            "malicious"
        }
    }
}

// ─── Confidence interval ──────────────────────────────────────────────────────

/// A 95% confidence interval around an aggregate score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    pub point_estimate: f64,
    pub lower_95: f64,
    pub upper_95: f64,
    pub sample_size: usize,
}

impl ConfidenceInterval {
    #[must_use]
    pub fn compute(scores: &[f64]) -> Self {
        if scores.is_empty() {
            return Self {
                point_estimate: 0.0,
                lower_95: 0.0,
                upper_95: 0.0,
                sample_size: 0,
            };
        }
        let n = f64::from(u32::try_from(scores.len()).unwrap_or(u32::MAX));
        let mean: f64 = scores.iter().sum::<f64>() / n;
        let variance: f64 = if n < 2.0 {
            0.0
        } else {
            scores.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0)
        };
        let stderr = (variance / n).sqrt();
        // 1.96 for 95% CI
        let margin = 1.96 * stderr;
        Self {
            point_estimate: mean,
            lower_95: (mean - margin).max(0.0),
            upper_95: (mean + margin).min(100.0),
            sample_size: scores.len(),
        }
    }
}

// ─── Aggregated result ────────────────────────────────────────────────────────

/// The final aggregated score and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedScore {
    /// Final clamped score 0–100.
    pub final_score: u8,
    /// Threat label per policy.
    pub label: String,
    /// Per-analyzer breakdowns.
    pub breakdown: Vec<TriageScore>,
    /// Confidence interval.
    pub ci: ConfidenceInterval,
    /// Dominant analyzer (highest weighted contribution).
    pub dominant_analyzer: String,
    /// Total weight sum used for normalisation.
    pub total_weight: f64,
}

impl AggregatedScore {
    #[must_use]
    pub fn is_malicious(&self) -> bool {
        self.label == "malicious"
    }
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.label == "suspicious"
    }
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.label == "clean"
    }

    /// One-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} (score={}, CI=[{:.1}-{:.1}], dominant={})",
            self.label.to_uppercase(),
            self.final_score,
            self.ci.lower_95,
            self.ci.upper_95,
            self.dominant_analyzer,
        )
    }
}

// ─── Score aggregator ─────────────────────────────────────────────────────────

/// Aggregates multiple [`TriageScore`]s into an [`AggregatedScore`].
pub struct ScoreAggregator {
    policy: ThresholdPolicy,
    /// Default weights per analyzer kind.
    weights: HashMap<String, f64>,
}

impl Default for ScoreAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl ScoreAggregator {
    #[must_use]
    pub fn new() -> Self {
        let mut weights = HashMap::new();
        weights.insert("yara".into(), 1.5);
        weights.insert("imports".into(), 1.2);
        weights.insert("packer".into(), 0.8);
        weights.insert("entropy".into(), 0.9);
        weights.insert("strings".into(), 1.0);
        weights.insert("signature".into(), 0.7);
        weights.insert("network".into(), 1.0);
        weights.insert("script".into(), 1.1);
        weights.insert("binary_structure".into(), 0.6);
        Self {
            policy: ThresholdPolicy::default(),
            weights,
        }
    }

    #[must_use]
    pub const fn with_policy(mut self, policy: ThresholdPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn set_weight(&mut self, kind: &str, weight: f64) {
        self.weights.insert(kind.to_string(), weight);
    }

    /// Aggregate a list of triage scores.
    #[must_use]
    pub fn aggregate(&self, scores: &[TriageScore]) -> AggregatedScore {
        if scores.is_empty() {
            let ci = ConfidenceInterval::compute(&[]);
            return AggregatedScore {
                final_score: 0,
                label: "clean".into(),
                breakdown: Vec::new(),
                ci,
                dominant_analyzer: "none".into(),
                total_weight: 0.0,
            };
        }

        let mut weighted_sum = 0.0f64;
        let mut total_weight = 0.0f64;
        let mut best_kind = String::new();
        let mut best_contribution = 0.0f64;
        let mut raw_values: Vec<f64> = Vec::new();

        // Build augmented scores with default weights
        let augmented: Vec<TriageScore> = scores
            .iter()
            .map(|s| {
                let default_w = self.weights.get(s.kind.as_str()).copied().unwrap_or(1.0);
                let effective_w = s.weight * default_w;
                let mut s2 = s.clone();
                s2.weight = effective_w;
                s2
            })
            .collect();

        for s in &augmented {
            let contrib = f64::from(s.raw) * s.weight * s.confidence;
            weighted_sum += contrib;
            total_weight += s.weight;
            raw_values.push(f64::from(s.raw));
            if contrib > best_contribution {
                best_contribution = contrib;
                best_kind = s.kind.to_string();
            }
        }

        let normalised = if total_weight > 0.0 {
            (weighted_sum / total_weight).clamp(0.0, 100.0)
        } else {
            0.0
        };

        let final_score = floor_f64_to_u8(normalised.clamp(0.0, 100.0));
        let label = self.policy.classify(final_score).to_string();
        let ci = ConfidenceInterval::compute(&raw_values);

        AggregatedScore {
            final_score,
            label,
            breakdown: augmented,
            ci,
            dominant_analyzer: best_kind,
            total_weight,
        }
    }

    /// Aggregate and add a penalty for high-entropy data.
    #[must_use]
    pub fn aggregate_with_entropy_penalty(
        &self,
        scores: &[TriageScore],
        entropy: f64,
    ) -> AggregatedScore {
        let mut all = scores.to_vec();
        if entropy > 7.0 {
            let penalty = floor_f64_to_u8(((entropy - 7.0) * 50.0).clamp(0.0, 40.0));
            all.push(
                TriageScore::new(
                    AnalyzerKind::Entropy,
                    penalty,
                    format!("high entropy {entropy:.3}"),
                )
                .with_weight(0.9),
            );
        }
        self.aggregate(&all)
    }

    /// Aggregate and boost score based on matched YARA rule count.
    #[must_use]
    pub fn aggregate_with_yara_boost(
        &self,
        scores: &[TriageScore],
        yara_match_count: usize,
    ) -> AggregatedScore {
        let mut all = scores.to_vec();
        if yara_match_count > 0 {
            let boost = (u8::try_from(yara_match_count).unwrap_or(u8::MAX).saturating_mul(15)).min(60);
            all.push(
                TriageScore::new(
                    AnalyzerKind::Yara,
                    boost,
                    format!("{yara_match_count} YARA rule(s) matched"),
                )
                .with_weight(1.5),
            );
        }
        self.aggregate(&all)
    }
}

// ─── Score normaliser ─────────────────────────────────────────────────────────

/// Normalises raw numeric scores from heterogeneous sources.
pub struct ScoreNormaliser;

impl ScoreNormaliser {
    /// Normalise a raw value from [lo, hi] to [0, 100].
    #[must_use]
    pub fn normalise(value: f64, lo: f64, hi: f64) -> u8 {
        if hi <= lo {
            return 0;
        }
        floor_f64_to_u8(((value - lo) / (hi - lo) * 100.0).clamp(0.0, 100.0))
    }

    /// Map a list of raw scores to a single 0–100 value using max.
    pub fn max_normalise(scores: &[f64], max_possible: f64) -> u8 {
        let max = scores.iter().copied().fold(0.0_f64, f64::max);
        Self::normalise(max, 0.0, max_possible)
    }

    /// Map entropy (0–8) to 0–100 score.
    #[must_use]
    pub fn from_entropy(entropy: f64) -> u8 {
        // Below 4.0 → benign; 7.0+ → highly suspicious
        if entropy < 4.0 {
            0
        } else {
            Self::normalise(entropy, 4.0, 8.0)
        }
    }

    /// Map an import suspicion count to 0–100 score.
    #[must_use]
    pub fn from_import_count(suspicious: usize, total: usize) -> u8 {
        if total == 0 {
            return 0;
        }
        let ratio = f64::from(u32::try_from(suspicious).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX));
        floor_f64_to_u8((ratio * 100.0).clamp(0.0, 100.0))
    }
}

// ─── Score history ────────────────────────────────────────────────────────────

/// Rolling history of aggregated scores for trend analysis.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ScoreHistory {
    entries: Vec<(u64, u8)>,
    capacity: usize,
}

impl ScoreHistory {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::new(),
            capacity: capacity.max(1),
        }
    }

    pub fn push(&mut self, timestamp: u64, score: u8) {
        if self.entries.len() >= self.capacity {
            self.entries.remove(0);
        }
        self.entries.push((timestamp, score));
    }

    #[must_use]
    pub fn average(&self) -> f64 {
        if self.entries.is_empty() {
            return 0.0;
        }
        self.entries.iter().map(|(_, s)| f64::from(*s)).sum::<f64>() / f64::from(u32::try_from(self.entries.len()).unwrap_or(u32::MAX))
    }

    /// # Panics
    ///
    /// Panics if `self.entries` is empty (caller must check `len() >= 2` first).
    #[must_use]
    pub fn trend(&self) -> f64 {
        if self.entries.len() < 2 {
            return 0.0;
        }
        let n = f64::from(u32::try_from(self.entries.len()).unwrap_or(u32::MAX));
        let (last_ts, last_score) = self.entries.last().unwrap();
        let (first_ts, first_score) = self.entries.first().unwrap();
        if last_ts == first_ts {
            return 0.0;
        }
        let last_ts_f = f64::from(u32::try_from(*last_ts).unwrap_or(u32::MAX));
        let first_ts_f = f64::from(u32::try_from(*first_ts).unwrap_or(u32::MAX));
        (f64::from(*last_score) - f64::from(*first_score)) / (last_ts_f - first_ts_f)
            * n
    }

    #[must_use]
    pub fn max_score(&self) -> u8 {
        self.entries.iter().map(|(_, s)| *s).max().unwrap_or(0)
    }
}

// ─── Multi-file aggregator ────────────────────────────────────────────────────

/// Aggregates scores from multiple file analyses (batch mode).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BatchAggregator {
    pub total_files: usize,
    pub malicious_files: usize,
    pub suspicious_files: usize,
    pub clean_files: usize,
    pub score_sum: u64,
    pub max_score: u8,
    pub family_counts: HashMap<String, usize>,
}

impl BatchAggregator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, result: &AggregatedScore) {
        self.total_files += 1;
        self.score_sum += u64::from(result.final_score);
        if result.final_score > self.max_score {
            self.max_score = result.final_score;
        }
        match result.label.as_str() {
            "malicious" => self.malicious_files += 1,
            "suspicious" => self.suspicious_files += 1,
            _ => self.clean_files += 1,
        }
        *self
            .family_counts
            .entry(result.dominant_analyzer.clone())
            .or_insert(0) += 1;
    }

    #[must_use]
    pub fn average_score(&self) -> f64 {
        if self.total_files == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.score_sum).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.total_files).unwrap_or(u32::MAX))
    }

    #[must_use]
    pub fn malicious_rate(&self) -> f64 {
        if self.total_files == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.malicious_files).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.total_files).unwrap_or(u32::MAX))
    }

    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Files: {} | Malicious: {} ({:.1}%) | Suspicious: {} | Clean: {} | AvgScore: {:.1}",
            self.total_files,
            self.malicious_files,
            self.malicious_rate() * 100.0,
            self.suspicious_files,
            self.clean_files,
            self.average_score(),
        )
    }
}

// ─── Score comparison ─────────────────────────────────────────────────────────

/// Compare two aggregated scores and produce a diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreDiff {
    pub before: u8,
    pub after: u8,
    pub delta: i16,
    pub label_before: String,
    pub label_after: String,
    pub escalated: bool,
    pub deescalated: bool,
}

impl ScoreDiff {
    #[must_use]
    pub fn new(before: &AggregatedScore, after: &AggregatedScore) -> Self {
        let delta = i16::from(after.final_score) - i16::from(before.final_score);
        Self {
            before: before.final_score,
            after: after.final_score,
            delta,
            label_before: before.label.clone(),
            label_after: after.label.clone(),
            escalated: delta > 0 && after.label != before.label,
            deescalated: delta < 0 && after.label != before.label,
        }
    }
}

// ─── Score preset ─────────────────────────────────────────────────────────────

/// Pre-built score presets for common malware categories.
pub struct ScorePreset;

impl ScorePreset {
    /// Score for a clean file.
    #[must_use]
    pub fn clean() -> TriageScore {
        TriageScore::new(AnalyzerKind::Strings, 0, "no suspicious indicators")
    }

    /// Score for a UPX-packed file.
    #[must_use]
    pub fn upx_packed() -> TriageScore {
        TriageScore::new(AnalyzerKind::Packer, 25, "UPX packer signature found").with_weight(0.8)
    }

    /// Score for a VMProtect-protected file.
    #[must_use]
    pub fn vmprotect() -> TriageScore {
        TriageScore::new(AnalyzerKind::Packer, 40, "VMProtect virtualizer detected")
            .with_weight(1.0)
    }

    /// Score for a high-entropy file.
    #[must_use]
    pub fn high_entropy(entropy: f64) -> TriageScore {
        let raw = ScoreNormaliser::from_entropy(entropy);
        TriageScore::new(AnalyzerKind::Entropy, raw, format!("entropy={entropy:.3}"))
            .with_weight(0.9)
    }

    /// Score for YARA matches.
    #[must_use]
    pub fn yara_matches(count: usize, max_severity: &str) -> TriageScore {
        let base: u8 = match max_severity.to_lowercase().as_str() {
            "critical" => 90,
            "high" => 65,
            "medium" => 40,
            "low" => 20,
            _ => 10,
        };
        let boosted = u8::try_from((u32::from(base) + u32::try_from(count).unwrap_or(u32::MAX).min(10) * 3).min(100)).unwrap_or(100);
        TriageScore::new(
            AnalyzerKind::Yara,
            boosted,
            format!("{count} YARA rule(s) matched, max_severity={max_severity}"),
        )
        .with_weight(1.5)
    }

    /// Score for suspicious imports.
    #[must_use]
    pub fn suspicious_imports(suspicious: usize, total: usize) -> TriageScore {
        let raw = ScoreNormaliser::from_import_count(suspicious, total);
        TriageScore::new(
            AnalyzerKind::Imports,
            raw,
            format!("{suspicious}/{total} suspicious imports"),
        )
        .with_weight(1.2)
    }
}

// ─── Score filter ─────────────────────────────────────────────────────────────

/// Filter a list of triage scores, keeping only those above a minimum.
#[must_use]
pub fn filter_scores(scores: &[TriageScore], min_raw: u8) -> Vec<&TriageScore> {
    scores.iter().filter(|s| s.raw >= min_raw).collect()
}

/// Deduplicate scores by analyzer kind, keeping the highest raw score per kind.
#[must_use]
pub fn dedup_scores(scores: &[TriageScore]) -> Vec<TriageScore> {
    let mut best: HashMap<String, TriageScore> = HashMap::new();
    for s in scores {
        let key = s.kind.as_str().to_string();
        let entry = best.entry(key).or_insert_with(|| s.clone());
        if s.raw > entry.raw {
            *entry = s.clone();
        }
    }
    let mut result: Vec<TriageScore> = best.into_values().collect();
    result.sort_by(|a, b| b.raw.cmp(&a.raw));
    result
}

// ─── Score report ─────────────────────────────────────────────────────────────

/// A structured report derived from an aggregated score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreReport {
    pub final_score: u8,
    pub label: String,
    pub ci_low: f64,
    pub ci_high: f64,
    pub dominant_analyzer: String,
    pub signals: Vec<ScoreSignalSummary>,
}

/// Summary of one analyzer's contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreSignalSummary {
    pub analyzer: String,
    pub raw_score: u8,
    pub weight: f64,
    pub weighted_contribution: f64,
    pub reason: String,
}

impl ScoreReport {
    #[must_use]
    pub fn from_aggregated(a: &AggregatedScore) -> Self {
        let signals = a
            .breakdown
            .iter()
            .map(|s| ScoreSignalSummary {
                analyzer: s.kind.to_string(),
                raw_score: s.raw,
                weight: s.weight,
                weighted_contribution: s.weighted(),
                reason: s.reason.clone(),
            })
            .collect();
        Self {
            final_score: a.final_score,
            label: a.label.clone(),
            ci_low: a.ci.lower_95,
            ci_high: a.ci.upper_95,
            dominant_analyzer: a.dominant_analyzer.clone(),
            signals,
        }
    }

    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    #[must_use]
    pub fn to_text(&self) -> String {
        use std::fmt::Write as _;
        let mut out = format!(
            "Score: {} | Label: {} | CI: [{:.1}-{:.1}] | Dominant: {}\n",
            self.final_score,
            self.label.to_uppercase(),
            self.ci_low,
            self.ci_high,
            self.dominant_analyzer,
        );
        for sig in &self.signals {
            let _ = writeln!(out,
                "  {:20} raw={:3} w={:.1} contrib={:.1} | {}",
                sig.analyzer, sig.raw_score, sig.weight, sig.weighted_contribution, sig.reason
            );
        }
        out
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregator_empty_returns_clean() {
        let agg = ScoreAggregator::new();
        let result = agg.aggregate(&[]);
        assert_eq!(result.label, "clean");
        assert_eq!(result.final_score, 0);
    }

    #[test]
    fn aggregator_single_critical_score_malicious() {
        let agg = ScoreAggregator::new();
        let scores = vec![TriageScore::new(
            AnalyzerKind::Yara,
            90,
            "critical YARA match",
        )];
        let result = agg.aggregate(&scores);
        assert_eq!(result.label, "malicious");
        assert!(result.final_score >= 60);
    }

    #[test]
    fn aggregator_multiple_scores_blended() {
        let agg = ScoreAggregator::new();
        let scores = vec![
            TriageScore::new(AnalyzerKind::Entropy, 30, "moderate entropy"),
            TriageScore::new(AnalyzerKind::Strings, 25, "suspicious strings"),
            TriageScore::new(AnalyzerKind::Imports, 20, "API calls"),
        ];
        let result = agg.aggregate(&scores);
        assert!(result.final_score > 0 && result.final_score <= 100);
    }

    #[test]
    fn threshold_policy_classify() {
        let policy = ThresholdPolicy::default();
        assert_eq!(policy.classify(0), "clean");
        assert_eq!(policy.classify(19), "clean");
        assert_eq!(policy.classify(20), "suspicious");
        assert_eq!(policy.classify(59), "suspicious");
        assert_eq!(policy.classify(60), "malicious");
    }

    #[test]
    fn threshold_policy_strict() {
        let policy = ThresholdPolicy::strict();

        // strict(): clean_max = 9, suspicious_max = 39, malicious_min = 40.
        //
        // This test previously asserted `classify(10) == "malicious"` while its
        // own comment said the threshold was 40 — it contradicted itself, and
        // the implementation was right. Corrected 2026-07-29 to pin every band
        // AND both boundaries, which is what a threshold test is for.
        assert_eq!(policy.classify(0), "clean");
        assert_eq!(policy.classify(9), "clean", "9 is the last clean score");
        assert_eq!(policy.classify(10), "suspicious", "10 opens the suspicious band");
        assert_eq!(policy.classify(39), "suspicious", "39 is the last suspicious score");
        assert_eq!(policy.classify(40), "malicious", "40 is malicious_min");
        assert_eq!(policy.classify(100), "malicious");
    }

    #[test]
    fn confidence_interval_single_value() {
        let ci = ConfidenceInterval::compute(&[50.0]);
        assert_eq!(ci.point_estimate, 50.0);
        assert_eq!(ci.lower_95, 50.0);
    }

    #[test]
    fn confidence_interval_multiple_values() {
        let ci = ConfidenceInterval::compute(&[40.0, 50.0, 60.0]);
        assert!((ci.point_estimate - 50.0).abs() < 1.0);
        assert!(ci.lower_95 < ci.point_estimate);
        assert!(ci.upper_95 > ci.point_estimate);
    }

    #[test]
    fn score_normaliser_entropy() {
        assert_eq!(ScoreNormaliser::from_entropy(3.0), 0);
        let high = ScoreNormaliser::from_entropy(7.5);
        assert!(high > 50);
    }

    #[test]
    fn score_normaliser_imports() {
        assert_eq!(ScoreNormaliser::from_import_count(0, 100), 0);
        assert_eq!(ScoreNormaliser::from_import_count(100, 100), 100);
        let partial = ScoreNormaliser::from_import_count(10, 100);
        assert_eq!(partial, 10);
    }

    #[test]
    fn score_history_trend() {
        let mut hist = ScoreHistory::new(10);
        hist.push(1, 10);
        hist.push(2, 50);
        hist.push(3, 90);
        assert!(hist.trend() > 0.0);
        assert_eq!(hist.max_score(), 90);
    }

    #[test]
    fn batch_aggregator_rates() {
        let agg_inner = ScoreAggregator::new();
        let clean = agg_inner.aggregate(&[TriageScore::new(AnalyzerKind::Entropy, 5, "low")]);
        let mal = agg_inner.aggregate(&[TriageScore::new(AnalyzerKind::Yara, 90, "critical")]);

        let mut batch = BatchAggregator::new();
        batch.add(&clean);
        batch.add(&mal);
        assert_eq!(batch.total_files, 2);
        assert!((batch.malicious_rate() - 0.5).abs() < 0.01);
    }

    #[test]
    fn triage_score_weighted_contribution() {
        let s = TriageScore::new(AnalyzerKind::Yara, 80, "test")
            .with_weight(2.0)
            .with_confidence(0.5);
        assert!((s.weighted() - 80.0).abs() < 1.0);
    }

    #[test]
    fn analyzer_kind_display() {
        assert_eq!(AnalyzerKind::Yara.as_str(), "yara");
        assert_eq!(
            AnalyzerKind::Custom("myanalyzer".into()).as_str(),
            "myanalyzer"
        );
    }

    #[test]
    fn aggregated_score_summary_format() {
        let agg = ScoreAggregator::new();
        let result = agg.aggregate(&[TriageScore::new(AnalyzerKind::Yara, 70, "test")]);
        let s = result.summary();
        assert!(s.contains("score="));
    }
}
