//! Entropy-based deobfuscation quality scoring.
//!
//! [`EntropyScorer`] measures how "well" a candidate decoded byte sequence
//! looks — combining Shannon entropy, printability, and structural magic-byte
//! detection into a [`CompositeScore`].  A [`ScoreHistory`] tracks improvement
//! across successive decode attempts.

use std::collections::VecDeque;

// ─────────────────────────────────────────────────────────────────────────────
// Metric traits
// ─────────────────────────────────────────────────────────────────────────────

/// A scoring metric that maps a byte slice to a `f32` in `[0.0, 1.0]`.
///
/// Higher is better (more natural / more structured).
pub trait DeobfMetric: std::fmt::Debug + Send + Sync {
    /// Short unique name for this metric.
    fn name(&self) -> &str;

    /// Score `data`, returning a value in `[0.0, 1.0]`.
    fn score(&self, data: &[u8]) -> f32;

    /// Weight of this metric in a composite score.  Default is `1.0`.
    fn weight(&self) -> f32 {
        1.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EntropyMetric
// ─────────────────────────────────────────────────────────────────────────────

/// Inverted Shannon entropy metric.
///
/// High entropy (≈ 8.0 bits/byte) indicates encrypted / compressed data and
/// scores `0.0`.  Low entropy (constant or patterned output) scores `1.0`.
///
/// **Note:** very low entropy can also indicate a failed decryption.  Combine
/// with [`PrintabilityMetric`] to disambiguate.
#[derive(Debug, Clone, Default)]
pub struct EntropyMetric;

impl EntropyMetric {
    /// Create a new metric.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compute the Shannon entropy of `data` in bits per byte `[0.0, 8.0]`.
    #[must_use]
    pub fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let n = data.len() as f64;
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / n;
                -p * p.log2()
            })
            .sum()
    }
}

impl DeobfMetric for EntropyMetric {
    fn name(&self) -> &'static str {
        "entropy"
    }

    fn score(&self, data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.5; // neutral for empty input
        }
        let entropy = Self::shannon_entropy(data);
        // Score is inverted and normalised: 0 bits → 1.0, 8 bits → 0.0.
        // We use a non-linear mapping: score = 1 - (entropy/8)^0.6 to reward
        // mildly-low entropy more than extremely-low.
        let norm = (entropy / 8.0).clamp(0.0, 1.0) as f32;
        let score = 1.0 - norm.powf(0.6);
        score.clamp(0.0, 1.0)
    }

    fn weight(&self) -> f32 {
        1.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PrintabilityMetric
// ─────────────────────────────────────────────────────────────────────────────

/// Printable-ASCII content metric.
///
/// Measures the fraction of bytes that are printable ASCII (0x20–0x7E) plus
/// common control characters (tab, newline, carriage return).  Scores `1.0`
/// for fully printable data, `0.0` for fully binary.
#[derive(Debug, Clone)]
pub struct PrintabilityMetric {
    /// Minimum printable fraction to achieve full score.  Default `0.70`.
    pub target_ratio: f32,
}

impl Default for PrintabilityMetric {
    fn default() -> Self {
        Self { target_ratio: 0.70 }
    }
}

impl PrintabilityMetric {
    /// Create a metric with the default target ratio (0.70).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a metric with a custom target ratio.
    #[must_use]
    pub const fn with_target(target_ratio: f32) -> Self {
        // NaN-safe clamp: `f32::clamp` propagates NaN and `is_nan()` is not
        // available in a const fn. `target_ratio` is later used as a divisor,
        // so a NaN here would silently poison every score.
        Self {
            target_ratio: if target_ratio >= 1.0 {
                1.0
            } else if target_ratio > 0.0 {
                target_ratio
            } else {
                0.0
            },
        }
    }

    /// Count printable bytes in `data`.
    #[must_use]
    pub fn printable_count(data: &[u8]) -> usize {
        data.iter()
            .filter(|&&b| matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E))
            .count()
    }

    /// Fraction of `data` that is printable, in `[0.0, 1.0]`.
    #[must_use]
    pub fn printable_ratio(data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }
        Self::printable_count(data) as f32 / data.len() as f32
    }
}

impl DeobfMetric for PrintabilityMetric {
    fn name(&self) -> &'static str {
        "printability"
    }

    fn score(&self, data: &[u8]) -> f32 {
        let ratio = Self::printable_ratio(data);
        // Scale so that `target_ratio` maps to 1.0.
        (ratio / self.target_ratio.max(f32::EPSILON)).clamp(0.0, 1.0)
    }

    fn weight(&self) -> f32 {
        1.2
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StructureMetric
// ─────────────────────────────────────────────────────────────────────────────

/// Structure-detection metric: awards a bonus when decoded bytes contain a
/// recognisable magic signature (ELF, PE, ZIP, PNG, …).
///
/// A structural match is strong evidence of successful decoding.
#[derive(Debug, Clone, Default)]
pub struct StructureMetric;

/// A detected structure in decoded bytes.
#[cfg_attr(any(), derive(Eq))]
#[derive(Debug, Clone, PartialEq)]
pub struct StructureHit {
    /// Name of the structure (e.g. `"ELF"`, `"ZIP"`, `"PNG"`).
    pub name: &'static str,
    /// Byte offset of the hit.
    pub offset: usize,
    /// Confidence of the hit in `[0.0, 1.0]`.
    pub confidence: f32,
}

impl StructureMetric {
    /// Create a new metric.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Scan `data` for known magic signatures.
    #[must_use]
    pub fn detect_structures(data: &[u8]) -> Vec<StructureHit> {
        let mut hits = Vec::new();

        let signatures: &[(&[u8], &'static str, f32)] = &[
            (b"\x7fELF", "ELF", 1.0),
            (b"MZ", "PE", 0.9),
            (b"\x00asm", "WASM", 1.0),
            (b"PK\x03\x04", "ZIP", 1.0),
            (b"%PDF", "PDF", 1.0),
            (b"\x89PNG\r\n\x1a\n", "PNG", 1.0),
            (b"\xff\xd8\xff", "JPEG", 0.9),
            (b"GIF89a", "GIF89a", 1.0),
            (b"GIF87a", "GIF87a", 1.0),
            (b"BZh", "BZIP2", 0.9),
            (b"\x1f\x8b", "GZIP", 0.9),
            (b"Rar!", "RAR", 1.0),
            (b"\x37\x7a\xbc\xaf", "7ZIP", 1.0),
            (b"dex\n", "DEX", 1.0),
            (b"\x1bLua", "Lua", 1.0),
            (b"MSCF", "CAB", 1.0),
            (b"\xcf\xfa\xed\xfe", "MachO-LE64", 1.0),
            (b"\xce\xfa\xed\xfe", "MachO-LE32", 1.0),
        ];

        for (magic, name, confidence) in signatures {
            // Check at offset 0 (and scan through the first 4 KiB for embedded).
            let scan_range = data.len().min(4096).saturating_sub(magic.len());
            for offset in 0..=scan_range {
                if data[offset..].starts_with(magic) {
                    hits.push(StructureHit {
                        name,
                        offset,
                        confidence: *confidence,
                    });
                }
            }
        }

        hits
    }
}

impl DeobfMetric for StructureMetric {
    fn name(&self) -> &'static str {
        "structure"
    }

    fn score(&self, data: &[u8]) -> f32 {
        let hits = Self::detect_structures(data);
        if hits.is_empty() {
            // No known structure — modest neutral score.
            return 0.3;
        }
        // Best confidence among all hits.
        hits.iter()
            .map(|h| h.confidence)
            .fold(0.0f32, f32::max)
            .clamp(0.0, 1.0)
    }

    fn weight(&self) -> f32 {
        1.5
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CompositeScore
// ─────────────────────────────────────────────────────────────────────────────

/// A weighted composite quality score.
#[derive(Debug, Clone, PartialEq)]
pub struct CompositeScore {
    /// Weighted average of all metric scores.
    pub composite: f32,
    /// Individual per-metric scores.
    pub components: Vec<(String, f32)>,
    /// Total weight sum (for debugging).
    pub total_weight: f32,
}

impl CompositeScore {
    /// Return `true` when `composite >= threshold`.
    #[must_use]
    pub fn is_good(&self, threshold: f32) -> bool {
        self.composite >= threshold
    }

    /// Return the score for the named component, if present.
    #[must_use]
    pub fn component(&self, name: &str) -> Option<f32> {
        self.components
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, s)| *s)
    }

    /// Classify the composite score into a human-readable tier.
    #[must_use]
    pub fn tier(&self) -> &'static str {
        if self.composite >= 0.85 {
            "excellent"
        } else if self.composite >= 0.65 {
            "good"
        } else if self.composite >= 0.45 {
            "fair"
        } else if self.composite >= 0.25 {
            "poor"
        } else {
            "bad"
        }
    }
}

impl std::fmt::Display for CompositeScore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.3} ({})", self.composite, self.tier())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EntropyScorer
// ─────────────────────────────────────────────────────────────────────────────

/// Measures the quality of a decoded byte sequence using multiple metrics.
///
/// Combine any number of [`DeobfMetric`] implementations; the scorer computes
/// a weighted average.
pub struct EntropyScorer {
    metrics: Vec<Box<dyn DeobfMetric>>,
}

impl std::fmt::Debug for EntropyScorer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.metrics.iter().map(|m| m.name()).collect();
        f.debug_struct("EntropyScorer")
            .field("metrics", &names)
            .finish_non_exhaustive()
    }
}

impl Default for EntropyScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyScorer {
    /// Create a scorer with the three built-in metrics: entropy, printability,
    /// structure.
    #[must_use]
    pub fn new() -> Self {
        let mut s = Self {
            metrics: Vec::new(),
        };
        s.add_metric(Box::new(EntropyMetric::new()));
        s.add_metric(Box::new(PrintabilityMetric::new()));
        s.add_metric(Box::new(StructureMetric::new()));
        s
    }

    /// Create a scorer with no metrics (use [`add_metric`](Self::add_metric)
    /// to configure it).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            metrics: Vec::new(),
        }
    }

    /// Add a metric.
    pub fn add_metric(&mut self, metric: Box<dyn DeobfMetric>) {
        self.metrics.push(metric);
    }

    /// Score `data` and return a [`CompositeScore`].
    ///
    /// Returns a score of `0.0` when no metrics are registered.
    #[must_use]
    pub fn score(&self, data: &[u8]) -> CompositeScore {
        if self.metrics.is_empty() {
            return CompositeScore {
                composite: 0.0,
                components: vec![],
                total_weight: 0.0,
            };
        }

        let mut weighted_sum = 0.0f32;
        let mut total_weight = 0.0f32;
        let mut components = Vec::with_capacity(self.metrics.len());

        for metric in &self.metrics {
            let s = metric.score(data).clamp(0.0, 1.0);
            let w = metric.weight();
            weighted_sum += s * w;
            total_weight += w;
            components.push((metric.name().to_owned(), s));
        }

        let composite = if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            0.0
        }
        .clamp(0.0, 1.0);

        CompositeScore {
            composite,
            components,
            total_weight,
        }
    }

    /// Compare two byte slices and return which one scores higher.
    ///
    /// Returns `true` when `a` scores at least as well as `b`.
    #[must_use]
    pub fn is_better(&self, a: &[u8], b: &[u8]) -> bool {
        self.score(a).composite >= self.score(b).composite
    }

    /// Number of registered metrics.
    #[must_use]
    pub fn metric_count(&self) -> usize {
        self.metrics.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScoreHistory
// ─────────────────────────────────────────────────────────────────────────────

/// Records composite scores across successive decode attempts so the caller
/// can detect improvement or stagnation.
#[derive(Debug, Clone, Default)]
pub struct ScoreHistory {
    /// Stored scores in chronological order (capped at `capacity`).
    scores: VecDeque<f32>,
    /// Maximum number of entries to keep.
    capacity: usize,
}

impl ScoreHistory {
    /// Create a history with the given `capacity`.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            scores: VecDeque::with_capacity(capacity),
            capacity: capacity.max(1),
        }
    }

    /// Push a score into the history.
    pub fn push(&mut self, score: f32) {
        if self.scores.len() >= self.capacity {
            self.scores.pop_front();
        }
        self.scores.push_back(score.clamp(0.0, 1.0));
    }

    /// Return the most recent score, or `None` if empty.
    #[must_use]
    pub fn latest(&self) -> Option<f32> {
        self.scores.back().copied()
    }

    /// Return the best (highest) score ever recorded.
    #[must_use]
    pub fn best(&self) -> Option<f32> {
        self.scores.iter().copied().reduce(f32::max)
    }

    /// Return the running average of all stored scores.
    #[must_use]
    pub fn average(&self) -> f32 {
        if self.scores.is_empty() {
            return 0.0;
        }
        self.scores.iter().sum::<f32>() / self.scores.len() as f32
    }

    /// `true` when the most recent score is strictly better than the previous.
    #[must_use]
    pub fn is_improving(&self) -> bool {
        if self.scores.len() < 2 {
            return false;
        }
        let n = self.scores.len();
        self.scores[n - 1] > self.scores[n - 2]
    }

    /// `true` when the last `window` scores have not improved by more than `delta`.
    #[must_use]
    pub fn is_stagnant(&self, window: usize, delta: f32) -> bool {
        if self.scores.len() < window {
            return false;
        }
        let tail: Vec<f32> = self.scores.iter().rev().take(window).copied().collect();
        let max = tail.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let min = tail.iter().copied().fold(f32::INFINITY, f32::min);
        (max - min) <= delta
    }

    /// Number of scores recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scores.len()
    }

    /// Returns `true` if no scores have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }

    /// Drain all recorded scores.
    pub fn clear(&mut self) {
        self.scores.clear();
    }

    /// All scores in chronological order.
    #[must_use]
    pub fn all(&self) -> Vec<f32> {
        self.scores.iter().copied().collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EntropyMetric ─────────────────────────────────────────────────────────

    #[test]
    fn test_entropy_uniform_low_score() {
        // Maximum-entropy data → low quality score.
        let data: Vec<u8> = (0..=255).cycle().take(512).collect();
        let m = EntropyMetric::new();
        let s = m.score(&data);
        assert!(s < 0.5, "uniform data should score low, got {s}");
    }

    #[test]
    fn test_entropy_constant_high_score() {
        let data = vec![0xAAu8; 256];
        let m = EntropyMetric::new();
        let s = m.score(&data);
        assert!(s > 0.8, "constant data should score high, got {s}");
    }

    #[test]
    fn test_entropy_empty_neutral() {
        let m = EntropyMetric::new();
        let s = m.score(&[]);
        assert_eq!(s, 0.5);
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        let data: Vec<u8> = (0..=255).collect();
        let e = EntropyMetric::shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "expected ~8.0 bits, got {e}");
    }

    #[test]
    fn test_shannon_entropy_constant() {
        let data = vec![0x42u8; 100];
        assert_eq!(EntropyMetric::shannon_entropy(&data), 0.0);
    }

    // ── PrintabilityMetric ────────────────────────────────────────────────────

    #[test]
    fn test_printability_all_printable() {
        let data = b"Hello, World! This is readable text.";
        let m = PrintabilityMetric::new();
        assert!(m.score(data) >= 1.0);
    }

    #[test]
    fn test_printability_zero_for_binary() {
        let data = vec![0x00u8, 0x01, 0x02, 0x03, 0x04];
        let m = PrintabilityMetric::new();
        let s = m.score(&data);
        assert!(s < 0.1, "binary data should score near 0, got {s}");
    }

    #[test]
    fn test_printability_ratio_half() {
        // 4 printable, 4 non-printable.
        let data = b"ABCD\x00\x01\x02\x03";
        let ratio = PrintabilityMetric::printable_ratio(data);
        assert!((ratio - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_printability_custom_target() {
        // With target=0.5, 50% printable = full score.
        let data = b"ABCD\x00\x01\x02\x03";
        let m = PrintabilityMetric::with_target(0.5);
        let s = m.score(data);
        assert!(s >= 1.0);
    }

    // ── StructureMetric ───────────────────────────────────────────────────────

    #[test]
    fn test_structure_elf_detected() {
        let data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00";
        let hits = StructureMetric::detect_structures(data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].name, "ELF");
    }

    #[test]
    fn test_structure_zip_detected() {
        let data = b"PK\x03\x04extra bytes here";
        let hits = StructureMetric::detect_structures(data);
        assert!(hits.iter().any(|h| h.name == "ZIP"));
    }

    #[test]
    fn test_structure_no_hit_returns_neutral() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02];
        let m = StructureMetric::new();
        let s = m.score(&data);
        assert_eq!(s, 0.3);
    }

    #[test]
    fn test_structure_elf_score_high() {
        let data = b"\x7fELF\x02\x01\x01\x00";
        let m = StructureMetric::new();
        let s = m.score(data);
        assert!(s >= 1.0);
    }

    // ── CompositeScore ────────────────────────────────────────────────────────

    #[test]
    fn test_composite_score_tier() {
        let s = CompositeScore {
            composite: 0.9,
            components: vec![],
            total_weight: 1.0,
        };
        assert_eq!(s.tier(), "excellent");

        let s2 = CompositeScore {
            composite: 0.2,
            components: vec![],
            total_weight: 1.0,
        };
        assert_eq!(s2.tier(), "bad");
    }

    #[test]
    fn test_composite_score_is_good() {
        let s = CompositeScore {
            composite: 0.8,
            components: vec![],
            total_weight: 1.0,
        };
        assert!(s.is_good(0.7));
        assert!(!s.is_good(0.9));
    }

    #[test]
    fn test_composite_score_component_lookup() {
        let s = CompositeScore {
            composite: 0.5,
            components: vec![("entropy".to_owned(), 0.6)],
            total_weight: 1.0,
        };
        assert_eq!(s.component("entropy"), Some(0.6));
        assert_eq!(s.component("missing"), None);
    }

    // ── EntropyScorer ─────────────────────────────────────────────────────────

    #[test]
    fn test_scorer_empty_metrics() {
        let s = EntropyScorer::empty();
        let result = s.score(b"hello");
        assert_eq!(result.composite, 0.0);
    }

    #[test]
    fn test_scorer_elf_scores_high() {
        let data = b"\x7fELF\x02\x01\x01\x00hello world this is some readable text";
        let scorer = EntropyScorer::new();
        let result = scorer.score(data);
        assert!(
            result.composite > 0.4,
            "ELF data should score decently, got {}",
            result.composite
        );
    }

    #[test]
    fn test_scorer_is_better() {
        let scorer = EntropyScorer::new();
        let readable = b"Hello, World! This is a legible string.";
        let random: Vec<u8> = (0..=255u8).cycle().take(40).collect();
        assert!(scorer.is_better(readable, &random));
    }

    #[test]
    fn test_scorer_metric_count() {
        let s = EntropyScorer::new();
        assert_eq!(s.metric_count(), 3);
    }

    #[test]
    fn test_scorer_add_metric() {
        let mut s = EntropyScorer::empty();
        s.add_metric(Box::new(EntropyMetric::new()));
        assert_eq!(s.metric_count(), 1);
    }

    // ── ScoreHistory ─────────────────────────────────────────────────────────

    #[test]
    fn test_history_push_and_latest() {
        let mut h = ScoreHistory::new(5);
        h.push(0.3);
        h.push(0.5);
        h.push(0.7);
        assert_eq!(h.latest(), Some(0.7));
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn test_history_capacity_evicts_oldest() {
        let mut h = ScoreHistory::new(3);
        h.push(0.1);
        h.push(0.2);
        h.push(0.3);
        h.push(0.4); // evicts 0.1
        assert_eq!(h.len(), 3);
        assert!(!h.all().contains(&0.1));
    }

    #[test]
    fn test_history_best() {
        let mut h = ScoreHistory::new(10);
        h.push(0.3);
        h.push(0.9);
        h.push(0.6);
        assert_eq!(h.best(), Some(0.9));
    }

    #[test]
    fn test_history_average() {
        let mut h = ScoreHistory::new(10);
        h.push(0.4);
        h.push(0.6);
        let avg = h.average();
        assert!((avg - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_history_is_improving() {
        let mut h = ScoreHistory::new(10);
        assert!(!h.is_improving());
        h.push(0.4);
        h.push(0.7);
        assert!(h.is_improving());
        h.push(0.6);
        assert!(!h.is_improving());
    }

    #[test]
    fn test_history_is_stagnant() {
        let mut h = ScoreHistory::new(10);
        h.push(0.50);
        h.push(0.51);
        h.push(0.49);
        h.push(0.50);
        assert!(h.is_stagnant(4, 0.05));
        assert!(!h.is_stagnant(4, 0.001));
    }

    #[test]
    fn test_history_empty() {
        let h = ScoreHistory::new(5);
        assert!(h.is_empty());
        assert_eq!(h.latest(), None);
        assert_eq!(h.best(), None);
        assert_eq!(h.average(), 0.0);
    }

    #[test]
    fn test_history_clear() {
        let mut h = ScoreHistory::new(5);
        h.push(0.5);
        h.clear();
        assert!(h.is_empty());
    }

    #[test]
    fn test_history_clamps_score() {
        let mut h = ScoreHistory::new(5);
        h.push(1.5); // should clamp to 1.0
        assert_eq!(h.latest(), Some(1.0));
        h.push(-0.3); // should clamp to 0.0
        assert_eq!(h.latest(), Some(0.0));
    }
}
