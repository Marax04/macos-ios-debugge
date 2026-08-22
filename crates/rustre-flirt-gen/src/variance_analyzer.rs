//! Byte-variance analysis for FLIRT pattern generation.
//!
//! Given a set of sample function bodies (same function, multiple compilation
//! units or library versions), the [`VarianceAnalyzer`] identifies byte
//! positions that are *stable* (same value across samples) and marks
//! unstable positions as wildcards.

// ── ByteFreq ──────────────────────────────────────────────────────────────────

/// Frequency counts for all 256 byte values at a single offset.
#[derive(Debug, Clone)]
pub struct ByteFreq {
    /// Byte offset within the function.
    pub offset: usize,
    /// How many times each byte value (0–255) appeared at this offset.
    pub counts: [u32; 256],
    /// Total number of samples that contributed to `counts`.
    pub total: u32,
}

impl ByteFreq {
    /// Create a zero-initialised `ByteFreq` for `offset`.
    #[must_use]
    pub const fn new(offset: usize) -> Self {
        Self {
            offset,
            counts: [0u32; 256],
            total: 0,
        }
    }

    /// Record one occurrence of `byte` at this offset.
    pub const fn record(&mut self, byte: u8) {
        self.counts[byte as usize] += 1;
        self.total += 1;
    }

    /// Return `(most_common_byte, frequency_ratio)`.
    ///
    /// The frequency ratio is the fraction of samples (0.0–1.0) in which the
    /// most common byte appeared.
    ///
    /// # Panics
    ///
    /// Panics if the `counts` array is empty (cannot occur: array size is 256).
    #[must_use]
    pub fn most_common(&self) -> (u8, f64) {
        if self.total == 0 {
            return (0, 0.0);
        }
        let (byte_val, &count) = self
            .counts
            .iter()
            .enumerate()
            .max_by_key(|(_, c)| **c)
            .unwrap(); // safe: array is non-empty
        (u8::try_from(byte_val).unwrap_or(0), f64::from(count) / f64::from(self.total))
    }

    /// Shannon entropy of the byte distribution at this offset (bits).
    ///
    /// Returns 0.0 for positions with no samples.
    #[must_use]
    pub fn entropy(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let total = f64::from(self.total);
        let mut h = 0.0f64;
        for &c in &self.counts {
            if c > 0 {
                let p = f64::from(c) / total;
                h = p.mul_add(-p.log2(), h);
            }
        }
        h
    }
}

// ── VarianceResult ────────────────────────────────────────────────────────────

/// Analysis result for a single byte offset.
#[derive(Debug, Clone)]
pub struct VarianceResult {
    /// Byte offset within the function.
    pub offset: usize,
    /// Shannon entropy at this position.
    pub entropy: f64,
    /// Frequency ratio of the most common byte value.
    pub top_freq: f64,
    /// The most common byte value.
    pub top_byte: u8,
    /// Whether this position is considered stable (low entropy, high frequency).
    pub is_stable: bool,
}

// ── Stability predicate ────────────────────────────────────────────────────────

/// Returns `true` if `freq` represents a *stable* byte position.
///
/// A position is stable when:
/// - its Shannon entropy is below `entropy_threshold`, AND
/// - its most-common-byte frequency is at least `min_freq`.
#[must_use]
pub fn is_stable(freq: &ByteFreq, entropy_threshold: f64, min_freq: f64) -> bool {
    if freq.total == 0 {
        return false;
    }
    let (_, top) = freq.most_common();
    freq.entropy() < entropy_threshold && top >= min_freq
}

// ── VarianceAnalyzer ──────────────────────────────────────────────────────────

/// Analyses a collection of function byte-samples to identify stable positions.
#[derive(Debug, Clone)]
pub struct VarianceAnalyzer {
    /// Maximum Shannon entropy for a position to be considered stable.
    pub entropy_threshold: f64,
    /// Minimum most-common-byte frequency ratio for stability.
    pub min_frequency: f64,
}

impl Default for VarianceAnalyzer {
    fn default() -> Self {
        Self {
            entropy_threshold: 2.0,
            min_frequency: 0.7,
        }
    }
}

impl VarianceAnalyzer {
    /// Create a new analyzer with custom thresholds.
    #[must_use]
    pub const fn new(entropy_threshold: f64, min_frequency: f64) -> Self {
        Self {
            entropy_threshold,
            min_frequency,
        }
    }

    /// Analyse `samples` up to `pattern_len` bytes.
    ///
    /// For each offset `0..pattern_len`, counts byte frequencies across all
    /// samples that are long enough, then classifies each position as stable
    /// or unstable.
    ///
    /// Returns one [`VarianceResult`] per offset.
    #[must_use]
    pub fn analyze(&self, samples: &[&[u8]], pattern_len: usize) -> Vec<VarianceResult> {
        let mut freqs: Vec<ByteFreq> = (0..pattern_len).map(ByteFreq::new).collect();

        for &sample in samples {
            for (off, freq) in freqs.iter_mut().enumerate() {
                if off < sample.len() {
                    freq.record(sample[off]);
                }
            }
        }

        freqs
            .iter()
            .map(|freq| {
                let (top_byte, top_freq) = freq.most_common();
                let entropy = freq.entropy();
                let stable = is_stable(freq, self.entropy_threshold, self.min_frequency);
                VarianceResult {
                    offset: freq.offset,
                    entropy,
                    top_freq,
                    top_byte,
                    is_stable: stable,
                }
            })
            .collect()
    }

    /// Build a pattern vector from variance results and a reference function body.
    ///
    /// - Stable positions → `Some(top_byte)` (from the reference, or `top_byte`).
    /// - Unstable positions → `None` (wildcard).
    #[must_use]
    pub fn build_pattern(results: &[VarianceResult], reference: &[u8]) -> Vec<Option<u8>> {
        results
            .iter()
            .map(|r| {
                if r.is_stable {
                    // Use the reference byte if available, otherwise fall back to
                    // the statistically most common byte.
                    if r.offset < reference.len() {
                        Some(reference[r.offset])
                    } else {
                        Some(r.top_byte)
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// Find the `window_len`-byte window of consecutive *stable* positions
    /// with the best average frequency ratio.
    ///
    /// Returns the start offset of the best window.
    /// Returns 0 if no window contains any stable positions.
    #[must_use]
    pub fn optimal_crc_window(results: &[VarianceResult], window_len: usize) -> usize {
        if results.is_empty() || window_len == 0 {
            return 0;
        }

        let effective_len = window_len.min(results.len());
        let mut best_start = 0usize;
        let mut best_score = -1.0f64;

        let n = results.len();
        for start in 0..n {
            let end = (start + effective_len).min(n);
            let window = &results[start..end];
            let avg_freq: f64 =
                window.iter().map(|r| r.top_freq).sum::<f64>() / f64::from(u32::try_from(window.len()).unwrap_or(u32::MAX));
            if avg_freq > best_score {
                best_score = avg_freq;
                best_start = start;
            }
        }

        best_start
    }

    /// Fraction of non-wildcard bytes in a pattern (0.0 to 1.0).
    #[must_use]
    pub fn quality_score(pattern: &[Option<u8>]) -> f64 {
        if pattern.is_empty() {
            return 0.0;
        }
        let concrete = pattern.iter().filter(|b| b.is_some()).count();
        f64::from(u32::try_from(concrete).unwrap_or(u32::MAX)) / f64::from(u32::try_from(pattern.len()).unwrap_or(u32::MAX))
    }

    /// Length of the pattern up to and including the last non-wildcard byte.
    ///
    /// Returns 0 if the pattern is all wildcards.
    #[must_use]
    pub fn effective_length(pattern: &[Option<u8>]) -> usize {
        pattern
            .iter()
            .enumerate()
            .rev()
            .find(|(_, b)| b.is_some())
            .map_or(0, |(i, _)| i + 1)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ByteFreq ──────────────────────────────────────────────────────────────

    #[test]
    fn test_bytefreq_empty_most_common() {
        let bf = ByteFreq::new(0);
        let (b, f) = bf.most_common();
        assert_eq!(b, 0);
        assert!((f - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_bytefreq_record_and_most_common() {
        let mut bf = ByteFreq::new(0);
        bf.record(0x55);
        bf.record(0x55);
        bf.record(0x8B);
        let (b, f) = bf.most_common();
        assert_eq!(b, 0x55);
        assert!((f - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_bytefreq_entropy_uniform() {
        let mut bf = ByteFreq::new(0);
        // Uniform over 4 values → entropy = log2(4) = 2.0
        for v in [0u8, 1, 2, 3] {
            bf.record(v);
        }
        let h = bf.entropy();
        assert!((h - 2.0).abs() < 1e-9, "entropy={h}");
    }

    #[test]
    fn test_bytefreq_entropy_constant() {
        let mut bf = ByteFreq::new(0);
        for _ in 0..10 {
            bf.record(0x55);
        }
        let h = bf.entropy();
        assert!(h < 1e-9, "entropy of constant should be ~0, got {h}");
    }

    #[test]
    fn test_bytefreq_entropy_empty() {
        let bf = ByteFreq::new(0);
        assert!((bf.entropy() - 0.0).abs() < f64::EPSILON);
    }

    // ── is_stable ─────────────────────────────────────────────────────────────

    #[test]
    fn test_is_stable_constant_byte() {
        let mut bf = ByteFreq::new(0);
        for _ in 0..10 {
            bf.record(0x55);
        }
        assert!(is_stable(&bf, 2.0, 0.7));
    }

    #[test]
    fn test_is_stable_noisy_byte() {
        let mut bf = ByteFreq::new(0);
        for v in 0u8..=9 {
            bf.record(v);
        }
        assert!(!is_stable(&bf, 2.0, 0.7));
    }

    #[test]
    fn test_is_stable_empty_is_false() {
        let bf = ByteFreq::new(0);
        assert!(!is_stable(&bf, 2.0, 0.7));
    }

    // ── VarianceAnalyzer ──────────────────────────────────────────────────────

    #[test]
    fn test_analyze_all_same_bytes() {
        let sample = [0x55u8, 0x8B, 0xEC, 0x83];
        let samples: Vec<&[u8]> = vec![&sample; 10];
        let va = VarianceAnalyzer::default();
        let results = va.analyze(&samples, 4);
        assert_eq!(results.len(), 4);
        assert!(results.iter().all(|r| r.is_stable));
    }

    #[test]
    fn test_analyze_varying_byte_unstable() {
        let mut samples: Vec<Vec<u8>> = Vec::new();
        for v in 0u8..10 {
            samples.push(vec![v, 0x8B, 0xEC]);
        }
        let slices: Vec<&[u8]> = samples.iter().map(std::vec::Vec::as_slice).collect();
        let va = VarianceAnalyzer::default();
        let results = va.analyze(&slices, 3);
        assert!(!results[0].is_stable, "first byte varies");
        assert!(results[1].is_stable, "second byte constant");
    }

    #[test]
    fn test_analyze_empty_samples() {
        let va = VarianceAnalyzer::default();
        let results = va.analyze(&[], 4);
        assert_eq!(results.len(), 4);
        assert!(results.iter().all(|r| !r.is_stable));
    }

    #[test]
    fn test_analyze_pattern_len_zero() {
        let va = VarianceAnalyzer::default();
        let sample = [0x55u8];
        let results = va.analyze(&[&sample], 0);
        assert!(results.is_empty());
    }

    // ── build_pattern ─────────────────────────────────────────────────────────

    #[test]
    fn test_build_pattern_all_stable() {
        let sample = [0x55u8, 0x8B, 0xEC];
        let samples: Vec<&[u8]> = vec![&sample; 5];
        let va = VarianceAnalyzer::default();
        let results = va.analyze(&samples, 3);
        let pat = VarianceAnalyzer::build_pattern(&results, &sample);
        assert_eq!(pat, vec![Some(0x55), Some(0x8B), Some(0xEC)]);
    }

    #[test]
    fn test_build_pattern_unstable_becomes_wildcard() {
        let mut samples: Vec<Vec<u8>> = Vec::new();
        for v in 0u8..10 {
            samples.push(vec![v, 0xCC]);
        }
        let slices: Vec<&[u8]> = samples.iter().map(std::vec::Vec::as_slice).collect();
        let va = VarianceAnalyzer::default();
        let results = va.analyze(&slices, 2);
        let reference = [0x55u8, 0xCC];
        let pat = VarianceAnalyzer::build_pattern(&results, &reference);
        assert!(pat[0].is_none(), "unstable byte should be wildcard");
        assert!(pat[1].is_some(), "stable byte should be Some");
    }

    // ── optimal_crc_window ────────────────────────────────────────────────────

    #[test]
    fn test_optimal_crc_window_all_stable() {
        let sample = [0x55u8; 16];
        let samples: Vec<&[u8]> = vec![&sample; 5];
        let va = VarianceAnalyzer::default();
        let results = va.analyze(&samples, 16);
        let win = VarianceAnalyzer::optimal_crc_window(&results, 4);
        assert!(win < 16);
    }

    #[test]
    fn test_optimal_crc_window_empty_results() {
        let win = VarianceAnalyzer::optimal_crc_window(&[], 4);
        assert_eq!(win, 0);
    }

    #[test]
    fn test_optimal_crc_window_zero_len() {
        let results = vec![VarianceResult {
            offset: 0,
            entropy: 0.0,
            top_freq: 1.0,
            top_byte: 0x55,
            is_stable: true,
        }];
        let win = VarianceAnalyzer::optimal_crc_window(&results, 0);
        assert_eq!(win, 0);
    }

    // ── quality_score ─────────────────────────────────────────────────────────

    #[test]
    fn test_quality_score_all_concrete() {
        let pat = vec![Some(0x55u8); 8];
        assert!((VarianceAnalyzer::quality_score(&pat) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_quality_score_all_wildcard() {
        let pat: Vec<Option<u8>> = vec![None; 8];
        assert!((VarianceAnalyzer::quality_score(&pat) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_quality_score_mixed() {
        let pat: Vec<Option<u8>> = vec![Some(0x55), None, Some(0x8B), None];
        assert!((VarianceAnalyzer::quality_score(&pat) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_quality_score_empty() {
        let pat: Vec<Option<u8>> = vec![];
        assert!((VarianceAnalyzer::quality_score(&pat) - 0.0).abs() < f64::EPSILON);
    }

    // ── effective_length ──────────────────────────────────────────────────────

    #[test]
    fn test_effective_length_no_wildcards() {
        let pat = vec![Some(0x55u8), Some(0x8B), Some(0xEC)];
        assert_eq!(VarianceAnalyzer::effective_length(&pat), 3);
    }

    #[test]
    fn test_effective_length_trailing_wildcards() {
        let pat: Vec<Option<u8>> = vec![Some(0x55), Some(0x8B), None, None];
        assert_eq!(VarianceAnalyzer::effective_length(&pat), 2);
    }

    #[test]
    fn test_effective_length_all_wildcard() {
        let pat: Vec<Option<u8>> = vec![None; 4];
        assert_eq!(VarianceAnalyzer::effective_length(&pat), 0);
    }

    #[test]
    fn test_effective_length_empty() {
        let pat: Vec<Option<u8>> = vec![];
        assert_eq!(VarianceAnalyzer::effective_length(&pat), 0);
    }

    // ── VarianceAnalyzer default ──────────────────────────────────────────────

    #[test]
    fn test_default_thresholds() {
        let va = VarianceAnalyzer::default();
        assert!((va.entropy_threshold - 2.0).abs() < 1e-9);
        assert!((va.min_frequency - 0.7).abs() < 1e-9);
    }

    #[test]
    fn test_custom_thresholds() {
        let va = VarianceAnalyzer::new(1.0, 0.9);
        assert!((va.entropy_threshold - 1.0).abs() < 1e-9);
        assert!((va.min_frequency - 0.9).abs() < 1e-9);
    }
}
