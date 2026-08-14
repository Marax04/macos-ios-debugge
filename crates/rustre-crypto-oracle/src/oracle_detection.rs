//! Cryptographic oracle detection and classification: padding oracles,
//! timing oracles, ECB oracles.  Provides fingerprinting, differential
//! testing, behavioural profiling, and false-positive filtering.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// Re-exported so downstream consumers (oracle detectors, exploit drivers) can
// reach for the same primitives this module would use without re-importing
// them from their crate-internal paths.
pub use std::collections::HashMap;
pub use std::time::{Duration, Instant};

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OracleDetectError {
    #[error("insufficient samples: need {need}, have {have}")]
    InsufficientSamples { need: usize, have: usize },
    #[error("oracle query failed: {0}")]
    QueryFailed(String),
    #[error("block size mismatch")]
    BlockSizeMismatch,
    #[error("false positive filter rejected result")]
    FalsePositive,
    #[error("classifier error: {0}")]
    ClassifierError(String),
}

// ── BehaviorProfile ───────────────────────────────────────────────────────────

/// Observed response characteristics from oracle queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorProfile {
    pub response_times_us: Vec<u64>,
    pub response_lengths: Vec<usize>,
    pub status_codes: Vec<u16>,
    pub error_messages: Vec<String>,
}

impl BehaviorProfile {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            response_times_us: Vec::new(),
            response_lengths: Vec::new(),
            status_codes: Vec::new(),
            error_messages: Vec::new(),
        }
    }

    pub fn add_sample(&mut self, time_us: u64, length: usize, status: u16, error: Option<String>) {
        self.response_times_us.push(time_us);
        self.response_lengths.push(length);
        self.status_codes.push(status);
        if let Some(e) = error {
            self.error_messages.push(e);
        }
    }

    #[must_use] 
    pub const fn sample_count(&self) -> usize {
        self.response_times_us.len()
    }

    /// Integer mean response time in µs (avoids f64 casts).
    #[must_use]
    pub fn mean_time_us_int(&self) -> Option<u64> {
        if self.response_times_us.is_empty() {
            return None;
        }
        let sum: u64 = self.response_times_us.iter().copied().fold(0u64, u64::saturating_add);
        let count = u64::try_from(self.response_times_us.len()).unwrap_or(u64::MAX);
        Some(sum / count.max(1))
    }

    #[must_use]
    pub fn mean_time_us(&self) -> Option<f64> {
        if self.response_times_us.is_empty() {
            return None;
        }
        Some(
            f64::from(u32::try_from(self.response_times_us.iter().copied().sum::<u64>()).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.response_times_us.len()).unwrap_or(u32::MAX)),
        )
    }

    #[must_use] 
    pub fn std_dev_time_us(&self) -> Option<f64> {
        let mean = self.mean_time_us()?;
        let n = f64::from(u32::try_from(self.response_times_us.len()).unwrap_or(u32::MAX));
        let variance: f64 = self
            .response_times_us
            .iter()
            .map(|&t| (f64::from(u32::try_from(t).unwrap_or(u32::MAX)) - mean).powi(2))
            .sum::<f64>()
            / n;
        Some(variance.sqrt())
    }

    #[must_use] 
    pub fn mean_length(&self) -> Option<f64> {
        if self.response_lengths.is_empty() {
            return None;
        }
        Some(
            f64::from(u32::try_from(self.response_lengths.iter().copied().sum::<usize>()).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.response_lengths.len()).unwrap_or(u32::MAX)),
        )
    }

    #[must_use] 
    pub fn distinct_status_codes(&self) -> Vec<u16> {
        let mut codes: Vec<u16> = self.status_codes.clone();
        codes.sort_unstable();
        codes.dedup();
        codes
    }

    #[must_use] 
    pub fn distinct_lengths(&self) -> Vec<usize> {
        let mut lens: Vec<usize> = self.response_lengths.clone();
        lens.sort_unstable();
        lens.dedup();
        lens
    }

    /// True if the length distribution is bimodal (padding oracle indicator).
    #[must_use] 
    pub fn is_length_bimodal(&self) -> bool {
        self.distinct_lengths().len() == 2
    }

    /// True if status codes are bimodal (padding oracle indicator).
    #[must_use] 
    pub fn is_status_bimodal(&self) -> bool {
        self.distinct_status_codes().len() == 2
    }
}

impl Default for BehaviorProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ── OracleFingerprint ─────────────────────────────────────────────────────────

/// Fingerprint that characterises one class of oracle responses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OracleFingerprint {
    pub label: String,
    pub expected_status_codes: Vec<u16>,
    pub expected_length_range: (usize, usize),
    pub expected_error_substring: Option<String>,
    pub mean_time_us: Option<f64>,
}

impl OracleFingerprint {
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            expected_status_codes: Vec::new(),
            expected_length_range: (0, usize::MAX),
            expected_error_substring: None,
            mean_time_us: None,
        }
    }

    /// Check if a single response sample matches this fingerprint.
    #[must_use] 
    pub fn matches(&self, status: u16, length: usize, error: Option<&str>) -> bool {
        let status_ok =
            self.expected_status_codes.is_empty() || self.expected_status_codes.contains(&status);
        let length_ok =
            length >= self.expected_length_range.0 && length <= self.expected_length_range.1;
        let error_ok = self.expected_error_substring.as_ref()
            .is_none_or(|sub| error.is_some_and(|e| e.contains(sub.as_str())));
        status_ok && length_ok && error_ok
    }
}

// ── DifferentialTester ────────────────────────────────────────────────────────

/// Applies differential queries to detect oracle behaviour.
///
/// The tester sends valid and invalid ciphertexts (or ciphertexts with
/// modified padding bytes) and compares the two resulting behaviour profiles.
pub struct DifferentialTester {
    pub valid_profile: BehaviorProfile,
    pub invalid_profile: BehaviorProfile,
}

impl DifferentialTester {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            valid_profile: BehaviorProfile::new(),
            invalid_profile: BehaviorProfile::new(),
        }
    }

    pub fn record_valid(&mut self, time_us: u64, len: usize, status: u16, error: Option<String>) {
        self.valid_profile.add_sample(time_us, len, status, error);
    }

    pub fn record_invalid(&mut self, time_us: u64, len: usize, status: u16, error: Option<String>) {
        self.invalid_profile.add_sample(time_us, len, status, error);
    }

    /// Compute timing difference between valid and invalid responses (µs).
    #[must_use]
    pub fn timing_delta_us(&self) -> Option<f64> {
        let m_valid = self.valid_profile.mean_time_us()?;
        let m_invalid = self.invalid_profile.mean_time_us()?;
        Some((m_valid - m_invalid).abs())
    }

    /// Integer timing delta in µs (avoids f64 casts).
    #[must_use]
    pub fn timing_delta_us_int(&self) -> Option<u64> {
        let m_valid = self.valid_profile.mean_time_us_int()?;
        let m_invalid = self.invalid_profile.mean_time_us_int()?;
        Some(m_valid.abs_diff(m_invalid))
    }

    /// True if a statistically significant timing difference is observed.
    #[must_use] 
    pub fn has_timing_difference(&self, threshold_us: f64) -> bool {
        self.timing_delta_us()
            .is_some_and(|d| d > threshold_us)
    }

    /// True if the length distributions differ between valid and invalid.
    #[must_use] 
    pub fn has_length_difference(&self) -> bool {
        let vl = self.valid_profile.mean_length();
        let il = self.invalid_profile.mean_length();
        match (vl, il) {
            (Some(v), Some(i)) => (v - i).abs() > 0.5,
            _ => false,
        }
    }

    /// True if the status-code distributions differ.
    #[must_use] 
    pub fn has_status_difference(&self) -> bool {
        let vs = self.valid_profile.distinct_status_codes();
        let is = self.invalid_profile.distinct_status_codes();
        vs != is
    }
}

impl Default for DifferentialTester {
    fn default() -> Self {
        Self::new()
    }
}

// ── OracleClassifier ─────────────────────────────────────────────────────────

/// Classification result produced by the oracle analyser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OracleClass {
    PaddingOracle,
    TimingOracle,
    EcbOracle,
    LengthOracle,
    ErrorMessageOracle,
    NoOracle,
}

/// Classifies oracle type from differential test results.
pub struct OracleClassifier;

impl OracleClassifier {
    /// Classify the oracle type given a differential tester snapshot.
    #[must_use] 
    pub fn classify(tester: &DifferentialTester) -> OracleClass {
        // ECB: look for repeating blocks in valid responses (handled separately)
        // Padding oracle: status or length difference without timing
        // Timing oracle: significant timing difference
        let has_time = tester.has_timing_difference(500.0); // 500 µs threshold
        let has_len = tester.has_length_difference();
        let has_stat = tester.has_status_difference();

        if has_time && !has_len && !has_stat {
            OracleClass::TimingOracle
        } else if has_stat || has_len {
            OracleClass::PaddingOracle
        } else if has_time {
            OracleClass::TimingOracle
        } else {
            OracleClass::NoOracle
        }
    }

    /// Check for ECB mode by detecting repeating 16-byte blocks.
    #[must_use] 
    pub fn detect_ecb(ciphertexts: &[Vec<u8>], block_size: usize) -> bool {
        for ct in ciphertexts {
            if ct.len() < block_size * 2 {
                continue;
            }
            let blocks: Vec<&[u8]> = ct.chunks(block_size).collect();
            let n = blocks.len();
            for i in 0..n {
                for j in (i + 1)..n {
                    if blocks[i] == blocks[j] {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Estimate the block size used by the oracle by observing length jumps.
    #[must_use] 
    pub fn estimate_block_size(response_lengths: &[usize]) -> Option<usize> {
        let mut sorted = response_lengths.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() < 2 {
            return None;
        }
        let diff = sorted[1].saturating_sub(sorted[0]);
        if diff == 0 {
            return None;
        }
        // Block size must be a power of 2 between 8 and 64.
        // Prefer the largest matching block size, since e.g. a delta of 16
        // is divisible by both 8 and 16 but 16 is the real cipher block size.
        for bs in [64, 32, 16, 8] {
            if diff.is_multiple_of(bs) {
                return Some(bs);
            }
        }
        Some(diff)
    }
}

// ── FalsePositiveFilter ───────────────────────────────────────────────────────

/// Filters out false positive oracle detections.
pub struct FalsePositiveFilter {
    /// Minimum number of samples required.
    pub min_samples: usize,
    /// Maximum coefficient of variation for timing to accept as oracle.
    pub max_time_cv: f64,
    /// Minimum number of distinct status codes.
    pub min_distinct_statuses: usize,
}

impl FalsePositiveFilter {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            min_samples: 10,
            max_time_cv: 1.0,
            min_distinct_statuses: 2,
        }
    }

    /// Apply filter. Returns `Ok(())` if the detection appears genuine.
    ///
    /// # Errors
    /// Returns `OracleDetectError::InsufficientSamples` or `OracleDetectError::FalsePositive`
    /// if the detection is rejected.
    pub fn validate(
        &self,
        tester: &DifferentialTester,
        class: OracleClass,
    ) -> Result<(), OracleDetectError> {
        if tester.valid_profile.sample_count() < self.min_samples {
            return Err(OracleDetectError::InsufficientSamples {
                need: self.min_samples,
                have: tester.valid_profile.sample_count(),
            });
        }

        match class {
            OracleClass::TimingOracle => {
                // Check coefficient of variation: if noise is too high, reject
                if let (Some(mean), Some(std)) = (
                    tester.valid_profile.mean_time_us(),
                    tester.valid_profile.std_dev_time_us(),
                ) {
                    let cv = std / mean;
                    if cv > self.max_time_cv {
                        return Err(OracleDetectError::FalsePositive);
                    }
                }
            }
            OracleClass::PaddingOracle => {
                let valid_statuses = tester.valid_profile.distinct_status_codes().len();
                let invalid_statuses = tester.invalid_profile.distinct_status_codes().len();
                if valid_statuses + invalid_statuses < self.min_distinct_statuses {
                    return Err(OracleDetectError::FalsePositive);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl Default for FalsePositiveFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ── OracleDetection ───────────────────────────────────────────────────────────

/// Boolean signals from the oracle detection pipeline, packed as a bitmask.
///
/// | bit | meaning             |
/// |-----|---------------------|
/// | 0   | `length_difference` |
/// | 1   | `status_difference` |
/// | 2   | `ecb_detected`      |
/// | 3   | `is_false_positive` |
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct OracleSignals(pub u8);

impl OracleSignals {
    const LENGTH_DIFFERENCE: u8 = 1;
    const STATUS_DIFFERENCE: u8 = 2;
    const ECB_DETECTED: u8 = 4;
    const IS_FALSE_POSITIVE: u8 = 8;

    /// Build `OracleSignals` from a `(length_difference, status_difference, ecb_detected, is_false_positive)` tuple.
    #[must_use]
    pub const fn from_tuple(flags: (bool, bool, bool, bool)) -> Self {
        let (length_difference, status_difference, ecb_detected, is_false_positive) = flags;
        let mut bits = 0u8;
        if length_difference  { bits |= Self::LENGTH_DIFFERENCE; }
        if status_difference  { bits |= Self::STATUS_DIFFERENCE; }
        if ecb_detected       { bits |= Self::ECB_DETECTED; }
        if is_false_positive  { bits |= Self::IS_FALSE_POSITIVE; }
        Self(bits)
    }

    /// Response length differed between valid and invalid queries.
    #[must_use] pub const fn length_difference(self) -> bool  { self.0 & Self::LENGTH_DIFFERENCE  != 0 }
    /// HTTP/application status code differed.
    #[must_use] pub const fn status_difference(self) -> bool  { self.0 & Self::STATUS_DIFFERENCE  != 0 }
    /// ECB mode block pattern detected.
    #[must_use] pub const fn ecb_detected(self) -> bool       { self.0 & Self::ECB_DETECTED       != 0 }
    /// Detection classified as a false positive.
    #[must_use] pub const fn is_false_positive(self) -> bool  { self.0 & Self::IS_FALSE_POSITIVE  != 0 }
}

/// Complete oracle detection pipeline result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleDetection {
    pub target: String,
    pub oracle_class: OracleClass,
    pub confidence: u8, // 0-100
    pub fingerprints: Vec<OracleFingerprint>,
    pub timing_delta_us: Option<f64>,
    pub signals: OracleSignals,
    pub estimated_block_size: Option<usize>,
    pub notes: Vec<String>,
}

impl OracleDetection {
    #[must_use]
    pub fn no_oracle(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            oracle_class: OracleClass::NoOracle,
            confidence: 0,
            fingerprints: Vec::new(),
            timing_delta_us: None,
            signals: OracleSignals::default(),
            estimated_block_size: None,
            notes: Vec::new(),
        }
    }

    /// Run a full detection pass.
    #[must_use]
    pub fn run(
        target: impl Into<String>,
        tester: &DifferentialTester,
        ciphertexts: &[Vec<u8>],
        block_size: usize,
        filter: &FalsePositiveFilter,
    ) -> Self {
        let class = OracleClassifier::classify(tester);
        let ecb = OracleClassifier::detect_ecb(ciphertexts, block_size);
        let final_class = if ecb && class == OracleClass::NoOracle {
            OracleClass::EcbOracle
        } else {
            class
        };

        let is_fp = filter.validate(tester, final_class).is_err();

        let confidence = if is_fp {
            0
        } else {
            match final_class {
                OracleClass::PaddingOracle => {
                    let base: u8 = 60;
                    let extra = if tester.has_status_difference() {
                        25
                    } else {
                        0
                    } + if tester.has_length_difference() {
                        15
                    } else {
                        0
                    };
                    (base + extra).min(100)
                }
                OracleClass::TimingOracle => {
                    // delta is µs; 5000 µs → 100% confidence (integer path, no f64 cast)
                    let delta_us = tester.timing_delta_us_int().unwrap_or(0);
                    if delta_us >= 5_000 {
                        100u8
                    } else {
                        // delta_us ∈ [0, 4999]; product ≤ 499 900 fits u64; result ≤ 99
                        u8::try_from(delta_us * 100 / 5_000).unwrap_or(99)
                    }
                }
                OracleClass::EcbOracle => 90,
                OracleClass::NoOracle => 0,
                _ => 50,
            }
        };

        let lens: Vec<usize> = tester
            .valid_profile
            .response_lengths
            .iter()
            .chain(tester.invalid_profile.response_lengths.iter())
            .copied()
            .collect();
        let est_bs = OracleClassifier::estimate_block_size(&lens);

        Self {
            target: target.into(),
            oracle_class: final_class,
            confidence,
            fingerprints: Vec::new(),
            timing_delta_us: tester.timing_delta_us(),
            signals: OracleSignals::from_tuple((
                tester.has_length_difference(),
                tester.has_status_difference(),
                ecb,
                is_fp,
            )),
            estimated_block_size: est_bs,
            notes: Vec::new(),
        }
    }

    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    #[must_use]
    pub fn is_oracle_found(&self) -> bool {
        self.oracle_class != OracleClass::NoOracle && !self.signals.is_false_positive()
    }

    /// Convenience accessor for `signals.length_difference`.
    #[must_use]
    pub const fn length_difference(&self) -> bool { self.signals.length_difference() }

    /// Convenience accessor for `signals.status_difference`.
    #[must_use]
    pub const fn status_difference(&self) -> bool { self.signals.status_difference() }

    /// Convenience accessor for `signals.ecb_detected`.
    #[must_use]
    pub const fn ecb_detected(&self) -> bool { self.signals.ecb_detected() }

    /// Convenience accessor for `signals.is_false_positive`.
    #[must_use]
    pub const fn is_false_positive(&self) -> bool { self.signals.is_false_positive() }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── BehaviorProfile tests ────────────────────────────────────────────────

    #[test]
    fn test_behavior_profile_add_sample() {
        let mut p = BehaviorProfile::new();
        p.add_sample(1000, 128, 200, None);
        p.add_sample(1100, 128, 200, None);
        assert_eq!(p.sample_count(), 2);
    }

    #[test]
    fn test_behavior_profile_mean_time() {
        let mut p = BehaviorProfile::new();
        p.add_sample(1000, 0, 200, None);
        p.add_sample(2000, 0, 200, None);
        let m = p.mean_time_us().unwrap();
        assert!((m - 1500.0).abs() < 1.0);
    }

    #[test]
    fn test_behavior_profile_std_dev() {
        let mut p = BehaviorProfile::new();
        for v in [100u64, 200, 300, 400, 500] {
            p.add_sample(v, 0, 200, None);
        }
        let sd = p.std_dev_time_us().unwrap();
        assert!(sd > 0.0);
    }

    #[test]
    fn test_behavior_profile_distinct_statuses() {
        let mut p = BehaviorProfile::new();
        p.add_sample(100, 10, 200, None);
        p.add_sample(100, 20, 500, None);
        p.add_sample(100, 10, 200, None);
        let codes = p.distinct_status_codes();
        assert_eq!(codes.len(), 2);
        assert!(codes.contains(&200));
        assert!(codes.contains(&500));
    }

    #[test]
    fn test_behavior_profile_bimodal_length() {
        let mut p = BehaviorProfile::new();
        p.add_sample(100, 128, 200, None);
        p.add_sample(100, 128, 200, None);
        p.add_sample(100, 256, 500, None);
        assert!(p.is_length_bimodal());
    }

    #[test]
    fn test_behavior_profile_not_bimodal_length() {
        let mut p = BehaviorProfile::new();
        p.add_sample(100, 128, 200, None);
        assert!(!p.is_length_bimodal());
    }

    #[test]
    fn test_behavior_profile_mean_empty() {
        let p = BehaviorProfile::new();
        assert!(p.mean_time_us().is_none());
        assert!(p.mean_length().is_none());
    }

    // ── OracleFingerprint tests ──────────────────────────────────────────────

    #[test]
    fn test_fingerprint_matches_status() {
        let mut fp = OracleFingerprint::new("padding");
        fp.expected_status_codes = vec![500];
        assert!(fp.matches(500, 100, None));
        assert!(!fp.matches(200, 100, None));
    }

    #[test]
    fn test_fingerprint_matches_length_range() {
        let mut fp = OracleFingerprint::new("test");
        fp.expected_length_range = (100, 200);
        assert!(fp.matches(200, 150, None));
        assert!(!fp.matches(200, 50, None));
    }

    #[test]
    fn test_fingerprint_matches_error_substring() {
        let mut fp = OracleFingerprint::new("padding");
        fp.expected_error_substring = Some("padding".into());
        assert!(fp.matches(500, 100, Some("bad padding error")));
        assert!(!fp.matches(500, 100, None));
    }

    // ── DifferentialTester tests ─────────────────────────────────────────────

    #[test]
    fn test_differential_timing_difference() {
        let mut dt = DifferentialTester::new();
        for _ in 0..10 {
            dt.record_valid(5000, 200, 200, None);
        }
        for _ in 0..10 {
            dt.record_invalid(1000, 200, 200, None);
        }
        assert!(dt.has_timing_difference(500.0));
    }

    #[test]
    fn test_differential_no_timing_difference() {
        let mut dt = DifferentialTester::new();
        for _ in 0..5 {
            dt.record_valid(1000, 200, 200, None);
        }
        for _ in 0..5 {
            dt.record_invalid(1010, 200, 200, None);
        }
        assert!(!dt.has_timing_difference(500.0));
    }

    #[test]
    fn test_differential_length_difference() {
        let mut dt = DifferentialTester::new();
        dt.record_valid(100, 256, 200, None);
        dt.record_invalid(100, 128, 500, None);
        assert!(dt.has_length_difference());
    }

    #[test]
    fn test_differential_status_difference() {
        let mut dt = DifferentialTester::new();
        dt.record_valid(100, 128, 200, None);
        dt.record_invalid(100, 128, 403, None);
        assert!(dt.has_status_difference());
    }

    #[test]
    fn test_differential_timing_delta() {
        let mut dt = DifferentialTester::new();
        dt.record_valid(2000, 128, 200, None);
        dt.record_invalid(1000, 128, 200, None);
        let delta = dt.timing_delta_us().unwrap();
        assert!((delta - 1000.0).abs() < 1.0);
    }

    // ── OracleClassifier tests ───────────────────────────────────────────────

    #[test]
    fn test_classify_padding_oracle() {
        let mut dt = DifferentialTester::new();
        for _ in 0..5 {
            dt.record_valid(100, 200, 200, None);
        }
        for _ in 0..5 {
            dt.record_invalid(100, 200, 403, None);
        }
        assert_eq!(OracleClassifier::classify(&dt), OracleClass::PaddingOracle);
    }

    #[test]
    fn test_classify_timing_oracle() {
        let mut dt = DifferentialTester::new();
        for _ in 0..5 {
            dt.record_valid(10000, 200, 200, None);
        }
        for _ in 0..5 {
            dt.record_invalid(1000, 200, 200, None);
        }
        assert_eq!(OracleClassifier::classify(&dt), OracleClass::TimingOracle);
    }

    #[test]
    fn test_classify_no_oracle() {
        let mut dt = DifferentialTester::new();
        for _ in 0..5 {
            dt.record_valid(1000, 200, 200, None);
        }
        for _ in 0..5 {
            dt.record_invalid(1000, 200, 200, None);
        }
        assert_eq!(OracleClassifier::classify(&dt), OracleClass::NoOracle);
    }

    #[test]
    fn test_detect_ecb_repeating_blocks() {
        let block = vec![0xABu8; 16];
        let mut ct = vec![0u8; 16];
        ct.extend_from_slice(&block);
        ct.extend_from_slice(&block);
        assert!(OracleClassifier::detect_ecb(&[ct], 16));
    }

    #[test]
    fn test_detect_ecb_no_repeating_blocks() {
        let ct = (0..48u8).collect::<Vec<u8>>();
        assert!(!OracleClassifier::detect_ecb(&[ct], 16));
    }

    #[test]
    fn test_estimate_block_size() {
        let lens = vec![32, 48, 64];
        assert_eq!(OracleClassifier::estimate_block_size(&lens), Some(16));
    }

    #[test]
    fn test_estimate_block_size_none_single() {
        let lens = vec![32];
        assert!(OracleClassifier::estimate_block_size(&lens).is_none());
    }

    // ── FalsePositiveFilter tests ────────────────────────────────────────────

    #[test]
    fn test_filter_insufficient_samples() {
        let dt = DifferentialTester::new();
        let filter = FalsePositiveFilter::new();
        let err = filter.validate(&dt, OracleClass::TimingOracle).unwrap_err();
        assert!(matches!(err, OracleDetectError::InsufficientSamples { .. }));
    }

    #[test]
    fn test_filter_padding_oracle_valid() {
        let mut dt = DifferentialTester::new();
        for _ in 0..10 {
            dt.record_valid(100, 200, 200, None);
        }
        for _ in 0..10 {
            dt.record_invalid(100, 200, 500, None);
        }
        let filter = FalsePositiveFilter::new();
        assert!(filter.validate(&dt, OracleClass::PaddingOracle).is_ok());
    }

    #[test]
    fn test_filter_timing_high_noise_rejected() {
        let mut dt = DifferentialTester::new();
        // Very noisy timing: CV will be high
        for v in [1u64, 100_000, 50, 90_000, 200, 80_000, 10, 70_000, 5, 60_000] {
            dt.record_valid(v, 200, 200, None);
        }
        for _ in 0..10 {
            dt.record_invalid(100, 200, 200, None);
        }
        let filter = FalsePositiveFilter::new();
        let result = filter.validate(&dt, OracleClass::TimingOracle);
        assert!(result.is_err());
    }

    // ── OracleDetection top-level tests ─────────────────────────────────────

    #[test]
    fn test_oracle_detection_no_oracle() {
        let det = OracleDetection::no_oracle("https://example.com");
        assert!(!det.is_oracle_found());
        assert_eq!(det.oracle_class, OracleClass::NoOracle);
    }

    #[test]
    fn test_oracle_detection_padding_oracle() {
        let mut dt = DifferentialTester::new();
        for _ in 0..15 {
            dt.record_valid(100, 200, 200, None);
        }
        for _ in 0..15 {
            dt.record_invalid(100, 200, 403, None);
        }
        let filter = FalsePositiveFilter::new();
        let det = OracleDetection::run("https://target.example.com/decrypt", &dt, &[], 16, &filter);
        assert_eq!(det.oracle_class, OracleClass::PaddingOracle);
        assert!(det.is_oracle_found());
        assert!(det.confidence > 0);
    }

    #[test]
    fn test_oracle_detection_ecb_oracle() {
        let mut dt = DifferentialTester::new();
        for _ in 0..15 {
            dt.record_valid(100, 200, 200, None);
        }
        for _ in 0..15 {
            dt.record_invalid(100, 200, 200, None);
        }
        // craft a ciphertext with repeating 16-byte blocks
        let block = vec![0xFEu8; 16];
        let mut ct = Vec::new();
        ct.extend_from_slice(&block);
        ct.extend_from_slice(&block);
        let filter = FalsePositiveFilter::new();
        let det = OracleDetection::run("ecb_target", &dt, &[ct], 16, &filter);
        assert_eq!(det.oracle_class, OracleClass::EcbOracle);
        assert!(det.ecb_detected());
    }

    #[test]
    fn test_oracle_detection_add_note() {
        let mut det = OracleDetection::no_oracle("t");
        det.add_note("found CBC with static IV");
        assert_eq!(det.notes.len(), 1);
    }

    #[test]
    fn test_oracle_detection_false_positive_flag() {
        let dt = DifferentialTester::new();
        let filter = FalsePositiveFilter::new();
        let det = OracleDetection::run("nosamples", &dt, &[], 16, &filter);
        assert!(det.is_false_positive());
        assert!(!det.is_oracle_found());
    }

    #[test]
    fn test_behavior_profile_is_status_bimodal() {
        let mut p = BehaviorProfile::new();
        p.add_sample(100, 200, 200, None);
        p.add_sample(100, 200, 403, None);
        assert!(p.is_status_bimodal());
    }

    #[test]
    fn test_behavior_profile_not_status_bimodal() {
        let mut p = BehaviorProfile::new();
        p.add_sample(100, 200, 200, None);
        p.add_sample(100, 200, 200, None);
        assert!(!p.is_status_bimodal());
    }

    #[test]
    fn test_differential_no_length_difference_equal() {
        let mut dt = DifferentialTester::new();
        for _ in 0..5 {
            dt.record_valid(100, 200, 200, None);
        }
        for _ in 0..5 {
            dt.record_invalid(100, 200, 200, None);
        }
        assert!(!dt.has_length_difference());
    }

    #[test]
    fn test_estimate_block_size_none_empty() {
        assert!(OracleClassifier::estimate_block_size(&[]).is_none());
    }

    #[test]
    fn test_fingerprint_empty_status_codes_matches_any() {
        let fp = OracleFingerprint::new("any");
        assert!(fp.matches(200, 100, None));
        assert!(fp.matches(500, 100, None));
    }

    #[test]
    fn test_oracle_no_oracle_class() {
        let det = OracleDetection::no_oracle("target");
        assert_eq!(det.oracle_class, OracleClass::NoOracle);
        assert_eq!(det.confidence, 0);
        assert!(!det.ecb_detected());
    }

    #[test]
    fn test_false_positive_filter_custom_min_samples() {
        let mut filter = FalsePositiveFilter::new();
        filter.min_samples = 5;
        let mut dt = DifferentialTester::new();
        for _ in 0..5 {
            dt.record_valid(100, 200, 200, None);
        }
        for _ in 0..5 {
            dt.record_invalid(100, 200, 500, None);
        }
        assert!(filter.validate(&dt, OracleClass::PaddingOracle).is_ok());
    }

    #[test]
    fn test_ecb_detection_short_ciphertext() {
        // block too short to compare
        let ct = vec![0xABu8; 10];
        assert!(!OracleClassifier::detect_ecb(&[ct], 16));
    }

    #[test]
    fn test_timing_delta_none_empty() {
        let dt = DifferentialTester::new();
        assert!(dt.timing_delta_us().is_none());
    }

    #[test]
    fn test_behavior_profile_mean_length() {
        let mut p = BehaviorProfile::new();
        p.add_sample(0, 100, 200, None);
        p.add_sample(0, 200, 200, None);
        let m = p.mean_length().unwrap();
        assert!((m - 150.0).abs() < 1.0);
    }
}
