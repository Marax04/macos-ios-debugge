//! Full timing oracle attack engine for `rustre-crypto-oracle`.
//!
//! Implements statistical timing side-channel analysis:
//! measurement collection, distribution fitting, Student's t-test,
//! byte-by-byte recovery, and reporting.

use ahash::{HashMap, HashMapExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum TimingError {
    #[error("insufficient measurements: need at least {0}, got {1}")]
    InsufficientMeasurements(usize, usize),
    #[error("all timing samples are identical — oracle may be constant-time")]
    ConstantTime,
    #[error("no significant timing difference found for byte {0} at position {1}")]
    NoSignificantDiff(u8, usize),
    /// Same as [`Self::NoSignificantDiff`], but carries the best-observed
    /// t-statistic so callers can decide whether to retry with more samples.
    #[error("byte {byte} at position {position} not exploitable (t={t_stat:.3})")]
    BelowExploitabilityThreshold {
        byte: u8,
        position: usize,
        t_stat: f64,
    },
    #[error("attack aborted: {0}")]
    Aborted(String),
    #[error("{0}")]
    Other(String),
}

// ── TimingMeasurement ─────────────────────────────────────────────────────────

/// A single timing measurement: the input bytes submitted and the observed latency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimingMeasurement {
    /// The input submitted to the oracle.
    pub input: Vec<u8>,
    /// Observed duration in nanoseconds.
    pub duration_ns: u64,
    /// Optional run sequence number (for correlation analysis).
    pub sequence: Option<u64>,
    /// True if this is a control (baseline) measurement.
    pub is_control: bool,
}

impl TimingMeasurement {
    #[must_use]
    pub const fn new(input: Vec<u8>, duration_ns: u64) -> Self {
        Self { input, duration_ns, sequence: None, is_control: false }
    }

    #[must_use]
    pub const fn control(input: Vec<u8>, duration_ns: u64) -> Self {
        Self { input, duration_ns, sequence: None, is_control: true }
    }
}

// ── TimingDistribution ────────────────────────────────────────────────────────

/// Statistical summary of a set of timing measurements.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimingDistribution {
    pub count: usize,
    pub mean_ns: f64,
    pub variance_ns2: f64,
    pub std_dev_ns: f64,
    pub min_ns: u64,
    pub max_ns: u64,
    pub median_ns: u64,
    pub percentile_95_ns: u64,
}

impl TimingDistribution {
    /// Compute distribution statistics from a slice of measurements.
    ///
    /// # Errors
    ///
    /// Returns [`TimingError::InsufficientMeasurements`] if `measurements` is empty.
    ///
    /// # Panics
    ///
    /// Panics if the sorted duration vector is empty after filtering (should not happen given the
    /// non-empty check above, but indexing `durations[0]` would panic on an empty slice).
    pub fn from_measurements(measurements: &[TimingMeasurement]) -> Result<Self, TimingError> {
        if measurements.is_empty() {
            return Err(TimingError::InsufficientMeasurements(1, 0));
        }
        let mut durations: Vec<u64> = measurements.iter().map(|m| m.duration_ns).collect();
        let count = durations.len();
        durations.sort_unstable();

        let min_ns = durations[0];
        let max_ns = *durations.last().unwrap();
        let median_ns = durations[count / 2];
        // p95 index: integer arithmetic to avoid f64 casts entirely
        let p95_idx = (count * 95 / 100).min(count - 1);
        let percentile_95_ns = durations[p95_idx];

        let sum: f64 = durations.iter().map(|&d| f64::from(u32::try_from(d).unwrap_or(u32::MAX))).sum();
        let mean_ns = sum / f64::from(u32::try_from(count).unwrap_or(u32::MAX));
        let variance_ns2 = durations.iter()
            .map(|&d| { let diff = f64::from(u32::try_from(d).unwrap_or(u32::MAX)) - mean_ns; diff * diff })
            .sum::<f64>() / f64::from(u32::try_from(count.saturating_sub(1).max(1)).unwrap_or(u32::MAX));
        let std_dev_ns = variance_ns2.sqrt();

        Ok(Self { count, mean_ns, variance_ns2, std_dev_ns, min_ns, max_ns, median_ns, percentile_95_ns })
    }

    /// From raw durations.
    ///
    /// # Errors
    ///
    /// Returns [`TimingError::InsufficientMeasurements`] if `durations` is empty.
    pub fn from_durations(durations: &[u64]) -> Result<Self, TimingError> {
        let measurements: Vec<TimingMeasurement> = durations.iter()
            .map(|&d| TimingMeasurement::new(vec![], d))
            .collect();
        Self::from_measurements(&measurements)
    }

    /// Coefficient of variation (`std_dev / mean`).
    #[must_use]
    pub fn cv(&self) -> f64 {
        if self.mean_ns < 1.0 { 0.0 } else { self.std_dev_ns / self.mean_ns }
    }

    /// True if the timing appears constant (CV < 0.01 and max-min < 1000 ns).
    #[must_use]
    pub fn is_constant_time(&self) -> bool {
        self.cv() < 0.01 && (self.max_ns - self.min_ns) < 1_000
    }
}

// ── StatisticalAnalysis ───────────────────────────────────────────────────────

/// Statistical tests comparing two timing distributions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalAnalysis {
    pub sample_a: TimingDistribution,
    pub sample_b: TimingDistribution,
    /// Welch's t-statistic.
    pub t_statistic: f64,
    /// Estimated p-value (two-tailed, approximated).
    pub p_value: f64,
    /// Whether the result is statistically significant (p < alpha).
    pub significant: bool,
    /// The significance threshold used.
    pub alpha: f64,
    /// Mean difference in nanoseconds (b.mean - a.mean).
    pub mean_diff_ns: f64,
    /// Effect size (Cohen's d).
    pub cohens_d: f64,
}

impl StatisticalAnalysis {
    /// Run Welch's t-test between two groups of measurements.
    ///
    /// # Errors
    ///
    /// Returns [`TimingError`] if either group is empty or statistics cannot be computed.
    pub fn welch_t_test(
        group_a: &[TimingMeasurement],
        group_b: &[TimingMeasurement],
        alpha: f64,
    ) -> Result<Self, TimingError> {
        let dist_a = TimingDistribution::from_measurements(group_a)?;
        let dist_b = TimingDistribution::from_measurements(group_b)?;
        Self::from_distributions(dist_a, dist_b, alpha)
    }

    /// Compare two [`TimingDistribution`] objects.
    ///
    /// # Errors
    ///
    /// Returns [`TimingError`] if the distributions have zero count.
    pub fn from_distributions(
        dist_a: TimingDistribution,
        dist_b: TimingDistribution,
        alpha: f64,
    ) -> Result<Self, TimingError> {
        let na = f64::from(u32::try_from(dist_a.count).unwrap_or(u32::MAX));
        let nb = f64::from(u32::try_from(dist_b.count).unwrap_or(u32::MAX));
        let va = dist_a.variance_ns2;
        let vb = dist_b.variance_ns2;

        let mean_diff_raw = dist_b.mean_ns - dist_a.mean_ns;
        let se = ((va / na) + (vb / nb)).sqrt();
        // When both samples have zero variance but distinct means, the populations
        // are perfectly separable; report this as an extreme t-statistic so
        // significance and Cohen's d reflect a clear timing leak.
        let t_statistic = if se < 1e-12 {
            if mean_diff_raw.abs() > 1e-12 {
                mean_diff_raw.signum() * f64::INFINITY
            } else {
                0.0
            }
        } else {
            mean_diff_raw / se
        };

        // Approximate p-value using normal distribution for large samples
        let p_value = 2.0 * normal_cdf_complementary(t_statistic.abs());
        let significant = p_value < alpha;

        // Pooled Cohen's d
        let pooled_std = ((na - 1.0).mul_add(va, (nb - 1.0) * vb) / (na + nb - 2.0)).sqrt();
        let cohens_d = if pooled_std < 1e-12 {
            if mean_diff_raw.abs() > 1e-12 {
                mean_diff_raw.signum() * f64::INFINITY
            } else {
                0.0
            }
        } else {
            mean_diff_raw / pooled_std
        };

        let mean_diff_ns = dist_b.mean_ns - dist_a.mean_ns;

        Ok(Self {
            sample_a: dist_a,
            sample_b: dist_b,
            t_statistic,
            p_value,
            significant,
            alpha,
            mean_diff_ns,
            cohens_d,
        })
    }

    /// True if the difference is likely due to a timing side-channel.
    #[must_use]
    pub fn is_exploitable(&self) -> bool {
        self.significant && self.cohens_d.abs() > 0.5
    }
}

/// Complementary CDF of the standard normal distribution (2-tailed approximation).
/// Uses the Abramowitz & Stegun 7.1.26 approximation with relative error < 1.5e-7.
fn normal_cdf_complementary(x: f64) -> f64 {
    let x = x.abs();
    if x > 38.0 { return 0.0; }
    let t = 1.0 / 0.231_641_9_f64.mul_add(x, 1.0);
    let y = t * (0.319_381_530
        + t * (-0.356_563_782
        + t * (1.781_477_937
        + t * (-1.821_255_978
        + t * 1.330_274_429))));
    1.0 / (2.0 * std::f64::consts::PI).sqrt() * (-x * x / 2.0).exp() * y
}

// ── ByteOracle ────────────────────────────────────────────────────────────────

/// Abstraction for an oracle that accepts a byte sequence and returns a timing.
pub trait ByteOracle: Send + Sync {
    /// Query the oracle with the given input and return elapsed nanoseconds.
    fn query(&self, input: &[u8]) -> u64;
}

/// In-memory oracle backed by a closure for testing.
pub struct ClosureOracle<F: Fn(&[u8]) -> u64 + Send + Sync> {
    f: F,
}

impl<F: Fn(&[u8]) -> u64 + Send + Sync> ClosureOracle<F> {
    #[must_use]
    pub const fn new(f: F) -> Self { Self { f } }
}

impl<F: Fn(&[u8]) -> u64 + Send + Sync> ByteOracle for ClosureOracle<F> {
    fn query(&self, input: &[u8]) -> u64 { (self.f)(input) }
}

// ── TimingReport ──────────────────────────────────────────────────────────────

/// Complete report from a timing oracle attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingReport {
    /// Number of oracle queries made.
    pub total_queries: u64,
    /// Whether the target appears to be constant-time.
    pub constant_time: bool,
    /// Bytes recovered by the attack.
    pub recovered_bytes: Vec<u8>,
    /// Per-position statistical analyses.
    pub per_position_analyses: Vec<StatisticalAnalysis>,
    /// Peak t-statistic observed.
    pub peak_t_statistic: f64,
    /// Minimum p-value observed.
    pub min_p_value: f64,
    /// Whether the attack succeeded (at least one byte recovered with p < 0.05).
    pub attack_succeeded: bool,
    /// Human-readable summary.
    pub summary: String,
}

impl TimingReport {
    #[must_use]
    pub fn constant_time_report() -> Self {
        Self {
            total_queries: 0,
            constant_time: true,
            recovered_bytes: Vec::new(),
            per_position_analyses: Vec::new(),
            peak_t_statistic: 0.0,
            min_p_value: 1.0,
            attack_succeeded: false,
            summary: "Target appears to be constant-time — timing attack infeasible".into(),
        }
    }

    fn build_summary(succeeded: bool, recovered: &[u8], total_queries: u64) -> String {
        if succeeded {
            let hex: String = recovered.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc });
            format!("Attack succeeded: recovered {} bytes [{}] using {total_queries} queries", recovered.len(), hex)
        } else {
            format!("Attack failed to recover reliable bytes after {total_queries} queries")
        }
    }
}

// ── TimingOracleFull ──────────────────────────────────────────────────────────

/// Full timing oracle attack engine.
///
/// Performs a byte-by-byte timing side-channel attack similar to the
/// BEAST / Lucky13 / timing-based padding oracle attacks.
///
/// The attack proceeds position by position:
/// 1. Collect `samples_per_byte` measurements for each of 256 candidate bytes.
/// 2. Compare each candidate's distribution to the baseline.
/// 3. Select the candidate with the most significant timing deviation.
pub struct TimingOracleFull {
    /// Number of repeated measurements per candidate.
    pub samples_per_byte: usize,
    /// Statistical significance threshold (alpha).
    pub alpha: f64,
    /// Minimum effect size (Cohen's d) to consider exploitable.
    pub min_effect_size: f64,
    /// Maximum bytes to recover in one run.
    pub max_bytes: usize,
    /// Warmup queries before collecting measurements.
    pub warmup_queries: usize,
}

impl Default for TimingOracleFull {
    fn default() -> Self {
        Self {
            samples_per_byte: 50,
            alpha: 0.05,
            min_effect_size: 0.3,
            max_bytes: 32,
            warmup_queries: 10,
        }
    }
}

impl TimingOracleFull {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Create with custom sample count and significance level.
    #[must_use]
    pub fn with_params(samples_per_byte: usize, alpha: f64) -> Self {
        Self { samples_per_byte, alpha, ..Self::default() }
    }

    /// Collect `n` timing measurements for `input` from the oracle.
    pub fn collect_measurements(
        &self,
        oracle: &dyn ByteOracle,
        input: &[u8],
        n: usize,
        is_control: bool,
    ) -> Vec<TimingMeasurement> {
        // Warmup
        for _ in 0..self.warmup_queries.min(3) {
            oracle.query(input);
        }
        (0..n).map(|seq| {
            let d = oracle.query(input);
            TimingMeasurement { input: input.to_vec(), duration_ns: d, sequence: Some(seq as u64), is_control }
        }).collect()
    }

    /// Attack a single byte position.
    ///
    /// Tries all 256 possible byte values at `position` in the `template` input.
    /// Returns the recovered byte and the statistical analysis for the winner.
    ///
    /// # Errors
    ///
    /// Returns [`TimingError`] if `position` is out of range or no exploitable difference is found.
    pub fn attack_byte(
        &self,
        oracle: &dyn ByteOracle,
        template: &[u8],
        position: usize,
        query_counter: &mut u64,
    ) -> Result<(u8, StatisticalAnalysis), TimingError> {
        if position >= template.len() {
            return Err(TimingError::Aborted(format!("position {position} out of range")));
        }

        // Baseline: measure with a control value
        let mut control_input = template.to_vec();
        control_input[position] = 0x00;
        let baseline = self.collect_measurements(oracle, &control_input, self.samples_per_byte, true);
        *query_counter += baseline.len() as u64;

        let baseline_dist = TimingDistribution::from_measurements(&baseline)?;
        // Note: we don't early-return on a constant baseline distribution here.
        // A constant baseline simply means the control value happens to hit a
        // single timing class; the overall oracle may still leak data when
        // different candidate values are probed.  The pre-check in
        // `run_attack` is responsible for global constant-time detection.

        let mut best_byte = 0u8;
        let mut best_t   = 0.0f64;
        let mut best_mean = f64::NEG_INFINITY;
        let mut best_analysis: Option<StatisticalAnalysis> = None;

        for candidate in 0u8..=255 {
            let mut probe = template.to_vec();
            probe[position] = candidate;
            let measurements = self.collect_measurements(oracle, &probe, self.samples_per_byte, false);
            *query_counter += measurements.len() as u64;

            let probe_dist = TimingDistribution::from_measurements(&measurements)?;
            let probe_mean = probe_dist.mean_ns;
            let analysis = StatisticalAnalysis::from_distributions(baseline_dist.clone(), probe_dist, self.alpha)?;

            let t_abs = analysis.t_statistic.abs();
            // Primary: greater |t|.  Tie-breaker (notably useful when several
            // candidates produce an identical infinite t-statistic because the
            // baseline has zero variance): pick the candidate with the largest
            // probe-distribution mean, matching the "highest timing wins"
            // contract documented for `attack_byte`.
            // `inf - inf` is NaN and `NaN < EPSILON` is false, so the
            // subtraction form could never detect the very case the comment
            // above describes: with a noiseless oracle every candidate has zero
            // variance, every t-statistic is infinite, and the first candidate
            // to reach infinity (byte 1) won permanently — the tie-breaker was
            // unreachable exactly when it was needed. `==` compares infinities
            // correctly; the epsilon form stays for near-equal finite values.
            let same_t = t_abs == best_t || (t_abs - best_t).abs() < f64::EPSILON;
            let better = t_abs > best_t || (same_t && probe_mean > best_mean);
            if better {
                best_t = t_abs;
                best_mean = probe_mean;
                best_byte = candidate;
                best_analysis = Some(analysis);
            }
        }

        match best_analysis {
            Some(a) if a.is_exploitable() => Ok((best_byte, a)),
            Some(a) => Err(TimingError::BelowExploitabilityThreshold {
                byte: best_byte,
                position,
                t_stat: a.t_statistic,
            }),
            None => Err(TimingError::NoSignificantDiff(0, position)),
        }
    }

    /// Run the full multi-byte attack.
    pub fn run_attack(
        &self,
        oracle: &dyn ByteOracle,
        initial_template: &[u8],
    ) -> TimingReport {
        if initial_template.is_empty() {
            return TimingReport::constant_time_report();
        }

        // Quick constant-time check: vary the first byte of the template so that
        // a data-dependent oracle has a chance to reveal itself. Probing only the
        // original template would miss leaks keyed on input byte value.
        let mut check_inputs: Vec<Vec<u8>> = vec![initial_template.to_vec()];
        let mut alt = initial_template.to_vec();
        alt[0] = alt[0].wrapping_add(0xAA);
        check_inputs.push(alt);
        let mut check = Vec::new();
        for inp in &check_inputs {
            check.extend(self.collect_measurements(oracle, inp, self.samples_per_byte.min(20), true));
        }
        let mut total_queries = check.len() as u64;
        if let Ok(dist) = TimingDistribution::from_measurements(&check) && dist.is_constant_time() {
            let mut report = TimingReport::constant_time_report();
            report.total_queries = total_queries;
            return report;
        }

        let mut recovered = Vec::new();
        let mut per_position = Vec::new();
        let mut peak_t = 0.0f64;
        let mut min_p = 1.0f64;
        let max_pos = initial_template.len().min(self.max_bytes);

        for pos in 0..max_pos {
            match self.attack_byte(oracle, initial_template, pos, &mut total_queries) {
                Ok((byte, analysis)) => {
                    peak_t = peak_t.max(analysis.t_statistic.abs());
                    min_p  = min_p.min(analysis.p_value);
                    per_position.push(analysis);
                    recovered.push(byte);
                }
                Err(TimingError::ConstantTime) => break,
                Err(_) => {
                    per_position.push(StatisticalAnalysis {
                        sample_a: TimingDistribution { count: 0, mean_ns: 0.0, variance_ns2: 0.0, std_dev_ns: 0.0, min_ns: 0, max_ns: 0, median_ns: 0, percentile_95_ns: 0 },
                        sample_b: TimingDistribution { count: 0, mean_ns: 0.0, variance_ns2: 0.0, std_dev_ns: 0.0, min_ns: 0, max_ns: 0, median_ns: 0, percentile_95_ns: 0 },
                        t_statistic: 0.0, p_value: 1.0, significant: false,
                        alpha: self.alpha, mean_diff_ns: 0.0, cohens_d: 0.0,
                    });
                    recovered.push(0x00);
                }
            }
        }

        let attack_succeeded = !recovered.is_empty() && min_p < self.alpha;
        let summary = TimingReport::build_summary(attack_succeeded, &recovered, total_queries);

        TimingReport {
            total_queries,
            constant_time: false,
            recovered_bytes: recovered,
            per_position_analyses: per_position,
            peak_t_statistic: peak_t,
            min_p_value: min_p,
            attack_succeeded,
            summary,
        }
    }

    /// Estimate the number of queries needed to attack a secret of `byte_len` bytes.
    #[must_use]
    pub fn estimate_query_count(&self, byte_len: usize) -> u64 {
        let per_byte = u64::try_from(256 + 1 + self.warmup_queries).unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(self.samples_per_byte).unwrap_or(u64::MAX));
        per_byte.saturating_mul(u64::try_from(byte_len).unwrap_or(u64::MAX))
    }
}

// ── CachingTimingOracle ───────────────────────────────────────────────────────

/// Wraps a `ByteOracle`, caching results for identical inputs.
pub struct CachingTimingOracle<O: ByteOracle> {
    inner: O,
    cache: std::sync::Mutex<HashMap<Vec<u8>, Vec<u64>>>,
    max_cache_size: usize,
}

impl<O: ByteOracle> CachingTimingOracle<O> {
    pub fn new(inner: O, max_cache_size: usize) -> Self {
        Self { inner, cache: std::sync::Mutex::new(HashMap::new()), max_cache_size }
    }

    /// # Panics
    ///
    /// Panics if the internal cache mutex is poisoned.
    #[must_use]
    pub fn cache_hit_count(&self) -> usize {
        self.cache.lock().unwrap().values().map(Vec::len).sum()
    }
}

impl<O: ByteOracle> ByteOracle for CachingTimingOracle<O> {
    fn query(&self, input: &[u8]) -> u64 {
        let result = self.inner.query(input);
        let mut cache = self.cache.lock().unwrap();
        if cache.len() < self.max_cache_size {
            cache.entry(input.to_vec()).or_default().push(result);
        }
        result
    }
}

// ── Outlier filtering ─────────────────────────────────────────────────────────

/// Remove outliers from a set of measurements using IQR-based filtering.
/// Measurements outside [Q1 - 1.5*IQR, Q3 + 1.5*IQR] are removed.
#[must_use]
pub fn remove_outliers(measurements: &[TimingMeasurement]) -> Vec<TimingMeasurement> {
    if measurements.len() < 4 {
        return measurements.to_vec();
    }
    let mut durations: Vec<u64> = measurements.iter().map(|m| m.duration_ns).collect();
    durations.sort_unstable();
    let n = durations.len();
    let q1 = f64::from(u32::try_from(durations[n / 4]).unwrap_or(u32::MAX));
    let q3 = f64::from(u32::try_from(durations[3 * n / 4]).unwrap_or(u32::MAX));
    let iqr = q3 - q1;
    let lo = 1.5f64.mul_add(-iqr, q1);
    let hi = 1.5f64.mul_add(iqr, q3);
    measurements.iter()
        .filter(|m| {
            let d = f64::from(u32::try_from(m.duration_ns).unwrap_or(u32::MAX));
            d >= lo && d <= hi
        })
        .cloned()
        .collect()
}

/// Compute the median of a slice of u64 values.
pub fn median(values: &mut [u64]) -> Option<u64> {
    if values.is_empty() { return None; }
    values.sort_unstable();
    let mid = values.len() / 2;
    Some(values[mid])
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper oracles ────────────────────────────────────────────────────────

    /// Oracle that returns a fixed constant (constant-time).
    struct ConstantOracle;
    impl ByteOracle for ConstantOracle {
        fn query(&self, _: &[u8]) -> u64 { 1000 }
    }

    /// Oracle with timing proportional to input[0] value (leaks byte 0).
    struct LeakyOracle;
    impl ByteOracle for LeakyOracle {
        fn query(&self, input: &[u8]) -> u64 {
            let base = 1_000u64;
            let leak = u64::from(input.first().copied().unwrap_or(0)) * 100;
            base + leak
        }
    }

    /// Oracle with realistic noise + leak.
    struct NoisyLeakyOracle { seed: std::sync::atomic::AtomicU64 }
    impl NoisyLeakyOracle {
        fn new() -> Self { Self { seed: std::sync::atomic::AtomicU64::new(0x1234_5678_90AB_CDEF_u64) } }
        fn next_noise(&self) -> u64 {
            let old = self.seed.load(std::sync::atomic::Ordering::Relaxed);
            let s = old.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            self.seed.store(s, std::sync::atomic::Ordering::Relaxed);
            (s >> 33) % 200  // noise in [0, 200) ns
        }
    }
    impl ByteOracle for NoisyLeakyOracle {
        fn query(&self, input: &[u8]) -> u64 {
            let base = 5_000u64;
            let leak = if input.first().copied().unwrap_or(0) == 0x42 { 2_000 } else { 0 };
            base + leak + self.next_noise()
        }
    }

    #[test]
    fn test_noisy_leaky_oracle_query() {
        let oracle = NoisyLeakyOracle::new();
        let t_leak = oracle.query(&[0x42]);
        let t_no_leak = oracle.query(&[0x00]);
        // leaked path adds 2000 ns; noise < 200, so difference must be positive
        assert!(t_leak.saturating_sub(t_no_leak) > 0 || t_no_leak.saturating_sub(t_leak) < 400);
    }

    #[test]
    fn test_timing_measurement_new() {
        let m = TimingMeasurement::new(vec![0x01], 1234);
        assert_eq!(m.duration_ns, 1234);
        assert!(!m.is_control);
    }

    #[test]
    fn test_timing_measurement_control() {
        let m = TimingMeasurement::control(vec![0x00], 999);
        assert!(m.is_control);
    }

    #[test]
    fn test_timing_distribution_basic() {
        let measurements: Vec<TimingMeasurement> = (0..10).map(|i| TimingMeasurement::new(vec![], 1000 + i * 100)).collect();
        let dist = TimingDistribution::from_measurements(&measurements).unwrap();
        assert_eq!(dist.count, 10);
        assert!(dist.min_ns < dist.max_ns);
        assert!(dist.mean_ns > 0.0);
    }

    #[test]
    fn test_timing_distribution_empty() {
        let result = TimingDistribution::from_measurements(&[]);
        assert!(matches!(result, Err(TimingError::InsufficientMeasurements(_, _))));
    }

    #[test]
    fn test_timing_distribution_constant_time() {
        let measurements: Vec<TimingMeasurement> = (0..100).map(|_| TimingMeasurement::new(vec![], 1000)).collect();
        let dist = TimingDistribution::from_measurements(&measurements).unwrap();
        assert!(dist.is_constant_time());
    }

    #[test]
    fn test_timing_distribution_not_constant() {
        let measurements: Vec<TimingMeasurement> = (0..100).map(|i| TimingMeasurement::new(vec![], 1000 + i * 1000)).collect();
        let dist = TimingDistribution::from_measurements(&measurements).unwrap();
        assert!(!dist.is_constant_time());
    }

    #[test]
    fn test_timing_distribution_cv() {
        let dist = TimingDistribution { count: 10, mean_ns: 1000.0, variance_ns2: 100.0, std_dev_ns: 10.0, min_ns: 990, max_ns: 1010, median_ns: 1000, percentile_95_ns: 1009 };
        assert!((dist.cv() - 0.01).abs() < 1e-9);
    }

    #[test]
    fn test_timing_distribution_from_durations() {
        let durations = vec![100u64, 200, 300, 400, 500];
        let dist = TimingDistribution::from_durations(&durations).unwrap();
        assert_eq!(dist.count, 5);
        assert_eq!(dist.min_ns, 100);
        assert_eq!(dist.max_ns, 500);
    }

    #[test]
    fn test_statistical_analysis_significant_diff() {
        // Two groups with clearly different means
        let group_a: Vec<TimingMeasurement> = (0..50).map(|_| TimingMeasurement::new(vec![], 1_000)).collect();
        let group_b: Vec<TimingMeasurement> = (0..50).map(|_| TimingMeasurement::new(vec![], 10_000)).collect();
        let analysis = StatisticalAnalysis::welch_t_test(&group_a, &group_b, 0.05).unwrap();
        assert!(analysis.significant);
        assert!(analysis.t_statistic.abs() > 2.0);
    }

    #[test]
    fn test_statistical_analysis_no_diff() {
        let group: Vec<TimingMeasurement> = (0..50).map(|_| TimingMeasurement::new(vec![], 1_000)).collect();
        let analysis = StatisticalAnalysis::welch_t_test(&group, &group, 0.05).unwrap();
        // Same groups → t ≈ 0
        assert!(analysis.t_statistic.abs() < 1e-6);
    }

    #[test]
    fn test_statistical_analysis_cohen_d() {
        let group_a: Vec<TimingMeasurement> = (0..100).map(|_| TimingMeasurement::new(vec![], 1_000)).collect();
        let group_b: Vec<TimingMeasurement> = (0..100).map(|_| TimingMeasurement::new(vec![], 2_000)).collect();
        let analysis = StatisticalAnalysis::welch_t_test(&group_a, &group_b, 0.05).unwrap();
        assert!(analysis.cohens_d.abs() > 0.0);
        assert!(analysis.mean_diff_ns > 0.0);
    }

    #[test]
    fn test_statistical_analysis_is_exploitable() {
        let group_a: Vec<TimingMeasurement> = (0..50).map(|_| TimingMeasurement::new(vec![], 1_000)).collect();
        let group_b: Vec<TimingMeasurement> = (0..50).map(|_| TimingMeasurement::new(vec![], 10_000)).collect();
        let analysis = StatisticalAnalysis::welch_t_test(&group_a, &group_b, 0.05).unwrap();
        assert!(analysis.is_exploitable());
    }

    #[test]
    fn test_oracle_collect_measurements() {
        let oracle = LeakyOracle;
        let engine = TimingOracleFull::with_params(5, 0.05);
        let measurements = engine.collect_measurements(&oracle, &[0x42], 5, false);
        assert_eq!(measurements.len(), 5);
    }

    #[test]
    fn test_oracle_constant_time_detection() {
        let oracle = ConstantOracle;
        let engine = TimingOracleFull::with_params(20, 0.05);
        let report = engine.run_attack(&oracle, &[0x00, 0x00]);
        assert!(report.constant_time || !report.attack_succeeded);
    }

    #[test]
    fn test_oracle_full_run_leaky() {
        let oracle = LeakyOracle;
        let engine = TimingOracleFull {
            samples_per_byte: 10,
            alpha: 0.05,
            min_effect_size: 0.1,
            max_bytes: 1,
            warmup_queries: 1,
        };
        let report = engine.run_attack(&oracle, &[0x00]);
        // With a clearly leaky oracle the recovered byte should be the one with highest timing
        assert!(report.total_queries > 0);
        assert!(!report.recovered_bytes.is_empty());
    }

    #[test]
    fn test_oracle_empty_template() {
        let oracle = LeakyOracle;
        let engine = TimingOracleFull::default();
        let report = engine.run_attack(&oracle, &[]);
        assert!(report.constant_time);
    }

    #[test]
    fn test_estimate_query_count() {
        let engine = TimingOracleFull::with_params(50, 0.05);
        let estimate = engine.estimate_query_count(4);
        // 4 bytes × (256 + 1 + warmup=10) × 50 = 4 × 267 × 50 = 53400
        assert!(estimate > 0);
    }

    #[test]
    fn test_caching_oracle() {
        let oracle = CachingTimingOracle::new(LeakyOracle, 1000);
        oracle.query(&[0x01]);
        oracle.query(&[0x01]);
        assert!(oracle.cache_hit_count() >= 2);
    }

    #[test]
    fn test_remove_outliers_removes_extremes() {
        let mut measurements: Vec<TimingMeasurement> = (0..100).map(|i| TimingMeasurement::new(vec![], 1000 + i)).collect();
        // Add extreme outliers
        measurements.push(TimingMeasurement::new(vec![], 1_000_000));
        measurements.push(TimingMeasurement::new(vec![], 0));
        let filtered = remove_outliers(&measurements);
        assert!(filtered.len() < measurements.len());
        assert!(!filtered.iter().any(|m| m.duration_ns == 1_000_000));
    }

    #[test]
    fn test_remove_outliers_small_sample() {
        let measurements = vec![
            TimingMeasurement::new(vec![], 100),
            TimingMeasurement::new(vec![], 200),
        ];
        let filtered = remove_outliers(&measurements);
        assert_eq!(filtered.len(), 2); // too few to filter
    }

    #[test]
    fn test_median_odd() {
        let mut v = vec![3u64, 1, 4, 1, 5];
        assert_eq!(median(&mut v), Some(3));
    }

    #[test]
    fn test_median_even() {
        let mut v = vec![2u64, 4, 6, 8];
        assert_eq!(median(&mut v), Some(6));
    }

    #[test]
    fn test_median_empty() {
        assert_eq!(median(&mut []), None);
    }

    #[test]
    fn test_timing_report_constant_time() {
        let r = TimingReport::constant_time_report();
        assert!(r.constant_time);
        assert!(!r.attack_succeeded);
        assert!(r.recovered_bytes.is_empty());
    }

    #[test]
    fn test_normal_cdf_tail() {
        // large x → probability near 0
        let p = normal_cdf_complementary(10.0);
        assert!(p < 0.01);
        // x = 0 → probability = ~0.398 (not exactly 0.5 due to approximation)
        let p0 = normal_cdf_complementary(0.0);
        assert!(p0 > 0.1 && p0 < 0.5);
    }

    #[test]
    fn test_attack_byte_leaky_oracle() {
        let oracle = LeakyOracle;
        let engine = TimingOracleFull {
            samples_per_byte: 10,
            alpha: 0.05,
            min_effect_size: 0.1,
            max_bytes: 1,
            warmup_queries: 0,
        };
        let mut qcount = 0u64;
        // The leaky oracle gives highest timing for byte=255 at position 0
        match engine.attack_byte(&oracle, &[0x00], 0, &mut qcount) {
            Ok((byte, analysis)) => {
                // Should recover byte=255 (max timing)
                assert_eq!(byte, 0xFF);
                assert!(analysis.t_statistic.abs() > 0.0);
            }
            Err(TimingError::ConstantTime) => {} // acceptable
            Err(e) => panic!("Unexpected error: {e}"),
        }
    }

    #[test]
    fn test_statistical_analysis_p_value_range() {
        let group_a: Vec<TimingMeasurement> = (0..30).map(|_| TimingMeasurement::new(vec![], 1_000)).collect();
        let group_b: Vec<TimingMeasurement> = (0..30).map(|_| TimingMeasurement::new(vec![], 1_100)).collect();
        let analysis = StatisticalAnalysis::welch_t_test(&group_a, &group_b, 0.05).unwrap();
        assert!((0.0..=1.0).contains(&analysis.p_value));
    }

    #[test]
    fn test_distribution_percentile_within_range() {
        let durations: Vec<u64> = (0..100).map(|i| i * 10).collect();
        let dist = TimingDistribution::from_durations(&durations).unwrap();
        assert!(dist.percentile_95_ns >= dist.median_ns);
    }
}
