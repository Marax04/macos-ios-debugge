//! Classical statistical randomness tests for binary triage.
//!
//! These tests complement Shannon entropy by measuring different facets of
//! "randomness". High-quality random / encrypted data scores near the ideal on
//! every test, whereas structured code, text, or compressed data deviates on at
//! least one of them.
//!
//! The implementations follow the classic `ent`(1) battery:
//! * [`monte_carlo_pi`] — estimate π by treating byte pairs as 2-D coordinates.
//! * [`serial_correlation`] — lag-1 autocorrelation of the byte stream.
//! * [`arithmetic_mean`] — mean byte value (127.5 for ideal random data).
//! * [`RandomnessReport`] — all of the above plus Shannon entropy, aggregated.

use serde::{Deserialize, Serialize};
use crate::casts;

// ─────────────────────────────────────────────────────────────────────────────
// monte_carlo_pi
// ─────────────────────────────────────────────────────────────────────────────

/// Estimate π using the Monte-Carlo method over `data`.
///
/// Consecutive groups of six bytes are interpreted as a 24-bit X coordinate and
/// a 24-bit Y coordinate inside the unit square. The fraction of points landing
/// inside the inscribed quarter circle approximates `π / 4`. For genuinely
/// random data the estimate converges to π (≈ 3.14159); structured data
/// produces a noticeably skewed estimate.
///
/// Returns `0.0` when fewer than six bytes are available (no complete point).
#[must_use]
pub fn monte_carlo_pi(data: &[u8]) -> f64 {
    // Each point consumes 3 bytes per axis → 6 bytes per point.
    const BYTES_PER_COORD: usize = 3;
    const BYTES_PER_POINT: usize = BYTES_PER_COORD * 2;
    // Largest representable 24-bit value, used to normalise to [0, 1).
    let max_coord = f64::from((1u32 << (8 * casts::usize_to_u32(BYTES_PER_COORD))) - 1);

    let points = data.len() / BYTES_PER_POINT;
    if points == 0 {
        return 0.0;
    }

    let mut inside = 0u64;
    for chunk in data.chunks_exact(BYTES_PER_POINT) {
        let x = u32::from(chunk[0]) << 16 | u32::from(chunk[1]) << 8 | u32::from(chunk[2]);
        let y = u32::from(chunk[3]) << 16 | u32::from(chunk[4]) << 8 | u32::from(chunk[5]);
        let fx = f64::from(x) / max_coord;
        let fy = f64::from(y) / max_coord;
        if fx * fx + fy * fy <= 1.0 {
            inside += 1;
        }
    }

    4.0 * casts::u64_to_f64(inside) / casts::usize_to_f64(points)
}

/// Absolute relative error of [`monte_carlo_pi`] against the true value of π.
///
/// Returns a value in `[0.0, ∞)`; values near `0.0` indicate random data while
/// large values indicate structure. Returns `1.0` (100 % error) for inputs too
/// short to produce any point.
#[must_use]
pub fn monte_carlo_pi_error(data: &[u8]) -> f64 {
    let estimate = monte_carlo_pi(data);
    if estimate == 0.0 {
        return 1.0;
    }
    (estimate - std::f64::consts::PI).abs() / std::f64::consts::PI
}

// ─────────────────────────────────────────────────────────────────────────────
// serial_correlation
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the lag-1 serial-correlation coefficient of the byte stream.
///
/// This measures how much each byte depends on its predecessor. The result lies
/// in `[-1.0, 1.0]`:
/// * near `0.0` → successive bytes are uncorrelated (random / encrypted),
/// * near `±1.0` → strong linear dependence (ramps, counters, padding).
///
/// Returns `0.0` when fewer than two bytes are present or when the byte stream
/// has zero variance (e.g. a constant fill), since correlation is undefined.
#[must_use]
pub fn serial_correlation(data: &[u8]) -> f64 {
    let n = data.len();
    if n < 2 {
        return 0.0;
    }

    // Pairs are (data[i], data[i+1]) wrapping around at the end, matching the
    // circular definition used by `ent`.
    let nf = casts::usize_to_f64(n);
    let mut sum = 0.0f64; // Σ x_i
    let mut sum_sq = 0.0f64; // Σ x_i²
    let mut sum_prod = 0.0f64; // Σ x_i · x_{i+1}

    for i in 0..n {
        let x = f64::from(data[i]);
        let next = f64::from(data[(i + 1) % n]);
        sum += x;
        sum_sq += x * x;
        sum_prod += x * next;
    }

    let numerator = nf.mul_add(sum_prod, -(sum * sum));
    let denominator = nf.mul_add(sum_sq, -(sum * sum));
    if denominator.abs() < f64::EPSILON {
        return 0.0;
    }
    (numerator / denominator).clamp(-1.0, 1.0)
}

// ─────────────────────────────────────────────────────────────────────────────
// arithmetic_mean
// ─────────────────────────────────────────────────────────────────────────────

/// Arithmetic mean of the byte values in `data`.
///
/// For uniformly random data this converges to `127.5`. Strong deviation
/// suggests biased content (e.g. mostly-ASCII text trends toward ~64–96, while
/// null-padded regions trend toward 0).
///
/// Returns `0.0` for empty input.
#[must_use]
pub fn arithmetic_mean(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let sum: u64 = data.iter().map(|&b| u64::from(b)).sum();
    casts::u64_to_f64(sum) / casts::usize_to_f64(data.len())
}

/// Absolute deviation of [`arithmetic_mean`] from the ideal random mean (127.5),
/// normalised to `[0.0, 1.0]`.
///
/// `0.0` means the mean is exactly 127.5; `1.0` means it is at an extreme
/// (all `0x00` or all `0xFF`). Returns `1.0` for empty input.
#[must_use]
pub fn mean_deviation(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 1.0;
    }
    (arithmetic_mean(data) - 127.5).abs() / 127.5
}

// ─────────────────────────────────────────────────────────────────────────────
// RandomnessReport
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated output of the full randomness-test battery for one buffer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RandomnessReport {
    /// Shannon entropy in bits per byte (0.0 – 8.0).
    pub entropy: f64,
    /// Monte-Carlo π estimate.
    pub monte_carlo_pi: f64,
    /// Relative error of the π estimate (0.0 = perfect).
    pub monte_carlo_error: f64,
    /// Lag-1 serial-correlation coefficient (−1.0 – 1.0).
    pub serial_correlation: f64,
    /// Arithmetic mean of bytes (ideal 127.5).
    pub arithmetic_mean: f64,
    /// Normalised deviation of the mean from 127.5 (0.0 – 1.0).
    pub mean_deviation: f64,
    /// Number of bytes analysed.
    pub length: usize,
}

impl RandomnessReport {
    /// Run every randomness test in this module over `data` and collect the
    /// results.
    #[must_use]
    pub fn analyze(data: &[u8]) -> Self {
        Self {
            entropy: crate::shannon_entropy(data),
            monte_carlo_pi: monte_carlo_pi(data),
            monte_carlo_error: monte_carlo_pi_error(data),
            serial_correlation: serial_correlation(data),
            arithmetic_mean: arithmetic_mean(data),
            mean_deviation: mean_deviation(data),
            length: data.len(),
        }
    }

    /// A heuristic "looks random" score in `[0.0, 1.0]` combining all tests.
    ///
    /// `1.0` means every test points to high-quality randomness; values near
    /// `0.0` indicate strong structure. The score is the mean of four
    /// sub-scores: normalised entropy, π accuracy, low serial correlation, and
    /// mean centrality.
    #[must_use]
    pub fn randomness_score(&self) -> f64 {
        if self.length == 0 {
            return 0.0;
        }
        let entropy_score = (self.entropy / 8.0).clamp(0.0, 1.0);
        let pi_score = (1.0 - self.monte_carlo_error).clamp(0.0, 1.0);
        let corr_score = (1.0 - self.serial_correlation.abs()).clamp(0.0, 1.0);
        let mean_score = (1.0 - self.mean_deviation).clamp(0.0, 1.0);
        (entropy_score + pi_score + corr_score + mean_score) / 4.0
    }

    /// Returns `true` if the buffer passes every test within tolerant bounds,
    /// i.e. it statistically resembles random / encrypted data.
    #[must_use]
    pub fn looks_random(&self) -> bool {
        self.entropy > 7.5
            && self.monte_carlo_error < 0.05
            && self.serial_correlation.abs() < 0.10
            && self.mean_deviation < 0.05
    }
}

impl std::fmt::Display for RandomnessReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Randomness(len={}, H={:.3}, π≈{:.4} (err {:.2}%), scc={:.4}, mean={:.1}, score={:.2})",
            self.length,
            self.entropy,
            self.monte_carlo_pi,
            self.monte_carlo_error * 100.0,
            self.serial_correlation,
            self.arithmetic_mean,
            self.randomness_score(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A simple deterministic LCG to produce pseudo-random bytes for tests
    /// without pulling in an external RNG dependency.
    fn pseudo_random(n: usize) -> Vec<u8> {
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            // xorshift64*
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let v = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            out.push((v >> 33) as u8);
        }
        out
    }

    fn ascii_text(n: usize) -> Vec<u8> {
        let sample = b"The quick brown fox jumps over the lazy dog. ";
        sample.iter().copied().cycle().take(n).collect()
    }

    // ── monte_carlo_pi ────────────────────────────────────────────────────

    #[test]
    fn test_monte_carlo_pi_too_short() {
        assert_eq!(monte_carlo_pi(&[1, 2, 3]), 0.0);
        assert!((monte_carlo_pi(&[]) - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_monte_carlo_pi_random_near_pi() {
        let data = pseudo_random(120_000);
        let est = monte_carlo_pi(&data);
        assert!(
            (est - std::f64::consts::PI).abs() < 0.05,
            "estimate {est} not near π"
        );
    }

    #[test]
    fn test_monte_carlo_pi_zeros_is_extreme() {
        // All zeros → every point at origin → always inside → estimate 4.0.
        let est = monte_carlo_pi(&[0u8; 600]);
        assert!((est - 4.0).abs() < 1e-9, "got {est}");
    }

    #[test]
    fn test_monte_carlo_error_random_small() {
        let data = pseudo_random(120_000);
        assert!(monte_carlo_pi_error(&data) < 0.02);
    }

    #[test]
    fn test_monte_carlo_error_short_is_one() {
        assert!((monte_carlo_pi_error(&[1, 2]) - 1.0).abs() < 1e-9);
    }

    // ── serial_correlation ────────────────────────────────────────────────

    #[test]
    fn test_serial_correlation_too_short() {
        assert!((serial_correlation(&[]) - (0.0)).abs() < f64::EPSILON);
        assert!((serial_correlation(&[5]) - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_serial_correlation_constant_is_zero() {
        // Zero variance → undefined correlation → defined as 0.0.
        assert!((serial_correlation(&[7u8; 100]) - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_serial_correlation_random_near_zero() {
        let data = pseudo_random(50_000);
        assert!(
            serial_correlation(&data).abs() < 0.05,
            "scc {} too large",
            serial_correlation(&data)
        );
    }

    #[test]
    fn test_serial_correlation_ramp_is_high() {
        // A rising ramp is strongly positively correlated.
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let scc = serial_correlation(&data);
        assert!(scc > 0.9, "ramp scc {scc} should be near 1");
    }

    #[test]
    fn test_serial_correlation_in_range() {
        let data = pseudo_random(1000);
        let scc = serial_correlation(&data);
        assert!((-1.0..=1.0).contains(&scc));
    }

    // ── arithmetic_mean ───────────────────────────────────────────────────

    #[test]
    fn test_arithmetic_mean_empty() {
        assert!((arithmetic_mean(&[]) - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_arithmetic_mean_uniform_is_centre() {
        let data: Vec<u8> = (0u8..=255).collect();
        assert!((arithmetic_mean(&data) - 127.5).abs() < 1e-9);
    }

    #[test]
    fn test_arithmetic_mean_zeros() {
        assert!((arithmetic_mean(&[0u8; 100]) - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_mean_deviation_uniform_is_zero() {
        let data: Vec<u8> = (0u8..=255).collect();
        assert!(mean_deviation(&data) < 1e-9);
    }

    #[test]
    fn test_mean_deviation_zeros_is_one() {
        assert!((mean_deviation(&[0u8; 100]) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_mean_deviation_empty_is_one() {
        assert!((mean_deviation(&[]) - 1.0).abs() < 1e-9);
    }

    // ── RandomnessReport ──────────────────────────────────────────────────

    #[test]
    fn test_report_random_looks_random() {
        let data = pseudo_random(120_000);
        let r = RandomnessReport::analyze(&data);
        assert!(r.looks_random(), "report: {r}");
        assert!(r.randomness_score() > 0.9, "score {}", r.randomness_score());
    }

    #[test]
    fn test_report_zeros_not_random() {
        let r = RandomnessReport::analyze(&[0u8; 4096]);
        assert!(!r.looks_random());
        assert!(r.randomness_score() < 0.5);
    }

    #[test]
    fn test_report_text_not_random() {
        let r = RandomnessReport::analyze(&ascii_text(4096));
        assert!(!r.looks_random());
        // Text has moderate entropy but biased mean and some correlation.
        assert!(r.randomness_score() < 0.95);
    }

    #[test]
    fn test_report_empty_score_zero() {
        let r = RandomnessReport::analyze(&[]);
        assert!((r.randomness_score() - (0.0)).abs() < f64::EPSILON);
        assert_eq!(r.length, 0);
    }

    #[test]
    fn test_report_display_contains_fields() {
        let r = RandomnessReport::analyze(&pseudo_random(6000));
        let s = r.to_string();
        assert!(s.contains("Randomness"));
        assert!(s.contains("score="));
    }

    #[test]
    fn test_report_fields_populated() {
        let data = pseudo_random(6000);
        let r = RandomnessReport::analyze(&data);
        assert_eq!(r.length, 6000);
        assert!(r.entropy > 0.0);
        assert!(r.monte_carlo_pi > 0.0);
    }
}
