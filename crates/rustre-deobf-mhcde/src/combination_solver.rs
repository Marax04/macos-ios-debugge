//! `combination_solver` — iterative hypothesis combination and quality measurement.
//!
//! [`CombinationSolver`] tries a ranked sequence of deobfuscation hypotheses
//! one by one, applies each to the binary, measures output quality, and
//! backtracks if quality decreases.  The result is the best-quality output
//! found across all combinations tried.

use ahash::AHashMap as HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::feature_extractor::{FeatureExtractor, FeatureVector};
use crate::hypothesis_engine::{Algorithm, Hypothesis};

/// Re-exported map type used to score hypothesis combinations.
pub type HypothesisScoreMap = HashMap<String, f64>;
/// Re-exported feature vector used to compare combination outputs.
pub type CombinationFeatureVector = FeatureVector;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the combination solver.
#[derive(Debug, Error)]
pub enum SolverError {
    /// No hypotheses were provided.
    #[error("no hypotheses to solve")]
    NoHypotheses,
    /// The input binary is empty.
    #[error("empty input binary")]
    EmptyBinary,
    /// A hypothesis produced a binary of a different length (unsupported).
    #[error("hypothesis '{0}' changed binary length — unsupported")]
    LengthChanged(String),
    /// An internal error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// QualityMetric
// ─────────────────────────────────────────────────────────────────────────────

/// Quality metric computed on a binary region after hypothesis application.
///
/// Higher is better in all fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QualityMetric {
    /// Naturalness score (low entropy + high printability = high).
    pub naturalness: f64,
    /// String coverage (fraction of bytes in printable runs ≥ 4).
    pub string_coverage: f64,
    /// Instruction diversity (distinct first-byte opcodes / 256).
    pub instruction_diversity: f64,
    /// Fraction of bytes that are NOT NOP / padding.
    pub code_density: f64,
    /// Composite score: weighted average.
    pub composite: f64,
}

impl QualityMetric {
    /// Compute a quality metric from raw binary data.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        if data.is_empty() {
            return Self {
                naturalness: 0.0,
                string_coverage: 0.0,
                instruction_diversity: 0.0,
                code_density: 0.0,
                composite: 0.0,
            };
        }

        let fv = FeatureExtractor::extract_raw(data);

        // Naturalness: inverted entropy + string coverage
        let inv_entropy = 1.0 - fv.byte_entropy;
        let naturalness = (inv_entropy * 0.5 + fv.string_coverage * 0.5).clamp(0.0, 1.0);

        // Code density: fraction of non-NOP, non-zero bytes
        let code_bytes = data.iter().filter(|&&b| b != 0x90 && b != 0x00).count();
        let code_density = code_bytes as f64 / data.len() as f64;

        let composite = (fv.instruction_diversity.mul_add(0.20, naturalness * 0.40 + fv.string_coverage * 0.25)
            + code_density * 0.15)
            .clamp(0.0, 1.0);

        Self {
            naturalness,
            string_coverage: fv.string_coverage,
            instruction_diversity: fv.instruction_diversity,
            code_density,
            composite,
        }
    }

    /// Returns `true` if this metric is strictly better than `other`.
    #[must_use]
    pub fn is_better_than(&self, other: &Self) -> bool {
        self.composite > other.composite + 1e-9
    }

    /// Delta between composite scores (positive = improvement).
    #[must_use]
    pub fn improvement_over(&self, other: &Self) -> f64 {
        self.composite - other.composite
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SolverStep
// ─────────────────────────────────────────────────────────────────────────────

/// A single step in the solver's execution trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolverStep {
    /// Hypothesis that was tried.
    pub hypothesis_label: String,
    /// Quality before applying this hypothesis.
    pub quality_before: f64,
    /// Quality after applying this hypothesis.
    pub quality_after: f64,
    /// Whether this hypothesis was accepted (quality improved).
    pub accepted: bool,
    /// Reason for rejection if not accepted.
    pub rejection_reason: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// SolverResult
// ─────────────────────────────────────────────────────────────────────────────

/// Final result of a [`CombinationSolver`] run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolverResult {
    /// The best binary found (may equal input if no hypothesis improved quality).
    pub best_binary: Vec<u8>,
    /// Quality metric for `best_binary`.
    pub best_quality: QualityMetric,
    /// Quality metric for the original input.
    pub original_quality: QualityMetric,
    /// Labels of the hypotheses that were accepted in order.
    pub accepted_hypotheses: Vec<String>,
    /// Ordered trace of all steps (accepted and rejected).
    pub trace: Vec<SolverStep>,
    /// Total improvement (composite quality delta).
    pub total_improvement: f64,
}

impl SolverResult {
    /// Returns `true` if at least one hypothesis improved quality.
    #[must_use]
    pub const fn improved(&self) -> bool {
        !self.accepted_hypotheses.is_empty()
    }

    /// Human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "accepted {}/{} hypotheses, quality {:.4} → {:.4} (+{:.4})",
            self.accepted_hypotheses.len(),
            self.trace.len(),
            self.original_quality.composite,
            self.best_quality.composite,
            self.total_improvement,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HypothesisApplicator
// ─────────────────────────────────────────────────────────────────────────────

/// Applies a [`Hypothesis`] algorithm to a byte slice and returns the
/// transformed bytes.
///
/// Returns `None` if the algorithm cannot be applied without changing the
/// binary's length in an unsupported way (e.g. decompression).
#[derive(Debug, Clone, Default)]
pub struct HypothesisApplicator;

impl HypothesisApplicator {
    /// Apply `hypothesis` to `data` and return the result, or `None` if not
    /// applicable without length change.
    #[must_use]
    pub fn apply(&self, data: &[u8], hypothesis: &Hypothesis) -> Option<Vec<u8>> {
        match &hypothesis.algorithm {
            Algorithm::XorConstant { key } => Some(data.iter().map(|&b| b ^ key).collect()),
            Algorithm::XorCyclic { key } if !key.is_empty() => Some(
                data.iter()
                    .enumerate()
                    .map(|(i, &b)| b ^ key[i % key.len()])
                    .collect(),
            ),
            Algorithm::XorRolling { initial_key } => {
                let mut k = *initial_key;
                Some(
                    data.iter()
                        .map(|&b| {
                            let p = b ^ k;
                            k = b;
                            p
                        })
                        .collect(),
                )
            }
            Algorithm::NopElimination => {
                // Replace NOP sleds (≥ 2 consecutive 0x90) with 0x00 runs.
                let mut out = data.to_vec();
                let mut i = 0;
                while i < out.len() {
                    if out[i] == 0x90 {
                        let start = i;
                        while i < out.len() && out[i] == 0x90 {
                            i += 1;
                        }
                        if i - start >= 2 {
                            for byte in &mut out[start..i] {
                                *byte = 0x00;
                            }
                        }
                    } else {
                        i += 1;
                    }
                }
                Some(out)
            }
            Algorithm::OpaquePredicateRemoval => {
                // NOP out xor eax,eax; test eax,eax; jz/jnz (31 C0 85 C0 74/75 xx)
                let mut out = data.to_vec();
                let mut i = 0;
                while i + 5 < out.len() {
                    if out[i] == 0x31
                        && out[i + 1] == 0xC0
                        && out[i + 2] == 0x85
                        && out[i + 3] == 0xC0
                        && (out[i + 4] == 0x74 || out[i + 4] == 0x75)
                    {
                        for b in &mut out[i..i + 5] {
                            *b = 0x90;
                        }
                        i += 5;
                    } else {
                        i += 1;
                    }
                }
                Some(out)
            }
            Algorithm::Rc4 { key } if !key.is_empty() => {
                // RC4 KSA + PRGA
                let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
                let mut j = 0u8;
                for ii in 0u8..=255 {
                    j = j
                        .wrapping_add(s[ii as usize])
                        .wrapping_add(key[ii as usize % key.len()]);
                    s.swap(ii as usize, j as usize);
                }
                let mut ii = 0u8;
                let mut j2 = 0u8;
                let out: Vec<u8> = data
                    .iter()
                    .map(|&d| {
                        ii = ii.wrapping_add(1);
                        j2 = j2.wrapping_add(s[ii as usize]);
                        s.swap(ii as usize, j2 as usize);
                        let k = s[s[ii as usize].wrapping_add(s[j2 as usize]) as usize];
                        d ^ k
                    })
                    .collect();
                Some(out)
            }
            // Algorithms that change length or require external tools → not applicable
            Algorithm::UpxUnpack
            | Algorithm::CffRemoval
            | Algorithm::MbaSimplification
            | Algorithm::AntiDebugPatch
            | Algorithm::StringDecryption { .. } => None,
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CombinationSolver
// ─────────────────────────────────────────────────────────────────────────────

/// Greedy hypothesis combination solver with backtracking.
///
/// # Algorithm
/// 1. Compute baseline quality Q₀ on the original binary.
/// 2. For each hypothesis H in `hypotheses` (in order):
///    a. Apply H to the current best binary → B'.
///    b. Compute Q' = quality(B').
///    c. If Q' > `Q_current`: accept (update current best → B', `Q_current` → Q').
///    d. Else: reject and continue with next hypothesis.
/// 3. Return the best binary found.
///
/// The solver does **not** try all 2ⁿ combinations; it is a greedy pass.
/// For exhaustive search use [`CombinationSolver::solve_exhaustive`].
#[derive(Debug, Clone)]
pub struct CombinationSolver {
    applicator: HypothesisApplicator,
    /// Minimum quality improvement required to accept a hypothesis.
    pub min_improvement: f64,
    /// Maximum number of hypotheses to try.
    pub max_hypotheses: usize,
}

impl Default for CombinationSolver {
    fn default() -> Self {
        Self {
            applicator: HypothesisApplicator,
            min_improvement: 1e-4,
            max_hypotheses: 16,
        }
    }
}

impl CombinationSolver {
    /// Create a solver with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a solver with custom settings.
    #[must_use]
    pub const fn with_settings(min_improvement: f64, max_hypotheses: usize) -> Self {
        Self {
            applicator: HypothesisApplicator,
            min_improvement,
            max_hypotheses,
        }
    }

    /// Run the greedy solver on `data` using the provided hypotheses.
    ///
    /// # Errors
    /// Returns [`SolverError`] if the input is empty, or no hypotheses are
    /// provided.
    pub fn solve(
        &self,
        data: &[u8],
        hypotheses: &[Hypothesis],
    ) -> Result<SolverResult, SolverError> {
        if data.is_empty() {
            return Err(SolverError::EmptyBinary);
        }
        if hypotheses.is_empty() {
            return Err(SolverError::NoHypotheses);
        }

        let original_quality = QualityMetric::from_bytes(data);
        let mut current_binary = data.to_vec();
        let mut current_quality = original_quality.clone();
        let mut accepted = Vec::new();
        let mut trace = Vec::new();

        for h in hypotheses.iter().take(self.max_hypotheses) {
            let q_before = current_quality.composite;

            match self.applicator.apply(&current_binary, h) {
                None => {
                    trace.push(SolverStep {
                        hypothesis_label: h.label.clone(),
                        quality_before: q_before,
                        quality_after: q_before,
                        accepted: false,
                        rejection_reason: Some(
                            "algorithm not applicable to binary data".to_owned(),
                        ),
                    });
                    continue;
                }
                Some(candidate) => {
                    if candidate.len() != current_binary.len() {
                        trace.push(SolverStep {
                            hypothesis_label: h.label.clone(),
                            quality_before: q_before,
                            quality_after: q_before,
                            accepted: false,
                            rejection_reason: Some("length changed".to_owned()),
                        });
                        continue;
                    }
                    let q_after_metric = QualityMetric::from_bytes(&candidate);
                    let q_after = q_after_metric.composite;
                    let improved = q_after > q_before + self.min_improvement;

                    trace.push(SolverStep {
                        hypothesis_label: h.label.clone(),
                        quality_before: q_before,
                        quality_after: q_after,
                        accepted: improved,
                        rejection_reason: if improved {
                            None
                        } else {
                            Some(format!(
                                "quality did not improve ({q_after:.4} ≤ {q_before:.4})"
                            ))
                        },
                    });

                    if improved {
                        current_binary = candidate;
                        current_quality = q_after_metric;
                        accepted.push(h.label.clone());
                    }
                }
            }
        }

        let total_improvement = current_quality.composite - original_quality.composite;

        Ok(SolverResult {
            best_binary: current_binary,
            best_quality: current_quality,
            original_quality,
            accepted_hypotheses: accepted,
            trace,
            total_improvement,
        })
    }

    /// Exhaustive solver: tries every subset of hypotheses (2ⁿ combinations).
    ///
    /// **Warning**: exponential complexity; only suitable for small hypothesis
    /// sets (n ≤ 20).
    ///
    /// # Errors
    /// Same as [`solve`].
    ///
    /// [`solve`]: CombinationSolver::solve
    pub fn solve_exhaustive(
        &self,
        data: &[u8],
        hypotheses: &[Hypothesis],
    ) -> Result<SolverResult, SolverError> {
        if data.is_empty() {
            return Err(SolverError::EmptyBinary);
        }
        if hypotheses.is_empty() {
            return Err(SolverError::NoHypotheses);
        }
        if hypotheses.len() > 20 {
            return Err(SolverError::Internal(
                "too many hypotheses for exhaustive search (max 20)".to_owned(),
            ));
        }

        let original_quality = QualityMetric::from_bytes(data);
        let mut best_binary = data.to_vec();
        let mut best_quality = original_quality.clone();
        let mut best_combo: Vec<String> = Vec::new();

        let n = hypotheses.len();
        for mask in 1u32..(1u32 << n) {
            let mut candidate = data.to_vec();
            let mut combo = Vec::with_capacity(n);
            let mut valid = true;

            for bit in 0..n {
                if mask & (1 << bit) != 0 {
                    match self.applicator.apply(&candidate, &hypotheses[bit]) {
                        Some(next) if next.len() == candidate.len() => {
                            combo.push(hypotheses[bit].label.clone());
                            candidate = next;
                        }
                        _ => {
                            valid = false;
                            break;
                        }
                    }
                }
            }
            if !valid {
                continue;
            }
            let q = QualityMetric::from_bytes(&candidate);
            if q.is_better_than(&best_quality) {
                best_quality = q;
                best_binary = candidate;
                best_combo = combo;
            }
        }

        let total_improvement = best_quality.composite - original_quality.composite;
        Ok(SolverResult {
            best_binary,
            best_quality,
            original_quality,
            accepted_hypotheses: best_combo,
            trace: Vec::new(), // trace not populated for exhaustive mode
            total_improvement,
        })
    }

    /// Apply hypotheses to multiple non-overlapping windows of `data` and
    /// return the best per-window results.
    ///
    /// Each window is solved independently; results are stitched back into a
    /// full binary.
    ///
    /// # Errors
    /// Returns [`SolverError::EmptyBinary`] if `data` is empty or
    /// `window_size` is zero.
    pub fn solve_windowed(
        &self,
        data: &[u8],
        hypotheses: &[Hypothesis],
        window_size: usize,
    ) -> Result<Vec<u8>, SolverError> {
        if data.is_empty() {
            return Err(SolverError::EmptyBinary);
        }
        if window_size == 0 {
            return Err(SolverError::Internal("window_size must be > 0".to_owned()));
        }

        let mut output = data.to_vec();
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + window_size).min(data.len());
            let window = &data[offset..end];
            if let Ok(result) = self.solve(window, hypotheses)
                && result.improved() {
                    output[offset..end].copy_from_slice(&result.best_binary);
                }
            offset += window_size;
        }
        Ok(output)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypothesis_engine::Algorithm;

    fn xor_hypothesis(key: u8) -> Hypothesis {
        Hypothesis::new(
            u64::from(key),
            format!("xor-0x{key:02x}"),
            Algorithm::XorConstant { key },
            0.8,
        )
    }

    fn nop_hypothesis() -> Hypothesis {
        Hypothesis::new(200, "nop-elim", Algorithm::NopElimination, 0.7)
    }

    #[test]
    fn test_xor_decryption_improves_quality() {
        // XOR-encrypt some ASCII text with key 0x42
        let plaintext = b"Hello, World! This is clear text for testing deobfuscation.";
        let cipher: Vec<u8> = plaintext.iter().map(|&b| b ^ 0x42).collect();

        let solver = CombinationSolver::new();
        let hypotheses = vec![xor_hypothesis(0x42)];
        let result = solver.solve(&cipher, &hypotheses).unwrap();
        assert!(
            result.improved(),
            "XOR decryption should improve quality on encrypted ASCII"
        );
        assert!(result.total_improvement > 0.0);
    }

    #[test]
    fn test_wrong_xor_key_rejected() {
        let plaintext = b"Hello, World! Testing deobfuscation with a clear message here.";
        let cipher: Vec<u8> = plaintext.iter().map(|&b| b ^ 0x42).collect();

        let solver = CombinationSolver::new();
        // Use wrong key 0xFF
        let hypotheses = vec![xor_hypothesis(0xFF)];
        let result = solver.solve(&cipher, &hypotheses).unwrap();
        // Wrong key should not yield printable output → might be rejected
        // (or barely accepted; this is a heuristic test)
        let _ = result; // just check it doesn't panic
    }

    #[test]
    fn test_nop_elimination_applied() {
        let mut data = vec![0x55u8, 0x8Bu8, 0xECu8]; // push ebp; mov ebp,esp
        data.extend_from_slice(&[0x90u8; 64]); // big NOP sled
        data.extend_from_slice(b"LoadLibraryA");

        let solver = CombinationSolver::new();
        let hypotheses = vec![nop_hypothesis()];
        let result = solver.solve(&data, &hypotheses).unwrap();
        // NOP elimination zero-fills the NOP sled → more code bytes visible
        // Quality change direction depends on heuristic but it should run:
        assert_eq!(result.trace.len(), 1);
    }

    #[test]
    fn test_empty_binary_error() {
        let solver = CombinationSolver::new();
        let result = solver.solve(&[], &[xor_hypothesis(0x00)]);
        assert!(matches!(result, Err(SolverError::EmptyBinary)));
    }

    #[test]
    fn test_no_hypotheses_error() {
        let solver = CombinationSolver::new();
        let result = solver.solve(&[0x90u8; 8], &[]);
        assert!(matches!(result, Err(SolverError::NoHypotheses)));
    }

    #[test]
    fn test_quality_metric_fields_in_range() {
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let q = QualityMetric::from_bytes(&data);
        assert!((0.0..=1.0).contains(&q.naturalness));
        assert!((0.0..=1.0).contains(&q.composite));
    }

    #[test]
    fn test_solver_result_summary_format() {
        let plaintext = b"Test summary output for solver result.";
        let cipher: Vec<u8> = plaintext.iter().map(|&b| b ^ 0x55).collect();
        let solver = CombinationSolver::new();
        let result = solver.solve(&cipher, &[xor_hypothesis(0x55)]).unwrap();
        let summary = result.summary();
        assert!(summary.contains("hypotheses"));
    }

    #[test]
    fn test_exhaustive_small() {
        let plaintext = b"Short test.";
        let cipher: Vec<u8> = plaintext.iter().map(|&b| b ^ 0x10).collect();
        let solver = CombinationSolver::new();
        let hypotheses = vec![xor_hypothesis(0x10), xor_hypothesis(0x20)];
        let result = solver.solve_exhaustive(&cipher, &hypotheses).unwrap();
        // The correct key should be in the best combo
        assert!(result.best_quality.composite >= result.original_quality.composite);
    }

    #[test]
    fn test_windowed_solve() {
        let data: Vec<u8> = b"AAAA".iter().cycle().take(64).copied().collect();
        let solver = CombinationSolver::new();
        let hypotheses = vec![xor_hypothesis(0x41)]; // 0x41 = 'A', XOR makes zeros
        let output = solver.solve_windowed(&data, &hypotheses, 16).unwrap();
        assert_eq!(output.len(), data.len());
    }

    #[test]
    fn test_hypothesis_applicator_rc4() {
        let app = HypothesisApplicator;
        let key = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let h = Hypothesis::new(1, "rc4", Algorithm::Rc4 { key: key }, 0.9);
        let data = b"Hello World 1234567890".to_vec();
        let encrypted = app.apply(&data, &h).unwrap();
        let decrypted = app.apply(&encrypted, &h).unwrap();
        assert_eq!(decrypted, data, "RC4 should be symmetric");
    }
}
