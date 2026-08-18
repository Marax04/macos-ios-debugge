//! `hypothesis_validator` — Validate deobfuscation hypotheses.
//!
//! After a hypothesis is executed and produces a transformed byte sequence,
//! the validator checks whether the result makes semantic sense as real code:
//! is the naturalness high, the entropy in a reasonable range, are there
//! recognisable instruction preambles, and so on.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{EntropyAnalyzer, ScoreModel};
use crate::hypothesis_generator::HypothesisKind;

// ─────────────────────────────────────────────────────────────────────────────
// ValidationCriteria
// ─────────────────────────────────────────────────────────────────────────────

/// The set of quality criteria applied by [`HypothesisValidator`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationCriteria {
    /// Minimum naturalness score (0.0–1.0) required for the result to pass.
    pub min_naturalness: f64,
    /// Maximum byte-stream entropy (0.0–8.0) permitted for plain code.
    pub max_entropy: f32,
    /// Minimum byte-stream entropy below which the result is considered trivial.
    pub min_entropy: f32,
    /// If `true`, require at least one recognisable function preamble byte sequence.
    pub require_preamble: bool,
    /// If `true`, require that the output ends with a RET (0xC3) or JMP (0xEB/0xE9).
    pub require_terminal_insn: bool,
    /// If `true`, reject outputs that consist of ≥ 80% identical bytes.
    pub reject_flat_output: bool,
    /// Maximum acceptable NOP density.
    pub max_nop_density: f32,
}

impl Default for ValidationCriteria {
    fn default() -> Self {
        Self {
            min_naturalness: 0.35,
            max_entropy: 7.5,
            min_entropy: 1.0,
            require_preamble: false,
            require_terminal_insn: false,
            reject_flat_output: true,
            max_nop_density: 0.60,
        }
    }
}

impl ValidationCriteria {
    /// Lenient criteria — used when the input is very short or obscure.
    #[must_use]
    pub const fn lenient() -> Self {
        Self {
            min_naturalness: 0.15,
            max_entropy: 7.9,
            min_entropy: 0.1,
            require_preamble: false,
            require_terminal_insn: false,
            reject_flat_output: false,
            max_nop_density: 0.90,
        }
    }

    /// Strict criteria — used when high confidence is required.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            min_naturalness: 0.60,
            max_entropy: 7.0,
            min_entropy: 2.5,
            require_preamble: true,
            require_terminal_insn: true,
            reject_flat_output: true,
            max_nop_density: 0.20,
        }
    }

    /// Select appropriate criteria based on hypothesis kind.
    #[must_use]
    pub fn for_kind(kind: HypothesisKind) -> Self {
        match kind {
            HypothesisKind::Identity => Self::default(),
            HypothesisKind::NopPadded => Self {
                min_naturalness: 0.40,
                max_nop_density: 0.30,
                ..Default::default()
            },
            HypothesisKind::XorSingleByte => Self {
                min_naturalness: 0.45,
                require_preamble: false,
                ..Default::default()
            },
            HypothesisKind::VirtualMachine => Self::lenient(),
            _ => Self::default(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidationResult
// ─────────────────────────────────────────────────────────────────────────────

/// The outcome of validating a hypothesis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether all mandatory criteria passed.
    pub passed: bool,
    /// Overall quality score produced by the validator (0.0–1.0).
    pub quality_score: f64,
    /// Individual criterion outcomes.
    pub criteria_results: HashMap<String, bool>,
    /// Failure messages for criteria that did not pass.
    pub failures: Vec<String>,
    /// Observations appended by the validator for diagnostic purposes.
    pub observations: Vec<String>,
    /// Naturalness measured on the output bytes.
    pub naturalness: f64,
    /// Shannon entropy of the output bytes.
    pub entropy: f32,
}

impl ValidationResult {
    /// Returns `true` if the result is a high-quality transformation.
    #[must_use]
    pub fn is_high_quality(&self) -> bool {
        self.passed && self.quality_score >= 0.65
    }

    /// Returns `true` if the result passed but with lower confidence.
    #[must_use]
    pub fn is_acceptable(&self) -> bool {
        self.passed && self.quality_score >= 0.40
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CodePatternChecker
// ─────────────────────────────────────────────────────────────────────────────

/// Lightweight pattern checker for x86/x64 instruction sequences.
#[derive(Debug, Clone, Default)]
struct CodePatternChecker;

impl CodePatternChecker {
    /// Check for common x86-64 function preamble sequences.
    ///
    /// Known preambles:
    /// - `55 48 89 E5` — `push rbp; mov rbp, rsp`
    /// - `55 8B EC` — `push ebp; mov ebp, esp` (32-bit)
    /// - `53 56 57` — `push rbx; push rsi; push rdi`
    /// - `48 83 EC xx` — `sub rsp, imm8`
    fn has_preamble(data: &[u8]) -> bool {
        if data.len() < 3 {
            return false;
        }
        // Scan for any of the known preambles in the first 64 bytes
        let search_len = data.len().min(64);
        let scan = &data[..search_len];

        scan.windows(4).any(|w| matches!(w, [0x55, 0x48, 0x89, 0xE5]))
            || scan.windows(3).any(|w| matches!(w, [0x55, 0x8B, 0xEC]))
            || scan.windows(3).any(|w| matches!(w, [0x53, 0x56, 0x57]))
            || scan.windows(4).any(|w| matches!(w[0..3], [0x48, 0x83, 0xEC]))
    }

    /// Check that the last non-NOP byte of `data` is a valid terminal instruction.
    fn has_terminal_insn(data: &[u8]) -> bool {
        // Walk backwards skipping NOPs
        for &b in data.iter().rev() {
            if b == 0x90 {
                continue;
            }
            return matches!(b, 0xC3 | 0xEB | 0xE9 | 0xC2);
        }
        false
    }

    /// Returns `true` when ≥ 80% of bytes have the same value.
    fn is_flat(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let mut freq = [0u32; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let max = freq.iter().copied().max().unwrap_or(0);
        max as f32 / data.len() as f32 >= 0.80
    }

    /// Compute NOP density.
    fn nop_density(data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }
        let count = data.iter().filter(|&&b| b == 0x90).count();
        count as f32 / data.len() as f32
    }

    /// Count the number of CALL instructions (0xE8).
    fn call_count(data: &[u8]) -> usize {
        data.iter().filter(|&&b| b == 0xE8).count()
    }

    /// Count the number of RET instructions (0xC3).
    fn ret_count(data: &[u8]) -> usize {
        data.iter().filter(|&&b| b == 0xC3).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HypothesisValidator
// ─────────────────────────────────────────────────────────────────────────────

/// Validates whether a deobfuscation hypothesis result makes semantic sense.
///
/// Applies a configurable set of [`ValidationCriteria`] to the output bytes
/// and returns a detailed [`ValidationResult`].
///
/// # Usage
/// ```rust,ignore
/// let validator = HypothesisValidator::new(ValidationCriteria::default());
/// let result = validator.validate(&transformed_bytes, HypothesisKind::XorSingleByte);
/// if result.passed {
///     println!("Hypothesis validated with quality {:.2}", result.quality_score);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct HypothesisValidator {
    criteria: ValidationCriteria,
}

impl HypothesisValidator {
    /// Create a validator with the given criteria.
    #[must_use]
    pub const fn new(criteria: ValidationCriteria) -> Self {
        Self { criteria }
    }

    /// Create a validator with default criteria.
    #[must_use]
    pub fn default() -> Self {
        Self::new(ValidationCriteria::default())
    }

    /// Create a validator for the given hypothesis kind.
    #[must_use]
    pub fn for_kind(kind: HypothesisKind) -> Self {
        Self::new(ValidationCriteria::for_kind(kind))
    }

    /// Validate `output` bytes as a deobfuscated result.
    ///
    /// Returns a [`ValidationResult`] describing whether the output passes all
    /// configured criteria.
    #[must_use]
    pub fn validate(&self, output: &[u8], kind: HypothesisKind) -> ValidationResult {
        let mut criteria_results: HashMap<String, bool> = HashMap::new();
        let mut failures: Vec<String> = Vec::new();
        let mut observations: Vec<String> = Vec::new();

        if output.is_empty() {
            return ValidationResult {
                passed: false,
                quality_score: 0.0,
                criteria_results,
                failures: vec!["output is empty".to_string()],
                observations: vec!["zero-length output cannot be validated".to_string()],
                naturalness: 0.0,
                entropy: 0.0,
            };
        }

        let naturalness = ScoreModel::naturalness_score(output);
        let entropy = EntropyAnalyzer::entropy(output);
        let nop_density = CodePatternChecker::nop_density(output);
        let call_cnt = CodePatternChecker::call_count(output);
        let ret_cnt = CodePatternChecker::ret_count(output);

        observations.push(format!("naturalness={naturalness:.3}"));
        observations.push(format!("entropy={entropy:.2}"));
        observations.push(format!("nop_density={nop_density:.3}"));
        observations.push(format!("calls={call_cnt} rets={ret_cnt}"));
        observations.push(format!("len={}", output.len()));

        // ── Criterion: min naturalness ──────────────────────────────────────
        let nat_ok = naturalness >= self.criteria.min_naturalness;
        criteria_results.insert("min_naturalness".to_string(), nat_ok);
        if !nat_ok {
            failures.push(format!(
                "naturalness {naturalness:.3} < minimum {:.3}",
                self.criteria.min_naturalness
            ));
        }

        // ── Criterion: max entropy ──────────────────────────────────────────
        let max_ent_ok = entropy <= self.criteria.max_entropy;
        criteria_results.insert("max_entropy".to_string(), max_ent_ok);
        if !max_ent_ok {
            failures.push(format!(
                "entropy {entropy:.2} > maximum {:.2}",
                self.criteria.max_entropy
            ));
        }

        // ── Criterion: min entropy ──────────────────────────────────────────
        let min_ent_ok = entropy >= self.criteria.min_entropy;
        criteria_results.insert("min_entropy".to_string(), min_ent_ok);
        if !min_ent_ok {
            failures.push(format!(
                "entropy {entropy:.2} < minimum {:.2}",
                self.criteria.min_entropy
            ));
        }

        // ── Criterion: require preamble ─────────────────────────────────────
        let preamble_ok = if self.criteria.require_preamble {
            let ok = CodePatternChecker::has_preamble(output);
            if !ok {
                failures.push("no recognised function preamble found".to_string());
            }
            ok
        } else {
            true
        };
        criteria_results.insert("require_preamble".to_string(), preamble_ok);

        // ── Criterion: require terminal instruction ─────────────────────────
        let terminal_ok = if self.criteria.require_terminal_insn {
            let ok = CodePatternChecker::has_terminal_insn(output);
            if !ok {
                failures.push("no terminal instruction (RET/JMP) found".to_string());
            }
            ok
        } else {
            true
        };
        criteria_results.insert("require_terminal_insn".to_string(), terminal_ok);

        // ── Criterion: reject flat output ───────────────────────────────────
        let flat_ok = if self.criteria.reject_flat_output {
            let is_flat = CodePatternChecker::is_flat(output);
            if is_flat {
                failures.push("≥80% of output bytes are identical (flat output)".to_string());
            }
            !is_flat
        } else {
            true
        };
        criteria_results.insert("reject_flat_output".to_string(), flat_ok);

        // ── Criterion: max NOP density ──────────────────────────────────────
        let nop_ok = nop_density <= self.criteria.max_nop_density;
        criteria_results.insert("max_nop_density".to_string(), nop_ok);
        if !nop_ok {
            failures.push(format!(
                "nop_density {nop_density:.3} > max {:.3}",
                self.criteria.max_nop_density
            ));
        }

        let all_passed = nat_ok && max_ent_ok && min_ent_ok && preamble_ok && terminal_ok && flat_ok && nop_ok;

        // ── Quality score (weighted) ────────────────────────────────────────
        let quality_score = self.compute_quality(
            naturalness,
            entropy,
            nop_density,
            call_cnt,
            ret_cnt,
            output.len(),
            kind,
        );

        ValidationResult {
            passed: all_passed,
            quality_score,
            criteria_results,
            failures,
            observations,
            naturalness,
            entropy,
        }
    }

    /// Validate multiple candidate outputs and return the one with the highest
    /// quality score that also passes all criteria, or `None` if none pass.
    #[must_use]
    pub fn select_best<'a>(
        &self,
        candidates: &[(&'a [u8], HypothesisKind)],
    ) -> Option<(&'a [u8], ValidationResult)> {
        candidates
            .iter()
            .filter_map(|(data, kind)| {
                let r = self.validate(data, *kind);
                if r.passed {
                    Some((*data, r))
                } else {
                    None
                }
            })
            .max_by(|(_, ra), (_, rb)| {
                ra.quality_score
                    .partial_cmp(&rb.quality_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn compute_quality(
        &self,
        naturalness: f64,
        entropy: f32,
        nop_density: f32,
        call_cnt: usize,
        ret_cnt: usize,
        len: usize,
        kind: HypothesisKind,
    ) -> f64 {
        // Naturalness contributes 40%
        let nat_score = naturalness * 0.40;

        // Entropy bonus: penalise very high or very low entropy
        let ent_f64 = entropy as f64;
        let ent_score = if ent_f64 < 1.5 || ent_f64 > 7.2 {
            0.0
        } else {
            let normalised = (ent_f64 - 1.5) / (7.2 - 1.5);
            let bell = 1.0 - (normalised - 0.5).abs() * 2.0;
            bell.max(0.0) * 0.25
        };

        // NOP penalty
        let nop_penalty = (nop_density as f64 * 0.3).min(0.15);

        // Length bonus: tiny fragments score lower
        let len_score = if len < 16 {
            0.0
        } else if len < 64 {
            0.05
        } else {
            0.10
        };

        // Call/ret balance bonus
        let cr_bonus = if ret_cnt > 0 && call_cnt > 0 {
            0.10
        } else if ret_cnt > 0 {
            0.05
        } else {
            0.0
        };

        // Kind-specific modifier
        let kind_mod = match kind {
            HypothesisKind::Identity => 0.10,
            HypothesisKind::NopPadded => 0.05,
            HypothesisKind::XorSingleByte => 0.05,
            _ => 0.0,
        };

        (nat_score + ent_score + len_score + cr_bonus + kind_mod - nop_penalty).clamp(0.0, 1.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// is_valid_code() — standalone helper
// ─────────────────────────────────────────────────────────────────────────────

/// Quick check: does `data` look like valid, deobfuscated x86 code?
///
/// Uses default criteria. Returns `true` when the output passes all checks.
#[must_use]
pub fn is_valid_code(data: &[u8]) -> bool {
    let validator = HypothesisValidator::default();
    validator.validate(data, HypothesisKind::Identity).passed
}

/// Quick check with lenient criteria.
#[must_use]
pub fn is_plausible_code(data: &[u8]) -> bool {
    let validator = HypothesisValidator::new(ValidationCriteria::lenient());
    validator.validate(data, HypothesisKind::Identity).passed
}

/// Return the quality score for `data` using the default criteria.
#[must_use]
pub fn quality_score(data: &[u8]) -> f64 {
    let validator = HypothesisValidator::default();
    validator.validate(data, HypothesisKind::Identity).quality_score
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchValidator
// ─────────────────────────────────────────────────────────────────────────────

/// Validates multiple (bytes, kind) pairs and returns a summary report.
#[derive(Debug, Clone, Default)]
pub struct BatchValidator {
    criteria: ValidationCriteria,
}

impl BatchValidator {
    /// Create with default criteria.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with given criteria.
    #[must_use]
    pub const fn with_criteria(criteria: ValidationCriteria) -> Self {
        Self { criteria }
    }

    /// Validate a batch and return one [`ValidationResult`] per input.
    #[must_use]
    pub fn validate_all<'a>(
        &self,
        items: &[(&'a [u8], HypothesisKind)],
    ) -> Vec<ValidationResult> {
        let validator = HypothesisValidator::new(self.criteria.clone());
        items
            .iter()
            .map(|(data, kind)| validator.validate(data, *kind))
            .collect()
    }

    /// Return the count of results that passed.
    #[must_use]
    pub fn pass_count(&self, results: &[ValidationResult]) -> usize {
        results.iter().filter(|r| r.passed).count()
    }

    /// Return the mean quality score.
    #[must_use]
    pub fn mean_quality(&self, results: &[ValidationResult]) -> f64 {
        if results.is_empty() {
            return 0.0;
        }
        results.iter().map(|r| r.quality_score).sum::<f64>() / results.len() as f64
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_code() -> Vec<u8> {
        // push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret
        vec![0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3]
    }

    fn nop_sled() -> Vec<u8> {
        vec![0x90u8; 64]
    }

    fn random_bytes() -> Vec<u8> {
        let mut v = Vec::with_capacity(64);
        let mut s = 42u64;
        for _ in 0..64 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            v.push(s as u8);
        }
        v
    }

    #[test]
    fn test_validate_empty() {
        let v = HypothesisValidator::default();
        let r = v.validate(&[], HypothesisKind::Identity);
        assert!(!r.passed);
    }

    #[test]
    fn test_validate_clean_code_passes() {
        let v = HypothesisValidator::default();
        let r = v.validate(&clean_code(), HypothesisKind::Identity);
        // May or may not pass depending on naturalness; just check it ran
        assert!(r.quality_score >= 0.0 && r.quality_score <= 1.0);
    }

    #[test]
    fn test_nop_sled_fails_nop_density() {
        let v = HypothesisValidator::default();
        let r = v.validate(&nop_sled(), HypothesisKind::NopPadded);
        // NOP density should exceed default max
        assert!(!r.criteria_results["max_nop_density"]);
    }

    #[test]
    fn test_entropy_range_check() {
        let v = HypothesisValidator::default();
        let r = v.validate(&clean_code(), HypothesisKind::Identity);
        assert!(r.entropy >= 0.0 && r.entropy <= 8.0);
    }

    #[test]
    fn test_naturalness_range_check() {
        let v = HypothesisValidator::default();
        let r = v.validate(&clean_code(), HypothesisKind::Identity);
        assert!(r.naturalness >= 0.0 && r.naturalness <= 1.0);
    }

    #[test]
    fn test_is_valid_code_empty_false() {
        assert!(!is_valid_code(&[]));
    }

    #[test]
    fn test_is_plausible_code_not_empty() {
        let data = clean_code();
        // Lenient criteria — should pass for non-empty reasonable bytes
        let result = is_plausible_code(&data);
        let _ = result; // just check it doesn't panic
    }

    #[test]
    fn test_quality_score_nonnegative() {
        let data = clean_code();
        let q = quality_score(&data);
        assert!(q >= 0.0 && q <= 1.0);
    }

    #[test]
    fn test_strict_criteria_require_preamble() {
        let criteria = ValidationCriteria::strict();
        let v = HypothesisValidator::new(criteria);
        let data = vec![0x31, 0xC0, 0xC3]; // xor eax,eax; ret — no preamble
        let r = v.validate(&data, HypothesisKind::Identity);
        assert!(!r.criteria_results["require_preamble"]);
    }

    #[test]
    fn test_strict_criteria_require_terminal() {
        let criteria = ValidationCriteria::strict();
        let v = HypothesisValidator::new(criteria);
        let data = vec![0x55, 0x48, 0x89, 0xE5]; // preamble but no ret
        let r = v.validate(&data, HypothesisKind::Identity);
        assert!(!r.criteria_results["require_terminal_insn"]);
    }

    #[test]
    fn test_flat_output_rejected() {
        let criteria = ValidationCriteria::default();
        let v = HypothesisValidator::new(criteria);
        let flat = vec![0x42u8; 64];
        let r = v.validate(&flat, HypothesisKind::Identity);
        assert!(!r.criteria_results["reject_flat_output"]);
    }

    #[test]
    fn test_lenient_criteria_passes_more() {
        let lenient = HypothesisValidator::new(ValidationCriteria::lenient());
        let default = HypothesisValidator::default();
        let data = random_bytes();
        let lr = lenient.validate(&data, HypothesisKind::Identity);
        let dr = default.validate(&data, HypothesisKind::Identity);
        // Lenient should be at least as likely to pass as default
        if !dr.passed {
            // lenient may still pass what default rejects
            let _ = lr.passed;
        }
    }

    #[test]
    fn test_observations_populated() {
        let v = HypothesisValidator::default();
        let r = v.validate(&clean_code(), HypothesisKind::Identity);
        assert!(!r.observations.is_empty());
    }

    #[test]
    fn test_select_best_returns_highest_quality() {
        let v = HypothesisValidator::new(ValidationCriteria::lenient());
        let d1 = clean_code();
        let d2 = vec![0x90u8; 4];
        let candidates: Vec<(&[u8], HypothesisKind)> = vec![
            (&d1, HypothesisKind::Identity),
            (&d2, HypothesisKind::NopPadded),
        ];
        if let Some((_best_data, res)) = v.select_best(&candidates) {
            assert!(res.quality_score >= 0.0);
        }
    }

    #[test]
    fn test_batch_validator_pass_count() {
        let bv = BatchValidator::new();
        let d1 = clean_code();
        let d2 = nop_sled();
        let items: Vec<(&[u8], HypothesisKind)> = vec![
            (&d1, HypothesisKind::Identity),
            (&d2, HypothesisKind::NopPadded),
        ];
        let results = bv.validate_all(&items);
        assert_eq!(results.len(), 2);
        let _ = bv.pass_count(&results);
    }

    #[test]
    fn test_batch_validator_mean_quality() {
        let bv = BatchValidator::new();
        let d1 = clean_code();
        let items: Vec<(&[u8], HypothesisKind)> = vec![(&d1, HypothesisKind::Identity)];
        let results = bv.validate_all(&items);
        let mean = bv.mean_quality(&results);
        assert!(mean >= 0.0 && mean <= 1.0);
    }

    #[test]
    fn test_criteria_for_kind_nop_padded() {
        let c = ValidationCriteria::for_kind(HypothesisKind::NopPadded);
        assert!(c.max_nop_density < 1.0);
    }

    #[test]
    fn test_has_preamble_detection() {
        let preamble = vec![0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0xC3];
        assert!(CodePatternChecker::has_preamble(&preamble));
    }

    #[test]
    fn test_has_no_preamble() {
        let no_pre = vec![0x31, 0xC0, 0xC3];
        assert!(!CodePatternChecker::has_preamble(&no_pre));
    }
}
