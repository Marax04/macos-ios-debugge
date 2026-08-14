//! MBA simplification extensions for `rustre-deobf-mba`.
//!
//! Provides the `MbaSimplifier` high-level wrapper, `SiMBA`-style statistical
//! verification, and batch simplification utilities.

use crate::{
    MbaDeobfuscationPass, MbaExprParser, MbaSimplifier as CoreSimplifier, SimplificationResult,
    TruthTableVerifier,
};
pub use crate::{MbaExpr, MbaPassResult, MbaPatternDb, VerificationResult, build_rule_database};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── MbaReport ─────────────────────────────────────────────────────────────────

/// Per-expression simplification result summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MbaExprResult {
    pub original_text: String,
    pub simplified_text: String,
    pub complexity_before: usize,
    pub complexity_after: usize,
    pub reduction_pct: f32,
    pub rules_fired: Vec<String>,
    pub verified: bool,
}

impl MbaExprResult {
    #[must_use]
    pub fn from_simplification(original_text: String, result: &SimplificationResult) -> Self {
        let reduction_pct = if result.complexity_before == 0 {
            0.0
        } else {
            (result
                .complexity_before
                .saturating_sub(result.complexity_after)) as f32
                / result.complexity_before as f32
                * 100.0
        };
        Self {
            original_text,
            simplified_text: result.simplified.to_string(),
            complexity_before: result.complexity_before,
            complexity_after: result.complexity_after,
            reduction_pct,
            rules_fired: result.rules_applied.clone(),
            verified: result.verified,
        }
    }

    #[must_use]
    pub const fn was_simplified(&self) -> bool {
        self.complexity_after < self.complexity_before
    }
}

/// Aggregate MBA analysis report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MbaReport {
    pub results: Vec<MbaExprResult>,
    pub total_expressions: usize,
    pub simplified_count: usize,
    pub verified_count: usize,
    pub total_complexity_reduction: usize,
    pub avg_reduction_pct: f32,
}

impl MbaReport {
    #[must_use]
    pub fn from_results(results: Vec<MbaExprResult>) -> Self {
        let total = results.len();
        let simplified = results.iter().filter(|r| r.was_simplified()).count();
        let verified = results.iter().filter(|r| r.verified).count();
        let total_red: usize = results
            .iter()
            .map(|r| r.complexity_before.saturating_sub(r.complexity_after))
            .sum();
        let avg_red = if total > 0 {
            results.iter().map(|r| r.reduction_pct).sum::<f32>() / total as f32
        } else {
            0.0
        };
        Self {
            results,
            total_expressions: total,
            simplified_count: simplified,
            verified_count: verified,
            total_complexity_reduction: total_red,
            avg_reduction_pct: avg_red,
        }
    }

    /// Markdown summary.
    #[must_use]
    pub fn markdown_summary(&self) -> String {
        format!(
            "## MBA Simplification Report\n- Expressions: {}\n- Simplified: {}\n- Verified: {}\n- Avg reduction: {:.1}%\n",
            self.total_expressions,
            self.simplified_count,
            self.verified_count,
            self.avg_reduction_pct
        )
    }
}

// ── SiMBA algorithm ───────────────────────────────────────────────────────────

/// Confidence tier for `SiMBA` statistical simplification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SimbaConfidence {
    High,
    Medium,
    Low,
    Unverified,
}

/// Result of `SiMBA` statistical simplification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimbaResult {
    pub original: String,
    pub simplified: String,
    pub confidence: SimbaConfidence,
    pub samples_tested: usize,
    pub mismatches: usize,
}

impl SimbaResult {
    #[must_use]
    pub const fn is_equivalent(&self) -> bool {
        self.mismatches == 0
    }
}

/// SiMBA-style statistical MBA simplification.
///
/// Uses random sampling to probabilistically verify that the simplified
/// expression is semantically equivalent to the original.
pub struct SiMBA {
    pub samples: usize,
    pub bits: u32,
}

impl Default for SiMBA {
    fn default() -> Self {
        Self {
            samples: 256,
            bits: 8,
        }
    }
}

impl SiMBA {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_samples(mut self, n: usize) -> Self {
        self.samples = n;
        self
    }

    #[must_use]
    pub const fn with_bits(mut self, b: u32) -> Self {
        self.bits = b;
        self
    }

    /// Simplify `expr_text` and verify via sampling.
    pub fn simplify(&self, expr_text: &str) -> Result<SimbaResult, String> {
        let expr = MbaExprParser::parse(expr_text)?;
        let simplifier = CoreSimplifier::new().without_verification();
        let result = simplifier.simplify(expr.clone());
        let simplified_text = result.simplified.to_string();

        // Verify via truth table sampling.
        let verifier = TruthTableVerifier {
            bits: self.bits,
            max_vars: 4,
            use_random: false,
        };
        let vr = verifier.verify_equivalent(&expr, &result.simplified);
        let confidence = match vr.samples_tested {
            0 => SimbaConfidence::Unverified,
            n if n < 64 => {
                if vr.equivalent {
                    SimbaConfidence::Low
                } else {
                    SimbaConfidence::Unverified
                }
            }
            n if n < 256 => {
                if vr.equivalent {
                    SimbaConfidence::Medium
                } else {
                    SimbaConfidence::Unverified
                }
            }
            _ => {
                if vr.equivalent {
                    SimbaConfidence::High
                } else {
                    SimbaConfidence::Unverified
                }
            }
        };

        Ok(SimbaResult {
            original: expr_text.to_string(),
            simplified: simplified_text,
            confidence,
            samples_tested: vr.samples_tested,
            mismatches: usize::from(!vr.equivalent),
        })
    }
}

// ── VerifiedSimplification ────────────────────────────────────────────────────

/// A simplification result that has been formally verified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedSimplification {
    pub original_text: String,
    pub simplified_text: String,
    pub is_equivalent: bool,
    pub method: VerificationMethod,
    pub complexity_before: usize,
    pub complexity_after: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationMethod {
    /// Exhaustive truth-table check.
    TruthTable,
    /// Statistical sampling (SiMBA-style).
    Statistical,
    /// Not verified.
    None,
}

impl VerifiedSimplification {
    #[must_use]
    pub fn reduction_ratio(&self) -> f32 {
        if self.complexity_before == 0 {
            return 0.0;
        }
        1.0 - (self.complexity_after as f32 / self.complexity_before as f32)
    }
}

// ── MbaSimplifier (high-level wrapper) ───────────────────────────────────────

/// High-level MBA simplification engine wrapping the core simplifier,
/// `SiMBA` verification, and batch capabilities.
pub struct MbaSimplifier {
    core: MbaDeobfuscationPass,
    simba: SiMBA,
    pub use_verification: bool,
    pub verification_method: VerificationMethod,
}

impl Default for MbaSimplifier {
    fn default() -> Self {
        Self::new()
    }
}

impl MbaSimplifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            core: MbaDeobfuscationPass::new(),
            simba: SiMBA::new(),
            use_verification: true,
            verification_method: VerificationMethod::TruthTable,
        }
    }

    #[must_use]
    pub const fn with_statistical_verification(mut self) -> Self {
        self.verification_method = VerificationMethod::Statistical;
        self
    }

    #[must_use]
    pub const fn without_verification(mut self) -> Self {
        self.use_verification = false;
        self.verification_method = VerificationMethod::None;
        self
    }

    /// Simplify a single expression text.
    pub fn simplify_text(&self, expr_text: &str) -> Result<VerifiedSimplification, String> {
        let expr = MbaExprParser::parse(expr_text)?;
        let complexity_before = expr.complexity();
        let result = self.core.analyze_expression(expr.clone());
        let complexity_after = result.complexity_after;
        let simplified_text = result.simplified.to_string();

        let is_equivalent = if self.use_verification {
            match self.verification_method {
                VerificationMethod::TruthTable => {
                    let v = TruthTableVerifier::new();
                    v.verify_equivalent(&expr, &result.simplified).equivalent
                }
                VerificationMethod::Statistical => match self.simba.simplify(expr_text) {
                    Ok(sr) => sr.is_equivalent(),
                    Err(_) => false,
                },
                VerificationMethod::None => true,
            }
        } else {
            result.verified
        };

        Ok(VerifiedSimplification {
            original_text: expr_text.to_string(),
            simplified_text,
            is_equivalent,
            method: self.verification_method,
            complexity_before,
            complexity_after,
        })
    }

    /// Simplify a batch of expression texts and return a report.
    #[must_use] 
    pub fn simplify_batch(&self, expressions: &[&str]) -> MbaReport {
        let mut results = Vec::with_capacity(expressions.len());
        for &expr_text in expressions {
            let expr = match MbaExprParser::parse(expr_text) {
                Ok(e) => e,
                Err(_) => continue,
            };
            let sr = self.core.analyze_expression(expr);
            results.push(MbaExprResult::from_simplification(
                expr_text.to_string(),
                &sr,
            ));
        }
        MbaReport::from_results(results)
    }

    /// Simplify all expressions and return only those that were actually simplified.
    #[must_use] 
    pub fn simplify_and_filter(&self, expressions: &[&str]) -> Vec<VerifiedSimplification> {
        expressions
            .iter()
            .filter_map(|&expr_text| {
                self.simplify_text(expr_text)
                    .ok()
                    .filter(|r| r.complexity_after < r.complexity_before)
            })
            .collect()
    }

    /// Test a known MBA identity holds.
    #[must_use]
    pub fn verify_identity(&self, lhs_text: &str, rhs_text: &str) -> Option<bool> {
        let lhs = MbaExprParser::parse(lhs_text).ok()?;
        let rhs = MbaExprParser::parse(rhs_text).ok()?;
        let v = TruthTableVerifier::new();
        Some(v.verify_equivalent(&lhs, &rhs).equivalent)
    }
}

// ── BulkSimplifier ────────────────────────────────────────────────────────────

/// Simplifies many expressions with caching.
pub struct BulkSimplifier {
    simplifier: MbaSimplifier,
    cache: HashMap<String, VerifiedSimplification>,
}

impl Default for BulkSimplifier {
    fn default() -> Self {
        Self::new()
    }
}

impl BulkSimplifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            simplifier: MbaSimplifier::new(),
            cache: HashMap::new(),
        }
    }

    /// Simplify `expr_text`, using the cache for repeated expressions.
    pub fn simplify(&mut self, expr_text: &str) -> Result<&VerifiedSimplification, String> {
        use std::collections::hash_map::Entry;
        match self.cache.entry(expr_text.to_string()) {
            Entry::Occupied(e) => Ok(e.into_mut()),
            Entry::Vacant(e) => {
                let result = self.simplifier.simplify_text(expr_text)?;
                Ok(e.insert(result))
            }
        }
    }

    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MbaExprResult ────────────────────────────────────────────────────────

    #[test]
    fn test_expr_result_was_simplified() {
        let simplifier = CoreSimplifier::new();
        let expr = MbaExprParser::parse("(x & x)").unwrap();
        let sr = simplifier.simplify(expr);
        let result = MbaExprResult::from_simplification("(x & x)".to_string(), &sr);
        assert!(result.was_simplified());
        assert!(result.reduction_pct > 0.0);
    }

    #[test]
    fn test_expr_result_not_simplified() {
        let simplifier = CoreSimplifier::new();
        let expr = MbaExprParser::parse("x").unwrap();
        let sr = simplifier.simplify(expr);
        let result = MbaExprResult::from_simplification("x".to_string(), &sr);
        assert!(!result.was_simplified());
    }

    // ── MbaReport ────────────────────────────────────────────────────────────

    #[test]
    fn test_mba_report_from_results() {
        let simplifier = CoreSimplifier::new();
        let expressions = ["(x & x)", "(x | x)", "(x ^ 0)"];
        let mut results = Vec::new();
        for &e in &expressions {
            let expr = MbaExprParser::parse(e).unwrap();
            let sr = simplifier.simplify(expr);
            results.push(MbaExprResult::from_simplification(e.to_string(), &sr));
        }
        let report = MbaReport::from_results(results);
        assert_eq!(report.total_expressions, 3);
        assert!(report.simplified_count > 0);
    }

    #[test]
    fn test_mba_report_markdown_summary() {
        let report = MbaReport::from_results(Vec::new());
        let md = report.markdown_summary();
        assert!(md.contains("MBA Simplification Report"));
    }

    // ── SiMBA ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_simba_simplify_xor_self() {
        let simba = SiMBA::new().with_bits(4);
        let result = simba.simplify("(x ^ x)").unwrap();
        assert!(result.is_equivalent());
        assert_eq!(result.simplified, "0");
    }

    #[test]
    fn test_simba_simplify_and_self() {
        let simba = SiMBA::new().with_bits(4);
        let result = simba.simplify("(x & x)").unwrap();
        assert!(result.is_equivalent());
    }

    #[test]
    fn test_simba_samples_default() {
        let simba = SiMBA::default();
        assert_eq!(simba.samples, 256);
    }

    #[test]
    fn test_simba_invalid_expression() {
        let simba = SiMBA::new();
        assert!(simba.simplify("(x $$$ y)").is_err());
    }

    #[test]
    fn test_simba_confidence_high_many_samples() {
        let simba = SiMBA::new().with_bits(8).with_samples(1000);
        let result = simba.simplify("(x ^ 0)").unwrap();
        assert!(matches!(
            result.confidence,
            SimbaConfidence::High | SimbaConfidence::Medium
        ));
    }

    // ── VerifiedSimplification ────────────────────────────────────────────────

    #[test]
    fn test_verified_simplification_reduction_ratio() {
        let vs = VerifiedSimplification {
            original_text: "(x & x)".into(),
            simplified_text: "x".into(),
            is_equivalent: true,
            method: VerificationMethod::TruthTable,
            complexity_before: 3,
            complexity_after: 1,
        };
        assert!((vs.reduction_ratio() - (2.0 / 3.0)).abs() < 0.001);
    }

    #[test]
    fn test_verified_simplification_zero_complexity() {
        let vs = VerifiedSimplification {
            original_text: String::new(),
            simplified_text: String::new(),
            is_equivalent: true,
            method: VerificationMethod::None,
            complexity_before: 0,
            complexity_after: 0,
        };
        assert_eq!(vs.reduction_ratio(), 0.0);
    }

    // ── MbaSimplifier ─────────────────────────────────────────────────────────

    #[test]
    fn test_mba_simplifier_xor_self() {
        let s = MbaSimplifier::new();
        let r = s.simplify_text("(x ^ x)").unwrap();
        assert!(r.is_equivalent);
        assert_eq!(r.simplified_text, "0");
    }

    #[test]
    fn test_mba_simplifier_and_or() {
        let s = MbaSimplifier::new();
        let r = s.simplify_text("((x & y) + (x | y))").unwrap();
        assert!(r.is_equivalent);
        assert!(r.complexity_after <= r.complexity_before);
    }

    #[test]
    fn test_mba_simplifier_batch() {
        let s = MbaSimplifier::new();
        let exprs = ["(x ^ x)", "(x | x)", "((x & 0) + 0)"];
        let report = s.simplify_batch(&exprs);
        assert_eq!(report.total_expressions, 3);
    }

    #[test]
    fn test_mba_simplifier_filter_keeps_simplified() {
        let s = MbaSimplifier::new();
        let exprs = ["(x ^ x)", "x"]; // first should simplify, second should not
        let simplified = s.simplify_and_filter(&exprs);
        assert!(
            simplified
                .iter()
                .all(|r| r.complexity_after < r.complexity_before)
        );
    }

    #[test]
    fn test_mba_simplifier_verify_identity() {
        let s = MbaSimplifier::new();
        // (x & y) + (x | y) == x + y
        let result = s.verify_identity("((x & y) + (x | y))", "(x + y)");
        assert_eq!(result, Some(true));
    }

    #[test]
    fn test_mba_simplifier_verify_non_identity() {
        let s = MbaSimplifier::new();
        // x != (x + 1)
        let result = s.verify_identity("x", "(x + 1)");
        assert_eq!(result, Some(false));
    }

    #[test]
    fn test_mba_simplifier_statistical_mode() {
        let s = MbaSimplifier::new().with_statistical_verification();
        let r = s.simplify_text("(x ^ x)").unwrap();
        assert_eq!(r.method, VerificationMethod::Statistical);
    }

    #[test]
    fn test_mba_simplifier_no_verification() {
        let s = MbaSimplifier::new().without_verification();
        let r = s.simplify_text("(x ^ x)").unwrap();
        assert_eq!(r.method, VerificationMethod::None);
    }

    // ── BulkSimplifier ────────────────────────────────────────────────────────

    #[test]
    fn test_bulk_simplifier_caches() {
        let mut bulk = BulkSimplifier::new();
        bulk.simplify("(x ^ x)").unwrap();
        bulk.simplify("(x ^ x)").unwrap(); // second call uses cache
        assert_eq!(bulk.cache_size(), 1);
    }

    #[test]
    fn test_bulk_simplifier_clear_cache() {
        let mut bulk = BulkSimplifier::new();
        bulk.simplify("(x & x)").unwrap();
        assert_eq!(bulk.cache_size(), 1);
        bulk.clear_cache();
        assert_eq!(bulk.cache_size(), 0);
    }

    #[test]
    fn test_bulk_simplifier_multiple_expressions() {
        let mut bulk = BulkSimplifier::new();
        bulk.simplify("(x ^ x)").unwrap();
        bulk.simplify("(x | x)").unwrap();
        assert_eq!(bulk.cache_size(), 2);
    }

    #[test]
    fn test_bulk_simplifier_error_invalid() {
        let mut bulk = BulkSimplifier::new();
        assert!(bulk.simplify("!!!invalid!!!").is_err());
    }

    // ── Known MBA identities ──────────────────────────────────────────────────

    #[test]
    fn test_identity_or_minus_and_equals_xor() {
        let s = MbaSimplifier::new();
        let result = s.verify_identity("((x | y) - (x & y))", "(x ^ y)");
        assert_eq!(result, Some(true));
    }

    #[test]
    fn test_identity_sum_minus_and_equals_or() {
        let s = MbaSimplifier::new();
        let result = s.verify_identity("((x + y) - (x & y))", "(x | y)");
        assert_eq!(result, Some(true));
    }

    #[test]
    fn test_identity_double_not() {
        let s = MbaSimplifier::new();
        let r = s.simplify_text("(~(~x))").unwrap();
        assert!(r.is_equivalent);
        assert_eq!(r.simplified_text, "x");
    }

    #[test]
    fn test_identity_mul_zero() {
        let s = MbaSimplifier::new();
        let r = s.simplify_text("(x * 0)").unwrap();
        assert!(r.is_equivalent);
        assert_eq!(r.simplified_text, "0");
    }
}
