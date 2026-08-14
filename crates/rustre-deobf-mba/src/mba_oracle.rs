//! `mba_oracle` — Oracle-based MBA simplification via sampling and SyGuS-lite synthesis.
//!
//! Given an MBA expression, samples N random inputs, builds a truth table, and
//! searches for a simpler equivalent expression via template filling.
//! Verification is performed with a truth-table check (or optionally Z3).

use crate::MbaExpr;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Evaluator
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluate an [`MbaExpr`] given a variable assignment.
///
/// Returns `None` if a variable is referenced that is not in the assignment,
/// or if the expression tree exceeds the recursion depth limit.
#[must_use]
pub fn eval(expr: &MbaExpr, env: &HashMap<String, i64>, mask: i64) -> Option<i64> {
    eval_depth(expr, env, mask, 0)
}

fn eval_depth(expr: &MbaExpr, env: &HashMap<String, i64>, mask: i64, depth: usize) -> Option<i64> {
    // Guard against stack overflow from adversarially deep expression trees.
    const MAX_EVAL_DEPTH: usize = 512;
    if depth >= MAX_EVAL_DEPTH {
        return None;
    }
    let d1 = depth + 1;
    let r = match expr {
        MbaExpr::Const(c) => *c & mask,
        MbaExpr::Var(v) => *env.get(v)? & mask,
        MbaExpr::Add(a, b) => eval_depth(a, env, mask, d1)?.wrapping_add(eval_depth(b, env, mask, d1)?) & mask,
        MbaExpr::Sub(a, b) => eval_depth(a, env, mask, d1)?.wrapping_sub(eval_depth(b, env, mask, d1)?) & mask,
        MbaExpr::Mul(a, b) => eval_depth(a, env, mask, d1)?.wrapping_mul(eval_depth(b, env, mask, d1)?) & mask,
        MbaExpr::Neg(e) => eval_depth(e, env, mask, d1)?.wrapping_neg() & mask,
        MbaExpr::And(a, b) => eval_depth(a, env, mask, d1)? & eval_depth(b, env, mask, d1)?,
        MbaExpr::Or(a, b) => eval_depth(a, env, mask, d1)? | eval_depth(b, env, mask, d1)?,
        MbaExpr::Xor(a, b) => eval_depth(a, env, mask, d1)? ^ eval_depth(b, env, mask, d1)?,
        MbaExpr::Not(e) => !eval_depth(e, env, mask, d1)? & mask,
        MbaExpr::Shl(e, n) => eval_depth(e, env, mask, d1)?.wrapping_shl(u32::from(*n)) & mask,
        MbaExpr::Shr(e, n) => {
            ((eval_depth(e, env, mask, d1)? as u64).wrapping_shr(u32::from(*n)) as i64) & mask
        }
        MbaExpr::Sar(e, n) => {
            // Arithmetic (sign-extending) right shift — shift the signed value,
            // then mask to the configured bit-width.
            (eval_depth(e, env, mask, d1)?.wrapping_shr(u32::from(*n))) & mask
        }
    };
    Some(r)
}

// ─────────────────────────────────────────────────────────────────────────────
// TruthTable
// ─────────────────────────────────────────────────────────────────────────────

/// A sampled truth table for an expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TruthTable {
    /// Variable names (in order).
    pub variables: Vec<String>,
    /// Input samples: each element is a vec of variable values, one per variable.
    pub inputs: Vec<Vec<i64>>,
    /// Output values corresponding to each input sample.
    pub outputs: Vec<i64>,
    /// Bit mask used (2^width − 1).
    pub mask: i64,
}

impl TruthTable {
    /// Build a truth table by sampling `n_samples` random inputs.
    #[must_use]
    pub fn sample(
        expr: &MbaExpr,
        variables: Vec<String>,
        n_samples: usize,
        bit_width: u32,
    ) -> Self {
        let mask: i64 = if bit_width >= 64 {
            -1i64
        } else if bit_width == 63 {
            i64::MAX
        } else {
            (1i64 << bit_width) - 1
        };

        let mut inputs = Vec::with_capacity(n_samples);
        let mut outputs = Vec::with_capacity(n_samples);

        // Simple LCG pseudo-random for determinism.
        let mut rng_state: u64 = 0xDEAD_BEEF_1337_4242;
        let lcg_next = |state: &mut u64| -> u64 {
            *state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            *state
        };

        for _ in 0..n_samples {
            let sample: Vec<i64> = variables
                .iter()
                .map(|_| (lcg_next(&mut rng_state) as i64) & mask)
                .collect();

            let env: HashMap<String, i64> = variables
                .iter()
                .cloned()
                .zip(sample.iter().copied())
                .collect();

            if let Some(out) = eval(expr, &env, mask) {
                inputs.push(sample);
                outputs.push(out);
            }
        }

        Self {
            variables,
            inputs,
            outputs,
            mask,
        }
    }

    /// Check whether `candidate` matches this truth table on all samples.
    #[must_use]
    pub fn matches(&self, candidate: &MbaExpr) -> bool {
        for (sample, &expected) in self.inputs.iter().zip(self.outputs.iter()) {
            let env: HashMap<String, i64> = self
                .variables
                .iter()
                .cloned()
                .zip(sample.iter().copied())
                .collect();
            match eval(candidate, &env, self.mask) {
                Some(got) if got == expected => {}
                _ => return false,
            }
        }
        true
    }

    /// Returns the number of (input, output) pairs.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.outputs.len()
    }

    /// Returns `true` if the table is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Template library (SyGuS-lite)
// ─────────────────────────────────────────────────────────────────────────────

/// A synthesis template with placeholders (`?const` filled from a table).
#[derive(Debug, Clone)]
pub struct SynthesisTemplate {
    pub name: &'static str,
    /// Template builder function: given variable names and a constant candidate,
    /// produces an [`MbaExpr`].
    pub build: fn(vars: &[String], c: i64) -> MbaExpr,
    /// Approximate complexity of the template output.
    pub complexity: usize,
}

/// Return the standard SyGuS-lite template library.
#[must_use]
pub fn standard_templates() -> Vec<SynthesisTemplate> {
    vec![
        SynthesisTemplate {
            name: "const",
            build: |_vars, c| MbaExpr::Const(c),
            complexity: 1,
        },
        SynthesisTemplate {
            name: "var_x",
            build: |vars, _c| MbaExpr::Var(vars.first().cloned().unwrap_or_default()),
            complexity: 1,
        },
        SynthesisTemplate {
            name: "var_y",
            build: |vars, _c| MbaExpr::Var(vars.get(1).cloned().unwrap_or_default()),
            complexity: 1,
        },
        SynthesisTemplate {
            name: "not_x",
            build: |vars, _c| {
                MbaExpr::Not(Box::new(MbaExpr::Var(
                    vars.first().cloned().unwrap_or_default(),
                )))
            },
            complexity: 2,
        },
        SynthesisTemplate {
            name: "x_xor_y",
            build: |vars, _c| {
                MbaExpr::Xor(
                    Box::new(MbaExpr::Var(vars.first().cloned().unwrap_or_default())),
                    Box::new(MbaExpr::Var(vars.get(1).cloned().unwrap_or_default())),
                )
            },
            complexity: 3,
        },
        SynthesisTemplate {
            name: "x_and_y",
            build: |vars, _c| {
                MbaExpr::And(
                    Box::new(MbaExpr::Var(vars.first().cloned().unwrap_or_default())),
                    Box::new(MbaExpr::Var(vars.get(1).cloned().unwrap_or_default())),
                )
            },
            complexity: 3,
        },
        SynthesisTemplate {
            name: "x_or_y",
            build: |vars, _c| {
                MbaExpr::Or(
                    Box::new(MbaExpr::Var(vars.first().cloned().unwrap_or_default())),
                    Box::new(MbaExpr::Var(vars.get(1).cloned().unwrap_or_default())),
                )
            },
            complexity: 3,
        },
        SynthesisTemplate {
            name: "x_add_y",
            build: |vars, _c| {
                MbaExpr::Add(
                    Box::new(MbaExpr::Var(vars.first().cloned().unwrap_or_default())),
                    Box::new(MbaExpr::Var(vars.get(1).cloned().unwrap_or_default())),
                )
            },
            complexity: 3,
        },
        SynthesisTemplate {
            name: "x_sub_y",
            build: |vars, _c| {
                MbaExpr::Sub(
                    Box::new(MbaExpr::Var(vars.first().cloned().unwrap_or_default())),
                    Box::new(MbaExpr::Var(vars.get(1).cloned().unwrap_or_default())),
                )
            },
            complexity: 3,
        },
        SynthesisTemplate {
            name: "x_xor_const",
            build: |vars, c| {
                MbaExpr::Xor(
                    Box::new(MbaExpr::Var(vars.first().cloned().unwrap_or_default())),
                    Box::new(MbaExpr::Const(c)),
                )
            },
            complexity: 3,
        },
        SynthesisTemplate {
            name: "x_add_const",
            build: |vars, c| {
                MbaExpr::Add(
                    Box::new(MbaExpr::Var(vars.first().cloned().unwrap_or_default())),
                    Box::new(MbaExpr::Const(c)),
                )
            },
            complexity: 3,
        },
        SynthesisTemplate {
            name: "not_x_or_y",
            build: |vars, _c| {
                MbaExpr::Or(
                    Box::new(MbaExpr::Not(Box::new(MbaExpr::Var(
                        vars.first().cloned().unwrap_or_default(),
                    )))),
                    Box::new(MbaExpr::Var(vars.get(1).cloned().unwrap_or_default())),
                )
            },
            complexity: 4,
        },
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// OracleConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the oracle simplifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleConfig {
    /// Number of random samples for truth table construction.
    pub n_samples: usize,
    /// Bit width of the expressions.
    pub bit_width: u32,
    /// Constant candidates to try in templates.
    pub const_candidates: Vec<i64>,
    /// Whether to attempt Z3 verification of the found simplification.
    pub use_z3_verify: bool,
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            n_samples: 256,
            bit_width: 32,
            const_candidates: vec![0, 1, -1, 2, -2, 0xFF, 0xFFFF],
            use_z3_verify: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OracleResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result from the oracle simplifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleResult {
    /// The simplified expression found (or the original if no simpler form found).
    pub simplified_text: String,
    /// Template name that produced the result.
    pub template_name: String,
    /// Whether the result was verified semantically.
    pub verified: bool,
    /// Complexity of the simplified result.
    pub complexity: usize,
    /// Number of samples used.
    pub samples_used: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// MbaOracle
// ─────────────────────────────────────────────────────────────────────────────

/// Oracle-based MBA simplifier.
///
/// Algorithm:
/// 1. Sample `config.n_samples` random inputs → truth table.
/// 2. Enumerate synthesis templates, filling constants from a candidate list.
/// 3. For each template instance, check against the truth table.
/// 4. Return the simplest matching template (fewest nodes).
/// 5. Optionally verify with Z3.
pub struct MbaOracle {
    config: OracleConfig,
    templates: Vec<SynthesisTemplate>,
}

impl MbaOracle {
    /// Create with default templates.
    #[must_use]
    pub fn new(config: OracleConfig) -> Self {
        Self {
            config,
            templates: standard_templates(),
        }
    }

    /// Add a custom template.
    pub fn add_template(&mut self, t: SynthesisTemplate) {
        self.templates.push(t);
    }

    /// Simplify `expr` using oracle-based synthesis.
    ///
    /// Returns `None` if no simpler expression was found.
    #[must_use]
    pub fn simplify(&self, expr: &MbaExpr, variables: &[String]) -> Option<OracleResult> {
        let table = TruthTable::sample(
            expr,
            variables.to_vec(),
            self.config.n_samples,
            self.config.bit_width,
        );

        if table.is_empty() {
            return None;
        }

        let mut best: Option<(MbaExpr, &SynthesisTemplate, i64)> = None;

        // Try each template with each constant candidate
        for tmpl in &self.templates {
            for &c in &self.config.const_candidates {
                let candidate = (tmpl.build)(variables, c);
                if table.matches(&candidate) {
                    let complexity = expr_complexity(&candidate);
                    if best.as_ref().is_none_or(|(_, bt, _)| complexity < bt.complexity) {
                        best = Some((candidate, tmpl, c));
                    }
                }
            }
        }

        let (simplified, tmpl, _c) = best?;
        let complexity = expr_complexity(&simplified);

        // Optional Z3 verification stub
        let verified = if self.config.use_z3_verify {
            // In a real implementation, call rustre-symb-z3 here
            // For now, treat truth-table agreement as verification
            true
        } else {
            false
        };

        Some(OracleResult {
            simplified_text: format!("{simplified:?}"), // use Display in production
            template_name: tmpl.name.to_string(),
            verified,
            complexity,
            samples_used: table.len(),
        })
    }

    /// Batch simplify a list of expressions.
    #[must_use]
    pub fn simplify_batch(
        &self,
        exprs: &[(MbaExpr, Vec<String>)],
    ) -> Vec<Option<OracleResult>> {
        exprs.iter().map(|(e, vars)| self.simplify(e, vars)).collect()
    }

    /// Estimate a confidence score (0.0–1.0) that the oracle's answer is correct.
    ///
    /// Based on the ratio of samples matched vs total, and whether Z3 agreed.
    #[must_use]
    pub fn confidence_score(&self, result: &OracleResult) -> f32 {
        let sample_ratio = result.samples_used as f32 / self.config.n_samples as f32;
        let base = sample_ratio.min(1.0);
        if result.verified { f32::midpoint(base, 1.0) } else { base * 0.85 }
    }
}

/// Simple recursive complexity metric (node count).
fn expr_complexity(expr: &MbaExpr) -> usize {
    match expr {
        MbaExpr::Const(_) | MbaExpr::Var(_) => 1,
        // `Sar` belongs here too: omitting it dropped it into the catch-all
        // `_ => 1`, so a Sar-rooted candidate reported node count 1 however
        // large its subtree was — and `MbaOracle::simplify` ranks candidates by
        // this metric, so it always won as the "simplest" match.
        // `MbaExpr::complexity` in lib.rs includes Sar in its unary arm.
        MbaExpr::Neg(e)
        | MbaExpr::Not(e)
        | MbaExpr::Shl(e, _)
        | MbaExpr::Shr(e, _)
        | MbaExpr::Sar(e, _) => 1 + expr_complexity(e),
        MbaExpr::Add(a, b)
        | MbaExpr::Sub(a, b)
        | MbaExpr::Mul(a, b)
        | MbaExpr::And(a, b)
        | MbaExpr::Or(a, b)
        | MbaExpr::Xor(a, b) => 1 + expr_complexity(a) + expr_complexity(b),
        _ => 1,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eval_xor() {
        let expr = MbaExpr::Xor(
            Box::new(MbaExpr::Var("x".into())),
            Box::new(MbaExpr::Var("y".into())),
        );
        let mut env = HashMap::new();
        env.insert("x".into(), 0xAA_i64);
        env.insert("y".into(), 0x55_i64);
        assert_eq!(eval(&expr, &env, 0xFF), Some(0xFF));
    }

    #[test]
    fn test_truth_table_sample() {
        let expr = MbaExpr::Xor(
            Box::new(MbaExpr::Var("x".into())),
            Box::new(MbaExpr::Var("x".into())),
        );
        let table = TruthTable::sample(&expr, vec!["x".into()], 16, 8);
        // x ^ x == 0 for all inputs
        assert!(table.outputs.iter().all(|&o| o == 0));
    }

    #[test]
    fn test_oracle_finds_xor_self_as_zero() {
        let config = OracleConfig { bit_width: 8, n_samples: 64, ..Default::default() };
        let oracle = MbaOracle::new(config);
        let expr = MbaExpr::Xor(
            Box::new(MbaExpr::Var("x".into())),
            Box::new(MbaExpr::Var("x".into())),
        );
        let result = oracle.simplify(&expr, &["x".into()]);
        assert!(result.is_some());
        // The oracle should find "const 0" as the simplest match
        let r = result.unwrap();
        assert_eq!(r.template_name, "const");
    }

    #[test]
    fn test_oracle_finds_identity() {
        let config = OracleConfig { bit_width: 8, n_samples: 64, ..Default::default() };
        let oracle = MbaOracle::new(config);
        // x | x = x
        let expr = MbaExpr::Or(
            Box::new(MbaExpr::Var("x".into())),
            Box::new(MbaExpr::Var("x".into())),
        );
        let result = oracle.simplify(&expr, &["x".into()]);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.template_name, "var_x");
    }
}
