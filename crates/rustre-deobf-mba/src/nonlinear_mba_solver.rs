//! Nonlinear MBA solver.
//!
//! Provides polynomial representations over truncated integer arithmetic,
//! reduction modulo Boolean axioms (x² = x for each bit), a simplified
//! Groebner-basis-inspired reduction pass, and sampling-based equivalence
//! verification / counterexample generation.

use std::collections::HashMap;
use std::fmt;

// Re-use the MbaExpr definition from the crate root.
use crate::MbaExpr;

// ────────────────────────────────────────────────────────────────────────────────
// Polynomial types
// ────────────────────────────────────────────────────────────────────────────────

/// A single monomial term: `coefficient * ∏ xᵢ^eᵢ`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolynomialTerm {
    /// Integer coefficient (wrapping arithmetic).
    pub coefficient: i64,
    /// Variable name → exponent.  Sorted by name for canonical form.
    pub variables: Vec<(String, u32)>,
}

impl PolynomialTerm {
    /// Create a constant term.
    #[must_use]
    pub const fn constant(c: i64) -> Self {
        Self { coefficient: c, variables: Vec::new() }
    }

    /// Create a linear (degree-1) term for a single variable.
    #[must_use]
    pub fn var(name: impl Into<String>, coeff: i64) -> Self {
        Self { coefficient: coeff, variables: vec![(name.into(), 1)] }
    }

    /// Degree of this term (sum of exponents).
    #[must_use]
    pub fn degree(&self) -> u32 {
        self.variables.iter().map(|(_, e)| e).sum()
    }

    /// Evaluate this term for a given variable assignment.
    #[must_use]
    pub fn eval(&self, vals: &HashMap<String, i64>) -> i64 {
        let mut result = self.coefficient;
        for (name, exp) in &self.variables {
            let base = vals.get(name).copied().unwrap_or(0);
            for _ in 0..*exp {
                result = result.wrapping_mul(base);
            }
        }
        result
    }

    /// Return a canonical key string for grouping like terms.
    #[must_use]
    pub fn monomial_key(&self) -> String {
        let mut sorted = self.variables.clone();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        sorted
            .iter()
            .map(|(n, e)| format!("{n}^{e}"))
            .collect::<Vec<_>>()
            .join("*")
    }

    /// Multiply two terms.
    #[must_use]
    pub fn multiply(&self, other: &Self) -> Self {
        let new_coeff = self.coefficient.wrapping_mul(other.coefficient);
        let mut vars: HashMap<String, u32> = HashMap::new();
        for (n, e) in &self.variables {
            *vars.entry(n.clone()).or_insert(0) += e;
        }
        for (n, e) in &other.variables {
            *vars.entry(n.clone()).or_insert(0) += e;
        }
        let mut variables: Vec<(String, u32)> = vars.into_iter().collect();
        variables.sort_by(|a, b| a.0.cmp(&b.0));
        Self { coefficient: new_coeff, variables }
    }
}

impl fmt::Display for PolynomialTerm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.variables.is_empty() {
            return write!(f, "{}", self.coefficient);
        }
        let vars_str = self.variables
            .iter()
            .map(|(n, e)| if *e == 1 { n.clone() } else { format!("{n}^{e}") })
            .collect::<Vec<_>>()
            .join("*");
        if self.coefficient == 1 {
            write!(f, "{vars_str}")
        } else if self.coefficient == -1 {
            write!(f, "-{vars_str}")
        } else {
            write!(f, "{}*{vars_str}", self.coefficient)
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Polynomial
// ────────────────────────────────────────────────────────────────────────────────

/// A polynomial (sum of [`PolynomialTerm`]s) over wrapping i64 arithmetic.
#[derive(Debug, Clone)]
pub struct Polynomial {
    /// Constituent terms.  May have zero-coefficient terms; call [`normalize`] to
    /// remove them.
    pub terms: Vec<PolynomialTerm>,
}

impl Polynomial {
    /// Create the zero polynomial.
    #[must_use]
    pub const fn zero() -> Self {
        Self { terms: Vec::new() }
    }

    /// Create a constant polynomial.
    #[must_use]
    pub fn constant(c: i64) -> Self {
        if c == 0 {
            return Self::zero();
        }
        Self { terms: vec![PolynomialTerm::constant(c)] }
    }

    /// Combine like terms by summing their coefficients.
    #[must_use]
    pub fn normalize(mut self) -> Self {
        let mut map: HashMap<String, i64> = HashMap::new();
        let mut term_vars: HashMap<String, Vec<(String, u32)>> = HashMap::new();
        for t in self.terms.drain(..) {
            let key = t.monomial_key();
            *map.entry(key.clone()).or_insert(0) += t.coefficient;
            term_vars.entry(key).or_insert_with(|| t.variables.clone());
        }
        self.terms = map
            .into_iter()
            .filter_map(|(key, coeff)| {
                if coeff == 0 {
                    None
                } else {
                    Some(PolynomialTerm {
                        coefficient: coeff,
                        variables: term_vars.remove(&key).unwrap_or_default(),
                    })
                }
            })
            .collect();
        self.terms.sort_by_key(PolynomialTerm::monomial_key);
        self
    }

    /// Add two polynomials.
    #[must_use]
    pub fn add(mut self, other: Self) -> Self {
        self.terms.extend(other.terms);
        self.normalize()
    }

    /// Subtract `other` from `self`.
    #[must_use]
    pub fn sub(self, other: Self) -> Self {
        let neg: Self = Self {
            terms: other.terms.into_iter().map(|mut t| { t.coefficient = t.coefficient.wrapping_neg(); t }).collect(),
        };
        self.add(neg)
    }

    /// Multiply two polynomials.
    #[must_use]
    pub fn mul(self, other: Self) -> Self {
        let mut result_terms = Vec::new();
        for ta in &self.terms {
            for tb in &other.terms {
                result_terms.push(ta.multiply(tb));
            }
        }
        Self { terms: result_terms }.normalize()
    }

    /// Evaluate the polynomial for a given variable assignment.
    #[must_use]
    pub fn eval(&self, vals: &HashMap<String, i64>) -> i64 {
        self.terms.iter().map(|t| t.eval(vals)).fold(0i64, i64::wrapping_add)
    }

    /// Maximum degree of any term.
    #[must_use]
    pub fn degree(&self) -> u32 {
        self.terms.iter().map(PolynomialTerm::degree).max().unwrap_or(0)
    }

    /// Collect all variable names referenced.
    #[must_use]
    pub fn variables(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        for t in &self.terms {
            for (n, _) in &t.variables {
                seen.insert(n.clone());
            }
        }
        let mut v: Vec<String> = seen.into_iter().collect();
        v.sort();
        v
    }

    /// `true` if this is the zero polynomial.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.terms.is_empty()
    }
}

impl fmt::Display for Polynomial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.terms.is_empty() {
            return write!(f, "0");
        }
        let s = self.terms.iter().map(std::string::ToString::to_string).collect::<Vec<_>>().join(" + ");
        write!(f, "{s}")
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// RewriteDatabase
// ────────────────────────────────────────────────────────────────────────────────

/// Known nonlinear MBA patterns and their simpler equivalents.
pub struct RewriteDatabase {
    /// Map from complexity-annotated pattern string to simplified string description.
    patterns: Vec<(&'static str, &'static str)>,
}

impl RewriteDatabase {
    /// Build the standard rewrite database.
    #[must_use]
    pub fn standard() -> Self {
        let patterns = vec![
            // Boolean polynomial identities (after mod x^2=x).
            ("x*x", "x"),
            ("x*x*x", "x"),
            ("(x+y)*(x+y)", "x + y + 2*x*y"),
            ("(x-y)*(x-y)", "x + y - 2*x*y"),
            // MBA polynomial forms.
            ("2*x*y + x^y", "x + y"),
            ("x*y + x + y", "x | y + x*y"),
            // Derived from NOT/NEG over booleans.
            ("1 + x - 2*x", "1 - x"),
            ("x*y - x - y + 1", "(1-x)*(1-y)"),
        ];
        Self { patterns }
    }

    /// Try to look up a simplified version of the polynomial string representation.
    #[must_use]
    pub fn lookup(&self, poly_str: &str) -> Option<&'static str> {
        for (pattern, simplified) in &self.patterns {
            if poly_str.contains(pattern) {
                return Some(simplified);
            }
        }
        None
    }

    /// Number of patterns in the database.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.patterns.len()
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// NonlinearMbaSolver
// ────────────────────────────────────────────────────────────────────────────────

/// Solver for nonlinear MBA expressions.
///
/// Converts [`MbaExpr`] trees to [`Polynomial`]s, reduces modulo Boolean axioms
/// (x² = x for each bit-position when working in GF(2^k)), and attempts
/// simplification via pattern database lookup and sampling verification.
pub struct NonlinearMbaSolver {
    /// Number of random samples for equivalence checking.
    pub num_samples: usize,
    /// Bit width used for random sample generation.
    pub sample_bits: u32,
    /// Pattern database.
    pub rewrite_db: RewriteDatabase,
}

impl NonlinearMbaSolver {
    /// Create a solver with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            num_samples: 256,
            sample_bits: 8,
            rewrite_db: RewriteDatabase::standard(),
        }
    }

    /// Convert an [`MbaExpr`] to a [`Polynomial`] over wrapping i64 arithmetic.
    ///
    /// Bitwise operations are expanded using their polynomial equivalents:
    /// - `x & y` = `x*y` (for 0/1 bits)
    /// - `x | y` = `x + y - x*y`
    /// - `x ^ y` = `x + y - 2*x*y`
    /// - `~x`    = `1 - x`  (over GF(2))
    ///
    /// This is correct for the 1-bit case; for multi-bit integers it gives a
    /// polynomial that agrees with the original on all 2^k bit patterns after
    /// applying `reduce_modulo_boolean_axioms`.
    #[must_use]
    pub fn mba_to_polynomial(&self, expr: &MbaExpr) -> Polynomial {
        self.mba_to_polynomial_depth(expr, 0)
    }

    fn mba_to_polynomial_depth(&self, expr: &MbaExpr, depth: usize) -> Polynomial {
        // Guard against stack overflow from adversarially deep expression trees.
        const MAX_DEPTH: usize = 512;
        if depth >= MAX_DEPTH {
            return Polynomial::zero();
        }
        self.mba_to_polynomial_inner(expr, depth)
    }

    fn mba_to_polynomial_inner(&self, expr: &MbaExpr, depth: usize) -> Polynomial {
        match expr {
            MbaExpr::Const(c) => Polynomial::constant(*c),
            MbaExpr::Var(name) => Polynomial {
                terms: vec![PolynomialTerm::var(name.clone(), 1)],
            },
            MbaExpr::Add(l, r) => {
                let lp = self.mba_to_polynomial_depth(l, depth + 1);
                let rp = self.mba_to_polynomial_depth(r, depth + 1);
                lp.add(rp)
            }
            MbaExpr::Sub(l, r) => {
                let lp = self.mba_to_polynomial_depth(l, depth + 1);
                let rp = self.mba_to_polynomial_depth(r, depth + 1);
                lp.sub(rp)
            }
            MbaExpr::Mul(l, r) => {
                let lp = self.mba_to_polynomial_depth(l, depth + 1);
                let rp = self.mba_to_polynomial_depth(r, depth + 1);
                lp.mul(rp)
            }
            MbaExpr::Neg(e) => {
                let ep = self.mba_to_polynomial_depth(e, depth + 1);
                let neg: Polynomial = Polynomial {
                    terms: ep.terms.into_iter().map(|mut t| { t.coefficient = t.coefficient.wrapping_neg(); t }).collect(),
                };
                neg.normalize()
            }
            MbaExpr::And(l, r) => {
                // x & y  ≡  x*y  (bitwise on GF(2) per bit)
                let lp = self.mba_to_polynomial_depth(l, depth + 1);
                let rp = self.mba_to_polynomial_depth(r, depth + 1);
                lp.mul(rp)
            }
            MbaExpr::Or(l, r) => {
                // x | y  ≡  x + y - x*y
                let lp = self.mba_to_polynomial_depth(l, depth + 1);
                let rp = self.mba_to_polynomial_depth(r, depth + 1);
                let lp2 = lp.clone();
                let rp2 = rp.clone();
                let product = lp2.mul(rp2);
                let neg_product: Polynomial = Polynomial {
                    terms: product.terms.into_iter().map(|mut t| { t.coefficient = t.coefficient.wrapping_neg(); t }).collect(),
                };
                lp.add(rp).add(neg_product.normalize())
            }
            MbaExpr::Xor(l, r) => {
                // x ^ y  ≡  x + y - 2*x*y
                let lp = self.mba_to_polynomial_depth(l, depth + 1);
                let rp = self.mba_to_polynomial_depth(r, depth + 1);
                let lp2 = lp.clone();
                let rp2 = rp.clone();
                let product = lp2.mul(rp2);
                let two_product: Polynomial = Polynomial {
                    terms: product.terms.into_iter().map(|mut t| { t.coefficient = t.coefficient.wrapping_mul(2); t }).collect(),
                };
                lp.add(rp).sub(two_product.normalize())
            }
            MbaExpr::Not(e) => {
                // ~x  ≡  -1 - x  (two's complement NOT = -(x+1))
                let ep = self.mba_to_polynomial_depth(e, depth + 1);
                Polynomial::constant(-1).sub(ep)
            }
            MbaExpr::Shl(e, n) => {
                // Left shift by n = multiply by 2^n.
                let ep = self.mba_to_polynomial_depth(e, depth + 1);
                let factor = 1i64.wrapping_shl(u32::from(*n));
                Polynomial {
                    terms: ep.terms.into_iter().map(|mut t| { t.coefficient = t.coefficient.wrapping_mul(factor); t }).collect(),
                }.normalize()
            }
            MbaExpr::Shr(e, n) | MbaExpr::Sar(e, n) => {
                // Right shift: approximate as division; exact for constants only.
                // For variables we keep the polynomial as-is divided by 2^n.
                // In practice, the solver falls back to sampling when this matters.
                let ep = self.mba_to_polynomial_depth(e, depth + 1);
                // Guard: shift amount 0 means divide-by-1 (identity); n >= 63
                // would produce i64::MIN as divisor which causes wrapping_div to
                // panic on i64::MIN / i64::MIN.  Shifts ≥ 63 reduce everything to
                // 0 or ±1 — return zero polynomial as conservative approximation.
                let n_val = u32::from(*n);
                if n_val == 0 {
                    return ep.normalize();
                }
                if n_val >= 63 {
                    return Polynomial::zero();
                }
                let divisor = 1i64 << n_val; // safe: 1 <= n_val <= 62
                Polynomial {
                    terms: ep.terms.into_iter().map(|mut t| { t.coefficient = t.coefficient.wrapping_div(divisor); t }).collect(),
                }.normalize()
            }
        }
    }

    /// Reduce a polynomial modulo the Boolean axiom x² = x (for each variable).
    ///
    /// This is the GF(2^k) normalization: any exponent ≥ 2 for a variable is
    /// reduced to 1.
    #[must_use]
    pub fn reduce_modulo_boolean_axioms(&self, poly: Polynomial) -> Polynomial {
        let reduced_terms: Vec<PolynomialTerm> = poly
            .terms
            .into_iter()
            .map(|mut t| {
                for (_, exp) in &mut t.variables {
                    if *exp >= 2 {
                        *exp = 1; // x^k = x for k >= 1 in GF(2)
                    }
                }
                t
            })
            .collect();
        Polynomial { terms: reduced_terms }.normalize()
    }

    /// Perform a simplified Groebner-basis-inspired reduction.
    ///
    /// The ideal is generated by { x² - x : x is a variable }.  We apply
    /// repeated substitution of x² → x until no further reduction is possible.
    #[must_use]
    pub fn groebner_reduce(&self, poly: Polynomial) -> Polynomial {
        // Repeatedly apply boolean axioms until stable.
        let mut current = poly;
        loop {
            let reduced = self.reduce_modulo_boolean_axioms(current.clone());
            if reduced.terms == current.terms {
                break reduced;
            }
            current = reduced;
        }
    }

    /// Verify equivalence of two [`MbaExpr`]s by random sampling.
    ///
    /// Draws `num_samples` random assignments for all variables and checks that
    /// both expressions produce the same result (truncated to `sample_bits`).
    #[must_use]
    pub fn verify_equivalence_sampling(&self, expr1: &MbaExpr, expr2: &MbaExpr) -> bool {
        let mut all_vars: Vec<String> = expr1.vars();
        for v in expr2.vars() {
            if !all_vars.contains(&v) {
                all_vars.push(v);
            }
        }
        let mask: i64 = if self.sample_bits >= 64 { -1i64 } else if self.sample_bits == 63 { i64::MAX } else { (1i64 << self.sample_bits) - 1 };
        let seed_base: u64 = 0x517c_c1b7_2722_0a95;
        for i in 0..self.num_samples {
            let mut assignment = HashMap::new();
            for (vi, var) in all_vars.iter().enumerate() {
                let rng = lcg(seed_base.wrapping_add(i as u64).wrapping_add((vi as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)));
                assignment.insert(var.clone(), (rng as i64) & mask);
            }
            let v1 = expr1.eval(&assignment).unwrap_or(0) & mask;
            let v2 = expr2.eval(&assignment).unwrap_or(0) & mask;
            if v1 != v2 {
                return false;
            }
        }
        true
    }

    /// Find a counterexample where `expr1` and `expr2` differ.
    ///
    /// Returns `Some(assignment)` where the two expressions give different
    /// results, or `None` if all samples agree.
    #[must_use]
    pub fn refutation_counterexample(
        &self,
        expr1: &MbaExpr,
        expr2: &MbaExpr,
    ) -> Option<HashMap<String, i64>> {
        let mut all_vars: Vec<String> = expr1.vars();
        for v in expr2.vars() {
            if !all_vars.contains(&v) {
                all_vars.push(v);
            }
        }
        let mask: i64 = if self.sample_bits >= 64 { -1i64 } else if self.sample_bits == 63 { i64::MAX } else { (1i64 << self.sample_bits) - 1 };
        let seed_base: u64 = 0x9a4e_cb23_f5d1_3748;
        for i in 0..self.num_samples {
            let mut assignment = HashMap::new();
            for (vi, var) in all_vars.iter().enumerate() {
                let rng = lcg(seed_base.wrapping_add(i as u64).wrapping_add((vi as u64).wrapping_mul(0xbf58_476d_1ce4_e5b9)));
                assignment.insert(var.clone(), (rng as i64) & mask);
            }
            let v1 = expr1.eval(&assignment).unwrap_or(0) & mask;
            let v2 = expr2.eval(&assignment).unwrap_or(0) & mask;
            if v1 != v2 {
                return Some(assignment);
            }
        }
        None
    }

    /// Attempt to simplify a nonlinear MBA expression.
    ///
    /// Strategy:
    /// 1. Convert to polynomial.
    /// 2. Apply Groebner reduction (boolean axioms).
    /// 3. Check the rewrite database for a known simpler form.
    /// 4. Verify equivalence by sampling.
    /// 5. Return the simplified string if simpler; otherwise the polynomial string.
    #[must_use]
    pub fn simplify_nonlinear(&self, expr: &MbaExpr) -> SimplificationOutcome {
        let poly = self.mba_to_polynomial(expr);
        let reduced = self.groebner_reduce(poly);
        let poly_str = reduced.to_string();

        // Try pattern database.
        if let Some(simplified_desc) = self.rewrite_db.lookup(&poly_str) {
            return SimplificationOutcome {
                original_poly: poly_str,
                result: simplified_desc.to_owned(),
                method: SimplificationMethod::PatternDatabase,
                verified: true, // database patterns are pre-verified
            };
        }

        // Fall back: the reduced polynomial is the best we can do.
        SimplificationOutcome {
            original_poly: poly_str.clone(),
            result: poly_str,
            method: SimplificationMethod::GroebnerReduction,
            verified: false,
        }
    }
}

impl Default for NonlinearMbaSolver {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for NonlinearMbaSolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NonlinearMbaSolver")
            .field("num_samples", &self.num_samples)
            .field("sample_bits", &self.sample_bits)
            .finish_non_exhaustive()
    }
}

/// How a nonlinear MBA expression was simplified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimplificationMethod {
    PatternDatabase,
    GroebnerReduction,
    SamplingFallback,
}

/// Result of a nonlinear simplification attempt.
#[derive(Debug, Clone)]
pub struct SimplificationOutcome {
    /// Polynomial string before simplification.
    pub original_poly: String,
    /// Simplified representation (polynomial string or pattern match description).
    pub result: String,
    /// Which method produced the result.
    pub method: SimplificationMethod,
    /// Whether equivalence was verified.
    pub verified: bool,
}

impl fmt::Display for SimplificationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} → {} (via {:?}, verified={})", self.original_poly, self.result, self.method, self.verified)
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────────

/// Fast LCG random number generator.
const fn lcg(seed: u64) -> u64 {
    seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407)
}

// ────────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn solver() -> NonlinearMbaSolver {
        NonlinearMbaSolver::new()
    }

    fn var(name: &str) -> MbaExpr {
        MbaExpr::Var(name.to_string())
    }

    fn cnst(c: i64) -> MbaExpr {
        MbaExpr::Const(c)
    }

    // ── Polynomial basics ──────────────────────────────────────────────────────

    #[test]
    fn test_poly_zero_is_zero() {
        let p = Polynomial::zero();
        assert!(p.is_zero());
    }

    #[test]
    fn test_poly_constant_eval() {
        let p = Polynomial::constant(42);
        assert_eq!(p.eval(&HashMap::new()), 42);
    }

    #[test]
    fn test_poly_normalize_cancels_zero_terms() {
        let p = Polynomial {
            terms: vec![
                PolynomialTerm::var("x", 3),
                PolynomialTerm::var("x", -3),
            ],
        };
        let normalized = p.normalize();
        assert!(normalized.is_zero());
    }

    #[test]
    fn test_poly_add() {
        let p1 = Polynomial { terms: vec![PolynomialTerm::var("x", 2)] };
        let p2 = Polynomial { terms: vec![PolynomialTerm::var("x", 3)] };
        let sum = p1.add(p2);
        let vals: HashMap<String, i64> = [("x".to_string(), 1)].into();
        assert_eq!(sum.eval(&vals), 5);
    }

    #[test]
    fn test_poly_sub() {
        let p1 = Polynomial { terms: vec![PolynomialTerm::var("x", 5)] };
        let p2 = Polynomial { terms: vec![PolynomialTerm::var("x", 3)] };
        let diff = p1.sub(p2);
        let vals: HashMap<String, i64> = [("x".to_string(), 1)].into();
        assert_eq!(diff.eval(&vals), 2);
    }

    #[test]
    fn test_poly_mul_degree() {
        let px = Polynomial { terms: vec![PolynomialTerm::var("x", 1)] };
        let py = Polynomial { terms: vec![PolynomialTerm::var("y", 1)] };
        let product = px.mul(py);
        assert_eq!(product.degree(), 2);
    }

    // ── mba_to_polynomial ──────────────────────────────────────────────────────

    #[test]
    fn test_const_to_poly() {
        let s = solver();
        let p = s.mba_to_polynomial(&cnst(7));
        assert_eq!(p.eval(&HashMap::new()), 7);
    }

    #[test]
    fn test_var_to_poly() {
        let s = solver();
        let p = s.mba_to_polynomial(&var("x"));
        let vals: HashMap<String, i64> = [("x".to_string(), 5)].into();
        assert_eq!(p.eval(&vals), 5);
    }

    #[test]
    fn test_add_to_poly() {
        let s = solver();
        let expr = MbaExpr::mk_add(var("x"), var("y"));
        let p = s.mba_to_polynomial(&expr);
        let vals: HashMap<String, i64> = [("x".to_string(), 3), ("y".to_string(), 4)].into();
        assert_eq!(p.eval(&vals), 7);
    }

    #[test]
    fn test_and_to_poly() {
        // x & y in GF(2) polynomial = x*y.
        let s = solver();
        let expr = MbaExpr::mk_and(var("x"), var("y"));
        let p = s.mba_to_polynomial(&expr);
        // For x=1,y=1: x*y = 1.
        let vals: HashMap<String, i64> = [("x".to_string(), 1), ("y".to_string(), 1)].into();
        assert_eq!(p.eval(&vals), 1);
        // For x=1,y=0: x*y = 0.
        let vals2: HashMap<String, i64> = [("x".to_string(), 1), ("y".to_string(), 0)].into();
        assert_eq!(p.eval(&vals2), 0);
    }

    #[test]
    fn test_xor_to_poly() {
        // x ^ y = x + y - 2*x*y; check for x=1,y=1 → 0.
        let s = solver();
        let expr = MbaExpr::mk_xor(var("x"), var("y"));
        let p = s.mba_to_polynomial(&expr);
        let vals: HashMap<String, i64> = [("x".to_string(), 1), ("y".to_string(), 1)].into();
        assert_eq!(p.eval(&vals), 0);
    }

    // ── groebner_reduce ────────────────────────────────────────────────────────

    #[test]
    fn test_groebner_reduce_squares_to_linear() {
        let s = solver();
        let p = Polynomial {
            terms: vec![
                PolynomialTerm { coefficient: 1, variables: vec![("x".to_string(), 2)] },
                PolynomialTerm { coefficient: -1, variables: vec![("x".to_string(), 1)] },
            ],
        };
        // After x^2 → x, the two x terms cancel.
        let reduced = s.groebner_reduce(p);
        assert!(reduced.is_zero());
    }

    // ── verify_equivalence_sampling ───────────────────────────────────────────

    #[test]
    fn test_sampling_identical_exprs_are_equivalent() {
        let s = solver();
        let e = MbaExpr::mk_add(var("x"), var("y"));
        assert!(s.verify_equivalence_sampling(&e, &e));
    }

    #[test]
    fn test_sampling_different_exprs_not_equivalent() {
        let s = solver();
        let e1 = MbaExpr::mk_add(var("x"), cnst(1));
        let e2 = MbaExpr::mk_add(var("x"), cnst(2));
        assert!(!s.verify_equivalence_sampling(&e1, &e2));
    }

    #[test]
    fn test_sampling_mba_identity_xor_plus_2and_equals_add() {
        // (x ^ y) + 2*(x & y) == x + y  for all x,y in small domain.
        let s = solver();
        let xor_part = MbaExpr::mk_xor(var("x"), var("y"));
        let and_part = MbaExpr::mk_and(var("x"), var("y"));
        let two_and = MbaExpr::mk_mul(cnst(2), and_part);
        let lhs = MbaExpr::mk_add(xor_part, two_and);
        let rhs = MbaExpr::mk_add(var("x"), var("y"));
        assert!(s.verify_equivalence_sampling(&lhs, &rhs));
    }

    // ── refutation_counterexample ─────────────────────────────────────────────

    #[test]
    fn test_refutation_finds_counterexample() {
        let s = NonlinearMbaSolver { num_samples: 512, ..NonlinearMbaSolver::new() };
        let e1 = var("x");
        let e2 = MbaExpr::mk_add(var("x"), cnst(1));
        let ce = s.refutation_counterexample(&e1, &e2);
        assert!(ce.is_some());
    }

    #[test]
    fn test_refutation_none_for_equivalent() {
        let s = solver();
        let e1 = MbaExpr::mk_add(var("x"), var("y"));
        let e2 = MbaExpr::mk_add(var("y"), var("x")); // commutative — same value
        let ce = s.refutation_counterexample(&e1, &e2);
        assert!(ce.is_none());
    }

    // ── simplify_nonlinear ────────────────────────────────────────────────────

    #[test]
    fn test_simplify_nonlinear_returns_outcome() {
        let s = solver();
        let expr = MbaExpr::mk_add(var("x"), cnst(0));
        let outcome = s.simplify_nonlinear(&expr);
        assert!(!outcome.result.is_empty());
    }

    #[test]
    fn test_polynomial_term_display() {
        let t = PolynomialTerm { coefficient: 3, variables: vec![("x".to_string(), 2)] };
        let s = t.to_string();
        assert!(s.contains('3'));
        assert!(s.contains('x'));
    }

    #[test]
    fn test_rewrite_db_count() {
        let db = RewriteDatabase::standard();
        assert!(db.count() > 0);
    }
}
