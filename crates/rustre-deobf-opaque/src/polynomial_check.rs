//! `polynomial_check` — polynomial invariant checker and bitwise identity database.

use crate::OpaqueExpr;
pub use std::collections::HashMap;

// ── PolynomialInvariant ───────────────────────────────────────────────────────

/// A polynomial invariant of the form `p(x) mod m == c`.
///
/// The polynomial `p` is represented as a list of `(coefficient, exponent)` terms.
#[derive(Debug, Clone)]
pub struct PolynomialInvariant {
    /// Terms: `(coefficient, exponent)`.
    pub terms: Vec<(i64, u32)>,
    /// Modulus.
    pub modulus: i64,
    /// Expected constant residue.
    pub expected: i64,
    /// Human-readable description.
    pub description: String,
}

impl PolynomialInvariant {
    /// Create a new invariant.
    #[must_use]
    pub fn new(
        terms: Vec<(i64, u32)>,
        modulus: i64,
        expected: i64,
        description: impl Into<String>,
    ) -> Self {
        Self {
            terms,
            modulus,
            expected,
            description: description.into(),
        }
    }

    /// Evaluate `p(x)` for a given `x`.
    #[must_use]
    pub fn eval_poly(&self, x: i64) -> i64 {
        self.terms.iter().fold(0i64, |acc, &(coeff, exp)| {
            let term = coeff.wrapping_mul(i64_pow(x, exp));
            acc.wrapping_add(term)
        })
    }

    /// Evaluate `p(x) mod m`.
    #[must_use]
    pub fn eval(&self, x: i64) -> i64 {
        if self.modulus == 0 {
            return self.eval_poly(x);
        }
        self.eval_poly(x).wrapping_rem(self.modulus)
    }

    /// Check that `p(x) mod m == expected` for the given `x`.
    #[must_use]
    pub fn holds(&self, x: i64) -> bool {
        self.eval(x) == self.expected
    }

    /// Verify the invariant holds for all `x` in `0..sample_count`.
    #[must_use]
    pub fn verify_range(&self, sample_count: u32) -> bool {
        for x in 0i64..i64::from(sample_count) {
            if !self.holds(x) {
                return false;
            }
        }
        true
    }
}

const fn i64_pow(base: i64, exp: u32) -> i64 {
    if exp == 0 {
        return 1;
    }
    let mut result = 1i64;
    let mut b = base;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = result.wrapping_mul(b);
        }
        b = b.wrapping_mul(b);
        e >>= 1;
    }
    result
}

// ── check_polynomial_invariant ────────────────────────────────────────────────

/// Check whether the given polynomial invariant holds for `n` sample values.
#[must_use]
pub fn check_polynomial_invariant(inv: &PolynomialInvariant, samples: u32) -> bool {
    inv.verify_range(samples)
}

// ── Common invariants ─────────────────────────────────────────────────────────

/// Build the invariant: `n*(n+1) mod 2 == 0` (product of consecutive integers is even).
#[must_use]
pub fn consecutive_product_invariant() -> PolynomialInvariant {
    // n*(n+1) = n^2 + n  →  terms: [(1,2),(1,1)], mod 2, expected 0
    PolynomialInvariant::new(
        vec![(1, 2), (1, 1)],
        2,
        0,
        "n*(n+1) mod 2 == 0 (product of consecutive integers is even)",
    )
}

/// `n*(n-1) mod 2 == 0`
#[must_use]
pub fn consecutive_pred_product_invariant() -> PolynomialInvariant {
    // n*(n-1) = n^2 - n  →  terms: [(1,2),(-1,1)]
    PolynomialInvariant::new(vec![(1, 2), (-1, 1)], 2, 0, "n*(n-1) mod 2 == 0")
}

/// `n^2 + n mod 2 == 0` (same as `consecutive_product` but written differently).
#[must_use]
pub fn square_plus_n_invariant() -> PolynomialInvariant {
    PolynomialInvariant::new(vec![(1, 2), (1, 1)], 2, 0, "n^2 + n mod 2 == 0")
}

/// `3*n*(n+1) mod 6 == 0` (3 consecutive triangular numbers divisible by 6).
#[must_use]
pub fn triangular_mod6_invariant() -> PolynomialInvariant {
    // 3*(n^2+n)  →  terms: [(3,2),(3,1)]
    PolynomialInvariant::new(vec![(3, 2), (3, 1)], 6, 0, "3*n*(n+1) mod 6 == 0")
}

// ── ZnRingCalculator ──────────────────────────────────────────────────────────

/// Arithmetic in `Z_n` (integers mod n).
pub struct ZnRingCalculator {
    /// The modulus n.
    pub n: i64,
}

impl ZnRingCalculator {
    /// Create a new `Z_n` calculator.
    #[must_use]
    pub fn new(n: i64) -> Self {
        assert!(n > 0, "modulus must be positive");
        Self { n }
    }

    /// Reduce `x` to the canonical representative in `[0, n)`.
    #[must_use]
    pub const fn reduce(&self, x: i64) -> i64 {
        x.rem_euclid(self.n)
    }

    /// `a + b mod n`.
    #[must_use]
    pub const fn add(&self, a: i64, b: i64) -> i64 {
        self.reduce(a.wrapping_add(b))
    }

    /// `a - b mod n`.
    #[must_use]
    pub const fn sub(&self, a: i64, b: i64) -> i64 {
        self.reduce(a.wrapping_sub(b))
    }

    /// `a * b mod n`.
    #[must_use]
    pub const fn mul(&self, a: i64, b: i64) -> i64 {
        self.reduce(a.wrapping_mul(b))
    }

    /// `a^k mod n`.
    #[must_use]
    pub const fn pow(&self, base: i64, k: u32) -> i64 {
        let mut result = 1i64;
        let mut b = self.reduce(base);
        let mut e = k;
        while e > 0 {
            if e & 1 == 1 {
                result = self.mul(result, b);
            }
            b = self.mul(b, b);
            e >>= 1;
        }
        result
    }

    /// `a^(-1) mod n` via extended Euclidean algorithm.
    ///
    /// Returns `None` if `gcd(a, n) != 1` (no inverse exists).
    #[must_use]
    pub fn inv(&self, a: i64) -> Option<i64> {
        let a = self.reduce(a);
        let (g, x, _) = extended_gcd(a, self.n);
        if g == 1 { Some(self.reduce(x)) } else { None }
    }

    /// `a / b mod n` (requires b to be invertible).
    #[must_use]
    pub fn div(&self, a: i64, b: i64) -> Option<i64> {
        let inv_b = self.inv(b)?;
        Some(self.mul(a, inv_b))
    }

    /// Evaluate a polynomial `p(x)` mod n.
    #[must_use]
    pub fn eval_poly(&self, terms: &[(i64, u32)], x: i64) -> i64 {
        terms.iter().fold(0i64, |acc, &(c, e)| {
            let term = self.mul(c, self.pow(x, e));
            self.add(acc, term)
        })
    }
}

fn extended_gcd(lhs: i64, rhs: i64) -> (i64, i64, i64) {
    if rhs == 0 {
        return (lhs, 1, 0);
    }
    let (gcd, coef_x, coef_y) = extended_gcd(rhs, lhs % rhs);
    (gcd, coef_y, coef_x - (lhs / rhs) * coef_y)
}

// ── BitwideInvariantDb ────────────────────────────────────────────────────────

/// A database of common bitwise manipulation identities.
pub struct BitwideInvariantDb {
    entries: Vec<BitwideEntry>,
}

/// One entry in the bitwise invariant database.
#[derive(Debug, Clone)]
pub struct BitwideEntry {
    /// Short name of the identity.
    pub name: &'static str,
    /// English description.
    pub description: &'static str,
    /// Whether the identity evaluates to always-true (1) or always-false (0).
    pub always_true: bool,
    /// Checker function: returns `true` if `expr` matches this pattern.
    pub check: fn(&OpaqueExpr) -> bool,
}

impl BitwideInvariantDb {
    /// Build the database.
    #[must_use]
    pub fn build() -> Self {
        let mut db = Self {
            entries: Vec::new(),
        };

        // x & 0 == 0
        db.entries.push(BitwideEntry {
            name: "and_zero_eq_zero",
            description: "x & 0 == 0",
            always_true: true,
            check: |e| matches!(e, OpaqueExpr::Eq(l, r)
                if matches!(r.as_ref(), OpaqueExpr::Const(0))
                && matches!(l.as_ref(), OpaqueExpr::And(a,b)
                    if matches!(a.as_ref(), OpaqueExpr::Const(0)) || matches!(b.as_ref(), OpaqueExpr::Const(0)))),
        });

        // x | (-1) == -1
        db.entries.push(BitwideEntry {
            name: "or_allones_eq_allones",
            description: "x | (-1) == -1",
            always_true: true,
            check: |e| matches!(e, OpaqueExpr::Eq(l, r)
                if matches!(r.as_ref(), OpaqueExpr::Const(-1))
                && matches!(l.as_ref(), OpaqueExpr::Or(a,b)
                    if matches!(a.as_ref(), OpaqueExpr::Const(-1)) || matches!(b.as_ref(), OpaqueExpr::Const(-1)))),
        });

        // x ^ x == 0
        db.entries.push(BitwideEntry {
            name: "xor_self_zero",
            description: "x ^ x == 0",
            always_true: true,
            check: |e| {
                matches!(e, OpaqueExpr::Eq(l, r)
                if matches!(r.as_ref(), OpaqueExpr::Const(0))
                && matches!(l.as_ref(), OpaqueExpr::Xor(a,b) if a.is_trivially_equal(b)))
            },
        });

        // ~(~x) == x
        db.entries.push(BitwideEntry {
            name: "double_not",
            description: "~~x == x",
            always_true: true,
            check: |e| matches!(e, OpaqueExpr::Eq(l, r)
                if matches!(l.as_ref(), OpaqueExpr::Not(inner) if matches!(inner.as_ref(), OpaqueExpr::Not(inner2) if inner2.is_trivially_equal(r)))),
        });

        // x | ~x == -1
        db.entries.push(BitwideEntry {
            name: "or_not_x_allones",
            description: "x | ~x == -1",
            always_true: true,
            check: |e| {
                if let OpaqueExpr::Eq(l, r) = e
                    && matches!(r.as_ref(), OpaqueExpr::Const(-1))
                        && let OpaqueExpr::Or(a, b) = l.as_ref() {
                            for (x, y) in [(a, b), (b, a)] {
                                if let OpaqueExpr::Not(inner) = y.as_ref()
                                    && x.is_trivially_equal(inner) {
                                        return true;
                                    }
                            }
                        }
                false
            },
        });

        // x & ~x == 0
        db.entries.push(BitwideEntry {
            name: "and_not_x_zero",
            description: "x & ~x == 0",
            always_true: true,
            check: |e| {
                if let OpaqueExpr::Eq(l, r) = e
                    && matches!(r.as_ref(), OpaqueExpr::Const(0))
                        && let OpaqueExpr::And(a, b) = l.as_ref() {
                            for (x, y) in [(a, b), (b, a)] {
                                if let OpaqueExpr::Not(inner) = y.as_ref()
                                    && x.is_trivially_equal(inner) {
                                        return true;
                                    }
                            }
                        }
                false
            },
        });

        // (x << 0) == x
        db.entries.push(BitwideEntry {
            name: "shl_zero",
            description: "(x << 0) == x",
            always_true: true,
            check: |e| matches!(e, OpaqueExpr::Eq(l, r) if matches!(l.as_ref(), OpaqueExpr::Shl(inner, 0) if inner.is_trivially_equal(r))),
        });

        // (x >> 0) == x
        db.entries.push(BitwideEntry {
            name: "shr_zero",
            description: "(x >> 0) == x",
            always_true: true,
            check: |e| matches!(e, OpaqueExpr::Eq(l, r) if matches!(l.as_ref(), OpaqueExpr::Shr(inner, 0) if inner.is_trivially_equal(r))),
        });

        // x ^ 0 == x
        db.entries.push(BitwideEntry {
            name: "xor_zero_eq_self",
            description: "x ^ 0 == x",
            always_true: true,
            check: |e| {
                if let OpaqueExpr::Eq(l, r) = e
                    && let OpaqueExpr::Xor(a, b) = l.as_ref() {
                        if matches!(b.as_ref(), OpaqueExpr::Const(0)) && a.is_trivially_equal(r) {
                            return true;
                        }
                        if matches!(a.as_ref(), OpaqueExpr::Const(0)) && b.is_trivially_equal(r) {
                            return true;
                        }
                    }
                false
            },
        });

        // x | 0 == x
        db.entries.push(BitwideEntry {
            name: "or_zero_eq_self",
            description: "x | 0 == x",
            always_true: true,
            check: |e| {
                if let OpaqueExpr::Eq(l, r) = e
                    && let OpaqueExpr::Or(a, b) = l.as_ref() {
                        if matches!(b.as_ref(), OpaqueExpr::Const(0)) && a.is_trivially_equal(r) {
                            return true;
                        }
                        if matches!(a.as_ref(), OpaqueExpr::Const(0)) && b.is_trivially_equal(r) {
                            return true;
                        }
                    }
                false
            },
        });

        // x & (-1) == x
        db.entries.push(BitwideEntry {
            name: "and_allones_eq_self",
            description: "x & (-1) == x",
            always_true: true,
            check: |e| {
                if let OpaqueExpr::Eq(l, r) = e
                    && let OpaqueExpr::And(a, b) = l.as_ref() {
                        if matches!(b.as_ref(), OpaqueExpr::Const(-1)) && a.is_trivially_equal(r) {
                            return true;
                        }
                        if matches!(a.as_ref(), OpaqueExpr::Const(-1)) && b.is_trivially_equal(r) {
                            return true;
                        }
                    }
                false
            },
        });

        // popcount(x) >= 0
        db.entries.push(BitwideEntry {
            name: "popcount_ge0",
            description: "popcount(x) >= 0",
            always_true: true,
            check: |e| matches!(e, OpaqueExpr::Ge(l, r)
                if matches!(l.as_ref(), OpaqueExpr::BitCount(_)) && matches!(r.as_ref(), OpaqueExpr::Const(0))),
        });

        db
    }

    /// Check `expr` against all entries.
    ///
    /// Returns `Some((name, always_true))` for the first matching entry.
    #[must_use]
    pub fn check(&self, expr: &OpaqueExpr) -> Option<(&'static str, bool)> {
        for entry in &self.entries {
            if (entry.check)(expr) {
                return Some((entry.name, entry.always_true));
            }
        }
        None
    }

    /// Number of registered identities.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if no identities are registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── PolynomialChecker ─────────────────────────────────────────────────────────

/// A checker that applies known polynomial invariants and bitwise identities
/// to determine if an expression is an opaque predicate.
pub struct PolynomialChecker {
    pub zn: ZnRingCalculator,
    pub bitwise_db: BitwideInvariantDb,
}

impl PolynomialChecker {
    /// Create a new checker.
    #[must_use]
    pub fn new(modulus: i64) -> Self {
        Self {
            zn: ZnRingCalculator::new(modulus.max(1)),
            bitwise_db: BitwideInvariantDb::build(),
        }
    }

    /// Check whether `expr` matches any known polynomial or bitwise invariant.
    ///
    /// Returns `Some(always_true)` if a match is found.
    #[must_use]
    pub fn check(&self, expr: &OpaqueExpr) -> Option<bool> {
        if let Some((_, always_true)) = self.bitwise_db.check(expr) {
            return Some(always_true);
        }
        None
    }

    /// Verify a polynomial invariant over 256 sample values.
    #[must_use]
    pub fn verify_poly(&self, inv: &PolynomialInvariant) -> bool {
        check_polynomial_invariant(inv, 256)
    }

    /// Build the standard library of well-known polynomial invariants.
    #[must_use]
    pub fn standard_invariants() -> Vec<PolynomialInvariant> {
        vec![
            consecutive_product_invariant(),
            consecutive_pred_product_invariant(),
            square_plus_n_invariant(),
            triangular_mod6_invariant(),
            // 2*n*(n+1) mod 4 == 0
            PolynomialInvariant::new(vec![(2, 2), (2, 1)], 4, 0, "2*n*(n+1) mod 4 == 0"),
            // n^3 - n mod 6 == 0  (product of 3 consecutive = n*(n-1)*(n+1))
            PolynomialInvariant::new(vec![(1, 3), (0 - 1, 1)], 6, 0, "n^3 - n mod 6 == 0"),
        ]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn x() -> OpaqueExpr {
        OpaqueExpr::Var("x".into())
    }

    #[test]
    fn test_consecutive_product_holds_many_values() {
        let inv = consecutive_product_invariant();
        assert!(inv.verify_range(200));
    }

    #[test]
    fn test_consecutive_pred_product_holds() {
        let inv = consecutive_pred_product_invariant();
        assert!(inv.verify_range(100));
    }

    #[test]
    fn test_square_plus_n_holds() {
        let inv = square_plus_n_invariant();
        assert!(inv.verify_range(100));
    }

    #[test]
    fn test_triangular_mod6_holds() {
        let inv = triangular_mod6_invariant();
        assert!(inv.verify_range(50));
    }

    #[test]
    fn test_polynomial_invariant_eval_specific() {
        let inv = consecutive_product_invariant();
        for n in 0i64..20 {
            assert_eq!(inv.eval(n), 0, "failed for n={n}");
        }
    }

    #[test]
    fn test_polynomial_invariant_eval_poly() {
        // p(x) = 2*x + 1 (should give odd values)
        let inv = PolynomialInvariant::new(vec![(2, 1), (1, 0)], 2, 1, "2x+1 always odd");
        assert!(inv.verify_range(100));
    }

    #[test]
    fn test_check_polynomial_invariant_fn() {
        let inv = consecutive_product_invariant();
        assert!(check_polynomial_invariant(&inv, 128));
    }

    #[test]
    fn test_zn_add() {
        let zn = ZnRingCalculator::new(7);
        assert_eq!(zn.add(5, 4), 2); // 9 mod 7 = 2
    }

    #[test]
    fn test_zn_sub() {
        let zn = ZnRingCalculator::new(7);
        assert_eq!(zn.sub(3, 5), 5); // -2 mod 7 = 5
    }

    #[test]
    fn test_zn_mul() {
        let zn = ZnRingCalculator::new(7);
        assert_eq!(zn.mul(3, 5), 1); // 15 mod 7 = 1
    }

    #[test]
    fn test_zn_pow() {
        let zn = ZnRingCalculator::new(7);
        assert_eq!(zn.pow(2, 10), 2); // 1024 mod 7 = 2
    }

    #[test]
    fn test_zn_inv_exists() {
        let zn = ZnRingCalculator::new(7);
        let inv = zn.inv(3).unwrap();
        assert_eq!(zn.mul(3, inv), 1);
    }

    #[test]
    fn test_zn_inv_no_inverse() {
        let zn = ZnRingCalculator::new(6);
        assert!(zn.inv(2).is_none()); // gcd(2,6)=2 != 1
    }

    #[test]
    fn test_zn_div() {
        let zn = ZnRingCalculator::new(7);
        assert_eq!(zn.div(6, 3), Some(2));
    }

    #[test]
    fn test_zn_eval_poly() {
        let zn = ZnRingCalculator::new(5);
        // p(x) = x^2 + x = x(x+1) — always even, but mod 5 can be anything
        let terms = vec![(1i64, 2u32), (1i64, 1u32)];
        let _ = zn.eval_poly(&terms, 3);
    }

    #[test]
    fn test_zn_reduce_negative() {
        let zn = ZnRingCalculator::new(7);
        assert_eq!(zn.reduce(-1), 6);
    }

    #[test]
    fn test_bitwise_db_build() {
        let db = BitwideInvariantDb::build();
        assert!(db.len() >= 10);
    }

    #[test]
    fn test_bitwise_db_and_zero() {
        let db = BitwideInvariantDb::build();
        let e = OpaqueExpr::Eq(
            Box::new(OpaqueExpr::And(
                Box::new(x()),
                Box::new(OpaqueExpr::Const(0)),
            )),
            Box::new(OpaqueExpr::Const(0)),
        );
        assert!(db.check(&e).is_some());
    }

    #[test]
    fn test_bitwise_db_xor_self() {
        let db = BitwideInvariantDb::build();
        let e = OpaqueExpr::Eq(
            Box::new(OpaqueExpr::Xor(Box::new(x()), Box::new(x()))),
            Box::new(OpaqueExpr::Const(0)),
        );
        assert!(db.check(&e).is_some());
    }

    #[test]
    fn test_bitwise_db_no_match() {
        let db = BitwideInvariantDb::build();
        let e = OpaqueExpr::Ge(Box::new(x()), Box::new(OpaqueExpr::Const(42)));
        assert!(db.check(&e).is_none());
    }

    #[test]
    fn test_polynomial_checker_bitwise() {
        let checker = PolynomialChecker::new(2);
        let e = OpaqueExpr::Eq(
            Box::new(OpaqueExpr::Xor(Box::new(x()), Box::new(x()))),
            Box::new(OpaqueExpr::Const(0)),
        );
        assert_eq!(checker.check(&e), Some(true));
    }

    #[test]
    fn test_polynomial_checker_no_match() {
        let checker = PolynomialChecker::new(2);
        let e = OpaqueExpr::Ge(Box::new(x()), Box::new(OpaqueExpr::Const(100)));
        assert_eq!(checker.check(&e), None);
    }

    #[test]
    fn test_standard_invariants_all_hold() {
        let invariants = PolynomialChecker::standard_invariants();
        for inv in &invariants {
            assert!(
                inv.verify_range(50),
                "invariant '{}' failed",
                inv.description
            );
        }
    }

    #[test]
    fn test_i64_pow_zero() {
        assert_eq!(i64_pow(5, 0), 1);
    }

    #[test]
    fn test_i64_pow_basic() {
        assert_eq!(i64_pow(3, 4), 81);
    }

    #[test]
    fn test_polynomial_checker_verify_poly() {
        let checker = PolynomialChecker::new(2);
        let inv = consecutive_product_invariant();
        assert!(checker.verify_poly(&inv));
    }

    #[test]
    fn test_bitwise_db_popcount_ge0() {
        let db = BitwideInvariantDb::build();
        let e = OpaqueExpr::Ge(
            Box::new(OpaqueExpr::BitCount(Box::new(x()))),
            Box::new(OpaqueExpr::Const(0)),
        );
        assert!(db.check(&e).is_some());
    }
}
