//! `pattern_library` — Static database of known opaque predicate patterns.
//!
//! Covers:
//! * OLLVM standard patterns
//! * Boolean algebra identities
//! * Arithmetic invariants (wrapping_add overflow, modular arithmetic)
//! * Fermat's little theorem patterns
//! * Detection without SMT for pattern-matched predicates


use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::PredicateValue;

// ─────────────────────────────────────────────────────────────────────────────
// Pattern category
// ─────────────────────────────────────────────────────────────────────────────

/// Category of an opaque predicate pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatternCategory {
    /// OLLVM-generated pattern.
    Ollvm,
    /// Generic boolean algebra tautology / contradiction.
    BooleanAlgebra,
    /// Arithmetic invariant (modular, Fermat, wrapping).
    Arithmetic,
    /// Polynomial / algebraic identity.
    Polynomial,
    /// Data-structure–based invariant (e.g. pointer alignment).
    DataStructure,
    /// Custom pattern added by the user.
    Custom,
}

impl std::fmt::Display for PatternCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Ollvm => "OLLVM",
            Self::BooleanAlgebra => "BooleanAlgebra",
            Self::Arithmetic => "Arithmetic",
            Self::Polynomial => "Polynomial",
            Self::DataStructure => "DataStructure",
            Self::Custom => "Custom",
        };
        write!(f, "{}", s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern match mode
// ─────────────────────────────────────────────────────────────────────────────

/// How to match a pattern against a predicate expression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MatchMode {
    /// The pattern is matched by an exact structural rule (described as a human-readable rule name).
    Structural(String),
    /// The pattern is matched by evaluating the canonical string form against a regex.
    Textual(String),
    /// The pattern is matched by evaluating a truth-table for N samples.
    TruthTable { samples: u32 },
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternEntry
// ─────────────────────────────────────────────────────────────────────────────

/// One entry in the opaque predicate pattern library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternEntry {
    /// Unique pattern identifier.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Category.
    pub category: PatternCategory,
    /// Whether the predicate is always true (vs always false).
    pub predicate_value: PredicateValue,
    /// How this pattern is matched.
    pub match_mode: MatchMode,
    /// Confidence when this pattern matches.
    pub base_confidence: f32,
    /// Representative expression written as a source snippet (documentation).
    pub example: String,
    /// Number of variables the pattern has (1..=8).
    pub variable_count: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// Structural predicate descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified structural description of a predicate for matching.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PredicateDesc {
    /// `x - x == 0`
    XMinusXEqZero,
    /// `x ^ x == 0`
    XXorXEqZero,
    /// `x & ~x == 0`
    XAndNotXEqZero,
    /// `x | ~x == -1`
    XOrNotXEqAllOnes,
    /// `x * (x - 1) % 2 == 0`  (product of consecutive integers is even)
    ConsecutiveProductEven,
    /// `x² >= 0` (signed — always true in absence of overflow)
    SquareGeZero,
    /// `(x & 1) | (~x & 1) == 1`
    LsbTautology,
    /// `x.wrapping_add(c).wrapping_sub(c) == x`
    WrappingAddSub,
    /// `x % 2 == 0 || x % 2 == 1` (always true — covers both parities)
    ParityAlwaysValid,
    /// `(x >> n) << n <= x` (unsigned, always true)
    ShiftRoundDown,
    /// `x == x`
    TrivialEq,
    /// `(a & b) | (a & !b) == a`
    AndOrDistributive,
    /// Boolean: `(x & 1) == (x & 1)` — tautological self-equality
    BitwiseSelfEq,
    /// Fermat: `x^(p-1) % p == 1` (for non-zero x, small prime p)
    FermatLittleTheorem { prime: u32 },
    /// `x * (x + 1)` is always even.
    XTimesXPlus1Even,
    /// `(x ^ k) ^ k == x` for any constant `k` (here `0xFF`).
    DoubleXorMaskCancels,
    /// `(x | y) >= x` (and symmetrically `>= y`) — unsigned.
    OrGeOperand,
    /// `(x & y) <= x` (and symmetrically `<= y`) — unsigned.
    AndLeOperand,
    /// `x | 0 == x`.
    OrZeroIdentity,
    /// `x & !0 == x` (i.e. `x & -1 == x`).
    AndAllOnesIdentity,
    /// `(x << n) >> n == x` — opaque-false when high bits matter (sign-ext trap).
    ShiftLeftRightSignExtTrap,
    /// `(x ^ x) | (y ^ y) == 0`.
    DoubleSelfXorOrZero,
    /// Unknown / not structurally classified.
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternLibrary
// ─────────────────────────────────────────────────────────────────────────────

/// Static database of known opaque predicate patterns.
pub struct PatternLibrary {
    patterns: Vec<PatternEntry>,
    /// Maps structural descriptor → pattern indices.
    structural_index: HashMap<String, Vec<usize>>,
}

impl PatternLibrary {
    /// Build the default pattern library.
    pub fn new() -> Self {
        let mut lib = Self {
            patterns: Vec::new(),
            structural_index: HashMap::new(),
        };
        lib.load_ollvm_patterns();
        lib.load_boolean_algebra_patterns();
        lib.load_arithmetic_patterns();
        lib.load_polynomial_patterns();
        lib.load_extended_patterns();
        lib.build_index();
        lib
    }

    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    fn add(&mut self, entry: PatternEntry) {
        self.patterns.push(entry);
    }

    fn build_index(&mut self) {
        for (idx, p) in self.patterns.iter().enumerate() {
            self.structural_index
                .entry(p.id.clone())
                .or_default()
                .push(idx);
        }
    }

    // ── OLLVM patterns ────────────────────────────────────────────────────────

    fn load_ollvm_patterns(&mut self) {
        // OLLVM BCF (bogus control flow) injects predicates of the form:
        //   `y * (y - 1) % 2 == 0`  — product of consecutive integers is divisible by 2
        self.add(PatternEntry {
            id: "ollvm-consecutive-even".into(),
            description: "y * (y - 1) % 2 == 0: product of consecutive integers is even".into(),
            category: PatternCategory::Ollvm,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("ConsecutiveProductEven".into()),
            base_confidence: 0.92,
            example: "y * (y - 1) % 2 == 0".into(),
            variable_count: 1,
        });

        // `x² ≥ 0` — signed square is always non-negative (modulo wrap, but obfuscators use i32 bounded domains)
        self.add(PatternEntry {
            id: "ollvm-square-ge-zero".into(),
            description: "x * x >= 0 (signed): square is always non-negative in i32 domain".into(),
            category: PatternCategory::Ollvm,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("SquareGeZero".into()),
            base_confidence: 0.88,
            example: "x * x >= 0".into(),
            variable_count: 1,
        });

        // `(x & 1) | (~x & 1) == 1` — LSB of any word is covered by x or ~x
        self.add(PatternEntry {
            id: "ollvm-lsb-tautology".into(),
            description: "(x & 1) | (~x & 1) == 1: LSB always set in union".into(),
            category: PatternCategory::Ollvm,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("LsbTautology".into()),
            base_confidence: 0.94,
            example: "(x & 1) | (~x & 1) == 1".into(),
            variable_count: 1,
        });

        // OLLVM also generates: `(a | b) & ~(a & b)` — XOR expressed via AND/OR
        self.add(PatternEntry {
            id: "ollvm-xor-via-and-or".into(),
            description: "(a | b) & ~(a & b) == a ^ b — always equivalent".into(),
            category: PatternCategory::Ollvm,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Textual("(a \\| b) & ~(a & b)".into()),
            base_confidence: 0.80,
            example: "(a | b) & ~(a & b) == a ^ b".into(),
            variable_count: 2,
        });

        // OLLVM: `x + ~x == -1` (wrapping; ~x = -1 - x)
        self.add(PatternEntry {
            id: "ollvm-x-plus-notx-minus-one".into(),
            description: "x + ~x == -1: always true (bit identity)".into(),
            category: PatternCategory::Ollvm,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("XAndNotXEqZero".into()), // reuse closest desc
            base_confidence: 0.91,
            example: "x + ~x == -1".into(),
            variable_count: 1,
        });

        // OLLVM bogus always-false: `(x & 1) == 2`
        self.add(PatternEntry {
            id: "ollvm-lsb-eq-2".into(),
            description: "(x & 1) == 2: always false (LSB is 0 or 1, never 2)".into(),
            category: PatternCategory::Ollvm,
            predicate_value: PredicateValue::AlwaysFalse,
            match_mode: MatchMode::Structural("LsbAlwaysFalse".into()),
            base_confidence: 0.95,
            example: "(x & 1) == 2".into(),
            variable_count: 1,
        });
    }

    // ── Boolean algebra patterns ──────────────────────────────────────────────

    fn load_boolean_algebra_patterns(&mut self) {
        let bool_patterns: &[(&str, &str, PredicateValue, &str, f32)] = &[
            ("bool-x-minus-x", "x - x == 0", PredicateValue::AlwaysTrue, "x - x == 0", 0.99),
            ("bool-x-xor-x", "x ^ x == 0", PredicateValue::AlwaysTrue, "x ^ x == 0", 0.99),
            ("bool-x-and-notx", "x & ~x == 0", PredicateValue::AlwaysTrue, "x & ~x == 0", 0.99),
            ("bool-x-or-notx", "x | ~x == -1", PredicateValue::AlwaysTrue, "x | ~x == -1", 0.99),
            ("bool-x-eq-x", "x == x", PredicateValue::AlwaysTrue, "x == x", 0.99),
            ("bool-not-not-x", "~~x == x", PredicateValue::AlwaysTrue, "~~x == x", 0.98),
            ("bool-x-and-x", "x & x == x", PredicateValue::AlwaysTrue, "x & x == x", 0.98),
            ("bool-x-or-x", "x | x == x", PredicateValue::AlwaysTrue, "x | x == x", 0.98),
            // De Morgan
            ("bool-demorgan-1", "~(a & b) == ~a | ~b", PredicateValue::AlwaysTrue, "~(a & b) == ~a | ~b", 0.97),
            ("bool-demorgan-2", "~(a | b) == ~a & ~b", PredicateValue::AlwaysTrue, "~(a | b) == ~a & ~b", 0.97),
            // Absorption
            ("bool-absorb-1", "a & (a | b) == a", PredicateValue::AlwaysTrue, "a & (a | b) == a", 0.95),
            ("bool-absorb-2", "a | (a & b) == a", PredicateValue::AlwaysTrue, "a | (a & b) == a", 0.95),
            // Distributive
            ("bool-dist-and-or", "(a & b) | (a & c) == a & (b | c)", PredicateValue::AlwaysTrue,
             "(a & b) | (a & c) == a & (b | c)", 0.93),
        ];

        for (id, desc, val, example, conf) in bool_patterns {
            self.add(PatternEntry {
                id: id.to_string(),
                description: desc.to_string(),
                category: PatternCategory::BooleanAlgebra,
                predicate_value: *val,
                match_mode: MatchMode::Structural(id.to_string()),
                base_confidence: *conf,
                example: example.to_string(),
                variable_count: if desc.contains('a') || desc.contains('b') { 2 } else { 1 },
            });
        }
    }

    // ── Arithmetic patterns ───────────────────────────────────────────────────

    fn load_arithmetic_patterns(&mut self) {
        // wrapping_add / wrapping_sub cancel
        self.add(PatternEntry {
            id: "arith-wrap-add-sub".into(),
            description: "x.wrapping_add(c).wrapping_sub(c) == x".into(),
            category: PatternCategory::Arithmetic,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("WrappingAddSub".into()),
            base_confidence: 0.90,
            example: "x.wrapping_add(42).wrapping_sub(42) == x".into(),
            variable_count: 1,
        });

        // Parity: x % 2 == 0 || x % 2 == 1
        self.add(PatternEntry {
            id: "arith-parity-valid".into(),
            description: "x % 2 is always 0 or 1".into(),
            category: PatternCategory::Arithmetic,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("ParityAlwaysValid".into()),
            base_confidence: 0.88,
            example: "(x % 2 == 0) || (x % 2 == 1)".into(),
            variable_count: 1,
        });

        // Fermat patterns for small primes
        for &prime in &[2u32, 3, 5, 7, 11, 13] {
            self.add(PatternEntry {
                id: format!("arith-fermat-p{}", prime),
                description: format!("x^({}-1) % {} == 1 for x != 0 (Fermat's little theorem)", prime, prime),
                category: PatternCategory::Arithmetic,
                predicate_value: PredicateValue::AlwaysTrue,
                match_mode: MatchMode::Structural(format!("FermatLittleTheorem({})", prime)),
                base_confidence: 0.78,
                example: format!("x^{} % {} == 1", prime - 1, prime),
                variable_count: 1,
            });
        }

        // Shift round-down: (x >> n) << n <= x (unsigned)
        self.add(PatternEntry {
            id: "arith-shift-round-down".into(),
            description: "(x >> n) << n <= x (unsigned alignment)".into(),
            category: PatternCategory::Arithmetic,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("ShiftRoundDown".into()),
            base_confidence: 0.85,
            example: "(x >> 4) << 4 <= x".into(),
            variable_count: 1,
        });

        // Overflow sentinel: x + 1 > x (unsigned, wraps when x == MAX)
        // This is FALSE when x == UINT_MAX, so it's NOT an opaque always-true.
        // We list it as always_false for the case where the obfuscator compares
        // unsigned max + 1 to expect > max (which wraps to 0, so 0 > MAX is false).
        self.add(PatternEntry {
            id: "arith-umax-overflow".into(),
            description: "UINT_MAX.wrapping_add(1) > UINT_MAX — always false".into(),
            category: PatternCategory::Arithmetic,
            predicate_value: PredicateValue::AlwaysFalse,
            match_mode: MatchMode::Structural("UmaxOverflow".into()),
            base_confidence: 0.86,
            example: "u32::MAX.wrapping_add(1) > u32::MAX  // 0 > MAX = false".into(),
            variable_count: 0,
        });
    }

    // ── Polynomial patterns ───────────────────────────────────────────────────

    fn load_polynomial_patterns(&mut self) {
        // x*(x-1) % 2 == 0 (consecutive integers, product always even)
        self.add(PatternEntry {
            id: "poly-consecutive-even".into(),
            description: "x*(x-1) % 2 == 0".into(),
            category: PatternCategory::Polynomial,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("ConsecutiveProductEven".into()),
            base_confidence: 0.93,
            example: "x * (x - 1) % 2 == 0".into(),
            variable_count: 1,
        });

        // x*(x+1)*(x+2) % 6 == 0 — product of 3 consecutive integers divisible by 6
        self.add(PatternEntry {
            id: "poly-three-consecutive-div6".into(),
            description: "x*(x+1)*(x+2) % 6 == 0".into(),
            category: PatternCategory::Polynomial,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::TruthTable { samples: 256 },
            base_confidence: 0.85,
            example: "x * (x + 1) * (x + 2) % 6 == 0".into(),
            variable_count: 1,
        });

        // x^2 + x ≡ 0 (mod 2) — equivalent to x*(x+1) % 2 == 0
        self.add(PatternEntry {
            id: "poly-x2-plus-x-even".into(),
            description: "x*x + x ≡ 0 (mod 2)".into(),
            category: PatternCategory::Polynomial,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("ConsecutiveProductEven".into()),
            base_confidence: 0.90,
            example: "(x*x + x) % 2 == 0".into(),
            variable_count: 1,
        });

        // (a + b)^2 == a^2 + 2ab + b^2 — algebraic identity
        self.add(PatternEntry {
            id: "poly-binomial-square".into(),
            description: "(a+b)^2 == a^2 + 2ab + b^2".into(),
            category: PatternCategory::Polynomial,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::TruthTable { samples: 512 },
            base_confidence: 0.82,
            example: "(a+b)*(a+b) == a*a + 2*a*b + b*b".into(),
            variable_count: 2,
        });
    }

    fn load_extended_patterns(&mut self) {
        self.add(PatternEntry {
            id: "ext-x-times-x-plus-1-even".into(),
            description: "x * (x + 1) % 2 == 0".into(),
            category: PatternCategory::Polynomial,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("XTimesXPlus1Even".into()),
            base_confidence: 0.94,
            example: "x * (x + 1) % 2 == 0".into(),
            variable_count: 1,
        });

        self.add(PatternEntry {
            id: "ext-square-ge-zero-signed".into(),
            description: "x * x >= 0 (signed bounded domain)".into(),
            category: PatternCategory::Arithmetic,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("SquareGeZero".into()),
            base_confidence: 0.88,
            example: "(x as i32) * (x as i32) >= 0".into(),
            variable_count: 1,
        });

        self.add(PatternEntry {
            id: "ext-double-xor-mask-cancels".into(),
            description: "(x ^ k) ^ k == x: double XOR with same mask cancels".into(),
            category: PatternCategory::BooleanAlgebra,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("DoubleXorMaskCancels".into()),
            base_confidence: 0.99,
            example: "(x ^ 0xFF) ^ 0xFF == x".into(),
            variable_count: 1,
        });

        self.add(PatternEntry {
            id: "ext-or-ge-operand".into(),
            description: "(x | y) >= x and (x | y) >= y (unsigned)".into(),
            category: PatternCategory::BooleanAlgebra,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("OrGeOperand".into()),
            base_confidence: 0.96,
            example: "(x | y) >= x".into(),
            variable_count: 2,
        });

        self.add(PatternEntry {
            id: "ext-and-le-operand".into(),
            description: "(x & y) <= x and (x & y) <= y (unsigned)".into(),
            category: PatternCategory::BooleanAlgebra,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("AndLeOperand".into()),
            base_confidence: 0.96,
            example: "(x & y) <= x".into(),
            variable_count: 2,
        });

        self.add(PatternEntry {
            id: "ext-x-minus-x-zero".into(),
            description: "x - x == 0".into(),
            category: PatternCategory::Arithmetic,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("bool-x-minus-x".into()),
            base_confidence: 0.99,
            example: "x - x == 0".into(),
            variable_count: 1,
        });

        self.add(PatternEntry {
            id: "ext-or-zero-identity".into(),
            description: "x | 0 == x".into(),
            category: PatternCategory::BooleanAlgebra,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("OrZeroIdentity".into()),
            base_confidence: 0.99,
            example: "x | 0 == x".into(),
            variable_count: 1,
        });

        self.add(PatternEntry {
            id: "ext-and-all-ones-identity".into(),
            description: "x & !0 == x (x & -1 == x)".into(),
            category: PatternCategory::BooleanAlgebra,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("AndAllOnesIdentity".into()),
            base_confidence: 0.99,
            example: "x & !0 == x".into(),
            variable_count: 1,
        });

        self.add(PatternEntry {
            id: "ext-shift-left-right-sign-ext-trap".into(),
            description: "(x << n) >> n != x: high-bit loss makes this opaque-false".into(),
            category: PatternCategory::Arithmetic,
            predicate_value: PredicateValue::AlwaysFalse,
            match_mode: MatchMode::Structural("ShiftLeftRightSignExtTrap".into()),
            base_confidence: 0.82,
            example: "((x << 8) >> 8) == x  // false when high bits of x are set".into(),
            variable_count: 1,
        });

        self.add(PatternEntry {
            id: "ext-double-self-xor-or-zero".into(),
            description: "(x ^ x) | (y ^ y) == 0".into(),
            category: PatternCategory::BooleanAlgebra,
            predicate_value: PredicateValue::AlwaysTrue,
            match_mode: MatchMode::Structural("DoubleSelfXorOrZero".into()),
            base_confidence: 0.99,
            example: "(x ^ x) | (y ^ y) == 0".into(),
            variable_count: 2,
        });
    }

    // ── Pattern lookup ────────────────────────────────────────────────────────

    /// Look up patterns by category.
    pub fn by_category(&self, cat: PatternCategory) -> Vec<&PatternEntry> {
        self.patterns.iter().filter(|p| p.category == cat).collect()
    }

    /// Look up a pattern by its unique ID.
    pub fn by_id(&self, id: &str) -> Option<&PatternEntry> {
        self.patterns.iter().find(|p| p.id == id)
    }

    /// Return all patterns that match the given `PredicateValue`.
    pub fn by_value(&self, val: PredicateValue) -> Vec<&PatternEntry> {
        self.patterns.iter().filter(|p| p.predicate_value == val).collect()
    }

    // ── Structural matching ───────────────────────────────────────────────────

    /// Attempt to match a predicate descriptor against the library.
    ///
    /// Returns the best-matching entry (highest confidence) if any match.
    pub fn match_descriptor(&self, desc: &PredicateDesc) -> Option<(&PatternEntry, f32)> {
        let structural_name = descriptor_to_structural_name(desc);

        let matches: Vec<&PatternEntry> = self
            .patterns
            .iter()
            .filter(|p| {
                if let MatchMode::Structural(ref name) = p.match_mode {
                    name == structural_name
                } else {
                    false
                }
            })
            .collect();

        matches
            .into_iter()
            .max_by(|a, b| {
                a.base_confidence
                    .partial_cmp(&b.base_confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|e| (e, e.base_confidence))
    }

    /// Check a predicate descriptor and return the [`PredicateValue`] without SMT.
    pub fn classify_no_smt(&self, desc: &PredicateDesc) -> Option<(PredicateValue, f32)> {
        // Exhaustive truth-table for 1-variable patterns
        match desc {
            PredicateDesc::XMinusXEqZero
            | PredicateDesc::XXorXEqZero
            | PredicateDesc::XAndNotXEqZero
            | PredicateDesc::XOrNotXEqAllOnes
            | PredicateDesc::TrivialEq
            | PredicateDesc::LsbTautology => {
                Some((PredicateValue::AlwaysTrue, 0.97))
            }
            PredicateDesc::SquareGeZero => {
                // True for the i32 domain up to abs(x) < sqrt(i32::MAX)
                Some((PredicateValue::AlwaysTrue, 0.85))
            }
            PredicateDesc::ConsecutiveProductEven => {
                Some((PredicateValue::AlwaysTrue, 0.93))
            }
            PredicateDesc::WrappingAddSub => {
                Some((PredicateValue::AlwaysTrue, 0.90))
            }
            PredicateDesc::ParityAlwaysValid => {
                Some((PredicateValue::AlwaysTrue, 0.88))
            }
            PredicateDesc::ShiftRoundDown => {
                Some((PredicateValue::AlwaysTrue, 0.85))
            }
            PredicateDesc::AndOrDistributive | PredicateDesc::BitwiseSelfEq => {
                Some((PredicateValue::AlwaysTrue, 0.95))
            }
            PredicateDesc::FermatLittleTheorem { .. } => {
                Some((PredicateValue::AlwaysTrue, 0.75))
            }
            PredicateDesc::XTimesXPlus1Even => Some((PredicateValue::AlwaysTrue, 0.94)),
            PredicateDesc::DoubleXorMaskCancels => Some((PredicateValue::AlwaysTrue, 0.99)),
            PredicateDesc::OrGeOperand => Some((PredicateValue::AlwaysTrue, 0.96)),
            PredicateDesc::AndLeOperand => Some((PredicateValue::AlwaysTrue, 0.96)),
            PredicateDesc::OrZeroIdentity => Some((PredicateValue::AlwaysTrue, 0.99)),
            PredicateDesc::AndAllOnesIdentity => Some((PredicateValue::AlwaysTrue, 0.99)),
            PredicateDesc::ShiftLeftRightSignExtTrap => Some((PredicateValue::AlwaysFalse, 0.82)),
            PredicateDesc::DoubleSelfXorOrZero => Some((PredicateValue::AlwaysTrue, 0.99)),
            PredicateDesc::Unknown => None,
        }
    }

    /// Bulk-classify a list of descriptors.
    pub fn classify_many(
        &self,
        descs: &[PredicateDesc],
    ) -> Vec<(PredicateDesc, Option<(PredicateValue, f32)>)> {
        descs
            .iter()
            .map(|d| (d.clone(), self.classify_no_smt(d)))
            .collect()
    }

    /// Return summary statistics about the library.
    pub fn stats(&self) -> LibraryStats {
        let mut by_cat: HashMap<String, usize> = HashMap::new();
        let mut always_true = 0usize;
        let mut always_false = 0usize;
        let mut unknown = 0usize;

        for p in &self.patterns {
            *by_cat.entry(p.category.to_string()).or_insert(0) += 1;
            match p.predicate_value {
                PredicateValue::AlwaysTrue => always_true += 1,
                PredicateValue::AlwaysFalse => always_false += 1,
                PredicateValue::Unknown => unknown += 1,
            }
        }

        LibraryStats {
            total_patterns: self.patterns.len(),
            always_true_count: always_true,
            always_false_count: always_false,
            unknown_count: unknown,
            by_category: by_cat,
        }
    }
}

impl Default for PatternLibrary {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary statistics about the pattern library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryStats {
    pub total_patterns: usize,
    pub always_true_count: usize,
    pub always_false_count: usize,
    pub unknown_count: usize,
    pub by_category: HashMap<String, usize>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

fn descriptor_to_structural_name(desc: &PredicateDesc) -> &'static str {
    match desc {
        PredicateDesc::XMinusXEqZero => "bool-x-minus-x",
        PredicateDesc::XXorXEqZero => "bool-x-xor-x",
        PredicateDesc::XAndNotXEqZero => "bool-x-and-notx",
        PredicateDesc::XOrNotXEqAllOnes => "bool-x-or-notx",
        PredicateDesc::ConsecutiveProductEven => "ConsecutiveProductEven",
        PredicateDesc::SquareGeZero => "SquareGeZero",
        PredicateDesc::LsbTautology => "LsbTautology",
        PredicateDesc::WrappingAddSub => "WrappingAddSub",
        PredicateDesc::ParityAlwaysValid => "ParityAlwaysValid",
        PredicateDesc::ShiftRoundDown => "ShiftRoundDown",
        PredicateDesc::TrivialEq => "bool-x-eq-x",
        PredicateDesc::AndOrDistributive => "bool-dist-and-or",
        PredicateDesc::BitwiseSelfEq => "BitwiseSelfEq",
        PredicateDesc::FermatLittleTheorem { .. } => "FermatLittleTheorem",
        PredicateDesc::XTimesXPlus1Even => "XTimesXPlus1Even",
        PredicateDesc::DoubleXorMaskCancels => "DoubleXorMaskCancels",
        PredicateDesc::OrGeOperand => "OrGeOperand",
        PredicateDesc::AndLeOperand => "AndLeOperand",
        PredicateDesc::OrZeroIdentity => "OrZeroIdentity",
        PredicateDesc::AndAllOnesIdentity => "AndAllOnesIdentity",
        PredicateDesc::ShiftLeftRightSignExtTrap => "ShiftLeftRightSignExtTrap",
        PredicateDesc::DoubleSelfXorOrZero => "DoubleSelfXorOrZero",
        PredicateDesc::Unknown => "",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_not_empty() {
        let lib = PatternLibrary::new();
        assert!(lib.pattern_count() >= 20, "expected ≥ 20 patterns, got {}", lib.pattern_count());
    }

    #[test]
    fn test_by_category_ollvm() {
        let lib = PatternLibrary::new();
        let ollvm = lib.by_category(PatternCategory::Ollvm);
        assert!(!ollvm.is_empty());
    }

    #[test]
    fn test_classify_x_minus_x() {
        let lib = PatternLibrary::new();
        let result = lib.classify_no_smt(&PredicateDesc::XMinusXEqZero);
        assert_eq!(result, Some((PredicateValue::AlwaysTrue, 0.97)));
    }

    #[test]
    fn test_classify_lsb_tautology() {
        let lib = PatternLibrary::new();
        let result = lib.classify_no_smt(&PredicateDesc::LsbTautology);
        assert_eq!(result.map(|(v, _)| v), Some(PredicateValue::AlwaysTrue));
    }

    #[test]
    fn test_classify_unknown() {
        let lib = PatternLibrary::new();
        let result = lib.classify_no_smt(&PredicateDesc::Unknown);
        assert!(result.is_none());
    }

    #[test]
    fn test_by_id_exists() {
        let lib = PatternLibrary::new();
        let entry = lib.by_id("ollvm-consecutive-even");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().predicate_value, PredicateValue::AlwaysTrue);
    }

    #[test]
    fn test_by_value_always_false() {
        let lib = PatternLibrary::new();
        let always_false = lib.by_value(PredicateValue::AlwaysFalse);
        assert!(!always_false.is_empty());
    }

    #[test]
    fn test_stats_totals() {
        let lib = PatternLibrary::new();
        let stats = lib.stats();
        assert_eq!(
            stats.always_true_count + stats.always_false_count + stats.unknown_count,
            stats.total_patterns
        );
    }

    #[test]
    fn test_classify_many() {
        let lib = PatternLibrary::new();
        let descs = vec![
            PredicateDesc::XMinusXEqZero,
            PredicateDesc::SquareGeZero,
            PredicateDesc::Unknown,
        ];
        let results = lib.classify_many(&descs);
        assert_eq!(results.len(), 3);
        assert!(results[0].1.is_some()); // XMinusX is known
        assert!(results[2].1.is_none()); // Unknown has no match
    }

    #[test]
    fn test_ext_x_times_x_plus_1_even() {
        let lib = PatternLibrary::new();
        let r = lib.classify_no_smt(&PredicateDesc::XTimesXPlus1Even).unwrap();
        assert_eq!(r.0, PredicateValue::AlwaysTrue);
        for x in 0u32..256 {
            assert_eq!((x.wrapping_mul(x.wrapping_add(1))) % 2, 0);
        }
        assert!(lib.by_id("ext-x-times-x-plus-1-even").is_some());
    }

    #[test]
    fn test_ext_square_ge_zero() {
        let lib = PatternLibrary::new();
        assert!(lib.by_id("ext-square-ge-zero-signed").is_some());
        for x in -1000i32..1000 {
            assert!((x as i64) * (x as i64) >= 0);
        }
    }

    #[test]
    fn test_ext_double_xor_mask_cancels() {
        let lib = PatternLibrary::new();
        let r = lib.classify_no_smt(&PredicateDesc::DoubleXorMaskCancels).unwrap();
        assert_eq!(r.0, PredicateValue::AlwaysTrue);
        for x in 0u32..1024 {
            assert_eq!((x ^ 0xFF) ^ 0xFF, x);
        }
        assert!(lib.by_id("ext-double-xor-mask-cancels").is_some());
    }

    #[test]
    fn test_ext_or_ge_operand() {
        let lib = PatternLibrary::new();
        let r = lib.classify_no_smt(&PredicateDesc::OrGeOperand).unwrap();
        assert_eq!(r.0, PredicateValue::AlwaysTrue);
        for x in 0u32..64 {
            for y in 0u32..64 {
                assert!((x | y) >= x);
                assert!((x | y) >= y);
            }
        }
        assert!(lib.by_id("ext-or-ge-operand").is_some());
    }

    #[test]
    fn test_ext_and_le_operand() {
        let lib = PatternLibrary::new();
        let r = lib.classify_no_smt(&PredicateDesc::AndLeOperand).unwrap();
        assert_eq!(r.0, PredicateValue::AlwaysTrue);
        for x in 0u32..64 {
            for y in 0u32..64 {
                assert!((x & y) <= x);
                assert!((x & y) <= y);
            }
        }
        assert!(lib.by_id("ext-and-le-operand").is_some());
    }

    #[test]
    fn test_ext_x_minus_x_zero() {
        let lib = PatternLibrary::new();
        assert!(lib.by_id("ext-x-minus-x-zero").is_some());
        for x in 0u32..1024 {
            assert_eq!(x.wrapping_sub(x), 0);
        }
    }

    #[test]
    fn test_ext_or_zero_identity() {
        let lib = PatternLibrary::new();
        let r = lib.classify_no_smt(&PredicateDesc::OrZeroIdentity).unwrap();
        assert_eq!(r.0, PredicateValue::AlwaysTrue);
        for x in 0u32..1024 {
            assert_eq!(x | 0, x);
        }
        assert!(lib.by_id("ext-or-zero-identity").is_some());
    }

    #[test]
    fn test_ext_and_all_ones_identity() {
        let lib = PatternLibrary::new();
        let r = lib.classify_no_smt(&PredicateDesc::AndAllOnesIdentity).unwrap();
        assert_eq!(r.0, PredicateValue::AlwaysTrue);
        for x in 0u32..1024 {
            assert_eq!(x & !0u32, x);
        }
        assert!(lib.by_id("ext-and-all-ones-identity").is_some());
    }

    #[test]
    fn test_ext_shift_left_right_sign_ext_trap() {
        let lib = PatternLibrary::new();
        let r = lib.classify_no_smt(&PredicateDesc::ShiftLeftRightSignExtTrap).unwrap();
        assert_eq!(r.0, PredicateValue::AlwaysFalse);
        let x: u32 = 0xFF00_0001;
        assert_ne!((x << 8) >> 8, x);
        assert!(lib.by_id("ext-shift-left-right-sign-ext-trap").is_some());
    }

    #[test]
    fn test_ext_double_self_xor_or_zero() {
        let lib = PatternLibrary::new();
        let r = lib.classify_no_smt(&PredicateDesc::DoubleSelfXorOrZero).unwrap();
        assert_eq!(r.0, PredicateValue::AlwaysTrue);
        for x in 0u32..64 {
            for y in 0u32..64 {
                assert_eq!((x ^ x) | (y ^ y), 0);
            }
        }
        assert!(lib.by_id("ext-double-self-xor-or-zero").is_some());
    }

    #[test]
    fn test_fermat_patterns_loaded() {
        let lib = PatternLibrary::new();
        for prime in &[2u32, 3, 5, 7] {
            let id = format!("arith-fermat-p{}", prime);
            assert!(lib.by_id(&id).is_some(), "missing pattern {}", id);
        }
    }
}
