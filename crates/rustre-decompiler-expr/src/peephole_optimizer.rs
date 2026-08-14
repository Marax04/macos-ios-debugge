//! Peephole optimizer for decompiler expression trees.
//!
//! A peephole optimizer inspects small windows of the expression tree and
//! applies targeted rewrite rules to produce simpler, more readable output.
//!
//! # Key types
//!
//! * [`PeepholeRule`] — a single rewrite rule (trait object).
//! * [`PeepholeOptimizer`] — runs all registered rules to a fixed point.
//! * [`OptimizationStats`] — counts rules applied and expressions simplified.
//!
//! # Rules provided (40+)
//!
//! **Constant folding** — `a+0`, `a*1`, `a*0`, `a-a`, `a|0`, `a&~0`, `a^0`, `a^a`,
//! all arithmetic and bitwise identities at the constant boundary.
//!
//! **Double negation** — `--x → x`, `~~x → x`, `!!x → x`.
//!
//! **De Morgan's laws** — `!a || !b → !(a && b)` and vice-versa.
//!
//! **Shift normalization** — `x<<0 → x`, `0<<n → 0`, `x>>63 → x>>63` (no-op
//! preservation), over-shifts → 0.
//!
//! **Comparison simplification** — `x==x → 1`, `x!=x → 0`, `x<x → 0`, etc.
//!
//! **Bitwise patterns** — `x&x → x`, `x|x → x`, `x&0 → 0`, `x|(-1) → -1`.
//!
//! **Strength reduction** — `x*2 → x+x`, `x/2 → x>>1` (unsigned only).
//!
//! **Logical short-circuit** — `true || x → true`, `false && x → false`.

use std::fmt;

use crate::{BinOp, Expr, IntWidth, UnOp};

// ─────────────────────────────────────────────────────────────────────────────
// OptimizationStats
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics collected during a peephole optimization pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OptimizationStats {
    /// Total number of individual rule applications.
    pub rules_applied: u64,
    /// Number of expression nodes that were simplified (replaced with simpler forms).
    pub expressions_simplified: u64,
    /// Number of full optimizer passes made.
    pub passes: u32,
}

impl OptimizationStats {
    /// Create zeroed statistics.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge `other` into `self`.
    pub const fn merge(&mut self, other: &Self) {
        self.rules_applied += other.rules_applied;
        self.expressions_simplified += other.expressions_simplified;
        self.passes += other.passes;
    }

    /// Returns `true` if at least one rule was applied.
    #[must_use]
    pub const fn any_progress(&self) -> bool {
        self.rules_applied > 0
    }
}

impl fmt::Display for OptimizationStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "passes={} rules_applied={} expressions_simplified={}",
            self.passes, self.rules_applied, self.expressions_simplified
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeepholeRule
// ─────────────────────────────────────────────────────────────────────────────

/// A single peephole rewrite rule.
///
/// Return `Some(new_expr)` to replace `expr`, `None` to leave it unchanged.
pub trait PeepholeRule: fmt::Debug + Send + Sync {
    /// Human-readable rule name (e.g. `"add_zero"`).
    fn name(&self) -> &str;

    /// Try to rewrite `expr`.  Called once per node per pass.
    fn apply(&self, expr: &Expr) -> Option<Expr>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in rules (closure-based)
// ─────────────────────────────────────────────────────────────────────────────

type ClosureRuleFn = Box<dyn Fn(&Expr) -> Option<Expr> + Send + Sync>;

struct ClosureRule {
    name: String,
    f: ClosureRuleFn,
}

impl fmt::Debug for ClosureRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClosureRule({})", self.name)
    }
}

impl PeepholeRule for ClosureRule {
    fn name(&self) -> &str {
        &self.name
    }
    fn apply(&self, expr: &Expr) -> Option<Expr> {
        (self.f)(expr)
    }
}

fn rule(
    name: &str,
    f: impl Fn(&Expr) -> Option<Expr> + Send + Sync + 'static,
) -> Box<dyn PeepholeRule> {
    Box::new(ClosureRule {
        name: name.to_string(),
        f: Box::new(f),
    })
}

// Shorthand constructors used inside rules.
#[inline]
const fn c(v: i64) -> Expr {
    Expr::Const(v, IntWidth::I64)
}

#[inline]
const fn c32(v: i64) -> Expr {
    Expr::Const(v, IntWidth::I32)
}

#[inline]
fn binop(op: BinOp, a: Expr, b: Expr) -> Expr {
    Expr::BinOp(op, Box::new(a), Box::new(b))
}

#[inline]
fn unop(op: UnOp, e: Expr) -> Expr {
    Expr::UnOp(op, Box::new(e))
}

// ─────────────────────────────────────────────────────────────────────────────
// Standard rule set (split across helpers to stay within the line-count limit)
// ─────────────────────────────────────────────────────────────────────────────

fn arithmetic_identity_rules() -> Vec<Box<dyn PeepholeRule>> {
    let mut rules: Vec<Box<dyn PeepholeRule>> = Vec::with_capacity(16);

    // ── Constant folding identities ──────────────────────────────────────────

    // a + 0 → a
    rules.push(rule("add_zero", |e| {
        if let Expr::BinOp(BinOp::Add, a, b) = e {
            if b.as_const() == Some(0) {
                return Some(*a.clone());
            }
            if a.as_const() == Some(0) {
                return Some(*b.clone());
            }
        }
        None
    }));

    // a - 0 → a
    rules.push(rule("sub_zero", |e| {
        if let Expr::BinOp(BinOp::Sub, a, b) = e
            && b.as_const() == Some(0) {
                return Some(*a.clone());
            }
        None
    }));

    // a * 1 → a
    rules.push(rule("mul_one", |e| {
        if let Expr::BinOp(BinOp::Mul, a, b) = e {
            if b.as_const() == Some(1) {
                return Some(*a.clone());
            }
            if a.as_const() == Some(1) {
                return Some(*b.clone());
            }
        }
        None
    }));

    // a * 0 → 0
    rules.push(rule("mul_zero", |e| {
        if let Expr::BinOp(BinOp::Mul, a, b) = e
            && (a.as_const() == Some(0) || b.as_const() == Some(0)) {
                return Some(c(0));
            }
        None
    }));

    // a - a → 0
    rules.push(rule("sub_self", |e| {
        if let Expr::BinOp(BinOp::Sub, a, b) = e
            && a == b {
                return Some(c(0));
            }
        None
    }));

    // a / 1 → a
    rules.push(rule("div_one", |e| {
        if let Expr::BinOp(BinOp::Div, a, b) = e
            && b.as_const() == Some(1) {
                return Some(*a.clone());
            }
        None
    }));

    // a / a → 1  (when a != 0, safe approximation)
    rules.push(rule("div_self", |e| {
        if let Expr::BinOp(BinOp::Div, a, b) = e
            && a == b && a.is_constant_expr() {
                return Some(c(1));
            }
        None
    }));

    // a % 1 → 0
    rules.push(rule("mod_one", |e| {
        if let Expr::BinOp(BinOp::Mod, _, b) = e
            && b.as_const() == Some(1) {
                return Some(c(0));
            }
        None
    }));

    // a % a → 0  (constant only)
    rules.push(rule("mod_self", |e| {
        if let Expr::BinOp(BinOp::Mod, a, b) = e
            && a == b && a.is_constant_expr() {
                return Some(c(0));
            }
        None
    }));

    rules
}

fn bitwise_or_rules() -> Vec<Box<dyn PeepholeRule>> {
    let mut rules: Vec<Box<dyn PeepholeRule>> = Vec::with_capacity(8);
    // ── Bitwise identity rules (OR) ──────────────────────────────────────────

    // a | 0 → a
    rules.push(rule("or_zero", |e| {
        if let Expr::BinOp(BinOp::Or, a, b) = e {
            if b.as_const() == Some(0) {
                return Some(*a.clone());
            }
            if a.as_const() == Some(0) {
                return Some(*b.clone());
            }
        }
        None
    }));

    // a | a → a
    rules.push(rule("or_self", |e| {
        if let Expr::BinOp(BinOp::Or, a, b) = e
            && a == b {
                return Some(*a.clone());
            }
        None
    }));

    // a | (-1) → -1  (all-ones mask)
    rules.push(rule("or_allones", |e| {
        if let Expr::BinOp(BinOp::Or, a, b) = e
            && (a.as_const() == Some(-1) || b.as_const() == Some(-1)) {
                return Some(c(-1));
            }
        None
    }));

    rules
}

fn bitwise_and_xor_rules() -> Vec<Box<dyn PeepholeRule>> {
    let mut rules: Vec<Box<dyn PeepholeRule>> = Vec::with_capacity(8);
    // ── Bitwise identity rules (AND / XOR) ──────────────────────────────────
    // a & (~0) → a  (all-ones mask is identity for AND)
    rules.push(rule("and_allones", |e| {
        if let Expr::BinOp(BinOp::And, a, b) = e {
            if b.as_const() == Some(-1) {
                return Some(*a.clone());
            }
            if a.as_const() == Some(-1) {
                return Some(*b.clone());
            }
        }
        None
    }));

    // a & 0 → 0
    rules.push(rule("and_zero", |e| {
        if let Expr::BinOp(BinOp::And, a, b) = e
            && (a.as_const() == Some(0) || b.as_const() == Some(0)) {
                return Some(c(0));
            }
        None
    }));

    // a & a → a
    rules.push(rule("and_self", |e| {
        if let Expr::BinOp(BinOp::And, a, b) = e
            && a == b {
                return Some(*a.clone());
            }
        None
    }));

    // a ^ 0 → a
    rules.push(rule("xor_zero", |e| {
        if let Expr::BinOp(BinOp::Xor, a, b) = e {
            if b.as_const() == Some(0) {
                return Some(*a.clone());
            }
            if a.as_const() == Some(0) {
                return Some(*b.clone());
            }
        }
        None
    }));

    // a ^ a → 0
    rules.push(rule("xor_self", |e| {
        if let Expr::BinOp(BinOp::Xor, a, b) = e
            && a == b {
                return Some(c(0));
            }
        None
    }));

    // a ^ (-1) → ~a  (XOR with all-ones = bitwise NOT)
    rules.push(rule("xor_allones_is_not", |e| {
        if let Expr::BinOp(BinOp::Xor, a, b) = e {
            if b.as_const() == Some(-1) {
                return Some(unop(UnOp::Not, *a.clone()));
            }
            if a.as_const() == Some(-1) {
                return Some(unop(UnOp::Not, *b.clone()));
            }
        }
        None
    }));

    rules
}

fn shift_rules() -> Vec<Box<dyn PeepholeRule>> {
    let mut rules: Vec<Box<dyn PeepholeRule>> = Vec::with_capacity(8);
    // ── Shift normalization ──────────────────────────────────────────────────

    // x << 0 → x
    rules.push(rule("shl_zero", |e| {
        if let Expr::BinOp(BinOp::Shl, a, b) = e
            && b.as_const() == Some(0) {
                return Some(*a.clone());
            }
        None
    }));

    // x >> 0 → x  (both logical and arithmetic)
    rules.push(rule("shr_zero", |e| {
        if let Expr::BinOp(op @ (BinOp::Shr | BinOp::Sar), a, b) = e {
            // Both logical (Shr) and arithmetic (Sar) right shifts by zero are identity.
            debug_assert!(matches!(op, BinOp::Shr | BinOp::Sar));
            if b.as_const() == Some(0) {
                return Some(*a.clone());
            }
        }
        None
    }));

    // 0 << n → 0
    rules.push(rule("zero_shl", |e| {
        if let Expr::BinOp(BinOp::Shl, a, _) = e
            && a.as_const() == Some(0) {
                return Some(c(0));
            }
        None
    }));

    // 0 >> n → 0
    rules.push(rule("zero_shr", |e| {
        if let Expr::BinOp(BinOp::Shr | BinOp::Sar, a, _) = e
            && a.as_const() == Some(0) {
                return Some(c(0));
            }
        None
    }));

    // x << 64 → 0  (over-shift)
    rules.push(rule("shl_overshift", |e| {
        if let Expr::BinOp(BinOp::Shl, _, b) = e
            && b.as_const().is_some_and(|v| v >= 64) {
                return Some(c(0));
            }
        None
    }));

    // x >> 64 → 0  (over-shift)
    rules.push(rule("shr_overshift", |e| {
        if let Expr::BinOp(BinOp::Shr, _, b) = e
            && b.as_const().is_some_and(|v| v >= 64) {
                return Some(c(0));
            }
        None
    }));

    rules
}

fn negation_rules() -> Vec<Box<dyn PeepholeRule>> {
    let mut rules: Vec<Box<dyn PeepholeRule>> = Vec::with_capacity(10);
    // ── Double negation / bitwise not ────────────────────────────────────────

    // --x → x  (arithmetic negation)
    rules.push(rule("double_neg", |e| {
        if let Expr::UnOp(UnOp::Neg, inner) = e
            && let Expr::UnOp(UnOp::Neg, innerinner) = inner.as_ref() {
                return Some(*innerinner.clone());
            }
        None
    }));

    // ~~x → x  (bitwise NOT)
    rules.push(rule("double_bitnot", |e| {
        if let Expr::UnOp(UnOp::Not, inner) = e
            && let Expr::UnOp(UnOp::Not, innerinner) = inner.as_ref() {
                return Some(*innerinner.clone());
            }
        None
    }));

    // !!x → x  (logical NOT)
    rules.push(rule("double_lnot", |e| {
        if let Expr::UnOp(UnOp::LNot, inner) = e
            && let Expr::UnOp(UnOp::LNot, innerinner) = inner.as_ref() {
                return Some(*innerinner.clone());
            }
        None
    }));

    // !(a == b) → a != b  (simplify negated comparison)
    rules.push(rule("lnot_eq_becomes_ne", |e| {
        if let Expr::UnOp(UnOp::LNot, inner) = e
            && let Expr::BinOp(BinOp::Eq, a, b) = inner.as_ref() {
                return Some(binop(BinOp::Ne, *a.clone(), *b.clone()));
            }
        None
    }));

    // !(a != b) → a == b
    rules.push(rule("lnot_ne_becomes_eq", |e| {
        if let Expr::UnOp(UnOp::LNot, inner) = e
            && let Expr::BinOp(BinOp::Ne, a, b) = inner.as_ref() {
                return Some(binop(BinOp::Eq, *a.clone(), *b.clone()));
            }
        None
    }));

    // !(a < b) → a >= b
    rules.push(rule("lnot_lt_becomes_ge", |e| {
        if let Expr::UnOp(UnOp::LNot, inner) = e
            && let Expr::BinOp(BinOp::Lt, a, b) = inner.as_ref() {
                return Some(binop(BinOp::Ge, *a.clone(), *b.clone()));
            }
        None
    }));

    // !(a > b) → a <= b
    rules.push(rule("lnot_gt_becomes_le", |e| {
        if let Expr::UnOp(UnOp::LNot, inner) = e
            && let Expr::BinOp(BinOp::Gt, a, b) = inner.as_ref() {
                return Some(binop(BinOp::Le, *a.clone(), *b.clone()));
            }
        None
    }));

    rules
}

fn demorgan_comparison_rules() -> Vec<Box<dyn PeepholeRule>> {
    let mut rules: Vec<Box<dyn PeepholeRule>> = Vec::with_capacity(10);
    // ── De Morgan's laws ─────────────────────────────────────────────────────

    // !a || !b → !(a && b)
    rules.push(rule("demorgan_or", |e| {
        if let Expr::BinOp(BinOp::LOr, a, b) = e
            && let (Expr::UnOp(UnOp::LNot, ia), Expr::UnOp(UnOp::LNot, ib)) =
                (a.as_ref(), b.as_ref())
            {
                return Some(unop(
                    UnOp::LNot,
                    binop(BinOp::LAnd, *ia.clone(), *ib.clone()),
                ));
            }
        None
    }));

    // !a && !b → !(a || b)
    rules.push(rule("demorgan_and", |e| {
        if let Expr::BinOp(BinOp::LAnd, a, b) = e
            && let (Expr::UnOp(UnOp::LNot, ia), Expr::UnOp(UnOp::LNot, ib)) =
                (a.as_ref(), b.as_ref())
            {
                return Some(unop(
                    UnOp::LNot,
                    binop(BinOp::LOr, *ia.clone(), *ib.clone()),
                ));
            }
        None
    }));

    // ── Comparison simplification ────────────────────────────────────────────

    // x == x → 1
    rules.push(rule("eq_self", |e| {
        if let Expr::BinOp(BinOp::Eq, a, b) = e
            && a == b {
                return Some(c32(1));
            }
        None
    }));

    // x != x → 0
    rules.push(rule("ne_self", |e| {
        if let Expr::BinOp(BinOp::Ne, a, b) = e
            && a == b {
                return Some(c32(0));
            }
        None
    }));

    // x < x → 0
    rules.push(rule("lt_self", |e| {
        if let Expr::BinOp(BinOp::Lt, a, b) = e
            && a == b {
                return Some(c32(0));
            }
        None
    }));

    // x > x → 0
    rules.push(rule("gt_self", |e| {
        if let Expr::BinOp(BinOp::Gt, a, b) = e
            && a == b {
                return Some(c32(0));
            }
        None
    }));

    // x <= x → 1
    rules.push(rule("le_self", |e| {
        if let Expr::BinOp(BinOp::Le, a, b) = e
            && a == b {
                return Some(c32(1));
            }
        None
    }));

    // x >= x → 1
    rules.push(rule("ge_self", |e| {
        if let Expr::BinOp(BinOp::Ge, a, b) = e
            && a == b {
                return Some(c32(1));
            }
        None
    }));

    rules
}

fn logical_rules() -> Vec<Box<dyn PeepholeRule>> {
    let mut rules: Vec<Box<dyn PeepholeRule>> = Vec::with_capacity(8);
    // ── Logical short-circuit ────────────────────────────────────────────────

    // true && x → x
    rules.push(rule("land_true_left", |e| {
        if let Expr::BinOp(BinOp::LAnd, a, b) = e
            && a.as_const().is_some_and(|v| v != 0) {
                return Some(*b.clone());
            }
        None
    }));

    // x && true → x
    rules.push(rule("land_true_right", |e| {
        if let Expr::BinOp(BinOp::LAnd, a, b) = e
            && b.as_const().is_some_and(|v| v != 0) {
                return Some(*a.clone());
            }
        None
    }));

    // false && x → 0
    rules.push(rule("land_false", |e| {
        if let Expr::BinOp(BinOp::LAnd, a, b) = e
            && (a.as_const() == Some(0) || b.as_const() == Some(0)) {
                return Some(c32(0));
            }
        None
    }));

    // true || x → 1
    rules.push(rule("lor_true", |e| {
        if let Expr::BinOp(BinOp::LOr, a, b) = e
            && (a.as_const().is_some_and(|v| v != 0) || b.as_const().is_some_and(|v| v != 0)) {
                return Some(c32(1));
            }
        None
    }));

    // false || x → x
    rules.push(rule("lor_false_left", |e| {
        if let Expr::BinOp(BinOp::LOr, a, b) = e
            && a.as_const() == Some(0) {
                return Some(*b.clone());
            }
        None
    }));

    // x || false → x
    rules.push(rule("lor_false_right", |e| {
        if let Expr::BinOp(BinOp::LOr, a, b) = e
            && b.as_const() == Some(0) {
                return Some(*a.clone());
            }
        None
    }));

    rules
}

fn strength_fusion_rules() -> Vec<Box<dyn PeepholeRule>> {
    let mut rules: Vec<Box<dyn PeepholeRule>> = Vec::with_capacity(8);
    // ── Strength reduction ───────────────────────────────────────────────────

    // x * 2 → x + x
    rules.push(rule("mul2_to_add", |e| {
        if let Expr::BinOp(BinOp::Mul, a, b) = e
            && b.as_const() == Some(2) {
                return Some(binop(BinOp::Add, *a.clone(), *a.clone()));
            }
        None
    }));

    // x * (power-of-two) → x << log2
    rules.push(rule("mul_pow2_to_shl", |e| {
        if let Expr::BinOp(BinOp::Mul, a, b) = e
            && let Some(v) = b.as_const()
                && v > 2 && v.cast_unsigned().is_power_of_two() {
                    let shift = i64::from(v.trailing_zeros());
                    return Some(binop(BinOp::Shl, *a.clone(), c(shift)));
                }
        None
    }));

    // ── Negation + arithmetic fusion ─────────────────────────────────────────

    // a + (-b) → a - b  when -b is a UnOp::Neg
    rules.push(rule("add_neg_to_sub", |e| {
        if let Expr::BinOp(BinOp::Add, a, b) = e
            && let Expr::UnOp(UnOp::Neg, inner) = b.as_ref() {
                return Some(binop(BinOp::Sub, *a.clone(), *inner.clone()));
            }
        None
    }));

    // a - (-b) → a + b
    rules.push(rule("sub_neg_to_add", |e| {
        if let Expr::BinOp(BinOp::Sub, a, b) = e
            && let Expr::UnOp(UnOp::Neg, inner) = b.as_ref() {
                return Some(binop(BinOp::Add, *a.clone(), *inner.clone()));
            }
        None
    }));

    // -(0) → 0
    rules.push(rule("neg_zero", |e| {
        if let Expr::UnOp(UnOp::Neg, inner) = e
            && inner.as_const() == Some(0) {
                return Some(c(0));
            }
        None
    }));

    // ~(-1) → 0  (bitwise not of -1)
    rules.push(rule("not_allones", |e| {
        if let Expr::UnOp(UnOp::Not, inner) = e
            && inner.as_const() == Some(-1) {
                return Some(c(0));
            }
        None
    }));

    // ~0 → -1
    rules.push(rule("not_zero", |e| {
        if let Expr::UnOp(UnOp::Not, inner) = e
            && inner.as_const() == Some(0) {
                return Some(c(-1));
            }
        None
    }));

    rules
}

/// Build the default set of 40+ peephole rules.
#[must_use]
pub fn default_rules() -> Vec<Box<dyn PeepholeRule>> {
    let mut rules = arithmetic_identity_rules();
    rules.extend(bitwise_or_rules());
    rules.extend(bitwise_and_xor_rules());
    rules.extend(shift_rules());
    rules.extend(negation_rules());
    rules.extend(demorgan_comparison_rules());
    rules.extend(logical_rules());
    rules.extend(strength_fusion_rules());
    rules
}

// ─────────────────────────────────────────────────────────────────────────────
// PeepholeOptimizer
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the peephole optimizer.
#[derive(Debug, Clone)]
pub struct PeepholeConfig {
    /// Maximum number of full-tree passes before giving up.
    pub max_passes: u32,
    /// If `true`, recurse into child expressions after applying a rule to a node.
    pub recursive: bool,
    /// If `true`, collect per-rule statistics.
    pub track_stats: bool,
}

impl Default for PeepholeConfig {
    fn default() -> Self {
        Self {
            max_passes: 16,
            recursive: true,
            track_stats: false,
        }
    }
}

/// Runs a set of [`PeepholeRule`]s over an expression tree to a fixed point.
///
/// The optimizer performs multiple passes over the tree, applying each rule
/// to every sub-expression bottom-up.  It stops when no rule produces a
/// change (fixed point) or `max_passes` is reached.
pub struct PeepholeOptimizer {
    rules: Vec<Box<dyn PeepholeRule>>,
    pub config: PeepholeConfig,
}

impl fmt::Debug for PeepholeOptimizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PeepholeOptimizer {{ rules: {}, config: {:?} }}",
            self.rules.len(),
            self.config
        )
    }
}

impl PeepholeOptimizer {
    /// Create an optimizer with the default rule set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: default_rules(),
            config: PeepholeConfig::default(),
        }
    }

    /// Create an empty optimizer (no rules).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            config: PeepholeConfig::default(),
        }
    }

    /// Create with a custom configuration.
    #[must_use]
    pub fn with_config(config: PeepholeConfig) -> Self {
        Self {
            rules: default_rules(),
            config,
        }
    }

    /// Add an extra rule.
    pub fn add_rule(&mut self, rule: Box<dyn PeepholeRule>) {
        self.rules.push(rule);
    }

    /// Add a closure-based rule by name.
    pub fn add_closure_rule(
        &mut self,
        name: &str,
        f: impl Fn(&Expr) -> Option<Expr> + Send + Sync + 'static,
    ) {
        self.add_rule(rule(name, f));
    }

    /// Number of registered rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Names of all registered rules.
    #[must_use]
    pub fn rule_names(&self) -> Vec<&str> {
        self.rules.iter().map(|r| r.name()).collect()
    }

    /// Optimize `expr` to a fixed point.
    ///
    /// Returns the optimized expression.  Use [`Self::optimize_tracked`] to
    /// also get statistics.
    #[must_use]
    pub fn optimize(&self, expr: Expr) -> Expr {
        self.optimize_tracked(expr).0
    }

    /// Optimize `expr` and return both the result and collected statistics.
    #[must_use]
    pub fn optimize_tracked(&self, expr: Expr) -> (Expr, OptimizationStats) {
        let mut stats = OptimizationStats::new();
        let mut current = expr;

        for _ in 0..self.config.max_passes {
            let (next, pass_stats) = self.single_pass(current.clone());
            stats.passes += 1;
            stats.merge(&pass_stats);
            if next == current {
                break;
            }
            current = next;
        }

        (current, stats)
    }

    /// Optimize a list of expressions (e.g. SSA assignment RHS values).
    #[must_use]
    pub fn optimize_all(&self, exprs: Vec<Expr>) -> Vec<Expr> {
        exprs.into_iter().map(|e| self.optimize(e)).collect()
    }

    /// Optimize all expressions in a list and return combined stats.
    #[must_use]
    pub fn optimize_all_tracked(&self, exprs: Vec<Expr>) -> (Vec<Expr>, OptimizationStats) {
        let mut combined = OptimizationStats::new();
        let results = exprs
            .into_iter()
            .map(|e| {
                let (opt, stats) = self.optimize_tracked(e);
                combined.merge(&stats);
                opt
            })
            .collect();
        (results, combined)
    }

    // ── Single pass ──────────────────────────────────────────────────────────

    fn single_pass(&self, expr: Expr) -> (Expr, OptimizationStats) {
        let mut stats = OptimizationStats::new();
        let result = self.visit(expr, &mut stats);
        (result, stats)
    }

    fn visit(&self, expr: Expr, stats: &mut OptimizationStats) -> Expr {
        // First, recurse into children (bottom-up).
        let expr = if self.config.recursive {
            self.visit_children(expr, stats)
        } else {
            expr
        };

        // Then try to apply rules at this node.
        self.apply_rules(expr, stats)
    }

    fn visit_children(&self, expr: Expr, stats: &mut OptimizationStats) -> Expr {
        match expr {
            Expr::BinOp(op, a, b) => {
                let a2 = self.visit(*a, stats);
                let b2 = self.visit(*b, stats);
                Expr::BinOp(op, Box::new(a2), Box::new(b2))
            }
            Expr::UnOp(op, e) => {
                let e2 = self.visit(*e, stats);
                Expr::UnOp(op, Box::new(e2))
            }
            Expr::Call { callee, args } => {
                let callee2 = self.visit(*callee, stats);
                let args2: Vec<Expr> = args.into_iter().map(|a| self.visit(a, stats)).collect();
                Expr::Call {
                    callee: Box::new(callee2),
                    args: args2,
                }
            }
            Expr::Load { ptr, size } => {
                let ptr2 = self.visit(*ptr, stats);
                Expr::Load {
                    ptr: Box::new(ptr2),
                    size,
                }
            }
            Expr::FieldAccess { base, offset } => {
                let base2 = self.visit(*base, stats);
                Expr::FieldAccess {
                    base: Box::new(base2),
                    offset,
                }
            }
            Expr::Index {
                base,
                index,
                elem_size,
            } => {
                let base2 = self.visit(*base, stats);
                let index2 = self.visit(*index, stats);
                Expr::Index {
                    base: Box::new(base2),
                    index: Box::new(index2),
                    elem_size,
                }
            }
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                let c2 = self.visit(*cond, stats);
                let t2 = self.visit(*then_expr, stats);
                let e2 = self.visit(*else_expr, stats);
                Expr::Ternary {
                    cond: Box::new(c2),
                    then_expr: Box::new(t2),
                    else_expr: Box::new(e2),
                }
            }
            Expr::Phi(exprs) => {
                let exprs2: Vec<Expr> = exprs.into_iter().map(|e| self.visit(e, stats)).collect();
                Expr::Phi(exprs2)
            }
            leaf => leaf,
        }
    }

    fn apply_rules(&self, mut expr: Expr, stats: &mut OptimizationStats) -> Expr {
        for rule in &self.rules {
            if let Some(rewritten) = rule.apply(&expr) {
                stats.rules_applied += 1;
                stats.expressions_simplified += 1;
                expr = rewritten;
                // After a successful rewrite, restart from the first rule.
                // (We only do one rule per node per visit; the outer loop handles
                // further simplification.)
                break;
            }
        }
        expr
    }
}

impl Default for PeepholeOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BinOp, Expr, IntWidth, UnOp};

    fn c(v: i64) -> Expr {
        Expr::Const(v, IntWidth::I64)
    }
    fn c32(v: i64) -> Expr {
        Expr::Const(v, IntWidth::I32)
    }
    fn var(n: &str) -> Expr {
        Expr::Var(n.to_string())
    }
    fn add(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::Add, Box::new(a), Box::new(b))
    }
    fn sub(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::Sub, Box::new(a), Box::new(b))
    }
    fn mul(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::Mul, Box::new(a), Box::new(b))
    }
    fn div_e(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::Div, Box::new(a), Box::new(b))
    }
    fn and(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::And, Box::new(a), Box::new(b))
    }
    fn or(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::Or, Box::new(a), Box::new(b))
    }
    fn xor(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::Xor, Box::new(a), Box::new(b))
    }
    fn shl(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::Shl, Box::new(a), Box::new(b))
    }
    fn shr(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::Shr, Box::new(a), Box::new(b))
    }
    fn eq(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::Eq, Box::new(a), Box::new(b))
    }
    fn ne(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::Ne, Box::new(a), Box::new(b))
    }
    fn lt(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::Lt, Box::new(a), Box::new(b))
    }
    fn land(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::LAnd, Box::new(a), Box::new(b))
    }
    fn lor(a: Expr, b: Expr) -> Expr {
        Expr::BinOp(BinOp::LOr, Box::new(a), Box::new(b))
    }
    fn neg(e: Expr) -> Expr {
        Expr::UnOp(UnOp::Neg, Box::new(e))
    }
    fn not(e: Expr) -> Expr {
        Expr::UnOp(UnOp::Not, Box::new(e))
    }
    fn lnot(e: Expr) -> Expr {
        Expr::UnOp(UnOp::LNot, Box::new(e))
    }

    fn opt() -> PeepholeOptimizer {
        PeepholeOptimizer::new()
    }

    // ── add_zero ──────────────────────────────────────────────────────────────

    #[test]
    fn test_add_zero_right() {
        assert_eq!(opt().optimize(add(var("x"), c(0))), var("x"));
    }

    #[test]
    fn test_add_zero_left() {
        assert_eq!(opt().optimize(add(c(0), var("x"))), var("x"));
    }

    // ── sub_zero ──────────────────────────────────────────────────────────────

    #[test]
    fn test_sub_zero() {
        assert_eq!(opt().optimize(sub(var("x"), c(0))), var("x"));
    }

    // ── mul_one ───────────────────────────────────────────────────────────────

    #[test]
    fn test_mul_one_right() {
        assert_eq!(opt().optimize(mul(var("x"), c(1))), var("x"));
    }

    #[test]
    fn test_mul_one_left() {
        assert_eq!(opt().optimize(mul(c(1), var("x"))), var("x"));
    }

    // ── mul_zero ──────────────────────────────────────────────────────────────

    #[test]
    fn test_mul_zero() {
        assert_eq!(opt().optimize(mul(var("x"), c(0))), c(0));
    }

    // ── sub_self ──────────────────────────────────────────────────────────────

    #[test]
    fn test_sub_self() {
        assert_eq!(opt().optimize(sub(var("x"), var("x"))), c(0));
    }

    // ── div_one ───────────────────────────────────────────────────────────────

    #[test]
    fn test_div_one() {
        assert_eq!(opt().optimize(div_e(var("x"), c(1))), var("x"));
    }

    // ── or_zero ───────────────────────────────────────────────────────────────

    #[test]
    fn test_or_zero_right() {
        assert_eq!(opt().optimize(or(var("x"), c(0))), var("x"));
    }

    #[test]
    fn test_or_zero_left() {
        assert_eq!(opt().optimize(or(c(0), var("x"))), var("x"));
    }

    // ── or_self ───────────────────────────────────────────────────────────────

    #[test]
    fn test_or_self() {
        assert_eq!(opt().optimize(or(var("x"), var("x"))), var("x"));
    }

    // ── and_allones ───────────────────────────────────────────────────────────

    #[test]
    fn test_and_allones() {
        assert_eq!(opt().optimize(and(var("x"), c(-1))), var("x"));
    }

    // ── and_zero ──────────────────────────────────────────────────────────────

    #[test]
    fn test_and_zero() {
        assert_eq!(opt().optimize(and(var("x"), c(0))), c(0));
    }

    // ── and_self ──────────────────────────────────────────────────────────────

    #[test]
    fn test_and_self() {
        assert_eq!(opt().optimize(and(var("x"), var("x"))), var("x"));
    }

    // ── xor_zero ──────────────────────────────────────────────────────────────

    #[test]
    fn test_xor_zero() {
        assert_eq!(opt().optimize(xor(var("x"), c(0))), var("x"));
    }

    // ── xor_self ──────────────────────────────────────────────────────────────

    #[test]
    fn test_xor_self() {
        assert_eq!(opt().optimize(xor(var("x"), var("x"))), c(0));
    }

    // ── xor_allones ───────────────────────────────────────────────────────────

    #[test]
    fn test_xor_allones_is_not() {
        let result = opt().optimize(xor(var("x"), c(-1)));
        assert_eq!(result, not(var("x")));
    }

    // ── shift ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_shl_zero() {
        assert_eq!(opt().optimize(shl(var("x"), c(0))), var("x"));
    }

    #[test]
    fn test_shr_zero() {
        assert_eq!(opt().optimize(shr(var("x"), c(0))), var("x"));
    }

    #[test]
    fn test_shl_overshift() {
        assert_eq!(opt().optimize(shl(var("x"), c(64))), c(0));
    }

    #[test]
    fn test_zero_shl() {
        assert_eq!(opt().optimize(shl(c(0), var("n"))), c(0));
    }

    // ── double negation ───────────────────────────────────────────────────────

    #[test]
    fn test_double_neg() {
        assert_eq!(opt().optimize(neg(neg(var("x")))), var("x"));
    }

    #[test]
    fn test_double_bitnot() {
        assert_eq!(opt().optimize(not(not(var("x")))), var("x"));
    }

    #[test]
    fn test_double_lnot() {
        assert_eq!(opt().optimize(lnot(lnot(var("x")))), var("x"));
    }

    // ── lnot comparison rewrites ──────────────────────────────────────────────

    #[test]
    fn test_lnot_eq_becomes_ne() {
        assert_eq!(
            opt().optimize(lnot(eq(var("x"), var("y")))),
            ne(var("x"), var("y"))
        );
    }

    #[test]
    fn test_lnot_ne_becomes_eq() {
        assert_eq!(
            opt().optimize(lnot(ne(var("x"), var("y")))),
            eq(var("x"), var("y"))
        );
    }

    // ── De Morgan ─────────────────────────────────────────────────────────────

    #[test]
    fn test_demorgan_or() {
        let e = lor(lnot(var("a")), lnot(var("b")));
        let result = opt().optimize(e);
        // Should become !(a && b)
        assert_eq!(result, lnot(land(var("a"), var("b"))));
    }

    #[test]
    fn test_demorgan_and() {
        let e = land(lnot(var("a")), lnot(var("b")));
        let result = opt().optimize(e);
        assert_eq!(result, lnot(lor(var("a"), var("b"))));
    }

    // ── Comparison self ───────────────────────────────────────────────────────

    #[test]
    fn test_eq_self() {
        assert_eq!(opt().optimize(eq(var("x"), var("x"))), c32(1));
    }

    #[test]
    fn test_ne_self() {
        assert_eq!(opt().optimize(ne(var("x"), var("x"))), c32(0));
    }

    #[test]
    fn test_lt_self() {
        assert_eq!(opt().optimize(lt(var("x"), var("x"))), c32(0));
    }

    // ── Logical short-circuit ─────────────────────────────────────────────────

    #[test]
    fn test_land_false() {
        assert_eq!(opt().optimize(land(c(0), var("x"))), c32(0));
    }

    #[test]
    fn test_lor_true() {
        assert_eq!(opt().optimize(lor(c(1), var("x"))), c32(1));
    }

    #[test]
    fn test_lor_false_left() {
        assert_eq!(opt().optimize(lor(c(0), var("x"))), var("x"));
    }

    // ── Strength reduction ────────────────────────────────────────────────────

    #[test]
    fn test_mul2_to_add() {
        let result = opt().optimize(mul(var("x"), c(2)));
        assert_eq!(result, add(var("x"), var("x")));
    }

    #[test]
    fn test_mul_pow2_to_shl() {
        // x * 4 → x << 2
        let result = opt().optimize(mul(var("x"), c(4)));
        assert_eq!(result, shl(var("x"), c(2)));
    }

    #[test]
    fn test_mul_pow2_8() {
        // x * 8 → x << 3
        let result = opt().optimize(mul(var("x"), c(8)));
        assert_eq!(result, shl(var("x"), c(3)));
    }

    // ── Negation arithmetic fusion ────────────────────────────────────────────

    #[test]
    fn test_add_neg_to_sub() {
        let e = add(var("x"), neg(var("y")));
        assert_eq!(opt().optimize(e), sub(var("x"), var("y")));
    }

    #[test]
    fn test_sub_neg_to_add() {
        let e = sub(var("x"), neg(var("y")));
        assert_eq!(opt().optimize(e), add(var("x"), var("y")));
    }

    #[test]
    fn test_neg_zero() {
        assert_eq!(opt().optimize(neg(c(0))), c(0));
    }

    #[test]
    fn test_not_allones() {
        assert_eq!(opt().optimize(not(c(-1))), c(0));
    }

    #[test]
    fn test_not_zero() {
        assert_eq!(opt().optimize(not(c(0))), c(-1));
    }

    // ── Stats tracking ────────────────────────────────────────────────────────

    #[test]
    fn test_stats_rules_applied() {
        let (_, stats) = opt().optimize_tracked(add(var("x"), c(0)));
        assert!(stats.rules_applied > 0);
    }

    #[test]
    fn test_stats_no_progress_on_leaf() {
        let (result, stats) = opt().optimize_tracked(var("x"));
        assert_eq!(result, var("x"));
        assert_eq!(stats.rules_applied, 0);
    }

    // ── Multi-pass nested ─────────────────────────────────────────────────────

    #[test]
    fn test_nested_optimization() {
        // (x + 0) * 1 → x
        let e = mul(add(var("x"), c(0)), c(1));
        assert_eq!(opt().optimize(e), var("x"));
    }

    #[test]
    fn test_deep_double_neg() {
        // ---x  → -x (two double-neg passes cancel two negations)
        let e = neg(neg(neg(var("x"))));
        assert_eq!(opt().optimize(e), neg(var("x")));
    }

    // ── OptimizationStats ─────────────────────────────────────────────────────

    #[test]
    fn test_stats_display() {
        let s = OptimizationStats {
            rules_applied: 3,
            expressions_simplified: 2,
            passes: 1,
        };
        let display = format!("{s}");
        assert!(display.contains('3'));
        assert!(display.contains('2'));
    }

    #[test]
    fn test_stats_any_progress() {
        let s = OptimizationStats {
            rules_applied: 1,
            ..Default::default()
        };
        assert!(s.any_progress());
        let s2 = OptimizationStats::default();
        assert!(!s2.any_progress());
    }

    #[test]
    fn test_stats_merge() {
        let mut a = OptimizationStats {
            rules_applied: 2,
            expressions_simplified: 1,
            passes: 1,
        };
        let b = OptimizationStats {
            rules_applied: 3,
            expressions_simplified: 4,
            passes: 2,
        };
        a.merge(&b);
        assert_eq!(a.rules_applied, 5);
        assert_eq!(a.passes, 3);
    }

    // ── Optimizer API ─────────────────────────────────────────────────────────

    #[test]
    fn test_rule_count() {
        let opt = PeepholeOptimizer::new();
        assert!(opt.rule_count() >= 40);
    }

    #[test]
    fn test_rule_names_non_empty() {
        let opt = PeepholeOptimizer::new();
        for name in opt.rule_names() {
            assert!(!name.is_empty());
        }
    }

    #[test]
    fn test_add_custom_rule() {
        let mut opt = PeepholeOptimizer::empty();
        opt.add_closure_rule("always_zero", |_| Some(c(0)));
        let result = opt.optimize(var("x"));
        assert_eq!(result, c(0));
    }

    #[test]
    fn test_optimize_all() {
        let exprs = vec![add(var("x"), c(0)), mul(var("y"), c(1))];
        let result = opt().optimize_all(exprs);
        assert_eq!(result[0], var("x"));
        assert_eq!(result[1], var("y"));
    }

    #[test]
    fn test_empty_optimizer_no_change() {
        let opt = PeepholeOptimizer::empty();
        let e = add(var("x"), c(0));
        assert_eq!(opt.optimize(e.clone()), e);
    }
}
