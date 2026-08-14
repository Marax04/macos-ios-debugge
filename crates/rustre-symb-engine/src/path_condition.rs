//! `path_condition` — Path conditions for symbolic execution.
//!
//! Provides [`PathCondition`], [`Constraint`], [`ConditionSet`],
//! [`add_constraint`], and [`is_satisfiable`].

use rustre_symb::SymExpr;
use std::collections::HashSet;
use std::fmt;

// ── Constraint ─────────────────────────────────────────────────────────────────

/// The kind of comparison used in a constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstraintKind {
    /// Symbolic expression must be non-zero (true).
    IsTrue,
    /// Symbolic expression must be zero (false).
    IsFalse,
    /// Two expressions are equal.
    Equal,
    /// Two expressions are not equal.
    NotEqual,
    /// Left < Right (unsigned).
    UnsignedLt,
    /// Left <= Right (unsigned).
    UnsignedLe,
    /// Left < Right (signed).
    SignedLt,
    /// Left <= Right (signed).
    SignedLe,
}

impl fmt::Display for ConstraintKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::IsTrue => "is_true",
            Self::IsFalse => "is_false",
            Self::Equal => "==",
            Self::NotEqual => "!=",
            Self::UnsignedLt => "u<",
            Self::UnsignedLe => "u<=",
            Self::SignedLt => "s<",
            Self::SignedLe => "s<=",
        };
        f.write_str(s)
    }
}

/// A single path constraint: a predicate that must hold for the path to be taken.
#[derive(Debug, Clone)]
pub struct Constraint {
    /// The kind of comparison.
    pub kind: ConstraintKind,
    /// Left-hand side expression.
    pub lhs: SymExpr,
    /// Right-hand side expression (may be a concrete zero for `IsTrue`/`IsFalse`).
    pub rhs: SymExpr,
    /// Whether this constraint was added on the `true` branch (vs negated on `false`).
    pub polarity: bool,
    /// Source address that generated this constraint (0 if unknown).
    pub source_addr: u64,
    /// Human-readable label.
    pub label: String,
}

impl Constraint {
    /// Create an `IsTrue` constraint (expression != 0).
    #[must_use]
    pub const fn is_true(expr: SymExpr, source_addr: u64) -> Self {
        Self {
            kind: ConstraintKind::IsTrue,
            lhs: expr,
            rhs: SymExpr::ConstBv { val: 0, width: 1 },
            polarity: true,
            source_addr,
            label: String::new(),
        }
    }

    /// Create an `IsFalse` constraint (expression == 0).
    #[must_use]
    pub const fn is_false(expr: SymExpr, source_addr: u64) -> Self {
        Self {
            kind: ConstraintKind::IsFalse,
            lhs: expr,
            rhs: SymExpr::ConstBv { val: 0, width: 1 },
            polarity: false,
            source_addr,
            label: String::new(),
        }
    }

    /// Create an equality constraint.
    #[must_use]
    pub const fn equal(lhs: SymExpr, rhs: SymExpr, source_addr: u64) -> Self {
        Self {
            kind: ConstraintKind::Equal,
            lhs,
            rhs,
            polarity: true,
            source_addr,
            label: String::new(),
        }
    }

    /// Create a not-equal constraint.
    #[must_use]
    pub const fn not_equal(lhs: SymExpr, rhs: SymExpr, source_addr: u64) -> Self {
        Self {
            kind: ConstraintKind::NotEqual,
            lhs,
            rhs,
            polarity: true,
            source_addr,
            label: String::new(),
        }
    }

    /// Attach a label for debugging.
    #[must_use]
    pub fn labeled(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// Negate this constraint (flip polarity and kind where applicable).
    #[must_use]
    pub fn negate(&self) -> Self {
        // For the ordering kinds the operands must be SWAPPED as well as the
        // kind flipped: NOT(a < b) is `a >= b`, i.e. `b <= a`. Flipping only the
        // kind yields `a <= b`, which is not the negation (both hold for a < b).
        let (new_kind, new_polarity, swap) = match self.kind {
            ConstraintKind::IsTrue => (ConstraintKind::IsFalse, false, false),
            ConstraintKind::IsFalse => (ConstraintKind::IsTrue, true, false),
            ConstraintKind::Equal => (ConstraintKind::NotEqual, !self.polarity, false),
            ConstraintKind::NotEqual => (ConstraintKind::Equal, !self.polarity, false),
            ConstraintKind::UnsignedLt => (ConstraintKind::UnsignedLe, !self.polarity, true),
            ConstraintKind::UnsignedLe => (ConstraintKind::UnsignedLt, !self.polarity, true),
            ConstraintKind::SignedLt => (ConstraintKind::SignedLe, !self.polarity, true),
            ConstraintKind::SignedLe => (ConstraintKind::SignedLt, !self.polarity, true),
        };
        let (lhs, rhs) = if swap {
            (self.rhs.clone(), self.lhs.clone())
        } else {
            (self.lhs.clone(), self.rhs.clone())
        };
        Self {
            kind: new_kind,
            lhs,
            rhs,
            polarity: new_polarity,
            source_addr: self.source_addr,
            label: format!("NOT({})", self.label),
        }
    }

    /// Quick syntactic check: is this obviously always true?
    #[must_use]
    pub fn is_tautology(&self) -> bool {
        if let (
            SymExpr::ConstBv { val: l, width: lw },
            SymExpr::ConstBv { val: r, width: rw },
        ) = (&self.lhs, &self.rhs)
        {
            let (sl, sr) = (sign_extend(*l, *lw), sign_extend(*r, *rw));
            match self.kind {
                ConstraintKind::Equal => l == r,
                ConstraintKind::NotEqual => l != r,
                ConstraintKind::IsTrue => *l != 0,
                ConstraintKind::IsFalse => *l == 0,
                ConstraintKind::UnsignedLt => l < r,
                ConstraintKind::UnsignedLe => l <= r,
                ConstraintKind::SignedLt => sl < sr,
                ConstraintKind::SignedLe => sl <= sr,
            }
        } else {
            false
        }
    }

    /// Quick syntactic check: is this obviously always false?
    #[must_use]
    pub fn is_contradiction(&self) -> bool {
        if let (
            SymExpr::ConstBv { val: l, width: lw },
            SymExpr::ConstBv { val: r, width: rw },
        ) = (&self.lhs, &self.rhs)
        {
            let (sl, sr) = (sign_extend(*l, *lw), sign_extend(*r, *rw));
            match self.kind {
                ConstraintKind::Equal => l != r,
                ConstraintKind::NotEqual => l == r,
                ConstraintKind::IsTrue => *l == 0,
                ConstraintKind::IsFalse => *l != 0,
                ConstraintKind::UnsignedLt => l >= r,
                ConstraintKind::UnsignedLe => l > r,
                ConstraintKind::SignedLt => sl >= sr,
                ConstraintKind::SignedLe => sl > sr,
            }
        } else {
            false
        }
    }
}

/// Reinterpret the low `width` bits of `val` as a two's-complement signed
/// integer, sign-extended to 64 bits.
///
/// Signed constraint kinds must not be evaluated on the raw `u64` payload: a
/// 64-bit `0xFFFF_FFFF_FFFF_FFFF` is `-1`, not a huge positive number, and the
/// unsigned comparison gives the opposite verdict. Widths of 0 or >= 64 are
/// passed through unchanged.
#[must_use]
fn sign_extend(val: u64, width: u32) -> i64 {
    if width == 0 || width >= 64 {
        return val.cast_signed();
    }
    let shift = 64 - width;
    (val << shift).cast_signed() >> shift
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lbl = if self.label.is_empty() {
            String::new()
        } else {
            format!(" /* {} */", self.label)
        };
        write!(f, "({:?} {} {:?}){lbl}", self.lhs, self.kind, self.rhs)
    }
}

// ── PathCondition ──────────────────────────────────────────────────────────────

/// The accumulated path condition for a single symbolic execution path.
///
/// A path condition is a conjunction of [`Constraint`]s that must all be
/// satisfiable simultaneously for the path to be feasible.
#[derive(Debug, Clone, Default)]
pub struct PathCondition {
    constraints: Vec<Constraint>,
    /// Cached infeasibility flag (set when a contradiction is detected).
    infeasible: bool,
}

impl PathCondition {
    /// Create an empty (trivially satisfiable) path condition.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a constraint and check for obvious contradictions.
    pub fn add(&mut self, c: Constraint) {
        if self.infeasible {
            return;
        }
        if c.is_contradiction() {
            self.infeasible = true;
        }
        self.constraints.push(c);
    }

    /// Number of constraints in this condition.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.constraints.len()
    }

    /// Whether there are no constraints.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }

    /// Whether the path condition has been determined to be infeasible.
    #[must_use]
    pub const fn is_infeasible(&self) -> bool {
        self.infeasible
    }

    /// Iterate over constraints.
    pub fn iter(&self) -> impl Iterator<Item = &Constraint> {
        self.constraints.iter()
    }

    /// Constraints originating from a specific source address.
    #[must_use]
    pub fn constraints_from(&self, addr: u64) -> Vec<&Constraint> {
        self.constraints
            .iter()
            .filter(|c| c.source_addr == addr)
            .collect()
    }

    /// Build a conjunction `SymExpr` from all constraints' lhs expressions.
    #[must_use]
    pub fn as_conjunction(&self) -> Option<SymExpr> {
        let mut it = self.constraints.iter();
        let first = it.next()?;
        let init = first.lhs.clone();
        Some(it.fold(init, |acc, c| SymExpr::and(acc, c.lhs.clone())))
    }

    /// Merge another path condition into this one (take the conjunction).
    pub fn merge(&mut self, other: &Self) {
        for c in &other.constraints {
            self.add(c.clone());
        }
        if other.infeasible {
            self.infeasible = true;
        }
    }

    /// Fork: return a new path condition with `extra` added.
    #[must_use]
    pub fn fork_with(&self, extra: Constraint) -> Self {
        let mut forked = self.clone();
        forked.add(extra);
        forked
    }

    /// Remove constraints older than `depth` from the tail.
    pub fn trim_to_depth(&mut self, depth: usize) {
        if self.constraints.len() > depth {
            self.constraints.drain(..self.constraints.len() - depth);
        }
    }
}

impl fmt::Display for PathCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return write!(f, "true");
        }
        let parts: Vec<String> = self.constraints.iter().map(ToString::to_string).collect();
        write!(f, "{}", parts.join(" ∧ "))
    }
}

// ── ConditionSet ───────────────────────────────────────────────────────────────

/// A collection of [`PathCondition`]s corresponding to different execution paths.
///
/// Useful for tracking multiple forked paths simultaneously.
#[derive(Debug, Clone, Default)]
pub struct ConditionSet {
    conditions: Vec<PathCondition>,
    /// Maximum number of conditions to retain (oldest are pruned).
    max_size: usize,
}

impl ConditionSet {
    /// Create a new empty condition set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            conditions: Vec::new(),
            max_size: 256,
        }
    }

    /// Create a condition set with a custom capacity limit.
    #[must_use]
    pub const fn with_max(max_size: usize) -> Self {
        Self {
            conditions: Vec::new(),
            max_size,
        }
    }

    /// Add a path condition.
    pub fn push(&mut self, cond: PathCondition) {
        if self.conditions.len() >= self.max_size {
            self.conditions.remove(0);
        }
        self.conditions.push(cond);
    }

    /// Number of conditions in the set.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.conditions.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.conditions.is_empty()
    }

    /// Drain infeasible conditions.
    pub fn prune_infeasible(&mut self) {
        self.conditions.retain(|c| !c.is_infeasible());
    }

    /// Return all feasible conditions.
    #[must_use]
    pub fn feasible(&self) -> Vec<&PathCondition> {
        self.conditions
            .iter()
            .filter(|c| !c.is_infeasible())
            .collect()
    }

    /// Total constraint count across all conditions.
    #[must_use]
    pub fn total_constraints(&self) -> usize {
        self.conditions.iter().map(PathCondition::len).sum()
    }

    /// Find conditions that have constraints from a given source address.
    #[must_use]
    pub fn conditions_touching(&self, addr: u64) -> Vec<&PathCondition> {
        self.conditions
            .iter()
            .filter(|c| c.constraints.iter().any(|con| con.source_addr == addr))
            .collect()
    }

    /// Unique source addresses across all conditions.
    #[must_use]
    pub fn unique_sources(&self) -> HashSet<u64> {
        self.conditions
            .iter()
            .flat_map(|c| c.constraints.iter().map(|con| con.source_addr))
            .collect()
    }
}

// ── Free functions ─────────────────────────────────────────────────────────────

/// Append a constraint to a path condition.
///
/// Convenience wrapper; equivalent to `pc.add(constraint)`.
pub fn add_constraint(pc: &mut PathCondition, constraint: Constraint) {
    pc.add(constraint);
}

/// Perform a lightweight syntactic satisfiability check on a path condition.
///
/// Returns `true` if the condition is not obviously infeasible.
/// This does **not** invoke an SMT solver; it only checks for syntactic contradictions
/// (concrete-vs-concrete comparisons that are false) and the cached infeasibility flag.
#[must_use]
pub fn is_satisfiable(pc: &PathCondition) -> bool {
    if pc.is_infeasible() {
        return false;
    }
    // Check each constraint individually for obvious contradictions
    for c in pc.iter() {
        if c.is_contradiction() {
            return false;
        }
    }
    true
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn concrete(v: u64) -> SymExpr {
        SymExpr::ConstBv { val: v, width: 64 }
    }

    fn sym(name: &str) -> SymExpr {
        SymExpr::Symbol(0, 64, name.to_string())
    }

    #[test]
    fn test_constraint_is_true_tautology() {
        let c = Constraint::is_true(concrete(1), 0x0);
        assert!(c.is_tautology());
        assert!(!c.is_contradiction());
    }

    #[test]
    fn test_constraint_is_false_contradiction() {
        let c = Constraint::is_false(concrete(1), 0x0);
        assert!(c.is_contradiction());
    }

    #[test]
    fn test_constraint_equal_concrete() {
        let c = Constraint::equal(concrete(5), concrete(5), 0x0);
        assert!(c.is_tautology());
        let c2 = Constraint::equal(concrete(5), concrete(6), 0x0);
        assert!(c2.is_contradiction());
    }

    #[test]
    fn test_constraint_not_equal() {
        let c = Constraint::not_equal(concrete(3), concrete(4), 0x0);
        assert!(c.is_tautology());
        let c2 = Constraint::not_equal(concrete(3), concrete(3), 0x0);
        assert!(c2.is_contradiction());
    }

    #[test]
    fn test_constraint_negate_is_true() {
        let c = Constraint::is_true(sym("x"), 0x1000);
        let neg = c.negate();
        assert_eq!(neg.kind, ConstraintKind::IsFalse);
    }

    #[test]
    fn test_constraint_negate_equal() {
        let c = Constraint::equal(sym("x"), concrete(0), 0x0);
        let neg = c.negate();
        assert_eq!(neg.kind, ConstraintKind::NotEqual);
    }

    #[test]
    fn test_constraint_labeled() {
        let c = Constraint::is_true(sym("x"), 0x0).labeled("branch cond");
        assert_eq!(c.label, "branch cond");
    }

    #[test]
    fn test_constraint_display() {
        let c = Constraint::equal(concrete(1), concrete(1), 0x0).labeled("chk");
        let s = c.to_string();
        assert!(!s.is_empty());
    }

    #[test]
    fn test_path_condition_empty() {
        let pc = PathCondition::new();
        assert!(pc.is_empty());
        assert!(!pc.is_infeasible());
    }

    #[test]
    fn test_path_condition_add_satisfiable() {
        let mut pc = PathCondition::new();
        pc.add(Constraint::is_true(sym("x"), 0x0));
        assert_eq!(pc.len(), 1);
        assert!(!pc.is_infeasible());
    }

    #[test]
    fn test_path_condition_add_contradiction() {
        let mut pc = PathCondition::new();
        pc.add(Constraint::is_false(concrete(1), 0x0)); // concrete 1 != 0 is contradiction for IsFalse
        assert!(pc.is_infeasible());
    }

    #[test]
    fn test_path_condition_as_conjunction_empty() {
        let pc = PathCondition::new();
        assert!(pc.as_conjunction().is_none());
    }

    #[test]
    fn test_path_condition_as_conjunction_one() {
        let mut pc = PathCondition::new();
        pc.add(Constraint::is_true(sym("x"), 0x0));
        assert!(pc.as_conjunction().is_some());
    }

    #[test]
    fn test_path_condition_fork_with() {
        let mut pc = PathCondition::new();
        pc.add(Constraint::is_true(sym("x"), 0x0));
        let forked = pc.fork_with(Constraint::is_true(sym("y"), 0x0));
        assert_eq!(forked.len(), 2);
        assert_eq!(pc.len(), 1); // original unchanged
    }

    #[test]
    fn test_path_condition_merge() {
        let mut a = PathCondition::new();
        a.add(Constraint::is_true(sym("x"), 0x0));
        let mut b = PathCondition::new();
        b.add(Constraint::is_true(sym("y"), 0x0));
        a.merge(&b);
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn test_path_condition_trim_to_depth() {
        let mut pc = PathCondition::new();
        for i in 0..10u64 {
            pc.add(Constraint::is_true(sym(&format!("x{i}")), i));
        }
        pc.trim_to_depth(3);
        assert_eq!(pc.len(), 3);
    }

    #[test]
    fn test_path_condition_display() {
        let pc = PathCondition::new();
        assert_eq!(pc.to_string(), "true");
    }

    #[test]
    fn test_condition_set_push_and_prune() {
        let mut cs = ConditionSet::new();
        let mut pc1 = PathCondition::new();
        pc1.add(Constraint::is_true(sym("a"), 0x0));
        let mut pc2 = PathCondition::new();
        pc2.add(Constraint::is_false(concrete(1), 0x0)); // infeasible
        cs.push(pc1);
        cs.push(pc2);
        assert_eq!(cs.len(), 2);
        cs.prune_infeasible();
        assert_eq!(cs.len(), 1);
    }

    #[test]
    fn test_condition_set_feasible() {
        let mut cs = ConditionSet::new();
        cs.push(PathCondition::new()); // trivially feasible
        let mut bad = PathCondition::new();
        bad.add(Constraint::is_false(concrete(99), 0x0));
        cs.push(bad);
        assert_eq!(cs.feasible().len(), 1);
    }

    #[test]
    fn test_condition_set_max_size() {
        let mut cs = ConditionSet::with_max(3);
        for _ in 0..5 {
            cs.push(PathCondition::new());
        }
        assert_eq!(cs.len(), 3);
    }

    #[test]
    fn test_add_constraint_free_fn() {
        let mut pc = PathCondition::new();
        add_constraint(&mut pc, Constraint::is_true(sym("z"), 0x0));
        assert_eq!(pc.len(), 1);
    }

    #[test]
    fn test_is_satisfiable_free_fn() {
        let pc = PathCondition::new();
        assert!(is_satisfiable(&pc));
    }

    #[test]
    fn test_is_satisfiable_contradiction() {
        let mut pc = PathCondition::new();
        pc.add(Constraint::is_false(concrete(1), 0x0));
        assert!(!is_satisfiable(&pc));
    }

    #[test]
    fn test_is_satisfiable_symbolic() {
        let mut pc = PathCondition::new();
        pc.add(Constraint::is_true(sym("unknown"), 0x0));
        // Symbolic, not concretely false → satisfiable
        assert!(is_satisfiable(&pc));
    }

    #[test]
    fn test_constraint_kind_display() {
        assert_eq!(ConstraintKind::Equal.to_string(), "==");
        assert_eq!(ConstraintKind::UnsignedLt.to_string(), "u<");
        assert_eq!(ConstraintKind::IsTrue.to_string(), "is_true");
    }
}
