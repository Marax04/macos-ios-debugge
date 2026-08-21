//! Constraint propagation for IADL-driven deobfuscation.
//!
//! This module provides a constraint-propagation engine that reasons about
//! value ranges and equalities across a deobfuscated program's variables.
//! It drives the IADL feedback loop by producing tighter bounds that other
//! passes (e.g. opaque-predicate elimination) can exploit.

pub use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// ValueRange — an interval on the integer domain
// ─────────────────────────────────────────────────────────────────────────────

/// An integer-valued interval `[lo, hi]` over the signed 64-bit domain.
///
/// The special variant `Top` means "any value" (widest possible range).
/// `Bottom` means "no value" (unreachable / contradiction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueRange {
    Top,
    Bottom,
    Bounded { lo: i64, hi: i64 },
}

impl ValueRange {
    /// The widest possible range.
    #[must_use] 
    pub const fn top() -> Self {
        Self::Top
    }

    /// An empty / contradictory range.
    #[must_use] 
    pub const fn bottom() -> Self {
        Self::Bottom
    }

    /// A single concrete value.
    #[must_use] 
    pub const fn constant(v: i64) -> Self {
        Self::Bounded { lo: v, hi: v }
    }

    /// A bounded range.
    #[must_use] 
    pub const fn bounded(lo: i64, hi: i64) -> Self {
        if lo > hi {
            Self::Bottom
        } else {
            Self::Bounded { lo, hi }
        }
    }

    /// Widen `self` to contain `other`.  (Lattice join.)
    #[must_use] 
    pub fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, x) | (x, Self::Bottom) => x.clone(),
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Bounded { lo: l1, hi: h1 }, Self::Bounded { lo: l2, hi: h2 }) => {
                Self::bounded((*l1).min(*l2), (*h1).max(*h2))
            }
        }
    }

    /// Narrow `self` to the intersection with `other`.  (Lattice meet.)
    #[must_use] 
    pub fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Top, x) | (x, Self::Top) => x.clone(),
            (Self::Bounded { lo: l1, hi: h1 }, Self::Bounded { lo: l2, hi: h2 }) => {
                Self::bounded((*l1).max(*l2), (*h1).min(*h2))
            }
        }
    }

    /// True if this range is a single concrete value.
    #[must_use] 
    pub fn is_constant(&self) -> bool {
        matches!(self, Self::Bounded { lo, hi } if lo == hi)
    }

    /// Extract the constant value, if any.
    #[must_use] 
    pub fn constant_value(&self) -> Option<i64> {
        if let Self::Bounded { lo, hi } = self
            && lo == hi {
                return Some(*lo);
            }
        None
    }

    /// True if `v` is within the range.
    #[must_use] 
    pub const fn contains(&self, v: i64) -> bool {
        match self {
            Self::Top => true,
            Self::Bottom => false,
            Self::Bounded { lo, hi } => *lo <= v && v <= *hi,
        }
    }

    /// Width of the range (number of representable integers).
    #[must_use] 
    pub const fn width(&self) -> Option<u64> {
        match self {
            Self::Top | Self::Bottom => None,
            Self::Bounded { lo, hi } => {
                let w = hi.wrapping_sub(*lo) as u64 + 1;
                Some(w)
            }
        }
    }

    /// Arithmetic add with another range.
    #[must_use] 
    pub const fn add(&self, rhs: &Self) -> Self {
        match (self, rhs) {
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Bounded { lo: l1, hi: h1 }, Self::Bounded { lo: l2, hi: h2 }) => {
                Self::bounded(l1.saturating_add(*l2), h1.saturating_add(*h2))
            }
        }
    }
}

impl fmt::Display for ValueRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Top => write!(f, "⊤"),
            Self::Bottom => write!(f, "⊥"),
            Self::Bounded { lo, hi } if lo == hi => write!(f, "{lo}"),
            Self::Bounded { lo, hi } => write!(f, "[{lo}, {hi}]"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeobfConstraint — a single constraint relating variables / constants
// ─────────────────────────────────────────────────────────────────────────────

/// A constraint that can be propagated through the constraint graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeobfConstraint {
    /// Variable equals a concrete value.
    Equals { var: String, value: i64 },
    /// Variable is within a range.
    InRange { var: String, lo: i64, hi: i64 },
    /// Variable is not equal to a concrete value.
    NotEqual { var: String, value: i64 },
    /// Variable A equals variable B plus an offset.
    AffineEqual {
        lhs: String,
        rhs: String,
        offset: i64,
    },
    /// Variable is one of an enumerated set.
    OneOf { var: String, values: Vec<i64> },
    /// Variable is greater than another variable.
    GreaterThan { lhs: String, rhs: String },
    /// A boolean-valued variable must be true.
    MustBeTrue { var: String },
    /// A boolean-valued variable must be false.
    MustBeFalse { var: String },
}

impl DeobfConstraint {
    /// Return the primary variable affected by this constraint.
    #[must_use] 
    pub fn primary_var(&self) -> &str {
        match self {
            Self::AffineEqual { lhs, .. } | Self::GreaterThan { lhs, .. } => lhs,
            Self::Equals { var, .. } | Self::InRange { var, .. } | Self::NotEqual { var, .. } | Self::OneOf { var, .. } | Self::MustBeTrue { var } | Self::MustBeFalse { var } => var,
        }
    }

    /// Derive a [`ValueRange`] for the primary variable from this constraint,
    /// given the current environment.
    #[must_use] 
    pub fn derive_range(&self, env: &HashMap<String, ValueRange>) -> Option<ValueRange> {
        match self {
            Self::Equals { value, .. } => Some(ValueRange::constant(*value)),
            Self::InRange { lo, hi, .. } => Some(ValueRange::bounded(*lo, *hi)),
            Self::NotEqual { var, value } => {
                // Can only narrow if the variable is already bounded.
                if let Some(ValueRange::Bounded { lo, hi }) = env.get(var)
                    && *lo == *hi && lo == value {
                        return Some(ValueRange::Bottom); // contradiction
                    }
                None // not enough info to narrow
            }
            Self::OneOf { values, .. } => {
                let lo = values.iter().min().copied()?;
                let hi = values.iter().max().copied()?;
                Some(ValueRange::bounded(lo, hi))
            }
            Self::AffineEqual { rhs, offset, .. } => {
                let rhs_range = env.get(rhs)?;
                if let ValueRange::Bounded { lo, hi } = rhs_range {
                    Some(ValueRange::bounded(
                        lo.saturating_add(*offset),
                        hi.saturating_add(*offset),
                    ))
                } else {
                    None
                }
            }
            Self::MustBeTrue { .. } => Some(ValueRange::constant(1)),
            Self::MustBeFalse { .. } => Some(ValueRange::constant(0)),
            Self::GreaterThan { rhs, .. } => {
                let rhs_range = env.get(rhs)?;
                if let ValueRange::Bounded { hi, .. } = rhs_range {
                    Some(ValueRange::bounded(*hi + 1, i64::MAX))
                } else {
                    None
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintGraph — dependency graph over constraints
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks which constraints mention which variables so the solver can
/// propagate changes efficiently via a worklist.
#[derive(Debug, Default)]
pub struct ConstraintGraph {
    /// `var → set of constraint indices` that reference that variable.
    pub var_to_constraints: HashMap<String, HashSet<usize>>,
    pub constraints: Vec<DeobfConstraint>,
}

impl ConstraintGraph {
    /// Add a constraint and register its variable dependencies.
    pub fn add(&mut self, c: DeobfConstraint) -> usize {
        let idx = self.constraints.len();
        // Register primary variable.
        self.var_to_constraints
            .entry(c.primary_var().to_string())
            .or_default()
            .insert(idx);
        // Register secondary variables for affine / gt constraints.
        match &c {
            DeobfConstraint::AffineEqual { rhs, .. } | DeobfConstraint::GreaterThan { rhs, .. } => {
                self.var_to_constraints
                    .entry(rhs.clone())
                    .or_default()
                    .insert(idx);
            }
            _ => {}
        }
        self.constraints.push(c);
        idx
    }

    /// Return all constraint indices that depend on `var`.
    pub fn constraints_for(&self, var: &str) -> impl Iterator<Item = usize> + '_ {
        self.var_to_constraints
            .get(var)
            .map(|s| s.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.constraints.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PropagationResult — output of a solver run
// ─────────────────────────────────────────────────────────────────────────────

/// The result produced by [`ConstraintSolver::solve`].
#[derive(Debug, Default)]
pub struct PropagationResult {
    /// Final value ranges for each variable.
    pub ranges: HashMap<String, ValueRange>,
    /// Variables whose range collapsed to `Bottom` (contradictions).
    pub contradictions: Vec<String>,
    /// Number of propagation iterations performed.
    pub iterations: usize,
    /// Whether the solver reached a fixpoint.
    pub converged: bool,
    /// Variables that became concrete constants.
    pub constants_found: HashMap<String, i64>,
}

impl PropagationResult {
    /// True if no contradictions were found.
    #[must_use] 
    pub const fn is_consistent(&self) -> bool {
        self.contradictions.is_empty()
    }

    /// Look up the range for a variable (returns `Top` if unknown).
    #[must_use] 
    pub fn range_of(&self, var: &str) -> &ValueRange {
        self.ranges.get(var).unwrap_or(&ValueRange::Top)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintSolver — worklist-based propagation
// ─────────────────────────────────────────────────────────────────────────────

/// Worklist-based constraint propagation solver.
///
/// The solver maintains a map `var → ValueRange` and iterates until either a
/// fixpoint is reached or the maximum iteration count is exceeded.
pub struct ConstraintSolver {
    /// Maximum number of worklist iterations.
    pub max_iterations: usize,
}

impl Default for ConstraintSolver {
    fn default() -> Self {
        Self {
            max_iterations: 256,
        }
    }
}

impl ConstraintSolver {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub const fn with_max_iterations(n: usize) -> Self {
        Self { max_iterations: n }
    }

    /// Run propagation on `graph`.
    ///
    /// Initial ranges can be supplied via `initial`; any variable not present
    /// starts as `Top`.
    #[must_use] 
    pub fn solve(
        &self,
        graph: &ConstraintGraph,
        initial: HashMap<String, ValueRange>,
    ) -> PropagationResult {
        let mut env: HashMap<String, ValueRange> = initial;
        let mut result = PropagationResult::default();

        // Initialise worklist with all constraint indices.
        let mut worklist: VecDeque<usize> = (0..graph.constraints.len()).collect();
        let mut in_list: HashSet<usize> = worklist.iter().copied().collect();

        while let Some(idx) = worklist.pop_front() {
            in_list.remove(&idx);
            result.iterations += 1;
            if result.iterations > self.max_iterations {
                break;
            }

            let c = &graph.constraints[idx];
            let var = c.primary_var().to_string();
            let derived = c.derive_range(&env);

            if let Some(new_range) = derived {
                let old = env.entry(var.clone()).or_insert(ValueRange::Top).clone();
                let narrowed = old.meet(&new_range);
                if narrowed != old {
                    env.insert(var.clone(), narrowed);
                    // Re-enqueue all constraints that depend on this variable.
                    for dep_idx in graph.constraints_for(&var) {
                        if in_list.insert(dep_idx) {
                            worklist.push_back(dep_idx);
                        }
                    }
                }
            }
        }

        // Collect results.
        result.converged = result.iterations <= self.max_iterations;
        for (var, range) in &env {
            if range == &ValueRange::Bottom {
                result.contradictions.push(var.clone());
            }
            if let Some(v) = range.constant_value() {
                result.constants_found.insert(var.clone(), v);
            }
        }
        result.ranges = env;
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstraintPropagation — façade
// ─────────────────────────────────────────────────────────────────────────────

/// High-level façade that wraps graph construction + solving in one call.
pub struct ConstraintPropagation {
    pub solver: ConstraintSolver,
}

impl Default for ConstraintPropagation {
    fn default() -> Self {
        Self {
            solver: ConstraintSolver::new(),
        }
    }
}

impl ConstraintPropagation {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add constraints and solve in one step.
    #[must_use] 
    pub fn propagate(
        &self,
        constraints: Vec<DeobfConstraint>,
        initial: HashMap<String, ValueRange>,
    ) -> PropagationResult {
        let mut graph = ConstraintGraph::default();
        for c in constraints {
            graph.add(c);
        }
        self.solver.solve(&graph, initial)
    }

    /// Convenience: propagate a single equality.
    #[must_use] 
    pub fn propagate_equality(&self, var: &str, value: i64) -> PropagationResult {
        self.propagate(
            vec![DeobfConstraint::Equals {
                var: var.to_string(),
                value,
            }],
            HashMap::new(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ValueRange ────────────────────────────────────────────────────────────

    #[test]
    fn vr_constant_is_constant() {
        let r = ValueRange::constant(42);
        assert!(r.is_constant());
        assert_eq!(r.constant_value(), Some(42));
    }

    #[test]
    fn vr_top_is_not_constant() {
        assert!(!ValueRange::Top.is_constant());
    }

    #[test]
    fn vr_bottom_is_not_constant() {
        assert!(!ValueRange::Bottom.is_constant());
    }

    #[test]
    fn vr_bounded_invalid_is_bottom() {
        let r = ValueRange::bounded(10, 5);
        assert_eq!(r, ValueRange::Bottom);
    }

    #[test]
    fn vr_join_two_bounded() {
        let a = ValueRange::bounded(0, 5);
        let b = ValueRange::bounded(3, 10);
        let j = a.join(&b);
        assert_eq!(j, ValueRange::bounded(0, 10));
    }

    #[test]
    fn vr_join_with_bottom() {
        let a = ValueRange::bounded(0, 5);
        let j = a.join(&ValueRange::Bottom);
        assert_eq!(j, a);
    }

    #[test]
    fn vr_meet_two_bounded() {
        let a = ValueRange::bounded(0, 10);
        let b = ValueRange::bounded(5, 15);
        let m = a.meet(&b);
        assert_eq!(m, ValueRange::bounded(5, 10));
    }

    #[test]
    fn vr_meet_non_overlapping() {
        let a = ValueRange::bounded(0, 5);
        let b = ValueRange::bounded(10, 20);
        let m = a.meet(&b);
        assert_eq!(m, ValueRange::Bottom);
    }

    #[test]
    fn vr_meet_with_top() {
        let a = ValueRange::bounded(1, 9);
        let m = a.meet(&ValueRange::Top);
        assert_eq!(m, a);
    }

    #[test]
    fn vr_contains_true() {
        let r = ValueRange::bounded(0, 10);
        assert!(r.contains(5));
    }

    #[test]
    fn vr_contains_false() {
        let r = ValueRange::bounded(0, 10);
        assert!(!r.contains(11));
    }

    #[test]
    fn vr_width() {
        let r = ValueRange::bounded(0, 9);
        assert_eq!(r.width(), Some(10));
    }

    #[test]
    fn vr_width_constant() {
        let r = ValueRange::constant(7);
        assert_eq!(r.width(), Some(1));
    }

    #[test]
    fn vr_add_bounded() {
        let a = ValueRange::bounded(1, 3);
        let b = ValueRange::bounded(10, 20);
        let s = a.add(&b);
        assert_eq!(s, ValueRange::bounded(11, 23));
    }

    #[test]
    fn vr_display_top() {
        assert_eq!(ValueRange::Top.to_string(), "⊤");
    }

    #[test]
    fn vr_display_bottom() {
        assert_eq!(ValueRange::Bottom.to_string(), "⊥");
    }

    #[test]
    fn vr_display_constant() {
        assert_eq!(ValueRange::constant(42).to_string(), "42");
    }

    #[test]
    fn vr_display_range() {
        assert_eq!(ValueRange::bounded(1, 5).to_string(), "[1, 5]");
    }

    // ── DeobfConstraint ───────────────────────────────────────────────────────

    #[test]
    fn constraint_equals_primary_var() {
        let c = DeobfConstraint::Equals {
            var: "x".into(),
            value: 5,
        };
        assert_eq!(c.primary_var(), "x");
    }

    #[test]
    fn constraint_equals_derive() {
        let c = DeobfConstraint::Equals {
            var: "x".into(),
            value: 7,
        };
        let r = c.derive_range(&HashMap::new()).unwrap();
        assert_eq!(r.constant_value(), Some(7));
    }

    #[test]
    fn constraint_in_range_derive() {
        let c = DeobfConstraint::InRange {
            var: "x".into(),
            lo: 1,
            hi: 9,
        };
        let r = c.derive_range(&HashMap::new()).unwrap();
        assert_eq!(r, ValueRange::bounded(1, 9));
    }

    #[test]
    fn constraint_one_of_derives_range() {
        let c = DeobfConstraint::OneOf {
            var: "x".into(),
            values: vec![3, 7, 15],
        };
        let r = c.derive_range(&HashMap::new()).unwrap();
        assert_eq!(r, ValueRange::bounded(3, 15));
    }

    #[test]
    fn constraint_must_be_true() {
        let c = DeobfConstraint::MustBeTrue { var: "flag".into() };
        let r = c.derive_range(&HashMap::new()).unwrap();
        assert_eq!(r.constant_value(), Some(1));
    }

    #[test]
    fn constraint_must_be_false() {
        let c = DeobfConstraint::MustBeFalse { var: "flag".into() };
        let r = c.derive_range(&HashMap::new()).unwrap();
        assert_eq!(r.constant_value(), Some(0));
    }

    #[test]
    fn constraint_affine_equal_derive() {
        let c = DeobfConstraint::AffineEqual {
            lhs: "y".into(),
            rhs: "x".into(),
            offset: 5,
        };
        let mut env = HashMap::new();
        env.insert("x".to_string(), ValueRange::constant(10));
        let r = c.derive_range(&env).unwrap();
        assert_eq!(r.constant_value(), Some(15));
    }

    #[test]
    fn constraint_greater_than_derive() {
        let c = DeobfConstraint::GreaterThan {
            lhs: "y".into(),
            rhs: "x".into(),
        };
        let mut env = HashMap::new();
        env.insert("x".to_string(), ValueRange::constant(5));
        let r = c.derive_range(&env).unwrap();
        if let ValueRange::Bounded { lo, .. } = r {
            assert_eq!(lo, 6);
        } else {
            panic!("expected bounded range");
        }
    }

    // ── ConstraintGraph ───────────────────────────────────────────────────────

    #[test]
    fn graph_add_and_len() {
        let mut g = ConstraintGraph::default();
        g.add(DeobfConstraint::Equals {
            var: "x".into(),
            value: 1,
        });
        g.add(DeobfConstraint::InRange {
            var: "y".into(),
            lo: 0,
            hi: 10,
        });
        assert_eq!(g.len(), 2);
    }

    #[test]
    fn graph_constraints_for_variable() {
        let mut g = ConstraintGraph::default();
        g.add(DeobfConstraint::Equals {
            var: "x".into(),
            value: 1,
        });
        g.add(DeobfConstraint::Equals {
            var: "x".into(),
            value: 2,
        });
        
        assert_eq!(g.constraints_for("x").count(), 2);
    }

    #[test]
    fn graph_empty_initially() {
        let g = ConstraintGraph::default();
        assert!(g.is_empty());
    }

    // ── ConstraintSolver ─────────────────────────────────────────────────────

    #[test]
    fn solver_equality_propagates() {
        let solver = ConstraintSolver::new();
        let mut g = ConstraintGraph::default();
        g.add(DeobfConstraint::Equals {
            var: "x".into(),
            value: 42,
        });
        let r = solver.solve(&g, HashMap::new());
        assert_eq!(r.range_of("x").constant_value(), Some(42));
    }

    #[test]
    fn solver_constants_found() {
        let solver = ConstraintSolver::new();
        let mut g = ConstraintGraph::default();
        g.add(DeobfConstraint::Equals {
            var: "a".into(),
            value: 7,
        });
        let r = solver.solve(&g, HashMap::new());
        assert_eq!(r.constants_found.get("a"), Some(&7));
    }

    #[test]
    fn solver_contradiction_detected() {
        let solver = ConstraintSolver::new();
        let mut g = ConstraintGraph::default();
        // x in [10, 20] AND x in [30, 40] → contradiction.
        g.add(DeobfConstraint::InRange {
            var: "x".into(),
            lo: 10,
            hi: 20,
        });
        g.add(DeobfConstraint::InRange {
            var: "x".into(),
            lo: 30,
            hi: 40,
        });
        let r = solver.solve(&g, HashMap::new());
        // Either contradiction detected or range collapses.
        let xr = r.range_of("x");
        assert!(
            xr == &ValueRange::Bottom || !r.is_consistent(),
            "expected contradiction for non-overlapping ranges"
        );
    }

    #[test]
    fn solver_converged() {
        let solver = ConstraintSolver::new();
        let mut g = ConstraintGraph::default();
        g.add(DeobfConstraint::Equals {
            var: "z".into(),
            value: 0,
        });
        let r = solver.solve(&g, HashMap::new());
        assert!(r.converged);
    }

    // ── ConstraintPropagation ─────────────────────────────────────────────────

    #[test]
    fn cp_propagate_equality() {
        let cp = ConstraintPropagation::new();
        let r = cp.propagate_equality("v", 99);
        assert_eq!(r.range_of("v").constant_value(), Some(99));
    }

    #[test]
    fn cp_propagate_consistent() {
        let cp = ConstraintPropagation::new();
        let r = cp.propagate(
            vec![DeobfConstraint::InRange {
                var: "x".into(),
                lo: 0,
                hi: 100,
            }],
            HashMap::new(),
        );
        assert!(r.is_consistent());
    }

    #[test]
    fn cp_propagate_multiple() {
        let cp = ConstraintPropagation::new();
        let r = cp.propagate(
            vec![
                DeobfConstraint::InRange {
                    var: "x".into(),
                    lo: 0,
                    hi: 50,
                },
                DeobfConstraint::InRange {
                    var: "x".into(),
                    lo: 25,
                    hi: 100,
                },
            ],
            HashMap::new(),
        );
        // Intersection: [25, 50]
        assert_eq!(*r.range_of("x"), ValueRange::bounded(25, 50));
    }

    #[test]
    fn cp_initial_values_respected() {
        let cp = ConstraintPropagation::new();
        let mut initial = HashMap::new();
        initial.insert("y".to_string(), ValueRange::constant(10));
        let r = cp.propagate(vec![], initial);
        assert_eq!(r.range_of("y").constant_value(), Some(10));
    }
}
