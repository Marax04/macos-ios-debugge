//! Constraint solver: `ConstraintSolver`, `Constraint`, `SolveResult`,
//! `is_feasible()`.
//!
//! Provides a pure-Rust, zero-external-dependency constraint solver that
//! works on the symbolic value types defined in [`crate::symbolic_value`].
//! The solver supports:
//! - Constant-folding based satisfiability checks.
//! - Interval-domain propagation for bitvector constraints.
//! - Unit propagation for boolean clauses.
//! - A simple DPLL-style search with backtracking.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::symbolic_value::{SymbolicValue, ValueKind, ValueWidth};

// ── Constraint ────────────────────────────────────────────────────────────────

/// A single constraint asserting that `expr` must hold (i.e. evaluate to
/// a non-zero value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    /// The boolean-typed symbolic expression that must be true.
    pub expr: SymbolicValue,
    /// Optional human-readable label for debugging.
    pub label: Option<String>,
    /// Whether this is a hard constraint (vs. a soft optimisation hint).
    pub hard: bool,
}

impl Constraint {
    /// Build a hard constraint with no label.
    #[must_use]
    pub const fn hard(expr: SymbolicValue) -> Self {
        Self { expr, label: None, hard: true }
    }

    /// Build a hard constraint with a label.
    #[must_use]
    pub fn hard_labeled(expr: SymbolicValue, label: impl Into<String>) -> Self {
        Self { expr, label: Some(label.into()), hard: true }
    }

    /// Build a soft constraint.
    #[must_use]
    pub const fn soft(expr: SymbolicValue) -> Self {
        Self { expr, label: None, hard: false }
    }

    /// Return `true` if this constraint is trivially satisfied.
    #[must_use]
    pub const fn is_trivially_true(&self) -> bool {
        matches!(self.expr.as_concrete(), Some(v) if v != 0)
    }

    /// Return `true` if this constraint is trivially unsatisfiable.
    #[must_use]
    pub const fn is_trivially_false(&self) -> bool {
        matches!(self.expr.as_concrete(), Some(0))
    }
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(lbl) = &self.label {
            write!(f, "[{lbl}] {}", self.expr)
        } else {
            write!(f, "{}", self.expr)
        }
    }
}

// ── SolveResult ───────────────────────────────────────────────────────────────

/// The outcome of a solver query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SolveResult {
    /// All constraints are satisfiable; the model maps variable IDs to concrete
    /// values.
    Sat(HashMap<u64, u64>),
    /// The constraint set is unsatisfiable.
    Unsat,
    /// The solver timed out or hit a resource limit.
    Unknown(String),
}

impl SolveResult {
    #[must_use]
    pub const fn is_sat(&self) -> bool {
        matches!(self, Self::Sat(_))
    }

    #[must_use]
    pub const fn is_unsat(&self) -> bool {
        matches!(self, Self::Unsat)
    }

    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown(_))
    }

    /// Return the model if this is SAT.
    #[must_use]
    pub const fn model(&self) -> Option<&HashMap<u64, u64>> {
        match self {
            Self::Sat(m) => Some(m),
            _ => None,
        }
    }
}

impl fmt::Display for SolveResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sat(m) => write!(f, "SAT (model size: {})", m.len()),
            Self::Unsat => write!(f, "UNSAT"),
            Self::Unknown(r) => write!(f, "UNKNOWN: {r}"),
        }
    }
}

// ── Interval domain ───────────────────────────────────────────────────────────

/// A bitvector interval `[lo, hi]` (unsigned).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Interval {
    lo: u64,
    hi: u64,
    width: ValueWidth,
}

impl Interval {
    const fn full(width: ValueWidth) -> Self {
        Self { lo: 0, hi: width.mask64(), width }
    }

    const fn point(v: u64, width: ValueWidth) -> Self {
        let v = v & width.mask64();
        Self { lo: v, hi: v, width }
    }

    const fn is_empty(&self) -> bool {
        self.lo > self.hi
    }

    const fn is_singleton(&self) -> bool {
        self.lo == self.hi
    }

    fn intersect(&self, other: &Self) -> Self {
        Self {
            lo: self.lo.max(other.lo),
            hi: self.hi.min(other.hi),
            width: self.width,
        }
    }

    const fn add(&self, rhs: &Self) -> Self {
        let mask = self.width.mask64();
        Self {
            lo: self.lo.wrapping_add(rhs.lo) & mask,
            hi: self.hi.wrapping_add(rhs.hi) & mask,
            width: self.width,
        }
    }

    fn and(&self, rhs: &Self) -> Self {
        // Conservative: result is bounded by the smaller of hi values.
        Self {
            lo: 0,
            hi: self.hi.min(rhs.hi),
            width: self.width,
        }
    }
}

// ── ConstraintSolver ──────────────────────────────────────────────────────────

/// Solver configuration.
#[derive(Debug, Clone)]
pub struct SolverConfig {
    /// Maximum number of backtracking steps (DPLL search limit).
    pub max_backtracks: u32,
    /// Maximum recursion depth in expression evaluation.
    pub max_eval_depth: u32,
    /// Whether to apply interval propagation.
    pub use_intervals: bool,
    /// Whether to try DPLL-style splitting.
    pub use_dpll: bool,
}

impl Default for SolverConfig {
    fn default() -> Self {
        Self {
            max_backtracks: 1024,
            max_eval_depth: 64,
            use_intervals: true,
            use_dpll: true,
        }
    }
}

/// Lightweight constraint solver for symbolic bitvector constraints.
///
/// The solver operates in three phases:
/// 1. **Constant folding**: trivially true/false constraints are removed.
/// 2. **Interval propagation**: each variable's domain is narrowed.
/// 3. **DPLL search**: variables are assigned concrete values and
///    constraints are checked.
pub struct ConstraintSolver {
    config: SolverConfig,
    /// The accumulated constraint set.
    constraints: Vec<Constraint>,
    /// Statistics.
    stats: SolverStats,
}

#[derive(Debug, Default, Clone)]
pub struct SolverStats {
    pub solve_calls: u64,
    pub sat_results: u64,
    pub unsat_results: u64,
    pub unknown_results: u64,
    pub backtracks: u64,
    pub propagation_steps: u64,
}

impl ConstraintSolver {
    /// Create a new solver with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: SolverConfig::default(),
            constraints: Vec::new(),
            stats: SolverStats::default(),
        }
    }

    /// Create a solver with custom configuration.
    #[must_use]
    pub fn with_config(config: SolverConfig) -> Self {
        Self {
            config,
            constraints: Vec::new(),
            stats: SolverStats::default(),
        }
    }

    // ── Constraint management ────────────────────────────────────────────────

    /// Add a constraint.
    pub fn add(&mut self, c: Constraint) {
        self.constraints.push(c);
    }

    /// Add a raw expression as a hard constraint.
    pub fn assert(&mut self, expr: SymbolicValue) {
        self.add(Constraint::hard(expr));
    }

    /// Add a raw expression as a hard constraint with a label.
    pub fn assert_labeled(&mut self, expr: SymbolicValue, label: impl Into<String>) {
        self.add(Constraint::hard_labeled(expr, label));
    }

    /// Remove all constraints.
    pub fn reset(&mut self) {
        self.constraints.clear();
    }

    /// Return the number of constraints.
    #[must_use]
    pub const fn constraint_count(&self) -> usize {
        self.constraints.len()
    }

    /// Return a reference to the current stats.
    #[must_use]
    pub const fn stats(&self) -> &SolverStats {
        &self.stats
    }

    // ── Quick feasibility check ──────────────────────────────────────────────

    /// Check whether the current constraint set is feasible, returning `true`
    /// if SAT and `false` if UNSAT.
    ///
    /// This is a convenience wrapper around [`ConstraintSolver::solve`].
    #[must_use]
    pub fn is_feasible(&mut self) -> bool {
        self.solve().is_sat()
    }

    // ── Main solve entry point ───────────────────────────────────────────────

    /// Attempt to solve the current constraint set.
    ///
    /// Returns a [`SolveResult`] indicating satisfiability and, on SAT, a
    /// witness model mapping variable IDs to concrete values.
    pub fn solve(&mut self) -> SolveResult {
        self.stats.solve_calls += 1;

        // Phase 1: constant folding — check for trivially UNSAT constraints.
        for c in &self.constraints {
            if c.hard && c.is_trivially_false() {
                self.stats.unsat_results += 1;
                return SolveResult::Unsat;
            }
        }

        // Phase 2: collect all symbolic variables.
        let mut var_ids: HashMap<u64, ValueWidth> = HashMap::new();
        for c in &self.constraints {
            collect_vars_with_width(&c.expr, &mut var_ids);
        }

        if var_ids.is_empty() {
            // All constraints are concrete — must all be non-zero to be SAT.
            let all_true = self.constraints.iter().all(|c| {
                !c.hard || !c.is_trivially_false()
            });
            if all_true {
                self.stats.sat_results += 1;
                return SolveResult::Sat(HashMap::new());
            }
            self.stats.unsat_results += 1;
            return SolveResult::Unsat;
        }

        // Phase 3: interval propagation to narrow variable domains.
        let mut domains: HashMap<u64, Interval> = var_ids
            .iter()
            .map(|(&id, &w)| (id, Interval::full(w)))
            .collect();

        if self.config.use_intervals {
            self.propagate_intervals(&mut domains);
        }

        // Check if any domain is empty (UNSAT).
        for iv in domains.values() {
            if iv.is_empty() {
                self.stats.unsat_results += 1;
                return SolveResult::Unsat;
            }
        }

        // Phase 4: if all domains are singletons, we have a model.
        if domains.values().all(Interval::is_singleton) {
            let model: HashMap<u64, u64> = domains.iter().map(|(&id, iv)| (id, iv.lo)).collect();
            if self.check_model(&model) {
                self.stats.sat_results += 1;
                return SolveResult::Sat(model);
            }
            self.stats.unsat_results += 1;
            return SolveResult::Unsat;
        }

        // Phase 5: DPLL-style search.
        if self.config.use_dpll {
            let var_list: Vec<(u64, ValueWidth)> = var_ids.into_iter().collect();
            let mut backtracks = 0u32;
            let result = self.dpll_search(
                &var_list,
                0,
                &mut HashMap::new(),
                &domains,
                &mut backtracks,
            );
            if let Some(model) = result {
                self.stats.sat_results += 1;
                SolveResult::Sat(model)
            } else {
                self.stats.unsat_results += 1;
                SolveResult::Unsat
            }
        } else {
            // No DPLL — try the midpoint of each domain as a witness.
            let model: HashMap<u64, u64> = domains
                .iter()
                .map(|(&id, iv)| (id, iv.lo + (iv.hi - iv.lo) / 2))
                .collect();
            if self.check_model(&model) {
                self.stats.sat_results += 1;
                SolveResult::Sat(model)
            } else {
                self.stats.unknown_results += 1;
                SolveResult::Unknown("incomplete search without DPLL".into())
            }
        }
    }

    // ── Interval propagation ─────────────────────────────────────────────────

    fn propagate_intervals(&mut self, domains: &mut HashMap<u64, Interval>) {
        // Iterate to a fixed point (up to 16 rounds).
        for _ in 0..16 {
            let mut changed = false;
            for c in &self.constraints {
                if !c.hard {
                    continue;
                }
                if self.narrow_from_constraint(&c.expr, domains) {
                    changed = true;
                    self.stats.propagation_steps += 1;
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// Attempt to narrow variable domains from a single constraint expression.
    /// Returns `true` if any domain changed.
    fn narrow_from_constraint(
        &self,
        expr: &SymbolicValue,
        domains: &mut HashMap<u64, Interval>,
    ) -> bool {
        match &expr.kind {
            // expr is an equality: lhs == rhs
            ValueKind::Eq(lhs, rhs) => {
                if let ValueKind::Symbolic { id, .. } = &lhs.kind
                    && let ValueKind::Concrete(v) = &rhs.kind {
                        let new_iv = Interval::point(*v, lhs.width);
                        if let Some(iv) = domains.get_mut(id) {
                            let narrowed = iv.intersect(&new_iv);
                            if narrowed != *iv {
                                *iv = narrowed;
                                return true;
                            }
                        }
                    }
                if let ValueKind::Symbolic { id, .. } = &rhs.kind
                    && let ValueKind::Concrete(v) = &lhs.kind {
                        let new_iv = Interval::point(*v, rhs.width);
                        if let Some(iv) = domains.get_mut(id) {
                            let narrowed = iv.intersect(&new_iv);
                            if narrowed != *iv {
                                *iv = narrowed;
                                return true;
                            }
                        }
                    }
                false
            }
            // Recurse into AND-like conjunctions.
            ValueKind::And(l, r) => {
                let cl = self.narrow_from_constraint(l, domains);
                let cr = self.narrow_from_constraint(r, domains);
                // Also fuse the two sub-intervals via the bitwise-AND domain
                // operator so that constraints like `(x & mask) == k` tighten
                // the upper bound of `x` even when the conjunction's sides
                // do not individually mention `x` as Eq.
                let fused = if let (
                    ValueKind::Symbolic { id: lid, .. },
                    ValueKind::Symbolic { id: rid, .. },
                ) = (&l.kind, &r.kind)
                {
                    if lid == rid {
                        if let (Some(li), Some(ri)) =
                            (domains.get(lid).cloned(), domains.get(rid).cloned())
                        {
                            let combined = li.and(&ri);
                            if let Some(iv) = domains.get_mut(lid) {
                                let new_iv = iv.intersect(&combined);
                                if new_iv == *iv {
                                    false
                                } else {
                                    *iv = new_iv;
                                    true
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };
                cl || cr || fused
            }
            // Equality with an Add(symbolic, concrete) on one side:
            // tighten the symbolic operand's interval via the inverse of the
            // interval-add domain operator.
            ValueKind::ULt(lhs, rhs) => {
                let mut changed = false;
                if let ValueKind::Add(a, b) = &lhs.kind
                    && let (ValueKind::Symbolic { id, .. }, ValueKind::Concrete(c)) =
                        (&a.kind, &b.kind)
                        && let ValueKind::Concrete(upper) = &rhs.kind
                            && let Some(iv) = domains.get_mut(id) {
                                let shift = Interval::point(*c, a.width);
                                let shifted = iv.add(&shift);
                                if shifted.hi >= *upper {
                                    let new_hi = upper.saturating_sub(c.saturating_add(1));
                                    if iv.hi > new_hi {
                                        iv.hi = new_hi;
                                        changed = true;
                                    }
                                }
                            }
                if !changed {
                    if let ValueKind::Symbolic { id, .. } = &lhs.kind
                        && let ValueKind::Concrete(upper) = &rhs.kind
                            && let Some(iv) = domains.get_mut(id)
                                && iv.hi >= *upper {
                                    iv.hi = upper.saturating_sub(1);
                                    changed = true;
                                }
                    if let ValueKind::Symbolic { id, .. } = &rhs.kind
                        && let ValueKind::Concrete(lower) = &lhs.kind
                            && let Some(iv) = domains.get_mut(id) {
                                let min_rhs = lower + 1;
                                if iv.lo < min_rhs {
                                    iv.lo = min_rhs;
                                    changed = true;
                                }
                            }
                }
                changed
            }
            _ => false,
        }
    }

    // ── DPLL search ──────────────────────────────────────────────────────────

    fn dpll_search(
        &mut self,
        vars: &[(u64, ValueWidth)],
        idx: usize,
        assignment: &mut HashMap<u64, u64>,
        domains: &HashMap<u64, Interval>,
        backtracks: &mut u32,
    ) -> Option<HashMap<u64, u64>> {
        if idx == vars.len() {
            if self.check_model(assignment) {
                return Some(assignment.clone());
            }
            *backtracks += 1;
            self.stats.backtracks += 1;
            return None;
        }
        if *backtracks >= self.config.max_backtracks {
            return None;
        }
        let (id, width) = vars[idx];
        let iv = domains.get(&id).cloned().unwrap_or_else(|| Interval::full(width));
        // Try lo, hi, and midpoint as candidate values.
        let mid = iv.lo + (iv.hi - iv.lo) / 2;
        let candidates = if iv.is_singleton() {
            vec![iv.lo]
        } else {
            let mut cands = vec![iv.lo, mid, iv.hi];
            cands.dedup();
            cands
        };

        for candidate in candidates {
            assignment.insert(id, candidate);
            // Quick feasibility check for just the assigned vars.
            let prefix_ok = self.constraints.iter().all(|c| {
                if !c.hard {
                    return true;
                }
                match c.expr.evaluate(assignment) {
                    Some(0) => false,
                    _ => true, // undetermined (symbolic) or non-zero
                }
            });
            if prefix_ok
                && let Some(model) = self.dpll_search(vars, idx + 1, assignment, domains, backtracks) {
                    return Some(model);
                }
            assignment.remove(&id);
            *backtracks += 1;
            self.stats.backtracks += 1;
            if *backtracks >= self.config.max_backtracks {
                return None;
            }
        }
        None
    }

    // ── Model checking ───────────────────────────────────────────────────────

    /// Check whether `model` satisfies all hard constraints.
    fn check_model(&self, model: &HashMap<u64, u64>) -> bool {
        for c in &self.constraints {
            if !c.hard {
                continue;
            }
            match c.expr.evaluate(model) {
                Some(0) => return false,
                Some(_) => {}
                None => {
                    // Cannot evaluate — treat as unknown (optimistic).
                }
            }
        }
        true
    }

    // ── Incremental helpers ──────────────────────────────────────────────────

    /// Push a new constraint and check feasibility incrementally.
    pub fn push_and_check(&mut self, c: Constraint) -> SolveResult {
        // Fast-path: if the constraint is trivially false, bail out immediately.
        if c.hard && c.is_trivially_false() {
            self.stats.solve_calls += 1;
            self.stats.unsat_results += 1;
            return SolveResult::Unsat;
        }
        self.constraints.push(c);
        self.solve()
    }

    /// Return the subset of constraints that cannot be satisfied together.
    ///
    /// Uses a naive greedy minimisation: add constraints one by one, removing
    /// any that make the set satisfiable when excluded.
    #[must_use]
    pub fn minimal_unsat_core(&mut self) -> Vec<Constraint> {
        // Quick check: is the full set UNSAT?
        if self.solve().is_sat() {
            return vec![];
        }

        let all = self.constraints.clone();
        let mut core: Vec<Constraint> = Vec::new();

        for c in &all {
            self.constraints = core.clone();
            self.constraints.push(c.clone());
            if self.solve().is_unsat() {
                core.push(c.clone());
            }
        }
        self.constraints = all;
        core
    }
}

impl Default for ConstraintSolver {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ConstraintSolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConstraintSolver")
            .field("constraints", &self.constraints.len())
            .field("stats", &self.stats)
            .finish()
    }
}

// ── Free functions ─────────────────────────────────────────────────────────────

/// Check whether a set of symbolic expressions is simultaneously satisfiable.
///
/// This is a convenience function that creates a one-shot solver, adds all
/// expressions as hard constraints, and returns the feasibility result.
#[must_use]
pub fn is_feasible(constraints: &[SymbolicValue]) -> bool {
    let mut solver = ConstraintSolver::new();
    for c in constraints {
        solver.assert(c.clone());
    }
    solver.is_feasible()
}

/// Solve a set of constraints and return the result.
#[must_use] 
pub fn solve_constraints(constraints: Vec<Constraint>) -> SolveResult {
    let mut solver = ConstraintSolver::new();
    for c in constraints {
        solver.add(c);
    }
    solver.solve()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn collect_vars_with_width(expr: &SymbolicValue, out: &mut HashMap<u64, ValueWidth>) {
    match &expr.kind {
        ValueKind::Symbolic { id, .. } => {
            out.entry(*id).or_insert(expr.width);
        }
        ValueKind::Concrete(_) => {}
        ValueKind::Add(l, r)
        | ValueKind::Sub(l, r)
        | ValueKind::Mul(l, r)
        | ValueKind::UDiv(l, r)
        | ValueKind::And(l, r)
        | ValueKind::Or(l, r)
        | ValueKind::Xor(l, r)
        | ValueKind::Shl(l, r)
        | ValueKind::Shr(l, r)
        | ValueKind::Eq(l, r)
        | ValueKind::ULt(l, r)
        | ValueKind::SLt(l, r) => {
            collect_vars_with_width(l, out);
            collect_vars_with_width(r, out);
        }
        ValueKind::Not(e)
        | ValueKind::ZExt { inner: e, .. }
        | ValueKind::SExt { inner: e, .. }
        | ValueKind::Extract { inner: e, .. }
        | ValueKind::Load { addr: e, .. } => {
            collect_vars_with_width(e, out);
        }
        ValueKind::Ite { cond, then_val, else_val } => {
            collect_vars_with_width(cond, out);
            collect_vars_with_width(then_val, out);
            collect_vars_with_width(else_val, out);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbolic_value::{SymbolicValue, ValueWidth};

    fn var(id: u64, name: &str) -> SymbolicValue {
        SymbolicValue::var_with_id(id, name, ValueWidth::W32)
    }

    fn const32(v: u64) -> SymbolicValue {
        SymbolicValue::constant(v, ValueWidth::W32)
    }

    #[test]
    fn test_trivially_true_constraint() {
        let c = Constraint::hard(SymbolicValue::constant(1, ValueWidth::W1));
        assert!(c.is_trivially_true());
        assert!(!c.is_trivially_false());
    }

    #[test]
    fn test_trivially_false_constraint() {
        let c = Constraint::hard(SymbolicValue::constant(0, ValueWidth::W1));
        assert!(c.is_trivially_false());
    }

    #[test]
    fn test_unsat_trivially_false() {
        let mut solver = ConstraintSolver::new();
        solver.assert(SymbolicValue::constant(0, ValueWidth::W1));
        assert!(solver.solve().is_unsat());
    }

    #[test]
    fn test_sat_trivially_true() {
        let mut solver = ConstraintSolver::new();
        solver.assert(SymbolicValue::constant(1, ValueWidth::W1));
        let result = solver.solve();
        assert!(result.is_sat());
    }

    #[test]
    fn test_sat_one_var() {
        // x == 42  should be SAT with x = 42
        let x = var(1, "x");
        let forty_two = const32(42);
        let eq = x.eq_cmp(forty_two);
        let result = solve_constraints(vec![Constraint::hard(eq)]);
        assert!(result.is_sat());
        if let SolveResult::Sat(m) = result {
            assert_eq!(m.get(&1), Some(&42));
        }
    }

    #[test]
    fn test_sat_two_vars() {
        // x == 10 AND y == 20
        let x = var(10, "x");
        let y = var(20, "y");
        let c1 = Constraint::hard(x.clone().eq_cmp(const32(10)));
        let c2 = Constraint::hard(y.clone().eq_cmp(const32(20)));
        let result = solve_constraints(vec![c1, c2]);
        assert!(result.is_sat());
    }

    #[test]
    fn test_unsat_contradiction() {
        // x == 5 AND x == 6 — contradiction
        let x1 = var(1, "x");
        let x2 = var(1, "x");
        let c1 = Constraint::hard(x1.eq_cmp(const32(5)));
        let c2 = Constraint::hard(x2.eq_cmp(const32(6)));
        let result = solve_constraints(vec![c1, c2]);
        assert!(result.is_unsat());
    }

    #[test]
    fn test_is_feasible_sat() {
        let x = var(1, "x");
        let expr = x.eq_cmp(const32(100));
        assert!(is_feasible(&[expr]));
    }

    #[test]
    fn test_is_feasible_unsat() {
        let expr = SymbolicValue::constant(0, ValueWidth::W1);
        assert!(!is_feasible(&[expr]));
    }

    #[test]
    fn test_solver_stats() {
        let mut s = ConstraintSolver::new();
        s.assert(SymbolicValue::constant(1, ValueWidth::W1));
        s.solve();
        assert_eq!(s.stats().solve_calls, 1);
    }

    #[test]
    fn test_push_and_check_trivially_false() {
        let mut s = ConstraintSolver::new();
        let r = s.push_and_check(Constraint::hard(SymbolicValue::constant(0, ValueWidth::W1)));
        assert!(r.is_unsat());
    }

    #[test]
    fn test_constraint_display() {
        let c = Constraint::hard_labeled(
            SymbolicValue::constant(1, ValueWidth::W1),
            "test",
        );
        let s = format!("{c}");
        assert!(s.contains("test"));
    }

    #[test]
    fn test_ult_propagation() {
        // x <u 10  →  x should be in [0, 9]
        let x = var(1, "x");
        let ten = const32(10);
        let lt = x.ult(ten);
        let result = solve_constraints(vec![Constraint::hard(lt)]);
        assert!(result.is_sat());
        if let SolveResult::Sat(m) = result {
            if let Some(&v) = m.get(&1) {
                assert!(v < 10, "Expected x < 10, got {v}");
            }
        }
    }

    #[test]
    fn test_no_constraints_is_sat() {
        let mut s = ConstraintSolver::new();
        assert!(s.solve().is_sat());
    }

    #[test]
    fn test_soft_constraint_ignored_for_unsat() {
        let mut s = ConstraintSolver::new();
        // Soft false — should not cause UNSAT.
        s.add(Constraint::soft(SymbolicValue::constant(0, ValueWidth::W1)));
        assert!(s.solve().is_sat());
    }

    #[test]
    fn test_solve_result_display() {
        let r = SolveResult::Sat(HashMap::new());
        assert!(format!("{r}").contains("SAT"));
        let r2 = SolveResult::Unsat;
        assert!(format!("{r2}").contains("UNSAT"));
    }
}
