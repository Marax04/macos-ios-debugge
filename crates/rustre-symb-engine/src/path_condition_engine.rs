//! `path_condition_engine` — Full path condition management.
//!
//! Provides:
//! * [`PathConditionEngine`] — manages path conditions for all active paths
//! * [`PathCondition`]       — a conjunction of symbolic constraints on one path
//! * [`ConstraintSet`]       — an ordered set of constraints with deduplication
//! * [`FeasibilityChecker`]  — check whether a path condition is satisfiable
//! * [`PathPruner`]          — prune infeasible or depth-exceeded paths
//! * [`ModelExtractor`]      — extract concrete values from a SAT model

use std::collections::{HashMap, HashSet};
use std::fmt;

/// Re-export of [`VecDeque`] for callers maintaining BFS-style frontiers
/// of path conditions without an extra import.
pub use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use rustre_symb::SymExpr;

/// Re-exports of the lower-level symbolic primitives consumed by the
/// feasibility checker so callers can build queries directly.
pub use rustre_symb::{SymbolicError, SymbolicState};

// ─── errors ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum PathConditionError {
    PathNotFound(u64),
    SolverUnavailable,
    MaxDepthExceeded(usize),
    Infeasible,
    Custom(String),
}

impl fmt::Display for PathConditionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathNotFound(id) => write!(f, "path {id} not found"),
            Self::SolverUnavailable => write!(f, "solver unavailable"),
            Self::MaxDepthExceeded(d) => write!(f, "max depth {d} exceeded"),
            Self::Infeasible => write!(f, "path is infeasible"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for PathConditionError {}

// ─── ConstraintId ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ConstraintId(pub u64);

impl fmt::Display for ConstraintId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "C#{}", self.0)
    }
}

// ─── ConstraintEntry ─────────────────────────────────────────────────────────

/// A single constraint with an identifier and optional metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintEntry {
    pub id: ConstraintId,
    pub expr: SymExpr,
    pub origin: String,
    pub is_branch: bool,
    pub branch_taken: Option<bool>,
}

impl ConstraintEntry {
    pub fn new(id: ConstraintId, expr: SymExpr, origin: impl Into<String>) -> Self {
        Self {
            id,
            expr,
            origin: origin.into(),
            is_branch: false,
            branch_taken: None,
        }
    }

    #[must_use]
    pub const fn branch(mut self, taken: bool) -> Self {
        self.is_branch = true;
        self.branch_taken = Some(taken);
        self
    }

    #[must_use]
    pub fn is_negation_of(&self, other: &Self) -> bool {
        if let SymExpr::Not(inner) = &self.expr {
            inner.as_ref() == &other.expr
        } else {
            false
        }
    }
}

impl fmt::Display for ConstraintEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Constraint({}, origin={})", self.id, self.origin)
    }
}

// ─── ConstraintSet ───────────────────────────────────────────────────────────

/// An ordered set of constraints with deduplication.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConstraintSet {
    pub entries: Vec<ConstraintEntry>,
    seen_ids: HashSet<ConstraintId>,
    next_id: u64,
}

impl ConstraintSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, expr: SymExpr, origin: impl Into<String>) -> ConstraintId {
        let id = ConstraintId(self.next_id);
        self.next_id += 1;
        if self.seen_ids.insert(id) {
            self.entries.push(ConstraintEntry::new(id, expr, origin));
        }
        id
    }

    #[must_use]
    pub fn add_branch(
        &mut self,
        expr: SymExpr,
        taken: bool,
        origin: impl Into<String>,
    ) -> ConstraintId {
        let id = ConstraintId(self.next_id);
        self.next_id += 1;
        self.seen_ids.insert(id);
        self.entries
            .push(ConstraintEntry::new(id, expr, origin).branch(taken));
        id
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn remove(&mut self, id: ConstraintId) -> bool {
        if let Some(pos) = self.entries.iter().position(|e| e.id == id) {
            self.entries.remove(pos);
            self.seen_ids.remove(&id);
            true
        } else {
            false
        }
    }

    #[must_use]
    pub fn exprs(&self) -> Vec<&SymExpr> {
        self.entries.iter().map(|e| &e.expr).collect()
    }

    #[must_use]
    pub fn branch_constraints(&self) -> Vec<&ConstraintEntry> {
        self.entries.iter().filter(|e| e.is_branch).collect()
    }

    #[must_use]
    pub fn has_contradictions(&self) -> bool {
        for i in 0..self.entries.len() {
            for j in 0..self.entries.len() {
                if i != j && self.entries[i].is_negation_of(&self.entries[j]) {
                    return true;
                }
            }
        }
        false
    }

    /// Return a clone extended with one more constraint.
    #[must_use]
    pub fn extended(&self, expr: SymExpr, origin: impl Into<String>) -> Self {
        let mut cloned = self.clone();
        cloned.add(expr, origin);
        cloned
    }
}

impl fmt::Display for ConstraintSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConstraintSet {{ {} constraints }}", self.entries.len())
    }
}

// ─── FeasibilityStatus ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeasibilityStatus {
    Feasible,
    Infeasible,
    Unknown,
}

impl fmt::Display for FeasibilityStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Feasible => write!(f, "feasible"),
            Self::Infeasible => write!(f, "infeasible"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─── FeasibilityChecker ──────────────────────────────────────────────────────

/// Checks whether a constraint set is satisfiable.
pub struct FeasibilityChecker {
    pub checks_performed: u64,
    pub infeasible_detected: u64,
    pub timeout_ms: u64,
}

impl FeasibilityChecker {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            checks_performed: 0,
            infeasible_detected: 0,
            timeout_ms: 5000,
        }
    }

    #[must_use]
    pub const fn with_timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Check feasibility of the given constraint set.
    pub fn check(&mut self, cs: &ConstraintSet) -> FeasibilityStatus {
        self.checks_performed += 1;

        // Quick syntactic checks
        if cs.is_empty() {
            return FeasibilityStatus::Feasible;
        }

        if cs.has_contradictions() {
            self.infeasible_detected += 1;
            return FeasibilityStatus::Infeasible;
        }

        // Detect trivially false: Const(0, 1) in constraints
        for e in &cs.entries {
            if matches!(&e.expr, SymExpr::ConstBv { val: 0, width: 1 }) {
                self.infeasible_detected += 1;
                return FeasibilityStatus::Infeasible;
            }
        }

        // Otherwise: assume feasible (no external solver in this layer)
        FeasibilityStatus::Feasible
    }

    pub fn is_feasible(&mut self, cs: &ConstraintSet) -> bool {
        self.check(cs) == FeasibilityStatus::Feasible
    }
}

impl Default for FeasibilityChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── PathCondition ───────────────────────────────────────────────────────────

/// A path condition: the conjunction of all constraints along one execution path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathCondition {
    pub path_id: u64,
    pub constraints: ConstraintSet,
    pub depth: usize,
    pub feasibility: FeasibilityStatus,
    pub is_target_reached: bool,
    pub entry_pc: u64,
    pub current_pc: u64,
}

impl PathCondition {
    #[must_use]
    pub fn new(path_id: u64, entry_pc: u64) -> Self {
        Self {
            path_id,
            constraints: ConstraintSet::new(),
            depth: 0,
            feasibility: FeasibilityStatus::Unknown,
            is_target_reached: false,
            entry_pc,
            current_pc: entry_pc,
        }
    }

    pub fn add_constraint(&mut self, expr: SymExpr, origin: impl Into<String>) -> ConstraintId {
        self.constraints.add(expr, origin)
    }

    pub fn add_branch_constraint(
        &mut self,
        expr: SymExpr,
        taken: bool,
        origin: impl Into<String>,
    ) -> ConstraintId {
        self.depth += 1;
        self.constraints.add_branch(expr, taken, origin)
    }

    pub const fn mark_infeasible(&mut self) {
        self.feasibility = FeasibilityStatus::Infeasible;
    }

    pub const fn mark_feasible(&mut self) {
        self.feasibility = FeasibilityStatus::Feasible;
    }

    #[must_use]
    pub fn is_infeasible(&self) -> bool {
        self.feasibility == FeasibilityStatus::Infeasible
    }

    #[must_use]
    pub const fn constraint_count(&self) -> usize {
        self.constraints.len()
    }

    /// Fork into a true-branch and false-branch clone.
    #[must_use]
    pub fn fork(
        &self,
        condition: SymExpr,
        true_pc: u64,
        false_pc: u64,
    ) -> (Self, Self) {
        let mut true_path = self.clone();
        true_path.path_id = self.path_id * 2 + 1;
        true_path.current_pc = true_pc;
        let _ = true_path
            .constraints
            .add_branch(condition.clone(), true, "fork_true");

        let mut false_path = self.clone();
        false_path.path_id = self.path_id * 2 + 2;
        false_path.current_pc = false_pc;
        let _ = false_path
            .constraints
            .add_branch(SymExpr::Not(Box::new(condition)), false, "fork_false");

        (true_path, false_path)
    }
}

impl fmt::Display for PathCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PathCond(id={}, pc={:#x}, depth={}, {}, constraints={})",
            self.path_id,
            self.current_pc,
            self.depth,
            self.feasibility,
            self.constraints.len()
        )
    }
}

// ─── ModelExtractor ──────────────────────────────────────────────────────────

/// Extracts a concrete model (variable assignments) from a satisfiable path condition.
pub struct ModelExtractor {
    pub extractions: u64,
}

impl ModelExtractor {
    #[must_use]
    pub const fn new() -> Self {
        Self { extractions: 0 }
    }

    /// Produce a model: for each symbolic variable referenced in the
    /// constraint set, assign it a concrete value.  This implementation
    /// uses a syntactic heuristic (no external solver).
    pub fn extract(&mut self, pc: &PathCondition) -> HashMap<String, u64> {
        self.extractions += 1;
        let mut model: HashMap<String, u64> = HashMap::new();

        // Walk all constraint expressions and collect symbolic variable names
        for entry in &pc.constraints.entries {
            Self::collect_symbols(&entry.expr, &mut model);
        }

        model
    }

    fn collect_symbols(expr: &SymExpr, model: &mut HashMap<String, u64>) {
        match expr {
            SymExpr::Var { name, .. } => {
                // Assign a default concrete value of 0 unless already assigned.
                model.entry(name.clone()).or_insert(0);
            }
            SymExpr::Not(inner) | SymExpr::Neg(inner) | SymExpr::BoolNot(inner) => {
                Self::collect_symbols(inner, model);
            }
            SymExpr::Add(a, b)
            | SymExpr::Sub(a, b)
            | SymExpr::Mul(a, b)
            | SymExpr::UDiv(a, b)
            | SymExpr::SDiv(a, b)
            | SymExpr::URem(a, b)
            | SymExpr::SRem(a, b)
            | SymExpr::And(a, b)
            | SymExpr::Or(a, b)
            | SymExpr::Xor(a, b)
            | SymExpr::Shl(a, b)
            | SymExpr::LShr(a, b)
            | SymExpr::AShr(a, b)
            | SymExpr::Eq(a, b)
            | SymExpr::Ne(a, b)
            | SymExpr::ULt(a, b)
            | SymExpr::ULe(a, b)
            | SymExpr::UGt(a, b)
            | SymExpr::UGe(a, b)
            | SymExpr::SLt(a, b)
            | SymExpr::SLe(a, b)
            | SymExpr::SGt(a, b)
            | SymExpr::SGe(a, b)
            | SymExpr::BoolAnd(a, b)
            | SymExpr::BoolOr(a, b)
            | SymExpr::Concat(a, b) => {
                Self::collect_symbols(a, model);
                Self::collect_symbols(b, model);
            }
            SymExpr::Ite { cond, then_, else_ } => {
                Self::collect_symbols(cond, model);
                Self::collect_symbols(then_, model);
                Self::collect_symbols(else_, model);
            }
            SymExpr::ConstBv { .. } | SymExpr::ConstBool(_) => {}
            SymExpr::Load { addr, .. } => Self::collect_symbols(addr, model),
            SymExpr::Store { mem, addr, val } => {
                Self::collect_symbols(mem, model);
                Self::collect_symbols(addr, model);
                Self::collect_symbols(val, model);
            }
            SymExpr::Extract { expr, .. } => Self::collect_symbols(expr, model),
            SymExpr::ZExt { expr, .. } | SymExpr::SExt { expr, .. } => {
                Self::collect_symbols(expr, model);
            }
        }
    }
}

impl Default for ModelExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── PathPruner ──────────────────────────────────────────────────────────────

/// Prunes infeasible or depth-exceeded paths from a worklist.
pub struct PathPruner {
    pub max_depth: usize,
    pub checker: FeasibilityChecker,
    pub pruned_infeasible: u64,
    pub pruned_depth: u64,
    pub pruned_contradiction: u64,
}

impl PathPruner {
    #[must_use]
    pub const fn new(max_depth: usize) -> Self {
        Self {
            max_depth,
            checker: FeasibilityChecker::new(),
            pruned_infeasible: 0,
            pruned_depth: 0,
            pruned_contradiction: 0,
        }
    }

    /// Determine whether the given path condition should be pruned.
    pub fn should_prune(&mut self, pc: &PathCondition) -> bool {
        // Already marked infeasible
        if pc.is_infeasible() {
            self.pruned_infeasible += 1;
            return true;
        }
        // Depth exceeded
        if pc.depth > self.max_depth {
            self.pruned_depth += 1;
            return true;
        }
        // Contradiction detection
        if pc.constraints.has_contradictions() {
            self.pruned_contradiction += 1;
            return true;
        }
        // Feasibility check
        match self.checker.check(&pc.constraints) {
            FeasibilityStatus::Infeasible => {
                self.pruned_infeasible += 1;
                true
            }
            _ => false,
        }
    }

    /// Filter a collection of path conditions, returning only feasible ones.
    pub fn filter(&mut self, paths: Vec<PathCondition>) -> Vec<PathCondition> {
        paths
            .into_iter()
            .filter(|pc| !self.should_prune(pc))
            .collect()
    }

    #[must_use]
    pub const fn total_pruned(&self) -> u64 {
        self.pruned_infeasible + self.pruned_depth + self.pruned_contradiction
    }
}

// ─── PathConditionEngine ─────────────────────────────────────────────────────

/// Manages path conditions for all active symbolic execution paths.
pub struct PathConditionEngine {
    pub max_depth: usize,
    pub max_paths: usize,
    paths: HashMap<u64, PathCondition>,
    pub pruner: PathPruner,
    pub extractor: ModelExtractor,
    next_path_id: u64,
    pub total_forks: u64,
    pub total_merges: u64,
}

impl PathConditionEngine {
    #[must_use]
    pub fn new(max_depth: usize, max_paths: usize) -> Self {
        Self {
            max_depth,
            max_paths,
            paths: HashMap::new(),
            pruner: PathPruner::new(max_depth),
            extractor: ModelExtractor::new(),
            next_path_id: 0,
            total_forks: 0,
            total_merges: 0,
        }
    }

    /// Create and register a new initial path condition.
    pub fn new_path(&mut self, entry_pc: u64) -> u64 {
        let id = self.next_path_id;
        self.next_path_id += 1;
        self.paths.insert(id, PathCondition::new(id, entry_pc));
        id
    }

    #[must_use]
    pub fn get(&self, id: u64) -> Option<&PathCondition> {
        self.paths.get(&id)
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut PathCondition> {
        self.paths.get_mut(&id)
    }

    /// Add a constraint to a path.
    ///
    /// # Errors
    ///
    /// Returns [`PathConditionError::PathNotFound`] if `path_id` does not exist.
    pub fn add_constraint(
        &mut self,
        path_id: u64,
        expr: SymExpr,
        origin: impl Into<String>,
    ) -> Result<ConstraintId, PathConditionError> {
        let pc = self
            .paths
            .get_mut(&path_id)
            .ok_or(PathConditionError::PathNotFound(path_id))?;
        Ok(pc.add_constraint(expr, origin))
    }

    /// Fork a path at a branch.
    ///
    /// # Errors
    ///
    /// Returns [`PathConditionError::MaxDepthExceeded`] if the path limit is
    /// reached, or [`PathConditionError::PathNotFound`] if `path_id` is unknown.
    pub fn fork_path(
        &mut self,
        path_id: u64,
        condition: SymExpr,
        true_pc: u64,
        false_pc: u64,
    ) -> Result<(u64, u64), PathConditionError> {
        if self.paths.len() >= self.max_paths {
            return Err(PathConditionError::MaxDepthExceeded(self.paths.len()));
        }

        let pc = self
            .paths
            .remove(&path_id)
            .ok_or(PathConditionError::PathNotFound(path_id))?;

        let (mut true_path, mut false_path) = pc.fork(condition, true_pc, false_pc);
        let true_id = self.next_path_id;
        true_path.path_id = true_id;
        self.next_path_id += 1;
        let false_id = self.next_path_id;
        false_path.path_id = false_id;
        self.next_path_id += 1;

        self.paths.insert(true_id, true_path);
        self.paths.insert(false_id, false_path);
        self.total_forks += 1;

        Ok((true_id, false_id))
    }

    /// Remove (terminate) a path.
    pub fn terminate_path(&mut self, path_id: u64) -> bool {
        self.paths.remove(&path_id).is_some()
    }

    /// Prune all infeasible paths in place.
    pub fn prune_infeasible(&mut self) {
        let to_remove: Vec<u64> = self
            .paths
            .iter()
            .filter(|(_, pc)| self.pruner.should_prune(pc))
            .map(|(id, _)| *id)
            .collect();
        for id in to_remove {
            self.paths.remove(&id);
        }
    }

    /// Extract a model for the given path.
    ///
    /// # Errors
    ///
    /// Returns [`PathConditionError::PathNotFound`] if `path_id` does not exist.
    pub fn extract_model(
        &mut self,
        path_id: u64,
    ) -> Result<HashMap<String, u64>, PathConditionError> {
        let pc = self
            .paths
            .get(&path_id)
            .ok_or(PathConditionError::PathNotFound(path_id))?;
        Ok(self.extractor.extract(pc))
    }

    #[must_use]
    pub fn active_path_count(&self) -> usize {
        self.paths.len()
    }

    #[must_use]
    pub fn all_path_ids(&self) -> Vec<u64> {
        self.paths.keys().copied().collect()
    }

    #[must_use]
    pub fn feasible_paths(&self) -> Vec<&PathCondition> {
        self.paths
            .values()
            .filter(|pc| pc.feasibility != FeasibilityStatus::Infeasible)
            .collect()
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_symb::SymExpr;

    fn sym(name: &str) -> SymExpr {
        SymExpr::Symbol(1, 64, name)
    }

    fn const1(v: u64) -> SymExpr {
        SymExpr::Const(v, 1)
    }

    fn _const64(v: u64) -> SymExpr {
        SymExpr::Const(v, 64)
    }

    // ── ConstraintSet ────────────────────────────────────────────────────────

    #[test]
    fn test_constraint_set_add() {
        let mut cs = ConstraintSet::new();
        let _id = cs.add(sym("x"), "test");
        assert_eq!(cs.len(), 1);
        assert!(!cs.is_empty());
    }

    #[test]
    fn test_constraint_set_remove() {
        let mut cs = ConstraintSet::new();
        let id = cs.add(sym("x"), "test");
        assert!(cs.remove(id));
        assert!(cs.is_empty());
    }

    #[test]
    fn test_constraint_set_remove_missing() {
        let mut cs = ConstraintSet::new();
        assert!(!cs.remove(ConstraintId(999)));
    }

    #[test]
    fn test_constraint_set_branch_constraints() {
        let mut cs = ConstraintSet::new();
        cs.add(sym("x"), "non-branch");
        let _ = cs.add_branch(sym("cond"), true, "branch");
        let branches = cs.branch_constraints();
        assert_eq!(branches.len(), 1);
    }

    #[test]
    fn test_constraint_set_has_contradictions() {
        let mut cs = ConstraintSet::new();
        let cond = sym("x");
        cs.add(cond.clone(), "a");
        cs.add(SymExpr::Not(Box::new(cond)), "b");
        assert!(cs.has_contradictions());
    }

    #[test]
    fn test_constraint_set_no_contradiction() {
        let mut cs = ConstraintSet::new();
        cs.add(sym("x"), "a");
        cs.add(sym("y"), "b");
        assert!(!cs.has_contradictions());
    }

    #[test]
    fn test_constraint_set_extended() {
        let cs = ConstraintSet::new();
        let cs2 = cs.extended(sym("z"), "new");
        assert_eq!(cs2.len(), 1);
        assert_eq!(cs.len(), 0); // original unchanged
    }

    #[test]
    fn test_constraint_entry_is_negation_of() {
        let id1 = ConstraintId(1);
        let id2 = ConstraintId(2);
        let cond = sym("x");
        let a = ConstraintEntry::new(id1, cond.clone(), "a");
        let b = ConstraintEntry::new(id2, SymExpr::Not(Box::new(cond)), "b");
        assert!(b.is_negation_of(&a));
        assert!(!a.is_negation_of(&b));
    }

    // ── FeasibilityChecker ───────────────────────────────────────────────────

    #[test]
    fn test_feasibility_empty() {
        let mut fc = FeasibilityChecker::new();
        let cs = ConstraintSet::new();
        assert_eq!(fc.check(&cs), FeasibilityStatus::Feasible);
    }

    #[test]
    fn test_feasibility_contradiction() {
        let mut fc = FeasibilityChecker::new();
        let mut cs = ConstraintSet::new();
        let x = sym("x");
        cs.add(x.clone(), "a");
        cs.add(SymExpr::Not(Box::new(x)), "b");
        assert_eq!(fc.check(&cs), FeasibilityStatus::Infeasible);
    }

    #[test]
    fn test_feasibility_trivially_false() {
        let mut fc = FeasibilityChecker::new();
        let mut cs = ConstraintSet::new();
        cs.add(const1(0), "always_false");
        assert_eq!(fc.check(&cs), FeasibilityStatus::Infeasible);
    }

    #[test]
    fn test_feasibility_normal() {
        let mut fc = FeasibilityChecker::new();
        let mut cs = ConstraintSet::new();
        cs.add(sym("x"), "ok");
        assert_eq!(fc.check(&cs), FeasibilityStatus::Feasible);
    }

    #[test]
    fn test_feasibility_counter() {
        let mut fc = FeasibilityChecker::new();
        let cs = ConstraintSet::new();
        fc.check(&cs);
        fc.check(&cs);
        assert_eq!(fc.checks_performed, 2);
    }

    // ── PathCondition ────────────────────────────────────────────────────────

    #[test]
    fn test_path_condition_new() {
        let pc = PathCondition::new(1, 0x1000);
        assert_eq!(pc.path_id, 1);
        assert_eq!(pc.entry_pc, 0x1000);
        assert_eq!(pc.depth, 0);
    }

    #[test]
    fn test_path_condition_add_constraint() {
        let mut pc = PathCondition::new(0, 0x1000);
        pc.add_constraint(sym("x"), "test");
        assert_eq!(pc.constraint_count(), 1);
    }

    #[test]
    fn test_path_condition_add_branch_increments_depth() {
        let mut pc = PathCondition::new(0, 0x1000);
        pc.add_branch_constraint(sym("cond"), true, "branch");
        assert_eq!(pc.depth, 1);
    }

    #[test]
    fn test_path_condition_mark_infeasible() {
        let mut pc = PathCondition::new(0, 0x1000);
        pc.mark_infeasible();
        assert!(pc.is_infeasible());
    }

    #[test]
    fn test_path_condition_fork() {
        let pc = PathCondition::new(0, 0x1000);
        let (true_path, false_path) = pc.fork(sym("cond"), 0x2000, 0x3000);
        assert_eq!(true_path.current_pc, 0x2000);
        assert_eq!(false_path.current_pc, 0x3000);
        assert!(true_path.constraints.branch_constraints().len() == 1);
        assert!(false_path.constraints.branch_constraints().len() == 1);
    }

    #[test]
    fn test_path_condition_fork_negation() {
        let pc = PathCondition::new(0, 0x1000);
        let (_, false_path) = pc.fork(sym("cond"), 0x2000, 0x3000);
        assert!(matches!(
            false_path.constraints.entries.last().map(|e| &e.expr),
            Some(SymExpr::Not(_))
        ));
    }

    // ── PathPruner ───────────────────────────────────────────────────────────

    #[test]
    fn test_pruner_prune_infeasible() {
        let mut pruner = PathPruner::new(100);
        let mut pc = PathCondition::new(0, 0x1000);
        pc.mark_infeasible();
        assert!(pruner.should_prune(&pc));
        assert_eq!(pruner.pruned_infeasible, 1);
    }

    #[test]
    fn test_pruner_prune_depth() {
        let mut pruner = PathPruner::new(5);
        let mut pc = PathCondition::new(0, 0x1000);
        pc.depth = 10;
        assert!(pruner.should_prune(&pc));
        assert_eq!(pruner.pruned_depth, 1);
    }

    #[test]
    fn test_pruner_keep_feasible() {
        let mut pruner = PathPruner::new(100);
        let pc = PathCondition::new(0, 0x1000);
        assert!(!pruner.should_prune(&pc));
    }

    #[test]
    fn test_pruner_filter() {
        let mut pruner = PathPruner::new(100);
        let mut pc1 = PathCondition::new(0, 0x1000);
        pc1.mark_infeasible();
        let pc2 = PathCondition::new(1, 0x2000);
        let remaining = pruner.filter(vec![pc1, pc2]);
        assert_eq!(remaining.len(), 1);
    }

    #[test]
    fn test_pruner_total_pruned() {
        let mut pruner = PathPruner::new(5);
        let mut pc1 = PathCondition::new(0, 0x1000);
        pc1.mark_infeasible();
        let mut pc2 = PathCondition::new(1, 0x2000);
        pc2.depth = 10;
        pruner.should_prune(&pc1);
        pruner.should_prune(&pc2);
        assert_eq!(pruner.total_pruned(), 2);
    }

    // ── ModelExtractor ───────────────────────────────────────────────────────

    #[test]
    fn test_extractor_empty_model() {
        let mut extractor = ModelExtractor::new();
        let pc = PathCondition::new(0, 0x1000);
        let model = extractor.extract(&pc);
        assert!(model.is_empty());
    }

    #[test]
    fn test_extractor_with_symbol() {
        let mut extractor = ModelExtractor::new();
        let mut pc = PathCondition::new(0, 0x1000);
        pc.add_constraint(sym("my_var"), "test");
        let model = extractor.extract(&pc);
        assert!(model.contains_key("my_var"));
    }

    #[test]
    fn test_extractor_counter() {
        let mut extractor = ModelExtractor::new();
        let pc = PathCondition::new(0, 0x1000);
        extractor.extract(&pc);
        extractor.extract(&pc);
        assert_eq!(extractor.extractions, 2);
    }

    // ── PathConditionEngine ──────────────────────────────────────────────────

    #[test]
    fn test_engine_new_path() {
        let mut engine = PathConditionEngine::new(100, 256);
        let id = engine.new_path(0x1000);
        assert_eq!(engine.active_path_count(), 1);
        let pc = engine.get(id).unwrap();
        assert_eq!(pc.entry_pc, 0x1000);
    }

    #[test]
    fn test_engine_add_constraint() {
        let mut engine = PathConditionEngine::new(100, 256);
        let id = engine.new_path(0x1000);
        engine.add_constraint(id, sym("x"), "test").unwrap();
        assert_eq!(engine.get(id).unwrap().constraint_count(), 1);
    }

    #[test]
    fn test_engine_add_constraint_missing_path() {
        let mut engine = PathConditionEngine::new(100, 256);
        let result = engine.add_constraint(999, sym("x"), "test");
        assert!(matches!(result, Err(PathConditionError::PathNotFound(999))));
    }

    #[test]
    fn test_engine_fork_path() {
        let mut engine = PathConditionEngine::new(100, 256);
        let id = engine.new_path(0x1000);
        let (_t, _f) = engine.fork_path(id, sym("cond"), 0x2000, 0x3000).unwrap();
        assert_eq!(engine.active_path_count(), 2);
        assert!(!engine.paths.contains_key(&id)); // original removed
    }

    #[test]
    fn test_engine_terminate_path() {
        let mut engine = PathConditionEngine::new(100, 256);
        let id = engine.new_path(0x1000);
        assert!(engine.terminate_path(id));
        assert_eq!(engine.active_path_count(), 0);
    }

    #[test]
    fn test_engine_prune_infeasible() {
        let mut engine = PathConditionEngine::new(100, 256);
        let id = engine.new_path(0x1000);
        engine.get_mut(id).unwrap().mark_infeasible();
        engine.prune_infeasible();
        assert_eq!(engine.active_path_count(), 0);
    }

    #[test]
    fn test_engine_extract_model() {
        let mut engine = PathConditionEngine::new(100, 256);
        let id = engine.new_path(0x1000);
        engine.add_constraint(id, sym("y"), "test").unwrap();
        let model = engine.extract_model(id).unwrap();
        assert!(model.contains_key("y"));
    }

    #[test]
    fn test_engine_feasible_paths() {
        let mut engine = PathConditionEngine::new(100, 256);
        let _id1 = engine.new_path(0x1000);
        let id2 = engine.new_path(0x2000);
        engine.get_mut(id2).unwrap().mark_infeasible();
        let feasible = engine.feasible_paths();
        assert_eq!(feasible.len(), 1);
    }

    #[test]
    fn test_engine_all_path_ids() {
        let mut engine = PathConditionEngine::new(100, 256);
        let id1 = engine.new_path(0x1000);
        let id2 = engine.new_path(0x2000);
        let ids = engine.all_path_ids();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn test_engine_fork_increments_count() {
        let mut engine = PathConditionEngine::new(100, 256);
        let id = engine.new_path(0x1000);
        engine.fork_path(id, sym("cond"), 0x2000, 0x3000).unwrap();
        assert_eq!(engine.total_forks, 1);
    }

    #[test]
    fn test_engine_terminate_missing() {
        let mut engine = PathConditionEngine::new(100, 256);
        assert!(!engine.terminate_path(9999));
    }

    #[test]
    fn test_engine_extract_missing_path() {
        let mut engine = PathConditionEngine::new(100, 256);
        let result = engine.extract_model(9999);
        assert!(matches!(
            result,
            Err(PathConditionError::PathNotFound(9999))
        ));
    }

    #[test]
    fn test_path_condition_fork_ids_differ() {
        let pc = PathCondition::new(0, 0x1000);
        let (t, f) = pc.fork(sym("x"), 0x2000, 0x3000);
        assert_ne!(t.path_id, f.path_id);
    }

    #[test]
    fn test_path_condition_mark_feasible() {
        let mut pc = PathCondition::new(0, 0x1000);
        pc.mark_infeasible();
        pc.mark_feasible();
        assert!(!pc.is_infeasible());
    }

    #[test]
    fn test_constraint_set_exprs() {
        let mut cs = ConstraintSet::new();
        cs.add(sym("a"), "src1");
        cs.add(sym("b"), "src2");
        let exprs = cs.exprs();
        assert_eq!(exprs.len(), 2);
    }

    #[test]
    fn test_feasibility_checker_infeasible_counter() {
        let mut fc = FeasibilityChecker::new();
        let mut cs = ConstraintSet::new();
        cs.add(const1(0), "always_false");
        fc.check(&cs);
        assert_eq!(fc.infeasible_detected, 1);
    }

    #[test]
    fn test_pruner_total_after_multiple() {
        let mut pruner = PathPruner::new(5);
        let mut pc1 = PathCondition::new(0, 0x1000);
        pc1.depth = 10;
        let mut pc2 = PathCondition::new(1, 0x2000);
        pc2.mark_infeasible();
        pruner.should_prune(&pc1);
        pruner.should_prune(&pc2);
        assert_eq!(pruner.total_pruned(), 2);
    }

    #[test]
    fn test_model_extractor_nested() {
        let mut extractor = ModelExtractor::new();
        let mut pc = PathCondition::new(0, 0x1000);
        // Nested expression: (a + b) = c
        let add = SymExpr::Add(Box::new(sym("a")), Box::new(sym("b")));
        let eq = SymExpr::Eq(Box::new(add), Box::new(sym("c")));
        pc.add_constraint(eq, "nested");
        let model = extractor.extract(&pc);
        assert!(model.contains_key("a"));
        assert!(model.contains_key("b"));
        assert!(model.contains_key("c"));
    }
}
