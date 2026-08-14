//! `symbolic_execution_engine` — Full symbolic execution driver.
//!
//! Provides:
//! * [`SymbolicExecutionEngine`] — orchestrates symbolic execution
//! * [`SymbolicState`]           — full symbolic machine state (registers + memory + path)
//! * [`PathExplorer`]            — manages path exploration worklist
//! * [`BranchMerge`]             — merge symbolic states at join points
//! * [`ConstraintSystem`]        — set of path constraints
//! * [`SolverInterface`]         — trait for querying an SMT solver

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::SymExpr;
pub use crate::{SymbolicError, SymbolicState};

// ─── errors ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum EngineError {
    PathExplosion { path_count: usize },
    SolverTimeout,
    InfeasiblePath,
    MergeConflict(String),
    Custom(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathExplosion { path_count } => write!(f, "path explosion: {path_count} paths"),
            Self::SolverTimeout => write!(f, "solver timeout"),
            Self::InfeasiblePath => write!(f, "infeasible path"),
            Self::MergeConflict(s) => write!(f, "merge conflict: {s}"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for EngineError {}

// ─── ConstraintSystem ────────────────────────────────────────────────────────

/// A collection of path constraints (conjunction of symbolic expressions).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConstraintSystem {
    pub constraints: Vec<SymExpr>,
    pub is_satisfiable: Option<bool>,
    pub depth: usize,
}

impl ConstraintSystem {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, constraint: SymExpr) {
        self.constraints.push(constraint);
        self.is_satisfiable = None; // invalidate cached result
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.constraints.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }

    /// Return a new `ConstraintSystem` with an extra constraint (branch taken).
    #[must_use]
    pub fn with_branch_true(&self, cond: SymExpr) -> Self {
        let mut cs = self.clone();
        cs.add(cond);
        cs.depth += 1;
        cs
    }

    /// Return a new `ConstraintSystem` with a negated constraint (branch not taken).
    #[must_use]
    pub fn with_branch_false(&self, cond: SymExpr) -> Self {
        let mut cs = self.clone();
        cs.add(SymExpr::Not(Box::new(cond)));
        cs.depth += 1;
        cs
    }

    /// Mark this constraint system as known satisfiable/unsatisfiable.
    pub const fn set_satisfiable(&mut self, sat: bool) {
        self.is_satisfiable = Some(sat);
    }

    #[must_use]
    pub fn is_known_unsat(&self) -> bool {
        self.is_satisfiable == Some(false)
    }

    /// Merge two constraint systems: keeps all constraints from both.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for c in &other.constraints {
            result.add(c.clone());
        }
        result
    }
}

impl fmt::Display for ConstraintSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ConstraintSystem {{ constraints={}, depth={} }}",
            self.constraints.len(),
            self.depth
        )
    }
}

// ─── SolverResult ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SolverResult {
    Sat,
    Unsat,
    Unknown,
    Timeout,
}

impl fmt::Display for SolverResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sat => write!(f, "sat"),
            Self::Unsat => write!(f, "unsat"),
            Self::Unknown => write!(f, "unknown"),
            Self::Timeout => write!(f, "timeout"),
        }
    }
}

/// Model: concrete values for symbolic variables.
pub type SolverModel = HashMap<String, u64>;

// ─── SolverInterface ─────────────────────────────────────────────────────────

/// Trait for communicating with an SMT solver backend.
pub trait SolverInterface: fmt::Debug {
    /// Check satisfiability of the given constraint system.
    fn check_sat(&mut self, cs: &ConstraintSystem) -> SolverResult;

    /// If sat, extract a model (concrete values for all symbols).
    fn get_model(&mut self, cs: &ConstraintSystem) -> Option<SolverModel>;

    /// Check if `target` is reachable under `cs`.
    fn is_reachable(&mut self, cs: &ConstraintSystem, target: &SymExpr) -> bool;

    /// Name of this solver.
    fn name(&self) -> &str;
}

/// A trivial solver that never invokes an external process — used for tests
/// and as a stand-in when z3 is not available.
#[derive(Debug, Default)]
pub struct TrivialSolver {
    pub calls: u64,
}

impl SolverInterface for TrivialSolver {
    fn check_sat(&mut self, cs: &ConstraintSystem) -> SolverResult {
        self.calls += 1;
        // Trivial: claim SAT unless there are >100 constraints (test heuristic)
        if cs.len() > 100 {
            SolverResult::Unknown
        } else {
            SolverResult::Sat
        }
    }

    fn get_model(&mut self, _cs: &ConstraintSystem) -> Option<SolverModel> {
        self.calls += 1;
        Some(HashMap::new())
    }

    fn is_reachable(&mut self, cs: &ConstraintSystem, _target: &SymExpr) -> bool {
        self.calls += 1;
        cs.len() <= 100
    }

    fn name(&self) -> &'static str {
        "trivial"
    }
}

// ─── ExecutionConfig ─────────────────────────────────────────────────────────

/// Configuration knobs for the symbolic execution engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    pub max_paths: usize,
    pub max_depth: usize,
    pub max_solver_calls: u64,
    pub lazy_constraints: bool,
    pub merge_at_joins: bool,
    pub check_every_n_steps: usize,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            max_paths: 256,
            max_depth: 512,
            max_solver_calls: 10_000,
            lazy_constraints: true,
            merge_at_joins: false,
            check_every_n_steps: 50,
        }
    }
}

impl ExecutionConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_max_paths(mut self, n: usize) -> Self {
        self.max_paths = n;
        self
    }

    #[must_use]
    pub const fn with_max_depth(mut self, d: usize) -> Self {
        self.max_depth = d;
        self
    }

    #[must_use]
    pub const fn with_lazy_constraints(mut self, lazy: bool) -> Self {
        self.lazy_constraints = lazy;
        self
    }
}

// ─── PathLabel ───────────────────────────────────────────────────────────────

/// Unique identifier for a symbolic execution path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathId(pub u64);

impl fmt::Display for PathId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Path#{}", self.0)
    }
}

// ─── BranchMerge ─────────────────────────────────────────────────────────────

/// Merges two symbolic states at a control-flow join point.
#[derive(Debug, Default)]
pub struct BranchMerge {
    pub merges_performed: u64,
    pub merges_skipped: u64,
}

impl BranchMerge {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge `a` and `b` into a new state.  Register values that differ
    /// become `ITE(path_cond`, va, vb) expressions.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MergeConflict`] when the two states cannot be
    /// reconciled (e.g. their program counters disagree).
    pub fn merge(&mut self, a: &EngineState, b: &EngineState) -> Result<EngineState, EngineError> {
        if a.pc != b.pc {
            return Err(EngineError::MergeConflict(format!(
                "PC mismatch: {:#x} vs {:#x}",
                a.pc, b.pc
            )));
        }
        let all_regs: HashSet<String> = a
            .registers
            .keys()
            .chain(b.registers.keys())
            .cloned()
            .collect();
        let mut merged_regs: HashMap<String, SymExpr> = HashMap::with_capacity(all_regs.len());

        for reg in all_regs {
            let va = a
                .registers
                .get(&reg)
                .cloned()
                .unwrap_or(SymExpr::Const(0, 64));
            let vb = b
                .registers
                .get(&reg)
                .cloned()
                .unwrap_or(SymExpr::Const(0, 64));
            if va == vb {
                merged_regs.insert(reg, va);
            } else {
                // ITE(path_condition_a, va, vb)
                let ite = SymExpr::Ite(
                    Box::new(SymExpr::Symbol(
                        a.path_id.0,
                        1,
                        format!("path_{}", a.path_id.0),
                    )),
                    Box::new(va),
                    Box::new(vb),
                );
                merged_regs.insert(reg, ite);
            }
        }

        let merged_cs = a.constraints.union(&b.constraints);

        self.merges_performed += 1;
        Ok(EngineState {
            path_id: a.path_id,
            pc: a.pc,
            registers: merged_regs,
            memory: a.memory.clone(),
            constraints: merged_cs,
            step_count: a.step_count.max(b.step_count),
            terminated: false,
        })
    }
}

// ─── EngineState ─────────────────────────────────────────────────────────────

/// Full state of a single symbolic execution path.
#[derive(Debug, Clone)]
pub struct EngineState {
    pub path_id: PathId,
    pub pc: u64,
    pub registers: HashMap<String, SymExpr>,
    pub memory: HashMap<u64, SymExpr>,
    pub constraints: ConstraintSystem,
    pub step_count: usize,
    pub terminated: bool,
}

impl EngineState {
    #[must_use]
    pub fn new(path_id: PathId, entry_pc: u64) -> Self {
        Self {
            path_id,
            pc: entry_pc,
            registers: HashMap::new(),
            memory: HashMap::new(),
            constraints: ConstraintSystem::new(),
            step_count: 0,
            terminated: false,
        }
    }

    pub fn set_register(&mut self, name: impl Into<String>, value: SymExpr) {
        self.registers.insert(name.into(), value);
    }

    #[must_use]
    pub fn get_register(&self, name: &str) -> Option<&SymExpr> {
        self.registers.get(name)
    }

    pub fn write_memory(&mut self, addr: u64, value: SymExpr) {
        self.memory.insert(addr, value);
    }

    #[must_use]
    pub fn read_memory(&self, addr: u64) -> Option<&SymExpr> {
        self.memory.get(&addr)
    }

    pub fn add_constraint(&mut self, c: SymExpr) {
        self.constraints.add(c);
    }

    #[must_use]
    pub fn fork_true(&self, condition: SymExpr, new_pc: u64, new_id: PathId) -> Self {
        let mut child = self.clone();
        child.path_id = new_id;
        child.pc = new_pc;
        child.constraints = self.constraints.with_branch_true(condition);
        child
    }

    #[must_use]
    pub fn fork_false(&self, condition: SymExpr, new_pc: u64, new_id: PathId) -> Self {
        let mut child = self.clone();
        child.path_id = new_id;
        child.pc = new_pc;
        child.constraints = self.constraints.with_branch_false(condition);
        child
    }

    #[must_use]
    pub const fn is_depth_exceeded(&self, max_depth: usize) -> bool {
        self.constraints.depth > max_depth
    }
}

impl fmt::Display for EngineState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EngineState {{ {}, pc={:#x}, regs={}, constraints={} }}",
            self.path_id,
            self.pc,
            self.registers.len(),
            self.constraints.len()
        )
    }
}

// ─── PathExplorer ────────────────────────────────────────────────────────────

/// Manages the worklist of active symbolic execution paths.
#[derive(Debug)]
pub struct PathExplorer {
    pub worklist: VecDeque<EngineState>,
    pub completed: Vec<EngineState>,
    pub pruned: u64,
    pub next_path_id: u64,
}

impl PathExplorer {
    #[must_use]
    pub fn new(initial: EngineState) -> Self {
        let mut wl = VecDeque::new();
        wl.push_back(initial);
        Self {
            worklist: wl,
            completed: Vec::new(),
            pruned: 0,
            next_path_id: 1,
        }
    }

    pub const fn new_path_id(&mut self) -> PathId {
        let id = PathId(self.next_path_id);
        self.next_path_id += 1;
        id
    }

    pub fn enqueue(&mut self, state: EngineState) {
        self.worklist.push_back(state);
    }

    pub fn dequeue(&mut self) -> Option<EngineState> {
        self.worklist.pop_front()
    }

    pub fn mark_completed(&mut self, state: EngineState) {
        self.completed.push(state);
    }

    pub const fn prune(&mut self) {
        self.pruned += 1;
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.worklist.len()
    }

    #[must_use]
    pub fn total_paths(&self) -> usize {
        self.worklist.len()
            + self.completed.len()
            + usize::try_from(self.pruned).unwrap_or(usize::MAX)
    }

    #[must_use]
    pub fn is_done(&self) -> bool {
        self.worklist.is_empty()
    }
}

// ─── SymbolicExecutionEngine ─────────────────────────────────────────────────

/// Engine statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EngineStats {
    pub paths_explored: u64,
    pub paths_pruned: u64,
    pub solver_calls: u64,
    pub branches_taken: u64,
    pub total_steps: u64,
}

/// The top-level symbolic execution engine.
pub struct SymbolicExecutionEngine {
    pub config: ExecutionConfig,
    pub solver: Box<dyn SolverInterface>,
    pub stats: EngineStats,
    pub merger: BranchMerge,
}

impl SymbolicExecutionEngine {
    #[must_use]
    pub fn new(config: ExecutionConfig, solver: Box<dyn SolverInterface>) -> Self {
        Self {
            config,
            solver,
            stats: EngineStats::default(),
            merger: BranchMerge::new(),
        }
    }

    #[must_use]
    pub fn with_trivial_solver(config: ExecutionConfig) -> Self {
        Self::new(config, Box::new(TrivialSolver::default()))
    }

    /// Check if a constraint system is satisfiable.
    pub fn check_satisfiable(&mut self, cs: &ConstraintSystem) -> bool {
        self.stats.solver_calls += 1;
        matches!(self.solver.check_sat(cs), SolverResult::Sat)
    }

    /// Create the initial state at a given entry address.
    #[must_use]
    pub fn create_initial_state(&self, entry: u64) -> EngineState {
        EngineState::new(PathId(0), entry)
    }

    /// Fork a state at a conditional branch.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::PathExplosion`] when adding the forked states
    /// would exceed [`EngineConfig::max_paths`].
    pub fn fork_state(
        &mut self,
        state: &EngineState,
        condition: SymExpr,
        true_target: u64,
        false_target: u64,
        explorer: &mut PathExplorer,
    ) -> Result<(), EngineError> {
        if explorer.total_paths() >= self.config.max_paths {
            return Err(EngineError::PathExplosion {
                path_count: explorer.total_paths(),
            });
        }

        self.stats.branches_taken += 1;

        let id_true = explorer.new_path_id();
        let id_false = explorer.new_path_id();

        let true_state = state.fork_true(condition.clone(), true_target, id_true);
        let false_state = state.fork_false(condition, false_target, id_false);

        // Prune infeasible paths (if not using lazy constraints)
        if self.config.lazy_constraints {
            explorer.enqueue(true_state);
            explorer.enqueue(false_state);
        } else {
            let true_sat = {
                self.stats.solver_calls += 1;
                matches!(
                    self.solver.check_sat(&true_state.constraints),
                    SolverResult::Sat
                )
            };
            if true_sat {
                explorer.enqueue(true_state);
            } else {
                explorer.prune();
            }

            let false_sat = {
                self.stats.solver_calls += 1;
                matches!(
                    self.solver.check_sat(&false_state.constraints),
                    SolverResult::Sat
                )
            };
            if false_sat {
                explorer.enqueue(false_state);
            } else {
                explorer.prune();
            }
        }

        Ok(())
    }

    /// Process a single state step (simplified — advances PC by 1 and applies
    /// a symbolic register write).
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::PathExplosion`] when the state's depth exceeds
    /// [`EngineConfig::max_depth`].
    pub fn step_state(&mut self, mut state: EngineState) -> Result<EngineState, EngineError> {
        if state.is_depth_exceeded(self.config.max_depth) {
            return Err(EngineError::PathExplosion {
                path_count: state.constraints.depth,
            });
        }
        state.pc = state.pc.wrapping_add(1);
        state.step_count += 1;
        self.stats.total_steps += 1;
        Ok(state)
    }

    /// Run symbolic exploration from `entry_pc` for at most `max_steps` steps.
    ///
    /// # Errors
    ///
    /// Propagates any [`EngineError`] returned by the inner step/fork machinery
    /// (such as [`EngineError::PathExplosion`] on path-count overflow).
    pub fn run(&mut self, entry: u64, max_steps: usize) -> Result<Vec<EngineState>, EngineError> {
        let initial = self.create_initial_state(entry);
        let mut explorer = PathExplorer::new(initial);
        let mut step_counter = 0;

        while !explorer.is_done() && step_counter < max_steps {
            let Some(state) = explorer.dequeue() else {
                break;
            };

            if state.terminated || state.is_depth_exceeded(self.config.max_depth) {
                explorer.mark_completed(state);
                continue;
            }

            let stepped = self.step_state(state)?;
            step_counter += 1;

            // Every N steps, fork unconditionally (simulated branching)
            if stepped.step_count.is_multiple_of(self.config.check_every_n_steps)
                && explorer.active_count() < self.config.max_paths / 2
            {
                let cond = SymExpr::Symbol(stepped.path_id.0, 1, "branch_cond".to_string());
                let pc = stepped.pc;
                let mut s = stepped;
                let id = explorer.new_path_id();
                let false_path = s.fork_false(cond.clone(), pc + 100, id);
                s.constraints = s.constraints.with_branch_true(cond);
                explorer.enqueue(false_path);
                explorer.enqueue(s);
            } else {
                explorer.enqueue(stepped);
            }
        }

        // Flush any remaining active paths into completed when the step budget runs out.
        while let Some(s) = explorer.dequeue() {
            explorer.mark_completed(s);
        }
        self.stats.paths_explored = explorer.completed.len() as u64;
        self.stats.paths_pruned = explorer.pruned;

        Ok(explorer.completed)
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SymExpr;

    fn sym(name: &str) -> SymExpr {
        SymExpr::Symbol(0, 64, name.to_string())
    }

    fn const64(v: u64) -> SymExpr {
        SymExpr::Const(v, 64)
    }

    // ── ConstraintSystem ─────────────────────────────────────────────────────

    #[test]
    fn test_constraint_system_add() {
        let mut cs = ConstraintSystem::new();
        cs.add(sym("x"));
        assert_eq!(cs.len(), 1);
        assert!(!cs.is_empty());
    }

    #[test]
    fn test_constraint_system_branch_true() {
        let cs = ConstraintSystem::new();
        let cs2 = cs.with_branch_true(sym("cond"));
        assert_eq!(cs2.len(), 1);
        assert_eq!(cs2.depth, 1);
    }

    #[test]
    fn test_constraint_system_branch_false() {
        let cs = ConstraintSystem::new();
        let cs2 = cs.with_branch_false(sym("cond"));
        assert_eq!(cs2.len(), 1);
        assert!(matches!(&cs2.constraints[0], SymExpr::Not(_)));
    }

    #[test]
    fn test_constraint_system_set_satisfiable() {
        let mut cs = ConstraintSystem::new();
        cs.set_satisfiable(false);
        assert!(cs.is_known_unsat());
    }

    #[test]
    fn test_constraint_system_union() {
        let mut a = ConstraintSystem::new();
        a.add(sym("x"));
        let mut b = ConstraintSystem::new();
        b.add(sym("y"));
        let merged = a.union(&b);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_constraint_system_invalidate_on_add() {
        let mut cs = ConstraintSystem::new();
        cs.set_satisfiable(true);
        cs.add(sym("more"));
        assert!(cs.is_satisfiable.is_none());
    }

    // ── EngineState ──────────────────────────────────────────────────────────

    #[test]
    fn test_engine_state_set_get_register() {
        let mut s = EngineState::new(PathId(0), 0x1000);
        s.set_register("rax", const64(42));
        assert!(s.get_register("rax").is_some());
        assert!(s.get_register("rbx").is_none());
    }

    #[test]
    fn test_engine_state_memory_rw() {
        let mut s = EngineState::new(PathId(0), 0x1000);
        s.write_memory(0x8000, const64(0xFF));
        assert!(s.read_memory(0x8000).is_some());
        assert!(s.read_memory(0x9000).is_none());
    }

    #[test]
    fn test_engine_state_fork_true() {
        let s = EngineState::new(PathId(0), 0x1000);
        let child = s.fork_true(sym("c"), 0x2000, PathId(1));
        assert_eq!(child.pc, 0x2000);
        assert_eq!(child.path_id, PathId(1));
        assert_eq!(child.constraints.len(), 1);
    }

    #[test]
    fn test_engine_state_fork_false() {
        let s = EngineState::new(PathId(0), 0x1000);
        let child = s.fork_false(sym("c"), 0x3000, PathId(2));
        assert_eq!(child.pc, 0x3000);
        assert!(matches!(&child.constraints.constraints[0], SymExpr::Not(_)));
    }

    #[test]
    fn test_engine_state_depth_exceeded() {
        let mut s = EngineState::new(PathId(0), 0x1000);
        s.constraints.depth = 600;
        assert!(s.is_depth_exceeded(512));
        assert!(!s.is_depth_exceeded(600));
    }

    #[test]
    fn test_engine_state_add_constraint() {
        let mut s = EngineState::new(PathId(0), 0x1000);
        s.add_constraint(sym("x"));
        assert_eq!(s.constraints.len(), 1);
    }

    // ── PathExplorer ─────────────────────────────────────────────────────────

    #[test]
    fn test_path_explorer_enqueue_dequeue() {
        let s = EngineState::new(PathId(0), 0x1000);
        let mut explorer = PathExplorer::new(s);
        assert_eq!(explorer.active_count(), 1);
        let dequeued = explorer.dequeue().unwrap();
        assert_eq!(dequeued.pc, 0x1000);
        assert_eq!(explorer.active_count(), 0);
    }

    #[test]
    fn test_path_explorer_done() {
        let s = EngineState::new(PathId(0), 0x1000);
        let mut explorer = PathExplorer::new(s);
        explorer.dequeue();
        assert!(explorer.is_done());
    }

    #[test]
    fn test_path_explorer_prune() {
        let s = EngineState::new(PathId(0), 0x1000);
        let mut explorer = PathExplorer::new(s);
        explorer.prune();
        assert_eq!(explorer.pruned, 1);
    }

    #[test]
    fn test_path_explorer_total_paths() {
        let s = EngineState::new(PathId(0), 0x1000);
        let mut explorer = PathExplorer::new(s);
        let s2 = EngineState::new(PathId(1), 0x2000);
        explorer.enqueue(s2);
        assert_eq!(explorer.total_paths(), 2);
    }

    #[test]
    fn test_path_explorer_new_path_id() {
        let s = EngineState::new(PathId(0), 0x1000);
        let mut explorer = PathExplorer::new(s);
        assert_eq!(explorer.new_path_id(), PathId(1));
        assert_eq!(explorer.new_path_id(), PathId(2));
    }

    // ── BranchMerge ──────────────────────────────────────────────────────────

    #[test]
    fn test_branch_merge_same_pc() {
        let mut merger = BranchMerge::new();
        let mut a = EngineState::new(PathId(0), 0x5000);
        let mut b = EngineState::new(PathId(1), 0x5000);
        a.set_register("rax", const64(1));
        b.set_register("rax", const64(2));
        let merged = merger.merge(&a, &b).unwrap();
        assert_eq!(merged.pc, 0x5000);
        assert_eq!(merger.merges_performed, 1);
    }

    #[test]
    fn test_branch_merge_different_pc_error() {
        let mut merger = BranchMerge::new();
        let a = EngineState::new(PathId(0), 0x5000);
        let b = EngineState::new(PathId(1), 0x6000);
        assert!(matches!(
            merger.merge(&a, &b),
            Err(EngineError::MergeConflict(_))
        ));
    }

    #[test]
    fn test_branch_merge_same_register_value() {
        let mut merger = BranchMerge::new();
        let mut a = EngineState::new(PathId(0), 0x5000);
        let mut b = EngineState::new(PathId(1), 0x5000);
        a.set_register("rax", const64(42));
        b.set_register("rax", const64(42));
        let merged = merger.merge(&a, &b).unwrap();
        assert!(matches!(
            merged.registers.get("rax"),
            Some(SymExpr::ConstBv { val: 42, width: 64 })
        ));
    }

    // ── TrivialSolver ────────────────────────────────────────────────────────

    #[test]
    fn test_trivial_solver_sat() {
        let mut s = TrivialSolver::default();
        let cs = ConstraintSystem::new();
        assert_eq!(s.check_sat(&cs), SolverResult::Sat);
    }

    #[test]
    fn test_trivial_solver_model() {
        let mut s = TrivialSolver::default();
        let cs = ConstraintSystem::new();
        assert!(s.get_model(&cs).is_some());
    }

    #[test]
    fn test_trivial_solver_reachable() {
        let mut s = TrivialSolver::default();
        let cs = ConstraintSystem::new();
        assert!(s.is_reachable(&cs, &sym("target")));
    }

    // ── ExecutionConfig ──────────────────────────────────────────────────────

    #[test]
    fn test_config_defaults() {
        let c = ExecutionConfig::default();
        assert!(c.max_paths > 0);
        assert!(c.max_depth > 0);
    }

    #[test]
    fn test_config_builder() {
        let c = ExecutionConfig::new().with_max_paths(10).with_max_depth(20);
        assert_eq!(c.max_paths, 10);
        assert_eq!(c.max_depth, 20);
    }

    // ── SymbolicExecutionEngine ───────────────────────────────────────────────

    #[test]
    fn test_engine_create_initial_state() {
        let engine = SymbolicExecutionEngine::with_trivial_solver(ExecutionConfig::default());
        let s = engine.create_initial_state(0xDEAD);
        assert_eq!(s.pc, 0xDEAD);
    }

    #[test]
    fn test_engine_check_satisfiable() {
        let mut engine = SymbolicExecutionEngine::with_trivial_solver(ExecutionConfig::default());
        let cs = ConstraintSystem::new();
        assert!(engine.check_satisfiable(&cs));
        assert_eq!(engine.stats.solver_calls, 1);
    }

    #[test]
    fn test_engine_run_basic() {
        let config = ExecutionConfig::new().with_max_paths(32).with_max_depth(10);
        let mut engine = SymbolicExecutionEngine::with_trivial_solver(config);
        let completed = engine.run(0x1000, 5).unwrap();
        assert!(!completed.is_empty());
        assert!(engine.stats.total_steps > 0);
    }

    #[test]
    fn test_engine_fork_state() {
        let mut engine = SymbolicExecutionEngine::with_trivial_solver(ExecutionConfig::default());
        let state = EngineState::new(PathId(0), 0x1000);
        let mut explorer = PathExplorer::new(EngineState::new(PathId(99), 0xFFFF));
        let _ = explorer.dequeue(); // clear initial
        engine
            .fork_state(&state, sym("cond"), 0x2000, 0x3000, &mut explorer)
            .unwrap();
        assert_eq!(explorer.active_count(), 2);
    }

    #[test]
    fn test_engine_path_explosion_limit() {
        let config = ExecutionConfig::new().with_max_paths(2);
        let mut engine = SymbolicExecutionEngine::with_trivial_solver(config);
        let state = EngineState::new(PathId(0), 0x1000);
        let mut explorer = PathExplorer::new(EngineState::new(PathId(99), 0xFFFF));
        // Fill up to limit
        for _ in 0..3 {
            let id = explorer.new_path_id();
            explorer.enqueue(EngineState::new(id, 0x1000));
        }
        let result = engine.fork_state(&state, sym("c"), 0x2000, 0x3000, &mut explorer);
        assert!(matches!(result, Err(EngineError::PathExplosion { .. })));
    }

    #[test]
    fn test_solver_result_display() {
        assert_eq!(format!("{}", SolverResult::Sat), "sat");
        assert_eq!(format!("{}", SolverResult::Unsat), "unsat");
    }

    #[test]
    fn test_solver_result_unknown() {
        assert_eq!(format!("{}", SolverResult::Unknown), "unknown");
        assert_eq!(format!("{}", SolverResult::Timeout), "timeout");
    }

    #[test]
    fn test_trivial_solver_many_constraints_unknown() {
        let mut s = TrivialSolver::default();
        let mut cs = ConstraintSystem::new();
        for i in 0..101u64 {
            cs.add(SymExpr::Symbol(i, 1, format!("x{i}")));
        }
        assert_eq!(s.check_sat(&cs), SolverResult::Unknown);
    }

    #[test]
    fn test_engine_state_display() {
        let s = EngineState::new(PathId(5), 0xABCD);
        let disp = format!("{s}");
        assert!(disp.contains("Path#5"));
        assert!(disp.contains("0xabcd"));
    }

    #[test]
    fn test_path_id_display() {
        let p = PathId(99);
        assert_eq!(format!("{p}"), "Path#99");
    }

    #[test]
    fn test_engine_stats_default() {
        let s = EngineStats::default();
        assert_eq!(s.paths_explored, 0);
        assert_eq!(s.solver_calls, 0);
    }

    #[test]
    fn test_config_lazy_constraints() {
        let c = ExecutionConfig::new().with_lazy_constraints(false);
        assert!(!c.lazy_constraints);
    }

    #[test]
    fn test_branch_merge_stats() {
        let mut merger = BranchMerge::new();
        let a = EngineState::new(PathId(0), 0x5000);
        let b = EngineState::new(PathId(1), 0x5000);
        merger.merge(&a, &b).unwrap();
        assert_eq!(merger.merges_performed, 1);
        assert_eq!(merger.merges_skipped, 0);
    }

    #[test]
    fn test_engine_step_increments_pc() {
        let mut engine = SymbolicExecutionEngine::with_trivial_solver(ExecutionConfig::default());
        let s = EngineState::new(PathId(0), 0x1000);
        let stepped = engine.step_state(s).unwrap();
        assert_eq!(stepped.pc, 0x1001);
        assert_eq!(stepped.step_count, 1);
    }

    #[test]
    fn test_engine_run_many_steps() {
        let config = ExecutionConfig::new()
            .with_max_paths(64)
            .with_max_depth(200);
        let mut engine = SymbolicExecutionEngine::with_trivial_solver(config);
        let completed = engine.run(0x1000, 20).unwrap();
        assert!(!completed.is_empty());
        assert!(engine.stats.total_steps >= 10);
    }

    #[test]
    fn test_constraint_system_depth_increments() {
        let cs = ConstraintSystem::new();
        let cs2 = cs.with_branch_true(sym("c1"));
        let cs3 = cs2.with_branch_false(sym("c2"));
        assert_eq!(cs3.depth, 2);
    }
}
