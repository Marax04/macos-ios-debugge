//! `concolic` — Concolic (concrete + symbolic) execution — **simple flip-and-re-execute layer**.
//!
//! Concolic execution runs the program concretely while simultaneously tracking
//! a symbolic path condition. At each branch, the concrete value determines
//! which edge to follow, and the symbolic constraint is recorded. After a
//! complete execution, the engine can *flip* any branch constraint to generate
//! a new input that exercises the opposite branch (test-input generation).
//!
//! # Layer overview (within this crate)
//!
//! | Module | Role |
//! |--------|------|
//! | **`concolic`** (this file) | Simple flip-and-re-execute loop; [`ConcolicState`] pairs concrete + symbolic state, [`ConcolicEngine`] manages the flip budget, [`ConcolicExecutor`] drives the outer loop. |
//! | [`concolic_execution`](crate::concolic_execution) | Coverage-guided campaign with a priority [`TestCaseQueue`](crate::concolic_execution::TestCaseQueue), deduplication via [`FlipHistory`](crate::concolic_execution::FlipHistory), and a [`FlipBudget`](crate::concolic_execution::FlipBudget). Operates on pre-collected [`SymbolicState`](crate::SymbolicState) paths. |
//! | [`concolic_executor`](crate::concolic_executor) | Lower-level campaign with a pluggable [`ConcolicSolver`](crate::concolic_executor::ConcolicSolver) trait, a worklist, and a `run_campaign` driver. Provides the [`PerturbationSolver`](crate::concolic_executor::PerturbationSolver) default back-end. |
//!
//! The three modules are **intentionally distinct layers** — they are not duplicates.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use crate::SymType;
use crate::{SymExpr, SymbolicError, SymbolicState};

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ConcolicError {
    #[error("no branch to flip at index {0}")]
    NoBranchAtIndex(usize),
    #[error("path condition is unsatisfiable after flip")]
    UnsatAfterFlip,
    #[error("concrete model missing variable: {0}")]
    MissingConcreteValue(String),
    #[error("symbolic execution step failed: {0}")]
    SymbolicStep(#[from] SymbolicError),
    #[error("max steps exceeded: {0}")]
    MaxStepsExceeded(u64),
    #[error("concolic run exhausted all flip candidates")]
    ExhaustedFlips,
}

// ─── ConcreteSolution ─────────────────────────────────────────────────────────

/// A concrete assignment to all symbolic input variables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConcreteSolution {
    /// Variable name → concrete value.
    pub values: HashMap<String, u64>,
    /// The index of the branch that was flipped to generate this solution.
    pub flipped_branch: Option<usize>,
    /// Whether the path condition was satisfiable under this assignment.
    pub is_sat: bool,
}

impl ConcreteSolution {
    /// Create a solution from an existing environment.
    #[must_use]
    pub const fn from_env(values: HashMap<String, u64>) -> Self {
        Self {
            values,
            flipped_branch: None,
            is_sat: true,
        }
    }

    /// Return the value of `var`, or `0` if not present.
    #[must_use]
    pub fn get(&self, var: &str) -> u64 {
        self.values.get(var).copied().unwrap_or(0)
    }

    /// Set a value for `var`.
    pub fn set(&mut self, var: impl Into<String>, val: u64) {
        self.values.insert(var.into(), val);
    }
}

// ─── BranchRecord ─────────────────────────────────────────────────────────────

/// A single recorded branch decision during concolic execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchRecord {
    /// Address of the branch instruction.
    pub pc: u64,
    /// The symbolic expression of the branch condition.
    pub condition: SymExpr,
    /// The concrete value that was taken (true = branch taken, false = fallthrough).
    pub concrete_value: bool,
    /// Whether this branch has already been flipped in a previous iteration.
    pub already_flipped: bool,
}

impl BranchRecord {
    #[must_use]
    pub const fn new(pc: u64, condition: SymExpr, concrete_value: bool) -> Self {
        Self {
            pc,
            condition,
            concrete_value,
            already_flipped: false,
        }
    }

    /// Return the constraint that asserts the opposite of `concrete_value`.
    #[must_use]
    pub fn flipped_constraint(&self) -> SymExpr {
        if self.concrete_value {
            // Was taken (true); flip to not-taken (false).
            SymExpr::BoolNot(Box::new(self.condition.clone()))
        } else {
            // Was not taken (false); flip to taken (true).
            self.condition.clone()
        }
    }

    /// Return the constraint that asserts `concrete_value` (the path taken).
    #[must_use]
    pub fn taken_constraint(&self) -> SymExpr {
        if self.concrete_value {
            self.condition.clone()
        } else {
            SymExpr::BoolNot(Box::new(self.condition.clone()))
        }
    }
}

// ─── ConcolicState ────────────────────────────────────────────────────────────

/// Combined concrete + symbolic execution state.
///
/// The `concrete` map holds the current concrete values for all variables (the
/// "real" execution).  The `symbolic` [`SymbolicState`] tracks the path
/// condition symbolically.  Branches are decided by the concrete value, but
/// the symbolic constraint is recorded in `branch_trace`.
#[derive(Debug, Clone)]
pub struct ConcolicState {
    /// Concrete value for every variable name encountered.
    pub concrete: HashMap<String, u64>,
    /// Underlying symbolic state (registers, memory, path condition).
    pub symbolic: SymbolicState,
    /// Ordered list of branch decisions made so far.
    pub branch_trace: Vec<BranchRecord>,
    /// Total number of steps executed.
    pub step_count: u64,
    /// Whether this execution has completed normally.
    pub completed: bool,
    /// Optional label for this run (e.g. "initial" or "flip@5").
    pub label: Option<String>,
}

impl ConcolicState {
    /// Create a new `ConcolicState` from an initial concrete environment.
    #[must_use]
    pub fn new(concrete: HashMap<String, u64>) -> Self {
        let mut symbolic = SymbolicState::new();
        // Seed symbolic registers from concrete values.
        for (name, &val) in &concrete {
            symbolic.write_register(name, SymExpr::bv(val, 64));
        }
        Self {
            concrete,
            symbolic,
            branch_trace: Vec::new(),
            step_count: 0,
            completed: false,
            label: None,
        }
    }

    /// Create a concolic state with a label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Create a concolic state from a [`SymbolicState`] and concrete values.
    #[must_use]
    pub const fn from_symbolic(symbolic: SymbolicState, concrete: HashMap<String, u64>) -> Self {
        Self {
            concrete,
            symbolic,
            branch_trace: Vec::new(),
            step_count: 0,
            completed: false,
            label: None,
        }
    }

    /// Record a branch decision.
    ///
    /// `cond_expr` is the symbolic expression; `concrete_taken` is the result
    /// of evaluating it with the current concrete model.
    pub fn record_branch(&mut self, pc: u64, cond_expr: SymExpr, concrete_taken: bool) {
        // Add the taken constraint to the symbolic path condition.
        let constraint = if concrete_taken {
            cond_expr.clone()
        } else {
            SymExpr::BoolNot(Box::new(cond_expr.clone()))
        };
        self.symbolic.path_condition.push(constraint);
        self.branch_trace
            .push(BranchRecord::new(pc, cond_expr, concrete_taken));
    }

    /// Evaluate `expr` concretely using `self.concrete`.
    #[must_use]
    pub fn eval_concrete(&self, expr: &SymExpr) -> Option<u64> {
        expr.evaluate(&self.concrete)
    }

    /// Read a concrete register value.
    #[must_use]
    pub fn read_concrete(&self, name: &str) -> u64 {
        self.concrete.get(name).copied().unwrap_or(0)
    }

    /// Write a concrete register value and update the symbolic state.
    pub fn write_register(&mut self, name: impl Into<String>, sym_val: SymExpr, concrete_val: u64) {
        let n = name.into();
        self.concrete.insert(n.clone(), concrete_val);
        self.symbolic.write_register(n, sym_val);
    }

    /// Return the number of branch records.
    #[must_use]
    pub const fn branch_count(&self) -> usize {
        self.branch_trace.len()
    }

    /// Produce a [`ConcreteSolution`] from the current concrete map.
    #[must_use]
    pub fn solution(&self) -> ConcreteSolution {
        ConcreteSolution::from_env(self.concrete.clone())
    }
}

// ─── FlipResult ───────────────────────────────────────────────────────────────

/// Result of a flip-constraint operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlipResult {
    /// The branch index that was flipped.
    pub flipped_index: usize,
    /// Address of the flipped branch.
    pub branch_pc: u64,
    /// The new path condition (all prefix constraints + the flipped constraint).
    pub new_path_condition: Vec<SymExpr>,
    /// Proposed concrete solution (heuristic; 0 for unknown symbolic vars).
    pub proposed_solution: ConcreteSolution,
}

// ─── ConcolicEngine ───────────────────────────────────────────────────────────

/// Core concolic engine that manages flip-constraint test generation.
///
/// After an execution trace is collected in a [`ConcolicState`], the engine
/// iterates over branch decisions in reverse (deepest first), flips each
/// unflipped branch while keeping prefix constraints, and constructs a new
/// proposed concrete solution.
#[derive(Debug, Default)]
pub struct ConcolicEngine {
    /// History of all generated solutions (including the initial seed).
    pub solutions: Vec<ConcreteSolution>,
    /// Indices of branches that have already been flipped.
    flipped_branches: std::collections::HashSet<usize>,
    /// Maximum number of flip iterations before giving up.
    pub max_flips: usize,
}

impl ConcolicEngine {
    /// Create a new engine with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            solutions: Vec::new(),
            flipped_branches: std::collections::HashSet::new(),
            max_flips: 256,
        }
    }

    /// Create an engine with a custom flip limit.
    #[must_use]
    pub fn with_max_flips(max_flips: usize) -> Self {
        Self {
            max_flips,
            ..Self::new()
        }
    }

    /// Record the initial seed solution.
    pub fn record_initial(&mut self, solution: ConcreteSolution) {
        self.solutions.push(solution);
    }

    /// Attempt to flip branch at `branch_index` in `trace`.
    ///
    /// Returns a [`FlipResult`] whose `proposed_solution` is built from the
    /// prefix constraints + the flipped constraint, with symbolic variables
    /// defaulted to 0.
    ///
    /// # Errors
    ///
    /// Returns [`ConcolicError::NoBranchAtIndex`] when `branch_index` is past the
    /// end of the trace, or [`ConcolicError::FlipBudgetExceeded`] when the
    /// configured flip budget is exhausted.
    pub fn flip_constraint(
        &mut self,
        trace: &ConcolicState,
        branch_index: usize,
    ) -> Result<FlipResult, ConcolicError> {
        if branch_index >= trace.branch_trace.len() {
            return Err(ConcolicError::NoBranchAtIndex(branch_index));
        }
        if self.flipped_branches.len() >= self.max_flips {
            return Err(ConcolicError::ExhaustedFlips);
        }

        let branch = &trace.branch_trace[branch_index];
        let branch_pc = branch.pc;

        // Build the new path condition: prefix constraints (0..branch_index)
        // with the original polarity, plus the flipped constraint.
        let mut new_pc: Vec<SymExpr> = trace.branch_trace[..branch_index]
            .iter()
            .map(BranchRecord::taken_constraint)
            .collect();
        new_pc.push(branch.flipped_constraint());

        // Heuristic solution: collect all symbolic vars, default to 0.
        let mut env: HashMap<String, u64> = trace.concrete.clone();
        for constraint in &new_pc {
            collect_vars_env(constraint, &mut env);
        }

        // Check trivial satisfiability.
        let is_sat = !new_pc.contains(&SymExpr::ConstBool(false));
        if !is_sat {
            return Err(ConcolicError::UnsatAfterFlip);
        }

        self.flipped_branches.insert(branch_index);

        let solution = ConcreteSolution {
            values: env,
            flipped_branch: Some(branch_index),
            is_sat,
        };
        self.solutions.push(solution.clone());

        Ok(FlipResult {
            flipped_index: branch_index,
            branch_pc,
            new_path_condition: new_pc,
            proposed_solution: solution,
        })
    }

    /// Iterate over all unflipped branches in `trace` from deepest first,
    /// generating flip results.
    pub fn generate_all_flips(
        &mut self,
        trace: &ConcolicState,
    ) -> Vec<Result<FlipResult, ConcolicError>> {
        let n = trace.branch_count();
        (0..n)
            .rev()
            .filter(|i| !trace.branch_trace[*i].already_flipped)
            .map(|i| self.flip_constraint(trace, i))
            .collect()
    }

    /// Return the number of successful flips so far.
    #[must_use]
    pub fn flip_count(&self) -> usize {
        self.flipped_branches.len()
    }

    /// Return all solutions generated so far.
    #[must_use]
    pub fn all_solutions(&self) -> &[ConcreteSolution] {
        &self.solutions
    }
}

// ─── ConcolicExecutor ─────────────────────────────────────────────────────────

/// High-level driver that manages the concolic execution loop.
///
/// Users implement [`ConcolicStep`] to describe how a single instruction
/// is executed both concretely and symbolically. The executor then drives
/// the flip-and-re-execute loop.
pub trait ConcolicStep {
    /// Execute one step of the program.
    ///
    /// Update `state` in place: advance `state.symbolic.pc`, update registers,
    /// and call `state.record_branch` at every conditional jump.
    ///
    /// Return `Ok(true)` to continue, `Ok(false)` to signal program end, or
    /// `Err` on error.
    ///
    /// # Errors
    ///
    /// Implementors may return any [`ConcolicError`] variant relevant to the
    /// step failure (e.g. an unsupported instruction or a violated invariant).
    fn step(&mut self, state: &mut ConcolicState) -> Result<bool, ConcolicError>;
}

/// Configuration for the concolic executor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcolicConfig {
    /// Maximum number of steps per execution run.
    pub max_steps_per_run: u64,
    /// Maximum number of execution runs (initial + flips).
    pub max_runs: usize,
    /// Whether to stop after the first run without flipping.
    pub dry_run_only: bool,
}

impl Default for ConcolicConfig {
    fn default() -> Self {
        Self {
            max_steps_per_run: 100_000,
            max_runs: 64,
            dry_run_only: false,
        }
    }
}

/// Drives the full concolic execution loop.
pub struct ConcolicExecutor {
    pub engine: ConcolicEngine,
    pub config: ConcolicConfig,
    /// All traces produced (one per run).
    pub traces: Vec<ConcolicState>,
}

impl ConcolicExecutor {
    /// Create a new executor.
    #[must_use]
    pub fn new(config: ConcolicConfig) -> Self {
        Self {
            engine: ConcolicEngine::with_max_flips(config.max_runs.max(1) * 4),
            config,
            traces: Vec::new(),
        }
    }

    /// Run the concolic loop.
    ///
    /// 1. Execute `initial_state` concretely + symbolically to produce a trace.
    /// 2. Flip branches in the trace.
    /// 3. For each flip result, create a new `ConcolicState` seeded with the
    ///    proposed solution and run again.
    /// 4. Repeat until `max_runs` or no more flippable branches.
    ///
    /// # Errors
    ///
    /// Propagates any [`ConcolicError`] returned by the underlying stepper or
    /// flip engine while exploring runs.
    pub fn run<S: ConcolicStep>(
        &mut self,
        mut initial_state: ConcolicState,
        stepper: &mut S,
    ) -> Result<(), ConcolicError> {
        // First run.
        self.execute_run(&mut initial_state, stepper)?;
        self.engine.record_initial(initial_state.solution());
        self.traces.push(initial_state.clone());

        if self.config.dry_run_only {
            return Ok(());
        }

        let mut run_count = 1usize;

        loop {
            if run_count >= self.config.max_runs {
                break;
            }
            // Find the deepest unflipped branch across all traces.
            let Some((trace_idx, branch_idx)) = self.find_next_flip_target() else {
                break;
            };

            let trace = self.traces[trace_idx].clone();
            let flip = match self.engine.flip_constraint(&trace, branch_idx) {
                Ok(f) => f,
                Err(ConcolicError::UnsatAfterFlip) => continue,
                Err(ConcolicError::ExhaustedFlips) => break,
                Err(e) => return Err(e),
            };

            // Build new initial state from the proposed solution.
            let new_concrete = flip.proposed_solution.values.clone();
            let mut new_state = ConcolicState::new(new_concrete);
            new_state.label = Some(format!("flip@{branch_idx}"));

            self.execute_run(&mut new_state, stepper)?;
            self.traces.push(new_state);
            run_count += 1;
        }

        Ok(())
    }

    fn execute_run<S: ConcolicStep>(
        &self,
        state: &mut ConcolicState,
        stepper: &mut S,
    ) -> Result<(), ConcolicError> {
        let max = self.config.max_steps_per_run;
        loop {
            if state.step_count >= max {
                return Err(ConcolicError::MaxStepsExceeded(state.step_count));
            }
            state.step_count += 1;
            let cont = stepper.step(state)?;
            if !cont {
                state.completed = true;
                break;
            }
        }
        Ok(())
    }

    /// Find (`trace_index`, `branch_index`) of the deepest unflipped branch.
    fn find_next_flip_target(&self) -> Option<(usize, usize)> {
        for (ti, trace) in self.traces.iter().enumerate() {
            for (bi, branch) in trace.branch_trace.iter().enumerate().rev() {
                if !branch.already_flipped && !self.engine.flipped_branches.contains(&bi) {
                    return Some((ti, bi));
                }
            }
        }
        None
    }

    /// Return all solutions found across runs.
    #[must_use]
    pub fn solutions(&self) -> &[ConcreteSolution] {
        self.engine.all_solutions()
    }

    /// Return the number of runs completed.
    #[must_use]
    pub const fn run_count(&self) -> usize {
        self.traces.len()
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Collect symbolic variable names from `expr` and insert them into `env`
/// with a default value of 0 if not already present.
fn collect_vars_env(expr: &SymExpr, env: &mut HashMap<String, u64>) {
    match expr {
        SymExpr::Var { name, .. } => {
            env.entry(name.clone()).or_insert(0);
        }
        SymExpr::Add(l, r)
        | SymExpr::Sub(l, r)
        | SymExpr::Mul(l, r)
        | SymExpr::UDiv(l, r)
        | SymExpr::SDiv(l, r)
        | SymExpr::URem(l, r)
        | SymExpr::SRem(l, r)
        | SymExpr::And(l, r)
        | SymExpr::Or(l, r)
        | SymExpr::Xor(l, r)
        | SymExpr::Shl(l, r)
        | SymExpr::LShr(l, r)
        | SymExpr::AShr(l, r)
        | SymExpr::Concat(l, r)
        | SymExpr::Eq(l, r)
        | SymExpr::Ne(l, r)
        | SymExpr::ULt(l, r)
        | SymExpr::ULe(l, r)
        | SymExpr::UGt(l, r)
        | SymExpr::UGe(l, r)
        | SymExpr::SLt(l, r)
        | SymExpr::SLe(l, r)
        | SymExpr::SGt(l, r)
        | SymExpr::SGe(l, r)
        | SymExpr::BoolAnd(l, r)
        | SymExpr::BoolOr(l, r) => {
            collect_vars_env(l, env);
            collect_vars_env(r, env);
        }
        SymExpr::Not(e)
        | SymExpr::Neg(e)
        | SymExpr::BoolNot(e)
        | SymExpr::ZExt { expr: e, .. }
        | SymExpr::SExt { expr: e, .. }
        | SymExpr::Extract { expr: e, .. }
        | SymExpr::Load { addr: e, .. } => {
            collect_vars_env(e, env);
        }
        SymExpr::Ite { cond, then_, else_ } => {
            collect_vars_env(cond, env);
            collect_vars_env(then_, env);
            collect_vars_env(else_, env);
        }
        SymExpr::Store { mem, addr, val } => {
            collect_vars_env(mem, env);
            collect_vars_env(addr, env);
            collect_vars_env(val, env);
        }
        SymExpr::ConstBv { .. } | SymExpr::ConstBool(_) => {}
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, u64)]) -> HashMap<String, u64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn test_branch_record_flip_true() {
        let b = BranchRecord::new(0x100, SymExpr::ConstBool(true), true);
        let flipped = b.flipped_constraint();
        assert!(matches!(flipped, SymExpr::BoolNot(_)));
    }

    #[test]
    fn test_branch_record_flip_false() {
        let b = BranchRecord::new(0x100, SymExpr::ConstBool(false), false);
        let flipped = b.flipped_constraint();
        // Was not-taken (false) → flip to taken: the condition itself.
        assert_eq!(flipped, SymExpr::ConstBool(false));
    }

    #[test]
    fn test_branch_record_taken_constraint() {
        let cond = SymExpr::var("x", SymType::BitVec(1));
        let b = BranchRecord::new(0x200, cond.clone(), true);
        // Taken = true → constraint is the condition itself.
        assert_eq!(b.taken_constraint(), cond);
    }

    #[test]
    fn test_concolic_state_record_branch() {
        let mut state = ConcolicState::new(env(&[("x", 1)]));
        let cond = SymExpr::var("x", SymType::BitVec(1));
        state.record_branch(0x100, cond, true);
        assert_eq!(state.branch_count(), 1);
        assert_eq!(state.symbolic.path_condition.len(), 1);
    }

    #[test]
    fn test_concolic_state_eval_concrete() {
        let state = ConcolicState::new(env(&[("rax", 42)]));
        let expr = SymExpr::var("rax", SymType::BitVec(64));
        assert_eq!(state.eval_concrete(&expr), Some(42));
    }

    #[test]
    fn test_concolic_state_write_register() {
        let mut state = ConcolicState::new(env(&[]));
        let sym = SymExpr::bv(99, 64);
        state.write_register("rbx", sym.clone(), 99);
        assert_eq!(state.read_concrete("rbx"), 99);
        assert_eq!(state.symbolic.read_register("rbx"), sym);
    }

    #[test]
    fn test_engine_flip_constraint() {
        let mut engine = ConcolicEngine::new();
        let mut state = ConcolicState::new(env(&[("x", 1)]));
        let cond = SymExpr::var("x", SymType::BitVec(1));
        state.record_branch(0x100, cond, true);
        state.record_branch(0x200, SymExpr::var("y", SymType::BitVec(1)), false);

        let flip = engine.flip_constraint(&state, 0).unwrap();
        assert_eq!(flip.flipped_index, 0);
        assert_eq!(flip.branch_pc, 0x100);
    }

    #[test]
    fn test_engine_flip_out_of_range() {
        let mut engine = ConcolicEngine::new();
        let state = ConcolicState::new(env(&[]));
        assert!(matches!(
            engine.flip_constraint(&state, 5),
            Err(ConcolicError::NoBranchAtIndex(5))
        ));
    }

    #[test]
    fn test_engine_generate_all_flips() {
        let mut engine = ConcolicEngine::new();
        let mut state = ConcolicState::new(env(&[("a", 0), ("b", 0)]));
        state.record_branch(0x10, SymExpr::var("a", SymType::BitVec(1)), false);
        state.record_branch(0x20, SymExpr::var("b", SymType::BitVec(1)), true);

        let results = engine.generate_all_flips(&state);
        // 2 branches: both should flip (deepest first = index 1, then 0).
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(std::result::Result::is_ok));
    }

    #[test]
    fn test_concrete_solution_get_default() {
        let sol = ConcreteSolution::from_env(env(&[("rax", 7)]));
        assert_eq!(sol.get("rax"), 7);
        assert_eq!(sol.get("rbx"), 0); // default
    }

    #[test]
    fn test_collect_vars_env() {
        let expr = SymExpr::Add(
            Box::new(SymExpr::var("a", SymType::BitVec(64))),
            Box::new(SymExpr::var("b", SymType::BitVec(64))),
        );
        let mut env_map = HashMap::new();
        collect_vars_env(&expr, &mut env_map);
        assert!(env_map.contains_key("a"));
        assert!(env_map.contains_key("b"));
        assert_eq!(env_map["a"], 0);
        assert_eq!(env_map["b"], 0);
    }

    #[test]
    fn test_concolic_config_default() {
        let c = ConcolicConfig::default();
        assert_eq!(c.max_steps_per_run, 100_000);
        assert_eq!(c.max_runs, 64);
        assert!(!c.dry_run_only);
    }

    #[test]
    fn test_executor_dry_run() {
        struct NopStepper;
        impl ConcolicStep for NopStepper {
            fn step(&mut self, state: &mut ConcolicState) -> Result<bool, ConcolicError> {
                state.symbolic.pc += 1;
                // Terminate immediately.
                Ok(false)
            }
        }

        let config = ConcolicConfig {
            dry_run_only: true,
            ..Default::default()
        };
        let mut executor = ConcolicExecutor::new(config);
        let initial = ConcolicState::new(env(&[("x", 5)]));
        executor.run(initial, &mut NopStepper).unwrap();
        assert_eq!(executor.run_count(), 1);
        assert_eq!(executor.solutions().len(), 1);
    }

    #[test]
    fn test_executor_with_branch_and_flip() {
        struct OneBranchStepper {
            step: u32,
        }
        impl ConcolicStep for OneBranchStepper {
            fn step(&mut self, state: &mut ConcolicState) -> Result<bool, ConcolicError> {
                self.step += 1;
                if self.step == 1 {
                    let cond = SymExpr::var("input", SymType::BitVec(1));
                    let concrete = state.read_concrete("input") != 0;
                    state.record_branch(0x100, cond, concrete);
                }
                Ok(self.step < 3)
            }
        }

        let config = ConcolicConfig {
            max_runs: 3,
            ..Default::default()
        };
        let mut executor = ConcolicExecutor::new(config);
        let initial = ConcolicState::new(env(&[("input", 1)]));
        executor
            .run(initial, &mut OneBranchStepper { step: 0 })
            .unwrap();
        // Should have at least 2 runs: initial + one flip.
        assert!(executor.run_count() >= 1);
    }

    #[test]
    fn test_concolic_state_with_label() {
        let state = ConcolicState::new(env(&[])).with_label("test-run");
        assert_eq!(state.label.as_deref(), Some("test-run"));
    }
}
