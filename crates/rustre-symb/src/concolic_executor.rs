//! `concolic_executor` — Solver-backed concolic campaign with pluggable SMT backend.
//!
//! **Layer**: the lowest-level concolic campaign driver.  Unlike
//! [`concolic`](crate::concolic) (flip-and-re-execute) and
//! [`concolic_execution`](crate::concolic_execution) (coverage-guided priority
//! queue), this module owns the *concrete execution loop* and delegates
//! constraint solving to a [`ConcolicSolver`] trait.  The default back-end is
//! the lightweight [`PerturbationSolver`]; a Z3 backend can be plugged in.
//!
//! Runs the binary concretely (via a lightweight emulation model) while
//! building the symbolic path constraint in parallel.  At each conditional
//! branch the engine:
//!
//! 1. Records the concrete outcome and adds the corresponding symbolic
//!    constraint to the path condition.
//! 2. Periodically *negates* one previously-taken branch constraint to
//!    generate a new, diverging concrete input via the solver.
//! 3. Feeds new inputs back into the worklist so coverage grows monotonically.
//!
//! # Layer overview (within this crate)
//!
//! See [`concolic`](crate::concolic) module docs for the full table.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{SymExpr, SymType, SymbolicError, SymbolicState};

// ─── Concrete machine word ───────────────────────────────────────────────────

/// A concrete 64-bit machine value.
pub type ConcreteVal = u64;

// ─── Input / seed ────────────────────────────────────────────────────────────

/// One concrete test-case input (a mapping from symbolic variable name → value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConcreteInput {
    pub values: HashMap<String, ConcreteVal>,
    /// Execution generation (0 = seed).
    pub generation: u32,
    /// Which branch index was negated to derive this input (`None` = seed).
    pub negated_branch: Option<usize>,
}

impl ConcreteInput {
    /// Create a seed input with all symbolic vars set to zero.
    pub fn seed(vars: impl IntoIterator<Item = String>) -> Self {
        Self {
            values: vars.into_iter().map(|v| (v, 0u64)).collect(),
            generation: 0,
            negated_branch: None,
        }
    }

    /// Evaluate a [`SymExpr`] under this concrete assignment.
    #[must_use] 
    pub fn eval(&self, expr: &SymExpr) -> Option<ConcreteVal> {
        eval_expr(expr, &self.values)
    }
}

fn eval_expr(expr: &SymExpr, env: &HashMap<String, ConcreteVal>) -> Option<ConcreteVal> {
    match expr {
        SymExpr::ConstBv { val, .. } => Some(*val),
        SymExpr::ConstBool(b) => Some(u64::from(*b)),
        SymExpr::Var { name, .. } => env.get(name).copied(),
        SymExpr::Add(a, b) => Some(eval_expr(a, env)?.wrapping_add(eval_expr(b, env)?)),
        SymExpr::Sub(a, b) => Some(eval_expr(a, env)?.wrapping_sub(eval_expr(b, env)?)),
        SymExpr::Mul(a, b) => Some(eval_expr(a, env)?.wrapping_mul(eval_expr(b, env)?)),
        SymExpr::UDiv(a, b) => {
            let d = eval_expr(b, env)?;
            if d == 0 { None } else { Some(eval_expr(a, env)? / d) }
        }
        SymExpr::And(a, b) => Some(eval_expr(a, env)? & eval_expr(b, env)?),
        SymExpr::Or(a, b) => Some(eval_expr(a, env)? | eval_expr(b, env)?),
        SymExpr::Xor(a, b) => Some(eval_expr(a, env)? ^ eval_expr(b, env)?),
        SymExpr::Not(a) => Some(!eval_expr(a, env)?),
        SymExpr::Neg(a) => Some(eval_expr(a, env)?.wrapping_neg()),
        SymExpr::Shl(a, b) => Some(eval_expr(a, env)? << (eval_expr(b, env)? & 63)),
        SymExpr::LShr(a, b) => Some(eval_expr(a, env)? >> (eval_expr(b, env)? & 63)),
        SymExpr::AShr(a, b) => {
            let v = eval_expr(a, env)? as i64;
            let s = eval_expr(b, env)? & 63;
            Some((v >> s) as u64)
        }
        SymExpr::Eq(a, b) => Some(u64::from(eval_expr(a, env)? == eval_expr(b, env)?)),
        SymExpr::Ne(a, b) => Some(u64::from(eval_expr(a, env)? != eval_expr(b, env)?)),
        SymExpr::ULt(a, b) => Some(u64::from(eval_expr(a, env)? < eval_expr(b, env)?)),
        SymExpr::ULe(a, b) => Some(u64::from(eval_expr(a, env)? <= eval_expr(b, env)?)),
        SymExpr::SLt(a, b) => {
            Some(u64::from((eval_expr(a, env)? as i64) < (eval_expr(b, env)? as i64)))
        }
        SymExpr::BoolAnd(a, b) => {
            Some(u64::from(eval_expr(a, env)? != 0 && eval_expr(b, env)? != 0))
        }
        SymExpr::BoolOr(a, b) => {
            Some(u64::from(eval_expr(a, env)? != 0 || eval_expr(b, env)? != 0))
        }
        SymExpr::BoolNot(a) => Some(u64::from(eval_expr(a, env)? == 0)),
        SymExpr::ZExt { expr, target_width } => {
            let mask = if *target_width >= 64 { u64::MAX } else { (1u64 << target_width) - 1 };
            Some(eval_expr(expr, env)? & mask)
        }
        SymExpr::SExt { expr, target_width } => {
            let v = eval_expr(expr, env)?;
            // sign extend: assume source is 64-bit already for simplicity
            let shift = 64u32.saturating_sub(*target_width);
            Some(((v as i64) << shift >> shift) as u64)
        }
        SymExpr::Concat(hi, lo) => {
            // heuristic: lo occupies lower 32 bits
            Some((eval_expr(hi, env)? << 32) | (eval_expr(lo, env)? & 0xFFFF_FFFF))
        }
        SymExpr::Ite { cond, then_, else_ } => {
            if eval_expr(cond, env)? != 0 {
                eval_expr(then_, env)
            } else {
                eval_expr(else_, env)
            }
        }
        _ => None,
    }
}

// ─── Branch record ───────────────────────────────────────────────────────────

/// A single conditional branch encountered during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchRecord {
    /// Program counter of the branch instruction.
    pub pc: u64,
    /// Symbolic condition at this branch.
    pub condition: SymExpr,
    /// Concrete outcome: `true` = taken.
    pub taken: bool,
    /// Depth in current execution path.
    pub depth: u32,
}

impl BranchRecord {
    /// Return the symbolic constraint for the *taken* direction.
    #[must_use] 
    pub fn taken_constraint(&self) -> SymExpr {
        if self.taken {
            self.condition.clone()
        } else {
            SymExpr::BoolNot(Box::new(self.condition.clone()))
        }
    }

    /// Return the constraint for the *not-taken* direction.
    #[must_use] 
    pub fn negated_constraint(&self) -> SymExpr {
        if self.taken {
            SymExpr::BoolNot(Box::new(self.condition.clone()))
        } else {
            self.condition.clone()
        }
    }
}

// ─── Path condition ───────────────────────────────────────────────────────────

/// The conjunction of constraints accumulated on the current path.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathConstraint {
    pub branches: Vec<BranchRecord>,
}

impl PathConstraint {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new branch constraint.
    pub fn push(&mut self, rec: BranchRecord) {
        self.branches.push(rec);
    }

    /// Build the conjunction of all taken-direction constraints.
    #[must_use] 
    pub fn conjunction(&self) -> Option<SymExpr> {
        let mut it = self.branches.iter().map(BranchRecord::taken_constraint);
        let first = it.next()?;
        Some(it.fold(first, |acc, c| SymExpr::BoolAnd(Box::new(acc), Box::new(c))))
    }

    /// Build a conjunction with branch `idx` negated.
    #[must_use] 
    pub fn conjunction_negate(&self, idx: usize) -> Option<SymExpr> {
        let mut it = self.branches.iter().enumerate().map(|(i, b)| {
            if i == idx { b.negated_constraint() } else { b.taken_constraint() }
        });
        let first = it.next()?;
        Some(it.fold(first, |acc, c| SymExpr::BoolAnd(Box::new(acc), Box::new(c))))
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.branches.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.branches.is_empty()
    }
}

// ─── Naive solver ─────────────────────────────────────────────────────────────

/// A minimal constraint solver used when no external SMT backend is available.
///
/// Performs purely syntactic simplification and constant propagation.  For real
/// deployments, plug in the `rustre-symb-z3` backend.
pub trait ConcolicSolver: Send + Sync {
    /// Given a constraint (conjunction) and the set of free symbolic
    /// variables, return a concrete assignment satisfying the constraint, or
    /// `None` if unsatisfiable / unknown.
    fn solve(
        &self,
        constraint: &SymExpr,
        vars: &HashMap<String, SymType>,
    ) -> Option<HashMap<String, ConcreteVal>>;
}

/// Trivial solver: tries ±1 perturbations around the seed.
#[derive(Debug, Default)]
pub struct PerturbationSolver {
    pub seed_delta: u64,
}

impl ConcolicSolver for PerturbationSolver {
    fn solve(
        &self,
        constraint: &SymExpr,
        vars: &HashMap<String, SymType>,
    ) -> Option<HashMap<String, ConcreteVal>> {
        // Enumerate small perturbations and return the first satisfying one.
        for delta in [1u64, 2, 4, 8, 16, 255, 256, 0xFFFF, 0xFFFF_FFFF] {
            let candidate: HashMap<String, ConcreteVal> =
                vars.keys().map(|v| (v.clone(), delta)).collect();
            if eval_expr(constraint, &candidate).is_some_and(|v| v != 0) {
                return Some(candidate);
            }
        }
        None
    }
}

// ─── ConcolicExecutor ─────────────────────────────────────────────────────────

/// Configuration for the concolic executor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcolicConfig {
    /// Maximum number of branch negations to attempt.
    pub max_negations: usize,
    /// Maximum depth of a single concrete execution.
    pub max_depth: u32,
    /// Number of seeds to start with.
    pub seed_count: usize,
    /// Negation interval: negate every N branches.
    pub negation_interval: usize,
    /// Maximum total inputs to generate.
    pub max_inputs: usize,
}

impl Default for ConcolicConfig {
    fn default() -> Self {
        Self {
            max_negations: 64,
            max_depth: 1024,
            seed_count: 1,
            negation_interval: 4,
            max_inputs: 256,
        }
    }
}

/// Coverage information: set of (pc, `branch_taken`) pairs observed.
#[derive(Debug, Default, Clone)]
pub struct CoverageMap {
    covered: HashSet<(u64, bool)>,
}

impl CoverageMap {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a branch outcome; returns `true` if this is a new coverage point.
    pub fn record(&mut self, pc: u64, taken: bool) -> bool {
        self.covered.insert((pc, taken))
    }

    #[must_use] 
    pub fn coverage_count(&self) -> usize {
        self.covered.len()
    }

    /// Return `true` if both sides of the branch at `pc` have been covered.
    #[must_use] 
    pub fn is_fully_covered(&self, pc: u64) -> bool {
        self.covered.contains(&(pc, true)) && self.covered.contains(&(pc, false))
    }
}

/// Statistics collected during a concolic run.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ConcolicStats {
    pub total_executions: u64,
    pub total_branches: u64,
    pub new_coverage_points: u64,
    pub solved_constraints: u64,
    pub failed_solves: u64,
    pub inputs_generated: u64,
}

/// Callback invoked on each concrete execution step.
///
/// Return `Ok(())` to continue or `Err(SymbolicError)` to abort.
pub type StepCallback = Box<dyn Fn(u64, &ConcreteInput, &PathConstraint) -> Result<(), SymbolicError> + Send + Sync>;

/// Result of a single concrete+symbolic execution.
#[derive(Debug)]
pub struct ExecutionResult {
    pub input: ConcreteInput,
    pub path: PathConstraint,
    pub coverage_points: usize,
    pub depth_reached: u32,
    pub error: Option<SymbolicError>,
}

/// The main concolic executor.
///
/// ```text
///   seed input ──► concrete execution ──► path constraint
///                                              │
///                              negate branch N ▼
///                         SMT solve ──► new concrete input
///                                              │
///                              push onto worklist ──► repeat
/// ```
pub struct ConcolicExecutor {
    config: ConcolicConfig,
    solver: Box<dyn ConcolicSolver>,
    symbolic_vars: HashMap<String, SymType>,
    worklist: VecDeque<ConcreteInput>,
    seen_inputs: HashSet<Vec<(String, ConcreteVal)>>,
    coverage: CoverageMap,
    stats: ConcolicStats,
    results: Vec<ExecutionResult>,
    step_cb: Option<StepCallback>,
}

impl ConcolicExecutor {
    /// Create a new executor with the given solver and symbolic variable set.
    #[must_use] 
    pub fn new(
        config: ConcolicConfig,
        solver: Box<dyn ConcolicSolver>,
        symbolic_vars: HashMap<String, SymType>,
    ) -> Self {
        Self {
            config,
            solver,
            symbolic_vars,
            worklist: VecDeque::new(),
            seen_inputs: HashSet::new(),
            coverage: CoverageMap::new(),
            stats: ConcolicStats::default(),
            results: Vec::new(),
            step_cb: None,
        }
    }

    /// Convenience constructor with the default perturbation solver.
    #[must_use] 
    pub fn with_perturbation_solver(
        config: ConcolicConfig,
        symbolic_vars: HashMap<String, SymType>,
    ) -> Self {
        Self::new(config, Box::new(PerturbationSolver::default()), symbolic_vars)
    }

    /// Register a step callback (called after each concrete execution step).
    pub fn on_step(&mut self, cb: StepCallback) {
        self.step_cb = Some(cb);
    }

    /// Seed the executor with an initial concrete input.
    pub fn add_seed(&mut self, input: ConcreteInput) {
        if self.try_enqueue(input.clone()) {
            self.worklist.push_back(input);
        }
    }

    /// Add default zero-seed for all symbolic variables.
    pub fn add_zero_seed(&mut self) {
        let seed = ConcreteInput::seed(self.symbolic_vars.keys().cloned());
        self.add_seed(seed);
    }

    fn try_enqueue(&mut self, input: ConcreteInput) -> bool {
        let mut key: Vec<(String, ConcreteVal)> = input.values.iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        key.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        self.seen_inputs.insert(key)
    }

    /// Execute one concrete input and record the path constraint.
    ///
    /// The caller must supply a *concrete step function* that drives the
    /// emulator forward.  The function receives the current PC, the concrete
    /// environment, and a mutable reference to the path constraint.  It
    /// returns `Some((next_pc, branch_record))` if a branch was encountered,
    /// or `None` to terminate execution.
    pub fn run_concrete<F>(
        &mut self,
        input: ConcreteInput,
        mut step: F,
    ) -> ExecutionResult
    where
        F: FnMut(
            u64,
            &ConcreteInput,
            &mut PathConstraint,
        ) -> Option<(u64, Option<BranchRecord>)>,
    {
        let mut path = PathConstraint::new();
        let mut pc: u64 = 0;
        let mut depth = 0u32;
        let mut error = None;

        loop {
            if depth >= self.config.max_depth {
                break;
            }
            if let Some(cb) = &self.step_cb
                && let Err(e) = cb(pc, &input, &path) {
                    error = Some(e);
                    break;
                }
            match step(pc, &input, &mut path) {
                None => break,
                Some((next_pc, branch)) => {
                    if let Some(b) = branch {
                        let is_new = self.coverage.record(b.pc, b.taken);
                        if is_new {
                            self.stats.new_coverage_points += 1;
                        }
                        self.stats.total_branches += 1;
                        path.push(b);
                    }
                    pc = next_pc;
                    depth += 1;
                }
            }
        }

        self.stats.total_executions += 1;
        let cov = self.coverage.coverage_count();
        ExecutionResult {
            input,
            path,
            coverage_points: cov,
            depth_reached: depth,
            error,
        }
    }

    /// Generate new inputs by negating branch constraints from a completed
    /// execution result, then enqueue them.
    pub fn generate_inputs_from_result(&mut self, result: &ExecutionResult) {
        let n = result.path.len();
        let mut negated = 0;

        for idx in (0..n).step_by(self.config.negation_interval.max(1)) {
            if negated >= self.config.max_negations {
                break;
            }
            if self.stats.inputs_generated as usize >= self.config.max_inputs {
                break;
            }
            // Skip if both branch directions are already covered.
            let branch_pc = result.path.branches[idx].pc;
            if self.coverage.is_fully_covered(branch_pc) {
                continue;
            }
            // Build the negated path constraint.
            let Some(negated_formula) = result.path.conjunction_negate(idx) else {
                continue;
            };
            // Solve for new concrete values.
            match self.solver.solve(&negated_formula, &self.symbolic_vars) {
                Some(values) => {
                    let new_input = ConcreteInput {
                        values,
                        generation: result.input.generation + 1,
                        negated_branch: Some(idx),
                    };
                    if self.try_enqueue(new_input.clone()) {
                        self.worklist.push_back(new_input);
                        self.stats.solved_constraints += 1;
                        self.stats.inputs_generated += 1;
                        negated += 1;
                    }
                }
                None => {
                    self.stats.failed_solves += 1;
                }
            }
        }
    }

    /// Run the full concolic campaign: process worklist, generate new inputs,
    /// repeat until budget exhausted.
    ///
    /// The `step` closure must implement the concrete execution step (see
    /// [`Self::run_concrete`]).
    pub fn run_campaign<F>(&mut self, mut step: F) -> &[ExecutionResult]
    where
        F: FnMut(
            u64,
            &ConcreteInput,
            &mut PathConstraint,
        ) -> Option<(u64, Option<BranchRecord>)>,
    {
        // Add default seed if the worklist is empty.
        if self.worklist.is_empty() {
            self.add_zero_seed();
        }

        while let Some(input) = self.worklist.pop_front() {
            if self.stats.inputs_generated as usize >= self.config.max_inputs
                && self.results.len() >= self.config.max_inputs
            {
                break;
            }
            let result = self.run_concrete(input, &mut step);
            self.generate_inputs_from_result(&result);
            self.results.push(result);
        }

        &self.results
    }

    /// Return accumulated statistics.
    #[must_use] 
    pub const fn stats(&self) -> &ConcolicStats {
        &self.stats
    }

    /// Return the current coverage map.
    #[must_use] 
    pub const fn coverage(&self) -> &CoverageMap {
        &self.coverage
    }

    /// Drain all completed execution results.
    pub fn take_results(&mut self) -> Vec<ExecutionResult> {
        std::mem::take(&mut self.results)
    }
}

// ─── Integration helper ───────────────────────────────────────────────────────

/// Build a [`SymbolicState`]-driven step function for use with
/// [`ConcolicExecutor::run_campaign`].
///
/// This is a higher-level adapter that runs one instruction of a
/// [`SymbolicState`] concretely and records the branch constraint if the
/// instruction is a conditional branch.
pub struct SymbolicStateDriver {
    pub state: SymbolicState,
}

impl SymbolicStateDriver {
    #[must_use] 
    pub const fn new(state: SymbolicState) -> Self {
        Self { state }
    }

    /// Evaluate the current PC register concretely.
    #[must_use] 
    pub fn concrete_pc(&self, input: &ConcreteInput) -> u64 {
        match self.state.registers.get("rip").or_else(|| self.state.registers.get("pc")) {
            Some(expr) => input.eval(expr).unwrap_or(0),
            None => 0,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vars() -> HashMap<String, SymType> {
        let mut m = HashMap::new();
        m.insert("x".into(), SymType::BitVec(64));
        m.insert("y".into(), SymType::BitVec(64));
        m
    }

    #[test]
    fn test_eval_add() {
        let mut env = HashMap::new();
        env.insert("x".to_string(), 10u64);
        env.insert("y".to_string(), 32u64);
        let expr = SymExpr::Add(
            Box::new(SymExpr::Var { name: "x".into(), ty: SymType::BitVec(64) }),
            Box::new(SymExpr::Var { name: "y".into(), ty: SymType::BitVec(64) }),
        );
        assert_eq!(eval_expr(&expr, &env), Some(42));
    }

    #[test]
    fn test_path_constraint_negate() {
        let cond = SymExpr::Var { name: "x".into(), ty: SymType::BitVec(64) };
        let mut pc = PathConstraint::new();
        pc.push(BranchRecord { pc: 0x1000, condition: cond.clone(), taken: true, depth: 0 });
        pc.push(BranchRecord { pc: 0x1010, condition: cond.clone(), taken: true, depth: 1 });

        // Negate branch 0 — should have BoolNot for first.
        let neg = pc.conjunction_negate(0).unwrap();
        match &neg {
            SymExpr::BoolAnd(left, _right) => {
                assert!(matches!(left.as_ref(), SymExpr::BoolNot(_)));
            }
            _ => panic!("expected BoolAnd"),
        }
    }

    #[test]
    fn test_coverage_map() {
        let mut cov = CoverageMap::new();
        assert!(cov.record(0x1000, true));
        assert!(!cov.record(0x1000, true)); // duplicate
        assert!(cov.record(0x1000, false));
        assert!(cov.is_fully_covered(0x1000));
        assert!(!cov.is_fully_covered(0x2000));
    }

    #[test]
    fn test_perturbation_solver() {
        let solver = PerturbationSolver::default();
        let vars = make_vars();
        // condition: x != 0 (i.e. x > 0 symbolically)
        let cond = SymExpr::Ne(
            Box::new(SymExpr::Var { name: "x".into(), ty: SymType::BitVec(64) }),
            Box::new(SymExpr::ConstBv { val: 0, width: 64 }),
        );
        let result = solver.solve(&cond, &vars);
        assert!(result.is_some());
        let env = result.unwrap();
        assert_ne!(env["x"], 0);
    }

    #[test]
    fn test_executor_campaign_empty() {
        let config = ConcolicConfig { max_inputs: 4, ..Default::default() };
        let vars = make_vars();
        let mut exec = ConcolicExecutor::with_perturbation_solver(config, vars);

        // Step function: terminates immediately.
        let results = exec.run_campaign(|_pc, _input, _path| None);
        assert!(!results.is_empty());
    }
}
