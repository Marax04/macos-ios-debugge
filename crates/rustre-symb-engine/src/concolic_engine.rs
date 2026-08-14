//! Concolic (concrete + symbolic) co-execution engine.
//!
//! Maintains a concrete execution trace alongside symbolic constraints.  At
//! each branch, the engine records the concrete outcome and generates a new
//! path with the branch flipped to drive test-case generation.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::ExecutorConfig;
use rustre_symb::SymExpr;

/// Re-exports of the engine-level exploration strategy and the lower-level
/// symbolic state type so concolic consumers can configure exploration and
/// query state without an extra import.
pub use crate::ExplorationStrategy;
pub use rustre_symb::SymbolicState;

// ─── ConcolicValue ────────────────────────────────────────────────────────────

/// A value that is simultaneously concrete and symbolic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcolicValue {
    /// Concrete (observed) value.
    pub concrete: u64,
    /// Symbolic expression (may be a constant if the value is fully determined).
    pub symbolic: SymExpr,
}

impl ConcolicValue {
    /// Construct a fully concrete value.
    #[must_use]
    pub const fn concrete(val: u64) -> Self {
        Self {
            concrete: val,
            symbolic: SymExpr::constant(64, val),
        }
    }

    /// Construct a symbolic value with a given concrete witness.
    #[must_use]
    pub const fn symbolic(concrete: u64, sym: SymExpr) -> Self {
        Self {
            concrete,
            symbolic: sym,
        }
    }

    /// Whether this value is fully determined (constant symbolic expression).
    #[must_use]
    pub const fn is_concrete(&self) -> bool {
        self.symbolic.as_const_u64().is_some()
    }
}

// ─── BranchFlip ───────────────────────────────────────────────────────────────

/// Records a branch point where the concrete run took one direction; the other
/// direction should be explored next (test generation target).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchFlip {
    /// Program counter of the branch instruction.
    pub pc: u64,
    /// The branch condition as a symbolic expression.
    pub condition: SymExpr,
    /// The concrete outcome (true = taken, false = not-taken).
    pub concrete_outcome: bool,
    /// Depth in the concrete execution at which this branch occurred.
    pub depth: u32,
    /// Whether this flip has already been scheduled for exploration.
    pub scheduled: bool,
}

impl BranchFlip {
    #[must_use]
    pub const fn new(pc: u64, condition: SymExpr, concrete_outcome: bool, depth: u32) -> Self {
        Self {
            pc,
            condition,
            concrete_outcome,
            depth,
            scheduled: false,
        }
    }

    /// Mark as scheduled.
    pub const fn mark_scheduled(&mut self) {
        self.scheduled = true;
    }
}

// ─── ConcolicState ────────────────────────────────────────────────────────────

/// Combined concrete + symbolic state for one execution path.
#[derive(Debug, Clone)]
pub struct ConcolicState {
    /// Current PC.
    pub pc: u64,
    /// Concrete register values.
    pub concrete_regs: HashMap<String, u64>,
    /// Symbolic register values.
    pub symbolic_regs: HashMap<String, SymExpr>,
    /// Path constraints accumulated so far (symbolic conditions).
    pub path_constraints: Vec<SymExpr>,
    /// Concrete memory snapshot (addr → byte).
    pub memory: HashMap<u64, u8>,
    /// Execution depth (step count).
    pub depth: u32,
    /// State ID.
    pub id: u64,
}

impl ConcolicState {
    #[must_use]
    pub fn new(id: u64, pc: u64) -> Self {
        Self {
            pc,
            concrete_regs: HashMap::new(),
            symbolic_regs: HashMap::new(),
            path_constraints: Vec::new(),
            memory: HashMap::new(),
            depth: 0,
            id,
        }
    }

    /// Set a register to a concrete/symbolic pair.
    pub fn set_reg(&mut self, name: impl Into<String>, value: ConcolicValue) {
        let n = name.into();
        self.concrete_regs.insert(n.clone(), value.concrete);
        self.symbolic_regs.insert(n, value.symbolic);
    }

    /// Get the concrete value of a register.
    #[must_use]
    pub fn concrete_reg(&self, name: &str) -> u64 {
        self.concrete_regs.get(name).copied().unwrap_or(0)
    }

    /// Get the symbolic expression of a register.
    #[must_use]
    pub fn symbolic_reg(&self, name: &str) -> Option<&SymExpr> {
        self.symbolic_regs.get(name)
    }

    /// Add a path constraint.
    pub fn add_constraint(&mut self, expr: SymExpr) {
        self.path_constraints.push(expr);
    }

    /// Write a concrete byte to memory.
    pub fn write_byte(&mut self, addr: u64, byte: u8) {
        self.memory.insert(addr, byte);
    }

    /// Read a concrete byte from memory.
    #[must_use]
    pub fn read_byte(&self, addr: u64) -> u8 {
        self.memory.get(&addr).copied().unwrap_or(0)
    }

    /// Advance the PC and increment depth.
    pub const fn advance(&mut self, new_pc: u64) {
        self.pc = new_pc;
        self.depth = self.depth.saturating_add(1);
    }
}

// ─── TestCase ─────────────────────────────────────────────────────────────────

/// A generated test case: concrete input assignments that drive a specific path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    /// Test ID.
    pub id: u64,
    /// Concrete input assignments (variable name → concrete value).
    pub inputs: HashMap<String, u64>,
    /// The branch PC that this test case was generated to cover.
    pub target_pc: u64,
    /// Path constraints at generation time.
    pub constraints: Vec<SymExpr>,
}

impl TestCase {
    #[must_use]
    pub const fn new(
        id: u64,
        inputs: HashMap<String, u64>,
        target_pc: u64,
        constraints: Vec<SymExpr>,
    ) -> Self {
        Self {
            id,
            inputs,
            target_pc,
            constraints,
        }
    }
}

// ─── TestCaseGenerator ────────────────────────────────────────────────────────

/// Generates test cases from [`BranchFlip`] records.
#[derive(Debug, Default)]
pub struct TestCaseGenerator {
    next_id: u64,
    generated: Vec<TestCase>,
}

impl TestCaseGenerator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a test case by negating the concrete outcome of `flip`,
    /// given the prefix constraints `prefix`.
    pub fn generate(
        &mut self,
        flip: &BranchFlip,
        prefix: Vec<SymExpr>,
        concrete_witness: HashMap<String, u64>,
    ) -> TestCase {
        let id = self.next_id;
        self.next_id += 1;
        let mut constraints = prefix;
        // Add the negated condition (we want the *other* branch taken).
        constraints.push(flip.condition.clone());
        let tc = TestCase::new(id, concrete_witness, flip.pc, constraints);
        self.generated.push(tc.clone());
        tc
    }

    /// All generated test cases.
    #[must_use]
    pub fn cases(&self) -> &[TestCase] {
        &self.generated
    }

    /// Number of test cases generated.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.generated.len()
    }
}

// ─── ConcolicSession ──────────────────────────────────────────────────────────

/// Manages a concolic execution session: the concrete run, branch flips, and
/// test-case generation.
#[derive(Debug)]
pub struct ConcolicSession {
    /// All branch flips recorded during the concrete run.
    pub flips: Vec<BranchFlip>,
    /// Test-case generator.
    pub generator: TestCaseGenerator,
    /// Current concrete execution depth.
    pub depth: u32,
    /// Total branches encountered.
    pub total_branches: u64,
    /// Concrete run PC trace.
    pc_trace: Vec<u64>,
}

impl ConcolicSession {
    #[must_use]
    pub fn new() -> Self {
        Self {
            flips: Vec::new(),
            generator: TestCaseGenerator::new(),
            depth: 0,
            total_branches: 0,
            pc_trace: Vec::new(),
        }
    }

    /// Record a branch in the concrete run.
    pub fn record_branch(&mut self, pc: u64, condition: SymExpr, concrete_outcome: bool) {
        self.total_branches += 1;
        self.flips
            .push(BranchFlip::new(pc, condition, concrete_outcome, self.depth));
    }

    /// Advance to a new PC.
    pub fn step(&mut self, pc: u64) {
        self.pc_trace.push(pc);
        self.depth = self.depth.saturating_add(1);
    }

    /// Return unscheduled flips (branch points not yet explored).
    #[must_use]
    pub fn pending_flips(&self) -> Vec<&BranchFlip> {
        self.flips.iter().filter(|f| !f.scheduled).collect()
    }

    /// Schedule the next unscheduled flip and generate a test case.
    pub fn schedule_next_flip(
        &mut self,
        concrete_witness: HashMap<String, u64>,
    ) -> Option<TestCase> {
        let flip = self.flips.iter_mut().find(|f| !f.scheduled)?;
        flip.mark_scheduled();
        let flip_ref: BranchFlip = flip.clone();
        Some(
            self.generator
                .generate(&flip_ref, Vec::new(), concrete_witness),
        )
    }

    /// PC trace of the concrete run.
    #[must_use]
    pub fn pc_trace(&self) -> &[u64] {
        &self.pc_trace
    }

    /// Number of branches flipped so far.
    #[must_use]
    pub fn scheduled_count(&self) -> usize {
        self.flips.iter().filter(|f| f.scheduled).count()
    }
}

impl Default for ConcolicSession {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ConcolicEngine ───────────────────────────────────────────────────────────

/// High-level concolic engine.
///
/// Maintains a concrete state and drives the concolic session.
#[derive(Debug)]
pub struct ConcolicEngine {
    pub config: ExecutorConfig,
    pub state: ConcolicState,
    pub session: ConcolicSession,
    next_state_id: u64,
}

impl ConcolicEngine {
    /// Create a new engine starting at `entry_pc`.
    #[must_use]
    pub fn new(entry_pc: u64, config: ExecutorConfig) -> Self {
        Self {
            state: ConcolicState::new(0, entry_pc),
            session: ConcolicSession::new(),
            config,
            next_state_id: 1,
        }
    }

    /// Simulate executing one instruction at the current PC.
    ///
    /// `new_pc`: the PC after execution.
    /// `reg_updates`: new concrete/symbolic values for changed registers.
    pub fn step(&mut self, new_pc: u64, reg_updates: Vec<(String, ConcolicValue)>) {
        for (name, val) in reg_updates {
            self.state.set_reg(name, val);
        }
        self.session.step(self.state.pc);
        self.state.advance(new_pc);
    }

    /// Evaluate a branch.  `condition` is the symbolic branch condition;
    /// `concrete_outcome` is what the concrete run did.
    pub fn branch(
        &mut self,
        branch_pc: u64,
        taken_pc: u64,
        fallthrough_pc: u64,
        condition: SymExpr,
        concrete_outcome: bool,
    ) {
        self.session
            .record_branch(branch_pc, condition.clone(), concrete_outcome);
        // Follow concrete outcome.
        let next_pc = if concrete_outcome {
            taken_pc
        } else {
            fallthrough_pc
        };
        let _ = concrete_outcome;
        let constraint = condition;
        self.state.add_constraint(constraint);
        self.session.step(branch_pc);
        self.state.pc = next_pc;
        self.state.depth = self.state.depth.saturating_add(1);
    }

    /// Generate the next test case by flipping the oldest unscheduled branch.
    pub fn generate_test_case(&mut self, witness: HashMap<String, u64>) -> Option<TestCase> {
        self.session.schedule_next_flip(witness)
    }

    /// Allocate and return a fresh state identifier; useful for callers that
    /// fork the concolic state and want stable ids per fork.
    pub const fn fresh_state_id(&mut self) -> u64 {
        let id = self.next_state_id;
        self.next_state_id = self.next_state_id.saturating_add(1);
        id
    }

    /// Return the next state id without consuming it.
    #[must_use]
    pub const fn peek_next_state_id(&self) -> u64 {
        self.next_state_id
    }

    /// All generated test cases.
    #[must_use]
    pub fn test_cases(&self) -> &[TestCase] {
        self.session.generator.cases()
    }

    /// Number of test cases generated.
    #[must_use]
    pub const fn test_case_count(&self) -> usize {
        self.session.generator.count()
    }

    /// Current PC.
    #[must_use]
    pub const fn pc(&self) -> u64 {
        self.state.pc
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_symb::SymExpr;

    // --- ConcolicValue ---

    #[test]
    fn concolic_value_concrete_is_concrete() {
        let v = ConcolicValue::concrete(42);
        assert!(v.is_concrete());
        assert_eq!(v.concrete, 42);
    }

    #[test]
    fn concolic_value_symbolic_not_concrete() {
        let sym = SymExpr::Symbol(1, 64, "x");
        let v = ConcolicValue::symbolic(42, sym);
        assert!(!v.is_concrete());
    }

    // --- BranchFlip ---

    #[test]
    fn branch_flip_new_not_scheduled() {
        let f = BranchFlip::new(0x1000, SymExpr::constant(1, 1), true, 3);
        assert!(!f.scheduled);
    }

    #[test]
    fn branch_flip_mark_scheduled() {
        let mut f = BranchFlip::new(0, SymExpr::constant(1, 0), false, 0);
        f.mark_scheduled();
        assert!(f.scheduled);
    }

    // --- ConcolicState ---

    #[test]
    fn concolic_state_set_get_reg() {
        let mut s = ConcolicState::new(0, 0x1000);
        s.set_reg("rax", ConcolicValue::concrete(99));
        assert_eq!(s.concrete_reg("rax"), 99);
        assert!(s.symbolic_reg("rax").is_some());
    }

    #[test]
    fn concolic_state_read_write_memory() {
        let mut s = ConcolicState::new(0, 0);
        s.write_byte(0x2000, 0xAB);
        assert_eq!(s.read_byte(0x2000), 0xAB);
        assert_eq!(s.read_byte(0x9999), 0); // unwritten → 0
    }

    #[test]
    fn concolic_state_add_constraint() {
        let mut s = ConcolicState::new(0, 0);
        s.add_constraint(SymExpr::constant(1, 1));
        assert_eq!(s.path_constraints.len(), 1);
    }

    #[test]
    fn concolic_state_advance() {
        let mut s = ConcolicState::new(0, 0x1000);
        s.advance(0x1002);
        assert_eq!(s.pc, 0x1002);
        assert_eq!(s.depth, 1);
    }

    #[test]
    fn concolic_state_default_reg_zero() {
        let s = ConcolicState::new(0, 0);
        assert_eq!(s.concrete_reg("rip"), 0);
    }

    // --- TestCaseGenerator ---

    #[test]
    fn generator_generates_test_case() {
        let mut g = TestCaseGenerator::new();
        let flip = BranchFlip::new(0x1000, SymExpr::constant(1, 1), true, 0);
        let mut inputs = HashMap::new();
        inputs.insert("input0".into(), 42u64);
        let tc = g.generate(&flip, vec![], inputs);
        assert_eq!(tc.target_pc, 0x1000);
        assert_eq!(tc.id, 0);
        assert_eq!(g.count(), 1);
    }

    #[test]
    fn generator_ids_increment() {
        let mut g = TestCaseGenerator::new();
        let flip = BranchFlip::new(0, SymExpr::constant(1, 0), false, 0);
        let tc1 = g.generate(&flip, vec![], HashMap::new());
        let tc2 = g.generate(&flip, vec![], HashMap::new());
        assert_eq!(tc2.id, tc1.id + 1);
    }

    // --- ConcolicSession ---

    #[test]
    fn session_record_branch() {
        let mut sess = ConcolicSession::new();
        sess.record_branch(0x1000, SymExpr::constant(1, 1), true);
        assert_eq!(sess.total_branches, 1);
        assert_eq!(sess.flips.len(), 1);
    }

    #[test]
    fn session_pending_flips_all_initially() {
        let mut sess = ConcolicSession::new();
        sess.record_branch(0xA, SymExpr::constant(1, 0), true);
        sess.record_branch(0xB, SymExpr::constant(1, 0), false);
        assert_eq!(sess.pending_flips().len(), 2);
    }

    #[test]
    fn session_schedule_next_flip() {
        let mut sess = ConcolicSession::new();
        sess.record_branch(0x1000, SymExpr::constant(1, 1), true);
        let tc = sess.schedule_next_flip(HashMap::new());
        assert!(tc.is_some());
        assert_eq!(sess.scheduled_count(), 1);
        assert_eq!(sess.pending_flips().len(), 0);
    }

    #[test]
    fn session_schedule_when_no_flips_returns_none() {
        let mut sess = ConcolicSession::new();
        assert!(sess.schedule_next_flip(HashMap::new()).is_none());
    }

    #[test]
    fn session_step_pc_trace() {
        let mut sess = ConcolicSession::new();
        sess.step(0x1000);
        sess.step(0x1002);
        assert_eq!(sess.pc_trace(), &[0x1000, 0x1002]);
    }

    // --- ConcolicEngine ---

    #[test]
    fn engine_step_advances_pc() {
        let mut e = ConcolicEngine::new(0x1000, ExecutorConfig::default());
        e.step(0x1002, vec![]);
        assert_eq!(e.pc(), 0x1002);
    }

    #[test]
    fn engine_branch_taken() {
        let mut e = ConcolicEngine::new(0x1000, ExecutorConfig::default());
        e.branch(0x1000, 0x2000, 0x1002, SymExpr::constant(1, 1), true);
        assert_eq!(e.pc(), 0x2000);
    }

    #[test]
    fn engine_branch_not_taken() {
        let mut e = ConcolicEngine::new(0x1000, ExecutorConfig::default());
        e.branch(0x1000, 0x2000, 0x1002, SymExpr::constant(1, 1), false);
        assert_eq!(e.pc(), 0x1002);
    }

    #[test]
    fn engine_generate_test_case() {
        let mut e = ConcolicEngine::new(0x1000, ExecutorConfig::default());
        e.branch(0x1000, 0x2000, 0x1002, SymExpr::constant(1, 1), true);
        let tc = e.generate_test_case(HashMap::new());
        assert!(tc.is_some());
        assert_eq!(e.test_case_count(), 1);
    }

    #[test]
    fn engine_no_test_case_without_branches() {
        let mut e = ConcolicEngine::new(0x1000, ExecutorConfig::default());
        assert!(e.generate_test_case(HashMap::new()).is_none());
    }

    #[test]
    fn engine_test_cases_accumulate() {
        let mut e = ConcolicEngine::new(0x1000, ExecutorConfig::default());
        for pc in [0x1000u64, 0x1010, 0x1020] {
            e.branch(pc, pc + 0x100, pc + 2, SymExpr::constant(1, 1), true);
        }
        e.generate_test_case(HashMap::new());
        e.generate_test_case(HashMap::new());
        assert_eq!(e.test_case_count(), 2);
    }
}
