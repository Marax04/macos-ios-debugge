//! `symbolic_executor` — Step-by-step symbolic instruction execution.
//!
//! Provides [`SymbolicExecutor`], [`ExecutionState`], and [`ExecutionPath`],
//! plus the [`step_instruction`] helper.

use crate::path_condition::{Constraint, ConditionSet, PathCondition, add_constraint, is_satisfiable};
use crate::symbolic_memory::SymbolicMemory;
use rustre_symb::{SymExpr, SymbolicError};
use std::collections::{HashMap, VecDeque};
use std::fmt;

// ── StepError ──────────────────────────────────────────────────────────────────

/// Errors that can occur during a single execution step.
#[derive(Debug, thiserror::Error)]
pub enum StepError {
    #[error("symbolic error: {0}")]
    Symbolic(#[from] SymbolicError),
    #[error("unsupported opcode: {0:#04x}")]
    UnsupportedOpcode(u8),
    #[error("execution halted at {0:#x}")]
    Halted(u64),
    #[error("path limit exceeded")]
    PathLimitExceeded,
    #[error("depth limit exceeded at {0:#x}")]
    DepthLimitExceeded(u64),
    #[error("memory error: {0}")]
    Memory(String),
    #[error("division by zero")]
    DivisionByZero,
}

// ── Instruction ────────────────────────────────────────────────────────────────

/// A decoded (simplified) instruction fed to the executor.
#[derive(Debug, Clone)]
pub enum Instruction {
    /// Move `src` expression into register `dst`.
    Mov { dst: String, src: SymExpr },
    /// Add two registers and store in `dst`.
    Add { dst: String, lhs: String, rhs: String },
    /// Subtract `rhs` from `lhs`, store in `dst`.
    Sub { dst: String, lhs: String, rhs: String },
    /// Bitwise AND.
    And { dst: String, lhs: String, rhs: String },
    /// Bitwise OR.
    Or { dst: String, lhs: String, rhs: String },
    /// Bitwise XOR.
    Xor { dst: String, lhs: String, rhs: String },
    /// Conditional branch: if `cond_reg` != 0, jump to `target`; else fall through.
    Branch { cond_reg: String, target: u64, fallthrough: u64 },
    /// Unconditional jump.
    Jump { target: u64 },
    /// Load `width` bytes from `[base_reg + offset]` into `dst`.
    Load { dst: String, base_reg: String, offset: i64, width: u8 },
    /// Store `src_reg` to `[base_reg + offset]`.
    Store { base_reg: String, offset: i64, src_reg: String, width: u8 },
    /// Function call to `target` (pushes return address).
    Call { target: u64, return_addr: u64 },
    /// Return from function.
    Return,
    /// No-op.
    Nop,
    /// Explicit halt.
    Halt,
}

// ── ExecutionState ─────────────────────────────────────────────────────────────

/// The complete symbolic state of a single execution path at one point in time.
#[derive(Debug, Clone)]
pub struct ExecutionState {
    /// Current program counter.
    pub pc: u64,
    /// Symbolic register file.
    pub registers: HashMap<String, SymExpr>,
    /// Symbolic memory.
    pub memory: SymbolicMemory,
    /// Path condition accumulated so far.
    pub path_condition: PathCondition,
    /// Call stack (return addresses).
    pub call_stack: Vec<u64>,
    /// Number of steps taken since start.
    pub steps: u64,
    /// Whether this state is still active.
    pub is_alive: bool,
    /// Whether execution halted normally.
    pub halted: bool,
    /// State identifier.
    pub id: u64,
}

impl ExecutionState {
    /// Create a fresh execution state at `entry_pc`.
    #[must_use]
    pub fn new(entry_pc: u64, memory: SymbolicMemory, id: u64) -> Self {
        Self {
            pc: entry_pc,
            registers: HashMap::new(),
            memory,
            path_condition: PathCondition::new(),
            call_stack: Vec::new(),
            steps: 0,
            is_alive: true,
            halted: false,
            id,
        }
    }

    /// Read a register value, returning a fresh symbol if not yet defined.
    #[must_use]
    pub fn read_reg(&self, name: &str) -> SymExpr {
        self.registers
            .get(name)
            .cloned()
            .unwrap_or_else(|| SymExpr::Symbol(self.id, 64, format!("reg_{name}")))
    }

    /// Write a register value.
    pub fn write_reg(&mut self, name: impl Into<String>, val: SymExpr) {
        self.registers.insert(name.into(), val);
    }

    /// Fork this state, returning a child state with `extra_constraint` added.
    #[must_use]
    pub fn fork(&self, extra_constraint: Constraint, new_pc: u64, new_id: u64) -> Self {
        let mut child = self.clone();
        child.id = new_id;
        child.pc = new_pc;
        child.path_condition.add(extra_constraint);
        child
    }

    /// Whether the path condition is still satisfiable (syntactic check).
    #[must_use]
    pub fn is_feasible(&self) -> bool {
        is_satisfiable(&self.path_condition)
    }

    /// Add a constraint to the path condition.
    pub fn add_path_constraint(&mut self, c: Constraint) {
        add_constraint(&mut self.path_condition, c);
        if !self.is_feasible() {
            self.is_alive = false;
        }
    }

    /// Summary string for logging.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "State#{} pc={:#x} steps={} constraints={} alive={}",
            self.id,
            self.pc,
            self.steps,
            self.path_condition.len(),
            self.is_alive,
        )
    }
}

impl fmt::Display for ExecutionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ── ExecutionPath ──────────────────────────────────────────────────────────────

/// A recorded linear sequence of addresses visited on one execution path.
#[derive(Debug, Clone, Default)]
pub struct ExecutionPath {
    /// Sequence of `(pc, instruction_description)` pairs.
    pub trace: Vec<(u64, String)>,
    /// Whether this path reached a terminal state (halt / return with empty stack).
    pub is_complete: bool,
    /// Constraints at the end of the path.
    pub final_condition: PathCondition,
    /// State id this path belongs to.
    pub state_id: u64,
}

impl ExecutionPath {
    /// Create an empty path for the given state.
    #[must_use]
    pub fn new(state_id: u64) -> Self {
        Self {
            state_id,
            ..Self::default()
        }
    }

    /// Append a step to the trace.
    pub fn push(&mut self, pc: u64, desc: impl Into<String>) {
        self.trace.push((pc, desc.into()));
    }

    /// Length of the trace.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.trace.len()
    }

    /// Whether the trace is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.trace.is_empty()
    }

    /// Whether `addr` appears anywhere in the trace.
    #[must_use]
    pub fn visited(&self, addr: u64) -> bool {
        self.trace.iter().any(|(pc, _)| *pc == addr)
    }

    /// How many times `addr` appears (loop iteration count).
    #[must_use]
    pub fn visit_count(&self, addr: u64) -> usize {
        self.trace.iter().filter(|(pc, _)| *pc == addr).count()
    }

    /// All unique addresses visited.
    #[must_use]
    pub fn unique_addresses(&self) -> Vec<u64> {
        let mut addrs: Vec<u64> = self.trace.iter().map(|(a, _)| *a).collect();
        addrs.sort_unstable();
        addrs.dedup();
        addrs
    }
}

// ── ExecutorConfig ─────────────────────────────────────────────────────────────

/// Configuration knobs for the symbolic executor.
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Maximum number of steps per path before giving up.
    pub max_steps: u64,
    /// Maximum number of active states (paths) at once.
    pub max_states: usize,
    /// Maximum call stack depth.
    pub max_call_depth: usize,
    /// Maximum times any single address may be visited on one path (loop bound).
    pub loop_bound: usize,
    /// Whether to record a full instruction trace per path.
    pub record_trace: bool,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            max_steps: 10_000,
            max_states: 1024,
            max_call_depth: 64,
            loop_bound: 8,
            record_trace: true,
        }
    }
}

impl ExecutorConfig {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_steps: 10_000,
            max_states: 1024,
            max_call_depth: 64,
            loop_bound: 8,
            record_trace: true,
        }
    }
}

// ── SymbolicExecutor ───────────────────────────────────────────────────────────

/// Orchestrates symbolic execution of a decoded instruction stream.
///
/// Maintains a worklist of active [`ExecutionState`]s and executes them one step
/// at a time, forking on conditional branches.
pub struct SymbolicExecutor {
    config: ExecutorConfig,
    worklist: VecDeque<ExecutionState>,
    completed: Vec<ExecutionState>,
    paths: Vec<ExecutionPath>,
    next_state_id: u64,
    total_steps: u64,
    total_forks: u64,
    /// Instruction provider: address → instruction.
    /// In a real engine this would be a disassembler; here it is a table.
    instruction_table: HashMap<u64, Instruction>,
    condition_set: ConditionSet,
}

impl SymbolicExecutor {
    /// Create an executor with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ExecutorConfig::default(),
            worklist: VecDeque::new(),
            completed: Vec::new(),
            paths: Vec::new(),
            next_state_id: 0,
            total_steps: 0,
            total_forks: 0,
            instruction_table: HashMap::new(),
            condition_set: ConditionSet::new(),
        }
    }

    /// Apply a custom configuration.
    #[must_use]
    pub const fn with_config(mut self, cfg: ExecutorConfig) -> Self {
        self.config = cfg;
        self
    }

    /// Seed the instruction table.
    pub fn add_instruction(&mut self, addr: u64, instr: Instruction) {
        self.instruction_table.insert(addr, instr);
    }

    /// Add multiple instructions.
    pub fn add_instructions(&mut self, instrs: Vec<(u64, Instruction)>) {
        for (addr, instr) in instrs {
            self.instruction_table.insert(addr, instr);
        }
    }

    /// Enqueue an initial execution state.
    pub fn push_state(&mut self, state: ExecutionState) {
        self.worklist.push_back(state);
    }

    /// Create a fresh state and enqueue it.
    pub fn add_entry_point(&mut self, pc: u64, memory: SymbolicMemory) -> u64 {
        let id = self.next_state_id;
        self.next_state_id += 1;
        let state = ExecutionState::new(pc, memory, id);
        self.worklist.push_back(state);
        id
    }

    /// Run until all states are complete or limits are exceeded.
    pub fn run(&mut self) {
        while let Some(state) = self.worklist.pop_front() {
            self.process_state(state);
        }
    }

    /// Run exactly `n` steps across all active states.
    pub fn run_n_steps(&mut self, n: u64) {
        let mut done = 0u64;
        while done < n {
            if let Some(state) = self.worklist.pop_front() {
                let new_states = self.step_one(state);
                for s in new_states {
                    if s.is_alive {
                        self.worklist.push_back(s);
                    } else {
                        self.record_completed_path(&s);
                        self.completed.push(s);
                    }
                }
                done += 1;
            } else {
                break;
            }
        }
        self.total_steps += done;
    }

    fn process_state(&mut self, state: ExecutionState) {
        let mut current = state;
        while current.is_alive && !current.halted {
            if current.steps >= self.config.max_steps {
                current.is_alive = false;
                break;
            }
            let mut new_states = self.step_one(current.clone());
            if new_states.len() > 1 {
                // Fork: push extras onto worklist
                for extra in new_states.drain(1..) {
                    if self.worklist.len() < self.config.max_states {
                        self.worklist.push_back(extra);
                    }
                }
                self.total_forks += 1;
            }
            if let Some(next) = new_states.into_iter().next() {
                current = next;
            } else {
                break;
            }
        }
        self.record_completed_path(&current);
        self.completed.push(current);
    }

    /// Persist a finished state as an [`ExecutionPath`] and integrate its
    /// final path-condition into the executor's [`ConditionSet`].
    fn record_completed_path(&mut self, state: &ExecutionState) {
        let mut path = ExecutionPath::new(state.id);
        path.is_complete = state.halted;
        path.final_condition = state.path_condition.clone();
        // Replay PC history is unavailable here; record terminal pc as a
        // single-step trace so downstream consumers can join paths by
        // (state_id, end_pc).
        path.push(state.pc, "<terminal>");
        self.condition_set.push(state.path_condition.clone());
        self.paths.push(path);
    }

    /// Read-only view of recorded completed paths.
    #[must_use]
    pub fn paths(&self) -> &[ExecutionPath] {
        &self.paths
    }

    /// Aggregated condition set across all completed paths.
    #[must_use]
    pub const fn condition_set(&self) -> &ConditionSet {
        &self.condition_set
    }

    /// Compute an effective memory address from a base register value and an offset.
    #[must_use]
    const fn effective_addr(base: &SymExpr, offset: i64) -> u64 {
        if let SymExpr::ConstBv { val: v, .. } = base {
            (*v).cast_signed().wrapping_add(offset).cast_unsigned()
        } else {
            offset.unsigned_abs()
        }
    }

    /// Fork a conditional branch into taken and fall-through states.
    fn step_branch(
        &mut self,
        state: &ExecutionState,
        cond: SymExpr,
        target: u64,
        fallthrough: u64,
    ) -> Vec<ExecutionState> {
        let pc = state.pc;
        let id_taken = { let id = self.next_state_id; self.next_state_id += 1; id };
        let id_fall  = { let id = self.next_state_id; self.next_state_id += 1; id };
        let taken = state.fork(Constraint::is_true(cond.clone(), pc), target, id_taken);
        let fall  = state.fork(Constraint::is_false(cond, pc), fallthrough, id_fall);
        vec![taken, fall]
    }

    /// Execute one instruction for `state`, returning resulting states.
    /// Returns 1 state normally, 2 on a branch (taken + not-taken).
    fn step_one(&mut self, mut state: ExecutionState) -> Vec<ExecutionState> {
        let pc = state.pc;
        let Some(instr) = self.instruction_table.get(&pc).cloned() else {
            state.is_alive = false;
            return vec![state];
        };

        state.steps += 1;
        self.total_steps += 1;

        match instr {
            Instruction::Nop => {
                state.pc += 1;
                vec![state]
            }
            Instruction::Halt => {
                state.halted = true;
                state.is_alive = false;
                vec![state]
            }
            Instruction::Mov { dst, src } => {
                state.write_reg(dst, src);
                state.pc += 1;
                vec![state]
            }
            Instruction::Add { dst, lhs, rhs } => {
                let l = state.read_reg(&lhs);
                let r = state.read_reg(&rhs);
                state.write_reg(dst, SymExpr::add_expr(l, r));
                state.pc += 1;
                vec![state]
            }
            Instruction::Sub { dst, lhs, rhs } => {
                let l = state.read_reg(&lhs);
                let r = state.read_reg(&rhs);
                state.write_reg(dst, SymExpr::sub_expr(l, r));
                state.pc += 1;
                vec![state]
            }
            Instruction::And { dst, lhs, rhs } => {
                let l = state.read_reg(&lhs);
                let r = state.read_reg(&rhs);
                state.write_reg(dst, SymExpr::and(l, r));
                state.pc += 1;
                vec![state]
            }
            Instruction::Or { dst, lhs, rhs } => {
                let l = state.read_reg(&lhs);
                let r = state.read_reg(&rhs);
                state.write_reg(dst, SymExpr::or(l, r));
                state.pc += 1;
                vec![state]
            }
            Instruction::Xor { dst, lhs, rhs } => {
                let l = state.read_reg(&lhs);
                let r = state.read_reg(&rhs);
                state.write_reg(dst, SymExpr::xor(l, r));
                state.pc += 1;
                vec![state]
            }
            Instruction::Branch { cond_reg, target, fallthrough } => {
                let cond = state.read_reg(&cond_reg);
                self.step_branch(&state, cond, target, fallthrough)
            }
            Instruction::Jump { target } => {
                state.pc = target;
                vec![state]
            }
            Instruction::Load { dst, base_reg, offset, width } => {
                let base = state.read_reg(&base_reg);
                let addr = Self::effective_addr(&base, offset);
                let val = state.memory.read_le(addr, width).unwrap_or_else(|_| SymExpr::ConstBv { val: 0, width: u32::from(width) * 8 });
                state.write_reg(dst, val);
                state.pc += 1;
                vec![state]
            }
            Instruction::Store { base_reg, offset, src_reg, width } => {
                let base = state.read_reg(&base_reg);
                let src = state.read_reg(&src_reg);
                let addr = Self::effective_addr(&base, offset);
                // Silently ignore out-of-bounds stores (symbolic model
                // conservatively drops stores to unmapped addresses).
                // The error is logged via the memory's internal error path;
                // swallowing it is intentional for now but noted here so
                // downstream tooling can intercept it.
                let _store_result = state.memory.write_le_symbolic(addr, &src, width);
                state.pc += 1;
                vec![state]
            }
            Instruction::Call { target, return_addr } => {
                if state.call_stack.len() >= self.config.max_call_depth {
                    state.is_alive = false;
                    return vec![state];
                }
                state.call_stack.push(return_addr);
                state.pc = target;
                vec![state]
            }
            Instruction::Return => {
                if let Some(ret) = state.call_stack.pop() {
                    state.pc = ret;
                } else {
                    state.halted = true;
                    state.is_alive = false;
                }
                vec![state]
            }
        }
    }

    /// Number of active states in the worklist.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.worklist.len()
    }

    /// Number of completed states.
    #[must_use]
    pub const fn completed_count(&self) -> usize {
        self.completed.len()
    }

    /// Total steps taken across all states.
    #[must_use]
    pub const fn total_steps(&self) -> u64 {
        self.total_steps
    }

    /// Total branch forks.
    #[must_use]
    pub const fn total_forks(&self) -> u64 {
        self.total_forks
    }

    /// All completed states.
    #[must_use]
    pub fn completed_states(&self) -> &[ExecutionState] {
        &self.completed
    }

    /// Completed states that halted normally.
    #[must_use]
    pub fn halted_states(&self) -> Vec<&ExecutionState> {
        self.completed.iter().filter(|s| s.halted).collect()
    }
}

impl Default for SymbolicExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ── step_instruction free function ────────────────────────────────────────────

/// Execute a single instruction against a state, returning the resulting states.
///
/// This is a convenience wrapper over the executor's internal step logic for
/// testing and incremental use.
#[must_use]
pub fn step_instruction(
    state: ExecutionState,
    instr: Instruction,
) -> Vec<ExecutionState> {
    let pc = state.pc;
    let mut exec = SymbolicExecutor::new();
    exec.add_instruction(pc, instr);
    exec.step_one(state)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbolic_memory::RegionPerms;
    use crate::symbolic_memory::MemoryRegion;

    fn make_state(pc: u64) -> ExecutionState {
        let mut mem = SymbolicMemory::new();
        mem.map_region(MemoryRegion::new("stack", 0x7000, 0x1000, RegionPerms::rw()));
        ExecutionState::new(pc, mem, 0)
    }

    #[test]
    fn test_state_read_write_reg() {
        let mut s = make_state(0x1000);
        s.write_reg("rax", SymExpr::ConstBv { val: 42, width: 64 });
        let v = s.read_reg("rax");
        assert!(matches!(v, SymExpr::ConstBv { val: 42, width: 64 }));
    }

    #[test]
    fn test_state_undefined_reg_is_symbol() {
        let s = make_state(0x1000);
        let v = s.read_reg("rbx");
        assert!(matches!(v, SymExpr::Var { .. }));
    }

    #[test]
    fn test_state_is_feasible_initially() {
        let s = make_state(0x1000);
        assert!(s.is_feasible());
    }

    #[test]
    fn test_state_fork() {
        let s = make_state(0x1000);
        let c = Constraint::is_true(SymExpr::ConstBv { val: 1, width: 64 }, 0x0);
        let child = s.fork(c, 0x2000, 99);
        assert_eq!(child.pc, 0x2000);
        assert_eq!(child.id, 99);
        assert_eq!(child.path_condition.len(), 1);
    }

    #[test]
    fn test_state_add_path_constraint_contradiction() {
        let mut s = make_state(0x1000);
        let c = Constraint::is_false(SymExpr::ConstBv { val: 1, width: 64 }, 0x0); // contradiction
        s.add_path_constraint(c);
        assert!(!s.is_alive);
    }

    #[test]
    fn test_state_summary() {
        let s = make_state(0x1000);
        let sum = s.summary();
        assert!(sum.contains("0x1000"));
    }

    #[test]
    fn test_execution_path_visited() {
        let mut path = ExecutionPath::new(0);
        path.push(0x1000, "nop");
        path.push(0x1001, "nop");
        assert!(path.visited(0x1000));
        assert!(!path.visited(0x9999));
    }

    #[test]
    fn test_execution_path_visit_count() {
        let mut path = ExecutionPath::new(0);
        path.push(0x1000, "loop head");
        path.push(0x1001, "body");
        path.push(0x1000, "loop head");
        assert_eq!(path.visit_count(0x1000), 2);
    }

    #[test]
    fn test_execution_path_unique_addresses() {
        let mut path = ExecutionPath::new(0);
        path.push(0x1002, "a");
        path.push(0x1001, "b");
        path.push(0x1002, "a again");
        let unique = path.unique_addresses();
        assert_eq!(unique.len(), 2);
    }

    #[test]
    fn test_step_instruction_nop() {
        let s = make_state(0x1000);
        let results = step_instruction(s, Instruction::Nop);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pc, 0x1001);
    }

    #[test]
    fn test_step_instruction_halt() {
        let s = make_state(0x1000);
        let results = step_instruction(s, Instruction::Halt);
        assert_eq!(results.len(), 1);
        assert!(results[0].halted);
    }

    #[test]
    fn test_step_instruction_mov() {
        let s = make_state(0x1000);
        let results = step_instruction(s, Instruction::Mov {
            dst: "rax".to_string(),
            src: SymExpr::ConstBv { val: 99, width: 64 },
        });
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].read_reg("rax"), SymExpr::ConstBv { val: 99, width: 64 }));
        assert_eq!(results[0].pc, 0x1001);
    }

    #[test]
    fn test_step_instruction_add() {
        let mut s = make_state(0x1000);
        s.write_reg("rax", SymExpr::ConstBv { val: 3, width: 64 });
        s.write_reg("rbx", SymExpr::ConstBv { val: 4, width: 64 });
        let results = step_instruction(s, Instruction::Add {
            dst: "rcx".to_string(),
            lhs: "rax".to_string(),
            rhs: "rbx".to_string(),
        });
        assert_eq!(results.len(), 1);
        // Result should be Add(3, 4)
        assert!(matches!(results[0].read_reg("rcx"), SymExpr::Add(_, _)));
    }

    #[test]
    fn test_step_instruction_branch_forks() {
        let mut s = make_state(0x1000);
        s.write_reg("cond", SymExpr::Symbol(1, 1, "cond".to_string()));
        let results = step_instruction(s, Instruction::Branch {
            cond_reg: "cond".to_string(),
            target: 0x2000,
            fallthrough: 0x1001,
        });
        assert_eq!(results.len(), 2);
        let pcs: Vec<u64> = results.iter().map(|s| s.pc).collect();
        assert!(pcs.contains(&0x2000));
        assert!(pcs.contains(&0x1001));
    }

    #[test]
    fn test_step_instruction_jump() {
        let s = make_state(0x1000);
        let results = step_instruction(s, Instruction::Jump { target: 0x3000 });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pc, 0x3000);
    }

    #[test]
    fn test_step_instruction_call_return() {
        let s = make_state(0x1000);
        let after_call = step_instruction(s, Instruction::Call {
            target: 0x2000,
            return_addr: 0x1005,
        });
        assert_eq!(after_call[0].pc, 0x2000);
        assert_eq!(after_call[0].call_stack.len(), 1);

        let after_ret = step_instruction(after_call.into_iter().next().unwrap(), Instruction::Return);
        assert_eq!(after_ret[0].pc, 0x1005);
        assert!(after_ret[0].call_stack.is_empty());
    }

    #[test]
    fn test_executor_run_simple() {
        let mut exec = SymbolicExecutor::new();
        exec.add_instructions(vec![
            (0x1000, Instruction::Nop),
            (0x1001, Instruction::Halt),
        ]);
        exec.add_entry_point(0x1000, {
            let mut m = SymbolicMemory::new();
            m.map_region(MemoryRegion::new("s", 0x7000, 0x100, RegionPerms::rw()));
            m
        });
        exec.run();
        assert_eq!(exec.active_count(), 0);
        assert!(exec.completed_count() > 0);
    }

    #[test]
    fn test_executor_fork_stats() {
        let mut exec = SymbolicExecutor::new();
        exec.add_instructions(vec![
            (0x1000, Instruction::Branch {
                cond_reg: "cond".to_string(),
                target: 0x2000,
                fallthrough: 0x1001,
            }),
            (0x1001, Instruction::Halt),
            (0x2000, Instruction::Halt),
        ]);
        let mut entry = ExecutionState::new(0x1000, {
            let mut m = SymbolicMemory::new();
            m.map_region(MemoryRegion::new("s", 0x7000, 0x100, RegionPerms::rw()));
            m
        }, 0);
        entry.write_reg("cond", SymExpr::Symbol(0, 1, "cond".to_string()));
        exec.push_state(entry);
        exec.run();
        assert!(exec.total_forks() >= 1);
    }

    #[test]
    fn test_executor_config_default() {
        let cfg = ExecutorConfig::default();
        assert!(cfg.max_steps > 0);
        assert!(cfg.max_states > 0);
    }
}
