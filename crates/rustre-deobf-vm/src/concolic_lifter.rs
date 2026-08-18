//! Concolic Execution for VM Handler Semantic Recovery
//!
//! Runs a lightweight concolic (concrete + symbolic) execution engine over
//! disassembled handler bodies to automatically infer what each handler does:
//! - [`ConcolicState`] — combined concrete + symbolic machine state
//! - [`SymbolicValue`] — an expression tree of symbolic + concrete terms
//! - [`ConcolicLifter`] — drives the execution of a handler body
//! - [`PathCondition`] — accumulated branch constraints
//! - [`HandlerOutputAnalysis`] — summarises what the handler produced


use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from concolic lifting.
#[derive(Debug, Error)]
pub enum ConcolicError {
    #[error("divide by zero in concrete execution at offset {offset}")]
    DivideByZero { offset: usize },

    #[error("symbolic expression tree depth exceeded limit {limit}")]
    TreeTooDeep { limit: usize },

    #[error("unsupported instruction opcode {opcode:#04x} at offset {offset}")]
    UnsupportedInstruction { opcode: u8, offset: usize },

    #[error("stack underflow during concolic execution (depth was {depth})")]
    StackUnderflow { depth: usize },

    #[error("memory access out of symbolic address space at address {addr:#x}")]
    OutOfRange { addr: u64 },

    #[error("maximum step count {max} reached without halting")]
    MaxStepsReached { max: usize },
}

// ─────────────────────────────────────────────────────────────────────────────
// SymbolicValue — expression tree
// ─────────────────────────────────────────────────────────────────────────────

/// A symbolic expression term in the concolic engine.
///
/// Represents the value of a register, stack slot, or memory cell either as
/// a concrete 64-bit constant, a named symbolic variable, or a compound
/// expression involving arithmetic / logical operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolicValue {
    /// A concrete (fully known) 64-bit value.
    Concrete(u64),
    /// A symbolic variable with a name and bit-width.
    Var { name: String, bits: u8 },
    /// Binary operation node.
    BinOp {
        op: SymBinOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    /// Unary operation node.
    UnOp {
        op: SymUnOp,
        operand: Box<Self>,
    },
    /// Extract bits [hi..lo] from a value.
    Extract {
        value: Box<Self>,
        hi: u8,
        lo: u8,
    },
    /// Zero-extend a value to `bits` bits.
    ZExt { value: Box<Self>, bits: u8 },
    /// Sign-extend a value to `bits` bits.
    SExt { value: Box<Self>, bits: u8 },
    /// Conditional selection (ite).
    Ite {
        cond: Box<Self>,
        then_: Box<Self>,
        else_: Box<Self>,
    },
}

/// Symbolic binary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymBinOp {
    Add,
    Sub,
    Mul,
    UDiv,
    SDiv,
    And,
    Or,
    Xor,
    Shl,
    LShr,
    AShr,
    Rol,
    Ror,
    Eq,
    Ne,
    Ult,
    Ule,
    Slt,
    Sle,
}

/// Symbolic unary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymUnOp {
    Not,
    Neg,
    Bswap,
    Clz, // count leading zeros
    Ctz, // count trailing zeros
    Popcnt,
}

impl SymbolicValue {
    /// Create a symbolic variable with the given name and 64-bit width.
    pub fn var64(name: impl Into<String>) -> Self {
        Self::Var {
            name: name.into(),
            bits: 64,
        }
    }

    /// Create a symbolic variable with 32-bit width.
    pub fn var32(name: impl Into<String>) -> Self {
        Self::Var {
            name: name.into(),
            bits: 32,
        }
    }

    /// Returns `true` if this value is fully concrete.
    #[must_use]
    pub const fn is_concrete(&self) -> bool {
        matches!(self, Self::Concrete(_))
    }

    /// Extract the concrete value if fully known.
    #[must_use]
    pub const fn as_concrete(&self) -> Option<u64> {
        if let Self::Concrete(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Approximate the depth of the expression tree.
    ///
    /// Uses an iterative BFS rather than recursion to avoid stack overflow on
    /// deeply-nested attacker-supplied trees (dos-unbounded-recursion).
    /// Saturates at 65535.
    #[must_use]
    pub fn depth(&self) -> usize {
        // (node, depth_so_far)
        let mut stack: Vec<(&Self, usize)> = vec![(self, 0)];
        let mut max_depth = 0usize;
        while let Some((node, d)) = stack.pop() {
            if d > max_depth {
                max_depth = d;
            }
            // Bound traversal to avoid spending O(n) on huge trees.
            if d >= 65535 {
                break;
            }
            match node {
                Self::Concrete(_) | Self::Var { .. } => {}
                Self::BinOp { lhs, rhs, .. } => {
                    stack.push((lhs, d + 1));
                    stack.push((rhs, d + 1));
                }
                Self::UnOp { operand, .. } => stack.push((operand, d + 1)),
                Self::Extract { value, .. }
                | Self::ZExt { value, .. }
                | Self::SExt { value, .. } => stack.push((value, d + 1)),
                Self::Ite { cond, then_, else_ } => {
                    stack.push((cond, d + 1));
                    stack.push((then_, d + 1));
                    stack.push((else_, d + 1));
                }
            }
        }
        max_depth
    }

    /// Constant-fold if both operands are concrete.
    #[must_use]
    pub fn add(lhs: Self, rhs: Self) -> Self {
        if let (Self::Concrete(a), Self::Concrete(b)) = (&lhs, &rhs) {
            return Self::Concrete(a.wrapping_add(*b));
        }
        Self::BinOp {
            op: SymBinOp::Add,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Constant-fold subtraction.
    #[must_use]
    pub fn sub(lhs: Self, rhs: Self) -> Self {
        if let (Self::Concrete(a), Self::Concrete(b)) = (&lhs, &rhs) {
            return Self::Concrete(a.wrapping_sub(*b));
        }
        Self::BinOp {
            op: SymBinOp::Sub,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Constant-fold XOR.
    #[must_use]
    pub fn xor(lhs: Self, rhs: Self) -> Self {
        if let (Self::Concrete(a), Self::Concrete(b)) = (&lhs, &rhs) {
            return Self::Concrete(a ^ b);
        }
        Self::BinOp {
            op: SymBinOp::Xor,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Constant-fold AND.
    #[must_use]
    pub fn and(lhs: Self, rhs: Self) -> Self {
        if let (Self::Concrete(a), Self::Concrete(b)) = (&lhs, &rhs) {
            return Self::Concrete(a & b);
        }
        Self::BinOp {
            op: SymBinOp::And,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Constant-fold OR.
    #[must_use]
    pub fn or(lhs: Self, rhs: Self) -> Self {
        if let (Self::Concrete(a), Self::Concrete(b)) = (&lhs, &rhs) {
            return Self::Concrete(a | b);
        }
        Self::BinOp {
            op: SymBinOp::Or,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Constant-fold NOT.
    #[must_use]
    pub fn not(val: Self) -> Self {
        if let Self::Concrete(v) = &val {
            return Self::Concrete(!v);
        }
        Self::UnOp {
            op: SymUnOp::Not,
            operand: Box::new(val),
        }
    }

    /// Constant-fold NEG.
    #[must_use]
    pub fn neg(val: Self) -> Self {
        if let Self::Concrete(v) = &val {
            return Self::Concrete(v.wrapping_neg());
        }
        Self::UnOp {
            op: SymUnOp::Neg,
            operand: Box::new(val),
        }
    }

    /// Pretty-print the expression (simplified).
    ///
    /// Recursion is bounded at depth 64 to prevent stack overflow on deep trees
    /// (dos-unbounded-recursion).
    #[must_use]
    pub fn display(&self) -> String {
        self.display_bounded(64)
    }

    fn display_bounded(&self, budget: usize) -> String {
        if budget == 0 {
            return "…".to_owned();
        }
        let next = budget - 1;
        match self {
            Self::Concrete(v) => format!("{v:#x}"),
            Self::Var { name, bits } => format!("{name}:{bits}"),
            Self::BinOp { op, lhs, rhs } => {
                format!("({} {:?} {})", lhs.display_bounded(next), op, rhs.display_bounded(next))
            }
            Self::UnOp { op, operand } => format!("({:?} {})", op, operand.display_bounded(next)),
            Self::Extract { value, hi, lo } => format!("{}[{}:{}]", value.display_bounded(next), hi, lo),
            Self::ZExt { value, bits } => format!("zext({}, {})", value.display_bounded(next), bits),
            Self::SExt { value, bits } => format!("sext({}, {})", value.display_bounded(next), bits),
            Self::Ite { cond, then_, else_ } => format!(
                "ite({}, {}, {})",
                cond.display_bounded(next),
                then_.display_bounded(next),
                else_.display_bounded(next)
            ),
        }
    }

    /// Collect all symbolic variable names referenced in this expression.
    ///
    /// Uses an explicit work-stack to avoid unbounded recursion on attacker-controlled
    /// expression trees (dos-unbounded-recursion).
    #[must_use]
    pub fn symbolic_vars(&self) -> Vec<String> {
        let mut vars = Vec::new();
        // Iterative traversal: avoid stack overflow on deep symbolic trees.
        let mut work: Vec<&Self> = vec![self];
        while let Some(node) = work.pop() {
            match node {
                Self::Concrete(_) => {}
                Self::Var { name, .. } => vars.push(name.clone()),
                Self::BinOp { lhs, rhs, .. } => {
                    work.push(lhs);
                    work.push(rhs);
                }
                Self::UnOp { operand, .. } => work.push(operand),
                Self::Extract { value, .. }
                | Self::ZExt { value, .. }
                | Self::SExt { value, .. } => work.push(value),
                Self::Ite { cond, then_, else_ } => {
                    work.push(cond);
                    work.push(then_);
                    work.push(else_);
                }
            }
        }
        vars.sort();
        vars.dedup();
        vars
    }

    /// Recursive variable collector — **superseded**, kept as the reference
    /// formulation of the traversal.
    ///
    /// ⚠ Do not reach for this on untrusted input. [`Self::symbolic_vars`] was
    /// deliberately rewritten as an *iterative* traversal to close an unbounded
    /// recursion (a deep symbolic tree overflows the stack); this method is the
    /// recursive form that change replaced. Calling it from the pipeline would
    /// reintroduce the defect, so it is exposed rather than wired, and this is
    /// the sentence that says so — it previously had no caller and no warning,
    /// because an `#[allow(dead_code)]` was hiding both.
    ///
    /// It stays because it is the readable statement of what the iterative
    /// version computes, and `recursive_and_iterative_agree` below pins the two
    /// to the same answer on trees shallow enough to be safe.
    pub fn collect_vars(&self, out: &mut Vec<String>) {
        match self {
            Self::Concrete(_) => {}
            Self::Var { name, .. } => out.push(name.clone()),
            Self::BinOp { lhs, rhs, .. } => {
                lhs.collect_vars(out);
                rhs.collect_vars(out);
            }
            Self::UnOp { operand, .. } => operand.collect_vars(out),
            Self::Extract { value, .. } | Self::ZExt { value, .. } | Self::SExt { value, .. } => {
                value.collect_vars(out);
            }
            Self::Ite { cond, then_, else_ } => {
                cond.collect_vars(out);
                then_.collect_vars(out);
                else_.collect_vars(out);
            }
        }
    }
}

impl std::ops::Add for SymbolicValue {
    type Output = Self;
    fn add(self, rhs: Self) -> Self { Self::add(self, rhs) }
}

impl std::ops::Sub for SymbolicValue {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self { Self::sub(self, rhs) }
}

impl std::ops::Not for SymbolicValue {
    type Output = Self;
    fn not(self) -> Self { Self::not(self) }
}

impl std::ops::Neg for SymbolicValue {
    type Output = Self;
    fn neg(self) -> Self { Self::neg(self) }
}

// ─────────────────────────────────────────────────────────────────────────────
// PathCondition
// ─────────────────────────────────────────────────────────────────────────────

/// A single branch constraint accumulated during concolic execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchConstraint {
    /// Offset in the handler body where the branch occurs.
    pub offset: usize,
    /// The symbolic condition under which the branch is taken.
    pub condition: SymbolicValue,
    /// Whether the branch was concretely taken (`true`) or not taken (`false`).
    pub taken: bool,
}

/// Accumulated path conditions from a concolic execution run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathCondition {
    /// Ordered list of branch constraints encountered.
    pub constraints: Vec<BranchConstraint>,
}

impl PathCondition {
    /// Create an empty path condition.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a branch constraint.
    pub fn push(&mut self, constraint: BranchConstraint) {
        self.constraints.push(constraint);
    }

    /// Returns `true` if the path is unconditional (no branches).
    #[must_use]
    pub const fn is_straight_line(&self) -> bool {
        self.constraints.is_empty()
    }

    /// Returns the number of branch points on this path.
    #[must_use]
    pub const fn branch_count(&self) -> usize {
        self.constraints.len()
    }

    /// Returns `true` if any constraint involves a symbolic (non-concrete) condition.
    #[must_use]
    pub fn has_symbolic_branch(&self) -> bool {
        self.constraints.iter().any(|c| !c.condition.is_concrete())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConcolicState — combined concrete + symbolic machine state
// ─────────────────────────────────────────────────────────────────────────────

/// Register file index (x86 general-purpose registers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum X86Reg {
    Eax = 0,
    Ecx = 1,
    Edx = 2,
    Ebx = 3,
    Esp = 4,
    Ebp = 5,
    Esi = 6,
    Edi = 7,
    // Extended 64-bit aliases (same index, different width)
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

impl X86Reg {
    /// Create from an index (0-15).
    #[must_use]
    pub const fn from_index(i: u8) -> Option<Self> {
        let reg = match i {
            0 => Self::Eax,
            1 => Self::Ecx,
            2 => Self::Edx,
            3 => Self::Ebx,
            4 => Self::Esp,
            5 => Self::Ebp,
            6 => Self::Esi,
            7 => Self::Edi,
            8 => Self::R8,
            9 => Self::R9,
            10 => Self::R10,
            11 => Self::R11,
            12 => Self::R12,
            13 => Self::R13,
            14 => Self::R14,
            15 => Self::R15,
            _ => return None,
        };
        Some(reg)
    }

    /// Name string (32-bit form).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Eax => "EAX",
            Self::Ecx => "ECX",
            Self::Edx => "EDX",
            Self::Ebx => "EBX",
            Self::Esp => "ESP",
            Self::Ebp => "EBP",
            Self::Esi => "ESI",
            Self::Edi => "EDI",
            Self::R8 => "R8",
            Self::R9 => "R9",
            Self::R10 => "R10",
            Self::R11 => "R11",
            Self::R12 => "R12",
            Self::R13 => "R13",
            Self::R14 => "R14",
            Self::R15 => "R15",
        }
    }
}

/// The combined concolic machine state at a single execution point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcolicState {
    /// Concrete register values (indexed by `X86Reg` as `u8`).
    pub concrete_regs: [u64; 16],
    /// Symbolic expressions for registers (None = fully concrete).
    pub symbolic_regs: [Option<SymbolicValue>; 16],
    /// Concrete stack (grows downward; index 0 is top-of-stack).
    pub concrete_stack: Vec<u64>,
    /// Symbolic stack values matching `concrete_stack`.
    pub symbolic_stack: Vec<Option<SymbolicValue>>,
    /// Concrete flags: bit0=ZF, bit1=CF, bit2=SF, bit3=OF, bit4=PF.
    pub flags: u32,
    /// Symbolic flags expression (None = fully concrete).
    pub symbolic_flags: Option<SymbolicValue>,
    /// Concrete memory cells (addr → byte).
    pub concrete_memory: HashMap<u64, u8>,
    /// Symbolic memory cells (addr → expression).
    pub symbolic_memory: HashMap<u64, SymbolicValue>,
    /// Instruction pointer (offset into the handler body).
    pub ip: usize,
    /// Number of instructions executed so far.
    pub step_count: usize,
}

impl ConcolicState {
    /// Create an initial state with symbolic inputs for a 32-bit handler.
    ///
    /// Each register is initialised to a symbolic variable so the engine
    /// can track which input registers the handler reads.
    #[must_use]
    pub fn new_symbolic_32() -> Self {
        let mut sym = [const { None }; 16];
        let concrete = [0u64; 16];
        for i in 0..8u8 {
            if let Some(reg) = X86Reg::from_index(i) {
                sym[i as usize] = Some(SymbolicValue::var32(reg.name()));
            }
        }
        // Concrete stack pre-populated with symbolic sentinels.
        let stack_sym: Vec<Option<SymbolicValue>> = (0..8)
            .map(|i| Some(SymbolicValue::var64(format!("STACK_{i}"))))
            .collect();
        let stack_conc: Vec<u64> = vec![0u64; 8];

        Self {
            concrete_regs: concrete,
            symbolic_regs: sym,
            concrete_stack: stack_conc,
            symbolic_stack: stack_sym,
            flags: 0,
            symbolic_flags: None,
            concrete_memory: HashMap::new(),
            symbolic_memory: HashMap::new(),
            ip: 0,
            step_count: 0,
        }
    }

    /// Read a register's symbolic value (falls back to concrete if no symbolic).
    #[must_use]
    pub fn read_reg_sym(&self, reg: X86Reg) -> SymbolicValue {
        let idx = reg as usize;
        self.symbolic_regs[idx]
            .clone()
            .unwrap_or(SymbolicValue::Concrete(self.concrete_regs[idx]))
    }

    /// Write a register (concrete + symbolic).
    pub fn write_reg(&mut self, reg: X86Reg, concrete: u64, symbolic: Option<SymbolicValue>) {
        let idx = reg as usize;
        self.concrete_regs[idx] = concrete;
        self.symbolic_regs[idx] = symbolic;
    }

    /// Push a value onto the concolic stack.
    pub fn push(&mut self, concrete: u64, symbolic: Option<SymbolicValue>) {
        self.concrete_stack.push(concrete);
        self.symbolic_stack.push(symbolic);
    }

    /// Pop a value from the concolic stack.
    ///
    /// # Errors
    ///
    /// Returns [`ConcolicError::StackUnderflow`] if the stack is empty.
    ///
    /// # Panics
    ///
    /// Panics if the concrete and symbolic stacks become mismatched in length.
    pub fn pop(&mut self) -> Result<(u64, Option<SymbolicValue>), ConcolicError> {
        let depth = self.concrete_stack.len();
        if depth == 0 {
            return Err(ConcolicError::StackUnderflow { depth: 0 });
        }
        Ok((
            self.concrete_stack.pop().unwrap(),
            self.symbolic_stack.pop().unwrap(),
        ))
    }

    /// Set the zero flag based on a concrete result.
    pub const fn set_zero_flag(&mut self, result: u64) {
        if result == 0 {
            self.flags |= 1;
        } else {
            self.flags &= !1;
        }
    }

    /// Zero flag.
    #[must_use]
    pub const fn zero_flag(&self) -> bool {
        self.flags & 1 != 0
    }

    /// Sign flag.
    #[must_use]
    pub const fn sign_flag(&self) -> bool {
        self.flags & 4 != 0
    }

    /// Write a byte to concrete + symbolic memory.
    pub fn write_mem_byte(&mut self, addr: u64, byte: u8, sym: Option<SymbolicValue>) {
        self.concrete_memory.insert(addr, byte);
        if let Some(s) = sym {
            self.symbolic_memory.insert(addr, s);
        }
    }

    /// Read a byte from concrete memory (0 for unmapped).
    #[must_use]
    pub fn read_mem_byte(&self, addr: u64) -> u8 {
        self.concrete_memory.get(&addr).copied().unwrap_or(0)
    }

    /// Snapshot of symbolic register state for output analysis.
    #[must_use]
    pub fn symbolic_register_snapshot(&self) -> HashMap<String, SymbolicValue> {
        let mut snap = HashMap::new();
        for i in 0..8u8 {
            if let Some(reg) = X86Reg::from_index(i)
                && let Some(sym) = &self.symbolic_regs[i as usize] {
                    snap.insert(reg.name().to_owned(), sym.clone());
                }
        }
        snap
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HandlerOutputAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of what a VM handler produced during concolic execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerOutputAnalysis {
    /// Final symbolic expressions for each register after execution.
    pub final_regs: HashMap<String, SymbolicValue>,
    /// Final symbolic values on the stack (bottom to top).
    pub final_stack: Vec<SymbolicValue>,
    /// Accumulated path conditions.
    pub path: PathCondition,
    /// Memory write records: (`address_expr`, `value_expr`).
    pub memory_writes: Vec<(SymbolicValue, SymbolicValue)>,
    /// Memory read records: (`address_expr`, `value_expr`).
    pub memory_reads: Vec<(SymbolicValue, SymbolicValue)>,
    /// Inferred handler semantic (from output pattern).
    pub inferred_semantic: InferredSemantic,
    /// Confidence in the inferred semantic [0.0, 1.0].
    pub confidence: f32,
    /// Number of concolic steps executed.
    pub steps_executed: usize,
    /// Whether execution reached a clean halt.
    pub halted_cleanly: bool,
    /// Human-readable analysis notes.
    pub notes: Vec<String>,
}

impl HandlerOutputAnalysis {
    /// Create an empty output analysis.
    #[must_use]
    pub fn new() -> Self {
        Self {
            final_regs: HashMap::new(),
            final_stack: Vec::new(),
            path: PathCondition::new(),
            memory_writes: Vec::new(),
            memory_reads: Vec::new(),
            inferred_semantic: InferredSemantic::Unknown,
            confidence: 0.0,
            steps_executed: 0,
            halted_cleanly: false,
            notes: Vec::new(),
        }
    }

    /// Returns `true` if the handler is a straight-line (no branches) operation.
    #[must_use]
    pub const fn is_straight_line(&self) -> bool {
        self.path.is_straight_line()
    }

    /// Returns all symbolic variable names referenced in the output.
    #[must_use]
    pub fn input_variables(&self) -> Vec<String> {
        let mut vars = Vec::new();
        for v in self.final_regs.values() {
            vars.extend(v.symbolic_vars());
        }
        for v in &self.final_stack {
            vars.extend(v.symbolic_vars());
        }
        vars.sort();
        vars.dedup();
        vars
    }
}

impl Default for HandlerOutputAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

/// Semantics inferred from a concolic execution run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InferredSemantic {
    /// Stack push: one input consumed, one value added to stack.
    Push,
    /// Stack pop: one value taken from stack, stored somewhere.
    Pop,
    /// Binary ALU: two stack inputs consumed, one result pushed.
    BinaryAlu,
    /// Unary ALU: one stack input consumed, one result pushed.
    UnaryAlu,
    /// Memory load: address popped, value pushed.
    MemLoad,
    /// Memory store: value + address popped, nothing pushed.
    MemStore,
    /// Unconditional branch: new VIP loaded.
    Jump,
    /// Conditional branch: path condition accumulates one constraint.
    CondBranch,
    /// Call: pushes return VIP, then jumps.
    Call,
    /// Return: pops VIP, jumps there.
    Return,
    /// NOP: stack and registers unchanged.
    Nop,
    /// VM exit: leaves the VM interpreter loop.
    VmExit,
    /// Unknown pattern.
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// ConcolicLifter — the engine
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the concolic lifter.
#[derive(Debug, Clone)]
pub struct ConcolicConfig {
    /// Maximum number of concolic steps before giving up.
    pub max_steps: usize,
    /// Maximum symbolic expression depth before simplifying to Unknown.
    pub max_tree_depth: usize,
    /// Whether to record every memory access (may be expensive).
    pub track_memory: bool,
    /// Whether to perform constant folding.
    pub constant_fold: bool,
}

impl Default for ConcolicConfig {
    fn default() -> Self {
        Self {
            max_steps: 10_000,
            max_tree_depth: 32,
            track_memory: true,
            constant_fold: true,
        }
    }
}

/// Drives concolic execution over a VM handler body.
///
/// The engine interprets a simplified x86-like bytecode where each byte
/// is decoded as a micro-instruction. Real usage would pass actual lifted
/// instruction streams from a disassembler. This implementation provides
/// the symbolic tracking infrastructure used by the VM lifting pipeline.
#[derive(Debug, Clone, Default)]
pub struct ConcolicLifter {
    pub config: ConcolicConfig,
}

impl ConcolicLifter {
    /// Create a new lifter with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom configuration.
    #[must_use]
    pub const fn with_config(config: ConcolicConfig) -> Self {
        Self { config }
    }

    /// Execute a handler body represented as a sequence of [`ConcolicMicroOp`]
    /// starting from `state` and return an output analysis.
    ///
    /// # Errors
    ///
    /// Returns [`ConcolicError`] if execution hits divide-by-zero, stack
    /// underflow, or exceeds the configured step limit.
    ///
    /// # Panics
    ///
    /// Panics if the concrete stack and symbolic stack become mismatched in
    /// length during internal pop operations.
    pub fn lift(
        &self,
        ops: &[ConcolicMicroOp],
        mut state: ConcolicState,
    ) -> Result<HandlerOutputAnalysis, ConcolicError> {
        let mut output = HandlerOutputAnalysis::new();
        let initial_stack_len = i32::try_from(state.symbolic_stack.len()).unwrap_or(i32::MAX);

        for (offset, op) in ops.iter().enumerate() {
            if state.step_count >= self.config.max_steps {
                return Err(ConcolicError::MaxStepsReached {
                    max: self.config.max_steps,
                });
            }
            state.step_count += 1;
            state.ip = offset;

            match op {
                ConcolicMicroOp::Nop => {}

                ConcolicMicroOp::PushConst(val) => {
                    state.push(*val, Some(SymbolicValue::Concrete(*val)));
                }

                ConcolicMicroOp::PushReg(reg) => {
                    let idx = *reg as usize;
                    let conc = state.concrete_regs[idx];
                    let sym = state.symbolic_regs[idx]
                        .clone()
                        .unwrap_or(SymbolicValue::Concrete(conc));
                    state.push(conc, Some(sym));
                }

                ConcolicMicroOp::PopReg(reg) => {
                    let (conc, sym) = state.pop()?;
                    state.write_reg(*reg, conc, sym);
                }

                ConcolicMicroOp::BinOp(op) => {
                    let (b_conc, b_sym) = state.pop()?;
                    let (a_conc, a_sym) = state.pop()?;
                    let a_s = a_sym.unwrap_or(SymbolicValue::Concrete(a_conc));
                    let b_s = b_sym.unwrap_or(SymbolicValue::Concrete(b_conc));
                    let (result_conc, result_sym) = Self::eval_binop(*op, a_conc, b_conc, a_s, b_s);
                    state.set_zero_flag(result_conc);
                    state.push(result_conc, Some(result_sym));
                }

                ConcolicMicroOp::UnOp(op) => {
                    let (a_conc, a_sym) = state.pop()?;
                    let a_s = a_sym.unwrap_or(SymbolicValue::Concrete(a_conc));
                    let (result_conc, result_sym) = Self::eval_unop(*op, a_conc, a_s);
                    state.push(result_conc, Some(result_sym));
                }

                ConcolicMicroOp::LoadMem => {
                    let (addr_conc, addr_sym) = state.pop()?;
                    let val = u64::from(Self::read_u32_from_mem(&state, addr_conc));
                    let addr_s = addr_sym.unwrap_or(SymbolicValue::Concrete(addr_conc));
                    let val_sym = SymbolicValue::var64(format!("MEM[{addr_conc:#x}]"));
                    if self.config.track_memory {
                        output.memory_reads.push((addr_s, val_sym.clone()));
                    }
                    state.push(val, Some(val_sym));
                }

                ConcolicMicroOp::StoreMem => {
                    let (addr_conc, addr_sym) = state.pop()?;
                    let (val_conc, val_sym) = state.pop()?;
                    let addr_s = addr_sym.unwrap_or(SymbolicValue::Concrete(addr_conc));
                    let val_s = val_sym.unwrap_or(SymbolicValue::Concrete(val_conc));
                    if self.config.track_memory {
                        output.memory_writes.push((addr_s.clone(), val_s.clone()));
                    }
                    // Write concretely too.
                    let bytes = u32::try_from(val_conc).unwrap_or(u32::MAX).to_le_bytes();
                    for (i, &b) in bytes.iter().enumerate() {
                        state.write_mem_byte(addr_conc + i as u64, b, None);
                    }
                }

                ConcolicMicroOp::CondBranch {
                    condition_reg,
                    taken_offset,
                } => {
                    let reg_idx = *condition_reg as usize;
                    let conc_cond = state.concrete_regs[reg_idx];
                    let sym_cond = state.symbolic_regs[reg_idx]
                        .clone()
                        .unwrap_or(SymbolicValue::Concrete(conc_cond));
                    let taken = conc_cond != 0;
                    output.path.push(BranchConstraint {
                        offset,
                        condition: sym_cond,
                        taken,
                    });
                    if taken {
                        // Fast-forward IP: in the micro-op stream we just record the branch.
                        let _ = taken_offset; // Would change state.ip in a real interpreter.
                    }
                }

                ConcolicMicroOp::Halt => {
                    output.halted_cleanly = true;
                    break;
                }
            }
        }

        output.steps_executed = state.step_count;
        // Capture final register snapshot.
        output.final_regs = state.symbolic_register_snapshot();
        // Capture final stack.
        output.final_stack = state
            .symbolic_stack
            .iter()
            .map(|s| s.clone().unwrap_or(SymbolicValue::Concrete(0)))
            .collect();

        // Infer semantic from output shape.
        output.inferred_semantic = Self::infer_semantic(&output, initial_stack_len);
        output.confidence = Self::score_semantic(&output);

        Ok(output)
    }

    // ── Evaluation helpers ────────────────────────────────────────────────────

    fn eval_binop(
        op: SymBinOp,
        a: u64,
        b: u64,
        a_sym: SymbolicValue,
        b_sym: SymbolicValue,
    ) -> (u64, SymbolicValue) {
        let shift = u32::try_from(b & 63).unwrap_or(63);
        let conc = match op {
            SymBinOp::Add => a.wrapping_add(b),
            SymBinOp::Sub => a.wrapping_sub(b),
            SymBinOp::Mul => a.wrapping_mul(b),
            SymBinOp::And => a & b,
            SymBinOp::Or => a | b,
            SymBinOp::Xor => a ^ b,
            SymBinOp::Shl => a.wrapping_shl(shift),
            SymBinOp::LShr => a.wrapping_shr(shift),
            SymBinOp::AShr => a.cast_signed().wrapping_shr(shift).cast_unsigned(),
            SymBinOp::UDiv => {
                if b == 0 { 0 } else { a / b }
            }
            SymBinOp::SDiv => {
                if b == 0 { 0 } else { (a.cast_signed() / b.cast_signed()).cast_unsigned() }
            }
            SymBinOp::Eq => u64::from(a == b),
            SymBinOp::Ne => u64::from(a != b),
            SymBinOp::Ult => u64::from(a < b),
            SymBinOp::Ule => u64::from(a <= b),
            SymBinOp::Slt => u64::from(a.cast_signed() < b.cast_signed()),
            SymBinOp::Sle => u64::from(a.cast_signed() <= b.cast_signed()),
            SymBinOp::Rol => a.rotate_left(shift),
            SymBinOp::Ror => a.rotate_right(shift),
        };

        // Symbolic: build the operation node (constant-fold if both concrete).
        let sym = match (a_sym.as_concrete(), b_sym.as_concrete()) {
            (Some(av), Some(bv)) => SymbolicValue::Concrete(match op {
                SymBinOp::Add => av.wrapping_add(bv),
                SymBinOp::Sub => av.wrapping_sub(bv),
                _ => conc,
            }),
            _ => SymbolicValue::BinOp {
                op,
                lhs: Box::new(a_sym),
                rhs: Box::new(b_sym),
            },
        };

        (conc, sym)
    }

    fn eval_unop(op: SymUnOp, a: u64, a_sym: SymbolicValue) -> (u64, SymbolicValue) {
        let conc = match op {
            SymUnOp::Not => !a,
            SymUnOp::Neg => a.wrapping_neg(),
            SymUnOp::Bswap => a.swap_bytes(),
            SymUnOp::Clz => u64::from(a.leading_zeros()),
            SymUnOp::Ctz => u64::from(a.trailing_zeros()),
            SymUnOp::Popcnt => u64::from(a.count_ones()),
        };
        let sym = a_sym.as_concrete().map_or_else(
            || SymbolicValue::UnOp { op, operand: Box::new(a_sym) },
            |cv| SymbolicValue::Concrete(match op {
                SymUnOp::Not => !cv,
                SymUnOp::Neg => cv.wrapping_neg(),
                _ => conc,
            }),
        );
        (conc, sym)
    }

    fn read_u32_from_mem(state: &ConcolicState, addr: u64) -> u32 {
        let b0 = u32::from(state.read_mem_byte(addr));
        let b1 = u32::from(state.read_mem_byte(addr + 1));
        let b2 = u32::from(state.read_mem_byte(addr + 2));
        let b3 = u32::from(state.read_mem_byte(addr + 3));
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }

    fn infer_semantic(output: &HandlerOutputAnalysis, initial_stack_len: i32) -> InferredSemantic {
        let stack_delta = i32::try_from(output.final_stack.len()).unwrap_or(i32::MAX) - initial_stack_len;
        let has_mem_write = !output.memory_writes.is_empty();
        let has_mem_read = !output.memory_reads.is_empty();
        let is_branching = output.path.branch_count() > 0;

        if is_branching {
            return InferredSemantic::CondBranch;
        }
        if has_mem_write && !has_mem_read && stack_delta < 0 {
            return InferredSemantic::MemStore;
        }
        if has_mem_read && !has_mem_write && stack_delta > 0 {
            return InferredSemantic::MemLoad;
        }
        if stack_delta > 0 {
            return InferredSemantic::Push;
        }
        if stack_delta < -1 {
            return InferredSemantic::MemStore;
        }
        if stack_delta == -1 {
            return InferredSemantic::BinaryAlu;
        }
        if stack_delta == 0 && !has_mem_write && !has_mem_read {
            return InferredSemantic::Nop;
        }
        if stack_delta == 0 {
            return InferredSemantic::UnaryAlu;
        }
        InferredSemantic::Unknown
    }

    const fn score_semantic(output: &HandlerOutputAnalysis) -> f32 {
        if output.halted_cleanly { 0.75 } else { 0.40 }
    }
}

/// Simplified micro-operations for the concolic engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConcolicMicroOp {
    Nop,
    PushConst(u64),
    PushReg(X86Reg),
    PopReg(X86Reg),
    BinOp(SymBinOp),
    UnOp(SymUnOp),
    LoadMem,
    StoreMem,
    CondBranch {
        condition_reg: X86Reg,
        taken_offset: i32,
    },
    Halt,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> ConcolicState {
        ConcolicState::new_symbolic_32()
    }

    #[test]
    fn test_symbolic_value_concrete() {
        let v = SymbolicValue::Concrete(42);
        assert!(v.is_concrete());
        assert_eq!(v.as_concrete(), Some(42));
        assert_eq!(v.depth(), 0);
    }

    #[test]
    fn test_symbolic_value_var() {
        let v = SymbolicValue::var64("EAX");
        assert!(!v.is_concrete());
        assert_eq!(v.as_concrete(), None);
        let vars = v.symbolic_vars();
        assert_eq!(vars, vec!["EAX"]);
    }

    #[test]
    fn test_symbolic_value_add_constant_fold() {
        let a = SymbolicValue::Concrete(10);
        let b = SymbolicValue::Concrete(20);
        let result = SymbolicValue::add(a, b);
        assert_eq!(result, SymbolicValue::Concrete(30));
    }

    #[test]
    fn test_symbolic_value_xor_self_zero() {
        let a = SymbolicValue::var64("X");
        let b = SymbolicValue::var64("X");
        // Can't fold symbolically (distinct nodes), but display should work.
        let r = SymbolicValue::xor(a, b);
        assert!(!r.is_concrete());
        let display = r.display();
        assert!(display.contains("Xor"));
    }

    #[test]
    fn test_symbolic_value_not_concrete() {
        let v = SymbolicValue::Concrete(0xFF);
        let r = SymbolicValue::not(v);
        assert_eq!(r, SymbolicValue::Concrete(!0xFF));
    }

    #[test]
    fn test_symbolic_value_neg_concrete() {
        let v = SymbolicValue::Concrete(1u64);
        let r = SymbolicValue::neg(v);
        assert_eq!(r, SymbolicValue::Concrete(u64::MAX)); // wrapping neg of 1
    }

    #[test]
    fn test_symbolic_value_depth() {
        let a = SymbolicValue::var64("A");
        let b = SymbolicValue::var64("B");
        let c = SymbolicValue::add(a, b);
        assert_eq!(c.depth(), 1);
    }

    #[test]
    fn test_symbolic_value_collect_vars() {
        let a = SymbolicValue::var64("A");
        let b = SymbolicValue::var64("B");
        let c = SymbolicValue::add(a, b);
        let vars = c.symbolic_vars();
        assert_eq!(vars, vec!["A", "B"]);
    }

    #[test]
    fn test_concolic_state_push_pop() {
        let mut state = make_state();
        // Remove the pre-filled symbolic stack.
        state.concrete_stack.clear();
        state.symbolic_stack.clear();
        state.push(42, Some(SymbolicValue::Concrete(42)));
        state.push(99, None);
        let (v, s) = state.pop().unwrap();
        assert_eq!(v, 99);
        assert!(s.is_none());
    }

    #[test]
    fn test_concolic_state_stack_underflow() {
        let mut state = ConcolicState::new_symbolic_32();
        state.concrete_stack.clear();
        state.symbolic_stack.clear();
        assert!(state.pop().is_err());
    }

    #[test]
    fn test_concolic_state_write_read_reg() {
        let mut state = make_state();
        state.write_reg(X86Reg::Eax, 0xDEAD, Some(SymbolicValue::Concrete(0xDEAD)));
        let sym = state.read_reg_sym(X86Reg::Eax);
        assert_eq!(sym.as_concrete(), Some(0xDEAD));
    }

    #[test]
    fn test_concolic_lifter_nop_halt() {
        let lifter = ConcolicLifter::new();
        let state = ConcolicState::new_symbolic_32();
        let ops = vec![ConcolicMicroOp::Nop, ConcolicMicroOp::Halt];
        let output = lifter.lift(&ops, state).unwrap();
        assert!(output.halted_cleanly);
        assert_eq!(output.steps_executed, 2);
    }

    #[test]
    fn test_concolic_lifter_push_const() {
        let lifter = ConcolicLifter::new();
        let mut state = ConcolicState::new_symbolic_32();
        state.concrete_stack.clear();
        state.symbolic_stack.clear();
        let ops = vec![ConcolicMicroOp::PushConst(42), ConcolicMicroOp::Halt];
        let output = lifter.lift(&ops, state).unwrap();
        // Stack should have one item: 42.
        assert_eq!(
            output.final_stack.last().and_then(SymbolicValue::as_concrete),
            Some(42)
        );
    }

    #[test]
    fn test_concolic_lifter_binop_add() {
        let lifter = ConcolicLifter::new();
        let mut state = ConcolicState::new_symbolic_32();
        state.concrete_stack.clear();
        state.symbolic_stack.clear();
        let ops = vec![
            ConcolicMicroOp::PushConst(10),
            ConcolicMicroOp::PushConst(20),
            ConcolicMicroOp::BinOp(SymBinOp::Add),
            ConcolicMicroOp::Halt,
        ];
        let output = lifter.lift(&ops, state).unwrap();
        let top = output.final_stack.last().and_then(SymbolicValue::as_concrete);
        assert_eq!(top, Some(30));
    }

    #[test]
    fn test_concolic_lifter_unop_not() {
        let lifter = ConcolicLifter::new();
        let mut state = ConcolicState::new_symbolic_32();
        state.concrete_stack.clear();
        state.symbolic_stack.clear();
        let ops = vec![
            ConcolicMicroOp::PushConst(0xFF),
            ConcolicMicroOp::UnOp(SymUnOp::Not),
            ConcolicMicroOp::Halt,
        ];
        let output = lifter.lift(&ops, state).unwrap();
        let top = output.final_stack.last().and_then(SymbolicValue::as_concrete);
        assert_eq!(top, Some(!0xFFu64));
    }

    #[test]
    fn test_concolic_lifter_max_steps_error() {
        let lifter = ConcolicLifter::with_config(ConcolicConfig {
            max_steps: 2,
            ..Default::default()
        });
        let state = ConcolicState::new_symbolic_32();
        // Three NOPs → should exhaust max_steps.
        let ops = vec![
            ConcolicMicroOp::Nop,
            ConcolicMicroOp::Nop,
            ConcolicMicroOp::Nop,
        ];
        let result = lifter.lift(&ops, state);
        assert!(matches!(result, Err(ConcolicError::MaxStepsReached { .. })));
    }

    #[test]
    fn test_path_condition_straight_line() {
        let path = PathCondition::new();
        assert!(path.is_straight_line());
        assert!(!path.has_symbolic_branch());
    }

    #[test]
    fn test_inferred_semantic_nop() {
        let lifter = ConcolicLifter::new();
        let mut state = ConcolicState::new_symbolic_32();
        state.concrete_stack.clear();
        state.symbolic_stack.clear();
        let ops = vec![ConcolicMicroOp::Nop, ConcolicMicroOp::Halt];
        let output = lifter.lift(&ops, state).unwrap();
        // Empty stack + no reg changes → Nop
        assert_eq!(output.inferred_semantic, InferredSemantic::Nop);
    }

    #[test]
    fn test_x86_reg_from_index() {
        assert_eq!(X86Reg::from_index(0), Some(X86Reg::Eax));
        assert_eq!(X86Reg::from_index(7), Some(X86Reg::Edi));
        assert_eq!(X86Reg::from_index(255), None);
    }

    #[test]
    fn test_x86_reg_name() {
        assert_eq!(X86Reg::Esi.name(), "ESI");
        assert_eq!(X86Reg::R15.name(), "R15");
    }
}


#[cfg(test)]
mod collect_vars_agreement_tests {
    use super::{SymBinOp, SymbolicValue};

    /// The superseded recursive collector and the iterative one that replaced
    /// it must return the same variable set. Depth is kept small on purpose:
    /// the recursive form is exactly the one that cannot take a deep tree.
    #[test]
    fn recursive_and_iterative_agree() {
        let expr = SymbolicValue::BinOp {
            op: SymBinOp::Add,
            lhs: Box::new(SymbolicValue::Var { name: "a".to_string(), bits: 64 }),
            rhs: Box::new(SymbolicValue::BinOp {
                op: SymBinOp::Add,
                lhs: Box::new(SymbolicValue::Var { name: "b".to_string(), bits: 64 }),
                rhs: Box::new(SymbolicValue::Concrete(7)),
            }),
        };

        let iterative = expr.symbolic_vars();

        let mut recursive = Vec::new();
        expr.collect_vars(&mut recursive);
        recursive.sort();
        recursive.dedup();

        assert_eq!(iterative, recursive, "the two traversals must agree");
        assert_eq!(iterative, vec!["a".to_string(), "b".to_string()]);
    }
}
