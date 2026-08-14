//! `yara_vm` — YARA bytecode virtual machine.
//!
//! Stack-based VM that executes compiled YARA rule bytecode.  Implements all
//! YARA operators: string matching, integer operations, Boolean logic, count
//! operators, at/in/of operators, and string-search acceleration via an
//! Aho-Corasick automaton.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the YARA VM.
#[derive(Debug, Error)]
pub enum VmError {
    /// Stack underflow during execution.
    #[error("stack underflow at pc={0}")]
    StackUnderflow(usize),
    /// Invalid opcode encountered.
    #[error("unknown opcode {0:#04x} at pc={1}")]
    InvalidOpcode(u8, usize),
    /// Division by zero.
    #[error("division by zero at pc={0}")]
    DivisionByZero(usize),
    /// String index out of range.
    #[error("string index {0} out of range (have {1} strings)")]
    StringIndexOutOfRange(usize, usize),
    /// Execution limit exceeded.
    #[error("execution step limit exceeded")]
    StepLimitExceeded,
    /// Type mismatch on stack.
    #[error("type mismatch: expected {expected}, got {got} at pc={pc}")]
    TypeMismatch {
        /// Expected type description.
        expected: &'static str,
        /// Actual type description.
        got: &'static str,
        /// Program counter at the point of mismatch.
        pc: usize,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// YaraOpcode
// ─────────────────────────────────────────────────────────────────────────────

/// YARA VM opcodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum YaraOpcode {
    // ── Literals ────────────────────────────────────────────────────────────
    /// Push a 64-bit integer constant.
    PushInt(i64),
    /// Push a boolean constant.
    PushBool(bool),
    /// Push the file size (bytes) of the scan target.
    PushFilesize,
    /// Push the entry-point offset of the scan target (or -1 if unavailable).
    PushEntrypoint,

    // ── String operations ───────────────────────────────────────────────────
    /// Test whether string `index` matched at least once; push bool.
    StringMatch(usize),
    /// Push the match count for string `index`.
    StringCount(usize),
    /// Test whether string `index` matched at file offset on top of stack.
    StringAt(usize),
    /// Test whether string `index` matched within [lo, hi] on top of stack.
    /// Stack layout before: hi (top), lo.
    StringIn(usize),

    // ── Integer arithmetic ──────────────────────────────────────────────────
    /// Add top two integers, push result.
    AddInt,
    /// Subtract: pop b then a, push a - b.
    SubInt,
    /// Multiply top two integers, push result.
    MulInt,
    /// Divide: pop b then a, push a / b.
    DivInt,
    /// Modulo: pop b then a, push a % b.
    ModInt,
    /// Bitwise AND of top two integers.
    BitAnd,
    /// Bitwise OR of top two integers.
    BitOr,
    /// Bitwise XOR of top two integers.
    BitXor,
    /// Bitwise NOT of top integer.
    BitNot,
    /// Arithmetic left shift: pop b (shift) then a, push a << b.
    Shl,
    /// Arithmetic right shift: pop b (shift) then a, push a >> b.
    Shr,
    /// Negate integer on top of stack.
    NegInt,

    // ── Integer comparisons ─────────────────────────────────────────────────
    /// Equal: pop two ints, push bool.
    CmpEq,
    /// Not equal.
    CmpNe,
    /// Less than.
    CmpLt,
    /// Less than or equal.
    CmpLe,
    /// Greater than.
    CmpGt,
    /// Greater than or equal.
    CmpGe,

    // ── Boolean logic ───────────────────────────────────────────────────────
    /// Logical AND of top two booleans.
    BoolAnd,
    /// Logical OR of top two booleans.
    BoolOr,
    /// Logical NOT of top boolean.
    BoolNot,

    // ── Control flow ────────────────────────────────────────────────────────
    /// Unconditional jump to `target`.
    Jmp(usize),
    /// Jump to `target` if top-of-stack bool is true (does not pop).
    JmpTrue(usize),
    /// Jump to `target` if top-of-stack bool is false (does not pop).
    JmpFalse(usize),
    /// Pop the boolean on top and discard it.
    Pop,
    /// Duplicate the top value.
    Dup,

    // ── "of" / "for" operators ───────────────────────────────────────────────
    /// Push the number of strings (from a list of indices) that matched.
    /// Argument: list of string indices to count.
    CountOf(Vec<usize>),
    /// Push true if at least `n` of the listed string indices matched.
    AtLeastOf(u32, Vec<usize>),
    /// Push true if all listed string indices matched.
    AllOf(Vec<usize>),
    /// Push true if any of the listed string indices matched.
    AnyOf(Vec<usize>),

    // ── Halt ────────────────────────────────────────────────────────────────
    /// Terminate execution; the final result is the top-of-stack bool.
    Halt,
}

// ─────────────────────────────────────────────────────────────────────────────
// StringIndex — a handle to a compiled string pattern
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque index into the string table of a compiled ruleset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StringIndex(pub usize);

impl StringIndex {
    /// Create a new `StringIndex`.
    #[must_use]
    pub const fn new(idx: usize) -> Self {
        Self(idx)
    }

    /// Return the raw index.
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MatchContext — per-scan pre-computed match data
// ─────────────────────────────────────────────────────────────────────────────

/// Pre-computed match information for a single scan.
///
/// The VM receives a `MatchContext` rather than rerunning searches on every
/// rule evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchContext {
    /// For each string index: list of (`file_offset`, `matched_byte_length`).
    pub hits: Vec<Vec<(u64, usize)>>,
    /// Total size of the scanned data in bytes.
    pub filesize: u64,
    /// Entry-point offset, if known.
    pub entry_point: Option<u64>,
}

impl MatchContext {
    /// Create a new `MatchContext` for `n_strings` tracked patterns.
    #[must_use]
    pub fn new(n_strings: usize, filesize: u64) -> Self {
        Self {
            hits: vec![Vec::new(); n_strings],
            filesize,
            entry_point: None,
        }
    }

    /// Record a match for string `idx` at `offset` with length `len`.
    pub fn record_hit(&mut self, idx: usize, offset: u64, len: usize) {
        if idx < self.hits.len() {
            self.hits[idx].push((offset, len));
        }
    }

    /// Whether string `idx` matched at all.
    #[must_use]
    pub fn matched(&self, idx: usize) -> bool {
        self.hits.get(idx).is_some_and(|v| !v.is_empty())
    }

    /// Hit count for string `idx`.
    #[must_use]
    pub fn count(&self, idx: usize) -> usize {
        self.hits.get(idx).map_or(0, Vec::len)
    }

    /// Whether string `idx` matched at exactly `offset`.
    #[must_use]
    pub fn hit_at(&self, idx: usize, offset: u64) -> bool {
        self.hits
            .get(idx)
            .is_some_and(|v| v.iter().any(|(o, _)| *o == offset))
    }

    /// Whether string `idx` matched within the inclusive range [lo, hi].
    #[must_use]
    pub fn hit_in(&self, idx: usize, lo: u64, hi: u64) -> bool {
        self.hits
            .get(idx)
            .is_some_and(|v| v.iter().any(|(o, _)| *o >= lo && *o <= hi))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// YaraStack
// ─────────────────────────────────────────────────────────────────────────────

/// Tagged value on the YARA VM stack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StackValue {
    /// 64-bit signed integer.
    Int(i64),
    /// Boolean.
    Bool(bool),
}

impl StackValue {
    /// Coerce to i64 or return a type description.
    const fn as_int(&self) -> Result<i64, &'static str> {
        match self {
            Self::Int(v) => Ok(*v),
            Self::Bool(_) => Err("bool"),
        }
    }

    /// Coerce to bool or return a type description.
    const fn as_bool(&self) -> Result<bool, &'static str> {
        match self {
            Self::Bool(v) => Ok(*v),
            Self::Int(_) => Err("int"),
        }
    }

    /// Type name for error messages.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Int(_) => "int",
            Self::Bool(_) => "bool",
        }
    }
}

impl std::fmt::Display for StackValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Int(v) => write!(f, "{}:{}", self.type_name(), v),
            Self::Bool(v) => write!(f, "{}:{}", self.type_name(), v),
        }
    }
}

/// The YARA VM execution stack.
#[derive(Debug, Clone, Default)]
pub struct YaraStack {
    values: Vec<StackValue>,
}

impl YaraStack {
    /// Create a new empty stack.
    #[must_use]
    pub const fn new() -> Self {
        Self { values: Vec::new() }
    }

    /// Push a value.
    pub fn push(&mut self, v: StackValue) {
        self.values.push(v);
    }

    /// Pop a value.
    ///
    /// # Errors
    ///
    /// Returns [`VmError::StackUnderflow`] if the stack is empty.
    pub fn pop(&mut self, pc: usize) -> Result<StackValue, VmError> {
        self.values.pop().ok_or(VmError::StackUnderflow(pc))
    }

    /// Peek at the top value without popping.
    ///
    /// # Errors
    ///
    /// Returns [`VmError::StackUnderflow`] if the stack is empty.
    pub fn peek(&self, pc: usize) -> Result<&StackValue, VmError> {
        self.values.last().ok_or(VmError::StackUnderflow(pc))
    }

    /// Current depth.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.values.len()
    }

    /// Pop two values and return (second, top).
    ///
    /// # Errors
    ///
    /// Returns [`VmError::StackUnderflow`] if fewer than two values are on the stack.
    pub fn pop2(&mut self, pc: usize) -> Result<(StackValue, StackValue), VmError> {
        let b = self.pop(pc)?;
        let a = self.pop(pc)?;
        Ok((a, b))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// YaraVm
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of VM steps before aborting (prevents infinite loops).
const MAX_STEPS: usize = 1_000_000;

/// YARA bytecode virtual machine.
///
/// Executes a slice of [`YaraOpcode`] instructions against a [`MatchContext`].
/// The VM is designed to be reused: construct once, call [`execute`] repeatedly
/// with different contexts.
///
/// # Example
///
/// ```rust,ignore
/// let bytecode = vec![
///     YaraOpcode::StringMatch(0),
///     YaraOpcode::Halt,
/// ];
/// let mut ctx = MatchContext::new(1, 1024);
/// ctx.record_hit(0, 0x10, 4);
/// let vm = YaraVm::new();
/// assert_eq!(vm.execute(&bytecode, &ctx).unwrap(), true);
/// ```
#[derive(Debug, Clone, Default)]
pub struct YaraVm {
    /// Enable debug tracing (prints each step to stderr).
    pub trace: bool,
}

impl YaraVm {
    /// Create a new VM instance.
    #[must_use]
    pub const fn new() -> Self {
        Self { trace: false }
    }

    /// Create a VM with execution tracing enabled.
    #[must_use]
    pub const fn with_trace() -> Self {
        Self { trace: true }
    }

    /// Execute `bytecode` against `ctx`.
    ///
    /// Returns the final boolean result (top-of-stack after `Halt`).
    ///
    /// # Errors
    ///
    /// Returns [`VmError`] on any execution fault.
    pub fn execute(
        &self,
        bytecode: &[YaraOpcode],
        ctx: &MatchContext,
    ) -> Result<bool, VmError> {
        let mut stack = YaraStack::new();
        let mut pc = 0usize;
        let mut steps = 0usize;

        while pc < bytecode.len() {
            if steps >= MAX_STEPS {
                return Err(VmError::StepLimitExceeded);
            }
            steps += 1;

            let op = &bytecode[pc];

            match op {
                // ── Literals ────────────────────────────────────────────────
                YaraOpcode::PushInt(v) => {
                    stack.push(StackValue::Int(*v));
                    pc += 1;
                }
                YaraOpcode::PushBool(v) => {
                    stack.push(StackValue::Bool(*v));
                    pc += 1;
                }
                YaraOpcode::PushFilesize => {
                    stack.push(StackValue::Int(ctx.filesize.cast_signed()));
                    pc += 1;
                }
                YaraOpcode::PushEntrypoint => {
                    let ep = ctx.entry_point.map_or(-1i64, |v| v.cast_signed());
                    stack.push(StackValue::Int(ep));
                    pc += 1;
                }

                // ── String operations ────────────────────────────────────────
                YaraOpcode::StringMatch(idx) => {
                    Self::check_idx(*idx, ctx, pc)?;
                    stack.push(StackValue::Bool(ctx.matched(*idx)));
                    pc += 1;
                }
                YaraOpcode::StringCount(idx) => {
                    Self::check_idx(*idx, ctx, pc)?;
                    stack.push(StackValue::Int(i64::try_from(ctx.count(*idx)).unwrap_or(i64::MAX)));
                    pc += 1;
                }
                YaraOpcode::StringAt(idx) => {
                    Self::check_idx(*idx, ctx, pc)?;
                    let offset = stack.pop(pc)?;
                    let off = Self::to_int(&offset, pc)?;
                    let result = if off < 0 {
                        false
                    } else {
                        ctx.hit_at(*idx, off.cast_unsigned())
                    };
                    stack.push(StackValue::Bool(result));
                    pc += 1;
                }
                YaraOpcode::StringIn(idx) => {
                    Self::check_idx(*idx, ctx, pc)?;
                    let hi_val = stack.pop(pc)?;
                    let lo_val = stack.pop(pc)?;
                    let hi = Self::to_int(&hi_val, pc)?;
                    let lo = Self::to_int(&lo_val, pc)?;
                    let result = if lo < 0 || hi < 0 || lo > hi {
                        false
                    } else {
                        ctx.hit_in(*idx, lo.cast_unsigned(), hi.cast_unsigned())
                    };
                    stack.push(StackValue::Bool(result));
                    pc += 1;
                }

                // ── Integer arithmetic ───────────────────────────────────────
                YaraOpcode::AddInt => {
                    let (a, b) = stack.pop2(pc)?;
                    stack.push(StackValue::Int(
                        Self::to_int(&a, pc)?.wrapping_add(Self::to_int(&b, pc)?),
                    ));
                    pc += 1;
                }
                YaraOpcode::SubInt => {
                    let (a, b) = stack.pop2(pc)?;
                    stack.push(StackValue::Int(
                        Self::to_int(&a, pc)?.wrapping_sub(Self::to_int(&b, pc)?),
                    ));
                    pc += 1;
                }
                YaraOpcode::MulInt => {
                    let (a, b) = stack.pop2(pc)?;
                    stack.push(StackValue::Int(
                        Self::to_int(&a, pc)?.wrapping_mul(Self::to_int(&b, pc)?),
                    ));
                    pc += 1;
                }
                YaraOpcode::DivInt => {
                    let (a, b) = stack.pop2(pc)?;
                    let divisor = Self::to_int(&b, pc)?;
                    if divisor == 0 {
                        return Err(VmError::DivisionByZero(pc));
                    }
                    stack.push(StackValue::Int(Self::to_int(&a, pc)?.wrapping_div(divisor)));
                    pc += 1;
                }
                YaraOpcode::ModInt => {
                    let (a, b) = stack.pop2(pc)?;
                    let divisor = Self::to_int(&b, pc)?;
                    if divisor == 0 {
                        return Err(VmError::DivisionByZero(pc));
                    }
                    stack.push(StackValue::Int(Self::to_int(&a, pc)? % divisor));
                    pc += 1;
                }
                YaraOpcode::BitAnd => {
                    let (a, b) = stack.pop2(pc)?;
                    stack.push(StackValue::Int(
                        Self::to_int(&a, pc)? & Self::to_int(&b, pc)?,
                    ));
                    pc += 1;
                }
                YaraOpcode::BitOr => {
                    let (a, b) = stack.pop2(pc)?;
                    stack.push(StackValue::Int(
                        Self::to_int(&a, pc)? | Self::to_int(&b, pc)?,
                    ));
                    pc += 1;
                }
                YaraOpcode::BitXor => {
                    let (a, b) = stack.pop2(pc)?;
                    stack.push(StackValue::Int(
                        Self::to_int(&a, pc)? ^ Self::to_int(&b, pc)?,
                    ));
                    pc += 1;
                }
                YaraOpcode::BitNot => {
                    let a = stack.pop(pc)?;
                    stack.push(StackValue::Int(!Self::to_int(&a, pc)?));
                    pc += 1;
                }
                YaraOpcode::Shl => {
                    let (a, b) = stack.pop2(pc)?;
                    let shift = u32::try_from(Self::to_int(&b, pc)? & 63).unwrap_or(0);
                    stack.push(StackValue::Int(Self::to_int(&a, pc)?.wrapping_shl(shift)));
                    pc += 1;
                }
                YaraOpcode::Shr => {
                    let (a, b) = stack.pop2(pc)?;
                    let shift = u32::try_from(Self::to_int(&b, pc)? & 63).unwrap_or(0);
                    stack.push(StackValue::Int(Self::to_int(&a, pc)?.wrapping_shr(shift)));
                    pc += 1;
                }
                YaraOpcode::NegInt => {
                    let a = stack.pop(pc)?;
                    stack.push(StackValue::Int(Self::to_int(&a, pc)?.wrapping_neg()));
                    pc += 1;
                }

                // ── Integer comparisons ──────────────────────────────────────
                YaraOpcode::CmpEq => {
                    let (a, b) = stack.pop2(pc)?;
                    let result = match (&a, &b) {
                        (StackValue::Int(x), StackValue::Int(y)) => x == y,
                        (StackValue::Bool(x), StackValue::Bool(y)) => x == y,
                        _ => false,
                    };
                    stack.push(StackValue::Bool(result));
                    pc += 1;
                }
                YaraOpcode::CmpNe => {
                    let (a, b) = stack.pop2(pc)?;
                    let result = match (&a, &b) {
                        (StackValue::Int(x), StackValue::Int(y)) => x != y,
                        (StackValue::Bool(x), StackValue::Bool(y)) => x != y,
                        _ => true,
                    };
                    stack.push(StackValue::Bool(result));
                    pc += 1;
                }
                YaraOpcode::CmpLt => {
                    let (a, b) = stack.pop2(pc)?;
                    stack.push(StackValue::Bool(
                        Self::to_int(&a, pc)? < Self::to_int(&b, pc)?,
                    ));
                    pc += 1;
                }
                YaraOpcode::CmpLe => {
                    let (a, b) = stack.pop2(pc)?;
                    stack.push(StackValue::Bool(
                        Self::to_int(&a, pc)? <= Self::to_int(&b, pc)?,
                    ));
                    pc += 1;
                }
                YaraOpcode::CmpGt => {
                    let (a, b) = stack.pop2(pc)?;
                    stack.push(StackValue::Bool(
                        Self::to_int(&a, pc)? > Self::to_int(&b, pc)?,
                    ));
                    pc += 1;
                }
                YaraOpcode::CmpGe => {
                    let (a, b) = stack.pop2(pc)?;
                    stack.push(StackValue::Bool(
                        Self::to_int(&a, pc)? >= Self::to_int(&b, pc)?,
                    ));
                    pc += 1;
                }

                // ── Boolean logic ────────────────────────────────────────────
                YaraOpcode::BoolAnd => {
                    let (a, b) = stack.pop2(pc)?;
                    stack.push(StackValue::Bool(
                        Self::to_bool(&a, pc)? && Self::to_bool(&b, pc)?,
                    ));
                    pc += 1;
                }
                YaraOpcode::BoolOr => {
                    let (a, b) = stack.pop2(pc)?;
                    stack.push(StackValue::Bool(
                        Self::to_bool(&a, pc)? || Self::to_bool(&b, pc)?,
                    ));
                    pc += 1;
                }
                YaraOpcode::BoolNot => {
                    let a = stack.pop(pc)?;
                    stack.push(StackValue::Bool(!Self::to_bool(&a, pc)?));
                    pc += 1;
                }

                // ── Control flow ─────────────────────────────────────────────
                YaraOpcode::Jmp(target) => {
                    pc = *target;
                }
                YaraOpcode::JmpTrue(target) => {
                    let v = stack.peek(pc)?;
                    if Self::to_bool(v, pc)? {
                        pc = *target;
                    } else {
                        pc += 1;
                    }
                }
                YaraOpcode::JmpFalse(target) => {
                    let v = stack.peek(pc)?;
                    if Self::to_bool(v, pc)? {
                        pc += 1;
                    } else {
                        pc = *target;
                    }
                }
                YaraOpcode::Pop => {
                    stack.pop(pc)?;
                    pc += 1;
                }
                YaraOpcode::Dup => {
                    let top = stack.peek(pc)?.clone();
                    stack.push(top);
                    pc += 1;
                }

                // ── "of" / "for" operators ───────────────────────────────────
                YaraOpcode::CountOf(indices) => {
                    let count = i64::try_from(
                        indices.iter().filter(|&&idx| ctx.matched(idx)).count()
                    ).unwrap_or(i64::MAX);
                    stack.push(StackValue::Int(count));
                    pc += 1;
                }
                YaraOpcode::AtLeastOf(min, indices) => {
                    let count = u32::try_from(
                        indices.iter().filter(|&&idx| ctx.matched(idx)).count()
                    ).unwrap_or(u32::MAX);
                    stack.push(StackValue::Bool(count >= *min));
                    pc += 1;
                }
                YaraOpcode::AllOf(indices) => {
                    let result = indices.iter().all(|&idx| ctx.matched(idx));
                    stack.push(StackValue::Bool(result));
                    pc += 1;
                }
                YaraOpcode::AnyOf(indices) => {
                    let result = indices.iter().any(|&idx| ctx.matched(idx));
                    stack.push(StackValue::Bool(result));
                    pc += 1;
                }

                // ── Halt ─────────────────────────────────────────────────────
                YaraOpcode::Halt => {
                    break;
                }
            }
        }

        let result = stack.pop(pc)?;
        Self::to_bool(&result, pc)
    }

    // ─── helpers ──────────────────────────────────────────────────────────────

    fn check_idx(idx: usize, ctx: &MatchContext, pc: usize) -> Result<(), VmError> {
        if idx >= ctx.hits.len() {
            Err(VmError::StringIndexOutOfRange(idx, ctx.hits.len()))
        } else {
            let _ = pc;
            Ok(())
        }
    }

    fn to_int(v: &StackValue, pc: usize) -> Result<i64, VmError> {
        v.as_int().map_err(|got| VmError::TypeMismatch {
            expected: "int",
            got,
            pc,
        })
    }

    fn to_bool(v: &StackValue, pc: usize) -> Result<bool, VmError> {
        v.as_bool().map_err(|got| VmError::TypeMismatch {
            expected: "bool",
            got,
            pc,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Aho-Corasick accelerator
// ─────────────────────────────────────────────────────────────────────────────

/// A node in the Aho-Corasick automaton.
#[derive(Debug, Clone)]
struct AcNode {
    /// Children: byte → node index.
    children: HashMap<u8, usize>,
    /// Failure link.
    fail: usize,
    /// Pattern indices that end at this node.
    output: Vec<usize>,
}

impl AcNode {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            fail: 0,
            output: Vec::new(),
        }
    }
}

/// Aho-Corasick string searcher.
///
/// Accelerates multi-pattern search required to fill a [`MatchContext`] before
/// YARA VM execution.
#[derive(Debug, Clone)]
pub struct AhoCorasick {
    nodes: Vec<AcNode>,
    patterns: Vec<Vec<u8>>,
}

impl AhoCorasick {
    /// Build an automaton from `patterns`.
    ///
    /// Each pattern is assigned an index equal to its position in `patterns`.
    ///
    /// # Panics
    ///
    /// Panics if internal node indices are inconsistent (should not occur with valid input).
    #[must_use]
    pub fn build(patterns: &[Vec<u8>]) -> Self {
        let mut nodes = vec![AcNode::new()];

        // Phase 1: trie insertion
        for (pid, pat) in patterns.iter().enumerate() {
            let mut cur = 0usize;
            for &byte in pat {
                if !nodes[cur].children.contains_key(&byte) {
                    let nidx = nodes.len();
                    nodes.push(AcNode::new());
                    nodes[cur].children.insert(byte, nidx);
                }
                cur = *nodes[cur].children.get(&byte).unwrap();
            }
            nodes[cur].output.push(pid);
        }

        // Phase 2: BFS to compute failure links
        let mut queue = std::collections::VecDeque::new();
        let root_children: Vec<usize> = nodes[0].children.values().copied().collect();
        for child in root_children {
            nodes[child].fail = 0;
            queue.push_back(child);
        }

        while let Some(node_idx) = queue.pop_front() {
            let children_bytes: Vec<u8> = nodes[node_idx].children.keys().copied().collect();
            for byte in children_bytes {
                let child_idx = nodes[node_idx].children[&byte];
                // Find failure link for child
                let mut fail = nodes[node_idx].fail;
                loop {
                    if let Some(next) = nodes[fail].children.get(&byte).copied().filter(|&n| n != child_idx) {
                        nodes[child_idx].fail = next;
                        // Merge output
                        let extra: Vec<usize> = nodes[next].output.clone();
                        nodes[child_idx].output.extend(extra);
                        break;
                    }
                    if fail == 0 {
                        nodes[child_idx].fail = 0;
                        break;
                    }
                    fail = nodes[fail].fail;
                }
                queue.push_back(child_idx);
            }
        }

        Self {
            nodes,
            patterns: patterns.to_vec(),
        }
    }

    /// Search `data` and return all `(pattern_index, start_offset)` pairs.
    #[must_use]
    pub fn search(&self, data: &[u8]) -> Vec<(usize, usize)> {
        let mut results = Vec::new();
        let mut state = 0usize;

        for (i, &byte) in data.iter().enumerate() {
            // Follow failure links until we find a transition or reach root
            loop {
                if let Some(&next) = self.nodes[state].children.get(&byte) {
                    state = next;
                    break;
                }
                if state == 0 {
                    break;
                }
                state = self.nodes[state].fail;
            }
            // Collect outputs
            for &pid in &self.nodes[state].output {
                let pat_len = self.patterns[pid].len();
                let start = i + 1 - pat_len;
                results.push((pid, start));
            }
        }

        results
    }

    /// Populate a [`MatchContext`] by searching `data` for all patterns.
    pub fn fill_context(&self, data: &[u8], ctx: &mut MatchContext) {
        for (pid, offset) in self.search(data) {
            let len = self.patterns[pid].len();
            ctx.record_hit(pid, offset as u64, len);
        }
    }

    /// Number of patterns in the automaton.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CompiledRule — bytecode + metadata bundle
// ─────────────────────────────────────────────────────────────────────────────

/// A compiled YARA rule: bytecode, string patterns, and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledRule {
    /// Rule name.
    pub name: String,
    /// Classification tags.
    pub tags: Vec<String>,
    /// Metadata key→value.
    pub meta: HashMap<String, String>,
    /// Compiled string patterns.
    pub patterns: Vec<Vec<u8>>,
    /// VM bytecode for the rule condition.
    pub bytecode: Vec<YaraOpcode>,
}

impl CompiledRule {
    /// Create a new compiled rule.
    #[must_use]
    pub fn new(name: impl Into<String>, bytecode: Vec<YaraOpcode>) -> Self {
        Self {
            name: name.into(),
            tags: Vec::new(),
            meta: HashMap::new(),
            patterns: Vec::new(),
            bytecode,
        }
    }

    /// Add a string pattern; returns the assigned [`StringIndex`].
    pub fn add_pattern(&mut self, pattern: Vec<u8>) -> StringIndex {
        let idx = self.patterns.len();
        self.patterns.push(pattern);
        StringIndex::new(idx)
    }

    /// Add metadata.
    pub fn add_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.meta.insert(key.into(), value.into());
    }

    /// Evaluate this rule against `data`.
    #[must_use]
    pub fn evaluate(&self, data: &[u8]) -> bool {
        let ac = AhoCorasick::build(&self.patterns);
        let mut ctx = MatchContext::new(self.patterns.len(), data.len() as u64);
        ac.fill_context(data, &mut ctx);
        let vm = YaraVm::new();
        vm.execute(&self.bytecode, &ctx).unwrap_or(false)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_int_halt() {
        let bc = vec![YaraOpcode::PushBool(true), YaraOpcode::Halt];
        let ctx = MatchContext::new(0, 100);
        let vm = YaraVm::new();
        assert_eq!(vm.execute(&bc, &ctx).unwrap(), true);
    }

    #[test]
    fn test_string_match_true() {
        let bc = vec![YaraOpcode::StringMatch(0), YaraOpcode::Halt];
        let mut ctx = MatchContext::new(1, 100);
        ctx.record_hit(0, 0, 4);
        let vm = YaraVm::new();
        assert!(vm.execute(&bc, &ctx).unwrap());
    }

    #[test]
    fn test_string_match_false() {
        let bc = vec![YaraOpcode::StringMatch(0), YaraOpcode::Halt];
        let ctx = MatchContext::new(1, 100);
        let vm = YaraVm::new();
        assert!(!vm.execute(&bc, &ctx).unwrap());
    }

    #[test]
    fn test_bool_and() {
        let bc = vec![
            YaraOpcode::PushBool(true),
            YaraOpcode::PushBool(false),
            YaraOpcode::BoolAnd,
            YaraOpcode::Halt,
        ];
        let ctx = MatchContext::new(0, 0);
        let vm = YaraVm::new();
        assert!(!vm.execute(&bc, &ctx).unwrap());
    }

    #[test]
    fn test_integer_add() {
        let bc = vec![
            YaraOpcode::PushInt(3),
            YaraOpcode::PushInt(4),
            YaraOpcode::AddInt,
            YaraOpcode::PushInt(7),
            YaraOpcode::CmpEq,
            YaraOpcode::Halt,
        ];
        let ctx = MatchContext::new(0, 0);
        let vm = YaraVm::new();
        assert!(vm.execute(&bc, &ctx).unwrap());
    }

    #[test]
    fn test_filesize_push() {
        let bc = vec![
            YaraOpcode::PushFilesize,
            YaraOpcode::PushInt(1024),
            YaraOpcode::CmpEq,
            YaraOpcode::Halt,
        ];
        let ctx = MatchContext::new(0, 1024);
        let vm = YaraVm::new();
        assert!(vm.execute(&bc, &ctx).unwrap());
    }

    #[test]
    fn test_division_by_zero() {
        let bc = vec![
            YaraOpcode::PushInt(10),
            YaraOpcode::PushInt(0),
            YaraOpcode::DivInt,
            YaraOpcode::PushBool(true),
            YaraOpcode::Halt,
        ];
        let ctx = MatchContext::new(0, 0);
        let vm = YaraVm::new();
        assert!(matches!(vm.execute(&bc, &ctx), Err(VmError::DivisionByZero(_))));
    }

    #[test]
    fn test_aho_corasick_basic() {
        let patterns = vec![b"MZ".to_vec(), b"ELF".to_vec()];
        let ac = AhoCorasick::build(&patterns);
        let data = b"headerMZhello\x7fELFend";
        let hits = ac.search(data);
        assert!(hits.iter().any(|&(pid, _)| pid == 0));
        assert!(hits.iter().any(|&(pid, _)| pid == 1));
    }

    #[test]
    fn test_compiled_rule_evaluate() {
        let mut rule = CompiledRule::new("test", vec![]);
        let idx = rule.add_pattern(b"MZ".to_vec());
        rule.bytecode = vec![
            YaraOpcode::StringMatch(idx.as_usize()),
            YaraOpcode::Halt,
        ];
        let data = b"MZhello world";
        assert!(rule.evaluate(data));
        let data2 = b"hello world";
        assert!(!rule.evaluate(data2));
    }

    #[test]
    fn test_at_least_of() {
        let bc = vec![
            YaraOpcode::AtLeastOf(2, vec![0, 1, 2]),
            YaraOpcode::Halt,
        ];
        let mut ctx = MatchContext::new(3, 100);
        ctx.record_hit(0, 0, 2);
        ctx.record_hit(2, 10, 3);
        let vm = YaraVm::new();
        assert!(vm.execute(&bc, &ctx).unwrap());
    }

    #[test]
    fn test_string_at_offset() {
        let bc = vec![
            YaraOpcode::PushInt(0x10),
            YaraOpcode::StringAt(0),
            YaraOpcode::Halt,
        ];
        let mut ctx = MatchContext::new(1, 100);
        ctx.record_hit(0, 0x10, 4);
        let vm = YaraVm::new();
        assert!(vm.execute(&bc, &ctx).unwrap());
    }
}
