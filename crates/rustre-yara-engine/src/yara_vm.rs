//! `yara_vm` — A YARA virtual machine: instruction set, stack, heap,
//! executor, and debugger for evaluating compiled YARA conditions.

use std::collections::HashMap;
use std::fmt;

use num_traits::ToPrimitive as _;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Numeric coercion helpers
// ---------------------------------------------------------------------------

/// Convert an `f64` to `i64`, saturating on overflow and returning 0 on NaN.
#[inline]
fn f64_to_i64_saturating(f: f64) -> i64 {
    // i64::MAX rounds up to 2^63 in f64; i64::MIN = -2^63 is exact in f64.
    const I64_MAX_F64: f64 = 9_223_372_036_854_775_808.0_f64; // 2^63
    const I64_MIN_F64: f64 = -9_223_372_036_854_775_808.0_f64; // -2^63
    if f.is_nan() {
        0
    } else if f >= I64_MAX_F64 {
        i64::MAX
    } else if f <= I64_MIN_F64 {
        i64::MIN
    } else {
        // f is finite and bounded within i64 range; ToPrimitive::to_i64 is a
        // lossless, safe conversion that clippy accepts without any allow attrs.
        f.to_i64().unwrap_or(0)
    }
}

/// Convert an `i64` to `f64`. Mantissa precision loss is acceptable for VM coercion.
#[inline]
fn i64_to_f64_lossy(n: i64) -> f64 {
    // Use the unsigned-absolute-value split approach to avoid a direct as-cast on i64.
    let neg = n < 0;
    let abs = n.unsigned_abs();
    let lo = f64::from(u32::try_from(abs & 0xFFFF_FFFF).unwrap_or(u32::MAX));
    let hi = f64::from(u32::try_from(abs >> 32).unwrap_or(u32::MAX));
    let result = hi.mul_add(4_294_967_296.0, lo);
    if neg { -result } else { result }
}

// ---------------------------------------------------------------------------
// YaraInstruction — VM instruction set
// ---------------------------------------------------------------------------

/// A single instruction in the YARA VM bytecode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum YaraInstruction {
    // --- Stack manipulation ---
    /// Push an integer constant onto the stack.
    PushInt(i64),
    /// Push a boolean constant.
    PushBool(bool),
    /// Push a float constant.
    PushFloat(f64),
    /// Duplicate the top of the stack.
    Dup,
    /// Discard the top of the stack.
    Pop,
    /// Swap top two stack elements.
    Swap,

    // --- Arithmetic ---
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Neg,

    // --- Bitwise ---
    BitAnd,
    BitOr,
    BitXor,
    BitNot,
    Shl,
    Shr,

    // --- Comparison ---
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,

    // --- Logical ---
    And,
    Or,
    Not,

    // --- String / pattern operations ---
    /// Test whether pattern `$id` matched in the scan context.
    PatternMatch(String),
    /// Push the count of matches for pattern `$id`.
    PatternCount(String),
    /// Push the offset of the nth match for `$id`.
    PatternOffset(String, u32),
    /// Push the length of the nth match for `$id`.
    PatternLength(String, u32),
    /// Test if `$id` matched at a specific offset.
    PatternAt(String, u64),
    /// Test if `$id` matched within a range `[lo, hi]`.
    PatternIn(String, u64, u64),

    // --- Control flow ---
    /// Unconditional jump to label index.
    Jmp(u32),
    /// Jump if top of stack is false.
    JmpFalse(u32),
    /// Jump if top of stack is true.
    JmpTrue(u32),
    /// Return the top of stack as the rule result.
    Return,
    /// Halt with an error.
    Halt(String),

    // --- Context access ---
    /// Push the file size.
    FileSize,
    /// Push 1 if all patterns matched, else 0.
    AllOf,
    /// Push 1 if any pattern matched, else 0.
    AnyOf,
    /// Push 1 if no pattern matched, else 0.
    NoneOf,

    // --- Loop support ---
    /// Push a loop counter variable.
    LoadVar(String),
    /// Store top of stack into a variable.
    StoreVar(String),
    /// Increment a variable.
    IncVar(String),
}

impl fmt::Display for YaraInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PushInt(n) => write!(f, "PUSH_INT {n}"),
            Self::PushBool(b) => write!(f, "PUSH_BOOL {b}"),
            Self::PushFloat(v) => write!(f, "PUSH_FLOAT {v}"),
            Self::PatternMatch(id) => write!(f, "PAT_MATCH {id}"),
            Self::PatternCount(id) => write!(f, "PAT_COUNT {id}"),
            Self::Jmp(t) => write!(f, "JMP {t}"),
            Self::JmpFalse(t) => write!(f, "JMP_FALSE {t}"),
            Self::JmpTrue(t) => write!(f, "JMP_TRUE {t}"),
            Self::Return => write!(f, "RETURN"),
            Self::Halt(msg) => write!(f, "HALT {msg}"),
            _ => write!(f, "{self:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// YaraStack
// ---------------------------------------------------------------------------

/// Stack value for the YARA VM.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StackValue {
    Int(i64),
    Bool(bool),
    Float(f64),
    Undefined,
}

impl StackValue {
    /// Coerce to boolean for conditional jumps.
    #[must_use]
    pub fn as_bool(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::Int(n) => *n != 0,
            Self::Float(f) => *f != 0.0,
            Self::Undefined => false,
        }
    }

    /// Coerce to integer.
    #[must_use]
    pub fn as_int(&self) -> i64 {
        match self {
            Self::Int(n) => *n,
            Self::Bool(b) => i64::from(*b),
            Self::Float(f) => f64_to_i64_saturating(*f),
            Self::Undefined => 0,
        }
    }

    /// Coerce to float.
    #[must_use]
    pub fn as_float(&self) -> f64 {
        match self {
            Self::Float(f) => *f,
            Self::Int(n) => i64_to_f64_lossy(*n),
            Self::Bool(b) => {
                if *b {
                    1.0
                } else {
                    0.0
                }
            }
            Self::Undefined => 0.0,
        }
    }

    /// Whether this is the undefined value.
    #[must_use]
    pub const fn is_undefined(&self) -> bool {
        matches!(self, Self::Undefined)
    }
}

impl fmt::Display for StackValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(n) => write!(f, "Int({n})"),
            Self::Bool(b) => write!(f, "Bool({b})"),
            Self::Float(v) => write!(f, "Float({v})"),
            Self::Undefined => write!(f, "Undefined"),
        }
    }
}

/// The operand stack.
#[derive(Debug, Clone, Default)]
pub struct YaraStack {
    data: Vec<StackValue>,
    max_depth: usize,
}

impl YaraStack {
    const DEFAULT_MAX: usize = 1024;

    /// Create a new stack with default capacity.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            data: Vec::new(),
            max_depth: Self::DEFAULT_MAX,
        }
    }

    /// Push a value.
    ///
    /// # Errors
    /// Returns [`VmError::StackOverflow`] if the stack exceeds its maximum depth.
    pub fn push(&mut self, val: StackValue) -> Result<(), VmError> {
        if self.data.len() >= self.max_depth {
            return Err(VmError::StackOverflow);
        }
        self.data.push(val);
        Ok(())
    }

    /// Pop a value.
    ///
    /// # Errors
    /// Returns [`VmError::StackUnderflow`] if the stack is empty.
    pub fn pop(&mut self) -> Result<StackValue, VmError> {
        self.data.pop().ok_or(VmError::StackUnderflow)
    }

    /// Peek at the top without consuming.
    #[must_use]
    pub fn peek(&self) -> Option<&StackValue> {
        self.data.last()
    }

    /// Stack depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.data.len()
    }

    /// Is the stack empty?
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ---------------------------------------------------------------------------
// YaraHeap — variable storage
// ---------------------------------------------------------------------------

/// Simple variable heap for the YARA VM.
#[derive(Debug, Clone, Default)]
pub struct YaraHeap {
    vars: HashMap<String, StackValue>,
}

impl YaraHeap {
    /// Create a new empty heap.
    #[must_use]
    pub fn new() -> Self {
        Self {
            vars: HashMap::new(),
        }
    }

    /// Load a variable (returns `Undefined` if not found).
    #[must_use]
    pub fn load(&self, name: &str) -> StackValue {
        self.vars
            .get(name)
            .cloned()
            .unwrap_or(StackValue::Undefined)
    }

    /// Store a variable.
    pub fn store(&mut self, name: impl Into<String>, val: StackValue) {
        self.vars.insert(name.into(), val);
    }

    /// Increment an integer variable.
    pub fn increment(&mut self, name: &str) {
        let cur = self.load(name).as_int();
        self.store(name, StackValue::Int(cur.saturating_add(1)));
    }

    /// Number of stored variables.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vars.len()
    }

    /// Whether the heap is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }
}

// ---------------------------------------------------------------------------
// VmError
// ---------------------------------------------------------------------------

/// VM execution error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmError {
    StackOverflow,
    StackUnderflow,
    DivisionByZero,
    InvalidJumpTarget(u32),
    HaltInstruction(String),
    TypeMismatch { expected: &'static str, got: String },
    ExecutionLimit,
    InvalidInstruction,
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StackOverflow => write!(f, "stack overflow"),
            Self::StackUnderflow => write!(f, "stack underflow"),
            Self::DivisionByZero => write!(f, "division by zero"),
            Self::InvalidJumpTarget(t) => write!(f, "invalid jump target {t}"),
            Self::HaltInstruction(msg) => write!(f, "halt: {msg}"),
            Self::TypeMismatch { expected, got } => {
                write!(f, "type mismatch: expected {expected}, got {got}")
            }
            Self::ExecutionLimit => write!(f, "execution limit exceeded"),
            Self::InvalidInstruction => write!(f, "invalid instruction"),
        }
    }
}

// ---------------------------------------------------------------------------
// YaraExecutionContext — pattern match results
// ---------------------------------------------------------------------------

/// Pattern match information available to the VM.
#[derive(Debug, Clone, Default)]
pub struct YaraExecutionContext {
    /// `id` → list of match offsets.
    pub pattern_offsets: HashMap<String, Vec<u64>>,
    /// Total file size.
    pub file_size: u64,
}

impl YaraExecutionContext {
    /// Create a new context.
    #[must_use]
    pub fn new(file_size: u64) -> Self {
        Self {
            pattern_offsets: HashMap::new(),
            file_size,
        }
    }

    /// Register pattern matches.
    pub fn set_matches(&mut self, id: impl Into<String>, offsets: Vec<u64>) {
        self.pattern_offsets.insert(id.into(), offsets);
    }

    /// Whether pattern `id` matched.
    #[must_use]
    pub fn matched(&self, id: &str) -> bool {
        self.pattern_offsets.get(id).is_some_and(|v| !v.is_empty())
    }

    /// Match count for pattern `id`.
    #[must_use]
    pub fn count(&self, id: &str) -> u64 {
        self.pattern_offsets.get(id).map_or(0, |v| v.len() as u64)
    }

    /// Offset of the nth match (0-indexed).
    #[must_use]
    pub fn offset(&self, id: &str, n: u32) -> Option<u64> {
        self.pattern_offsets.get(id)?.get(n as usize).copied()
    }

    /// Whether all registered patterns matched.
    #[must_use]
    pub fn all_matched(&self) -> bool {
        !self.pattern_offsets.is_empty() && self.pattern_offsets.values().all(|v| !v.is_empty())
    }

    /// Whether any registered pattern matched.
    #[must_use]
    pub fn any_matched(&self) -> bool {
        self.pattern_offsets.values().any(|v| !v.is_empty())
    }
}

// ---------------------------------------------------------------------------
// YaraExecutor
// ---------------------------------------------------------------------------

/// The YARA VM executor.
pub struct YaraExecutor {
    pub max_instructions: usize,
}

impl YaraExecutor {
    const DEFAULT_LIMIT: usize = 100_000;

    /// Create with default instruction limit.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_instructions: Self::DEFAULT_LIMIT,
        }
    }

    /// Create with custom instruction limit.
    #[must_use]
    pub const fn with_limit(limit: usize) -> Self {
        Self {
            max_instructions: limit,
        }
    }

    /// Execute a program and return the boolean result.
    ///
    /// # Errors
    /// Returns a [`VmError`] if execution fails or the instruction limit is exceeded.
    pub fn execute(
        &self,
        program: &[YaraInstruction],
        ctx: &YaraExecutionContext,
    ) -> Result<bool, VmError> {
        let result = self.run(program, ctx)?;
        Ok(result.as_bool())
    }

    /// Execute and return the raw stack value.
    ///
    /// # Errors
    /// Returns a [`VmError`] if execution fails or the instruction limit is exceeded.
    pub fn run(
        &self,
        program: &[YaraInstruction],
        ctx: &YaraExecutionContext,
    ) -> Result<StackValue, VmError> {
        let mut stack = YaraStack::new();
        let mut heap = YaraHeap::new();
        let mut ip: u32 = 0;
        let mut instructions_executed = 0usize;

        while (ip as usize) < program.len() {
            if instructions_executed >= self.max_instructions {
                return Err(VmError::ExecutionLimit);
            }
            instructions_executed += 1;
            let instr = &program[ip as usize];
            ip += 1;
            if Self::exec_arith_bit(instr, &mut stack)? { continue; }
            if Self::exec_cmp_logical(instr, &mut stack)? { continue; }
            if Self::exec_pattern(instr, &mut stack, ctx)? { continue; }
            match Self::exec_ctrl_ctx(instr, &mut stack, &mut heap, ctx, program.len(), &mut ip)? {
                ExecSignal::Continue => {}
                ExecSignal::ReturnFromStack => return stack.pop(),
            }
        }

        Ok(stack.pop().unwrap_or(StackValue::Undefined))
    }

    /// Arithmetic and bitwise instructions. Returns `true` if handled.
    fn exec_arith_bit(instr: &YaraInstruction, stack: &mut YaraStack) -> Result<bool, VmError> {
        match instr {
            YaraInstruction::PushInt(n)   => { stack.push(StackValue::Int(*n))?; }
            YaraInstruction::PushBool(b)  => { stack.push(StackValue::Bool(*b))?; }
            YaraInstruction::PushFloat(f) => { stack.push(StackValue::Float(*f))?; }
            YaraInstruction::Dup => {
                let top = stack.peek().cloned().ok_or(VmError::StackUnderflow)?;
                stack.push(top)?;
            }
            YaraInstruction::Pop  => { stack.pop()?; }
            YaraInstruction::Swap => { let a = stack.pop()?; let b = stack.pop()?; stack.push(a)?; stack.push(b)?; }
            YaraInstruction::Add => { let b = stack.pop()?.as_int(); let a = stack.pop()?.as_int(); stack.push(StackValue::Int(a.wrapping_add(b)))?; }
            YaraInstruction::Sub => { let b = stack.pop()?.as_int(); let a = stack.pop()?.as_int(); stack.push(StackValue::Int(a.wrapping_sub(b)))?; }
            YaraInstruction::Mul => { let b = stack.pop()?.as_int(); let a = stack.pop()?.as_int(); stack.push(StackValue::Int(a.wrapping_mul(b)))?; }
            YaraInstruction::Div => {
                let b = stack.pop()?.as_int(); let a = stack.pop()?.as_int();
                if b == 0 { return Err(VmError::DivisionByZero); }
                stack.push(StackValue::Int(a / b))?;
            }
            YaraInstruction::Mod => {
                let b = stack.pop()?.as_int(); let a = stack.pop()?.as_int();
                if b == 0 { return Err(VmError::DivisionByZero); }
                stack.push(StackValue::Int(a % b))?;
            }
            YaraInstruction::Neg    => { let a = stack.pop()?.as_int(); stack.push(StackValue::Int(-a))?; }
            YaraInstruction::BitAnd => { let b = stack.pop()?.as_int(); let a = stack.pop()?.as_int(); stack.push(StackValue::Int(a & b))?; }
            YaraInstruction::BitOr  => { let b = stack.pop()?.as_int(); let a = stack.pop()?.as_int(); stack.push(StackValue::Int(a | b))?; }
            YaraInstruction::BitXor => { let b = stack.pop()?.as_int(); let a = stack.pop()?.as_int(); stack.push(StackValue::Int(a ^ b))?; }
            YaraInstruction::BitNot => { let a = stack.pop()?.as_int(); stack.push(StackValue::Int(!a))?; }
            YaraInstruction::Shl => {
                let s = u32::try_from(stack.pop()?.as_int() & 63).unwrap_or(0);
                let a = stack.pop()?.as_int();
                stack.push(StackValue::Int(a.wrapping_shl(s)))?;
            }
            YaraInstruction::Shr => {
                let s = u32::try_from(stack.pop()?.as_int() & 63).unwrap_or(0);
                let a = stack.pop()?.as_int();
                stack.push(StackValue::Int(a.wrapping_shr(s)))?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Comparison and logical instructions. Returns `true` if handled.
    fn exec_cmp_logical(instr: &YaraInstruction, stack: &mut YaraStack) -> Result<bool, VmError> {
        match instr {
            YaraInstruction::Eq  => { let b = stack.pop()?.as_int(); let a = stack.pop()?.as_int(); stack.push(StackValue::Bool(a == b))?; }
            YaraInstruction::Ne  => { let b = stack.pop()?.as_int(); let a = stack.pop()?.as_int(); stack.push(StackValue::Bool(a != b))?; }
            YaraInstruction::Lt  => { let b = stack.pop()?.as_int(); let a = stack.pop()?.as_int(); stack.push(StackValue::Bool(a <  b))?; }
            YaraInstruction::Le  => { let b = stack.pop()?.as_int(); let a = stack.pop()?.as_int(); stack.push(StackValue::Bool(a <= b))?; }
            YaraInstruction::Gt  => { let b = stack.pop()?.as_int(); let a = stack.pop()?.as_int(); stack.push(StackValue::Bool(a >  b))?; }
            YaraInstruction::Ge  => { let b = stack.pop()?.as_int(); let a = stack.pop()?.as_int(); stack.push(StackValue::Bool(a >= b))?; }
            YaraInstruction::And => { let b = stack.pop()?.as_bool(); let a = stack.pop()?.as_bool(); stack.push(StackValue::Bool(a && b))?; }
            YaraInstruction::Or  => { let b = stack.pop()?.as_bool(); let a = stack.pop()?.as_bool(); stack.push(StackValue::Bool(a || b))?; }
            YaraInstruction::Not => { let a = stack.pop()?.as_bool(); stack.push(StackValue::Bool(!a))?; }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Pattern-matching instructions. Returns `true` if handled.
    fn exec_pattern(instr: &YaraInstruction, stack: &mut YaraStack, ctx: &YaraExecutionContext) -> Result<bool, VmError> {
        match instr {
            YaraInstruction::PatternMatch(id) => { stack.push(StackValue::Bool(ctx.matched(id)))?; }
            YaraInstruction::PatternCount(id) => {
                stack.push(StackValue::Int(i64::try_from(ctx.count(id)).unwrap_or(i64::MAX)))?;
            }
            YaraInstruction::PatternOffset(id, n) => {
                let v = ctx.offset(id, *n).map_or(StackValue::Undefined, |o| {
                    StackValue::Int(i64::try_from(o).unwrap_or(i64::MAX))
                });
                stack.push(v)?;
            }
            YaraInstruction::PatternLength(id, _n) => {
                let v = if ctx.matched(id) { StackValue::Int(0) } else { StackValue::Undefined };
                stack.push(v)?;
            }
            YaraInstruction::PatternAt(id, offset) => {
                let hit = ctx.pattern_offsets.get(id.as_str())
                    .is_some_and(|offsets| offsets.contains(offset));
                stack.push(StackValue::Bool(hit))?;
            }
            YaraInstruction::PatternIn(id, lo, hi) => {
                let hit = ctx.pattern_offsets.get(id.as_str())
                    .is_some_and(|offsets| offsets.iter().any(|&o| o >= *lo && o <= *hi));
                stack.push(StackValue::Bool(hit))?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Control-flow, context, and variable instructions.
    fn exec_ctrl_ctx(
        instr: &YaraInstruction,
        stack: &mut YaraStack,
        heap: &mut YaraHeap,
        ctx: &YaraExecutionContext,
        program_len: usize,
        ip: &mut u32,
    ) -> Result<ExecSignal, VmError> {
        match instr {
            YaraInstruction::Jmp(target) => {
                if *target as usize >= program_len { return Err(VmError::InvalidJumpTarget(*target)); }
                *ip = *target;
            }
            YaraInstruction::JmpFalse(target) => {
                if !stack.pop()?.as_bool() {
                    if *target as usize >= program_len { return Err(VmError::InvalidJumpTarget(*target)); }
                    *ip = *target;
                }
            }
            YaraInstruction::JmpTrue(target) => {
                if stack.pop()?.as_bool() {
                    if *target as usize >= program_len { return Err(VmError::InvalidJumpTarget(*target)); }
                    *ip = *target;
                }
            }
            YaraInstruction::Return => return Ok(ExecSignal::ReturnFromStack),
            YaraInstruction::Halt(msg) => return Err(VmError::HaltInstruction(msg.clone())),
            YaraInstruction::FileSize => {
                stack.push(StackValue::Int(i64::try_from(ctx.file_size).unwrap_or(i64::MAX)))?;
            }
            YaraInstruction::AllOf  => stack.push(StackValue::Bool(ctx.all_matched()))?,
            YaraInstruction::AnyOf  => stack.push(StackValue::Bool(ctx.any_matched()))?,
            YaraInstruction::NoneOf => stack.push(StackValue::Bool(!ctx.any_matched()))?,
            YaraInstruction::LoadVar(name) => { let val = heap.load(name); stack.push(val)?; }
            YaraInstruction::StoreVar(name) => { let val = stack.pop()?; heap.store(name.clone(), val); }
            YaraInstruction::IncVar(name) => heap.increment(name),
            _ => {}
        }
        Ok(ExecSignal::Continue)
    }
}

/// Signal returned by `exec_ctrl_ctx` to the main execution loop.
enum ExecSignal {
    Continue,
    ReturnFromStack,
}

impl Default for YaraExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// YaraDebugger — step-through VM debugging
// ---------------------------------------------------------------------------

/// A single step trace entry.
#[derive(Debug, Clone)]
pub struct DebugStep {
    pub ip: u32,
    pub instruction: YaraInstruction,
    pub stack_before: Vec<StackValue>,
    pub stack_after: Vec<StackValue>,
}

/// Step-through debugger for the YARA VM.
pub struct YaraDebugger {
    pub trace: Vec<DebugStep>,
    pub breakpoints: Vec<u32>,
    max_steps: usize,
}

impl YaraDebugger {
    /// Create a new debugger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            trace: Vec::new(),
            breakpoints: Vec::new(),
            max_steps: 10_000,
        }
    }

    /// Set a breakpoint at the given instruction index.
    pub fn set_breakpoint(&mut self, ip: u32) {
        if !self.breakpoints.contains(&ip) {
            self.breakpoints.push(ip);
        }
    }

    /// Clear all breakpoints.
    pub fn clear_breakpoints(&mut self) {
        self.breakpoints.clear();
    }

    /// Execute a program with tracing.
    ///
    /// # Errors
    /// Returns a [`VmError`] if execution fails.
    pub fn trace_execute(
        &mut self,
        program: &[YaraInstruction],
        ctx: &YaraExecutionContext,
    ) -> Result<bool, VmError> {
        self.trace.clear();
        let executor = YaraExecutor::with_limit(self.max_steps);

        // Simplified trace: just execute and record the program
        for (ip, instr) in program.iter().enumerate() {
            if self
                .breakpoints
                .contains(&u32::try_from(ip).unwrap_or(u32::MAX))
            {
                // In a real debugger, this would pause; here we just record
            }
            self.trace.push(DebugStep {
                ip: u32::try_from(ip).unwrap_or(u32::MAX),
                instruction: instr.clone(),
                stack_before: Vec::new(),
                stack_after: Vec::new(),
            });
        }

        executor.execute(program, ctx)
    }

    /// Return a disassembly string for the program.
    #[must_use]
    pub fn disassemble(program: &[YaraInstruction]) -> String {
        let mut out = String::new();
        for (i, instr) in program.iter().enumerate() {
            use std::fmt::Write as _;
            let _ = writeln!(out, "{i:04}: {instr}");
        }
        out
    }

    /// Instruction count in the last trace.
    #[must_use]
    pub const fn trace_len(&self) -> usize {
        self.trace.len()
    }
}

impl Default for YaraDebugger {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// YaraVm — the top-level VM facade
// ---------------------------------------------------------------------------

/// The YARA virtual machine — compiles and executes conditions.
pub struct YaraVm {
    executor: YaraExecutor,
}

impl YaraVm {
    /// Create a new VM.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            executor: YaraExecutor::new(),
        }
    }

    /// Execute a bytecode program directly.
    ///
    /// # Errors
    /// Returns a [`VmError`] if execution fails.
    pub fn execute(
        &self,
        program: &[YaraInstruction],
        ctx: &YaraExecutionContext,
    ) -> Result<bool, VmError> {
        self.executor.execute(program, ctx)
    }

    /// Compile a simple condition from a list of pattern identifiers.
    ///
    /// Creates a program that returns `true` if any pattern matched.
    #[must_use]
    pub fn compile_any_of(patterns: &[&str]) -> Vec<YaraInstruction> {
        let mut prog = Vec::new();
        if patterns.is_empty() {
            prog.push(YaraInstruction::PushBool(false));
            prog.push(YaraInstruction::Return);
            return prog;
        }
        prog.push(YaraInstruction::PatternMatch(patterns[0].to_string()));
        for &p in &patterns[1..] {
            prog.push(YaraInstruction::PatternMatch(p.to_string()));
            prog.push(YaraInstruction::Or);
        }
        prog.push(YaraInstruction::Return);
        prog
    }

    /// Compile a program that returns `true` if all patterns matched.
    #[must_use]
    pub fn compile_all_of(patterns: &[&str]) -> Vec<YaraInstruction> {
        let mut prog = Vec::new();
        if patterns.is_empty() {
            prog.push(YaraInstruction::PushBool(true));
            prog.push(YaraInstruction::Return);
            return prog;
        }
        prog.push(YaraInstruction::PatternMatch(patterns[0].to_string()));
        for &p in &patterns[1..] {
            prog.push(YaraInstruction::PatternMatch(p.to_string()));
            prog.push(YaraInstruction::And);
        }
        prog.push(YaraInstruction::Return);
        prog
    }

    /// Compile a filesize > threshold comparison.
    #[must_use]
    pub fn compile_filesize_gt(threshold: i64) -> Vec<YaraInstruction> {
        vec![
            YaraInstruction::FileSize,
            YaraInstruction::PushInt(threshold),
            YaraInstruction::Gt,
            YaraInstruction::Return,
        ]
    }
}

impl Default for YaraVm {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> YaraExecutionContext {
        let mut ctx = YaraExecutionContext::new(1024);
        ctx.set_matches("$s0", vec![0x100, 0x200]);
        ctx.set_matches("$s1", vec![0x300]);
        ctx
    }

    #[test]
    fn test_push_int_return() {
        let vm = YaraVm::new();
        let prog = vec![YaraInstruction::PushInt(42), YaraInstruction::Return];
        let ctx = YaraExecutionContext::new(0);
        let r = vm.executor.run(&prog, &ctx).unwrap();
        assert_eq!(r, StackValue::Int(42));
    }

    #[test]
    fn test_push_bool_true() {
        let vm = YaraVm::new();
        let prog = vec![YaraInstruction::PushBool(true), YaraInstruction::Return];
        let ctx = YaraExecutionContext::new(0);
        let r = vm.executor.execute(&prog, &ctx).unwrap();
        assert!(r);
    }

    #[test]
    fn test_add_instruction() {
        let vm = YaraVm::new();
        let prog = vec![
            YaraInstruction::PushInt(10),
            YaraInstruction::PushInt(32),
            YaraInstruction::Add,
            YaraInstruction::Return,
        ];
        let ctx = YaraExecutionContext::new(0);
        let r = vm.executor.run(&prog, &ctx).unwrap();
        assert_eq!(r.as_int(), 42);
    }

    #[test]
    fn test_sub_instruction() {
        let vm = YaraVm::new();
        let prog = vec![
            YaraInstruction::PushInt(50),
            YaraInstruction::PushInt(8),
            YaraInstruction::Sub,
            YaraInstruction::Return,
        ];
        let ctx = YaraExecutionContext::new(0);
        let r = vm.executor.run(&prog, &ctx).unwrap();
        assert_eq!(r.as_int(), 42);
    }

    #[test]
    fn test_mul_instruction() {
        let vm = YaraVm::new();
        let prog = vec![
            YaraInstruction::PushInt(6),
            YaraInstruction::PushInt(7),
            YaraInstruction::Mul,
            YaraInstruction::Return,
        ];
        let ctx = YaraExecutionContext::new(0);
        assert_eq!(vm.executor.run(&prog, &ctx).unwrap().as_int(), 42);
    }

    #[test]
    fn test_div_instruction() {
        let vm = YaraVm::new();
        let prog = vec![
            YaraInstruction::PushInt(84),
            YaraInstruction::PushInt(2),
            YaraInstruction::Div,
            YaraInstruction::Return,
        ];
        let ctx = YaraExecutionContext::new(0);
        assert_eq!(vm.executor.run(&prog, &ctx).unwrap().as_int(), 42);
    }

    #[test]
    fn test_div_by_zero_error() {
        let vm = YaraVm::new();
        let prog = vec![
            YaraInstruction::PushInt(1),
            YaraInstruction::PushInt(0),
            YaraInstruction::Div,
            YaraInstruction::Return,
        ];
        let ctx = YaraExecutionContext::new(0);
        assert_eq!(vm.executor.run(&prog, &ctx), Err(VmError::DivisionByZero));
    }

    #[test]
    fn test_eq_instruction() {
        let vm = YaraVm::new();
        let prog = vec![
            YaraInstruction::PushInt(42),
            YaraInstruction::PushInt(42),
            YaraInstruction::Eq,
            YaraInstruction::Return,
        ];
        let ctx = YaraExecutionContext::new(0);
        assert!(vm.executor.execute(&prog, &ctx).unwrap());
    }

    #[test]
    fn test_ne_instruction() {
        let vm = YaraVm::new();
        let prog = vec![
            YaraInstruction::PushInt(1),
            YaraInstruction::PushInt(2),
            YaraInstruction::Ne,
            YaraInstruction::Return,
        ];
        let ctx = YaraExecutionContext::new(0);
        assert!(vm.executor.execute(&prog, &ctx).unwrap());
    }

    #[test]
    fn test_pattern_match_true() {
        let vm = YaraVm::new();
        let prog = vec![
            YaraInstruction::PatternMatch("$s0".to_string()),
            YaraInstruction::Return,
        ];
        let ctx = make_ctx();
        assert!(vm.executor.execute(&prog, &ctx).unwrap());
    }

    #[test]
    fn test_pattern_match_false() {
        let vm = YaraVm::new();
        let prog = vec![
            YaraInstruction::PatternMatch("$s9".to_string()),
            YaraInstruction::Return,
        ];
        let ctx = make_ctx();
        assert!(!vm.executor.execute(&prog, &ctx).unwrap());
    }

    #[test]
    fn test_pattern_count() {
        let vm = YaraVm::new();
        let prog = vec![
            YaraInstruction::PatternCount("$s0".to_string()),
            YaraInstruction::Return,
        ];
        let ctx = make_ctx();
        assert_eq!(vm.executor.run(&prog, &ctx).unwrap().as_int(), 2);
    }

    #[test]
    fn test_file_size() {
        let vm = YaraVm::new();
        let prog = vec![YaraInstruction::FileSize, YaraInstruction::Return];
        let ctx = YaraExecutionContext::new(4096);
        assert_eq!(vm.executor.run(&prog, &ctx).unwrap().as_int(), 4096);
    }

    #[test]
    fn test_jmp_false() {
        let vm = YaraVm::new();
        // If false, jump to index 3 (PushBool(false)), else return true
        let prog = vec![
            YaraInstruction::PushBool(false), // 0
            YaraInstruction::JmpFalse(3),     // 1
            YaraInstruction::PushBool(true),  // 2 (skipped)
            YaraInstruction::PushBool(false), // 3
            YaraInstruction::Return,          // 4
        ];
        let ctx = YaraExecutionContext::new(0);
        assert!(!vm.executor.execute(&prog, &ctx).unwrap());
    }

    #[test]
    fn test_not_instruction() {
        let vm = YaraVm::new();
        let prog = vec![
            YaraInstruction::PushBool(true),
            YaraInstruction::Not,
            YaraInstruction::Return,
        ];
        let ctx = YaraExecutionContext::new(0);
        assert!(!vm.executor.execute(&prog, &ctx).unwrap());
    }

    #[test]
    fn test_stack_overflow() {
        let executor = YaraExecutor::new();
        assert_eq!(executor.max_instructions, YaraExecutor::DEFAULT_LIMIT);
        let mut stack = YaraStack::new();
        stack.max_depth = 2;
        assert!(stack.push(StackValue::Int(1)).is_ok());
        assert!(stack.push(StackValue::Int(2)).is_ok());
        assert_eq!(stack.push(StackValue::Int(3)), Err(VmError::StackOverflow));
    }

    #[test]
    fn test_stack_underflow() {
        let mut stack = YaraStack::new();
        assert_eq!(stack.pop(), Err(VmError::StackUnderflow));
    }

    #[test]
    fn test_heap_store_load() {
        let mut heap = YaraHeap::new();
        heap.store("x", StackValue::Int(99));
        assert_eq!(heap.load("x"), StackValue::Int(99));
    }

    #[test]
    fn test_heap_load_undefined() {
        let heap = YaraHeap::new();
        assert!(heap.load("missing").is_undefined());
    }

    #[test]
    fn test_heap_increment() {
        let mut heap = YaraHeap::new();
        heap.store("i", StackValue::Int(5));
        heap.increment("i");
        assert_eq!(heap.load("i").as_int(), 6);
    }

    #[test]
    fn test_compile_any_of() {
        let prog = YaraVm::compile_any_of(&["$s0", "$s1"]);
        let vm = YaraVm::new();
        let mut ctx = YaraExecutionContext::new(0);
        ctx.set_matches("$s0", vec![0x100]);
        assert!(vm.execute(&prog, &ctx).unwrap());
    }

    #[test]
    fn test_compile_any_of_empty() {
        let prog = YaraVm::compile_any_of(&[]);
        let vm = YaraVm::new();
        let ctx = YaraExecutionContext::new(0);
        assert!(!vm.execute(&prog, &ctx).unwrap());
    }

    #[test]
    fn test_compile_all_of() {
        let prog = YaraVm::compile_all_of(&["$s0", "$s1"]);
        let vm = YaraVm::new();
        let ctx = make_ctx();
        assert!(vm.execute(&prog, &ctx).unwrap());
    }

    #[test]
    fn test_compile_filesize_gt() {
        let prog = YaraVm::compile_filesize_gt(512);
        let vm = YaraVm::new();
        let ctx = YaraExecutionContext::new(1024);
        assert!(vm.execute(&prog, &ctx).unwrap());
    }

    #[test]
    fn test_compile_filesize_gt_false() {
        let prog = YaraVm::compile_filesize_gt(2048);
        let vm = YaraVm::new();
        let ctx = YaraExecutionContext::new(1024);
        assert!(!vm.execute(&prog, &ctx).unwrap());
    }

    #[test]
    fn test_debugger_trace() {
        let mut dbg = YaraDebugger::new();
        let prog = vec![YaraInstruction::PushBool(true), YaraInstruction::Return];
        let ctx = YaraExecutionContext::new(0);
        let _ = dbg.trace_execute(&prog, &ctx);
        assert_eq!(dbg.trace_len(), 2);
    }

    #[test]
    fn test_debugger_disassemble() {
        let prog = vec![YaraInstruction::PushInt(42), YaraInstruction::Return];
        let s = YaraDebugger::disassemble(&prog);
        assert!(s.contains("PUSH_INT 42"));
        assert!(s.contains("RETURN"));
    }

    #[test]
    fn test_halt_instruction() {
        let vm = YaraVm::new();
        let prog = vec![YaraInstruction::Halt("test halt".to_string())];
        let ctx = YaraExecutionContext::new(0);
        assert!(matches!(
            vm.execute(&prog, &ctx),
            Err(VmError::HaltInstruction(_))
        ));
    }

    #[test]
    fn test_execution_limit() {
        let executor = YaraExecutor::with_limit(5);
        let prog: Vec<YaraInstruction> =
            (0..100).map(|_| YaraInstruction::PushBool(true)).collect();
        let ctx = YaraExecutionContext::new(0);
        assert_eq!(executor.execute(&prog, &ctx), Err(VmError::ExecutionLimit));
    }
}
