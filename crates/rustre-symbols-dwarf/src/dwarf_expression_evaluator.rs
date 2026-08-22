//! DWARF expression evaluator.
//!
//! Evaluates DWARF location expressions (`DW_FORM_exprloc` / `DW_FORM_block`)
//! against a machine register context.  Supports all commonly used `DW_OP_*`
//! opcodes including stack arithmetic, memory dereferences, register values,
//! and frame-relative locations.
//!
//! The primary entry point is [`DwarfExprEvaluator`] which evaluates a raw byte
//! slice representing a DWARF expression.
//!
//! # Parallel implementations
//!
//! This crate ships more than one location-expression implementation: see also `dwarf_location_expr` and `location_expr`.
//! None of them is wired into [`crate::DwarfReader`], which uses its own
//! inline copy, so each carries an independent bug set and a fix applied
//! here does not propagate. Pick one deliberately and stay on it.
//! This is the only one of the three with a `max_ops` loop guard.

use std::collections::HashMap;

// ── DW_OP opcode constants ────────────────────────────────────────────────────

const DW_OP_ADDR: u8 = 0x03;
const DW_OP_DEREF: u8 = 0x06;
const DW_OP_CONST1U: u8 = 0x08;
const DW_OP_CONST1S: u8 = 0x09;
const DW_OP_CONST2U: u8 = 0x0a;
const DW_OP_CONST2S: u8 = 0x0b;
const DW_OP_CONST4U: u8 = 0x0c;
const DW_OP_CONST4S: u8 = 0x0d;
const DW_OP_CONST8U: u8 = 0x0e;
const DW_OP_CONST8S: u8 = 0x0f;
const DW_OP_CONSTU: u8 = 0x10;
const DW_OP_CONSTS: u8 = 0x11;
const DW_OP_DUP: u8 = 0x12;
const DW_OP_DROP: u8 = 0x13;
const DW_OP_OVER: u8 = 0x14;
const DW_OP_PICK: u8 = 0x15;
const DW_OP_SWAP: u8 = 0x16;
const DW_OP_ROT: u8 = 0x17;
const DW_OP_ABS: u8 = 0x19;
const DW_OP_AND: u8 = 0x1a;
const DW_OP_DIV: u8 = 0x1b;
const DW_OP_MINUS: u8 = 0x1c;
const DW_OP_MOD: u8 = 0x1d;
const DW_OP_MUL: u8 = 0x1e;
const DW_OP_NEG: u8 = 0x1f;
const DW_OP_NOT: u8 = 0x20;
const DW_OP_OR: u8 = 0x21;
const DW_OP_PLUS: u8 = 0x22;
const DW_OP_PLUS_UCONST: u8 = 0x23;
const DW_OP_SHL: u8 = 0x24;
const DW_OP_SHR: u8 = 0x25;
const DW_OP_SHRA: u8 = 0x26;
const DW_OP_XOR: u8 = 0x27;
const DW_OP_BRA: u8 = 0x28;
const DW_OP_EQ: u8 = 0x29;
const DW_OP_GE: u8 = 0x2a;
const DW_OP_GT: u8 = 0x2b;
const DW_OP_LE: u8 = 0x2c;
const DW_OP_LT: u8 = 0x2d;
const DW_OP_NE: u8 = 0x2e;
const DW_OP_SKIP: u8 = 0x2f;
const DW_OP_LIT0: u8 = 0x30;
const DW_OP_LIT31: u8 = 0x4f;
const DW_OP_REG0: u8 = 0x50;
const DW_OP_REG31: u8 = 0x6f;
const DW_OP_BREG0: u8 = 0x70;
const DW_OP_BREG31: u8 = 0x8f;
const DW_OP_REGX: u8 = 0x90;
const DW_OP_FBREG: u8 = 0x91;
const DW_OP_BREGX: u8 = 0x92;
const DW_OP_PIECE: u8 = 0x93;
const DW_OP_DEREF_SIZE: u8 = 0x94;
const DW_OP_NOP: u8 = 0x96;
const DW_OP_STACK_VALUE: u8 = 0x9f;

// ── ExprStack ─────────────────────────────────────────────────────────────────

/// The evaluation stack for a DWARF expression.
#[derive(Debug, Clone, Default)]
pub struct ExprStack {
    values: Vec<i64>,
}

impl ExprStack {
    /// Create an empty stack.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a value.
    pub fn push(&mut self, v: i64) {
        self.values.push(v);
    }

    /// Pop a value, returning `None` if the stack is empty.
    pub fn pop(&mut self) -> Option<i64> {
        self.values.pop()
    }

    /// Peek at the top value without removing it.
    #[must_use]
    pub fn top(&self) -> Option<i64> {
        self.values.last().copied()
    }

    /// Stack depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.values.len()
    }

    /// Whether the stack is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Clear the stack.
    pub fn clear(&mut self) {
        self.values.clear();
    }

    /// Pick (copy) element `index` from the top (0 = top).
    #[must_use]
    pub fn pick(&self, index: usize) -> Option<i64> {
        let n = self.values.len();
        n.checked_sub(1 + index).and_then(|i| self.values.get(i).copied())
    }
}

// ── RegisterFile ─────────────────────────────────────────────────────────────

/// Provides register values to the evaluator.
///
/// The default implementation returns 0 for all registers.
pub trait RegisterFile: std::fmt::Debug {
    /// Read register `reg` as a 64-bit value.
    fn read(&self, reg: u32) -> i64;

    /// Read the frame base (used by `DW_OP_fbreg`).
    fn frame_base(&self) -> i64 {
        0
    }
}

/// A simple `HashMap`-backed register file, useful for tests.
#[derive(Debug, Default, Clone)]
pub struct SimpleRegisterFile {
    regs: HashMap<u32, i64>,
    frame_base: i64,
}

impl SimpleRegisterFile {
    /// Create an empty register file (all registers return 0).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a register value.
    pub fn set(&mut self, reg: u32, value: i64) {
        self.regs.insert(reg, value);
    }

    /// Set the frame base.
    pub const fn set_frame_base(&mut self, fb: i64) {
        self.frame_base = fb;
    }
}

impl RegisterFile for SimpleRegisterFile {
    fn read(&self, reg: u32) -> i64 {
        self.regs.get(&reg).copied().unwrap_or(0)
    }
    fn frame_base(&self) -> i64 {
        self.frame_base
    }
}

// ── OpResult ─────────────────────────────────────────────────────────────────

/// The result of evaluating a DWARF expression.
#[derive(Debug, Clone, PartialEq)]
pub enum OpResult {
    /// The expression evaluates to a memory address.
    Address(u64),
    /// The expression evaluates to a register value (the object is in the register).
    Register(u32),
    /// The expression evaluates to an implicit stack value.
    Value(i64),
    /// The expression is a piece composite (multi-location).
    Composite(Vec<PieceLocation>),
    /// Evaluation failed or the expression is empty.
    Unknown,
}

/// Describes one piece of a composite location.
#[derive(Debug, Clone, PartialEq)]
pub struct PieceLocation {
    /// The location of this piece.
    pub location: Box<OpResult>,
    /// Size of the piece in bytes (0 = remainder).
    pub size_bytes: u64,
}

// ── EvalError ─────────────────────────────────────────────────────────────────

/// Errors that can occur during expression evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    /// The byte stream ended unexpectedly in the middle of an opcode.
    UnexpectedEnd,
    /// The stack underflowed (not enough values for the opcode).
    StackUnderflow,
    /// Division by zero.
    DivisionByZero,
    /// Unsupported or unknown opcode.
    UnknownOpcode(u8),
    /// An index went out of bounds.
    OutOfBounds,
    /// The expression requires reading target memory (`DW_OP_deref` and
    /// friends), which this evaluator deliberately cannot do.
    ///
    /// This is reported as an error rather than silently leaving the *address*
    /// on the stack: doing the latter returns the address OF a value where the
    /// expression asked for the value itself, which is indistinguishable from
    /// success at the call site.
    RequiresMemory,
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEnd => write!(f, "unexpected end of expression"),
            Self::StackUnderflow => write!(f, "stack underflow"),
            Self::DivisionByZero => write!(f, "division by zero"),
            Self::UnknownOpcode(op) => write!(f, "unknown opcode 0x{op:02x}"),
            Self::OutOfBounds => write!(f, "index out of bounds"),
            Self::RequiresMemory => write!(f, "expression requires a memory read"),
        }
    }
}

// ── Byte helpers ──────────────────────────────────────────────────────────────

fn read_u8(data: &[u8], off: &mut usize) -> Result<u8, EvalError> {
    data.get(*off)
        .copied()
        .inspect(|_v| {
            *off += 1;
        })
        .ok_or(EvalError::UnexpectedEnd)
}

fn read_u16_le(data: &[u8], off: &mut usize) -> Result<u16, EvalError> {
    if *off + 2 > data.len() {
        return Err(EvalError::UnexpectedEnd);
    }
    let v = u16::from_le_bytes([data[*off], data[*off + 1]]);
    *off += 2;
    Ok(v)
}

fn read_u32_le(data: &[u8], off: &mut usize) -> Result<u32, EvalError> {
    if *off + 4 > data.len() {
        return Err(EvalError::UnexpectedEnd);
    }
    let v = u32::from_le_bytes(data[*off..*off + 4].try_into().unwrap());
    *off += 4;
    Ok(v)
}

fn read_u64_le(data: &[u8], off: &mut usize) -> Result<u64, EvalError> {
    if *off + 8 > data.len() {
        return Err(EvalError::UnexpectedEnd);
    }
    let v = u64::from_le_bytes(data[*off..*off + 8].try_into().unwrap());
    *off += 8;
    Ok(v)
}

fn read_uleb128(data: &[u8], off: &mut usize) -> Result<u64, EvalError> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let b = read_u8(data, off)?;
        if shift >= 64 {
            return Err(EvalError::UnexpectedEnd);
        }
        result |= u64::from(b & 0x7f) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(result);
        }
    }
}

fn read_sleb128(data: &[u8], off: &mut usize) -> Result<i64, EvalError> {
    let mut result = 0i64;
    let mut shift = 0u32;
    let b = loop {
        let byte = read_u8(data, off)?;
        result |= i64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break byte;
        }
        if shift >= 64 {
            return Err(EvalError::UnexpectedEnd);
        }
    };
    if shift < 64 && (b & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Ok(result)
}

// ── DwarfExprEvaluator ────────────────────────────────────────────────────────

/// Evaluates DWARF location expressions.
///
/// Create one evaluator per binary word size (typically 8 for 64-bit targets),
/// then call [`execute_opcode`] on it iteratively or use the higher-level
/// [`location_expression`] function.
#[derive(Debug, Clone)]
pub struct DwarfExprEvaluator {
    /// Address size in bytes (4 or 8).
    pub addr_size: u8,
    /// Maximum stack depth to prevent runaway expressions.
    pub max_stack: usize,
    /// Maximum number of opcodes to execute (loop guard).
    pub max_ops: usize,
}

impl Default for DwarfExprEvaluator {
    fn default() -> Self {
        Self {
            addr_size: 8,
            max_stack: 256,
            max_ops: 4096,
        }
    }
}

impl DwarfExprEvaluator {
    /// Create an evaluator for a 64-bit target.
    #[must_use]
    pub fn new_64bit() -> Self {
        Self {
            addr_size: 8,
            ..Self::default()
        }
    }

    /// Create an evaluator for a 32-bit target.
    #[must_use]
    pub fn new_32bit() -> Self {
        Self {
            addr_size: 4,
            ..Self::default()
        }
    }

    /// Evaluate a single opcode, mutating `stack` and advancing `off`.
    ///
    /// Returns `Ok(false)` when the opcode terminates evaluation early
    /// (`DW_OP_stack_value`, `DW_OP_reg*`).
    pub fn execute_opcode(
        &self,
        expr: &[u8],
        off: &mut usize,
        stack: &mut ExprStack,
        regs: &dyn RegisterFile,
        pieces: &mut Vec<PieceLocation>,
        is_register: &mut Option<u32>,
        is_stack_value: &mut bool,
    ) -> Result<bool, EvalError> {
        let op = read_u8(expr, off)?;

        match op {
            // ── Address push ─────────────────────────────────────────────────
            DW_OP_ADDR => {
                let addr = if self.addr_size == 8 {
                    read_u64_le(expr, off)?.cast_signed()
                } else {
                    i64::from(read_u32_le(expr, off)?)
                };
                stack.push(addr);
            }

            // ── Constant pushes ───────────────────────────────────────────────
            DW_OP_CONST1U => stack.push(i64::from(read_u8(expr, off)?)),
            DW_OP_CONST1S => stack.push(i64::from(read_u8(expr, off)?.cast_signed())),
            DW_OP_CONST2U => stack.push(i64::from(read_u16_le(expr, off)?)),
            DW_OP_CONST2S => stack.push(i64::from(read_u16_le(expr, off)?.cast_signed())),
            DW_OP_CONST4U => stack.push(i64::from(read_u32_le(expr, off)?)),
            DW_OP_CONST4S => stack.push(i64::from(read_u32_le(expr, off)?.cast_signed())),
            DW_OP_CONST8U => stack.push(read_u64_le(expr, off)?.cast_signed()),
            DW_OP_CONST8S => stack.push(read_u64_le(expr, off)?.cast_signed()),
            DW_OP_CONSTU => stack.push(read_uleb128(expr, off)?.cast_signed()),
            DW_OP_CONSTS => stack.push(read_sleb128(expr, off)?),

            // ── Lit0..Lit31 ───────────────────────────────────────────────────
            o if (DW_OP_LIT0..=DW_OP_LIT31).contains(&o) => {
                stack.push(i64::from(o - DW_OP_LIT0));
            }

            // ── Register values (no memory) ───────────────────────────────────
            o if (DW_OP_REG0..=DW_OP_REG31).contains(&o) => {
                let reg = u32::from(o - DW_OP_REG0);
                *is_register = Some(reg);
                stack.push(regs.read(reg));
                return Ok(false); // terminates expression
            }
            DW_OP_REGX => {
                let reg = read_uleb128(expr, off)? as u32;
                *is_register = Some(reg);
                stack.push(regs.read(reg));
                return Ok(false);
            }

            // ── Register-based address ────────────────────────────────────────
            o if (DW_OP_BREG0..=DW_OP_BREG31).contains(&o) => {
                let reg = u32::from(o - DW_OP_BREG0);
                let offset = read_sleb128(expr, off)?;
                stack.push(regs.read(reg).wrapping_add(offset));
            }
            DW_OP_BREGX => {
                let reg = read_uleb128(expr, off)? as u32;
                let offset = read_sleb128(expr, off)?;
                stack.push(regs.read(reg).wrapping_add(offset));
            }
            DW_OP_FBREG => {
                let offset = read_sleb128(expr, off)?;
                stack.push(regs.frame_base().wrapping_add(offset));
            }

            // ── Stack manipulation ────────────────────────────────────────────
            DW_OP_DUP => {
                let v = stack.top().ok_or(EvalError::StackUnderflow)?;
                stack.push(v);
            }
            DW_OP_DROP => {
                stack.pop().ok_or(EvalError::StackUnderflow)?;
            }
            DW_OP_OVER => {
                let v = stack.pick(1).ok_or(EvalError::StackUnderflow)?;
                stack.push(v);
            }
            DW_OP_PICK => {
                let idx = read_u8(expr, off)? as usize;
                let v = stack.pick(idx).ok_or(EvalError::OutOfBounds)?;
                stack.push(v);
            }
            DW_OP_SWAP => {
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let b = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(a);
                stack.push(b);
            }
            DW_OP_ROT => {
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let b = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let c = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(a);
                stack.push(c);
                stack.push(b);
            }

            // ── Arithmetic / logical ──────────────────────────────────────────
            DW_OP_ABS => {
                let v = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(v.saturating_abs());
            }
            DW_OP_NEG => {
                let v = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(v.wrapping_neg());
            }
            DW_OP_NOT => {
                let v = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(!v);
            }
            DW_OP_AND => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(a & b);
            }
            DW_OP_OR => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(a | b);
            }
            DW_OP_XOR => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(a ^ b);
            }
            DW_OP_PLUS => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(a.wrapping_add(b));
            }
            DW_OP_PLUS_UCONST => {
                let addend = read_uleb128(expr, off)?.cast_signed();
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(a.wrapping_add(addend));
            }
            DW_OP_MINUS => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(a.wrapping_sub(b));
            }
            DW_OP_MUL => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(a.wrapping_mul(b));
            }
            DW_OP_DIV => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                if b == 0 {
                    return Err(EvalError::DivisionByZero);
                }
                stack.push(a.wrapping_div(b));
            }
            DW_OP_MOD => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                if b == 0 {
                    return Err(EvalError::DivisionByZero);
                }
                stack.push(a.wrapping_rem(b));
            }
            DW_OP_SHL => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)? as u32;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(a.wrapping_shl(b & 63));
            }
            DW_OP_SHR => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)? as u32;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?.cast_unsigned();
                stack.push((a >> (b & 63)).cast_signed());
            }
            DW_OP_SHRA => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)? as u32;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(a.wrapping_shr(b & 63));
            }

            // ── Comparison ────────────────────────────────────────────────────
            DW_OP_EQ => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(i64::from(a == b));
            }
            DW_OP_GE => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(i64::from(a >= b));
            }
            DW_OP_GT => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(i64::from(a > b));
            }
            DW_OP_LE => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(i64::from(a <= b));
            }
            DW_OP_LT => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(i64::from(a < b));
            }
            DW_OP_NE => {
                let b = stack.pop().ok_or(EvalError::StackUnderflow)?;
                let a = stack.pop().ok_or(EvalError::StackUnderflow)?;
                stack.push(i64::from(a != b));
            }

            // ── Control flow ──────────────────────────────────────────────────
            DW_OP_SKIP => {
                let delta = read_u16_le(expr, off)?.cast_signed();
                let new_off = (*off).cast_signed()
                    .checked_add(isize::from(delta))
                    .and_then(|v| usize::try_from(v).ok())
                    .ok_or(EvalError::OutOfBounds)?;
                if new_off > expr.len() {
                    return Err(EvalError::OutOfBounds);
                }
                *off = new_off;
            }
            DW_OP_BRA => {
                let delta = read_u16_le(expr, off)?.cast_signed();
                let cond = stack.pop().ok_or(EvalError::StackUnderflow)?;
                if cond != 0 {
                    let new_off = (*off).cast_signed()
                        .checked_add(isize::from(delta))
                        .and_then(|v| usize::try_from(v).ok())
                        .ok_or(EvalError::OutOfBounds)?;
                    if new_off > expr.len() {
                        return Err(EvalError::OutOfBounds);
                    }
                    *off = new_off;
                }
            }

            // ── Memory dereference ────────────────────────────────────────────
            DW_OP_DEREF => {
                // Previously a silent no-op, which left the ADDRESS on the
                // stack where the expression asked for the value at it.
                return Err(EvalError::RequiresMemory);
            }
            DW_OP_DEREF_SIZE => {
                let _size = read_u8(expr, off)?;
                return Err(EvalError::RequiresMemory);
            }

            // ── Pieces ────────────────────────────────────────────────────────
            DW_OP_PIECE => {
                let size = read_uleb128(expr, off)?;
                // DW_OP_piece consumes the location it describes; leaving it on
                // the stack corrupted every subsequent piece.
                let loc = match stack.pop() {
                    Some(v) => OpResult::Address(v.cast_unsigned()),
                    None => OpResult::Unknown,
                };
                pieces.push(PieceLocation {
                    location: Box::new(loc),
                    size_bytes: size,
                });
            }

            // ── Stack value terminator ────────────────────────────────────────
            DW_OP_STACK_VALUE => {
                *is_stack_value = true;
                return Ok(false);
            }

            // ── NOP ───────────────────────────────────────────────────────────
            DW_OP_NOP => {}

            // ── Unknown ───────────────────────────────────────────────────────
            unknown => return Err(EvalError::UnknownOpcode(unknown)),
        }

        if stack.depth() > self.max_stack {
            stack.pop(); // trim to avoid unbounded growth
        }

        Ok(true) // continue
    }
}

// ── location_expression ───────────────────────────────────────────────────────

/// Evaluate a complete DWARF location expression and return an [`OpResult`].
///
/// This is the main public API.  It runs the expression through the
/// [`DwarfExprEvaluator`] state machine and classifies the result.
///
/// # Errors
/// Returns an [`EvalError`] if the expression is malformed.
pub fn location_expression(
    expr: &[u8],
    evaluator: &DwarfExprEvaluator,
    regs: &dyn RegisterFile,
) -> Result<OpResult, EvalError> {
    if expr.is_empty() {
        return Ok(OpResult::Unknown);
    }

    let mut stack = ExprStack::new();
    let mut pieces: Vec<PieceLocation> = Vec::new();
    let mut is_register: Option<u32> = None;
    let mut is_stack_value = false;
    let mut off = 0usize;
    let mut op_count = 0usize;

    while off < expr.len() {
        op_count += 1;
        if op_count > evaluator.max_ops {
            break;
        }
        let cont = evaluator.execute_opcode(
            expr,
            &mut off,
            &mut stack,
            regs,
            &mut pieces,
            &mut is_register,
            &mut is_stack_value,
        )?;
        if !cont {
            break;
        }
    }

    // Classify the result.
    if !pieces.is_empty() {
        return Ok(OpResult::Composite(pieces));
    }
    if let Some(reg) = is_register {
        return Ok(OpResult::Register(reg));
    }
    if is_stack_value {
        return Ok(stack.top().map_or(OpResult::Unknown, OpResult::Value));
    }
    if let Some(addr) = stack.top() {
        return Ok(OpResult::Address(addr.cast_unsigned()));
    }
    Ok(OpResult::Unknown)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn eval_with_regs(expr: &[u8], regs: &dyn RegisterFile) -> Result<OpResult, EvalError> {
        location_expression(expr, &DwarfExprEvaluator::new_64bit(), regs)
    }

    fn eval(expr: &[u8]) -> Result<OpResult, EvalError> {
        eval_with_regs(expr, &SimpleRegisterFile::new())
    }

    fn uleb(mut n: u64) -> Vec<u8> {
        let mut v = Vec::new();
        loop {
            let mut b = (n & 0x7f) as u8;
            n >>= 7;
            if n != 0 {
                b |= 0x80;
            }
            v.push(b);
            if n == 0 {
                break;
            }
        }
        v
    }

    fn sleb(mut n: i64) -> Vec<u8> {
        let mut v = Vec::new();
        loop {
            let mut b = (n & 0x7f) as u8;
            n >>= 7;
            let done = (n == 0 && b & 0x40 == 0) || (n == -1 && b & 0x40 != 0);
            if !done {
                b |= 0x80;
            }
            v.push(b);
            if done {
                break;
            }
        }
        v
    }

    #[test]
    fn empty_expression() {
        assert_eq!(eval(b"").unwrap(), OpResult::Unknown);
    }

    #[test]
    fn lit0() {
        assert_eq!(eval(&[DW_OP_LIT0]).unwrap(), OpResult::Address(0));
    }

    #[test]
    fn lit7() {
        assert_eq!(eval(&[DW_OP_LIT0 + 7]).unwrap(), OpResult::Address(7));
    }

    #[test]
    fn lit31() {
        assert_eq!(eval(&[DW_OP_LIT31]).unwrap(), OpResult::Address(31));
    }

    #[test]
    fn const1u() {
        assert_eq!(eval(&[DW_OP_CONST1U, 42]).unwrap(), OpResult::Address(42));
    }

    #[test]
    fn const1s_negative() {
        let r = eval(&[DW_OP_CONST1S, 0xfe]).unwrap();
        assert_eq!(r, OpResult::Address((-2i64).cast_unsigned()));
    }

    #[test]
    fn const4u() {
        let mut e = vec![DW_OP_CONST4U];
        e.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert_eq!(eval(&e).unwrap(), OpResult::Address(0xDEAD_BEEF));
    }

    #[test]
    fn constu_large() {
        let mut e = vec![DW_OP_CONSTU];
        e.extend(uleb(0x1_0000_0000));
        assert_eq!(eval(&e).unwrap(), OpResult::Address(0x1_0000_0000));
    }

    #[test]
    fn consts_negative() {
        let mut e = vec![DW_OP_CONSTS];
        e.extend(sleb(-16));
        assert_eq!(eval(&e).unwrap(), OpResult::Address((-16i64).cast_unsigned()));
    }

    #[test]
    fn reg0() {
        let mut regs = SimpleRegisterFile::new();
        regs.set(0, 0x7fff_0000);
        let r = eval_with_regs(&[DW_OP_REG0], &regs).unwrap();
        assert_eq!(r, OpResult::Register(0));
    }

    #[test]
    fn regx() {
        let mut regs = SimpleRegisterFile::new();
        regs.set(32, 123);
        let mut e = vec![DW_OP_REGX];
        e.extend(uleb(32));
        assert_eq!(eval_with_regs(&e, &regs).unwrap(), OpResult::Register(32));
    }

    #[test]
    fn breg0_offset() {
        let mut regs = SimpleRegisterFile::new();
        regs.set(0, 0x100);
        let mut e = vec![DW_OP_BREG0];
        e.extend(sleb(-8));
        assert_eq!(
            eval_with_regs(&e, &regs).unwrap(),
            OpResult::Address(0x100u64.wrapping_add((-8i64).cast_unsigned()))
        );
    }

    #[test]
    fn fbreg_offset() {
        let mut regs = SimpleRegisterFile::new();
        regs.set_frame_base(0x200);
        let mut e = vec![DW_OP_FBREG];
        e.extend(sleb(-16));
        assert_eq!(
            eval_with_regs(&e, &regs).unwrap(),
            OpResult::Address((0x200i64 - 16) as u64)
        );
    }

    #[test]
    fn plus_two_consts() {
        let expr = [DW_OP_LIT0 + 10, DW_OP_LIT0 + 5, DW_OP_PLUS];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address(15));
    }

    #[test]
    fn minus_op() {
        let expr = [DW_OP_LIT0 + 20, DW_OP_LIT0 + 8, DW_OP_MINUS];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address(12));
    }

    #[test]
    fn mul_op() {
        let expr = [DW_OP_LIT0 + 3, DW_OP_LIT0 + 4, DW_OP_MUL];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address(12));
    }

    #[test]
    fn and_op() {
        let expr = [DW_OP_LIT0 + 7, DW_OP_LIT0 + 5, DW_OP_AND];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address(5));
    }

    #[test]
    fn or_op() {
        let expr = [DW_OP_LIT0 + 5, DW_OP_LIT0 + 2, DW_OP_OR];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address(7));
    }

    #[test]
    fn xor_op() {
        let expr = [DW_OP_LIT0 + 7, DW_OP_LIT0 + 3, DW_OP_XOR];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address(4));
    }

    #[test]
    fn div_op() {
        let expr = [DW_OP_LIT0 + 10, DW_OP_LIT0 + 2, DW_OP_DIV];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address(5));
    }

    #[test]
    fn div_by_zero() {
        let expr = [DW_OP_LIT0 + 10, DW_OP_LIT0, DW_OP_DIV];
        assert_eq!(eval(&expr).unwrap_err(), EvalError::DivisionByZero);
    }

    #[test]
    fn dup_op() {
        let expr = [DW_OP_LIT0 + 5, DW_OP_DUP, DW_OP_PLUS];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address(10));
    }

    #[test]
    fn drop_op() {
        let expr = [DW_OP_LIT0 + 5, DW_OP_LIT0 + 9, DW_OP_DROP];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address(5));
    }

    #[test]
    fn over_op() {
        // stack: [3, 7] → over → [3, 7, 3]
        let expr = [DW_OP_LIT0 + 3, DW_OP_LIT0 + 7, DW_OP_OVER];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address(3));
    }

    #[test]
    fn stack_underflow() {
        assert_eq!(eval(&[DW_OP_PLUS]).unwrap_err(), EvalError::StackUnderflow);
    }

    #[test]
    fn stack_value_terminator() {
        // DW_OP_LIT only covers 0..=31; for 42 we need a DW_OP_const1u push.
        let expr = [DW_OP_CONST1U, 42, DW_OP_STACK_VALUE];
        assert_eq!(eval(&expr).unwrap(), OpResult::Value(42));
    }

    #[test]
    fn plus_uconst() {
        let mut e = vec![DW_OP_LIT0 + 10, DW_OP_PLUS_UCONST];
        e.extend(uleb(5));
        assert_eq!(eval(&e).unwrap(), OpResult::Address(15));
    }

    #[test]
    fn eq_comparison() {
        let expr = [DW_OP_LIT0 + 5, DW_OP_LIT0 + 5, DW_OP_EQ];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address(1));
    }

    #[test]
    fn ne_comparison() {
        let expr = [DW_OP_LIT0 + 5, DW_OP_LIT0 + 3, DW_OP_NE];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address(1));
    }

    #[test]
    fn nop_is_transparent() {
        let expr = [DW_OP_NOP, DW_OP_LIT0 + 7];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address(7));
    }

    #[test]
    fn swap_op() {
        // [3, 7] → swap → [7, 3]; top should be 7
        let expr = [DW_OP_LIT0 + 3, DW_OP_LIT0 + 7, DW_OP_SWAP];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address(3));
    }

    #[test]
    fn neg_op() {
        let expr = [DW_OP_LIT0 + 5, DW_OP_NEG];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address((-5i64).cast_unsigned()));
    }

    #[test]
    fn shl_op() {
        let expr = [DW_OP_LIT0 + 3, DW_OP_LIT0 + 2, DW_OP_SHL];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address(12));
    }

    #[test]
    fn shr_op() {
        let expr = [DW_OP_LIT0 + 16, DW_OP_LIT0 + 2, DW_OP_SHR];
        assert_eq!(eval(&expr).unwrap(), OpResult::Address(4));
    }
}
