//! `rustre-arch-jvm::jvm_lifter`
//!
//! JVM operand-stack → virtual-register lifter.
//!
//! The JVM is a stack machine.  This module converts JVM bytecode to a simple
//! register-based IR by simulating the operand stack at lift time.  Each stack
//! slot is assigned a fresh virtual register (`vN`), and instructions become
//! three-address code assignments.
//!
//! # Design
//!
//! * [`StackSlot`] — one slot on the abstract operand stack.
//! * [`LiftedValue`] — a value (constant, virtual register, or reference).
//! * [`LiftedInstr`] — a lifted three-address-code instruction.
//! * [`JvmLifter`] — the main lifter that walks a flat bytecode array.

use crate::JvmInstr;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// LiftError
// ─────────────────────────────────────────────────────────────────────────────

/// Error type for the lifter.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LiftError {
    #[error("stack underflow at pc={pc:#x}")]
    StackUnderflow { pc: usize },
    #[error("unsupported opcode {opcode:#04x} at pc={pc:#x}")]
    UnsupportedOpcode { opcode: u8, pc: usize },
    #[error("truncated bytecode at pc={pc:#x}")]
    Truncated { pc: usize },
}

// ─────────────────────────────────────────────────────────────────────────────
// StackSlot
// ─────────────────────────────────────────────────────────────────────────────

/// The JVM category of a stack slot or local variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotCategory {
    /// Category 1: int, float, reference, returnAddress — one slot wide.
    Cat1,
    /// Category 2: long, double — two slots wide.
    Cat2,
}

/// One logical slot on the abstract operand stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackSlot {
    /// Virtual register number assigned to this value.
    pub vreg: u32,
    /// Category of the value.
    pub category: SlotCategory,
    /// Descriptive type hint (e.g. `"int"`, `"long"`, `"ref"`).
    pub type_hint: String,
}

impl StackSlot {
    fn new(vreg: u32, category: SlotCategory, hint: &str) -> Self {
        Self {
            vreg,
            category,
            type_hint: hint.to_string(),
        }
    }

    fn cat1(vreg: u32) -> Self {
        Self::new(vreg, SlotCategory::Cat1, "int")
    }
    fn cat2(vreg: u32) -> Self {
        Self::new(vreg, SlotCategory::Cat2, "long")
    }
    fn float(vreg: u32) -> Self {
        Self::new(vreg, SlotCategory::Cat1, "float")
    }
    fn double(vreg: u32) -> Self {
        Self::new(vreg, SlotCategory::Cat2, "double")
    }
    fn reference(vreg: u32) -> Self {
        Self::new(vreg, SlotCategory::Cat1, "ref")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LiftedValue
// ─────────────────────────────────────────────────────────────────────────────

/// A value produced by a lifted instruction.
#[derive(Debug, Clone, PartialEq)]
pub enum LiftedValue {
    /// An integer constant.
    IntConst(i64),
    /// A floating-point constant.
    FloatConst(f64),
    /// Null reference.
    Null,
    /// A virtual register holding a value.
    VReg(u32),
    /// A constant pool reference (index).
    CpRef(u16),
}

impl std::fmt::Display for LiftedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntConst(n) => write!(f, "{n}"),
            Self::FloatConst(v) => write!(f, "{v}"),
            Self::Null => write!(f, "null"),
            Self::VReg(n) => write!(f, "v{n}"),
            Self::CpRef(idx) => write!(f, "cp#{idx}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LiftedOpKind
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of a lifted three-address instruction.
#[derive(Debug, Clone, PartialEq)]
pub enum LiftedOpKind {
    // Constants
    Const(LiftedValue),
    // Loads / stores
    LoadLocal(u16),
    StoreLocal(u16),
    // Arithmetic (binary)
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    // Arithmetic (unary)
    Neg,
    // Bitwise
    And,
    Or,
    Xor,
    // Shifts
    Shl,
    Shr,
    Ushr,
    // Comparisons
    Cmp,
    // Conversions
    Convert { from: String, to: String },
    // Control flow
    IfBranch { cond: String, target: i32 },
    Goto(i32),
    Jsr(i32),
    Return,
    ReturnValue,
    // Invocations
    InvokeVirtual(u16),
    InvokeSpecial(u16),
    InvokeStatic(u16),
    InvokeInterface { cpref: u16, count: u8 },
    InvokeDynamic(u16),
    // Object / array
    GetField(u16),
    PutField(u16),
    GetStatic(u16),
    PutStatic(u16),
    New(u16),
    NewArray(u8),
    ANewArray(u16),
    MultiANewArray { cpref: u16, dims: u8 },
    ArrayLength,
    // Exception
    AThrow,
    // Monitor
    MonitorEnter,
    MonitorExit,
    // Array loads/stores
    ArrayLoad,
    ArrayStore,
    // Stack ops (expressed as copy/dup moves)
    Copy,
    Pop,
    // Nop
    Nop,
}

impl std::fmt::Display for LiftedOpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Const(v) => write!(f, "const {v}"),
            Self::LoadLocal(n) => write!(f, "load_local {n}"),
            Self::StoreLocal(n) => write!(f, "store_local {n}"),
            Self::Add => write!(f, "add"),
            Self::Sub => write!(f, "sub"),
            Self::Mul => write!(f, "mul"),
            Self::Div => write!(f, "div"),
            Self::Rem => write!(f, "rem"),
            Self::Neg => write!(f, "neg"),
            Self::And => write!(f, "and"),
            Self::Or => write!(f, "or"),
            Self::Xor => write!(f, "xor"),
            Self::Shl => write!(f, "shl"),
            Self::Shr => write!(f, "shr"),
            Self::Ushr => write!(f, "ushr"),
            Self::Cmp => write!(f, "cmp"),
            Self::Convert { from, to } => write!(f, "convert {from}→{to}"),
            Self::IfBranch { cond, target } => write!(f, "if_{cond} -> {target}"),
            Self::Goto(t) => write!(f, "goto {t}"),
            Self::Jsr(t) => write!(f, "jsr {t}"),
            Self::Return => write!(f, "return"),
            Self::ReturnValue => write!(f, "return_value"),
            Self::InvokeVirtual(n) => write!(f, "invokevirtual #{n}"),
            Self::InvokeSpecial(n) => write!(f, "invokespecial #{n}"),
            Self::InvokeStatic(n) => write!(f, "invokestatic #{n}"),
            Self::InvokeInterface { cpref, count } => {
                write!(f, "invokeinterface #{cpref} count={count}")
            }
            Self::InvokeDynamic(n) => write!(f, "invokedynamic #{n}"),
            Self::GetField(n) => write!(f, "getfield #{n}"),
            Self::PutField(n) => write!(f, "putfield #{n}"),
            Self::GetStatic(n) => write!(f, "getstatic #{n}"),
            Self::PutStatic(n) => write!(f, "putstatic #{n}"),
            Self::New(n) => write!(f, "new #{n}"),
            Self::NewArray(t) => write!(f, "newarray type={t}"),
            Self::ANewArray(n) => write!(f, "anewarray #{n}"),
            Self::MultiANewArray { cpref, dims } => {
                write!(f, "multianewarray #{cpref} dims={dims}")
            }
            Self::ArrayLength => write!(f, "arraylength"),
            Self::AThrow => write!(f, "athrow"),
            Self::MonitorEnter => write!(f, "monitorenter"),
            Self::MonitorExit => write!(f, "monitorexit"),
            Self::ArrayLoad => write!(f, "array_load"),
            Self::ArrayStore => write!(f, "array_store"),
            Self::Copy => write!(f, "copy"),
            Self::Pop => write!(f, "pop"),
            Self::Nop => write!(f, "nop"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LiftedInstr
// ─────────────────────────────────────────────────────────────────────────────

/// A single lifted three-address instruction.
#[derive(Debug, Clone, PartialEq)]
pub struct LiftedInstr {
    /// Bytecode program counter of the source JVM instruction.
    pub pc: usize,
    /// Operation kind.
    pub op: LiftedOpKind,
    /// Destination virtual register, if any.
    pub dest: Option<u32>,
    /// Source virtual registers / operands.
    pub srcs: Vec<LiftedValue>,
}

impl LiftedInstr {
    const fn new(pc: usize, op: LiftedOpKind) -> Self {
        Self {
            pc,
            op,
            dest: None,
            srcs: vec![],
        }
    }

    const fn with_dest(mut self, d: u32) -> Self {
        self.dest = Some(d);
        self
    }
    fn with_src(mut self, s: LiftedValue) -> Self {
        self.srcs.push(s);
        self
    }
}

impl std::fmt::Display for LiftedInstr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:#06x}] ", self.pc)?;
        if let Some(d) = self.dest {
            write!(f, "v{d} = ")?;
        }
        write!(f, "{}", self.op)?;
        if !self.srcs.is_empty() {
            write!(f, " (")?;
            for (i, s) in self.srcs.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{s}")?;
            }
            write!(f, ")")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JvmLifter
// ─────────────────────────────────────────────────────────────────────────────

/// JVM stack → register lifter.
///
/// Simulate the operand stack and local variable array to produce
/// [`LiftedInstr`] from raw JVM bytecode.
pub struct JvmLifter {
    /// Current operand stack.
    stack: Vec<StackSlot>,
    /// Local variable slots — map from local index to current virtual register.
    locals: HashMap<u16, u32>,
    /// Counter for fresh virtual register allocation.
    next_vreg: u32,
    /// Lifted output instructions.
    pub output: Vec<LiftedInstr>,
}

impl JvmLifter {
    /// Create a new lifter with an empty stack and no locals.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            locals: HashMap::new(),
            next_vreg: 0,
            output: Vec::new(),
        }
    }

    /// Reset the lifter state (stack, locals, output).
    pub fn reset(&mut self) {
        self.stack.clear();
        self.locals.clear();
        self.next_vreg = 0;
        self.output.clear();
    }

    /// Lift all instructions from `bytecode`.
    ///
    /// # Errors
    ///
    /// Returns [`LiftError`] on stack underflow, unsupported opcode, or
    /// truncated bytecode.
    pub fn lift_method(&mut self, bytecode: &[u8]) -> Result<(), LiftError> {
        let mut pc = 0usize;
        while pc < bytecode.len() {
            let (instr, sz) =
                JvmInstr::decode_at(&bytecode[pc..], pc).map_err(|_| LiftError::Truncated { pc })?;
            self.lift_instr(&instr, pc, &bytecode[pc..])?;
            pc += sz;
        }
        Ok(())
    }

    /// Lift a single decoded instruction at `pc`.
    ///
    /// # Errors
    ///
    /// Returns [`LiftError::StackUnderflow`] when a pop is attempted on an
    /// empty stack, or [`LiftError::UnsupportedOpcode`] for unrecognised opcodes.
    pub fn lift_instr(
        &mut self,
        instr: &JvmInstr,
        pc: usize,
        _raw: &[u8],
    ) -> Result<(), LiftError> {
        let op = instr.raw[0];
        match op {
            // ── NOP ──────────────────────────────────────────────────────────
            0x00 => {
                self.emit(pc, LiftedOpKind::Nop);
            }

            // ── Constants ────────────────────────────────────────────────────
            0x01 => {
                let v = self.alloc_ref();
                self.push_ref(v, pc);
            }
            0x02 => {
                let v = self.const_int(-1, pc);
                self.push_int(v);
            }
            0x03 => {
                let v = self.const_int(0, pc);
                self.push_int(v);
            }
            0x04 => {
                let v = self.const_int(1, pc);
                self.push_int(v);
            }
            0x05 => {
                let v = self.const_int(2, pc);
                self.push_int(v);
            }
            0x06 => {
                let v = self.const_int(3, pc);
                self.push_int(v);
            }
            0x07 => {
                let v = self.const_int(4, pc);
                self.push_int(v);
            }
            0x08 => {
                let v = self.const_int(5, pc);
                self.push_int(v);
            }
            0x09 => {
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::Const(LiftedValue::IntConst(0)), v);
                self.stack.push(StackSlot::cat2(v));
            }
            0x0a => {
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::Const(LiftedValue::IntConst(1)), v);
                self.stack.push(StackSlot::cat2(v));
            }
            0x0b => {
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::Const(LiftedValue::FloatConst(0.0)), v);
                self.stack.push(StackSlot::float(v));
            }
            0x0c => {
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::Const(LiftedValue::FloatConst(1.0)), v);
                self.stack.push(StackSlot::float(v));
            }
            0x0d => {
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::Const(LiftedValue::FloatConst(2.0)), v);
                self.stack.push(StackSlot::float(v));
            }
            0x0e => {
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::Const(LiftedValue::FloatConst(0.0)), v);
                self.stack.push(StackSlot::double(v));
            }
            0x0f => {
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::Const(LiftedValue::FloatConst(1.0)), v);
                self.stack.push(StackSlot::double(v));
            }

            // bipush
            0x10 => {
                let imm = i64::from(i8::from_ne_bytes([instr.raw[1]]));
                let v = self.const_int(imm, pc);
                self.push_int(v);
            }
            // sipush
            0x11 => {
                let imm = i64::from(i16::from_be_bytes([instr.raw[1], instr.raw[2]]));
                let v = self.const_int(imm, pc);
                self.push_int(v);
            }
            // ldc, ldc_w, ldc2_w
            0x12..=0x14 => {
                let idx = if op == 0x12 {
                    u16::from(instr.raw[1])
                } else {
                    u16::from_be_bytes([instr.raw[1], instr.raw[2]])
                };
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::Const(LiftedValue::CpRef(idx)), v);
                let slot = if op == 0x14 {
                    StackSlot::cat2(v)
                } else {
                    StackSlot::cat1(v)
                };
                self.stack.push(slot);
            }

            // ── iload variants ───────────────────────────────────────────────
            0x15 => {
                let idx = u16::from(instr.raw[1]);
                self.lift_iload(idx, pc);
            }
            0x1a => {
                self.lift_iload(0, pc);
            }
            0x1b => {
                self.lift_iload(1, pc);
            }
            0x1c => {
                self.lift_iload(2, pc);
            }
            0x1d => {
                self.lift_iload(3, pc);
            }

            // ── lload variants ───────────────────────────────────────────────
            0x16 => {
                let idx = u16::from(instr.raw[1]);
                self.lift_lload(idx, pc);
            }
            0x1e => {
                self.lift_lload(0, pc);
            }
            0x1f => {
                self.lift_lload(1, pc);
            }
            0x20 => {
                self.lift_lload(2, pc);
            }
            0x21 => {
                self.lift_lload(3, pc);
            }

            // ── fload variants ───────────────────────────────────────────────
            0x17 => {
                let idx = u16::from(instr.raw[1]);
                self.lift_fload(idx, pc);
            }
            0x22 => {
                self.lift_fload(0, pc);
            }
            0x23 => {
                self.lift_fload(1, pc);
            }
            0x24 => {
                self.lift_fload(2, pc);
            }
            0x25 => {
                self.lift_fload(3, pc);
            }

            // ── dload variants ───────────────────────────────────────────────
            0x18 => {
                let idx = u16::from(instr.raw[1]);
                self.lift_dload(idx, pc);
            }
            0x26 => {
                self.lift_dload(0, pc);
            }
            0x27 => {
                self.lift_dload(1, pc);
            }
            0x28 => {
                self.lift_dload(2, pc);
            }
            0x29 => {
                self.lift_dload(3, pc);
            }

            // ── aload variants ───────────────────────────────────────────────
            0x19 => {
                let idx = u16::from(instr.raw[1]);
                self.lift_aload(idx, pc);
            }
            0x2a => {
                self.lift_aload(0, pc);
            }
            0x2b => {
                self.lift_aload(1, pc);
            }
            0x2c => {
                self.lift_aload(2, pc);
            }
            0x2d => {
                self.lift_aload(3, pc);
            }

            // ── Array loads ──────────────────────────────────────────────────
            0x2e..=0x35 => {
                let _idx = self.pop(pc)?;
                let _arr = self.pop(pc)?;
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::ArrayLoad, v);
                let slot = if op == 0x2f || op == 0x31 {
                    StackSlot::cat2(v)
                } else {
                    StackSlot::cat1(v)
                };
                self.stack.push(slot);
            }

            // ── istore variants ──────────────────────────────────────────────
            0x36 => {
                let idx = u16::from(instr.raw[1]);
                self.lift_istore(idx, pc)?;
            }
            0x3b => {
                self.lift_istore(0, pc)?;
            }
            0x3c => {
                self.lift_istore(1, pc)?;
            }
            0x3d => {
                self.lift_istore(2, pc)?;
            }
            0x3e => {
                self.lift_istore(3, pc)?;
            }

            // ── lstore variants ──────────────────────────────────────────────
            0x37 => {
                let idx = u16::from(instr.raw[1]);
                self.lift_lstore(idx, pc)?;
            }
            0x3f => {
                self.lift_lstore(0, pc)?;
            }
            0x40 => {
                self.lift_lstore(1, pc)?;
            }
            0x41 => {
                self.lift_lstore(2, pc)?;
            }
            0x42 => {
                self.lift_lstore(3, pc)?;
            }

            // ── fstore variants ──────────────────────────────────────────────
            0x38 => {
                let idx = u16::from(instr.raw[1]);
                self.lift_fstore(idx, pc)?;
            }
            0x43 => {
                self.lift_fstore(0, pc)?;
            }
            0x44 => {
                self.lift_fstore(1, pc)?;
            }
            0x45 => {
                self.lift_fstore(2, pc)?;
            }
            0x46 => {
                self.lift_fstore(3, pc)?;
            }

            // ── dstore variants ──────────────────────────────────────────────
            0x39 => {
                let idx = u16::from(instr.raw[1]);
                self.lift_dstore(idx, pc)?;
            }
            0x47 => {
                self.lift_dstore(0, pc)?;
            }
            0x48 => {
                self.lift_dstore(1, pc)?;
            }
            0x49 => {
                self.lift_dstore(2, pc)?;
            }
            0x4a => {
                self.lift_dstore(3, pc)?;
            }

            // ── astore variants ──────────────────────────────────────────────
            0x3a => {
                let idx = u16::from(instr.raw[1]);
                self.lift_astore(idx, pc)?;
            }
            0x4b => {
                self.lift_astore(0, pc)?;
            }
            0x4c => {
                self.lift_astore(1, pc)?;
            }
            0x4d => {
                self.lift_astore(2, pc)?;
            }
            0x4e => {
                self.lift_astore(3, pc)?;
            }

            // ── Array stores ─────────────────────────────────────────────────
            0x4f..=0x56 => {
                let _val = self.pop(pc)?;
                let _idx = self.pop(pc)?;
                let _arr = self.pop(pc)?;
                self.emit(pc, LiftedOpKind::ArrayStore);
            }

            // ── Stack manipulation ────────────────────────────────────────────
            0x57 => {
                self.pop(pc)?;
                self.emit(pc, LiftedOpKind::Pop);
            }
            0x58 => {
                let top = self.pop(pc)?;
                if top.category == SlotCategory::Cat1 {
                    self.pop(pc)?;
                }
                self.emit(pc, LiftedOpKind::Pop);
            }
            0x59 => {
                // dup
                let top = self.peek(pc)?.clone();
                let v = self.alloc_vreg();
                self.emit_dest_src(pc, LiftedOpKind::Copy, v, LiftedValue::VReg(top.vreg));
                self.stack
                    .push(StackSlot::new(v, top.category, &top.type_hint));
            }
            // dup_x1, dup_x2, dup2, dup2_x1, dup2_x2, swap — approximate as copy
            0x5a..=0x5f => {
                let top = self.peek(pc)?.clone();
                let v = self.alloc_vreg();
                self.emit_dest_src(pc, LiftedOpKind::Copy, v, LiftedValue::VReg(top.vreg));
                self.stack.push(StackSlot::cat1(v));
            }

            // ── Arithmetic ────────────────────────────────────────────────────
            // iadd, ladd, fadd, dadd
            0x60..=0x63 => {
                self.lift_binop(LiftedOpKind::Add, op, pc)?;
            }
            // isub, lsub, fsub, dsub
            0x64..=0x67 => {
                self.lift_binop(LiftedOpKind::Sub, op, pc)?;
            }
            // imul, lmul, fmul, dmul
            0x68..=0x6b => {
                self.lift_binop(LiftedOpKind::Mul, op, pc)?;
            }
            // idiv, ldiv, fdiv, ddiv
            0x6c..=0x6f => {
                self.lift_binop(LiftedOpKind::Div, op, pc)?;
            }
            // irem, lrem, frem, drem
            0x70..=0x73 => {
                self.lift_binop(LiftedOpKind::Rem, op, pc)?;
            }
            // ineg, lneg, fneg, dneg
            0x74..=0x77 => {
                self.lift_unop(LiftedOpKind::Neg, op, pc)?;
            }
            // ishl, lshl, ishr, lshr, iushr, lushr
            0x78 | 0x79 => {
                self.lift_binop(LiftedOpKind::Shl, op, pc)?;
            }
            0x7a | 0x7b => {
                self.lift_binop(LiftedOpKind::Shr, op, pc)?;
            }
            0x7c | 0x7d => {
                self.lift_binop(LiftedOpKind::Ushr, op, pc)?;
            }
            // iand, land
            0x7e | 0x7f => {
                self.lift_binop(LiftedOpKind::And, op, pc)?;
            }
            // ior, lor
            0x80 | 0x81 => {
                self.lift_binop(LiftedOpKind::Or, op, pc)?;
            }
            // ixor, lxor
            0x82 | 0x83 => {
                self.lift_binop(LiftedOpKind::Xor, op, pc)?;
            }
            // iinc: increment local by constant — does not touch the stack
            0x84 => {
                let idx = u16::from(instr.raw[1]);
                let imm = i64::from(i8::from_ne_bytes([instr.raw[2]]));
                let src_vreg = self.local_vreg(idx);
                let v = self.alloc_vreg();
                let li = LiftedInstr {
                    pc,
                    op: LiftedOpKind::Add,
                    dest: Some(v),
                    srcs: vec![LiftedValue::VReg(src_vreg), LiftedValue::IntConst(imm)],
                };
                self.output.push(li);
                self.locals.insert(idx, v);
            }

            // ── Conversions ───────────────────────────────────────────────────
            0x85 => {
                self.lift_convert("int", "long", op, pc)?;
            }
            0x86 => {
                self.lift_convert("int", "float", op, pc)?;
            }
            0x87 => {
                self.lift_convert("int", "double", op, pc)?;
            }
            0x88 => {
                self.lift_convert("long", "int", op, pc)?;
            }
            0x89 => {
                self.lift_convert("long", "float", op, pc)?;
            }
            0x8a => {
                self.lift_convert("long", "double", op, pc)?;
            }
            0x8b => {
                self.lift_convert("float", "int", op, pc)?;
            }
            0x8c => {
                self.lift_convert("float", "long", op, pc)?;
            }
            0x8d => {
                self.lift_convert("float", "double", op, pc)?;
            }
            0x8e => {
                self.lift_convert("double", "int", op, pc)?;
            }
            0x8f => {
                self.lift_convert("double", "long", op, pc)?;
            }
            0x90 => {
                self.lift_convert("double", "float", op, pc)?;
            }
            0x91 => {
                self.lift_convert("int", "byte", op, pc)?;
            }
            0x92 => {
                self.lift_convert("int", "char", op, pc)?;
            }
            0x93 => {
                self.lift_convert("int", "short", op, pc)?;
            }

            // ── Comparisons ───────────────────────────────────────────────────
            0x94..=0x98 => {
                let rhs = self.pop(pc)?;
                let lhs = self.pop(pc)?;
                let v = self.alloc_vreg();
                let li = LiftedInstr {
                    pc,
                    op: LiftedOpKind::Cmp,
                    dest: Some(v),
                    srcs: vec![LiftedValue::VReg(lhs.vreg), LiftedValue::VReg(rhs.vreg)],
                };
                self.output.push(li);
                self.stack.push(StackSlot::cat1(v));
            }

            // ── Conditionals ──────────────────────────────────────────────────
            0x99..=0x9e => {
                let cond = match op {
                    0x99 => "eq",
                    0x9a => "ne",
                    0x9b => "lt",
                    0x9c => "ge",
                    0x9d => "gt",
                    _ => "le",
                };
                let target = i32::from(i16::from_be_bytes([instr.raw[1], instr.raw[2]]));
                let val = self.pop(pc)?;
                let li = LiftedInstr {
                    pc,
                    op: LiftedOpKind::IfBranch {
                        cond: cond.into(),
                        target,
                    },
                    dest: None,
                    srcs: vec![LiftedValue::VReg(val.vreg), LiftedValue::IntConst(0)],
                };
                self.output.push(li);
            }
            0x9f..=0xa4 => {
                let cond = match op {
                    0x9f => "icmpeq",
                    0xa0 => "icmpne",
                    0xa1 => "icmplt",
                    0xa2 => "icmpge",
                    0xa3 => "icmpgt",
                    _ => "icmple",
                };
                let target = i32::from(i16::from_be_bytes([instr.raw[1], instr.raw[2]]));
                let rhs = self.pop(pc)?;
                let lhs = self.pop(pc)?;
                let li = LiftedInstr {
                    pc,
                    op: LiftedOpKind::IfBranch {
                        cond: cond.into(),
                        target,
                    },
                    dest: None,
                    srcs: vec![LiftedValue::VReg(lhs.vreg), LiftedValue::VReg(rhs.vreg)],
                };
                self.output.push(li);
            }
            0xa5 | 0xa6 => {
                let cond = if op == 0xa5 { "acmpeq" } else { "acmpne" };
                let target = i32::from(i16::from_be_bytes([instr.raw[1], instr.raw[2]]));
                let rhs = self.pop(pc)?;
                let lhs = self.pop(pc)?;
                let li = LiftedInstr {
                    pc,
                    op: LiftedOpKind::IfBranch {
                        cond: cond.into(),
                        target,
                    },
                    dest: None,
                    srcs: vec![LiftedValue::VReg(lhs.vreg), LiftedValue::VReg(rhs.vreg)],
                };
                self.output.push(li);
            }

            // ── Goto / Jsr / Ret ─────────────────────────────────────────────
            0xa7 => {
                let target = i32::from(i16::from_be_bytes([instr.raw[1], instr.raw[2]]));
                self.emit(pc, LiftedOpKind::Goto(target));
            }
            0xa8 => {
                let target = i32::from(i16::from_be_bytes([instr.raw[1], instr.raw[2]]));
                let v = self.alloc_vreg(); // push return address
                self.emit_dest(pc, LiftedOpKind::Jsr(target), v);
                self.stack.push(StackSlot::cat1(v));
            }
            0xa9 => {
                self.pop(pc)?;
                self.emit(pc, LiftedOpKind::Return);
            }
            0xc8 => {
                let target =
                    i32::from_be_bytes([instr.raw[1], instr.raw[2], instr.raw[3], instr.raw[4]]);
                self.emit(pc, LiftedOpKind::Goto(target));
            }
            0xc9 => {
                let target =
                    i32::from_be_bytes([instr.raw[1], instr.raw[2], instr.raw[3], instr.raw[4]]);
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::Jsr(target), v);
                self.stack.push(StackSlot::cat1(v));
            }

            // ── Returns ───────────────────────────────────────────────────────
            0xac..=0xb0 => {
                let val = self.pop(pc)?;
                let li = LiftedInstr {
                    pc,
                    op: LiftedOpKind::ReturnValue,
                    dest: None,
                    srcs: vec![LiftedValue::VReg(val.vreg)],
                };
                self.output.push(li);
            }
            0xb1 => {
                self.emit(pc, LiftedOpKind::Return);
            }

            // ── References ────────────────────────────────────────────────────
            0xb2 => {
                let cpref = u16::from_be_bytes([instr.raw[1], instr.raw[2]]);
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::GetStatic(cpref), v);
                self.stack.push(StackSlot::cat1(v));
            }
            0xb3 => {
                let cpref = u16::from_be_bytes([instr.raw[1], instr.raw[2]]);
                let val = self.pop(pc)?;
                let li = LiftedInstr {
                    pc,
                    op: LiftedOpKind::PutStatic(cpref),
                    dest: None,
                    srcs: vec![LiftedValue::VReg(val.vreg)],
                };
                self.output.push(li);
            }
            0xb4 => {
                let cpref = u16::from_be_bytes([instr.raw[1], instr.raw[2]]);
                let obj = self.pop(pc)?;
                let v = self.alloc_vreg();
                let li = LiftedInstr {
                    pc,
                    op: LiftedOpKind::GetField(cpref),
                    dest: Some(v),
                    srcs: vec![LiftedValue::VReg(obj.vreg)],
                };
                self.output.push(li);
                self.stack.push(StackSlot::cat1(v));
            }
            0xb5 => {
                let cpref = u16::from_be_bytes([instr.raw[1], instr.raw[2]]);
                let val = self.pop(pc)?;
                let obj = self.pop(pc)?;
                let li = LiftedInstr {
                    pc,
                    op: LiftedOpKind::PutField(cpref),
                    dest: None,
                    srcs: vec![LiftedValue::VReg(obj.vreg), LiftedValue::VReg(val.vreg)],
                };
                self.output.push(li);
            }

            // ── Invocations ───────────────────────────────────────────────────
            0xb6 => {
                let cpref = u16::from_be_bytes([instr.raw[1], instr.raw[2]]);
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::InvokeVirtual(cpref), v);
                self.stack.push(StackSlot::cat1(v));
            }
            0xb7 => {
                let cpref = u16::from_be_bytes([instr.raw[1], instr.raw[2]]);
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::InvokeSpecial(cpref), v);
                self.stack.push(StackSlot::cat1(v));
            }
            0xb8 => {
                let cpref = u16::from_be_bytes([instr.raw[1], instr.raw[2]]);
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::InvokeStatic(cpref), v);
                self.stack.push(StackSlot::cat1(v));
            }
            0xb9 => {
                let cpref = u16::from_be_bytes([instr.raw[1], instr.raw[2]]);
                let count = instr.raw[3];
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::InvokeInterface { cpref, count }, v);
                self.stack.push(StackSlot::cat1(v));
            }
            0xba => {
                let cpref = u16::from_be_bytes([instr.raw[1], instr.raw[2]]);
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::InvokeDynamic(cpref), v);
                self.stack.push(StackSlot::cat1(v));
            }

            // ── Object creation / arrays ──────────────────────────────────────
            0xbb => {
                let cpref = u16::from_be_bytes([instr.raw[1], instr.raw[2]]);
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::New(cpref), v);
                self.stack.push(StackSlot::reference(v));
            }
            0xbc => {
                let atype = instr.raw[1];
                let count = self.pop(pc)?;
                let v = self.alloc_vreg();
                let li = LiftedInstr {
                    pc,
                    op: LiftedOpKind::NewArray(atype),
                    dest: Some(v),
                    srcs: vec![LiftedValue::VReg(count.vreg)],
                };
                self.output.push(li);
                self.stack.push(StackSlot::reference(v));
            }
            0xbd => {
                let cpref = u16::from_be_bytes([instr.raw[1], instr.raw[2]]);
                let count = self.pop(pc)?;
                let v = self.alloc_vreg();
                let li = LiftedInstr {
                    pc,
                    op: LiftedOpKind::ANewArray(cpref),
                    dest: Some(v),
                    srcs: vec![LiftedValue::VReg(count.vreg)],
                };
                self.output.push(li);
                self.stack.push(StackSlot::reference(v));
            }
            0xbe => {
                let arr = self.pop(pc)?;
                let v = self.alloc_vreg();
                let li = LiftedInstr {
                    pc,
                    op: LiftedOpKind::ArrayLength,
                    dest: Some(v),
                    srcs: vec![LiftedValue::VReg(arr.vreg)],
                };
                self.output.push(li);
                self.stack.push(StackSlot::cat1(v));
            }
            0xc5 => {
                let cpref = u16::from_be_bytes([instr.raw[1], instr.raw[2]]);
                let dims = instr.raw[3];
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::MultiANewArray { cpref, dims }, v);
                self.stack.push(StackSlot::reference(v));
            }

            // ── athrow ────────────────────────────────────────────────────────
            0xbf => {
                let _exc = self.pop(pc)?;
                self.emit(pc, LiftedOpKind::AThrow);
            }

            // ── checkcast / instanceof ────────────────────────────────────────
            0xc0 => {
                // checkcast: top of stack unchanged (reference stays)
                // Modelled as a no-op for now.
                let _ = self.peek(pc)?;
            }
            0xc1 => {
                // instanceof: pops reference, pushes int
                let _ref_ = self.pop(pc)?;
                let v = self.alloc_vreg();
                self.emit_dest(pc, LiftedOpKind::Nop, v);
                self.stack.push(StackSlot::cat1(v));
            }

            // ── monitorenter / monitorexit ────────────────────────────────────
            0xc2 => {
                self.pop(pc)?;
                self.emit(pc, LiftedOpKind::MonitorEnter);
            }
            0xc3 => {
                self.pop(pc)?;
                self.emit(pc, LiftedOpKind::MonitorExit);
            }

            // ── ifnull / ifnonnull ────────────────────────────────────────────
            0xc6 => {
                let target = i32::from(i16::from_be_bytes([instr.raw[1], instr.raw[2]]));
                let val = self.pop(pc)?;
                let li = LiftedInstr {
                    pc,
                    op: LiftedOpKind::IfBranch {
                        cond: "null".into(),
                        target,
                    },
                    dest: None,
                    srcs: vec![LiftedValue::VReg(val.vreg)],
                };
                self.output.push(li);
            }
            0xc7 => {
                let target = i32::from(i16::from_be_bytes([instr.raw[1], instr.raw[2]]));
                let val = self.pop(pc)?;
                let li = LiftedInstr {
                    pc,
                    op: LiftedOpKind::IfBranch {
                        cond: "nonnull".into(),
                        target,
                    },
                    dest: None,
                    srcs: vec![LiftedValue::VReg(val.vreg)],
                };
                self.output.push(li);
            }

            // ── tableswitch / lookupswitch ─────────────────────────────────────
            0xaa | 0xab => {
                let _key = self.pop(pc)?;
                self.emit(pc, LiftedOpKind::Goto(0)); // abstract switch
            }

            // ── wide prefix ───────────────────────────────────────────────────
            0xc4 => {
                // Re-decode sub-instruction and dispatch.
                let sub = instr.raw[1];
                let wide_idx = u16::from_be_bytes([instr.raw[2], instr.raw[3]]);
                match sub {
                    0x15..=0x19 => {
                        let v = self.local_vreg(wide_idx);
                        let cat = if sub == 0x16 || sub == 0x18 {
                            SlotCategory::Cat2
                        } else {
                            SlotCategory::Cat1
                        };
                        let li = LiftedInstr {
                            pc,
                            op: LiftedOpKind::LoadLocal(wide_idx),
                            dest: Some(v),
                            srcs: vec![],
                        };
                        self.output.push(li);
                        self.stack.push(StackSlot::new(v, cat, "wide"));
                    }
                    0x36..=0x3a => {
                        let val = self.pop(pc)?;
                        let li = LiftedInstr {
                            pc,
                            op: LiftedOpKind::StoreLocal(wide_idx),
                            dest: None,
                            srcs: vec![LiftedValue::VReg(val.vreg)],
                        };
                        self.output.push(li);
                        self.locals.insert(wide_idx, val.vreg);
                    }
                    0x84 => {
                        let imm = i64::from(i16::from_be_bytes([instr.raw[4], instr.raw[5]]));
                        let src = self.local_vreg(wide_idx);
                        let v = self.alloc_vreg();
                        let li = LiftedInstr {
                            pc,
                            op: LiftedOpKind::Add,
                            dest: Some(v),
                            srcs: vec![LiftedValue::VReg(src), LiftedValue::IntConst(imm)],
                        };
                        self.output.push(li);
                        self.locals.insert(wide_idx, v);
                    }
                    _ => {}
                }
            }

            _ => {
                // Unknown / reserved — skip
            }
        }
        Ok(())
    }

    // ── State accessors ────────────────────────────────────────────────────────

    /// Current stack depth.
    #[must_use]
    pub const fn stack_depth(&self) -> usize {
        self.stack.len()
    }

    /// Number of lifted instructions emitted so far.
    #[must_use]
    pub const fn output_count(&self) -> usize {
        self.output.len()
    }

    /// Return all output instructions.
    #[must_use]
    pub fn instructions(&self) -> &[LiftedInstr] {
        &self.output
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    const fn alloc_vreg(&mut self) -> u32 {
        let v = self.next_vreg;
        self.next_vreg += 1;
        v
    }

    const fn alloc_ref(&mut self) -> u32 {
        self.alloc_vreg()
    }

    fn local_vreg(&mut self, idx: u16) -> u32 {
        if let Some(&v) = self.locals.get(&idx) {
            v
        } else {
            let v = self.alloc_vreg();
            self.locals.insert(idx, v);
            v
        }
    }

    fn push_int(&mut self, vreg: u32) {
        self.stack.push(StackSlot::cat1(vreg));
    }

    fn push_ref(&mut self, vreg: u32, pc: usize) {
        let v = vreg;
        self.emit_dest(pc, LiftedOpKind::Const(LiftedValue::Null), v);
        self.stack.push(StackSlot::reference(v));
    }

    fn const_int(&mut self, n: i64, pc: usize) -> u32 {
        let v = self.alloc_vreg();
        self.emit_dest(pc, LiftedOpKind::Const(LiftedValue::IntConst(n)), v);
        v
    }

    fn pop(&mut self, pc: usize) -> Result<StackSlot, LiftError> {
        self.stack.pop().ok_or(LiftError::StackUnderflow { pc })
    }

    fn peek(&self, pc: usize) -> Result<&StackSlot, LiftError> {
        self.stack.last().ok_or(LiftError::StackUnderflow { pc })
    }

    fn emit(&mut self, pc: usize, op: LiftedOpKind) {
        self.output.push(LiftedInstr::new(pc, op));
    }

    fn emit_dest(&mut self, pc: usize, op: LiftedOpKind, dest: u32) {
        self.output.push(LiftedInstr::new(pc, op).with_dest(dest));
    }

    fn emit_dest_src(&mut self, pc: usize, op: LiftedOpKind, dest: u32, src: LiftedValue) {
        self.output
            .push(LiftedInstr::new(pc, op).with_dest(dest).with_src(src));
    }

    /// Lift any of the `*load` opcodes: read a local into a fresh vreg, emit
    /// the `LoadLocal`, and push the slot `make_slot` builds for it.
    ///
    /// The slot constructor is a parameter, not a category flag: `iload`,
    /// `fload` and `aload` all push one slot but push `cat1`, `float` and
    /// `reference` respectively, and collapsing them would erase the type.
    fn lift_load(&mut self, idx: u16, pc: usize, make_slot: fn(u32) -> StackSlot) {
        let v = self.local_vreg(idx);
        self.output.push(LiftedInstr {
            pc,
            op: LiftedOpKind::LoadLocal(idx),
            dest: Some(v),
            srcs: vec![],
        });
        self.stack.push(make_slot(v));
    }

    fn lift_iload(&mut self, idx: u16, pc: usize) {
        self.lift_load(idx, pc, StackSlot::cat1);
    }

    fn lift_lload(&mut self, idx: u16, pc: usize) {
        self.lift_load(idx, pc, StackSlot::cat2);
    }

    fn lift_fload(&mut self, idx: u16, pc: usize) {
        self.lift_load(idx, pc, StackSlot::float);
    }

    fn lift_dload(&mut self, idx: u16, pc: usize) {
        self.lift_load(idx, pc, StackSlot::double);
    }

    fn lift_aload(&mut self, idx: u16, pc: usize) {
        self.lift_load(idx, pc, StackSlot::reference);
    }

    fn lift_istore(&mut self, idx: u16, pc: usize) -> Result<(), LiftError> {
        let val = self.pop(pc)?;
        self.output.push(LiftedInstr {
            pc,
            op: LiftedOpKind::StoreLocal(idx),
            dest: None,
            srcs: vec![LiftedValue::VReg(val.vreg)],
        });
        self.locals.insert(idx, val.vreg);
        Ok(())
    }

    fn lift_lstore(&mut self, idx: u16, pc: usize) -> Result<(), LiftError> {
        let val = self.pop(pc)?;
        self.output.push(LiftedInstr {
            pc,
            op: LiftedOpKind::StoreLocal(idx),
            dest: None,
            srcs: vec![LiftedValue::VReg(val.vreg)],
        });
        self.locals.insert(idx, val.vreg);
        Ok(())
    }

    fn lift_fstore(&mut self, idx: u16, pc: usize) -> Result<(), LiftError> {
        let val = self.pop(pc)?;
        self.output.push(LiftedInstr {
            pc,
            op: LiftedOpKind::StoreLocal(idx),
            dest: None,
            srcs: vec![LiftedValue::VReg(val.vreg)],
        });
        self.locals.insert(idx, val.vreg);
        Ok(())
    }

    fn lift_dstore(&mut self, idx: u16, pc: usize) -> Result<(), LiftError> {
        let val = self.pop(pc)?;
        self.output.push(LiftedInstr {
            pc,
            op: LiftedOpKind::StoreLocal(idx),
            dest: None,
            srcs: vec![LiftedValue::VReg(val.vreg)],
        });
        self.locals.insert(idx, val.vreg);
        Ok(())
    }

    fn lift_astore(&mut self, idx: u16, pc: usize) -> Result<(), LiftError> {
        let val = self.pop(pc)?;
        self.output.push(LiftedInstr {
            pc,
            op: LiftedOpKind::StoreLocal(idx),
            dest: None,
            srcs: vec![LiftedValue::VReg(val.vreg)],
        });
        self.locals.insert(idx, val.vreg);
        Ok(())
    }

    fn lift_binop(&mut self, kind: LiftedOpKind, op: u8, pc: usize) -> Result<(), LiftError> {
        let rhs = self.pop(pc)?;
        let lhs = self.pop(pc)?;
        let v = self.alloc_vreg();
        let li = LiftedInstr {
            pc,
            op: kind,
            dest: Some(v),
            srcs: vec![LiftedValue::VReg(lhs.vreg), LiftedValue::VReg(rhs.vreg)],
        };
        self.output.push(li);
        let slot = if matches!(
            op,
            0x61 | 0x63
                | 0x65
                | 0x67
                | 0x69
                | 0x6b
                | 0x6d
                | 0x6f
                | 0x71
                | 0x73
                | 0x75
                | 0x77
                | 0x79
                | 0x7b
                | 0x7d
                | 0x7f
                | 0x81
                | 0x83
        ) {
            StackSlot::cat2(v)
        } else {
            StackSlot::cat1(v)
        };
        self.stack.push(slot);
        Ok(())
    }

    fn lift_unop(&mut self, kind: LiftedOpKind, op: u8, pc: usize) -> Result<(), LiftError> {
        let val = self.pop(pc)?;
        let v = self.alloc_vreg();
        let li = LiftedInstr {
            pc,
            op: kind,
            dest: Some(v),
            srcs: vec![LiftedValue::VReg(val.vreg)],
        };
        self.output.push(li);
        let slot = if matches!(op, 0x75 | 0x77) {
            StackSlot::cat2(v)
        } else {
            StackSlot::cat1(v)
        };
        self.stack.push(slot);
        Ok(())
    }

    fn lift_convert(&mut self, from: &str, to: &str, _op: u8, pc: usize) -> Result<(), LiftError> {
        let val = self.pop(pc)?;
        let v = self.alloc_vreg();
        let li = LiftedInstr {
            pc,
            op: LiftedOpKind::Convert {
                from: from.into(),
                to: to.into(),
            },
            dest: Some(v),
            srcs: vec![LiftedValue::VReg(val.vreg)],
        };
        self.output.push(li);
        let slot = if matches!(to, "long" | "double") {
            StackSlot::cat2(v)
        } else {
            StackSlot::cat1(v)
        };
        self.stack.push(slot);
        Ok(())
    }
}

impl Default for JvmLifter {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn lift(bytes: &[u8]) -> Vec<LiftedInstr> {
        let mut l = JvmLifter::new();
        l.lift_method(bytes).expect("lift failed");
        l.output.clone()
    }

    // ── Constants ────────────────────────────────────────────────────────────

    #[test]
    fn test_lift_iconst_0() {
        let out = lift(&[0x03]); // iconst_0
        assert!(!out.is_empty());
        // The const instruction produces a const 0
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::Const(LiftedValue::IntConst(0))))
        );
    }

    #[test]
    fn test_lift_iconst_m1() {
        let out = lift(&[0x02]); // iconst_m1
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::Const(LiftedValue::IntConst(-1))))
        );
    }

    #[test]
    fn test_lift_bipush() {
        let out = lift(&[0x10, 0x2a]); // bipush 42
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::Const(LiftedValue::IntConst(42))))
        );
    }

    #[test]
    fn test_lift_sipush() {
        let out = lift(&[0x11, 0x01, 0x00]); // sipush 256
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::Const(LiftedValue::IntConst(256))))
        );
    }

    #[test]
    fn test_lift_ldc() {
        let out = lift(&[0x12, 0x05]); // ldc #5
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::Const(LiftedValue::CpRef(5))))
        );
    }

    // ── Loads ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_lift_iload_0() {
        let out = lift(&[0x1a]); // iload_0
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::LoadLocal(0)))
        );
    }

    #[test]
    fn test_lift_iload_3() {
        let out = lift(&[0x1d]); // iload_3
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::LoadLocal(3)))
        );
    }

    #[test]
    fn test_lift_iload_index() {
        let out = lift(&[0x15, 0x07]); // iload 7
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::LoadLocal(7)))
        );
    }

    #[test]
    fn test_lift_aload_0() {
        let out = lift(&[0x2a]); // aload_0
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::LoadLocal(0)))
        );
    }

    /// Each `*load` opcode must push a slot carrying its OWN type hint and
    /// category. Guards the shared `lift_load` helper: an earlier version of
    /// it took a bool "is cat2" flag, which silently mapped fload -> "int",
    /// dload -> "long" and aload -> "int". The whole suite still passed,
    /// because nothing else asserted the type hint.
    #[test]
    fn each_load_opcode_pushes_its_own_slot_type() {
        // iload_0, lload_0, fload_0, dload_0, aload_0
        for (code, hint, cat) in [
            (0x1au8, "int", SlotCategory::Cat1),
            (0x1e, "long", SlotCategory::Cat2),
            (0x22, "float", SlotCategory::Cat1),
            (0x26, "double", SlotCategory::Cat2),
            (0x2a, "ref", SlotCategory::Cat1),
        ] {
            let mut l = JvmLifter::new();
            l.lift_method(&[code]).expect("lift failed");
            let slot = l.stack.last().expect("load must push a slot");
            assert_eq!(slot.type_hint, hint, "opcode {code:#04x} type hint");
            assert_eq!(slot.category, cat, "opcode {code:#04x} category");
        }
    }

    // ── Stores ────────────────────────────────────────────────────────────────

    #[test]
    fn test_lift_istore_0() {
        // iconst_1  istore_0
        let out = lift(&[0x04, 0x3b]);
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::StoreLocal(0)))
        );
    }

    #[test]
    fn test_lift_istore_index() {
        let out = lift(&[0x04, 0x36, 0x05]);
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::StoreLocal(5)))
        );
    }

    // ── Arithmetic ───────────────────────────────────────────────────────────

    #[test]
    fn test_lift_iadd() {
        // iconst_1  iconst_2  iadd
        let out = lift(&[0x04, 0x05, 0x60]);
        assert!(out.iter().any(|i| matches!(&i.op, LiftedOpKind::Add)));
        // result is on the stack → one more item than before add
    }

    #[test]
    fn test_lift_isub() {
        let out = lift(&[0x04, 0x05, 0x64]);
        assert!(out.iter().any(|i| matches!(&i.op, LiftedOpKind::Sub)));
    }

    #[test]
    fn test_lift_imul() {
        let out = lift(&[0x04, 0x05, 0x68]);
        assert!(out.iter().any(|i| matches!(&i.op, LiftedOpKind::Mul)));
    }

    #[test]
    fn test_lift_idiv() {
        let out = lift(&[0x04, 0x05, 0x6c]);
        assert!(out.iter().any(|i| matches!(&i.op, LiftedOpKind::Div)));
    }

    #[test]
    fn test_lift_irem() {
        let out = lift(&[0x04, 0x05, 0x70]);
        assert!(out.iter().any(|i| matches!(&i.op, LiftedOpKind::Rem)));
    }

    #[test]
    fn test_lift_ineg() {
        let out = lift(&[0x04, 0x74]);
        assert!(out.iter().any(|i| matches!(&i.op, LiftedOpKind::Neg)));
    }

    #[test]
    fn test_lift_iand() {
        let out = lift(&[0x04, 0x05, 0x7e]);
        assert!(out.iter().any(|i| matches!(&i.op, LiftedOpKind::And)));
    }

    #[test]
    fn test_lift_ior() {
        let out = lift(&[0x04, 0x05, 0x80]);
        assert!(out.iter().any(|i| matches!(&i.op, LiftedOpKind::Or)));
    }

    #[test]
    fn test_lift_ixor() {
        let out = lift(&[0x04, 0x05, 0x82]);
        assert!(out.iter().any(|i| matches!(&i.op, LiftedOpKind::Xor)));
    }

    #[test]
    fn test_lift_ishl() {
        let out = lift(&[0x04, 0x05, 0x78]);
        assert!(out.iter().any(|i| matches!(&i.op, LiftedOpKind::Shl)));
    }

    #[test]
    fn test_lift_ishr() {
        let out = lift(&[0x04, 0x05, 0x7a]);
        assert!(out.iter().any(|i| matches!(&i.op, LiftedOpKind::Shr)));
    }

    #[test]
    fn test_lift_iushr() {
        let out = lift(&[0x04, 0x05, 0x7c]);
        assert!(out.iter().any(|i| matches!(&i.op, LiftedOpKind::Ushr)));
    }

    // ── iinc ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_lift_iinc() {
        let out = lift(&[0x84, 0x02, 0x01]); // iinc 2, 1
        assert!(
            out.iter()
                .any(|i| i.srcs.contains(&LiftedValue::IntConst(1)))
        );
    }

    // ── Comparisons ──────────────────────────────────────────────────────────

    #[test]
    fn test_lift_ifeq() {
        // bipush 0  ifeq +5
        let out = lift(&[0x10, 0x00, 0x99, 0x00, 0x05]);
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::IfBranch { cond, .. } if cond == "eq"))
        );
    }

    #[test]
    fn test_lift_if_icmpeq() {
        let out = lift(&[0x03, 0x04, 0x9f, 0x00, 0x05]);
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::IfBranch { cond, .. } if cond == "icmpeq"))
        );
    }

    // ── Invocations ──────────────────────────────────────────────────────────

    #[test]
    fn test_lift_invokevirtual() {
        let out = lift(&[0xb6, 0x00, 0x05]); // invokevirtual #5
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::InvokeVirtual(5)))
        );
    }

    #[test]
    fn test_lift_invokestatic() {
        let out = lift(&[0xb8, 0x00, 0x0a]); // invokestatic #10
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::InvokeStatic(10)))
        );
    }

    #[test]
    fn test_lift_invokespecial() {
        let out = lift(&[0xb7, 0x00, 0x01]); // invokespecial #1
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::InvokeSpecial(1)))
        );
    }

    // ── Field access ─────────────────────────────────────────────────────────

    #[test]
    fn test_lift_getfield() {
        let out = lift(&[0x2a, 0xb4, 0x00, 0x03]); // aload_0 getfield #3
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::GetField(3)))
        );
    }

    #[test]
    fn test_lift_getstatic() {
        let out = lift(&[0xb2, 0x00, 0x07]); // getstatic #7
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::GetStatic(7)))
        );
    }

    // ── Object creation ───────────────────────────────────────────────────────

    #[test]
    fn test_lift_new() {
        let out = lift(&[0xbb, 0x00, 0x0b]); // new #11
        assert!(out.iter().any(|i| matches!(&i.op, LiftedOpKind::New(11))));
    }

    #[test]
    fn test_lift_newarray() {
        let out = lift(&[0x04, 0xbc, 0x0a]); // iconst_1, newarray int
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::NewArray(_)))
        );
    }

    #[test]
    fn test_lift_arraylength() {
        let out = lift(&[0x2a, 0xbe]); // aload_0, arraylength
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::ArrayLength))
        );
    }

    // ── Return ────────────────────────────────────────────────────────────────

    #[test]
    fn test_lift_return() {
        let out = lift(&[0xb1]); // return (void)
        assert!(out.iter().any(|i| matches!(&i.op, LiftedOpKind::Return)));
    }

    #[test]
    fn test_lift_ireturn() {
        let out = lift(&[0x04, 0xac]); // iconst_1, ireturn
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::ReturnValue))
        );
    }

    // ── Stack underflow ───────────────────────────────────────────────────────

    #[test]
    fn test_lift_stack_underflow() {
        let mut l = JvmLifter::new();
        let result = l.lift_method(&[0x60]); // iadd with empty stack
        assert!(matches!(result, Err(LiftError::StackUnderflow { .. })));
    }

    // ── goto ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_lift_goto() {
        let out = lift(&[0xa7, 0x00, 0x05]); // goto +5
        assert!(out.iter().any(|i| matches!(&i.op, LiftedOpKind::Goto(5))));
    }

    // ── Monitoring ────────────────────────────────────────────────────────────

    #[test]
    fn test_lift_monitorenter() {
        let out = lift(&[0x2a, 0xc2]); // aload_0, monitorenter
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::MonitorEnter))
        );
    }

    #[test]
    fn test_lift_monitorexit() {
        let out = lift(&[0x2a, 0xc3]); // aload_0, monitorexit
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, LiftedOpKind::MonitorExit))
        );
    }

    // ── Display ───────────────────────────────────────────────────────────────

    #[test]
    fn test_lifted_value_display() {
        assert_eq!(LiftedValue::IntConst(42).to_string(), "42");
        assert_eq!(LiftedValue::Null.to_string(), "null");
        assert_eq!(LiftedValue::VReg(3).to_string(), "v3");
        assert_eq!(LiftedValue::CpRef(5).to_string(), "cp#5");
    }

    #[test]
    fn test_lifted_instr_display() {
        let li = LiftedInstr {
            pc: 0,
            op: LiftedOpKind::Add,
            dest: Some(0),
            srcs: vec![LiftedValue::VReg(1), LiftedValue::VReg(2)],
        };
        let s = li.to_string();
        assert!(s.contains("v0"));
        assert!(s.contains("add"));
    }
}
