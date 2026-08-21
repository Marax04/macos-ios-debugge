//! CIL → IL lifter: translates stack-based CIL instructions into register-based IL.
//!
//! CIL is a stack machine.  The lifter maintains a simulated evaluation stack and
//! maps stack pops/pushes to named virtual registers, emitting IL assignments.

// ---------------------------------------------------------------------------
// IL types
// ---------------------------------------------------------------------------

/// Width of a CIL evaluation-stack slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotWidth {
    /// 32-bit integer or native-int on 32-bit targets.
    I32,
    /// 64-bit integer.
    I64,
    /// 32-bit float.
    F32,
    /// 64-bit float.
    F64,
    /// Object reference.
    Ref,
    /// Managed pointer (& type).
    ManagedPtr,
    /// Value type (struct on stack).
    ValueType,
}

/// A CIL IL expression.
#[derive(Debug, Clone, PartialEq)]
pub enum CilILExpr {
    /// A virtual register (stack slot).
    Reg(u32, SlotWidth),
    /// A method argument, loaded by index.
    Arg(u16),
    /// A local variable, loaded by index.
    Local(u16),
    /// A 32-bit integer constant.
    ConstI32(i32),
    /// A 64-bit integer constant.
    ConstI64(i64),
    /// A 32-bit float constant.
    ConstF32(f32),
    /// A 64-bit float constant.
    ConstF64(f64),
    /// A null reference.
    Null,
    /// A string literal (metadata token).
    ConstStr(u32),
    /// Binary arithmetic / logical operation.
    BinOp {
        op: CilBinOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    /// Unary operation.
    UnOp { op: CilUnOp, src: Box<Self> },
    /// Indirect load from managed pointer.
    IndLoad {
        ptr: Box<Self>,
        width: SlotWidth,
    },
    /// Field load: `obj.field_token`.
    LdFld { obj: Box<Self>, token: u32 },
    /// Static field load.
    LdSFld { token: u32 },
    /// Array element load.
    LdElem {
        array: Box<Self>,
        index: Box<Self>,
        width: SlotWidth,
    },
    /// Array length.
    LdLen(Box<Self>),
    /// New object.
    NewObj {
        ctor_token: u32,
        args: Vec<Self>,
    },
    /// Cast result.
    CastClass {
        obj: Box<Self>,
        type_token: u32,
    },
    /// `isinst` test.
    IsInst {
        obj: Box<Self>,
        type_token: u32,
    },
    /// Box value.
    Box {
        val: Box<Self>,
        type_token: u32,
    },
    /// Unbox value.
    Unbox {
        val: Box<Self>,
        type_token: u32,
    },
    /// The result of a call (for use in move-result patterns).
    CallResult,
}

/// CIL binary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CilBinOp {
    Add,
    Sub,
    Mul,
    Div,
    DivUn,
    Rem,
    RemUn,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    ShrUn,
    // Overflow variants
    AddOvf,
    AddOvfUn,
    MulOvf,
    MulOvfUn,
    SubOvf,
    SubOvfUn,
}

/// CIL unary operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CilUnOp {
    Neg,
    Not,
    ConvI1,
    ConvI2,
    ConvI4,
    ConvI8,
    ConvR4,
    ConvR8,
    ConvU1,
    ConvU2,
    ConvU4,
    ConvU8,
    ConvU,
    ConvI,
    ConvRUn,
}

// ---------------------------------------------------------------------------
// IL instructions
// ---------------------------------------------------------------------------

/// A single CIL IL instruction after lifting.
#[derive(Debug, Clone, PartialEq)]
pub enum CilILInsn {
    /// `vDest = expr`
    Assign { dest: u32, expr: CilILExpr },
    /// Store to argument: `arg[index] = value_reg`
    StArg { index: u16, src: u32 },
    /// Store to local:    `local[index] = value_reg`
    StLoc { index: u16, src: u32 },
    /// Indirect store: `*ptr = value`
    StInd {
        ptr: u32,
        val: u32,
        width: SlotWidth,
    },
    /// Field store: `obj.field = value`
    StFld {
        obj: u32,
        field_token: u32,
        val: u32,
    },
    /// Static field store.
    StSFld { field_token: u32, val: u32 },
    /// Array element store.
    StElem {
        array: u32,
        index: u32,
        val: u32,
        width: SlotWidth,
    },
    /// Unconditional branch.
    Goto { offset: i32 },
    /// Conditional branch: `if cond(lhs, rhs) goto offset`.
    Branch {
        cond: BranchCond,
        lhs: u32,
        rhs: u32,
        offset: i32,
    },
    /// Return with optional value.
    Return { val: Option<u32> },
    /// Throw exception.
    Throw { obj: u32 },
    /// Call: `method_token(args)`.
    Call {
        method_token: u32,
        args: Vec<u32>,
        has_result: bool,
    },
    /// Virtual call.
    CallVirt {
        method_token: u32,
        args: Vec<u32>,
        has_result: bool,
    },
    /// Nop.
    Nop,
    /// Duplicate top of stack (materialised as an assignment).
    Dup { dest: u32, src: u32 },
    /// Pop (discard top of stack).
    Pop { src: u32 },
    /// endfinally / endfilter.
    EndEH,
    /// leave <offset>
    Leave { offset: i32 },
}

/// Branch condition kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BranchCond {
    True,
    False,
    Eq,
    Ne,
    Ge,
    Gt,
    Le,
    Lt,
    GeUn,
    GtUn,
    LeUn,
    LtUn,
}

// ---------------------------------------------------------------------------
// Stack machine state
// ---------------------------------------------------------------------------

/// Simulated evaluation stack slot.
#[derive(Debug, Clone, Copy, PartialEq)]
struct StackSlot {
    reg: u32,
    width: SlotWidth,
}

/// Simulated CIL evaluation stack.
struct EvalStack {
    slots: Vec<StackSlot>,
    next_reg: u32,
}

impl EvalStack {
    const fn new() -> Self {
        Self {
            slots: Vec::new(),
            next_reg: 0,
        }
    }

    /// Allocate a new virtual register and push it.
    fn push(&mut self, width: SlotWidth) -> u32 {
        let reg = self.next_reg;
        self.next_reg += 1;
        self.slots.push(StackSlot { reg, width });
        reg
    }

    /// Pop the top slot.
    fn pop(&mut self) -> Option<StackSlot> {
        self.slots.pop()
    }

    /// Pop two operands (rhs first, then lhs).
    fn pop2(&mut self) -> Option<(StackSlot, StackSlot)> {
        let rhs = self.pop()?;
        let lhs = self.pop()?;
        Some((lhs, rhs))
    }

    /// Peek at the top slot without removing it.
    fn peek(&self) -> Option<&StackSlot> {
        self.slots.last()
    }
}

// ---------------------------------------------------------------------------
// Lift errors
// ---------------------------------------------------------------------------

/// Errors from the CIL lifter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CilLiftError {
    /// Input too short.
    Truncated,
    /// Opcode not yet handled.
    Unimplemented(u8),
    /// Stack underflow.
    StackUnderflow,
    /// The 0xFE prefix opcode is not yet handled.
    UnimplementedPrefix(u8),
}

impl std::fmt::Display for CilLiftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated CIL bytecode"),
            Self::Unimplemented(op) => write!(f, "unimplemented CIL opcode 0x{op:02X}"),
            Self::StackUnderflow => write!(f, "evaluation stack underflow"),
            Self::UnimplementedPrefix(op) => write!(f, "unimplemented 0xFE opcode 0x{op:02X}"),
        }
    }
}

impl std::error::Error for CilLiftError {}

// ---------------------------------------------------------------------------
// CilLifter
// ---------------------------------------------------------------------------

/// CIL → IL lifter.
///
/// Call [`CilLifter::lift_one`] repeatedly to translate a CIL method body.
/// The lifter tracks a simulated evaluation stack across calls.
pub struct CilLifter {
    stack: EvalStack,
}

impl CilLifter {
    /// Create a new lifter with an empty evaluation stack.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stack: EvalStack::new(),
        }
    }

    /// Reset the evaluation stack (e.g. at the start of a new method).
    pub fn reset(&mut self) {
        self.stack = EvalStack::new();
    }

    /// Lift one CIL instruction from `bytes`.
    ///
    /// Returns `(Vec<CilILInsn>, bytes_consumed)`.
    ///
    /// # Errors
    /// Returns [`CilLiftError`] for truncated input, stack underflow,
    /// or unimplemented opcodes.
    pub fn lift_one(&mut self, bytes: &[u8]) -> Result<(Vec<CilILInsn>, usize), CilLiftError> {
        if bytes.is_empty() {
            return Err(CilLiftError::Truncated);
        }
        let op = bytes[0];

        let u8_op = |off: usize| bytes.get(off).copied().ok_or(CilLiftError::Truncated);
        let i8_op = |off: usize| {
            bytes
                .get(off)
                .map(|&b| b.cast_signed())
                .ok_or(CilLiftError::Truncated)
        };
        let i32_op = |off: usize| -> Result<i32, CilLiftError> {
            if bytes.len() < off + 4 {
                return Err(CilLiftError::Truncated);
            }
            Ok(i32::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
            ]))
        };
        let i64_op = |off: usize| -> Result<i64, CilLiftError> {
            if bytes.len() < off + 8 {
                return Err(CilLiftError::Truncated);
            }
            Ok(i64::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ]))
        };
        let u32_op = |off: usize| -> Result<u32, CilLiftError> {
            if bytes.len() < off + 4 {
                return Err(CilLiftError::Truncated);
            }
            Ok(u32::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
            ]))
        };
        let f32_op = |off: usize| -> Result<f32, CilLiftError> {
            if bytes.len() < off + 4 {
                return Err(CilLiftError::Truncated);
            }
            Ok(f32::from_le_bytes([bytes[off], bytes[off+1], bytes[off+2], bytes[off+3]]))
        };
        let f64_op = |off: usize| -> Result<f64, CilLiftError> {
            let raw = i64_op(off)?;
            Ok(f64::from_le_bytes(raw.to_le_bytes()))
        };

        macro_rules! pop {
            () => {
                self.stack.pop().ok_or(CilLiftError::StackUnderflow)?
            };
        }
        macro_rules! pop2 {
            () => {
                self.stack.pop2().ok_or(CilLiftError::StackUnderflow)?
            };
        }

        let mut out = Vec::new();

        match op {
            // nop
            // break
            0x00 | 0x01 => {
                out.push(CilILInsn::Nop);
                return Ok((out, 1));
            }

            // ldarg.0 … ldarg.3
            0x02..=0x05 => {
                let idx = u16::from(op - 0x02);
                let r = self.stack.push(SlotWidth::I32);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::Arg(idx),
                });
                return Ok((out, 1));
            }
            // ldloc.0 … ldloc.3
            0x06..=0x09 => {
                let idx = u16::from(op - 0x06);
                let r = self.stack.push(SlotWidth::I32);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::Local(idx),
                });
                return Ok((out, 1));
            }
            // stloc.0 … stloc.3
            0x0a..=0x0d => {
                let idx = u16::from(op - 0x0a);
                let src_slot = pop!();
                out.push(CilILInsn::StLoc {
                    index: idx,
                    src: src_slot.reg,
                });
                return Ok((out, 1));
            }

            // ldarg.s <uint8>
            0x0e => {
                let idx = u16::from(u8_op(1)?);
                let r = self.stack.push(SlotWidth::I32);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::Arg(idx),
                });
                return Ok((out, 2));
            }
            // ldarga.s <uint8>
            0x0f => {
                let idx = u16::from(u8_op(1)?);
                let r = self.stack.push(SlotWidth::ManagedPtr);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::Arg(idx),
                });
                return Ok((out, 2));
            }
            // starg.s <uint8>
            0x10 => {
                let idx = u16::from(u8_op(1)?);
                let src_slot = pop!();
                out.push(CilILInsn::StArg {
                    index: idx,
                    src: src_slot.reg,
                });
                return Ok((out, 2));
            }
            // ldloc.s <uint8>
            0x11 => {
                let idx = u16::from(u8_op(1)?);
                let r = self.stack.push(SlotWidth::I32);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::Local(idx),
                });
                return Ok((out, 2));
            }
            // ldloca.s <uint8>
            0x12 => {
                let idx = u16::from(u8_op(1)?);
                let r = self.stack.push(SlotWidth::ManagedPtr);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::Local(idx),
                });
                return Ok((out, 2));
            }
            // stloc.s <uint8>
            0x13 => {
                let idx = u16::from(u8_op(1)?);
                let src_slot = pop!();
                out.push(CilILInsn::StLoc {
                    index: idx,
                    src: src_slot.reg,
                });
                return Ok((out, 2));
            }

            // ldnull
            0x14 => {
                let r = self.stack.push(SlotWidth::Ref);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::Null,
                });
                return Ok((out, 1));
            }
            // ldc.i4.m1
            0x15 => {
                let r = self.stack.push(SlotWidth::I32);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::ConstI32(-1),
                });
                return Ok((out, 1));
            }
            // ldc.i4.0 … ldc.i4.8
            0x16..=0x1e => {
                let val = i32::from(op - 0x16);
                let r = self.stack.push(SlotWidth::I32);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::ConstI32(val),
                });
                return Ok((out, 1));
            }
            // ldc.i4.s <int8>
            0x1f => {
                let val = i32::from(i8_op(1)?);
                let r = self.stack.push(SlotWidth::I32);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::ConstI32(val),
                });
                return Ok((out, 2));
            }
            // ldc.i4 <int32>
            0x20 => {
                let val = i32_op(1)?;
                let r = self.stack.push(SlotWidth::I32);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::ConstI32(val),
                });
                return Ok((out, 5));
            }
            // ldc.i8 <int64>
            0x21 => {
                let val = i64_op(1)?;
                let r = self.stack.push(SlotWidth::I64);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::ConstI64(val),
                });
                return Ok((out, 9));
            }
            // ldc.r4 <float32>
            0x22 => {
                let val = f32_op(1)?;
                let r = self.stack.push(SlotWidth::F32);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::ConstF32(val),
                });
                return Ok((out, 5));
            }
            // ldc.r8 <float64>
            0x23 => {
                let val = f64_op(1)?;
                let r = self.stack.push(SlotWidth::F64);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::ConstF64(val),
                });
                return Ok((out, 9));
            }

            // dup
            0x25 => {
                let top = *self
                    .stack
                    .peek()
                    .ok_or(CilLiftError::StackUnderflow)?;
                let r = self.stack.push(top.width);
                out.push(CilILInsn::Dup {
                    dest: r,
                    src: top.reg,
                });
                return Ok((out, 1));
            }
            // pop
            0x26 => {
                let s = pop!();
                out.push(CilILInsn::Pop { src: s.reg });
                return Ok((out, 1));
            }

            // jmp <token>
            0x27 => {
                let _token = u32_op(1)?;
                out.push(CilILInsn::Goto { offset: 0 });
                return Ok((out, 5));
            }
            // call <token>
            0x28 | 0x29 => {
                let token = u32_op(1)?;
                out.push(CilILInsn::Call {
                    method_token: token,
                    args: vec![],
                    has_result: true,
                });
                return Ok((out, 5));
            }
            // calli <token>
            // ret
            0x2a => {
                let val = self.stack.pop().map(|s| s.reg);
                out.push(CilILInsn::Return { val });
                return Ok((out, 1));
            }

            // br.s <int8>
            0x2b => {
                let off = i32::from(i8_op(1)?);
                out.push(CilILInsn::Goto { offset: off });
                return Ok((out, 2));
            }
            // brfalse.s / brtrue.s / beq.s … blt.un.s
            0x2c => {
                let off = i32::from(i8_op(1)?);
                let s = pop!();
                out.push(CilILInsn::Branch {
                    cond: BranchCond::False,
                    lhs: s.reg,
                    rhs: 0,
                    offset: off,
                });
                return Ok((out, 2));
            }
            0x2d => {
                let off = i32::from(i8_op(1)?);
                let s = pop!();
                out.push(CilILInsn::Branch {
                    cond: BranchCond::True,
                    lhs: s.reg,
                    rhs: 0,
                    offset: off,
                });
                return Ok((out, 2));
            }
            0x2e..=0x37 => {
                let off = i32::from(i8_op(1)?);
                let cond = short_branch_cond(op);
                let (lhs, rhs) = pop2!();
                out.push(CilILInsn::Branch {
                    cond,
                    lhs: lhs.reg,
                    rhs: rhs.reg,
                    offset: off,
                });
                return Ok((out, 2));
            }
            // br <int32>
            0x38 => {
                let off = i32_op(1)?;
                out.push(CilILInsn::Goto { offset: off });
                return Ok((out, 5));
            }
            // brfalse <int32>
            0x39 => {
                let off = i32_op(1)?;
                let s = pop!();
                out.push(CilILInsn::Branch {
                    cond: BranchCond::False,
                    lhs: s.reg,
                    rhs: 0,
                    offset: off,
                });
                return Ok((out, 5));
            }
            // brtrue <int32>
            0x3a => {
                let off = i32_op(1)?;
                let s = pop!();
                out.push(CilILInsn::Branch {
                    cond: BranchCond::True,
                    lhs: s.reg,
                    rhs: 0,
                    offset: off,
                });
                return Ok((out, 5));
            }
            0x3b..=0x44 => {
                let off = i32_op(1)?;
                let cond = long_branch_cond(op);
                let (lhs, rhs) = pop2!();
                out.push(CilILInsn::Branch {
                    cond,
                    lhs: lhs.reg,
                    rhs: rhs.reg,
                    offset: off,
                });
                return Ok((out, 5));
            }

            // Arithmetic / logic (all pop 2, push 1)
            0x58 => {
                return self.lift_binop(CilBinOp::Add, SlotWidth::I32);
            } // add
            0x59 => {
                return self.lift_binop(CilBinOp::Sub, SlotWidth::I32);
            } // sub
            0x5a => {
                return self.lift_binop(CilBinOp::Mul, SlotWidth::I32);
            } // mul
            0x5b => {
                return self.lift_binop(CilBinOp::Div, SlotWidth::I32);
            } // div
            0x5c => {
                return self.lift_binop(CilBinOp::DivUn, SlotWidth::I32);
            }
            0x5d => {
                return self.lift_binop(CilBinOp::Rem, SlotWidth::I32);
            }
            0x5e => {
                return self.lift_binop(CilBinOp::RemUn, SlotWidth::I32);
            }
            0x5f => {
                return self.lift_binop(CilBinOp::And, SlotWidth::I32);
            }
            0x60 => {
                return self.lift_binop(CilBinOp::Or, SlotWidth::I32);
            }
            0x61 => {
                return self.lift_binop(CilBinOp::Xor, SlotWidth::I32);
            }
            0x62 => {
                return self.lift_binop(CilBinOp::Shl, SlotWidth::I32);
            }
            0x63 => {
                return self.lift_binop(CilBinOp::Shr, SlotWidth::I32);
            }
            0x64 => {
                return self.lift_binop(CilBinOp::ShrUn, SlotWidth::I32);
            }
            0x65 => {
                return self.lift_unop(CilUnOp::Neg, SlotWidth::I32);
            } // neg
            0x66 => {
                return self.lift_unop(CilUnOp::Not, SlotWidth::I32);
            } // not

            // conv.*
            0x67 => {
                return self.lift_unop(CilUnOp::ConvI1, SlotWidth::I32);
            }
            0x68 => {
                return self.lift_unop(CilUnOp::ConvI2, SlotWidth::I32);
            }
            0x69 => {
                return self.lift_unop(CilUnOp::ConvI4, SlotWidth::I32);
            }
            0x6a => {
                return self.lift_unop(CilUnOp::ConvI8, SlotWidth::I64);
            }
            0x6b => {
                return self.lift_unop(CilUnOp::ConvR4, SlotWidth::F32);
            }
            0x6c => {
                return self.lift_unop(CilUnOp::ConvR8, SlotWidth::F64);
            }
            0x6d => {
                return self.lift_unop(CilUnOp::ConvU4, SlotWidth::I32);
            }
            0x6e => {
                return self.lift_unop(CilUnOp::ConvU8, SlotWidth::I64);
            }

            // callvirt <token>
            0x6f => {
                let token = u32_op(1)?;
                out.push(CilILInsn::CallVirt {
                    method_token: token,
                    args: vec![],
                    has_result: true,
                });
                return Ok((out, 5));
            }

            // throw
            0x7a => {
                let s = pop!();
                out.push(CilILInsn::Throw { obj: s.reg });
                return Ok((out, 1));
            }

            // ldfld <token>
            0x7b => {
                let token = u32_op(1)?;
                let obj_slot = pop!();
                let r = self.stack.push(SlotWidth::I32);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::LdFld {
                        obj: Box::new(CilILExpr::Reg(obj_slot.reg, obj_slot.width)),
                        token,
                    },
                });
                return Ok((out, 5));
            }
            // stfld <token>
            0x7d => {
                let token = u32_op(1)?;
                let val_slot = pop!();
                let obj_slot = pop!();
                out.push(CilILInsn::StFld {
                    obj: obj_slot.reg,
                    field_token: token,
                    val: val_slot.reg,
                });
                return Ok((out, 5));
            }
            // ldsfld <token>
            0x7e => {
                let token = u32_op(1)?;
                let r = self.stack.push(SlotWidth::I32);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::LdSFld { token },
                });
                return Ok((out, 5));
            }
            // stsfld <token>
            0x80 => {
                let token = u32_op(1)?;
                let val_slot = pop!();
                out.push(CilILInsn::StSFld {
                    field_token: token,
                    val: val_slot.reg,
                });
                return Ok((out, 5));
            }

            // ldlen
            0x8e => {
                let s = pop!();
                let r = self.stack.push(SlotWidth::I32);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::LdLen(Box::new(CilILExpr::Reg(s.reg, s.width))),
                });
                return Ok((out, 1));
            }

            // ldelem.*
            0x90..=0x9a => {
                let w = ldelem_width(op);
                let idx_slot = pop!();
                let arr_slot = pop!();
                let r = self.stack.push(w);
                out.push(CilILInsn::Assign {
                    dest: r,
                    expr: CilILExpr::LdElem {
                        array: Box::new(CilILExpr::Reg(arr_slot.reg, arr_slot.width)),
                        index: Box::new(CilILExpr::Reg(idx_slot.reg, idx_slot.width)),
                        width: w,
                    },
                });
                return Ok((out, 1));
            }

            // stelem.*
            0x9b..=0xa2 => {
                let w = stelem_width(op);
                let val_slot = pop!();
                let idx_slot = pop!();
                let arr_slot = pop!();
                out.push(CilILInsn::StElem {
                    array: arr_slot.reg,
                    index: idx_slot.reg,
                    val: val_slot.reg,
                    width: w,
                });
                return Ok((out, 1));
            }

            // overflow arithmetic
            0xd6 => {
                return self.lift_binop(CilBinOp::AddOvf, SlotWidth::I32);
            }
            0xd7 => {
                return self.lift_binop(CilBinOp::AddOvfUn, SlotWidth::I32);
            }
            0xd8 => {
                return self.lift_binop(CilBinOp::MulOvf, SlotWidth::I32);
            }
            0xd9 => {
                return self.lift_binop(CilBinOp::MulOvfUn, SlotWidth::I32);
            }
            0xda => {
                return self.lift_binop(CilBinOp::SubOvf, SlotWidth::I32);
            }
            0xdb => {
                return self.lift_binop(CilBinOp::SubOvfUn, SlotWidth::I32);
            }

            // endfinally
            0xdc => {
                out.push(CilILInsn::EndEH);
            }
            // leave <int32>
            0xdd => {
                let off = i32_op(1)?;
                out.push(CilILInsn::Leave { offset: off });
                return Ok((out, 5));
            }
            // leave.s <int8>
            0xde => {
                let off = i32::from(i8_op(1)?);
                out.push(CilILInsn::Leave { offset: off });
                return Ok((out, 2));
            }

            // 0xFE prefix
            0xfe => {
                let op2 = u8_op(1)?;
                return self.lift_fe_prefix(op2, bytes);
            }

            _ => return Err(CilLiftError::Unimplemented(op)),
        }

        Ok((out, 1))
    }

    fn lift_binop(
        &mut self,
        op: CilBinOp,
        width: SlotWidth,
    ) -> Result<(Vec<CilILInsn>, usize), CilLiftError> {
        let (lhs, rhs) = self.stack.pop2().ok_or(CilLiftError::StackUnderflow)?;
        let r = self.stack.push(width);
        Ok((
            vec![CilILInsn::Assign {
                dest: r,
                expr: CilILExpr::BinOp {
                    op,
                    lhs: Box::new(CilILExpr::Reg(lhs.reg, lhs.width)),
                    rhs: Box::new(CilILExpr::Reg(rhs.reg, rhs.width)),
                },
            }],
            1,
        ))
    }

    fn lift_unop(
        &mut self,
        op: CilUnOp,
        width: SlotWidth,
    ) -> Result<(Vec<CilILInsn>, usize), CilLiftError> {
        let src = self.stack.pop().ok_or(CilLiftError::StackUnderflow)?;
        let r = self.stack.push(width);
        Ok((
            vec![CilILInsn::Assign {
                dest: r,
                expr: CilILExpr::UnOp {
                    op,
                    src: Box::new(CilILExpr::Reg(src.reg, src.width)),
                },
            }],
            1,
        ))
    }

    fn lift_fe_prefix(
        &mut self,
        op2: u8,
        _bytes: &[u8],
    ) -> Result<(Vec<CilILInsn>, usize), CilLiftError> {
        match op2 {
            0x01 => {
                // ceq
                let (lhs, rhs) = self.stack.pop2().ok_or(CilLiftError::StackUnderflow)?;
                let r = self.stack.push(SlotWidth::I32);
                Ok((
                    vec![CilILInsn::Assign {
                        dest: r,
                        expr: CilILExpr::BinOp {
                            op: CilBinOp::And,
                            lhs: Box::new(CilILExpr::Reg(lhs.reg, lhs.width)),
                            rhs: Box::new(CilILExpr::Reg(rhs.reg, rhs.width)),
                        },
                    }],
                    2,
                ))
            }
            0x02..=0x05 => {
                // cgt / cgt.un / clt / clt.un
                let (lhs, rhs) = self.stack.pop2().ok_or(CilLiftError::StackUnderflow)?;
                let r = self.stack.push(SlotWidth::I32);
                Ok((
                    vec![CilILInsn::Assign {
                        dest: r,
                        expr: CilILExpr::BinOp {
                            op: CilBinOp::And,
                            lhs: Box::new(CilILExpr::Reg(lhs.reg, lhs.width)),
                            rhs: Box::new(CilILExpr::Reg(rhs.reg, rhs.width)),
                        },
                    }],
                    2,
                ))
            }
            0x0f => {
                // localloc
                let sz = self.stack.pop().ok_or(CilLiftError::StackUnderflow)?;
                let r = self.stack.push(SlotWidth::ManagedPtr);
                Ok((
                    vec![CilILInsn::Assign {
                        dest: r,
                        expr: CilILExpr::Reg(sz.reg, sz.width),
                    }],
                    2,
                ))
            }
            0x11 => {
                // endfilter
                let _ = self.stack.pop();
                Ok((vec![CilILInsn::EndEH], 2))
            }
            0x1a => {
                // rethrow
                Ok((vec![CilILInsn::Throw { obj: u32::MAX }], 2))
            }
            _ => Err(CilLiftError::UnimplementedPrefix(op2)),
        }
    }
}

impl Default for CilLifter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Branch condition helpers
// ---------------------------------------------------------------------------

const fn short_branch_cond(op: u8) -> BranchCond {
    match op {
        0x2e => BranchCond::Eq,
        0x2f => BranchCond::Ge,
        0x30 => BranchCond::Gt,
        0x31 => BranchCond::Le,
        0x32 => BranchCond::Lt,
        0x33 => BranchCond::Ne,
        0x34 => BranchCond::GeUn,
        0x35 => BranchCond::GtUn,
        0x36 => BranchCond::LeUn,
        _ => BranchCond::LtUn,
    }
}

const fn long_branch_cond(op: u8) -> BranchCond {
    match op {
        0x3b => BranchCond::Eq,
        0x3c => BranchCond::Ge,
        0x3d => BranchCond::Gt,
        0x3e => BranchCond::Le,
        0x3f => BranchCond::Lt,
        0x40 => BranchCond::Ne,
        0x41 => BranchCond::GeUn,
        0x42 => BranchCond::GtUn,
        0x43 => BranchCond::LeUn,
        _ => BranchCond::LtUn,
    }
}

const fn ldelem_width(op: u8) -> SlotWidth {
    match op {
        0x90 | 0x91 | 0x92 | 0x93 | 0x94 | 0x95 | 0x97 => SlotWidth::I32,
        0x96 => SlotWidth::I64,
        0x98 => SlotWidth::F32,
        0x99 => SlotWidth::F64,
        _ => SlotWidth::Ref,
    }
}

const fn stelem_width(op: u8) -> SlotWidth {
    match op {
        0x9b..=0x9e => SlotWidth::I32,
        0x9f => SlotWidth::I64,
        0xa0 => SlotWidth::F32,
        0xa1 => SlotWidth::F64,
        _ => SlotWidth::Ref,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn lift(bytes: &[u8]) -> Vec<CilILInsn> {
        let mut lifter = CilLifter::new();
        lifter.lift_one(bytes).unwrap().0
    }

    #[test]
    fn test_nop() {
        let insns = lift(&[0x00]);
        assert_eq!(insns[0], CilILInsn::Nop);
    }

    #[test]
    fn test_ldarg0_stloc0() {
        let mut lifter = CilLifter::new();
        // ldarg.0: push
        let (i1, _) = lifter.lift_one(&[0x02]).unwrap();
        assert!(matches!(
            i1[0],
            CilILInsn::Assign {
                expr: CilILExpr::Arg(0),
                ..
            }
        ));
        // stloc.0: pop
        let (i2, _) = lifter.lift_one(&[0x0a]).unwrap();
        assert!(matches!(i2[0], CilILInsn::StLoc { index: 0, .. }));
    }

    #[test]
    fn test_ldc_i4_m1() {
        let insns = lift(&[0x15]);
        assert!(matches!(
            insns[0],
            CilILInsn::Assign {
                expr: CilILExpr::ConstI32(-1),
                ..
            }
        ));
    }

    #[test]
    fn test_ldc_i4_0_through_8() {
        for n in 0i32..=8 {
            let op = 0x16u8 + u8::try_from(n).expect("loop runs over 0..=8");
            let insns = lift(&[op]);
            assert!(
                matches!(insns[0], CilILInsn::Assign { expr: CilILExpr::ConstI32(v), .. } if v == n)
            );
        }
    }

    #[test]
    fn test_ldc_i4_s() {
        let insns = lift(&[0x1f, 0xff]); // -1
        assert!(matches!(
            insns[0],
            CilILInsn::Assign {
                expr: CilILExpr::ConstI32(-1),
                ..
            }
        ));
    }

    #[test]
    fn test_ldc_i4() {
        let mut buf = vec![0x20u8];
        buf.extend_from_slice(&42_i32.to_le_bytes());
        let insns = lift(&buf);
        assert!(matches!(
            insns[0],
            CilILInsn::Assign {
                expr: CilILExpr::ConstI32(42),
                ..
            }
        ));
    }

    #[test]
    fn test_ldc_i8() {
        let mut buf = vec![0x21u8];
        buf.extend_from_slice(&(-1_i64).to_le_bytes());
        let insns = lift(&buf);
        assert!(matches!(
            insns[0],
            CilILInsn::Assign {
                expr: CilILExpr::ConstI64(-1),
                ..
            }
        ));
    }

    #[test]
    fn test_add_binop() {
        let mut lifter = CilLifter::new();
        lifter.lift_one(&[0x17]).unwrap(); // ldc.i4.1
        lifter.lift_one(&[0x18]).unwrap(); // ldc.i4.2
        let (insns, _) = lifter.lift_one(&[0x58]).unwrap(); // add
        assert!(matches!(
            insns[0],
            CilILInsn::Assign {
                expr: CilILExpr::BinOp {
                    op: CilBinOp::Add,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn test_sub() {
        let mut lifter = CilLifter::new();
        lifter.lift_one(&[0x17]).unwrap();
        lifter.lift_one(&[0x18]).unwrap();
        let (insns, _) = lifter.lift_one(&[0x59]).unwrap();
        assert!(matches!(
            insns[0],
            CilILInsn::Assign {
                expr: CilILExpr::BinOp {
                    op: CilBinOp::Sub,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn test_neg() {
        let mut lifter = CilLifter::new();
        lifter.lift_one(&[0x17]).unwrap();
        let (insns, _) = lifter.lift_one(&[0x65]).unwrap();
        assert!(matches!(
            insns[0],
            CilILInsn::Assign {
                expr: CilILExpr::UnOp {
                    op: CilUnOp::Neg,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn test_ret_with_value() {
        let mut lifter = CilLifter::new();
        lifter.lift_one(&[0x17]).unwrap(); // ldc.i4.1
        let (insns, _) = lifter.lift_one(&[0x2a]).unwrap(); // ret
        assert!(matches!(insns[0], CilILInsn::Return { val: Some(_) }));
    }

    #[test]
    fn test_ret_void() {
        let mut lifter = CilLifter::new();
        let (insns, _) = lifter.lift_one(&[0x2a]).unwrap();
        assert!(matches!(insns[0], CilILInsn::Return { val: None }));
    }

    #[test]
    fn test_br_s() {
        let insns = lift(&[0x2b, 0x04]);
        assert!(matches!(insns[0], CilILInsn::Goto { offset: 4 }));
    }

    #[test]
    fn test_brfalse_s() {
        let mut lifter = CilLifter::new();
        lifter.lift_one(&[0x16]).unwrap();
        let (insns, _) = lifter.lift_one(&[0x2c, 0x03]).unwrap();
        assert!(matches!(
            insns[0],
            CilILInsn::Branch {
                cond: BranchCond::False,
                ..
            }
        ));
    }

    #[test]
    fn test_brtrue_s() {
        let mut lifter = CilLifter::new();
        lifter.lift_one(&[0x16]).unwrap();
        let (insns, _) = lifter.lift_one(&[0x2d, 0x03]).unwrap();
        assert!(matches!(
            insns[0],
            CilILInsn::Branch {
                cond: BranchCond::True,
                ..
            }
        ));
    }

    #[test]
    fn test_call() {
        let mut buf = vec![0x28u8];
        buf.extend_from_slice(&0x0600_0001_u32.to_le_bytes());
        let insns = lift(&buf);
        assert!(matches!(
            insns[0],
            CilILInsn::Call {
                method_token: 0x0600_0001,
                ..
            }
        ));
    }

    #[test]
    fn test_callvirt() {
        let mut buf = vec![0x6f_u8];
        buf.extend_from_slice(&0x0a00_0002_u32.to_le_bytes());
        let insns = lift(&buf);
        assert!(matches!(
            insns[0],
            CilILInsn::CallVirt {
                method_token: 0x0a00_0002,
                ..
            }
        ));
    }

    #[test]
    fn test_throw() {
        let mut lifter = CilLifter::new();
        lifter.lift_one(&[0x14]).unwrap(); // ldnull
        let (insns, _) = lifter.lift_one(&[0x7a]).unwrap();
        assert!(matches!(insns[0], CilILInsn::Throw { .. }));
    }

    #[test]
    fn test_endfinally() {
        let insns = lift(&[0xdc]);
        assert_eq!(insns[0], CilILInsn::EndEH);
    }

    #[test]
    fn test_leave() {
        let mut buf = vec![0xdd_u8];
        buf.extend_from_slice(&10_i32.to_le_bytes());
        let insns = lift(&buf);
        assert!(matches!(insns[0], CilILInsn::Leave { offset: 10 }));
    }

    #[test]
    fn test_fe_ceq() {
        let mut lifter = CilLifter::new();
        lifter.lift_one(&[0x17]).unwrap();
        lifter.lift_one(&[0x18]).unwrap();
        let (insns, sz) = lifter.lift_one(&[0xfe, 0x01]).unwrap();
        assert_eq!(sz, 2);
        assert!(matches!(insns[0], CilILInsn::Assign { .. }));
    }

    #[test]
    fn test_stack_underflow() {
        let mut lifter = CilLifter::new();
        let err = lifter.lift_one(&[0x58]).unwrap_err(); // add with empty stack
        assert_eq!(err, CilLiftError::StackUnderflow);
    }

    #[test]
    fn test_dup() {
        let mut lifter = CilLifter::new();
        lifter.lift_one(&[0x17]).unwrap(); // ldc.i4.1
        let (insns, _) = lifter.lift_one(&[0x25]).unwrap(); // dup
        assert!(matches!(insns[0], CilILInsn::Dup { .. }));
    }

    #[test]
    fn test_pop() {
        let mut lifter = CilLifter::new();
        lifter.lift_one(&[0x17]).unwrap();
        let (insns, _) = lifter.lift_one(&[0x26]).unwrap();
        assert!(matches!(insns[0], CilILInsn::Pop { .. }));
    }

    #[test]
    fn test_ldsfld_stsfld() {
        let mut token_buf = vec![0x7e_u8]; // ldsfld
        token_buf.extend_from_slice(&1_u32.to_le_bytes());
        let insns = lift(&token_buf);
        assert!(matches!(
            insns[0],
            CilILInsn::Assign {
                expr: CilILExpr::LdSFld { token: 1 },
                ..
            }
        ));
    }
}
