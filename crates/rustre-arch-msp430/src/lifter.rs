//! `lifter.rs` — LLIL-equivalent lifter for MSP430.
//!
//! Maps each decoded [`Msp430Insn`] to a sequence of [`IlOp`] intermediate
//! language operations.  The IL is intentionally simple (inspired by Binary
//! Ninja LLIL / Ghidra P-code) and is designed to be lowered further by a
//! consumer.
//!
//! # Status Register flags
//!
//! SR bits (see [`crate::sr_bits`]):
//! * **C** (carry)  — bit 0
//! * **Z** (zero)   — bit 1
//! * **N** (neg)    — bit 2
//! * **GIE**        — bit 3 (not set by arithmetic, only explicit BIS/BIC)
//! * **CPUOFF**     — bit 4
//! * **OSCOFF**     — bit 5
//! * **SCG0/SCG1**  — bits 6-7
//! * **V** (ovf)    — bit 8

use crate::{
    AddrMode,
    decoder::{InsnKind, Msp430Insn, Op1, Op2, Operand},
    regs, sr_bits,
};

// ── IL value types ─────────────────────────────────────────────────────────────

/// Width of an IL value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IlWidth {
    Byte,
    Word,
}

impl IlWidth {
    /// Return the byte size.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
        }
    }

    /// Return the bit mask for this width.
    #[must_use]
    pub const fn mask(self) -> u32 {
        match self {
            Self::Byte => 0xFF,
            Self::Word => 0xFFFF,
        }
    }

    /// Return the sign bit for this width.
    #[must_use]
    pub const fn sign_bit(self) -> u32 {
        match self {
            Self::Byte => 0x80,
            Self::Word => 0x8000,
        }
    }
}

impl From<bool> for IlWidth {
    /// Convert byte-width flag (`true` = byte, `false` = word).
    fn from(bw: bool) -> Self {
        if bw { Self::Byte } else { Self::Word }
    }
}

// ── IL expression ─────────────────────────────────────────────────────────────

/// An IL expression — the right-hand side of an assignment or operand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IlExpr {
    /// Integer constant.
    Const(u32),
    /// Read a register by index.
    Reg(u32),
    /// Read a flag from the SR by mask.
    Flag(u16),
    /// Read memory at a computed address.
    Load { addr: Box<Self>, width: IlWidth },
    /// Binary arithmetic addition (no carry).
    Add(Box<Self>, Box<Self>),
    /// Binary subtraction.
    Sub(Box<Self>, Box<Self>),
    /// Addition with carry-in.
    Addc(Box<Self>, Box<Self>, Box<Self>),
    /// Subtraction with borrow (SUBC).
    Subc(Box<Self>, Box<Self>, Box<Self>),
    /// Bitwise AND.
    And(Box<Self>, Box<Self>),
    /// Bitwise OR (BIS).
    Or(Box<Self>, Box<Self>),
    /// Bitwise XOR.
    Xor(Box<Self>, Box<Self>),
    /// Bitwise NOT.
    Not(Box<Self>),
    /// Logical shift right by 1 (with carry propagation: RRC).
    Rrc(Box<Self>, Box<Self>), // (value, carry_in)
    /// Arithmetic shift right by 1 (RRA).
    Rra(Box<Self>),
    /// Swap bytes (SWPB).
    Swpb(Box<Self>),
    /// Sign-extend byte to word (SXT).
    Sxt(Box<Self>),
    /// Zero-extend to word width.
    ZExt(Box<Self>, IlWidth),
    /// Truncate / mask to width.
    Trunc(Box<Self>, IlWidth),
    /// Carry-out from addition (for flag synthesis).
    CarryOf(Box<Self>, Box<Self>),
    /// Overflow flag from signed addition.
    OverflowOf(Box<Self>, Box<Self>),
}

impl IlExpr {
    fn boxed(self) -> Box<Self> {
        Box::new(self)
    }

    /// Construct a Const(0).
    #[must_use] 
    pub const fn zero() -> Self {
        Self::Const(0)
    }
    /// Construct a Const(1).
    #[must_use] 
    pub const fn one() -> Self {
        Self::Const(1)
    }
}

// ── IL statement ──────────────────────────────────────────────────────────────

/// An IL statement — one side-effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IlStmt {
    /// Write to a register.
    SetReg {
        reg: u32,
        value: IlExpr,
        width: IlWidth,
    },
    /// Write to a status-register flag.
    SetFlag { mask: u16, value: IlExpr },
    /// Write to memory.
    Store {
        addr: IlExpr,
        value: IlExpr,
        width: IlWidth,
    },
    /// Unconditional branch to a constant target.
    Jump(u32),
    /// Conditional branch: `if cond { goto taken }`.
    Branch {
        cond: IlExpr,
        taken: u32,
        fallthrough: u32,
    },
    /// Call to a computed address.
    Call(IlExpr),
    /// Return from function.
    Ret,
    /// No-operation / intrinsic.
    Nop,
    /// System call / software interrupt.
    SysCall(u32),
    /// Undefined/unlifted instruction marker.
    Undef,
}

// ── Lifted instruction ─────────────────────────────────────────────────────────

/// The lifted IL for one machine instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftedInsn {
    /// Source instruction address.
    pub addr: u64,
    /// Byte size of the original instruction.
    pub size: usize,
    /// IL statements emitted, in order.
    pub stmts: Vec<IlStmt>,
}

impl LiftedInsn {
    const fn new(addr: u64, size: usize) -> Self {
        Self {
            addr,
            size,
            stmts: Vec::new(),
        }
    }

    fn push(&mut self, s: IlStmt) {
        self.stmts.push(s);
    }

    fn set_reg(&mut self, reg: u32, val: IlExpr, w: IlWidth) {
        self.push(IlStmt::SetReg {
            reg,
            value: val,
            width: w,
        });
    }

    fn set_flag(&mut self, mask: u16, val: IlExpr) {
        self.push(IlStmt::SetFlag { mask, value: val });
    }

    fn store(&mut self, addr: IlExpr, val: IlExpr, w: IlWidth) {
        self.push(IlStmt::Store {
            addr,
            value: val,
            width: w,
        });
    }
}

// ── Lifter context ────────────────────────────────────────────────────────────

/// Lifts a decoded MSP430 instruction to IL.
#[derive(Debug, Default)]
pub struct Msp430Lifter {
    /// Base address of the current function being lifted (for call-graph purposes).
    pub func_base: u64,
}

impl Msp430Lifter {
    /// Create a new lifter.
    #[must_use]
    pub const fn new() -> Self {
        Self { func_base: 0 }
    }

    /// Lift one decoded instruction, returning its IL.
    #[must_use]
    pub fn lift_insn(&self, insn: &Msp430Insn) -> LiftedInsn {
        let mut out = LiftedInsn::new(insn.addr, insn.size);
        match &insn.kind {
            InsnKind::Jump { cond, target } => {
                lift_jump(&mut out, *cond, *target, insn.addr, insn.size);
            }
            InsnKind::OneOp { op, bw, src } => {
                lift_one_op(&mut out, *op, *bw, src);
            }
            InsnKind::TwoOp { op, bw, src, dst } => {
                lift_two_op(&mut out, *op, *bw, src, dst);
            }
            InsnKind::Emulated { mnemonic, bw, dst } => {
                lift_emulated(&mut out, mnemonic, *bw, dst, insn.addr, insn.size);
            }
            InsnKind::Data(_) => {
                out.push(IlStmt::Undef);
            }
        }
        out
    }

    /// Lift a slice of decoded instructions.
    #[must_use]
    pub fn lift_all(&self, insns: &[Msp430Insn]) -> Vec<LiftedInsn> {
        insns.iter().map(|i| self.lift_insn(i)).collect()
    }
}

// ── Jump lifting ──────────────────────────────────────────────────────────────

use crate::decoder::JumpCond;

fn lift_jump(out: &mut LiftedInsn, cond: JumpCond, target: u16, addr: u64, size: usize) {
    let fallthrough = u32::try_from(addr + size as u64).unwrap_or(u32::MAX);
    let target_u32 = u32::from(target);

    if cond == JumpCond::Jmp {
        out.push(IlStmt::Jump(target_u32));
        return;
    }

    // Build condition expression from SR flags.
    let cond_expr = match cond {
        JumpCond::Jne => IlExpr::Not(IlExpr::Flag(sr_bits::Z).boxed()),
        JumpCond::Jeq => IlExpr::Flag(sr_bits::Z),
        JumpCond::Jnc => IlExpr::Not(IlExpr::Flag(sr_bits::C).boxed()),
        JumpCond::Jc => IlExpr::Flag(sr_bits::C),
        JumpCond::Jn => IlExpr::Flag(sr_bits::N),
        JumpCond::Jge => {
            // N == V  (both clear or both set)
            IlExpr::Not(
                IlExpr::Xor(
                    IlExpr::Flag(sr_bits::N).boxed(),
                    IlExpr::Flag(sr_bits::V).boxed(),
                )
                .boxed(),
            )
        }
        JumpCond::Jl => {
            // N != V
            IlExpr::Xor(
                IlExpr::Flag(sr_bits::N).boxed(),
                IlExpr::Flag(sr_bits::V).boxed(),
            )
        }
        JumpCond::Jmp => unreachable!(),
    };

    out.push(IlStmt::Branch {
        cond: cond_expr,
        taken: target_u32,
        fallthrough,
    });
}

// ── Format-II (single-operand) lifting ────────────────────────────────────────

fn lift_one_op(out: &mut LiftedInsn, op: Op1, bw: bool, src: &Operand) {
    let w = IlWidth::from(bw);
    match op {
        Op1::Reti => {
            // Pop SR, then pop PC.
            let sp = IlExpr::Reg(regs::SP);
            let sr_val = IlExpr::Load {
                addr: sp.clone().boxed(),
                width: IlWidth::Word,
            };
            out.set_reg(regs::SR, sr_val, IlWidth::Word);
            let sp_plus2 = IlExpr::Add(sp.boxed(), IlExpr::Const(2).boxed());
            out.set_reg(regs::SP, sp_plus2.clone(), IlWidth::Word);
            let pc_val = IlExpr::Load {
                addr: sp_plus2.boxed(),
                width: IlWidth::Word,
            };
            out.set_reg(regs::PC, pc_val, IlWidth::Word);
            let new_sp = IlExpr::Add(IlExpr::Reg(regs::SP).boxed(), IlExpr::Const(2).boxed());
            out.set_reg(regs::SP, new_sp, IlWidth::Word);
            out.push(IlStmt::Ret);
        }
        Op1::Call => {
            let target = read_operand(src);
            // Push return address (PC already past this instruction — caller sets it).
            // We model this as a Call IL statement.
            out.push(IlStmt::Call(target));
        }
        Op1::Push => {
            let val = read_operand(src);
            // SP -= 2; MEM[SP] = val
            let new_sp = IlExpr::Sub(IlExpr::Reg(regs::SP).boxed(), IlExpr::Const(2).boxed());
            out.set_reg(regs::SP, new_sp.clone(), IlWidth::Word);
            out.store(new_sp, val, w);
        }
        Op1::Rrc => {
            let val = read_operand(src);
            let carry_in = IlExpr::Flag(sr_bits::C);
            let result = IlExpr::Rrc(val.clone().boxed(), carry_in.boxed());
            // New carry = old bit 0.
            let new_carry = IlExpr::And(val.boxed(), IlExpr::Const(1).boxed());
            write_operand(out, src, result.clone(), w);
            emit_nzc_flags(out, result, new_carry);
            out.set_flag(sr_bits::V, IlExpr::zero());
        }
        Op1::Rra => {
            let val = read_operand(src);
            let result = IlExpr::Rra(val.clone().boxed());
            let new_carry = IlExpr::And(val.boxed(), IlExpr::Const(1).boxed());
            write_operand(out, src, result.clone(), w);
            emit_nzc_flags(out, result, new_carry);
            out.set_flag(sr_bits::V, IlExpr::zero());
        }
        Op1::Swpb => {
            let val = read_operand(src);
            let result = IlExpr::Swpb(val.boxed());
            write_operand(out, src, result, w);
            // SWPB does not affect flags.
        }
        Op1::Sxt => {
            let val = read_operand(src);
            let result = IlExpr::Sxt(val.boxed());
            write_operand(out, src, result.clone(), IlWidth::Word);
            // SXT: Z=(result==0), N=(bit15), C=(result!=0), V=0
            let is_nonzero = IlExpr::Not(
                IlExpr::And(
                    IlExpr::Xor(result.clone().boxed(), IlExpr::Const(0).boxed()).boxed(),
                    IlExpr::Const(0xFFFF).boxed(),
                )
                .boxed(),
            );
            emit_nz_flags(out, result);
            out.set_flag(sr_bits::C, is_nonzero);
            out.set_flag(sr_bits::V, IlExpr::zero());
        }
    }
}

// ── Format-I (two-operand) lifting ────────────────────────────────────────────

fn lift_two_op(out: &mut LiftedInsn, op: Op2, bw: bool, src: &Operand, dst: &Operand) {
    let w = IlWidth::from(bw);
    let src_val = read_operand(src);
    let dst_val = read_operand(dst);

    match op {
        Op2::Mov => {
            write_operand(out, dst, src_val, w);
        }
        Op2::Add => {
            let result = IlExpr::Add(src_val.clone().boxed(), dst_val.clone().boxed());
            write_operand(out, dst, result.clone(), w);
            let carry = IlExpr::CarryOf(src_val.clone().boxed(), dst_val.clone().boxed());
            let ovf = IlExpr::OverflowOf(src_val.boxed(), dst_val.boxed());
            emit_nz_flags(out, result);
            out.set_flag(sr_bits::C, carry);
            out.set_flag(sr_bits::V, ovf);
        }
        Op2::Addc => {
            let c_in = IlExpr::Flag(sr_bits::C);
            let result = IlExpr::Addc(
                src_val.clone().boxed(),
                dst_val.clone().boxed(),
                c_in.boxed(),
            );
            write_operand(out, dst, result.clone(), w);
            let carry = IlExpr::CarryOf(src_val.clone().boxed(), dst_val.clone().boxed());
            let ovf = IlExpr::OverflowOf(src_val.boxed(), dst_val.boxed());
            emit_nz_flags(out, result);
            out.set_flag(sr_bits::C, carry);
            out.set_flag(sr_bits::V, ovf);
        }
        Op2::Sub => {
            // SUB dst - src = dst + ~src + 1
            let not_src = IlExpr::Not(src_val.clone().boxed());
            let result = IlExpr::Addc(
                not_src.clone().boxed(),
                dst_val.clone().boxed(),
                IlExpr::one().boxed(),
            );
            write_operand(out, dst, result.clone(), w);
            let carry = IlExpr::CarryOf(not_src.boxed(), dst_val.clone().boxed());
            let ovf = IlExpr::OverflowOf(src_val.boxed(), dst_val.boxed());
            emit_nz_flags(out, result);
            out.set_flag(sr_bits::C, carry);
            out.set_flag(sr_bits::V, ovf);
        }
        Op2::Subc => {
            let c_in = IlExpr::Flag(sr_bits::C);
            let not_src = IlExpr::Not(src_val.clone().boxed());
            let result = IlExpr::Subc(
                not_src.clone().boxed(),
                dst_val.clone().boxed(),
                c_in.boxed(),
            );
            write_operand(out, dst, result.clone(), w);
            let carry = IlExpr::CarryOf(not_src.boxed(), dst_val.clone().boxed());
            let ovf = IlExpr::OverflowOf(src_val.boxed(), dst_val.boxed());
            emit_nz_flags(out, result);
            out.set_flag(sr_bits::C, carry);
            out.set_flag(sr_bits::V, ovf);
        }
        Op2::Cmp => {
            // CMP = SUB but result is discarded; only flags updated.
            let not_src = IlExpr::Not(src_val.clone().boxed());
            let result = IlExpr::Addc(
                not_src.clone().boxed(),
                dst_val.clone().boxed(),
                IlExpr::one().boxed(),
            );
            let carry = IlExpr::CarryOf(not_src.boxed(), dst_val.clone().boxed());
            let ovf = IlExpr::OverflowOf(src_val.boxed(), dst_val.boxed());
            emit_nz_flags(out, result);
            out.set_flag(sr_bits::C, carry);
            out.set_flag(sr_bits::V, ovf);
        }
        Op2::Dadd => {
            // BCD addition — modelled as opaque add + flag update.
            let result = IlExpr::Add(src_val.clone().boxed(), dst_val.clone().boxed());
            write_operand(out, dst, result.clone(), w);
            let carry = IlExpr::CarryOf(src_val.boxed(), dst_val.boxed());
            emit_nzc_flags(out, result, carry);
            out.set_flag(sr_bits::V, IlExpr::zero());
        }
        Op2::Bit => {
            // BIT = AND, result discarded; C = (result != 0), V = 0.
            let result = IlExpr::And(src_val.boxed(), dst_val.boxed());
            emit_nz_flags(out, result.clone());
            // C = NOT Z (for BIT)
            let c = IlExpr::Not(
                IlExpr::And(
                    IlExpr::Xor(result.boxed(), IlExpr::Const(0).boxed()).boxed(),
                    IlExpr::Const(0).boxed(),
                )
                .boxed(),
            );
            out.set_flag(sr_bits::C, c);
            out.set_flag(sr_bits::V, IlExpr::zero());
        }
        Op2::Bic => {
            let result = IlExpr::And(dst_val.boxed(), IlExpr::Not(src_val.boxed()).boxed());
            write_operand(out, dst, result, w);
            // BIC does not affect flags.
        }
        Op2::Bis => {
            let result = IlExpr::Or(src_val.boxed(), dst_val.boxed());
            write_operand(out, dst, result, w);
            // BIS does not affect flags.
        }
        Op2::Xor => {
            let result = IlExpr::Xor(src_val.clone().boxed(), dst_val.clone().boxed());
            write_operand(out, dst, result.clone(), w);
            // XOR: C = (src MSB set), V = (src MSB && dst MSB)
            let c = IlExpr::And(src_val.clone().boxed(), IlExpr::Const(0x8000).boxed());
            let v = IlExpr::And(src_val.boxed(), dst_val.boxed());
            emit_nz_flags(out, result);
            out.set_flag(sr_bits::C, c);
            out.set_flag(sr_bits::V, v);
        }
        Op2::And => {
            let result = IlExpr::And(src_val.boxed(), dst_val.boxed());
            write_operand(out, dst, result.clone(), w);
            // AND: C = (result != 0), V = 0
            let c = IlExpr::Not(
                IlExpr::And(
                    IlExpr::Xor(result.clone().boxed(), IlExpr::Const(0).boxed()).boxed(),
                    IlExpr::Const(0xFFFF).boxed(),
                )
                .boxed(),
            );
            emit_nz_flags(out, result);
            out.set_flag(sr_bits::C, c);
            out.set_flag(sr_bits::V, IlExpr::zero());
        }
    }
}

// ── Emulated instruction lifting ──────────────────────────────────────────────

fn lift_emulated(
    out: &mut LiftedInsn,
    mnemonic: &str,
    bw: bool,
    dst: &Operand,
    addr: u64,
    size: usize,
) {
    let w = IlWidth::from(bw);
    let fallthrough = u32::try_from(addr + size as u64).unwrap_or(u32::MAX);
    match mnemonic {
        "RET" => {
            let sp = IlExpr::Reg(regs::SP);
            let pc_val = IlExpr::Load {
                addr: sp.clone().boxed(),
                width: IlWidth::Word,
            };
            out.set_reg(
                regs::SP,
                IlExpr::Add(sp.boxed(), IlExpr::Const(2).boxed()),
                IlWidth::Word,
            );
            out.set_reg(regs::PC, pc_val, IlWidth::Word);
            out.push(IlStmt::Ret);
        }
        "CLR.W" | "CLR.B" => {
            write_operand(out, dst, IlExpr::zero(), w);
        }
        "INC" => {
            let val = read_operand(dst);
            let result = IlExpr::Add(val.clone().boxed(), IlExpr::one().boxed());
            write_operand(out, dst, result.clone(), w);
            emit_nz_flags(out, result);
            let carry = IlExpr::CarryOf(val.boxed(), IlExpr::one().boxed());
            out.set_flag(sr_bits::C, carry);
        }
        "DEC" => {
            let val = read_operand(dst);
            let result = IlExpr::Sub(val.clone().boxed(), IlExpr::one().boxed());
            write_operand(out, dst, result.clone(), w);
            emit_nz_flags(out, result);
            // DEC: C = (val != 0)
            let c = IlExpr::Not(IlExpr::And(val.boxed(), IlExpr::Const(0xFFFF).boxed()).boxed());
            out.set_flag(sr_bits::C, c);
        }
        "INV" => {
            let val = read_operand(dst);
            let result = IlExpr::Not(val.boxed());
            write_operand(out, dst, result.clone(), w);
            emit_nz_flags(out, result);
        }
        "DINT" => {
            // BIC #GIE, SR
            let sr = IlExpr::Reg(regs::SR);
            let new_sr = IlExpr::And(sr.boxed(), IlExpr::Const(!u32::from(sr_bits::GIE)).boxed());
            out.set_reg(regs::SR, new_sr, IlWidth::Word);
        }
        "EINT" => {
            // BIS #GIE, SR
            let sr = IlExpr::Reg(regs::SR);
            let new_sr = IlExpr::Or(sr.boxed(), IlExpr::Const(u32::from(sr_bits::GIE)).boxed());
            out.set_reg(regs::SR, new_sr, IlWidth::Word);
        }
        // "NOP" and all unknown mnemonics emit a no-op.
        _ => {
            out.push(IlStmt::Nop);
        }
    }
    let _ = fallthrough;
}

// ── Helper: read an operand into an IlExpr ────────────────────────────────────

fn read_operand(op: &Operand) -> IlExpr {
    match op.mode {
        AddrMode::Register => IlExpr::Reg(u32::from(op.reg)),
        AddrMode::Constant(c) => IlExpr::Const(i32::from(c).cast_unsigned()),
        AddrMode::Immediate => IlExpr::Const(u32::from(op.ext.unwrap_or(0))),
        AddrMode::Indexed => {
            let base = IlExpr::Reg(u32::from(op.reg));
            let offset = IlExpr::Const(u32::from(op.ext.unwrap_or(0)));
            let addr = IlExpr::Add(base.boxed(), offset.boxed());
            IlExpr::Load {
                addr: addr.boxed(),
                width: IlWidth::Word,
            }
        }
        AddrMode::Absolute | AddrMode::Symbolic => {
            let addr = IlExpr::Const(u32::from(op.ext.unwrap_or(0)));
            IlExpr::Load {
                addr: addr.boxed(),
                width: IlWidth::Word,
            }
        }
        // IndirectAutoInc: post-increment side-effect not modelled in IL; just reads.
        AddrMode::Indirect | AddrMode::IndirectAutoInc => {
            let addr = IlExpr::Reg(u32::from(op.reg));
            IlExpr::Load {
                addr: addr.boxed(),
                width: IlWidth::Word,
            }
        }
    }
}

// ── Helper: write a result to an operand destination ──────────────────────────

fn write_operand(out: &mut LiftedInsn, op: &Operand, val: IlExpr, w: IlWidth) {
    match op.mode {
        AddrMode::Register => {
            out.set_reg(u32::from(op.reg), val, w);
        }
        AddrMode::Indexed => {
            let base = IlExpr::Reg(u32::from(op.reg));
            let offset = IlExpr::Const(u32::from(op.ext.unwrap_or(0)));
            let addr = IlExpr::Add(base.boxed(), offset.boxed());
            out.store(addr, val, w);
        }
        AddrMode::Absolute | AddrMode::Symbolic => {
            let addr = IlExpr::Const(u32::from(op.ext.unwrap_or(0)));
            out.store(addr, val, w);
        }
        // Indirect / AutoInc as destination is unusual but supported.
        AddrMode::Indirect | AddrMode::IndirectAutoInc => {
            let addr = IlExpr::Reg(u32::from(op.reg));
            out.store(addr, val, w);
        }
        _ => {
            // Constants / Immediate cannot be written to; emit Undef.
            out.push(IlStmt::Undef);
        }
    }
}

// ── Helper: emit N/Z flag updates ─────────────────────────────────────────────

fn emit_nz_flags(out: &mut LiftedInsn, result: IlExpr) {
    // Z = (result == 0)
    out.set_flag(sr_bits::Z, IlExpr::Not(result.clone().boxed()));
    // N = MSB
    out.set_flag(
        sr_bits::N,
        IlExpr::And(result.boxed(), IlExpr::Const(0x8000).boxed()),
    );
}

fn emit_nzc_flags(out: &mut LiftedInsn, result: IlExpr, carry: IlExpr) {
    emit_nz_flags(out, result);
    out.set_flag(sr_bits::C, carry);
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::decode_insn;

    fn lift(bytes: &[u8]) -> LiftedInsn {
        let insn = decode_insn(bytes, 0x4000).expect("decode failed");
        Msp430Lifter::new().lift_insn(&insn)
    }

    // ── Jumps ─────────────────────────────────────────────────────────────────

    #[test]
    fn jmp_produces_jump_stmt() {
        let li = lift(&[0x00, 0x3C]); // JMP +0 → 0x4002
        assert!(li.stmts.iter().any(|s| matches!(s, IlStmt::Jump(0x4002))));
    }

    #[test]
    fn jeq_produces_branch_stmt() {
        let li = lift(&[0x00, 0x24]); // JEQ target=0x4002
        assert!(li.stmts.iter().any(|s| matches!(s, IlStmt::Branch { .. })));
    }

    #[test]
    fn jne_condition_is_not_z() {
        let li = lift(&[0x00, 0x20]); // JNE +0 → 0x4002
        let branch = li
            .stmts
            .iter()
            .find_map(|s| {
                if let IlStmt::Branch { cond, .. } = s {
                    Some(cond.clone())
                } else {
                    None
                }
            })
            .expect("no branch");
        assert!(matches!(branch, IlExpr::Not(_)));
    }

    // ── Format II ─────────────────────────────────────────────────────────────

    #[test]
    fn push_emits_store() {
        let li = lift(&[0x04, 0x12]); // PUSH.W R4
        assert!(li.stmts.iter().any(|s| matches!(s, IlStmt::Store { .. })));
    }

    #[test]
    fn call_emits_call() {
        let li = lift(&[0xB0, 0x12, 0x00, 0x44]); // CALL #0x4400
        assert!(li.stmts.iter().any(|s| matches!(s, IlStmt::Call(_))));
    }

    #[test]
    fn reti_emits_ret() {
        let li = lift(&[0x00, 0x13]); // RETI
        assert!(li.stmts.iter().any(|s| matches!(s, IlStmt::Ret)));
    }

    #[test]
    fn rrc_emits_reg_set_and_carry() {
        let li = lift(&[0x04, 0x10]); // RRC.W R4
        // Should set R4 and update carry flag.
        assert!(
            li.stmts
                .iter()
                .any(|s| matches!(s, IlStmt::SetReg { reg: 4, .. }))
        );
        assert!(
            li.stmts
                .iter()
                .any(|s| matches!(s, IlStmt::SetFlag { mask, .. } if *mask == sr_bits::C))
        );
    }

    #[test]
    fn swpb_emits_set_reg_no_flags() {
        let li = lift(&[0x84, 0x10]); // SWPB R4
        assert!(
            li.stmts
                .iter()
                .any(|s| matches!(s, IlStmt::SetReg { reg: 4, .. }))
        );
        // No flag updates expected from SWPB.
        assert!(!li.stmts.iter().any(|s| matches!(s, IlStmt::SetFlag { .. })));
    }

    // ── Format I ──────────────────────────────────────────────────────────────

    #[test]
    fn mov_reg_reg_single_setreg() {
        let li = lift(&[0x04, 0x45]); // MOV.W R4, R5
        let setreg_count = li
            .stmts
            .iter()
            .filter(|s| matches!(s, IlStmt::SetReg { .. }))
            .count();
        assert_eq!(setreg_count, 1);
    }

    #[test]
    fn add_emits_flags() {
        let li = lift(&[0x04, 0x55]); // ADD.W R4, R5
        assert!(
            li.stmts
                .iter()
                .any(|s| matches!(s, IlStmt::SetFlag { mask, .. } if *mask == sr_bits::C))
        );
        assert!(
            li.stmts
                .iter()
                .any(|s| matches!(s, IlStmt::SetFlag { mask, .. } if *mask == sr_bits::V))
        );
        assert!(
            li.stmts
                .iter()
                .any(|s| matches!(s, IlStmt::SetFlag { mask, .. } if *mask == sr_bits::Z))
        );
        assert!(
            li.stmts
                .iter()
                .any(|s| matches!(s, IlStmt::SetFlag { mask, .. } if *mask == sr_bits::N))
        );
    }

    #[test]
    fn cmp_no_setreg_only_flags() {
        let li = lift(&[0x04, 0x95]); // CMP.W R4, R5
        // CMP discards result — no SetReg for R5.
        assert!(
            !li.stmts
                .iter()
                .any(|s| matches!(s, IlStmt::SetReg { reg: 5, .. }))
        );
        assert!(li.stmts.iter().any(|s| matches!(s, IlStmt::SetFlag { .. })));
    }

    #[test]
    fn bic_no_flags() {
        let li = lift(&[0x04, 0xC5]); // BIC.W R4, R5
        assert!(!li.stmts.iter().any(|s| matches!(s, IlStmt::SetFlag { .. })));
    }

    #[test]
    fn bis_no_flags() {
        let li = lift(&[0x04, 0xD5]); // BIS.W R4, R5
        assert!(!li.stmts.iter().any(|s| matches!(s, IlStmt::SetFlag { .. })));
    }

    #[test]
    fn xor_emits_flags() {
        let li = lift(&[0x04, 0xE5]); // XOR.W R4, R5
        assert!(li.stmts.iter().any(|s| matches!(s, IlStmt::SetFlag { .. })));
    }

    // ── Emulated ──────────────────────────────────────────────────────────────

    #[test]
    fn ret_emits_ret_stmt() {
        let li = lift(&[0x30, 0x41]); // MOV @SP+, PC = RET
        assert!(li.stmts.iter().any(|s| matches!(s, IlStmt::Ret)));
    }

    #[test]
    fn nop_emits_nop() {
        let li = lift(&[0x04, 0x44]); // MOV R4, R4 = NOP
        assert!(li.stmts.iter().any(|s| matches!(s, IlStmt::Nop)));
    }

    // ── IlWidth helpers ───────────────────────────────────────────────────────

    #[test]
    fn il_width_byte() {
        assert_eq!(IlWidth::Byte.bytes(), 1);
        assert_eq!(IlWidth::Byte.mask(), 0xFF);
        assert_eq!(IlWidth::Byte.sign_bit(), 0x80);
    }

    #[test]
    fn il_width_word() {
        assert_eq!(IlWidth::Word.bytes(), 2);
        assert_eq!(IlWidth::Word.mask(), 0xFFFF);
        assert_eq!(IlWidth::Word.sign_bit(), 0x8000);
    }

    #[test]
    fn il_width_from_bool() {
        assert_eq!(IlWidth::from(true), IlWidth::Byte);
        assert_eq!(IlWidth::from(false), IlWidth::Word);
    }

    // ── lift_all ──────────────────────────────────────────────────────────────

    #[test]
    fn lift_all_two_instrs() {
        use crate::decoder::decode_all;
        let code = [0x04u8, 0x45, 0x00, 0x3C]; // MOV + JMP
        let insns = decode_all(&code, 0x4000);
        let lifted = Msp430Lifter::new().lift_all(&insns);
        assert_eq!(lifted.len(), 2);
        assert_eq!(lifted[0].addr, 0x4000);
        assert_eq!(lifted[1].addr, 0x4002);
    }
}
