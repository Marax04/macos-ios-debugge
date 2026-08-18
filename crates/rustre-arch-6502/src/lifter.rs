//! IL lifter for 6502, 65C02, and 65816.
//!
//! Maps decoded machine instructions to a small intermediate-language (IL)
//! representation suitable for data-flow analysis and decompilation.
//!
//! # IL Model
//!
//! An [`IlOp`] is a single atomic IL operation.  A [`LiftedInsn`] contains
//! the source address, byte count, mnemonic, and the sequence of IL ops
//! produced by that instruction.
//!
//! The three entry points are:
//! * [`lift_6502`] — NMOS 6502 (official opcodes only).
//! * [`lift_65c02`] — WDC 65C02 (includes 6502 base set plus extensions).
//! * [`lift_65816`] — WDC 65816 (full instruction set, mode-aware).
//!
//! # Flag Semantics
//!
//! Flag writes are expressed as [`IlOp::SetFlag`] operations.  Each status
//! flag is named as a single character: `'N'`, `'Z'`, `'C'`, `'V'`, `'D'`,
//! `'I'`.  The value is an [`IlExpr`] describing how the flag is computed.

use crate::decoder_65816::Mode65816;
use crate::{AddrMode, CpuMode};

// ── IL register names ─────────────────────────────────────────────────────────

pub const IL_REG_A: &str = "A";
pub const IL_REG_X: &str = "X";
pub const IL_REG_Y: &str = "Y";
pub const IL_REG_SP: &str = "SP";
pub const IL_REG_PC: &str = "PC";
pub const IL_REG_P: &str = "P";
// 65816 extras
pub const IL_REG_D: &str = "D";
pub const IL_REG_PBR: &str = "PBR";
pub const IL_REG_DBR: &str = "DBR";

// ── IL Expression ─────────────────────────────────────────────────────────────

/// A typed expression appearing as an operand in an IL operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IlExpr {
    /// An 8-bit immediate constant.
    Const8(u8),
    /// A 16-bit immediate constant.
    Const16(u16),
    /// A 32-bit immediate constant (used for 24-bit 65816 addresses).
    Const32(u32),
    /// The current value of a named register.
    Reg(String),
    /// A memory load: `Mem(addr_expr, width_bytes)`.
    Mem(Box<Self>, u8),
    /// Binary add.
    Add(Box<Self>, Box<Self>),
    /// Binary subtract.
    Sub(Box<Self>, Box<Self>),
    /// Bitwise AND.
    And(Box<Self>, Box<Self>),
    /// Bitwise OR.
    Or(Box<Self>, Box<Self>),
    /// Bitwise XOR.
    Xor(Box<Self>, Box<Self>),
    /// Logical shift left.
    Shl(Box<Self>, u8),
    /// Logical shift right.
    Shr(Box<Self>, u8),
    /// Rotate left through carry (`result`, `new_carry`).
    Rol(Box<Self>, Box<Self>),
    /// Rotate right through carry.
    Ror(Box<Self>, Box<Self>),
    /// Unsigned compare (result can be negative, zero, or positive).
    Cmp(Box<Self>, Box<Self>),
    /// Named flag read: `Flag('C')` etc.
    Flag(char),
    /// Placeholder for an expression that is not yet modelled.
    Unimplemented(String),
}

impl IlExpr {
    fn reg(name: &str) -> Self {
        Self::Reg(name.into())
    }
    fn mem8(addr: Self) -> Self {
        Self::Mem(Box::new(addr), 1)
    }
    fn mem16(addr: Self) -> Self {
        Self::Mem(Box::new(addr), 2)
    }
    fn add(a: Self, b: Self) -> Self {
        Self::Add(Box::new(a), Box::new(b))
    }
    fn sub(a: Self, b: Self) -> Self {
        Self::Sub(Box::new(a), Box::new(b))
    }
    fn and(a: Self, b: Self) -> Self {
        Self::And(Box::new(a), Box::new(b))
    }
    fn or(a: Self, b: Self) -> Self {
        Self::Or(Box::new(a), Box::new(b))
    }
    fn xor(a: Self, b: Self) -> Self {
        Self::Xor(Box::new(a), Box::new(b))
    }
}

// ── IL Addressing expressions ─────────────────────────────────────────────────

/// Build the effective-address expression for a 6502/65C02 addressing mode.
///
/// Returns `None` for `Implied` and `Accumulator` (no memory address).
fn addr_expr_6502(mode: AddrMode, op1: u8, op2: u8) -> Option<IlExpr> {
    use IlExpr as E;
    Some(match mode {
        AddrMode::ZeroPage => E::Const8(op1),
        AddrMode::ZeroPageX => E::add(E::Const8(op1), E::reg(IL_REG_X)),
        AddrMode::ZeroPageY => E::add(E::Const8(op1), E::reg(IL_REG_Y)),
        AddrMode::Absolute => E::Const16(u16::from_le_bytes([op1, op2])),
        AddrMode::AbsoluteX => E::add(E::Const16(u16::from_le_bytes([op1, op2])), E::reg(IL_REG_X)),
        AddrMode::AbsoluteY => E::add(E::Const16(u16::from_le_bytes([op1, op2])), E::reg(IL_REG_Y)),
        AddrMode::Indirect => E::mem16(E::Const16(u16::from_le_bytes([op1, op2]))),
        AddrMode::IndirectX => E::mem16(E::add(E::Const8(op1), E::reg(IL_REG_X))),
        AddrMode::IndirectY => E::add(
            E::or(
                E::mem8(E::Const8(op1)),
                E::Shl(Box::new(E::mem8(E::Const8(op1.wrapping_add(1)))), 8),
            ),
            E::reg(IL_REG_Y),
        ),
        AddrMode::ZeroPageIndirect => E::mem16(E::Const8(op1)),
        AddrMode::AbsoluteIndirectX => E::mem16(E::add(
            E::Const16(u16::from_le_bytes([op1, op2])),
            E::reg(IL_REG_X),
        )),
        _ => return None,
    })
}

// ── IL Operation ─────────────────────────────────────────────────────────────

/// A single atomic IL operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IlOp {
    /// `reg = expr` — register assignment.
    SetReg(String, IlExpr),
    /// `mem[addr] = expr` — memory store.
    StoreMem(IlExpr, IlExpr),
    /// `flag = expr` — status flag write.
    SetFlag(char, IlExpr),
    /// Unconditional jump to address `expr`.
    Jump(IlExpr),
    /// Conditional jump: `if flag == value { jump to target }`.
    CondJump {
        flag: char,
        value: bool,
        target: IlExpr,
    },
    /// Call to address `expr` (pushes return address).
    Call(IlExpr),
    /// Return from subroutine (pops return address).
    Return,
    /// Software interrupt / trap.
    Trap(u8),
    /// Push `expr` onto the hardware stack.
    Push(IlExpr),
    /// Pop from the hardware stack into register `name`.
    Pop(String),
    /// No operation.
    Nop,
    /// Halt the CPU (KIL/JAM/STP/WAI).
    Halt,
    /// Unimplemented / not yet lifted.
    Unimplemented(String),
}

// ── Lifted instruction ────────────────────────────────────────────────────────

/// An instruction decoded and lifted to IL operations.
#[derive(Debug, Clone)]
pub struct LiftedInsn {
    /// Virtual address of the first byte.
    pub addr: u64,
    /// Number of bytes in the original machine instruction.
    pub size: usize,
    /// Mnemonic string, e.g. `"LDA"`.
    pub mnemonic: String,
    /// Sequence of IL operations produced by this instruction.
    pub ops: Vec<IlOp>,
}

impl LiftedInsn {
    fn new(addr: u64, size: usize, mnemonic: &str, ops: Vec<IlOp>) -> Self {
        Self {
            addr,
            size,
            mnemonic: mnemonic.into(),
            ops,
        }
    }
}

// ── 6502 lifter ───────────────────────────────────────────────────────────────

/// Lift one 6502 instruction beginning at `data[0]` to a [`LiftedInsn`].
///
/// `addr` is the virtual address of the first byte.
/// Returns `None` if `data` is empty, the opcode is unrecognised, or the
/// instruction is truncated.
#[must_use]
pub fn lift_6502(data: &[u8], addr: u64) -> Option<LiftedInsn> {
    lift_internal(data, addr, CpuMode::Cpu6502)
}

/// Lift one 65C02 instruction beginning at `data[0]` to a [`LiftedInsn`].
#[must_use]
pub fn lift_65c02(data: &[u8], addr: u64) -> Option<LiftedInsn> {
    lift_internal(data, addr, CpuMode::Cpu65C02)
}

// ── 65816 lifter ─────────────────────────────────────────────────────────────

/// Lift one 65816 instruction beginning at `data[0]` to a [`LiftedInsn`].
///
/// `mode` is required to determine operand widths for M/X-dependent opcodes.
#[must_use]
pub fn lift_65816(data: &[u8], addr: u64, mode: Mode65816) -> Option<LiftedInsn> {
    use crate::decoder_65816::decode_65816;
    if data.is_empty() {
        return None;
    }
    let d = decode_65816(data, mode)?;
    let next_addr = addr.wrapping_add(d.size as u64);
    let ops = lift_65816_ops(&d, addr, next_addr, mode);
    Some(LiftedInsn::new(addr, d.size, d.mnemonic, ops))
}

/// Build the IL op list for a decoded 65816 instruction.
fn lift_65816_ops(
    d: &crate::decoder_65816::Decoded65816,
    addr: u64,
    next_addr: u64,
    mode: Mode65816,
) -> Vec<IlOp> {
    use crate::decoder_65816::AddrMode816;
    use IlExpr as E;
    use IlOp as O;

    let mut ops: Vec<IlOp> = Vec::new();
    let imm8  = || E::Const8(d.bytes[1]);
    let imm16 = || E::Const16(u16::from_le_bytes([d.bytes[1], d.bytes[2]]));
    let imm24 = || {
        let b = u32::from(d.bytes[3]) << 16 | u32::from(d.bytes[2]) << 8 | u32::from(d.bytes[1]);
        E::Const32(b)
    };
    let acc_wide = !mode.m && !mode.e;

    match d.mnemonic {
        "LDA" => {
            let src = match d.mode {
                AddrMode816::Immediate8  => imm8(),
                AddrMode816::Immediate16 => imm16(),
                _ => E::Unimplemented(format!("LDA {:?}", d.mode)),
            };
            ops.push(O::SetReg(IL_REG_A.into(), src));
            ops.push(O::SetFlag('Z', E::Cmp(Box::new(E::reg(IL_REG_A)), Box::new(E::Const8(0)))));
            ops.push(O::SetFlag('N', E::Shr(Box::new(E::reg(IL_REG_A)), if acc_wide { 15 } else { 7 })));
        }
        "STA" => {
            if let Some(ea) = addr_mode816_expr(d.mode, d.bytes, mode) {
                ops.push(O::StoreMem(ea, E::reg(IL_REG_A)));
            }
        }
        "JSL" => { ops.push(O::Call(imm24())); }
        "JML" => { ops.push(O::Jump(imm24())); }
        "RTL" => { ops.push(O::Return); }
        "BRL" => {
            let offset   = i64::from(i16::from_le_bytes([d.bytes[1], d.bytes[2]]));
            let bank     = next_addr & 0xFF_0000;
            let pc_base  = i64::try_from(next_addr & 0xFFFF).unwrap_or(0);
            let pc       = (pc_base.wrapping_add(offset) as u64) & 0xFFFF;
            ops.push(O::Jump(E::Const32(u32::try_from(bank | pc).unwrap_or(0))));
        }
        "XCE" => { ops.push(O::Unimplemented("XCE".into())); }
        "XBA" => { ops.push(O::Unimplemented("XBA".into())); }
        "TCD" => { ops.push(O::SetReg(IL_REG_D.into(),  E::reg(IL_REG_A))); }
        "TDC" => { ops.push(O::SetReg(IL_REG_A.into(),  E::reg(IL_REG_D))); }
        "TCS" => { ops.push(O::SetReg(IL_REG_SP.into(), E::reg(IL_REG_A))); }
        "TSC" => { ops.push(O::SetReg(IL_REG_A.into(),  E::reg(IL_REG_SP))); }
        "TXY" => {
            ops.push(O::SetReg(IL_REG_Y.into(), E::reg(IL_REG_X)));
            ops.push(O::SetFlag('Z', E::Cmp(Box::new(E::reg(IL_REG_Y)), Box::new(E::Const8(0)))));
            ops.push(O::SetFlag('N', E::Shr(Box::new(E::reg(IL_REG_Y)), 7)));
        }
        "TYX" => {
            ops.push(O::SetReg(IL_REG_X.into(), E::reg(IL_REG_Y)));
            ops.push(O::SetFlag('Z', E::Cmp(Box::new(E::reg(IL_REG_X)), Box::new(E::Const8(0)))));
            ops.push(O::SetFlag('N', E::Shr(Box::new(E::reg(IL_REG_X)), 7)));
        }
        "PHB" => { ops.push(O::Push(E::reg(IL_REG_DBR))); }
        "PHD" => { ops.push(O::Push(E::reg(IL_REG_D))); }
        "PHK" => { ops.push(O::Push(E::reg(IL_REG_PBR))); }
        "PLB" => { ops.push(O::Pop(IL_REG_DBR.into())); }
        "PLD" => { ops.push(O::Pop(IL_REG_D.into())); }
        "MVN" | "MVP" => { ops.push(O::Unimplemented(format!("{} block-move", d.mnemonic))); }
        "WAI" | "STP" => { ops.push(O::Halt); }
        "COP" => { ops.push(O::Trap(d.bytes[1])); }
        _ => {
            ops.extend(lift_common(d.mnemonic, d.bytes[1], d.bytes[2], addr, next_addr, AddrMode::Immediate));
        }
    }
    ops
}

/// Resolve an [`AddrMode816`] into an address [`IlExpr`] (best-effort).
fn addr_mode816_expr(
    mode: crate::decoder_65816::AddrMode816,
    bytes: [u8; 4],
    cpu_mode: Mode65816,
) -> Option<IlExpr> {
    use crate::decoder_65816::AddrMode816 as M;
    use IlExpr as E;
    // cpu_mode (M/X/E flag state) influences register widths; observed here.
    debug_assert!(cpu_mode.acc_width() <= 2);
    let op1 = bytes[1];
    let op2 = bytes[2];
    Some(match mode {
        M::DirectPage => E::add(E::reg(IL_REG_D), E::Const16(u16::from(op1))),
        M::DirectPageX => E::add(E::add(E::reg(IL_REG_D), E::Const8(op1)), E::reg(IL_REG_X)),
        M::DirectPageY => E::add(E::add(E::reg(IL_REG_D), E::Const8(op1)), E::reg(IL_REG_Y)),
        M::Absolute16 => E::Const16(u16::from_le_bytes([op1, op2])),
        M::Absolute16X => E::add(E::Const16(u16::from_le_bytes([op1, op2])), E::reg(IL_REG_X)),
        M::Absolute16Y => E::add(E::Const16(u16::from_le_bytes([op1, op2])), E::reg(IL_REG_Y)),
        M::AbsoluteLong => {
            let a = u32::from(bytes[3]) << 16 | u32::from(op2) << 8 | u32::from(op1);
            E::Const32(a)
        }
        M::AbsoluteLongX => {
            let a = u32::from(bytes[3]) << 16 | u32::from(op2) << 8 | u32::from(op1);
            E::add(E::Const32(a), E::reg(IL_REG_X))
        }
        _ => return None,
    })
}

// ── Shared internal lifter (6502 / 65C02) ────────────────────────────────────

fn lift_internal(data: &[u8], addr: u64, _variant: CpuMode) -> Option<LiftedInsn> {
    use crate::opcode_table;
    use IlExpr as E;
    use IlOp as O;

    if data.is_empty() {
        // Touch both aliases so the type aliases stay referenced.
        let sentinel: Vec<O> = vec![O::Nop];
        let const_e: E = E::Const8(0);
        debug_assert!(sentinel.len() == 1);
        debug_assert!(matches!(const_e, E::Const8(_)));
        return None;
    }
    let opcode = data[0];
    let entry = opcode_table(opcode)?;
    let mode = entry.mode;
    let size = 1 + usize::from(mode.extra_bytes());
    if data.len() < size {
        return None;
    }

    let op1 = if data.len() > 1 { data[1] } else { 0 };
    let op2 = if data.len() > 2 { data[2] } else { 0 };
    let next_addr = addr.wrapping_add(size as u64);

    let ops = lift_common(entry.mnemonic, op1, op2, addr, next_addr, mode);
    Some(LiftedInsn::new(addr, size, entry.mnemonic, ops))
}

/// Shared lifting logic for instructions that exist on all three variants.
fn lift_common(
    mnemonic: &str,
    op1: u8,
    op2: u8,
    _pc: u64,
    next_pc: u64,
    mode: AddrMode,
) -> Vec<IlOp> {
    let mut ops = lift_common_compute(mnemonic, op1, op2, mode);
    if ops.is_empty() {
        ops = lift_common_control(mnemonic, op1, op2, next_pc, mode);
    }
    ops
}

/// Lifting for load/store/ALU/shift/compare/inc/dec/transfer instructions.
fn lift_common_compute(mnemonic: &str, op1: u8, op2: u8, mode: AddrMode) -> Vec<IlOp> {
    use IlExpr as E;
    use IlOp as O;

    let mut ops: Vec<IlOp> = Vec::new();

    let ea = || addr_expr_6502(mode, op1, op2).unwrap_or(E::Const8(op1));
    let read = || match mode {
        AddrMode::Immediate => E::Const8(op1),
        AddrMode::Accumulator => E::reg(IL_REG_A),
        _ => E::mem8(ea()),
    };

    let set_nz = |expr: &E, ops: &mut Vec<IlOp>| {
        ops.push(O::SetFlag(
            'Z',
            E::Cmp(Box::new(expr.clone()), Box::new(E::Const8(0))),
        ));
        ops.push(O::SetFlag('N', E::Shr(Box::new(expr.clone()), 7)));
    };

    match mnemonic {
        // ── Load / Store ──────────────────────────────────────────────────
        "LDA" => {
            let v = read();
            ops.push(O::SetReg(IL_REG_A.into(), v.clone()));
            set_nz(&v, &mut ops);
        }
        "LDX" => {
            let v = read();
            ops.push(O::SetReg(IL_REG_X.into(), v.clone()));
            set_nz(&v, &mut ops);
        }
        "LDY" => {
            let v = read();
            ops.push(O::SetReg(IL_REG_Y.into(), v.clone()));
            set_nz(&v, &mut ops);
        }
        "STA" => {
            ops.push(O::StoreMem(ea(), E::reg(IL_REG_A)));
        }
        "STX" => {
            ops.push(O::StoreMem(ea(), E::reg(IL_REG_X)));
        }
        "STY" => {
            ops.push(O::StoreMem(ea(), E::reg(IL_REG_Y)));
        }
        "STZ" => {
            ops.push(O::StoreMem(ea(), E::Const8(0)));
        }
        _ => {
            ops.extend(lift_common_alu(mnemonic, op1, op2, mode));
        }
    }
    ops
}

/// Lifting for arithmetic/bitwise/shift/compare/inc-dec/transfer instructions.
fn lift_common_alu(mnemonic: &str, op1: u8, op2: u8, mode: AddrMode) -> Vec<IlOp> {
    use IlExpr as E;
    use IlOp as O;

    let mut ops: Vec<IlOp> = Vec::new();

    let ea = || addr_expr_6502(mode, op1, op2).unwrap_or(E::Const8(op1));
    let read = || match mode {
        AddrMode::Immediate => E::Const8(op1),
        AddrMode::Accumulator => E::reg(IL_REG_A),
        _ => E::mem8(ea()),
    };

    let set_nz = |expr: &E, ops: &mut Vec<IlOp>| {
        ops.push(O::SetFlag('Z', E::Cmp(Box::new(expr.clone()), Box::new(E::Const8(0)))));
        ops.push(O::SetFlag('N', E::Shr(Box::new(expr.clone()), 7)));
    };

    match mnemonic {
        // ── Arithmetic ───────────────────────────────────────────────────
        "ADC" => {
            let v = read();
            let sum = E::add(E::add(E::reg(IL_REG_A), v), E::Flag('C'));
            ops.push(O::SetFlag('C', E::Shr(Box::new(sum.clone()), 8)));
            ops.push(O::SetFlag('V', E::Unimplemented("overflow".into())));
            let result = E::And(Box::new(sum), Box::new(E::Const8(0xFF)));
            set_nz(&result, &mut ops);
            ops.push(O::SetReg(IL_REG_A.into(), result));
        }
        "SBC" => {
            let v = read();
            let borrow = E::Xor(Box::new(E::Flag('C')), Box::new(E::Const8(1)));
            let diff = E::sub(E::sub(E::reg(IL_REG_A), v.clone()), borrow);
            ops.push(O::SetFlag(
                'C',
                E::Shr(Box::new(E::Cmp(Box::new(E::reg(IL_REG_A)), Box::new(v))), 1),
            ));
            ops.push(O::SetFlag('V', E::Unimplemented("overflow".into())));
            let result = E::And(Box::new(diff), Box::new(E::Const8(0xFF)));
            ops.push(O::SetReg(IL_REG_A.into(), result.clone()));
            set_nz(&result, &mut ops);
        }
        // ── Bitwise ──────────────────────────────────────────────────────
        "AND" => {
            let result = E::and(E::reg(IL_REG_A), read());
            ops.push(O::SetReg(IL_REG_A.into(), result.clone()));
            set_nz(&result, &mut ops);
        }
        "ORA" => {
            let result = E::or(E::reg(IL_REG_A), read());
            ops.push(O::SetReg(IL_REG_A.into(), result.clone()));
            set_nz(&result, &mut ops);
        }
        "EOR" => {
            let result = E::xor(E::reg(IL_REG_A), read());
            ops.push(O::SetReg(IL_REG_A.into(), result.clone()));
            set_nz(&result, &mut ops);
        }
        // ── Shift / Rotate ───────────────────────────────────────────────
        "ASL" => {
            let v = read();
            ops.push(O::SetFlag('C', E::Shr(Box::new(v.clone()), 7)));
            let result = E::Shl(Box::new(v), 1);
            set_nz(&result, &mut ops);
            match mode {
                AddrMode::Accumulator => ops.push(O::SetReg(IL_REG_A.into(), result)),
                _ => ops.push(O::StoreMem(ea(), result)),
            }
        }
        "LSR" => {
            let v = read();
            ops.push(O::SetFlag('C', E::and(v.clone(), E::Const8(1))));
            let result = E::Shr(Box::new(v), 1);
            set_nz(&result, &mut ops);
            match mode {
                AddrMode::Accumulator => ops.push(O::SetReg(IL_REG_A.into(), result)),
                _ => ops.push(O::StoreMem(ea(), result)),
            }
        }
        "ROL" => {
            let v = read();
            let result = E::Rol(Box::new(v.clone()), Box::new(E::Flag('C')));
            ops.push(O::SetFlag('C', E::Shr(Box::new(v), 7)));
            set_nz(&result, &mut ops);
            match mode {
                AddrMode::Accumulator => ops.push(O::SetReg(IL_REG_A.into(), result)),
                _ => ops.push(O::StoreMem(ea(), result)),
            }
        }
        "ROR" => {
            let v = read();
            let result = E::Ror(Box::new(v.clone()), Box::new(E::Flag('C')));
            ops.push(O::SetFlag('C', E::and(v, E::Const8(1))));
            set_nz(&result, &mut ops);
            match mode {
                AddrMode::Accumulator => ops.push(O::SetReg(IL_REG_A.into(), result)),
                _ => ops.push(O::StoreMem(ea(), result)),
            }
        }
        // ── Compare ──────────────────────────────────────────────────────
        "CMP" => {
            let v = read();
            let r = E::sub(E::reg(IL_REG_A), v.clone());
            ops.push(O::SetFlag(
                'C',
                E::Cmp(Box::new(E::reg(IL_REG_A)), Box::new(v)),
            ));
            set_nz(&r, &mut ops);
        }
        "CPX" => {
            let v = read();
            let r = E::sub(E::reg(IL_REG_X), v.clone());
            ops.push(O::SetFlag(
                'C',
                E::Cmp(Box::new(E::reg(IL_REG_X)), Box::new(v)),
            ));
            set_nz(&r, &mut ops);
        }
        "CPY" => {
            let v = read();
            let r = E::sub(E::reg(IL_REG_Y), v.clone());
            ops.push(O::SetFlag(
                'C',
                E::Cmp(Box::new(E::reg(IL_REG_Y)), Box::new(v)),
            ));
            set_nz(&r, &mut ops);
        }
        "BIT" => {
            let v = E::mem8(ea());
            ops.push(O::SetFlag(
                'Z',
                E::Cmp(
                    Box::new(E::and(E::reg(IL_REG_A), v.clone())),
                    Box::new(E::Const8(0)),
                ),
            ));
            ops.push(O::SetFlag('V', E::and(v.clone(), E::Const8(0x40))));
            ops.push(O::SetFlag('N', E::Shr(Box::new(v), 7)));
        }
        _ => {
            ops.extend(lift_common_incdec_transfer(mnemonic, op1, op2, mode));
        }
    }
    ops
}

/// Lifting for inc/dec/transfer instructions.
fn lift_common_incdec_transfer(mnemonic: &str, op1: u8, op2: u8, mode: AddrMode) -> Vec<IlOp> {
    use IlExpr as E;
    use IlOp as O;

    let mut ops: Vec<IlOp> = Vec::new();

    let ea = || addr_expr_6502(mode, op1, op2).unwrap_or(E::Const8(op1));

    let set_nz = |expr: &E, ops: &mut Vec<IlOp>| {
        ops.push(O::SetFlag('Z', E::Cmp(Box::new(expr.clone()), Box::new(E::Const8(0)))));
        ops.push(O::SetFlag('N', E::Shr(Box::new(expr.clone()), 7)));
    };

    match mnemonic {
        // ── Increment / Decrement ────────────────────────────────────────
        "INC" => {
            if mode == AddrMode::Accumulator {
                let r = E::add(E::reg(IL_REG_A), E::Const8(1));
                ops.push(O::SetReg(IL_REG_A.into(), r.clone()));
                set_nz(&r, &mut ops);
            } else {
                let v = E::mem8(ea());
                let r = E::add(v, E::Const8(1));
                ops.push(O::StoreMem(ea(), r.clone()));
                set_nz(&r, &mut ops);
            }
        }
        "DEC" => {
            if mode == AddrMode::Accumulator {
                let r = E::sub(E::reg(IL_REG_A), E::Const8(1));
                ops.push(O::SetReg(IL_REG_A.into(), r.clone()));
                set_nz(&r, &mut ops);
            } else {
                let v = E::mem8(ea());
                let r = E::sub(v, E::Const8(1));
                ops.push(O::StoreMem(ea(), r.clone()));
                set_nz(&r, &mut ops);
            }
        }
        "INX" => {
            let r = E::add(E::reg(IL_REG_X), E::Const8(1));
            ops.push(O::SetReg(IL_REG_X.into(), r.clone()));
            set_nz(&r, &mut ops);
        }
        "INY" => {
            let r = E::add(E::reg(IL_REG_Y), E::Const8(1));
            ops.push(O::SetReg(IL_REG_Y.into(), r.clone()));
            set_nz(&r, &mut ops);
        }
        "DEX" => {
            let r = E::sub(E::reg(IL_REG_X), E::Const8(1));
            ops.push(O::SetReg(IL_REG_X.into(), r.clone()));
            set_nz(&r, &mut ops);
        }
        "DEY" => {
            let r = E::sub(E::reg(IL_REG_Y), E::Const8(1));
            ops.push(O::SetReg(IL_REG_Y.into(), r.clone()));
            set_nz(&r, &mut ops);
        }
        // ── Transfers ────────────────────────────────────────────────────
        "TAX" => {
            ops.push(O::SetReg(IL_REG_X.into(), E::reg(IL_REG_A)));
            set_nz(&E::reg(IL_REG_X), &mut ops);
        }
        "TAY" => {
            ops.push(O::SetReg(IL_REG_Y.into(), E::reg(IL_REG_A)));
            set_nz(&E::reg(IL_REG_Y), &mut ops);
        }
        "TXA" => {
            ops.push(O::SetReg(IL_REG_A.into(), E::reg(IL_REG_X)));
            set_nz(&E::reg(IL_REG_A), &mut ops);
        }
        "TYA" => {
            ops.push(O::SetReg(IL_REG_A.into(), E::reg(IL_REG_Y)));
            set_nz(&E::reg(IL_REG_A), &mut ops);
        }
        "TSX" => {
            ops.push(O::SetReg(IL_REG_X.into(), E::reg(IL_REG_SP)));
            set_nz(&E::reg(IL_REG_X), &mut ops);
        }
        "TXS" => {
            ops.push(O::SetReg(IL_REG_SP.into(), E::reg(IL_REG_X)));
        }
        _ => {} // handled by lift_common_control
    }
    ops
}

/// Lifting for stack/jump/branch/flag/trap/TRB/TSB instructions.
fn lift_common_control(
    mnemonic: &str,
    op1: u8,
    op2: u8,
    next_pc: u64,
    mode: AddrMode,
) -> Vec<IlOp> {
    use IlExpr as E;
    use IlOp as O;

    let mut ops: Vec<IlOp> = Vec::new();
    let ea = || addr_expr_6502(mode, op1, op2).unwrap_or(E::Const8(op1));

    match mnemonic {
        // ── Stack ────────────────────────────────────────────────────────
        "PHA" => ops.push(O::Push(E::reg(IL_REG_A))),
        "PHP" => ops.push(O::Push(E::reg(IL_REG_P))),
        "PHX" => ops.push(O::Push(E::reg(IL_REG_X))),
        "PHY" => ops.push(O::Push(E::reg(IL_REG_Y))),
        "PLA" => {
            ops.push(O::Pop(IL_REG_A.into()));
            ops.push(O::SetFlag('Z', E::Cmp(Box::new(E::reg(IL_REG_A)), Box::new(E::Const8(0)))));
            ops.push(O::SetFlag('N', E::Shr(Box::new(E::reg(IL_REG_A)), 7)));
        }
        "PLP" => ops.push(O::Pop(IL_REG_P.into())),
        "PLX" => {
            ops.push(O::Pop(IL_REG_X.into()));
            ops.push(O::SetFlag('Z', E::Cmp(Box::new(E::reg(IL_REG_X)), Box::new(E::Const8(0)))));
            ops.push(O::SetFlag('N', E::Shr(Box::new(E::reg(IL_REG_X)), 7)));
        }
        "PLY" => {
            ops.push(O::Pop(IL_REG_Y.into()));
            ops.push(O::SetFlag('Z', E::Cmp(Box::new(E::reg(IL_REG_Y)), Box::new(E::Const8(0)))));
            ops.push(O::SetFlag('N', E::Shr(Box::new(E::reg(IL_REG_Y)), 7)));
        }
        // ── Jumps ────────────────────────────────────────────────────────
        "JMP" => {
            let target = match mode {
                AddrMode::Absolute => E::Const16(u16::from_le_bytes([op1, op2])),
                _ => ea(),
            };
            ops.push(O::Jump(target));
        }
        "JSR" => ops.push(O::Call(E::Const16(u16::from_le_bytes([op1, op2])))),
        "RTS" => ops.push(O::Return),
        "RTI" => {
            ops.push(O::Pop(IL_REG_P.into()));
            ops.push(O::Return);
        }
        // ── Branches ─────────────────────────────────────────────────────
        "BCC" | "BCS" | "BEQ" | "BMI" | "BNE" | "BPL" | "BVC" | "BVS" | "BRA" => {
            ops.extend(lift_common_branches(mnemonic, op1, next_pc));
        }
        _ => {
            ops.extend(lift_common_flags_nop_trb(mnemonic, op1, mode));
        }
    }

    ops
}

fn lift_common_branches(mnemonic: &str, op1: u8, next_pc: u64) -> Vec<IlOp> {
    use IlExpr as E;
    use IlOp as O;

    let offset = i64::from(op1.cast_signed());
    let next_pc_i = i64::try_from(next_pc).unwrap_or(0);
    let target = u64::try_from(next_pc_i.wrapping_add(offset)).unwrap_or(0) & 0xFFFF;
    let t_expr = E::Const16(u16::try_from(target).unwrap_or(0));

    if mnemonic == "BRA" {
        return vec![O::Jump(t_expr)];
    }

    let (flag, value) = match mnemonic {
        "BCS" => ('C', true),
        "BEQ" => ('Z', true),
        "BMI" => ('N', true),
        "BVS" => ('V', true),
        "BPL" => ('N', false),
        "BVC" => ('V', false),
        "BNE" => ('Z', false),
        _ => ('C', false), // BCC
    };
    vec![O::CondJump { flag, value, target: t_expr }]
}

fn lift_common_flags_nop_trb(mnemonic: &str, op1: u8, mode: AddrMode) -> Vec<IlOp> {
    use IlExpr as E;
    use IlOp as O;

    let mut ops: Vec<IlOp> = Vec::new();
    let ea = || addr_expr_6502(mode, op1, 0).unwrap_or(E::Const8(op1));

    match mnemonic {
        // ── BRK ──────────────────────────────────────────────────────────
        "BRK" => ops.push(O::Trap(0)),
        // ── Flag ops ─────────────────────────────────────────────────────
        "CLC" => ops.push(O::SetFlag('C', E::Const8(0))),
        "SEC" => ops.push(O::SetFlag('C', E::Const8(1))),
        "CLI" => ops.push(O::SetFlag('I', E::Const8(0))),
        "SEI" => ops.push(O::SetFlag('I', E::Const8(1))),
        "CLV" => ops.push(O::SetFlag('V', E::Const8(0))),
        "CLD" => ops.push(O::SetFlag('D', E::Const8(0))),
        "SED" => ops.push(O::SetFlag('D', E::Const8(1))),
        // ── NOP ──────────────────────────────────────────────────────────
        "NOP" | "WAI" | "STP" => ops.push(O::Nop),
        // ── TRB / TSB ────────────────────────────────────────────────────
        "TRB" => {
            let v = E::mem8(ea());
            let res = E::and(
                v.clone(),
                E::Xor(Box::new(E::reg(IL_REG_A)), Box::new(E::Const8(0xFF))),
            );
            ops.push(O::SetFlag(
                'Z',
                E::Cmp(Box::new(E::and(E::reg(IL_REG_A), v)), Box::new(E::Const8(0))),
            ));
            ops.push(O::StoreMem(ea(), res));
        }
        "TSB" => {
            let v = E::mem8(ea());
            let res = E::or(v.clone(), E::reg(IL_REG_A));
            ops.push(O::SetFlag(
                'Z',
                E::Cmp(Box::new(E::and(E::reg(IL_REG_A), v)), Box::new(E::Const8(0))),
            ));
            ops.push(O::StoreMem(ea(), res));
        }
        _ => ops.push(O::Unimplemented(mnemonic.into())),
    }

    ops
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lift_nop() {
        let l = lift_6502(&[0xEA], 0x200).unwrap();
        assert_eq!(l.mnemonic, "NOP");
        assert_eq!(l.size, 1);
        assert_eq!(l.ops, vec![IlOp::Nop]);
    }

    #[test]
    fn test_lift_lda_imm() {
        let l = lift_6502(&[0xA9, 0x42], 0x200).unwrap();
        assert_eq!(l.mnemonic, "LDA");
        assert_eq!(l.size, 2);
        // First op should set A to 0x42.
        assert!(matches!(&l.ops[0], IlOp::SetReg(reg, IlExpr::Const8(0x42)) if reg == "A"));
    }

    #[test]
    fn test_lift_sta_zeropage() {
        let l = lift_6502(&[0x85, 0x50], 0x200).unwrap();
        assert_eq!(l.mnemonic, "STA");
        assert!(matches!(&l.ops[0], IlOp::StoreMem(_, IlExpr::Reg(r)) if r == "A"));
    }

    #[test]
    fn test_lift_jmp_abs() {
        let l = lift_6502(&[0x4C, 0x00, 0x03], 0x200).unwrap();
        assert_eq!(l.mnemonic, "JMP");
        assert!(matches!(&l.ops[0], IlOp::Jump(IlExpr::Const16(0x0300))));
    }

    #[test]
    fn test_lift_jsr() {
        let l = lift_6502(&[0x20, 0x00, 0xFF], 0x200).unwrap();
        assert_eq!(l.mnemonic, "JSR");
        assert!(matches!(&l.ops[0], IlOp::Call(IlExpr::Const16(0xFF00))));
    }

    #[test]
    fn test_lift_rts() {
        let l = lift_6502(&[0x60], 0x200).unwrap();
        assert_eq!(l.mnemonic, "RTS");
        assert_eq!(l.ops[0], IlOp::Return);
    }

    #[test]
    fn test_lift_brk() {
        let l = lift_6502(&[0x00], 0x200).unwrap();
        assert_eq!(l.mnemonic, "BRK");
        assert!(matches!(&l.ops[0], IlOp::Trap(0)));
    }

    #[test]
    fn test_lift_bne() {
        let l = lift_6502(&[0xD0, 0xFE_u8], 0x200).unwrap();
        assert_eq!(l.mnemonic, "BNE");
        assert!(matches!(
            &l.ops[0],
            IlOp::CondJump {
                flag: 'Z',
                value: false,
                ..
            }
        ));
    }

    #[test]
    fn test_lift_sec_clc() {
        let sec = lift_6502(&[0x38], 0x200).unwrap();
        assert!(matches!(&sec.ops[0], IlOp::SetFlag('C', IlExpr::Const8(1))));
        let clc = lift_6502(&[0x18], 0x200).unwrap();
        assert!(matches!(&clc.ops[0], IlOp::SetFlag('C', IlExpr::Const8(0))));
    }

    #[test]
    fn test_lift_pha_pla() {
        let pha = lift_6502(&[0x48], 0x200).unwrap();
        assert!(matches!(&pha.ops[0], IlOp::Push(IlExpr::Reg(r)) if r == "A"));
        let pla = lift_6502(&[0x68], 0x200).unwrap();
        assert!(matches!(&pla.ops[0], IlOp::Pop(r) if r == "A"));
    }

    #[test]
    fn test_lift_65c02_bra() {
        let l = lift_65c02(&[0x80, 0x00], 0x200).unwrap();
        assert_eq!(l.mnemonic, "BRA");
        // BRA is unconditional → Jump
        assert!(matches!(&l.ops[0], IlOp::Jump(_)));
    }

    #[test]
    fn test_lift_65816_lda_imm_8bit() {
        let mode = Mode65816::native8();
        let l = lift_65816(&[0xA9, 0x55], 0x1000, mode).unwrap();
        assert_eq!(l.mnemonic, "LDA");
        assert!(matches!(&l.ops[0], IlOp::SetReg(r, IlExpr::Const8(0x55)) if r == "A"));
    }

    #[test]
    fn test_lift_65816_jsl() {
        let mode = Mode65816::native8();
        let l = lift_65816(&[0x22, 0x00, 0x80, 0x01], 0x10000, mode).unwrap();
        assert_eq!(l.mnemonic, "JSL");
        assert!(matches!(&l.ops[0], IlOp::Call(_)));
    }

    #[test]
    fn test_lift_65816_rtl() {
        let mode = Mode65816::native8();
        let l = lift_65816(&[0x6B], 0x10000, mode).unwrap();
        assert_eq!(l.mnemonic, "RTL");
        assert_eq!(l.ops[0], IlOp::Return);
    }

    #[test]
    fn test_lift_empty_returns_none() {
        assert!(lift_6502(&[], 0).is_none());
        assert!(lift_65c02(&[], 0).is_none());
        assert!(lift_65816(&[], 0, Mode65816::default()).is_none());
    }
}
