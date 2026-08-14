//! SPARC LLIL lifter: lifts decoded SPARC instructions to Low-Level IL.
//!
//! Handles the SPARC register window model (g/o/l/i banks), SAVE/RESTORE
//! register window rotation, delay slot scheduling, and PSR flag updates.

use std::collections::HashMap;
use std::fmt;

use crate::sparc_decoder::{Cond, DecodeError, Operand, SparcDecoder, SparcInsn};

// ─── LLIL (simplified) ────────────────────────────────────────────────────────

/// A simplified Low-Level IL expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// Read a register.
    Reg(String),
    /// Constant integer.
    Const(i64),
    /// Unsigned constant.
    UConst(u64),
    /// Binary add.
    Add(Box<Expr>, Box<Expr>),
    /// Binary sub.
    Sub(Box<Expr>, Box<Expr>),
    /// Bitwise AND.
    And(Box<Expr>, Box<Expr>),
    /// Bitwise OR.
    Or(Box<Expr>, Box<Expr>),
    /// Bitwise XOR.
    Xor(Box<Expr>, Box<Expr>),
    /// Bitwise NOT.
    Not(Box<Expr>),
    /// Logical shift left.
    Shl(Box<Expr>, Box<Expr>),
    /// Logical shift right.
    Shr(Box<Expr>, Box<Expr>),
    /// Arithmetic shift right.
    AShr(Box<Expr>, Box<Expr>),
    /// Unsigned multiply.
    UMul(Box<Expr>, Box<Expr>),
    /// Signed multiply.
    SMul(Box<Expr>, Box<Expr>),
    /// Unsigned divide.
    UDiv(Box<Expr>, Box<Expr>),
    /// Signed divide.
    SDiv(Box<Expr>, Box<Expr>),
    /// Zero-extend N bits.
    ZxN(u32, Box<Expr>),
    /// Sign-extend N bits.
    SxN(u32, Box<Expr>),
    /// Load N bytes from an address.
    Load(u32, Box<Expr>),
    /// PC-relative target.
    PcRel(i64),
    /// Unknown / nop expression.
    Nop,
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Reg(r) => write!(f, "{r}"),
            Expr::Const(v) => write!(f, "{v}"),
            Expr::UConst(v) => write!(f, "0x{v:x}"),
            Expr::Add(a, b) => write!(f, "({a} + {b})"),
            Expr::Sub(a, b) => write!(f, "({a} - {b})"),
            Expr::And(a, b) => write!(f, "({a} & {b})"),
            Expr::Or(a, b) => write!(f, "({a} | {b})"),
            Expr::Xor(a, b) => write!(f, "({a} ^ {b})"),
            Expr::Not(a) => write!(f, "~{a}"),
            Expr::Shl(a, b) => write!(f, "({a} << {b})"),
            Expr::Shr(a, b) => write!(f, "({a} >> {b})"),
            Expr::AShr(a, b) => write!(f, "({a} >>a {b})"),
            Expr::UMul(a, b) => write!(f, "({a} u* {b})"),
            Expr::SMul(a, b) => write!(f, "({a} s* {b})"),
            Expr::UDiv(a, b) => write!(f, "({a} u/ {b})"),
            Expr::SDiv(a, b) => write!(f, "({a} s/ {b})"),
            Expr::ZxN(n, a) => write!(f, "zx{n}({a})"),
            Expr::SxN(n, a) => write!(f, "sx{n}({a})"),
            Expr::Load(n, a) => write!(f, "mem{n}[{a}]"),
            Expr::PcRel(v) => write!(f, "pc+({v}*4)"),
            Expr::Nop => write!(f, "nop"),
        }
    }
}

// ─── LlilOp ───────────────────────────────────────────────────────────────────

/// A single LLIL operation.
#[derive(Debug, Clone)]
pub enum LlilOp {
    /// Set a register to an expression value.
    SetReg { dest: String, value: Expr },
    /// Store N bytes of `value` at `addr`.
    Store { size: u32, addr: Expr, value: Expr },
    /// Unconditional jump to expression.
    Jump(Expr),
    /// Conditional jump: if `cond` → `target`, else fall-through.
    CondJump { cond: String, target: Expr },
    /// Call target.
    Call(Expr),
    /// Return from function.
    Return(Expr),
    /// Update PSR integer condition codes from `value`.
    SetFlags(Expr),
    /// System trap.
    Trap(u8),
    /// No operation.
    Nop,
    /// Push register window (SAVE).
    PushWindow { rd: String, rs1: String, src: Expr },
    /// Pop register window (RESTORE).
    PopWindow { rd: String, rs1: String, src: Expr },
    /// Unimplemented marker.
    Unimplemented(String),
}

impl fmt::Display for LlilOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LlilOp::SetReg { dest, value } => write!(f, "{dest} = {value}"),
            LlilOp::Store { size, addr, value } => write!(f, "mem{size}[{addr}] = {value}"),
            LlilOp::Jump(e) => write!(f, "goto {e}"),
            LlilOp::CondJump { cond, target } => write!(f, "if ({cond}) goto {target}"),
            LlilOp::Call(e) => write!(f, "call {e}"),
            LlilOp::Return(e) => write!(f, "return {e}"),
            LlilOp::SetFlags(e) => write!(f, "flags = flags({e})"),
            LlilOp::Trap(n) => write!(f, "trap {n}"),
            LlilOp::Nop => write!(f, "nop"),
            LlilOp::PushWindow { rd, rs1, src } => write!(f, "push_window {rd} = {rs1} + {src}"),
            LlilOp::PopWindow { rd, rs1, src } => write!(f, "pop_window {rd} = {rs1} + {src}"),
            LlilOp::Unimplemented(s) => write!(f, "unimpl({s})"),
        }
    }
}

// ─── LiftedInsn ───────────────────────────────────────────────────────────────

/// A lifted instruction: original bytes + list of LLIL ops.
#[derive(Debug, Clone)]
pub struct LiftedInsn {
    /// The decoded SPARC instruction.
    pub insn: SparcInsn,
    /// LLIL operations (may be empty for NOPs).
    pub ops: Vec<LlilOp>,
    /// True if a delay-slot instruction follows and was consumed.
    pub delay_slot_consumed: bool,
}

impl LiftedInsn {
    fn new(insn: SparcInsn, ops: Vec<LlilOp>) -> Self {
        Self {
            insn,
            ops,
            delay_slot_consumed: false,
        }
    }
}

// ─── RegisterBank ─────────────────────────────────────────────────────────────

/// The SPARC register window model.
///
/// SPARC has 8 global registers (g0-g7), plus a configurable number of windows
/// each containing 16 registers split into an "out" (o) and "local+in" (l/i)
/// half.  On SAVE the window rotates: caller's `o` become the new `i`.
#[derive(Debug, Clone)]
pub struct RegisterBank {
    /// Current window level (CWP, Current Window Pointer).
    pub cwp: u8,
    /// Maximum window index.
    pub nwindows: u8,
    /// Register values for each window, indexed [cwp][reg_in_window].
    windows: Vec<[u64; 16]>,
    /// Global registers g0-g7.
    globals: [u64; 8],
    /// PC
    pub pc: u64,
    /// nPC (delayed branch target).
    pub npc: u64,
    /// PSR (Processor State Register).
    pub psr: u32,
    /// Y register (for multiply).
    pub y: u32,
}

impl RegisterBank {
    pub fn new(nwindows: u8) -> Self {
        Self {
            cwp: 0,
            nwindows,
            windows: vec![[0u64; 16]; nwindows as usize],
            globals: [0u64; 8],
            pc: 0,
            npc: 4,
            psr: 0,
            y: 0,
        }
    }

    /// Read a SPARC register (0 = %g0, …, 31 = %i7).
    pub fn read(&self, reg: u8) -> u64 {
        let r = reg & 0x1F;
        if r == 0 {
            return 0; // %g0 always zero
        }
        if r < 8 {
            return self.globals[r as usize];
        }
        // Register within the current window: r - 8 is index 0..15
        let win_idx = (r - 8) as usize;
        let cwp = self.cwp as usize;
        self.windows[cwp][win_idx]
    }

    /// Write a SPARC register.
    pub fn write(&mut self, reg: u8, value: u64) {
        let r = reg & 0x1F;
        if r == 0 {
            return; // %g0 is always 0
        }
        if r < 8 {
            self.globals[r as usize] = value;
            return;
        }
        let win_idx = (r - 8) as usize;
        let cwp = self.cwp as usize;
        self.windows[cwp][win_idx] = value;
    }

    /// Perform a SAVE: rotate window inward (CWP = CWP - 1 mod NWINDOWS).
    pub fn save_window(&mut self) {
        self.cwp = (self.cwp + self.nwindows - 1) % self.nwindows;
    }

    /// Perform a RESTORE: rotate window outward (CWP = CWP + 1 mod NWINDOWS).
    pub fn restore_window(&mut self) {
        self.cwp = (self.cwp + 1) % self.nwindows;
    }

    /// PSR N flag.
    pub fn n_flag(&self) -> bool {
        (self.psr >> 23) & 1 != 0
    }
    /// PSR Z flag.
    pub fn z_flag(&self) -> bool {
        (self.psr >> 22) & 1 != 0
    }
    /// PSR V flag.
    pub fn v_flag(&self) -> bool {
        (self.psr >> 21) & 1 != 0
    }
    /// PSR C flag.
    pub fn c_flag(&self) -> bool {
        (self.psr >> 20) & 1 != 0
    }

    /// Set the integer condition codes in PSR from a result value.
    pub fn set_icc(&mut self, result: i64, carry: bool, overflow: bool) {
        let n = result < 0;
        let z = result == 0;
        let mut psr = self.psr & !0x00F00000;
        if n {
            psr |= 1 << 23;
        }
        if z {
            psr |= 1 << 22;
        }
        if overflow {
            psr |= 1 << 21;
        }
        if carry {
            psr |= 1 << 20;
        }
        self.psr = psr;
    }

    /// Evaluate a branch condition against current PSR.
    pub fn eval_condition(&self, cond: Cond) -> bool {
        let n = self.n_flag();
        let z = self.z_flag();
        let v = self.v_flag();
        let c = self.c_flag();
        match cond {
            Cond::N => false,
            Cond::E => z,
            Cond::LE => z || (n ^ v),
            Cond::L => n ^ v,
            Cond::LEU => c || z,
            Cond::CS => c,
            Cond::NEG => n,
            Cond::VS => v,
            Cond::A => true,
            Cond::NE => !z,
            Cond::G => !(z || (n ^ v)),
            Cond::GE => !(n ^ v),
            Cond::GU => !(c || z),
            Cond::CC => !c,
            Cond::POS => !n,
            Cond::VC => !v,
        }
    }
}

// ─── DelaySlotBuffer ──────────────────────────────────────────────────────────

/// Buffers the instruction after a branch/call for delay-slot handling.
#[derive(Debug, Default)]
pub struct DelaySlotBuffer {
    pending: Option<LiftedInsn>,
}

impl DelaySlotBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, lifted: LiftedInsn) {
        self.pending = Some(lifted);
    }

    pub fn take(&mut self) -> Option<LiftedInsn> {
        self.pending.take()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_none()
    }
}

// ─── SparcLifter ─────────────────────────────────────────────────────────────

/// Lifts decoded SPARC instructions to LLIL.
pub struct SparcLifter {
    decoder: SparcDecoder,
    delay_buf: DelaySlotBuffer,
}

impl SparcLifter {
    pub fn new() -> Self {
        Self {
            decoder: SparcDecoder::new(),
            delay_buf: DelaySlotBuffer::new(),
        }
    }

    pub fn new_v9() -> Self {
        Self {
            decoder: SparcDecoder::new_v9(),
            delay_buf: DelaySlotBuffer::new(),
        }
    }

    /// Lift a single raw 32-bit word.
    pub fn lift(&mut self, raw: u32, pc: u64) -> Result<LiftedInsn, DecodeError> {
        let insn = self.decoder.decode(raw)?;
        Ok(self.lift_insn(insn, pc))
    }

    /// Lift from a byte slice (big-endian).
    pub fn lift_bytes(&mut self, bytes: &[u8], pc: u64) -> Result<LiftedInsn, DecodeError> {
        let insn = self.decoder.decode_bytes(bytes)?;
        Ok(self.lift_insn(insn, pc))
    }

    fn lift_insn(&self, insn: SparcInsn, pc: u64) -> LiftedInsn {
        let ops = self.lift_sparc_insn(&insn, pc);
        LiftedInsn::new(insn, ops)
    }

    /// Core lifting logic.
    pub fn lift_sparc_insn(&self, insn: &SparcInsn, pc: u64) -> Vec<LlilOp> {
        let mn = insn.mnemonic.as_str();
        match mn {
            "nop" => vec![LlilOp::Nop],

            "call" => {
                let target = self.lift_operand(
                    insn.operands.first().unwrap_or(&Operand::Reg(0)),
                    pc,
                );
                let link_reg = "%o7".to_string();
                vec![
                    LlilOp::SetReg {
                        dest: link_reg,
                        value: Expr::UConst(pc),
                    },
                    LlilOp::Call(target),
                ]
            }

            "jmpl" => {
                let addr = self.lift_operand(
                    insn.operands.first().unwrap_or(&Operand::Reg(0)),
                    pc,
                );
                let rd_name = insn
                    .rd
                    .map(reg_str)
                    .unwrap_or_else(|| "%g0".to_string());
                if rd_name == "%g0" {
                    // ret / retl variants
                    vec![LlilOp::Return(addr)]
                } else {
                    vec![
                        LlilOp::SetReg {
                            dest: rd_name,
                            value: Expr::UConst(pc),
                        },
                        LlilOp::Jump(addr),
                    ]
                }
            }

            "rett" => {
                let rs1 = self.lift_operand(
                    insn.operands.first().unwrap_or(&Operand::Reg(0)),
                    pc,
                );
                let src = self.lift_operand(
                    insn.operands.get(1).unwrap_or(&Operand::Reg(0)),
                    pc,
                );
                let addr = Expr::Add(Box::new(rs1), Box::new(src));
                vec![LlilOp::Return(addr)]
            }

            "save" => {
                let rs1 = self.lift_operand(
                    insn.operands.first().unwrap_or(&Operand::Reg(0)),
                    pc,
                );
                let src = self.lift_operand(
                    insn.operands.get(1).unwrap_or(&Operand::Reg(0)),
                    pc,
                );
                let rd = insn.rd.map(reg_str).unwrap_or("%g0".to_string());
                vec![LlilOp::PushWindow {
                    rd,
                    rs1: rs1.to_string(),
                    src,
                }]
            }

            "restore" => {
                let rs1 = self.lift_operand(
                    insn.operands.first().unwrap_or(&Operand::Reg(0)),
                    pc,
                );
                let src = self.lift_operand(
                    insn.operands.get(1).unwrap_or(&Operand::Reg(0)),
                    pc,
                );
                let rd = insn.rd.map(reg_str).unwrap_or("%g0".to_string());
                vec![LlilOp::PopWindow {
                    rd,
                    rs1: rs1.to_string(),
                    src,
                }]
            }

            "sethi" => {
                let rd = insn.rd.map(reg_str).unwrap_or("%g0".to_string());
                if let Some(Operand::Imm22(imm22)) = insn.operands.first() {
                    let val = (*imm22) << 10;
                    vec![LlilOp::SetReg {
                        dest: rd,
                        value: Expr::UConst(val as u64),
                    }]
                } else {
                    vec![LlilOp::Nop]
                }
            }

            "add" | "addx" => self.lift_alu(insn, pc, |a, b| Expr::Add(Box::new(a), Box::new(b))),
            "sub" | "subx" => self.lift_alu(insn, pc, |a, b| Expr::Sub(Box::new(a), Box::new(b))),
            "and" => self.lift_alu(insn, pc, |a, b| Expr::And(Box::new(a), Box::new(b))),
            "or" => self.lift_alu(insn, pc, |a, b| Expr::Or(Box::new(a), Box::new(b))),
            "xor" => self.lift_alu(insn, pc, |a, b| Expr::Xor(Box::new(a), Box::new(b))),
            "andn" => self.lift_alu(insn, pc, |a, b| {
                Expr::And(Box::new(a), Box::new(Expr::Not(Box::new(b))))
            }),
            "orn" => self.lift_alu(insn, pc, |a, b| {
                Expr::Or(Box::new(a), Box::new(Expr::Not(Box::new(b))))
            }),
            "xnor" => self.lift_alu(insn, pc, |a, b| {
                Expr::Not(Box::new(Expr::Xor(Box::new(a), Box::new(b))))
            }),
            "sll" => self.lift_alu(insn, pc, |a, b| Expr::Shl(Box::new(a), Box::new(b))),
            "srl" => self.lift_alu(insn, pc, |a, b| Expr::Shr(Box::new(a), Box::new(b))),
            "sra" => self.lift_alu(insn, pc, |a, b| Expr::AShr(Box::new(a), Box::new(b))),
            "umul" | "mulscc" => {
                self.lift_alu(insn, pc, |a, b| Expr::UMul(Box::new(a), Box::new(b)))
            }
            "smul" => self.lift_alu(insn, pc, |a, b| Expr::SMul(Box::new(a), Box::new(b))),
            "udiv" => self.lift_alu(insn, pc, |a, b| Expr::UDiv(Box::new(a), Box::new(b))),
            "sdiv" => self.lift_alu(insn, pc, |a, b| Expr::SDiv(Box::new(a), Box::new(b))),

            // Loads
            "ldsb" => self.lift_load(insn, pc, 1, true),
            "ldsh" => self.lift_load(insn, pc, 2, true),
            "ldub" => self.lift_load(insn, pc, 1, false),
            "lduh" => self.lift_load(insn, pc, 2, false),
            "ld" => self.lift_load(insn, pc, 4, false),
            "ldd" => self.lift_load(insn, pc, 8, false),
            "ldf" => self.lift_load(insn, pc, 4, false),
            "lddf" => self.lift_load(insn, pc, 8, false),

            // Stores
            "stb" => self.lift_store(insn, pc, 1),
            "sth" => self.lift_store(insn, pc, 2),
            "st" => self.lift_store(insn, pc, 4),
            "std" => self.lift_store(insn, pc, 8),
            "stf" => self.lift_store(insn, pc, 4),
            "stdf" => self.lift_store(insn, pc, 8),

            // Branches
            _ if insn.branch_cond.is_some() => {
                let cond = insn.branch_cond.unwrap();
                let target = self.lift_operand(
                    insn.operands.first().unwrap_or(&Operand::Reg(0)),
                    pc,
                );
                if cond == Cond::A {
                    vec![LlilOp::Jump(target)]
                } else {
                    let cond_str = cond.mnemonic().to_string();
                    vec![LlilOp::CondJump {
                        cond: cond_str,
                        target,
                    }]
                }
            }

            // Traps
            _ if insn.trap_cond.is_some() => {
                vec![LlilOp::Trap(0)]
            }

            "rd" | "wr" | "flush" => vec![LlilOp::Unimplemented(mn.to_string())],

            _ => vec![LlilOp::Unimplemented(mn.to_string())],
        }
    }

    fn lift_alu<F>(&self, insn: &SparcInsn, pc: u64, f: F) -> Vec<LlilOp>
    where
        F: FnOnce(Expr, Expr) -> Expr,
    {
        let rs1 = self.lift_operand(insn.operands.first().unwrap_or(&Operand::Reg(0)), pc);
        let src = self.lift_operand(insn.operands.get(1).unwrap_or(&Operand::Reg(0)), pc);
        let result = f(rs1, src);
        let rd = insn.rd.map(reg_str).unwrap_or("%g0".to_string());
        let mut ops = Vec::new();
        if insn.sets_icc {
            ops.push(LlilOp::SetFlags(result.clone()));
        }
        if rd != "%g0" {
            ops.push(LlilOp::SetReg {
                dest: rd,
                value: result,
            });
        }
        ops
    }

    fn lift_load(&self, insn: &SparcInsn, pc: u64, size: u32, sign_extend: bool) -> Vec<LlilOp> {
        let addr = self.lift_operand(insn.operands.first().unwrap_or(&Operand::Reg(0)), pc);
        let load_expr = Expr::Load(size, Box::new(addr));
        let value = if sign_extend {
            Expr::SxN(32, Box::new(load_expr))
        } else {
            Expr::ZxN(32, Box::new(load_expr))
        };
        let rd = insn.rd.map(reg_str).unwrap_or("%g0".to_string());
        if rd == "%g0" {
            vec![LlilOp::Nop]
        } else {
            vec![LlilOp::SetReg { dest: rd, value }]
        }
    }

    fn lift_store(&self, insn: &SparcInsn, pc: u64, size: u32) -> Vec<LlilOp> {
        // First operand is the value reg, second is address
        let val = self.lift_operand(insn.operands.first().unwrap_or(&Operand::Reg(0)), pc);
        let addr = self.lift_operand(insn.operands.get(1).unwrap_or(&Operand::Reg(0)), pc);
        vec![LlilOp::Store {
            size,
            addr,
            value: val,
        }]
    }

    fn lift_operand(&self, op: &Operand, pc: u64) -> Expr {
        match op {
            Operand::Reg(r) => {
                if *r == 0 {
                    Expr::Const(0)
                } else {
                    Expr::Reg(reg_str(*r))
                }
            }
            Operand::FReg(r) => Expr::Reg(format!("%f{r}")),
            Operand::Simm13(v) => Expr::Const(*v as i64),
            Operand::Imm22(v) => Expr::UConst(*v as u64),
            Operand::PcOff(v) => {
                let target = (pc as i64) + (*v as i64) * 4;
                Expr::UConst(target as u64)
            }
            Operand::MemReg(b, i) => {
                let base = if *b == 0 {
                    Expr::Const(0)
                } else {
                    Expr::Reg(reg_str(*b))
                };
                let idx = if *i == 0 {
                    Expr::Const(0)
                } else {
                    Expr::Reg(reg_str(*i))
                };
                Expr::Add(Box::new(base), Box::new(idx))
            }
            Operand::MemImm(b, v) => {
                let base = if *b == 0 {
                    Expr::Const(0)
                } else {
                    Expr::Reg(reg_str(*b))
                };
                Expr::Add(Box::new(base), Box::new(Expr::Const(*v as i64)))
            }
        }
    }

    /// Borrow the delay-slot buffer used when lifting a stream of instructions.
    #[must_use]
    pub fn delay_slot_buffer(&self) -> &DelaySlotBuffer {
        &self.delay_buf
    }

    /// Mutable view of the delay-slot buffer (callers driving a lift loop).
    pub fn delay_slot_buffer_mut(&mut self) -> &mut DelaySlotBuffer {
        &mut self.delay_buf
    }

    /// Build an LLIL-op kind histogram for a sequence of lifted instructions.
    ///
    /// Returns a map from a coarse op-kind label ("nop", "call", "jump", "set",
    /// "store", "load", "ret", "other") to occurrence count.
    #[must_use]
    pub fn op_kind_histogram(&self, lifted: &[LiftedInsn]) -> HashMap<&'static str, usize> {
        let mut hist: HashMap<&'static str, usize> = HashMap::new();
        for li in lifted {
            for op in &li.ops {
                let key = match op {
                    LlilOp::Nop => "nop",
                    LlilOp::Call(_) => "call",
                    LlilOp::Jump(_) => "jump",
                    LlilOp::SetReg { .. } => "set",
                    LlilOp::Store { .. } => "store",
                    LlilOp::Return(_) => "ret",
                    _ => "other",
                };
                *hist.entry(key).or_insert(0) += 1;
            }
        }
        hist
    }
}

fn reg_str(r: u8) -> String {
    crate::sparc_decoder::reg_name(r).to_string()
}

impl Default for SparcLifter {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sparc_decoder::SparcDecoder;

    fn lifter() -> SparcLifter {
        SparcLifter::new()
    }

    fn encode_f3_rrr(op3: u8, rd: u8, rs1: u8, rs2: u8) -> u32 {
        (0b10 << 30)
            | ((rd as u32) << 25)
            | ((op3 as u32) << 19)
            | ((rs1 as u32) << 14)
            | (rs2 as u32)
    }
    fn encode_f3_rri(op3: u8, rd: u8, rs1: u8, simm13: i16) -> u32 {
        (0b10 << 30)
            | ((rd as u32) << 25)
            | ((op3 as u32) << 19)
            | ((rs1 as u32) << 14)
            | (1 << 13)
            | ((simm13 as u32) & 0x1FFF)
    }
    fn encode_f3_mem(op3: u8, rd: u8, rs1: u8, rs2: u8) -> u32 {
        (0b11 << 30)
            | ((rd as u32) << 25)
            | ((op3 as u32) << 19)
            | ((rs1 as u32) << 14)
            | (rs2 as u32)
    }
    fn encode_call(disp30: u32) -> u32 {
        (0b01 << 30) | (disp30 & 0x3FFF_FFFF)
    }

    #[test]
    fn test_lift_nop() {
        let mut l = lifter();
        // SETHI %g0, 0
        let raw: u32 = 0x0100_0000 /* SETHI %g0, 0 = NOP: op=00, rd=0, op2=0b100, imm22=0 */;
        let lifted = l.lift(raw, 0x1000).unwrap();
        assert!(lifted.ops.iter().any(|o| matches!(o, LlilOp::Nop)));
    }

    #[test]
    fn test_lift_add() {
        let mut l = lifter();
        let raw = encode_f3_rrr(0x00, 1, 2, 3);
        let lifted = l.lift(raw, 0).unwrap();
        assert!(
            lifted
                .ops
                .iter()
                .any(|o| matches!(o, LlilOp::SetReg { .. }))
        );
    }

    #[test]
    fn test_lift_add_result_expr() {
        let mut l = lifter();
        let raw = encode_f3_rrr(0x00, 1, 2, 3);
        let lifted = l.lift(raw, 0).unwrap();
        if let LlilOp::SetReg { dest, value } = &lifted.ops[0] {
            assert_eq!(dest, "%g1");
            assert!(matches!(value, Expr::Add(_, _)));
        }
    }

    #[test]
    fn test_lift_addcc_sets_flags() {
        let mut l = lifter();
        let raw = encode_f3_rrr(0x10, 1, 2, 3);
        let lifted = l.lift(raw, 0).unwrap();
        assert!(lifted.ops.iter().any(|o| matches!(o, LlilOp::SetFlags(_))));
    }

    #[test]
    fn test_lift_sub() {
        let mut l = lifter();
        let raw = encode_f3_rrr(0x04, 2, 3, 4);
        let lifted = l.lift(raw, 0).unwrap();
        if let LlilOp::SetReg { value, .. } = &lifted.ops[0] {
            assert!(matches!(value, Expr::Sub(_, _)));
        }
    }

    #[test]
    fn test_lift_and() {
        let mut l = lifter();
        let raw = encode_f3_rrr(0x01, 1, 2, 3);
        let lifted = l.lift(raw, 0).unwrap();
        if let LlilOp::SetReg { value, .. } = &lifted.ops[0] {
            assert!(matches!(value, Expr::And(_, _)));
        }
    }

    #[test]
    fn test_lift_or() {
        let mut l = lifter();
        let raw = encode_f3_rrr(0x02, 1, 2, 3);
        let lifted = l.lift(raw, 0).unwrap();
        if let LlilOp::SetReg { value, .. } = &lifted.ops[0] {
            assert!(matches!(value, Expr::Or(_, _)));
        }
    }

    #[test]
    fn test_lift_sll() {
        let mut l = lifter();
        let raw = encode_f3_rri(0x25, 1, 2, 4);
        let lifted = l.lift(raw, 0).unwrap();
        if let LlilOp::SetReg { value, .. } = &lifted.ops[0] {
            assert!(matches!(value, Expr::Shl(_, _)));
        }
    }

    #[test]
    fn test_lift_srl() {
        let mut l = lifter();
        let raw = encode_f3_rrr(0x26, 1, 2, 3);
        let lifted = l.lift(raw, 0).unwrap();
        if let LlilOp::SetReg { value, .. } = &lifted.ops[0] {
            assert!(matches!(value, Expr::Shr(_, _)));
        }
    }

    #[test]
    fn test_lift_sra() {
        let mut l = lifter();
        let raw = encode_f3_rrr(0x27, 1, 2, 3);
        let lifted = l.lift(raw, 0).unwrap();
        if let LlilOp::SetReg { value, .. } = &lifted.ops[0] {
            assert!(matches!(value, Expr::AShr(_, _)));
        }
    }

    #[test]
    fn test_lift_ld() {
        let mut l = lifter();
        let raw = encode_f3_mem(0x00, 1, 8, 0);
        let lifted = l.lift(raw, 0).unwrap();
        assert!(
            lifted
                .ops
                .iter()
                .any(|o| matches!(o, LlilOp::SetReg { .. }))
        );
    }

    #[test]
    fn test_lift_st() {
        let mut l = lifter();
        let raw = encode_f3_mem(0x04, 1, 8, 4);
        let lifted = l.lift(raw, 0).unwrap();
        assert!(lifted.ops.iter().any(|o| matches!(o, LlilOp::Store { .. })));
    }

    #[test]
    fn test_lift_call() {
        let mut l = lifter();
        let raw = encode_call(100);
        let lifted = l.lift(raw, 0x1000).unwrap();
        assert!(lifted.ops.iter().any(|o| matches!(o, LlilOp::Call(_))));
        // Link register should be set
        assert!(
            lifted
                .ops
                .iter()
                .any(|o| matches!(o, LlilOp::SetReg { dest, .. } if dest == "%o7"))
        );
    }

    #[test]
    fn test_lift_save() {
        let mut l = lifter();
        let raw = encode_f3_rri(0x3C, 30, 30, -96);
        let lifted = l.lift(raw, 0).unwrap();
        assert!(
            lifted
                .ops
                .iter()
                .any(|o| matches!(o, LlilOp::PushWindow { .. }))
        );
    }

    #[test]
    fn test_lift_restore() {
        let mut l = lifter();
        let raw = encode_f3_rrr(0x3D, 0, 0, 0);
        let lifted = l.lift(raw, 0).unwrap();
        assert!(
            lifted
                .ops
                .iter()
                .any(|o| matches!(o, LlilOp::PopWindow { .. }))
        );
    }

    #[test]
    fn test_register_bank_g0_always_zero() {
        let mut rb = RegisterBank::new(8);
        rb.write(0, 0xDEAD);
        assert_eq!(rb.read(0), 0);
    }

    #[test]
    fn test_register_bank_write_read() {
        let mut rb = RegisterBank::new(8);
        rb.write(1, 42);
        assert_eq!(rb.read(1), 42);
    }

    #[test]
    fn test_register_bank_save_restore() {
        let mut rb = RegisterBank::new(8);
        let cwp_before = rb.cwp;
        rb.save_window();
        assert_ne!(rb.cwp, cwp_before);
        rb.restore_window();
        assert_eq!(rb.cwp, cwp_before);
    }

    #[test]
    fn test_register_bank_psr_flags() {
        let mut rb = RegisterBank::new(8);
        rb.set_icc(-1, false, false);
        assert!(rb.n_flag());
        assert!(!rb.z_flag());
    }

    #[test]
    fn test_register_bank_z_flag() {
        let mut rb = RegisterBank::new(8);
        rb.set_icc(0, false, false);
        assert!(rb.z_flag());
        assert!(!rb.n_flag());
    }

    #[test]
    fn test_eval_condition_always() {
        let rb = RegisterBank::new(8);
        assert!(rb.eval_condition(Cond::A));
    }

    #[test]
    fn test_eval_condition_never() {
        let rb = RegisterBank::new(8);
        assert!(!rb.eval_condition(Cond::N));
    }

    #[test]
    fn test_eval_condition_equal_after_sub() {
        let mut rb = RegisterBank::new(8);
        rb.set_icc(0, false, false); // result = 0 → Z=1
        assert!(rb.eval_condition(Cond::E));
        assert!(!rb.eval_condition(Cond::NE));
    }

    #[test]
    fn test_lift_sethi() {
        let mut l = lifter();
        // sethi 0x3fc00, %o0 → value = 0x3fc00 << 10
        let raw: u32 = ((8u32) << 25) | (0b100 << 22) | 0x3fc00;
        let lifted = l.lift(raw, 0).unwrap();
        assert!(
            lifted
                .ops
                .iter()
                .any(|o| matches!(o, LlilOp::SetReg { dest, .. } if dest == "%o0"))
        );
    }

    #[test]
    fn test_lift_branch_always() {
        let mut l = lifter();
        // ba: op2=010, cond=A (1000), annul=0
        let raw: u32 = (0b10000 << 25) | (0b010 << 22) | 50;
        let lifted = l.lift(raw, 0x1000).unwrap();
        assert!(lifted.ops.iter().any(|o| matches!(o, LlilOp::Jump(_))));
    }

    #[test]
    fn test_decoder_then_lift_add() {
        // Drive the decoder directly to confirm it produces the same shape the
        // lifter consumes when called via lift().
        let dec = SparcDecoder::new();
        let raw = encode_f3_rrr(0x00, 1, 2, 3);
        let insn = dec.decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "add");
        let lifter = lifter();
        let ops = lifter.lift_sparc_insn(&insn, 0);
        assert!(ops.iter().any(|o| matches!(o, LlilOp::SetReg { .. })));
    }
}

// ─── LlilPrinter ─────────────────────────────────────────────────────────────

/// Pretty-prints a sequence of LLIL operations.
pub struct LlilPrinter {
    pub indent: usize,
    pub show_raw: bool,
}

impl LlilPrinter {
    pub fn new() -> Self {
        Self {
            indent: 0,
            show_raw: false,
        }
    }

    pub fn with_raw(mut self) -> Self {
        self.show_raw = true;
        self
    }

    pub fn print_lifted(&self, lifted: &LiftedInsn) -> Vec<String> {
        let mut lines = Vec::new();
        let prefix = " ".repeat(self.indent);
        if self.show_raw {
            lines.push(format!(
                "{prefix}; [{:08x}] {}",
                lifted.insn.raw,
                lifted.insn.disassemble()
            ));
        } else {
            lines.push(format!("{prefix}; {}", lifted.insn.disassemble()));
        }
        for op in &lifted.ops {
            lines.push(format!("{prefix}    {op}"));
        }
        lines
    }

    pub fn print_all(&self, lifted_insns: &[LiftedInsn]) -> String {
        lifted_insns
            .iter()
            .flat_map(|li| self.print_lifted(li))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for LlilPrinter {
    fn default() -> Self {
        Self::new()
    }
}

// ─── RegisterWindowSimulator ─────────────────────────────────────────────────

/// Simulates the full SPARC register window state for emulation.
pub struct RegisterWindowSimulator {
    pub bank: RegisterBank,
    pub call_depth: u32,
}

impl RegisterWindowSimulator {
    pub fn new() -> Self {
        Self {
            bank: RegisterBank::new(8),
            call_depth: 0,
        }
    }

    /// Execute a SAVE: rotate window, compute new %sp.
    pub fn execute_save(&mut self, rs1: u64, src: i64) -> u64 {
        let new_sp = (rs1 as i64).wrapping_add(src) as u64;
        self.bank.save_window();
        self.bank.write(14, new_sp); // %sp = %o6
        self.call_depth += 1;
        new_sp
    }

    /// Execute a RESTORE: rotate window back.
    pub fn execute_restore(&mut self, rs1: u64, src: i64) -> u64 {
        let result = (rs1 as i64).wrapping_add(src) as u64;
        self.bank.restore_window();
        self.call_depth = self.call_depth.saturating_sub(1);
        result
    }

    pub fn current_sp(&self) -> u64 {
        self.bank.read(14)
    }
    pub fn current_fp(&self) -> u64 {
        self.bank.read(30)
    }
}

impl Default for RegisterWindowSimulator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod extra_tests {
    use super::*;

    fn encode_f3_rrr(op3: u8, rd: u8, rs1: u8, rs2: u8) -> u32 {
        (0b10 << 30)
            | ((rd as u32) << 25)
            | ((op3 as u32) << 19)
            | ((rs1 as u32) << 14)
            | (rs2 as u32)
    }

    #[test]
    fn test_llil_printer_basic() {
        let mut l = SparcLifter::new();
        let raw = ((0b10u32 << 30) | (1u32 << 25)) | (2u32 << 14) | 3u32;
        let lifted = l.lift(raw, 0).unwrap();
        let printer = LlilPrinter::new();
        let lines = printer.print_lifted(&lifted);
        assert!(!lines.is_empty());
        assert!(lines.iter().any(|l| l.contains("add")));
    }

    #[test]
    fn test_llil_printer_with_raw() {
        let mut l = SparcLifter::new();
        // NOP
        let nop_raw: u32 = 0x0100_0000 /* SETHI %g0, 0 = NOP: op=00, rd=0, op2=0b100, imm22=0 */;
        let lifted = l.lift(nop_raw, 0).unwrap();
        let printer = LlilPrinter::new().with_raw();
        let lines = printer.print_lifted(&lifted);
        assert!(lines.iter().any(|ln| ln.contains('[')));
    }

    #[test]
    fn test_llil_printer_print_all() {
        let mut l = SparcLifter::new();
        let mut insns = Vec::new();
        let nop: u32 = 0x0100_0000 /* SETHI %g0, 0 = NOP: op=00, rd=0, op2=0b100, imm22=0 */;
        insns.push(l.lift(nop, 0x1000).unwrap());
        insns.push(l.lift(nop, 0x1004).unwrap());
        let printer = LlilPrinter::new();
        let s = printer.print_all(&insns);
        assert!(!s.is_empty());
    }

    #[test]
    fn test_register_window_sim_save() {
        let mut sim = RegisterWindowSimulator::new();
        let new_sp = sim.execute_save(0x7fff0000, -96);
        assert_eq!(new_sp, 0x7fff0000u64.wrapping_add((-96i64) as u64));
        assert_eq!(sim.call_depth, 1);
    }

    #[test]
    fn test_register_window_sim_restore() {
        let mut sim = RegisterWindowSimulator::new();
        sim.execute_save(0x7fff0000, -96);
        sim.execute_restore(0, 0);
        assert_eq!(sim.call_depth, 0);
    }

    #[test]
    fn test_register_window_sim_sp() {
        let mut sim = RegisterWindowSimulator::new();
        sim.execute_save(0x7fff0060, -96);
        let sp = sim.current_sp();
        assert_eq!(sp, 0x7fff0000);
    }

    #[test]
    fn test_expr_display_add() {
        let e = Expr::Add(Box::new(Expr::Reg("%o0".into())), Box::new(Expr::Const(4)));
        assert!(e.to_string().contains('+'));
    }

    #[test]
    fn test_expr_display_load() {
        let e = Expr::Load(4, Box::new(Expr::UConst(0x401000)));
        assert!(e.to_string().contains("mem4"));
    }

    #[test]
    fn test_llil_op_display_setreg() {
        let op = LlilOp::SetReg {
            dest: "%i0".into(),
            value: Expr::Const(42),
        };
        assert!(op.to_string().contains("%i0"));
        assert!(op.to_string().contains("42"));
    }

    #[test]
    fn test_llil_op_display_store() {
        let op = LlilOp::Store {
            size: 4,
            addr: Expr::Reg("%sp".into()),
            value: Expr::Const(0),
        };
        assert!(op.to_string().contains("mem4"));
    }

    #[test]
    fn test_lifted_insn_has_delay_slot_call() {
        let mut l = SparcLifter::new();
        let call_raw: u32 = (0b01u32 << 30) | 100u32;
        let li = l.lift(call_raw, 0x1000).unwrap();
        assert!(li.insn.has_delay_slot);
    }

    #[test]
    fn test_encode_f3_rrr_lifts_add() {
        // The local encoder produces a valid Format-3 reg-reg ADD.
        let mut l = SparcLifter::new();
        let raw = encode_f3_rrr(0x00, 1, 2, 3);
        let lifted = l.lift(raw, 0).unwrap();
        assert!(
            lifted
                .ops
                .iter()
                .any(|o| matches!(o, LlilOp::SetReg { .. }))
        );
    }
}
