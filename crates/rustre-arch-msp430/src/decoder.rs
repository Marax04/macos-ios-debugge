//! `decoder.rs` — Complete MSP430 instruction decoder.
//!
//! Produces typed [`Msp430Insn`] values from raw bytes.  All three instruction
//! formats are covered:
//!
//! * **Format I** (double-operand): MOV / ADD / ADDC / SUBC / SUB / CMP /
//!   DADD / BIT / BIC / BIS / XOR / AND
//! * **Format II** (single-operand): RRC / SWPB / RRA / SXT / PUSH / CALL /
//!   RETI
//! * **Format III** (jump): JNE / JEQ / JNC / JC / JN / JGE / JL / JMP
//!
//! Addressing modes: Register, Indexed, Indirect, `IndirectAutoincrement`,
//! Symbolic, Absolute, Immediate, Constant.

use crate::{AddrMode, constant_generator, reg_name, src_addr_mode};
use rustre_core::errors::CoreError;

// ── Opcodes ───────────────────────────────────────────────────────────────────

/// Format-I (two-operand) opcode identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op2 {
    Mov,
    Add,
    Addc,
    Subc,
    Sub,
    Cmp,
    Dadd,
    Bit,
    Bic,
    Bis,
    Xor,
    And,
}

impl Op2 {
    /// Decode from the 4-bit opcode field (bits 15-12 of instruction word).
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            4 => Some(Self::Mov),
            5 => Some(Self::Add),
            6 => Some(Self::Addc),
            7 => Some(Self::Subc),
            8 => Some(Self::Sub),
            9 => Some(Self::Cmp),
            10 => Some(Self::Dadd),
            11 => Some(Self::Bit),
            12 => Some(Self::Bic),
            13 => Some(Self::Bis),
            14 => Some(Self::Xor),
            15 => Some(Self::And),
            _ => None,
        }
    }

    /// Return the canonical mnemonic for this opcode.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Mov => "MOV",
            Self::Add => "ADD",
            Self::Addc => "ADDC",
            Self::Subc => "SUBC",
            Self::Sub => "SUB",
            Self::Cmp => "CMP",
            Self::Dadd => "DADD",
            Self::Bit => "BIT",
            Self::Bic => "BIC",
            Self::Bis => "BIS",
            Self::Xor => "XOR",
            Self::And => "AND",
        }
    }

    /// Whether this instruction reads-and-discards the result (test-only).
    #[must_use]
    pub const fn is_test_only(self) -> bool {
        matches!(self, Self::Cmp | Self::Bit)
    }

    /// Whether this instruction updates the Status Register.
    #[must_use]
    pub const fn updates_flags(self) -> bool {
        !matches!(self, Self::Mov | Self::Bic | Self::Bis)
    }
}

/// Format-II (single-operand) opcode identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op1 {
    Rrc,
    Swpb,
    Rra,
    Sxt,
    Push,
    Call,
    Reti,
}

impl Op1 {
    /// Decode from the 3-bit opcode field (bits 9-7 of instruction word).
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::Rrc),
            1 => Some(Self::Swpb),
            2 => Some(Self::Rra),
            3 => Some(Self::Sxt),
            4 => Some(Self::Push),
            5 => Some(Self::Call),
            6 => Some(Self::Reti),
            _ => None,
        }
    }

    /// Return the canonical mnemonic for this opcode.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Rrc => "RRC",
            Self::Swpb => "SWPB",
            Self::Rra => "RRA",
            Self::Sxt => "SXT",
            Self::Push => "PUSH",
            Self::Call => "CALL",
            Self::Reti => "RETI",
        }
    }

    /// Whether this opcode uses the byte/word (BW) bit.
    #[must_use]
    pub const fn uses_bw(self) -> bool {
        matches!(self, Self::Rrc | Self::Rra | Self::Push)
    }
}

/// Jump condition codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JumpCond {
    Jne,
    Jeq,
    Jnc,
    Jc,
    Jn,
    Jge,
    Jl,
    Jmp,
}

impl JumpCond {
    /// Decode from the 3-bit condition field.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 7 {
            0 => Self::Jne,
            1 => Self::Jeq,
            2 => Self::Jnc,
            3 => Self::Jc,
            4 => Self::Jn,
            5 => Self::Jge,
            6 => Self::Jl,
            _ => Self::Jmp,
        }
    }

    /// Return the canonical mnemonic for this condition.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Jne => "JNE",
            Self::Jeq => "JEQ",
            Self::Jnc => "JNC",
            Self::Jc => "JC",
            Self::Jn => "JN",
            Self::Jge => "JGE",
            Self::Jl => "JL",
            Self::Jmp => "JMP",
        }
    }

    /// Return `true` if the jump is conditional (not unconditional JMP).
    #[must_use]
    pub const fn is_conditional(self) -> bool {
        !matches!(self, Self::Jmp)
    }
}

// ── Operand representation ─────────────────────────────────────────────────────

/// A decoded MSP430 operand (source or destination).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operand {
    /// The addressing mode.
    pub mode: AddrMode,
    /// Register number (0-15).
    pub reg: u8,
    /// Extension word value (offset, absolute address, or immediate).
    pub ext: Option<u16>,
}

impl Operand {
    /// Construct a register-direct operand.
    #[must_use]
    pub const fn register(reg: u8) -> Self {
        Self {
            mode: AddrMode::Register,
            reg,
            ext: None,
        }
    }

    /// Construct an immediate operand.
    #[must_use]
    pub const fn immediate(value: u16) -> Self {
        Self {
            mode: AddrMode::Immediate,
            reg: 0,
            ext: Some(value),
        }
    }

    /// Construct a constant-generator operand.
    #[must_use]
    pub const fn constant(c: i8) -> Self {
        Self {
            mode: AddrMode::Constant(c),
            reg: 3,
            ext: None,
        }
    }

    /// Return the concrete integer value of a constant or immediate operand.
    #[must_use]
    pub fn const_value(&self) -> Option<i32> {
        match self.mode {
            AddrMode::Constant(c) => Some(i32::from(c)),
            AddrMode::Immediate => self.ext.map(|v| i32::from(v.cast_signed())),
            _ => None,
        }
    }

    /// Format this operand as AT&T-style text (source usage).
    #[must_use]
    pub fn format_src(&self) -> String {
        match self.mode {
            AddrMode::Register => reg_name(self.reg).to_string(),
            AddrMode::Indexed => {
                format!("{}({})", self.ext.unwrap_or(0).cast_signed(), reg_name(self.reg))
            }
            AddrMode::Absolute => format!("&0x{:04X}", self.ext.unwrap_or(0)),
            AddrMode::Indirect => format!("@{}", reg_name(self.reg)),
            AddrMode::IndirectAutoInc => format!("@{}+", reg_name(self.reg)),
            AddrMode::Immediate => format!("#0x{:04X}", self.ext.unwrap_or(0)),
            AddrMode::Constant(c) => format!("#{c}"),
            AddrMode::Symbolic => format!("0x{:04X}", self.ext.unwrap_or(0)),
        }
    }

    /// Format this operand as a destination (no `@` prefix, etc.).
    #[must_use]
    pub fn format_dst(&self) -> String {
        match self.mode {
            AddrMode::Register => reg_name(self.reg).to_string(),
            AddrMode::Absolute => format!("&0x{:04X}", self.ext.unwrap_or(0)),
            AddrMode::Indexed | AddrMode::Symbolic => {
                format!("{}({})", self.ext.unwrap_or(0).cast_signed(), reg_name(self.reg))
            }
            _ => self.format_src(),
        }
    }
}

// ── Instruction kinds ─────────────────────────────────────────────────────────

/// The body of a decoded MSP430 instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsnKind {
    /// Format I: two-operand.
    TwoOp {
        op: Op2,
        bw: bool, // true = byte operation
        src: Operand,
        dst: Operand,
    },
    /// Format II: single-operand.
    OneOp { op: Op1, bw: bool, src: Operand },
    /// Format III: conditional or unconditional jump.
    Jump { cond: JumpCond, target: u16 },
    /// Emulated (pseudo) instruction backed by a two-operand encoding.
    Emulated {
        mnemonic: &'static str,
        bw: bool,
        dst: Operand,
    },
    /// Unknown / undecodable data word.
    Data(u16),
}

/// A fully-decoded MSP430 instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Msp430Insn {
    /// Instruction kind and operands.
    pub kind: InsnKind,
    /// Total byte width (2, 4, or 6).
    pub size: usize,
    /// The raw instruction word (first 16 bits).
    pub raw: u16,
    /// Address at which the instruction was decoded.
    pub addr: u64,
}

impl Msp430Insn {
    /// Return the instruction mnemonic (with `.B`/`.W` suffix where applicable).
    #[must_use]
    pub fn mnemonic(&self) -> String {
        match &self.kind {
            InsnKind::TwoOp { op, bw, .. } => {
                format!("{}{}", op.mnemonic(), if *bw { ".B" } else { ".W" })
            }
            InsnKind::OneOp { op, bw, .. } => {
                if op.uses_bw() {
                    format!("{}{}", op.mnemonic(), if *bw { ".B" } else { ".W" })
                } else {
                    op.mnemonic().to_string()
                }
            }
            InsnKind::Jump { cond, .. } => cond.mnemonic().to_string(),
            InsnKind::Emulated { mnemonic, .. } => mnemonic.to_string(),
            InsnKind::Data(_) => "DC.W".to_string(),
        }
    }

    /// Return `true` if this instruction is a branch (conditional or not).
    #[must_use]
    pub const fn is_branch(&self) -> bool {
        matches!(self.kind, InsnKind::Jump { .. })
    }

    /// Return `true` if this instruction is a conditional branch.
    #[must_use]
    pub const fn is_conditional(&self) -> bool {
        matches!(self.kind, InsnKind::Jump { cond, .. } if cond.is_conditional())
    }

    /// Return `true` if this instruction is a CALL.
    #[must_use]
    pub const fn is_call(&self) -> bool {
        matches!(self.kind, InsnKind::OneOp { op: Op1::Call, .. })
    }

    /// Return `true` if this instruction is a return (RETI or emulated RET).
    #[must_use]
    pub fn is_ret(&self) -> bool {
        matches!(
            self.kind,
            InsnKind::OneOp { op: Op1::Reti, .. }
                | InsnKind::Emulated {
                    mnemonic: "RET",
                    ..
                }
        )
    }

    /// Return `true` if this instruction terminates a basic block.
    #[must_use]
    pub fn is_terminator(&self) -> bool {
        self.is_branch() || self.is_ret() || self.is_call()
    }

    /// Return the static branch target, if known.
    #[must_use]
    pub fn branch_target(&self) -> Option<u64> {
        match &self.kind {
            InsnKind::Jump { target, .. } => Some(u64::from(*target)),
            // CALL #imm: the call target is the immediate source operand.
            InsnKind::OneOp { op: Op1::Call, src, .. } => match src.mode {
                AddrMode::Immediate | AddrMode::Absolute => src.ext.map(u64::from),
                _ => None,
            },
            _ => None,
        }
    }

    /// Format the full instruction text (AT&T style).
    #[must_use]
    pub fn display(&self) -> String {
        match &self.kind {
            InsnKind::TwoOp { op, bw, src, dst } => {
                let suf = if *bw { ".B" } else { ".W" };
                format!(
                    "{}{}\t{},{}",
                    op.mnemonic(),
                    suf,
                    src.format_src(),
                    dst.format_dst()
                )
            }
            InsnKind::OneOp { op, bw, src } => {
                let suf = if op.uses_bw() {
                    if *bw { ".B" } else { ".W" }
                } else {
                    ""
                };
                format!("{}{}\t{}", op.mnemonic(), suf, src.format_src())
            }
            InsnKind::Jump { cond, target } => {
                format!("{}\t0x{:04X}", cond.mnemonic(), target)
            }
            InsnKind::Emulated { mnemonic, dst, .. } => {
                format!("{}\t{}", mnemonic, dst.format_dst())
            }
            InsnKind::Data(w) => format!("DC.W\t0x{w:04X}"),
        }
    }
}

// ── Decode entry point ─────────────────────────────────────────────────────────

/// Decode one MSP430 instruction from `bytes` at address `pc`.
///
/// Returns the typed [`Msp430Insn`] on success.
///
/// # Errors
/// Returns [`CoreError::InvalidFormat`] if there are fewer than 2 bytes.
pub fn decode_insn(bytes: &[u8], pc: u64) -> Result<Msp430Insn, CoreError> {
    if bytes.len() < 2 {
        return Err(CoreError::InvalidFormat {
            message: "need at least 2 bytes".into(),
        });
    }
    let word = u16::from_le_bytes([bytes[0], bytes[1]]);

    // Helper: read extension word at byte offset `off`.
    let ext = |off: usize| -> Option<u16> {
        bytes
            .get(off..off + 2)
            .map(|s| u16::from_le_bytes([s[0], s[1]]))
    };

    // ── Format III: jump (bits 15-13 == 001) ─────────────────────────────────
    if (word >> 13) == 0b001 {
        return Ok(decode_jump(word, pc));
    }

    // ── Format II: single-operand (bits 15-10 == 0001 00) ────────────────────
    if (word >> 10) & 0x3F == 0b00_0100 {
        return Ok(decode_one_op(word, pc, ext));
    }

    // ── Format I: two-operand (opcode 4..=15) ────────────────────────────────
    let opcode4 = (word >> 12) as u8;
    if opcode4 >= 4 {
        return Ok(decode_two_op(word, pc, ext));
    }

    // Data word.
    Ok(Msp430Insn {
        kind: InsnKind::Data(word),
        size: 2,
        raw: word,
        addr: pc,
    })
}

// ── Format III decoder ────────────────────────────────────────────────────────

/// Wrapping cast from i64 to u16 (intentional truncation for MSP430 16-bit PC).
#[inline]
const fn i64_to_u16_wrap(v: i64) -> u16 {
    v as u16
}

fn decode_jump(word: u16, pc: u64) -> Msp430Insn {
    let cond_bits = ((word >> 10) & 7) as u8;
    let raw_off = word & 0x3FF;
    // Sign-extend 10-bit offset.
    let offset: i16 = if raw_off & 0x200 != 0 {
        raw_off.cast_signed() | (-0x400_i16)
    } else {
        raw_off.cast_signed()
    };
    // Target = PC+2 + offset*2 (PC is already pointing at next instruction).
    let target = i64_to_u16_wrap(
        pc.cast_signed()
            .wrapping_add(2)
            .wrapping_add(i64::from(offset) * 2),
    );
    let cond = JumpCond::from_bits(cond_bits);
    Msp430Insn {
        kind: InsnKind::Jump { cond, target },
        size: 2,
        raw: word,
        addr: pc,
    }
}

// ── Format II decoder ─────────────────────────────────────────────────────────

fn decode_one_op(
    word: u16,
    pc: u64,
    ext: impl Fn(usize) -> Option<u16>,
) -> Msp430Insn {
    let opcode3 = ((word >> 7) & 7) as u8;

    // RETI takes no operand: its low six bits (B/W, As, register) are
    // don't-care and no extension word is fetched, so it is always two bytes.
    // Keying this off the exact word `0x1300` left every other encoding of the
    // same opcode falling through to the generic operand path below, which
    // invented an extension word and reported size 4 or 6 — `0x1310` decoded as
    // a 4-byte RETI.  A linear sweep would then skip two live bytes.
    // `msp430_decoder::decode_type2` keys off the opcode bits and is the model
    // followed here.
    if opcode3 == 6 {
        return Msp430Insn {
            kind: InsnKind::OneOp {
                op: Op1::Reti,
                bw: false,
                src: Operand::register(0), // operand unused
            },
            size: 2,
            raw: word,
            addr: pc,
        };
    }

    let bw = (word >> 6) & 1 != 0;
    let as_bits = ((word >> 4) & 3) as u8;
    let reg = (word & 0xF) as u8;

    let op = Op1::from_bits(opcode3).unwrap_or(Op1::Reti);
    let mode = src_addr_mode(as_bits, reg);
    let ext1 = ext(2);

    let operand = build_operand(mode, reg, ext1);
    let size = 2 + mode.ext_words() * 2;

    Msp430Insn {
        kind: InsnKind::OneOp {
            op,
            bw,
            src: operand,
        },
        size,
        raw: word,
        addr: pc,
    }
}

// ── Format I decoder ──────────────────────────────────────────────────────────

fn decode_two_op(
    word: u16,
    pc: u64,
    ext: impl Fn(usize) -> Option<u16>,
) -> Msp430Insn {
    let opcode4 = (word >> 12) as u8;
    let src_reg = ((word >> 8) & 0xF) as u8;
    let ad = ((word >> 7) & 1) as u8;
    let bw = (word >> 6) & 1 != 0;
    let as_bits = ((word >> 4) & 3) as u8;
    let dst_reg = (word & 0xF) as u8;

    let src_mode = src_addr_mode(as_bits, src_reg);
    let src_ext_words = src_mode.ext_words();
    let dst_ext_words = usize::from(ad != 0);

    let ext1 = ext(2);
    let ext2 = ext(2 + src_ext_words * 2);

    let src = build_operand(src_mode, src_reg, ext1);
    let dst = build_dst_operand(ad, dst_reg, ext2);
    let size = 2 + (src_ext_words + dst_ext_words) * 2;

    let Some(op) = Op2::from_bits(opcode4) else {
        return Msp430Insn {
            kind: InsnKind::Data(word),
            size: 2,
            raw: word,
            addr: pc,
        };
    };

    // Check for emulated instructions.
    if let Some(emu) = check_emulated_insn(opcode4, src_reg, dst_reg, as_bits, ad, bw) {
        // For emulated MOV @SP+, PC (RET) we need no dst.
        let dst_operand = build_dst_operand(ad, dst_reg, ext2);
        return Msp430Insn {
            kind: InsnKind::Emulated {
                mnemonic: emu,
                bw,
                dst: dst_operand,
            },
            size,
            raw: word,
            addr: pc,
        };
    }

    Msp430Insn {
        kind: InsnKind::TwoOp { op, bw, src, dst },
        size,
        raw: word,
        addr: pc,
    }
}

// ── Operand builders ──────────────────────────────────────────────────────────

const fn build_operand(mode: AddrMode, reg: u8, ext: Option<u16>) -> Operand {
    Operand { mode, reg, ext }
}

const fn build_dst_operand(ad: u8, reg: u8, ext: Option<u16>) -> Operand {
    if ad == 0 {
        Operand::register(reg)
    } else if reg == 2 {
        // Absolute addressing: R2 with ad=1.
        Operand {
            mode: AddrMode::Absolute,
            reg: 2,
            ext,
        }
    } else {
        Operand {
            mode: AddrMode::Indexed,
            reg,
            ext,
        }
    }
}

// ── Emulated instruction detection ────────────────────────────────────────────

/// Return the emulated mnemonic if this two-operand encoding is a pseudo-instruction.
#[must_use]
pub const fn check_emulated_insn(
    opcode4: u8,
    src_reg: u8,
    dst_reg: u8,
    as_bits: u8,
    ad: u8,
    bw: bool,
) -> Option<&'static str> {
    // Use constant-generator source to identify common patterns.
    let cg = constant_generator(src_reg, as_bits);
    match (opcode4, src_reg, dst_reg, as_bits, ad, cg) {
        // MOV #0, dst  → CLR
        (4, 3, _, 0, _, _) if !bw => Some("CLR.W"),
        (4, 3, _, 0, _, _) => Some("CLR.B"),
        // MOV @SP+, PC → RET
        (4, 1, 0, 3, 0, _) => Some("RET"),
        // ADD CG=#1, dst → INC
        (5, _, _, _, _, Some(1)) => Some("INC"),
        // ADD CG=#-1, dst → DEC  |  SUB CG=#1, dst → DEC
        (5, _, _, _, _, Some(-1)) | (8, _, _, _, _, Some(1)) => Some("DEC"),
        // XOR CG=#-1, dst → INV
        (14, _, _, _, _, Some(-1)) => Some("INV"),
        // BIC #8, SR → DINT  (disable interrupts: clear GIE)
        (12, 3, 2, 3, 0, _) => Some("DINT"),
        // BIS #8, SR → EINT  (enable interrupts: set GIE)
        (13, 3, 2, 3, 0, _) => Some("EINT"),
        // MOV Rn, Rn (same src & dst, register mode) → NOP
        (4, s, d, 0, 0, _) if s == d => Some("NOP"),
        _ => None,
    }
}

// ── Decode multiple instructions ──────────────────────────────────────────────

/// Decode all instructions from a flat byte slice starting at `base_addr`.
///
/// Stops on decode failure and returns everything successfully decoded so far.
#[must_use]
pub fn decode_all(bytes: &[u8], base_addr: u64) -> Vec<Msp430Insn> {
    let mut result = Vec::with_capacity(bytes.len() / 3);
    let mut off = 0usize;
    while off + 1 < bytes.len() {
        match decode_insn(&bytes[off..], base_addr + off as u64) {
            Ok(insn) => {
                off += insn.size;
                result.push(insn);
            }
            Err(_) => {
                off += 2; // skip unknown word
            }
        }
    }
    result
}

/// Decode instructions, stopping as soon as a terminator (branch/ret/call) is seen.
///
/// Returns the instructions of one basic block including the terminator.
#[must_use]
pub fn decode_block(bytes: &[u8], base_addr: u64) -> Vec<Msp430Insn> {
    let mut result = Vec::new();
    let mut off = 0usize;
    while off + 1 < bytes.len() {
        match decode_insn(&bytes[off..], base_addr + off as u64) {
            Ok(insn) => {
                let term = insn.is_terminator();
                off += insn.size;
                result.push(insn);
                if term {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn at(pc: u64, bytes: &[u8]) -> Msp430Insn {
        decode_insn(bytes, pc).expect("decode failed")
    }

    // ── Format III jumps ──────────────────────────────────────────────────────

    #[test]
    fn jmp_forward() {
        // JMP +0 at 0x4000 → target = 0x4002
        let insn = at(0x4000, &[0x00, 0x3C]);
        assert_eq!(insn.mnemonic(), "JMP");
        assert_eq!(insn.branch_target(), Some(0x4002));
        assert!(!insn.is_conditional());
        assert_eq!(insn.size, 2);
    }

    #[test]
    fn jne_backward() {
        // JNE backward at 0x4002 → target = 0x4000. PC after fetch = 0x4004,
        // so offset = (0x4000 - 0x4004)/2 = -2; 10-bit raw = 0x3FE.
        // word = 0b001_000_11_1111_1110 = 0x23FE (original test had 0x23FF which is offset -1).
        let insn = at(0x4002, &[0xFE, 0x23]);
        assert_eq!(insn.mnemonic(), "JNE");
        assert!(insn.is_conditional());
        assert_eq!(insn.branch_target(), Some(0x4000));
    }

    #[test]
    fn jeq_forward() {
        let insn = at(0x4000, &[0x00, 0x24]);
        assert_eq!(insn.mnemonic(), "JEQ");
        assert!(insn.is_conditional());
    }

    #[test]
    fn jnc_cond() {
        let insn = at(0x4000, &[0x00, 0x28]);
        assert_eq!(insn.mnemonic(), "JNC");
        assert!(insn.is_conditional());
    }

    #[test]
    fn jc_cond() {
        let insn = at(0x4000, &[0x00, 0x2C]);
        assert_eq!(insn.mnemonic(), "JC");
    }

    #[test]
    fn jn_cond() {
        let insn = at(0x4000, &[0x00, 0x30]);
        assert_eq!(insn.mnemonic(), "JN");
    }

    #[test]
    fn jge_cond() {
        let insn = at(0x4000, &[0x00, 0x34]);
        assert_eq!(insn.mnemonic(), "JGE");
    }

    #[test]
    fn jl_cond() {
        let insn = at(0x4000, &[0x00, 0x38]);
        assert_eq!(insn.mnemonic(), "JL");
    }

    // ── Format II single-operand ──────────────────────────────────────────────

    #[test]
    fn reti() {
        let insn = at(0x4000, &[0x00, 0x13]);
        assert_eq!(insn.mnemonic(), "RETI");
        assert!(insn.is_ret());
        assert_eq!(insn.size, 2);
    }

    #[test]
    fn call_immediate() {
        // CALL #0x4400
        let insn = at(0x4000, &[0xB0, 0x12, 0x00, 0x44]);
        assert_eq!(insn.mnemonic(), "CALL");
        assert!(insn.is_call());
        assert_eq!(insn.size, 4);
    }

    #[test]
    fn push_word_reg() {
        // PUSH.W R4: opcode3=4, bw=0, as=0, reg=4 = 0x1204
        let insn = at(0x4000, &[0x04, 0x12]);
        assert_eq!(insn.mnemonic(), "PUSH.W");
        assert_eq!(insn.size, 2);
    }

    #[test]
    fn push_byte() {
        // PUSH.B R4: opcode3=4, bw=1, as=0, reg=4 = 0x1244
        let insn = at(0x4000, &[0x44, 0x12]);
        assert_eq!(insn.mnemonic(), "PUSH.B");
    }

    #[test]
    fn rrc_word() {
        // RRC.W R4 = 0x1004
        let insn = at(0x4000, &[0x04, 0x10]);
        assert_eq!(insn.mnemonic(), "RRC.W");
    }

    #[test]
    fn rra_word() {
        // RRA.W R4: opcode3=2, bw=0, as=0, reg=4
        // 0x1000 | (2<<7) | 4 = 0x1000 | 0x100 | 4 = 0x1104
        let insn = at(0x4000, &[0x04, 0x11]);
        assert_eq!(insn.mnemonic(), "RRA.W");
    }

    #[test]
    fn swpb_reg() {
        // SWPB R4: opcode3=1, bw=0, as=0, reg=4 = 0x1084
        let insn = at(0x4000, &[0x84, 0x10]);
        assert_eq!(insn.mnemonic(), "SWPB");
    }

    #[test]
    fn sxt_reg() {
        // SXT R4: opcode3=3, as=0, reg=4
        // 0x1000 | (3<<7) | 4 = 0x1000 | 0x180 | 4 = 0x1184
        let insn = at(0x4000, &[0x84, 0x11]);
        assert_eq!(insn.mnemonic(), "SXT");
    }

    // ── Format I two-operand ──────────────────────────────────────────────────

    #[test]
    fn mov_reg_reg() {
        // MOV.W R4, R5 = 0x4504
        let insn = at(0x4000, &[0x04, 0x45]);
        assert_eq!(insn.mnemonic(), "MOV.W");
        assert_eq!(insn.size, 2);
    }

    #[test]
    fn mov_imm_reg() {
        // MOV.W #0x1234, R4
        let insn = at(0x4000, &[0x34, 0x40, 0x34, 0x12]);
        assert_eq!(insn.mnemonic(), "MOV.W");
        assert_eq!(insn.size, 4);
        if let InsnKind::TwoOp { src, .. } = &insn.kind {
            assert_eq!(src.ext, Some(0x1234));
        } else {
            panic!("expected TwoOp");
        }
    }

    #[test]
    fn add_word() {
        let insn = at(0x4000, &[0x04, 0x55]);
        assert_eq!(insn.mnemonic(), "ADD.W");
    }

    #[test]
    fn add_byte() {
        let insn = at(0x4000, &[0x44, 0x55]);
        assert_eq!(insn.mnemonic(), "ADD.B");
    }

    #[test]
    fn addc_word() {
        let insn = at(0x4000, &[0x04, 0x65]);
        assert_eq!(insn.mnemonic(), "ADDC.W");
    }

    #[test]
    fn subc_word() {
        let insn = at(0x4000, &[0x04, 0x75]);
        assert_eq!(insn.mnemonic(), "SUBC.W");
    }

    #[test]
    fn sub_word() {
        let insn = at(0x4000, &[0x04, 0x85]);
        assert_eq!(insn.mnemonic(), "SUB.W");
    }

    #[test]
    fn cmp_word() {
        let insn = at(0x4000, &[0x04, 0x95]);
        assert_eq!(insn.mnemonic(), "CMP.W");
    }

    #[test]
    fn dadd_word() {
        let insn = at(0x4000, &[0x04, 0xA5]);
        assert_eq!(insn.mnemonic(), "DADD.W");
    }

    #[test]
    fn bit_word() {
        let insn = at(0x4000, &[0x04, 0xB5]);
        assert_eq!(insn.mnemonic(), "BIT.W");
    }

    #[test]
    fn bic_word() {
        let insn = at(0x4000, &[0x04, 0xC5]);
        assert_eq!(insn.mnemonic(), "BIC.W");
    }

    #[test]
    fn bis_word() {
        let insn = at(0x4000, &[0x04, 0xD5]);
        assert_eq!(insn.mnemonic(), "BIS.W");
    }

    #[test]
    fn xor_word() {
        let insn = at(0x4000, &[0x04, 0xE5]);
        assert_eq!(insn.mnemonic(), "XOR.W");
    }

    #[test]
    fn and_word() {
        let insn = at(0x4000, &[0x04, 0xF5]);
        assert_eq!(insn.mnemonic(), "AND.W");
    }

    // ── Emulated instructions ─────────────────────────────────────────────────

    #[test]
    fn emulated_ret() {
        // MOV @SP+, PC = RET  (src=SP=R1, as=3=AutoInc, dst=PC=R0)
        // word = (4<<12)|(1<<8)|(0<<7)|(0<<6)|(3<<4)|0 = 0x4130
        let insn = at(0x4000, &[0x30, 0x41]);
        assert_eq!(insn.mnemonic(), "RET");
        assert!(insn.is_ret());
    }

    #[test]
    fn emulated_nop() {
        // MOV R4, R4 = NOP
        let insn = at(0x4000, &[0x04, 0x44]);
        assert_eq!(insn.mnemonic(), "NOP");
    }

    // ── Addressing modes ──────────────────────────────────────────────────────

    #[test]
    fn indexed_src() {
        // MOV.W 0x10(R4), R5  — src=indexed(R4), ext=0x0010, dst=R5
        // word = (4<<12)|(4<<8)|(0<<7)|(0<<6)|(1<<4)|5 = 0x4415
        let insn = at(0x4000, &[0x15, 0x44, 0x10, 0x00]);
        assert_eq!(insn.mnemonic(), "MOV.W");
        assert_eq!(insn.size, 4);
    }

    #[test]
    fn absolute_dst() {
        // MOV.W R4, &0x0200  — dst=absolute, ad=1, reg=R2, ext=0x0200
        // word = (4<<12)|(4<<8)|(1<<7)|(0<<6)|(0<<4)|2 = 0x4482
        let insn = at(0x4000, &[0x82, 0x44, 0x00, 0x02]);
        assert_eq!(insn.mnemonic(), "MOV.W");
        assert_eq!(insn.size, 4);
    }

    #[test]
    fn indirect_src() {
        // MOV.W @R4, R5 — as=2 indirect
        // word = (4<<12)|(4<<8)|(0<<7)|(0<<6)|(2<<4)|5 = 0x4425
        let insn = at(0x4000, &[0x25, 0x44]);
        assert_eq!(insn.mnemonic(), "MOV.W");
        if let InsnKind::TwoOp { src, .. } = &insn.kind {
            assert_eq!(src.mode, AddrMode::Indirect);
        }
    }

    #[test]
    fn indirect_autoinc() {
        // MOV.W @R4+, R5 — as=3
        let insn = at(0x4000, &[0x35, 0x44]);
        if let InsnKind::TwoOp { src, .. } = &insn.kind {
            assert_eq!(src.mode, AddrMode::IndirectAutoInc);
        }
    }

    // ── Truncated error ────────────────────────────────────────────────────────

    #[test]
    fn truncated_error() {
        assert!(decode_insn(&[0x04], 0x4000).is_err());
    }

    // ── decode_all / decode_block ─────────────────────────────────────────────

    #[test]
    fn decode_all_two_instrs() {
        let code = [0x04u8, 0x45, 0x04, 0x55]; // MOV.W R4,R5; ADD.W R4,R5
        let insns = decode_all(&code, 0x4000);
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].mnemonic(), "MOV.W");
        assert_eq!(insns[1].mnemonic(), "ADD.W");
    }

    #[test]
    fn decode_block_stops_at_ret() {
        let code = [0x04u8, 0x45, 0x30, 0x41, 0x04, 0x55]; // MOV; RET; ADD
        let block = decode_block(&code, 0x4000);
        assert_eq!(block.len(), 2); // only MOV and RET
        assert!(block[1].is_ret());
    }

    // ── Op2 / Op1 helpers ─────────────────────────────────────────────────────

    #[test]
    fn op2_test_only() {
        assert!(Op2::Cmp.is_test_only());
        assert!(Op2::Bit.is_test_only());
        assert!(!Op2::Add.is_test_only());
    }

    #[test]
    fn op2_updates_flags() {
        assert!(Op2::Add.updates_flags());
        assert!(!Op2::Mov.updates_flags());
        assert!(!Op2::Bic.updates_flags());
    }

    #[test]
    fn op1_uses_bw() {
        assert!(Op1::Rrc.uses_bw());
        assert!(Op1::Rra.uses_bw());
        assert!(Op1::Push.uses_bw());
        assert!(!Op1::Swpb.uses_bw());
        assert!(!Op1::Call.uses_bw());
    }
}
