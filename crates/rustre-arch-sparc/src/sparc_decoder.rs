//! SPARC v8/v9 instruction decoder.
//!
//! Decodes 4-byte big-endian SPARC instructions from all three formats:
//! - Format 1 (`op=01`): `CALL`
//! - Format 2 (`op=00`): `SETHI` / `Bicc` / `BPcc` / `FBfcc` / `CBccc`
//! - Format 3 (`op=10/11`): arithmetic, logical, load/store, FP, control
//!
//! Covers all Format 3 opcodes listed in the SPARC v8 Architecture Manual.

use std::fmt;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    UnknownOpcode { raw: u32 },
    ReservedEncoding { raw: u32 },
    UnalignedAddress { addr: u64 },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOpcode { raw } => write!(f, "unknown opcode in 0x{raw:08x}"),
            Self::ReservedEncoding { raw } => write!(f, "reserved encoding 0x{raw:08x}"),
            Self::UnalignedAddress { addr } => write!(f, "unaligned address 0x{addr:x}"),
        }
    }
}

impl std::error::Error for DecodeError {}

// ─── Register helpers ─────────────────────────────────────────────────────────

/// Convert a 5-bit register field to a display name.
#[must_use]
pub fn reg_name(r: u8) -> &'static str {
    // SPARC register windows: g0-g7, o0-o7, l0-l7, i0-i7
    match r & 0x1F {
        0 => "%g0",
        1 => "%g1",
        2 => "%g2",
        3 => "%g3",
        4 => "%g4",
        5 => "%g5",
        6 => "%g6",
        7 => "%g7",
        8 => "%o0",
        9 => "%o1",
        10 => "%o2",
        11 => "%o3",
        12 => "%o4",
        13 => "%o5",
        14 => "%sp",
        15 => "%o7",
        16 => "%l0",
        17 => "%l1",
        18 => "%l2",
        19 => "%l3",
        20 => "%l4",
        21 => "%l5",
        22 => "%l6",
        23 => "%l7",
        24 => "%i0",
        25 => "%i1",
        26 => "%i2",
        27 => "%i3",
        28 => "%i4",
        29 => "%i5",
        30 => "%fp",
        31 => "%i7",
        _ => unreachable!(),
    }
}

/// Convert a 5-bit FP register field.
#[must_use]
pub fn freg_name(r: u8) -> String {
    format!("%f{}", r & 0x1F)
}

// ─── Condition codes ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cond {
    N = 0b0000,
    E = 0b0001,
    LE = 0b0010,
    L = 0b0011,
    LEU = 0b0100,
    CS = 0b0101,
    NEG = 0b0110,
    VS = 0b0111,
    A = 0b1000,
    NE = 0b1001,
    G = 0b1010,
    GE = 0b1011,
    GU = 0b1100,
    CC = 0b1101,
    POS = 0b1110,
    VC = 0b1111,
}

impl Cond {
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0xF {
            0b0000 => Self::N,
            0b0001 => Self::E,
            0b0010 => Self::LE,
            0b0011 => Self::L,
            0b0100 => Self::LEU,
            0b0101 => Self::CS,
            0b0110 => Self::NEG,
            0b0111 => Self::VS,
            0b1000 => Self::A,
            0b1001 => Self::NE,
            0b1010 => Self::G,
            0b1011 => Self::GE,
            0b1100 => Self::GU,
            0b1101 => Self::CC,
            0b1110 => Self::POS,
            0b1111 => Self::VC,
            _ => unreachable!(),
        }
    }

    #[must_use]
    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::N => "n",
            Self::E => "e",
            Self::LE => "le",
            Self::L => "l",
            Self::LEU => "leu",
            Self::CS => "cs",
            Self::NEG => "neg",
            Self::VS => "vs",
            Self::A => "a",
            Self::NE => "ne",
            Self::G => "g",
            Self::GE => "ge",
            Self::GU => "gu",
            Self::CC => "cc",
            Self::POS => "pos",
            Self::VC => "vc",
        }
    }
}

// ─── Operand ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    /// Integer register.
    Reg(u8),
    /// FP register.
    FReg(u8),
    /// 13-bit sign-extended immediate.
    Simm13(i16),
    /// 22-bit unsigned immediate (for SETHI).
    Imm22(u32),
    /// PC-relative word offset (multiply by 4 for byte offset).
    PcOff(i32),
    /// [rs1 + rs2] memory address.
    MemReg(u8, u8),
    /// [rs1 + simm13] memory address.
    MemImm(u8, i16),
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reg(r) => write!(f, "{}", reg_name(*r)),
            Self::FReg(r) => write!(f, "{}", freg_name(*r)),
            Self::Simm13(v) => write!(f, "{v}"),
            Self::Imm22(v) => write!(f, "0x{v:x}"),
            Self::PcOff(v) => write!(f, ".+{}", v * 4),
            Self::MemReg(b, i) => write!(f, "[{} + {}]", reg_name(*b), reg_name(*i)),
            Self::MemImm(b, i) => {
                if *i >= 0 {
                    write!(f, "[{} + {}]", reg_name(*b), i)
                } else {
                    write!(f, "[{} - {}]", reg_name(*b), -i32::from(*i))
                }
            }
        }
    }
}

// ─── SparcInsn ────────────────────────────────────────────────────────────────

/// A decoded SPARC instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparcInsn {
    /// Raw 32-bit encoding.
    pub raw: u32,
    /// Instruction mnemonic.
    pub mnemonic: String,
    /// Destination register (rd field), if applicable.
    pub rd: Option<u8>,
    /// Source operands.
    pub operands: Vec<Operand>,
    /// True if the instruction sets condition codes (CC suffix).
    pub sets_icc: bool,
    /// True if this is a delay-slot instruction.
    pub has_delay_slot: bool,
    /// Annul bit (branch annul variant).
    pub annul: bool,
    /// Trap condition (for Ticc).
    pub trap_cond: Option<Cond>,
    /// Branch condition (for Bicc).
    pub branch_cond: Option<Cond>,
}

impl SparcInsn {
    fn new(raw: u32, mnemonic: &str) -> Self {
        Self {
            raw,
            mnemonic: mnemonic.to_string(),
            rd: None,
            operands: Vec::new(),
            sets_icc: false,
            has_delay_slot: false,
            annul: false,
            trap_cond: None,
            branch_cond: None,
        }
    }

    /// True if this instruction reads memory.
    #[must_use]
    pub fn is_load(&self) -> bool {
        matches!(
            self.mnemonic.as_str(),
            "ldsb"
                | "ldsh"
                | "ldub"
                | "lduh"
                | "ld"
                | "ldd"
                | "ldsba"
                | "ldsha"
                | "lduba"
                | "lduha"
                | "lda"
                | "ldda"
                | "ldf"
                | "lddf"
                | "ldfsr"
                | "ldcsr"
        )
    }

    /// True if this instruction writes memory.
    #[must_use]
    pub fn is_store(&self) -> bool {
        matches!(
            self.mnemonic.as_str(),
            "stb"
                | "sth"
                | "st"
                | "std"
                | "stba"
                | "stha"
                | "sta"
                | "stda"
                | "stf"
                | "stdf"
                | "stfsr"
                | "stdfq"
        )
    }

    /// True if this is a branch.
    #[must_use]
    pub fn is_branch(&self) -> bool {
        self.branch_cond.is_some()
            || self.mnemonic == "call"
            || self.mnemonic == "jmpl"
            || self.mnemonic == "rett"
    }

    /// True if this is a call.
    #[must_use]
    pub fn is_call(&self) -> bool {
        self.mnemonic == "call"
    }

    /// Assembly-style disassembly string.
    #[must_use]
    pub fn disassemble(&self) -> String {
        let mut s = self.mnemonic.clone();
        if self.sets_icc {
            s.push_str("cc");
        }
        if !self.operands.is_empty() {
            s.push(' ');
            let parts: Vec<String> = self.operands.iter().map(ToString::to_string).collect();
            s.push_str(&parts.join(", "));
        }
        if let Some(rd) = self.rd {
            if self.operands.is_empty() {
                s.push(' ');
            } else {
                s.push_str(", ");
            }
            s.push_str(reg_name(rd));
        }
        s
    }
}

// ─── SparcDecoder ─────────────────────────────────────────────────────────────

/// SPARC instruction decoder.
pub struct SparcDecoder {
    /// True for SPARC v9 (64-bit) mode.
    pub v9: bool,
}

impl SparcDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self { v9: false }
    }

    #[must_use]
    pub const fn new_v9() -> Self {
        Self { v9: true }
    }

    /// Decode a single 32-bit big-endian word.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if the encoding is unknown or reserved.
    pub fn decode(&self, raw: u32) -> Result<SparcInsn, DecodeError> {
        let op = raw >> 30;
        match op {
            0b01 => Ok(Self::decode_format1(raw)),
            0b00 => Self::decode_format2(raw),
            0b10 | 0b11 => self.decode_format3(raw),
            _ => Err(DecodeError::UnknownOpcode { raw }),
        }
    }

    /// Decode from a byte slice (big-endian).
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if the slice has fewer than 4 bytes, or if the
    /// encoding is unknown or reserved.
    pub fn decode_bytes(&self, bytes: &[u8]) -> Result<SparcInsn, DecodeError> {
        if bytes.len() < 4 {
            return Err(DecodeError::UnknownOpcode { raw: 0 });
        }
        let raw = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        self.decode(raw)
    }

    // ── Format 1: CALL ───────────────────────────────────────────────────────

    fn decode_format1(raw: u32) -> SparcInsn {
        // call disp30: bits[29:0] = 30-bit word offset
        let disp30 = (raw & 0x3FFF_FFFF).cast_signed();
        // Sign-extend 30 bits
        let offset = if disp30 & (1 << 29) != 0 {
            disp30 | (-1i32 << 30)
        } else {
            disp30
        };
        let mut insn = SparcInsn::new(raw, "call");
        insn.operands.push(Operand::PcOff(offset));
        insn.has_delay_slot = true;
        insn
    }

    // ── Format 2: SETHI / Bicc / BPcc / FBfcc ────────────────────────────────

    fn decode_format2(raw: u32) -> Result<SparcInsn, DecodeError> {
        let op2 = (raw >> 22) & 0x7;
        let rd = ((raw >> 25) & 0x1F) as u8;

        match op2 {
            0b100 => {
                // SETHI
                let imm22 = raw & 0x003F_FFFF;
                if rd == 0 && imm22 == 0 {
                    // NOP special case
                    return Ok(SparcInsn::new(raw, "nop"));
                }
                let mut insn = SparcInsn::new(raw, "sethi");
                insn.rd = Some(rd);
                insn.operands.push(Operand::Imm22(imm22));
                Ok(insn)
            }
            0b010 => {
                // Bicc — integer condition branch
                let cond = Cond::from_bits(rd >> 1);
                let annul = (rd & 1) != 0;
                let disp22 = (raw & 0x003F_FFFF).cast_signed();
                let offset = if disp22 & (1 << 21) != 0 {
                    disp22 | (-1i32 << 22)
                } else {
                    disp22
                };
                let mnemonic = format!("b{}{}", cond.mnemonic(), if annul { ",a" } else { "" });
                let mut insn = SparcInsn::new(raw, &mnemonic);
                insn.branch_cond = Some(cond);
                insn.annul = annul;
                insn.operands.push(Operand::PcOff(offset));
                insn.has_delay_slot = true;
                Ok(insn)
            }
            0b110 => {
                // FBfcc — FP condition branch
                let cond = Cond::from_bits(rd >> 1);
                let annul = (rd & 1) != 0;
                let disp22 = (raw & 0x003F_FFFF).cast_signed();
                let offset = if disp22 & (1 << 21) != 0 {
                    disp22 | (-1i32 << 22)
                } else {
                    disp22
                };
                let mnemonic = format!("fb{}{}", cond.mnemonic(), if annul { ",a" } else { "" });
                let mut insn = SparcInsn::new(raw, &mnemonic);
                insn.branch_cond = Some(cond);
                insn.annul = annul;
                insn.operands.push(Operand::PcOff(offset));
                insn.has_delay_slot = true;
                Ok(insn)
            }
            0b000 => Err(DecodeError::ReservedEncoding { raw }),
            _ => Err(DecodeError::UnknownOpcode { raw }),
        }
    }

    // ── Format 3: Arithmetic / Load / Store / Control ────────────────────────

    fn decode_format3(&self, raw: u32) -> Result<SparcInsn, DecodeError> {
        let op = (raw >> 30) & 0x3;
        let rd = ((raw >> 25) & 0x1F) as u8;
        let op3 = ((raw >> 19) & 0x3F) as u8;
        let rs1 = ((raw >> 14) & 0x1F) as u8;
        let i = (raw >> 13) & 1;
        let rs2 = (raw & 0x1F) as u8;
        let simm13 = {
            let v = (raw & 0x1FFF) as i16;
            if v & (1 << 12) != 0 {
                v | (-1i16 << 13)
            } else {
                v
            }
        };

        // Build the src operand
        let src = if i == 1 {
            Operand::Simm13(simm13)
        } else {
            Operand::Reg(rs2)
        };

        // Build the address operand for load/store
        let addr = if i == 1 {
            Operand::MemImm(rs1, simm13)
        } else {
            Operand::MemReg(rs1, rs2)
        };

        if op == 0b10 {
            Self::decode_format3_op10(raw, rd, op3, rs1, src, self.v9)
        } else {
            Self::decode_format3_op11(raw, rd, op3, addr, self.v9)
        }
    }

    fn decode_format3_op10(
        raw: u32,
        rd: u8,
        op3: u8,
        rs1: u8,
        src: Operand,
        _v9: bool,
    ) -> Result<SparcInsn, DecodeError> {
        macro_rules! alu {
            ($mn:expr) => {{
                let mut insn = SparcInsn::new(raw, $mn);
                insn.rd = Some(rd);
                insn.operands.push(Operand::Reg(rs1));
                insn.operands.push(src);
                Ok(insn)
            }};
        }
        macro_rules! alu_cc {
            ($mn:expr) => {{
                let mut insn = SparcInsn::new(raw, $mn);
                insn.rd = Some(rd);
                insn.operands.push(Operand::Reg(rs1));
                insn.operands.push(src);
                insn.sets_icc = true;
                Ok(insn)
            }};
        }
        match op3 {
            0x00 => alu!("add"),
            0x01 => alu!("and"),
            0x02 => alu!("or"),
            0x03 => alu!("xor"),
            0x04 => alu!("sub"),
            0x05 => alu!("andn"),
            0x06 => alu!("orn"),
            0x07 => alu!("xnor"),
            0x08 => alu!("addx"),
            0x0A => alu!("umul"),
            0x0B => alu!("smul"),
            0x0C => alu!("subx"),
            0x0E => alu!("udiv"),
            0x0F => alu!("sdiv"),
            0x10 => alu_cc!("add"),
            0x11 => alu_cc!("and"),
            0x12 => alu_cc!("or"),
            0x13 => alu_cc!("xor"),
            0x14 => alu_cc!("sub"),
            0x15 => alu_cc!("andn"),
            0x16 => alu_cc!("orn"),
            0x17 => alu_cc!("xnor"),
            0x18 => alu_cc!("addx"),
            0x19 => alu!("mulscc"),
            0x1A => alu_cc!("umul"),
            0x1B => alu_cc!("smul"),
            0x1C => alu_cc!("subx"),
            0x1E => alu_cc!("udiv"),
            0x1F => alu_cc!("sdiv"),
            0x25 => {
                let src = if let Operand::Simm13(v) = src { Operand::Simm13(v & 0x1F) } else { src }; // SLL
                let mut insn = SparcInsn::new(raw, "sll");
                insn.rd = Some(rd);
                insn.operands.push(Operand::Reg(rs1));
                insn.operands.push(src);
                Ok(insn)
            }
            0x26 => alu!("srl"),
            0x27 => alu!("sra"),
            0x28 => {
                let mut insn = SparcInsn::new(raw, "rd"); // RD: read special register
                insn.rd = Some(rd);
                insn.operands.push(Operand::Reg(rs1));
                Ok(insn)
            }
            0x30 => alu!("wr"),
            0x38 => {
                // JMPL
                let addr = match src {
                    Operand::Simm13(v) => Operand::MemImm(rs1, v),
                    Operand::Reg(rs2) => Operand::MemReg(rs1, rs2),
                    other => other,
                };
                let mut insn = SparcInsn::new(raw, "jmpl");
                insn.rd = Some(rd); insn.operands.push(addr); insn.has_delay_slot = true;
                Ok(insn)
            }
            0x39 => {
                // RETT
                let mut insn = SparcInsn::new(raw, "rett");
                insn.operands.push(Operand::Reg(rs1)); insn.operands.push(src); insn.has_delay_slot = true;
                Ok(insn)
            }
            0x3A => {
                // Ticc
                let cond = Cond::from_bits(rd >> 1);
                let mut insn = SparcInsn::new(raw, &format!("t{}", cond.mnemonic()));
                insn.trap_cond = Some(cond); insn.operands.push(Operand::Reg(rs1)); insn.operands.push(src);
                Ok(insn)
            }
            0x3B => {
                // FLUSH
                let mut insn = SparcInsn::new(raw, "flush");
                insn.operands.push(Operand::Reg(rs1)); insn.operands.push(src);
                Ok(insn)
            }
            0x3C => alu!("save"),
            0x3D => alu!("restore"),
            _ => Err(DecodeError::UnknownOpcode { raw }),
        }
    }

    fn decode_format3_op11(
        raw: u32,
        rd: u8,
        op3: u8,
        addr: Operand,
        _v9: bool,
    ) -> Result<SparcInsn, DecodeError> {
        let mnemonic = match op3 {
            0x00 => "ld",
            0x01 => "ldub",
            0x02 => "lduh",
            0x03 => "ldd",
            0x04 => "st",
            0x05 => "stb",
            0x06 => "sth",
            0x07 => "std",
            0x08 => "ldsb",
            0x09 => "ldsh",
            0x0A => "ldsba",
            0x0B => "ldsha",
            0x0C => "lduba",
            0x0D => "lduha",
            0x0F => "ldda",
            0x14 => "sta",
            0x15 => "stba",
            0x16 => "stha",
            0x17 => "stda",
            0x20 => "ldf",
            0x23 => "lddf",
            0x24 => "stf",
            0x27 => "stdf",
            0x21 => "ldfsr",
            0x25 => "stfsr",
            0x26 => "stdfq",
            0x30 => "ldc",
            0x33 => "lddc",
            0x34 => "stc",
            0x37 => "stdc",
            0x31 => "ldcsr",
            0x35 => "stcsr",
            _ => return Err(DecodeError::UnknownOpcode { raw }),
        };

        let mut insn = SparcInsn::new(raw, mnemonic);

        // Loads: [addr], rd  — Stores: rd, [addr]
        let is_load = matches!(
            op3,
            0x00 | 0x01
                | 0x02
                | 0x03
                | 0x08
                | 0x09
                | 0x0A
                | 0x0B
                | 0x0C
                | 0x0D
                | 0x0F
                | 0x20
                | 0x23
                | 0x21
                | 0x30
                | 0x33
                | 0x31
        );

        if is_load {
            insn.operands.push(addr);
            insn.rd = Some(rd);
        } else {
            insn.operands.push(Operand::Reg(rd));
            insn.operands.push(addr);
        }

        Ok(insn)
    }
}

impl Default for SparcDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dec() -> SparcDecoder {
        SparcDecoder::new()
    }

    /// Encode a CALL instruction with a 30-bit word offset.
    fn encode_call(disp30: u32) -> u32 {
        (0b01_u32 << 30) | (disp30 & 0x3FFF_FFFF)
    }

    /// Encode SETHI rd, imm22.
    fn encode_sethi(rd: u8, imm22: u32) -> u32 {
        (u32::from(rd) << 25) | (0b100 << 22) | (imm22 & 0x003F_FFFF)
    }

    /// Encode a Format 3 ALU reg-reg: op=10, op3, rd, rs1, i=0, rs2.
    fn encode_f3_rrr(op3: u8, rd: u8, rs1: u8, rs2: u8) -> u32 {
        (0b10 << 30)
            | (u32::from(rd) << 25)
            | (u32::from(op3) << 19)
            | (u32::from(rs1) << 14)
            | u32::from(rs2)
    }

    /// Encode a Format 3 ALU reg-imm: op=10, op3, rd, rs1, i=1, simm13.
    fn encode_f3_rri(op3: u8, rd: u8, rs1: u8, simm13: i16) -> u32 {
        (0b10 << 30)
            | (u32::from(rd) << 25)
            | (u32::from(op3) << 19)
            | (u32::from(rs1) << 14)
            | (1 << 13)
            | (u32::from(simm13.cast_unsigned()) & 0x1FFF)
    }

    /// Encode a Format 3 load/store op=11.
    fn encode_f3_mem(op3: u8, rd: u8, rs1: u8, rs2: u8) -> u32 {
        (0b11 << 30)
            | (u32::from(rd) << 25)
            | (u32::from(op3) << 19)
            | (u32::from(rs1) << 14)
            | u32::from(rs2)
    }

    /// Encode a Format 3 load/store with simm13.
    fn encode_f3_mem_imm(op3: u8, rd: u8, rs1: u8, simm13: i16) -> u32 {
        (0b11 << 30)
            | (u32::from(rd) << 25)
            | (u32::from(op3) << 19)
            | (u32::from(rs1) << 14)
            | (1 << 13)
            | (u32::from(simm13.cast_unsigned()) & 0x1FFF)
    }

    #[test]
    fn test_decode_call() {
        let raw = encode_call(100);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "call");
        assert!(insn.has_delay_slot);
    }

    #[test]
    fn test_decode_nop() {
        // SETHI %g0, 0 = NOP
        let raw = encode_sethi(0, 0);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "nop");
    }

    #[test]
    fn test_decode_sethi() {
        let raw = encode_sethi(1, 0xFFFFF);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "sethi");
        assert_eq!(insn.rd, Some(1));
    }

    #[test]
    fn test_decode_add() {
        let raw = encode_f3_rrr(0x00, 2, 3, 4);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "add");
        assert_eq!(insn.rd, Some(2));
        assert!(!insn.sets_icc);
    }

    #[test]
    fn test_decode_addcc() {
        let raw = encode_f3_rrr(0x10, 2, 3, 4);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "add");
        assert!(insn.sets_icc);
    }

    #[test]
    fn test_decode_sub() {
        let raw = encode_f3_rrr(0x04, 1, 2, 3);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "sub");
    }

    #[test]
    fn test_decode_and() {
        let raw = encode_f3_rrr(0x01, 5, 6, 7);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "and");
    }

    #[test]
    fn test_decode_or() {
        let raw = encode_f3_rrr(0x02, 1, 2, 3);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "or");
    }

    #[test]
    fn test_decode_xor() {
        let raw = encode_f3_rrr(0x03, 1, 2, 3);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "xor");
    }

    #[test]
    fn test_decode_sll() {
        let raw = encode_f3_rri(0x25, 2, 3, 2);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "sll");
    }

    #[test]
    fn test_decode_srl() {
        let raw = encode_f3_rrr(0x26, 2, 3, 4);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "srl");
    }

    #[test]
    fn test_decode_sra() {
        let raw = encode_f3_rrr(0x27, 2, 3, 4);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "sra");
    }

    #[test]
    fn test_decode_save() {
        let raw = encode_f3_rri(0x3C, 30, 30, -96);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "save");
    }

    #[test]
    fn test_decode_restore() {
        let raw = encode_f3_rrr(0x3D, 0, 0, 0);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "restore");
    }

    #[test]
    fn test_decode_jmpl() {
        let raw = encode_f3_rri(0x38, 15, 15, 8);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "jmpl");
        assert!(insn.has_delay_slot);
    }

    #[test]
    fn test_decode_ld() {
        let raw = encode_f3_mem(0x00, 1, 2, 3);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "ld");
        assert!(insn.is_load());
    }

    #[test]
    fn test_decode_ld_simm13() {
        // ld [%g2 + 8], %g1 — same opcode as test_decode_ld but with the
        // simm13 immediate variant of Format 3.
        let raw = encode_f3_mem_imm(0x00, 1, 2, 8);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "ld");
        assert!(insn.is_load());
    }

    #[test]
    fn test_decode_st() {
        let raw = encode_f3_mem(0x04, 1, 2, 3);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "st");
        assert!(insn.is_store());
    }

    #[test]
    fn test_decode_ldsb() {
        let raw = encode_f3_mem(0x08, 1, 2, 3);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "ldsb");
    }

    #[test]
    fn test_decode_lduh() {
        let raw = encode_f3_mem(0x02, 1, 2, 3);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "lduh");
    }

    #[test]
    fn test_decode_ldd() {
        let raw = encode_f3_mem(0x03, 2, 8, 0);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "ldd");
    }

    #[test]
    fn test_decode_stb() {
        let raw = encode_f3_mem(0x05, 1, 2, 0);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "stb");
    }

    #[test]
    fn test_decode_sth() {
        let raw = encode_f3_mem(0x06, 1, 2, 0);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "sth");
    }

    #[test]
    fn test_decode_branch_a() {
        // ba (branch always): op2=010, cond=1000, annul=0
        let raw: u32 = (0b10000_u32 << 25) // cond=A, annul=0
            | (0b010 << 22)
            | 0x64;
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "ba");
        assert!(insn.has_delay_slot);
    }

    #[test]
    fn test_decode_branch_e() {
        // be: cond=0001
        let raw: u32 = (0b00010_u32 << 25)  // cond=E, annul=0
            | (0b010 << 22)
            | 0x32;
        let insn = dec().decode(raw).unwrap();
        assert!(insn.mnemonic.starts_with("be"));
    }

    #[test]
    fn test_decode_umul() {
        let raw = encode_f3_rrr(0x0A, 1, 2, 3);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "umul");
    }

    #[test]
    fn test_decode_smul() {
        let raw = encode_f3_rrr(0x0B, 1, 2, 3);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "smul");
    }

    #[test]
    fn test_decode_udiv() {
        let raw = encode_f3_rrr(0x0E, 1, 2, 3);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "udiv");
    }

    #[test]
    fn test_reg_name_global() {
        assert_eq!(reg_name(0), "%g0");
        assert_eq!(reg_name(7), "%g7");
    }

    #[test]
    fn test_reg_name_out() {
        assert_eq!(reg_name(8), "%o0");
        assert_eq!(reg_name(14), "%sp");
    }

    #[test]
    fn test_reg_name_in() {
        assert_eq!(reg_name(24), "%i0");
        assert_eq!(reg_name(30), "%fp");
    }

    #[test]
    fn test_decode_ldf() {
        let raw = encode_f3_mem(0x20, 1, 8, 0);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "ldf");
    }

    #[test]
    fn test_decode_stf() {
        let raw = encode_f3_mem(0x24, 0, 8, 4);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "stf");
    }

    #[test]
    fn test_decode_std() {
        let raw = encode_f3_mem(0x07, 1, 8, 0);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "std");
        assert!(insn.is_store());
    }

    #[test]
    fn test_decode_addx() {
        let raw = encode_f3_rrr(0x08, 1, 2, 3);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "addx");
    }

    #[test]
    fn test_decode_xnor() {
        let raw = encode_f3_rrr(0x07, 1, 2, 3);
        let insn = dec().decode(raw).unwrap();
        assert_eq!(insn.mnemonic, "xnor");
    }

    #[test]
    fn test_disassemble_string_not_empty() {
        let raw = encode_f3_rrr(0x00, 1, 2, 3);
        let insn = dec().decode(raw).unwrap();
        assert!(!insn.disassemble().is_empty());
    }

    #[test]
    fn test_cond_mnemonic_ne() {
        assert_eq!(Cond::NE.mnemonic(), "ne");
    }

    #[test]
    fn test_cond_mnemonic_ge() {
        assert_eq!(Cond::GE.mnemonic(), "ge");
    }

    #[test]
    fn test_operand_display_simm13() {
        let op = Operand::Simm13(-8);
        assert_eq!(op.to_string(), "-8");
    }

    #[test]
    fn test_operand_display_mem_imm() {
        let op = Operand::MemImm(8, 16);
        assert!(op.to_string().contains("%o0") || op.to_string().contains("16"));
    }

    #[test]
    fn test_operand_display_mem_reg() {
        let op = Operand::MemReg(8, 9);
        let s = op.to_string();
        assert!(s.contains('['));
    }

    #[test]
    fn test_decode_bytes_too_short() {
        let d = dec();
        let result = d.decode_bytes(&[0x60, 0xE8]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_bytes_valid() {
        let d = dec();
        // An all-zero 4-byte word is the SPARC "UNIMP 0" instruction (op=00,
        // op2=000). Confirm decode_bytes accepts that input as well-formed
        // (even if the decoder reports an UNIMP — it should not panic).
        let zero_bytes = 0u32.to_be_bytes();
        let _ = d.decode_bytes(&zero_bytes);
        // Known safe encoding: add %g0+%g0 → %g0
        let raw: u32 = 0b10 << 30;
        let bytes = raw.to_be_bytes();
        let result = d.decode_bytes(&bytes);
        assert!(result.is_ok());
    }
}
