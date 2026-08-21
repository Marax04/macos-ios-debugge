//! AVR instruction decoder — full 16/32-bit opcode set.
//!
//! All AVR instruction classes are decoded: arithmetic, logical, data transfer,
//! branch, and I/O operations.

// ── Address type ──────────────────────────────────────────────────────────────

/// A byte-addressed code location in AVR flash (22-bit maximum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AvrAddr(pub u32);

impl AvrAddr {
    #[must_use]
    pub const fn as_u32(self) -> u32 { self.0 & 0x3F_FFFF }
}

impl std::fmt::Display for AvrAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:06X}", self.0 & 0x3F_FFFF)
    }
}

// ── Operand ───────────────────────────────────────────────────────────────────

/// An operand for a decoded AVR instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvrOperand {
    /// General register Rd (0-31).
    Reg(u8),
    /// Register pair (hi, lo) e.g. X = (R27, R26).
    RegPair(u8, u8),
    /// Register pair with post-increment: X+.
    RegPairPostInc(u8, u8),
    /// Register pair with pre-decrement: -X.
    RegPairPreDec(u8, u8),
    /// 8-bit unsigned immediate constant K.
    Imm8(u8),
    /// 6-bit unsigned immediate (ADIW/SBIW).
    Imm6(u8),
    /// 12-bit signed relative jump offset in words (RJMP/RCALL) – stored as i16.
    RelOffset12(i16),
    /// 7-bit signed relative branch offset in words (BRXX) – stored as i8.
    RelOffset7(i8),
    /// 16-bit absolute data-space address (LDS/STS).
    DataAddr(u16),
    /// 22-bit absolute flash word address (JMP/CALL).
    FlashAddr(u32),
    /// I/O port address (6-bit, 0x00-0x3F).
    IoPort(u8),
    /// I/O port address with bit index: (port, bit).
    IoPortBit(u8, u8),
    /// Bit index (0-7).
    Bit(u8),
    /// Y or Z with 6-bit displacement (`LDD`/`STD`): (`base_reg`=28 or 30, q).
    IndexDisp(u8, u8),
}

impl AvrOperand {
    /// Format as assembly text.
    #[must_use]
    pub fn format(&self) -> String {
        match self {
            Self::Reg(r) => format!("R{r}"),
            Self::RegPair(h, l) => format!("R{h}:R{l}"),
            Self::RegPairPostInc(h, _) => {
                match h {
                    27 => "X+".to_string(),
                    29 => "Y+".to_string(),
                    31 => "Z+".to_string(),
                    _ => format!("R{}+", h - 1),
                }
            }
            Self::RegPairPreDec(h, _) => {
                match h {
                    27 => "-X".to_string(),
                    29 => "-Y".to_string(),
                    31 => "-Z".to_string(),
                    _ => format!("-R{}", h - 1),
                }
            }
            Self::Imm8(k) => format!("0x{k:02X}"),
            Self::Imm6(k) => format!("{k}"),
            Self::RelOffset12(o) => format!("{o:+}"),
            Self::RelOffset7(o) => format!("{o:+}"),
            Self::DataAddr(a) => format!("0x{a:04X}"),
            Self::FlashAddr(a) => format!("0x{a:06X}"),
            Self::IoPort(a) => format!("0x{a:02X}"),
            Self::IoPortBit(a, b) => format!("0x{a:02X},{b}"),
            Self::Bit(b) => format!("{b}"),
            Self::IndexDisp(base, q) => {
                let name = if *base == 28 { "Y" } else { "Z" };
                if *q == 0 { name.to_string() } else { format!("{name}+{q}") }
            }
        }
    }
}

// ── Decoded instruction ───────────────────────────────────────────────────────

/// Broad opcode category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvrOpcode {
    Nop, Add, Adc, Adiw, Sub, Subi, Sbc, Sbci, Sbiw,
    And, Andi, Or, Ori, Eor, Com, Neg, Inc, Dec,
    Mul, Muls, Mulsu, Fmul, Fmuls, Fmulsu,
    Lsr, Ror, Asr, Swap, Bset, Bclr, Bst, Bld,
    Sbi, Cbi, Sbic, Sbis,
    Cp, Cpc, Cpi, Cpse,
    Mov, Movw, Ldi,
    Ld, Ldd, Lds, St, Std, Sts, Push, Pop,
    In, Out,
    Lpm, Elpm, Spm,
    Rjmp, Rcall, Jmp, Call, Ret, Reti, Ijmp, Icall, Eijmp, Eicall,
    Brbs, Brbc,
    Sbrc, Sbrs,
    Sleep, Wdr, Break,
    Unknown,
}

/// Properties of a decoded instruction, packed as one bit set.
///
/// Six adjacent `bool` fields are interchangeable to the compiler; a single
/// bit set with named constants cannot be filled in the wrong order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AvrInstrFlags(u8);

impl AvrInstrFlags {
    /// The instruction reads data memory.
    pub const READS_MEM: u8 = 1 << 0;
    /// The instruction writes data memory.
    pub const WRITES_MEM: u8 = 1 << 1;
    /// The instruction is a call.
    pub const IS_CALL: u8 = 1 << 2;
    /// The instruction is a return.
    pub const IS_RET: u8 = 1 << 3;
    /// The instruction is a conditional branch.
    pub const IS_CONDITIONAL: u8 = 1 << 4;
    /// The instruction is an unconditional branch.
    pub const IS_BRANCH: u8 = 1 << 5;

    /// Every bit this type tracks.
    pub const MASK: u8 = Self::READS_MEM
        | Self::WRITES_MEM
        | Self::IS_CALL
        | Self::IS_RET
        | Self::IS_CONDITIONAL
        | Self::IS_BRANCH;

    /// No property set.
    pub const NONE: Self = Self(0);

    /// Keep only the bits this type tracks.
    #[must_use]
    pub const fn from_bits(v: u8) -> Self { Self(v & Self::MASK) }

    /// The raw bit image.
    #[must_use]
    pub const fn bits(self) -> u8 { self.0 }

    /// True when `bit` (one of the associated constants) is set.
    #[must_use]
    pub const fn has(self, bit: u8) -> bool { self.0 & bit != 0 }

    /// A copy with `bit` set (`on`) or cleared.
    #[must_use]
    pub const fn with(self, bit: u8, on: bool) -> Self {
        if on { Self(self.0 | (bit & Self::MASK)) } else { Self(self.0 & !bit) }
    }

    /// Set or clear `bit` in place.
    pub const fn set(&mut self, bit: u8, on: bool) {
        *self = self.with(bit, on);
    }
}

impl core::ops::BitOr for AvrInstrFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
}

/// A fully decoded AVR instruction.
#[derive(Debug, Clone)]
pub struct AvrInstr {
    /// Raw bytes (2 or 4).
    pub raw: [u8; 4],
    /// Instruction length in bytes (2 or 4).
    pub len: u8,
    /// Opcode category.
    pub opcode: AvrOpcode,
    /// Mnemonic string.
    pub mnemonic: String,
    /// Decoded operands (0, 1, or 2).
    pub operands: Vec<AvrOperand>,
    /// PC-relative absolute branch target (byte address), if applicable.
    pub branch_target: Option<AvrAddr>,
    /// Instruction property bits.
    pub flags: AvrInstrFlags,
}

impl AvrInstr {
    /// Whether this instruction has the `READS_MEM` property.
    #[must_use]
    pub const fn reads_mem(&self) -> bool { self.flags.has(AvrInstrFlags::READS_MEM) }
    /// Set the `READS_MEM` property.
    pub const fn set_reads_mem(&mut self, on: bool) { self.flags.set(AvrInstrFlags::READS_MEM, on); }
    /// Whether this instruction has the `WRITES_MEM` property.
    #[must_use]
    pub const fn writes_mem(&self) -> bool { self.flags.has(AvrInstrFlags::WRITES_MEM) }
    /// Set the `WRITES_MEM` property.
    pub const fn set_writes_mem(&mut self, on: bool) { self.flags.set(AvrInstrFlags::WRITES_MEM, on); }
    /// Whether this instruction has the `IS_CALL` property.
    #[must_use]
    pub const fn is_call(&self) -> bool { self.flags.has(AvrInstrFlags::IS_CALL) }
    /// Set the `IS_CALL` property.
    pub const fn set_is_call(&mut self, on: bool) { self.flags.set(AvrInstrFlags::IS_CALL, on); }
    /// Whether this instruction has the `IS_RET` property.
    #[must_use]
    pub const fn is_ret(&self) -> bool { self.flags.has(AvrInstrFlags::IS_RET) }
    /// Set the `IS_RET` property.
    pub const fn set_is_ret(&mut self, on: bool) { self.flags.set(AvrInstrFlags::IS_RET, on); }
    /// Whether this instruction has the `IS_CONDITIONAL` property.
    #[must_use]
    pub const fn is_conditional(&self) -> bool { self.flags.has(AvrInstrFlags::IS_CONDITIONAL) }
    /// Set the `IS_CONDITIONAL` property.
    pub const fn set_is_conditional(&mut self, on: bool) { self.flags.set(AvrInstrFlags::IS_CONDITIONAL, on); }
    /// Whether this instruction has the `IS_BRANCH` property.
    #[must_use]
    pub const fn is_branch(&self) -> bool { self.flags.has(AvrInstrFlags::IS_BRANCH) }
    /// Set the `IS_BRANCH` property.
    pub const fn set_is_branch(&mut self, on: bool) { self.flags.set(AvrInstrFlags::IS_BRANCH, on); }

    /// Format operands separated by ", ".
    #[must_use]
    pub fn operand_string(&self) -> String {
        self.operands.iter().map(AvrOperand::format).collect::<Vec<_>>().join(", ")
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn rdrr(word: u16) -> (u8, u8) {
    let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX);
    let r = u8::try_from(((word & 0x0200) >> 5) | (word & 0x0F)).unwrap_or(u8::MAX);
    (d, r)
}

const fn sign_ext_12(w: u16) -> i16 {
    let v = (w & 0x0FFF).cast_signed();
    if v & 0x0800 != 0 { v - 0x1000 } else { v }
}

fn branch_target_12(pc: u32, offset: i16) -> AvrAddr {
    // PC after fetch = pc + 2; offset in words → bytes = offset*2
    let target = i64::from(pc) + 2 + i64::from(offset) * 2;
    AvrAddr(u32::try_from(target & 0x3F_FFFF).unwrap_or(0))
}

fn branch_target_7(pc: u32, offset: i8) -> AvrAddr {
    let target = i64::from(pc) + 2 + i64::from(offset) * 2;
    AvrAddr(u32::try_from(target & 0x3F_FFFF).unwrap_or(0))
}

fn simple_instr(raw2: u16, opcode: AvrOpcode, mn: &str) -> AvrInstr {
    AvrInstr {
        raw: [u8::try_from(raw2 & 0xFF).unwrap_or(u8::MAX), u8::try_from(raw2 >> 8).unwrap_or(u8::MAX), 0, 0],
        len: 2,
        opcode,
        mnemonic: mn.to_string(),
        operands: vec![],
        branch_target: None,
                flags: AvrInstrFlags::NONE,
    }
}

fn reg_instr(raw2: u16, opcode: AvrOpcode, mn: &str, d: u8, r: u8) -> AvrInstr {
    AvrInstr {
        raw: [u8::try_from(raw2 & 0xFF).unwrap_or(u8::MAX), u8::try_from(raw2 >> 8).unwrap_or(u8::MAX), 0, 0],
        len: 2, opcode, mnemonic: mn.to_string(),
        operands: vec![AvrOperand::Reg(d), AvrOperand::Reg(r)],
        branch_target: None,
                flags: AvrInstrFlags::NONE,
    }
}

fn reg_imm_instr(raw2: u16, opcode: AvrOpcode, mn: &str, d: u8, k: u8) -> AvrInstr {
    AvrInstr {
        raw: [u8::try_from(raw2 & 0xFF).unwrap_or(u8::MAX), u8::try_from(raw2 >> 8).unwrap_or(u8::MAX), 0, 0],
        len: 2, opcode, mnemonic: mn.to_string(),
        operands: vec![AvrOperand::Reg(d), AvrOperand::Imm8(k)],
        branch_target: None,
                flags: AvrInstrFlags::NONE,
    }
}

// ── The Decoder ───────────────────────────────────────────────────────────────

/// AVR instruction decoder.
///
/// Stateless beyond the `avr32` flag that enables 22-bit address decoding.
#[derive(Debug, Clone, Copy, Default)]
pub struct AvrDecoder {
    /// Enable 22-bit (CALL/JMP) and EIJMP/EICALL for large-flash devices.
    pub avr32: bool,
}

impl AvrDecoder {
    /// Create a decoder for standard `ATmega` devices (<= 128 KB flash).
    #[must_use]
    pub const fn new() -> Self { Self { avr32: false } }
    /// Create a decoder for large-flash devices (`ATmega2560` etc., > 128 KB).
    #[must_use]
    pub const fn new_large() -> Self { Self { avr32: true } }

    /// Decode one instruction from a little-endian byte slice.
    ///
    /// Returns `None` if fewer than 2 bytes are available.
    #[must_use]
    pub fn decode(&self, pc: u32, bytes: &[u8]) -> Option<AvrInstr> {
        if bytes.len() < 2 { return None; }
        let word = u16::from_le_bytes([bytes[0], bytes[1]]);
        Some(Self::decode_word(pc, word, bytes))
    }

    /// Decode one already-fetched opcode word.
    ///
    /// Total by construction: a word matching no encoding is still returned, as
    /// a `DC.W` data word, so this never yields "no answer" for a 2-byte input.
    fn decode_word(pc: u32, word: u16, bytes: &[u8]) -> AvrInstr {
        // Fixed single-byte equivalents
        if let Some(i) = Self::decode_fixed(pc, word) { return i; }
        if let Some(i) = Self::decode_alu(word) { return i; }
        if let Some(i) = Self::decode_mem(word, bytes) { return i; }
        if let Some(i) = Self::decode_branch(pc, word, bytes) { return i; }
        // Unknown
        AvrInstr {
            raw: [bytes[0], bytes[1], 0, 0],
            len: 2, opcode: AvrOpcode::Unknown,
            mnemonic: "DC.W".to_string(),
            operands: vec![AvrOperand::Imm8(u8::try_from(word).unwrap_or(u8::MAX))],
            branch_target: None,
                        flags: AvrInstrFlags::NONE,
        }
    }

    fn decode_fixed(pc: u32, word: u16) -> Option<AvrInstr> {
        let _ = pc;
        match word {
            0x0000 => Some(simple_instr(word, AvrOpcode::Nop, "NOP")),
            0x9508 => Some({
                let mut i = simple_instr(word, AvrOpcode::Ret, "RET");
                i.set_is_ret(true); i
            }),
            0x9518 => Some({ let mut i = simple_instr(word, AvrOpcode::Reti, "RETI"); i.set_is_ret(true); i }),
            0x9409 => Some({ let mut i = simple_instr(word, AvrOpcode::Ijmp, "IJMP"); i.set_is_branch(true); i }),
            0x9509 => Some({ let mut i = simple_instr(word, AvrOpcode::Icall, "ICALL"); i.set_is_call(true); i }),
            0x9419 => Some({ let mut i = simple_instr(word, AvrOpcode::Eijmp, "EIJMP"); i.set_is_branch(true); i }),
            0x9519 => Some({ let mut i = simple_instr(word, AvrOpcode::Eicall, "EICALL"); i.set_is_call(true); i }),
            0x95C8 => Some({ let mut i = simple_instr(word, AvrOpcode::Lpm, "LPM"); i.set_reads_mem(true); i }),
            0x95E8 => Some({ let mut i = simple_instr(word, AvrOpcode::Spm, "SPM"); i.set_writes_mem(true); i }),
            0x9588 => Some(simple_instr(word, AvrOpcode::Sleep, "SLEEP")),
            0x95A8 => Some(simple_instr(word, AvrOpcode::Wdr, "WDR")),
            0x9598 => Some(simple_instr(word, AvrOpcode::Break, "BREAK")),
            _ => None,
        }
    }

    fn decode_alu(word: u16) -> Option<AvrInstr> {
        // ADD
        if (word & 0xFC00) == 0x0C00 { let (d,r) = rdrr(word); return Some(reg_instr(word, AvrOpcode::Add, "ADD", d, r)); }
        // ADC
        if (word & 0xFC00) == 0x1C00 { let (d,r) = rdrr(word); return Some(reg_instr(word, AvrOpcode::Adc, "ADC", d, r)); }
        // ADIW
        if (word & 0xFF00) == 0x9600 {
            let d = u8::try_from(24 + (((word >> 4) & 3) * 2)).unwrap_or(u8::MAX);
            let k = u8::try_from(((word & 0xC0) >> 2) | (word & 0x0F)).unwrap_or(u8::MAX);
            let mut i = simple_instr(word, AvrOpcode::Adiw, "ADIW");
            i.operands = vec![AvrOperand::RegPair(d+1, d), AvrOperand::Imm6(k)];
            return Some(i);
        }
        // SUB
        if (word & 0xFC00) == 0x1800 { let (d,r) = rdrr(word); return Some(reg_instr(word, AvrOpcode::Sub, "SUB", d, r)); }
        // SUBI
        if (word & 0xF000) == 0x5000 {
            let d = u8::try_from(16 + ((word >> 4) & 0xF)).unwrap_or(u8::MAX);
            let k = u8::try_from(((word & 0x0F00) >> 4) | (word & 0x0F)).unwrap_or(u8::MAX);
            return Some(reg_imm_instr(word, AvrOpcode::Subi, "SUBI", d, k));
        }
        // SBC
        if (word & 0xFC00) == 0x0800 { let (d,r) = rdrr(word); return Some(reg_instr(word, AvrOpcode::Sbc, "SBC", d, r)); }
        // SBCI
        if (word & 0xF000) == 0x4000 {
            let d = u8::try_from(16 + ((word >> 4) & 0xF)).unwrap_or(u8::MAX);
            let k = u8::try_from(((word & 0x0F00) >> 4) | (word & 0x0F)).unwrap_or(u8::MAX);
            return Some(reg_imm_instr(word, AvrOpcode::Sbci, "SBCI", d, k));
        }
        // SBIW
        if (word & 0xFF00) == 0x9700 {
            let d = u8::try_from(24 + (((word >> 4) & 3) * 2)).unwrap_or(u8::MAX);
            let k = u8::try_from(((word & 0xC0) >> 2) | (word & 0x0F)).unwrap_or(u8::MAX);
            let mut i = simple_instr(word, AvrOpcode::Sbiw, "SBIW");
            i.operands = vec![AvrOperand::RegPair(d+1, d), AvrOperand::Imm6(k)];
            return Some(i);
        }
        // AND
        if (word & 0xFC00) == 0x2000 { let (d,r) = rdrr(word); return Some(reg_instr(word, AvrOpcode::And, "AND", d, r)); }
        // ANDI
        if (word & 0xF000) == 0x7000 {
            let d = u8::try_from(16 + ((word >> 4) & 0xF)).unwrap_or(u8::MAX);
            let k = u8::try_from(((word & 0x0F00) >> 4) | (word & 0x0F)).unwrap_or(u8::MAX);
            return Some(reg_imm_instr(word, AvrOpcode::Andi, "ANDI", d, k));
        }
        // OR
        if (word & 0xFC00) == 0x2800 { let (d,r) = rdrr(word); return Some(reg_instr(word, AvrOpcode::Or, "OR", d, r)); }
        // ORI
        if (word & 0xF000) == 0x6000 {
            let d = u8::try_from(16 + ((word >> 4) & 0xF)).unwrap_or(u8::MAX);
            let k = u8::try_from(((word & 0x0F00) >> 4) | (word & 0x0F)).unwrap_or(u8::MAX);
            return Some(reg_imm_instr(word, AvrOpcode::Ori, "ORI", d, k));
        }
        // EOR
        if (word & 0xFC00) == 0x2400 { let (d,r) = rdrr(word); return Some(reg_instr(word, AvrOpcode::Eor, "EOR", d, r)); }
        // COM
        if (word & 0xFE0F) == 0x9400 { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Com, "COM"); i.operands = vec![AvrOperand::Reg(d)]; return Some(i); }
        // NEG
        if (word & 0xFE0F) == 0x9401 { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Neg, "NEG"); i.operands = vec![AvrOperand::Reg(d)]; return Some(i); }
        // INC
        if (word & 0xFE0F) == 0x9403 { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Inc, "INC"); i.operands = vec![AvrOperand::Reg(d)]; return Some(i); }
        // DEC
        if (word & 0xFE0F) == 0x940A { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Dec, "DEC"); i.operands = vec![AvrOperand::Reg(d)]; return Some(i); }
        // MUL
        if (word & 0xFC00) == 0x9C00 { let (d,r) = rdrr(word); return Some(reg_instr(word, AvrOpcode::Mul, "MUL", d, r)); }
        // MULS
        if (word & 0xFF00) == 0x0200 {
            let d = u8::try_from(16 + ((word >> 4) & 0xF)).unwrap_or(u8::MAX);
            let r = u8::try_from(16 + (word & 0xF)).unwrap_or(u8::MAX);
            return Some(reg_instr(word, AvrOpcode::Muls, "MULS", d, r));
        }
        // MULSU
        if (word & 0xFF88) == 0x0300 {
            let d = u8::try_from(16 + ((word >> 4) & 7)).unwrap_or(u8::MAX);
            let r = u8::try_from(16 + (word & 7)).unwrap_or(u8::MAX);
            return Some(reg_instr(word, AvrOpcode::Mulsu, "MULSU", d, r));
        }
        Self::decode_alu_more(word)
    }

    /// Continuation of [`decode_alu`]; split out only to keep each function short.
    fn decode_alu_more(word: u16) -> Option<AvrInstr> {
        // FMUL
        if (word & 0xFF88) == 0x0308 {
            let d = u8::try_from(16 + ((word >> 4) & 7)).unwrap_or(u8::MAX);
            let r = u8::try_from(16 + (word & 7)).unwrap_or(u8::MAX);
            return Some(reg_instr(word, AvrOpcode::Fmul, "FMUL", d, r));
        }
        // LSR
        if (word & 0xFE0F) == 0x9406 { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Lsr, "LSR"); i.operands = vec![AvrOperand::Reg(d)]; return Some(i); }
        // ROR
        if (word & 0xFE0F) == 0x9407 { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Ror, "ROR"); i.operands = vec![AvrOperand::Reg(d)]; return Some(i); }
        // ASR
        if (word & 0xFE0F) == 0x9405 { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Asr, "ASR"); i.operands = vec![AvrOperand::Reg(d)]; return Some(i); }
        // SWAP
        if (word & 0xFE0F) == 0x9402 { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Swap, "SWAP"); i.operands = vec![AvrOperand::Reg(d)]; return Some(i); }
        // BSET s
        if (word & 0xFF8F) == 0x9408 {
            let s = u8::try_from((word >> 4) & 7).unwrap_or(u8::MAX);
            let mn = ["SEC","SEZ","SEN","SEV","SES","SEH","SET","SEI"][s as usize];
            let mut i = simple_instr(word, AvrOpcode::Bset, mn);
            i.operands = vec![AvrOperand::Bit(s)]; return Some(i);
        }
        // BCLR s
        if (word & 0xFF8F) == 0x9488 {
            let s = u8::try_from((word >> 4) & 7).unwrap_or(u8::MAX);
            let mn = ["CLC","CLZ","CLN","CLV","CLS","CLH","CLT","CLI"][s as usize];
            let mut i = simple_instr(word, AvrOpcode::Bclr, mn);
            i.operands = vec![AvrOperand::Bit(s)]; return Some(i);
        }
        // BST
        if (word & 0xFE08) == 0xFA00 {
            let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let b = u8::try_from(word & 7).unwrap_or(u8::MAX);
            let mut i = simple_instr(word, AvrOpcode::Bst, "BST");
            i.operands = vec![AvrOperand::Reg(d), AvrOperand::Bit(b)]; return Some(i);
        }
        // BLD
        if (word & 0xFE08) == 0xF800 {
            let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let b = u8::try_from(word & 7).unwrap_or(u8::MAX);
            let mut i = simple_instr(word, AvrOpcode::Bld, "BLD");
            i.operands = vec![AvrOperand::Reg(d), AvrOperand::Bit(b)]; return Some(i);
        }
        // SBI
        if (word & 0xFF00) == 0x9A00 {
            let a = ((word >> 3) & 0x1F) as u8; let b = u8::try_from(word & 7).unwrap_or(u8::MAX);
            let mut i = simple_instr(word, AvrOpcode::Sbi, "SBI");
            i.operands = vec![AvrOperand::IoPortBit(a, b)]; return Some(i);
        }
        // CBI
        if (word & 0xFF00) == 0x9800 {
            let a = ((word >> 3) & 0x1F) as u8; let b = u8::try_from(word & 7).unwrap_or(u8::MAX);
            let mut i = simple_instr(word, AvrOpcode::Cbi, "CBI");
            i.operands = vec![AvrOperand::IoPortBit(a, b)]; return Some(i);
        }
        // SBIC / SBIS
        if (word & 0xFF00) == 0x9900 {
            let a = ((word >> 3) & 0x1F) as u8; let b = u8::try_from(word & 7).unwrap_or(u8::MAX);
            let mut i = simple_instr(word, AvrOpcode::Sbic, "SBIC");
            i.set_is_conditional(true);
            i.operands = vec![AvrOperand::IoPortBit(a, b)]; return Some(i);
        }
        if (word & 0xFF00) == 0x9B00 {
            let a = ((word >> 3) & 0x1F) as u8; let b = u8::try_from(word & 7).unwrap_or(u8::MAX);
            let mut i = simple_instr(word, AvrOpcode::Sbis, "SBIS");
            i.set_is_conditional(true);
            i.operands = vec![AvrOperand::IoPortBit(a, b)]; return Some(i);
        }
        // CP
        if (word & 0xFC00) == 0x1400 { let (d,r) = rdrr(word); return Some(reg_instr(word, AvrOpcode::Cp, "CP", d, r)); }
        // CPC
        if (word & 0xFC00) == 0x0400 { let (d,r) = rdrr(word); return Some(reg_instr(word, AvrOpcode::Cpc, "CPC", d, r)); }
        // CPI
        if (word & 0xF000) == 0x3000 {
            let d = u8::try_from(16 + ((word >> 4) & 0xF)).unwrap_or(u8::MAX);
            let k = u8::try_from(((word & 0x0F00) >> 4) | (word & 0x0F)).unwrap_or(u8::MAX);
            return Some(reg_imm_instr(word, AvrOpcode::Cpi, "CPI", d, k));
        }
        None
    }

    fn decode_mem(word: u16, bytes: &[u8]) -> Option<AvrInstr> {
        // MOV
        if (word & 0xFC00) == 0x2C00 { let (d,r) = rdrr(word); return Some(reg_instr(word, AvrOpcode::Mov, "MOV", d, r)); }
        // MOVW
        if (word & 0xFF00) == 0x0100 {
            let d = u8::try_from(((word >> 4) & 0xF) * 2).unwrap_or(u8::MAX);
            let r = u8::try_from((word & 0xF) * 2).unwrap_or(u8::MAX);
            let mut i = simple_instr(word, AvrOpcode::Movw, "MOVW");
            i.operands = vec![AvrOperand::RegPair(d+1,d), AvrOperand::RegPair(r+1,r)]; return Some(i);
        }
        // LDI
        if (word & 0xF000) == 0xE000 {
            let d = u8::try_from(16 + ((word >> 4) & 0xF)).unwrap_or(u8::MAX);
            let k = u8::try_from(((word & 0x0F00) >> 4) | (word & 0x0F)).unwrap_or(u8::MAX);
            return Some(reg_imm_instr(word, AvrOpcode::Ldi, "LDI", d, k));
        }
        // LD X
        if (word & 0xFE0F) == 0x900C { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Ld, "LD"); i.set_reads_mem(true); i.operands = vec![AvrOperand::Reg(d), AvrOperand::RegPair(27,26)]; return Some(i); }
        if (word & 0xFE0F) == 0x900D { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Ld, "LD"); i.set_reads_mem(true); i.operands = vec![AvrOperand::Reg(d), AvrOperand::RegPairPostInc(27,26)]; return Some(i); }
        if (word & 0xFE0F) == 0x900E { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Ld, "LD"); i.set_reads_mem(true); i.operands = vec![AvrOperand::Reg(d), AvrOperand::RegPairPreDec(27,26)]; return Some(i); }
        // LD Y
        if (word & 0xFE0F) == 0x8008 { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Ld, "LD"); i.set_reads_mem(true); i.operands = vec![AvrOperand::Reg(d), AvrOperand::RegPair(29,28)]; return Some(i); }
        if (word & 0xFE0F) == 0x9009 { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Ld, "LD"); i.set_reads_mem(true); i.operands = vec![AvrOperand::Reg(d), AvrOperand::RegPairPostInc(29,28)]; return Some(i); }
        if (word & 0xFE0F) == 0x900A { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Ld, "LD"); i.set_reads_mem(true); i.operands = vec![AvrOperand::Reg(d), AvrOperand::RegPairPreDec(29,28)]; return Some(i); }
        // LD Z
        if (word & 0xFE0F) == 0x8000 { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Ld, "LD"); i.set_reads_mem(true); i.operands = vec![AvrOperand::Reg(d), AvrOperand::RegPair(31,30)]; return Some(i); }
        if (word & 0xFE0F) == 0x9001 { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Ld, "LD"); i.set_reads_mem(true); i.operands = vec![AvrOperand::Reg(d), AvrOperand::RegPairPostInc(31,30)]; return Some(i); }
        if (word & 0xFE0F) == 0x9002 { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Ld, "LD"); i.set_reads_mem(true); i.operands = vec![AvrOperand::Reg(d), AvrOperand::RegPairPreDec(31,30)]; return Some(i); }
        // LDD Y+q
        if (word & 0xD208) == 0x8008 && word & 0x0207 != 0 {
            let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX);
            let q = u8::try_from(((word & 0x2000) >> 8) | ((word & 0x0C00) >> 7) | (word & 0x07)).unwrap_or(u8::MAX);
            let mut i = simple_instr(word, AvrOpcode::Ldd, "LDD"); i.set_reads_mem(true);
            i.operands = vec![AvrOperand::Reg(d), AvrOperand::IndexDisp(29, q)]; return Some(i);
        }
        // LDD Z+q
        if (word & 0xD208) == 0x8000 && word & 0x0207 != 0 {
            let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX);
            let q = u8::try_from(((word & 0x2000) >> 8) | ((word & 0x0C00) >> 7) | (word & 0x07)).unwrap_or(u8::MAX);
            let mut i = simple_instr(word, AvrOpcode::Ldd, "LDD"); i.set_reads_mem(true);
            i.operands = vec![AvrOperand::Reg(d), AvrOperand::IndexDisp(31, q)]; return Some(i);
        }
        // LDS
        if (word & 0xFE0F) == 0x9000 {
            if bytes.len() < 4 { return None; }
            let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX);
            let addr = u16::from_le_bytes([bytes[2], bytes[3]]);
            let mut i = AvrInstr { raw: [bytes[0],bytes[1],bytes[2],bytes[3]], len: 4, opcode: AvrOpcode::Lds, mnemonic: "LDS".to_string(), operands: vec![AvrOperand::Reg(d), AvrOperand::DataAddr(addr)], branch_target: None, flags: AvrInstrFlags::from_bits(AvrInstrFlags::READS_MEM) };
            i.len = 4; return Some(i);
        }
        // ST X
        if (word & 0xFE0F) == 0x920C { let r = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::St, "ST"); i.set_writes_mem(true); i.operands = vec![AvrOperand::RegPair(27,26), AvrOperand::Reg(r)]; return Some(i); }
        if (word & 0xFE0F) == 0x920D { let r = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::St, "ST"); i.set_writes_mem(true); i.operands = vec![AvrOperand::RegPairPostInc(27,26), AvrOperand::Reg(r)]; return Some(i); }
        if (word & 0xFE0F) == 0x920E { let r = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::St, "ST"); i.set_writes_mem(true); i.operands = vec![AvrOperand::RegPairPreDec(27,26), AvrOperand::Reg(r)]; return Some(i); }
        if (word & 0xFE0F) == 0x9209 { let r = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::St, "ST"); i.set_writes_mem(true); i.operands = vec![AvrOperand::RegPairPostInc(29,28), AvrOperand::Reg(r)]; return Some(i); }
        if (word & 0xFE0F) == 0x9201 { let r = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::St, "ST"); i.set_writes_mem(true); i.operands = vec![AvrOperand::RegPairPostInc(31,30), AvrOperand::Reg(r)]; return Some(i); }
        // STS
        if (word & 0xFE0F) == 0x9200 {
            if bytes.len() < 4 { return None; }
            let r = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX);
            let addr = u16::from_le_bytes([bytes[2], bytes[3]]);
            let i = AvrInstr { raw: [bytes[0],bytes[1],bytes[2],bytes[3]], len: 4, opcode: AvrOpcode::Sts, mnemonic: "STS".to_string(), operands: vec![AvrOperand::DataAddr(addr), AvrOperand::Reg(r)], branch_target: None, flags: AvrInstrFlags::from_bits(AvrInstrFlags::WRITES_MEM) };
            return Some(i);
        }
        // PUSH
        if (word & 0xFE0F) == 0x920F { let r = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Push, "PUSH"); i.set_writes_mem(true); i.operands = vec![AvrOperand::Reg(r)]; return Some(i); }
        // POP
        if (word & 0xFE0F) == 0x900F { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Pop, "POP"); i.set_reads_mem(true); i.operands = vec![AvrOperand::Reg(d)]; return Some(i); }
        // IN
        if (word & 0xF800) == 0xB000 {
            let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX);
            let a = u8::try_from(((word & 0x0600) >> 5) | (word & 0x0F)).unwrap_or(u8::MAX);
            let mut i = simple_instr(word, AvrOpcode::In, "IN");
            i.operands = vec![AvrOperand::Reg(d), AvrOperand::IoPort(a)]; return Some(i);
        }
        // OUT
        if (word & 0xF800) == 0xB800 {
            let r = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX);
            let a = u8::try_from(((word & 0x0600) >> 5) | (word & 0x0F)).unwrap_or(u8::MAX);
            let mut i = simple_instr(word, AvrOpcode::Out, "OUT");
            i.operands = vec![AvrOperand::IoPort(a), AvrOperand::Reg(r)]; return Some(i);
        }
        // LPM Rd,Z
        if (word & 0xFE0F) == 0x9004 { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Lpm, "LPM"); i.set_reads_mem(true); i.operands = vec![AvrOperand::Reg(d), AvrOperand::RegPair(31,30)]; return Some(i); }
        // LPM Rd,Z+
        if (word & 0xFE0F) == 0x9005 { let d = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let mut i = simple_instr(word, AvrOpcode::Lpm, "LPM"); i.set_reads_mem(true); i.operands = vec![AvrOperand::Reg(d), AvrOperand::RegPairPostInc(31,30)]; return Some(i); }
        None
    }

    fn decode_branch(pc: u32, word: u16, bytes: &[u8]) -> Option<AvrInstr> {
        // RJMP
        if (word & 0xF000) == 0xC000 {
            let k = sign_ext_12(word);
            let target = branch_target_12(pc, k);
            let mut i = simple_instr(word, AvrOpcode::Rjmp, "RJMP");
            i.set_is_branch(true); i.branch_target = Some(target);
            i.operands = vec![AvrOperand::RelOffset12(k)]; return Some(i);
        }
        // RCALL
        if (word & 0xF000) == 0xD000 {
            let k = sign_ext_12(word);
            let target = branch_target_12(pc, k);
            let mut i = simple_instr(word, AvrOpcode::Rcall, "RCALL");
            i.set_is_call(true); i.branch_target = Some(target);
            i.operands = vec![AvrOperand::RelOffset12(k)]; return Some(i);
        }
        // JMP (32-bit)
        if (word & 0xFE0E) == 0x940C {
            if bytes.len() < 4 { return None; }
            let k_hi = ((u32::from(word) & 0x01F0) >> 3) | (u32::from(word) & 1);
            let k_lo = u32::from(u16::from_le_bytes([bytes[2], bytes[3]]));
            let target = (k_hi << 16) | k_lo;
            let i = AvrInstr { raw: [bytes[0],bytes[1],bytes[2],bytes[3]], len: 4, opcode: AvrOpcode::Jmp, mnemonic: "JMP".to_string(), operands: vec![AvrOperand::FlashAddr(target)], branch_target: Some(AvrAddr(target * 2)), flags: AvrInstrFlags::from_bits(AvrInstrFlags::IS_BRANCH) };
            return Some(i);
        }
        // CALL (32-bit)
        if (word & 0xFE0E) == 0x940E {
            if bytes.len() < 4 { return None; }
            let k_hi = ((u32::from(word) & 0x01F0) >> 3) | (u32::from(word) & 1);
            let k_lo = u32::from(u16::from_le_bytes([bytes[2], bytes[3]]));
            let target = (k_hi << 16) | k_lo;
            let i = AvrInstr { raw: [bytes[0],bytes[1],bytes[2],bytes[3]], len: 4, opcode: AvrOpcode::Call, mnemonic: "CALL".to_string(), operands: vec![AvrOperand::FlashAddr(target)], branch_target: Some(AvrAddr(target * 2)), flags: AvrInstrFlags::from_bits(AvrInstrFlags::IS_CALL) };
            return Some(i);
        }
        // BRBS (set bit branches) 1111 0kkk kkkk ksss
        if (word & 0xFC00) == 0xF000 {
            let k_raw = u8::try_from((word >> 3) & 0x7F).unwrap_or(0).cast_signed();
            let k: i8 = if k_raw & 0x40 != 0 { k_raw | -0x80_i8 } else { k_raw };
            let s = u8::try_from(word & 7).unwrap_or(u8::MAX);
            let target = branch_target_7(pc, k);
            let mn = ["BRCS","BREQ","BRMI","BRVS","BRLT","BRHS","BRTS","BRIE"][s as usize];
            let mut i = simple_instr(word, AvrOpcode::Brbs, mn);
            i.set_is_conditional(true); i.set_is_branch(true); i.branch_target = Some(target);
            i.operands = vec![AvrOperand::RelOffset7(k)]; return Some(i);
        }
        // BRBC (clear bit branches)
        if (word & 0xFC00) == 0xF400 {
            let k_raw = u8::try_from((word >> 3) & 0x7F).unwrap_or(0).cast_signed();
            let k: i8 = if k_raw & 0x40 != 0 { k_raw | -0x80_i8 } else { k_raw };
            let s = u8::try_from(word & 7).unwrap_or(u8::MAX);
            let target = branch_target_7(pc, k);
            let mn = ["BRCC","BRNE","BRPL","BRVC","BRGE","BRHC","BRTC","BRID"][s as usize];
            let mut i = simple_instr(word, AvrOpcode::Brbc, mn);
            i.set_is_conditional(true); i.set_is_branch(true); i.branch_target = Some(target);
            i.operands = vec![AvrOperand::RelOffset7(k)]; return Some(i);
        }
        // CPSE
        if (word & 0xFC00) == 0x1000 {
            let (d,r) = rdrr(word);
            let mut i = reg_instr(word, AvrOpcode::Cpse, "CPSE", d, r);
            i.set_is_conditional(true); return Some(i);
        }
        // SBRC
        if (word & 0xFE08) == 0xFC00 {
            let r = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let b = u8::try_from(word & 7).unwrap_or(u8::MAX);
            let mut i = simple_instr(word, AvrOpcode::Sbrc, "SBRC");
            i.set_is_conditional(true);
            i.operands = vec![AvrOperand::Reg(r), AvrOperand::Bit(b)]; return Some(i);
        }
        // SBRS
        if (word & 0xFE08) == 0xFE00 {
            let r = u8::try_from((word >> 4) & 0x1F).unwrap_or(u8::MAX); let b = u8::try_from(word & 7).unwrap_or(u8::MAX);
            let mut i = simple_instr(word, AvrOpcode::Sbrs, "SBRS");
            i.set_is_conditional(true);
            i.operands = vec![AvrOperand::Reg(r), AvrOperand::Bit(b)]; return Some(i);
        }
        let _ = bytes;
        None
    }
}

// ── Linear iterator ───────────────────────────────────────────────────────────

/// Iterates over all instructions in an AVR code byte slice.
pub struct AvrDecoderIter<'a> {
    dec: AvrDecoder,
    bytes: &'a [u8],
    offset: usize,
    pc: u32,
}

impl<'a> AvrDecoderIter<'a> {
    #[must_use]
    pub const fn new(dec: AvrDecoder, bytes: &'a [u8], base_pc: u32) -> Self {
        Self { dec, bytes, offset: 0, pc: base_pc }
    }
}

impl Iterator for AvrDecoderIter<'_> {
    type Item = AvrInstr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() { return None; }
        let i = self.dec.decode(self.pc, &self.bytes[self.offset..])?;
        let len = i.len as usize;
        self.offset += len;
        self.pc += u32::try_from(len).unwrap_or(u32::MAX);
        Some(i)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dec() -> AvrDecoder { AvrDecoder::new() }

    #[test]
    fn test_nop() {
        let i = dec().decode(0, &[0x00, 0x00]).unwrap();
        assert_eq!(i.mnemonic, "NOP");
        assert_eq!(i.len, 2);
    }

    #[test]
    fn test_ret() {
        let i = dec().decode(0, &[0x08, 0x95]).unwrap();
        assert_eq!(i.mnemonic, "RET");
        assert!(i.is_ret());
    }

    #[test]
    fn test_add() {
        // ADD R0,R1: 0x0C01
        let i = dec().decode(0, &[0x01, 0x0C]).unwrap();
        assert_eq!(i.mnemonic, "ADD");
    }

    #[test]
    fn test_ldi() {
        let i = dec().decode(0, &[0x02, 0xE4]).unwrap();
        assert_eq!(i.mnemonic, "LDI");
        assert!(i.operands[0] == AvrOperand::Reg(16));
    }

    #[test]
    fn test_rjmp() {
        let i = dec().decode(0x100, &[0xFF, 0xCF]).unwrap();
        assert_eq!(i.mnemonic, "RJMP");
        assert!(i.is_branch());
        assert_eq!(i.branch_target, Some(AvrAddr(0x100)));
    }

    #[test]
    fn test_call_32bit() {
        let i = dec().decode(0, &[0x0E, 0x94, 0x10, 0x00]).unwrap();
        assert_eq!(i.mnemonic, "CALL");
        assert!(i.is_call());
        assert_eq!(i.len, 4);
    }

    #[test]
    fn test_brne() {
        let i = dec().decode(0x100, &[0x01, 0xF4]).unwrap();
        assert_eq!(i.mnemonic, "BRNE");
        assert!(i.is_conditional());
    }

    #[test]
    fn test_push_pop() {
        let push = dec().decode(0, &[0x0F, 0x93]).unwrap();
        assert_eq!(push.mnemonic, "PUSH");
        assert!(push.writes_mem());
        let pop = dec().decode(0, &[0x0F, 0x90]).unwrap();
        assert_eq!(pop.mnemonic, "POP");
        assert!(pop.reads_mem());
    }

    #[test]
    fn test_ld_x() {
        let i = dec().decode(0, &[0x0C, 0x90]).unwrap();
        assert_eq!(i.mnemonic, "LD");
        assert!(i.reads_mem());
    }

    #[test]
    fn test_lds_32bit() {
        let i = dec().decode(0, &[0x00, 0x90, 0x00, 0x01]).unwrap();
        assert_eq!(i.mnemonic, "LDS");
        assert_eq!(i.len, 4);
    }

    #[test]
    fn test_in_out() {
        let i_in = dec().decode(0, &[0x02, 0xB6]).unwrap();
        assert_eq!(i_in.mnemonic, "IN");
        let i_out = dec().decode(0, &[0x1F, 0xBF]).unwrap();
        assert_eq!(i_out.mnemonic, "OUT");
    }

    #[test]
    fn test_iter() {
        let code = [0x00u8, 0x00, 0x08, 0x95];
        let v: Vec<_> = AvrDecoderIter::new(AvrDecoder::new(), &code, 0).collect();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].mnemonic, "NOP");
        assert_eq!(v[1].mnemonic, "RET");
    }
}
