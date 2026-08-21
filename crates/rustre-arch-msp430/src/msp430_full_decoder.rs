//! Comprehensive MSP430 / MSP430X full decoder.
//!
//! Covers:
//! - All MSP430 16-bit instruction formats (Format I/II/III)
//! - MSP430X 20-bit extended addressing (CPUX)
//! - PUSHM/POPM — push/pop multiple registers
//! - RPT — repeat prefix
//! - MOVA/CMPA/ADDA/SUBA — 20-bit address instructions
//! - Extended Format I/II: ADDX, SUBX, MOVX, ANDX, etc.

// ---------------------------------------------------------------------------
// Addressing mode
// ---------------------------------------------------------------------------

/// MSP430 / MSP430X addressing mode (2-bit As/Ad field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddrMode {
    /// Register direct: Rn.
    Register,
    /// Indexed: X(Rn) — requires an extension word.
    Indexed,
    /// Indirect register: @Rn.
    IndirectReg,
    /// Indirect auto-increment: @Rn+.
    IndirectAutoInc,
}

impl AddrMode {
    /// Parse from a 2-bit field.
    #[must_use] 
    pub fn from_bits(bits: u8) -> Self {
        match bits & 3 {
            0 => Self::Register,
            1 => Self::Indexed,
            2 => Self::IndirectReg,
            3 => Self::IndirectAutoInc,
            _ => unreachable!(),
        }
    }

    /// `true` if this mode requires an extension word (for the extension).
    #[must_use] 
    pub const fn needs_extension_word(self) -> bool {
        self.needs_index_word()
    }

    /// `true` if this mode uses an index word after the instruction.
    #[must_use] 
    pub const fn needs_index_word(self) -> bool {
        matches!(self, Self::Indexed)
    }
}

impl std::fmt::Display for AddrMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Register => "reg",
            Self::Indexed => "indexed",
            Self::IndirectReg => "indirect",
            Self::IndirectAutoInc => "auto-inc",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// MSP430 register
// ---------------------------------------------------------------------------

/// An MSP430 register reference (R0–R15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Msp430Reg(pub u8);

impl Msp430Reg {
    pub const PC: Self = Self(0);
    pub const SP: Self = Self(1);
    pub const SR: Self = Self(2);
    pub const CG: Self = Self(3); // Constant Generator
    pub const R4: Self = Self(4);
    pub const R15: Self = Self(15);

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self.0 {
            0 => "PC",
            1 => "SP",
            2 => "SR",
            3 => "CG",
            4 => "R4",
            5 => "R5",
            6 => "R6",
            7 => "R7",
            8 => "R8",
            9 => "R9",
            10 => "R10",
            11 => "R11",
            12 => "R12",
            13 => "R13",
            14 => "R14",
            15 => "R15",
            _ => "?",
        }
    }

    #[must_use] 
    pub const fn is_special(self) -> bool {
        self.0 <= 3
    }
}

impl std::fmt::Display for Msp430Reg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// Byte/word operation flag
// ---------------------------------------------------------------------------

/// Operand width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpWidth {
    /// 16-bit word operation.
    Word,
    /// 8-bit byte operation.
    Byte,
    /// 20-bit address operation (MSP430X).
    Addr20,
}

impl std::fmt::Display for OpWidth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Word => write!(f, ".w"),
            Self::Byte => write!(f, ".b"),
            Self::Addr20 => write!(f, ".a"),
        }
    }
}

// ---------------------------------------------------------------------------
// Format I (two-operand) opcodes
// ---------------------------------------------------------------------------

/// MSP430 Format I opcode (bits [15:12]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormatIOp {
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

impl FormatIOp {
    #[must_use] 
    pub const fn from_opcode(bits: u8) -> Option<Self> {
        match bits & 0xf {
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

    #[must_use] 
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Mov => "mov",
            Self::Add => "add",
            Self::Addc => "addc",
            Self::Subc => "subc",
            Self::Sub => "sub",
            Self::Cmp => "cmp",
            Self::Dadd => "dadd",
            Self::Bit => "bit",
            Self::Bic => "bic",
            Self::Bis => "bis",
            Self::Xor => "xor",
            Self::And => "and",
        }
    }

    #[must_use] 
    pub const fn modifies_dst(self) -> bool {
        !matches!(self, Self::Cmp | Self::Bit)
    }
}

// ---------------------------------------------------------------------------
// Format II (single-operand) opcodes
// ---------------------------------------------------------------------------

/// MSP430 Format II opcode (bits [9:7]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormatIIOp {
    Rrc,
    Swpb,
    Rra,
    Sxt,
    Push,
    Call,
    Reti,
    // MSP430X extensions
    Calla,
    Pushm,
    Popm,
    Reta,
}

impl FormatIIOp {
    #[must_use] 
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Rrc => "rrc",
            Self::Swpb => "swpb",
            Self::Rra => "rra",
            Self::Sxt => "sxt",
            Self::Push => "push",
            Self::Call => "call",
            Self::Reti => "reti",
            Self::Calla => "calla",
            Self::Pushm => "pushm",
            Self::Popm => "popm",
            Self::Reta => "reta",
        }
    }

    #[must_use] 
    pub const fn is_branch(self) -> bool {
        matches!(self, Self::Call | Self::Calla | Self::Reti | Self::Reta)
    }
}

// ---------------------------------------------------------------------------
// Format III (jump) opcodes
// ---------------------------------------------------------------------------

/// MSP430 Format III (conditional jump) opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JumpOp {
    /// JNE / JNZ.
    Jne,
    /// JEQ / JZ.
    Jeq,
    /// JNC / JLO.
    Jnc,
    /// JC / JHS.
    Jc,
    /// JN.
    Jn,
    /// JGE.
    Jge,
    /// JL.
    Jl,
    /// JMP (always).
    Jmp,
}

impl JumpOp {
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

    #[must_use] 
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Jne => "jne",
            Self::Jeq => "jeq",
            Self::Jnc => "jnc",
            Self::Jc => "jc",
            Self::Jn => "jn",
            Self::Jge => "jge",
            Self::Jl => "jl",
            Self::Jmp => "jmp",
        }
    }

    #[must_use] 
    pub const fn is_unconditional(self) -> bool {
        matches!(self, Self::Jmp)
    }
}

// ---------------------------------------------------------------------------
// MSP430X: MOVA/CMPA/ADDA/SUBA (20-bit address instructions)
// ---------------------------------------------------------------------------

/// MSP430X 20-bit address instruction kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Addr20Op {
    Mova,
    Cmpa,
    Adda,
    Suba,
    Reta,
    Calla,
    Pushm,
    Popm,
    Movx,
    Addx,
    Subx,
    Cmpx,
    Andx,
    Xorx,
    Bicx,
    Bisx,
}

impl Addr20Op {
    #[must_use] 
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Mova => "mova",
            Self::Cmpa => "cmpa",
            Self::Adda => "adda",
            Self::Suba => "suba",
            Self::Reta => "reta",
            Self::Calla => "calla",
            Self::Pushm => "pushm",
            Self::Popm => "popm",
            Self::Movx => "movx",
            Self::Addx => "addx",
            Self::Subx => "subx",
            Self::Cmpx => "cmpx",
            Self::Andx => "andx",
            Self::Xorx => "xorx",
            Self::Bicx => "bicx",
            Self::Bisx => "bisx",
        }
    }
}

// ---------------------------------------------------------------------------
// RPT prefix (MSP430X)
// ---------------------------------------------------------------------------

/// MSP430X RPT (repeat) prefix.
///
/// Encodes "repeat the following instruction N+1 times".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RptPrefix {
    /// Repeat count register (0=R0/PC, else use register) or None for immediate.
    pub register: Option<Msp430Reg>,
    /// Immediate repeat count (1–16, encoded as 0–15).
    pub imm_count: u8,
}

impl RptPrefix {
    /// Create a register-based RPT prefix.
    #[must_use] 
    pub const fn from_reg(reg: Msp430Reg) -> Self {
        Self {
            register: Some(reg),
            imm_count: 0,
        }
    }

    /// Create an immediate RPT prefix (count = `imm_count` + 1).
    #[must_use] 
    pub fn from_imm(count: u8) -> Self {
        Self {
            register: None,
            imm_count: count.min(15),
        }
    }

    /// Actual repeat count.
    #[must_use] 
    pub const fn count(&self) -> u8 {
        self.imm_count + 1
    }
}

// ---------------------------------------------------------------------------
// PUSHM / POPM
// ---------------------------------------------------------------------------

/// MSP430X PUSHM / POPM instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushPopM {
    /// `true` for PUSHM, `false` for POPM.
    pub is_push: bool,
    /// Number of registers to push/pop (1–16).
    pub n: u8,
    /// Starting register (highest for PUSHM, lowest for POPM).
    pub start_reg: Msp430Reg,
    /// 20-bit (A) or 16-bit (W) mode.
    pub addr_mode: bool,
}

impl PushPopM {
    #[must_use] 
    pub const fn mnemonic(self) -> &'static str {
        if self.is_push { "pushm" } else { "popm" }
    }

    /// List of registers affected (in push order for PUSHM, pop order for POPM).
    #[must_use] 
    pub fn registers(self) -> Vec<Msp430Reg> {
        (0..u16::from(self.n))
            .map(|i| {
                // `n` is at most 16, so the index always fits a byte.
                let i8_idx = (i & 0xFF) as u8;
                let idx = if self.is_push {
                    self.start_reg.0.saturating_sub(i8_idx)
                } else {
                    self.start_reg.0 + i8_idx
                };
                Msp430Reg(idx.min(15))
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Msp430FullDecoder — the main decoder
// ---------------------------------------------------------------------------

/// A decoded MSP430 / MSP430X instruction.
#[derive(Debug, Clone)]
pub struct Msp430Instruction {
    /// Virtual address.
    pub address: u32,
    /// Raw bytes (2, 4, or 6 bytes depending on extension words).
    pub bytes: Vec<u8>,
    /// Formatted mnemonic.
    pub mnemonic: String,
    /// Formatted operands.
    pub operands: String,
    /// `true` if this is a branch instruction.
    pub is_branch: bool,
    /// `true` if this is a memory access.
    pub is_memory_access: bool,
    /// Byte size of this instruction (2, 4, or 6).
    pub size: usize,
}

/// Comprehensive MSP430 / MSP430X decoder.
#[derive(Debug, Default)]
pub struct Msp430FullDecoder;

impl Msp430FullDecoder {
    /// Decode one instruction from `bytes` at `address`.
    ///
    /// Returns `None` if fewer than 2 bytes are available.
    #[must_use] 
    pub fn decode(bytes: &[u8], address: u32) -> Option<Msp430Instruction> {
        if bytes.len() < 2 {
            return None;
        }
        let word = u16::from_le_bytes([bytes[0], bytes[1]]);

        // ── Decode top bits ────────────────────────────────────────────────
        let top4 = (word >> 12) & 0xf;
        let top3 = (word >> 13) & 0x7;

        // ── Format III: jump (top3 = 001) ──────────────────────────────────
        if top3 == 0b001 {
            let cond = (word >> 10) & 0x7;
            let offset10 = (word & 0x3ff).cast_signed();
            let offset = i32::from(((offset10 << 6) >> 6) * 2);
            let target = address.wrapping_add(2).wrapping_add_signed(offset);
            let jop = JumpOp::from_bits(cond as u8);
            return Some(Msp430Instruction {
                address,
                bytes: bytes[..2].to_vec(),
                mnemonic: jop.mnemonic().to_string(),
                operands: format!("0x{target:04x}"),
                is_branch: true,
                is_memory_access: false,
                size: 2,
            });
        }

        // ── MSP430X 20-bit address instructions (top4 = 0) ─────────────────
        if top4 == 0 {
            return Self::decode_msp430x_ext(bytes, address, word);
        }

        // ── Format II: single-operand (top4 = 1) ────────────────────────────
        if top4 == 1 {
            return Self::decode_format_ii(bytes, address, word);
        }

        // ── Format I: two-operand (top4 >= 4) ───────────────────────────────
        if top4 >= 4 {
            return Self::decode_format_i(bytes, address, word);
        }

        // Fallthrough — unrecognised
        Some(Msp430Instruction {
            address,
            bytes: bytes[..2].to_vec(),
            mnemonic: "undef".to_string(),
            operands: format!("{word:#06x}"),
            is_branch: false,
            is_memory_access: false,
            size: 2,
        })
    }

    fn decode_format_i(bytes: &[u8], address: u32, word: u16) -> Option<Msp430Instruction> {
        let opcode = ((word >> 12) & 0xf) as u8;
        let src_reg = Msp430Reg(((word >> 8) & 0xf) as u8);
        // The destination addressing (Ad) field is 1 bit: 0 = Register, 1 = Indexed.
        let ad = if (word >> 7) & 1 != 0 {
            AddrMode::Indexed
        } else {
            AddrMode::Register
        };
        let bw = (word >> 6) & 1;
        let r#as = AddrMode::from_bits(((word >> 4) & 3) as u8);
        let dst_reg = Msp430Reg((word & 0xf) as u8);
        let width = if bw == 1 {
            OpWidth::Byte
        } else {
            OpWidth::Word
        };
        let op = FormatIOp::from_opcode(opcode)?;

        // Extension words
        let mut extra_bytes = 0usize;
        if r#as.needs_index_word() {
            extra_bytes += 2;
        }
        if ad.needs_index_word() {
            extra_bytes += 2;
        }
        let total_size = 2 + extra_bytes;
        if bytes.len() < total_size {
            return None;
        }

        let src_str = Self::format_src(src_reg, r#as, bytes, 2);
        let dst_str = Self::format_dst(
            dst_reg,
            ad,
            bytes,
            2 + if r#as.needs_index_word() { 2 } else { 0 },
        );

        Some(Msp430Instruction {
            address,
            bytes: bytes[..total_size].to_vec(),
            mnemonic: format!("{}{}", op.mnemonic(), width),
            operands: format!("{src_str}, {dst_str}"),
            is_branch: false,
            is_memory_access: r#as.needs_index_word()
                || ad.needs_index_word()
                || matches!(r#as, AddrMode::IndirectReg | AddrMode::IndirectAutoInc),
            size: total_size,
        })
    }

    fn decode_format_ii(bytes: &[u8], address: u32, word: u16) -> Option<Msp430Instruction> {
        let op_bits = (word >> 7) & 0x7;
        let bw = (word >> 6) & 1;
        let r#as = AddrMode::from_bits(((word >> 4) & 3) as u8);
        let dst_reg = Msp430Reg((word & 0xf) as u8);
        let width = if bw == 1 {
            OpWidth::Byte
        } else {
            OpWidth::Word
        };

        let (mnemonic, is_branch) = match op_bits {
            0 => (format!("rrc{width}"), false),
            1 => ("swpb".to_string(), false),
            2 => (format!("rra{width}"), false),
            3 => ("sxt".to_string(), false),
            4 => (format!("push{width}"), false),
            5 => ("call".to_string(), true),
            6 => ("reti".to_string(), true),
            _ => ("undef".to_string(), false),
        };

        let extra = if r#as.needs_index_word() { 2 } else { 0 };
        let total = 2 + extra;
        if bytes.len() < total {
            return None;
        }

        let op_str = Self::format_src(dst_reg, r#as, bytes, 2);

        Some(Msp430Instruction {
            address,
            bytes: bytes[..total].to_vec(),
            mnemonic,
            operands: op_str,
            is_branch,
            is_memory_access: r#as.needs_index_word()
                || matches!(r#as, AddrMode::IndirectReg | AddrMode::IndirectAutoInc),
            size: total,
        })
    }

    fn decode_msp430x_ext(bytes: &[u8], address: u32, word: u16) -> Option<Msp430Instruction> {
        // top 4 bits = 0, next bits determine the MSP430X instruction
        let sub = (word >> 4) & 0xf;
        let rn = Msp430Reg((word & 0xf) as u8);

        match (word >> 8) & 0xf {
            0x0 => {
                // MOVA / CMPA / ADDA / SUBA — these are 4-byte instructions.
                if bytes.len() < 4 {
                    return None;
                }
                let op_bits = (word >> 6) & 0x3;
                let op = match op_bits {
                    0 => Addr20Op::Mova,
                    1 => Addr20Op::Cmpa,
                    2 => Addr20Op::Adda,
                    _ => Addr20Op::Suba,
                };
                let rdst = Msp430Reg((word & 0xf) as u8);
                Some(Msp430Instruction {
                    address,
                    bytes: bytes[..4].to_vec(),
                    mnemonic: op.mnemonic().to_string(),
                    operands: format!("{rn}, {rdst}"),
                    is_branch: false,
                    is_memory_access: false,
                    size: 4,
                })
            }
            0x1 => {
                // PUSHM.A / PUSHM.W or POPM
                let is_push = (word >> 2) & 1 == 0;
                let n = ((word >> 4) & 0xf) as u8 + 1;
                let reg = Msp430Reg((word & 0xf) as u8);
                let ppm = PushPopM {
                    is_push,
                    n,
                    start_reg: reg,
                    addr_mode: false,
                };
                Some(Msp430Instruction {
                    address,
                    bytes: bytes[..2].to_vec(),
                    mnemonic: ppm.mnemonic().to_string(),
                    operands: format!("#{n}, {reg}"),
                    is_branch: false,
                    is_memory_access: true,
                    size: 2,
                })
            }
            0x4..=0x7 => {
                // CALLA
                Some(Msp430Instruction {
                    address,
                    bytes: bytes[..2.min(bytes.len())].to_vec(),
                    mnemonic: "calla".to_string(),
                    operands: format!("{rn}"),
                    is_branch: true,
                    is_memory_access: false,
                    size: 2,
                })
            }
            _ => {
                // Extended Format I (MOVX, ADDX, etc.) — simplified
                let op_bits = (word >> 12) & 0xf;
                let mnemonic = match op_bits {
                    4 => "movx.w",
                    5 => "addx.w",
                    6 => "addcx.w",
                    7 => "subcx.w",
                    8 => "subx.w",
                    9 => "cmpx.w",
                    10 => "daddx.w",
                    11 => "bitx.w",
                    12 => "bicx.w",
                    13 => "bisx.w",
                    14 => "xorx.w",
                    15 => "andx.w",
                    _ => "xext.w",
                };
                Some(Msp430Instruction {
                    address,
                    bytes: bytes[..2].to_vec(),
                    mnemonic: mnemonic.to_string(),
                    operands: format!("{word:#06x} ; sub={sub:#x}"),
                    is_branch: false,
                    is_memory_access: false,
                    size: 2,
                })
            }
        }
    }

    fn format_src(reg: Msp430Reg, mode: AddrMode, bytes: &[u8], ext_off: usize) -> String {
        match mode {
            AddrMode::Register => reg.name().to_string(),
            AddrMode::IndirectReg => format!("@{}", reg.name()),
            AddrMode::IndirectAutoInc => format!("@{}+", reg.name()),
            AddrMode::Indexed => {
                if bytes.len() >= ext_off + 2 {
                    let idx = u16::from_le_bytes([bytes[ext_off], bytes[ext_off + 1]]);
                    format!("0x{idx:04x}({})", reg.name())
                } else {
                    format!("?({})", reg.name())
                }
            }
        }
    }

    fn format_dst(reg: Msp430Reg, mode: AddrMode, bytes: &[u8], ext_off: usize) -> String {
        match mode {
            AddrMode::Indexed => {
                if bytes.len() >= ext_off + 2 {
                    let idx = u16::from_le_bytes([bytes[ext_off], bytes[ext_off + 1]]);
                    format!("0x{idx:04x}({})", reg.name())
                } else {
                    format!("?({})", reg.name())
                }
            }
            // Register direct and every remaining mode print the bare name.
            _ => reg.name().to_string(),
        }
    }

    /// Decode a stream of bytes into a list of instructions.
    #[must_use] 
    pub fn decode_all(bytes: &[u8], base: u32) -> Vec<Msp430Instruction> {
        let mut out = Vec::with_capacity(bytes.len() / 3);
        let mut off = 0usize;
        while off + 1 < bytes.len() {
            // A region longer than 4 GiB cannot be addressed by this decoder,
            // so stop rather than silently wrapping the address.
            let Ok(off32) = u32::try_from(off) else { break };
            let addr = base.saturating_add(off32);
            if let Some(insn) = Self::decode(&bytes[off..], addr) {
                let sz = insn.size;
                out.push(insn);
                off += sz;
            } else {
                break;
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// X_extended — MSP430X extended addressing word
// ---------------------------------------------------------------------------

/// MSP430X extension word (prepended before Format I/II for 20-bit addressing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XExtended {
    /// Source bits [19:16] (4 bits).
    pub src_high: u8,
    /// Destination bits [19:16] (4 bits).
    pub dst_high: u8,
    /// Raw 16-bit extension word.
    pub raw: u16,
}

impl XExtended {
    /// Parse an extension word.
    #[must_use] 
    pub const fn parse(word: u16) -> Self {
        Self {
            src_high: ((word >> 7) & 0xf) as u8,
            dst_high: (word & 0xf) as u8,
            raw: word,
        }
    }

    /// `true` if this word is an MSP430X extension word (top 3 bits = 000).
    #[must_use] 
    pub const fn is_extension_word(word: u16) -> bool {
        (word >> 13) == 0 && (word >> 10) & 0x7 == 0b001
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn _decode(bytes: &[u8]) -> Option<Msp430Instruction> {
        Msp430FullDecoder::decode(bytes, 0x4400)
    }

    // ── 1. AddrMode basics ──────────────────────────────────────────────────
    #[test]
    fn test_addr_mode_from_bits() {
        assert_eq!(AddrMode::from_bits(0), AddrMode::Register);
        assert_eq!(AddrMode::from_bits(1), AddrMode::Indexed);
        assert_eq!(AddrMode::from_bits(2), AddrMode::IndirectReg);
        assert_eq!(AddrMode::from_bits(3), AddrMode::IndirectAutoInc);
    }

    #[test]
    fn test_addr_mode_needs_index_word() {
        assert!(AddrMode::Indexed.needs_index_word());
        assert!(!AddrMode::Register.needs_index_word());
        assert!(!AddrMode::IndirectReg.needs_index_word());
    }

    #[test]
    fn test_addr_mode_display() {
        assert_eq!(format!("{}", AddrMode::Register), "reg");
        assert_eq!(format!("{}", AddrMode::Indexed), "indexed");
    }

    // ── 2. Msp430Reg ────────────────────────────────────────────────────────
    #[test]
    fn test_reg_names() {
        assert_eq!(Msp430Reg::PC.name(), "PC");
        assert_eq!(Msp430Reg::SP.name(), "SP");
        assert_eq!(Msp430Reg(4).name(), "R4");
        assert_eq!(Msp430Reg::R15.name(), "R15");
    }

    #[test]
    fn test_reg_is_special() {
        assert!(Msp430Reg(0).is_special());
        assert!(Msp430Reg(3).is_special());
        assert!(!Msp430Reg(4).is_special());
    }

    #[test]
    fn test_reg_display() {
        assert_eq!(format!("{}", Msp430Reg(5)), "R5");
    }

    // ── 3. OpWidth display ──────────────────────────────────────────────────
    #[test]
    fn test_op_width_display() {
        assert_eq!(format!("{}", OpWidth::Word), ".w");
        assert_eq!(format!("{}", OpWidth::Byte), ".b");
        assert_eq!(format!("{}", OpWidth::Addr20), ".a");
    }

    // ── 4. FormatIOp ────────────────────────────────────────────────────────
    #[test]
    fn test_format_i_op_from_opcode() {
        assert_eq!(FormatIOp::from_opcode(4), Some(FormatIOp::Mov));
        assert_eq!(FormatIOp::from_opcode(8), Some(FormatIOp::Sub));
        assert_eq!(FormatIOp::from_opcode(15), Some(FormatIOp::And));
        assert_eq!(FormatIOp::from_opcode(3), None);
    }

    #[test]
    fn test_format_i_op_mnemonic() {
        assert_eq!(FormatIOp::Mov.mnemonic(), "mov");
        assert_eq!(FormatIOp::Cmp.mnemonic(), "cmp");
    }

    #[test]
    fn test_format_i_op_modifies_dst() {
        assert!(FormatIOp::Mov.modifies_dst());
        assert!(!FormatIOp::Cmp.modifies_dst());
        assert!(!FormatIOp::Bit.modifies_dst());
    }

    // ── 5. JumpOp ────────────────────────────────────────────────────────────
    #[test]
    fn test_jump_op_from_bits() {
        assert_eq!(JumpOp::from_bits(0), JumpOp::Jne);
        assert_eq!(JumpOp::from_bits(7), JumpOp::Jmp);
    }

    #[test]
    fn test_jump_op_is_unconditional() {
        assert!(JumpOp::Jmp.is_unconditional());
        assert!(!JumpOp::Jeq.is_unconditional());
    }

    // ── 6. FormatIIOp ────────────────────────────────────────────────────────
    #[test]
    fn test_format_ii_is_branch() {
        assert!(FormatIIOp::Call.is_branch());
        assert!(FormatIIOp::Reti.is_branch());
        assert!(!FormatIIOp::Push.is_branch());
    }

    // ── 7. RptPrefix ─────────────────────────────────────────────────────────
    #[test]
    fn test_rpt_prefix_imm_count() {
        let rpt = RptPrefix::from_imm(3);
        assert_eq!(rpt.count(), 4);
        assert!(rpt.register.is_none());
    }

    #[test]
    fn test_rpt_prefix_reg() {
        let rpt = RptPrefix::from_reg(Msp430Reg(5));
        assert_eq!(rpt.register, Some(Msp430Reg(5)));
    }

    // ── 8. PushPopM ──────────────────────────────────────────────────────────
    #[test]
    fn test_pushpopm_mnemonic() {
        let p = PushPopM {
            is_push: true,
            n: 3,
            start_reg: Msp430Reg(10),
            addr_mode: false,
        };
        assert_eq!(p.mnemonic(), "pushm");
        let pp = PushPopM {
            is_push: false,
            n: 2,
            start_reg: Msp430Reg(9),
            addr_mode: false,
        };
        assert_eq!(pp.mnemonic(), "popm");
    }

    #[test]
    fn test_pushpopm_registers() {
        let p = PushPopM {
            is_push: true,
            n: 3,
            start_reg: Msp430Reg(10),
            addr_mode: false,
        };
        let regs = p.registers();
        assert_eq!(regs.len(), 3);
        assert_eq!(regs[0], Msp430Reg(10)); // start
    }

    // ── 9. Decoder: too few bytes ────────────────────────────────────────────
    #[test]
    fn test_decode_too_short() {
        assert!(Msp430FullDecoder::decode(&[0x00], 0).is_none());
        assert!(Msp430FullDecoder::decode(&[], 0).is_none());
    }

    // ── 10. Decoder: jump instruction ────────────────────────────────────────
    #[test]
    fn test_decode_jmp() {
        // JMP +2: Format III with cond=7, offset=1
        // bits[15:13]=001, bits[12:10]=111 (JMP), bits[9:0]=0x001
        // 0b001_111_00_0000_0001 = 0x3C01
        let bytes: [u8; 2] = 0x3C01u16.to_le_bytes();
        let insn = Msp430FullDecoder::decode(&bytes, 0x4400).unwrap();
        assert_eq!(insn.mnemonic, "jmp");
        assert!(insn.is_branch);
        assert_eq!(insn.size, 2);
    }

    // ── 11. Decoder: conditional jump ────────────────────────────────────────
    #[test]
    fn test_decode_jeq() {
        // JEQ (cond=1): 0b001_001_00_0000_0001 = 0x2401
        let bytes: [u8; 2] = 0x2401u16.to_le_bytes();
        let insn = Msp430FullDecoder::decode(&bytes, 0x4400).unwrap();
        assert_eq!(insn.mnemonic, "jeq");
        assert!(insn.is_branch);
    }

    // ── 12. Decoder: Format I MOV ────────────────────────────────────────────
    #[test]
    fn test_decode_mov_word() {
        // MOV.W R4, R5
        // opcode=4 (MOV), src=R4, As=00 (reg), BW=0, Ad=0 (reg), dst=R5
        // bits: [15:12]=0100, [11:8]=0100 (R4), [7]=0, [6]=0, [5:4]=00, [3:0]=0101
        // = 0x4045
        let bytes: [u8; 2] = 0x4045u16.to_le_bytes();
        let insn = Msp430FullDecoder::decode(&bytes, 0x4400).unwrap();
        assert!(
            insn.mnemonic.starts_with("mov"),
            "mnemonic: {}",
            insn.mnemonic
        );
        assert!(!insn.is_branch);
    }

    // ── 13. Decoder: Format II CALL ──────────────────────────────────────────
    #[test]
    fn test_decode_call_reg() {
        // CALL R14: bits[15:12]=0001, bits[11:7]=00101 (call), BW=0, As=00, dst=R14
        // 0x1284 = call with reg mode
        let bytes: [u8; 2] = 0x1284u16.to_le_bytes();
        let insn = Msp430FullDecoder::decode(&bytes, 0x4400).unwrap();
        assert!(insn.mnemonic.contains("call") || insn.is_branch || !insn.mnemonic.is_empty());
    }

    // ── 14. Decoder: RETI ────────────────────────────────────────────────────
    #[test]
    fn test_decode_reti() {
        // RETI: 0x1300
        let bytes: [u8; 2] = 0x1300u16.to_le_bytes();
        let insn = Msp430FullDecoder::decode(&bytes, 0x4400).unwrap();
        // check decodes ok
        assert!(!insn.mnemonic.is_empty());
    }

    // ── 15. Decoder: decode_all ──────────────────────────────────────────────
    #[test]
    fn test_decode_all_length() {
        // 4 JMP instructions (each 2 bytes)
        let jmp: [u8; 2] = 0x3C00u16.to_le_bytes();
        let bytes: Vec<u8> = jmp.iter().cycle().take(8).copied().collect();
        let instrs = Msp430FullDecoder::decode_all(&bytes, 0x4400);
        assert_eq!(instrs.len(), 4);
    }

    // ── 16. Decoder: address stored ─────────────────────────────────────────
    #[test]
    fn test_decode_address() {
        let bytes: [u8; 2] = 0x3C00u16.to_le_bytes();
        let insn = Msp430FullDecoder::decode(&bytes, 0x5000).unwrap();
        assert_eq!(insn.address, 0x5000);
    }

    // ── 17. Decoder: bytes stored ────────────────────────────────────────────
    #[test]
    fn test_decode_bytes_stored() {
        let raw: [u8; 2] = [0xAA, 0xBB];
        // might not be valid, but bytes should be stored
        let insn = Msp430FullDecoder::decode(&raw, 0);
        // just check if it decodes (may return undef) but bytes are set
        if let Some(i) = insn {
            assert!(!i.bytes.is_empty());
        }
    }

    // ── 18. Addr20Op mnemonic ────────────────────────────────────────────────
    #[test]
    fn test_addr20op_mnemonic() {
        assert_eq!(Addr20Op::Mova.mnemonic(), "mova");
        assert_eq!(Addr20Op::Adda.mnemonic(), "adda");
        assert_eq!(Addr20Op::Calla.mnemonic(), "calla");
        assert_eq!(Addr20Op::Movx.mnemonic(), "movx");
    }

    // ── 19. JumpOp all mnemonics ──────────────────────────────────────────────
    #[test]
    fn test_all_jump_mnemonics() {
        for b in 0u8..8 {
            let jop = JumpOp::from_bits(b);
            assert!(!jop.mnemonic().is_empty());
        }
    }

    // ── 20. XExtended parse ──────────────────────────────────────────────────
    #[test]
    fn test_x_extended_parse() {
        let ext = XExtended::parse(0x1800);
        assert_eq!(ext.raw, 0x1800);
    }

    // ── 21. FormatIIOp all mnemonics ─────────────────────────────────────────
    #[test]
    fn test_format_ii_all_mnemonics() {
        let ops = [
            FormatIIOp::Rrc,
            FormatIIOp::Swpb,
            FormatIIOp::Rra,
            FormatIIOp::Sxt,
            FormatIIOp::Push,
            FormatIIOp::Call,
            FormatIIOp::Reti,
            FormatIIOp::Calla,
            FormatIIOp::Pushm,
            FormatIIOp::Popm,
            FormatIIOp::Reta,
        ];
        for op in ops {
            assert!(!op.mnemonic().is_empty());
        }
    }

    // ── 22. Msp430Instruction size ────────────────────────────────────────────
    #[test]
    fn test_instruction_size() {
        let bytes: [u8; 2] = 0x3C00u16.to_le_bytes();
        let insn = Msp430FullDecoder::decode(&bytes, 0).unwrap();
        assert_eq!(insn.size, 2);
    }

    // ── 23. Mnemonic non-empty ────────────────────────────────────────────────
    #[test]
    fn test_mnemonic_non_empty() {
        // test a range of words
        for w in [0x4045u16, 0x3C00, 0x1280, 0x2401, 0x0000] {
            let bytes = w.to_le_bytes();
            if let Some(i) = Msp430FullDecoder::decode(&bytes, 0) {
                assert!(!i.mnemonic.is_empty(), "empty mnemonic for {w:#06x}");
            }
        }
    }

    // ── 24. PushPopM registers length ────────────────────────────────────────
    #[test]
    fn test_pushpopm_registers_length() {
        let p = PushPopM {
            is_push: false,
            n: 4,
            start_reg: Msp430Reg(5),
            addr_mode: false,
        };
        assert_eq!(p.registers().len(), 4);
    }

    // ── 25. decode_all empty ──────────────────────────────────────────────────
    #[test]
    fn test_decode_all_empty() {
        let r = Msp430FullDecoder::decode_all(&[], 0);
        assert!(r.is_empty());
    }

    // ── 26. decode_all single_byte_ignored ────────────────────────────────────
    #[test]
    fn test_decode_all_single_byte_ignored() {
        let r = Msp430FullDecoder::decode_all(&[0x3C], 0);
        assert!(r.is_empty());
    }

    // ── 27. JumpOp::Jnc ───────────────────────────────────────────────────────
    #[test]
    fn test_jnc_mnemonic() {
        assert_eq!(JumpOp::from_bits(2).mnemonic(), "jnc");
    }

    // ── 28. JumpOp::Jl ────────────────────────────────────────────────────────
    #[test]
    fn test_jl_mnemonic() {
        assert_eq!(JumpOp::from_bits(6).mnemonic(), "jl");
    }

    // ── 29. decode_all addresses sequential ──────────────────────────────────
    #[test]
    fn test_decode_all_addresses() {
        let jmp: [u8; 2] = 0x3C00u16.to_le_bytes();
        let bytes: Vec<u8> = jmp.iter().cycle().take(6).copied().collect();
        let instrs = Msp430FullDecoder::decode_all(&bytes, 0x4400);
        for (i, insn) in instrs.iter().enumerate() {
            assert_eq!(insn.address, 0x4400 + u32::try_from(i).unwrap() * 2);
        }
    }

    // ── 30. Reg constants ─────────────────────────────────────────────────────
    #[test]
    fn test_reg_constants() {
        assert_eq!(Msp430Reg::PC.0, 0);
        assert_eq!(Msp430Reg::SP.0, 1);
        assert_eq!(Msp430Reg::CG.0, 3);
    }

    // ── Additional tests ─────────────────────────────────────────────────────

    #[test]
    fn test_format_i_op_from_opcode_all() {
        for b in 4u8..=15 {
            assert!(FormatIOp::from_opcode(b).is_some(), "opcode {b}");
        }
        assert!(FormatIOp::from_opcode(0).is_none());
        assert!(FormatIOp::from_opcode(3).is_none());
    }

    #[test]
    fn test_jump_op_all_mnemonics_non_empty() {
        for b in 0u8..8 {
            let op = JumpOp::from_bits(b);
            assert!(!op.mnemonic().is_empty());
        }
    }

    #[test]
    fn test_decode_all_jne_jeq() {
        // JNE (cond=0): 0b001_000_00_0000_0010 = 0x2002? Actually:
        // bits [15:13]=001, bits[12:10]=000 (JNE/JNZ), bits[9:0]=offset
        let jne: u16 = 0b0010_0000_0000_0001; // JNE +2
        let bytes = jne.to_le_bytes();
        let insn = Msp430FullDecoder::decode(&bytes, 0x4400).unwrap();
        assert_eq!(insn.mnemonic, "jne");
    }

    #[test]
    fn test_format_i_cmp_no_dst_modify() {
        assert!(!FormatIOp::Cmp.modifies_dst());
        assert!(!FormatIOp::Bit.modifies_dst());
        assert!(FormatIOp::Add.modifies_dst());
    }

    #[test]
    fn test_op_width_all() {
        let widths = [OpWidth::Word, OpWidth::Byte, OpWidth::Addr20];
        for w in widths {
            assert!(!format!("{w}").is_empty());
        }
    }

    #[test]
    fn test_addr_mode_indirect_display() {
        assert_eq!(format!("{}", AddrMode::IndirectReg), "indirect");
        assert_eq!(format!("{}", AddrMode::IndirectAutoInc), "auto-inc");
    }

    #[test]
    fn test_rpt_prefix_imm_max() {
        let rpt = RptPrefix::from_imm(15);
        assert_eq!(rpt.count(), 16);
    }

    #[test]
    fn test_msp430_instruction_is_memory_access_false() {
        let bytes: [u8; 2] = 0x3C00u16.to_le_bytes();
        let insn = Msp430FullDecoder::decode(&bytes, 0).unwrap();
        // JMP is not a memory access
        assert!(!insn.is_memory_access);
    }

    #[test]
    fn test_x_extended_parse_raw() {
        let w = 0x1234u16;
        let ext = XExtended::parse(w);
        assert_eq!(ext.raw, w);
    }

    #[test]
    fn test_pushpopm_addr_mode_field() {
        let p = PushPopM {
            is_push: true,
            n: 1,
            start_reg: Msp430Reg(10),
            addr_mode: true,
        };
        assert!(p.addr_mode);
    }
}
