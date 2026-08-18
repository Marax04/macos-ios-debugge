//! MOS 6502 disassembler — official opcodes + illegal/undocumented opcodes.
//!
//! Covers all 256 opcode slots including LAX, SAX, DCP, ISC, RLA, RRA, SLO, SRE,
//! ANC, ALR, ARR, XAA, AHX, TAS, SHY, SHX, LAS, and KIL variants.

use std::fmt;

// ── Cycle table (index = opcode) ──────────────────────────────────────────────
/// Base cycle counts for all 256 opcodes. +1 if page crossed, +1 if branch taken.
pub static CYCLE_TABLE: [u8; 256] = [
    7, 6, 2, 8, 3, 3, 5, 5, 3, 2, 2, 2, 4, 4, 6, 6, // 0x00–0x0F
    2, 5, 2, 8, 4, 4, 6, 6, 2, 4, 2, 7, 4, 4, 7, 7, // 0x10–0x1F
    6, 6, 2, 8, 3, 3, 5, 5, 4, 2, 2, 2, 4, 4, 6, 6, // 0x20–0x2F
    2, 5, 2, 8, 4, 4, 6, 6, 2, 4, 2, 7, 4, 4, 7, 7, // 0x30–0x3F
    6, 6, 2, 8, 3, 3, 5, 5, 3, 2, 2, 2, 3, 4, 6, 6, // 0x40–0x4F
    2, 5, 2, 8, 4, 4, 6, 6, 2, 4, 2, 7, 4, 4, 7, 7, // 0x50–0x5F
    6, 6, 2, 8, 3, 3, 5, 5, 4, 2, 2, 2, 5, 4, 6, 6, // 0x60–0x6F
    2, 5, 2, 8, 4, 4, 6, 6, 2, 4, 2, 7, 4, 4, 7, 7, // 0x70–0x7F
    2, 6, 2, 6, 3, 3, 3, 3, 2, 2, 2, 2, 4, 4, 4, 4, // 0x80–0x8F
    2, 6, 2, 6, 4, 4, 4, 4, 2, 5, 2, 5, 5, 5, 5, 5, // 0x90–0x9F
    2, 6, 2, 6, 3, 3, 3, 3, 2, 2, 2, 2, 4, 4, 4, 4, // 0xA0–0xAF
    2, 5, 2, 5, 4, 4, 4, 4, 2, 4, 2, 4, 4, 4, 4, 4, // 0xB0–0xBF
    2, 6, 2, 8, 3, 3, 5, 5, 2, 2, 2, 2, 4, 4, 6, 6, // 0xC0–0xCF
    2, 5, 2, 8, 4, 4, 6, 6, 2, 4, 2, 7, 4, 4, 7, 7, // 0xD0–0xDF
    2, 6, 2, 8, 3, 3, 5, 5, 2, 2, 2, 2, 4, 4, 6, 6, // 0xE0–0xEF
    2, 5, 2, 8, 4, 4, 6, 6, 2, 4, 2, 7, 4, 4, 7, 7, // 0xF0–0xFF
];

// ── Addressing mode operand ───────────────────────────────────────────────────

/// Decoded operand for a 6502 instruction, encoding the addressing mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mos6502Operand {
    Implied,
    Accumulator,
    Immediate(u8),
    ZeroPage(u8),
    ZeroPageX(u8),
    ZeroPageY(u8),
    Absolute(u16),
    AbsoluteX(u16),
    AbsoluteY(u16),
    Indirect(u16),
    IndirectX(u8),
    IndirectY(u8),
    Relative(i8),
}

impl fmt::Display for Mos6502Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mos6502Operand::Implied => Ok(()),
            Mos6502Operand::Accumulator => write!(f, "A"),
            Mos6502Operand::Immediate(v) => write!(f, "#${v:02X}"),
            Mos6502Operand::ZeroPage(a) => write!(f, "${a:02X}"),
            Mos6502Operand::ZeroPageX(a) => write!(f, "${a:02X},X"),
            Mos6502Operand::ZeroPageY(a) => write!(f, "${a:02X},Y"),
            Mos6502Operand::Absolute(a) => write!(f, "${a:04X}"),
            Mos6502Operand::AbsoluteX(a) => write!(f, "${a:04X},X"),
            Mos6502Operand::AbsoluteY(a) => write!(f, "${a:04X},Y"),
            Mos6502Operand::Indirect(a) => write!(f, "(${a:04X})"),
            Mos6502Operand::IndirectX(a) => write!(f, "(${a:02X},X)"),
            Mos6502Operand::IndirectY(a) => write!(f, "(${a:02X}),Y"),
            Mos6502Operand::Relative(off) => write!(f, "{off:+}"),
        }
    }
}

// ── Decoded instruction ───────────────────────────────────────────────────────

/// A fully decoded MOS 6502 instruction.
#[derive(Debug, Clone)]
pub struct Mos6502Insn {
    /// Program counter of this instruction.
    pub addr: u16,
    /// Raw opcode byte.
    pub opcode: u8,
    /// All bytes consumed (1–3).
    pub bytes: Vec<u8>,
    /// ASCII mnemonic (uppercase, 3–4 chars).
    pub mnemonic: &'static str,
    /// Decoded operand / addressing mode.
    pub operand: Mos6502Operand,
    /// Base cycle count (before page-cross / branch-taken adjustments).
    pub cycles: u8,
    /// True for unofficial / illegal opcodes.
    pub illegal: bool,
}

impl Mos6502Insn {
    /// Number of bytes this instruction occupies.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Human-readable disassembly, e.g. `"LDA #$FF"`.
    #[must_use]
    pub fn format_insn(&self) -> String {
        let op_str = self.operand.to_string();
        if op_str.is_empty() {
            self.mnemonic.to_string()
        } else {
            format!("{} {}", self.mnemonic, op_str)
        }
    }

    /// Address of the next instruction.
    #[must_use]
    pub fn next_addr(&self) -> u16 {
        self.addr.wrapping_add(self.len() as u16)
    }

    /// Resolve the absolute branch target (for `Relative` operands).
    #[must_use]
    pub fn branch_target(&self) -> Option<u16> {
        if let Mos6502Operand::Relative(off) = self.operand {
            let next = self.next_addr();
            Some(next.wrapping_add(i16::from(off) as u16))
        } else {
            None
        }
    }
}

impl fmt::Display for Mos6502Insn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "${:04X}: {:8}", self.addr, self.format_insn())
    }
}

// ── Opcode table entry ────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct OpcodeEntry {
    mnemonic: &'static str,
    mode: AddrMode,
    illegal: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AddrMode {
    Imp,
    Acc,
    Imm,
    Zpg,
    ZpgX,
    ZpgY,
    Abs,
    AbsX,
    AbsY,
    Ind,
    IndX,
    IndY,
    Rel,
    Kil, // JAM / KIL (locks up the CPU)
}

impl AddrMode {
    const fn byte_count(self) -> usize {
        match self {
            AddrMode::Imp | AddrMode::Acc | AddrMode::Kil => 1,
            AddrMode::Imm
            | AddrMode::Zpg
            | AddrMode::ZpgX
            | AddrMode::ZpgY
            | AddrMode::IndX
            | AddrMode::IndY
            | AddrMode::Rel => 2,
            AddrMode::Abs | AddrMode::AbsX | AddrMode::AbsY | AddrMode::Ind => 3,
        }
    }
}

macro_rules! op {
    ($m:expr, $mode:expr) => {
        OpcodeEntry { mnemonic: $m, mode: $mode, illegal: false }
    };
    ($m:expr, $mode:expr, ill) => {
        OpcodeEntry { mnemonic: $m, mode: $mode, illegal: true }
    };
}

// Full 256-entry opcode table.
static OPCODE_TABLE: [OpcodeEntry; 256] = [
    /* 00 */ op!("BRK", AddrMode::Imp),
    /* 01 */ op!("ORA", AddrMode::IndX),
    /* 02 */ op!("KIL", AddrMode::Kil, ill),
    /* 03 */ op!("SLO", AddrMode::IndX, ill),
    /* 04 */ op!("NOP", AddrMode::Zpg, ill),
    /* 05 */ op!("ORA", AddrMode::Zpg),
    /* 06 */ op!("ASL", AddrMode::Zpg),
    /* 07 */ op!("SLO", AddrMode::Zpg, ill),
    /* 08 */ op!("PHP", AddrMode::Imp),
    /* 09 */ op!("ORA", AddrMode::Imm),
    /* 0A */ op!("ASL", AddrMode::Acc),
    /* 0B */ op!("ANC", AddrMode::Imm, ill),
    /* 0C */ op!("NOP", AddrMode::Abs, ill),
    /* 0D */ op!("ORA", AddrMode::Abs),
    /* 0E */ op!("ASL", AddrMode::Abs),
    /* 0F */ op!("SLO", AddrMode::Abs, ill),
    /* 10 */ op!("BPL", AddrMode::Rel),
    /* 11 */ op!("ORA", AddrMode::IndY),
    /* 12 */ op!("KIL", AddrMode::Kil, ill),
    /* 13 */ op!("SLO", AddrMode::IndY, ill),
    /* 14 */ op!("NOP", AddrMode::ZpgX, ill),
    /* 15 */ op!("ORA", AddrMode::ZpgX),
    /* 16 */ op!("ASL", AddrMode::ZpgX),
    /* 17 */ op!("SLO", AddrMode::ZpgX, ill),
    /* 18 */ op!("CLC", AddrMode::Imp),
    /* 19 */ op!("ORA", AddrMode::AbsY),
    /* 1A */ op!("NOP", AddrMode::Imp, ill),
    /* 1B */ op!("SLO", AddrMode::AbsY, ill),
    /* 1C */ op!("NOP", AddrMode::AbsX, ill),
    /* 1D */ op!("ORA", AddrMode::AbsX),
    /* 1E */ op!("ASL", AddrMode::AbsX),
    /* 1F */ op!("SLO", AddrMode::AbsX, ill),
    /* 20 */ op!("JSR", AddrMode::Abs),
    /* 21 */ op!("AND", AddrMode::IndX),
    /* 22 */ op!("KIL", AddrMode::Kil, ill),
    /* 23 */ op!("RLA", AddrMode::IndX, ill),
    /* 24 */ op!("BIT", AddrMode::Zpg),
    /* 25 */ op!("AND", AddrMode::Zpg),
    /* 26 */ op!("ROL", AddrMode::Zpg),
    /* 27 */ op!("RLA", AddrMode::Zpg, ill),
    /* 28 */ op!("PLP", AddrMode::Imp),
    /* 29 */ op!("AND", AddrMode::Imm),
    /* 2A */ op!("ROL", AddrMode::Acc),
    /* 2B */ op!("ANC", AddrMode::Imm, ill),
    /* 2C */ op!("BIT", AddrMode::Abs),
    /* 2D */ op!("AND", AddrMode::Abs),
    /* 2E */ op!("ROL", AddrMode::Abs),
    /* 2F */ op!("RLA", AddrMode::Abs, ill),
    /* 30 */ op!("BMI", AddrMode::Rel),
    /* 31 */ op!("AND", AddrMode::IndY),
    /* 32 */ op!("KIL", AddrMode::Kil, ill),
    /* 33 */ op!("RLA", AddrMode::IndY, ill),
    /* 34 */ op!("NOP", AddrMode::ZpgX, ill),
    /* 35 */ op!("AND", AddrMode::ZpgX),
    /* 36 */ op!("ROL", AddrMode::ZpgX),
    /* 37 */ op!("RLA", AddrMode::ZpgX, ill),
    /* 38 */ op!("SEC", AddrMode::Imp),
    /* 39 */ op!("AND", AddrMode::AbsY),
    /* 3A */ op!("NOP", AddrMode::Imp, ill),
    /* 3B */ op!("RLA", AddrMode::AbsY, ill),
    /* 3C */ op!("NOP", AddrMode::AbsX, ill),
    /* 3D */ op!("AND", AddrMode::AbsX),
    /* 3E */ op!("ROL", AddrMode::AbsX),
    /* 3F */ op!("RLA", AddrMode::AbsX, ill),
    /* 40 */ op!("RTI", AddrMode::Imp),
    /* 41 */ op!("EOR", AddrMode::IndX),
    /* 42 */ op!("KIL", AddrMode::Kil, ill),
    /* 43 */ op!("SRE", AddrMode::IndX, ill),
    /* 44 */ op!("NOP", AddrMode::Zpg, ill),
    /* 45 */ op!("EOR", AddrMode::Zpg),
    /* 46 */ op!("LSR", AddrMode::Zpg),
    /* 47 */ op!("SRE", AddrMode::Zpg, ill),
    /* 48 */ op!("PHA", AddrMode::Imp),
    /* 49 */ op!("EOR", AddrMode::Imm),
    /* 4A */ op!("LSR", AddrMode::Acc),
    /* 4B */ op!("ALR", AddrMode::Imm, ill),
    /* 4C */ op!("JMP", AddrMode::Abs),
    /* 4D */ op!("EOR", AddrMode::Abs),
    /* 4E */ op!("LSR", AddrMode::Abs),
    /* 4F */ op!("SRE", AddrMode::Abs, ill),
    /* 50 */ op!("BVC", AddrMode::Rel),
    /* 51 */ op!("EOR", AddrMode::IndY),
    /* 52 */ op!("KIL", AddrMode::Kil, ill),
    /* 53 */ op!("SRE", AddrMode::IndY, ill),
    /* 54 */ op!("NOP", AddrMode::ZpgX, ill),
    /* 55 */ op!("EOR", AddrMode::ZpgX),
    /* 56 */ op!("LSR", AddrMode::ZpgX),
    /* 57 */ op!("SRE", AddrMode::ZpgX, ill),
    /* 58 */ op!("CLI", AddrMode::Imp),
    /* 59 */ op!("EOR", AddrMode::AbsY),
    /* 5A */ op!("NOP", AddrMode::Imp, ill),
    /* 5B */ op!("SRE", AddrMode::AbsY, ill),
    /* 5C */ op!("NOP", AddrMode::AbsX, ill),
    /* 5D */ op!("EOR", AddrMode::AbsX),
    /* 5E */ op!("LSR", AddrMode::AbsX),
    /* 5F */ op!("SRE", AddrMode::AbsX, ill),
    /* 60 */ op!("RTS", AddrMode::Imp),
    /* 61 */ op!("ADC", AddrMode::IndX),
    /* 62 */ op!("KIL", AddrMode::Kil, ill),
    /* 63 */ op!("RRA", AddrMode::IndX, ill),
    /* 64 */ op!("NOP", AddrMode::Zpg, ill),
    /* 65 */ op!("ADC", AddrMode::Zpg),
    /* 66 */ op!("ROR", AddrMode::Zpg),
    /* 67 */ op!("RRA", AddrMode::Zpg, ill),
    /* 68 */ op!("PLA", AddrMode::Imp),
    /* 69 */ op!("ADC", AddrMode::Imm),
    /* 6A */ op!("ROR", AddrMode::Acc),
    /* 6B */ op!("ARR", AddrMode::Imm, ill),
    /* 6C */ op!("JMP", AddrMode::Ind),
    /* 6D */ op!("ADC", AddrMode::Abs),
    /* 6E */ op!("ROR", AddrMode::Abs),
    /* 6F */ op!("RRA", AddrMode::Abs, ill),
    /* 70 */ op!("BVS", AddrMode::Rel),
    /* 71 */ op!("ADC", AddrMode::IndY),
    /* 72 */ op!("KIL", AddrMode::Kil, ill),
    /* 73 */ op!("RRA", AddrMode::IndY, ill),
    /* 74 */ op!("NOP", AddrMode::ZpgX, ill),
    /* 75 */ op!("ADC", AddrMode::ZpgX),
    /* 76 */ op!("ROR", AddrMode::ZpgX),
    /* 77 */ op!("RRA", AddrMode::ZpgX, ill),
    /* 78 */ op!("SEI", AddrMode::Imp),
    /* 79 */ op!("ADC", AddrMode::AbsY),
    /* 7A */ op!("NOP", AddrMode::Imp, ill),
    /* 7B */ op!("RRA", AddrMode::AbsY, ill),
    /* 7C */ op!("NOP", AddrMode::AbsX, ill),
    /* 7D */ op!("ADC", AddrMode::AbsX),
    /* 7E */ op!("ROR", AddrMode::AbsX),
    /* 7F */ op!("RRA", AddrMode::AbsX, ill),
    /* 80 */ op!("NOP", AddrMode::Imm, ill),
    /* 81 */ op!("STA", AddrMode::IndX),
    /* 82 */ op!("NOP", AddrMode::Imm, ill),
    /* 83 */ op!("SAX", AddrMode::IndX, ill),
    /* 84 */ op!("STY", AddrMode::Zpg),
    /* 85 */ op!("STA", AddrMode::Zpg),
    /* 86 */ op!("STX", AddrMode::Zpg),
    /* 87 */ op!("SAX", AddrMode::Zpg, ill),
    /* 88 */ op!("DEY", AddrMode::Imp),
    /* 89 */ op!("NOP", AddrMode::Imm, ill),
    /* 8A */ op!("TXA", AddrMode::Imp),
    /* 8B */ op!("XAA", AddrMode::Imm, ill),
    /* 8C */ op!("STY", AddrMode::Abs),
    /* 8D */ op!("STA", AddrMode::Abs),
    /* 8E */ op!("STX", AddrMode::Abs),
    /* 8F */ op!("SAX", AddrMode::Abs, ill),
    /* 90 */ op!("BCC", AddrMode::Rel),
    /* 91 */ op!("STA", AddrMode::IndY),
    /* 92 */ op!("KIL", AddrMode::Kil, ill),
    /* 93 */ op!("AHX", AddrMode::IndY, ill),
    /* 94 */ op!("STY", AddrMode::ZpgX),
    /* 95 */ op!("STA", AddrMode::ZpgX),
    /* 96 */ op!("STX", AddrMode::ZpgY),
    /* 97 */ op!("SAX", AddrMode::ZpgY, ill),
    /* 98 */ op!("TYA", AddrMode::Imp),
    /* 99 */ op!("STA", AddrMode::AbsY),
    /* 9A */ op!("TXS", AddrMode::Imp),
    /* 9B */ op!("TAS", AddrMode::AbsY, ill),
    /* 9C */ op!("SHY", AddrMode::AbsX, ill),
    /* 9D */ op!("STA", AddrMode::AbsX),
    /* 9E */ op!("SHX", AddrMode::AbsY, ill),
    /* 9F */ op!("AHX", AddrMode::AbsY, ill),
    /* A0 */ op!("LDY", AddrMode::Imm),
    /* A1 */ op!("LDA", AddrMode::IndX),
    /* A2 */ op!("LDX", AddrMode::Imm),
    /* A3 */ op!("LAX", AddrMode::IndX, ill),
    /* A4 */ op!("LDY", AddrMode::Zpg),
    /* A5 */ op!("LDA", AddrMode::Zpg),
    /* A6 */ op!("LDX", AddrMode::Zpg),
    /* A7 */ op!("LAX", AddrMode::Zpg, ill),
    /* A8 */ op!("TAY", AddrMode::Imp),
    /* A9 */ op!("LDA", AddrMode::Imm),
    /* AA */ op!("TAX", AddrMode::Imp),
    /* AB */ op!("LAX", AddrMode::Imm, ill),
    /* AC */ op!("LDY", AddrMode::Abs),
    /* AD */ op!("LDA", AddrMode::Abs),
    /* AE */ op!("LDX", AddrMode::Abs),
    /* AF */ op!("LAX", AddrMode::Abs, ill),
    /* B0 */ op!("BCS", AddrMode::Rel),
    /* B1 */ op!("LDA", AddrMode::IndY),
    /* B2 */ op!("KIL", AddrMode::Kil, ill),
    /* B3 */ op!("LAX", AddrMode::IndY, ill),
    /* B4 */ op!("LDY", AddrMode::ZpgX),
    /* B5 */ op!("LDA", AddrMode::ZpgX),
    /* B6 */ op!("LDX", AddrMode::ZpgY),
    /* B7 */ op!("LAX", AddrMode::ZpgY, ill),
    /* B8 */ op!("CLV", AddrMode::Imp),
    /* B9 */ op!("LDA", AddrMode::AbsY),
    /* BA */ op!("TSX", AddrMode::Imp),
    /* BB */ op!("LAS", AddrMode::AbsY, ill),
    /* BC */ op!("LDY", AddrMode::AbsX),
    /* BD */ op!("LDA", AddrMode::AbsX),
    /* BE */ op!("LDX", AddrMode::AbsY),
    /* BF */ op!("LAX", AddrMode::AbsY, ill),
    /* C0 */ op!("CPY", AddrMode::Imm),
    /* C1 */ op!("CMP", AddrMode::IndX),
    /* C2 */ op!("NOP", AddrMode::Imm, ill),
    /* C3 */ op!("DCP", AddrMode::IndX, ill),
    /* C4 */ op!("CPY", AddrMode::Zpg),
    /* C5 */ op!("CMP", AddrMode::Zpg),
    /* C6 */ op!("DEC", AddrMode::Zpg),
    /* C7 */ op!("DCP", AddrMode::Zpg, ill),
    /* C8 */ op!("INY", AddrMode::Imp),
    /* C9 */ op!("CMP", AddrMode::Imm),
    /* CA */ op!("DEX", AddrMode::Imp),
    /* CB */ op!("AXS", AddrMode::Imm, ill),
    /* CC */ op!("CPY", AddrMode::Abs),
    /* CD */ op!("CMP", AddrMode::Abs),
    /* CE */ op!("DEC", AddrMode::Abs),
    /* CF */ op!("DCP", AddrMode::Abs, ill),
    /* D0 */ op!("BNE", AddrMode::Rel),
    /* D1 */ op!("CMP", AddrMode::IndY),
    /* D2 */ op!("KIL", AddrMode::Kil, ill),
    /* D3 */ op!("DCP", AddrMode::IndY, ill),
    /* D4 */ op!("NOP", AddrMode::ZpgX, ill),
    /* D5 */ op!("CMP", AddrMode::ZpgX),
    /* D6 */ op!("DEC", AddrMode::ZpgX),
    /* D7 */ op!("DCP", AddrMode::ZpgX, ill),
    /* D8 */ op!("CLD", AddrMode::Imp),
    /* D9 */ op!("CMP", AddrMode::AbsY),
    /* DA */ op!("NOP", AddrMode::Imp, ill),
    /* DB */ op!("DCP", AddrMode::AbsY, ill),
    /* DC */ op!("NOP", AddrMode::AbsX, ill),
    /* DD */ op!("CMP", AddrMode::AbsX),
    /* DE */ op!("DEC", AddrMode::AbsX),
    /* DF */ op!("DCP", AddrMode::AbsX, ill),
    /* E0 */ op!("CPX", AddrMode::Imm),
    /* E1 */ op!("SBC", AddrMode::IndX),
    /* E2 */ op!("NOP", AddrMode::Imm, ill),
    /* E3 */ op!("ISC", AddrMode::IndX, ill),
    /* E4 */ op!("CPX", AddrMode::Zpg),
    /* E5 */ op!("SBC", AddrMode::Zpg),
    /* E6 */ op!("INC", AddrMode::Zpg),
    /* E7 */ op!("ISC", AddrMode::Zpg, ill),
    /* E8 */ op!("INX", AddrMode::Imp),
    /* E9 */ op!("SBC", AddrMode::Imm),
    /* EA */ op!("NOP", AddrMode::Imp),
    /* EB */ op!("SBC", AddrMode::Imm, ill),
    /* EC */ op!("CPX", AddrMode::Abs),
    /* ED */ op!("SBC", AddrMode::Abs),
    /* EE */ op!("INC", AddrMode::Abs),
    /* EF */ op!("ISC", AddrMode::Abs, ill),
    /* F0 */ op!("BEQ", AddrMode::Rel),
    /* F1 */ op!("SBC", AddrMode::IndY),
    /* F2 */ op!("KIL", AddrMode::Kil, ill),
    /* F3 */ op!("ISC", AddrMode::IndY, ill),
    /* F4 */ op!("NOP", AddrMode::ZpgX, ill),
    /* F5 */ op!("SBC", AddrMode::ZpgX),
    /* F6 */ op!("INC", AddrMode::ZpgX),
    /* F7 */ op!("ISC", AddrMode::ZpgX, ill),
    /* F8 */ op!("SED", AddrMode::Imp),
    /* F9 */ op!("SBC", AddrMode::AbsY),
    /* FA */ op!("NOP", AddrMode::Imp, ill),
    /* FB */ op!("ISC", AddrMode::AbsY, ill),
    /* FC */ op!("NOP", AddrMode::AbsX, ill),
    /* FD */ op!("SBC", AddrMode::AbsX),
    /* FE */ op!("INC", AddrMode::AbsX),
    /* FF */ op!("ISC", AddrMode::AbsX, ill),
];

// ── Disassembler ──────────────────────────────────────────────────────────────

/// Stateless MOS 6502 disassembler.
pub struct Mos6502Disassembler;

impl Mos6502Disassembler {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Decode one instruction at `pc` from `data` (data is addressed from `base_addr`).
    #[must_use]
    pub fn decode_one(&self, data: &[u8], base_addr: u16, offset: usize) -> Option<Mos6502Insn> {
        if offset >= data.len() {
            return None;
        }
        let opcode = data[offset];
        let entry = OPCODE_TABLE[opcode as usize];
        let needed = entry.mode.byte_count();
        if offset + needed > data.len() {
            // Emit a 1-byte "truncated" NOP for safety.
            return Some(Mos6502Insn {
                addr: base_addr.wrapping_add(offset as u16),
                opcode,
                bytes: vec![opcode],
                mnemonic: "???",
                operand: Mos6502Operand::Implied,
                cycles: 2,
                illegal: true,
            });
        }
        let addr = base_addr.wrapping_add(offset as u16);
        let raw = &data[offset..offset + needed];
        let operand = Self::build_operand(entry.mode, raw, addr);
        Some(Mos6502Insn {
            addr,
            opcode,
            bytes: raw.to_vec(),
            mnemonic: entry.mnemonic,
            operand,
            cycles: CYCLE_TABLE[opcode as usize],
            illegal: entry.illegal,
        })
    }

    fn build_operand(mode: AddrMode, raw: &[u8], addr: u16) -> Mos6502Operand {
        match mode {
            AddrMode::Imp | AddrMode::Kil => Mos6502Operand::Implied,
            AddrMode::Acc => Mos6502Operand::Accumulator,
            AddrMode::Imm => Mos6502Operand::Immediate(raw[1]),
            AddrMode::Zpg => Mos6502Operand::ZeroPage(raw[1]),
            AddrMode::ZpgX => Mos6502Operand::ZeroPageX(raw[1]),
            AddrMode::ZpgY => Mos6502Operand::ZeroPageY(raw[1]),
            AddrMode::Abs => Mos6502Operand::Absolute(u16::from_le_bytes([raw[1], raw[2]])),
            AddrMode::AbsX => Mos6502Operand::AbsoluteX(u16::from_le_bytes([raw[1], raw[2]])),
            AddrMode::AbsY => Mos6502Operand::AbsoluteY(u16::from_le_bytes([raw[1], raw[2]])),
            AddrMode::Ind => Mos6502Operand::Indirect(u16::from_le_bytes([raw[1], raw[2]])),
            AddrMode::IndX => Mos6502Operand::IndirectX(raw[1]),
            AddrMode::IndY => Mos6502Operand::IndirectY(raw[1]),
            AddrMode::Rel => {
                let next = addr.wrapping_add(2);
                let _ = next; // branch target resolved lazily
                Mos6502Operand::Relative(raw[1] as i8)
            }
        }
    }

    /// Decode a complete buffer into instructions, starting from `base_addr`.
    #[must_use]
    pub fn decode(&self, data: &[u8], base_addr: u16) -> Vec<Mos6502Insn> {
        // Average 6502 instruction is ~2 bytes; over-allocate slightly.
        let mut result = Vec::with_capacity(data.len() / 2 + 1);
        let mut offset = 0usize;
        while offset < data.len() {
            if let Some(insn) = self.decode_one(data, base_addr, offset) {
                let advance = insn.len().max(1);
                result.push(insn);
                offset += advance;
            } else {
                break;
            }
        }
        result
    }

    /// Detect BCD (Binary Coded Decimal) mode usage in the instruction stream.
    /// Returns offsets where `SED` (Set Decimal) is encountered.
    #[must_use]
    pub fn detect_bcd_mode(&self, insns: &[Mos6502Insn]) -> Vec<u16> {
        insns.iter()
            .filter(|i| i.mnemonic == "SED")
            .map(|i| i.addr)
            .collect()
    }

    /// Read the 6502 interrupt vectors from the last 6 bytes of a ROM image.
    /// Standard layout: NMI at $FFFA/$FFFB, RESET at $FFFC/$FFFD, IRQ/BRK at $FFFE/$FFFF.
    #[must_use]
    pub fn detect_irq_vectors(&self, data: &[u8]) -> Option<InterruptVectors> {
        if data.len() < 6 {
            return None;
        }
        let base = data.len() - 6;
        let nmi   = u16::from_le_bytes([data[base],     data[base + 1]]);
        let reset = u16::from_le_bytes([data[base + 2], data[base + 3]]);
        let irq   = u16::from_le_bytes([data[base + 4], data[base + 5]]);
        Some(InterruptVectors { nmi, reset, irq })
    }

    /// Format a range of instructions as a listing string.
    #[must_use]
    pub fn format_listing(&self, insns: &[Mos6502Insn]) -> String {
        use std::fmt::Write as _;
        // Reserve ~20 chars per instruction as a rough lower bound.
        let mut out = String::with_capacity(insns.len() * 20);
        for insn in insns {
            // Build bytes hex in a small stack buffer to avoid a heap allocation
            // per instruction.
            let mut bytes_hex = String::with_capacity(insn.bytes.len() * 3);
            for b in &insn.bytes {
                let _ = write!(bytes_hex, "{b:02X} ");
            }
            let bytes_hex = bytes_hex.trim_end();
            let ill = if insn.illegal { '*' } else { ' ' };
            let _ = writeln!(
                out,
                "${:04X}: {:8} {}{}",
                insn.addr,
                bytes_hex,
                ill,
                insn.format_insn()
            );
        }
        out
    }

    /// Count cycles for a linear block (ignoring branches/page-crosses).
    #[must_use]
    pub fn count_cycles(&self, insns: &[Mos6502Insn]) -> u32 {
        insns.iter().map(|i| u32::from(i.cycles)).sum()
    }

    /// Find all JSR targets in the instruction stream.
    #[must_use]
    pub fn find_jsr_targets(&self, insns: &[Mos6502Insn]) -> Vec<u16> {
        insns.iter()
            .filter_map(|i| {
                if let Mos6502Operand::Absolute(target) = i.operand {
                    (i.mnemonic == "JSR").then_some(target)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Find all unconditional JMP targets.
    #[must_use]
    pub fn find_jmp_targets(&self, insns: &[Mos6502Insn]) -> Vec<u16> {
        insns.iter()
            .filter_map(|i| {
                if let Mos6502Operand::Absolute(target) = i.operand {
                    (i.mnemonic == "JMP").then_some(target)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Collect all illegal opcodes in a decoded stream.
    #[must_use]
    pub fn find_illegal_opcodes<'a>(&self, insns: &'a [Mos6502Insn]) -> Vec<&'a Mos6502Insn> {
        insns.iter().filter(|i| i.illegal).collect()
    }

    /// Return the opcode entry for a raw byte.
    #[must_use]
    pub fn opcode_info(opcode: u8) -> (&'static str, bool) {
        let e = OPCODE_TABLE[opcode as usize];
        (e.mnemonic, e.illegal)
    }
}

impl Default for Mos6502Disassembler {
    fn default() -> Self {
        Self::new()
    }
}

/// 6502 interrupt vectors (NMI, RESET, IRQ/BRK).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterruptVectors {
    pub nmi: u16,
    pub reset: u16,
    pub irq: u16,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dis() -> Mos6502Disassembler {
        Mos6502Disassembler::new()
    }

    #[test]
    fn decode_lda_imm() {
        let insns = dis().decode(&[0xA9, 0xFF], 0x0000);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].mnemonic, "LDA");
        assert_eq!(insns[0].operand, Mos6502Operand::Immediate(0xFF));
        assert_eq!(insns[0].cycles, 2);
        assert!(!insns[0].illegal);
    }

    #[test]
    fn decode_lda_zpg() {
        let insns = dis().decode(&[0xA5, 0x42], 0x0200);
        assert_eq!(insns[0].mnemonic, "LDA");
        assert_eq!(insns[0].operand, Mos6502Operand::ZeroPage(0x42));
        assert_eq!(insns[0].addr, 0x0200);
    }

    #[test]
    fn decode_jsr_abs() {
        let insns = dis().decode(&[0x20, 0x00, 0xC0], 0x8000);
        assert_eq!(insns[0].mnemonic, "JSR");
        assert_eq!(insns[0].operand, Mos6502Operand::Absolute(0xC000));
        assert_eq!(insns[0].cycles, 6);
    }

    #[test]
    fn decode_bne_rel() {
        let insns = dis().decode(&[0xD0, 0x04], 0x0300);
        assert_eq!(insns[0].mnemonic, "BNE");
        assert_eq!(insns[0].operand, Mos6502Operand::Relative(4));
        assert_eq!(insns[0].branch_target(), Some(0x0306));
    }

    #[test]
    fn decode_bne_backward() {
        let insns = dis().decode(&[0xD0, 0xFE_u8], 0x0300); // -2 => infinite loop
        if let Mos6502Operand::Relative(off) = insns[0].operand {
            assert_eq!(off, -2i8);
        } else {
            panic!("wrong operand");
        }
    }

    #[test]
    fn decode_jmp_indirect() {
        let insns = dis().decode(&[0x6C, 0x10, 0x03], 0x0000);
        assert_eq!(insns[0].mnemonic, "JMP");
        assert_eq!(insns[0].operand, Mos6502Operand::Indirect(0x0310));
    }

    #[test]
    fn decode_illegal_lax() {
        let insns = dis().decode(&[0xA7, 0x80], 0x0000);
        assert_eq!(insns[0].mnemonic, "LAX");
        assert!(insns[0].illegal);
        assert_eq!(insns[0].operand, Mos6502Operand::ZeroPage(0x80));
    }

    #[test]
    fn decode_illegal_sax() {
        let insns = dis().decode(&[0x87, 0x20], 0x0000);
        assert_eq!(insns[0].mnemonic, "SAX");
        assert!(insns[0].illegal);
    }

    #[test]
    fn decode_illegal_dcp() {
        let insns = dis().decode(&[0xC7, 0x10], 0x0000);
        assert_eq!(insns[0].mnemonic, "DCP");
        assert!(insns[0].illegal);
    }

    #[test]
    fn decode_illegal_isc() {
        let insns = dis().decode(&[0xE7, 0x10], 0x0000);
        assert_eq!(insns[0].mnemonic, "ISC");
        assert!(insns[0].illegal);
    }

    #[test]
    fn detect_bcd_mode_finds_sed() {
        let data = [0xA9, 0x01, 0xF8, 0x69, 0x01]; // LDA #1, SED, ADC #1
        let insns = dis().decode(&data, 0x0200);
        let bcd = dis().detect_bcd_mode(&insns);
        assert_eq!(bcd, vec![0x0202]);
    }

    #[test]
    fn detect_irq_vectors_valid() {
        let mut rom = vec![0u8; 64];
        rom[58] = 0x00; rom[59] = 0x80; // NMI  = $8000
        rom[60] = 0x00; rom[61] = 0xC0; // RESET= $C000
        rom[62] = 0x00; rom[63] = 0xFF; // IRQ  = $FF00
        let vecs = dis().detect_irq_vectors(&rom).unwrap();
        assert_eq!(vecs.nmi, 0x8000);
        assert_eq!(vecs.reset, 0xC000);
        assert_eq!(vecs.irq, 0xFF00);
    }

    #[test]
    fn cycle_table_brk_is_7() {
        assert_eq!(CYCLE_TABLE[0x00], 7);
    }

    #[test]
    fn cycle_table_nop_is_2() {
        assert_eq!(CYCLE_TABLE[0xEA], 2);
    }

    #[test]
    fn find_jsr_targets() {
        let data = [0x20, 0x00, 0xC0, 0x20, 0x10, 0xC0];
        let insns = dis().decode(&data, 0x8000);
        let targets = dis().find_jsr_targets(&insns);
        assert_eq!(targets, vec![0xC000, 0xC010]);
    }

    #[test]
    fn format_insn_accumulator() {
        let insns = dis().decode(&[0x0A], 0x0000); // ASL A
        assert_eq!(insns[0].format_insn(), "ASL A");
    }

    #[test]
    fn decode_abs_x_sta() {
        let insns = dis().decode(&[0x9D, 0x00, 0x02], 0x0000);
        assert_eq!(insns[0].mnemonic, "STA");
        assert_eq!(insns[0].operand, Mos6502Operand::AbsoluteX(0x0200));
    }

    #[test]
    fn decode_ind_x_lda() {
        let insns = dis().decode(&[0xA1, 0x10], 0x0000);
        assert_eq!(insns[0].mnemonic, "LDA");
        assert_eq!(insns[0].operand, Mos6502Operand::IndirectX(0x10));
    }

    #[test]
    fn decode_ind_y_lda() {
        let insns = dis().decode(&[0xB1, 0x10], 0x0000);
        assert_eq!(insns[0].mnemonic, "LDA");
        assert_eq!(insns[0].operand, Mos6502Operand::IndirectY(0x10));
    }

    #[test]
    fn kil_is_1_byte_illegal() {
        let insns = dis().decode(&[0x02], 0x0000);
        assert_eq!(insns[0].mnemonic, "KIL");
        assert!(insns[0].illegal);
        assert_eq!(insns[0].bytes.len(), 1);
    }
}
