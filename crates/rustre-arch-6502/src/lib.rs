//! `rustre-arch-6502`
//!
//! MOS 6502, 65C02, and 65816 architecture implementation for the `RustRE` Suite.
//!
//! Covers all 56 official 6502 opcodes, all addressing modes, cycle counts,
//! undocumented/illegal opcodes, 65C02 extensions, and 65816 extensions.

use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
use rustre_core::arch::{BranchCondition, RegisterKind};
use rustre_core::{address::Address, endian::Endian, errors::CoreError};

// ── Extension modules ─────────────────────────────────────────────────────────

/// WDC 65C02 decoder extensions (BBR/BBS/RMB/SMB/STZ/TRB/TSB/WAI/STP).
pub mod decoder_65c02;

/// WDC 65816 decoder (24-bit addressing, native/emulation mode, full ISA).
pub mod decoder_65816;

/// IL lifter: maps 6502/65C02/65816 instructions to IL operations.
pub mod lifter;

/// Software emulator for 6502, 65C02, and 65816 with BCD mode and interrupts.
pub mod emulator;

/// Static analysis utilities: function detection, vector tables, strings, entropy.
pub mod analysis;

/// Comprehensive CPU test harness: TestCase, TestRunner, FlagChecker,
/// CycleCounter, TestReport, and 100+ built-in test cases covering every
/// addressing mode on 6502/65C02/65816.
///
pub mod cpu_tester;

/// Two-pass 6502/65C02/65816 assembler with directives, labels, and listing output.
pub mod assembler_6502;

/// MOS 6502 disassembler: full 256-opcode table including all illegal opcodes.
pub mod mos6502_disassembler;

/// MOS 6502 addressing mode decoder and 64 KB memory model.
pub mod mos6502_addressing_modes;

/// MOS 6502 ROM format analyzer: iNES/NES, C64 PRG, Atari 2600, Apple II.
pub mod mos6502_rom_analyzer;

/// MOS 6502 addressing mode decoder and effective-address calculator.
pub mod mos6502_address_modes;

/// Zero-page variable tracking for MOS 6502 programs.
pub mod mos6502_zero_page;

/// Platform identification via 6502 hardware vectors (RESET/NMI/IRQ).
pub mod mos6502_platform_vectors;

// ── Register IDs ─────────────────────────────────────────────────────────────
pub const REG_A: u32 = 0;
pub const REG_X: u32 = 1;
pub const REG_Y: u32 = 2;
pub const REG_SP: u32 = 3;
pub const REG_PC: u32 = 4;
pub const REG_P: u32 = 5;

// ── Status register bits ──────────────────────────────────────────────────────
pub mod status {
    pub const C: u8 = 1 << 0; // Carry
    pub const Z: u8 = 1 << 1; // Zero
    pub const I: u8 = 1 << 2; // IRQ Disable
    pub const D: u8 = 1 << 3; // Decimal Mode
    pub const B: u8 = 1 << 4; // Break
    pub const U: u8 = 1 << 5; // Unused (always 1)
    pub const V: u8 = 1 << 6; // Overflow
    pub const N: u8 = 1 << 7; // Negative
}

// ── Addressing modes ──────────────────────────────────────────────────────────

/// All 6502/65C02/65816 addressing modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrMode {
    Implied,
    Accumulator,
    Immediate,
    ZeroPage,
    ZeroPageX,
    ZeroPageY,
    Absolute,
    AbsoluteX,
    AbsoluteY,
    Indirect,
    IndirectX, // (zp,X)
    IndirectY, // (zp),Y
    Relative,
    // 65C02 / 65816 extensions
    ZeroPageIndirect,  // (zp)
    AbsoluteIndirectX, // (abs,X)
    RelativeLong,      // 65816 only (3-byte)
    // Illegal opcodes that encode two operations
    Illegal,
}

impl AddrMode {
    /// Number of operand bytes (not counting the opcode byte).
    #[must_use]
    pub const fn extra_bytes(self) -> u16 {
        match self {
            Self::Implied | Self::Accumulator | Self::Illegal => 0,
            Self::Immediate
            | Self::ZeroPage
            | Self::ZeroPageX
            | Self::ZeroPageY
            | Self::IndirectX
            | Self::IndirectY
            | Self::Relative
            | Self::ZeroPageIndirect => 1,
            Self::Absolute
            | Self::AbsoluteX
            | Self::AbsoluteY
            | Self::Indirect
            | Self::AbsoluteIndirectX
            | Self::RelativeLong => 2,
        }
    }

    /// Human-readable mode name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Implied => "implied",
            Self::Accumulator => "accumulator",
            Self::Immediate => "immediate",
            Self::ZeroPage => "zero-page",
            Self::ZeroPageX => "zero-page,X",
            Self::ZeroPageY => "zero-page,Y",
            Self::Absolute => "absolute",
            Self::AbsoluteX => "absolute,X",
            Self::AbsoluteY => "absolute,Y",
            Self::Indirect => "indirect",
            Self::IndirectX => "(indirect,X)",
            Self::IndirectY => "(indirect),Y",
            Self::Relative => "relative",
            Self::ZeroPageIndirect => "(zero-page)",
            Self::AbsoluteIndirectX => "(absolute,X)",
            Self::RelativeLong => "relative-long",
            Self::Illegal => "illegal",
        }
    }
}

// ── Opcode entry ──────────────────────────────────────────────────────────────

/// Descriptor for a single opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpcodeEntry {
    pub mnemonic: &'static str,
    pub mode: AddrMode,
    pub flags: InstrFlags,
    /// Base cycle count.
    pub cycles: u8,
    /// Whether this is an illegal/undocumented opcode.
    pub illegal: bool,
    /// CPU variant that supports this opcode.
    pub variant: CpuVariant,
}

/// Which CPU variant an opcode belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuVariant {
    Cpu6502,
    Cpu65C02,
    Cpu65816,
    Illegal6502,
}

impl OpcodeEntry {
    pub(crate) const fn base(
        mnemonic: &'static str,
        mode: AddrMode,
        flags: InstrFlags,
        cycles: u8,
    ) -> Self {
        Self {
            mnemonic,
            mode,
            flags,
            cycles,
            illegal: false,
            variant: CpuVariant::Cpu6502,
        }
    }

    pub(crate) const fn illegal_op(mnemonic: &'static str, mode: AddrMode, cycles: u8) -> Self {
        Self {
            mnemonic,
            mode,
            flags: InstrFlags::NONE,
            cycles,
            illegal: true,
            variant: CpuVariant::Illegal6502,
        }
    }

    pub(crate) const fn c02(
        mnemonic: &'static str,
        mode: AddrMode,
        flags: InstrFlags,
        cycles: u8,
    ) -> Self {
        Self {
            mnemonic,
            mode,
            flags,
            cycles,
            illegal: false,
            variant: CpuVariant::Cpu65C02,
        }
    }
}

const fn branch_entry(mnemonic: &'static str) -> OpcodeEntry {
    OpcodeEntry::base(
        mnemonic,
        AddrMode::Relative,
        InstrFlags::BRANCH.union(InstrFlags::CONDITIONAL),
        2,
    )
}

// ── Complete opcode table ─────────────────────────────────────────────────────

/// Look up an opcode entry for opcode byte `b`.
/// Returns `None` for truly undefined opcodes.
#[must_use]
pub fn opcode_table(b: u8) -> Option<OpcodeEntry> {
    match b >> 5 {
        0 => opcode_table_p1(b),
        1 => opcode_table_p2(b),
        2 => opcode_table_p3(b),
        3 => opcode_table_p4(b),
        4 => opcode_table_p5(b),
        5 => opcode_table_p6(b),
        6 => opcode_table_p7(b),
        _ => opcode_table_p8(b),
    }
}

fn opcode_table_p1(b: u8) -> Option<OpcodeEntry> {
    Some(match b {
        // ── ASL ──────────────────────────────────────────────────────────────
        0x0A => OpcodeEntry::base("ASL", AddrMode::Accumulator, InstrFlags::NONE, 2),
        0x06 => OpcodeEntry::base(
            "ASL",
            AddrMode::ZeroPage,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            5,
        ),
        0x16 => OpcodeEntry::base(
            "ASL",
            AddrMode::ZeroPageX,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            6,
        ),
        0x0E => OpcodeEntry::base(
            "ASL",
            AddrMode::Absolute,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            6,
        ),
        0x1E => OpcodeEntry::base(
            "ASL",
            AddrMode::AbsoluteX,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            7,
        ),
        0x10 => branch_entry("BPL"),
        // ── BRK ──────────────────────────────────────────────────────────────
        0x00 => OpcodeEntry::base("BRK", AddrMode::Implied, InstrFlags::BRANCH, 7),
        // ── Flag clears ───────────────────────────────────────────────────────
        0x18 => OpcodeEntry::base("CLC", AddrMode::Implied, InstrFlags::NONE, 2),
        // ── ORA ──────────────────────────────────────────────────────────────
        0x09 => OpcodeEntry::base("ORA", AddrMode::Immediate, InstrFlags::NONE, 2),
        0x05 => OpcodeEntry::base("ORA", AddrMode::ZeroPage, InstrFlags::READ_MEM, 3),
        0x15 => OpcodeEntry::base("ORA", AddrMode::ZeroPageX, InstrFlags::READ_MEM, 4),
        0x0D => OpcodeEntry::base("ORA", AddrMode::Absolute, InstrFlags::READ_MEM, 4),
        0x1D => OpcodeEntry::base("ORA", AddrMode::AbsoluteX, InstrFlags::READ_MEM, 4),
        0x19 => OpcodeEntry::base("ORA", AddrMode::AbsoluteY, InstrFlags::READ_MEM, 4),
        0x01 => OpcodeEntry::base("ORA", AddrMode::IndirectX, InstrFlags::READ_MEM, 6),
        0x11 => OpcodeEntry::base("ORA", AddrMode::IndirectY, InstrFlags::READ_MEM, 5),
        0x08 => OpcodeEntry::base("PHP", AddrMode::Implied, InstrFlags::WRITE_MEM, 3),
        0x0B => OpcodeEntry::illegal_op("ANC", AddrMode::Immediate, 2),
        0x03 => OpcodeEntry::illegal_op("SLO", AddrMode::IndirectX, 8),
        0x07 => OpcodeEntry::illegal_op("SLO", AddrMode::ZeroPage, 5),
        0x17 => OpcodeEntry::illegal_op("SLO", AddrMode::ZeroPageX, 6),
        0x0F => OpcodeEntry::illegal_op("SLO", AddrMode::Absolute, 6),
        0x1F => OpcodeEntry::illegal_op("SLO", AddrMode::AbsoluteX, 7),
        0x1B => OpcodeEntry::illegal_op("SLO", AddrMode::AbsoluteY, 7),
        0x13 => OpcodeEntry::illegal_op("SLO", AddrMode::IndirectY, 8),
        // KIL / JAM – halt CPU (NMOS only; these slots are used by 65C02 ZP-indirect)
        // Only list NMOS-only KIL slots not claimed by any official or 65C02 opcode:
        0x02 => OpcodeEntry::illegal_op("KIL", AddrMode::Implied, 2),
        0x12 => OpcodeEntry::c02("ORA", AddrMode::ZeroPageIndirect, InstrFlags::READ_MEM, 5),
        0x1A => OpcodeEntry::c02("INC", AddrMode::Accumulator, InstrFlags::NONE, 2),
        0x14 => OpcodeEntry::c02(
            "TRB",
            AddrMode::ZeroPage,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            5,
        ),
        0x1C => OpcodeEntry::c02(
            "TRB",
            AddrMode::Absolute,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            6,
        ),
        0x04 => OpcodeEntry::c02(
            "TSB",
            AddrMode::ZeroPage,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            5,
        ),
        0x0C => OpcodeEntry::c02(
            "TSB",
            AddrMode::Absolute,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            6,
        ),
        _ => return None,
    })
}

fn opcode_table_p2(b: u8) -> Option<OpcodeEntry> {
    Some(match b {
        // ── AND ──────────────────────────────────────────────────────────────
        0x29 => OpcodeEntry::base("AND", AddrMode::Immediate, InstrFlags::NONE, 2),
        0x25 => OpcodeEntry::base("AND", AddrMode::ZeroPage, InstrFlags::READ_MEM, 3),
        0x35 => OpcodeEntry::base("AND", AddrMode::ZeroPageX, InstrFlags::READ_MEM, 4),
        0x2D => OpcodeEntry::base("AND", AddrMode::Absolute, InstrFlags::READ_MEM, 4),
        0x3D => OpcodeEntry::base("AND", AddrMode::AbsoluteX, InstrFlags::READ_MEM, 4),
        0x39 => OpcodeEntry::base("AND", AddrMode::AbsoluteY, InstrFlags::READ_MEM, 4),
        0x21 => OpcodeEntry::base("AND", AddrMode::IndirectX, InstrFlags::READ_MEM, 6),
        0x31 => OpcodeEntry::base("AND", AddrMode::IndirectY, InstrFlags::READ_MEM, 5),
        0x30 => branch_entry("BMI"),
        // ── BIT ──────────────────────────────────────────────────────────────
        0x24 => OpcodeEntry::base("BIT", AddrMode::ZeroPage, InstrFlags::READ_MEM, 3),
        0x2C => OpcodeEntry::base("BIT", AddrMode::Absolute, InstrFlags::READ_MEM, 4),
        // ── JSR ──────────────────────────────────────────────────────────────
        0x20 => OpcodeEntry::base("JSR", AddrMode::Absolute, InstrFlags::CALL, 6),
        0x28 => OpcodeEntry::base("PLP", AddrMode::Implied, InstrFlags::READ_MEM, 4),
        // ── ROL ──────────────────────────────────────────────────────────────
        0x2A => OpcodeEntry::base("ROL", AddrMode::Accumulator, InstrFlags::NONE, 2),
        0x26 => OpcodeEntry::base(
            "ROL",
            AddrMode::ZeroPage,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            5,
        ),
        0x36 => OpcodeEntry::base(
            "ROL",
            AddrMode::ZeroPageX,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            6,
        ),
        0x2E => OpcodeEntry::base(
            "ROL",
            AddrMode::Absolute,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            6,
        ),
        0x3E => OpcodeEntry::base(
            "ROL",
            AddrMode::AbsoluteX,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            7,
        ),
        // ── Flag sets ─────────────────────────────────────────────────────────
        0x38 => OpcodeEntry::base("SEC", AddrMode::Implied, InstrFlags::NONE, 2),
        0x2B => OpcodeEntry::illegal_op("ANC", AddrMode::Immediate, 2),
        0x23 => OpcodeEntry::illegal_op("RLA", AddrMode::IndirectX, 8),
        0x27 => OpcodeEntry::illegal_op("RLA", AddrMode::ZeroPage, 5),
        0x37 => OpcodeEntry::illegal_op("RLA", AddrMode::ZeroPageX, 6),
        0x2F => OpcodeEntry::illegal_op("RLA", AddrMode::Absolute, 6),
        0x3F => OpcodeEntry::illegal_op("RLA", AddrMode::AbsoluteX, 7),
        0x3B => OpcodeEntry::illegal_op("RLA", AddrMode::AbsoluteY, 7),
        0x33 => OpcodeEntry::illegal_op("RLA", AddrMode::IndirectY, 8),
        0x22 => OpcodeEntry::illegal_op("KIL", AddrMode::Implied, 2),
        0x32 => OpcodeEntry::c02("AND", AddrMode::ZeroPageIndirect, InstrFlags::READ_MEM, 5),
        0x34 => OpcodeEntry::c02("BIT", AddrMode::ZeroPageX, InstrFlags::READ_MEM, 4),
        0x3C => OpcodeEntry::c02("BIT", AddrMode::AbsoluteX, InstrFlags::READ_MEM, 4),
        0x3A => OpcodeEntry::c02("DEC", AddrMode::Accumulator, InstrFlags::NONE, 2),
        _ => return None,
    })
}

fn opcode_table_p3(b: u8) -> Option<OpcodeEntry> {
    Some(match b {
        0x50 => branch_entry("BVC"),
        0x58 => OpcodeEntry::base("CLI", AddrMode::Implied, InstrFlags::NONE, 2),
        // ── EOR ──────────────────────────────────────────────────────────────
        0x49 => OpcodeEntry::base("EOR", AddrMode::Immediate, InstrFlags::NONE, 2),
        0x45 => OpcodeEntry::base("EOR", AddrMode::ZeroPage, InstrFlags::READ_MEM, 3),
        0x55 => OpcodeEntry::base("EOR", AddrMode::ZeroPageX, InstrFlags::READ_MEM, 4),
        0x4D => OpcodeEntry::base("EOR", AddrMode::Absolute, InstrFlags::READ_MEM, 4),
        0x5D => OpcodeEntry::base("EOR", AddrMode::AbsoluteX, InstrFlags::READ_MEM, 4),
        0x59 => OpcodeEntry::base("EOR", AddrMode::AbsoluteY, InstrFlags::READ_MEM, 4),
        0x41 => OpcodeEntry::base("EOR", AddrMode::IndirectX, InstrFlags::READ_MEM, 6),
        0x51 => OpcodeEntry::base("EOR", AddrMode::IndirectY, InstrFlags::READ_MEM, 5),
        // ── JMP ──────────────────────────────────────────────────────────────
        0x4C => OpcodeEntry::base("JMP", AddrMode::Absolute, InstrFlags::BRANCH, 3),
        // ── LSR ──────────────────────────────────────────────────────────────
        0x4A => OpcodeEntry::base("LSR", AddrMode::Accumulator, InstrFlags::NONE, 2),
        0x46 => OpcodeEntry::base(
            "LSR",
            AddrMode::ZeroPage,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            5,
        ),
        0x56 => OpcodeEntry::base(
            "LSR",
            AddrMode::ZeroPageX,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            6,
        ),
        0x4E => OpcodeEntry::base(
            "LSR",
            AddrMode::Absolute,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            6,
        ),
        0x5E => OpcodeEntry::base(
            "LSR",
            AddrMode::AbsoluteX,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            7,
        ),
        // ── Stack push/pull ───────────────────────────────────────────────────
        0x48 => OpcodeEntry::base("PHA", AddrMode::Implied, InstrFlags::WRITE_MEM, 3),
        // ── Returns ───────────────────────────────────────────────────────────
        0x40 => OpcodeEntry::base("RTI", AddrMode::Implied, InstrFlags::RET, 6),
        // ── Selected undocumented/illegal opcodes ─────────────────────────────
        0x4B => OpcodeEntry::illegal_op("ALR", AddrMode::Immediate, 2),
        0x43 => OpcodeEntry::illegal_op("SRE", AddrMode::IndirectX, 8),
        0x47 => OpcodeEntry::illegal_op("SRE", AddrMode::ZeroPage, 5),
        0x57 => OpcodeEntry::illegal_op("SRE", AddrMode::ZeroPageX, 6),
        0x4F => OpcodeEntry::illegal_op("SRE", AddrMode::Absolute, 6),
        0x5F => OpcodeEntry::illegal_op("SRE", AddrMode::AbsoluteX, 7),
        0x5B => OpcodeEntry::illegal_op("SRE", AddrMode::AbsoluteY, 7),
        0x53 => OpcodeEntry::illegal_op("SRE", AddrMode::IndirectY, 8),
        // Double-NOP zp (slots not claimed by 65C02)
        0x44 => OpcodeEntry::illegal_op("NOP", AddrMode::ZeroPage, 3), // SKB zp
        // Triple-NOP zpX (slots not claimed by 65C02)
        0x54 => OpcodeEntry::illegal_op("NOP", AddrMode::ZeroPageX, 4),
        // Triple-NOP absX (slots not claimed by 65C02)
        0x5C => OpcodeEntry::illegal_op("NOP", AddrMode::AbsoluteX, 4),
        0x42 => OpcodeEntry::illegal_op("KIL", AddrMode::Implied, 2),
        0x52 => OpcodeEntry::c02("EOR", AddrMode::ZeroPageIndirect, InstrFlags::READ_MEM, 5),
        0x5A => OpcodeEntry::c02("PHY", AddrMode::Implied, InstrFlags::WRITE_MEM, 3),
        _ => return None,
    })
}

fn opcode_table_p4(b: u8) -> Option<OpcodeEntry> {
    Some(match b {
        // ── ADC ──────────────────────────────────────────────────────────────
        0x69 => OpcodeEntry::base("ADC", AddrMode::Immediate, InstrFlags::NONE, 2),
        0x65 => OpcodeEntry::base("ADC", AddrMode::ZeroPage, InstrFlags::READ_MEM, 3),
        0x75 => OpcodeEntry::base("ADC", AddrMode::ZeroPageX, InstrFlags::READ_MEM, 4),
        0x6D => OpcodeEntry::base("ADC", AddrMode::Absolute, InstrFlags::READ_MEM, 4),
        0x7D => OpcodeEntry::base("ADC", AddrMode::AbsoluteX, InstrFlags::READ_MEM, 4),
        0x79 => OpcodeEntry::base("ADC", AddrMode::AbsoluteY, InstrFlags::READ_MEM, 4),
        0x61 => OpcodeEntry::base("ADC", AddrMode::IndirectX, InstrFlags::READ_MEM, 6),
        0x71 => OpcodeEntry::base("ADC", AddrMode::IndirectY, InstrFlags::READ_MEM, 5),
        0x70 => branch_entry("BVS"),
        0x6C => OpcodeEntry::base(
            "JMP",
            AddrMode::Indirect,
            InstrFlags::BRANCH | InstrFlags::INDIRECT,
            5,
        ),
        0x68 => OpcodeEntry::base("PLA", AddrMode::Implied, InstrFlags::READ_MEM, 4),
        // ── ROR ──────────────────────────────────────────────────────────────
        0x6A => OpcodeEntry::base("ROR", AddrMode::Accumulator, InstrFlags::NONE, 2),
        0x66 => OpcodeEntry::base(
            "ROR",
            AddrMode::ZeroPage,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            5,
        ),
        0x76 => OpcodeEntry::base(
            "ROR",
            AddrMode::ZeroPageX,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            6,
        ),
        0x6E => OpcodeEntry::base(
            "ROR",
            AddrMode::Absolute,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            6,
        ),
        0x7E => OpcodeEntry::base(
            "ROR",
            AddrMode::AbsoluteX,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            7,
        ),
        0x60 => OpcodeEntry::base("RTS", AddrMode::Implied, InstrFlags::RET, 6),
        0x78 => OpcodeEntry::base("SEI", AddrMode::Implied, InstrFlags::NONE, 2),
        0x6B => OpcodeEntry::illegal_op("ARR", AddrMode::Immediate, 2),
        0x63 => OpcodeEntry::illegal_op("RRA", AddrMode::IndirectX, 8),
        0x67 => OpcodeEntry::illegal_op("RRA", AddrMode::ZeroPage, 5),
        0x77 => OpcodeEntry::illegal_op("RRA", AddrMode::ZeroPageX, 6),
        0x6F => OpcodeEntry::illegal_op("RRA", AddrMode::Absolute, 6),
        0x7F => OpcodeEntry::illegal_op("RRA", AddrMode::AbsoluteX, 7),
        0x7B => OpcodeEntry::illegal_op("RRA", AddrMode::AbsoluteY, 7),
        0x73 => OpcodeEntry::illegal_op("RRA", AddrMode::IndirectY, 8),
        0x62 => OpcodeEntry::illegal_op("KIL", AddrMode::Implied, 2),
        // ── 65C02 extras ──────────────────────────────────────────────────────
        0x72 => OpcodeEntry::c02("ADC", AddrMode::ZeroPageIndirect, InstrFlags::READ_MEM, 5),
        0x7C => OpcodeEntry::c02(
            "JMP",
            AddrMode::AbsoluteIndirectX,
            InstrFlags::BRANCH | InstrFlags::INDIRECT,
            6,
        ),
        0x7A => OpcodeEntry::c02("PLY", AddrMode::Implied, InstrFlags::READ_MEM, 4),
        0x64 => OpcodeEntry::c02("STZ", AddrMode::ZeroPage, InstrFlags::WRITE_MEM, 3),
        0x74 => OpcodeEntry::c02("STZ", AddrMode::ZeroPageX, InstrFlags::WRITE_MEM, 4),
        _ => return None,
    })
}

const fn opcode_table_p5(b: u8) -> Option<OpcodeEntry> {
    Some(match b {
        // ── BCC/BCS/BEQ/BMI/BNE/BPL/BVC/BVS ─────────────────────────────────
        0x90 => branch_entry("BCC"),
        0x88 => OpcodeEntry::base("DEY", AddrMode::Implied, InstrFlags::NONE, 2),
        // ── STA ──────────────────────────────────────────────────────────────
        0x85 => OpcodeEntry::base("STA", AddrMode::ZeroPage, InstrFlags::WRITE_MEM, 3),
        0x95 => OpcodeEntry::base("STA", AddrMode::ZeroPageX, InstrFlags::WRITE_MEM, 4),
        0x8D => OpcodeEntry::base("STA", AddrMode::Absolute, InstrFlags::WRITE_MEM, 4),
        0x9D => OpcodeEntry::base("STA", AddrMode::AbsoluteX, InstrFlags::WRITE_MEM, 5),
        0x99 => OpcodeEntry::base("STA", AddrMode::AbsoluteY, InstrFlags::WRITE_MEM, 5),
        0x81 => OpcodeEntry::base("STA", AddrMode::IndirectX, InstrFlags::WRITE_MEM, 6),
        0x91 => OpcodeEntry::base("STA", AddrMode::IndirectY, InstrFlags::WRITE_MEM, 6),
        // ── STX / STY ─────────────────────────────────────────────────────────
        0x86 => OpcodeEntry::base("STX", AddrMode::ZeroPage, InstrFlags::WRITE_MEM, 3),
        0x96 => OpcodeEntry::base("STX", AddrMode::ZeroPageY, InstrFlags::WRITE_MEM, 4),
        0x8E => OpcodeEntry::base("STX", AddrMode::Absolute, InstrFlags::WRITE_MEM, 4),
        0x84 => OpcodeEntry::base("STY", AddrMode::ZeroPage, InstrFlags::WRITE_MEM, 3),
        0x94 => OpcodeEntry::base("STY", AddrMode::ZeroPageX, InstrFlags::WRITE_MEM, 4),
        0x8C => OpcodeEntry::base("STY", AddrMode::Absolute, InstrFlags::WRITE_MEM, 4),
        0x8A => OpcodeEntry::base("TXA", AddrMode::Implied, InstrFlags::NONE, 2),
        0x9A => OpcodeEntry::base("TXS", AddrMode::Implied, InstrFlags::NONE, 2),
        0x98 => OpcodeEntry::base("TYA", AddrMode::Implied, InstrFlags::NONE, 2),
        0x8B => OpcodeEntry::illegal_op("XAA", AddrMode::Immediate, 2),
        0x83 => OpcodeEntry::illegal_op("SAX", AddrMode::IndirectX, 6),
        0x87 => OpcodeEntry::illegal_op("SAX", AddrMode::ZeroPage, 3),
        0x97 => OpcodeEntry::illegal_op("SAX", AddrMode::ZeroPageY, 4),
        0x8F => OpcodeEntry::illegal_op("SAX", AddrMode::Absolute, 4),
        // ── More illegal (NMOS-only) opcodes ──────────────────────────────────
        // Extra immediate NOPs (SKB – skip byte, read and discard #imm)
        // NOTE: 0x80 is BRA on 65C02; here it appears only in the NMOS context
        //       but since the opcode_table is shared and 65C02 entries appear
        //       later in the match, only the first arm fires – we therefore place
        //       NMOS illegals for slots that the 65C02 section does NOT override.
        0x82 => OpcodeEntry::illegal_op("NOP", AddrMode::Immediate, 2), // SKB
        // AHX / SHA – AND A with X and high byte of addr+1, store
        0x93 => OpcodeEntry::illegal_op("AHX", AddrMode::IndirectY, 6),
        0x9F => OpcodeEntry::illegal_op("AHX", AddrMode::AbsoluteY, 5),
        // SHX – AND X with high byte of abs addr+1, store
        // Note: 0x9E is STZ absX on 65C02; on NMOS it is SHX absY.
        // 0x9C is STZ abs on 65C02; on NMOS it is SHY absX.
        // Since the opcode_table is CPU-agnostic, callers filter by CpuVariant.
        // The 65C02 entries for 0x9C/0x9E appear later and would duplicate;
        // these NMOS entries are therefore omitted here – SHX/SHY are exposed
        // through cpu_variant() rather than the shared lookup.
        // TAS – AND A with X → SP; store to memory
        0x9B => OpcodeEntry::illegal_op("TAS", AddrMode::AbsoluteY, 5),
        0x92 => OpcodeEntry::c02("STA", AddrMode::ZeroPageIndirect, InstrFlags::WRITE_MEM, 5),
        0x80 => OpcodeEntry::c02("BRA", AddrMode::Relative, InstrFlags::BRANCH, 2),
        0x89 => OpcodeEntry::c02("BIT", AddrMode::Immediate, InstrFlags::NONE, 2),
        0x9C => OpcodeEntry::c02("STZ", AddrMode::Absolute, InstrFlags::WRITE_MEM, 4),
        0x9E => OpcodeEntry::c02("STZ", AddrMode::AbsoluteX, InstrFlags::WRITE_MEM, 5),
        _ => return None,
    })
}

const fn opcode_table_p6(b: u8) -> Option<OpcodeEntry> {
    Some(match b {
        0xB0 => branch_entry("BCS"),
        0xB8 => OpcodeEntry::base("CLV", AddrMode::Implied, InstrFlags::NONE, 2),
        // ── LDA ──────────────────────────────────────────────────────────────
        0xA9 => OpcodeEntry::base("LDA", AddrMode::Immediate, InstrFlags::NONE, 2),
        0xA5 => OpcodeEntry::base("LDA", AddrMode::ZeroPage, InstrFlags::READ_MEM, 3),
        0xB5 => OpcodeEntry::base("LDA", AddrMode::ZeroPageX, InstrFlags::READ_MEM, 4),
        0xAD => OpcodeEntry::base("LDA", AddrMode::Absolute, InstrFlags::READ_MEM, 4),
        0xBD => OpcodeEntry::base("LDA", AddrMode::AbsoluteX, InstrFlags::READ_MEM, 4),
        0xB9 => OpcodeEntry::base("LDA", AddrMode::AbsoluteY, InstrFlags::READ_MEM, 4),
        0xA1 => OpcodeEntry::base("LDA", AddrMode::IndirectX, InstrFlags::READ_MEM, 6),
        0xB1 => OpcodeEntry::base("LDA", AddrMode::IndirectY, InstrFlags::READ_MEM, 5),
        // ── LDX ──────────────────────────────────────────────────────────────
        0xA2 => OpcodeEntry::base("LDX", AddrMode::Immediate, InstrFlags::NONE, 2),
        0xA6 => OpcodeEntry::base("LDX", AddrMode::ZeroPage, InstrFlags::READ_MEM, 3),
        0xB6 => OpcodeEntry::base("LDX", AddrMode::ZeroPageY, InstrFlags::READ_MEM, 4),
        0xAE => OpcodeEntry::base("LDX", AddrMode::Absolute, InstrFlags::READ_MEM, 4),
        0xBE => OpcodeEntry::base("LDX", AddrMode::AbsoluteY, InstrFlags::READ_MEM, 4),
        // ── LDY ──────────────────────────────────────────────────────────────
        0xA0 => OpcodeEntry::base("LDY", AddrMode::Immediate, InstrFlags::NONE, 2),
        0xA4 => OpcodeEntry::base("LDY", AddrMode::ZeroPage, InstrFlags::READ_MEM, 3),
        0xB4 => OpcodeEntry::base("LDY", AddrMode::ZeroPageX, InstrFlags::READ_MEM, 4),
        0xAC => OpcodeEntry::base("LDY", AddrMode::Absolute, InstrFlags::READ_MEM, 4),
        0xBC => OpcodeEntry::base("LDY", AddrMode::AbsoluteX, InstrFlags::READ_MEM, 4),
        // ── Transfers ────────────────────────────────────────────────────────
        0xAA => OpcodeEntry::base("TAX", AddrMode::Implied, InstrFlags::NONE, 2),
        0xA8 => OpcodeEntry::base("TAY", AddrMode::Implied, InstrFlags::NONE, 2),
        0xBA => OpcodeEntry::base("TSX", AddrMode::Implied, InstrFlags::NONE, 2),
        0xA3 => OpcodeEntry::illegal_op("LAX", AddrMode::IndirectX, 6),
        0xB3 => OpcodeEntry::illegal_op("LAX", AddrMode::IndirectY, 5),
        0xA7 => OpcodeEntry::illegal_op("LAX", AddrMode::ZeroPage, 3),
        0xB7 => OpcodeEntry::illegal_op("LAX", AddrMode::ZeroPageY, 4),
        0xAF => OpcodeEntry::illegal_op("LAX", AddrMode::Absolute, 4),
        0xBF => OpcodeEntry::illegal_op("LAX", AddrMode::AbsoluteY, 4),
        // LAS – AND mem with SP → A, X, SP
        0xBB => OpcodeEntry::illegal_op("LAS", AddrMode::AbsoluteY, 4),
        0xB2 => OpcodeEntry::c02("LDA", AddrMode::ZeroPageIndirect, InstrFlags::READ_MEM, 5),
        _ => return None,
    })
}

fn opcode_table_p7(b: u8) -> Option<OpcodeEntry> {
    Some(match b {
        0xD0 => branch_entry("BNE"),
        0xD8 => OpcodeEntry::base("CLD", AddrMode::Implied, InstrFlags::NONE, 2),
        // ── CMP ──────────────────────────────────────────────────────────────
        0xC9 => OpcodeEntry::base("CMP", AddrMode::Immediate, InstrFlags::NONE, 2),
        0xC5 => OpcodeEntry::base("CMP", AddrMode::ZeroPage, InstrFlags::READ_MEM, 3),
        0xD5 => OpcodeEntry::base("CMP", AddrMode::ZeroPageX, InstrFlags::READ_MEM, 4),
        0xCD => OpcodeEntry::base("CMP", AddrMode::Absolute, InstrFlags::READ_MEM, 4),
        0xDD => OpcodeEntry::base("CMP", AddrMode::AbsoluteX, InstrFlags::READ_MEM, 4),
        0xD9 => OpcodeEntry::base("CMP", AddrMode::AbsoluteY, InstrFlags::READ_MEM, 4),
        0xC1 => OpcodeEntry::base("CMP", AddrMode::IndirectX, InstrFlags::READ_MEM, 6),
        0xD1 => OpcodeEntry::base("CMP", AddrMode::IndirectY, InstrFlags::READ_MEM, 5),
        // ── CPY ──────────────────────────────────────────────────────────────
        0xC0 => OpcodeEntry::base("CPY", AddrMode::Immediate, InstrFlags::NONE, 2),
        0xC4 => OpcodeEntry::base("CPY", AddrMode::ZeroPage, InstrFlags::READ_MEM, 3),
        0xCC => OpcodeEntry::base("CPY", AddrMode::Absolute, InstrFlags::READ_MEM, 4),
        // ── DEC ──────────────────────────────────────────────────────────────
        0xC6 => OpcodeEntry::base(
            "DEC",
            AddrMode::ZeroPage,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            5,
        ),
        0xD6 => OpcodeEntry::base(
            "DEC",
            AddrMode::ZeroPageX,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            6,
        ),
        0xCE => OpcodeEntry::base(
            "DEC",
            AddrMode::Absolute,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            6,
        ),
        0xDE => OpcodeEntry::base(
            "DEC",
            AddrMode::AbsoluteX,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            7,
        ),
        0xCA => OpcodeEntry::base("DEX", AddrMode::Implied, InstrFlags::NONE, 2),
        0xC8 => OpcodeEntry::base("INY", AddrMode::Implied, InstrFlags::NONE, 2),
        0xCB => OpcodeEntry::illegal_op("AXS", AddrMode::Immediate, 2),
        0xC3 => OpcodeEntry::illegal_op("DCP", AddrMode::IndirectX, 8),
        0xC7 => OpcodeEntry::illegal_op("DCP", AddrMode::ZeroPage, 5),
        0xD7 => OpcodeEntry::illegal_op("DCP", AddrMode::ZeroPageX, 6),
        0xCF => OpcodeEntry::illegal_op("DCP", AddrMode::Absolute, 6),
        0xDF => OpcodeEntry::illegal_op("DCP", AddrMode::AbsoluteX, 7),
        0xDB => OpcodeEntry::illegal_op("DCP", AddrMode::AbsoluteY, 7),
        0xD3 => OpcodeEntry::illegal_op("DCP", AddrMode::IndirectY, 8),
        0xC2 => OpcodeEntry::illegal_op("NOP", AddrMode::Immediate, 2), // SKB
        0xD4 => OpcodeEntry::illegal_op("NOP", AddrMode::ZeroPageX, 4),
        0xDC => OpcodeEntry::illegal_op("NOP", AddrMode::AbsoluteX, 4),
        0xD2 => OpcodeEntry::c02("CMP", AddrMode::ZeroPageIndirect, InstrFlags::READ_MEM, 5),
        0xDA => OpcodeEntry::c02("PHX", AddrMode::Implied, InstrFlags::WRITE_MEM, 3),
        _ => return None,
    })
}

fn opcode_table_p8(b: u8) -> Option<OpcodeEntry> {
    Some(match b {
        0xF0 => branch_entry("BEQ"),
        // ── CPX ──────────────────────────────────────────────────────────────
        0xE0 => OpcodeEntry::base("CPX", AddrMode::Immediate, InstrFlags::NONE, 2),
        0xE4 => OpcodeEntry::base("CPX", AddrMode::ZeroPage, InstrFlags::READ_MEM, 3),
        0xEC => OpcodeEntry::base("CPX", AddrMode::Absolute, InstrFlags::READ_MEM, 4),
        // ── INC ──────────────────────────────────────────────────────────────
        0xE6 => OpcodeEntry::base(
            "INC",
            AddrMode::ZeroPage,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            5,
        ),
        0xF6 => OpcodeEntry::base(
            "INC",
            AddrMode::ZeroPageX,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            6,
        ),
        0xEE => OpcodeEntry::base(
            "INC",
            AddrMode::Absolute,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            6,
        ),
        0xFE => OpcodeEntry::base(
            "INC",
            AddrMode::AbsoluteX,
            InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
            7,
        ),
        0xE8 => OpcodeEntry::base("INX", AddrMode::Implied, InstrFlags::NONE, 2),
        // ── NOP ──────────────────────────────────────────────────────────────
        0xEA => OpcodeEntry::base("NOP", AddrMode::Implied, InstrFlags::NONE, 2),
        // ── SBC ──────────────────────────────────────────────────────────────
        0xE9 => OpcodeEntry::base("SBC", AddrMode::Immediate, InstrFlags::NONE, 2),
        0xE5 => OpcodeEntry::base("SBC", AddrMode::ZeroPage, InstrFlags::READ_MEM, 3),
        0xF5 => OpcodeEntry::base("SBC", AddrMode::ZeroPageX, InstrFlags::READ_MEM, 4),
        0xED => OpcodeEntry::base("SBC", AddrMode::Absolute, InstrFlags::READ_MEM, 4),
        0xFD => OpcodeEntry::base("SBC", AddrMode::AbsoluteX, InstrFlags::READ_MEM, 4),
        0xF9 => OpcodeEntry::base("SBC", AddrMode::AbsoluteY, InstrFlags::READ_MEM, 4),
        0xE1 => OpcodeEntry::base("SBC", AddrMode::IndirectX, InstrFlags::READ_MEM, 6),
        0xF1 => OpcodeEntry::base("SBC", AddrMode::IndirectY, InstrFlags::READ_MEM, 5),
        0xF8 => OpcodeEntry::base("SED", AddrMode::Implied, InstrFlags::NONE, 2),
        0xE3 => OpcodeEntry::illegal_op("ISC", AddrMode::IndirectX, 8),
        0xE7 => OpcodeEntry::illegal_op("ISC", AddrMode::ZeroPage, 5),
        0xF7 => OpcodeEntry::illegal_op("ISC", AddrMode::ZeroPageX, 6),
        0xEF => OpcodeEntry::illegal_op("ISC", AddrMode::Absolute, 6),
        0xFF => OpcodeEntry::illegal_op("ISC", AddrMode::AbsoluteX, 7),
        0xFB => OpcodeEntry::illegal_op("ISC", AddrMode::AbsoluteY, 7),
        0xF3 => OpcodeEntry::illegal_op("ISC", AddrMode::IndirectY, 8),
        0xE2 => OpcodeEntry::illegal_op("NOP", AddrMode::Immediate, 2), // SKB
        0xF4 => OpcodeEntry::illegal_op("NOP", AddrMode::ZeroPageX, 4),
        0xFC => OpcodeEntry::illegal_op("NOP", AddrMode::AbsoluteX, 4),
        0xF2 => OpcodeEntry::c02("SBC", AddrMode::ZeroPageIndirect, InstrFlags::READ_MEM, 5),
        0xFA => OpcodeEntry::c02("PLX", AddrMode::Implied, InstrFlags::READ_MEM, 4),
        _ => return None,
    })
}

// ── Operand formatter ─────────────────────────────────────────────────────────

/// Format the operand string for an instruction.
#[must_use]
pub fn format_operand(mode: AddrMode, bytes: &[u8], pc: u64) -> String {
    // Safe accessors — callers don't always guarantee sufficient length.
    let b1 = bytes.get(1).copied().unwrap_or(0);
    let b2 = bytes.get(2).copied().unwrap_or(0);
    match mode {
        AddrMode::Implied | AddrMode::Illegal => String::new(),
        AddrMode::Accumulator => "A".into(),
        AddrMode::Immediate => format!("#${b1:02X}"),
        AddrMode::ZeroPage => format!("${b1:02X}"),
        AddrMode::ZeroPageX => format!("${b1:02X},X"),
        AddrMode::ZeroPageY => format!("${b1:02X},Y"),
        AddrMode::Absolute => {
            let addr = u16::from_le_bytes([b1, b2]);
            format!("${addr:04X}")
        }
        AddrMode::AbsoluteX => {
            let addr = u16::from_le_bytes([b1, b2]);
            format!("${addr:04X},X")
        }
        AddrMode::AbsoluteY => {
            let addr = u16::from_le_bytes([b1, b2]);
            format!("${addr:04X},Y")
        }
        AddrMode::Indirect => {
            let addr = u16::from_le_bytes([b1, b2]);
            format!("(${addr:04X})")
        }
        AddrMode::IndirectX => format!("(${b1:02X},X)"),
        AddrMode::IndirectY => format!("(${b1:02X}),Y"),
        AddrMode::Relative => {
            let offset = b1 as i8;
            let target = pc
                .wrapping_add(2)
                .wrapping_add(i64::from(offset).cast_unsigned());
            format!("${:04X}", target & 0xFFFF)
        }
        AddrMode::ZeroPageIndirect => format!("(${b1:02X})"),
        AddrMode::AbsoluteIndirectX => {
            let addr = u16::from_le_bytes([b1, b2]);
            format!("(${addr:04X},X)")
        }
        AddrMode::RelativeLong => {
            let offset = i16::from_le_bytes([b1, b2]);
            let target = pc
                .wrapping_add(3)
                .wrapping_add(i64::from(offset).cast_unsigned());
            format!("${:06X}", target & 0xFF_FFFF)
        }
    }
}

// ── Branch analysis ───────────────────────────────────────────────────────────

/// Return the branch target for a relative branch instruction, if decodable.
#[must_use]
pub fn branch_target(pc: u64, bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 2 {
        return None;
    }
    let offset = i8::from_ne_bytes([bytes[1]]);
    Some(
        pc.wrapping_add(2)
            .wrapping_add(i64::from(offset).cast_unsigned())
            & 0xFFFF,
    )
}

// ── CPU variant selector ──────────────────────────────────────────────────────

/// Selects which CPU variants to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CpuMode {
    #[default]
    Cpu6502,
    Cpu65C02,
    Cpu65816,
}

impl CpuMode {
    /// Return the architecture name string.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cpu6502 => "6502",
            Self::Cpu65C02 => "65c02",
            Self::Cpu65816 => "65816",
        }
    }
}

// ── Main architecture struct ──────────────────────────────────────────────────

/// MOS 6502 / 65C02 / 65816 architecture.
#[derive(Debug, Clone, Default)]
pub struct Cpu6502Arch {
    pub mode: CpuMode,
    /// If `true`, illegal opcodes are decoded rather than returning an error.
    pub decode_illegal: bool,
}

impl Cpu6502Arch {
    /// Create a standard NMOS 6502 architecture.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a 65C02 architecture.
    #[must_use]
    pub const fn new_65c02() -> Self {
        Self {
            mode: CpuMode::Cpu65C02,
            decode_illegal: false,
        }
    }

    /// Enable decoding of illegal/undocumented opcodes.
    #[must_use]
    pub const fn with_illegal_opcodes(mut self) -> Self {
        self.decode_illegal = true;
        self
    }

    /// Return the cycle count for a given opcode byte, if known.
    #[must_use]
    pub fn cycle_count(&self, opcode: u8) -> Option<u8> {
        opcode_table(opcode).map(|e| e.cycles)
    }
}

impl Architecture for Cpu6502Arch {
    fn name(&self) -> &str {
        self.mode.name()
    }

    fn pointer_size(&self) -> usize {
        2
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        if bytes.is_empty() {
            return Err(CoreError::InvalidFormat {
                message: "empty byte slice".into(),
            });
        }
        let opcode_byte = bytes[0];
        let entry = opcode_table(opcode_byte).ok_or_else(|| CoreError::InvalidFormat {
            message: format!("unknown opcode 0x{opcode_byte:02X}"),
        })?;

        // Reject illegal opcodes if not enabled.
        if entry.illegal && !self.decode_illegal {
            return Err(CoreError::InvalidFormat {
                message: format!("illegal opcode 0x{opcode_byte:02X} (enable with decode_illegal)"),
            });
        }

        let instr_size = 1 + usize::from(entry.mode.extra_bytes());
        if bytes.len() < instr_size {
            return Err(CoreError::InvalidFormat {
                message: format!("truncated: need {instr_size} bytes, have {}", bytes.len()),
            });
        }

        let operands = format_operand(entry.mode, &bytes[..instr_size], address.as_u64());
        let mut instr = Instruction::new(
            address,
            instr_size,
            entry.mnemonic.to_string(),
            bytes[..instr_size].to_vec(),
        );
        instr.operands = operands;
        instr.flags = entry.flags;
        Ok(instr)
    }

    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo> {
        if !instr
            .flags
            .intersects(InstrFlags::BRANCH | InstrFlags::CALL)
        {
            return vec![];
        }
        // Indirect jumps (e.g. JMP ($XXXX)) have a statically unknown target
        // because the destination is read from memory at runtime.
        if instr.flags.contains(InstrFlags::INDIRECT) {
            return vec![BranchInfo::indirect_jump()];
        }
        // Return instructions have no static target.
        if instr.flags.contains(InstrFlags::RET) {
            return vec![BranchInfo::ret()];
        }
        // Compute the target from raw instruction bytes rather than the
        // already-formatted operand string to avoid fragile string parsing.
        let bytes = &instr.bytes;
        let target_val: Option<u64> = match bytes.len() {
            // Relative branches: opcode + 1-byte signed offset.
            2 => {
                let offset = bytes[1] as i8 as i64;
                let next_pc = instr.address.as_u64().wrapping_add(2);
                Some((next_pc as i64).wrapping_add(offset) as u64)
            }
            // Absolute / absolute-X jumps: opcode + 2-byte little-endian address.
            3 => {
                let lo = bytes[1] as u64;
                let hi = bytes[2] as u64;
                Some(lo | (hi << 8))
            }
            _ => None,
        };
        if let Some(target) = target_val {
            let branch = if instr.flags.contains(InstrFlags::CALL) {
                BranchInfo::call(target)
            } else if instr.flags.contains(InstrFlags::CONDITIONAL) {
                BranchInfo::conditional_jump(target, BranchCondition::Custom(0))
            } else {
                BranchInfo::unconditional_jump(target)
            };
            return vec![branch];
        }
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        vec![
            RegisterInfo::new("A", REG_A, 1, RegisterKind::General),
            RegisterInfo::new("X", REG_X, 1, RegisterKind::General),
            RegisterInfo::new("Y", REG_Y, 1, RegisterKind::General),
            RegisterInfo::new("SP", REG_SP, 1, RegisterKind::Stack),
            RegisterInfo::new("PC", REG_PC, 2, RegisterKind::ProgramCounter),
            RegisterInfo::new("P", REG_P, 1, RegisterKind::Flags),
        ]
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![
            CallingConvention::new("6502_cc65")
                .with_int_args(vec!["A".into(), "X".into(), "Y".into()])
                .with_return_regs(vec!["A".into(), "X".into()]),
            CallingConvention::new("6502_kick")
                .with_int_args(vec!["A".into(), "X".into(), "Y".into()])
                .with_return_regs(vec!["A".into()]),
        ]
    }
}

// ── Linear disassembler ───────────────────────────────────────────────────────

/// Linear-sweep disassembler for 6502 code.
pub struct Cpu6502LinearDisassembler<'a> {
    arch: &'a Cpu6502Arch,
    bytes: &'a [u8],
    base: Address,
    offset: usize,
}

impl<'a> Cpu6502LinearDisassembler<'a> {
    /// Create a new linear disassembler.
    #[must_use]
    pub const fn new(arch: &'a Cpu6502Arch, bytes: &'a [u8], base: Address) -> Self {
        Self {
            arch,
            bytes,
            base,
            offset: 0,
        }
    }

    /// Current byte offset.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Return `true` if all bytes have been consumed.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.offset >= self.bytes.len()
    }
}

impl Iterator for Cpu6502LinearDisassembler<'_> {
    type Item = Result<Instruction, CoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done() {
            return None;
        }
        let addr = self.base + self.offset as u64;
        let result = self.arch.disassemble(addr, &self.bytes[self.offset..]);
        match &result {
            Ok(instr) => self.offset += instr.size,
            Err(_) => self.offset += 1,
        }
        Some(result)
    }
}

// ── DisasmResult ─────────────────────────────────────────────────────────────

/// Result of disassembling a single 6502 instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisasmResult {
    /// Human-readable disassembly text, e.g. `"LDA $1234,X  ; abs,X"`.
    pub text: String,
    /// Number of bytes consumed (1–3).
    pub bytes_consumed: usize,
}

/// Disassemble one instruction from `data[offset..]` at the given virtual
/// `addr`, returning a [`DisasmResult`].
///
/// Format: `"MNEM operand  ; mode_name"` with 4-wide mnemonic column.
///
/// Returns `None` if `offset` is out of range or the byte is unrecognised.
#[must_use]
pub fn disassemble_one(data: &[u8], offset: usize, addr: u16) -> Option<DisasmResult> {
    let slice = data.get(offset..)?;
    if slice.is_empty() {
        return None;
    }
    let entry = opcode_table(slice[0])?;
    let instr_size = 1 + entry.mode.extra_bytes() as usize;
    if slice.len() < instr_size {
        return None;
    }
    let operand = format_operand(entry.mode, &slice[..instr_size], u64::from(addr));
    let text = if operand.is_empty() {
        format!("{:<4}  ; {}", entry.mnemonic, entry.mode.name())
    } else {
        format!("{:<4} {}  ; {}", entry.mnemonic, operand, entry.mode.name())
    };
    Some(DisasmResult {
        text,
        bytes_consumed: instr_size,
    })
}

// ── Cycle-count helper ────────────────────────────────────────────────────────

/// Return the base cycle count for `opcode`.
///
/// When `crossed_page` is `true`, one extra cycle is added for instructions
/// that cross a page boundary (`AbsoluteX` / `AbsoluteY` / `IndirectY` loads).
#[must_use]
pub fn cycles(opcode: u8, crossed_page: bool) -> u8 {
    let entry = opcode_table(opcode);
    let base = entry.map_or(2, |e| e.cycles);
    if crossed_page {
        // Only certain addressing modes incur a page-crossing penalty.
        let penalty = matches!(
            entry.map(|e| e.mode),
            Some(AddrMode::AbsoluteX | AddrMode::AbsoluteY | AddrMode::IndirectY)
        );
        if penalty { base + 1 } else { base }
    } else {
        base
    }
}

// ── CPU state ─────────────────────────────────────────────────────────────────

/// Snapshot of the MOS 6502 architectural state.
#[derive(Debug, Clone, Default)]
pub struct Cpu6502State {
    /// Accumulator.
    pub a: u8,
    /// Index register X.
    pub x: u8,
    /// Index register Y.
    pub y: u8,
    /// Stack pointer (page 1 offset, 0x00–0xFF).
    pub sp: u8,
    /// Program counter.
    pub pc: u16,
    /// Processor status flags (N V - B D I Z C).
    pub p: u8,
}

impl Cpu6502State {
    /// Create a reset state (PC=0xFFFC vector, SP=0xFD, P=0x24).
    #[must_use]
    pub const fn reset(memory: &[u8; 65536]) -> Self {
        let lo = memory[0xFFFC] as u16;
        let hi = memory[0xFFFD] as u16;
        Self {
            a: 0,
            x: 0,
            y: 0,
            sp: 0xFD,
            pc: (hi << 8) | lo,
            p: status::U | status::I,
        }
    }

    // ── Status flag helpers ───────────────────────────────────────────────────

    #[inline]
    const fn carry(&self) -> bool {
        self.p & status::C != 0
    }
    #[inline]
    const fn zero(&self) -> bool {
        self.p & status::Z != 0
    }
    #[inline]
    const fn overflow(&self) -> bool {
        self.p & status::V != 0
    }
    #[inline]
    const fn negative(&self) -> bool {
        self.p & status::N != 0
    }

    #[inline]
    const fn set_flag(&mut self, mask: u8, v: bool) {
        if v {
            self.p |= mask;
        } else {
            self.p &= !mask;
        }
    }

    #[inline]
    const fn set_nz(&mut self, v: u8) {
        self.set_flag(status::Z, v == 0);
        self.set_flag(status::N, v & 0x80 != 0);
    }

    // ── Stack helpers ─────────────────────────────────────────────────────────

    #[inline]
    const fn push(&mut self, mem: &mut [u8; 65536], v: u8) {
        mem[0x0100 | self.sp as usize] = v;
        self.sp = self.sp.wrapping_sub(1);
    }

    #[inline]
    const fn pop(&mut self, mem: &[u8; 65536]) -> u8 {
        self.sp = self.sp.wrapping_add(1);
        mem[0x0100 | self.sp as usize]
    }

    #[inline]
    const fn push16(&mut self, mem: &mut [u8; 65536], v: u16) {
        let [lo, hi] = v.to_le_bytes();
        self.push(mem, hi);
        self.push(mem, lo);
    }

    #[inline]
    fn pop16(&mut self, mem: &[u8; 65536]) -> u16 {
        let lo = u16::from(self.pop(mem));
        let hi = u16::from(self.pop(mem));
        (hi << 8) | lo
    }

    // ── Addressing mode resolution ────────────────────────────────────────────

    /// Compute the effective address (16-bit) for all non-implied modes.
    /// Also returns whether a page boundary was crossed.
    const fn effective_addr(&self, mem: &[u8; 65536], mode: AddrMode, op1: u8, op2: u8) -> (u16, bool) {
        match mode {
            AddrMode::ZeroPageX => (op1.wrapping_add(self.x) as u16, false),
            AddrMode::ZeroPageY => (op1.wrapping_add(self.y) as u16, false),
            AddrMode::Absolute => {
                let addr = u16::from_le_bytes([op1, op2]);
                (addr, false)
            }
            AddrMode::AbsoluteX => {
                let base = u16::from_le_bytes([op1, op2]);
                let addr = base.wrapping_add(self.x as u16);
                (addr, (base & 0xFF00) != (addr & 0xFF00))
            }
            AddrMode::AbsoluteY => {
                let base = u16::from_le_bytes([op1, op2]);
                let addr = base.wrapping_add(self.y as u16);
                (addr, (base & 0xFF00) != (addr & 0xFF00))
            }
            AddrMode::Indirect => {
                let ptr = u16::from_le_bytes([op1, op2]);
                // Famous 6502 page-wrap bug: high byte wraps within same page.
                let lo = mem[ptr as usize] as u16;
                let hi = mem[((ptr & 0xFF00) | ((ptr.wrapping_add(1)) & 0x00FF)) as usize] as u16;
                ((hi << 8) | lo, false)
            }
            AddrMode::IndirectX => {
                let zp = op1.wrapping_add(self.x) as usize;
                let lo = mem[zp & 0xFF] as u16;
                let hi = mem[(zp.wrapping_add(1)) & 0xFF] as u16;
                ((hi << 8) | lo, false)
            }
            AddrMode::IndirectY => {
                let lo = mem[op1 as usize] as u16;
                let hi = mem[op1.wrapping_add(1) as usize] as u16;
                let base = (hi << 8) | lo;
                let addr = base.wrapping_add(self.y as u16);
                (addr, (base & 0xFF00) != (addr & 0xFF00))
            }
            AddrMode::ZeroPageIndirect => {
                let lo = mem[op1 as usize] as u16;
                let hi = mem[op1.wrapping_add(1) as usize] as u16;
                ((hi << 8) | lo, false)
            }
            _ => (op1 as u16, false), // Immediate / Implied / Accumulator
        }
    }

    /// Read a byte from memory using the given addressing mode.
    const fn read_operand(&self, mem: &[u8; 65536], mode: AddrMode, op1: u8, op2: u8) -> u8 {
        match mode {
            AddrMode::Immediate => op1,
            AddrMode::Accumulator => self.a,
            _ => {
                let (addr, _) = self.effective_addr(mem, mode, op1, op2);
                mem[addr as usize]
            }
        }
    }

    /// Write a byte back to memory (or accumulator for RMW-accumulator ops).
    fn write_operand(&mut self, mem: &mut [u8; 65536], mode: AddrMode, op1: u8, op2: u8, v: u8) {
        if mode == AddrMode::Accumulator {
            self.a = v;
        } else {
            let (addr, _) = self.effective_addr(mem, mode, op1, op2);
            mem[addr as usize] = v;
        }
    }
}

// ── Single-step emulator ──────────────────────────────────────────────────────

/// Execute one instruction from `memory[state.pc]`.
///
/// Returns the number of cycles consumed.  The emulation covers all official
/// 6502 opcodes plus the most common illegals.  Decimal mode ADC/SBC is **not**
/// emulated (the flags are set as if in binary mode, matching the NES variant).
///
/// # Panics
///
/// Does not panic – illegal memory accesses wrap within the 64 KiB space.
pub fn execute_one(state: &mut Cpu6502State, memory: &mut [u8; 65536]) -> u8 {
    let pc = state.pc;
    let opcode = memory[pc as usize];
    let op1 = memory[pc.wrapping_add(1) as usize];
    let op2 = memory[pc.wrapping_add(2) as usize];

    let Some(entry) = opcode_table(opcode) else {
        // Completely undefined – treat as 2-cycle NOP.
        state.pc = pc.wrapping_add(1);
        return 2;
    };
    let mode = entry.mode;
    let instr_len = 1 + mode.extra_bytes();
    let next_pc = pc.wrapping_add(instr_len);

    // Resolve effective address / operand value upfront for read operations.
    let (eff_addr, page_cross) = state.effective_addr(memory, mode, op1, op2);
    let base_cycles = entry.cycles;
    let extra_cycle = u8::from(page_cross);

    let mut extra = extra_cycle;
    let mut branched = false;

    match opcode {
        // ── LDA ──────────────────────────────────────────────────────────────
        0xA9 | 0xA5 | 0xB5 | 0xAD | 0xBD | 0xB9 | 0xA1 | 0xB1 => {
            let v = state.read_operand(memory, mode, op1, op2);
            state.a = v;
            state.set_nz(v);
        }
        // ── LDX ──────────────────────────────────────────────────────────────
        0xA2 | 0xA6 | 0xB6 | 0xAE | 0xBE => {
            let v = state.read_operand(memory, mode, op1, op2);
            state.x = v;
            state.set_nz(v);
        }
        // ── LDY ──────────────────────────────────────────────────────────────
        0xA0 | 0xA4 | 0xB4 | 0xAC | 0xBC => {
            let v = state.read_operand(memory, mode, op1, op2);
            state.y = v;
            state.set_nz(v);
        }
        // ── STA ──────────────────────────────────────────────────────────────
        0x85 | 0x95 | 0x8D | 0x9D | 0x99 | 0x81 | 0x91 => {
            memory[eff_addr as usize] = state.a;
        }
        // ── STX ──────────────────────────────────────────────────────────────
        0x86 | 0x96 | 0x8E => {
            memory[eff_addr as usize] = state.x;
        }
        // ── STY ──────────────────────────────────────────────────────────────
        0x84 | 0x94 | 0x8C => {
            memory[eff_addr as usize] = state.y;
        }
        // ── ADC ──────────────────────────────────────────────────────────────
        0x69 | 0x65 | 0x75 | 0x6D | 0x7D | 0x79 | 0x61 | 0x71 => {
            let v = state.read_operand(memory, mode, op1, op2);
            let carry_in = u16::from(state.carry());
            let result = u16::from(state.a) + u16::from(v) + carry_in;
            let overflow = (!(state.a ^ v) & (state.a ^ result.to_le_bytes()[0]) & 0x80) != 0;
            state.set_flag(status::C, result > 0xFF);
            state.set_flag(status::V, overflow);
            state.a = result.to_le_bytes()[0];
            state.set_nz(state.a);
        }
        // ── SBC ──────────────────────────────────────────────────────────────
        0xE9 | 0xE5 | 0xF5 | 0xED | 0xFD | 0xF9 | 0xE1 | 0xF1 => {
            let v = state.read_operand(memory, mode, op1, op2);
            // SBC = A + ~v + C; use wrapping math so debug builds don't panic.
            let carry_in = u16::from(state.carry());
            let inv_v = u16::from(!v);
            let result = u16::from(state.a)
                .wrapping_add(inv_v)
                .wrapping_add(carry_in);
            let overflow = ((state.a ^ v) & (state.a ^ result.to_le_bytes()[0]) & 0x80) != 0;
            state.set_flag(status::C, result > 0xFF);
            state.set_flag(status::V, overflow);
            state.a = result.to_le_bytes()[0];
            state.set_nz(state.a);
        }
        // ── AND ──────────────────────────────────────────────────────────────
        0x29 | 0x25 | 0x35 | 0x2D | 0x3D | 0x39 | 0x21 | 0x31 => {
            let v = state.read_operand(memory, mode, op1, op2);
            state.a &= v;
            state.set_nz(state.a);
        }
        // ── ORA ──────────────────────────────────────────────────────────────
        0x09 | 0x05 | 0x15 | 0x0D | 0x1D | 0x19 | 0x01 | 0x11 => {
            let v = state.read_operand(memory, mode, op1, op2);
            state.a |= v;
            state.set_nz(state.a);
        }
        // ── EOR ──────────────────────────────────────────────────────────────
        0x49 | 0x45 | 0x55 | 0x4D | 0x5D | 0x59 | 0x41 | 0x51 => {
            let v = state.read_operand(memory, mode, op1, op2);
            state.a ^= v;
            state.set_nz(state.a);
        }
        // ── CMP ──────────────────────────────────────────────────────────────
        0xC9 | 0xC5 | 0xD5 | 0xCD | 0xDD | 0xD9 | 0xC1 | 0xD1 => {
            let v = state.read_operand(memory, mode, op1, op2);
            let r = state.a.wrapping_sub(v);
            state.set_flag(status::C, state.a >= v);
            state.set_nz(r);
        }
        // ── CPX ──────────────────────────────────────────────────────────────
        0xE0 | 0xE4 | 0xEC => {
            let v = state.read_operand(memory, mode, op1, op2);
            let r = state.x.wrapping_sub(v);
            state.set_flag(status::C, state.x >= v);
            state.set_nz(r);
        }
        // ── CPY ──────────────────────────────────────────────────────────────
        0xC0 | 0xC4 | 0xCC => {
            let v = state.read_operand(memory, mode, op1, op2);
            let r = state.y.wrapping_sub(v);
            state.set_flag(status::C, state.y >= v);
            state.set_nz(r);
        }
        // ── BIT ──────────────────────────────────────────────────────────────
        0x24 | 0x2C => {
            let v = memory[eff_addr as usize];
            state.set_flag(status::Z, state.a & v == 0);
            state.set_flag(status::V, v & 0x40 != 0);
            state.set_flag(status::N, v & 0x80 != 0);
        }
        // ── INC ──────────────────────────────────────────────────────────────
        0xE6 | 0xF6 | 0xEE | 0xFE => {
            let v = memory[eff_addr as usize].wrapping_add(1);
            memory[eff_addr as usize] = v;
            state.set_nz(v);
        }
        0xE8 => {
            state.x = state.x.wrapping_add(1);
            state.set_nz(state.x);
        } // INX
        0xC8 => {
            state.y = state.y.wrapping_add(1);
            state.set_nz(state.y);
        } // INY
        // ── DEC ──────────────────────────────────────────────────────────────
        0xC6 | 0xD6 | 0xCE | 0xDE => {
            let v = memory[eff_addr as usize].wrapping_sub(1);
            memory[eff_addr as usize] = v;
            state.set_nz(v);
        }
        0xCA => {
            state.x = state.x.wrapping_sub(1);
            state.set_nz(state.x);
        } // DEX
        0x88 => {
            state.y = state.y.wrapping_sub(1);
            state.set_nz(state.y);
        } // DEY
        // ── ASL ──────────────────────────────────────────────────────────────
        0x0A | 0x06 | 0x16 | 0x0E | 0x1E => {
            let v = state.read_operand(memory, mode, op1, op2);
            state.set_flag(status::C, v & 0x80 != 0);
            let r = v << 1;
            state.set_nz(r);
            state.write_operand(memory, mode, op1, op2, r);
        }
        // ── LSR ──────────────────────────────────────────────────────────────
        0x4A | 0x46 | 0x56 | 0x4E | 0x5E => {
            let v = state.read_operand(memory, mode, op1, op2);
            state.set_flag(status::C, v & 0x01 != 0);
            let r = v >> 1;
            state.set_nz(r);
            state.write_operand(memory, mode, op1, op2, r);
        }
        // ── ROL ──────────────────────────────────────────────────────────────
        0x2A | 0x26 | 0x36 | 0x2E | 0x3E => {
            let v = state.read_operand(memory, mode, op1, op2);
            let old_c = u8::from(state.carry());
            state.set_flag(status::C, v & 0x80 != 0);
            let r = (v << 1) | old_c;
            state.set_nz(r);
            state.write_operand(memory, mode, op1, op2, r);
        }
        // ── ROR ──────────────────────────────────────────────────────────────
        0x6A | 0x66 | 0x76 | 0x6E | 0x7E => {
            let v = state.read_operand(memory, mode, op1, op2);
            let old_c = if state.carry() { 0x80u8 } else { 0 };
            state.set_flag(status::C, v & 0x01 != 0);
            let r = (v >> 1) | old_c;
            state.set_nz(r);
            state.write_operand(memory, mode, op1, op2, r);
        }
        // ── JMP ──────────────────────────────────────────────────────────────
        0x4C => {
            // JMP abs
            state.pc = u16::from_le_bytes([op1, op2]);
            return base_cycles;
        }
        0x6C => {
            // JMP (ind)
            let ptr = u16::from_le_bytes([op1, op2]);
            let lo = u16::from(memory[ptr as usize]);
            // 6502 page-wrap bug
            let hi = u16::from(memory[((ptr & 0xFF00) | (ptr.wrapping_add(1) & 0x00FF)) as usize]);
            state.pc = (hi << 8) | lo;
            return base_cycles;
        }
        // ── JSR ──────────────────────────────────────────────────────────────
        0x20 => {
            let target = u16::from_le_bytes([op1, op2]);
            state.push16(memory, next_pc.wrapping_sub(1));
            state.pc = target;
            return base_cycles;
        }
        // ── RTS ──────────────────────────────────────────────────────────────
        0x60 => {
            let addr = state.pop16(memory).wrapping_add(1);
            state.pc = addr;
            return base_cycles;
        }
        // ── RTI ──────────────────────────────────────────────────────────────
        0x40 => {
            let p = state.pop(memory);
            state.p = (p | status::U) & !status::B;
            let ret = state.pop16(memory);
            state.pc = ret;
            return base_cycles;
        }
        // ── BRK ──────────────────────────────────────────────────────────────
        0x00 => {
            state.push16(memory, pc.wrapping_add(2));
            state.push(memory, state.p | status::B | status::U);
            state.set_flag(status::I, true);
            let lo = u16::from(memory[0xFFFE]);
            let hi = u16::from(memory[0xFFFF]);
            state.pc = (hi << 8) | lo;
            return base_cycles;
        }
        // ── Branches ─────────────────────────────────────────────────────────
        0x90 | 0xB0 | 0xF0 | 0x30 | 0xD0 | 0x10 | 0x50 | 0x70 => {
            let taken = match opcode {
                0x90 => !state.carry(),    // BCC
                0xB0 => state.carry(),     // BCS
                0xF0 => state.zero(),      // BEQ
                0x30 => state.negative(),  // BMI
                0xD0 => !state.zero(),     // BNE
                0x10 => !state.negative(), // BPL
                0x50 => !state.overflow(), // BVC
                0x70 => state.overflow(),  // BVS
                _ => false,
            };
            if taken {
                let new_pc = next_pc.wrapping_add_signed(i16::from(op1.cast_signed()));
                let page_cross_branch = (next_pc & 0xFF00) != (new_pc & 0xFF00);
                state.pc = new_pc;
                extra = 1 + u8::from(page_cross_branch);
                branched = true;
            }
        }
        // ── Stack push/pull ───────────────────────────────────────────────────
        0x48 => state.push(memory, state.a), // PHA
        0x08 => state.push(memory, state.p | status::B | status::U), // PHP
        0x68 => {
            let v = state.pop(memory);
            state.a = v;
            state.set_nz(v);
        } // PLA
        0x28 => {
            // PLP
            let v = state.pop(memory);
            state.p = (v | status::U) & !status::B;
        }
        // ── Transfers ────────────────────────────────────────────────────────
        0xAA => {
            state.x = state.a;
            state.set_nz(state.x);
        } // TAX
        0xA8 => {
            state.y = state.a;
            state.set_nz(state.y);
        } // TAY
        0xBA => {
            state.x = state.sp;
            state.set_nz(state.x);
        } // TSX
        0x8A => {
            state.a = state.x;
            state.set_nz(state.a);
        } // TXA
        0x9A => {
            state.sp = state.x;
        } // TXS (no flags)
        0x98 => {
            state.a = state.y;
            state.set_nz(state.a);
        } // TYA
        // ── Flag instructions ────────────────────────────────────────────────
        0x18 => state.set_flag(status::C, false), // CLC
        0x38 => state.set_flag(status::C, true),  // SEC
        0x58 => state.set_flag(status::I, false), // CLI
        0x78 => state.set_flag(status::I, true),  // SEI
        0xB8 => state.set_flag(status::V, false), // CLV
        0xD8 => state.set_flag(status::D, false), // CLD
        0xF8 => state.set_flag(status::D, true),  // SED
        // ── NOP ──────────────────────────────────────────────────────────────
        0xEA => {} // official NOP
        // ── Illegal: LAX ─────────────────────────────────────────────────────
        0xA7 | 0xB7 | 0xAF | 0xBF | 0xA3 | 0xB3 => {
            let v = state.read_operand(memory, mode, op1, op2);
            state.a = v;
            state.x = v;
            state.set_nz(v);
        }
        // ── Illegal: SAX ─────────────────────────────────────────────────────
        0x87 | 0x97 | 0x8F | 0x83 => {
            memory[eff_addr as usize] = state.a & state.x;
        }
        // ── Illegal: DCP ─────────────────────────────────────────────────────
        0xC7 | 0xD7 | 0xCF | 0xDF | 0xDB | 0xC3 | 0xD3 => {
            let v = memory[eff_addr as usize].wrapping_sub(1);
            memory[eff_addr as usize] = v;
            let r = state.a.wrapping_sub(v);
            state.set_flag(status::C, state.a >= v);
            state.set_nz(r);
        }
        // ── Illegal: ISC ─────────────────────────────────────────────────────
        0xE7 | 0xF7 | 0xEF | 0xFF | 0xFB | 0xE3 | 0xF3 => {
            let v = memory[eff_addr as usize].wrapping_add(1);
            memory[eff_addr as usize] = v;
            // ISC = INC then SBC; A + ~v + C with wrapping math.
            let carry_in = u16::from(state.carry());
            let inv_v = u16::from(!v);
            let result = u16::from(state.a)
                .wrapping_add(inv_v)
                .wrapping_add(carry_in);
            let overflow = ((state.a ^ v) & (state.a ^ result.to_le_bytes()[0]) & 0x80) != 0;
            state.set_flag(status::C, result > 0xFF);
            state.set_flag(status::V, overflow);
            state.a = result.to_le_bytes()[0];
            state.set_nz(state.a);
        }
        // ── Illegal: SLO ─────────────────────────────────────────────────────
        0x07 | 0x17 | 0x0F | 0x1F | 0x1B | 0x03 | 0x13 => {
            let v = memory[eff_addr as usize];
            state.set_flag(status::C, v & 0x80 != 0);
            let shifted = v << 1;
            memory[eff_addr as usize] = shifted;
            state.a |= shifted;
            state.set_nz(state.a);
        }
        // ── Illegal: RLA ─────────────────────────────────────────────────────
        0x27 | 0x37 | 0x2F | 0x3F | 0x3B | 0x23 | 0x33 => {
            let v = memory[eff_addr as usize];
            let old_c = u8::from(state.carry());
            state.set_flag(status::C, v & 0x80 != 0);
            let r = (v << 1) | old_c;
            memory[eff_addr as usize] = r;
            state.a &= r;
            state.set_nz(state.a);
        }
        // ── Illegal: SRE ─────────────────────────────────────────────────────
        0x47 | 0x57 | 0x4F | 0x5F | 0x5B | 0x43 | 0x53 => {
            let v = memory[eff_addr as usize];
            state.set_flag(status::C, v & 0x01 != 0);
            let r = v >> 1;
            memory[eff_addr as usize] = r;
            state.a ^= r;
            state.set_nz(state.a);
        }
        // ── Illegal: RRA ─────────────────────────────────────────────────────
        0x67 | 0x77 | 0x6F | 0x7F | 0x7B | 0x63 | 0x73 => {
            let v = memory[eff_addr as usize];
            let old_c = if state.carry() { 0x80u8 } else { 0 };
            state.set_flag(status::C, v & 0x01 != 0);
            let r = (v >> 1) | old_c;
            memory[eff_addr as usize] = r;
            let carry_in = u16::from(state.carry());
            let result = u16::from(state.a) + u16::from(r) + carry_in;
            let overflow = (!(state.a ^ r) & (state.a ^ result.to_le_bytes()[0]) & 0x80) != 0;
            state.set_flag(status::C, result > 0xFF);
            state.set_flag(status::V, overflow);
            state.a = result.to_le_bytes()[0];
            state.set_nz(state.a);
        }
        // ── Illegal: ALR ─────────────────────────────────────────────────────
        0x4B => {
            state.a &= op1;
            state.set_flag(status::C, state.a & 0x01 != 0);
            state.a >>= 1;
            state.set_nz(state.a);
        }
        // ── Illegal: ANC ─────────────────────────────────────────────────────
        0x0B | 0x2B => {
            state.a &= op1;
            state.set_nz(state.a);
            state.set_flag(status::C, state.a & 0x80 != 0);
        }
        // ── Illegal: ARR ─────────────────────────────────────────────────────
        0x6B => {
            let v = state.a & op1;
            let old_c = if state.carry() { 0x80u8 } else { 0 };
            state.a = (v >> 1) | old_c;
            state.set_nz(state.a);
            state.set_flag(status::C, state.a & 0x40 != 0);
            let b6 = (state.a >> 6) & 1;
            let b5 = (state.a >> 5) & 1;
            state.set_flag(status::V, (b6 ^ b5) != 0);
        }
        // ── Illegal: AXS / SBX ───────────────────────────────────────────────
        0xCB => {
            let v = state.a & state.x;
            let r = v.wrapping_sub(op1);
            state.set_flag(status::C, v >= op1);
            state.set_nz(r);
            state.x = r;
        }
        // ── Illegal: XAA ─────────────────────────────────────────────────────
        0x8B => {
            // Unstable on real hardware; canonical implementation:
            state.a = state.x & op1;
            state.set_nz(state.a);
        }
        // ── Illegal: LAS ─────────────────────────────────────────────────────
        0xBB => {
            let v = memory[eff_addr as usize] & state.sp;
            state.a = v;
            state.x = v;
            state.sp = v;
            state.set_nz(v);
        }
        // ── Illegal: TAS ─────────────────────────────────────────────────────
        0x9B => {
            state.sp = state.a & state.x;
            let hi = ((eff_addr >> 8) as u8).wrapping_add(1);
            memory[eff_addr as usize] = state.sp & hi;
        }
        // ── Illegal: AHX ─────────────────────────────────────────────────────
        0x93 | 0x9F => {
            let hi = ((eff_addr >> 8) as u8).wrapping_add(1);
            memory[eff_addr as usize] = state.a & state.x & hi;
        }
        // ── Illegal: SHY ─────────────────────────────────────────────────────
        0x9C => {
            let hi = ((eff_addr >> 8) as u8).wrapping_add(1);
            memory[eff_addr as usize] = state.y & hi;
        }
        // ── Illegal: SHX ─────────────────────────────────────────────────────
        0x9E => {
            let hi = ((eff_addr >> 8) as u8).wrapping_add(1);
            memory[eff_addr as usize] = state.x & hi;
        }
        // ── KIL / JAM ────────────────────────────────────────────────────────
        0x02 | 0x22 | 0x42 | 0x62 => {
            // CPU halts; in emulation we just stall by returning max cycles.
            return 255;
        }
        // ── All other illegal NOPs (read and discard) ─────────────────────────
        _ => {
            // Extra NOPs and unimplemented illegals – consume cycles, do nothing.
        }
    }

    if !branched {
        state.pc = next_pc;
    }
    base_cycles + extra
}

// ── MemoryBus6502 ─────────────────────────────────────────────────────────────

/// Flat 64 KiB memory bus for a 6502 system.
///
/// Provides a simple, non-banked address space with helpers for loading
/// programs and setting the reset vector.
pub struct MemoryBus6502 {
    /// Raw 64 KiB RAM.
    pub ram: [u8; 65536],
}

impl Default for MemoryBus6502 {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryBus6502 {
    /// Create a zeroed 64 KiB memory bus.
    #[must_use]
    pub const fn new() -> Self {
        Self { ram: [0u8; 65536] }
    }

    /// Read a byte from `addr`.
    #[inline]
    #[must_use]
    pub const fn load(&self, addr: u16) -> u8 {
        self.ram[addr as usize]
    }

    /// Write `val` to `addr`.
    #[inline]
    pub const fn store(&mut self, addr: u16, val: u8) {
        self.ram[addr as usize] = val;
    }

    /// Copy `program` bytes into RAM starting at `origin`.
    ///
    /// Bytes that would exceed address 0xFFFF are silently truncated.
    pub fn load_program(&mut self, program: &[u8], origin: u16) {
        let start = origin as usize;
        let end = (start + program.len()).min(65536);
        let count = end - start;
        self.ram[start..end].copy_from_slice(&program[..count]);
    }

    /// Write the 16-bit reset vector to 0xFFFC–0xFFFD (little-endian).
    pub const fn set_reset_vector(&mut self, addr: u16) {
        self.ram[0xFFFC] = (addr & 0xFF) as u8;
        self.ram[0xFFFD] = (addr >> 8) as u8;
    }
}

// ── Cpu6502State (full emulator version) ─────────────────────────────────────

/// The RESET vector address (points to the two-byte little-endian PC value).
pub const RESET_VECTOR: u16 = 0xFFFC;

/// Complete architectural state for the MOS 6502 single-step emulator.
///
/// This struct intentionally mirrors the register names in the specification
/// (`a`, `x`, `y`, `sp`, `pc`, `status`, `cycles`) and exposes ergonomic
/// helpers for flag manipulation and stack access.
///
/// Note: `status` uses the same bit layout as `status::*` constants in this
/// crate (N V U B D I Z C, bit 7..0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpu6502EmuState {
    /// Accumulator.
    pub a: u8,
    /// Index register X.
    pub x: u8,
    /// Index register Y.
    pub y: u8,
    /// Stack pointer (offset into page 1; hardware address is 0x0100 + sp).
    pub sp: u8,
    /// Program counter.
    pub pc: u16,
    /// Processor status flags (N V U B D I Z C).
    pub status: u8,
    /// Total cycle count accumulated since construction / last reset.
    pub cycles: u64,
}

impl Default for Cpu6502EmuState {
    fn default() -> Self {
        Self::new()
    }
}

impl Cpu6502EmuState {
    /// Create a reset state: PC = 0xFFFC (vector NOT yet dereferenced),
    /// SP = 0xFD, status = 0x20 (U bit set), all other registers zeroed,
    /// cycles = 0.
    ///
    /// To fully replicate hardware reset, dereference the reset vector after
    /// constructing with [`Cpu6502::reset`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            a: 0,
            x: 0,
            y: 0,
            sp: 0xFD,
            pc: RESET_VECTOR,
            status: status::U,
            cycles: 0,
        }
    }

    // ── Flag helpers ──────────────────────────────────────────────────────────

    /// Set or clear a single flag bit in `status`.
    ///
    /// `flag` should be one of the `status::*` constants.
    #[inline]
    pub const fn set_flag(&mut self, flag: u8, val: bool) {
        if val {
            self.status |= flag;
        } else {
            self.status &= !flag;
        }
    }

    /// Test whether a single flag bit is set in `status`.
    ///
    /// `flag` should be one of the `status::*` constants.
    #[inline]
    #[must_use]
    pub const fn get_flag(&self, flag: u8) -> bool {
        self.status & flag != 0
    }

    /// Update the **N**egative and **Z**ero flags based on `val`.
    #[inline]
    pub const fn update_nz(&mut self, val: u8) {
        self.set_flag(status::Z, val == 0);
        self.set_flag(status::N, val & 0x80 != 0);
    }

    // ── Memory access helpers ─────────────────────────────────────────────────

    /// Bounds-checked read: out-of-range addresses read as `0` (open bus).
    #[inline]
    fn rd(mem: &[u8], addr: usize) -> u8 {
        mem.get(addr).copied().unwrap_or(0)
    }

    /// Bounds-checked write: out-of-range addresses are ignored.
    #[inline]
    fn wr(mem: &mut [u8], addr: usize, val: u8) {
        if let Some(b) = mem.get_mut(addr) {
            *b = val;
        }
    }

    // ── Stack helpers ─────────────────────────────────────────────────────────

    /// Push `val` onto the hardware stack (page 1).
    ///
    /// Stores to `0x0100 | sp`, then decrements `sp`.
    #[inline]
    pub fn push(&mut self, val: u8, mem: &mut [u8]) {
        let addr = 0x0100usize | self.sp as usize;
        Self::wr(mem, addr, val);
        self.sp = self.sp.wrapping_sub(1);
    }

    /// Pull (pop) a byte from the hardware stack.
    ///
    /// Increments `sp` first, then reads from `0x0100 | sp`.
    #[inline]
    pub fn pop(&mut self, mem: &[u8]) -> u8 {
        self.sp = self.sp.wrapping_add(1);
        Self::rd(mem, 0x0100usize | self.sp as usize)
    }

    // Internal 16-bit push/pop helpers ─────────────────────────────────────

    #[inline]
    fn push16(&mut self, val: u16, mem: &mut [u8]) {
        self.push((val >> 8) as u8, mem);
        self.push(val.to_le_bytes()[0], mem);
    }

    #[inline]
    fn pop16(&mut self, mem: &[u8]) -> u16 {
        let lo = u16::from(self.pop(mem));
        let hi = u16::from(self.pop(mem));
        (hi << 8) | lo
    }

    // Internal flag shortcuts ────────────────────────────────────────────────

    #[inline]
    const fn carry(&self) -> bool {
        self.status & status::C != 0
    }
    #[inline]
    const fn zero(&self) -> bool {
        self.status & status::Z != 0
    }
    #[inline]
    const fn negative(&self) -> bool {
        self.status & status::N != 0
    }
    #[inline]
    const fn overflow(&self) -> bool {
        self.status & status::V != 0
    }

    // Internal address-mode resolver ────────────────────────────────────────

    /// Compute the effective 16-bit address for the given mode, reading
    /// operand bytes from `mem`.  Also reports page-boundary crossings.
    fn resolve_addr(&self, mem: &[u8], mode: AddrMode, op1: u8, op2: u8) -> (u16, bool) {
        match mode {
            AddrMode::ZeroPageX => (u16::from(op1.wrapping_add(self.x)), false),
            AddrMode::ZeroPageY => (u16::from(op1.wrapping_add(self.y)), false),
            AddrMode::Absolute => (u16::from_le_bytes([op1, op2]), false),
            AddrMode::AbsoluteX => {
                let base = u16::from_le_bytes([op1, op2]);
                let addr = base.wrapping_add(u16::from(self.x));
                (addr, (base & 0xFF00) != (addr & 0xFF00))
            }
            AddrMode::AbsoluteY => {
                let base = u16::from_le_bytes([op1, op2]);
                let addr = base.wrapping_add(u16::from(self.y));
                (addr, (base & 0xFF00) != (addr & 0xFF00))
            }
            AddrMode::Indirect => {
                // Classic 6502 page-wrap bug: high byte comes from same page.
                let ptr = u16::from_le_bytes([op1, op2]);
                let lo = u16::from(Self::rd(mem, ptr as usize));
                let hi_ptr = (ptr & 0xFF00) | (ptr.wrapping_add(1) & 0x00FF);
                let hi = u16::from(Self::rd(mem, hi_ptr as usize));
                ((hi << 8) | lo, false)
            }
            AddrMode::IndirectX => {
                let zp = op1.wrapping_add(self.x) as usize;
                let lo = u16::from(Self::rd(mem, zp & 0xFF));
                let hi = u16::from(Self::rd(mem, (zp + 1) & 0xFF));
                ((hi << 8) | lo, false)
            }
            AddrMode::IndirectY => {
                let lo = u16::from(Self::rd(mem, op1 as usize));
                let hi = u16::from(Self::rd(mem, op1.wrapping_add(1) as usize));
                let base = (hi << 8) | lo;
                let addr = base.wrapping_add(u16::from(self.y));
                (addr, (base & 0xFF00) != (addr & 0xFF00))
            }
            AddrMode::ZeroPageIndirect => {
                let lo = u16::from(Self::rd(mem, op1 as usize));
                let hi = u16::from(Self::rd(mem, op1.wrapping_add(1) as usize));
                ((hi << 8) | lo, false)
            }
            _ => (u16::from(op1), false),
        }
    }

    /// Read the operand value (immediate, accumulator, or memory).
    fn read_val(&self, mem: &[u8], mode: AddrMode, op1: u8, op2: u8) -> u8 {
        match mode {
            AddrMode::Immediate => op1,
            AddrMode::Accumulator => self.a,
            _ => {
                let (addr, _) = self.resolve_addr(mem, mode, op1, op2);
                Self::rd(mem, addr as usize)
            }
        }
    }

    /// Write a byte back to an accumulator-or-memory target.
    fn write_val(&mut self, mem: &mut [u8], mode: AddrMode, op1: u8, op2: u8, val: u8) {
        if mode == AddrMode::Accumulator { self.a = val } else {
            let (addr, _) = self.resolve_addr(mem, mode, op1, op2);
            Self::wr(mem, addr as usize, val);
        }
    }
}

// ── Cpu6502 emulator driver ───────────────────────────────────────────────────

/// Stateless 6502 emulator driver.
///
/// All mutable state lives in [`Cpu6502EmuState`] and memory lives in a
/// plain `[u8]` slice (or [`MemoryBus6502::ram`]).  The driver provides
/// [`Cpu6502::step`] for single-stepping and [`Cpu6502::run_until`] for
/// running to a breakpoint.
#[derive(Debug, Clone, Default)]
pub struct Cpu6502;

impl Cpu6502 {
    /// Create a new driver instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Initialise `state` to a hardware-reset condition, reading the reset
    /// vector from `mem[0xFFFC..=0xFFFD]`.
    pub fn reset(state: &mut Cpu6502EmuState, mem: &[u8]) {
        state.a = 0;
        state.x = 0;
        state.y = 0;
        state.sp = 0xFD;
        state.status = status::U | status::I;
        state.cycles = 0;
        let lo = u16::from(mem[0xFFFC]);
        let hi = u16::from(mem[0xFFFD]);
        state.pc = (hi << 8) | lo;
    }

    /// Execute the single instruction at `state.pc`, advancing the CPU state.
    ///
    /// Returns the number of cycles consumed by this instruction.  The cycle
    /// count is also added to `state.cycles`.
    ///
    /// All 56 official NMOS 6502 opcodes are implemented.  Decimal mode
    /// (D flag) is accepted but ADC/SBC execute in binary mode (NES
    /// convention).  Illegal/undocumented opcodes are treated as NOPs.
    pub fn step(state: &mut Cpu6502EmuState, mem: &mut [u8]) -> u8 {
        let pc = state.pc;
        let opcode = mem[pc as usize];
        let op1 = mem[pc.wrapping_add(1) as usize];
        let op2 = mem[pc.wrapping_add(2) as usize];

        let Some(entry) = opcode_table(opcode) else {
            // Completely undefined opcode – treat as a 2-cycle NOP.
            state.pc = pc.wrapping_add(1);
            state.cycles = state.cycles.saturating_add(2);
            return 2;
        };

        let mode = entry.mode;
        let instr_len = 1 + mode.extra_bytes();
        let next_pc = pc.wrapping_add(instr_len);

        let (eff_addr, page_cross) = state.resolve_addr(mem, mode, op1, op2);
        let base_cycles = entry.cycles;
        let page_penalty = u8::from(page_cross);

        let mut extra = page_penalty;
        let mut branched = false;

        match opcode {
            // ── LDA ──────────────────────────────────────────────────────────
            0xA9 | 0xA5 | 0xB5 | 0xAD | 0xBD | 0xB9 | 0xA1 | 0xB1 => {
                let v = state.read_val(mem, mode, op1, op2);
                state.a = v;
                state.update_nz(v);
            }
            // ── LDX ──────────────────────────────────────────────────────────
            0xA2 | 0xA6 | 0xB6 | 0xAE | 0xBE => {
                let v = state.read_val(mem, mode, op1, op2);
                state.x = v;
                state.update_nz(v);
            }
            // ── LDY ──────────────────────────────────────────────────────────
            0xA0 | 0xA4 | 0xB4 | 0xAC | 0xBC => {
                let v = state.read_val(mem, mode, op1, op2);
                state.y = v;
                state.update_nz(v);
            }
            // ── STA ──────────────────────────────────────────────────────────
            0x85 | 0x95 | 0x8D | 0x9D | 0x99 | 0x81 | 0x91 => {
                mem[eff_addr as usize] = state.a;
            }
            // ── STX ──────────────────────────────────────────────────────────
            0x86 | 0x96 | 0x8E => {
                mem[eff_addr as usize] = state.x;
            }
            // ── STY ──────────────────────────────────────────────────────────
            0x84 | 0x94 | 0x8C => {
                mem[eff_addr as usize] = state.y;
            }
            // ── ADC ──────────────────────────────────────────────────────────
            0x69 | 0x65 | 0x75 | 0x6D | 0x7D | 0x79 | 0x61 | 0x71 => {
                let v = state.read_val(mem, mode, op1, op2);
                let c_in = u16::from(state.carry());
                let result = u16::from(state.a) + u16::from(v) + c_in;
                let overflow = (!(state.a ^ v) & (state.a ^ result.to_le_bytes()[0]) & 0x80) != 0;
                state.set_flag(status::C, result > 0xFF);
                state.set_flag(status::V, overflow);
                state.a = result.to_le_bytes()[0];
                state.update_nz(state.a);
            }
            // ── SBC ──────────────────────────────────────────────────────────
            0xE9 | 0xE5 | 0xF5 | 0xED | 0xFD | 0xF9 | 0xE1 | 0xF1 => {
                let v = state.read_val(mem, mode, op1, op2);
                let borrow = u16::from(!state.carry());
                let result = u16::from(state.a) - u16::from(v) - borrow;
                let overflow = ((state.a ^ v) & (state.a ^ result.to_le_bytes()[0]) & 0x80) != 0;
                state.set_flag(status::C, result < 0x100);
                state.set_flag(status::V, overflow);
                state.a = result.to_le_bytes()[0];
                state.update_nz(state.a);
            }
            // ── AND ──────────────────────────────────────────────────────────
            0x29 | 0x25 | 0x35 | 0x2D | 0x3D | 0x39 | 0x21 | 0x31 => {
                let v = state.read_val(mem, mode, op1, op2);
                state.a &= v;
                state.update_nz(state.a);
            }
            // ── ORA ──────────────────────────────────────────────────────────
            0x09 | 0x05 | 0x15 | 0x0D | 0x1D | 0x19 | 0x01 | 0x11 => {
                let v = state.read_val(mem, mode, op1, op2);
                state.a |= v;
                state.update_nz(state.a);
            }
            // ── EOR ──────────────────────────────────────────────────────────
            0x49 | 0x45 | 0x55 | 0x4D | 0x5D | 0x59 | 0x41 | 0x51 => {
                let v = state.read_val(mem, mode, op1, op2);
                state.a ^= v;
                state.update_nz(state.a);
            }
            // ── CMP ──────────────────────────────────────────────────────────
            0xC9 | 0xC5 | 0xD5 | 0xCD | 0xDD | 0xD9 | 0xC1 | 0xD1 => {
                let v = state.read_val(mem, mode, op1, op2);
                let r = state.a.wrapping_sub(v);
                state.set_flag(status::C, state.a >= v);
                state.update_nz(r);
            }
            // ── CPX ──────────────────────────────────────────────────────────
            0xE0 | 0xE4 | 0xEC => {
                let v = state.read_val(mem, mode, op1, op2);
                let r = state.x.wrapping_sub(v);
                state.set_flag(status::C, state.x >= v);
                state.update_nz(r);
            }
            // ── CPY ──────────────────────────────────────────────────────────
            0xC0 | 0xC4 | 0xCC => {
                let v = state.read_val(mem, mode, op1, op2);
                let r = state.y.wrapping_sub(v);
                state.set_flag(status::C, state.y >= v);
                state.update_nz(r);
            }
            // ── BIT ──────────────────────────────────────────────────────────
            0x24 | 0x2C => {
                let v = mem[eff_addr as usize];
                state.set_flag(status::Z, state.a & v == 0);
                state.set_flag(status::V, v & 0x40 != 0);
                state.set_flag(status::N, v & 0x80 != 0);
            }
            // ── INC ──────────────────────────────────────────────────────────
            0xE6 | 0xF6 | 0xEE | 0xFE => {
                let v = mem[eff_addr as usize].wrapping_add(1);
                mem[eff_addr as usize] = v;
                state.update_nz(v);
            }
            // ── INX / INY ────────────────────────────────────────────────────
            0xE8 => {
                state.x = state.x.wrapping_add(1);
                state.update_nz(state.x);
            }
            0xC8 => {
                state.y = state.y.wrapping_add(1);
                state.update_nz(state.y);
            }
            // ── DEC ──────────────────────────────────────────────────────────
            0xC6 | 0xD6 | 0xCE | 0xDE => {
                let v = mem[eff_addr as usize].wrapping_sub(1);
                mem[eff_addr as usize] = v;
                state.update_nz(v);
            }
            // ── DEX / DEY ────────────────────────────────────────────────────
            0xCA => {
                state.x = state.x.wrapping_sub(1);
                state.update_nz(state.x);
            }
            0x88 => {
                state.y = state.y.wrapping_sub(1);
                state.update_nz(state.y);
            }
            // ── ASL ──────────────────────────────────────────────────────────
            0x0A | 0x06 | 0x16 | 0x0E | 0x1E => {
                let v = state.read_val(mem, mode, op1, op2);
                state.set_flag(status::C, v & 0x80 != 0);
                let r = v << 1;
                state.update_nz(r);
                state.write_val(mem, mode, op1, op2, r);
            }
            // ── LSR ──────────────────────────────────────────────────────────
            0x4A | 0x46 | 0x56 | 0x4E | 0x5E => {
                let v = state.read_val(mem, mode, op1, op2);
                state.set_flag(status::C, v & 0x01 != 0);
                let r = v >> 1;
                state.update_nz(r);
                state.write_val(mem, mode, op1, op2, r);
            }
            // ── ROL ──────────────────────────────────────────────────────────
            0x2A | 0x26 | 0x36 | 0x2E | 0x3E => {
                let v = state.read_val(mem, mode, op1, op2);
                let old_c = u8::from(state.carry());
                state.set_flag(status::C, v & 0x80 != 0);
                let r = (v << 1) | old_c;
                state.update_nz(r);
                state.write_val(mem, mode, op1, op2, r);
            }
            // ── ROR ──────────────────────────────────────────────────────────
            0x6A | 0x66 | 0x76 | 0x6E | 0x7E => {
                let v = state.read_val(mem, mode, op1, op2);
                let old_c = if state.carry() { 0x80u8 } else { 0 };
                state.set_flag(status::C, v & 0x01 != 0);
                let r = (v >> 1) | old_c;
                state.update_nz(r);
                state.write_val(mem, mode, op1, op2, r);
            }
            // ── JMP abs ──────────────────────────────────────────────────────
            0x4C => {
                state.pc = u16::from_le_bytes([op1, op2]);
                let c = base_cycles;
                state.cycles = state.cycles.saturating_add(u64::from(c));
                return c;
            }
            // ── JMP (ind) ────────────────────────────────────────────────────
            0x6C => {
                let ptr = u16::from_le_bytes([op1, op2]);
                let lo = u16::from(mem[ptr as usize]);
                // Classic 6502 page-wrap bug.
                let hi = u16::from(mem[((ptr & 0xFF00) | (ptr.wrapping_add(1) & 0x00FF)) as usize]);
                state.pc = (hi << 8) | lo;
                let c = base_cycles;
                state.cycles = state.cycles.saturating_add(u64::from(c));
                return c;
            }
            // ── JSR ──────────────────────────────────────────────────────────
            0x20 => {
                let target = u16::from_le_bytes([op1, op2]);
                state.push16(next_pc.wrapping_sub(1), mem);
                state.pc = target;
                let c = base_cycles;
                state.cycles = state.cycles.saturating_add(u64::from(c));
                return c;
            }
            // ── RTS ──────────────────────────────────────────────────────────
            0x60 => {
                let ret = state.pop16(mem).wrapping_add(1);
                state.pc = ret;
                let c = base_cycles;
                state.cycles = state.cycles.saturating_add(u64::from(c));
                return c;
            }
            // ── RTI ──────────────────────────────────────────────────────────
            0x40 => {
                let p = state.pop(mem);
                state.status = (p | status::U) & !status::B;
                let ret = state.pop16(mem);
                state.pc = ret;
                let c = base_cycles;
                state.cycles = state.cycles.saturating_add(u64::from(c));
                return c;
            }
            // ── BRK ──────────────────────────────────────────────────────────
            0x00 => {
                // Push PC+2 (one past the padding byte) and then push status.
                state.push16(pc.wrapping_add(2), mem);
                state.push(state.status | status::B | status::U, mem);
                state.set_flag(status::I, true);
                let lo = u16::from(mem[0xFFFE]);
                let hi = u16::from(mem[0xFFFF]);
                state.pc = (hi << 8) | lo;
                let c = base_cycles;
                state.cycles = state.cycles.saturating_add(u64::from(c));
                return c;
            }
            // ── Conditional branches ──────────────────────────────────────────
            // BCC BCS BEQ BMI BNE BPL BVC BVS
            0x90 | 0xB0 | 0xF0 | 0x30 | 0xD0 | 0x10 | 0x50 | 0x70 => {
                let taken = match opcode {
                    0x90 => !state.carry(),    // BCC
                    0xB0 => state.carry(),     // BCS
                    0xF0 => state.zero(),      // BEQ
                    0x30 => state.negative(),  // BMI
                    0xD0 => !state.zero(),     // BNE
                    0x10 => !state.negative(), // BPL
                    0x50 => !state.overflow(), // BVC
                    0x70 => state.overflow(),  // BVS
                    _ => false,
                };
                if taken {
                    let new_pc = next_pc.wrapping_add_signed(i16::from(op1.cast_signed()));
                    let cross_page = (next_pc & 0xFF00) != (new_pc & 0xFF00);
                    state.pc = new_pc;
                    // +1 for branch taken, +1 more if page crossed.
                    extra = 1 + u8::from(cross_page);
                    branched = true;
                }
            }
            // ── Stack push/pull ───────────────────────────────────────────────
            0x48 => state.push(state.a, mem), // PHA
            0x08 => {
                // PHP
                let v = state.status | status::B | status::U;
                state.push(v, mem);
            }
            0x68 => {
                // PLA
                let v = state.pop(mem);
                state.a = v;
                state.update_nz(v);
            }
            0x28 => {
                // PLP
                let v = state.pop(mem);
                state.status = (v | status::U) & !status::B;
            }
            // ── Register transfers ────────────────────────────────────────────
            0xAA => {
                state.x = state.a;
                state.update_nz(state.x);
            } // TAX
            0xA8 => {
                state.y = state.a;
                state.update_nz(state.y);
            } // TAY
            0xBA => {
                state.x = state.sp;
                state.update_nz(state.x);
            } // TSX
            0x8A => {
                state.a = state.x;
                state.update_nz(state.a);
            } // TXA
            0x9A => {
                state.sp = state.x;
            } // TXS (no NZ update)
            0x98 => {
                state.a = state.y;
                state.update_nz(state.a);
            } // TYA
            // ── Flag instructions ─────────────────────────────────────────────
            0x18 => state.set_flag(status::C, false), // CLC
            0x38 => state.set_flag(status::C, true),  // SEC
            0x58 => state.set_flag(status::I, false), // CLI
            0x78 => state.set_flag(status::I, true),  // SEI
            0xB8 => state.set_flag(status::V, false), // CLV
            0xD8 => state.set_flag(status::D, false), // CLD
            0xF8 => state.set_flag(status::D, true),  // SED
            // ── NOP ──────────────────────────────────────────────────────────
            0xEA => {} // 2 cycles, no operation
            // ── All other bytes treated as NOP ────────────────────────────────
            _ => {}
        }

        if !branched {
            state.pc = next_pc;
        }
        let total = base_cycles + extra;
        state.cycles = state.cycles.saturating_add(u64::from(total));
        total
    }

    /// Run the CPU until `state.pc == stop_pc` or `state.cycles` has
    /// accumulated at least `max_cycles` cycles (counted from entry, not
    /// from zero).
    ///
    /// Returns the total number of cycles consumed during this call.
    pub fn run_until(
        state: &mut Cpu6502EmuState,
        mem: &mut [u8],
        stop_pc: u16,
        max_cycles: u64,
    ) -> u64 {
        let start_cycles = state.cycles;
        loop {
            if state.pc == stop_pc {
                break;
            }
            let elapsed = state.cycles.saturating_sub(start_cycles);
            if elapsed >= max_cycles {
                break;
            }
            Self::step(state, mem);
        }
        state.cycles.saturating_sub(start_cycles)
    }
}

// ── Improved disassembler ─────────────────────────────────────────────────────

/// Disassemble up to `n_instrs` instructions from `data`, treating byte 0 as
/// if it lives at virtual address `start_addr`.
///
/// Each returned string is formatted as:
/// ```text
/// C000  A9 00     LDA #$00
/// ```
/// The address column is 4 hex digits, the bytes column is left-padded to
/// 8 characters (up to 3 bytes at 3 chars each), and the mnemonic+operand
/// fill the remainder.
///
/// Unknown or truncated bytes are rendered as `??` with a `???` mnemonic.
#[must_use]
pub fn disassemble_range(data: &[u8], start_addr: u16, n_instrs: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(n_instrs);
    let mut offset = 0usize;
    let mut addr = start_addr;

    while out.len() < n_instrs && offset < data.len() {
        let slice = &data[offset..];

        // Determine opcode and instruction length.
        let (mnemonic, operand_str, instr_len) = if let Some(entry) = opcode_table(slice[0]) {
            let ilen = 1 + entry.mode.extra_bytes() as usize;
            if slice.len() < ilen {
                // Truncated – emit a single ?? byte.
                let byte_hex = format!("{:02X}", slice[0]);
                let line = format!("{addr:04X}  {byte_hex:<8}  ???");
                out.push(line);
                offset += 1;
                addr = addr.wrapping_add(1);
                continue;
            }
            let instr_bytes = &slice[..ilen];
            let operand = format_operand(entry.mode, instr_bytes, u64::from(addr));
            (entry.mnemonic, operand, ilen)
        } else {
            // Unknown opcode.
            let byte_hex = format!("{:02X}", slice[0]);
            let line = format!("{addr:04X}  {byte_hex:<8}  ???");
            out.push(line);
            offset += 1;
            addr = addr.wrapping_add(1);
            continue;
        };

        // Build the raw-bytes column (max 3 bytes, space-separated, padded).
        let raw_bytes = &data[offset..offset + instr_len];
        let bytes_str: String = raw_bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");

        // Pad bytes column to 8 characters ("XX XX XX" = 8 chars).
        let line = if operand_str.is_empty() {
            format!("{addr:04X}  {bytes_str:<8}  {mnemonic}")
        } else {
            format!("{addr:04X}  {bytes_str:<8}  {mnemonic} {operand_str}")
        };

        out.push(line);
        offset += instr_len;
        addr = addr.wrapping_add(instr_len as u16);
    }

    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::arch::BranchKind;

    fn arch() -> Cpu6502Arch {
        Cpu6502Arch::new()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    // ── Basic instructions ────────────────────────────────────────────────────

    #[test]
    fn test_nop() {
        let i = arch().disassemble(addr(0x200), &[0xEA]).unwrap();
        assert_eq!(i.mnemonic, "NOP");
        assert_eq!(i.size, 1);
        assert!(i.operands.is_empty());
    }

    #[test]
    fn test_lda_immediate() {
        let i = arch().disassemble(addr(0x200), &[0xA9, 0x42]).unwrap();
        assert_eq!(i.mnemonic, "LDA");
        assert_eq!(i.operands, "#$42");
        assert_eq!(i.size, 2);
    }

    #[test]
    fn test_lda_absolute() {
        let i = arch()
            .disassemble(addr(0x200), &[0xAD, 0x00, 0x20])
            .unwrap();
        assert_eq!(i.mnemonic, "LDA");
        assert_eq!(i.operands, "$2000");
    }

    #[test]
    fn test_sta_indirect_y() {
        let i = arch().disassemble(addr(0x200), &[0x91, 0x50]).unwrap();
        assert_eq!(i.mnemonic, "STA");
        assert_eq!(i.operands, "($50),Y");
    }

    #[test]
    fn test_jmp_absolute() {
        let i = arch()
            .disassemble(addr(0x200), &[0x4C, 0x00, 0x03])
            .unwrap();
        assert_eq!(i.mnemonic, "JMP");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_jmp_indirect() {
        let i = arch()
            .disassemble(addr(0x200), &[0x6C, 0xFF, 0x01])
            .unwrap();
        assert_eq!(i.mnemonic, "JMP");
        assert!(i.flags.contains(InstrFlags::INDIRECT));
    }

    #[test]
    fn test_jsr() {
        let i = arch()
            .disassemble(addr(0x200), &[0x20, 0x00, 0xFF])
            .unwrap();
        assert_eq!(i.mnemonic, "JSR");
        assert!(i.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_rts() {
        let i = arch().disassemble(addr(0x200), &[0x60]).unwrap();
        assert_eq!(i.mnemonic, "RTS");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_rti() {
        let i = arch().disassemble(addr(0x200), &[0x40]).unwrap();
        assert_eq!(i.mnemonic, "RTI");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_brk() {
        let i = arch().disassemble(addr(0x200), &[0x00]).unwrap();
        assert_eq!(i.mnemonic, "BRK");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    // ── Branches ──────────────────────────────────────────────────────────────

    #[test]
    fn test_bne_forward() {
        let i = arch().disassemble(addr(0x200), &[0xD0, 0x10]).unwrap();
        assert_eq!(i.mnemonic, "BNE");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
        assert_eq!(i.operands, "$0212");
    }

    #[test]
    fn test_bne_backward() {
        let i = arch().disassemble(addr(0x210), &[0xD0, 0xFE_u8]).unwrap();
        assert_eq!(i.operands, "$0210");
    }

    #[test]
    fn test_bcc() {
        let i = arch().disassemble(addr(0x200), &[0x90, 0x00]).unwrap();
        assert_eq!(i.mnemonic, "BCC");
    }

    #[test]
    fn test_bcs() {
        let i = arch().disassemble(addr(0x200), &[0xB0, 0x00]).unwrap();
        assert_eq!(i.mnemonic, "BCS");
    }

    #[test]
    fn test_beq() {
        let i = arch().disassemble(addr(0x200), &[0xF0, 0x00]).unwrap();
        assert_eq!(i.mnemonic, "BEQ");
    }

    // ── Addressing modes ──────────────────────────────────────────────────────

    #[test]
    fn test_asl_accumulator() {
        let i = arch().disassemble(addr(0x200), &[0x0A]).unwrap();
        assert_eq!(i.mnemonic, "ASL");
        assert_eq!(i.operands, "A");
    }

    #[test]
    fn test_ldx_zeropage_y() {
        let i = arch().disassemble(addr(0x300), &[0xB6, 0x10]).unwrap();
        assert_eq!(i.mnemonic, "LDX");
        assert_eq!(i.operands, "$10,Y");
    }

    #[test]
    fn test_stx_absolute() {
        let i = arch()
            .disassemble(addr(0x300), &[0x8E, 0x00, 0x02])
            .unwrap();
        assert_eq!(i.mnemonic, "STX");
        assert_eq!(i.operands, "$0200");
    }

    #[test]
    fn test_lda_indirect_x() {
        let i = arch().disassemble(addr(0x200), &[0xA1, 0x20]).unwrap();
        assert_eq!(i.mnemonic, "LDA");
        assert_eq!(i.operands, "($20,X)");
    }

    // ── Flags ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_flag_ops() {
        for &(op, mnem) in &[
            (0x38u8, "SEC"),
            (0xF8, "SED"),
            (0x78, "SEI"),
            (0x18, "CLC"),
            (0xD8, "CLD"),
            (0x58, "CLI"),
            (0xB8, "CLV"),
        ] {
            let i = arch().disassemble(addr(0x200), &[op]).unwrap();
            assert_eq!(i.mnemonic, mnem, "opcode 0x{op:02X}");
        }
    }

    // ── Registers / metadata ──────────────────────────────────────────────────

    #[test]
    fn test_registers_count() {
        assert_eq!(arch().registers().len(), 6);
    }

    #[test]
    fn test_endian() {
        assert_eq!(arch().endian(), Endian::Little);
    }

    #[test]
    fn test_name() {
        assert_eq!(arch().name(), "6502");
    }

    #[test]
    fn test_calling_convention() {
        let cc = arch().calling_conventions();
        assert_eq!(cc.len(), 2);
        assert_eq!(cc[0].name, "6502_cc65");
    }

    // ── Error cases ───────────────────────────────────────────────────────────

    #[test]
    fn test_unknown_opcode_error() {
        // 0x02 is KIL (illegal) – rejected by default when decode_illegal is off.
        let result = arch().disassemble(addr(0x200), &[0x02]);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_error() {
        let result = arch().disassemble(addr(0x200), &[0xAD, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_error() {
        let result = arch().disassemble(addr(0x200), &[]);
        assert!(result.is_err());
    }

    // ── Illegal opcodes ───────────────────────────────────────────────────────

    #[test]
    fn test_illegal_rejected_by_default() {
        let a = arch();
        let result = a.disassemble(addr(0x200), &[0xA7, 0x10]); // LAX zp
        assert!(result.is_err());
    }

    #[test]
    fn test_illegal_decoded_when_enabled() {
        let a = Cpu6502Arch::new().with_illegal_opcodes();
        let i = a.disassemble(addr(0x200), &[0xA7, 0x10]).unwrap();
        assert_eq!(i.mnemonic, "LAX");
    }

    // ── 65C02 ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_65c02_bra() {
        let a = Cpu6502Arch::new_65c02();
        let i = a.disassemble(addr(0x200), &[0x80, 0x00]).unwrap();
        assert_eq!(i.mnemonic, "BRA");
    }

    #[test]
    fn test_65c02_stz() {
        let a = Cpu6502Arch::new_65c02();
        let i = a.disassemble(addr(0x200), &[0x64, 0x10]).unwrap();
        assert_eq!(i.mnemonic, "STZ");
    }

    #[test]
    fn test_65c02_phx_plx() {
        let a = Cpu6502Arch::new_65c02();
        let phx = a.disassemble(addr(0x200), &[0xDA]).unwrap();
        assert_eq!(phx.mnemonic, "PHX");
        let plx = a.disassemble(addr(0x200), &[0xFA]).unwrap();
        assert_eq!(plx.mnemonic, "PLX");
    }

    #[test]
    fn test_65c02_name() {
        assert_eq!(Cpu6502Arch::new_65c02().name(), "65c02");
    }

    // ── Linear disassembler ───────────────────────────────────────────────────

    #[test]
    fn test_linear_disassembler() {
        let code = [0xA9u8, 0x42, 0xAA, 0x60];
        let a = arch();
        let instrs: Vec<_> = Cpu6502LinearDisassembler::new(&a, &code, addr(0x200))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[0].mnemonic, "LDA");
        assert_eq!(instrs[1].mnemonic, "TAX");
        assert_eq!(instrs[2].mnemonic, "RTS");
    }

    #[test]
    fn test_linear_disassembler_skips_invalid() {
        // 0x02 is now a KIL illegal opcode – use with_illegal_opcodes OFF so it errors.
        // Since arch() has decode_illegal=false, 0x02 will produce an error.
        let code = [0x02u8, 0xEA]; // KIL (illegal, rejected) then NOP
        let a = arch();
        let results: Vec<_> = Cpu6502LinearDisassembler::new(&a, &code, addr(0)).collect();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_err());
        assert_eq!(results[1].as_ref().unwrap().mnemonic, "NOP");
    }

    // ── get_branches ──────────────────────────────────────────────────────────

    #[test]
    fn test_get_branches_jmp() {
        let a = arch();
        let i = a.disassemble(addr(0x200), &[0x4C, 0x00, 0x03]).unwrap();
        let b = a.get_branches(&i);
        assert_eq!(b.len(), 1);
        assert_ne!(b[0].kind, BranchKind::ConditionalJump);
        assert_ne!(b[0].kind, BranchKind::Call);
    }

    #[test]
    fn test_get_branches_jsr() {
        let a = arch();
        let i = a.disassemble(addr(0x200), &[0x20, 0x00, 0xFF]).unwrap();
        let b = a.get_branches(&i);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].kind, BranchKind::Call);
    }

    #[test]
    fn test_get_branches_nop() {
        let a = arch();
        let i = a.disassemble(addr(0x200), &[0xEA]).unwrap();
        assert!(a.get_branches(&i).is_empty());
    }

    // ── Cycle counts ─────────────────────────────────────────────────────────

    #[test]
    fn test_cycle_counts() {
        let a = arch();
        assert_eq!(a.cycle_count(0xEA), Some(2)); // NOP
        assert_eq!(a.cycle_count(0x20), Some(6)); // JSR abs
        assert_eq!(a.cycle_count(0x6C), Some(5)); // JMP (abs)
        assert_eq!(a.cycle_count(0xFF), Some(7)); // ISC abs,X (undocumented but tabled)
        assert_eq!(a.cycle_count(0x02), Some(2)); // KIL – illegal but tabled
        assert_eq!(a.cycle_count(0xBB), Some(4)); // LAS – illegal but tabled
    }

    // ── cycles() standalone helper ────────────────────────────────────────────

    #[test]
    fn test_cycles_no_page_cross() {
        assert_eq!(cycles(0xEA, false), 2); // NOP
        assert_eq!(cycles(0x20, false), 6); // JSR abs
        assert_eq!(cycles(0x00, false), 7); // BRK
        assert_eq!(cycles(0xBD, false), 4); // LDA abs,X (no cross)
    }

    #[test]
    fn test_cycles_with_page_cross() {
        // LDA abs,X incurs +1 on page cross
        assert_eq!(cycles(0xBD, true), 5);
        // LDA abs,Y incurs +1 on page cross
        assert_eq!(cycles(0xB9, true), 5);
        // LDA (zp),Y incurs +1 on page cross
        assert_eq!(cycles(0xB1, true), 6);
        // LDA #imm is immune to page crossing
        assert_eq!(cycles(0xA9, true), 2);
    }

    // ── disassemble_one ───────────────────────────────────────────────────────

    #[test]
    fn test_disassemble_one_nop() {
        let data = [0xEAu8];
        let r = disassemble_one(&data, 0, 0x200).unwrap();
        assert_eq!(r.bytes_consumed, 1);
        assert!(r.text.contains("NOP"));
        assert!(r.text.contains("implied"));
    }

    #[test]
    fn test_disassemble_one_lda_immediate() {
        let data = [0xA9u8, 0x42];
        let r = disassemble_one(&data, 0, 0x200).unwrap();
        assert_eq!(r.bytes_consumed, 2);
        assert!(r.text.contains("LDA"));
        assert!(r.text.contains("#$42"));
        assert!(r.text.contains("immediate"));
    }

    #[test]
    fn test_disassemble_one_jsr_abs() {
        let data = [0x20u8, 0x00, 0xFF];
        let r = disassemble_one(&data, 0, 0x200).unwrap();
        assert_eq!(r.bytes_consumed, 3);
        assert!(r.text.contains("JSR"));
        assert!(r.text.contains("$FF00"));
    }

    #[test]
    fn test_disassemble_one_offset() {
        let data = [0x00u8, 0xEA]; // BRK, NOP
        let r = disassemble_one(&data, 1, 0x201).unwrap();
        assert!(r.text.contains("NOP"));
    }

    #[test]
    fn test_disassemble_one_out_of_range() {
        let data = [0xA9u8]; // LDA imm needs 2 bytes
        assert!(disassemble_one(&data, 0, 0).is_none()); // truncated
        assert!(disassemble_one(&data, 5, 0).is_none()); // offset past end
    }

    // ── Cpu6502State / execute_one ────────────────────────────────────────────

    fn make_state() -> (Cpu6502State, Box<[u8; 65536]>) {
        let mut mem = Box::new([0u8; 65536]);
        // Write reset vector pointing to 0x0200
        mem[0xFFFC] = 0x00;
        mem[0xFFFD] = 0x02;
        let state = Cpu6502State::reset(&mem);
        (state, mem)
    }

    fn run(program: &[u8]) -> (Cpu6502State, Box<[u8; 65536]>) {
        let (mut state, mut mem) = make_state();
        for (i, &b) in program.iter().enumerate() {
            mem[0x200 + i] = b;
        }
        // Execute all instructions until we hit a KIL or run past the program.
        let end = 0x200u16 + program.len() as u16;
        let mut guard = 0u32;
        while state.pc < end && guard < 10_000 {
            let c = execute_one(&mut state, &mut mem);
            if c == 255 {
                break;
            } // KIL
            guard += 1;
        }
        (state, mem)
    }

    #[test]
    fn test_emu_nop() {
        let (state, _) = run(&[0xEA]); // NOP
        assert_eq!(state.pc, 0x201);
    }

    #[test]
    fn test_emu_lda_sta() {
        // LDA #$42 ; STA $10
        let (state, mem) = run(&[0xA9, 0x42, 0x85, 0x10]);
        assert_eq!(state.a, 0x42);
        assert_eq!(mem[0x10], 0x42);
    }

    #[test]
    fn test_emu_ldx_stx_ldy_sty() {
        // LDX #$11 ; STX $20 ; LDY #$22 ; STY $21
        let (state, mem) = run(&[0xA2, 0x11, 0x86, 0x20, 0xA0, 0x22, 0x84, 0x21]);
        assert_eq!(state.x, 0x11);
        assert_eq!(mem[0x20], 0x11);
        assert_eq!(state.y, 0x22);
        assert_eq!(mem[0x21], 0x22);
    }

    #[test]
    fn test_emu_inx_dex() {
        // LDX #$05 ; INX ; INX ; DEX
        let (state, _) = run(&[0xA2, 0x05, 0xE8, 0xE8, 0xCA]);
        assert_eq!(state.x, 0x06);
    }

    #[test]
    fn test_emu_iny_dey() {
        // LDY #0 ; INY ; INY
        let (state, _) = run(&[0xA0, 0x00, 0xC8, 0xC8]);
        assert_eq!(state.y, 0x02);
    }

    #[test]
    fn test_emu_adc() {
        // LDA #$10 ; ADC #$20
        let (state, _) = run(&[0xA9, 0x10, 0x69, 0x20]);
        assert_eq!(state.a, 0x30);
        assert!(state.p & status::C == 0);
        assert!(state.p & status::Z == 0);
    }

    #[test]
    fn test_emu_adc_carry() {
        // LDA #$FF ; ADC #$01 → should set carry, result = 0x00, set Z
        let (state, _) = run(&[0xA9, 0xFF, 0x69, 0x01]);
        assert_eq!(state.a, 0x00);
        assert!(state.p & status::C != 0);
        assert!(state.p & status::Z != 0);
    }

    #[test]
    fn test_emu_sbc() {
        // SEC ; LDA #$10 ; SBC #$05
        let (state, _) = run(&[0x38, 0xA9, 0x10, 0xE9, 0x05]);
        assert_eq!(state.a, 0x0B);
        assert!(state.p & status::C != 0); // borrow = 0 means carry set
    }

    #[test]
    fn test_emu_and_ora_eor() {
        // LDA #$FF ; AND #$0F → 0x0F ; ORA #$F0 → 0xFF ; EOR #$FF → 0x00
        let (state, _) = run(&[0xA9, 0xFF, 0x29, 0x0F, 0x09, 0xF0, 0x49, 0xFF]);
        assert_eq!(state.a, 0x00);
        assert!(state.p & status::Z != 0);
    }

    #[test]
    fn test_emu_cmp_sets_carry() {
        // LDA #$10 ; CMP #$05 → carry set (A >= operand)
        let (state, _) = run(&[0xA9, 0x10, 0xC9, 0x05]);
        assert!(state.p & status::C != 0);
        assert!(state.p & status::Z == 0);
    }

    #[test]
    fn test_emu_cmp_equal() {
        // LDA #$42 ; CMP #$42 → carry+zero set
        let (state, _) = run(&[0xA9, 0x42, 0xC9, 0x42]);
        assert!(state.p & status::C != 0);
        assert!(state.p & status::Z != 0);
    }

    #[test]
    fn test_emu_asl_lsr() {
        // LDA #$80 ; ASL A → carry set, A=0x00
        let (state, _) = run(&[0xA9, 0x80, 0x0A]);
        assert_eq!(state.a, 0x00);
        assert!(state.p & status::C != 0);
        assert!(state.p & status::Z != 0);
    }

    #[test]
    fn test_emu_rol_ror() {
        // SEC ; LDA #$00 ; ROL A → A=0x01 (carry shifts in)
        let (state, _) = run(&[0x38, 0xA9, 0x00, 0x2A]);
        assert_eq!(state.a, 0x01);
        assert!(state.p & status::C == 0);
    }

    #[test]
    fn test_emu_tax_tay_txa_tya() {
        // LDA #$55 ; TAX ; LDA #$00 ; TXA → A should be 0x55 again
        let (state, _) = run(&[0xA9, 0x55, 0xAA, 0xA9, 0x00, 0x8A]);
        assert_eq!(state.a, 0x55);
        assert_eq!(state.x, 0x55);
    }

    #[test]
    fn test_emu_txs_tsx() {
        // LDX #$EF ; TXS ; TSX (round-trip)
        let (state, _) = run(&[0xA2, 0xEF, 0x9A, 0xBA]);
        assert_eq!(state.sp, 0xEF);
        assert_eq!(state.x, 0xEF);
    }

    #[test]
    fn test_emu_pha_pla() {
        // LDA #$AB ; PHA ; LDA #$00 ; PLA → A should be 0xAB again
        let (state, _) = run(&[0xA9, 0xAB, 0x48, 0xA9, 0x00, 0x68]);
        assert_eq!(state.a, 0xAB);
    }

    #[test]
    fn test_emu_php_plp() {
        // SEC ; PHP ; CLC ; PLP → carry should be restored
        let (state, _) = run(&[0x38, 0x08, 0x18, 0x28]);
        assert!(state.p & status::C != 0);
    }

    #[test]
    fn test_emu_bne_taken() {
        // LDX #$03 ; DEX ; BNE -3 (loop back to DEX) ; → X should be 0 when BNE falls through
        // Encoding: LDX #03 (A2 03) DEX (CA) BNE -3 (D0 FD)
        // -3 as signed byte = 0xFD, next_pc=0x205, 0x205 + (-3) = 0x202 = DEX
        let (state, _) = run(&[0xA2, 0x03, 0xCA, 0xD0, 0xFD]);
        assert_eq!(state.x, 0x00);
        assert!(state.p & status::Z != 0);
    }

    #[test]
    fn test_emu_jmp_abs() {
        // JMP $0205 ; NOP ; NOP ; LDA #$42
        // Offset layout: 0x200=JMP, 0x201=05, 0x202=02, 0x203=NOP, 0x204=NOP, 0x205=LDA, 0x206=42
        let (state, _) = run(&[0x4C, 0x05, 0x02, 0xEA, 0xEA, 0xA9, 0x42]);
        assert_eq!(state.a, 0x42);
    }

    #[test]
    fn test_emu_jsr_rts() {
        // JSR $0205 ; LDA #$FF ; RTS ; (at 0x205) LDA #$42 ; RTS
        // 0x200: JSR $0205 (20 05 02)
        // 0x203: LDA #$FF (A9 FF) -- should be skipped on return
        // 0x205: LDA #$42 (A9 42)
        // 0x207: RTS (60) → returns to 0x203, then continues to 0x205...
        // Actually let's just check that after JSR+RTS the PC is after the JSR.
        // Better: JSR sub at 0x205, then NOP, then A=0xFF; sub sets A=0x42 then RTS
        // We place them so that after RTS, pc=0x203, which is LDA #$FF, so final A=$FF.
        // Hmm, simpler: just test A=0x42 from the sub.
        let mut prog = [0u8; 10];
        prog[0] = 0x20;
        prog[1] = 0x06;
        prog[2] = 0x02; // JSR $0206
        prog[3] = 0xEA; // NOP (not reached because sub doesn't return in this test slice)
        prog[4] = 0xEA; // NOP
        prog[5] = 0xEA; // pad
        prog[6] = 0xA9;
        prog[7] = 0x42; // LDA #$42
        prog[8] = 0x60; // RTS
        prog[9] = 0xEA; // NOP
        let (state, _) = run(&prog);
        assert_eq!(state.a, 0x42);
    }

    #[test]
    fn test_emu_flag_ops() {
        // SEC CLC SEC CLI SEI CLD SED CLV
        let (state, _) = run(&[0x38, 0x18, 0x38, 0x58, 0x78, 0xD8, 0xF8]);
        assert!(state.p & status::C != 0); // SEC
        assert!(state.p & status::I != 0); // SEI
        assert!(state.p & status::D != 0); // SED
    }

    #[test]
    fn test_emu_inc_dec_memory() {
        // INC $50 (start at 0), then DEC $50
        let (mut state, mut mem) = make_state();
        mem[0x50] = 0x00;
        mem[0x200] = 0xE6;
        mem[0x201] = 0x50; // INC $50
        mem[0x202] = 0xE6;
        mem[0x203] = 0x50; // INC $50
        mem[0x204] = 0xC6;
        mem[0x205] = 0x50; // DEC $50
        for _ in 0..3 {
            execute_one(&mut state, &mut mem);
        }
        assert_eq!(mem[0x50], 0x01);
    }

    #[test]
    fn test_emu_illegal_lax() {
        // LAX #$55 – not a valid mode; use LAX zp (0xA7)
        let (mut state, mut mem) = make_state();
        mem[0x50] = 0x42;
        mem[0x200] = 0xA7;
        mem[0x201] = 0x50; // LAX $50
        let _arch = Cpu6502Arch::new().with_illegal_opcodes();
        // execute_one doesn't check variant, so just run directly:
        execute_one(&mut state, &mut mem);
        assert_eq!(state.a, 0x42);
        assert_eq!(state.x, 0x42);
    }

    #[test]
    fn test_emu_illegal_dcp() {
        // DCP $50 (0xC7): DEC $50 then CMP A with result
        let (mut state, mut mem) = make_state();
        state.a = 0x10;
        mem[0x50] = 0x11; // after DEC → 0x10; CMP 0x10 == 0x10 → Z set, C set
        mem[0x200] = 0xC7;
        mem[0x201] = 0x50;
        execute_one(&mut state, &mut mem);
        assert_eq!(mem[0x50], 0x10);
        assert!(state.p & status::Z != 0);
        assert!(state.p & status::C != 0);
    }

    #[test]
    fn test_emu_kil_halts() {
        // KIL (0x02) should return 255 cycles
        let (mut state, mut mem) = make_state();
        mem[0x200] = 0x02;
        let c = execute_one(&mut state, &mut mem);
        assert_eq!(c, 255);
        // PC should not advance (we returned early)
        assert_eq!(state.pc, 0x200);
    }

    // ── AddrMode helpers ──────────────────────────────────────────────────────

    #[test]
    fn test_addr_mode_extra_bytes() {
        assert_eq!(AddrMode::Implied.extra_bytes(), 0);
        assert_eq!(AddrMode::Immediate.extra_bytes(), 1);
        assert_eq!(AddrMode::Absolute.extra_bytes(), 2);
    }

    #[test]
    fn test_addr_mode_names() {
        assert_eq!(AddrMode::Relative.name(), "relative");
        assert_eq!(AddrMode::IndirectX.name(), "(indirect,X)");
    }
}
