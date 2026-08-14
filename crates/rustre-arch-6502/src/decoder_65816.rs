//! WDC 65816 decoder.
//!
//! The 65816 is a 16/8-bit hybrid CPU backward-compatible with the 6502 at
//! the binary level when running in *emulation mode*.  In *native mode* the
//! processor gains:
//!
//! * 24-bit program-bank addressing (16 MiB address space).
//! * Three new registers: **D** (direct-page, 16-bit), **PBR** (program bank),
//!   **DBR** (data bank).
//! * Selectable 8/16-bit accumulator (controlled by the **m** flag) and
//!   selectable 8/16-bit index registers (controlled by the **x** flag).
//! * A large set of new opcodes: PEA, PEI, PER, PHB, PHD, PHK, PLB, PLD,
//!   TCD, TCS, TDC, TSC, TXY, TYX, XBA, XCE, MVN, MVP, COP, BRL, JML,
//!   JSL, RTL, and more.
//! * Long (`24-bit`) addressing modes.
//!
//! This module provides [`decode_65816`] and the supporting [`Decoded65816`]
//! type.  Accumulator/index operand widths are communicated through
//! [`Mode65816`] so that the caller can track the current M/X flag state.

use crate::AddrMode;
use rustre_core::arch::InstrFlags;

// ── New addressing modes for the 65816 ───────────────────────────────────────
//
// The 65816 introduces several addressing modes that have no equivalent in
// the 6502/65C02 families.  We represent them using the existing `AddrMode`
// enum where possible, and define new string tags for the formatter.

/// 65816-specific addressing modes beyond those in [`AddrMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrMode816 {
    /// Standard modes shared with 6502/65C02.
    Base(AddrMode),
    /// `dp` — Direct-page (one-byte offset from D register; 1 extra byte).
    DirectPage,
    /// `dp,X` — Direct-page indexed by X; 1 extra byte.
    DirectPageX,
    /// `dp,Y` — Direct-page indexed by Y; 1 extra byte.
    DirectPageY,
    /// `(dp)` — Direct-page indirect (24-bit pointer); 1 extra byte.
    DirectPageIndirect,
    /// `[dp]` — Direct-page indirect long (24-bit effective address); 1 extra.
    DirectPageIndirectLong,
    /// `(dp,X)` — Direct-page indexed indirect; 1 extra byte.
    DirectPageIndirectX,
    /// `(dp),Y` — Direct-page indirect indexed by Y; 1 extra byte.
    DirectPageIndirectY,
    /// `[dp],Y` — Direct-page indirect long indexed by Y; 1 extra byte.
    DirectPageIndirectLongY,
    /// `abs` — 16-bit absolute; 2 extra bytes.
    Absolute16,
    /// `abs,X` — Absolute indexed X; 2 extra bytes.
    Absolute16X,
    /// `abs,Y` — Absolute indexed Y; 2 extra bytes.
    Absolute16Y,
    /// `long` — 24-bit absolute (bank + 16-bit addr); 3 extra bytes.
    AbsoluteLong,
    /// `long,X` — 24-bit absolute indexed by X; 3 extra bytes.
    AbsoluteLongX,
    /// `(abs)` — Absolute indirect; 2 extra bytes.
    AbsoluteIndirect,
    /// `(abs,X)` — Absolute indirect indexed X; 2 extra bytes.
    AbsoluteIndirectX,
    /// `[abs]` — Absolute indirect long (JML); 2 extra bytes.
    AbsoluteIndirectLong,
    /// `rl` — Relative long (16-bit signed offset from PC+3); 2 extra bytes.
    RelativeLong,
    /// `sr,S` — Stack-relative; 1 extra byte.
    StackRelative,
    /// `(sr,S),Y` — Stack-relative indirect indexed Y; 1 extra byte.
    StackRelativeIndirectY,
    /// `src,dst` — Block move (MVN/MVP): 2 extra bytes (bank numbers).
    BlockMove,
    /// Implied (no operand).
    Implied,
    /// Accumulator (no operand).
    Accumulator,
    /// Immediate with 8-bit operand (1 extra byte).
    Immediate8,
    /// Immediate with 16-bit operand (2 extra bytes) — used when m=0 or x=0.
    Immediate16,
}

impl AddrMode816 {
    /// Number of operand bytes beyond the opcode byte.
    #[must_use]
    pub const fn extra_bytes(self) -> usize {
        match self {
            Self::Immediate8
            | Self::DirectPage
            | Self::DirectPageX
            | Self::DirectPageY
            | Self::DirectPageIndirect
            | Self::DirectPageIndirectLong
            | Self::DirectPageIndirectX
            | Self::DirectPageIndirectY
            | Self::DirectPageIndirectLongY
            | Self::StackRelative
            | Self::StackRelativeIndirectY
            | Self::Base(
                AddrMode::ZeroPage
                | AddrMode::ZeroPageX
                | AddrMode::ZeroPageY
                | AddrMode::Relative
                | AddrMode::ZeroPageIndirect
                | AddrMode::IndirectX
                | AddrMode::IndirectY,
            ) => 1,

            Self::Immediate16
            | Self::Absolute16
            | Self::Absolute16X
            | Self::Absolute16Y
            | Self::AbsoluteIndirect
            | Self::AbsoluteIndirectX
            | Self::AbsoluteIndirectLong
            | Self::RelativeLong
            | Self::BlockMove
            | Self::Base(
                AddrMode::Absolute
                | AddrMode::AbsoluteX
                | AddrMode::AbsoluteY
                | AddrMode::Indirect
                | AddrMode::AbsoluteIndirectX
                | AddrMode::RelativeLong,
            ) => 2,

            Self::AbsoluteLong | Self::AbsoluteLongX => 3,
            // fallthrough for remaining base modes
            Self::Implied | Self::Accumulator | Self::Base(_) => 0,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Base(m) => m.name(),
            Self::Implied => "implied",
            Self::Accumulator => "accumulator",
            Self::Immediate8 => "immediate8",
            Self::Immediate16 => "immediate16",
            Self::DirectPage => "direct-page",
            Self::DirectPageX => "direct-page,X",
            Self::DirectPageY => "direct-page,Y",
            Self::DirectPageIndirect => "(direct-page)",
            Self::DirectPageIndirectLong => "[direct-page]",
            Self::DirectPageIndirectX => "(direct-page,X)",
            Self::DirectPageIndirectY => "(direct-page),Y",
            Self::DirectPageIndirectLongY => "[direct-page],Y",
            Self::Absolute16 => "absolute",
            Self::Absolute16X => "absolute,X",
            Self::Absolute16Y => "absolute,Y",
            Self::AbsoluteLong => "absolute-long",
            Self::AbsoluteLongX => "absolute-long,X",
            Self::AbsoluteIndirect => "(absolute)",
            Self::AbsoluteIndirectX => "(absolute,X)",
            Self::AbsoluteIndirectLong => "[absolute]",
            Self::RelativeLong => "relative-long",
            Self::StackRelative => "stack-relative",
            Self::StackRelativeIndirectY => "(stack-relative),Y",
            Self::BlockMove => "block-move",
        }
    }
}

// ── CPU mode (M/X flags) ──────────────────────────────────────────────────────

/// Tracks the current M and X flag state for the 65816.
///
/// * `m = false` → accumulator is 16 bits.
/// * `m = true`  → accumulator is 8 bits.
/// * `x = false` → index registers are 16 bits.
/// * `x = true`  → index registers are 8 bits.
///
/// In emulation mode (`e = true`) both flags are effectively forced to 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Mode65816 {
    /// Accumulator/memory width flag (false = 16-bit, true = 8-bit).
    pub m: bool,
    /// Index register width flag (false = 16-bit, true = 8-bit).
    pub x: bool,
    /// Emulation mode flag.  When set, the CPU behaves like a 65C02.
    pub e: bool,
}

impl Mode65816 {
    /// Create a mode in native 16-bit mode (m=0, x=0, e=0).
    #[must_use]
    pub const fn native16() -> Self {
        Self {
            m: false,
            x: false,
            e: false,
        }
    }

    /// Create a mode in native 8-bit mode (m=1, x=1, e=0).
    #[must_use]
    pub const fn native8() -> Self {
        Self {
            m: true,
            x: true,
            e: false,
        }
    }

    /// Create emulation mode (e=1).
    #[must_use]
    pub const fn emulation() -> Self {
        Self {
            m: true,
            x: true,
            e: true,
        }
    }

    /// Width of accumulator operands in bytes (1 or 2).
    #[must_use]
    pub const fn acc_width(self) -> usize {
        if self.m || self.e { 1 } else { 2 }
    }

    /// Width of index register operands in bytes (1 or 2).
    #[must_use]
    pub const fn idx_width(self) -> usize {
        if self.x || self.e { 1 } else { 2 }
    }
}

// ── 65816 opcode descriptor ───────────────────────────────────────────────────

/// Describes how a 65816 opcode's operand width depends on the M/X flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandWidth {
    /// Fixed width, independent of M/X.
    Fixed(AddrMode816),
    /// Width depends on the M (accumulator) flag.
    AccFlag,
    /// Width depends on the X (index) flag.
    IdxFlag,
}

/// A 65816 opcode table entry.
#[derive(Debug, Clone, Copy)]
pub struct OpcodeEntry816 {
    pub mnemonic: &'static str,
    pub width: OperandWidth,
    pub flags: InstrFlags,
    pub base_cycles: u8,
}

impl OpcodeEntry816 {
    const fn new(
        mnemonic: &'static str,
        width: OperandWidth,
        flags: InstrFlags,
        base_cycles: u8,
    ) -> Self {
        Self {
            mnemonic,
            width,
            flags,
            base_cycles,
        }
    }

    const fn implied(mnemonic: &'static str, cycles: u8) -> Self {
        Self::new(
            mnemonic,
            OperandWidth::Fixed(AddrMode816::Implied),
            InstrFlags::NONE,
            cycles,
        )
    }

    const fn imm_m(mnemonic: &'static str, cycles: u8) -> Self {
        Self::new(mnemonic, OperandWidth::AccFlag, InstrFlags::NONE, cycles)
    }

    const fn imm_x(mnemonic: &'static str, cycles: u8) -> Self {
        Self::new(mnemonic, OperandWidth::IdxFlag, InstrFlags::NONE, cycles)
    }
}

// ── 65816 opcode table ────────────────────────────────────────────────────────

/// Full 65816 opcode table.
///
/// Returns `None` for truly undefined opcodes (none in the 65816; all 256
/// opcodes are defined, though some are NOP-like).
#[must_use]
pub fn opcode_table_65816(b: u8) -> Option<OpcodeEntry816> {
    match b >> 5 {
        0 => opcode_table_65816_p1(b),
        1 => opcode_table_65816_p2(b),
        2 => opcode_table_65816_p3(b),
        3 => opcode_table_65816_p4(b),
        4 => opcode_table_65816_p5(b),
        5 => opcode_table_65816_p6(b),
        6 => opcode_table_65816_p7(b),
        _ => opcode_table_65816_p8(b),
    }
}

fn opcode_table_65816_p1(b: u8) -> Option<OpcodeEntry816> {
    use AddrMode816 as M;
    use InstrFlags as F;
    use OperandWidth as W;
    Some(match u16::from(b) {
        // ── ASL ──────────────────────────────────────────────────────────────
        0x0A => OpcodeEntry816::new("ASL", W::Fixed(M::Accumulator), F::NONE, 2),
        0x06 => OpcodeEntry816::new(
            "ASL",
            W::Fixed(M::DirectPage),
            F::READ_MEM | F::WRITE_MEM,
            5,
        ),
        0x16 => OpcodeEntry816::new(
            "ASL",
            W::Fixed(M::DirectPageX),
            F::READ_MEM | F::WRITE_MEM,
            6,
        ),
        0x0E => OpcodeEntry816::new(
            "ASL",
            W::Fixed(M::Absolute16),
            F::READ_MEM | F::WRITE_MEM,
            6,
        ),
        0x1E => OpcodeEntry816::new(
            "ASL",
            W::Fixed(M::Absolute16X),
            F::READ_MEM | F::WRITE_MEM,
            7,
        ),
        0x10 => OpcodeEntry816::new(
            "BPL",
            W::Fixed(M::Base(AddrMode::Relative)),
            F::BRANCH | F::CONDITIONAL,
            2,
        ),
        // ── BRK / COP ────────────────────────────────────────────────────────
        0x00 => OpcodeEntry816::new("BRK", W::Fixed(M::Immediate8), F::BRANCH, 7),
        0x02 => OpcodeEntry816::new("COP", W::Fixed(M::Immediate8), F::BRANCH, 7),
        // ── CLC/CLD/CLI/CLV/SEC/SED/SEI ──────────────────────────────────────
        0x18 => OpcodeEntry816::implied("CLC", 2),
        0x1A => OpcodeEntry816::new("INC", W::Fixed(M::Accumulator), F::NONE, 2),
        // ── ORA ──────────────────────────────────────────────────────────────
        0x09 => OpcodeEntry816::imm_m("ORA", 2),
        0x05 => OpcodeEntry816::new("ORA", W::Fixed(M::DirectPage), F::READ_MEM, 3),
        0x15 => OpcodeEntry816::new("ORA", W::Fixed(M::DirectPageX), F::READ_MEM, 4),
        0x12 => OpcodeEntry816::new("ORA", W::Fixed(M::DirectPageIndirect), F::READ_MEM, 5),
        0x01 => OpcodeEntry816::new("ORA", W::Fixed(M::DirectPageIndirectX), F::READ_MEM, 6),
        0x11 => OpcodeEntry816::new("ORA", W::Fixed(M::DirectPageIndirectY), F::READ_MEM, 5),
        0x07 => OpcodeEntry816::new("ORA", W::Fixed(M::DirectPageIndirectLong), F::READ_MEM, 6),
        0x17 => OpcodeEntry816::new("ORA", W::Fixed(M::DirectPageIndirectLongY), F::READ_MEM, 6),
        0x0D => OpcodeEntry816::new("ORA", W::Fixed(M::Absolute16), F::READ_MEM, 4),
        0x1D => OpcodeEntry816::new("ORA", W::Fixed(M::Absolute16X), F::READ_MEM, 4),
        0x19 => OpcodeEntry816::new("ORA", W::Fixed(M::Absolute16Y), F::READ_MEM, 4),
        0x0F => OpcodeEntry816::new("ORA", W::Fixed(M::AbsoluteLong), F::READ_MEM, 5),
        0x1F => OpcodeEntry816::new("ORA", W::Fixed(M::AbsoluteLongX), F::READ_MEM, 5),
        0x03 => OpcodeEntry816::new("ORA", W::Fixed(M::StackRelative), F::READ_MEM, 4),
        0x13 => OpcodeEntry816::new("ORA", W::Fixed(M::StackRelativeIndirectY), F::READ_MEM, 7),
        0x08 => OpcodeEntry816::implied("PHP", 3),
        0x0B => OpcodeEntry816::implied("PHD", 4),
        0x1B => OpcodeEntry816::implied("TCS", 2),
        // ── TRB / TSB ────────────────────────────────────────────────────────
        0x14 => OpcodeEntry816::new(
            "TRB",
            W::Fixed(M::DirectPage),
            F::READ_MEM | F::WRITE_MEM,
            5,
        ),
        0x1C => OpcodeEntry816::new(
            "TRB",
            W::Fixed(M::Absolute16),
            F::READ_MEM | F::WRITE_MEM,
            6,
        ),
        0x04 => OpcodeEntry816::new(
            "TSB",
            W::Fixed(M::DirectPage),
            F::READ_MEM | F::WRITE_MEM,
            5,
        ),
        0x0C => OpcodeEntry816::new(
            "TSB",
            W::Fixed(M::Absolute16),
            F::READ_MEM | F::WRITE_MEM,
            6,
        ),
        _ => return None,
    })
}

fn opcode_table_65816_p2(b: u8) -> Option<OpcodeEntry816> {
    use AddrMode816 as M;
    use InstrFlags as F;
    use OperandWidth as W;
    Some(match u16::from(b) {
        // ── AND ──────────────────────────────────────────────────────────────
        0x29 => OpcodeEntry816::imm_m("AND", 2),
        0x25 => OpcodeEntry816::new("AND", W::Fixed(M::DirectPage), F::READ_MEM, 3),
        0x35 => OpcodeEntry816::new("AND", W::Fixed(M::DirectPageX), F::READ_MEM, 4),
        0x32 => OpcodeEntry816::new("AND", W::Fixed(M::DirectPageIndirect), F::READ_MEM, 5),
        0x21 => OpcodeEntry816::new("AND", W::Fixed(M::DirectPageIndirectX), F::READ_MEM, 6),
        0x31 => OpcodeEntry816::new("AND", W::Fixed(M::DirectPageIndirectY), F::READ_MEM, 5),
        0x27 => OpcodeEntry816::new("AND", W::Fixed(M::DirectPageIndirectLong), F::READ_MEM, 6),
        0x37 => OpcodeEntry816::new("AND", W::Fixed(M::DirectPageIndirectLongY), F::READ_MEM, 6),
        0x2D => OpcodeEntry816::new("AND", W::Fixed(M::Absolute16), F::READ_MEM, 4),
        0x3D => OpcodeEntry816::new("AND", W::Fixed(M::Absolute16X), F::READ_MEM, 4),
        0x39 => OpcodeEntry816::new("AND", W::Fixed(M::Absolute16Y), F::READ_MEM, 4),
        0x2F => OpcodeEntry816::new("AND", W::Fixed(M::AbsoluteLong), F::READ_MEM, 5),
        0x3F => OpcodeEntry816::new("AND", W::Fixed(M::AbsoluteLongX), F::READ_MEM, 5),
        0x23 => OpcodeEntry816::new("AND", W::Fixed(M::StackRelative), F::READ_MEM, 4),
        0x33 => OpcodeEntry816::new("AND", W::Fixed(M::StackRelativeIndirectY), F::READ_MEM, 7),
        0x30 => OpcodeEntry816::new(
            "BMI",
            W::Fixed(M::Base(AddrMode::Relative)),
            F::BRANCH | F::CONDITIONAL,
            2,
        ),
        // ── BIT ──────────────────────────────────────────────────────────────
        0x24 => OpcodeEntry816::new("BIT", W::Fixed(M::DirectPage), F::READ_MEM, 3),
        0x34 => OpcodeEntry816::new("BIT", W::Fixed(M::DirectPageX), F::READ_MEM, 4),
        0x2C => OpcodeEntry816::new("BIT", W::Fixed(M::Absolute16), F::READ_MEM, 4),
        0x3C => OpcodeEntry816::new("BIT", W::Fixed(M::Absolute16X), F::READ_MEM, 4),
        0x38 => OpcodeEntry816::implied("SEC", 2),
        0x3A => OpcodeEntry816::new("DEC", W::Fixed(M::Accumulator), F::NONE, 2),
        // ── JSR / JSL ────────────────────────────────────────────────────────
        0x20 => OpcodeEntry816::new("JSR", W::Fixed(M::Absolute16), F::CALL, 6),
        0x22 => OpcodeEntry816::new("JSL", W::Fixed(M::AbsoluteLong), F::CALL, 8),
        0x28 => OpcodeEntry816::implied("PLP", 4),
        0x2B => OpcodeEntry816::implied("PLD", 5),
        // ── ROL / ROR ────────────────────────────────────────────────────────
        0x2A => OpcodeEntry816::new("ROL", W::Fixed(M::Accumulator), F::NONE, 2),
        0x26 => OpcodeEntry816::new(
            "ROL",
            W::Fixed(M::DirectPage),
            F::READ_MEM | F::WRITE_MEM,
            5,
        ),
        0x36 => OpcodeEntry816::new(
            "ROL",
            W::Fixed(M::DirectPageX),
            F::READ_MEM | F::WRITE_MEM,
            6,
        ),
        0x2E => OpcodeEntry816::new(
            "ROL",
            W::Fixed(M::Absolute16),
            F::READ_MEM | F::WRITE_MEM,
            6,
        ),
        0x3E => OpcodeEntry816::new(
            "ROL",
            W::Fixed(M::Absolute16X),
            F::READ_MEM | F::WRITE_MEM,
            7,
        ),
        0x3B => OpcodeEntry816::implied("TSC", 2),
        _ => return None,
    })
}

fn opcode_table_65816_p3(b: u8) -> Option<OpcodeEntry816> {
    use AddrMode816 as M;
    use InstrFlags as F;
    use OperandWidth as W;
    Some(match u16::from(b) {
        0x50 => OpcodeEntry816::new(
            "BVC",
            W::Fixed(M::Base(AddrMode::Relative)),
            F::BRANCH | F::CONDITIONAL,
            2,
        ),
        0x58 => OpcodeEntry816::implied("CLI", 2),
        // ── EOR ──────────────────────────────────────────────────────────────
        0x49 => OpcodeEntry816::imm_m("EOR", 2),
        0x45 => OpcodeEntry816::new("EOR", W::Fixed(M::DirectPage), F::READ_MEM, 3),
        0x55 => OpcodeEntry816::new("EOR", W::Fixed(M::DirectPageX), F::READ_MEM, 4),
        0x52 => OpcodeEntry816::new("EOR", W::Fixed(M::DirectPageIndirect), F::READ_MEM, 5),
        0x41 => OpcodeEntry816::new("EOR", W::Fixed(M::DirectPageIndirectX), F::READ_MEM, 6),
        0x51 => OpcodeEntry816::new("EOR", W::Fixed(M::DirectPageIndirectY), F::READ_MEM, 5),
        0x47 => OpcodeEntry816::new("EOR", W::Fixed(M::DirectPageIndirectLong), F::READ_MEM, 6),
        0x57 => OpcodeEntry816::new("EOR", W::Fixed(M::DirectPageIndirectLongY), F::READ_MEM, 6),
        0x4D => OpcodeEntry816::new("EOR", W::Fixed(M::Absolute16), F::READ_MEM, 4),
        0x5D => OpcodeEntry816::new("EOR", W::Fixed(M::Absolute16X), F::READ_MEM, 4),
        0x59 => OpcodeEntry816::new("EOR", W::Fixed(M::Absolute16Y), F::READ_MEM, 4),
        0x4F => OpcodeEntry816::new("EOR", W::Fixed(M::AbsoluteLong), F::READ_MEM, 5),
        0x5F => OpcodeEntry816::new("EOR", W::Fixed(M::AbsoluteLongX), F::READ_MEM, 5),
        0x43 => OpcodeEntry816::new("EOR", W::Fixed(M::StackRelative), F::READ_MEM, 4),
        0x53 => OpcodeEntry816::new("EOR", W::Fixed(M::StackRelativeIndirectY), F::READ_MEM, 7),
        // ── JMP ──────────────────────────────────────────────────────────────
        0x4C => OpcodeEntry816::new("JMP", W::Fixed(M::Absolute16), F::BRANCH, 3),
        // 65816 long jumps
        0x5C => OpcodeEntry816::new("JML", W::Fixed(M::AbsoluteLong), F::BRANCH, 4),
        // ── LSR ──────────────────────────────────────────────────────────────
        0x4A => OpcodeEntry816::new("LSR", W::Fixed(M::Accumulator), F::NONE, 2),
        0x46 => OpcodeEntry816::new(
            "LSR",
            W::Fixed(M::DirectPage),
            F::READ_MEM | F::WRITE_MEM,
            5,
        ),
        0x56 => OpcodeEntry816::new(
            "LSR",
            W::Fixed(M::DirectPageX),
            F::READ_MEM | F::WRITE_MEM,
            6,
        ),
        0x4E => OpcodeEntry816::new(
            "LSR",
            W::Fixed(M::Absolute16),
            F::READ_MEM | F::WRITE_MEM,
            6,
        ),
        0x5E => OpcodeEntry816::new(
            "LSR",
            W::Fixed(M::Absolute16X),
            F::READ_MEM | F::WRITE_MEM,
            7,
        ),
        // ── Block moves ───────────────────────────────────────────────────────
        0x54 => OpcodeEntry816::new("MVN", W::Fixed(M::BlockMove), F::NONE, 7),
        0x44 => OpcodeEntry816::new("MVP", W::Fixed(M::BlockMove), F::NONE, 7),
        // ── Stack push/pull ───────────────────────────────────────────────────
        0x48 => OpcodeEntry816::implied("PHA", 3),
        0x5A => OpcodeEntry816::implied("PHY", 3),
        0x4B => OpcodeEntry816::implied("PHK", 3),
        // ── Returns ───────────────────────────────────────────────────────────
        0x40 => OpcodeEntry816::implied("RTI", 6),
        // 65816 new transfers
        0x5B => OpcodeEntry816::implied("TCD", 2),
        // No undefined opcodes on the 65816; remaining slots are WDM (reserved).
        0x42 => OpcodeEntry816::new("WDM", W::Fixed(M::Immediate8), F::NONE, 2),
        _ => return None,
    })
}

fn opcode_table_65816_p4(b: u8) -> Option<OpcodeEntry816> {
    use AddrMode816 as M;
    use InstrFlags as F;
    use OperandWidth as W;
    Some(match u16::from(b) {
        // ── ADC ──────────────────────────────────────────────────────────────
        0x69 => OpcodeEntry816::imm_m("ADC", 2),
        0x65 => OpcodeEntry816::new("ADC", W::Fixed(M::DirectPage), F::READ_MEM, 3),
        0x75 => OpcodeEntry816::new("ADC", W::Fixed(M::DirectPageX), F::READ_MEM, 4),
        0x72 => OpcodeEntry816::new("ADC", W::Fixed(M::DirectPageIndirect), F::READ_MEM, 5),
        0x61 => OpcodeEntry816::new("ADC", W::Fixed(M::DirectPageIndirectX), F::READ_MEM, 6),
        0x71 => OpcodeEntry816::new("ADC", W::Fixed(M::DirectPageIndirectY), F::READ_MEM, 5),
        0x67 => OpcodeEntry816::new("ADC", W::Fixed(M::DirectPageIndirectLong), F::READ_MEM, 6),
        0x77 => OpcodeEntry816::new("ADC", W::Fixed(M::DirectPageIndirectLongY), F::READ_MEM, 6),
        0x6D => OpcodeEntry816::new("ADC", W::Fixed(M::Absolute16), F::READ_MEM, 4),
        0x7D => OpcodeEntry816::new("ADC", W::Fixed(M::Absolute16X), F::READ_MEM, 4),
        0x79 => OpcodeEntry816::new("ADC", W::Fixed(M::Absolute16Y), F::READ_MEM, 4),
        0x6F => OpcodeEntry816::new("ADC", W::Fixed(M::AbsoluteLong), F::READ_MEM, 5),
        0x7F => OpcodeEntry816::new("ADC", W::Fixed(M::AbsoluteLongX), F::READ_MEM, 5),
        0x63 => OpcodeEntry816::new("ADC", W::Fixed(M::StackRelative), F::READ_MEM, 4),
        0x73 => OpcodeEntry816::new("ADC", W::Fixed(M::StackRelativeIndirectY), F::READ_MEM, 7),
        0x70 => OpcodeEntry816::new(
            "BVS",
            W::Fixed(M::Base(AddrMode::Relative)),
            F::BRANCH | F::CONDITIONAL,
            2,
        ),
        0x78 => OpcodeEntry816::implied("SEI", 2),
        0x6C => OpcodeEntry816::new(
            "JMP",
            W::Fixed(M::AbsoluteIndirect),
            F::BRANCH | F::INDIRECT,
            5,
        ),
        0x7C => OpcodeEntry816::new(
            "JMP",
            W::Fixed(M::AbsoluteIndirectX),
            F::BRANCH | F::INDIRECT,
            6,
        ),
        0x68 => OpcodeEntry816::implied("PLA", 4),
        0x7A => OpcodeEntry816::implied("PLY", 4),
        0x62 => OpcodeEntry816::new("PER", W::Fixed(M::RelativeLong), F::WRITE_MEM, 6),
        0x6A => OpcodeEntry816::new("ROR", W::Fixed(M::Accumulator), F::NONE, 2),
        0x66 => OpcodeEntry816::new(
            "ROR",
            W::Fixed(M::DirectPage),
            F::READ_MEM | F::WRITE_MEM,
            5,
        ),
        0x76 => OpcodeEntry816::new(
            "ROR",
            W::Fixed(M::DirectPageX),
            F::READ_MEM | F::WRITE_MEM,
            6,
        ),
        0x6E => OpcodeEntry816::new(
            "ROR",
            W::Fixed(M::Absolute16),
            F::READ_MEM | F::WRITE_MEM,
            6,
        ),
        0x7E => OpcodeEntry816::new(
            "ROR",
            W::Fixed(M::Absolute16X),
            F::READ_MEM | F::WRITE_MEM,
            7,
        ),
        0x60 => OpcodeEntry816::implied("RTS", 6),
        0x6B => OpcodeEntry816::implied("RTL", 6),
        0x64 => OpcodeEntry816::new("STZ", W::Fixed(M::DirectPage), F::WRITE_MEM, 3),
        0x74 => OpcodeEntry816::new("STZ", W::Fixed(M::DirectPageX), F::WRITE_MEM, 4),
        0x7B => OpcodeEntry816::implied("TDC", 2),
        _ => return None,
    })
}

fn opcode_table_65816_p5(b: u8) -> Option<OpcodeEntry816> {
    use AddrMode816 as M;
    use InstrFlags as F;
    use OperandWidth as W;
    Some(match u16::from(b) {
        // ── Branches ─────────────────────────────────────────────────────────
        0x90 => OpcodeEntry816::new(
            "BCC",
            W::Fixed(M::Base(AddrMode::Relative)),
            F::BRANCH | F::CONDITIONAL,
            2,
        ),
        0x80 => OpcodeEntry816::new("BRA", W::Fixed(M::Base(AddrMode::Relative)), F::BRANCH, 2),
        // 65816 long relative branch
        0x82 => OpcodeEntry816::new("BRL", W::Fixed(M::RelativeLong), F::BRANCH, 4),
        0x89 => OpcodeEntry816::imm_m("BIT", 2),
        0x88 => OpcodeEntry816::implied("DEY", 2),
        // 65816 new push/pull
        0x8B => OpcodeEntry816::implied("PHB", 3),
        // ── STA ──────────────────────────────────────────────────────────────
        0x85 => OpcodeEntry816::new("STA", W::Fixed(M::DirectPage), F::WRITE_MEM, 3),
        0x95 => OpcodeEntry816::new("STA", W::Fixed(M::DirectPageX), F::WRITE_MEM, 4),
        0x92 => OpcodeEntry816::new("STA", W::Fixed(M::DirectPageIndirect), F::WRITE_MEM, 5),
        0x81 => OpcodeEntry816::new("STA", W::Fixed(M::DirectPageIndirectX), F::WRITE_MEM, 6),
        0x91 => OpcodeEntry816::new("STA", W::Fixed(M::DirectPageIndirectY), F::WRITE_MEM, 6),
        0x87 => OpcodeEntry816::new("STA", W::Fixed(M::DirectPageIndirectLong), F::WRITE_MEM, 6),
        0x97 => OpcodeEntry816::new("STA", W::Fixed(M::DirectPageIndirectLongY), F::WRITE_MEM, 6),
        0x8D => OpcodeEntry816::new("STA", W::Fixed(M::Absolute16), F::WRITE_MEM, 4),
        0x9D => OpcodeEntry816::new("STA", W::Fixed(M::Absolute16X), F::WRITE_MEM, 5),
        0x99 => OpcodeEntry816::new("STA", W::Fixed(M::Absolute16Y), F::WRITE_MEM, 5),
        0x8F => OpcodeEntry816::new("STA", W::Fixed(M::AbsoluteLong), F::WRITE_MEM, 5),
        0x9F => OpcodeEntry816::new("STA", W::Fixed(M::AbsoluteLongX), F::WRITE_MEM, 5),
        0x83 => OpcodeEntry816::new("STA", W::Fixed(M::StackRelative), F::WRITE_MEM, 4),
        0x93 => OpcodeEntry816::new("STA", W::Fixed(M::StackRelativeIndirectY), F::WRITE_MEM, 7),
        // ── STX / STY / STZ ──────────────────────────────────────────────────
        0x86 => OpcodeEntry816::new("STX", W::Fixed(M::DirectPage), F::WRITE_MEM, 3),
        0x96 => OpcodeEntry816::new("STX", W::Fixed(M::DirectPageY), F::WRITE_MEM, 4),
        0x8E => OpcodeEntry816::new("STX", W::Fixed(M::Absolute16), F::WRITE_MEM, 4),
        0x84 => OpcodeEntry816::new("STY", W::Fixed(M::DirectPage), F::WRITE_MEM, 3),
        0x94 => OpcodeEntry816::new("STY", W::Fixed(M::DirectPageX), F::WRITE_MEM, 4),
        0x8C => OpcodeEntry816::new("STY", W::Fixed(M::Absolute16), F::WRITE_MEM, 4),
        0x9C => OpcodeEntry816::new("STZ", W::Fixed(M::Absolute16), F::WRITE_MEM, 4),
        0x9E => OpcodeEntry816::new("STZ", W::Fixed(M::Absolute16X), F::WRITE_MEM, 5),
        0x8A => OpcodeEntry816::implied("TXA", 2),
        0x9A => OpcodeEntry816::implied("TXS", 2),
        0x98 => OpcodeEntry816::implied("TYA", 2),
        0x9B => OpcodeEntry816::implied("TXY", 2),
        _ => return None,
    })
}

fn opcode_table_65816_p6(b: u8) -> Option<OpcodeEntry816> {
    use AddrMode816 as M;
    use InstrFlags as F;
    use OperandWidth as W;
    Some(match u16::from(b) {
        0xB0 => OpcodeEntry816::new(
            "BCS",
            W::Fixed(M::Base(AddrMode::Relative)),
            F::BRANCH | F::CONDITIONAL,
            2,
        ),
        0xB8 => OpcodeEntry816::implied("CLV", 2),
        // ── LDA ──────────────────────────────────────────────────────────────
        0xA9 => OpcodeEntry816::imm_m("LDA", 2),
        0xA5 => OpcodeEntry816::new("LDA", W::Fixed(M::DirectPage), F::READ_MEM, 3),
        0xB5 => OpcodeEntry816::new("LDA", W::Fixed(M::DirectPageX), F::READ_MEM, 4),
        0xB2 => OpcodeEntry816::new("LDA", W::Fixed(M::DirectPageIndirect), F::READ_MEM, 5),
        0xA1 => OpcodeEntry816::new("LDA", W::Fixed(M::DirectPageIndirectX), F::READ_MEM, 6),
        0xB1 => OpcodeEntry816::new("LDA", W::Fixed(M::DirectPageIndirectY), F::READ_MEM, 5),
        0xA7 => OpcodeEntry816::new("LDA", W::Fixed(M::DirectPageIndirectLong), F::READ_MEM, 6),
        0xB7 => OpcodeEntry816::new("LDA", W::Fixed(M::DirectPageIndirectLongY), F::READ_MEM, 6),
        0xAD => OpcodeEntry816::new("LDA", W::Fixed(M::Absolute16), F::READ_MEM, 4),
        0xBD => OpcodeEntry816::new("LDA", W::Fixed(M::Absolute16X), F::READ_MEM, 4),
        0xB9 => OpcodeEntry816::new("LDA", W::Fixed(M::Absolute16Y), F::READ_MEM, 4),
        0xAF => OpcodeEntry816::new("LDA", W::Fixed(M::AbsoluteLong), F::READ_MEM, 5),
        0xBF => OpcodeEntry816::new("LDA", W::Fixed(M::AbsoluteLongX), F::READ_MEM, 5),
        0xA3 => OpcodeEntry816::new("LDA", W::Fixed(M::StackRelative), F::READ_MEM, 4),
        0xB3 => OpcodeEntry816::new("LDA", W::Fixed(M::StackRelativeIndirectY), F::READ_MEM, 7),
        // ── LDX / LDY ────────────────────────────────────────────────────────
        0xA2 => OpcodeEntry816::imm_x("LDX", 2),
        0xA6 => OpcodeEntry816::new("LDX", W::Fixed(M::DirectPage), F::READ_MEM, 3),
        0xB6 => OpcodeEntry816::new("LDX", W::Fixed(M::DirectPageY), F::READ_MEM, 4),
        0xAE => OpcodeEntry816::new("LDX", W::Fixed(M::Absolute16), F::READ_MEM, 4),
        0xBE => OpcodeEntry816::new("LDX", W::Fixed(M::Absolute16Y), F::READ_MEM, 4),
        0xA0 => OpcodeEntry816::imm_x("LDY", 2),
        0xA4 => OpcodeEntry816::new("LDY", W::Fixed(M::DirectPage), F::READ_MEM, 3),
        0xB4 => OpcodeEntry816::new("LDY", W::Fixed(M::DirectPageX), F::READ_MEM, 4),
        0xAC => OpcodeEntry816::new("LDY", W::Fixed(M::Absolute16), F::READ_MEM, 4),
        0xBC => OpcodeEntry816::new("LDY", W::Fixed(M::Absolute16X), F::READ_MEM, 4),
        0xAB => OpcodeEntry816::implied("PLB", 4),
        // ── Transfers ────────────────────────────────────────────────────────
        0xAA => OpcodeEntry816::implied("TAX", 2),
        0xA8 => OpcodeEntry816::implied("TAY", 2),
        0xBA => OpcodeEntry816::implied("TSX", 2),
        0xBB => OpcodeEntry816::implied("TYX", 2),
        _ => return None,
    })
}

fn opcode_table_65816_p7(b: u8) -> Option<OpcodeEntry816> {
    use AddrMode816 as M;
    use InstrFlags as F;
    use OperandWidth as W;
    Some(match u16::from(b) {
        0xD0 => OpcodeEntry816::new(
            "BNE",
            W::Fixed(M::Base(AddrMode::Relative)),
            F::BRANCH | F::CONDITIONAL,
            2,
        ),
        0xD8 => OpcodeEntry816::implied("CLD", 2),
        // ── REP / SEP – change P flags ────────────────────────────────────────
        0xC2 => OpcodeEntry816::new("REP", W::Fixed(M::Immediate8), F::NONE, 3),
        // ── CMP ──────────────────────────────────────────────────────────────
        0xC9 => OpcodeEntry816::imm_m("CMP", 2),
        0xC5 => OpcodeEntry816::new("CMP", W::Fixed(M::DirectPage), F::READ_MEM, 3),
        0xD5 => OpcodeEntry816::new("CMP", W::Fixed(M::DirectPageX), F::READ_MEM, 4),
        0xD2 => OpcodeEntry816::new("CMP", W::Fixed(M::DirectPageIndirect), F::READ_MEM, 5),
        0xC1 => OpcodeEntry816::new("CMP", W::Fixed(M::DirectPageIndirectX), F::READ_MEM, 6),
        0xD1 => OpcodeEntry816::new("CMP", W::Fixed(M::DirectPageIndirectY), F::READ_MEM, 5),
        0xC7 => OpcodeEntry816::new("CMP", W::Fixed(M::DirectPageIndirectLong), F::READ_MEM, 6),
        0xD7 => OpcodeEntry816::new("CMP", W::Fixed(M::DirectPageIndirectLongY), F::READ_MEM, 6),
        0xCD => OpcodeEntry816::new("CMP", W::Fixed(M::Absolute16), F::READ_MEM, 4),
        0xDD => OpcodeEntry816::new("CMP", W::Fixed(M::Absolute16X), F::READ_MEM, 4),
        0xD9 => OpcodeEntry816::new("CMP", W::Fixed(M::Absolute16Y), F::READ_MEM, 4),
        0xCF => OpcodeEntry816::new("CMP", W::Fixed(M::AbsoluteLong), F::READ_MEM, 5),
        0xDF => OpcodeEntry816::new("CMP", W::Fixed(M::AbsoluteLongX), F::READ_MEM, 5),
        0xC3 => OpcodeEntry816::new("CMP", W::Fixed(M::StackRelative), F::READ_MEM, 4),
        0xD3 => OpcodeEntry816::new("CMP", W::Fixed(M::StackRelativeIndirectY), F::READ_MEM, 7),
        0xC0 => OpcodeEntry816::imm_x("CPY", 2),
        0xC4 => OpcodeEntry816::new("CPY", W::Fixed(M::DirectPage), F::READ_MEM, 3),
        0xCC => OpcodeEntry816::new("CPY", W::Fixed(M::Absolute16), F::READ_MEM, 4),
        // ── DEC ──────────────────────────────────────────────────────────────
        0xC6 => OpcodeEntry816::new(
            "DEC",
            W::Fixed(M::DirectPage),
            F::READ_MEM | F::WRITE_MEM,
            5,
        ),
        0xD6 => OpcodeEntry816::new(
            "DEC",
            W::Fixed(M::DirectPageX),
            F::READ_MEM | F::WRITE_MEM,
            6,
        ),
        0xCE => OpcodeEntry816::new(
            "DEC",
            W::Fixed(M::Absolute16),
            F::READ_MEM | F::WRITE_MEM,
            6,
        ),
        0xDE => OpcodeEntry816::new(
            "DEC",
            W::Fixed(M::Absolute16X),
            F::READ_MEM | F::WRITE_MEM,
            7,
        ),
        0xCA => OpcodeEntry816::implied("DEX", 2),
        0xC8 => OpcodeEntry816::implied("INY", 2),
        0xDC => OpcodeEntry816::new(
            "JML",
            W::Fixed(M::AbsoluteIndirectLong),
            F::BRANCH | F::INDIRECT,
            6,
        ),
        0xDA => OpcodeEntry816::implied("PHX", 3),
        0xD4 => OpcodeEntry816::new(
            "PEI",
            W::Fixed(M::DirectPage),
            F::READ_MEM | F::WRITE_MEM,
            6,
        ),
        // ── WAI / STP ────────────────────────────────────────────────────────
        0xCB => OpcodeEntry816::implied("WAI", 3),
        0xDB => OpcodeEntry816::implied("STP", 3),
        _ => return None,
    })
}

fn opcode_table_65816_p8(b: u8) -> Option<OpcodeEntry816> {
    use AddrMode816 as M;
    use InstrFlags as F;
    use OperandWidth as W;
    Some(match u16::from(b) {
        0xF0 => OpcodeEntry816::new(
            "BEQ",
            W::Fixed(M::Base(AddrMode::Relative)),
            F::BRANCH | F::CONDITIONAL,
            2,
        ),
        0xF8 => OpcodeEntry816::implied("SED", 2),
        0xE2 => OpcodeEntry816::new("SEP", W::Fixed(M::Immediate8), F::NONE, 3),
        // ── CPX / CPY ────────────────────────────────────────────────────────
        0xE0 => OpcodeEntry816::imm_x("CPX", 2),
        0xE4 => OpcodeEntry816::new("CPX", W::Fixed(M::DirectPage), F::READ_MEM, 3),
        0xEC => OpcodeEntry816::new("CPX", W::Fixed(M::Absolute16), F::READ_MEM, 4),
        // ── INC ──────────────────────────────────────────────────────────────
        0xE6 => OpcodeEntry816::new(
            "INC",
            W::Fixed(M::DirectPage),
            F::READ_MEM | F::WRITE_MEM,
            5,
        ),
        0xF6 => OpcodeEntry816::new(
            "INC",
            W::Fixed(M::DirectPageX),
            F::READ_MEM | F::WRITE_MEM,
            6,
        ),
        0xEE => OpcodeEntry816::new(
            "INC",
            W::Fixed(M::Absolute16),
            F::READ_MEM | F::WRITE_MEM,
            6,
        ),
        0xFE => OpcodeEntry816::new(
            "INC",
            W::Fixed(M::Absolute16X),
            F::READ_MEM | F::WRITE_MEM,
            7,
        ),
        0xE8 => OpcodeEntry816::implied("INX", 2),
        0xFC => OpcodeEntry816::new(
            "JSR",
            W::Fixed(M::AbsoluteIndirectX),
            F::CALL | F::INDIRECT,
            8,
        ),
        // ── NOP ──────────────────────────────────────────────────────────────
        0xEA => OpcodeEntry816::implied("NOP", 2),
        0xFA => OpcodeEntry816::implied("PLX", 4),
        // ── PEA / PEI / PER ──────────────────────────────────────────────────
        0xF4 => OpcodeEntry816::new("PEA", W::Fixed(M::Absolute16), F::WRITE_MEM, 5),
        // ── SBC ──────────────────────────────────────────────────────────────
        0xE9 => OpcodeEntry816::imm_m("SBC", 2),
        0xE5 => OpcodeEntry816::new("SBC", W::Fixed(M::DirectPage), F::READ_MEM, 3),
        0xF5 => OpcodeEntry816::new("SBC", W::Fixed(M::DirectPageX), F::READ_MEM, 4),
        0xF2 => OpcodeEntry816::new("SBC", W::Fixed(M::DirectPageIndirect), F::READ_MEM, 5),
        0xE1 => OpcodeEntry816::new("SBC", W::Fixed(M::DirectPageIndirectX), F::READ_MEM, 6),
        0xF1 => OpcodeEntry816::new("SBC", W::Fixed(M::DirectPageIndirectY), F::READ_MEM, 5),
        0xE7 => OpcodeEntry816::new("SBC", W::Fixed(M::DirectPageIndirectLong), F::READ_MEM, 6),
        0xF7 => OpcodeEntry816::new("SBC", W::Fixed(M::DirectPageIndirectLongY), F::READ_MEM, 6),
        0xED => OpcodeEntry816::new("SBC", W::Fixed(M::Absolute16), F::READ_MEM, 4),
        0xFD => OpcodeEntry816::new("SBC", W::Fixed(M::Absolute16X), F::READ_MEM, 4),
        0xF9 => OpcodeEntry816::new("SBC", W::Fixed(M::Absolute16Y), F::READ_MEM, 4),
        0xEF => OpcodeEntry816::new("SBC", W::Fixed(M::AbsoluteLong), F::READ_MEM, 5),
        0xFF => OpcodeEntry816::new("SBC", W::Fixed(M::AbsoluteLongX), F::READ_MEM, 5),
        0xE3 => OpcodeEntry816::new("SBC", W::Fixed(M::StackRelative), F::READ_MEM, 4),
        0xF3 => OpcodeEntry816::new("SBC", W::Fixed(M::StackRelativeIndirectY), F::READ_MEM, 7),
        0xEB => OpcodeEntry816::implied("XBA", 2),
        0xFB => OpcodeEntry816::implied("XCE", 2),
        _ => return None,
    })
}

// ── Decoded65816 ─────────────────────────────────────────────────────────────

/// Result of decoding one 65816 instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded65816 {
    pub mnemonic: &'static str,
    pub mode: AddrMode816,
    pub flags: InstrFlags,
    pub base_cycles: u8,
    /// Total instruction size in bytes.
    pub size: usize,
    /// Raw instruction bytes (up to 4).
    pub bytes: [u8; 4],
}

// ── Decoder ───────────────────────────────────────────────────────────────────

/// Decode one 65816 instruction from `bytes` using `mode` to determine
/// whether accumulator/index immediate operands are 8 or 16 bits.
///
/// Returns `None` when `bytes` is empty, contains an unrecognised opcode,
/// or does not contain enough bytes for a complete instruction.
#[must_use]
pub fn decode_65816(bytes: &[u8], mode: Mode65816) -> Option<Decoded65816> {
    if bytes.is_empty() {
        return None;
    }
    let opcode = bytes[0];
    let entry = opcode_table_65816(opcode)?;

    // Resolve the concrete addressing mode (handles M/X-dependent widths).
    let addr_mode = resolve_mode(&entry, mode);
    let size = 1 + addr_mode.extra_bytes();

    if bytes.len() < size {
        return None;
    }

    let mut raw = [0u8; 4];
    let copy_len = size.min(4);
    raw[..copy_len].copy_from_slice(&bytes[..copy_len]);

    Some(Decoded65816 {
        mnemonic: entry.mnemonic,
        mode: addr_mode,
        flags: entry.flags,
        base_cycles: entry.base_cycles,
        size,
        bytes: raw,
    })
}

/// Resolve the concrete `AddrMode816` for an opcode entry given current M/X flags.
const fn resolve_mode(entry: &OpcodeEntry816, mode: Mode65816) -> AddrMode816 {
    match entry.width {
        OperandWidth::Fixed(m) => m,
        OperandWidth::AccFlag => {
            if mode.acc_width() == 2 {
                AddrMode816::Immediate16
            } else {
                AddrMode816::Immediate8
            }
        }
        OperandWidth::IdxFlag => {
            if mode.idx_width() == 2 {
                AddrMode816::Immediate16
            } else {
                AddrMode816::Immediate8
            }
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mode16() -> Mode65816 {
        Mode65816::native16()
    }
    fn mode8() -> Mode65816 {
        Mode65816::native8()
    }

    #[test]
    fn test_decode_lda_imm_8bit() {
        let d = decode_65816(&[0xA9, 0x42], mode8()).unwrap();
        assert_eq!(d.mnemonic, "LDA");
        assert_eq!(d.mode, AddrMode816::Immediate8);
        assert_eq!(d.size, 2);
    }

    #[test]
    fn test_decode_lda_imm_16bit() {
        let d = decode_65816(&[0xA9, 0x34, 0x12], mode16()).unwrap();
        assert_eq!(d.mnemonic, "LDA");
        assert_eq!(d.mode, AddrMode816::Immediate16);
        assert_eq!(d.size, 3);
    }

    #[test]
    fn test_decode_jsl() {
        let d = decode_65816(&[0x22, 0x00, 0x80, 0x01], mode8()).unwrap();
        assert_eq!(d.mnemonic, "JSL");
        assert_eq!(d.size, 4);
        assert!(d.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_decode_jml_absolute_long() {
        let d = decode_65816(&[0x5C, 0x00, 0x00, 0x01], mode8()).unwrap();
        assert_eq!(d.mnemonic, "JML");
        assert_eq!(d.mode, AddrMode816::AbsoluteLong);
    }

    #[test]
    fn test_decode_mvn_mvp() {
        let mvn = decode_65816(&[0x54, 0x01, 0x00], mode8()).unwrap();
        assert_eq!(mvn.mnemonic, "MVN");
        assert_eq!(mvn.mode, AddrMode816::BlockMove);
        assert_eq!(mvn.size, 3);

        let mvp = decode_65816(&[0x44, 0x00, 0x01], mode8()).unwrap();
        assert_eq!(mvp.mnemonic, "MVP");
    }

    #[test]
    fn test_decode_brl() {
        let d = decode_65816(&[0x82, 0x00, 0x10], mode8()).unwrap();
        assert_eq!(d.mnemonic, "BRL");
        assert_eq!(d.size, 3);
    }

    #[test]
    fn test_decode_new_transfers() {
        for (op, mn) in [
            (0x5Bu8, "TCD"),
            (0x1B, "TCS"),
            (0x7B, "TDC"),
            (0x3B, "TSC"),
            (0x9B, "TXY"),
            (0xBB, "TYX"),
            (0xEB, "XBA"),
            (0xFB, "XCE"),
        ] {
            let d = decode_65816(&[op], mode8()).unwrap();
            assert_eq!(d.mnemonic, mn, "opcode 0x{op:02X}");
            assert_eq!(d.size, 1);
        }
    }

    #[test]
    fn test_decode_new_push_pull() {
        for (op, mn) in [
            (0x8Bu8, "PHB"),
            (0x0B, "PHD"),
            (0x4B, "PHK"),
            (0xAB, "PLB"),
            (0x2B, "PLD"),
        ] {
            let d = decode_65816(&[op], mode8()).unwrap();
            assert_eq!(d.mnemonic, mn);
            assert_eq!(d.size, 1);
        }
    }

    #[test]
    fn test_decode_pea_pei_per() {
        let pea = decode_65816(&[0xF4, 0x00, 0x20], mode8()).unwrap();
        assert_eq!(pea.mnemonic, "PEA");
        assert_eq!(pea.size, 3);

        let pei = decode_65816(&[0xD4, 0x50], mode8()).unwrap();
        assert_eq!(pei.mnemonic, "PEI");
        assert_eq!(pei.size, 2);

        let per = decode_65816(&[0x62, 0x00, 0x10], mode8()).unwrap();
        assert_eq!(per.mnemonic, "PER");
        assert_eq!(per.size, 3);
    }

    #[test]
    fn test_decode_rtl() {
        let d = decode_65816(&[0x6B], mode8()).unwrap();
        assert_eq!(d.mnemonic, "RTL");
    }

    #[test]
    fn test_decode_rep_sep() {
        let rep = decode_65816(&[0xC2, 0x30], mode8()).unwrap();
        assert_eq!(rep.mnemonic, "REP");
        assert_eq!(rep.size, 2);

        let sep = decode_65816(&[0xE2, 0x20], mode8()).unwrap();
        assert_eq!(sep.mnemonic, "SEP");
    }

    #[test]
    fn test_mode_acc_width() {
        assert_eq!(mode16().acc_width(), 2);
        assert_eq!(mode8().acc_width(), 1);
        assert_eq!(Mode65816::emulation().acc_width(), 1);
    }

    #[test]
    fn test_mode_idx_width() {
        assert_eq!(mode16().idx_width(), 2);
        assert_eq!(mode8().idx_width(), 1);
    }

    #[test]
    fn test_truncated_returns_none() {
        // JSL needs 4 bytes
        assert!(decode_65816(&[0x22, 0x00, 0x80], mode8()).is_none());
    }
}
