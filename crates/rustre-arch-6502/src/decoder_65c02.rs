//! WDC 65C02 decoder extensions.
//!
//! This module provides the full decode table and decoder function for the
//! WDC 65C02, which extends the original NMOS 6502 with:
//!
//! * New single-byte opcodes: PHX, PHY, PLX, PLY, BRA, INC A, DEC A, WAI, STP.
//! * New two-byte opcodes: STZ (zero page, zero page X, absolute, absolute X),
//!   TRB (zero page, absolute), TSB (zero page, absolute).
//! * Sixteen bit-manipulation instructions: BBR0–BBR7, BBS0–BBS7,
//!   RMB0–RMB7, SMB0–SMB7.
//! * New addressing modes: zero-page indirect `(zp)`, absolute indexed
//!   indirect `(abs,X)`.
//! * Fixes for the 6502 indirect-JMP page-wrap bug (JMP ($xxFF) now reads
//!   across the page boundary correctly).
//!
//! The top-level entry point is [`decode_65c02`], which accepts a raw byte
//! slice and returns a [`Decoded65C02`] describing the instruction.

use crate::{AddrMode, CpuVariant, OpcodeEntry};
use rustre_core::arch::InstrFlags;

// ── Bit instruction helpers ───────────────────────────────────────────────────

/// Create one of the 65C02 zero-page bit-test-and-branch instructions (BBR/BBS).
///
/// These are 3-byte instructions: opcode, zero-page address, relative offset.
const fn bit_branch(mnemonic: &'static str) -> OpcodeEntry {
    OpcodeEntry {
        mnemonic,
        // The ZeroPage byte is consumed, then a Relative byte — we model this
        // as ZeroPageIndirect for the purposes of extra_bytes() but the real
        // instruction is 3 bytes.  We override size in Decoded65C02.
        mode: AddrMode::ZeroPage,
        flags: InstrFlags::BRANCH.union(InstrFlags::CONDITIONAL),
        cycles: 5,
        illegal: false,
        variant: CpuVariant::Cpu65C02,
    }
}

/// Create one of the 65C02 zero-page bit-set/clear instructions (RMB/SMB).
const fn bit_rmw(mnemonic: &'static str) -> OpcodeEntry {
    OpcodeEntry {
        mnemonic,
        mode: AddrMode::ZeroPage,
        flags: InstrFlags::READ_MEM.union(InstrFlags::WRITE_MEM),
        cycles: 5,
        illegal: false,
        variant: CpuVariant::Cpu65C02,
    }
}

// ── 65C02 opcode table ────────────────────────────────────────────────────────

/// Look up a 65C02 opcode entry.
///
/// Returns `None` only for the very small number of codes that are truly
/// undefined on the 65C02 (most slots formerly occupied by NMOS illegal
/// opcodes are redefined here or become single-cycle NOPs).
#[must_use]
pub fn opcode_table_65c02(b: u8) -> Option<OpcodeEntry> {
    match b {
        0x00..=0x5F => opcode_table_65c02_q1(b),
        0x60..=0xBF => opcode_table_65c02_q2(b),
        0xC0..=0xFF => opcode_table_65c02_q3(b),
    }
}

fn opcode_table_65c02_q1(b: u8) -> Option<OpcodeEntry> {
    use InstrFlags as F;
    Some(match b {
        // ── AND ──────────────────────────────────────────────────────────────
        0x29 => OpcodeEntry::base("AND", AddrMode::Immediate, F::NONE, 2),
        0x25 => OpcodeEntry::base("AND", AddrMode::ZeroPage, F::READ_MEM, 3),
        0x35 => OpcodeEntry::base("AND", AddrMode::ZeroPageX, F::READ_MEM, 4),
        0x2D => OpcodeEntry::base("AND", AddrMode::Absolute, F::READ_MEM, 4),
        0x3D => OpcodeEntry::base("AND", AddrMode::AbsoluteX, F::READ_MEM, 4),
        0x39 => OpcodeEntry::base("AND", AddrMode::AbsoluteY, F::READ_MEM, 4),
        0x21 => OpcodeEntry::base("AND", AddrMode::IndirectX, F::READ_MEM, 6),
        0x31 => OpcodeEntry::base("AND", AddrMode::IndirectY, F::READ_MEM, 5),
        0x32 => OpcodeEntry::c02("AND", AddrMode::ZeroPageIndirect, F::READ_MEM, 5),
        // ── ASL ──────────────────────────────────────────────────────────────
        0x0A => OpcodeEntry::base("ASL", AddrMode::Accumulator, F::NONE, 2),
        0x06 => OpcodeEntry::base("ASL", AddrMode::ZeroPage, F::READ_MEM | F::WRITE_MEM, 5),
        0x16 => OpcodeEntry::base("ASL", AddrMode::ZeroPageX, F::READ_MEM | F::WRITE_MEM, 6),
        0x0E => OpcodeEntry::base("ASL", AddrMode::Absolute, F::READ_MEM | F::WRITE_MEM, 6),
        0x1E => OpcodeEntry::base("ASL", AddrMode::AbsoluteX, F::READ_MEM | F::WRITE_MEM, 6),
        0x30 => OpcodeEntry::base("BMI", AddrMode::Relative, F::BRANCH | F::CONDITIONAL, 2),
        0x10 => OpcodeEntry::base("BPL", AddrMode::Relative, F::BRANCH | F::CONDITIONAL, 2),
        0x50 => OpcodeEntry::base("BVC", AddrMode::Relative, F::BRANCH | F::CONDITIONAL, 2),
        // ── BIT ──────────────────────────────────────────────────────────────
        0x24 => OpcodeEntry::base("BIT", AddrMode::ZeroPage, F::READ_MEM, 3),
        0x2C => OpcodeEntry::base("BIT", AddrMode::Absolute, F::READ_MEM, 4),
        0x34 => OpcodeEntry::c02("BIT", AddrMode::ZeroPageX, F::READ_MEM, 4),
        0x3C => OpcodeEntry::c02("BIT", AddrMode::AbsoluteX, F::READ_MEM, 4),
        // ── BRK ──────────────────────────────────────────────────────────────
        0x00 => OpcodeEntry::base("BRK", AddrMode::Implied, F::BRANCH, 7),
        // ── Flag clears ───────────────────────────────────────────────────────
        0x18 => OpcodeEntry::base("CLC", AddrMode::Implied, F::NONE, 2),
        0x58 => OpcodeEntry::base("CLI", AddrMode::Implied, F::NONE, 2),
        0x3A => OpcodeEntry::c02("DEC", AddrMode::Accumulator, F::NONE, 2),
        // ── EOR ──────────────────────────────────────────────────────────────
        0x49 => OpcodeEntry::base("EOR", AddrMode::Immediate, F::NONE, 2),
        0x45 => OpcodeEntry::base("EOR", AddrMode::ZeroPage, F::READ_MEM, 3),
        0x55 => OpcodeEntry::base("EOR", AddrMode::ZeroPageX, F::READ_MEM, 4),
        0x4D => OpcodeEntry::base("EOR", AddrMode::Absolute, F::READ_MEM, 4),
        0x5D => OpcodeEntry::base("EOR", AddrMode::AbsoluteX, F::READ_MEM, 4),
        0x59 => OpcodeEntry::base("EOR", AddrMode::AbsoluteY, F::READ_MEM, 4),
        0x41 => OpcodeEntry::base("EOR", AddrMode::IndirectX, F::READ_MEM, 6),
        0x51 => OpcodeEntry::base("EOR", AddrMode::IndirectY, F::READ_MEM, 5),
        0x52 => OpcodeEntry::c02("EOR", AddrMode::ZeroPageIndirect, F::READ_MEM, 5),
        0x1A => OpcodeEntry::c02("INC", AddrMode::Accumulator, F::NONE, 2),
        // ── JMP ──────────────────────────────────────────────────────────────
        0x4C => OpcodeEntry::base("JMP", AddrMode::Absolute, F::BRANCH, 3),
        // ── JSR ──────────────────────────────────────────────────────────────
        0x20 => OpcodeEntry::base("JSR", AddrMode::Absolute, F::CALL, 6),
        // ── LSR ──────────────────────────────────────────────────────────────
        0x4A => OpcodeEntry::base("LSR", AddrMode::Accumulator, F::NONE, 2),
        0x46 => OpcodeEntry::base("LSR", AddrMode::ZeroPage, F::READ_MEM | F::WRITE_MEM, 5),
        0x56 => OpcodeEntry::base("LSR", AddrMode::ZeroPageX, F::READ_MEM | F::WRITE_MEM, 6),
        0x4E => OpcodeEntry::base("LSR", AddrMode::Absolute, F::READ_MEM | F::WRITE_MEM, 6),
        0x5E => OpcodeEntry::base("LSR", AddrMode::AbsoluteX, F::READ_MEM | F::WRITE_MEM, 7),
        // ── ORA ──────────────────────────────────────────────────────────────
        0x09 => OpcodeEntry::base("ORA", AddrMode::Immediate, F::NONE, 2),
        0x05 => OpcodeEntry::base("ORA", AddrMode::ZeroPage, F::READ_MEM, 3),
        0x15 => OpcodeEntry::base("ORA", AddrMode::ZeroPageX, F::READ_MEM, 4),
        0x0D => OpcodeEntry::base("ORA", AddrMode::Absolute, F::READ_MEM, 4),
        0x1D => OpcodeEntry::base("ORA", AddrMode::AbsoluteX, F::READ_MEM, 4),
        0x19 => OpcodeEntry::base("ORA", AddrMode::AbsoluteY, F::READ_MEM, 4),
        0x01 => OpcodeEntry::base("ORA", AddrMode::IndirectX, F::READ_MEM, 6),
        0x11 => OpcodeEntry::base("ORA", AddrMode::IndirectY, F::READ_MEM, 5),
        0x12 => OpcodeEntry::c02("ORA", AddrMode::ZeroPageIndirect, F::READ_MEM, 5),
        // ── Stack push/pull ───────────────────────────────────────────────────
        0x48 => OpcodeEntry::base("PHA", AddrMode::Implied, F::WRITE_MEM, 3),
        0x08 => OpcodeEntry::base("PHP", AddrMode::Implied, F::WRITE_MEM, 3),
        0x28 => OpcodeEntry::base("PLP", AddrMode::Implied, F::READ_MEM, 4),
        0x5A => OpcodeEntry::c02("PHY", AddrMode::Implied, F::WRITE_MEM, 3),
        // ── ROL ──────────────────────────────────────────────────────────────
        0x2A => OpcodeEntry::base("ROL", AddrMode::Accumulator, F::NONE, 2),
        0x26 => OpcodeEntry::base("ROL", AddrMode::ZeroPage, F::READ_MEM | F::WRITE_MEM, 5),
        0x36 => OpcodeEntry::base("ROL", AddrMode::ZeroPageX, F::READ_MEM | F::WRITE_MEM, 6),
        0x2E => OpcodeEntry::base("ROL", AddrMode::Absolute, F::READ_MEM | F::WRITE_MEM, 6),
        0x3E => OpcodeEntry::base("ROL", AddrMode::AbsoluteX, F::READ_MEM | F::WRITE_MEM, 7),
        // ── Returns ───────────────────────────────────────────────────────────
        0x40 => OpcodeEntry::base("RTI", AddrMode::Implied, F::RET, 6),
        // ── Flag sets ─────────────────────────────────────────────────────────
        0x38 => OpcodeEntry::base("SEC", AddrMode::Implied, F::NONE, 2),
        // ── TRB / TSB (65C02 new) ─────────────────────────────────────────────
        0x14 => OpcodeEntry::c02("TRB", AddrMode::ZeroPage, F::READ_MEM | F::WRITE_MEM, 5),
        0x1C => OpcodeEntry::c02("TRB", AddrMode::Absolute, F::READ_MEM | F::WRITE_MEM, 6),
        0x04 => OpcodeEntry::c02("TSB", AddrMode::ZeroPage, F::READ_MEM | F::WRITE_MEM, 5),
        0x0C => OpcodeEntry::c02("TSB", AddrMode::Absolute, F::READ_MEM | F::WRITE_MEM, 6),
        // ── RMB0–RMB7 ────────────────────────────────────────────────────────
        0x07 => bit_rmw("RMB0"),
        0x17 => bit_rmw("RMB1"),
        0x27 => bit_rmw("RMB2"),
        0x37 => bit_rmw("RMB3"),
        0x47 => bit_rmw("RMB4"),
        0x57 => bit_rmw("RMB5"),
        // ── BBR0–BBR7 (3-byte: zp, rel) ──────────────────────────────────────
        0x0F => bit_branch("BBR0"),
        0x1F => bit_branch("BBR1"),
        0x2F => bit_branch("BBR2"),
        0x3F => bit_branch("BBR3"),
        0x4F => bit_branch("BBR4"),
        0x5F => bit_branch("BBR5"),
        _ => return None,
    })
}

fn opcode_table_65c02_q2(b: u8) -> Option<OpcodeEntry> {
    use InstrFlags as F;
    Some(match b {
        // ── ADC ──────────────────────────────────────────────────────────────
        0x69 => OpcodeEntry::base("ADC", AddrMode::Immediate, F::NONE, 2),
        0x65 => OpcodeEntry::base("ADC", AddrMode::ZeroPage, F::READ_MEM, 3),
        0x75 => OpcodeEntry::base("ADC", AddrMode::ZeroPageX, F::READ_MEM, 4),
        0x6D => OpcodeEntry::base("ADC", AddrMode::Absolute, F::READ_MEM, 4),
        0x7D => OpcodeEntry::base("ADC", AddrMode::AbsoluteX, F::READ_MEM, 4),
        0x79 => OpcodeEntry::base("ADC", AddrMode::AbsoluteY, F::READ_MEM, 4),
        0x61 => OpcodeEntry::base("ADC", AddrMode::IndirectX, F::READ_MEM, 6),
        0x71 => OpcodeEntry::base("ADC", AddrMode::IndirectY, F::READ_MEM, 5),
        0x72 => OpcodeEntry::c02("ADC", AddrMode::ZeroPageIndirect, F::READ_MEM, 5),
        // ── Branches ─────────────────────────────────────────────────────────
        0x90 => OpcodeEntry::base("BCC", AddrMode::Relative, F::BRANCH | F::CONDITIONAL, 2),
        0xB0 => OpcodeEntry::base("BCS", AddrMode::Relative, F::BRANCH | F::CONDITIONAL, 2),
        0x70 => OpcodeEntry::base("BVS", AddrMode::Relative, F::BRANCH | F::CONDITIONAL, 2),
        // 65C02: BRA – unconditional relative branch
        0x80 => OpcodeEntry::c02("BRA", AddrMode::Relative, F::BRANCH, 2),
        0x89 => OpcodeEntry::c02("BIT", AddrMode::Immediate, F::NONE, 2),
        0xB8 => OpcodeEntry::base("CLV", AddrMode::Implied, F::NONE, 2),
        0x88 => OpcodeEntry::base("DEY", AddrMode::Implied, F::NONE, 2),
        // 65C02 fixes the indirect JMP page-wrap bug.
        0x6C => OpcodeEntry::c02("JMP", AddrMode::Indirect, F::BRANCH | F::INDIRECT, 6),
        // 65C02 adds (abs,X) indirect JMP.
        0x7C => OpcodeEntry::c02(
            "JMP",
            AddrMode::AbsoluteIndirectX,
            F::BRANCH | F::INDIRECT,
            6,
        ),
        // ── LDA ──────────────────────────────────────────────────────────────
        0xA9 => OpcodeEntry::base("LDA", AddrMode::Immediate, F::NONE, 2),
        0xA5 => OpcodeEntry::base("LDA", AddrMode::ZeroPage, F::READ_MEM, 3),
        0xB5 => OpcodeEntry::base("LDA", AddrMode::ZeroPageX, F::READ_MEM, 4),
        0xAD => OpcodeEntry::base("LDA", AddrMode::Absolute, F::READ_MEM, 4),
        0xBD => OpcodeEntry::base("LDA", AddrMode::AbsoluteX, F::READ_MEM, 4),
        0xB9 => OpcodeEntry::base("LDA", AddrMode::AbsoluteY, F::READ_MEM, 4),
        0xA1 => OpcodeEntry::base("LDA", AddrMode::IndirectX, F::READ_MEM, 6),
        0xB1 => OpcodeEntry::base("LDA", AddrMode::IndirectY, F::READ_MEM, 5),
        0xB2 => OpcodeEntry::c02("LDA", AddrMode::ZeroPageIndirect, F::READ_MEM, 5),
        // ── LDX ──────────────────────────────────────────────────────────────
        0xA2 => OpcodeEntry::base("LDX", AddrMode::Immediate, F::NONE, 2),
        0xA6 => OpcodeEntry::base("LDX", AddrMode::ZeroPage, F::READ_MEM, 3),
        0xB6 => OpcodeEntry::base("LDX", AddrMode::ZeroPageY, F::READ_MEM, 4),
        0xAE => OpcodeEntry::base("LDX", AddrMode::Absolute, F::READ_MEM, 4),
        0xBE => OpcodeEntry::base("LDX", AddrMode::AbsoluteY, F::READ_MEM, 4),
        // ── LDY ──────────────────────────────────────────────────────────────
        0xA0 => OpcodeEntry::base("LDY", AddrMode::Immediate, F::NONE, 2),
        0xA4 => OpcodeEntry::base("LDY", AddrMode::ZeroPage, F::READ_MEM, 3),
        0xB4 => OpcodeEntry::base("LDY", AddrMode::ZeroPageX, F::READ_MEM, 4),
        0xAC => OpcodeEntry::base("LDY", AddrMode::Absolute, F::READ_MEM, 4),
        0xBC => OpcodeEntry::base("LDY", AddrMode::AbsoluteX, F::READ_MEM, 4),
        0x68 => OpcodeEntry::base("PLA", AddrMode::Implied, F::READ_MEM, 4),
        0x7A => OpcodeEntry::c02("PLY", AddrMode::Implied, F::READ_MEM, 4),
        // ── ROR ──────────────────────────────────────────────────────────────
        0x6A => OpcodeEntry::base("ROR", AddrMode::Accumulator, F::NONE, 2),
        0x66 => OpcodeEntry::base("ROR", AddrMode::ZeroPage, F::READ_MEM | F::WRITE_MEM, 5),
        0x76 => OpcodeEntry::base("ROR", AddrMode::ZeroPageX, F::READ_MEM | F::WRITE_MEM, 6),
        0x6E => OpcodeEntry::base("ROR", AddrMode::Absolute, F::READ_MEM | F::WRITE_MEM, 6),
        0x7E => OpcodeEntry::base("ROR", AddrMode::AbsoluteX, F::READ_MEM | F::WRITE_MEM, 7),
        0x60 => OpcodeEntry::base("RTS", AddrMode::Implied, F::RET, 6),
        0x78 => OpcodeEntry::base("SEI", AddrMode::Implied, F::NONE, 2),
        // ── STA ──────────────────────────────────────────────────────────────
        0x85 => OpcodeEntry::base("STA", AddrMode::ZeroPage, F::WRITE_MEM, 3),
        0x95 => OpcodeEntry::base("STA", AddrMode::ZeroPageX, F::WRITE_MEM, 4),
        0x8D => OpcodeEntry::base("STA", AddrMode::Absolute, F::WRITE_MEM, 4),
        0x9D => OpcodeEntry::base("STA", AddrMode::AbsoluteX, F::WRITE_MEM, 5),
        0x99 => OpcodeEntry::base("STA", AddrMode::AbsoluteY, F::WRITE_MEM, 5),
        0x81 => OpcodeEntry::base("STA", AddrMode::IndirectX, F::WRITE_MEM, 6),
        0x91 => OpcodeEntry::base("STA", AddrMode::IndirectY, F::WRITE_MEM, 6),
        0x92 => OpcodeEntry::c02("STA", AddrMode::ZeroPageIndirect, F::WRITE_MEM, 5),
        // ── STX / STY ─────────────────────────────────────────────────────────
        0x86 => OpcodeEntry::base("STX", AddrMode::ZeroPage, F::WRITE_MEM, 3),
        0x96 => OpcodeEntry::base("STX", AddrMode::ZeroPageY, F::WRITE_MEM, 4),
        0x8E => OpcodeEntry::base("STX", AddrMode::Absolute, F::WRITE_MEM, 4),
        0x84 => OpcodeEntry::base("STY", AddrMode::ZeroPage, F::WRITE_MEM, 3),
        0x94 => OpcodeEntry::base("STY", AddrMode::ZeroPageX, F::WRITE_MEM, 4),
        0x8C => OpcodeEntry::base("STY", AddrMode::Absolute, F::WRITE_MEM, 4),
        // ── STZ (65C02 new) ───────────────────────────────────────────────────
        0x64 => OpcodeEntry::c02("STZ", AddrMode::ZeroPage, F::WRITE_MEM, 3),
        0x74 => OpcodeEntry::c02("STZ", AddrMode::ZeroPageX, F::WRITE_MEM, 4),
        0x9C => OpcodeEntry::c02("STZ", AddrMode::Absolute, F::WRITE_MEM, 4),
        0x9E => OpcodeEntry::c02("STZ", AddrMode::AbsoluteX, F::WRITE_MEM, 5),
        // ── Transfers ────────────────────────────────────────────────────────
        0xAA => OpcodeEntry::base("TAX", AddrMode::Implied, F::NONE, 2),
        0xA8 => OpcodeEntry::base("TAY", AddrMode::Implied, F::NONE, 2),
        0xBA => OpcodeEntry::base("TSX", AddrMode::Implied, F::NONE, 2),
        0x8A => OpcodeEntry::base("TXA", AddrMode::Implied, F::NONE, 2),
        0x9A => OpcodeEntry::base("TXS", AddrMode::Implied, F::NONE, 2),
        0x98 => OpcodeEntry::base("TYA", AddrMode::Implied, F::NONE, 2),
        0x67 => bit_rmw("RMB6"),
        0x77 => bit_rmw("RMB7"),
        // ── SMB0–SMB7 ────────────────────────────────────────────────────────
        0x87 => bit_rmw("SMB0"),
        0x97 => bit_rmw("SMB1"),
        0xA7 => bit_rmw("SMB2"),
        0xB7 => bit_rmw("SMB3"),
        0x6F => bit_branch("BBR6"),
        0x7F => bit_branch("BBR7"),
        // ── BBS0–BBS7 (3-byte: zp, rel) ──────────────────────────────────────
        0x8F => bit_branch("BBS0"),
        0x9F => bit_branch("BBS1"),
        0xAF => bit_branch("BBS2"),
        0xBF => bit_branch("BBS3"),
        _ => return None,
    })
}

fn opcode_table_65c02_q3(b: u8) -> Option<OpcodeEntry> {
    use InstrFlags as F;
    Some(match b {
        0xF0 => OpcodeEntry::base("BEQ", AddrMode::Relative, F::BRANCH | F::CONDITIONAL, 2),
        0xD0 => OpcodeEntry::base("BNE", AddrMode::Relative, F::BRANCH | F::CONDITIONAL, 2),
        0xD8 => OpcodeEntry::base("CLD", AddrMode::Implied, F::NONE, 2),
        // ── CMP ──────────────────────────────────────────────────────────────
        0xC9 => OpcodeEntry::base("CMP", AddrMode::Immediate, F::NONE, 2),
        0xC5 => OpcodeEntry::base("CMP", AddrMode::ZeroPage, F::READ_MEM, 3),
        0xD5 => OpcodeEntry::base("CMP", AddrMode::ZeroPageX, F::READ_MEM, 4),
        0xCD => OpcodeEntry::base("CMP", AddrMode::Absolute, F::READ_MEM, 4),
        0xDD => OpcodeEntry::base("CMP", AddrMode::AbsoluteX, F::READ_MEM, 4),
        0xD9 => OpcodeEntry::base("CMP", AddrMode::AbsoluteY, F::READ_MEM, 4),
        0xC1 => OpcodeEntry::base("CMP", AddrMode::IndirectX, F::READ_MEM, 6),
        0xD1 => OpcodeEntry::base("CMP", AddrMode::IndirectY, F::READ_MEM, 5),
        0xD2 => OpcodeEntry::c02("CMP", AddrMode::ZeroPageIndirect, F::READ_MEM, 5),
        // ── CPX ──────────────────────────────────────────────────────────────
        0xE0 => OpcodeEntry::base("CPX", AddrMode::Immediate, F::NONE, 2),
        0xE4 => OpcodeEntry::base("CPX", AddrMode::ZeroPage, F::READ_MEM, 3),
        0xEC => OpcodeEntry::base("CPX", AddrMode::Absolute, F::READ_MEM, 4),
        // ── CPY ──────────────────────────────────────────────────────────────
        0xC0 => OpcodeEntry::base("CPY", AddrMode::Immediate, F::NONE, 2),
        0xC4 => OpcodeEntry::base("CPY", AddrMode::ZeroPage, F::READ_MEM, 3),
        0xCC => OpcodeEntry::base("CPY", AddrMode::Absolute, F::READ_MEM, 4),
        // ── DEC ──────────────────────────────────────────────────────────────
        0xC6 => OpcodeEntry::base("DEC", AddrMode::ZeroPage, F::READ_MEM | F::WRITE_MEM, 5),
        0xD6 => OpcodeEntry::base("DEC", AddrMode::ZeroPageX, F::READ_MEM | F::WRITE_MEM, 6),
        0xCE => OpcodeEntry::base("DEC", AddrMode::Absolute, F::READ_MEM | F::WRITE_MEM, 6),
        0xDE => OpcodeEntry::base("DEC", AddrMode::AbsoluteX, F::READ_MEM | F::WRITE_MEM, 7),
        0xCA => OpcodeEntry::base("DEX", AddrMode::Implied, F::NONE, 2),
        // ── INC ──────────────────────────────────────────────────────────────
        0xE6 => OpcodeEntry::base("INC", AddrMode::ZeroPage, F::READ_MEM | F::WRITE_MEM, 5),
        0xF6 => OpcodeEntry::base("INC", AddrMode::ZeroPageX, F::READ_MEM | F::WRITE_MEM, 6),
        0xEE => OpcodeEntry::base("INC", AddrMode::Absolute, F::READ_MEM | F::WRITE_MEM, 6),
        0xFE => OpcodeEntry::base("INC", AddrMode::AbsoluteX, F::READ_MEM | F::WRITE_MEM, 7),
        0xE8 => OpcodeEntry::base("INX", AddrMode::Implied, F::NONE, 2),
        0xC8 => OpcodeEntry::base("INY", AddrMode::Implied, F::NONE, 2),
        // ── NOP ──────────────────────────────────────────────────────────────
        0xEA => OpcodeEntry::base("NOP", AddrMode::Implied, F::NONE, 2),
        // 65C02 new stack instructions
        0xDA => OpcodeEntry::c02("PHX", AddrMode::Implied, F::WRITE_MEM, 3),
        0xFA => OpcodeEntry::c02("PLX", AddrMode::Implied, F::READ_MEM, 4),
        // ── SBC ──────────────────────────────────────────────────────────────
        0xE9 => OpcodeEntry::base("SBC", AddrMode::Immediate, F::NONE, 2),
        0xE5 => OpcodeEntry::base("SBC", AddrMode::ZeroPage, F::READ_MEM, 3),
        0xF5 => OpcodeEntry::base("SBC", AddrMode::ZeroPageX, F::READ_MEM, 4),
        0xED => OpcodeEntry::base("SBC", AddrMode::Absolute, F::READ_MEM, 4),
        0xFD => OpcodeEntry::base("SBC", AddrMode::AbsoluteX, F::READ_MEM, 4),
        0xF9 => OpcodeEntry::base("SBC", AddrMode::AbsoluteY, F::READ_MEM, 4),
        0xE1 => OpcodeEntry::base("SBC", AddrMode::IndirectX, F::READ_MEM, 6),
        0xF1 => OpcodeEntry::base("SBC", AddrMode::IndirectY, F::READ_MEM, 5),
        0xF2 => OpcodeEntry::c02("SBC", AddrMode::ZeroPageIndirect, F::READ_MEM, 5),
        0xF8 => OpcodeEntry::base("SED", AddrMode::Implied, F::NONE, 2),
        // ── WAI / STP (65C02 new) ─────────────────────────────────────────────
        0xCB => OpcodeEntry::c02("WAI", AddrMode::Implied, F::NONE, 3),
        0xDB => OpcodeEntry::c02("STP", AddrMode::Implied, F::NONE, 3),
        0xC7 => bit_rmw("SMB4"),
        0xD7 => bit_rmw("SMB5"),
        0xE7 => bit_rmw("SMB6"),
        0xF7 => bit_rmw("SMB7"),
        0xCF => bit_branch("BBS4"),
        0xDF => bit_branch("BBS5"),
        0xEF => bit_branch("BBS6"),
        0xFF => bit_branch("BBS7"),
        _ => return None,
    })
}

// ── Decoded65C02 ─────────────────────────────────────────────────────────────

/// Result of decoding one 65C02 instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded65C02 {
    /// Entry from the opcode table.
    pub entry: OpcodeEntry,
    /// Total instruction byte count (1–3).
    pub size: usize,
    /// Raw instruction bytes (up to 3).
    pub bytes: [u8; 3],
}

impl Decoded65C02 {
    /// Whether this instruction is one of the 3-byte BBR/BBS bit-branch ops.
    #[must_use]
    pub const fn is_bit_branch(&self) -> bool {
        matches!(
            self.bytes[0],
            0x0F | 0x1F
                | 0x2F
                | 0x3F
                | 0x4F
                | 0x5F
                | 0x6F
                | 0x7F
                | 0x8F
                | 0x9F
                | 0xAF
                | 0xBF
                | 0xCF
                | 0xDF
                | 0xEF
                | 0xFF
        )
    }

    /// Whether this instruction is one of the 2-byte RMB/SMB bit-clear/set ops.
    #[must_use]
    pub const fn is_bit_rmw(&self) -> bool {
        matches!(
            self.bytes[0],
            0x07 | 0x17
                | 0x27
                | 0x37
                | 0x47
                | 0x57
                | 0x67
                | 0x77
                | 0x87
                | 0x97
                | 0xA7
                | 0xB7
                | 0xC7
                | 0xD7
                | 0xE7
                | 0xF7
        )
    }

    /// The bit number tested/modified by BBR/BBS/RMB/SMB (0–7).
    ///
    /// Returns `None` if the instruction is not a bit-manipulation op.
    #[must_use]
    pub const fn bit_index(&self) -> Option<u8> {
        if self.is_bit_branch() || self.is_bit_rmw() {
            Some((self.bytes[0] >> 4) & 0x07)
        } else {
            None
        }
    }

    /// For BBR/BBS: the zero-page address to test (second byte).
    #[must_use]
    pub const fn bbr_bbs_zp(&self) -> Option<u8> {
        if self.is_bit_branch() {
            Some(self.bytes[1])
        } else {
            None
        }
    }

    /// For BBR/BBS: the signed relative offset (third byte).
    #[must_use]
    pub const fn bbr_bbs_offset(&self) -> Option<i8> {
        if self.is_bit_branch() {
            Some(self.bytes[2].cast_signed())
        } else {
            None
        }
    }
}

// ── Decoder ───────────────────────────────────────────────────────────────────

/// Decode one 65C02 instruction from `bytes`.
///
/// Returns `None` if `bytes` is empty, contains an unrecognised opcode, or
/// is too short to hold the full instruction.
///
/// The 65C02 has two instruction classes with non-standard sizing:
/// * **BBR0–BBS7**: 3 bytes (opcode, zero-page addr, relative offset).
/// * **RMB0–SMB7**: 2 bytes (opcode, zero-page addr).
///
/// All other instructions follow the standard `1 + mode.extra_bytes()` rule.
#[must_use]
pub fn decode_65c02(bytes: &[u8]) -> Option<Decoded65C02> {
    if bytes.is_empty() {
        return None;
    }
    let opcode = bytes[0];
    let entry = opcode_table_65c02(opcode)?;

    // BBR/BBS are always 3 bytes even though the OpcodeEntry records ZeroPage
    // (1 extra byte) — they consume an additional relative-offset byte.
    let size: usize = if is_bit_branch_opcode(opcode) {
        3
    } else {
        1 + usize::from(entry.mode.extra_bytes())
    };

    if bytes.len() < size {
        return None;
    }

    let mut raw = [0u8; 3];
    raw[..size].copy_from_slice(&bytes[..size]);

    Some(Decoded65C02 {
        entry,
        size,
        bytes: raw,
    })
}

/// Return `true` if `opcode` is a BBR0–BBS7 bit-branch instruction.
#[inline]
#[must_use]
pub const fn is_bit_branch_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        0x0F | 0x1F
            | 0x2F
            | 0x3F
            | 0x4F
            | 0x5F
            | 0x6F
            | 0x7F
            | 0x8F
            | 0x9F
            | 0xAF
            | 0xBF
            | 0xCF
            | 0xDF
            | 0xEF
            | 0xFF
    )
}

/// Return `true` if `opcode` is an RMB0–SMB7 bit-modify instruction.
#[inline]
#[must_use]
pub const fn is_bit_rmw_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        0x07 | 0x17
            | 0x27
            | 0x37
            | 0x47
            | 0x57
            | 0x67
            | 0x77
            | 0x87
            | 0x97
            | 0xA7
            | 0xB7
            | 0xC7
            | 0xD7
            | 0xE7
            | 0xF7
    )
}

/// Format the operand string for a 65C02 instruction.
///
/// Handles the non-standard BBR/BBS 3-byte format and delegates everything
/// else to the shared `format_operand` in the parent module.
#[must_use]
pub fn format_operand_65c02(entry: &OpcodeEntry, raw: &[u8; 3], size: usize, pc: u64) -> String {
    let opcode = raw[0];
    if is_bit_branch_opcode(opcode) && size == 3 {
        let zp = raw[1];
        let offset = i64::from(raw[2].cast_signed());
        let target = pc.wrapping_add(3).wrapping_add_signed(offset) & 0xFFFF;
        return format!("${zp:02X},${target:04X}");
    }
    crate::format_operand(entry.mode, raw, pc)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_bra() {
        let d = decode_65c02(&[0x80, 0x05]).unwrap();
        assert_eq!(d.entry.mnemonic, "BRA");
        assert_eq!(d.size, 2);
    }

    #[test]
    fn test_decode_phx_plx() {
        let phx = decode_65c02(&[0xDA]).unwrap();
        assert_eq!(phx.entry.mnemonic, "PHX");
        assert_eq!(phx.size, 1);
        let plx = decode_65c02(&[0xFA]).unwrap();
        assert_eq!(plx.entry.mnemonic, "PLX");
    }

    #[test]
    fn test_decode_phy_ply() {
        assert_eq!(decode_65c02(&[0x5A]).unwrap().entry.mnemonic, "PHY");
        assert_eq!(decode_65c02(&[0x7A]).unwrap().entry.mnemonic, "PLY");
    }

    #[test]
    fn test_decode_stz() {
        assert_eq!(decode_65c02(&[0x64, 0x10]).unwrap().entry.mnemonic, "STZ");
        assert_eq!(
            decode_65c02(&[0x9C, 0x00, 0x20]).unwrap().entry.mnemonic,
            "STZ"
        );
    }

    #[test]
    fn test_decode_trb_tsb() {
        let trb = decode_65c02(&[0x14, 0x50]).unwrap();
        assert_eq!(trb.entry.mnemonic, "TRB");
        let tsb = decode_65c02(&[0x04, 0x50]).unwrap();
        assert_eq!(tsb.entry.mnemonic, "TSB");
    }

    #[test]
    fn test_decode_wai_stp() {
        assert_eq!(decode_65c02(&[0xCB]).unwrap().entry.mnemonic, "WAI");
        assert_eq!(decode_65c02(&[0xDB]).unwrap().entry.mnemonic, "STP");
    }

    #[test]
    fn test_decode_rmb_smb() {
        let rmb0 = decode_65c02(&[0x07, 0x10]).unwrap();
        assert_eq!(rmb0.entry.mnemonic, "RMB0");
        assert_eq!(rmb0.size, 2);
        assert_eq!(rmb0.bit_index(), Some(0));

        let smb3 = decode_65c02(&[0xB7, 0x20]).unwrap();
        assert_eq!(smb3.entry.mnemonic, "SMB3");
        assert_eq!(smb3.bit_index(), Some(3));
    }

    #[test]
    fn test_decode_bbr_bbs() {
        // BBR2 zp=$40, offset=+5
        let bbr2 = decode_65c02(&[0x2F, 0x40, 0x05]).unwrap();
        assert_eq!(bbr2.entry.mnemonic, "BBR2");
        assert_eq!(bbr2.size, 3);
        assert!(bbr2.is_bit_branch());
        assert_eq!(bbr2.bit_index(), Some(2));
        assert_eq!(bbr2.bbr_bbs_zp(), Some(0x40));
        assert_eq!(bbr2.bbr_bbs_offset(), Some(5i8));

        // BBS7 zp=$10, offset=-2
        let bbs7 = decode_65c02(&[0xFF, 0x10, 0xFE]).unwrap();
        assert_eq!(bbs7.entry.mnemonic, "BBS7");
        assert_eq!(bbs7.size, 3);
        assert_eq!(bbs7.bit_index(), Some(7));
    }

    #[test]
    fn test_decode_zp_indirect() {
        let d = decode_65c02(&[0xB2, 0x50]).unwrap();
        assert_eq!(d.entry.mnemonic, "LDA");
        assert_eq!(d.entry.mode, AddrMode::ZeroPageIndirect);
        assert_eq!(d.size, 2);
    }

    #[test]
    fn test_decode_jmp_abs_indirect_x() {
        let d = decode_65c02(&[0x7C, 0x00, 0x80]).unwrap();
        assert_eq!(d.entry.mnemonic, "JMP");
        assert_eq!(d.entry.mode, AddrMode::AbsoluteIndirectX);
    }

    #[test]
    fn test_truncated_returns_none() {
        assert!(decode_65c02(&[0xB2]).is_none()); // LDA (zp) needs 2 bytes
    }

    #[test]
    fn test_empty_returns_none() {
        assert!(decode_65c02(&[]).is_none());
    }
}
