//! x86 opcode tables: 1-byte, 2-byte (0F), 3-byte (0F38/0F3A),
//! plus operand-encoding types and flag-effect tables.
//!
//! # Layer distinction
//!
//! This module provides **compile-time, zero-heap static arrays** (`OPCODE_TABLE_1BYTE`,
//! `OPCODE_TABLE_2BYTE`, `OPCODE_TABLE_0F38`, `OPCODE_TABLE_0F3A`) that are
//! indexed directly by opcode byte and are used for:
//!
//! - Lightweight instruction-length computation (see `crate::length`)
//! - SSE instruction descriptor metadata (see `crate::sse`, which imports [`OpEnc`])
//! - Any path that must avoid heap allocation at startup
//!
//! For the **runtime decode engine** — which builds `Vec`-backed tables with
//! rich per-entry metadata (description strings, privilege flags, fault flags,
//! group extensions, 0F-escape sub-tables) — see [`crate::x86_decode_table`].
//! The two modules cover the same opcode space but at different abstraction levels
//! and are intentionally kept separate.

// ---------------------------------------------------------------------------
// Operand Encoding
// ---------------------------------------------------------------------------

/// Operand encoding type for an x86 instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum OpEnc {
    /// No operands.
    ZO,
    /// Opcode + /r `ModRM`: reg field selects register, r/m is destination.
    MR,
    /// Opcode + /r `ModRM`: reg field selects register, r/m is source.
    RM,
    /// Opcode + imm8 immediate only.
    I8,
    /// Opcode + imm16 immediate only.
    I16,
    /// Opcode + imm32 immediate only.
    I32,
    /// Opcode + imm64 immediate only.
    I64,
    /// Opcode low 3 bits encode register (reg in opcode).
    O,
    /// Opcode low 3 bits + imm.
    OI,
    /// `ModRM` /digit + imm.
    MI,
    /// `ModRM` /digit, no immediate.
    M,
    /// Direct offset / moffs (MOV AL,moffs).
    FD,
    /// Direct offset / moffs (MOV moffs,AL).
    TD,
    /// Relative 8-bit offset.
    D8,
    /// Relative 16/32-bit offset.
    D32,
    /// Far pointer (ptr16:16 or ptr16:32).
    S,
    /// VEX-encoded: reg, vvvv, r/m.
    RVM,
    /// VEX-encoded: r/m, vvvv, reg.
    MVR,
    /// VEX-encoded: reg, r/m.
    RMV,
}

// ---------------------------------------------------------------------------
// Flag Effects
// ---------------------------------------------------------------------------

/// EFLAGS affected by an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct FlagEffect {
    /// Flags set to 1.
    pub sets: u32,
    /// Flags cleared to 0.
    pub clears: u32,
    /// Flags modified according to result.
    pub modifies: u32,
    /// Flags whose value is undefined after execution.
    pub undefined: u32,
}

impl FlagEffect {
    /// Construct a [`FlagEffect`] with all fields zero (no effect).
    pub const fn none() -> Self {
        Self {
            sets: 0,
            clears: 0,
            modifies: 0,
            undefined: 0,
        }
    }

    /// Construct a [`FlagEffect`] that modifies the standard arithmetic flags.
    pub const fn arith() -> Self {
        Self {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF | FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        }
    }

    /// Construct a [`FlagEffect`] that modifies logic flags (CF=OF=0, rest by result).
    pub const fn logic() -> Self {
        Self {
            sets: 0,
            clears: FLAG_CF | FLAG_OF,
            modifies: FLAG_PF | FLAG_ZF | FLAG_SF,
            undefined: FLAG_AF,
        }
    }
}

/// Carry flag bit position in EFLAGS.
pub const FLAG_CF: u32 = 1 << 0;
/// Parity flag.
pub const FLAG_PF: u32 = 1 << 2;
/// Auxiliary carry flag.
pub const FLAG_AF: u32 = 1 << 4;
/// Zero flag.
pub const FLAG_ZF: u32 = 1 << 6;
/// Sign flag.
pub const FLAG_SF: u32 = 1 << 7;
/// Trap flag.
pub const FLAG_TF: u32 = 1 << 8;
/// Interrupt enable flag.
pub const FLAG_IF: u32 = 1 << 9;
/// Direction flag.
pub const FLAG_DF: u32 = 1 << 10;
/// Overflow flag.
pub const FLAG_OF: u32 = 1 << 11;

// ---------------------------------------------------------------------------
// One-byte opcode table entry
// ---------------------------------------------------------------------------

/// A single entry in the 1-byte opcode table.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct OpcodeEntry1 {
    /// Opcode byte (0x00–0xFF).
    pub opcode: u8,
    /// Canonical mnemonic string.
    pub mnemonic: &'static str,
    /// Operand encoding.
    pub enc: OpEnc,
    /// Flag effects.
    pub flags: FlagEffect,
}

impl OpcodeEntry1 {
    const fn new(opcode: u8, mnemonic: &'static str, enc: OpEnc, flags: FlagEffect) -> Self {
        Self {
            opcode,
            mnemonic,
            enc,
            flags,
        }
    }
}

/// Complete 1-byte opcode table (256 entries, indexed by opcode byte).
///
/// Entries marked `"???"` are either invalid, multi-byte escapes, or
/// prefix bytes decoded at a higher level.
pub static OPCODE_TABLE_1BYTE: [OpcodeEntry1; 256] = [
    // 0x00 – 0x05  ADD
    OpcodeEntry1::new(0x00, "add", OpEnc::MR, FlagEffect::arith()),
    OpcodeEntry1::new(0x01, "add", OpEnc::MR, FlagEffect::arith()),
    OpcodeEntry1::new(0x02, "add", OpEnc::RM, FlagEffect::arith()),
    OpcodeEntry1::new(0x03, "add", OpEnc::RM, FlagEffect::arith()),
    OpcodeEntry1::new(0x04, "add", OpEnc::I8, FlagEffect::arith()),
    OpcodeEntry1::new(0x05, "add", OpEnc::I32, FlagEffect::arith()),
    // 0x06 – 0x07  PUSH/POP ES (invalid in 64-bit)
    OpcodeEntry1::new(0x06, "push", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x07, "pop", OpEnc::ZO, FlagEffect::none()),
    // 0x08 – 0x0D  OR
    OpcodeEntry1::new(0x08, "or", OpEnc::MR, FlagEffect::logic()),
    OpcodeEntry1::new(0x09, "or", OpEnc::MR, FlagEffect::logic()),
    OpcodeEntry1::new(0x0A, "or", OpEnc::RM, FlagEffect::logic()),
    OpcodeEntry1::new(0x0B, "or", OpEnc::RM, FlagEffect::logic()),
    OpcodeEntry1::new(0x0C, "or", OpEnc::I8, FlagEffect::logic()),
    OpcodeEntry1::new(0x0D, "or", OpEnc::I32, FlagEffect::logic()),
    // 0x0E  PUSH CS  0x0F 2-byte escape
    OpcodeEntry1::new(0x0E, "push", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x0F, "???", OpEnc::ZO, FlagEffect::none()),
    // 0x10 – 0x15  ADC
    OpcodeEntry1::new(0x10, "adc", OpEnc::MR, FlagEffect::arith()),
    OpcodeEntry1::new(0x11, "adc", OpEnc::MR, FlagEffect::arith()),
    OpcodeEntry1::new(0x12, "adc", OpEnc::RM, FlagEffect::arith()),
    OpcodeEntry1::new(0x13, "adc", OpEnc::RM, FlagEffect::arith()),
    OpcodeEntry1::new(0x14, "adc", OpEnc::I8, FlagEffect::arith()),
    OpcodeEntry1::new(0x15, "adc", OpEnc::I32, FlagEffect::arith()),
    // 0x16 – 0x17  PUSH/POP SS
    OpcodeEntry1::new(0x16, "push", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x17, "pop", OpEnc::ZO, FlagEffect::none()),
    // 0x18 – 0x1D  SBB
    OpcodeEntry1::new(0x18, "sbb", OpEnc::MR, FlagEffect::arith()),
    OpcodeEntry1::new(0x19, "sbb", OpEnc::MR, FlagEffect::arith()),
    OpcodeEntry1::new(0x1A, "sbb", OpEnc::RM, FlagEffect::arith()),
    OpcodeEntry1::new(0x1B, "sbb", OpEnc::RM, FlagEffect::arith()),
    OpcodeEntry1::new(0x1C, "sbb", OpEnc::I8, FlagEffect::arith()),
    OpcodeEntry1::new(0x1D, "sbb", OpEnc::I32, FlagEffect::arith()),
    // 0x1E – 0x1F  PUSH/POP DS
    OpcodeEntry1::new(0x1E, "push", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x1F, "pop", OpEnc::ZO, FlagEffect::none()),
    // 0x20 – 0x25  AND
    OpcodeEntry1::new(0x20, "and", OpEnc::MR, FlagEffect::logic()),
    OpcodeEntry1::new(0x21, "and", OpEnc::MR, FlagEffect::logic()),
    OpcodeEntry1::new(0x22, "and", OpEnc::RM, FlagEffect::logic()),
    OpcodeEntry1::new(0x23, "and", OpEnc::RM, FlagEffect::logic()),
    OpcodeEntry1::new(0x24, "and", OpEnc::I8, FlagEffect::logic()),
    OpcodeEntry1::new(0x25, "and", OpEnc::I32, FlagEffect::logic()),
    // 0x26  ES prefix  0x27 DAA
    OpcodeEntry1::new(0x26, "es:", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x27, "daa", OpEnc::ZO, FlagEffect::arith()),
    // 0x28 – 0x2D  SUB
    OpcodeEntry1::new(0x28, "sub", OpEnc::MR, FlagEffect::arith()),
    OpcodeEntry1::new(0x29, "sub", OpEnc::MR, FlagEffect::arith()),
    OpcodeEntry1::new(0x2A, "sub", OpEnc::RM, FlagEffect::arith()),
    OpcodeEntry1::new(0x2B, "sub", OpEnc::RM, FlagEffect::arith()),
    OpcodeEntry1::new(0x2C, "sub", OpEnc::I8, FlagEffect::arith()),
    OpcodeEntry1::new(0x2D, "sub", OpEnc::I32, FlagEffect::arith()),
    // 0x2E CS prefix  0x2F DAS
    OpcodeEntry1::new(0x2E, "cs:", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x2F, "das", OpEnc::ZO, FlagEffect::arith()),
    // 0x30 – 0x35  XOR
    OpcodeEntry1::new(0x30, "xor", OpEnc::MR, FlagEffect::logic()),
    OpcodeEntry1::new(0x31, "xor", OpEnc::MR, FlagEffect::logic()),
    OpcodeEntry1::new(0x32, "xor", OpEnc::RM, FlagEffect::logic()),
    OpcodeEntry1::new(0x33, "xor", OpEnc::RM, FlagEffect::logic()),
    OpcodeEntry1::new(0x34, "xor", OpEnc::I8, FlagEffect::logic()),
    OpcodeEntry1::new(0x35, "xor", OpEnc::I32, FlagEffect::logic()),
    // 0x36 SS prefix  0x37 AAA
    OpcodeEntry1::new(0x36, "ss:", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(
        0x37,
        "aaa",
        OpEnc::ZO,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_AF | FLAG_CF,
            undefined: FLAG_OF | FLAG_SF | FLAG_ZF | FLAG_PF,
        },
    ),
    // 0x38 – 0x3D  CMP
    OpcodeEntry1::new(0x38, "cmp", OpEnc::MR, FlagEffect::arith()),
    OpcodeEntry1::new(0x39, "cmp", OpEnc::MR, FlagEffect::arith()),
    OpcodeEntry1::new(0x3A, "cmp", OpEnc::RM, FlagEffect::arith()),
    OpcodeEntry1::new(0x3B, "cmp", OpEnc::RM, FlagEffect::arith()),
    OpcodeEntry1::new(0x3C, "cmp", OpEnc::I8, FlagEffect::arith()),
    OpcodeEntry1::new(0x3D, "cmp", OpEnc::I32, FlagEffect::arith()),
    // 0x3E DS prefix  0x3F AAS
    OpcodeEntry1::new(0x3E, "ds:", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(
        0x3F,
        "aas",
        OpEnc::ZO,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_AF | FLAG_CF,
            undefined: FLAG_OF | FLAG_SF | FLAG_ZF | FLAG_PF,
        },
    ),
    // 0x40 – 0x4F  INC/DEC r16/r32  (or REX prefix in 64-bit)
    OpcodeEntry1::new(
        0x40,
        "inc",
        OpEnc::O,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0x41,
        "inc",
        OpEnc::O,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0x42,
        "inc",
        OpEnc::O,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0x43,
        "inc",
        OpEnc::O,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0x44,
        "inc",
        OpEnc::O,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0x45,
        "inc",
        OpEnc::O,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0x46,
        "inc",
        OpEnc::O,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0x47,
        "inc",
        OpEnc::O,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0x48,
        "dec",
        OpEnc::O,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0x49,
        "dec",
        OpEnc::O,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0x4A,
        "dec",
        OpEnc::O,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0x4B,
        "dec",
        OpEnc::O,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0x4C,
        "dec",
        OpEnc::O,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0x4D,
        "dec",
        OpEnc::O,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0x4E,
        "dec",
        OpEnc::O,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0x4F,
        "dec",
        OpEnc::O,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    // 0x50 – 0x57  PUSH r16/r32/r64
    OpcodeEntry1::new(0x50, "push", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x51, "push", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x52, "push", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x53, "push", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x54, "push", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x55, "push", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x56, "push", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x57, "push", OpEnc::O, FlagEffect::none()),
    // 0x58 – 0x5F  POP r16/r32/r64
    OpcodeEntry1::new(0x58, "pop", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x59, "pop", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x5A, "pop", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x5B, "pop", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x5C, "pop", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x5D, "pop", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x5E, "pop", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x5F, "pop", OpEnc::O, FlagEffect::none()),
    // 0x60 – 0x67
    OpcodeEntry1::new(0x60, "pusha", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x61, "popa", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x62, "bound", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry1::new(
        0x63,
        "arpl",
        OpEnc::MR,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_ZF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(0x64, "fs:", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x65, "gs:", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x66, "opdsz", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x67, "addrsz", OpEnc::ZO, FlagEffect::none()),
    // 0x68 – 0x6B  PUSH imm / IMUL /6A PUSH imm8
    OpcodeEntry1::new(0x68, "push", OpEnc::I32, FlagEffect::none()),
    OpcodeEntry1::new(0x69, "imul", OpEnc::RMV, FlagEffect::arith()),
    OpcodeEntry1::new(0x6A, "push", OpEnc::I8, FlagEffect::none()),
    OpcodeEntry1::new(0x6B, "imul", OpEnc::RMV, FlagEffect::arith()),
    // 0x6C – 0x6F  INS / OUTS
    OpcodeEntry1::new(0x6C, "insb", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x6D, "insd", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x6E, "outsb", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x6F, "outsd", OpEnc::ZO, FlagEffect::none()),
    // 0x70 – 0x7F  Jcc rel8
    OpcodeEntry1::new(0x70, "jo", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0x71, "jno", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0x72, "jb", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0x73, "jnb", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0x74, "jz", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0x75, "jnz", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0x76, "jbe", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0x77, "jnbe", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0x78, "js", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0x79, "jns", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0x7A, "jp", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0x7B, "jnp", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0x7C, "jl", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0x7D, "jnl", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0x7E, "jle", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0x7F, "jnle", OpEnc::D8, FlagEffect::none()),
    // 0x80 – 0x83  Grp1 ALU imm
    OpcodeEntry1::new(0x80, "grp1", OpEnc::MI, FlagEffect::arith()),
    OpcodeEntry1::new(0x81, "grp1", OpEnc::MI, FlagEffect::arith()),
    OpcodeEntry1::new(0x82, "grp1", OpEnc::MI, FlagEffect::arith()),
    OpcodeEntry1::new(0x83, "grp1", OpEnc::MI, FlagEffect::arith()),
    // 0x84 – 0x85  TEST
    OpcodeEntry1::new(0x84, "test", OpEnc::MR, FlagEffect::logic()),
    OpcodeEntry1::new(0x85, "test", OpEnc::MR, FlagEffect::logic()),
    // 0x86 – 0x87  XCHG
    OpcodeEntry1::new(0x86, "xchg", OpEnc::MR, FlagEffect::none()),
    OpcodeEntry1::new(0x87, "xchg", OpEnc::MR, FlagEffect::none()),
    // 0x88 – 0x8E  MOV
    OpcodeEntry1::new(0x88, "mov", OpEnc::MR, FlagEffect::none()),
    OpcodeEntry1::new(0x89, "mov", OpEnc::MR, FlagEffect::none()),
    OpcodeEntry1::new(0x8A, "mov", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry1::new(0x8B, "mov", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry1::new(0x8C, "mov", OpEnc::MR, FlagEffect::none()),
    OpcodeEntry1::new(0x8D, "lea", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry1::new(0x8E, "mov", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry1::new(0x8F, "pop", OpEnc::M, FlagEffect::none()),
    // 0x90 – 0x97  XCHG r,rAX / NOP
    OpcodeEntry1::new(0x90, "nop", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x91, "xchg", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x92, "xchg", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x93, "xchg", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x94, "xchg", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x95, "xchg", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x96, "xchg", OpEnc::O, FlagEffect::none()),
    OpcodeEntry1::new(0x97, "xchg", OpEnc::O, FlagEffect::none()),
    // 0x98 – 0x9F
    OpcodeEntry1::new(0x98, "cbw", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x99, "cdq", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x9A, "call", OpEnc::S, FlagEffect::none()),
    OpcodeEntry1::new(0x9B, "wait", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0x9C, "pushf", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(
        0x9D,
        "popf",
        OpEnc::ZO,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF
                | FLAG_PF
                | FLAG_AF
                | FLAG_ZF
                | FLAG_SF
                | FLAG_TF
                | FLAG_IF
                | FLAG_DF
                | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0x9E,
        "sahf",
        OpEnc::ZO,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF | FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(0x9F, "lahf", OpEnc::ZO, FlagEffect::none()),
    // 0xA0 – 0xA3  MOV moffs
    OpcodeEntry1::new(0xA0, "mov", OpEnc::FD, FlagEffect::none()),
    OpcodeEntry1::new(0xA1, "mov", OpEnc::FD, FlagEffect::none()),
    OpcodeEntry1::new(0xA2, "mov", OpEnc::TD, FlagEffect::none()),
    OpcodeEntry1::new(0xA3, "mov", OpEnc::TD, FlagEffect::none()),
    // 0xA4 – 0xA7  MOVS / CMPS
    OpcodeEntry1::new(0xA4, "movsb", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0xA5, "movsd", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0xA6, "cmpsb", OpEnc::ZO, FlagEffect::arith()),
    OpcodeEntry1::new(0xA7, "cmpsd", OpEnc::ZO, FlagEffect::arith()),
    // 0xA8 – 0xA9  TEST imm
    OpcodeEntry1::new(0xA8, "test", OpEnc::I8, FlagEffect::logic()),
    OpcodeEntry1::new(0xA9, "test", OpEnc::I32, FlagEffect::logic()),
    // 0xAA – 0xAF  STOS / LODS / SCAS
    OpcodeEntry1::new(0xAA, "stosb", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0xAB, "stosd", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0xAC, "lodsb", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0xAD, "lodsd", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0xAE, "scasb", OpEnc::ZO, FlagEffect::arith()),
    OpcodeEntry1::new(0xAF, "scasd", OpEnc::ZO, FlagEffect::arith()),
    // 0xB0 – 0xBF  MOV reg, imm
    OpcodeEntry1::new(0xB0, "mov", OpEnc::OI, FlagEffect::none()),
    OpcodeEntry1::new(0xB1, "mov", OpEnc::OI, FlagEffect::none()),
    OpcodeEntry1::new(0xB2, "mov", OpEnc::OI, FlagEffect::none()),
    OpcodeEntry1::new(0xB3, "mov", OpEnc::OI, FlagEffect::none()),
    OpcodeEntry1::new(0xB4, "mov", OpEnc::OI, FlagEffect::none()),
    OpcodeEntry1::new(0xB5, "mov", OpEnc::OI, FlagEffect::none()),
    OpcodeEntry1::new(0xB6, "mov", OpEnc::OI, FlagEffect::none()),
    OpcodeEntry1::new(0xB7, "mov", OpEnc::OI, FlagEffect::none()),
    OpcodeEntry1::new(0xB8, "mov", OpEnc::OI, FlagEffect::none()),
    OpcodeEntry1::new(0xB9, "mov", OpEnc::OI, FlagEffect::none()),
    OpcodeEntry1::new(0xBA, "mov", OpEnc::OI, FlagEffect::none()),
    OpcodeEntry1::new(0xBB, "mov", OpEnc::OI, FlagEffect::none()),
    OpcodeEntry1::new(0xBC, "mov", OpEnc::OI, FlagEffect::none()),
    OpcodeEntry1::new(0xBD, "mov", OpEnc::OI, FlagEffect::none()),
    OpcodeEntry1::new(0xBE, "mov", OpEnc::OI, FlagEffect::none()),
    OpcodeEntry1::new(0xBF, "mov", OpEnc::OI, FlagEffect::none()),
    // 0xC0 – 0xC1  Grp2 shift imm8
    OpcodeEntry1::new(
        0xC0,
        "grp2",
        OpEnc::MI,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF | FLAG_OF,
            undefined: FLAG_AF,
        },
    ),
    OpcodeEntry1::new(
        0xC1,
        "grp2",
        OpEnc::MI,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF | FLAG_OF,
            undefined: FLAG_AF,
        },
    ),
    // 0xC2 – 0xC3  RET near
    OpcodeEntry1::new(0xC2, "ret", OpEnc::I16, FlagEffect::none()),
    OpcodeEntry1::new(0xC3, "ret", OpEnc::ZO, FlagEffect::none()),
    // 0xC4 – 0xC5  LES/LDS (or VEX prefix in 64-bit)
    OpcodeEntry1::new(0xC4, "les", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry1::new(0xC5, "lds", OpEnc::RM, FlagEffect::none()),
    // 0xC6 – 0xC7  MOV r/m, imm
    OpcodeEntry1::new(0xC6, "mov", OpEnc::MI, FlagEffect::none()),
    OpcodeEntry1::new(0xC7, "mov", OpEnc::MI, FlagEffect::none()),
    // 0xC8 – 0xCF
    OpcodeEntry1::new(0xC8, "enter", OpEnc::I16, FlagEffect::none()),
    OpcodeEntry1::new(0xC9, "leave", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0xCA, "retf", OpEnc::I16, FlagEffect::none()),
    OpcodeEntry1::new(0xCB, "retf", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(
        0xCC,
        "int3",
        OpEnc::ZO,
        FlagEffect {
            sets: FLAG_TF,
            clears: 0,
            modifies: 0,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(0xCD, "int", OpEnc::I8, FlagEffect::none()),
    OpcodeEntry1::new(0xCE, "into", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(
        0xCF,
        "iret",
        OpEnc::ZO,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF
                | FLAG_PF
                | FLAG_AF
                | FLAG_ZF
                | FLAG_SF
                | FLAG_TF
                | FLAG_IF
                | FLAG_DF
                | FLAG_OF,
            undefined: 0,
        },
    ),
    // 0xD0 – 0xD3  Grp2 rotate/shift
    OpcodeEntry1::new(
        0xD0,
        "grp2",
        OpEnc::M,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF | FLAG_OF,
            undefined: FLAG_AF,
        },
    ),
    OpcodeEntry1::new(
        0xD1,
        "grp2",
        OpEnc::M,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF | FLAG_OF,
            undefined: FLAG_AF,
        },
    ),
    OpcodeEntry1::new(
        0xD2,
        "grp2",
        OpEnc::M,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF | FLAG_OF,
            undefined: FLAG_AF,
        },
    ),
    OpcodeEntry1::new(
        0xD3,
        "grp2",
        OpEnc::M,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF | FLAG_OF,
            undefined: FLAG_AF,
        },
    ),
    // 0xD4 – 0xD5  AAM / AAD
    OpcodeEntry1::new(
        0xD4,
        "aam",
        OpEnc::I8,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_ZF | FLAG_SF,
            undefined: FLAG_CF | FLAG_AF | FLAG_OF,
        },
    ),
    OpcodeEntry1::new(
        0xD5,
        "aad",
        OpEnc::I8,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_ZF | FLAG_SF,
            undefined: FLAG_CF | FLAG_AF | FLAG_OF,
        },
    ),
    OpcodeEntry1::new(0xD6, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0xD7, "xlat", OpEnc::ZO, FlagEffect::none()),
    // 0xD8 – 0xDF  x87 FPU escape
    OpcodeEntry1::new(0xD8, "x87", OpEnc::M, FlagEffect::none()),
    OpcodeEntry1::new(0xD9, "x87", OpEnc::M, FlagEffect::none()),
    OpcodeEntry1::new(0xDA, "x87", OpEnc::M, FlagEffect::none()),
    OpcodeEntry1::new(0xDB, "x87", OpEnc::M, FlagEffect::none()),
    OpcodeEntry1::new(0xDC, "x87", OpEnc::M, FlagEffect::none()),
    OpcodeEntry1::new(0xDD, "x87", OpEnc::M, FlagEffect::none()),
    OpcodeEntry1::new(0xDE, "x87", OpEnc::M, FlagEffect::none()),
    OpcodeEntry1::new(0xDF, "x87", OpEnc::M, FlagEffect::none()),
    // 0xE0 – 0xE3  LOOP / JCXZ
    OpcodeEntry1::new(0xE0, "loopne", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0xE1, "loope", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0xE2, "loop", OpEnc::D8, FlagEffect::none()),
    OpcodeEntry1::new(0xE3, "jcxz", OpEnc::D8, FlagEffect::none()),
    // 0xE4 – 0xE7  IN / OUT imm8
    OpcodeEntry1::new(0xE4, "in", OpEnc::I8, FlagEffect::none()),
    OpcodeEntry1::new(0xE5, "in", OpEnc::I8, FlagEffect::none()),
    OpcodeEntry1::new(0xE6, "out", OpEnc::I8, FlagEffect::none()),
    OpcodeEntry1::new(0xE7, "out", OpEnc::I8, FlagEffect::none()),
    // 0xE8 – 0xEB  CALL/JMP
    OpcodeEntry1::new(0xE8, "call", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry1::new(0xE9, "jmp", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry1::new(0xEA, "jmp", OpEnc::S, FlagEffect::none()),
    OpcodeEntry1::new(0xEB, "jmp", OpEnc::D8, FlagEffect::none()),
    // 0xEC – 0xEF  IN / OUT DX
    OpcodeEntry1::new(0xEC, "in", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0xED, "in", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0xEE, "out", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0xEF, "out", OpEnc::ZO, FlagEffect::none()),
    // 0xF0 – 0xF7
    OpcodeEntry1::new(0xF0, "lock", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0xF1, "icebp", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0xF2, "repne", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0xF3, "rep", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(0xF4, "hlt", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry1::new(
        0xF5,
        "cmc",
        OpEnc::ZO,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(0xF6, "grp3", OpEnc::M, FlagEffect::arith()),
    OpcodeEntry1::new(0xF7, "grp3", OpEnc::M, FlagEffect::arith()),
    // 0xF8 – 0xFF
    OpcodeEntry1::new(
        0xF8,
        "clc",
        OpEnc::ZO,
        FlagEffect {
            sets: 0,
            clears: FLAG_CF,
            modifies: 0,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0xF9,
        "stc",
        OpEnc::ZO,
        FlagEffect {
            sets: FLAG_CF,
            clears: 0,
            modifies: 0,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0xFA,
        "cli",
        OpEnc::ZO,
        FlagEffect {
            sets: 0,
            clears: FLAG_IF,
            modifies: 0,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0xFB,
        "sti",
        OpEnc::ZO,
        FlagEffect {
            sets: FLAG_IF,
            clears: 0,
            modifies: 0,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0xFC,
        "cld",
        OpEnc::ZO,
        FlagEffect {
            sets: 0,
            clears: FLAG_DF,
            modifies: 0,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0xFD,
        "std",
        OpEnc::ZO,
        FlagEffect {
            sets: FLAG_DF,
            clears: 0,
            modifies: 0,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(
        0xFE,
        "grp4",
        OpEnc::M,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF,
            undefined: 0,
        },
    ),
    OpcodeEntry1::new(0xFF, "grp5", OpEnc::M, FlagEffect::none()),
];

// ---------------------------------------------------------------------------
// 2-byte opcode table (0F xx)
// ---------------------------------------------------------------------------

/// An entry in the 2-byte (0F-prefixed) opcode table.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct OpcodeEntry2 {
    /// Second opcode byte (0x00–0xFF).
    pub opcode: u8,
    /// Canonical mnemonic.
    pub mnemonic: &'static str,
    /// Operand encoding.
    pub enc: OpEnc,
    /// Flag effects.
    pub flags: FlagEffect,
}

impl OpcodeEntry2 {
    const fn new(opcode: u8, mnemonic: &'static str, enc: OpEnc, flags: FlagEffect) -> Self {
        Self {
            opcode,
            mnemonic,
            enc,
            flags,
        }
    }
}

/// 2-byte opcode table (0F prefix), 256 entries.
pub static OPCODE_TABLE_2BYTE: [OpcodeEntry2; 256] = [
    OpcodeEntry2::new(0x00, "grp6", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x01, "grp7", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(
        0x02,
        "lar",
        OpEnc::RM,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_ZF,
            undefined: 0,
        },
    ),
    OpcodeEntry2::new(
        0x03,
        "lsl",
        OpEnc::RM,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_ZF,
            undefined: 0,
        },
    ),
    OpcodeEntry2::new(0x04, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x05, "syscall", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x06, "clts", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x07, "sysret", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x08, "invd", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x09, "wbinvd", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x0A, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x0B, "ud2", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x0C, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x0D, "nop", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x0E, "femms", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x0F, "3dnow", OpEnc::RM, FlagEffect::none()),
    // 0x10 – 0x1F  SSE move
    OpcodeEntry2::new(0x10, "movups", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x11, "movups", OpEnc::MR, FlagEffect::none()),
    OpcodeEntry2::new(0x12, "movlps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x13, "movlps", OpEnc::MR, FlagEffect::none()),
    OpcodeEntry2::new(0x14, "unpcklps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x15, "unpckhps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x16, "movhps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x17, "movhps", OpEnc::MR, FlagEffect::none()),
    OpcodeEntry2::new(0x18, "prefetch", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x19, "nop", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x1A, "nop", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x1B, "nop", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x1C, "nop", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x1D, "nop", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x1E, "nop", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x1F, "nop", OpEnc::M, FlagEffect::none()),
    // 0x20 – 0x27  MOV CR/DR
    OpcodeEntry2::new(0x20, "mov", OpEnc::MR, FlagEffect::none()),
    OpcodeEntry2::new(0x21, "mov", OpEnc::MR, FlagEffect::none()),
    OpcodeEntry2::new(0x22, "mov", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x23, "mov", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x24, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x25, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x26, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x27, "???", OpEnc::ZO, FlagEffect::none()),
    // 0x28 – 0x2F  SSE move / convert
    OpcodeEntry2::new(0x28, "movaps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x29, "movaps", OpEnc::MR, FlagEffect::none()),
    OpcodeEntry2::new(0x2A, "cvtpi2ps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x2B, "movntps", OpEnc::MR, FlagEffect::none()),
    OpcodeEntry2::new(0x2C, "cvttps2pi", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x2D, "cvtps2pi", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(
        0x2E,
        "ucomiss",
        OpEnc::RM,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_ZF | FLAG_PF | FLAG_CF,
            undefined: FLAG_AF | FLAG_SF | FLAG_OF,
        },
    ),
    OpcodeEntry2::new(
        0x2F,
        "comiss",
        OpEnc::RM,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_ZF | FLAG_PF | FLAG_CF,
            undefined: FLAG_AF | FLAG_SF | FLAG_OF,
        },
    ),
    // 0x30 – 0x3F  system
    OpcodeEntry2::new(0x30, "wrmsr", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x31, "rdtsc", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x32, "rdmsr", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x33, "rdpmc", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x34, "sysenter", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x35, "sysexit", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x36, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x37, "getsec", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x38, "0F38", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x39, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x3A, "0F3A", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x3B, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x3C, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x3D, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x3E, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x3F, "???", OpEnc::ZO, FlagEffect::none()),
    // 0x40 – 0x4F  CMOVcc
    OpcodeEntry2::new(0x40, "cmovo", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x41, "cmovno", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x42, "cmovc", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x43, "cmovnc", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x44, "cmovz", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x45, "cmovnz", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x46, "cmovbe", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x47, "cmovnbe", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x48, "cmovs", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x49, "cmovns", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x4A, "cmovp", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x4B, "cmovnp", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x4C, "cmovl", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x4D, "cmovnl", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x4E, "cmovle", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x4F, "cmovnle", OpEnc::RM, FlagEffect::none()),
    // 0x50 – 0x5F  SSE arithmetic
    OpcodeEntry2::new(0x50, "movmskps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x51, "sqrtps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x52, "rsqrtps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x53, "rcpps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x54, "andps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x55, "andnps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x56, "orps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x57, "xorps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x58, "addps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x59, "mulps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x5A, "cvtps2pd", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x5B, "cvtdq2ps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x5C, "subps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x5D, "minps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x5E, "divps", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x5F, "maxps", OpEnc::RM, FlagEffect::none()),
    // 0x60 – 0x6F  MMX/SSE2 pack/unpack
    OpcodeEntry2::new(0x60, "punpcklbw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x61, "punpcklwd", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x62, "punpckldq", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x63, "packsswb", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x64, "pcmpgtb", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x65, "pcmpgtw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x66, "pcmpgtd", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x67, "packuswb", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x68, "punpckhbw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x69, "punpckhwd", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x6A, "punpckhdq", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x6B, "packssdw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x6C, "punpcklqdq", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x6D, "punpckhqdq", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x6E, "movd", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x6F, "movdqa", OpEnc::RM, FlagEffect::none()),
    // 0x70 – 0x7F  SSE shuffles / moves
    OpcodeEntry2::new(0x70, "pshufd", OpEnc::RMV, FlagEffect::none()),
    OpcodeEntry2::new(0x71, "grp12", OpEnc::MI, FlagEffect::none()),
    OpcodeEntry2::new(0x72, "grp13", OpEnc::MI, FlagEffect::none()),
    OpcodeEntry2::new(0x73, "grp14", OpEnc::MI, FlagEffect::none()),
    OpcodeEntry2::new(0x74, "pcmpeqb", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x75, "pcmpeqw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x76, "pcmpeqd", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x77, "emms", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(
        0x78,
        "vmread",
        OpEnc::MR,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF | FLAG_ZF,
            undefined: 0,
        },
    ),
    OpcodeEntry2::new(
        0x79,
        "vmwrite",
        OpEnc::RM,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF | FLAG_ZF,
            undefined: 0,
        },
    ),
    OpcodeEntry2::new(0x7A, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x7B, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0x7C, "haddpd", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x7D, "hsubpd", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0x7E, "movd", OpEnc::MR, FlagEffect::none()),
    OpcodeEntry2::new(0x7F, "movdqa", OpEnc::MR, FlagEffect::none()),
    // 0x80 – 0x8F  Jcc rel32
    OpcodeEntry2::new(0x80, "jo", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry2::new(0x81, "jno", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry2::new(0x82, "jb", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry2::new(0x83, "jnb", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry2::new(0x84, "jz", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry2::new(0x85, "jnz", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry2::new(0x86, "jbe", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry2::new(0x87, "jnbe", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry2::new(0x88, "js", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry2::new(0x89, "jns", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry2::new(0x8A, "jp", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry2::new(0x8B, "jnp", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry2::new(0x8C, "jl", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry2::new(0x8D, "jnl", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry2::new(0x8E, "jle", OpEnc::D32, FlagEffect::none()),
    OpcodeEntry2::new(0x8F, "jnle", OpEnc::D32, FlagEffect::none()),
    // 0x90 – 0x9F  SETcc
    OpcodeEntry2::new(0x90, "seto", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x91, "setno", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x92, "setc", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x93, "setnc", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x94, "setz", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x95, "setnz", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x96, "setbe", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x97, "setnbe", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x98, "sets", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x99, "setns", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x9A, "setp", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x9B, "setnp", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x9C, "setl", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x9D, "setnl", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x9E, "setle", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0x9F, "setnle", OpEnc::M, FlagEffect::none()),
    // 0xA0 – 0xAF  system / bit manipulation
    OpcodeEntry2::new(0xA0, "push", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0xA1, "pop", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0xA2, "cpuid", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(
        0xA3,
        "bt",
        OpEnc::MR,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF,
            undefined: FLAG_OF | FLAG_SF | FLAG_AF | FLAG_PF,
        },
    ),
    OpcodeEntry2::new(
        0xA4,
        "shld",
        OpEnc::MR,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF | FLAG_PF | FLAG_ZF | FLAG_SF,
            undefined: FLAG_OF | FLAG_AF,
        },
    ),
    OpcodeEntry2::new(
        0xA5,
        "shld",
        OpEnc::MR,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF | FLAG_PF | FLAG_ZF | FLAG_SF,
            undefined: FLAG_OF | FLAG_AF,
        },
    ),
    OpcodeEntry2::new(0xA6, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0xA7, "???", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0xA8, "push", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0xA9, "pop", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(0xAA, "rsm", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(
        0xAB,
        "bts",
        OpEnc::MR,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF,
            undefined: FLAG_OF | FLAG_SF | FLAG_AF | FLAG_PF,
        },
    ),
    OpcodeEntry2::new(
        0xAC,
        "shrd",
        OpEnc::MR,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF | FLAG_PF | FLAG_ZF | FLAG_SF,
            undefined: FLAG_OF | FLAG_AF,
        },
    ),
    OpcodeEntry2::new(
        0xAD,
        "shrd",
        OpEnc::MR,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF | FLAG_PF | FLAG_ZF | FLAG_SF,
            undefined: FLAG_OF | FLAG_AF,
        },
    ),
    OpcodeEntry2::new(0xAE, "grp15", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0xAF, "imul", OpEnc::RM, FlagEffect::arith()),
    // 0xB0 – 0xBF  CMPXCHG / movzx / bsf / bsr / bt*
    OpcodeEntry2::new(0xB0, "cmpxchg", OpEnc::MR, FlagEffect::arith()),
    OpcodeEntry2::new(0xB1, "cmpxchg", OpEnc::MR, FlagEffect::arith()),
    OpcodeEntry2::new(0xB2, "lss", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(
        0xB3,
        "btr",
        OpEnc::MR,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF,
            undefined: FLAG_OF | FLAG_SF | FLAG_AF | FLAG_PF,
        },
    ),
    OpcodeEntry2::new(0xB4, "lfs", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xB5, "lgs", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xB6, "movzx", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xB7, "movzx", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(
        0xB8,
        "popcnt",
        OpEnc::RM,
        FlagEffect {
            sets: 0,
            clears: FLAG_CF | FLAG_OF | FLAG_SF | FLAG_AF,
            modifies: FLAG_ZF | FLAG_PF,
            undefined: 0,
        },
    ),
    OpcodeEntry2::new(0xB9, "grp10", OpEnc::ZO, FlagEffect::none()),
    OpcodeEntry2::new(
        0xBA,
        "grp8",
        OpEnc::MI,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF,
            undefined: FLAG_OF | FLAG_SF | FLAG_AF | FLAG_PF,
        },
    ),
    OpcodeEntry2::new(
        0xBB,
        "btc",
        OpEnc::MR,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_CF,
            undefined: FLAG_OF | FLAG_SF | FLAG_AF | FLAG_PF,
        },
    ),
    OpcodeEntry2::new(
        0xBC,
        "bsf",
        OpEnc::RM,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_ZF,
            undefined: FLAG_CF | FLAG_OF | FLAG_SF | FLAG_AF | FLAG_PF,
        },
    ),
    OpcodeEntry2::new(
        0xBD,
        "bsr",
        OpEnc::RM,
        FlagEffect {
            sets: 0,
            clears: 0,
            modifies: FLAG_ZF,
            undefined: FLAG_CF | FLAG_OF | FLAG_SF | FLAG_AF | FLAG_PF,
        },
    ),
    OpcodeEntry2::new(0xBE, "movsx", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xBF, "movsx", OpEnc::RM, FlagEffect::none()),
    // 0xC0 – 0xCF
    OpcodeEntry2::new(0xC0, "xadd", OpEnc::MR, FlagEffect::arith()),
    OpcodeEntry2::new(0xC1, "xadd", OpEnc::MR, FlagEffect::arith()),
    OpcodeEntry2::new(0xC2, "cmpps", OpEnc::RMV, FlagEffect::none()),
    OpcodeEntry2::new(0xC3, "movnti", OpEnc::MR, FlagEffect::none()),
    OpcodeEntry2::new(0xC4, "pinsrw", OpEnc::RMV, FlagEffect::none()),
    OpcodeEntry2::new(0xC5, "pextrw", OpEnc::RMV, FlagEffect::none()),
    OpcodeEntry2::new(0xC6, "shufps", OpEnc::RMV, FlagEffect::none()),
    OpcodeEntry2::new(0xC7, "grp9", OpEnc::M, FlagEffect::none()),
    OpcodeEntry2::new(0xC8, "bswap", OpEnc::O, FlagEffect::none()),
    OpcodeEntry2::new(0xC9, "bswap", OpEnc::O, FlagEffect::none()),
    OpcodeEntry2::new(0xCA, "bswap", OpEnc::O, FlagEffect::none()),
    OpcodeEntry2::new(0xCB, "bswap", OpEnc::O, FlagEffect::none()),
    OpcodeEntry2::new(0xCC, "bswap", OpEnc::O, FlagEffect::none()),
    OpcodeEntry2::new(0xCD, "bswap", OpEnc::O, FlagEffect::none()),
    OpcodeEntry2::new(0xCE, "bswap", OpEnc::O, FlagEffect::none()),
    OpcodeEntry2::new(0xCF, "bswap", OpEnc::O, FlagEffect::none()),
    // 0xD0 – 0xFF  SSE2 and MMX
    OpcodeEntry2::new(0xD0, "addsubpd", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xD1, "psrlw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xD2, "psrld", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xD3, "psrlq", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xD4, "paddq", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xD5, "pmullw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xD6, "movq", OpEnc::MR, FlagEffect::none()),
    OpcodeEntry2::new(0xD7, "pmovmskb", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xD8, "psubusb", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xD9, "psubusw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xDA, "pminub", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xDB, "pand", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xDC, "paddusb", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xDD, "paddusw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xDE, "pmaxub", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xDF, "pandn", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xE0, "pavgb", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xE1, "psraw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xE2, "psrad", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xE3, "pavgw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xE4, "pmulhuw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xE5, "pmulhw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xE6, "cvttpd2dq", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xE7, "movntq", OpEnc::MR, FlagEffect::none()),
    OpcodeEntry2::new(0xE8, "psubsb", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xE9, "psubsw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xEA, "pminsw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xEB, "por", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xEC, "paddsb", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xED, "paddsw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xEE, "pmaxsw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xEF, "pxor", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xF0, "lddqu", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xF1, "psllw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xF2, "pslld", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xF3, "psllq", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xF4, "pmuludq", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xF5, "pmaddwd", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xF6, "psadbw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xF7, "maskmovq", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xF8, "psubb", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xF9, "psubw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xFA, "psubd", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xFB, "psubq", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xFC, "paddb", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xFD, "paddw", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xFE, "paddd", OpEnc::RM, FlagEffect::none()),
    OpcodeEntry2::new(0xFF, "ud0", OpEnc::ZO, FlagEffect::none()),
];

// ---------------------------------------------------------------------------
// Lookup helpers
// ---------------------------------------------------------------------------

/// Look up a 1-byte opcode entry.
pub fn lookup_1byte(opcode: u8) -> &'static OpcodeEntry1 {
    &OPCODE_TABLE_1BYTE[opcode as usize]
}

/// Look up a 2-byte opcode entry (0F prefix assumed already consumed).
pub fn lookup_2byte(opcode: u8) -> &'static OpcodeEntry2 {
    &OPCODE_TABLE_2BYTE[opcode as usize]
}

// ---------------------------------------------------------------------------
// x87 FPU sub-tables
// ---------------------------------------------------------------------------

/// An x87 FPU instruction encoding (escape byte D8..DF + `ModRM`).
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct X87Entry {
    /// Mnemonic string (e.g. `"fadd"`, `"fld"`).
    pub mnemonic: &'static str,
    /// Whether the instruction pops the stack.
    pub pops: bool,
}

impl X87Entry {
    const fn new(mnemonic: &'static str, pops: bool) -> Self {
        Self { mnemonic, pops }
    }
}

/// x87 D8 escape (reg field 0–7, mem operand).
pub static X87_D8_MEM: [X87Entry; 8] = [
    X87Entry::new("fadd", false),
    X87Entry::new("fmul", false),
    X87Entry::new("fcom", false),
    X87Entry::new("fcomp", true),
    X87Entry::new("fsub", false),
    X87Entry::new("fsubr", false),
    X87Entry::new("fdiv", false),
    X87Entry::new("fdivr", false),
];

/// x87 D9 escape (reg 0–7, mem operand).
pub static X87_D9_MEM: [X87Entry; 8] = [
    X87Entry::new("fld", false),
    X87Entry::new("???", false),
    X87Entry::new("fst", false),
    X87Entry::new("fstp", true),
    X87Entry::new("fldenv", false),
    X87Entry::new("fldcw", false),
    X87Entry::new("fnstenv", false),
    X87Entry::new("fnstcw", false),
];

/// x87 DA escape (reg 0–7, mem operand — 32-bit int).
pub static X87_DA_MEM: [X87Entry; 8] = [
    X87Entry::new("fiadd", false),
    X87Entry::new("fimul", false),
    X87Entry::new("ficom", false),
    X87Entry::new("ficomp", true),
    X87Entry::new("fisub", false),
    X87Entry::new("fisubr", false),
    X87Entry::new("fidiv", false),
    X87Entry::new("fidivr", false),
];

/// x87 DB escape (reg 0–7, mem operand — 32-bit int).
pub static X87_DB_MEM: [X87Entry; 8] = [
    X87Entry::new("fild", false),
    X87Entry::new("fisttp", true),
    X87Entry::new("fist", false),
    X87Entry::new("fistp", true),
    X87Entry::new("???", false),
    X87Entry::new("fld", false),
    X87Entry::new("???", false),
    X87Entry::new("fstp", true),
];

/// x87 DC escape (reg 0–7, mem operand — 64-bit float).
pub static X87_DC_MEM: [X87Entry; 8] = [
    X87Entry::new("fadd", false),
    X87Entry::new("fmul", false),
    X87Entry::new("fcom", false),
    X87Entry::new("fcomp", true),
    X87Entry::new("fsub", false),
    X87Entry::new("fsubr", false),
    X87Entry::new("fdiv", false),
    X87Entry::new("fdivr", false),
];

/// x87 DD escape (reg 0–7, mem operand — 64-bit float).
pub static X87_DD_MEM: [X87Entry; 8] = [
    X87Entry::new("fld", false),
    X87Entry::new("fisttp", true),
    X87Entry::new("fst", false),
    X87Entry::new("fstp", true),
    X87Entry::new("frstor", false),
    X87Entry::new("???", false),
    X87Entry::new("fnsave", false),
    X87Entry::new("fnstsw", false),
];

/// x87 DE escape (reg 0–7, mem operand — 16-bit int).
pub static X87_DE_MEM: [X87Entry; 8] = [
    X87Entry::new("fiadd", false),
    X87Entry::new("fimul", false),
    X87Entry::new("ficom", false),
    X87Entry::new("ficomp", true),
    X87Entry::new("fisub", false),
    X87Entry::new("fisubr", false),
    X87Entry::new("fidiv", false),
    X87Entry::new("fidivr", false),
];

/// x87 DF escape (reg 0–7, mem operand — 16-bit int).
pub static X87_DF_MEM: [X87Entry; 8] = [
    X87Entry::new("fild", false),
    X87Entry::new("fisttp", true),
    X87Entry::new("fist", false),
    X87Entry::new("fistp", true),
    X87Entry::new("fbld", false),
    X87Entry::new("fild", false),
    X87Entry::new("fbstp", true),
    X87Entry::new("fistp", true),
];

/// Look up an x87 instruction for a given escape byte and `ModRM` reg field
/// when the `ModRM` refers to a memory operand (mod != 3).
///
/// Returns `None` if the escape byte is not in D8–DF range.
#[must_use]
pub fn x87_mem_lookup(escape: u8, reg: u8) -> Option<&'static X87Entry> {
    let idx = (reg & 7) as usize;
    match escape {
        0xD8 => Some(&X87_D8_MEM[idx]),
        0xD9 => Some(&X87_D9_MEM[idx]),
        0xDA => Some(&X87_DA_MEM[idx]),
        0xDB => Some(&X87_DB_MEM[idx]),
        0xDC => Some(&X87_DC_MEM[idx]),
        0xDD => Some(&X87_DD_MEM[idx]),
        0xDE => Some(&X87_DE_MEM[idx]),
        0xDF => Some(&X87_DF_MEM[idx]),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// SSE extension tables (mnemonic name lists)
// ---------------------------------------------------------------------------

/// All SSE (xmm, no VEX prefix) instruction mnemonics.
pub static SSE_MNEMONICS: &[&str] = &[
    "movaps",
    "movups",
    "movss",
    "movsd",
    "movlps",
    "movhps",
    "movlhps",
    "movhlps",
    "movntps",
    "movntpd",
    "movdqa",
    "movdqu",
    "movq",
    "movd",
    "addps",
    "addss",
    "addpd",
    "addsd",
    "subps",
    "subss",
    "subpd",
    "subsd",
    "mulps",
    "mulss",
    "mulpd",
    "mulsd",
    "divps",
    "divss",
    "divpd",
    "divsd",
    "sqrtps",
    "sqrtss",
    "sqrtpd",
    "sqrtsd",
    "maxps",
    "maxss",
    "maxpd",
    "maxsd",
    "minps",
    "minss",
    "minpd",
    "minsd",
    "rsqrtps",
    "rsqrtss",
    "rcpps",
    "rcpss",
    "andps",
    "andpd",
    "andnps",
    "andnpd",
    "orps",
    "orpd",
    "xorps",
    "xorpd",
    "cmpps",
    "cmpss",
    "cmppd",
    "cmpsd",
    "ucomiss",
    "ucomisd",
    "comiss",
    "comisd",
    "shufps",
    "shufpd",
    "unpcklps",
    "unpckhps",
    "unpcklpd",
    "unpckhpd",
    "cvtsi2ss",
    "cvtsi2sd",
    "cvttss2si",
    "cvtss2si",
    "cvttsd2si",
    "cvtsd2si",
    "cvtps2pd",
    "cvtpd2ps",
    "cvtps2dq",
    "cvtdq2ps",
    "cvttps2dq",
    "cvtpd2dq",
    "cvttpd2dq",
    "cvtdq2pd",
    "pand",
    "pandn",
    "por",
    "pxor",
    "paddb",
    "paddw",
    "paddd",
    "paddq",
    "paddsb",
    "paddsw",
    "paddusb",
    "paddusw",
    "psubb",
    "psubw",
    "psubd",
    "psubq",
    "psubsb",
    "psubsw",
    "psubusb",
    "psubusw",
    "pmullw",
    "pmulhw",
    "pmulhuw",
    "pmuludq",
    "pmaddwd",
    "pcmpeqb",
    "pcmpeqw",
    "pcmpeqd",
    "pcmpgtb",
    "pcmpgtw",
    "pcmpgtd",
    "packuswb",
    "packusdw",
    "packsswb",
    "packssdw",
    "punpcklbw",
    "punpcklwd",
    "punpckldq",
    "punpcklqdq",
    "punpckhbw",
    "punpckhwd",
    "punpckhdq",
    "punpckhqdq",
    "psrlw",
    "psrld",
    "psrlq",
    "psrldq",
    "psllw",
    "pslld",
    "psllq",
    "pslldq",
    "psraw",
    "psrad",
    "pshufw",
    "pshufd",
    "pshufhw",
    "pshuflw",
    "pinsrw",
    "pextrw",
    "pmovmskb",
    "pavgb",
    "pavgw",
    "pminsw",
    "pmaxsw",
    "pminub",
    "pmaxub",
    "psadbw",
    "maskmovq",
    "movntq",
    "stmxcsr",
    "ldmxcsr",
    "sfence",
    "lfence",
    "mfence",
    "prefetch0",
    "prefetch1",
    "prefetch2",
    "prefetchnta",
    "fxsave",
    "fxrstor",
    // SSE3
    "addsubps",
    "addsubpd",
    "haddps",
    "haddpd",
    "hsubps",
    "hsubpd",
    "movsldup",
    "movshdup",
    "movddup",
    "lddqu",
    "monitor",
    "mwait",
    // SSSE3
    "pshufb",
    "phaddw",
    "phaddd",
    "phaddsw",
    "pmaddubsw",
    "phsubw",
    "phsubd",
    "phsubsw",
    "psignb",
    "psignw",
    "psignd",
    "pmulhrsw",
    "palignr",
    "pabsb",
    "pabsw",
    "pabsd",
    // SSE4.1
    "pblendvb",
    "blendvps",
    "blendvpd",
    "blendps",
    "blendpd",
    "pblendw",
    "pmulld",
    "pmuldq",
    "dpps",
    "dppd",
    "pcmpeqq",
    "packusdw",
    "movntdqa",
    "pinsrb",
    "pinsrd",
    "pinsrq",
    "pextrb",
    "pextrd",
    "pextrq",
    "pmaxsb",
    "pmaxsd",
    "pmaxuw",
    "pmaxud",
    "pminsb",
    "pminsd",
    "pminuw",
    "pminud",
    "roundps",
    "roundss",
    "roundpd",
    "roundsd",
    "ptestps",
    "ptestpd",
    "ptest",
    "phminposuw",
    "pmovsx",
    "pmovzx",
    // SSE4.2
    "pcmpestri",
    "pcmpestrm",
    "pcmpistri",
    "pcmpistrm",
    "pcmpgtq",
    "crc32",
    "popcnt",
];

/// All AVX/AVX2 instruction mnemonics (VEX-encoded, 128/256-bit).
pub static AVX_MNEMONICS: &[&str] = &[
    // AVX move
    "vmovaps",
    "vmovups",
    "vmovss",
    "vmovsd",
    "vmovlps",
    "vmovhps",
    "vmovdqa",
    "vmovdqu",
    "vmovq",
    "vmovd",
    "vmovntps",
    "vmovntpd",
    "vmovntdq",
    "vmovntdqa",
    // AVX arithmetic
    "vaddps",
    "vaddss",
    "vaddpd",
    "vaddsd",
    "vsubps",
    "vsubss",
    "vsubpd",
    "vsubsd",
    "vmulps",
    "vmulss",
    "vmulpd",
    "vmulsd",
    "vdivps",
    "vdivss",
    "vdivpd",
    "vdivsd",
    "vsqrtps",
    "vsqrtss",
    "vsqrtpd",
    "vsqrtsd",
    "vmaxps",
    "vmaxss",
    "vmaxpd",
    "vmaxsd",
    "vminps",
    "vminss",
    "vminpd",
    "vminsd",
    "vrsqrtps",
    "vrsqrtss",
    "vrcpps",
    "vrcpss",
    // AVX bitwise
    "vandps",
    "vandpd",
    "vandnps",
    "vandnpd",
    "vorps",
    "vorpd",
    "vxorps",
    "vxorpd",
    // AVX compare
    "vcmpps",
    "vcmpss",
    "vcmppd",
    "vcmpsd",
    "vucomiss",
    "vucomisd",
    "vcomiss",
    "vcomisd",
    // AVX shuffle/blend
    "vshufps",
    "vshufpd",
    "vunpcklps",
    "vunpckhps",
    "vunpcklpd",
    "vunpckhpd",
    "vpermilps",
    "vpermilpd",
    "vperm2f128",
    "vperm2i128",
    "vblendps",
    "vblendpd",
    "vblendvps",
    "vblendvpd",
    "vpblendw",
    "vpblendd",
    "vpblendvb",
    // AVX horizontal
    "vhaddps",
    "vhaddpd",
    "vhsubps",
    "vhsubpd",
    "vaddsubps",
    "vaddsubpd",
    // AVX convert
    "vcvtsi2ss",
    "vcvtsi2sd",
    "vcvttss2si",
    "vcvtss2si",
    "vcvttsd2si",
    "vcvtsd2si",
    "vcvtps2pd",
    "vcvtpd2ps",
    "vcvtps2dq",
    "vcvtdq2ps",
    "vcvttps2dq",
    "vcvtpd2dq",
    "vcvttpd2dq",
    "vcvtdq2pd",
    // AVX integer (128/256)
    "vpand",
    "vpandn",
    "vpor",
    "vpxor",
    "vpaddb",
    "vpaddw",
    "vpaddd",
    "vpaddq",
    "vpaddsb",
    "vpaddsw",
    "vpaddusb",
    "vpaddusw",
    "vpsubb",
    "vpsubw",
    "vpsubd",
    "vpsubq",
    "vpsubsb",
    "vpsubsw",
    "vpsubusb",
    "vpsubusw",
    "vpmullw",
    "vpmulhw",
    "vpmulhuw",
    "vpmuludq",
    "vpmulld",
    "vpmaddwd",
    "vpmaddubsw",
    "vpcmpeqb",
    "vpcmpeqw",
    "vpcmpeqd",
    "vpcmpeqq",
    "vpcmpgtb",
    "vpcmpgtw",
    "vpcmpgtd",
    "vpcmpgtq",
    "vpackuswb",
    "vpackusdw",
    "vpacksswb",
    "vpackssdw",
    "vpunpcklbw",
    "vpunpcklwd",
    "vpunpckldq",
    "vpunpcklqdq",
    "vpunpckhbw",
    "vpunpckhwd",
    "vpunpckhdq",
    "vpunpckhqdq",
    "vpsrlw",
    "vpsrld",
    "vpsrlq",
    "vpsrldq",
    "vpsllw",
    "vpslld",
    "vpsllq",
    "vpslldq",
    "vpsraw",
    "vpsrad",
    "vpshufb",
    "vpshufd",
    "vpshufhw",
    "vpshuflw",
    "vpavgb",
    "vpavgw",
    "vpminsb",
    "vpminsd",
    "vpminub",
    "vpminud",
    "vpmaxsb",
    "vpmaxsd",
    "vpmaxub",
    "vpmaxud",
    "vpsadbw",
    "vptest",
    "vpalignr",
    "vpabsb",
    "vpabsw",
    "vpabsd",
    "vphaddw",
    "vphaddd",
    "vphaddsw",
    "vphsubw",
    "vphsubd",
    "vphsubsw",
    "vpmulhrsw",
    "vpcmpistrm",
    "vpcmpistri",
    "vpcmpestrm",
    "vpcmpestri",
    // AVX 256-bit specific
    "vbroadcastss",
    "vbroadcastsd",
    "vbroadcastf128",
    "vbroadcasti128",
    "vextractf128",
    "vinsertf128",
    "vextracti128",
    "vinserti128",
    "vmaskmovps",
    "vmaskmovpd",
    "vpmaskmovd",
    "vpmaskmovq",
    // AVX2 integer
    "vpermd",
    "vpermps",
    "vpermq",
    "vpermpd",
    "vpgatherdd",
    "vpgatherdq",
    "vpgatherqd",
    "vpgatherqq",
    "vgatherdps",
    "vgatherdpd",
    "vgatherqps",
    "vgatherqpd",
    "vpblendd",
    "vpsllvd",
    "vpsllvq",
    "vpsrlvd",
    "vpsrlvq",
    "vpsravd",
    "vfmadd132ps",
    "vfmadd213ps",
    "vfmadd231ps",
    "vfmadd132pd",
    "vfmadd213pd",
    "vfmadd231pd",
    "vfmadd132ss",
    "vfmadd213ss",
    "vfmadd231ss",
    "vfmadd132sd",
    "vfmadd213sd",
    "vfmadd231sd",
    "vfnmadd132ps",
    "vfnmadd213ps",
    "vfnmadd231ps",
    "vfnmadd132pd",
    "vfnmadd213pd",
    "vfnmadd231pd",
    "vfmsub132ps",
    "vfmsub213ps",
    "vfmsub231ps",
    "vfmsub132pd",
    "vfmsub213pd",
    "vfmsub231pd",
    "vfnmsub132ps",
    "vfnmsub213ps",
    "vfnmsub231ps",
    "vfnmsub132pd",
    "vfnmsub213pd",
    "vfnmsub231pd",
    "vfmaddsub132ps",
    "vfmaddsub213ps",
    "vfmaddsub231ps",
    "vfmaddsub132pd",
    "vfmaddsub213pd",
    "vfmaddsub231pd",
    "vfmsubadd132ps",
    "vfmsubadd213ps",
    "vfmsubadd231ps",
    "vfmsubadd132pd",
    "vfmsubadd213pd",
    "vfmsubadd231pd",
    "vaesdec",
    "vaesdeclast",
    "vaesenc",
    "vaesenclast",
    "vaesimc",
    "vaeskeygenassist",
    "vpclmulqdq",
    "vcvtph2ps",
    "vcvtps2ph",
    "vdpps",
    "vdppd",
    "vroundps",
    "vroundss",
    "vroundpd",
    "vroundsd",
    "vpinsrb",
    "vpinsrd",
    "vpinsrq",
    "vpinsrw",
    "vpextrb",
    "vpextrd",
    "vpextrq",
    "vpextrw",
    "vpmovsx",
    "vpmovzx",
    "vphminposuw",
    "vstmxcsr",
    "vldmxcsr",
    "vzeroall",
    "vzeroupper",
    "vmovmskps",
    "vmovmskpd",
];

/// AVX-512 instruction mnemonics (EVEX-encoded).
pub static AVX512_MNEMONICS: &[&str] = &[
    // Move with masking
    "vmovaps",
    "vmovups",
    "vmovdqa32",
    "vmovdqa64",
    "vmovdqu8",
    "vmovdqu16",
    "vmovdqu32",
    "vmovdqu64",
    // Arithmetic with masking
    "vaddps",
    "vaddpd",
    "vsubps",
    "vsubpd",
    "vmulps",
    "vmulpd",
    "vdivps",
    "vdivpd",
    "vsqrtps",
    "vsqrtpd",
    "vfmadd213ps",
    "vfmadd213pd",
    // Integer with masking
    "vpaddb",
    "vpaddw",
    "vpaddd",
    "vpaddq",
    "vpsubb",
    "vpsubw",
    "vpsubd",
    "vpsubq",
    "vpmullw",
    "vpmulld",
    "vpmullq",
    "vpmuldq",
    "vpmuludq",
    "vpcmpeqb",
    "vpcmpeqw",
    "vpcmpeqd",
    "vpcmpeqq",
    "vpcmpb",
    "vpcmpw",
    "vpcmpd",
    "vpcmpq",
    "vpcmpub",
    "vpcmpuw",
    "vpcmpud",
    "vpcmpuq",
    // Compress/expand
    "vpcompressd",
    "vpcompressq",
    "vpexpandd",
    "vpexpandq",
    "vcompressps",
    "vcompresspd",
    "vexpandps",
    "vexpandpd",
    // Scatter/gather
    "vpscatterdd",
    "vpscatterdq",
    "vpscatterqd",
    "vpscatterqq",
    "vscatterdps",
    "vscatterdpd",
    "vscatterqps",
    "vscatterqpd",
    "vpgatherdd",
    "vpgatherdq",
    "vpgatherqd",
    "vpgatherqq",
    // Broadcast
    "vpbroadcastb",
    "vpbroadcastw",
    "vpbroadcastd",
    "vpbroadcastq",
    "vbroadcastss",
    "vbroadcastsd",
    "vbroadcastf32x2",
    "vbroadcastf32x4",
    "vbroadcastf64x2",
    // Permute
    "vpermt2b",
    "vpermt2w",
    "vpermt2d",
    "vpermt2q",
    "vpermt2ps",
    "vpermt2pd",
    "vpermi2b",
    "vpermi2w",
    "vpermi2d",
    "vpermi2q",
    "vpermi2ps",
    "vpermi2pd",
    "vpermb",
    "vpermw",
    "vpermd",
    "vpermq",
    "vpermps",
    "vpermpd",
    // Shift with imm
    "vpsllw",
    "vpslld",
    "vpsllq",
    "vpsrlw",
    "vpsrld",
    "vpsrlq",
    "vpsraw",
    "vpsrad",
    "vpsraq",
    // Ternary logic
    "vpternlogd",
    "vpternlogq",
    // Conflict detection
    "vpconflictd",
    "vpconflictq",
    // Leading zero count
    "vplzcntd",
    "vplzcntq",
    // Reduce
    "vreduceps",
    "vreducepd",
    "vreducess",
    "vreducesd",
    // Range
    "vrangeps",
    "vrangepd",
    "vrangess",
    "vrangesd",
    // Class
    "vfpclassps",
    "vfpclasspd",
    "vfpclassss",
    "vfpclasssd",
    // Popcnt
    "vpopcntb",
    "vpopcntw",
    "vpopcntd",
    "vpopcntq",
    // Mask operations
    "kmovb",
    "kmovw",
    "kmovd",
    "kmovq",
    "kandw",
    "kandb",
    "kandd",
    "kandq",
    "korw",
    "korb",
    "kord",
    "korq",
    "kxorw",
    "kxorb",
    "kxord",
    "kxorq",
    "knotw",
    "knotb",
    "knotd",
    "knotq",
    "kandnw",
    "kandnb",
    "kandnd",
    "kandnq",
    "kortestw",
    "kortestb",
    "kortestd",
    "kortestq",
    "ktestw",
    "ktestb",
    "ktestd",
    "ktestq",
    "kshiftlb",
    "kshiftlw",
    "kshiftld",
    "kshiftlq",
    "kshiftrb",
    "kshiftrw",
    "kshiftrd",
    "kshiftrq",
    "kunpckbw",
    "kunpckwd",
    "kunpckdq",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_1byte_table_length() {
        assert_eq!(OPCODE_TABLE_1BYTE.len(), 256);
    }

    #[test]
    fn test_2byte_table_length() {
        assert_eq!(OPCODE_TABLE_2BYTE.len(), 256);
    }

    #[test]
    fn test_opcode_indices_correct_1byte() {
        for (i, entry) in OPCODE_TABLE_1BYTE.iter().enumerate() {
            assert_eq!(
                entry.opcode as usize, i,
                "1-byte table index mismatch at {i:#04x}"
            );
        }
    }

    #[test]
    fn test_opcode_indices_correct_2byte() {
        for (i, entry) in OPCODE_TABLE_2BYTE.iter().enumerate() {
            assert_eq!(
                entry.opcode as usize, i,
                "2-byte table index mismatch at {i:#04x}"
            );
        }
    }

    #[test]
    fn test_lookup_1byte_add() {
        let e = lookup_1byte(0x01);
        assert_eq!(e.mnemonic, "add");
        assert!(matches!(e.enc, OpEnc::MR));
    }

    #[test]
    fn test_lookup_1byte_ret() {
        let e = lookup_1byte(0xC3);
        assert_eq!(e.mnemonic, "ret");
    }

    #[test]
    fn test_lookup_2byte_cmovo() {
        let e = lookup_2byte(0x40);
        assert_eq!(e.mnemonic, "cmovo");
    }

    #[test]
    fn test_lookup_2byte_syscall() {
        let e = lookup_2byte(0x05);
        assert_eq!(e.mnemonic, "syscall");
    }

    #[test]
    fn test_x87_d8_fadd() {
        let e = x87_mem_lookup(0xD8, 0).unwrap();
        assert_eq!(e.mnemonic, "fadd");
        assert!(!e.pops);
    }

    #[test]
    fn test_x87_df_fistp() {
        let e = x87_mem_lookup(0xDF, 3).unwrap();
        assert_eq!(e.mnemonic, "fistp");
        assert!(e.pops);
    }

    #[test]
    fn test_x87_invalid_escape() {
        assert!(x87_mem_lookup(0xC0, 0).is_none());
    }

    #[test]
    fn test_flag_effect_arith_modifies() {
        let fe = FlagEffect::arith();
        assert_ne!(fe.modifies & FLAG_ZF, 0);
        assert_ne!(fe.modifies & FLAG_CF, 0);
        assert_ne!(fe.modifies & FLAG_SF, 0);
        assert_ne!(fe.modifies & FLAG_OF, 0);
    }

    #[test]
    fn test_flag_effect_logic_clears_cf_of() {
        let fe = FlagEffect::logic();
        assert_ne!(fe.clears & FLAG_CF, 0);
        assert_ne!(fe.clears & FLAG_OF, 0);
    }

    #[test]
    fn test_sse_mnemonics_non_empty() {
        assert!(!SSE_MNEMONICS.is_empty());
        assert!(SSE_MNEMONICS.contains(&"addps"));
        assert!(SSE_MNEMONICS.contains(&"pcmpeqb"));
    }

    #[test]
    fn test_avx_mnemonics_non_empty() {
        assert!(!AVX_MNEMONICS.is_empty());
        assert!(AVX_MNEMONICS.contains(&"vaddps"));
        assert!(AVX_MNEMONICS.contains(&"vzeroall"));
    }

    #[test]
    fn test_avx512_mnemonics_non_empty() {
        assert!(!AVX512_MNEMONICS.is_empty());
        assert!(AVX512_MNEMONICS.contains(&"kmovw"));
        assert!(AVX512_MNEMONICS.contains(&"vpternlogd"));
    }
}
