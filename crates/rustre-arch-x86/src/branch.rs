//! x86 branch-type classification and instruction category helpers.
//!
//! This module provides:
//! - [`BranchKind`] — fine-grained branch type.
//! - [`classify_branch`] — classify any instruction byte sequence into a
//!   [`BranchKind`] without full decode.
//! - [`InstrClass`] — broader instruction category for quick tagging.
//! - String-instruction prefix detection.

// ---------------------------------------------------------------------------
// BranchKind
// ---------------------------------------------------------------------------

/// Fine-grained classification of a branch / transfer-of-control instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum BranchKind {
    /// Direct unconditional jump (JMP rel8/rel32, or far JMP).
    DirectJump,
    /// Conditional jump (Jcc rel8/rel32).
    ConditionalJump,
    /// Direct call (CALL rel32, or far CALL).
    DirectCall,
    /// Indirect call (CALL r/m).
    IndirectCall,
    /// Indirect jump (JMP r/m or JMP far mem).
    IndirectJump,
    /// Return from procedure (RET/RETN/RETF).
    Return,
    /// Software interrupt (INT/INT3/INTO).
    Interrupt,
    /// System call / system enter (SYSCALL/SYSENTER).
    Syscall,
    /// Loop instruction (LOOP/LOOPE/LOOPNE/JCXZ/JECXZ/JRCXZ).
    Loop,
    /// Not a branch or control-transfer.
    NotBranch,
}

impl BranchKind {
    /// Returns `true` if this kind is any sort of branch or call.
    #[must_use]
    pub fn is_branch(self) -> bool {
        !matches!(self, Self::NotBranch)
    }

    /// Returns `true` if this kind terminates a basic block (no fall-through).
    #[must_use]
    pub fn terminates_block(self) -> bool {
        matches!(
            self,
            Self::DirectJump | Self::IndirectJump | Self::Return | Self::Interrupt | Self::Syscall
        )
    }

    /// Returns `true` for conditional branches that may fall through.
    #[must_use]
    pub fn is_conditional(self) -> bool {
        matches!(self, Self::ConditionalJump | Self::Loop)
    }

    /// Returns `true` for calls.
    #[must_use]
    pub fn is_call(self) -> bool {
        matches!(self, Self::DirectCall | Self::IndirectCall)
    }
}

// ---------------------------------------------------------------------------
// Quick branch classification
// ---------------------------------------------------------------------------

/// Classify the first instruction in `bytes` as a [`BranchKind`].
///
/// Skips legacy/REX prefixes.  Does not perform full decode; uses opcode
/// pattern matching only.
///
/// # Panics
///
/// Does not panic.
pub fn classify_branch(bytes: &[u8]) -> BranchKind {
    if bytes.is_empty() {
        return BranchKind::NotBranch;
    }

    // Skip legacy prefixes + REX using the shared, CPU-accurate prefix scanner
    // (handles operand/address-size overrides and REX-not-last nullification).
    let pos = crate::prefix::PrefixSet::consume(bytes, true).count;

    if pos >= bytes.len() {
        return BranchKind::NotBranch;
    }

    let opcode = bytes[pos];

    match opcode {
        // JMP rel8/rel32
        0xE9..=0xEB => BranchKind::DirectJump,
        // CALL rel32 / CALL far
        0xE8 | 0x9A => BranchKind::DirectCall,
        // Jcc rel8
        0x70..=0x7F => BranchKind::ConditionalJump,
        // LOOP / LOOPE / LOOPNE / JCXZ
        0xE0..=0xE3 => BranchKind::Loop,
        // INT3 / INT n / INTO
        0xCC..=0xCE => BranchKind::Interrupt,
        // ICEBP / INT1 — a one-byte software interrupt. Undocumented by Intel
        // but real, implemented on every x86, and common in anti-debug code,
        // which is exactly the input this crate is pointed at. It was missing
        // here while `x86_decode_table` knew it (as the `icebp`/`int1` alias
        // pair), so the two retained descriptions disagreed. Consequential
        // because `BranchKind::Interrupt` terminates a block: classified
        // `NotBranch`, an ICEBP silently runs two basic blocks together.
        0xF1 => BranchKind::Interrupt,
        // RET near / RETN imm16
        0xC2 | 0xC3 => BranchKind::Return,
        // RETF / RETF imm16
        0xCA | 0xCB => BranchKind::Return,
        // IRET / IRETD / IRETQ — return from interrupt
        0xCF => BranchKind::Return,
        // FF /2 = CALL r/m, FF /4 = JMP r/m, FF /5 = JMP far mem
        0xFF => {
            if let Some(&modrm) = bytes.get(pos + 1) {
                let reg = (modrm >> 3) & 0x7;
                match reg {
                    2 => BranchKind::IndirectCall,
                    3 => BranchKind::IndirectCall, // CALL far m16:ptr
                    4 => BranchKind::IndirectJump,
                    5 => BranchKind::IndirectJump, // JMP far
                    _ => BranchKind::NotBranch,
                }
            } else {
                BranchKind::NotBranch
            }
        }
        // 2-byte escape
        0x0F => {
            if let Some(&op2) = bytes.get(pos + 1) {
                match op2 {
                    // Jcc rel32
                    0x80..=0x8F => BranchKind::ConditionalJump,
                    // SYSCALL
                    0x05 => BranchKind::Syscall,
                    // SYSRET
                    0x07 => BranchKind::Return,
                    // SYSENTER
                    0x34 => BranchKind::Syscall,
                    // SYSEXIT
                    0x35 => BranchKind::Return,
                    // RSM — resume from System Management Mode (returns)
                    0xAA => BranchKind::Return,
                    _ => BranchKind::NotBranch,
                }
            } else {
                BranchKind::NotBranch
            }
        }
        _ => BranchKind::NotBranch,
    }
}

// ---------------------------------------------------------------------------
// Instruction class
// ---------------------------------------------------------------------------

/// Broad instruction category for quick tagging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum InstrClass {
    /// Integer arithmetic (ADD/SUB/MUL/DIV/INC/DEC/NEG/CMP/TEST/…).
    IntegerArith,
    /// Logical (AND/OR/XOR/NOT/…).
    Logical,
    /// Shift / rotate (SHL/SHR/SAR/ROL/ROR/RCL/RCR/SHLD/SHRD).
    Shift,
    /// Data movement (MOV/MOVZX/MOVSX/XCHG/BSWAP/PUSH/POP/LEA/…).
    Move,
    /// Call / branch / return.
    Control,
    /// Memory fence / prefetch / cache control.
    MemoryHint,
    /// String operation (MOVS/CMPS/SCAS/LODS/STOS).
    String,
    /// SSE / AVX / FPU / SIMD.
    Simd,
    /// x87 FPU.
    X87,
    /// Privileged / system instruction.
    System,
    /// Miscellaneous / NOP.
    Misc,
}

/// Classify a 1-byte opcode into an [`InstrClass`].
///
/// For instructions that require further disambiguation (`ModRM` /reg),
/// this returns a best-effort class based on the primary opcode.
pub fn classify_opcode(opcode: u8) -> InstrClass {
    match opcode {
        0x00..=0x05 | 0x10..=0x15 | 0x18..=0x1D |
        0x28..=0x2D | 0x38..=0x3D |
        0x40..=0x4F | // INC/DEC (or REX)
        0x69 | 0x6B | // IMUL
        0x80..=0x83 | // GRP1
        0xF6 | 0xF7   // GRP3
        => InstrClass::IntegerArith,

        0x08..=0x0D | 0x20..=0x25 | 0x30..=0x35 => InstrClass::Logical,

        0xC0 | 0xC1 | 0xD0..=0xD3 => InstrClass::Shift,

        0x50..=0x5F | // PUSH/POP
        0x88..=0x8E | 0x8F |
        0x90..=0x97 | // XCHG / NOP
        0xA0..=0xA3 | // MOV moffs
        0xB0..=0xBF | // MOV imm
        0xC6 | 0xC7   // MOV r/m, imm
        => InstrClass::Move,

        0x70..=0x7F | 0xE0..=0xE3 | // Jcc / LOOP
        0xE8 | 0xE9 | 0xEA | 0xEB | // CALL/JMP
        0xC2 | 0xC3 | 0xCA | 0xCB | // RET
        0xCC | 0xCD | 0xCE | 0xFF   // INT / GRP5
        => InstrClass::Control,

        0xA4..=0xA7 | 0xAA..=0xAF => InstrClass::String,

        0xD8..=0xDF => InstrClass::X87,

        0xF4 | // HLT
        0xFA | 0xFB | // CLI/STI
        0xFC | 0xFD   // CLD/STD
        => InstrClass::System,

        0x9B | 0xF1 => InstrClass::Misc, // WAIT / ICEBP

        _ => InstrClass::Misc,
    }
}

// ---------------------------------------------------------------------------
// String-instruction helpers
// ---------------------------------------------------------------------------

/// A string instruction variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum StringInstr {
    MovsByte,
    MovsWord,
    MovsDWord,
    MovsQWord,
    CmpsByte,
    CmpsWord,
    CmpsDWord,
    CmpsQWord,
    ScasByte,
    ScasWord,
    ScasDWord,
    ScasQWord,
    LodsByte,
    LodsWord,
    LodsDWord,
    LodsQWord,
    StosByte,
    StosWord,
    StosDWord,
    StosQWord,
}

impl StringInstr {
    /// The AT&T/GAS mnemonic for this string instruction.
    #[must_use]
    pub fn mnemonic(self) -> &'static str {
        match self {
            Self::MovsByte => "movsb",
            Self::MovsWord => "movsw",
            Self::MovsDWord => "movsd",
            Self::MovsQWord => "movsq",
            Self::CmpsByte => "cmpsb",
            Self::CmpsWord => "cmpsw",
            Self::CmpsDWord => "cmpsd",
            Self::CmpsQWord => "cmpsq",
            Self::ScasByte => "scasb",
            Self::ScasWord => "scasw",
            Self::ScasDWord => "scasd",
            Self::ScasQWord => "scasq",
            Self::LodsByte => "lodsb",
            Self::LodsWord => "lodsw",
            Self::LodsDWord => "lodsd",
            Self::LodsQWord => "lodsq",
            Self::StosByte => "stosb",
            Self::StosWord => "stosw",
            Self::StosDWord => "stosd",
            Self::StosQWord => "stosq",
        }
    }

    /// Returns `true` for instructions that read from `[rsi]`.
    #[must_use]
    pub fn reads_src(self) -> bool {
        matches!(
            self,
            Self::MovsByte
                | Self::MovsWord
                | Self::MovsDWord
                | Self::MovsQWord
                | Self::CmpsByte
                | Self::CmpsWord
                | Self::CmpsDWord
                | Self::CmpsQWord
                | Self::LodsByte
                | Self::LodsWord
                | Self::LodsDWord
                | Self::LodsQWord
        )
    }

    /// Returns `true` for instructions that write to `[rdi]`.
    #[must_use]
    pub fn writes_dst(self) -> bool {
        matches!(
            self,
            Self::MovsByte
                | Self::MovsWord
                | Self::MovsDWord
                | Self::MovsQWord
                | Self::StosByte
                | Self::StosWord
                | Self::StosDWord
                | Self::StosQWord
        )
    }
}

/// String-instruction prefix classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum RepPrefix {
    None,
    /// REP / REPE / REPZ — repeat while ECX != 0 (and ZF = 1 for CMPS/SCAS).
    Rep,
    /// REPNE / REPNZ — repeat while ECX != 0 and ZF = 0.
    Repne,
}

/// Decode optional REP/REPNE prefix and string opcode from `bytes`.
///
/// Returns `(rep_prefix, string_instr, has_opsize_prefix)` when the
/// instruction is a string instruction, else `None`.
///
/// `bits` must be 16, 32, or 64.
#[must_use]
pub fn decode_string_instr(bytes: &[u8], bits: u32) -> Option<(RepPrefix, StringInstr, bool)> {
    if bytes.is_empty() {
        return None;
    }
    let mut pos = 0usize;
    let mut rep = RepPrefix::None;
    let mut opsize = false;

    // Consume REP/REPNE, opsize prefix
    loop {
        if pos >= bytes.len() {
            return None;
        }
        match bytes[pos] {
            0xF3 => {
                rep = RepPrefix::Rep;
                pos += 1;
            }
            0xF2 => {
                rep = RepPrefix::Repne;
                pos += 1;
            }
            0x66 => {
                opsize = true;
                pos += 1;
            }
            0x67 => {
                pos += 1;
            } // addr-size — ignore
            // Segment overrides
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => {
                pos += 1;
            }
            _ => break,
        }
    }

    // REX in 64-bit mode
    let has_rex_w = if bits == 64 && pos < bytes.len() && (bytes[pos] >> 4) == 0x4 {
        let rex = bytes[pos];
        pos += 1;
        (rex & 0x08) != 0 // REX.W
    } else {
        false
    };

    if pos >= bytes.len() {
        return None;
    }

    let opcode = bytes[pos];

    let instr = if has_rex_w {
        match opcode {
            0xA4 => StringInstr::MovsByte,
            0xA5 => StringInstr::MovsQWord,
            0xA6 => StringInstr::CmpsByte,
            0xA7 => StringInstr::CmpsQWord,
            0xAA => StringInstr::StosByte,
            0xAB => StringInstr::StosQWord,
            0xAC => StringInstr::LodsByte,
            0xAD => StringInstr::LodsQWord,
            0xAE => StringInstr::ScasByte,
            0xAF => StringInstr::ScasQWord,
            _ => return None,
        }
    } else if opsize {
        match opcode {
            0xA4 => StringInstr::MovsByte,
            0xA5 => StringInstr::MovsWord,
            0xA6 => StringInstr::CmpsByte,
            0xA7 => StringInstr::CmpsWord,
            0xAA => StringInstr::StosByte,
            0xAB => StringInstr::StosWord,
            0xAC => StringInstr::LodsByte,
            0xAD => StringInstr::LodsWord,
            0xAE => StringInstr::ScasByte,
            0xAF => StringInstr::ScasWord,
            _ => return None,
        }
    } else {
        match opcode {
            0xA4 => StringInstr::MovsByte,
            0xA5 => StringInstr::MovsDWord,
            0xA6 => StringInstr::CmpsByte,
            0xA7 => StringInstr::CmpsDWord,
            0xAA => StringInstr::StosByte,
            0xAB => StringInstr::StosDWord,
            0xAC => StringInstr::LodsByte,
            0xAD => StringInstr::LodsDWord,
            0xAE => StringInstr::ScasByte,
            0xAF => StringInstr::ScasDWord,
            _ => return None,
        }
    };

    Some((rep, instr, opsize))
}

// ---------------------------------------------------------------------------
// Addressing-mode helpers (32/64-bit)
// ---------------------------------------------------------------------------

/// Effective-address base for 32/64-bit `ModRM`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum EffAddr {
    /// Register direct: `rax`, `ecx`, etc.
    Register(String),
    /// Base register with signed displacement.
    BaseDisp { base: String, disp: i32 },
    /// Base + (scaled) index + displacement.
    BasePlusIndex {
        base: String,
        index: String,
        scale: u8,
        disp: i32,
    },
    /// RIP-relative addressing (64-bit mode only).
    RipRelative { disp: i32 },
    /// Absolute 32-bit address (mod=0, r/m=5 in 32-bit mode).
    Absolute32(u32),
}

impl EffAddr {
    /// Format the effective address as a bracketed expression.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Register(r) => r.clone(),
            Self::BaseDisp { base, disp } => {
                if *disp == 0 {
                    format!("[{base}]")
                } else if *disp > 0 {
                    format!("[{base}+0x{disp:x}]")
                } else {
                    format!("[{base}-0x{:x}]", disp.unsigned_abs())
                }
            }
            Self::BasePlusIndex {
                base,
                index,
                scale,
                disp,
            } => {
                let idx = if *scale > 1 {
                    format!("{index}*{scale}")
                } else {
                    index.clone()
                };
                if *disp == 0 {
                    format!("[{base}+{idx}]")
                } else if *disp > 0 {
                    format!("[{base}+{idx}+0x{disp:x}]")
                } else {
                    format!("[{base}+{idx}-0x{:x}]", disp.unsigned_abs())
                }
            }
            Self::RipRelative { disp } => {
                if *disp >= 0 {
                    format!("[rip+0x{disp:x}]")
                } else {
                    format!("[rip-0x{:x}]", disp.unsigned_abs())
                }
            }
            Self::Absolute32(addr) => format!("[0x{addr:08x}]"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_jmp_short() {
        assert_eq!(classify_branch(&[0xEB, 0x00]), BranchKind::DirectJump);
    }

    #[test]
    fn test_classify_jmp_near() {
        assert_eq!(
            classify_branch(&[0xE9, 0x00, 0x00, 0x00, 0x00]),
            BranchKind::DirectJump
        );
    }

    #[test]
    fn test_classify_call() {
        assert_eq!(
            classify_branch(&[0xE8, 0x00, 0x00, 0x00, 0x00]),
            BranchKind::DirectCall
        );
    }

    #[test]
    fn test_classify_jcc_all() {
        for b in 0x70u8..=0x7F {
            assert_eq!(
                classify_branch(&[b, 0x00]),
                BranchKind::ConditionalJump,
                "opcode 0x{b:02X}"
            );
        }
    }

    #[test]
    fn test_classify_ret() {
        assert_eq!(classify_branch(&[0xC3]), BranchKind::Return);
        assert_eq!(classify_branch(&[0xC2, 0x08, 0x00]), BranchKind::Return);
    }

    #[test]
    fn test_classify_int3() {
        assert_eq!(classify_branch(&[0xCC]), BranchKind::Interrupt);
    }

    /// REGRESSION: `F1` is ICEBP/INT1, a one-byte software interrupt. It was
    /// classified `NotBranch`, so it did not terminate a basic block and two
    /// blocks were silently joined — in anti-debug code, where ICEBP is a
    /// staple, exactly where a correct CFG matters most. Found by
    /// `tests/branch_class_vs_iced.rs`, not by reading this file.
    #[test]
    fn test_classify_icebp_int1() {
        assert_eq!(classify_branch(&[0xF1]), BranchKind::Interrupt);
        assert!(BranchKind::Interrupt.terminates_block());
    }

    #[test]
    fn test_classify_syscall() {
        assert_eq!(classify_branch(&[0x0F, 0x05]), BranchKind::Syscall);
    }

    #[test]
    fn test_classify_indirect_call() {
        // FF /2 — CALL r/m
        assert_eq!(classify_branch(&[0xFF, 0xD0]), BranchKind::IndirectCall); // FF D0 = CALL rax
    }

    #[test]
    fn test_classify_indirect_jmp() {
        // FF /4 — JMP r/m
        assert_eq!(classify_branch(&[0xFF, 0xE0]), BranchKind::IndirectJump); // FF E0 = JMP rax
    }

    #[test]
    fn test_classify_loop() {
        assert_eq!(classify_branch(&[0xE2, 0x00]), BranchKind::Loop);
        assert_eq!(classify_branch(&[0xE0, 0x00]), BranchKind::Loop);
    }

    #[test]
    fn test_classify_nop_not_branch() {
        assert_eq!(classify_branch(&[0x90]), BranchKind::NotBranch);
    }

    #[test]
    fn test_classify_jcc_rel32() {
        // 0F 8x — Jcc rel32
        for op2 in 0x80u8..=0x8F {
            let r = classify_branch(&[0x0F, op2, 0, 0, 0, 0]);
            assert_eq!(r, BranchKind::ConditionalJump, "0F {op2:02X}");
        }
    }

    #[test]
    fn test_branch_kind_properties() {
        assert!(BranchKind::DirectJump.terminates_block());
        assert!(!BranchKind::ConditionalJump.terminates_block());
        assert!(BranchKind::ConditionalJump.is_conditional());
        assert!(!BranchKind::DirectJump.is_conditional());
        assert!(BranchKind::DirectCall.is_call());
        assert!(BranchKind::IndirectCall.is_call());
        assert!(!BranchKind::Return.is_call());
    }

    #[test]
    fn test_classify_opcode_arith() {
        assert_eq!(classify_opcode(0x01), InstrClass::IntegerArith);
        assert_eq!(classify_opcode(0x03), InstrClass::IntegerArith);
    }

    #[test]
    fn test_classify_opcode_move() {
        assert_eq!(classify_opcode(0x89), InstrClass::Move);
        assert_eq!(classify_opcode(0x8B), InstrClass::Move);
        assert_eq!(classify_opcode(0xB8), InstrClass::Move);
    }

    #[test]
    fn test_classify_opcode_x87() {
        for b in 0xD8u8..=0xDF {
            assert_eq!(classify_opcode(b), InstrClass::X87);
        }
    }

    #[test]
    fn test_classify_opcode_string() {
        assert_eq!(classify_opcode(0xA4), InstrClass::String);
        assert_eq!(classify_opcode(0xAA), InstrClass::String);
    }

    #[test]
    fn test_decode_string_instr_basic() {
        // F3 A4 — REP MOVSB
        let r = decode_string_instr(&[0xF3, 0xA4], 64).unwrap();
        assert_eq!(r.0, RepPrefix::Rep);
        assert_eq!(r.1, StringInstr::MovsByte);
    }

    #[test]
    fn test_decode_string_instr_repne_scasb() {
        // F2 AE — REPNE SCASB
        let r = decode_string_instr(&[0xF2, 0xAE], 64).unwrap();
        assert_eq!(r.0, RepPrefix::Repne);
        assert_eq!(r.1, StringInstr::ScasByte);
    }

    #[test]
    fn test_decode_string_instr_no_prefix() {
        // AB — STOSD (no prefix, 32-bit mode)
        let r = decode_string_instr(&[0xAB], 32).unwrap();
        assert_eq!(r.0, RepPrefix::None);
        assert_eq!(r.1, StringInstr::StosDWord);
    }

    #[test]
    fn test_decode_string_instr_rex_w_movsq() {
        // 48 A5 — REX.W MOVSQ
        let r = decode_string_instr(&[0x48, 0xA5], 64).unwrap();
        assert_eq!(r.1, StringInstr::MovsQWord);
    }

    #[test]
    fn test_decode_string_instr_not_string() {
        assert!(decode_string_instr(&[0x90], 64).is_none());
    }

    #[test]
    fn test_eff_addr_display_register() {
        let ea = EffAddr::Register("rax".into());
        assert_eq!(ea.display(), "rax");
    }

    #[test]
    fn test_eff_addr_display_base_disp() {
        let ea = EffAddr::BaseDisp {
            base: "rbp".into(),
            disp: -8,
        };
        assert_eq!(ea.display(), "[rbp-0x8]");
    }

    #[test]
    fn test_eff_addr_display_rip_rel() {
        let ea = EffAddr::RipRelative { disp: 0x1234 };
        assert_eq!(ea.display(), "[rip+0x1234]");
    }

    #[test]
    fn test_eff_addr_display_abs32() {
        let ea = EffAddr::Absolute32(0xDEAD_BEEF);
        assert_eq!(ea.display(), "[0xdeadbeef]");
    }

    // ── Differential validation of classify_branch against iced-x86 ──────────
    //
    // For the unambiguous control-flow families, `classify_branch` must agree
    // with iced's authoritative `flow_control()`. (SYSCALL/SYSENTER/INT and
    // exceptions are intentionally excluded — their family mapping is a project
    // convention, not a property of the encoding.)

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
    }

    #[test]
    fn diff_classify_branch_vs_iced_64bit() {
        use iced_x86::{Decoder, DecoderOptions, FlowControl};
        let mut rng = Lcg(0x2244_6688_aacc_ee00);
        let mut checked = 0usize;
        for _ in 0..80_000 {
            let len = 1 + (rng.next() % 10) as usize;
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                bytes.push((rng.next() >> 32) as u8);
            }
            let mut dec = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE);
            let iced = dec.decode();
            if iced.is_invalid() {
                continue;
            }
            let kind = classify_branch(&bytes);
            // Expected `classify_branch` family for each clear iced flow class.
            let ok = match iced.flow_control() {
                FlowControl::ConditionalBranch => {
                    matches!(kind, BranchKind::ConditionalJump | BranchKind::Loop)
                }
                FlowControl::UnconditionalBranch => matches!(kind, BranchKind::DirectJump),
                FlowControl::IndirectBranch => matches!(kind, BranchKind::IndirectJump),
                FlowControl::IndirectCall => matches!(kind, BranchKind::IndirectCall),
                FlowControl::Return => matches!(kind, BranchKind::Return),
                // iced tags both direct CALL (E8/9A) and SYSCALL/SYSENTER as
                // `Call`; classify_branch splits the latter into `Syscall`.
                FlowControl::Call => {
                    matches!(kind, BranchKind::DirectCall | BranchKind::Syscall)
                }
                // Next / Interrupt / Exception: family mapping not asserted.
                _ => true,
            };
            assert!(
                ok,
                "classify_branch disagrees with iced: bytes={:02x?} flow={:?} kind={:?} ({})",
                &bytes[..iced.len().min(bytes.len())],
                iced.flow_control(),
                kind,
                iced
            );
            checked += 1;
        }
        assert!(checked > 200, "too few instructions exercised: {checked}");
    }
}
