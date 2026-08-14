//! `rustre-arch-msp430`
//!
//! Texas Instruments MSP430 / MSP430X architecture implementation for the
//! `RustRE` Suite.  Supports the full 16-bit MSP430 instruction set and the
//! 20-bit MSP430X extensions.
//!
//! # Instruction formats
//! * **Format I** (two-operand): `opcode[4] src[4] ad[1] bw[1] as[2] dst[4]`
//! * **Format II** (single-operand): `0001 00 opcode[3] bw[1] as[2] reg[4]`
//! * **Format III** (jump): `001 cond[3] offset[10]`
//!
//! Extension words (one or two following the base word) encode indexed,
//! symbolic, absolute, and immediate addressing modes.
//!
//! # Modules
//!
//! * [`decoder`]      — typed instruction decoder ([`decoder::Msp430Insn`]).
//! * [`lifter`]       — LLIL-equivalent IL lifter ([`lifter::IlOp`]).
//! * [`disassembler`] — linear + recursive disassembly, AT&T formatter.
//! * [`emulator`]     — step-level software emulator with peripheral I/O.
//! * [`analysis`]     — function / ISR detection, string scanning, xrefs.

pub mod analysis;
pub mod decoder;
pub mod disassembler;
pub mod emulator;
pub mod lifter;
pub mod msp430_decoder;
pub mod msp430_registers;

/// Higher-level MSP430 analysis: MemoryMapAnalyzer, PowerModeAnalysis,
/// CriticalSectionDetector, WatchdogPatterns, FlashWriteDetector,
/// BootloaderAnalysis, Msp430Analysis.
///
pub mod msp430_analysis;

/// MSP430 peripheral model: Peripheral trait, Timer_A, USCI, ADC10/ADC12,
/// WatchdogTimer, PortRegisters, FlashController, and PeripheralBus.
pub mod msp430_peripherals;

/// Comprehensive MSP430/MSP430X full decoder: Msp430FullDecoder, X_extended,
/// PUSHM/POPM, RPT repeat prefix, MOVA/CMPA/ADDA/SUBA.
pub mod msp430_full_decoder;

/// MSP430X extended instruction set: 20-bit address space, MOVA/CMPA/ADDA/SUBA,
/// PUSHM/POPM, RRCM/RRUM/RLAM/RRAM, CALLA/RETA, BRA.
pub mod msp430x_extended;

/// MSP430 SFR address map: SfrEntry, PeripheralKind, sfr_name_at().
pub mod msp430_sfr_map;

/// MSP430 interrupt vector table: Msp430InterruptTable, InterruptVector, IsrInfo, vector_at().
pub mod msp430_interrupt_table;

/// MSP430 calling conventions: Msp430CallingConvention, ArgRegister, ReturnReg, stack_arg_offset().
pub mod msp430_calling_convention;
pub mod msp430_addressing_modes;
pub mod msp430_interrupt_vectors;
pub mod msp430_peripheral_map;

use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
use rustre_core::{
    address::Address,
    arch::{BranchCondition, RegisterKind},
    endian::Endian,
    errors::CoreError,
};

// ── Register definitions ─────────────────────────────────────────────────────

/// MSP430 register identifiers.
pub mod regs {
    pub const PC: u32 = 0; // R0 — Program Counter
    pub const SP: u32 = 1; // R1 — Stack Pointer
    pub const SR: u32 = 2; // R2 — Status Register / CG1
    pub const CG2: u32 = 3; // R3 — Constant Generator 2
    pub const R4: u32 = 4;
    pub const R5: u32 = 5;
    pub const R6: u32 = 6;
    pub const R7: u32 = 7;
    pub const R8: u32 = 8;
    pub const R9: u32 = 9;
    pub const R10: u32 = 10;
    pub const R11: u32 = 11;
    pub const R12: u32 = 12;
    pub const R13: u32 = 13;
    pub const R14: u32 = 14;
    pub const R15: u32 = 15;
}

/// Status Register bit masks.
pub mod sr_bits {
    /// Carry flag.
    pub const C: u16 = 1 << 0;
    /// Zero flag.
    pub const Z: u16 = 1 << 1;
    /// Negative flag.
    pub const N: u16 = 1 << 2;
    /// General Interrupt Enable.
    pub const GIE: u16 = 1 << 3;
    /// CPU Off.
    pub const CPUOFF: u16 = 1 << 4;
    /// Oscillator Off.
    pub const OSCOFF: u16 = 1 << 5;
    /// System Clock Generator 0.
    pub const SCG0: u16 = 1 << 6;
    /// System Clock Generator 1.
    pub const SCG1: u16 = 1 << 7;
    /// Overflow flag.
    pub const V: u16 = 1 << 8;
}

// ── Interrupt vectors ─────────────────────────────────────────────────────────

/// Well-known MSP430 interrupt vector addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptVector {
    /// Power-On Reset / Watchdog Timer.
    Reset,
    /// Non-Maskable Interrupt 1.
    Nmi1,
    /// Timer A capture/compare 0.
    TimerA0,
    /// Timer A capture/compare 1–4 / overflow.
    TimerA1,
    /// USCI A0 / B0 transmit.
    UscitxA0B0,
    /// USCI A0 / B0 receive.
    UsciRxA0B0,
    /// Watchdog timer interval.
    Watchdog,
    /// Comparator A.
    ComparatorA,
    /// Port 2.
    Port2,
    /// Port 1.
    Port1,
}

impl InterruptVector {
    /// Return the vector table address for this interrupt.
    #[must_use]
    pub const fn address(self) -> u16 {
        match self {
            Self::Port1 => 0xFFE2,
            Self::Port2 => 0xFFE4,
            Self::ComparatorA => 0xFFE6,
            Self::Watchdog => 0xFFE8,
            Self::UsciRxA0B0 => 0xFFEA,
            Self::UscitxA0B0 => 0xFFEC,
            Self::TimerA1 => 0xFFEE,
            Self::TimerA0 => 0xFFF0,
            Self::Nmi1 => 0xFFFC,
            Self::Reset => 0xFFFE,
        }
    }

    /// Return the name of this interrupt vector.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Reset => "RESET",
            Self::Nmi1 => "NMI",
            Self::TimerA0 => "TIMERA0",
            Self::TimerA1 => "TIMERA1",
            Self::UscitxA0B0 => "USCI_TX",
            Self::UsciRxA0B0 => "USCI_RX",
            Self::Watchdog => "WDT",
            Self::ComparatorA => "COMP_A",
            Self::Port2 => "PORT2",
            Self::Port1 => "PORT1",
        }
    }

    /// Return all known interrupt vectors.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Reset,
            Self::Nmi1,
            Self::TimerA0,
            Self::TimerA1,
            Self::UscitxA0B0,
            Self::UsciRxA0B0,
            Self::Watchdog,
            Self::ComparatorA,
            Self::Port2,
            Self::Port1,
        ]
    }
}

// ── Addressing mode ───────────────────────────────────────────────────────────

/// MSP430 source/destination addressing modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrMode {
    /// Rn — register direct.
    Register,
    /// offset(Rn) — register indexed.
    Indexed,
    /// &ADDR — absolute (uses R2/SR base).
    Absolute,
    /// @Rn — register indirect.
    Indirect,
    /// @Rn+ — register indirect with auto-increment.
    IndirectAutoInc,
    /// #N — immediate (PC indirect auto-inc).
    Immediate,
    /// Constant from constant generator (R2/R3 with special AS values).
    Constant(i8),
    /// ADDR — symbolic (PC-relative indexed).
    Symbolic,
}

impl AddrMode {
    /// Number of extension words required.
    #[must_use]
    pub const fn ext_words(self) -> usize {
        match self {
            Self::Register | Self::Indirect | Self::IndirectAutoInc => 0,
            Self::Indexed | Self::Absolute | Self::Immediate | Self::Symbolic => 1,
            Self::Constant(_) => 0,
        }
    }

    /// Return a human-readable mode name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Register => "Register",
            Self::Indexed => "Indexed",
            Self::Absolute => "Absolute",
            Self::Indirect => "Indirect",
            Self::IndirectAutoInc => "IndirectAutoInc",
            Self::Immediate => "Immediate",
            Self::Constant(_) => "Constant",
            Self::Symbolic => "Symbolic",
        }
    }

    /// Return `true` if this mode reads from memory.
    #[must_use]
    pub const fn reads_memory(self) -> bool {
        matches!(
            self,
            Self::Indexed
                | Self::Absolute
                | Self::Indirect
                | Self::IndirectAutoInc
                | Self::Symbolic
        )
    }

    /// Return `true` if this mode writes to memory.
    #[must_use]
    pub const fn writes_memory(self) -> bool {
        matches!(self, Self::Indexed | Self::Absolute | Self::Symbolic)
    }
}

// ── Constant generator ────────────────────────────────────────────────────────

/// Decode the constant-generator value from (reg, `as_bits`).
/// Returns `Some(value)` if this is a constant-generator combination.
#[must_use]
pub const fn constant_generator(reg: u8, as_bits: u8) -> Option<i8> {
    match (reg, as_bits) {
        (2, 0) => None, // SR register mode (not CG)
        (2, 1) => None, // SR indexed (not CG)
        (2, 2) => Some(4),
        (2, 3) => Some(8),
        (3, 0) => Some(0),
        (3, 1) => Some(1),
        (3, 2) => Some(2),
        (3, 3) => Some(-1),
        _ => None,
    }
}

/// Resolve the addressing mode for a source operand given AS bits and register.
#[must_use]
pub const fn src_addr_mode(as_bits: u8, reg: u8) -> AddrMode {
    if let Some(c) = constant_generator(reg, as_bits) {
        return AddrMode::Constant(c);
    }
    match as_bits {
        0 => AddrMode::Register,
        1 => {
            if reg == 2 {
                AddrMode::Absolute
            } else {
                AddrMode::Indexed
            }
        }
        2 => AddrMode::Indirect,
        _ => {
            if reg == 0 {
                AddrMode::Immediate
            } else {
                AddrMode::IndirectAutoInc
            }
        }
    }
}

// ── Register name ─────────────────────────────────────────────────────────────

/// Return the canonical name for MSP430 register `r`.
#[must_use]
pub const fn reg_name(r: u8) -> &'static str {
    match r {
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
        _ => "Rx",
    }
}

/// Return `.B` if `bw != 0`, otherwise `.W`.
#[must_use]
pub const fn bw_suffix(bw: u8) -> &'static str {
    if bw != 0 { ".B" } else { ".W" }
}

// ── Operand formatting ────────────────────────────────────────────────────────

/// Format a source operand given mode, register, and optional extension word.
#[must_use]
pub fn format_src(as_bits: u8, reg: u8, ext: Option<u16>) -> String {
    match src_addr_mode(as_bits, reg) {
        AddrMode::Register => reg_name(reg).to_string(),
        AddrMode::Indexed => format!("{}({})", ext.unwrap_or(0) as i16, reg_name(reg)),
        AddrMode::Absolute => format!("&0x{:04X}", ext.unwrap_or(0)),
        AddrMode::Indirect => format!("@{}", reg_name(reg)),
        AddrMode::IndirectAutoInc => format!("@{}+", reg_name(reg)),
        AddrMode::Immediate => format!("#0x{:04X}", ext.unwrap_or(0)),
        AddrMode::Constant(c) => format!("#{c}"),
        AddrMode::Symbolic => format!("0x{:04X}", ext.unwrap_or(0)),
    }
}

/// Format a destination operand given AD bit, register, and optional extension word.
#[must_use]
pub fn format_dst(ad: u8, reg: u8, ext: Option<u16>) -> String {
    match ad {
        0 => reg_name(reg).to_string(),
        _ => {
            if reg == 2 {
                format!("&0x{:04X}", ext.unwrap_or(0))
            } else {
                format!("{}({})", ext.unwrap_or(0) as i16, reg_name(reg))
            }
        }
    }
}

// ── Emulated instructions ─────────────────────────────────────────────────────

/// Check if a two-operand instruction is actually an emulated (pseudo) instruction.
/// Returns `Some(mnemonic)` if so.
#[must_use]
pub const fn check_emulated(
    opcode4: u8,
    src_reg: u8,
    dst_reg: u8,
    as_bits: u8,
    ad: u8,
    bw: u8,
) -> Option<&'static str> {
    match (opcode4, src_reg, dst_reg, as_bits, ad) {
        // MOV #0, dst  => CLR dst  (constant-generator encoding: R3, as=0)
        (4, 3, _, 0, _) if bw == 0 => Some("CLR.W"),
        (4, 3, _, 0, _) if bw != 0 => Some("CLR.B"),
        // MOV #0, dst  => CLR dst  (immediate-mode encoding: R0/PC, as=3, immediate=0)
        // The caller must have verified that the immediate extension word is 0.
        (4, 0, _, 3, _) if bw == 0 => Some("CLR.W"),
        (4, 0, _, 3, _) if bw != 0 => Some("CLR.B"),
        // MOV @SP+, PC => RET
        (4, 1, 0, 3, 0) => Some("RET"),
        // ADD #-1, dst => DEC
        (5, 3, _, 3, _) => Some("DEC"),
        // ADD #1, dst  => INC
        (5, 3, _, 1, _) => Some("INC"),
        // SUB #1, dst  => DEC (via sub immediate)
        // XOR #-1, dst => INV
        (14, 3, _, 3, _) => Some("INV"),
        // MOV Rn, Rn   => NOP (same src and dst register, register mode)
        (4, s, d, 0, 0) if s == d => Some("NOP"),
        _ => None,
    }
}

// ── Decoder ───────────────────────────────────────────────────────────────────

/// Decoded MSP430 instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInstr {
    pub mnemonic: String,
    pub operands: String,
    pub size: usize,
    pub flags: InstrFlags,
    /// Branch target address, if known statically.
    pub branch_target: Option<u64>,
}

/// Decode one MSP430 instruction from `bytes` at address `pc`.
///
/// # Errors
/// Returns `CoreError::InvalidInput` if `bytes` is too short.
pub fn decode(bytes: &[u8], pc: u64) -> Result<DecodedInstr, CoreError> {
    if bytes.len() < 2 {
        return Err(CoreError::InvalidFormat {
            message: "need at least 2 bytes".into(),
        });
    }
    let word = u16::from_le_bytes([bytes[0], bytes[1]]);

    let ext_at = |off: usize| -> Option<u16> {
        if bytes.len() >= off + 2 {
            Some(u16::from_le_bytes([bytes[off], bytes[off + 1]]))
        } else {
            None
        }
    };

    // ── Format III: Jump (bits 15-13 == 001) ─────────────────────────────────
    let hi3 = (word >> 13) as u8;
    if hi3 == 0b001 {
        return decode_jump(word, pc);
    }

    // ── Format II: Single-operand (bits 15-10 == 0001 00) ────────────────────
    let hi6 = (word >> 10) & 0x3F;
    if hi6 == 0b00_0100 {
        return decode_single_op(word, bytes, ext_at, pc);
    }

    // ── Format I: Two-operand (opcode in bits 15-12, >= 4) ───────────────────
    let opcode4 = (word >> 12) as u8;
    if opcode4 >= 4 {
        return decode_two_op(word, bytes, ext_at, opcode4);
    }

    // Unknown / data word.
    Ok(DecodedInstr {
        mnemonic: "DC.W".into(),
        operands: format!("0x{word:04X}"),
        size: 2,
        flags: InstrFlags::NONE,
        branch_target: None,
    })
}

fn decode_jump(word: u16, pc: u64) -> Result<DecodedInstr, CoreError> {
    let cond = ((word >> 10) & 7) as u8;
    let raw_offset = word & 0x3FF;
    // Sign-extend 10-bit value.
    let offset = if raw_offset & 0x200 != 0 {
        (raw_offset as i16) | (-0x400_i16)
    } else {
        raw_offset as i16
    };
    let target = (pc as i64)
        .wrapping_add(2)
        .wrapping_add(i64::from(offset) * 2) as u64;

    let (mn, is_cond) = match cond {
        0 => ("JNE", true),
        1 => ("JEQ", true),
        2 => ("JNC", true),
        3 => ("JC", true),
        4 => ("JN", true),
        5 => ("JGE", true),
        6 => ("JL", true),
        _ => ("JMP", false),
    };

    let mut flags = InstrFlags::BRANCH;
    if is_cond {
        flags |= InstrFlags::CONDITIONAL;
    }

    Ok(DecodedInstr {
        mnemonic: mn.to_string(),
        operands: format!("0x{:04X}", target & 0xFFFFF),
        size: 2,
        flags,
        branch_target: Some(target),
    })
}

fn decode_single_op(
    word: u16,
    _bytes: &[u8],
    ext_at: impl Fn(usize) -> Option<u16>,
    _pc: u64,
) -> Result<DecodedInstr, CoreError> {
    let opcode3 = ((word >> 7) & 7) as u8;
    let bw = ((word >> 6) & 1) as u8;
    let as_bits = ((word >> 4) & 3) as u8;
    let reg = (word & 0xF) as u8;

    // Special case: RETI = 0x1300
    if word == 0x1300 {
        return Ok(DecodedInstr {
            mnemonic: "RETI".into(),
            operands: String::new(),
            size: 2,
            flags: InstrFlags::RET,
            branch_target: None,
        });
    }

    let mode = src_addr_mode(as_bits, reg);
    let ext_words = mode.ext_words();
    let size = 2 + ext_words * 2;
    let ext1 = ext_at(2);
    let src = format_src(as_bits, reg, ext1);

    let (mn, flags) = match opcode3 {
        0 => (format!("RRC{}", bw_suffix(bw)), InstrFlags::NONE),
        1 => ("SWPB".to_string(), InstrFlags::NONE),
        2 => (format!("RRA{}", bw_suffix(bw)), InstrFlags::NONE),
        3 => ("SXT".to_string(), InstrFlags::NONE),
        4 => (format!("PUSH{}", bw_suffix(bw)), InstrFlags::WRITE_MEM),
        5 => ("CALL".to_string(), InstrFlags::CALL),
        6 => ("RETI".to_string(), InstrFlags::RET),
        _ => ("DC.W".to_string(), InstrFlags::NONE),
    };

    Ok(DecodedInstr {
        mnemonic: mn,
        operands: src,
        size,
        flags,
        branch_target: None,
    })
}

fn decode_two_op(
    word: u16,
    _bytes: &[u8],
    ext_at: impl Fn(usize) -> Option<u16>,
    opcode4: u8,
) -> Result<DecodedInstr, CoreError> {
    let src_reg = ((word >> 8) & 0xF) as u8;
    let ad = ((word >> 7) & 1) as u8;
    let bw = ((word >> 6) & 1) as u8;
    let as_bits = ((word >> 4) & 3) as u8;
    let dst_reg = (word & 0xF) as u8;

    let src_mode = src_addr_mode(as_bits, src_reg);
    let src_ext_words = src_mode.ext_words();
    let dst_ext_words = usize::from(ad != 0);
    let total_ext = src_ext_words + dst_ext_words;
    let size = 2 + total_ext * 2;

    let ext1 = ext_at(2);
    let ext2 = ext_at(2 + src_ext_words * 2);

    // Check for emulated instructions.
    // The CLR-from-immediate rules in check_emulated require that the source
    // immediate extension word is zero; verify that here before consulting it.
    let immediate_is_zero = ext1 == Some(0);
    let emulated = if opcode4 == 4 && src_reg == 0 && as_bits == 3 && !immediate_is_zero {
        None
    } else {
        check_emulated(opcode4, src_reg, dst_reg, as_bits, ad, bw)
    };

    let mn = if let Some(emu) = emulated {
        emu.to_string()
    } else {
        match opcode4 {
            4 => format!("MOV{}", bw_suffix(bw)),
            5 => format!("ADD{}", bw_suffix(bw)),
            6 => format!("ADDC{}", bw_suffix(bw)),
            7 => format!("SUBC{}", bw_suffix(bw)),
            8 => format!("SUB{}", bw_suffix(bw)),
            9 => format!("CMP{}", bw_suffix(bw)),
            10 => format!("DADD{}", bw_suffix(bw)),
            11 => format!("BIT{}", bw_suffix(bw)),
            12 => format!("BIC{}", bw_suffix(bw)),
            13 => format!("BIS{}", bw_suffix(bw)),
            14 => format!("XOR{}", bw_suffix(bw)),
            15 => format!("AND{}", bw_suffix(bw)),
            _ => "DC.W".to_string(),
        }
    };

    let src = format_src(as_bits, src_reg, ext1);
    let dst = format_dst(ad, dst_reg, ext2);
    let operands = format!("{src},{dst}");

    // Memory access flags.
    let mem_flags = match (src_mode, ad) {
        (AddrMode::Register, 0) => InstrFlags::NONE,
        (_, 1) => InstrFlags::READ_MEM | InstrFlags::WRITE_MEM,
        _ => InstrFlags::READ_MEM,
    };

    // CALL via MOV @SP+, PC is handled by emulated above (RET).
    let flags = mem_flags;

    Ok(DecodedInstr {
        mnemonic: mn,
        operands,
        size,
        flags,
        branch_target: None,
    })
}

// ── MSP430X extended instructions ─────────────────────────────────────────────

/// MSP430X 20-bit extended instruction extensions.
/// Extension word prefix: 0001 10[Z] [SX] [A/L] [n-1/CG] [DST/SRC]
pub mod msp430x {
    use super::CoreError;

    /// Check if `word` is an MSP430X extension prefix word.
    #[must_use]
    pub const fn is_extension_word(word: u16) -> bool {
        // Extension word: bits 15-11 = 0001 1
        (word >> 11) == 0b0_0011
    }

    /// Decode an MSP430X `MOVA`, `CMPA`, `ADDA`, `SUBA` instruction.
    #[must_use]
    pub const fn decode_format_a(word: u16) -> Option<&'static str> {
        let bits = (word >> 8) & 0xF;
        match bits {
            0b0000 => Some("MOVA"),
            0b0001 => Some("CMPA"),
            0b0010 => Some("ADDA"),
            0b0011 => Some("SUBA"),
            _ => None,
        }
    }

    /// Return the 20-bit address range for MSP430X (vs 16-bit for MSP430).
    #[must_use]
    pub const fn max_address() -> u32 {
        0x000F_FFFF
    }

    /// Decode the `RRAM`, `RLAM`, `RRUM`, `RRCM` rotate/shift extended instructions.
    ///
    /// These are MSP430X Format II extended instructions where the extension word
    /// modifies a base Format II single-operand opcode.
    #[must_use]
    pub const fn decode_rotate_extended(ext_word: u16, base_word: u16) -> Option<&'static str> {
        // Extension word must be valid.
        if !is_extension_word(ext_word) {
            return None;
        }
        // opcode3 from the base word bits 9-7.
        let opcode3 = ((base_word >> 7) & 7) as u8;
        // A/L bit in extension word bit 6 selects 20-bit (A) vs 16-bit (L) operation.
        let al_bit = (ext_word >> 6) & 1;
        // ZC bit (extension word bit 8) distinguishes RLAM from RRA when opcode3=2.
        let zc_bit = (ext_word >> 8) & 1;
        match opcode3 {
            0 => Some(if al_bit != 0 { "RRCM.A" } else { "RRCM.W" }),
            1 => Some(if al_bit != 0 { "RRUM.A" } else { "RRUM.W" }),
            2 if zc_bit != 0 => Some(if al_bit != 0 { "RLAM.A" } else { "RLAM.W" }),
            2 => Some(if al_bit != 0 { "RRAM.A" } else { "RRAM.W" }),
            3 => Some(if al_bit != 0 { "RRAM.A" } else { "RRAM.W" }),
            _ => None,
        }
    }

    /// Decode an MSP430X `PUSHM`/`POPM` push/pop multiple register instruction.
    ///
    /// Format: `0001 01 n-1[4] A/L[1] Rdst[4]`
    ///
    /// # Errors
    /// Returns an error if `word` doesn't match the PUSHM/POPM encoding.
    pub fn decode_pushm_popm(word: u16) -> Result<(&'static str, u8, u8, bool), CoreError> {
        // MSP430X PUSHM/POPM: bits[15:10] = 000101, bit9 = 0 PUSHM / 1 POPM,
        // bit8 = A/L (0 = .A 20-bit, 1 = .W 16-bit), bits[7:4] = n-1,
        // bits[3:0] = dst. So PUSHM.A=0x14nd, PUSHM.W=0x15nd, POPM.A=0x16nd,
        // POPM.W=0x17nd — exactly what this function's own doc comment always
        // described.
        //
        // The previous decode read `top5 = word >> 11` AND
        // `n_minus_1 = (word >> 8) & 0xF`, so BIT 11 belonged to both fields.
        // POPM has that bit set, which leaked into the count's high bit and
        // made EVERY POPM report n >= 9 (`decode_pushm_popm(0x1804)` returned
        // n = 9 for what the caller meant as n = 1). It also placed A/L at bit 4,
        // inside the n-1 field.
        //
        // NOTE: a SECOND implementation of this same decode exists at
        // msp430x_extended.rs:488, and it does NOT agree with this one either —
        // it tests `word >> 10 == 0b000001`, i.e. 0x0400..0x07FF, where the ISA
        // puts PUSHM/POPM at 0x1400..0x17FF (bits[15:10] = 000101 = 5). That
        // copy is still wrong; it is left alone here rather than edited blind,
        // but the duplication itself is the underlying defect.
        if (word >> 10) != 0b00_0101 {
            return Err(CoreError::InvalidFormat {
                message: "not PUSHM/POPM".into(),
            });
        }
        let is_pushm = (word >> 9) & 1 == 0;
        let n_minus_1 = ((word >> 4) & 0xF) as u8;
        let al_bit = ((word >> 8) & 1) != 0;
        let dst_reg = (word & 0xF) as u8;
        let mnemonic = if is_pushm { "PUSHM" } else { "POPM" };
        Ok((mnemonic, n_minus_1 + 1, dst_reg, al_bit))
    }

    /// Encode an MSP430X extension word for a two-operand instruction.
    ///
    /// The extension word format is:
    /// `0001 1 ZC [0] [SX] [A/L] [n/CG4] [n/CG5] [DST3] [SRC3]`
    #[must_use]
    pub fn encode_extension_word(zc: bool, sx: bool, al: bool, src_high: u8, dst_high: u8) -> u16 {
        let mut w: u16 = 0b0001_1000_0000_0000;
        if zc {
            w |= 1 << 8;
        }
        if sx {
            w |= 1 << 7;
        }
        if al {
            w |= 1 << 6;
        }
        w |= (u16::from(dst_high) & 0xF) << 4;
        w |= u16::from(src_high) & 0xF;
        w
    }
}

// ── Register file ─────────────────────────────────────────────────────────────

/// Simulated MSP430 register file (16 registers, 16-bit each).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterFile {
    pub regs: [u16; 16],
}

impl RegisterFile {
    /// Create a zeroed register file.
    #[must_use]
    pub const fn new() -> Self {
        Self { regs: [0u16; 16] }
    }

    /// Read a register.
    ///
    /// # Panics
    /// Panics if `r >= 16`.
    #[must_use]
    pub const fn read(&self, r: u8) -> u16 {
        self.regs[r as usize]
    }

    /// Write a register.
    ///
    /// # Panics
    /// Panics if `r >= 16`.
    pub const fn write(&mut self, r: u8, val: u16) {
        self.regs[r as usize] = val;
    }

    /// Return the Program Counter.
    #[must_use]
    pub const fn pc(&self) -> u16 {
        self.regs[0]
    }

    /// Set the Program Counter.
    pub const fn set_pc(&mut self, val: u16) {
        self.regs[0] = val;
    }

    /// Return the Stack Pointer.
    #[must_use]
    pub const fn sp(&self) -> u16 {
        self.regs[1]
    }

    /// Set the Stack Pointer.
    pub const fn set_sp(&mut self, val: u16) {
        self.regs[1] = val;
    }

    /// Return the Status Register.
    #[must_use]
    pub const fn sr(&self) -> u16 {
        self.regs[2]
    }

    /// Return `true` if the Carry flag is set.
    #[must_use]
    pub const fn carry(&self) -> bool {
        self.regs[2] & sr_bits::C != 0
    }

    /// Return `true` if the Zero flag is set.
    #[must_use]
    pub const fn zero(&self) -> bool {
        self.regs[2] & sr_bits::Z != 0
    }

    /// Return `true` if the Negative flag is set.
    #[must_use]
    pub const fn negative(&self) -> bool {
        self.regs[2] & sr_bits::N != 0
    }

    /// Return `true` if the Overflow flag is set.
    #[must_use]
    pub const fn overflow(&self) -> bool {
        self.regs[2] & sr_bits::V != 0
    }

    /// Set a specific SR bit.
    pub const fn set_sr_bit(&mut self, mask: u16, set: bool) {
        if set {
            self.regs[2] |= mask;
        } else {
            self.regs[2] &= !mask;
        }
    }

    /// Return `true` if the CPU-off mode is active (CPUOFF bit set in SR).
    #[must_use]
    pub const fn cpu_off(&self) -> bool {
        self.regs[2] & sr_bits::CPUOFF != 0
    }

    /// Return `true` if general interrupts are enabled (GIE bit set in SR).
    #[must_use]
    pub const fn interrupts_enabled(&self) -> bool {
        self.regs[2] & sr_bits::GIE != 0
    }

    /// Decrement SP by 2 (stack push housekeeping — does NOT write any value).
    ///
    /// `RegisterFile` has no associated memory, so writing the stack word must
    /// be done separately by the caller via `FlatMemory::write_word`.  The old
    /// signature `push(&mut self, _val: u16)` silently discarded the value,
    /// which was a latent state-corruption hazard for any caller that assumed
    /// the value was written.  The parameter has been removed so the compiler
    /// rejects such misuse.
    ///
    /// Returns the new SP value (the address to write the word to).
    pub const fn push(&mut self) -> u16 {
        let new_sp = self.regs[1].wrapping_sub(2);
        self.regs[1] = new_sp;
        new_sp
    }

    /// Pop a 16-bit value from the stack, incrementing SP by 2.
    ///
    /// Returns the address that was popped from (the old SP value).
    pub const fn pop(&mut self) -> u16 {
        let old_sp = self.regs[1];
        self.regs[1] = old_sp.wrapping_add(2);
        old_sp
    }

    /// Update carry, zero, and negative flags from a 16-bit result.
    pub const fn update_flags_word(&mut self, result: u16, carry: bool, overflow: bool) {
        self.set_sr_bit(sr_bits::Z, result == 0);
        self.set_sr_bit(sr_bits::N, result & 0x8000 != 0);
        self.set_sr_bit(sr_bits::C, carry);
        self.set_sr_bit(sr_bits::V, overflow);
    }

    /// Update carry, zero, and negative flags from an 8-bit result.
    pub const fn update_flags_byte(&mut self, result: u8, carry: bool, overflow: bool) {
        self.set_sr_bit(sr_bits::Z, result == 0);
        self.set_sr_bit(sr_bits::N, result & 0x80 != 0);
        self.set_sr_bit(sr_bits::C, carry);
        self.set_sr_bit(sr_bits::V, overflow);
    }
}

impl Default for RegisterFile {
    fn default() -> Self {
        Self::new()
    }
}

// ── ALU operations ────────────────────────────────────────────────────────────

/// Result of an ALU word-width operation, including updated flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AluResult {
    /// The 16-bit result value.
    pub result: u16,
    /// Whether the carry flag should be set.
    pub carry: bool,
    /// Whether the overflow flag should be set.
    pub overflow: bool,
    /// Whether the zero flag should be set.
    pub zero: bool,
    /// Whether the negative flag should be set.
    pub negative: bool,
}

impl AluResult {
    /// Construct from a raw 16-bit result and carry.
    #[must_use]
    pub const fn from_word(result: u16, carry: bool, overflow: bool) -> Self {
        Self {
            result,
            carry,
            overflow,
            zero: result == 0,
            negative: result & 0x8000 != 0,
        }
    }
}

/// Perform a 16-bit ADD operation, returning the result and updated flags.
#[must_use]
pub fn alu_add(src: u16, dst: u16) -> AluResult {
    let wide = u32::from(src).wrapping_add(u32::from(dst));
    let result = wide as u16;
    let carry = wide > 0xFFFF;
    // Overflow: both operands same sign but result has different sign.
    let overflow = (!(src ^ dst) & (src ^ result)) & 0x8000 != 0;
    AluResult::from_word(result, carry, overflow)
}

/// Perform a 16-bit ADD with carry operation.
#[must_use]
pub fn alu_addc(src: u16, dst: u16, c_in: bool) -> AluResult {
    let wide = u32::from(src)
        .wrapping_add(u32::from(dst))
        .wrapping_add(u32::from(c_in));
    let result = wide as u16;
    let carry = wide > 0xFFFF;
    let overflow = (!(src ^ dst) & (src ^ result)) & 0x8000 != 0;
    AluResult::from_word(result, carry, overflow)
}

/// Perform a 16-bit SUB operation (dst - src), returning the result and flags.
#[must_use]
pub fn alu_sub(src: u16, dst: u16) -> AluResult {
    // SUB is implemented as ADD of one's complement + carry-in 1.
    alu_addc(!src, dst, true)
}

/// Perform a 16-bit SUB with borrow (SUBC: dst - src - NOT(C)).
#[must_use]
pub fn alu_subc(src: u16, dst: u16, c_in: bool) -> AluResult {
    alu_addc(!src, dst, c_in)
}

/// Perform a 16-bit AND operation.
#[must_use]
pub const fn alu_and(src: u16, dst: u16) -> AluResult {
    let result = src & dst;
    // AND clears carry and overflow.
    AluResult::from_word(result, false, false)
}

/// Perform a 16-bit OR (BIS) operation.
#[must_use]
pub const fn alu_bis(src: u16, dst: u16) -> AluResult {
    let result = src | dst;
    AluResult::from_word(result, false, false)
}

/// Perform a 16-bit XOR operation.
#[must_use]
pub const fn alu_xor(src: u16, dst: u16) -> AluResult {
    let result = src ^ dst;
    let carry = src & 0x8000 != 0;
    let overflow = (src & 0x8000 != 0) && (dst & 0x8000 != 0);
    AluResult::from_word(result, carry, overflow)
}

/// Perform a 16-bit rotate-right-through-carry (RRC).
#[must_use]
pub fn alu_rrc(val: u16, carry_in: bool) -> AluResult {
    let new_carry = val & 1 != 0;
    let result = (val >> 1) | (u16::from(carry_in) << 15);
    AluResult::from_word(result, new_carry, false)
}

/// Perform a 16-bit arithmetic right shift (RRA).
#[must_use]
pub const fn alu_rra(val: u16) -> AluResult {
    let new_carry = val & 1 != 0;
    let result = ((val as i16) >> 1) as u16;
    AluResult::from_word(result, new_carry, false)
}

/// Perform a 16-bit swap-bytes (SWPB).
#[must_use]
pub const fn alu_swpb(val: u16) -> u16 {
    val.rotate_left(8)
}

/// Perform sign-extend byte to word (SXT): sign-extend bit 7 to bits 15-8.
#[must_use]
pub const fn alu_sxt(val: u16) -> AluResult {
    let result = if val & 0x80 != 0 {
        val | 0xFF00
    } else {
        val & 0x00FF
    };
    let carry = result != 0;
    AluResult::from_word(result, carry, false)
}

// ── Simple flat memory model ──────────────────────────────────────────────────

/// A simple flat byte-addressable memory model for MSP430 simulation.
///
/// Covers the full 64 KiB address space of the base MSP430.
pub struct FlatMemory {
    data: Box<[u8; 0x10000]>,
}

impl FlatMemory {
    /// Create a zero-initialised flat memory.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: Box::new([0u8; 0x10000]),
        }
    }

    /// Read a byte at `addr` (wraps at 64 KiB).
    #[must_use]
    pub fn read_byte(&self, addr: u16) -> u8 {
        self.data[addr as usize]
    }

    /// Write a byte at `addr`.
    pub fn write_byte(&mut self, addr: u16, val: u8) {
        self.data[addr as usize] = val;
    }

    /// Read a little-endian 16-bit word at `addr`.
    #[must_use]
    pub fn read_word(&self, addr: u16) -> u16 {
        let lo = u16::from(self.data[addr as usize]);
        let hi = u16::from(self.data[addr.wrapping_add(1) as usize]);
        lo | (hi << 8)
    }

    /// Write a little-endian 16-bit word at `addr`.
    pub fn write_word(&mut self, addr: u16, val: u16) {
        self.data[addr as usize] = (val & 0xFF) as u8;
        self.data[addr.wrapping_add(1) as usize] = (val >> 8) as u8;
    }

    /// Load a slice of bytes starting at `addr`.
    ///
    /// # Panics
    /// Panics if `bytes` is longer than the available space from `addr` to the
    /// end of the 16-bit address space (0x10000).  This prevents the silent
    /// address wrap that would corrupt the beginning of memory.
    pub fn load(&mut self, addr: u16, bytes: &[u8]) {
        let available = 0x10000usize - addr as usize;
        assert!(
            bytes.len() <= available,
            "FlatMemory::load: {} bytes starting at {:#06x} would wrap past end of address space (max {})",
            bytes.len(), addr, available
        );
        for (i, &b) in bytes.iter().enumerate() {
            self.data[addr as usize + i] = b;
        }
    }

    /// Return a reference to the underlying byte slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.data.as_ref()
    }

    /// Read the reset vector (address stored at 0xFFFE).
    #[must_use]
    pub fn reset_vector(&self) -> u16 {
        self.read_word(0xFFFE)
    }
}

impl Default for FlatMemory {
    fn default() -> Self {
        Self::new()
    }
}

// ── Step-level emulator ───────────────────────────────────────────────────────

/// Lightweight single-step emulator for MSP430 (base 16-bit).
///
/// Executes one decoded instruction at a time against a `FlatMemory` and
/// `RegisterFile`. Does not handle interrupts — only core ALU and data-move
/// semantics are implemented.
pub struct Msp430Emulator {
    /// The current register file state.
    pub regs: RegisterFile,
    /// The flat memory model.
    pub mem: FlatMemory,
    /// Total number of instructions executed.
    pub instr_count: u64,
}

impl Msp430Emulator {
    /// Create a new emulator with zeroed state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            regs: RegisterFile::new(),
            mem: FlatMemory::new(),
            instr_count: 0,
        }
    }

    /// Reset the CPU: load PC from reset vector, clear SR.
    pub fn reset(&mut self) {
        let entry = self.mem.reset_vector();
        self.regs.set_pc(entry);
        self.regs.regs[2] = 0; // clear SR
    }

    /// Read a source operand value given addressing mode details.
    ///
    /// Returns `(value, new_pc)` — `new_pc` accounts for any immediate words
    /// consumed; it is the caller's responsibility to update PC.
    #[must_use]
    pub fn read_src_operand(&mut self, as_bits: u8, reg: u8, pc_after_word: u16) -> (u16, u16) {
        match src_addr_mode(as_bits, reg) {
            AddrMode::Register => (self.regs.read(reg), pc_after_word),
            AddrMode::Indirect => {
                let addr = self.regs.read(reg);
                (self.mem.read_word(addr), pc_after_word)
            }
            AddrMode::IndirectAutoInc => {
                let addr = self.regs.read(reg);
                let val = self.mem.read_word(addr);
                self.regs.write(reg, addr.wrapping_add(2));
                (val, pc_after_word)
            }
            AddrMode::Immediate => {
                let imm = self.mem.read_word(pc_after_word);
                (imm, pc_after_word.wrapping_add(2))
            }
            AddrMode::Indexed => {
                let offset = self.mem.read_word(pc_after_word) as i16;
                let base = self.regs.read(reg);
                let ea = base.wrapping_add(offset as u16);
                (self.mem.read_word(ea), pc_after_word.wrapping_add(2))
            }
            AddrMode::Absolute => {
                let abs = self.mem.read_word(pc_after_word);
                (self.mem.read_word(abs), pc_after_word.wrapping_add(2))
            }
            AddrMode::Symbolic => {
                let offset = self.mem.read_word(pc_after_word) as i16;
                let ea = pc_after_word.wrapping_add(offset as u16);
                (self.mem.read_word(ea), pc_after_word.wrapping_add(2))
            }
            AddrMode::Constant(c) => (c as u16, pc_after_word),
        }
    }

    /// Execute one instruction at the current PC.
    ///
    /// Returns `Ok(())` on success, or an error if the bytes couldn't be decoded.
    ///
    /// # Errors
    /// Returns `CoreError::InvalidFormat` if the instruction cannot be decoded.
    pub fn step(&mut self) -> Result<(), CoreError> {
        let pc = self.regs.pc();
        let pc_after = pc.wrapping_add(2);

        // Fetch two bytes.
        let lo = self.mem.read_byte(pc);
        let hi = self.mem.read_byte(pc.wrapping_add(1));
        let word = u16::from_le_bytes([lo, hi]);

        self.regs.set_pc(pc_after);

        // Dispatch.
        let hi3 = (word >> 13) as u8;
        if hi3 == 0b001 {
            self.exec_jump(word);
        } else {
            let hi6 = (word >> 10) & 0x3F;
            if hi6 == 0b00_0100 {
                self.exec_single_op(word)?;
            } else {
                let opcode4 = (word >> 12) as u8;
                if opcode4 >= 4 {
                    self.exec_two_op(word, opcode4)?;
                }
                // else: data word, ignore
            }
        }

        self.instr_count += 1;
        Ok(())
    }

    fn exec_jump(&mut self, word: u16) {
        let cond = ((word >> 10) & 7) as u8;
        let raw_offset = word & 0x3FF;
        let offset = if raw_offset & 0x200 != 0 {
            (raw_offset as i16) | (-0x400_i16)
        } else {
            raw_offset as i16
        };

        let taken = match cond {
            0 => !self.regs.zero(),                            // JNE/JNZ
            1 => self.regs.zero(),                             // JEQ/JZ
            2 => !self.regs.carry(),                           // JNC/JLO
            3 => self.regs.carry(),                            // JC/JHS
            4 => self.regs.negative(),                         // JN
            5 => self.regs.negative() == self.regs.overflow(), // JGE
            6 => self.regs.negative() != self.regs.overflow(), // JL
            _ => true,                                         // JMP
        };

        if taken {
            let cur_pc = self.regs.pc();
            let new_pc = (i32::from(cur_pc) + i32::from(offset) * 2) as u16;
            self.regs.set_pc(new_pc);
        }
    }

    fn exec_single_op(&mut self, word: u16) -> Result<(), CoreError> {
        if word == 0x1300 {
            // RETI: pop SR then PC.
            let sp = self.regs.sp();
            let sr_val = self.mem.read_word(sp);
            let pc_val = self.mem.read_word(sp.wrapping_add(2));
            self.regs.regs[2] = sr_val;
            self.regs.set_pc(pc_val);
            self.regs.set_sp(sp.wrapping_add(4));
            return Ok(());
        }

        let opcode3 = ((word >> 7) & 7) as u8;
        let bw = ((word >> 6) & 1) as u8;
        let as_bits = ((word >> 4) & 3) as u8;
        let reg = (word & 0xF) as u8;
        let cur_pc = self.regs.pc();

        match opcode3 {
            0 /* RRC */ => {
                let (val, new_pc) = self.read_src_operand(as_bits, reg, cur_pc);
                self.regs.set_pc(new_pc);
                let result = if bw == 0 {
                    let r = alu_rrc(val, self.regs.carry());
                    self.regs.update_flags_word(r.result, r.carry, r.overflow);
                    r.result
                } else {
                    let rv = alu_rrc(val & 0xFF, self.regs.carry());
                    self.regs.update_flags_byte(rv.result as u8, rv.carry, rv.overflow);
                    rv.result & 0xFF
                };
                if as_bits == 0 {
                    self.regs.write(reg, result);
                }
            }
            2 /* RRA */ => {
                let (val, new_pc) = self.read_src_operand(as_bits, reg, cur_pc);
                self.regs.set_pc(new_pc);
                let r = alu_rra(val);
                self.regs.update_flags_word(r.result, r.carry, r.overflow);
                if as_bits == 0 {
                    self.regs.write(reg, r.result);
                }
            }
            1 /* SWPB */ => {
                let (val, new_pc) = self.read_src_operand(as_bits, reg, cur_pc);
                self.regs.set_pc(new_pc);
                let result = alu_swpb(val);
                if as_bits == 0 {
                    self.regs.write(reg, result);
                }
            }
            3 /* SXT */ => {
                let (val, new_pc) = self.read_src_operand(as_bits, reg, cur_pc);
                self.regs.set_pc(new_pc);
                let r = alu_sxt(val);
                self.regs.update_flags_word(r.result, r.carry, r.overflow);
                if as_bits == 0 {
                    self.regs.write(reg, r.result);
                }
            }
            4 /* PUSH */ => {
                let (val, new_pc) = self.read_src_operand(as_bits, reg, cur_pc);
                self.regs.set_pc(new_pc);
                let sp = self.regs.sp().wrapping_sub(2);
                self.regs.set_sp(sp);
                if bw == 0 {
                    self.mem.write_word(sp, val);
                } else {
                    self.mem.write_byte(sp, (val & 0xFF) as u8);
                }
            }
            5 /* CALL */ => {
                let (target, new_pc) = self.read_src_operand(as_bits, reg, cur_pc);
                self.regs.set_pc(new_pc);
                // Push return address (new_pc already advanced past any ext word).
                let ret_addr = self.regs.pc();
                let sp = self.regs.sp().wrapping_sub(2);
                self.regs.set_sp(sp);
                self.mem.write_word(sp, ret_addr);
                self.regs.set_pc(target);
            }
            _ => {}
        }
        Ok(())
    }

    fn exec_two_op(&mut self, word: u16, opcode4: u8) -> Result<(), CoreError> {
        let src_reg = ((word >> 8) & 0xF) as u8;
        let ad = ((word >> 7) & 1) as u8;
        let bw = ((word >> 6) & 1) as u8;
        let as_bits = ((word >> 4) & 3) as u8;
        let dst_reg = (word & 0xF) as u8;

        let cur_pc = self.regs.pc();
        let (src_val, new_pc) = self.read_src_operand(as_bits, src_reg, cur_pc);
        self.regs.set_pc(new_pc);

        // Read destination effective address or register.
        let (dst_val, dst_ea): (u16, Option<u16>) = if ad == 0 {
            (self.regs.read(dst_reg), None)
        } else {
            // Indexed or absolute destination: next word is offset/address.
            let pc2 = self.regs.pc();
            let ext = self.mem.read_word(pc2);
            self.regs.set_pc(pc2.wrapping_add(2));
            let ea = if dst_reg == 2 {
                ext
            } else {
                self.regs.read(dst_reg).wrapping_add(ext)
            };
            (self.mem.read_word(ea), Some(ea))
        };

        let carry_in = self.regs.carry();

        let result: AluResult = match opcode4 {
            4 => AluResult::from_word(src_val, false, false), // MOV
            5 => alu_add(src_val, dst_val),                   // ADD
            6 => alu_addc(src_val, dst_val, carry_in),        // ADDC
            7 => alu_subc(src_val, dst_val, carry_in),        // SUBC
            8 => alu_sub(src_val, dst_val),                   // SUB
            9 => alu_sub(src_val, dst_val),                   // CMP (discard)
            11 => {
                
                alu_and(src_val, dst_val)
            } // BIT (discard)
            12 => AluResult::from_word(dst_val & !src_val, false, false), // BIC
            13 => AluResult::from_word(dst_val | src_val, false, false), // BIS
            14 => alu_xor(src_val, dst_val),                  // XOR
            15 => alu_and(src_val, dst_val),                  // AND
            _ => AluResult::from_word(dst_val, false, false),
        };

        // Update flags for all except MOV/BIC/BIS.
        match opcode4 {
            4 | 12 | 13 => {}
            _ => {
                if bw == 0 {
                    self.regs
                        .update_flags_word(result.result, result.carry, result.overflow);
                } else {
                    self.regs
                        .update_flags_byte(result.result as u8, result.carry, result.overflow);
                }
            }
        }

        // Write result (not for CMP / BIT which are test-only).
        if opcode4 != 9 && opcode4 != 11 {
            let write_val = if bw != 0 {
                result.result & 0xFF
            } else {
                result.result
            };
            match dst_ea {
                None => self.regs.write(dst_reg, write_val),
                Some(ea) => {
                    if bw == 0 {
                        self.mem.write_word(ea, write_val);
                    } else {
                        self.mem.write_byte(ea, write_val as u8);
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for Msp430Emulator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Control-flow graph types ──────────────────────────────────────────────────

/// A basic block in a MSP430 control-flow graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    /// Start address of the block.
    pub start: u64,
    /// End address of the block (exclusive: start of next instruction after last).
    pub end: u64,
    /// Addresses of successor blocks.
    pub successors: Vec<u64>,
    /// Decoded instructions in order.
    pub instrs: Vec<DecodedInstr>,
}

impl BasicBlock {
    /// Create a new empty basic block starting at `start`.
    #[must_use]
    pub const fn new(start: u64) -> Self {
        Self {
            start,
            end: start,
            successors: Vec::new(),
            instrs: Vec::new(),
        }
    }

    /// Return the number of instructions in the block.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instrs.len()
    }

    /// Return `true` if the block contains no instructions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instrs.is_empty()
    }
}

/// Perform a simple linear recursive-descent CFG reconstruction starting at
/// `entry` within `bytes` (mapped at `base_addr`).
///
/// This is a best-effort algorithm: it stops at function calls, returns,
/// data words, and already-visited addresses. Branches within the image are
/// followed recursively up to `max_blocks`.
///
/// # Errors
/// Returns `CoreError::InvalidFormat` on decode failure of the first block.
pub fn build_cfg(
    bytes: &[u8],
    base_addr: u64,
    entry: u64,
    max_blocks: usize,
) -> Result<Vec<BasicBlock>, CoreError> {
    use std::collections::{HashSet, VecDeque};
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut worklist: VecDeque<u64> = VecDeque::from([entry]);
    let mut visited: HashSet<u64> = HashSet::new();

    while let Some(addr) = worklist.pop_front() {
        if blocks.len() >= max_blocks {
            break;
        }
        if !visited.insert(addr) {
            continue;
        }

        if addr < base_addr || addr >= base_addr + bytes.len() as u64 {
            continue;
        }

        let mut block = BasicBlock::new(addr);
        let mut cur = addr;

        loop {
            if cur < base_addr || cur >= base_addr + bytes.len() as u64 {
                break;
            }
            let off = (cur - base_addr) as usize;
            let slice = &bytes[off..];
            let dec = match decode(slice, cur) {
                Ok(d) => d,
                Err(_) => break,
            };

            let next_addr = cur + dec.size as u64;
            let is_term = dec
                .flags
                .intersects(InstrFlags::BRANCH | InstrFlags::RET | InstrFlags::CALL);

            if dec.flags.contains(InstrFlags::BRANCH) {
                if let Some(target) = dec.branch_target {
                    block.successors.push(target);
                    worklist.push_back(target);
                }
                if dec.flags.contains(InstrFlags::CONDITIONAL) {
                    block.successors.push(next_addr);
                    worklist.push_back(next_addr);
                }
            }

            block.instrs.push(dec);
            cur = next_addr;
            block.end = cur;

            if is_term {
                break;
            }
        }

        if !block.is_empty() {
            blocks.push(block);
        }
    }

    Ok(blocks)
}

// ── Main architecture struct ──────────────────────────────────────────────────

/// TI MSP430 / MSP430X architecture.
#[derive(Debug, Clone)]
pub struct Msp430Arch {
    /// Address width: 16 for base MSP430, 20 for MSP430X.
    pub bits: u32,
}

impl Msp430Arch {
    /// Create a standard 16-bit MSP430 architecture.
    #[must_use]
    pub const fn new_16() -> Self {
        Self { bits: 16 }
    }

    /// Create a 20-bit MSP430X architecture.
    #[must_use]
    pub const fn new_20() -> Self {
        Self { bits: 20 }
    }

    /// Return `true` if this is the 20-bit MSP430X variant.
    #[must_use]
    pub const fn is_msp430x(&self) -> bool {
        self.bits == 20
    }

    /// Return all known interrupt vectors.
    #[must_use]
    pub const fn interrupt_vectors(&self) -> &'static [InterruptVector] {
        InterruptVector::all()
    }

    /// Return the maximum addressable value.
    #[must_use]
    pub const fn max_addr(&self) -> u64 {
        if self.is_msp430x() {
            0x000F_FFFF
        } else {
            0xFFFF
        }
    }
}

impl Default for Msp430Arch {
    fn default() -> Self {
        Self::new_16()
    }
}

impl Architecture for Msp430Arch {
    fn name(&self) -> &str {
        if self.is_msp430x() {
            "msp430x"
        } else {
            "msp430"
        }
    }

    fn pointer_size(&self) -> usize {
        if self.is_msp430x() { 4 } else { 2 }
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        let dec = decode(bytes, address.as_u64())?;
        let mut instr = Instruction::new(
            address,
            dec.size,
            dec.mnemonic,
            bytes[..dec.size.min(bytes.len())].to_vec(),
        );
        instr.operands = dec.operands;
        instr.flags = dec.flags;
        Ok(instr)
    }

    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo> {
        if !instr
            .flags
            .intersects(InstrFlags::BRANCH | InstrFlags::CALL)
        {
            return vec![];
        }
        // Try to parse the target address from the operand string. The operand
        // may carry an immediate prefix (`#`) and/or a hex prefix (`0x`), e.g.
        // CALL renders as `#0x4400` and JMP as `0x4002`, so strip both before
        // collecting the leading run of hex digits.
        let ops = instr
            .operands
            .trim_start_matches('#')
            .trim_start_matches("0x");
        let hex: String = ops.chars().take_while(char::is_ascii_hexdigit).collect();
        if let Ok(target_val) = u64::from_str_radix(&hex, 16) {
            if instr.flags.contains(InstrFlags::CALL) {
                return vec![BranchInfo::call(target_val)];
            } else if instr.flags.contains(InstrFlags::CONDITIONAL) {
                return vec![BranchInfo::conditional_jump(
                    target_val,
                    BranchCondition::Custom(0),
                )];
            }
            return vec![BranchInfo::unconditional_jump(target_val)];
        }
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        let mut regs = vec![
            RegisterInfo::new("PC", regs::PC, 2, RegisterKind::ProgramCounter),
            RegisterInfo::new("SP", regs::SP, 2, RegisterKind::Stack),
            RegisterInfo::new("SR", regs::SR, 2, RegisterKind::Flags),
            RegisterInfo::new("CG", regs::CG2, 2, RegisterKind::General),
        ];
        for i in 4u32..=15 {
            regs.push(RegisterInfo::new(
                format!("R{i}"),
                regs::R4 + (i - 4),
                2,
                RegisterKind::General,
            ));
        }
        regs
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![
            CallingConvention::new("msp430_gcc")
                .with_int_args(vec!["R15".into(), "R14".into(), "R13".into(), "R12".into()])
                .with_return_regs(vec!["R15".into(), "R14".into()]),
            CallingConvention::new("msp430_iar")
                .with_int_args(vec!["R12".into(), "R13".into(), "R14".into(), "R15".into()])
                .with_return_regs(vec!["R12".into(), "R13".into()]),
        ]
    }
}

// ── Linear disassembler ───────────────────────────────────────────────────────

/// Linear-sweep disassembler for MSP430 code.
pub struct Msp430LinearDisassembler<'a> {
    arch: &'a Msp430Arch,
    bytes: &'a [u8],
    base: Address,
    offset: usize,
}

impl<'a> Msp430LinearDisassembler<'a> {
    /// Create a new linear disassembler.
    #[must_use]
    pub const fn new(arch: &'a Msp430Arch, bytes: &'a [u8], base: Address) -> Self {
        Self {
            arch,
            bytes,
            base,
            offset: 0,
        }
    }

    /// Return the current disassembly offset.
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

impl Iterator for Msp430LinearDisassembler<'_> {
    type Item = Result<Instruction, CoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done() {
            return None;
        }
        let addr = self.base + self.offset as u64;
        let result = self.arch.disassemble(addr, &self.bytes[self.offset..]);
        match &result {
            Ok(instr) => self.offset += instr.size,
            Err(_) => self.offset += 2,
        }
        Some(result)
    }
}

// ── Assembler helpers ─────────────────────────────────────────────────────────

/// Encode a Format III jump instruction.
///
/// # Errors
/// Returns `CoreError::InvalidInput` if `cond > 7` or `offset` is out of range.
pub fn encode_jump(cond: u8, offset: i16) -> Result<u16, CoreError> {
    if cond > 7 {
        return Err(CoreError::InvalidFormat {
            message: format!("cond {cond} > 7"),
        });
    }
    if !(-512..=511).contains(&offset) {
        return Err(CoreError::InvalidFormat {
            message: format!("jump offset {offset} out of 10-bit range"),
        });
    }
    let raw = (offset as u16) & 0x3FF;
    Ok(0x2000 | (u16::from(cond) << 10) | raw)
}

/// Encode a Format I two-operand instruction (no extension words).
///
/// # Errors
/// Returns `CoreError::InvalidInput` if `opcode4 < 4` or `opcode4 > 15`.
pub fn encode_two_op(
    opcode4: u8,
    src: u8,
    ad: u8,
    bw: u8,
    as_: u8,
    dst: u8,
) -> Result<u16, CoreError> {
    if !(4..=15).contains(&opcode4) {
        return Err(CoreError::InvalidFormat {
            message: format!("two-op opcode {opcode4} out of range"),
        });
    }
    Ok((u16::from(opcode4) << 12)
        | (u16::from(src) << 8)
        | (u16::from(ad) << 7)
        | (u16::from(bw) << 6)
        | (u16::from(as_) << 4)
        | u16::from(dst))
}

/// Encode a Format II single-operand instruction.
///
/// `opcode3` must be in range 0..=6; `bw` is 0 for word, 1 for byte;
/// `as_` is the 2-bit addressing mode; `reg` is the target register.
///
/// # Errors
/// Returns `CoreError::InvalidFormat` if `opcode3 > 6`.
pub fn encode_single_op(opcode3: u8, bw: u8, as_: u8, reg: u8) -> Result<u16, CoreError> {
    if opcode3 > 6 {
        return Err(CoreError::InvalidFormat {
            message: format!("single-op opcode3 {opcode3} out of range"),
        });
    }
    Ok(0x1000 | (u16::from(opcode3) << 7) | (u16::from(bw) << 6) | (u16::from(as_) << 4) | u16::from(reg))
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn arch() -> Msp430Arch {
        Msp430Arch::default()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    // ── Format III: Jump ──────────────────────────────────────────────────────

    #[test]
    fn test_jmp_forward() {
        let instr = arch().disassemble(addr(0x4000), &[0x00, 0x3C]).unwrap();
        assert_eq!(instr.mnemonic, "JMP");
        assert!(instr.flags.contains(InstrFlags::BRANCH));
        assert!(!instr.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_jne() {
        let instr = arch().disassemble(addr(0x4000), &[0xFE, 0x23]).unwrap();
        assert_eq!(instr.mnemonic, "JNE");
        assert!(instr.flags.contains(InstrFlags::CONDITIONAL));
        assert_eq!(instr.size, 2);
    }

    #[test]
    fn test_jeq() {
        let instr = arch().disassemble(addr(0x4000), &[0x00, 0x24]).unwrap();
        assert_eq!(instr.mnemonic, "JEQ");
    }

    #[test]
    fn test_jnc() {
        let instr = arch().disassemble(addr(0x4000), &[0x00, 0x28]).unwrap();
        assert_eq!(instr.mnemonic, "JNC");
        assert!(instr.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_jc() {
        let instr = arch().disassemble(addr(0x4000), &[0x00, 0x2C]).unwrap();
        assert_eq!(instr.mnemonic, "JC");
        assert!(instr.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_jge() {
        let instr = arch().disassemble(addr(0x4000), &[0x00, 0x34]).unwrap();
        assert_eq!(instr.mnemonic, "JGE");
    }

    #[test]
    fn test_jl() {
        let instr = arch().disassemble(addr(0x4000), &[0x00, 0x38]).unwrap();
        assert_eq!(instr.mnemonic, "JL");
    }

    // ── Format I: Two-operand ─────────────────────────────────────────────────

    #[test]
    fn test_mov_reg_reg() {
        // MOV.W R4, R5 = 0x4504
        let instr = arch().disassemble(addr(0x4000), &[0x04, 0x45]).unwrap();
        assert_eq!(instr.mnemonic, "MOV.W");
        assert_eq!(instr.size, 2);
    }

    #[test]
    fn test_mov_imm_reg() {
        // MOV.W #0x1234, R4
        let instr = arch()
            .disassemble(addr(0x4000), &[0x34, 0x40, 0x34, 0x12])
            .unwrap();
        assert_eq!(instr.mnemonic, "MOV.W");
        assert_eq!(instr.size, 4);
        assert!(instr.operands.contains("1234"));
    }

    #[test]
    fn test_add_word() {
        let instr = arch().disassemble(addr(0x4000), &[0x04, 0x55]).unwrap();
        assert_eq!(instr.mnemonic, "ADD.W");
    }

    #[test]
    fn test_add_byte() {
        let instr = arch().disassemble(addr(0x4000), &[0x44, 0x55]).unwrap();
        assert_eq!(instr.mnemonic, "ADD.B");
    }

    #[test]
    fn test_sub_word() {
        let instr = arch().disassemble(addr(0x4000), &[0x04, 0x85]).unwrap();
        assert_eq!(instr.mnemonic, "SUB.W");
    }

    #[test]
    fn test_cmp_word() {
        let instr = arch().disassemble(addr(0x4000), &[0x04, 0x95]).unwrap();
        assert_eq!(instr.mnemonic, "CMP.W");
    }

    #[test]
    fn test_and_word() {
        let instr = arch().disassemble(addr(0x4000), &[0x04, 0xF5]).unwrap();
        assert_eq!(instr.mnemonic, "AND.W");
    }

    #[test]
    fn test_bis_word() {
        let instr = arch().disassemble(addr(0x4000), &[0x04, 0xD5]).unwrap();
        assert_eq!(instr.mnemonic, "BIS.W");
    }

    #[test]
    fn test_xor_word() {
        let instr = arch().disassemble(addr(0x4000), &[0x04, 0xE5]).unwrap();
        assert_eq!(instr.mnemonic, "XOR.W");
    }

    #[test]
    fn test_bit_word() {
        let instr = arch().disassemble(addr(0x4000), &[0x04, 0xB5]).unwrap();
        assert_eq!(instr.mnemonic, "BIT.W");
    }

    #[test]
    fn test_dadd_word() {
        // DADD.W R4, R5 = 0xA504
        let instr = arch().disassemble(addr(0x4000), &[0x04, 0xA5]).unwrap();
        assert_eq!(instr.mnemonic, "DADD.W");
    }

    // ── Format II: Single-operand ─────────────────────────────────────────────

    #[test]
    fn test_call_immediate() {
        // CALL #0x4400 = B0 12 00 44
        let instr = arch()
            .disassemble(addr(0x4000), &[0xB0, 0x12, 0x00, 0x44])
            .unwrap();
        assert_eq!(instr.mnemonic, "CALL");
        assert!(instr.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_reti() {
        // RETI = 00 13
        let instr = arch().disassemble(addr(0x4000), &[0x00, 0x13]).unwrap();
        assert_eq!(instr.mnemonic, "RETI");
        assert!(instr.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_push_word() {
        let instr = arch().disassemble(addr(0x4000), &[0x04, 0x12]).unwrap();
        assert!(instr.mnemonic.starts_with("PUSH"));
    }

    // ── Misc ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_truncated_error() {
        let result = arch().disassemble(addr(0x4000), &[0x04]);
        assert!(result.is_err());
    }

    #[test]
    fn test_registers_count() {
        assert_eq!(arch().registers().len(), 16);
    }

    #[test]
    fn test_name_endian() {
        assert_eq!(arch().name(), "msp430");
        assert_eq!(arch().endian(), Endian::Little);
        assert_eq!(arch().pointer_size(), 2);
    }

    #[test]
    fn test_msp430x_name() {
        let a = Msp430Arch::new_20();
        assert_eq!(a.name(), "msp430x");
        assert_eq!(a.pointer_size(), 4);
        assert!(a.is_msp430x());
    }

    #[test]
    fn test_calling_convention() {
        let cc = arch().calling_conventions();
        assert_eq!(cc.len(), 2);
        assert_eq!(cc[0].name, "msp430_gcc");
        assert_eq!(cc[1].name, "msp430_iar");
    }

    #[test]
    fn test_linear_disassembler() {
        let code = [0x04u8, 0x45, 0x04, 0x55]; // MOV.W R4,R5; ADD.W R4,R5
        let a = arch();
        let instrs: Vec<_> = Msp430LinearDisassembler::new(&a, &code, addr(0x4000))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[0].mnemonic, "MOV.W");
        assert_eq!(instrs[1].mnemonic, "ADD.W");
    }

    // ── Register file ─────────────────────────────────────────────────────────

    #[test]
    fn test_register_file_read_write() {
        let mut rf = RegisterFile::new();
        rf.write(4, 0xABCD);
        assert_eq!(rf.read(4), 0xABCD);
    }

    #[test]
    fn test_register_file_pc_sp() {
        let mut rf = RegisterFile::new();
        rf.set_pc(0x4000);
        rf.set_sp(0x0300);
        assert_eq!(rf.pc(), 0x4000);
        assert_eq!(rf.sp(), 0x0300);
    }

    #[test]
    fn test_register_file_flags() {
        let mut rf = RegisterFile::new();
        assert!(!rf.carry());
        rf.set_sr_bit(sr_bits::C, true);
        assert!(rf.carry());
        rf.set_sr_bit(sr_bits::Z, true);
        assert!(rf.zero());
    }

    // ── Constant generator ────────────────────────────────────────────────────

    #[test]
    fn test_constant_generator() {
        assert_eq!(constant_generator(3, 0), Some(0));
        assert_eq!(constant_generator(3, 1), Some(1));
        assert_eq!(constant_generator(3, 2), Some(2));
        assert_eq!(constant_generator(3, 3), Some(-1));
        assert_eq!(constant_generator(2, 2), Some(4));
        assert_eq!(constant_generator(2, 3), Some(8));
        assert_eq!(constant_generator(4, 0), None);
    }

    // ── Assembler helpers ─────────────────────────────────────────────────────

    #[test]
    fn test_encode_jump_jmp() {
        // JMP +0 should produce the same as the test byte sequence [0x00, 0x3C].
        let encoded = encode_jump(7, 0).unwrap();
        assert_eq!(encoded, 0x3C00);
    }

    #[test]
    fn test_encode_jump_cond_out_of_range() {
        assert!(encode_jump(8, 0).is_err());
    }

    #[test]
    fn test_encode_jump_offset_out_of_range() {
        assert!(encode_jump(7, 512).is_err());
    }

    #[test]
    fn test_encode_two_op() {
        // MOV.W R4, R5 (reg-reg, no ext words)
        // opcode=4 (MOV), src=R4 in bits 11-8, dst=R5 in bits 3-0 → 0x4405.
        let w = encode_two_op(4, 4, 0, 0, 0, 5).unwrap();
        assert_eq!(w, 0x4405);
    }

    #[test]
    fn test_encode_two_op_out_of_range() {
        assert!(encode_two_op(3, 0, 0, 0, 0, 0).is_err());
    }

    // ── Interrupt vectors ─────────────────────────────────────────────────────

    #[test]
    fn test_interrupt_vectors_all() {
        let all = InterruptVector::all();
        assert!(!all.is_empty());
        assert_eq!(InterruptVector::Reset.address(), 0xFFFE);
        assert_eq!(InterruptVector::Reset.name(), "RESET");
    }

    #[test]
    fn test_msp430x_extension_word() {
        // Extension word: bits 15-11 = 0b0_0011 = 0x1800
        assert!(msp430x::is_extension_word(0x1800));
        assert!(!msp430x::is_extension_word(0x4000));
        assert_eq!(msp430x::max_address(), 0x000F_FFFF);
    }

    // ── get_branches ──────────────────────────────────────────────────────────

    #[test]
    fn test_get_branches_jmp() {
        use rustre_core::arch::BranchKind;
        let code = [0x00u8, 0x3C]; // JMP +0 → target = 0x4002
        let a = arch();
        let instr = a.disassemble(addr(0x4000), &code).unwrap();
        let branches = a.get_branches(&instr);
        assert_eq!(branches.len(), 1);
        assert!(branches[0].is_unconditional());
        assert_eq!(branches[0].kind, BranchKind::UnconditionalJump);
    }

    #[test]
    fn test_get_branches_call() {
        use rustre_core::arch::BranchKind;
        let code = [0xB0u8, 0x12, 0x00, 0x44]; // CALL #0x4400
        let a = arch();
        let instr = a.disassemble(addr(0x4000), &code).unwrap();
        let branches = a.get_branches(&instr);
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].kind, BranchKind::Call);
    }

    #[test]
    fn test_get_branches_normal_instr() {
        let code = [0x04u8, 0x45]; // MOV.W R4,R5
        let a = arch();
        let instr = a.disassemble(addr(0x4000), &code).unwrap();
        assert!(a.get_branches(&instr).is_empty());
    }

    // ── ALU operations ────────────────────────────────────────────────────────

    #[test]
    fn test_alu_add_basic() {
        let r = alu_add(0x0001, 0x0001);
        assert_eq!(r.result, 0x0002);
        assert!(!r.carry);
        assert!(!r.zero);
        assert!(!r.negative);
    }

    #[test]
    fn test_alu_add_carry() {
        let r = alu_add(0xFFFF, 0x0001);
        assert_eq!(r.result, 0x0000);
        assert!(r.carry);
        assert!(r.zero);
    }

    #[test]
    fn test_alu_add_overflow() {
        // 0x7FFF + 1 = 0x8000 → signed overflow: positive + positive = negative.
        let r = alu_add(0x7FFF, 0x0001);
        assert_eq!(r.result, 0x8000);
        assert!(r.overflow);
        assert!(!r.carry);
    }

    #[test]
    fn test_alu_sub_basic() {
        let r = alu_sub(0x0001, 0x0002);
        assert_eq!(r.result, 0x0001);
        assert!(r.carry); // MSP430: carry = NOT borrow
    }

    #[test]
    fn test_alu_sub_zero() {
        let r = alu_sub(0x0005, 0x0005);
        assert_eq!(r.result, 0x0000);
        assert!(r.zero);
        assert!(r.carry);
    }

    #[test]
    fn test_alu_and() {
        let r = alu_and(0xF0F0, 0xFF00);
        assert_eq!(r.result, 0xF000);
        assert!(!r.carry);
        assert!(!r.overflow);
    }

    #[test]
    fn test_alu_xor() {
        let r = alu_xor(0x00FF, 0xFF00);
        assert_eq!(r.result, 0xFFFF);
    }

    #[test]
    fn test_alu_rrc_carry_in() {
        // 0x0002, carry_in=1 → result = 0x8001, carry_out = 0.
        let r = alu_rrc(0x0002, true);
        assert_eq!(r.result, 0x8001);
        assert!(!r.carry);
    }

    #[test]
    fn test_alu_rra_arithmetic() {
        // 0x8000 >> 1 arithmetic = 0xC000 (sign bit preserved).
        let r = alu_rra(0x8000);
        assert_eq!(r.result, 0xC000);
        assert!(!r.carry);
    }

    #[test]
    fn test_alu_swpb() {
        assert_eq!(alu_swpb(0xABCD), 0xCDAB);
        assert_eq!(alu_swpb(0x0001), 0x0100);
    }

    #[test]
    fn test_alu_sxt_positive() {
        let r = alu_sxt(0x007F);
        assert_eq!(r.result, 0x007F);
        assert!(r.carry);
    }

    #[test]
    fn test_alu_sxt_negative() {
        let r = alu_sxt(0x0080);
        assert_eq!(r.result, 0xFF80);
        assert!(r.carry);
    }

    #[test]
    fn test_alu_sxt_zero() {
        let r = alu_sxt(0x0000);
        assert_eq!(r.result, 0x0000);
        assert!(!r.carry);
    }

    // ── FlatMemory ────────────────────────────────────────────────────────────

    #[test]
    fn test_flat_memory_byte_rw() {
        let mut m = FlatMemory::new();
        m.write_byte(0x0200, 0xAB);
        assert_eq!(m.read_byte(0x0200), 0xAB);
    }

    #[test]
    fn test_flat_memory_word_rw() {
        let mut m = FlatMemory::new();
        m.write_word(0x0200, 0x1234);
        assert_eq!(m.read_word(0x0200), 0x1234);
        // Verify little-endian storage.
        assert_eq!(m.read_byte(0x0200), 0x34);
        assert_eq!(m.read_byte(0x0201), 0x12);
    }

    #[test]
    fn test_flat_memory_load() {
        let mut m = FlatMemory::new();
        m.load(0x4000, &[0x01, 0x02, 0x03]);
        assert_eq!(m.read_byte(0x4000), 0x01);
        assert_eq!(m.read_byte(0x4001), 0x02);
        assert_eq!(m.read_byte(0x4002), 0x03);
    }

    #[test]
    fn test_flat_memory_reset_vector() {
        let mut m = FlatMemory::new();
        m.write_word(0xFFFE, 0x4400);
        assert_eq!(m.reset_vector(), 0x4400);
    }

    // ── Emulator ──────────────────────────────────────────────────────────────

    #[test]
    fn test_emulator_mov_reg_reg() {
        // MOV.W R5, R4 — R5 holds 0x1234, after step R4 should be 0x1234.
        // Encoding: MOV.W (opcode=4) src=R5 (5), ad=0, bw=0, as=0, dst=R4 (4)
        // word = (4<<12)|(5<<8)|(0<<7)|(0<<6)|(0<<4)|4 = 0x4504
        let mut emu = Msp430Emulator::new();
        emu.mem.write_word(0x4000, 0x4504);
        emu.regs.set_pc(0x4000);
        emu.regs.write(5, 0x1234);
        emu.step().unwrap();
        assert_eq!(emu.regs.read(4), 0x1234);
        assert_eq!(emu.regs.pc(), 0x4002);
    }

    #[test]
    fn test_emulator_add_reg_reg() {
        // ADD.W R4, R5 (opcode=5): src=R4(4), dst=R5(5), all reg-reg.
        // word = (5<<12)|(4<<8)|(0<<7)|(0<<6)|(0<<4)|5 = 0x5405
        let mut emu = Msp430Emulator::new();
        emu.mem.write_word(0x4000, 0x5405);
        emu.regs.set_pc(0x4000);
        emu.regs.write(4, 3);
        emu.regs.write(5, 7);
        emu.step().unwrap();
        assert_eq!(emu.regs.read(5), 10);
    }

    #[test]
    fn test_emulator_jmp_taken() {
        // JMP offset=0 at 0x4000 → target = 0x4002.
        let mut emu = Msp430Emulator::new();
        emu.mem.write_word(0x4000, 0x3C00); // JMP +0
        emu.regs.set_pc(0x4000);
        emu.step().unwrap();
        // PC advanced to 0x4002, then JMP offset 0 means target = 0x4002.
        assert_eq!(emu.regs.pc(), 0x4002);
    }

    #[test]
    fn test_emulator_push_pop_word() {
        // PUSH.W R4 then manually verify memory; then check SP change.
        // PUSH.W R4: opcode3=4, bw=0, as=0 (reg), reg=4 → 0x1204
        let mut emu = Msp430Emulator::new();
        emu.regs.set_sp(0x0300);
        emu.regs.write(4, 0xBEEF);
        emu.mem.write_word(0x4000, 0x1204);
        emu.regs.set_pc(0x4000);
        emu.step().unwrap();
        assert_eq!(emu.regs.sp(), 0x02FE);
        assert_eq!(emu.mem.read_word(0x02FE), 0xBEEF);
    }

    #[test]
    fn test_emulator_rrc_word() {
        // RRC.W R4 (opcode3=0, bw=0, as=0, reg=4) = 0x1004
        let mut emu = Msp430Emulator::new();
        emu.regs.write(4, 0x0002);
        emu.regs.set_sr_bit(sr_bits::C, false);
        emu.mem.write_word(0x4000, 0x1004);
        emu.regs.set_pc(0x4000);
        emu.step().unwrap();
        assert_eq!(emu.regs.read(4), 0x0001);
        assert!(!emu.regs.carry());
    }

    #[test]
    fn test_emulator_swpb() {
        // SWPB R4: opcode3=1, bw=0, as=0, reg=4 = 0x1084
        let mut emu = Msp430Emulator::new();
        emu.regs.write(4, 0xABCD);
        emu.mem.write_word(0x4000, 0x1084);
        emu.regs.set_pc(0x4000);
        emu.step().unwrap();
        assert_eq!(emu.regs.read(4), 0xCDAB);
    }

    #[test]
    fn test_emulator_instr_count() {
        let mut emu = Msp430Emulator::new();
        // MOV.W R4, R5 twice
        emu.mem.write_word(0x4000, 0x4504);
        emu.mem.write_word(0x4002, 0x4504);
        emu.regs.set_pc(0x4000);
        emu.step().unwrap();
        emu.step().unwrap();
        assert_eq!(emu.instr_count, 2);
    }

    // ── CFG building ──────────────────────────────────────────────────────────

    #[test]
    fn test_build_cfg_single_block() {
        // MOV.W R4,R5 ; ADD.W R4,R5 ; RET (RETI = 0x1300)
        let code: &[u8] = &[0x04, 0x45, 0x04, 0x55, 0x00, 0x13];
        let blocks = build_cfg(code, 0x4000, 0x4000, 16).unwrap();
        assert!(!blocks.is_empty());
        assert_eq!(blocks[0].start, 0x4000);
    }

    #[test]
    fn test_build_cfg_branch() {
        // JMP +0 (self-loop)
        let code: &[u8] = &[0x00, 0x3C]; // JMP offset=0 → 0x4002
        let blocks = build_cfg(code, 0x4000, 0x4000, 16).unwrap();
        assert!(!blocks.is_empty());
    }

    // ── encode_single_op ──────────────────────────────────────────────────────

    #[test]
    fn test_encode_single_op_rrc() {
        // RRC.W R4: opcode3=0, bw=0, as=0 (reg), reg=4
        let w = encode_single_op(0, 0, 0, 4).unwrap();
        assert_eq!(w, 0x1004);
    }

    #[test]
    fn test_encode_single_op_push_byte() {
        // PUSH.B R5: opcode3=4, bw=1, as=0, reg=5
        let w = encode_single_op(4, 1, 0, 5).unwrap();
        // 0x1000 | (4<<7) | (1<<6) | (0<<4) | 5 = 0x1000 | 0x200 | 0x40 | 5 = 0x1245
        assert_eq!(w, 0x1245);
    }

    #[test]
    fn test_encode_single_op_out_of_range() {
        assert!(encode_single_op(7, 0, 0, 0).is_err());
    }

    // ── AddrMode helpers ──────────────────────────────────────────────────────

    #[test]
    fn test_addr_mode_reads_memory() {
        assert!(AddrMode::Indexed.reads_memory());
        assert!(AddrMode::Absolute.reads_memory());
        assert!(AddrMode::Indirect.reads_memory());
        assert!(AddrMode::IndirectAutoInc.reads_memory());
        assert!(!AddrMode::Register.reads_memory());
        assert!(!AddrMode::Immediate.reads_memory());
        assert!(!AddrMode::Constant(0).reads_memory());
    }

    #[test]
    fn test_addr_mode_writes_memory() {
        assert!(AddrMode::Indexed.writes_memory());
        assert!(AddrMode::Absolute.writes_memory());
        assert!(!AddrMode::Register.writes_memory());
        assert!(!AddrMode::Indirect.writes_memory());
        assert!(!AddrMode::IndirectAutoInc.writes_memory());
    }

    // ── RegisterFile push/pop ─────────────────────────────────────────────────

    #[test]
    fn test_register_file_push_pop() {
        let mut rf = RegisterFile::new();
        rf.set_sp(0x0300);
        let new_sp = rf.push();
        assert_eq!(new_sp, 0x02FE);
        assert_eq!(rf.sp(), 0x02FE);
        let old_sp = rf.pop();
        assert_eq!(old_sp, 0x02FE);
        assert_eq!(rf.sp(), 0x0300);
    }

    #[test]
    fn test_register_file_cpu_off() {
        let mut rf = RegisterFile::new();
        assert!(!rf.cpu_off());
        rf.set_sr_bit(sr_bits::CPUOFF, true);
        assert!(rf.cpu_off());
    }

    #[test]
    fn test_register_file_interrupts_enabled() {
        let mut rf = RegisterFile::new();
        assert!(!rf.interrupts_enabled());
        rf.set_sr_bit(sr_bits::GIE, true);
        assert!(rf.interrupts_enabled());
    }

    // ── MSP430X helpers ───────────────────────────────────────────────────────

    #[test]
    fn test_msp430x_encode_extension_word() {
        let w = msp430x::encode_extension_word(false, false, true, 0, 0);
        // 0b0001_1000_0000_0000 | (1<<6) = 0x1840
        assert_eq!(w & 0xF840, 0x1840);
    }

    #[test]
    fn test_msp430x_decode_pushm_popm() {
        // PUSHM.W #2, R15 in the REAL MSP430X layout:
        //   bits[15:10] = 000101, bit9 = 0 (PUSHM), bit8 = A/L,
        //   bits[7:4] = n-1, bits[3:0] = dst
        //   = 0001 0101 0001 1111 = 0x151F
        //
        // This test previously built 0x111F from the old, field-overlapping
        // decode (bits 11-8 as n-1, A/L at bit 4) — a layout in which bit 11
        // belonged to BOTH the opcode and the count, which is exactly why every
        // POPM decoded with n >= 9. It pinned that bug in place.
        let word: u16 = 0x151F;
        let (mn, n, dst, al) = msp430x::decode_pushm_popm(word).unwrap();
        assert_eq!(mn, "PUSHM");
        assert_eq!(n, 2, "n-1 = 1 in bits[7:4]");
        assert_eq!(dst, 15);
        assert!(al, "bit8 = 1 is the .W form");

        // The old encoding must now be rejected outright: 0x111F has
        // bits[15:10] = 000100, which is not the PUSHM/POPM opcode at all.
        assert!(msp430x::decode_pushm_popm(0x111F).is_err());
    }

    #[test]
    fn test_msp430x_decode_pushm_invalid() {
        assert!(msp430x::decode_pushm_popm(0x4000).is_err());
    }
}
