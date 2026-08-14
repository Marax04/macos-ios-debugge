//! `rustre-arch-avr`
//!
//! Atmel AVR microcontroller architecture implementation for the `RustRE` Suite.
//! Supports Attiny, Atmega, and Xmega variants.

pub mod avr_analysis;
pub mod avr_emulator;
pub mod avr_interrupt_model;
pub mod avr_pgm_memory;

/// AVR higher-level code analysis: AvrPrologue (PUSH R28/R29), AvrEpilogue,
/// AvrStringDetector, AvrBootloaderPattern, AvrSignatureScanner, AvrCodeAnalysis.
///
pub mod avr_code_analysis;

/// Full device descriptors.
///
/// Covers `ATmega328P`, `ATmega2560`, `ATtiny85`, `ATtiny13`,
/// `ATxmega256A3U` — flash/SRAM/EEPROM, SFR maps, IVTs, fuse bits.
pub mod avr_devices;

/// IN/OUT address decoder.
///
/// Provides register names, bit-field descriptions, timer/USART
/// configuration helpers, `ATmega328P` and `ATmega2560` I/O maps.
pub mod avr_io_decoder;

pub mod avr_decoder;
pub mod avr_disassembler;
pub mod avr_registers;
pub mod avr_io_map;
pub mod avr_io_registers;
pub mod avr_interrupt_vectors;
pub mod avr_fuse_bits;

use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
use rustre_core::arch::{BranchCondition, RegisterKind};
use rustre_core::{address::Address, endian::Endian, errors::CoreError};

// ── Variant ───────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvrVariant {
    Attiny,
    Atmega,
    Xmega,
}

impl AvrVariant {
    const fn name(self) -> &'static str {
        match self {
            Self::Attiny => "avr-tiny",
            Self::Atmega => "avr-mega",
            Self::Xmega => "avr-xmega",
        }
    }
}

// ── Register IDs ──────────────────────────────────────────────────────────────
const REG_R0: u32 = 0;
const REG_SREG: u32 = 32;
const REG_SP: u32 = 33;
const REG_PC: u32 = 34;
// X = R26:R27, Y = R28:R29, Z = R30:R31
const REG_X: u32 = 35;
const REG_Y: u32 = 36;
const REG_Z: u32 = 37;

// ── Decode result ─────────────────────────────────────────────────────────────
struct Decoded {
    mnemonic: String,
    operands: String,
    size: usize, // in bytes (2 or 4)
    flags: InstrFlags,
}

fn decoded(mn: &str, ops: String, size: usize, flags: InstrFlags) -> Decoded {
    Decoded {
        mnemonic: mn.to_string(),
        operands: ops,
        size,
        flags,
    }
}

const fn branch_flags() -> InstrFlags {
    InstrFlags::BRANCH.union(InstrFlags::CONDITIONAL)
}

const fn rdrr(word: u16) -> (u16, u16) {
    let d = (word >> 4) & 0x1F;
    let r = ((word & 0x0200) >> 5) | (word & 0x0F);
    (d, r)
}

/// Decode fixed AVR opcodes (no operands).
fn decode_avr_fixed(word: u16) -> Option<Decoded> {
    match word {
        // ── NOP ──────────────────────────────────────────────────────────────
        0x0000 => Some(decoded("NOP", String::new(), 2, InstrFlags::NONE)),
        // ── SLEEP ─────────────────────────────────────────────────────────────
        0x9588 => Some(decoded("SLEEP", String::new(), 2, InstrFlags::NONE)),
        // ── WDR ──────────────────────────────────────────────────────────────
        0x95A8 => Some(decoded("WDR", String::new(), 2, InstrFlags::NONE)),
        // ── BREAK ────────────────────────────────────────────────────────────
        0x9598 => Some(decoded("BREAK", String::new(), 2, InstrFlags::NONE)),
        // ── RET ──────────────────────────────────────────────────────────────
        0x9508 => Some(decoded("RET", String::new(), 2, InstrFlags::RET)),
        // ── RETI ─────────────────────────────────────────────────────────────
        0x9518 => Some(decoded("RETI", String::new(), 2, InstrFlags::RET)),
        // ── IJMP ─────────────────────────────────────────────────────────────
        0x9409 => Some(decoded(
            "IJMP",
            String::new(),
            2,
            InstrFlags::BRANCH.union(InstrFlags::INDIRECT),
        )),
        // ── ICALL ────────────────────────────────────────────────────────────
        0x9509 => Some(decoded(
            "ICALL",
            String::new(),
            2,
            InstrFlags::CALL.union(InstrFlags::INDIRECT),
        )),
        // ── EIJMP ────────────────────────────────────────────────────────────
        0x9419 => Some(decoded(
            "EIJMP",
            String::new(),
            2,
            InstrFlags::BRANCH.union(InstrFlags::INDIRECT),
        )),
        // ── EICALL ───────────────────────────────────────────────────────────
        0x9519 => Some(decoded(
            "EICALL",
            String::new(),
            2,
            InstrFlags::CALL.union(InstrFlags::INDIRECT),
        )),
        // ── LPM (r0) ──────────────────────────────────────────────────────────
        0x95C8 => Some(decoded("LPM", String::new(), 2, InstrFlags::READ_MEM)),
        // ── SPM ───────────────────────────────────────────────────────────────
        0x95E8 => Some(decoded("SPM", String::new(), 2, InstrFlags::WRITE_MEM)),
        _ => None,
    }
}

/// Decode arithmetic/logic AVR instructions.
fn decode_avr_alu(word: u16) -> Option<Decoded> {
    // ── ADD Rd,Rr  0000 11rd dddd rrrr ────────────────────────────────────────
    if (word & 0xFC00) == 0x0C00 {
        let (d, r) = rdrr(word);
        return Some(decoded("ADD", format!("R{d},R{r}"), 2, InstrFlags::NONE));
    }
    // ── ADC Rd,Rr  0001 11rd dddd rrrr ────────────────────────────────────────
    if (word & 0xFC00) == 0x1C00 {
        let (d, r) = rdrr(word);
        return Some(decoded("ADC", format!("R{d},R{r}"), 2, InstrFlags::NONE));
    }
    // ── ADIW Rd+1:Rd,K  1001 0110 KKdd KKKK ─────────────────────────────────
    if (word & 0xFF00) == 0x9600 {
        let d = 24 + (((word >> 4) & 3) * 2);
        let k = ((word & 0xC0) >> 2) | (word & 0x0F);
        return Some(decoded(
            "ADIW",
            format!("R{}:R{},{}", d + 1, d, k),
            2,
            InstrFlags::NONE,
        ));
    }
    // ── SUB Rd,Rr  0001 10rd dddd rrrr ────────────────────────────────────────
    if (word & 0xFC00) == 0x1800 {
        let (d, r) = rdrr(word);
        return Some(decoded("SUB", format!("R{d},R{r}"), 2, InstrFlags::NONE));
    }
    // ── SUBI Rd,K  0101 KKKK dddd KKKK ───────────────────────────────────────
    if (word & 0xF000) == 0x5000 {
        let d = 16 + ((word >> 4) & 0xF);
        let k = ((word & 0x0F00) >> 4) | (word & 0x0F);
        return Some(decoded(
            "SUBI",
            format!("R{d},${k:02X}"),
            2,
            InstrFlags::NONE,
        ));
    }
    // ── SBC Rd,Rr  0000 10rd dddd rrrr ────────────────────────────────────────
    if (word & 0xFC00) == 0x0800 {
        let (d, r) = rdrr(word);
        return Some(decoded("SBC", format!("R{d},R{r}"), 2, InstrFlags::NONE));
    }
    // ── SBCI Rd,K  0100 KKKK dddd KKKK ───────────────────────────────────────
    if (word & 0xF000) == 0x4000 {
        let d = 16 + ((word >> 4) & 0xF);
        let k = ((word & 0x0F00) >> 4) | (word & 0x0F);
        return Some(decoded(
            "SBCI",
            format!("R{d},${k:02X}"),
            2,
            InstrFlags::NONE,
        ));
    }
    // ── SBIW Rd+1:Rd,K  1001 0111 KKdd KKKK ─────────────────────────────────
    if (word & 0xFF00) == 0x9700 {
        let d = 24 + (((word >> 4) & 3) * 2);
        let k = ((word & 0xC0) >> 2) | (word & 0x0F);
        return Some(decoded(
            "SBIW",
            format!("R{}:R{},{}", d + 1, d, k),
            2,
            InstrFlags::NONE,
        ));
    }
    // ── AND Rd,Rr  0010 00rd dddd rrrr ────────────────────────────────────────
    if (word & 0xFC00) == 0x2000 {
        let (d, r) = rdrr(word);
        return Some(decoded("AND", format!("R{d},R{r}"), 2, InstrFlags::NONE));
    }
    // ── ANDI Rd,K  0111 KKKK dddd KKKK ───────────────────────────────────────
    if (word & 0xF000) == 0x7000 {
        let d = 16 + ((word >> 4) & 0xF);
        let k = ((word & 0x0F00) >> 4) | (word & 0x0F);
        return Some(decoded(
            "ANDI",
            format!("R{d},${k:02X}"),
            2,
            InstrFlags::NONE,
        ));
    }
    // ── OR Rd,Rr  0010 10rd dddd rrrr ─────────────────────────────────────────
    if (word & 0xFC00) == 0x2800 {
        let (d, r) = rdrr(word);
        return Some(decoded("OR", format!("R{d},R{r}"), 2, InstrFlags::NONE));
    }
    // ── ORI Rd,K  0110 KKKK dddd KKKK ────────────────────────────────────────
    if (word & 0xF000) == 0x6000 {
        let d = 16 + ((word >> 4) & 0xF);
        let k = ((word & 0x0F00) >> 4) | (word & 0x0F);
        return Some(decoded(
            "ORI",
            format!("R{d},${k:02X}"),
            2,
            InstrFlags::NONE,
        ));
    }
    // ── EOR Rd,Rr  0010 01rd dddd rrrr ────────────────────────────────────────
    if (word & 0xFC00) == 0x2400 {
        let (d, r) = rdrr(word);
        return Some(decoded("EOR", format!("R{d},R{r}"), 2, InstrFlags::NONE));
    }
    // ── COM Rd  1001 010d dddd 0000 ────────────────────────────────────────────
    if (word & 0xFE0F) == 0x9400 {
        let d = (word >> 4) & 0x1F;
        return Some(decoded("COM", format!("R{d}"), 2, InstrFlags::NONE));
    }
    // ── NEG Rd  1001 010d dddd 0001 ────────────────────────────────────────────
    if (word & 0xFE0F) == 0x9401 {
        let d = (word >> 4) & 0x1F;
        return Some(decoded("NEG", format!("R{d}"), 2, InstrFlags::NONE));
    }
    // ── INC Rd  1001 010d dddd 0011 ────────────────────────────────────────────
    if (word & 0xFE0F) == 0x9403 {
        let d = (word >> 4) & 0x1F;
        return Some(decoded("INC", format!("R{d}"), 2, InstrFlags::NONE));
    }
    // ── DEC Rd  1001 010d dddd 1010 ────────────────────────────────────────────
    if (word & 0xFE0F) == 0x940A {
        let d = (word >> 4) & 0x1F;
        return Some(decoded("DEC", format!("R{d}"), 2, InstrFlags::NONE));
    }
    // ── MUL Rd,Rr  1001 11rd dddd rrrr ────────────────────────────────────────
    if (word & 0xFC00) == 0x9C00 {
        let (d, r) = rdrr(word);
        return Some(decoded("MUL", format!("R{d},R{r}"), 2, InstrFlags::NONE));
    }
    // ── MULS Rd,Rr  0000 0010 dddd rrrr ──────────────────────────────────────
    if (word & 0xFF00) == 0x0200 {
        let d = 16 + ((word >> 4) & 0xF);
        let r = 16 + (word & 0xF);
        return Some(decoded("MULS", format!("R{d},R{r}"), 2, InstrFlags::NONE));
    }
    // ── MULSU Rd,Rr  0000 0011 0ddd 0rrr ─────────────────────────────────────
    if (word & 0xFF88) == 0x0300 {
        let d = 16 + ((word >> 4) & 7);
        let r = 16 + (word & 7);
        return Some(decoded("MULSU", format!("R{d},R{r}"), 2, InstrFlags::NONE));
    }
    decode_avr_alu2(word)
}

/// Decode shift/bit/compare AVR instructions (second part of ALU decoding).
fn decode_avr_alu2(word: u16) -> Option<Decoded> {
    // ── LSR Rd  1001 010d dddd 0110 ───────────────────────────────────────────
    if (word & 0xFE0F) == 0x9406 {
        let d = (word >> 4) & 0x1F;
        return Some(decoded("LSR", format!("R{d}"), 2, InstrFlags::NONE));
    }
    // ── ROR Rd  1001 010d dddd 0111 ───────────────────────────────────────────
    if (word & 0xFE0F) == 0x9407 {
        let d = (word >> 4) & 0x1F;
        return Some(decoded("ROR", format!("R{d}"), 2, InstrFlags::NONE));
    }
    // ── ASR Rd  1001 010d dddd 0101 ───────────────────────────────────────────
    if (word & 0xFE0F) == 0x9405 {
        let d = (word >> 4) & 0x1F;
        return Some(decoded("ASR", format!("R{d}"), 2, InstrFlags::NONE));
    }
    // ── SWAP Rd  1001 010d dddd 0010 ──────────────────────────────────────────
    if (word & 0xFE0F) == 0x9402 {
        let d = (word >> 4) & 0x1F;
        return Some(decoded("SWAP", format!("R{d}"), 2, InstrFlags::NONE));
    }
    // ── BSET s  1001 0100 0sss 1000 ───────────────────────────────────────────
    if (word & 0xFF8F) == 0x9408 {
        let s = (word >> 4) & 7;
        // Use canonical alias names for each SREG bit
        let mne = match s {
            0 => "SEC", 1 => "SEZ", 2 => "SEN", 3 => "SEV",
            4 => "SES", 5 => "SEH", 6 => "SET", 7 => "SEI",
            _ => "BSET",
        };
        let ops = if mne == "BSET" { format!("{s}") } else { String::new() };
        return Some(decoded(mne, ops, 2, InstrFlags::NONE));
    }
    // ── BCLR s  1001 0100 1sss 1000 ───────────────────────────────────────────
    if (word & 0xFF8F) == 0x9488 {
        let s = (word >> 4) & 7;
        let mne = match s {
            0 => "CLC", 1 => "CLZ", 2 => "CLN", 3 => "CLV",
            4 => "CLS", 5 => "CLH", 6 => "CLT", 7 => "CLI",
            _ => "BCLR",
        };
        let ops = if mne == "BCLR" { format!("{s}") } else { String::new() };
        return Some(decoded(mne, ops, 2, InstrFlags::NONE));
    }
    // ── BST Rd,b  1111 101d dddd 0bbb ─────────────────────────────────────────
    if (word & 0xFE08) == 0xFA00 {
        let d = (word >> 4) & 0x1F;
        let b = word & 7;
        return Some(decoded("BST", format!("R{d},{b}"), 2, InstrFlags::NONE));
    }
    // ── BLD Rd,b  1111 100d dddd 0bbb ─────────────────────────────────────────
    if (word & 0xFE08) == 0xF800 {
        let d = (word >> 4) & 0x1F;
        let b = word & 7;
        return Some(decoded("BLD", format!("R{d},{b}"), 2, InstrFlags::NONE));
    }
    // ── SBI A,b  1001 1010 AAAA Abbb ──────────────────────────────────────────
    if (word & 0xFF00) == 0x9A00 {
        let a = (word >> 3) & 0x1F;
        let b = word & 7;
        return Some(decoded("SBI", format!("${a:02X},{b}"), 2, InstrFlags::NONE));
    }
    // ── CBI A,b  1001 1000 AAAA Abbb ──────────────────────────────────────────
    if (word & 0xFF00) == 0x9800 {
        let a = (word >> 3) & 0x1F;
        let b = word & 7;
        return Some(decoded("CBI", format!("${a:02X},{b}"), 2, InstrFlags::NONE));
    }
    // ── CP Rd,Rr  0001 01rd dddd rrrr ─────────────────────────────────────────
    if (word & 0xFC00) == 0x1400 {
        let (d, r) = rdrr(word);
        return Some(decoded("CP", format!("R{d},R{r}"), 2, InstrFlags::NONE));
    }
    // ── CPC Rd,Rr  0000 01rd dddd rrrr ────────────────────────────────────────
    if (word & 0xFC00) == 0x0400 {
        let (d, r) = rdrr(word);
        return Some(decoded("CPC", format!("R{d},R{r}"), 2, InstrFlags::NONE));
    }
    // ── CPI Rd,K  0011 KKKK dddd KKKK ────────────────────────────────────────
    if (word & 0xF000) == 0x3000 {
        let d = 16 + ((word >> 4) & 0xF);
        let k = ((word & 0x0F00) >> 4) | (word & 0x0F);
        return Some(decoded(
            "CPI",
            format!("R{d},${k:02X}"),
            2,
            InstrFlags::NONE,
        ));
    }
    None
}

/// Decode load/store AVR instructions.
fn decode_avr_mem(word: u16, bytes: &[u8]) -> Result<Option<Decoded>, CoreError> {
    // ── MOV Rd,Rr  0010 11rd dddd rrrr ────────────────────────────────────────
    if (word & 0xFC00) == 0x2C00 {
        let (d, r) = rdrr(word);
        return Ok(Some(decoded(
            "MOV",
            format!("R{d},R{r}"),
            2,
            InstrFlags::NONE,
        )));
    }
    // ── MOVW Rd+1:Rd, Rr+1:Rr  0000 0001 dddd rrrr ───────────────────────────
    if (word & 0xFF00) == 0x0100 {
        let d = ((word >> 4) & 0xF) * 2;
        let r = (word & 0xF) * 2;
        return Ok(Some(decoded(
            "MOVW",
            format!("R{}:R{},R{}:R{}", d + 1, d, r + 1, r),
            2,
            InstrFlags::NONE,
        )));
    }
    // ── LDI Rd,K  1110 KKKK dddd KKKK ────────────────────────────────────────
    if (word & 0xF000) == 0xE000 {
        let d = 16 + ((word >> 4) & 0xF);
        let k = ((word & 0x0F00) >> 4) | (word & 0x0F);
        return Ok(Some(decoded(
            "LDI",
            format!("R{d},${k:02X}"),
            2,
            InstrFlags::NONE,
        )));
    }
    // ── LD Rd,X  1001 000d dddd 1100 ──────────────────────────────────────────
    if (word & 0xFE0F) == 0x900C {
        let d = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "LD",
            format!("R{d},X"),
            2,
            InstrFlags::READ_MEM,
        )));
    }
    // ── LD Rd,X+  1001 000d dddd 1101 ─────────────────────────────────────────
    if (word & 0xFE0F) == 0x900D {
        let d = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "LD",
            format!("R{d},X+"),
            2,
            InstrFlags::READ_MEM,
        )));
    }
    // ── LD Rd,-X  1001 000d dddd 1110 ─────────────────────────────────────────
    if (word & 0xFE0F) == 0x900E {
        let d = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "LD",
            format!("R{d},-X"),
            2,
            InstrFlags::READ_MEM,
        )));
    }
    // ── LD Rd,Y+  1001 000d dddd 1001 ─────────────────────────────────────────
    if (word & 0xFE0F) == 0x9009 {
        let d = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "LD",
            format!("R{d},Y+"),
            2,
            InstrFlags::READ_MEM,
        )));
    }
    // ── LD Rd,-Y  1001 000d dddd 1010 ─────────────────────────────────────────
    if (word & 0xFE0F) == 0x900A {
        let d = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "LD",
            format!("R{d},-Y"),
            2,
            InstrFlags::READ_MEM,
        )));
    }
    // ── LD Rd,(Y)  1000 000d dddd 1000 ───────────────────────────────────────
    if (word & 0xFE0F) == 0x8008 {
        let d = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "LD",
            format!("R{d},Y"),
            2,
            InstrFlags::READ_MEM,
        )));
    }
    // ── LD Rd,(Z)  1000 000d dddd 0000 ───────────────────────────────────────
    if (word & 0xFE0F) == 0x8000 {
        let d = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "LD",
            format!("R{d},Z"),
            2,
            InstrFlags::READ_MEM,
        )));
    }
    // ── LD Rd,Z+  1001 000d dddd 0001 ─────────────────────────────────────────
    if (word & 0xFE0F) == 0x9001 {
        let d = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "LD",
            format!("R{d},Z+"),
            2,
            InstrFlags::READ_MEM,
        )));
    }
    // ── LD Rd,-Z  1001 000d dddd 0010 ─────────────────────────────────────────
    if (word & 0xFE0F) == 0x9002 {
        let d = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "LD",
            format!("R{d},-Z"),
            2,
            InstrFlags::READ_MEM,
        )));
    }
    // ── LDD Rd,Y+q  10q0 qq0d dddd 1qqq ──────────────────────────────────────
    if (word & 0xD208) == 0x8008 {
        let d = (word >> 4) & 0x1F;
        let q = ((word & 0x2000) >> 8) | ((word & 0x0C00) >> 7) | (word & 0x07);
        return Ok(Some(decoded(
            "LDD",
            format!("R{d},Y+{q}"),
            2,
            InstrFlags::READ_MEM,
        )));
    }
    // ── LDD Rd,Z+q  10q0 qq0d dddd 0qqq ──────────────────────────────────────
    if (word & 0xD208) == 0x8000 {
        let d = (word >> 4) & 0x1F;
        let q = ((word & 0x2000) >> 8) | ((word & 0x0C00) >> 7) | (word & 0x07);
        return Ok(Some(decoded(
            "LDD",
            format!("R{d},Z+{q}"),
            2,
            InstrFlags::READ_MEM,
        )));
    }
    // ── LDS Rd,k  1001 000d dddd 0000 + 16-bit k ─────────────────────────────
    if (word & 0xFE0F) == 0x9000 {
        if bytes.len() < 4 {
            return Err(CoreError::InvalidFormat {
                message: "truncated LDS".to_string(),
            });
        }
        let d = (word >> 4) & 0x1F;
        let k = u16::from_le_bytes([bytes[2], bytes[3]]);
        return Ok(Some(decoded(
            "LDS",
            format!("R{d},${k:04X}"),
            4,
            InstrFlags::READ_MEM,
        )));
    }
    decode_avr_store(word, bytes)
}

/// Decode store/IO AVR instructions (second part of memory decoding).
fn decode_avr_store(word: u16, bytes: &[u8]) -> Result<Option<Decoded>, CoreError> {
    // ── ST X,Rr  1001 001r rrrr 1100 ──────────────────────────────────────────
    if (word & 0xFE0F) == 0x920C {
        let r = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "ST",
            format!("X,R{r}"),
            2,
            InstrFlags::WRITE_MEM,
        )));
    }
    // ── ST X+,Rr  1001 001r rrrr 1101 ─────────────────────────────────────────
    if (word & 0xFE0F) == 0x920D {
        let r = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "ST",
            format!("X+,R{r}"),
            2,
            InstrFlags::WRITE_MEM,
        )));
    }
    // ── ST -X,Rr  1001 001r rrrr 1110 ─────────────────────────────────────────
    if (word & 0xFE0F) == 0x920E {
        let r = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "ST",
            format!("-X,R{r}"),
            2,
            InstrFlags::WRITE_MEM,
        )));
    }
    // ── ST Y+,Rr  1001 001r rrrr 1001 ─────────────────────────────────────────
    if (word & 0xFE0F) == 0x9209 {
        let r = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "ST",
            format!("Y+,R{r}"),
            2,
            InstrFlags::WRITE_MEM,
        )));
    }
    // ── ST Z+,Rr  1001 001r rrrr 0001 ─────────────────────────────────────────
    if (word & 0xFE0F) == 0x9201 {
        let r = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "ST",
            format!("Z+,R{r}"),
            2,
            InstrFlags::WRITE_MEM,
        )));
    }
    // ── STS k,Rr  1001 001r rrrr 0000 + 16-bit k ─────────────────────────────
    if (word & 0xFE0F) == 0x9200 {
        if bytes.len() < 4 {
            return Err(CoreError::InvalidFormat {
                message: "truncated STS".to_string(),
            });
        }
        let r = (word >> 4) & 0x1F;
        let k = u16::from_le_bytes([bytes[2], bytes[3]]);
        return Ok(Some(decoded(
            "STS",
            format!("${k:04X},R{r}"),
            4,
            InstrFlags::WRITE_MEM,
        )));
    }
    // ── PUSH Rr  1001 001r rrrr 1111 ──────────────────────────────────────────
    if (word & 0xFE0F) == 0x920F {
        let r = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "PUSH",
            format!("R{r}"),
            2,
            InstrFlags::WRITE_MEM,
        )));
    }
    // ── POP Rd  1001 000d dddd 1111 ───────────────────────────────────────────
    if (word & 0xFE0F) == 0x900F {
        let d = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "POP",
            format!("R{d}"),
            2,
            InstrFlags::READ_MEM,
        )));
    }
    // ── IN Rd,A  1011 0AAd dddd AAAA ──────────────────────────────────────────
    if (word & 0xF800) == 0xB000 {
        let d = (word >> 4) & 0x1F;
        let a = ((word & 0x0600) >> 5) | (word & 0x0F);
        return Ok(Some(decoded(
            "IN",
            format!("R{d},${a:02X}"),
            2,
            InstrFlags::NONE,
        )));
    }
    // ── OUT A,Rr  1011 1AAr rrrr AAAA ─────────────────────────────────────────
    if (word & 0xF800) == 0xB800 {
        let r = (word >> 4) & 0x1F;
        let a = ((word & 0x0600) >> 5) | (word & 0x0F);
        return Ok(Some(decoded(
            "OUT",
            format!("${a:02X},R{r}"),
            2,
            InstrFlags::NONE,
        )));
    }
    // ── LPM Rd,Z  1001 000d dddd 0100 ─────────────────────────────────────────
    if (word & 0xFE0F) == 0x9004 {
        let d = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "LPM",
            format!("R{d},Z"),
            2,
            InstrFlags::READ_MEM,
        )));
    }
    // ── LPM Rd,Z+  1001 000d dddd 0101 ───────────────────────────────────────
    if (word & 0xFE0F) == 0x9005 {
        let d = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "LPM",
            format!("R{d},Z+"),
            2,
            InstrFlags::READ_MEM,
        )));
    }
    // ── ELPM Rd,Z+  1001 000d dddd 0111 ──────────────────────────────────────
    if (word & 0xFE0F) == 0x9007 {
        let d = (word >> 4) & 0x1F;
        return Ok(Some(decoded(
            "ELPM",
            format!("R{d},Z+"),
            2,
            InstrFlags::READ_MEM,
        )));
    }
    Ok(None)
}

/// Sign-extend a 12-bit value (bits 11:0) to i32.
fn sign_ext_12(raw: u16) -> i32 {
    let v = i32::from(raw & 0x0FFF);
    if v & 0x0800 != 0 { v - 0x1000 } else { v }
}

/// Compute a relative-jump target from `pc`, offset `k` (in words → bytes = k*2).
fn rel_target(pc: u64, k: i32) -> u64 {
    pc.wrapping_add(2).wrapping_add_signed(i64::from(k) * 2)
}

/// Compute a relative-jump target from `pc`, offset `k` (i8, in words → bytes = k*2).
fn rel_target_i8(pc: u64, k: i8) -> u64 {
    pc.wrapping_add(2).wrapping_add_signed(i64::from(k) * 2)
}

/// Decode branch/jump AVR instructions.
fn decode_avr_branch(word: u16, bytes: &[u8], pc: u64) -> Result<Option<Decoded>, CoreError> {
    // ── RJMP k  1100 kkkk kkkk kkkk ──────────────────────────────────────────
    if (word & 0xF000) == 0xC000 {
        let k = sign_ext_12(word);
        let target = rel_target(pc, k);
        return Ok(Some(decoded(
            "RJMP",
            format!("${target:04X}"),
            2,
            InstrFlags::BRANCH,
        )));
    }
    // ── RCALL k  1101 kkkk kkkk kkkk ─────────────────────────────────────────
    if (word & 0xF000) == 0xD000 {
        let k = sign_ext_12(word);
        let target = rel_target(pc, k);
        return Ok(Some(decoded(
            "RCALL",
            format!("${target:04X}"),
            2,
            InstrFlags::CALL,
        )));
    }
    // ── JMP k  1001 010k kkkk 110k kkkk kkkk kkkk kkkk (32-bit) ──────────────
    if (word & 0xFE0E) == 0x940C {
        if bytes.len() < 4 {
            return Err(CoreError::InvalidFormat {
                message: "truncated JMP".to_string(),
            });
        }
        let k_hi = ((u32::from(word) & 0x01F0) >> 3) | (u32::from(word) & 1);
        let k_lo = u32::from(u16::from_le_bytes([bytes[2], bytes[3]]));
        let target = (k_hi << 16) | k_lo;
        return Ok(Some(decoded(
            "JMP",
            format!("${target:06X}"),
            4,
            InstrFlags::BRANCH,
        )));
    }
    // ── CALL k  1001 010k kkkk 111k (32-bit) ─────────────────────────────────
    if (word & 0xFE0E) == 0x940E {
        if bytes.len() < 4 {
            return Err(CoreError::InvalidFormat {
                message: "truncated CALL".to_string(),
            });
        }
        let k_hi = ((u32::from(word) & 0x01F0) >> 3) | (u32::from(word) & 1);
        let k_lo = u32::from(u16::from_le_bytes([bytes[2], bytes[3]]));
        let target = (k_hi << 16) | k_lo;
        return Ok(Some(decoded(
            "CALL",
            format!("${target:06X}"),
            4,
            InstrFlags::CALL,
        )));
    }
    // ── Branch instructions: BRBS/BRBC s,k  1111 0kkk kkkk ksss ────────────────
    if (word & 0xFC00) == 0xF000 {
        let k_raw = ((word >> 3) & 0x7F) as i8;
        let k = if k_raw & 0x40 != 0 {
            k_raw | -0x80_i8
        } else {
            k_raw
        };
        let s = word & 7;
        let target = rel_target_i8(pc, k);
        let mn = match s {
            0 => "BRCS",
            1 => "BREQ",
            2 => "BRMI",
            3 => "BRVS",
            4 => "BRLT",
            5 => "BRHS",
            6 => "BRTS",
            _ => "BRIE",
        };
        return Ok(Some(decoded(
            mn,
            format!("${target:04X}"),
            2,
            branch_flags(),
        )));
    }
    if (word & 0xFC00) == 0xF400 {
        let k_raw = ((word >> 3) & 0x7F) as i8;
        let k = if k_raw & 0x40 != 0 {
            k_raw | -0x80_i8
        } else {
            k_raw
        };
        let s = word & 7;
        let target = rel_target_i8(pc, k);
        let mn = match s {
            0 => "BRCC",
            1 => "BRNE",
            2 => "BRPL",
            3 => "BRVC",
            4 => "BRGE",
            5 => "BRHC",
            6 => "BRTC",
            _ => "BRID",
        };
        return Ok(Some(decoded(
            mn,
            format!("${target:04X}"),
            2,
            branch_flags(),
        )));
    }
    // ── CPSE Rd,Rr  0001 00rd dddd rrrr ──────────────────────────────────────
    if (word & 0xFC00) == 0x1000 {
        let (d, r) = rdrr(word);
        return Ok(Some(decoded(
            "CPSE",
            format!("R{d},R{r}"),
            2,
            branch_flags(),
        )));
    }
    // ── SBRC Rr,b  1111 110r rrrr 0bbb ────────────────────────────────────────
    if (word & 0xFE08) == 0xFC00 {
        let r = (word >> 4) & 0x1F;
        let b = word & 7;
        return Ok(Some(decoded(
            "SBRC",
            format!("R{r},{b}"),
            2,
            branch_flags(),
        )));
    }
    // ── SBRS Rr,b  1111 111r rrrr 0bbb ────────────────────────────────────────
    if (word & 0xFE08) == 0xFE00 {
        let r = (word >> 4) & 0x1F;
        let b = word & 7;
        return Ok(Some(decoded(
            "SBRS",
            format!("R{r},{b}"),
            2,
            branch_flags(),
        )));
    }
    Ok(None)
}

/// Decode a 16-bit AVR instruction word (and optionally a 32-bit one).
fn decode_avr(bytes: &[u8], pc: u64) -> Result<Decoded, CoreError> {
    if bytes.len() < 2 {
        return Err(CoreError::InvalidFormat {
            message: "truncated".to_string(),
        });
    }
    let word = u16::from_le_bytes([bytes[0], bytes[1]]);

    if let Some(d) = decode_avr_fixed(word) {
        return Ok(d);
    }
    if let Some(d) = decode_avr_alu(word) {
        return Ok(d);
    }
    if let Some(d) = decode_avr_mem(word, bytes)? {
        return Ok(d);
    }
    if let Some(d) = decode_avr_branch(word, bytes, pc)? {
        return Ok(d);
    }

    Ok(decoded("DC.W", format!("${word:04X}"), 2, InstrFlags::NONE))
}

// ── Main architecture struct ──────────────────────────────────────────────────

/// AVR microcontroller architecture.
#[derive(Debug, Clone)]
pub struct AvrArch {
    pub variant: AvrVariant,
}

impl AvrArch {
    #[must_use]
    pub const fn new(variant: AvrVariant) -> Self {
        Self { variant }
    }
}

impl Default for AvrArch {
    fn default() -> Self {
        Self::new(AvrVariant::Atmega)
    }
}

impl Architecture for AvrArch {
    fn name(&self) -> &str {
        self.variant.name()
    }

    fn pointer_size(&self) -> usize {
        2 // 16-bit data address space (SRAM)
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        let dec = decode_avr(bytes, address.as_u64())?;
        if dec.size > bytes.len() {
            return Err(CoreError::InvalidFormat {
                message: format!(
                    "truncated AVR instruction: need {} bytes, have {}",
                    dec.size,
                    bytes.len()
                ),
            });
        }
        let raw = bytes[..dec.size].to_vec();
        let mut instr = Instruction::new(address, dec.size, dec.mnemonic, raw);
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
        let ops = &instr.operands;
        let hex: String = ops
            .trim_start_matches('$')
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .collect();
        if let Ok(target) = u64::from_str_radix(&hex, 16) {
            let target = target & 0x3F_FFFF;
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
        let mut regs: Vec<RegisterInfo> = (0u32..32)
            .map(|i| RegisterInfo::new(format!("R{i}"), REG_R0 + i, 1, RegisterKind::General))
            .collect();
        regs.push(RegisterInfo::new("SREG", REG_SREG, 1, RegisterKind::Flags));
        regs.push(RegisterInfo::new("SP", REG_SP, 2, RegisterKind::Stack));
        regs.push(RegisterInfo::new(
            "PC",
            REG_PC,
            2,
            RegisterKind::ProgramCounter,
        ));
        regs.push(RegisterInfo::new("X", REG_X, 2, RegisterKind::General));
        regs.push(RegisterInfo::new("Y", REG_Y, 2, RegisterKind::General));
        regs.push(RegisterInfo::new("Z", REG_Z, 2, RegisterKind::General));
        regs
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![
            CallingConvention::new("avr_gcc")
                .with_int_args(vec![
                    "R24".to_string(),
                    "R22".to_string(),
                    "R20".to_string(),
                ])
                .with_return_regs(vec!["R24".to_string(), "R25".to_string()]),
        ]
    }
}

// ── Linear disassembler ───────────────────────────────────────────────────────

/// Linear-sweep disassembler for AVR code.
pub struct AvrLinearDisassembler<'a> {
    arch: &'a AvrArch,
    bytes: &'a [u8],
    base: Address,
    offset: usize,
}

impl<'a> AvrLinearDisassembler<'a> {
    #[must_use]
    pub const fn new(arch: &'a AvrArch, bytes: &'a [u8], base: Address) -> Self {
        Self {
            arch,
            bytes,
            base,
            offset: 0,
        }
    }
}

impl Iterator for AvrLinearDisassembler<'_> {
    type Item = Result<Instruction, CoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
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

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn arch() -> AvrArch {
        AvrArch::default()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    #[test]
    fn test_nop() {
        let instr = arch().disassemble(addr(0), &[0x00, 0x00]).unwrap();
        assert_eq!(instr.mnemonic, "NOP");
        assert_eq!(instr.size, 2);
    }

    #[test]
    fn test_ret() {
        let instr = arch().disassemble(addr(0), &[0x08, 0x95]).unwrap();
        assert_eq!(instr.mnemonic, "RET");
        assert!(instr.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_reti() {
        let instr = arch().disassemble(addr(0), &[0x18, 0x95]).unwrap();
        assert_eq!(instr.mnemonic, "RETI");
        assert!(instr.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_ldi() {
        // LDI R16,0x42: encoding 1110 KKKK dddd KKKK, d=0→R16, K=0x42 → bits[11:8]=4, bits[3:0]=2
        // word = 0xE402, LE bytes = [0x02, 0xE4]
        let instr = arch().disassemble(addr(0), &[0x02, 0xE4]).unwrap();
        assert_eq!(instr.mnemonic, "LDI");
        assert!(instr.operands.contains("R16"));
        assert!(instr.operands.contains("42"));
    }

    #[test]
    fn test_add() {
        // ADD R0,R1 = 0x0C01 LE = 01 0C
        let instr = arch().disassemble(addr(0), &[0x01, 0x0C]).unwrap();
        assert_eq!(instr.mnemonic, "ADD");
    }

    #[test]
    fn test_rjmp() {
        // RJMP 0 (self-loop) = CF FF
        let instr = arch().disassemble(addr(0x100), &[0xFF, 0xCF]).unwrap();
        assert_eq!(instr.mnemonic, "RJMP");
        assert_eq!(instr.operands, "$0100");
        assert!(instr.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_rcall() {
        let instr = arch().disassemble(addr(0x100), &[0x05, 0xD0]).unwrap();
        assert_eq!(instr.mnemonic, "RCALL");
        assert!(instr.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_push() {
        // PUSH R16: 1001 001r rrrr 1111, r=16=10000 → 1001 0011 0000 1111 = 0x930F, LE=[0x0F,0x93]
        let instr = arch().disassemble(addr(0), &[0x0F, 0x93]).unwrap();
        assert_eq!(instr.mnemonic, "PUSH");
        assert!(instr.operands.contains("R16"));
    }

    #[test]
    fn test_pop() {
        // POP R16 = 0F 90
        let instr = arch().disassemble(addr(0), &[0x0F, 0x90]).unwrap();
        assert_eq!(instr.mnemonic, "POP");
    }

    #[test]
    fn test_breq() {
        let instr = arch().disassemble(addr(0x100), &[0x01, 0xF4]).unwrap();
        assert_eq!(instr.mnemonic, "BRNE");
        assert!(instr.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_jmp_32bit() {
        let instr = arch()
            .disassemble(addr(0), &[0x0C, 0x94, 0x00, 0x01])
            .unwrap();
        assert_eq!(instr.mnemonic, "JMP");
        assert_eq!(instr.size, 4);
        assert!(instr.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_call_32bit() {
        let instr = arch()
            .disassemble(addr(0), &[0x0E, 0x94, 0x10, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "CALL");
        assert_eq!(instr.size, 4);
        assert!(instr.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_in_out() {
        let instr = arch().disassemble(addr(0), &[0x02, 0xB6]).unwrap();
        assert_eq!(instr.mnemonic, "IN");
    }

    #[test]
    fn test_registers_count() {
        assert_eq!(arch().registers().len(), 38); // 32 + SREG + SP + PC + X + Y + Z
    }

    #[test]
    fn test_name_endian() {
        assert_eq!(arch().name(), "avr-mega");
        assert_eq!(arch().endian(), Endian::Little);
    }

    #[test]
    fn test_linear_disassembler() {
        let code = [0x00u8, 0x00, 0x08, 0x95]; // NOP, RET
        let a = arch();
        let instrs: Vec<_> = AvrLinearDisassembler::new(&a, &code, addr(0))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[0].mnemonic, "NOP");
        assert_eq!(instrs[1].mnemonic, "RET");
    }

    #[test]
    fn test_adiw() {
        // ADIW R25:R24,1 = 01 96
        let instr = arch().disassemble(addr(0), &[0x01, 0x96]).unwrap();
        assert_eq!(instr.mnemonic, "ADIW");
    }

    #[test]
    fn test_sei_cli() {
        let sei = arch().disassemble(addr(0), &[0x78, 0x94]).unwrap();
        assert_eq!(sei.mnemonic, "SEI");
        let cli = arch().disassemble(addr(0), &[0xF8, 0x94]).unwrap();
        assert_eq!(cli.mnemonic, "CLI");
    }

    #[test]
    fn test_eor_clr() {
        // EOR R0,R0 = clears R0. Encoding: 0010 01rd dddd rrrr, d=0, r=0 → 0x2400 LE=[0x00,0x24]
        let instr = arch().disassemble(addr(0), &[0x00, 0x24]).unwrap();
        assert_eq!(instr.mnemonic, "EOR");
        assert_eq!(instr.size, 2);
    }

    #[test]
    fn test_mov_r0_r1() {
        // MOV R0,R1: 0010 11rd dddd rrrr, d=0, r=1 → 0010 1100 0000 0001 = 0x2C01 LE=[0x01,0x2C]
        let instr = arch().disassemble(addr(0), &[0x01, 0x2C]).unwrap();
        assert_eq!(instr.mnemonic, "MOV");
        assert!(instr.operands.contains("R0"));
        assert!(instr.operands.contains("R1"));
    }

    #[test]
    fn test_calling_convention() {
        let cc = arch().calling_conventions();
        assert!(!cc.is_empty());
        assert_eq!(cc[0].name, "avr_gcc");
        assert!(cc[0].return_regs.contains(&"R24".to_string()));
    }

    #[test]
    fn test_ijmp_icall_flags() {
        let ijmp = arch().disassemble(addr(0), &[0x09, 0x94]).unwrap();
        assert_eq!(ijmp.mnemonic, "IJMP");
        assert!(ijmp.flags.contains(InstrFlags::INDIRECT));
        let icall = arch().disassemble(addr(0), &[0x09, 0x95]).unwrap();
        assert_eq!(icall.mnemonic, "ICALL");
        assert!(icall.flags.contains(InstrFlags::CALL));
    }

    // ── More tests ────────────────────────────────────────────────────────

    #[test]
    fn test_sleep() {
        let instr = arch().disassemble(addr(0), &[0x88, 0x95]).unwrap();
        assert_eq!(instr.mnemonic, "SLEEP");
    }

    #[test]
    fn test_wdr() {
        let instr = arch().disassemble(addr(0), &[0xA8, 0x95]).unwrap();
        assert_eq!(instr.mnemonic, "WDR");
    }

    #[test]
    fn test_break() {
        let instr = arch().disassemble(addr(0), &[0x98, 0x95]).unwrap();
        assert_eq!(instr.mnemonic, "BREAK");
    }

    #[test]
    fn test_sub() {
        // SUB R0,R1: 0001 10rd dddd rrrr, d=0, r=1 → 0x1801 LE=[0x01,0x18]
        let instr = arch().disassemble(addr(0), &[0x01, 0x18]).unwrap();
        assert_eq!(instr.mnemonic, "SUB");
    }

    #[test]
    fn test_and_r0_r1() {
        // AND R0,R1: 0x2001 LE=[0x01,0x20]
        let instr = arch().disassemble(addr(0), &[0x01, 0x20]).unwrap();
        assert_eq!(instr.mnemonic, "AND");
    }

    #[test]
    fn test_or_r0_r1() {
        // OR R0,R1: 0x2801 LE=[0x01,0x28]
        let instr = arch().disassemble(addr(0), &[0x01, 0x28]).unwrap();
        assert_eq!(instr.mnemonic, "OR");
    }

    #[test]
    fn test_mul() {
        // MUL R0,R1: 0x9C01 LE=[0x01,0x9C]
        let instr = arch().disassemble(addr(0), &[0x01, 0x9C]).unwrap();
        assert_eq!(instr.mnemonic, "MUL");
    }

    #[test]
    fn test_lsr() {
        // LSR R0: 0x9406 LE=[0x06,0x94]
        let instr = arch().disassemble(addr(0), &[0x06, 0x94]).unwrap();
        assert_eq!(instr.mnemonic, "LSR");
    }

    #[test]
    fn test_ror() {
        // ROR R0: 0x9407 LE=[0x07,0x94]
        let instr = arch().disassemble(addr(0), &[0x07, 0x94]).unwrap();
        assert_eq!(instr.mnemonic, "ROR");
    }

    #[test]
    fn test_asr() {
        // ASR R0: 0x9405 LE=[0x05,0x94]
        let instr = arch().disassemble(addr(0), &[0x05, 0x94]).unwrap();
        assert_eq!(instr.mnemonic, "ASR");
    }

    #[test]
    fn test_com() {
        // COM R0: 0x9400 LE=[0x00,0x94]
        let instr = arch().disassemble(addr(0), &[0x00, 0x94]).unwrap();
        assert_eq!(instr.mnemonic, "COM");
    }

    #[test]
    fn test_inc() {
        // INC R0: 0x9403 LE=[0x03,0x94]
        let instr = arch().disassemble(addr(0), &[0x03, 0x94]).unwrap();
        assert_eq!(instr.mnemonic, "INC");
    }

    #[test]
    fn test_dec() {
        // DEC R0: 0x940A LE=[0x0A,0x94]
        let instr = arch().disassemble(addr(0), &[0x0A, 0x94]).unwrap();
        assert_eq!(instr.mnemonic, "DEC");
    }

    #[test]
    fn test_neg() {
        // NEG R0: 0x9401 LE=[0x01,0x94]
        let instr = arch().disassemble(addr(0), &[0x01, 0x94]).unwrap();
        assert_eq!(instr.mnemonic, "NEG");
    }

    #[test]
    fn test_andi() {
        // ANDI R16,0xFF: 0x7F00 LE=[0x00,0x7F] (d=0→R16, K=0xFF?)
        // ANDI: 0111 KKKK dddd KKKK, d=0(R16), K=0xFF → bits[11:8]=0xF, bits[3:0]=0xF
        // word = 0x7F0F LE=[0x0F,0x7F]
        let instr = arch().disassemble(addr(0), &[0x0F, 0x7F]).unwrap();
        assert_eq!(instr.mnemonic, "ANDI");
        assert!(instr.operands.contains("R16"));
    }

    #[test]
    fn test_ori() {
        // ORI R16,0x01: 0x6001 LE=[0x01,0x60]
        let instr = arch().disassemble(addr(0), &[0x01, 0x60]).unwrap();
        assert_eq!(instr.mnemonic, "ORI");
    }

    #[test]
    fn test_brcs() {
        // BRCS target: F000 with s=0 → 0xF000 + offset
        // BRCS +2: k=1, s=0 → 1111 0000 0000 1000 = 0xF008 LE=[0x08,0xF0]
        let instr = arch().disassemble(addr(0x100), &[0x08, 0xF0]).unwrap();
        assert_eq!(instr.mnemonic, "BRCS");
        assert!(instr.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_breq_fc() {
        // BREQ is s=1 in BRBS group (0xF000): 0xF001 + offset*8
        // BREQ +2: k=1, s=1 → 1111 0000 0000 1001 = 0xF009 LE=[0x09,0xF0]
        let instr = arch().disassemble(addr(0x100), &[0x09, 0xF0]).unwrap();
        assert_eq!(instr.mnemonic, "BREQ");
    }

    #[test]
    fn test_ld_x() {
        // LD R0,X: 0x900C LE=[0x0C,0x90]
        let instr = arch().disassemble(addr(0), &[0x0C, 0x90]).unwrap();
        assert_eq!(instr.mnemonic, "LD");
        assert!(instr.operands.contains('X'));
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_st_x() {
        // ST X,R0: 0x920C LE=[0x0C,0x92]
        let instr = arch().disassemble(addr(0), &[0x0C, 0x92]).unwrap();
        assert_eq!(instr.mnemonic, "ST");
        assert!(instr.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_lds_32bit() {
        // LDS R0,0x0100: 0x9000 + [0x00,0x01]
        let instr = arch()
            .disassemble(addr(0), &[0x00, 0x90, 0x00, 0x01])
            .unwrap();
        assert_eq!(instr.mnemonic, "LDS");
        assert_eq!(instr.size, 4);
    }

    #[test]
    fn test_sts_32bit() {
        // STS 0x0200,R0: 0x9200 + [0x00,0x02]
        let instr = arch()
            .disassemble(addr(0), &[0x00, 0x92, 0x00, 0x02])
            .unwrap();
        assert_eq!(instr.mnemonic, "STS");
        assert_eq!(instr.size, 4);
        assert!(instr.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_lpm_z() {
        // LPM R0,Z: 0x9004 LE=[0x04,0x90]
        let instr = arch().disassemble(addr(0), &[0x04, 0x90]).unwrap();
        assert_eq!(instr.mnemonic, "LPM");
        assert!(instr.operands.contains('Z'));
    }

    #[test]
    fn test_out_port() {
        // OUT 0x3F,R1: 1011 1AAr rrrr AAAA, A=0x3F, r=1
        // 0xBF: 1011 1111 0001 1111 = 0xBF1F LE=[0x1F,0xBF]
        let instr = arch().disassemble(addr(0), &[0x1F, 0xBF]).unwrap();
        assert_eq!(instr.mnemonic, "OUT");
    }

    #[test]
    fn test_cpse() {
        // CPSE R0,R1: 0x1001 LE=[0x01,0x10]
        let instr = arch().disassemble(addr(0), &[0x01, 0x10]).unwrap();
        assert_eq!(instr.mnemonic, "CPSE");
        assert!(instr.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_sbrc() {
        // SBRC R0,0: 0xFC00 LE=[0x00,0xFC]
        let instr = arch().disassemble(addr(0), &[0x00, 0xFC]).unwrap();
        assert_eq!(instr.mnemonic, "SBRC");
    }

    #[test]
    fn test_sbrs() {
        // SBRS R0,0: 0xFE00 LE=[0x00,0xFE]
        let instr = arch().disassemble(addr(0), &[0x00, 0xFE]).unwrap();
        assert_eq!(instr.mnemonic, "SBRS");
    }

    #[test]
    fn test_cp() {
        // CP R0,R1: 0x1401 LE=[0x01,0x14]
        let instr = arch().disassemble(addr(0), &[0x01, 0x14]).unwrap();
        assert_eq!(instr.mnemonic, "CP");
    }

    #[test]
    fn test_cpi() {
        // CPI R16,0x00: 0x3000 LE=[0x00,0x30]
        let instr = arch().disassemble(addr(0), &[0x00, 0x30]).unwrap();
        assert_eq!(instr.mnemonic, "CPI");
    }

    #[test]
    fn test_muls() {
        // MULS R16,R16: 0x0200 LE=[0x00,0x02]
        let instr = arch().disassemble(addr(0), &[0x00, 0x02]).unwrap();
        assert_eq!(instr.mnemonic, "MULS");
    }

    #[test]
    fn test_swap() {
        // SWAP R0: 0x9402 LE=[0x02,0x94]
        let instr = arch().disassemble(addr(0), &[0x02, 0x94]).unwrap();
        assert_eq!(instr.mnemonic, "SWAP");
    }

    #[test]
    fn test_bst_bld() {
        // BST R0,0: 0xFA00 LE=[0x00,0xFA]
        let bst = arch().disassemble(addr(0), &[0x00, 0xFA]).unwrap();
        assert_eq!(bst.mnemonic, "BST");
        // BLD R0,0: 0xF800 LE=[0x00,0xF8]
        let bld = arch().disassemble(addr(0), &[0x00, 0xF8]).unwrap();
        assert_eq!(bld.mnemonic, "BLD");
    }

    #[test]
    fn test_sbi_cbi() {
        // SBI 0x02,0: 0x9A10 LE=[0x10,0x9A]
        let sbi = arch().disassemble(addr(0), &[0x10, 0x9A]).unwrap();
        assert_eq!(sbi.mnemonic, "SBI");
        // CBI 0x02,0: 0x9810 LE=[0x10,0x98]
        let cbi = arch().disassemble(addr(0), &[0x10, 0x98]).unwrap();
        assert_eq!(cbi.mnemonic, "CBI");
    }

    #[test]
    fn test_sbiw() {
        // SBIW R25:R24,1: 0x9701 LE=[0x01,0x97]
        let instr = arch().disassemble(addr(0), &[0x01, 0x97]).unwrap();
        assert_eq!(instr.mnemonic, "SBIW");
    }

    #[test]
    fn test_movw() {
        // MOVW R0:R1, R2:R3: 0x0101 LE=[0x01,0x01]
        let instr = arch().disassemble(addr(0), &[0x01, 0x01]).unwrap();
        assert_eq!(instr.mnemonic, "MOVW");
    }

    #[test]
    fn test_branch_target_extraction() {
        // RJMP +2 at PC=0: RJMP target = 0+2+1*2 = 4. k=1 → 0xC001 LE=[0x01,0xC0]
        let a = arch();
        let instr = a.disassemble(addr(0), &[0x01, 0xC0]).unwrap();
        let branches = a.get_branches(&instr);
        assert!(!branches.is_empty());
        assert_eq!(branches[0].target, Some(4));
    }

    #[test]
    fn test_attiny_variant() {
        let a = AvrArch::new(AvrVariant::Attiny);
        assert_eq!(a.name(), "avr-tiny");
        let instr = a.disassemble(addr(0), &[0x00, 0x00]).unwrap();
        assert_eq!(instr.mnemonic, "NOP");
    }

    #[test]
    fn test_xmega_variant() {
        let a = AvrArch::new(AvrVariant::Xmega);
        assert_eq!(a.name(), "avr-xmega");
    }

    #[test]
    fn test_lpm_no_operand() {
        // LPM (no operand) = 0x95C8 LE=[0xC8,0x95]
        let instr = arch().disassemble(addr(0), &[0xC8, 0x95]).unwrap();
        assert_eq!(instr.mnemonic, "LPM");
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
    }
}

// ── AVR Instruction Kind Classification ───────────────────────────────────────

/// Broad category of an AVR instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvrInstrKind {
    /// NOP.
    Nop,
    /// Integer arithmetic (ADD, SUB, MUL, …).
    Arithmetic,
    /// Logic (AND, OR, EOR, …).
    Logic,
    /// Shift / rotate (LSR, ROR, ASR, …).
    Shift,
    /// Compare (CP, CPC, CPI, CPSE).
    Compare,
    /// Data transfer (MOV, LDI, …).
    Transfer,
    /// Load from memory.
    Load,
    /// Store to memory.
    Store,
    /// I/O port (IN, OUT, SBI, CBI).
    Io,
    /// Stack (PUSH, POP).
    Stack,
    /// Conditional branch.
    CondBranch,
    /// Unconditional branch / jump.
    Branch,
    /// Call.
    Call,
    /// Return.
    Return,
    /// Bit manipulation (BST, BLD, BSET, BCLR, SEI/CLI/…).
    BitOp,
    /// System / power (SLEEP, WDR, BREAK).
    System,
    /// Unknown / data word.
    Unknown,
}

impl AvrInstrKind {
    /// Classify an AVR instruction by mnemonic.
    #[must_use]
    pub fn from_mnemonic(mn: &str) -> Self {
        match mn {
            "NOP" => Self::Nop,
            "ADD" | "ADC" | "ADIW" | "SUB" | "SUBI" | "SBC" | "SBCI" | "SBIW" | "MUL" | "MULS"
            | "MULSU" | "NEG" | "INC" | "DEC" => Self::Arithmetic,
            "AND" | "ANDI" | "OR" | "ORI" | "EOR" | "COM" => Self::Logic,
            "LSR" | "ROR" | "ASR" | "SWAP" => Self::Shift,
            "CP" | "CPC" | "CPI" | "CPSE" => Self::Compare,
            "MOV" | "MOVW" | "LDI" => Self::Transfer,
            "LD" | "LDD" | "LDS" | "LPM" | "ELPM" => Self::Load,
            "ST" | "STD" | "STS" | "SPM" => Self::Store,
            "IN" | "OUT" | "SBI" | "CBI" => Self::Io,
            "PUSH" | "POP" => Self::Stack,
            "BRCS" | "BRCC" | "BREQ" | "BRNE" | "BRMI" | "BRPL" | "BRVS" | "BRVC" | "BRLT"
            | "BRGE" | "BRHS" | "BRHC" | "BRTS" | "BRTC" | "BRIE" | "BRID" | "SBRC" | "SBRS" => {
                Self::CondBranch
            }
            "RJMP" | "JMP" | "IJMP" | "EIJMP" => Self::Branch,
            "RCALL" | "CALL" | "ICALL" | "EICALL" => Self::Call,
            "RET" | "RETI" => Self::Return,
            "BST" | "BLD" | "BSET" | "BCLR" | "SEC" | "SEZ" | "SEN" | "SEV" | "SES" | "SEH"
            | "SET" | "SEI" | "CLC" | "CLZ" | "CLN" | "CLV" | "CLS" | "CLH" | "CLT" | "CLI" => {
                Self::BitOp
            }
            "SLEEP" | "WDR" | "BREAK" => Self::System,
            _ => Self::Unknown,
        }
    }

    /// Whether this kind is a control flow transfer.
    #[must_use]
    pub const fn is_control_flow(&self) -> bool {
        matches!(
            self,
            Self::CondBranch | Self::Branch | Self::Call | Self::Return
        )
    }

    /// Whether this kind accesses memory (load or store).
    #[must_use]
    pub const fn is_memory(&self) -> bool {
        matches!(self, Self::Load | Self::Store)
    }

    /// Whether this kind does I/O.
    #[must_use]
    pub fn is_io(&self) -> bool {
        *self == Self::Io
    }
}

// ── AVR IO Register Map ───────────────────────────────────────────────────────

/// A single AVR I/O register entry.
#[derive(Debug, Clone)]
pub struct AvrIoReg {
    /// I/O address (0x00–0x3F for classic I/O, 0x40–0xFF extended).
    pub addr: u8,
    /// Register name.
    pub name: &'static str,
    /// Short description.
    pub description: &'static str,
}

/// `ATmega328P` I/O register map (classic range 0x00–0x3F).
pub static ATMEGA328P_IO_MAP: &[AvrIoReg] = &[
    AvrIoReg {
        addr: 0x00,
        name: "PINB",
        description: "Port B Input Pins",
    },
    AvrIoReg {
        addr: 0x01,
        name: "DDRB",
        description: "Port B Data Direction",
    },
    AvrIoReg {
        addr: 0x02,
        name: "PORTB",
        description: "Port B Data Register",
    },
    AvrIoReg {
        addr: 0x03,
        name: "PINC",
        description: "Port C Input Pins",
    },
    AvrIoReg {
        addr: 0x04,
        name: "DDRC",
        description: "Port C Data Direction",
    },
    AvrIoReg {
        addr: 0x05,
        name: "PORTC",
        description: "Port C Data Register",
    },
    AvrIoReg {
        addr: 0x06,
        name: "PIND",
        description: "Port D Input Pins",
    },
    AvrIoReg {
        addr: 0x07,
        name: "DDRD",
        description: "Port D Data Direction",
    },
    AvrIoReg {
        addr: 0x08,
        name: "PORTD",
        description: "Port D Data Register",
    },
    AvrIoReg {
        addr: 0x15,
        name: "TIFR0",
        description: "Timer/Counter 0 Interrupt Flag",
    },
    AvrIoReg {
        addr: 0x16,
        name: "TIFR1",
        description: "Timer/Counter 1 Interrupt Flag",
    },
    AvrIoReg {
        addr: 0x17,
        name: "TIFR2",
        description: "Timer/Counter 2 Interrupt Flag",
    },
    AvrIoReg {
        addr: 0x1B,
        name: "PCIFR",
        description: "Pin Change Interrupt Flag",
    },
    AvrIoReg {
        addr: 0x1C,
        name: "EIFR",
        description: "External Interrupt Flag",
    },
    AvrIoReg {
        addr: 0x1D,
        name: "EIMSK",
        description: "External Interrupt Mask",
    },
    AvrIoReg {
        addr: 0x1E,
        name: "GPIOR0",
        description: "General Purpose I/O 0",
    },
    AvrIoReg {
        addr: 0x1F,
        name: "EECR",
        description: "EEPROM Control",
    },
    AvrIoReg {
        addr: 0x20,
        name: "EEDR",
        description: "EEPROM Data",
    },
    AvrIoReg {
        addr: 0x21,
        name: "EEARL",
        description: "EEPROM Address Low",
    },
    AvrIoReg {
        addr: 0x22,
        name: "EEARH",
        description: "EEPROM Address High",
    },
    AvrIoReg {
        addr: 0x23,
        name: "GTCCR",
        description: "General Timer/Counter Control",
    },
    AvrIoReg {
        addr: 0x24,
        name: "TCCR0A",
        description: "Timer/Counter 0 Control A",
    },
    AvrIoReg {
        addr: 0x25,
        name: "TCCR0B",
        description: "Timer/Counter 0 Control B",
    },
    AvrIoReg {
        addr: 0x26,
        name: "TCNT0",
        description: "Timer/Counter 0 Count",
    },
    AvrIoReg {
        addr: 0x27,
        name: "OCR0A",
        description: "Timer/Counter 0 Output Compare A",
    },
    AvrIoReg {
        addr: 0x28,
        name: "OCR0B",
        description: "Timer/Counter 0 Output Compare B",
    },
    AvrIoReg {
        addr: 0x2A,
        name: "GPIOR1",
        description: "General Purpose I/O 1",
    },
    AvrIoReg {
        addr: 0x2B,
        name: "GPIOR2",
        description: "General Purpose I/O 2",
    },
    AvrIoReg {
        addr: 0x2C,
        name: "SPCR",
        description: "SPI Control",
    },
    AvrIoReg {
        addr: 0x2D,
        name: "SPSR",
        description: "SPI Status",
    },
    AvrIoReg {
        addr: 0x2E,
        name: "SPDR",
        description: "SPI Data",
    },
    AvrIoReg {
        addr: 0x30,
        name: "ACSR",
        description: "Analog Comparator Control/Status",
    },
    AvrIoReg {
        addr: 0x33,
        name: "SMCR",
        description: "Sleep Mode Control",
    },
    AvrIoReg {
        addr: 0x34,
        name: "MCUSR",
        description: "MCU Status",
    },
    AvrIoReg {
        addr: 0x35,
        name: "MCUCR",
        description: "MCU Control",
    },
    AvrIoReg {
        addr: 0x37,
        name: "SPMCSR",
        description: "Store Program Memory Control/Status",
    },
    AvrIoReg {
        addr: 0x3B,
        name: "RAMPZ",
        description: "RAM Page Z Select",
    },
    AvrIoReg {
        addr: 0x3C,
        name: "SPL",
        description: "Stack Pointer Low",
    },
    AvrIoReg {
        addr: 0x3D,
        name: "SPH",
        description: "Stack Pointer High",
    },
    AvrIoReg {
        addr: 0x3F,
        name: "SREG",
        description: "Status Register",
    },
];

/// Look up an I/O register by address.
#[must_use]
pub fn lookup_io_reg(addr: u8) -> Option<&'static AvrIoReg> {
    ATMEGA328P_IO_MAP.iter().find(|r| r.addr == addr)
}

// ── AVR Interrupt Vector Table ────────────────────────────────────────────────

/// A single AVR interrupt vector entry.
#[derive(Debug, Clone)]
pub struct AvrInterruptVector {
    /// Vector number (0-based; vector 0 = reset).
    pub number: u8,
    /// Vector name.
    pub name: &'static str,
    /// Description.
    pub description: &'static str,
    /// Byte offset from flash start (vector number * 2 for tiny/mega).
    pub byte_offset: u16,
}

/// `ATmega328P` interrupt vector table.
pub static ATMEGA328P_VECTORS: &[AvrInterruptVector] = &[
    AvrInterruptVector {
        number: 0,
        name: "RESET",
        description: "External Pin, Power-on Reset, Brown-out Reset, Watchdog",
        byte_offset: 0x0000,
    },
    AvrInterruptVector {
        number: 1,
        name: "INT0",
        description: "External Interrupt Request 0",
        byte_offset: 0x0002,
    },
    AvrInterruptVector {
        number: 2,
        name: "INT1",
        description: "External Interrupt Request 1",
        byte_offset: 0x0004,
    },
    AvrInterruptVector {
        number: 3,
        name: "PCINT0",
        description: "Pin Change Interrupt Request 0",
        byte_offset: 0x0006,
    },
    AvrInterruptVector {
        number: 4,
        name: "PCINT1",
        description: "Pin Change Interrupt Request 1",
        byte_offset: 0x0008,
    },
    AvrInterruptVector {
        number: 5,
        name: "PCINT2",
        description: "Pin Change Interrupt Request 2",
        byte_offset: 0x000A,
    },
    AvrInterruptVector {
        number: 6,
        name: "WDT",
        description: "Watchdog Time-out Interrupt",
        byte_offset: 0x000C,
    },
    AvrInterruptVector {
        number: 7,
        name: "TIMER2_COMPA",
        description: "Timer/Counter2 Compare Match A",
        byte_offset: 0x000E,
    },
    AvrInterruptVector {
        number: 8,
        name: "TIMER2_COMPB",
        description: "Timer/Counter2 Compare Match B",
        byte_offset: 0x0010,
    },
    AvrInterruptVector {
        number: 9,
        name: "TIMER2_OVF",
        description: "Timer/Counter2 Overflow",
        byte_offset: 0x0012,
    },
    AvrInterruptVector {
        number: 10,
        name: "TIMER1_CAPT",
        description: "Timer/Counter1 Capture Event",
        byte_offset: 0x0014,
    },
    AvrInterruptVector {
        number: 11,
        name: "TIMER1_COMPA",
        description: "Timer/Counter1 Compare Match A",
        byte_offset: 0x0016,
    },
    AvrInterruptVector {
        number: 12,
        name: "TIMER1_COMPB",
        description: "Timer/Counter1 Compare Match B",
        byte_offset: 0x0018,
    },
    AvrInterruptVector {
        number: 13,
        name: "TIMER1_OVF",
        description: "Timer/Counter1 Overflow",
        byte_offset: 0x001A,
    },
    AvrInterruptVector {
        number: 14,
        name: "TIMER0_COMPA",
        description: "Timer/Counter0 Compare Match A",
        byte_offset: 0x001C,
    },
    AvrInterruptVector {
        number: 15,
        name: "TIMER0_COMPB",
        description: "Timer/Counter0 Compare Match B",
        byte_offset: 0x001E,
    },
    AvrInterruptVector {
        number: 16,
        name: "TIMER0_OVF",
        description: "Timer/Counter0 Overflow",
        byte_offset: 0x0020,
    },
    AvrInterruptVector {
        number: 17,
        name: "SPI_STC",
        description: "SPI Serial Transfer Complete",
        byte_offset: 0x0022,
    },
    AvrInterruptVector {
        number: 18,
        name: "USART_RX",
        description: "USART Rx Complete",
        byte_offset: 0x0024,
    },
    AvrInterruptVector {
        number: 19,
        name: "USART_UDRE",
        description: "USART Data Register Empty",
        byte_offset: 0x0026,
    },
    AvrInterruptVector {
        number: 20,
        name: "USART_TX",
        description: "USART Tx Complete",
        byte_offset: 0x0028,
    },
    AvrInterruptVector {
        number: 21,
        name: "ADC",
        description: "ADC Conversion Complete",
        byte_offset: 0x002A,
    },
    AvrInterruptVector {
        number: 22,
        name: "EE_READY",
        description: "EEPROM Ready",
        byte_offset: 0x002C,
    },
    AvrInterruptVector {
        number: 23,
        name: "ANALOG_COMP",
        description: "Analog Comparator",
        byte_offset: 0x002E,
    },
    AvrInterruptVector {
        number: 24,
        name: "TWI",
        description: "Two-wire Serial Interface",
        byte_offset: 0x0030,
    },
    AvrInterruptVector {
        number: 25,
        name: "SPM_READY",
        description: "Store Program Memory Ready",
        byte_offset: 0x0032,
    },
];

/// Look up an interrupt vector by number.
#[must_use]
pub fn lookup_vector(number: u8) -> Option<&'static AvrInterruptVector> {
    ATMEGA328P_VECTORS.iter().find(|v| v.number == number)
}

// ── AVR Code Statistics ───────────────────────────────────────────────────────

/// Statistics from linear-sweep disassembly of AVR code.
#[derive(Debug, Clone, Default)]
pub struct AvrCodeStats {
    /// Total instructions.
    pub total: usize,
    /// NOPs.
    pub nops: usize,
    /// Arithmetic instructions.
    pub arithmetic: usize,
    /// Logic instructions.
    pub logic: usize,
    /// Shift/rotate instructions.
    pub shifts: usize,
    /// Compare instructions.
    pub compares: usize,
    /// Data transfer instructions.
    pub transfers: usize,
    /// Load instructions.
    pub loads: usize,
    /// Store instructions.
    pub stores: usize,
    /// I/O instructions.
    pub io_ops: usize,
    /// Stack instructions (PUSH/POP).
    pub stack_ops: usize,
    /// Conditional branches.
    pub cond_branches: usize,
    /// Unconditional branches.
    pub branches: usize,
    /// Calls.
    pub calls: usize,
    /// Returns.
    pub returns: usize,
    /// Bit manipulation instructions.
    pub bit_ops: usize,
    /// System instructions.
    pub system: usize,
    /// Decode errors.
    pub errors: usize,
}

impl AvrCodeStats {
    /// Collect statistics by linear-sweep over `bytes`.
    #[must_use]
    pub fn from_bytes(arch: &AvrArch, bytes: &[u8], base: Address) -> Self {
        let mut s = Self::default();
        let iter = AvrLinearDisassembler::new(arch, bytes, base);
        for result in iter {
            match result {
                Err(_) => s.errors += 1,
                Ok(instr) => {
                    s.total += 1;
                    match AvrInstrKind::from_mnemonic(&instr.mnemonic) {
                        AvrInstrKind::Nop => s.nops += 1,
                        AvrInstrKind::Arithmetic => s.arithmetic += 1,
                        AvrInstrKind::Logic => s.logic += 1,
                        AvrInstrKind::Shift => s.shifts += 1,
                        AvrInstrKind::Compare => s.compares += 1,
                        AvrInstrKind::Transfer => s.transfers += 1,
                        AvrInstrKind::Load => s.loads += 1,
                        AvrInstrKind::Store => s.stores += 1,
                        AvrInstrKind::Io => s.io_ops += 1,
                        AvrInstrKind::Stack => s.stack_ops += 1,
                        AvrInstrKind::CondBranch => s.cond_branches += 1,
                        AvrInstrKind::Branch => s.branches += 1,
                        AvrInstrKind::Call => s.calls += 1,
                        AvrInstrKind::Return => s.returns += 1,
                        AvrInstrKind::BitOp => s.bit_ops += 1,
                        AvrInstrKind::System => s.system += 1,
                        AvrInstrKind::Unknown => {}
                    }
                }
            }
        }
        s
    }
}

// ── AVR Function Prologue / Epilogue Detection ────────────────────────────────

/// AVR GCC function prologue/epilogue pattern matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvrFuncPattern {
    /// `PUSH Rxx` — callee-saved register preservation.
    SaveReg(String),
    /// `POP Rxx` — callee-saved register restoration.
    RestoreReg(String),
    /// `RCALL .` (self-call, old-style stack frame reservation).
    StackReserve,
    /// `RET` / `RETI` — function return.
    FuncReturn,
    /// No recognized pattern.
    None,
}

impl AvrFuncPattern {
    /// Identify a pattern from a single instruction.
    #[must_use]
    pub fn from_instr(instr: &Instruction) -> Self {
        match instr.mnemonic.as_str() {
            "PUSH" => Self::SaveReg(instr.operands.clone()),
            "POP" => Self::RestoreReg(instr.operands.clone()),
            "RET" | "RETI" => Self::FuncReturn,
            "RCALL" if instr.operands == "$0002" => Self::StackReserve,
            _ => Self::None,
        }
    }
}

// ── AVR Basic Block ───────────────────────────────────────────────────────────

/// A basic block of AVR instructions.
#[derive(Debug, Clone)]
pub struct AvrBasicBlock {
    /// Start address.
    pub start: Address,
    /// Instructions.
    pub instructions: Vec<Instruction>,
}

impl AvrBasicBlock {
    /// Find basic blocks in `bytes`.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if any instruction fails to decode.
    pub fn find_blocks(
        arch: &AvrArch,
        bytes: &[u8],
        base: Address,
    ) -> Result<Vec<Self>, CoreError> {
        let mut blocks: Vec<Self> = Vec::new();
        let mut current: Vec<Instruction> = Vec::new();
        let mut block_start = base;
        let mut offset = 0usize;

        while offset < bytes.len() {
            if bytes.len() - offset < 2 {
                break;
            }
            let addr = base + offset as u64;
            let instr = arch.disassemble(addr, &bytes[offset..])?;
            let is_terminator = instr.flags.intersects(InstrFlags::BRANCH | InstrFlags::RET);
            let sz = instr.size;
            current.push(instr);
            offset += sz;

            if is_terminator {
                blocks.push(Self {
                    start: block_start,
                    instructions: std::mem::take(&mut current),
                });
                block_start = base + offset as u64;
            }
        }

        if !current.is_empty() {
            blocks.push(Self {
                start: block_start,
                instructions: current,
            });
        }

        Ok(blocks)
    }

    /// Number of instructions in this block.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Whether the block is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

// ── AVR SREG Bit Definitions ──────────────────────────────────────────────────

/// SREG bit positions and names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AvrSregBit {
    /// Carry flag.
    C = 0,
    /// Zero flag.
    Z = 1,
    /// Negative flag.
    N = 2,
    /// Overflow flag.
    V = 3,
    /// Sign flag (N XOR V).
    S = 4,
    /// Half-carry flag.
    H = 5,
    /// Transfer bit.
    T = 6,
    /// Global interrupt enable.
    I = 7,
}

impl AvrSregBit {
    /// Name of this SREG bit.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::C => "C",
            Self::Z => "Z",
            Self::N => "N",
            Self::V => "V",
            Self::S => "S",
            Self::H => "H",
            Self::T => "T",
            Self::I => "I",
        }
    }

    /// Bit mask for this flag in SREG.
    #[must_use]
    pub const fn mask(self) -> u8 {
        1 << (self as u8)
    }
}

// ── AVR Disassembly Formatter ─────────────────────────────────────────────────

/// Format an AVR instruction in a standard way.
#[must_use]
pub fn avr_format(instr: &Instruction) -> String {
    if instr.operands.is_empty() {
        instr.mnemonic.clone()
    } else {
        format!("{} {}", instr.mnemonic, instr.operands)
    }
}

/// Format with address prefix.
#[must_use]
pub fn avr_format_with_addr(instr: &Instruction) -> String {
    format!("{:06X}: {}", instr.address.as_u64(), avr_format(instr))
}

// ── AVR Annotation ────────────────────────────────────────────────────────────

/// An annotated AVR instruction with kind and pattern information.
#[derive(Debug, Clone)]
pub struct AnnotatedAvrInstr {
    /// The underlying instruction.
    pub instr: Instruction,
    /// Instruction kind.
    pub kind: AvrInstrKind,
    /// Function pattern (if any).
    pub pattern: AvrFuncPattern,
}

impl AnnotatedAvrInstr {
    /// Annotate a single instruction.
    #[must_use]
    pub fn from_instr(instr: Instruction) -> Self {
        let kind = AvrInstrKind::from_mnemonic(&instr.mnemonic);
        let pattern = AvrFuncPattern::from_instr(&instr);
        Self {
            instr,
            kind,
            pattern,
        }
    }
}

/// Disassemble and annotate a byte slice.
///
/// # Errors
///
/// Returns `CoreError` if any instruction fails to decode.
pub fn disassemble_annotated(
    arch: &AvrArch,
    bytes: &[u8],
    base: Address,
) -> Result<Vec<AnnotatedAvrInstr>, CoreError> {
    // AVR instructions are 2 or 4 bytes; reserve based on a 2-byte average.
    // Cap the pre-allocation to 64 Ki entries so an attacker-supplied large
    // binary cannot exhaust memory through Vec::with_capacity alone.
    let mut results = Vec::with_capacity((bytes.len() / 2).min(65536));
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < 2 {
            break;
        }
        let addr = base + offset as u64;
        let instr = arch.disassemble(addr, &bytes[offset..])?;
        let sz = instr.size;
        results.push(AnnotatedAvrInstr::from_instr(instr));
        offset += sz;
    }
    Ok(results)
}

// ── AVR Prologue Detector ─────────────────────────────────────────────────────

/// Information about a detected function prologue.
#[derive(Debug, Clone)]
pub struct AvrPrologueInfo {
    /// Registers saved (in order).
    pub saved_regs: Vec<String>,
    /// Number of prologue instructions (PUSH count).
    pub push_count: usize,
}

impl AvrPrologueInfo {
    /// Detect the prologue at the start of a sequence of annotated instructions.
    #[must_use]
    pub fn detect(instrs: &[AnnotatedAvrInstr]) -> Self {
        let mut saved_regs = Vec::new();
        let mut push_count = 0;
        for ai in instrs {
            if let AvrFuncPattern::SaveReg(ref r) = ai.pattern {
                saved_regs.push(r.clone());
                push_count += 1;
            } else {
                break;
            }
        }
        Self {
            saved_regs,
            push_count,
        }
    }
}

// ── AVR Calling Convention Details ───────────────────────────────────────────

/// Detailed AVR GCC calling convention register usage.
#[derive(Debug, Clone)]
pub struct AvrRegRole {
    /// Register name.
    pub name: &'static str,
    /// Register number (0-31).
    pub number: u8,
    /// Whether it is caller-saved (scratch).
    pub caller_saved: bool,
    /// Whether it is used for parameter passing.
    pub param: bool,
    /// Parameter index if used (0-based).
    pub param_index: Option<u8>,
}

/// AVR GCC register roles.
pub static AVR_REG_ROLES: &[AvrRegRole] = &[
    AvrRegRole {
        name: "R0",
        number: 0,
        caller_saved: true,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R1",
        number: 1,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R2",
        number: 2,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R3",
        number: 3,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R4",
        number: 4,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R5",
        number: 5,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R6",
        number: 6,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R7",
        number: 7,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R8",
        number: 8,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R9",
        number: 9,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R10",
        number: 10,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R11",
        number: 11,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R12",
        number: 12,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R13",
        number: 13,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R14",
        number: 14,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R15",
        number: 15,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R16",
        number: 16,
        caller_saved: true,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R17",
        number: 17,
        caller_saved: true,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R18",
        number: 18,
        caller_saved: true,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R19",
        number: 19,
        caller_saved: true,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R20",
        number: 20,
        caller_saved: true,
        param: true,
        param_index: Some(2),
    },
    AvrRegRole {
        name: "R21",
        number: 21,
        caller_saved: true,
        param: true,
        param_index: Some(2),
    },
    AvrRegRole {
        name: "R22",
        number: 22,
        caller_saved: true,
        param: true,
        param_index: Some(1),
    },
    AvrRegRole {
        name: "R23",
        number: 23,
        caller_saved: true,
        param: true,
        param_index: Some(1),
    },
    AvrRegRole {
        name: "R24",
        number: 24,
        caller_saved: true,
        param: true,
        param_index: Some(0),
    },
    AvrRegRole {
        name: "R25",
        number: 25,
        caller_saved: true,
        param: true,
        param_index: Some(0),
    },
    AvrRegRole {
        name: "R26",
        number: 26,
        caller_saved: true,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R27",
        number: 27,
        caller_saved: true,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R28",
        number: 28,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R29",
        number: 29,
        caller_saved: false,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R30",
        number: 30,
        caller_saved: true,
        param: false,
        param_index: None,
    },
    AvrRegRole {
        name: "R31",
        number: 31,
        caller_saved: true,
        param: false,
        param_index: None,
    },
];

/// Look up a register role by register number.
#[must_use]
pub fn lookup_reg_role(number: u8) -> Option<&'static AvrRegRole> {
    AVR_REG_ROLES.iter().find(|r| r.number == number)
}

// ── AVR Disassembly Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;

    fn arch() -> AvrArch {
        AvrArch::default()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    #[test]
    fn test_kind_nop() {
        assert_eq!(AvrInstrKind::from_mnemonic("NOP"), AvrInstrKind::Nop);
    }

    #[test]
    fn test_kind_add() {
        assert_eq!(AvrInstrKind::from_mnemonic("ADD"), AvrInstrKind::Arithmetic);
    }

    #[test]
    fn test_kind_and_logic() {
        assert_eq!(AvrInstrKind::from_mnemonic("AND"), AvrInstrKind::Logic);
        assert!(!AvrInstrKind::Logic.is_control_flow());
    }

    #[test]
    fn test_kind_lsr_shift() {
        assert_eq!(AvrInstrKind::from_mnemonic("LSR"), AvrInstrKind::Shift);
    }

    #[test]
    fn test_kind_cpi_compare() {
        assert_eq!(AvrInstrKind::from_mnemonic("CPI"), AvrInstrKind::Compare);
    }

    #[test]
    fn test_kind_mov_transfer() {
        assert_eq!(AvrInstrKind::from_mnemonic("MOV"), AvrInstrKind::Transfer);
    }

    #[test]
    fn test_kind_ld_load() {
        assert_eq!(AvrInstrKind::from_mnemonic("LD"), AvrInstrKind::Load);
        assert!(AvrInstrKind::Load.is_memory());
    }

    #[test]
    fn test_kind_st_store() {
        assert_eq!(AvrInstrKind::from_mnemonic("ST"), AvrInstrKind::Store);
        assert!(AvrInstrKind::Store.is_memory());
    }

    #[test]
    fn test_kind_in_io() {
        assert_eq!(AvrInstrKind::from_mnemonic("IN"), AvrInstrKind::Io);
        assert!(AvrInstrKind::Io.is_io());
    }

    #[test]
    fn test_kind_push_stack() {
        assert_eq!(AvrInstrKind::from_mnemonic("PUSH"), AvrInstrKind::Stack);
    }

    #[test]
    fn test_kind_brne_cond() {
        assert_eq!(
            AvrInstrKind::from_mnemonic("BRNE"),
            AvrInstrKind::CondBranch
        );
        assert!(AvrInstrKind::CondBranch.is_control_flow());
    }

    #[test]
    fn test_kind_rjmp_branch() {
        assert_eq!(AvrInstrKind::from_mnemonic("RJMP"), AvrInstrKind::Branch);
        assert!(AvrInstrKind::Branch.is_control_flow());
    }

    #[test]
    fn test_kind_call() {
        assert_eq!(AvrInstrKind::from_mnemonic("CALL"), AvrInstrKind::Call);
        assert!(AvrInstrKind::Call.is_control_flow());
    }

    #[test]
    fn test_kind_ret() {
        assert_eq!(AvrInstrKind::from_mnemonic("RET"), AvrInstrKind::Return);
        assert!(AvrInstrKind::Return.is_control_flow());
    }

    #[test]
    fn test_kind_sei_bitop() {
        assert_eq!(AvrInstrKind::from_mnemonic("SEI"), AvrInstrKind::BitOp);
    }

    #[test]
    fn test_kind_sleep_system() {
        assert_eq!(AvrInstrKind::from_mnemonic("SLEEP"), AvrInstrKind::System);
    }

    #[test]
    fn test_io_reg_sreg() {
        let r = lookup_io_reg(0x3F).unwrap();
        assert_eq!(r.name, "SREG");
    }

    #[test]
    fn test_io_reg_portb() {
        let r = lookup_io_reg(0x02).unwrap();
        assert_eq!(r.name, "PORTB");
    }

    #[test]
    fn test_io_reg_not_found() {
        assert!(lookup_io_reg(0xFF).is_none());
    }

    #[test]
    fn test_vector_reset() {
        let v = lookup_vector(0).unwrap();
        assert_eq!(v.name, "RESET");
        assert_eq!(v.byte_offset, 0);
    }

    #[test]
    fn test_vector_usart_rx() {
        let v = lookup_vector(18).unwrap();
        assert_eq!(v.name, "USART_RX");
    }

    #[test]
    fn test_vector_not_found() {
        assert!(lookup_vector(255).is_none());
    }

    #[test]
    fn test_stats_nop_ret() {
        let code = [0x00u8, 0x00, 0x08, 0x95]; // NOP, RET
        let a = arch();
        let stats = AvrCodeStats::from_bytes(&a, &code, addr(0));
        assert_eq!(stats.total, 2);
        assert_eq!(stats.nops, 1);
        assert_eq!(stats.returns, 1);
    }

    #[test]
    fn test_stats_loads_stores() {
        let code = [
            0x0Cu8, 0x90, // LD R0,X
            0x0Cu8, 0x92, // ST X,R0
        ];
        let a = arch();
        let stats = AvrCodeStats::from_bytes(&a, &code, addr(0));
        assert_eq!(stats.loads, 1);
        assert_eq!(stats.stores, 1);
    }

    #[test]
    fn test_basic_block_rjmp_splits() {
        // NOP + RJMP (terminates block) + NOP (new block)
        let code = [
            0x00u8, 0x00, // NOP
            0xFF, 0xCF, // RJMP self (terminates block)
            0x00, 0x00, // NOP (new block)
        ];
        let a = arch();
        let blocks = AvrBasicBlock::find_blocks(&a, &code, addr(0)).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].len(), 2); // NOP + RJMP
        assert_eq!(blocks[1].len(), 1); // NOP
    }

    #[test]
    fn test_pattern_push() {
        let instr = arch().disassemble(addr(0), &[0x0F, 0x93]).unwrap();
        let pat = AvrFuncPattern::from_instr(&instr);
        assert!(matches!(pat, AvrFuncPattern::SaveReg(_)));
    }

    #[test]
    fn test_pattern_pop() {
        let instr = arch().disassemble(addr(0), &[0x0F, 0x90]).unwrap();
        let pat = AvrFuncPattern::from_instr(&instr);
        assert!(matches!(pat, AvrFuncPattern::RestoreReg(_)));
    }

    #[test]
    fn test_pattern_ret() {
        let instr = arch().disassemble(addr(0), &[0x08, 0x95]).unwrap();
        let pat = AvrFuncPattern::from_instr(&instr);
        assert_eq!(pat, AvrFuncPattern::FuncReturn);
    }

    #[test]
    fn test_prologue_detect() {
        // PUSH R29, PUSH R28, NOP
        let code = [
            0xDF, 0x93, // PUSH R29 = 1001 0011 1101 1111 = 0x93DF
            0xCF, 0x93, // PUSH R28 = 1001 0011 1100 1111 = 0x93CF
            0x00, 0x00, // NOP
        ];
        let a = arch();
        let annotated = disassemble_annotated(&a, &code, addr(0)).unwrap();
        let prologue = AvrPrologueInfo::detect(&annotated);
        assert_eq!(prologue.push_count, 2);
        assert_eq!(prologue.saved_regs.len(), 2);
    }

    #[test]
    fn test_sreg_mask() {
        assert_eq!(AvrSregBit::I.mask(), 0x80);
        assert_eq!(AvrSregBit::C.mask(), 0x01);
        assert_eq!(AvrSregBit::Z.mask(), 0x02);
    }

    #[test]
    fn test_sreg_names() {
        assert_eq!(AvrSregBit::I.name(), "I");
        assert_eq!(AvrSregBit::N.name(), "N");
    }

    #[test]
    fn test_reg_role_r24_param() {
        let r = lookup_reg_role(24).unwrap();
        assert!(r.param);
        assert_eq!(r.param_index, Some(0));
        assert!(r.caller_saved);
    }

    #[test]
    fn test_reg_role_r1_callee_saved() {
        let r = lookup_reg_role(1).unwrap();
        assert!(!r.caller_saved);
        assert!(!r.param);
    }

    #[test]
    fn test_reg_role_not_found() {
        assert!(lookup_reg_role(200).is_none());
    }

    #[test]
    fn test_format_avr() {
        let instr = arch().disassemble(addr(0), &[0x00, 0x00]).unwrap();
        assert_eq!(avr_format(&instr), "NOP");
    }

    #[test]
    fn test_format_with_addr() {
        let instr = arch().disassemble(addr(0x200), &[0x00, 0x00]).unwrap();
        let s = avr_format_with_addr(&instr);
        assert!(s.contains("000200") || s.contains("200"), "got: {s}");
        assert!(s.contains("NOP"));
    }

    #[test]
    fn test_annotated_disasm() {
        let code = [0x00u8, 0x00, 0x08, 0x95]; // NOP, RET
        let a = arch();
        let ann = disassemble_annotated(&a, &code, addr(0)).unwrap();
        assert_eq!(ann.len(), 2);
        assert_eq!(ann[0].kind, AvrInstrKind::Nop);
        assert_eq!(ann[1].kind, AvrInstrKind::Return);
    }

    #[test]
    fn test_vectors_count() {
        assert_eq!(ATMEGA328P_VECTORS.len(), 26);
    }

    #[test]
    fn test_io_map_sreg_addr() {
        let sreg = lookup_io_reg(0x3F).unwrap();
        assert_eq!(sreg.addr, 0x3F);
    }

    #[test]
    fn test_avr_reg_roles_count() {
        assert_eq!(AVR_REG_ROLES.len(), 32);
    }
}

// ── AVR Encoding Helpers ──────────────────────────────────────────────────────

/// Encode an AVR `NOP` instruction.
#[must_use]
pub const fn encode_nop() -> u16 {
    0x0000
}

/// Encode `RJMP k` (relative jump, 12-bit signed displacement in words).
///
/// # Panics
///
/// Panics if `k` is outside −2048..=2047.
#[must_use]
pub fn encode_rjmp(k: i16) -> u16 {
    assert!(
        (-2048..=2047).contains(&i32::from(k)),
        "RJMP displacement out of range"
    );
    0xC000u16 | (k.cast_unsigned() & 0x0FFF)
}

/// Encode `RCALL k` (relative call, 12-bit signed displacement in words).
///
/// # Panics
///
/// Panics if `k` is outside −2048..=2047.
#[must_use]
pub fn encode_rcall(k: i16) -> u16 {
    assert!(
        (-2048..=2047).contains(&i32::from(k)),
        "RCALL displacement out of range"
    );
    0xD000u16 | (k.cast_unsigned() & 0x0FFF)
}

/// Encode `MOV rd, rr` (copy register, 0 ≤ d,r ≤ 31).
///
/// # Panics
///
/// Panics if `rd` or `rr` > 31.
#[must_use]
pub fn encode_mov(rd: u8, rr: u8) -> u16 {
    assert!(rd <= 31 && rr <= 31, "MOV register out of range");
    let d = u16::from(rd);
    let r = u16::from(rr);
    0x2C00 | ((d & 0x10) << 4) | ((r & 0x10) << 5) | ((d & 0x0F) << 4) | (r & 0x0F)
}

/// Encode `ADD rd, rr` (d = d + r).
///
/// # Panics
///
/// Panics if `rd` or `rr` > 31.
#[must_use]
pub fn encode_add(rd: u8, rr: u8) -> u16 {
    assert!(rd <= 31 && rr <= 31, "ADD register out of range");
    let d = u16::from(rd);
    let r = u16::from(rr);
    0x0C00 | ((d & 0x10) << 4) | ((r & 0x10) << 5) | ((d & 0x0F) << 4) | (r & 0x0F)
}

/// Encode `ADC rd, rr` (add with carry, d = d + r + C).
///
/// # Panics
///
/// Panics if `rd` or `rr` > 31.
#[must_use]
pub fn encode_adc(rd: u8, rr: u8) -> u16 {
    assert!(rd <= 31 && rr <= 31, "ADC register out of range");
    let d = u16::from(rd);
    let r = u16::from(rr);
    0x1C00 | ((d & 0x10) << 4) | ((r & 0x10) << 5) | ((d & 0x0F) << 4) | (r & 0x0F)
}

/// Encode `SUB rd, rr`.
///
/// # Panics
///
/// Panics if `rd` or `rr` > 31.
#[must_use]
pub fn encode_sub(rd: u8, rr: u8) -> u16 {
    assert!(rd <= 31 && rr <= 31, "SUB register out of range");
    let d = u16::from(rd);
    let r = u16::from(rr);
    0x1800 | ((d & 0x10) << 4) | ((r & 0x10) << 5) | ((d & 0x0F) << 4) | (r & 0x0F)
}

/// Encode `AND rd, rr`.
///
/// # Panics
///
/// Panics if `rd` or `rr` > 31.
#[must_use]
pub fn encode_and(rd: u8, rr: u8) -> u16 {
    assert!(rd <= 31 && rr <= 31, "AND register out of range");
    let d = u16::from(rd);
    let r = u16::from(rr);
    0x2000 | ((d & 0x10) << 4) | ((r & 0x10) << 5) | ((d & 0x0F) << 4) | (r & 0x0F)
}

/// Encode `OR rd, rr`.
///
/// # Panics
///
/// Panics if `rd` or `rr` > 31.
#[must_use]
pub fn encode_or(rd: u8, rr: u8) -> u16 {
    assert!(rd <= 31 && rr <= 31, "OR register out of range");
    let d = u16::from(rd);
    let r = u16::from(rr);
    0x2800 | ((d & 0x10) << 4) | ((r & 0x10) << 5) | ((d & 0x0F) << 4) | (r & 0x0F)
}

/// Encode `EOR rd, rr` (exclusive or).
///
/// # Panics
///
/// Panics if `rd` or `rr` > 31.
#[must_use]
pub fn encode_eor(rd: u8, rr: u8) -> u16 {
    assert!(rd <= 31 && rr <= 31, "EOR register out of range");
    let d = u16::from(rd);
    let r = u16::from(rr);
    0x2400 | ((d & 0x10) << 4) | ((r & 0x10) << 5) | ((d & 0x0F) << 4) | (r & 0x0F)
}

/// Encode `CP rd, rr` (compare, no result stored).
///
/// # Panics
///
/// Panics if `rd` or `rr` > 31.
#[must_use]
pub fn encode_cp(rd: u8, rr: u8) -> u16 {
    assert!(rd <= 31 && rr <= 31, "CP register out of range");
    let d = u16::from(rd);
    let r = u16::from(rr);
    0x1400 | ((d & 0x10) << 4) | ((r & 0x10) << 5) | ((d & 0x0F) << 4) | (r & 0x0F)
}

/// Encode `CPC rd, rr` (compare with carry).
///
/// # Panics
///
/// Panics if `rd` or `rr` > 31.
#[must_use]
pub fn encode_cpc(rd: u8, rr: u8) -> u16 {
    assert!(rd <= 31 && rr <= 31, "CPC register out of range");
    let d = u16::from(rd);
    let r = u16::from(rr);
    0x0400 | ((d & 0x10) << 4) | ((r & 0x10) << 5) | ((d & 0x0F) << 4) | (r & 0x0F)
}

/// Encode `CPSE rd, rr` (compare, skip if equal).
///
/// # Panics
///
/// Panics if `rd` or `rr` > 31.
#[must_use]
pub fn encode_cpse(rd: u8, rr: u8) -> u16 {
    assert!(rd <= 31 && rr <= 31, "CPSE register out of range");
    let d = u16::from(rd);
    let r = u16::from(rr);
    0x1000 | ((d & 0x10) << 4) | ((r & 0x10) << 5) | ((d & 0x0F) << 4) | (r & 0x0F)
}

/// Encode `LDI rd, K` (load immediate, 16 ≤ rd ≤ 31, 0 ≤ K ≤ 255).
///
/// # Panics
///
/// Panics if `rd` < 16 or `rd` > 31 or `k` > 255.
#[must_use]
pub fn encode_ldi(rd: u8, k: u8) -> u16 {
    assert!((16..=31).contains(&rd), "LDI destination must be r16–r31");
    let d = u16::from(rd - 16);
    let kw = u16::from(k);
    0xE000 | ((kw & 0xF0) << 4) | (d << 4) | (kw & 0x0F)
}

/// Encode `SUBI rd, K` (subtract immediate, 16 ≤ rd ≤ 31).
///
/// # Panics
///
/// Panics if `rd` < 16 or `rd` > 31.
#[must_use]
pub fn encode_subi(rd: u8, k: u8) -> u16 {
    assert!((16..=31).contains(&rd), "SUBI destination must be r16–r31");
    let d = u16::from(rd - 16);
    let kw = u16::from(k);
    0x5000 | ((kw & 0xF0) << 4) | (d << 4) | (kw & 0x0F)
}

/// Encode `SBCI rd, K` (subtract with carry immediate, 16 ≤ rd ≤ 31).
///
/// # Panics
///
/// Panics if `rd` < 16 or `rd` > 31.
#[must_use]
pub fn encode_sbci(rd: u8, k: u8) -> u16 {
    assert!((16..=31).contains(&rd), "SBCI destination must be r16–r31");
    let d = u16::from(rd - 16);
    let kw = u16::from(k);
    0x4000 | ((kw & 0xF0) << 4) | (d << 4) | (kw & 0x0F)
}

/// Encode `ANDI rd, K` (AND immediate, 16 ≤ rd ≤ 31).
///
/// # Panics
///
/// Panics if `rd` < 16 or `rd` > 31.
#[must_use]
pub fn encode_andi(rd: u8, k: u8) -> u16 {
    assert!((16..=31).contains(&rd), "ANDI destination must be r16–r31");
    let d = u16::from(rd - 16);
    let kw = u16::from(k);
    0x7000 | ((kw & 0xF0) << 4) | (d << 4) | (kw & 0x0F)
}

/// Encode `ORI rd, K` (OR immediate, 16 ≤ rd ≤ 31).
///
/// # Panics
///
/// Panics if `rd` < 16 or `rd` > 31.
#[must_use]
pub fn encode_ori(rd: u8, k: u8) -> u16 {
    assert!((16..=31).contains(&rd), "ORI destination must be r16–r31");
    let d = u16::from(rd - 16);
    let kw = u16::from(k);
    0x6000 | ((kw & 0xF0) << 4) | (d << 4) | (kw & 0x0F)
}

/// Encode `CPI rd, K` (compare with immediate, 16 ≤ rd ≤ 31).
///
/// # Panics
///
/// Panics if `rd` < 16 or `rd` > 31.
#[must_use]
pub fn encode_cpi(rd: u8, k: u8) -> u16 {
    assert!((16..=31).contains(&rd), "CPI destination must be r16–r31");
    let d = u16::from(rd - 16);
    let kw = u16::from(k);
    0x3000 | ((kw & 0xF0) << 4) | (d << 4) | (kw & 0x0F)
}

/// Encode `INC rd` (increment register, 0 ≤ rd ≤ 31).
///
/// # Panics
///
/// Panics if `rd` > 31.
#[must_use]
pub fn encode_inc(rd: u8) -> u16 {
    assert!(rd <= 31, "INC register out of range");
    0x9403 | (u16::from(rd) << 4)
}

/// Encode `DEC rd` (decrement register, 0 ≤ rd ≤ 31).
///
/// # Panics
///
/// Panics if `rd` > 31.
#[must_use]
pub fn encode_dec(rd: u8) -> u16 {
    assert!(rd <= 31, "DEC register out of range");
    0x940A | (u16::from(rd) << 4)
}

/// Encode `NEG rd` (two's complement negation, 0 ≤ rd ≤ 31).
///
/// # Panics
///
/// Panics if `rd` > 31.
#[must_use]
pub fn encode_neg(rd: u8) -> u16 {
    assert!(rd <= 31, "NEG register out of range");
    0x9401 | (u16::from(rd) << 4)
}

/// Encode `COM rd` (bitwise complement, 0 ≤ rd ≤ 31).
///
/// # Panics
///
/// Panics if `rd` > 31.
#[must_use]
pub fn encode_com(rd: u8) -> u16 {
    assert!(rd <= 31, "COM register out of range");
    0x9400 | (u16::from(rd) << 4)
}

/// Encode `LSR rd` (logical shift right, 0 ≤ rd ≤ 31).
///
/// # Panics
///
/// Panics if `rd` > 31.
#[must_use]
pub fn encode_lsr(rd: u8) -> u16 {
    assert!(rd <= 31, "LSR register out of range");
    0x9406 | (u16::from(rd) << 4)
}

/// Encode `ASR rd` (arithmetic shift right, 0 ≤ rd ≤ 31).
///
/// # Panics
///
/// Panics if `rd` > 31.
#[must_use]
pub fn encode_asr(rd: u8) -> u16 {
    assert!(rd <= 31, "ASR register out of range");
    0x9405 | (u16::from(rd) << 4)
}

/// Encode `ROR rd` (rotate right through carry, 0 ≤ rd ≤ 31).
///
/// # Panics
///
/// Panics if `rd` > 31.
#[must_use]
pub fn encode_ror(rd: u8) -> u16 {
    assert!(rd <= 31, "ROR register out of range");
    0x9407 | (u16::from(rd) << 4)
}

/// Encode `SWAP rd` (nibble swap, 0 ≤ rd ≤ 31).
///
/// # Panics
///
/// Panics if `rd` > 31.
#[must_use]
pub fn encode_swap(rd: u8) -> u16 {
    assert!(rd <= 31, "SWAP register out of range");
    0x9402 | (u16::from(rd) << 4)
}

/// Encode `PUSH rr` (push register to stack, 0 ≤ rr ≤ 31).
///
/// # Panics
///
/// Panics if `rr` > 31.
#[must_use]
pub fn encode_push(rr: u8) -> u16 {
    assert!(rr <= 31, "PUSH register out of range");
    0x920F | (u16::from(rr) << 4)
}

/// Encode `POP rd` (pop register from stack, 0 ≤ rd ≤ 31).
///
/// # Panics
///
/// Panics if `rd` > 31.
#[must_use]
pub fn encode_pop(rd: u8) -> u16 {
    assert!(rd <= 31, "POP register out of range");
    0x900F | (u16::from(rd) << 4)
}

/// Encode `RET` (return from subroutine).
#[must_use]
pub const fn encode_ret() -> u16 {
    0x9508
}

/// Encode `RETI` (return from interrupt).
#[must_use]
pub const fn encode_reti() -> u16 {
    0x9518
}

/// Encode `SLEEP` (enter sleep mode).
#[must_use]
pub const fn encode_sleep() -> u16 {
    0x9588
}

/// Encode `WDR` (watchdog reset).
#[must_use]
pub const fn encode_wdr() -> u16 {
    0x95A8
}

/// Encode `CLR rd` (clear register, pseudo for EOR rd,rd).
///
/// # Panics
///
/// Panics if `rd` > 31.
#[must_use]
pub fn encode_clr(rd: u8) -> u16 {
    encode_eor(rd, rd)
}

/// Encode `TST rd` (test register, pseudo for AND rd,rd).
///
/// # Panics
///
/// Panics if `rd` > 31.
#[must_use]
pub fn encode_tst(rd: u8) -> u16 {
    encode_and(rd, rd)
}

// ── AVR Exception / Interrupt Descriptor Table ────────────────────────────────

/// An AVR interrupt vector full descriptor.
#[derive(Debug, Clone)]
pub struct AvrIntVectorFull {
    /// Vector number (0-based, 0 = RESET).
    pub number: u8,
    /// Word address of the vector in flash.
    pub word_addr: u16,
    /// Vector name.
    pub name: &'static str,
    /// Default priority (lower = higher priority on AVR).
    pub priority: u8,
    /// Whether the interrupt is maskable via SREG.I.
    pub maskable: bool,
    /// Description.
    pub description: &'static str,
}

/// `ATmega328P` complete interrupt vector table.
pub static ATMEGA328P_INT_VECTORS: &[AvrIntVectorFull] = &[
    AvrIntVectorFull {
        number: 0,
        word_addr: 0x0000,
        name: "RESET",
        priority: 1,
        maskable: false,
        description: "External pin, power-on reset, brown-out reset, watchdog reset",
    },
    AvrIntVectorFull {
        number: 1,
        word_addr: 0x0002,
        name: "INT0",
        priority: 2,
        maskable: true,
        description: "External interrupt request 0",
    },
    AvrIntVectorFull {
        number: 2,
        word_addr: 0x0004,
        name: "INT1",
        priority: 3,
        maskable: true,
        description: "External interrupt request 1",
    },
    AvrIntVectorFull {
        number: 3,
        word_addr: 0x0006,
        name: "PCINT0",
        priority: 4,
        maskable: true,
        description: "Pin change interrupt request 0",
    },
    AvrIntVectorFull {
        number: 4,
        word_addr: 0x0008,
        name: "PCINT1",
        priority: 5,
        maskable: true,
        description: "Pin change interrupt request 1",
    },
    AvrIntVectorFull {
        number: 5,
        word_addr: 0x000A,
        name: "PCINT2",
        priority: 6,
        maskable: true,
        description: "Pin change interrupt request 2",
    },
    AvrIntVectorFull {
        number: 6,
        word_addr: 0x000C,
        name: "WDT",
        priority: 7,
        maskable: true,
        description: "Watchdog time-out interrupt",
    },
    AvrIntVectorFull {
        number: 7,
        word_addr: 0x000E,
        name: "TIMER2_COMPA",
        priority: 8,
        maskable: true,
        description: "Timer/Counter2 compare match A",
    },
    AvrIntVectorFull {
        number: 8,
        word_addr: 0x0010,
        name: "TIMER2_COMPB",
        priority: 9,
        maskable: true,
        description: "Timer/Counter2 compare match B",
    },
    AvrIntVectorFull {
        number: 9,
        word_addr: 0x0012,
        name: "TIMER2_OVF",
        priority: 10,
        maskable: true,
        description: "Timer/Counter2 overflow",
    },
    AvrIntVectorFull {
        number: 10,
        word_addr: 0x0014,
        name: "TIMER1_CAPT",
        priority: 11,
        maskable: true,
        description: "Timer/Counter1 capture event",
    },
    AvrIntVectorFull {
        number: 11,
        word_addr: 0x0016,
        name: "TIMER1_COMPA",
        priority: 12,
        maskable: true,
        description: "Timer/Counter1 compare match A",
    },
    AvrIntVectorFull {
        number: 12,
        word_addr: 0x0018,
        name: "TIMER1_COMPB",
        priority: 13,
        maskable: true,
        description: "Timer/Counter1 compare match B",
    },
    AvrIntVectorFull {
        number: 13,
        word_addr: 0x001A,
        name: "TIMER1_OVF",
        priority: 14,
        maskable: true,
        description: "Timer/Counter1 overflow",
    },
    AvrIntVectorFull {
        number: 14,
        word_addr: 0x001C,
        name: "TIMER0_COMPA",
        priority: 15,
        maskable: true,
        description: "Timer/Counter0 compare match A",
    },
    AvrIntVectorFull {
        number: 15,
        word_addr: 0x001E,
        name: "TIMER0_COMPB",
        priority: 16,
        maskable: true,
        description: "Timer/Counter0 compare match B",
    },
    AvrIntVectorFull {
        number: 16,
        word_addr: 0x0020,
        name: "TIMER0_OVF",
        priority: 17,
        maskable: true,
        description: "Timer/Counter0 overflow",
    },
    AvrIntVectorFull {
        number: 17,
        word_addr: 0x0022,
        name: "SPI_STC",
        priority: 18,
        maskable: true,
        description: "SPI serial transfer complete",
    },
    AvrIntVectorFull {
        number: 18,
        word_addr: 0x0024,
        name: "USART_RXC",
        priority: 19,
        maskable: true,
        description: "USART Rx complete",
    },
    AvrIntVectorFull {
        number: 19,
        word_addr: 0x0026,
        name: "USART_UDRE",
        priority: 20,
        maskable: true,
        description: "USART data register empty",
    },
    AvrIntVectorFull {
        number: 20,
        word_addr: 0x0028,
        name: "USART_TXC",
        priority: 21,
        maskable: true,
        description: "USART Tx complete",
    },
    AvrIntVectorFull {
        number: 21,
        word_addr: 0x002A,
        name: "ADC",
        priority: 22,
        maskable: true,
        description: "ADC conversion complete",
    },
    AvrIntVectorFull {
        number: 22,
        word_addr: 0x002C,
        name: "EE_READY",
        priority: 23,
        maskable: true,
        description: "EEPROM ready",
    },
    AvrIntVectorFull {
        number: 23,
        word_addr: 0x002E,
        name: "ANALOG_COMP",
        priority: 24,
        maskable: true,
        description: "Analog comparator",
    },
    AvrIntVectorFull {
        number: 24,
        word_addr: 0x0030,
        name: "TWI",
        priority: 25,
        maskable: true,
        description: "2-wire serial interface (I2C)",
    },
    AvrIntVectorFull {
        number: 25,
        word_addr: 0x0032,
        name: "SPM_READY",
        priority: 26,
        maskable: true,
        description: "Store program memory ready",
    },
];

/// Look up an interrupt vector by name.
#[must_use]
pub fn lookup_int_vector_by_name(name: &str) -> Option<&'static AvrIntVectorFull> {
    ATMEGA328P_INT_VECTORS.iter().find(|v| v.name == name)
}

/// Look up an interrupt vector by number.
#[must_use]
pub fn lookup_int_vector_by_number(n: u8) -> Option<&'static AvrIntVectorFull> {
    ATMEGA328P_INT_VECTORS.iter().find(|v| v.number == n)
}

// ── AVR Calling Convention ────────────────────────────────────────────────────

/// Describes how a parameter is passed in the AVR GCC ABI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvrParamLocation {
    /// Passed in a register pair (rd:rd+1, rd ∈ {8,10,12,14,16,18,20,22,24}).
    RegPair(u8),
    /// Passed on the stack.
    Stack(u8),
}

/// Compute AVR GCC ABI parameter locations.
///
/// In the AVR GCC ABI, integer/pointer parameters are passed in pairs
/// r25:r24, r23:r22, r21:r20, r19:r18 (up to 4 pairs = 8 regs).
/// Return values go in r25:r24 (8-bit: r24 only).
///
/// Each entry is the low register of the pair.
#[must_use]
pub fn avr_param_locations(count: usize) -> Vec<AvrParamLocation> {
    let reg_pairs = [24u8, 22, 20, 18, 16, 14, 12, 10];
    // Cap the pre-allocation to a sane maximum (256) so an attacker-controlled
    // `count` value cannot exhaust memory via Vec::with_capacity.
    let mut result = Vec::with_capacity(count.min(256));
    for i in 0..count {
        if i < reg_pairs.len() {
            result.push(AvrParamLocation::RegPair(reg_pairs[i]));
        } else {
            result.push(AvrParamLocation::Stack(u8::try_from(i - reg_pairs.len()).unwrap_or(u8::MAX) * 2));
        }
    }
    result
}

// ── AVR Stack Frame Analysis ──────────────────────────────────────────────────

/// An AVR function stack frame description.
#[derive(Debug, Clone)]
pub struct AvrStackFrame {
    /// Total frame size in bytes (from SBIW/RCALL overhead).
    pub frame_size: u16,
    /// Number of saved registers (PUSH instructions in prologue).
    pub saved_regs: u8,
    /// Whether SREG is saved.
    pub sreg_saved: bool,
}

impl AvrStackFrame {
    /// Compute a typical frame size.
    ///
    /// Saved regs on stack + 2 bytes for return address.
    #[must_use]
    pub fn compute(saved_regs: u8, local_bytes: u16, sreg: bool) -> Self {
        let sreg_bytes = u16::from(sreg);
        Self {
            frame_size: u16::from(saved_regs) + sreg_bytes + local_bytes + 2,
            saved_regs,
            sreg_saved: sreg,
        }
    }
}

// ── AVR Idiom Identification ──────────────────────────────────────────────────

/// Recognized AVR instruction idioms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvrIdiom {
    /// `NOP` — no operation.
    Nop,
    /// `CLR rd` — clear register (EOR rd,rd).
    ClearReg(u8),
    /// `TST rd` — test register (AND rd,rd).
    TestReg(u8),
    /// `LSL rd` — logical shift left (ADD rd,rd).
    LogicalShiftLeft(u8),
    /// `ROL rd` — rotate left through carry (ADC rd,rd).
    RotateLeft(u8),
    /// General — no recognized idiom.
    General,
}

/// Identify whether a single decoded instruction is a common AVR idiom.
#[must_use]
pub fn identify_avr_idiom(instr: &Instruction) -> AvrIdiom {
    let m = instr.mnemonic.as_str();
    let ops = instr.operands.as_str();
    match m {
        "NOP" => AvrIdiom::Nop,
        "EOR" => {
            // CLR rd: EOR rd,rd
            if let Some((a, b)) = ops.split_once(',') && a.trim() == b.trim() && let Some(n) = parse_reg_num(a.trim()) {
                return AvrIdiom::ClearReg(n);
            }
            AvrIdiom::General
        }
        "AND" => {
            // TST rd: AND rd,rd
            if let Some((a, b)) = ops.split_once(',') && a.trim() == b.trim() && let Some(n) = parse_reg_num(a.trim()) {
                return AvrIdiom::TestReg(n);
            }
            AvrIdiom::General
        }
        "ADD" => {
            // LSL rd: ADD rd,rd
            if let Some((a, b)) = ops.split_once(',') && a.trim() == b.trim() && let Some(n) = parse_reg_num(a.trim()) {
                return AvrIdiom::LogicalShiftLeft(n);
            }
            AvrIdiom::General
        }
        "ADC" => {
            // ROL rd: ADC rd,rd
            if let Some((a, b)) = ops.split_once(',') && a.trim() == b.trim() && let Some(n) = parse_reg_num(a.trim()) {
                return AvrIdiom::RotateLeft(n);
            }
            AvrIdiom::General
        }
        _ => AvrIdiom::General,
    }
}

/// Parse "rN" register notation, returning the register number.
fn parse_reg_num(s: &str) -> Option<u8> {
    s.strip_prefix('r')
        .or_else(|| s.strip_prefix('R'))
        .and_then(|n| n.parse().ok())
}

// ── AVR Extended I/O Register Map ─────────────────────────────────────────────

/// An extended (memory-mapped) I/O register descriptor for `ATmega2560`.
#[derive(Debug, Clone, Copy)]
pub struct AvrExtIoReg {
    /// Memory address (0x0020–0x01FF for standard mapping).
    pub mem_addr: u16,
    /// I/O address offset (0x00–0x1F for `IN`/`OUT`, others use `LDS`/`STS`).
    pub io_addr: Option<u8>,
    /// Register name.
    pub name: &'static str,
    /// Description.
    pub description: &'static str,
}

/// `ATmega328P` extended I/O register map (selected registers).
pub static ATMEGA328P_EXT_IO: &[AvrExtIoReg] = &[
    AvrExtIoReg {
        mem_addr: 0x0023,
        io_addr: Some(0x03),
        name: "PINB",
        description: "Port B input pins",
    },
    AvrExtIoReg {
        mem_addr: 0x0024,
        io_addr: Some(0x04),
        name: "DDRB",
        description: "Port B data direction register",
    },
    AvrExtIoReg {
        mem_addr: 0x0025,
        io_addr: Some(0x05),
        name: "PORTB",
        description: "Port B data register",
    },
    AvrExtIoReg {
        mem_addr: 0x0026,
        io_addr: Some(0x06),
        name: "PINC",
        description: "Port C input pins",
    },
    AvrExtIoReg {
        mem_addr: 0x0027,
        io_addr: Some(0x07),
        name: "DDRC",
        description: "Port C data direction register",
    },
    AvrExtIoReg {
        mem_addr: 0x0028,
        io_addr: Some(0x08),
        name: "PORTC",
        description: "Port C data register",
    },
    AvrExtIoReg {
        mem_addr: 0x0029,
        io_addr: Some(0x09),
        name: "PIND",
        description: "Port D input pins",
    },
    AvrExtIoReg {
        mem_addr: 0x002A,
        io_addr: Some(0x0A),
        name: "DDRD",
        description: "Port D data direction register",
    },
    AvrExtIoReg {
        mem_addr: 0x002B,
        io_addr: Some(0x0B),
        name: "PORTD",
        description: "Port D data register",
    },
    AvrExtIoReg {
        mem_addr: 0x0035,
        io_addr: Some(0x15),
        name: "TIFR0",
        description: "Timer/Counter0 interrupt flag register",
    },
    AvrExtIoReg {
        mem_addr: 0x0036,
        io_addr: Some(0x16),
        name: "TIFR1",
        description: "Timer/Counter1 interrupt flag register",
    },
    AvrExtIoReg {
        mem_addr: 0x0037,
        io_addr: Some(0x17),
        name: "TIFR2",
        description: "Timer/Counter2 interrupt flag register",
    },
    AvrExtIoReg {
        mem_addr: 0x003B,
        io_addr: Some(0x1B),
        name: "PCIFR",
        description: "Pin change interrupt flag register",
    },
    AvrExtIoReg {
        mem_addr: 0x003C,
        io_addr: Some(0x1C),
        name: "EIFR",
        description: "External interrupt flag register",
    },
    AvrExtIoReg {
        mem_addr: 0x003D,
        io_addr: Some(0x1D),
        name: "EIMSK",
        description: "External interrupt mask register",
    },
    AvrExtIoReg {
        mem_addr: 0x003E,
        io_addr: Some(0x1E),
        name: "GPIOR0",
        description: "General purpose I/O register 0",
    },
    AvrExtIoReg {
        mem_addr: 0x003F,
        io_addr: Some(0x1F),
        name: "EECR",
        description: "EEPROM control register",
    },
    AvrExtIoReg {
        mem_addr: 0x0040,
        io_addr: None,
        name: "EEDR",
        description: "EEPROM data register",
    },
    AvrExtIoReg {
        mem_addr: 0x0041,
        io_addr: None,
        name: "EEARL",
        description: "EEPROM address register low",
    },
    AvrExtIoReg {
        mem_addr: 0x0042,
        io_addr: None,
        name: "EEARH",
        description: "EEPROM address register high",
    },
    AvrExtIoReg {
        mem_addr: 0x0043,
        io_addr: None,
        name: "GTCCR",
        description: "General timer/counter control register",
    },
    AvrExtIoReg {
        mem_addr: 0x0044,
        io_addr: None,
        name: "TCCR0A",
        description: "Timer/Counter0 control register A",
    },
    AvrExtIoReg {
        mem_addr: 0x0045,
        io_addr: None,
        name: "TCCR0B",
        description: "Timer/Counter0 control register B",
    },
    AvrExtIoReg {
        mem_addr: 0x0046,
        io_addr: None,
        name: "TCNT0",
        description: "Timer/Counter0 register",
    },
    AvrExtIoReg {
        mem_addr: 0x0047,
        io_addr: None,
        name: "OCR0A",
        description: "Timer/Counter0 output compare register A",
    },
    AvrExtIoReg {
        mem_addr: 0x0048,
        io_addr: None,
        name: "OCR0B",
        description: "Timer/Counter0 output compare register B",
    },
    AvrExtIoReg {
        mem_addr: 0x004A,
        io_addr: None,
        name: "GPIOR1",
        description: "General purpose I/O register 1",
    },
    AvrExtIoReg {
        mem_addr: 0x004B,
        io_addr: None,
        name: "GPIOR2",
        description: "General purpose I/O register 2",
    },
    AvrExtIoReg {
        mem_addr: 0x004C,
        io_addr: None,
        name: "SPCR",
        description: "SPI control register",
    },
    AvrExtIoReg {
        mem_addr: 0x004D,
        io_addr: None,
        name: "SPSR",
        description: "SPI status register",
    },
    AvrExtIoReg {
        mem_addr: 0x004E,
        io_addr: None,
        name: "SPDR",
        description: "SPI data register",
    },
    AvrExtIoReg {
        mem_addr: 0x0050,
        io_addr: None,
        name: "ACSR",
        description: "Analog comparator control and status register",
    },
    AvrExtIoReg {
        mem_addr: 0x0053,
        io_addr: None,
        name: "SMCR",
        description: "Sleep mode control register",
    },
    AvrExtIoReg {
        mem_addr: 0x0054,
        io_addr: None,
        name: "MCUSR",
        description: "MCU status register",
    },
    AvrExtIoReg {
        mem_addr: 0x0055,
        io_addr: None,
        name: "MCUCR",
        description: "MCU control register",
    },
    AvrExtIoReg {
        mem_addr: 0x0057,
        io_addr: None,
        name: "SPMCSR",
        description: "Store program memory control and status register",
    },
    AvrExtIoReg {
        mem_addr: 0x005D,
        io_addr: None,
        name: "SPL",
        description: "Stack pointer low",
    },
    AvrExtIoReg {
        mem_addr: 0x005E,
        io_addr: None,
        name: "SPH",
        description: "Stack pointer high",
    },
    AvrExtIoReg {
        mem_addr: 0x005F,
        io_addr: None,
        name: "SREG",
        description: "Status register",
    },
    AvrExtIoReg {
        mem_addr: 0x0060,
        io_addr: None,
        name: "WDTCSR",
        description: "Watchdog timer control register",
    },
    AvrExtIoReg {
        mem_addr: 0x0061,
        io_addr: None,
        name: "CLKPR",
        description: "Clock prescale register",
    },
    AvrExtIoReg {
        mem_addr: 0x0064,
        io_addr: None,
        name: "PRR",
        description: "Power reduction register",
    },
    AvrExtIoReg {
        mem_addr: 0x0066,
        io_addr: None,
        name: "OSCCAL",
        description: "Oscillator calibration register",
    },
    AvrExtIoReg {
        mem_addr: 0x0068,
        io_addr: None,
        name: "PCICR",
        description: "Pin change interrupt control register",
    },
    AvrExtIoReg {
        mem_addr: 0x0069,
        io_addr: None,
        name: "EICRA",
        description: "External interrupt control register A",
    },
    AvrExtIoReg {
        mem_addr: 0x006B,
        io_addr: None,
        name: "PCMSK0",
        description: "Pin change mask register 0",
    },
    AvrExtIoReg {
        mem_addr: 0x006C,
        io_addr: None,
        name: "PCMSK1",
        description: "Pin change mask register 1",
    },
    AvrExtIoReg {
        mem_addr: 0x006D,
        io_addr: None,
        name: "PCMSK2",
        description: "Pin change mask register 2",
    },
    AvrExtIoReg {
        mem_addr: 0x006E,
        io_addr: None,
        name: "TIMSK0",
        description: "Timer/Counter0 interrupt mask register",
    },
    AvrExtIoReg {
        mem_addr: 0x006F,
        io_addr: None,
        name: "TIMSK1",
        description: "Timer/Counter1 interrupt mask register",
    },
    AvrExtIoReg {
        mem_addr: 0x0070,
        io_addr: None,
        name: "TIMSK2",
        description: "Timer/Counter2 interrupt mask register",
    },
    AvrExtIoReg {
        mem_addr: 0x0078,
        io_addr: None,
        name: "ADCL",
        description: "ADC data register low",
    },
    AvrExtIoReg {
        mem_addr: 0x0079,
        io_addr: None,
        name: "ADCH",
        description: "ADC data register high",
    },
    AvrExtIoReg {
        mem_addr: 0x007A,
        io_addr: None,
        name: "ADCSRA",
        description: "ADC control and status register A",
    },
    AvrExtIoReg {
        mem_addr: 0x007B,
        io_addr: None,
        name: "ADCSRB",
        description: "ADC control and status register B",
    },
    AvrExtIoReg {
        mem_addr: 0x007C,
        io_addr: None,
        name: "ADMUX",
        description: "ADC multiplexer selection register",
    },
    AvrExtIoReg {
        mem_addr: 0x007E,
        io_addr: None,
        name: "DIDR0",
        description: "Digital input disable register 0",
    },
    AvrExtIoReg {
        mem_addr: 0x007F,
        io_addr: None,
        name: "DIDR1",
        description: "Digital input disable register 1",
    },
    AvrExtIoReg {
        mem_addr: 0x0080,
        io_addr: None,
        name: "TCCR1A",
        description: "Timer/Counter1 control register A",
    },
    AvrExtIoReg {
        mem_addr: 0x0081,
        io_addr: None,
        name: "TCCR1B",
        description: "Timer/Counter1 control register B",
    },
    AvrExtIoReg {
        mem_addr: 0x0082,
        io_addr: None,
        name: "TCCR1C",
        description: "Timer/Counter1 control register C",
    },
    AvrExtIoReg {
        mem_addr: 0x0084,
        io_addr: None,
        name: "TCNT1L",
        description: "Timer/Counter1 low byte",
    },
    AvrExtIoReg {
        mem_addr: 0x0085,
        io_addr: None,
        name: "TCNT1H",
        description: "Timer/Counter1 high byte",
    },
    AvrExtIoReg {
        mem_addr: 0x0086,
        io_addr: None,
        name: "ICR1L",
        description: "Timer/Counter1 input capture register low",
    },
    AvrExtIoReg {
        mem_addr: 0x0087,
        io_addr: None,
        name: "ICR1H",
        description: "Timer/Counter1 input capture register high",
    },
    AvrExtIoReg {
        mem_addr: 0x0088,
        io_addr: None,
        name: "OCR1AL",
        description: "Timer/Counter1 output compare register A low",
    },
    AvrExtIoReg {
        mem_addr: 0x0089,
        io_addr: None,
        name: "OCR1AH",
        description: "Timer/Counter1 output compare register A high",
    },
    AvrExtIoReg {
        mem_addr: 0x008A,
        io_addr: None,
        name: "OCR1BL",
        description: "Timer/Counter1 output compare register B low",
    },
    AvrExtIoReg {
        mem_addr: 0x008B,
        io_addr: None,
        name: "OCR1BH",
        description: "Timer/Counter1 output compare register B high",
    },
    AvrExtIoReg {
        mem_addr: 0x00B0,
        io_addr: None,
        name: "TCCR2A",
        description: "Timer/Counter2 control register A",
    },
    AvrExtIoReg {
        mem_addr: 0x00B1,
        io_addr: None,
        name: "TCCR2B",
        description: "Timer/Counter2 control register B",
    },
    AvrExtIoReg {
        mem_addr: 0x00B2,
        io_addr: None,
        name: "TCNT2",
        description: "Timer/Counter2 register",
    },
    AvrExtIoReg {
        mem_addr: 0x00B3,
        io_addr: None,
        name: "OCR2A",
        description: "Timer/Counter2 output compare register A",
    },
    AvrExtIoReg {
        mem_addr: 0x00B4,
        io_addr: None,
        name: "OCR2B",
        description: "Timer/Counter2 output compare register B",
    },
    AvrExtIoReg {
        mem_addr: 0x00B8,
        io_addr: None,
        name: "ASSR",
        description: "Asynchronous status register",
    },
    AvrExtIoReg {
        mem_addr: 0x00BA,
        io_addr: None,
        name: "TWBR",
        description: "TWI bit rate register",
    },
    AvrExtIoReg {
        mem_addr: 0x00BB,
        io_addr: None,
        name: "TWSR",
        description: "TWI status register",
    },
    AvrExtIoReg {
        mem_addr: 0x00BC,
        io_addr: None,
        name: "TWAR",
        description: "TWI (slave) address register",
    },
    AvrExtIoReg {
        mem_addr: 0x00BD,
        io_addr: None,
        name: "TWDR",
        description: "TWI data register",
    },
    AvrExtIoReg {
        mem_addr: 0x00BE,
        io_addr: None,
        name: "TWCR",
        description: "TWI control register",
    },
    AvrExtIoReg {
        mem_addr: 0x00BF,
        io_addr: None,
        name: "TWAMR",
        description: "TWI (slave) address mask register",
    },
    AvrExtIoReg {
        mem_addr: 0x00C0,
        io_addr: None,
        name: "UCSR0A",
        description: "USART0 control and status register A",
    },
    AvrExtIoReg {
        mem_addr: 0x00C1,
        io_addr: None,
        name: "UCSR0B",
        description: "USART0 control and status register B",
    },
    AvrExtIoReg {
        mem_addr: 0x00C2,
        io_addr: None,
        name: "UCSR0C",
        description: "USART0 control and status register C",
    },
    AvrExtIoReg {
        mem_addr: 0x00C4,
        io_addr: None,
        name: "UBRR0L",
        description: "USART0 baud rate register low",
    },
    AvrExtIoReg {
        mem_addr: 0x00C5,
        io_addr: None,
        name: "UBRR0H",
        description: "USART0 baud rate register high",
    },
    AvrExtIoReg {
        mem_addr: 0x00C6,
        io_addr: None,
        name: "UDR0",
        description: "USART0 I/O data register",
    },
];

/// Look up an extended I/O register by memory address.
#[must_use]
pub fn lookup_ext_io_by_mem(addr: u16) -> Option<&'static AvrExtIoReg> {
    ATMEGA328P_EXT_IO.iter().find(|r| r.mem_addr == addr)
}

/// Look up an extended I/O register by name.
#[must_use]
pub fn lookup_ext_io_by_name(name: &str) -> Option<&'static AvrExtIoReg> {
    ATMEGA328P_EXT_IO.iter().find(|r| r.name == name)
}

// ── AVR Code Analysis ─────────────────────────────────────────────────────────

/// Branch target extraction from a decoded AVR sequence.
///
/// Returns `(from_byte_addr, to_byte_addr)` for every taken branch or call.
#[must_use]
pub fn extract_avr_branch_targets(instrs: &[Instruction]) -> Vec<(Address, Address)> {
    let mut targets = Vec::new();
    for instr in instrs {
        if instr
            .flags
            .intersects(InstrFlags::BRANCH | InstrFlags::CALL)
        {
            let ops = instr.operands.trim();
            let last = ops.rsplit(',').next().unwrap_or(ops).trim();
            if let Some(hex) = last.strip_prefix("0x").or_else(|| last.strip_prefix("0X")) && let Ok(target) = u64::from_str_radix(hex, 16) {
                targets.push((instr.address, Address::new(target)));
            }
        }
    }
    targets
}

/// Detect if the first instructions of a function form a standard AVR
/// GCC prologue: PUSH of callee-saved registers followed by optional RCALL.
///
/// Returns the number of saved registers detected.
#[must_use]
pub fn detect_avr_prologue_regs(instrs: &[Instruction]) -> u8 {
    u8::try_from(instrs.iter().take_while(|i| i.mnemonic == "PUSH").count()).unwrap_or(u8::MAX)
}

/// Detect if the last instructions of a window form a standard AVR epilogue.
///
/// Looks for POP + RET pattern.
#[must_use]
pub fn detect_avr_epilogue(instrs: &[Instruction]) -> bool {
    let has_pop = instrs.iter().any(|i| i.mnemonic == "POP");
    let has_ret = instrs
        .iter()
        .any(|i| i.mnemonic == "RET" || i.mnemonic == "RETI");
    has_pop && has_ret
}

// ── Additional Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod avr_enc_tests {
    use super::*;

    fn arch() -> AvrArch {
        AvrArch::default()
    }
    fn addr(a: u64) -> Address {
        Address::new(a)
    }

    // ── Basic encoding roundtrips ────────────────────────────────────────────

    #[test]
    fn test_encode_nop() {
        let enc = encode_nop().to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "NOP");
    }

    #[test]
    fn test_encode_rjmp() {
        // RJMP 0 = branch to self
        let enc = encode_rjmp(0).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "RJMP");
    }

    #[test]
    fn test_encode_rcall() {
        let enc = encode_rcall(0).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "RCALL");
    }

    #[test]
    fn test_encode_mov() {
        let enc = encode_mov(5, 10).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "MOV");
    }

    #[test]
    fn test_encode_add() {
        let enc = encode_add(3, 4).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "ADD");
    }

    #[test]
    fn test_encode_adc() {
        let enc = encode_adc(3, 4).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "ADC");
    }

    #[test]
    fn test_encode_sub() {
        let enc = encode_sub(3, 4).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "SUB");
    }

    #[test]
    fn test_encode_and() {
        let enc = encode_and(3, 4).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "AND");
    }

    #[test]
    fn test_encode_or() {
        let enc = encode_or(3, 4).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "OR");
    }

    #[test]
    fn test_encode_eor() {
        let enc = encode_eor(3, 4).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "EOR");
    }

    #[test]
    fn test_encode_cp() {
        let enc = encode_cp(3, 4).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "CP");
    }

    #[test]
    fn test_encode_cpc() {
        let enc = encode_cpc(3, 4).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "CPC");
    }

    #[test]
    fn test_encode_cpse() {
        let enc = encode_cpse(3, 4).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "CPSE");
    }

    #[test]
    fn test_encode_ldi() {
        // LDI R24, 42 — 42 decimal = 0x2A, decoder uses $XX hex format
        let enc = encode_ldi(24, 42).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "LDI");
        assert!(
            instr.operands.contains("$2A")
                || instr.operands.contains("$2a")
                || instr.operands.contains("42")
                || instr.operands.contains("2A")
        );
    }

    #[test]
    fn test_encode_subi() {
        let enc = encode_subi(24, 1).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "SUBI");
    }

    #[test]
    fn test_encode_sbci() {
        let enc = encode_sbci(24, 0).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "SBCI");
    }

    #[test]
    fn test_encode_andi() {
        let enc = encode_andi(24, 0xFF).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "ANDI");
    }

    #[test]
    fn test_encode_ori() {
        let enc = encode_ori(24, 0x01).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "ORI");
    }

    #[test]
    fn test_encode_cpi() {
        let enc = encode_cpi(24, 10).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "CPI");
    }

    #[test]
    fn test_encode_inc() {
        let enc = encode_inc(3).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "INC");
    }

    #[test]
    fn test_encode_dec() {
        let enc = encode_dec(3).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "DEC");
    }

    #[test]
    fn test_encode_neg() {
        let enc = encode_neg(3).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "NEG");
    }

    #[test]
    fn test_encode_com() {
        let enc = encode_com(3).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "COM");
    }

    #[test]
    fn test_encode_lsr() {
        let enc = encode_lsr(3).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "LSR");
    }

    #[test]
    fn test_encode_asr() {
        let enc = encode_asr(3).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "ASR");
    }

    #[test]
    fn test_encode_ror() {
        let enc = encode_ror(3).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "ROR");
    }

    #[test]
    fn test_encode_swap() {
        let enc = encode_swap(3).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "SWAP");
    }

    #[test]
    fn test_encode_push_pop() {
        let push = encode_push(24).to_le_bytes();
        let pop = encode_pop(24).to_le_bytes();
        let p_instr = arch().disassemble(addr(0), &push).unwrap();
        let o_instr = arch().disassemble(addr(0), &pop).unwrap();
        assert_eq!(p_instr.mnemonic, "PUSH");
        assert_eq!(o_instr.mnemonic, "POP");
    }

    #[test]
    fn test_encode_ret() {
        let enc = encode_ret().to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "RET");
    }

    #[test]
    fn test_encode_reti() {
        let enc = encode_reti().to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "RETI");
    }

    #[test]
    fn test_encode_sleep() {
        let enc = encode_sleep().to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "SLEEP");
    }

    #[test]
    fn test_encode_wdr() {
        let enc = encode_wdr().to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "WDR");
    }

    #[test]
    fn test_encode_clr_pseudo() {
        // CLR = EOR rd,rd
        let enc = encode_clr(5).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "EOR");
    }

    #[test]
    fn test_encode_tst_pseudo() {
        // TST = AND rd,rd
        let enc = encode_tst(7).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "AND");
    }

    // ── Interrupt vectors ────────────────────────────────────────────────────

    #[test]
    fn test_int_vector_reset() {
        let v = lookup_int_vector_by_name("RESET").unwrap();
        assert_eq!(v.word_addr, 0x0000);
        assert!(!v.maskable);
    }

    #[test]
    fn test_int_vector_timer0_ovf() {
        let v = lookup_int_vector_by_name("TIMER0_OVF").unwrap();
        assert!(v.maskable);
    }

    #[test]
    fn test_int_vector_by_number() {
        let v = lookup_int_vector_by_number(0).unwrap();
        assert_eq!(v.name, "RESET");
    }

    #[test]
    fn test_int_vector_missing() {
        assert!(lookup_int_vector_by_name("NONEXISTENT").is_none());
    }

    #[test]
    fn test_int_vector_count() {
        assert_eq!(ATMEGA328P_INT_VECTORS.len(), 26);
    }

    // ── Extended I/O ─────────────────────────────────────────────────────────

    #[test]
    fn test_ext_io_portb_by_mem() {
        let r = lookup_ext_io_by_mem(0x0025).unwrap();
        assert_eq!(r.name, "PORTB");
    }

    #[test]
    fn test_ext_io_sreg_by_name() {
        let r = lookup_ext_io_by_name("SREG").unwrap();
        assert_eq!(r.mem_addr, 0x005F);
    }

    #[test]
    fn test_ext_io_missing() {
        assert!(lookup_ext_io_by_mem(0x9999).is_none());
    }

    #[test]
    fn test_ext_io_count() {
        assert!(ATMEGA328P_EXT_IO.len() >= 50);
    }

    // ── Calling convention ───────────────────────────────────────────────────

    #[test]
    fn test_avr_param_locations_first() {
        let locs = avr_param_locations(2);
        assert_eq!(locs[0], AvrParamLocation::RegPair(24));
        assert_eq!(locs[1], AvrParamLocation::RegPair(22));
    }

    #[test]
    fn test_avr_param_locations_spill() {
        let locs = avr_param_locations(10);
        assert!(matches!(locs[8], AvrParamLocation::Stack(_)));
    }

    // ── Stack frame ──────────────────────────────────────────────────────────

    #[test]
    fn test_stack_frame_compute() {
        let frame = AvrStackFrame::compute(3, 4, false);
        // 3 saved + 4 local + 2 return addr = 9
        assert_eq!(frame.frame_size, 9);
    }

    #[test]
    fn test_stack_frame_with_sreg() {
        let frame = AvrStackFrame::compute(0, 0, true);
        // 0 saved + 1 sreg + 0 local + 2 ret = 3
        assert_eq!(frame.frame_size, 3);
    }

    // ── Idiom detection ──────────────────────────────────────────────────────

    #[test]
    fn test_idiom_nop() {
        let enc = encode_nop().to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(identify_avr_idiom(&instr), AvrIdiom::Nop);
    }

    #[test]
    fn test_idiom_clr() {
        // EOR r5,r5 → CLR r5
        let enc = encode_eor(5, 5).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(identify_avr_idiom(&instr), AvrIdiom::ClearReg(5));
    }

    #[test]
    fn test_idiom_tst() {
        // AND r7,r7 → TST r7
        let enc = encode_and(7, 7).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(identify_avr_idiom(&instr), AvrIdiom::TestReg(7));
    }

    #[test]
    fn test_idiom_lsl() {
        // ADD r3,r3 → LSL r3
        let enc = encode_add(3, 3).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(identify_avr_idiom(&instr), AvrIdiom::LogicalShiftLeft(3));
    }

    #[test]
    fn test_idiom_rol() {
        // ADC r3,r3 → ROL r3
        let enc = encode_adc(3, 3).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(identify_avr_idiom(&instr), AvrIdiom::RotateLeft(3));
    }

    #[test]
    fn test_idiom_general() {
        let enc = encode_mov(3, 4).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(identify_avr_idiom(&instr), AvrIdiom::General);
    }

    // ── Branch targets ───────────────────────────────────────────────────────

    #[test]
    fn test_branch_targets_empty() {
        assert!(extract_avr_branch_targets(&[]).is_empty());
    }

    // ── Prologue / epilogue detection ────────────────────────────────────────

    #[test]
    fn test_prologue_detect_pushes() {
        let p1 = encode_push(24).to_le_bytes();
        let p2 = encode_push(25).to_le_bytes();
        let bytes: Vec<u8> = [p1, p2].iter().flat_map(|b| b.iter().copied()).collect();
        let a = arch();
        let mut instrs = Vec::new();
        for i in 0..2 {
            instrs.push(
                a.disassemble(addr((i * 2) as u64), &bytes[i * 2..])
                    .unwrap(),
            );
        }
        assert_eq!(detect_avr_prologue_regs(&instrs), 2);
    }

    #[test]
    fn test_epilogue_detect() {
        let pop = encode_pop(24).to_le_bytes();
        let ret = encode_ret().to_le_bytes();
        let a = arch();
        let pop_i = a.disassemble(addr(0), &pop).unwrap();
        let ret_i = a.disassemble(addr(2), &ret).unwrap();
        assert!(detect_avr_epilogue(&[pop_i, ret_i]));
    }

    #[test]
    fn test_epilogue_no_pop() {
        let ret = encode_ret().to_le_bytes();
        let ret_i = arch().disassemble(addr(0), &ret).unwrap();
        assert!(!detect_avr_epilogue(&[ret_i]));
    }
}

// ── AVR Instruction Reference Table ──────────────────────────────────────────

/// An entry in the AVR instruction set reference.
#[derive(Debug, Clone, Copy)]
pub struct AvrInstrRef {
    /// Mnemonic.
    pub mnemonic: &'static str,
    /// Operation category.
    pub category: AvrInstrCategory,
    /// Instruction word size in bytes (2 or 4).
    pub size: u8,
    /// Number of CPU cycles (minimum).
    pub cycles_min: u8,
    /// Number of CPU cycles (maximum — may differ for branches).
    pub cycles_max: u8,
    /// Whether the instruction modifies the status register (SREG).
    pub affects_sreg: bool,
    /// Brief description.
    pub description: &'static str,
}

/// AVR instruction category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvrInstrCategory {
    /// Arithmetic.
    Arithmetic,
    /// Logic.
    Logic,
    /// Bit operations.
    BitOp,
    /// Compare.
    Compare,
    /// Data transfer.
    Transfer,
    /// Branch.
    Branch,
    /// Call/Return.
    CallReturn,
    /// Skip.
    Skip,
    /// Load/Store.
    LoadStore,
    /// I/O.
    Io,
    /// System/Control.
    System,
}

/// Comprehensive AVR instruction reference table.
pub static AVR_INSTR_REF: &[AvrInstrRef] = &[
    AvrInstrRef {
        mnemonic: "NOP",
        category: AvrInstrCategory::System,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: false,
        description: "No operation",
    },
    AvrInstrRef {
        mnemonic: "ADD",
        category: AvrInstrCategory::Arithmetic,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Add without carry",
    },
    AvrInstrRef {
        mnemonic: "ADC",
        category: AvrInstrCategory::Arithmetic,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Add with carry",
    },
    AvrInstrRef {
        mnemonic: "ADIW",
        category: AvrInstrCategory::Arithmetic,
        size: 2,
        cycles_min: 2,
        cycles_max: 2,
        affects_sreg: true,
        description: "Add immediate to word",
    },
    AvrInstrRef {
        mnemonic: "SUB",
        category: AvrInstrCategory::Arithmetic,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Subtract without carry",
    },
    AvrInstrRef {
        mnemonic: "SUBI",
        category: AvrInstrCategory::Arithmetic,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Subtract immediate",
    },
    AvrInstrRef {
        mnemonic: "SBC",
        category: AvrInstrCategory::Arithmetic,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Subtract with carry",
    },
    AvrInstrRef {
        mnemonic: "SBCI",
        category: AvrInstrCategory::Arithmetic,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Subtract immediate with carry",
    },
    AvrInstrRef {
        mnemonic: "SBIW",
        category: AvrInstrCategory::Arithmetic,
        size: 2,
        cycles_min: 2,
        cycles_max: 2,
        affects_sreg: true,
        description: "Subtract immediate from word",
    },
    AvrInstrRef {
        mnemonic: "AND",
        category: AvrInstrCategory::Logic,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Logical AND",
    },
    AvrInstrRef {
        mnemonic: "ANDI",
        category: AvrInstrCategory::Logic,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Logical AND with immediate",
    },
    AvrInstrRef {
        mnemonic: "OR",
        category: AvrInstrCategory::Logic,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Logical OR",
    },
    AvrInstrRef {
        mnemonic: "ORI",
        category: AvrInstrCategory::Logic,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Logical OR with immediate",
    },
    AvrInstrRef {
        mnemonic: "EOR",
        category: AvrInstrCategory::Logic,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Exclusive OR",
    },
    AvrInstrRef {
        mnemonic: "COM",
        category: AvrInstrCategory::Logic,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "One's complement",
    },
    AvrInstrRef {
        mnemonic: "NEG",
        category: AvrInstrCategory::Arithmetic,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Two's complement",
    },
    AvrInstrRef {
        mnemonic: "INC",
        category: AvrInstrCategory::Arithmetic,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Increment",
    },
    AvrInstrRef {
        mnemonic: "DEC",
        category: AvrInstrCategory::Arithmetic,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Decrement",
    },
    AvrInstrRef {
        mnemonic: "MUL",
        category: AvrInstrCategory::Arithmetic,
        size: 2,
        cycles_min: 2,
        cycles_max: 2,
        affects_sreg: true,
        description: "Multiply unsigned",
    },
    AvrInstrRef {
        mnemonic: "MULS",
        category: AvrInstrCategory::Arithmetic,
        size: 2,
        cycles_min: 2,
        cycles_max: 2,
        affects_sreg: true,
        description: "Multiply signed",
    },
    AvrInstrRef {
        mnemonic: "MULSU",
        category: AvrInstrCategory::Arithmetic,
        size: 2,
        cycles_min: 2,
        cycles_max: 2,
        affects_sreg: true,
        description: "Multiply signed with unsigned",
    },
    AvrInstrRef {
        mnemonic: "LSR",
        category: AvrInstrCategory::BitOp,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Logical shift right",
    },
    AvrInstrRef {
        mnemonic: "ASR",
        category: AvrInstrCategory::BitOp,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Arithmetic shift right",
    },
    AvrInstrRef {
        mnemonic: "ROR",
        category: AvrInstrCategory::BitOp,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Rotate right through carry",
    },
    AvrInstrRef {
        mnemonic: "SWAP",
        category: AvrInstrCategory::BitOp,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: false,
        description: "Swap nibbles",
    },
    AvrInstrRef {
        mnemonic: "SBI",
        category: AvrInstrCategory::BitOp,
        size: 2,
        cycles_min: 2,
        cycles_max: 2,
        affects_sreg: false,
        description: "Set bit in I/O register",
    },
    AvrInstrRef {
        mnemonic: "CBI",
        category: AvrInstrCategory::BitOp,
        size: 2,
        cycles_min: 2,
        cycles_max: 2,
        affects_sreg: false,
        description: "Clear bit in I/O register",
    },
    AvrInstrRef {
        mnemonic: "BST",
        category: AvrInstrCategory::BitOp,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Bit store from register to T-flag",
    },
    AvrInstrRef {
        mnemonic: "BLD",
        category: AvrInstrCategory::BitOp,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: false,
        description: "Bit load from T-flag to register",
    },
    AvrInstrRef {
        mnemonic: "CP",
        category: AvrInstrCategory::Compare,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Compare",
    },
    AvrInstrRef {
        mnemonic: "CPC",
        category: AvrInstrCategory::Compare,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Compare with carry",
    },
    AvrInstrRef {
        mnemonic: "CPI",
        category: AvrInstrCategory::Compare,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Compare with immediate",
    },
    AvrInstrRef {
        mnemonic: "CPSE",
        category: AvrInstrCategory::Skip,
        size: 2,
        cycles_min: 1,
        cycles_max: 3,
        affects_sreg: false,
        description: "Compare, skip if equal",
    },
    AvrInstrRef {
        mnemonic: "MOV",
        category: AvrInstrCategory::Transfer,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: false,
        description: "Copy register",
    },
    AvrInstrRef {
        mnemonic: "MOVW",
        category: AvrInstrCategory::Transfer,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: false,
        description: "Copy register word",
    },
    AvrInstrRef {
        mnemonic: "LDI",
        category: AvrInstrCategory::Transfer,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: false,
        description: "Load immediate",
    },
    AvrInstrRef {
        mnemonic: "LD",
        category: AvrInstrCategory::LoadStore,
        size: 2,
        cycles_min: 2,
        cycles_max: 2,
        affects_sreg: false,
        description: "Load indirect from data space",
    },
    AvrInstrRef {
        mnemonic: "LDS",
        category: AvrInstrCategory::LoadStore,
        size: 4,
        cycles_min: 2,
        cycles_max: 2,
        affects_sreg: false,
        description: "Load direct from data space",
    },
    AvrInstrRef {
        mnemonic: "ST",
        category: AvrInstrCategory::LoadStore,
        size: 2,
        cycles_min: 2,
        cycles_max: 2,
        affects_sreg: false,
        description: "Store indirect to data space",
    },
    AvrInstrRef {
        mnemonic: "STS",
        category: AvrInstrCategory::LoadStore,
        size: 4,
        cycles_min: 2,
        cycles_max: 2,
        affects_sreg: false,
        description: "Store direct to data space",
    },
    AvrInstrRef {
        mnemonic: "LPM",
        category: AvrInstrCategory::LoadStore,
        size: 2,
        cycles_min: 3,
        cycles_max: 3,
        affects_sreg: false,
        description: "Load program memory",
    },
    AvrInstrRef {
        mnemonic: "SPM",
        category: AvrInstrCategory::LoadStore,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: false,
        description: "Store program memory",
    },
    AvrInstrRef {
        mnemonic: "IN",
        category: AvrInstrCategory::Io,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: false,
        description: "Load I/O location",
    },
    AvrInstrRef {
        mnemonic: "OUT",
        category: AvrInstrCategory::Io,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: false,
        description: "Store I/O location",
    },
    AvrInstrRef {
        mnemonic: "PUSH",
        category: AvrInstrCategory::LoadStore,
        size: 2,
        cycles_min: 2,
        cycles_max: 2,
        affects_sreg: false,
        description: "Push register on stack",
    },
    AvrInstrRef {
        mnemonic: "POP",
        category: AvrInstrCategory::LoadStore,
        size: 2,
        cycles_min: 2,
        cycles_max: 2,
        affects_sreg: false,
        description: "Pop register from stack",
    },
    AvrInstrRef {
        mnemonic: "RJMP",
        category: AvrInstrCategory::Branch,
        size: 2,
        cycles_min: 2,
        cycles_max: 2,
        affects_sreg: false,
        description: "Relative jump",
    },
    AvrInstrRef {
        mnemonic: "JMP",
        category: AvrInstrCategory::Branch,
        size: 4,
        cycles_min: 3,
        cycles_max: 3,
        affects_sreg: false,
        description: "Jump",
    },
    AvrInstrRef {
        mnemonic: "IJMP",
        category: AvrInstrCategory::Branch,
        size: 2,
        cycles_min: 2,
        cycles_max: 2,
        affects_sreg: false,
        description: "Indirect jump to Z",
    },
    AvrInstrRef {
        mnemonic: "RCALL",
        category: AvrInstrCategory::CallReturn,
        size: 2,
        cycles_min: 3,
        cycles_max: 4,
        affects_sreg: false,
        description: "Relative call to subroutine",
    },
    AvrInstrRef {
        mnemonic: "CALL",
        category: AvrInstrCategory::CallReturn,
        size: 4,
        cycles_min: 4,
        cycles_max: 5,
        affects_sreg: false,
        description: "Long call to subroutine",
    },
    AvrInstrRef {
        mnemonic: "ICALL",
        category: AvrInstrCategory::CallReturn,
        size: 2,
        cycles_min: 3,
        cycles_max: 4,
        affects_sreg: false,
        description: "Indirect call to Z",
    },
    AvrInstrRef {
        mnemonic: "RET",
        category: AvrInstrCategory::CallReturn,
        size: 2,
        cycles_min: 4,
        cycles_max: 5,
        affects_sreg: false,
        description: "Return from subroutine",
    },
    AvrInstrRef {
        mnemonic: "RETI",
        category: AvrInstrCategory::CallReturn,
        size: 2,
        cycles_min: 4,
        cycles_max: 5,
        affects_sreg: true,
        description: "Return from interrupt",
    },
    AvrInstrRef {
        mnemonic: "SBRC",
        category: AvrInstrCategory::Skip,
        size: 2,
        cycles_min: 1,
        cycles_max: 3,
        affects_sreg: false,
        description: "Skip if bit in register cleared",
    },
    AvrInstrRef {
        mnemonic: "SBRS",
        category: AvrInstrCategory::Skip,
        size: 2,
        cycles_min: 1,
        cycles_max: 3,
        affects_sreg: false,
        description: "Skip if bit in register set",
    },
    AvrInstrRef {
        mnemonic: "SBIC",
        category: AvrInstrCategory::Skip,
        size: 2,
        cycles_min: 1,
        cycles_max: 3,
        affects_sreg: false,
        description: "Skip if bit in I/O register cleared",
    },
    AvrInstrRef {
        mnemonic: "SBIS",
        category: AvrInstrCategory::Skip,
        size: 2,
        cycles_min: 1,
        cycles_max: 3,
        affects_sreg: false,
        description: "Skip if bit in I/O register set",
    },
    AvrInstrRef {
        mnemonic: "BRBS",
        category: AvrInstrCategory::Branch,
        size: 2,
        cycles_min: 1,
        cycles_max: 2,
        affects_sreg: false,
        description: "Branch if status flag set",
    },
    AvrInstrRef {
        mnemonic: "BRBC",
        category: AvrInstrCategory::Branch,
        size: 2,
        cycles_min: 1,
        cycles_max: 2,
        affects_sreg: false,
        description: "Branch if status flag cleared",
    },
    AvrInstrRef {
        mnemonic: "BREQ",
        category: AvrInstrCategory::Branch,
        size: 2,
        cycles_min: 1,
        cycles_max: 2,
        affects_sreg: false,
        description: "Branch if equal",
    },
    AvrInstrRef {
        mnemonic: "BRNE",
        category: AvrInstrCategory::Branch,
        size: 2,
        cycles_min: 1,
        cycles_max: 2,
        affects_sreg: false,
        description: "Branch if not equal",
    },
    AvrInstrRef {
        mnemonic: "BRCS",
        category: AvrInstrCategory::Branch,
        size: 2,
        cycles_min: 1,
        cycles_max: 2,
        affects_sreg: false,
        description: "Branch if carry set",
    },
    AvrInstrRef {
        mnemonic: "BRCC",
        category: AvrInstrCategory::Branch,
        size: 2,
        cycles_min: 1,
        cycles_max: 2,
        affects_sreg: false,
        description: "Branch if carry cleared",
    },
    AvrInstrRef {
        mnemonic: "BRSH",
        category: AvrInstrCategory::Branch,
        size: 2,
        cycles_min: 1,
        cycles_max: 2,
        affects_sreg: false,
        description: "Branch if same or higher",
    },
    AvrInstrRef {
        mnemonic: "BRLO",
        category: AvrInstrCategory::Branch,
        size: 2,
        cycles_min: 1,
        cycles_max: 2,
        affects_sreg: false,
        description: "Branch if lower",
    },
    AvrInstrRef {
        mnemonic: "BRGE",
        category: AvrInstrCategory::Branch,
        size: 2,
        cycles_min: 1,
        cycles_max: 2,
        affects_sreg: false,
        description: "Branch if greater or equal (signed)",
    },
    AvrInstrRef {
        mnemonic: "BRLT",
        category: AvrInstrCategory::Branch,
        size: 2,
        cycles_min: 1,
        cycles_max: 2,
        affects_sreg: false,
        description: "Branch if less than (signed)",
    },
    AvrInstrRef {
        mnemonic: "SEI",
        category: AvrInstrCategory::System,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Set global interrupt enable",
    },
    AvrInstrRef {
        mnemonic: "CLI",
        category: AvrInstrCategory::System,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Clear global interrupt enable",
    },
    AvrInstrRef {
        mnemonic: "SEC",
        category: AvrInstrCategory::System,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Set carry flag",
    },
    AvrInstrRef {
        mnemonic: "CLC",
        category: AvrInstrCategory::System,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Clear carry flag",
    },
    AvrInstrRef {
        mnemonic: "SEN",
        category: AvrInstrCategory::System,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Set negative flag",
    },
    AvrInstrRef {
        mnemonic: "CLN",
        category: AvrInstrCategory::System,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Clear negative flag",
    },
    AvrInstrRef {
        mnemonic: "SEZ",
        category: AvrInstrCategory::System,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Set zero flag",
    },
    AvrInstrRef {
        mnemonic: "CLZ",
        category: AvrInstrCategory::System,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: true,
        description: "Clear zero flag",
    },
    AvrInstrRef {
        mnemonic: "SLEEP",
        category: AvrInstrCategory::System,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: false,
        description: "Enter sleep mode",
    },
    AvrInstrRef {
        mnemonic: "WDR",
        category: AvrInstrCategory::System,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: false,
        description: "Watchdog reset",
    },
    AvrInstrRef {
        mnemonic: "BREAK",
        category: AvrInstrCategory::System,
        size: 2,
        cycles_min: 1,
        cycles_max: 1,
        affects_sreg: false,
        description: "Break (debugWIRE)",
    },
];

/// Look up an AVR instruction reference entry by mnemonic.
#[must_use]
pub fn lookup_avr_instr_ref(mnemonic: &str) -> Option<&'static AvrInstrRef> {
    AVR_INSTR_REF.iter().find(|r| r.mnemonic == mnemonic)
}

// ── More Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod ref_tests {
    use super::*;

    #[test]
    fn test_instr_ref_nop() {
        let r = lookup_avr_instr_ref("NOP").unwrap();
        assert_eq!(r.cycles_min, 1);
        assert!(!r.affects_sreg);
    }

    #[test]
    fn test_instr_ref_add() {
        let r = lookup_avr_instr_ref("ADD").unwrap();
        assert!(r.affects_sreg);
        assert_eq!(r.category, AvrInstrCategory::Arithmetic);
    }

    #[test]
    fn test_instr_ref_rcall_cycles() {
        let r = lookup_avr_instr_ref("RCALL").unwrap();
        assert!(r.cycles_min <= r.cycles_max);
        assert_eq!(r.category, AvrInstrCategory::CallReturn);
    }

    #[test]
    fn test_instr_ref_lds_size() {
        let r = lookup_avr_instr_ref("LDS").unwrap();
        assert_eq!(r.size, 4);
    }

    #[test]
    fn test_instr_ref_missing() {
        assert!(lookup_avr_instr_ref("FAKEINSTR").is_none());
    }

    #[test]
    fn test_instr_ref_table_size() {
        assert!(AVR_INSTR_REF.len() >= 60);
    }
}

// ── AVR Code Metrics ──────────────────────────────────────────────────────────

/// Compute the total cycle count of an instruction sequence (best-case).
///
/// Uses the AVR instruction reference table for cycle counts.
/// Instructions not found in the table are counted as 1 cycle.
#[must_use]
pub fn avr_cycle_count_min(instrs: &[Instruction]) -> u32 {
    instrs
        .iter()
        .map(|i| lookup_avr_instr_ref(&i.mnemonic).map_or(1, |r| u32::from(r.cycles_min)))
        .sum()
}

/// Compute the total cycle count (worst-case / taken branches).
#[must_use]
pub fn avr_cycle_count_max(instrs: &[Instruction]) -> u32 {
    instrs
        .iter()
        .map(|i| lookup_avr_instr_ref(&i.mnemonic).map_or(1, |r| u32::from(r.cycles_max)))
        .sum()
}

/// Count how many instructions in the sequence modify SREG.
#[must_use]
pub fn avr_sreg_modifying_count(instrs: &[Instruction]) -> usize {
    instrs
        .iter()
        .filter(|i| lookup_avr_instr_ref(&i.mnemonic).is_some_and(|r| r.affects_sreg))
        .count()
}

// ── AVR Fixed Instruction Size Helper ────────────────────────────────────────

/// Return the size in bytes of an AVR instruction word.
///
/// 2-byte instructions: all except `CALL`, `JMP`, `LDS`, `STS` which are 4.
#[must_use]
pub fn avr_instr_byte_size(mnemonic: &str) -> usize {
    match mnemonic {
        "CALL" | "JMP" | "LDS" | "STS" => 4,
        _ => 2,
    }
}

#[cfg(test)]
mod metrics_tests {
    use super::*;

    fn arch() -> AvrArch {
        AvrArch::default()
    }
    fn addr(a: u64) -> Address {
        Address::new(a)
    }

    #[test]
    fn test_cycle_count_nop() {
        let enc = encode_nop().to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(avr_cycle_count_min(&[instr]), 1);
    }

    #[test]
    fn test_cycle_count_adiw() {
        // ADIW is 2 cycles
        let r = lookup_avr_instr_ref("ADIW").unwrap();
        assert_eq!(r.cycles_min, 2);
    }

    #[test]
    fn test_sreg_modifying_add() {
        let enc = encode_add(3, 4).to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(avr_sreg_modifying_count(&[instr]), 1);
    }

    #[test]
    fn test_sreg_modifying_nop() {
        let enc = encode_nop().to_le_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(avr_sreg_modifying_count(&[instr]), 0);
    }

    #[test]
    fn test_instr_byte_size_normal() {
        assert_eq!(avr_instr_byte_size("NOP"), 2);
        assert_eq!(avr_instr_byte_size("ADD"), 2);
    }

    #[test]
    fn test_instr_byte_size_long() {
        assert_eq!(avr_instr_byte_size("JMP"), 4);
        assert_eq!(avr_instr_byte_size("CALL"), 4);
        assert_eq!(avr_instr_byte_size("LDS"), 4);
        assert_eq!(avr_instr_byte_size("STS"), 4);
    }

    #[test]
    fn test_cycle_min_max_order() {
        for r in AVR_INSTR_REF {
            assert!(
                r.cycles_min <= r.cycles_max,
                "Mnemonic {} has cycles_min > cycles_max",
                r.mnemonic
            );
        }
    }

    #[test]
    fn test_int_vector_all_maskable_except_reset() {
        for v in ATMEGA328P_INT_VECTORS {
            if v.name == "RESET" {
                assert!(!v.maskable);
            } else {
                assert!(v.maskable, "{} should be maskable", v.name);
            }
        }
    }

    #[test]
    fn test_ext_io_io_addr_range() {
        for r in ATMEGA328P_EXT_IO {
            if let Some(io) = r.io_addr {
                assert!(io <= 0x3F, "{} io_addr 0x{:02X} out of range", r.name, io);
            }
        }
    }
}

// ── AVR Architecture Constants ────────────────────────────────────────────────

/// Maximum flash size in bytes for `ATmega328P` (32 KiB).
pub const ATMEGA328P_FLASH_BYTES: u32 = 32 * 1024;

/// Maximum SRAM size in bytes for `ATmega328P` (2 KiB).
pub const ATMEGA328P_SRAM_BYTES: u32 = 2 * 1024;

/// EEPROM size in bytes for `ATmega328P` (1 KiB).
pub const ATMEGA328P_EEPROM_BYTES: u32 = 1024;

/// Maximum flash size in words for `ATmega328P` (16 Ki words).
pub const ATMEGA328P_FLASH_WORDS: u32 = ATMEGA328P_FLASH_BYTES / 2;

/// `ATmega328P` CPU frequency at 5V (maximum, Hz).
pub const ATMEGA328P_MAX_FREQ_HZ: u32 = 20_000_000;

/// Whether an `ATmega328P` address is in flash (word address ≤ max flash words).
#[must_use]
pub const fn is_flash_addr(word_addr: u32) -> bool {
    word_addr < ATMEGA328P_FLASH_WORDS
}

/// Whether an `ATmega328P` address is in SRAM (byte addr 0x0100–0x08FF).
#[must_use]
pub const fn is_sram_addr(byte_addr: u16) -> bool {
    byte_addr >= 0x0100 && byte_addr <= 0x08FF
}

/// Whether an `ATmega328P` address is in the I/O range (byte addr 0x0020–0x00FF).
#[must_use]
pub const fn is_io_space_addr(byte_addr: u16) -> bool {
    byte_addr >= 0x0020 && byte_addr <= 0x00FF
}

#[cfg(test)]
mod const_tests {
    use super::*;

    #[test]
    fn test_flash_bytes() {
        assert_eq!(ATMEGA328P_FLASH_BYTES, 32768);
    }

    #[test]
    fn test_flash_words() {
        assert_eq!(ATMEGA328P_FLASH_WORDS, 16384);
    }

    #[test]
    fn test_is_flash_addr() {
        assert!(is_flash_addr(0));
        assert!(is_flash_addr(16383));
        assert!(!is_flash_addr(16384));
    }

    #[test]
    fn test_is_sram_addr() {
        assert!(is_sram_addr(0x0100));
        assert!(!is_sram_addr(0x001F));
    }

    #[test]
    fn test_is_io_space_addr() {
        assert!(is_io_space_addr(0x0020));
        assert!(is_io_space_addr(0x005F));
        assert!(!is_io_space_addr(0x0100));
    }
}
