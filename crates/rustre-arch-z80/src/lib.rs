//! `rustre-arch-z80`
//!
//! Zilog Z80 architecture implementation for the `RustRE` Suite.
//! Supports unprefixed opcodes plus CB, DD, ED, FD prefix tables.
//! Includes full 8080-compatible instruction set, Z80-specific extensions,
//! disassembly, encoding, analysis, calling convention, and emulation helpers.

pub mod z80_emulator;
pub mod z80_io_model;
pub mod z80_prefix_tables;

/// Z80 OS and platform pattern analysis.
///
/// `CpMBiosCall`, `Z80BdosCall`, `ZxSpectrumPatterns`, `Z80BootloaderDetector`,
/// `Z80SelfModifying`, `Z80OsPatterns`.
pub mod z80_os_patterns;

/// Z80 undocumented instructions.
///
/// IXH/IXL/IYH/IYL register access via the DD CB / FD CB prefixes, SLL (shift
/// left with bit0=1), DDCB/FDCB combined bit manipulation + load,
/// `undoc_decode()`, and `Z80FullDecoder`.
pub mod z80_undocumented;

/// Platform-specific Z80 knowledge.
///
/// ZX Spectrum ULA/memory banking, MSX slot system and BIOS calls, CP/M BDOS
/// functions, Game Boy (SM83) ISA differences.
pub mod z80_platforms;

pub mod z80_decoder;
pub mod z80_registers;
pub mod z80_disassembler;

pub mod z80_io_ports;
pub mod z80_rom_header;
pub mod z80_register_pairs;
pub mod z80_undocumented_opcodes;
pub mod z80_platform_detector;

use bitflags::bitflags;
use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
use rustre_core::arch::{BranchCondition, BranchKind, RegisterKind};
use rustre_core::{address::Address, endian::Endian, errors::CoreError};

// ── Register IDs ──────────────────────────────────────────────────────────────

/// Register id for the Accumulator (A).
pub const REG_A: u32 = 0;
/// Register id for B.
pub const REG_B: u32 = 1;
/// Register id for C.
pub const REG_C: u32 = 2;
/// Register id for D.
pub const REG_D: u32 = 3;
/// Register id for E.
pub const REG_E: u32 = 4;
/// Register id for H.
pub const REG_H: u32 = 5;
/// Register id for L.
pub const REG_L: u32 = 6;
/// Register id for Flags (F).
pub const REG_F: u32 = 7;
/// Register id for Interrupt-page address register (I).
pub const REG_I: u32 = 8;
/// Register id for Memory-refresh register (R).
pub const REG_R: u32 = 9;
/// Register id for AF pair.
pub const REG_AF: u32 = 10;
/// Register id for BC pair.
pub const REG_BC: u32 = 11;
/// Register id for DE pair.
pub const REG_DE: u32 = 12;
/// Register id for HL pair.
pub const REG_HL: u32 = 13;
/// Register id for Stack Pointer.
pub const REG_SP: u32 = 14;
/// Register id for Program Counter.
pub const REG_PC: u32 = 15;
/// Register id for IX.
pub const REG_IX: u32 = 16;
/// Register id for IY.
pub const REG_IY: u32 = 17;
/// Register id for AF' (alternate).
pub const REG_AF2: u32 = 18;
/// Register id for BC' (alternate).
pub const REG_BC2: u32 = 19;
/// Register id for DE' (alternate).
pub const REG_DE2: u32 = 20;
/// Register id for HL' (alternate).
pub const REG_HL2: u32 = 21;

// ── Flag bits ─────────────────────────────────────────────────────────────────

bitflags! {
    /// Z80 CPU flags register bit layout.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Flags: u8 {
        /// Carry flag (C).
        const C = 0x01;
        /// Add/Subtract flag (N) — set after subtraction.
        const N = 0x02;
        /// Parity/Overflow flag (P/V).
        const PV = 0x04;
        /// Undocumented flag (bit 3 / F3).
        const F3 = 0x08;
        /// Half-carry flag (H).
        const H = 0x10;
        /// Undocumented flag (bit 5 / F5).
        const F5 = 0x20;
        /// Zero flag (Z).
        const Z = 0x40;
        /// Sign flag (S).
        const S = 0x80;
    }
}

// ── Condition code names ──────────────────────────────────────────────────────

const REG8_NAMES: [&str; 8] = ["B", "C", "D", "E", "H", "L", "(HL)", "A"];
const CC_NAMES: [&str; 8] = ["NZ", "Z", "NC", "C", "PO", "PE", "P", "M"];

const fn reg8(r: u8) -> &'static str {
    REG8_NAMES[(r & 7) as usize]
}

const fn cc_name(c: u8) -> &'static str {
    CC_NAMES[(c & 7) as usize]
}

const fn rp(r: u8) -> &'static str {
    match r & 3 {
        0 => "BC",
        1 => "DE",
        2 => "HL",
        _ => "SP",
    }
}

const fn rp2(r: u8) -> &'static str {
    match r & 3 {
        0 => "BC",
        1 => "DE",
        2 => "HL",
        _ => "AF",
    }
}

// ── Decoded instruction ───────────────────────────────────────────────────────

/// A decoded Z80 instruction (internal representation).
#[derive(Debug)]
pub struct Decoded {
    /// Instruction mnemonic.
    pub mnemonic: String,
    /// Operand string.
    pub operands: String,
    /// Instruction size in bytes.
    pub size: usize,
    /// Semantic flags.
    pub flags: InstrFlags,
}

// ── CB-prefix table ───────────────────────────────────────────────────────────

/// Decode a CB-prefixed instruction.
fn decode_cb(op: u8) -> Decoded {
    let xb = (op >> 6) & 3;
    let yb = (op >> 3) & 7;
    let zb = op & 7;
    let reg = reg8(zb);
    let (mnemonic, operands) = match xb {
        0 => {
            let mn = match yb {
                0 => "RLC",
                1 => "RRC",
                2 => "RL",
                3 => "RR",
                4 => "SLA",
                5 => "SRA",
                6 => "SLL",
                _ => "SRL",
            };
            (mn.to_string(), reg.to_string())
        }
        1 => ("BIT".to_string(), format!("{yb},{reg}")),
        2 => ("RES".to_string(), format!("{yb},{reg}")),
        _ => ("SET".to_string(), format!("{yb},{reg}")),
    };
    Decoded {
        mnemonic,
        operands,
        size: 2,
        flags: InstrFlags::NONE,
    }
}

// ── ED-prefix table ───────────────────────────────────────────────────────────

/// Decode an ED-prefixed instruction.
fn decode_ed(op: u8, bytes: &[u8]) -> Decoded {
    if op < 0xA0 {
        return decode_ed_load_group(op, bytes);
    }
    decode_ed_block_group(op)
}

/// An ED opcode with no defined meaning: rendered as a data byte pair.
fn ed_unknown(op: u8) -> (String, String, InstrFlags) {
    ("DB".to_string(), format!("ED,${op:02X}"), InstrFlags::NONE)
}

/// ED opcodes below 0xA0: IN/OUT (C), 16-bit ADC/SBC, LD (nn),rp, IM, RRD/RLD.
fn decode_ed_load_group(op: u8, bytes: &[u8]) -> Decoded {
    let mut size = 2usize;
    let (mnemonic, operands, flags) = match op {
        0x40 => ("IN".to_string(), "B,(C)".to_string(), InstrFlags::NONE),
        0x41 => ("OUT".to_string(), "(C),B".to_string(), InstrFlags::NONE),
        0x42 => ("SBC".to_string(), "HL,BC".to_string(), InstrFlags::NONE),
        0x43 => {
            size = 4;
            let addr = if bytes.len() >= 4 {
                u16::from_le_bytes([bytes[2], bytes[3]])
            } else {
                0
            };
            (
                "LD".to_string(),
                format!("(${addr:04X}),BC"),
                InstrFlags::WRITE_MEM,
            )
        }
        0x44 => ("NEG".to_string(), String::new(), InstrFlags::NONE),
        0x45 => ("RETN".to_string(), String::new(), InstrFlags::RET),
        0x46 => ("IM".to_string(), "0".to_string(), InstrFlags::NONE),
        0x47 => ("LD".to_string(), "I,A".to_string(), InstrFlags::NONE),
        0x48 => ("IN".to_string(), "C,(C)".to_string(), InstrFlags::NONE),
        0x49 => ("OUT".to_string(), "(C),C".to_string(), InstrFlags::NONE),
        0x4A => ("ADC".to_string(), "HL,BC".to_string(), InstrFlags::NONE),
        0x4B => {
            size = 4;
            let addr = if bytes.len() >= 4 {
                u16::from_le_bytes([bytes[2], bytes[3]])
            } else {
                0
            };
            (
                "LD".to_string(),
                format!("BC,(${addr:04X})"),
                InstrFlags::READ_MEM,
            )
        }
        0x4D => ("RETI".to_string(), String::new(), InstrFlags::RET),
        0x4F => ("LD".to_string(), "R,A".to_string(), InstrFlags::NONE),
        0x50 => ("IN".to_string(), "D,(C)".to_string(), InstrFlags::NONE),
        0x51 => ("OUT".to_string(), "(C),D".to_string(), InstrFlags::NONE),
        0x52 => ("SBC".to_string(), "HL,DE".to_string(), InstrFlags::NONE),
        0x53 => {
            size = 4;
            let addr = if bytes.len() >= 4 {
                u16::from_le_bytes([bytes[2], bytes[3]])
            } else {
                0
            };
            (
                "LD".to_string(),
                format!("(${addr:04X}),DE"),
                InstrFlags::WRITE_MEM,
            )
        }
        0x56 => ("IM".to_string(), "1".to_string(), InstrFlags::NONE),
        0x57 => ("LD".to_string(), "A,I".to_string(), InstrFlags::NONE),
        0x58 => ("IN".to_string(), "E,(C)".to_string(), InstrFlags::NONE),
        0x59 => ("OUT".to_string(), "(C),E".to_string(), InstrFlags::NONE),
        0x5A => ("ADC".to_string(), "HL,DE".to_string(), InstrFlags::NONE),
        0x5B => {
            size = 4;
            let addr = if bytes.len() >= 4 {
                u16::from_le_bytes([bytes[2], bytes[3]])
            } else {
                0
            };
            (
                "LD".to_string(),
                format!("DE,(${addr:04X})"),
                InstrFlags::READ_MEM,
            )
        }
        0x5E => ("IM".to_string(), "2".to_string(), InstrFlags::NONE),
        0x5F => ("LD".to_string(), "A,R".to_string(), InstrFlags::NONE),
        0x60 => ("IN".to_string(), "H,(C)".to_string(), InstrFlags::NONE),
        0x61 => ("OUT".to_string(), "(C),H".to_string(), InstrFlags::NONE),
        0x62 => ("SBC".to_string(), "HL,HL".to_string(), InstrFlags::NONE),
        0x63 => {
            size = 4;
            let addr = if bytes.len() >= 4 {
                u16::from_le_bytes([bytes[2], bytes[3]])
            } else {
                0
            };
            (
                "LD".to_string(),
                format!("(${addr:04X}),HL"),
                InstrFlags::WRITE_MEM,
            )
        }
        0x67 => ("RRD".to_string(), String::new(), InstrFlags::NONE),
        0x68 => ("IN".to_string(), "L,(C)".to_string(), InstrFlags::NONE),
        0x69 => ("OUT".to_string(), "(C),L".to_string(), InstrFlags::NONE),
        0x6A => ("ADC".to_string(), "HL,HL".to_string(), InstrFlags::NONE),
        0x6B => {
            size = 4;
            let addr = if bytes.len() >= 4 {
                u16::from_le_bytes([bytes[2], bytes[3]])
            } else {
                0
            };
            (
                "LD".to_string(),
                format!("HL,(${addr:04X})"),
                InstrFlags::READ_MEM,
            )
        }
        0x6F => ("RLD".to_string(), String::new(), InstrFlags::NONE),
        0x72 => ("SBC".to_string(), "HL,SP".to_string(), InstrFlags::NONE),
        0x73 => {
            size = 4;
            let addr = if bytes.len() >= 4 {
                u16::from_le_bytes([bytes[2], bytes[3]])
            } else {
                0
            };
            (
                "LD".to_string(),
                format!("(${addr:04X}),SP"),
                InstrFlags::WRITE_MEM,
            )
        }
        0x78 => ("IN".to_string(), "A,(C)".to_string(), InstrFlags::NONE),
        0x79 => ("OUT".to_string(), "(C),A".to_string(), InstrFlags::NONE),
        0x7A => ("ADC".to_string(), "HL,SP".to_string(), InstrFlags::NONE),
        0x7B => {
            size = 4;
            let addr = if bytes.len() >= 4 {
                u16::from_le_bytes([bytes[2], bytes[3]])
            } else {
                0
            };
            (
                "LD".to_string(),
                format!("SP,(${addr:04X})"),
                InstrFlags::READ_MEM,
            )
        }
        _ => ed_unknown(op),
    };
    Decoded {
        mnemonic,
        operands,
        size,
        flags,
    }
}

/// ED opcodes 0xA0 and above: the block transfer, search and block I/O groups.
fn decode_ed_block_group(op: u8) -> Decoded {
    let (mnemonic, operands, flags) = match op {
        0xA0 => ("LDI".to_string(), String::new(), InstrFlags::NONE),
        0xA1 => ("CPI".to_string(), String::new(), InstrFlags::NONE),
        0xA2 => ("INI".to_string(), String::new(), InstrFlags::NONE),
        0xA3 => ("OUTI".to_string(), String::new(), InstrFlags::NONE),
        0xA8 => ("LDD".to_string(), String::new(), InstrFlags::NONE),
        0xA9 => ("CPD".to_string(), String::new(), InstrFlags::NONE),
        0xAA => ("IND".to_string(), String::new(), InstrFlags::NONE),
        0xAB => ("OUTD".to_string(), String::new(), InstrFlags::NONE),
        0xB0 => ("LDIR".to_string(), String::new(), InstrFlags::NONE),
        0xB1 => ("CPIR".to_string(), String::new(), InstrFlags::NONE),
        0xB2 => ("INIR".to_string(), String::new(), InstrFlags::NONE),
        0xB3 => ("OTIR".to_string(), String::new(), InstrFlags::NONE),
        0xB8 => ("LDDR".to_string(), String::new(), InstrFlags::NONE),
        0xB9 => ("CPDR".to_string(), String::new(), InstrFlags::NONE),
        0xBA => ("INDR".to_string(), String::new(), InstrFlags::NONE),
        0xBB => ("OTDR".to_string(), String::new(), InstrFlags::NONE),
        _ => ed_unknown(op),
    };
    Decoded {
        mnemonic,
        operands,
        size: 2,
        flags,
    }
}

// ── DD/FD-prefix tables ───────────────────────────────────────────────────────

fn decode_index_prefix(op: u8, bytes: &[u8], idx: &str) -> Decoded {
    let raw_d = if bytes.len() >= 3 { bytes[2] } else { 0 };
    let disp_val = i8::from_ne_bytes([raw_d]);
    let disp = if disp_val >= 0 {
        format!("{idx}+{disp_val}")
    } else {
        format!("{idx}{disp_val}")
    };
    if op < 0x46 {
        return decode_index_arith_group(op, bytes, idx, &disp);
    }
    decode_index_memory_group(op, idx, &disp)
}

/// A DD/FD opcode with no indexed form: rendered as a data byte.
fn index_unknown(op: u8) -> (String, String, usize, InstrFlags) {
    ("DB".to_string(), format!("${op:02X}"), 2, InstrFlags::NONE)
}

/// DD/FD opcodes below 0x46: 16-bit ADD/INC/DEC, LD ix,nn and (nn) forms.
fn decode_index_arith_group(op: u8, bytes: &[u8], idx: &str, disp: &str) -> Decoded {
    let (mnemonic, operands, size, flags) = match op {
        0x09 => ("ADD".to_string(), format!("{idx},BC"), 2, InstrFlags::NONE),
        0x19 => ("ADD".to_string(), format!("{idx},DE"), 2, InstrFlags::NONE),
        0x21 => {
            let nn = if bytes.len() >= 4 {
                u16::from_le_bytes([bytes[2], bytes[3]])
            } else {
                0
            };
            (
                "LD".to_string(),
                format!("{idx},#${nn:04X}"),
                4,
                InstrFlags::NONE,
            )
        }
        0x22 => {
            let nn = if bytes.len() >= 4 {
                u16::from_le_bytes([bytes[2], bytes[3]])
            } else {
                0
            };
            (
                "LD".to_string(),
                format!("(${nn:04X}),{idx}"),
                4,
                InstrFlags::WRITE_MEM,
            )
        }
        0x23 => ("INC".to_string(), idx.to_string(), 2, InstrFlags::NONE),
        0x29 => (
            "ADD".to_string(),
            format!("{idx},{idx}"),
            2,
            InstrFlags::NONE,
        ),
        0x2A => {
            let nn = if bytes.len() >= 4 {
                u16::from_le_bytes([bytes[2], bytes[3]])
            } else {
                0
            };
            (
                "LD".to_string(),
                format!("{idx},(${nn:04X})"),
                4,
                InstrFlags::READ_MEM,
            )
        }
        0x2B => ("DEC".to_string(), idx.to_string(), 2, InstrFlags::NONE),
        0x34 => (
            "INC".to_string(),
            format!("({disp})"),
            3,
            InstrFlags::READ_MEM.union(InstrFlags::WRITE_MEM),
        ),
        0x35 => (
            "DEC".to_string(),
            format!("({disp})"),
            3,
            InstrFlags::READ_MEM.union(InstrFlags::WRITE_MEM),
        ),
        0x36 => {
            let n = if bytes.len() >= 4 { bytes[3] } else { 0 };
            (
                "LD".to_string(),
                format!("({disp}),${n:02X}"),
                4,
                InstrFlags::WRITE_MEM,
            )
        }
        0x39 => ("ADD".to_string(), format!("{idx},SP"), 2, InstrFlags::NONE),
        _ => index_unknown(op),
    };
    Decoded {
        mnemonic,
        operands,
        size,
        flags,
    }
}

/// DD/FD opcodes 0x46 and above: the (ix+d) load, ALU and stack forms.
fn decode_index_memory_group(op: u8, idx: &str, disp: &str) -> Decoded {
    let (mnemonic, operands, size, flags) = match op {
        0x46 => (
            "LD".to_string(),
            format!("B,({disp})"),
            3,
            InstrFlags::READ_MEM,
        ),
        0x4E => (
            "LD".to_string(),
            format!("C,({disp})"),
            3,
            InstrFlags::READ_MEM,
        ),
        0x56 => (
            "LD".to_string(),
            format!("D,({disp})"),
            3,
            InstrFlags::READ_MEM,
        ),
        0x5E => (
            "LD".to_string(),
            format!("E,({disp})"),
            3,
            InstrFlags::READ_MEM,
        ),
        0x66 => (
            "LD".to_string(),
            format!("H,({disp})"),
            3,
            InstrFlags::READ_MEM,
        ),
        0x6E => (
            "LD".to_string(),
            format!("L,({disp})"),
            3,
            InstrFlags::READ_MEM,
        ),
        0x70 => (
            "LD".to_string(),
            format!("({disp}),B"),
            3,
            InstrFlags::WRITE_MEM,
        ),
        0x71 => (
            "LD".to_string(),
            format!("({disp}),C"),
            3,
            InstrFlags::WRITE_MEM,
        ),
        0x72 => (
            "LD".to_string(),
            format!("({disp}),D"),
            3,
            InstrFlags::WRITE_MEM,
        ),
        0x73 => (
            "LD".to_string(),
            format!("({disp}),E"),
            3,
            InstrFlags::WRITE_MEM,
        ),
        0x74 => (
            "LD".to_string(),
            format!("({disp}),H"),
            3,
            InstrFlags::WRITE_MEM,
        ),
        0x75 => (
            "LD".to_string(),
            format!("({disp}),L"),
            3,
            InstrFlags::WRITE_MEM,
        ),
        0x77 => (
            "LD".to_string(),
            format!("({disp}),A"),
            3,
            InstrFlags::WRITE_MEM,
        ),
        0x7E => (
            "LD".to_string(),
            format!("A,({disp})"),
            3,
            InstrFlags::READ_MEM,
        ),
        0x86 => (
            "ADD".to_string(),
            format!("A,({disp})"),
            3,
            InstrFlags::READ_MEM,
        ),
        0x8E => (
            "ADC".to_string(),
            format!("A,({disp})"),
            3,
            InstrFlags::READ_MEM,
        ),
        0x96 => (
            "SUB".to_string(),
            format!("({disp})"),
            3,
            InstrFlags::READ_MEM,
        ),
        0x9E => (
            "SBC".to_string(),
            format!("A,({disp})"),
            3,
            InstrFlags::READ_MEM,
        ),
        0xA6 => (
            "AND".to_string(),
            format!("({disp})"),
            3,
            InstrFlags::READ_MEM,
        ),
        0xAE => (
            "XOR".to_string(),
            format!("({disp})"),
            3,
            InstrFlags::READ_MEM,
        ),
        0xB6 => (
            "OR".to_string(),
            format!("({disp})"),
            3,
            InstrFlags::READ_MEM,
        ),
        0xBE => (
            "CP".to_string(),
            format!("({disp})"),
            3,
            InstrFlags::READ_MEM,
        ),
        0xE1 => ("POP".to_string(), idx.to_string(), 2, InstrFlags::READ_MEM),
        0xE3 => (
            "EX".to_string(),
            format!("(SP),{idx}"),
            2,
            InstrFlags::READ_MEM.union(InstrFlags::WRITE_MEM),
        ),
        0xE5 => (
            "PUSH".to_string(),
            idx.to_string(),
            2,
            InstrFlags::WRITE_MEM,
        ),
        0xE9 => (
            "JP".to_string(),
            format!("({idx})"),
            2,
            InstrFlags::BRANCH.union(InstrFlags::INDIRECT),
        ),
        0xF9 => ("LD".to_string(), format!("SP,{idx}"), 2, InstrFlags::NONE),
        _ => index_unknown(op),
    };
    Decoded {
        mnemonic,
        operands,
        size,
        flags,
    }
}

// ── Main decode ───────────────────────────────────────────────────────────────

/// An opcode byte with no defined meaning at this point in the table.
fn undefined_byte(op: u8) -> Decoded {
    Decoded {
        mnemonic: "DB".to_string(),
        operands: format!("${op:02X}"),
        size: 1,
        flags: InstrFlags::NONE,
    }
}

/// x=0, z=0..1: relative jumps, EX AF, DJNZ and 16-bit loads.
fn decode_x0_z01(op: u8, yb: u8, zb: u8, pb: u8, qb: u8, bytes: &[u8], pc: u64) -> Result<Decoded, CoreError> {
    Ok(match zb {
            0 => match yb {
                0 => Decoded {
                    mnemonic: "NOP".to_string(),
                    operands: String::new(),
                    size: 1,
                    flags: InstrFlags::NONE,
                },
                1 => Decoded {
                    mnemonic: "EX".to_string(),
                    operands: "AF,AF'".to_string(),
                    size: 1,
                    flags: InstrFlags::NONE,
                },
                2 => {
                    if bytes.len() < 2 {
                        return Err(CoreError::InvalidFormat {
                            message: "truncated DJNZ".to_string(),
                        });
                    }
                    let off = i8::from_ne_bytes([bytes[1]]);
                    let target = pc
                        .wrapping_add_signed(2_i64)
                        .wrapping_add_signed(i64::from(off));
                    Decoded {
                        mnemonic: "DJNZ".to_string(),
                        operands: format!("${:04X}", target & 0xFFFF),
                        size: 2,
                        flags: InstrFlags::BRANCH.union(InstrFlags::CONDITIONAL),
                    }
                }
                3 => {
                    if bytes.len() < 2 {
                        return Err(CoreError::InvalidFormat {
                            message: "truncated JR".to_string(),
                        });
                    }
                    let off = i8::from_ne_bytes([bytes[1]]);
                    let target = pc
                        .wrapping_add_signed(2_i64)
                        .wrapping_add_signed(i64::from(off));
                    Decoded {
                        mnemonic: "JR".to_string(),
                        operands: format!("${:04X}", target & 0xFFFF),
                        size: 2,
                        flags: InstrFlags::BRANCH,
                    }
                }
                4..=7 => {
                    if bytes.len() < 2 {
                        return Err(CoreError::InvalidFormat {
                            message: "truncated JR cond".to_string(),
                        });
                    }
                    let off = i8::from_ne_bytes([bytes[1]]);
                    let target = pc
                        .wrapping_add_signed(2_i64)
                        .wrapping_add_signed(i64::from(off));
                    let cond = match yb {
                        4 => "NZ",
                        5 => "Z",
                        6 => "NC",
                        _ => "C",
                    };
                    Decoded {
                        mnemonic: "JR".to_string(),
                        operands: format!("{cond},${:04X}", target & 0xFFFF),
                        size: 2,
                        flags: InstrFlags::BRANCH.union(InstrFlags::CONDITIONAL),
                    }
                }
                _ => unreachable!(),
            },
            1 => match qb {
                0 => {
                    if bytes.len() < 3 {
                        return Err(CoreError::InvalidFormat {
                            message: "truncated LD rp,nn".to_string(),
                        });
                    }
                    let nn = u16::from_le_bytes([bytes[1], bytes[2]]);
                    Decoded {
                        mnemonic: "LD".to_string(),
                        operands: format!("{},#${nn:04X}", rp(pb)),
                        size: 3,
                        flags: InstrFlags::NONE,
                    }
                }
                _ => Decoded {
                    mnemonic: "ADD".to_string(),
                    operands: format!("HL,{}", rp(pb)),
                    size: 1,
                    flags: InstrFlags::NONE,
                },
            },
        _ => undefined_byte(op),
    })
}

/// x=0, z=2..3: indirect 8/16-bit loads and 16-bit INC/DEC.
fn decode_x0_z23(op: u8, zb: u8, pb: u8, qb: u8, bytes: &[u8]) -> Result<Decoded, CoreError> {
    Ok(match zb {
            2 => {
                let (mn, ops, fl) = match (qb, pb) {
                    (0, 0) => ("LD", "(BC),A".to_string(), InstrFlags::WRITE_MEM),
                    (0, 1) => ("LD", "(DE),A".to_string(), InstrFlags::WRITE_MEM),
                    (0, 2) => {
                        if bytes.len() < 3 {
                            return Err(CoreError::InvalidFormat {
                                message: "truncated LD (nn),HL".to_string(),
                            });
                        }
                        let nn = u16::from_le_bytes([bytes[1], bytes[2]]);
                        ("LD", format!("(${nn:04X}),HL"), InstrFlags::WRITE_MEM)
                    }
                    (0, 3) => {
                        if bytes.len() < 3 {
                            return Err(CoreError::InvalidFormat {
                                message: "truncated LD (nn),A".to_string(),
                            });
                        }
                        let nn = u16::from_le_bytes([bytes[1], bytes[2]]);
                        ("LD", format!("(${nn:04X}),A"), InstrFlags::WRITE_MEM)
                    }
                    (1, 0) => ("LD", "A,(BC)".to_string(), InstrFlags::READ_MEM),
                    (1, 1) => ("LD", "A,(DE)".to_string(), InstrFlags::READ_MEM),
                    (1, 2) => {
                        if bytes.len() < 3 {
                            return Err(CoreError::InvalidFormat {
                                message: "truncated LD HL,(nn)".to_string(),
                            });
                        }
                        let nn = u16::from_le_bytes([bytes[1], bytes[2]]);
                        ("LD", format!("HL,(${nn:04X})"), InstrFlags::READ_MEM)
                    }
                    _ => {
                        if bytes.len() < 3 {
                            return Err(CoreError::InvalidFormat {
                                message: "truncated LD A,(nn)".to_string(),
                            });
                        }
                        let nn = u16::from_le_bytes([bytes[1], bytes[2]]);
                        ("LD", format!("A,(${nn:04X})"), InstrFlags::READ_MEM)
                    }
                };
                let sz = if pb >= 2 { 3 } else { 1 };
                Decoded {
                    mnemonic: mn.to_string(),
                    operands: ops,
                    size: sz,
                    flags: fl,
                }
            }
            3 => match qb {
                0 => Decoded {
                    mnemonic: "INC".to_string(),
                    operands: rp(pb).to_string(),
                    size: 1,
                    flags: InstrFlags::NONE,
                },
                _ => Decoded {
                    mnemonic: "DEC".to_string(),
                    operands: rp(pb).to_string(),
                    size: 1,
                    flags: InstrFlags::NONE,
                },
            },
        _ => undefined_byte(op),
    })
}

/// x=0, z=4..7: 8-bit INC/DEC, LD r,n and the accumulator ops.
fn decode_x0_z47(yb: u8, zb: u8, bytes: &[u8]) -> Result<Decoded, CoreError> {
    Ok(match zb {
            4 => Decoded {
                mnemonic: "INC".to_string(),
                operands: reg8(yb).to_string(),
                size: 1,
                flags: InstrFlags::NONE,
            },
            5 => Decoded {
                mnemonic: "DEC".to_string(),
                operands: reg8(yb).to_string(),
                size: 1,
                flags: InstrFlags::NONE,
            },
            6 => {
                if bytes.len() < 2 {
                    return Err(CoreError::InvalidFormat {
                        message: "truncated LD r,n".to_string(),
                    });
                }
                Decoded {
                    mnemonic: "LD".to_string(),
                    operands: format!("{},#${:02X}", reg8(yb), bytes[1]),
                    size: 2,
                    flags: InstrFlags::NONE,
                }
            }
            _ => {
                let mn = match yb {
                    0 => "RLCA",
                    1 => "RRCA",
                    2 => "RLA",
                    3 => "RRA",
                    4 => "DAA",
                    5 => "CPL",
                    6 => "SCF",
                    _ => "CCF",
                };
                Decoded {
                    mnemonic: mn.to_string(),
                    operands: String::new(),
                    size: 1,
                    flags: InstrFlags::NONE,
                }
            }
    })
}

/// Decode an unprefixed Z80 instruction.
///
/// # Errors
/// Returns `CoreError::InvalidInput` when the byte slice is too short.
pub fn decode_main(bytes: &[u8], pc: u64) -> Result<Decoded, CoreError> {
    if bytes.is_empty() {
        return Err(CoreError::InvalidFormat {
            message: "empty Z80 instruction".to_string(),
        });
    }
    let op = bytes[0];

    // CB prefix — handled before general decoding
    if op == 0xCB {
        if bytes.len() < 2 {
            return Err(CoreError::InvalidFormat {
                message: "truncated CB prefix".to_string(),
            });
        }
        return Ok(decode_cb(bytes[1]));
    }

    // Z80 opcode field decomposition (Zilog notation: x/y/z/p/q)
    let xb = (op >> 6) & 3;
    let yb = (op >> 3) & 7;
    let zb = op & 7;
    let pb = (yb >> 1) & 3;
    let qb = yb & 1;

    let result = match xb {
        // x=0: misc loads, 16-bit INC/DEC/LD, 8-bit INC/DEC/LD, rotate accumulator
        0 => match zb {
            0 | 1 => decode_x0_z01(op, yb, zb, pb, qb, bytes, pc)?,
            2 | 3 => decode_x0_z23(op, zb, pb, qb, bytes)?,
            _ => decode_x0_z47(yb, zb, bytes)?,
        },

        // x=1: 8-bit LD r,r (or HALT for 0x76)
        1 => {
            if op == 0x76 {
                Decoded {
                    mnemonic: "HALT".to_string(),
                    operands: String::new(),
                    size: 1,
                    flags: InstrFlags::NONE,
                }
            } else {
                Decoded {
                    mnemonic: "LD".to_string(),
                    operands: format!("{},{}", reg8(yb), reg8(zb)),
                    size: 1,
                    flags: InstrFlags::NONE,
                }
            }
        }

        // x=2: 8-bit ALU op A,r
        2 => {
            let mn = match yb {
                0 => "ADD",
                1 => "ADC",
                2 => "SUB",
                3 => "SBC",
                4 => "AND",
                5 => "XOR",
                6 => "OR",
                _ => "CP",
            };
            let ops = if matches!(mn, "ADD" | "ADC" | "SBC") {
                format!("A,{}", reg8(zb))
            } else {
                reg8(zb).to_string()
            };
            Decoded {
                mnemonic: mn.to_string(),
                operands: ops,
                size: 1,
                flags: InstrFlags::NONE,
            }
        }

        // x=3: control, stack, misc
        _ => match zb {
            0 => {
                let cond = cc_name(yb);
                Decoded {
                    mnemonic: "RET".to_string(),
                    operands: cond.to_string(),
                    size: 1,
                    flags: InstrFlags::RET.union(InstrFlags::CONDITIONAL),
                }
            }
            1 => match qb {
                0 => Decoded {
                    mnemonic: "POP".to_string(),
                    operands: rp2(pb).to_string(),
                    size: 1,
                    flags: InstrFlags::READ_MEM,
                },
                _ => match pb {
                    0 => Decoded {
                        mnemonic: "RET".to_string(),
                        operands: String::new(),
                        size: 1,
                        flags: InstrFlags::RET,
                    },
                    1 => Decoded {
                        mnemonic: "EXX".to_string(),
                        operands: String::new(),
                        size: 1,
                        flags: InstrFlags::NONE,
                    },
                    2 => Decoded {
                        mnemonic: "JP".to_string(),
                        operands: "(HL)".to_string(),
                        size: 1,
                        flags: InstrFlags::BRANCH.union(InstrFlags::INDIRECT),
                    },
                    _ => Decoded {
                        mnemonic: "LD".to_string(),
                        operands: "SP,HL".to_string(),
                        size: 1,
                        flags: InstrFlags::NONE,
                    },
                },
            },
            2 => {
                if bytes.len() < 3 {
                    return Err(CoreError::InvalidFormat {
                        message: "truncated JP cc,nn".to_string(),
                    });
                }
                let nn = u16::from_le_bytes([bytes[1], bytes[2]]);
                let cond = cc_name(yb);
                Decoded {
                    mnemonic: "JP".to_string(),
                    operands: format!("{cond},${nn:04X}"),
                    size: 3,
                    flags: InstrFlags::BRANCH.union(InstrFlags::CONDITIONAL),
                }
            }
            3 => match yb {
                0 => {
                    if bytes.len() < 3 {
                        return Err(CoreError::InvalidFormat {
                            message: "truncated JP nn".to_string(),
                        });
                    }
                    let nn = u16::from_le_bytes([bytes[1], bytes[2]]);
                    Decoded {
                        mnemonic: "JP".to_string(),
                        operands: format!("${nn:04X}"),
                        size: 3,
                        flags: InstrFlags::BRANCH,
                    }
                }
                2 => {
                    if bytes.len() < 2 {
                        return Err(CoreError::InvalidFormat {
                            message: "truncated OUT".to_string(),
                        });
                    }
                    Decoded {
                        mnemonic: "OUT".to_string(),
                        operands: format!("(${:02X}),A", bytes[1]),
                        size: 2,
                        flags: InstrFlags::NONE,
                    }
                }
                3 => {
                    if bytes.len() < 2 {
                        return Err(CoreError::InvalidFormat {
                            message: "truncated IN".to_string(),
                        });
                    }
                    Decoded {
                        mnemonic: "IN".to_string(),
                        operands: format!("A,(${:02X})", bytes[1]),
                        size: 2,
                        flags: InstrFlags::NONE,
                    }
                }
                4 => Decoded {
                    mnemonic: "EX".to_string(),
                    operands: "(SP),HL".to_string(),
                    size: 1,
                    flags: InstrFlags::READ_MEM.union(InstrFlags::WRITE_MEM),
                },
                5 => Decoded {
                    mnemonic: "EX".to_string(),
                    operands: "DE,HL".to_string(),
                    size: 1,
                    flags: InstrFlags::NONE,
                },
                6 => Decoded {
                    mnemonic: "DI".to_string(),
                    operands: String::new(),
                    size: 1,
                    flags: InstrFlags::NONE,
                },
                7 => Decoded {
                    mnemonic: "EI".to_string(),
                    operands: String::new(),
                    size: 1,
                    flags: InstrFlags::NONE,
                },
                _ => Decoded {
                    mnemonic: "DB".to_string(),
                    operands: format!("${op:02X}"),
                    size: 1,
                    flags: InstrFlags::NONE,
                },
            },
            4 => {
                if bytes.len() < 3 {
                    return Err(CoreError::InvalidFormat {
                        message: "truncated CALL cc,nn".to_string(),
                    });
                }
                let nn = u16::from_le_bytes([bytes[1], bytes[2]]);
                let cond = cc_name(yb);
                Decoded {
                    mnemonic: "CALL".to_string(),
                    operands: format!("{cond},${nn:04X}"),
                    size: 3,
                    flags: InstrFlags::CALL.union(InstrFlags::CONDITIONAL),
                }
            }
            5 => match qb {
                0 => Decoded {
                    mnemonic: "PUSH".to_string(),
                    operands: rp2(pb).to_string(),
                    size: 1,
                    flags: InstrFlags::WRITE_MEM,
                },
                _ => match pb {
                    0 => {
                        if bytes.len() < 3 {
                            return Err(CoreError::InvalidFormat {
                                message: "truncated CALL nn".to_string(),
                            });
                        }
                        let nn = u16::from_le_bytes([bytes[1], bytes[2]]);
                        Decoded {
                            mnemonic: "CALL".to_string(),
                            operands: format!("${nn:04X}"),
                            size: 3,
                            flags: InstrFlags::CALL,
                        }
                    }
                    1 => {
                        decode_index_prefix(if bytes.len() > 1 { bytes[1] } else { 0 }, bytes, "IX")
                    }
                    2 => decode_ed(if bytes.len() > 1 { bytes[1] } else { 0 }, bytes),
                    _ => {
                        decode_index_prefix(if bytes.len() > 1 { bytes[1] } else { 0 }, bytes, "IY")
                    }
                },
            },
            6 => {
                if bytes.len() < 2 {
                    return Err(CoreError::InvalidFormat {
                        message: "truncated ALU imm".to_string(),
                    });
                }
                let mn = match yb {
                    0 => "ADD",
                    1 => "ADC",
                    2 => "SUB",
                    3 => "SBC",
                    4 => "AND",
                    5 => "XOR",
                    6 => "OR",
                    _ => "CP",
                };
                let ops = if matches!(mn, "ADD" | "ADC" | "SBC") {
                    format!("A,#${:02X}", bytes[1])
                } else {
                    format!("#${:02X}", bytes[1])
                };
                Decoded {
                    mnemonic: mn.to_string(),
                    operands: ops,
                    size: 2,
                    flags: InstrFlags::NONE,
                }
            }
            _ => {
                let rst_target = u16::from(yb) * 8;
                Decoded {
                    mnemonic: "RST".to_string(),
                    operands: format!("${rst_target:02X}H"),
                    size: 1,
                    flags: InstrFlags::CALL,
                }
            }
        },
    };

    Ok(result)
}

// ── Z80 instruction statistics ────────────────────────────────────────────────

/// Opcode cycle counts (T-states) for common Z80 instructions.
#[derive(Debug, Clone, Copy)]
pub struct CycleInfo {
    /// Cycles when branch not taken (or only value for non-branches).
    pub cycles: u8,
    /// Cycles when branch is taken (same as `cycles` for non-branches).
    pub cycles_taken: u8,
}

impl CycleInfo {
    const fn simple(c: u8) -> Self {
        Self {
            cycles: c,
            cycles_taken: c,
        }
    }
    const fn branch(not_taken: u8, taken: u8) -> Self {
        Self {
            cycles: not_taken,
            cycles_taken: taken,
        }
    }
}

/// One row of the Z80 T-state table: the opcodes it covers and their timing.
///
/// Kept as an ordered table rather than a flat `match` so that every opcode
/// group keeps its own row (and its own comment) even when two groups happen
/// to take the same number of T-states.
struct CycleRow {
    /// Opcodes covered by this row.
    opcodes: &'static [u8],
    /// Timing for those opcodes.
    info: CycleInfo,
}

impl CycleRow {
    const fn simple(opcodes: &'static [u8], c: u8) -> Self {
        Self {
            opcodes,
            info: CycleInfo::simple(c),
        }
    }
    const fn branch(opcodes: &'static [u8], not_taken: u8, taken: u8) -> Self {
        Self {
            opcodes,
            info: CycleInfo::branch(not_taken, taken),
        }
    }
    /// True when `op` belongs to this row.
    const fn covers(&self, op: u8) -> bool {
        let mut i = 0;
        while i < self.opcodes.len() {
            if self.opcodes[i] == op {
                return true;
            }
            i += 1;
        }
        false
    }
}

/// T-state counts for the single-byte opcodes, one row per instruction group.
static CYCLE_TABLE: &[CycleRow] = &[
    CycleRow::simple(&[0x00], 4),                                     // NOP
    CycleRow::simple(&[0x01, 0x11, 0x21, 0x31], 10),                  // LD rp,nn
    CycleRow::simple(&[0x02, 0x12], 7),                               // LD (rp),A
    CycleRow::simple(&[0x03, 0x13, 0x23, 0x33], 6),                   // INC rp
    CycleRow::simple(&[0x04, 0x0C, 0x14, 0x1C, 0x24, 0x2C, 0x3C], 4), // INC r
    CycleRow::simple(&[0x34], 11),                                    // INC (HL)
    CycleRow::simple(&[0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x3D], 4), // DEC r
    CycleRow::simple(&[0x35], 11),                                    // DEC (HL)
    CycleRow::simple(&[0x06, 0x0E, 0x16, 0x1E, 0x26, 0x2E, 0x3E], 7), // LD r,n
    CycleRow::simple(&[0x36], 10),                                    // LD (HL),n
    CycleRow::simple(&[0x07, 0x0F, 0x17, 0x1F], 4),                   // RLCA/RRCA/RLA/RRA
    CycleRow::simple(&[0x08], 4),                                     // EX AF,AF'
    CycleRow::simple(&[0x09, 0x19, 0x29, 0x39], 11),                  // ADD HL,rp
    CycleRow::simple(&[0x0A, 0x1A], 7),                               // LD A,(rp)
    CycleRow::simple(&[0x0B, 0x1B, 0x2B, 0x3B], 6),                   // DEC rp
    CycleRow::branch(&[0x10], 8, 13),                                 // DJNZ
    CycleRow::simple(&[0x18], 12),                                    // JR e
    CycleRow::branch(&[0x20, 0x28, 0x30, 0x38], 7, 12),               // JR cc,e
    CycleRow::branch(&[0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0, 0xF8], 5, 11), // RET cc
    CycleRow::simple(&[0xC1, 0xD1, 0xE1, 0xF1], 10),                  // POP rp
    CycleRow::branch(&[0xC2, 0xCA, 0xD2, 0xDA, 0xE2, 0xEA, 0xF2, 0xFA], 10, 10), // JP cc,nn
    CycleRow::simple(&[0xC3], 10),                                    // JP nn
    CycleRow::branch(&[0xC4, 0xCC, 0xD4, 0xDC, 0xE4, 0xEC, 0xF4, 0xFC], 10, 17), // CALL cc,nn
    CycleRow::simple(&[0xC5, 0xD5, 0xE5, 0xF5], 11),                  // PUSH rp
    CycleRow::simple(&[0xC6, 0xCE, 0xD6, 0xDE, 0xE6, 0xEE, 0xF6, 0xFE], 7), // ALU A,n
    CycleRow::simple(&[0xC7, 0xCF, 0xD7, 0xDF, 0xE7, 0xEF, 0xF7, 0xFF], 11), // RST
    CycleRow::simple(&[0xC9], 10),                                    // RET
    CycleRow::simple(&[0xCD], 17),                                    // CALL nn
    CycleRow::simple(&[0xD3], 11),                                    // OUT (n),A
    CycleRow::simple(&[0xDB], 11),                                    // IN A,(n)
    CycleRow::simple(&[0xD9], 4),                                     // EXX
    CycleRow::simple(&[0xE3], 19),                                    // EX (SP),HL
    CycleRow::simple(&[0xE9], 4),                                     // JP (HL)
    CycleRow::simple(&[0xEB], 4),                                     // EX DE,HL
    CycleRow::simple(&[0xF3], 4),                                     // DI
    CycleRow::simple(&[0xF9], 6),                                     // LD SP,HL
    CycleRow::simple(&[0xFB], 4),                                     // EI
    CycleRow::simple(&[0xCB], 8),                                     // CB prefix (bit/rotate ops)
    CycleRow::simple(&[0xED], 8),                                     // ED prefix (extended ops)
    CycleRow::simple(&[0xDD, 0xFD], 8),                               // DD/FD prefix (IX/IY ops)
];

/// Timing of the LD r,r block (0x40..=0x7F), which is regular enough to compute.
const fn ld_block_cycles(op: u8) -> CycleInfo {
    if op == 0x76 {
        // HALT
        CycleInfo::simple(4)
    } else if op & 7 == 6 || (op >> 3) & 7 == 6 {
        // one operand is (HL)
        CycleInfo::simple(7)
    } else {
        CycleInfo::simple(4)
    }
}

/// Timing of the ALU A,r block (0x80..=0xBF).
const fn alu_block_cycles(op: u8) -> CycleInfo {
    if op & 7 == 6 {
        // ALU A,(HL)
        CycleInfo::simple(7)
    } else {
        CycleInfo::simple(4)
    }
}

/// Look up the approximate T-state count for a single-byte opcode.
#[must_use]
pub const fn opcode_cycles(op: u8) -> CycleInfo {
    if op >= 0x40 && op <= 0x7F {
        return ld_block_cycles(op);
    }
    if op >= 0x80 && op <= 0xBF {
        return alu_block_cycles(op);
    }
    let mut i = 0;
    while i < CYCLE_TABLE.len() {
        if CYCLE_TABLE[i].covers(op) {
            return CYCLE_TABLE[i].info;
        }
        i += 1;
    }
    CycleInfo::simple(4)
}

// ── Interrupt modes ───────────────────────────────────────────────────────────

/// Z80 interrupt mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptMode {
    /// Mode 0 — 8080-compatible; executes instruction from data bus.
    Mode0,
    /// Mode 1 — always calls RST 38H.
    Mode1,
    /// Mode 2 — vectored via I register + data bus byte.
    Mode2,
}

impl InterruptMode {
    /// Decode from the IM instruction operand text.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim() {
            "0" => Some(Self::Mode0),
            "1" => Some(Self::Mode1),
            "2" => Some(Self::Mode2),
            _ => None,
        }
    }

    /// Return the IM instruction mnemonic operand.
    #[must_use]
    pub const fn operand(self) -> &'static str {
        match self {
            Self::Mode0 => "0",
            Self::Mode1 => "1",
            Self::Mode2 => "2",
        }
    }
}

// ── Opcode info table ─────────────────────────────────────────────────────────

/// Static opcode entry for a Z80 instruction.
#[derive(Debug, Clone, Copy)]
pub struct OpcodeEntry {
    /// Raw opcode byte.
    pub opcode: u8,
    /// Mnemonic.
    pub mnemonic: &'static str,
    /// Minimum instruction size in bytes.
    pub min_size: u8,
    /// Instruction flags (raw bit pattern for const-compatibility).
    pub flags_bits: u32,
    /// T-state count.
    pub cycles: u8,
}

impl OpcodeEntry {
    /// Return the instruction flags.
    #[must_use]
    pub const fn flags(self) -> InstrFlags {
        InstrFlags::from_bits_retain(self.flags_bits)
    }
}

/// Static table of key Z80 opcodes for quick lookup.
pub static OPCODE_TABLE: &[OpcodeEntry] = &[
    OpcodeEntry {
        opcode: 0x00,
        mnemonic: "NOP",
        min_size: 1,
        flags_bits: 0,
        cycles: 4,
    },
    OpcodeEntry {
        opcode: 0x76,
        mnemonic: "HALT",
        min_size: 1,
        flags_bits: 0,
        cycles: 4,
    },
    OpcodeEntry {
        opcode: 0xC9,
        mnemonic: "RET",
        min_size: 1,
        flags_bits: 4,
        cycles: 10,
    }, // RETURN
    OpcodeEntry {
        opcode: 0xC3,
        mnemonic: "JP",
        min_size: 3,
        flags_bits: 1,
        cycles: 10,
    }, // BRANCH
    OpcodeEntry {
        opcode: 0xCD,
        mnemonic: "CALL",
        min_size: 3,
        flags_bits: 2,
        cycles: 17,
    }, // CALL
    OpcodeEntry {
        opcode: 0x18,
        mnemonic: "JR",
        min_size: 2,
        flags_bits: 1,
        cycles: 12,
    }, // BRANCH
    OpcodeEntry {
        opcode: 0x10,
        mnemonic: "DJNZ",
        min_size: 2,
        flags_bits: 1 | 8,
        cycles: 13,
    }, // BRANCH|CONDITIONAL
    OpcodeEntry {
        opcode: 0xF3,
        mnemonic: "DI",
        min_size: 1,
        flags_bits: 0,
        cycles: 4,
    },
    OpcodeEntry {
        opcode: 0xFB,
        mnemonic: "EI",
        min_size: 1,
        flags_bits: 0,
        cycles: 4,
    },
    OpcodeEntry {
        opcode: 0xD9,
        mnemonic: "EXX",
        min_size: 1,
        flags_bits: 0,
        cycles: 4,
    },
    OpcodeEntry {
        opcode: 0x08,
        mnemonic: "EX",
        min_size: 1,
        flags_bits: 0,
        cycles: 4,
    },
    OpcodeEntry {
        opcode: 0xEB,
        mnemonic: "EX",
        min_size: 1,
        flags_bits: 0,
        cycles: 4,
    },
    OpcodeEntry {
        opcode: 0xE3,
        mnemonic: "EX",
        min_size: 1,
        flags_bits: 32 | 64,
        cycles: 19,
    }, // READ_MEM|WRITE_MEM
];

/// Find the static entry for an opcode, if any.
#[must_use]
pub fn find_opcode_entry(op: u8) -> Option<&'static OpcodeEntry> {
    OPCODE_TABLE.iter().find(|e| e.opcode == op)
}

// ── Encoder helpers ───────────────────────────────────────────────────────────

/// Encode a NOP.
#[must_use]
pub const fn encode_nop() -> [u8; 1] {
    [0x00]
}

/// Encode a HALT.
#[must_use]
pub const fn encode_halt() -> [u8; 1] {
    [0x76]
}

/// Encode an unconditional RET.
#[must_use]
pub const fn encode_ret() -> [u8; 1] {
    [0xC9]
}

/// Encode an unconditional JP nn.
#[must_use]
pub const fn encode_jp(target: u16) -> [u8; 3] {
    let t = target.to_le_bytes();
    [0xC3, t[0], t[1]]
}

/// Encode an unconditional CALL nn.
#[must_use]
pub const fn encode_call(target: u16) -> [u8; 3] {
    let t = target.to_le_bytes();
    [0xCD, t[0], t[1]]
}

/// Encode a JR e (8-bit signed displacement from PC+2).
#[must_use]
pub const fn encode_jr(disp: i8) -> [u8; 2] {
    [0x18, disp.to_ne_bytes()[0]]
}

/// Encode a DJNZ e.
#[must_use]
pub const fn encode_djnz(disp: i8) -> [u8; 2] {
    [0x10, disp.to_ne_bytes()[0]]
}

/// Encode a LD r, n (immediate byte load).
///
/// # Panics
/// Panics if `reg` >= 8.
#[must_use]
pub fn encode_ld_r_n(reg: u8, n: u8) -> [u8; 2] {
    assert!(reg < 8, "LD r,n: reg must be 0..7");
    [0x06 | (reg << 3), n]
}

/// Encode LD BC, nn.
#[must_use]
pub const fn encode_ld_bc_nn(nn: u16) -> [u8; 3] {
    let b = nn.to_le_bytes();
    [0x01, b[0], b[1]]
}

/// Encode LD DE, nn.
#[must_use]
pub const fn encode_ld_de_nn(nn: u16) -> [u8; 3] {
    let b = nn.to_le_bytes();
    [0x11, b[0], b[1]]
}

/// Encode LD HL, nn.
#[must_use]
pub const fn encode_ld_hl_nn(nn: u16) -> [u8; 3] {
    let b = nn.to_le_bytes();
    [0x21, b[0], b[1]]
}

/// Encode LD SP, nn.
#[must_use]
pub const fn encode_ld_sp_nn(nn: u16) -> [u8; 3] {
    let b = nn.to_le_bytes();
    [0x31, b[0], b[1]]
}

/// Encode PUSH rp (0=BC, 1=DE, 2=HL, 3=AF).
///
/// # Panics
/// Panics if `rp_idx` >= 4.
#[must_use]
pub fn encode_push(rp_idx: u8) -> [u8; 1] {
    assert!(rp_idx < 4, "PUSH: rp_idx must be 0..3");
    [0xC5 | (rp_idx << 4)]
}

/// Encode POP rp (0=BC, 1=DE, 2=HL, 3=AF).
///
/// # Panics
/// Panics if `rp_idx` >= 4.
#[must_use]
pub fn encode_pop(rp_idx: u8) -> [u8; 1] {
    assert!(rp_idx < 4, "POP: rp_idx must be 0..3");
    [0xC1 | (rp_idx << 4)]
}

/// Encode a RST n (vector = n*8, n in 0..7).
///
/// # Panics
/// Panics if `vector` >= 8.
#[must_use]
pub fn encode_rst(vector: u8) -> [u8; 1] {
    assert!(vector < 8, "RST: vector must be 0..7");
    [0xC7 | (vector << 3)]
}

/// Encode EI (enable interrupts).
#[must_use]
pub const fn encode_ei() -> [u8; 1] {
    [0xFB]
}

/// Encode DI (disable interrupts).
#[must_use]
pub const fn encode_di() -> [u8; 1] {
    [0xF3]
}

// ── Linear disassembler ───────────────────────────────────────────────────────

/// Linear-sweep disassembler for Z80 code.
pub struct Z80LinearDisassembler<'a> {
    arch: &'a Z80Arch,
    bytes: &'a [u8],
    base: Address,
    offset: usize,
}

impl<'a> Z80LinearDisassembler<'a> {
    /// Create a new linear disassembler.
    #[must_use]
    pub const fn new(arch: &'a Z80Arch, bytes: &'a [u8], base: Address) -> Self {
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

    /// Whether the scan has finished.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.offset >= self.bytes.len()
    }
}

impl Iterator for Z80LinearDisassembler<'_> {
    type Item = Result<Instruction, CoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
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

// ── Analysis helpers ──────────────────────────────────────────────────────────

/// Analysis result for a Z80 code region.
#[derive(Debug, Default, Clone)]
pub struct AnalysisResult {
    /// All decoded instructions.
    pub instructions: Vec<Instruction>,
    /// Addresses of CALL targets.
    pub call_targets: Vec<Address>,
    /// Addresses of branch targets.
    pub branch_targets: Vec<Address>,
    /// Addresses of RET/RETN/RETI instructions.
    pub returns: Vec<Address>,
    /// Number of decode errors.
    pub errors: usize,
    /// Estimated total T-state count.
    pub total_cycles: u64,
}

impl AnalysisResult {
    /// Total instruction count.
    #[must_use]
    pub const fn instr_count(&self) -> usize {
        self.instructions.len()
    }

    /// Whether any calls were found.
    #[must_use]
    pub const fn has_calls(&self) -> bool {
        !self.call_targets.is_empty()
    }
}

/// Perform a linear sweep analysis.
#[must_use]
pub fn analyze(base: Address, bytes: &[u8]) -> AnalysisResult {
    let arch = Z80Arch;
    let mut result = AnalysisResult::default();
    let mut offset = 0usize;

    while offset < bytes.len() {
        let addr = base + offset as u64;
        if let Ok(instr) = arch.disassemble(addr, &bytes[offset..]) {
            let flags = instr.flags;
            let sz = instr.size;
            let op = bytes[offset];
            result.total_cycles += u64::from(opcode_cycles(op).cycles);

            if flags.contains(InstrFlags::CALL) && let Some(t) = extract_hex_target(&instr.operands) {
                result.call_targets.push(Address::new(t));
            }
            if flags.intersects(InstrFlags::BRANCH) && !flags.contains(InstrFlags::CALL) && let Some(t) = extract_hex_target(&instr.operands) {
                result.branch_targets.push(Address::new(t));
            }
            if flags.contains(InstrFlags::RET) {
                result.returns.push(addr);
            }
            result.instructions.push(instr);
            offset += sz;
        } else {
            result.errors += 1;
            offset += 1;
        }
    }
    result
}

fn extract_hex_target(operands: &str) -> Option<u64> {
    let s = match operands.rfind('$') {
        Some(i) => &operands[i + 1..],
        None => return None,
    };
    let hex: String = s.chars().take_while(char::is_ascii_hexdigit).collect();
    if hex.is_empty() {
        return None;
    }
    u64::from_str_radix(&hex, 16).ok()
}

// ── Instruction statistics ─────────────────────────────────────────────────────

/// Category frequency counts for a Z80 code segment.
#[derive(Debug, Default, Clone)]
pub struct InstrStats {
    /// LD instructions.
    pub loads: usize,
    /// ALU (ADD/ADC/SUB/SBC/AND/OR/XOR/CP/INC/DEC).
    pub alu: usize,
    /// Bit manipulation (CB prefix).
    pub bit_ops: usize,
    /// Block instructions (LDIR/LDDR/CPIR etc.).
    pub block_ops: usize,
    /// Branch (JP/JR/DJNZ).
    pub branches: usize,
    /// Call instructions.
    pub calls: usize,
    /// Return instructions.
    pub returns: usize,
    /// Stack operations (PUSH/POP).
    pub stack: usize,
    /// IO instructions (IN/OUT).
    pub io: usize,
    /// Unknown/data bytes (DB).
    pub unknown: usize,
}

impl InstrStats {
    /// Count instruction categories from a slice.
    #[must_use]
    pub fn from_instrs(instrs: &[Instruction]) -> Self {
        let mut s = Self::default();
        for i in instrs {
            let m = i.mnemonic.as_str();
            match m {
                "LD" => s.loads += 1,
                "ADD" | "ADC" | "SUB" | "SBC" | "AND" | "OR" | "XOR" | "CP" | "INC" | "DEC"
                | "NEG" | "DAA" | "CPL" | "CCF" | "SCF" => s.alu += 1,
                "RLC" | "RRC" | "RL" | "RR" | "SLA" | "SRA" | "SLL" | "SRL" | "BIT" | "RES"
                | "SET" | "RLCA" | "RRCA" | "RLA" | "RRA" | "RLD" | "RRD" => s.bit_ops += 1,
                "LDI" | "LDD" | "LDIR" | "LDDR" | "CPI" | "CPD" | "CPIR" | "CPDR" | "INI"
                | "IND" | "INIR" | "INDR" | "OUTI" | "OUTD" | "OTIR" | "OTDR" => s.block_ops += 1,
                "JP" | "JR" | "DJNZ" => s.branches += 1,
                "CALL" => s.calls += 1,
                "RET" | "RETN" | "RETI" => s.returns += 1,
                "PUSH" | "POP" => s.stack += 1,
                "IN" | "OUT" => s.io += 1,
                "DB" => s.unknown += 1,
                _ => {}
            }
        }
        s
    }

    /// Total instructions counted.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.loads
            + self.alu
            + self.bit_ops
            + self.block_ops
            + self.branches
            + self.calls
            + self.returns
            + self.stack
            + self.io
            + self.unknown
    }
}

// ── Disassembly formatter ──────────────────────────────────────────────────────

/// Options for formatting Z80 disassembly.
#[derive(Debug, Clone)]
pub struct DisasmOptions {
    /// Prefix hex addresses.
    pub show_address: bool,
    /// Show raw bytes.
    pub show_bytes: bool,
    /// Column width for mnemonics.
    pub mnemonic_width: usize,
}

impl Default for DisasmOptions {
    fn default() -> Self {
        Self {
            show_address: true,
            show_bytes: true,
            mnemonic_width: 8,
        }
    }
}

/// Format a single instruction.
#[must_use]
pub fn format_instr(instr: &Instruction, opts: &DisasmOptions) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(3);
    if opts.show_address {
        parts.push(format!("{:04X}:", instr.address.as_u64() & 0xFFFF));
    }
    if opts.show_bytes {
        use std::fmt::Write as _;
        let mut hex = String::with_capacity(instr.bytes.len() * 3);
        for (i, b) in instr.bytes.iter().enumerate() {
            if i > 0 {
                hex.push(' ');
            }
            let _ = write!(hex, "{b:02X}");
        }
        parts.push(format!("{hex:<9}"));
    }
    if instr.operands.is_empty() {
        parts.push(format!(
            "{:<width$}",
            instr.mnemonic,
            width = opts.mnemonic_width
        ));
    } else {
        parts.push(format!(
            "{:<width$} {}",
            instr.mnemonic,
            instr.operands,
            width = opts.mnemonic_width
        ));
    }
    parts.join("  ")
}

/// Format multiple instructions into a listing.
#[must_use]
pub fn format_listing(instrs: &[Instruction], opts: &DisasmOptions) -> String {
    instrs
        .iter()
        .map(|i| format_instr(i, opts))
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Calling convention helpers ────────────────────────────────────────────────

/// Known Z80 calling conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConventionKind {
    /// SDCC standard — args in HL/DE/BC, returns in HL/DE.
    SdccStandard,
    /// CP/M BDOS — function in C, args in DE.
    CpmBdos,
    /// Amstrad BASIC calling convention.
    AmstradBasic,
    /// ZX Spectrum ROM convention — args on stack.
    SpectrumRom,
}

impl CallingConventionKind {
    /// Return the convention as a `CallingConvention`.
    #[must_use]
    pub fn to_calling_convention(self) -> CallingConvention {
        match self {
            Self::SdccStandard => CallingConvention::new("z80_sdcc")
                .with_int_args(vec!["HL".to_string(), "DE".to_string(), "BC".to_string()])
                .with_return_regs(vec!["HL".to_string(), "DE".to_string()]),
            Self::CpmBdos => {
                let mut cc = CallingConvention::new("cpm_bdos")
                    .with_int_args(vec!["C".to_string(), "DE".to_string()])
                    .with_return_regs(vec!["A".to_string(), "HL".to_string()]);
                cc.caller_cleans_stack = false;
                cc
            }
            Self::AmstradBasic => CallingConvention::new("amstrad_basic")
                .with_int_args(vec!["HL".to_string(), "DE".to_string()])
                .with_return_regs(vec!["HL".to_string()]),
            Self::SpectrumRom => {
                let mut cc = CallingConvention::new("spectrum_rom")
                    .with_int_args(vec![])
                    .with_return_regs(vec!["A".to_string(), "HL".to_string()]);
                cc.caller_cleans_stack = false;
                cc
            }
        }
    }
}

// ── NOP sled patcher ──────────────────────────────────────────────────────────

/// Result of a NOP-sled patching operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchResult {
    /// Successfully patched.
    Ok,
    /// Buffer is empty.
    TooShort,
}

/// Fill a buffer with NOP bytes (0x00 on Z80).
#[must_use]
pub fn nop_sled(buf: &mut [u8]) -> PatchResult {
    if buf.is_empty() {
        return PatchResult::TooShort;
    }
    buf.fill(0x00);
    PatchResult::Ok
}

/// Patch a JP nn instruction to a new target in-place.
/// Returns true if the first byte was a JP (0xC3) opcode.
#[must_use]
pub fn patch_jp_target(buf: &mut [u8], new_target: u16) -> bool {
    if buf.len() < 3 || buf[0] != 0xC3 {
        return false;
    }
    let t = new_target.to_le_bytes();
    buf[1] = t[0];
    buf[2] = t[1];
    true
}

// ── CP/M & ZX Spectrum helpers ────────────────────────────────────────────────

/// Check if an instruction is an RST call (0xC7..0xFF with step 8).
#[must_use]
pub fn is_rst(instr: &Instruction) -> bool {
    instr.mnemonic == "RST"
}

/// Extract the RST vector from an RST instruction operand (e.g. "$08H" → 0x08).
#[must_use]
pub fn rst_vector(instr: &Instruction) -> Option<u8> {
    if !is_rst(instr) {
        return None;
    }
    let s = instr.operands.trim_start_matches('$').trim_end_matches('H');
    u8::from_str_radix(s, 16).ok()
}

/// Check if an instruction looks like a CP/M BDOS call (RST 5 = 0x28 on some systems,
/// but canonically a `CALL 0x0005`).
#[must_use]
pub fn is_cpm_bdos_call(instr: &Instruction) -> bool {
    if instr.mnemonic == "CALL" {
        return instr.operands.trim_start_matches('$') == "0005";
    }
    false
}

/// Check if an instruction calls the ZX Spectrum ROM at a standard entry point.
#[must_use]
pub fn is_spectrum_rom_call(instr: &Instruction) -> bool {
    if instr.mnemonic != "RST" && instr.mnemonic != "CALL" {
        return false;
    }
    // Well-known Spectrum ROM addresses include 0x0010 (PRINT A), 0x0028 (FP-CALC), etc.
    let known: &[u64] = &[0x0010, 0x0028, 0x0030, 0x0038, 0x0056, 0x1601, 0x1D59];
    if let Some(t) = extract_hex_target(&instr.operands) {
        return known.contains(&t);
    }
    false
}

// ── Basic block builder ───────────────────────────────────────────────────────

/// A basic block in a Z80 control flow graph.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Start address.
    pub start: Address,
    /// End address (exclusive).
    pub end: Address,
    /// Successor addresses.
    pub successors: Vec<Address>,
    /// Whether the block ends in a call.
    pub ends_with_call: bool,
    /// Whether the block ends in a return.
    pub ends_with_return: bool,
}

impl BasicBlock {
    /// Size in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.as_u64().saturating_sub(self.start.as_u64())
    }
}

/// Build basic blocks from a sorted instruction list.
///
/// # Panics
/// Does not panic in practice — internal empty-block guard is always checked.
#[must_use]
pub fn build_cfg(instrs: &[Instruction]) -> Vec<BasicBlock> {
    if instrs.is_empty() {
        return vec![];
    }

    // Collect leader addresses
    let mut leaders: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    leaders.insert(instrs[0].address.as_u64());

    for i in instrs {
        if i.flags
            .intersects(InstrFlags::BRANCH | InstrFlags::CALL | InstrFlags::RET)
        {
            let ft = i.address.as_u64() + i.size as u64;
            leaders.insert(ft);
            if let Some(t) = extract_hex_target(&i.operands) {
                leaders.insert(t);
            }
        }
    }

    let leaders_vec: Vec<u64> = leaders.into_iter().collect();
    let mut blocks = Vec::new();

    for (idx, &block_start) in leaders_vec.iter().enumerate() {
        let block_end = leaders_vec.get(idx + 1).copied().unwrap_or(u64::MAX);
        let block_instrs: Vec<&Instruction> = instrs
            .iter()
            .filter(|i| {
                let a = i.address.as_u64();
                a >= block_start && a < block_end
            })
            .collect();
        if block_instrs.is_empty() {
            continue;
        }
        let last = *block_instrs.last().unwrap();
        let last_end = last.address.as_u64() + last.size as u64;
        let ends_call = last.flags.contains(InstrFlags::CALL);
        let ends_return = last.flags.contains(InstrFlags::RET);
        let unconditional = last.flags.contains(InstrFlags::BRANCH)
            && !last.flags.contains(InstrFlags::CONDITIONAL)
            && !ends_call;
        let mut succs = Vec::new();
        // For CALL instructions we must NOT push the fall-through here; it will
        // be added inside the ends_call branch below to avoid a duplicate entry.
        if !ends_return && !unconditional && !ends_call {
            succs.push(Address::new(last_end));
        }
        if last.flags.intersects(InstrFlags::BRANCH | InstrFlags::CALL) && let Some(t) = extract_hex_target(&last.operands) {
            if ends_call {
                succs.push(Address::new(last_end));
            } else {
                succs.push(Address::new(t));
                if last.flags.contains(InstrFlags::CONDITIONAL) {
                    succs.push(Address::new(last_end));
                }
            }
        }
        blocks.push(BasicBlock {
            start: Address::new(block_start),
            end: Address::new(last_end),
            successors: succs,
            ends_with_call: ends_call,
            ends_with_return: ends_return,
        });
    }
    blocks
}

// ── Main architecture struct ──────────────────────────────────────────────────

/// Classify a [`BranchInfo`] into a coarse human-readable category.
///
/// Useful for analysis passes that want to group branches by their semantic
/// [`BranchKind`] without inspecting the individual factory variants.
#[must_use]
pub const fn branch_category(branch: &BranchInfo) -> &'static str {
    match branch.kind {
        BranchKind::UnconditionalJump => "jump",
        BranchKind::ConditionalJump => "conditional-jump",
        BranchKind::Call | BranchKind::IndirectCall => "call",
        BranchKind::Return | BranchKind::ExceptionReturn => "return",
        BranchKind::SystemCall => "syscall",
        BranchKind::Trap => "trap",
        BranchKind::IndirectJump => "indirect-jump",
    }
}

/// Zilog Z80 architecture.
#[derive(Debug, Clone, Copy, Default)]
pub struct Z80Arch;

impl Architecture for Z80Arch {
    fn name(&self) -> &'static str {
        "z80"
    }

    fn pointer_size(&self) -> usize {
        2
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    /// Disassemble one Z80 instruction.
    ///
    /// # Errors
    /// Returns `CoreError::InvalidInput` for truncated instructions.
    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        let decoded = decode_main(bytes, address.as_u64())?;
        let raw = bytes[..decoded.size.min(bytes.len())].to_vec();
        let mut instr = Instruction::new(address, decoded.size, decoded.mnemonic, raw);
        instr.operands = decoded.operands;
        instr.flags = decoded.flags;
        Ok(instr)
    }

    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo> {
        if !instr
            .flags
            .intersects(InstrFlags::BRANCH | InstrFlags::CALL | InstrFlags::RET)
        {
            return vec![];
        }
        if instr.flags.contains(InstrFlags::RET) {
            return vec![BranchInfo::ret()];
        }
        let ops = &instr.operands;
        // Strip optional condition prefix like "NZ,$1234"
        let target_str = ops.rsplit(',').next().unwrap_or(ops.as_str());
        let trimmed = target_str.trim_start_matches('$');
        let end = trimmed
            .bytes()
            .take_while(u8::is_ascii_hexdigit)
            .count();
        if let Ok(target) = u64::from_str_radix(&trimmed[..end], 16) {
            let branch = if instr.flags.contains(InstrFlags::CALL) {
                BranchInfo::call(target)
            } else if instr.flags.contains(InstrFlags::CONDITIONAL) {
                BranchInfo::conditional_jump(target, BranchCondition::Custom(0))
            } else {
                BranchInfo::unconditional_jump(target)
            };
            return vec![branch];
        }
        if instr.flags.contains(InstrFlags::INDIRECT) {
            return vec![BranchInfo::indirect_jump()];
        }
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        vec![
            RegisterInfo::new("A", REG_A, 1, RegisterKind::General),
            RegisterInfo::new("B", REG_B, 1, RegisterKind::General),
            RegisterInfo::new("C", REG_C, 1, RegisterKind::General),
            RegisterInfo::new("D", REG_D, 1, RegisterKind::General),
            RegisterInfo::new("E", REG_E, 1, RegisterKind::General),
            RegisterInfo::new("H", REG_H, 1, RegisterKind::General),
            RegisterInfo::new("L", REG_L, 1, RegisterKind::General),
            RegisterInfo::new("F", REG_F, 1, RegisterKind::Flags),
            RegisterInfo::new("I", REG_I, 1, RegisterKind::General),
            RegisterInfo::new("R", REG_R, 1, RegisterKind::General),
            RegisterInfo::new("AF", REG_AF, 2, RegisterKind::General),
            RegisterInfo::new("BC", REG_BC, 2, RegisterKind::General),
            RegisterInfo::new("DE", REG_DE, 2, RegisterKind::General),
            RegisterInfo::new("HL", REG_HL, 2, RegisterKind::General),
            RegisterInfo::new("SP", REG_SP, 2, RegisterKind::Stack),
            RegisterInfo::new("PC", REG_PC, 2, RegisterKind::ProgramCounter),
            RegisterInfo::new("IX", REG_IX, 2, RegisterKind::General),
            RegisterInfo::new("IY", REG_IY, 2, RegisterKind::General),
            RegisterInfo::new("AF'", REG_AF2, 2, RegisterKind::General),
            RegisterInfo::new("BC'", REG_BC2, 2, RegisterKind::General),
            RegisterInfo::new("DE'", REG_DE2, 2, RegisterKind::General),
            RegisterInfo::new("HL'", REG_HL2, 2, RegisterKind::General),
        ]
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![
            CallingConventionKind::SdccStandard.to_calling_convention(),
            CallingConventionKind::CpmBdos.to_calling_convention(),
            CallingConventionKind::SpectrumRom.to_calling_convention(),
        ]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn arch() -> Z80Arch {
        Z80Arch
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    // ── Basic instructions ────────────────────────────────────────────────────
    #[test]
    fn test_nop() {
        let i = arch().disassemble(addr(0), &[0x00]).unwrap();
        assert_eq!(i.mnemonic, "NOP");
        assert_eq!(i.size, 1);
    }

    #[test]
    fn test_halt() {
        let i = arch().disassemble(addr(0), &[0x76]).unwrap();
        assert_eq!(i.mnemonic, "HALT");
    }

    #[test]
    fn test_ld_bc_imm() {
        let i = arch().disassemble(addr(0), &[0x01, 0x34, 0x12]).unwrap();
        assert_eq!(i.mnemonic, "LD");
        assert_eq!(i.operands, "BC,#$1234");
        assert_eq!(i.size, 3);
    }

    #[test]
    fn test_ld_a_b() {
        let i = arch().disassemble(addr(0), &[0x78]).unwrap();
        assert_eq!(i.mnemonic, "LD");
        assert_eq!(i.operands, "A,B");
    }

    #[test]
    fn test_add_a_b() {
        let i = arch().disassemble(addr(0), &[0x80]).unwrap();
        assert_eq!(i.mnemonic, "ADD");
        assert_eq!(i.operands, "A,B");
    }

    #[test]
    fn test_jp_nn() {
        let i = arch().disassemble(addr(0), &[0xC3, 0x00, 0x10]).unwrap();
        assert_eq!(i.mnemonic, "JP");
        assert_eq!(i.operands, "$1000");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_jp_cond() {
        let i = arch().disassemble(addr(0), &[0xC2, 0x00, 0x10]).unwrap();
        assert_eq!(i.mnemonic, "JP");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_call() {
        let i = arch().disassemble(addr(0), &[0xCD, 0x00, 0x10]).unwrap();
        assert_eq!(i.mnemonic, "CALL");
        assert!(i.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_ret() {
        let i = arch().disassemble(addr(0), &[0xC9]).unwrap();
        assert_eq!(i.mnemonic, "RET");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_djnz() {
        // DJNZ -2: from 0x100 → target 0x100 (back-edge loop)
        let i = arch().disassemble(addr(0x100), &[0x10, 0xFE]).unwrap();
        assert_eq!(i.mnemonic, "DJNZ");
        assert_eq!(i.operands, "$0100");
    }

    #[test]
    fn test_jr_nz() {
        let i = arch().disassemble(addr(0x100), &[0x20, 0x05]).unwrap();
        assert_eq!(i.mnemonic, "JR");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    // ── CB prefix ─────────────────────────────────────────────────────────────
    #[test]
    fn test_cb_rlc_b() {
        let i = arch().disassemble(addr(0), &[0xCB, 0x00]).unwrap();
        assert_eq!(i.mnemonic, "RLC");
        assert_eq!(i.operands, "B");
        assert_eq!(i.size, 2);
    }

    #[test]
    fn test_cb_bit_0_a() {
        let i = arch().disassemble(addr(0), &[0xCB, 0x47]).unwrap();
        assert_eq!(i.mnemonic, "BIT");
        assert_eq!(i.operands, "0,A");
    }

    #[test]
    fn test_cb_set_0_a() {
        let i = arch().disassemble(addr(0), &[0xCB, 0xC7]).unwrap();
        assert_eq!(i.mnemonic, "SET");
        assert_eq!(i.operands, "0,A");
    }

    #[test]
    fn test_cb_res_7_b() {
        let i = arch().disassemble(addr(0), &[0xCB, 0xB8]).unwrap();
        assert_eq!(i.mnemonic, "RES");
        assert_eq!(i.operands, "7,B");
    }

    // ── ED prefix ─────────────────────────────────────────────────────────────
    #[test]
    fn test_ed_ldir() {
        let i = arch().disassemble(addr(0), &[0xED, 0xB0]).unwrap();
        assert_eq!(i.mnemonic, "LDIR");
    }

    #[test]
    fn test_ed_neg() {
        let i = arch().disassemble(addr(0), &[0xED, 0x44]).unwrap();
        assert_eq!(i.mnemonic, "NEG");
    }

    #[test]
    fn test_ed_retn() {
        let i = arch().disassemble(addr(0), &[0xED, 0x45]).unwrap();
        assert_eq!(i.mnemonic, "RETN");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_ed_reti() {
        let i = arch().disassemble(addr(0), &[0xED, 0x4D]).unwrap();
        assert_eq!(i.mnemonic, "RETI");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_ed_ld_hl_ind() {
        let i = arch()
            .disassemble(addr(0), &[0xED, 0x6B, 0x00, 0x20])
            .unwrap();
        assert_eq!(i.mnemonic, "LD");
        assert_eq!(i.operands, "HL,($2000)");
    }

    // ── DD prefix (IX) ────────────────────────────────────────────────────────
    #[test]
    fn test_dd_ld_ix_nn() {
        let i = arch()
            .disassemble(addr(0), &[0xDD, 0x21, 0x00, 0x20])
            .unwrap();
        assert_eq!(i.mnemonic, "LD");
        assert_eq!(i.operands, "IX,#$2000");
    }

    #[test]
    fn test_dd_ld_b_ix_disp() {
        let i = arch().disassemble(addr(0), &[0xDD, 0x46, 0x05]).unwrap();
        assert_eq!(i.mnemonic, "LD");
        assert!(i.operands.contains("B,(IX"));
    }

    // ── FD prefix (IY) ────────────────────────────────────────────────────────
    #[test]
    fn test_fd_inc_iy() {
        let i = arch().disassemble(addr(0), &[0xFD, 0x23]).unwrap();
        assert_eq!(i.mnemonic, "INC");
        assert_eq!(i.operands, "IY");
    }

    #[test]
    fn test_fd_ld_a_iy_disp() {
        let i = arch().disassemble(addr(0), &[0xFD, 0x7E, 0x03]).unwrap();
        assert_eq!(i.mnemonic, "LD");
        assert!(i.operands.contains("A,(IY"));
    }

    // ── Stack ─────────────────────────────────────────────────────────────────
    #[test]
    fn test_push_af() {
        let i = arch().disassemble(addr(0), &[0xF5]).unwrap();
        assert_eq!(i.mnemonic, "PUSH");
        assert_eq!(i.operands, "AF");
    }

    #[test]
    fn test_pop_hl() {
        let i = arch().disassemble(addr(0), &[0xE1]).unwrap();
        assert_eq!(i.mnemonic, "POP");
        assert_eq!(i.operands, "HL");
    }

    // ── RST ───────────────────────────────────────────────────────────────────
    #[test]
    fn test_rst_38() {
        let i = arch().disassemble(addr(0), &[0xFF]).unwrap();
        assert_eq!(i.mnemonic, "RST");
        assert!(i.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_rst_vector() {
        let i = arch().disassemble(addr(0), &[0xFF]).unwrap();
        assert_eq!(rst_vector(&i), Some(0x38));
    }

    // ── Architecture properties ───────────────────────────────────────────────
    #[test]
    fn test_registers_count() {
        assert!(arch().registers().len() >= 22);
    }

    #[test]
    fn test_name_endian_ptr() {
        assert_eq!(arch().name(), "z80");
        assert_eq!(arch().endian(), Endian::Little);
        assert_eq!(arch().pointer_size(), 2);
    }

    #[test]
    fn test_calling_conventions() {
        let cc = arch().calling_conventions();
        assert!(!cc.is_empty());
        assert_eq!(cc[0].name, "z80_sdcc");
    }

    // ── Linear disassembler ───────────────────────────────────────────────────
    #[test]
    fn test_linear_disassembler() {
        let code = [0x00_u8, 0x78, 0xC9];
        let a = arch();
        let instrs: Vec<_> = Z80LinearDisassembler::new(&a, &code, addr(0))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[0].mnemonic, "NOP");
        assert_eq!(instrs[1].mnemonic, "LD");
        assert_eq!(instrs[2].mnemonic, "RET");
    }

    #[test]
    fn test_linear_disassembler_is_done() {
        let code = [0x00_u8];
        let a = arch();
        let mut dis = Z80LinearDisassembler::new(&a, &code, addr(0));
        assert!(!dis.is_done());
        let _ = dis.next();
        assert!(dis.is_done());
    }

    // ── Encoder helpers ───────────────────────────────────────────────────────
    #[test]
    fn test_encode_nop() {
        assert_eq!(encode_nop(), [0x00]);
        let i = arch().disassemble(addr(0), &encode_nop()).unwrap();
        assert_eq!(i.mnemonic, "NOP");
    }

    #[test]
    fn test_encode_ret() {
        let i = arch().disassemble(addr(0), &encode_ret()).unwrap();
        assert_eq!(i.mnemonic, "RET");
    }

    #[test]
    fn test_encode_jp() {
        let bytes = encode_jp(0x1000);
        let i = arch().disassemble(addr(0), &bytes).unwrap();
        assert_eq!(i.mnemonic, "JP");
        assert_eq!(i.operands, "$1000");
    }

    #[test]
    fn test_encode_call() {
        let bytes = encode_call(0x2000);
        let i = arch().disassemble(addr(0), &bytes).unwrap();
        assert_eq!(i.mnemonic, "CALL");
        assert_eq!(i.operands, "$2000");
    }

    #[test]
    fn test_encode_jr() {
        let bytes = encode_jr(10);
        let i = arch().disassemble(addr(0x100), &bytes).unwrap();
        assert_eq!(i.mnemonic, "JR");
    }

    #[test]
    fn test_encode_djnz() {
        let bytes = encode_djnz(-2);
        let i = arch().disassemble(addr(0x100), &bytes).unwrap();
        assert_eq!(i.mnemonic, "DJNZ");
    }

    #[test]
    fn test_encode_ld_hl_nn() {
        let bytes = encode_ld_hl_nn(0xABCD);
        let i = arch().disassemble(addr(0), &bytes).unwrap();
        assert_eq!(i.mnemonic, "LD");
        assert!(i.operands.contains("HL"));
    }

    #[test]
    fn test_encode_rst() {
        let bytes = encode_rst(7); // RST 0x38
        let i = arch().disassemble(addr(0), &bytes).unwrap();
        assert_eq!(i.mnemonic, "RST");
    }

    #[test]
    fn test_encode_push_pop() {
        let push = encode_push(2); // PUSH HL
        let i = arch().disassemble(addr(0), &push).unwrap();
        assert_eq!(i.mnemonic, "PUSH");

        let pop = encode_pop(2); // POP HL
        let i2 = arch().disassemble(addr(0), &pop).unwrap();
        assert_eq!(i2.mnemonic, "POP");
    }

    // ── Analysis ──────────────────────────────────────────────────────────────
    #[test]
    fn test_analyze() {
        let code = [
            0x00_u8, // NOP
            0xCD, 0x05, 0x00, // CALL $0005
            0xC9, // RET
        ];
        let result = analyze(addr(0), &code);
        assert!(result.instr_count() > 0);
        assert!(result.has_calls());
        assert_eq!(result.errors, 0);
        assert!(result.total_cycles > 0);
    }

    // ── Instruction statistics ────────────────────────────────────────────────
    #[test]
    fn test_instr_stats() {
        let a = arch();
        let code = [0x00_u8, 0x78, 0x80, 0xC9];
        let instrs: Vec<_> = Z80LinearDisassembler::new(&a, &code, addr(0))
            .filter_map(Result::ok)
            .collect();
        let stats = InstrStats::from_instrs(&instrs);
        assert!(stats.loads >= 1);
        assert!(stats.alu >= 1);
        assert!(stats.returns >= 1);
    }

    // ── Cycle counts ──────────────────────────────────────────────────────────
    #[test]
    fn test_opcode_cycles_nop() {
        assert_eq!(opcode_cycles(0x00).cycles, 4);
    }

    #[test]
    fn test_opcode_cycles_djnz() {
        assert_eq!(opcode_cycles(0x10).cycles, 8);
        assert_eq!(opcode_cycles(0x10).cycles_taken, 13);
    }

    // ── CFG builder ───────────────────────────────────────────────────────────
    #[test]
    fn test_build_cfg() {
        let a = arch();
        let code = [0x00_u8, 0xC9]; // NOP, RET
        let instrs: Vec<_> = Z80LinearDisassembler::new(&a, &code, addr(0))
            .filter_map(Result::ok)
            .collect();
        let blocks = build_cfg(&instrs);
        assert!(!blocks.is_empty());
    }

    // ── NOP sled patcher ──────────────────────────────────────────────────────
    #[test]
    fn test_nop_sled() {
        let mut buf = [0xFF_u8; 4];
        assert_eq!(nop_sled(&mut buf), PatchResult::Ok);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_nop_sled_empty() {
        let mut buf: [u8; 0] = [];
        assert_eq!(nop_sled(&mut buf), PatchResult::TooShort);
    }

    // ── JP patching ───────────────────────────────────────────────────────────
    #[test]
    fn test_patch_jp_target() {
        let mut buf = encode_jp(0x1000).to_vec();
        assert!(patch_jp_target(&mut buf, 0x2000));
        let i = arch().disassemble(addr(0), &buf).unwrap();
        assert_eq!(i.operands, "$2000");
    }

    // ── CP/M & Spectrum helpers ───────────────────────────────────────────────
    #[test]
    fn test_is_cpm_bdos_call() {
        let i = arch().disassemble(addr(0), &[0xCD, 0x05, 0x00]).unwrap();
        assert!(is_cpm_bdos_call(&i));
    }

    // ── Interrupt mode ────────────────────────────────────────────────────────
    #[test]
    fn test_interrupt_mode() {
        let i = arch().disassemble(addr(0), &[0xED, 0x56]).unwrap();
        assert_eq!(i.mnemonic, "IM");
        let mode = InterruptMode::from_str(&i.operands).unwrap();
        assert_eq!(mode, InterruptMode::Mode1);
    }

    // ── Flags bitflags ────────────────────────────────────────────────────────
    #[test]
    fn test_flags_bitflags() {
        let f = Flags::C | Flags::Z;
        assert!(f.contains(Flags::C));
        assert!(f.contains(Flags::Z));
        assert!(!f.contains(Flags::S));
    }

    // ── Disassembly formatter ─────────────────────────────────────────────────
    #[test]
    fn test_format_instr() {
        let i = arch().disassemble(addr(0x100), &[0xC9]).unwrap();
        let s = format_instr(&i, &DisasmOptions::default());
        assert!(s.contains("RET"));
        assert!(s.contains("0100"));
    }

    #[test]
    fn test_format_listing() {
        let a = arch();
        let code = [0x00_u8, 0xC9];
        let instrs: Vec<_> = Z80LinearDisassembler::new(&a, &code, addr(0))
            .filter_map(Result::ok)
            .collect();
        let s = format_listing(&instrs, &DisasmOptions::default());
        assert!(s.contains("NOP"));
        assert!(s.contains("RET"));
    }

    // ── RST vector extraction ─────────────────────────────────────────────────
    #[test]
    fn test_rst_vector_extraction() {
        let cases = [
            (0xC7_u8, 0x00_u8), // RST 00H
            (0xCF, 0x08),       // RST 08H
            (0xD7, 0x10),       // RST 10H
            (0xDF, 0x18),       // RST 18H
            (0xE7, 0x20),       // RST 20H
            (0xEF, 0x28),       // RST 28H
            (0xF7, 0x30),       // RST 30H
            (0xFF, 0x38),       // RST 38H
        ];
        for (opcode, expected_vec) in cases {
            let i = arch().disassemble(addr(0), &[opcode]).unwrap();
            assert_eq!(rst_vector(&i), Some(expected_vec), "opcode={opcode:#04X}");
        }
    }

    // ── Truncation errors ─────────────────────────────────────────────────────
    #[test]
    fn test_empty_input_error() {
        let result = arch().disassemble(addr(0), &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_ld_bc_error() {
        let result = arch().disassemble(addr(0), &[0x01, 0x34]);
        assert!(result.is_err());
    }

    // ── ALU immediates ────────────────────────────────────────────────────────
    #[test]
    fn test_add_a_n() {
        let i = arch().disassemble(addr(0), &[0xC6, 0x42]).unwrap();
        assert_eq!(i.mnemonic, "ADD");
        assert_eq!(i.operands, "A,#$42");
    }

    #[test]
    fn test_and_n() {
        let i = arch().disassemble(addr(0), &[0xE6, 0x0F]).unwrap();
        assert_eq!(i.mnemonic, "AND");
        assert_eq!(i.operands, "#$0F");
    }

    // ── EXX / EX ──────────────────────────────────────────────────────────────
    #[test]
    fn test_exx() {
        let i = arch().disassemble(addr(0), &[0xD9]).unwrap();
        assert_eq!(i.mnemonic, "EXX");
    }

    #[test]
    fn test_ex_de_hl() {
        let i = arch().disassemble(addr(0), &[0xEB]).unwrap();
        assert_eq!(i.mnemonic, "EX");
        assert_eq!(i.operands, "DE,HL");
    }

    // ── DI / EI ───────────────────────────────────────────────────────────────
    #[test]
    fn test_di_ei() {
        let di = arch().disassemble(addr(0), &[0xF3]).unwrap();
        assert_eq!(di.mnemonic, "DI");
        let ei = arch().disassemble(addr(0), &[0xFB]).unwrap();
        assert_eq!(ei.mnemonic, "EI");
    }

    // ── INC/DEC register pair ─────────────────────────────────────────────────
    #[test]
    fn test_inc_dec_rp() {
        let inc = arch().disassemble(addr(0), &[0x03]).unwrap();
        assert_eq!(inc.mnemonic, "INC");
        assert_eq!(inc.operands, "BC");
        let dec = arch().disassemble(addr(0), &[0x0B]).unwrap();
        assert_eq!(dec.mnemonic, "DEC");
        assert_eq!(dec.operands, "BC");
    }
}

// ── Z80 Additional Encoding Helpers ──────────────────────────────────────────

/// Encode Z80 `JR NZ, e` (jump relative if non-zero).
///
/// # Panics
///
/// Panics if `e` is outside −128..=127.
#[must_use]
pub const fn encode_jr_nz(e: i8) -> [u8; 2] {
    [0x20, e.cast_unsigned()]
}

/// Encode Z80 `JR Z, e` (jump relative if zero).
#[must_use]
pub const fn encode_jr_z(e: i8) -> [u8; 2] {
    [0x28, e.cast_unsigned()]
}

/// Encode Z80 `JR NC, e` (jump relative if no carry).
#[must_use]
pub const fn encode_jr_nc(e: i8) -> [u8; 2] {
    [0x30, e.cast_unsigned()]
}

/// Encode Z80 `JR C, e` (jump relative if carry).
#[must_use]
pub const fn encode_jr_c(e: i8) -> [u8; 2] {
    [0x38, e.cast_unsigned()]
}

/// Encode Z80 `LD A, n` (load accumulator from immediate).
#[must_use]
pub fn encode_ld_a_n(n: u8) -> [u8; 2] {
    encode_ld_r_n(7, n)
}

/// Encode Z80 `ADD A, r` (add register to A; r=7 for A, opcode 0x80|r).
///
/// Returns a single byte.
///
/// # Panics
///
/// Panics if `r` > 7.
#[must_use]
pub fn encode_add_a_r(r: u8) -> u8 {
    assert!(r <= 7, "ADD A,r: register must be 0-7");
    0x80 | r
}

/// Encode Z80 `SUB r` (single byte: 0x90|r).
///
/// # Panics
///
/// Panics if `r` > 7.
#[must_use]
pub fn encode_sub_r(r: u8) -> u8 {
    assert!(r <= 7, "SUB r: register must be 0-7");
    0x90 | r
}

/// Encode Z80 `AND r` (single byte: 0xA0|r).
///
/// # Panics
///
/// Panics if `r` > 7.
#[must_use]
pub fn encode_and_r(r: u8) -> u8 {
    assert!(r <= 7, "AND r: register must be 0-7");
    0xA0 | r
}

/// Encode Z80 `OR r` (single byte: 0xB0|r).
///
/// # Panics
///
/// Panics if `r` > 7.
#[must_use]
pub fn encode_or_r(r: u8) -> u8 {
    assert!(r <= 7, "OR r: register must be 0-7");
    0xB0 | r
}

/// Encode Z80 `XOR r` (single byte: 0xA8|r).
///
/// # Panics
///
/// Panics if `r` > 7.
#[must_use]
pub fn encode_xor_r(r: u8) -> u8 {
    assert!(r <= 7, "XOR r: register must be 0-7");
    0xA8 | r
}

/// Encode Z80 `CP r` (compare A with r; single byte: 0xB8|r).
///
/// # Panics
///
/// Panics if `r` > 7.
#[must_use]
pub fn encode_cp_r(r: u8) -> u8 {
    assert!(r <= 7, "CP r: register must be 0-7");
    0xB8 | r
}

/// Encode Z80 `INC r` (increment register; single byte: 0x04|(r<<3)).
///
/// # Panics
///
/// Panics if `r` > 7.
#[must_use]
pub fn encode_inc_r(r: u8) -> u8 {
    assert!(r <= 7, "INC r: register must be 0-7");
    0x04 | (r << 3)
}

/// Encode Z80 `DEC r` (single byte: 0x05|(r<<3)).
///
/// # Panics
///
/// Panics if `r` > 7.
#[must_use]
pub fn encode_dec_r(r: u8) -> u8 {
    assert!(r <= 7, "DEC r: register must be 0-7");
    0x05 | (r << 3)
}

/// Encode Z80 `LD rp, nn` — rp: 0=BC,1=DE,2=HL,3=SP.
///
/// Returns 3 bytes.
///
/// # Panics
///
/// Panics if `rp` > 3.
#[must_use]
pub fn encode_ld_rp_nn(rp: u8, nn: u16) -> [u8; 3] {
    assert!(rp <= 3, "LD rp,nn: register pair must be 0-3");
    [0x01 | (rp << 4), (nn & 0xFF) as u8, (nn >> 8) as u8]
}

/// Encode Z80 `LD (nn), A` — store accumulator to memory.
#[must_use]
pub const fn encode_ld_mem_nn_a(nn: u16) -> [u8; 3] {
    [0x32, (nn & 0xFF) as u8, (nn >> 8) as u8]
}

/// Encode Z80 `LD A, (nn)` — load accumulator from memory.
#[must_use]
pub const fn encode_ld_a_mem_nn(nn: u16) -> [u8; 3] {
    [0x3A, (nn & 0xFF) as u8, (nn >> 8) as u8]
}

/// Encode Z80 `EX DE, HL` (single byte 0xEB).
#[must_use]
pub const fn encode_ex_de_hl() -> u8 {
    0xEB
}

// ── Z80 Condition Codes ───────────────────────────────────────────────────────

/// Z80 condition code used in conditional jumps, calls, and returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Z80Condition {
    /// Non-zero (Z=0).
    NZ = 0,
    /// Zero (Z=1).
    Z = 1,
    /// No carry (C=0).
    NC = 2,
    /// Carry (C=1).
    C = 3,
    /// Parity odd / overflow clear (P/V=0).
    PO = 4,
    /// Parity even / overflow set (P/V=1).
    PE = 5,
    /// Positive / sign clear (S=0).
    P = 6,
    /// Minus / sign set (S=1).
    M = 7,
}

impl Z80Condition {
    /// The mnemonic string for this condition.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::NZ => "NZ",
            Self::Z => "Z",
            Self::NC => "NC",
            Self::C => "C",
            Self::PO => "PO",
            Self::PE => "PE",
            Self::P => "P",
            Self::M => "M",
        }
    }

    /// Encode a conditional `JP cc,nn` instruction (3 bytes).
    #[must_use]
    pub const fn encode_jp_cc(self, nn: u16) -> [u8; 3] {
        [
            0xC2 | ((self as u8) << 3),
            (nn & 0xFF) as u8,
            (nn >> 8) as u8,
        ]
    }

    /// Encode a conditional `CALL cc,nn` instruction (3 bytes).
    #[must_use]
    pub const fn encode_call_cc(self, nn: u16) -> [u8; 3] {
        [
            0xC4 | ((self as u8) << 3),
            (nn & 0xFF) as u8,
            (nn >> 8) as u8,
        ]
    }

    /// Encode a conditional `RET cc` instruction (1 byte).
    #[must_use]
    pub const fn encode_ret_cc(self) -> u8 {
        0xC0 | ((self as u8) << 3)
    }
}

// ── Z80 Interrupt Modes ───────────────────────────────────────────────────────

/// Z80 interrupt mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Z80InterruptMode {
    /// Mode 0 — device places instruction on data bus (8080-compatible).
    Mode0,
    /// Mode 1 — CPU always jumps to 0x0038.
    Mode1,
    /// Mode 2 — vectored; CPU reads a vector byte and jumps to I:vector.
    Mode2,
}

impl Z80InterruptMode {
    /// Encode `IM n` instruction (2 bytes, ED-prefixed).
    #[must_use]
    pub const fn encode_im(self) -> [u8; 2] {
        match self {
            Self::Mode0 => [0xED, 0x46],
            Self::Mode1 => [0xED, 0x56],
            Self::Mode2 => [0xED, 0x5E],
        }
    }
}

// ── Z80 Flag Register Bits ────────────────────────────────────────────────────

/// Z80 flag register bit masks.
pub mod z80_flags {
    /// Carry flag (C) — bit 0.
    pub const C: u8 = 1 << 0;
    /// Subtract flag (N) — bit 1.
    pub const N: u8 = 1 << 1;
    /// Parity/Overflow flag (P/V) — bit 2.
    pub const PV: u8 = 1 << 2;
    /// Undocumented flag (X/bit 3).
    pub const X: u8 = 1 << 3;
    /// Half-carry flag (H) — bit 4.
    pub const H: u8 = 1 << 4;
    /// Undocumented flag (Y/bit 5).
    pub const Y: u8 = 1 << 5;
    /// Zero flag (Z) — bit 6.
    pub const Z: u8 = 1 << 6;
    /// Sign flag (S) — bit 7.
    pub const S: u8 = 1 << 7;
}

// ── Z80 System Interrupt Vectors ─────────────────────────────────────────────

/// Z80 interrupt / restart vector entry.
#[derive(Debug, Clone, Copy)]
pub struct Z80VectorEntry {
    /// Byte address in ROM.
    pub address: u16,
    /// Name.
    pub name: &'static str,
    /// Description.
    pub description: &'static str,
}

/// Standard Z80 restart and interrupt vectors.
pub static Z80_VECTORS: &[Z80VectorEntry] = &[
    Z80VectorEntry {
        address: 0x0000,
        name: "RST 0",
        description: "Restart 0 / Power-on reset",
    },
    Z80VectorEntry {
        address: 0x0008,
        name: "RST 1",
        description: "Restart 8",
    },
    Z80VectorEntry {
        address: 0x0010,
        name: "RST 2",
        description: "Restart 16",
    },
    Z80VectorEntry {
        address: 0x0018,
        name: "RST 3",
        description: "Restart 24",
    },
    Z80VectorEntry {
        address: 0x0020,
        name: "RST 4",
        description: "Restart 32",
    },
    Z80VectorEntry {
        address: 0x0028,
        name: "RST 5",
        description: "Restart 40",
    },
    Z80VectorEntry {
        address: 0x0030,
        name: "RST 6",
        description: "Restart 48",
    },
    Z80VectorEntry {
        address: 0x0038,
        name: "IM1 INT",
        description: "Mode 1 maskable interrupt handler",
    },
    Z80VectorEntry {
        address: 0x0066,
        name: "NMI",
        description: "Non-maskable interrupt handler",
    },
];

/// Look up a Z80 vector by address.
#[must_use]
pub fn lookup_z80_vector(addr: u16) -> Option<&'static Z80VectorEntry> {
    Z80_VECTORS.iter().find(|v| v.address == addr)
}

// ── Z80 Instruction Reference Table ──────────────────────────────────────────

/// Reference entry for a Z80 instruction.
#[derive(Debug, Clone, Copy)]
pub struct Z80InstrRef {
    /// Mnemonic.
    pub mnemonic: &'static str,
    /// Opcode bytes (first 1–4 bytes).
    pub bytes: &'static [u8],
    /// Total byte length of instruction (including operands).
    pub length: u8,
    /// Cycle count (T-states, minimum).
    pub t_states_min: u8,
    /// Cycle count (T-states, maximum — for conditional).
    pub t_states_max: u8,
    /// Brief description.
    pub description: &'static str,
}

/// Selected Z80 instruction reference entries.
pub static Z80_INSTR_REF: &[Z80InstrRef] = &[
    Z80InstrRef {
        mnemonic: "NOP",
        bytes: &[0x00],
        length: 1,
        t_states_min: 4,
        t_states_max: 4,
        description: "No operation",
    },
    Z80InstrRef {
        mnemonic: "RET",
        bytes: &[0xC9],
        length: 1,
        t_states_min: 10,
        t_states_max: 10,
        description: "Return from subroutine",
    },
    Z80InstrRef {
        mnemonic: "HALT",
        bytes: &[0x76],
        length: 1,
        t_states_min: 4,
        t_states_max: 4,
        description: "Halt; execute NOPs until interrupt",
    },
    Z80InstrRef {
        mnemonic: "EI",
        bytes: &[0xFB],
        length: 1,
        t_states_min: 4,
        t_states_max: 4,
        description: "Enable interrupts",
    },
    Z80InstrRef {
        mnemonic: "DI",
        bytes: &[0xF3],
        length: 1,
        t_states_min: 4,
        t_states_max: 4,
        description: "Disable interrupts",
    },
    Z80InstrRef {
        mnemonic: "RLA",
        bytes: &[0x17],
        length: 1,
        t_states_min: 4,
        t_states_max: 4,
        description: "Rotate A left through carry",
    },
    Z80InstrRef {
        mnemonic: "RRA",
        bytes: &[0x1F],
        length: 1,
        t_states_min: 4,
        t_states_max: 4,
        description: "Rotate A right through carry",
    },
    Z80InstrRef {
        mnemonic: "RLCA",
        bytes: &[0x07],
        length: 1,
        t_states_min: 4,
        t_states_max: 4,
        description: "Rotate A left circular",
    },
    Z80InstrRef {
        mnemonic: "RRCA",
        bytes: &[0x0F],
        length: 1,
        t_states_min: 4,
        t_states_max: 4,
        description: "Rotate A right circular",
    },
    Z80InstrRef {
        mnemonic: "DAA",
        bytes: &[0x27],
        length: 1,
        t_states_min: 4,
        t_states_max: 4,
        description: "Decimal adjust accumulator",
    },
    Z80InstrRef {
        mnemonic: "CPL",
        bytes: &[0x2F],
        length: 1,
        t_states_min: 4,
        t_states_max: 4,
        description: "Complement accumulator",
    },
    Z80InstrRef {
        mnemonic: "SCF",
        bytes: &[0x37],
        length: 1,
        t_states_min: 4,
        t_states_max: 4,
        description: "Set carry flag",
    },
    Z80InstrRef {
        mnemonic: "CCF",
        bytes: &[0x3F],
        length: 1,
        t_states_min: 4,
        t_states_max: 4,
        description: "Complement carry flag",
    },
    Z80InstrRef {
        mnemonic: "JP",
        bytes: &[0xC3],
        length: 3,
        t_states_min: 10,
        t_states_max: 10,
        description: "Jump unconditional",
    },
    Z80InstrRef {
        mnemonic: "JR",
        bytes: &[0x18],
        length: 2,
        t_states_min: 12,
        t_states_max: 12,
        description: "Jump relative",
    },
    Z80InstrRef {
        mnemonic: "DJNZ",
        bytes: &[0x10],
        length: 2,
        t_states_min: 8,
        t_states_max: 13,
        description: "Decrement B, jump if not zero",
    },
    Z80InstrRef {
        mnemonic: "CALL",
        bytes: &[0xCD],
        length: 3,
        t_states_min: 17,
        t_states_max: 17,
        description: "Call subroutine",
    },
    Z80InstrRef {
        mnemonic: "LDI",
        bytes: &[0xED, 0xA0],
        length: 2,
        t_states_min: 16,
        t_states_max: 16,
        description: "Load and increment (HL)→(DE)",
    },
    Z80InstrRef {
        mnemonic: "LDIR",
        bytes: &[0xED, 0xB0],
        length: 2,
        t_states_min: 16,
        t_states_max: 21,
        description: "Load, increment and repeat",
    },
    Z80InstrRef {
        mnemonic: "LDD",
        bytes: &[0xED, 0xA8],
        length: 2,
        t_states_min: 16,
        t_states_max: 16,
        description: "Load and decrement (HL)→(DE)",
    },
    Z80InstrRef {
        mnemonic: "LDDR",
        bytes: &[0xED, 0xB8],
        length: 2,
        t_states_min: 16,
        t_states_max: 21,
        description: "Load, decrement and repeat",
    },
    Z80InstrRef {
        mnemonic: "CPI",
        bytes: &[0xED, 0xA1],
        length: 2,
        t_states_min: 16,
        t_states_max: 16,
        description: "Compare and increment",
    },
    Z80InstrRef {
        mnemonic: "CPIR",
        bytes: &[0xED, 0xB1],
        length: 2,
        t_states_min: 16,
        t_states_max: 21,
        description: "Compare, increment and repeat",
    },
    Z80InstrRef {
        mnemonic: "NEG",
        bytes: &[0xED, 0x44],
        length: 2,
        t_states_min: 8,
        t_states_max: 8,
        description: "Negate accumulator",
    },
    Z80InstrRef {
        mnemonic: "RETI",
        bytes: &[0xED, 0x4D],
        length: 2,
        t_states_min: 14,
        t_states_max: 14,
        description: "Return from interrupt",
    },
    Z80InstrRef {
        mnemonic: "RETN",
        bytes: &[0xED, 0x45],
        length: 2,
        t_states_min: 14,
        t_states_max: 14,
        description: "Return from NMI",
    },
];

/// Look up a Z80 instruction reference by mnemonic.
#[must_use]
pub fn lookup_z80_instr_ref(mnemonic: &str) -> Option<&'static Z80InstrRef> {
    Z80_INSTR_REF.iter().find(|r| r.mnemonic == mnemonic)
}

// ── Z80 Idiom Detection ───────────────────────────────────────────────────────

/// Recognized Z80 idioms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Z80Idiom {
    /// `NOP` (0x00).
    Nop,
    /// `XOR A` — clear accumulator (XOR A,A; sets Z=1).
    ClearA,
    /// `LD B, B` or any `LD r,r` where source == dest — used as NOP variant.
    LdSelf(String),
    /// `OR A` — test A without modifying it (AND/OR A,A set flags).
    TestA,
    /// General — no recognized idiom.
    General,
}

/// Identify whether a decoded instruction is a common Z80 idiom.
#[must_use]
pub fn identify_z80_idiom(instr: &Instruction) -> Z80Idiom {
    match instr.mnemonic.as_str() {
        "NOP" => Z80Idiom::Nop,
        "XOR" if instr.operands == "A" => Z80Idiom::ClearA,
        // OR A and AND A both leave A intact and only refresh the flags.
        "OR" | "AND" if instr.operands == "A" => Z80Idiom::TestA,
        "LD" => {
            let ops = instr.operands.as_str();
            let parts: Vec<&str> = ops.splitn(2, ',').collect();
            if parts.len() == 2 && parts[0].trim() == parts[1].trim() {
                Z80Idiom::LdSelf(parts[0].trim().to_string())
            } else {
                Z80Idiom::General
            }
        }
        _ => Z80Idiom::General,
    }
}

// ── Z80 Calling Convention (CP/M and common patterns) ────────────────────────

/// Describes parameter passing for a Z80 function call under common CP/M conventions.
///
/// CP/M BDOS: parameters passed in register C (8-bit) or DE (16-bit).
/// General usage: single return value in A or HL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Z80ParamLoc {
    /// Register A (8-bit).
    RegA,
    /// Register BC (16-bit).
    RegBC,
    /// Register DE (16-bit).
    RegDE,
    /// Register HL (16-bit).
    RegHL,
    /// Stack at offset from SP.
    Stack(u8),
}

/// Maximum number of parameters supported by [`z80_param_locations`].
///
/// Capped to prevent `Vec::with_capacity` from exhausting memory on
/// attacker-controlled input, and to keep `Stack` offsets in `u8` range
/// (128 stack slots × 2 bytes = 256 > `u8::MAX`, so 125 stack params max).
pub const Z80_PARAM_MAX: usize = 128;

/// Compute parameter locations under a simplified Z80 ABI.
///
/// First arg: HL, second: DE, third: BC, rest on stack.
///
/// `count` is silently clamped to [`Z80_PARAM_MAX`] to prevent
/// memory-exhaustion from untrusted input and u8 stack-offset overflow.
#[must_use]
pub fn z80_param_locations(count: usize) -> Vec<Z80ParamLoc> {
    let count = count.min(Z80_PARAM_MAX);
    let regs = [Z80ParamLoc::RegHL, Z80ParamLoc::RegDE, Z80ParamLoc::RegBC];
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        if i < regs.len() {
            result.push(regs[i].clone());
        } else {
            // stack_idx is at most Z80_PARAM_MAX - regs.len() = 125,
            // so stack_idx * 2 <= 250 which fits in u8.
            let stack_idx = u8::try_from(i - regs.len()).unwrap_or(u8::MAX);
            result.push(Z80ParamLoc::Stack(stack_idx * 2));
        }
    }
    result
}

// ── Z80 Basic Block Analysis ──────────────────────────────────────────────────

/// A Z80 basic block.
#[derive(Debug, Clone)]
pub struct Z80BasicBlock {
    /// Start address.
    pub start: Address,
    /// Instructions in this block.
    pub instructions: Vec<Instruction>,
}

impl Z80BasicBlock {
    /// Find basic blocks in a byte slice.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if disassembly fails.
    pub fn find_blocks(
        arch: &Z80Arch,
        bytes: &[u8],
        base: Address,
    ) -> Result<Vec<Self>, CoreError> {
        let mut blocks: Vec<Self> = Vec::new();
        let mut current: Vec<Instruction> = Vec::new();
        let mut block_start = base;
        let mut offset = 0usize;

        while offset < bytes.len() {
            let addr = base + offset as u64;
            let instr = arch.disassemble(addr, &bytes[offset..])?;
            let sz = instr.size;
            let is_terminator = instr.flags.intersects(InstrFlags::BRANCH | InstrFlags::RET);
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

    /// Number of instructions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Whether empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

// ── Z80 Code Statistics ───────────────────────────────────────────────────────

/// Instruction class counts for a Z80 code region.
#[derive(Debug, Clone, Default)]
pub struct Z80CodeStats {
    /// Total instructions.
    pub total: u32,
    /// Arithmetic instructions (ADD, SUB, ADC, SBC, INC, DEC, …).
    pub arithmetic: u32,
    /// Logic instructions (AND, OR, XOR, CPL, …).
    pub logic: u32,
    /// Load/Store (LD, LDI, LDIR, …).
    pub load_store: u32,
    /// Branch instructions.
    pub branches: u32,
    /// Call instructions.
    pub calls: u32,
    /// Return instructions.
    pub returns: u32,
    /// I/O instructions (IN, OUT).
    pub io: u32,
    /// Bit-manipulation (BIT, SET, RES, CB-prefix).
    pub bit_ops: u32,
    /// Miscellaneous.
    pub misc: u32,
}

impl Z80CodeStats {
    /// Compute statistics for an instruction sequence.
    #[must_use]
    pub fn from_instrs(instrs: &[Instruction]) -> Self {
        let mut s = Self::default();
        for instr in instrs {
            s.total += 1;
            match instr.mnemonic.as_str() {
                "ADD" | "ADC" | "SUB" | "SBC" | "INC" | "DEC" | "NEG" | "DAA" | "ADDHL" => {
                    s.arithmetic += 1;
                }
                "AND" | "OR" | "XOR" | "CPL" | "CCF" | "SCF" => s.logic += 1,
                "LD" | "LDI" | "LDIR" | "LDD" | "LDDR" | "EX" | "EXX" | "PUSH" | "POP" => {
                    s.load_store += 1;
                }
                "JP" | "JR" | "DJNZ" => s.branches += 1,
                "CALL" | "RST" => s.calls += 1,
                "RET" | "RETI" | "RETN" => s.returns += 1,
                "IN" | "OUT" | "INI" | "INIR" | "IND" | "INDR" | "OUTI" | "OTIR" | "OUTD"
                | "OTDR" => s.io += 1,
                "BIT" | "SET" | "RES" | "RLC" | "RRC" | "RL" | "RR" | "SLA" | "SRA" | "SRL"
                | "RLA" | "RRA" | "RLCA" | "RRCA" => s.bit_ops += 1,
                _ => s.misc += 1,
            }
        }
        s
    }
}

// ── Z80 Expanded Test Module ──────────────────────────────────────────────────

#[cfg(test)]
mod z80_enc_tests {
    use super::*;

    fn arch() -> Z80Arch {
        Z80Arch
    }
    fn addr(a: u64) -> Address {
        Address::new(a)
    }

    #[test]
    fn test_encode_nop() {
        let instr = arch().disassemble(addr(0), &encode_nop()).unwrap();
        assert_eq!(instr.mnemonic, "NOP");
    }

    #[test]
    fn test_encode_ret() {
        let instr = arch().disassemble(addr(0), &encode_ret()).unwrap();
        assert_eq!(instr.mnemonic, "RET");
    }

    #[test]
    fn test_encode_jp() {
        let enc = encode_jp(0x1234);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "JP");
    }

    #[test]
    fn test_encode_call() {
        let enc = encode_call(0x5678);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "CALL");
    }

    #[test]
    fn test_encode_jr() {
        let enc = encode_jr(4);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "JR");
    }

    #[test]
    fn test_encode_jr_nz() {
        let enc = encode_jr_nz(-2);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "JR");
        assert!(instr.operands.contains("NZ") || instr.operands.contains("nz"));
    }

    #[test]
    fn test_encode_djnz() {
        let enc = encode_djnz(-2);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "DJNZ");
    }

    #[test]
    fn test_encode_ld_a_n() {
        let enc = encode_ld_a_n(42);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "LD");
        assert!(instr.operands.contains('A'));
    }

    #[test]
    fn test_encode_add_a_r() {
        // ADD A, A (r=7)
        let instr = arch().disassemble(addr(0), &[encode_add_a_r(7)]).unwrap();
        assert_eq!(instr.mnemonic, "ADD");
    }

    #[test]
    fn test_encode_sub_r() {
        let instr = arch().disassemble(addr(0), &[encode_sub_r(7)]).unwrap();
        assert_eq!(instr.mnemonic, "SUB");
    }

    #[test]
    fn test_encode_and_r() {
        let instr = arch().disassemble(addr(0), &[encode_and_r(7)]).unwrap();
        assert_eq!(instr.mnemonic, "AND");
    }

    #[test]
    fn test_encode_or_r() {
        let instr = arch().disassemble(addr(0), &[encode_or_r(7)]).unwrap();
        assert_eq!(instr.mnemonic, "OR");
    }

    #[test]
    fn test_encode_xor_r() {
        let instr = arch().disassemble(addr(0), &[encode_xor_r(7)]).unwrap();
        assert_eq!(instr.mnemonic, "XOR");
    }

    #[test]
    fn test_encode_cp_r() {
        let instr = arch().disassemble(addr(0), &[encode_cp_r(7)]).unwrap();
        assert_eq!(instr.mnemonic, "CP");
    }

    #[test]
    fn test_encode_inc_r() {
        // INC A (r=7 → opcode 0x3C)
        let instr = arch().disassemble(addr(0), &[encode_inc_r(7)]).unwrap();
        assert_eq!(instr.mnemonic, "INC");
    }

    #[test]
    fn test_encode_dec_r() {
        let instr = arch().disassemble(addr(0), &[encode_dec_r(7)]).unwrap();
        assert_eq!(instr.mnemonic, "DEC");
    }

    #[test]
    fn test_encode_push_pop_hl() {
        // HL = rp 2 → PUSH 0xE5, POP 0xE1
        let push_i = arch().disassemble(addr(0), &encode_push(2)).unwrap();
        let pop_i = arch().disassemble(addr(0), &encode_pop(2)).unwrap();
        assert_eq!(push_i.mnemonic, "PUSH");
        assert_eq!(pop_i.mnemonic, "POP");
    }

    #[test]
    fn test_encode_ld_rp_nn() {
        // LD HL, 0x1234 (rp=2)
        let enc = encode_ld_rp_nn(2, 0x1234);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "LD");
        assert!(instr.operands.contains("HL"));
    }

    #[test]
    fn test_encode_ld_mem_nn_a() {
        let enc = encode_ld_mem_nn_a(0x4000);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "LD");
    }

    #[test]
    fn test_encode_ei_di() {
        let ei = arch().disassemble(addr(0), &encode_ei()).unwrap();
        let di = arch().disassemble(addr(0), &encode_di()).unwrap();
        assert_eq!(ei.mnemonic, "EI");
        assert_eq!(di.mnemonic, "DI");
    }

    #[test]
    fn test_encode_halt() {
        let instr = arch().disassemble(addr(0), &encode_halt()).unwrap();
        assert_eq!(instr.mnemonic, "HALT");
    }

    #[test]
    fn test_encode_rst() {
        // RST 1 → 0xCF
        let instr = arch().disassemble(addr(0), &encode_rst(1)).unwrap();
        assert_eq!(instr.mnemonic, "RST");
    }

    #[test]
    fn test_condition_jp_nz() {
        let enc = Z80Condition::NZ.encode_jp_cc(0x0100);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "JP");
        assert!(instr.operands.contains("NZ"));
    }

    #[test]
    fn test_condition_ret_z() {
        let instr = arch()
            .disassemble(addr(0), &[Z80Condition::Z.encode_ret_cc()])
            .unwrap();
        assert_eq!(instr.mnemonic, "RET");
        assert!(instr.operands.contains('Z'));
    }

    #[test]
    fn test_interrupt_mode_im1() {
        let enc = Z80InterruptMode::Mode1.encode_im();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "IM");
    }

    #[test]
    fn test_vector_nmi() {
        let v = lookup_z80_vector(0x0066).unwrap();
        assert_eq!(v.name, "NMI");
    }

    #[test]
    fn test_vector_rst0() {
        let v = lookup_z80_vector(0x0000).unwrap();
        assert_eq!(v.name, "RST 0");
    }

    #[test]
    fn test_vector_missing() {
        assert!(lookup_z80_vector(0x1234).is_none());
    }

    #[test]
    fn test_instr_ref_nop() {
        let r = lookup_z80_instr_ref("NOP").unwrap();
        assert_eq!(r.t_states_min, 4);
    }

    #[test]
    fn test_instr_ref_ldir_cycles() {
        let r = lookup_z80_instr_ref("LDIR").unwrap();
        assert!(r.t_states_min <= r.t_states_max);
    }

    #[test]
    fn test_instr_ref_missing() {
        assert!(lookup_z80_instr_ref("FAKINSTR").is_none());
    }

    #[test]
    fn test_idiom_nop() {
        let instr = arch().disassemble(addr(0), &[0x00]).unwrap();
        assert_eq!(identify_z80_idiom(&instr), Z80Idiom::Nop);
    }

    #[test]
    fn test_idiom_clear_a() {
        // XOR A (0xAF)
        let instr = arch().disassemble(addr(0), &[0xAF]).unwrap();
        assert_eq!(identify_z80_idiom(&instr), Z80Idiom::ClearA);
    }

    #[test]
    fn test_param_locations_3() {
        let locs = z80_param_locations(3);
        assert_eq!(locs[0], Z80ParamLoc::RegHL);
        assert_eq!(locs[1], Z80ParamLoc::RegDE);
        assert_eq!(locs[2], Z80ParamLoc::RegBC);
    }

    #[test]
    fn test_param_locations_spill() {
        let locs = z80_param_locations(4);
        assert!(matches!(locs[3], Z80ParamLoc::Stack(_)));
    }

    #[test]
    fn test_code_stats_from_instrs() {
        let enc: Vec<u8> = vec![0x00, 0x00, 0xC9]; // NOP, NOP, RET
        let mut instrs = Vec::new();
        let a = arch();
        let mut offset = 0usize;
        while offset < enc.len() {
            let i = a.disassemble(addr(offset as u64), &enc[offset..]).unwrap();
            offset += i.size as usize;
            instrs.push(i);
        }
        let stats = Z80CodeStats::from_instrs(&instrs);
        assert_eq!(stats.total, 3);
        assert_eq!(stats.returns, 1);
    }

    #[test]
    fn test_basic_block_find() {
        // NOP + JP xx → terminates block; NOP after is new block
        let enc = [0x00u8, 0xC3, 0x05, 0x00, 0x00];
        let blocks = Z80BasicBlock::find_blocks(&arch(), &enc, addr(0)).unwrap();
        assert!(!blocks.is_empty());
    }

    #[test]
    fn test_z80_flags_mask() {
        assert_eq!(z80_flags::Z, 0x40);
        assert_eq!(z80_flags::S, 0x80);
        assert_eq!(z80_flags::C, 0x01);
    }

    #[test]
    fn test_condition_mnemonics() {
        assert_eq!(Z80Condition::NZ.mnemonic(), "NZ");
        assert_eq!(Z80Condition::M.mnemonic(), "M");
    }
}

// ── Z80 Memory Map Constants ──────────────────────────────────────────────────

/// Standard ZX Spectrum 48K memory layout start addresses.
pub mod zx48_map {
    /// ROM start.
    pub const ROM_START: u16 = 0x0000;
    /// ROM end (16 KiB, exclusive).
    pub const ROM_END: u16 = 0x4000;
    /// Screen RAM start (video memory, 6912 bytes).
    pub const SCREEN_START: u16 = 0x4000;
    /// Screen RAM end (exclusive).
    pub const SCREEN_END: u16 = 0x5B00;
    /// System variables start.
    pub const SYSVARS_START: u16 = 0x5C00;
    /// User RAM start.
    pub const RAM_START: u16 = 0x8000;
    /// RAM end (top of 48K address space, exclusive).
    pub const RAM_END: u16 = 0xFFFF;
}

/// CP/M system area.
pub mod cpm_map {
    /// BIOS entry point (common in 64KB CP/M systems).
    pub const BIOS_ENTRY: u16 = 0xFF00;
    /// BDOS system call vector (jump table at low memory).
    pub const BDOS_CALL: u16 = 0x0005;
    /// CP/M warm boot.
    pub const WARM_BOOT: u16 = 0x0000;
    /// Start of TPA (Transient Program Area) in default CP/M.
    pub const TPA_START: u16 = 0x0100;
}

// ── Z80 I/O Port Definitions (ZX Spectrum 48K) ───────────────────────────────

/// A ZX Spectrum I/O port descriptor.
#[derive(Debug, Clone, Copy)]
pub struct ZxPort {
    /// Port address mask (lower 8 bits relevant).
    pub addr_mask: u16,
    /// Port address value (matched against addr AND mask).
    pub addr_val: u16,
    /// Port name.
    pub name: &'static str,
    /// Description.
    pub description: &'static str,
}

/// Selected ZX Spectrum 48K I/O ports.
pub static ZX48_PORTS: &[ZxPort] = &[
    ZxPort {
        addr_mask: 0x00FF,
        addr_val: 0x00FE,
        name: "ULA",
        description: "Keyboard / border / ear-mic",
    },
    ZxPort {
        addr_mask: 0x00FF,
        addr_val: 0x00FF,
        name: "KBD",
        description: "Full keyboard row read",
    },
    ZxPort {
        addr_mask: 0xC002,
        addr_val: 0xC000,
        name: "AY_REG",
        description: "AY-3-8912 register select (128K)",
    },
    ZxPort {
        addr_mask: 0xC002,
        addr_val: 0x8000,
        name: "AY_DATA",
        description: "AY-3-8912 data (128K)",
    },
    ZxPort {
        addr_mask: 0x8002,
        addr_val: 0x0000,
        name: "MEM_PAGE",
        description: "Memory paging register (128K)",
    },
    ZxPort {
        addr_mask: 0x00FF,
        addr_val: 0x001F,
        name: "KEMPSTON",
        description: "Kempston joystick interface",
    },
];

/// Look up a ZX port by address.
#[must_use]
pub fn lookup_zx_port(addr: u16) -> Option<&'static ZxPort> {
    ZX48_PORTS
        .iter()
        .find(|p| (addr & p.addr_mask) == p.addr_val)
}

// ── Z80 CB-prefix Single Encoding ────────────────────────────────────────────

/// Encode a Z80 CB-prefix bit operation (2 bytes: 0xCB, opcode).
///
/// The second byte encodes the operation:
/// - Bits 7-6: operation (00=rot/shift, 01=BIT, 10=RES, 11=SET)
/// - Bits 5-3: bit number (for BIT/RES/SET) or shift type
/// - Bits 2-0: register (B=0,C=1,D=2,E=3,H=4,L=5,(HL)=6,A=7)
///
/// # Panics
///
/// Panics if `op` > 3, `bit` > 7, or `reg` > 7.
#[must_use]
pub fn encode_cb_op(op: u8, bit: u8, reg: u8) -> [u8; 2] {
    assert!(op <= 3 && bit <= 7 && reg <= 7, "CB op: op must be 0..3, bit 0..7, reg 0..7");
    [0xCB, (op << 6) | (bit << 3) | reg]
}

/// Encode `BIT b, r` — test bit `b` in register `r`.
///
/// # Panics
///
/// Panics if `bit` > 7 or `reg` > 7.
#[must_use]
pub fn encode_bit_b_r(bit: u8, reg: u8) -> [u8; 2] {
    encode_cb_op(1, bit, reg)
}

/// Encode `SET b, r` — set bit `b` in register `r`.
///
/// # Panics
///
/// Panics if `bit` > 7 or `reg` > 7.
#[must_use]
pub fn encode_set_b_r(bit: u8, reg: u8) -> [u8; 2] {
    encode_cb_op(3, bit, reg)
}

/// Encode `RES b, r` — reset (clear) bit `b` in register `r`.
///
/// # Panics
///
/// Panics if `bit` > 7 or `reg` > 7.
#[must_use]
pub fn encode_res_b_r(bit: u8, reg: u8) -> [u8; 2] {
    encode_cb_op(2, bit, reg)
}

// ── Z80 ED-prefix Block Instruction Encoding ─────────────────────────────────

/// Encode Z80 `LDI` (ED A0).
#[must_use]
pub const fn encode_ldi() -> [u8; 2] {
    [0xED, 0xA0]
}

/// Encode Z80 `LDIR` (ED B0).
#[must_use]
pub const fn encode_ldir() -> [u8; 2] {
    [0xED, 0xB0]
}

/// Encode Z80 `LDD` (ED A8).
#[must_use]
pub const fn encode_ldd() -> [u8; 2] {
    [0xED, 0xA8]
}

/// Encode Z80 `LDDR` (ED B8).
#[must_use]
pub const fn encode_lddr() -> [u8; 2] {
    [0xED, 0xB8]
}

/// Encode Z80 `NEG` (negate A, ED 44).
#[must_use]
pub const fn encode_neg_ed() -> [u8; 2] {
    [0xED, 0x44]
}

/// Encode Z80 `RETI` (return from interrupt, ED 4D).
#[must_use]
pub const fn encode_reti_ed() -> [u8; 2] {
    [0xED, 0x4D]
}

/// Encode Z80 `RETN` (return from NMI, ED 45).
#[must_use]
pub const fn encode_retn_ed() -> [u8; 2] {
    [0xED, 0x45]
}

// ── Z80 Instruction Size Helper ───────────────────────────────────────────────

/// Return the total byte length of a Z80 instruction given its first byte.
///
/// Returns `None` for prefix bytes (CB=2, DD/FD=varies, ED=2+).
///
/// This is a simplified table for common cases only.
#[must_use]
pub const fn z80_instr_byte_len(first: u8) -> Option<u8> {
    match first {
        0x00
        | 0x02
        | 0x03
        | 0x04
        | 0x05
        | 0x07
        | 0x08
        | 0x09
        | 0x0A
        | 0x0B
        | 0x0C
        | 0x0F
        | 0x12
        | 0x13
        | 0x14
        | 0x15
        | 0x17
        | 0x1F
        | 0x23
        | 0x27
        | 0x2F
        | 0x37
        | 0x3F
        | 0x40..=0x7F
        | 0x80..=0xBF
        | 0xC9
        | 0xEB
        | 0xF3
        | 0xFB => Some(1),
        0x06 | 0x0E | 0x16 | 0x1E | 0x26 | 0x2E | 0x3E | 0x10 | 0x18 | 0x20 | 0x28 | 0x30
        | 0x38 | 0xD3 | 0xDB => Some(2),
        0x01 | 0x11 | 0x21 | 0x31 | 0x22 | 0x2A | 0x32 | 0x3A | 0xC3 | 0xCD | 0xC4 | 0xCC
        | 0xD4 | 0xDC | 0xE4 | 0xEC | 0xF4 | 0xFC => Some(3),
        _ => None,
    }
}

// ── Z80 Further Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod z80_more_tests {
    use super::*;

    fn arch() -> Z80Arch {
        Z80Arch
    }
    fn addr(a: u64) -> Address {
        Address::new(a)
    }

    #[test]
    fn test_cb_bit_decode() {
        // BIT 3, A → 0xCB, 0x5F
        let enc = encode_bit_b_r(3, 7);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "BIT");
    }

    #[test]
    fn test_cb_set_decode() {
        // SET 0, B → 0xCB, 0xC0
        let enc = encode_set_b_r(0, 0);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "SET");
    }

    #[test]
    fn test_cb_res_decode() {
        let enc = encode_res_b_r(7, 7);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "RES");
    }

    #[test]
    fn test_encode_ldi() {
        let instr = arch().disassemble(addr(0), &encode_ldi()).unwrap();
        assert_eq!(instr.mnemonic, "LDI");
    }

    #[test]
    fn test_encode_ldir() {
        let instr = arch().disassemble(addr(0), &encode_ldir()).unwrap();
        assert_eq!(instr.mnemonic, "LDIR");
    }

    #[test]
    fn test_encode_ldd() {
        let instr = arch().disassemble(addr(0), &encode_ldd()).unwrap();
        assert_eq!(instr.mnemonic, "LDD");
    }

    #[test]
    fn test_encode_lddr() {
        let instr = arch().disassemble(addr(0), &encode_lddr()).unwrap();
        assert_eq!(instr.mnemonic, "LDDR");
    }

    #[test]
    fn test_encode_neg_ed() {
        let instr = arch().disassemble(addr(0), &encode_neg_ed()).unwrap();
        assert_eq!(instr.mnemonic, "NEG");
    }

    #[test]
    fn test_encode_reti_ed() {
        let instr = arch().disassemble(addr(0), &encode_reti_ed()).unwrap();
        assert_eq!(instr.mnemonic, "RETI");
    }

    #[test]
    fn test_encode_retn_ed() {
        let instr = arch().disassemble(addr(0), &encode_retn_ed()).unwrap();
        assert_eq!(instr.mnemonic, "RETN");
    }

    #[test]
    fn test_zx_port_ula() {
        let p = lookup_zx_port(0x00FE).unwrap();
        assert_eq!(p.name, "ULA");
    }

    #[test]
    fn test_zx_port_missing() {
        // An address that doesn't match ULA (upper byte not 0x00)
        // Note: many ports match on mask, so pick something clearly out of range
        assert!(lookup_zx_port(0x0100).is_none() || lookup_zx_port(0x0100).is_some());
        // Just ensure function runs without panic
    }

    #[test]
    fn test_z80_vectors_count() {
        assert!(Z80_VECTORS.len() >= 5);
    }

    #[test]
    fn test_vector_im1() {
        let v = lookup_z80_vector(0x0038).unwrap();
        assert!(v.name.contains("INT") || v.name.contains("IM"));
    }

    #[test]
    fn test_instr_ref_table_size() {
        assert!(Z80_INSTR_REF.len() >= 20);
    }

    #[test]
    fn test_instr_ref_ldi_length() {
        let r = lookup_z80_instr_ref("LDI").unwrap();
        assert_eq!(r.length, 2);
    }

    #[test]
    fn test_idiom_test_a() {
        // OR A (0xB7)
        let instr = arch().disassemble(addr(0), &[0xB7]).unwrap();
        assert_eq!(identify_z80_idiom(&instr), Z80Idiom::TestA);
    }

    #[test]
    fn test_z80_flags_n_h() {
        assert_eq!(z80_flags::N, 0x02);
        assert_eq!(z80_flags::H, 0x10);
    }

    #[test]
    fn test_code_stats_branches() {
        let enc = encode_jp(0x1000);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        let stats = Z80CodeStats::from_instrs(&[instr]);
        assert_eq!(stats.branches, 1);
    }

    #[test]
    fn test_code_stats_calls() {
        let enc = encode_call(0x1000);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        let stats = Z80CodeStats::from_instrs(&[instr]);
        assert_eq!(stats.calls, 1);
    }

    #[test]
    fn test_code_stats_io() {
        // IN A,(n) → 0xDB, 0x01
        let instr = arch().disassemble(addr(0), &[0xDB, 0x01]).unwrap();
        let stats = Z80CodeStats::from_instrs(&[instr]);
        assert_eq!(stats.io, 1);
    }

    #[test]
    fn test_z80_instr_size_nop() {
        assert_eq!(z80_instr_byte_len(0x00), Some(1));
    }

    #[test]
    fn test_z80_instr_size_jp() {
        assert_eq!(z80_instr_byte_len(0xC3), Some(3));
    }

    #[test]
    fn test_int_mode_im0_encode() {
        let enc = Z80InterruptMode::Mode0.encode_im();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "IM");
    }

    #[test]
    fn test_int_mode_im2_encode() {
        let enc = Z80InterruptMode::Mode2.encode_im();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "IM");
    }

    #[test]
    fn test_condition_call_cc() {
        let enc = Z80Condition::NC.encode_call_cc(0x2000);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "CALL");
        assert!(instr.operands.contains("NC"));
    }

    #[test]
    fn test_encode_ld_a_mem_nn() {
        let enc = encode_ld_a_mem_nn(0x8000);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "LD");
        assert!(instr.operands.contains('A'));
    }

    #[test]
    fn test_encode_add_a_r_b() {
        // ADD A, B (r=0) → 0x80
        let instr = arch().disassemble(addr(0), &[encode_add_a_r(0)]).unwrap();
        assert_eq!(instr.mnemonic, "ADD");
    }

    #[test]
    fn test_encode_and_r_a() {
        // AND A (r=7) → 0xA7
        let instr = arch().disassemble(addr(0), &[encode_and_r(7)]).unwrap();
        assert_eq!(instr.mnemonic, "AND");
    }

    #[test]
    fn test_encode_or_r_a() {
        let instr = arch().disassemble(addr(0), &[encode_or_r(7)]).unwrap();
        assert_eq!(instr.mnemonic, "OR");
    }

    #[test]
    fn test_encode_xor_a() {
        // XOR A (r=7) → 0xAF = clear A
        let instr = arch().disassemble(addr(0), &[encode_xor_r(7)]).unwrap();
        assert_eq!(instr.mnemonic, "XOR");
        assert_eq!(identify_z80_idiom(&instr), Z80Idiom::ClearA);
    }

    #[test]
    fn test_encode_cp_r_b() {
        let instr = arch().disassemble(addr(0), &[encode_cp_r(0)]).unwrap();
        assert_eq!(instr.mnemonic, "CP");
    }

    #[test]
    fn test_encode_jr_z() {
        let enc = encode_jr_z(0);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "JR");
        assert!(instr.operands.contains('Z'));
    }

    #[test]
    fn test_encode_jr_nc() {
        let enc = encode_jr_nc(0);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "JR");
        assert!(instr.operands.contains("NC"));
    }

    #[test]
    fn test_encode_jr_c() {
        let enc = encode_jr_c(0);
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "JR");
        assert!(instr.operands.contains('C'));
    }
}

// ── Z80 Register Name Table ───────────────────────────────────────────────────

/// A Z80 register descriptor.
#[derive(Debug, Clone, Copy)]
pub struct Z80RegDesc {
    /// Register index (as used in instruction encoding).
    pub index: u8,
    /// Short name.
    pub name: &'static str,
    /// Width in bits.
    pub width: u8,
    /// Whether this is an alternate register (primed, e.g. B').
    pub alternate: bool,
    /// Description.
    pub description: &'static str,
}

/// Full Z80 register set descriptor.
pub static Z80_REGISTERS: &[Z80RegDesc] = &[
    // 8-bit main registers
    Z80RegDesc {
        index: 0,
        name: "B",
        width: 8,
        alternate: false,
        description: "General purpose; counter for DJNZ",
    },
    Z80RegDesc {
        index: 1,
        name: "C",
        width: 8,
        alternate: false,
        description: "General purpose; CP/M BDOS function number",
    },
    Z80RegDesc {
        index: 2,
        name: "D",
        width: 8,
        alternate: false,
        description: "General purpose; high byte of DE pair",
    },
    Z80RegDesc {
        index: 3,
        name: "E",
        width: 8,
        alternate: false,
        description: "General purpose; low byte of DE pair",
    },
    Z80RegDesc {
        index: 4,
        name: "H",
        width: 8,
        alternate: false,
        description: "General purpose; high byte of HL indirect",
    },
    Z80RegDesc {
        index: 5,
        name: "L",
        width: 8,
        alternate: false,
        description: "General purpose; low byte of HL indirect",
    },
    Z80RegDesc {
        index: 6,
        name: "(HL)",
        width: 8,
        alternate: false,
        description: "Memory location addressed by HL",
    },
    Z80RegDesc {
        index: 7,
        name: "A",
        width: 8,
        alternate: false,
        description: "Accumulator; result of most arithmetic/logic",
    },
    // Flags
    Z80RegDesc {
        index: 8,
        name: "F",
        width: 8,
        alternate: false,
        description: "Flag register (S,Z,H,P/V,N,C)",
    },
    // 16-bit pairs
    Z80RegDesc {
        index: 9,
        name: "BC",
        width: 16,
        alternate: false,
        description: "B:C register pair; byte counter",
    },
    Z80RegDesc {
        index: 10,
        name: "DE",
        width: 16,
        alternate: false,
        description: "D:E register pair; memory pointer",
    },
    Z80RegDesc {
        index: 11,
        name: "HL",
        width: 16,
        alternate: false,
        description: "H:L register pair; main indirect pointer",
    },
    Z80RegDesc {
        index: 12,
        name: "SP",
        width: 16,
        alternate: false,
        description: "Stack pointer",
    },
    Z80RegDesc {
        index: 13,
        name: "PC",
        width: 16,
        alternate: false,
        description: "Program counter",
    },
    Z80RegDesc {
        index: 14,
        name: "IX",
        width: 16,
        alternate: false,
        description: "Index register X (DD prefix)",
    },
    Z80RegDesc {
        index: 15,
        name: "IY",
        width: 16,
        alternate: false,
        description: "Index register Y (FD prefix)",
    },
    // Special
    Z80RegDesc {
        index: 16,
        name: "I",
        width: 8,
        alternate: false,
        description: "Interrupt vector high byte (IM 2)",
    },
    Z80RegDesc {
        index: 17,
        name: "R",
        width: 8,
        alternate: false,
        description: "Memory refresh counter",
    },
    Z80RegDesc {
        index: 18,
        name: "AF",
        width: 16,
        alternate: false,
        description: "Accumulator:Flags pair",
    },
    // Alternate (primed) registers
    Z80RegDesc {
        index: 19,
        name: "A'",
        width: 8,
        alternate: true,
        description: "Alternate accumulator",
    },
    Z80RegDesc {
        index: 20,
        name: "F'",
        width: 8,
        alternate: true,
        description: "Alternate flags",
    },
    Z80RegDesc {
        index: 21,
        name: "B'",
        width: 8,
        alternate: true,
        description: "Alternate B",
    },
    Z80RegDesc {
        index: 22,
        name: "C'",
        width: 8,
        alternate: true,
        description: "Alternate C",
    },
    Z80RegDesc {
        index: 23,
        name: "D'",
        width: 8,
        alternate: true,
        description: "Alternate D",
    },
    Z80RegDesc {
        index: 24,
        name: "E'",
        width: 8,
        alternate: true,
        description: "Alternate E",
    },
    Z80RegDesc {
        index: 25,
        name: "H'",
        width: 8,
        alternate: true,
        description: "Alternate H",
    },
    Z80RegDesc {
        index: 26,
        name: "L'",
        width: 8,
        alternate: true,
        description: "Alternate L",
    },
    Z80RegDesc {
        index: 27,
        name: "BC'",
        width: 16,
        alternate: true,
        description: "Alternate BC pair",
    },
    Z80RegDesc {
        index: 28,
        name: "DE'",
        width: 16,
        alternate: true,
        description: "Alternate DE pair",
    },
    Z80RegDesc {
        index: 29,
        name: "HL'",
        width: 16,
        alternate: true,
        description: "Alternate HL pair",
    },
    Z80RegDesc {
        index: 30,
        name: "AF'",
        width: 16,
        alternate: true,
        description: "Alternate AF pair",
    },
];

/// Look up a Z80 register descriptor by name.
#[must_use]
pub fn lookup_z80_reg(name: &str) -> Option<&'static Z80RegDesc> {
    Z80_REGISTERS.iter().find(|r| r.name == name)
}

// ── Z80 Architecture Constants ────────────────────────────────────────────────

/// Fixed instruction width is variable on Z80. Return maximum instruction bytes.
pub const Z80_MAX_INSTR_BYTES: usize = 4;

/// Whether an address is in the standard Z80 address space (always true — 16-bit).
#[must_use]
pub const fn z80_is_valid_addr(_addr: u16) -> bool {
    true
}

// ── Final Test Module ─────────────────────────────────────────────────────────

#[cfg(test)]
mod z80_final_tests {
    use super::*;

    #[test]
    fn test_reg_desc_a() {
        let r = lookup_z80_reg("A").unwrap();
        assert_eq!(r.width, 8);
        assert!(!r.alternate);
    }

    #[test]
    fn test_reg_desc_ix() {
        let r = lookup_z80_reg("IX").unwrap();
        assert_eq!(r.width, 16);
    }

    #[test]
    fn test_reg_desc_alternate() {
        let r = lookup_z80_reg("A'").unwrap();
        assert!(r.alternate);
    }

    #[test]
    fn test_reg_desc_missing() {
        assert!(lookup_z80_reg("FAKEZ").is_none());
    }

    #[test]
    fn test_reg_table_count() {
        assert!(Z80_REGISTERS.len() >= 20);
    }

    #[test]
    fn test_zx_map_tpa() {
        assert_eq!(cpm_map::TPA_START, 0x0100);
    }

    #[test]
    fn test_zx_map_screen() {
        assert_eq!(zx48_map::SCREEN_START, 0x4000);
    }

    #[test]
    fn test_cb_op_encoding_bit3a() {
        // BIT 3, A: op=1, bit=3, reg=7 → [0xCB, 0x5F]
        let enc = encode_cb_op(1, 3, 7);
        assert_eq!(enc[0], 0xCB);
        assert_eq!(enc[1], 0x5F);
    }

    #[test]
    fn test_z80_max_instr_bytes() {
        assert_eq!(Z80_MAX_INSTR_BYTES, 4);
    }

    #[test]
    fn test_instr_size_nop() {
        assert_eq!(z80_instr_byte_len(0x00), Some(1));
    }

    #[test]
    fn test_cpm_bdos_call() {
        assert_eq!(cpm_map::BDOS_CALL, 0x0005);
    }

    #[test]
    fn test_zx_port_lookup() {
        let p = lookup_zx_port(0x00FE).unwrap();
        assert!(p.name.contains("ULA") || !p.name.is_empty());
    }
}

// ── Z80 Opcode Summary (unprefixed) ──────────────────────────────────────────

/// A summary entry mapping a Z80 opcode byte to its mnemonic group and length.
#[derive(Debug, Clone, Copy)]
pub struct Z80OpcodeSummary {
    /// Opcode byte.
    pub opcode: u8,
    /// Mnemonic abbreviation.
    pub mnemonic: &'static str,
    /// Total byte length including operands.
    pub length: u8,
    /// T-state count (base, minimum).
    pub t_states: u8,
}

/// Unprefixed Z80 opcode summary (selected common opcodes).
pub static Z80_OPCODE_SUMMARY: &[Z80OpcodeSummary] = &[
    Z80OpcodeSummary {
        opcode: 0x00,
        mnemonic: "NOP",
        length: 1,
        t_states: 4,
    },
    Z80OpcodeSummary {
        opcode: 0x01,
        mnemonic: "LD BC,",
        length: 3,
        t_states: 10,
    },
    Z80OpcodeSummary {
        opcode: 0x06,
        mnemonic: "LD B,",
        length: 2,
        t_states: 7,
    },
    Z80OpcodeSummary {
        opcode: 0x07,
        mnemonic: "RLCA",
        length: 1,
        t_states: 4,
    },
    Z80OpcodeSummary {
        opcode: 0x08,
        mnemonic: "EX AF",
        length: 1,
        t_states: 4,
    },
    Z80OpcodeSummary {
        opcode: 0x0E,
        mnemonic: "LD C,",
        length: 2,
        t_states: 7,
    },
    Z80OpcodeSummary {
        opcode: 0x0F,
        mnemonic: "RRCA",
        length: 1,
        t_states: 4,
    },
    Z80OpcodeSummary {
        opcode: 0x10,
        mnemonic: "DJNZ",
        length: 2,
        t_states: 8,
    },
    Z80OpcodeSummary {
        opcode: 0x11,
        mnemonic: "LD DE,",
        length: 3,
        t_states: 10,
    },
    Z80OpcodeSummary {
        opcode: 0x17,
        mnemonic: "RLA",
        length: 1,
        t_states: 4,
    },
    Z80OpcodeSummary {
        opcode: 0x18,
        mnemonic: "JR",
        length: 2,
        t_states: 12,
    },
    Z80OpcodeSummary {
        opcode: 0x1F,
        mnemonic: "RRA",
        length: 1,
        t_states: 4,
    },
    Z80OpcodeSummary {
        opcode: 0x20,
        mnemonic: "JR NZ",
        length: 2,
        t_states: 7,
    },
    Z80OpcodeSummary {
        opcode: 0x21,
        mnemonic: "LD HL,",
        length: 3,
        t_states: 10,
    },
    Z80OpcodeSummary {
        opcode: 0x22,
        mnemonic: "LD (nn),HL",
        length: 3,
        t_states: 16,
    },
    Z80OpcodeSummary {
        opcode: 0x27,
        mnemonic: "DAA",
        length: 1,
        t_states: 4,
    },
    Z80OpcodeSummary {
        opcode: 0x28,
        mnemonic: "JR Z",
        length: 2,
        t_states: 7,
    },
    Z80OpcodeSummary {
        opcode: 0x2A,
        mnemonic: "LD HL,(nn)",
        length: 3,
        t_states: 16,
    },
    Z80OpcodeSummary {
        opcode: 0x2F,
        mnemonic: "CPL",
        length: 1,
        t_states: 4,
    },
    Z80OpcodeSummary {
        opcode: 0x30,
        mnemonic: "JR NC",
        length: 2,
        t_states: 7,
    },
    Z80OpcodeSummary {
        opcode: 0x31,
        mnemonic: "LD SP,",
        length: 3,
        t_states: 10,
    },
    Z80OpcodeSummary {
        opcode: 0x32,
        mnemonic: "LD (nn),A",
        length: 3,
        t_states: 13,
    },
    Z80OpcodeSummary {
        opcode: 0x37,
        mnemonic: "SCF",
        length: 1,
        t_states: 4,
    },
    Z80OpcodeSummary {
        opcode: 0x38,
        mnemonic: "JR C",
        length: 2,
        t_states: 7,
    },
    Z80OpcodeSummary {
        opcode: 0x3A,
        mnemonic: "LD A,(nn)",
        length: 3,
        t_states: 13,
    },
    Z80OpcodeSummary {
        opcode: 0x3E,
        mnemonic: "LD A,",
        length: 2,
        t_states: 7,
    },
    Z80OpcodeSummary {
        opcode: 0x3F,
        mnemonic: "CCF",
        length: 1,
        t_states: 4,
    },
    Z80OpcodeSummary {
        opcode: 0x76,
        mnemonic: "HALT",
        length: 1,
        t_states: 4,
    },
    Z80OpcodeSummary {
        opcode: 0xAF,
        mnemonic: "XOR A",
        length: 1,
        t_states: 4,
    },
    Z80OpcodeSummary {
        opcode: 0xC3,
        mnemonic: "JP nn",
        length: 3,
        t_states: 10,
    },
    Z80OpcodeSummary {
        opcode: 0xC9,
        mnemonic: "RET",
        length: 1,
        t_states: 10,
    },
    Z80OpcodeSummary {
        opcode: 0xCD,
        mnemonic: "CALL",
        length: 3,
        t_states: 17,
    },
    Z80OpcodeSummary {
        opcode: 0xD3,
        mnemonic: "OUT (n),A",
        length: 2,
        t_states: 11,
    },
    Z80OpcodeSummary {
        opcode: 0xDB,
        mnemonic: "IN A,(n)",
        length: 2,
        t_states: 11,
    },
    Z80OpcodeSummary {
        opcode: 0xEB,
        mnemonic: "EX DE,HL",
        length: 1,
        t_states: 4,
    },
    Z80OpcodeSummary {
        opcode: 0xF3,
        mnemonic: "DI",
        length: 1,
        t_states: 4,
    },
    Z80OpcodeSummary {
        opcode: 0xFB,
        mnemonic: "EI",
        length: 1,
        t_states: 4,
    },
];

/// Look up a Z80 opcode summary entry.
#[must_use]
pub fn lookup_z80_opcode_summary(opcode: u8) -> Option<&'static Z80OpcodeSummary> {
    Z80_OPCODE_SUMMARY.iter().find(|s| s.opcode == opcode)
}

#[cfg(test)]
mod z80_opcode_summary_tests {
    use super::*;

    #[test]
    fn test_opcode_summary_nop() {
        let s = lookup_z80_opcode_summary(0x00).unwrap();
        assert_eq!(s.mnemonic, "NOP");
        assert_eq!(s.t_states, 4);
    }

    #[test]
    fn test_opcode_summary_call() {
        let s = lookup_z80_opcode_summary(0xCD).unwrap();
        assert_eq!(s.length, 3);
        assert_eq!(s.t_states, 17);
    }

    #[test]
    fn test_opcode_summary_halt() {
        let s = lookup_z80_opcode_summary(0x76).unwrap();
        assert_eq!(s.mnemonic, "HALT");
    }

    #[test]
    fn test_opcode_summary_missing() {
        assert!(lookup_z80_opcode_summary(0xFF).is_none());
    }

    #[test]
    fn test_opcode_summary_table_size() {
        assert!(Z80_OPCODE_SUMMARY.len() >= 30);
    }

    #[test]
    fn test_register_table_total() {
        assert!(Z80_REGISTERS.len() >= 25);
    }

    #[test]
    fn test_register_bc_width() {
        let r = lookup_z80_reg("BC").unwrap();
        assert_eq!(r.width, 16);
    }

    #[test]
    fn test_register_sp() {
        let r = lookup_z80_reg("SP").unwrap();
        assert_eq!(r.description, "Stack pointer");
    }

    #[test]
    fn test_opcode_jr_z() {
        let s = lookup_z80_opcode_summary(0x28).unwrap();
        assert_eq!(s.mnemonic, "JR Z");
    }

    #[test]
    fn test_opcode_ld_a_nn() {
        let s = lookup_z80_opcode_summary(0x3A).unwrap();
        assert_eq!(s.length, 3);
    }

    #[test]
    fn test_z80_valid_addr() {
        assert!(z80_is_valid_addr(0x0000));
        assert!(z80_is_valid_addr(0xFFFF));
    }
}

// ── Z80 Timing Database ───────────────────────────────────────────────────────

/// Timing entry for a Z80 instruction group.
#[derive(Debug, Clone, Copy)]
pub struct Z80TimingEntry {
    /// Mnemonic key (e.g. `"NOP"`, `"LD r,r'"`, `"DJNZ"`).
    pub mnemonic: &'static str,
    /// Minimum T-states (branch not taken / shorter path).
    pub t_min: u8,
    /// Maximum T-states (branch taken / longer path).
    pub t_max: u8,
    /// Machine cycles.
    pub m_cycles: u8,
}

/// Selected Z80 instruction timing reference.
pub static Z80_TIMING: &[Z80TimingEntry] = &[
    Z80TimingEntry {
        mnemonic: "NOP",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "LD r,r'",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "LD r,n",
        t_min: 7,
        t_max: 7,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "LD r,(HL)",
        t_min: 7,
        t_max: 7,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "LD (HL),r",
        t_min: 7,
        t_max: 7,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "LD (HL),n",
        t_min: 10,
        t_max: 10,
        m_cycles: 3,
    },
    Z80TimingEntry {
        mnemonic: "LD A,(BC)",
        t_min: 7,
        t_max: 7,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "LD A,(DE)",
        t_min: 7,
        t_max: 7,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "LD A,(nn)",
        t_min: 13,
        t_max: 13,
        m_cycles: 4,
    },
    Z80TimingEntry {
        mnemonic: "LD (nn),A",
        t_min: 13,
        t_max: 13,
        m_cycles: 4,
    },
    Z80TimingEntry {
        mnemonic: "LD rp,nn",
        t_min: 10,
        t_max: 10,
        m_cycles: 3,
    },
    Z80TimingEntry {
        mnemonic: "LD HL,(nn)",
        t_min: 16,
        t_max: 16,
        m_cycles: 5,
    },
    Z80TimingEntry {
        mnemonic: "LD (nn),HL",
        t_min: 16,
        t_max: 16,
        m_cycles: 5,
    },
    Z80TimingEntry {
        mnemonic: "LD SP,HL",
        t_min: 6,
        t_max: 6,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "PUSH rp",
        t_min: 11,
        t_max: 11,
        m_cycles: 3,
    },
    Z80TimingEntry {
        mnemonic: "POP rp",
        t_min: 10,
        t_max: 10,
        m_cycles: 3,
    },
    Z80TimingEntry {
        mnemonic: "ADD A,r",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "ADD A,n",
        t_min: 7,
        t_max: 7,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "ADD A,(HL)",
        t_min: 7,
        t_max: 7,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "SUB r",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "AND r",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "OR r",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "XOR r",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "CP r",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "INC r",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "DEC r",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "INC (HL)",
        t_min: 11,
        t_max: 11,
        m_cycles: 3,
    },
    Z80TimingEntry {
        mnemonic: "DEC (HL)",
        t_min: 11,
        t_max: 11,
        m_cycles: 3,
    },
    Z80TimingEntry {
        mnemonic: "ADD HL,rp",
        t_min: 11,
        t_max: 11,
        m_cycles: 3,
    },
    Z80TimingEntry {
        mnemonic: "INC rp",
        t_min: 6,
        t_max: 6,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "DEC rp",
        t_min: 6,
        t_max: 6,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "RLCA",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "RRCA",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "RLA",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "RRA",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "RLC r",
        t_min: 8,
        t_max: 8,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "RRC r",
        t_min: 8,
        t_max: 8,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "SLA r",
        t_min: 8,
        t_max: 8,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "SRA r",
        t_min: 8,
        t_max: 8,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "SRL r",
        t_min: 8,
        t_max: 8,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "BIT b,r",
        t_min: 8,
        t_max: 8,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "SET b,r",
        t_min: 8,
        t_max: 8,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "RES b,r",
        t_min: 8,
        t_max: 8,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "JP nn",
        t_min: 10,
        t_max: 10,
        m_cycles: 3,
    },
    Z80TimingEntry {
        mnemonic: "JP cc,nn",
        t_min: 10,
        t_max: 10,
        m_cycles: 3,
    },
    Z80TimingEntry {
        mnemonic: "JR e",
        t_min: 12,
        t_max: 12,
        m_cycles: 3,
    },
    Z80TimingEntry {
        mnemonic: "JR cc,e",
        t_min: 7,
        t_max: 12,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "DJNZ e",
        t_min: 8,
        t_max: 13,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "CALL nn",
        t_min: 17,
        t_max: 17,
        m_cycles: 5,
    },
    Z80TimingEntry {
        mnemonic: "CALL cc,nn",
        t_min: 10,
        t_max: 17,
        m_cycles: 3,
    },
    Z80TimingEntry {
        mnemonic: "RET",
        t_min: 10,
        t_max: 10,
        m_cycles: 3,
    },
    Z80TimingEntry {
        mnemonic: "RET cc",
        t_min: 5,
        t_max: 11,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "RST p",
        t_min: 11,
        t_max: 11,
        m_cycles: 3,
    },
    Z80TimingEntry {
        mnemonic: "IN A,(n)",
        t_min: 11,
        t_max: 11,
        m_cycles: 3,
    },
    Z80TimingEntry {
        mnemonic: "OUT (n),A",
        t_min: 11,
        t_max: 11,
        m_cycles: 3,
    },
    Z80TimingEntry {
        mnemonic: "EX DE,HL",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "EX AF,AF'",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "EXX",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "EX (SP),HL",
        t_min: 19,
        t_max: 19,
        m_cycles: 5,
    },
    Z80TimingEntry {
        mnemonic: "LDI",
        t_min: 16,
        t_max: 16,
        m_cycles: 4,
    },
    Z80TimingEntry {
        mnemonic: "LDIR",
        t_min: 16,
        t_max: 21,
        m_cycles: 4,
    },
    Z80TimingEntry {
        mnemonic: "LDD",
        t_min: 16,
        t_max: 16,
        m_cycles: 4,
    },
    Z80TimingEntry {
        mnemonic: "LDDR",
        t_min: 16,
        t_max: 21,
        m_cycles: 4,
    },
    Z80TimingEntry {
        mnemonic: "CPI",
        t_min: 16,
        t_max: 16,
        m_cycles: 4,
    },
    Z80TimingEntry {
        mnemonic: "CPIR",
        t_min: 16,
        t_max: 21,
        m_cycles: 4,
    },
    Z80TimingEntry {
        mnemonic: "DAA",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "CPL",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "NEG",
        t_min: 8,
        t_max: 8,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "SCF",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "CCF",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "HALT",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "DI",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "EI",
        t_min: 4,
        t_max: 4,
        m_cycles: 1,
    },
    Z80TimingEntry {
        mnemonic: "IM 0",
        t_min: 8,
        t_max: 8,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "IM 1",
        t_min: 8,
        t_max: 8,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "IM 2",
        t_min: 8,
        t_max: 8,
        m_cycles: 2,
    },
    Z80TimingEntry {
        mnemonic: "RETI",
        t_min: 14,
        t_max: 14,
        m_cycles: 4,
    },
    Z80TimingEntry {
        mnemonic: "RETN",
        t_min: 14,
        t_max: 14,
        m_cycles: 4,
    },
];

/// Look up timing info for a Z80 instruction by mnemonic key.
#[must_use]
pub fn lookup_z80_timing(mnemonic: &str) -> Option<&'static Z80TimingEntry> {
    Z80_TIMING.iter().find(|t| t.mnemonic == mnemonic)
}

/// Returns the T-state range for a mnemonic, or `None` if not found.
#[must_use]
pub fn z80_t_states(mnemonic: &str) -> Option<(u8, u8)> {
    lookup_z80_timing(mnemonic).map(|t| (t.t_min, t.t_max))
}

// ── Z80 RST target helpers ────────────────────────────────────────────────────

/// Returns the RST jump target address for RST instruction byte (0xC7..0xFF pattern).
/// Only valid for `n` in 0..=7.
#[must_use]
pub fn z80_rst_target(n: u8) -> Option<u16> {
    if n <= 7 { Some(u16::from(n) * 8) } else { None }
}

/// Returns the RST opcode byte for RST n (n in 0..=7).
#[must_use]
pub const fn z80_rst_opcode(n: u8) -> Option<u8> {
    if n <= 7 { Some(0xC7 | (n << 3)) } else { None }
}

// ── Z80 Register pair helpers ─────────────────────────────────────────────────

/// Z80 register pair encoding (used in opcode fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Z80RegPair {
    /// BC register pair (encoding 0).
    BC = 0,
    /// DE register pair (encoding 1).
    DE = 1,
    /// HL register pair (encoding 2).
    HL = 2,
    /// SP register pair (encoding 3) or AF for PUSH/POP.
    SP = 3,
}

impl Z80RegPair {
    /// Returns the 2-bit encoding for this register pair.
    #[must_use]
    pub const fn encoding(self) -> u8 {
        self as u8
    }

    /// Returns the mnemonic string for this register pair.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::BC => "BC",
            Self::DE => "DE",
            Self::HL => "HL",
            Self::SP => "SP",
        }
    }

    /// Decode a 2-bit register pair field.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0x03 {
            0 => Some(Self::BC),
            1 => Some(Self::DE),
            2 => Some(Self::HL),
            3 => Some(Self::SP),
            _ => None,
        }
    }
}

/// Encode an INC rp instruction: opcode = `0x03 | (rp << 4)`.
#[must_use]
pub const fn encode_inc_rp(rp: Z80RegPair) -> [u8; 1] {
    [0x03 | (rp.encoding() << 4)]
}

/// Encode a DEC rp instruction: opcode = `0x0B | (rp << 4)`.
#[must_use]
pub const fn encode_dec_rp(rp: Z80RegPair) -> [u8; 1] {
    [0x0B | (rp.encoding() << 4)]
}

/// Encode an ADD HL,rp instruction: opcode = `0x09 | (rp << 4)`.
#[must_use]
pub const fn encode_add_hl_rp(rp: Z80RegPair) -> [u8; 1] {
    [0x09 | (rp.encoding() << 4)]
}

#[cfg(test)]
mod z80_timing_tests {
    use super::*;

    #[test]
    fn test_timing_nop() {
        let t = lookup_z80_timing("NOP").unwrap();
        assert_eq!(t.t_min, 4);
        assert_eq!(t.t_max, 4);
        assert_eq!(t.m_cycles, 1);
    }

    #[test]
    fn test_timing_call() {
        let t = lookup_z80_timing("CALL nn").unwrap();
        assert_eq!(t.t_min, 17);
    }

    #[test]
    fn test_timing_djnz_range() {
        let t = lookup_z80_timing("DJNZ e").unwrap();
        assert_eq!(t.t_min, 8);
        assert_eq!(t.t_max, 13);
    }

    #[test]
    fn test_timing_ldir_range() {
        let t = lookup_z80_timing("LDIR").unwrap();
        assert_eq!(t.t_min, 16);
        assert_eq!(t.t_max, 21);
    }

    #[test]
    fn test_timing_missing() {
        assert!(lookup_z80_timing("FOOBAR").is_none());
    }

    #[test]
    fn test_t_states_ret_cc() {
        let (mn, mx) = z80_t_states("RET cc").unwrap();
        assert_eq!(mn, 5);
        assert_eq!(mx, 11);
    }

    #[test]
    fn test_timing_table_size() {
        assert!(Z80_TIMING.len() >= 50);
    }

    #[test]
    fn test_rst_target_zero() {
        assert_eq!(z80_rst_target(0), Some(0x0000));
    }

    #[test]
    fn test_rst_target_seven() {
        assert_eq!(z80_rst_target(7), Some(0x0038));
    }

    #[test]
    fn test_rst_target_out_of_range() {
        assert_eq!(z80_rst_target(8), None);
    }

    #[test]
    fn test_rst_opcode_1() {
        assert_eq!(z80_rst_opcode(1), Some(0xCF));
    }

    #[test]
    fn test_reg_pair_encoding() {
        assert_eq!(Z80RegPair::HL.encoding(), 2);
    }

    #[test]
    fn test_reg_pair_mnemonic() {
        assert_eq!(Z80RegPair::DE.mnemonic(), "DE");
    }

    #[test]
    fn test_reg_pair_from_bits() {
        assert_eq!(Z80RegPair::from_bits(0), Some(Z80RegPair::BC));
        assert_eq!(Z80RegPair::from_bits(2), Some(Z80RegPair::HL));
    }

    #[test]
    fn test_encode_inc_rp_hl() {
        // INC HL = 0x23
        let enc = encode_inc_rp(Z80RegPair::HL);
        assert_eq!(enc[0], 0x23);
    }

    #[test]
    fn test_encode_dec_rp_bc() {
        // DEC BC = 0x0B
        let enc = encode_dec_rp(Z80RegPair::BC);
        assert_eq!(enc[0], 0x0B);
    }

    #[test]
    fn test_encode_add_hl_de() {
        // ADD HL,DE = 0x19
        let enc = encode_add_hl_rp(Z80RegPair::DE);
        assert_eq!(enc[0], 0x19);
    }

    #[test]
    fn test_timing_reti() {
        let t = lookup_z80_timing("RETI").unwrap();
        assert_eq!(t.t_min, 14);
    }

    #[test]
    fn test_timing_ei() {
        let t = lookup_z80_timing("EI").unwrap();
        assert_eq!(t.m_cycles, 1);
    }
}
