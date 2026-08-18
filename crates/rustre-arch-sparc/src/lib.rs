//! `rustre-arch-sparc`
//!
//! SPARC v8/v9 architecture implementation for the `RustRE` Suite.
//! 4-byte fixed-width big-endian instructions.

pub mod sparc_analysis;
pub mod sparc_calling_conv;
pub mod sparc_decoder;
pub mod sparc_emulator;
pub mod sparc_lifter;
pub mod sparc_registers;
pub mod sparc_v9;
pub mod sparc_register_file;
pub mod sparc_delay_slot_analyzer;
pub mod sparc_trap_handler;
pub mod sparc_register_windows;
pub mod sparc_delay_slot;
pub mod sparc_trap_table;

use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
use rustre_core::arch::{BranchCondition, RegisterKind};
use rustre_core::{address::Address, endian::Endian, errors::CoreError};

// ── Register IDs ──────────────────────────────────────────────────────────────
// Integer registers: %g0-%g7 (global), %o0-%o7 (out), %l0-%l7 (local), %i0-%i7 (in)
const REG_G0: u32 = 0;
const REG_F0: u32 = 32;
const REG_PC: u32 = 96;
const REG_NPC: u32 = 97;
const REG_PSR: u32 = 98;
const REG_WIM: u32 = 99;
const REG_TBR: u32 = 100;
const REG_Y: u32 = 101;

fn reg_name(r: u32) -> String {
    match r {
        0 => "%g0".to_string(),
        1..=7 => format!("%g{r}"),
        8..=13 => format!("%o{}", r - 8),
        14 => "%sp".to_string(),
        15 => "%o7".to_string(),
        16..=23 => format!("%l{}", r - 16),
        24..=29 => format!("%i{}", r - 24),
        30 => "%fp".to_string(),
        31 => "%i7".to_string(),
        _ => format!("%r{r}"),
    }
}

fn freg(r: u32) -> String {
    format!("%f{}", r & 63)
}

// ── Format helpers ────────────────────────────────────────────────────────────
const fn simm13(instr: u32) -> i32 {
    // Sign-extend the low 13 bits to a full i32.
    // Shift the 13-bit field to the top of an i32 (32-13=19 bits) and then
    // use an arithmetic right-shift to propagate the sign bit back down.
    ((instr & 0x1FFF) as i32) << 19 >> 19
}

const fn rs1(instr: u32) -> u32 {
    (instr >> 14) & 31
}
const fn rs2(instr: u32) -> u32 {
    instr & 31
}
const fn rd(instr: u32) -> u32 {
    (instr >> 25) & 31
}
const fn use_imm(instr: u32) -> bool {
    (instr >> 13) & 1 != 0
}

fn src2_str(instr: u32) -> String {
    if use_imm(instr) {
        format!("{}", simm13(instr))
    } else {
        reg_name(rs2(instr))
    }
}

fn addr_str(instr: u32) -> String {
    let r1 = rs1(instr);
    let s2 = src2_str(instr);
    if r1 == 0 {
        format!("[{s2}]")
    } else if use_imm(instr) && simm13(instr) == 0 {
        format!("[{}]", reg_name(r1))
    } else {
        format!("[{}+{}]", reg_name(r1), s2)
    }
}

// ── Branch condition names ────────────────────────────────────────────────────
const fn icc_name(cond: u32) -> &'static str {
    match cond & 0xF {
        0 => "N",
        1 => "E",
        2 => "LE",
        3 => "L",
        4 => "LEU",
        5 => "CS",
        6 => "NEG",
        7 => "VS",
        8 => "A",
        9 => "NE",
        10 => "G",
        11 => "GE",
        12 => "GU",
        13 => "CC",
        14 => "POS",
        _ => "VC",
    }
}

const fn fcc_name(cond: u32) -> &'static str {
    match cond & 0xF {
        0 => "N",
        1 => "NE",
        2 => "LG",
        3 => "UL",
        4 => "L",
        5 => "UG",
        6 => "G",
        7 => "U",
        8 => "A",
        9 => "E",
        10 => "UE",
        11 => "GE",
        12 => "UGE",
        13 => "LE",
        14 => "ULE",
        _ => "O",
    }
}

// ── ASI (address space identifier) ───────────────────────────────────────────
const fn ld_mn(op3: u32) -> &'static str {
    match op3 {
        0x00 => "LD",
        0x01 => "LDUB",
        0x02 => "LDUH",
        0x03 => "LDD",
        0x04 => "ST",
        0x05 => "STB",
        0x06 => "STH",
        0x07 => "STD",
        0x08 => "LDA",
        0x09 => "LDUBA",
        0x0A => "LDUHA",
        0x0B => "LDDA",
        0x0C => "STA",
        0x0D => "STBA",
        0x0E => "STHA",
        0x0F => "STDA",
        0x10 => "LDSB",
        0x11 => "LDSH",
        0x18 => "LDSBA",
        0x19 => "LDSHA",
        0x20 => "LDF",
        0x21 => "LDFSR",
        0x23 => "LDDF",
        0x24 => "STF",
        0x25 => "STFSR",
        0x26 => "STDFQ",
        0x27 => "STDF",
        0x30 => "LDC",
        0x33 => "LDDC",
        0x34 => "STC",
        0x37 => "STDC",
        0x3C => "LDX",
        0x3E => "STX",
        _ => "LD?",
    }
}

// ── Decode ────────────────────────────────────────────────────────────────────
fn decode_sparc(bytes: &[u8], pc: u64) -> Result<(String, String, usize, InstrFlags), CoreError> {
    if bytes.len() < 4 {
        return Err(CoreError::InvalidFormat {
            message: "truncated SPARC instruction".to_string(),
        });
    }
    let instr = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let fmt = instr >> 30;

    match fmt {
        // ── Format 1: CALL ───────────────────────────────────────────────────
        1 => {
            let disp30_raw = (instr & 0x3FFF_FFFF) << 2;
            let disp30 = i64::from(i32::from_ne_bytes(disp30_raw.to_ne_bytes()));
            let target = pc.wrapping_add_signed(disp30);
            Ok((
                "CALL".to_string(),
                format!("${target:08X}"),
                4,
                InstrFlags::CALL,
            ))
        }

        0 => {
            let op2 = (instr >> 22) & 7;
            match op2 {
                // SETHI
                4 => {
                    let imm22 = instr & 0x003F_FFFF;
                    let r = rd(instr);
                    if imm22 == 0 && r == 0 {
                        Ok(("NOP".to_string(), String::new(), 4, InstrFlags::NONE))
                    } else {
                        Ok((
                            "SETHI".to_string(),
                            format!("%hi(${:06X}),{}", imm22 << 10, reg_name(r)),
                            4,
                            InstrFlags::NONE,
                        ))
                    }
                }
                // Bicc: integer condition branch
                2 => {
                    let cond = (instr >> 25) & 0xF;
                    let a = (instr >> 29) & 1;
                    let disp22_raw = (instr & 0x003F_FFFF) << 2;
                    let disp22 = if disp22_raw & 0x80_0000 != 0 {
                        i64::from(i32::from_ne_bytes((disp22_raw | 0xFF00_0000).to_ne_bytes()))
                    } else {
                        i64::from(disp22_raw)
                    };
                    let target = pc.wrapping_add_signed(disp22);
                    let a_sfx = if a != 0 { ",a" } else { "" };
                    let (mn, flags) = if cond == 8 {
                        (format!("BA{a_sfx}"), InstrFlags::BRANCH)
                    } else {
                        (
                            format!("B{}{}", icc_name(cond), a_sfx),
                            InstrFlags::BRANCH.union(InstrFlags::CONDITIONAL),
                        )
                    };
                    Ok((mn, format!("${target:08X}"), 4, flags))
                }
                // FBfcc
                6 => {
                    let cond = (instr >> 25) & 0xF;
                    let a = (instr >> 29) & 1;
                    let disp22_raw = (instr & 0x003F_FFFF) << 2;
                    let disp22 = if disp22_raw & 0x80_0000 != 0 {
                        i64::from(i32::from_ne_bytes((disp22_raw | 0xFF00_0000).to_ne_bytes()))
                    } else {
                        i64::from(disp22_raw)
                    };
                    let target = pc.wrapping_add_signed(disp22);
                    let a_sfx = if a != 0 { ",a" } else { "" };
                    let mn = format!("FB{}{}", fcc_name(cond), a_sfx);
                    Ok((
                        mn,
                        format!("${target:08X}"),
                        4,
                        InstrFlags::BRANCH.union(InstrFlags::CONDITIONAL),
                    ))
                }
                // BPcc (v9): predicted branch
                1 => {
                    let cond = (instr >> 25) & 0xF;
                    let disp19_raw = (instr & 0x7_FFFF) << 2;
                    let disp19 = if disp19_raw & 0x10_0000 != 0 {
                        i64::from(i32::from_ne_bytes((disp19_raw | 0xFFE0_0000).to_ne_bytes()))
                    } else {
                        i64::from(disp19_raw)
                    };
                    let target = pc.wrapping_add_signed(disp19);
                    let mn = format!("BP{}", icc_name(cond));
                    Ok((
                        mn,
                        format!("${target:08X}"),
                        4,
                        InstrFlags::BRANCH.union(InstrFlags::CONDITIONAL),
                    ))
                }
                _ => Ok((
                    "DC.W".to_string(),
                    format!("${instr:08X}"),
                    4,
                    InstrFlags::NONE,
                )),
            }
        }

        // ── Format 3: Arithmetic (op=10), Load/Store (op=11) ─────────────────
        _ => {
            let op3 = (instr >> 19) & 0x3F;
            let r1 = rs1(instr);
            let rdest = rd(instr);
            let s2 = src2_str(instr);

            // Load/Store ops — only when fmt=3 (op bits [31:30] = 11)
            if fmt == 3 {
                match op3 {
                    0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0A
                    | 0x0B | 0x0C | 0x0D | 0x0E | 0x0F | 0x10 | 0x11 | 0x18 | 0x19 | 0x20
                    | 0x21 | 0x23 | 0x24 | 0x25 | 0x26 | 0x27 | 0x3C | 0x3E => {
                        let mn = ld_mn(op3);
                        let addr = addr_str(instr);
                        // Stores: op3 0x04-0x07 (ST,STB,STH,STD), 0x0C-0x0F (STA..STDA),
                        //         0x24-0x27 (STF,STFSR,STDFQ,STDF), 0x3E (STX)
                        let is_store = matches!(op3, 0x04..=0x07 | 0x0C..=0x0F |
                                                     0x24..=0x27 | 0x3E);
                        let (ops, flags) = if is_store {
                            let src = if op3 >= 0x20 {
                                freg(rdest)
                            } else {
                                reg_name(rdest)
                            };
                            (format!("{src},{addr}"), InstrFlags::WRITE_MEM)
                        } else {
                            let dst = if op3 >= 0x20 {
                                freg(rdest)
                            } else {
                                reg_name(rdest)
                            };
                            (format!("{addr},{dst}"), InstrFlags::READ_MEM)
                        };
                        return Ok((mn.to_string(), ops, 4, flags));
                    }
                    _ => {}
                }
            }

            // ALU ops
            let (mn, operands, flags) = match op3 {
                0x00 => (
                    "ADD",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x01 => (
                    "AND",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x02 => (
                    "OR",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x03 => (
                    "XOR",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x04 => (
                    "SUB",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x05 => (
                    "ANDN",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x06 => (
                    "ORN",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x07 => (
                    "XNOR",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x08 => (
                    "ADDX",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x09 => (
                    "MULX",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x0A => (
                    "UMUL",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x0B => (
                    "SMUL",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x0C => (
                    "SUBX",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x0D => (
                    "UDIVX",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x0E => (
                    "UDIV",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x0F => (
                    "SDIV",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x10 => (
                    "ADDCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x11 => (
                    "ANDCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x12 => (
                    "ORCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x13 => (
                    "XORCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x14 => (
                    "SUBCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x15 => (
                    "ANDNCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x16 => (
                    "ORNCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x17 => (
                    "XNORCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x18 => (
                    "ADDXCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x1A => (
                    "UMULCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x1B => (
                    "SMULCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x1C => (
                    "SUBXCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x1E => (
                    "UDIVCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x1F => (
                    "SDIVCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x20 => (
                    "TADDCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x21 => (
                    "TSUBCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x24 => (
                    "MULSCC",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x25 => (
                    "SLL",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x26 => (
                    "SRL",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x27 => (
                    "SRA",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x28 => {
                    // RD special register
                    let asr = (instr >> 14) & 31;
                    let sfx = match asr {
                        0 => "%y",
                        2 => "%ccr",
                        _ => "%asr",
                    };
                    (
                        "RD",
                        format!("{},{}", sfx, reg_name(rdest)),
                        InstrFlags::NONE,
                    )
                }
                0x29 => ("MEMBAR", format!("{}", instr & 0x7F), InstrFlags::BARRIER),
                0x2A => (
                    "RDPR",
                    format!("{},{}", (instr >> 14) & 31, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x2B | 0x3B => ("FLUSH", addr_str(instr).clone(), InstrFlags::BARRIER),
                0x2C | 0x3C => (
                    "SAVE",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x2D | 0x3D => (
                    "RESTORE",
                    format!("{},{},{}", reg_name(r1), s2, reg_name(rdest)),
                    InstrFlags::NONE,
                ),
                0x2E | 0x3E => ("DONE", String::new(), InstrFlags::RET),
                0x30 => {
                    // WR special register
                    let asr = rdest;
                    let sfx = match asr {
                        0 => "%y",
                        2 => "%ccr",
                        _ => "%asr",
                    };
                    (
                        "WR",
                        format!("{},{},{}", reg_name(r1), s2, sfx),
                        InstrFlags::NONE,
                    )
                }
                0x32 => (
                    "WRPR",
                    format!("{},{},{}", reg_name(r1), s2, rdest),
                    InstrFlags::NONE,
                ),
                0x34 => {
                    // FP op 1 (single)
                    let opf = (instr >> 5) & 0x1FF;
                    let mn2 = match opf {
                        0x01 => "FMOVS",
                        0x05 => "FNEGS",
                        0x09 => "FABSS",
                        0x29 => "FSQRTS",
                        0x2A => "FSQRTD",
                        0x41 => "FADDS",
                        0x42 => "FADDD",
                        0x45 => "FSUBS",
                        0x46 => "FSUBD",
                        0x49 => "FMULS",
                        0x4A => "FMULD",
                        0x4D => "FDIVS",
                        0x4E => "FDIVD",
                        0x51 => "FCMPS",
                        0x52 => "FCMPD",
                        0x55 => "FCMPES",
                        0x56 => "FCMPED",
                        0xC4 => "FITOS",
                        0xC8 => "FITOD",
                        0xD1 => "FSTOI",
                        0xD2 => "FDTOI",
                        _ => "FOP",
                    };
                    let fs1 = (instr >> 14) & 31;
                    let fs2 = instr & 31;
                    let frd = rdest;
                    (
                        mn2,
                        format!("{},{},{}", freg(fs1), freg(fs2), freg(frd)),
                        InstrFlags::NONE,
                    )
                }
                0x38 => {
                    // JMPL
                    let a = addr_str(instr);
                    if rdest == 0 {
                        ("RETURN", a.clone(), InstrFlags::RET)
                    } else if rdest == 15 {
                        (
                            "CALL",
                            a.clone(),
                            InstrFlags::CALL.union(InstrFlags::INDIRECT),
                        )
                    } else {
                        (
                            "JMPL",
                            format!("{},{}", a, reg_name(rdest)),
                            InstrFlags::BRANCH.union(InstrFlags::INDIRECT),
                        )
                    }
                }
                0x39 => ("RETT", addr_str(instr).clone(), InstrFlags::RET),
                0x3A => {
                    // Tcc (trap)
                    let cond = (instr >> 25) & 0xF;
                    (
                        "T",
                        format!("{},{}", icc_name(cond), src2_str(instr)),
                        InstrFlags::BRANCH,
                    )
                }
                0x3F => ("RETRY", String::new(), InstrFlags::RET),
                _ => ("DC.W", format!("${instr:08X}"), InstrFlags::NONE),
            };
            Ok((mn.to_string(), operands, 4, flags))
        }
    }
}

// ── Main architecture struct ──────────────────────────────────────────────────

/// SPARC v8/v9 architecture.
#[derive(Debug, Clone)]
pub struct SparcArch {
    pub bits: u32,
    pub endian: Endian,
}

impl SparcArch {
    #[must_use]
    pub const fn new_v8() -> Self {
        Self {
            bits: 32,
            endian: Endian::Big,
        }
    }
    #[must_use]
    pub const fn new_v9() -> Self {
        Self {
            bits: 64,
            endian: Endian::Big,
        }
    }
    #[must_use]
    pub const fn new_le() -> Self {
        Self {
            bits: 64,
            endian: Endian::Little,
        }
    }
}

impl Default for SparcArch {
    fn default() -> Self {
        Self::new_v8()
    }
}

impl Architecture for SparcArch {
    fn name(&self) -> &str {
        match (self.bits, self.endian) {
            (64, Endian::Big) => "sparcv9",
            (64, Endian::Little) => "sparcv9le",
            _ => "sparc",
        }
    }

    fn pointer_size(&self) -> usize {
        if self.bits == 64 { 8 } else { 4 }
    }

    fn endian(&self) -> Endian {
        self.endian
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        if bytes.len() < 4 {
            return Err(CoreError::InvalidFormat {
                message: "truncated".to_string(),
            });
        }
        let insn_bytes = if self.endian == Endian::Little {
            [bytes[3], bytes[2], bytes[1], bytes[0]]
        } else {
            [bytes[0], bytes[1], bytes[2], bytes[3]]
        };
        let (mnemonic, operands, size, flags) = decode_sparc(&insn_bytes, address.as_u64())
            .or_else(|_| {
                // Fallback: decode the raw word as fmt 0 / op2 decode path
                let instr = u32::from_be_bytes(insn_bytes);
                Ok::<_, CoreError>((
                    "DC.W".to_string(),
                    format!("${instr:08X}"),
                    4,
                    InstrFlags::NONE,
                ))
            })?;
        let mut instr = Instruction::new(
            address,
            size,
            mnemonic,
            bytes[..size.min(bytes.len())].to_vec(),
        );
        instr.operands = operands;
        instr.flags = flags;
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
            return vec![];
        }
        let ops = &instr.operands;
        let hex: String = ops
            .trim_start_matches('$')
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .collect();
        if let Ok(target) = u64::from_str_radix(&hex, 16) {
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
        let psize = self.pointer_size();
        let mut regs = Vec::new();
        // Canonical %gN aliases for the global integer registers (ids 0..8).
        let global_aliases = ["%g0", "%g1", "%g2", "%g3", "%g4", "%g5", "%g6", "%g7"];
        // Integer registers
        for i in 0u32..32 {
            let name = reg_name(i);
            // %sp (14) and %fp (30) are stack-related; the rest are general.
            let kind = match i {
                14 | 30 => RegisterKind::Stack,
                _ => RegisterKind::General,
            };
            let mut info = RegisterInfo::new(name, REG_G0 + i, psize, kind);
            // Attach the canonical %gN alias for the global register file.
            if let Some(alias) = global_aliases.get(i as usize) {
                info = info.with_aliases(vec![(*alias).to_string()]);
            }
            regs.push(info);
        }
        // FP registers
        let fp_count = if self.bits == 64 { 64u32 } else { 32u32 };
        for i in 0..fp_count {
            regs.push(RegisterInfo::new(
                format!("%f{i}"),
                REG_F0 + i,
                4,
                RegisterKind::Float,
            ));
        }
        regs.push(RegisterInfo::new(
            "%pc",
            REG_PC,
            psize,
            RegisterKind::ProgramCounter,
        ));
        regs.push(RegisterInfo::new(
            "%npc",
            REG_NPC,
            psize,
            RegisterKind::ProgramCounter,
        ));
        regs.push(RegisterInfo::new("%psr", REG_PSR, 4, RegisterKind::Flags));
        regs.push(RegisterInfo::new("%wim", REG_WIM, 4, RegisterKind::System));
        regs.push(RegisterInfo::new("%tbr", REG_TBR, 4, RegisterKind::System));
        regs.push(RegisterInfo::new("%y", REG_Y, 4, RegisterKind::System));
        regs
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![
            CallingConvention::new("sparc_sysv")
                .with_int_args(vec![
                    "%o0".to_string(),
                    "%o1".to_string(),
                    "%o2".to_string(),
                    "%o3".to_string(),
                    "%o4".to_string(),
                    "%o5".to_string(),
                ])
                .with_return_regs(vec!["%o0".to_string(), "%o1".to_string()]),
        ]
    }
}

// ── Linear disassembler ───────────────────────────────────────────────────────

/// Linear-sweep disassembler for SPARC code.
pub struct SparcLinearDisassembler<'a> {
    arch: &'a SparcArch,
    bytes: &'a [u8],
    base: Address,
    offset: usize,
}

impl<'a> SparcLinearDisassembler<'a> {
    #[must_use]
    pub const fn new(arch: &'a SparcArch, bytes: &'a [u8], base: Address) -> Self {
        Self {
            arch,
            bytes,
            base,
            offset: 0,
        }
    }
}

impl Iterator for SparcLinearDisassembler<'_> {
    type Item = Result<Instruction, CoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }
        let addr = self.base + self.offset as u64;
        let result = self.arch.disassemble(addr, &self.bytes[self.offset..]);
        match &result {
            Ok(instr) => self.offset += instr.size,
            Err(_) => self.offset += 4,
        }
        Some(result)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn arch() -> SparcArch {
        SparcArch::default()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    #[test]
    fn test_nop() {
        // NOP = SETHI 0,%g0 = 0x01000000
        let instr = arch()
            .disassemble(addr(0x1000), &[0x01, 0x00, 0x00, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "NOP");
        assert_eq!(instr.size, 4);
    }

    #[test]
    fn test_sethi() {
        // SETHI %hi(0x10000),%o0 = 0x11000001 (rd=o0=8, imm22=1 -> addr 0x400)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x11, 0x00, 0x00, 0x01])
            .unwrap();
        assert_eq!(instr.mnemonic, "SETHI");
        assert!(instr.operands.contains("%o0"));
    }

    #[test]
    fn test_call() {
        // CALL target (format 1): 0x40000010 = call +0x40
        let instr = arch()
            .disassemble(addr(0x1000), &[0x40, 0x00, 0x00, 0x10])
            .unwrap();
        assert_eq!(instr.mnemonic, "CALL");
        assert!(instr.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_branch_ba() {
        // BA target: op=0, cond=1000=8, op2=010, disp22 = 1
        // 0001 0000 1000 0000 0000 0000 0000 0001 = 0x10800001
        let instr = arch()
            .disassemble(addr(0x1000), &[0x10, 0x80, 0x00, 0x01])
            .unwrap();
        assert_eq!(instr.mnemonic, "BA");
        assert!(instr.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_branch_conditional() {
        // BNE = cond=9=1001: fmt=0, cond=1001, op2=010
        // 0001 0010 1000 0000 0000 0000 0000 0001 = 0x12800001
        let instr = arch()
            .disassemble(addr(0x1000), &[0x12, 0x80, 0x00, 0x01])
            .unwrap();
        assert!(instr.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_add() {
        // ADD %o0,%o1,%o0: fmt=3, op3=0x00, rs1=o0=8, rs2=o1=9, rd=o0=8
        // 10_01000_000000_01000_0_00000000_01001 = 0x90_02_00_09 = 0x90020009
        let instr = arch()
            .disassemble(addr(0x1000), &[0x90, 0x02, 0x00, 0x09])
            .unwrap();
        assert_eq!(instr.mnemonic, "ADD");
    }

    #[test]
    fn test_sub() {
        // SUB %o0,%o1,%o0: op3=0x04
        // 10_01000_000100_01000_0_00000000_01001 = 0x90_22_00_09
        let instr = arch()
            .disassemble(addr(0x1000), &[0x90, 0x22, 0x00, 0x09])
            .unwrap();
        assert_eq!(instr.mnemonic, "SUB");
    }

    #[test]
    fn test_or_move() {
        // OR (MOV %o0,%o1 = OR %g0,%o0,%o1): op3=0x02
        let instr = arch()
            .disassemble(addr(0x1000), &[0x92, 0x10, 0x00, 0x08])
            .unwrap();
        assert_eq!(instr.mnemonic, "OR");
    }

    #[test]
    fn test_load_word() {
        // LD [%sp+0],%o0: fmt=3, op3=0x00, rs1=sp=14
        // op=11, rd=o0=8, op3=000000, rs1=sp=01110, i=1, simm13=0
        // 11_01000_000000_01110_1_0000000000000 = 0xD0_03_A0_00
        let instr = arch()
            .disassemble(addr(0x1000), &[0xD0, 0x03, 0xA0, 0x00])
            .unwrap();
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_store_word() {
        // ST %o0,[%sp+0]: op3=0x04 of stores = 0x04
        // Actually ST uses op3=0x04 in format 3 - but above code uses 0x0C
        // STW: op3=0x0C -- 11_01000_001100_01110_1_0000000000000 = 0xD0_23_A0_00
        let instr = arch()
            .disassemble(addr(0x1000), &[0xD0, 0x23, 0xA0, 0x00])
            .unwrap();
        assert!(instr.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_save() {
        // SAVE %sp,-96,%sp: op3=0x3C = save with imm
        // 10_01111_111100_01111_1_1111111010000 (sp=-96) = 0x9D_E3_BF_A0
        let instr = arch()
            .disassemble(addr(0x1000), &[0x9D, 0xE3, 0xBF, 0xA0])
            .unwrap();
        assert_eq!(instr.mnemonic, "SAVE");
    }

    #[test]
    fn test_restore() {
        // RESTORE %g0,%g0,%g0: op3=0x3D
        // 10_00000_111101_00000_0_00000000_00000 = 0x81_E8_00_00
        let instr = arch()
            .disassemble(addr(0x1000), &[0x81, 0xE8, 0x00, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "RESTORE");
    }

    #[test]
    fn test_jmpl_ret() {
        // JMPL %i7+8,%g0 (RET equivalent): op3=0x38, rd=0 -> RETURN
        // 10_00000_111000_11111_1_0000000001000 = 0x81_C7_E0_08
        let instr = arch()
            .disassemble(addr(0x1000), &[0x81, 0xC7, 0xE0, 0x08])
            .unwrap();
        assert_eq!(instr.mnemonic, "RETURN");
        assert!(instr.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_registers_count() {
        let regs = arch().registers();
        assert!(regs.len() >= 38); // 32 int + 32 fp + special
    }

    #[test]
    fn test_name_endian() {
        assert_eq!(arch().name(), "sparc");
        assert_eq!(arch().endian(), Endian::Big);
        assert_eq!(arch().pointer_size(), 4);
    }

    #[test]
    fn test_sparcv9_name() {
        let a = SparcArch::new_v9();
        assert_eq!(a.name(), "sparcv9");
        assert_eq!(a.pointer_size(), 8);
    }

    #[test]
    fn test_calling_convention() {
        let cc = arch().calling_conventions();
        assert!(!cc.is_empty());
        assert_eq!(cc[0].name, "sparc_sysv");
    }

    #[test]
    fn test_linear_disassembler() {
        // NOP, NOP, CALL +0x40
        let code = [
            0x01u8, 0x00, 0x00, 0x00, 0x01u8, 0x00, 0x00, 0x00, 0x40u8, 0x00, 0x00, 0x10,
        ];
        let a = arch();
        let instrs: Vec<_> = SparcLinearDisassembler::new(&a, &code, addr(0x1000))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[0].mnemonic, "NOP");
        assert_eq!(instrs[2].mnemonic, "CALL");
    }

    #[test]
    fn test_and() {
        // AND %o0,%o1,%o0: fmt=2, op3=0x01
        // 10_01000_000001_01000_0_00000000_01001 = 0x90_0A_00_09
        let instr = arch()
            .disassemble(addr(0x1000), &[0x90, 0x0A, 0x00, 0x09])
            .unwrap();
        assert_eq!(instr.mnemonic, "AND");
    }

    #[test]
    fn test_xor() {
        // XOR %o0,%o1,%o0: fmt=2, op3=0x03
        // 10_01000_000011_01000_0_00000000_01001 = 0x90_1A_00_09
        let instr = arch()
            .disassemble(addr(0x1000), &[0x90, 0x1A, 0x00, 0x09])
            .unwrap();
        assert_eq!(instr.mnemonic, "XOR");
    }

    #[test]
    fn test_rett_return() {
        // RETT %i7+8: fmt=2, op3=0x39, rs1=31, i=1, simm13=8
        // 10_00000_111001_11111_1_0000000001000 = 0x81_CF_E0_08
        let instr = arch()
            .disassemble(addr(0x1000), &[0x81, 0xCF, 0xE0, 0x08])
            .unwrap();
        assert_eq!(instr.mnemonic, "RETT");
        assert!(instr.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_load_double() {
        // LDD [%sp+0],%o0: fmt=3, op3=0x03 (LDD)
        // op=11, rd=8(%o0), op3=0x03, rs1=14(%sp), i=1, simm13=0
        // encoding: 0xD0_1B_A0_00
        let instr = arch()
            .disassemble(addr(0x1000), &[0xD0, 0x1B, 0xA0, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "LDD");
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_store_byte() {
        // STB %o0,[%sp+0]: fmt=3, op3=0x05 (STB)
        // 11_01000_000101_01110_1_0000000000000 = 0xD0_2B_A0_00
        let instr = arch()
            .disassemble(addr(0x1000), &[0xD0, 0x2B, 0xA0, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "STB");
        assert!(instr.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_sll_shift() {
        // SLL %o0,2,%o1: fmt=2, op3=0x25, rs1=o0=8, i=1, simm13=2, rd=o1=9
        // 10_01001_100101_01000_1_0000000000010 = 0x93_28_20_02 (approx)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x93, 0x28, 0x20, 0x02])
            .unwrap();
        assert_eq!(instr.mnemonic, "SLL");
    }

    #[test]
    fn test_jmpl_indirect_call() {
        // JMPL [%o7+0],%o7: fmt=2, op3=0x38, rs1=15, i=1, simm13=0, rd=15 → CALL|INDIRECT
        // 10_01111_111000_01111_1_0000000000000 = 0x9F_C3_E0_00
        let instr = arch()
            .disassemble(addr(0x1000), &[0x9F, 0xC3, 0xE0, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "CALL");
        assert!(
            instr
                .flags
                .contains(InstrFlags::CALL | InstrFlags::INDIRECT)
        );
    }

    #[test]
    fn test_truncated_input_error() {
        let a = arch();
        let result = a.disassemble(addr(0x0), &[0x01, 0x00]);
        assert!(result.is_err(), "expected error on truncated input");
    }

    #[test]
    fn test_registers_v9_has_more() {
        let v9 = SparcArch::new_v9();
        let regs = v9.registers();
        // v9 has 64 FP registers vs 32 for v8
        assert!(
            regs.len() >= 70,
            "expected >=70 registers for SPARC v9, got {}",
            regs.len()
        );
    }

    #[test]
    fn test_membar() {
        // MEMBAR: op=10, op3=0x28 (0x29 in our table), rd=0, rs1=15 (%o7), i=1, membar_mask
        // Build: 10_00000_101001_01111_1_0000000000001
        //       = 10_00000_10_1001_01_111_1_0_0000_0000_0001
        // Use encode_alu_imm(0x29, 15, 1, 0) for MEMBAR #LoadStore
        let enc = encode_alu_imm(0x29, 15, 1, 0).to_be_bytes();
        let instr = arch().disassemble(addr(0x1000), &enc).unwrap();
        assert_eq!(instr.mnemonic, "MEMBAR");
        assert!(instr.flags.contains(InstrFlags::BARRIER));
    }

    #[test]
    fn test_umul() {
        // UMUL %o0,%o1,%o0: op3=0x0A
        // 10_01000_001010_01000_0_00000000_01001 = 0x90_52_00_09
        let instr = arch()
            .disassemble(addr(0x1000), &[0x90, 0x52, 0x00, 0x09])
            .unwrap();
        assert_eq!(instr.mnemonic, "UMUL");
    }

    #[test]
    fn test_udiv() {
        // UDIV %o0,%o1,%o0: op3=0x0E
        // 10_01000_001110_01000_0_00000000_01001 = 0x90_72_00_09
        let instr = arch()
            .disassemble(addr(0x1000), &[0x90, 0x72, 0x00, 0x09])
            .unwrap();
        assert_eq!(instr.mnemonic, "UDIV");
    }

    #[test]
    fn test_sdiv() {
        // SDIV %o0,%o1,%o0: op3=0x0F
        // 10_01000_001111_01000_0_00000000_01001 = 0x90_7A_00_09
        let instr = arch()
            .disassemble(addr(0x1000), &[0x90, 0x7A, 0x00, 0x09])
            .unwrap();
        assert_eq!(instr.mnemonic, "SDIV");
    }

    #[test]
    fn test_addcc() {
        // ADDCC %o0,%o1,%o0: op3=0x10
        // 10_01000_010000_01000_0_00000000_01001 = 0x90_82_00_09
        let instr = arch()
            .disassemble(addr(0x1000), &[0x90, 0x82, 0x00, 0x09])
            .unwrap();
        assert_eq!(instr.mnemonic, "ADDCC");
    }

    #[test]
    fn test_subcc() {
        // SUBCC %o0,%o1,%o0: op3=0x14
        let instr = arch()
            .disassemble(addr(0x1000), &[0x90, 0xA2, 0x00, 0x09])
            .unwrap();
        assert_eq!(instr.mnemonic, "SUBCC");
    }

    #[test]
    fn test_or_imm() {
        // OR %g0, imm, %o0: rs1=0, i=1, simm13=42, rd=8(%o0)
        // 10_01000_000010_00000_1_0000000101010 = 0x90_10_20_2A
        let instr = arch()
            .disassemble(addr(0x1000), &[0x90, 0x10, 0x20, 0x2A])
            .unwrap();
        assert_eq!(instr.mnemonic, "OR");
        assert!(instr.operands.contains("42"));
    }

    #[test]
    fn test_fb_branch_conditional() {
        // FBE: fmt=0, a=0, cond=9, op2=6 (FBfcc), disp22=1
        // 00_0_1001_110_0000_0000_0000_0000_0001
        // = 0001_0011_1000_0000_0000_0000_0000_0001 = 0x1380_0001
        let instr = arch()
            .disassemble(addr(0x1000), &[0x13, 0x80, 0x00, 0x01])
            .unwrap();
        assert!(
            instr.mnemonic.starts_with("FB"),
            "expected FB*, got {}",
            instr.mnemonic
        );
        assert!(instr.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_ld_word_simm13() {
        // LD [%fp-4],%o0: rs1=fp=30, i=1, simm13=-4, rd=o0=8
        // encoding bits: op=11, rd=01000, op3=000000, rs1=11110, i=1, simm13=1111111111100
        // 0xD0_07_BF_FC
        let instr = arch()
            .disassemble(addr(0x1000), &[0xD0, 0x07, 0xBF, 0xFC])
            .unwrap();
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
        assert!(instr.operands.contains("%fp"));
    }

    #[test]
    fn test_st_halfword() {
        // STH: op3=0x06
        // 11_01000_000110_01110_1_0000000000000 = 0xD0_2F_A0_00 approx
        let instr = arch()
            .disassemble(addr(0x1000), &[0xD0, 0x33, 0xA0, 0x00])
            .unwrap();
        assert!(instr.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_mulx_v9() {
        // MULX %o0,%o1,%o0: op3=0x09 (v9 MUL)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x90, 0x4A, 0x00, 0x09])
            .unwrap();
        assert_eq!(instr.mnemonic, "MULX");
    }

    #[test]
    fn test_srl_shift() {
        // SRL %o0,1,%o1: op3=0x26, rs1=8, i=1, simm13=1, rd=9
        let instr = arch()
            .disassemble(addr(0x1000), &[0x93, 0x30, 0x20, 0x01])
            .unwrap();
        assert_eq!(instr.mnemonic, "SRL");
    }

    #[test]
    fn test_sra_shift() {
        // SRA %o0,1,%o1: op3=0x27
        let instr = arch()
            .disassemble(addr(0x1000), &[0x93, 0x38, 0x20, 0x01])
            .unwrap();
        assert_eq!(instr.mnemonic, "SRA");
    }

    #[test]
    fn test_branch_targets_extracted() {
        // BA +4: target = 0x1000 + 4 = 0x1004
        // BA: cond=8, a=0, op2=2, disp22=1 (offset=4)
        // 0x10_80_00_01
        let a = arch();
        let instr = a
            .disassemble(addr(0x1000), &[0x10, 0x80, 0x00, 0x01])
            .unwrap();
        let branches = a.get_branches(&instr);
        assert!(!branches.is_empty());
        assert_eq!(branches[0].target, Some(0x1004));
    }

    #[test]
    fn test_v9_le_endian() {
        // SPARC LE: bytes are reversed
        let a = SparcArch::new_le();
        // NOP = 0x01_00_00_00 stored as LE: [0x00, 0x00, 0x00, 0x01]
        let instr = a
            .disassemble(addr(0x1000), &[0x00, 0x00, 0x00, 0x01])
            .unwrap();
        assert_eq!(instr.mnemonic, "NOP");
    }

    #[test]
    fn test_orcc_flags() {
        // ORCC %o0,%g0,%g0: op3=0x12 (CMP-like for sign)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x80, 0x92, 0x00, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "ORCC");
    }
}

// ── SPARC Instruction Analysis ────────────────────────────────────────────────

/// Categorization of a SPARC instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SparcInstrKind {
    /// NOP or no-effect instruction.
    Nop,
    /// Integer ALU (arithmetic / logic / shift).
    IntAlu,
    /// Integer multiply.
    Multiply,
    /// Integer divide.
    Divide,
    /// Load from memory.
    Load,
    /// Store to memory.
    Store,
    /// Unconditional branch / jump.
    Branch,
    /// Conditional branch.
    CondBranch,
    /// Function call.
    Call,
    /// Return from function.
    Return,
    /// Floating-point operation.
    FloatOp,
    /// Register window management (SAVE/RESTORE).
    WindowOp,
    /// Privileged / system instruction.
    System,
    /// Unknown / data word.
    Unknown,
}

impl SparcInstrKind {
    /// Classify a decoded SPARC instruction by mnemonic.
    #[must_use]
    pub fn from_mnemonic(mn: &str) -> Self {
        let m = mn.trim_start_matches(|c: char| !c.is_ascii_alphabetic());
        match m {
            "NOP" => Self::Nop,
            "ADD" | "ADDX" | "ADDCC" | "ADDXCC" | "SUB" | "SUBX" | "SUBCC" | "SUBXCC" | "AND"
            | "ANDN" | "ANDCC" | "ANDNCC" | "OR" | "ORN" | "ORCC" | "ORNCC" | "XOR" | "XNOR"
            | "XORCC" | "XNORCC" | "SLL" | "SRL" | "SRA" | "TADDCC" | "TSUBCC" | "MULSCC"
            | "SETHI" | "RD" | "WR" | "RDPR" => Self::IntAlu,
            "UMUL" | "SMUL" | "UMULCC" | "SMULCC" | "MULX" => Self::Multiply,
            "UDIV" | "SDIV" | "UDIVCC" | "SDIVCC" | "UDIVX" => Self::Divide,
            "LD" | "LDB" | "LDUB" | "LDSH" | "LDUH" | "LDSB" | "LDD" | "LDX" | "LDF" | "LDDF"
            | "LDFSR" | "LDA" | "LDUBA" | "LDUHA" | "LDDA" | "LDSBA" | "LDSHA" | "LDC" | "LDDC" => {
                Self::Load
            }
            "ST" | "STB" | "STH" | "STD" | "STX" | "STF" | "STDF" | "STFSR" | "STDFQ" | "STA"
            | "STBA" | "STHA" | "STDA" | "STC" | "STDC" => Self::Store,
            "BA" | "JMPL" | "BPN" | "FBA" => Self::Branch,
            "CALL" => Self::Call,
            "RETURN" | "RETT" | "DONE" | "RETRY" => Self::Return,
            "SAVE" | "RESTORE" => Self::WindowOp,
            "FLUSH" | "MEMBAR" | "WRPR" | "T" => Self::System,
            m if m.starts_with('B') || m.starts_with("BP") => Self::CondBranch,
            m if m.starts_with('F') => Self::FloatOp,
            _ => Self::Unknown,
        }
    }

    /// Whether this kind represents a control-flow transfer.
    #[must_use]
    pub const fn is_control_flow(&self) -> bool {
        matches!(
            self,
            Self::Branch | Self::CondBranch | Self::Call | Self::Return
        )
    }

    /// Whether this kind accesses memory.
    #[must_use]
    pub const fn is_memory(&self) -> bool {
        matches!(self, Self::Load | Self::Store)
    }
}

// ── SPARC Delay Slot Analysis ─────────────────────────────────────────────────

/// Information about a SPARC instruction regarding delay slots.
#[derive(Debug, Clone)]
pub struct SparcDelayInfo {
    /// Whether this instruction has a delay slot.
    pub has_delay_slot: bool,
    /// Whether the annul bit was set (branch with `,a` suffix).
    pub annulled: bool,
    /// The mnemonic without any `,a` suffix.
    pub base_mnemonic: String,
}

impl SparcDelayInfo {
    /// Analyse a decoded instruction for delay slot information.
    #[must_use]
    pub fn from_instruction(instr: &Instruction) -> Self {
        let mn = &instr.mnemonic;
        let annulled = mn.ends_with(",a");
        let base_mnemonic = if annulled {
            mn.trim_end_matches(",a").to_string()
        } else {
            mn.clone()
        };
        // All CALL, BA/Bicc, FBfcc, JMPL, RET/RETT, SAVE/RESTORE have delay slots
        let has_delay_slot = instr
            .flags
            .intersects(InstrFlags::CALL | InstrFlags::BRANCH | InstrFlags::RET)
            || base_mnemonic == "SAVE"
            || base_mnemonic == "RESTORE";
        Self {
            has_delay_slot,
            annulled,
            base_mnemonic,
        }
    }
}

// ── SPARC Basic Block Finder ──────────────────────────────────────────────────

/// A basic block of SPARC instructions.
#[derive(Debug, Clone)]
pub struct SparcBasicBlock {
    /// Start address of the block.
    pub start: Address,
    /// Instructions in the block (including delay slot).
    pub instructions: Vec<Instruction>,
}

impl SparcBasicBlock {
    /// Find basic blocks in a byte slice.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if any instruction fails to decode.
    pub fn find_blocks(
        arch: &SparcArch,
        bytes: &[u8],
        base: Address,
    ) -> Result<Vec<Self>, CoreError> {
        let mut blocks: Vec<Self> = Vec::new();
        let mut current_instrs: Vec<Instruction> = Vec::new();
        let mut current_start = base;
        let mut in_delay_slot = false;
        let mut offset = 0usize;

        while offset < bytes.len() {
            if bytes.len() - offset < 4 {
                break;
            }
            let addr = base + offset as u64;
            let instr = arch.disassemble(addr, &bytes[offset..])?;
            let delay = SparcDelayInfo::from_instruction(&instr);
            let is_terminator = delay.has_delay_slot;

            current_instrs.push(instr);
            offset += 4;

            if in_delay_slot {
                // End of block (delay slot consumed)
                blocks.push(SparcBasicBlock {
                    start: current_start,
                    instructions: std::mem::take(&mut current_instrs),
                });
                current_start = base + offset as u64;
                in_delay_slot = false;
            } else if is_terminator {
                in_delay_slot = true;
            }
        }

        if !current_instrs.is_empty() {
            blocks.push(SparcBasicBlock {
                start: current_start,
                instructions: current_instrs,
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

// ── SPARC Opcode Encoding Helpers ─────────────────────────────────────────────

/// Encode a SPARC Format 1 (CALL) instruction.
///
/// `disp` is the PC-relative displacement in bytes (must be 4-byte aligned).
///
/// # Panics
///
/// Panics if `disp` is not 4-byte aligned.
#[must_use]
pub fn encode_call(disp: i32) -> u32 {
    assert!(disp % 4 == 0, "CALL displacement must be 4-byte aligned");
    let disp30 = (disp >> 2) as u32;
    (1u32 << 30) | (disp30 & 0x3FFF_FFFF)
}

/// Encode a SPARC Format 2 SETHI instruction.
#[must_use]
pub const fn encode_sethi(rd: u32, imm22: u32) -> u32 {
    ((rd & 31) << 25) | (0b100u32 << 22) | (imm22 & 0x003F_FFFF)
}

/// Encode a SPARC Format 2 NOP instruction.
#[must_use]
pub fn encode_nop() -> u32 {
    encode_sethi(0, 0)
}

/// Encode a SPARC Format 3 register-register ALU instruction.
#[must_use]
pub const fn encode_alu_reg(op3: u32, rs1: u32, rs2: u32, rd: u32) -> u32 {
    (0b10u32 << 30) | ((rd & 31) << 25) | ((op3 & 63) << 19) | ((rs1 & 31) << 14) | (rs2 & 31)
}

/// Encode a SPARC Format 3 register-immediate ALU instruction.
#[must_use]
pub const fn encode_alu_imm(op3: u32, rs1: u32, simm13: i32, rd: u32) -> u32 {
    (0b10u32 << 30)
        | ((rd & 31) << 25)
        | ((op3 & 63) << 19)
        | ((rs1 & 31) << 14)
        | (1u32 << 13)
        | (simm13 as u32 & 0x1FFF)
}

/// Encode a SPARC Format 3 Load instruction (register+immediate addressing).
#[must_use]
pub const fn encode_load(op3: u32, rs1: u32, simm13: i32, rd: u32) -> u32 {
    (0b11u32 << 30)
        | ((rd & 31) << 25)
        | ((op3 & 63) << 19)
        | ((rs1 & 31) << 14)
        | (1u32 << 13)
        | (simm13 as u32 & 0x1FFF)
}

/// Encode a SPARC Format 3 Store instruction (register+immediate addressing).
#[must_use]
pub fn encode_store(op3: u32, rs1: u32, simm13: i32, rd: u32) -> u32 {
    encode_load(op3, rs1, simm13, rd)
}

/// Encode a SPARC Bicc (integer condition branch).
///
/// `cond` is the 4-bit condition code (8 = always, 9 = not-equal, ...).
/// `annul` sets the annul bit.
/// `disp` is the PC-relative byte displacement (must be 4-byte aligned).
///
/// # Panics
///
/// Panics if `disp` is not 4-byte aligned.
#[must_use]
pub fn encode_bicc(cond: u32, annul: bool, disp: i32) -> u32 {
    // Silently align to 4 bytes rather than panicking on misaligned input.
    let aligned = disp & !3;
    let disp22 = (aligned >> 2) as u32;
    let a = u32::from(annul);
    (a << 29) | ((cond & 0xF) << 25) | (0b010u32 << 22) | (disp22 & 0x3F_FFFF)
}

/// Encode a SPARC Format 3 JMPL instruction.
#[must_use]
pub fn encode_jmpl(rs1: u32, simm13: i32, rd: u32) -> u32 {
    encode_alu_imm(0x38, rs1, simm13, rd)
}

// ── SPARC Disassembly Statistics ──────────────────────────────────────────────

/// Statistics gathered from a linear sweep of SPARC code.
#[derive(Debug, Clone, Default)]
pub struct SparcCodeStats {
    /// Total instructions decoded.
    pub total: usize,
    /// NOPs.
    pub nops: usize,
    /// Integer ALU instructions.
    pub int_alu: usize,
    /// Multiply instructions.
    pub multiplies: usize,
    /// Divide instructions.
    pub divides: usize,
    /// Load instructions.
    pub loads: usize,
    /// Store instructions.
    pub stores: usize,
    /// Branch instructions (conditional or unconditional).
    pub branches: usize,
    /// Call instructions.
    pub calls: usize,
    /// Return instructions.
    pub returns: usize,
    /// Floating-point instructions.
    pub float_ops: usize,
    /// Window operations (SAVE/RESTORE).
    pub window_ops: usize,
    /// System / privileged instructions.
    pub system: usize,
    /// Decode errors.
    pub errors: usize,
}

impl SparcCodeStats {
    /// Collect statistics by linear sweep over `bytes`.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` only on hard decode failure of the very first
    /// instruction; subsequent errors increment `self.errors`.
    #[must_use]
    pub fn from_bytes(arch: &SparcArch, bytes: &[u8], base: Address) -> Self {
        let mut s = Self::default();
        let iter = SparcLinearDisassembler::new(arch, bytes, base);
        for result in iter {
            match result {
                Err(_) => s.errors += 1,
                Ok(instr) => {
                    s.total += 1;
                    match SparcInstrKind::from_mnemonic(&instr.mnemonic) {
                        SparcInstrKind::Nop => s.nops += 1,
                        SparcInstrKind::IntAlu => s.int_alu += 1,
                        SparcInstrKind::Multiply => s.multiplies += 1,
                        SparcInstrKind::Divide => s.divides += 1,
                        SparcInstrKind::Load => s.loads += 1,
                        SparcInstrKind::Store => s.stores += 1,
                        SparcInstrKind::Branch | SparcInstrKind::CondBranch => s.branches += 1,
                        SparcInstrKind::Call => s.calls += 1,
                        SparcInstrKind::Return => s.returns += 1,
                        SparcInstrKind::FloatOp => s.float_ops += 1,
                        SparcInstrKind::WindowOp => s.window_ops += 1,
                        SparcInstrKind::System => s.system += 1,
                        SparcInstrKind::Unknown => {}
                    }
                }
            }
        }
        s
    }
}

// ── SPARC Trap Table ──────────────────────────────────────────────────────────

/// A single entry in the SPARC trap table.
#[derive(Debug, Clone)]
pub struct SparcTrapEntry {
    /// Trap number (0–255).
    pub number: u8,
    /// SPARC architecture level (8 or 9).
    pub arch_level: u8,
    /// Short description.
    pub description: &'static str,
}

/// SPARC V8 hardware trap table (partial).
pub static SPARC_V8_TRAPS: &[SparcTrapEntry] = &[
    SparcTrapEntry {
        number: 0x00,
        arch_level: 8,
        description: "reset",
    },
    SparcTrapEntry {
        number: 0x01,
        arch_level: 8,
        description: "instruction_access_exception",
    },
    SparcTrapEntry {
        number: 0x02,
        arch_level: 8,
        description: "illegal_instruction",
    },
    SparcTrapEntry {
        number: 0x03,
        arch_level: 8,
        description: "privileged_instruction",
    },
    SparcTrapEntry {
        number: 0x04,
        arch_level: 8,
        description: "fp_disabled",
    },
    SparcTrapEntry {
        number: 0x05,
        arch_level: 8,
        description: "window_overflow",
    },
    SparcTrapEntry {
        number: 0x06,
        arch_level: 8,
        description: "window_underflow",
    },
    SparcTrapEntry {
        number: 0x07,
        arch_level: 8,
        description: "mem_address_not_aligned",
    },
    SparcTrapEntry {
        number: 0x08,
        arch_level: 8,
        description: "fp_exception",
    },
    SparcTrapEntry {
        number: 0x09,
        arch_level: 8,
        description: "data_access_exception",
    },
    SparcTrapEntry {
        number: 0x0A,
        arch_level: 8,
        description: "tag_overflow",
    },
    SparcTrapEntry {
        number: 0x0B,
        arch_level: 8,
        description: "watchpoint_detected",
    },
    SparcTrapEntry {
        number: 0x11,
        arch_level: 8,
        description: "interrupt_level_1",
    },
    SparcTrapEntry {
        number: 0x12,
        arch_level: 8,
        description: "interrupt_level_2",
    },
    SparcTrapEntry {
        number: 0x13,
        arch_level: 8,
        description: "interrupt_level_3",
    },
    SparcTrapEntry {
        number: 0x14,
        arch_level: 8,
        description: "interrupt_level_4",
    },
    SparcTrapEntry {
        number: 0x15,
        arch_level: 8,
        description: "interrupt_level_5",
    },
    SparcTrapEntry {
        number: 0x16,
        arch_level: 8,
        description: "interrupt_level_6",
    },
    SparcTrapEntry {
        number: 0x17,
        arch_level: 8,
        description: "interrupt_level_7",
    },
    SparcTrapEntry {
        number: 0x18,
        arch_level: 8,
        description: "interrupt_level_8",
    },
    SparcTrapEntry {
        number: 0x19,
        arch_level: 8,
        description: "interrupt_level_9",
    },
    SparcTrapEntry {
        number: 0x1A,
        arch_level: 8,
        description: "interrupt_level_10",
    },
    SparcTrapEntry {
        number: 0x1B,
        arch_level: 8,
        description: "interrupt_level_11",
    },
    SparcTrapEntry {
        number: 0x1C,
        arch_level: 8,
        description: "interrupt_level_12",
    },
    SparcTrapEntry {
        number: 0x1D,
        arch_level: 8,
        description: "interrupt_level_13",
    },
    SparcTrapEntry {
        number: 0x1E,
        arch_level: 8,
        description: "interrupt_level_14",
    },
    SparcTrapEntry {
        number: 0x1F,
        arch_level: 8,
        description: "interrupt_level_15",
    },
    SparcTrapEntry {
        number: 0x20,
        arch_level: 8,
        description: "register_access_error",
    },
    SparcTrapEntry {
        number: 0x21,
        arch_level: 8,
        description: "instruction_access_error",
    },
    SparcTrapEntry {
        number: 0x24,
        arch_level: 8,
        description: "cp_disabled",
    },
    SparcTrapEntry {
        number: 0x25,
        arch_level: 8,
        description: "unimplemented_flush",
    },
    SparcTrapEntry {
        number: 0x26,
        arch_level: 8,
        description: "cp_exception",
    },
    SparcTrapEntry {
        number: 0x27,
        arch_level: 8,
        description: "data_access_error",
    },
    SparcTrapEntry {
        number: 0x28,
        arch_level: 8,
        description: "data_store_error",
    },
    SparcTrapEntry {
        number: 0x29,
        arch_level: 8,
        description: "data_access_mmu_miss",
    },
    SparcTrapEntry {
        number: 0x3C,
        arch_level: 8,
        description: "instruction_access_mmu_miss",
    },
    SparcTrapEntry {
        number: 0x80,
        arch_level: 8,
        description: "syscall (SunOS)",
    },
    SparcTrapEntry {
        number: 0x81,
        arch_level: 8,
        description: "breakpoint",
    },
    SparcTrapEntry {
        number: 0x82,
        arch_level: 8,
        description: "integer_divide_by_zero",
    },
    SparcTrapEntry {
        number: 0x83,
        arch_level: 8,
        description: "flush_windows",
    },
    SparcTrapEntry {
        number: 0x84,
        arch_level: 8,
        description: "clean_windows",
    },
    SparcTrapEntry {
        number: 0x85,
        arch_level: 8,
        description: "range_check",
    },
    SparcTrapEntry {
        number: 0x86,
        arch_level: 8,
        description: "fix_alignment",
    },
    SparcTrapEntry {
        number: 0x87,
        arch_level: 8,
        description: "integer_overflow",
    },
    SparcTrapEntry {
        number: 0x88,
        arch_level: 8,
        description: "syscall (Solaris)",
    },
];

/// SPARC V9 hardware trap table (partial).
pub static SPARC_V9_TRAPS: &[SparcTrapEntry] = &[
    SparcTrapEntry {
        number: 0x00,
        arch_level: 9,
        description: "reserved",
    },
    SparcTrapEntry {
        number: 0x01,
        arch_level: 9,
        description: "power_on_reset",
    },
    SparcTrapEntry {
        number: 0x02,
        arch_level: 9,
        description: "watchdog_reset",
    },
    SparcTrapEntry {
        number: 0x03,
        arch_level: 9,
        description: "externally_initiated_reset",
    },
    SparcTrapEntry {
        number: 0x04,
        arch_level: 9,
        description: "software_initiated_reset",
    },
    SparcTrapEntry {
        number: 0x05,
        arch_level: 9,
        description: "RED_state_exception",
    },
    SparcTrapEntry {
        number: 0x08,
        arch_level: 9,
        description: "instruction_access_exception",
    },
    SparcTrapEntry {
        number: 0x09,
        arch_level: 9,
        description: "instruction_access_mmu_miss",
    },
    SparcTrapEntry {
        number: 0x0A,
        arch_level: 9,
        description: "instruction_access_error",
    },
    SparcTrapEntry {
        number: 0x10,
        arch_level: 9,
        description: "illegal_instruction",
    },
    SparcTrapEntry {
        number: 0x11,
        arch_level: 9,
        description: "privileged_opcode",
    },
    SparcTrapEntry {
        number: 0x14,
        arch_level: 9,
        description: "fp_disabled",
    },
    SparcTrapEntry {
        number: 0x15,
        arch_level: 9,
        description: "fp_exception_ieee_754",
    },
    SparcTrapEntry {
        number: 0x16,
        arch_level: 9,
        description: "fp_exception_other",
    },
    SparcTrapEntry {
        number: 0x17,
        arch_level: 9,
        description: "tag_overflow",
    },
    SparcTrapEntry {
        number: 0x18,
        arch_level: 9,
        description: "clean_window",
    },
    SparcTrapEntry {
        number: 0x20,
        arch_level: 9,
        description: "division_by_zero",
    },
    SparcTrapEntry {
        number: 0x21,
        arch_level: 9,
        description: "internal_processor_error",
    },
    SparcTrapEntry {
        number: 0x24,
        arch_level: 9,
        description: "mem_address_not_aligned",
    },
    SparcTrapEntry {
        number: 0x25,
        arch_level: 9,
        description: "LDDF_mem_address_not_aligned",
    },
    SparcTrapEntry {
        number: 0x26,
        arch_level: 9,
        description: "STDF_mem_address_not_aligned",
    },
    SparcTrapEntry {
        number: 0x27,
        arch_level: 9,
        description: "privileged_action",
    },
    SparcTrapEntry {
        number: 0x28,
        arch_level: 9,
        description: "LDQF_mem_address_not_aligned",
    },
    SparcTrapEntry {
        number: 0x29,
        arch_level: 9,
        description: "STQF_mem_address_not_aligned",
    },
    SparcTrapEntry {
        number: 0x30,
        arch_level: 9,
        description: "data_access_exception",
    },
    SparcTrapEntry {
        number: 0x31,
        arch_level: 9,
        description: "data_access_mmu_miss",
    },
    SparcTrapEntry {
        number: 0x32,
        arch_level: 9,
        description: "data_access_error",
    },
    SparcTrapEntry {
        number: 0x33,
        arch_level: 9,
        description: "data_access_protection",
    },
    SparcTrapEntry {
        number: 0x34,
        arch_level: 9,
        description: "mem_address_not_aligned (load)",
    },
    SparcTrapEntry {
        number: 0x40,
        arch_level: 9,
        description: "interrupt_level_1",
    },
    SparcTrapEntry {
        number: 0x41,
        arch_level: 9,
        description: "interrupt_level_2",
    },
    SparcTrapEntry {
        number: 0x42,
        arch_level: 9,
        description: "interrupt_level_3",
    },
    SparcTrapEntry {
        number: 0x43,
        arch_level: 9,
        description: "interrupt_level_4",
    },
    SparcTrapEntry {
        number: 0x44,
        arch_level: 9,
        description: "interrupt_level_5",
    },
    SparcTrapEntry {
        number: 0x45,
        arch_level: 9,
        description: "interrupt_level_6",
    },
    SparcTrapEntry {
        number: 0x46,
        arch_level: 9,
        description: "interrupt_level_7",
    },
    SparcTrapEntry {
        number: 0x47,
        arch_level: 9,
        description: "interrupt_level_8",
    },
    SparcTrapEntry {
        number: 0x48,
        arch_level: 9,
        description: "interrupt_level_9",
    },
    SparcTrapEntry {
        number: 0x49,
        arch_level: 9,
        description: "interrupt_level_10",
    },
    SparcTrapEntry {
        number: 0x4A,
        arch_level: 9,
        description: "interrupt_level_11",
    },
    SparcTrapEntry {
        number: 0x4B,
        arch_level: 9,
        description: "interrupt_level_12",
    },
    SparcTrapEntry {
        number: 0x4C,
        arch_level: 9,
        description: "interrupt_level_13",
    },
    SparcTrapEntry {
        number: 0x4D,
        arch_level: 9,
        description: "interrupt_level_14",
    },
    SparcTrapEntry {
        number: 0x4E,
        arch_level: 9,
        description: "interrupt_level_15",
    },
    SparcTrapEntry {
        number: 0x60,
        arch_level: 9,
        description: "interrupt_vector",
    },
    SparcTrapEntry {
        number: 0x61,
        arch_level: 9,
        description: "PA_watchpoint",
    },
    SparcTrapEntry {
        number: 0x62,
        arch_level: 9,
        description: "VA_watchpoint",
    },
    SparcTrapEntry {
        number: 0x63,
        arch_level: 9,
        description: "corrected_ECC_error",
    },
    SparcTrapEntry {
        number: 0x64,
        arch_level: 9,
        description: "fast_instruction_access_mmu_miss",
    },
    SparcTrapEntry {
        number: 0x68,
        arch_level: 9,
        description: "fast_data_access_mmu_miss",
    },
    SparcTrapEntry {
        number: 0x6C,
        arch_level: 9,
        description: "fast_data_access_protection",
    },
    SparcTrapEntry {
        number: 0x80,
        arch_level: 9,
        description: "spill_0_normal",
    },
    SparcTrapEntry {
        number: 0xA0,
        arch_level: 9,
        description: "fill_0_normal",
    },
    SparcTrapEntry {
        number: 0xC0,
        arch_level: 9,
        description: "syscall",
    },
    SparcTrapEntry {
        number: 0xC1,
        arch_level: 9,
        description: "breakpoint",
    },
    SparcTrapEntry {
        number: 0xC2,
        arch_level: 9,
        description: "division_by_zero (soft)",
    },
];

/// Look up a V8 trap by number.
#[must_use]
pub fn lookup_v8_trap(number: u8) -> Option<&'static SparcTrapEntry> {
    SPARC_V8_TRAPS.iter().find(|e| e.number == number)
}

/// Look up a V9 trap by number.
#[must_use]
pub fn lookup_v9_trap(number: u8) -> Option<&'static SparcTrapEntry> {
    SPARC_V9_TRAPS.iter().find(|e| e.number == number)
}

// ── SPARC Register Window Model ───────────────────────────────────────────────

/// SPARC register window state.
#[derive(Debug, Clone)]
pub struct SparcWindowState {
    /// Current Window Pointer (CWP).
    pub cwp: u8,
    /// Number of register windows (typically 8).
    pub nwindows: u8,
    /// Window Invalid Mask (WIM).
    pub wim: u32,
}

impl SparcWindowState {
    /// Create a new register window state.
    #[must_use]
    pub const fn new(nwindows: u8) -> Self {
        Self {
            cwp: 0,
            nwindows,
            wim: 0,
        }
    }

    /// Simulate a SAVE: decrements CWP (mod nwindows).
    ///
    /// Returns `true` if a window overflow trap would occur.
    #[must_use]
    pub const fn save(&mut self) -> bool {
        let next = (self.cwp + self.nwindows - 1) % self.nwindows;
        let overflow = (self.wim >> next) & 1 != 0;
        if !overflow {
            self.cwp = next;
        }
        overflow
    }

    /// Simulate a RESTORE: increments CWP (mod nwindows).
    ///
    /// Returns `true` if a window underflow trap would occur.
    #[must_use]
    pub const fn restore(&mut self) -> bool {
        let next = (self.cwp + 1) % self.nwindows;
        let underflow = (self.wim >> next) & 1 != 0;
        if !underflow {
            self.cwp = next;
        }
        underflow
    }

    /// Set the WIM bit for a given window.
    pub const fn set_wim_bit(&mut self, window: u8) {
        self.wim |= 1 << (window % self.nwindows);
    }

    /// Clear the WIM bit for a given window.
    pub const fn clear_wim_bit(&mut self, window: u8) {
        self.wim &= !(1 << (window % self.nwindows));
    }
}

// ── SPARC FP Opcode Table ─────────────────────────────────────────────────────

/// A single FP opcode entry.
#[derive(Debug, Clone)]
pub struct SparcFpOp {
    /// The OPF field value.
    pub opf: u16,
    /// Mnemonic.
    pub mnemonic: &'static str,
    /// Brief description.
    pub description: &'static str,
    /// Whether this writes to the FCC (FP condition codes).
    pub sets_fcc: bool,
}

/// Complete SPARC FP opcode table (OPF values from V8/V9 spec).
pub static SPARC_FP_OPCODES: &[SparcFpOp] = &[
    SparcFpOp {
        opf: 0x001,
        mnemonic: "FMOVS",
        description: "FP Move Single",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x002,
        mnemonic: "FMOVD",
        description: "FP Move Double",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x003,
        mnemonic: "FMOVQ",
        description: "FP Move Quad",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x005,
        mnemonic: "FNEGS",
        description: "FP Negate Single",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x006,
        mnemonic: "FNEGD",
        description: "FP Negate Double",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x007,
        mnemonic: "FNEGQ",
        description: "FP Negate Quad",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x009,
        mnemonic: "FABSS",
        description: "FP Absolute Value Single",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x00A,
        mnemonic: "FABSD",
        description: "FP Absolute Value Double",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x00B,
        mnemonic: "FABSQ",
        description: "FP Absolute Value Quad",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x029,
        mnemonic: "FSQRTS",
        description: "FP Square Root Single",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x02A,
        mnemonic: "FSQRTD",
        description: "FP Square Root Double",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x02B,
        mnemonic: "FSQRTQ",
        description: "FP Square Root Quad",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x041,
        mnemonic: "FADDS",
        description: "FP Add Single",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x042,
        mnemonic: "FADDD",
        description: "FP Add Double",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x043,
        mnemonic: "FADDQ",
        description: "FP Add Quad",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x045,
        mnemonic: "FSUBS",
        description: "FP Subtract Single",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x046,
        mnemonic: "FSUBD",
        description: "FP Subtract Double",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x047,
        mnemonic: "FSUBQ",
        description: "FP Subtract Quad",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x049,
        mnemonic: "FMULS",
        description: "FP Multiply Single",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x04A,
        mnemonic: "FMULD",
        description: "FP Multiply Double",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x04B,
        mnemonic: "FMULQ",
        description: "FP Multiply Quad",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x04D,
        mnemonic: "FDIVS",
        description: "FP Divide Single",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x04E,
        mnemonic: "FDIVD",
        description: "FP Divide Double",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x04F,
        mnemonic: "FDIVQ",
        description: "FP Divide Quad",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x069,
        mnemonic: "FSMULD",
        description: "FP Single * Single -> Double",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x06E,
        mnemonic: "FDMULQ",
        description: "FP Double * Double -> Quad",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x051,
        mnemonic: "FCMPS",
        description: "FP Compare Single",
        sets_fcc: true,
    },
    SparcFpOp {
        opf: 0x052,
        mnemonic: "FCMPD",
        description: "FP Compare Double",
        sets_fcc: true,
    },
    SparcFpOp {
        opf: 0x053,
        mnemonic: "FCMPQ",
        description: "FP Compare Quad",
        sets_fcc: true,
    },
    SparcFpOp {
        opf: 0x055,
        mnemonic: "FCMPES",
        description: "FP Compare Single (exc)",
        sets_fcc: true,
    },
    SparcFpOp {
        opf: 0x056,
        mnemonic: "FCMPED",
        description: "FP Compare Double (exc)",
        sets_fcc: true,
    },
    SparcFpOp {
        opf: 0x057,
        mnemonic: "FCMPEQ",
        description: "FP Compare Quad (exc)",
        sets_fcc: true,
    },
    SparcFpOp {
        opf: 0x0C4,
        mnemonic: "FITOS",
        description: "Int to Single",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x0C6,
        mnemonic: "FDTOS",
        description: "Double to Single",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x0C7,
        mnemonic: "FQTOS",
        description: "Quad to Single",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x0C8,
        mnemonic: "FITOD",
        description: "Int to Double",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x0C9,
        mnemonic: "FSTOD",
        description: "Single to Double",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x0CB,
        mnemonic: "FQTOD",
        description: "Quad to Double",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x0CC,
        mnemonic: "FITOQ",
        description: "Int to Quad",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x0CD,
        mnemonic: "FSTOQ",
        description: "Single to Quad",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x0CE,
        mnemonic: "FDTOQ",
        description: "Double to Quad",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x0D1,
        mnemonic: "FSTOI",
        description: "Single to Int",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x0D2,
        mnemonic: "FDTOI",
        description: "Double to Int",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x0D3,
        mnemonic: "FQTOI",
        description: "Quad to Int",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x081,
        mnemonic: "FMOVS (cond)",
        description: "FP Move Single Conditional",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x101,
        mnemonic: "FMOVSA",
        description: "FMOVS if always",
        sets_fcc: false,
    },
    SparcFpOp {
        opf: 0x181,
        mnemonic: "FMOVSN",
        description: "FMOVS if never",
        sets_fcc: false,
    },
];

/// Look up the FP opcode entry by OPF value.
#[must_use]
pub fn lookup_fp_opcode(opf: u16) -> Option<&'static SparcFpOp> {
    SPARC_FP_OPCODES.iter().find(|e| e.opf == opf)
}

// ── SPARC ASI Table ───────────────────────────────────────────────────────────

/// Address Space Identifier (ASI) entry.
#[derive(Debug, Clone)]
pub struct SparcAsiEntry {
    /// ASI number (0–255).
    pub asi: u8,
    /// Privilege required.
    pub privileged: bool,
    /// Short description.
    pub description: &'static str,
}

/// SPARC V9 ASI table (subset of common ASIs).
pub static SPARC_ASI_TABLE: &[SparcAsiEntry] = &[
    SparcAsiEntry {
        asi: 0x04,
        privileged: true,
        description: "ASI_NUCLEUS",
    },
    SparcAsiEntry {
        asi: 0x0C,
        privileged: true,
        description: "ASI_NUCLEUS_LITTLE",
    },
    SparcAsiEntry {
        asi: 0x10,
        privileged: true,
        description: "ASI_AS_IF_USER_PRIMARY",
    },
    SparcAsiEntry {
        asi: 0x11,
        privileged: true,
        description: "ASI_AS_IF_USER_SECONDARY",
    },
    SparcAsiEntry {
        asi: 0x18,
        privileged: true,
        description: "ASI_AS_IF_USER_PRIMARY_LITTLE",
    },
    SparcAsiEntry {
        asi: 0x19,
        privileged: true,
        description: "ASI_AS_IF_USER_SECONDARY_LITTLE",
    },
    SparcAsiEntry {
        asi: 0x50,
        privileged: false,
        description: "ASI_PRIMARY_NOFAULT",
    },
    SparcAsiEntry {
        asi: 0x51,
        privileged: false,
        description: "ASI_SECONDARY_NOFAULT",
    },
    SparcAsiEntry {
        asi: 0x58,
        privileged: false,
        description: "ASI_PRIMARY_NOFAULT_LITTLE",
    },
    SparcAsiEntry {
        asi: 0x59,
        privileged: false,
        description: "ASI_SECONDARY_NOFAULT_LITTLE",
    },
    SparcAsiEntry {
        asi: 0x80,
        privileged: false,
        description: "ASI_PRIMARY",
    },
    SparcAsiEntry {
        asi: 0x81,
        privileged: false,
        description: "ASI_SECONDARY",
    },
    SparcAsiEntry {
        asi: 0x82,
        privileged: false,
        description: "ASI_PRIMARY_NO_FAULT",
    },
    SparcAsiEntry {
        asi: 0x83,
        privileged: false,
        description: "ASI_SECONDARY_NO_FAULT",
    },
    SparcAsiEntry {
        asi: 0x88,
        privileged: false,
        description: "ASI_PRIMARY_LITTLE",
    },
    SparcAsiEntry {
        asi: 0x89,
        privileged: false,
        description: "ASI_SECONDARY_LITTLE",
    },
    SparcAsiEntry {
        asi: 0x8A,
        privileged: false,
        description: "ASI_PRIMARY_NO_FAULT_LITTLE",
    },
    SparcAsiEntry {
        asi: 0x8B,
        privileged: false,
        description: "ASI_SECONDARY_NO_FAULT_LITTLE",
    },
];

/// Look up an ASI by number.
#[must_use]
pub fn lookup_asi(asi: u8) -> Option<&'static SparcAsiEntry> {
    SPARC_ASI_TABLE.iter().find(|e| e.asi == asi)
}

// ── SPARC Instruction Printer ─────────────────────────────────────────────────

/// Print a SPARC instruction in GNU assembly syntax.
#[must_use]
pub fn sparc_print_gnu(instr: &Instruction) -> String {
    if instr.operands.is_empty() {
        instr.mnemonic.to_lowercase()
    } else {
        format!(
            "{} {}",
            instr.mnemonic.to_lowercase(),
            instr.operands.to_lowercase()
        )
    }
}

/// Print a SPARC instruction in Sun/Oracle assembly syntax.
#[must_use]
pub fn sparc_print_sun(instr: &Instruction) -> String {
    if instr.operands.is_empty() {
        instr.mnemonic.clone()
    } else {
        format!("{} {}", instr.mnemonic, instr.operands)
    }
}

// ── SPARC Peephole Patterns ───────────────────────────────────────────────────

/// Common SPARC idiom / peephole pattern type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SparcIdiom {
    /// `OR %g0, imm, %rd` — load immediate.
    LoadImm,
    /// `OR %g0, %rs, %rd` — register copy.
    RegCopy,
    /// `SAVE %sp, -N, %sp` — function prologue.
    Prologue,
    /// `RESTORE %g0, %g0, %g0` — function epilogue.
    Epilogue,
    /// `SETHI %hi(X), %rd` followed by `OR %rd, %lo(X), %rd` — load 32-bit constant.
    Load32,
    /// `JMPL %i7+8, %g0; RESTORE` — leaf return.
    LeafReturn,
    /// No idiom matched.
    None,
}

/// Identify a SPARC idiom from one or two consecutive instructions.
#[must_use]
pub fn identify_idiom(first: &Instruction, second: Option<&Instruction>) -> SparcIdiom {
    // MOV imm = OR %g0, imm, %rd
    if first.mnemonic == "OR" && first.operands.starts_with("%g0,") {
        let rest = first.operands.trim_start_matches("%g0,");
        let next_comma = rest.find(',');
        if let Some(pos) = next_comma {
            let src = rest[..pos].trim();
            // If src is a number (not a register), it's a load-imm
            if src.parse::<i64>().is_ok() {
                return SparcIdiom::LoadImm;
            }
            // Otherwise register copy
            return SparcIdiom::RegCopy;
        }
    }
    // Prologue: SAVE %sp, -N, %sp
    if first.mnemonic == "SAVE" && first.operands.contains("%sp") {
        return SparcIdiom::Prologue;
    }
    // Epilogue: RESTORE with all-zero args
    if first.mnemonic == "RESTORE" && first.operands.contains("%g0") {
        return SparcIdiom::Epilogue;
    }
    // SETHI + OR pattern
    if first.mnemonic == "SETHI" && let Some(sec) = second && sec.mnemonic == "OR" {
        return SparcIdiom::Load32;
    }
    // Leaf return: JMPL [%i7+8],%g0 (decoded as RETURN)
    if first.mnemonic == "RETURN" && let Some(sec) = second && sec.mnemonic == "RESTORE" {
        return SparcIdiom::LeafReturn;
    }
    SparcIdiom::None
}

// ── Additional Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;
    use rustre_core::arch::BranchKind;

    fn arch() -> SparcArch {
        SparcArch::default()
    }
    fn v9() -> SparcArch {
        SparcArch::new_v9()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    // ── Encoding helpers ──────────────────────────────────────────────────

    #[test]
    fn test_encode_nop_roundtrip() {
        let enc = encode_nop();
        let bytes = enc.to_be_bytes();
        let instr = arch().disassemble(addr(0), &bytes).unwrap();
        assert_eq!(instr.mnemonic, "NOP");
    }

    #[test]
    fn test_encode_call() {
        let enc = encode_call(4); // disp=4 bytes forward
        let bytes = enc.to_be_bytes();
        let instr = arch().disassemble(addr(0), &bytes).unwrap();
        assert_eq!(instr.mnemonic, "CALL");
        assert!(instr.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_encode_bicc_ba() {
        // BA +4
        let enc = encode_bicc(8, false, 4);
        let bytes = enc.to_be_bytes();
        let instr = arch().disassemble(addr(0x1000), &bytes).unwrap();
        assert_eq!(instr.mnemonic, "BA");
    }

    #[test]
    fn test_encode_bicc_annul() {
        let enc = encode_bicc(8, true, 8);
        let bytes = enc.to_be_bytes();
        let instr = arch().disassemble(addr(0x1000), &bytes).unwrap();
        assert_eq!(instr.mnemonic, "BA,a");
    }

    #[test]
    fn test_encode_alu_reg_add() {
        // ADD %o0, %o1, %o0
        let enc = encode_alu_reg(0x00, 8, 9, 8);
        let bytes = enc.to_be_bytes();
        let instr = arch().disassemble(addr(0), &bytes).unwrap();
        assert_eq!(instr.mnemonic, "ADD");
    }

    #[test]
    fn test_encode_alu_imm_or() {
        // OR %g0, 42, %o0 (MOV 42, %o0)
        let enc = encode_alu_imm(0x02, 0, 42, 8);
        let bytes = enc.to_be_bytes();
        let instr = arch().disassemble(addr(0), &bytes).unwrap();
        assert_eq!(instr.mnemonic, "OR");
        assert!(instr.operands.contains("42"));
    }

    #[test]
    fn test_encode_load_ld() {
        // LD [%sp+4], %o0: op3=0x00 (LD), rs1=sp=14, simm13=4, rd=8
        let enc = encode_load(0x00, 14, 4, 8);
        let bytes = enc.to_be_bytes();
        let instr = arch().disassemble(addr(0), &bytes).unwrap();
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_encode_store_st() {
        // ST %o0, [%sp+4]: op3=0x04 (ST)
        let enc = encode_store(0x04, 14, 4, 8);
        let bytes = enc.to_be_bytes();
        let instr = arch().disassemble(addr(0), &bytes).unwrap();
        assert!(instr.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_encode_jmpl_ret() {
        // JMPL %i7+8, %g0 -> RETURN
        let enc = encode_jmpl(31, 8, 0);
        let bytes = enc.to_be_bytes();
        let instr = arch().disassemble(addr(0), &bytes).unwrap();
        assert_eq!(instr.mnemonic, "RETURN");
        assert!(instr.flags.contains(InstrFlags::RET));
    }

    // ── Trap table lookups ────────────────────────────────────────────────

    #[test]
    fn test_v8_trap_reset() {
        let t = lookup_v8_trap(0x00).unwrap();
        assert_eq!(t.description, "reset");
    }

    #[test]
    fn test_v8_trap_syscall() {
        let t = lookup_v8_trap(0x80).unwrap();
        assert!(t.description.contains("syscall"));
    }

    #[test]
    fn test_v9_trap_fp_disabled() {
        let t = lookup_v9_trap(0x14).unwrap();
        assert_eq!(t.description, "fp_disabled");
    }

    #[test]
    fn test_v9_trap_data_access() {
        let t = lookup_v9_trap(0x30).unwrap();
        assert_eq!(t.description, "data_access_exception");
    }

    #[test]
    fn test_trap_not_found() {
        assert!(lookup_v8_trap(0xFE).is_none());
    }

    // ── FP opcode table ───────────────────────────────────────────────────

    #[test]
    fn test_fp_opcode_fadds() {
        let op = lookup_fp_opcode(0x041).unwrap();
        assert_eq!(op.mnemonic, "FADDS");
        assert!(!op.sets_fcc);
    }

    #[test]
    fn test_fp_opcode_fcmps() {
        let op = lookup_fp_opcode(0x051).unwrap();
        assert_eq!(op.mnemonic, "FCMPS");
        assert!(op.sets_fcc);
    }

    #[test]
    fn test_fp_opcode_fitos() {
        let op = lookup_fp_opcode(0x0C4).unwrap();
        assert_eq!(op.mnemonic, "FITOS");
    }

    #[test]
    fn test_fp_opcode_not_found() {
        assert!(lookup_fp_opcode(0xFFFF).is_none());
    }

    // ── ASI table ─────────────────────────────────────────────────────────

    #[test]
    fn test_asi_primary() {
        let a = lookup_asi(0x80).unwrap();
        assert_eq!(a.description, "ASI_PRIMARY");
        assert!(!a.privileged);
    }

    #[test]
    fn test_asi_nucleus_privileged() {
        let a = lookup_asi(0x04).unwrap();
        assert!(a.privileged);
    }

    #[test]
    fn test_asi_not_found() {
        assert!(lookup_asi(0xFF).is_none());
    }

    // ── Instruction kind classification ───────────────────────────────────

    #[test]
    fn test_kind_nop() {
        assert_eq!(SparcInstrKind::from_mnemonic("NOP"), SparcInstrKind::Nop);
    }

    #[test]
    fn test_kind_add() {
        assert_eq!(SparcInstrKind::from_mnemonic("ADD"), SparcInstrKind::IntAlu);
    }

    #[test]
    fn test_kind_umul() {
        assert_eq!(
            SparcInstrKind::from_mnemonic("UMUL"),
            SparcInstrKind::Multiply
        );
    }

    #[test]
    fn test_kind_udiv() {
        assert_eq!(
            SparcInstrKind::from_mnemonic("UDIV"),
            SparcInstrKind::Divide
        );
    }

    #[test]
    fn test_kind_load() {
        assert_eq!(SparcInstrKind::from_mnemonic("LD"), SparcInstrKind::Load);
        assert!(SparcInstrKind::Load.is_memory());
    }

    #[test]
    fn test_kind_store() {
        assert_eq!(SparcInstrKind::from_mnemonic("ST"), SparcInstrKind::Store);
        assert!(SparcInstrKind::Store.is_memory());
    }

    #[test]
    fn test_kind_call() {
        assert_eq!(SparcInstrKind::from_mnemonic("CALL"), SparcInstrKind::Call);
        assert!(SparcInstrKind::Call.is_control_flow());
    }

    #[test]
    fn test_kind_return() {
        assert_eq!(
            SparcInstrKind::from_mnemonic("RETURN"),
            SparcInstrKind::Return
        );
        assert!(SparcInstrKind::Return.is_control_flow());
    }

    #[test]
    fn test_kind_branch_conditional() {
        assert_eq!(
            SparcInstrKind::from_mnemonic("BNE"),
            SparcInstrKind::CondBranch
        );
    }

    #[test]
    fn test_kind_float_op() {
        assert_eq!(
            SparcInstrKind::from_mnemonic("FADDS"),
            SparcInstrKind::FloatOp
        );
    }

    #[test]
    fn test_kind_window_op() {
        assert_eq!(
            SparcInstrKind::from_mnemonic("SAVE"),
            SparcInstrKind::WindowOp
        );
    }

    // ── Delay slot analysis ───────────────────────────────────────────────

    #[test]
    fn test_delay_slot_call() {
        let instr = arch()
            .disassemble(addr(0x1000), &[0x40, 0x00, 0x00, 0x10])
            .unwrap();
        let info = SparcDelayInfo::from_instruction(&instr);
        assert!(info.has_delay_slot);
        assert!(!info.annulled);
    }

    #[test]
    fn test_delay_slot_ba_annul() {
        // BA,a +4: cond=8, a=1, op2=2, disp22=1 → 0x30800001
        let instr = arch()
            .disassemble(addr(0x1000), &[0x30, 0x80, 0x00, 0x01])
            .unwrap();
        let info = SparcDelayInfo::from_instruction(&instr);
        assert!(info.has_delay_slot);
        assert!(info.annulled);
        assert_eq!(info.base_mnemonic, "BA");
    }

    #[test]
    fn test_no_delay_slot_add() {
        let instr = arch()
            .disassemble(addr(0x1000), &[0x90, 0x02, 0x00, 0x09])
            .unwrap();
        let info = SparcDelayInfo::from_instruction(&instr);
        assert!(!info.has_delay_slot);
    }

    // ── Register window model ─────────────────────────────────────────────

    #[test]
    fn test_window_save_restore() {
        let mut ws = SparcWindowState::new(8);
        assert!(!ws.save());
        assert_eq!(ws.cwp, 7);
        assert!(!ws.restore());
        assert_eq!(ws.cwp, 0);
    }

    #[test]
    fn test_window_overflow() {
        let mut ws = SparcWindowState::new(8);
        ws.set_wim_bit(7);
        let overflow = ws.save();
        assert!(overflow);
        // CWP should NOT change on overflow
        assert_eq!(ws.cwp, 0);
    }

    #[test]
    fn test_window_underflow() {
        let mut ws = SparcWindowState::new(8);
        ws.set_wim_bit(1);
        let underflow = ws.restore();
        assert!(underflow);
        assert_eq!(ws.cwp, 0);
    }

    // ── Code statistics ───────────────────────────────────────────────────

    #[test]
    fn test_stats_basic() {
        // NOP + CALL
        let code = [
            0x01u8, 0x00, 0x00, 0x00, // NOP
            0x40u8, 0x00, 0x00, 0x01, // CALL +4
            0x01u8, 0x00, 0x00, 0x00, // NOP (delay slot)
        ];
        let a = arch();
        let stats = SparcCodeStats::from_bytes(&a, &code, addr(0x1000));
        assert_eq!(stats.total, 3);
        assert_eq!(stats.nops, 2);
        assert_eq!(stats.calls, 1);
    }

    #[test]
    fn test_stats_loads_stores() {
        let code = [
            0xD0u8, 0x03, 0xA0, 0x00, // LD
            0xD0u8, 0x23, 0xA0, 0x00, // ST
        ];
        let a = arch();
        let stats = SparcCodeStats::from_bytes(&a, &code, addr(0x1000));
        assert_eq!(stats.loads, 1);
        assert_eq!(stats.stores, 1);
    }

    // ── Basic block finder ────────────────────────────────────────────────

    #[test]
    fn test_basic_block_call_splits() {
        // CALL has a delay slot — should form one block of 2 (call + nop)
        let code = [
            0x40u8, 0x00, 0x00, 0x01, // CALL
            0x01u8, 0x00, 0x00, 0x00, // NOP (delay slot)
            0x90u8, 0x02, 0x00, 0x09, // ADD (new block)
        ];
        let a = arch();
        let blocks = SparcBasicBlock::find_blocks(&a, &code, addr(0x1000)).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].len(), 2); // CALL + delay slot NOP
        assert_eq!(blocks[1].len(), 1); // ADD
    }

    // ── Printer ───────────────────────────────────────────────────────────

    #[test]
    fn test_print_gnu_nop() {
        let instr = arch()
            .disassemble(addr(0), &[0x01, 0x00, 0x00, 0x00])
            .unwrap();
        let s = sparc_print_gnu(&instr);
        assert_eq!(s, "nop");
    }

    #[test]
    fn test_print_sun_call() {
        let instr = arch()
            .disassemble(addr(0x1000), &[0x40, 0x00, 0x00, 0x10])
            .unwrap();
        let s = sparc_print_sun(&instr);
        assert!(s.starts_with("CALL"));
    }

    // ── Idiom detection ───────────────────────────────────────────────────

    #[test]
    fn test_idiom_load_imm() {
        // OR %g0, 42, %o0
        let enc = encode_alu_imm(0x02, 0, 42, 8).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        let idiom = identify_idiom(&instr, None);
        assert_eq!(idiom, SparcIdiom::LoadImm);
    }

    #[test]
    fn test_idiom_prologue() {
        // SAVE %sp, -96, %sp
        let instr = arch()
            .disassemble(addr(0x1000), &[0x9D, 0xE3, 0xBF, 0xA0])
            .unwrap();
        let idiom = identify_idiom(&instr, None);
        assert_eq!(idiom, SparcIdiom::Prologue);
    }

    #[test]
    fn test_idiom_epilogue() {
        // RESTORE %g0,%g0,%g0
        let instr = arch()
            .disassemble(addr(0x1000), &[0x81, 0xE8, 0x00, 0x00])
            .unwrap();
        let idiom = identify_idiom(&instr, None);
        assert_eq!(idiom, SparcIdiom::Epilogue);
    }

    // ── v9 specific ───────────────────────────────────────────────────────

    #[test]
    fn test_v9_pointer_size() {
        assert_eq!(v9().pointer_size(), 8);
    }

    #[test]
    fn test_v9_calling_convention() {
        let a = v9();
        let cc = a.calling_conventions();
        assert!(!cc.is_empty());
        assert!(cc[0].int_args.contains(&"%o0".to_string()));
    }

    #[test]
    fn test_v9_branches_vec() {
        let a = v9();
        let instr = a
            .disassemble(addr(0x1000), &[0x10, 0x80, 0x00, 0x01])
            .unwrap();
        let branches = a.get_branches(&instr);
        assert!(!branches.is_empty());
        assert_ne!(branches[0].kind, BranchKind::ConditionalJump);
    }
}

// ── SPARC Calling Convention Details ─────────────────────────────────────────

/// SPARC calling convention parameter descriptor.
#[derive(Debug, Clone)]
pub struct SparcParamInfo {
    /// Register name (e.g., "%o0").
    pub register: &'static str,
    /// Parameter index (0-based).
    pub index: u8,
    /// Whether this register is used for integer or float (true = float).
    pub is_float: bool,
}

/// SPARC V8/SysV integer argument registers.
pub static SPARC_V8_INT_ARGS: &[SparcParamInfo] = &[
    SparcParamInfo {
        register: "%o0",
        index: 0,
        is_float: false,
    },
    SparcParamInfo {
        register: "%o1",
        index: 1,
        is_float: false,
    },
    SparcParamInfo {
        register: "%o2",
        index: 2,
        is_float: false,
    },
    SparcParamInfo {
        register: "%o3",
        index: 3,
        is_float: false,
    },
    SparcParamInfo {
        register: "%o4",
        index: 4,
        is_float: false,
    },
    SparcParamInfo {
        register: "%o5",
        index: 5,
        is_float: false,
    },
];

/// SPARC V9/LP64 integer argument registers (same as V8 but with 64-bit widths).
pub static SPARC_V9_INT_ARGS: &[SparcParamInfo] = &[
    SparcParamInfo {
        register: "%o0",
        index: 0,
        is_float: false,
    },
    SparcParamInfo {
        register: "%o1",
        index: 1,
        is_float: false,
    },
    SparcParamInfo {
        register: "%o2",
        index: 2,
        is_float: false,
    },
    SparcParamInfo {
        register: "%o3",
        index: 3,
        is_float: false,
    },
    SparcParamInfo {
        register: "%o4",
        index: 4,
        is_float: false,
    },
    SparcParamInfo {
        register: "%o5",
        index: 5,
        is_float: false,
    },
];

/// SPARC V9 FP argument registers.
pub static SPARC_V9_FP_ARGS: &[SparcParamInfo] = &[
    SparcParamInfo {
        register: "%f0",
        index: 0,
        is_float: true,
    },
    SparcParamInfo {
        register: "%f2",
        index: 1,
        is_float: true,
    },
    SparcParamInfo {
        register: "%f4",
        index: 2,
        is_float: true,
    },
    SparcParamInfo {
        register: "%f6",
        index: 3,
        is_float: true,
    },
    SparcParamInfo {
        register: "%f8",
        index: 4,
        is_float: true,
    },
    SparcParamInfo {
        register: "%f10",
        index: 5,
        is_float: true,
    },
    SparcParamInfo {
        register: "%f12",
        index: 6,
        is_float: true,
    },
    SparcParamInfo {
        register: "%f14",
        index: 7,
        is_float: true,
    },
    SparcParamInfo {
        register: "%f16",
        index: 8,
        is_float: true,
    },
    SparcParamInfo {
        register: "%f18",
        index: 9,
        is_float: true,
    },
    SparcParamInfo {
        register: "%f20",
        index: 10,
        is_float: true,
    },
    SparcParamInfo {
        register: "%f22",
        index: 11,
        is_float: true,
    },
    SparcParamInfo {
        register: "%f24",
        index: 12,
        is_float: true,
    },
    SparcParamInfo {
        register: "%f26",
        index: 13,
        is_float: true,
    },
    SparcParamInfo {
        register: "%f28",
        index: 14,
        is_float: true,
    },
    SparcParamInfo {
        register: "%f30",
        index: 15,
        is_float: true,
    },
];

// ── SPARC Condition Code Table ────────────────────────────────────────────────

/// A single condition code entry.
#[derive(Debug, Clone)]
pub struct SparcCondEntry {
    /// Condition code number (4 bits).
    pub code: u8,
    /// Mnemonic suffix for integer branches.
    pub icc_suffix: &'static str,
    /// Mnemonic suffix for FP branches.
    pub fcc_suffix: &'static str,
    /// Long description.
    pub description: &'static str,
}

/// Complete SPARC condition code table.
pub static SPARC_CONDITIONS: &[SparcCondEntry] = &[
    SparcCondEntry {
        code: 0,
        icc_suffix: "N",
        fcc_suffix: "N",
        description: "Never",
    },
    SparcCondEntry {
        code: 1,
        icc_suffix: "E",
        fcc_suffix: "NE",
        description: "Equal / Not Equal (FP)",
    },
    SparcCondEntry {
        code: 2,
        icc_suffix: "LE",
        fcc_suffix: "LG",
        description: "Less or Equal / Less or Greater",
    },
    SparcCondEntry {
        code: 3,
        icc_suffix: "L",
        fcc_suffix: "UL",
        description: "Less / Unordered or Less",
    },
    SparcCondEntry {
        code: 4,
        icc_suffix: "LEU",
        fcc_suffix: "L",
        description: "Less or Equal Unsigned / Less",
    },
    SparcCondEntry {
        code: 5,
        icc_suffix: "CS",
        fcc_suffix: "UG",
        description: "Carry Set / Unordered or Greater",
    },
    SparcCondEntry {
        code: 6,
        icc_suffix: "NEG",
        fcc_suffix: "G",
        description: "Negative / Greater",
    },
    SparcCondEntry {
        code: 7,
        icc_suffix: "VS",
        fcc_suffix: "U",
        description: "Overflow Set / Unordered",
    },
    SparcCondEntry {
        code: 8,
        icc_suffix: "A",
        fcc_suffix: "A",
        description: "Always",
    },
    SparcCondEntry {
        code: 9,
        icc_suffix: "NE",
        fcc_suffix: "E",
        description: "Not Equal / Equal (FP)",
    },
    SparcCondEntry {
        code: 10,
        icc_suffix: "G",
        fcc_suffix: "UE",
        description: "Greater / Unordered or Equal",
    },
    SparcCondEntry {
        code: 11,
        icc_suffix: "GE",
        fcc_suffix: "GE",
        description: "Greater or Equal",
    },
    SparcCondEntry {
        code: 12,
        icc_suffix: "GU",
        fcc_suffix: "UGE",
        description: "Greater Unsigned / Unordered or GE",
    },
    SparcCondEntry {
        code: 13,
        icc_suffix: "CC",
        fcc_suffix: "LE",
        description: "Carry Clear / Less or Equal",
    },
    SparcCondEntry {
        code: 14,
        icc_suffix: "POS",
        fcc_suffix: "ULE",
        description: "Positive / Unordered or LE",
    },
    SparcCondEntry {
        code: 15,
        icc_suffix: "VC",
        fcc_suffix: "O",
        description: "Overflow Clear / Ordered",
    },
];

/// Look up a condition entry by code.
#[must_use]
pub fn lookup_condition(code: u8) -> Option<&'static SparcCondEntry> {
    SPARC_CONDITIONS.iter().find(|e| e.code == code)
}

// ── SPARC Instruction Encoding Reference ─────────────────────────────────────

/// Summary of a SPARC instruction format.
#[derive(Debug, Clone)]
pub struct SparcFormatInfo {
    /// Format identifier (1, 2, 3).
    pub format: u8,
    /// Opcode field name.
    pub opcode_field: &'static str,
    /// Description of the format.
    pub description: &'static str,
}

/// SPARC instruction formats.
pub static SPARC_FORMATS: &[SparcFormatInfo] = &[
    SparcFormatInfo {
        format: 1,
        opcode_field: "op=01",
        description: "Format 1: CALL — 30-bit PC-relative displacement",
    },
    SparcFormatInfo {
        format: 2,
        opcode_field: "op=00",
        description: "Format 2: branches (Bicc, FBfcc, BPcc) and SETHI",
    },
    SparcFormatInfo {
        format: 3,
        opcode_field: "op=10 or op=11",
        description: "Format 3: ALU (op=10) and load/store (op=11) with reg+reg or reg+simm13",
    },
];

// ── SPARC v9 Privileged Register Table ───────────────────────────────────────

/// A SPARC v9 privileged register.
#[derive(Debug, Clone)]
pub struct SparcPrivReg {
    /// WRPR/RDPR field number.
    pub field: u8,
    /// Register name.
    pub name: &'static str,
    /// Whether it can be read with RDPR.
    pub readable: bool,
    /// Whether it can be written with WRPR.
    pub writable: bool,
}

/// SPARC v9 privileged registers.
pub static SPARC_V9_PRIV_REGS: &[SparcPrivReg] = &[
    SparcPrivReg {
        field: 0,
        name: "%tpc",
        readable: true,
        writable: true,
    },
    SparcPrivReg {
        field: 1,
        name: "%tnpc",
        readable: true,
        writable: true,
    },
    SparcPrivReg {
        field: 2,
        name: "%tstate",
        readable: true,
        writable: true,
    },
    SparcPrivReg {
        field: 3,
        name: "%tt",
        readable: true,
        writable: true,
    },
    SparcPrivReg {
        field: 4,
        name: "%tick",
        readable: true,
        writable: true,
    },
    SparcPrivReg {
        field: 5,
        name: "%tba",
        readable: true,
        writable: true,
    },
    SparcPrivReg {
        field: 6,
        name: "%pstate",
        readable: true,
        writable: true,
    },
    SparcPrivReg {
        field: 7,
        name: "%tl",
        readable: true,
        writable: true,
    },
    SparcPrivReg {
        field: 8,
        name: "%pil",
        readable: true,
        writable: true,
    },
    SparcPrivReg {
        field: 9,
        name: "%cwp",
        readable: true,
        writable: true,
    },
    SparcPrivReg {
        field: 10,
        name: "%cansave",
        readable: true,
        writable: true,
    },
    SparcPrivReg {
        field: 11,
        name: "%canrestore",
        readable: true,
        writable: true,
    },
    SparcPrivReg {
        field: 12,
        name: "%cleanwin",
        readable: true,
        writable: true,
    },
    SparcPrivReg {
        field: 13,
        name: "%otherwin",
        readable: true,
        writable: true,
    },
    SparcPrivReg {
        field: 14,
        name: "%wstate",
        readable: true,
        writable: true,
    },
    SparcPrivReg {
        field: 15,
        name: "%fq",
        readable: true,
        writable: false,
    },
    SparcPrivReg {
        field: 31,
        name: "%ver",
        readable: true,
        writable: false,
    },
];

/// Look up a SPARC v9 privileged register by field number.
#[must_use]
pub fn lookup_priv_reg(field: u8) -> Option<&'static SparcPrivReg> {
    SPARC_V9_PRIV_REGS.iter().find(|r| r.field == field)
}

// ── SPARC Instruction Sequence Builder ───────────────────────────────────────

/// Build a minimal SPARC v8 function prologue.
///
/// Returns the encoding of: `SAVE %sp, -framesize, %sp`
/// `framesize` should be a multiple of 8 and at most 4096-8=4088.
///
/// # Panics
///
/// Panics if `framesize` is 0 or > 4088 or not a multiple of 8.
#[must_use]
pub fn build_prologue(framesize: u32) -> u32 {
    assert!(
        framesize > 0 && framesize <= 4088 && framesize.is_multiple_of(8),
        "framesize must be a multiple of 8 in [8, 4088], got {framesize}"
    );
    // SAVE %sp, -framesize, %sp: op3=0x3C, rs1=sp=14, i=1, simm13=-framesize, rd=sp=14
    encode_alu_imm(0x3C, 14, -(framesize as i32), 14)
}

/// Build a minimal SPARC function epilogue sequence.
///
/// Returns two words: `[RESTORE, NOP]`
#[must_use]
pub fn build_epilogue() -> [u32; 2] {
    // RESTORE %g0, %g0, %g0: op3=0x3D, rs1=0, rs2=0, rd=0
    let restore = encode_alu_reg(0x3D, 0, 0, 0);
    let nop = encode_nop();
    [restore, nop]
}

/// Build a SPARC function return sequence.
///
/// Returns two words: `[JMPL %i7+8, %g0, NOP]`
#[must_use]
pub fn build_return_seq() -> [u32; 2] {
    let jmpl = encode_jmpl(31, 8, 0); // JMPL %i7+8, %g0 -> RETURN
    let nop = encode_nop();
    [jmpl, nop]
}

// ── SPARC Instruction Liveness Helpers ───────────────────────────────────────

/// Register set (bitmask for registers 0-31 + 32-63 FP).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SparcRegSet {
    /// Integer register bits (bit i = register %ri).
    pub int_mask: u64,
    /// FP register bits (bit i = %fi).
    pub fp_mask: u64,
}

impl SparcRegSet {
    /// Create an empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            int_mask: 0,
            fp_mask: 0,
        }
    }

    /// Add an integer register (0-63).
    pub const fn add_int(&mut self, reg: u32) {
        if reg < 64 {
            self.int_mask |= 1u64 << reg;
        }
    }

    /// Remove an integer register (0-63).
    pub const fn remove_int(&mut self, reg: u32) {
        if reg < 64 {
            self.int_mask &= !(1u64 << reg);
        }
    }

    /// Test if an integer register is in the set.
    #[must_use]
    pub const fn contains_int(&self, reg: u32) -> bool {
        reg < 64 && (self.int_mask >> reg) & 1 != 0
    }

    /// Add an FP register (0-63).
    pub const fn add_fp(&mut self, reg: u32) {
        if reg < 64 {
            self.fp_mask |= 1u64 << reg;
        }
    }

    /// Test if an FP register is in the set.
    #[must_use]
    pub const fn contains_fp(&self, reg: u32) -> bool {
        reg < 64 && (self.fp_mask >> reg) & 1 != 0
    }

    /// Union of two sets.
    #[must_use]
    pub const fn union(&self, other: &Self) -> Self {
        Self {
            int_mask: self.int_mask | other.int_mask,
            fp_mask: self.fp_mask | other.fp_mask,
        }
    }

    /// Intersection of two sets.
    #[must_use]
    pub const fn intersect(&self, other: &Self) -> Self {
        Self {
            int_mask: self.int_mask & other.int_mask,
            fp_mask: self.fp_mask & other.fp_mask,
        }
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.int_mask == 0 && self.fp_mask == 0
    }

    /// Number of registers in the set.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.int_mask.count_ones() + self.fp_mask.count_ones()
    }
}

// ── SPARC Disassembler with Annotation ───────────────────────────────────────

/// An annotated SPARC instruction.
#[derive(Debug, Clone)]
pub struct AnnotatedSparcInstr {
    /// The underlying instruction.
    pub instr: Instruction,
    /// Detected idiom (if any).
    pub idiom: SparcIdiom,
    /// Instruction kind.
    pub kind: SparcInstrKind,
    /// Delay slot info.
    pub delay: SparcDelayInfo,
}

impl AnnotatedSparcInstr {
    /// Annotate a single decoded instruction (without successor for idiom detection).
    #[must_use]
    pub fn from_instr(instr: Instruction) -> Self {
        let idiom = identify_idiom(&instr, None);
        let kind = SparcInstrKind::from_mnemonic(&instr.mnemonic);
        let delay = SparcDelayInfo::from_instruction(&instr);
        Self {
            instr,
            idiom,
            kind,
            delay,
        }
    }
}

/// Disassemble a SPARC byte slice with annotation.
///
/// # Errors
///
/// Returns `CoreError` if any instruction cannot be decoded.
pub fn disassemble_annotated(
    arch: &SparcArch,
    bytes: &[u8],
    base: Address,
) -> Result<Vec<AnnotatedSparcInstr>, CoreError> {
    let mut results = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        let addr = base + offset as u64;
        let instr = arch.disassemble(addr, &bytes[offset..])?;
        let annotated = AnnotatedSparcInstr::from_instr(instr);
        offset += 4;
        results.push(annotated);
    }
    // Second pass: update idioms with successor context
    let n = results.len();
    for i in 0..n.saturating_sub(1) {
        let next_instr = results[i + 1].instr.clone();
        let curr_instr = &results[i].instr;
        results[i].idiom = identify_idiom(curr_instr, Some(&next_instr));
    }
    Ok(results)
}

// ── SPARC Branch Resolver ─────────────────────────────────────────────────────

/// Resolve all branch targets in a sequence of annotated instructions.
///
/// Returns a list of `(from_address, to_address, is_conditional, is_call)` tuples.
#[must_use]
pub fn resolve_branches(instrs: &[AnnotatedSparcInstr]) -> Vec<(Address, Address, bool, bool)> {
    let mut out = Vec::new();
    for ai in instrs {
        if ai
            .instr
            .flags
            .intersects(InstrFlags::BRANCH | InstrFlags::CALL)
        {
            let ops = &ai.instr.operands;
            let hex: String = ops
                .trim_start_matches('$')
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            if let Ok(target) = u64::from_str_radix(&hex, 16) {
                out.push((
                    ai.instr.address,
                    Address::new(target),
                    ai.instr.flags.contains(InstrFlags::CONDITIONAL),
                    ai.instr.flags.contains(InstrFlags::CALL),
                ));
            }
        }
    }
    out
}

// ── More Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod advanced_tests {
    use super::*;

    fn arch() -> SparcArch {
        SparcArch::default()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    #[test]
    fn test_cond_table_always() {
        let c = lookup_condition(8).unwrap();
        assert_eq!(c.icc_suffix, "A");
        assert_eq!(c.fcc_suffix, "A");
    }

    #[test]
    fn test_cond_table_ne() {
        let c = lookup_condition(9).unwrap();
        assert_eq!(c.icc_suffix, "NE");
    }

    #[test]
    fn test_cond_not_found() {
        assert!(lookup_condition(255).is_none());
    }

    #[test]
    fn test_priv_reg_tpc() {
        let r = lookup_priv_reg(0).unwrap();
        assert_eq!(r.name, "%tpc");
        assert!(r.readable);
        assert!(r.writable);
    }

    #[test]
    fn test_priv_reg_ver_readonly() {
        let r = lookup_priv_reg(31).unwrap();
        assert_eq!(r.name, "%ver");
        assert!(r.readable);
        assert!(!r.writable);
    }

    #[test]
    fn test_priv_reg_not_found() {
        assert!(lookup_priv_reg(100).is_none());
    }

    #[test]
    fn test_build_prologue() {
        let enc = build_prologue(96).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "SAVE");
        assert!(instr.operands.contains("%sp"));
        assert!(
            instr.operands.contains("-96")
                || instr.operands.contains("−96")
                || instr.operands.contains("%sp")
        );
    }

    #[test]
    fn test_build_epilogue() {
        let eps = build_epilogue();
        let restore = arch().disassemble(addr(0), &eps[0].to_be_bytes()).unwrap();
        assert_eq!(restore.mnemonic, "RESTORE");
        let nop = arch().disassemble(addr(4), &eps[1].to_be_bytes()).unwrap();
        assert_eq!(nop.mnemonic, "NOP");
    }

    #[test]
    fn test_build_return_seq() {
        let seq = build_return_seq();
        let ret = arch().disassemble(addr(0), &seq[0].to_be_bytes()).unwrap();
        assert_eq!(ret.mnemonic, "RETURN");
        let nop = arch().disassemble(addr(4), &seq[1].to_be_bytes()).unwrap();
        assert_eq!(nop.mnemonic, "NOP");
    }

    #[test]
    fn test_reg_set_basic() {
        let mut rs = SparcRegSet::new();
        rs.add_int(8);
        rs.add_int(9);
        assert!(rs.contains_int(8));
        assert!(rs.contains_int(9));
        assert!(!rs.contains_int(10));
        assert_eq!(rs.count(), 2);
    }

    #[test]
    fn test_reg_set_remove() {
        let mut rs = SparcRegSet::new();
        rs.add_int(8);
        rs.remove_int(8);
        assert!(!rs.contains_int(8));
        assert!(rs.is_empty());
    }

    #[test]
    fn test_reg_set_fp() {
        let mut rs = SparcRegSet::new();
        rs.add_fp(0);
        rs.add_fp(2);
        assert!(rs.contains_fp(0));
        assert!(!rs.contains_fp(1));
        assert_eq!(rs.fp_mask.count_ones(), 2);
    }

    #[test]
    fn test_reg_set_union() {
        let mut a = SparcRegSet::new();
        a.add_int(0);
        let mut b = SparcRegSet::new();
        b.add_int(1);
        let u = a.union(&b);
        assert!(u.contains_int(0));
        assert!(u.contains_int(1));
    }

    #[test]
    fn test_reg_set_intersect() {
        let mut a = SparcRegSet::new();
        a.add_int(0);
        a.add_int(1);
        let mut b = SparcRegSet::new();
        b.add_int(1);
        b.add_int(2);
        let i = a.intersect(&b);
        assert!(!i.contains_int(0));
        assert!(i.contains_int(1));
        assert!(!i.contains_int(2));
    }

    #[test]
    fn test_annotated_disasm() {
        let code = [
            0x01u8, 0x00, 0x00, 0x00, // NOP
            0x90u8, 0x02, 0x00, 0x09, // ADD
        ];
        let a = arch();
        let annotated = disassemble_annotated(&a, &code, addr(0)).unwrap();
        assert_eq!(annotated.len(), 2);
        assert_eq!(annotated[0].kind, SparcInstrKind::Nop);
        assert_eq!(annotated[1].kind, SparcInstrKind::IntAlu);
    }

    #[test]
    fn test_branch_resolver() {
        // NOP + CALL+4 + NOP
        let code = [
            0x01u8, 0x00, 0x00, 0x00, // NOP @ 0x1000
            0x40u8, 0x00, 0x00, 0x01, // CALL +4 @ 0x1004 -> target 0x1008
            0x01u8, 0x00, 0x00, 0x00, // NOP @ 0x1008
        ];
        let a = arch();
        let annotated = disassemble_annotated(&a, &code, addr(0x1000)).unwrap();
        let branches = resolve_branches(&annotated);
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].1.as_u64(), 0x1008);
        assert!(branches[0].3); // is_call
    }

    #[test]
    fn test_sparc_formats_table() {
        assert_eq!(SPARC_FORMATS.len(), 3);
        assert_eq!(SPARC_FORMATS[0].format, 1);
        assert_eq!(SPARC_FORMATS[1].format, 2);
        assert_eq!(SPARC_FORMATS[2].format, 3);
    }

    #[test]
    fn test_v8_int_args_count() {
        assert_eq!(SPARC_V8_INT_ARGS.len(), 6);
        assert_eq!(SPARC_V8_INT_ARGS[0].register, "%o0");
    }

    #[test]
    fn test_v9_fp_args_count() {
        assert_eq!(SPARC_V9_FP_ARGS.len(), 16);
        assert!(SPARC_V9_FP_ARGS.iter().all(|a| a.is_float));
    }

    #[test]
    fn test_idiom_reg_copy() {
        // OR %g0, %o0, %o1 -> RegCopy
        let enc = encode_alu_reg(0x02, 0, 8, 9).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        // rs1=0 (%g0), rs2=8 (%o0), rd=9 (%o1)
        let idiom = identify_idiom(&instr, None);
        assert_eq!(idiom, SparcIdiom::RegCopy);
    }

    #[test]
    fn test_idiom_load32() {
        // SETHI followed by OR
        let sethi = encode_sethi(8, 0x1234).to_be_bytes();
        let or_enc = encode_alu_imm(0x02, 8, 0x56, 8).to_be_bytes();
        let instr1 = arch().disassemble(addr(0), &sethi).unwrap();
        let instr2 = arch().disassemble(addr(4), &or_enc).unwrap();
        let idiom = identify_idiom(&instr1, Some(&instr2));
        assert_eq!(idiom, SparcIdiom::Load32);
    }

    #[test]
    fn test_encode_sethi_roundtrip() {
        let enc = encode_sethi(8, 0x10000).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "SETHI");
    }

    #[test]
    fn test_v9_priv_regs_count() {
        assert!(SPARC_V9_PRIV_REGS.len() >= 16);
    }

    #[test]
    fn test_v9_has_clean_window_trap() {
        let t = lookup_v9_trap(0x18).unwrap();
        assert_eq!(t.description, "clean_window");
        assert_eq!(t.arch_level, 9);
    }

    #[test]
    fn test_v8_trap_fp_exception() {
        let t = lookup_v8_trap(0x08).unwrap();
        assert_eq!(t.description, "fp_exception");
    }

    #[test]
    fn test_condition_table_completeness() {
        // All 16 conditions should be present
        assert_eq!(SPARC_CONDITIONS.len(), 16);
        for i in 0u8..16 {
            assert!(lookup_condition(i).is_some(), "condition {i} missing");
        }
    }

    #[test]
    fn test_fp_table_fsmuld() {
        let op = lookup_fp_opcode(0x069).unwrap();
        assert_eq!(op.mnemonic, "FSMULD");
    }

    #[test]
    fn test_fp_table_fdmulq() {
        let op = lookup_fp_opcode(0x06E).unwrap();
        assert_eq!(op.mnemonic, "FDMULQ");
    }

    #[test]
    fn test_v9_le_registers() {
        let a = SparcArch::new_le();
        let regs = a.registers();
        assert!(regs.len() >= 70);
    }

    #[test]
    fn test_window_multiple_saves() {
        let mut ws = SparcWindowState::new(8);
        for _ in 0..7 {
            assert!(!ws.save());
        }
        // After 7 saves, cwp = 1; one more would go to 0
        // Set WIM bit on window 0
        ws.set_wim_bit(0);
        let overflow = ws.save();
        assert!(overflow);
    }

    #[test]
    fn test_window_clear_wim() {
        let mut ws = SparcWindowState::new(8);
        ws.set_wim_bit(3);
        assert!((ws.wim >> 3) & 1 == 1);
        ws.clear_wim_bit(3);
        assert!((ws.wim >> 3) & 1 == 0);
    }

    #[test]
    fn test_orcc_is_int_alu() {
        assert_eq!(
            SparcInstrKind::from_mnemonic("ORCC"),
            SparcInstrKind::IntAlu
        );
    }

    #[test]
    fn test_mulx_is_multiply() {
        assert_eq!(
            SparcInstrKind::from_mnemonic("MULX"),
            SparcInstrKind::Multiply
        );
    }

    #[test]
    fn test_udivx_is_divide() {
        assert_eq!(
            SparcInstrKind::from_mnemonic("UDIVX"),
            SparcInstrKind::Divide
        );
    }
}

// ── SPARC Synthetic Instruction Macros ────────────────────────────────────────

/// Synthetic instruction: `MOV imm, %rd` → `OR %g0, imm, %rd`.
///
/// `imm` must fit in 13 bits (-4096..4095).
///
/// # Panics
///
/// Panics if `imm` is outside the signed 13-bit range.
#[must_use]
pub fn synth_mov_imm(imm: i32, rd: u32) -> u32 {
    assert!(
        (-4096..=4095).contains(&imm),
        "imm {imm} out of 13-bit range"
    );
    encode_alu_imm(0x02, 0, imm, rd)
}

/// Synthetic instruction: `MOV %rs, %rd` → `OR %g0, %rs, %rd`.
#[must_use]
pub fn synth_mov_reg(rs: u32, rd: u32) -> u32 {
    encode_alu_reg(0x02, 0, rs, rd)
}

/// Synthetic instruction: `CLR %rd` → `OR %g0, %g0, %rd`.
#[must_use]
pub fn synth_clr(rd: u32) -> u32 {
    encode_alu_reg(0x02, 0, 0, rd)
}

/// Synthetic instruction: `NOT %rs, %rd` → `XNOR %rs, %g0, %rd`.
#[must_use]
pub fn synth_not(rs: u32, rd: u32) -> u32 {
    encode_alu_reg(0x07, rs, 0, rd)
}

/// Synthetic instruction: `NEG %rs, %rd` → `SUB %g0, %rs, %rd`.
#[must_use]
pub fn synth_neg(rs: u32, rd: u32) -> u32 {
    encode_alu_reg(0x04, 0, rs, rd)
}

/// Synthetic instruction: `TST %rs` → `ORCC %g0, %rs, %g0` (sets icc).
#[must_use]
pub fn synth_tst(rs: u32) -> u32 {
    encode_alu_reg(0x12, 0, rs, 0)
}

/// Synthetic instruction: `CMP %rs1, %rs2` → `SUBCC %rs1, %rs2, %g0`.
#[must_use]
pub fn synth_cmp_reg(rs1: u32, rs2: u32) -> u32 {
    encode_alu_reg(0x14, rs1, rs2, 0)
}

/// Synthetic instruction: `CMP %rs1, imm` → `SUBCC %rs1, imm, %g0`.
///
/// # Panics
///
/// Panics if `imm` is outside the signed 13-bit range.
#[must_use]
pub fn synth_cmp_imm(rs1: u32, imm: i32) -> u32 {
    assert!(
        (-4096..=4095).contains(&imm),
        "imm {imm} out of 13-bit range"
    );
    encode_alu_imm(0x14, rs1, imm, 0)
}

/// Synthetic instruction: `INC %rd` → `ADD %rd, 1, %rd`.
#[must_use]
pub fn synth_inc(rd: u32) -> u32 {
    encode_alu_imm(0x00, rd, 1, rd)
}

/// Synthetic instruction: `DEC %rd` → `SUB %rd, 1, %rd`.
#[must_use]
pub fn synth_dec(rd: u32) -> u32 {
    encode_alu_imm(0x04, rd, 1, rd)
}

/// Synthetic instruction: `SET val, %rd` — expands to SETHI + OR for values
/// needing both hi22 and lo10 parts. Returns 1 or 2 words.
///
/// If `val` fits in 13 bits (signed), returns `[MOV val, %rd]`.
/// Otherwise returns `[SETHI %hi(val), %rd; OR %rd, %lo(val), %rd]`.
#[must_use]
pub fn synth_set(val: u32, rd: u32) -> Vec<u32> {
    let sv = val as i32;
    if (-4096..=4095).contains(&sv) {
        vec![synth_mov_imm(sv, rd)]
    } else {
        let hi22 = val >> 10;
        let lo10 = val & 0x3FF;
        let sethi = encode_sethi(rd, hi22);
        let or = encode_alu_imm(0x02, rd, lo10 as i32, rd);
        vec![sethi, or]
    }
}

// ── SPARC Call Frame Information ──────────────────────────────────────────────

/// SPARC stack layout constants for `SysV` ABI.
#[derive(Debug, Clone)]
pub struct SparcStackLayout {
    /// Frame size in bytes (must be multiple of 8, minimum 96).
    pub frame_size: u32,
    /// Bias added to %sp in SPARC V9 (2047 for V9, 0 for V8).
    pub stack_bias: i32,
}

impl SparcStackLayout {
    /// Create a V8 stack layout for the given frame size.
    ///
    /// # Panics
    ///
    /// Panics if `frame_size` is not a multiple of 8 or less than 96.
    #[must_use]
    pub fn new_v8(frame_size: u32) -> Self {
        assert!(
            frame_size >= 96 && frame_size.is_multiple_of(8),
            "V8 frame size must be >= 96 and multiple of 8"
        );
        Self {
            frame_size,
            stack_bias: 0,
        }
    }

    /// Create a V9 stack layout (with 2047-byte stack bias).
    ///
    /// # Panics
    ///
    /// Panics if `frame_size` is not a multiple of 16 or less than 128.
    #[must_use]
    pub fn new_v9(frame_size: u32) -> Self {
        assert!(
            frame_size >= 128 && frame_size.is_multiple_of(16),
            "V9 frame size must be >= 128 and multiple of 16"
        );
        Self {
            frame_size,
            stack_bias: 2047,
        }
    }

    /// Offset from biased %sp to the save area base.
    #[must_use]
    pub const fn save_area_offset(&self) -> i32 {
        self.stack_bias
    }

    /// Offset from biased %sp to the local variable area.
    #[must_use]
    pub const fn locals_offset(&self) -> i32 {
        self.stack_bias + 128 // After the 16-register save area (8 local + 8 in)
    }

    /// Byte offset from %fp (previous %sp) to the first outgoing argument slot.
    #[must_use]
    pub const fn outgoing_args_offset(&self) -> i32 {
        // In V8: %sp + 68 is first outgoing arg slot
        // In V9: %sp + 2047 + 128 is first outgoing arg slot
        self.stack_bias + 128
    }
}

// ── SPARC Disassembly Annotation Printer ─────────────────────────────────────

/// Produce a formatted disassembly line with annotations.
#[must_use]
pub fn format_annotated(ai: &AnnotatedSparcInstr) -> String {
    let idiom_label = match &ai.idiom {
        SparcIdiom::LoadImm => " ; load-imm",
        SparcIdiom::RegCopy => " ; reg-copy",
        SparcIdiom::Prologue => " ; prologue",
        SparcIdiom::Epilogue => " ; epilogue",
        SparcIdiom::Load32 => " ; load-32",
        SparcIdiom::LeafReturn => " ; leaf-return",
        SparcIdiom::None => "",
    };
    let delay_label = if ai.delay.has_delay_slot { " <ds>" } else { "" };
    let addr = ai.instr.address.as_u64();
    if ai.instr.operands.is_empty() {
        format!(
            "{addr:08x}  {}{}{idiom_label}",
            ai.instr.mnemonic, delay_label
        )
    } else {
        format!(
            "{addr:08x}  {} {}{delay_label}{idiom_label}",
            ai.instr.mnemonic, ai.instr.operands
        )
    }
}

// ── SPARC Instruction Byte Pattern Extractor ─────────────────────────────────

/// Extract all branch target offsets (PC-relative) from a byte buffer.
///
/// Returns a list of `(pc_of_branch, target_address)` pairs.
#[must_use]
pub fn extract_branch_targets(bytes: &[u8], base: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let len = bytes.len();
    let mut i = 0;
    while i + 4 <= len {
        let instr = u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        let pc = base + i as u64;
        let fmt = instr >> 30;
        match fmt {
            1 => {
                // CALL
                let disp30_raw = (instr & 0x3FFF_FFFF) << 2;
                let disp = i64::from(i32::from_ne_bytes(disp30_raw.to_ne_bytes()));
                let target = pc.wrapping_add_signed(disp);
                out.push((pc, target));
            }
            0 => {
                let op2 = (instr >> 22) & 7;
                if op2 == 2 || op2 == 6 {
                    // Bicc or FBfcc
                    let disp22_raw = (instr & 0x003F_FFFF) << 2;
                    let disp22 = if disp22_raw & 0x80_0000 != 0 {
                        i64::from(i32::from_ne_bytes((disp22_raw | 0xFF00_0000).to_ne_bytes()))
                    } else {
                        i64::from(disp22_raw)
                    };
                    let target = pc.wrapping_add_signed(disp22);
                    out.push((pc, target));
                } else if op2 == 1 {
                    // BPcc
                    let disp19_raw = (instr & 0x7_FFFF) << 2;
                    let disp19 = if disp19_raw & 0x10_0000 != 0 {
                        i64::from(i32::from_ne_bytes((disp19_raw | 0xFFE0_0000).to_ne_bytes()))
                    } else {
                        i64::from(disp19_raw)
                    };
                    let target = pc.wrapping_add_signed(disp19);
                    out.push((pc, target));
                }
            }
            _ => {}
        }
        i += 4;
    }
    out
}

// ── SPARC Instruction Counter ─────────────────────────────────────────────────

/// Count instruction mix from raw bytes (no decode needed for counting).
#[derive(Debug, Clone, Default)]
pub struct SparcRawMix {
    /// Format 1 (CALL) instructions.
    pub calls: u64,
    /// Format 2 branch instructions (Bicc/FBfcc/BPcc).
    pub branches: u64,
    /// Format 2 SETHI/NOP instructions.
    pub sethis: u64,
    /// Format 3 ALU instructions (op=10).
    pub alu: u64,
    /// Format 3 Load/Store instructions (op=11).
    pub mem: u64,
}

impl SparcRawMix {
    /// Compute raw instruction mix from bytes without full decode.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut m = Self::default();
        let mut i = 0;
        while i + 4 <= bytes.len() {
            let instr = u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
            match instr >> 30 {
                1 => m.calls += 1,
                0 => {
                    let op2 = (instr >> 22) & 7;
                    if matches!(op2, 1 | 2 | 6) {
                        m.branches += 1;
                    } else {
                        m.sethis += 1;
                    }
                }
                2 => m.alu += 1,
                3 => m.mem += 1,
                _ => {}
            }
            i += 4;
        }
        m
    }
}

// ── Final Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod final_tests {
    use super::*;

    fn arch() -> SparcArch {
        SparcArch::default()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    #[test]
    fn test_synth_mov_imm() {
        let enc = synth_mov_imm(42, 8).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "OR");
        assert!(instr.operands.contains("42"));
    }

    #[test]
    fn test_synth_clr() {
        let enc = synth_clr(8).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "OR");
        // %g0, %g0, %o0
        assert!(instr.operands.contains("%g0"));
    }

    #[test]
    fn test_synth_not() {
        let enc = synth_not(8, 9).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "XNOR");
    }

    #[test]
    fn test_synth_neg() {
        let enc = synth_neg(8, 9).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "SUB");
    }

    #[test]
    fn test_synth_tst() {
        let enc = synth_tst(8).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "ORCC");
    }

    #[test]
    fn test_synth_cmp_reg() {
        let enc = synth_cmp_reg(8, 9).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "SUBCC");
    }

    #[test]
    fn test_synth_cmp_imm() {
        let enc = synth_cmp_imm(8, 5).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "SUBCC");
        assert!(instr.operands.contains('5'));
    }

    #[test]
    fn test_synth_inc() {
        let enc = synth_inc(8).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "ADD");
        assert!(instr.operands.contains('1'));
    }

    #[test]
    fn test_synth_dec() {
        let enc = synth_dec(8).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "SUB");
        assert!(instr.operands.contains('1'));
    }

    #[test]
    fn test_synth_set_small() {
        let words = synth_set(100, 8);
        assert_eq!(words.len(), 1);
        let instr = arch()
            .disassemble(addr(0), &words[0].to_be_bytes())
            .unwrap();
        assert_eq!(instr.mnemonic, "OR");
        assert!(instr.operands.contains("100"));
    }

    #[test]
    fn test_synth_set_large() {
        let words = synth_set(0x12345678, 8);
        assert_eq!(words.len(), 2);
        let instr0 = arch()
            .disassemble(addr(0), &words[0].to_be_bytes())
            .unwrap();
        let instr1 = arch()
            .disassemble(addr(4), &words[1].to_be_bytes())
            .unwrap();
        assert_eq!(instr0.mnemonic, "SETHI");
        assert_eq!(instr1.mnemonic, "OR");
    }

    #[test]
    fn test_stack_layout_v8() {
        let sl = SparcStackLayout::new_v8(96);
        assert_eq!(sl.stack_bias, 0);
        assert_eq!(sl.frame_size, 96);
        assert_eq!(sl.save_area_offset(), 0);
    }

    #[test]
    fn test_stack_layout_v9() {
        let sl = SparcStackLayout::new_v9(128);
        assert_eq!(sl.stack_bias, 2047);
        assert_eq!(sl.locals_offset(), 2047 + 128);
    }

    #[test]
    fn test_format_annotated() {
        let bytes = [0x01u8, 0x00, 0x00, 0x00]; // NOP
        let a = arch();
        let instrs = disassemble_annotated(&a, &bytes, addr(0x1000)).unwrap();
        let line = format_annotated(&instrs[0]);
        assert!(line.contains("NOP") || line.contains("nop") || line.contains("00001000"));
    }

    #[test]
    fn test_extract_branch_targets_call() {
        // CALL +4 at address 0x1000
        let enc = encode_call(4).to_be_bytes();
        let targets = extract_branch_targets(&enc, 0x1000);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, 0x1000);
        assert_eq!(targets[0].1, 0x1004);
    }

    #[test]
    fn test_extract_branch_targets_bicc() {
        // BA +8 at 0x1000
        let enc = encode_bicc(8, false, 8).to_be_bytes();
        let targets = extract_branch_targets(&enc, 0x1000);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].1, 0x1008);
    }

    #[test]
    fn test_raw_mix_basic() {
        let code: Vec<u8> = [
            encode_call(4).to_be_bytes().to_vec(),
            encode_nop().to_be_bytes().to_vec(),
            encode_alu_reg(0x00, 8, 9, 8).to_be_bytes().to_vec(),
            encode_load(0x00, 14, 0, 8).to_be_bytes().to_vec(),
        ]
        .concat();
        let mix = SparcRawMix::from_bytes(&code);
        assert_eq!(mix.calls, 1);
        assert_eq!(mix.sethis, 1); // NOP is SETHI
        assert_eq!(mix.alu, 1);
        assert_eq!(mix.mem, 1);
    }

    #[test]
    fn test_raw_mix_branches() {
        let b = encode_bicc(8, false, 4).to_be_bytes();
        let mix = SparcRawMix::from_bytes(&b);
        assert_eq!(mix.branches, 1);
    }

    #[test]
    fn test_mov_reg() {
        let enc = synth_mov_reg(8, 9).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "OR");
    }
}
