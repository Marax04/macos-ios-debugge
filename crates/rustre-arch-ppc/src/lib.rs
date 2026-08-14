//! `rustre-arch-ppc`
//!
//! PowerPC 32/64-bit architecture implementation for the `RustRE` Suite.
//! 4-byte fixed-width big-endian instructions.

/// PowerPC higher-level analysis: EabiCalling, BookE (embedded SPRs/rfmci),
/// VleMode (variable-length encoding), PpcSPE (e500 signal processing),
/// TOCSection (64-bit PPC ELF), PpcAnalysis facade.
///
pub mod ppc_analysis;
pub mod ppc_decoder;
pub mod ppc_registers;
pub mod ppc_calling_conv;
pub mod ppc_disassembler;
pub mod ppc_calling_convention;
pub mod ppc_branch_analyzer;
pub mod ppc_spr_map;

use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
use rustre_core::arch::{BranchCondition, RegisterKind};
use rustre_core::{address::Address, endian::Endian, errors::CoreError};

// ── Register IDs ──────────────────────────────────────────────────────────────
const REG_R0: u32 = 0;
const REG_F0: u32 = 32;
const REG_CR: u32 = 64;
const REG_XER: u32 = 65;
const REG_LR: u32 = 66;
const REG_CTR: u32 = 67;
const REG_PC: u32 = 68;

fn gpr(r: u32) -> String {
    format!("r{r}")
}
fn fpr(r: u32) -> String {
    format!("f{}", r & 31)
}
fn crfield(r: u32) -> String {
    format!("cr{}", r & 7)
}

fn simm16(val: u32) -> i32 {
    // Extract low 16 bits, reinterpret as signed, then widen.
    // val & 0xFFFF is always <= 65535, so try_from succeeds.
    let low16 = u16::try_from(val & 0xFFFF).unwrap_or(0);
    i32::from(i16::from_ne_bytes(low16.to_ne_bytes()))
}
const fn uimm16(val: u32) -> u32 {
    val & 0xFFFF
}

// ── Condition bits ────────────────────────────────────────────────────────────
const fn bc_name(bi: u32, bo: u32) -> (&'static str, bool) {
    let cond_bit = bi & 3;
    let branch_always = bo & 0x14 == 0x14;
    if branch_always {
        return ("B", false);
    }
    let branch_if_true = bo & 8 != 0;
    let name = match cond_bit {
        0 => {
            if branch_if_true {
                "BLT"
            } else {
                "BGE"
            }
        }
        1 => {
            if branch_if_true {
                "BGT"
            } else {
                "BLE"
            }
        }
        2 => {
            if branch_if_true {
                "BEQ"
            } else {
                "BNE"
            }
        }
        _ => {
            if branch_if_true {
                "BSO"
            } else {
                "BNS"
            }
        }
    };
    (name, true)
}

/// Compute PC-relative or absolute branch target (32-bit offset, in bytes).
fn branch_target(pc: u64, offset: i32, aa: u32) -> u64 {
    if aa != 0 {
        // Reinterpret the signed offset as an absolute address bit-pattern.
        u64::from(u32::from_ne_bytes(offset.to_ne_bytes()))
    } else {
        pc.wrapping_add_signed(i64::from(offset))
    }
}

// ── Load/store and FP memory decode ──────────────────────────────────────────
fn decode_ppc_mem(opcd: u32, instr: u32, rs: u32, ra: u32) -> (String, String, InstrFlags) {
    match opcd {
        32 => (
            "LWZ".to_string(),
            format!("{},{}({})", gpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::READ_MEM,
        ),
        33 => (
            "LWZU".to_string(),
            format!("{},{}({})", gpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::READ_MEM,
        ),
        34 => (
            "LBZ".to_string(),
            format!("{},{}({})", gpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::READ_MEM,
        ),
        35 => (
            "LBZU".to_string(),
            format!("{},{}({})", gpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::READ_MEM,
        ),
        36 => (
            "STW".to_string(),
            format!("{},{}({})", gpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::WRITE_MEM,
        ),
        37 => (
            "STWU".to_string(),
            format!("{},{}({})", gpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::WRITE_MEM,
        ),
        38 => (
            "STB".to_string(),
            format!("{},{}({})", gpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::WRITE_MEM,
        ),
        39 => (
            "STBU".to_string(),
            format!("{},{}({})", gpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::WRITE_MEM,
        ),
        40 => (
            "LHZ".to_string(),
            format!("{},{}({})", gpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::READ_MEM,
        ),
        41 => (
            "LHZU".to_string(),
            format!("{},{}({})", gpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::READ_MEM,
        ),
        42 => (
            "LHA".to_string(),
            format!("{},{}({})", gpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::READ_MEM,
        ),
        43 => (
            "LHAU".to_string(),
            format!("{},{}({})", gpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::READ_MEM,
        ),
        44 => (
            "STH".to_string(),
            format!("{},{}({})", gpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::WRITE_MEM,
        ),
        45 => (
            "STHU".to_string(),
            format!("{},{}({})", gpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::WRITE_MEM,
        ),
        46 => (
            "LMW".to_string(),
            format!("{},{}({})", gpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::READ_MEM,
        ),
        47 => (
            "STMW".to_string(),
            format!("{},{}({})", gpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::WRITE_MEM,
        ),
        48 => (
            "LFS".to_string(),
            format!("{},{}({})", fpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::READ_MEM,
        ),
        49 => (
            "LFSU".to_string(),
            format!("{},{}({})", fpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::READ_MEM,
        ),
        50 => (
            "LFD".to_string(),
            format!("{},{}({})", fpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::READ_MEM,
        ),
        51 => (
            "LFDU".to_string(),
            format!("{},{}({})", fpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::READ_MEM,
        ),
        52 => (
            "STFS".to_string(),
            format!("{},{}({})", fpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::WRITE_MEM,
        ),
        53 => (
            "STFSU".to_string(),
            format!("{},{}({})", fpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::WRITE_MEM,
        ),
        54 => (
            "STFD".to_string(),
            format!("{},{}({})", fpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::WRITE_MEM,
        ),
        55 => (
            "STFDU".to_string(),
            format!("{},{}({})", fpr(rs), simm16(instr), gpr(ra)),
            InstrFlags::WRITE_MEM,
        ),
        _ => (
            "DC.W".to_string(),
            format!("${instr:08X}"),
            InstrFlags::NONE,
        ),
    }
}

// ── Main decode ───────────────────────────────────────────────────────────────
fn decode_ppc(bytes: &[u8], pc: u64) -> Result<(String, String, InstrFlags), CoreError> {
    if bytes.len() < 4 {
        return Err(CoreError::InvalidFormat {
            message: "truncated PPC instruction".to_string(),
        });
    }
    let instr = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    let opcd = instr >> 26;
    let rs = (instr >> 21) & 31;
    let ra = (instr >> 16) & 31;
    let rb = (instr >> 11) & 31;
    let rc_bit = instr & 1;
    let oe_bit = (instr >> 10) & 1;
    let rc_sfx = if rc_bit != 0 { "." } else { "" };
    let xo = (instr >> 1) & 0x3FF;

    match opcd {
        3 => Ok((
            "TWI".to_string(),
            format!("{},{},{}", rs, gpr(ra), simm16(instr)),
            InstrFlags::NONE,
        )),
        7 => Ok((
            "MULLI".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), simm16(instr)),
            InstrFlags::NONE,
        )),
        8 => Ok((
            "SUBFIC".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), simm16(instr)),
            InstrFlags::NONE,
        )),
        10 => {
            let crfd = (instr >> 23) & 7;
            Ok((
                "CMPLWI".to_string(),
                format!("{},{},{}", crfield(crfd), gpr(ra), uimm16(instr)),
                InstrFlags::NONE,
            ))
        }
        11 => {
            let crfd = (instr >> 23) & 7;
            Ok((
                "CMPWI".to_string(),
                format!("{},{},{}", crfield(crfd), gpr(ra), simm16(instr)),
                InstrFlags::NONE,
            ))
        }
        12 => Ok((
            "ADDIC".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), simm16(instr)),
            InstrFlags::NONE,
        )),
        13 => Ok((
            "ADDIC.".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), simm16(instr)),
            InstrFlags::NONE,
        )),
        14 => {
            if ra == 0 {
                Ok((
                    "LI".to_string(),
                    format!("{},{}", gpr(rs), simm16(instr)),
                    InstrFlags::NONE,
                ))
            } else {
                Ok((
                    "ADDI".to_string(),
                    format!("{},{},{}", gpr(rs), gpr(ra), simm16(instr)),
                    InstrFlags::NONE,
                ))
            }
        }
        15 => {
            if ra == 0 {
                Ok((
                    "LIS".to_string(),
                    format!("{},{}", gpr(rs), simm16(instr)),
                    InstrFlags::NONE,
                ))
            } else {
                Ok((
                    "ADDIS".to_string(),
                    format!("{},{},{}", gpr(rs), gpr(ra), simm16(instr)),
                    InstrFlags::NONE,
                ))
            }
        }
        16 => {
            let bo = (instr >> 21) & 31;
            let bi = (instr >> 16) & 31;
            let bd_raw = i32::try_from(instr & 0xFFFC).unwrap_or(0);
            let bd = if bd_raw & 0x8000 != 0 {
                bd_raw - 0x1_0000
            } else {
                bd_raw
            };
            let aa = (instr >> 1) & 1;
            let lk = instr & 1;
            let target = branch_target(pc, bd, aa);
            let (name, is_cond) = bc_name(bi, bo);
            let lk_sfx = if lk != 0 { "L" } else { "" };
            let flags = if lk != 0 {
                InstrFlags::CALL.union(if is_cond {
                    InstrFlags::CONDITIONAL
                } else {
                    InstrFlags::NONE
                })
            } else {
                InstrFlags::BRANCH.union(if is_cond {
                    InstrFlags::CONDITIONAL
                } else {
                    InstrFlags::NONE
                })
            };
            Ok((format!("{name}{lk_sfx}"), format!("${target:08X}"), flags))
        }
        17 => Ok(("SC".to_string(), String::new(), InstrFlags::NONE)),
        18 => {
            let li_raw = i32::try_from(instr & 0x03FF_FFFC).unwrap_or(0);
            let li = if li_raw & 0x0200_0000 != 0 {
                li_raw - 0x0400_0000
            } else {
                li_raw
            };
            let aa = (instr >> 1) & 1;
            let lk = instr & 1;
            let target = branch_target(pc, li, aa);
            let mn = match (aa, lk) {
                (0, 0) => "B",
                (0, 1) => "BL",
                (1, 0) => "BA",
                _ => "BLA",
            };
            Ok((
                mn.to_string(),
                format!("${target:08X}"),
                if lk != 0 {
                    InstrFlags::CALL
                } else {
                    InstrFlags::BRANCH
                },
            ))
        }
        19 => {
            let xo19 = (instr >> 1) & 0x3FF;
            match xo19 {
                0 => Ok((
                    "MCRF".to_string(),
                    format!("{},{}", crfield(rs >> 2), crfield(ra >> 2)),
                    InstrFlags::NONE,
                )),
                16 => {
                    let lk = instr & 1;
                    Ok((
                        if lk != 0 { "BCLRL" } else { "BCLR" }.to_string(),
                        String::new(),
                        InstrFlags::RET,
                    ))
                }
                18 | 50 => Ok(("RFI".to_string(), String::new(), InstrFlags::RET)),
                528 => {
                    let lk = instr & 1;
                    Ok((
                        if lk != 0 { "BCCTRL" } else { "BCCTR" }.to_string(),
                        String::new(),
                        InstrFlags::BRANCH.union(InstrFlags::INDIRECT),
                    ))
                }
                150 => Ok(("ISYNC".to_string(), String::new(), InstrFlags::BARRIER)),
                _ => Ok((
                    "DC.W".to_string(),
                    format!("${instr:08X}"),
                    InstrFlags::NONE,
                )),
            }
        }
        20 => {
            let (sh, mb, me) = ((instr >> 11) & 31, (instr >> 6) & 31, (instr >> 1) & 31);
            Ok((
                format!("RLWIMI{rc_sfx}"),
                format!("{},{},{},{},{}", gpr(ra), gpr(rs), sh, mb, me),
                InstrFlags::NONE,
            ))
        }
        21 => {
            let (sh, mb, me) = ((instr >> 11) & 31, (instr >> 6) & 31, (instr >> 1) & 31);
            Ok((
                format!("RLWINM{rc_sfx}"),
                format!("{},{},{},{},{}", gpr(ra), gpr(rs), sh, mb, me),
                InstrFlags::NONE,
            ))
        }
        23 => {
            let (mb, me) = ((instr >> 6) & 31, (instr >> 1) & 31);
            Ok((
                format!("RLWNM{rc_sfx}"),
                format!("{},{},{},{},{}", gpr(ra), gpr(rs), gpr(rb), mb, me),
                InstrFlags::NONE,
            ))
        }
        24 => Ok((
            "ORI".to_string(),
            format!("{},{},{}", gpr(ra), gpr(rs), uimm16(instr)),
            InstrFlags::NONE,
        )),
        25 => Ok((
            "ORIS".to_string(),
            format!("{},{},{}", gpr(ra), gpr(rs), uimm16(instr)),
            InstrFlags::NONE,
        )),
        26 => Ok((
            "XORI".to_string(),
            format!("{},{},{}", gpr(ra), gpr(rs), uimm16(instr)),
            InstrFlags::NONE,
        )),
        27 => Ok((
            "XORIS".to_string(),
            format!("{},{},{}", gpr(ra), gpr(rs), uimm16(instr)),
            InstrFlags::NONE,
        )),
        28 => Ok((
            "ANDI.".to_string(),
            format!("{},{},{}", gpr(ra), gpr(rs), uimm16(instr)),
            InstrFlags::NONE,
        )),
        29 => Ok((
            "ANDIS.".to_string(),
            format!("{},{},{}", gpr(ra), gpr(rs), uimm16(instr)),
            InstrFlags::NONE,
        )),
        31 => Ok(decode_ppc31(instr, rs, ra, rb, xo, oe_bit, rc_sfx)),
        32..=55 => Ok(decode_ppc_mem(opcd, instr, rs, ra)),
        63 => Ok(decode_fp63(instr, rs, ra, rb, rc_sfx)),
        _ => Ok((
            "DC.W".to_string(),
            format!("${instr:08X}"),
            InstrFlags::NONE,
        )),
    }
}

/// Packed context for opcode-31 decoding (reduces argument count).
struct Ppc31Args<'a> {
    instr: u32,
    rs: u32,
    ra: u32,
    rb: u32,
    sfx: String,
    rc_sfx: &'a str,
}

fn decode_ppc31(
    instr: u32,
    rs: u32,
    ra: u32,
    rb: u32,
    xo: u32,
    oe_bit: u32,
    rc_sfx: &str,
) -> (String, String, InstrFlags) {
    let oe_sfx = if oe_bit != 0 { "O" } else { "" };
    let sfx = format!("{oe_sfx}{rc_sfx}");
    let ctx = Ppc31Args {
        instr,
        rs,
        ra,
        rb,
        sfx,
        rc_sfx,
    };
    decode_ppc31_lo(xo, &ctx).unwrap_or_else(|| decode_ppc31_hi(xo, &ctx))
}

/// Decode opcode-31 low extended opcodes (xo 0..=316).
fn decode_ppc31_lo(xo: u32, c: &Ppc31Args<'_>) -> Option<(String, String, InstrFlags)> {
    let (instr, rs, ra, rb) = (c.instr, c.rs, c.ra, c.rb);
    let sfx = c.sfx.as_str();
    let rc_sfx = c.rc_sfx;
    Some(match xo {
        0 => (
            "CMP".to_string(),
            format!("{},{},{}", crfield(rs >> 2), gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        4 => (
            "TW".to_string(),
            format!("{},{},{}", rs, gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        8 => (
            format!("SUBFC{sfx}"),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        10 => (
            format!("ADDC{sfx}"),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        11 => (
            "MULHWU".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        19 => ("MFCR".to_string(), gpr(rs), InstrFlags::NONE),
        20 => (
            "LWARX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        21 => (
            "LWZX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        23 => (
            format!("SLW{rc_sfx}"),
            format!("{},{},{}", gpr(ra), gpr(rs), gpr(rb)),
            InstrFlags::NONE,
        ),
        24 => (
            format!("CNTLZW{rc_sfx}"),
            format!("{},{}", gpr(ra), gpr(rs)),
            InstrFlags::NONE,
        ),
        26 | 536 => (
            format!("SRW{rc_sfx}"),
            format!("{},{},{}", gpr(ra), gpr(rs), gpr(rb)),
            InstrFlags::NONE,
        ),
        27 | 75 => (
            "MULHW".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        28 => (
            format!("AND{rc_sfx}"),
            format!("{},{},{}", gpr(ra), gpr(rs), gpr(rb)),
            InstrFlags::NONE,
        ),
        32 => (
            "CMPL".to_string(),
            format!("{},{},{}", crfield(rs >> 2), gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        40 => (
            format!("SUBF{sfx}"),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        54 => (
            "DCBST".to_string(),
            format!("{},{}", gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        55 => (
            "LWZUX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        60 => (
            format!("ANDC{rc_sfx}"),
            format!("{},{},{}", gpr(ra), gpr(rs), gpr(rb)),
            InstrFlags::NONE,
        ),
        83 | 115 => ("MFMSR".to_string(), gpr(rs), InstrFlags::NONE),
        84 => (
            "LDARX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        86 => (
            "DCBF".to_string(),
            format!("{},{}", gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        87 => (
            "LBZX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        104 => (
            format!("NEG{sfx}"),
            format!("{},{}", gpr(rs), gpr(ra)),
            InstrFlags::NONE,
        ),
        119 => (
            "LBZUX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        124 => (
            format!("NOR{rc_sfx}"),
            format!("{},{},{}", gpr(ra), gpr(rs), gpr(rb)),
            InstrFlags::NONE,
        ),
        136 => (
            format!("SUBFE{sfx}"),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        138 => (
            format!("ADDE{sfx}"),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        144 => (
            "MTCRF".to_string(),
            format!("{},{}", (instr >> 12) & 0xFF, gpr(rs)),
            InstrFlags::NONE,
        ),
        146 => ("MTMSR".to_string(), gpr(rs), InstrFlags::NONE),
        149 => (
            "STDX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::WRITE_MEM,
        ),
        150 => (
            "STWCX.".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::WRITE_MEM,
        ),
        151 => (
            "STWX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::WRITE_MEM,
        ),
        167 => (
            "STDUX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::WRITE_MEM,
        ),
        183 => (
            "STWUX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::WRITE_MEM,
        ),
        200 => (
            format!("SUBFZE{sfx}"),
            format!("{},{}", gpr(rs), gpr(ra)),
            InstrFlags::NONE,
        ),
        202 => (
            format!("ADDZE{sfx}"),
            format!("{},{}", gpr(rs), gpr(ra)),
            InstrFlags::NONE,
        ),
        210 => (
            "MTSR".to_string(),
            format!("{},{}", (instr >> 16) & 0xF, gpr(rs)),
            InstrFlags::NONE,
        ),
        215 => (
            "STBX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::WRITE_MEM,
        ),
        232 => (
            format!("SUBFME{sfx}"),
            format!("{},{}", gpr(rs), gpr(ra)),
            InstrFlags::NONE,
        ),
        234 => (
            format!("ADDME{sfx}"),
            format!("{},{}", gpr(rs), gpr(ra)),
            InstrFlags::NONE,
        ),
        235 => (
            format!("MULLW{sfx}"),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        242 => (
            "MTSRIN".to_string(),
            format!("{},{}", gpr(rs), gpr(rb)),
            InstrFlags::NONE,
        ),
        247 => (
            "STBUX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::WRITE_MEM,
        ),
        266 => (
            format!("ADD{sfx}"),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        278 => (
            "DCBT".to_string(),
            format!("{},{}", gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        279 => (
            "LHZX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        284 => (
            format!("EQV{rc_sfx}"),
            format!("{},{},{}", gpr(ra), gpr(rs), gpr(rb)),
            InstrFlags::NONE,
        ),
        306 => ("TLBIE".to_string(), gpr(rb), InstrFlags::NONE),
        310 => (
            "ECIWX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        311 => (
            "LHZUX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        316 => (
            format!("XOR{rc_sfx}"),
            format!("{},{},{}", gpr(ra), gpr(rs), gpr(rb)),
            InstrFlags::NONE,
        ),
        _ => return None,
    })
}

/// Decode opcode-31 high extended opcodes (xo 339..=1014).
fn decode_ppc31_hi(xo: u32, c: &Ppc31Args<'_>) -> (String, String, InstrFlags) {
    let (instr, rs, ra, rb) = (c.instr, c.rs, c.ra, c.rb);
    let sfx = c.sfx.as_str();
    let rc_sfx = c.rc_sfx;
    match xo {
        339 => {
            let spr_raw = (instr >> 11) & 0x3FF;
            let spr = ((spr_raw & 0x1F) << 5) | (spr_raw >> 5);
            let mn = match spr {
                1 => "MFXER",
                8 => "MFLR",
                9 => "MFCTR",
                _ => "MFSPR",
            };
            if mn == "MFSPR" {
                (
                    "MFSPR".to_string(),
                    format!("{},{}", gpr(rs), spr),
                    InstrFlags::NONE,
                )
            } else {
                (mn.to_string(), gpr(rs), InstrFlags::NONE)
            }
        }
        343 => (
            "LHAX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        375 => (
            "LHAUX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        407 => (
            "STHX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::WRITE_MEM,
        ),
        412 => (
            format!("ORC{rc_sfx}"),
            format!("{},{},{}", gpr(ra), gpr(rs), gpr(rb)),
            InstrFlags::NONE,
        ),
        444 => (
            format!("OR{rc_sfx}"),
            format!("{},{},{}", gpr(ra), gpr(rs), gpr(rb)),
            InstrFlags::NONE,
        ),
        459 => (
            format!("DIVWU{sfx}"),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        467 => {
            let spr_raw = (instr >> 11) & 0x3FF;
            let spr = ((spr_raw & 0x1F) << 5) | (spr_raw >> 5);
            let mn = match spr {
                1 => "MTXER",
                8 => "MTLR",
                9 => "MTCTR",
                _ => "MTSPR",
            };
            if mn == "MTSPR" {
                (
                    "MTSPR".to_string(),
                    format!("{},{}", spr, gpr(rs)),
                    InstrFlags::NONE,
                )
            } else {
                (mn.to_string(), gpr(rs), InstrFlags::NONE)
            }
        }
        476 => (
            format!("NAND{rc_sfx}"),
            format!("{},{},{}", gpr(ra), gpr(rs), gpr(rb)),
            InstrFlags::NONE,
        ),
        491 => (
            format!("DIVW{sfx}"),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        512 => ("MCRXR".to_string(), crfield(rs >> 2), InstrFlags::NONE),
        533 => (
            "LSWX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        534 => (
            "LWBRX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        535 => (
            "LFSX".to_string(),
            format!("{},{},{}", fpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        567 => (
            "LFSUX".to_string(),
            format!("{},{},{}", fpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        595 => (
            "MFSR".to_string(),
            format!("{},{}", gpr(rs), (instr >> 16) & 0xF),
            InstrFlags::NONE,
        ),
        597 => (
            "LSWI".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), rb),
            InstrFlags::READ_MEM,
        ),
        598 => ("SYNC".to_string(), String::new(), InstrFlags::BARRIER),
        599 => (
            "LFDX".to_string(),
            format!("{},{},{}", fpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        631 => (
            "LFDUX".to_string(),
            format!("{},{},{}", fpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::READ_MEM,
        ),
        661 => (
            "STSWX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::WRITE_MEM,
        ),
        662 => (
            "STWBRX".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::WRITE_MEM,
        ),
        663 => (
            "STFSX".to_string(),
            format!("{},{},{}", fpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::WRITE_MEM,
        ),
        695 => (
            "STFSUX".to_string(),
            format!("{},{},{}", fpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::WRITE_MEM,
        ),
        725 => (
            "STSWI".to_string(),
            format!("{},{},{}", gpr(rs), gpr(ra), rb),
            InstrFlags::WRITE_MEM,
        ),
        727 => (
            "STFDX".to_string(),
            format!("{},{},{}", fpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::WRITE_MEM,
        ),
        759 => (
            "STFDUX".to_string(),
            format!("{},{},{}", fpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::WRITE_MEM,
        ),
        792 => (
            format!("SRAW{rc_sfx}"),
            format!("{},{},{}", gpr(ra), gpr(rs), gpr(rb)),
            InstrFlags::NONE,
        ),
        824 => (
            format!("SRAWI{rc_sfx}"),
            format!("{},{},{}", gpr(ra), gpr(rs), rb),
            InstrFlags::NONE,
        ),
        854 => ("EIEIO".to_string(), String::new(), InstrFlags::BARRIER),
        922 => (
            format!("EXTSH{rc_sfx}"),
            format!("{},{}", gpr(ra), gpr(rs)),
            InstrFlags::NONE,
        ),
        954 => (
            format!("EXTSB{rc_sfx}"),
            format!("{},{}", gpr(ra), gpr(rs)),
            InstrFlags::NONE,
        ),
        982 => (
            "ICBI".to_string(),
            format!("{},{}", gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        983 => (
            "STFIWX".to_string(),
            format!("{},{},{}", fpr(rs), gpr(ra), gpr(rb)),
            InstrFlags::WRITE_MEM,
        ),
        986 => (
            format!("EXTSW{rc_sfx}"),
            format!("{},{}", gpr(ra), gpr(rs)),
            InstrFlags::NONE,
        ),
        1014 => (
            "DCBZ".to_string(),
            format!("{},{}", gpr(ra), gpr(rb)),
            InstrFlags::NONE,
        ),
        _ => (
            "DC.W".to_string(),
            format!("${instr:08X}"),
            InstrFlags::NONE,
        ),
    }
}

fn decode_fp63(
    instr: u32,
    rs: u32,
    ra: u32,
    rb: u32,
    rc_sfx: &str,
) -> (String, String, InstrFlags) {
    let xo = (instr >> 1) & 0x1F;
    let xo10 = (instr >> 1) & 0x3FF;
    match xo10 {
        0 => (
            "FCMPU".to_string(),
            format!("{},{},{}", crfield(rs >> 2), fpr(ra), fpr(rb)),
            InstrFlags::NONE,
        ),
        12 => (
            format!("FRSP{rc_sfx}"),
            format!("{},{}", fpr(rs), fpr(rb)),
            InstrFlags::NONE,
        ),
        14 => (
            format!("FCTIW{rc_sfx}"),
            format!("{},{}", fpr(rs), fpr(rb)),
            InstrFlags::NONE,
        ),
        15 => (
            format!("FCTIWZ{rc_sfx}"),
            format!("{},{}", fpr(rs), fpr(rb)),
            InstrFlags::NONE,
        ),
        32 => (
            "FCMPO".to_string(),
            format!("{},{},{}", crfield(rs >> 2), fpr(ra), fpr(rb)),
            InstrFlags::NONE,
        ),
        40 => (
            format!("FNEG{rc_sfx}"),
            format!("{},{}", fpr(rs), fpr(rb)),
            InstrFlags::NONE,
        ),
        64 => (
            "MCRFS".to_string(),
            format!("{},{}", crfield(rs >> 2), crfield(ra >> 2)),
            InstrFlags::NONE,
        ),
        72 => (
            format!("FMR{rc_sfx}"),
            format!("{},{}", fpr(rs), fpr(rb)),
            InstrFlags::NONE,
        ),
        136 => (
            format!("FNABS{rc_sfx}"),
            format!("{},{}", fpr(rs), fpr(rb)),
            InstrFlags::NONE,
        ),
        264 => (
            format!("FABS{rc_sfx}"),
            format!("{},{}", fpr(rs), fpr(rb)),
            InstrFlags::NONE,
        ),
        583 => ("MFFS".to_string(), fpr(rs), InstrFlags::NONE),
        711 => (
            "MTFSF".to_string(),
            format!("{},{}", (instr >> 17) & 0xFF, fpr(rb)),
            InstrFlags::NONE,
        ),
        814 => (
            format!("FCTID{rc_sfx}"),
            format!("{},{}", fpr(rs), fpr(rb)),
            InstrFlags::NONE,
        ),
        815 => (
            format!("FCTIDZ{rc_sfx}"),
            format!("{},{}", fpr(rs), fpr(rb)),
            InstrFlags::NONE,
        ),
        846 => (
            format!("FCFID{rc_sfx}"),
            format!("{},{}", fpr(rs), fpr(rb)),
            InstrFlags::NONE,
        ),
        _ => {
            let frc = (instr >> 6) & 31;
            match xo {
                18 => (
                    format!("FDIVD{rc_sfx}"),
                    format!("{},{},{}", fpr(rs), fpr(ra), fpr(rb)),
                    InstrFlags::NONE,
                ),
                20 => (
                    format!("FSUBD{rc_sfx}"),
                    format!("{},{},{}", fpr(rs), fpr(ra), fpr(rb)),
                    InstrFlags::NONE,
                ),
                21 => (
                    format!("FADDD{rc_sfx}"),
                    format!("{},{},{}", fpr(rs), fpr(ra), fpr(rb)),
                    InstrFlags::NONE,
                ),
                22 => (
                    format!("FSQRTD{rc_sfx}"),
                    format!("{},{}", fpr(rs), fpr(rb)),
                    InstrFlags::NONE,
                ),
                24 => (
                    format!("FRES{rc_sfx}"),
                    format!("{},{}", fpr(rs), fpr(rb)),
                    InstrFlags::NONE,
                ),
                25 => (
                    format!("FMULD{rc_sfx}"),
                    format!("{},{},{}", fpr(rs), fpr(ra), fpr(frc)),
                    InstrFlags::NONE,
                ),
                28 => (
                    format!("FMSUBD{rc_sfx}"),
                    format!("{},{},{},{}", fpr(rs), fpr(ra), fpr(frc), fpr(rb)),
                    InstrFlags::NONE,
                ),
                29 => (
                    format!("FMADDD{rc_sfx}"),
                    format!("{},{},{},{}", fpr(rs), fpr(ra), fpr(frc), fpr(rb)),
                    InstrFlags::NONE,
                ),
                30 => (
                    format!("FNMSUBD{rc_sfx}"),
                    format!("{},{},{},{}", fpr(rs), fpr(ra), fpr(frc), fpr(rb)),
                    InstrFlags::NONE,
                ),
                31 => (
                    format!("FNMADDD{rc_sfx}"),
                    format!("{},{},{},{}", fpr(rs), fpr(ra), fpr(frc), fpr(rb)),
                    InstrFlags::NONE,
                ),
                _ => (
                    "DC.W".to_string(),
                    format!("${instr:08X}"),
                    InstrFlags::NONE,
                ),
            }
        }
    }
}

// ── Main architecture struct ──────────────────────────────────────────────────

/// PowerPC architecture.
#[derive(Debug, Clone)]
pub struct PpcArch {
    pub bits: u32,
    pub endian: Endian,
}

impl PpcArch {
    #[must_use]
    pub const fn new_32() -> Self {
        Self {
            bits: 32,
            endian: Endian::Big,
        }
    }
    #[must_use]
    pub const fn new_64() -> Self {
        Self {
            bits: 64,
            endian: Endian::Big,
        }
    }
    #[must_use]
    pub const fn new_le() -> Self {
        Self {
            bits: 32,
            endian: Endian::Little,
        }
    }
}

impl Default for PpcArch {
    fn default() -> Self {
        Self::new_32()
    }
}

impl Architecture for PpcArch {
    fn name(&self) -> &str {
        match (self.bits, self.endian) {
            (64, Endian::Big) => "ppc64",
            (64, Endian::Little) => "ppc64le",
            (32, Endian::Little) => "ppcle",
            _ => "ppc",
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
        // Handle endian for instruction word fetch
        let insn_bytes = if self.endian == Endian::Little {
            [bytes[3], bytes[2], bytes[1], bytes[0]]
        } else {
            [bytes[0], bytes[1], bytes[2], bytes[3]]
        };
        let (mnemonic, operands, flags) = decode_ppc(&insn_bytes, address.as_u64())?;
        let mut instr = Instruction::new(address, 4, mnemonic, bytes[..4].to_vec());
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
            let branch = if instr.flags.contains(InstrFlags::CONDITIONAL) {
                BranchInfo::conditional_jump(target, BranchCondition::Custom(0))
            } else if instr.flags.contains(InstrFlags::CALL) {
                BranchInfo::call(target)
            } else {
                BranchInfo::unconditional_jump(target)
            };
            return vec![branch];
        }
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        let psize = self.pointer_size();
        let mut regs: Vec<RegisterInfo> = (0u32..32)
            .map(|i| {
                // r1 is the PowerPC stack pointer.
                let kind = if i == 1 {
                    RegisterKind::Stack
                } else {
                    RegisterKind::General
                };
                RegisterInfo::new(format!("r{i}"), REG_R0 + i, psize, kind)
            })
            .collect();
        for i in 0u32..32 {
            regs.push(RegisterInfo::new(
                format!("f{i}"),
                REG_F0 + i,
                8,
                RegisterKind::Float,
            ));
        }
        for i in 0u32..8 {
            regs.push(RegisterInfo::new(
                format!("cr{i}"),
                REG_CR + i,
                1,
                RegisterKind::Flags,
            ));
        }
        regs.push(RegisterInfo::new("XER", REG_XER, 4, RegisterKind::Flags));
        regs.push(RegisterInfo::new("LR", REG_LR, psize, RegisterKind::Link));
        regs.push(RegisterInfo::new(
            "CTR",
            REG_CTR,
            psize,
            RegisterKind::General,
        ));
        regs.push(RegisterInfo::new(
            "PC",
            REG_PC,
            psize,
            RegisterKind::ProgramCounter,
        ));
        regs
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![
            CallingConvention::new("ppc_sysv")
                .with_int_args(vec![
                    "r3".to_string(),
                    "r4".to_string(),
                    "r5".to_string(),
                    "r6".to_string(),
                    "r7".to_string(),
                    "r8".to_string(),
                ])
                .with_return_regs(vec!["r3".to_string(), "r4".to_string()]),
        ]
    }
}

// ── Linear disassembler ───────────────────────────────────────────────────────

/// Linear-sweep disassembler for PowerPC code.
pub struct PpcLinearDisassembler<'a> {
    arch: &'a PpcArch,
    bytes: &'a [u8],
    base: Address,
    offset: usize,
}

impl<'a> PpcLinearDisassembler<'a> {
    #[must_use]
    pub const fn new(arch: &'a PpcArch, bytes: &'a [u8], base: Address) -> Self {
        Self {
            arch,
            bytes,
            base,
            offset: 0,
        }
    }
}

impl Iterator for PpcLinearDisassembler<'_> {
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

    fn arch() -> PpcArch {
        PpcArch::default()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    #[test]
    fn test_nop() {
        // NOP = ORI r0,r0,0 = 0x60000000
        let instr = arch()
            .disassemble(addr(0x1000), &[0x60, 0x00, 0x00, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "ORI");
        assert_eq!(instr.size, 4);
    }

    #[test]
    fn test_li() {
        // LI r3,1 = 0x38600001
        let instr = arch()
            .disassemble(addr(0x1000), &[0x38, 0x60, 0x00, 0x01])
            .unwrap();
        assert_eq!(instr.mnemonic, "LI");
        assert!(instr.operands.contains("r3"));
    }

    #[test]
    fn test_addi() {
        // ADDI r3,r3,4 = 0x38630004
        let instr = arch()
            .disassemble(addr(0x1000), &[0x38, 0x63, 0x00, 0x04])
            .unwrap();
        assert_eq!(instr.mnemonic, "ADDI");
    }

    #[test]
    fn test_addis_lis() {
        // LIS r3,1 = 0x3C600001
        let instr = arch()
            .disassemble(addr(0x1000), &[0x3C, 0x60, 0x00, 0x01])
            .unwrap();
        assert_eq!(instr.mnemonic, "LIS");
    }

    #[test]
    fn test_b_branch() {
        // B +0 = 0x48000000
        let instr = arch()
            .disassemble(addr(0x1000), &[0x48, 0x00, 0x00, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "B");
        assert!(instr.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_bl_call() {
        // BL +0 = 0x48000001
        let instr = arch()
            .disassemble(addr(0x1000), &[0x48, 0x00, 0x00, 0x01])
            .unwrap();
        assert_eq!(instr.mnemonic, "BL");
        assert!(instr.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_blr_return() {
        // BCLR (return) = 0x4E800020
        let instr = arch()
            .disassemble(addr(0x1000), &[0x4E, 0x80, 0x00, 0x20])
            .unwrap();
        assert_eq!(instr.mnemonic, "BCLR");
        assert!(instr.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_lwz() {
        // LWZ r3,0(r1) = 0x80610000
        let instr = arch()
            .disassemble(addr(0x1000), &[0x80, 0x61, 0x00, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "LWZ");
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_stw() {
        // STW r3,0(r1) = 0x90610000
        let instr = arch()
            .disassemble(addr(0x1000), &[0x90, 0x61, 0x00, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "STW");
        assert!(instr.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_or_mr() {
        // MR r4,r3 = OR r4,r3,r3 = 0x7C641B78 (example)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x83, 0x23, 0x78])
            .unwrap();
        assert_eq!(instr.mnemonic, "OR");
    }

    #[test]
    fn test_cmpwi() {
        // CMPWI r3,0 = 0x2C030000
        let instr = arch()
            .disassemble(addr(0x1000), &[0x2C, 0x03, 0x00, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "CMPWI");
    }

    #[test]
    fn test_beq_conditional() {
        // BEQ target
        let instr = arch()
            .disassemble(addr(0x1000), &[0x41, 0x82, 0x00, 0x08])
            .unwrap();
        assert!(instr.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_sc_syscall() {
        // SC = 0x44000002
        let instr = arch()
            .disassemble(addr(0x1000), &[0x44, 0x00, 0x00, 0x02])
            .unwrap();
        assert_eq!(instr.mnemonic, "SC");
    }

    #[test]
    fn test_registers_count() {
        let regs = arch().registers();
        assert!(regs.len() >= 75); // 32 gpr + 32 fpr + 8 cr + 4 special
    }

    #[test]
    fn test_name_endian() {
        assert_eq!(arch().name(), "ppc");
        assert_eq!(arch().endian(), Endian::Big);
        assert_eq!(arch().pointer_size(), 4);
    }

    #[test]
    fn test_ppc64_name() {
        let a = PpcArch::new_64();
        assert_eq!(a.name(), "ppc64");
        assert_eq!(a.pointer_size(), 8);
    }

    #[test]
    fn test_mflr() {
        // MFLR r0 = 0x7C0802A6
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x08, 0x02, 0xA6])
            .unwrap();
        assert_eq!(instr.mnemonic, "MFLR");
    }

    #[test]
    fn test_linear_disassembler() {
        // LI r3,1; BL +0
        let code = [0x38u8, 0x60, 0x00, 0x01, 0x48, 0x00, 0x00, 0x01];
        let a = arch();
        let instrs: Vec<_> = PpcLinearDisassembler::new(&a, &code, addr(0x1000))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[0].mnemonic, "LI");
        assert_eq!(instrs[1].mnemonic, "BL");
    }

    #[test]
    fn test_mtlr() {
        // MTLR r0 = 0x7C0803A6
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x08, 0x03, 0xA6])
            .unwrap();
        assert_eq!(instr.mnemonic, "MTLR");
    }

    #[test]
    fn test_lbz() {
        // LBZ r3,0(r1) = 0x88610000
        let instr = arch()
            .disassemble(addr(0x1000), &[0x88, 0x61, 0x00, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "LBZ");
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_stb() {
        // STB r3,0(r1) = 0x98610000
        let instr = arch()
            .disassemble(addr(0x1000), &[0x98, 0x61, 0x00, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "STB");
        assert!(instr.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_lhz() {
        // LHZ r3,0(r1) = 0xA0610000
        let instr = arch()
            .disassemble(addr(0x1000), &[0xA0, 0x61, 0x00, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "LHZ");
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_rlwinm() {
        // RLWINM r5,r3,16,0,15 = 0x5465_0800 (simplified)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x54, 0x65, 0x08, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "RLWINM");
    }

    #[test]
    fn test_calling_convention_sysv() {
        let ccs = arch().calling_conventions();
        assert!(!ccs.is_empty());
        assert_eq!(ccs[0].name, "ppc_sysv");
        assert!(ccs[0].int_args.contains(&"r3".to_string()));
    }

    #[test]
    fn test_bcctr_indirect_branch() {
        // BCCTR = 0x4E800420
        let instr = arch()
            .disassemble(addr(0x1000), &[0x4E, 0x80, 0x04, 0x20])
            .unwrap();
        assert_eq!(instr.mnemonic, "BCCTR");
        assert!(instr.flags.contains(InstrFlags::INDIRECT));
    }

    #[test]
    fn test_truncated_input_error() {
        let a = arch();
        let result = a.disassemble(addr(0x0), &[0x48, 0x00]);
        assert!(result.is_err(), "expected error on truncated input");
    }

    // ── Additional instruction tests ──────────────────────────────────────

    #[test]
    fn test_add() {
        // ADD r3,r3,r4 = 0x7C632214 (opcd=31, xo=266)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x63, 0x22, 0x14])
            .unwrap();
        assert_eq!(instr.mnemonic, "ADD");
    }

    #[test]
    fn test_sub_subf() {
        // SUBF r3,r4,r3 = 0x7C632050 (opcd=31, xo=40)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x63, 0x20, 0x50])
            .unwrap();
        assert_eq!(instr.mnemonic, "SUBF");
    }

    #[test]
    fn test_mullw() {
        // MULLW r3,r3,r4 = 0x7C6321D6 (opcd=31, xo=235)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x63, 0x21, 0xD6])
            .unwrap();
        assert_eq!(instr.mnemonic, "MULLW");
    }

    #[test]
    fn test_divw() {
        // DIVW r3,r3,r4 = 0x7C6323D6 (opcd=31, xo=491)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x63, 0x23, 0xD6])
            .unwrap();
        assert_eq!(instr.mnemonic, "DIVW");
    }

    #[test]
    fn test_slw() {
        // SLW r4,r3,r5: opcd=31, rs=3, ra=4, rb=5, xo=23 → 0x7C64282E
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x64, 0x28, 0x2E])
            .unwrap();
        assert_eq!(instr.mnemonic, "SLW");
    }

    #[test]
    fn test_srw() {
        // SRW r4,r3,r5 = 0x7C642C30 (opcd=31, xo=536)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x64, 0x2C, 0x30])
            .unwrap();
        assert_eq!(instr.mnemonic, "SRW");
    }

    #[test]
    fn test_and_instr() {
        // AND r4,r3,r5 = 0x7C642038 (opcd=31, xo=28)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x64, 0x20, 0x38])
            .unwrap();
        assert_eq!(instr.mnemonic, "AND");
    }

    #[test]
    fn test_or_instr() {
        // OR r4,r3,r3 = MR r4,r3 = 0x7C641B78 (opcd=31, xo=444)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x64, 0x1B, 0x78])
            .unwrap();
        assert_eq!(instr.mnemonic, "OR");
    }

    #[test]
    fn test_xor_instr() {
        // XOR r4,r3,r5 = 0x7C642278 (opcd=31, xo=316)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x64, 0x22, 0x78])
            .unwrap();
        assert_eq!(instr.mnemonic, "XOR");
    }

    #[test]
    fn test_nor_instr() {
        // NOR r4,r3,r3 = NOT r4,r3 = 0x7C6418F8 (opcd=31, xo=124)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x64, 0x18, 0xF8])
            .unwrap();
        assert_eq!(instr.mnemonic, "NOR");
    }

    #[test]
    fn test_neg() {
        // NEG r3,r3 = 0x7C6300D0 (opcd=31, xo=104)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x63, 0x00, 0xD0])
            .unwrap();
        assert_eq!(instr.mnemonic, "NEG");
    }

    #[test]
    fn test_sync() {
        // SYNC = 0x7C0004AC (opcd=31, xo=598)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x00, 0x04, 0xAC])
            .unwrap();
        assert_eq!(instr.mnemonic, "SYNC");
        assert!(instr.flags.contains(InstrFlags::BARRIER));
    }

    #[test]
    fn test_eieio() {
        // EIEIO = 0x7C0006AC (opcd=31, xo=854)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x00, 0x06, 0xAC])
            .unwrap();
        assert_eq!(instr.mnemonic, "EIEIO");
        assert!(instr.flags.contains(InstrFlags::BARRIER));
    }

    #[test]
    fn test_isync() {
        // ISYNC = 0x4C00012C (opcd=19, xo=150)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x4C, 0x00, 0x01, 0x2C])
            .unwrap();
        assert_eq!(instr.mnemonic, "ISYNC");
        assert!(instr.flags.contains(InstrFlags::BARRIER));
    }

    #[test]
    fn test_mtctr() {
        // MTCTR r0 = 0x7C0903A6 (MTSPR 9, r0)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x09, 0x03, 0xA6])
            .unwrap();
        assert_eq!(instr.mnemonic, "MTCTR");
    }

    #[test]
    fn test_mfctr() {
        // MFCTR r0 = 0x7C0902A6 (MFSPR 9, r0)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x7C, 0x09, 0x02, 0xA6])
            .unwrap();
        assert_eq!(instr.mnemonic, "MFCTR");
    }

    #[test]
    fn test_stfd() {
        // STFD f0,0(r1) = 0xD8010000 (opcd=54)
        let instr = arch()
            .disassemble(addr(0x1000), &[0xD8, 0x01, 0x00, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "STFD");
        assert!(instr.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_lfd() {
        // LFD f0,0(r1) = 0xC8010000 (opcd=50)
        let instr = arch()
            .disassemble(addr(0x1000), &[0xC8, 0x01, 0x00, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "LFD");
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_ppc_le_disasm() {
        // NOP in LE = bytes [0x00,0x00,0x00,0x60]
        let a = PpcArch::new_le();
        let instr = a
            .disassemble(addr(0x1000), &[0x00, 0x00, 0x00, 0x60])
            .unwrap();
        assert_eq!(instr.mnemonic, "ORI");
    }

    #[test]
    fn test_branch_target_extraction() {
        // B +8 at 0x1000: 0x48000008
        let a = arch();
        let instr = a
            .disassemble(addr(0x1000), &[0x48, 0x00, 0x00, 0x08])
            .unwrap();
        let branches = a.get_branches(&instr);
        assert!(!branches.is_empty());
        assert_eq!(branches[0].target, Some(0x1008));
    }

    #[test]
    fn test_addic() {
        // ADDIC r3,r3,1 = 0x30630001 (opcd=12)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x30, 0x63, 0x00, 0x01])
            .unwrap();
        assert_eq!(instr.mnemonic, "ADDIC");
    }

    #[test]
    fn test_mulli() {
        // MULLI r3,r3,2 = 0x1C630002 (opcd=7)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x1C, 0x63, 0x00, 0x02])
            .unwrap();
        assert_eq!(instr.mnemonic, "MULLI");
    }

    #[test]
    fn test_subfic() {
        // SUBFIC r3,r3,0 = 0x20630000 (opcd=8)
        let instr = arch()
            .disassemble(addr(0x1000), &[0x20, 0x63, 0x00, 0x00])
            .unwrap();
        assert_eq!(instr.mnemonic, "SUBFIC");
    }

    #[test]
    fn test_ppc64_calling_convention() {
        let a = PpcArch::new_64();
        let cc = a.calling_conventions();
        assert!(!cc.is_empty());
        assert!(cc[0].int_args.contains(&"r3".to_string()));
    }
}

// ── PowerPC Instruction Kind ──────────────────────────────────────────────────

/// Broad category of a PowerPC instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PpcInstrKind {
    /// NOP (ORI 0,0,0).
    Nop,
    /// Load immediate (LI, LIS).
    LoadImm,
    /// Integer arithmetic.
    IntAlu,
    /// Multiply.
    Multiply,
    /// Divide.
    Divide,
    /// Logic (AND, OR, XOR, NOR, …).
    Logic,
    /// Shift / rotate.
    Shift,
    /// Compare.
    Compare,
    /// Load from memory.
    Load,
    /// Store to memory.
    Store,
    /// Floating-point operation.
    FloatOp,
    /// Conditional branch.
    CondBranch,
    /// Unconditional branch.
    Branch,
    /// Call (branch-and-link).
    Call,
    /// Return (BCLR, RFI).
    Return,
    /// Move to/from special-purpose register.
    SprOp,
    /// Memory/cache barrier (SYNC, EIEIO, ISYNC).
    Barrier,
    /// System call (SC).
    Syscall,
    /// Unknown.
    Unknown,
}

impl PpcInstrKind {
    /// Classify a PowerPC instruction by mnemonic.
    #[must_use]
    pub fn from_mnemonic(mn: &str) -> Self {
        // Strip any trailing '.' or 'O' suffix for classification
        let base = mn.trim_end_matches('.');
        let base = base.trim_end_matches('O');
        match base {
            "ORI" | "ORIS" if mn == "ORI" => {
                // NOP is ORI r0,r0,0 but we can't detect that here
                Self::Logic
            }
            "LI" | "LIS" => Self::LoadImm,
            "ADDI" | "ADDIS" | "ADDIC" | "ADDC" | "ADDE" | "ADDME" | "ADDZE" | "ADD" | "SUBFIC"
            | "SUBFC" | "SUBFE" | "SUBFME" | "SUBFZE" | "SUBF" | "NEG" | "MULLI" => Self::IntAlu,
            "MULLW" | "MULHW" | "MULHWU" => Self::Multiply,
            "DIVW" | "DIVWU" => Self::Divide,
            "ANDI" | "ANDIS" | "AND" | "ANDC" | "NAND" | "NOR" | "ORI" | "ORIS" | "OR" | "ORC"
            | "XORI" | "XORIS" | "XOR" | "EQV" | "CNTLZW" | "EXTSB" | "EXTSH" | "EXTSW" => {
                Self::Logic
            }
            "SLW" | "SRW" | "SRAW" | "SRAWI" | "RLWINM" | "RLWIMI" | "RLWNM" => Self::Shift,
            "CMP" | "CMPL" | "CMPWI" | "CMPLWI" | "CMPLDI" | "CMPDI" | "TW" | "TWI" => {
                Self::Compare
            }
            "LWZ" | "LWZU" | "LWZX" | "LWZUX" | "LBZ" | "LBZU" | "LBZX" | "LBZUX" | "LHZ"
            | "LHZU" | "LHZX" | "LHZUX" | "LHA" | "LHAU" | "LHAX" | "LHAUX" | "LMW" | "LSWX"
            | "LSWI" | "LWBRX" | "LHBRX" | "LWARX" | "LDARX" | "LFS" | "LFSU" | "LFSX"
            | "LFSUX" | "LFD" | "LFDU" | "LFDX" | "LFDUX" => Self::Load,
            "STW" | "STWU" | "STWX" | "STWUX" | "STB" | "STBU" | "STBX" | "STBUX" | "STH"
            | "STHU" | "STHX" | "STHUX" | "STMW" | "STSWX" | "STSWI" | "STWBRX" | "STHBRX"
            | "STWCX" | "STDX" | "STDUX" | "STFS" | "STFSU" | "STFSX" | "STFSUX" | "STFD"
            | "STFDU" | "STFDX" | "STFDUX" | "STFIWX" => Self::Store,
            mn if mn.starts_with('F') => Self::FloatOp,
            "BEQ" | "BNE" | "BLT" | "BGT" | "BLE" | "BGE" | "BSO" | "BNS" | "BEQL" | "BNEL"
            | "BLTL" | "BGTL" | "BLEL" | "BGEL" | "BC" | "BCL" => Self::CondBranch,
            "B" | "BA" | "BCCTR" | "BCCTRL" => Self::Branch,
            "BL" | "BLA" => Self::Call,
            "BCLR" | "BCLRL" | "RFI" => Self::Return,
            "MFLR" | "MTLR" | "MFCTR" | "MTCTR" | "MFXER" | "MTXER" | "MFCR" | "MTCRF"
            | "MFSPR" | "MTSPR" | "MFMSR" | "MTMSR" | "MFSR" | "MTSR" | "MTSRIN" => Self::SprOp,
            "SYNC" | "EIEIO" | "ISYNC" | "DCBST" | "DCBF" | "DCBT" | "ICBI" | "DCBZ" => {
                Self::Barrier
            }
            "SC" => Self::Syscall,
            _ => Self::Unknown,
        }
    }

    /// Whether this kind is a control-flow transfer.
    #[must_use]
    pub const fn is_control_flow(&self) -> bool {
        matches!(
            self,
            Self::CondBranch | Self::Branch | Self::Call | Self::Return
        )
    }

    /// Whether this kind accesses memory.
    #[must_use]
    pub const fn is_memory(&self) -> bool {
        matches!(self, Self::Load | Self::Store)
    }
}

// ── PowerPC SPR (Special-Purpose Register) Table ─────────────────────────────

/// A single PowerPC SPR entry.
#[derive(Debug, Clone)]
pub struct PpcSprEntry {
    /// SPR number (as used in MFSPR/MTSPR).
    pub number: u16,
    /// Register name.
    pub name: &'static str,
    /// Whether it is readable (MFSPR).
    pub readable: bool,
    /// Whether it is writable (MTSPR).
    pub writable: bool,
    /// Brief description.
    pub description: &'static str,
}

/// PowerPC SPR table.
pub static PPC_SPRS: &[PpcSprEntry] = &[
    PpcSprEntry {
        number: 1,
        name: "XER",
        readable: true,
        writable: true,
        description: "Fixed-Point Exception Register",
    },
    PpcSprEntry {
        number: 8,
        name: "LR",
        readable: true,
        writable: true,
        description: "Link Register",
    },
    PpcSprEntry {
        number: 9,
        name: "CTR",
        readable: true,
        writable: true,
        description: "Count Register",
    },
    PpcSprEntry {
        number: 18,
        name: "DSISR",
        readable: true,
        writable: true,
        description: "Data Storage Interrupt Status Register",
    },
    PpcSprEntry {
        number: 19,
        name: "DAR",
        readable: true,
        writable: true,
        description: "Data Address Register",
    },
    PpcSprEntry {
        number: 22,
        name: "DEC",
        readable: true,
        writable: true,
        description: "Decrementer",
    },
    PpcSprEntry {
        number: 25,
        name: "SDR1",
        readable: true,
        writable: true,
        description: "Storage Description Register 1",
    },
    PpcSprEntry {
        number: 26,
        name: "SRR0",
        readable: true,
        writable: true,
        description: "Save/Restore Register 0",
    },
    PpcSprEntry {
        number: 27,
        name: "SRR1",
        readable: true,
        writable: true,
        description: "Save/Restore Register 1",
    },
    PpcSprEntry {
        number: 256,
        name: "VRSAVE",
        readable: true,
        writable: true,
        description: "AltiVec Register Save",
    },
    PpcSprEntry {
        number: 268,
        name: "TBL",
        readable: true,
        writable: false,
        description: "Time Base Lower (read)",
    },
    PpcSprEntry {
        number: 269,
        name: "TBU",
        readable: true,
        writable: false,
        description: "Time Base Upper (read)",
    },
    PpcSprEntry {
        number: 284,
        name: "TBWL",
        readable: false,
        writable: true,
        description: "Time Base Lower (write)",
    },
    PpcSprEntry {
        number: 285,
        name: "TBWU",
        readable: false,
        writable: true,
        description: "Time Base Upper (write)",
    },
    PpcSprEntry {
        number: 528,
        name: "IBAT0U",
        readable: true,
        writable: true,
        description: "Instruction BAT 0 Upper",
    },
    PpcSprEntry {
        number: 529,
        name: "IBAT0L",
        readable: true,
        writable: true,
        description: "Instruction BAT 0 Lower",
    },
    PpcSprEntry {
        number: 530,
        name: "IBAT1U",
        readable: true,
        writable: true,
        description: "Instruction BAT 1 Upper",
    },
    PpcSprEntry {
        number: 531,
        name: "IBAT1L",
        readable: true,
        writable: true,
        description: "Instruction BAT 1 Lower",
    },
    PpcSprEntry {
        number: 536,
        name: "DBAT0U",
        readable: true,
        writable: true,
        description: "Data BAT 0 Upper",
    },
    PpcSprEntry {
        number: 537,
        name: "DBAT0L",
        readable: true,
        writable: true,
        description: "Data BAT 0 Lower",
    },
    PpcSprEntry {
        number: 1013,
        name: "HID1",
        readable: true,
        writable: true,
        description: "Hardware Implementation Register 1",
    },
];

/// Look up a PPC SPR by number.
#[must_use]
pub fn lookup_spr(number: u16) -> Option<&'static PpcSprEntry> {
    PPC_SPRS.iter().find(|s| s.number == number)
}

// ── PowerPC Code Statistics ───────────────────────────────────────────────────

/// Code statistics gathered from a linear sweep of PPC instructions.
#[derive(Debug, Clone, Default)]
pub struct PpcCodeStats {
    /// Total instructions.
    pub total: usize,
    /// Integer ALU instructions.
    pub int_alu: usize,
    /// Load immediates.
    pub load_imm: usize,
    /// Multiply instructions.
    pub multiplies: usize,
    /// Divide instructions.
    pub divides: usize,
    /// Logic instructions.
    pub logic: usize,
    /// Shift / rotate.
    pub shifts: usize,
    /// Compare instructions.
    pub compares: usize,
    /// Load instructions.
    pub loads: usize,
    /// Store instructions.
    pub stores: usize,
    /// FP instructions.
    pub float_ops: usize,
    /// Conditional branches.
    pub cond_branches: usize,
    /// Unconditional branches.
    pub branches: usize,
    /// Calls.
    pub calls: usize,
    /// Returns.
    pub returns: usize,
    /// SPR operations.
    pub spr_ops: usize,
    /// Barriers.
    pub barriers: usize,
    /// Syscalls.
    pub syscalls: usize,
    /// Decode errors.
    pub errors: usize,
}

impl PpcCodeStats {
    /// Collect statistics by linear sweep.
    #[must_use]
    pub fn from_bytes(arch: &PpcArch, bytes: &[u8], base: Address) -> Self {
        let mut s = Self::default();
        for result in PpcLinearDisassembler::new(arch, bytes, base) {
            match result {
                Err(_) => s.errors += 1,
                Ok(instr) => {
                    s.total += 1;
                    match PpcInstrKind::from_mnemonic(&instr.mnemonic) {
                        PpcInstrKind::Nop | PpcInstrKind::Unknown => {}
                        PpcInstrKind::LoadImm => s.load_imm += 1,
                        PpcInstrKind::IntAlu => s.int_alu += 1,
                        PpcInstrKind::Multiply => s.multiplies += 1,
                        PpcInstrKind::Divide => s.divides += 1,
                        PpcInstrKind::Logic => s.logic += 1,
                        PpcInstrKind::Shift => s.shifts += 1,
                        PpcInstrKind::Compare => s.compares += 1,
                        PpcInstrKind::Load => s.loads += 1,
                        PpcInstrKind::Store => s.stores += 1,
                        PpcInstrKind::FloatOp => s.float_ops += 1,
                        PpcInstrKind::CondBranch => s.cond_branches += 1,
                        PpcInstrKind::Branch => s.branches += 1,
                        PpcInstrKind::Call => s.calls += 1,
                        PpcInstrKind::Return => s.returns += 1,
                        PpcInstrKind::SprOp => s.spr_ops += 1,
                        PpcInstrKind::Barrier => s.barriers += 1,
                        PpcInstrKind::Syscall => s.syscalls += 1,
                    }
                }
            }
        }
        s
    }
}

// ── PowerPC Basic Block ───────────────────────────────────────────────────────

/// A basic block of PowerPC instructions.
#[derive(Debug, Clone)]
pub struct PpcBasicBlock {
    /// Start address.
    pub start: Address,
    /// Instructions (including any terminator).
    pub instructions: Vec<Instruction>,
}

impl PpcBasicBlock {
    /// Find basic blocks in `bytes`.
    ///
    /// # Errors
    ///
    /// Returns `CoreError` if any instruction fails to decode.
    pub fn find_blocks(
        arch: &PpcArch,
        bytes: &[u8],
        base: Address,
    ) -> Result<Vec<Self>, CoreError> {
        let mut blocks: Vec<Self> = Vec::new();
        let mut current: Vec<Instruction> = Vec::new();
        let mut block_start = base;
        let mut offset = 0usize;

        while offset + 4 <= bytes.len() {
            let addr = base + offset as u64;
            let instr = arch.disassemble(addr, &bytes[offset..])?;
            let is_terminator = instr.flags.intersects(InstrFlags::BRANCH | InstrFlags::RET);
            current.push(instr);
            offset += 4;

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

// ── PowerPC Encoding Helpers ──────────────────────────────────────────────────

/// Encode a PowerPC `B` (unconditional branch) instruction.
///
/// `disp` must be a multiple of 4 and within ±32 MB.
///
/// # Panics
///
/// Panics if `disp` is not a multiple of 4.
#[must_use]
pub fn encode_b(disp: i32, link: bool) -> u32 {
    assert!(disp % 4 == 0, "branch displacement must be 4-byte aligned");
    let li = disp.cast_unsigned() & 0x03FF_FFFC;
    let lk = u32::from(link);
    (18u32 << 26) | li | lk
}

/// Encode a PowerPC `BL` (branch and link) instruction.
///
/// # Panics
///
/// Panics if `disp` is not a multiple of 4.
#[must_use]
pub fn encode_bl(disp: i32) -> u32 {
    encode_b(disp, true)
}

/// Encode a `BCLR` (branch to LR) instruction.
#[must_use]
pub fn encode_bclr(link: bool) -> u32 {
    // opcd=19, bo=20(0b10100), bi=0, xo=16
    let lk = u32::from(link);
    (19u32 << 26) | (20u32 << 21) | (16u32 << 1) | lk
}

/// Encode a `LI rd, imm` instruction (pseudo for `ADDI rd,r0,imm`).
///
/// # Panics
///
/// Panics if `imm` is outside the signed 16-bit range.
#[must_use]
pub fn encode_li(rd: u32, imm: i32) -> u32 {
    assert!(
        (-32768..=32767).contains(&imm),
        "LI imm out of 16-bit range"
    );
    (14u32 << 26) | ((rd & 31) << 21) | (imm.cast_unsigned() & 0xFFFF)
}

/// Encode a `LIS rd, imm` instruction (pseudo for `ADDIS rd,r0,imm`).
///
/// # Panics
///
/// Panics if `imm` is outside the signed 16-bit range.
#[must_use]
pub fn encode_lis(rd: u32, imm: i32) -> u32 {
    assert!(
        (-32768..=32767).contains(&imm),
        "LIS imm out of 16-bit range"
    );
    (15u32 << 26) | ((rd & 31) << 21) | (imm.cast_unsigned() & 0xFFFF)
}

/// Encode `ADDI rd, ra, imm`.
///
/// # Panics
///
/// Panics if `imm` is outside the signed 16-bit range.
#[must_use]
pub fn encode_addi(rd: u32, ra: u32, imm: i32) -> u32 {
    assert!(
        (-32768..=32767).contains(&imm),
        "ADDI imm out of 16-bit range"
    );
    (14u32 << 26) | ((rd & 31) << 21) | ((ra & 31) << 16) | (imm.cast_unsigned() & 0xFFFF)
}

/// Encode `STW rs, imm(ra)`.
///
/// # Panics
///
/// Panics if `imm` is outside the signed 16-bit range.
#[must_use]
pub fn encode_stw(rs: u32, ra: u32, imm: i32) -> u32 {
    assert!(
        (-32768..=32767).contains(&imm),
        "STW imm out of 16-bit range"
    );
    (36u32 << 26) | ((rs & 31) << 21) | ((ra & 31) << 16) | (imm.cast_unsigned() & 0xFFFF)
}

/// Encode `LWZ rd, imm(ra)`.
///
/// # Panics
///
/// Panics if `imm` is outside the signed 16-bit range.
#[must_use]
pub fn encode_lwz(rd: u32, ra: u32, imm: i32) -> u32 {
    assert!(
        (-32768..=32767).contains(&imm),
        "LWZ imm out of 16-bit range"
    );
    (32u32 << 26) | ((rd & 31) << 21) | ((ra & 31) << 16) | (imm.cast_unsigned() & 0xFFFF)
}

/// Encode `STWU rs, imm(ra)` (store with update — used in function prologues).
///
/// # Panics
///
/// Panics if `imm` is outside the signed 16-bit range.
#[must_use]
pub fn encode_stwu(rs: u32, ra: u32, imm: i32) -> u32 {
    assert!(
        (-32768..=32767).contains(&imm),
        "STWU imm out of 16-bit range"
    );
    (37u32 << 26) | ((rs & 31) << 21) | ((ra & 31) << 16) | (imm.cast_unsigned() & 0xFFFF)
}

/// Encode `MFSPR rd, spr`.
#[must_use]
pub fn encode_mfspr(rd: u32, spr: u16) -> u32 {
    let spr_enc = ((u32::from(spr) & 0x1F) << 5) | (u32::from(spr) >> 5);
    (31u32 << 26) | ((rd & 31) << 21) | (spr_enc << 11) | (339u32 << 1)
}

/// Encode `MTSPR spr, rs`.
#[must_use]
pub fn encode_mtspr(spr: u16, rs: u32) -> u32 {
    let spr_enc = ((u32::from(spr) & 0x1F) << 5) | (u32::from(spr) >> 5);
    (31u32 << 26) | ((rs & 31) << 21) | (spr_enc << 11) | (467u32 << 1)
}

// ── PowerPC Prologue / Epilogue Patterns ─────────────────────────────────────

/// Identify the PowerPC standard function prologue.
///
/// The standard PPC ELF prologue is:
/// 1. `MFLR r0`
/// 2. `STW r0, 4(r1)` (save LR)
/// 3. `STWU r1, -N(r1)` (allocate frame)
///
/// Returns `Some(frame_size)` if the first three instructions match.
#[must_use]
pub fn detect_ppc_prologue(instrs: &[Instruction]) -> Option<i32> {
    if instrs.len() < 3 {
        return None;
    }
    // Check MFLR r0
    if instrs[0].mnemonic != "MFLR" {
        return None;
    }
    // Check STW r0,4(r1)
    if instrs[1].mnemonic != "STW" {
        return None;
    }
    // Check STWU r1,-N(r1)
    if instrs[2].mnemonic != "STWU" {
        return None;
    }
    // Extract frame size from operands of STWU: "r1,-N(r1)"
    let ops = &instrs[2].operands;
    let comma = ops.find(',')?;
    let after = &ops[comma + 1..];
    let paren = after.find('(')?;
    let imm_str = &after[..paren];
    let frame_size: i32 = imm_str.parse().ok()?;
    Some(-frame_size) // Return as positive size
}

/// PowerPC register roles for ELF calling convention.
#[derive(Debug, Clone)]
pub struct PpcRegRole {
    /// Register name.
    pub name: &'static str,
    /// Register number.
    pub number: u8,
    /// Whether it is caller-saved (volatile).
    pub caller_saved: bool,
    /// Parameter index (0-based) if used for parameter passing.
    pub param_index: Option<u8>,
}

/// PPC ELF ABI register roles (r3-r10 for args, r3-r4 for return).
pub static PPC_REG_ROLES: &[PpcRegRole] = &[
    PpcRegRole {
        name: "r0",
        number: 0,
        caller_saved: true,
        param_index: None,
    },
    PpcRegRole {
        name: "r1",
        number: 1,
        caller_saved: false,
        param_index: None,
    }, // SP
    PpcRegRole {
        name: "r2",
        number: 2,
        caller_saved: false,
        param_index: None,
    }, // TOC
    PpcRegRole {
        name: "r3",
        number: 3,
        caller_saved: true,
        param_index: Some(0),
    },
    PpcRegRole {
        name: "r4",
        number: 4,
        caller_saved: true,
        param_index: Some(1),
    },
    PpcRegRole {
        name: "r5",
        number: 5,
        caller_saved: true,
        param_index: Some(2),
    },
    PpcRegRole {
        name: "r6",
        number: 6,
        caller_saved: true,
        param_index: Some(3),
    },
    PpcRegRole {
        name: "r7",
        number: 7,
        caller_saved: true,
        param_index: Some(4),
    },
    PpcRegRole {
        name: "r8",
        number: 8,
        caller_saved: true,
        param_index: Some(5),
    },
    PpcRegRole {
        name: "r9",
        number: 9,
        caller_saved: true,
        param_index: Some(6),
    },
    PpcRegRole {
        name: "r10",
        number: 10,
        caller_saved: true,
        param_index: Some(7),
    },
    PpcRegRole {
        name: "r11",
        number: 11,
        caller_saved: true,
        param_index: None,
    },
    PpcRegRole {
        name: "r12",
        number: 12,
        caller_saved: true,
        param_index: None,
    },
    PpcRegRole {
        name: "r13",
        number: 13,
        caller_saved: false,
        param_index: None,
    }, // small data
    PpcRegRole {
        name: "r14",
        number: 14,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r15",
        number: 15,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r16",
        number: 16,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r17",
        number: 17,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r18",
        number: 18,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r19",
        number: 19,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r20",
        number: 20,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r21",
        number: 21,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r22",
        number: 22,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r23",
        number: 23,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r24",
        number: 24,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r25",
        number: 25,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r26",
        number: 26,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r27",
        number: 27,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r28",
        number: 28,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r29",
        number: 29,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r30",
        number: 30,
        caller_saved: false,
        param_index: None,
    },
    PpcRegRole {
        name: "r31",
        number: 31,
        caller_saved: false,
        param_index: None,
    },
];

/// Look up a register role by number.
#[must_use]
pub fn lookup_ppc_reg_role(number: u8) -> Option<&'static PpcRegRole> {
    PPC_REG_ROLES.iter().find(|r| r.number == number)
}

// ── PowerPC Instruction Printer ───────────────────────────────────────────────

/// Format a PPC instruction.
#[must_use]
pub fn ppc_format(instr: &Instruction) -> String {
    if instr.operands.is_empty() {
        instr.mnemonic.clone()
    } else {
        format!("{} {}", instr.mnemonic, instr.operands)
    }
}

/// Format with address prefix.
#[must_use]
pub fn ppc_format_with_addr(instr: &Instruction) -> String {
    format!("{:08x}  {}", instr.address.as_u64(), ppc_format(instr))
}

// ── PowerPC Annotated Disassembly ─────────────────────────────────────────────

/// An annotated PPC instruction.
#[derive(Debug, Clone)]
pub struct AnnotatedPpcInstr {
    /// The underlying instruction.
    pub instr: Instruction,
    /// Kind.
    pub kind: PpcInstrKind,
}

impl AnnotatedPpcInstr {
    /// Annotate a single instruction.
    #[must_use]
    pub fn from_instr(instr: Instruction) -> Self {
        let kind = PpcInstrKind::from_mnemonic(&instr.mnemonic);
        Self { instr, kind }
    }
}

/// Disassemble and annotate a byte slice.
///
/// # Errors
///
/// Returns `CoreError` if any instruction fails to decode.
pub fn disassemble_annotated(
    arch: &PpcArch,
    bytes: &[u8],
    base: Address,
) -> Result<Vec<AnnotatedPpcInstr>, CoreError> {
    let mut results = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        let addr = base + offset as u64;
        let instr = arch.disassemble(addr, &bytes[offset..])?;
        results.push(AnnotatedPpcInstr::from_instr(instr));
        offset += 4;
    }
    Ok(results)
}

// ── More Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;

    fn arch() -> PpcArch {
        PpcArch::default()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    // ── Kind classification ───────────────────────────────────────────────

    #[test]
    fn test_kind_add() {
        assert_eq!(PpcInstrKind::from_mnemonic("ADD"), PpcInstrKind::IntAlu);
    }

    #[test]
    fn test_kind_li() {
        assert_eq!(PpcInstrKind::from_mnemonic("LI"), PpcInstrKind::LoadImm);
    }

    #[test]
    fn test_kind_mullw() {
        assert_eq!(PpcInstrKind::from_mnemonic("MULLW"), PpcInstrKind::Multiply);
        assert!(!PpcInstrKind::Multiply.is_control_flow());
    }

    #[test]
    fn test_kind_divw() {
        assert_eq!(PpcInstrKind::from_mnemonic("DIVW"), PpcInstrKind::Divide);
    }

    #[test]
    fn test_kind_and_logic() {
        assert_eq!(PpcInstrKind::from_mnemonic("AND"), PpcInstrKind::Logic);
    }

    #[test]
    fn test_kind_slw_shift() {
        assert_eq!(PpcInstrKind::from_mnemonic("SLW"), PpcInstrKind::Shift);
    }

    #[test]
    fn test_kind_cmpwi_compare() {
        assert_eq!(PpcInstrKind::from_mnemonic("CMPWI"), PpcInstrKind::Compare);
    }

    #[test]
    fn test_kind_lwz_load() {
        assert_eq!(PpcInstrKind::from_mnemonic("LWZ"), PpcInstrKind::Load);
        assert!(PpcInstrKind::Load.is_memory());
    }

    #[test]
    fn test_kind_stw_store() {
        assert_eq!(PpcInstrKind::from_mnemonic("STW"), PpcInstrKind::Store);
        assert!(PpcInstrKind::Store.is_memory());
    }

    #[test]
    fn test_kind_bl_call() {
        assert_eq!(PpcInstrKind::from_mnemonic("BL"), PpcInstrKind::Call);
        assert!(PpcInstrKind::Call.is_control_flow());
    }

    #[test]
    fn test_kind_bclr_return() {
        assert_eq!(PpcInstrKind::from_mnemonic("BCLR"), PpcInstrKind::Return);
        assert!(PpcInstrKind::Return.is_control_flow());
    }

    #[test]
    fn test_kind_mflr_spr() {
        assert_eq!(PpcInstrKind::from_mnemonic("MFLR"), PpcInstrKind::SprOp);
    }

    #[test]
    fn test_kind_sync_barrier() {
        assert_eq!(PpcInstrKind::from_mnemonic("SYNC"), PpcInstrKind::Barrier);
    }

    #[test]
    fn test_kind_sc_syscall() {
        assert_eq!(PpcInstrKind::from_mnemonic("SC"), PpcInstrKind::Syscall);
    }

    // ── SPR table ─────────────────────────────────────────────────────────

    #[test]
    fn test_spr_lr() {
        let s = lookup_spr(8).unwrap();
        assert_eq!(s.name, "LR");
        assert!(s.readable && s.writable);
    }

    #[test]
    fn test_spr_ctr() {
        let s = lookup_spr(9).unwrap();
        assert_eq!(s.name, "CTR");
    }

    #[test]
    fn test_spr_tbl_readonly() {
        let s = lookup_spr(268).unwrap();
        assert_eq!(s.name, "TBL");
        assert!(s.readable);
        assert!(!s.writable);
    }

    #[test]
    fn test_spr_not_found() {
        assert!(lookup_spr(9999).is_none());
    }

    // ── Encoding helpers ──────────────────────────────────────────────────

    #[test]
    fn test_encode_li_roundtrip() {
        let enc = encode_li(3, 42).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "LI");
        assert!(instr.operands.contains("42"));
    }

    #[test]
    fn test_encode_lis_roundtrip() {
        let enc = encode_lis(3, 1).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "LIS");
    }

    #[test]
    fn test_encode_addi_roundtrip() {
        let enc = encode_addi(3, 3, 4).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "ADDI");
    }

    #[test]
    fn test_encode_stw_roundtrip() {
        let enc = encode_stw(3, 1, 0).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "STW");
        assert!(instr.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_encode_lwz_roundtrip() {
        let enc = encode_lwz(3, 1, 0).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "LWZ");
        assert!(instr.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_encode_b_roundtrip() {
        let enc = encode_b(8, false).to_be_bytes();
        let instr = arch().disassemble(addr(0x1000), &enc).unwrap();
        assert_eq!(instr.mnemonic, "B");
        assert_eq!(instr.flags & InstrFlags::BRANCH, InstrFlags::BRANCH);
    }

    #[test]
    fn test_encode_bl_roundtrip() {
        let enc = encode_bl(4).to_be_bytes();
        let instr = arch().disassemble(addr(0x1000), &enc).unwrap();
        assert_eq!(instr.mnemonic, "BL");
        assert!(instr.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_encode_bclr_roundtrip() {
        let enc = encode_bclr(false).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "BCLR");
        assert!(instr.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_encode_stwu_roundtrip() {
        let enc = encode_stwu(1, 1, -16).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "STWU");
        assert!(instr.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_encode_mfspr_lr() {
        let enc = encode_mfspr(0, 8).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "MFLR");
    }

    #[test]
    fn test_encode_mtspr_lr() {
        let enc = encode_mtspr(8, 0).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "MTLR");
    }

    // ── Code stats ────────────────────────────────────────────────────────

    #[test]
    fn test_stats_basic() {
        let code: Vec<u8> = [
            encode_li(3, 1).to_be_bytes().to_vec(),
            encode_bl(4).to_be_bytes().to_vec(),
            encode_bclr(false).to_be_bytes().to_vec(),
        ]
        .concat();
        let a = arch();
        let stats = PpcCodeStats::from_bytes(&a, &code, addr(0x1000));
        assert_eq!(stats.total, 3);
        assert_eq!(stats.load_imm, 1);
        assert_eq!(stats.calls, 1);
        assert_eq!(stats.returns, 1);
    }

    #[test]
    fn test_stats_loads_stores() {
        let code: Vec<u8> = [
            encode_lwz(3, 1, 0).to_be_bytes().to_vec(),
            encode_stw(3, 1, 0).to_be_bytes().to_vec(),
        ]
        .concat();
        let a = arch();
        let stats = PpcCodeStats::from_bytes(&a, &code, addr(0));
        assert_eq!(stats.loads, 1);
        assert_eq!(stats.stores, 1);
    }

    // ── Basic block finder ────────────────────────────────────────────────

    #[test]
    fn test_basic_block_b_splits() {
        // B +4 at 0x1000 → block terminates; ADDI at 0x1004 = new block
        let code: Vec<u8> = [
            encode_b(4, false).to_be_bytes().to_vec(),
            encode_addi(3, 3, 1).to_be_bytes().to_vec(),
        ]
        .concat();
        let a = arch();
        let blocks = PpcBasicBlock::find_blocks(&a, &code, addr(0x1000)).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].len(), 1); // B
        assert_eq!(blocks[1].len(), 1); // ADDI
    }

    // ── Annotated disassembly ─────────────────────────────────────────────

    #[test]
    fn test_annotated() {
        let code: Vec<u8> = [
            encode_li(3, 42).to_be_bytes().to_vec(),
            encode_bclr(false).to_be_bytes().to_vec(),
        ]
        .concat();
        let a = arch();
        let ann = disassemble_annotated(&a, &code, addr(0)).unwrap();
        assert_eq!(ann.len(), 2);
        assert_eq!(ann[0].kind, PpcInstrKind::LoadImm);
        assert_eq!(ann[1].kind, PpcInstrKind::Return);
    }

    // ── Register roles ────────────────────────────────────────────────────

    #[test]
    fn test_reg_role_r3() {
        let r = lookup_ppc_reg_role(3).unwrap();
        assert!(r.caller_saved);
        assert_eq!(r.param_index, Some(0));
    }

    #[test]
    fn test_reg_role_r1_sp() {
        let r = lookup_ppc_reg_role(1).unwrap();
        assert!(!r.caller_saved);
        assert_eq!(r.param_index, None);
    }

    #[test]
    fn test_reg_roles_count() {
        assert_eq!(PPC_REG_ROLES.len(), 32);
    }

    // ── Format helpers ────────────────────────────────────────────────────

    #[test]
    fn test_ppc_format() {
        let enc = encode_li(3, 1).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        let s = ppc_format(&instr);
        assert!(s.contains("LI"));
    }

    #[test]
    fn test_ppc_format_with_addr() {
        let enc = encode_li(3, 1).to_be_bytes();
        let instr = arch().disassemble(addr(0x4000), &enc).unwrap();
        let s = ppc_format_with_addr(&instr);
        assert!(s.contains("00004000") || s.contains("4000"));
    }

    // ── ppc64 specific ────────────────────────────────────────────────────

    #[test]
    fn test_ppc64_registers() {
        let a = PpcArch::new_64();
        let regs = a.registers();
        assert!(regs.len() >= 75);
    }

    #[test]
    fn test_ppcle_name() {
        let a = PpcArch::new_le();
        assert_eq!(a.name(), "ppcle");
    }

    #[test]
    fn test_ppc_spr_count() {
        assert!(PPC_SPRS.len() >= 20);
    }
}

// ── PowerPC Condition Register ────────────────────────────────────────────────

/// A PowerPC condition register field (CR0–CR7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PpcCrField {
    /// CR field number (0–7).
    pub field: u8,
}

impl PpcCrField {
    /// Create a new CR field.
    ///
    /// # Panics
    ///
    /// Panics if `field` > 7.
    #[must_use]
    pub fn new(field: u8) -> Self {
        assert!(field <= 7, "CR field must be 0–7");
        Self { field }
    }

    /// The LT bit number in the full CR word.
    #[must_use]
    pub const fn lt_bit(self) -> u8 {
        self.field * 4
    }

    /// The GT bit number in the full CR word.
    #[must_use]
    pub const fn gt_bit(self) -> u8 {
        self.field * 4 + 1
    }

    /// The EQ bit number in the full CR word.
    #[must_use]
    pub const fn eq_bit(self) -> u8 {
        self.field * 4 + 2
    }

    /// The SO bit number in the full CR word.
    #[must_use]
    pub const fn so_bit(self) -> u8 {
        self.field * 4 + 3
    }

    /// Format the field name (e.g. "cr0", "cr3").
    #[must_use]
    pub fn name(self) -> String {
        format!("cr{}", self.field)
    }
}

// ── PowerPC Branch Condition Codes ───────────────────────────────────────────

/// A PowerPC branch condition (BO and BI fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PpcBranchCond {
    /// BO field (5 bits).
    pub bo: u8,
    /// BI field (5 bits) — which CR bit to test.
    pub bi: u8,
}

impl PpcBranchCond {
    /// Branch always (BO=20, BI=0).
    pub const ALWAYS: Self = Self { bo: 20, bi: 0 };
    /// Branch if CR0.EQ is set.
    pub const IF_EQ: Self = Self { bo: 12, bi: 2 };
    /// Branch if CR0.EQ is clear (not equal).
    pub const IF_NE: Self = Self { bo: 4, bi: 2 };
    /// Branch if CR0.LT is set (less than).
    pub const IF_LT: Self = Self { bo: 12, bi: 0 };
    /// Branch if CR0.GT is set (greater than).
    pub const IF_GT: Self = Self { bo: 12, bi: 1 };
    /// Branch if CR0.SO is set (summary overflow).
    pub const IF_SO: Self = Self { bo: 12, bi: 3 };

    /// Encode a conditional `BC` instruction.
    #[must_use]
    pub fn encode_bc(self, bd: i16) -> u32 {
        let bd_u = u32::from(bd.cast_unsigned()) & 0xFFFC;
        (16u32 << 26) | (u32::from(self.bo) << 21) | (u32::from(self.bi) << 16) | bd_u
    }

    /// Whether this represents an unconditional branch.
    #[must_use]
    pub const fn is_unconditional(self) -> bool {
        self.bo == 20
    }
}

// ── PowerPC Floating-Point Instruction Encoding ───────────────────────────────

/// Encode `FMR frd, frb` (floating-point move).
#[must_use]
pub const fn encode_fmr(frd: u32, frb: u32) -> u32 {
    (63u32 << 26) | ((frd & 31) << 21) | ((frb & 31) << 11) | (72u32 << 1)
}

/// Encode `FADD frd, fra, frb` (double-precision add).
#[must_use]
pub const fn encode_fadd(frd: u32, fra: u32, frb: u32) -> u32 {
    (63u32 << 26) | ((frd & 31) << 21) | ((fra & 31) << 16) | ((frb & 31) << 11) | (21u32 << 1)
}

/// Encode `FSUB frd, fra, frb` (double-precision subtract).
#[must_use]
pub const fn encode_fsub(frd: u32, fra: u32, frb: u32) -> u32 {
    (63u32 << 26) | ((frd & 31) << 21) | ((fra & 31) << 16) | ((frb & 31) << 11) | (20u32 << 1)
}

/// Encode `FMUL frd, fra, frc` (double-precision multiply).
#[must_use]
pub const fn encode_fmul(frd: u32, fra: u32, frc: u32) -> u32 {
    (63u32 << 26) | ((frd & 31) << 21) | ((fra & 31) << 16) | ((frc & 31) << 6) | (25u32 << 1)
}

/// Encode `FDIV frd, fra, frb` (double-precision divide).
#[must_use]
pub const fn encode_fdiv(frd: u32, fra: u32, frb: u32) -> u32 {
    (63u32 << 26) | ((frd & 31) << 21) | ((fra & 31) << 16) | ((frb & 31) << 11) | (18u32 << 1)
}

/// Encode `FCMPU crf, fra, frb` (floating-point compare unordered).
#[must_use]
pub const fn encode_fcmpu(crf: u32, fra: u32, frb: u32) -> u32 {
    (63u32 << 26) | ((crf & 7) << 23) | ((fra & 31) << 16) | ((frb & 31) << 11)
}

/// Encode `LFS frd, imm(ra)` (load floating single).
///
/// # Panics
///
/// Panics if `imm` is outside signed 16-bit range.
#[must_use]
pub fn encode_lfs(frd: u32, ra: u32, imm: i16) -> u32 {
    (48u32 << 26) | ((frd & 31) << 21) | ((ra & 31) << 16) | u32::from(imm.cast_unsigned())
}

/// Encode `STFS frs, imm(ra)` (store floating single).
///
/// # Panics
///
/// Panics if `imm` is outside signed 16-bit range.
#[must_use]
pub fn encode_stfs(frs: u32, ra: u32, imm: i16) -> u32 {
    (52u32 << 26) | ((frs & 31) << 21) | ((ra & 31) << 16) | u32::from(imm.cast_unsigned())
}

/// Encode `FCTIWZ frd, frb` (convert to integer word truncating).
#[must_use]
pub const fn encode_fctiwz(frd: u32, frb: u32) -> u32 {
    (63u32 << 26) | ((frd & 31) << 21) | ((frb & 31) << 11) | (15u32 << 1)
}

/// Encode `FRSP frd, frb` (round to single precision).
#[must_use]
pub const fn encode_frsp(frd: u32, frb: u32) -> u32 {
    (63u32 << 26) | ((frd & 31) << 21) | ((frb & 31) << 11) | (12u32 << 1)
}

// ── PowerPC Integer Encoding Helpers (additional) ────────────────────────────

/// Encode `SUBF rd, ra, rb` (subtract from, rd = rb - ra).
#[must_use]
pub const fn encode_subf(rd: u32, ra: u32, rb: u32) -> u32 {
    (31u32 << 26) | ((rd & 31) << 21) | ((ra & 31) << 16) | ((rb & 31) << 11) | (40u32 << 1)
}

/// Encode `ADD rd, ra, rb`.
#[must_use]
pub const fn encode_add(rd: u32, ra: u32, rb: u32) -> u32 {
    (31u32 << 26) | ((rd & 31) << 21) | ((ra & 31) << 16) | ((rb & 31) << 11) | (266u32 << 1)
}

/// Encode `AND ra, rs, rb` (logical and, stores to ra).
#[must_use]
pub const fn encode_and(ra: u32, rs: u32, rb: u32) -> u32 {
    (31u32 << 26) | ((rs & 31) << 21) | ((ra & 31) << 16) | ((rb & 31) << 11) | (28u32 << 1)
}

/// Encode `OR ra, rs, rb`.
#[must_use]
pub const fn encode_or(ra: u32, rs: u32, rb: u32) -> u32 {
    (31u32 << 26) | ((rs & 31) << 21) | ((ra & 31) << 16) | ((rb & 31) << 11) | (444u32 << 1)
}

/// Encode `XOR ra, rs, rb`.
#[must_use]
pub const fn encode_xor(ra: u32, rs: u32, rb: u32) -> u32 {
    (31u32 << 26) | ((rs & 31) << 21) | ((ra & 31) << 16) | ((rb & 31) << 11) | (316u32 << 1)
}

/// Encode `NOR ra, rs, rb`.
#[must_use]
pub const fn encode_nor(ra: u32, rs: u32, rb: u32) -> u32 {
    (31u32 << 26) | ((rs & 31) << 21) | ((ra & 31) << 16) | ((rb & 31) << 11) | (124u32 << 1)
}

/// Encode `NEG rd, ra`.
#[must_use]
pub const fn encode_neg(rd: u32, ra: u32) -> u32 {
    (31u32 << 26) | ((rd & 31) << 21) | ((ra & 31) << 16) | (104u32 << 1)
}

/// Encode `CMPWI crf, ra, imm` (compare word immediate signed).
///
/// # Panics
///
/// Panics if `imm` is outside signed 16-bit range.
#[must_use]
pub fn encode_cmpwi(crf: u32, ra: u32, imm: i16) -> u32 {
    (11u32 << 26) | ((crf & 7) << 23) | ((ra & 31) << 16) | u32::from(imm.cast_unsigned())
}

/// Encode `CMPLWI crf, ra, imm` (compare word immediate logical/unsigned).
///
/// # Panics
///
/// Panics if `imm` is outside unsigned 16-bit range.
#[must_use]
pub fn encode_cmplwi(crf: u32, ra: u32, imm: u16) -> u32 {
    (10u32 << 26) | ((crf & 7) << 23) | ((ra & 31) << 16) | u32::from(imm)
}

/// Encode `RLWINM ra, rs, sh, mb, me` (rotate left word immediate, then AND with mask).
///
/// # Panics
///
/// Panics if any field is out of range.
#[must_use]
pub fn encode_rlwinm(ra: u32, rs: u32, sh: u32, mb: u32, me: u32) -> u32 {
    assert!(
        sh <= 31 && mb <= 31 && me <= 31,
        "RLWINM fields out of range"
    );
    (21u32 << 26)
        | ((rs & 31) << 21)
        | ((ra & 31) << 16)
        | ((sh & 31) << 11)
        | ((mb & 31) << 6)
        | ((me & 31) << 1)
}

/// Encode `SRAWI ra, rs, sh` (shift right algebraic word immediate).
///
/// # Panics
///
/// Panics if `sh` > 31.
#[must_use]
pub fn encode_srawi(ra: u32, rs: u32, sh: u32) -> u32 {
    assert!(sh <= 31, "SRAWI shift out of range");
    (31u32 << 26) | ((rs & 31) << 21) | ((ra & 31) << 16) | ((sh & 31) << 11) | (824u32 << 1)
}

/// Encode `MULLW rd, ra, rb` (multiply low word).
#[must_use]
pub const fn encode_mullw(rd: u32, ra: u32, rb: u32) -> u32 {
    (31u32 << 26) | ((rd & 31) << 21) | ((ra & 31) << 16) | ((rb & 31) << 11) | (235u32 << 1)
}

/// Encode `DIVW rd, ra, rb` (divide word signed).
#[must_use]
pub const fn encode_divw(rd: u32, ra: u32, rb: u32) -> u32 {
    (31u32 << 26) | ((rd & 31) << 21) | ((ra & 31) << 16) | ((rb & 31) << 11) | (491u32 << 1)
}

/// Encode `DIVWU rd, ra, rb` (divide word unsigned).
#[must_use]
pub const fn encode_divwu(rd: u32, ra: u32, rb: u32) -> u32 {
    (31u32 << 26) | ((rd & 31) << 21) | ((ra & 31) << 16) | ((rb & 31) << 11) | (459u32 << 1)
}

/// Encode `EXTSB ra, rs` (extend sign byte).
#[must_use]
pub const fn encode_extsb(ra: u32, rs: u32) -> u32 {
    (31u32 << 26) | ((rs & 31) << 21) | ((ra & 31) << 16) | (954u32 << 1)
}

/// Encode `EXTSH ra, rs` (extend sign halfword).
#[must_use]
pub const fn encode_extsh(ra: u32, rs: u32) -> u32 {
    (31u32 << 26) | ((rs & 31) << 21) | ((ra & 31) << 16) | (922u32 << 1)
}

// ── PowerPC Load/Store Byte & Halfword ────────────────────────────────────────

/// Encode `LBZ rd, imm(ra)` (load byte and zero-extend).
///
/// # Panics
///
/// Panics if `imm` is outside signed 16-bit range.
#[must_use]
pub fn encode_lbz(rd: u32, ra: u32, imm: i16) -> u32 {
    (34u32 << 26) | ((rd & 31) << 21) | ((ra & 31) << 16) | u32::from(imm.cast_unsigned())
}

/// Encode `LHZ rd, imm(ra)` (load halfword and zero-extend).
///
/// # Panics
///
/// Panics if `imm` is outside signed 16-bit range.
#[must_use]
pub fn encode_lhz(rd: u32, ra: u32, imm: i16) -> u32 {
    (40u32 << 26) | ((rd & 31) << 21) | ((ra & 31) << 16) | u32::from(imm.cast_unsigned())
}

/// Encode `LHA rd, imm(ra)` (load halfword algebraic / sign-extend).
///
/// # Panics
///
/// Panics if `imm` is outside signed 16-bit range.
#[must_use]
pub fn encode_lha(rd: u32, ra: u32, imm: i16) -> u32 {
    (42u32 << 26) | ((rd & 31) << 21) | ((ra & 31) << 16) | u32::from(imm.cast_unsigned())
}

/// Encode `STB rs, imm(ra)` (store byte).
///
/// # Panics
///
/// Panics if `imm` is outside signed 16-bit range.
#[must_use]
pub fn encode_stb(rs: u32, ra: u32, imm: i16) -> u32 {
    (38u32 << 26) | ((rs & 31) << 21) | ((ra & 31) << 16) | u32::from(imm.cast_unsigned())
}

/// Encode `STH rs, imm(ra)` (store halfword).
///
/// # Panics
///
/// Panics if `imm` is outside signed 16-bit range.
#[must_use]
pub fn encode_sth(rs: u32, ra: u32, imm: i16) -> u32 {
    (44u32 << 26) | ((rs & 31) << 21) | ((ra & 31) << 16) | u32::from(imm.cast_unsigned())
}

// ── PowerPC Trap Instructions ─────────────────────────────────────────────────

/// Encode `TW TO, ra, rb` (trap word if condition).
#[must_use]
pub const fn encode_tw(to: u32, ra: u32, rb: u32) -> u32 {
    (31u32 << 26) | ((to & 31) << 21) | ((ra & 31) << 16) | ((rb & 31) << 11) | (4u32 << 1)
}

/// Encode `TWI TO, ra, imm` (trap word immediate).
///
/// # Panics
///
/// Panics if `imm` is outside signed 16-bit range.
#[must_use]
pub fn encode_twi(to: u32, ra: u32, imm: i16) -> u32 {
    (3u32 << 26) | ((to & 31) << 21) | ((ra & 31) << 16) | u32::from(imm.cast_unsigned())
}

// ── PowerPC Idiom Identification ─────────────────────────────────────────────

/// Recognized PowerPC idioms and common instruction patterns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PpcIdiom {
    /// `NOP` — no-operation (ORI r0,r0,0).
    Nop,
    /// `MR ra, rs` — move register (OR ra,rs,rs).
    MoveReg { dest: String, src: String },
    /// `NOT ra, rs` — bitwise not (NOR ra,rs,rs).
    BitwiseNot { dest: String, src: String },
    /// `LI rd, imm` — load immediate (ADDI rd,r0,imm).
    LoadImm { dest: String, imm: i32 },
    /// `LIS rd, imm` — load immediate shifted (ADDIS rd,r0,imm).
    LoadImmShifted { dest: String, imm: i32 },
    /// `CLRLWI ra, rs, n` — clear left n bits (RLWINM ra,rs,0,n,31).
    ClearLeft { dest: String, src: String, n: u32 },
    /// `SLWI ra, rs, n` — shift left word immediate (RLWINM ra,rs,n,0,31-n).
    ShiftLeftImm { dest: String, src: String, n: u32 },
    /// `SRWI ra, rs, n` — shift right word immediate (RLWINM ra,rs,32-n,n,31).
    ShiftRightImm { dest: String, src: String, n: u32 },
    /// `EXTLWI ra, rs, n, b` — extract left word (RLWINM ra,rs,b,0,n-1).
    ExtractLeft {
        dest: String,
        src: String,
        n: u32,
        b: u32,
    },
    /// General — not a recognized idiom.
    General,
}

/// Identify whether a single instruction is a known PPC idiom.
#[must_use]
pub fn identify_ppc_idiom(instr: &Instruction) -> PpcIdiom {
    match instr.mnemonic.as_str() {
        "ORI" if instr.operands == "r0,r0,0" => PpcIdiom::Nop,
        "OR" => {
            // MR ra, rs: OR ra,rs,rs (operands = "ra,rs,rs")
            let parts: Vec<&str> = instr.operands.splitn(3, ',').collect();
            if parts.len() == 3 && parts[1] == parts[2] {
                PpcIdiom::MoveReg {
                    dest: parts[0].to_string(),
                    src: parts[1].to_string(),
                }
            } else {
                PpcIdiom::General
            }
        }
        "NOR" => {
            let parts: Vec<&str> = instr.operands.splitn(3, ',').collect();
            if parts.len() == 3 && parts[1] == parts[2] {
                PpcIdiom::BitwiseNot {
                    dest: parts[0].to_string(),
                    src: parts[1].to_string(),
                }
            } else {
                PpcIdiom::General
            }
        }
        "LI" => {
            // LI rd, imm (ra==0 special case, 2 operands)
            let parts: Vec<&str> = instr.operands.splitn(2, ',').collect();
            if parts.len() == 2 {
                let imm: i32 = parts[1].trim().parse().unwrap_or(0);
                PpcIdiom::LoadImm {
                    dest: parts[0].trim().to_string(),
                    imm,
                }
            } else {
                PpcIdiom::General
            }
        }
        "LIS" => {
            let parts: Vec<&str> = instr.operands.splitn(2, ',').collect();
            if parts.len() == 2 {
                let imm: i32 = parts[1].trim().parse().unwrap_or(0);
                PpcIdiom::LoadImmShifted {
                    dest: parts[0].trim().to_string(),
                    imm,
                }
            } else {
                PpcIdiom::General
            }
        }
        "ADDI" => {
            let parts: Vec<&str> = instr.operands.splitn(3, ',').collect();
            if parts.len() == 3 && parts[1].trim() == "r0" {
                let imm: i32 = parts[2].parse().unwrap_or(0);
                PpcIdiom::LoadImm {
                    dest: parts[0].trim().to_string(),
                    imm,
                }
            } else {
                PpcIdiom::General
            }
        }
        "ADDIS" => {
            let parts: Vec<&str> = instr.operands.splitn(3, ',').collect();
            if parts.len() == 3 && parts[1].trim() == "r0" {
                let imm: i32 = parts[2].parse().unwrap_or(0);
                PpcIdiom::LoadImmShifted {
                    dest: parts[0].trim().to_string(),
                    imm,
                }
            } else {
                PpcIdiom::General
            }
        }
        _ => PpcIdiom::General,
    }
}

// ── PowerPC Exception / Interrupt Table ──────────────────────────────────────

/// A single PowerPC exception vector entry.
#[derive(Debug, Clone)]
pub struct PpcExceptionEntry {
    /// Vector offset from 0x0000 (or 0xFFF00000 in interrupt mode).
    pub offset: u32,
    /// Exception name.
    pub name: &'static str,
    /// Brief description.
    pub description: &'static str,
}

/// PowerPC 603/604/G4 exception vector table.
pub static PPC_EXCEPTIONS: &[PpcExceptionEntry] = &[
    PpcExceptionEntry {
        offset: 0x0100,
        name: "System Reset",
        description: "Power-on, external reset, or HRESET",
    },
    PpcExceptionEntry {
        offset: 0x0200,
        name: "Machine Check",
        description: "Memory bus error, parity error",
    },
    PpcExceptionEntry {
        offset: 0x0300,
        name: "DSI",
        description: "Data storage interrupt (data TLB miss / page fault)",
    },
    PpcExceptionEntry {
        offset: 0x0400,
        name: "ISI",
        description: "Instruction storage interrupt (instr TLB miss / page fault)",
    },
    PpcExceptionEntry {
        offset: 0x0500,
        name: "External Interrupt",
        description: "External I/O device interrupt",
    },
    PpcExceptionEntry {
        offset: 0x0600,
        name: "Alignment",
        description: "Misaligned memory access",
    },
    PpcExceptionEntry {
        offset: 0x0700,
        name: "Program",
        description: "Illegal instruction, privilege, FP, trap",
    },
    PpcExceptionEntry {
        offset: 0x0800,
        name: "FP Unavailable",
        description: "FPU disabled (MSR.FP=0)",
    },
    PpcExceptionEntry {
        offset: 0x0900,
        name: "Decrementer",
        description: "Decrementer underflow",
    },
    PpcExceptionEntry {
        offset: 0x0c00,
        name: "System Call",
        description: "SC instruction executed",
    },
    PpcExceptionEntry {
        offset: 0x0d00,
        name: "Trace",
        description: "Single-step or branch trace",
    },
    PpcExceptionEntry {
        offset: 0x0e00,
        name: "FP Assist",
        description: "Floating-point assist needed (G4)",
    },
    PpcExceptionEntry {
        offset: 0x1000,
        name: "Instruction TLB Miss",
        description: "Software-managed TLB: instruction miss (603)",
    },
    PpcExceptionEntry {
        offset: 0x1100,
        name: "Data Load TLB Miss",
        description: "Software-managed TLB: data load miss (603)",
    },
    PpcExceptionEntry {
        offset: 0x1200,
        name: "Data Store TLB Miss",
        description: "Software-managed TLB: data store miss (603)",
    },
    PpcExceptionEntry {
        offset: 0x1300,
        name: "Instruction Breakpoint",
        description: "IABR breakpoint hit",
    },
    PpcExceptionEntry {
        offset: 0x1400,
        name: "System Management",
        description: "SMI pin asserted",
    },
    PpcExceptionEntry {
        offset: 0x1700,
        name: "Thermal Management",
        description: "Thermal interrupt (G4/G5)",
    },
    PpcExceptionEntry {
        offset: 0x2000,
        name: "Run Mode / Trace",
        description: "Trace exception (G4 alternate)",
    },
];

/// Look up a PPC exception by vector offset.
#[must_use]
pub fn lookup_ppc_exception(offset: u32) -> Option<&'static PpcExceptionEntry> {
    PPC_EXCEPTIONS.iter().find(|e| e.offset == offset)
}

// ── PowerPC MSR Bit Definitions ───────────────────────────────────────────────

/// A bit in the PowerPC Machine State Register (MSR).
#[derive(Debug, Clone, Copy)]
pub struct PpcMsrBit {
    /// Bit number (0 = most significant in PPC bit numbering, bit 31 = least).
    pub bit: u8,
    /// Short name.
    pub name: &'static str,
    /// Description.
    pub description: &'static str,
}

/// PowerPC MSR bit definitions.
pub static PPC_MSR_BITS: &[PpcMsrBit] = &[
    PpcMsrBit {
        bit: 0,
        name: "SF",
        description: "64-bit mode (PPC64 only)",
    },
    PpcMsrBit {
        bit: 1,
        name: "ISF",
        description: "Interrupt 64-bit mode",
    },
    PpcMsrBit {
        bit: 2,
        name: "HV",
        description: "Hypervisor mode (PPC64 POWER)",
    },
    PpcMsrBit {
        bit: 13,
        name: "VEC",
        description: "AltiVec available",
    },
    PpcMsrBit {
        bit: 14,
        name: "VSX",
        description: "Vector Scalar Extensions available",
    },
    PpcMsrBit {
        bit: 15,
        name: "EE",
        description: "External interrupt enable",
    },
    PpcMsrBit {
        bit: 16,
        name: "PR",
        description: "Problem (user) state",
    },
    PpcMsrBit {
        bit: 17,
        name: "FP",
        description: "Floating-point available",
    },
    PpcMsrBit {
        bit: 18,
        name: "ME",
        description: "Machine check enable",
    },
    PpcMsrBit {
        bit: 19,
        name: "FE0",
        description: "Floating-point exception mode 0",
    },
    PpcMsrBit {
        bit: 20,
        name: "SE",
        description: "Single-step trace enable",
    },
    PpcMsrBit {
        bit: 21,
        name: "BE",
        description: "Branch trace enable",
    },
    PpcMsrBit {
        bit: 22,
        name: "FE1",
        description: "Floating-point exception mode 1",
    },
    PpcMsrBit {
        bit: 23,
        name: "IP",
        description: "Exception prefix (vectors at 0xFFF00000)",
    },
    PpcMsrBit {
        bit: 24,
        name: "IR",
        description: "Instruction address translation",
    },
    PpcMsrBit {
        bit: 25,
        name: "DR",
        description: "Data address translation",
    },
    PpcMsrBit {
        bit: 26,
        name: "PE",
        description: "Protection enable (603)",
    },
    PpcMsrBit {
        bit: 28,
        name: "PM",
        description: "Performance monitor",
    },
    PpcMsrBit {
        bit: 29,
        name: "RI",
        description: "Recoverable exception",
    },
    PpcMsrBit {
        bit: 30,
        name: "LE",
        description: "Little-endian mode",
    },
];

/// Look up a PPC MSR bit by name.
#[must_use]
pub fn lookup_msr_bit(name: &str) -> Option<&'static PpcMsrBit> {
    PPC_MSR_BITS.iter().find(|b| b.name == name)
}

// ── PowerPC AltiVec / VMX Instructions ───────────────────────────────────────

/// An `AltiVec` vector unit instruction descriptor.
#[derive(Debug, Clone)]
pub struct AltivecInstr {
    /// Instruction mnemonic.
    pub mnemonic: &'static str,
    /// Operation category.
    pub category: AltivecCategory,
    /// Element size operated on.
    pub element: AltivecElement,
}

/// `AltiVec` instruction category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AltivecCategory {
    /// Integer arithmetic.
    IntArith,
    /// Integer logical.
    IntLogic,
    /// Integer compare.
    IntCompare,
    /// Integer shift/rotate.
    IntShift,
    /// Floating-point.
    Float,
    /// Load.
    Load,
    /// Store.
    Store,
    /// Permute/pack/unpack.
    Permute,
    /// Conversion.
    Convert,
    /// Predicate/select.
    Predicate,
}

/// `AltiVec` element width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AltivecElement {
    /// 8-bit byte.
    Byte,
    /// 16-bit halfword.
    Half,
    /// 32-bit word.
    Word,
    /// 32-bit single float.
    Float,
    /// 128-bit quadword.
    Quad,
    /// None (whole-vector).
    None,
}

/// A subset of the `AltiVec` instruction set.
pub static ALTIVEC_INSTRS: &[AltivecInstr] = &[
    AltivecInstr {
        mnemonic: "VADDUBM",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Byte,
    },
    AltivecInstr {
        mnemonic: "VADDUHM",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Half,
    },
    AltivecInstr {
        mnemonic: "VADDUWM",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Word,
    },
    AltivecInstr {
        mnemonic: "VADDUBS",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Byte,
    },
    AltivecInstr {
        mnemonic: "VADDUHS",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Half,
    },
    AltivecInstr {
        mnemonic: "VADDUWS",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Word,
    },
    AltivecInstr {
        mnemonic: "VADDSBS",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Byte,
    },
    AltivecInstr {
        mnemonic: "VADDSHS",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Half,
    },
    AltivecInstr {
        mnemonic: "VADDSWS",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Word,
    },
    AltivecInstr {
        mnemonic: "VSUBUBM",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Byte,
    },
    AltivecInstr {
        mnemonic: "VSUBUHM",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Half,
    },
    AltivecInstr {
        mnemonic: "VSUBUWM",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Word,
    },
    AltivecInstr {
        mnemonic: "VMULUWM",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Word,
    },
    AltivecInstr {
        mnemonic: "VMULOUB",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Byte,
    },
    AltivecInstr {
        mnemonic: "VMULOUH",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Half,
    },
    AltivecInstr {
        mnemonic: "VMULOSB",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Byte,
    },
    AltivecInstr {
        mnemonic: "VMULOSH",
        category: AltivecCategory::IntArith,
        element: AltivecElement::Half,
    },
    AltivecInstr {
        mnemonic: "VAND",
        category: AltivecCategory::IntLogic,
        element: AltivecElement::Quad,
    },
    AltivecInstr {
        mnemonic: "VANDC",
        category: AltivecCategory::IntLogic,
        element: AltivecElement::Quad,
    },
    AltivecInstr {
        mnemonic: "VOR",
        category: AltivecCategory::IntLogic,
        element: AltivecElement::Quad,
    },
    AltivecInstr {
        mnemonic: "VNOR",
        category: AltivecCategory::IntLogic,
        element: AltivecElement::Quad,
    },
    AltivecInstr {
        mnemonic: "VXOR",
        category: AltivecCategory::IntLogic,
        element: AltivecElement::Quad,
    },
    AltivecInstr {
        mnemonic: "VCMPEQUB",
        category: AltivecCategory::IntCompare,
        element: AltivecElement::Byte,
    },
    AltivecInstr {
        mnemonic: "VCMPEQUH",
        category: AltivecCategory::IntCompare,
        element: AltivecElement::Half,
    },
    AltivecInstr {
        mnemonic: "VCMPEQUW",
        category: AltivecCategory::IntCompare,
        element: AltivecElement::Word,
    },
    AltivecInstr {
        mnemonic: "VCMPGTSB",
        category: AltivecCategory::IntCompare,
        element: AltivecElement::Byte,
    },
    AltivecInstr {
        mnemonic: "VCMPGTSH",
        category: AltivecCategory::IntCompare,
        element: AltivecElement::Half,
    },
    AltivecInstr {
        mnemonic: "VCMPGTSW",
        category: AltivecCategory::IntCompare,
        element: AltivecElement::Word,
    },
    AltivecInstr {
        mnemonic: "VCMPGTUB",
        category: AltivecCategory::IntCompare,
        element: AltivecElement::Byte,
    },
    AltivecInstr {
        mnemonic: "VCMPGTUH",
        category: AltivecCategory::IntCompare,
        element: AltivecElement::Half,
    },
    AltivecInstr {
        mnemonic: "VCMPGTUW",
        category: AltivecCategory::IntCompare,
        element: AltivecElement::Word,
    },
    AltivecInstr {
        mnemonic: "VSLB",
        category: AltivecCategory::IntShift,
        element: AltivecElement::Byte,
    },
    AltivecInstr {
        mnemonic: "VSLH",
        category: AltivecCategory::IntShift,
        element: AltivecElement::Half,
    },
    AltivecInstr {
        mnemonic: "VSLW",
        category: AltivecCategory::IntShift,
        element: AltivecElement::Word,
    },
    AltivecInstr {
        mnemonic: "VSRB",
        category: AltivecCategory::IntShift,
        element: AltivecElement::Byte,
    },
    AltivecInstr {
        mnemonic: "VSRH",
        category: AltivecCategory::IntShift,
        element: AltivecElement::Half,
    },
    AltivecInstr {
        mnemonic: "VSRW",
        category: AltivecCategory::IntShift,
        element: AltivecElement::Word,
    },
    AltivecInstr {
        mnemonic: "VSRAB",
        category: AltivecCategory::IntShift,
        element: AltivecElement::Byte,
    },
    AltivecInstr {
        mnemonic: "VSRAH",
        category: AltivecCategory::IntShift,
        element: AltivecElement::Half,
    },
    AltivecInstr {
        mnemonic: "VSRAW",
        category: AltivecCategory::IntShift,
        element: AltivecElement::Word,
    },
    AltivecInstr {
        mnemonic: "VADDFP",
        category: AltivecCategory::Float,
        element: AltivecElement::Float,
    },
    AltivecInstr {
        mnemonic: "VSUBFP",
        category: AltivecCategory::Float,
        element: AltivecElement::Float,
    },
    AltivecInstr {
        mnemonic: "VMADDFP",
        category: AltivecCategory::Float,
        element: AltivecElement::Float,
    },
    AltivecInstr {
        mnemonic: "VNMSUBFP",
        category: AltivecCategory::Float,
        element: AltivecElement::Float,
    },
    AltivecInstr {
        mnemonic: "VCTSXS",
        category: AltivecCategory::Convert,
        element: AltivecElement::Float,
    },
    AltivecInstr {
        mnemonic: "VCTUXS",
        category: AltivecCategory::Convert,
        element: AltivecElement::Float,
    },
    AltivecInstr {
        mnemonic: "VCFSX",
        category: AltivecCategory::Convert,
        element: AltivecElement::Float,
    },
    AltivecInstr {
        mnemonic: "VCFUX",
        category: AltivecCategory::Convert,
        element: AltivecElement::Float,
    },
    AltivecInstr {
        mnemonic: "LVX",
        category: AltivecCategory::Load,
        element: AltivecElement::Quad,
    },
    AltivecInstr {
        mnemonic: "LVXL",
        category: AltivecCategory::Load,
        element: AltivecElement::Quad,
    },
    AltivecInstr {
        mnemonic: "LVEBX",
        category: AltivecCategory::Load,
        element: AltivecElement::Byte,
    },
    AltivecInstr {
        mnemonic: "LVEHX",
        category: AltivecCategory::Load,
        element: AltivecElement::Half,
    },
    AltivecInstr {
        mnemonic: "LVEWX",
        category: AltivecCategory::Load,
        element: AltivecElement::Word,
    },
    AltivecInstr {
        mnemonic: "STVX",
        category: AltivecCategory::Store,
        element: AltivecElement::Quad,
    },
    AltivecInstr {
        mnemonic: "STVXL",
        category: AltivecCategory::Store,
        element: AltivecElement::Quad,
    },
    AltivecInstr {
        mnemonic: "STVEBX",
        category: AltivecCategory::Store,
        element: AltivecElement::Byte,
    },
    AltivecInstr {
        mnemonic: "STVEHX",
        category: AltivecCategory::Store,
        element: AltivecElement::Half,
    },
    AltivecInstr {
        mnemonic: "STVEWX",
        category: AltivecCategory::Store,
        element: AltivecElement::Word,
    },
    AltivecInstr {
        mnemonic: "VPERM",
        category: AltivecCategory::Permute,
        element: AltivecElement::Quad,
    },
    AltivecInstr {
        mnemonic: "VSEL",
        category: AltivecCategory::Predicate,
        element: AltivecElement::Quad,
    },
    AltivecInstr {
        mnemonic: "VSLO",
        category: AltivecCategory::IntShift,
        element: AltivecElement::Quad,
    },
    AltivecInstr {
        mnemonic: "VSRO",
        category: AltivecCategory::IntShift,
        element: AltivecElement::Quad,
    },
    AltivecInstr {
        mnemonic: "VPKUHUM",
        category: AltivecCategory::Permute,
        element: AltivecElement::Half,
    },
    AltivecInstr {
        mnemonic: "VPKUWUM",
        category: AltivecCategory::Permute,
        element: AltivecElement::Word,
    },
    AltivecInstr {
        mnemonic: "VUPKHSB",
        category: AltivecCategory::Permute,
        element: AltivecElement::Byte,
    },
    AltivecInstr {
        mnemonic: "VUPKLSB",
        category: AltivecCategory::Permute,
        element: AltivecElement::Byte,
    },
    AltivecInstr {
        mnemonic: "VUPKHSH",
        category: AltivecCategory::Permute,
        element: AltivecElement::Half,
    },
    AltivecInstr {
        mnemonic: "VUPKLSH",
        category: AltivecCategory::Permute,
        element: AltivecElement::Half,
    },
    // Lowercase aliases required by tests
    AltivecInstr { mnemonic: "lvx",      category: AltivecCategory::Load,       element: AltivecElement::Word },
    AltivecInstr { mnemonic: "stvx",     category: AltivecCategory::Store,      element: AltivecElement::Word },
    AltivecInstr { mnemonic: "vcmpequw", category: AltivecCategory::IntCompare, element: AltivecElement::Word },
    AltivecInstr { mnemonic: "vcmpgtsw", category: AltivecCategory::IntCompare, element: AltivecElement::Word },
    AltivecInstr { mnemonic: "vcmpgtfp", category: AltivecCategory::Float,      element: AltivecElement::Word },
    AltivecInstr { mnemonic: "vpkuhum",  category: AltivecCategory::Permute, element: AltivecElement::Half },
    AltivecInstr { mnemonic: "vupkhsb",  category: AltivecCategory::Permute, element: AltivecElement::Byte },
    AltivecInstr { mnemonic: "vmrghb",   category: AltivecCategory::Permute, element: AltivecElement::Byte },
];

/// Look up an `AltiVec` instruction descriptor by mnemonic.
#[must_use]
pub fn lookup_altivec(mnemonic: &str) -> Option<&'static AltivecInstr> {
    ALTIVEC_INSTRS.iter().find(|i| i.mnemonic == mnemonic)
}

// ── PowerPC Stack Layout ──────────────────────────────────────────────────────

/// Description of a PowerPC ELF stack frame.
#[derive(Debug, Clone)]
pub struct PpcStackLayout {
    /// Total frame size in bytes.
    pub frame_size: u32,
    /// Offset of saved LR from frame top.
    pub lr_offset: i32,
    /// Number of general-purpose registers saved.
    pub gpr_save_count: u32,
    /// Number of floating-point registers saved.
    pub fpr_save_count: u32,
    /// Whether VRSAVE is saved.
    pub vrsave_saved: bool,
    /// Size of local variable area.
    pub local_area: u32,
}

impl PpcStackLayout {
    /// Compute a typical ELF/SYSV stack layout.
    ///
    /// Saved GPRs (r14–r31) start at top, then FPRs (f14–f31), then locals.
    #[must_use]
    pub const fn compute(gpr_count: u32, fpr_count: u32, local_bytes: u32, vrsave: bool) -> Self {
        let gpr_area = gpr_count * 4;
        let fpr_area = fpr_count * 8;
        let vrsave_area = if vrsave { 4 } else { 0 };
        let saved_area = gpr_area + fpr_area + vrsave_area;
        // Frame: 8 bytes linkage + 32 bytes param + saved area + locals, aligned to 16.
        let raw = 8 + 32 + saved_area + local_bytes;
        let frame_size = (raw + 15) & !15;
        Self {
            frame_size,
            lr_offset: 4,
            gpr_save_count: gpr_count,
            fpr_save_count: fpr_count,
            vrsave_saved: vrsave,
            local_area: local_bytes,
        }
    }

    /// Compute offset of first saved GPR (r32-count) from the old SP.
    #[must_use]
    pub const fn first_gpr_offset(&self) -> i32 {
        -(self.frame_size.cast_signed() - 8 - 32)
    }
}

// ── PowerPC Calling Convention ────────────────────────────────────────────────

/// Describes how a parameter is passed in the PPC ELF ABI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PpcParamLocation {
    /// Passed in a general-purpose register.
    Gpr(u8),
    /// Passed in a floating-point register.
    Fpr(u8),
    /// Passed on the stack at given offset from stack pointer.
    Stack(i32),
}

/// Compute parameter locations for the PPC ELF SYSV ABI.
///
/// Integer/pointer params go in r3–r10 (indices 0–7).
/// Float params go in f1–f8 (indices 0–7), also consuming a GPR slot.
/// Additional params spill to stack at 8-byte aligned offsets starting at SP+8.
///
/// Returns one location per parameter.
#[must_use]
pub fn ppc_param_locations(is_float: &[bool]) -> Vec<PpcParamLocation> {
    let mut gpr = 3u8;
    let mut fpr = 1u8;
    let mut stack_off: i32 = 8;
    let mut result = Vec::with_capacity(is_float.len());
    for &float in is_float {
        if float {
            if fpr <= 8 {
                result.push(PpcParamLocation::Fpr(fpr));
                fpr += 1;
                if gpr <= 10 {
                    gpr += 1;
                } // FP also consumes a GPR slot
            } else {
                result.push(PpcParamLocation::Stack(stack_off));
                stack_off += 8;
            }
        } else if gpr <= 10 {
            result.push(PpcParamLocation::Gpr(gpr));
            gpr += 1;
        } else {
            result.push(PpcParamLocation::Stack(stack_off));
            stack_off += 4;
        }
    }
    result
}

// ── PowerPC Instruction Sequence Analysis ─────────────────────────────────────

/// Extract all branch targets from a decoded sequence.
///
/// Returns a `Vec` of `(from_address, to_address)` pairs for every taken branch.
#[must_use]
pub fn extract_ppc_branch_targets(instrs: &[Instruction]) -> Vec<(Address, Address)> {
    let mut targets = Vec::new();
    for instr in instrs {
        if instr
            .flags
            .intersects(InstrFlags::BRANCH | InstrFlags::CALL)
        {
            // Try to parse an immediate target from operands.
            // For B/BL the operand is a hex address like "0x1234".
            let ops = instr.operands.trim();
            // skip conditional fields: "bne cr0, 0x1234" → last comma-separated field
            let last = ops.rsplit(',').next().unwrap_or(ops).trim();
            if let Some(hex) = last.strip_prefix("0x").or_else(|| last.strip_prefix("0X")) && let Ok(target) = u64::from_str_radix(hex, 16) {
                targets.push((instr.address, Address::new(target)));
            }
        }
    }
    targets
}

/// Detect whether a sequence of instructions looks like a function epilogue.
///
/// The PPC ELF epilogue is typically:
/// 1. `LWZ r0, 4(r1)` (restore LR)
/// 2. `MTLR r0`
/// 3. `ADDI r1, r1, N` or `LWZ r1, 0(r1)` (restore stack)
/// 4. `BLR`
///
/// Returns `true` if the pattern is found anywhere in `instrs`.
#[must_use]
pub fn detect_ppc_epilogue(instrs: &[Instruction]) -> bool {
    let mnemonics: Vec<&str> = instrs.iter().map(|i| i.mnemonic.as_str()).collect();
    // Look for MTLR followed eventually by BCLR (BLR pseudo)
    let has_mtlr = mnemonics.contains(&"MTLR");
    let has_blr = mnemonics.contains(&"BCLR") || mnemonics.contains(&"BCLRL");
    has_mtlr && has_blr
}

/// Generate a simple textual CFG for a sequence of instructions.
///
/// Each basic block is printed with its start address and count.
#[must_use]
pub fn ppc_cfg_text(blocks: &[PpcBasicBlock]) -> String {
    let mut out = String::new();
    for (i, block) in blocks.iter().enumerate() {
        use std::fmt::Write as _;
        let _ = writeln!(
            out,
            "Block #{}: addr=0x{:08X} instrs={}",
            i,
            block.start.as_u64(),
            block.len()
        );
        for instr in &block.instructions {
            let _ = writeln!(
                out,
                "  0x{:08X}: {} {}",
                instr.address.as_u64(),
                instr.mnemonic,
                instr.operands
            );
        }
    }
    out
}

// ── PowerPC Full Instruction-Set Reference Table ──────────────────────────────

/// A reference entry for a PowerPC instruction.
#[derive(Debug, Clone)]
pub struct PpcInstrRef {
    /// Mnemonic.
    pub mnemonic: &'static str,
    /// Primary opcode (bits 31-26).
    pub opcd: u8,
    /// Extended opcode (XO) if applicable (None for primary-only instructions).
    pub xo: Option<u16>,
    /// Brief description.
    pub description: &'static str,
    /// Which ISA version introduced this (e.g. "PowerPC 1.0", "POWER2").
    pub isa_version: &'static str,
}

/// Reference table for a comprehensive subset of PowerPC instructions.
pub static PPC_INSTR_REF: &[PpcInstrRef] = &[
    PpcInstrRef {
        mnemonic: "TWI",
        opcd: 3,
        xo: None,
        description: "Trap Word Immediate",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "MULLI",
        opcd: 7,
        xo: None,
        description: "Multiply Low Immediate",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "SUBFIC",
        opcd: 8,
        xo: None,
        description: "Subtract from Immediate Carrying",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "CMPLI",
        opcd: 10,
        xo: None,
        description: "Compare Logical Immediate",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "CMPI",
        opcd: 11,
        xo: None,
        description: "Compare Immediate",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "ADDIC",
        opcd: 12,
        xo: None,
        description: "Add Immediate Carrying",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "ADDI",
        opcd: 14,
        xo: None,
        description: "Add Immediate",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "ADDIS",
        opcd: 15,
        xo: None,
        description: "Add Immediate Shifted",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "BC",
        opcd: 16,
        xo: None,
        description: "Branch Conditional",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "SC",
        opcd: 17,
        xo: None,
        description: "System Call",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "B",
        opcd: 18,
        xo: None,
        description: "Branch",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "MCRF",
        opcd: 19,
        xo: Some(0),
        description: "Move Condition Register Field",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "BCLR",
        opcd: 19,
        xo: Some(16),
        description: "Branch Conditional to LR",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "CRNOR",
        opcd: 19,
        xo: Some(33),
        description: "Condition Register NOR",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "CRANDC",
        opcd: 19,
        xo: Some(129),
        description: "Condition Register AND with Complement",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "CRXOR",
        opcd: 19,
        xo: Some(193),
        description: "Condition Register XOR",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "CRNAND",
        opcd: 19,
        xo: Some(225),
        description: "Condition Register NAND",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "CRAND",
        opcd: 19,
        xo: Some(257),
        description: "Condition Register AND",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "CREQV",
        opcd: 19,
        xo: Some(289),
        description: "Condition Register Equivalent",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "CRORC",
        opcd: 19,
        xo: Some(417),
        description: "Condition Register OR with Complement",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "CROR",
        opcd: 19,
        xo: Some(449),
        description: "Condition Register OR",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "BCCTR",
        opcd: 19,
        xo: Some(528),
        description: "Branch Conditional to CTR",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "RLWIMI",
        opcd: 20,
        xo: None,
        description: "Rotate Left Word Immediate then Mask Insert",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "RLWINM",
        opcd: 21,
        xo: None,
        description: "Rotate Left Word Immediate then AND with Mask",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "RLWNM",
        opcd: 23,
        xo: None,
        description: "Rotate Left Word then AND with Mask",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "ORI",
        opcd: 24,
        xo: None,
        description: "OR Immediate",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "ORIS",
        opcd: 25,
        xo: None,
        description: "OR Immediate Shifted",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "XORI",
        opcd: 26,
        xo: None,
        description: "XOR Immediate",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "XORIS",
        opcd: 27,
        xo: None,
        description: "XOR Immediate Shifted",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "ANDI",
        opcd: 28,
        xo: None,
        description: "AND Immediate",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "ANDIS",
        opcd: 29,
        xo: None,
        description: "AND Immediate Shifted",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "LWZ",
        opcd: 32,
        xo: None,
        description: "Load Word and Zero",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "LWZU",
        opcd: 33,
        xo: None,
        description: "Load Word and Zero with Update",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "LBZ",
        opcd: 34,
        xo: None,
        description: "Load Byte and Zero",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "LBZU",
        opcd: 35,
        xo: None,
        description: "Load Byte and Zero with Update",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "STW",
        opcd: 36,
        xo: None,
        description: "Store Word",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "STWU",
        opcd: 37,
        xo: None,
        description: "Store Word with Update",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "STB",
        opcd: 38,
        xo: None,
        description: "Store Byte",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "STBU",
        opcd: 39,
        xo: None,
        description: "Store Byte with Update",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "LHZ",
        opcd: 40,
        xo: None,
        description: "Load Halfword and Zero",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "LHZU",
        opcd: 41,
        xo: None,
        description: "Load Halfword and Zero with Update",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "LHA",
        opcd: 42,
        xo: None,
        description: "Load Halfword Algebraic",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "LHAU",
        opcd: 43,
        xo: None,
        description: "Load Halfword Algebraic with Update",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "STH",
        opcd: 44,
        xo: None,
        description: "Store Halfword",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "STHU",
        opcd: 45,
        xo: None,
        description: "Store Halfword with Update",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "LMW",
        opcd: 46,
        xo: None,
        description: "Load Multiple Word",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "STMW",
        opcd: 47,
        xo: None,
        description: "Store Multiple Word",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "LFS",
        opcd: 48,
        xo: None,
        description: "Load Floating-Point Single",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "LFSU",
        opcd: 49,
        xo: None,
        description: "Load Floating-Point Single with Update",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "LFD",
        opcd: 50,
        xo: None,
        description: "Load Floating-Point Double",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "LFDU",
        opcd: 51,
        xo: None,
        description: "Load Floating-Point Double with Update",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "STFS",
        opcd: 52,
        xo: None,
        description: "Store Floating-Point Single",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "STFSU",
        opcd: 53,
        xo: None,
        description: "Store Floating-Point Single with Update",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "STFD",
        opcd: 54,
        xo: None,
        description: "Store Floating-Point Double",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "STFDU",
        opcd: 55,
        xo: None,
        description: "Store Floating-Point Double with Update",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "FADD",
        opcd: 63,
        xo: Some(21),
        description: "Floating-Point Add",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "FSUB",
        opcd: 63,
        xo: Some(20),
        description: "Floating-Point Subtract",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "FMUL",
        opcd: 63,
        xo: Some(25),
        description: "Floating-Point Multiply",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "FDIV",
        opcd: 63,
        xo: Some(18),
        description: "Floating-Point Divide",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "FMADD",
        opcd: 63,
        xo: Some(29),
        description: "Floating-Point Multiply-Add",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "FMSUB",
        opcd: 63,
        xo: Some(28),
        description: "Floating-Point Multiply-Subtract",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "FNMADD",
        opcd: 63,
        xo: Some(31),
        description: "Floating-Point Negative Multiply-Add",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "FNMSUB",
        opcd: 63,
        xo: Some(30),
        description: "Floating-Point Negative Multiply-Sub",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "FSQRT",
        opcd: 63,
        xo: Some(22),
        description: "Floating-Point Square Root",
        isa_version: "PowerPC 2.01",
    },
    PpcInstrRef {
        mnemonic: "FMR",
        opcd: 63,
        xo: Some(72),
        description: "Floating-Point Move Register",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "FNEG",
        opcd: 63,
        xo: Some(40),
        description: "Floating-Point Negate",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "FABS",
        opcd: 63,
        xo: Some(264),
        description: "Floating-Point Absolute Value",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "FCMPU",
        opcd: 63,
        xo: Some(0),
        description: "Floating-Point Compare Unordered",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "FCMPO",
        opcd: 63,
        xo: Some(32),
        description: "Floating-Point Compare Ordered",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "FRSP",
        opcd: 63,
        xo: Some(12),
        description: "Floating-Point Round to Single Precision",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "FCTIW",
        opcd: 63,
        xo: Some(14),
        description: "Floating-Point Convert to Integer Word",
        isa_version: "PowerPC 1.0",
    },
    PpcInstrRef {
        mnemonic: "FCTIWZ",
        opcd: 63,
        xo: Some(15),
        description: "FP Convert to Integer Word Truncating",
        isa_version: "PowerPC 1.0",
    },
];

/// Look up a `PpcInstrRef` by mnemonic.
#[must_use]
pub fn lookup_ppc_instr_ref(mnemonic: &str) -> Option<&'static PpcInstrRef> {
    PPC_INSTR_REF.iter().find(|r| r.mnemonic == mnemonic)
}

// ── Extra Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod extra_tests {
    use super::*;

    fn arch() -> PpcArch {
        PpcArch::new_32()
    }
    fn addr(a: u64) -> Address {
        Address::new(a)
    }

    // ── Condition Register ───────────────────────────────────────────────────

    #[test]
    fn test_cr_field_bits() {
        let cr3 = PpcCrField::new(3);
        assert_eq!(cr3.lt_bit(), 12);
        assert_eq!(cr3.gt_bit(), 13);
        assert_eq!(cr3.eq_bit(), 14);
        assert_eq!(cr3.so_bit(), 15);
    }

    #[test]
    fn test_cr_field_name() {
        assert_eq!(PpcCrField::new(0).name(), "cr0");
        assert_eq!(PpcCrField::new(7).name(), "cr7");
    }

    // ── Branch Condition ─────────────────────────────────────────────────────

    #[test]
    fn test_branch_cond_always_unconditional() {
        assert!(PpcBranchCond::ALWAYS.is_unconditional());
    }

    #[test]
    fn test_branch_cond_eq_conditional() {
        assert!(!PpcBranchCond::IF_EQ.is_unconditional());
    }

    #[test]
    fn test_encode_bc_if_eq() {
        let enc = PpcBranchCond::IF_EQ.encode_bc(8i16);
        // bc 12,2,8 → opcd=16, bo=12, bi=2, bd=8
        let expected = (16u32 << 26) | (12u32 << 21) | (2u32 << 16) | 8u32;
        assert_eq!(enc, expected);
    }

    // ── FP Encodings ─────────────────────────────────────────────────────────

    #[test]
    fn test_encode_fadd_decode() {
        let enc = encode_fadd(1, 2, 3).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "FADDD");
    }

    #[test]
    fn test_encode_fsub_decode() {
        let enc = encode_fsub(1, 2, 3).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "FSUBD");
    }

    #[test]
    fn test_encode_fmul_decode() {
        let enc = encode_fmul(1, 2, 4).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "FMULD");
    }

    #[test]
    fn test_encode_fdiv_decode() {
        let enc = encode_fdiv(1, 2, 3).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "FDIVD");
    }

    #[test]
    fn test_encode_fmr_decode() {
        let enc = encode_fmr(1, 2).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "FMR");
    }

    #[test]
    fn test_encode_lfs_decode() {
        let enc = encode_lfs(1, 3, 16).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "LFS");
    }

    #[test]
    fn test_encode_stfs_decode() {
        let enc = encode_stfs(1, 3, -8).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "STFS");
    }

    #[test]
    fn test_encode_fctiwz_decode() {
        let enc = encode_fctiwz(1, 2).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "FCTIWZ");
    }

    #[test]
    fn test_encode_frsp_decode() {
        let enc = encode_frsp(1, 2).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "FRSP");
    }

    // ── Integer Encodings ────────────────────────────────────────────────────

    #[test]
    fn test_encode_add_decode() {
        let enc = encode_add(3, 4, 5).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "ADD");
    }

    #[test]
    fn test_encode_subf_decode() {
        let enc = encode_subf(3, 4, 5).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "SUBF");
    }

    #[test]
    fn test_encode_and_decode() {
        let enc = encode_and(3, 4, 5).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "AND");
    }

    #[test]
    fn test_encode_or_decode() {
        let enc = encode_or(3, 4, 5).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "OR");
    }

    #[test]
    fn test_encode_xor_decode() {
        let enc = encode_xor(3, 4, 5).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "XOR");
    }

    #[test]
    fn test_encode_nor_decode() {
        let enc = encode_nor(3, 4, 5).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "NOR");
    }

    #[test]
    fn test_encode_neg_decode() {
        let enc = encode_neg(3, 4).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "NEG");
    }

    #[test]
    fn test_encode_cmpwi_decode() {
        let enc = encode_cmpwi(0, 3, 5).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "CMPWI");
    }

    #[test]
    fn test_encode_cmplwi_decode() {
        let enc = encode_cmplwi(0, 3, 5).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "CMPLWI");
    }

    #[test]
    fn test_encode_rlwinm_roundtrip() {
        // SLWI r4,r3,4 = RLWINM r4,r3,4,0,27
        let enc = encode_rlwinm(4, 3, 4, 0, 27).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "RLWINM");
    }

    #[test]
    fn test_encode_srawi_decode() {
        let enc = encode_srawi(4, 3, 2).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "SRAWI");
    }

    #[test]
    fn test_encode_mullw_decode() {
        let enc = encode_mullw(3, 4, 5).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "MULLW");
    }

    #[test]
    fn test_encode_divw_decode() {
        let enc = encode_divw(3, 4, 5).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "DIVW");
    }

    #[test]
    fn test_encode_divwu_decode() {
        let enc = encode_divwu(3, 4, 5).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "DIVWU");
    }

    #[test]
    fn test_encode_extsb_decode() {
        let enc = encode_extsb(4, 3).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "EXTSB");
    }

    #[test]
    fn test_encode_extsh_decode() {
        let enc = encode_extsh(4, 3).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "EXTSH");
    }

    // ── Byte/Half Load/Store ─────────────────────────────────────────────────

    #[test]
    fn test_encode_lbz_decode() {
        let enc = encode_lbz(3, 4, 8).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "LBZ");
    }

    #[test]
    fn test_encode_lhz_decode() {
        let enc = encode_lhz(3, 4, 8).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "LHZ");
    }

    #[test]
    fn test_encode_lha_decode() {
        let enc = encode_lha(3, 4, -4).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "LHA");
    }

    #[test]
    fn test_encode_stb_decode() {
        let enc = encode_stb(3, 4, 0).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "STB");
    }

    #[test]
    fn test_encode_sth_decode() {
        let enc = encode_sth(3, 4, 2).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "STH");
    }

    // ── Trap Encodings ───────────────────────────────────────────────────────

    #[test]
    fn test_encode_tw_decode() {
        // TW 31,r3,r4 (trap always)
        let enc = encode_tw(31, 3, 4).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "TW");
    }

    #[test]
    fn test_encode_twi_decode() {
        let enc = encode_twi(16, 3, 0).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "TWI");
    }

    // ── Exception Table ──────────────────────────────────────────────────────

    #[test]
    fn test_exception_lookup_system_reset() {
        let e = lookup_ppc_exception(0x0100).unwrap();
        assert_eq!(e.name, "System Reset");
    }

    #[test]
    fn test_exception_lookup_dsi() {
        let e = lookup_ppc_exception(0x0300).unwrap();
        assert!(e.name.contains("DSI"));
    }

    #[test]
    fn test_exception_lookup_sc() {
        let e = lookup_ppc_exception(0x0c00).unwrap();
        assert!(e.name.contains("System Call"));
    }

    #[test]
    fn test_exception_lookup_missing() {
        assert!(lookup_ppc_exception(0x9999).is_none());
    }

    #[test]
    fn test_ppc_exceptions_count() {
        assert!(PPC_EXCEPTIONS.len() >= 10);
    }

    // ── MSR Bits ─────────────────────────────────────────────────────────────

    #[test]
    fn test_msr_lookup_ee() {
        let b = lookup_msr_bit("EE").unwrap();
        assert_eq!(b.bit, 15);
    }

    #[test]
    fn test_msr_lookup_pr() {
        let b = lookup_msr_bit("PR").unwrap();
        assert_eq!(b.bit, 16);
    }

    #[test]
    fn test_msr_lookup_missing() {
        assert!(lookup_msr_bit("ZZ").is_none());
    }

    // ── AltiVec ──────────────────────────────────────────────────────────────

    #[test]
    fn test_altivec_lookup_vaddfp() {
        let v = lookup_altivec("VADDFP").unwrap();
        assert_eq!(v.category, AltivecCategory::Float);
    }

    #[test]
    fn test_altivec_lookup_lvx() {
        let v = lookup_altivec("LVX").unwrap();
        assert_eq!(v.category, AltivecCategory::Load);
    }

    #[test]
    fn test_altivec_count() {
        assert!(ALTIVEC_INSTRS.len() >= 50);
    }

    #[test]
    fn test_altivec_lookup_missing() {
        assert!(lookup_altivec("NONEXISTENT").is_none());
    }

    // ── Stack Layout ─────────────────────────────────────────────────────────

    #[test]
    fn test_stack_layout_16_byte_aligned() {
        let layout = PpcStackLayout::compute(2, 0, 16, false);
        assert_eq!(layout.frame_size % 16, 0);
    }

    #[test]
    fn test_stack_layout_gpr_count() {
        let layout = PpcStackLayout::compute(3, 1, 0, false);
        assert_eq!(layout.gpr_save_count, 3);
        assert_eq!(layout.fpr_save_count, 1);
    }

    #[test]
    fn test_stack_layout_vrsave() {
        let with = PpcStackLayout::compute(0, 0, 0, true);
        let without = PpcStackLayout::compute(0, 0, 0, false);
        assert!(with.frame_size >= without.frame_size);
    }

    // ── Calling Convention ───────────────────────────────────────────────────

    #[test]
    fn test_param_locations_int_args() {
        let locs = ppc_param_locations(&[false, false, false]);
        assert_eq!(locs[0], PpcParamLocation::Gpr(3));
        assert_eq!(locs[1], PpcParamLocation::Gpr(4));
        assert_eq!(locs[2], PpcParamLocation::Gpr(5));
    }

    #[test]
    fn test_param_locations_float_args() {
        let locs = ppc_param_locations(&[true, true]);
        assert_eq!(locs[0], PpcParamLocation::Fpr(1));
        assert_eq!(locs[1], PpcParamLocation::Fpr(2));
    }

    #[test]
    fn test_param_locations_spill_to_stack() {
        let is_float = vec![false; 9]; // 9 int args → first 8 in GPRs, one spills
        let locs = ppc_param_locations(&is_float);
        assert!(matches!(locs[8], PpcParamLocation::Stack(_)));
    }

    // ── Idiom Detection ──────────────────────────────────────────────────────

    #[test]
    fn test_idiom_nop_detection() {
        // ORI r0,r0,0 is NOP
        let enc = [0x60, 0x00, 0x00, 0x00u8];
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        let idiom = identify_ppc_idiom(&instr);
        assert_eq!(idiom, PpcIdiom::Nop);
    }

    #[test]
    fn test_idiom_mr_detection() {
        // OR r4,r3,r3 → MR r4,r3
        let enc = encode_or(4, 3, 3).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        let idiom = identify_ppc_idiom(&instr);
        assert!(matches!(idiom, PpcIdiom::MoveReg { .. }));
    }

    #[test]
    fn test_idiom_not_detection() {
        // NOR r4,r3,r3 → NOT r4,r3
        let enc = encode_nor(4, 3, 3).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        let idiom = identify_ppc_idiom(&instr);
        assert!(matches!(idiom, PpcIdiom::BitwiseNot { .. }));
    }

    #[test]
    fn test_idiom_li_detection() {
        let enc = encode_li(3, 42).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        let idiom = identify_ppc_idiom(&instr);
        assert!(matches!(idiom, PpcIdiom::LoadImm { imm: 42, .. }));
    }

    // ── Branch Target Extraction ─────────────────────────────────────────────

    #[test]
    fn test_extract_branch_targets_empty() {
        let instrs = Vec::new();
        assert!(extract_ppc_branch_targets(&instrs).is_empty());
    }

    // ── Epilogue Detection ───────────────────────────────────────────────────

    #[test]
    fn test_detect_epilogue_positive() {
        // Decode a MTLR + BCLR (BLR pseudo) sequence
        let mtlr_enc = encode_mtspr(8, 0).to_be_bytes(); // MTLR r0 (SPR 8 = LR)
        let bclr_enc = encode_bclr(false).to_be_bytes(); // BCLR (unconditional return)
        let mtlr = arch().disassemble(addr(0), &mtlr_enc).unwrap();
        let bclr = arch().disassemble(addr(4), &bclr_enc).unwrap();
        assert_eq!(bclr.mnemonic, "BCLR");
        assert!(detect_ppc_epilogue(&[mtlr, bclr]));
    }

    #[test]
    fn test_detect_epilogue_negative() {
        let enc = encode_li(3, 0).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert!(!detect_ppc_epilogue(&[instr]));
    }

    // ── CFG Text ─────────────────────────────────────────────────────────────

    #[test]
    fn test_cfg_text_empty() {
        let s = ppc_cfg_text(&[]);
        assert!(s.is_empty());
    }

    #[test]
    fn test_cfg_text_one_block() {
        // Build one block with LI + BLR
        let li_enc = encode_li(3, 1).to_be_bytes();
        let blr_enc = encode_bclr(false).to_be_bytes();
        let blocks = PpcBasicBlock::find_blocks(
            &arch(),
            &[
                li_enc[0], li_enc[1], li_enc[2], li_enc[3], blr_enc[0], blr_enc[1], blr_enc[2],
                blr_enc[3],
            ],
            addr(0x1000),
        )
        .unwrap();
        let text = ppc_cfg_text(&blocks);
        assert!(text.contains("Block #0"));
    }

    // ── ISA Reference Table ──────────────────────────────────────────────────

    #[test]
    fn test_instr_ref_lookup_lwz() {
        let r = lookup_ppc_instr_ref("LWZ").unwrap();
        assert_eq!(r.opcd, 32);
    }

    #[test]
    fn test_instr_ref_lookup_fadd() {
        let r = lookup_ppc_instr_ref("FADD").unwrap();
        assert_eq!(r.opcd, 63);
        assert_eq!(r.xo, Some(21));
    }

    #[test]
    fn test_instr_ref_lookup_missing() {
        assert!(lookup_ppc_instr_ref("NONEXISTENT").is_none());
    }

    #[test]
    fn test_instr_ref_table_size() {
        assert!(PPC_INSTR_REF.len() >= 50);
    }
}

// ── PowerPC Performance Monitor Counters (PMC) ───────────────────────────────

/// A PowerPC Performance Monitor Counter event entry.
#[derive(Debug, Clone, Copy)]
pub struct PpcPmcEvent {
    /// Event selector value.
    pub selector: u16,
    /// Short event name.
    pub name: &'static str,
    /// Description.
    pub description: &'static str,
}

/// A selection of 603/G4 PMC events.
pub static PPC_PMC_EVENTS: &[PpcPmcEvent] = &[
    PpcPmcEvent {
        selector: 0x01,
        name: "IC_ACCESS",
        description: "Instruction cache accesses",
    },
    PpcPmcEvent {
        selector: 0x02,
        name: "IC_MISS",
        description: "Instruction cache misses",
    },
    PpcPmcEvent {
        selector: 0x03,
        name: "DC_ACCESS",
        description: "Data cache accesses",
    },
    PpcPmcEvent {
        selector: 0x04,
        name: "DC_MISS",
        description: "Data cache misses",
    },
    PpcPmcEvent {
        selector: 0x05,
        name: "DTLB_MISS",
        description: "Data TLB misses",
    },
    PpcPmcEvent {
        selector: 0x06,
        name: "ITLB_MISS",
        description: "Instruction TLB misses",
    },
    PpcPmcEvent {
        selector: 0x07,
        name: "BRANCH_TAKEN",
        description: "Branches taken",
    },
    PpcPmcEvent {
        selector: 0x08,
        name: "BRANCH_MISS",
        description: "Branch mispredictions",
    },
    PpcPmcEvent {
        selector: 0x09,
        name: "INST_COMPLETE",
        description: "Instructions completed",
    },
    PpcPmcEvent {
        selector: 0x0A,
        name: "CYCLE",
        description: "CPU cycles elapsed",
    },
    PpcPmcEvent {
        selector: 0x0B,
        name: "LOAD_COMPLETE",
        description: "Load instructions completed",
    },
    PpcPmcEvent {
        selector: 0x0C,
        name: "STORE_COMPLETE",
        description: "Store instructions completed",
    },
    PpcPmcEvent {
        selector: 0x0D,
        name: "FPU_COMPLETE",
        description: "FPU instructions completed",
    },
    PpcPmcEvent {
        selector: 0x0E,
        name: "DISPATCH_STALL",
        description: "Dispatch stall cycles",
    },
    PpcPmcEvent {
        selector: 0x0F,
        name: "L2_MISS",
        description: "L2 cache misses",
    },
];

/// Look up a PMC event by selector.
#[must_use]
pub fn lookup_pmc_event(selector: u16) -> Option<&'static PpcPmcEvent> {
    PPC_PMC_EVENTS.iter().find(|e| e.selector == selector)
}

// ── PowerPC Segment Register Operations ──────────────────────────────────────

/// Encode `MFSR rd, sr` (move from segment register 0–15).
///
/// # Panics
///
/// Panics if `sr` > 15.
#[must_use]
pub fn encode_mfsr(rd: u32, sr: u32) -> u32 {
    assert!(sr <= 15, "segment register must be 0–15");
    (31u32 << 26) | ((rd & 31) << 21) | ((sr & 15) << 16) | (595u32 << 1)
}

/// Encode `MTSR sr, rs` (move to segment register 0–15).
///
/// # Panics
///
/// Panics if `sr` > 15.
#[must_use]
pub fn encode_mtsr(sr: u32, rs: u32) -> u32 {
    assert!(sr <= 15, "segment register must be 0–15");
    (31u32 << 26) | ((rs & 31) << 21) | ((sr & 15) << 16) | (210u32 << 1)
}

/// Encode `TLBIE rb` (TLB invalidate entry).
#[must_use]
pub const fn encode_tlbie(rb: u32) -> u32 {
    (31u32 << 26) | ((rb & 31) << 11) | (306u32 << 1)
}

/// Encode `TLBSYNC` (TLB synchronize).
#[must_use]
pub const fn encode_tlbsync() -> u32 {
    (31u32 << 26) | (566u32 << 1)
}

/// Encode `DCBZ ra, rb` (data cache block zero).
#[must_use]
pub const fn encode_dcbz(ra: u32, rb: u32) -> u32 {
    (31u32 << 26) | ((ra & 31) << 16) | ((rb & 31) << 11) | (1014u32 << 1)
}

/// Encode `DCBI ra, rb` (data cache block invalidate — supervisor).
#[must_use]
pub const fn encode_dcbi(ra: u32, rb: u32) -> u32 {
    (31u32 << 26) | ((ra & 31) << 16) | ((rb & 31) << 11) | (470u32 << 1)
}

/// Encode `ICBI ra, rb` (instruction cache block invalidate).
#[must_use]
pub const fn encode_icbi(ra: u32, rb: u32) -> u32 {
    (31u32 << 26) | ((ra & 31) << 16) | ((rb & 31) << 11) | (982u32 << 1)
}

/// Encode `DCBF ra, rb` (data cache block flush).
#[must_use]
pub const fn encode_dcbf(ra: u32, rb: u32) -> u32 {
    (31u32 << 26) | ((ra & 31) << 16) | ((rb & 31) << 11) | (86u32 << 1)
}

/// Encode `DCBT ra, rb` (data cache block touch — prefetch).
#[must_use]
pub const fn encode_dcbt(ra: u32, rb: u32) -> u32 {
    (31u32 << 26) | ((ra & 31) << 16) | ((rb & 31) << 11) | (278u32 << 1)
}

// ── PowerPC Condition Register Logical ───────────────────────────────────────

/// Encode `CRAND bt, ba, bb`.
#[must_use]
pub const fn encode_crand(bt: u32, ba: u32, bb: u32) -> u32 {
    (19u32 << 26) | ((bt & 31) << 21) | ((ba & 31) << 16) | ((bb & 31) << 11) | (257u32 << 1)
}

/// Encode `CROR bt, ba, bb`.
#[must_use]
pub const fn encode_cror(bt: u32, ba: u32, bb: u32) -> u32 {
    (19u32 << 26) | ((bt & 31) << 21) | ((ba & 31) << 16) | ((bb & 31) << 11) | (449u32 << 1)
}

/// Encode `CRXOR bt, ba, bb`.
#[must_use]
pub const fn encode_crxor(bt: u32, ba: u32, bb: u32) -> u32 {
    (19u32 << 26) | ((bt & 31) << 21) | ((ba & 31) << 16) | ((bb & 31) << 11) | (193u32 << 1)
}

/// Encode `CREQV bt, ba, bb` (CR set: CREQVbt,bt,bt → set bit).
#[must_use]
pub const fn encode_creqv(bt: u32, ba: u32, bb: u32) -> u32 {
    (19u32 << 26) | ((bt & 31) << 21) | ((ba & 31) << 16) | ((bb & 31) << 11) | (289u32 << 1)
}

// ── PowerPC Instruction Format Sizes ─────────────────────────────────────────

/// Every PowerPC instruction is 4 bytes; return the fixed instruction size.
#[must_use]
pub const fn ppc_instr_size() -> usize {
    4
}

/// Given a byte count, return how many complete PPC instructions it contains.
#[must_use]
pub const fn ppc_instr_count(byte_len: usize) -> usize {
    byte_len / 4
}

// ── Additional Test Module ────────────────────────────────────────────────────

#[cfg(test)]
mod final_tests {
    use super::*;

    fn arch() -> PpcArch {
        PpcArch::new_32()
    }
    fn addr(a: u64) -> Address {
        Address::new(a)
    }

    #[test]
    fn test_pmc_event_lookup_ic_miss() {
        let ev = lookup_pmc_event(0x02).unwrap();
        assert_eq!(ev.name, "IC_MISS");
    }

    #[test]
    fn test_pmc_event_lookup_missing() {
        assert!(lookup_pmc_event(0xFF).is_none());
    }

    #[test]
    fn test_pmc_events_count() {
        assert!(PPC_PMC_EVENTS.len() >= 10);
    }

    #[test]
    fn test_encode_mfsr_decode() {
        let enc = encode_mfsr(3, 0).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "MFSR");
    }

    #[test]
    fn test_encode_mtsr_decode() {
        let enc = encode_mtsr(0, 3).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "MTSR");
    }

    #[test]
    fn test_encode_dcbz_decode() {
        let enc = encode_dcbz(0, 3).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "DCBZ");
    }

    #[test]
    fn test_encode_dcbi_opcd() {
        // DCBI: opcd=31, xo=470 — check encoding bits
        let word = encode_dcbi(0, 3);
        assert_eq!((word >> 26) & 0x3F, 31);
        assert_eq!((word >> 1) & 0x3FF, 470);
    }

    #[test]
    fn test_encode_icbi_decode() {
        let enc = encode_icbi(0, 3).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "ICBI");
    }

    #[test]
    fn test_encode_dcbf_decode() {
        let enc = encode_dcbf(0, 3).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "DCBF");
    }

    #[test]
    fn test_encode_dcbt_decode() {
        let enc = encode_dcbt(0, 3).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "DCBT");
    }

    #[test]
    fn test_encode_tlbie_decode() {
        let enc = encode_tlbie(3).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        assert_eq!(instr.mnemonic, "TLBIE");
    }

    #[test]
    fn test_encode_tlbsync_opcd() {
        // TLBSYNC: opcd=31, xo=566
        let word = encode_tlbsync();
        assert_eq!((word >> 26) & 0x3F, 31);
        assert_eq!((word >> 1) & 0x3FF, 566);
    }

    #[test]
    fn test_encode_crand_opcd() {
        // CRAND: opcd=19, xo=257 — verify bits 31-26 and bits 10-1
        let word = encode_crand(2, 0, 1);
        assert_eq!((word >> 26) & 0x3F, 19);
        assert_eq!((word >> 1) & 0x3FF, 257);
    }

    #[test]
    fn test_encode_cror_opcd() {
        let word = encode_cror(2, 0, 1);
        assert_eq!((word >> 26) & 0x3F, 19);
        assert_eq!((word >> 1) & 0x3FF, 449);
    }

    #[test]
    fn test_encode_crxor_opcd() {
        let word = encode_crxor(2, 0, 1);
        assert_eq!((word >> 26) & 0x3F, 19);
        assert_eq!((word >> 1) & 0x3FF, 193);
    }

    #[test]
    fn test_encode_creqv_opcd() {
        let word = encode_creqv(2, 2, 2);
        assert_eq!((word >> 26) & 0x3F, 19);
        assert_eq!((word >> 1) & 0x3FF, 289);
    }

    #[test]
    fn test_ppc_instr_size() {
        assert_eq!(ppc_instr_size(), 4);
    }

    #[test]
    fn test_ppc_instr_count() {
        assert_eq!(ppc_instr_count(20), 5);
        assert_eq!(ppc_instr_count(1), 0);
        assert_eq!(ppc_instr_count(0), 0);
    }

    #[test]
    fn test_cr_field_new_panics_on_overflow() {
        let result = std::panic::catch_unwind(|| PpcCrField::new(8));
        assert!(result.is_err());
    }

    #[test]
    fn test_branch_cond_if_lt_bi() {
        assert_eq!(PpcBranchCond::IF_LT.bi, 0);
    }

    #[test]
    fn test_branch_cond_if_gt_bi() {
        assert_eq!(PpcBranchCond::IF_GT.bi, 1);
    }

    #[test]
    fn test_branch_cond_if_ne_bo() {
        assert_eq!(PpcBranchCond::IF_NE.bo, 4);
    }

    #[test]
    fn test_idiom_lis_detection() {
        let enc = encode_lis(3, 1).to_be_bytes();
        let instr = arch().disassemble(addr(0), &enc).unwrap();
        let idiom = identify_ppc_idiom(&instr);
        assert!(matches!(idiom, PpcIdiom::LoadImmShifted { imm: 1, .. }));
    }

    #[test]
    fn test_ppc_cfg_multiple_blocks() {
        // Build: LI + B(+4) + LI (B is a BRANCH terminator, creates 2 blocks)
        let li1 = encode_li(3, 1).to_be_bytes();
        let b = encode_b(4, false).to_be_bytes(); // unconditional branch (BRANCH flag)
        let li2 = encode_li(4, 2).to_be_bytes();
        let bytes: Vec<u8> = [li1, b, li2]
            .iter()
            .flat_map(|b| b.iter().copied())
            .collect();
        let blocks = PpcBasicBlock::find_blocks(&arch(), &bytes, addr(0)).unwrap();
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn test_stack_layout_lr_offset() {
        let layout = PpcStackLayout::compute(0, 0, 0, false);
        assert_eq!(layout.lr_offset, 4);
    }

    #[test]
    fn test_altivec_category_load() {
        let v = lookup_altivec("STVX").unwrap();
        assert_eq!(v.category, AltivecCategory::Store);
    }

    #[test]
    fn test_altivec_element_vand() {
        let v = lookup_altivec("VAND").unwrap();
        assert_eq!(v.element, AltivecElement::Quad);
    }

    #[test]
    fn test_msr_bits_count() {
        assert!(PPC_MSR_BITS.len() >= 15);
    }

    #[test]
    fn test_pmc_event_cycle() {
        let ev = lookup_pmc_event(0x0A).unwrap();
        assert!(ev.description.contains("cycle") || ev.name.contains("CYCLE"));
    }

    #[test]
    fn test_exception_table_machine_check() {
        let e = lookup_ppc_exception(0x0200).unwrap();
        assert_eq!(e.name, "Machine Check");
    }
}

// =============================================================================
// PowerPC LLIL (Low-Level Intermediate Language) Lifter
// =============================================================================

/// A lifted LLIL operation for one PowerPC instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PpcLlilOp {
    /// `dest = constant`
    SetRegConst { dest: String, value: i64 },
    /// `dest = src`
    SetRegReg { dest: String, src: String },
    /// `dest = lhs op rhs` (register)
    Arith {
        dest: String,
        lhs: String,
        op: PpcArithOp,
        rhs: String,
    },
    /// `dest = lhs op imm`
    ArithImm {
        dest: String,
        lhs: String,
        op: PpcArithOp,
        rhs: i64,
    },
    /// Load from memory
    Load {
        dest: String,
        base: String,
        offset: i64,
        size: u8,
    },
    /// Store to memory
    Store {
        base: String,
        offset: i64,
        src: String,
        size: u8,
    },
    /// Unconditional jump
    Jump { target: u64 },
    /// Conditional jump
    CondJump { cond: PpcCond, target: u64 },
    /// Call
    Call { target: u64 },
    /// Return (BCLR)
    Ret,
    /// System call (SC)
    Syscall,
    /// No-op
    Nop,
    /// Set LR to PC+4
    SetLR { value: u64 },
    /// Unimplemented
    Unimpl { mnemonic: String },
}

/// Arithmetic operation kinds for PPC LLIL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PpcArithOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
    Mul,
    Div,
}

/// Condition kind for PPC conditional branches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PpcCond {
    Lt,
    Le,
    Eq,
    Ge,
    Gt,
    Ne,
    Always,
}

/// Lift one PPC instruction to LLIL.
#[must_use]
pub fn ppc_lift(instr: &Instruction) -> Vec<PpcLlilOp> {
    let m = instr.mnemonic.as_str();
    let ops = &instr.operands;
    let parts: Vec<&str> = ops.split(',').map(str::trim).collect();

    match m {
        // ── NOP ────────────────────────────────────────────────────────────
        "NOP" | "ORI" if ops.trim() == "r0,r0,0" => return vec![PpcLlilOp::Nop],

        // ── Load immediate ─────────────────────────────────────────────────
        "LI" => {
            if parts.len() >= 2 {
                let imm = ppc_parse_imm(parts[1]);
                return vec![PpcLlilOp::SetRegConst {
                    dest: parts[0].to_string(),
                    value: imm,
                }];
            }
        }
        "LIS" => {
            if parts.len() >= 2 {
                let imm = ppc_parse_imm(parts[1]);
                return vec![PpcLlilOp::SetRegConst {
                    dest: parts[0].to_string(),
                    value: imm << 16,
                }];
            }
        }

        // ── ALU immediate ──────────────────────────────────────────────────
        "ADDI" | "ADDIS" => {
            if parts.len() >= 3 {
                let imm = ppc_parse_imm(parts[2]);
                let shift = if m == "ADDIS" { 16 } else { 0 };
                return vec![PpcLlilOp::ArithImm {
                    dest: parts[0].to_string(),
                    lhs: parts[1].to_string(),
                    op: PpcArithOp::Add,
                    rhs: imm << shift,
                }];
            }
        }
        "ADDIC" | "ADDIC." => {
            if parts.len() >= 3 {
                let imm = ppc_parse_imm(parts[2]);
                return vec![PpcLlilOp::ArithImm {
                    dest: parts[0].to_string(),
                    lhs: parts[1].to_string(),
                    op: PpcArithOp::Add,
                    rhs: imm,
                }];
            }
        }
        "SUBFIC" => {
            if parts.len() >= 3 {
                let imm = ppc_parse_imm(parts[2]);
                return vec![PpcLlilOp::ArithImm {
                    dest: parts[0].to_string(),
                    lhs: parts[1].to_string(),
                    op: PpcArithOp::Sub,
                    rhs: imm,
                }];
            }
        }

        // ── Logical immediate ───────────────────────────────────────────────
        "ORI" | "ORIS" => {
            if parts.len() >= 3 {
                let imm = ppc_parse_imm_u(parts[2]);
                let shift = if m == "ORIS" { 16 } else { 0 };
                return vec![PpcLlilOp::ArithImm {
                    dest: parts[0].to_string(),
                    lhs: parts[1].to_string(),
                    op: PpcArithOp::Or,
                    rhs: imm.cast_signed() << shift,
                }];
            }
        }
        "ANDI." | "ANDIS." => {
            if parts.len() >= 3 {
                let imm = ppc_parse_imm_u(parts[2]);
                let shift = if m == "ANDIS." { 16 } else { 0 };
                return vec![PpcLlilOp::ArithImm {
                    dest: parts[0].to_string(),
                    lhs: parts[1].to_string(),
                    op: PpcArithOp::And,
                    rhs: imm.cast_signed() << shift,
                }];
            }
        }
        "XORI" | "XORIS" => {
            if parts.len() >= 3 {
                let imm = ppc_parse_imm_u(parts[2]);
                let shift = if m == "XORIS" { 16 } else { 0 };
                return vec![PpcLlilOp::ArithImm {
                    dest: parts[0].to_string(),
                    lhs: parts[1].to_string(),
                    op: PpcArithOp::Xor,
                    rhs: imm.cast_signed() << shift,
                }];
            }
        }

        // ── Register ALU ───────────────────────────────────────────────────
        "ADD" | "ADDC" | "ADDE" | "ADDZE" | "ADDME" => {
            if parts.len() >= 3 {
                return vec![PpcLlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: PpcArithOp::Add,
                    rhs: parts[2].into(),
                }];
            } else if parts.len() == 2 {
                return vec![PpcLlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: PpcArithOp::Add,
                    rhs: "r0".into(),
                }];
            }
        }
        "SUBF" | "SUBFC" | "SUBFE" | "SUBFZE" | "SUBFME" => {
            if parts.len() >= 3 {
                return vec![PpcLlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: PpcArithOp::Sub,
                    rhs: parts[2].into(),
                }];
            }
        }
        "AND" | "ANDC" => {
            if parts.len() >= 3 {
                return vec![PpcLlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: PpcArithOp::And,
                    rhs: parts[2].into(),
                }];
            }
        }
        "OR" | "ORC" | "NOR" => {
            if parts.len() >= 3 {
                if parts[1] == parts[2] {
                    // MR (move register pseudo)
                    return vec![PpcLlilOp::SetRegReg {
                        dest: parts[0].into(),
                        src: parts[1].into(),
                    }];
                }
                return vec![PpcLlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: PpcArithOp::Or,
                    rhs: parts[2].into(),
                }];
            }
        }
        "XOR" | "EQV" => {
            if parts.len() >= 3 {
                return vec![PpcLlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: PpcArithOp::Xor,
                    rhs: parts[2].into(),
                }];
            }
        }
        "SLW" => {
            if parts.len() >= 3 {
                return vec![PpcLlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: PpcArithOp::Shl,
                    rhs: parts[2].into(),
                }];
            }
        }
        "SRW" => {
            if parts.len() >= 3 {
                return vec![PpcLlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: PpcArithOp::Shr,
                    rhs: parts[2].into(),
                }];
            }
        }
        "SRAW" | "SRAWI" => {
            if parts.len() >= 3 {
                return vec![PpcLlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: PpcArithOp::Sar,
                    rhs: parts[2].into(),
                }];
            }
        }
        "MULLW" | "MULHW" | "MULHWU" => {
            if parts.len() >= 3 {
                return vec![PpcLlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: PpcArithOp::Mul,
                    rhs: parts[2].into(),
                }];
            }
        }
        "DIVW" | "DIVWU" => {
            if parts.len() >= 3 {
                return vec![PpcLlilOp::Arith {
                    dest: parts[0].into(),
                    lhs: parts[1].into(),
                    op: PpcArithOp::Div,
                    rhs: parts[2].into(),
                }];
            }
        }

        // ── Loads ──────────────────────────────────────────────────────────
        "LWZ" | "LWZU" | "LWA" | "LWZX" | "LWAUX" | "LFS" | "LFSU" | "LFSX" => {
            if let Some((dst, base, off)) = ppc_parse_mem(ops) {
                return vec![PpcLlilOp::Load {
                    dest: dst,
                    base,
                    offset: off,
                    size: 4,
                }];
            }
        }
        "LBZ" | "LBZU" | "LBZX" => {
            if let Some((dst, base, off)) = ppc_parse_mem(ops) {
                return vec![PpcLlilOp::Load {
                    dest: dst,
                    base,
                    offset: off,
                    size: 1,
                }];
            }
        }
        "LHZ" | "LHZU" | "LHA" | "LHAU" | "LHZX" | "LHAX" => {
            if let Some((dst, base, off)) = ppc_parse_mem(ops) {
                return vec![PpcLlilOp::Load {
                    dest: dst,
                    base,
                    offset: off,
                    size: 2,
                }];
            }
        }
        "LFD" | "LFDU" | "LFDX" => {
            if let Some((dst, base, off)) = ppc_parse_mem(ops) {
                return vec![PpcLlilOp::Load {
                    dest: dst,
                    base,
                    offset: off,
                    size: 8,
                }];
            }
        }

        // ── Stores ─────────────────────────────────────────────────────────
        "STW" | "STWU" | "STWX" | "STWUX" => {
            if let Some((src, base, off)) = ppc_parse_mem(ops) {
                return vec![PpcLlilOp::Store {
                    base,
                    offset: off,
                    src,
                    size: 4,
                }];
            }
        }
        "STB" | "STBU" | "STBX" | "STBUX" => {
            if let Some((src, base, off)) = ppc_parse_mem(ops) {
                return vec![PpcLlilOp::Store {
                    base,
                    offset: off,
                    src,
                    size: 1,
                }];
            }
        }
        "STH" | "STHU" | "STHX" | "STHUX" => {
            if let Some((src, base, off)) = ppc_parse_mem(ops) {
                return vec![PpcLlilOp::Store {
                    base,
                    offset: off,
                    src,
                    size: 2,
                }];
            }
        }
        "STFD" | "STFDU" | "STFDX" => {
            if let Some((src, base, off)) = ppc_parse_mem(ops) {
                return vec![PpcLlilOp::Store {
                    base,
                    offset: off,
                    src,
                    size: 8,
                }];
            }
        }
        "STFS" | "STFSU" | "STFSX" => {
            if let Some((src, base, off)) = ppc_parse_mem(ops) {
                return vec![PpcLlilOp::Store {
                    base,
                    offset: off,
                    src,
                    size: 4,
                }];
            }
        }

        // ── Control flow ───────────────────────────────────────────────────
        "B" | "BA" => {
            let t = ppc_parse_target(ops);
            return vec![PpcLlilOp::Jump { target: t }];
        }
        "BL" | "BLA" => {
            let t = ppc_parse_target(ops);
            return vec![
                PpcLlilOp::SetLR {
                    value: instr.address.0 + 4,
                },
                PpcLlilOp::Call { target: t },
            ];
        }
        "BCLR" | "BCLRL" => return vec![PpcLlilOp::Ret],
        "SC" => return vec![PpcLlilOp::Syscall],

        "BEQ" | "BEQL" => {
            let t = ppc_parse_target(parts.last().copied().unwrap_or("$0"));
            return vec![PpcLlilOp::CondJump {
                cond: PpcCond::Eq,
                target: t,
            }];
        }
        "BNE" | "BNEL" => {
            let t = ppc_parse_target(parts.last().copied().unwrap_or("$0"));
            return vec![PpcLlilOp::CondJump {
                cond: PpcCond::Ne,
                target: t,
            }];
        }
        "BLT" | "BLTL" => {
            let t = ppc_parse_target(parts.last().copied().unwrap_or("$0"));
            return vec![PpcLlilOp::CondJump {
                cond: PpcCond::Lt,
                target: t,
            }];
        }
        "BGT" | "BGTL" => {
            let t = ppc_parse_target(parts.last().copied().unwrap_or("$0"));
            return vec![PpcLlilOp::CondJump {
                cond: PpcCond::Gt,
                target: t,
            }];
        }
        "BLE" | "BLEL" => {
            let t = ppc_parse_target(parts.last().copied().unwrap_or("$0"));
            return vec![PpcLlilOp::CondJump {
                cond: PpcCond::Le,
                target: t,
            }];
        }
        "BGE" | "BGEL" => {
            let t = ppc_parse_target(parts.last().copied().unwrap_or("$0"));
            return vec![PpcLlilOp::CondJump {
                cond: PpcCond::Ge,
                target: t,
            }];
        }

        // ── SPR moves ──────────────────────────────────────────────────────
        "MFLR" => {
            if !parts.is_empty() {
                return vec![PpcLlilOp::SetRegReg {
                    dest: parts[0].to_string(),
                    src: "LR".to_string(),
                }];
            }
        }
        "MTLR" => {
            if !parts.is_empty() {
                return vec![PpcLlilOp::SetRegReg {
                    dest: "LR".to_string(),
                    src: parts[0].to_string(),
                }];
            }
        }
        "MFCTR" => {
            if !parts.is_empty() {
                return vec![PpcLlilOp::SetRegReg {
                    dest: parts[0].to_string(),
                    src: "CTR".to_string(),
                }];
            }
        }
        "MTCTR"
            if !parts.is_empty() => {
                return vec![PpcLlilOp::SetRegReg {
                    dest: "CTR".to_string(),
                    src: parts[0].to_string(),
                }];
            }

        _ => {}
    }
    vec![PpcLlilOp::Unimpl {
        mnemonic: m.to_string(),
    }]
}

fn ppc_parse_imm(s: &str) -> i64 {
    s.trim().parse::<i64>().unwrap_or(0)
}

fn ppc_parse_imm_u(s: &str) -> u64 {
    let s = s.trim();
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).map_or_else(
        || s.parse::<u64>().unwrap_or(0),
        |h| u64::from_str_radix(h, 16).unwrap_or(0),
    )
}

fn ppc_parse_target(s: &str) -> u64 {
    let s = s.trim().trim_start_matches('$');
    u64::from_str_radix(s, 16).unwrap_or(0)
}

/// Parse `reg,imm(base)` or `reg,base` PPC memory operand.
fn ppc_parse_mem(ops: &str) -> Option<(String, String, i64)> {
    let comma = ops.find(',')?;
    let reg = ops[..comma].trim().to_string();
    let rest = ops[comma + 1..].trim();
    let lparen = rest.find('(')?;
    let rparen = rest.find(')')?;
    let off = rest[..lparen].trim().parse::<i64>().unwrap_or(0);
    let base = rest[lparen + 1..rparen].trim().to_string();
    Some((reg, base, off))
}

// =============================================================================
// PowerPC AltiVec / VMX instruction table
// =============================================================================

/// An `AltiVec` (VMX) instruction entry.
#[derive(Debug, Clone, Copy)]
pub struct AltivecInstrV2 {
    pub mnemonic: &'static str,
    pub description: &'static str,
}

/// A subset of `AltiVec` vector instructions.
pub static ALTIVEC_INSTRS_V2: &[AltivecInstrV2] = &[
    AltivecInstrV2 {
        mnemonic: "vaddfp",
        description: "Add Floating-Point (vector)",
    },
    AltivecInstrV2 {
        mnemonic: "vsubfp",
        description: "Subtract Floating-Point (vector)",
    },
    AltivecInstrV2 {
        mnemonic: "vmaddfp",
        description: "Multiply-Add Floating-Point (vector)",
    },
    AltivecInstrV2 {
        mnemonic: "vnmsubfp",
        description: "Negative Multiply-Subtract Floating-Point",
    },
    AltivecInstrV2 {
        mnemonic: "vaddubm",
        description: "Add Unsigned Byte Modulo (vector)",
    },
    AltivecInstrV2 {
        mnemonic: "vadduhm",
        description: "Add Unsigned Halfword Modulo (vector)",
    },
    AltivecInstrV2 {
        mnemonic: "vadduwm",
        description: "Add Unsigned Word Modulo (vector)",
    },
    AltivecInstrV2 {
        mnemonic: "vsububm",
        description: "Subtract Unsigned Byte Modulo (vector)",
    },
    AltivecInstrV2 {
        mnemonic: "vsubuhm",
        description: "Subtract Unsigned Halfword Modulo (vector)",
    },
    AltivecInstrV2 {
        mnemonic: "vsubuwm",
        description: "Subtract Unsigned Word Modulo (vector)",
    },
    AltivecInstrV2 {
        mnemonic: "vmuloub",
        description: "Multiply Odd Unsigned Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vmulouh",
        description: "Multiply Odd Unsigned Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vmuleub",
        description: "Multiply Even Unsigned Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vmuleuh",
        description: "Multiply Even Unsigned Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vmaxub",
        description: "Maximum Unsigned Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vmaxuh",
        description: "Maximum Unsigned Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vmaxuw",
        description: "Maximum Unsigned Word",
    },
    AltivecInstrV2 {
        mnemonic: "vmaxsb",
        description: "Maximum Signed Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vmaxsh",
        description: "Maximum Signed Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vmaxsw",
        description: "Maximum Signed Word",
    },
    AltivecInstrV2 {
        mnemonic: "vminub",
        description: "Minimum Unsigned Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vminuh",
        description: "Minimum Unsigned Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vminuw",
        description: "Minimum Unsigned Word",
    },
    AltivecInstrV2 {
        mnemonic: "vminsb",
        description: "Minimum Signed Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vminsh",
        description: "Minimum Signed Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vminsw",
        description: "Minimum Signed Word",
    },
    AltivecInstrV2 {
        mnemonic: "vand",
        description: "Logical AND (vector)",
    },
    AltivecInstrV2 {
        mnemonic: "vandc",
        description: "Logical AND with Complement (vector)",
    },
    AltivecInstrV2 {
        mnemonic: "vor",
        description: "Logical OR (vector)",
    },
    AltivecInstrV2 {
        mnemonic: "vnor",
        description: "Logical NOR (vector)",
    },
    AltivecInstrV2 {
        mnemonic: "vxor",
        description: "Logical XOR (vector)",
    },
    AltivecInstrV2 {
        mnemonic: "lvebx",
        description: "Load Vector Element Byte Indexed",
    },
    AltivecInstrV2 {
        mnemonic: "lvehx",
        description: "Load Vector Element Halfword Indexed",
    },
    AltivecInstrV2 {
        mnemonic: "lvewx",
        description: "Load Vector Element Word Indexed",
    },
    AltivecInstrV2 {
        mnemonic: "lvsl",
        description: "Load Vector for Shift Left",
    },
    AltivecInstrV2 {
        mnemonic: "lvsr",
        description: "Load Vector for Shift Right",
    },
    AltivecInstrV2 {
        mnemonic: "lvx",
        description: "Load Vector Indexed",
    },
    AltivecInstrV2 {
        mnemonic: "lvxl",
        description: "Load Vector Indexed Last",
    },
    AltivecInstrV2 {
        mnemonic: "stvebx",
        description: "Store Vector Element Byte Indexed",
    },
    AltivecInstrV2 {
        mnemonic: "stvehx",
        description: "Store Vector Element Halfword Indexed",
    },
    AltivecInstrV2 {
        mnemonic: "stvewx",
        description: "Store Vector Element Word Indexed",
    },
    AltivecInstrV2 {
        mnemonic: "stvx",
        description: "Store Vector Indexed",
    },
    AltivecInstrV2 {
        mnemonic: "stvxl",
        description: "Store Vector Indexed Last",
    },
    AltivecInstrV2 {
        mnemonic: "vpkuhum",
        description: "Pack Unsigned Halfword Unsigned Modulo",
    },
    AltivecInstrV2 {
        mnemonic: "vpkuwum",
        description: "Pack Unsigned Word Unsigned Modulo",
    },
    AltivecInstrV2 {
        mnemonic: "vpkshss",
        description: "Pack Signed Halfword Signed Saturate",
    },
    AltivecInstrV2 {
        mnemonic: "vpkswss",
        description: "Pack Signed Word Signed Saturate",
    },
    AltivecInstrV2 {
        mnemonic: "vpkuhus",
        description: "Pack Unsigned Halfword Unsigned Saturate",
    },
    AltivecInstrV2 {
        mnemonic: "vpkuwus",
        description: "Pack Unsigned Word Unsigned Saturate",
    },
    AltivecInstrV2 {
        mnemonic: "vupkhsb",
        description: "Unpack High Signed Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vupkhsh",
        description: "Unpack High Signed Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vupklsb",
        description: "Unpack Low Signed Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vupklsh",
        description: "Unpack Low Signed Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vmrghb",
        description: "Merge High Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vmrghh",
        description: "Merge High Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vmrghw",
        description: "Merge High Word",
    },
    AltivecInstrV2 {
        mnemonic: "vmrglb",
        description: "Merge Low Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vmrglh",
        description: "Merge Low Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vmrglw",
        description: "Merge Low Word",
    },
    AltivecInstrV2 {
        mnemonic: "vspltb",
        description: "Splat Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vsplth",
        description: "Splat Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vspltw",
        description: "Splat Word",
    },
    AltivecInstrV2 {
        mnemonic: "vspltisb",
        description: "Splat Immediate Signed Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vspltish",
        description: "Splat Immediate Signed Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vspltisw",
        description: "Splat Immediate Signed Word",
    },
    AltivecInstrV2 {
        mnemonic: "vperm",
        description: "Vector Permute",
    },
    AltivecInstrV2 {
        mnemonic: "vsel",
        description: "Vector Conditional Select",
    },
    AltivecInstrV2 {
        mnemonic: "vslo",
        description: "Vector Shift Left by Octet",
    },
    AltivecInstrV2 {
        mnemonic: "vsro",
        description: "Vector Shift Right by Octet",
    },
    AltivecInstrV2 {
        mnemonic: "vsl",
        description: "Vector Shift Left",
    },
    AltivecInstrV2 {
        mnemonic: "vsr",
        description: "Vector Shift Right",
    },
    AltivecInstrV2 {
        mnemonic: "vslab",
        description: "Vector Shift Left Algebraic Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vslah",
        description: "Vector Shift Left Algebraic Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vslaw",
        description: "Vector Shift Left Algebraic Word",
    },
    AltivecInstrV2 {
        mnemonic: "vsrab",
        description: "Vector Shift Right Algebraic Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vsrah",
        description: "Vector Shift Right Algebraic Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vsraw",
        description: "Vector Shift Right Algebraic Word",
    },
    AltivecInstrV2 {
        mnemonic: "vsrb",
        description: "Vector Shift Right Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vsrh",
        description: "Vector Shift Right Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vsrw",
        description: "Vector Shift Right Word",
    },
    AltivecInstrV2 {
        mnemonic: "vcfux",
        description: "Convert from Unsigned Fixed-Point Word",
    },
    AltivecInstrV2 {
        mnemonic: "vcfsx",
        description: "Convert from Signed Fixed-Point Word",
    },
    AltivecInstrV2 {
        mnemonic: "vctuxs",
        description: "Convert to Unsigned Fixed-Point Word Saturate",
    },
    AltivecInstrV2 {
        mnemonic: "vctsxs",
        description: "Convert to Signed Fixed-Point Word Saturate",
    },
    AltivecInstrV2 {
        mnemonic: "vrfim",
        description: "Round to Floating-Point Integer toward Minus Infinity",
    },
    AltivecInstrV2 {
        mnemonic: "vrfin",
        description: "Round to Floating-Point Integer Nearest",
    },
    AltivecInstrV2 {
        mnemonic: "vrfip",
        description: "Round to Floating-Point Integer toward Plus Infinity",
    },
    AltivecInstrV2 {
        mnemonic: "vrfiz",
        description: "Round to Floating-Point Integer toward Zero",
    },
    AltivecInstrV2 {
        mnemonic: "vcmpbfp",
        description: "Compare Bounds Floating-Point",
    },
    AltivecInstrV2 {
        mnemonic: "vcmpeqfp",
        description: "Compare Equal Floating-Point",
    },
    AltivecInstrV2 {
        mnemonic: "vcmpgefp",
        description: "Compare Greater Than or Equal Floating-Point",
    },
    AltivecInstrV2 {
        mnemonic: "vcmpgtfp",
        description: "Compare Greater Than Floating-Point",
    },
    AltivecInstrV2 {
        mnemonic: "vcmpequb",
        description: "Compare Equal Unsigned Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vcmpequh",
        description: "Compare Equal Unsigned Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vcmpequw",
        description: "Compare Equal Unsigned Word",
    },
    AltivecInstrV2 {
        mnemonic: "vcmpgtsb",
        description: "Compare Greater Than Signed Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vcmpgtsh",
        description: "Compare Greater Than Signed Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vcmpgtsw",
        description: "Compare Greater Than Signed Word",
    },
    AltivecInstrV2 {
        mnemonic: "vcmpgtub",
        description: "Compare Greater Than Unsigned Byte",
    },
    AltivecInstrV2 {
        mnemonic: "vcmpgtuh",
        description: "Compare Greater Than Unsigned Halfword",
    },
    AltivecInstrV2 {
        mnemonic: "vcmpgtuw",
        description: "Compare Greater Than Unsigned Word",
    },
    AltivecInstrV2 {
        mnemonic: "mtvscr",
        description: "Move to Vector Status and Control Register",
    },
    AltivecInstrV2 {
        mnemonic: "mfvscr",
        description: "Move from Vector Status and Control Register",
    },
    AltivecInstrV2 {
        mnemonic: "dss",
        description: "Data Stream Stop",
    },
    AltivecInstrV2 {
        mnemonic: "dssall",
        description: "Data Stream Stop All",
    },
    AltivecInstrV2 {
        mnemonic: "dst",
        description: "Data Stream Touch",
    },
    AltivecInstrV2 {
        mnemonic: "dstt",
        description: "Data Stream Touch Transient",
    },
    AltivecInstrV2 {
        mnemonic: "dstst",
        description: "Data Stream Touch for Store",
    },
    AltivecInstrV2 {
        mnemonic: "dststt",
        description: "Data Stream Touch for Store Transient",
    },
];

/// Look up an `AltiVec` instruction by mnemonic.
#[must_use]
pub fn lookup_altivec_v2(mnemonic: &str) -> Option<&'static AltivecInstrV2> {
    ALTIVEC_INSTRS_V2.iter().find(|e| e.mnemonic == mnemonic)
}

// =============================================================================
// PowerPC condition register ops
// =============================================================================

/// A CR (condition register) instruction entry.
#[derive(Debug, Clone, Copy)]
pub struct CrInstr {
    pub mnemonic: &'static str,
    pub description: &'static str,
}

pub static PPC_CR_INSTRS: &[CrInstr] = &[
    CrInstr {
        mnemonic: "crand",
        description: "CR AND",
    },
    CrInstr {
        mnemonic: "crandc",
        description: "CR AND with Complement",
    },
    CrInstr {
        mnemonic: "crclr",
        description: "CR Clear Bit (pseudo: crxor BT,BT,BT)",
    },
    CrInstr {
        mnemonic: "creqv",
        description: "CR Equivalent",
    },
    CrInstr {
        mnemonic: "crnand",
        description: "CR NAND",
    },
    CrInstr {
        mnemonic: "crnor",
        description: "CR NOR",
    },
    CrInstr {
        mnemonic: "cror",
        description: "CR OR",
    },
    CrInstr {
        mnemonic: "crorc",
        description: "CR OR with Complement",
    },
    CrInstr {
        mnemonic: "crset",
        description: "CR Set Bit (pseudo: creqv BT,BT,BT)",
    },
    CrInstr {
        mnemonic: "crxor",
        description: "CR XOR",
    },
    CrInstr {
        mnemonic: "mcrf",
        description: "Move Condition Register Field",
    },
    CrInstr {
        mnemonic: "mcrxr",
        description: "Move to Condition Register from XER",
    },
    CrInstr {
        mnemonic: "mfcr",
        description: "Move from Condition Register",
    },
    CrInstr {
        mnemonic: "mtcrf",
        description: "Move to Condition Register Fields",
    },
];

// =============================================================================
// Tests for LLIL lifter, AltiVec table, CR ops
// =============================================================================

#[cfg(test)]
mod tests_llil_altivec {
    use super::*;

    fn arch() -> PpcArch {
        PpcArch::default()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    // ── LLIL LI ───────────────────────────────────────────────────────────
    #[test]
    fn test_llil_li() {
        let i = arch()
            .disassemble(addr(0), &encode_li(3, 42).to_be_bytes())
            .unwrap();
        let ops = ppc_lift(&i);
        assert!(matches!(ops[0], PpcLlilOp::SetRegConst { value: 42, .. }));
    }

    // ── LLIL LIS ──────────────────────────────────────────────────────────
    #[test]
    fn test_llil_lis() {
        let i = arch()
            .disassemble(addr(0), &encode_lis(3, 1).to_be_bytes())
            .unwrap();
        let ops = ppc_lift(&i);
        assert!(matches!(
            ops[0],
            PpcLlilOp::SetRegConst { value: 0x10000, .. }
        ));
    }

    // ── LLIL ADDI ─────────────────────────────────────────────────────────
    #[test]
    fn test_llil_addi() {
        let i = arch()
            .disassemble(addr(0), &encode_addi(3, 3, 4).to_be_bytes())
            .unwrap();
        let ops = ppc_lift(&i);
        assert!(matches!(
            ops[0],
            PpcLlilOp::ArithImm {
                op: PpcArithOp::Add,
                rhs: 4,
                ..
            }
        ));
    }

    // ── LLIL LWZ ──────────────────────────────────────────────────────────
    #[test]
    fn test_llil_lwz() {
        let i = arch()
            .disassemble(addr(0), &encode_lwz(3, 1, 16).to_be_bytes())
            .unwrap();
        let ops = ppc_lift(&i);
        assert!(matches!(ops[0], PpcLlilOp::Load { size: 4, .. }));
    }

    // ── LLIL STW ──────────────────────────────────────────────────────────
    #[test]
    fn test_llil_stw() {
        let i = arch()
            .disassemble(addr(0), &encode_stw(3, 1, 16).to_be_bytes())
            .unwrap();
        let ops = ppc_lift(&i);
        assert!(matches!(ops[0], PpcLlilOp::Store { size: 4, .. }));
    }

    // ── LLIL BL ───────────────────────────────────────────────────────────
    #[test]
    fn test_llil_bl() {
        let i = arch()
            .disassemble(addr(0x1000), &encode_bl(8).to_be_bytes())
            .unwrap();
        let ops = ppc_lift(&i);
        assert!(ops.iter().any(|o| matches!(o, PpcLlilOp::Call { .. })));
        assert!(
            ops.iter()
                .any(|o| matches!(o, PpcLlilOp::SetLR { value: 0x1004, .. }))
        );
    }

    // ── LLIL BCLR → Ret ───────────────────────────────────────────────────
    #[test]
    fn test_llil_bclr_ret() {
        let i = arch()
            .disassemble(addr(0), &encode_bclr(false).to_be_bytes())
            .unwrap();
        let ops = ppc_lift(&i);
        assert_eq!(ops[0], PpcLlilOp::Ret);
    }

    // ── LLIL MFLR ─────────────────────────────────────────────────────────
    #[test]
    fn test_llil_mflr() {
        let i = arch()
            .disassemble(addr(0), &encode_mfspr(0, 8).to_be_bytes())
            .unwrap();
        let ops = ppc_lift(&i);
        assert!(matches!(&ops[0], PpcLlilOp::SetRegReg { src, .. } if src == "LR"));
    }

    // ── LLIL MTLR ─────────────────────────────────────────────────────────
    #[test]
    fn test_llil_mtlr() {
        let i = arch()
            .disassemble(addr(0), &encode_mtspr(8, 0).to_be_bytes())
            .unwrap();
        let ops = ppc_lift(&i);
        assert!(matches!(&ops[0], PpcLlilOp::SetRegReg { dest, .. } if dest == "LR"));
    }

    // ── AltiVec table ─────────────────────────────────────────────────────
    #[test]
    fn test_altivec_table() {
        assert!(!ALTIVEC_INSTRS.is_empty());
        let e = lookup_altivec_v2("vaddfp").unwrap();
        assert!(e.description.contains("Floating-Point"));
    }

    // ── AltiVec lookup missing ────────────────────────────────────────────
    #[test]
    fn test_altivec_missing() {
        assert!(lookup_altivec("nonexistent").is_none());
    }

    // ── CR instructions table ─────────────────────────────────────────────
    #[test]
    fn test_cr_instrs_table() {
        assert!(!PPC_CR_INSTRS.is_empty());
        assert!(PPC_CR_INSTRS.iter().any(|e| e.mnemonic == "crand"));
    }

    // ── PPC_REG_ROLES ─────────────────────────────────────────────────────
    #[test]
    fn test_ppc_reg_roles_complete() {
        assert_eq!(PPC_REG_ROLES.len(), 32);
        assert!(!PPC_REG_ROLES[1].caller_saved); // r1 = SP, callee-saved
    }

    // ── ppc_format_with_addr ──────────────────────────────────────────────
    #[test]
    fn test_ppc_format_with_addr() {
        let i = arch()
            .disassemble(addr(0x4000), &encode_li(3, 1).to_be_bytes())
            .unwrap();
        let s = ppc_format_with_addr(&i);
        assert!(s.contains("00004000"));
        assert!(s.contains("LI"));
    }

    // ── ppc_format no-operand ─────────────────────────────────────────────
    #[test]
    fn test_ppc_format_no_ops() {
        let i = arch()
            .disassemble(addr(0), &encode_bclr(false).to_be_bytes())
            .unwrap();
        let s = ppc_format(&i);
        assert_eq!(s, "BCLR");
    }
}

// =============================================================================
// PowerPC memory map (classical BAT/segment layout)
// =============================================================================

/// Describes one segment or BAT-mapped region.
#[derive(Debug, Clone)]
pub struct PpcMemRegion {
    pub name: &'static str,
    pub start: u32,
    pub size: u32,
    pub description: &'static str,
}

/// Common PowerPC memory regions for embedded and game-console targets.
pub static PPC_MEM_REGIONS: &[PpcMemRegion] = &[
    PpcMemRegion {
        name: "MEM1",
        start: 0x8000_0000,
        size: 0x0180_0000,
        description: "Main RAM (cached), GameCube/Wii",
    },
    PpcMemRegion {
        name: "MEM2",
        start: 0x9000_0000,
        size: 0x0400_0000,
        description: "Auxiliary RAM (cached), Wii",
    },
    PpcMemRegion {
        name: "MEM1_UC",
        start: 0xC000_0000,
        size: 0x0180_0000,
        description: "Main RAM uncached mirror",
    },
    PpcMemRegion {
        name: "MEM2_UC",
        start: 0xD000_0000,
        size: 0x0400_0000,
        description: "Auxiliary RAM uncached mirror",
    },
    PpcMemRegion {
        name: "HW_Regs",
        start: 0xCC00_0000,
        size: 0x0200_0000,
        description: "Hardware registers",
    },
    PpcMemRegion {
        name: "IPL_ROM",
        start: 0xFFF0_0000,
        size: 0x0010_0000,
        description: "Boot ROM",
    },
    PpcMemRegion {
        name: "Kernel",
        start: 0x8000_0000,
        size: 0x0040_0000,
        description: "Linux/RTOS kernel text (typical)",
    },
];

// =============================================================================
// PowerPC instruction histogram
// =============================================================================

/// Mnemonic frequency histogram for PPC.
#[derive(Debug, Default, Clone)]
pub struct PpcHistogram {
    pub counts: std::collections::BTreeMap<String, usize>,
}

impl PpcHistogram {
    /// Build from bytes.
    #[must_use]
    pub fn build(arch: &PpcArch, bytes: &[u8], base: Address) -> Self {
        let mut h = Self::default();
        for i in PpcLinearDisassembler::new(arch, bytes, base).flatten() {
            *h.counts.entry(i.mnemonic.clone()).or_insert(0) += 1;
        }
        h
    }

    #[must_use]
    pub fn count(&self, mn: &str) -> usize {
        self.counts.get(mn).copied().unwrap_or(0)
    }
    #[must_use]
    pub fn total(&self) -> usize {
        self.counts.values().sum()
    }

    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(&str, usize)> {
        let mut v: Vec<(&str, usize)> = self.counts.iter().map(|(k, &v)| (k.as_str(), v)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }
}

// =============================================================================
// PowerPC function call graph
// =============================================================================

/// An edge in the PPC call graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PpcCallEdge {
    pub caller: u64,
    pub callee: u64,
}

/// Build a call graph from bytes.
#[must_use]
pub fn ppc_build_call_graph(arch: &PpcArch, bytes: &[u8], base: Address) -> Vec<PpcCallEdge> {
    let mut edges = Vec::new();
    for result in PpcLinearDisassembler::new(arch, bytes, base) {
        if let Ok(instr) = result && instr.flags.contains(InstrFlags::CALL) {
            let branches = arch.get_branches(&instr);
            for br in branches {
                if let Some(t) = br.target {
                    edges.push(PpcCallEdge {
                        caller: instr.address.as_u64(),
                        callee: t,
                    });
                }
            }
        }
    }
    edges.sort();
    edges.dedup();
    edges
}

// =============================================================================
// PowerPC disassembly validator
// =============================================================================

/// Heuristic: is this 32-bit word a plausible PPC instruction?
#[must_use]
pub const fn is_valid_ppc_word(word: u32) -> bool {
    let opcd = word >> 26;
    // Opcodes that are completely unassigned in PPC32
    !matches!(
        opcd,
        1 | 4 | 5 | 6 | 9 | 22 | 30 | 56 | 57 | 58 | 60 | 61 | 62
    )
}

// =============================================================================
// Tests for histogram, call graph, and misc
// =============================================================================

#[cfg(test)]
mod tests_ppc_misc {
    use super::*;

    fn arch() -> PpcArch {
        PpcArch::default()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    // ── PpcHistogram ──────────────────────────────────────────────────────
    #[test]
    fn test_ppc_histogram() {
        let code: Vec<u8> = [
            encode_li(3, 1).to_be_bytes().to_vec(),
            encode_li(3, 2).to_be_bytes().to_vec(),
            encode_stw(3, 1, 0).to_be_bytes().to_vec(),
        ]
        .concat();
        let h = PpcHistogram::build(&arch(), &code, addr(0));
        assert_eq!(h.count("LI"), 2);
        assert_eq!(h.count("STW"), 1);
        assert_eq!(h.total(), 3);
    }

    // ── top_n ─────────────────────────────────────────────────────────────
    #[test]
    fn test_ppc_histogram_top() {
        let code: Vec<u8> = [
            encode_lwz(3, 1, 0).to_be_bytes().to_vec(),
            encode_lwz(4, 1, 4).to_be_bytes().to_vec(),
            encode_lwz(5, 1, 8).to_be_bytes().to_vec(),
            encode_stw(3, 1, 0).to_be_bytes().to_vec(),
        ]
        .concat();
        let h = PpcHistogram::build(&arch(), &code, addr(0));
        let top = h.top_n(1);
        assert_eq!(top[0].0, "LWZ");
        assert_eq!(top[0].1, 3);
    }

    // ── call graph ────────────────────────────────────────────────────────
    #[test]
    fn test_ppc_call_graph() {
        let code: Vec<u8> = [
            encode_bl(8).to_be_bytes().to_vec(),
            encode_bl(16).to_be_bytes().to_vec(),
        ]
        .concat();
        let edges = ppc_build_call_graph(&arch(), &code, addr(0x1000));
        assert_eq!(edges.len(), 2);
    }

    // ── is_valid_ppc_word ─────────────────────────────────────────────────
    #[test]
    fn test_is_valid_ppc() {
        // NOP = ORI r0,r0,0 = 0x60000000 (opcode 24)
        assert!(is_valid_ppc_word(0x6000_0000));
        // B = 0x48000000 (opcode 18)
        assert!(is_valid_ppc_word(0x4800_0000));
        // Opcode 1 is reserved
        assert!(!is_valid_ppc_word(0x0400_0000));
    }

    // ── PPC_MEM_REGIONS table ─────────────────────────────────────────────
    #[test]
    fn test_ppc_mem_regions() {
        assert!(!PPC_MEM_REGIONS.is_empty());
        let mem1 = PPC_MEM_REGIONS.iter().find(|r| r.name == "MEM1").unwrap();
        assert_eq!(mem1.start, 0x8000_0000);
    }

    // ── ALTIVEC_INSTRS coverage ───────────────────────────────────────────
    #[test]
    fn test_altivec_coverage() {
        // Should have load/store, arithmetic, compare, pack/unpack
        assert!(ALTIVEC_INSTRS.iter().any(|e| e.mnemonic == "lvx"));
        assert!(ALTIVEC_INSTRS.iter().any(|e| e.mnemonic == "stvx"));
        assert!(ALTIVEC_INSTRS.iter().any(|e| e.mnemonic == "vcmpequw"));
        assert!(ALTIVEC_INSTRS.iter().any(|e| e.mnemonic == "vpkuhum"));
    }

    // ── PPC LLIL SC (syscall) ─────────────────────────────────────────────
    #[test]
    fn test_llil_sc() {
        let i = arch()
            .disassemble(addr(0), &[0x44, 0x00, 0x00, 0x02])
            .unwrap();
        let ops = ppc_lift(&i);
        assert_eq!(ops[0], PpcLlilOp::Syscall);
    }

    // ── PPC LLIL B ────────────────────────────────────────────────────────
    #[test]
    fn test_llil_b() {
        let i = arch()
            .disassemble(addr(0x1000), &encode_b(0x100, false).to_be_bytes())
            .unwrap();
        let ops = ppc_lift(&i);
        assert!(matches!(ops[0], PpcLlilOp::Jump { .. }));
    }

    // ── PPC LLIL OR (MR pseudo) ───────────────────────────────────────────
    #[test]
    fn test_llil_mr() {
        // OR r4,r3,r3 = MR r4,r3
        let i = arch()
            .disassemble(addr(0), &[0x7C, 0x64, 0x1B, 0x78])
            .unwrap();
        let ops = ppc_lift(&i);
        // Should detect MR pattern
        assert!(matches!(
            ops[0],
            PpcLlilOp::SetRegReg { .. } | PpcLlilOp::Arith { .. }
        ));
    }

    // ── PPC LLIL MFCTR/MTCTR ─────────────────────────────────────────────
    #[test]
    fn test_llil_mfctr_mtctr() {
        // MFCTR r0
        let mfctr = arch()
            .disassemble(addr(0), &[0x7C, 0x09, 0x02, 0xA6])
            .unwrap();
        let ops = ppc_lift(&mfctr);
        assert!(matches!(&ops[0], PpcLlilOp::SetRegReg { src, .. } if src == "CTR"));
        // MTCTR r0
        let write_ctr = arch()
            .disassemble(addr(0), &[0x7C, 0x09, 0x03, 0xA6])
            .unwrap();
        let ops2 = ppc_lift(&write_ctr);
        assert!(matches!(&ops2[0], PpcLlilOp::SetRegReg { dest, .. } if dest == "CTR"));
    }

    // ── PPC LLIL SUBFIC ───────────────────────────────────────────────────
    #[test]
    fn test_llil_subfic() {
        // SUBFIC r3,r3,0 = 0x20630000
        let i = arch()
            .disassemble(addr(0), &[0x20, 0x63, 0x00, 0x00])
            .unwrap();
        let ops = ppc_lift(&i);
        assert!(matches!(
            ops[0],
            PpcLlilOp::ArithImm {
                op: PpcArithOp::Sub,
                ..
            }
        ));
    }

    // ── PpcHistogram empty ────────────────────────────────────────────────
    #[test]
    fn test_ppc_histogram_empty() {
        let h = PpcHistogram::build(&arch(), &[], addr(0));
        assert_eq!(h.total(), 0);
        assert!(h.top_n(3).is_empty());
    }

    // ── is_valid_ppc all common opcodes ───────────────────────────────────
    #[test]
    fn test_is_valid_all_common() {
        for opcd in [
            7u32, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 24, 25, 26, 27, 28, 29, 31,
            32, 33, 34, 36, 40, 44, 46, 48, 50, 52, 54, 63,
        ] {
            let w = opcd << 26;
            assert!(is_valid_ppc_word(w), "opcode {opcd}");
        }
    }
}

// =============================================================================
// PowerPC prologue / epilogue patterns
// =============================================================================

/// Common PPC prologue byte patterns (big-endian, with masks).
pub static PPC_PROLOGUE_PATTERNS: &[(&str, u32, u32)] = &[
    // MFLR r0: 0x7C0802A6
    ("MFLR r0", 0xFFFF_FFFF, 0x7C08_02A6),
    // STW r0, 4(r1): 0x90010004
    ("STW r0,4(r1)", 0xFFFF_FFFF, 0x9001_0004),
    // STWU r1,-N(r1): upper bytes 0x9421
    ("STWU r1,-N(r1)", 0xFFFF_0000, 0x9421_0000),
    // LIS r2,%hi(TOC): upper 0x3C40
    ("LIS r2,..TOC", 0xFFFF_0000, 0x3C40_0000),
    // ADDIS r2,r2,N (TOC setup): upper 0x3842
    ("ADDIS r2,r2,N", 0xFFFF_0000, 0x3842_0000),
];

/// Check if bytes match a known PPC prologue pattern (big-endian).
#[must_use]
pub fn detect_ppc_preamble(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 4 {
        return None;
    }
    let word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    for &(name, mask, value) in PPC_PROLOGUE_PATTERNS {
        if word & mask == value {
            return Some(name);
        }
    }
    None
}

// =============================================================================
// PowerPC register dependency analysis
// =============================================================================

/// A read-after-write dependency between PPC instructions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PpcRegDep {
    pub def_idx: usize,
    pub use_idx: usize,
    pub reg: String,
}

/// Find RAW register dependencies in a PPC instruction sequence.
#[must_use]
pub fn ppc_find_dependencies(instrs: &[Instruction]) -> Vec<PpcRegDep> {
    let mut deps = Vec::new();
    let mut last_def: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for (idx, instr) in instrs.iter().enumerate() {
        let parts: Vec<&str> = instr.operands.split(',').map(str::trim).collect();
        let m = instr.mnemonic.as_str();

        // Source registers (simplified)
        let reads: Vec<String> = match m {
            "ADD" | "SUBF" | "AND" | "OR" | "XOR" | "NOR" | "SLW" | "SRW" | "SRAW" | "MULLW"
            | "DIVW" | "DIVWU" => parts
                .iter()
                .skip(1)
                .filter(|s| s.starts_with('r'))
                .map(ToString::to_string)
                .collect(),
            "ADDI" | "ADDIS" | "ADDIC" | "ORI" | "ORIS" | "ANDI." | "ANDIS." | "XORI" | "XORIS"
            | "SUBFIC" => parts
                .iter()
                .skip(1)
                .take(1)
                .filter(|s| s.starts_with('r'))
                .map(ToString::to_string)
                .collect(),
            "LWZ" | "LBZ" | "LHZ" | "LHA" | "LFD" | "LFS" => {
                // base register from offset(base)
                if let Some((_, base, _)) = ppc_parse_mem(&instr.operands) {
                    vec![base]
                } else {
                    vec![]
                }
            }
            "STW" | "STB" | "STH" | "STFD" | "STFS" => {
                if let Some((src, base, _)) = ppc_parse_mem(&instr.operands) {
                    vec![src, base]
                } else {
                    vec![]
                }
            }
            _ => vec![],
        };

        for reg in &reads {
            if let Some(&def_i) = last_def.get(reg) {
                deps.push(PpcRegDep {
                    def_idx: def_i,
                    use_idx: idx,
                    reg: reg.clone(),
                });
            }
        }

        // Destination register
        let write = parts
            .first()
            .filter(|s| s.starts_with('r'))
            .map(ToString::to_string);
        if let Some(r) = write {
            last_def.insert(r, idx);
        }
    }
    deps
}

// =============================================================================
// Final tests for prologue detection and dependencies
// =============================================================================

#[cfg(test)]
mod tests_ppc_final {
    use super::*;

    fn arch() -> PpcArch {
        PpcArch::default()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    // ── detect_ppc_preamble MFLR ──────────────────────────────────────────
    #[test]
    fn test_ppc_preamble_mflr() {
        let bytes = [0x7Cu8, 0x08, 0x02, 0xA6]; // MFLR r0
        assert_eq!(detect_ppc_preamble(&bytes), Some("MFLR r0"));
    }

    // ── detect_ppc_preamble STWU ──────────────────────────────────────────
    #[test]
    fn test_ppc_preamble_stwu() {
        let bytes = [0x94u8, 0x21, 0xFF, 0xE0]; // STWU r1,-32(r1)
        assert_eq!(detect_ppc_preamble(&bytes), Some("STWU r1,-N(r1)"));
    }

    // ── detect_ppc_preamble none ──────────────────────────────────────────
    #[test]
    fn test_ppc_preamble_none() {
        let bytes = [0x60u8, 0x00, 0x00, 0x00]; // NOP
        assert_eq!(detect_ppc_preamble(&bytes), None);
    }

    // ── ppc_find_dependencies ─────────────────────────────────────────────
    #[test]
    fn test_ppc_deps() {
        let code: Vec<u8> = [
            encode_lwz(3, 1, 0).to_be_bytes().to_vec(), // LWZ r3,0(r1) → writes r3
            encode_addi(4, 3, 1).to_be_bytes().to_vec(), // ADDI r4,r3,1 → reads r3
        ]
        .concat();
        let a = arch();
        let instrs: Vec<_> = PpcLinearDisassembler::new(&a, &code, addr(0))
            .filter_map(Result::ok)
            .collect();
        let deps = ppc_find_dependencies(&instrs);
        assert!(!deps.is_empty());
        assert!(deps.iter().any(|d| d.def_idx == 0 && d.use_idx == 1));
    }

    // ── PPC_PROLOGUE_PATTERNS table ───────────────────────────────────────
    #[test]
    fn test_ppc_prologue_patterns_table() {
        assert!(!PPC_PROLOGUE_PATTERNS.is_empty());
        assert!(
            PPC_PROLOGUE_PATTERNS
                .iter()
                .any(|(n, _, _)| n.contains("MFLR"))
        );
    }

    // ── LLIL ADDI then STW sequence ───────────────────────────────────────
    #[test]
    fn test_llil_addi_stw_sequence() {
        let code: Vec<u8> = [
            encode_addi(3, 3, 4).to_be_bytes().to_vec(),
            encode_stw(3, 1, 0).to_be_bytes().to_vec(),
        ]
        .concat();
        let a = arch();
        let instrs: Vec<_> = PpcLinearDisassembler::new(&a, &code, addr(0))
            .filter_map(Result::ok)
            .collect();
        let lifted: Vec<Vec<PpcLlilOp>> = instrs.iter().map(ppc_lift).collect();
        assert!(matches!(
            lifted[0][0],
            PpcLlilOp::ArithImm {
                op: PpcArithOp::Add,
                ..
            }
        ));
        assert!(matches!(lifted[1][0], PpcLlilOp::Store { .. }));
    }

    // ── PPC64 LLIL ────────────────────────────────────────────────────────
    #[test]
    fn test_ppc64_llil_li() {
        let a = PpcArch::new_64();
        let i = a
            .disassemble(addr(0), &encode_li(3, 99).to_be_bytes())
            .unwrap();
        let ops = ppc_lift(&i);
        assert!(matches!(ops[0], PpcLlilOp::SetRegConst { value: 99, .. }));
    }

    // ── PPC LE LLIL ───────────────────────────────────────────────────────
    #[test]
    fn test_ppcle_llil_li() {
        let a = PpcArch::new_le();
        // NOP in LE = 0x60000000 in BE = bytes [0x00,0x00,0x00,0x60] in LE
        let i = a.disassemble(addr(0), &[0x00, 0x00, 0x00, 0x60]).unwrap();
        // ORI is often NOP; just verify it decodes
        assert!(!i.mnemonic.is_empty());
    }

    // ── ppc_build_call_graph empty ────────────────────────────────────────
    #[test]
    fn test_ppc_call_graph_empty() {
        let edges = ppc_build_call_graph(&arch(), &[], addr(0));
        assert!(edges.is_empty());
    }

    // ── PpcHistogram count missing ────────────────────────────────────────
    #[test]
    fn test_ppc_hist_missing() {
        let h = PpcHistogram::default();
        assert_eq!(h.count("LWZ"), 0);
    }
}

// =============================================================================
// PowerPC MSR (Machine State Register) fields
// =============================================================================

/// PowerPC MSR bit positions (PPC32).
pub mod ppc_msr {
    /// Power Management Enable.
    pub const POW: u32 = 18;
    /// Exception Little-Endian Mode.
    pub const ILE: u32 = 16;
    /// External Interrupt Enable.
    pub const EE: u32 = 15;
    /// Privilege Level (1 = user, 0 = supervisor).
    pub const PR: u32 = 14;
    /// Floating-Point Available.
    pub const FP: u32 = 13;
    /// Machine Check Enable.
    pub const ME: u32 = 12;
    /// FP Exception Mode 0.
    pub const FE0: u32 = 11;
    /// Single-Step Trace Enable.
    pub const SE: u32 = 10;
    /// Branch Trace Enable.
    pub const BE: u32 = 9;
    /// FP Exception Mode 1.
    pub const FE1: u32 = 8;
    /// Instruction Relocate.
    pub const IR: u32 = 5;
    /// Data Relocate.
    pub const DR: u32 = 4;
    /// Performance Monitor Mark.
    pub const PMM: u32 = 2;
    /// Little-Endian Mode.
    pub const LE: u32 = 0;

    /// Is the CPU in user mode?
    #[must_use]
    pub const fn is_user_mode(msr: u32) -> bool {
        (msr >> PR) & 1 != 0
    }
    /// Is the FPU available?
    #[must_use]
    pub const fn fpu_available(msr: u32) -> bool {
        (msr >> FP) & 1 != 0
    }
    /// Is address translation enabled?
    #[must_use]
    pub const fn translate_enabled(msr: u32) -> bool {
        (msr >> IR) & 1 != 0 || (msr >> DR) & 1 != 0
    }
}

// =============================================================================
// PowerPC XER register fields
// =============================================================================

/// PowerPC XER register field helpers.
pub mod ppc_xer {
    /// Summary Overflow (SO) bit.
    pub const SO: u32 = 31;
    /// Overflow (OV) bit.
    pub const OV: u32 = 30;
    /// Carry (CA) bit.
    pub const CA: u32 = 29;
    /// Byte Count field (bits 0-6).
    pub const BC_MASK: u32 = 0x7F;

    #[must_use]
    pub const fn so(xer: u32) -> bool {
        (xer >> SO) & 1 != 0
    }
    #[must_use]
    pub const fn ov(xer: u32) -> bool {
        (xer >> OV) & 1 != 0
    }
    #[must_use]
    pub const fn ca(xer: u32) -> bool {
        (xer >> CA) & 1 != 0
    }
    #[must_use]
    pub const fn byte_count(xer: u32) -> u32 {
        xer & BC_MASK
    }
}

// =============================================================================
// Tests for MSR and XER helpers
// =============================================================================

#[cfg(test)]
mod tests_ppc_system {
    use super::*;
    use ppc_msr::*;
    use ppc_xer::*;

    // ── MSR user mode ─────────────────────────────────────────────────────
    #[test]
    fn test_msr_user() {
        let msr_user: u32 = 1 << PR;
        assert!(is_user_mode(msr_user));
        assert!(!is_user_mode(0));
    }

    // ── MSR FPU available ─────────────────────────────────────────────────
    #[test]
    fn test_msr_fpu() {
        let msr: u32 = 1 << FP;
        assert!(fpu_available(msr));
        assert!(!fpu_available(0));
    }

    // ── MSR translate ─────────────────────────────────────────────────────
    #[test]
    fn test_msr_translate() {
        let msr: u32 = (1 << IR) | (1 << DR);
        assert!(translate_enabled(msr));
        assert!(!translate_enabled(0));
    }

    // ── XER fields ────────────────────────────────────────────────────────
    #[test]
    fn test_xer_so_ov_ca() {
        let xer: u32 = (1 << SO) | (1 << CA);
        assert!(so(xer));
        assert!(!ov(xer));
        assert!(ca(xer));
        assert_eq!(byte_count(xer), 0);
    }

    // ── XER byte count ────────────────────────────────────────────────────
    #[test]
    fn test_xer_byte_count() {
        let xer: u32 = 0x25; // 37 decimal
        assert_eq!(byte_count(xer), 37);
    }

    // ── PpcLlilOp derive PartialEq ────────────────────────────────────────
    #[test]
    fn test_llil_equality() {
        let a = PpcLlilOp::Ret;
        let b = PpcLlilOp::Ret;
        assert_eq!(a, b);
        let c = PpcLlilOp::Syscall;
        assert_ne!(a, c);
    }

    // ── ppc_parse_mem ─────────────────────────────────────────────────────
    #[test]
    fn test_ppc_parse_mem() {
        // "r3,16(r1)" format
        let result = ppc_parse_mem("r3,16(r1)");
        assert_eq!(result, Some(("r3".to_string(), "r1".to_string(), 16)));
    }

    // ── detect_ppc_preamble short slice ───────────────────────────────────
    #[test]
    fn test_detect_ppc_short() {
        assert_eq!(detect_ppc_preamble(&[0x7C, 0x08]), None);
    }

    // ── PPC64 pointer size and name ───────────────────────────────────────
    #[test]
    fn test_ppc64_properties() {
        let a = PpcArch::new_64();
        assert_eq!(a.pointer_size(), 8);
        assert_eq!(a.name(), "ppc64");
        assert_eq!(a.endian(), Endian::Big);
    }

    // ── PPC LE name ───────────────────────────────────────────────────────
    #[test]
    fn test_ppcle_name() {
        let a = PpcArch::new_le();
        assert_eq!(a.name(), "ppcle");
        assert_eq!(a.endian(), Endian::Little);
    }

    // ── PPC_REG_ROLES r10 is arg ──────────────────────────────────────────
    #[test]
    fn test_reg_role_r10() {
        let r = lookup_ppc_reg_role(10).unwrap();
        assert_eq!(r.param_index, Some(7));
        assert!(r.caller_saved);
    }

    // ── encode_b must be 4-byte aligned ──────────────────────────────────
    #[test]
    #[should_panic(expected = "branch displacement must be 4-byte aligned")]
    fn test_encode_b_unaligned_panics() {
        let _ = encode_b(3, false);
    }

    // ── encode_li imm range ───────────────────────────────────────────────
    #[test]
    #[should_panic(expected = "LI imm out of 16-bit range")]
    fn test_encode_li_overflow_panics() {
        let _ = encode_li(3, 65536);
    }

    // ── PpcArch default == new_32 ─────────────────────────────────────────
    #[test]
    fn test_ppcarch_default() {
        let d = PpcArch::default();
        let n = PpcArch::new_32();
        assert_eq!(d.bits, n.bits);
        assert_eq!(d.endian, n.endian);
    }

    // ── lookup_spr returns None for unknown ───────────────────────────────
    #[test]
    fn test_lookup_spr_unknown() {
        assert!(lookup_spr(42).is_none());
    }

    // ── PpcInstrKind::Unknown ─────────────────────────────────────────────
    #[test]
    fn test_kind_unknown() {
        assert_eq!(PpcInstrKind::from_mnemonic("ZZZZZ"), PpcInstrKind::Unknown);
        assert!(!PpcInstrKind::Unknown.is_control_flow());
        assert!(!PpcInstrKind::Unknown.is_memory());
    }

    // ── ppc_build_call_graph single BL ────────────────────────────────────
    #[test]
    fn test_ppc_call_graph_single() {
        // BL +0x100 at 0x1000 → callee = 0x1100
        let code = encode_b(0x100, true).to_be_bytes();
        let edges = ppc_build_call_graph(&PpcArch::default(), &code, Address::new(0x1000));
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].caller, 0x1000);
        assert_eq!(edges[0].callee, 0x1100);
    }

    // ── PpcRegDep equality ────────────────────────────────────────────────
    #[test]
    fn test_ppc_reg_dep_eq() {
        let d1 = PpcRegDep {
            def_idx: 0,
            use_idx: 1,
            reg: "r3".into(),
        };
        let d2 = PpcRegDep {
            def_idx: 0,
            use_idx: 1,
            reg: "r3".into(),
        };
        assert_eq!(d1, d2);
    }

    // ── ppc_msr constants are distinct ───────────────────────────────────
    #[test]
    fn test_msr_constants_distinct() {
        let bits = [PR, FP, ME, EE, IR, DR, LE];
        let mut set = std::collections::HashSet::new();
        for &b in &bits {
            assert!(set.insert(b), "duplicate MSR bit {b}");
        }
    }

    // ── ppc_xer SO flag ───────────────────────────────────────────────────
    #[test]
    fn test_xer_so_only() {
        let xer: u32 = 1 << SO;
        assert!(so(xer));
        assert!(!ov(xer));
        assert!(!ca(xer));
    }

    // ── PPC_CR_INSTRS table completeness ──────────────────────────────────
    #[test]
    fn test_cr_instrs_completeness() {
        assert!(PPC_CR_INSTRS.iter().any(|e| e.mnemonic == "crxor"));
        assert!(PPC_CR_INSTRS.iter().any(|e| e.mnemonic == "mcrf"));
    }

    // ── ALTIVEC_INSTRS pack/unpack group ─────────────────────────────────
    #[test]
    fn test_altivec_pack_unpack() {
        assert!(ALTIVEC_INSTRS.iter().any(|e| e.mnemonic == "vpkuhum"));
        assert!(ALTIVEC_INSTRS.iter().any(|e| e.mnemonic == "vupkhsb"));
        assert!(ALTIVEC_INSTRS.iter().any(|e| e.mnemonic == "vmrghb"));
    }

    // ── PpcCodeStats all zero default ─────────────────────────────────────
    #[test]
    fn test_ppc_stats_zero_default() {
        let s = PpcCodeStats::default();
        assert_eq!(s.total, 0);
        assert_eq!(s.loads, 0);
        assert_eq!(s.stores, 0);
        assert_eq!(s.branches, 0);
    }

    // ── PpcBasicBlock len/is_empty ────────────────────────────────────────
    #[test]
    fn test_ppc_block_empty() {
        let b = PpcBasicBlock {
            start: Address::new(0),
            instructions: vec![],
        };
        assert!(b.is_empty());
        assert_eq!(b.len(), 0);
    }

    // ── ppc_format round-trip ─────────────────────────────────────────────
    #[test]
    fn test_ppc_format_add() {
        // ADD r3,r3,r4 = 0x7C632214
        let i = PpcArch::default()
            .disassemble(Address::new(0), &[0x7C, 0x63, 0x22, 0x14])
            .unwrap();
        let s = ppc_format(&i);
        assert!(s.contains("ADD"));
        assert!(s.contains("r3"));
    }

    // ── ALTIVEC compare ops exist ─────────────────────────────────────────
    #[test]
    fn test_altivec_compare_ops() {
        assert!(ALTIVEC_INSTRS.iter().any(|e| e.mnemonic == "vcmpequw"));
        assert!(ALTIVEC_INSTRS.iter().any(|e| e.mnemonic == "vcmpgtsw"));
        assert!(ALTIVEC_INSTRS.iter().any(|e| e.mnemonic == "vcmpgtfp"));
    }

    // ── PPC_MEM_REGIONS has IPL_ROM ───────────────────────────────────────
    #[test]
    fn test_ppc_mem_ipl_rom() {
        assert!(PPC_MEM_REGIONS.iter().any(|r| r.name == "IPL_ROM"));
        let rom = PPC_MEM_REGIONS
            .iter()
            .find(|r| r.name == "IPL_ROM")
            .unwrap();
        assert_eq!(rom.start, 0xFFF0_0000);
    }

    // ── encode_stwu negative offset ───────────────────────────────────────
    #[test]
    fn test_encode_stwu_negative() {
        let enc = encode_stwu(1, 1, -32).to_be_bytes();
        let i = PpcArch::default()
            .disassemble(Address::new(0), &enc)
            .unwrap();
        assert_eq!(i.mnemonic, "STWU");
        assert!(i.flags.contains(InstrFlags::WRITE_MEM));
    }
}

pub mod ppc_lifter;

/// PowerPC AltiVec/VMX extension: AltiVecDecoder, VmxRegister, AltiVecInsn,
/// AltiVecLifter, VSCR flags, and a full VMX register file.
pub mod ppc_altivec;

// End of rustre-arch-ppc — 5000+ lines of PowerPC 32/64 architecture implementation.
// Coverage: I/B/D/DS/X/XL/XFX/XO/A/M-forms, AltiVec/VMX, LLIL lifter, 80+ tests.
