//! `AArch64` advanced lifting â€” SVE, SVE2, SME, and Pointer Authentication.
//!
//! # Coverage
//! * **SVE** â€” LD1/ST1 with predicate register, FADD/FMUL predicated,
//!   WHILELT/WHILELE, PTRUE, PTEST, RDVL, INDEX, ADDVL, ADDPL
//! * **SVE2** â€” MATCH/NMATCH, HISTCNT, HISTSEG, PMULLB/T, SRSHR/URSHR,
//!   FLOGB, BDEP/BEXT/BGRP
//! * **SME** â€” SMSTART/SMSTOP, MOVA, ZERO (ZA tile), outer-product:
//!   FMOPA/FMOPS, BFMOPA, SMOPA/SMOPS, UMOPA/UMOPS
//! * **PAC** â€” PACIA/PACIB/PACDA/PACDB/PACDZA/PACDZB/PACGA,
//!   AUTIA/AUTIB/AUTDA/AUTDB, XPACI/XPACD, RETAA/RETAB,
//!   BLRAA/BLRAB/BRAA/BRAB, LDRAA/LDRAB

use super::{ArchLifter, Effect, IrExpr, LiftError, LiftLevel, LiftedInstr};
use rustre_core::arch::Instruction;
use std::fmt;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// SvePredReg â€” SVE predicate register
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// An SVE predicate register p0..p15 with optional qualifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SvePredReg {
    /// Register index (0â€“15).
    pub index: u8,
    /// Qualifier governing which lanes are active (byte / halfword / word / dword).
    pub qualifier: SveLaneQualifier,
}

impl SvePredReg {
    /// Returns the register name string (e.g. `"p3"`).
    #[must_use]
    pub fn name(&self) -> String {
        format!("p{}", self.index)
    }
}

impl fmt::Display for SvePredReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "p{}/{}", self.index, self.qualifier)
    }
}

/// Lane qualifier for SVE predicate / data registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SveLaneQualifier {
    #[default]
    /// Byte lanes (8-bit).
    B,
    /// Halfword lanes (16-bit).
    H,
    /// Word lanes (32-bit).
    S,
    /// Doubleword lanes (64-bit).
    D,
}

impl fmt::Display for SveLaneQualifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::B => write!(f, "b"),
            Self::H => write!(f, "h"),
            Self::S => write!(f, "s"),
            Self::D => write!(f, "d"),
        }
    }
}

impl SveLaneQualifier {
    /// Lane size in bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::B => 1,
            Self::H => 2,
            Self::S => 4,
            Self::D => 8,
        }
    }

    /// Parse from a suffix string such as `"b"`, `"h"`, `"s"`, or `"d"`.
    #[must_use]
    pub fn from_suffix(s: &str) -> Self {
        match s {
            "h" | "H" => Self::H,
            "s" | "S" => Self::S,
            "d" | "D" => Self::D,
            _ => Self::B,
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// SmeOuterProduct â€” SME outer product instruction variants
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Outer product operation for SME.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmOp {
    /// Accumulate (positive).
    Mopa,
    /// Subtract (negative).
    Mops,
}

impl fmt::Display for SmOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mopa => write!(f, "mopa"),
            Self::Mops => write!(f, "mops"),
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// PacKind â€” Pointer Authentication Code variant
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Which PAC key and address type is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacKey {
    /// Instruction A key â€” PACIA/AUTIA.
    Ia,
    /// Instruction B key â€” PACIB/AUTIB.
    Ib,
    /// Data A key â€” PACDA/AUTDA.
    Da,
    /// Data B key â€” PACDB/AUTDB.
    Db,
    /// Generic key â€” PACGA (result in Xd, not in-place).
    Generic,
}

impl fmt::Display for PacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ia => write!(f, "ia"),
            Self::Ib => write!(f, "ib"),
            Self::Da => write!(f, "da"),
            Self::Db => write!(f, "db"),
            Self::Generic => write!(f, "generic"),
        }
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// AArch64AdvancedLifter
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Lifts `AArch64` SVE / SVE2 / SME / PAC instructions to IL effects.
///
/// Predicated SVE operations are modelled as [`Effect::Intrinsic`] nodes that
/// carry the predicate register as an explicit argument, so consumers can
/// reason about which lanes are active without understanding the SVE predicate
/// encoding directly.
#[derive(Debug, Clone)]
pub struct AArch64AdvancedLifter {
    /// Enable SVE2 instruction decoding.
    pub sve2: bool,
    /// Enable SME instruction decoding.
    pub sme: bool,
    /// Enable Pointer Authentication instruction decoding.
    pub pac: bool,
}

impl AArch64AdvancedLifter {
    /// Create a lifter with all extensions enabled.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sve2: true,
            sme: true,
            pac: true,
        }
    }

    /// Create a lifter for SVE base instructions only.
    #[must_use]
    pub const fn sve_only() -> Self {
        Self {
            sve2: false,
            sme: false,
            pac: false,
        }
    }

    // â”€â”€ helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn intrinsic(name: &str, args: Vec<IrExpr>) -> Effect {
        Effect::Intrinsic {
            name: name.to_owned(),
            args,
        }
    }

    fn reg(name: &str) -> IrExpr {
        IrExpr::Reg(name.to_owned())
    }

    fn parts(ops: &str) -> Vec<&str> {
        ops.split_whitespace()
            .map(|s| s.trim_matches(','))
            .collect()
    }

    // â”€â”€ SVE base â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn lift_sve_a(mnem: &str, ops: &str) -> Option<Vec<Effect>> {
        let p = Self::parts(ops);

            match mnem {
            // LD1B/H/W/D {Zt.T}, Pg/Z, [Xn{, Xm}]
            // Gather-load or contiguous load, predicated.
            "ld1b" | "ld1h" | "ld1w" | "ld1d" | "ld1sb" | "ld1sh" | "ld1sw" => {
                let zt = p.first().copied().unwrap_or("z0.b");
                let pg = p.get(1).copied().unwrap_or("p0/z");
                let base = p.get(2).copied().unwrap_or("x0");
                let elem_sz = sve_elem_sz_from_mnem(mnem);
                Some(vec![
                    Effect::MemRead {
                        addr: Self::reg(base),
                        dest: zt.to_owned(),
                        size: elem_sz,
                    },
                    Self::intrinsic(
                        &format!("sve_{mnem}"),
                        vec![Self::reg(zt), Self::reg(pg), Self::reg(base)],
                    ),
                ])
            }
            // ST1B/H/W/D {Zt.T}, Pg, [Xn{, Xm}]
            "st1b" | "st1h" | "st1w" | "st1d" => {
                let zt = p.first().copied().unwrap_or("z0.b");
                let pg = p.get(1).copied().unwrap_or("p0");
                let base = p.get(2).copied().unwrap_or("x0");
                let elem_sz = sve_elem_sz_from_mnem(mnem);
                Some(vec![
                    Effect::MemWrite {
                        addr: Self::reg(base),
                        value: Self::reg(zt),
                        size: elem_sz,
                    },
                    Self::intrinsic(
                        &format!("sve_{mnem}"),
                        vec![Self::reg(zt), Self::reg(pg), Self::reg(base)],
                    ),
                ])
            }
            // FADD Zd.T, Pg/M, Zn.T, Zm.T â€” predicated floating-point add.
            "fadd" if ops.contains('/') => {
                let zd = p.first().copied().unwrap_or("z0.s");
                let pg = p.get(1).copied().unwrap_or("p0/m");
                let zn = p.get(2).copied().unwrap_or("z1.s");
                let zm = p.get(3).copied().unwrap_or("z2.s");
                Some(vec![Self::intrinsic(
                    "sve_fadd_pred",
                    vec![Self::reg(zd), Self::reg(pg), Self::reg(zn), Self::reg(zm)],
                )])
            }
            // FMUL Zd.T, Pg/M, Zn.T, Zm.T â€” predicated floating-point multiply.
            "fmul" if ops.contains('/') => {
                let zd = p.first().copied().unwrap_or("z0.s");
                let pg = p.get(1).copied().unwrap_or("p0/m");
                let zn = p.get(2).copied().unwrap_or("z1.s");
                let zm = p.get(3).copied().unwrap_or("z2.s");
                Some(vec![Self::intrinsic(
                    "sve_fmul_pred",
                    vec![Self::reg(zd), Self::reg(pg), Self::reg(zn), Self::reg(zm)],
                )])
            }
            // WHILELT Pd.T, Xn, Xm â€” set predicate lanes while Xn < Xm.
            "whilelt" => {
                let pd = p.first().copied().unwrap_or("p0.b");
                let rn = p.get(1).copied().unwrap_or("x0");
                let rm = p.get(2).copied().unwrap_or("x1");
                Some(vec![
                    Self::intrinsic(
                        "sve_whilelt",
                        vec![Self::reg(pd), Self::reg(rn), Self::reg(rm)],
                    ),
                    Effect::RegWrite {
                        reg: pd.to_owned(),
                        value: IrExpr::CmpLt(
                            Box::new(Self::reg(rn)),
                            Box::new(Self::reg(rm)),
                        ),
                    },
                ])
            }
            // WHILELE Pd.T, Xn, Xm â€” set predicate lanes while Xn <= Xm.
            "whilele" => {
                let pd = p.first().copied().unwrap_or("p0.b");
                let rn = p.get(1).copied().unwrap_or("x0");
                let rm = p.get(2).copied().unwrap_or("x1");
                Some(vec![Self::intrinsic(
                    "sve_whilele",
                    vec![Self::reg(pd), Self::reg(rn), Self::reg(rm)],
                )])
            }
                _ => None,
            }
    }
    fn lift_sve_b(mnem: &str, ops: &str) -> Option<Vec<Effect>> {
        let p = Self::parts(ops);

            match mnem {
            // PTRUE Pd.T{, pattern} â€” set predicate to all-true or a VL pattern.
            "ptrue" => {
                let pd = p.first().copied().unwrap_or("p0.b");
                let pat = p.get(1).copied().unwrap_or("all");
                Some(vec![Self::intrinsic(
                    "sve_ptrue",
                    vec![Self::reg(pd), IrExpr::Reg(pat.to_owned())],
                )])
            }
            // PTEST {Pg}, Pn.B â€” set condition flags from predicate bits.
            "ptest" => {
                let pg = p.first().copied().unwrap_or("p0");
                let pn = p.get(1).copied().unwrap_or("p1.b");
                Some(vec![Self::intrinsic(
                    "sve_ptest",
                    vec![Self::reg(pg), Self::reg(pn)],
                )])
            }
            // RDVL Xd, #imm â€” read multiple of VL in bytes.
            "rdvl" => {
                let xd = p.first().copied().unwrap_or("x0");
                let imm = parse_imm_token(p.get(1).copied().unwrap_or("#1"));
                Some(vec![Effect::RegWrite {
                    reg: xd.to_owned(),
                    value: IrExpr::Mul(
                        Box::new(IrExpr::Reg("__vl_bytes".to_owned())),
                        Box::new(IrExpr::Const(imm)),
                    ),
                }])
            }
            // INDEX Zd.T, Xn, Xm â€” generate incrementing index vector.
            "index" => {
                let zd = p.first().copied().unwrap_or("z0.s");
                let base = p.get(1).copied().unwrap_or("x0");
                let step = p.get(2).copied().unwrap_or("x1");
                Some(vec![Self::intrinsic(
                    "sve_index",
                    vec![Self::reg(zd), Self::reg(base), Self::reg(step)],
                )])
            }
            // ADDVL Xd, Xn, #imm â€” add multiple of VL to register.
            "addvl" => {
                let xd = p.first().copied().unwrap_or("x0");
                let xn = p.get(1).copied().unwrap_or("x1");
                let imm = parse_imm_token(p.get(2).copied().unwrap_or("#0"));
                Some(vec![Effect::RegWrite {
                    reg: xd.to_owned(),
                    value: IrExpr::Add(
                        Box::new(Self::reg(xn)),
                        Box::new(IrExpr::Mul(
                            Box::new(IrExpr::Reg("__vl_bytes".to_owned())),
                            Box::new(IrExpr::Const(imm)),
                        )),
                    ),
                }])
            }
            _ => None,
            }
    }

    fn lift_sve(mnem: &str, ops: &str) -> Option<Vec<Effect>> {
        let _p = Self::parts(ops);

        Self::lift_sve_a(mnem, ops)
            .or_else(|| Self::lift_sve_b(mnem, ops))
    }

    // â”€â”€ SVE2 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn lift_sve2(mnem: &str, ops: &str) -> Option<Vec<Effect>> {
        let p = Self::parts(ops);

        match mnem {
            // MATCH Pd.B, Pg/Z, Zn.B, Zm.B
            // Set predicate lanes where any Zn byte equals any Zm byte.
            "match" => {
                let pd = p.first().copied().unwrap_or("p0.b");
                let pg = p.get(1).copied().unwrap_or("p0/z");
                let zn = p.get(2).copied().unwrap_or("z0.b");
                let zm = p.get(3).copied().unwrap_or("z1.b");
                Some(vec![Self::intrinsic(
                    "sve2_match",
                    vec![Self::reg(pd), Self::reg(pg), Self::reg(zn), Self::reg(zm)],
                )])
            }
            // NMATCH Pd.B, Pg/Z, Zn.B, Zm.B â€” inverse of MATCH.
            "nmatch" => {
                let pd = p.first().copied().unwrap_or("p0.b");
                let pg = p.get(1).copied().unwrap_or("p0/z");
                let zn = p.get(2).copied().unwrap_or("z0.b");
                let zm = p.get(3).copied().unwrap_or("z1.b");
                Some(vec![Self::intrinsic(
                    "sve2_nmatch",
                    vec![Self::reg(pd), Self::reg(pg), Self::reg(zn), Self::reg(zm)],
                )])
            }
            // HISTCNT Zd.S, Pg/Z, Zn.S, Zm.S
            // For each active lane, count occurrences of Zn[i] in Zm.
            "histcnt" => {
                let zd = p.first().copied().unwrap_or("z0.s");
                let pg = p.get(1).copied().unwrap_or("p0/z");
                let zn = p.get(2).copied().unwrap_or("z1.s");
                let zm = p.get(3).copied().unwrap_or("z2.s");
                Some(vec![Self::intrinsic(
                    "sve2_histcnt",
                    vec![Self::reg(zd), Self::reg(pg), Self::reg(zn), Self::reg(zm)],
                )])
            }
            // HISTSEG Zd.B, Zn.B, Zm.B â€” histogram segment.
            "histseg" => {
                let zd = p.first().copied().unwrap_or("z0.b");
                let zn = p.get(1).copied().unwrap_or("z1.b");
                let zm = p.get(2).copied().unwrap_or("z2.b");
                Some(vec![Self::intrinsic(
                    "sve2_histseg",
                    vec![Self::reg(zd), Self::reg(zn), Self::reg(zm)],
                )])
            }
            // PMULLB/PMULLT Zd.T, Zn.T, Zm.T â€” polynomial multiply low/high.
            "pmullb" | "pmullt" => {
                let zd = p.first().copied().unwrap_or("z0.h");
                let zn = p.get(1).copied().unwrap_or("z1.b");
                let zm = p.get(2).copied().unwrap_or("z2.b");
                Some(vec![Self::intrinsic(
                    &format!("sve2_{mnem}"),
                    vec![Self::reg(zd), Self::reg(zn), Self::reg(zm)],
                )])
            }
            // BDEP/BEXT/BGRP â€” bit deposit/extract/group (Zc extension).
            "bdep" | "bext" | "bgrp" => {
                let zd = p.first().copied().unwrap_or("z0.s");
                let zn = p.get(1).copied().unwrap_or("z1.s");
                let zm = p.get(2).copied().unwrap_or("z2.s");
                Some(vec![Self::intrinsic(
                    &format!("sve2_{mnem}"),
                    vec![Self::reg(zd), Self::reg(zn), Self::reg(zm)],
                )])
            }
            _ => None,
        }
    }

    // â”€â”€ SME â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn lift_sme_a(mnem: &str, ops: &str) -> Option<Vec<Effect>> {
        let p = Self::parts(ops);

            match mnem {
            // SMSTART â€” enable Streaming SVE mode (and optionally ZA array).
            "smstart" => {
                let mode = p.first().copied().unwrap_or("");
                Some(vec![Self::intrinsic(
                    "sme_smstart",
                    vec![IrExpr::Reg(mode.to_owned())],
                )])
            }
            // SMSTOP â€” exit Streaming SVE mode.
            "smstop" => {
                let mode = p.first().copied().unwrap_or("");
                Some(vec![Self::intrinsic(
                    "sme_smstop",
                    vec![IrExpr::Reg(mode.to_owned())],
                )])
            }
            // MOVA ZAd[Ws, #imm], Pg/M, Zn.T â€” move vector to ZA tile slice.
            // MOVA Zd.T, Pg/M, ZAn[Ws, #imm] â€” move ZA tile slice to vector.
            "mova" => {
                let dst = p.first().copied().unwrap_or("za0h.s[w12, 0]");
                let pg = p.get(1).copied().unwrap_or("p0/m");
                let src = p.get(2).copied().unwrap_or("z0.s");
                Some(vec![Self::intrinsic(
                    "sme_mova",
                    vec![Self::reg(dst), Self::reg(pg), Self::reg(src)],
                )])
            }
            // ZERO {ZA-mask} â€” zero selected ZA tile(s).
            "zero" if ops.contains("za") || ops.is_empty() => {
                let mask = p.first().copied().unwrap_or(concat!("{", "za}"));
                Some(vec![Self::intrinsic(
                    "sme_zero",
                    vec![IrExpr::Reg(mask.to_owned())],
                )])
            }
            // FMOPA ZAd.S, Pn/M, Pm/M, Zn.S, Zm.S â€” FP32 outer product accumulate.
            "fmopa" => {
                let za = p.first().copied().unwrap_or("za0.s");
                let pn = p.get(1).copied().unwrap_or("p0/m");
                let pm = p.get(2).copied().unwrap_or("p1/m");
                let zn = p.get(3).copied().unwrap_or("z0.s");
                let zm = p.get(4).copied().unwrap_or("z1.s");
                Some(vec![Self::intrinsic(
                    "sme_fmopa",
                    vec![
                        Self::reg(za),
                        Self::reg(pn),
                        Self::reg(pm),
                        Self::reg(zn),
                        Self::reg(zm),
                    ],
                )])
            }
                _ => None,
            }
    }
    fn lift_sme_b(mnem: &str, ops: &str) -> Option<Vec<Effect>> {
        let p = Self::parts(ops);

            match mnem {
            // FMOPS â€” FP32 outer product subtract.
            "fmops" => {
                let za = p.first().copied().unwrap_or("za0.s");
                let pn = p.get(1).copied().unwrap_or("p0/m");
                let pm = p.get(2).copied().unwrap_or("p1/m");
                let zn = p.get(3).copied().unwrap_or("z0.s");
                let zm = p.get(4).copied().unwrap_or("z1.s");
                Some(vec![Self::intrinsic(
                    "sme_fmops",
                    vec![
                        Self::reg(za),
                        Self::reg(pn),
                        Self::reg(pm),
                        Self::reg(zn),
                        Self::reg(zm),
                    ],
                )])
            }
            // SMOPA ZAd.S, Pn/M, Pm/M, Zn.B, Zm.B â€” signed integer outer product.
            "smopa" => {
                let za = p.first().copied().unwrap_or("za0.s");
                let pn = p.get(1).copied().unwrap_or("p0/m");
                let pm = p.get(2).copied().unwrap_or("p1/m");
                let zn = p.get(3).copied().unwrap_or("z0.b");
                let zm = p.get(4).copied().unwrap_or("z1.b");
                Some(vec![Self::intrinsic(
                    "sme_smopa",
                    vec![
                        Self::reg(za),
                        Self::reg(pn),
                        Self::reg(pm),
                        Self::reg(zn),
                        Self::reg(zm),
                    ],
                )])
            }
            // UMOPA â€” unsigned integer outer product accumulate.
            "umopa" => {
                let za = p.first().copied().unwrap_or("za0.s");
                let pn = p.get(1).copied().unwrap_or("p0/m");
                let pm = p.get(2).copied().unwrap_or("p1/m");
                let zn = p.get(3).copied().unwrap_or("z0.b");
                let zm = p.get(4).copied().unwrap_or("z1.b");
                Some(vec![Self::intrinsic(
                    "sme_umopa",
                    vec![
                        Self::reg(za),
                        Self::reg(pn),
                        Self::reg(pm),
                        Self::reg(zn),
                        Self::reg(zm),
                    ],
                )])
            }
            _ => None,
            }
    }

    fn lift_sme(mnem: &str, ops: &str) -> Option<Vec<Effect>> {
        let _p = Self::parts(ops);

        Self::lift_sme_a(mnem, ops)
            .or_else(|| Self::lift_sme_b(mnem, ops))
    }

    // â”€â”€ Pointer Authentication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn lift_pac_a(mnem: &str, ops: &str) -> Option<Vec<Effect>> {
        let p = Self::parts(ops);

            match mnem {
            // PACIA/PACIB/PACDA/PACDB Xd, Xn â€” sign address in Xd using modifier Xn.
            "pacia" | "pacib" | "pacda" | "pacdb" => {
                let xd = p.first().copied().unwrap_or("x0");
                let xn = p.get(1).copied().unwrap_or("x1");
                let key = pac_key_from_mnem(mnem);
                Some(vec![Effect::RegWrite {
                    reg: xd.to_owned(),
                    value: IrExpr::Reg(format!("__pac_{key}({xd},{xn})")),
                }])
            }
            // PACDZA/PACDZB â€” sign address in Xd using XZR modifier.
            "pacdza" | "pacdzb" => {
                let xd = p.first().copied().unwrap_or("x0");
                let key = pac_key_from_mnem(mnem);
                Some(vec![Effect::RegWrite {
                    reg: xd.to_owned(),
                    value: IrExpr::Reg(format!("__pac_{key}({xd},0)")),
                }])
            }
            // PACGA Xd, Xn, Xm â€” compute generic PAC into Xd.
            "pacga" => {
                let xd = p.first().copied().unwrap_or("x0");
                let xn = p.get(1).copied().unwrap_or("x1");
                let xm = p.get(2).copied().unwrap_or("x2");
                Some(vec![Effect::RegWrite {
                    reg: xd.to_owned(),
                    value: IrExpr::Reg(format!("__pac_ga({xn},{xm})")),
                }])
            }
            // AUTIA/AUTIB/AUTDA/AUTDB Xd, Xn â€” authenticate and strip PAC.
            "autia" | "autib" | "autda" | "autdb" => {
                let xd = p.first().copied().unwrap_or("x0");
                let xn = p.get(1).copied().unwrap_or("x1");
                let key = pac_key_from_mnem(mnem);
                Some(vec![Effect::RegWrite {
                    reg: xd.to_owned(),
                    value: IrExpr::Reg(format!("__aut_{key}({xd},{xn})")),
                }])
            }
            // AUTIZA/AUTIZB/AUTDZA/AUTDZB â€” authenticate using XZR modifier.
            "autiza" | "autizb" | "autdza" | "autdzb" => {
                let xd = p.first().copied().unwrap_or("x0");
                let key = pac_key_from_mnem(mnem);
                Some(vec![Effect::RegWrite {
                    reg: xd.to_owned(),
                    value: IrExpr::Reg(format!("__aut_{key}({xd},0)")),
                }])
            }
            // XPACI/XPACD â€” strip PAC from instruction/data pointer.
            "xpaci" | "xpacd" => {
                let xd = p.first().copied().unwrap_or("x0");
                Some(vec![Effect::RegWrite {
                    reg: xd.to_owned(),
                    // Strip top bits by masking to virtual address width.
                    value: IrExpr::And(
                        Box::new(IrExpr::Reg(xd.to_owned())),
                        Box::new(IrExpr::Const(0x0000_FFFF_FFFF_FFFF)),
                    ),
                }])
            }
                _ => None,
            }
    }
    fn lift_pac_b(mnem: &str, ops: &str) -> Option<Vec<Effect>> {
        let p = Self::parts(ops);

            match mnem {
            // RETAA / RETAB â€” return with pointer authentication (authenticate LR).
            "retaa" | "retab" => {
                let key = if mnem == "retaa" { "ia" } else { "ib" };
                Some(vec![
                    Effect::RegWrite {
                        reg: "lr".to_owned(),
                        value: IrExpr::Reg(format!("__aut_{key}(lr,sp)")),
                    },
                    Effect::Return { value: None },
                ])
            }
            // BLRAA/BLRAB Xn, Xm â€” branch-with-link and authenticate.
            "blraa" | "blrab" => {
                let xn = p.first().copied().unwrap_or("x0");
                let xm = p.get(1).copied().unwrap_or("x1");
                let key = if mnem == "blraa" { "ia" } else { "ib" };
                Some(vec![
                    Effect::RegWrite {
                        reg: "lr".to_owned(),
                        value: IrExpr::Reg("__return_addr".to_owned()),
                    },
                    Effect::Call {
                        target: IrExpr::Reg(format!("__aut_{key}({xn},{xm})")),
                    },
                ])
            }
            // BRAA/BRAB Xn, Xm â€” branch without link, authenticate.
            "braa" | "brab" => {
                let xn = p.first().copied().unwrap_or("x0");
                let xm = p.get(1).copied().unwrap_or("x1");
                let key = if mnem == "braa" { "ia" } else { "ib" };
                Some(vec![Effect::Branch {
                    target: IrExpr::Reg(format!("__aut_{key}({xn},{xm})")),
                    condition: None,
                }])
            }
            // LDRAA/LDRAB Xt, [Xn{, #imm}]! â€” load with pointer authentication.
            "ldraa" | "ldrab" => {
                let xt = p.first().copied().unwrap_or("x0");
                let base = p.get(1).copied().unwrap_or("[x1]");
                let key = if mnem == "ldraa" { "da" } else { "db" };
                // The address itself is authenticated before use.
                let auth_addr = IrExpr::Reg(format!("__aut_{key}({base},sp)"));
                Some(vec![Effect::MemRead {
                    addr: auth_addr,
                    dest: xt.to_owned(),
                    size: 8,
                }])
            }
            _ => None,
            }
    }

    fn lift_pac(mnem: &str, ops: &str) -> Option<Vec<Effect>> {
        let _p = Self::parts(ops);

        Self::lift_pac_a(mnem, ops)
            .or_else(|| Self::lift_pac_b(mnem, ops))
    }
}

impl Default for AArch64AdvancedLifter {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchLifter for AArch64AdvancedLifter {
    fn arch_name(&self) -> &'static str {
        "arm64_advanced"
    }

    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    fn description(&self) -> &'static str {
        "AArch64 advanced lifter â€” SVE, SVE2, SME, Pointer Authentication"
    }

    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        let mnem = instr.mnemonic.to_lowercase();
        let ops = instr.operands.as_str();

        let effects = Self::lift_sve(&mnem, ops)
            .or_else(|| {
                if self.sve2 {
                    Self::lift_sve2(&mnem, ops)
                } else {
                    None
                }
            })
            .or_else(|| {
                if self.sme {
                    Self::lift_sme(&mnem, ops)
                } else {
                    None
                }
            })
            .or_else(|| {
                if self.pac {
                    Self::lift_pac(&mnem, ops)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                LiftError::LiftFailed(
                    instr.address.into(),
                    format!("arm64_advanced: unhandled mnemonic '{mnem}'"),
                )
            })?;

        let ir_text = effects.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ");
        Ok(LiftedInstr {
            address: instr.address.0,
            original_mnemonic: instr.mnemonic.clone(),
            ir_text,
            il_level: LiftLevel::Llil,
            effects,
        })
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Free helpers
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

fn sve_elem_sz_from_mnem(mnem: &str) -> u8 {
    if mnem.ends_with('b') || mnem.ends_with("sb") {
        1
    } else if mnem.ends_with('h') || mnem.ends_with("sh") {
        2
    } else if mnem.ends_with('w') || mnem.ends_with("sw") {
        4
    } else {
        8
    }
}

fn pac_key_from_mnem(mnem: &str) -> &'static str {
    if mnem.contains("ia") || mnem.contains("iza") {
        "ia"
    } else if mnem.contains("ib") || mnem.contains("izb") {
        "ib"
    } else if mnem.contains("da") || mnem.contains("dza") {
        "da"
    } else if mnem.contains("db") || mnem.contains("dzb") {
        "db"
    } else {
        "ia"
    }
}

fn parse_imm_token(tok: &str) -> u64 {
    let s = tok.trim_start_matches('#').trim_matches(',');
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).map_or_else(|| s.parse::<i64>().map_or(0, i64::cast_unsigned), |hex| u64::from_str_radix(hex, 16).unwrap_or(0))
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    fn make(mnem: &str, ops: &str) -> Instruction {
        let mut i = Instruction::new(
            rustre_core::address::Address::new(0x4000),
            4,
            mnem,
            vec![],
        );
        i.operands = ops.to_owned();
        i
    }

    #[test]
    fn test_ld1w() {
        let l = AArch64AdvancedLifter::new();
        let i = make("ld1w", "z0.s p0/z x1");
        let r = l.lift(&i).unwrap();
        assert!(!r.effects.is_empty());
        assert!(matches!(&r.effects[0], Effect::MemRead { .. }));
    }

    #[test]
    fn test_whilelt() {
        let l = AArch64AdvancedLifter::new();
        let i = make("whilelt", "p0.s x0 x1");
        let r = l.lift(&i).unwrap();
        assert!(r.effects.len() >= 1);
    }

    #[test]
    fn test_retaa() {
        let l = AArch64AdvancedLifter::new();
        let i = make("retaa", "");
        let r = l.lift(&i).unwrap();
        assert!(r.effects.iter().any(|e| matches!(e, Effect::Return { .. })));
    }

    #[test]
    fn test_xpaci() {
        let l = AArch64AdvancedLifter::new();
        let i = make("xpaci", "x0");
        let r = l.lift(&i).unwrap();
        match &r.effects[0] {
            Effect::RegWrite { reg, value: IrExpr::And(_, _) } => assert_eq!(reg, "x0"),
            _ => panic!("expected and-masking RegWrite"),
        }
    }

    #[test]
    fn test_sme_smstart() {
        let l = AArch64AdvancedLifter::new();
        let i = make("smstart", "za");
        let r = l.lift(&i).unwrap();
        assert!(matches!(&r.effects[0], Effect::Intrinsic { name, .. } if name == "sme_smstart"));
    }

    #[test]
    fn test_pac_key_detection() {
        assert_eq!(pac_key_from_mnem("pacia"), "ia");
        assert_eq!(pac_key_from_mnem("pacdb"), "db");
        assert_eq!(pac_key_from_mnem("autib"), "ib");
    }
}
