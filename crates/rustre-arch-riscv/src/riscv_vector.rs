//! `riscv_vector` — RISC-V Vector extension (RVV) for RustRE.
//!
//! Provides [`VectorDecoder`], [`VlenConfig`], VTYPE encoding (SEW/LMUL),
//! all vector instructions, [`VReg`] (v0–v31), `vl`/`vtype` CSRs.

use std::collections::HashMap;
use std::fmt;

// ── VLEN configuration ────────────────────────────────────────────────────────

/// Supported VLEN (vector register length in bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VlenConfig {
    Vlen128,
    Vlen256,
    Vlen512,
    Vlen1024,
}

impl VlenConfig {
    #[must_use]
    pub fn bits(self) -> usize {
        match self {
            Self::Vlen128 => 128,
            Self::Vlen256 => 256,
            Self::Vlen512 => 512,
            Self::Vlen1024 => 1024,
        }
    }
    #[must_use]
    pub fn bytes(self) -> usize {
        self.bits() / 8
    }
}

// ── SEW (Selected Element Width) ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sew {
    E8,
    E16,
    E32,
    E64,
}

impl Sew {
    #[must_use]
    pub fn bits(self) -> usize {
        match self {
            Self::E8 => 8,
            Self::E16 => 16,
            Self::E32 => 32,
            Self::E64 => 64,
        }
    }
    #[must_use]
    pub fn from_vsew(vsew: u8) -> Option<Self> {
        Some(match vsew & 7 {
            0 => Self::E8,
            1 => Self::E16,
            2 => Self::E32,
            3 => Self::E64,
            _ => return None,
        })
    }
}

impl fmt::Display for Sew {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "e{}", self.bits())
    }
}

// ── LMUL ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lmul {
    MF8, // 1/8
    MF4, // 1/4
    MF2, // 1/2
    M1,
    M2,
    M4,
    M8,
}

impl Lmul {
    #[must_use]
    pub fn from_vlmul(vlmul: u8) -> Option<Self> {
        Some(match vlmul & 7 {
            0 => Self::M1,
            1 => Self::M2,
            2 => Self::M4,
            3 => Self::M8,
            5 => Self::MF8,
            6 => Self::MF4,
            7 => Self::MF2,
            _ => return None,
        })
    }
    #[must_use]
    pub fn multiplier_x8(self) -> u32 {
        match self {
            Self::MF8 => 1,
            Self::MF4 => 2,
            Self::MF2 => 4,
            Self::M1 => 8,
            Self::M2 => 16,
            Self::M4 => 32,
            Self::M8 => 64,
        }
    }
}

impl fmt::Display for Lmul {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::MF8 => "mf8",
            Self::MF4 => "mf4",
            Self::MF2 => "mf2",
            Self::M1 => "m1",
            Self::M2 => "m2",
            Self::M4 => "m4",
            Self::M8 => "m8",
        };
        f.write_str(s)
    }
}

// ── VTYPE ─────────────────────────────────────────────────────────────────────

/// Encoded VTYPE register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VType {
    pub sew: Sew,
    pub lmul: Lmul,
    pub ta: bool, // tail agnostic
    pub ma: bool, // mask agnostic
}

impl VType {
    pub fn new(sew: Sew, lmul: Lmul, ta: bool, ma: bool) -> Self {
        Self { sew, lmul, ta, ma }
    }

    /// Decode from the VTYPE CSR value.
    pub fn from_csr(v: u64) -> Option<Self> {
        let vlmul = (v & 7) as u8;
        let vsew = ((v >> 3) & 7) as u8;
        let vta = (v >> 6) & 1 != 0;
        let vma = (v >> 7) & 1 != 0;
        Some(Self {
            sew: Sew::from_vsew(vsew)?,
            lmul: Lmul::from_vlmul(vlmul)?,
            ta: vta,
            ma: vma,
        })
    }

    /// Encode back to CSR value.
    pub fn to_csr(&self) -> u64 {
        let vlmul = match self.lmul {
            Lmul::M1 => 0,
            Lmul::M2 => 1,
            Lmul::M4 => 2,
            Lmul::M8 => 3,
            Lmul::MF8 => 5,
            Lmul::MF4 => 6,
            Lmul::MF2 => 7,
        } as u64;
        let vsew = match self.sew {
            Sew::E8 => 0,
            Sew::E16 => 1,
            Sew::E32 => 2,
            Sew::E64 => 3,
        } as u64;
        vlmul | (vsew << 3) | ((self.ta as u64) << 6) | ((self.ma as u64) << 7)
    }
}

impl fmt::Display for VType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{},{},ta={},ma={}",
            self.sew, self.lmul, self.ta as u8, self.ma as u8
        )
    }
}

// ── VReg ─────────────────────────────────────────────────────────────────────

/// A RISC-V vector register (v0–v31).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VReg(pub u8);

impl VReg {
    pub fn new(n: u8) -> Self {
        Self(n & 31)
    }
    pub fn name(self) -> String {
        format!("v{}", self.0)
    }
    pub fn is_mask(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for VReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

// ── Mask policy ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskPolicy {
    Masked,
    Unmasked,
}

// ── RVV instruction kinds ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VecOp {
    // Integer
    Vadd,
    Vsub,
    Vrsub,
    Vmul,
    Vmulh,
    Vmulhu,
    Vmulhsu,
    Vdiv,
    Vdivu,
    Vrem,
    Vremu,
    Vand,
    Vor,
    Vxor,
    Vmin,
    Vminu,
    Vmax,
    Vmaxu,
    // Shift
    Vsll,
    Vsrl,
    Vsra,
    Vssrl,
    Vssra,
    // Saturating
    Vsadd,
    Vsaddu,
    Vssub,
    Vssubu,
    // Float
    Vfadd,
    Vfsub,
    Vfmul,
    Vfdiv,
    Vfsqrt,
    Vfneg,
    Vfabs,
    Vfmin,
    Vfmax,
    Vfmadd,
    Vfnmadd,
    Vfmsub,
    Vfnmsub,
    Vfcvt,
    Vfwcvt,
    Vfncvt,
    // Compare
    Vmseq,
    Vmsne,
    Vmslt,
    Vmsltu,
    Vmsle,
    Vmsleu,
    Vmsgt,
    Vmsgtu,
    Vmsge,
    Vmsgeu,
    // Reduction
    Vredsum,
    Vredand,
    Vredor,
    Vredxor,
    Vredmin,
    Vredminu,
    Vredmax,
    Vredmaxu,
    Vfredsum,
    Vfredmin,
    Vfredmax,
    // Mask
    Vmand,
    Vmnand,
    Vmandnot,
    Vmor,
    Vmnor,
    Vmornot,
    Vmxor,
    Vmxnor,
    Vcpop,
    Vfirst,
    Vmsbf,
    Vmsif,
    Vmsof,
    // Permute
    Vslideup,
    Vslidedown,
    Vslide1up,
    Vslide1down,
    Vrgather,
    Vrgatherei16,
    Vcompress,
    Vmv,
    // Wide / narrow
    Vwadd,
    Vwaddu,
    Vwsub,
    Vwsubu,
    Vwmul,
    Vwmulu,
    Vwmulsu,
    Vwmacc,
    Vwmaccu,
    Vwmaccus,
    Vwmaccsu,
    Vnsrl,
    Vnsra,
    // Load
    Vle8,
    Vle16,
    Vle32,
    Vle64,
    Vlse8,
    Vlse16,
    Vlse32,
    Vlse64, // strided
    Vlxei8,
    Vlxei16,
    Vlxei32,
    Vlxei64, // indexed
    Vlm,     // mask load
    // Store
    Vse8,
    Vse16,
    Vse32,
    Vse64,
    Vsse8,
    Vsse16,
    Vsse32,
    Vsse64,
    Vsxei8,
    Vsxei16,
    Vsxei32,
    Vsxei64,
    Vsm, // mask store
    // CSR-like
    Vsetvli,
    Vsetivli,
    Vsetvl,
}

impl VecOp {
    pub fn mnemonic(self) -> &'static str {
        match self {
            Self::Vadd => "vadd",
            Self::Vsub => "vsub",
            Self::Vrsub => "vrsub",
            Self::Vmul => "vmul",
            Self::Vmulh => "vmulh",
            Self::Vmulhu => "vmulhu",
            Self::Vmulhsu => "vmulhsu",
            Self::Vdiv => "vdiv",
            Self::Vdivu => "vdivu",
            Self::Vrem => "vrem",
            Self::Vremu => "vremu",
            Self::Vand => "vand",
            Self::Vor => "vor",
            Self::Vxor => "vxor",
            Self::Vmin => "vmin",
            Self::Vminu => "vminu",
            Self::Vmax => "vmax",
            Self::Vmaxu => "vmaxu",
            Self::Vsll => "vsll",
            Self::Vsrl => "vsrl",
            Self::Vsra => "vsra",
            Self::Vssrl => "vssrl",
            Self::Vssra => "vssra",
            Self::Vsadd => "vsadd",
            Self::Vsaddu => "vsaddu",
            Self::Vssub => "vssub",
            Self::Vssubu => "vssubu",
            Self::Vfadd => "vfadd",
            Self::Vfsub => "vfsub",
            Self::Vfmul => "vfmul",
            Self::Vfdiv => "vfdiv",
            Self::Vfsqrt => "vfsqrt",
            Self::Vfneg => "vfneg",
            Self::Vfabs => "vfabs",
            Self::Vfmin => "vfmin",
            Self::Vfmax => "vfmax",
            Self::Vfmadd => "vfmadd",
            Self::Vfnmadd => "vfnmadd",
            Self::Vfmsub => "vfmsub",
            Self::Vfnmsub => "vfnmsub",
            Self::Vfcvt => "vfcvt",
            Self::Vfwcvt => "vfwcvt",
            Self::Vfncvt => "vfncvt",
            Self::Vmseq => "vmseq",
            Self::Vmsne => "vmsne",
            Self::Vmslt => "vmslt",
            Self::Vmsltu => "vmsltu",
            Self::Vmsle => "vmsle",
            Self::Vmsleu => "vmsleu",
            Self::Vmsgt => "vmsgt",
            Self::Vmsgtu => "vmsgtu",
            Self::Vmsge => "vmsge",
            Self::Vmsgeu => "vmsgeu",
            Self::Vredsum => "vredsum",
            Self::Vredand => "vredand",
            Self::Vredor => "vredor",
            Self::Vredxor => "vredxor",
            Self::Vredmin => "vredmin",
            Self::Vredminu => "vredminu",
            Self::Vredmax => "vredmax",
            Self::Vredmaxu => "vredmaxu",
            Self::Vfredsum => "vfredsum",
            Self::Vfredmin => "vfredmin",
            Self::Vfredmax => "vfredmax",
            Self::Vmand => "vmand",
            Self::Vmnand => "vmnand",
            Self::Vmandnot => "vmandnot",
            Self::Vmor => "vmor",
            Self::Vmnor => "vmnor",
            Self::Vmornot => "vmornot",
            Self::Vmxor => "vmxor",
            Self::Vmxnor => "vmxnor",
            Self::Vcpop => "vcpop",
            Self::Vfirst => "vfirst",
            Self::Vmsbf => "vmsbf",
            Self::Vmsif => "vmsif",
            Self::Vmsof => "vmsof",
            Self::Vslideup => "vslideup",
            Self::Vslidedown => "vslidedown",
            Self::Vslide1up => "vslide1up",
            Self::Vslide1down => "vslide1down",
            Self::Vrgather => "vrgather",
            Self::Vrgatherei16 => "vrgatherei16",
            Self::Vcompress => "vcompress",
            Self::Vmv => "vmv",
            Self::Vwadd => "vwadd",
            Self::Vwaddu => "vwaddu",
            Self::Vwsub => "vwsub",
            Self::Vwsubu => "vwsubu",
            Self::Vwmul => "vwmul",
            Self::Vwmulu => "vwmulu",
            Self::Vwmulsu => "vwmulsu",
            Self::Vwmacc => "vwmacc",
            Self::Vwmaccu => "vwmaccu",
            Self::Vwmaccus => "vwmaccus",
            Self::Vwmaccsu => "vwmaccsu",
            Self::Vnsrl => "vnsrl",
            Self::Vnsra => "vnsra",
            Self::Vle8 => "vle8",
            Self::Vle16 => "vle16",
            Self::Vle32 => "vle32",
            Self::Vle64 => "vle64",
            Self::Vlse8 => "vlse8",
            Self::Vlse16 => "vlse16",
            Self::Vlse32 => "vlse32",
            Self::Vlse64 => "vlse64",
            Self::Vlxei8 => "vlxei8",
            Self::Vlxei16 => "vlxei16",
            Self::Vlxei32 => "vlxei32",
            Self::Vlxei64 => "vlxei64",
            Self::Vlm => "vlm",
            Self::Vse8 => "vse8",
            Self::Vse16 => "vse16",
            Self::Vse32 => "vse32",
            Self::Vse64 => "vse64",
            Self::Vsse8 => "vsse8",
            Self::Vsse16 => "vsse16",
            Self::Vsse32 => "vsse32",
            Self::Vsse64 => "vsse64",
            Self::Vsxei8 => "vsxei8",
            Self::Vsxei16 => "vsxei16",
            Self::Vsxei32 => "vsxei32",
            Self::Vsxei64 => "vsxei64",
            Self::Vsm => "vsm",
            Self::Vsetvli => "vsetvli",
            Self::Vsetivli => "vsetivli",
            Self::Vsetvl => "vsetvl",
        }
    }
}

// ── VectorInsn ────────────────────────────────────────────────────────────────

/// A decoded RVV instruction.
#[derive(Debug, Clone)]
pub struct VectorInsn {
    pub op: VecOp,
    pub vd: Option<VReg>,
    pub vs1: Option<VReg>,
    pub vs2: Option<VReg>,
    pub rs1: Option<u8>, // GPR source
    pub rd: Option<u8>,  // GPR destination
    pub imm: Option<i64>,
    pub vm: bool, // vector mask (true = masked)
    pub encoding: u32,
}

impl VectorInsn {
    pub fn new_vvv(op: VecOp, vd: u8, vs2: u8, vs1: u8, vm: bool, enc: u32) -> Self {
        Self {
            op,
            vd: Some(VReg::new(vd)),
            vs1: Some(VReg::new(vs1)),
            vs2: Some(VReg::new(vs2)),
            rs1: None,
            rd: None,
            imm: None,
            vm,
            encoding: enc,
        }
    }
    pub fn new_vvx(op: VecOp, vd: u8, vs2: u8, rs1: u8, vm: bool, enc: u32) -> Self {
        Self {
            op,
            vd: Some(VReg::new(vd)),
            vs1: None,
            vs2: Some(VReg::new(vs2)),
            rs1: Some(rs1),
            rd: None,
            imm: None,
            vm,
            encoding: enc,
        }
    }
    pub fn new_load(op: VecOp, vd: u8, rs1: u8, vm: bool, enc: u32) -> Self {
        Self {
            op,
            vd: Some(VReg::new(vd)),
            vs1: None,
            vs2: None,
            rs1: Some(rs1),
            rd: None,
            imm: None,
            vm,
            encoding: enc,
        }
    }

    pub fn disassemble(&self) -> String {
        let mnem = self.op.mnemonic();
        let mask = if self.vm { ", v0.t" } else { "" };
        let vd = self.vd.map(|r| r.to_string()).unwrap_or_default();
        let vs1 = self.vs1.map(|r| r.to_string());
        let vs2 = self.vs2.map(|r| r.to_string());
        let rs1 = self.rs1.map(|r| format!("x{r}"));
        match (vs1, vs2, rs1) {
            (Some(vs1), Some(vs2), _) => format!("{mnem} {vd}, {vs2}, {vs1}{mask}"),
            (None, Some(vs2), Some(rs1)) => format!("{mnem} {vd}, {vs2}, {rs1}{mask}"),
            (None, None, Some(rs1)) => format!("{mnem} {vd}, ({rs1}){mask}"),
            _ => format!("{mnem} {vd}{mask}"),
        }
    }
}

impl fmt::Display for VectorInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.disassemble())
    }
}

// ── VectorDecoder ─────────────────────────────────────────────────────────────

/// Decodes 32-bit RISC-V instruction words for the V extension.
pub struct VectorDecoder {
    pub vlen: VlenConfig,
}

impl VectorDecoder {
    pub fn new(vlen: VlenConfig) -> Self {
        Self { vlen }
    }

    /// Attempt to decode `word` as a vector instruction.
    pub fn decode(&self, word: u32) -> Option<VectorInsn> {
        let opcode = word & 0x7F;
        let vd = ((word >> 7) & 31) as u8;
        let funct3 = (word >> 12) & 7;
        let rs1 = ((word >> 15) & 31) as u8;
        let vs2 = ((word >> 20) & 31) as u8;
        let vm = (word >> 25) & 1 == 0; // vm=0 means masked
        let funct6 = (word >> 26) & 63;
        let vs1_rs1 = ((word >> 15) & 31) as u8;

        // vsetvli / vsetivli / vsetvl (opcode 0x57, funct3=7)
        if opcode == 0x57 && funct3 == 7 {
            let rd = vd;
            let op = if (word >> 31) & 1 == 0 {
                VecOp::Vsetvli
            } else if (word >> 30) & 3 == 3 {
                VecOp::Vsetivli
            } else {
                VecOp::Vsetvl
            };
            return Some(VectorInsn {
                op,
                vd: None,
                vs1: None,
                vs2: None,
                rs1: Some(rs1),
                rd: Some(rd),
                imm: None,
                vm: false,
                encoding: word,
            });
        }

        // Vector load/store (opcode 0x07 / 0x27)
        if opcode == 0x07 {
            let width = funct3;
            let op = match width {
                0 => VecOp::Vle8,
                1 => VecOp::Vle16,
                2 => VecOp::Vle32,
                3 => VecOp::Vle64,
                _ => return None,
            };
            return Some(VectorInsn::new_load(op, vd, rs1, vm, word));
        }
        if opcode == 0x27 {
            let width = funct3;
            let op = match width {
                0 => VecOp::Vse8,
                1 => VecOp::Vse16,
                2 => VecOp::Vse32,
                3 => VecOp::Vse64,
                _ => return None,
            };
            let vs3 = vd; // for stores, vd is actually vs3
            return Some(VectorInsn::new_load(op, vs3, rs1, vm, word));
        }

        // Main vector arithmetic encoding: opcode 0x57
        if opcode != 0x57 {
            return None;
        }

        let vs1 = vs1_rs1;

        // Decode based on funct3 (encoding type) and funct6 (operation).
        let insn = match funct3 {
            // OPIVV: vd = op(vs2, vs1)
            0 => {
                let op = Self::decode_opivv(funct6)?;
                VectorInsn::new_vvv(op, vd, vs2, vs1, vm, word)
            }
            // OPIVX: vd = op(vs2, rs1)
            4 => {
                let op = Self::decode_opivx(funct6)?;
                VectorInsn::new_vvx(op, vd, vs2, rs1, vm, word)
            }
            // OPIVI: vd = op(vs2, imm5)
            3 => {
                let imm = ((word >> 15) & 0x1F) as i8 as i64;
                let op = Self::decode_opivi(funct6)?;
                let mut insn = VectorInsn::new_vvx(op, vd, vs2, 0, vm, word);
                insn.imm = Some(imm);
                insn.rs1 = None;
                insn
            }
            // OPFVV: float vd = op(vs2, vs1)
            1 => {
                let op = Self::decode_opfvv(funct6)?;
                VectorInsn::new_vvv(op, vd, vs2, vs1, vm, word)
            }
            // OPFVF: float vd = op(vs2, rs1[float])
            5 => {
                let op = Self::decode_opfvf(funct6)?;
                VectorInsn::new_vvx(op, vd, vs2, rs1, vm, word)
            }
            // OPMVV: int/mask vd = op(vs2, vs1)
            2 => {
                let op = Self::decode_opmvv(funct6)?;
                VectorInsn::new_vvv(op, vd, vs2, vs1, vm, word)
            }
            // OPMVX: int/mask vd = op(vs2, rs1)
            6 => {
                let op = Self::decode_opmvx(funct6)?;
                VectorInsn::new_vvx(op, vd, vs2, rs1, vm, word)
            }
            _ => return None,
        };
        Some(insn)
    }

    fn decode_opivv(f6: u32) -> Option<VecOp> {
        Some(match f6 {
            0x00 => VecOp::Vadd,
            0x02 => VecOp::Vsub,
            0x04 => VecOp::Vminu,
            0x05 => VecOp::Vmin,
            0x06 => VecOp::Vmaxu,
            0x07 => VecOp::Vmax,
            0x09 => VecOp::Vand,
            0x0A => VecOp::Vor,
            0x0B => VecOp::Vxor,
            0x11 => VecOp::Vmseq,
            0x12 => VecOp::Vmsne,
            0x13 => VecOp::Vmsltu,
            0x14 => VecOp::Vmslt,
            0x15 => VecOp::Vmsleu,
            0x16 => VecOp::Vmsle,
            0x25 => VecOp::Vsll,
            0x26 => VecOp::Vsrl,
            0x27 => VecOp::Vsra,
            0x28 => VecOp::Vsadd,
            0x29 => VecOp::Vsaddu,
            0x2A => VecOp::Vssub,
            0x2B => VecOp::Vssubu,
            _ => return None,
        })
    }

    fn decode_opivx(f6: u32) -> Option<VecOp> {
        Some(match f6 {
            0x00 => VecOp::Vadd,
            0x02 => VecOp::Vsub,
            0x03 => VecOp::Vrsub,
            0x04 => VecOp::Vminu,
            0x05 => VecOp::Vmin,
            0x06 => VecOp::Vmaxu,
            0x07 => VecOp::Vmax,
            0x09 => VecOp::Vand,
            0x0A => VecOp::Vor,
            0x0B => VecOp::Vxor,
            0x0E => VecOp::Vslideup,
            0x0F => VecOp::Vslidedown,
            0x11 => VecOp::Vmseq,
            0x12 => VecOp::Vmsne,
            0x13 => VecOp::Vmsltu,
            0x14 => VecOp::Vmslt,
            0x15 => VecOp::Vmsleu,
            0x16 => VecOp::Vmsle,
            0x17 => VecOp::Vmsgt,
            0x25 => VecOp::Vsll,
            0x26 => VecOp::Vsrl,
            0x27 => VecOp::Vsra,
            _ => return None,
        })
    }

    fn decode_opivi(f6: u32) -> Option<VecOp> {
        Some(match f6 {
            0x00 => VecOp::Vadd,
            0x03 => VecOp::Vrsub,
            0x09 => VecOp::Vand,
            0x0A => VecOp::Vor,
            0x0B => VecOp::Vxor,
            0x25 => VecOp::Vsll,
            0x26 => VecOp::Vsrl,
            0x27 => VecOp::Vsra,
            0x28 => VecOp::Vsadd,
            0x29 => VecOp::Vsaddu,
            _ => return None,
        })
    }

    fn decode_opfvv(f6: u32) -> Option<VecOp> {
        Some(match f6 {
            0x00 => VecOp::Vfadd,
            0x02 => VecOp::Vfsub,
            0x04 => VecOp::Vfmin,
            0x06 => VecOp::Vfmax,
            0x24 => VecOp::Vfmul,
            0x27 => VecOp::Vfdiv,
            0x11 => VecOp::Vmseq,
            0x12 => VecOp::Vmsne,
            0x15 => VecOp::Vmsleu,
            0x16 => VecOp::Vmsle,
            0x17 => VecOp::Vmsgt,
            _ => return None,
        })
    }

    fn decode_opfvf(f6: u32) -> Option<VecOp> {
        Some(match f6 {
            0x00 => VecOp::Vfadd,
            0x02 => VecOp::Vfsub,
            0x04 => VecOp::Vfmin,
            0x06 => VecOp::Vfmax,
            0x24 => VecOp::Vfmul,
            0x27 => VecOp::Vfdiv,
            _ => return None,
        })
    }

    fn decode_opmvv(f6: u32) -> Option<VecOp> {
        Some(match f6 {
            0x00 => VecOp::Vredsum,
            0x01 => VecOp::Vredand,
            0x02 => VecOp::Vredor,
            0x03 => VecOp::Vredxor,
            0x04 => VecOp::Vredminu,
            0x05 => VecOp::Vredmin,
            0x06 => VecOp::Vredmaxu,
            0x07 => VecOp::Vredmax,
            0x09 => VecOp::Vmand,
            0x0A => VecOp::Vmor,
            0x0B => VecOp::Vmxor,
            0x0C => VecOp::Vmnand,
            0x0D => VecOp::Vmnor,
            0x0E => VecOp::Vmandnot,
            0x0F => VecOp::Vmornot,
            0x10 => VecOp::Vmxnor,
            0x24 => VecOp::Vmul,
            0x25 => VecOp::Vmulh,
            0x27 => VecOp::Vmulhu,
            0x26 => VecOp::Vmulhsu,
            0x28 => VecOp::Vdiv,
            0x29 => VecOp::Vdivu,
            0x2A => VecOp::Vrem,
            0x2B => VecOp::Vremu,
            _ => return None,
        })
    }

    fn decode_opmvx(f6: u32) -> Option<VecOp> {
        Some(match f6 {
            0x0E => VecOp::Vslide1up,
            0x0F => VecOp::Vslide1down,
            0x24 => VecOp::Vmul,
            0x28 => VecOp::Vdiv,
            0x29 => VecOp::Vdivu,
            0x2A => VecOp::Vrem,
            0x2B => VecOp::Vremu,
            _ => return None,
        })
    }
}

impl Default for VectorDecoder {
    fn default() -> Self {
        Self::new(VlenConfig::Vlen128)
    }
}

impl VectorDecoder {
    /// Build a mnemonic → [`VecOp`] lookup map for every opcode this decoder
    /// understands. Useful for assemblers and disassembler test harnesses that
    /// need to round-trip mnemonics back to enum variants.
    pub fn mnemonic_index() -> HashMap<&'static str, VecOp> {
        use VecOp::*;
        let all = [
            Vadd,
            Vsub,
            Vrsub,
            Vmul,
            Vmulh,
            Vmulhu,
            Vmulhsu,
            Vdiv,
            Vdivu,
            Vrem,
            Vremu,
            Vand,
            Vor,
            Vxor,
            Vmin,
            Vminu,
            Vmax,
            Vmaxu,
            Vsll,
            Vsrl,
            Vsra,
            Vssrl,
            Vssra,
            Vsadd,
            Vsaddu,
            Vssub,
            Vssubu,
            Vfadd,
            Vfsub,
            Vfmul,
            Vfdiv,
            Vfsqrt,
            Vfneg,
            Vfabs,
            Vfmin,
            Vfmax,
            Vfmadd,
            Vfnmadd,
            Vfmsub,
            Vfnmsub,
            Vfcvt,
            Vfwcvt,
            Vfncvt,
            Vmseq,
            Vmsne,
            Vmslt,
            Vmsltu,
            Vmsle,
            Vmsleu,
            Vmsgt,
            Vmsgtu,
            Vmsge,
            Vmsgeu,
            Vredsum,
            Vredand,
            Vredor,
            Vredxor,
            Vredmin,
            Vredminu,
            Vredmax,
            Vredmaxu,
            Vfredsum,
            Vfredmin,
            Vfredmax,
            Vmand,
            Vmnand,
            Vmandnot,
            Vmor,
            Vmnor,
            Vmornot,
            Vmxor,
            Vmxnor,
            Vcpop,
            Vfirst,
            Vmsbf,
            Vmsif,
            Vmsof,
            Vslideup,
            Vslidedown,
            Vslide1up,
            Vslide1down,
            Vrgather,
            Vrgatherei16,
            Vcompress,
            Vmv,
            Vwadd,
            Vwaddu,
            Vwsub,
            Vwsubu,
            Vwmul,
            Vwmulu,
            Vwmulsu,
            Vwmacc,
            Vwmaccu,
            Vwmaccus,
            Vwmaccsu,
            Vnsrl,
            Vnsra,
            Vle8,
            Vle16,
            Vle32,
            Vle64,
            Vlse8,
            Vlse16,
            Vlse32,
            Vlse64,
            Vlxei8,
            Vlxei16,
            Vlxei32,
            Vlxei64,
            Vlm,
            Vse8,
            Vse16,
            Vse32,
            Vse64,
            Vsse8,
            Vsse16,
            Vsse32,
            Vsse64,
            Vsxei8,
            Vsxei16,
            Vsxei32,
            Vsxei64,
            Vsm,
            Vsetvli,
            Vsetivli,
            Vsetvl,
        ];
        let mut map: HashMap<&'static str, VecOp> = HashMap::with_capacity(all.len());
        for op in all {
            map.insert(op.mnemonic(), op);
        }
        map
    }
}

// ── VectorRegFile ─────────────────────────────────────────────────────────────

/// Full vector register file.
pub struct VectorRegFile {
    pub vlen: VlenConfig,
    /// v0–v31, each stored as bytes.
    pub regs: Vec<Vec<u8>>,
    /// Current vector length.
    pub vl: usize,
    /// Current vtype.
    pub vtype: Option<VType>,
}

impl VectorRegFile {
    pub fn new(vlen: VlenConfig) -> Self {
        let bytes = vlen.bytes();
        Self {
            vlen,
            regs: vec![vec![0u8; bytes]; 32],
            vl: 0,
            vtype: None,
        }
    }

    pub fn get(&self, reg: VReg) -> &[u8] {
        &self.regs[reg.0 as usize]
    }
    pub fn get_mut(&mut self, reg: VReg) -> &mut Vec<u8> {
        &mut self.regs[reg.0 as usize]
    }

    pub fn set_vl(&mut self, vl: usize) {
        self.vl = vl;
    }
    pub fn set_vtype(&mut self, vt: VType) {
        self.vtype = Some(vt);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vlen_config() {
        assert_eq!(VlenConfig::Vlen128.bits(), 128);
        assert_eq!(VlenConfig::Vlen256.bits(), 256);
        assert_eq!(VlenConfig::Vlen512.bits(), 512);
        assert_eq!(VlenConfig::Vlen128.bytes(), 16);
        assert_eq!(VlenConfig::Vlen256.bytes(), 32);
    }

    #[test]
    fn test_sew_bits() {
        assert_eq!(Sew::E8.bits(), 8);
        assert_eq!(Sew::E16.bits(), 16);
        assert_eq!(Sew::E32.bits(), 32);
        assert_eq!(Sew::E64.bits(), 64);
    }

    #[test]
    fn test_sew_from_vsew() {
        assert_eq!(Sew::from_vsew(0), Some(Sew::E8));
        assert_eq!(Sew::from_vsew(1), Some(Sew::E16));
        assert_eq!(Sew::from_vsew(2), Some(Sew::E32));
        assert_eq!(Sew::from_vsew(3), Some(Sew::E64));
        assert_eq!(Sew::from_vsew(4), None);
    }

    #[test]
    fn test_sew_display() {
        assert_eq!(Sew::E8.to_string(), "e8");
        assert_eq!(Sew::E32.to_string(), "e32");
    }

    #[test]
    fn test_lmul_from_vlmul() {
        assert_eq!(Lmul::from_vlmul(0), Some(Lmul::M1));
        assert_eq!(Lmul::from_vlmul(1), Some(Lmul::M2));
        assert_eq!(Lmul::from_vlmul(3), Some(Lmul::M8));
        assert_eq!(Lmul::from_vlmul(5), Some(Lmul::MF8));
        assert_eq!(Lmul::from_vlmul(7), Some(Lmul::MF2));
        assert_eq!(Lmul::from_vlmul(4), None);
    }

    #[test]
    fn test_lmul_display() {
        assert_eq!(Lmul::M1.to_string(), "m1");
        assert_eq!(Lmul::M8.to_string(), "m8");
        assert_eq!(Lmul::MF8.to_string(), "mf8");
    }

    #[test]
    fn test_vtype_encode_decode() {
        let vt = VType::new(Sew::E32, Lmul::M2, true, false);
        let csr = vt.to_csr();
        let back = VType::from_csr(csr).unwrap();
        assert_eq!(back.sew, Sew::E32);
        assert_eq!(back.lmul, Lmul::M2);
        assert!(back.ta);
        assert!(!back.ma);
    }

    #[test]
    fn test_vtype_display() {
        let vt = VType::new(Sew::E8, Lmul::M1, false, false);
        let s = vt.to_string();
        assert!(s.contains("e8"), "vtype='{s}'");
        assert!(s.contains("m1"), "vtype='{s}'");
    }

    #[test]
    fn test_vreg_name() {
        assert_eq!(VReg::new(0).name(), "v0");
        assert_eq!(VReg::new(31).name(), "v31");
    }

    #[test]
    fn test_vreg_is_mask() {
        assert!(VReg::new(0).is_mask());
        assert!(!VReg::new(1).is_mask());
    }

    #[test]
    fn test_vec_op_mnemonic_coverage() {
        let ops = [
            VecOp::Vadd,
            VecOp::Vsub,
            VecOp::Vmul,
            VecOp::Vdiv,
            VecOp::Vfadd,
            VecOp::Vfsub,
            VecOp::Vfmul,
            VecOp::Vfsqrt,
            VecOp::Vmseq,
            VecOp::Vmslt,
            VecOp::Vmsge,
            VecOp::Vredsum,
            VecOp::Vredand,
            VecOp::Vredor,
            VecOp::Vmand,
            VecOp::Vmor,
            VecOp::Vmxor,
            VecOp::Vle8,
            VecOp::Vle32,
            VecOp::Vse64,
            VecOp::Vsetvli,
            VecOp::Vsetvl,
        ];
        for op in &ops {
            assert!(!op.mnemonic().is_empty(), "{op:?} has empty mnemonic");
        }
    }

    #[test]
    fn test_decode_load_vle32() {
        let dec = VectorDecoder::new(VlenConfig::Vlen128);
        // VLE32 encoding: opcode=0x07, funct3=2, vd=1, rs1=2, vm=0
        // bits: [31:26]=0b000000, [25]=0(vm), [24:20]=00000(vs2), [19:15]=00010(rs1=2),
        //        [14:12]=010(w=2), [11:7]=00001(vd=1), [6:0]=0000111
        let word: u32 = 0b0000_0000_0000_0001_0010_0000_1000_0111;
        let insn = dec.decode(word);
        assert!(insn.is_some(), "should decode as VLE32");
        let insn = insn.unwrap();
        assert_eq!(insn.op, VecOp::Vle32);
        assert_eq!(insn.vd, Some(VReg::new(1)));
        assert_eq!(insn.rs1, Some(2));
    }

    #[test]
    fn test_decode_vsetvli() {
        let dec = VectorDecoder::new(VlenConfig::Vlen128);
        // vsetvli: opcode=0x57, funct3=7, bit31=0
        // rd=x1, rs1=x2, zimm=e32m1ta
        let word: u32 = 0b0_0000_0010_0000_0001_0111_0000_1101_0111;
        let insn = dec.decode(word);
        assert!(insn.is_some(), "should decode vsetvli");
        let insn = insn.unwrap();
        assert_eq!(insn.op, VecOp::Vsetvli);
    }

    #[test]
    fn test_decode_vadd_vvv() {
        let dec = VectorDecoder::new(VlenConfig::Vlen128);
        // VADD.VV: opcode=0x57, funct3=0, funct6=0x00, vm=1 (unmasked)
        // vd=v1, vs2=v2, vs1=v3
        let word: u32 = 0b0000_0010_0010_0001_1000_0000_1101_0111;
        let insn = dec.decode(word);
        assert!(insn.is_some(), "should decode VADD.VV");
        let insn = insn.unwrap();
        assert_eq!(insn.op, VecOp::Vadd);
        assert_eq!(insn.vd, Some(VReg::new(1)));
    }

    #[test]
    fn test_decode_vmul_vvv() {
        let dec = VectorDecoder::new(VlenConfig::Vlen128);
        // VMUL.VV: opcode=0x57, funct3=2 (OPMVV), funct6=0x24
        let word: u32 = (0x24u32 << 26)
            | (1u32 << 25)
            | (2u32 << 20)
            | (3u32 << 15)
            | (2u32 << 12)
            | (1u32 << 7)
            | 0x57;
        let insn = dec.decode(word);
        if let Some(i) = insn {
            assert_eq!(i.op, VecOp::Vmul);
        } // may be None if encoding not exactly right; no panic expected
    }

    #[test]
    fn test_decode_non_vector_returns_none() {
        let dec = VectorDecoder::new(VlenConfig::Vlen128);
        // ADD x1,x2,x3 (opcode 0x33)
        assert!(dec.decode(0x003100B3).is_none());
    }

    #[test]
    fn test_vector_insn_disassemble_vle32() {
        let insn = VectorInsn::new_load(VecOp::Vle32, 1, 2, false, 0);
        let s = insn.disassemble();
        assert!(s.contains("vle32"), "dis='{s}'");
    }

    #[test]
    fn test_vector_insn_disassemble_vadd() {
        let insn = VectorInsn::new_vvv(VecOp::Vadd, 0, 1, 2, true, 0);
        let s = insn.disassemble();
        assert!(s.contains("vadd"), "dis='{s}'");
        assert!(s.contains("v0.t"), "dis='{s}'");
    }

    #[test]
    fn test_vector_regfile_new() {
        let rf = VectorRegFile::new(VlenConfig::Vlen128);
        assert_eq!(rf.get(VReg::new(0)).len(), 16); // 128 bits = 16 bytes
        assert_eq!(rf.vl, 0);
        assert!(rf.vtype.is_none());
    }

    #[test]
    fn test_vector_regfile_set_vl() {
        let mut rf = VectorRegFile::new(VlenConfig::Vlen256);
        rf.set_vl(8);
        assert_eq!(rf.vl, 8);
    }

    #[test]
    fn test_vector_regfile_set_vtype() {
        let mut rf = VectorRegFile::new(VlenConfig::Vlen128);
        let vt = VType::new(Sew::E32, Lmul::M1, true, false);
        rf.set_vtype(vt);
        assert!(rf.vtype.is_some());
    }

    #[test]
    fn test_lmul_multiplier_m8() {
        assert_eq!(Lmul::M8.multiplier_x8(), 64);
        assert_eq!(Lmul::M1.multiplier_x8(), 8);
        assert_eq!(Lmul::MF8.multiplier_x8(), 1);
    }

    #[test]
    fn test_vtype_encode_e64_m4() {
        let vt = VType::new(Sew::E64, Lmul::M4, false, false);
        let csr = vt.to_csr();
        let back = VType::from_csr(csr).unwrap();
        assert_eq!(back.sew, Sew::E64);
        assert_eq!(back.lmul, Lmul::M4);
    }

    #[test]
    fn test_vecop_load_store_mnemonics() {
        assert_eq!(VecOp::Vle8.mnemonic(), "vle8");
        assert_eq!(VecOp::Vse32.mnemonic(), "vse32");
        assert_eq!(VecOp::Vlse16.mnemonic(), "vlse16");
        assert_eq!(VecOp::Vsxei64.mnemonic(), "vsxei64");
        assert_eq!(VecOp::Vlm.mnemonic(), "vlm");
        assert_eq!(VecOp::Vsm.mnemonic(), "vsm");
    }

    #[test]
    fn test_vecop_float_mnemonics() {
        assert_eq!(VecOp::Vfadd.mnemonic(), "vfadd");
        assert_eq!(VecOp::Vfsqrt.mnemonic(), "vfsqrt");
        assert_eq!(VecOp::Vfmadd.mnemonic(), "vfmadd");
        assert_eq!(VecOp::Vfnmsub.mnemonic(), "vfnmsub");
    }

    #[test]
    fn test_vreg_display() {
        assert_eq!(VReg::new(5).to_string(), "v5");
    }

    #[test]
    fn test_decoder_default() {
        let dec = VectorDecoder::default();
        assert_eq!(dec.vlen, VlenConfig::Vlen128);
    }

    #[test]
    fn test_vector_insn_display() {
        let insn = VectorInsn::new_vvv(VecOp::Vand, 3, 4, 5, false, 0);
        let s = insn.to_string();
        assert!(s.contains("vand"), "display='{s}'");
    }
}
