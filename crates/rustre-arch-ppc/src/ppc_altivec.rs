//! `ppc_altivec` — PowerPC AltiVec/VMX extension for RustRE.
//!
//! Provides [`AltiVecDecoder`], [`VmxRegister`], [`AltiVecInsn`],
//! [`AltiVecLifter`], and [`VSCR`] flags.

use std::collections::HashMap;
use std::fmt;

// ── VSCR ─────────────────────────────────────────────────────────────────────

/// The Vector Status and Control Register (VSCR).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VSCR(pub u32);

impl VSCR {
    /// Non-Java mode bit (bit 0).
    #[must_use]
    pub const fn nj(&self) -> bool {
        self.0 & 1 != 0
    }
    /// Set NJ bit.
    pub const fn set_nj(&mut self, v: bool) {
        if v {
            self.0 |= 1;
        } else {
            self.0 &= !1;
        }
    }

    /// SAT (saturation) flag (bit 16).
    #[must_use]
    pub const fn sat(&self) -> bool {
        self.0 & (1 << 16) != 0
    }
    /// Set SAT flag.
    pub const fn set_sat(&mut self, v: bool) {
        if v {
            self.0 |= 1 << 16;
        } else {
            self.0 &= !(1 << 16);
        }
    }
}

impl fmt::Display for VSCR {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VSCR{{NJ={}, SAT={}}}",
            u8::from(self.nj()),
            u8::from(self.sat())
        )
    }
}

// ── VmxRegister ──────────────────────────────────────────────────────────────

/// A 128-bit AltiVec/VMX register (v0–v31).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmxRegister {
    /// Physical register index (0–31).
    pub index: u8,
    /// 128-bit contents stored as two u64 (hi, lo).
    pub hi: u64,
    pub lo: u64,
}

impl VmxRegister {
    #[must_use]
    pub const fn new(index: u8) -> Self {
        Self {
            index: index & 31,
            hi: 0,
            lo: 0,
        }
    }

    #[must_use]
    pub fn from_u128(index: u8, v: u128) -> Self {
        Self {
            index: index & 31,
            hi: u64::try_from(v >> 64).unwrap_or(u64::MAX),
            lo: u64::try_from(v & u128::from(u64::MAX)).unwrap_or(u64::MAX),
        }
    }

    #[must_use]
    pub fn to_u128(self) -> u128 {
        (u128::from(self.hi) << 64) | u128::from(self.lo)
    }

    /// Read the 4 × 32-bit unsigned integer lanes (big-endian order).
    #[must_use]
    pub fn as_u32x4(self) -> [u32; 4] {
        let v = self.to_u128();
        // Each shift-and-mask leaves at most 32 significant bits, so the
        // conversion is exact; `try_from` states that instead of asserting it
        // in a comment, and the fallback can never be reached.
        let lane = |shift: u32| u32::try_from((v >> shift) & u128::from(u32::MAX)).unwrap_or(0);
        [lane(96), lane(64), lane(32), lane(0)]
    }

    /// Set from 4 × 32-bit lanes.
    #[must_use]
    pub fn from_u32x4(index: u8, lanes: [u32; 4]) -> Self {
        let v = (u128::from(lanes[0]) << 96)
            | (u128::from(lanes[1]) << 64)
            | (u128::from(lanes[2]) << 32)
            | u128::from(lanes[3]);
        Self::from_u128(index, v)
    }

    /// Read the 16 × 8-bit unsigned byte lanes.
    #[must_use]
    pub fn as_u8x16(self) -> [u8; 16] {
        let v = self.to_u128();
        let mut r = [0u8; 16];
        for (i, elem) in r.iter_mut().enumerate() {
            *elem = ((v >> ((15 - i) * 8)) & 0xFF) as u8;
        }
        r
    }

    /// Set from 16 × 8-bit lanes.
    #[must_use]
    pub fn from_u8x16(index: u8, bytes: [u8; 16]) -> Self {
        let mut v = 0u128;
        for (i, &b) in bytes.iter().enumerate() {
            v |= u128::from(b) << ((15 - i) * 8);
        }
        Self::from_u128(index, v)
    }

    #[must_use]
    pub fn name(self) -> String {
        format!("v{}", self.index)
    }
}

impl fmt::Display for VmxRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ── AltiVec instruction kinds ─────────────────────────────────────────────────

/// AltiVec/VMX instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AltiVecInsn {
    // Integer arithmetic (unsigned/signed)
    Vaddubm { vd: u8, va: u8, vb: u8 },
    Vadduhm { vd: u8, va: u8, vb: u8 },
    Vadduwm { vd: u8, va: u8, vb: u8 },
    Vadduds { vd: u8, va: u8, vb: u8 }, // add unsigned double saturate
    Vadduqs { vd: u8, va: u8, vb: u8 }, // add unsigned quad saturate
    Vaddubs { vd: u8, va: u8, vb: u8 }, // add unsigned byte saturate
    Vaddsbs { vd: u8, va: u8, vb: u8 }, // add signed byte saturate
    Vaddshs { vd: u8, va: u8, vb: u8 }, // add signed halfword saturate
    Vaddsws { vd: u8, va: u8, vb: u8 }, // add signed word saturate
    Vsububm { vd: u8, va: u8, vb: u8 },
    Vsubuhm { vd: u8, va: u8, vb: u8 },
    Vsubuwm { vd: u8, va: u8, vb: u8 },
    Vsubsbs { vd: u8, va: u8, vb: u8 },
    Vsubshs { vd: u8, va: u8, vb: u8 },
    Vsubsws { vd: u8, va: u8, vb: u8 },
    // Multiply / multiply-add
    Vmuleub { vd: u8, va: u8, vb: u8 }, // multiply even unsigned bytes
    Vmuloub { vd: u8, va: u8, vb: u8 }, // multiply odd unsigned bytes
    Vmuleuh { vd: u8, va: u8, vb: u8 },
    Vmulouh { vd: u8, va: u8, vb: u8 },
    Vmulesb { vd: u8, va: u8, vb: u8 },
    Vmulosb { vd: u8, va: u8, vb: u8 },
    Vmulesh { vd: u8, va: u8, vb: u8 },
    Vmulosh { vd: u8, va: u8, vb: u8 },
    // Sum
    Vsum4ubs { vd: u8, va: u8, vb: u8 },
    Vsum4sbs { vd: u8, va: u8, vb: u8 },
    Vsum2sws { vd: u8, va: u8, vb: u8 },
    Vsumsws { vd: u8, va: u8, vb: u8 },
    // Max / Min
    Vmaxub { vd: u8, va: u8, vb: u8 },
    Vmaxuh { vd: u8, va: u8, vb: u8 },
    Vmaxuw { vd: u8, va: u8, vb: u8 },
    Vmaxsb { vd: u8, va: u8, vb: u8 },
    Vmaxsh { vd: u8, va: u8, vb: u8 },
    Vmaxsw { vd: u8, va: u8, vb: u8 },
    Vminub { vd: u8, va: u8, vb: u8 },
    Vminuh { vd: u8, va: u8, vb: u8 },
    Vminuw { vd: u8, va: u8, vb: u8 },
    Vminsb { vd: u8, va: u8, vb: u8 },
    Vminsh { vd: u8, va: u8, vb: u8 },
    Vminsw { vd: u8, va: u8, vb: u8 },
    // Logical
    Vand { vd: u8, va: u8, vb: u8 },
    Vandc { vd: u8, va: u8, vb: u8 },
    Vor { vd: u8, va: u8, vb: u8 },
    Vorc { vd: u8, va: u8, vb: u8 },
    Vxor { vd: u8, va: u8, vb: u8 },
    Vnor { vd: u8, va: u8, vb: u8 },
    // Bitwise selection / permute
    Vsel { vd: u8, va: u8, vb: u8, vc: u8 },
    Vperm { vd: u8, va: u8, vb: u8, vc: u8 },
    Vslo { vd: u8, va: u8, vb: u8 }, // shift left by octet
    Vsro { vd: u8, va: u8, vb: u8 }, // shift right by octet
    // Compare
    Vcmpequb { vd: u8, va: u8, vb: u8, rc: bool },
    Vcmpequh { vd: u8, va: u8, vb: u8, rc: bool },
    Vcmpequw { vd: u8, va: u8, vb: u8, rc: bool },
    Vcmpgtsb { vd: u8, va: u8, vb: u8, rc: bool },
    Vcmpgtsh { vd: u8, va: u8, vb: u8, rc: bool },
    Vcmpgtsw { vd: u8, va: u8, vb: u8, rc: bool },
    Vcmpgtub { vd: u8, va: u8, vb: u8, rc: bool },
    Vcmpgtuh { vd: u8, va: u8, vb: u8, rc: bool },
    Vcmpgtuw { vd: u8, va: u8, vb: u8, rc: bool },
    // Float
    Vaddfp { vd: u8, va: u8, vb: u8 },
    Vsubfp { vd: u8, va: u8, vb: u8 },
    Vmulfp { vd: u8, va: u8, vb: u8 },
    Vmaddfp { vd: u8, va: u8, vb: u8, vc: u8 },
    Vnmsubfp { vd: u8, va: u8, vb: u8, vc: u8 },
    Vcmpeqfp { vd: u8, va: u8, vb: u8, rc: bool },
    Vcmpgtfp { vd: u8, va: u8, vb: u8, rc: bool },
    Vcmpgefp { vd: u8, va: u8, vb: u8, rc: bool },
    Vrefp { vd: u8, vb: u8 },
    Vrsqrtefp { vd: u8, vb: u8 },
    Vlogefp { vd: u8, vb: u8 },
    Vexptefp { vd: u8, vb: u8 },
    // Load / Store
    Lvewx { vd: u8, ra: u8, rb: u8 }, // load vector element word indexed
    Lvxl { vd: u8, ra: u8, rb: u8 },  // load vector indexed last
    Lvx { vd: u8, ra: u8, rb: u8 },   // load vector indexed
    Stvewx { vs: u8, ra: u8, rb: u8 }, // store vector element word indexed
    Stvx { vs: u8, ra: u8, rb: u8 },
    Stvxl { vs: u8, ra: u8, rb: u8 },
    // Shift
    Vslb { vd: u8, va: u8, vb: u8 },
    Vslh { vd: u8, va: u8, vb: u8 },
    Vslw { vd: u8, va: u8, vb: u8 },
    Vsrb { vd: u8, va: u8, vb: u8 },
    Vsrh { vd: u8, va: u8, vb: u8 },
    Vsrw { vd: u8, va: u8, vb: u8 },
    Vsrab { vd: u8, va: u8, vb: u8 },
    Vsrah { vd: u8, va: u8, vb: u8 },
    Vsraw { vd: u8, va: u8, vb: u8 },
    Vrl { vd: u8, va: u8, vb: u8 },
    // Misc
    Mfvscr { vd: u8 },
    Mtvscr { vb: u8 },
    Vspltb { vd: u8, vb: u8, uim: u8 },
    Vsplth { vd: u8, vb: u8, uim: u8 },
    Vspltw { vd: u8, vb: u8, uim: u8 },
    Vspltisb { vd: u8, sim: i8 },
    Vspltish { vd: u8, sim: i8 },
    Vspltisw { vd: u8, sim: i8 },
    Vpkuhum { vd: u8, va: u8, vb: u8 },
    Vpkuwum { vd: u8, va: u8, vb: u8 },
    Vpkuhus { vd: u8, va: u8, vb: u8 },
    Vpkuwus { vd: u8, va: u8, vb: u8 },
    Vpkshus { vd: u8, va: u8, vb: u8 },
    Vpkswus { vd: u8, va: u8, vb: u8 },
    Vpkshss { vd: u8, va: u8, vb: u8 },
    Vpkswss { vd: u8, va: u8, vb: u8 },
    Vupkhsb { vd: u8, vb: u8 },
    Vupkhsh { vd: u8, vb: u8 },
    Vupklsb { vd: u8, vb: u8 },
    Vupklsh { vd: u8, vb: u8 },
    Vmrghb { vd: u8, va: u8, vb: u8 },
    Vmrghh { vd: u8, va: u8, vb: u8 },
    Vmrghw { vd: u8, va: u8, vb: u8 },
    Vmrglb { vd: u8, va: u8, vb: u8 },
    Vmrglh { vd: u8, va: u8, vb: u8 },
    Vmrglw { vd: u8, va: u8, vb: u8 },
}

impl AltiVecInsn {
    /// Return the mnemonic string.
    #[must_use]
    pub const fn mnemonic(&self) -> &'static str {
        match self {
            Self::Vaddubm { .. } => "vaddubm",
            Self::Vadduhm { .. } => "vadduhm",
            Self::Vadduwm { .. } => "vadduwm",
            Self::Vadduds { .. } => "vadduds",
            Self::Vadduqs { .. } => "vadduqs",
            Self::Vaddubs { .. } => "vaddubs",
            Self::Vaddsbs { .. } => "vaddsbs",
            Self::Vaddshs { .. } => "vaddshs",
            Self::Vaddsws { .. } => "vaddsws",
            Self::Vsububm { .. } => "vsububm",
            Self::Vsubuhm { .. } => "vsubuhm",
            Self::Vsubuwm { .. } => "vsubuwm",
            Self::Vsubsbs { .. } => "vsubsbs",
            Self::Vsubshs { .. } => "vsubshs",
            Self::Vsubsws { .. } => "vsubsws",
            Self::Vmuleub { .. } => "vmuleub",
            Self::Vmuloub { .. } => "vmuloub",
            Self::Vmuleuh { .. } => "vmuleuh",
            Self::Vmulouh { .. } => "vmulouh",
            Self::Vmulesb { .. } => "vmulesb",
            Self::Vmulosb { .. } => "vmulosb",
            Self::Vmulesh { .. } => "vmulesh",
            Self::Vmulosh { .. } => "vmulosh",
            Self::Vsum4ubs { .. } => "vsum4ubs",
            Self::Vsum4sbs { .. } => "vsum4sbs",
            Self::Vsum2sws { .. } => "vsum2sws",
            Self::Vsumsws { .. } => "vsumsws",
            Self::Vmaxub { .. } => "vmaxub",
            Self::Vmaxuh { .. } => "vmaxuh",
            Self::Vmaxuw { .. } => "vmaxuw",
            Self::Vmaxsb { .. } => "vmaxsb",
            Self::Vmaxsh { .. } => "vmaxsh",
            Self::Vmaxsw { .. } => "vmaxsw",
            Self::Vminub { .. } => "vminub",
            Self::Vminuh { .. } => "vminuh",
            Self::Vminuw { .. } => "vminuw",
            Self::Vminsb { .. } => "vminsb",
            Self::Vminsh { .. } => "vminsh",
            Self::Vminsw { .. } => "vminsw",
            Self::Vand { .. } => "vand",
            Self::Vandc { .. } => "vandc",
            Self::Vor { .. } => "vor",
            Self::Vorc { .. } => "vorc",
            Self::Vxor { .. } => "vxor",
            Self::Vnor { .. } => "vnor",
            Self::Vsel { .. } => "vsel",
            Self::Vperm { .. } => "vperm",
            Self::Vslo { .. } => "vslo",
            Self::Vsro { .. } => "vsro",
            Self::Vcmpequb { .. } => "vcmpequb",
            Self::Vcmpequh { .. } => "vcmpequh",
            Self::Vcmpequw { .. } => "vcmpequw",
            Self::Vcmpgtsb { .. } => "vcmpgtsb",
            Self::Vcmpgtsh { .. } => "vcmpgtsh",
            Self::Vcmpgtsw { .. } => "vcmpgtsw",
            Self::Vcmpgtub { .. } => "vcmpgtub",
            _ => self.mnemonic_rest(),
        }
    }

    /// Second half of the mnemonic table, split out so that neither arm
    /// list exceeds the length a reader can hold in their head.
    const fn mnemonic_rest(&self) -> &'static str {
        match self {
            Self::Vcmpgtuh { .. } => "vcmpgtuh",
            Self::Vcmpgtuw { .. } => "vcmpgtuw",
            Self::Vaddfp { .. } => "vaddfp",
            Self::Vsubfp { .. } => "vsubfp",
            Self::Vmulfp { .. } => "vmulfp",
            Self::Vmaddfp { .. } => "vmaddfp",
            Self::Vnmsubfp { .. } => "vnmsubfp",
            Self::Vcmpeqfp { .. } => "vcmpeqfp",
            Self::Vcmpgtfp { .. } => "vcmpgtfp",
            Self::Vcmpgefp { .. } => "vcmpgefp",
            Self::Vrefp { .. } => "vrefp",
            Self::Vrsqrtefp { .. } => "vrsqrtefp",
            Self::Vlogefp { .. } => "vlogefp",
            Self::Vexptefp { .. } => "vexptefp",
            Self::Lvewx { .. } => "lvewx",
            Self::Lvxl { .. } => "lvxl",
            Self::Lvx { .. } => "lvx",
            Self::Stvewx { .. } => "stvewx",
            Self::Stvx { .. } => "stvx",
            Self::Stvxl { .. } => "stvxl",
            Self::Vslb { .. } => "vslb",
            Self::Vslh { .. } => "vslh",
            Self::Vslw { .. } => "vslw",
            Self::Vsrb { .. } => "vsrb",
            Self::Vsrh { .. } => "vsrh",
            Self::Vsrw { .. } => "vsrw",
            Self::Vsrab { .. } => "vsrab",
            Self::Vsrah { .. } => "vsrah",
            Self::Vsraw { .. } => "vsraw",
            Self::Vrl { .. } => "vrl",
            Self::Mfvscr { .. } => "mfvscr",
            Self::Mtvscr { .. } => "mtvscr",
            Self::Vspltb { .. } => "vspltb",
            Self::Vsplth { .. } => "vsplth",
            Self::Vspltw { .. } => "vspltw",
            Self::Vspltisb { .. } => "vspltisb",
            Self::Vspltish { .. } => "vspltish",
            Self::Vspltisw { .. } => "vspltisw",
            Self::Vpkuhum { .. } => "vpkuhum",
            Self::Vpkuwum { .. } => "vpkuwum",
            Self::Vpkuhus { .. } => "vpkuhus",
            Self::Vpkuwus { .. } => "vpkuwus",
            Self::Vpkshus { .. } => "vpkshus",
            Self::Vpkswus { .. } => "vpkswus",
            Self::Vpkshss { .. } => "vpkshss",
            Self::Vpkswss { .. } => "vpkswss",
            Self::Vupkhsb { .. } => "vupkhsb",
            Self::Vupkhsh { .. } => "vupkhsh",
            Self::Vupklsb { .. } => "vupklsb",
            Self::Vupklsh { .. } => "vupklsh",
            Self::Vmrghb { .. } => "vmrghb",
            Self::Vmrghh { .. } => "vmrghh",
            Self::Vmrghw { .. } => "vmrghw",
            Self::Vmrglb { .. } => "vmrglb",
            Self::Vmrglh { .. } => "vmrglh",
            Self::Vmrglw { .. } => "vmrglw",
            // Every remaining variant is answered by `mnemonic` before it
            // delegates here, so this arm is unreachable; it exists only so
            // the split table does not have to repeat the first half.
            _ => "",
        }
    }

    /// Disassemble to a human-readable string.
    #[must_use]
    pub fn disassemble(&self) -> String {
        macro_rules! tri {
            ($mn:expr, $vd:expr, $va:expr, $vb:expr) => {
                format!("{} v{}, v{}, v{}", $mn, $vd, $va, $vb)
            };
        }
        macro_rules! quad {
            ($mn:expr, $vd:expr, $va:expr, $vb:expr, $vc:expr) => {
                format!("{} v{}, v{}, v{}, v{}", $mn, $vd, $va, $vb, $vc)
            };
        }
        match self {
            Self::Vaddubm { vd, va, vb } => tri!("vaddubm", vd, va, vb),
            Self::Vadduhm { vd, va, vb } => tri!("vadduhm", vd, va, vb),
            Self::Vadduwm { vd, va, vb } => tri!("vadduwm", vd, va, vb),
            Self::Vadduqs { vd, va, vb } => tri!("vadduqs", vd, va, vb),
            Self::Vaddubs { vd, va, vb } => tri!("vaddubs", vd, va, vb),
            Self::Vaddsbs { vd, va, vb } => tri!("vaddsbs", vd, va, vb),
            Self::Vand { vd, va, vb } => tri!("vand", vd, va, vb),
            Self::Vor { vd, va, vb } => tri!("vor", vd, va, vb),
            Self::Vxor { vd, va, vb } => tri!("vxor", vd, va, vb),
            Self::Vnor { vd, va, vb } => tri!("vnor", vd, va, vb),
            Self::Vsel { vd, va, vb, vc } => quad!("vsel", vd, va, vb, vc),
            Self::Vperm { vd, va, vb, vc } => quad!("vperm", vd, va, vb, vc),
            Self::Vcmpequb { vd, va, vb, rc } => {
                let dot = if *rc { "." } else { "" };
                format!("vcmpequb{dot} v{vd}, v{va}, v{vb}")
            }
            Self::Vcmpequw { vd, va, vb, rc } => {
                let dot = if *rc { "." } else { "" };
                format!("vcmpequw{dot} v{vd}, v{va}, v{vb}")
            }
            Self::Mfvscr { vd } => format!("mfvscr v{vd}"),
            Self::Mtvscr { vb } => format!("mtvscr v{vb}"),
            Self::Vspltisb { vd, sim } => format!("vspltisb v{vd}, {sim}"),
            Self::Vspltish { vd, sim } => format!("vspltish v{vd}, {sim}"),
            Self::Vspltisw { vd, sim } => format!("vspltisw v{vd}, {sim}"),
            Self::Vspltb { vd, vb, uim } => format!("vspltb v{vd}, v{vb}, {uim}"),
            Self::Vsplth { vd, vb, uim } => format!("vsplth v{vd}, v{vb}, {uim}"),
            Self::Vspltw { vd, vb, uim } => format!("vspltw v{vd}, v{vb}, {uim}"),
            Self::Lvx { vd, ra, rb } => format!("lvx v{vd}, r{ra}, r{rb}"),
            Self::Stvx { vs, ra, rb } => format!("stvx v{vs}, r{ra}, r{rb}"),
            Self::Lvewx { vd, ra, rb } => format!("lvewx v{vd}, r{ra}, r{rb}"),
            Self::Stvewx { vs, ra, rb } => format!("stvewx v{vs}, r{ra}, r{rb}"),
            _ => format!("{} ...", self.mnemonic()),
        }
    }
}

impl fmt::Display for AltiVecInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.disassemble())
    }
}

// ── VMX register file ─────────────────────────────────────────────────────────

/// Full VMX register file (v0–v31).
#[derive(Debug, Clone)]
pub struct VmxRegFile {
    pub regs: [VmxRegister; 32],
    pub vscr: VSCR,
}

impl VmxRegFile {
    #[must_use]
    pub fn new() -> Self {
        Self {
            regs: std::array::from_fn(|i| VmxRegister::new(u8::try_from(i).unwrap_or(u8::MAX))),
            vscr: VSCR::default(),
        }
    }

    #[must_use]
    pub const fn get(&self, i: u8) -> &VmxRegister {
        &self.regs[(i & 31) as usize]
    }
    pub const fn set(&mut self, i: u8, v: VmxRegister) {
        self.regs[(i & 31) as usize] = v;
    }
}

impl Default for VmxRegFile {
    fn default() -> Self {
        Self::new()
    }
}

// ── AltiVecDecoder ────────────────────────────────────────────────────────────

/// Decodes 32-bit PowerPC instruction words that encode `AltiVec` operations.
pub struct AltiVecDecoder;

impl AltiVecDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Attempt to decode `word` as an `AltiVec` instruction.
    /// Returns `None` if not an `AltiVec` instruction.
    #[must_use]
    pub const fn decode(&self, word: u32) -> Option<AltiVecInsn> {
        // All AltiVec instructions have primary opcode 4 (bits 31:26 = 0b000100).
        let prim = word >> 26;
        if prim != 4 {
            return None;
        }

        let vd = ((word >> 21) & 31) as u8;
        let va = ((word >> 16) & 31) as u8;
        let vb = ((word >> 11) & 31) as u8;
        let vc = ((word >> 6) & 31) as u8;
        let xo = word & 0x7FF;
        let xo6 = word & 0x3F;
        let rc = (word >> 10) & 1 != 0;
        let uim = ((word >> 16) & 0x1F) as u8;
        let sim = ((word >> 16) & 0x1F) as i8;
        let ra = va;
        let rb = vb;

        Some(match xo {
            0x000 => AltiVecInsn::Vaddubm { vd, va, vb },
            0x040 => AltiVecInsn::Vadduhm { vd, va, vb },
            0x080 => AltiVecInsn::Vadduwm { vd, va, vb },
            0x180 => AltiVecInsn::Vaddubs { vd, va, vb },
            0x100 => AltiVecInsn::Vaddsbs { vd, va, vb },
            0x140 => AltiVecInsn::Vaddshs { vd, va, vb },
            0x0C0 => AltiVecInsn::Vaddsws { vd, va, vb },
            0x400 => AltiVecInsn::Vsububm { vd, va, vb },
            0x440 => AltiVecInsn::Vsubuhm { vd, va, vb },
            0x480 => AltiVecInsn::Vsubuwm { vd, va, vb },
            0x580 => AltiVecInsn::Vsubsbs { vd, va, vb },
            0x540 => AltiVecInsn::Vsubshs { vd, va, vb },
            0x5C0 => AltiVecInsn::Vsubsws { vd, va, vb },
            0x208 => AltiVecInsn::Vmuleub { vd, va, vb },
            0x008 => AltiVecInsn::Vmuloub { vd, va, vb },
            0x248 => AltiVecInsn::Vmuleuh { vd, va, vb },
            0x048 => AltiVecInsn::Vmulouh { vd, va, vb },
            0x600 => AltiVecInsn::Vmaxub { vd, va, vb },
            0x640 => AltiVecInsn::Vmaxuh { vd, va, vb },
            0x680 => AltiVecInsn::Vmaxuw { vd, va, vb },
            0x700 => AltiVecInsn::Vminub { vd, va, vb },
            0x740 => AltiVecInsn::Vminuh { vd, va, vb },
            0x780 => AltiVecInsn::Vminuw { vd, va, vb },
            0x404 => AltiVecInsn::Vand { vd, va, vb },
            0x444 => AltiVecInsn::Vandc { vd, va, vb },
            0x484 => AltiVecInsn::Vor { vd, va, vb },
            0x504 => AltiVecInsn::Vxor { vd, va, vb },
            0x20C => AltiVecInsn::Vspltb { vd, vb, uim },
            0x30C => AltiVecInsn::Vspltisb { vd, sim },
            0x544 => AltiVecInsn::Vnor { vd, va, vb },
            0x1C4 => AltiVecInsn::Lvx { vd, ra, rb },
            0x604 => AltiVecInsn::Vaddfp { vd, va, vb },
            0x644 => AltiVecInsn::Vsubfp { vd, va, vb },
            0x78C => AltiVecInsn::Mfvscr { vd },
            0x78D => AltiVecInsn::Mtvscr { vb },
            0x006 => AltiVecInsn::Vcmpequb { vd, va, vb, rc },
            _ => {
                // Handle 4-operand and special forms.
                if xo6 == 0x2A {
                    return Some(AltiVecInsn::Vsel { vd, va, vb, vc });
                }
                if xo6 == 0x2B {
                    return Some(AltiVecInsn::Vperm { vd, va, vb, vc });
                }
                return None;
            }
        })
    }
}

impl Default for AltiVecDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ── AltiVec execution ─────────────────────────────────────────────────────────

/// Execute an `AltiVec` instruction on the VMX register file.
pub fn execute<S: ::std::hash::BuildHasher>(
    insn: &AltiVecInsn,
    rf: &mut VmxRegFile,
    gpr: &[u64; 32],
    memory: &mut HashMap<u64, u8, S>,
) {
    match insn {
        AltiVecInsn::Vaddubm { vd, va, vb } => {
            let a = rf.get(*va).as_u8x16();
            let b = rf.get(*vb).as_u8x16();
            let mut r = [0u8; 16];
            for i in 0..16 {
                r[i] = a[i].wrapping_add(b[i]);
            }
            rf.set(*vd, VmxRegister::from_u8x16(*vd, r));
        }
        AltiVecInsn::Vsububm { vd, va, vb } => {
            let a = rf.get(*va).as_u8x16();
            let b = rf.get(*vb).as_u8x16();
            let mut r = [0u8; 16];
            for i in 0..16 {
                r[i] = a[i].wrapping_sub(b[i]);
            }
            rf.set(*vd, VmxRegister::from_u8x16(*vd, r));
        }
        AltiVecInsn::Vand { vd, va, vb } => {
            let a = rf.get(*va).to_u128();
            let b = rf.get(*vb).to_u128();
            rf.set(*vd, VmxRegister::from_u128(*vd, a & b));
        }
        AltiVecInsn::Vor { vd, va, vb } => {
            let a = rf.get(*va).to_u128();
            let b = rf.get(*vb).to_u128();
            rf.set(*vd, VmxRegister::from_u128(*vd, a | b));
        }
        AltiVecInsn::Vxor { vd, va, vb } => {
            let a = rf.get(*va).to_u128();
            let b = rf.get(*vb).to_u128();
            rf.set(*vd, VmxRegister::from_u128(*vd, a ^ b));
        }
        AltiVecInsn::Vnor { vd, va, vb } => {
            let a = rf.get(*va).to_u128();
            let b = rf.get(*vb).to_u128();
            rf.set(*vd, VmxRegister::from_u128(*vd, !(a | b)));
        }
        AltiVecInsn::Vsel { vd, va, vb, vc } => {
            let a = rf.get(*va).to_u128();
            let b = rf.get(*vb).to_u128();
            let c = rf.get(*vc).to_u128();
            // VSEL: result = (b & c) | (a & !c)
            let r = (b & c) | (a & !c);
            rf.set(*vd, VmxRegister::from_u128(*vd, r));
        }
        AltiVecInsn::Vspltisb { vd, sim } => {
            let mut r = [0u8; 16];
            r.fill((*sim).cast_unsigned());
            rf.set(*vd, VmxRegister::from_u8x16(*vd, r));
        }
        AltiVecInsn::Vspltisw { vd, sim } => {
            let word = i32::from(*sim).cast_unsigned();
            let lanes = [word; 4];
            rf.set(*vd, VmxRegister::from_u32x4(*vd, lanes));
        }
        AltiVecInsn::Vcmpequb { vd, va, vb, .. } => {
            let a = rf.get(*va).as_u8x16();
            let b = rf.get(*vb).as_u8x16();
            let mut r = [0u8; 16];
            for i in 0..16 {
                r[i] = if a[i] == b[i] { 0xFF } else { 0x00 };
            }
            rf.set(*vd, VmxRegister::from_u8x16(*vd, r));
        }
        AltiVecInsn::Vcmpequw { vd, va, vb, .. } => {
            let a = rf.get(*va).as_u32x4();
            let b = rf.get(*vb).as_u32x4();
            let mut r = [0u32; 4];
            for i in 0..4 {
                r[i] = if a[i] == b[i] { 0xFFFF_FFFFu32 } else { 0 };
            }
            rf.set(*vd, VmxRegister::from_u32x4(*vd, r));
        }
        AltiVecInsn::Mfvscr { vd } => {
            let v = u128::from(rf.vscr.0);
            rf.set(*vd, VmxRegister::from_u128(*vd, v));
        }
        AltiVecInsn::Mtvscr { vb } => {
            let v = rf.get(*vb).to_u128();
            rf.vscr = VSCR(u32::try_from(v).unwrap_or(u32::MAX));
        }
        AltiVecInsn::Lvx { vd, ra, rb } => {
            let addr = gpr[*ra as usize].wrapping_add(gpr[*rb as usize]) & !15;
            let mut bytes = [0u8; 16];
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = *memory.get(&(addr + u64::try_from(i).unwrap_or(u64::MAX))).unwrap_or(&0);
            }
            rf.set(*vd, VmxRegister::from_u8x16(*vd, bytes));
        }
        AltiVecInsn::Stvx { vs, ra, rb } => {
            let addr = gpr[*ra as usize].wrapping_add(gpr[*rb as usize]) & !15;
            let bytes = rf.get(*vs).as_u8x16();
            for (i, &b) in bytes.iter().enumerate() {
                memory.insert(addr + u64::try_from(i).unwrap_or(u64::MAX), b);
            }
        }
        _ => {} // unimplemented instructions are silently ignored
    }
}

// ── AltiVecLifter ─────────────────────────────────────────────────────────────

/// A simple IL node for `AltiVec` semantics.
#[derive(Debug, Clone)]
pub enum AltivecIlNode {
    Assign {
        vd: u8,
        rhs: Box<Self>,
    },
    BinOp {
        op: &'static str,
        va: u8,
        vb: u8,
    },
    TriOp {
        op: &'static str,
        va: u8,
        vb: u8,
        vc: u8,
    },
    UnOp {
        op: &'static str,
        vb: u8,
    },
    Splat {
        op: &'static str,
        imm: i64,
    },
    Unknown,
}

impl fmt::Display for AltivecIlNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Assign { vd, rhs } => write!(f, "v{vd} = {rhs}"),
            Self::BinOp { op, va, vb } => write!(f, "{op}(v{va}, v{vb})"),
            Self::TriOp { op, va, vb, vc } => write!(f, "{op}(v{va}, v{vb}, v{vc})"),
            Self::UnOp { op, vb } => write!(f, "{op}(v{vb})"),
            Self::Splat { op, imm } => write!(f, "{op}({imm})"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Lifts `AltiVec` instructions to IL nodes.
pub struct AltiVecLifter;

impl AltiVecLifter {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn lift(&self, insn: &AltiVecInsn) -> AltivecIlNode {
        match insn {
            AltiVecInsn::Vaddubm { vd, va, vb } => AltivecIlNode::Assign {
                vd: *vd,
                rhs: Box::new(AltivecIlNode::BinOp {
                    op: "vaddubm",
                    va: *va,
                    vb: *vb,
                }),
            },
            AltiVecInsn::Vsububm { vd, va, vb } => AltivecIlNode::Assign {
                vd: *vd,
                rhs: Box::new(AltivecIlNode::BinOp {
                    op: "vsububm",
                    va: *va,
                    vb: *vb,
                }),
            },
            AltiVecInsn::Vand { vd, va, vb } => AltivecIlNode::Assign {
                vd: *vd,
                rhs: Box::new(AltivecIlNode::BinOp {
                    op: "vand",
                    va: *va,
                    vb: *vb,
                }),
            },
            AltiVecInsn::Vor { vd, va, vb } => AltivecIlNode::Assign {
                vd: *vd,
                rhs: Box::new(AltivecIlNode::BinOp {
                    op: "vor",
                    va: *va,
                    vb: *vb,
                }),
            },
            AltiVecInsn::Vxor { vd, va, vb } => AltivecIlNode::Assign {
                vd: *vd,
                rhs: Box::new(AltivecIlNode::BinOp {
                    op: "vxor",
                    va: *va,
                    vb: *vb,
                }),
            },
            AltiVecInsn::Vnor { vd, va, vb } => AltivecIlNode::Assign {
                vd: *vd,
                rhs: Box::new(AltivecIlNode::BinOp {
                    op: "vnor",
                    va: *va,
                    vb: *vb,
                }),
            },
            AltiVecInsn::Vsel { vd, va, vb, vc } => AltivecIlNode::Assign {
                vd: *vd,
                rhs: Box::new(AltivecIlNode::TriOp {
                    op: "vsel",
                    va: *va,
                    vb: *vb,
                    vc: *vc,
                }),
            },
            AltiVecInsn::Vperm { vd, va, vb, vc } => AltivecIlNode::Assign {
                vd: *vd,
                rhs: Box::new(AltivecIlNode::TriOp {
                    op: "vperm",
                    va: *va,
                    vb: *vb,
                    vc: *vc,
                }),
            },
            AltiVecInsn::Mfvscr { vd } => AltivecIlNode::Assign {
                vd: *vd,
                rhs: Box::new(AltivecIlNode::UnOp {
                    op: "mfvscr",
                    vb: 0,
                }),
            },
            AltiVecInsn::Vspltisb { vd, sim } => AltivecIlNode::Assign {
                vd: *vd,
                rhs: Box::new(AltivecIlNode::Splat {
                    op: "vspltisb",
                    imm: i64::from(*sim),
                }),
            },
            AltiVecInsn::Vspltisw { vd, sim } => AltivecIlNode::Assign {
                vd: *vd,
                rhs: Box::new(AltivecIlNode::Splat {
                    op: "vspltisw",
                    imm: i64::from(*sim),
                }),
            },
            _ => AltivecIlNode::Unknown,
        }
    }
}

impl Default for AltiVecLifter {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rf() -> VmxRegFile {
        VmxRegFile::new()
    }
    fn gpr() -> [u64; 32] {
        [0u64; 32]
    }
    fn mem() -> HashMap<u64, u8> {
        HashMap::new()
    }

    // ── VSCR ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_vscr_default() {
        let v = VSCR::default();
        assert!(!v.nj());
        assert!(!v.sat());
    }

    #[test]
    fn test_vscr_set_nj() {
        let mut v = VSCR::default();
        v.set_nj(true);
        assert!(v.nj());
        v.set_nj(false);
        assert!(!v.nj());
    }

    #[test]
    fn test_vscr_set_sat() {
        let mut v = VSCR::default();
        v.set_sat(true);
        assert!(v.sat());
    }

    #[test]
    fn test_vscr_display() {
        let mut v = VSCR::default();
        v.set_sat(true);
        let s = v.to_string();
        assert!(s.contains("SAT=1"), "display='{s}'");
    }

    // ── VmxRegister ──────────────────────────────────────────────────────────

    #[test]
    fn test_vmx_register_u8x16_round_trip() {
        let bytes: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let r = VmxRegister::from_u8x16(0, bytes);
        let out = r.as_u8x16();
        assert_eq!(out, bytes);
    }

    #[test]
    fn test_vmx_register_u32x4_round_trip() {
        let lanes = [
            0x1234_5678u32,
            0xDEAD_BEEFu32,
            0x0000_0001u32,
            0xFFFF_FFFFu32,
        ];
        let r = VmxRegister::from_u32x4(1, lanes);
        let out = r.as_u32x4();
        assert_eq!(out, lanes);
    }

    #[test]
    fn test_vmx_register_name() {
        assert_eq!(VmxRegister::new(0).name(), "v0");
        assert_eq!(VmxRegister::new(31).name(), "v31");
    }

    #[test]
    fn test_vmx_register_wraps_at_31() {
        let r = VmxRegister::new(33);
        assert_eq!(r.index, 1);
    }

    // ── Execute ───────────────────────────────────────────────────────────────

    #[test]
    fn test_execute_vaddubm() {
        let mut regfile = rf();
        let gprs = gpr();
        let mut memory = mem();
        let lhs = [1u8; 16];
        let rhs = [2u8; 16];
        regfile.set(1, VmxRegister::from_u8x16(1, lhs));
        regfile.set(2, VmxRegister::from_u8x16(2, rhs));
        execute(
            &AltiVecInsn::Vaddubm {
                vd: 0,
                va: 1,
                vb: 2,
            },
            &mut regfile,
            &gprs,
            &mut memory,
        );
        let result = regfile.get(0).as_u8x16();
        assert!(result.iter().all(|&byte| byte == 3));
    }

    #[test]
    fn test_execute_vsububm() {
        let mut regfile = rf();
        let gprs = gpr();
        let mut memory = mem();
        let lhs = [5u8; 16];
        let rhs = [3u8; 16];
        regfile.set(1, VmxRegister::from_u8x16(1, lhs));
        regfile.set(2, VmxRegister::from_u8x16(2, rhs));
        execute(
            &AltiVecInsn::Vsububm {
                vd: 0,
                va: 1,
                vb: 2,
            },
            &mut regfile,
            &gprs,
            &mut memory,
        );
        let result = regfile.get(0).as_u8x16();
        assert!(result.iter().all(|&byte| byte == 2));
    }

    #[test]
    fn test_execute_vand() {
        let mut rf = rf();
        let g = gpr();
        let mut m = mem();
        rf.set(
            1,
            VmxRegister::from_u128(1, 0xFFFF_0000_0000_0000_FFFF_0000_0000_0000),
        );
        rf.set(
            2,
            VmxRegister::from_u128(2, 0x00FF_FF00_0000_0000_00FF_FF00_0000_0000),
        );
        execute(
            &AltiVecInsn::Vand {
                vd: 0,
                va: 1,
                vb: 2,
            },
            &mut rf,
            &g,
            &mut m,
        );
        let r = rf.get(0).to_u128();
        assert_eq!(r, 0x00FF_0000_0000_0000_00FF_0000_0000_0000u128);
    }

    #[test]
    fn test_execute_vor() {
        let mut rf = rf();
        let g = gpr();
        let mut m = mem();
        rf.set(
            1,
            VmxRegister::from_u128(1, 0xF0F0_F0F0_F0F0_F0F0_F0F0_F0F0_F0F0_F0F0),
        );
        rf.set(
            2,
            VmxRegister::from_u128(2, 0x0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F),
        );
        execute(
            &AltiVecInsn::Vor {
                vd: 0,
                va: 1,
                vb: 2,
            },
            &mut rf,
            &g,
            &mut m,
        );
        let r = rf.get(0).to_u128();
        assert_eq!(r, 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFFu128);
    }

    #[test]
    fn test_execute_vxor_self_is_zero() {
        let mut rf = rf();
        let g = gpr();
        let mut m = mem();
        rf.set(
            1,
            VmxRegister::from_u128(1, 0xDEAD_BEEF_CAFE_BABE_DEAD_BEEF_CAFE_BABE),
        );
        execute(
            &AltiVecInsn::Vxor {
                vd: 0,
                va: 1,
                vb: 1,
            },
            &mut rf,
            &g,
            &mut m,
        );
        assert_eq!(rf.get(0).to_u128(), 0);
    }

    #[test]
    fn test_execute_vnor() {
        let mut rf = rf();
        let g = gpr();
        let mut m = mem();
        rf.set(1, VmxRegister::from_u128(1, 0));
        rf.set(2, VmxRegister::from_u128(2, 0));
        execute(
            &AltiVecInsn::Vnor {
                vd: 0,
                va: 1,
                vb: 2,
            },
            &mut rf,
            &g,
            &mut m,
        );
        assert_eq!(rf.get(0).to_u128(), u128::MAX);
    }

    #[test]
    fn test_execute_vsel() {
        let mut rf = rf();
        let g = gpr();
        let mut m = mem();
        // vc=all zeros → select all from va
        rf.set(
            1,
            VmxRegister::from_u128(1, 0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA),
        );
        rf.set(
            2,
            VmxRegister::from_u128(2, 0x5555_5555_5555_5555_5555_5555_5555_5555),
        );
        rf.set(3, VmxRegister::from_u128(3, 0)); // select all from va
        execute(
            &AltiVecInsn::Vsel {
                vd: 0,
                va: 1,
                vb: 2,
                vc: 3,
            },
            &mut rf,
            &g,
            &mut m,
        );
        assert_eq!(
            rf.get(0).to_u128(),
            0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA
        );
    }

    #[test]
    fn test_execute_vspltisb() {
        let mut rf = rf();
        let g = gpr();
        let mut m = mem();
        execute(
            &AltiVecInsn::Vspltisb { vd: 0, sim: 42 },
            &mut rf,
            &g,
            &mut m,
        );
        let r = rf.get(0).as_u8x16();
        assert!(r.iter().all(|&x| x == 42));
    }

    #[test]
    fn test_execute_vcmpequb_all_match() {
        let mut rf = rf();
        let g = gpr();
        let mut m = mem();
        let bytes = [0xABu8; 16];
        rf.set(1, VmxRegister::from_u8x16(1, bytes));
        rf.set(2, VmxRegister::from_u8x16(2, bytes));
        execute(
            &AltiVecInsn::Vcmpequb {
                vd: 0,
                va: 1,
                vb: 2,
                rc: false,
            },
            &mut rf,
            &g,
            &mut m,
        );
        let r = rf.get(0).as_u8x16();
        assert!(r.iter().all(|&x| x == 0xFF));
    }

    #[test]
    fn test_execute_vcmpequb_no_match() {
        let mut rf = rf();
        let g = gpr();
        let mut m = mem();
        rf.set(1, VmxRegister::from_u8x16(1, [0u8; 16]));
        rf.set(2, VmxRegister::from_u8x16(2, [1u8; 16]));
        execute(
            &AltiVecInsn::Vcmpequb {
                vd: 0,
                va: 1,
                vb: 2,
                rc: false,
            },
            &mut rf,
            &g,
            &mut m,
        );
        let r = rf.get(0).as_u8x16();
        assert!(r.iter().all(|&x| x == 0));
    }

    #[test]
    fn test_execute_mfvscr() {
        let mut rf = rf();
        let g = gpr();
        let mut m = mem();
        rf.vscr = VSCR(0xDEAD_BEEF);
        execute(&AltiVecInsn::Mfvscr { vd: 0 }, &mut rf, &g, &mut m);
        let v = rf.get(0).to_u128();
        assert_eq!(v, 0xDEAD_BEEF);
    }

    #[test]
    fn test_execute_mtvscr() {
        let mut rf = rf();
        let g = gpr();
        let mut m = mem();
        rf.set(5, VmxRegister::from_u128(5, 0x0001_0001));
        execute(&AltiVecInsn::Mtvscr { vb: 5 }, &mut rf, &g, &mut m);
        assert_eq!(rf.vscr.0, 0x0001_0001);
    }

    #[test]
    fn test_execute_lvx_stvx_round_trip() {
        let mut rf = rf();
        let mut g = gpr();
        let mut m = mem();
        let bytes: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        // Store to memory.
        rf.set(1, VmxRegister::from_u8x16(1, bytes));
        g[2] = 0x100;
        execute(
            &AltiVecInsn::Stvx {
                vs: 1,
                ra: 2,
                rb: 0,
            },
            &mut rf,
            &g,
            &mut m,
        );
        // Load back.
        execute(
            &AltiVecInsn::Lvx {
                vd: 10,
                ra: 2,
                rb: 0,
            },
            &mut rf,
            &g,
            &mut m,
        );
        assert_eq!(rf.get(10).as_u8x16(), bytes);
    }

    // ── AltiVecLifter ─────────────────────────────────────────────────────────

    #[test]
    fn test_lifter_vaddubm() {
        let lifter = AltiVecLifter::new();
        let il = lifter.lift(&AltiVecInsn::Vaddubm {
            vd: 0,
            va: 1,
            vb: 2,
        });
        let s = il.to_string();
        assert!(s.contains("vaddubm"), "IL='{s}'");
        assert!(s.contains("v0"), "IL='{s}'");
    }

    #[test]
    fn test_lifter_vsel() {
        let lifter = AltiVecLifter::new();
        let il = lifter.lift(&AltiVecInsn::Vsel {
            vd: 0,
            va: 1,
            vb: 2,
            vc: 3,
        });
        let s = il.to_string();
        assert!(s.contains("vsel"), "IL='{s}'");
    }

    #[test]
    fn test_lifter_vspltisb() {
        let lifter = AltiVecLifter::new();
        let il = lifter.lift(&AltiVecInsn::Vspltisb { vd: 0, sim: 7 });
        let s = il.to_string();
        assert!(s.contains("vspltisb"), "IL='{s}'");
        assert!(s.contains('7'), "IL='{s}'");
    }

    // ── Mnemonic coverage ─────────────────────────────────────────────────────

    #[test]
    fn test_mnemonic_coverage() {
        let insns: Vec<Box<dyn Fn() -> &'static str>> = vec![
            Box::new(|| {
                AltiVecInsn::Vaddubm {
                    vd: 0,
                    va: 0,
                    vb: 0,
                }
                .mnemonic()
            }),
            Box::new(|| {
                AltiVecInsn::Vxor {
                    vd: 0,
                    va: 0,
                    vb: 0,
                }
                .mnemonic()
            }),
            Box::new(|| {
                AltiVecInsn::Vand {
                    vd: 0,
                    va: 0,
                    vb: 0,
                }
                .mnemonic()
            }),
            Box::new(|| {
                AltiVecInsn::Vnor {
                    vd: 0,
                    va: 0,
                    vb: 0,
                }
                .mnemonic()
            }),
            Box::new(|| {
                AltiVecInsn::Vor {
                    vd: 0,
                    va: 0,
                    vb: 0,
                }
                .mnemonic()
            }),
            Box::new(|| AltiVecInsn::Mfvscr { vd: 0 }.mnemonic()),
            Box::new(|| AltiVecInsn::Mtvscr { vb: 0 }.mnemonic()),
            Box::new(|| {
                AltiVecInsn::Lvewx {
                    vd: 0,
                    ra: 0,
                    rb: 0,
                }
                .mnemonic()
            }),
            Box::new(|| {
                AltiVecInsn::Stvewx {
                    vs: 0,
                    ra: 0,
                    rb: 0,
                }
                .mnemonic()
            }),
        ];
        for f in &insns {
            let m = f();
            assert!(!m.is_empty(), "empty mnemonic");
        }
    }

    #[test]
    fn test_disassembly_vand() {
        let s = AltiVecInsn::Vand {
            vd: 0,
            va: 1,
            vb: 2,
        }
        .disassemble();
        assert!(s.contains("vand"), "disasm='{s}'");
        assert!(s.contains("v0"), "disasm='{s}'");
    }

    #[test]
    fn test_disassembly_vspltisw() {
        let s = AltiVecInsn::Vspltisw { vd: 5, sim: -1 }.disassemble();
        assert!(s.contains("vspltisw"), "disasm='{s}'");
        assert!(s.contains("v5"), "disasm='{s}'");
    }
}
