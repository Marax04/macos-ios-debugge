//! `mips_fpu` — MIPS FPU (Coprocessor 1) for RustRE.
//!
//! Provides [`MipsFpuState`] (FPRs f0-f31 as f64), all FPU instructions,
//! [`FCSRFlags`], and [`MipsFpuLifter`].

use std::collections::HashMap;
use std::fmt;

// ── FPR file ──────────────────────────────────────────────────────────────────

/// The MIPS FPU register file — 32 × f64 (in 64-bit FPU mode).
/// In 32-bit FPU mode, even-numbered registers hold 32-bit floats.
#[derive(Debug, Clone)]
pub struct MipsFpuState {
    /// f0–f31 in double precision.
    pub fpr: [f64; 32],
    /// Floating-Point Control and Status Register (FCSR).
    pub fcsr: u32,
    /// FPU Implementation Register (FIR).
    pub fir: u32,
    /// Whether 64-bit FPU mode is active.
    pub fr_bit: bool,
}

impl MipsFpuState {
    /// Create a zeroed FPU state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            fpr: [0.0f64; 32],
            fcsr: 0,
            fir: 0x0000_0A00,
            fr_bit: true,
        }
    }

    /// Read a single-precision float from register `f`.
    #[must_use]
    pub const fn get_single(&self, f: usize) -> f32 {
        self.fpr[f & 31] as f32
    }

    /// Read a double-precision float from register `f`.
    #[must_use]
    pub const fn get_double(&self, f: usize) -> f64 {
        self.fpr[f & 31]
    }

    /// Write a single-precision float to register `f`.
    pub const fn set_single(&mut self, f: usize, v: f32) {
        self.fpr[f & 31] = v as f64;
    }

    /// Write a double-precision float to register `f`.
    pub const fn set_double(&mut self, f: usize, v: f64) {
        self.fpr[f & 31] = v;
    }

    /// Set the FCC (condition code) bit `cc` in FCSR.
    pub const fn set_fcc(&mut self, cc: u8, val: bool) {
        // MIPS FCSR has FCC0 at bit 23 and FCC1-7 at bits 25-31.
        // cc must be in 0..=7; clamp to avoid a panic on shift >= 32.
        let cc = cc & 7;
        let shift = if cc == 0 { 23u32 } else { 24 + cc as u32 };
        if val {
            self.fcsr |= 1 << shift;
        } else {
            self.fcsr &= !(1 << shift);
        }
    }

    /// Get the FCC bit `cc`.
    #[must_use]
    pub const fn get_fcc(&self, cc: u8) -> bool {
        let cc = cc & 7;
        let shift = if cc == 0 { 23u32 } else { 24 + cc as u32 };
        self.fcsr & (1 << shift) != 0
    }

    /// Clear all condition codes.
    pub const fn clear_fcc(&mut self) {
        // FCC0 = bit 23, FCC1-7 = bits 25-31.
        self.fcsr &= !(0xFF80_0000u32);
    }
}

impl Default for MipsFpuState {
    fn default() -> Self {
        Self::new()
    }
}

/// The low 32 bits of a 64-bit GPR, as written to a 32-bit FPU register.
///
/// MIPS `mtc1`/`ctc1` move the low word of the GPR by definition; masking
/// makes that explicit and provably in range.
#[must_use]
pub const fn low_u32(value: u64) -> u32 {
    (value & 0xFFFF_FFFF) as u32
}

// ── FCSRFlags ────────────────────────────────────────────────────────────────

/// Cause and flag bits from the FCSR register.
/// The five IEEE-754 exception flags of FCSR, packed at their hardware bit
/// positions instead of as separate `bool` fields.
///
/// Packing keeps the set addressable as one value (mask, union, compare) and
/// mirrors how the FCSR register actually stores them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FpuExceptionFlags(u32);

impl FpuExceptionFlags {
    /// Inexact result (FCSR bit 2).
    pub const INEXACT: u32 = 1 << 2;
    /// Underflow (FCSR bit 3).
    pub const UNDERFLOW: u32 = 1 << 3;
    /// Overflow (FCSR bit 4).
    pub const OVERFLOW: u32 = 1 << 4;
    /// Division by zero (FCSR bit 5).
    pub const DIV_ZERO: u32 = 1 << 5;
    /// Invalid operation (FCSR bit 6).
    pub const INVALID: u32 = 1 << 6;
    /// Every exception bit this type models.
    pub const ALL: u32 =
        Self::INEXACT | Self::UNDERFLOW | Self::OVERFLOW | Self::DIV_ZERO | Self::INVALID;

    /// Extract the exception bits from a raw FCSR value.
    #[must_use]
    pub const fn from_fcsr(fcsr: u32) -> Self {
        Self(fcsr & Self::ALL)
    }

    /// The raw exception bits, positioned as in FCSR.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// True when every bit in `mask` is set.
    #[must_use]
    pub const fn contains(self, mask: u32) -> bool {
        self.0 & mask == mask
    }

    /// Return a copy with `mask` set or cleared.
    #[must_use]
    pub const fn with(self, mask: u32, on: bool) -> Self {
        Self(if on { self.0 | mask } else { self.0 & !mask })
    }

    /// Inexact result flag.
    #[must_use]
    pub const fn inexact(self) -> bool {
        self.contains(Self::INEXACT)
    }

    /// Underflow flag.
    #[must_use]
    pub const fn underflow(self) -> bool {
        self.contains(Self::UNDERFLOW)
    }

    /// Overflow flag.
    #[must_use]
    pub const fn overflow(self) -> bool {
        self.contains(Self::OVERFLOW)
    }

    /// Division-by-zero flag.
    #[must_use]
    pub const fn div_zero(self) -> bool {
        self.contains(Self::DIV_ZERO)
    }

    /// Invalid-operation flag.
    #[must_use]
    pub const fn invalid(self) -> bool {
        self.contains(Self::INVALID)
    }

    /// True when no exception is recorded.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Cause and flag bits from the FCSR register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FCSRFlags {
    /// IEEE-754 exception flags.
    pub exceptions: FpuExceptionFlags,
    /// Flush-to-zero mode.
    pub flush_zero: bool,
    /// Current rounding mode (RM field, bits 1:0).
    pub rounding: u8,
}

impl FCSRFlags {
    /// Decode the flag and rounding fields of a raw FCSR value.
    #[must_use]
    pub const fn from_fcsr(fcsr: u32) -> Self {
        Self {
            exceptions: FpuExceptionFlags::from_fcsr(fcsr),
            flush_zero: fcsr & (1 << 24) != 0,
            rounding: (fcsr & 0x3) as u8,
        }
    }

    /// Re-encode these flags into a raw FCSR value.
    #[must_use]
    pub const fn to_fcsr(&self) -> u32 {
        let mut v = self.rounding as u32 | self.exceptions.bits();
        if self.flush_zero {
            v |= 1 << 24;
        }
        v
    }

    /// Inexact result flag.
    #[must_use]
    pub const fn inexact(&self) -> bool {
        self.exceptions.inexact()
    }

    /// Underflow flag.
    #[must_use]
    pub const fn underflow(&self) -> bool {
        self.exceptions.underflow()
    }

    /// Overflow flag.
    #[must_use]
    pub const fn overflow(&self) -> bool {
        self.exceptions.overflow()
    }

    /// Division-by-zero flag.
    #[must_use]
    pub const fn div_zero(&self) -> bool {
        self.exceptions.div_zero()
    }

    /// Invalid-operation flag.
    #[must_use]
    pub const fn invalid(&self) -> bool {
        self.exceptions.invalid()
    }

    /// Return the rounding mode name.
    #[must_use]
    pub const fn rounding_name(&self) -> &'static str {
        match self.rounding {
            0 => "round-nearest-even",
            1 => "round-toward-zero",
            2 => "round-toward-plus-infinity",
            3 => "round-toward-minus-infinity",
            _ => "unknown",
        }
    }
}

impl fmt::Display for FCSRFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FCSRFlags{{inexact={}, underflow={}, overflow={}, div_zero={}, invalid={}, rm={}}}",
            self.inexact(),
            self.underflow(),
            self.overflow(),
            self.div_zero(),
            self.invalid(),
            self.rounding_name()
        )
    }
}

// ── FPU condition codes ───────────────────────────────────────────────────────

/// MIPS FPU comparison condition codes (for C.cond.fmt).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FpuCondition {
    F,    // False (always false)
    Un,   // Unordered
    Eq,   // Equal
    Ueq,  // Unordered or Equal
    Olt,  // Ordered Less Than
    Ult,  // Unordered or Less Than
    Ole,  // Ordered Less or Equal
    Ule,  // Unordered or Less or Equal
    Sf,   // Signaling False
    Ngle, // Not (Greater or Less or Equal)
    Seq,  // Signaling Equal
    Ngl,  // Not (Greater or Less)
    Lt,   // Less Than
    Nge,  // Not (Greater or Equal)
    Le,   // Less or Equal
    Ngt,  // Not Greater Than
}

impl FpuCondition {
    /// Evaluate condition for two f64 values.
    ///
    /// These are IEEE-754 comparisons exactly as the hardware defines them, so
    /// the exact-equality and unordered (NaN) cases are deliberate. They are
    /// expressed through [`f64::partial_cmp`] so the ordered/unordered result
    /// is explicit rather than hidden behind `==` and negated `>=`.
    #[must_use]
    pub fn evaluate_d(&self, a: f64, b: f64) -> bool {
        use core::cmp::Ordering;
        let ord = a.partial_cmp(&b);
        let unordered = ord.is_none();
        let is_eq = ord == Some(Ordering::Equal);
        let is_lt = ord == Some(Ordering::Less);
        match self {
            Self::F | Self::Sf => false,
            Self::Un | Self::Ngle => unordered,
            Self::Eq | Self::Seq => is_eq,
            Self::Ueq | Self::Ngl => unordered || is_eq,
            Self::Olt | Self::Lt => is_lt,
            Self::Ult | Self::Nge => unordered || is_lt,
            Self::Ole | Self::Le => is_lt || is_eq,
            Self::Ule | Self::Ngt => unordered || is_lt || is_eq,
        }
    }

    /// Mnemonic suffix.
    #[must_use]
    pub const fn suffix(&self) -> &'static str {
        match self {
            Self::F => "f",
            Self::Un => "un",
            Self::Eq => "eq",
            Self::Ueq => "ueq",
            Self::Olt => "olt",
            Self::Ult => "ult",
            Self::Ole => "ole",
            Self::Ule => "ule",
            Self::Sf => "sf",
            Self::Ngle => "ngle",
            Self::Seq => "seq",
            Self::Ngl => "ngl",
            Self::Lt => "lt",
            Self::Nge => "nge",
            Self::Le => "le",
            Self::Ngt => "ngt",
        }
    }
}

// ── FPU instruction kind ─────────────────────────────────────────────────────

/// MIPS FPU instruction (Coprocessor 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MipsFpuInsn {
    // Arithmetic
    AddS {
        fd: u8,
        fs: u8,
        ft: u8,
    },
    AddD {
        fd: u8,
        fs: u8,
        ft: u8,
    },
    SubS {
        fd: u8,
        fs: u8,
        ft: u8,
    },
    SubD {
        fd: u8,
        fs: u8,
        ft: u8,
    },
    MulS {
        fd: u8,
        fs: u8,
        ft: u8,
    },
    MulD {
        fd: u8,
        fs: u8,
        ft: u8,
    },
    DivS {
        fd: u8,
        fs: u8,
        ft: u8,
    },
    DivD {
        fd: u8,
        fs: u8,
        ft: u8,
    },
    SqrtS {
        fd: u8,
        fs: u8,
    },
    SqrtD {
        fd: u8,
        fs: u8,
    },
    AbsS {
        fd: u8,
        fs: u8,
    },
    AbsD {
        fd: u8,
        fs: u8,
    },
    MovS {
        fd: u8,
        fs: u8,
    },
    MovD {
        fd: u8,
        fs: u8,
    },
    NegS {
        fd: u8,
        fs: u8,
    },
    NegD {
        fd: u8,
        fs: u8,
    },
    // Conversions
    CvtSD {
        fd: u8,
        fs: u8,
    }, // CVT.S.D
    CvtDS {
        fd: u8,
        fs: u8,
    }, // CVT.D.S
    CvtWS {
        fd: u8,
        fs: u8,
    }, // CVT.W.S
    CvtWD {
        fd: u8,
        fs: u8,
    }, // CVT.W.D
    CvtLs {
        fd: u8,
        fs: u8,
    }, // CVT.L.S
    CvtLD {
        fd: u8,
        fs: u8,
    }, // CVT.L.D
    CvtSW {
        fd: u8,
        fs: u8,
    }, // CVT.S.W
    CvtDW {
        fd: u8,
        fs: u8,
    }, // CVT.D.W
    // Rounding
    RoundWS {
        fd: u8,
        fs: u8,
    },
    RoundWD {
        fd: u8,
        fs: u8,
    },
    TruncWS {
        fd: u8,
        fs: u8,
    },
    TruncWD {
        fd: u8,
        fs: u8,
    },
    CeilWS {
        fd: u8,
        fs: u8,
    },
    CeilWD {
        fd: u8,
        fs: u8,
    },
    FloorWS {
        fd: u8,
        fs: u8,
    },
    FloorWD {
        fd: u8,
        fs: u8,
    },
    // Comparison
    CCond {
        cc: u8,
        fs: u8,
        ft: u8,
        cond: FpuCondition,
        fmt_d: bool,
    },
    // Conditional move (MOVT.S, MOVF.S, MOVT.D, MOVF.D)
    MovtS {
        fd: u8,
        fs: u8,
        cc: u8,
    },
    MovfS {
        fd: u8,
        fs: u8,
        cc: u8,
    },
    MovtD {
        fd: u8,
        fs: u8,
        cc: u8,
    },
    MovfD {
        fd: u8,
        fs: u8,
        cc: u8,
    },
    // Paired-Single (MIPS IV+)
    AddPS {
        fd: u8,
        fs: u8,
        ft: u8,
    },
    SubPS {
        fd: u8,
        fs: u8,
        ft: u8,
    },
    MulPS {
        fd: u8,
        fs: u8,
        ft: u8,
    },
    AbsPS {
        fd: u8,
        fs: u8,
    },
    NegPS {
        fd: u8,
        fs: u8,
    },
    MovPS {
        fd: u8,
        fs: u8,
    },
    // Load/Store
    Lwc1 {
        ft: u8,
        base: u8,
        offset: i16,
    },
    Ldc1 {
        ft: u8,
        base: u8,
        offset: i16,
    },
    Swc1 {
        ft: u8,
        base: u8,
        offset: i16,
    },
    Sdc1 {
        ft: u8,
        base: u8,
        offset: i16,
    },
    // Move to/from GP
    MfC1 {
        rt: u8,
        fs: u8,
    },
    MtC1 {
        rt: u8,
        fs: u8,
    },
    DmfC1 {
        rt: u8,
        fs: u8,
    },
    DmtC1 {
        rt: u8,
        fs: u8,
    },
    // CFC1 / CTC1
    CfC1 {
        rt: u8,
        fs: u8,
    },
    CtC1 {
        rt: u8,
        fs: u8,
    },
    // Branch on FPU condition
    Bc1t {
        cc: u8,
        offset: i16,
    },
    Bc1f {
        cc: u8,
        offset: i16,
    },
    Bc1tl {
        cc: u8,
        offset: i16,
    },
    Bc1fl {
        cc: u8,
        offset: i16,
    },
}

impl MipsFpuInsn {
    /// Execute this instruction, modifying `fpu` and `gpr` (r0–r31).
    pub fn execute(
        &self,
        fpu: &mut MipsFpuState,
        gpr: &mut [u64; 32],
        memory: &mut HashMap<u64, u8>,
        pc: u64,
    ) -> u64 {
        let mut next_pc = pc.wrapping_add(4);
        match *self {
            // ── Arithmetic ──────────────────────────────────────────────────
            Self::AddS { fd, fs, ft } => {
                let r = fpu.get_single(fs as usize) + fpu.get_single(ft as usize);
                fpu.set_single(fd as usize, r);
            }
            Self::AddD { fd, fs, ft }
            | Self::AddPS { fd, fs, ft } => {
                let r = fpu.get_double(fs as usize) + fpu.get_double(ft as usize);
                fpu.set_double(fd as usize, r);
            }
            Self::SubS { fd, fs, ft } => {
                let r = fpu.get_single(fs as usize) - fpu.get_single(ft as usize);
                fpu.set_single(fd as usize, r);
            }
            Self::SubD { fd, fs, ft }
            | Self::SubPS { fd, fs, ft } => {
                let r = fpu.get_double(fs as usize) - fpu.get_double(ft as usize);
                fpu.set_double(fd as usize, r);
            }
            Self::MulS { fd, fs, ft } => {
                let r = fpu.get_single(fs as usize) * fpu.get_single(ft as usize);
                fpu.set_single(fd as usize, r);
            }
            Self::MulD { fd, fs, ft }
            | Self::MulPS { fd, fs, ft } => {
                let r = fpu.get_double(fs as usize) * fpu.get_double(ft as usize);
                fpu.set_double(fd as usize, r);
            }
            Self::DivS { fd, fs, ft } => {
                let r = fpu.get_single(fs as usize) / fpu.get_single(ft as usize);
                fpu.set_single(fd as usize, r);
            }
            Self::DivD { fd, fs, ft } => {
                let r = fpu.get_double(fs as usize) / fpu.get_double(ft as usize);
                fpu.set_double(fd as usize, r);
            }
            Self::SqrtS { fd, fs } => {
                let r = fpu.get_single(fs as usize).sqrt();
                fpu.set_single(fd as usize, r);
            }
            Self::SqrtD { fd, fs } => {
                let r = fpu.get_double(fs as usize).sqrt();
                fpu.set_double(fd as usize, r);
            }
            Self::AbsS { fd, fs } => {
                let r = fpu.get_single(fs as usize).abs();
                fpu.set_single(fd as usize, r);
            }
            Self::AbsD { fd, fs }
            | Self::AbsPS { fd, fs } => {
                let r = fpu.get_double(fs as usize).abs();
                fpu.set_double(fd as usize, r);
            }
            Self::MovS { fd, fs } => {
                let r = fpu.get_single(fs as usize);
                fpu.set_single(fd as usize, r);
            }
            Self::MovD { fd, fs }
            | Self::MovPS { fd, fs } => {
                let r = fpu.get_double(fs as usize);
                fpu.set_double(fd as usize, r);
            }
            Self::NegS { fd, fs } => {
                let r = -fpu.get_single(fs as usize);
                fpu.set_single(fd as usize, r);
            }
            Self::NegD { fd, fs }
            | Self::NegPS { fd, fs } => {
                let r = -fpu.get_double(fs as usize);
                fpu.set_double(fd as usize, r);
            }
            // ── Conversions ──────────────────────────────────────────────────
            Self::CvtSD { fd, fs } => {
                let r = fpu.get_double(fs as usize) as f32;
                fpu.set_single(fd as usize, r);
            }
            Self::CvtDS { fd, fs } => {
                let r = f64::from(fpu.get_single(fs as usize));
                fpu.set_double(fd as usize, r);
            }
            Self::CvtWS { fd, fs } => {
                let r = fpu.get_single(fs as usize) as i32 as f32;
                fpu.set_single(fd as usize, r);
            }
            Self::CvtWD { fd, fs } => {
                let r = f64::from(fpu.get_double(fs as usize) as i32);
                fpu.set_double(fd as usize, r);
            }
            Self::CvtLs { fd, fs } => {
                let r = fpu.get_single(fs as usize) as i64 as f64;
                fpu.fpr[fd as usize] = r;
            }
            Self::CvtLD { fd, fs } => {
                let r = fpu.get_double(fs as usize) as i64 as f64;
                fpu.fpr[fd as usize] = r;
            }
            Self::CvtSW { fd, fs } => {
                let i = fpu.get_single(fs as usize) as i32;
                fpu.set_single(fd as usize, i as f32);
            }
            Self::CvtDW { fd, fs } => {
                let i = fpu.get_double(fs as usize) as i32;
                fpu.set_double(fd as usize, f64::from(i));
            }
            // ── Rounding ─────────────────────────────────────────────────────
            Self::RoundWS { fd, fs } => {
                let r = fpu.get_single(fs as usize).round();
                fpu.set_single(fd as usize, r);
            }
            Self::RoundWD { fd, fs } => {
                let r = fpu.get_double(fs as usize).round();
                fpu.set_double(fd as usize, r);
            }
            Self::TruncWS { fd, fs } => {
                let r = fpu.get_single(fs as usize).trunc();
                fpu.set_single(fd as usize, r);
            }
            Self::TruncWD { fd, fs } => {
                let r = fpu.get_double(fs as usize).trunc();
                fpu.set_double(fd as usize, r);
            }
            Self::CeilWS { fd, fs } => {
                let r = fpu.get_single(fs as usize).ceil();
                fpu.set_single(fd as usize, r);
            }
            Self::CeilWD { fd, fs } => {
                let r = fpu.get_double(fs as usize).ceil();
                fpu.set_double(fd as usize, r);
            }
            Self::FloorWS { fd, fs } => {
                let r = fpu.get_single(fs as usize).floor();
                fpu.set_single(fd as usize, r);
            }
            Self::FloorWD { fd, fs } => {
                let r = fpu.get_double(fs as usize).floor();
                fpu.set_double(fd as usize, r);
            }
            // ── Comparison ───────────────────────────────────────────────────
            Self::CCond {
                cc,
                fs,
                ft,
                cond,
                fmt_d,
            } => {
                let result = if fmt_d {
                    cond.evaluate_d(fpu.get_double(fs as usize), fpu.get_double(ft as usize))
                } else {
                    cond.evaluate_d(
                        f64::from(fpu.get_single(fs as usize)),
                        f64::from(fpu.get_single(ft as usize)),
                    )
                };
                fpu.set_fcc(cc, result);
            }
            // ── Conditional move ─────────────────────────────────────────────
            Self::MovtS { fd, fs, cc } => {
                if fpu.get_fcc(cc) {
                    let v = fpu.get_single(fs as usize);
                    fpu.set_single(fd as usize, v);
                }
            }
            Self::MovfS { fd, fs, cc } => {
                if !fpu.get_fcc(cc) {
                    let v = fpu.get_single(fs as usize);
                    fpu.set_single(fd as usize, v);
                }
            }
            Self::MovtD { fd, fs, cc } => {
                if fpu.get_fcc(cc) {
                    let v = fpu.get_double(fs as usize);
                    fpu.set_double(fd as usize, v);
                }
            }
            Self::MovfD { fd, fs, cc } => {
                if !fpu.get_fcc(cc) {
                    let v = fpu.get_double(fs as usize);
                    fpu.set_double(fd as usize, v);
                }
            }
            // ── Paired-single ─────────────────────────────────────────────────
            // ── Load/Store ───────────────────────────────────────────────────
            Self::Lwc1 { ft, base, offset } => {
                let addr = (gpr[base as usize].cast_signed() + i64::from(offset)).cast_unsigned();
                let b0 = u32::from(*memory.get(&addr).unwrap_or(&0));
                let b1 = u32::from(*memory.get(&(addr + 1)).unwrap_or(&0));
                let b2 = u32::from(*memory.get(&(addr + 2)).unwrap_or(&0));
                let b3 = u32::from(*memory.get(&(addr + 3)).unwrap_or(&0));
                let bits = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
                fpu.fpr[ft as usize] = f64::from(f32::from_bits(bits));
            }
            Self::Ldc1 { ft, base, offset } => {
                let addr = (gpr[base as usize].cast_signed() + i64::from(offset)).cast_unsigned();
                let mut bits = 0u64;
                for i in 0..8u64 {
                    bits |= u64::from(*memory.get(&(addr + i)).unwrap_or(&0)) << (i * 8);
                }
                fpu.fpr[ft as usize] = f64::from_bits(bits);
            }
            Self::Swc1 { ft, base, offset } => {
                let addr = (gpr[base as usize].cast_signed() + i64::from(offset)).cast_unsigned();
                let bits = (fpu.fpr[ft as usize] as f32).to_bits();
                for i in 0..4u64 {
                    memory.insert(addr + i, ((bits >> (i * 8)) & 0xFF) as u8);
                }
            }
            Self::Sdc1 { ft, base, offset } => {
                let addr = (gpr[base as usize].cast_signed() + i64::from(offset)).cast_unsigned();
                let bits = fpu.fpr[ft as usize].to_bits();
                for i in 0..8u64 {
                    memory.insert(addr + i, ((bits >> (i * 8)) & 0xFF) as u8);
                }
            }
            // ── Move to/from GP ───────────────────────────────────────────────
            Self::MfC1 { rt, fs } => {
                gpr[rt as usize] = u64::from((fpu.fpr[fs as usize] as f32).to_bits());
            }
            Self::MtC1 { rt, fs } => {
                let bits = low_u32(gpr[rt as usize]);
                fpu.fpr[fs as usize] = f64::from(f32::from_bits(bits));
            }
            Self::DmfC1 { rt, fs } => {
                gpr[rt as usize] = fpu.fpr[fs as usize].to_bits();
            }
            Self::DmtC1 { rt, fs } => {
                fpu.fpr[fs as usize] = f64::from_bits(gpr[rt as usize]);
            }
            Self::CfC1 { rt, fs } => {
                gpr[rt as usize] = if fs == 31 {
                    u64::from(fpu.fcsr)
                } else {
                    u64::from(fpu.fir)
                };
            }
            Self::CtC1 { rt, fs } => {
                if fs == 31 {
                    fpu.fcsr = low_u32(gpr[rt as usize]);
                }
            }
            // ── Branches ─────────────────────────────────────────────────────
            Self::Bc1t { cc, offset }
            | Self::Bc1tl { cc, offset } => {
                if fpu.get_fcc(cc) {
                    next_pc = (pc.cast_signed() + 4 + i64::from(offset) * 4).cast_unsigned();
                }
            }
            Self::Bc1f { cc, offset }
            | Self::Bc1fl { cc, offset } => {
                if !fpu.get_fcc(cc) {
                    next_pc = (pc.cast_signed() + 4 + i64::from(offset) * 4).cast_unsigned();
                }
            }
        }
        next_pc
    }

    /// Return a human-readable disassembly string.
    #[must_use]
    pub fn disassemble(&self) -> String {
        match *self {
            Self::AddS { fd, fs, ft } => format!("add.s   f{fd}, f{fs}, f{ft}"),
            Self::AddD { fd, fs, ft } => format!("add.d   f{fd}, f{fs}, f{ft}"),
            Self::SubS { fd, fs, ft } => format!("sub.s   f{fd}, f{fs}, f{ft}"),
            Self::SubD { fd, fs, ft } => format!("sub.d   f{fd}, f{fs}, f{ft}"),
            Self::MulS { fd, fs, ft } => format!("mul.s   f{fd}, f{fs}, f{ft}"),
            Self::MulD { fd, fs, ft } => format!("mul.d   f{fd}, f{fs}, f{ft}"),
            Self::DivS { fd, fs, ft } => format!("div.s   f{fd}, f{fs}, f{ft}"),
            Self::DivD { fd, fs, ft } => format!("div.d   f{fd}, f{fs}, f{ft}"),
            Self::SqrtS { fd, fs } => format!("sqrt.s  f{fd}, f{fs}"),
            Self::SqrtD { fd, fs } => format!("sqrt.d  f{fd}, f{fs}"),
            Self::AbsS { fd, fs } => format!("abs.s   f{fd}, f{fs}"),
            Self::AbsD { fd, fs } => format!("abs.d   f{fd}, f{fs}"),
            Self::MovS { fd, fs } => format!("mov.s   f{fd}, f{fs}"),
            Self::MovD { fd, fs } => format!("mov.d   f{fd}, f{fs}"),
            Self::NegS { fd, fs } => format!("neg.s   f{fd}, f{fs}"),
            Self::NegD { fd, fs } => format!("neg.d   f{fd}, f{fs}"),
            Self::CvtSD { fd, fs } => format!("cvt.s.d f{fd}, f{fs}"),
            Self::CvtDS { fd, fs } => format!("cvt.d.s f{fd}, f{fs}"),
            Self::CvtWS { fd, fs } => format!("cvt.w.s f{fd}, f{fs}"),
            Self::CvtWD { fd, fs } => format!("cvt.w.d f{fd}, f{fs}"),
            Self::TruncWS { fd, fs } => format!("trunc.w.s f{fd}, f{fs}"),
            Self::TruncWD { fd, fs } => format!("trunc.w.d f{fd}, f{fs}"),
            Self::RoundWS { fd, fs } => format!("round.w.s f{fd}, f{fs}"),
            Self::RoundWD { fd, fs } => format!("round.w.d f{fd}, f{fs}"),
            Self::CeilWS { fd, fs } => format!("ceil.w.s  f{fd}, f{fs}"),
            Self::CeilWD { fd, fs } => format!("ceil.w.d  f{fd}, f{fs}"),
            Self::FloorWS { fd, fs } => format!("floor.w.s f{fd}, f{fs}"),
            Self::FloorWD { fd, fs } => format!("floor.w.d f{fd}, f{fs}"),
            Self::CCond {
                cc,
                fs,
                ft,
                cond,
                fmt_d,
            } => {
                let fmt = if fmt_d { "d" } else { "s" };
                format!("c.{}.{} ${cc}, f{fs}, f{ft}", cond.suffix(), fmt)
            }
            Self::MovtS { fd, fs, cc } => format!("movt.s  f{fd}, f{fs}, ${cc}"),
            Self::MovfS { fd, fs, cc } => format!("movf.s  f{fd}, f{fs}, ${cc}"),
            Self::MovtD { fd, fs, cc } => format!("movt.d  f{fd}, f{fs}, ${cc}"),
            Self::MovfD { fd, fs, cc } => format!("movf.d  f{fd}, f{fs}, ${cc}"),
            Self::AddPS { fd, fs, ft } => format!("add.ps  f{fd}, f{fs}, f{ft}"),
            Self::SubPS { fd, fs, ft } => format!("sub.ps  f{fd}, f{fs}, f{ft}"),
            Self::MulPS { fd, fs, ft } => format!("mul.ps  f{fd}, f{fs}, f{ft}"),
            Self::AbsPS { fd, fs } => format!("abs.ps  f{fd}, f{fs}"),
            Self::NegPS { fd, fs } => format!("neg.ps  f{fd}, f{fs}"),
            Self::MovPS { fd, fs } => format!("mov.ps  f{fd}, f{fs}"),
            Self::Lwc1 { ft, base, offset } => format!("lwc1    f{ft}, {offset}(r{base})"),
            Self::Ldc1 { ft, base, offset } => format!("ldc1    f{ft}, {offset}(r{base})"),
            Self::Swc1 { ft, base, offset } => format!("swc1    f{ft}, {offset}(r{base})"),
            Self::Sdc1 { ft, base, offset } => format!("sdc1    f{ft}, {offset}(r{base})"),
            Self::MfC1 { rt, fs } => format!("mfc1    r{rt}, f{fs}"),
            Self::MtC1 { rt, fs } => format!("mtc1    r{rt}, f{fs}"),
            Self::DmfC1 { rt, fs } => format!("dmfc1   r{rt}, f{fs}"),
            Self::DmtC1 { rt, fs } => format!("dmtc1   r{rt}, f{fs}"),
            Self::CfC1 { rt, fs } => format!("cfc1    r{rt}, f{fs}"),
            Self::CtC1 { rt, fs } => format!("ctc1    r{rt}, f{fs}"),
            Self::Bc1t { cc, offset } => format!("bc1t    ${cc}, {offset}"),
            Self::Bc1f { cc, offset } => format!("bc1f    ${cc}, {offset}"),
            Self::Bc1tl { cc, offset } => format!("bc1tl   ${cc}, {offset}"),
            Self::Bc1fl { cc, offset } => format!("bc1fl   ${cc}, {offset}"),
            Self::CvtLs { fd, fs } => format!("cvt.l.s f{fd}, f{fs}"),
            Self::CvtLD { fd, fs } => format!("cvt.l.d f{fd}, f{fs}"),
            Self::CvtSW { fd, fs } => format!("cvt.s.w f{fd}, f{fs}"),
            Self::CvtDW { fd, fs } => format!("cvt.d.w f{fd}, f{fs}"),
        }
    }
}

impl fmt::Display for MipsFpuInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.disassemble())
    }
}

// ── MipsFpuLifter ─────────────────────────────────────────────────────────────

/// A simple IL node for MIPS FPU semantics.
#[derive(Debug, Clone)]
pub enum FpuIlNode {
    /// Register assignment: fd = rhs.
    Assign { fd: u8, rhs: Box<Self> },
    /// Binary float operation.
    BinOp {
        op: &'static str,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    /// Unary float operation.
    UnOp {
        op: &'static str,
        src: Box<Self>,
    },
    /// Conversion operation.
    Convert {
        op: &'static str,
        src: Box<Self>,
    },
    /// FPR read.
    Fpr(u8),
    /// GPR read.
    Gpr(u8),
    /// Condition-code read.
    Fcc(u8),
    /// Condition-code write.
    SetFcc { cc: u8, val: Box<Self> },
    /// Memory load.
    Load { addr: Box<Self>, size: u8 },
    /// Memory store.
    Store {
        addr: Box<Self>,
        val: Box<Self>,
        size: u8,
    },
    /// Unknown operation.
    Unknown,
}

impl fmt::Display for FpuIlNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Assign { fd, rhs } => write!(f, "f{fd} = {rhs}"),
            Self::BinOp { op, lhs, rhs } => write!(f, "{op}({lhs}, {rhs})"),
            Self::UnOp { op, src } | Self::Convert { op, src } => write!(f, "{op}({src})"),
            Self::Fpr(n) => write!(f, "f{n}"),
            Self::Gpr(n) => write!(f, "r{n}"),
            Self::Fcc(n) => write!(f, "fcc{n}"),
            Self::SetFcc { cc, val } => write!(f, "fcc{cc} = {val}"),
            Self::Load { addr, size } => write!(f, "mem[{addr}]:{size}"),
            Self::Store { addr, val, size } => write!(f, "mem[{addr}]:{size} = {val}"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Lifts MIPS FPU instructions to `FpuIlNode` trees.
pub struct MipsFpuLifter;

impl MipsFpuLifter {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn lift(&self, insn: &MipsFpuInsn) -> FpuIlNode {
        match *insn {
            MipsFpuInsn::AddS { fd, fs, ft } => FpuIlNode::Assign {
                fd,
                rhs: Box::new(FpuIlNode::BinOp {
                    op: "fadd.s",
                    lhs: Box::new(FpuIlNode::Fpr(fs)),
                    rhs: Box::new(FpuIlNode::Fpr(ft)),
                }),
            },
            MipsFpuInsn::AddD { fd, fs, ft } => FpuIlNode::Assign {
                fd,
                rhs: Box::new(FpuIlNode::BinOp {
                    op: "fadd.d",
                    lhs: Box::new(FpuIlNode::Fpr(fs)),
                    rhs: Box::new(FpuIlNode::Fpr(ft)),
                }),
            },
            MipsFpuInsn::SubS { fd, fs, ft } => FpuIlNode::Assign {
                fd,
                rhs: Box::new(FpuIlNode::BinOp {
                    op: "fsub.s",
                    lhs: Box::new(FpuIlNode::Fpr(fs)),
                    rhs: Box::new(FpuIlNode::Fpr(ft)),
                }),
            },
            MipsFpuInsn::SubD { fd, fs, ft } => FpuIlNode::Assign {
                fd,
                rhs: Box::new(FpuIlNode::BinOp {
                    op: "fsub.d",
                    lhs: Box::new(FpuIlNode::Fpr(fs)),
                    rhs: Box::new(FpuIlNode::Fpr(ft)),
                }),
            },
            MipsFpuInsn::MulS { fd, fs, ft } => FpuIlNode::Assign {
                fd,
                rhs: Box::new(FpuIlNode::BinOp {
                    op: "fmul.s",
                    lhs: Box::new(FpuIlNode::Fpr(fs)),
                    rhs: Box::new(FpuIlNode::Fpr(ft)),
                }),
            },
            MipsFpuInsn::MulD { fd, fs, ft } => FpuIlNode::Assign {
                fd,
                rhs: Box::new(FpuIlNode::BinOp {
                    op: "fmul.d",
                    lhs: Box::new(FpuIlNode::Fpr(fs)),
                    rhs: Box::new(FpuIlNode::Fpr(ft)),
                }),
            },
            MipsFpuInsn::DivS { fd, fs, ft } => FpuIlNode::Assign {
                fd,
                rhs: Box::new(FpuIlNode::BinOp {
                    op: "fdiv.s",
                    lhs: Box::new(FpuIlNode::Fpr(fs)),
                    rhs: Box::new(FpuIlNode::Fpr(ft)),
                }),
            },
            MipsFpuInsn::DivD { fd, fs, ft } => FpuIlNode::Assign {
                fd,
                rhs: Box::new(FpuIlNode::BinOp {
                    op: "fdiv.d",
                    lhs: Box::new(FpuIlNode::Fpr(fs)),
                    rhs: Box::new(FpuIlNode::Fpr(ft)),
                }),
            },
            MipsFpuInsn::SqrtS { fd, fs } => FpuIlNode::Assign {
                fd,
                rhs: Box::new(FpuIlNode::UnOp {
                    op: "sqrt.s",
                    src: Box::new(FpuIlNode::Fpr(fs)),
                }),
            },
            MipsFpuInsn::SqrtD { fd, fs } => FpuIlNode::Assign {
                fd,
                rhs: Box::new(FpuIlNode::UnOp {
                    op: "sqrt.d",
                    src: Box::new(FpuIlNode::Fpr(fs)),
                }),
            },
            MipsFpuInsn::AbsS { fd, fs } => FpuIlNode::Assign {
                fd,
                rhs: Box::new(FpuIlNode::UnOp {
                    op: "fabs.s",
                    src: Box::new(FpuIlNode::Fpr(fs)),
                }),
            },
            MipsFpuInsn::AbsD { fd, fs } => FpuIlNode::Assign {
                fd,
                rhs: Box::new(FpuIlNode::UnOp {
                    op: "fabs.d",
                    src: Box::new(FpuIlNode::Fpr(fs)),
                }),
            },
            MipsFpuInsn::NegS { fd, fs } => FpuIlNode::Assign {
                fd,
                rhs: Box::new(FpuIlNode::UnOp {
                    op: "fneg.s",
                    src: Box::new(FpuIlNode::Fpr(fs)),
                }),
            },
            MipsFpuInsn::NegD { fd, fs } => FpuIlNode::Assign {
                fd,
                rhs: Box::new(FpuIlNode::UnOp {
                    op: "fneg.d",
                    src: Box::new(FpuIlNode::Fpr(fs)),
                }),
            },
            MipsFpuInsn::CCond {
                cc,
                fs,
                ft,
                cond,
                fmt_d: _,
            } => FpuIlNode::SetFcc {
                cc,
                val: Box::new(FpuIlNode::BinOp {
                    op: cond.suffix(),
                    lhs: Box::new(FpuIlNode::Fpr(fs)),
                    rhs: Box::new(FpuIlNode::Fpr(ft)),
                }),
            },
            _ => FpuIlNode::Unknown,
        }
    }
}

impl Default for MipsFpuLifter {
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

    fn fpu() -> MipsFpuState {
        MipsFpuState::new()
    }
    fn gpr() -> [u64; 32] {
        [0u64; 32]
    }
    fn mem() -> HashMap<u64, u8> {
        HashMap::new()
    }

    #[test]
    fn test_add_s() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_single(2, 1.5);
        f.set_single(3, 2.5);
        MipsFpuInsn::AddS {
            fd: 0,
            fs: 2,
            ft: 3,
        }
        .execute(&mut f, &mut g, &mut m, 0x1000);
        assert!((f.get_single(0) - 4.0f32).abs() < 1e-6);
    }

    #[test]
    fn test_add_d() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_double(2, 1.5);
        f.set_double(3, 2.5);
        MipsFpuInsn::AddD {
            fd: 0,
            fs: 2,
            ft: 3,
        }
        .execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_double(0) - 4.0f64).abs() < 1e-10);
    }

    #[test]
    fn test_sub_d() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_double(0, 10.0);
        f.set_double(1, 3.0);
        MipsFpuInsn::SubD {
            fd: 2,
            fs: 0,
            ft: 1,
        }
        .execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_double(2) - 7.0).abs() < 1e-10);
    }

    #[test]
    fn test_mul_s() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_single(0, 3.0);
        f.set_single(1, 4.0);
        MipsFpuInsn::MulS {
            fd: 2,
            fs: 0,
            ft: 1,
        }
        .execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_single(2) - 12.0f32).abs() < 1e-6);
    }

    #[test]
    fn test_div_d() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_double(0, 10.0);
        f.set_double(1, 4.0);
        MipsFpuInsn::DivD {
            fd: 2,
            fs: 0,
            ft: 1,
        }
        .execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_double(2) - 2.5).abs() < 1e-10);
    }

    #[test]
    fn test_sqrt_d() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_double(1, 9.0);
        MipsFpuInsn::SqrtD { fd: 0, fs: 1 }.execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_double(0) - 3.0).abs() < 1e-10);
    }

    #[test]
    fn test_abs_s_negative() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_single(1, -5.0);
        MipsFpuInsn::AbsS { fd: 0, fs: 1 }.execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_single(0) - 5.0f32).abs() < 1e-6);
    }

    #[test]
    fn test_neg_d() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_double(1, 3.25_f64);
        MipsFpuInsn::NegD { fd: 0, fs: 1 }.execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_double(0) + 3.25_f64).abs() < 1e-10);
    }

    #[test]
    fn test_cvt_d_s() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_single(1, 3.25_f32);
        MipsFpuInsn::CvtDS { fd: 0, fs: 1 }.execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_double(0) - f64::from(3.25f32)).abs() < 1e-6);
    }

    #[test]
    fn test_cvt_s_d() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_double(1, 2.75_f64);
        MipsFpuInsn::CvtSD { fd: 0, fs: 1 }.execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_single(0) - 2.75f32).abs() < 1e-4);
    }

    #[test]
    fn test_trunc_w_d() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_double(1, 3.9);
        MipsFpuInsn::TruncWD { fd: 0, fs: 1 }.execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_double(0) - 3.0).abs() < 1e-10);
    }

    #[test]
    fn test_round_w_s() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_single(1, 3.5);
        MipsFpuInsn::RoundWS { fd: 0, fs: 1 }.execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_single(0) - 4.0f32).abs() < 1e-6);
    }

    #[test]
    fn test_ceil_w_d() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_double(1, 2.1);
        MipsFpuInsn::CeilWD { fd: 0, fs: 1 }.execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_double(0) - 3.0).abs() < 1e-10);
    }

    #[test]
    fn test_floor_w_s() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_single(1, 2.9);
        MipsFpuInsn::FloorWS { fd: 0, fs: 1 }.execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_single(0) - 2.0f32).abs() < 1e-6);
    }

    #[test]
    fn test_c_eq_d_true() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_double(1, 3.0);
        f.set_double(2, 3.0);
        MipsFpuInsn::CCond {
            cc: 0,
            fs: 1,
            ft: 2,
            cond: FpuCondition::Eq,
            fmt_d: true,
        }
        .execute(&mut f, &mut g, &mut m, 0);
        assert!(f.get_fcc(0));
    }

    #[test]
    fn test_c_eq_d_false() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_double(1, 1.0);
        f.set_double(2, 2.0);
        MipsFpuInsn::CCond {
            cc: 0,
            fs: 1,
            ft: 2,
            cond: FpuCondition::Eq,
            fmt_d: true,
        }
        .execute(&mut f, &mut g, &mut m, 0);
        assert!(!f.get_fcc(0));
    }

    #[test]
    fn test_c_lt_d() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_double(1, 1.0);
        f.set_double(2, 2.0);
        MipsFpuInsn::CCond {
            cc: 1,
            fs: 1,
            ft: 2,
            cond: FpuCondition::Lt,
            fmt_d: true,
        }
        .execute(&mut f, &mut g, &mut m, 0);
        assert!(f.get_fcc(1));
    }

    #[test]
    fn test_c_olt_unordered() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_double(1, f64::NAN);
        f.set_double(2, 2.0);
        // OLT is false if either is NaN.
        let result = FpuCondition::Olt.evaluate_d(f64::NAN, 2.0);
        assert!(!result);
        // ULT is true if either is NaN.
        let result = FpuCondition::Ult.evaluate_d(f64::NAN, 2.0);
        assert!(result);
        // Executing the OLT compare on the FPU state must agree with evaluate_d
        // (fcc unset) and must not perturb the GPR/memory contexts.
        MipsFpuInsn::CCond {
            cc: 0,
            fs: 1,
            ft: 2,
            cond: FpuCondition::Olt,
            fmt_d: true,
        }
        .execute(&mut f, &mut g, &mut m, 0);
        assert!(!f.get_fcc(0));
        MipsFpuInsn::CCond {
            cc: 0,
            fs: 1,
            ft: 2,
            cond: FpuCondition::Ult,
            fmt_d: true,
        }
        .execute(&mut f, &mut g, &mut m, 0);
        assert!(f.get_fcc(0));
    }

    #[test]
    fn test_mov_s() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_single(5, 3.25_f32);
        MipsFpuInsn::MovS { fd: 10, fs: 5 }.execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_single(10) - 3.25f32).abs() < 1e-6);
    }

    #[test]
    fn test_movt_s_taken() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_fcc(0, true);
        f.set_single(5, 9.99);
        MipsFpuInsn::MovtS {
            fd: 10,
            fs: 5,
            cc: 0,
        }
        .execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_single(10) - 9.99f32).abs() < 1e-4);
    }

    #[test]
    fn test_movf_s_not_taken() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_fcc(0, true); // cc=0 is true → movf not taken
        f.set_single(5, 1.0);
        f.set_single(10, 99.0);
        MipsFpuInsn::MovfS {
            fd: 10,
            fs: 5,
            cc: 0,
        }
        .execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_single(10) - 99.0f32).abs() < 1e-4);
    }

    #[test]
    fn test_mfc1_mtc1_round_trip() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_single(5, 1.5);
        MipsFpuInsn::MfC1 { rt: 10, fs: 5 }.execute(&mut f, &mut g, &mut m, 0);
        let bits = g[10];
        g[11] = bits;
        MipsFpuInsn::MtC1 { rt: 11, fs: 6 }.execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_single(6) - 1.5f32).abs() < 1e-6);
    }

    #[test]
    fn test_dmfc1_dmtc1_round_trip() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_double(0, std::f64::consts::PI);
        MipsFpuInsn::DmfC1 { rt: 5, fs: 0 }.execute(&mut f, &mut g, &mut m, 0);
        MipsFpuInsn::DmtC1 { rt: 5, fs: 1 }.execute(&mut f, &mut g, &mut m, 0);
        assert!((f.get_double(1) - std::f64::consts::PI).abs() < 1e-10);
    }

    #[test]
    fn test_bc1t_taken() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_fcc(0, true);
        let npc = MipsFpuInsn::Bc1t { cc: 0, offset: 10 }.execute(&mut f, &mut g, &mut m, 0x1000);
        assert_eq!(npc, 0x1000 + 4 + 10 * 4);
    }

    #[test]
    fn test_bc1f_not_taken() {
        let mut f = fpu();
        let mut g = gpr();
        let mut m = mem();
        f.set_fcc(0, true); // cc=0 true → bc1f not taken
        let npc = MipsFpuInsn::Bc1f { cc: 0, offset: 10 }.execute(&mut f, &mut g, &mut m, 0x1000);
        assert_eq!(npc, 0x1004);
    }

    #[test]
    fn test_fcsr_flags_from_to() {
        let mut fpu = MipsFpuState::new();
        fpu.fcsr = 0b0000_0000_0000_0000_0000_0000_0011_1100; // inexact+underflow+overflow+div_zero
        let flags = FCSRFlags::from_fcsr(fpu.fcsr);
        assert!(flags.inexact());
        assert!(flags.underflow());
        assert!(flags.overflow());
        assert!(flags.div_zero());
        assert!(!flags.invalid());
        let back = flags.to_fcsr();
        let flags2 = FCSRFlags::from_fcsr(back);
        assert_eq!(flags2.inexact(), flags.inexact());
    }

    #[test]
    fn test_fcsr_rounding_mode_names() {
        for (rm, name) in [
            (0, "round-nearest-even"),
            (1, "round-toward-zero"),
            (2, "round-toward-plus-infinity"),
            (3, "round-toward-minus-infinity"),
        ] {
            let f = FCSRFlags {
                rounding: rm,
                ..FCSRFlags::from_fcsr(0)
            };
            assert_eq!(f.rounding_name(), name);
        }
    }

    #[test]
    fn test_fpu_condition_suffix_all() {
        let conds = [
            FpuCondition::F,
            FpuCondition::Un,
            FpuCondition::Eq,
            FpuCondition::Ueq,
            FpuCondition::Olt,
            FpuCondition::Ult,
            FpuCondition::Ole,
            FpuCondition::Ule,
            FpuCondition::Sf,
            FpuCondition::Ngle,
            FpuCondition::Seq,
            FpuCondition::Ngl,
            FpuCondition::Lt,
            FpuCondition::Nge,
            FpuCondition::Le,
            FpuCondition::Ngt,
        ];
        for c in &conds {
            assert!(!c.suffix().is_empty(), "{c:?} has empty suffix");
        }
    }

    #[test]
    fn test_disassembly_add_s() {
        let s = MipsFpuInsn::AddS {
            fd: 0,
            fs: 2,
            ft: 4,
        }
        .disassemble();
        assert!(s.contains("add.s"), "got: {s}");
        assert!(s.contains("f0"), "got: {s}");
    }

    #[test]
    fn test_disassembly_c_cond() {
        let s = MipsFpuInsn::CCond {
            cc: 0,
            fs: 2,
            ft: 4,
            cond: FpuCondition::Eq,
            fmt_d: true,
        }
        .disassemble();
        assert!(s.contains("c.eq"), "got: {s}");
    }

    #[test]
    fn test_lifter_add_s() {
        let lifter = MipsFpuLifter::new();
        let il = lifter.lift(&MipsFpuInsn::AddS {
            fd: 0,
            fs: 1,
            ft: 2,
        });
        let s = il.to_string();
        assert!(s.contains("fadd.s"), "IL='{s}'");
    }

    #[test]
    fn test_lifter_ccond() {
        let lifter = MipsFpuLifter::new();
        let il = lifter.lift(&MipsFpuInsn::CCond {
            cc: 0,
            fs: 1,
            ft: 2,
            cond: FpuCondition::Lt,
            fmt_d: true,
        });
        let s = il.to_string();
        assert!(s.contains("fcc0"), "IL='{s}'");
    }

    #[test]
    fn test_fpu_state_default() {
        let f = MipsFpuState::default();
        assert_eq!(f.fpr[0], 0.0);
        assert!(f.fr_bit);
    }

    #[test]
    fn test_fpu_fcc_set_clear() {
        let mut f = MipsFpuState::new();
        f.set_fcc(0, true);
        assert!(f.get_fcc(0));
        f.set_fcc(0, false);
        assert!(!f.get_fcc(0));
        f.set_fcc(3, true);
        assert!(f.get_fcc(3));
        f.clear_fcc();
        assert!(!f.get_fcc(3));
    }
}
