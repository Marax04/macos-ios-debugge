//! M68K condition codes and CCR (Condition Code Register) modelling.
//!
//! The M68K CCR is the low byte of the Status Register (SR) and contains
//! five flag bits:
//!
//! | Bit | Name | Meaning                     |
//! |-----|------|-----------------------------|
//! | 4   | X    | Extend                      |
//! | 3   | N    | Negative                    |
//! | 2   | Z    | Zero                        |
//! | 1   | V    | Overflow                    |
//! | 0   | C    | Carry                       |
//!
//! This module provides:
//! - [`FlagBit`] — individual flag identifiers
//! - [`CcRegister`] — the full CCR state
//! - [`M68kConditionCode`] — the 16 Bcc/Scc condition codes
//! - [`evaluate_cc`] — evaluate a condition code against a [`CcRegister`]

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// FlagBit
// ─────────────────────────────────────────────────────────────────────────────

/// A single flag bit in the M68K CCR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlagBit {
    /// Carry flag (bit 0).
    C,
    /// Overflow flag (bit 1).
    V,
    /// Zero flag (bit 2).
    Z,
    /// Negative flag (bit 3).
    N,
    /// Extend flag (bit 4).
    X,
}

impl FlagBit {
    /// Bit position within the CCR byte.
    #[must_use]
    pub const fn bit_pos(self) -> u8 {
        match self {
            Self::C => 0,
            Self::V => 1,
            Self::Z => 2,
            Self::N => 3,
            Self::X => 4,
        }
    }

    /// Bitmask for this flag within the CCR byte.
    #[must_use]
    pub const fn mask(self) -> u8 {
        1 << self.bit_pos()
    }

    /// Single-character name (`C`, `V`, `Z`, `N`, `X`).
    #[must_use]
    pub const fn char(self) -> char {
        match self {
            Self::C => 'C',
            Self::V => 'V',
            Self::Z => 'Z',
            Self::N => 'N',
            Self::X => 'X',
        }
    }
}

impl fmt::Display for FlagBit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.char())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CcRegister
// ─────────────────────────────────────────────────────────────────────────────

/// Named flag values for constructing a [`CcRegister`].
///
/// Use with [`CcRegister::from_flags`].  All flags default to `false`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CcBits {
    /// Carry flag (C).
    pub carry: bool,
    /// Overflow flag (V).
    pub overflow: bool,
    /// Zero flag (Z).
    pub zero: bool,
    /// Negative flag (N).
    pub negative: bool,
    /// Extend flag (X).
    pub extend: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// CcRegister
// ─────────────────────────────────────────────────────────────────────────────

/// The M68K Condition Code Register (low byte of SR).
///
/// Bit layout: `???XNZVC` (bits 7..5 reserved, always 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CcRegister {
    pub raw: u8,
}

impl CcRegister {
    /// Construct from raw byte.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self { raw: raw & 0x1F }
    }

    /// Construct from individual flag values.
    #[must_use]
    pub fn from_flags(c: bool, v: bool, z: bool, n: bool, x: bool) -> Self {
        let mut raw: u8 = 0;
        if c { raw |= FlagBit::C.mask(); }
        if v { raw |= FlagBit::V.mask(); }
        if z { raw |= FlagBit::Z.mask(); }
        if n { raw |= FlagBit::N.mask(); }
        if x { raw |= FlagBit::X.mask(); }
        Self { raw }
    }

    /// Test a single flag bit.
    #[must_use]
    pub const fn flag(self, bit: FlagBit) -> bool {
        (self.raw & bit.mask()) != 0
    }

    /// Carry flag.
    #[must_use]
    pub const fn c(self) -> bool { self.flag(FlagBit::C) }
    /// Overflow flag.
    #[must_use]
    pub const fn v(self) -> bool { self.flag(FlagBit::V) }
    /// Zero flag.
    #[must_use]
    pub const fn z(self) -> bool { self.flag(FlagBit::Z) }
    /// Negative flag.
    #[must_use]
    pub const fn n(self) -> bool { self.flag(FlagBit::N) }
    /// Extend flag.
    #[must_use]
    pub const fn x(self) -> bool { self.flag(FlagBit::X) }

    /// Set or clear a flag.
    pub fn set_flag(&mut self, bit: FlagBit, value: bool) {
        if value {
            self.raw |= bit.mask();
        } else {
            self.raw &= !bit.mask();
        }
    }

    /// Update CCR from the result of a signed 32-bit addition.
    #[must_use]
    pub fn from_add32(a: i32, b: i32) -> Self {
        let result = a.wrapping_add(b);
        let ua = a as u32;
        let ub = b as u32;
        let ur = result as u32;
        // Carry occurs when the unsigned sum wraps past 2^32; equivalently the
        // wrapped result is strictly less than either addend.
        let carry = ur < ua || ur < ub;
        let overflow = ((a ^ result) & (b ^ result)) < 0;
        Self::from_flags(carry, overflow, result == 0, result < 0, carry)
    }

    /// Update CCR from the result of a signed 32-bit subtraction.
    #[must_use]
    pub fn from_sub32(a: i32, b: i32) -> Self {
        let result = a.wrapping_sub(b);
        let ua = a as u32;
        let ub = b as u32;
        let borrow = ua < ub;
        let overflow = ((a ^ b) & (a ^ result)) < 0;
        Self::from_flags(borrow, overflow, result == 0, result < 0, borrow)
    }

    /// Update CCR from a logic-operation result (AND/OR/EOR).
    ///
    /// C and V are always cleared; X is unchanged.
    #[must_use]
    pub fn from_logic32(result: i32, x: bool) -> Self {
        Self::from_flags(false, false, result == 0, result < 0, x)
    }

    /// CCR resulting from NEG.l (negate) of `a`.
    #[must_use]
    pub fn from_neg32(a: i32) -> Self {
        let result = (0i32).wrapping_sub(a);
        let carry = a != 0;
        let overflow = a == i32::MIN;
        Self::from_flags(carry, overflow, result == 0, result < 0, carry)
    }
}

impl fmt::Display for CcRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CCR[X={} N={} Z={} V={} C={}]",
            self.x() as u8,
            self.n() as u8,
            self.z() as u8,
            self.v() as u8,
            self.c() as u8,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// M68kConditionCode
// ─────────────────────────────────────────────────────────────────────────────

/// The 16 M68K condition codes used by Bcc, DBcc, and Scc instructions.
///
/// Encoding follows the M68000 Programmer's Reference Manual table 3-19.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum M68kConditionCode {
    /// T (True) — always branch (encode 0x0).
    T  = 0x0,
    /// F (False) — never branch (encode 0x1).
    F  = 0x1,
    /// HI — Higher (unsigned): C=0 AND Z=0.
    Hi = 0x2,
    /// LS — Lower or Same (unsigned): C=1 OR Z=1.
    Ls = 0x3,
    /// CC (HS) — Carry Clear / Higher or Same: C=0.
    Cc = 0x4,
    /// CS (LO) — Carry Set / Lower: C=1.
    Cs = 0x5,
    /// NE — Not Equal: Z=0.
    Ne = 0x6,
    /// EQ — Equal: Z=1.
    Eq = 0x7,
    /// VC — Overflow Clear: V=0.
    Vc = 0x8,
    /// VS — Overflow Set: V=1.
    Vs = 0x9,
    /// PL — Plus (non-negative): N=0.
    Pl = 0xA,
    /// MI — Minus (negative): N=1.
    Mi = 0xB,
    /// GE — Greater or Equal (signed): N=V.
    Ge = 0xC,
    /// LT — Less Than (signed): N≠V.
    Lt = 0xD,
    /// GT — Greater Than (signed): Z=0 AND N=V.
    Gt = 0xE,
    /// LE — Less or Equal (signed): Z=1 OR N≠V.
    Le = 0xF,
}

impl M68kConditionCode {
    /// Parse from the 4-bit condition field value (0x0–0xF).
    #[must_use]
    pub fn from_encoding(enc: u8) -> Option<Self> {
        Some(match enc & 0xF {
            0x0 => Self::T,
            0x1 => Self::F,
            0x2 => Self::Hi,
            0x3 => Self::Ls,
            0x4 => Self::Cc,
            0x5 => Self::Cs,
            0x6 => Self::Ne,
            0x7 => Self::Eq,
            0x8 => Self::Vc,
            0x9 => Self::Vs,
            0xA => Self::Pl,
            0xB => Self::Mi,
            0xC => Self::Ge,
            0xD => Self::Lt,
            0xE => Self::Gt,
            0xF => Self::Le,
            _   => return None,
        })
    }

    /// The 4-bit encoding of this condition.
    #[must_use]
    pub const fn encoding(self) -> u8 {
        self as u8
    }

    /// The Motorola mnemonic for this condition (e.g. `"hi"`, `"ne"`).
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::T  => "t",
            Self::F  => "f",
            Self::Hi => "hi",
            Self::Ls => "ls",
            Self::Cc => "cc",
            Self::Cs => "cs",
            Self::Ne => "ne",
            Self::Eq => "eq",
            Self::Vc => "vc",
            Self::Vs => "vs",
            Self::Pl => "pl",
            Self::Mi => "mi",
            Self::Ge => "ge",
            Self::Lt => "lt",
            Self::Gt => "gt",
            Self::Le => "le",
        }
    }

    /// A human-readable description of the condition.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::T  => "always true",
            Self::F  => "always false",
            Self::Hi => "higher (unsigned, C=0 AND Z=0)",
            Self::Ls => "lower or same (unsigned, C=1 OR Z=1)",
            Self::Cc => "carry clear (C=0)",
            Self::Cs => "carry set (C=1)",
            Self::Ne => "not equal (Z=0)",
            Self::Eq => "equal (Z=1)",
            Self::Vc => "overflow clear (V=0)",
            Self::Vs => "overflow set (V=1)",
            Self::Pl => "plus / non-negative (N=0)",
            Self::Mi => "minus / negative (N=1)",
            Self::Ge => "greater or equal signed (N=V)",
            Self::Lt => "less than signed (N≠V)",
            Self::Gt => "greater than signed (Z=0 AND N=V)",
            Self::Le => "less or equal signed (Z=1 OR N≠V)",
        }
    }

    /// The flags that this condition tests (informational).
    #[must_use]
    pub fn flags_tested(self) -> &'static [FlagBit] {
        match self {
            Self::T | Self::F => &[],
            Self::Hi | Self::Ls => &[FlagBit::C, FlagBit::Z],
            Self::Cc | Self::Cs => &[FlagBit::C],
            Self::Ne | Self::Eq => &[FlagBit::Z],
            Self::Vc | Self::Vs => &[FlagBit::V],
            Self::Pl | Self::Mi => &[FlagBit::N],
            Self::Ge | Self::Lt => &[FlagBit::N, FlagBit::V],
            Self::Gt | Self::Le => &[FlagBit::N, FlagBit::V, FlagBit::Z],
        }
    }

    /// Evaluate this condition against a [`CcRegister`] snapshot.
    ///
    /// Returns `true` if the branch/set condition is met.
    #[must_use]
    pub fn evaluate(self, ccr: CcRegister) -> bool {
        evaluate_cc(self, ccr)
    }

    /// Return the logical inverse (complement) of this condition.
    #[must_use]
    pub const fn complement(self) -> Self {
        // XOR the low bit of the encoding to flip between cc/cs, ne/eq, etc.
        // Special-case T↔F.
        match self {
            Self::T  => Self::F,
            Self::F  => Self::T,
            Self::Hi => Self::Ls,
            Self::Ls => Self::Hi,
            Self::Cc => Self::Cs,
            Self::Cs => Self::Cc,
            Self::Ne => Self::Eq,
            Self::Eq => Self::Ne,
            Self::Vc => Self::Vs,
            Self::Vs => Self::Vc,
            Self::Pl => Self::Mi,
            Self::Mi => Self::Pl,
            Self::Ge => Self::Lt,
            Self::Lt => Self::Ge,
            Self::Gt => Self::Le,
            Self::Le => Self::Gt,
        }
    }
}

impl fmt::Display for M68kConditionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.mnemonic())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// evaluate_cc
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluate a condition code against the given CCR snapshot.
///
/// This is the core function used by all Bcc, DBcc, and Scc emulation.
///
/// ```
/// use rustre_arch_68k::m68k_condition_codes::{
///     CcRegister, M68kConditionCode, evaluate_cc
/// };
///
/// // Z=1 → EQ is true.
/// let ccr = CcRegister::from_flags(false, false, true, false, false);
/// assert!(evaluate_cc(M68kConditionCode::Eq, ccr));
/// assert!(!evaluate_cc(M68kConditionCode::Ne, ccr));
/// ```
#[must_use]
pub fn evaluate_cc(cc: M68kConditionCode, ccr: CcRegister) -> bool {
    let c = ccr.c();
    let v = ccr.v();
    let z = ccr.z();
    let n = ccr.n();
    match cc {
        M68kConditionCode::T  => true,
        M68kConditionCode::F  => false,
        M68kConditionCode::Hi => !c && !z,
        M68kConditionCode::Ls => c || z,
        M68kConditionCode::Cc => !c,
        M68kConditionCode::Cs => c,
        M68kConditionCode::Ne => !z,
        M68kConditionCode::Eq => z,
        M68kConditionCode::Vc => !v,
        M68kConditionCode::Vs => v,
        M68kConditionCode::Pl => !n,
        M68kConditionCode::Mi => n,
        M68kConditionCode::Ge => n == v,
        M68kConditionCode::Lt => n != v,
        M68kConditionCode::Gt => !z && (n == v),
        M68kConditionCode::Le => z || (n != v),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ccr(c: bool, v: bool, z: bool, n: bool, x: bool) -> CcRegister {
        CcRegister::from_flags(c, v, z, n, x)
    }

    #[test]
    fn test_flag_masks() {
        assert_eq!(FlagBit::C.mask(), 0x01);
        assert_eq!(FlagBit::V.mask(), 0x02);
        assert_eq!(FlagBit::Z.mask(), 0x04);
        assert_eq!(FlagBit::N.mask(), 0x08);
        assert_eq!(FlagBit::X.mask(), 0x10);
    }

    #[test]
    fn test_ccr_from_raw() {
        let r = CcRegister::from_raw(0x1F);
        assert!(r.c() && r.v() && r.z() && r.n() && r.x());
    }

    #[test]
    fn test_ccr_from_raw_masks_upper() {
        let r = CcRegister::from_raw(0xFF);
        assert_eq!(r.raw, 0x1F);
    }

    #[test]
    fn test_ccr_set_flag() {
        let mut r = CcRegister::default();
        r.set_flag(FlagBit::Z, true);
        assert!(r.z());
        r.set_flag(FlagBit::Z, false);
        assert!(!r.z());
    }

    #[test]
    fn test_cc_t_always_true() {
        for raw in 0u8..=0x1F {
            let r = CcRegister::from_raw(raw);
            assert!(evaluate_cc(M68kConditionCode::T, r));
        }
    }

    #[test]
    fn test_cc_f_always_false() {
        for raw in 0u8..=0x1F {
            let r = CcRegister::from_raw(raw);
            assert!(!evaluate_cc(M68kConditionCode::F, r));
        }
    }

    #[test]
    fn test_eq_z_set() {
        assert!(evaluate_cc(M68kConditionCode::Eq, ccr(false, false, true, false, false)));
        assert!(!evaluate_cc(M68kConditionCode::Eq, ccr(false, false, false, false, false)));
    }

    #[test]
    fn test_ne_z_clear() {
        assert!(evaluate_cc(M68kConditionCode::Ne, ccr(false, false, false, false, false)));
        assert!(!evaluate_cc(M68kConditionCode::Ne, ccr(false, false, true, false, false)));
    }

    #[test]
    fn test_hi_c0_z0() {
        assert!(evaluate_cc(M68kConditionCode::Hi, ccr(false, false, false, false, false)));
        assert!(!evaluate_cc(M68kConditionCode::Hi, ccr(true, false, false, false, false)));
        assert!(!evaluate_cc(M68kConditionCode::Hi, ccr(false, false, true, false, false)));
    }

    #[test]
    fn test_ls_c_or_z() {
        assert!(evaluate_cc(M68kConditionCode::Ls, ccr(true, false, false, false, false)));
        assert!(evaluate_cc(M68kConditionCode::Ls, ccr(false, false, true, false, false)));
        assert!(!evaluate_cc(M68kConditionCode::Ls, ccr(false, false, false, false, false)));
    }

    #[test]
    fn test_ge_n_eq_v() {
        // N=0,V=0 → true
        assert!(evaluate_cc(M68kConditionCode::Ge, ccr(false, false, false, false, false)));
        // N=1,V=1 → true
        assert!(evaluate_cc(M68kConditionCode::Ge, ccr(false, true, false, true, false)));
        // N=1,V=0 → false
        assert!(!evaluate_cc(M68kConditionCode::Ge, ccr(false, false, false, true, false)));
    }

    #[test]
    fn test_lt_n_ne_v() {
        assert!(evaluate_cc(M68kConditionCode::Lt, ccr(false, false, false, true, false)));
        assert!(!evaluate_cc(M68kConditionCode::Lt, ccr(false, false, false, false, false)));
    }

    #[test]
    fn test_gt_z0_n_eq_v() {
        // Z=0,N=V(both 0) → true
        assert!(evaluate_cc(M68kConditionCode::Gt, ccr(false, false, false, false, false)));
        // Z=1 → false
        assert!(!evaluate_cc(M68kConditionCode::Gt, ccr(false, false, true, false, false)));
    }

    #[test]
    fn test_complement() {
        assert_eq!(M68kConditionCode::Eq.complement(), M68kConditionCode::Ne);
        assert_eq!(M68kConditionCode::Ge.complement(), M68kConditionCode::Lt);
        assert_eq!(M68kConditionCode::T.complement(), M68kConditionCode::F);
    }

    #[test]
    fn test_complement_is_inverse() {
        for enc in 0u8..=15 {
            let cc = M68kConditionCode::from_encoding(enc).unwrap();
            let ccr = CcRegister::from_raw(0x0F);
            assert_eq!(
                evaluate_cc(cc, ccr),
                !evaluate_cc(cc.complement(), ccr),
                "complement invariant failed for {cc}"
            );
        }
    }

    #[test]
    fn test_encoding_roundtrip() {
        for enc in 0u8..=15 {
            let cc = M68kConditionCode::from_encoding(enc).unwrap();
            assert_eq!(cc.encoding(), enc);
        }
    }

    #[test]
    fn test_from_add32_zero() {
        let ccr = CcRegister::from_add32(0, 0);
        assert!(ccr.z());
        assert!(!ccr.n());
        assert!(!ccr.c());
        assert!(!ccr.v());
    }

    #[test]
    fn test_from_add32_carry() {
        let ccr = CcRegister::from_add32(i32::MAX, 1);
        // wraps, so overflow is set; carry from u32 perspective.
        assert!(ccr.v());
    }

    #[test]
    fn test_from_sub32_borrow() {
        let ccr = CcRegister::from_sub32(0, 1);
        // 0 - 1 borrows.
        assert!(ccr.c());
        assert!(ccr.n());
    }

    #[test]
    fn test_from_logic32_clears_cv() {
        let ccr = CcRegister::from_logic32(-1, false);
        assert!(!ccr.c());
        assert!(!ccr.v());
        assert!(!ccr.z());
        assert!(ccr.n());
    }

    #[test]
    fn test_from_neg32_zero() {
        let ccr = CcRegister::from_neg32(0);
        assert!(ccr.z());
        assert!(!ccr.c());
    }

    #[test]
    fn test_ccr_display() {
        let r = CcRegister::from_flags(true, false, true, false, false);
        let s = r.to_string();
        assert!(s.contains("Z=1"));
        assert!(s.contains("C=1"));
        assert!(s.contains("N=0"));
    }

    #[test]
    fn test_mnemonic_all() {
        let expected = [
            "t","f","hi","ls","cc","cs","ne","eq",
            "vc","vs","pl","mi","ge","lt","gt","le",
        ];
        for (enc, &m) in expected.iter().enumerate() {
            let cc = M68kConditionCode::from_encoding(enc as u8).unwrap();
            assert_eq!(cc.mnemonic(), m);
        }
    }
}
