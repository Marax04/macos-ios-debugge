//! `ModRM` and SIB byte decoding for x86/x64.

use crate::prefix::RexPrefix;

// ---------------------------------------------------------------------------
// ModRM
// ---------------------------------------------------------------------------

/// Decoded `ModRM` byte.
///
/// Layout: `[7:6] mod | [5:3] reg | [2:0] r/m`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct ModRm {
    /// Addressing mode (0–3).
    pub mode: u8,
    /// Register / opcode extension field (3 bits, before REX extension).
    pub reg: u8,
    /// Register or memory operand field (3 bits, before REX extension).
    pub rm: u8,
}

impl ModRm {
    /// Decode a `ModRM` byte.
    pub fn decode(byte: u8) -> Self {
        Self {
            mode: (byte >> 6) & 0x3,
            reg: (byte >> 3) & 0x7,
            rm: byte & 0x7,
        }
    }

    /// Returns `true` if this `ModRM` refers to a register operand (mod == 3).
    #[must_use]
    pub fn is_reg(&self) -> bool {
        self.mode == 3
    }

    /// Returns `true` if a SIB byte follows (mod != 3 and r/m == 4).
    #[must_use]
    pub fn has_sib(&self) -> bool {
        self.mode != 3 && self.rm == 4
    }

    /// Returns `true` if a disp32 follows without a base register
    /// (mod == 0 and r/m == 5, or in 64-bit mode: RIP-relative).
    #[must_use]
    pub fn is_disp32_only(&self) -> bool {
        self.mode == 0 && self.rm == 5
    }

    /// Number of displacement bytes following (assuming no SIB).
    ///
    /// - mod 0, r/m 5 → 4
    /// - mod 1         → 1
    /// - mod 2         → 4
    /// - mod 3         → 0
    #[must_use]
    pub fn disp_size(&self) -> usize {
        match self.mode {
            0 if self.rm == 5 => 4,
            0 => 0,
            1 => 1,
            2 => 4,
            _ => 0,
        }
    }

    /// Apply REX.R to the reg field, returning the extended register index.
    #[must_use]
    pub fn reg_ext(&self, rex: &RexPrefix) -> u8 {
        rex.extend_reg(self.reg)
    }

    /// Apply REX.B to the r/m field, returning the extended register index.
    #[must_use]
    pub fn rm_ext(&self, rex: &RexPrefix) -> u8 {
        rex.extend_rm(self.rm)
    }
}

// ---------------------------------------------------------------------------
// SIB
// ---------------------------------------------------------------------------

/// Decoded SIB (Scale-Index-Base) byte.
///
/// Layout: `[7:6] scale | [5:3] index | [2:0] base`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct Sib {
    /// Scale factor exponent (0=×1, 1=×2, 2=×4, 3=×8).
    pub scale: u8,
    /// Index register field (3 bits).
    pub index: u8,
    /// Base register field (3 bits).
    pub base: u8,
}

impl Sib {
    /// Decode a SIB byte.
    pub fn decode(byte: u8) -> Self {
        Self {
            scale: (byte >> 6) & 0x3,
            index: (byte >> 3) & 0x7,
            base: byte & 0x7,
        }
    }

    /// The actual scale multiplier (1, 2, 4, or 8).
    #[must_use]
    pub fn scale_factor(&self) -> u8 {
        1u8 << self.scale
    }

    /// Returns `true` if the index field encodes "no index" (index == 4
    /// without REX.X, or index == 4 with REX.X — but index==4 always
    /// means no index regardless of REX.X).
    #[must_use]
    pub fn has_no_index(&self) -> bool {
        self.index == 4
    }

    /// Returns `true` if the base field may encode a displaced-only addressing
    /// (base == 5 and mod == 0 → no base register, disp32 only).
    #[must_use]
    pub fn base_is_disp_only(&self, modrm_mode: u8) -> bool {
        self.base == 5 && modrm_mode == 0
    }

    /// Apply REX.X to the index field.
    #[must_use]
    pub fn index_ext(&self, rex: &RexPrefix) -> u8 {
        rex.extend_index(self.index)
    }

    /// Apply REX.B to the base field.
    #[must_use]
    pub fn base_ext(&self, rex: &RexPrefix) -> u8 {
        rex.extend_base(self.base)
    }
}

// ---------------------------------------------------------------------------
// Addressing mode classification
// ---------------------------------------------------------------------------

/// Describes the decoded effective address for an r/m operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum EffectiveAddr {
    /// Direct register operand (mod 3).
    Register(u8),
    /// `[base + disp]` (mod 0/1/2, no SIB).
    BaseDisp { base: u8, disp: i32 },
    /// RIP-relative: `[RIP + disp32]` (64-bit mode, mod 0 rm 5, no SIB).
    RipRelative { disp: i32 },
    /// Absolute disp32 address (mirrors `branch.rs::EffAddr::Absolute32`):
    /// - 32-bit mode, mod 0 rm 5 without SIB (`[0x00401000]`), or
    /// - SIB with base==5/mod==0/index==4 in ANY mode — a SIB byte
    ///   suppresses RIP-relative addressing even in 64-bit mode.
    Absolute { addr: u32 },
    /// `[index*scale + disp]` only (no base).
    IndexScaleDisp { index: u8, scale: u8, disp: i32 },
    /// `[base + index*scale + disp]`.
    Full {
        base: u8,
        index: u8,
        scale: u8,
        disp: i32,
    },
}

impl EffectiveAddr {
    /// Decode the effective address from a `ModRM`, optional SIB, and displacement,
    /// given the mode bits and whether we are in 64-bit mode.
    ///
    /// `disp` should be sign-extended to i32 before calling.
    pub fn decode(
        modrm: ModRm,
        sib: Option<Sib>,
        disp: i32,
        rex: &RexPrefix,
        is_64bit: bool,
    ) -> Self {
        if modrm.is_reg() {
            return Self::Register(modrm.rm_ext(rex));
        }
        if let Some(sib) = sib {
            let base = sib.base_ext(rex);
            let index = sib.index_ext(rex);
            let scale = sib.scale_factor();
            if sib.base_is_disp_only(modrm.mode) {
                if sib.has_no_index() {
                    // disp32 only. A SIB form is NEVER RIP-relative, even in
                    // 64-bit mode — this encoding is exactly how compilers
                    // force absolute addressing (e.g. `mov eax, [abs32]` =
                    // 8B 04 25 disp32).
                    return Self::Absolute { addr: disp as u32 };
                }
                return Self::IndexScaleDisp { index, scale, disp };
            }
            if sib.has_no_index() {
                return Self::BaseDisp { base, disp };
            }
            return Self::Full {
                base,
                index,
                scale,
                disp,
            };
        }
        // No SIB
        if modrm.is_disp32_only() {
            if is_64bit {
                // mod=0 rm=5 without SIB is the ONLY RIP-relative encoding.
                return Self::RipRelative { disp };
            }
            // 32-bit mode: absolute disp32 ([0x00401000]), not [EIP+disp].
            return Self::Absolute { addr: disp as u32 };
        }
        let base = modrm.rm_ext(rex);
        Self::BaseDisp { base, disp }
    }

    /// Returns the base register index, if any.
    #[must_use]
    pub fn base_reg(&self) -> Option<u8> {
        match self {
            Self::Register(r) => Some(*r),
            Self::BaseDisp { base, .. } | Self::Full { base, .. } => Some(*base),
            _ => None,
        }
    }

    /// Returns `true` if this is a memory (non-register) operand.
    #[must_use]
    pub fn is_memory(&self) -> bool {
        !matches!(self, Self::Register(_))
    }
}

// ---------------------------------------------------------------------------
// Register name helpers
// ---------------------------------------------------------------------------

/// GPR name for the given size (in bytes) and register index (0–15, after REX extension).
///
/// Returns `"???"` for unknown indices.
#[must_use]
pub fn gpr_name(index: u8, size_bytes: u8, _has_rex: bool) -> &'static str {
    match size_bytes {
        1 => GPR8_NAMES_REX[index as usize & 0xF],
        2 => GPR16_NAMES[index as usize & 0xF],
        4 => GPR32_NAMES[index as usize & 0xF],
        8 => GPR64_NAMES[index as usize & 0xF],
        _ => "???",
    }
}

/// 64-bit register names (rax, rcx, … r15).
pub static GPR64_NAMES: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

/// 32-bit register names.
pub static GPR32_NAMES: [&str; 16] = [
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d",
    "r13d", "r14d", "r15d",
];

/// 16-bit register names.
pub static GPR16_NAMES: [&str; 16] = [
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w",
    "r14w", "r15w",
];

/// 8-bit register names (with REX prefix — SPL/BPL/SIL/DIL instead of AH/CH/DH/BH).
pub static GPR8_NAMES_REX: [&str; 16] = [
    "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b",
    "r13b", "r14b", "r15b",
];

/// 8-bit register names (without REX — legacy AH/CH/DH/BH for indices 4–7).
pub static GPR8_NAMES_NOREX: [&str; 8] = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"];

/// XMM register names (xmm0–xmm15).
pub static XMM_NAMES: [&str; 16] = [
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10",
    "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
];

/// YMM register names (ymm0–ymm15).
pub static YMM_NAMES: [&str; 16] = [
    "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9", "ymm10",
    "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",
];

/// ZMM register names (zmm0–zmm31).
pub static ZMM_NAMES: [&str; 32] = [
    "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7", "zmm8", "zmm9", "zmm10",
    "zmm11", "zmm12", "zmm13", "zmm14", "zmm15", "zmm16", "zmm17", "zmm18", "zmm19", "zmm20",
    "zmm21", "zmm22", "zmm23", "zmm24", "zmm25", "zmm26", "zmm27", "zmm28", "zmm29", "zmm30",
    "zmm31",
];

/// Opmask register names (k0–k7).
pub static KMASK_NAMES: [&str; 8] = ["k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7"];

/// Segment register names.
pub static SEG_NAMES: [&str; 8] = ["es", "cs", "ss", "ds", "fs", "gs", "???", "???"];

/// Control register names.
pub static CTRL_NAMES: [&str; 16] = [
    "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7", "cr8", "cr9", "cr10", "cr11", "cr12",
    "cr13", "cr14", "cr15",
];

/// Debug register names.
pub static DEBUG_NAMES: [&str; 8] = ["dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7"];

#[cfg(test)]
mod tests {
    use super::*;

    fn no_rex() -> RexPrefix {
        RexPrefix::default()
    }

    #[test]
    fn test_modrm_decode_reg() {
        let m = ModRm::decode(0xC8); // mod=3, reg=1, rm=0
        assert_eq!(m.mode, 3);
        assert_eq!(m.reg, 1);
        assert_eq!(m.rm, 0);
        assert!(m.is_reg());
    }

    #[test]
    fn test_modrm_no_sib() {
        let m = ModRm::decode(0x45); // mod=1, reg=0, rm=5
        assert!(!m.has_sib());
        assert_eq!(m.disp_size(), 1);
    }

    #[test]
    fn test_modrm_has_sib() {
        let m = ModRm::decode(0x04); // mod=0, reg=0, rm=4
        assert!(m.has_sib());
    }

    #[test]
    fn test_modrm_disp32() {
        let m = ModRm::decode(0x05); // mod=0, reg=0, rm=5
        assert!(m.is_disp32_only());
        assert_eq!(m.disp_size(), 4);
    }

    #[test]
    fn test_sib_scale_factor() {
        let s = Sib::decode(0x85); // scale=2(×4), index=0, base=5
        assert_eq!(s.scale_factor(), 4);
        assert!(!s.has_no_index());
    }

    #[test]
    fn test_sib_no_index() {
        let s = Sib::decode(0x24); // scale=0, index=4, base=4
        assert!(s.has_no_index());
    }

    #[test]
    fn test_effective_addr_register() {
        let m = ModRm::decode(0xC0); // mod=3, reg=0, rm=0
        let ea = EffectiveAddr::decode(m, None, 0, &no_rex(), false);
        assert_eq!(ea, EffectiveAddr::Register(0));
    }

    #[test]
    fn test_effective_addr_base_disp() {
        let m = ModRm::decode(0x40); // mod=1, reg=0, rm=0
        let ea = EffectiveAddr::decode(m, None, 8, &no_rex(), false);
        assert_eq!(ea, EffectiveAddr::BaseDisp { base: 0, disp: 8 });
    }

    #[test]
    fn test_effective_addr_rip_rel() {
        let m = ModRm::decode(0x05); // mod=0, rm=5 → RIP-rel in 64-bit
        let ea = EffectiveAddr::decode(m, None, 0x1234, &no_rex(), true);
        assert_eq!(ea, EffectiveAddr::RipRelative { disp: 0x1234 });
        assert!(ea.is_memory());
    }

    #[test]
    fn test_gpr_name_64() {
        assert_eq!(gpr_name(0, 8, false), "rax");
        assert_eq!(gpr_name(7, 8, false), "rdi");
        assert_eq!(gpr_name(8, 8, false), "r8");
    }

    #[test]
    fn test_gpr_name_32() {
        assert_eq!(gpr_name(0, 4, false), "eax");
        assert_eq!(gpr_name(4, 4, false), "esp");
    }

    #[test]
    fn test_zmm_names_complete() {
        assert_eq!(ZMM_NAMES.len(), 32);
        assert_eq!(ZMM_NAMES[0], "zmm0");
        assert_eq!(ZMM_NAMES[31], "zmm31");
    }

    #[test]
    fn test_kmask_names() {
        assert_eq!(KMASK_NAMES[0], "k0");
        assert_eq!(KMASK_NAMES[7], "k7");
    }

    // ───── Additional edge-case coverage ──────────────────────────────────

    #[test]
    fn modrm_decode_all_256_bytes_no_panic() {
        for b in 0u16..=0xFF {
            let m = ModRm::decode(b as u8);
            assert!(m.mode <= 3);
            assert!(m.reg <= 7);
            assert!(m.rm <= 7);
        }
    }

    #[test]
    fn modrm_disp_size_mode0_rm5_is_disp32() {
        let m = ModRm::decode(0b00_000_101); // mod=0 rm=5
        assert_eq!(m.disp_size(), 4);
        assert!(m.is_disp32_only());
        assert!(!m.has_sib());
    }

    #[test]
    fn modrm_has_sib_only_when_mode_lt3_and_rm4() {
        // mod=3 rm=4 should NOT have SIB (mod=3 is reg-direct)
        let m = ModRm::decode(0b11_000_100);
        assert!(!m.has_sib());
        assert!(m.is_reg());
        // mod=2 rm=4 has SIB
        let m2 = ModRm::decode(0b10_000_100);
        assert!(m2.has_sib());
        assert!(!m2.is_reg());
    }

    #[test]
    fn modrm_disp_size_all_modes() {
        // mode 1: 1 byte
        assert_eq!(ModRm::decode(0b01_000_000).disp_size(), 1);
        // mode 2: 4 bytes
        assert_eq!(ModRm::decode(0b10_000_000).disp_size(), 4);
        // mode 3: 0 bytes
        assert_eq!(ModRm::decode(0b11_000_000).disp_size(), 0);
        // mode 0 rm!=5: 0 bytes
        assert_eq!(ModRm::decode(0b00_000_000).disp_size(), 0);
    }

    #[test]
    fn sib_scale_factor_all_values() {
        // scale field 0..=3 -> factors 1,2,4,8
        let s0 = Sib::decode(0b00_000_000);
        let s1 = Sib::decode(0b01_000_000);
        let s2 = Sib::decode(0b10_000_000);
        let s3 = Sib::decode(0b11_000_000);
        assert_eq!(s0.scale_factor(), 1);
        assert_eq!(s1.scale_factor(), 2);
        assert_eq!(s2.scale_factor(), 4);
        assert_eq!(s3.scale_factor(), 8);
    }

    #[test]
    fn sib_has_no_index_when_index_eq_4() {
        let s = Sib::decode(0b00_100_000); // index=4
        assert!(s.has_no_index());
        let s2 = Sib::decode(0b00_011_000); // index=3
        assert!(!s2.has_no_index());
    }

    #[test]
    fn gpr_name_invalid_size_returns_unknown() {
        assert_eq!(gpr_name(0, 3, false), "???");
        assert_eq!(gpr_name(0, 0, false), "???");
        assert_eq!(gpr_name(0, 16, false), "???");
    }

    #[test]
    fn gpr_name_index_wraps_at_16() {
        // Function masks index with 0xF, so 16 maps to 0 (no panic).
        assert_eq!(gpr_name(16, 8, false), "rax");
        assert_eq!(gpr_name(255, 8, false), gpr_name(15, 8, false));
    }

    /// Regression: in 32-bit mode, mod=0 rm=5 is absolute disp32
    /// (`mov eax, [0x00401000]` = 8B 05 00 10 40 00), NOT [EIP+disp].
    #[test]
    fn effective_addr_32bit_disp32_is_absolute_not_riprel() {
        let m = ModRm::decode(0x05); // mod=0, reg=0, rm=5
        let ea = EffectiveAddr::decode(m, None, 0x0040_1000, &no_rex(), false);
        assert_eq!(ea, EffectiveAddr::Absolute { addr: 0x0040_1000 });
        assert!(ea.is_memory());
    }

    /// Regression: a SIB byte suppresses RIP-relative addressing even in
    /// 64-bit mode. `mov eax, [0x11223344]` = 8B 04 25 44 33 22 11:
    /// modrm=0x04 (mod=0 rm=4 -> SIB), sib=0x25 (index=4, base=5).
    #[test]
    fn effective_addr_sib_disp32_only_is_absolute_in_64bit() {
        let m = ModRm::decode(0x04); // mod=0, rm=4 -> SIB follows
        let s = Sib::decode(0x25); // scale=0, index=4 (none), base=5 (disp only)
        let ea = EffectiveAddr::decode(m, Some(s), 0x1122_3344, &no_rex(), true);
        assert_eq!(ea, EffectiveAddr::Absolute { addr: 0x1122_3344 });
    }

    /// Same SIB disp32-only form in 32-bit mode is also absolute.
    #[test]
    fn effective_addr_sib_disp32_only_is_absolute_in_32bit() {
        let m = ModRm::decode(0x04);
        let s = Sib::decode(0x25);
        let ea = EffectiveAddr::decode(m, Some(s), 0x1000, &no_rex(), false);
        assert_eq!(ea, EffectiveAddr::Absolute { addr: 0x1000 });
    }

    /// RIP-relative must still be produced on the no-SIB mod=0/rm=5 path
    /// in 64-bit mode (unchanged behavior).
    #[test]
    fn effective_addr_64bit_no_sib_disp32_still_riprel() {
        let m = ModRm::decode(0x05);
        let ea = EffectiveAddr::decode(m, None, -16, &no_rex(), true);
        assert_eq!(ea, EffectiveAddr::RipRelative { disp: -16 });
    }

    #[test]
    fn effective_addr_register_is_not_memory() {
        let rex = RexPrefix::default();
        let modrm = ModRm::decode(0b11_000_001); // reg-direct
        let ea = EffectiveAddr::decode(modrm, None, 0, &rex, true);
        assert!(!ea.is_memory());
        assert_eq!(ea.base_reg(), Some(1));
    }
}
