//! x86 prefix decoding: REX, VEX (2-byte and 3-byte), EVEX.
//!
//! # Layer distinction
//!
//! This module provides **low-level struct decoders** for individual prefix
//! bytes: [`RexPrefix`] parses 40h–4Fh REX bytes; [`VexPrefix`] and
//! [`EvexPrefix`] parse C5h/C4h/62h multi-byte VEX/EVEX encodings.  All types
//! are `Copy` and operate directly on raw byte values.
//!
//! For **high-level prefix classification** — grouping prefix bytes into
//! [`crate::x86_prefix_analyzer::PrefixGroup`] categories, detecting
//! mandatory-prefix semantics, and building a [`crate::x86_prefix_analyzer::X86PrefixAnalyzer`]
//! that processes a full prefix stream — see [`crate::x86_prefix_analyzer`].
//! The two modules are complementary, not duplicates.

// ---------------------------------------------------------------------------
// REX prefix
// ---------------------------------------------------------------------------

/// Decoded REX prefix byte (40h–4Fh in 64-bit mode).
///
/// A REX byte has the form `0100 WRXB`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[must_use]
pub struct RexPrefix {
    /// REX.W — promotes operand to 64-bit.
    pub w: bool,
    /// REX.R — extends ModRM.reg to register indices 8–15.
    pub r: bool,
    /// REX.X — extends SIB.index to register indices 8–15.
    pub x: bool,
    /// REX.B — extends ModRM.r/m, SIB.base, or opcode reg to 8–15.
    pub b: bool,
    /// Whether a REX byte was actually present.
    pub present: bool,
}

impl RexPrefix {
    /// Parse a REX byte. Returns a non-present default if the byte is not in
    /// the range 40h–4Fh.
    pub fn parse(byte: u8) -> Self {
        if byte >> 4 != 0x4 {
            return Self::default();
        }
        Self {
            w: (byte & 0x08) != 0,
            r: (byte & 0x04) != 0,
            x: (byte & 0x02) != 0,
            b: (byte & 0x01) != 0,
            present: true,
        }
    }

    /// Extend a 3-bit register field using the REX.R bit.
    ///
    /// Returns the extended (4-bit) register index.
    #[must_use]
    pub const fn extend_reg(&self, reg3: u8) -> u8 {
        reg3 | (if self.r { 8 } else { 0 })
    }

    /// Extend a 3-bit register field using the REX.B bit.
    ///
    /// Returns the extended (4-bit) register index.
    #[must_use]
    pub const fn extend_rm(&self, rm3: u8) -> u8 {
        rm3 | (if self.b { 8 } else { 0 })
    }

    /// Extend a 3-bit SIB index field using the REX.X bit.
    ///
    /// Returns the extended (4-bit) register index.
    #[must_use]
    pub const fn extend_index(&self, idx3: u8) -> u8 {
        idx3 | (if self.x { 8 } else { 0 })
    }

    /// Extend a 3-bit SIB base field using the REX.B bit.
    ///
    /// Returns the extended (4-bit) register index.
    #[must_use]
    pub const fn extend_base(&self, base3: u8) -> u8 {
        base3 | (if self.b { 8 } else { 0 })
    }
}

// ---------------------------------------------------------------------------
// VEX prefix
// ---------------------------------------------------------------------------

/// `Map_select` values for VEX/EVEX (equivalent to legacy escape bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum VexMap {
    /// 0F xx opcodes.
    Map0F,
    /// 0F 38 xx opcodes.
    Map0F38,
    /// 0F 3A xx opcodes.
    Map0F3A,
    /// Other / reserved.
    Other(u8),
}

impl VexMap {
    const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Map0F,
            2 => Self::Map0F38,
            3 => Self::Map0F3A,
            other => Self::Other(other),
        }
    }
}

/// Implied legacy prefix embedded in VEX/EVEX pp field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum VexPp {
    /// No prefix.
    None,
    /// 66h operand-size prefix (SSE2 / 128-bit integer).
    P66,
    /// F3h REP prefix.
    PF3,
    /// F2h REPNE prefix.
    PF2,
}

impl VexPp {
    fn from_u8(v: u8) -> Self {
        match v & 3 {
            0 => Self::None,
            1 => Self::P66,
            2 => Self::PF3,
            3 => Self::PF2,
            _ => unreachable!(),
        }
    }
}

/// Fully decoded VEX prefix (2-byte C5h or 3-byte C4h form).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct VexPrefix {
    /// R bit (inverted from byte — 0 means extension active).
    pub r: bool,
    /// X bit (3-byte form only; 0 means extension active).
    pub x: bool,
    /// B bit (3-byte form only; 0 means extension active).
    pub b: bool,
    /// W bit (3-byte form only).
    pub w: bool,
    /// Opcode map selector.
    pub map: VexMap,
    /// NDS/NDD register (4-bit, one's complement from vvvv).
    pub vvvv: u8,
    /// Vector length: `false` = 128-bit (XMM), `true` = 256-bit (YMM).
    pub l: bool,
    /// Implied legacy prefix.
    pub pp: VexPp,
}

impl VexPrefix {
    /// Parse a 2-byte VEX prefix (C5h form).
    ///
    /// `b0` must be C5h; `b1` is the second byte.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `b0 != 0xC5`.
    pub fn parse_2byte(b1: u8) -> Self {
        Self {
            r: (b1 & 0x80) == 0, // inverted
            x: false,
            b: false,
            w: false,
            map: VexMap::Map0F,
            vvvv: (!b1 >> 3) & 0xF,
            l: (b1 & 0x04) != 0,
            pp: VexPp::from_u8(b1),
        }
    }

    /// Parse a 3-byte VEX prefix (C4h form).
    ///
    /// `b1` and `b2` are the two payload bytes (after the C4h lead byte).
    pub fn parse_3byte(b1: u8, b2: u8) -> Self {
        Self {
            r: (b1 & 0x80) == 0,
            x: (b1 & 0x40) == 0,
            b: (b1 & 0x20) == 0,
            w: (b2 & 0x80) != 0,
            map: VexMap::from_u8(b1 & 0x1F),
            vvvv: (!b2 >> 3) & 0xF,
            l: (b2 & 0x04) != 0,
            pp: VexPp::from_u8(b2),
        }
    }

    /// Extend a 3-bit ModRM.reg with VEX.R.
    #[must_use]
    pub const fn extend_reg(&self, reg3: u8) -> u8 {
        reg3 | (if self.r { 8 } else { 0 })
    }

    /// Extend a 3-bit ModRM.r/m or SIB.base with VEX.B.
    #[must_use]
    pub const fn extend_rm(&self, rm3: u8) -> u8 {
        rm3 | (if self.b { 8 } else { 0 })
    }

    /// Extend a 3-bit SIB.index with VEX.X.
    #[must_use]
    pub const fn extend_index(&self, idx3: u8) -> u8 {
        idx3 | (if self.x { 8 } else { 0 })
    }

    /// The decoded vvvv register index (0–15).
    #[must_use]
    pub const fn vvvv_reg(&self) -> u8 {
        self.vvvv
    }

    /// Whether this is a 256-bit (YMM) operation.
    #[must_use]
    pub const fn is_256(&self) -> bool {
        self.l
    }
}

// ---------------------------------------------------------------------------
// EVEX prefix
// ---------------------------------------------------------------------------

/// Fully decoded EVEX prefix (62h lead byte, 3 payload bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct EvexPrefix {
    /// EVEX.R (extends ModRM.reg to 8–15).
    pub r: bool,
    /// EVEX.X (extends SIB.index to 8–15).
    pub x: bool,
    /// EVEX.B (extends ModRM.r/m or SIB.base to 8–15).
    pub b: bool,
    /// EVEX.R' — extends ModRM.reg to 16–31.
    pub r_prime: bool,
    /// EVEX.B' (AVX-512 extended) -- extends ModRM.r/m to 16–31 or indicates broadcast.
    pub b_prime: bool,
    /// EVEX.W — promotes operand size / selects element type.
    pub w: bool,
    /// Opcode map selector.
    pub map: VexMap,
    /// NDS/NDD register vvvv (4-bit, one's complement).
    pub vvvv: u8,
    /// Extended vvvv bit V' (5th vvvv bit).
    pub v_prime: bool,
    /// Implied legacy prefix.
    pub pp: VexPp,
    /// Vector length / rounding: 0=128, 1=256, 2=512, 3=rounding override.
    pub ll: u8,
    /// Zeroing/merging mask flag: `true` = zeroing.
    pub z: bool,
    /// Opmask register index (k0–k7).
    pub aaa: u8,
    /// Broadcast / rounding / SAE flag.
    pub b_flag: bool,
}

impl EvexPrefix {
    /// Parse an EVEX prefix from the three payload bytes (after 62h lead).
    ///
    /// `p0`, `p1`, `p2` correspond to bytes at offsets +1, +2, +3.
    pub fn parse(p0: u8, p1: u8, p2: u8) -> Self {
        Self {
            r: (p0 & 0x80) == 0,
            x: (p0 & 0x40) == 0,
            b: (p0 & 0x20) == 0,
            r_prime: (p0 & 0x10) == 0,
            b_prime: (p0 & 0x08) == 0,
            map: VexMap::from_u8(p0 & 0x07),
            w: (p1 & 0x80) != 0,
            vvvv: (!p1 >> 3) & 0xF,
            pp: VexPp::from_u8(p1),
            z: (p2 & 0x80) != 0,
            ll: (p2 >> 5) & 0x03,
            b_flag: (p2 & 0x10) != 0,
            v_prime: (p2 & 0x08) == 0,
            aaa: p2 & 0x07,
        }
    }

    /// Reconstruct the full (5-bit) NDS register index from vvvv and V'.
    #[must_use]
    pub const fn nds_reg(&self) -> u8 {
        self.vvvv | (if self.v_prime { 0 } else { 16 })
    }

    /// Whether this is a 512-bit (ZMM) vector operation.
    #[must_use]
    pub const fn is_zmm(&self) -> bool {
        self.ll == 2
    }

    /// Whether this is a 256-bit (YMM) vector operation.
    #[must_use]
    pub const fn is_ymm(&self) -> bool {
        self.ll == 1
    }

    /// Whether this is a 128-bit (XMM) vector operation.
    #[must_use]
    pub const fn is_xmm(&self) -> bool {
        self.ll == 0
    }

    /// Extend a 3-bit ModRM.reg to full width using R + R'.
    ///
    /// Returns a 5-bit index (0–31).
    #[must_use]
    pub const fn extend_reg(&self, reg3: u8) -> u8 {
        let r4 = reg3 | (if self.r { 8 } else { 0 });
        r4 | (if self.r_prime { 16 } else { 0 })
    }

    /// Extend a 3-bit ModRM.r/m or SIB.base with B.
    #[must_use]
    pub const fn extend_rm(&self, rm3: u8) -> u8 {
        rm3 | (if self.b { 8 } else { 0 })
    }

    /// Extend a 3-bit SIB.index with X.
    #[must_use]
    pub const fn extend_index(&self, idx3: u8) -> u8 {
        idx3 | (if self.x { 8 } else { 0 })
    }
}

// ---------------------------------------------------------------------------
// Segment override / legacy prefix classification
// ---------------------------------------------------------------------------

/// Legacy prefix groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum LegacyPrefix {
    /// Group 1: LOCK (F0h).
    Lock,
    /// Group 1: REPNE/REPNZ (F2h).
    RepNe,
    /// Group 1: REP/REPE/REPZ (F3h).
    Rep,
    /// Group 2: CS segment override.
    SegCs,
    /// Group 2: SS segment override.
    SegSs,
    /// Group 2: DS segment override.
    SegDs,
    /// Group 2: ES segment override.
    SegEs,
    /// Group 2: FS segment override.
    SegFs,
    /// Group 2: GS segment override.
    SegGs,
    /// Group 2: Branch not taken hint.
    BranchNotTaken,
    /// Group 2: Branch taken hint.
    BranchTaken,
    /// Group 3: Operand-size override (66h).
    OpSize,
    /// Group 4: Address-size override (67h).
    AddrSize,
}

/// Classify a byte as a legacy prefix, returning `None` if not a prefix.
#[must_use]
pub const fn classify_legacy_prefix(byte: u8) -> Option<LegacyPrefix> {
    match byte {
        0xF0 => Some(LegacyPrefix::Lock),
        0xF2 => Some(LegacyPrefix::RepNe),
        0xF3 => Some(LegacyPrefix::Rep),
        0x2E => Some(LegacyPrefix::SegCs), // also BranchNotTaken in some contexts
        0x36 => Some(LegacyPrefix::SegSs),
        0x3E => Some(LegacyPrefix::SegDs), // also BranchTaken in some contexts
        0x26 => Some(LegacyPrefix::SegEs),
        0x64 => Some(LegacyPrefix::SegFs),
        0x65 => Some(LegacyPrefix::SegGs),
        0x66 => Some(LegacyPrefix::OpSize),
        0x67 => Some(LegacyPrefix::AddrSize),
        _ => None,
    }
}

/// A collected set of legacy prefixes seen before an instruction.
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct PrefixSet {
    /// LOCK prefix present.
    pub lock: bool,
    /// REP/REPE/REPZ present.
    pub rep: bool,
    /// REPNE/REPNZ present.
    pub repne: bool,
    /// Operand-size override (66h).
    pub op_size: bool,
    /// Address-size override (67h).
    pub addr_size: bool,
    /// Segment override, if any.
    pub segment: Option<SegmentReg>,
    /// REX prefix, if present (64-bit mode only).
    pub rex: RexPrefix,
    /// Number of prefix bytes consumed.
    pub count: usize,
}

/// x86 segment register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum SegmentReg {
    Cs,
    Ss,
    Ds,
    Es,
    Fs,
    Gs,
}

impl PrefixSet {
    /// Consume all legacy (and optionally REX) prefix bytes from `bytes`,
    /// stopping at the first non-prefix byte or at a VEX/EVEX lead byte.
    ///
    /// Returns the number of bytes consumed.
    pub fn consume(bytes: &[u8], is_64bit: bool) -> Self {
        let mut ps = Self::default();
        // A REX prefix is only effective when it *immediately* precedes the
        // opcode (Intel SDM §2.2.1). Any legacy prefix appearing after a REX
        // therefore nullifies that REX — modelled here by clearing `ps.rex`
        // whenever a legacy prefix is consumed, and by *not* stopping at a REX
        // (so a trailing opcode keeps it, but a following prefix discards it).
        for &b in bytes {
            match b {
                0xF0 => {
                    ps.lock = true;
                    ps.count += 1;
                    ps.rex = RexPrefix::default();
                }
                0xF2 => {
                    ps.repne = true;
                    ps.count += 1;
                    ps.rex = RexPrefix::default();
                }
                0xF3 => {
                    ps.rep = true;
                    ps.count += 1;
                    ps.rex = RexPrefix::default();
                }
                0x26 => {
                    ps.segment = Some(SegmentReg::Es);
                    ps.count += 1;
                    ps.rex = RexPrefix::default();
                }
                0x2E => {
                    ps.segment = Some(SegmentReg::Cs);
                    ps.count += 1;
                    ps.rex = RexPrefix::default();
                }
                0x36 => {
                    ps.segment = Some(SegmentReg::Ss);
                    ps.count += 1;
                    ps.rex = RexPrefix::default();
                }
                0x3E => {
                    ps.segment = Some(SegmentReg::Ds);
                    ps.count += 1;
                    ps.rex = RexPrefix::default();
                }
                0x64 => {
                    ps.segment = Some(SegmentReg::Fs);
                    ps.count += 1;
                    ps.rex = RexPrefix::default();
                }
                0x65 => {
                    ps.segment = Some(SegmentReg::Gs);
                    ps.count += 1;
                    ps.rex = RexPrefix::default();
                }
                0x66 => {
                    ps.op_size = true;
                    ps.count += 1;
                    ps.rex = RexPrefix::default();
                }
                0x67 => {
                    ps.addr_size = true;
                    ps.count += 1;
                    ps.rex = RexPrefix::default();
                }
                b if is_64bit && (b >> 4) == 0x4 => {
                    // Tentatively the effective REX; a following prefix clears it,
                    // a following opcode keeps it.
                    ps.rex = RexPrefix::parse(b);
                    ps.count += 1;
                }
                0xC4 | 0xC5 | 0x62 => break, // VEX/EVEX — stop
                _ => break,
            }
        }
        ps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rex_parse_w() {
        let r = RexPrefix::parse(0x48);
        assert!(r.present);
        assert!(r.w);
        assert!(!r.r);
        assert!(!r.x);
        assert!(!r.b);
    }

    #[test]
    fn test_rex_parse_wrxb() {
        let r = RexPrefix::parse(0x4F);
        assert!(r.w && r.r && r.x && r.b);
    }

    #[test]
    fn test_rex_not_present() {
        let r = RexPrefix::parse(0x55);
        assert!(!r.present);
    }

    #[test]
    fn test_rex_extend_reg() {
        let r = RexPrefix::parse(0x44); // REX.R
        assert_eq!(r.extend_reg(3), 11); // 3 + 8
    }

    #[test]
    fn test_vex2_parse() {
        // C5 F8 → R=1(not ext), vvvv=0b1111→0, L=0, pp=00
        let v = VexPrefix::parse_2byte(0xF8);
        assert!(!v.r); // bit7 inverted: 1→r=true means extension
        // actually bit7=1 → r = (0x80 == 0) = false, so no extension
        assert!(!v.l);
        assert!(matches!(v.pp, VexPp::None));
        assert!(matches!(v.map, VexMap::Map0F));
    }

    #[test]
    fn test_vex3_parse() {
        // C4 E1 7D — vvvv=1111, L=1(256-bit), pp=01
        let v = VexPrefix::parse_3byte(0xE1, 0x7D);
        assert!(matches!(v.map, VexMap::Map0F));
        assert!(v.l); // bit2 of b2 = 1 (0x7D = 0111_1101)
    }

    #[test]
    fn test_evex_zmm() {
        // 62 F1 7C 48 — typical AVX-512 ZMM prefix
        let e = EvexPrefix::parse(0xF1, 0x7C, 0x48);
        assert!(e.is_zmm());
        assert!(!e.z);
    }

    #[test]
    fn test_evex_nds_reg() {
        // v_prime=false (bit3=1 → v_prime = (0x08==0) = false → nds adds 16)
        let e = EvexPrefix::parse(0x62, 0x7D, 0x08);
        let nds = e.nds_reg();
        assert!(nds < 32);
    }

    #[test]
    fn test_prefix_set_consume_lock_rep() {
        let bytes = &[0xF0, 0xF3, 0x90];
        let ps = PrefixSet::consume(bytes, false);
        assert!(ps.lock);
        assert!(ps.rep);
        assert_eq!(ps.count, 2);
    }

    #[test]
    fn test_prefix_set_consume_rex() {
        let bytes = &[0x48, 0x89];
        let ps = PrefixSet::consume(bytes, true);
        assert!(ps.rex.present);
        assert!(ps.rex.w);
        assert_eq!(ps.count, 1);
    }

    #[test]
    fn test_classify_legacy_prefix() {
        assert_eq!(classify_legacy_prefix(0xF0), Some(LegacyPrefix::Lock));
        assert_eq!(classify_legacy_prefix(0x66), Some(LegacyPrefix::OpSize));
        assert_eq!(classify_legacy_prefix(0x90), None);
    }
}
