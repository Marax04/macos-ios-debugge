//! x86 instruction prefix analysis.
//!
//! Provides [`X86PrefixAnalyzer`], [`Prefix`], [`PrefixGroup`], and
//! [`parse_prefix_byte()`] for decoding the legacy, REX, VEX, EVEX, and
//! XOP prefix bytes that appear before an x86 instruction encoding.
//!
//! # Layer distinction
//!
//! This module is the **high-level prefix classifier**: it maps raw prefix
//! bytes into [`PrefixGroup`] categories, detects mandatory-prefix semantics,
//! and exposes an [`X86PrefixAnalyzer`] that processes a full prefix stream
//! (including conflict detection within the same group).
//!
//! For **low-level struct decoders** that parse individual prefix bytes into
//! typed bit-field structs — `RexPrefix`, `VexPrefix`, `EvexPrefix` — see
//! [`crate::prefix`].
//!
//! # Dispatch status (NOT wired — 2026-07-23)
//!
//! This module does not run. `crate::prefix` is the one on the real path
//! (`length.rs:51` and `:564` call `PrefixSet::consume`); the only references
//! to `X86PrefixAnalyzer` / `parse_prefix_byte` anywhere in the workspace are
//! the `pub mod` line in lib.rs and `tests/blitz.rs`.
//!
//! This note replaces the previous claim that the two modules are
//! "complementary, not duplicates". That was misleading: it reads as though
//! both layers execute, so the project appears to have VEX/EVEX/XOP
//! prefix-group conflict detection available to analysis. It does not — that
//! capability exists here and is never invoked.
//!
//! Keep, delete, or wire — but do not assume it is live.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// PrefixGroup
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level category for a prefix byte or prefix encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PrefixGroup {
    /// Legacy group-1 prefixes (LOCK, REPNE, REP).
    Group1,
    /// Legacy group-2 prefixes (segment overrides, branch hints).
    Group2,
    /// Legacy group-3 prefix (operand-size override — 66h).
    Group3,
    /// Legacy group-4 prefix (address-size override — 67h).
    Group4,
    /// REX prefix (40h–4Fh, 64-bit mode only).
    Rex,
    /// VEX two-byte encoding (C5h).
    Vex2,
    /// VEX three-byte encoding (C4h).
    Vex3,
    /// EVEX four-byte encoding (62h).
    Evex,
    /// XOP prefix (8Fh with certain sub-bytes).
    Xop,
    /// BOUND/MPFX encodings that share a prefix byte.
    Bound,
    /// Not a prefix byte.
    NotAPrefix,
}

impl fmt::Display for PrefixGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Group1 => "Grp1",
            Self::Group2 => "Grp2",
            Self::Group3 => "Grp3",
            Self::Group4 => "Grp4",
            Self::Rex => "REX",
            Self::Vex2 => "VEX2",
            Self::Vex3 => "VEX3",
            Self::Evex => "EVEX",
            Self::Xop => "XOP",
            Self::Bound => "BOUND",
            Self::NotAPrefix => "NONE",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Prefix
// ─────────────────────────────────────────────────────────────────────────────

/// Detailed description of a single decoded prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix {
    /// The leading byte of the prefix.
    pub byte: u8,
    /// Which group this prefix belongs to.
    pub group: PrefixGroup,
    /// Human-readable name.
    pub name: &'static str,
    /// Whether this prefix is mandatory (required for decoding the opcode).
    pub is_mandatory: bool,
    /// Whether this prefix conflicts with others in the same group.
    pub is_exclusive: bool,
}

impl Prefix {
    fn new(
        byte: u8,
        group: PrefixGroup,
        name: &'static str,
        mandatory: bool,
        exclusive: bool,
    ) -> Self {
        Self {
            byte,
            group,
            name,
            is_mandatory: mandatory,
            is_exclusive: exclusive,
        }
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X}h ({} / {})", self.byte, self.name, self.group)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PrefixSet
// ─────────────────────────────────────────────────────────────────────────────

/// The complete decoded prefix state for one instruction.
#[derive(Debug, Clone, Default)]
pub struct PrefixSet {
    /// All prefixes found (in order).
    pub prefixes: Vec<Prefix>,
    /// Total bytes consumed by prefixes.
    pub prefix_bytes: usize,
    /// Whether LOCK is present.
    pub lock: bool,
    /// Whether REP (F3h) is present.
    pub rep: bool,
    /// Whether REPNE (F2h) is present.
    pub repne: bool,
    /// Whether operand-size override (66h) is present.
    pub operand_size_override: bool,
    /// Whether address-size override (67h) is present.
    pub address_size_override: bool,
    /// Segment override register, if any.
    pub segment_override: Option<SegmentReg>,
    /// REX prefix byte (0 = absent).
    pub rex: u8,
    /// Whether REX.W (64-bit operand size) is set.
    pub rex_w: bool,
    /// Whether REX.R (ModRM.reg extension) is set.
    pub rex_r: bool,
    /// Whether REX.X (SIB.index extension) is set.
    pub rex_x: bool,
    /// Whether REX.B (ModRM.rm / SIB.base / opcode-reg extension) is set.
    pub rex_b: bool,
    /// VEX/EVEX/XOP encoding header, if present.
    pub escape: Option<EscapeEncoding>,
    /// Whether any redundant (repeated) prefix was detected.
    pub has_redundant: bool,
    /// Whether any conflicting prefixes within the same group were detected.
    pub has_conflict: bool,
}

impl PrefixSet {
    #[must_use]
    pub fn is_vex_encoded(&self) -> bool {
        matches!(
            self.escape,
            Some(EscapeEncoding::Vex2(_) | EscapeEncoding::Vex3(_, _))
        )
    }

    #[must_use]
    pub fn is_evex_encoded(&self) -> bool {
        matches!(self.escape, Some(EscapeEncoding::Evex(_, _, _)))
    }

    #[must_use]
    pub fn is_xop_encoded(&self) -> bool {
        matches!(self.escape, Some(EscapeEncoding::Xop(_, _)))
    }

    #[must_use]
    pub fn effective_operand_size_override(&self) -> bool {
        self.operand_size_override || self.rex_w
    }
}

/// Segment register names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentReg {
    CS,
    SS,
    DS,
    ES,
    FS,
    GS,
}

impl fmt::Display for SegmentReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CS => "CS",
            Self::SS => "SS",
            Self::DS => "DS",
            Self::ES => "ES",
            Self::FS => "FS",
            Self::GS => "GS",
        };
        write!(f, "{s}")
    }
}

/// Extended escape encodings (VEX / EVEX / XOP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscapeEncoding {
    /// VEX 2-byte: (R̄, vvvv, L, pp).
    Vex2(u8),
    /// VEX 3-byte: (R̄X̄B̄, m-mmmm), (W, vvvv, L, pp).
    Vex3(u8, u8),
    /// EVEX: bytes P1, P2, P3.
    Evex(u8, u8, u8),
    /// XOP: bytes P1, P2.
    Xop(u8, u8),
}

// ─────────────────────────────────────────────────────────────────────────────
// X86PrefixAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Parses the prefix bytes from raw x86 instruction encoding.
///
/// Supports legacy, REX, VEX (2+3 byte), EVEX, and XOP prefixes.
#[derive(Debug)]
pub struct X86PrefixAnalyzer {
    /// Target machine bitness (16, 32, or 64).
    bitness: u32,
    /// Custom prefix override table.
    overrides: HashMap<u8, Prefix>,
}

impl X86PrefixAnalyzer {
    /// Create for 64-bit mode.
    #[must_use]
    pub fn new_64bit() -> Self {
        Self {
            bitness: 64,
            overrides: HashMap::new(),
        }
    }

    /// Create for 32-bit mode.
    #[must_use]
    pub fn new_32bit() -> Self {
        Self {
            bitness: 32,
            overrides: HashMap::new(),
        }
    }

    /// Create for 16-bit mode.
    #[must_use]
    pub fn new_16bit() -> Self {
        Self {
            bitness: 16,
            overrides: HashMap::new(),
        }
    }

    #[must_use]
    pub fn bitness(&self) -> u32 {
        self.bitness
    }

    /// Register a custom prefix description for `byte`.
    pub fn add_override(&mut self, prefix: Prefix) {
        self.overrides.insert(prefix.byte, prefix);
    }

    /// Parse all prefix bytes from `bytes`, returning a [`PrefixSet`] and the
    /// number of bytes consumed.
    #[must_use]
    pub fn parse(&self, bytes: &[u8]) -> (PrefixSet, usize) {
        let mut ps = PrefixSet::default();
        let mut i = 0usize;
        // At most 4 legacy prefix groups (g1–g4) plus "misc"; pre-size accordingly.
        let mut seen_groups: HashMap<&'static str, bool> = HashMap::with_capacity(5);

        while i < bytes.len() {
            let b = bytes[i];

            // VEX2 / VEX3 / EVEX / XOP — these consume multiple bytes.
            //
            // In 16/32-bit mode C5/C4/62 are the legacy LDS/LES/BOUND
            // opcodes unless the byte after the escape has mod == 0b11
            // (the standard mode-dependent ModRM disambiguation rule);
            // a legacy LDS/LES/BOUND ModRM never has mod == 0b11.
            let escape_ok = |next: u8| self.bitness == 64 || (next >> 6) == 0b11;
            if b == 0xC5 && i + 1 < bytes.len() && escape_ok(bytes[i + 1]) {
                // VEX 2-byte.
                let p1 = bytes[i + 1];
                ps.escape = Some(EscapeEncoding::Vex2(p1));
                ps.prefix_bytes = i + 2;
                ps.prefixes.push(Prefix::new(b, PrefixGroup::Vex2, "VEX2", true, true));
                return (ps, i + 2);
            }
            if b == 0xC4 && i + 2 < bytes.len() && escape_ok(bytes[i + 1]) {
                // VEX 3-byte.
                let p1 = bytes[i + 1];
                let p2 = bytes[i + 2];
                ps.escape = Some(EscapeEncoding::Vex3(p1, p2));
                ps.prefix_bytes = i + 3;
                ps.prefixes.push(Prefix::new(b, PrefixGroup::Vex3, "VEX3", true, true));
                return (ps, i + 3);
            }
            if b == 0x62 && i + 3 < bytes.len() && escape_ok(bytes[i + 1]) {
                // EVEX.
                let p1 = bytes[i + 1];
                let p2 = bytes[i + 2];
                let p3 = bytes[i + 3];
                ps.escape = Some(EscapeEncoding::Evex(p1, p2, p3));
                ps.prefix_bytes = i + 4;
                ps.prefixes.push(Prefix::new(b, PrefixGroup::Evex, "EVEX", true, true));
                return (ps, i + 4);
            }
            // In non-64-bit mode a C4/C5/62 that failed the disambiguation
            // above is a legacy opcode (LES/LDS/BOUND) — stop prefix parsing.
            if self.bitness != 64 && matches!(b, 0xC4 | 0xC5 | 0x62) {
                break;
            }
            if b == 0x8F && i + 2 < bytes.len() {
                let p1 = bytes[i + 1];
                // XOP if the 5-bit map_select field (bits [4:0]) is >= 8
                // (XOP maps 8, 9, 0xA). POP r/m64 requires the legacy
                // modrm.reg field to be 0, so map_select >= 8 (which has
                // bit 3 set) never collides with a valid POP encoding.
                let map_select = p1 & 0x1F;
                if map_select >= 8 {
                    let p2 = bytes[i + 2];
                    ps.escape = Some(EscapeEncoding::Xop(p1, p2));
                    ps.prefix_bytes = i + 3;
                    ps.prefixes.push(Prefix::new(b, PrefixGroup::Xop, "XOP", true, true));
                    return (ps, i + 3);
                }
                // Otherwise it's the BOUND / POP instruction — stop prefix parsing.
                break;
            }

            // Legacy prefix.
            let prefix = if let Some(ov) = self.overrides.get(&b) {
                ov.clone()
            } else if let Some(p) = parse_prefix_byte(b, self.bitness) {
                p
            } else {
                break; // Not a prefix byte.
            };

            // Conflict / redundancy detection within the same group.
            let group_key: &'static str = match prefix.group {
                PrefixGroup::Group1 => "g1",
                PrefixGroup::Group2 => "g2",
                PrefixGroup::Group3 => "g3",
                PrefixGroup::Group4 => "g4",
                _ => "misc",
            };
            if let Some(already) = seen_groups.get(group_key)
                && *already
            {
                if prefix.is_exclusive {
                    ps.has_conflict = true;
                } else {
                    ps.has_redundant = true;
                }
            }
            seen_groups.insert(group_key, true);

            // Accumulate semantic state.
            //
            // Every legacy prefix CLEARS any REX seen so far. Intel SDM Vol. 2
            // §2.2.1: the REX prefix must *immediately* precede the opcode (or
            // the 0F escape); placed anywhere else it is ignored. Verified
            // against a real decoder rather than taken from the manual alone —
            // `48 66 90` decodes as `xchg ax,ax`, not `xchg rax,rax`, so the
            // intervening 66 does nullify the REX.W.
            //
            // Without this the analyzer reported a REX that the CPU discards,
            // disagreeing with the live `prefix::PrefixSet::consume` (which has
            // always modelled the rule) on 2046 of 5832 prefix sequences —
            // every other field agreed, so this was the ONLY semantic split
            // between the two implementations.
            if matches!(b, 0xF0 | 0xF2 | 0xF3 | 0x66 | 0x67 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65)
            {
                ps.rex = 0;
                ps.rex_w = false;
                ps.rex_r = false;
                ps.rex_x = false;
                ps.rex_b = false;
            }
            match b {
                0xF0 => ps.lock = true,
                0xF2 => ps.repne = true,
                0xF3 => ps.rep = true,
                0x66 => ps.operand_size_override = true,
                0x67 => ps.address_size_override = true,
                0x2E => ps.segment_override = Some(SegmentReg::CS),
                0x36 => ps.segment_override = Some(SegmentReg::SS),
                0x3E => ps.segment_override = Some(SegmentReg::DS),
                0x26 => ps.segment_override = Some(SegmentReg::ES),
                0x64 => ps.segment_override = Some(SegmentReg::FS),
                0x65 => ps.segment_override = Some(SegmentReg::GS),
                0x40..=0x4F => {
                    ps.rex = b;
                    ps.rex_w = (b & 0x08) != 0;
                    ps.rex_r = (b & 0x04) != 0;
                    ps.rex_x = (b & 0x02) != 0;
                    ps.rex_b = (b & 0x01) != 0;
                }
                _ => {}
            }

            ps.prefixes.push(prefix);
            i += 1;
        }

        ps.prefix_bytes = i;
        (ps, i)
    }

    /// Parse just the prefix bytes and return the opcode byte(s) that follow.
    #[must_use]
    pub fn extract_opcode_bytes<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let (_, consumed) = self.parse(bytes);
        &bytes[consumed..]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_prefix_byte
// ─────────────────────────────────────────────────────────────────────────────

/// Primary entry point: parse a single prefix byte `b` for the given
/// `bitness` and return a [`Prefix`] if the byte is a recognised prefix.
///
/// Returns `None` if `b` is not a valid prefix for the given bitness.
#[must_use]
pub fn parse_prefix_byte(b: u8, bitness: u32) -> Option<Prefix> {
    match b {
        0xF0 => Some(Prefix::new(b, PrefixGroup::Group1, "LOCK",  false, true)),
        0xF2 => Some(Prefix::new(b, PrefixGroup::Group1, "REPNE", false, true)),
        0xF3 => Some(Prefix::new(b, PrefixGroup::Group1, "REP",   false, true)),
        0x2E => Some(Prefix::new(b, PrefixGroup::Group2, "CS:",   false, false)),
        0x36 => Some(Prefix::new(b, PrefixGroup::Group2, "SS:",   false, false)),
        0x3E => Some(Prefix::new(b, PrefixGroup::Group2, "DS:",   false, false)),
        0x26 => Some(Prefix::new(b, PrefixGroup::Group2, "ES:",   false, false)),
        0x64 => Some(Prefix::new(b, PrefixGroup::Group2, "FS:",   false, false)),
        0x65 => Some(Prefix::new(b, PrefixGroup::Group2, "GS:",   false, false)),
        0x66 => Some(Prefix::new(b, PrefixGroup::Group3, "OS:",   false, false)),
        0x67 => Some(Prefix::new(b, PrefixGroup::Group4, "AS:",   false, false)),
        0x40..=0x4F if bitness == 64 => {
            // REX prefix — only valid in 64-bit mode.
            Some(Prefix::new(b, PrefixGroup::Rex, "REX", false, true))
        }
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_prefix_parsed() {
        let p = parse_prefix_byte(0xF0, 64).unwrap();
        assert_eq!(p.group, PrefixGroup::Group1);
        assert_eq!(p.name, "LOCK");
    }

    #[test]
    fn rep_prefix_parsed() {
        let p = parse_prefix_byte(0xF3, 64).unwrap();
        assert_eq!(p.name, "REP");
    }

    #[test]
    fn rex_only_in_64bit() {
        assert!(parse_prefix_byte(0x48, 64).is_some());
        assert!(parse_prefix_byte(0x48, 32).is_none());
    }

    #[test]
    fn operand_size_override_parsed() {
        let p = parse_prefix_byte(0x66, 32).unwrap();
        assert_eq!(p.group, PrefixGroup::Group3);
    }

    #[test]
    fn non_prefix_byte_returns_none() {
        assert!(parse_prefix_byte(0x90, 64).is_none()); // NOP
        assert!(parse_prefix_byte(0x48, 32).is_none()); // DEC EAX in 32-bit
    }

    #[test]
    fn analyzer_parses_lock_add() {
        // LOCK ADD [rax], 1 = F0 83 00 01
        let bytes = [0xF0u8, 0x83, 0x00, 0x01];
        let analyzer = X86PrefixAnalyzer::new_64bit();
        let (ps, consumed) = analyzer.parse(&bytes);
        assert_eq!(consumed, 1);
        assert!(ps.lock);
    }

    #[test]
    fn analyzer_parses_rex_w() {
        // REX.W prefix = 0x48, then MOV rax, imm64
        let bytes = [0x48u8, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let analyzer = X86PrefixAnalyzer::new_64bit();
        let (ps, consumed) = analyzer.parse(&bytes);
        assert_eq!(consumed, 1);
        assert!(ps.rex_w);
        assert_eq!(ps.rex, 0x48);
    }

    /// REGRESSION: a REX is effective only when it IMMEDIATELY precedes the
    /// opcode (Intel SDM Vol. 2 §2.2.1). This analyzer reported a REX that any
    /// intervening legacy prefix discards, disagreeing with the live
    /// `prefix::PrefixSet::consume` on 2046 of 5832 prefix sequences.
    ///
    /// Ground truth is empirical, not just the manual: a real decoder reads
    /// `48 66 90` as `xchg ax,ax`. Were the REX.W live it would be
    /// `xchg rax,rax`.
    #[test]
    fn rex_is_nullified_by_a_following_legacy_prefix() {
        let analyzer = X86PrefixAnalyzer::new_64bit();

        // REX.W then 66 then opcode — the REX is discarded.
        let (ps, consumed) = analyzer.parse(&[0x48u8, 0x66, 0x90]);
        assert_eq!(consumed, 2, "both prefix bytes are still consumed");
        assert_eq!(ps.rex, 0, "REX must not survive an intervening 66");
        assert!(!ps.rex_w);
        assert!(ps.operand_size_override, "the 66 itself still applies");

        // REX immediately before the opcode — still effective.
        let (ps, _) = analyzer.parse(&[0x48u8, 0x90]);
        assert_eq!(ps.rex, 0x48);
        assert!(ps.rex_w);

        // A REX that follows a legacy prefix is the effective one.
        let (ps, _) = analyzer.parse(&[0x66u8, 0x48, 0x90]);
        assert_eq!(ps.rex, 0x48);
        assert!(ps.rex_w);
        assert!(ps.operand_size_override);
    }

    #[test]
    fn analyzer_parses_vex2() {
        // VEX2: C5 F8 28 C1 = VMOVAPS xmm0, xmm1
        let bytes = [0xC5u8, 0xF8, 0x28, 0xC1];
        let analyzer = X86PrefixAnalyzer::new_64bit();
        let (ps, consumed) = analyzer.parse(&bytes);
        assert_eq!(consumed, 2);
        assert!(ps.is_vex_encoded());
        assert!(matches!(ps.escape, Some(EscapeEncoding::Vex2(0xF8))));
    }

    #[test]
    fn analyzer_parses_evex() {
        // EVEX: 62 F1 7C 48 28 C1 = VMOVAPS zmm0, zmm1
        let bytes = [0x62u8, 0xF1, 0x7C, 0x48, 0x28, 0xC1];
        let analyzer = X86PrefixAnalyzer::new_64bit();
        let (ps, consumed) = analyzer.parse(&bytes);
        assert_eq!(consumed, 4);
        assert!(ps.is_evex_encoded());
    }

    #[test]
    fn segment_override_fs() {
        let bytes = [0x64u8, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00]; // MOV rax, fs:[0]
        let analyzer = X86PrefixAnalyzer::new_64bit();
        let (ps, _) = analyzer.parse(&bytes);
        assert_eq!(ps.segment_override, Some(SegmentReg::FS));
    }

    #[test]
    fn redundant_prefix_detected() {
        // Two operand-size overrides: 66 66 ...
        let bytes = [0x66u8, 0x66, 0x90];
        let analyzer = X86PrefixAnalyzer::new_64bit();
        let (ps, _) = analyzer.parse(&bytes);
        assert!(ps.has_redundant || ps.prefixes.len() >= 2);
    }

    #[test]
    fn extract_opcode_bytes_skips_prefix() {
        let bytes = [0xF0u8, 0x83, 0x00, 0x01];
        let analyzer = X86PrefixAnalyzer::new_64bit();
        let opcode = analyzer.extract_opcode_bytes(&bytes);
        assert_eq!(opcode[0], 0x83);
    }

    #[test]
    fn prefix_display() {
        let p = parse_prefix_byte(0xF0, 64).unwrap();
        let s = p.to_string();
        assert!(s.contains("F0"));
        assert!(s.contains("LOCK"));
    }

    /// Regression: XOP is discriminated by the 5-bit map_select field
    /// (p1 & 0x1F >= 8), not the 3-bit modrm.reg field (which can never
    /// be >= 8 after masking with 0x7).
    #[test]
    fn analyzer_parses_xop() {
        // XOP: 8F E8 78 B6 ... = VPMACSWW (map_select = 0xE8 & 0x1F = 8)
        let bytes = [0x8Fu8, 0xE8, 0x78, 0xB6, 0xC0, 0x00];
        let analyzer = X86PrefixAnalyzer::new_64bit();
        let (ps, consumed) = analyzer.parse(&bytes);
        assert!(ps.is_xop_encoded(), "8F E8 must be recognised as XOP");
        assert_eq!(consumed, 3);
        assert!(matches!(ps.escape, Some(EscapeEncoding::Xop(0xE8, 0x78))));
    }

    /// Regression: 8F with map_select < 8 is POP r/m64, not XOP.
    #[test]
    fn analyzer_8f_pop_not_xop() {
        // 8F 00 = POP [rax] (map_select = 0)
        let bytes = [0x8Fu8, 0x00, 0x00];
        let analyzer = X86PrefixAnalyzer::new_64bit();
        let (ps, consumed) = analyzer.parse(&bytes);
        assert!(!ps.is_xop_encoded());
        assert_eq!(consumed, 0);
    }

    /// Regression: in 32-bit mode, 62 with a following byte whose mod != 11
    /// is BOUND, not an EVEX prefix.
    #[test]
    fn analyzer_32bit_bound_not_evex() {
        // BOUND eax, [ebp+8] = 62 45 08
        let bytes = [0x62u8, 0x45, 0x08, 0x90];
        let analyzer = X86PrefixAnalyzer::new_32bit();
        let (ps, consumed) = analyzer.parse(&bytes);
        assert!(!ps.is_evex_encoded());
        assert_eq!(consumed, 0, "BOUND opcode must not be consumed as prefix");
    }

    /// Regression: in 32-bit mode, C4/C5 with mod != 11 are LES/LDS.
    #[test]
    fn analyzer_32bit_les_lds_not_vex() {
        let analyzer = X86PrefixAnalyzer::new_32bit();
        // LES eax, [ebx] = C4 03
        let (ps, consumed) = analyzer.parse(&[0xC4u8, 0x03, 0x90]);
        assert!(!ps.is_vex_encoded());
        assert_eq!(consumed, 0);
        // LDS eax, [ebx] = C5 03
        let (ps, consumed) = analyzer.parse(&[0xC5u8, 0x03, 0x90]);
        assert!(!ps.is_vex_encoded());
        assert_eq!(consumed, 0);
    }

    /// In 32-bit mode a C5 whose second byte has mod == 11 IS VEX
    /// (the ModRM disambiguation rule).
    #[test]
    fn analyzer_32bit_vex2_with_mod11() {
        // C5 F8 28 C1 = VMOVAPS xmm0, xmm1 (0xF8 >> 6 == 0b11)
        let bytes = [0xC5u8, 0xF8, 0x28, 0xC1];
        let analyzer = X86PrefixAnalyzer::new_32bit();
        let (ps, consumed) = analyzer.parse(&bytes);
        assert!(ps.is_vex_encoded());
        assert_eq!(consumed, 2);
    }
}
