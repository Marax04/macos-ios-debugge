//! Platform identification via 6502 hardware vectors.
//!
//! The MOS 6502 reads three 16-bit little-endian vectors from the top of
//! memory at power-on and interrupt time:
//!
//! | Vector  | Address       | Purpose                              |
//! |---------|---------------|--------------------------------------|
//! | NMI     | `$FFFA/$FFFB` | Non-maskable interrupt handler       |
//! | RESET   | `$FFFC/$FFFD` | Cold-start / warm-start entry point  |
//! | IRQ/BRK | `$FFFE/$FFFF` | Maskable IRQ and BRK instruction     |
//!
//! Different 6502-based platforms (NES, C64, Atari 2600, Apple II, etc.) place
//! recognisable values in these vectors, allowing a ROM analyzer to guess
//! the target platform without needing file-format headers.

use std::fmt;

// ── VectorEntry ───────────────────────────────────────────────────────────────

/// A single 6502 hardware vector (address pair + resolved target).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct VectorEntry {
    /// Name of the vector (`"RESET"`, `"NMI"`, `"IRQ"`).
    pub name: &'static str,
    /// The address in memory where this vector is stored.
    pub vector_addr: u16,
    /// The resolved target address (little-endian value read from `vector_addr`).
    pub target: u16,
}

impl<'de> serde::Deserialize<'de> for VectorEntry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        struct VectorEntryVisitor;
        impl<'de> Visitor<'de> for VectorEntryVisitor {
            type Value = VectorEntry;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("struct VectorEntry")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<VectorEntry, A::Error> {
                let mut name: Option<String> = None;
                let mut vector_addr: Option<u16> = None;
                let mut target: Option<u16> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "name" => name = Some(map.next_value()?),
                        "vector_addr" => vector_addr = Some(map.next_value()?),
                        "target" => target = Some(map.next_value()?),
                        _ => { let _ = map.next_value::<serde::de::IgnoredAny>()?; }
                    }
                }
                // Map the owned name String to a known static str, falling back to "?"
                let name_str: &'static str = match name.as_deref() {
                    Some("NMI")   => "NMI",
                    Some("RESET") => "RESET",
                    Some("IRQ")   => "IRQ",
                    _             => "?",
                };
                Ok(VectorEntry {
                    name: name_str,
                    vector_addr: vector_addr.ok_or_else(|| de::Error::missing_field("vector_addr"))?,
                    target: target.ok_or_else(|| de::Error::missing_field("target"))?,
                })
            }
        }
        deserializer.deserialize_map(VectorEntryVisitor)
    }
}

impl VectorEntry {
    /// Return `true` if the target address falls in the ROM region (`$8000`–`$FFFF`).
    #[must_use]
    pub const fn target_in_rom(self) -> bool {
        self.target >= 0x8000
    }

    /// Return `true` if the target address is zero (unset/unused vector).
    #[must_use]
    pub const fn is_unset(self) -> bool {
        self.target == 0x0000
    }

    /// Return `true` if the target address is the all-ones pattern (`$FFFF`),
    /// common for unused vectors in some ROM layouts.
    #[must_use]
    pub const fn is_blank(self) -> bool {
        self.target == 0xFFFF
    }
}

impl fmt::Display for VectorEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<5} @ ${:04X} → ${:04X}",
            self.name, self.vector_addr, self.target
        )
    }
}

// ── PlatformKind ──────────────────────────────────────────────────────────────

/// Known 6502-based platforms that can be detected from vector/address patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PlatformKind {
    /// Nintendo Entertainment System / Famicom.
    Nes,
    /// Commodore 64.
    C64,
    /// Atari 2600 / VCS.
    Atari2600,
    /// Apple II / II+ / IIe.
    AppleII,
    /// Atari 8-bit (400/800/XL/XE series).
    Atari8Bit,
    /// BBC Micro (Acorn).
    BbcMicro,
    /// Generic 6502 ROM (platform not identified).
    Generic6502,
    /// WDC 65816-based system (16-bit extended mode).
    W65816,
    /// Unknown platform.
    Unknown,
}

impl PlatformKind {
    /// Return a human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Nes => "NES/Famicom",
            Self::C64 => "Commodore 64",
            Self::Atari2600 => "Atari 2600/VCS",
            Self::AppleII => "Apple II",
            Self::Atari8Bit => "Atari 8-bit",
            Self::BbcMicro => "BBC Micro",
            Self::Generic6502 => "Generic 6502",
            Self::W65816 => "WDC 65816",
            Self::Unknown => "Unknown",
        }
    }

    /// Return a confidence level (0–100) for heuristic detections.
    #[must_use]
    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

impl fmt::Display for PlatformKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ── Mos6502PlatformVectors ────────────────────────────────────────────────────

/// The three 6502 hardware vectors read from a ROM image.
///
/// Constructed by [`Mos6502PlatformVectors::from_rom`] or
/// [`Mos6502PlatformVectors::from_bytes`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Mos6502PlatformVectors {
    /// NMI vector (`$FFFA/$FFFB`).
    pub nmi: VectorEntry,
    /// RESET vector (`$FFFC/$FFFD`).
    pub reset: VectorEntry,
    /// IRQ/BRK vector (`$FFFE/$FFFF`).
    pub irq: VectorEntry,
}

impl Mos6502PlatformVectors {
    /// Read vectors from a complete 64 KiB memory image.
    ///
    /// The image must be exactly 65536 bytes (or at least 65536 bytes long).
    ///
    /// # Errors
    /// Returns an error string if `mem` is shorter than 65536 bytes.
    pub fn from_full_memory(mem: &[u8]) -> Result<Self, String> {
        if mem.len() < 65536 {
            return Err(format!(
                "memory image is {} bytes, need 65536",
                mem.len()
            ));
        }
        Ok(Self::read_vectors(mem))
    }

    /// Read vectors from a ROM image mapped at `$8000` (i.e. a 32 KiB PRG ROM).
    ///
    /// The last 6 bytes of the slice are interpreted as the NMI/RESET/IRQ vectors.
    ///
    /// # Errors
    /// Returns an error string if `rom` is shorter than 6 bytes.
    pub fn from_rom(rom: &[u8]) -> Result<Self, String> {
        if rom.len() < 6 {
            return Err(format!("ROM is {} bytes, need at least 6", rom.len()));
        }
        // Vectors are the last 6 bytes of the ROM.
        let off = rom.len() - 6;
        let nmi_lo = rom[off];
        let nmi_hi = rom[off + 1];
        let rst_lo = rom[off + 2];
        let rst_hi = rom[off + 3];
        let irq_lo = rom[off + 4];
        let irq_hi = rom[off + 5];
        Ok(Self {
            nmi: VectorEntry {
                name: "NMI",
                vector_addr: 0xFFFA,
                target: u16::from_le_bytes([nmi_lo, nmi_hi]),
            },
            reset: VectorEntry {
                name: "RESET",
                vector_addr: 0xFFFC,
                target: u16::from_le_bytes([rst_lo, rst_hi]),
            },
            irq: VectorEntry {
                name: "IRQ",
                vector_addr: 0xFFFE,
                target: u16::from_le_bytes([irq_lo, irq_hi]),
            },
        })
    }

    /// Construct directly from known target addresses.
    #[must_use]
    pub const fn from_targets(nmi: u16, reset: u16, irq: u16) -> Self {
        Self {
            nmi: VectorEntry { name: "NMI", vector_addr: 0xFFFA, target: nmi },
            reset: VectorEntry { name: "RESET", vector_addr: 0xFFFC, target: reset },
            irq: VectorEntry { name: "IRQ", vector_addr: 0xFFFE, target: irq },
        }
    }

    /// Parse from a 6-byte raw slice `[nmi_lo, nmi_hi, rst_lo, rst_hi, irq_lo, irq_hi]`.
    ///
    /// # Errors
    /// Returns an error string if `bytes` has fewer than 6 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 6 {
            return Err(format!("need 6 bytes for vectors, got {}", bytes.len()));
        }
        Ok(Self {
            nmi: VectorEntry {
                name: "NMI",
                vector_addr: 0xFFFA,
                target: u16::from_le_bytes([bytes[0], bytes[1]]),
            },
            reset: VectorEntry {
                name: "RESET",
                vector_addr: 0xFFFC,
                target: u16::from_le_bytes([bytes[2], bytes[3]]),
            },
            irq: VectorEntry {
                name: "IRQ",
                vector_addr: 0xFFFE,
                target: u16::from_le_bytes([bytes[4], bytes[5]]),
            },
        })
    }

    /// Return all three vectors as an array `[nmi, reset, irq]`.
    #[must_use]
    pub const fn as_array(&self) -> [VectorEntry; 3] {
        [self.nmi, self.reset, self.irq]
    }

    /// Return `true` if all three vectors point into ROM (`$8000`–`$FFFF`).
    #[must_use]
    pub fn all_in_rom(&self) -> bool {
        self.nmi.target_in_rom() && self.reset.target_in_rom() && self.irq.target_in_rom()
    }

    /// Return `true` if any vector is unset (target `$0000`).
    #[must_use]
    pub fn has_unset_vector(&self) -> bool {
        self.nmi.is_unset() || self.reset.is_unset() || self.irq.is_unset()
    }

    /// Identify the likely platform from the vector values and RESET address.
    ///
    /// Heuristics are ordered from most specific to most generic.
    #[must_use]
    pub fn platform(&self) -> PlatformKind {
        platform_from_vectors(self)
    }

    fn read_vectors(mem: &[u8]) -> Self {
        let nmi = u16::from_le_bytes([mem[0xFFFA], mem[0xFFFB]]);
        let reset = u16::from_le_bytes([mem[0xFFFC], mem[0xFFFD]]);
        let irq = u16::from_le_bytes([mem[0xFFFE], mem[0xFFFF]]);
        Self {
            nmi: VectorEntry { name: "NMI", vector_addr: 0xFFFA, target: nmi },
            reset: VectorEntry { name: "RESET", vector_addr: 0xFFFC, target: reset },
            irq: VectorEntry { name: "IRQ", vector_addr: 0xFFFE, target: irq },
        }
    }
}

impl fmt::Display for Mos6502PlatformVectors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.nmi)?;
        writeln!(f, "{}", self.reset)?;
        write!(f, "{}", self.irq)
    }
}

// ── platform_from_vectors ─────────────────────────────────────────────────────

/// Identify the platform from a set of 6502 hardware vectors.
///
/// The heuristics used here are documented inline.
#[must_use]
pub fn platform_from_vectors(v: &Mos6502PlatformVectors) -> PlatformKind {
    let reset = v.reset.target;
    let nmi = v.nmi.target;
    let irq = v.irq.target;

    // ── Atari 2600 (check before NES: 2600 ROM lives in same address space) ─
    // The 2600 maps ROM at $F000–$FFFF (4 KiB) or $D000–$FFFF.  RESET is
    // usually at $F000, $F800, or similar.  IRQ is typically $0000 (unused)
    // since the 2600 TIA/RIOT doesn't generate IRQs.
    if reset >= 0xF000 && irq == 0x0000 {
        return PlatformKind::Atari2600;
    }
    if reset >= 0xD000 && reset < 0xF800 && irq == 0xFFFF {
        return PlatformKind::Atari2600;
    }

    // ── NES early-out (mapper-0 leaves IRQ = $FFFF) ─────────────────────────
    if irq == 0xFFFF && reset >= 0xC000 && nmi >= 0xC000 {
        return PlatformKind::Nes;
    }

    // ── Commodore 64 (check before NES: KERNAL vectors are in $FC00–$FFFF) ─
    // C64 RESET vector is typically $FCE2 (KERNAL ROM).  NMI is $FE43 or
    // $FE56.  IRQ points to $FF48 (KERNAL IRQ handler).
    if reset == 0xFCE2 || irq == 0xFF48 {
        return PlatformKind::C64;
    }
    // More general C64 heuristic: all vectors in $FC00–$FFFF range.
    if reset >= 0xFC00 && nmi >= 0xFC00 && irq >= 0xFC00 {
        return PlatformKind::C64;
    }

    // ── Apple II (check before NES: Monitor ROM is in $F800–$FFFF) ──────────
    // Apple II RESET is at $FA62 (Monitor) or $C600 (slot-ROM boot).
    // IRQ usually goes to $FA40 or similar Monitor addresses.
    if reset == 0xFA62 || (reset >= 0xC600 && reset < 0xC800) {
        return PlatformKind::AppleII;
    }
    if reset >= 0xF800 && nmi >= 0xF800 && irq >= 0xF000 && irq < 0xF800 {
        return PlatformKind::AppleII;
    }

    // ── NES ──────────────────────────────────────────────────────────────────
    // NES ROMs start at $8000 or $C000.  The NMI vector always points into the
    // ROM region, and the IRQ vector often points to the same address as RESET
    // or is unused ($FFFF) on mapper-0 ROMs.
    if (reset >= 0xC000) && (nmi >= 0xC000) && (irq == 0xFFFF || irq >= 0xC000) {
        return PlatformKind::Nes;
    }

    // ── Atari 8-bit ──────────────────────────────────────────────────────────
    // Atari 8-bit OS ROM is at $C000–$FFFF.  RESET is usually $C2F0 or similar.
    if reset >= 0xC000 && reset < 0xE000 && nmi >= 0xC000 {
        return PlatformKind::Atari8Bit;
    }

    // ── BBC Micro ────────────────────────────────────────────────────────────
    // BBC Micro MOS ROM is at $C000–$FFFF; RESET is typically $D9CD.
    if reset >= 0xD000 && reset < 0xE000 {
        return PlatformKind::BbcMicro;
    }

    // ── Generic 6502 ROM ─────────────────────────────────────────────────────
    // At least RESET points into ROM.
    if reset >= 0x8000 {
        return PlatformKind::Generic6502;
    }

    PlatformKind::Unknown
}

// ── VectorTable ───────────────────────────────────────────────────────────────

/// Extended vector information including platform identification and
/// confidence scoring.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VectorTable {
    /// The raw vectors.
    pub vectors: Mos6502PlatformVectors,
    /// Detected platform.
    pub platform: PlatformKind,
    /// Heuristic confidence score (0–100).
    pub confidence: u8,
    /// Human-readable rationale for the platform decision.
    pub rationale: String,
}

impl VectorTable {
    /// Analyse a set of vectors and produce a fully annotated table.
    #[must_use]
    pub fn analyze(vectors: Mos6502PlatformVectors) -> Self {
        let platform = platform_from_vectors(&vectors);
        let (confidence, rationale) = score_platform(platform, &vectors);
        Self {
            vectors,
            platform,
            confidence,
            rationale,
        }
    }
}

fn score_platform(platform: PlatformKind, v: &Mos6502PlatformVectors) -> (u8, String) {
    match platform {
        PlatformKind::C64 if v.reset.target == 0xFCE2 => {
            (95, "RESET=$FCE2 is the canonical C64 KERNAL entry point".into())
        }
        PlatformKind::C64 => {
            (70, "All vectors in $FC00–$FFFF, consistent with C64 KERNAL".into())
        }
        PlatformKind::Atari2600 => {
            (80, "RESET in $F000–$FFFF region; IRQ unused (Atari 2600 pattern)".into())
        }
        PlatformKind::Nes => {
            (75, "All vectors in ROM region $8000+, matches NES mapper pattern".into())
        }
        PlatformKind::AppleII if v.reset.target == 0xFA62 => {
            (90, "RESET=$FA62 is the Apple II Monitor entry point".into())
        }
        PlatformKind::AppleII => {
            (65, "RESET in $C600–$C800 slot ROM or Monitor range".into())
        }
        PlatformKind::Atari8Bit => {
            (60, "RESET/NMI in $C000–$DFFF, consistent with Atari 8-bit OS ROM".into())
        }
        PlatformKind::BbcMicro => {
            (55, "RESET in $D000–$DFFF, consistent with BBC Micro MOS ROM".into())
        }
        PlatformKind::Generic6502 => {
            (40, "RESET points into ROM ($8000+) but platform-specific markers absent".into())
        }
        _ => (10, "Vectors do not match any known platform pattern".into()),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rom_tail(nmi: u16, reset: u16, irq: u16) -> [u8; 6] {
        let [n0, n1] = nmi.to_le_bytes();
        let [r0, r1] = reset.to_le_bytes();
        let [i0, i1] = irq.to_le_bytes();
        [n0, n1, r0, r1, i0, i1]
    }

    #[test]
    fn test_vector_entry_in_rom() {
        let v = VectorEntry { name: "RESET", vector_addr: 0xFFFC, target: 0x8000 };
        assert!(v.target_in_rom());
        let v2 = VectorEntry { name: "RESET", vector_addr: 0xFFFC, target: 0x7FFF };
        assert!(!v2.target_in_rom());
    }

    #[test]
    fn test_vector_entry_unset_blank() {
        let unset = VectorEntry { name: "IRQ", vector_addr: 0xFFFE, target: 0x0000 };
        assert!(unset.is_unset());
        let blank = VectorEntry { name: "IRQ", vector_addr: 0xFFFE, target: 0xFFFF };
        assert!(blank.is_blank());
    }

    #[test]
    fn test_from_bytes_basic() {
        let bytes = make_rom_tail(0xC000, 0xC100, 0xC200);
        let pv = Mos6502PlatformVectors::from_bytes(&bytes).unwrap();
        assert_eq!(pv.nmi.target, 0xC000);
        assert_eq!(pv.reset.target, 0xC100);
        assert_eq!(pv.irq.target, 0xC200);
    }

    #[test]
    fn test_from_bytes_too_short() {
        assert!(Mos6502PlatformVectors::from_bytes(&[0; 5]).is_err());
    }

    #[test]
    fn test_from_rom_basic() {
        let mut rom = vec![0u8; 32768];
        let tail = make_rom_tail(0xC000, 0xC100, 0xC200);
        let len = rom.len();
        rom[len - 6..].copy_from_slice(&tail);
        let pv = Mos6502PlatformVectors::from_rom(&rom).unwrap();
        assert_eq!(pv.reset.target, 0xC100);
    }

    #[test]
    fn test_platform_nes() {
        let pv = Mos6502PlatformVectors::from_targets(0xFFF5, 0xFFFC, 0xFFFF);
        assert_eq!(pv.platform(), PlatformKind::Nes);
    }

    #[test]
    fn test_platform_atari2600() {
        let pv = Mos6502PlatformVectors::from_targets(0xFFFA, 0xF000, 0x0000);
        assert_eq!(pv.platform(), PlatformKind::Atari2600);
    }

    #[test]
    fn test_platform_c64_exact() {
        let pv = Mos6502PlatformVectors::from_targets(0xFE43, 0xFCE2, 0xFF48);
        assert_eq!(pv.platform(), PlatformKind::C64);
    }

    #[test]
    fn test_platform_apple2_monitor() {
        let pv = Mos6502PlatformVectors::from_targets(0xFBD9, 0xFA62, 0xFA40);
        assert_eq!(pv.platform(), PlatformKind::AppleII);
    }

    #[test]
    fn test_platform_generic() {
        let pv = Mos6502PlatformVectors::from_targets(0xA000, 0xA000, 0xA000);
        assert_eq!(pv.platform(), PlatformKind::Generic6502);
    }

    #[test]
    fn test_platform_unknown() {
        let pv = Mos6502PlatformVectors::from_targets(0x0200, 0x0200, 0x0200);
        assert_eq!(pv.platform(), PlatformKind::Unknown);
    }

    #[test]
    fn test_all_in_rom() {
        let pv = Mos6502PlatformVectors::from_targets(0x8000, 0x8100, 0x8200);
        assert!(pv.all_in_rom());
        let pv2 = Mos6502PlatformVectors::from_targets(0x7FFF, 0x8100, 0x8200);
        assert!(!pv2.all_in_rom());
    }

    #[test]
    fn test_has_unset_vector() {
        let pv = Mos6502PlatformVectors::from_targets(0x0000, 0x8000, 0x8100);
        assert!(pv.has_unset_vector());
    }

    #[test]
    fn test_as_array_len() {
        let pv = Mos6502PlatformVectors::from_targets(0, 0, 0);
        assert_eq!(pv.as_array().len(), 3);
    }

    #[test]
    fn test_display_vectors() {
        let pv = Mos6502PlatformVectors::from_targets(0xFFF5, 0xFFFC, 0xFFFF);
        let s = pv.to_string();
        assert!(s.contains("RESET"));
        assert!(s.contains("NMI"));
        assert!(s.contains("IRQ"));
    }

    #[test]
    fn test_platform_kind_display() {
        assert_eq!(PlatformKind::Nes.to_string(), "NES/Famicom");
        assert_eq!(PlatformKind::C64.to_string(), "Commodore 64");
        assert!(PlatformKind::Nes.is_known());
        assert!(!PlatformKind::Unknown.is_known());
    }

    #[test]
    fn test_vector_table_confidence_c64() {
        let pv = Mos6502PlatformVectors::from_targets(0xFE43, 0xFCE2, 0xFF48);
        let tbl = VectorTable::analyze(pv);
        assert_eq!(tbl.platform, PlatformKind::C64);
        assert!(tbl.confidence >= 90);
        assert!(!tbl.rationale.is_empty());
    }

    #[test]
    fn test_from_full_memory_too_short() {
        assert!(Mos6502PlatformVectors::from_full_memory(&[0; 100]).is_err());
    }

    #[test]
    fn test_from_full_memory_reads_vectors() {
        let mut mem = vec![0u8; 65536];
        // NMI = $C100, RESET = $C200, IRQ = $C300
        mem[0xFFFA] = 0x00;
        mem[0xFFFB] = 0xC1;
        mem[0xFFFC] = 0x00;
        mem[0xFFFD] = 0xC2;
        mem[0xFFFE] = 0x00;
        mem[0xFFFF] = 0xC3;
        let pv = Mos6502PlatformVectors::from_full_memory(&mem).unwrap();
        assert_eq!(pv.nmi.target, 0xC100);
        assert_eq!(pv.reset.target, 0xC200);
        assert_eq!(pv.irq.target, 0xC300);
    }
}
