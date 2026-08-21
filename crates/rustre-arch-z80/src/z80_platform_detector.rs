//! `z80_platform_detector` — Detect the Z80 platform from binary patterns.
//!
//! Different Z80 platforms use different interrupt vector layouts, ROM entry
//! points, memory maps, and peripheral I/O conventions.  This module detects:
//!
//! * **ZX Spectrum** — RST 8/16/28/38 patterns, ULA port 0xFE, shadow registers.
//! * **MSX** — BIOS call patterns (CALL 0x0090+), slot mechanism, `ENASLT`.
//! * **CP/M** — `CALL 0x0005` BDOS calls, `ORG 0x0100` entry point.
//! * **Game Boy (SM83)** — differs from true Z80 but shares 80% of opcodes;
//!   detected via GB-specific opcode sequences (STOP, SWAP, LD A,(C)).
//! * **Amstrad CPC** — specific firmware call addresses (0xBB00+).
//! * **TRS-80** — ROM entry points and OS call conventions.
//! * **Unknown** — when no platform can be determined.

use crate::{is_cpm_bdos_call, is_spectrum_rom_call, Instruction};
use rustre_core::address::Address;
use serde::{Deserialize, Serialize};
use std::fmt;

// ─── Z80Platform ─────────────────────────────────────────────────────────────

/// Detected Z80 (or Z80-compatible) platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Z80Platform {
    /// Sinclair ZX Spectrum (16K / 48K / 128K / +2 / +3).
    ZxSpectrum,
    /// MSX / MSX2 home computer standard.
    Msx,
    /// CP/M operating system (any Z80 CP/M machine).
    Cpm,
    /// Nintendo Game Boy (Sharp SM83 — Z80-derivative).
    GameBoy,
    /// Amstrad CPC 464 / 664 / 6128.
    AmstradCpc,
    /// TRS-80 Model I/III/IV.
    Trs80,
    /// Could not determine the platform.
    Unknown,
}

impl Z80Platform {
    /// Returns the human-readable platform name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ZxSpectrum => "ZX Spectrum",
            Self::Msx => "MSX",
            Self::Cpm => "CP/M",
            Self::GameBoy => "Game Boy (SM83)",
            Self::AmstradCpc => "Amstrad CPC",
            Self::Trs80 => "TRS-80",
            Self::Unknown => "Unknown",
        }
    }

    /// Returns the default RAM start address for the platform.
    #[must_use]
    pub const fn ram_start(self) -> u16 {
        match self {
            // Spectrum, CPC and TRS-80 all put user RAM at 0x4000.
            Self::ZxSpectrum | Self::AmstradCpc | Self::Trs80 => 0x4000,
            Self::Msx => 0x8000,
            Self::Cpm => 0x0100,
            Self::GameBoy => 0xC000,
            Self::Unknown => 0x0000,
        }
    }

    /// Returns the standard interrupt vector table address, if applicable.
    #[must_use]
    pub const fn interrupt_vector_address(self) -> Option<u16> {
        match self {
            // All the Z80 machines here use the IM 1 handler at 0x0038.
            Self::ZxSpectrum | Self::Msx | Self::AmstradCpc | Self::Trs80 => Some(0x0038),
            Self::GameBoy => Some(0x0040), // VBlank
            // CP/M is an OS, not a machine: it pins no vector of its own.
            Self::Cpm | Self::Unknown => None,
        }
    }

    /// Returns `true` when the platform supports shadow register sets.
    #[must_use]
    pub const fn has_shadow_registers(self) -> bool {
        // The SM83 (Game Boy) does NOT support EXX or EX AF,AF'
        !matches!(self, Self::GameBoy)
    }
}

impl fmt::Display for Z80Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ─── PlatformEvidence ─────────────────────────────────────────────────────────

/// A single piece of evidence that supports a specific platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformEvidence {
    /// Platform this evidence supports.
    pub platform: Z80Platform,
    /// Address where the evidence was found.
    pub address: u64,
    /// Weight [1, 100] — higher means stronger evidence.
    pub weight: u8,
    /// Human-readable description.
    pub description: String,
}

// ─── Z80PlatformDetector ─────────────────────────────────────────────────────

/// Detects the Z80 platform from disassembled instructions and binary patterns.
#[derive(Debug, Clone, Default)]
pub struct Z80PlatformDetector {
    /// Accumulated evidence for each platform.
    evidence: Vec<PlatformEvidence>,
}

impl Z80PlatformDetector {
    /// Create a new, empty detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a piece of evidence manually.
    pub fn add_evidence(&mut self, evidence: PlatformEvidence) {
        self.evidence.push(evidence);
    }

    /// Analyse a slice of decoded instructions and accumulate evidence.
    pub fn analyse_instructions(&mut self, instrs: &[Instruction]) {
        for instr in instrs {
            self.check_instruction(instr);
        }
    }

    /// Analyse raw binary bytes for byte-level platform signatures.
    pub fn analyse_binary(&mut self, binary: &[u8], base: u64) {
        // CP/M ORG 0x0100 entry and BDOS jump
        if binary.len() >= 3 {
            // Common CP/M start: JP 0x0100 + 3-byte BDOS stub
            if binary[0] == 0xC3 {
                let target = u16::from_le_bytes([binary[1], binary[2]]);
                if target == 0x0100 {
                    self.push(Z80Platform::Cpm, base, 60, "JP 0x0100 at address 0 (CP/M cold entry)".to_string());
                }
            }
        }
        // ZX Spectrum ULA port 0xFE detection
        self.scan_out_fe(binary, base);
        // MSX ENASLT / RDSLT patterns
        self.scan_msx_bios(binary, base);
        // Game Boy-specific opcodes
        self.scan_game_boy(binary, base);
        // Amstrad CPC firmware call range 0xBB00–0xBD00
        self.scan_amstrad_cpc(binary, base);
        // TRS-80 ROM signature
        self.scan_trs80(binary, base);
    }

    /// Detect the most likely platform given all accumulated evidence.
    #[must_use]
    pub fn detect(&self) -> Z80Platform {
        let mut scores: std::collections::HashMap<Z80Platform, u32> =
            std::collections::HashMap::new();
        for ev in &self.evidence {
            *scores.entry(ev.platform).or_default() += u32::from(ev.weight);
        }
        scores
            .into_iter()
            .max_by_key(|(_, score)| *score)
            .map_or(Z80Platform::Unknown, |(platform, _)| platform)
    }

    /// Detect from vectors: given interrupt vector addresses, return the most
    /// likely platform.
    ///
    /// `vectors` is a list of addresses found in the interrupt vector table
    /// (e.g. at 0x0038, 0x0040, 0x0048 for Game Boy).
    #[must_use]
    pub fn detect_from_vectors(&self, vectors: &[u64]) -> Z80Platform {
        if vectors.is_empty() {
            return self.detect();
        }
        let mut clone = self.clone();
        for &vec_addr in vectors {
            // Game Boy vectors cluster at 0x0040, 0x0048, 0x0050, 0x0058, 0x0060
            if (0x0040..=0x0060).contains(&vec_addr) && (vec_addr % 8 == 0) {
                clone.push(Z80Platform::GameBoy, vec_addr, 70, "Game Boy interrupt vector".to_string());
            }
            // Spectrum IM 2 vectors
            if vec_addr == 0x0038 {
                clone.push(Z80Platform::ZxSpectrum, vec_addr, 50, "IM 1 vector at 0x0038".to_string());
                clone.push(Z80Platform::Msx, vec_addr, 50, "MSX IM 1 vector at 0x0038".to_string());
                clone.push(Z80Platform::AmstradCpc, vec_addr, 40, "CPC IM 1 vector at 0x0038".to_string());
            }
            // CP/M — no meaningful fixed vector
            if vec_addr == 0x0005 {
                clone.push(Z80Platform::Cpm, vec_addr, 80, "BDOS entry at 0x0005".to_string());
            }
        }
        clone.detect()
    }

    /// Detect from a list of typed [`Address`] vectors.
    ///
    /// Convenience wrapper around [`Self::detect_from_vectors`] for callers
    /// working with the `rustre-core` typed address representation.
    #[must_use]
    pub fn detect_from_address_vectors(&self, vectors: &[Address]) -> Z80Platform {
        let raw: Vec<u64> = vectors.iter().map(|a| a.as_u64()).collect();
        self.detect_from_vectors(&raw)
    }

    /// Return all accumulated evidence.
    #[must_use]
    pub fn evidence(&self) -> &[PlatformEvidence] {
        &self.evidence
    }

    /// Return evidence filtered by platform.
    #[must_use]
    pub fn evidence_for(&self, platform: Z80Platform) -> Vec<&PlatformEvidence> {
        self.evidence.iter().filter(|e| e.platform == platform).collect()
    }

    /// Compute a normalised confidence [0.0, 1.0] for the detected platform.
    #[must_use]
    pub fn confidence(&self) -> f64 {
        let mut scores: std::collections::HashMap<Z80Platform, u32> =
            std::collections::HashMap::new();
        for ev in &self.evidence {
            *scores.entry(ev.platform).or_default() += u32::from(ev.weight);
        }
        let total: u32 = scores.values().sum();
        if total == 0 {
            return 0.0;
        }
        let best = scores.values().copied().max().unwrap_or(0);
        f64::from(best) / f64::from(total)
    }

    // ── private helpers ───────────────────────────────────────────────────────

    fn push(&mut self, platform: Z80Platform, address: u64, weight: u8, description: String) {
        self.evidence.push(PlatformEvidence { platform, address, weight, description });
    }

    fn check_instruction(&mut self, instr: &Instruction) {
        let addr = instr.address.as_u64();

        if is_spectrum_rom_call(instr) {
            self.push(Z80Platform::ZxSpectrum, addr, 70, format!("Spectrum ROM call: {} {}", instr.mnemonic, instr.operands));
        }

        if is_cpm_bdos_call(instr) {
            self.push(Z80Platform::Cpm, addr, 80, "CP/M BDOS CALL 0x0005".to_string());
        }

        // MSX BIOS calls (CALL 0x0090..0x01C0 range, step 3)
        if instr.mnemonic == "CALL"
            && let Some(target) = Self::parse_call_target(&instr.operands) {
                if (0x0090..=0x01C0).contains(&target) && target % 3 == 0 {
                    self.push(Z80Platform::Msx, addr, 55, format!("MSX BIOS call at ${target:04X}"));
                }
                // Amstrad CPC firmware range 0xBB00..0xBD00
                if (0xBB00..=0xBD00).contains(&target) {
                    self.push(Z80Platform::AmstradCpc, addr, 75, format!("Amstrad CPC firmware call at ${target:04X}"));
                }
                // TRS-80 LDOS/DOS+ calls
                if (0x4000..=0x4200).contains(&target) {
                    self.push(Z80Platform::Trs80, addr, 40, format!("Possible TRS-80 OS call at ${target:04X}"));
                }
            }

        // EXX and EX AF,AF' imply we're NOT on Game Boy
        if instr.mnemonic == "EXX" || (instr.mnemonic == "EX" && instr.operands.contains("AF'")) {
            // Negative evidence for Game Boy
            for plat in [Z80Platform::ZxSpectrum, Z80Platform::Msx, Z80Platform::Cpm] {
                self.push(plat, addr, 20, format!("{} — excludes Game Boy", instr.mnemonic));
            }
        }
    }

    fn parse_call_target(operands: &str) -> Option<u64> {
        let s = operands.trim_start_matches('$');
        let hex: String = s.chars().take_while(char::is_ascii_hexdigit).collect();
        if hex.is_empty() {
            return None;
        }
        u64::from_str_radix(&hex, 16).ok()
    }

    fn scan_out_fe(&mut self, binary: &[u8], base: u64) {
        // OUT (0xFE), A — ULA border control on ZX Spectrum
        // Opcode: D3 FE
        for (i, w) in binary.windows(2).enumerate() {
            if w == [0xD3, 0xFE] {
                self.push(Z80Platform::ZxSpectrum, base + i as u64, 75, "OUT (0xFE),A — Spectrum ULA port".to_string());
            }
        }
    }

    fn scan_msx_bios(&mut self, binary: &[u8], base: u64) {
        // MSX ENASLT = CALL 0x0024, RDSLT = CALL 0x000C
        let msxcalls: &[(u16, &str)] = &[
            (0x000C, "RDSLT"),
            (0x0014, "WRSLT"),
            (0x001C, "CALSLT"),
            (0x0024, "ENASLT"),
            (0x002C, "CALLF"),
        ];
        for (i, w) in binary.windows(3).enumerate() {
            if w[0] == 0xCD {
                let target = u16::from_le_bytes([w[1], w[2]]);
                for (addr, name) in msxcalls {
                    if target == *addr {
                        self.push(Z80Platform::Msx, base + i as u64, 85, format!("MSX BIOS {name} at CALL ${addr:04X}"));
                    }
                }
            }
        }
    }

    fn scan_game_boy(&mut self, binary: &[u8], base: u64) {
        // STOP instruction: 0x10 0x00
        for (i, w) in binary.windows(2).enumerate() {
            if w == [0x10, 0x00] {
                self.push(Z80Platform::GameBoy, base + i as u64, 80, "STOP instruction (0x10 0x00) — Game Boy specific".to_string());
            }
        }
        // SWAP r: CB 30..37 is SLL on Z80 but SWAP on SM83
        // Without context we can't distinguish; weight low
        for (i, w) in binary.windows(2).enumerate() {
            if w[0] == 0xCB && (0x30..=0x37).contains(&w[1]) {
                self.push(Z80Platform::GameBoy, base + i as u64, 30, "CB 3x — SWAP on Game Boy / SLL on Z80".to_string());
            }
        }
        // LD A,(0xFF00+C) = 0xF2 — Game Boy only
        for (i, &b) in binary.iter().enumerate() {
            if b == 0xF2 {
                self.push(Z80Platform::GameBoy, base + i as u64, 90, "LD A,(C) opcode 0xF2 — Game Boy only".to_string());
            }
        }
    }

    fn scan_amstrad_cpc(&mut self, binary: &[u8], base: u64) {
        // CPC firmware CALL range 0xBB00..0xBCFF (step 3)
        for (i, w) in binary.windows(3).enumerate() {
            if w[0] == 0xCD {
                let target = u16::from_le_bytes([w[1], w[2]]);
                if (0xBB00..=0xBCFF).contains(&target) {
                    self.push(Z80Platform::AmstradCpc, base + i as u64, 80, format!("Amstrad CPC firmware CALL ${target:04X}"));
                }
            }
        }
    }

    fn scan_trs80(&mut self, binary: &[u8], base: u64) {
        // TRS-80 Model I ROM signature at 0x0000: 0xF3 0xDB 0xFF (DI; IN A,(0xFF))
        if binary.starts_with(&[0xF3, 0xDB, 0xFF]) {
            self.push(Z80Platform::Trs80, base, 70, "TRS-80 ROM signature (DI; IN A,(0xFF))".to_string());
        }
        // LDOS CALL at 0x4210
        for (i, w) in binary.windows(3).enumerate() {
            if w[0] == 0xCD {
                let target = u16::from_le_bytes([w[1], w[2]]);
                if target == 0x4210 {
                    self.push(Z80Platform::Trs80, base + i as u64, 65, "CALL 0x4210 — LDOS entry point".to_string());
                }
            }
        }
    }
}

// ─── Free functions ───────────────────────────────────────────────────────────

/// Detect the Z80 platform from a binary blob and optional instruction list.
///
/// Convenience wrapper that creates a [`Z80PlatformDetector`], analyses both
/// the raw binary and the instructions, and returns the result.
#[must_use]
pub fn detect_platform(binary: &[u8], instrs: &[Instruction]) -> Z80Platform {
    let mut detector = Z80PlatformDetector::new();
    detector.analyse_binary(binary, 0);
    detector.analyse_instructions(instrs);
    detector.detect()
}

/// Detect the platform purely from interrupt vector addresses.
///
/// Useful when the binary is not available but the loaded memory is.
#[must_use]
pub fn detect_from_vectors(vectors: &[u64]) -> Z80Platform {
    Z80PlatformDetector::new().detect_from_vectors(vectors)
}

/// Returns a list of well-known interrupt vectors for the given platform.
#[must_use]
pub fn platform_interrupt_vectors(platform: Z80Platform) -> Vec<u16> {
    match platform {
        Z80Platform::GameBoy => vec![0x0040, 0x0048, 0x0050, 0x0058, 0x0060],
        // IM 1 machines: the single handler at 0x0038.
        Z80Platform::ZxSpectrum | Z80Platform::Msx | Z80Platform::AmstradCpc
        | Z80Platform::Trs80 => vec![0x0038],
        Z80Platform::Cpm | Z80Platform::Unknown => vec![],
    }
}

/// Returns a list of well-known RST (restart) entry points for the platform.
#[must_use]
pub fn platform_rst_targets(platform: Z80Platform) -> Vec<u16> {
    match platform {
        // These three reserve RST 0 for the reset entry, so it is not a target.
        Z80Platform::ZxSpectrum | Z80Platform::Msx | Z80Platform::AmstradCpc => {
            vec![0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x0030, 0x0038]
        }
        _ => vec![0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x0030, 0x0038],
    }
}

/// Map an address to the closest known named RST vector for the platform.
#[must_use]
pub fn nearest_rst(platform: Z80Platform, addr: u16) -> Option<u16> {
    platform_rst_targets(platform)
        .into_iter()
        .min_by_key(|&rst| addr.abs_diff(rst))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_name_spectrum() {
        assert_eq!(Z80Platform::ZxSpectrum.name(), "ZX Spectrum");
    }

    #[test]
    fn test_platform_name_cpm() {
        assert_eq!(Z80Platform::Cpm.name(), "CP/M");
    }

    #[test]
    fn test_platform_name_game_boy() {
        assert_eq!(Z80Platform::GameBoy.name(), "Game Boy (SM83)");
    }

    #[test]
    fn test_platform_display() {
        assert_eq!(format!("{}", Z80Platform::Msx), "MSX");
    }

    #[test]
    fn test_ram_start_spectrum() {
        assert_eq!(Z80Platform::ZxSpectrum.ram_start(), 0x4000);
    }

    #[test]
    fn test_ram_start_cpm() {
        assert_eq!(Z80Platform::Cpm.ram_start(), 0x0100);
    }

    #[test]
    fn test_interrupt_vector_spectrum() {
        assert_eq!(Z80Platform::ZxSpectrum.interrupt_vector_address(), Some(0x0038));
    }

    #[test]
    fn test_interrupt_vector_cpm_none() {
        assert!(Z80Platform::Cpm.interrupt_vector_address().is_none());
    }

    #[test]
    fn test_has_shadow_registers_true() {
        assert!(Z80Platform::ZxSpectrum.has_shadow_registers());
    }

    #[test]
    fn test_has_shadow_registers_game_boy_false() {
        assert!(!Z80Platform::GameBoy.has_shadow_registers());
    }

    #[test]
    fn test_detect_cpm_from_binary() {
        // JP 0x0100 at address 0 = CP/M cold entry
        let binary = [0xC3, 0x00, 0x01];
        let platform = detect_platform(&binary, &[]);
        assert_eq!(platform, Z80Platform::Cpm);
    }

    #[test]
    fn test_detect_spectrum_ula_out_fe() {
        let binary = [0x00, 0xD3, 0xFE, 0x00]; // NOP; OUT (0xFE),A; NOP
        let platform = detect_platform(&binary, &[]);
        assert_eq!(platform, Z80Platform::ZxSpectrum);
    }

    #[test]
    fn test_detect_game_boy_stop() {
        let binary = [0x10, 0x00]; // STOP
        let platform = detect_platform(&binary, &[]);
        assert_eq!(platform, Z80Platform::GameBoy);
    }

    #[test]
    fn test_detect_game_boy_ld_a_c() {
        let binary = [0xF2]; // LD A,(C) — GB only
        let platform = detect_platform(&binary, &[]);
        assert_eq!(platform, Z80Platform::GameBoy);
    }

    #[test]
    fn test_detect_from_vectors_game_boy() {
        let vectors = [0x0040u64, 0x0048, 0x0050];
        let platform = detect_from_vectors(&vectors);
        assert_eq!(platform, Z80Platform::GameBoy);
    }

    #[test]
    fn test_detect_from_vectors_cpm() {
        let vectors = [0x0005u64];
        let platform = detect_from_vectors(&vectors);
        assert_eq!(platform, Z80Platform::Cpm);
    }

    #[test]
    fn test_detect_unknown_empty() {
        let detector = Z80PlatformDetector::new();
        assert_eq!(detector.detect(), Z80Platform::Unknown);
    }

    #[test]
    fn test_confidence_no_evidence() {
        let detector = Z80PlatformDetector::new();
        assert!(detector.confidence().abs() < f64::EPSILON);
    }

    #[test]
    fn test_confidence_with_evidence() {
        let mut detector = Z80PlatformDetector::new();
        detector.analyse_binary(&[0xD3, 0xFE, 0xD3, 0xFE], 0); // 2x OUT (0xFE),A
        assert!(detector.confidence() > 0.0);
        assert!(detector.confidence() <= 1.0);
    }

    #[test]
    fn test_evidence_for_platform() {
        let mut detector = Z80PlatformDetector::new();
        detector.add_evidence(PlatformEvidence {
            platform: Z80Platform::Msx,
            address: 0x1000,
            weight: 60,
            description: "test".to_string(),
        });
        let evs = detector.evidence_for(Z80Platform::Msx);
        assert_eq!(evs.len(), 1);
        let evs_other = detector.evidence_for(Z80Platform::Cpm);
        assert!(evs_other.is_empty());
    }

    #[test]
    fn test_platform_rst_targets_spectrum() {
        let rsts = platform_rst_targets(Z80Platform::ZxSpectrum);
        assert!(rsts.contains(&0x0028));
        assert!(rsts.contains(&0x0038));
    }

    #[test]
    fn test_platform_interrupt_vectors_game_boy() {
        let vecs = platform_interrupt_vectors(Z80Platform::GameBoy);
        assert_eq!(vecs.len(), 5);
        assert!(vecs.contains(&0x0040));
    }

    #[test]
    fn test_nearest_rst_spectrum() {
        let rst = nearest_rst(Z80Platform::ZxSpectrum, 0x0039);
        assert_eq!(rst, Some(0x0038));
    }

    #[test]
    fn test_trs80_signature() {
        let binary = [0xF3, 0xDB, 0xFF, 0x00];
        let platform = detect_platform(&binary, &[]);
        assert_eq!(platform, Z80Platform::Trs80);
    }

    #[test]
    fn test_amstrad_cpc_firmware_call() {
        // CALL 0xBB06 — AMSTRAD CPC TXT OUTPUT
        let binary = [0xCD, 0x06, 0xBB];
        let platform = detect_platform(&binary, &[]);
        assert_eq!(platform, Z80Platform::AmstradCpc);
    }

    #[test]
    fn test_detect_from_vectors_empty_returns_unknown() {
        let platform = detect_from_vectors(&[]);
        assert_eq!(platform, Z80Platform::Unknown);
    }
}
