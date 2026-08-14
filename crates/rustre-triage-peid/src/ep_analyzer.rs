//! Entry-point analyzer: entropy, opcode diversity, packer stub detection.
//!
//! Provides [`EpAnalyzer`], [`EpCharacteristics`], [`TailJumpDetector`],
//! [`PushPopAnalyzer`], and [`OverlayDetector`].

pub use std::collections::HashMap;
use std::collections::HashSet;

use serde::{Deserialize, Serialize};

// ─── EpCharacteristics ────────────────────────────────────────────────────────

/// Summary of characteristics observed at the entry point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpCharacteristics {
    /// Shannon entropy of the first N bytes at EP (0.0 .. 8.0).
    pub entropy: f64,
    /// Number of distinct byte values in the EP window.
    pub byte_diversity: u16,
    /// Number of distinct first-byte opcodes observed.
    pub opcode_diversity: u8,
    /// True if the bytes match a known packer stub pattern.
    pub known_pattern: bool,
    /// Name of the matched known pattern, if any.
    pub pattern_name: Option<String>,
    /// True when the matched pattern is an ordinary compiler prologue rather
    /// than a packer stub. Read this before treating `known_pattern` as a
    /// packing signal — see [`EpPattern::benign`].
    #[serde(default)]
    pub pattern_is_benign: bool,
    /// True if the EP code appears to be a simple push/pop frame setup.
    pub is_frame_setup: bool,
    /// True if the EP code immediately dereferences an IAT pointer (DLL stub).
    pub is_iat_thunk: bool,
    /// True if the code contains a long jump/call to a far offset.
    pub has_long_jump: bool,
    /// True if suspicious: high entropy + known packer trait.
    pub suspicious: bool,
    /// Estimated code density (0.0 = all data, 1.0 = looks like code).
    pub code_density: f64,
}

impl Default for EpCharacteristics {
    fn default() -> Self {
        Self {
            entropy: 0.0,
            byte_diversity: 0,
            opcode_diversity: 0,
            known_pattern: false,
            pattern_name: None,
            pattern_is_benign: false,
            is_frame_setup: false,
            is_iat_thunk: false,
            has_long_jump: false,
            suspicious: false,
            code_density: 0.0,
        }
    }
}

// ─── Packer stub patterns ─────────────────────────────────────────────────────

/// A known packer/protector EP stub pattern.
#[derive(Debug, Clone)]
pub struct EpPattern {
    pub name: String,
    pub prefix: Vec<Option<u8>>,
    /// True when this prefix describes an ORDINARY compiler entry point rather
    /// than a packer/protector stub. The table below deliberately holds both
    /// kinds, so "we recognised this prefix" must never be read as "this is
    /// packed": a plain MSVC `push ebp; mov ebp, esp` is the most-recognised
    /// prefix there is, and it is the cleanest thing an EP can be.
    pub benign: bool,
}

impl EpPattern {
    fn new(name: &str, prefix: &[Option<u8>]) -> Self {
        Self {
            name: name.to_string(),
            prefix: prefix.to_vec(),
            benign: false,
        }
    }

    /// A packer/protector stub prefix.
    #[must_use]
    pub fn new_packer(name: &str, prefix: &[Option<u8>]) -> Self {
        Self::new(name, prefix)
    }

    /// An ordinary compiler prologue prefix — recognised, but not incriminating.
    #[must_use]
    pub fn new_benign(name: &str, prefix: &[Option<u8>]) -> Self {
        Self {
            benign: true,
            ..Self::new(name, prefix)
        }
    }

    fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.prefix.len() {
            return false;
        }
        for (i, p) in self.prefix.iter().enumerate() {
            if let Some(expected) = p
                && data[i] != *expected {
                    return false;
                }
        }
        true
    }
}

fn default_ep_patterns() -> Vec<EpPattern> {
    macro_rules! pat {
        ($name:expr, [$($b:expr),*]) => {
            EpPattern::new($name, &[$($b),*])
        };
    }
    // Ordinary compiler prologues: recognised, but NOT evidence of packing.
    macro_rules! pat_benign {
        ($name:expr, [$($b:expr),*]) => {
            EpPattern::new_benign($name, &[$($b),*])
        };
    }
    use std::option::Option::{None, Some};
    vec![
        pat!("UPX pushad+call", [Some(0x60), Some(0xE8)]),
        pat!("UPX movsi+8d", [Some(0x60), Some(0xBE)]),
        pat!(
            "ASPack pushad+call+near",
            [
                Some(0x60),
                Some(0xE8),
                Some(0x03),
                Some(0x00),
                Some(0x00),
                Some(0x00)
            ]
        ),
        pat!(
            "MPRESS pushad+call+0",
            [
                Some(0x60),
                Some(0xE8),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x58)
            ]
        ),
        pat!(
            "NsPack pushfd+pushad+call",
            [Some(0x9C), Some(0x60), Some(0xE8)]
        ),
        pat!(
            "FSG be+bf",
            [Some(0xBE), None, None, None, None, Some(0xBF)]
        ),
        pat!(
            "tElock/Themida E8+5D",
            [
                Some(0xE8),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x5D)
            ]
        ),
        pat!(
            "Generic E8 00*4 5D delta",
            [
                Some(0xE8),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x5D)
            ]
        ),
        pat!(".NET entry (FF 25)", [Some(0xFF), Some(0x25)]),
        pat_benign!(
            "x64 MSVC frame (40 53)",
            [Some(0x40), Some(0x53), Some(0x48), Some(0x83), Some(0xEC)]
        ),
        pat_benign!(
            "x64 GCC frame (55 48 89 E5)",
            [Some(0x55), Some(0x48), Some(0x89), Some(0xE5)]
        ),
        pat_benign!(
            "x86 MSVC frame (55 8B EC)",
            [Some(0x55), Some(0x8B), Some(0xEC)]
        ),
        pat_benign!(
            "x86 GCC frame (55 89 E5)",
            [Some(0x55), Some(0x89), Some(0xE5)]
        ),
        pat!("x64 Go stack-split", [Some(0x64), Some(0x48), Some(0x8B)]),
        pat!(
            "PECompact B8 push addr",
            [
                Some(0xB8),
                None,
                None,
                None,
                None,
                Some(0x50),
                Some(0x64),
                Some(0xFF),
                Some(0x35)
            ]
        ),
        pat!(
            "BeRoExePacker jmp EB 03",
            [Some(0xEB), Some(0x03), Some(0xCD), Some(0x20)]
        ),
        pat!(
            "ExeStealth junk EB 01",
            [Some(0xEB), Some(0x01), None, Some(0x60)]
        ),
        pat!(
            "Themida E8+5D+81ED",
            [
                Some(0xE8),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x00),
                Some(0x5D),
                Some(0x81),
                Some(0xED)
            ]
        ),
        pat!(
            "IAT thunk (FF 25 64-bit)",
            [Some(0xFF), Some(0x25), None, None, None, None]
        ),
        pat!("JMP far (E9)", [Some(0xE9)]),
        pat!("CALL far (E8)", [Some(0xE8)]),
        pat!("pushfd/pushad anti-debug", [Some(0x9C), Some(0x60)]),
    ]
}

// ─── EpAnalyzer ───────────────────────────────────────────────────────────────

/// Analyzes the first N bytes at an executable's entry point.
pub struct EpAnalyzer {
    patterns: Vec<EpPattern>,
    /// Number of bytes to analyze from EP.
    pub window: usize,
}

impl EpAnalyzer {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            patterns: default_ep_patterns(),
            window: 64,
        }
    }

    #[must_use] 
    pub const fn with_window(mut self, window: usize) -> Self {
        self.window = window;
        self
    }

    pub fn add_pattern(&mut self, p: EpPattern) {
        self.patterns.push(p);
    }

    /// Analyze the byte slice starting at EP.
    #[must_use] 
    pub fn analyze(&self, ep_bytes: &[u8]) -> EpCharacteristics {
        let window = self.window.min(ep_bytes.len());
        let data = &ep_bytes[..window];

        let mut ch = EpCharacteristics::default();
        if data.is_empty() {
            return ch;
        }

        ch.entropy = shannon_entropy(data);
        ch.byte_diversity = byte_diversity(data);
        ch.opcode_diversity = opcode_diversity(data);
        ch.code_density = code_density(data);
        ch.has_long_jump = has_long_jump(data);
        ch.is_iat_thunk = is_iat_thunk(data);
        ch.is_frame_setup = is_frame_setup(data);

        // Pattern match
        for pat in &self.patterns {
            if pat.matches(data) {
                ch.known_pattern = true;
                ch.pattern_name = Some(pat.name.clone());
                ch.pattern_is_benign = pat.benign;
                break;
            }
        }

        // Heuristic: suspicious if high entropy AND (known packer pattern OR not typical frame setup)
        ch.suspicious = ch.entropy > 6.5 || (ch.known_pattern && !ch.is_frame_setup);

        ch
    }

    /// Analyze and return a short summary string.
    #[must_use] 
    pub fn summarize(&self, ep_bytes: &[u8]) -> String {
        let ch = self.analyze(ep_bytes);
        let mut parts = Vec::new();
        parts.push(format!("entropy={:.2}", ch.entropy));
        parts.push(format!("diversity={}", ch.byte_diversity));
        if ch.known_pattern {
            parts.push(format!(
                "pattern={}",
                ch.pattern_name.as_deref().unwrap_or("?")
            ));
        }
        if ch.suspicious {
            parts.push("SUSPICIOUS".to_string());
        }
        if ch.is_frame_setup {
            parts.push("frame_setup".to_string());
        }
        if ch.is_iat_thunk {
            parts.push("iat_thunk".to_string());
        }
        parts.join(", ")
    }
}

impl Default for EpAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Entropy ──────────────────────────────────────────────────────────────────

/// Compute the Shannon entropy of a byte slice (0.0 .. 8.0).
#[must_use] 
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = f64::from(count) / n;
            h -= p * p.log2();
        }
    }
    h
}

/// Number of distinct byte values in `data`.
#[must_use] 
pub fn byte_diversity(data: &[u8]) -> u16 {
    let mut seen = [false; 256];
    for &b in data {
        seen[b as usize] = true;
    }
    seen.iter().filter(|&&x| x).count() as u16
}

/// Number of distinct first bytes that could be valid x86 opcodes.
#[must_use] 
pub fn opcode_diversity(data: &[u8]) -> u8 {
    let valid_opcodes: HashSet<u8> = [
        0x00, 0x01, 0x03, 0x0F, 0x20, 0x25, 0x29, 0x2B, 0x31, 0x33, 0x39, 0x3B, 0x40, 0x41, 0x48,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E,
        0x5F, 0x60, 0x61, 0x64, 0x65, 0x66, 0x68, 0x69, 0x6A, 0x6B, 0x74, 0x75, 0x76, 0x77, 0x80,
        0x81, 0x83, 0x85, 0x87, 0x89, 0x8B, 0x8D, 0x90, 0x9C, 0x9D, 0xA1, 0xA3, 0xB8, 0xBE, 0xBF,
        0xC3, 0xC7, 0xC9, 0xCC, 0xCD, 0xD0, 0xD1, 0xE8, 0xE9, 0xEB, 0xF3, 0xF4, 0xF7, 0xFF,
    ]
    .iter()
    .copied()
    .collect();

    let seen: HashSet<u8> = data
        .iter()
        .filter(|&&b| valid_opcodes.contains(&b))
        .copied()
        .collect();
    seen.len().min(255) as u8
}

/// Estimate code density (fraction of bytes that look like valid x86 opcodes).
#[must_use] 
pub fn code_density(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let valid: HashSet<u8> = [
        0x00, 0x01, 0x03, 0x0F, 0x25, 0x29, 0x2B, 0x31, 0x33, 0x39, 0x3B, 0x40, 0x41, 0x48, 0x50,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x64, 0x65, 0x66, 0x68, 0x69, 0x6A, 0x6B, 0x74, 0x75, 0x80, 0x81, 0x83, 0x85,
        0x87, 0x89, 0x8B, 0x8D, 0x90, 0x9C, 0x9D, 0xA1, 0xA3, 0xB8, 0xBE, 0xBF, 0xC3, 0xC7, 0xC9,
        0xCC, 0xCD, 0xD0, 0xD1, 0xE8, 0xE9, 0xEB, 0xF3, 0xF4, 0xF7, 0xFF,
    ]
    .iter()
    .copied()
    .collect();

    data.iter().filter(|&&b| valid.contains(&b)).count() as f64 / data.len() as f64
}

/// True if the first bytes look like an IAT thunk (FF 25 or FF 15 indirect call/jmp).
#[must_use] 
pub fn is_iat_thunk(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    data[0] == 0xFF && (data[1] == 0x25 || data[1] == 0x15)
}

/// True if the first bytes look like a standard frame setup (push ebp; mov ebp, esp).
#[must_use] 
pub fn is_frame_setup(data: &[u8]) -> bool {
    if data.len() < 3 {
        return false;
    }
    // x86: 55 8B EC
    if data[0] == 0x55 && data[1] == 0x8B && data[2] == 0xEC {
        return true;
    }
    // x64: 55 48 89 E5
    if data.len() >= 4 && data[0] == 0x55 && data[1] == 0x48 && data[2] == 0x89 && data[3] == 0xE5 {
        return true;
    }
    // x86 GCC/MinGW: 55 89 E5 — `push ebp; mov ebp, esp` without the 8B form.
    // The pattern table already knows this prologue by name ("x86 GCC frame"),
    // so omitting it here made the two disagree: `known_pattern` was true while
    // `is_frame_setup` was false, which is exactly the combination `suspicious`
    // treats as packing evidence. A stock 32-bit MinGW entry point was therefore
    // reported as Packed.
    if data[0] == 0x55 && data[1] == 0x89 && data[2] == 0xE5 {
        return true;
    }
    // x64: 40 53 48 83 EC (MSVC)
    if data.len() >= 5
        && data[0] == 0x40
        && data[1] == 0x53
        && data[2] == 0x48
        && data[3] == 0x83
        && data[4] == 0xEC
    {
        return true;
    }
    false
}

/// True if there's a long forward or backward jump/call in the first 8 bytes.
#[must_use] 
pub fn has_long_jump(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }
    // E9 xx xx xx xx (near jump)
    if data[0] == 0xE9 {
        let offset = i32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        if offset.abs() > 0x1000 {
            return true;
        }
    }
    // E8 xx xx xx xx (near call)
    if data[0] == 0xE8 {
        let offset = i32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        if offset.abs() > 0x100 {
            return true;
        }
    }
    false
}

// ─── TailJumpDetector ─────────────────────────────────────────────────────────

/// Detects "tail jump" patterns: a compressed stub that ends with a long jump back to OEP.
pub struct TailJumpDetector;

/// Result of a tail-jump scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailJump {
    /// Byte offset of the jump instruction in the stub.
    pub offset: usize,
    /// Kind of jump.
    pub kind: TailJumpKind,
    /// Raw target displacement (relative or absolute).
    pub target_displacement: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TailJumpKind {
    NearJmp,
    IndirectJmp,
    PushRet,
}

impl TailJumpDetector {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Scan `data` for candidate tail jumps (last few instructions).
    #[must_use] 
    pub fn find(&self, data: &[u8]) -> Vec<TailJump> {
        let mut results = Vec::new();

        for i in 0..data.len() {
            // E9 xx xx xx xx — near jmp rel32
            if i + 4 < data.len() && data[i] == 0xE9 {
                let disp = i32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
                results.push(TailJump {
                    offset: i,
                    kind: TailJumpKind::NearJmp,
                    target_displacement: i64::from(disp),
                });
            }

            // FF E4 / FF E0 / FF E1 / FF E2 etc — jmp [reg]
            if i + 1 < data.len() && data[i] == 0xFF {
                let modrm = data[i + 1];
                let reg = (modrm >> 3) & 7;
                if modrm >> 6 == 0b11 && reg == 4 {
                    // FF E4 = jmp esp (unusual, possible)
                    results.push(TailJump {
                        offset: i,
                        kind: TailJumpKind::IndirectJmp,
                        target_displacement: 0,
                    });
                }
                if modrm >> 6 == 0b11 && reg == 6 {
                    // FF E6 = jmp esi (typical packer tail)
                    results.push(TailJump {
                        offset: i,
                        kind: TailJumpKind::IndirectJmp,
                        target_displacement: 0,
                    });
                }
            }

            // 68 xx xx xx xx / C3 — push imm + ret (push-ret OEP redirect)
            if i + 5 < data.len() && data[i] == 0x68 && data[i + 5] == 0xC3 {
                let target =
                    u32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
                results.push(TailJump {
                    offset: i,
                    kind: TailJumpKind::PushRet,
                    target_displacement: i64::from(target),
                });
            }
        }

        results
    }
}

impl Default for TailJumpDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─── PushPopAnalyzer ──────────────────────────────────────────────────────────

/// Distinguishes normal push/pop frame setup from packer push-everything stubs.
pub struct PushPopAnalyzer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushPopProfile {
    /// Number of push instructions in the window.
    pub push_count: u8,
    /// Number of pop instructions in the window.
    pub pop_count: u8,
    /// True if the pattern looks like PUSHAD (60) + POPAD (61).
    pub has_pushad_popad: bool,
    /// True if the pattern looks like normal function prologue.
    pub is_normal_prologue: bool,
    /// True if looks like a packer "save all registers" stub.
    pub is_packer_stub: bool,
    /// Byte index within the EP window of the first PUSHAD (0x60), if any.
    /// Useful for locating where a packer's register-save stub begins.
    pub first_pushad_offset: Option<u8>,
}

impl PushPopAnalyzer {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    #[must_use] 
    pub fn analyze(&self, ep_bytes: &[u8]) -> PushPopProfile {
        let window = ep_bytes.len().min(32);
        let data = &ep_bytes[..window];

        let mut push_count: u8 = 0;
        let mut pop_count: u8 = 0;
        let mut has_pushad = false;
        let mut has_popad = false;
        let mut first_pushad_offset: Option<u8> = None;

        for (i, &b) in data.iter().enumerate() {
            match b {
                0x50..=0x57 => push_count = push_count.saturating_add(1),
                0x58..=0x5F => pop_count = pop_count.saturating_add(1),
                0x60 => {
                    if !has_pushad {
                        first_pushad_offset = Some(i as u8);
                    }
                    has_pushad = true;
                }
                0x61 => has_popad = true,
                0x68 | 0x6A => push_count = push_count.saturating_add(1),
                _ => {}
            }
        }

        let is_normal_prologue = is_frame_setup(ep_bytes);
        let is_packer_stub = has_pushad || (push_count >= 6 && pop_count == 0);

        PushPopProfile {
            push_count,
            pop_count,
            has_pushad_popad: has_pushad && has_popad,
            is_normal_prologue,
            is_packer_stub,
            first_pushad_offset,
        }
    }
}

impl Default for PushPopAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── OverlayDetector ─────────────────────────────────────────────────────────

/// Detects data appended after the last section (PE overlay).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayInfo {
    /// True if an overlay was detected.
    pub has_overlay: bool,
    /// Byte offset where the overlay starts.
    pub overlay_offset: Option<usize>,
    /// Overlay size in bytes.
    pub overlay_size: Option<usize>,
    /// Entropy of the overlay data.
    pub overlay_entropy: Option<f64>,
    /// Possible format hint.
    pub format_hint: Option<String>,
}

pub struct OverlayDetector;

impl OverlayDetector {
    #[must_use] 
    pub const fn new() -> Self {
        Self
    }

    /// Detect overlay given the full file data and the declared PE end offset.
    #[must_use] 
    pub fn detect(&self, file_data: &[u8], pe_end_offset: usize) -> OverlayInfo {
        if pe_end_offset >= file_data.len() {
            return OverlayInfo {
                has_overlay: false,
                overlay_offset: None,
                overlay_size: None,
                overlay_entropy: None,
                format_hint: None,
            };
        }

        let overlay = &file_data[pe_end_offset..];
        let entropy = shannon_entropy(overlay);
        let format_hint = detect_overlay_format(overlay);

        OverlayInfo {
            has_overlay: true,
            overlay_offset: Some(pe_end_offset),
            overlay_size: Some(overlay.len()),
            overlay_entropy: Some(entropy),
            format_hint,
        }
    }
}

impl Default for OverlayDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn detect_overlay_format(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }
    match &data[..4] {
        [0x50, 0x4B, 0x03, 0x04] => Some("Zip".into()),
        [0x52, 0x61, 0x72, 0x21] => Some("RAR".into()),
        [0x1F, 0x8B, ..] => Some("gzip".into()),
        [0x37, 0x7A, 0xBC, 0xAF] => Some("7-Zip".into()),
        [0x4D, 0x45, 0x49, 0x30] => Some("PyInstaller".into()),
        [0x4E, 0x45, 0x53, 0x1A] => Some("NSIS".into()),
        [0x7F, 0x45, 0x4C, 0x46] => Some("ELF".into()),
        [0x4D, 0x5A, ..] => Some("PE/MZ".into()),
        _ => None,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_all_same() {
        let data = vec![0xAAu8; 256];
        let e = shannon_entropy(&data);
        assert!(e < 0.01, "all same bytes → entropy ~0, got {e}");
    }

    #[test]
    fn test_entropy_all_different() {
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.9, "all different → entropy ~8, got {e}");
    }

    #[test]
    fn test_entropy_empty() {
        let e = shannon_entropy(&[]);
        assert_eq!(e, 0.0);
    }

    #[test]
    fn test_byte_diversity_all_same() {
        let data = vec![0x55u8; 100];
        assert_eq!(byte_diversity(&data), 1);
    }

    #[test]
    fn test_byte_diversity_all_different() {
        let data: Vec<u8> = (0..=255).collect();
        assert_eq!(byte_diversity(&data), 256);
    }

    #[test]
    fn test_opcode_diversity_basic() {
        let data = vec![0x55u8, 0x8B, 0xEC, 0x53, 0x56];
        let d = opcode_diversity(&data);
        assert!(d >= 4);
    }

    #[test]
    fn test_code_density_frame_prologue() {
        let data = vec![0x55u8, 0x8B, 0xEC, 0x53, 0x56, 0x57];
        let d = code_density(&data);
        assert!(d > 0.5);
    }

    #[test]
    fn test_is_frame_setup_x86() {
        let data = [0x55u8, 0x8B, 0xEC, 0x00];
        assert!(is_frame_setup(&data));
    }

    #[test]
    fn test_is_frame_setup_x64() {
        let data = [0x55u8, 0x48, 0x89, 0xE5];
        assert!(is_frame_setup(&data));
    }

    #[test]
    fn test_is_frame_setup_no() {
        let data = [0x60u8, 0xE8, 0x00, 0x00];
        assert!(!is_frame_setup(&data));
    }

    #[test]
    fn test_is_iat_thunk() {
        let data = [0xFFu8, 0x25, 0x00, 0x00];
        assert!(is_iat_thunk(&data));
    }

    #[test]
    fn test_is_iat_thunk_no() {
        let data = [0x55u8, 0x8B, 0xEC];
        assert!(!is_iat_thunk(&data));
    }

    #[test]
    fn test_has_long_jump_yes() {
        // E9 + large offset
        let disp: i32 = 0x10000;
        let mut data = vec![0xE9u8];
        data.extend_from_slice(&disp.to_le_bytes());
        data.push(0x00);
        assert!(has_long_jump(&data));
    }

    #[test]
    fn test_has_long_jump_no() {
        let data = [0x55u8, 0x8B, 0xEC, 0x00, 0x00, 0x00];
        assert!(!has_long_jump(&data));
    }

    #[test]
    fn test_ep_analyzer_frame_setup() {
        let analyzer = EpAnalyzer::new();
        let data = vec![0x55u8, 0x8B, 0xEC, 0x53, 0x56, 0x57, 0x33, 0xDB];
        let ch = analyzer.analyze(&data);
        assert!(ch.is_frame_setup);
        assert!(!ch.suspicious);
    }

    #[test]
    fn test_ep_analyzer_upx_pattern() {
        let analyzer = EpAnalyzer::new();
        // UPX pushad+call pattern
        let mut data = vec![0x60u8, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        data.extend(vec![0u8; 56]);
        let ch = analyzer.analyze(&data);
        assert!(ch.known_pattern);
        assert!(
            ch.pattern_name
                .as_deref()
                .is_some_and(|s| s.contains("UPX"))
        );
    }

    #[test]
    fn test_ep_analyzer_iat_thunk() {
        let analyzer = EpAnalyzer::new();
        let mut data = vec![0xFFu8, 0x25, 0x00, 0x10, 0x40, 0x00];
        data.extend(vec![0u8; 58]);
        let ch = analyzer.analyze(&data);
        assert!(ch.is_iat_thunk);
    }

    #[test]
    fn test_ep_analyzer_summary() {
        let analyzer = EpAnalyzer::new();
        let data = vec![0x55u8, 0x8B, 0xEC, 0x53, 0x56, 0x57, 0x33, 0xDB, 0x00, 0x00];
        let summary = analyzer.summarize(&data);
        assert!(summary.contains("entropy"));
    }

    #[test]
    fn test_tail_jump_near_jmp() {
        let det = TailJumpDetector::new();
        let disp: i32 = 0x50000;
        let mut data = vec![0x90u8; 8]; // nops
        data.push(0xE9);
        data.extend_from_slice(&disp.to_le_bytes());
        let jumps = det.find(&data);
        assert!(jumps.iter().any(|j| j.kind == TailJumpKind::NearJmp));
    }

    #[test]
    fn test_tail_jump_push_ret() {
        let det = TailJumpDetector::new();
        let mut data = vec![0x90u8; 4];
        data.push(0x68);
        data.extend_from_slice(&0x00401000u32.to_le_bytes());
        data.push(0xC3);
        let jumps = det.find(&data);
        assert!(jumps.iter().any(|j| j.kind == TailJumpKind::PushRet));
    }

    #[test]
    fn test_pushpop_normal_prologue() {
        let analyzer = PushPopAnalyzer::new();
        let data = [0x55u8, 0x8B, 0xEC, 0x53, 0x56, 0x57];
        let p = analyzer.analyze(&data);
        assert!(p.is_normal_prologue);
        assert!(!p.is_packer_stub);
    }

    #[test]
    fn test_pushpop_packer_stub() {
        let analyzer = PushPopAnalyzer::new();
        let data = [0x60u8, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0xC4, 0x04];
        let p = analyzer.analyze(&data);
        assert!(p.is_packer_stub);
    }

    #[test]
    fn test_overlay_detector_no_overlay() {
        let det = OverlayDetector::new();
        let data = vec![0xAAu8; 100];
        let info = det.detect(&data, 100);
        assert!(!info.has_overlay);
    }

    #[test]
    fn test_overlay_detector_zip_overlay() {
        let det = OverlayDetector::new();
        let mut data = vec![0xAAu8; 100];
        data.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04, 0x00]);
        let info = det.detect(&data, 100);
        assert!(info.has_overlay);
        assert_eq!(info.format_hint.as_deref(), Some("Zip"));
    }

    #[test]
    fn test_overlay_detector_entropy() {
        let det = OverlayDetector::new();
        let mut data = vec![0x55u8; 50];
        // High-entropy overlay (random-ish)
        let overlay: Vec<u8> = (0u8..=255).cycle().take(256).collect();
        data.extend_from_slice(&overlay);
        let info = det.detect(&data, 50);
        assert!(info.has_overlay);
        assert!(info.overlay_entropy.unwrap() > 6.0);
    }
}

// ─── EpReport ─────────────────────────────────────────────────────────────────

/// Full entry-point analysis report combining all sub-analyzers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EpReport {
    pub characteristics: EpCharacteristics,
    pub push_pop: PushPopProfile,
    pub tail_jumps: Vec<TailJump>,
    pub overlay: OverlayInfo,
    pub verdict: EpVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EpVerdict {
    /// Looks like a standard compiled binary.
    Clean,
    /// Has characteristics of a packer or protector.
    Packed,
    /// Encrypted or highly obfuscated.
    Encrypted,
    /// DLL/COM entry (IAT thunk).
    Thunk,
    /// Could not determine.
    Unknown,
}

impl std::fmt::Display for EpVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "CLEAN"),
            Self::Packed => write!(f, "PACKED"),
            Self::Encrypted => write!(f, "ENCRYPTED"),
            Self::Thunk => write!(f, "THUNK"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Run a full EP analysis and produce an [`EpReport`].
#[must_use] 
pub fn full_ep_analysis(file_data: &[u8], ep_offset: usize, pe_end: Option<usize>) -> EpReport {
    let ep_bytes = if ep_offset < file_data.len() {
        &file_data[ep_offset..]
    } else {
        &[]
    };

    let analyzer = EpAnalyzer::new();
    let pp_analyzer = PushPopAnalyzer::new();
    let tj_detector = TailJumpDetector::new();
    let ov_detector = OverlayDetector::new();

    let characteristics = analyzer.analyze(ep_bytes);
    let push_pop = pp_analyzer.analyze(ep_bytes);
    let tail_jumps = tj_detector.find(ep_bytes);
    let overlay = pe_end
        .map_or(OverlayInfo {
            has_overlay: false,
            overlay_offset: None,
            overlay_size: None,
            overlay_entropy: None,
            format_hint: None,
        }, |end| ov_detector.detect(file_data, end));

    let verdict = determine_verdict(&characteristics, &push_pop, &tail_jumps, &overlay);

    EpReport {
        characteristics,
        push_pop,
        tail_jumps,
        overlay,
        verdict,
    }
}

fn determine_verdict(
    ch: &EpCharacteristics,
    pp: &PushPopProfile,
    tjs: &[TailJump],
    ov: &OverlayInfo,
) -> EpVerdict {
    if ch.is_iat_thunk {
        return EpVerdict::Thunk;
    }
    if ch.entropy > 7.5 {
        return EpVerdict::Encrypted;
    }
    if ch.known_pattern && pp.is_packer_stub {
        return EpVerdict::Packed;
    }
    if !tjs.is_empty() && pp.is_packer_stub {
        return EpVerdict::Packed;
    }
    // A high-entropy overlay attached to an otherwise normal EP is a classic
    // self-extracting/packer fingerprint (installer SFX, UPX with overlay, etc.).
    if ov.has_overlay && ov.overlay_entropy.unwrap_or(0.0) > 7.0 {
        return EpVerdict::Packed;
    }
    // A recognised prefix is NOT by itself incriminating: the pattern table holds
    // ordinary compiler prologues too, and they are the SAME bytes `is_frame_setup`
    // keys on. Requiring `!known_pattern` here made Clean unreachable for every
    // canonical MSVC/GCC entry point, which then fell through to Unknown — the
    // cleanest possible EP was the one this function refused to call clean.
    if ch.is_frame_setup && (!ch.known_pattern || ch.pattern_is_benign) {
        return EpVerdict::Clean;
    }
    if ch.suspicious {
        return EpVerdict::Packed;
    }
    EpVerdict::Unknown
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_ep_verdict_display() {
        assert_eq!(EpVerdict::Clean.to_string(), "CLEAN");
        assert_eq!(EpVerdict::Packed.to_string(), "PACKED");
        assert_eq!(EpVerdict::Encrypted.to_string(), "ENCRYPTED");
        assert_eq!(EpVerdict::Thunk.to_string(), "THUNK");
    }

    #[test]
    fn test_full_ep_analysis_clean() {
        let data = vec![
            0x55u8, 0x8B, 0xEC, 0x53, 0x56, 0x57, 0x33, 0xDB, 0x89, 0x5D, 0xFC, 0x56, 0xFF, 0x15,
            0x00, 0x10, 0x40, 0x00, 0x5F, 0x5E, 0x5B, 0x5D, 0xC3, 0x00,
        ];
        let report = full_ep_analysis(&data, 0, None);
        assert_eq!(report.verdict, EpVerdict::Clean);
    }

    /// The MSVC prologue must be called Clean *while still being recognised*.
    /// Silencing the pattern table would also turn this verdict green, so assert
    /// both halves: the prefix is matched, and it is matched as benign.
    #[test]
    fn clean_verdict_does_not_require_giving_up_recognition() {
        let data = vec![
            0x55u8, 0x8B, 0xEC, 0x53, 0x56, 0x57, 0x33, 0xDB, 0x89, 0x5D, 0xFC, 0x56, 0xFF, 0x15,
            0x00, 0x10, 0x40, 0x00, 0x5F, 0x5E, 0x5B, 0x5D, 0xC3, 0x00,
        ];
        let report = full_ep_analysis(&data, 0, None);
        assert_eq!(report.verdict, EpVerdict::Clean);
        assert!(
            report.characteristics.known_pattern,
            "the prefix must still be recognised, not ignored"
        );
        assert_eq!(
            report.characteristics.pattern_name.as_deref(),
            Some("x86 MSVC frame (55 8B EC)")
        );
        assert!(report.characteristics.pattern_is_benign);
    }

    /// The counterpart: a real packer stub must NOT be reclassified as Clean by
    /// the benign-pattern relaxation.
    #[test]
    fn packer_stub_is_not_made_clean_by_the_benign_flag() {
        // UPX: pushad; call ... — not a frame setup, and not benign.
        let mut data = vec![0u8; 32];
        data[0] = 0x60;
        data[1] = 0xE8;
        let report = full_ep_analysis(&data, 0, None);
        assert_ne!(report.verdict, EpVerdict::Clean);
        assert!(!report.characteristics.pattern_is_benign);
    }

    /// A stock 32-bit MinGW/GCC entry point (`55 89 E5`) must not be called
    /// Packed. Before `is_frame_setup` learned this prologue, `known_pattern`
    /// was true while `is_frame_setup` was false — the exact pair `suspicious`
    /// reads as packing evidence — so this EP was reported as Packed.
    #[test]
    fn stock_mingw_prologue_is_not_reported_as_packed() {
        let mut data = vec![
            0x55u8, 0x89, 0xE5, 0x83, 0xEC, 0x18, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
        ];
        data.resize(32, 0x90);
        let report = full_ep_analysis(&data, 0, None);
        assert_ne!(
            report.verdict,
            EpVerdict::Packed,
            "a plain MinGW prologue must never be called Packed"
        );
        assert_eq!(report.verdict, EpVerdict::Clean);
        assert!(!report.characteristics.suspicious);
    }

    /// Every prefix that `is_frame_setup` keys on must be marked benign, or the
    /// Clean branch becomes unreachable again for that compiler.
    #[test]
    fn every_frame_setup_prefix_is_marked_benign() {
        let analyzer = EpAnalyzer::new();
        let frames: [&[u8]; 4] = [
            &[0x55, 0x8B, 0xEC],             // x86 MSVC
            &[0x55, 0x89, 0xE5],             // x86 GCC
            &[0x55, 0x48, 0x89, 0xE5],       // x64 GCC
            &[0x40, 0x53, 0x48, 0x83, 0xEC], // x64 MSVC
        ];
        for f in frames {
            assert!(is_frame_setup(f), "{f:02X?} should be a frame setup");
            let mut data = f.to_vec();
            data.resize(24, 0x90);
            let ch = analyzer.analyze(&data);
            assert!(
                !ch.known_pattern || ch.pattern_is_benign,
                "{f:02X?} matched {:?} as NON-benign, which would block the Clean verdict",
                ch.pattern_name
            );
        }
    }

    #[test]
    fn test_full_ep_analysis_thunk() {
        let mut data = vec![0xFFu8, 0x25, 0x00, 0x10, 0x40, 0x00];
        data.extend(vec![0u8; 58]);
        let report = full_ep_analysis(&data, 0, None);
        assert_eq!(report.verdict, EpVerdict::Thunk);
    }

    #[test]
    fn test_full_ep_analysis_packed() {
        // PUSHAD + CALL stub
        let mut data = vec![0x60u8, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED];
        data.extend(vec![0xAAu8; 55]);
        let report = full_ep_analysis(&data, 0, None);
        // Should be packed or at least suspicious
        assert!(report.verdict == EpVerdict::Packed || report.characteristics.suspicious);
    }

    #[test]
    fn test_full_ep_analysis_with_overlay() {
        let mut data = vec![0x55u8, 0x8B, 0xEC, 0x5D, 0xC3, 0x00, 0x00, 0x00];
        // Append zip overlay
        data.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04, 0x00]);
        let report = full_ep_analysis(&data, 0, Some(8));
        assert!(report.overlay.has_overlay);
    }

    #[test]
    fn test_ep_report_characteristics_included() {
        let data = vec![0x55u8, 0x48, 0x89, 0xE5, 0x90, 0x5D, 0xC3, 0x00];
        let report = full_ep_analysis(&data, 0, None);
        assert!(report.characteristics.is_frame_setup);
    }

    #[test]
    fn test_overlay_format_hints() {
        let det = OverlayDetector::new();
        let mut data = vec![0x00u8; 100];
        // RAR magic
        data.extend_from_slice(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]);
        let info = det.detect(&data, 100);
        assert_eq!(info.format_hint.as_deref(), Some("RAR"));
    }

    #[test]
    fn test_ep_analyzer_window_larger_than_data() {
        let analyzer = EpAnalyzer::new().with_window(1000);
        let data = vec![0x55u8; 10];
        let ch = analyzer.analyze(&data);
        // Should not panic, should use min(window, data.len())
        assert!(ch.byte_diversity <= 256);
    }

    #[test]
    fn test_push_pop_has_pushad_popad() {
        let analyzer = PushPopAnalyzer::new();
        let data = [0x60u8, 0x90, 0x90, 0x61]; // pushad, nop, nop, popad
        let p = analyzer.analyze(&data);
        assert!(p.has_pushad_popad);
    }

    #[test]
    fn test_tail_jump_no_jumps() {
        let det = TailJumpDetector::new();
        let data = vec![0x55u8, 0x8B, 0xEC, 0x5D, 0xC3];
        // Small near jump with offset < 0x100 should not trigger has_long_jump
        let jumps = det.find(&data);
        assert!(jumps.iter().all(|j| j.kind != TailJumpKind::NearJmp));
    }

    #[test]
    fn test_code_density_low_for_data() {
        // Random high-byte data unlikely to be code opcodes
        let data = vec![0xFEu8, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7];
        let d = code_density(&data);
        assert!(d < 0.5);
    }
}
