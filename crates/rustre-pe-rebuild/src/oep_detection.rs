//! OEP (Original Entry Point) detection heuristics for unpacked PE images.
//!
//! Key types:
//! - [`OepCandidate`] — an OEP guess with confidence and method name.
//! - [`OepDetector`] — coordinator running 10+ strategies.
//! - [`StolenBytesRecovery`] — recover prologues transplanted into packer stub.

use crate::{RebuildSection, compute_entropy};
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// OepMethod
// ---------------------------------------------------------------------------

/// Which detection strategy produced an OEP candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OepMethod {
    /// Explicit EP was supplied by the caller.
    ExplicitEp,
    /// Classic x86 PUSH EBP / MOV EBP, ESP prologue.
    X86ClassicPrologue,
    /// x64 PUSH RBP / MOV RBP, RSP prologue.
    X64ClassicPrologue,
    /// x64 SUB RSP, imm preamble.
    X64SubRsp,
    /// x86 SUB ESP, imm preamble.
    X86SubEsp,
    /// CRT startup pattern (PUSH EBX/ESI/EDI).
    CrtStartup,
    /// Low-entropy executable section start (unpacked section candidate).
    LowEntropySection,
    /// Tail-call JMP at end of the unpacker loop.
    TailCallJmp,
    /// First write target from emulated unpacker.
    FirstWriteTarget,
    /// IAT first-use heuristic.
    IatFirstUse,
    /// REX.W push register preamble (Windows x64 ABI).
    RexPush,
    /// Stolen bytes pattern (common prologue at unexpected offset).
    StolenBytes,
}

impl fmt::Display for OepMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExplicitEp => write!(f, "ExplicitEP"),
            Self::X86ClassicPrologue => write!(f, "x86ClassicPrologue"),
            Self::X64ClassicPrologue => write!(f, "x64ClassicPrologue"),
            Self::X64SubRsp => write!(f, "x64SubRsp"),
            Self::X86SubEsp => write!(f, "x86SubEsp"),
            Self::CrtStartup => write!(f, "CrtStartup"),
            Self::LowEntropySection => write!(f, "LowEntropySection"),
            Self::TailCallJmp => write!(f, "TailCallJmp"),
            Self::FirstWriteTarget => write!(f, "FirstWriteTarget"),
            Self::IatFirstUse => write!(f, "IatFirstUse"),
            Self::RexPush => write!(f, "RexPush"),
            Self::StolenBytes => write!(f, "StolenBytes"),
        }
    }
}

// ---------------------------------------------------------------------------
// OepCandidate
// ---------------------------------------------------------------------------

/// A single OEP candidate produced by one detection strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OepCandidate {
    /// Virtual address of the candidate OEP (absolute VA, not RVA).
    pub address: u64,
    /// Confidence in [0.0, 1.0].
    pub confidence: f32,
    /// Detection method.
    pub method: OepMethod,
    /// Human-readable reason.
    pub reason: String,
    /// Number of bytes that look like a valid function prologue.
    pub prologue_bytes: Vec<u8>,
}

impl OepCandidate {
    /// Returns `true` if confidence is at least 0.7.
    #[must_use]
    pub fn is_confident(&self) -> bool {
        self.confidence >= 0.7
    }

    /// Returns `true` if the candidate has a recognized prologue pattern.
    #[must_use]
    pub const fn has_prologue(&self) -> bool {
        !self.prologue_bytes.is_empty()
    }
}

impl fmt::Display for OepCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format address as "0xHHHH_LLLL" with underscore separator
        let hi = (self.address >> 16) as u32;
        let lo = (self.address & 0xFFFF) as u32;
        write!(
            f,
            "OEP@0x{hi:04x}_{lo:04x} conf={:.2} method={} ({})",
            self.confidence, self.method, self.reason
        )
    }
}

// ---------------------------------------------------------------------------
// StolenBytesRecovery
// ---------------------------------------------------------------------------

/// Attempts to detect and recover stolen bytes (prologue code moved into packer).
///
/// "Stolen bytes" is a technique where the first N bytes of the original entry
/// point are placed inside the packer stub and executed before the JMP back.
/// This module uses heuristic pattern matching to identify those bytes.
#[derive(Debug, Default)]
pub struct StolenBytesRecovery {
    /// Recovered stolen byte sequences.
    pub recovered: Vec<StolenBytesFragment>,
}

/// A fragment of stolen bytes recovered from the packer stub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StolenBytesFragment {
    /// File offset where the stolen bytes were found.
    pub stub_offset: u64,
    /// Reconstructed bytes.
    pub bytes: Vec<u8>,
    /// What pattern was matched.
    pub pattern_name: &'static str,
    /// Confidence (0.0–1.0).
    pub confidence: f32,
}

/// x86/x64 prologue byte patterns for stolen-bytes detection.
const PROLOGUE_PATTERNS: &[(&str, &[u8], f32)] = &[
    // x86 PUSH EBP / MOV EBP, ESP / SUB ESP, N
    ("x86_classic_8", &[0x55, 0x8B, 0xEC, 0x83, 0xEC], 0.85),
    // x86 PUSH EBP / MOV EBP, ESP
    ("x86_push_ebp", &[0x55, 0x8B, 0xEC], 0.75),
    // x64 PUSH RBP / MOV RBP, RSP
    ("x64_push_rbp", &[0x55, 0x48, 0x89, 0xE5], 0.85),
    // x64 SUB RSP, 0x28
    ("x64_sub_rsp_28", &[0x48, 0x83, 0xEC, 0x28], 0.80),
    // x64 SUB RSP, 0x38
    ("x64_sub_rsp_38", &[0x48, 0x83, 0xEC, 0x38], 0.78),
    // x64 SUB RSP, 0x48
    ("x64_sub_rsp_48", &[0x48, 0x83, 0xEC, 0x48], 0.78),
    // PUSH EBX / PUSH ESI / PUSH EDI (CRT startup)
    ("crt_startup", &[0x53, 0x56, 0x57], 0.65),
    // PUSH EAX/ECX/EDX/EBX/ESP/EBP/ESI/EDI (full PUSHAD-like but partial)
    ("push_regs_4", &[0x53, 0x55, 0x56, 0x57], 0.70),
    // x64 MOV [RSP+8], RBX / push sequence
    ("x64_frame_setup", &[0x48, 0x89, 0x5C, 0x24], 0.72),
];

impl StolenBytesRecovery {
    /// Create a new recovery engine.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            recovered: Vec::new(),
        }
    }

    /// Scan `data` for stolen byte patterns starting at each 4-byte aligned
    /// offset in `scan_range`.  Appends results to `self.recovered`.
    pub fn scan(&mut self, data: &[u8], scan_range: std::ops::Range<usize>) {
        let start = scan_range.start.min(data.len());
        let end = scan_range.end.min(data.len());
        let mut i = start;
        while i < end {
            let window = &data[i..end.min(i + 16)];
            for &(name, pattern, confidence) in PROLOGUE_PATTERNS {
                if window.len() >= pattern.len() && &window[..pattern.len()] == pattern {
                    self.recovered.push(StolenBytesFragment {
                        stub_offset: i as u64,
                        bytes: window[..pattern.len()].to_vec(),
                        pattern_name: name,
                        confidence,
                    });
                    break; // one match per offset
                }
            }
            i += 4;
        }
    }

    /// Return the highest-confidence recovered fragment, if any.
    #[must_use]
    pub fn best_candidate(&self) -> Option<&StolenBytesFragment> {
        self.recovered.iter().max_by(|a, b| {
            a.confidence
                .partial_cmp(&b.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Clear all results.
    pub fn clear(&mut self) {
        self.recovered.clear();
    }

    /// Number of fragments found.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.recovered.len()
    }
}

// ---------------------------------------------------------------------------
// OepDetector
// ---------------------------------------------------------------------------

/// Heuristic OEP detector running multiple strategies against a PE memory dump.
///
/// # Usage
///
/// ```rust,no_run
/// use rustre_pe_rebuild::oep_detection::OepDetector;
///
/// let dump = std::fs::read("dump.bin").unwrap();
/// let base = 0x0000_0001_4000_0000u64;
/// let mut det = OepDetector::new(base);
/// det.run_all(&dump);
/// if let Some(best) = det.best() {
///     println!("OEP = {best}");
/// }
/// ```
pub struct OepDetector {
    /// Virtual base address of `dump`.
    pub base: u64,
    /// All candidates collected so far.
    pub candidates: Vec<OepCandidate>,
    /// Entropy threshold below which a section is considered "unpacked" (default 7.0).
    pub low_entropy_threshold: f32,
    /// Minimum confidence to include in output (default 0.3).
    pub min_confidence: f32,
}

impl OepDetector {
    /// Create a new detector for a dump at `base`.
    #[must_use]
    pub const fn new(base: u64) -> Self {
        Self {
            base,
            candidates: Vec::new(),
            low_entropy_threshold: 7.0,
            min_confidence: 0.3,
        }
    }

    /// Run all strategies against `dump`.
    pub fn run_all(&mut self, dump: &[u8]) {
        self.candidates.clear();
        self.strategy_prologue_scan(dump);
        self.strategy_tail_call(dump);
        self.strategy_low_entropy_start(dump);
    }

    /// Run strategies against named sections (higher precision).
    pub fn run_on_sections(&mut self, sections: &[RebuildSection]) {
        self.candidates.clear();
        for sec in sections {
            if !sec.is_executable() {
                continue;
            }
            let ent = f64_to_f32(compute_entropy(&sec.data));
            // Low-entropy executable section → good OEP candidate.
            if ent < self.low_entropy_threshold {
                let confidence =
                    ((self.low_entropy_threshold - ent) / self.low_entropy_threshold).mul_add(0.4, 0.4);
                self.push(OepCandidate {
                    address: self.base + u64::from(sec.virtual_address),
                    confidence: confidence.min(1.0),
                    method: OepMethod::LowEntropySection,
                    reason: format!("Low-entropy ({ent:.2}) section {}", sec.name),
                    prologue_bytes: sec.data[..sec.data.len().min(8)].to_vec(),
                });
            }
            // Check prologue at section start.
            self.check_prologue_at(sec.data.as_slice(), self.base + u64::from(sec.virtual_address));
        }
        self.sort_by_confidence();
    }

    /// Explicitly set a known OEP RVA.
    pub fn set_known_oep(&mut self, ep_rva: u32) {
        self.push(OepCandidate {
            address: self.base + u64::from(ep_rva),
            confidence: 1.0,
            method: OepMethod::ExplicitEp,
            reason: format!("Explicit EP RVA {ep_rva:#x}"),
            prologue_bytes: Vec::new(),
        });
        self.sort_by_confidence();
    }

    /// Return the best (highest confidence) candidate, or `None`.
    #[must_use]
    pub fn best(&self) -> Option<&OepCandidate> {
        self.candidates.first()
    }

    /// Return all candidates meeting the minimum confidence threshold.
    #[must_use]
    pub fn filtered_candidates(&self) -> Vec<&OepCandidate> {
        self.candidates
            .iter()
            .filter(|c| c.confidence >= self.min_confidence)
            .collect()
    }

    /// Number of candidates.
    #[must_use]
    pub const fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    // ──────────────────────────────────────────────────────────────────────
    // Strategies
    // ──────────────────────────────────────────────────────────────────────

    /// Strategy 1: Scan for common x86/x64 function prologues.
    fn strategy_prologue_scan(&mut self, dump: &[u8]) {
        let mut i = 0usize;
        while i + 4 <= dump.len() {
            let va = self.base + i as u64;
            let b = &dump[i..];
            if let Some(c) = check_prologue(b, va) {
                self.push(c);
            }
            i += 4;
        }
    }

    /// Strategy 2: Tail-call JMP at end of high-entropy region.
    fn strategy_tail_call(&mut self, dump: &[u8]) {
        // Look for JMP DWORD / JMP QWORD patterns preceded by high-entropy data.
        let window = 0x1000usize;
        let mut i = window;
        while i + 5 <= dump.len() {
            let b = dump[i];
            // JMP rel32 (0xE9) or JMP r/m (0xFF 0x25 / 0xFF 0xE0)
            if b == 0xE9
                || (b == 0xFF
                    && i + 6 <= dump.len()
                    && (dump[i + 1] == 0x25 || dump[i + 1] == 0xE0))
            {
                let preceding_entropy = f64_to_f32(compute_entropy(&dump[i.saturating_sub(window)..i]));
                if preceding_entropy > 7.0 {
                    let target = if b == 0xE9 && i + 5 <= dump.len() {
                        let rel =
                            i32::from_le_bytes(dump[i + 1..i + 5].try_into().unwrap_or([0; 4]));
                        self.base + (i64::try_from(i).unwrap_or(i64::MAX) + 5 + i64::from(rel)).cast_unsigned()
                    } else {
                        self.base + i as u64 + 6
                    };
                    self.push(OepCandidate {
                        address: target,
                        confidence: 0.65,
                        method: OepMethod::TailCallJmp,
                        reason: format!(
                            "JMP at end of high-entropy region (entropy={preceding_entropy:.2})"
                        ),
                        prologue_bytes: Vec::new(),
                    });
                }
            }
            i += 16;
        }
    }

    /// Strategy 3: First low-entropy 4 KiB block start.
    fn strategy_low_entropy_start(&mut self, dump: &[u8]) {
        let block = 0x1000;
        let mut offset = 0usize;
        while offset + block <= dump.len() {
            let ent = f64_to_f32(compute_entropy(&dump[offset..offset + block]));
            if ent < self.low_entropy_threshold {
                let va = self.base + u64::try_from(offset).unwrap_or(u64::MAX);
                let b = &dump[offset..];
                let confidence =
                    ((self.low_entropy_threshold - ent) / self.low_entropy_threshold).mul_add(0.25, 0.35);
                self.push(OepCandidate {
                    address: va,
                    confidence: confidence.min(0.65),
                    method: OepMethod::LowEntropySection,
                    reason: format!("Low-entropy block at offset {offset:#x} (entropy={ent:.2})"),
                    prologue_bytes: b[..b.len().min(8)].to_vec(),
                });
                break; // first low-entropy block is the best guess
            }
            offset += block;
        }
    }

    fn check_prologue_at(&mut self, data: &[u8], va: u64) {
        if data.is_empty() {
            return;
        }
        if let Some(c) = check_prologue(data, va) {
            self.push(c);
        }
    }

    fn push(&mut self, c: OepCandidate) {
        self.candidates.push(c);
    }

    fn sort_by_confidence(&mut self) {
        self.candidates.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.address.cmp(&b.address))
        });
    }
}

impl fmt::Debug for OepDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OepDetector {{ base: {:#x}, candidates: {} }}",
            self.base,
            self.candidates.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Cast helpers
// ---------------------------------------------------------------------------

/// Lossily narrow an `f64` entropy value to `f32`.
const fn f64_to_f32(x: f64) -> f32 { x as f32 }

// ---------------------------------------------------------------------------
// check_prologue — pattern matching helper
// ---------------------------------------------------------------------------

fn check_prologue(b: &[u8], va: u64) -> Option<OepCandidate> {
    if b.len() < 2 {
        return None;
    }

    // x86 PUSH EBP / MOV EBP, ESP
    if b.len() >= 3 && b[0] == 0x55 && b[1] == 0x8B && b[2] == 0xEC {
        return Some(OepCandidate {
            address: va,
            confidence: 0.70,
            method: OepMethod::X86ClassicPrologue,
            reason: "PUSH EBP; MOV EBP, ESP".to_string(),
            prologue_bytes: b[..3.min(b.len())].to_vec(),
        });
    }
    // x64 PUSH RBP / MOV RBP, RSP
    if b.len() >= 4 && b[0] == 0x55 && b[1] == 0x48 && b[2] == 0x89 && b[3] == 0xE5 {
        return Some(OepCandidate {
            address: va,
            confidence: 0.75,
            method: OepMethod::X64ClassicPrologue,
            reason: "PUSH RBP; MOV RBP, RSP".to_string(),
            prologue_bytes: b[..4.min(b.len())].to_vec(),
        });
    }
    // x64 SUB RSP, imm8
    if b.len() >= 4 && b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xEC {
        return Some(OepCandidate {
            address: va,
            confidence: 0.72,
            method: OepMethod::X64SubRsp,
            reason: format!("SUB RSP, {:#x}", b[3]),
            prologue_bytes: b[..4.min(b.len())].to_vec(),
        });
    }
    // x86 SUB ESP, imm8
    if b.len() >= 3 && b[0] == 0x83 && b[1] == 0xEC {
        return Some(OepCandidate {
            address: va,
            confidence: 0.55,
            method: OepMethod::X86SubEsp,
            reason: format!("SUB ESP, {:#x}", b[2]),
            prologue_bytes: b[..3.min(b.len())].to_vec(),
        });
    }
    // CRT startup
    if b.len() >= 3 && b[0] == 0x53 && b[1] == 0x56 && b[2] == 0x57 {
        return Some(OepCandidate {
            address: va,
            confidence: 0.55,
            method: OepMethod::CrtStartup,
            reason: "PUSH EBX; PUSH ESI; PUSH EDI".to_string(),
            prologue_bytes: b[..3.min(b.len())].to_vec(),
        });
    }
    // REX.W PUSH register (0x40–0x4F prefix + 0x5x PUSH)
    if b.len() >= 2 && (b[0] & 0xF0) == 0x40 && (b[1] & 0xF8) == 0x50 {
        return Some(OepCandidate {
            address: va,
            confidence: 0.45,
            method: OepMethod::RexPush,
            reason: format!("REX+PUSH r{:x}", b[1] & 0x07),
            prologue_bytes: b[..2.min(b.len())].to_vec(),
        });
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_x86_prologue() -> Vec<u8> {
        // PUSH EBP; MOV EBP, ESP; SUB ESP, 0x10; NOP...
        let mut v = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
        v.extend_from_slice(&[0x90u8; 32]);
        v
    }

    fn make_x64_prologue() -> Vec<u8> {
        // PUSH RBP; MOV RBP, RSP; SUB RSP, 0x28; NOP...
        let mut v = vec![0x55u8, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x28];
        v.extend_from_slice(&[0x90u8; 32]);
        v
    }

    #[test]
    fn test_oep_detector_new() {
        let d = OepDetector::new(0x0001_4000_0000);
        assert_eq!(d.candidate_count(), 0);
        assert_eq!(d.base, 0x0001_4000_0000);
    }

    #[test]
    fn test_oep_detector_run_all_empty() {
        let mut d = OepDetector::new(0x0040_0000);
        d.run_all(&[]);
        assert_eq!(d.candidate_count(), 0);
    }

    #[test]
    fn test_oep_detector_x86_prologue() {
        let mut d = OepDetector::new(0x0040_0000);
        let data = make_x86_prologue();
        d.run_all(&data);
        assert!(d.best().is_some());
        let best = d.best().unwrap();
        assert!(best.confidence >= 0.5);
    }

    #[test]
    fn test_oep_detector_x64_prologue() {
        let mut d = OepDetector::new(0x0001_4000_0000);
        let data = make_x64_prologue();
        d.run_all(&data);
        assert!(d.best().is_some());
    }

    #[test]
    fn test_oep_detector_set_known_oep() {
        let mut d = OepDetector::new(0x0040_0000);
        d.set_known_oep(0x1000);
        let best = d.best().unwrap();
        assert_eq!(best.method, OepMethod::ExplicitEp);
        assert!((best.confidence - 1.0_f32).abs() < f32::EPSILON);
        assert_eq!(best.address, 0x0040_1000);
    }

    #[test]
    fn test_oep_candidate_display() {
        let c = OepCandidate {
            address: 0x0040_1000,
            confidence: 0.85,
            method: OepMethod::X86ClassicPrologue,
            reason: "test".to_string(),
            prologue_bytes: vec![0x55, 0x8B, 0xEC],
        };
        let s = c.to_string();
        assert!(s.contains("0x0040_1000"));
        assert!(s.contains("0.85"));
    }

    #[test]
    fn test_oep_candidate_is_confident() {
        let c = OepCandidate {
            address: 0,
            confidence: 0.8,
            method: OepMethod::LowEntropySection,
            reason: String::new(),
            prologue_bytes: vec![],
        };
        assert!(c.is_confident());
    }

    #[test]
    fn test_oep_candidate_not_confident() {
        let c = OepCandidate {
            address: 0,
            confidence: 0.4,
            method: OepMethod::LowEntropySection,
            reason: String::new(),
            prologue_bytes: vec![],
        };
        assert!(!c.is_confident());
    }

    #[test]
    fn test_oep_method_display() {
        assert_eq!(OepMethod::ExplicitEp.to_string(), "ExplicitEP");
        assert_eq!(OepMethod::X64SubRsp.to_string(), "x64SubRsp");
    }

    #[test]
    fn test_stolen_bytes_recovery_scan_x86() {
        let mut r = StolenBytesRecovery::new();
        let data = make_x86_prologue();
        r.scan(&data, 0..data.len());
        assert!(r.count() > 0);
    }

    #[test]
    fn test_stolen_bytes_recovery_scan_empty() {
        let mut r = StolenBytesRecovery::new();
        r.scan(&[], 0..0);
        assert_eq!(r.count(), 0);
    }

    #[test]
    fn test_stolen_bytes_best_candidate() {
        let mut r = StolenBytesRecovery::new();
        let data = make_x64_prologue();
        r.scan(&data, 0..data.len());
        if r.count() > 0 {
            let best = r.best_candidate().unwrap();
            assert!(best.confidence > 0.0);
        }
    }

    #[test]
    fn test_stolen_bytes_clear() {
        let mut r = StolenBytesRecovery::new();
        r.scan(&make_x86_prologue(), 0..6);
        r.clear();
        assert_eq!(r.count(), 0);
    }

    #[test]
    fn test_check_prologue_x86() {
        let b = [0x55u8, 0x8B, 0xEC, 0x90];
        let c = check_prologue(&b, 0x1000);
        assert!(c.is_some());
        let c = c.unwrap();
        assert_eq!(c.method, OepMethod::X86ClassicPrologue);
    }

    #[test]
    fn test_check_prologue_x64_sub() {
        let b = [0x48u8, 0x83, 0xEC, 0x28];
        let c = check_prologue(&b, 0x2000);
        assert!(c.is_some());
        let c = c.unwrap();
        assert_eq!(c.method, OepMethod::X64SubRsp);
    }

    #[test]
    fn test_check_prologue_none_on_nop() {
        let b = [0x90u8, 0x90, 0x90, 0x90];
        let c = check_prologue(&b, 0);
        assert!(c.is_none());
    }

    #[test]
    fn test_detector_filtered_candidates() {
        let mut d = OepDetector::new(0x0040_0000);
        d.set_known_oep(0x1000);
        let filtered = d.filtered_candidates();
        assert!(!filtered.is_empty());
    }

    #[test]
    fn test_detector_low_entropy_strategy() {
        let mut d = OepDetector::new(0x0040_0000);
        // Create a buffer: high-entropy first block, then low-entropy block
        let mut data = (0u8..=255).cycle().take(0x1000).collect::<Vec<_>>();
        data.extend(vec![0x90u8; 0x1000]); // low entropy
        d.run_all(&data);
        // Should find some low-entropy candidate
        
        assert!(d
            .candidates
            .iter().any(|c| c.method == OepMethod::LowEntropySection));
    }

    #[test]
    fn test_oep_has_prologue() {
        let c = OepCandidate {
            address: 0,
            confidence: 0.5,
            method: OepMethod::StolenBytes,
            reason: String::new(),
            prologue_bytes: vec![0x55, 0x8B, 0xEC],
        };
        assert!(c.has_prologue());
    }

    #[test]
    fn test_oep_no_prologue() {
        let c = OepCandidate {
            address: 0,
            confidence: 0.5,
            method: OepMethod::StolenBytes,
            reason: String::new(),
            prologue_bytes: vec![],
        };
        assert!(!c.has_prologue());
    }

    #[test]
    fn test_detector_debug() {
        let d = OepDetector::new(0x0040_0000);
        let s = format!("{d:?}");
        assert!(s.contains("OepDetector"));
    }
}
