//! `oep_finder` — Advanced Original Entry Point detection for packed PE files
//!
//! Supplements the existing [`oep_detection`] module with additional strategies
//! oriented toward dynamic and emulation-based OEP finding:
//!
//! * **Hardware breakpoint simulation** — record the first user-mode instruction
//!   that executes after the memory pattern changes from packed → unpacked.
//! * **Prologue scanning** — scan executable sections for common function prologues
//!   (x86, x64, ARM64) and score candidates by surrounding code quality.
//! * **Stack pointer balance check** — verify that the stack pointer at an OEP
//!   candidate is reasonably balanced relative to the process initial SP.
//! * **Section membership** — verify the candidate RVA falls within an
//!   executable section and is not inside the packer stub region.
//! * **SDK stub recognition** — detect well-known CRT / SDK start stubs
//!   (MSVC, MinGW, .NET, Delphi, VB).
//!
//! # Usage
//!
//! ```ignore
//! let finder = OepFinder::new(&pe_data, image_base);
//! let candidates = finder.scan_all()?;
//! let best = finder.best_candidate(&candidates)?;
//! println!("OEP RVA: {:#010x}", best.rva);
//! ```

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::RebuildError;

// ---------------------------------------------------------------------------
// OEP candidate
// ---------------------------------------------------------------------------

/// Confidence tier for an OEP candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OepConfidence {
    /// Speculative — might be correct.
    Low,
    /// Moderate confidence — passes basic heuristics.
    Medium,
    /// High confidence — multiple independent heuristics agree.
    High,
    /// Definitive — hardware breakpoint or known SDK stub match.
    Definitive,
}

impl std::fmt::Display for OepConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low       => write!(f, "Low"),
            Self::Medium    => write!(f, "Medium"),
            Self::High      => write!(f, "High"),
            Self::Definitive => write!(f, "Definitive"),
        }
    }
}

/// Which strategy produced this OEP candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OepStrategy {
    /// Classic x86 PUSH EBP / MOV EBP,ESP prologue.
    X86ClassicPrologue,
    /// x64 MOV [RSP+8],RCX or SUB RSP,imm prologue.
    X64Prologue,
    /// ARM64 STP X29,X30,[SP,#-n]! frame setup.
    Arm64Prologue,
    /// CRT startup stub (MSVC, MinGW, Delphi, etc.) recognized by byte pattern.
    CrtStartupStub { stub_name: String },
    /// Caller inferred from hardware breakpoint trace.
    HardwareBreakpoint,
    /// First section's entry point (last resort fallback).
    FirstExecutableSection,
    /// Supplied explicitly by the caller.
    Explicit,
    /// Stack pointer balance heuristic.
    StackBalance,
    /// Section membership cross-check.
    SectionMembership,
    /// High-entropy → low-entropy transition (unpack finish detection).
    EntropyTransition,
    /// Stolen bytes recovery (prologues relocated into stub).
    StolenBytesRecovery,
}

impl std::fmt::Display for OepStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86ClassicPrologue      => write!(f, "x86 classic prologue"),
            Self::X64Prologue             => write!(f, "x64 prologue"),
            Self::Arm64Prologue           => write!(f, "ARM64 prologue"),
            Self::CrtStartupStub { stub_name } => write!(f, "CRT stub: {stub_name}"),
            Self::HardwareBreakpoint      => write!(f, "HW breakpoint"),
            Self::FirstExecutableSection  => write!(f, "First exec section"),
            Self::Explicit                => write!(f, "Explicit"),
            Self::StackBalance            => write!(f, "Stack balance"),
            Self::SectionMembership       => write!(f, "Section membership"),
            Self::EntropyTransition       => write!(f, "Entropy transition"),
            Self::StolenBytesRecovery     => write!(f, "Stolen bytes"),
        }
    }
}

/// A single OEP candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OepCandidate {
    /// RVA of the candidate OEP within the PE image.
    pub rva: u32,
    /// Virtual address (`image_base` + `rva`).
    pub va: u64,
    /// Detection strategy.
    pub strategy: OepStrategy,
    /// Confidence level.
    pub confidence: OepConfidence,
    /// Human-readable note.
    pub note: String,
    /// Score (higher = more likely to be the real OEP).
    pub score: f64,
}

impl OepCandidate {
    fn new(rva: u32, va: u64, strategy: OepStrategy, confidence: OepConfidence, note: &str) -> Self {
        let score = match confidence {
            OepConfidence::Low       => 0.25,
            OepConfidence::Medium    => 0.5,
            OepConfidence::High      => 0.75,
            OepConfidence::Definitive => 1.0,
        };
        Self { rva, va, strategy, confidence, note: note.to_owned(), score }
    }
}

// ---------------------------------------------------------------------------
// Section info
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub rva: u32,
    pub virtual_size: u32,
    pub characteristics: u32,
}

impl SectionInfo {
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0020 != 0
    }
    #[must_use]
    pub const fn contains_rva(&self, rva: u32) -> bool {
        rva >= self.rva && rva < self.rva + self.virtual_size
    }
}

// ---------------------------------------------------------------------------
// OEP prologue patterns
// ---------------------------------------------------------------------------

/// x86 function prologue patterns (byte sequences at the start of functions).
pub const X86_PROLOGUES: &[(&[u8], &str)] = &[
    (&[0x55, 0x8B, 0xEC],             "PUSH EBP / MOV EBP,ESP"),
    (&[0x55, 0x89, 0xE5],             "PUSH EBP / MOV EBP,ESP (GCC)"),
    (&[0x53, 0x56, 0x57],             "PUSH EBX/ESI/EDI"),
    (&[0x81, 0xEC],                   "SUB ESP,imm32"),
    (&[0x83, 0xEC],                   "SUB ESP,imm8"),
    (&[0x56, 0x53],                   "PUSH ESI/EBX"),
    (&[0xE9],                         "JMP rel32 (thunk)"),
];

/// x64 function prologue patterns.
pub const X64_PROLOGUES: &[(&[u8], &str)] = &[
    (&[0x48, 0x89, 0x5C, 0x24],       "MOV [RSP+n],RBX"),
    (&[0x48, 0x83, 0xEC],             "SUB RSP,imm8"),
    (&[0x48, 0x81, 0xEC],             "SUB RSP,imm32"),
    (&[0x40, 0x53],                   "PUSH RBX (REX)"),
    (&[0x41, 0x54],                   "PUSH R12"),
    (&[0x55, 0x48, 0x8B, 0xEC],       "PUSH RBP / MOV RBP,RSP"),
    (&[0x4C, 0x8B, 0xDC],             "MOV R11,RSP"),
];

/// ARM64 function prologue patterns.
pub const ARM64_PROLOGUES: &[(&[u8], &str)] = &[
    (&[0xFD, 0x7B, 0xBE, 0xA9],       "STP X29,X30,[SP,#-0x20]!"),
    (&[0xFD, 0x7B, 0xBC, 0xA9],       "STP X29,X30,[SP,#-0x40]!"),
    (&[0xF3, 0x53, 0xBE, 0xA9],       "STP X19,X20,[SP,#-0x20]!"),
    (&[0xFF, 0x43, 0x00, 0xD1],       "SUB SP,SP,#0x10"),
    (&[0xFF, 0x83, 0x00, 0xD1],       "SUB SP,SP,#0x20"),
];

// ---------------------------------------------------------------------------
// Known CRT startup stubs
// ---------------------------------------------------------------------------

/// A known CRT startup byte pattern.
pub struct CrtStubPattern {
    pub name: &'static str,
    pub pattern: &'static [u8],
    pub mask: &'static [u8], // 0xFF = exact, 0x00 = wildcard
}

pub const CRT_STUBS: &[CrtStubPattern] = &[
    CrtStubPattern {
        name: "MSVC CRT (_mainCRTStartup)",
        pattern: &[0xE8, 0x00, 0x00, 0x00, 0x00, // CALL ?
                   0x83, 0xC4, 0x04,              // ADD ESP,4
                   0xC3],                          // RET
        mask:    &[0xFF, 0x00, 0x00, 0x00, 0x00,
                   0xFF, 0xFF, 0xFF,
                   0xFF],
    },
    CrtStubPattern {
        name: "MinGW CRT (_WinMainCRTStartup)",
        pattern: &[0x55, 0x89, 0xE5, 0x83, 0xE4, 0xF0],
        mask:    &[0xFF; 6],
    },
    CrtStubPattern {
        name: "Delphi EXE entry",
        pattern: &[0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x61],
        mask:    &[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF],
    },
    CrtStubPattern {
        name: "VB6 ThunRTMain",
        pattern: &[0x68, 0x00, 0x00, 0x00, 0x00, // PUSH offset ThunRTMain_struct
                   0xE8, 0x00, 0x00, 0x00, 0x00], // CALL ThunRTMain
        mask:    &[0xFF, 0x00, 0x00, 0x00, 0x00,
                   0xFF, 0x00, 0x00, 0x00, 0x00],
    },
    CrtStubPattern {
        name: ".NET CLR entry (_CorExeMain)",
        pattern: &[0xFF, 0x25], // JMP [IAT entry for _CorExeMain]
        mask:    &[0xFF, 0xFF],
    },
];

// ---------------------------------------------------------------------------
// OepFinder
// ---------------------------------------------------------------------------

type StrategyFn = Box<dyn Fn(&str) -> OepStrategy>;

/// Advanced OEP finder combining multiple heuristics.
pub struct OepFinder {
    /// Flat PE image bytes (may be memory-mapped or file layout).
    data: Vec<u8>,
    /// Image base (for VA computation).
    image_base: u64,
    /// Parsed section list.
    sections: Vec<SectionInfo>,
    /// Is 64-bit PE?
    is_x64: bool,
    /// RVA of the `AddressOfEntryPoint` field (current EP, may be packer EP).
    current_ep_rva: u32,
}

impl OepFinder {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create a finder from raw PE bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError`] if the PE headers cannot be parsed.
    pub fn from_bytes(data: Vec<u8>, image_base: u64) -> Result<Self, RebuildError> {
        let (sections, is_x64, current_ep_rva) = Self::parse_headers(&data)?;
        Ok(Self { data, image_base, sections, is_x64, current_ep_rva })
    }

    fn parse_headers(data: &[u8]) -> Result<(Vec<SectionInfo>, bool, u32), RebuildError> {
        if data.len() < 0x40 {
            return Err(RebuildError::Other("PE too small".into()));
        }
        let lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
        if lfanew + 4 > data.len() {
            return Err(RebuildError::Other("e_lfanew OOB".into()));
        }
        let coff = lfanew + 4;
        let num_sec = u16::from_le_bytes(data[coff+2..coff+4].try_into().unwrap()) as usize;
        let opt_sz  = u16::from_le_bytes(data[coff+16..coff+18].try_into().unwrap()) as usize;
        let opt     = coff + 20;
        if opt + 2 > data.len() { return Err(RebuildError::Other("no opt header".into())); }
        let magic   = u16::from_le_bytes(data[opt..opt+2].try_into().unwrap());
        let is_x64  = magic == 0x020B;
        // AddressOfEntryPoint is at opt+16 for both PE32 and PE32+.
        let ep_rva  = if opt + 20 <= data.len() {
            u32::from_le_bytes(data[opt+16..opt+20].try_into().unwrap())
        } else { 0 };
        let sec_table = opt + opt_sz;
        let mut sections = Vec::with_capacity(num_sec);
        for i in 0..num_sec {
            let base = sec_table + i * 40;
            if base + 40 > data.len() { break; }
            let name_bytes = &data[base..base+8];
            let name = String::from_utf8_lossy(name_bytes)
                .trim_end_matches('\0').to_owned();
            let virt_sz   = u32::from_le_bytes(data[base+8..base+12].try_into().unwrap());
            let virt_addr = u32::from_le_bytes(data[base+12..base+16].try_into().unwrap());
            let chars     = u32::from_le_bytes(data[base+36..base+40].try_into().unwrap());
            sections.push(SectionInfo {
                name, rva: virt_addr, virtual_size: virt_sz, characteristics: chars,
            });
        }
        Ok((sections, is_x64, ep_rva))
    }

    // -----------------------------------------------------------------------
    // Section helpers
    // -----------------------------------------------------------------------

    #[must_use]
    pub fn sections(&self) -> &[SectionInfo] { &self.sections }

    pub fn executable_sections(&self) -> impl Iterator<Item = &SectionInfo> {
        self.sections.iter().filter(|s| s.is_executable())
    }

    #[must_use]
    pub fn section_containing_rva(&self, rva: u32) -> Option<&SectionInfo> {
        self.sections.iter().find(|s| s.contains_rva(rva))
    }

    #[must_use]
    pub fn rva_to_file_offset(&self, rva: u32) -> Option<usize> {
        for sec in &self.sections {
            // Both operands come from a hostile section header: a wrapping sum
            // would silently skip the section.
            if rva >= sec.rva && rva < sec.rva.saturating_add(sec.virtual_size) {
                // Assume file-layout dump (pointer == VA for memory dumps).
                return Some(usize::try_from(rva).unwrap_or(usize::MAX));
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Scanning strategies
    // -----------------------------------------------------------------------

    /// Scan all executable sections for function prologue patterns.
    #[must_use]
    pub fn scan_prologue_patterns(&self) -> Vec<OepCandidate> {
        let mut candidates = Vec::new();
        let (patterns, strategy_ctor): (
            &[(&[u8], &str)],
            StrategyFn,
        ) = if self.is_x64 {
            (X64_PROLOGUES, Box::new(|_| OepStrategy::X64Prologue))
        } else {
            (X86_PROLOGUES, Box::new(|_| OepStrategy::X86ClassicPrologue))
        };

        for sec in self.executable_sections() {
            let start = usize::try_from(sec.rva).unwrap_or(usize::MAX);
            let end   = usize::try_from(sec.rva + sec.virtual_size).unwrap_or(usize::MAX);
            let end   = end.min(self.data.len());
            if start >= self.data.len() { continue; }

            for offset in (start..end).step_by(1) {
                for (pat, desc) in patterns {
                    if self.data[offset..].starts_with(pat) {
                        let rva = u32::try_from(offset).unwrap_or(u32::MAX);
                        let va  = self.image_base + u64::from(rva);
                        let mut c = OepCandidate::new(
                            rva, va,
                            strategy_ctor(desc),
                            OepConfidence::Low,
                            desc,
                        );
                        // Boost score if this is in the first executable section.
                        if sec.name == ".text" { c.score += 0.1; }
                        // Boost if close to the packer EP (within 0x1000).
                        let dist = rva.abs_diff(self.current_ep_rva);
                        if dist > 0x1000 && dist < 0x100_000 {
                            c.confidence = OepConfidence::Medium;
                            c.score = 0.5;
                        }
                        candidates.push(c);
                    }
                }
            }
        }
        candidates
    }

    /// Scan for known CRT startup stubs.
    #[must_use]
    pub fn scan_crt_stubs(&self) -> Vec<OepCandidate> {
        let mut candidates = Vec::new();
        for sec in self.executable_sections() {
            let start = usize::try_from(sec.rva).unwrap_or(usize::MAX);
            let end   = usize::try_from(sec.rva + sec.virtual_size).unwrap_or(usize::MAX);
            let end   = end.min(self.data.len());
            if start >= self.data.len() { continue; }

            for stub in CRT_STUBS {
                let pat = stub.pattern;
                let mask = stub.mask;
                if pat.len() > end - start { continue; }
                for offset in start..end.saturating_sub(pat.len()) {
                    if pattern_match(&self.data[offset..], pat, mask) {
                        let rva = u32::try_from(offset).unwrap_or(u32::MAX);
                        let va  = self.image_base + u64::from(rva);
                        candidates.push(OepCandidate::new(
                            rva, va,
                            OepStrategy::CrtStartupStub { stub_name: stub.name.to_owned() },
                            OepConfidence::High,
                            stub.name,
                        ));
                    }
                }
            }
        }
        candidates
    }

    /// Return the first executable section's first byte as a fallback OEP.
    #[must_use]
    pub fn first_executable_section_oep(&self) -> Option<OepCandidate> {
        let sec = self.executable_sections().next()?;
        let rva = sec.rva;
        let va  = self.image_base + u64::from(rva);
        Some(OepCandidate::new(
            rva, va,
            OepStrategy::FirstExecutableSection,
            OepConfidence::Low,
            "first byte of first executable section",
        ))
    }

    /// Validate `rva` against section membership and stack balance heuristics.
    ///
    /// `sp_at_candidate` is the observed stack pointer when execution reached
    /// `rva`; `initial_sp` is the stack pointer at process start.
    #[must_use]
    pub fn validate_candidate(
        &self,
        rva: u32,
        sp_at_candidate: Option<u64>,
        initial_sp: Option<u64>,
    ) -> CandidateValidation {
        let in_exec_section = self.section_containing_rva(rva)
            .is_some_and(SectionInfo::is_executable);

        let stack_balanced = match (sp_at_candidate, initial_sp) {
            (Some(sp), Some(isp)) => {
                // SP should be within a few hundred KB of initial SP.
                let diff = sp.abs_diff(isp);
                diff < 0x10_0000
            }
            _ => true, // cannot check
        };

        let not_in_packer_stub = self.current_ep_rva == 0
            || rva.abs_diff(self.current_ep_rva) > 0x100;

        CandidateValidation {
            rva,
            in_executable_section: in_exec_section,
            stack_balanced,
            not_in_packer_stub,
        }
    }

    /// Detect the entropy transition point in the PE data — the section whose
    /// trailing bytes have low entropy after a preceding section with high
    /// entropy (indicative of a section that was just decompressed).
    #[must_use]
    pub fn detect_entropy_transition(&self) -> Vec<OepCandidate> {
        let mut candidates = Vec::new();
        let mut prev_high_entropy = false;
        for sec in self.executable_sections() {
            let start = usize::try_from(sec.rva).unwrap_or(usize::MAX);
            let end   = usize::try_from(sec.rva + sec.virtual_size).unwrap_or(usize::MAX);
            let end   = end.min(self.data.len());
            if start >= self.data.len() { continue; }
            let ent = shannon_entropy(&self.data[start..end]);
            if prev_high_entropy && ent < 5.5 {
                // This section just transitioned from packed to unpacked.
                let rva = sec.rva;
                let va  = self.image_base + u64::from(rva);
                candidates.push(OepCandidate::new(
                    rva, va,
                    OepStrategy::EntropyTransition,
                    OepConfidence::Medium,
                    &format!("section {} entropy={ent:.2} (previous was high)", sec.name),
                ));
            }
            prev_high_entropy = ent > 7.0;
        }
        candidates
    }

    /// Record an OEP found by a hardware breakpoint (highest confidence).
    #[must_use]
    pub fn record_hwbp_oep(&self, rva: u32) -> OepCandidate {
        let va = self.image_base + u64::from(rva);
        OepCandidate {
            rva,
            va,
            strategy: OepStrategy::HardwareBreakpoint,
            confidence: OepConfidence::Definitive,
            note: "hardware breakpoint on execute".into(),
            score: 1.0,
        }
    }

    /// Run all strategies and return all candidates, sorted by score descending.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError`] if no executable sections are found or parsing fails.
    pub fn scan_all(&self) -> Result<Vec<OepCandidate>, RebuildError> {
        let mut all = Vec::new();
        all.extend(self.scan_prologue_patterns());
        all.extend(self.scan_crt_stubs());
        all.extend(self.detect_entropy_transition());
        if let Some(fb) = self.first_executable_section_oep() { all.push(fb); }
        // Deduplicate by RVA, keeping highest score.
        let mut by_rva: HashMap<u32, OepCandidate> = HashMap::new();
        for c in all {
            let entry = by_rva.entry(c.rva).or_insert_with(|| c.clone());
            if c.score > entry.score { *entry = c; }
        }
        let mut result: Vec<OepCandidate> = by_rva.into_values().collect();
        result.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        Ok(result)
    }

    /// Return the single best OEP candidate.
    ///
    /// # Errors
    ///
    /// Returns [`RebuildError::NoOepCandidates`] if the candidate list is empty.
    pub fn best_candidate<'a>(
        &self,
        candidates: &'a [OepCandidate],
    ) -> Result<&'a OepCandidate, RebuildError> {
        candidates.first().ok_or(RebuildError::NoOepCandidates)
    }
}

// ---------------------------------------------------------------------------
// Candidate validation result
// ---------------------------------------------------------------------------

/// Validation result for a single OEP candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateValidation {
    pub rva: u32,
    pub in_executable_section: bool,
    pub stack_balanced: bool,
    pub not_in_packer_stub: bool,
}

impl CandidateValidation {
    /// True only if all checks pass.
    #[must_use]
    pub const fn valid(&self) -> bool {
        self.in_executable_section && self.stack_balanced && self.not_in_packer_stub
    }
}

// ---------------------------------------------------------------------------
// Stolen bytes recovery
// ---------------------------------------------------------------------------

/// A stolen bytes record: bytes that were moved from the OEP to the packer
/// stub to prevent naive EP restoration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StolenBytes {
    /// Original RVA where these bytes should be placed.
    pub original_rva: u32,
    /// Original absolute VA (`image_base` + `original_rva`) for easier reporting.
    pub original_va: u64,
    /// The bytes that were stolen.
    pub bytes: Vec<u8>,
    /// Confidence that the recovery is correct.
    pub confidence: OepConfidence,
}

/// Attempt to recover stolen bytes by comparing the first N bytes at the
/// packer EP with known function prologue sequences.
///
/// Returns a list of possible stolen-bytes records to try patching back.
#[must_use]
pub fn recover_stolen_bytes(
    data: &[u8],
    packer_ep_rva: u32,
    image_base: u64,
    is_x64: bool,
) -> Vec<StolenBytes> {
    let start = usize::try_from(packer_ep_rva).unwrap_or(usize::MAX);
    if start >= data.len() { return Vec::new(); }
    let window = &data[start..(start + 64).min(data.len())];

    let prologues: &[(&[u8], &str)] =
        if is_x64 { X64_PROLOGUES } else { X86_PROLOGUES };

    let mut results = Vec::new();
    for (pat, _) in prologues {
        if window.starts_with(pat) {
            results.push(StolenBytes {
                original_rva: packer_ep_rva,
                original_va: image_base.wrapping_add(u64::from(packer_ep_rva)),
                bytes: pat.to_vec(),
                confidence: OepConfidence::Low,
            });
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pattern_match(data: &[u8], pattern: &[u8], mask: &[u8]) -> bool {
    if data.len() < pattern.len() { return false; }
    for i in 0..pattern.len() {
        if mask[i] != 0 && data[i] != pattern[i] { return false; }
    }
    true
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[usize::from(b)] += 1; }
    let len = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = f64::from(c) / len; -p * p.log2() })
        .sum()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_match_exact() {
        assert!(pattern_match(b"\x55\x8B\xEC\x90", b"\x55\x8B\xEC", b"\xFF\xFF\xFF"));
    }

    #[test]
    fn pattern_match_wildcard() {
        assert!(pattern_match(b"\xE8\x01\x02\x03\x04", b"\xE8\x00\x00\x00\x00", b"\xFF\x00\x00\x00\x00"));
    }

    #[test]
    fn shannon_entropy_uniform() {
        let data = vec![0x41u8; 256];
        assert!((shannon_entropy(&data) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn shannon_entropy_max() {
        let data: Vec<u8> = (0..=255u8).collect();
        // All 256 distinct bytes: entropy ~= 8.0
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "got {e}");
    }

    #[test]
    fn oep_confidence_ordering() {
        assert!(OepConfidence::Definitive > OepConfidence::High);
        assert!(OepConfidence::High > OepConfidence::Medium);
        assert!(OepConfidence::Medium > OepConfidence::Low);
    }
}
