//! Anti-analysis pattern recognition.
//!
//! Provides [`AntiAnalysisPattern`], [`PatternDetector`], [`PatternDensity`],
//! [`ObfuscationScore`], and [`CleaningStrategy`].

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// AntiAnalysisPattern
// ─────────────────────────────────────────────────────────────────────────────

/// A recognisable anti-analysis obfuscation pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AntiAnalysisPattern {
    /// Sequences of instructions that have no effect (junk code / dead code insertion).
    JunkCode,
    /// Control-flow that is intentionally entangled (goto spaghetti).
    SpaghettiCode,
    /// CALL instructions that are immediately popped and whose target is not a real function.
    BogusCall,
    /// JMP to the next instruction (opaque jumps that don't actually branch).
    OpaqueJump,
    /// Indirect jumps through computed addresses (e.g. `jmp [reg+disp]`).
    IndirectJump,
    /// Interleaved data and code in the same section.
    MixedDataCode,
    /// Constant folding obfuscation — constant values computed via redundant arithmetic.
    ObfuscatedConstant,
    /// Stack-based string construction (char by char, no static strings).
    StackString,
    /// XOR-encoded data regions.
    XorEncoding,
    /// Self-modifying code patterns.
    SelfModifying,
    /// Exception-based control flow (SEH/VEH hijacking for branching).
    ExceptionCF,
    /// Fake API calls (call to an import that returns immediately / does nothing).
    FakeApiCall,
    /// Overlapping instructions (x86 polyglot bytes).
    OverlappingInstructions,
    /// Infinite loop with hidden exit condition.
    ObfuscatedLoop,
    /// VM-protected region (detected by dispatcher-like structure).
    VmProtectedRegion,
}

impl std::fmt::Display for AntiAnalysisPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::JunkCode => "JunkCode",
            Self::SpaghettiCode => "SpaghettiCode",
            Self::BogusCall => "BogusCall",
            Self::OpaqueJump => "OpaqueJump",
            Self::IndirectJump => "IndirectJump",
            Self::MixedDataCode => "MixedDataCode",
            Self::ObfuscatedConstant => "ObfuscatedConstant",
            Self::StackString => "StackString",
            Self::XorEncoding => "XorEncoding",
            Self::SelfModifying => "SelfModifying",
            Self::ExceptionCF => "ExceptionCF",
            Self::FakeApiCall => "FakeApiCall",
            Self::OverlappingInstructions => "OverlappingInstructions",
            Self::ObfuscatedLoop => "ObfuscatedLoop",
            Self::VmProtectedRegion => "VmProtectedRegion",
        };
        write!(f, "{s}")
    }
}

impl AntiAnalysisPattern {
    /// Return a difficulty score for cleaning this pattern (1=easy, 5=very hard).
    #[must_use]
    pub const fn cleaning_difficulty(self) -> u8 {
        match self {
            Self::JunkCode => 2,
            Self::SpaghettiCode => 3,
            Self::BogusCall => 2,
            Self::OpaqueJump => 3,
            Self::IndirectJump => 4,
            Self::MixedDataCode => 3,
            Self::ObfuscatedConstant => 3,
            Self::StackString => 2,
            Self::XorEncoding => 2,
            Self::SelfModifying => 5,
            Self::ExceptionCF => 4,
            Self::FakeApiCall => 2,
            Self::OverlappingInstructions => 4,
            Self::ObfuscatedLoop => 3,
            Self::VmProtectedRegion => 5,
        }
    }

    /// Return `true` if this pattern typically requires dynamic analysis to clean.
    #[must_use]
    pub const fn requires_dynamic(self) -> bool {
        matches!(
            self,
            Self::SelfModifying | Self::VmProtectedRegion | Self::ExceptionCF
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternHit
// ─────────────────────────────────────────────────────────────────────────────

/// A specific instance of a detected anti-analysis pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternHit {
    pub pattern: AntiAnalysisPattern,
    pub address: u64,
    pub offset: usize,
    pub size: usize,
    pub confidence: u8,
    pub description: String,
    /// Matched / illustrative bytes.
    pub evidence_bytes: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal scanner entries
// ─────────────────────────────────────────────────────────────────────────────

struct PatternEntry {
    pattern: AntiAnalysisPattern,
    bytes: Vec<u8>,
    mask: Option<Vec<u8>>,
    confidence: u8,
    description: &'static str,
}

impl PatternEntry {
    fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.bytes.len() > data.len() {
            return false;
        }
        let s = &data[offset..offset + self.bytes.len()];
        match &self.mask {
            Some(m) => s
                .iter()
                .zip(self.bytes.iter())
                .zip(m.iter())
                .all(|((&d, &p), &mask)| (d & mask) == (p & mask)),
            None => s == self.bytes.as_slice(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects anti-analysis patterns in binary data.
pub struct PatternDetector {
    entries: Vec<PatternEntry>,
    base_address: u64,
    min_confidence: u8,
}

impl PatternDetector {
    #[must_use]
    pub fn new() -> Self {
        let mut d = Self {
            entries: Vec::new(),
            base_address: 0,
            min_confidence: 40,
        };
        d.populate();
        d
    }

    pub const fn set_base_address(&mut self, addr: u64) {
        self.base_address = addr;
    }

    pub const fn set_min_confidence(&mut self, c: u8) {
        self.min_confidence = c;
    }

    /// Maximum number of hits returned per scan to prevent memory exhaustion
    /// when attacker-controlled input contains an extremely dense pattern (e.g.
    /// a binary filled with 0xEB 0x00 would fire `OpaqueJump` at every byte).
    const MAX_HITS: usize = 65_536;

    /// Scan `data` for all registered patterns.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Vec<PatternHit> {
        let mut hits = Vec::new();
        'outer: for entry in &self.entries {
            if entry.confidence < self.min_confidence {
                continue;
            }
            for offset in 0..data
                .len()
                .saturating_sub(entry.bytes.len().saturating_sub(1))
            {
                if entry.matches_at(data, offset) {
                    hits.push(PatternHit {
                        pattern: entry.pattern,
                        address: self.base_address + offset as u64,
                        offset,
                        size: entry.bytes.len(),
                        confidence: entry.confidence,
                        description: entry.description.to_owned(),
                        evidence_bytes: data[offset..offset + entry.bytes.len()].to_vec(),
                    });
                    if hits.len() >= Self::MAX_HITS {
                        break 'outer;
                    }
                }
            }
        }
        hits.sort_by(|a, b| a.offset.cmp(&b.offset));
        hits
    }

    fn push(
        &mut self,
        pattern: AntiAnalysisPattern,
        bytes: Vec<u8>,
        mask: Option<Vec<u8>>,
        confidence: u8,
        description: &'static str,
    ) {
        self.entries.push(PatternEntry {
            pattern,
            bytes,
            mask,
            confidence,
            description,
        });
    }

    fn populate(&mut self) {
        // ── Junk code: XCHG EAX, EAX (= NOP), or redundant MOV EAX, EAX ──
        self.push(
            AntiAnalysisPattern::JunkCode,
            vec![0x87, 0xC0],
            None,
            60,
            "XCHG EAX,EAX (junk NOP equivalent)",
        );
        self.push(
            AntiAnalysisPattern::JunkCode,
            vec![0x8B, 0xC0],
            None,
            55,
            "MOV EAX,EAX (junk self-move)",
        );
        self.push(
            AntiAnalysisPattern::JunkCode,
            vec![0x8D, 0x40, 0x00],
            None,
            55,
            "LEA EAX,[EAX+0] (junk)",
        );
        // ── Bogus CALL (CALL $+5; POP REG pattern) ─────────────────────────
        self.push(
            AntiAnalysisPattern::BogusCall,
            vec![0xE8, 0x00, 0x00, 0x00, 0x00],
            None,
            70,
            "CALL $+5 (get-PC thunk / bogus call)",
        );
        // ── Opaque jump: JMP 0 / JMP $+2 ──────────────────────────────────
        self.push(
            AntiAnalysisPattern::OpaqueJump,
            vec![0xEB, 0x00],
            None,
            65,
            "JMP +0 (no-op short jump)",
        );
        self.push(
            AntiAnalysisPattern::OpaqueJump,
            vec![0xEB, 0xFE],
            None,
            75,
            "JMP $ (infinite loop — opaque or halt)",
        );
        // ── Indirect jump: JMP [REG] ───────────────────────────────────────
        self.push(
            AntiAnalysisPattern::IndirectJump,
            vec![0xFF, 0xE0],
            None,
            70,
            "JMP EAX (indirect jump through register)",
        );
        self.push(
            AntiAnalysisPattern::IndirectJump,
            vec![0xFF, 0xE1],
            None,
            70,
            "JMP ECX",
        );
        self.push(
            AntiAnalysisPattern::IndirectJump,
            vec![0xFF, 0xE2],
            None,
            70,
            "JMP EDX",
        );
        self.push(
            AntiAnalysisPattern::IndirectJump,
            vec![0xFF, 0xE3],
            None,
            70,
            "JMP EBX",
        );
        // 64-bit register jumps
        self.push(
            AntiAnalysisPattern::IndirectJump,
            vec![0xFF, 0xE0],
            None,
            68,
            "JMP RAX (64-bit indirect)",
        );
        // ── Stack string: byte-by-byte PUSH of ASCII chars ─────────────────
        // Pattern: PUSH imm8 (6A xx) where xx is printable ASCII, repeated.
        self.push(
            AntiAnalysisPattern::StackString,
            vec![0x6A, 0x41, 0x6A, 0x42],
            None,
            60,
            "Two PUSH imm8 ASCII chars (possible stack string)",
        );
        // MOV BYTE PTR [reg+offset], imm8
        self.push(
            AntiAnalysisPattern::StackString,
            vec![0xC6, 0x45],
            Some(vec![0xFF, 0xFF]),
            55,
            "MOV BYTE PTR [EBP+off],imm (stack string char)",
        );
        // ── XOR encoding: XOR EAX, imm32 loop pattern hint ────────────────
        self.push(
            AntiAnalysisPattern::XorEncoding,
            vec![0x35, 0xDE, 0xAD, 0xBE, 0xEF],
            None,
            70,
            "XOR EAX, 0xDEADBEEF (possible decode key)",
        );
        // Generic XOR reg, imm8
        self.push(
            AntiAnalysisPattern::XorEncoding,
            vec![0x80, 0x30],
            Some(vec![0xFF, 0xFF]),
            50,
            "XOR BYTE PTR [EAX], imm8 (XOR decode loop body)",
        );
        // ── Self-modifying code: write to code segment (REP STOS / MOVSB into .text) ──
        self.push(
            AntiAnalysisPattern::SelfModifying,
            vec![0xF3, 0xAA],
            None,
            65,
            "REP STOSB — may overwrite code",
        );
        self.push(
            AntiAnalysisPattern::SelfModifying,
            vec![0xF3, 0xA4],
            None,
            65,
            "REP MOVSB — may copy/overwrite code",
        );
        // ── Exception CF: INT2E / SYSENTER / INT 2D ────────────────────────
        self.push(
            AntiAnalysisPattern::ExceptionCF,
            vec![0xCD, 0x2E],
            None,
            72,
            "INT 0x2E (NT syscall / exception CF)",
        );
        self.push(
            AntiAnalysisPattern::ExceptionCF,
            vec![0xCD, 0x2D],
            None,
            75,
            "INT 0x2D (DebugService — exception-based anti-debug)",
        );
        self.push(
            AntiAnalysisPattern::ExceptionCF,
            vec![0xCD, 0x03],
            None,
            68,
            "INT 3 (software breakpoint)",
        );
        // ── Overlapping instructions: sequences that can be decoded two ways ─
        // Pattern: byte that starts one instruction but is also middle of another.
        self.push(
            AntiAnalysisPattern::OverlappingInstructions,
            vec![0xEB, 0x02, 0xFF, 0xFF],
            None,
            70,
            "JMP +2 over garbage bytes (overlapping)",
        );
        // ── VM protected region: large dispatcher stub hint ────────────────
        // Look for a pattern like: MOVZX EAX, BYTE PTR [ESI] (VM fetch)
        self.push(
            AntiAnalysisPattern::VmProtectedRegion,
            vec![0x0F, 0xB6, 0x06],
            None,
            60,
            "MOVZX EAX, [ESI] (possible VM opcode fetch)",
        );
        // ── Mixed data/code: 00 00 padding inside executable section ────────
        self.push(
            AntiAnalysisPattern::MixedDataCode,
            vec![
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
            None,
            40,
            "Long run of zero bytes in executable region (possible data padding)",
        );
        // ── Obfuscated constant: redundant arithmetic to produce zero ────────
        self.push(
            AntiAnalysisPattern::ObfuscatedConstant,
            vec![0x31, 0xC0, 0x35, 0x00, 0x00, 0x00, 0x00],
            Some(vec![0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]),
            55,
            "XOR EAX,EAX; XOR EAX,0 (redundant constant zero)",
        );
        // ── Obfuscated loop: DEC/INC with conditional opaque ────────────────
        self.push(
            AntiAnalysisPattern::ObfuscatedLoop,
            vec![0x48, 0x75, 0xFE],
            None,
            55,
            "DEC EAX; JNZ -2 (tight loop — possible counter obfuscation)",
        );
        // ── Fake API call: CALL followed immediately by RET ─────────────────
        self.push(
            AntiAnalysisPattern::FakeApiCall,
            vec![0xFF, 0x15],
            Some(vec![0xFF, 0xFF]),
            45,
            "CALL DWORD PTR [addr] (indirect call — possible fake API)",
        );
    }
}

impl Default for PatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternDensity
// ─────────────────────────────────────────────────────────────────────────────

/// Density of anti-analysis patterns in a binary region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternDensity {
    /// Bytes analysed.
    pub region_size: usize,
    /// Number of hits per 1024 bytes.
    pub hits_per_kb: f64,
    /// Hit counts broken down by pattern.
    pub by_pattern: HashMap<String, usize>,
    /// Most prevalent pattern.
    pub top_pattern: Option<AntiAnalysisPattern>,
}

impl PatternDensity {
    /// Compute density from a set of hits and the binary size.
    #[must_use]
    pub fn compute(hits: &[PatternHit], region_size: usize) -> Self {
        let mut by_pattern: HashMap<String, usize> = HashMap::new();
        for h in hits {
            *by_pattern.entry(h.pattern.to_string()).or_insert(0) += 1;
        }
        let hits_per_kb = if region_size == 0 {
            0.0
        } else {
            (hits.len() as f64 / region_size as f64) * 1024.0
        };
        let top_pattern = hits
            .iter()
            .max_by(|a, b| {
                let ca = by_pattern.get(&a.pattern.to_string()).copied().unwrap_or(0);
                let cb = by_pattern.get(&b.pattern.to_string()).copied().unwrap_or(0);
                ca.cmp(&cb)
            })
            .map(|h| h.pattern);

        Self {
            region_size,
            hits_per_kb,
            by_pattern,
            top_pattern,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ObfuscationScore
// ─────────────────────────────────────────────────────────────────────────────

/// Overall obfuscation score for a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationScore {
    /// 0.0 = no obfuscation, 100.0 = maximally obfuscated.
    pub score: f64,
    /// Human-readable label.
    pub label: &'static str,
    /// Constituent scores.
    pub components: HashMap<String, f64>,
    /// Detected pattern types.
    pub detected_patterns: Vec<AntiAnalysisPattern>,
}

impl ObfuscationScore {
    /// Compute the score from hits and binary size.
    #[must_use]
    pub fn compute(hits: &[PatternHit], binary_size: usize) -> Self {
        let mut by_pattern: HashMap<AntiAnalysisPattern, usize> = HashMap::new();
        for h in hits {
            *by_pattern.entry(h.pattern).or_insert(0) += 1;
        }

        // Weight each pattern type.
        let weights: &[(AntiAnalysisPattern, f64)] = &[
            (AntiAnalysisPattern::VmProtectedRegion, 30.0),
            (AntiAnalysisPattern::SelfModifying, 25.0),
            (AntiAnalysisPattern::ExceptionCF, 20.0),
            (AntiAnalysisPattern::IndirectJump, 15.0),
            (AntiAnalysisPattern::OverlappingInstructions, 15.0),
            (AntiAnalysisPattern::SpaghettiCode, 10.0),
            (AntiAnalysisPattern::OpaqueJump, 8.0),
            (AntiAnalysisPattern::XorEncoding, 8.0),
            (AntiAnalysisPattern::StackString, 5.0),
            (AntiAnalysisPattern::JunkCode, 4.0),
            (AntiAnalysisPattern::BogusCall, 5.0),
            (AntiAnalysisPattern::ObfuscatedConstant, 3.0),
        ];

        let mut components = HashMap::new();
        let mut raw_score = 0.0f64;

        for &(pat, weight) in weights {
            if let Some(&count) = by_pattern.get(&pat) {
                let density = if binary_size > 0 {
                    (count as f64 / binary_size as f64) * 10_000.0
                } else {
                    0.0
                };
                let contrib = (density * weight).min(weight); // cap per-pattern contribution
                components.insert(pat.to_string(), contrib);
                raw_score += contrib;
            }
        }

        let score = raw_score.min(100.0);
        let label = if score >= 80.0 {
            "Heavily Obfuscated"
        } else if score >= 50.0 {
            "Moderately Obfuscated"
        } else if score >= 20.0 {
            "Lightly Obfuscated"
        } else {
            "Minimal Obfuscation"
        };

        let detected_patterns: Vec<_> = by_pattern.keys().copied().collect();

        Self {
            score,
            label,
            components,
            detected_patterns,
        }
    }

    /// Return `true` if the binary is considered to have significant obfuscation.
    #[must_use]
    pub fn is_obfuscated(&self) -> bool {
        self.score >= 20.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CleaningStrategy
// ─────────────────────────────────────────────────────────────────────────────

/// A recommended strategy for cleaning a specific anti-analysis pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleaningStrategy {
    pub pattern: AntiAnalysisPattern,
    /// Short name.
    pub name: String,
    /// Detailed steps.
    pub steps: Vec<String>,
    /// Whether dynamic analysis is required.
    pub requires_dynamic: bool,
    /// Estimated effort (1=trivial, 5=very hard).
    pub effort: u8,
    /// Whether this can be fully automated.
    pub automatable: bool,
}

impl CleaningStrategy {
    /// Return the default cleaning strategy for a pattern.
    #[must_use]
    pub fn for_pattern(pattern: AntiAnalysisPattern) -> Self {
        let (name, steps, automatable) = match pattern {
            AntiAnalysisPattern::JunkCode => (
                "NOP-out junk instructions",
                vec![
                    "Identify instructions with no effect (XCHG EAX,EAX; MOV EAX,EAX; LEA EAX,[EAX+0])".into(),
                    "Replace with single NOP (0x90) or multi-byte NOP".into(),
                    "Re-run disassembly pass to verify control flow is unchanged".into(),
                ],
                true,
            ),
            AntiAnalysisPattern::BogusCall => (
                "Remove bogus CALL $+5 get-PC thunks",
                vec![
                    "Detect CALL $+5 pattern (E8 00 00 00 00)".into(),
                    "Determine whether the POP is consumed or discarded".into(),
                    "Replace with equivalent constant-load or NOP block".into(),
                ],
                true,
            ),
            AntiAnalysisPattern::OpaqueJump => (
                "Simplify opaque predicate jumps",
                vec![
                    "Identify always-taken / never-taken conditional jumps".into(),
                    "Replace with unconditional JMP or remove jump + dead block".into(),
                    "Update control-flow graph".into(),
                ],
                true,
            ),
            AntiAnalysisPattern::XorEncoding => (
                "Decode XOR-encoded regions",
                vec![
                    "Identify XOR key via loop analysis or constant propagation".into(),
                    "Apply XOR decode to the target byte range".into(),
                    "Re-disassemble decoded region".into(),
                ],
                true,
            ),
            AntiAnalysisPattern::StackString => (
                "Reconstruct stack strings",
                vec![
                    "Trace PUSH imm8/MOV BYTE PTR sequences".into(),
                    "Concatenate bytes in stack order to recover string".into(),
                    "Annotate recovered string as a comment in the listing".into(),
                ],
                true,
            ),
            AntiAnalysisPattern::SelfModifying => (
                "Emulate self-modifying code",
                vec![
                    "Run under controlled emulator (rustre-emu-shellcode)".into(),
                    "Capture final memory state after modification".into(),
                    "Dump and re-analyse the modified code".into(),
                ],
                false,
            ),
            AntiAnalysisPattern::VmProtectedRegion => (
                "Lift VM bytecode to IR",
                vec![
                    "Identify VM dispatcher via rustre-deobf-vmlift".into(),
                    "Recover virtual ISA via handler analysis".into(),
                    "Lift virtual instructions to LLIL".into(),
                    "Apply standard analysis passes on lifted IR".into(),
                ],
                false,
            ),
            AntiAnalysisPattern::IndirectJump => (
                "Resolve indirect jumps via VSA",
                vec![
                    "Run value-set analysis to bound jump targets".into(),
                    "Replace indirect jump with dispatch table stub".into(),
                    "Update control-flow graph with resolved targets".into(),
                ],
                false,
            ),
            _ => (
                "Manual inspection required",
                vec![
                    "Identify all instances of the pattern".into(),
                    "Analyse context and intended effect".into(),
                    "Apply appropriate patch or annotation".into(),
                ],
                false,
            ),
        };

        Self {
            pattern,
            name: name.into(),
            steps,
            requires_dynamic: pattern.requires_dynamic(),
            effort: pattern.cleaning_difficulty(),
            automatable,
        }
    }
}

/// Return cleaning strategies for all detected patterns.
#[must_use]
pub fn strategies_for_hits(hits: &[PatternHit]) -> Vec<CleaningStrategy> {
    let mut seen = std::collections::HashSet::new();
    let mut strategies = Vec::new();
    for h in hits {
        if seen.insert(h.pattern) {
            strategies.push(CleaningStrategy::for_pattern(h.pattern));
        }
    }
    strategies
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- AntiAnalysisPattern -------------------------------------------------

    #[test]
    fn test_pattern_display() {
        assert_eq!(AntiAnalysisPattern::JunkCode.to_string(), "JunkCode");
        assert_eq!(
            AntiAnalysisPattern::VmProtectedRegion.to_string(),
            "VmProtectedRegion"
        );
    }

    #[test]
    fn test_pattern_difficulty() {
        assert_eq!(AntiAnalysisPattern::SelfModifying.cleaning_difficulty(), 5);
        assert_eq!(AntiAnalysisPattern::JunkCode.cleaning_difficulty(), 2);
    }

    #[test]
    fn test_pattern_requires_dynamic() {
        assert!(AntiAnalysisPattern::SelfModifying.requires_dynamic());
        assert!(!AntiAnalysisPattern::JunkCode.requires_dynamic());
    }

    // -- PatternDetector -----------------------------------------------------

    #[test]
    fn test_detector_junk_xchg_eax_eax() {
        let d = PatternDetector::new();
        let data = vec![0x87, 0xC0, 0x90];
        let hits = d.detect(&data);
        assert!(
            hits.iter()
                .any(|h| h.pattern == AntiAnalysisPattern::JunkCode)
        );
    }

    #[test]
    fn test_detector_bogus_call() {
        let d = PatternDetector::new();
        let data = vec![0xE8, 0x00, 0x00, 0x00, 0x00, 0x58];
        let hits = d.detect(&data);
        assert!(
            hits.iter()
                .any(|h| h.pattern == AntiAnalysisPattern::BogusCall)
        );
    }

    #[test]
    fn test_detector_opaque_jump() {
        let d = PatternDetector::new();
        let data = vec![0xEB, 0x00, 0x90];
        let hits = d.detect(&data);
        assert!(
            hits.iter()
                .any(|h| h.pattern == AntiAnalysisPattern::OpaqueJump)
        );
    }

    #[test]
    fn test_detector_indirect_jump_eax() {
        let d = PatternDetector::new();
        let data = vec![0x90, 0xFF, 0xE0, 0x90];
        let hits = d.detect(&data);
        assert!(
            hits.iter()
                .any(|h| h.pattern == AntiAnalysisPattern::IndirectJump)
        );
    }

    #[test]
    fn test_detector_rdtsc() {
        // RDTSC is not in PatternDetector (it's in AntiDebugDetector), so we expect no hit.
        let d = PatternDetector::new();
        let data = vec![0x0F, 0x31];
        let hits = d.detect(&data);
        assert!(
            !hits
                .iter()
                .any(|h| h.pattern == AntiAnalysisPattern::ExceptionCF)
        );
    }

    #[test]
    fn test_detector_exception_cf_int2d() {
        let d = PatternDetector::new();
        let data = vec![0xCD, 0x2D, 0x90];
        let hits = d.detect(&data);
        assert!(
            hits.iter()
                .any(|h| h.pattern == AntiAnalysisPattern::ExceptionCF)
        );
    }

    #[test]
    fn test_detector_xor_encoding() {
        let d = PatternDetector::new();
        let data = vec![0x35, 0xDE, 0xAD, 0xBE, 0xEF];
        let hits = d.detect(&data);
        assert!(
            hits.iter()
                .any(|h| h.pattern == AntiAnalysisPattern::XorEncoding)
        );
    }

    #[test]
    fn test_detector_self_modifying_rep_stosb() {
        let d = PatternDetector::new();
        let data = vec![0xF3, 0xAA, 0x90];
        let hits = d.detect(&data);
        assert!(
            hits.iter()
                .any(|h| h.pattern == AntiAnalysisPattern::SelfModifying)
        );
    }

    #[test]
    fn test_detector_empty() {
        let d = PatternDetector::new();
        assert!(d.detect(&[]).is_empty());
    }

    #[test]
    fn test_detector_min_confidence() {
        let mut d = PatternDetector::new();
        d.set_min_confidence(100);
        let data = vec![0x87, 0xC0]; // JunkCode confidence is 60
        assert!(d.detect(&data).is_empty());
    }

    #[test]
    fn test_detector_base_address() {
        let mut d = PatternDetector::new();
        d.set_base_address(0x400000);
        let data = vec![0xE8, 0x00, 0x00, 0x00, 0x00];
        let hits = d.detect(&data);
        for h in &hits {
            assert!(h.address >= 0x400000);
        }
    }

    // -- PatternDensity ------------------------------------------------------

    #[test]
    fn test_pattern_density_compute() {
        let d = PatternDetector::new();
        let data = vec![0xEB, 0x00, 0x87, 0xC0, 0xFF, 0xE0, 0x90];
        let hits = d.detect(&data);
        let density = PatternDensity::compute(&hits, data.len());
        assert!(density.hits_per_kb >= 0.0);
        assert_eq!(density.region_size, data.len());
    }

    #[test]
    fn test_pattern_density_empty() {
        let density = PatternDensity::compute(&[], 0);
        assert_eq!(density.hits_per_kb, 0.0);
    }

    // -- ObfuscationScore ----------------------------------------------------

    #[test]
    fn test_obfuscation_score_no_hits() {
        let score = ObfuscationScore::compute(&[], 1024);
        assert_eq!(score.score, 0.0);
        assert!(!score.is_obfuscated());
    }

    #[test]
    fn test_obfuscation_score_with_hits() {
        let d = PatternDetector::new();
        let data = vec![0xE8, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x00, 0xFF, 0xE0];
        let hits = d.detect(&data);
        let score = ObfuscationScore::compute(&hits, data.len());
        assert!(score.score >= 0.0);
    }

    #[test]
    fn test_obfuscation_score_capped_at_100() {
        // Create many hits to try to push score above 100.
        let mut hits = Vec::new();
        for i in 0..10000u64 {
            hits.push(PatternHit {
                pattern: AntiAnalysisPattern::JunkCode,
                address: i,
                offset: i as usize,
                size: 2,
                confidence: 60,
                description: "junk".into(),
                evidence_bytes: vec![0x87, 0xC0],
            });
        }
        let score = ObfuscationScore::compute(&hits, 100);
        assert!(score.score <= 100.0);
    }

    // -- CleaningStrategy ----------------------------------------------------

    #[test]
    fn test_cleaning_strategy_junk_automatable() {
        let s = CleaningStrategy::for_pattern(AntiAnalysisPattern::JunkCode);
        assert!(s.automatable);
        assert!(!s.requires_dynamic);
        assert!(!s.steps.is_empty());
    }

    #[test]
    fn test_cleaning_strategy_vm_not_automatable() {
        let s = CleaningStrategy::for_pattern(AntiAnalysisPattern::VmProtectedRegion);
        assert!(!s.automatable);
        assert!(s.requires_dynamic);
    }

    #[test]
    fn test_strategies_for_hits_deduplicates() {
        let hits = vec![
            PatternHit {
                pattern: AntiAnalysisPattern::JunkCode,
                address: 0,
                offset: 0,
                size: 2,
                confidence: 60,
                description: "j".into(),
                evidence_bytes: vec![],
            },
            PatternHit {
                pattern: AntiAnalysisPattern::JunkCode,
                address: 4,
                offset: 4,
                size: 2,
                confidence: 60,
                description: "j".into(),
                evidence_bytes: vec![],
            },
            PatternHit {
                pattern: AntiAnalysisPattern::OpaqueJump,
                address: 8,
                offset: 8,
                size: 2,
                confidence: 65,
                description: "o".into(),
                evidence_bytes: vec![],
            },
        ];
        let strategies = strategies_for_hits(&hits);
        assert_eq!(strategies.len(), 2);
    }
}
