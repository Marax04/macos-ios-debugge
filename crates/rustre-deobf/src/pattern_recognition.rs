//! `pattern_recognition` — pattern-based obfuscation classifier.
//!
//! [`ObfuscationRecognizer`] scans a binary and assigns heuristic scores for
//! each [`ObfuscationPattern`] variant.  Scores are normalised to `[0.0, 1.0]`
//! and can be used to decide which specialised deobfuscation passes to run.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::XorDecryptor;

/// Cast a `usize` to `f64` without precision-loss warning by saturating at
/// `u32::MAX` (which is well above any realistic byte-buffer length).
#[inline]
fn len_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

// ─────────────────────────────────────────────────────────────────────────────
// ObfuscationPattern
// ─────────────────────────────────────────────────────────────────────────────

/// High-level obfuscation technique classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObfuscationPattern {
    /// Semantically dead code inserted to confuse analysis.
    JunkCode,
    /// Code that can never execute (unreachable blocks, dead assignments).
    DeadCode,
    /// Control-flow flattening via a state-machine dispatcher.
    Flattening,
    /// Bytecode VM with custom instruction set (Themida, VMP-style).
    VirtualMachine,
    /// Mixed Boolean Arithmetic: complex arithmetic expressions.
    ArithmeticMba,
    /// Encrypted / obfuscated string constants.
    StringEncryption,
    /// Anti-debugging techniques (timing, PEB, API detection).
    AntiDebug,
    /// Compressed or encrypted payload region (packer stub).
    PackedCode,
}

impl ObfuscationPattern {
    /// Return a human-readable name for this pattern.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::JunkCode => "junk-code",
            Self::DeadCode => "dead-code",
            Self::Flattening => "control-flow-flattening",
            Self::VirtualMachine => "virtual-machine",
            Self::ArithmeticMba => "arithmetic-mba",
            Self::StringEncryption => "string-encryption",
            Self::AntiDebug => "anti-debug",
            Self::PackedCode => "packed-code",
        }
    }

    /// Return all pattern variants in a stable order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::JunkCode,
            Self::DeadCode,
            Self::Flattening,
            Self::VirtualMachine,
            Self::ArithmeticMba,
            Self::StringEncryption,
            Self::AntiDebug,
            Self::PackedCode,
        ]
    }
}

impl std::fmt::Display for ObfuscationPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternScore
// ─────────────────────────────────────────────────────────────────────────────

/// Scored recognition result for a single [`ObfuscationPattern`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatternScore {
    /// The obfuscation technique.
    pub pattern: ObfuscationPattern,
    /// Heuristic score in `[0.0, 1.0]` (higher → more likely).
    pub score: f64,
    /// Supporting evidence messages.
    pub evidence: Vec<String>,
}

impl PatternScore {
    /// Create a new score with no evidence yet.
    #[must_use]
    pub const fn new(pattern: ObfuscationPattern, score: f64) -> Self {
        Self {
            pattern,
            score: score.clamp(0.0, 1.0),
            evidence: Vec::new(),
        }
    }

    /// Attach an evidence string and return `self`.
    #[must_use]
    pub fn with_evidence(mut self, ev: impl Into<String>) -> Self {
        self.evidence.push(ev.into());
        self
    }

    /// Returns `true` if the score exceeds the given threshold.
    #[must_use]
    pub fn exceeds(&self, threshold: f64) -> bool {
        self.score >= threshold
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RecognitionResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of running [`ObfuscationRecognizer::recognize`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecognitionResult {
    /// Scores for every [`ObfuscationPattern`].
    pub scores: Vec<PatternScore>,
    /// Binary size analysed.
    pub binary_size: usize,
    /// Shannon entropy of the full binary.
    pub global_entropy: f64,
}

impl RecognitionResult {
    /// Return the score for a specific pattern, or 0.0 if not present.
    #[must_use]
    pub fn score_for(&self, pattern: ObfuscationPattern) -> f64 {
        self.scores
            .iter()
            .find(|s| s.pattern == pattern)
            .map_or(0.0, |s| s.score)
    }

    /// Return all patterns whose score exceeds `threshold`.
    #[must_use]
    pub fn patterns_above(&self, threshold: f64) -> Vec<ObfuscationPattern> {
        self.scores
            .iter()
            .filter(|s| s.exceeds(threshold))
            .map(|s| s.pattern)
            .collect()
    }

    /// Return the single highest-scored pattern, if any scores > 0.
    ///
    /// # Panics
    ///
    /// Panics if a score contains `NaN` (which should never occur for
    /// well-formed pattern scores).
    #[must_use]
    pub fn dominant_pattern(&self) -> Option<ObfuscationPattern> {
        self.scores
            .iter()
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap())
            .and_then(|s| if s.score > 0.0 { Some(s.pattern) } else { None })
    }

    /// Collect all patterns as a name→score map.
    #[must_use]
    pub fn score_map(&self) -> HashMap<&str, f64> {
        let mut map = HashMap::with_capacity(self.scores.len());
        for s in &self.scores {
            map.insert(s.pattern.name(), s.score);
        }
        map
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ObfuscationRecognizer
// ─────────────────────────────────────────────────────────────────────────────

/// Scores a binary for all known [`ObfuscationPattern`]s using byte-level
/// heuristics.
///
/// Every heuristic is self-contained and runs in O(n) over the input bytes,
/// making the recognizer suitable for large binaries.
#[derive(Debug, Clone, Default)]
pub struct ObfuscationRecognizer {
    /// If `true`, emit detailed evidence strings (slower).
    pub verbose: bool,
}

impl ObfuscationRecognizer {
    /// Create a new recognizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a recognizer with verbose evidence collection enabled.
    #[must_use]
    pub const fn verbose() -> Self {
        Self { verbose: true }
    }

    /// Run all heuristics on `data` and return a [`RecognitionResult`].
    #[must_use]
    pub fn recognize(&self, data: &[u8]) -> RecognitionResult {
        let global_entropy = XorDecryptor::entropy(data);
        let scores = vec![
            self.score_junk_code(data),
            self.score_dead_code(data),
            self.score_flattening(data),
            self.score_virtual_machine(data),
            self.score_arithmetic_mba(data),
            self.score_string_encryption(data),
            self.score_anti_debug(data),
            self.score_packed_code(data, global_entropy),
        ];
        RecognitionResult {
            scores,
            binary_size: data.len(),
            global_entropy,
        }
    }

    // ── Individual heuristics ─────────────────────────────────────────────────

    /// Junk-code heuristic: NOP density + identity instruction sequences.
    fn score_junk_code(&self, data: &[u8]) -> PatternScore {
        if data.is_empty() {
            return PatternScore::new(ObfuscationPattern::JunkCode, 0.0);
        }

        let nop_count: usize = data.iter().map(|&b| usize::from(b == 0x90)).sum();
        let nop_ratio = len_f64(nop_count) / len_f64(data.len());

        // Count identity instructions: xor reg,reg (31 C0, 33 C0) and
        // push/pop same reg (50..57 followed by 58..5F with matching low bits).
        let mut identity_count = 0usize;
        let mut i = 0;
        while i + 1 < data.len() {
            let is_xor_reg_reg = (data[i] == 0x31 || data[i] == 0x33)
                && (data[i + 1] & 0xC0) == 0xC0
                && ((data[i + 1] >> 3) & 0x07) == (data[i + 1] & 0x07);
            let is_push_pop = data[i] >= 0x50 && data[i] <= 0x57 && data[i + 1] == data[i] + 8;
            if is_xor_reg_reg || is_push_pop {
                identity_count += 1;
                i += 2;
            } else {
                i += 1;
            }
        }

        let identity_ratio = len_f64(identity_count) / (len_f64(data.len()) / 2.0).max(1.0);
        let score = nop_ratio.mul_add(2.5, identity_ratio * 2.0).min(1.0);

        let mut ps = PatternScore::new(ObfuscationPattern::JunkCode, score);
        if self.verbose {
            ps.evidence.push(format!("NOP ratio: {nop_ratio:.3}"));
            ps.evidence
                .push(format!("identity instruction ratio: {identity_ratio:.3}"));
        }
        ps
    }

    /// Dead-code heuristic: unconditional jumps over non-NOP bytes.
    fn score_dead_code(&self, data: &[u8]) -> PatternScore {
        if data.len() < 4 {
            return PatternScore::new(ObfuscationPattern::DeadCode, 0.0);
        }

        // Count JMP rel8 (EB xx) where the skipped bytes are not 0x90 (real code)
        let mut dead_jumps = 0usize;
        let mut i = 0;
        while i + 1 < data.len() {
            if data[i] == 0xEB {
                let rel = i8::from_ne_bytes([data[i + 1]]);
                if rel > 1 {
                    let skip_start = i + 2;
                    let rel_target = i64::try_from(i).unwrap_or(i64::MAX).saturating_add(2).saturating_add(i64::from(rel));
                    let skip_end = usize::try_from(rel_target).unwrap_or(0).min(data.len());
                    if skip_start < skip_end {
                        let non_nop = data[skip_start..skip_end]
                            .iter()
                            .any(|&b| b != 0x90 && b != 0x00);
                        if non_nop {
                            dead_jumps += 1;
                        }
                    }
                }
                i += 2;
            } else {
                i += 1;
            }
        }

        let density = (len_f64(dead_jumps) / (len_f64(data.len()) / 64.0).max(1.0)).min(1.0);
        let score = (density * 3.0).min(1.0);
        let mut ps = PatternScore::new(ObfuscationPattern::DeadCode, score);
        if self.verbose {
            ps.evidence.push(format!("dead-jump count: {dead_jumps}"));
        }
        ps
    }

    /// CFF heuristic: indirect jumps (FF E0, FF 24, FF 25) relative to total branches.
    fn score_flattening(&self, data: &[u8]) -> PatternScore {
        if data.len() < 4 {
            return PatternScore::new(ObfuscationPattern::Flattening, 0.0);
        }

        let mut indirect = 0usize;
        let mut direct_branches = 0usize;
        let mut i = 0;
        while i + 1 < data.len() {
            if data[i] == 0xFF && matches!(data[i + 1], 0xE0 | 0xE1 | 0xE2 | 0xE3 | 0x24 | 0x25) {
                indirect += 1;
                i += 2;
            } else if matches!(
                data[i],
                0xEB | 0xE9 | 0x74 | 0x75 | 0x7C | 0x7D | 0x7E | 0x7F
            ) {
                direct_branches += 1;
                i += 1;
            } else {
                i += 1;
            }
        }

        let ratio = if direct_branches + indirect == 0 {
            0.0
        } else {
            len_f64(indirect) / len_f64(direct_branches + indirect)
        };

        // Also check for consecutive cmp imm+jmp (state-machine pattern):
        // CMP EAX, imm32 (3D xx xx xx xx) followed by conditional jump
        let mut state_cmp = 0usize;
        i = 0;
        while i + 5 < data.len() {
            if data[i] == 0x3D && matches!(data[i + 5], 0x74 | 0x75 | 0x7C | 0x7D) {
                state_cmp += 1;
            }
            i += 1;
        }
        let state_density = (len_f64(state_cmp) / (len_f64(data.len()) / 32.0).max(1.0)).min(1.0);

        let score = (ratio * 0.6 + state_density * 0.4).min(1.0);
        let mut ps = PatternScore::new(ObfuscationPattern::Flattening, score);
        if self.verbose {
            ps.evidence.push(format!("indirect-jump ratio: {ratio:.3}"));
            ps.evidence
                .push(format!("state-machine cmp density: {state_density:.3}"));
        }
        ps
    }

    /// VM heuristic: repeated byte-dispatch patterns (MOVZX+indirect-jmp loops).
    fn score_virtual_machine(&self, data: &[u8]) -> PatternScore {
        if data.len() < 8 {
            return PatternScore::new(ObfuscationPattern::VirtualMachine, 0.0);
        }

        // Typical VM dispatcher: MOVZX (0F B6 or 0F B7) + indirect JMP (FF E0/E3)
        let mut movzx_indirect = 0usize;
        let mut i = 0;
        while i + 3 < data.len() {
            if data[i] == 0x0F && matches!(data[i + 1], 0xB6 | 0xB7) && i + 4 < data.len() {
                // Look for FF Ex nearby (within 8 bytes)
                let window_end = (i + 12).min(data.len().saturating_sub(1));
                let has_indirect = data[i + 2..window_end]
                    .windows(2)
                    .any(|w| w[0] == 0xFF && matches!(w[1], 0xE0..=0xE3));
                if has_indirect {
                    movzx_indirect += 1;
                }
            }
            i += 1;
        }

        let density = (len_f64(movzx_indirect) / (len_f64(data.len()) / 128.0).max(1.0)).min(1.0);
        let score = (density * 4.0).min(1.0);
        let mut ps = PatternScore::new(ObfuscationPattern::VirtualMachine, score);
        if self.verbose {
            ps.evidence
                .push(format!("vm-dispatch patterns: {movzx_indirect}"));
        }
        ps
    }

    /// MBA heuristic: dense arithmetic (many ADD/SUB/XOR/AND/OR/NOT in sequence).
    fn score_arithmetic_mba(&self, data: &[u8]) -> PatternScore {
        if data.is_empty() {
            return PatternScore::new(ObfuscationPattern::ArithmeticMba, 0.0);
        }

        // Count arith opcodes (first byte category):
        // ADD: 00-05; OR: 08-0D; AND: 20-25; SUB: 28-2D; XOR: 30-35
        // NOT: F7 /2; NEG: F7 /3; IMUL: 0F AF; ROL/ROR: D1,D3 /0,/1
        let arith_count = data.iter().filter(|&&b| {
            matches!(b, 0x00..=0x05 | 0x08..=0x0D | 0x20..=0x25 | 0x28..=0x2D | 0x30..=0x35)
        }).count();

        let arith_ratio = len_f64(arith_count) / len_f64(data.len());

        // MBA also tends to have very few memory-touching instructions
        let mem_count = data
            .iter()
            .filter(|&&b| matches!(b, 0xA0..=0xA5 | 0xC6 | 0xC7))
            .count();
        let mem_ratio = len_f64(mem_count) / len_f64(data.len());

        // High arith + low mem + moderate entropy → MBA
        let entropy = XorDecryptor::entropy(data);
        let score = if arith_ratio > 0.15 && mem_ratio < 0.05 && entropy > 3.0 {
            arith_ratio.mul_add(2.0, (1.0 - mem_ratio) * 0.3).min(1.0)
        } else {
            (arith_ratio * 0.8).min(1.0)
        };

        let mut ps = PatternScore::new(ObfuscationPattern::ArithmeticMba, score);
        if self.verbose {
            ps.evidence
                .push(format!("arith-opcode ratio: {arith_ratio:.3}"));
            ps.evidence
                .push(format!("mem-opcode ratio: {mem_ratio:.3}"));
        }
        ps
    }

    /// String-encryption heuristic: short sequences with high entropy + XOR loops.
    fn score_string_encryption(&self, data: &[u8]) -> PatternScore {
        if data.len() < 8 {
            return PatternScore::new(ObfuscationPattern::StringEncryption, 0.0);
        }

        // Detect XOR-loop pattern: LOOP (E2) / LOOPNE (E0) with XOR byte register
        // A common pattern: XOR [mem+reg], key; INC/DEC reg; LOOP
        let mut xor_loops = 0usize;
        for i in 0..data.len().saturating_sub(3) {
            if data[i] == 0x30 || data[i] == 0x32 {
                // XOR byte instruction
                let has_loop = data[i..data.len().min(i + 16)]
                    .iter()
                    .any(|&b| matches!(b, 0xE2 | 0xE0 | 0xE1 | 0x49 | 0x41)); // LOOP / DEC / INC
                if has_loop {
                    xor_loops += 1;
                }
            }
        }

        // Also: count 4-byte aligned blocks with high entropy (encrypted string tables)
        let mut high_ent_blocks = 0usize;
        for chunk in data.chunks(64) {
            if XorDecryptor::entropy(chunk) > 6.5 && chunk.len() >= 32 {
                high_ent_blocks += 1;
            }
        }

        let loop_density = (len_f64(xor_loops) / (len_f64(data.len()) / 64.0).max(1.0)).min(1.0);
        let block_density =
            (len_f64(high_ent_blocks) / (len_f64(data.len()) / 256.0).max(1.0)).min(1.0);
        let score = (loop_density * 0.5 + block_density * 0.5).min(1.0);

        let mut ps = PatternScore::new(ObfuscationPattern::StringEncryption, score);
        if self.verbose {
            ps.evidence.push(format!("xor-loop patterns: {xor_loops}"));
            ps.evidence
                .push(format!("high-entropy 64-byte blocks: {high_ent_blocks}"));
        }
        ps
    }

    /// Anti-debug heuristic: known API name strings and timing instruction patterns.
    fn score_anti_debug(&self, data: &[u8]) -> PatternScore {
        const ANTIDEBUG_MARKERS: &[&[u8]] = &[
            b"IsDebuggerPresent",
            b"CheckRemoteDebuggerPresent",
            b"NtQueryInformationProcess",
            b"OutputDebugString",
            b"FindWindow",
            b"ZwSetInformationThread",
            b"GetTickCount",
            b"QueryPerformanceCounter",
            b"CloseHandle",
        ];

        let mut found_strings = 0usize;
        for marker in ANTIDEBUG_MARKERS {
            if data.windows(marker.len()).any(|w| w == *marker) {
                found_strings += 1;
            }
        }

        // CPUID (0F A2) often used for timing/fingerprinting
        let cpuid_count = data
            .windows(2)
            .filter(|w| w[0] == 0x0F && w[1] == 0xA2)
            .count();
        // RDTSC (0F 31)
        let rdtsc_count = data
            .windows(2)
            .filter(|w| w[0] == 0x0F && w[1] == 0x31)
            .count();

        let string_score = (len_f64(found_strings) * 0.15).min(0.6);
        let timing_score = (len_f64(cpuid_count + rdtsc_count) * 0.1).min(0.4);
        let score = (string_score + timing_score).min(1.0);

        let mut ps = PatternScore::new(ObfuscationPattern::AntiDebug, score);
        if self.verbose {
            ps.evidence
                .push(format!("anti-debug strings found: {found_strings}"));
            ps.evidence
                .push(format!("CPUID instructions: {cpuid_count}"));
            ps.evidence
                .push(format!("RDTSC instructions: {rdtsc_count}"));
        }
        ps
    }

    /// Packed-code heuristic: global entropy above 7.0 + UPX/PE markers.
    fn score_packed_code(&self, data: &[u8], entropy: f64) -> PatternScore {
        // High global entropy is the primary indicator.
        let entropy_score = if entropy > 7.5 {
            1.0
        } else if entropy > 7.0 {
            0.8
        } else if entropy > 6.5 {
            0.5
        } else {
            0.0
        };

        // UPX signature
        let has_upx = data
            .windows(4)
            .any(|w| w == b"UPX0" || w == b"UPX1" || w == b"UPX!");
        // MPRESS signature
        let has_mpress = data.windows(6).any(|w| w == b"MPRESS");
        // PE magic: `MZ` header present
        let has_mz = data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A;

        let packer_bonus = if has_upx || has_mpress { 0.3 } else { 0.0 };
        let pe_bonus = if has_mz && entropy_score > 0.0 {
            0.1
        } else {
            0.0
        };

        let score = f64::min(entropy_score + packer_bonus + pe_bonus, 1.0);
        let mut ps = PatternScore::new(ObfuscationPattern::PackedCode, score);
        if self.verbose {
            ps.evidence.push(format!("global entropy: {entropy:.3}"));
            if has_upx {
                ps.evidence.push("UPX signature detected".to_owned());
            }
            if has_mpress {
                ps.evidence.push("MPRESS signature detected".to_owned());
            }
        }
        ps
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nop_sled_scores_junk_code() {
        let data = vec![0x90u8; 256];
        let rec = ObfuscationRecognizer::new();
        let result = rec.recognize(&data);
        assert!(
            result.score_for(ObfuscationPattern::JunkCode) > 0.5,
            "NOP sled should score high for JunkCode"
        );
    }

    #[test]
    fn test_high_entropy_scores_packed() {
        // Pseudo-random-looking bytes → high entropy
        let data: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let rec = ObfuscationRecognizer::new();
        let result = rec.recognize(&data);
        assert!(result.score_for(ObfuscationPattern::PackedCode) > 0.0);
    }

    #[test]
    fn test_anti_debug_string_detection() {
        let mut data = vec![0u8; 32];
        data.extend_from_slice(b"IsDebuggerPresent");
        data.extend_from_slice(b"CheckRemoteDebuggerPresent");
        let rec = ObfuscationRecognizer::verbose();
        let result = rec.recognize(&data);
        assert!(result.score_for(ObfuscationPattern::AntiDebug) > 0.0);
    }

    #[test]
    fn test_patterns_above_threshold() {
        let data = vec![0x90u8; 512]; // heavy NOP sled
        let rec = ObfuscationRecognizer::new();
        let result = rec.recognize(&data);
        let above = result.patterns_above(0.5);
        assert!(above.contains(&ObfuscationPattern::JunkCode));
    }

    #[test]
    fn test_dominant_pattern() {
        let data = vec![0x90u8; 1024];
        let rec = ObfuscationRecognizer::new();
        let result = rec.recognize(&data);
        assert_eq!(
            result.dominant_pattern(),
            Some(ObfuscationPattern::JunkCode)
        );
    }

    #[test]
    fn test_empty_binary() {
        let rec = ObfuscationRecognizer::new();
        let result = rec.recognize(&[]);
        for s in &result.scores {
            assert_eq!(s.score, 0.0, "empty binary should produce zero scores");
        }
    }

    #[test]
    fn test_all_patterns_scored() {
        let data = vec![0xABu8; 256];
        let rec = ObfuscationRecognizer::new();
        let result = rec.recognize(&data);
        for p in ObfuscationPattern::all() {
            assert!(
                result.scores.iter().any(|s| s.pattern == *p),
                "missing pattern score for {}",
                p.name()
            );
        }
    }

    #[test]
    fn test_score_map_keys() {
        let data = vec![0u8; 64];
        let rec = ObfuscationRecognizer::new();
        let result = rec.recognize(&data);
        let map = result.score_map();
        assert!(map.contains_key("junk-code"));
        assert!(map.contains_key("packed-code"));
    }
}
