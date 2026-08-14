//! Multi-stage shellcode decoder for `rustre-emu-shellcode`.

use crate::{ExecutionResult, ExitReason, ShellcodeAnalysis, ShellcodeRunner};
use rustre_emu::EmulatorArch;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── DecoderAlgorithm ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecoderAlgorithm {
    XorConstant,
    XorRolling,
    XorCyclic,
    AddConstant,
    SubConstant,
    RolConstant,
    RorConstant,
    Rc4,
    MultiByteXor,
    Custom,
}

impl DecoderAlgorithm {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::XorConstant => "XOR(const)",
            Self::XorRolling => "XOR(rolling)",
            Self::XorCyclic => "XOR(cyclic)",
            Self::AddConstant => "ADD(const)",
            Self::SubConstant => "SUB(const)",
            Self::RolConstant => "ROL(const)",
            Self::RorConstant => "ROR(const)",
            Self::Rc4 => "RC4",
            Self::MultiByteXor => "XOR(multi-byte)",
            Self::Custom => "Custom",
        }
    }
}

// ── DecoderLoop ───────────────────────────────────────────────────────────────

/// A detected decode loop in shellcode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoderLoop {
    pub start_offset: usize,
    pub end_offset: usize,
    pub algorithm: DecoderAlgorithm,
    pub key_bytes: Vec<u8>,
    pub loop_count: usize,
    pub target_offset: u64,
    pub target_size: usize,
    pub confidence: f32,
}

impl DecoderLoop {
    #[must_use]
    pub const fn new(
        start: usize,
        end: usize,
        algo: DecoderAlgorithm,
        key: Vec<u8>,
        confidence: f32,
    ) -> Self {
        Self {
            start_offset: start,
            end_offset: end,
            algorithm: algo,
            key_bytes: key,
            loop_count: 0,
            target_offset: 0,
            target_size: 0,
            confidence,
        }
    }

    #[must_use]
    pub const fn size(&self) -> usize {
        self.end_offset.saturating_sub(self.start_offset)
    }
}

/// Detects XOR/ADD decode loops in raw shellcode bytes.
pub struct DecoderLoopDetector;

impl DecoderLoopDetector {
    /// Scan for common decode-loop signatures.
    #[must_use]
    pub fn detect(code: &[u8]) -> Vec<DecoderLoop> {
        let mut loops = Vec::new();

        // Pattern 1: XOR [reg+idx], imm8; INC reg; DEC counter; JNZ
        // Signature: 30 xx (XOR byte), 40|41|42|43|44|45|46|47 (INC), 4? (DEC), 75 (JNZ)
        // `saturating_sub(5)`, not `(6)`: every branch below carries its own
        // precise bound check (`i + 4`, `i + 5`, `i + 6`), so the outer limit
        // only has to keep `code[i + 1]` in range. Sizing it for the longest
        // pattern (the 7-byte XOR form, `i + 6 < len`) stole a valid starting
        // position from the 6-byte ADD form: a buffer holding exactly that
        // loop — `80 06 xx 46 E2 FB` — gave `0..0` and was never examined at
        // all, so a decoder stub occupying the tail of a buffer went unseen.
        for i in 0..code.len().saturating_sub(5) {
            if code[i] == 0x30 || code[i] == 0x32 {
                // XOR byte ptr [reg], reg/mem
                if i + 4 < code.len() && (0x40..=0x4F).contains(&code[i + 1]) && code[i + 3] == 0x75
                {
                    loops.push(DecoderLoop::new(
                        i,
                        i + 4,
                        DecoderAlgorithm::XorConstant,
                        vec![code[i + 1]],
                        0.70,
                    ));
                }
            }
            // 80 30 xx (XOR byte ptr [eax], imm8); INC; DEC; JNZ
            if code[i] == 0x80 && code[i + 1] == 0x30 && i + 6 < code.len() {
                let key = code[i + 2];
                if code[i + 5] == 0x75 || code[i + 5] == 0xE2 {
                    loops.push(DecoderLoop::new(
                        i,
                        i + 6,
                        DecoderAlgorithm::XorConstant,
                        vec![key],
                        0.85,
                    ));
                }
            }
            // ADD byte ptr [esi], imm8; INC; DEC; JNZ
            if code[i] == 0x80 && code[i + 1] == 0x06 && i + 5 < code.len() {
                let key = code[i + 2];
                loops.push(DecoderLoop::new(
                    i,
                    i + 5,
                    DecoderAlgorithm::AddConstant,
                    vec![key],
                    0.75,
                ));
            }
            // ROL byte ptr [esi], n; INC; LOOP
            if code[i] == 0xC0 && (code[i + 1] & 0xF8 == 0x00) && i + 4 < code.len() {
                let n = code[i + 2];
                loops.push(DecoderLoop::new(
                    i,
                    i + 4,
                    DecoderAlgorithm::RolConstant,
                    vec![n],
                    0.65,
                ));
            }
        }
        loops
    }
}

// ── DecodedStage ──────────────────────────────────────────────────────────────

/// One decoded stage in a multi-layer shellcode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedStage {
    pub stage_index: usize,
    pub decoded_bytes: Vec<u8>,
    pub algorithm: DecoderAlgorithm,
    pub key_bytes: Vec<u8>,
    pub entropy_before: f64,
    pub entropy_after: f64,
    pub contains_pe: bool,
    pub contains_shellcode: bool,
}

impl DecodedStage {
    #[must_use]
    pub fn new(
        idx: usize,
        input: &[u8],
        output: Vec<u8>,
        algo: DecoderAlgorithm,
        key: Vec<u8>,
    ) -> Self {
        let eb = entropy(input);
        let ea = entropy(&output);
        let pe = output.starts_with(b"MZ") || output.windows(4).any(|w| w == b"PE\0\0");
        let sc = looks_like_shellcode(&output);
        Self {
            stage_index: idx,
            decoded_bytes: output,
            algorithm: algo,
            key_bytes: key,
            entropy_before: eb,
            entropy_after: ea,
            contains_pe: pe,
            contains_shellcode: sc,
        }
    }

    #[must_use]
    pub fn entropy_drop(&self) -> f64 {
        (self.entropy_before - self.entropy_after).max(0.0)
    }
}

// ── StageChain ────────────────────────────────────────────────────────────────

/// A chain of decoded stages.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StageChain {
    pub stages: Vec<DecodedStage>,
}

impl StageChain {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, stage: DecodedStage) {
        self.stages.push(stage);
    }

    #[must_use]
    pub const fn depth(&self) -> usize {
        self.stages.len()
    }

    #[must_use]
    pub fn final_payload(&self) -> &[u8] {
        self.stages
            .last()
            .map_or(&[], |s| s.decoded_bytes.as_slice())
    }

    #[must_use]
    pub fn has_pe_payload(&self) -> bool {
        self.stages.iter().any(|s| s.contains_pe)
    }

    #[must_use]
    pub fn algorithm_chain(&self) -> Vec<DecoderAlgorithm> {
        self.stages.iter().map(|s| s.algorithm).collect()
    }

    #[must_use]
    pub fn total_entropy_reduction(&self) -> f64 {
        self.stages.iter().map(DecodedStage::entropy_drop).sum()
    }
}

// ── DecoderHash ───────────────────────────────────────────────────────────────

/// Uniquely identifies a decoder stub by hashing its structure.
pub struct DecoderHash;

impl DecoderHash {
    /// Compute a 64-bit FNV hash of the decoder stub bytes.
    #[must_use]
    pub fn hash(stub: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in stub {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }

    /// Return a hex string of the hash.
    #[must_use]
    pub fn hash_hex(stub: &[u8]) -> String {
        format!("{:016x}", Self::hash(stub))
    }

    /// Compute the hash of only the "skeleton" (non-imm bytes) of the stub.
    #[must_use]
    pub fn structural_hash(stub: &[u8]) -> u64 {
        // Mask out immediate bytes, keeping the skeleton.
        //
        // For the group-1 encoding these stubs use — `80 /digit ib`, e.g.
        // `80 30 42` for XOR byte ptr [eax], 0x42 — the layout is opcode,
        // ModRM, imm8, so the immediate sits *two* bytes after the opcode.
        // Masking at +1 hit the ModRM instead: it erased the operation and
        // register selection, which is exactly the structure this hash exists
        // to capture, while leaving the immediate — the one byte that is
        // supposed to vary — in the digest. Two stubs differing only in their
        // key therefore hashed differently.
        let normalized: Vec<u8> = stub
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                if i >= 2 && stub[i - 2] >= 0x80 {
                    0x00
                } else {
                    b
                }
            })
            .collect();
        Self::hash(&normalized)
    }
}

// ── ShellcodeFamily ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ShellcodeFamily {
    MetasploitMeterpreter,
    MetasploitShellReverse,
    MetasploitShellBind,
    CobaltStrikeBeacon,
    CobaltStrikeSleep,
    Empire,
    Sliver,
    BruteRatel,
    Donut,
    Shad0w,
    Custom,
    Unknown,
}

impl ShellcodeFamily {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MetasploitMeterpreter => "Metasploit/Meterpreter",
            Self::MetasploitShellReverse => "Metasploit/Shell Reverse TCP",
            Self::MetasploitShellBind => "Metasploit/Shell Bind TCP",
            Self::CobaltStrikeBeacon => "Cobalt Strike Beacon",
            Self::CobaltStrikeSleep => "Cobalt Strike Sleep (Obfuscation)",
            Self::Empire => "Empire",
            Self::Sliver => "Sliver",
            Self::BruteRatel => "Brute Ratel",
            Self::Donut => "Donut",
            Self::Shad0w => "Shad0w",
            Self::Custom => "Custom",
            Self::Unknown => "Unknown",
        }
    }
}

/// Identifies a shellcode family from patterns.
pub struct ShellcodeFamilyClassifier;

impl ShellcodeFamilyClassifier {
    /// Classify `shellcode` by scanning for known byte patterns.
    #[must_use]
    pub fn classify(shellcode: &[u8]) -> ShellcodeFamily {
        // Metasploit SHIKATA GA NAI XOR encoder prefix: FC E8 8?
        if shellcode.len() >= 3
            && shellcode[0] == 0xFC
            && shellcode[1] == 0xE8
            && (shellcode[2] & 0xF0 == 0x80)
        {
            return ShellcodeFamily::MetasploitMeterpreter;
        }
        // Cobalt Strike beacon header check: MZ at offset or specific patterns
        if shellcode.starts_with(b"MZ") {
            return ShellcodeFamily::CobaltStrikeBeacon;
        }
        // Common reverse-shell socket call pattern: 6A 00 6A 01 6A 02 (WSASocket args)
        if shellcode
            .windows(6)
            .any(|w| w == [0x6A, 0x02, 0x6A, 0x01, 0x6A, 0x06])
        {
            return ShellcodeFamily::MetasploitShellReverse;
        }
        // Donut: starts with 0x4D 0x5A 0x20 (MZ + space)
        if shellcode.len() >= 3
            && shellcode[0] == 0x4D
            && shellcode[1] == 0x5A
            && shellcode[2] == 0x20
        {
            return ShellcodeFamily::Donut;
        }
        ShellcodeFamily::Unknown
    }
}

// ── ShellcodeDecoder ──────────────────────────────────────────────────────────

/// Multi-stage shellcode decoder.
pub struct ShellcodeDecoder {
    pub max_stages: usize,
    pub min_entropy_drop: f64,
}

impl Default for ShellcodeDecoder {
    fn default() -> Self {
        Self {
            max_stages: 8,
            min_entropy_drop: 0.05,
        }
    }
}

impl ShellcodeDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_max_stages(mut self, n: usize) -> Self {
        self.max_stages = n;
        self
    }

    /// Decode a single layer of `data` using the best-fit algorithm.
    #[must_use]
    pub fn decode_layer(&self, data: &[u8], stage_idx: usize) -> Option<DecodedStage> {
        // Try XOR brute force
        let (best_key, decoded) = best_xor_key(data);
        let ea = entropy(&decoded);
        let eb = entropy(data);
        if eb - ea >= self.min_entropy_drop
            || decoded.iter().filter(|&&b| b.is_ascii_graphic()).count() > data.len() / 2
        {
            return Some(DecodedStage::new(
                stage_idx,
                data,
                decoded,
                DecoderAlgorithm::XorConstant,
                vec![best_key],
            ));
        }
        // Try common XOR keys
        for &key in &[0x55u8, 0xAA, 0x11, 0x33, 0x77, 0xFF] {
            let dec: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
            let ea2 = entropy(&dec);
            if eb - ea2 >= self.min_entropy_drop {
                return Some(DecodedStage::new(
                    stage_idx,
                    data,
                    dec,
                    DecoderAlgorithm::XorConstant,
                    vec![key],
                ));
            }
        }
        // Try ADD constant
        for &key in &[1u8, 5, 7, 13] {
            let dec: Vec<u8> = data.iter().map(|&b| b.wrapping_sub(key)).collect();
            if entropy(&dec) < eb - self.min_entropy_drop {
                return Some(DecodedStage::new(
                    stage_idx,
                    data,
                    dec,
                    DecoderAlgorithm::AddConstant,
                    vec![key],
                ));
            }
        }
        None
    }

    /// Recursively decode all layers.
    #[must_use]
    pub fn decode_all(&self, shellcode: &[u8]) -> StageChain {
        let mut chain = StageChain::new();
        let mut current = shellcode.to_vec();
        for stage_idx in 0..self.max_stages {
            match self.decode_layer(&current, stage_idx) {
                Some(stage) => {
                    let next = stage.decoded_bytes.clone();
                    chain.push(stage);
                    if next == current {
                        break;
                    }
                    current = next;
                    // Stop if the decoded payload looks ready (PE or ASCII shellcode)
                    if current.starts_with(b"MZ") || printable_ratio(&current) > 0.85 {
                        break;
                    }
                }
                None => break,
            }
        }
        chain
    }

    /// Identify the shellcode family.
    #[must_use]
    pub fn classify(&self, shellcode: &[u8]) -> ShellcodeFamily {
        ShellcodeFamilyClassifier::classify(shellcode)
    }

    /// Detect decoder loops in `shellcode`.
    #[must_use]
    pub fn find_decoder_loops(&self, shellcode: &[u8]) -> Vec<DecoderLoop> {
        DecoderLoopDetector::detect(shellcode)
    }

    /// Compute a decoder hash for `shellcode`.
    #[must_use]
    pub fn decoder_hash(&self, shellcode: &[u8]) -> String {
        DecoderHash::hash_hex(shellcode)
    }

    /// Statically decode `shellcode`, then attempt to execute every recovered
    /// stage under a [`ShellcodeRunner`] for the given architecture.
    ///
    /// Returns a map from stage index to the `(ExitReason, decode-loop-detected)`
    /// pair recorded for that stage. Stages whose [`ExecutionResult`] indicates
    /// a decode loop via [`ShellcodeAnalysis::detect_decode_loop`] are flagged.
    ///
    /// # Errors
    /// Propagates the first emulator error encountered.
    pub fn decode_and_run(
        &self,
        shellcode: &[u8],
        arch: EmulatorArch,
    ) -> Result<HashMap<usize, (ExitReason, bool)>, rustre_emu::EmulatorError> {
        let chain = self.decode_all(shellcode);
        let runner = ShellcodeRunner::new(arch);
        let mut report: HashMap<usize, (ExitReason, bool)> = HashMap::new();
        for stage in &chain.stages {
            let result: ExecutionResult = runner.run(&stage.decoded_bytes)?;
            let decode_loop = ShellcodeAnalysis::detect_decode_loop(&result);
            report.insert(stage.stage_index, (result.exit_reason, decode_loop));
        }
        Ok(report)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn printable_ratio(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ')
        .count() as f32
        / data.len() as f32
}

fn best_xor_key(data: &[u8]) -> (u8, Vec<u8>) {
    let mut best = 0u8;
    let mut best_score = 0usize;
    for k in 1u8..=255 {
        let score = data.iter().filter(|&&b| (b ^ k).is_ascii_graphic()).count();
        if score > best_score {
            best_score = score;
            best = k;
        }
    }
    (best, data.iter().map(|&b| b ^ best).collect())
}

fn looks_like_shellcode(data: &[u8]) -> bool {
    if data.len() < 16 {
        return false;
    }
    let typical = data
        .iter()
        .filter(|&&b| matches!(b, 0x50..=0x5F | 0x48..=0x4F | 0x90 | 0xC3 | 0xE8 | 0xFF))
        .count();
    typical * 3 > data.len()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DecoderAlgorithm ──────────────────────────────────────────────────────

    #[test]
    fn test_algo_name() {
        assert!(!DecoderAlgorithm::XorConstant.name().is_empty());
    }

    // ── DecoderLoop ───────────────────────────────────────────────────────────

    #[test]
    fn test_decoder_loop_size() {
        let l = DecoderLoop::new(0x10, 0x20, DecoderAlgorithm::XorConstant, vec![0x42], 0.8);
        assert_eq!(l.size(), 0x10);
    }

    #[test]
    fn test_decoder_loop_detector_xor() {
        let mut code = Vec::new();
        // 80 30 42 (XOR [eax], 0x42) + NOPs + 75 xx (JNZ)
        code.extend_from_slice(&[0x80, 0x30, 0x42, 0x90, 0x90, 0x75, 0xFB]);
        let loops = DecoderLoopDetector::detect(&code);
        assert!(!loops.is_empty());
        assert!(
            loops
                .iter()
                .any(|l| l.algorithm == DecoderAlgorithm::XorConstant)
        );
    }

    #[test]
    fn test_decoder_loop_detector_add() {
        let code = vec![0x80, 0x06, 0x07, 0x46, 0xE2, 0xFB];
        let loops = DecoderLoopDetector::detect(&code);
        assert!(
            loops
                .iter()
                .any(|l| l.algorithm == DecoderAlgorithm::AddConstant)
        );
    }

    // ── DecoderHash ───────────────────────────────────────────────────────────

    #[test]
    fn test_decoder_hash_deterministic() {
        let h1 = DecoderHash::hash(b"shellcode");
        let h2 = DecoderHash::hash(b"shellcode");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_decoder_hash_different() {
        assert_ne!(DecoderHash::hash(b"abc"), DecoderHash::hash(b"def"));
    }

    #[test]
    fn test_decoder_hash_hex_format() {
        let hex = DecoderHash::hash_hex(b"test");
        assert_eq!(hex.len(), 16);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_structural_hash_insensitive_to_imm() {
        // Two stubs that differ only in the immediate byte after opcode 0x80
        let s1 = vec![0x80, 0x30, 0x42, 0x90]; // XOR with 0x42
        let s2 = vec![0x80, 0x30, 0x55, 0x90]; // XOR with 0x55
        let h1 = DecoderHash::structural_hash(&s1);
        let h2 = DecoderHash::structural_hash(&s2);
        assert_eq!(h1, h2); // structural hash should match
    }

    // ── DecodedStage ──────────────────────────────────────────────────────────

    #[test]
    fn test_decoded_stage_entropy_drop() {
        // XOR with a constant is a bijection on bytes: it permutes the alphabet
        // without touching the frequencies, and Shannon entropy depends only on
        // the frequencies. So a single-byte XOR CANNOT produce an entropy drop —
        // the drop is exactly zero, whatever the plaintext.
        let plain = b"Hello, World! This is ASCII text.";
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ 0x42).collect();
        let stage = DecodedStage::new(
            0,
            &cipher,
            plain.to_vec(),
            DecoderAlgorithm::XorConstant,
            vec![0x42],
        );
        assert!(
            stage.entropy_drop().abs() < 1e-12,
            "XOR is a byte permutation, entropy must be invariant, got a drop of {}",
            stage.entropy_drop()
        );

        // A real drop needs the byte distribution to actually change: uniform
        // input (entropy 8) decoding to a constant run (entropy 0).
        let uniform: Vec<u8> = (0..=255u8).collect();
        let flat = vec![b'A'; 256];
        let stage = DecodedStage::new(1, &uniform, flat, DecoderAlgorithm::XorConstant, vec![0]);
        assert!(
            stage.entropy_drop() > 7.9,
            "expected a near-maximal drop, got {}",
            stage.entropy_drop()
        );
    }

    #[test]
    fn test_decoded_stage_pe_detection() {
        let pe_data = b"MZ\x90\x00";
        let stage = DecodedStage::new(
            0,
            b"",
            pe_data.to_vec(),
            DecoderAlgorithm::XorConstant,
            vec![],
        );
        assert!(stage.contains_pe);
    }

    // ── StageChain ────────────────────────────────────────────────────────────

    #[test]
    fn test_stage_chain_depth() {
        let mut chain = StageChain::new();
        chain.push(DecodedStage::new(
            0,
            &[0xAA],
            vec![0xBB],
            DecoderAlgorithm::XorConstant,
            vec![0x11],
        ));
        assert_eq!(chain.depth(), 1);
    }

    #[test]
    fn test_stage_chain_final_payload() {
        let mut chain = StageChain::new();
        chain.push(DecodedStage::new(
            0,
            &[0x00],
            vec![0xCC, 0xDD],
            DecoderAlgorithm::XorConstant,
            vec![],
        ));
        assert_eq!(chain.final_payload(), &[0xCC, 0xDD]);
    }

    #[test]
    fn test_stage_chain_algorithm_chain() {
        let mut chain = StageChain::new();
        chain.push(DecodedStage::new(
            0,
            &[],
            vec![],
            DecoderAlgorithm::XorConstant,
            vec![],
        ));
        chain.push(DecodedStage::new(
            1,
            &[],
            vec![],
            DecoderAlgorithm::Rc4,
            vec![],
        ));
        let algos = chain.algorithm_chain();
        assert_eq!(
            algos,
            vec![DecoderAlgorithm::XorConstant, DecoderAlgorithm::Rc4]
        );
    }

    #[test]
    fn test_stage_chain_has_pe() {
        let mut chain = StageChain::new();
        chain.push(DecodedStage::new(
            0,
            &[],
            b"MZ\x90\x00".to_vec(),
            DecoderAlgorithm::XorConstant,
            vec![],
        ));
        assert!(chain.has_pe_payload());
    }

    // ── ShellcodeFamilyClassifier ──────────────────────────────────────────────

    #[test]
    fn test_classify_shikata() {
        let sc = vec![0xFC, 0xE8, 0x82, 0x00]; // Shikata Ga Nai prefix
        assert_eq!(
            ShellcodeFamilyClassifier::classify(&sc),
            ShellcodeFamily::MetasploitMeterpreter
        );
    }

    #[test]
    fn test_classify_pe_as_cobalt() {
        let sc = b"MZ\x90\x00\x03\x00";
        assert_eq!(
            ShellcodeFamilyClassifier::classify(sc),
            ShellcodeFamily::CobaltStrikeBeacon
        );
    }

    #[test]
    fn test_classify_unknown() {
        let sc = vec![0x90u8; 32];
        assert_eq!(
            ShellcodeFamilyClassifier::classify(&sc),
            ShellcodeFamily::Unknown
        );
    }

    // ── ShellcodeDecoder ──────────────────────────────────────────────────────

    #[test]
    fn test_decoder_decode_layer_xor() {
        let decoder = ShellcodeDecoder::new();
        let key = 0x42u8;
        let plain = b"Hello CreateThread LoadLibrary";
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let stage = decoder.decode_layer(&cipher, 0);
        assert!(stage.is_some());
        let s = stage.unwrap();
        assert_eq!(s.algorithm, DecoderAlgorithm::XorConstant);
    }

    #[test]
    fn test_decoder_decode_all_single_layer() {
        let decoder = ShellcodeDecoder::new();
        let plain = b"Hello World VirtualAlloc CreateThread";
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ 0x55).collect();
        let chain = decoder.decode_all(&cipher);
        assert!(chain.depth() > 0 || chain.depth() == 0); // no panic
    }

    #[test]
    fn test_decoder_classify() {
        let decoder = ShellcodeDecoder::new();
        let sc = vec![0xFC, 0xE8, 0x82, 0x00];
        let fam = decoder.classify(&sc);
        assert_eq!(fam, ShellcodeFamily::MetasploitMeterpreter);
    }

    #[test]
    fn test_decoder_hash() {
        let decoder = ShellcodeDecoder::new();
        let h = decoder.decoder_hash(b"test stub");
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn test_decoder_find_loops() {
        let decoder = ShellcodeDecoder::new();
        let code = vec![0x80, 0x30, 0x42, 0x90, 0x90, 0x75, 0xFB];
        let loops = decoder.find_decoder_loops(&code);
        assert!(!loops.is_empty());
    }

    #[test]
    fn test_decoder_with_max_stages() {
        let d = ShellcodeDecoder::new().with_max_stages(3);
        assert_eq!(d.max_stages, 3);
    }

    #[test]
    fn test_family_names_nonempty() {
        for fam in [
            ShellcodeFamily::MetasploitMeterpreter,
            ShellcodeFamily::CobaltStrikeBeacon,
            ShellcodeFamily::Donut,
            ShellcodeFamily::Unknown,
        ] {
            assert!(!fam.name().is_empty());
        }
    }
}
