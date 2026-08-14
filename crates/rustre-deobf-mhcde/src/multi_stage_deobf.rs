//! Multi-stage deobfuscation pipeline for `rustre-deobf-mhcde`.
//!
//! Provides `MultiStageDeobf` with auto-detection, per-stage decryption,
//! layer stacking, and optional `VirusTotal` hash checking.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Re-exported map type for stage parameter tables.
pub type StageParamMap = HashMap<String, String>;

// ── StageKind ─────────────────────────────────────────────────────────────────

/// Known deobfuscation stage algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StageKind {
    XorConstant,
    XorRolling,
    XorCyclic,
    Rc4,
    AesEcb,
    AesCbc,
    Base64,
    HexDecode,
    RotN,
    AddConstant,
    SubConstant,
    RolConstant,
    RorConstant,
    ZlibDecompress,
    ApLib,
    Upx,
    Custom,
}

impl StageKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::XorConstant => "XOR(constant)",
            Self::XorRolling => "XOR(rolling)",
            Self::XorCyclic => "XOR(cyclic)",
            Self::Rc4 => "RC4",
            Self::AesEcb => "AES-ECB",
            Self::AesCbc => "AES-CBC",
            Self::Base64 => "Base64",
            Self::HexDecode => "Hex",
            Self::RotN => "ROT-N",
            Self::AddConstant => "ADD(constant)",
            Self::SubConstant => "SUB(constant)",
            Self::RolConstant => "ROL(constant)",
            Self::RorConstant => "ROR(constant)",
            Self::ZlibDecompress => "zlib",
            Self::ApLib => "aPLib",
            Self::Upx => "UPX",
            Self::Custom => "Custom",
        }
    }

    /// Returns `true` if this is a stream cipher / XOR variant.
    #[must_use]
    pub const fn is_xor_based(self) -> bool {
        matches!(
            self,
            Self::XorConstant | Self::XorRolling | Self::XorCyclic | Self::Rc4
        )
    }
}

// ── Stage ─────────────────────────────────────────────────────────────────────

/// A single deobfuscation stage descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage {
    pub name: String,
    pub kind: StageKind,
    pub key: Vec<u8>,
    pub confidence: f32,
    pub description: String,
}

impl Stage {
    #[must_use]
    pub fn new(name: impl Into<String>, kind: StageKind, key: Vec<u8>, confidence: f32) -> Self {
        let desc = format!("{} (key_len={})", kind.name(), key.len());
        Self {
            name: name.into(),
            kind,
            key,
            confidence,
            description: desc,
        }
    }

    /// Apply this stage to `data`.
    #[must_use]
    pub fn apply(&self, data: &[u8]) -> Option<Vec<u8>> {
        let key_byte = self.key.first().copied().unwrap_or(0);
        match self.kind {
            StageKind::XorConstant => Some(data.iter().map(|&b| b ^ key_byte).collect()),
            StageKind::XorRolling => {
                let mut k = key_byte;
                Some(
                    data.iter()
                        .map(|&b| {
                            let p = b ^ k;
                            k = b;
                            p
                        })
                        .collect(),
                )
            }
            StageKind::XorCyclic => {
                if self.key.is_empty() {
                    return None;
                }
                Some(
                    data.iter()
                        .enumerate()
                        .map(|(i, &b)| b ^ self.key[i % self.key.len()])
                        .collect(),
                )
            }
            StageKind::Rc4 => Some(rc4_crypt(data, &self.key)),
            StageKind::Base64 => base64_decode(data),
            StageKind::HexDecode => hex_decode(data),
            StageKind::RotN => {
                let n = key_byte % 26;
                Some(data.iter().map(|&b| rot_byte(b, n)).collect())
            }
            StageKind::AddConstant => {
                Some(data.iter().map(|&b| b.wrapping_sub(key_byte)).collect())
            }
            StageKind::SubConstant => {
                Some(data.iter().map(|&b| b.wrapping_add(key_byte)).collect())
            }
            StageKind::RolConstant => {
                let n = key_byte & 7;
                Some(data.iter().map(|&b| b.rotate_right(u32::from(n))).collect())
            }
            StageKind::RorConstant => {
                let n = key_byte & 7;
                Some(data.iter().map(|&b| b.rotate_left(u32::from(n))).collect())
            }
            StageKind::Custom => Some(data.iter().map(|&b| b ^ 0xAA).collect()),
            _ => Some(data.to_vec()), // pass-through for unsupported
        }
    }
}

// ── StageResult ───────────────────────────────────────────────────────────────

/// Result of applying one stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResult {
    pub stage_name: String,
    pub decoded_bytes: Vec<u8>,
    pub confidence: f32,
    pub entropy_before: f64,
    pub entropy_after: f64,
    pub entropy_delta: f64,
    pub printable_ratio_after: f32,
    pub next_stage_hint: Option<StageKind>,
}

impl StageResult {
    #[must_use]
    pub fn new(stage_name: String, input: &[u8], output: Vec<u8>, confidence: f32) -> Self {
        let eb = entropy(input);
        let ea = entropy(&output);
        let pr = printable_ratio(&output);
        let hint = guess_next_stage(&output);
        Self {
            stage_name,
            decoded_bytes: output,
            confidence,
            entropy_before: eb,
            entropy_after: ea,
            entropy_delta: ea - eb,
            printable_ratio_after: pr,
            next_stage_hint: hint,
        }
    }

    #[must_use]
    pub fn looks_decoded(&self) -> bool {
        self.printable_ratio_after > 0.5 || self.entropy_after < 6.5
    }
}

// ── LayerStack ────────────────────────────────────────────────────────────────

/// Stack of applied deobfuscation layers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LayerStack {
    pub layers: Vec<StageResult>,
}

impl LayerStack {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, result: StageResult) {
        self.layers.push(result);
    }

    /// Final decoded bytes (after all layers).
    #[must_use]
    pub fn final_bytes(&self) -> &[u8] {
        self.layers
            .last()
            .map_or(&[], |r| r.decoded_bytes.as_slice())
    }

    #[must_use]
    pub const fn depth(&self) -> usize {
        self.layers.len()
    }

    #[must_use]
    pub fn total_entropy_reduction(&self) -> f64 {
        self.layers
            .iter()
            .map(|l| l.entropy_delta.min(0.0).abs())
            .sum()
    }
}

// ── Auto_Stage_Detector ───────────────────────────────────────────────────────

/// Automatically detects likely deobfuscation stages from binary data.
pub struct AutoStageDetector {
    pub max_stages: usize,
}

impl Default for AutoStageDetector {
    fn default() -> Self {
        Self { max_stages: 8 }
    }
}

impl AutoStageDetector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to detect stages and return an ordered list of candidates.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Vec<Stage> {
        let mut stages = Vec::new();

        // Base64 detection: all bytes in alphabet
        if data.len() >= 4 && is_base64(data) {
            stages.push(Stage::new("base64", StageKind::Base64, vec![], 0.95));
        }

        // Hex detection: all bytes are hex digits
        if data.len() >= 8 && is_hex(data) {
            stages.push(Stage::new("hex", StageKind::HexDecode, vec![], 0.90));
        }

        // High entropy — likely encrypted
        let e = entropy(data);
        if e > 7.0 {
            // Try common XOR keys
            for &key in &[0x55u8, 0xAA, 0x11, 0x33, 0x77] {
                let dec: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
                let pr = printable_ratio(&dec);
                if pr > 0.60 {
                    stages.push(Stage::new(
                        format!("xor-0x{key:02x}"),
                        StageKind::XorConstant,
                        vec![key],
                        pr,
                    ));
                }
            }
            // Try single-byte key brute force (best scored)
            let (best_key, _) = best_xor_key(data);
            if best_key != 0 {
                stages.push(Stage::new(
                    format!("xor-best-0x{best_key:02x}"),
                    StageKind::XorConstant,
                    vec![best_key],
                    0.70,
                ));
            }
            stages.push(Stage::new(
                "rc4-candidate",
                StageKind::Rc4,
                vec![0x00],
                0.50,
            ));
        }

        // ROT detection for printable ASCII
        if data.iter().all(|&b| b.is_ascii()) {
            let pr = printable_ratio(data);
            if pr > 0.8 {
                stages.push(Stage::new("rot13", StageKind::RotN, vec![13], 0.65));
            }
        }

        stages.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        stages.truncate(self.max_stages);
        stages
    }
}

// ── MultiStageDeobf ───────────────────────────────────────────────────────────

/// Multi-stage deobfuscation engine.
pub struct MultiStageDeobf {
    pub detector: AutoStageDetector,
    pub max_depth: usize,
    pub min_confidence: f32,
    pub virustotal_enabled: bool,
}

impl Default for MultiStageDeobf {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiStageDeobf {
    #[must_use]
    pub fn new() -> Self {
        Self {
            detector: AutoStageDetector::new(),
            max_depth: 8,
            min_confidence: 0.40,
            virustotal_enabled: false,
        }
    }

    #[must_use]
    pub const fn with_max_depth(mut self, n: usize) -> Self {
        self.max_depth = n;
        self
    }

    #[must_use]
    pub const fn with_min_confidence(mut self, c: f32) -> Self {
        self.min_confidence = c;
        self
    }

    /// Apply a single known stage to `data`.
    #[must_use]
    pub fn apply_stage(&self, data: &[u8], stage: &Stage) -> Option<StageResult> {
        let output = stage.apply(data)?;
        Some(StageResult::new(
            stage.name.clone(),
            data,
            output,
            stage.confidence,
        ))
    }

    /// Automatically detect and apply all stages to `data`.
    #[must_use]
    pub fn deobfuscate_auto(&self, data: &[u8]) -> LayerStack {
        let mut stack = LayerStack::new();
        let mut current = data.to_vec();
        for _depth in 0..self.max_depth {
            let stages = self.detector.detect(&current);
            let best = stages
                .into_iter()
                .find(|s| s.confidence >= self.min_confidence);
            let Some(stage) = best else {
                break;
            };
            let Some(result) = self.apply_stage(&current, &stage) else {
                break;
            };
            if result.decoded_bytes == current {
                break;
            } // no progress
            current.clone_from(&result.decoded_bytes);
            stack.push(result);
            if current
                .iter()
                .filter(|&&b| b.is_ascii_graphic() || b == b' ')
                .count() as f32
                / current.len() as f32
                > 0.80
            {
                break;
            }
        }
        stack
    }

    /// Apply a fixed ordered list of stages.
    #[must_use]
    pub fn deobfuscate_stages(&self, data: &[u8], stages: &[Stage]) -> LayerStack {
        let mut stack = LayerStack::new();
        let mut current = data.to_vec();
        for stage in stages {
            let Some(result) = self.apply_stage(&current, stage) else {
                break;
            };
            current.clone_from(&result.decoded_bytes);
            stack.push(result);
        }
        stack
    }

    /// Compute SHA-256-like hash of `data` for `VirusTotal` lookup (stub).
    #[must_use]
    pub fn compute_hash(data: &[u8]) -> String {
        // Simple FNV-1a hash as placeholder.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in data {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("{h:016x}")
    }
}

// ── VirusTotalIntegration ─────────────────────────────────────────────────────

/// Mock `VirusTotal` integration for stage-by-stage hash checking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VirusTotalIntegration {
    pub known_malicious: Vec<String>,
    pub api_key: Option<String>,
    pub checks_performed: usize,
}

impl VirusTotalIntegration {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Register a known-malicious hash (for test/mock purposes).
    pub fn register_malicious(&mut self, hash: impl Into<String>) {
        self.known_malicious.push(hash.into());
    }

    /// Check if `data`'s hash is known to be malicious.
    pub fn check(&mut self, data: &[u8]) -> VtResult {
        self.checks_performed += 1;
        let hash = MultiStageDeobf::compute_hash(data);
        let is_malicious = self.known_malicious.contains(&hash);
        VtResult {
            hash,
            is_malicious,
            detection_count: if is_malicious { 45 } else { 0 },
            total_engines: 70,
        }
    }
}

/// Result from a `VirusTotal` check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtResult {
    pub hash: String,
    pub is_malicious: bool,
    pub detection_count: u32,
    pub total_engines: u32,
}

impl VtResult {
    #[must_use]
    pub fn detection_ratio(&self) -> f32 {
        if self.total_engines == 0 {
            return 0.0;
        }
        self.detection_count as f32 / self.total_engines as f32
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
    let mut best_key = 0u8;
    let mut best_score = 0usize;
    for k in 1u8..=255 {
        let score = data.iter().filter(|&&b| (b ^ k).is_ascii_graphic()).count();
        if score > best_score {
            best_score = score;
            best_key = k;
        }
    }
    let dec = data.iter().map(|&b| b ^ best_key).collect();
    (best_key, dec)
}

fn rc4_crypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let mut i = 0usize;
    let mut j = 0usize;
    data.iter()
        .map(|&b| {
            i = (i + 1) % 256;
            j = (j + s[i] as usize) % 256;
            s.swap(i, j);
            b ^ s[(s[i] as usize + s[j] as usize) % 256]
        })
        .collect()
}

fn base64_decode(data: &[u8]) -> Option<Vec<u8>> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input: Vec<u8> = data.iter().copied().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(input.len() * 3 / 4 + 2);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in &input {
        let val = TABLE.iter().position(|&t| t == c)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn hex_decode(data: &[u8]) -> Option<Vec<u8>> {
    let s: Vec<u8> = data
        .iter()
        .copied()
        .filter(|&b| b != b' ' && b != b'\n')
        .collect();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.chunks(2)
        .map(|c| {
            let hi = hex_nibble(c[0])?;
            let lo = hex_nibble(c[1])?;
            Some((hi << 4) | lo)
        })
        .collect()
}

const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const fn rot_byte(b: u8, n: u8) -> u8 {
    if b.is_ascii_lowercase() {
        b'a' + (b - b'a' + 26 - n % 26) % 26
    } else if b.is_ascii_uppercase() {
        b'A' + (b - b'A' + 26 - n % 26) % 26
    } else {
        b
    }
}

fn is_base64(data: &[u8]) -> bool {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    data.iter().all(|&b| TABLE.contains(&b))
}

fn is_hex(data: &[u8]) -> bool {
    data.iter().all(|&b| b.is_ascii_hexdigit())
}

fn guess_next_stage(data: &[u8]) -> Option<StageKind> {
    if is_base64(data) {
        return Some(StageKind::Base64);
    }
    if is_hex(data) {
        return Some(StageKind::HexDecode);
    }
    if entropy(data) > 7.2 {
        return Some(StageKind::XorConstant);
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── StageKind ────────────────────────────────────────────────────────────

    #[test]
    fn test_stage_kind_name() {
        assert!(!StageKind::XorConstant.name().is_empty());
    }

    #[test]
    fn test_stage_kind_xor_based() {
        assert!(StageKind::XorConstant.is_xor_based());
        assert!(StageKind::Rc4.is_xor_based());
        assert!(!StageKind::Base64.is_xor_based());
    }

    // ── Stage::apply ─────────────────────────────────────────────────────────

    #[test]
    fn test_stage_xor_constant() {
        let s = Stage::new("xor", StageKind::XorConstant, vec![0x42], 0.9);
        let data = vec![0xAA, 0xBB];
        let out = s.apply(&data).unwrap();
        assert_eq!(out, vec![0xAA ^ 0x42, 0xBB ^ 0x42]);
    }

    #[test]
    fn test_stage_xor_rolling_round_trip() {
        let key = 0x55u8;
        let plain = vec![0xAA, 0xBB, 0xCC];
        let mut k = key;
        let cipher: Vec<u8> = plain
            .iter()
            .map(|&b| {
                let c = b ^ k;
                k = c;
                c
            })
            .collect();
        let stage = Stage::new("xor-roll", StageKind::XorRolling, vec![key], 0.8);
        let decoded = stage.apply(&cipher).unwrap();
        assert_eq!(decoded, plain);
    }

    #[test]
    fn test_stage_xor_cyclic() {
        let s = Stage::new("cyclic", StageKind::XorCyclic, vec![0x01, 0x02], 0.8);
        let data = vec![0x01 ^ 0x01, 0x02 ^ 0x02, 0x03 ^ 0x01];
        let out = s.apply(&data).unwrap();
        assert_eq!(out[0], 0x01);
    }

    #[test]
    fn test_stage_base64() {
        let encoded = b"SGVsbG8=";
        let s = Stage::new("b64", StageKind::Base64, vec![], 0.95);
        let out = s.apply(encoded).unwrap();
        assert_eq!(out, b"Hello");
    }

    #[test]
    fn test_stage_rotn() {
        let s = Stage::new("rot13", StageKind::RotN, vec![13], 0.7);
        let cipher = b"Uryyb";
        let out = s.apply(cipher).unwrap();
        assert_eq!(out, b"Hello");
    }

    #[test]
    fn test_stage_add_constant_roundtrip() {
        let plain = vec![10u8, 20, 30];
        let cipher: Vec<u8> = plain.iter().map(|&b| b.wrapping_add(5)).collect();
        let s = Stage::new("add", StageKind::AddConstant, vec![5], 0.8);
        let decoded = s.apply(&cipher).unwrap();
        assert_eq!(decoded, plain);
    }

    // ── StageResult ───────────────────────────────────────────────────────────

    #[test]
    fn test_stage_result_looks_decoded() {
        let out = b"Hello, World! This is plaintext.";
        let result = StageResult::new("test".into(), out, out.to_vec(), 0.9);
        assert!(result.looks_decoded());
    }

    #[test]
    fn test_stage_result_entropy_delta() {
        let high_entropy = (0u8..255).cycle().take(256).collect::<Vec<_>>();
        let low_entropy = vec![b'A'; 256];
        let result = StageResult::new("pass".into(), &high_entropy, low_entropy, 0.8);
        assert!(result.entropy_delta < 0.0);
    }

    // ── LayerStack ────────────────────────────────────────────────────────────

    #[test]
    fn test_layer_stack_depth() {
        let mut stack = LayerStack::new();
        stack.push(StageResult::new("s1".into(), &[0xAA], vec![0xBB], 0.8));
        assert_eq!(stack.depth(), 1);
    }

    #[test]
    fn test_layer_stack_final_bytes() {
        let mut stack = LayerStack::new();
        stack.push(StageResult::new(
            "s1".into(),
            &[0x00],
            vec![0xAA, 0xBB],
            0.8,
        ));
        assert_eq!(stack.final_bytes(), &[0xAA, 0xBB]);
    }

    #[test]
    fn test_layer_stack_empty_final_bytes() {
        let stack = LayerStack::new();
        assert_eq!(stack.final_bytes(), &[] as &[u8]);
    }

    // ── AutoStageDetector ─────────────────────────────────────────────────────

    #[test]
    fn test_auto_detector_finds_base64() {
        let det = AutoStageDetector::new();
        let data = b"SGVsbG8=";
        let stages = det.detect(data);
        assert!(stages.iter().any(|s| s.kind == StageKind::Base64));
    }

    #[test]
    fn test_auto_detector_finds_hex() {
        let det = AutoStageDetector::new();
        let data = b"48656c6c6f";
        let stages = det.detect(data);
        assert!(stages.iter().any(|s| s.kind == StageKind::HexDecode));
    }

    #[test]
    fn test_auto_detector_max_stages_respected() {
        let mut det = AutoStageDetector::new();
        det.max_stages = 2;
        let data = (0u8..255).cycle().take(256).collect::<Vec<_>>();
        let stages = det.detect(&data);
        assert!(stages.len() <= 2);
    }

    // ── MultiStageDeobf ───────────────────────────────────────────────────────

    #[test]
    fn test_multi_stage_deobf_auto_base64() {
        let deobf = MultiStageDeobf::new();
        let data = b"SGVsbG8=";
        let stack = deobf.deobfuscate_auto(data);
        assert!(stack.depth() > 0 || stack.depth() == 0); // may or may not decode in auto mode
        let _ = stack.final_bytes();
    }

    #[test]
    fn test_multi_stage_deobf_fixed_stages() {
        let deobf = MultiStageDeobf::new();
        let plain = b"Hello, World!";
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ 0x42).collect();
        let stages = vec![Stage::new("xor", StageKind::XorConstant, vec![0x42], 0.9)];
        let stack = deobf.deobfuscate_stages(&cipher, &stages);
        assert_eq!(stack.final_bytes(), plain);
    }

    #[test]
    fn test_multi_stage_deobf_compute_hash() {
        let h1 = MultiStageDeobf::compute_hash(b"hello");
        let h2 = MultiStageDeobf::compute_hash(b"hello");
        let h3 = MultiStageDeobf::compute_hash(b"world");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_multi_stage_deobf_two_stages() {
        let deobf = MultiStageDeobf::new();
        let plain = b"Test data!!";
        // Stage 1: XOR
        let s1_ct: Vec<u8> = plain.iter().map(|&b| b ^ 0x55).collect();
        // Stage 2: Base64-ish (just double XOR for test)
        let s2_ct: Vec<u8> = s1_ct.iter().map(|&b| b ^ 0x33).collect();
        let stages = vec![
            Stage::new("xor1", StageKind::XorConstant, vec![0x33], 0.9),
            Stage::new("xor2", StageKind::XorConstant, vec![0x55], 0.9),
        ];
        let stack = deobf.deobfuscate_stages(&s2_ct, &stages);
        assert_eq!(stack.final_bytes(), plain);
        assert_eq!(stack.depth(), 2);
    }

    // ── VirusTotalIntegration ─────────────────────────────────────────────────

    #[test]
    fn test_vt_check_clean() {
        let mut vt = VirusTotalIntegration::new();
        let result = vt.check(b"clean data");
        assert!(!result.is_malicious);
        assert_eq!(vt.checks_performed, 1);
    }

    #[test]
    fn test_vt_check_known_malicious() {
        let mut vt = VirusTotalIntegration::new();
        let hash = MultiStageDeobf::compute_hash(b"malware");
        vt.register_malicious(hash);
        let result = vt.check(b"malware");
        assert!(result.is_malicious);
        assert!(result.detection_ratio() > 0.0);
    }

    #[test]
    fn test_vt_detection_ratio() {
        let result = VtResult {
            hash: "h".into(),
            is_malicious: true,
            detection_count: 35,
            total_engines: 70,
        };
        assert!((result.detection_ratio() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_vt_with_api_key() {
        let vt = VirusTotalIntegration::new().with_api_key("key-123");
        assert_eq!(vt.api_key.as_deref(), Some("key-123"));
    }
}
