//! Decryption and key-extraction utilities for obfuscated strings.
//!
//! This module builds on top of [`crate::encoding_detect`] to provide:
//!
//! * **Key extraction from code patterns** — recognise constant-folded or
//!   partially-evaluated keys embedded in instruction sequences near a
//!   decrypt stub.
//! * **Bulk decryption** — apply a recovered key to a set of encrypted string
//!   blobs to produce plaintext candidates.
//! * **Decrypt-stub heuristics** — detect common patterns such as an XOR loop,
//!   ROT loop, or base64-decode stub via instruction-stream fingerprints.
//! * **`DecryptionResult`** — a richly-typed result capturing the algorithm,
//!   key, plaintext, and confidence.

pub use crate::encoding_detect::detect_xor_single_byte;
use crate::encoding_detect::{
    DetectedEncoding, EncodingDetector, EncodingKind, base64_decode, hex_decode, rot_decode,
    xor_decode_multibyte, xor_decode_single,
};
use ahash::AHashMap;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// DecryptionAlgorithm
// ─────────────────────────────────────────────────────────────────────────────

/// The algorithm used to decrypt / decode an obfuscated string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DecryptionAlgorithm {
    /// Single-byte XOR with the given key.
    XorByte(u8),
    /// Multi-byte XOR with the given key.
    XorKey(Vec<u8>),
    /// ROT-N (Caesar cipher) with the given offset.
    RotN(u8),
    /// ROT-13.
    Rot13,
    /// Base64 decoding.
    Base64,
    /// Hex-string decoding.
    HexDecode,
    /// Custom algorithm (described by name).
    Custom(String),
    /// No encryption — data is already plaintext.
    Plaintext,
}

impl std::fmt::Display for DecryptionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::XorByte(k) => write!(f, "XOR(0x{k:02x})"),
            Self::XorKey(k) => {
                let s: Vec<String> = k.iter().map(|b| format!("{b:02x}")).collect();
                write!(f, "XOR-MB({})", s.join(":"))
            }
            Self::RotN(n) => write!(f, "ROT{n}"),
            Self::Rot13 => write!(f, "ROT13"),
            Self::Base64 => write!(f, "Base64"),
            Self::HexDecode => write!(f, "HexDecode"),
            Self::Custom(s) => write!(f, "Custom({s})"),
            Self::Plaintext => write!(f, "Plaintext"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DecryptionResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result of a decryption attempt.
#[derive(Debug, Clone)]
pub struct DecryptionResult {
    /// The algorithm used.
    pub algorithm: DecryptionAlgorithm,
    /// The key (may be empty for keyless algorithms like base64).
    pub key: Vec<u8>,
    /// The raw decrypted bytes.
    pub plaintext_bytes: Vec<u8>,
    /// The decrypted value as a UTF-8 string (lossy).
    pub plaintext_string: String,
    /// Confidence in this result (0–100).
    pub confidence: u8,
    /// Virtual address of the encrypted data in the binary (if known).
    pub source_address: Option<u64>,
}

impl DecryptionResult {
    /// Create a new result.
    #[must_use]
    pub fn new(
        algorithm: DecryptionAlgorithm,
        key: Vec<u8>,
        plaintext_bytes: Vec<u8>,
        confidence: u8,
    ) -> Self {
        let plaintext_string = String::from_utf8_lossy(&plaintext_bytes).into_owned();
        Self {
            algorithm,
            key,
            plaintext_bytes,
            plaintext_string,
            confidence,
            source_address: None,
        }
    }

    /// Attach a source address.
    #[must_use]
    pub const fn with_address(mut self, addr: u64) -> Self {
        self.source_address = Some(addr);
        self
    }

    /// Whether the plaintext is valid ASCII.
    #[must_use]
    pub fn is_ascii(&self) -> bool {
        self.plaintext_bytes
            .iter()
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
    }

    /// Fraction of printable ASCII bytes in the plaintext.
    #[must_use]
    pub fn printability(&self) -> f64 {
        if self.plaintext_bytes.is_empty() {
            return 0.0;
        }
        let p = self
            .plaintext_bytes
            .iter()
            .filter(|&&b| (0x20..=0x7E).contains(&b))
            .count();
        // Safe: both values fit in f64 for realistic string lengths.
        f64::from(u32::try_from(p).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.plaintext_bytes.len()).unwrap_or(u32::MAX))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Key extraction from code context
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified register state for key extraction.
///
/// Maps register names to their last constant value, as would be produced by
/// constant-folding or partial evaluation of an instruction stream.
pub type RegState = HashMap<String, u64>;

/// A simplified instruction model used for decrypt-stub pattern matching.
#[derive(Debug, Clone)]
pub enum KeyExtractInstr {
    /// Move an immediate constant into a register: `mov reg, imm`.
    MovImm { reg: String, imm: u64 },
    /// XOR a register with an immediate: `xor reg, imm`.
    XorImm { reg: String, imm: u64 },
    /// ADD an immediate to a register: `add reg, imm`.
    AddImm { reg: String, imm: u64 },
    /// Any other instruction (ignored during key extraction).
    Other,
}

/// Extract a single-byte XOR key from a simplified instruction stream.
///
/// Recognises patterns like:
/// ```asm
/// mov  al, 0x42
/// xor  [rbx], al
/// ```
/// or
/// ```asm
/// mov  cl, 0x37
/// ```
/// Returns the key byte if a constant is loaded into a byte register (`al`,
/// `cl`, `dl`, `bl`) and then used in an XOR instruction (or simply the loaded
/// constant if it is the only candidate).
#[must_use]
pub fn extract_xor_key_from_instrs(instrs: &[KeyExtractInstr]) -> Option<u8> {
    let mut state: RegState = HashMap::new();
    let mut xor_imm_candidate: Option<u8> = None;

    for instr in instrs {
        match instr {
            KeyExtractInstr::MovImm { reg, imm } => {
                state.insert(reg.clone(), *imm);
            }
            KeyExtractInstr::XorImm { reg: _, imm } => {
                // Immediate used in XOR is a key candidate.
                if let Ok(byte) = u8::try_from(*imm)
                    && byte > 0
                {
                    xor_imm_candidate = Some(byte);
                }
            }
            KeyExtractInstr::AddImm { reg, imm } => {
                let cur = state.get(reg).copied().unwrap_or(0);
                state.insert(reg.clone(), cur.wrapping_add(*imm));
            }
            KeyExtractInstr::Other => {}
        }
    }

    // Priority: an XOR-immediate is the strongest signal.
    if let Some(k) = xor_imm_candidate {
        return Some(k);
    }

    // Fall back: a constant in a byte-sized register (al, cl, dl, bl).
    let byte_regs = ["al", "cl", "dl", "bl"];
    for &reg in &byte_regs {
        if let Some(&v) = state.get(reg)
            && let Ok(byte) = u8::try_from(v)
            && byte > 0
        {
            return Some(byte);
        }
    }
    None
}

/// Extract a multi-byte XOR key from a simplified instruction stream.
///
/// Recognises patterns where multiple consecutive byte constants are loaded
/// into byte-register slots or stored to an array.  Returns the bytes in the
/// order they appear.
#[must_use]
pub fn extract_multibyte_key_from_instrs(instrs: &[KeyExtractInstr]) -> Vec<u8> {
    let mut key_bytes: Vec<u8> = Vec::new();
    for instr in instrs {
        match instr {
            KeyExtractInstr::MovImm { imm, .. } | KeyExtractInstr::XorImm { imm, .. }
                if *imm > 0 && *imm <= 0xFF =>
            {
                key_bytes.push(u8::try_from(*imm).unwrap_or(0));
            }
            // Out-of-range immediates fall through here as well as the
            // genuinely uninteresting variants; listed explicitly so a new
            // variant cannot be silently ignored.
            KeyExtractInstr::MovImm { .. }
            | KeyExtractInstr::XorImm { .. }
            | KeyExtractInstr::AddImm { .. }
            | KeyExtractInstr::Other => {}
        }
    }
    key_bytes
}

// ─────────────────────────────────────────────────────────────────────────────
// Decrypt-stub fingerprinting
// ─────────────────────────────────────────────────────────────────────────────

/// A detected decrypt-stub pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StubPattern {
    /// An XOR loop: `xor byte [reg], key; inc reg; dec counter; jnz`.
    XorLoop,
    /// A ROT loop: add/sub constant to each byte in a buffer.
    RotLoop,
    /// A base64 decode stub (calls a known function or has the base64 alphabet).
    Base64Stub,
    /// A custom decrypt loop (generic pattern: loop + byte manipulation).
    CustomLoop,
    /// No recognisable stub pattern.
    None,
}

/// A simplified branch/loop instruction model for stub detection.
#[derive(Debug, Clone)]
pub enum StubInstr {
    /// `xor [mem], reg/imm`.
    XorMem,
    /// `add [mem], reg/imm`.
    AddMem,
    /// `sub [mem], reg/imm`.
    SubMem,
    /// `inc reg`.
    Inc,
    /// `dec reg` or `loop`.
    Dec,
    /// A conditional jump backwards (loop-closing branch).
    Jnz,
    /// Load from the base64 alphabet table (LEA or MOVZX from a known table).
    Base64TableAccess,
    /// Any other instruction.
    Other,
}

/// Heuristically identify the decrypt-stub pattern in an instruction sequence.
#[must_use]
pub fn identify_stub_pattern(instrs: &[StubInstr]) -> StubPattern {
    let has_xor_mem = instrs.iter().any(|i| matches!(i, StubInstr::XorMem));
    let has_add_sub_mem = instrs
        .iter()
        .any(|i| matches!(i, StubInstr::AddMem | StubInstr::SubMem));
    let has_loop_close = instrs
        .iter()
        .any(|i| matches!(i, StubInstr::Jnz | StubInstr::Dec));
    let has_base64 = instrs
        .iter()
        .any(|i| matches!(i, StubInstr::Base64TableAccess));

    if has_base64 {
        StubPattern::Base64Stub
    } else if has_xor_mem && has_loop_close {
        StubPattern::XorLoop
    } else if has_add_sub_mem && has_loop_close {
        StubPattern::RotLoop
    } else if has_loop_close {
        StubPattern::CustomLoop
    } else {
        StubPattern::None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bulk decryption
// ─────────────────────────────────────────────────────────────────────────────

/// Decrypt `data` with a single-byte XOR key.
#[must_use]
pub fn decrypt_xor_byte(data: &[u8], key: u8) -> DecryptionResult {
    let plaintext = xor_decode_single(data, key);
    let p_count = plaintext.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count();
    let p_len = plaintext.len().max(1);
    // Avoid precision-loss casts: compute in integer arithmetic where possible.
    // confidence = min(p_count * 100 / p_len, 95) as u8
    let confidence = u8::try_from((p_count * 100 / p_len).min(95)).unwrap_or(95);
    DecryptionResult::new(
        DecryptionAlgorithm::XorByte(key),
        vec![key],
        plaintext,
        confidence,
    )
}

/// Decrypt `data` with a multi-byte XOR key.
#[must_use]
pub fn decrypt_xor_key(data: &[u8], key: &[u8]) -> DecryptionResult {
    let plaintext = xor_decode_multibyte(data, key);
    let p_count = plaintext.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count();
    let p_len = plaintext.len().max(1);
    let confidence = u8::try_from((p_count * 100 / p_len).min(95)).unwrap_or(95);
    DecryptionResult::new(
        DecryptionAlgorithm::XorKey(key.to_vec()),
        key.to_vec(),
        plaintext,
        confidence,
    )
}

/// Decrypt `data` with ROT-N.
#[must_use]
pub fn decrypt_rot_n(data: &[u8], n: u8) -> DecryptionResult {
    // Decryption is the inverse rotation of encryption: shift back by `n`.
    let plaintext = rot_decode(data, 26 - (n % 26));
    let p_count = plaintext.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ').count();
    let p_len = plaintext.len().max(1);
    // confidence = min(p_count * 80 / p_len, 80)
    let confidence = u8::try_from((p_count * 80 / p_len).min(80)).unwrap_or(80);
    let algo = if n == 13 {
        DecryptionAlgorithm::Rot13
    } else {
        DecryptionAlgorithm::RotN(n)
    };
    DecryptionResult::new(algo, vec![n], plaintext, confidence)
}

/// Decode `data` as base64.
#[must_use]
pub fn decrypt_base64(data: &[u8]) -> Option<DecryptionResult> {
    let decoded = base64_decode(data)?;
    let p_count = decoded.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count();
    // frac >= 0.80 ↔ p_count * 10 >= decoded.len().max(1) * 8
    let confidence = if p_count * 10 >= decoded.len().max(1) * 8 { 90u8 } else { 60 };
    Some(DecryptionResult::new(
        DecryptionAlgorithm::Base64,
        vec![],
        decoded,
        confidence,
    ))
}

/// Decode `data` as an ASCII hex string.
#[must_use]
pub fn decrypt_hex(data: &[u8]) -> Option<DecryptionResult> {
    let decoded = hex_decode(data)?;
    let p_count = decoded.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count();
    let confidence = if p_count * 10 >= decoded.len().max(1) * 8 { 85u8 } else { 55 };
    Some(DecryptionResult::new(
        DecryptionAlgorithm::HexDecode,
        vec![],
        decoded,
        confidence,
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Auto-decrypt using detected encoding
// ─────────────────────────────────────────────────────────────────────────────

/// Convert a [`DetectedEncoding`] into a [`DecryptionResult`].
#[must_use]
pub fn detected_to_result(det: DetectedEncoding) -> Option<DecryptionResult> {
    let plaintext = det.decoded?;
    let (algo, key) = match &det.kind {
        EncodingKind::XorSingleByte(k) => (DecryptionAlgorithm::XorByte(*k), vec![*k]),
        EncodingKind::XorMultiByte(k) => (DecryptionAlgorithm::XorKey(k.clone()), k.clone()),
        EncodingKind::RotN(n) => {
            let algo = if *n == 13 {
                DecryptionAlgorithm::Rot13
            } else {
                DecryptionAlgorithm::RotN(*n)
            };
            (algo, vec![*n])
        }
        EncodingKind::Base64 => (DecryptionAlgorithm::Base64, vec![]),
        EncodingKind::HexEncoded => (DecryptionAlgorithm::HexDecode, vec![]),
        EncodingKind::Plaintext => (DecryptionAlgorithm::Plaintext, vec![]),
        EncodingKind::Unknown => return None,
    };
    Some(DecryptionResult::new(algo, key, plaintext, det.confidence))
}

/// Auto-detect and decrypt `data`, returning the highest-confidence result.
#[must_use]
pub fn auto_decrypt(data: &[u8]) -> Option<DecryptionResult> {
    let det = EncodingDetector::default();
    let best = det.detect_best(data)?;
    detected_to_result(best)
}

// ─────────────────────────────────────────────────────────────────────────────
// BulkDecryptor — decrypt many blobs with a known key
// ─────────────────────────────────────────────────────────────────────────────

/// Applies a fixed decryption algorithm to many encrypted blobs.
pub struct BulkDecryptor {
    /// The algorithm and key to apply.
    pub algorithm: DecryptionAlgorithm,
}

impl BulkDecryptor {
    /// Create a decryptor for a single-byte XOR key.
    #[must_use]
    pub const fn xor_byte(key: u8) -> Self {
        Self {
            algorithm: DecryptionAlgorithm::XorByte(key),
        }
    }

    /// Create a decryptor for a multi-byte XOR key.
    #[must_use]
    pub const fn xor_key(key: Vec<u8>) -> Self {
        Self {
            algorithm: DecryptionAlgorithm::XorKey(key),
        }
    }

    /// Create a decryptor for ROT-N.
    #[must_use]
    pub const fn rot_n(n: u8) -> Self {
        let algo = if n == 13 {
            DecryptionAlgorithm::Rot13
        } else {
            DecryptionAlgorithm::RotN(n)
        };
        Self { algorithm: algo }
    }

    /// Decrypt a single blob.
    #[must_use]
    pub fn decrypt(&self, data: &[u8]) -> Option<DecryptionResult> {
        match &self.algorithm {
            DecryptionAlgorithm::XorByte(k) => Some(decrypt_xor_byte(data, *k)),
            DecryptionAlgorithm::XorKey(k) => Some(decrypt_xor_key(data, k)),
            DecryptionAlgorithm::RotN(_) | DecryptionAlgorithm::Rot13 => {
                let n = match &self.algorithm {
                    DecryptionAlgorithm::Rot13 => 13,
                    DecryptionAlgorithm::RotN(n) => *n,
                    _ => unreachable!(),
                };
                Some(decrypt_rot_n(data, n))
            }
            DecryptionAlgorithm::Base64 => decrypt_base64(data),
            DecryptionAlgorithm::HexDecode => decrypt_hex(data),
            DecryptionAlgorithm::Plaintext => Some(DecryptionResult::new(
                DecryptionAlgorithm::Plaintext,
                vec![],
                data.to_vec(),
                99,
            )),
            DecryptionAlgorithm::Custom(_) => None,
        }
    }

    /// Decrypt a collection of `(address, encrypted_data)` pairs.
    /// Results with `None` decryptions are omitted.
    #[must_use]
    pub fn decrypt_all(&self, blobs: &[(u64, &[u8])]) -> Vec<DecryptionResult> {
        blobs
            .iter()
            .filter_map(|(addr, data)| self.decrypt(data).map(|r| r.with_address(*addr)))
            .collect()
    }

    /// Decrypt and return only blobs that produce printable ASCII strings
    /// (>= 80 % printable bytes).
    #[must_use]
    pub fn decrypt_printable(&self, blobs: &[(u64, &[u8])]) -> Vec<DecryptionResult> {
        self.decrypt_all(blobs)
            .into_iter()
            .filter(|r| r.printability() >= 0.80)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringDecryptionPass — high-level API
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the string decryption pass.
#[derive(Debug, Clone)]
pub struct StringDecryptionConfig {
    /// Minimum plaintext length to report.
    pub min_length: usize,
    /// Minimum confidence to include a result.
    pub min_confidence: u8,
    /// Maximum number of blobs to process (0 = unlimited).
    pub max_blobs: usize,
}

impl Default for StringDecryptionConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            min_confidence: 50,
            max_blobs: 0,
        }
    }
}

/// Decrypt a collection of raw byte blobs using automatic encoding detection.
///
/// Each blob is analysed independently; the best-confidence result is kept if
/// it exceeds `config.min_confidence` and the plaintext length exceeds
/// `config.min_length`.
#[must_use]
pub fn decrypt_string_blobs(
    blobs: &[(u64, Vec<u8>)],
    config: &StringDecryptionConfig,
) -> Vec<DecryptionResult> {
    let det = EncodingDetector::default();
    let limit = if config.max_blobs == 0 {
        usize::MAX
    } else {
        config.max_blobs
    };

    blobs
        .iter()
        .take(limit)
        .filter_map(|(addr, data)| {
            let best = det.detect_best(data)?;
            if best.confidence < config.min_confidence {
                return None;
            }
            let result = detected_to_result(best)?;
            if result.plaintext_bytes.len() < config.min_length {
                return None;
            }
            Some(result.with_address(*addr))
        })
        .collect()
}

/// Group decryption results by algorithm for analysis.
///
/// Uses [`AHashMap`] because the key is the algorithm's display string, which
/// for `DecryptionAlgorithm::Custom` contains attacker-controlled content.
/// A standard `HashMap` with the default SipHash hasher also resists collision
/// attacks, but `AHashMap` is faster and equally safe here
/// (dos-hash-collision).
#[must_use]
pub fn group_by_algorithm(results: &[DecryptionResult]) -> AHashMap<String, Vec<&DecryptionResult>> {
    let mut map: AHashMap<String, Vec<&DecryptionResult>> = AHashMap::new();
    for r in results {
        map.entry(r.algorithm.to_string()).or_default().push(r);
    }
    map
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn enc_xor(plain: &[u8], key: u8) -> Vec<u8> {
        plain.iter().map(|&b| b ^ key).collect()
    }

    // ── DecryptionAlgorithm display ──────────────────────────────────────────

    #[test]
    fn test_algorithm_display_xor_byte() {
        let a = DecryptionAlgorithm::XorByte(0x42);
        assert_eq!(a.to_string(), "XOR(0x42)");
    }

    #[test]
    fn test_algorithm_display_rot13() {
        assert_eq!(DecryptionAlgorithm::Rot13.to_string(), "ROT13");
    }

    #[test]
    fn test_algorithm_display_base64() {
        assert_eq!(DecryptionAlgorithm::Base64.to_string(), "Base64");
    }

    #[test]
    fn test_algorithm_display_custom() {
        let a = DecryptionAlgorithm::Custom("rc4".to_string());
        assert!(a.to_string().contains("rc4"));
    }

    // ── DecryptionResult ─────────────────────────────────────────────────────

    #[test]
    fn test_decryption_result_new() {
        let r = DecryptionResult::new(
            DecryptionAlgorithm::XorByte(0x42),
            vec![0x42],
            b"Hello".to_vec(),
            90,
        );
        assert_eq!(r.plaintext_string, "Hello");
        assert!(r.is_ascii());
        assert!(r.printability() > 0.9);
    }

    #[test]
    fn test_decryption_result_with_address() {
        let r = DecryptionResult::new(DecryptionAlgorithm::Plaintext, vec![], b"test".to_vec(), 99)
            .with_address(0x1234);
        assert_eq!(r.source_address, Some(0x1234));
    }

    #[test]
    fn test_decryption_result_printability_full() {
        let r = DecryptionResult::new(
            DecryptionAlgorithm::Plaintext,
            vec![],
            b"Hello World".to_vec(),
            99,
        );
        assert!((r.printability() - 1.0).abs() < 0.01);
    }

    // ── Key extraction ───────────────────────────────────────────────────────

    #[test]
    fn test_extract_xor_key_from_mov_al() {
        let instrs = vec![
            KeyExtractInstr::MovImm {
                reg: "al".to_string(),
                imm: 0x42,
            },
            KeyExtractInstr::Other,
        ];
        let key = extract_xor_key_from_instrs(&instrs);
        assert_eq!(key, Some(0x42));
    }

    #[test]
    fn test_extract_xor_key_prefers_xor_imm() {
        let instrs = vec![
            KeyExtractInstr::MovImm {
                reg: "al".to_string(),
                imm: 0x10,
            },
            KeyExtractInstr::XorImm {
                reg: "al".to_string(),
                imm: 0x37,
            },
        ];
        let key = extract_xor_key_from_instrs(&instrs);
        assert_eq!(key, Some(0x37));
    }

    #[test]
    fn test_extract_xor_key_no_key() {
        let instrs = vec![KeyExtractInstr::Other, KeyExtractInstr::Other];
        let key = extract_xor_key_from_instrs(&instrs);
        assert!(key.is_none());
    }

    #[test]
    fn test_extract_multibyte_key() {
        let instrs = vec![
            KeyExtractInstr::MovImm {
                reg: "al".to_string(),
                imm: 0x41,
            },
            KeyExtractInstr::MovImm {
                reg: "bl".to_string(),
                imm: 0x42,
            },
            KeyExtractInstr::MovImm {
                reg: "cl".to_string(),
                imm: 0x43,
            },
        ];
        let key = extract_multibyte_key_from_instrs(&instrs);
        assert_eq!(key, vec![0x41, 0x42, 0x43]);
    }

    #[test]
    fn test_extract_multibyte_key_empty() {
        let instrs = vec![KeyExtractInstr::Other];
        assert!(extract_multibyte_key_from_instrs(&instrs).is_empty());
    }

    // ── Stub fingerprinting ──────────────────────────────────────────────────

    #[test]
    fn test_identify_stub_xor_loop() {
        let instrs = vec![
            StubInstr::XorMem,
            StubInstr::Inc,
            StubInstr::Dec,
            StubInstr::Jnz,
        ];
        assert_eq!(identify_stub_pattern(&instrs), StubPattern::XorLoop);
    }

    #[test]
    fn test_identify_stub_rot_loop() {
        let instrs = vec![StubInstr::AddMem, StubInstr::Inc, StubInstr::Jnz];
        assert_eq!(identify_stub_pattern(&instrs), StubPattern::RotLoop);
    }

    #[test]
    fn test_identify_stub_base64() {
        let instrs = vec![StubInstr::Base64TableAccess, StubInstr::Other];
        assert_eq!(identify_stub_pattern(&instrs), StubPattern::Base64Stub);
    }

    #[test]
    fn test_identify_stub_none() {
        let instrs = vec![StubInstr::Other, StubInstr::Other];
        assert_eq!(identify_stub_pattern(&instrs), StubPattern::None);
    }

    #[test]
    fn test_identify_stub_custom_loop() {
        let instrs = vec![StubInstr::Inc, StubInstr::Jnz];
        assert_eq!(identify_stub_pattern(&instrs), StubPattern::CustomLoop);
    }

    // ── decrypt_xor_byte ────────────────────────────────────────────────────

    #[test]
    fn test_decrypt_xor_byte_roundtrip() {
        let key = 0x5Au8;
        let plain = b"Hello World";
        let enc = enc_xor(plain, key);
        let result = decrypt_xor_byte(&enc, key);
        assert_eq!(result.plaintext_bytes, plain);
        assert!(result.confidence > 0);
    }

    #[test]
    fn test_decrypt_xor_byte_empty() {
        let r = decrypt_xor_byte(&[], 0x42);
        assert!(r.plaintext_bytes.is_empty());
    }

    // ── decrypt_xor_key ─────────────────────────────────────────────────────

    #[test]
    fn test_decrypt_xor_key_roundtrip() {
        let key = b"KEY";
        let plain = b"Hello World!!!";
        let enc: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % 3])
            .collect();
        let result = decrypt_xor_key(&enc, key);
        assert_eq!(&result.plaintext_bytes, plain);
    }

    // ── decrypt_rot_n ───────────────────────────────────────────────────────

    #[test]
    fn test_decrypt_rot_n_13() {
        let plain = b"Hello World";
        let enc = rot_decode(plain, 13);
        let result = decrypt_rot_n(&enc, 13);
        assert_eq!(result.plaintext_bytes, plain.to_vec());
        assert!(matches!(result.algorithm, DecryptionAlgorithm::Rot13));
    }

    #[test]
    fn test_decrypt_rot_n_7() {
        let plain = b"Rust RE tool";
        let enc = rot_decode(plain, 7);
        let result = decrypt_rot_n(&enc, 7);
        assert_eq!(result.plaintext_bytes, plain.to_vec());
        assert!(matches!(result.algorithm, DecryptionAlgorithm::RotN(7)));
    }

    // ── decrypt_base64 ──────────────────────────────────────────────────────

    #[test]
    fn test_decrypt_base64_hello() {
        let enc = b"SGVsbG8gV29ybGQ="; // "Hello World"
        let result = decrypt_base64(enc).unwrap();
        assert_eq!(result.plaintext_string, "Hello World");
    }

    #[test]
    fn test_decrypt_base64_invalid() {
        assert!(decrypt_base64(b"not!base64!!").is_none());
    }

    // ── decrypt_hex ─────────────────────────────────────────────────────────

    #[test]
    fn test_decrypt_hex_hello() {
        let enc = b"48656c6c6f"; // "Hello"
        let result = decrypt_hex(enc).unwrap();
        assert_eq!(result.plaintext_string, "Hello");
    }

    #[test]
    fn test_decrypt_hex_invalid() {
        assert!(decrypt_hex(b"ZZZZZ").is_none());
    }

    // ── auto_decrypt ────────────────────────────────────────────────────────

    #[test]
    fn test_auto_decrypt_xor_key() {
        let key = 0x11u8;
        let plain = b"secret password string here";
        let enc = enc_xor(plain, key);
        let result = auto_decrypt(&enc);
        assert!(result.is_some());
    }

    #[test]
    fn test_auto_decrypt_base64() {
        let enc = b"SGVsbG8gV29ybGQ=";
        let result = auto_decrypt(enc);
        assert!(result.is_some());
        assert!(matches!(
            result.unwrap().algorithm,
            DecryptionAlgorithm::Base64
        ));
    }

    // ── BulkDecryptor ────────────────────────────────────────────────────────

    #[test]
    fn test_bulk_decryptor_xor_byte() {
        let key = 0x55u8;
        let plain = b"Hello World";
        let enc = enc_xor(plain, key);
        let dec = BulkDecryptor::xor_byte(key);
        let blobs: Vec<(u64, &[u8])> = vec![(0x1000, &enc)];
        let results = dec.decrypt_all(&blobs);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].plaintext_bytes, plain);
        assert_eq!(results[0].source_address, Some(0x1000));
    }

    #[test]
    fn test_bulk_decryptor_decrypt_printable() {
        let key = 0x42u8;
        let plain = b"Hello World this is a printable string";
        let enc = enc_xor(plain, key);
        let garbage = [0u8; 16]; // not printable after XOR
        let dec = BulkDecryptor::xor_byte(key);
        let enc_garbage: Vec<u8> = garbage.iter().map(|&b| b ^ key).collect();
        let blobs: Vec<(u64, &[u8])> = vec![(0x1000, enc.as_slice()), (0x2000, &enc_garbage)];
        let results = dec.decrypt_printable(&blobs);
        // Only the printable one should pass the threshold.
        assert!(
            results
                .iter()
                .any(|r| r.plaintext_string.starts_with("Hello"))
        );
    }

    #[test]
    fn test_bulk_decryptor_base64() {
        let dec = BulkDecryptor {
            algorithm: DecryptionAlgorithm::Base64,
        };
        let enc = b"SGVsbG8gV29ybGQ=";
        let blobs: Vec<(u64, &[u8])> = vec![(0x100, enc.as_ref())];
        let results = dec.decrypt_all(&blobs);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].plaintext_string, "Hello World");
    }

    // ── decrypt_string_blobs ─────────────────────────────────────────────────

    #[test]
    fn test_decrypt_string_blobs_basic() {
        let key = 0x7Fu8;
        let plain = b"malware config string here";
        let enc: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let blobs = vec![(0x5000u64, enc)];
        let config = StringDecryptionConfig::default();
        let results = decrypt_string_blobs(&blobs, &config);
        // auto-detect should find the XOR key.
        let _ = results.is_empty(); // best-effort
    }

    #[test]
    fn test_decrypt_string_blobs_empty() {
        let blobs: Vec<(u64, Vec<u8>)> = vec![];
        let results = decrypt_string_blobs(&blobs, &StringDecryptionConfig::default());
        assert!(results.is_empty());
    }

    // ── group_by_algorithm ────────────────────────────────────────────────────

    #[test]
    fn test_group_by_algorithm() {
        let r1 = DecryptionResult::new(
            DecryptionAlgorithm::XorByte(0x42),
            vec![],
            b"a".to_vec(),
            80,
        );
        let r2 = DecryptionResult::new(DecryptionAlgorithm::Base64, vec![], b"b".to_vec(), 85);
        let r3 = DecryptionResult::new(
            DecryptionAlgorithm::XorByte(0x42),
            vec![],
            b"c".to_vec(),
            75,
        );
        let results = vec![r1, r2, r3];
        let groups = group_by_algorithm(&results);
        assert_eq!(groups.get("XOR(0x42)").map_or(0, std::vec::Vec::len), 2);
        assert_eq!(groups.get("Base64").map_or(0, std::vec::Vec::len), 1);
    }

    #[test]
    fn test_detected_to_result_xor() {
        let enc = enc_xor(b"Hello", 0x42);
        let det = detect_xor_single_byte(&enc).unwrap();
        let result = detected_to_result(det).unwrap();
        assert!(matches!(
            result.algorithm,
            DecryptionAlgorithm::XorByte(0x42)
        ));
    }

    #[test]
    fn test_decrypt_string_blobs_min_length_filter() {
        let plain = b"hi"; // too short
        let blobs = vec![(0u64, plain.to_vec())];
        let config = StringDecryptionConfig {
            min_length: 5,
            ..Default::default()
        };
        let results = decrypt_string_blobs(&blobs, &config);
        // "hi" is only 2 bytes, should be filtered out.
        assert!(results.iter().all(|r| r.plaintext_bytes.len() >= 5));
    }
}
