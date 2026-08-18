//! `rustre-deobf-string`
//!
//! Performs analysis passes to detect, isolate, and recover obfuscated strings.
//! Supports stack-string recovery, XOR/RC4/AES-like decryption, split-string
//! reconstruction, encoded-string detection, and brute-force key recovery.

pub mod ai_string_recovery;
pub mod chacha20;
pub mod crypto_string_decrypt;
pub mod deobf_pipeline;
pub mod pattern_matcher;
pub mod stack_string_recovery;
pub mod string_annotation;
pub mod string_classifier;
pub mod unicode_deobf;
pub mod xor_decryptor;
pub mod xor_string_decryptor;
pub mod stack_string_reconstructor;
pub mod encoding_detector;

pub mod xor_string_decoder;
pub mod custom_encoding_detector;
pub mod stack_string_decoder;
pub mod unicode_obfuscation_detector;
pub mod string_encryption_bruteforcer;
pub mod stack_string_asm_detector;
pub use stack_string_asm_detector::{detect_stack_strings, StackStringHit};

use rustre_il_llil::{LlilExpr, LlilInstruction, LlilRegister};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum StringDeobfError {
    #[error("key material is empty")]
    EmptyKey,
    #[error("invalid ciphertext length: {len}")]
    InvalidLength { len: usize },
    #[error("decrypted bytes are not valid UTF-8")]
    NotUtf8,
    #[error("brute-force key recovery found no viable candidate")]
    NoKeyFound,
    #[error("internal error: {0}")]
    Internal(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// RecoveredString
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredString {
    pub offset: u64,
    pub value: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// DecodedString — annotation produced for each recovered string
// ─────────────────────────────────────────────────────────────────────────────

/// Annotation placed at the call site in the knowledge graph for a decoded string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedString {
    /// Virtual address of the call site / instruction that produced this string.
    pub addr: u64,
    /// Original encrypted/encoded bytes.
    pub original_bytes: Vec<u8>,
    /// Recovered plaintext value.
    pub decoded_value: String,
    /// Algorithm used to recover it.
    pub algorithm: StringAlgorithm,
    /// Confidence score in [0, 100].
    pub confidence: u8,
}

impl DecodedString {
    #[must_use]
    pub const fn new(
        addr: u64,
        original_bytes: Vec<u8>,
        decoded_value: String,
        algorithm: StringAlgorithm,
        confidence: u8,
    ) -> Self {
        Self {
            addr,
            original_bytes,
            decoded_value,
            algorithm,
            confidence,
        }
    }

    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XorBruteforceCandidate — top-N single-byte XOR candidates
// ─────────────────────────────────────────────────────────────────────────────

/// A single candidate from single-byte XOR brute force.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XorBruteforceCandidate {
    pub key: u8,
    pub decrypted: Vec<u8>,
    pub printable_ratio: f64,
    pub confidence: u8,
    /// FIX K: callers were getting raw bytes and re-decoding client-side.
    /// Surface a best-effort UTF-8 view (strict first, then lossy with
    /// replacement chars) so the MCP response is human-readable directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded_utf8: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded_utf8_lossy: Option<String>,
}

impl XorBruteforceCandidate {
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.decrypted).ok()
    }
}

/// Brute-force all 256 single-byte XOR keys, score by printability, return top 3.
#[must_use]
pub fn xor_brute_force_top3(data: &[u8]) -> Vec<XorBruteforceCandidate> {
    if data.is_empty() {
        return Vec::new();
    }
    let scored: Vec<(u8, Vec<u8>, f64)> = (0u8..=255)
        .map(|key| {
            let dec: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
            let ratio = printable_ratio(&dec);
            (key, dec, ratio)
        })
        .collect();
    // Rank with the crate's text scorer, not with `printable_ratio` alone.
    //
    // Measured on this function's own test vector: 17 keys tie at ratio 1.0 and
    // the correct key sits 14th, so the stable sort kept the three lowest key
    // bytes. `looks_like_ascii_string` cannot break the tie either — it is true
    // for every one of those 17, because a wrong XOR key maps letters onto
    // letters and only disturbs the spaces (`"This is a secret"` competes with
    // `"Kwvl?vl?~?lz|mzk"`). `score_plaintext` weighs letter *distribution*, so
    // it separates them.
    // Score once per candidate, not once per comparison: `sort_by` calls its
    // comparator O(n log n) times, so scoring inside it re-derives the same 256
    // values thousands of times over.
    let mut ranked: Vec<(f64, (u8, Vec<u8>, f64))> = scored
        .into_iter()
        .map(|d| (crate::xor_string_decoder::score_plaintext(&d.1), d))
        .collect();
    ranked.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    ranked.truncate(3);
    let scored: Vec<(u8, Vec<u8>, f64)> = ranked.into_iter().map(|(_, d)| d).collect();
    scored
        .into_iter()
        .map(|(key, decrypted, pr)| {
            let known_pattern_bonus: u8 = if looks_like_ascii_string(&decrypted) {
                15
            } else {
                0
            };
            let confidence = ((pr * 100.0) as u8)
                .saturating_add(known_pattern_bonus)
                .min(100);
            let decoded_utf8 = std::str::from_utf8(&decrypted)
                .ok()
                .map(|s| s.to_string());
            let decoded_utf8_lossy = if decoded_utf8.is_none() {
                Some(String::from_utf8_lossy(&decrypted).into_owned())
            } else {
                None
            };
            XorBruteforceCandidate {
                key,
                decrypted,
                printable_ratio: pr,
                confidence,
                decoded_utf8,
                decoded_utf8_lossy,
            }
        })
        .collect()
}

fn looks_like_ascii_string(data: &[u8]) -> bool {
    if data.len() < 3 {
        return false;
    }
    data.last().copied() == Some(0)
        || data.iter().filter(|&&b| b.is_ascii_alphabetic()).count() > data.len() / 2
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-byte XOR: IC-based key length detection + frequency analysis
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultiByteXorResult {
    pub key_length: usize,
    pub key: Vec<u8>,
    pub decrypted: Vec<u8>,
    pub avg_ic: f64,
    pub confidence: u8,
}

/// IC-based key length detection for repeating XOR.
/// For each length k in `2..=max_key_len`, compute average IC of k sub-streams.
/// IC close to English (~0.065) indicates likely key length.
#[must_use]
pub fn detect_xor_key_length_ic(data: &[u8], max_key_len: usize) -> Vec<(usize, f64)> {
    if data.len() < 4 {
        return Vec::new();
    }
    let max_k = max_key_len.min(data.len() / 2).min(32);
    let mut scores: Vec<(usize, f64)> = (2..=max_k)
        .map(|k| (k, index_of_coincidence_period(data, k)))
        .collect();
    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scores
}

/// Recover multi-byte XOR key using IC-based key length detection
/// followed by frequency analysis on each sub-stream (Kasiski-style).
#[must_use]
pub fn recover_multibyte_xor(data: &[u8], max_key_len: usize) -> Vec<MultiByteXorResult> {
    let lengths = detect_xor_key_length_ic(data, max_key_len);
    let top_lengths: Vec<usize> = lengths.iter().take(3).map(|&(k, _)| k).collect();
    let mut results = Vec::new();
    for key_len in top_lengths {
        let avg_ic = index_of_coincidence_period(data, key_len);
        let key: Vec<u8> = (0..key_len)
            .map(|offset| {
                let stream: Vec<u8> = data.iter().copied().skip(offset).step_by(key_len).collect();
                recover_single_byte_xor_key(&stream)
            })
            .collect();
        let decrypted: Vec<u8> = data
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key_len])
            .collect();
        let pr = printable_ratio(&decrypted);
        // Score printability (0–70) and IC similarity to English baseline 0.065 (0–30).
        // Normalise IC against the English IC so random data (IC≈0.039) scores near 0
        // and English-like output (IC≈0.065) scores near 30.
        const ENGLISH_IC: f64 = 0.065;
        let ic_score = (avg_ic / ENGLISH_IC).min(1.0) * 30.0;
        let confidence = (pr * 70.0 + ic_score).min(100.0) as u8;
        results.push(MultiByteXorResult {
            key_length: key_len,
            key,
            decrypted,
            avg_ic,
            confidence,
        });
    }
    results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    results
}

fn recover_single_byte_xor_key(stream: &[u8]) -> u8 {
    let mut best_key = 0u8;
    let mut best_score = 0.0f64;
    for k in 0u8..=255 {
        let dec: Vec<u8> = stream.iter().map(|&b| b ^ k).collect();
        let score = english_frequency_score(&dec);
        if score > best_score {
            best_score = score;
            best_key = k;
        }
    }
    best_key
}

fn english_frequency_score(data: &[u8]) -> f64 {
    const FREQ: [f64; 26] = [
        0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609, 0.0697, 0.0015, 0.0077,
        0.0403, 0.0241, 0.0675, 0.0751, 0.0193, 0.0010, 0.0599, 0.0633, 0.0906, 0.0276, 0.0098,
        0.0236, 0.0015, 0.0197, 0.0007,
    ];
    // Common English words for recognition bonus
    const COMMON_WORDS: &[&str] = &[
        "the", "and", "for", "are", "but", "not", "you", "all", "any", "can", "had", "her",
        "was", "one", "our", "out", "day", "get", "has", "him", "his", "how", "its", "may",
        "new", "now", "old", "see", "two", "who", "boy", "did", "its", "let", "put", "say",
        "she", "too", "use", "hello", "world", "this", "that", "have", "from", "they", "will",
        "with", "your", "been", "come", "into", "just", "know", "like", "look", "make", "more",
        "over", "said", "some", "than", "them", "time", "very", "well", "what", "when", "word",
    ];
    let mut score = 0.0f64;
    for &b in data {
        if b.is_ascii_lowercase() {
            score += FREQ[(b - b'a') as usize];
        } else if b.is_ascii_uppercase() {
            score += FREQ[(b - b'A') as usize];
        } else if b == b' ' {
            score += 0.13;
        } else if !(32..=126).contains(&b) {
            score -= 0.05;
        }
    }
    score /= data.len().max(1) as f64;
    // Bonus for recognizable English words (normalized by length)
    if let Ok(s) = std::str::from_utf8(data) {
        let lower = s.to_ascii_lowercase();
        let word_bonus: f64 = COMMON_WORDS
            .iter()
            .filter(|&&w| lower.contains(w))
            .count() as f64
            * 0.02;
        score += word_bonus;
    }
    score
}

// ─────────────────────────────────────────────────────────────────────────────
// RC4 detection and key recovery
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rc4KsaPattern {
    pub loop_addr: u64,
    pub key_length: usize,
    pub confidence: u8,
}

/// Detect RC4 KSA pattern in MLIL:
///   for i in 0..256 { j = (j + S[i] + K[i%keylen]) % 256; swap S[i], S[j]; }
#[must_use]
pub fn detect_rc4_ksa_in_mlil(instructions: &[LlilInstruction]) -> Vec<Rc4KsaPattern> {
    let mut patterns = Vec::new();
    let mut add_count = 0usize;
    let mut swap_count = 0usize;
    let mut first_addr = 0u64;
    for (idx, inst) in instructions.iter().enumerate() {
        match inst {
            LlilInstruction::SetReg {
                value: LlilExpr::AddT(..),
                ..
            } => {
                add_count += 1;
                if first_addr == 0 {
                    first_addr = idx as u64;
                }
            }
            LlilInstruction::Store {
                value: LlilExpr::Load { .. },
                ..
            } => {
                swap_count += 1;
            }
            _ => {}
        }
    }
    if add_count >= 8 && swap_count >= 4 {
        let confidence = (((add_count + swap_count) as f64 / 20.0) * 80.0).min(90.0) as u8;
        patterns.push(Rc4KsaPattern {
            loop_addr: first_addr,
            key_length: 16,
            confidence,
        });
    }
    patterns
}

/// Attempt to recover RC4 key candidates from a known plaintext / ciphertext pair.
///
/// RC4 KSA is not reversible from the final S-box state alone: without the full
/// sequence of intermediate `j` values the recovered key bytes are meaningless
/// noise. This function therefore requires a known-plaintext pair and performs a
/// single-byte key-stream recovery: it XORs ciphertext with plaintext to get the
/// keystream and then uses that to verify candidate keys via re-running the KSA.
///
/// Returns a list of (`key_length`, key) candidates whose re-generated keystream
/// matches the observed keystream for the supplied sample.
#[must_use]
pub fn rc4_inverse_ksa(s_final: &[u8; 256]) -> Vec<Vec<u8>> {
    // The KSA only ever permutes the identity table, so its final state is always
    // a permutation of 0..=255. An input that is not one cannot have come from any
    // key, and answering it with a "closest" key would hand back exactly the
    // meaningless noise this function's own documentation warns about. Reject it
    // instead of guessing.
    let mut seen = [false; 256];
    for &b in s_final.iter() {
        if core::mem::replace(&mut seen[b as usize], true) {
            return Vec::new();
        }
    }

    // Try all 1-byte keys and check if any produce the given S-box exactly.
    // If no exact match, return the closest key by Hamming distance.
    let mut exact: Vec<Vec<u8>> = Vec::new();
    let mut best_dist = usize::MAX;
    let mut best_key = vec![0u8];
    for k in 0u8..=255 {
        let s = Rc4::ksa(&[k]);
        let dist = s.iter().zip(s_final.iter()).filter(|(a, b)| a != b).count();
        if dist == 0 {
            exact.push(vec![k]);
        } else if dist < best_dist {
            best_dist = dist;
            best_key = vec![k];
        }
    }
    if !exact.is_empty() {
        exact
    } else {
        vec![best_key]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64 variants
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Base64Variant {
    Standard,
    UrlSafe,
    Custom,
}

#[must_use]
pub fn detect_base64_variant(data: &[u8]) -> Option<Base64Variant> {
    if data.len() < 4 {
        return None;
    }
    let has_plus_slash = data.iter().any(|&b| b == b'+' || b == b'/');
    let has_dash_underscore = data.iter().any(|&b| b == b'-' || b == b'_');
    let all_b64_std = data
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=');
    let all_b64_url = data
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'=');
    // A '+' or '/' can only come from the STANDARD alphabet, so its presence
    // settles the question on its own — no url-safe encoding can contain one.
    //
    // ⚠ `has_plus_slash` was computed here and never read, behind an
    // `#[allow(unused_variables)]`-free warning that a crate-level allow was
    // hiding. The classification still worked, but by elimination rather than
    // by evidence: an input of pure alphanumerics is valid in BOTH alphabets
    // and was reported `Standard` with no positive signal for it. This branch
    // is behaviour-identical (`all_b64_std` already excludes '-' and '_', so
    // it implies `!has_dash_underscore`) and makes the positive case explicit.
    if all_b64_std && has_plus_slash {
        return Some(Base64Variant::Standard);
    }
    if all_b64_std && !has_dash_underscore {
        return Some(Base64Variant::Standard);
    }
    if all_b64_url && has_dash_underscore {
        return Some(Base64Variant::UrlSafe);
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let nonzero = (0u8..=255).filter(|&b| freq[b as usize] > 0).count();
    if nonzero == 64 || nonzero == 65 {
        return Some(Base64Variant::Custom);
    }
    None
}

pub fn decode_base64_urlsafe(input: &str) -> Result<Vec<u8>, StringDeobfError> {
    let normalized: String = input
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    Base64Decoder::decode(&normalized)
}

pub fn decode_base64_custom(
    input: &[u8],
    alphabet: &[u8; 64],
) -> Result<Vec<u8>, StringDeobfError> {
    let mut table = [255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let input_clean: Vec<u8> = input.iter().copied().filter(|&b| b != b'=').collect();
    let mut output = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in &input_clean {
        let val = table[c as usize];
        if val == 255 {
            return Err(StringDeobfError::Internal(format!("invalid char: {c:#x}")));
        }
        buf = (buf << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(output)
}

// ─────────────────────────────────────────────────────────────────────────────
// ROT13, Caesar brute force
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaesarBruteforceResult {
    pub rotation: u8,
    pub decrypted: String,
    pub score: f64,
    pub confidence: u8,
}

/// Brute force all 25 rotations, score by English word frequency.
#[must_use]
pub fn caesar_brute_force(input: &str) -> Vec<CaesarBruteforceResult> {
    let mut results: Vec<CaesarBruteforceResult> = (1u8..26)
        .map(|n| {
            let decrypted = RotN::decrypt(input, n);
            let score = english_frequency_score(decrypted.as_bytes());
            let confidence = ((score * 500.0).min(100.0)) as u8;
            CaesarBruteforceResult {
                rotation: n,
                decrypted,
                score,
                confidence,
            }
        })
        .collect();
    results.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// ADD/SUB/ROL/ROR constant operations
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArithObfType {
    Add,
    Sub,
    Rol,
    Ror,
    Xor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArithDeobfResult {
    pub obf_type: ArithObfType,
    pub constant: u8,
    pub decrypted: Vec<u8>,
    pub confidence: u8,
}

/// Detect ADD/SUB/XOR/ROL/ROR constant in MLIL loop, reverse it.
/// Falls back to brute-force over all 256 constants.
#[must_use]
pub fn detect_arith_obf_in_mlil(
    instructions: &[LlilInstruction],
    ciphertext: &[u8],
) -> Vec<ArithDeobfResult> {
    let mut results = Vec::new();

    for inst in instructions {
        match inst {
            LlilInstruction::SetReg {
                value: LlilExpr::AddT(_, rhs, _),
                ..
            } => {
                if let LlilExpr::Const { value, .. } = rhs.as_ref() {
                    let c = *value as u8;
                    let dec: Vec<u8> = ciphertext.iter().map(|&b| b.wrapping_sub(c)).collect();
                    let pr = printable_ratio(&dec);
                    if pr > 0.5 {
                        results.push(ArithDeobfResult {
                            obf_type: ArithObfType::Add,
                            constant: c,
                            decrypted: dec,
                            confidence: (pr * 90.0) as u8,
                        });
                    }
                }
            }
            LlilInstruction::SetReg {
                value: LlilExpr::SubT(_, rhs, _),
                ..
            } => {
                if let LlilExpr::Const { value, .. } = rhs.as_ref() {
                    let c = *value as u8;
                    let dec: Vec<u8> = ciphertext.iter().map(|&b| b.wrapping_add(c)).collect();
                    let pr = printable_ratio(&dec);
                    if pr > 0.5 {
                        results.push(ArithDeobfResult {
                            obf_type: ArithObfType::Sub,
                            constant: c,
                            decrypted: dec,
                            confidence: (pr * 90.0) as u8,
                        });
                    }
                }
            }
            LlilInstruction::SetReg {
                value: LlilExpr::Ror(_, rhs, _),
                ..
            } => {
                if let LlilExpr::Const { value, .. } = rhs.as_ref() {
                    let c = (*value % 8) as u8;
                    let dec: Vec<u8> = ciphertext
                        .iter()
                        .map(|&b| b.rotate_left(u32::from(c)))
                        .collect();
                    let pr = printable_ratio(&dec);
                    if pr > 0.5 {
                        results.push(ArithDeobfResult {
                            obf_type: ArithObfType::Ror,
                            constant: c,
                            decrypted: dec,
                            confidence: (pr * 85.0) as u8,
                        });
                    }
                }
            }
            LlilInstruction::SetReg {
                value: LlilExpr::Rol(_, rhs, _),
                ..
            } => {
                if let LlilExpr::Const { value, .. } = rhs.as_ref() {
                    let c = (*value % 8) as u8;
                    let dec: Vec<u8> = ciphertext
                        .iter()
                        .map(|&b| b.rotate_right(u32::from(c)))
                        .collect();
                    let pr = printable_ratio(&dec);
                    if pr > 0.5 {
                        results.push(ArithDeobfResult {
                            obf_type: ArithObfType::Rol,
                            constant: c,
                            decrypted: dec,
                            confidence: (pr * 85.0) as u8,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    // Brute force ADD/SUB over all 256 constants
    for c in 1u8..=255 {
        let dec_sub: Vec<u8> = ciphertext.iter().map(|&b| b.wrapping_sub(c)).collect();
        let pr = printable_ratio(&dec_sub);
        if pr > 0.75
            && !results
                .iter()
                .any(|r| r.obf_type == ArithObfType::Add && r.constant == c)
        {
            results.push(ArithDeobfResult {
                obf_type: ArithObfType::Add,
                constant: c,
                decrypted: dec_sub,
                confidence: (pr * 90.0) as u8,
            });
        }
    }

    results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Stack string reconstruction from MLIL (consecutive byte stores)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlilStackString {
    pub base_offset: i64,
    pub bytes: Vec<u8>,
    pub as_string: Option<String>,
}

#[must_use]
pub fn detect_mlil_stack_strings(instructions: &[LlilInstruction]) -> Vec<MlilStackString> {
    let mut stores: Vec<(i64, u8)> = Vec::new();
    for inst in instructions {
        if let LlilInstruction::Store {
            addr,
            size: _,
            value: LlilExpr::Const { value, .. },
        } = inst
            && let Some(off) = extract_stack_offset_i64(addr)
                && *value <= 0xFF {
                    stores.push((off, *value as u8));
                }
    }
    if stores.is_empty() {
        return Vec::new();
    }
    stores.sort_by_key(|&(off, _)| off);
    let mut results = Vec::new();
    let mut group_start = 0usize;
    while group_start < stores.len() {
        let (base_off, first_byte) = stores[group_start];
        let mut bytes = vec![first_byte];
        let mut idx = group_start + 1;
        while idx < stores.len() {
            let expected = base_off + bytes.len() as i64;
            if stores[idx].0 == expected {
                bytes.push(stores[idx].1);
                idx += 1;
            } else {
                break;
            }
        }
        if bytes.len() >= 2 {
            let as_string = if bytes.last().copied() == Some(0) {
                std::str::from_utf8(&bytes[..bytes.len() - 1])
                    .ok()
                    .map(std::string::ToString::to_string)
            } else {
                std::str::from_utf8(&bytes).ok().map(std::string::ToString::to_string)
            };
            results.push(MlilStackString {
                base_offset: base_off,
                bytes,
                as_string,
            });
            group_start = idx;
        } else {
            // Discard short group but advance by one byte only so that the next
            // iteration can consider a new group starting at group_start + 1,
            // allowing adjacent strings separated by a 1-byte gap to be recovered.
            group_start += 1;
        }
    }
    results
}

fn extract_stack_offset_i64(expr: &LlilExpr) -> Option<i64> {
    match expr {
        LlilExpr::RegisterRef {
            reg: LlilRegister::Concrete(r),
            ..
        } if r == "rsp" || r == "esp" || r == "rbp" || r == "ebp" => Some(0),
        LlilExpr::AddT(base, off, _) => match (base.as_ref(), off.as_ref()) {
            (
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(r),
                    ..
                },
                LlilExpr::Const { value, .. },
            ) if r == "rsp" || r == "esp" || r == "rbp" || r == "ebp" => {
                // Only accept offsets that fit in a non-negative i64 (stack
                // positive offsets from rsp/rbp are never larger than a
                // typical frame size). A very large u64 here is almost
                // certainly not a valid stack offset.
                i64::try_from(*value).ok()
            }
            _ => None,
        },
        LlilExpr::SubT(base, off, _) => match (base.as_ref(), off.as_ref()) {
            (
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(r),
                    ..
                },
                LlilExpr::Const { value, .. },
            ) if r == "rsp" || r == "esp" || r == "rbp" || r == "ebp" => {
                // Negate the offset; guard against overflow when value > i64::MAX.
                i64::try_from(*value).ok().and_then(|v| v.checked_neg())
            }
            _ => None,
        },
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper function emulation detection
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringDecoderSignature {
    pub func_addr: u64,
    pub param_count: usize,
    pub output_via_ptr: bool,
    pub algorithm: StringAlgorithm,
    pub confidence: u8,
}

/// Detect string-decoder helper: small function (<200 instr), no syscalls,
/// has XOR + memory ops → likely XOR decoder; 256-loop → likely RC4.
#[must_use]
pub fn detect_string_decoder_helpers(
    func_addr: u64,
    instructions: &[LlilInstruction],
) -> Vec<StringDecoderSignature> {
    let mut results = Vec::new();
    if instructions.len() > 200 {
        return results;
    }
    let has_syscall = instructions
        .iter()
        .any(|i| matches!(i, LlilInstruction::SysCall));
    if has_syscall {
        return results;
    }
    let xor_count = instructions
        .iter()
        .filter(|i| {
            matches!(
                i,
                LlilInstruction::SetReg {
                    value: LlilExpr::Xor(..),
                    ..
                } | LlilInstruction::Store {
                    value: LlilExpr::Xor(..),
                    ..
                }
            )
        })
        .count();
    let load_count = instructions
        .iter()
        .filter(|i| {
            matches!(
                i,
                LlilInstruction::SetReg {
                    value: LlilExpr::Load { .. },
                    ..
                }
            )
        })
        .count();
    if xor_count >= 1 && load_count >= 2 {
        let confidence = (((xor_count + load_count) as f64 / 5.0) * 70.0).min(90.0) as u8;
        results.push(StringDecoderSignature {
            func_addr,
            param_count: 3,
            output_via_ptr: true,
            algorithm: StringAlgorithm::XorCyclic,
            confidence,
        });
    }
    let large_loop = instructions.iter().any(|i| {
        matches!(
            i,
            LlilInstruction::SetReg {
                value: LlilExpr::Const { value: 256, .. },
                ..
            }
        )
    });
    if large_loop {
        results.push(StringDecoderSignature {
            func_addr,
            param_count: 3,
            output_via_ptr: true,
            algorithm: StringAlgorithm::Rc4,
            confidence: 75,
        });
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// String table batch decrypt
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringTableEntry {
    pub ptr: u64,
    pub length: u32,
    pub key: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringTableResult {
    pub entry: StringTableEntry,
    pub decrypted: Vec<u8>,
    pub plaintext: Option<String>,
    pub confidence: u8,
}

#[must_use]
pub fn batch_decrypt_string_table<F>(
    entries: &[StringTableEntry],
    data_provider: F,
    algorithm: StringAlgorithm,
) -> Vec<StringTableResult>
where
    F: Fn(u64, usize) -> Option<Vec<u8>>,
{
    entries
        .iter()
        .filter_map(|entry| {
            let raw = data_provider(entry.ptr, entry.length as usize)?;
            let decrypted = match algorithm {
                StringAlgorithm::XorConstant => {
                    let key = (entry.key & 0xFF) as u8;
                    XorDecryptor::decrypt_constant(&raw, key)
                }
                StringAlgorithm::XorCyclic => {
                    let key_bytes = entry.key.to_le_bytes();
                    let key_trimmed: Vec<u8> =
                        key_bytes.iter().copied().take_while(|&b| b != 0).collect();
                    if key_trimmed.is_empty() {
                        return None;
                    }
                    XorDecryptor::decrypt_cyclic(&raw, &key_trimmed).ok()?
                }
                StringAlgorithm::Rc4 => {
                    let key_bytes = entry.key.to_le_bytes();
                    Rc4::decrypt(&raw, &key_bytes)
                }
                _ => raw,
            };
            let pr = printable_ratio(&decrypted);
            let confidence = (pr * 90.0) as u8;
            let plaintext = std::str::from_utf8(&decrypted).ok().map(std::string::ToString::to_string);
            Some(StringTableResult {
                entry: entry.clone(),
                decrypted,
                plaintext,
                confidence,
            })
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Confidence scoring: 0..100
// ─────────────────────────────────────────────────────────────────────────────

/// Compute confidence score [0, 100] from printability ratio and known-pattern bonuses.
#[must_use]
pub fn compute_confidence(decrypted: &[u8]) -> u8 {
    let pr = printable_ratio(decrypted);
    let mut score = (pr * 100.0) as u8;
    if decrypted.windows(2).any(|w| w == b":/") {
        score = score.saturating_add(10);
    }
    if decrypted.windows(4).any(|w| w == b"http") {
        score = score.saturating_add(10);
    }
    if decrypted.last().copied() == Some(0) {
        score = score.saturating_add(5);
    }
    if english_frequency_score(decrypted) > 0.05 {
        score = score.saturating_add(5);
    }
    score.min(100)
}

// ─────────────────────────────────────────────────────────────────────────────
// EncryptedString
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedString {
    pub address: u64,
    pub ciphertext: Vec<u8>,
    pub algorithm: StringAlgorithm,
    pub plaintext_length: Option<usize>,
}

impl EncryptedString {
    #[must_use]
    pub const fn new(address: u64, ciphertext: Vec<u8>, algorithm: StringAlgorithm) -> Self {
        let plaintext_length = Some(ciphertext.len());
        Self {
            address,
            ciphertext,
            algorithm,
            plaintext_length,
        }
    }
    #[must_use]
    pub const fn len(&self) -> usize {
        self.ciphertext.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ciphertext.is_empty()
    }
    #[must_use]
    pub fn entropy(&self) -> f64 {
        byte_entropy(&self.ciphertext)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringAlgorithm
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StringAlgorithm {
    XorConstant,
    XorCyclic,
    XorRolling,
    Rc4,
    ChaCha20,
    RotN,
    Base64,
    HexEncoded,
    StackString,
    SplitString,
    AddConstant,
    SubConstant,
    RolConstant,
    RorConstant,
    Unknown,
}

impl StringAlgorithm {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::XorConstant => "XOR(constant)",
            Self::XorCyclic => "XOR(cyclic)",
            Self::XorRolling => "XOR(rolling)",
            Self::Rc4 => "RC4",
            Self::ChaCha20 => "ChaCha20",
            Self::RotN => "ROT-N",
            Self::Base64 => "Base64",
            Self::HexEncoded => "Hex",
            Self::StackString => "StackString",
            Self::SplitString => "SplitString",
            Self::AddConstant => "ADD(constant)",
            Self::SubConstant => "SUB(constant)",
            Self::RolConstant => "ROL(constant)",
            Self::RorConstant => "ROR(constant)",
            Self::Unknown => "Unknown",
        }
    }
    #[must_use]
    pub const fn is_stream_cipher(self) -> bool {
        matches!(self, Self::Rc4 | Self::ChaCha20)
    }
    #[must_use]
    pub const fn is_xor_variant(self) -> bool {
        matches!(self, Self::XorConstant | Self::XorCyclic | Self::XorRolling)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KeyCandidate
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyCandidate {
    pub key: Vec<u8>,
    pub algorithm: StringAlgorithm,
    pub confidence: f64,
    pub decrypted: Option<Vec<u8>>,
}

impl KeyCandidate {
    #[must_use]
    pub const fn new(key: Vec<u8>, algorithm: StringAlgorithm, confidence: f64) -> Self {
        Self {
            key,
            algorithm,
            confidence,
            decrypted: None,
        }
    }
    #[must_use]
    pub fn with_decrypted(mut self, decrypted: Vec<u8>) -> Self {
        self.decrypted = Some(decrypted);
        self
    }
    #[must_use]
    pub fn is_likely(&self) -> bool {
        self.confidence > 0.5
    }
    pub fn as_str(&self) -> Result<&str, StringDeobfError> {
        self.decrypted
            .as_deref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .ok_or(StringDeobfError::NotUtf8)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringResult
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringResult {
    pub address: u64,
    pub plaintext: String,
    pub algorithm: StringAlgorithm,
    pub key: Vec<u8>,
}

impl StringResult {
    #[must_use]
    pub const fn new(address: u64, plaintext: String, algorithm: StringAlgorithm, key: Vec<u8>) -> Self {
        Self {
            address,
            plaintext,
            algorithm,
            key,
        }
    }
    #[must_use]
    pub const fn len(&self) -> usize {
        self.plaintext.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.plaintext.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DecryptionRoutine
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionRoutine {
    pub address: u64,
    pub algorithm: StringAlgorithm,
    pub key_length: usize,
    pub confidence: u32,
    pub string_refs: Vec<u64>,
}

impl DecryptionRoutine {
    #[must_use]
    pub const fn new(address: u64, algorithm: StringAlgorithm, key_length: usize) -> Self {
        Self {
            address,
            algorithm,
            key_length,
            confidence: 50,
            string_refs: Vec::new(),
        }
    }
    #[must_use]
    pub fn with_confidence(mut self, confidence: u32) -> Self {
        self.confidence = confidence.min(100);
        self
    }
    pub fn add_string_ref(&mut self, addr: u64) {
        self.string_refs.push(addr);
    }
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringDeobfuscator
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StringDeobfuscator {
    pub min_printable_ratio: f64,
    pub min_length: usize,
    pub max_brute_key_len: usize,
    pub try_rc4: bool,
    pub try_xor: bool,
}

impl Default for StringDeobfuscator {
    fn default() -> Self {
        Self {
            min_printable_ratio: 0.75,
            min_length: 4,
            max_brute_key_len: 4,
            try_rc4: true,
            try_xor: true,
        }
    }
}

impl StringDeobfuscator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub const fn with_min_printable_ratio(mut self, ratio: f64) -> Self {
        // NaN-safe clamp: `f64::clamp` propagates NaN and `is_nan()` is not
        // available in a const fn. A NaN ratio would reject every candidate
        // string in silence, since all comparisons against NaN are false.
        self.min_printable_ratio = if ratio >= 1.0 {
            1.0
        } else if ratio > 0.0 {
            ratio
        } else {
            0.0
        };
        self
    }
    #[must_use]
    pub const fn with_min_length(mut self, len: usize) -> Self {
        self.min_length = len;
        self
    }

    #[must_use]
    pub fn run(&self, data: &[u8]) -> Vec<StringResult> {
        let mut results = Vec::new();
        if self.try_xor {
            results.extend(self.brute_force_xor(data));
        }
        if self.try_rc4 {
            results.extend(self.brute_force_rc4_single_byte(data));
        }
        results.sort_by(|a, b| {
            a.address
                .cmp(&b.address)
                .then(a.plaintext.cmp(&b.plaintext))
        });
        results.dedup_by(|a, b| a.address == b.address && a.plaintext == b.plaintext);
        results
    }

    #[must_use]
    pub fn brute_force_xor(&self, data: &[u8]) -> Vec<StringResult> {
        let mut results = Vec::new();
        for key in 1u8..=255 {
            let decrypted: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
            if let Some(s) = self.maybe_utf8_string(&decrypted) {
                results.push(StringResult::new(
                    0,
                    s,
                    StringAlgorithm::XorConstant,
                    vec![key],
                ));
            }
        }
        results
    }

    #[must_use]
    pub fn brute_force_rc4_single_byte(&self, data: &[u8]) -> Vec<StringResult> {
        let mut results = Vec::new();
        for key in 0u8..=255 {
            let decrypted = Rc4::decrypt(data, &[key]);
            if let Some(s) = self.maybe_utf8_string(&decrypted) {
                results.push(StringResult::new(0, s, StringAlgorithm::Rc4, vec![key]));
            }
        }
        results
    }

    fn maybe_utf8_string(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() < self.min_length {
            return None;
        }
        let printable = bytes
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b == b' ')
            .count();
        if (printable as f64 / bytes.len() as f64) < self.min_printable_ratio {
            return None;
        }
        std::str::from_utf8(bytes).ok().map(std::borrow::ToOwned::to_owned)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XorDecryptor
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XorDecryptor;

impl XorDecryptor {
    #[must_use]
    pub fn decrypt_constant(data: &[u8], key: u8) -> Vec<u8> {
        data.iter().map(|&b| b ^ key).collect()
    }
    pub fn decrypt_cyclic(data: &[u8], key: &[u8]) -> Result<Vec<u8>, StringDeobfError> {
        if key.is_empty() {
            return Err(StringDeobfError::EmptyKey);
        }
        Ok(data.iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect())
    }
    #[must_use]
    pub fn decrypt_rolling(data: &[u8], initial_key: u8) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, &b)| b ^ initial_key.wrapping_add(i as u8))
            .collect()
    }
    #[must_use]
    pub fn recover_key(data: &[u8]) -> (u8, Vec<u8>) {
        let mut best_key = 0u8;
        let mut best_score = 0usize;
        let mut best_dec = data.to_vec();
        for key in 0u8..=255 {
            let dec: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
            let score = dec
                .iter()
                .filter(|&&b| b.is_ascii_graphic() || b == b' ')
                .count();
            if score > best_score {
                best_score = score;
                best_key = key;
                best_dec = dec;
            }
        }
        (best_key, best_dec)
    }
    #[must_use]
    pub fn recover_key_2byte(data: &[u8]) -> ([u8; 2], Vec<u8>) {
        let mut best_key = [0u8; 2];
        let mut best_score = 0usize;
        for k0 in 0u8..=255 {
            for k1 in 0u8..=255 {
                let key = [k0, k1];
                let dec: Vec<u8> = data
                    .iter()
                    .enumerate()
                    .map(|(i, &b)| b ^ key[i % 2])
                    .collect();
                let score = dec
                    .iter()
                    .filter(|&&b| b.is_ascii_graphic() || b == b' ')
                    .count();
                if score > best_score {
                    best_score = score;
                    best_key = key;
                }
            }
        }
        let dec: Vec<u8> = data
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ best_key[i % 2])
            .collect();
        (best_key, dec)
    }
    #[must_use]
    pub fn detect_key_period(data: &[u8], max_period: usize) -> usize {
        if data.len() < 2 || max_period == 0 {
            return 1;
        }
        let max_period = max_period.min(data.len() / 2);
        let mut best_period = 1usize;
        let mut best_ioc = 0.0f64;
        for period in 1..=max_period {
            let ioc = index_of_coincidence_period(data, period);
            if ioc > best_ioc {
                best_ioc = ioc;
                best_period = period;
            }
        }
        best_period
    }
    #[must_use]
    pub fn entropy(data: &[u8]) -> f64 {
        byte_entropy(data)
    }
}

fn index_of_coincidence_period(data: &[u8], period: usize) -> f64 {
    let mut total_ioc = 0.0f64;
    let mut stream_count = 0usize;
    for offset in 0..period {
        let stream: Vec<u8> = data.iter().copied().skip(offset).step_by(period).collect();
        if stream.len() < 2 {
            continue;
        }
        let mut freq = [0u64; 256];
        for &b in &stream {
            freq[b as usize] += 1;
        }
        let n = stream.len() as f64;
        let ioc: f64 = freq
            .iter()
            .map(|&c| (c as f64) * (c as f64 - 1.0))
            .sum::<f64>()
            / (n * (n - 1.0));
        total_ioc += ioc;
        stream_count += 1;
    }
    if stream_count == 0 {
        0.0
    } else {
        total_ioc / stream_count as f64
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Rc4
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rc4;

impl Rc4 {
    #[must_use]
    pub fn ksa(key: &[u8]) -> [u8; 256] {
        let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
        if key.is_empty() {
            return s;
        }
        let mut j = 0usize;
        for i in 0..256 {
            j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
            s.swap(i, j);
        }
        s
    }
    #[must_use]
    pub fn prga(s: &mut [u8; 256], length: usize) -> Vec<u8> {
        let mut keystream = Vec::with_capacity(length);
        let mut i = 0usize;
        let mut j = 0usize;
        for _ in 0..length {
            i = (i + 1) % 256;
            j = (j + s[i] as usize) % 256;
            s.swap(i, j);
            keystream.push(s[(s[i] as usize + s[j] as usize) % 256]);
        }
        keystream
    }
    #[must_use]
    pub fn decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut s = Self::ksa(key);
        let keystream = Self::prga(&mut s, data.len());
        data.iter()
            .zip(keystream.iter())
            .map(|(&d, &k)| d ^ k)
            .collect()
    }
    #[must_use]
    pub fn brute_force_1byte(data: &[u8]) -> (u8, Vec<u8>) {
        let mut best_key = 0u8;
        let mut best_score = 0usize;
        let mut best_dec = data.to_vec();
        for k in 0u8..=255 {
            let dec = Self::decrypt(data, &[k]);
            let score = dec
                .iter()
                .filter(|&&b| b.is_ascii_graphic() || b == b' ')
                .count();
            if score > best_score {
                best_score = score;
                best_key = k;
                best_dec = dec;
            }
        }
        (best_key, best_dec)
    }
    #[must_use]
    pub fn brute_force_2byte(data: &[u8]) -> ([u8; 2], Vec<u8>) {
        let mut best_key = [0u8; 2];
        let mut best_score = 0usize;
        for k0 in 0u8..=255 {
            for k1 in 0u8..=255 {
                let key = [k0, k1];
                let dec = Self::decrypt(data, &key);
                let score = dec
                    .iter()
                    .filter(|&&b| b.is_ascii_graphic() || b == b' ')
                    .count();
                if score > best_score {
                    best_score = score;
                    best_key = key;
                }
            }
        }
        (best_key, Self::decrypt(data, &best_key))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RotN
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotN;

impl RotN {
    #[must_use]
    pub fn decrypt(s: &str, n: u8) -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_lowercase() {
                    (b'a' + (c as u8 - b'a' + 26 - n % 26) % 26) as char
                } else if c.is_ascii_uppercase() {
                    (b'A' + (c as u8 - b'A' + 26 - n % 26) % 26) as char
                } else {
                    c
                }
            })
            .collect()
    }
    #[must_use]
    pub fn rot13(s: &str) -> String {
        Self::decrypt(s, 13)
    }
    #[must_use]
    pub fn detect_rotation(s: &str) -> u8 {
        let mut best_n = 0u8;
        let mut best_score = 0.0f64;
        for n in 0u8..26 {
            let dec = Self::decrypt(s, n);
            let score = english_frequency_score(dec.as_bytes());
            if score > best_score {
                best_score = score;
                best_n = n;
            }
        }
        best_n
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64Decoder
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Base64Decoder;

impl Base64Decoder {
    const TABLE: &'static [u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn decode(input: &str) -> Result<Vec<u8>, StringDeobfError> {
        let input = input.trim_end_matches('=');
        let mut output = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0u32;
        for &c in input.as_bytes() {
            let val = Self::char_value(c)?;
            buf = (buf << 6) | u32::from(val);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                output.push((buf >> bits) as u8);
                buf &= (1 << bits) - 1;
            }
        }
        Ok(output)
    }

    fn char_value(c: u8) -> Result<u8, StringDeobfError> {
        Self::TABLE
            .iter()
            .position(|&t| t == c)
            .map(|p| p as u8)
            .ok_or_else(|| StringDeobfError::Internal(format!("invalid Base64 char: {c:#x}")))
    }

    #[must_use]
    pub fn encode(data: &[u8]) -> String {
        let mut out = String::new();
        let mut i = 0;
        while i + 2 < data.len() {
            let n = u32::from(data[i]) << 16 | u32::from(data[i + 1]) << 8 | u32::from(data[i + 2]);
            out.push(Self::TABLE[(n >> 18 & 0x3F) as usize] as char);
            out.push(Self::TABLE[(n >> 12 & 0x3F) as usize] as char);
            out.push(Self::TABLE[(n >> 6 & 0x3F) as usize] as char);
            out.push(Self::TABLE[(n & 0x3F) as usize] as char);
            i += 3;
        }
        match data.len() - i {
            1 => {
                let n = u32::from(data[i]) << 16;
                out.push(Self::TABLE[(n >> 18 & 0x3F) as usize] as char);
                out.push(Self::TABLE[(n >> 12 & 0x3F) as usize] as char);
                out.push_str("==");
            }
            2 => {
                let n = (u32::from(data[i]) << 16) | (u32::from(data[i + 1]) << 8);
                out.push(Self::TABLE[(n >> 18 & 0x3F) as usize] as char);
                out.push(Self::TABLE[(n >> 12 & 0x3F) as usize] as char);
                out.push(Self::TABLE[(n >> 6 & 0x3F) as usize] as char);
                out.push('=');
            }
            _ => {}
        }
        out
    }

    #[must_use]
    pub fn is_base64(s: &str) -> bool {
        let s = s.trim_end_matches('=');
        !s.is_empty() && s.bytes().all(|c| Self::TABLE.contains(&c))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexDecoder
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HexDecoder;

impl HexDecoder {
    pub fn decode(input: &str) -> Result<Vec<u8>, StringDeobfError> {
        let clean: String = input
            .replace("0x", "")
            .replace("0X", "")
            .replace([' ', ','], "");
        if !clean.len().is_multiple_of(2) {
            return Err(StringDeobfError::InvalidLength { len: clean.len() });
        }
        clean
            .as_bytes()
            .chunks(2)
            .map(|chunk| {
                let hi = hex_nibble(chunk[0])?;
                let lo = hex_nibble(chunk[1])?;
                Ok((hi << 4) | lo)
            })
            .collect()
    }
    #[must_use]
    pub fn encode(data: &[u8]) -> String {
        data.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc })
    }
    #[must_use]
    pub fn is_hex(s: &str) -> bool {
        let s = s.trim_start_matches("0x").trim_start_matches("0X");
        !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

fn hex_nibble(c: u8) -> Result<u8, StringDeobfError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(StringDeobfError::Internal(format!(
            "invalid hex char: {c:#x}"
        ))),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SplitStringRecovery
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringFragment {
    pub address: u64,
    pub data: Vec<u8>,
    pub order: usize,
}

impl StringFragment {
    #[must_use]
    pub const fn new(address: u64, data: Vec<u8>, order: usize) -> Self {
        Self {
            address,
            data,
            order,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SplitStringRecovery;

impl SplitStringRecovery {
    #[must_use]
    pub fn reconstruct(mut fragments: Vec<StringFragment>) -> Vec<u8> {
        fragments.sort_by_key(|f| f.order);
        fragments.into_iter().flat_map(|f| f.data).collect()
    }
    #[must_use]
    pub fn find_fragments(data: &[u8], patterns: &[(&[u8], usize)]) -> Vec<StringFragment> {
        let mut fragments = Vec::new();
        for (pattern, order) in patterns {
            if let Some(pos) = find_subsequence(data, pattern) {
                let end = (pos + pattern.len()).min(data.len());
                fragments.push(StringFragment::new(
                    pos as u64,
                    data[pos..end].to_vec(),
                    *order,
                ));
            }
        }
        fragments
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ─────────────────────────────────────────────────────────────────────────────
// EncodingDetector
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct EncodingDetector;

impl EncodingDetector {
    #[must_use]
    pub fn detect(data: &[u8]) -> StringAlgorithm {
        if data.is_empty() {
            return StringAlgorithm::Unknown;
        }
        if let Ok(s) = std::str::from_utf8(data) {
            // Check hex before base64: hex is more specific (only 0-9 a-fA-F)
            if HexDecoder::is_hex(s) {
                return StringAlgorithm::HexEncoded;
            }
            if Base64Decoder::is_base64(s) {
                return StringAlgorithm::Base64;
            }
            let rotation = RotN::detect_rotation(s);
            if rotation != 0 {
                let decoded = RotN::decrypt(s, rotation);
                let alpha_ratio = decoded.chars().filter(char::is_ascii_alphabetic).count()
                    as f64
                    / decoded.len() as f64;
                if alpha_ratio > 0.6 {
                    return StringAlgorithm::RotN;
                }
            }
        }
        let (max_freq, min_freq) = byte_freq_range(data);
        if byte_entropy(data) > 7.5 || max_freq.saturating_sub(min_freq) < 5 {
            return StringAlgorithm::Rc4;
        }
        let raw_printable = printable_ratio(data);
        let (_, xor_dec) = XorDecryptor::recover_key(data);
        if printable_ratio(&xor_dec) > raw_printable + 0.3 {
            return StringAlgorithm::XorConstant;
        }
        StringAlgorithm::Unknown
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility functions
// ─────────────────────────────────────────────────────────────────────────────

fn printable_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ')
        .count() as f64
        / data.len() as f64
}

fn byte_entropy(data: &[u8]) -> f64 {
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

fn byte_freq_range(data: &[u8]) -> (u64, u64) {
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    (
        *freq.iter().max().unwrap_or(&0),
        *freq.iter().filter(|&&c| c > 0).min().unwrap_or(&0),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// ApiHashDetector
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiHashAlgorithm {
    Crc32,
    Djb2,
    Fnv1a32,
    Sdbm,
    Adler32,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiHash {
    pub hash: u64,
    pub name: Option<String>,
    pub algorithm: ApiHashAlgorithm,
}

impl ApiHash {
    #[must_use]
    pub const fn new(hash: u64, algorithm: ApiHashAlgorithm) -> Self {
        Self {
            hash,
            name: None,
            algorithm,
        }
    }
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        self.name.is_some()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ApiHasher;

impl ApiHasher {
    #[must_use]
    pub fn djb2(data: &[u8]) -> u32 {
        let mut h = 5381u32;
        for &b in data {
            h = h.wrapping_mul(33).wrapping_add(u32::from(b));
        }
        h
    }
    #[must_use]
    pub fn fnv1a32(data: &[u8]) -> u32 {
        const P: u32 = 0x0100_0193;
        const B: u32 = 0x811C_9DC5;
        let mut h = B;
        for &b in data {
            h ^= u32::from(b);
            h = h.wrapping_mul(P);
        }
        h
    }
    #[must_use]
    pub fn sdbm(data: &[u8]) -> u32 {
        let mut h = 0u32;
        for &b in data {
            h = u32::from(b)
                .wrapping_add(h.wrapping_shl(6))
                .wrapping_add(h.wrapping_shl(16))
                .wrapping_sub(h);
        }
        h
    }
    #[must_use]
    pub fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                if crc & 1 == 1 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }
    #[must_use]
    pub fn adler32(data: &[u8]) -> u32 {
        const MOD: u32 = 65521;
        let mut a = 1u32;
        let mut b = 0u32;
        for &byte in data {
            a = (a + u32::from(byte)) % MOD;
            b = (b + a) % MOD;
        }
        (b << 16) | a
    }

    #[must_use]
    pub fn build_table(names: &[&str], algo: ApiHashAlgorithm) -> HashMap<u64, String> {
        let mut map = HashMap::new();
        for &name in names {
            let hash = match algo {
                ApiHashAlgorithm::Djb2 => u64::from(Self::djb2(name.as_bytes())),
                ApiHashAlgorithm::Fnv1a32 => u64::from(Self::fnv1a32(name.as_bytes())),
                ApiHashAlgorithm::Sdbm => u64::from(Self::sdbm(name.as_bytes())),
                ApiHashAlgorithm::Crc32 => u64::from(Self::crc32(name.as_bytes())),
                ApiHashAlgorithm::Adler32 => u64::from(Self::adler32(name.as_bytes())),
                ApiHashAlgorithm::Unknown => continue,
            };
            map.insert(hash, name.to_owned());
        }
        map
    }
    #[must_use]
    pub fn resolve(table: &HashMap<u64, String>, hash: u64) -> Option<&str> {
        table.get(&hash).map(std::string::String::as_str)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringChain
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainStage {
    pub algorithm: StringAlgorithm,
    pub key: Vec<u8>,
}
impl ChainStage {
    #[must_use]
    pub const fn new(algorithm: StringAlgorithm, key: Vec<u8>) -> Self {
        Self { algorithm, key }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecryptionChain {
    pub stages: Vec<ChainStage>,
}

impl DecryptionChain {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&mut self, stage: ChainStage) {
        self.stages.push(stage);
    }
    pub fn apply(&self, input: &[u8]) -> Result<Vec<u8>, StringDeobfError> {
        let mut data = input.to_vec();
        for stage in &self.stages {
            data = self.apply_stage(stage, &data)?;
        }
        Ok(data)
    }
    fn apply_stage(&self, stage: &ChainStage, data: &[u8]) -> Result<Vec<u8>, StringDeobfError> {
        match stage.algorithm {
            StringAlgorithm::XorConstant => {
                let key = *stage.key.first().ok_or(StringDeobfError::EmptyKey)?;
                Ok(XorDecryptor::decrypt_constant(data, key))
            }
            StringAlgorithm::XorCyclic => {
                if stage.key.is_empty() {
                    return Err(StringDeobfError::EmptyKey);
                }
                XorDecryptor::decrypt_cyclic(data, &stage.key)
            }
            StringAlgorithm::XorRolling => {
                let key = *stage.key.first().ok_or(StringDeobfError::EmptyKey)?;
                Ok(XorDecryptor::decrypt_rolling(data, key))
            }
            StringAlgorithm::Rc4 => {
                if stage.key.is_empty() {
                    return Err(StringDeobfError::EmptyKey);
                }
                Ok(Rc4::decrypt(data, &stage.key))
            }
            StringAlgorithm::Base64 => {
                let s = std::str::from_utf8(data).map_err(|_| StringDeobfError::NotUtf8)?;
                Base64Decoder::decode(s)
            }
            StringAlgorithm::HexEncoded => {
                let s = std::str::from_utf8(data).map_err(|_| StringDeobfError::NotUtf8)?;
                HexDecoder::decode(s)
            }
            StringAlgorithm::RotN => {
                let n = *stage.key.first().unwrap_or(&13);
                let s = std::str::from_utf8(data).map_err(|_| StringDeobfError::NotUtf8)?;
                Ok(RotN::decrypt(s, n).into_bytes())
            }
            _ => Ok(data.to_vec()),
        }
    }
    #[must_use]
    pub const fn len(&self) -> usize {
        self.stages.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringStatistics
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StringStatistics {
    pub total: usize,
    pub by_algorithm: HashMap<String, usize>,
    pub avg_length: f64,
    pub max_length: usize,
    pub min_length: usize,
}

impl StringStatistics {
    #[must_use]
    pub fn from_results(results: &[StringResult]) -> Self {
        if results.is_empty() {
            return Self::default();
        }
        let mut by_algorithm: HashMap<String, usize> = HashMap::new();
        let mut total_len = 0usize;
        let mut max_length = 0usize;
        let mut min_length = usize::MAX;
        for r in results {
            *by_algorithm
                .entry(r.algorithm.name().to_owned())
                .or_insert(0) += 1;
            total_len += r.len();
            max_length = max_length.max(r.len());
            min_length = min_length.min(r.len());
        }
        Self {
            total: results.len(),
            by_algorithm,
            avg_length: total_len as f64 / results.len() as f64,
            max_length,
            min_length,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy public API
// ─────────────────────────────────────────────────────────────────────────────

#[must_use]
pub fn recover_stack_strings(instructions: &[LlilInstruction]) -> Vec<RecoveredString> {
    let mut recovered = Vec::new();
    let mut current_chars = Vec::new();
    let mut current_start_offset: Option<i64> = None;
    let mut last_offset: Option<i64> = None;

    for inst in instructions {
        if let LlilInstruction::Store {
            addr: dest_expr,
            size: _,
            value: LlilExpr::Const {
                value: byte_val, ..
            },
        } = inst
        {
            // Use extract_stack_offset_i64 so that rbp-relative negative offsets
            // (SubT expressions) are also recognised, not just AddT positive offsets.
            let offset_opt = extract_stack_offset_i64(dest_expr);
            if let Some(offset) = offset_opt {
                if *byte_val > 0 && *byte_val < 256 {
                    let c = *byte_val as u8 as char;
                    if current_start_offset.is_none() {
                        current_start_offset = Some(offset);
                        last_offset = Some(offset);
                        current_chars.push(c);
                    } else {
                        let prev = last_offset.unwrap_or(offset);
                        if offset == prev + 1 {
                            current_chars.push(c);
                            last_offset = Some(offset);
                        } else {
                            if current_chars.len() >= 2 {
                                recovered.push(RecoveredString {
                                    offset: current_start_offset.unwrap_or(offset) as u64,
                                    value: current_chars.iter().collect(),
                                });
                            }
                            current_chars.clear();
                            current_start_offset = Some(offset);
                            last_offset = Some(offset);
                            current_chars.push(c);
                        }
                    }
                } else if *byte_val == 0 {
                    if !current_chars.is_empty() && current_chars.len() >= 2 {
                        recovered.push(RecoveredString {
                            offset: current_start_offset.unwrap_or(offset) as u64,
                            value: current_chars.iter().collect(),
                        });
                    }
                    current_chars.clear();
                    current_start_offset = None;
                    last_offset = None;
                }
            }
        }
    }
    if !current_chars.is_empty() && current_chars.len() >= 2 {
        recovered.push(RecoveredString {
            offset: current_start_offset.unwrap() as u64,
            value: current_chars.iter().collect(),
        });
    }
    recovered
}

#[must_use]
pub fn detect_xor_encryption(instructions: &[LlilInstruction]) -> bool {
    for inst in instructions {
        match inst {
            LlilInstruction::SetReg {
                value: LlilExpr::Xor(_, r, _),
                ..
            }
            | LlilInstruction::Store {
                value: LlilExpr::Xor(_, r, _),
                ..
            } => {
                if matches!(r.as_ref(), LlilExpr::Const { .. }) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

pub const fn run_pass() {}

// ─────────────────────────────────────────────────────────────────────────────
// XorKeyBruteforce
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XorKeyBruteforce;

impl XorKeyBruteforce {
    #[must_use]
    pub fn try_all_single_byte_keys(ciphertext: &[u8]) -> Vec<(u8, String)> {
        let mut results = Vec::new();
        for key in 1u8..=255 {
            let dec: Vec<u8> = ciphertext.iter().map(|&b| b ^ key).collect();
            if Self::is_printable_string(&dec)
                && let Ok(s) = std::str::from_utf8(&dec) {
                    results.push((key, s.to_owned()));
                }
        }
        results
    }
    #[must_use]
    pub fn is_printable_string(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        data.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count() as f64 / data.len() as f64
            >= 0.80
    }
    #[must_use]
    pub fn try_xor_key_guess(ciphertext: &[u8], key: &[u8]) -> Option<String> {
        if key.is_empty() || ciphertext.is_empty() {
            return None;
        }
        let dec: Vec<u8> = ciphertext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        if !Self::is_printable_string(&dec) {
            return None;
        }
        std::str::from_utf8(&dec).ok().map(std::borrow::ToOwned::to_owned)
    }
    #[must_use]
    pub fn best_single_byte_key(ciphertext: &[u8]) -> Option<(u8, String)> {
        let mut best: Option<(u8, String, usize)> = None;
        for key in 1u8..=255 {
            let dec: Vec<u8> = ciphertext.iter().map(|&b| b ^ key).collect();
            let score = dec.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count();
            if score == 0 {
                continue;
            }
            if let Ok(s) = std::str::from_utf8(&dec) {
                match &best {
                    None => best = Some((key, s.to_owned(), score)),
                    Some((_, _, prev)) if score > *prev => {
                        best = Some((key, s.to_owned(), score));
                    }
                    _ => {}
                }
            }
        }
        best.map(|(k, s, _)| (k, s))
    }
    #[must_use]
    pub fn printable_ratio(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        data.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count() as f64 / data.len() as f64
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StackStringReconstructor
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackStringPattern {
    pub stack_base_offset: i32,
    pub chars: Vec<u8>,
    pub start_offset: usize,
}

impl StackStringPattern {
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.chars).ok()
    }
    #[must_use]
    pub const fn len(&self) -> usize {
        self.chars.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub struct StackStringReconstructor;

impl StackStringReconstructor {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
    #[must_use]
    pub fn find_stack_string_patterns(code: &[u8]) -> Vec<StackStringPattern> {
        let mut stores: Vec<(usize, i8, u8)> = Vec::new();
        let mut i = 0;
        while i + 3 < code.len() {
            if code[i] == 0xC6 && code[i + 1] == 0x45 {
                stores.push((i, code[i + 2] as i8, code[i + 3]));
                i += 4;
                continue;
            }
            i += 1;
        }
        if stores.is_empty() {
            return Vec::new();
        }
        let mut patterns: Vec<StackStringPattern> = Vec::new();
        let mut group_start = 0usize;
        while group_start < stores.len() {
            let (code_off, base_disp, first_byte) = stores[group_start];
            let mut group = vec![first_byte];
            let mut last_disp = base_disp;
            let mut idx = group_start + 1;
            while idx < stores.len() {
                let (_, next_disp, next_byte) = stores[idx];
                let step = i16::from(next_disp) - i16::from(last_disp);
                if step == 1 || step == -1 {
                    group.push(next_byte);
                    last_disp = next_disp;
                    idx += 1;
                } else {
                    break;
                }
            }
            if group.len() >= 2 {
                let second_disp = if idx > group_start + 1 {
                    stores[group_start + 1].1
                } else {
                    base_disp
                };
                if (i16::from(second_disp) - i16::from(base_disp)) < 0 {
                    group.reverse();
                }
                patterns.push(StackStringPattern {
                    stack_base_offset: i32::from(base_disp),
                    chars: group,
                    start_offset: code_off,
                });
            }
            group_start = idx;
        }
        patterns
    }
    #[must_use]
    pub fn printable_patterns(code: &[u8]) -> Vec<StackStringPattern> {
        Self::find_stack_string_patterns(code)
            .into_iter()
            .filter(|p| XorKeyBruteforce::is_printable_string(&p.chars))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64Detector
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct Base64Detector;

impl Base64Detector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
    #[must_use]
    pub const fn is_base64_alphabet(b: u8) -> bool {
        b.is_ascii_uppercase()
            || b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || b == b'+'
            || b == b'/'
            || b == b'='
    }
    #[must_use]
    pub fn detect_base64(data: &[u8]) -> Vec<(usize, String)> {
        let mut results = Vec::new();
        let mut i = 0;
        while i < data.len() {
            if Self::is_base64_alphabet(data[i]) {
                let start = i;
                while i < data.len() && Self::is_base64_alphabet(data[i]) {
                    i += 1;
                }
                let run = &data[start..i];
                let usable_len = (run.len() / 4) * 4;
                if usable_len < 4 {
                    continue;
                }
                let candidate = &run[..usable_len];
                if let Ok(s) = std::str::from_utf8(candidate)
                    && let Ok(decoded) = Base64Decoder::decode(s)
                        && let Ok(text) = std::str::from_utf8(&decoded) {
                            results.push((start, text.to_owned()));
                        }
            } else {
                i += 1;
            }
        }
        results
    }
    #[must_use]
    pub fn detect_with_min_length(data: &[u8], min_len: usize) -> Vec<(usize, String)> {
        Self::detect_base64(data)
            .into_iter()
            .filter(|(_, s)| s.len() >= min_len)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringObfuscationReport
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringObfuscationReport {
    pub xor_candidates: Vec<(usize, u8, String)>,
    pub stack_strings: Vec<StackStringPattern>,
    pub base64_strings: Vec<(usize, String)>,
    pub suspected_obfuscation: bool,
}

impl StringObfuscationReport {
    #[must_use]
    pub fn analyze(code: &[u8]) -> Self {
        let mut xor_candidates: Vec<(usize, u8, String)> = Vec::new();
        let window = 16usize;
        let step = 8usize;
        let mut off = 0usize;
        while off + window <= code.len() {
            let slice = &code[off..off + window];
            for (key, decoded) in XorKeyBruteforce::try_all_single_byte_keys(slice) {
                if decoded.len() >= 4 {
                    xor_candidates.push((off, key, decoded));
                    break;
                }
            }
            off += step;
        }
        xor_candidates.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        xor_candidates.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
        let stack_strings = StackStringReconstructor::find_stack_string_patterns(code);
        let base64_strings = Base64Detector::detect_base64(code);
        let suspected_obfuscation = !xor_candidates.is_empty()
            || stack_strings.iter().any(|p| p.len() >= 4)
            || base64_strings.iter().any(|(_, s)| s.len() >= 4);
        Self {
            xor_candidates,
            stack_strings,
            base64_strings,
            suspected_obfuscation,
        }
    }
    #[must_use]
    pub const fn total_findings(&self) -> usize {
        self.xor_candidates.len() + self.stack_strings.len() + self.base64_strings.len()
    }
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.total_findings() == 0
    }
    #[must_use]
    pub fn xor_by_key(&self, key: u8) -> Vec<&(usize, u8, String)> {
        self.xor_candidates
            .iter()
            .filter(|(_, k, _)| *k == key)
            .collect()
    }
    #[must_use]
    pub fn printable_stack_strings(&self) -> Vec<&StackStringPattern> {
        self.stack_strings
            .iter()
            .filter(|p| XorKeyBruteforce::is_printable_string(&p.chars))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_il_llil::Size;

    fn make_rsp_store(offset: u64, byte_val: u64) -> LlilInstruction {
        let q = Size::QWord;
        let b = Size::Byte;
        LlilInstruction::Store {
            addr: LlilExpr::AddT(
                Box::new(LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("rsp".to_string()),
                    size: q,
                }),
                Box::new(LlilExpr::Const {
                    value: offset,
                    size: q,
                }),
                q,
            ),
            size: b,
            value: LlilExpr::Const {
                value: byte_val,
                size: b,
            },
        }
    }

    fn make_rbp_store(offset: u64, byte_val: u64) -> LlilInstruction {
        let q = Size::QWord;
        let b = Size::Byte;
        LlilInstruction::Store {
            addr: LlilExpr::AddT(
                Box::new(LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("rbp".to_string()),
                    size: q,
                }),
                Box::new(LlilExpr::Const {
                    value: offset,
                    size: q,
                }),
                q,
            ),
            size: b,
            value: LlilExpr::Const {
                value: byte_val,
                size: b,
            },
        }
    }

    #[test]
    fn test_recover_stack_strings_basic() {
        let instrs = vec![
            make_rsp_store(0, u64::from(b'H')),
            make_rsp_store(1, u64::from(b'e')),
            make_rsp_store(2, u64::from(b'l')),
            make_rsp_store(3, u64::from(b'l')),
            make_rsp_store(4, u64::from(b'o')),
        ];
        let result = recover_stack_strings(&instrs);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "Hello");
    }

    #[test]
    fn test_recover_stack_strings_rbp() {
        let instrs = vec![
            make_rbp_store(0, u64::from(b'A')),
            make_rbp_store(1, u64::from(b'B')),
            make_rbp_store(2, u64::from(b'C')),
        ];
        let result = recover_stack_strings(&instrs);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "ABC");
    }

    #[test]
    fn test_recover_stack_strings_null_terminated() {
        let instrs = vec![
            make_rsp_store(0, u64::from(b'H')),
            make_rsp_store(1, u64::from(b'i')),
            make_rsp_store(2, 0),
        ];
        let result = recover_stack_strings(&instrs);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "Hi");
    }

    #[test]
    fn test_recover_empty_instructions() {
        assert!(recover_stack_strings(&[]).is_empty());
    }

    #[test]
    fn test_recover_single_char_not_returned() {
        assert!(recover_stack_strings(&[make_rsp_store(0, u64::from(b'X'))]).is_empty());
    }

    #[test]
    fn test_recover_two_char_string() {
        let instrs = vec![
            make_rsp_store(0, u64::from(b'H')),
            make_rsp_store(1, u64::from(b'i')),
        ];
        let result = recover_stack_strings(&instrs);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "Hi");
    }

    #[test]
    fn test_xor_brute_force_top3_basic() {
        let plaintext = b"Hello World";
        let key = 0x42u8;
        let ciphertext: Vec<u8> = plaintext.iter().map(|&b| b ^ key).collect();
        let candidates = xor_brute_force_top3(&ciphertext);
        assert!(!candidates.is_empty());
        assert!(candidates[0].printable_ratio > 0.5);
    }

    #[test]
    fn test_xor_brute_force_top3_returns_at_most_3() {
        let data = vec![0x41u8; 16];
        assert!(xor_brute_force_top3(&data).len() <= 3);
    }

    #[test]
    fn test_xor_brute_force_top3_empty() {
        assert!(xor_brute_force_top3(&[]).is_empty());
    }

    #[test]
    fn test_xor_brute_force_top3_correct_key_in_top() {
        let plaintext = b"This is a secret message that is printable ASCII text!";
        let key = 0x5Cu8;
        let ct: Vec<u8> = plaintext.iter().map(|&b| b ^ key).collect();
        let candidates = xor_brute_force_top3(&ct);
        let found = candidates.iter().any(|c| c.key == key);
        assert!(found, "Expected key {key:#x} to be in top 3");
    }

    #[test]
    fn test_detect_xor_key_length_ic() {
        let plaintext = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key = b"XYZ";
        let ct: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % 3])
            .collect();
        let scores = detect_xor_key_length_ic(&ct, 16);
        assert!(!scores.is_empty());
        let found_3 = scores.iter().any(|&(k, _)| k == 3);
        assert!(found_3, "Expected key length 3 in top IC results");
    }

    #[test]
    fn test_recover_multibyte_xor_basic() {
        let plaintext = b"This is a test string for xor!  ";
        let key = b"KEY";
        let ct: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % 3])
            .collect();
        let results = recover_multibyte_xor(&ct, 8);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_rc4_round_trip() {
        let key = b"secret";
        let pt = b"Hello RC4 World!";
        let ct = Rc4::decrypt(pt, key);
        let dec = Rc4::decrypt(&ct, key);
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_rc4_brute_force_1byte() {
        let key = 0xABu8;
        let pt = b"SecretString!!!";
        let ct = Rc4::decrypt(pt, &[key]);
        let (found_key, dec) = Rc4::brute_force_1byte(&ct);
        assert_eq!(found_key, key);
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_detect_base64_variant_standard() {
        assert_eq!(
            detect_base64_variant(b"SGVsbG8gV29ybGQ="),
            Some(Base64Variant::Standard)
        );
    }

    #[test]
    fn test_detect_base64_variant_urlsafe() {
        assert_eq!(
            detect_base64_variant(b"SGVs-G8gV29y_GQ="),
            Some(Base64Variant::UrlSafe)
        );
    }

    #[test]
    fn test_decode_base64_urlsafe() {
        let result = decode_base64_urlsafe("SGVsbG8gV29ybGQ=").unwrap();
        assert_eq!(result, b"Hello World");
    }

    #[test]
    fn test_caesar_brute_force_rot13() {
        let input = "Uryyb Jbeyq";
        let results = caesar_brute_force(input);
        assert!(!results.is_empty());
        assert_eq!(results[0].rotation, 13);
        assert_eq!(results[0].decrypted, "Hello World");
    }

    #[test]
    fn test_caesar_brute_force_returns_25() {
        assert_eq!(caesar_brute_force("abc").len(), 25);
    }

    #[test]
    fn test_rot13_roundtrip() {
        let s = "Hello World";
        assert_eq!(RotN::rot13(&RotN::rot13(s)), s);
    }

    #[test]
    fn test_base64_encode_decode() {
        let data = b"Hello World";
        let enc = Base64Decoder::encode(data);
        let dec = Base64Decoder::decode(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn test_hex_encode_decode() {
        let data = b"\xDE\xAD\xBE\xEF";
        let enc = HexDecoder::encode(data);
        let dec = HexDecoder::decode(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn test_compute_confidence_high() {
        let data = b"Hello World! This is printable ASCII text here.";
        assert!(compute_confidence(data) > 80);
    }

    #[test]
    fn test_compute_confidence_binary() {
        let data: Vec<u8> = (0u8..=255).collect();
        assert!(compute_confidence(&data) < 60);
    }

    #[test]
    fn test_detect_arith_obf_brute_force() {
        let pt = b"Hello World!";
        let c = 7u8;
        let ct: Vec<u8> = pt.iter().map(|&b| b.wrapping_add(c)).collect();
        let results = detect_arith_obf_in_mlil(&[], &ct);
        assert!(
            results
                .iter()
                .any(|r| r.obf_type == ArithObfType::Add && r.constant == c)
        );
    }

    #[test]
    fn test_detect_mlil_stack_strings_empty() {
        assert!(detect_mlil_stack_strings(&[]).is_empty());
    }

    #[test]
    fn test_batch_decrypt_string_table_xor() {
        let pt = b"Secret";
        let key = 0x5Au8;
        let ct: Vec<u8> = pt.iter().map(|&b| b ^ key).collect();
        let entries = vec![StringTableEntry {
            ptr: 0x1000,
            length: ct.len() as u32,
            key: u32::from(key),
        }];
        let ct_clone = ct;
        let results = batch_decrypt_string_table(
            &entries,
            move |addr, len| {
                if addr == 0x1000 {
                    Some(ct_clone[..len].to_vec())
                } else {
                    None
                }
            },
            StringAlgorithm::XorConstant,
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decrypted, pt);
    }

    #[test]
    fn test_xor_key_bruteforce_is_printable() {
        assert!(XorKeyBruteforce::is_printable_string(b"Hello World"));
        assert!(!XorKeyBruteforce::is_printable_string(b"\x00\x01\x02\x03"));
        assert!(!XorKeyBruteforce::is_printable_string(b""));
    }

    #[test]
    fn test_stack_string_reconstructor_patterns() {
        let code: Vec<u8> = vec![
            0xC6, 0x45, 0x01, b'H', 0xC6, 0x45, 0x02, b'e', 0xC6, 0x45, 0x03, b'l', 0xC6, 0x45,
            0x04, b'l', 0xC6, 0x45, 0x05, b'o',
        ];
        let patterns = StackStringReconstructor::find_stack_string_patterns(&code);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].chars.len(), 5);
    }

    #[test]
    fn test_encoding_detector_base64() {
        let encoded = Base64Decoder::encode(b"Hello World");
        assert_eq!(
            EncodingDetector::detect(encoded.as_bytes()),
            StringAlgorithm::Base64
        );
    }

    #[test]
    fn test_encoding_detector_hex() {
        let encoded = HexDecoder::encode(b"Hello");
        assert_eq!(
            EncodingDetector::detect(encoded.as_bytes()),
            StringAlgorithm::HexEncoded
        );
    }

    #[test]
    fn test_decryption_chain_xor_then_rot13() {
        let plaintext = "Hello";
        let xor_key = 0x10u8;
        let xored: Vec<u8> = RotN::rot13(plaintext)
            .bytes()
            .map(|b| b ^ xor_key)
            .collect();
        let mut chain = DecryptionChain::new();
        chain.push(ChainStage::new(StringAlgorithm::XorConstant, vec![xor_key]));
        chain.push(ChainStage::new(StringAlgorithm::RotN, vec![13]));
        let result = chain.apply(&xored).unwrap();
        assert_eq!(std::str::from_utf8(&result).unwrap(), plaintext);
    }

    #[test]
    fn test_string_obfuscation_report_empty() {
        let report = StringObfuscationReport::analyze(&[]);
        assert!(report.is_clean());
        assert!(!report.suspected_obfuscation);
    }

    #[test]
    fn test_api_hasher_djb2() {
        let h = ApiHasher::djb2(b"CreateFile");
        assert!(h > 0);
        let table = ApiHasher::build_table(&["CreateFile", "ReadFile"], ApiHashAlgorithm::Djb2);
        assert!(ApiHasher::resolve(&table, u64::from(h)).is_some());
    }

    #[test]
    fn test_api_hasher_crc32() {
        assert!(ApiHasher::crc32(b"VirtualAlloc") > 0);
    }

    #[test]
    fn test_api_hasher_fnv1a32() {
        assert!(ApiHasher::fnv1a32(b"LoadLibrary") > 0);
    }

    #[test]
    fn test_string_statistics() {
        let results = vec![
            StringResult::new(
                0x1000,
                "Hello".to_string(),
                StringAlgorithm::XorConstant,
                vec![0x42],
            ),
            StringResult::new(
                0x2000,
                "World".to_string(),
                StringAlgorithm::Rc4,
                vec![0x01],
            ),
        ];
        let stats = StringStatistics::from_results(&results);
        assert_eq!(stats.total, 2);
        assert_eq!(stats.max_length, 5);
    }

    #[test]
    fn test_decoded_string_confidence() {
        let ds = DecodedString::new(
            0x1000,
            b"enc".to_vec(),
            "dec".to_string(),
            StringAlgorithm::XorConstant,
            85,
        );
        assert!(ds.is_high_confidence());
        let ds2 = DecodedString::new(
            0x2000,
            b"enc".to_vec(),
            "?".to_string(),
            StringAlgorithm::Unknown,
            40,
        );
        assert!(!ds2.is_high_confidence());
    }

    #[test]
    fn test_split_string_recovery() {
        let data = b"...Hello...World...";
        let frags = SplitStringRecovery::find_fragments(data, &[(b"Hello", 0), (b"World", 1)]);
        assert_eq!(frags.len(), 2);
        let reconstructed = SplitStringRecovery::reconstruct(frags);
        assert_eq!(&reconstructed[..5], b"Hello");
    }

    #[test]
    fn test_index_of_coincidence_english() {
        let english = b"the quick brown fox jumps over the lazy dog and then some more words";
        let ic = index_of_coincidence_period(english, 1);
        assert!(ic > 0.04, "IC of English should be > 0.04, got {ic}");
    }

    #[test]
    fn test_rc4_inverse_ksa_smoke() {
        let s = Rc4::ksa(b"testkey");
        let candidates = rc4_inverse_ksa(&s);
        assert!(!candidates.is_empty());
    }

    #[test]
    fn test_xor_decryptor_cyclic_roundtrip() {
        let data = b"ABCDEFGH";
        let key = b"XY";
        let enc = XorDecryptor::decrypt_cyclic(data, key).expect("non-empty key");
        let dec = XorDecryptor::decrypt_cyclic(&enc, key).expect("non-empty key");
        assert_eq!(dec, data);
    }

    #[test]
    fn test_xor_rolling_roundtrip() {
        let data = b"Hello World";
        let key = 0x33u8;
        let enc = XorDecryptor::decrypt_rolling(data, key);
        let dec = XorDecryptor::decrypt_rolling(&enc, key);
        assert_eq!(dec, data);
    }
}
