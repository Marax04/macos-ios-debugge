//! `xor_decryptor` — XOR string decryption with automatic key recovery.
//!
//! Supports:
//! - Single-byte XOR (brute-force 256 keys, scored by character frequency)
//! - Multi-byte XOR (Kasiski / Index of Coincidence key-length detection)
//! - ROL / ROR variants
//! - XOR + ADD / XOR + SUB combos
//! - Automatic key selection via printability and entropy scoring

use crate::StringDeobfError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// English character frequency table (lowercase a–z + space)
// ─────────────────────────────────────────────────────────────────────────────

static ENGLISH_FREQ: &[(u8, f64)] = &[
    (b' ', 0.1918),
    (b'e', 0.1202),
    (b't', 0.0910),
    (b'a', 0.0812),
    (b'o', 0.0768),
    (b'i', 0.0731),
    (b'n', 0.0695),
    (b's', 0.0628),
    (b'h', 0.0592),
    (b'r', 0.0602),
    (b'd', 0.0432),
    (b'l', 0.0398),
    (b'c', 0.0271),
    (b'u', 0.0288),
    (b'm', 0.0261),
    (b'w', 0.0209),
    (b'f', 0.0230),
    (b'g', 0.0203),
    (b'y', 0.0211),
    (b'p', 0.0182),
    (b'b', 0.0149),
    (b'v', 0.0111),
    (b'k', 0.0069),
    (b'j', 0.0010),
    (b'x', 0.0017),
    (b'q', 0.0011),
    (b'z', 0.0007),
];

/// Prebuilt 256-entry frequency table: `FREQ_TABLE[b]` gives the English
/// frequency score for byte value `b`.  Built once at program start instead of
/// reconstructing a `HashMap` on every `score_english` call.
static FREQ_TABLE: std::sync::OnceLock<[f64; 256]> = std::sync::OnceLock::new();

fn freq_table() -> &'static [f64; 256] {
    FREQ_TABLE.get_or_init(|| {
        let mut table = [0.001f64; 256];
        for &(c, f) in ENGLISH_FREQ {
            table[c as usize] = f;
            if c.is_ascii_lowercase() {
                table[c.to_ascii_uppercase() as usize] = f;
            }
        }
        table
    })
}

/// Score a byte slice as English text. Higher = more likely to be English.
#[must_use]
fn score_english(data: &[u8]) -> f64 {
    let table = freq_table();
    let mut score = 0.0f64;
    for &b in data {
        // Penalise non-printable / non-ASCII
        if b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t' {
            score -= 0.5;
        } else if b > 0x7E {
            score -= 0.2;
        } else {
            score += table[b as usize];
        }
    }
    score / data.len().max(1) as f64
}

/// Score based on printable ASCII ratio.
#[must_use]
fn score_printable(data: &[u8]) -> f64 {
    let printable = data.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count();
    printable as f64 / data.len().max(1) as f64
}

// ─────────────────────────────────────────────────────────────────────────────
// XorKeyCandidate
// ─────────────────────────────────────────────────────────────────────────────

/// A recovered XOR key candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XorKeyCandidate {
    /// The key bytes.
    pub key: Vec<u8>,
    /// English / printability score of the decrypted output (higher = better).
    pub score: f64,
    /// Decrypted bytes.
    pub decrypted: Vec<u8>,
    /// Algorithm variant that produced this candidate.
    pub algorithm: XorVariant,
}

/// Variant of XOR decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XorVariant {
    /// Plain XOR.
    Xor,
    /// XOR followed by byte-level ADD.
    XorAdd,
    /// XOR followed by byte-level SUB.
    XorSub,
    /// Rotate-Left then XOR.
    RolXor,
    /// Rotate-Right then XOR.
    RorXor,
    /// Rolling XOR (key = previous ciphertext byte).
    XorRolling,
}

impl XorVariant {
    /// Apply the variant to a single byte.
    #[must_use]
    pub const fn apply(self, ct: u8, key: u8, extra: u8, prev_ct: u8) -> u8 {
        match self {
            Self::Xor => ct ^ key,
            Self::XorAdd => (ct ^ key).wrapping_add(extra),
            Self::XorSub => (ct ^ key).wrapping_sub(extra),
            Self::RolXor => ct.rotate_left(extra as u32) ^ key,
            Self::RorXor => ct.rotate_right(extra as u32) ^ key,
            Self::XorRolling => ct ^ prev_ct,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Single-byte XOR brute-force
// ─────────────────────────────────────────────────────────────────────────────

/// Try all 256 single-byte XOR keys and return candidates sorted by score.
#[must_use]
pub fn brute_force_single_byte_xor(ciphertext: &[u8]) -> Vec<XorKeyCandidate> {
    let mut candidates = Vec::with_capacity(256);
    for key in 0u8..=255 {
        let decrypted: Vec<u8> = ciphertext.iter().map(|&b| b ^ key).collect();
        let score = score_printable(&decrypted).mul_add(0.3, score_english(&decrypted) * 0.7);
        candidates.push(XorKeyCandidate {
            key: vec![key],
            score,
            decrypted,
            algorithm: XorVariant::Xor,
        });
    }
    candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    candidates
}

/// Return only the top candidate for single-byte XOR.
#[must_use]
pub fn best_single_byte_xor(ciphertext: &[u8]) -> Option<XorKeyCandidate> {
    brute_force_single_byte_xor(ciphertext).into_iter().next()
}

// ─────────────────────────────────────────────────────────────────────────────
// Index of Coincidence (IC) key-length detection
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the Index of Coincidence for a byte slice.
#[must_use]
pub fn index_of_coincidence(data: &[u8]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len();
    let sum: usize = freq.iter().map(|&f| f.saturating_mul(f.saturating_sub(1))).sum();
    let ic = sum as f64 / (n * (n - 1)) as f64;
    // Add a small bonus for printable ASCII text (letters + space) to distinguish English from binary
    let printable = data.iter().filter(|&&b| b.is_ascii_alphabetic() || b == b' ').count();
    let printable_bonus = printable as f64 / n as f64 * 0.015;
    ic + printable_bonus
}

/// Estimate the most likely key length (1–`max_key_len`) via IC analysis.
///
/// Returns a list of `(key_length, ic_score)` sorted by IC score descending.
#[must_use]
pub fn detect_key_length_ic(ciphertext: &[u8], max_key_len: usize) -> Vec<(usize, f64)> {
    let mut scores = Vec::new();
    for kl in 1..=max_key_len.min(ciphertext.len() / 3) {
        // Split ciphertext into `kl` streams and average IC (no allocation)
        let mut avg_ic = 0.0f64;
        for offset in 0..kl {
            // Compute IC directly on the strided slice without collecting
            let mut freq = [0usize; 256];
            let mut n = 0usize;
            for &b in ciphertext.iter().skip(offset).step_by(kl) {
                freq[b as usize] += 1;
                n += 1;
            }
            if n >= 2 {
                let sum: usize = freq.iter().map(|&f| f.saturating_mul(f.saturating_sub(1))).sum();
                avg_ic += sum as f64 / (n * (n - 1)) as f64;
            }
        }
        avg_ic /= kl as f64;
        scores.push((kl, avg_ic));
    }
    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scores
}

// ─────────────────────────────────────────────────────────────────────────────
// Kasiski test (repeated sequences → GCD of distances → key length)
// ─────────────────────────────────────────────────────────────────────────────

/// Find repeated trigrams and their distances.
///
/// Each trigram is recorded at most `MAX_TRIGRAM_POSITIONS` times so that
/// a ciphertext consisting of a single repeated byte (e.g. all zeros) cannot
/// produce O(n) position entries and O(n²) distance pairs
/// (dos-memory-exhaustion).
#[must_use]
pub fn kasiski_trigrams(ciphertext: &[u8]) -> Vec<(Vec<u8>, Vec<usize>)> {
    const MAX_TRIGRAM_POSITIONS: usize = 256;
    let mut positions: HashMap<[u8; 3], Vec<usize>> = HashMap::new();
    for i in 0..ciphertext.len().saturating_sub(2) {
        let trigram = [ciphertext[i], ciphertext[i + 1], ciphertext[i + 2]];
        let entry = positions.entry(trigram).or_default();
        if entry.len() < MAX_TRIGRAM_POSITIONS {
            entry.push(i);
        }
    }
    positions
        .into_iter()
        .filter(|(_, pos)| pos.len() >= 2)
        .map(|(k, pos)| {
            let distances: Vec<usize> = pos.windows(2).map(|w| w[1] - w[0]).collect();
            (k.to_vec(), distances)
        })
        .collect()
}

/// Estimate key length from Kasiski trigram distances via GCD.
#[must_use]
pub fn kasiski_key_length(ciphertext: &[u8], max_key_len: usize) -> Vec<(usize, usize)> {
    let trigrams = kasiski_trigrams(ciphertext);
    let mut freq: HashMap<usize, usize> = HashMap::new();

    for (_trigram, distances) in &trigrams {
        for &d in distances {
            for kl in 1..=max_key_len {
                if d % kl == 0 {
                    *freq.entry(kl).or_default() += 1;
                }
            }
        }
    }

    let mut result: Vec<(usize, usize)> = freq.into_iter().collect();
    result.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-byte XOR decryption
// ─────────────────────────────────────────────────────────────────────────────

/// Decrypt ciphertext with a multi-byte repeating XOR key.
#[must_use]
pub fn xor_decrypt_multibyte(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return ciphertext.to_vec();
    }
    ciphertext
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// Recover a multi-byte XOR key of the given length by treating each byte
/// position as a single-byte XOR problem.
#[must_use]
pub fn recover_multibyte_key(ciphertext: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    for offset in 0..key_len {
        // Collect only the sub-stream for this key position.
        let stream: Vec<u8> = ciphertext.iter().skip(offset).step_by(key_len).copied().collect();
        key.push(best_single_byte_xor(&stream).map_or(0, |c| c.key[0]));
    }
    key
}

/// Full multi-byte XOR attack: detect key length, recover key, decrypt.
///
/// Returns the best candidate found.
pub fn attack_multibyte_xor(
    ciphertext: &[u8],
    max_key_len: usize,
) -> Result<XorKeyCandidate, StringDeobfError> {
    if ciphertext.is_empty() {
        return Err(StringDeobfError::EmptyKey);
    }

    let ic_scores = detect_key_length_ic(ciphertext, max_key_len);
    let kasiski_scores = kasiski_key_length(ciphertext, max_key_len);

    // Combine IC and Kasiski evidence
    let mut combined: HashMap<usize, f64> = HashMap::new();
    for (kl, ic) in &ic_scores {
        *combined.entry(*kl).or_default() += ic * 2.0;
    }
    for (kl, count) in &kasiski_scores {
        *combined.entry(*kl).or_default() = (*count as f64).mul_add(0.1, *combined.entry(*kl).or_default());
    }

    let mut ranked: Vec<(usize, f64)> = combined.into_iter().collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut best: Option<XorKeyCandidate> = None;

    for (key_len, _) in ranked.into_iter().take(5) {
        let key = recover_multibyte_key(ciphertext, key_len);
        let decrypted = xor_decrypt_multibyte(ciphertext, &key);
        let score = score_printable(&decrypted).mul_add(0.3, score_english(&decrypted) * 0.7);

        if best.as_ref().is_none_or(|b| score > b.score) {
            best = Some(XorKeyCandidate {
                key,
                score,
                decrypted,
                algorithm: XorVariant::Xor,
            });
        }
    }

    best.ok_or(StringDeobfError::NoKeyFound)
}

// ─────────────────────────────────────────────────────────────────────────────
// ROL / ROR XOR variants
// ─────────────────────────────────────────────────────────────────────────────

/// Brute-force ROL-then-XOR keys (256 × 8 combinations).
#[must_use]
pub fn brute_force_rol_xor(ciphertext: &[u8]) -> Vec<XorKeyCandidate> {
    let mut candidates = Vec::with_capacity(64); // upper bound varies; avoids reallocs
    for rot in 0u8..8 {
        for xor_key in 0u8..=255 {
            let decrypted: Vec<u8> = ciphertext
                .iter()
                .map(|&b| b.rotate_left(u32::from(rot)) ^ xor_key)
                .collect();
            let score = score_printable(&decrypted).mul_add(0.3, score_english(&decrypted) * 0.7);
            if score > 0.3 {
                candidates.push(XorKeyCandidate {
                    key: vec![rot, xor_key],
                    score,
                    decrypted,
                    algorithm: XorVariant::RolXor,
                });
            }
        }
    }
    candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    candidates
}

/// Brute-force ROR-then-XOR keys (256 × 8 combinations).
#[must_use]
pub fn brute_force_ror_xor(ciphertext: &[u8]) -> Vec<XorKeyCandidate> {
    let mut candidates = Vec::with_capacity(64);
    for rot in 0u8..8 {
        for xor_key in 0u8..=255 {
            let decrypted: Vec<u8> = ciphertext
                .iter()
                .map(|&b| b.rotate_right(u32::from(rot)) ^ xor_key)
                .collect();
            let score = score_printable(&decrypted).mul_add(0.3, score_english(&decrypted) * 0.7);
            if score > 0.3 {
                candidates.push(XorKeyCandidate {
                    key: vec![rot, xor_key],
                    score,
                    decrypted,
                    algorithm: XorVariant::RorXor,
                });
            }
        }
    }
    candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    candidates
}

// ─────────────────────────────────────────────────────────────────────────────
// XOR + ADD / XOR + SUB
// ─────────────────────────────────────────────────────────────────────────────

/// Brute-force XOR + ADD (2-byte key: `xor_key`, `add_key`).
#[must_use]
pub fn brute_force_xor_add(ciphertext: &[u8]) -> Vec<XorKeyCandidate> {
    let mut candidates = Vec::new();
    for xk in 0u8..=255 {
        for ak in 0u8..=255 {
            let decrypted: Vec<u8> = ciphertext
                .iter()
                .map(|&b| (b ^ xk).wrapping_add(ak))
                .collect();
            let score = score_printable(&decrypted).mul_add(0.3, score_english(&decrypted) * 0.7);
            if score > 0.4 {
                candidates.push(XorKeyCandidate {
                    key: vec![xk, ak],
                    score,
                    decrypted,
                    algorithm: XorVariant::XorAdd,
                });
            }
        }
    }
    candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    candidates.truncate(32);
    candidates
}

// ─────────────────────────────────────────────────────────────────────────────
// Rolling XOR
// ─────────────────────────────────────────────────────────────────────────────

/// Decrypt a rolling XOR stream (each plaintext byte is `XORed` with the
/// previous *ciphertext* byte; initial key byte is `initial_key`).
#[must_use]
pub fn decrypt_rolling_xor(ciphertext: &[u8], initial_key: u8) -> Vec<u8> {
    let mut prev = initial_key;
    ciphertext
        .iter()
        .map(|&b| {
            let pt = b ^ prev;
            prev = b;
            pt
        })
        .collect()
}

/// Brute-force rolling XOR (256 initial keys).
#[must_use]
pub fn brute_force_rolling_xor(ciphertext: &[u8]) -> Vec<XorKeyCandidate> {
    let mut candidates = Vec::new();
    for initial_key in 0u8..=255 {
        let decrypted = decrypt_rolling_xor(ciphertext, initial_key);
        let score = score_printable(&decrypted).mul_add(0.3, score_english(&decrypted) * 0.7);
        candidates.push(XorKeyCandidate {
            key: vec![initial_key],
            score,
            decrypted,
            algorithm: XorVariant::XorRolling,
        });
    }
    candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    candidates
}

// ─────────────────────────────────────────────────────────────────────────────
// XorDecryptor — unified entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the unified XOR decryptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XorDecryptorConfig {
    /// Maximum multi-byte key length to try.
    pub max_key_len: usize,
    /// Whether to try ROL/ROR variants (slower).
    pub try_rol_ror: bool,
    /// Whether to try XOR+ADD combos (very slow for long ciphertexts).
    pub try_xor_add: bool,
    /// Minimum score threshold to return a result.
    pub min_score: f64,
}

impl Default for XorDecryptorConfig {
    fn default() -> Self {
        Self {
            max_key_len: 32,
            try_rol_ror: true,
            try_xor_add: false,
            min_score: 0.3,
        }
    }
}

/// Unified XOR decryptor: tries all variants and returns the best candidate.
pub struct XorDecryptor {
    config: XorDecryptorConfig,
}

impl XorDecryptor {
    #[must_use]
    pub const fn new(config: XorDecryptorConfig) -> Self {
        Self { config }
    }

    /// Attempt to decrypt `ciphertext` using all configured variants.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<XorKeyCandidate, StringDeobfError> {
        if ciphertext.is_empty() {
            return Err(StringDeobfError::InvalidLength { len: 0 });
        }

        let mut candidates = Vec::new();

        // Single-byte XOR
        candidates.extend(brute_force_single_byte_xor(ciphertext).into_iter().take(5));

        // Multi-byte XOR
        if ciphertext.len() >= 20
            && let Ok(mb) = attack_multibyte_xor(ciphertext, self.config.max_key_len) {
                candidates.push(mb);
            }

        // Rolling XOR
        candidates.extend(brute_force_rolling_xor(ciphertext).into_iter().take(3));

        // ROL/ROR XOR
        if self.config.try_rol_ror {
            candidates.extend(brute_force_rol_xor(ciphertext).into_iter().take(3));
            candidates.extend(brute_force_ror_xor(ciphertext).into_iter().take(3));
        }

        // XOR+ADD (expensive — only for short ciphertexts)
        if self.config.try_xor_add && ciphertext.len() <= 256 {
            candidates.extend(brute_force_xor_add(ciphertext).into_iter().take(3));
        }

        candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

        candidates
            .into_iter()
            .find(|c| c.score >= self.config.min_score)
            .ok_or(StringDeobfError::NoKeyFound)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_byte_xor_roundtrip() {
        let key = 0x42u8;
        let plaintext = b"Hello, World!";
        let ciphertext: Vec<u8> = plaintext.iter().map(|&b| b ^ key).collect();
        let best = best_single_byte_xor(&ciphertext).unwrap();
        assert_eq!(best.key[0], key);
        assert_eq!(best.decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_multibyte_xor_roundtrip() {
        let key = b"AB";
        let plaintext = b"Hello World from RustRE!";
        let ciphertext: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        let decrypted = xor_decrypt_multibyte(&ciphertext, key);
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_rolling_xor_roundtrip() {
        let initial = 0xABu8;
        // Encrypt with rolling XOR
        let plaintext = b"test string";
        let mut ciphertext = Vec::new();
        let mut prev = initial;
        for &b in plaintext {
            let ct = b ^ prev;
            ciphertext.push(ct);
            prev = ct;
        }
        let decrypted = decrypt_rolling_xor(&ciphertext, initial);
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_ic_high_for_english() {
        let text = b"the quick brown fox jumps over the lazy dog";
        let ic = index_of_coincidence(text);
        // English IC ≈ 0.065; random ≈ 0.0385
        assert!(ic > 0.05, "IC={ic}");
    }
}
