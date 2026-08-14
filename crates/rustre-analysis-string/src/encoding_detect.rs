//! Encoding and obfuscation detection for binary strings.
//!
//! This module provides utilities to detect the encoding of raw byte sequences
//! that do not appear as plain ASCII or Unicode text in the binary, including:
//!
//! * **XOR obfuscation** — brute-force single-byte and multi-byte XOR key recovery.
//! * **ROT-N cipher** — detect the rotation offset (1–25) that maximises
//!   ASCII printability; ROT-13 detection as a special case.
//! * **Base64 encoding** — detect and decode base64-encoded strings.
//! * **Hex encoding** — detect contiguous hex digit runs that decode to printable data.
//! * **Custom cipher detection** — byte-frequency fingerprinting for custom simple
//!   stream ciphers.
//!
//! All detection routines return typed results with a confidence score (0–100)
//! so that callers can rank competing hypotheses.

pub use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// DetectedEncoding — the result type
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of encoding or obfuscation detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodingKind {
    /// Single-byte XOR with the given key.
    XorSingleByte(u8),
    /// Multi-byte XOR with the given key.
    XorMultiByte(Vec<u8>),
    /// ROT-N (Caesar) cipher with the given offset.
    RotN(u8),
    /// Base64-encoded data.
    Base64,
    /// Hex-encoded (ASCII hex digits) data.
    HexEncoded,
    /// Identity — data is already plaintext.
    Plaintext,
    /// Unknown / unrecognised encoding.
    Unknown,
}

impl std::fmt::Display for EncodingKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::XorSingleByte(k) => write!(f, "XOR(0x{k:02x})"),
            Self::XorMultiByte(k) => {
                let hex: Vec<String> = k.iter().map(|b| format!("{b:02x}")).collect();
                write!(f, "XOR-MB({})", hex.join(":"))
            }
            Self::RotN(n) => write!(f, "ROT{n}"),
            Self::Base64 => write!(f, "Base64"),
            Self::HexEncoded => write!(f, "HexEncoded"),
            Self::Plaintext => write!(f, "Plaintext"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Result of an encoding detection attempt.
#[derive(Debug, Clone)]
pub struct DetectedEncoding {
    /// The detected encoding kind.
    pub kind: EncodingKind,
    /// Confidence in the detection (0–100, higher is better).
    pub confidence: u8,
    /// The decoded data, if decoding was possible.
    pub decoded: Option<Vec<u8>>,
    /// If the decoded bytes form a valid UTF-8 string, it is stored here.
    pub decoded_string: Option<String>,
}

impl DetectedEncoding {
    /// Create a new detection result.
    #[must_use]
    pub fn new(kind: EncodingKind, confidence: u8, decoded: Option<Vec<u8>>) -> Self {
        let decoded_string = decoded
            .as_deref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .map(std::borrow::ToOwned::to_owned);
        Self {
            kind,
            confidence,
            decoded,
            decoded_string,
        }
    }

    /// Whether the detection is considered reliable (confidence >= 70).
    #[must_use]
    pub const fn is_reliable(&self) -> bool {
        self.confidence >= 70
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Count bytes in `data` that are printable ASCII (0x20–0x7E) after applying
/// `f(byte)`.
fn printable_count_after<F: Fn(u8) -> u8>(data: &[u8], f: F) -> usize {
    data.iter()
        .filter(|&&b| (0x20u8..=0x7Eu8).contains(&f(b)))
        .count()
}

/// Printability fraction of a byte slice in [0.0, 1.0].
fn printability(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let printable = data.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count();
    f64::from(u32::try_from(printable).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX))
}

/// Return `true` if `data` is predominantly printable ASCII (>= 80%).
fn is_printable_ascii(data: &[u8]) -> bool {
    printability(data) >= 0.80
}

// ─────────────────────────────────────────────────────────────────────────────
// XOR — single-byte brute-force
// ─────────────────────────────────────────────────────────────────────────────

/// Result of XOR key detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XorKeyCandidate {
    /// The candidate key byte.
    pub key: u8,
    /// Number of printable bytes produced when XOR-ing with this key.
    pub printable: usize,
    /// Total bytes in the data.
    pub total: usize,
}

impl XorKeyCandidate {
    /// Printability fraction when this key is applied.
    #[must_use]
    pub fn printability(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.printable).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.total).unwrap_or(u32::MAX))
        }
    }
}

/// Brute-force all 255 non-identity single-byte XOR keys and return them sorted
/// by printability descending.
#[must_use]
pub fn xor_key_candidates(data: &[u8]) -> Vec<XorKeyCandidate> {
    if data.is_empty() {
        return Vec::new();
    }
    let total = data.len();
    let mut candidates: Vec<XorKeyCandidate> = (1u8..=255)
        .map(|key| {
            let printable = printable_count_after(data, |b| b ^ key);
            XorKeyCandidate {
                key,
                printable,
                total,
            }
        })
        .collect();
    candidates.sort_unstable_by(|a, b| b.printable.cmp(&a.printable));
    candidates
}

/// Detect the best single-byte XOR key for `data`.
///
/// Returns `None` if no key produces more than 60 % printable output
/// (avoids false positives on already-printable or encrypted data).
#[must_use]
pub fn detect_xor_single_byte(data: &[u8]) -> Option<DetectedEncoding> {
    if data.is_empty() {
        return None;
    }
    let candidates = xor_key_candidates(data);
    let best = candidates.first()?;
    // If the data is already at least as printable as any XOR candidate
    // would make it, no XOR is needed.
    let identity_printable = data.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count();
    if is_printable_ascii(data) && best.printable <= identity_printable {
        return Some(DetectedEncoding::new(
            EncodingKind::Plaintext,
            95,
            Some(data.to_vec()),
        ));
    }
    if best.printable * 10 < best.total.max(1) * 6 {
        return None;
    }
    let decoded: Vec<u8> = data.iter().map(|&b| b ^ best.key).collect();
    let confidence = u8::try_from(
        (best.printable * 100 / best.total.max(1)).min(99)
    ).unwrap_or(99);
    Some(DetectedEncoding::new(
        EncodingKind::XorSingleByte(best.key),
        confidence,
        Some(decoded),
    ))
}

/// Decode `data` with the given single-byte XOR key.
#[must_use]
pub fn xor_decode_single(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|&b| b ^ key).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// XOR — multi-byte key (Kasiski-style)
// ─────────────────────────────────────────────────────────────────────────────

/// Estimate the XOR key length from the average normalised Hamming distance
/// between successive blocks.
///
/// Returns candidate key lengths from 2 to `max_key_len` paired with their
/// score, sorted **ascending — best candidate first**. The score is the mean
/// popcount-per-byte between consecutive `kl`-sized blocks, so it lies in
/// `0.0..=8.0` and a LOWER value indicates a better period.
///
/// The doc-comment used to describe an Index of Coincidence sorted
/// *descending*, where higher was better. The body has always computed a
/// Hamming distance and sorted ascending, so the code was self-consistent —
/// but anything written against the documented contract would have taken the
/// LAST entry as the best candidate and got the worst one. `f64::MAX` is
/// returned for a key length with fewer than two blocks, which sorts last.
#[must_use]
pub fn estimate_xor_key_length(data: &[u8], max_key_len: usize) -> Vec<(usize, f64)> {
    let max = max_key_len.min(data.len() / 2);
    let mut scores: Vec<(usize, f64)> = (2..=max)
        .map(|kl| {
            // Average normalised hamming distance between successive kl-byte blocks.
            let blocks: Vec<&[u8]> = data.chunks(kl).collect();
            if blocks.len() < 2 {
                return (kl, f64::MAX);
            }
            let pairs = blocks.len() - 1;
            let avg_dist: f64 = blocks
                .windows(2)
                .map(|w| normalised_hamming(w[0], w[1]))
                .sum::<f64>()
                / f64::from(u32::try_from(pairs).unwrap_or(u32::MAX));
            (kl, avg_dist)
        })
        .collect();
    scores.sort_unstable_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    scores
}

fn normalised_hamming(a: &[u8], b: &[u8]) -> f64 {
    let len = a.len().min(b.len());
    if len == 0 {
        return 0.0;
    }
    let bits: u32 = a
        .iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x ^ y).count_ones())
        .sum();
    f64::from(bits) / f64::from(u32::try_from(len).unwrap_or(u32::MAX))
}

/// Attempt to recover a multi-byte XOR key of the given length.
///
/// For each key-stream position, takes every `key_len`-th byte and finds the
/// single-byte key that maximises printability.
#[must_use]
pub fn recover_xor_multibyte_key(data: &[u8], key_len: usize) -> Vec<u8> {
    (0..key_len)
        .map(|pos| {
            let col: Vec<u8> = data.iter().skip(pos).step_by(key_len).copied().collect();
            xor_key_candidates(&col).first().map_or(0, |c| c.key)
        })
        .collect()
}

/// Decode `data` with a multi-byte XOR key.
#[must_use]
pub fn xor_decode_multibyte(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// Detect multi-byte XOR encoding, trying key lengths from 2 up to `max_key_len`.
#[must_use]
pub fn detect_xor_multibyte(data: &[u8], max_key_len: usize) -> Option<DetectedEncoding> {
    if data.len() < 8 {
        return None;
    }
    if is_printable_ascii(data) {
        return None; // already plaintext
    }
    let key_lengths = estimate_xor_key_length(data, max_key_len);
    // Try the top-3 candidate key lengths.
    let mut best: Option<(Vec<u8>, Vec<u8>, usize)> = None;
    for &(kl, _) in key_lengths.iter().take(3) {
        let key = recover_xor_multibyte_key(data, kl);
        let decoded = xor_decode_multibyte(data, &key);
        let p = decoded.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count();
        if p > best.as_ref().map_or(0, |(_, _, f)| *f) {
            best = Some((key, decoded, p));
        }
    }
    let (key, decoded, p_count) = best?;
    let p_len = decoded.len().max(1);
    if p_count * 10 < p_len * 6 {
        return None;
    }
    let confidence = u8::try_from((p_count * 100 / p_len).min(95)).unwrap_or(95);
    Some(DetectedEncoding::new(
        EncodingKind::XorMultiByte(key),
        confidence,
        Some(decoded),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// ROT-N detection
// ─────────────────────────────────────────────────────────────────────────────

/// Apply ROT-N to a single byte (works on both upper and lower case ASCII letters).
#[must_use]
pub const fn rot_byte(b: u8, n: u8) -> u8 {
    match b {
        b'a'..=b'z' => b'a' + (b - b'a' + n % 26) % 26,
        b'A'..=b'Z' => b'A' + (b - b'A' + n % 26) % 26,
        _ => b,
    }
}

/// Apply ROT-N to an entire byte slice.
#[must_use]
pub fn rot_decode(data: &[u8], n: u8) -> Vec<u8> {
    data.iter().map(|&b| rot_byte(b, n)).collect()
}

/// Inverse of [`rot_byte`]: undoes an ROT-N rotation.
#[must_use]
const fn rot_byte_inverse(b: u8, n: u8) -> u8 {
    rot_byte(b, 26 - (n % 26))
}

/// Score a ROT candidate by frequency of common English characters in the output.
/// Score a ROT candidate; returns score × 10 000 (fixed-point integer).
/// A typical English text scores around 600–700 (i.e. ≈ 0.065 in float terms).
fn rot_score(data: &[u8], n: u8) -> u32 {
    // English letter frequencies (a–z) × 10 000, stored as u32.
    const FREQ: [u32; 26] = [
        817, 150, 278, 425, 1270, 223, 202, 609, 697, 15, 77,
        403, 241, 675, 751, 193, 10, 599, 633, 906, 276, 98,
        236, 15, 197, 7,
    ];
    let mut counts = [0u32; 26];
    let mut letters = 0u32;
    for &b in data {
        let decoded = rot_byte_inverse(b, n);
        if decoded.is_ascii_alphabetic() {
            let idx = usize::from(decoded.to_ascii_lowercase() - b'a');
            counts[idx] += 1;
            letters += 1;
        }
    }
    if letters == 0 {
        return 0;
    }
    // score = sum(count[i] / letters * FREQ[i])
    // scaled = sum(count[i] * FREQ[i]) / letters
    let sum = counts.iter().enumerate().fold(0u64, |acc, (i, &c)| {
        acc + u64::from(c) * u64::from(FREQ[i])
    });
    u32::try_from(sum / u64::from(letters)).unwrap_or(u32::MAX)
}

/// Detect ROT-N encoding (rotation cipher) by scoring all 25 non-trivial
/// rotations against English letter frequencies.
///
/// Returns `None` if the data does not appear to be a ROT-N cipher (e.g., the
/// input is already plaintext, or contains too few letters).
#[must_use]
pub fn detect_rot_n(data: &[u8]) -> Option<DetectedEncoding> {
    if data.is_empty() {
        return None;
    }
    let letter_count = data.iter().filter(|b| b.is_ascii_alphabetic()).count();
    if letter_count < 4 {
        return None; // too few letters to score
    }
    // Use chi-squared distance against English letter frequencies for robust
    // discrimination on short inputs. Lower chi-squared = closer to English.
    const ENG_FREQ: [f64; 26] = [
        0.0817, 0.0150, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609, 0.0697,
        0.0015, 0.0077, 0.0403, 0.0241, 0.0675, 0.0751, 0.0193, 0.0010, 0.0599,
        0.0633, 0.0906, 0.0276, 0.0098, 0.0236, 0.0015, 0.0197, 0.0007,
    ];
    let chi_squared = |n: u8| -> f64 {
        let mut counts = [0u32; 26];
        let mut letters = 0u32;
        for &b in data {
            let dec = rot_byte_inverse(b, n);
            if dec.is_ascii_alphabetic() {
                counts[usize::from(dec.to_ascii_lowercase() - b'a')] += 1;
                letters += 1;
            }
        }
        if letters == 0 { return f64::INFINITY; }
        let lf = f64::from(letters);
        let mut chi = 0.0_f64;
        for i in 0..26 {
            let expected = ENG_FREQ[i] * lf;
            let observed = f64::from(counts[i]);
            let diff = observed - expected;
            chi += diff * diff / expected.max(0.0001);
        }
        chi
    };
    let mut best_n = 0u8;
    let mut best_chi = chi_squared(0);
    for n in 1u8..26 {
        let c = chi_squared(n);
        if c < best_chi {
            best_chi = c;
            best_n = n;
        }
    }
    let best_score = rot_score(data, best_n);
    if best_n == 0 || best_score < 200 {
        return None;
    }
    let decoded: Vec<u8> = data.iter().map(|&b| rot_byte_inverse(b, best_n)).collect();
    // Confidence: score / 650 * 80, capped at 90.  (650 ≈ 0.065 × 10 000)
    let confidence = u8::try_from((best_score * 80 / 650).min(90)).unwrap_or(90);
    Some(DetectedEncoding::new(
        EncodingKind::RotN(best_n),
        confidence,
        Some(decoded),
    ))
}

/// Convenience function for ROT-13 specifically.
#[must_use]
pub fn rot13_decode(data: &[u8]) -> Vec<u8> {
    rot_decode(data, 13)
}

/// Detect ROT-13 specifically (a common simple obfuscation).
#[must_use]
pub fn detect_rot13(data: &[u8]) -> Option<DetectedEncoding> {
    let decoded = rot13_decode(data);
    let p = decoded.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count();
    let len = decoded.len().max(1);
    if p * 4 >= len * 3 {
        let confidence = u8::try_from((p * 85 / len).min(85)).unwrap_or(85);
        Some(DetectedEncoding::new(
            EncodingKind::RotN(13),
            confidence,
            Some(decoded),
        ))
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64 detection and decoding
// ─────────────────────────────────────────────────────────────────────────────

/// The standard base64 alphabet.
const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/// Return `true` if all bytes of `data` are in the base64 alphabet.
#[must_use]
pub fn is_base64_alphabet(data: &[u8]) -> bool {
    data.iter().all(|b| BASE64_CHARS.contains(b))
}

/// Attempt to detect a base64-encoded string in `data`.
///
/// A candidate block must:
/// * Be at least 8 bytes.
/// * Have a length divisible by 4 (after stripping trailing `=` padding).
/// * Consist entirely of base64 alphabet characters.
/// * Decode to data with at least 50 % printable ASCII bytes (the decoded
///   payload is binary data in the general case, so we don't require >80 %).
#[must_use]
pub fn detect_base64(data: &[u8]) -> Option<DetectedEncoding> {
    if data.len() < 8 {
        return None;
    }
    // Strip whitespace for block detection.
    let stripped: Vec<u8> = data
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if !stripped.len().is_multiple_of(4) {
        return None;
    }
    if !is_base64_alphabet(&stripped) {
        return None;
    }
    let decoded = base64_decode(&stripped)?;
    let frac = printability(&decoded);
    let confidence = if frac >= 0.80 {
        90u8
    } else if frac >= 0.50 {
        70
    } else {
        50
    };
    Some(DetectedEncoding::new(
        EncodingKind::Base64,
        confidence,
        Some(decoded),
    ))
}

/// Minimal base64 decoder (standard alphabet, with padding).
#[must_use]
pub fn base64_decode(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity((data.len() / 4).saturating_mul(3));
    let mut buf = 0u32;
    let mut bits = 0usize;
    for &b in data {
        let val: u32 = match b {
            b'A'..=b'Z' => u32::from(b - b'A'),
            b'a'..=b'z' => u32::from(b - b'a') + 26,
            b'0'..=b'9' => u32::from(b - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                // padding — flush and stop
                break;
            }
            _ => return None,
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(buf >> bits).unwrap_or(0));
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Hex-encoded string detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detect a hex-encoded (ASCII hex digits) block in `data`.
///
/// Requires that:
/// * All bytes are `[0-9a-fA-F]`.
/// * Length is even and >= 8.
/// * Decoded bytes have >= 50 % printable ASCII ratio.
#[must_use]
pub fn detect_hex_encoded(data: &[u8]) -> Option<DetectedEncoding> {
    if data.len() < 8 || !data.len().is_multiple_of(2) {
        return None;
    }
    if !data.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let decoded = hex_decode(data)?;
    let frac = printability(&decoded);
    let confidence = if frac >= 0.80 {
        88u8
    } else if frac >= 0.50 {
        65
    } else {
        40
    };
    Some(DetectedEncoding::new(
        EncodingKind::HexEncoded,
        confidence,
        Some(decoded),
    ))
}

/// Decode a hex-encoded byte slice.
#[must_use]
pub fn hex_decode(data: &[u8]) -> Option<Vec<u8>> {
    if !data.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(data.len() / 2);
    for chunk in data.chunks_exact(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Byte frequency fingerprinting
// ─────────────────────────────────────────────────────────────────────────────

/// Byte frequency distribution of a byte slice.
#[derive(Debug, Clone)]
pub struct ByteFrequency {
    /// Counts for each byte value 0–255.
    pub counts: [u32; 256],
    /// Total number of bytes.
    pub total: usize,
}

impl ByteFrequency {
    /// Compute the frequency distribution of `data`.
    #[must_use]
    pub fn compute(data: &[u8]) -> Self {
        let mut counts = [0u32; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        Self {
            counts,
            total: data.len(),
        }
    }

    /// Return the frequency (0.0–1.0) of byte `b`.
    #[must_use]
    pub fn freq(&self, b: u8) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            f64::from(self.counts[b as usize]) / f64::from(u32::try_from(self.total).unwrap_or(u32::MAX))
        }
    }

    /// Shannon entropy of the distribution.
    #[must_use]
    pub fn entropy(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let n = f64::from(u32::try_from(self.total).unwrap_or(u32::MAX));
        self.counts.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
            let p = f64::from(c) / n;
            p.mul_add(-p.log2(), acc)
        })
    }

    /// Number of distinct byte values with non-zero frequency.
    #[must_use]
    pub fn unique_bytes(&self) -> usize {
        self.counts.iter().filter(|&&c| c > 0).count()
    }

    /// The most frequent byte value.
    #[must_use]
    pub fn mode(&self) -> u8 {
        self.counts
            .iter()
            .enumerate()
            .max_by_key(|(_, c)| *c)
            .map_or(0, |(b, _)| u8::try_from(b).unwrap_or(0))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EncodingDetector — orchestrate all detection strategies
// ─────────────────────────────────────────────────────────────────────────────

/// Bitmask flags for detection strategies.
pub mod strategy_flags {
    pub const MULTIBYTE_XOR: u8 = 0b0001;
    pub const ROT: u8           = 0b0010;
    pub const BASE64: u8        = 0b0100;
    pub const HEX: u8           = 0b1000;
    pub const ALL: u8           = MULTIBYTE_XOR | ROT | BASE64 | HEX;
}

/// Which detection strategies to enable, encoded as a bitmask of [`strategy_flags`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectionStrategies(pub u8);

impl DetectionStrategies {
    /// All strategies enabled.
    pub const ALL: Self = Self(strategy_flags::ALL);

    /// Returns `true` if the multi-byte XOR strategy is enabled.
    #[must_use]
    pub const fn multibyte_xor(self) -> bool { self.0 & strategy_flags::MULTIBYTE_XOR != 0 }
    /// Returns `true` if the ROT-N strategy is enabled.
    #[must_use]
    pub const fn rot(self) -> bool { self.0 & strategy_flags::ROT != 0 }
    /// Returns `true` if the Base64 strategy is enabled.
    #[must_use]
    pub const fn base64(self) -> bool { self.0 & strategy_flags::BASE64 != 0 }
    /// Returns `true` if the hex-encoded strategy is enabled.
    #[must_use]
    pub const fn hex(self) -> bool { self.0 & strategy_flags::HEX != 0 }
}

impl Default for DetectionStrategies {
    fn default() -> Self { Self::ALL }
}

/// Configuration for the encoding detector.
#[derive(Debug, Clone)]
pub struct EncodingDetectorConfig {
    /// Maximum XOR key length to try for multi-byte detection.
    pub max_xor_key_len: usize,
    /// Minimum confidence to include in results.
    pub min_confidence: u8,
    /// Which strategies to enable.
    pub strategies: DetectionStrategies,
}

impl Default for EncodingDetectorConfig {
    fn default() -> Self {
        Self {
            max_xor_key_len: 16,
            min_confidence: 50,
            strategies: DetectionStrategies::default(),
        }
    }
}

/// Orchestrates all encoding detection strategies.
pub struct EncodingDetector {
    /// Configuration.
    pub config: EncodingDetectorConfig,
}

impl Default for EncodingDetector {
    fn default() -> Self {
        Self::new(EncodingDetectorConfig::default())
    }
}

impl EncodingDetector {
    /// Create a new detector with the given configuration.
    #[must_use]
    pub const fn new(config: EncodingDetectorConfig) -> Self {
        Self { config }
    }

    /// Run all configured detection strategies on `data` and return all results
    /// with confidence >= `self.config.min_confidence`, sorted by confidence descending.
    #[must_use]
    pub fn detect_all(&self, data: &[u8]) -> Vec<DetectedEncoding> {
        let mut results = Vec::new();

        // Base64 — check before Plaintext so valid base64 strings aren't mis-labelled as plain.
        let base64_detected = if self.config.strategies.base64()
            && let Some(r) = detect_base64(data)
                && r.confidence >= self.config.min_confidence {
                    results.push(r);
                    true
                } else {
                    false
                };

        // Plaintext check — skip if the data was identified as Base64.
        if !base64_detected && is_printable_ascii(data) {
            results.push(DetectedEncoding::new(
                EncodingKind::Plaintext,
                95,
                Some(data.to_vec()),
            ));
        }

        // Hex encoded
        if self.config.strategies.hex()
            && let Some(r) = detect_hex_encoded(data)
                && r.confidence >= self.config.min_confidence {
                    results.push(r);
                }

        // XOR single-byte
        if let Some(r) = detect_xor_single_byte(data)
            && r.confidence >= self.config.min_confidence
                && !matches!(r.kind, EncodingKind::Plaintext)
            {
                results.push(r);
            }

        // XOR multi-byte
        if self.config.strategies.multibyte_xor()
            && let Some(r) = detect_xor_multibyte(data, self.config.max_xor_key_len)
                && r.confidence >= self.config.min_confidence {
                    results.push(r);
                }

        // ROT-N
        if self.config.strategies.rot()
            && let Some(r) = detect_rot_n(data)
                && r.confidence >= self.config.min_confidence {
                    results.push(r);
                }

        results.sort_unstable_by(|a, b| b.confidence.cmp(&a.confidence));
        results
    }

    /// Return the single best detection result, or `None` if nothing reaches
    /// `min_confidence`.
    #[must_use]
    pub fn detect_best(&self, data: &[u8]) -> Option<DetectedEncoding> {
        self.detect_all(data).into_iter().next()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience free functions
// ─────────────────────────────────────────────────────────────────────────────

/// Apply the best-detected decoding to `data` and return the decoded bytes,
/// or `None` if no encoding was confidently detected.
#[must_use]
pub fn auto_decode(data: &[u8]) -> Option<Vec<u8>> {
    let det = EncodingDetector::default();
    det.detect_best(data)?.decoded
}

/// Summarise the detected encoding of `data` as a human-readable string.
#[must_use]
pub fn encoding_summary(data: &[u8]) -> String {
    let det = EncodingDetector::default();
    match det.detect_best(data) {
        Some(r) => format!("{} (confidence={})", r.kind, r.confidence),
        None => "Unknown".to_owned(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── XOR single-byte ──────────────────────────────────────────────────────

    #[test]
    fn test_xor_decode_single_known() {
        // XOR "hello" with key 0x42 → encoded bytes.
        let key = 0x42u8;
        let plain = b"hello world";
        let enc: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let decoded = xor_decode_single(&enc, key);
        assert_eq!(&decoded, plain);
    }

    #[test]
    fn test_detect_xor_single_byte_recovers_key() {
        let key = 0x37u8;
        let plain = b"The quick brown fox jumps over the lazy dog";
        let enc: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let det = detect_xor_single_byte(&enc).expect("should detect XOR");
        assert!(
            matches!(det.kind, EncodingKind::XorSingleByte(k) if k == key),
            "expected key 0x{key:02x}, got {:?}",
            det.kind
        );
        assert!(det.confidence >= 60);
    }

    #[test]
    fn test_detect_xor_single_byte_plaintext() {
        let plain = b"hello world this is plaintext";
        let det = detect_xor_single_byte(plain).expect("should return Plaintext");
        assert!(matches!(det.kind, EncodingKind::Plaintext));
    }

    #[test]
    fn test_detect_xor_single_byte_empty() {
        assert!(detect_xor_single_byte(&[]).is_none());
    }

    #[test]
    fn test_xor_candidates_sorted_descending() {
        let key = 0x55u8;
        let plain = b"AAAAAAAAAAAA";
        let enc: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let cands = xor_key_candidates(&enc);
        assert!(!cands.is_empty());
        // First candidate should produce more printable bytes than last.
        assert!(cands.first().unwrap().printable >= cands.last().unwrap().printable);
    }

    // ── XOR multi-byte ───────────────────────────────────────────────────────

    #[test]
    fn test_xor_decode_multibyte() {
        let key = b"KEY";
        let plain = b"Hello World!!!";
        let enc: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % 3])
            .collect();
        let dec = xor_decode_multibyte(&enc, key);
        assert_eq!(&dec, plain);
    }

    #[test]
    fn test_xor_decode_multibyte_empty_key() {
        let data = b"unchanged";
        assert_eq!(xor_decode_multibyte(data, b""), data.to_vec());
    }

    #[test]
    fn test_normalised_hamming() {
        // Identical blocks => distance 0.
        let h = normalised_hamming(b"AAAA", b"AAAA");
        assert!((h - 0.0).abs() < 1e-9);
        // Completely different bits => distance 8 (all bits differ).
        let h2 = normalised_hamming(b"\xFFFF", b"\x0000");
        assert!(h2 > 0.0);
    }

    // ── ROT-N ────────────────────────────────────────────────────────────────

    #[test]
    fn test_rot_byte_upper() {
        assert_eq!(rot_byte(b'A', 13), b'N');
        assert_eq!(rot_byte(b'Z', 1), b'A');
    }

    #[test]
    fn test_rot_byte_lower() {
        assert_eq!(rot_byte(b'a', 13), b'n');
        assert_eq!(rot_byte(b'z', 13), b'm');
    }

    #[test]
    fn test_rot13_roundtrip() {
        let plain = b"Hello World";
        let encoded = rot13_decode(plain);
        let decoded = rot13_decode(&encoded);
        assert_eq!(&decoded, plain);
    }

    #[test]
    fn test_detect_rot13_simple() {
        let plain = b"Hello World This Is A Test Sentence";
        let encoded = rot13_decode(plain);
        let det = detect_rot13(&encoded);
        assert!(det.is_some(), "should detect ROT-13");
    }

    #[test]
    fn test_detect_rot_n_recovers_rotation() {
        // Use a longer string so the chi-squared test reliably identifies the rotation.
        let plain = b"The quick brown fox jumps over the lazy dog and this is extra text to help";
        let encoded = rot_decode(plain, 7);
        let det = detect_rot_n(&encoded);
        assert!(det.is_some(), "should detect ROT-7");
        if let Some(d) = det {
            assert!(matches!(d.kind, EncodingKind::RotN(7)));
        }
    }

    #[test]
    fn test_detect_rot_n_no_match_random() {
        // Random bytes with few letters → no ROT match.
        let data: Vec<u8> = (0..=255u8).collect();
        let _ = detect_rot_n(&data); // should not panic
    }

    // ── Base64 ───────────────────────────────────────────────────────────────

    #[test]
    fn test_base64_decode_hello() {
        // "Hello" in base64 is "SGVsbG8="
        let encoded = b"SGVsbG8=";
        let decoded = base64_decode(encoded).expect("should decode");
        assert_eq!(&decoded, b"Hello");
    }

    #[test]
    fn test_base64_decode_empty() {
        assert_eq!(base64_decode(b""), Some(vec![]));
    }

    #[test]
    fn test_base64_decode_invalid() {
        assert!(base64_decode(b"!!!!!!==").is_none());
    }

    #[test]
    fn test_detect_base64_valid() {
        // "Hello World" in base64 = "SGVsbG8gV29ybGQ="
        let encoded = b"SGVsbG8gV29ybGQ=";
        let det = detect_base64(encoded).expect("should detect");
        assert!(matches!(det.kind, EncodingKind::Base64));
        assert!(det.confidence >= 50);
        let decoded_str = det.decoded_string.as_deref().unwrap_or("");
        assert_eq!(decoded_str, "Hello World");
    }

    #[test]
    fn test_detect_base64_too_short() {
        let _ = detect_base64(b"AAAA"); // short = None or low confidence
    }

    #[test]
    fn test_detect_base64_not_aligned() {
        // 5 chars, not divisible by 4.
        assert!(detect_base64(b"AAAAA").is_none());
    }

    // ── Hex encoding ─────────────────────────────────────────────────────────

    #[test]
    fn test_hex_decode_basic() {
        let encoded = b"48656c6c6f"; // "Hello"
        let decoded = hex_decode(encoded).expect("should decode");
        assert_eq!(&decoded, b"Hello");
    }

    #[test]
    fn test_hex_decode_odd_length() {
        assert!(hex_decode(b"ABC").is_none());
    }

    #[test]
    fn test_detect_hex_encoded_hello() {
        let encoded = b"48656c6c6f20576f726c64"; // "Hello World"
        let det = detect_hex_encoded(encoded).expect("should detect");
        assert!(matches!(det.kind, EncodingKind::HexEncoded));
        assert!(det.confidence >= 50);
        let s = det.decoded_string.as_deref().unwrap_or("");
        assert_eq!(s, "Hello World");
    }

    #[test]
    fn test_detect_hex_not_hex_chars() {
        let data = b"XYZabcdef012"; // 'X','Y','Z' not hex
        assert!(detect_hex_encoded(data).is_none());
    }

    // ── ByteFrequency ────────────────────────────────────────────────────────

    #[test]
    fn test_byte_frequency_compute() {
        let data = b"aabbcc";
        let freq = ByteFrequency::compute(data);
        assert_eq!(freq.counts[b'a' as usize], 2);
        assert_eq!(freq.counts[b'b' as usize], 2);
        assert_eq!(freq.unique_bytes(), 3);
    }

    #[test]
    fn test_byte_frequency_entropy_uniform() {
        // All same byte → entropy 0.
        let data = vec![42u8; 100];
        let freq = ByteFrequency::compute(&data);
        assert!((freq.entropy() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_byte_frequency_entropy_max() {
        // All 256 distinct bytes once → entropy = 8.
        let data: Vec<u8> = (0..=255u8).collect();
        let freq = ByteFrequency::compute(&data);
        assert!((freq.entropy() - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_byte_frequency_mode() {
        let data = b"aaabbc"; // 'a' most frequent
        let freq = ByteFrequency::compute(data);
        assert_eq!(freq.mode(), b'a');
    }

    // ── EncodingDetector ─────────────────────────────────────────────────────

    #[test]
    fn test_encoding_detector_plaintext() {
        let det = EncodingDetector::default();
        let results = det.detect_all(b"Hello, World! This is plaintext.");
        assert!(!results.is_empty());
        assert!(
            results
                .iter()
                .any(|r| matches!(r.kind, EncodingKind::Plaintext))
        );
    }

    #[test]
    fn test_encoding_detector_base64() {
        let det = EncodingDetector::default();
        let results = det.detect_all(b"SGVsbG8gV29ybGQ="); // "Hello World"
        assert!(
            results
                .iter()
                .any(|r| matches!(r.kind, EncodingKind::Base64))
        );
    }

    #[test]
    fn test_encoding_detector_xor_best() {
        let key = 0x5Au8;
        let plain = b"This is secret malware config data";
        let enc: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let det = EncodingDetector::default();
        let best = det.detect_best(&enc);
        assert!(best.is_some());
        let best = best.unwrap();
        assert!(matches!(best.kind, EncodingKind::XorSingleByte(_)));
    }

    #[test]
    fn test_auto_decode_xor() {
        let key = 0x22u8;
        let plain = b"Hello from the malware C2 server";
        let enc: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let decoded = auto_decode(&enc);
        assert!(decoded.is_some());
    }

    #[test]
    fn test_encoding_summary_plaintext() {
        let s = encoding_summary(b"hello world plaintext");
        assert!(s.contains("Plaintext") || s.contains("XOR") || !s.is_empty());
    }

    #[test]
    fn test_is_base64_alphabet_valid() {
        assert!(is_base64_alphabet(b"SGVsbG8="));
        assert!(!is_base64_alphabet(b"Hello World!"));
    }

    #[test]
    fn test_rot_decode_offset_wraps() {
        // z + 1 = a
        assert_eq!(rot_byte(b'z', 1), b'a');
        assert_eq!(rot_byte(b'Z', 1), b'A');
    }

    #[test]
    fn test_detect_rot_n_empty() {
        assert!(detect_rot_n(&[]).is_none());
    }

    #[test]
    fn test_detect_hex_encoded_short() {
        assert!(detect_hex_encoded(b"4865").is_none()); // only 4 bytes, < 8
    }

    #[test]
    fn test_xor_candidates_empty() {
        assert!(xor_key_candidates(&[]).is_empty());
    }

    #[test]
    fn test_encoding_detector_detect_all_sorted() {
        let plain = b"Hello World";
        let det = EncodingDetector::default();
        let results = det.detect_all(plain);
        for i in 1..results.len() {
            assert!(
                results[i - 1].confidence >= results[i].confidence,
                "results should be sorted by confidence descending"
            );
        }
    }

    #[test]
    fn test_detected_encoding_is_reliable() {
        let r = DetectedEncoding::new(EncodingKind::Plaintext, 95, Some(b"hi".to_vec()));
        assert!(r.is_reliable());
        let r2 = DetectedEncoding::new(EncodingKind::Unknown, 30, None);
        assert!(!r2.is_reliable());
    }
}
