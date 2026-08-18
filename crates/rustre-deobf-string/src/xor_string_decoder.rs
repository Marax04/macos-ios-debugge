//! XOR-encrypted string decoder with single/multi-byte key brute force.
//!
//! Provides [`XorStringDecoder`] for bulk analysis of byte slices that may
//! contain XOR-obfuscated strings, as well as standalone helpers for
//! single-pass decoding and key scoring.
//!
//! # Layer distinction
//! This module is the **low-level XOR scan layer**.  It offers:
//! - [`score_plaintext`]: chi-squared English-frequency scorer used by other
//!   modules (e.g. [`crate::custom_encoding_detector`]).
//! - [`brute_force_xor`] / [`brute_force_xor_multi`]: exhaustive single- and
//!   multi-byte key recovery from a raw buffer.
//! - [`XorStringDecoder::scan`]: sliding-window scan that finds XOR-encoded
//!   substrings inside a larger binary blob.
//!
//! For decode-loop detection, result caching, null-terminated key pools, and
//! rotating-key variants see [`crate::xor_string_decryptor`].

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// XorKey
// ─────────────────────────────────────────────────────────────────────────────

/// A single- or multi-byte XOR key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct XorKey {
    /// Raw key bytes.
    pub bytes: Vec<u8>,
}

impl XorKey {
    /// Create a single-byte key.
    #[must_use]
    pub fn single(k: u8) -> Self {
        Self { bytes: vec![k] }
    }

    /// Create a multi-byte key.
    #[must_use]
    pub fn multi(bytes: impl Into<Vec<u8>>) -> Self {
        Self { bytes: bytes.into() }
    }

    /// Returns `true` for the identity key (all-zero single byte — no-op XOR).
    #[must_use]
    pub fn is_trivial(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }

    /// Key length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` when the key has zero length (degenerate).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Apply this key to `data` (XOR with rolling key).
    #[must_use]
    pub fn apply(&self, data: &[u8]) -> Vec<u8> {
        if self.bytes.is_empty() { return data.to_vec(); }
        data.iter().enumerate()
            .map(|(i, &b)| b ^ self.bytes[i % self.bytes.len()])
            .collect()
    }
}

impl fmt::Display for XorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.bytes.len() == 1 {
            write!(f, "0x{:02x}", self.bytes[0])
        } else {
            write!(f, "[")?;
            for (i, b) in self.bytes.iter().enumerate() {
                if i > 0 { write!(f, " ")?; }
                write!(f, "{b:02x}")?;
            }
            write!(f, "]")
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DecodedString
// ─────────────────────────────────────────────────────────────────────────────

/// A successfully decoded candidate string.
#[derive(Debug, Clone)]
pub struct DecodedString {
    /// Byte offset in the original buffer.
    pub offset: usize,
    /// The XOR key that produced this string.
    pub key: XorKey,
    /// The decoded printable text.
    pub text: String,
    /// Score (higher = more likely to be real text).
    pub score: f64,
}

impl DecodedString {
    /// Returns `true` if the decoded text is a plausible ASCII string.
    #[must_use]
    pub fn is_plausible(&self) -> bool {
        self.score > 0.5
    }
}

impl fmt::Display for DecodedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:#06x}] key={} score={:.2} {:?}", self.offset, self.key, self.score, self.text)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scoring helpers
// ─────────────────────────────────────────────────────────────────────────────

/// English letter frequency table (index = char - 'a', percentage).
const LETTER_FREQ: [f64; 26] = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
    0.772, 4.025, 2.406,  6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
    2.758, 0.978, 2.360,  0.150, 1.974, 0.074,
];

/// Letter statistics gathered over a (possibly decoded) byte sequence.
///
/// Extracted so that [`score_plaintext`] and [`score_plaintext_xored`] cannot
/// drift apart: they differ only in how bytes are produced, never in how they
/// are judged. They previously *had* drifted — the inline copy divided chi by
/// 50 where this one divided by 200 — which made a key's selection score
/// incomparable with the score it was later ranked by.
struct TextStats {
    letter_counts: [usize; 26],
    printable: usize,
    total_letters: usize,
    len: usize,
}

impl TextStats {
    #[inline]
    const fn tally(&mut self, b: u8) {
        if b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\t' {
            self.printable += 1;
        }
        if b.is_ascii_alphabetic() {
            self.letter_counts[(b.to_ascii_lowercase() - b'a') as usize] += 1;
            self.total_letters += 1;
        }
    }

    /// The single definition of "how English does this look?", in 0.0–1.0.
    ///
    /// Chi-squared is normalised **per letter**. Un-normalised, the statistic
    /// shrinks as the sample shrinks, so the old formula was monotone in the
    /// wrong direction: fewer letters meant a smaller chi and therefore a
    /// *higher* score, and printable punctuation such as `-<..*2/9lon` (three
    /// letters) outranked genuine English such as `password123` (eight). The
    /// density term closes the remaining gap — letters are the evidence for
    /// English, so text carrying almost none cannot score as if it did.
    fn score(&self) -> f64 {
        if self.len == 0 {
            return 0.0;
        }
        let printable_ratio = self.printable as f64 / self.len as f64;
        if printable_ratio < 0.8 {
            return printable_ratio * 0.5;
        }
        if self.total_letters == 0 {
            return printable_ratio * 0.6;
        }

        let n = self.total_letters as f64;
        let chi: f64 = self
            .letter_counts
            .iter()
            .enumerate()
            .map(|(i, &cnt)| {
                let expected = LETTER_FREQ[i] / 100.0 * n;
                let diff = cnt as f64 - expected;
                diff * diff / (expected + 1e-9)
            })
            .sum();

        // Per-letter chi: scale-free, so short and long samples compare fairly.
        let chi_score = 1.0 / (1.0 + (chi / n) / 4.0);
        // English prose runs ~55%+ letters once spaces and punctuation are counted.
        let density = (n / self.len as f64 / 0.55).min(1.0);

        printable_ratio * 0.25 + chi_score * 0.45 + density * 0.30
    }
}

/// Score a byte slice as English ASCII text.  Returns 0.0–1.0.
#[must_use]
pub fn score_plaintext(data: &[u8]) -> f64 {
    let mut stats = TextStats {
        letter_counts: [0; 26],
        printable: 0,
        total_letters: 0,
        len: data.len(),
    };
    for &b in data {
        stats.tally(b);
    }
    stats.score()
}

/// Convert a byte slice to a lossy UTF-8 string, replacing non-printable chars.
#[must_use]
pub fn to_display_string(data: &[u8]) -> String {
    data.iter().map(|&b| {
        if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }
    }).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Brute-force helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Brute-force all 256 single-byte XOR keys against `data`.
///
/// Returns all results sorted by score descending.
#[must_use]
pub fn brute_force_xor(data: &[u8]) -> Vec<(XorKey, f64, Vec<u8>)> {
    let mut results: Vec<(XorKey, f64, Vec<u8>)> = (0u8..=255)
        .map(|k| {
            let key = XorKey::single(k);
            let decoded = key.apply(data);
            let score = score_plaintext(&decoded);
            (key, score, decoded)
        })
        .collect();
    results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    results
}

/// Brute-force multi-byte XOR keys for `key_len` in `[1, max_key_len]`.
///
/// Uses the index-of-coincidence method to estimate the most likely key length,
/// then brute-forces each key byte independently.
#[must_use]
pub fn brute_force_xor_multi(data: &[u8], max_key_len: usize) -> Vec<(XorKey, f64)> {
    if data.is_empty() || max_key_len == 0 { return vec![]; }

    let mut results = Vec::new();
    for klen in 1..=max_key_len.min(data.len() / 2).min(16) {
        if let Some(key) = solve_multi_byte(data, klen) {
            let decoded = key.apply(data);
            let score = score_plaintext(&decoded);
            results.push((key, score));
        }
    }
    results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    results
}

/// Solve a multi-byte XOR key of a specific length by independently brute-
/// forcing each key byte position using frequency analysis.
fn solve_multi_byte(data: &[u8], key_len: usize) -> Option<XorKey> {
    if key_len == 0 { return None; }
    let mut key_bytes = Vec::with_capacity(key_len);
    // Reuse a single column buffer across positions to reduce allocations.
    let mut column: Vec<u8> = Vec::with_capacity((data.len() / key_len) + 1);
    for pos in 0..key_len {
        column.clear();
        column.extend(data.iter().skip(pos).step_by(key_len).copied());
        // Score each key byte candidate in-place (XOR is its own inverse).
        let (best_k, _) = (0u8..=255)
            .map(|k| {
                // Compute score_plaintext inline to avoid decoded Vec allocation.
                let s = score_plaintext_xored(&column, k);
                (k, s)
            })
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))?;
        key_bytes.push(best_k);
    }
    Some(XorKey::multi(key_bytes))
}

/// Score a column `XORed` with `k` without allocating a decoded buffer.
///
/// Identical to `score_plaintext(&column.iter().map(|c| c ^ k).collect())`, but
/// it decodes into the tally instead of into a `Vec`. The judgement itself is
/// [`TextStats::score`], shared with [`score_plaintext`], so the two can no
/// longer disagree about what a good decoding looks like.
fn score_plaintext_xored(column: &[u8], k: u8) -> f64 {
    let mut stats = TextStats {
        letter_counts: [0; 26],
        printable: 0,
        total_letters: 0,
        len: column.len(),
    };
    for &ct in column {
        stats.tally(ct ^ k);
    }
    stats.score()
}

// ─────────────────────────────────────────────────────────────────────────────
// XorStringDecoder
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the [`XorStringDecoder`].
#[derive(Debug, Clone)]
pub struct XorDecodeConfig {
    /// Minimum decoded string length to consider.
    pub min_length: usize,
    /// Minimum score threshold to report a candidate.
    pub min_score: f64,
    /// Maximum key length to try for multi-byte brute force.
    pub max_key_len: usize,
    /// Whether to also try multi-byte keys.
    pub try_multi_byte: bool,
    /// Only report strings that decode to pure ASCII.
    pub require_ascii: bool,
}

impl Default for XorDecodeConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            min_score: 0.55,
            max_key_len: 8,
            try_multi_byte: true,
            require_ascii: false,
        }
    }
}

/// Decoder that scans a binary blob for XOR-obfuscated strings.
///
/// Uses a sliding-window approach: for each window of `min_length..=max_len`
/// bytes, tries all single-byte (and optionally multi-byte) keys and collects
/// candidates that score above the threshold.
#[derive(Debug)]
pub struct XorStringDecoder {
    /// Configuration.
    pub config: XorDecodeConfig,
    /// Found candidates, populated after calling [`XorStringDecoder::scan`].
    pub candidates: Vec<DecodedString>,
}

impl XorStringDecoder {
    /// Create with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: XorDecodeConfig::default(),
            candidates: Vec::new(),
        }
    }

    /// Create with a custom configuration.
    #[must_use]
    pub const fn with_config(config: XorDecodeConfig) -> Self {
        Self { config, candidates: Vec::new() }
    }

    /// Scan a binary blob for XOR-encoded strings.
    ///
    /// Clears any previous results and populates `self.candidates`.
    pub fn scan(&mut self, data: &[u8]) {
        self.candidates.clear();
        let step = self.config.min_length.max(1);
        let mut seen: HashMap<(usize, u8), ()> = HashMap::new();

        let mut offset = 0;
        while offset + self.config.min_length <= data.len() {
            // Determine window end: grow until score drops or we hit a null run.
            let window_end = find_window_end(data, offset, self.config.min_length);
            if window_end <= offset { offset += step; continue; }

            let window = &data[offset..window_end];

            // Single-byte brute force
            let bf = brute_force_xor(window);
            if let Some((key, score, decoded)) = bf.into_iter().next() {
                if score >= self.config.min_score && !key.is_trivial() {
                    let k0 = key.bytes[0];
                    if seen.insert((offset, k0), ()).is_none() {
                        if let Ok(text) = std::str::from_utf8(&decoded) {
                            if !self.config.require_ascii || text.is_ascii() {
                                self.candidates.push(DecodedString {
                                    offset,
                                    key,
                                    text: text.to_owned(),
                                    score,
                                });
                            }
                        } else {
                            let text = to_display_string(&decoded);
                            if !self.config.require_ascii {
                                self.candidates.push(DecodedString {
                                    offset,
                                    key: XorKey::single(k0),
                                    text,
                                    score,
                                });
                            }
                        }
                    }
                }
            }

            // Multi-byte keys
            if self.config.try_multi_byte && window.len() >= self.config.max_key_len * 2 {
                let multi = brute_force_xor_multi(window, self.config.max_key_len);
                for (key, score) in multi.into_iter().take(3) {
                    if key.len() < 2 { continue; }
                    if score >= self.config.min_score {
                        let decoded = key.apply(window);
                        let text = String::from_utf8_lossy(&decoded).into_owned();
                        self.candidates.push(DecodedString { offset, key, text, score });
                    }
                }
            }

            offset += step;
        }

        self.candidates.sort_by(|a, b| b.score.partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal));
    }

    /// Decode a specific byte slice with a known [`XorKey`].
    #[must_use]
    pub fn decode_with_key(&self, data: &[u8], key: &XorKey) -> Vec<u8> {
        key.apply(data)
    }

    /// Return the top N candidates by score.
    #[must_use]
    pub fn top_candidates(&self, n: usize) -> &[DecodedString] {
        &self.candidates[..n.min(self.candidates.len())]
    }

    /// Deduplicate candidates by (offset, key).
    pub fn dedup(&mut self) {
        let mut seen = std::collections::HashSet::new();
        self.candidates.retain(|c| {
            seen.insert((c.offset, c.key.bytes.clone()))
        });
    }
}

impl Default for XorStringDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Find the end of a decodable window starting at `offset`.
///
/// Grows the window until a run of zeros (likely padding) is found or the
/// buffer ends.  Returns at least `offset + min_len`.
fn find_window_end(data: &[u8], offset: usize, min_len: usize) -> usize {
    let max_end = (offset + 256).min(data.len());
    let mut end = offset + min_len;
    while end < max_end {
        // Stop at a run of 4+ identical bytes (likely padding/null-terminated end)
        if end + 4 <= data.len() &&
            data[end] == data[end+1] && data[end] == data[end+2] && data[end] == data[end+3] {
            break;
        }
        end += 1;
    }
    end.min(data.len())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_key_apply_single() {
        let key = XorKey::single(0x41);
        let data = vec![0x41 ^ b'H', 0x41 ^ b'e', 0x41 ^ b'l', 0x41 ^ b'l', 0x41 ^ b'o'];
        let decoded = key.apply(&data);
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn xor_key_apply_multi() {
        let key = XorKey::multi(vec![0x01, 0x02, 0x03]);
        let data: Vec<u8> = vec![b'A' ^ 0x01, b'B' ^ 0x02, b'C' ^ 0x03, b'D' ^ 0x01];
        let decoded = key.apply(&data);
        assert_eq!(decoded, b"ABCD");
    }

    #[test]
    fn xor_key_trivial() {
        assert!(XorKey::single(0).is_trivial());
        assert!(!XorKey::single(1).is_trivial());
    }

    #[test]
    fn xor_key_display_single() {
        let k = XorKey::single(0xAB);
        assert_eq!(format!("{k}"), "0xab");
    }

    #[test]
    fn xor_key_display_multi() {
        let k = XorKey::multi(vec![0x01, 0x02]);
        let s = format!("{k}");
        assert!(s.contains("01") && s.contains("02"));
    }

    #[test]
    fn score_plaintext_english() {
        let s = b"The quick brown fox jumps over the lazy dog";
        let score = score_plaintext(s);
        assert!(score > 0.7, "score {score} too low for English text");
    }

    #[test]
    fn score_plaintext_garbage() {
        let garbage: Vec<u8> = (0..50).map(|i| (i * 37 + 199) as u8).collect();
        let score = score_plaintext(&garbage);
        assert!(score < 0.5, "score {score} too high for garbage");
    }

    #[test]
    fn brute_force_xor_finds_key() {
        let plaintext = b"Hello, world! This is a test string.";
        let key = 0x5A_u8;
        let ciphertext: Vec<u8> = plaintext.iter().map(|&b| b ^ key).collect();
        let results = brute_force_xor(&ciphertext);
        assert!(!results.is_empty());
        assert_eq!(results[0].0, XorKey::single(key), "top key should be 0x{key:02x}");
    }

    #[test]
    fn brute_force_xor_returns_256_results() {
        let data = vec![0xAA; 32];
        let results = brute_force_xor(&data);
        assert_eq!(results.len(), 256);
    }

    #[test]
    fn brute_force_xor_multi_finds_2byte_key() {
        let plaintext = b"abcdefghijklmnopqrstuvwxyzabcdef";
        let key = vec![0x13u8, 0x37];
        let ct: Vec<u8> = plaintext.iter().enumerate()
            .map(|(i, &b)| b ^ key[i % 2]).collect();
        let results = brute_force_xor_multi(&ct, 4);
        assert!(!results.is_empty());
        assert!(results[0].1 > 0.5);
    }

    #[test]
    fn decoder_scan_finds_xor_string() {
        let plaintext = b"password123";
        let key = 0x42_u8;
        let ct: Vec<u8> = plaintext.iter().map(|&b| b ^ key).collect();
        let mut decoder = XorStringDecoder::new();
        decoder.scan(&ct);
        let found = decoder.candidates.iter().any(|c| c.key == XorKey::single(key));
        assert!(found, "should find the XOR string with key 0x42");
    }

    #[test]
    fn decoder_decode_with_known_key() {
        let decoder = XorStringDecoder::new();
        let ct = vec![0x48 ^ 0x10, 0x65 ^ 0x10, 0x6C ^ 0x10];
        let decoded = decoder.decode_with_key(&ct, &XorKey::single(0x10));
        assert_eq!(decoded, b"Hel");
    }

    #[test]
    fn decoder_top_candidates() {
        let mut decoder = XorStringDecoder::new();
        let plaintext = b"The quick brown fox";
        let ct: Vec<u8> = plaintext.iter().map(|&b| b ^ 0x33).collect();
        decoder.scan(&ct);
        let top = decoder.top_candidates(3);
        assert!(top.len() <= 3);
    }

    #[test]
    fn decoder_dedup() {
        let mut decoder = XorStringDecoder::new();
        decoder.candidates.push(DecodedString {
            offset: 0, key: XorKey::single(1), text: "a".into(), score: 0.9,
        });
        decoder.candidates.push(DecodedString {
            offset: 0, key: XorKey::single(1), text: "a".into(), score: 0.9,
        });
        decoder.dedup();
        assert_eq!(decoder.candidates.len(), 1);
    }

    #[test]
    fn xor_key_len_and_empty() {
        let k = XorKey::single(5);
        assert_eq!(k.len(), 1);
        assert!(!k.is_empty());
        let empty = XorKey { bytes: vec![] };
        assert!(empty.is_empty());
    }
}
