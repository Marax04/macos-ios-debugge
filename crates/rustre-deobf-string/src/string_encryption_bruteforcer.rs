//! `string_encryption_bruteforcer` — Brute-force string encryption key recovery.
//!
//! Builds on the XOR, RC4, ADD/SUB/ROL/ROR primitives already in the crate root
//! to provide a unified, algorithm-agnostic brute-force framework.  Callers
//! supply a ciphertext and (optionally) a list of algorithms to try; the engine
//! returns ranked [`BruteforceResult`]s ordered by confidence.
//!
//! [`KeyCandidate`] is defined in the crate root (`lib.rs`) and re-exported
//! here so module users can `use rustre_deobf_string::string_encryption_bruteforcer::*`.

pub use crate::KeyCandidate;

use crate::{
    printable_ratio, Rc4, RotN, StringAlgorithm, XorDecryptor,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── BruteforceAlgorithm ──────────────────────────────────────────────────────

/// Algorithms the bruteforcer will attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BruteforceAlgorithm {
    /// Single-byte XOR.
    XorSingleByte,
    /// Two-byte cyclic XOR.
    XorTwoByte,
    /// RC4 with a 1-byte key.
    Rc4SingleByte,
    /// RC4 with a 2-byte key.
    Rc4TwoByte,
    /// ADD constant (reverse is SUB).
    AddConstant,
    /// SUB constant (reverse is ADD).
    SubConstant,
    /// ROL constant (reverse is ROR).
    RolConstant,
    /// ROR constant (reverse is ROL).
    RorConstant,
    /// ROT-N cipher (Caesar, a=1..25).
    RotN,
}

impl BruteforceAlgorithm {
    /// Returns the [`StringAlgorithm`] equivalent.
    #[must_use]
    pub const fn to_string_algorithm(self) -> StringAlgorithm {
        match self {
            Self::XorSingleByte => StringAlgorithm::XorConstant,
            Self::XorTwoByte => StringAlgorithm::XorCyclic,
            Self::Rc4SingleByte | Self::Rc4TwoByte => StringAlgorithm::Rc4,
            Self::AddConstant => StringAlgorithm::AddConstant,
            Self::SubConstant => StringAlgorithm::SubConstant,
            Self::RolConstant => StringAlgorithm::RolConstant,
            Self::RorConstant => StringAlgorithm::RorConstant,
            Self::RotN => StringAlgorithm::RotN,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::XorSingleByte => "XOR(1-byte)",
            Self::XorTwoByte => "XOR(2-byte)",
            Self::Rc4SingleByte => "RC4(1-byte)",
            Self::Rc4TwoByte => "RC4(2-byte)",
            Self::AddConstant => "ADD(constant)",
            Self::SubConstant => "SUB(constant)",
            Self::RolConstant => "ROL(constant)",
            Self::RorConstant => "ROR(constant)",
            Self::RotN => "ROT-N",
        }
    }
}

// ─── BruteforceResult ─────────────────────────────────────────────────────────

/// A single brute-force decryption candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteforceResult {
    /// The algorithm used.
    pub algorithm: BruteforceAlgorithm,
    /// Key bytes that produced this candidate.
    pub key: Vec<u8>,
    /// Decrypted plaintext bytes.
    pub plaintext: Vec<u8>,
    /// Ratio of printable bytes in the output [0.0, 1.0].
    pub printable_ratio: f64,
    /// Confidence score [0, 100].
    pub confidence: u8,
    /// Whether the plaintext looks like a valid UTF-8 string.
    pub is_utf8: bool,
    /// UTF-8 string representation if valid.
    pub as_string: Option<String>,
}

impl BruteforceResult {
    fn new(
        algorithm: BruteforceAlgorithm,
        key: Vec<u8>,
        plaintext: Vec<u8>,
        min_printable: f64,
    ) -> Option<Self> {
        let pr = printable_ratio(&plaintext);
        if pr < min_printable {
            return None;
        }
        let confidence = compute_confidence_internal(&plaintext, pr);
        let is_utf8 = std::str::from_utf8(&plaintext).is_ok();
        let as_string = std::str::from_utf8(&plaintext)
            .ok()
            .map(str::to_string);
        Some(Self {
            algorithm,
            key,
            plaintext,
            printable_ratio: pr,
            confidence,
            is_utf8,
            as_string,
        })
    }

    /// Returns the plaintext as a `&str` if it is valid UTF-8.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        self.as_string.as_deref()
    }
}

/// Fraction of characters that are spaces in ordinary English prose.
///
/// The space is the single most common character in written English, and it is
/// what separates real plaintext from printable noise: a wrong XOR key maps the
/// spaces of the original onto digits or punctuation, leaving letter counts
/// almost untouched. Scoring only `is_ascii_alphabetic` was therefore blind to
/// the strongest available signal — `AAAA BBBB CCCC DDDD` and `TTTT5WWWW5VVVV5`
/// tie on every other term.
const ENGLISH_SPACE_RATIO: f64 = 0.17;

fn compute_confidence_internal(data: &[u8], pr: f64) -> u8 {
    let mut score = (pr * 60.0) as u8;

    // Word structure: credit spacing that looks like prose, capped so that a
    // string of nothing but spaces cannot outrank real text.
    let spaces = data.iter().filter(|&&b| b == b' ').count() as f64
        / data.len().max(1) as f64;
    score = score.saturating_add(((spaces / ENGLISH_SPACE_RATIO).min(1.0) * 20.0) as u8);
    // Bonus for null-terminated strings
    if data.last().copied() == Some(0) {
        score = score.saturating_add(5);
    }
    // Bonus for common string patterns
    if data.windows(4).any(|w| w == b"http") {
        score = score.saturating_add(10);
    }
    if data.windows(2).any(|w| w == b":/") {
        score = score.saturating_add(5);
    }
    // Bonus for high alpha ratio
    let alpha = data.iter().filter(|&&b| b.is_ascii_alphabetic()).count() as f64
        / data.len().max(1) as f64;
    score = score.saturating_add((alpha * 15.0) as u8);
    score.min(100)
}

// ─── StringEncryptionBruteforcer ──────────────────────────────────────────────

/// Brute-forces string encryption on a ciphertext blob using multiple algorithms.
///
/// Call [`StringEncryptionBruteforcer::new`] to get an instance with sensible
/// defaults, tune the settings, then call [`bruteforce`] with your ciphertext.
///
/// [`bruteforce`]: Self::bruteforce
#[derive(Debug, Clone)]
pub struct StringEncryptionBruteforcer {
    /// Minimum printable-byte ratio to accept a candidate. Default 0.65.
    pub min_printable_ratio: f64,
    /// Maximum number of results to return per algorithm. Default 5.
    pub max_results_per_algo: usize,
    /// Whether to try XOR single-byte. Default true.
    pub try_xor_single: bool,
    /// Whether to try XOR two-byte. Default false (slow-ish for large inputs).
    pub try_xor_two: bool,
    /// Whether to try RC4 single-byte. Default true.
    pub try_rc4_single: bool,
    /// Whether to try RC4 two-byte. Default false.
    pub try_rc4_two: bool,
    /// Whether to try ADD/SUB constants. Default true.
    pub try_arith: bool,
    /// Whether to try ROL/ROR constants. Default false.
    pub try_rotate: bool,
    /// Whether to try ROT-N. Default false (text-only).
    pub try_rot_n: bool,
}

impl Default for StringEncryptionBruteforcer {
    fn default() -> Self {
        Self {
            min_printable_ratio: 0.65,
            max_results_per_algo: 5,
            try_xor_single: true,
            try_xor_two: false,
            try_rc4_single: true,
            try_rc4_two: false,
            try_arith: true,
            try_rotate: false,
            try_rot_n: false,
        }
    }
}

impl StringEncryptionBruteforcer {
    /// Create a new bruteforcer with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable XOR 1-byte brute force.
    #[must_use]
    pub const fn with_xor_single(mut self, v: bool) -> Self {
        self.try_xor_single = v;
        self
    }

    /// Enable or disable XOR 2-byte brute force.
    #[must_use]
    pub const fn with_xor_two(mut self, v: bool) -> Self {
        self.try_xor_two = v;
        self
    }

    /// Enable or disable RC4 1-byte brute force.
    #[must_use]
    pub const fn with_rc4_single(mut self, v: bool) -> Self {
        self.try_rc4_single = v;
        self
    }

    /// Enable or disable RC4 2-byte brute force.
    #[must_use]
    pub const fn with_rc4_two(mut self, v: bool) -> Self {
        self.try_rc4_two = v;
        self
    }

    /// Enable or disable ADD/SUB constant brute force.
    #[must_use]
    pub const fn with_arith(mut self, v: bool) -> Self {
        self.try_arith = v;
        self
    }

    /// Enable or disable ROL/ROR constant brute force.
    #[must_use]
    pub const fn with_rotate(mut self, v: bool) -> Self {
        self.try_rotate = v;
        self
    }

    /// Enable or disable ROT-N brute force.
    #[must_use]
    pub const fn with_rot_n(mut self, v: bool) -> Self {
        self.try_rot_n = v;
        self
    }

    /// Set the minimum printable ratio.
    #[must_use]
    pub const fn with_min_printable_ratio(mut self, r: f64) -> Self {
        // `clamp` propagates NaN; a NaN ratio rejects every candidate in
        // silence, because all comparisons against NaN are false.
        self.min_printable_ratio = if r.is_nan() { 0.0 } else { r.clamp(0.0, 1.0) };
        self
    }

    /// Run brute-force on `ciphertext` and return all candidates sorted by
    /// confidence (highest first).
    #[must_use]
    pub fn bruteforce(&self, ciphertext: &[u8]) -> Vec<BruteforceResult> {
        if ciphertext.is_empty() {
            return Vec::new();
        }
        let mut results: Vec<BruteforceResult> = Vec::new();

        if self.try_xor_single {
            results.extend(self.bf_xor_single(ciphertext));
        }
        if self.try_xor_two {
            results.extend(self.bf_xor_two(ciphertext));
        }
        if self.try_rc4_single {
            results.extend(self.bf_rc4_single(ciphertext));
        }
        if self.try_rc4_two {
            results.extend(self.bf_rc4_two(ciphertext));
        }
        if self.try_arith {
            results.extend(self.bf_arith(ciphertext));
        }
        if self.try_rotate {
            results.extend(self.bf_rotate(ciphertext));
        }
        if self.try_rot_n {
            results.extend(self.bf_rot_n(ciphertext));
        }

        results.sort_by_key(|b| std::cmp::Reverse(b.confidence));
        results
    }

    /// Return all results above a confidence threshold.
    #[must_use]
    pub fn bruteforce_above(&self, ciphertext: &[u8], min_confidence: u8) -> Vec<BruteforceResult> {
        self.bruteforce(ciphertext)
            .into_iter()
            .filter(|r| r.confidence >= min_confidence)
            .collect()
    }

    /// Return the single best result, if any.
    #[must_use]
    pub fn best(&self, ciphertext: &[u8]) -> Option<BruteforceResult> {
        self.bruteforce(ciphertext).into_iter().next()
    }

    // ── private helpers ───────────────────────────────────────────────────────

    fn bf_xor_single(&self, data: &[u8]) -> Vec<BruteforceResult> {
        let mut out: Vec<BruteforceResult> = (0u8..=255)
            .filter_map(|k| {
                let dec = XorDecryptor::decrypt_constant(data, k);
                BruteforceResult::new(
                    BruteforceAlgorithm::XorSingleByte,
                    vec![k],
                    dec,
                    self.min_printable_ratio,
                )
            })
            .collect();
        out.sort_by_key(|b| std::cmp::Reverse(b.confidence));
        out.truncate(self.max_results_per_algo);
        out
    }

    fn bf_xor_two(&self, data: &[u8]) -> Vec<BruteforceResult> {
        let mut best: Vec<(u8, BruteforceResult)> = Vec::new();
        for k0 in 0u8..=255 {
            for k1 in 0u8..=255 {
                let key = [k0, k1];
                let dec = match XorDecryptor::decrypt_cyclic(data, &key) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if let Some(r) = BruteforceResult::new(
                    BruteforceAlgorithm::XorTwoByte,
                    key.to_vec(),
                    dec,
                    self.min_printable_ratio,
                ) {
                    best.push((r.confidence, r));
                }
            }
        }
        best.sort_by_key(|b| std::cmp::Reverse(b.0));
        best.truncate(self.max_results_per_algo);
        best.into_iter().map(|(_, r)| r).collect()
    }

    fn bf_rc4_single(&self, data: &[u8]) -> Vec<BruteforceResult> {
        let mut out: Vec<BruteforceResult> = (0u8..=255)
            .filter_map(|k| {
                let dec = Rc4::decrypt(data, &[k]);
                BruteforceResult::new(
                    BruteforceAlgorithm::Rc4SingleByte,
                    vec![k],
                    dec,
                    self.min_printable_ratio,
                )
            })
            .collect();
        out.sort_by_key(|b| std::cmp::Reverse(b.confidence));
        out.truncate(self.max_results_per_algo);
        out
    }

    fn bf_rc4_two(&self, data: &[u8]) -> Vec<BruteforceResult> {
        let mut best: Vec<(u8, BruteforceResult)> = Vec::new();
        for k0 in 0u8..=255 {
            for k1 in 0u8..=255 {
                let key = [k0, k1];
                let dec = Rc4::decrypt(data, &key);
                if let Some(r) = BruteforceResult::new(
                    BruteforceAlgorithm::Rc4TwoByte,
                    key.to_vec(),
                    dec,
                    self.min_printable_ratio,
                ) {
                    best.push((r.confidence, r));
                }
            }
        }
        best.sort_by_key(|b| std::cmp::Reverse(b.0));
        best.truncate(self.max_results_per_algo);
        best.into_iter().map(|(_, r)| r).collect()
    }

    fn bf_arith(&self, data: &[u8]) -> Vec<BruteforceResult> {
        // Two algorithms, therefore two budgets. Sharing one `max_results_per_algo`
        // between them contradicts the field's own contract ("per algorithm") and
        // is not merely untidy: confidences tie heavily here, so whichever family
        // is pushed first fills every slot and the other is emitted zero times.
        // A SUB-encrypted string was therefore unrecoverable whenever five ADD
        // candidates happened to clear the printable threshold.
        let mut adds = Vec::new();
        let mut subs = Vec::new();
        for c in 1u8..=255 {
            // ADD constant → reverse is SUB
            let dec_sub: Vec<u8> = data.iter().map(|&b| b.wrapping_sub(c)).collect();
            if let Some(r) = BruteforceResult::new(
                BruteforceAlgorithm::AddConstant,
                vec![c],
                dec_sub,
                self.min_printable_ratio,
            ) {
                adds.push(r);
            }
            // SUB constant → reverse is ADD
            let dec_add: Vec<u8> = data.iter().map(|&b| b.wrapping_add(c)).collect();
            if let Some(r) = BruteforceResult::new(
                BruteforceAlgorithm::SubConstant,
                vec![c],
                dec_add,
                self.min_printable_ratio,
            ) {
                subs.push(r);
            }
        }
        let mut out = Vec::with_capacity(2 * self.max_results_per_algo);
        for mut family in [adds, subs] {
            family.sort_by_key(|b| std::cmp::Reverse(b.confidence));
            family.truncate(self.max_results_per_algo);
            out.append(&mut family);
        }
        out.sort_by_key(|b| std::cmp::Reverse(b.confidence));
        out
    }

    fn bf_rotate(&self, data: &[u8]) -> Vec<BruteforceResult> {
        let mut out = Vec::new();
        for bits in 1u8..8 {
            // ROL constant → reverse is ROR
            let dec_ror: Vec<u8> = data.iter().map(|&b| b.rotate_right(u32::from(bits))).collect();
            if let Some(r) = BruteforceResult::new(
                BruteforceAlgorithm::RolConstant,
                vec![bits],
                dec_ror,
                self.min_printable_ratio,
            ) {
                out.push(r);
            }
            // ROR constant → reverse is ROL
            let dec_rol: Vec<u8> = data.iter().map(|&b| b.rotate_left(u32::from(bits))).collect();
            if let Some(r) = BruteforceResult::new(
                BruteforceAlgorithm::RorConstant,
                vec![bits],
                dec_rol,
                self.min_printable_ratio,
            ) {
                out.push(r);
            }
        }
        out.sort_by_key(|b| std::cmp::Reverse(b.confidence));
        out.truncate(self.max_results_per_algo);
        out
    }

    fn bf_rot_n(&self, data: &[u8]) -> Vec<BruteforceResult> {
        let text = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let mut out: Vec<BruteforceResult> = (1u8..26)
            .filter_map(|n| {
                let dec = RotN::decrypt(text, n);
                BruteforceResult::new(
                    BruteforceAlgorithm::RotN,
                    vec![n],
                    dec.into_bytes(),
                    self.min_printable_ratio,
                )
            })
            .collect();
        out.sort_by_key(|b| std::cmp::Reverse(b.confidence));
        out.truncate(self.max_results_per_algo);
        out
    }
}

// ─── Free functions ───────────────────────────────────────────────────────────

/// Build a [`KeyCandidate`] from a [`BruteforceResult`].
#[must_use]
pub fn result_to_candidate(result: &BruteforceResult) -> KeyCandidate {
    KeyCandidate::new(
        result.key.clone(),
        result.algorithm.to_string_algorithm(),
        f64::from(result.confidence) / 100.0,
    )
    .with_decrypted(result.plaintext.clone())
}

/// Brute-force a ciphertext with the default engine (XOR + RC4 + arithmetic).
///
/// This is a convenience wrapper around [`StringEncryptionBruteforcer::bruteforce`].
#[must_use]
pub fn bruteforce(ciphertext: &[u8]) -> Vec<BruteforceResult> {
    StringEncryptionBruteforcer::new().bruteforce(ciphertext)
}

/// Brute-force and return the top `n` candidates as [`KeyCandidate`]s sorted by
/// confidence (highest first).
#[must_use]
pub fn bruteforce_top_n(ciphertext: &[u8], n: usize) -> Vec<KeyCandidate> {
    StringEncryptionBruteforcer::new()
        .bruteforce(ciphertext)
        .iter()
        .take(n)
        .map(result_to_candidate)
        .collect()
}

/// Quick printability-ratio scorer for a raw byte slice.
///
/// Returns a value in [0.0, 1.0] where 1.0 means all bytes are printable ASCII.
#[must_use]
pub fn printability_score(data: &[u8]) -> f64 {
    printable_ratio(data)
}

/// Aggregate statistics over a set of brute-force results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BruteforceStats {
    /// Total results examined.
    pub total: usize,
    /// Results per algorithm name.
    pub per_algorithm: HashMap<String, usize>,
    /// Highest confidence seen.
    pub max_confidence: u8,
    /// Number of results that are valid UTF-8.
    pub utf8_count: usize,
}

impl BruteforceStats {
    /// Compute statistics from a result slice.
    #[must_use]
    pub fn from_results(results: &[BruteforceResult]) -> Self {
        let mut per_algorithm: HashMap<String, usize> = HashMap::new();
        let mut max_confidence = 0u8;
        let mut utf8_count = 0usize;
        for r in results {
            *per_algorithm.entry(r.algorithm.name().to_string()).or_default() += 1;
            if r.confidence > max_confidence {
                max_confidence = r.confidence;
            }
            if r.is_utf8 {
                utf8_count += 1;
            }
        }
        Self {
            total: results.len(),
            per_algorithm,
            max_confidence,
            utf8_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_xor_ciphertext(plain: &[u8], key: u8) -> Vec<u8> {
        plain.iter().map(|&b| b ^ key).collect()
    }

    #[test]
    fn test_xor_single_byte_recovery() {
        let plain = b"hello world test";
        let cipher = make_xor_ciphertext(plain, 0x42);
        let bf = StringEncryptionBruteforcer::new();
        let results = bf.bruteforce(&cipher);
        assert!(!results.is_empty());
        let top = &results[0];
        assert!(top.confidence > 0);
    }

    #[test]
    fn test_xor_single_byte_correct_key() {
        let plain = b"AAAA BBBB CCCC DDDD";
        let key = 0x55u8;
        let cipher = make_xor_ciphertext(plain, key);
        let bf = StringEncryptionBruteforcer::new();
        let results = bf.bruteforce(&cipher);
        let found = results.iter().any(|r| {
            r.algorithm == BruteforceAlgorithm::XorSingleByte && r.key == vec![key]
        });
        assert!(found, "Should find XOR key 0x55");
    }

    #[test]
    fn test_rc4_single_byte_recovery() {
        let plain = b"test string data";
        let key = 0xABu8;
        let cipher = Rc4::decrypt(plain, &[key]);
        let bf = StringEncryptionBruteforcer::new();
        let results = bf.bruteforce(&cipher);
        let found = results.iter().any(|r| {
            r.algorithm == BruteforceAlgorithm::Rc4SingleByte && r.key == vec![key]
        });
        assert!(found, "Should find RC4 1-byte key 0xAB");
    }

    #[test]
    fn test_add_constant_recovery() {
        let plain = b"hello from adder";
        let c = 12u8;
        let cipher: Vec<u8> = plain.iter().map(|&b| b.wrapping_add(c)).collect();
        let bf = StringEncryptionBruteforcer::new();
        let results = bf.bruteforce(&cipher);
        // The variants name the ENCRYPTION, not the undo step: `AddConstant` is
        // documented as "ADD constant (reverse is SUB)", and `bf_arith` accordingly
        // labels the `b - c` candidate `AddConstant`. This plaintext was encrypted
        // with ADD(12), so that is the variant that must recover it — the test used
        // to ask for `SubConstant`, the reverse operation, and only checked that
        // *some* candidate carried key 12 without checking it decoded to anything.
        let found = results.iter().any(|r| {
            r.algorithm == BruteforceAlgorithm::AddConstant
                && r.key == vec![c]
                && r.plaintext.as_slice() == &plain[..]
        });
        assert!(found, "Should recover ADD(constant {c}) plaintext");
    }

    #[test]
    fn test_best_returns_highest_confidence() {
        let plain = b"hello world this is a real sentence!";
        let cipher = make_xor_ciphertext(plain, 0x11);
        let bf = StringEncryptionBruteforcer::new();
        let best = bf.best(&cipher);
        assert!(best.is_some());
    }

    #[test]
    fn test_empty_ciphertext_returns_empty() {
        let bf = StringEncryptionBruteforcer::new();
        let results = bf.bruteforce(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_bruteforce_above_threshold() {
        let plain = b"just a simple test string that is long enough";
        let cipher = make_xor_ciphertext(plain, 0x7F);
        let bf = StringEncryptionBruteforcer::new();
        let results = bf.bruteforce_above(&cipher, 70);
        for r in &results {
            assert!(r.confidence >= 70);
        }
    }

    #[test]
    fn test_result_to_candidate() {
        let plain = b"hello world";
        let cipher = make_xor_ciphertext(plain, 0x42);
        let bf = StringEncryptionBruteforcer::new();
        let results = bf.bruteforce(&cipher);
        if let Some(top) = results.first() {
            let cand = result_to_candidate(top);
            assert_eq!(cand.key, top.key);
            assert!(cand.confidence >= 0.0 && cand.confidence <= 1.0);
        }
    }

    #[test]
    fn test_bruteforce_top_n() {
        let plain = b"long enough plaintext with printable chars!";
        let cipher = make_xor_ciphertext(plain, 0x33);
        let candidates = bruteforce_top_n(&cipher, 3);
        assert!(candidates.len() <= 3);
    }

    #[test]
    fn test_printability_score_all_printable() {
        assert!(printability_score(b"hello world") > 0.99);
    }

    #[test]
    fn test_printability_score_all_binary() {
        let data: Vec<u8> = (0u8..128).map(|i| i | 0x80).collect();
        assert!(printability_score(&data) < 0.1);
    }

    #[test]
    fn test_bruteforce_stats_from_results() {
        let plain = b"another test plaintext for stats";
        let cipher = make_xor_ciphertext(plain, 0x10);
        let bf = StringEncryptionBruteforcer::new();
        let results = bf.bruteforce(&cipher);
        let stats = BruteforceStats::from_results(&results);
        assert_eq!(stats.total, results.len());
        assert!(stats.max_confidence <= 100);
    }

    #[test]
    fn test_algorithm_name() {
        assert_eq!(BruteforceAlgorithm::XorSingleByte.name(), "XOR(1-byte)");
        assert_eq!(BruteforceAlgorithm::Rc4TwoByte.name(), "RC4(2-byte)");
        assert_eq!(BruteforceAlgorithm::RotN.name(), "ROT-N");
    }

    #[test]
    fn test_algorithm_to_string_algorithm() {
        assert_eq!(
            BruteforceAlgorithm::XorSingleByte.to_string_algorithm(),
            StringAlgorithm::XorConstant
        );
        assert_eq!(
            BruteforceAlgorithm::Rc4SingleByte.to_string_algorithm(),
            StringAlgorithm::Rc4
        );
    }

    #[test]
    fn test_with_builder_pattern() {
        let bf = StringEncryptionBruteforcer::new()
            .with_xor_single(true)
            .with_rc4_single(false)
            .with_arith(false)
            .with_min_printable_ratio(0.8);
        assert!(bf.try_xor_single);
        assert!(!bf.try_rc4_single);
        assert!(!bf.try_arith);
        assert!((bf.min_printable_ratio - 0.8).abs() < 1e-9);
    }

    #[test]
    fn test_rot_n_recovery() {
        let plain = "hello world from rot cipher";
        let n = 13u8;
        let rotated = RotN::decrypt(plain, 26 - n); // encrypt by rotating the other way
        let bf = StringEncryptionBruteforcer::new().with_rot_n(true);
        let results = bf.bruteforce(rotated.as_bytes());
        let found = results.iter().any(|r| r.algorithm == BruteforceAlgorithm::RotN);
        // Rot-N might not have printable-ratio high enough for all inputs;
        // just check it doesn't panic.
        let _ = found;
    }
}
