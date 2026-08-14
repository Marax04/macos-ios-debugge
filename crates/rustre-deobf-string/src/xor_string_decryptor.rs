//! XOR string decryption: detect XOR decode loops, extract key bytes,
//! recover all encrypted strings, validate decrypted output.
//!
//! # Layer distinction
//! This module is the **higher-level XOR decryptor**.  It adds:
//! - Heuristic decode-loop detection from raw x86 byte sequences ([`XorDecryptor::detect_loops_heuristic`]).
//! - Batch decrypt with a results cache ([`XorDecryptor::batch_decrypt`]).
//! - Null-terminated key recovery from a binary pool ([`XorDecryptor::try_null_terminated_keys`]).
//! - Rotating-key decrypt ([`XorDecryptor::decrypt_with_rotating_key`]).
//! - Aggregate statistics ([`XorDecryptionStats`]).
//!
//! For low-level brute-force scanning of a binary blob (sliding-window approach,
//! chi-squared English scoring, multi-byte key via frequency analysis) see the
//! [`crate::xor_string_decoder`] module.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// XorKeyType — describes the key structure found in a decode loop
// ─────────────────────────────────────────────────────────────────────────────

/// Describes the type of XOR key material used in a decode loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XorKeyType {
    /// A single constant byte repeated for the entire buffer.
    SingleByte,
    /// A multi-byte key that repeats cyclically: key[i % keylen].
    Cyclic,
    /// Key derived from a null-terminated byte string in the binary.
    NullTerminated,
    /// Key byte changes every iteration based on a rotation or increment.
    Rolling,
    /// Key uses a linear congruential generator step.
    Lcg,
}

impl fmt::Display for XorKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SingleByte => write!(f, "single-byte"),
            Self::Cyclic => write!(f, "cyclic"),
            Self::NullTerminated => write!(f, "null-terminated"),
            Self::Rolling => write!(f, "rolling"),
            Self::Lcg => write!(f, "lcg"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XorLoop — represents a detected decode loop in disassembly bytes
// ─────────────────────────────────────────────────────────────────────────────

/// A detected XOR decode loop found in a code region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XorLoop {
    /// Virtual address of the loop header.
    pub loop_addr: u64,
    /// Number of instructions inside the loop body.
    pub body_insn_count: usize,
    /// Whether the loop increments an index register.
    pub has_index_increment: bool,
    /// Whether the loop contains a memory load (reading ciphertext).
    pub has_mem_load: bool,
    /// Whether the loop contains a memory store (writing plaintext).
    pub has_mem_store: bool,
    /// Whether the loop body contains an XOR operation.
    pub has_xor: bool,
    /// Estimated key length in bytes (1 = constant).
    pub key_length_hint: usize,
    /// Confidence that this is a string decode loop (0–100).
    pub confidence: u8,
}

impl XorLoop {
    /// Create a new `XorLoop` record.
    #[must_use]
    pub fn new(loop_addr: u64) -> Self {
        Self {
            loop_addr,
            body_insn_count: 0,
            has_index_increment: false,
            has_mem_load: false,
            has_mem_store: false,
            has_xor: false,
            key_length_hint: 1,
            confidence: 0,
        }
    }

    /// Compute the confidence score from detected components.
    #[must_use]
    pub fn computed_confidence(&self) -> u8 {
        let mut score: u32 = 0;
        if self.has_xor { score += 40; }
        if self.has_mem_load { score += 20; }
        if self.has_mem_store { score += 20; }
        if self.has_index_increment { score += 10; }
        if self.body_insn_count >= 3 && self.body_insn_count <= 30 { score += 10; }
        score.min(100) as u8
    }

    /// Returns `true` if this loop is likely a string decode loop.
    #[must_use]
    pub fn is_likely_decode_loop(&self) -> bool {
        self.has_xor && (self.has_mem_load || self.has_mem_store)
    }
}

impl fmt::Display for XorLoop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "XorLoop@{:#x} conf={} insns={} keylen_hint={}",
            self.loop_addr, self.confidence, self.body_insn_count, self.key_length_hint
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KeyCandidate — a proposed XOR key with scoring metadata
// ─────────────────────────────────────────────────────────────────────────────

/// A candidate XOR key together with its associated scoring.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyCandidate {
    /// The raw key bytes.
    pub key: Vec<u8>,
    /// Type of key structure this candidate represents.
    pub key_type: XorKeyType,
    /// Printable-ASCII ratio of the decrypted output (0.0–1.0).
    pub printable_ratio: f64,
    /// English-language frequency score of the decrypted output.
    pub english_score: f64,
    /// Overall confidence score (0–100).
    pub confidence: u8,
    /// Decrypted bytes produced by applying this key.
    pub decrypted: Vec<u8>,
}

impl KeyCandidate {
    /// Create a new candidate.
    #[must_use]
    pub fn new(key: Vec<u8>, key_type: XorKeyType, decrypted: Vec<u8>) -> Self {
        let printable_ratio = compute_printable_ratio(&decrypted);
        let english_score = compute_english_score(&decrypted);
        let confidence = ((printable_ratio * 80.0) + (english_score * 20.0)).min(100.0) as u8;
        Self {
            key,
            key_type,
            printable_ratio,
            english_score,
            confidence,
            decrypted,
        }
    }

    /// Returns `true` if the candidate appears to have produced a valid ASCII string.
    #[must_use]
    pub fn looks_like_string(&self) -> bool {
        self.printable_ratio >= 0.70
    }

    /// Try to interpret the decrypted bytes as a UTF-8 string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        let bytes = if self.decrypted.last().copied() == Some(0) {
            &self.decrypted[..self.decrypted.len() - 1]
        } else {
            &self.decrypted
        };
        std::str::from_utf8(bytes).ok()
    }
}

impl fmt::Display for KeyCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyCandidate({} {:02x?} pr={:.2} conf={})",
            self.key_type, self.key, self.printable_ratio, self.confidence
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DecryptedString — a recovered string with provenance
// ─────────────────────────────────────────────────────────────────────────────

/// A successfully decrypted string recovered from a binary.
#[derive(Debug, Clone, PartialEq)]
pub struct DecryptedString {
    /// Virtual address of the encrypted data.
    pub addr: u64,
    /// Raw (encrypted) bytes that were decrypted.
    pub ciphertext: Vec<u8>,
    /// The recovered plaintext value.
    pub plaintext: String,
    /// Key used to decrypt.
    pub key: Vec<u8>,
    /// Type of key.
    pub key_type: XorKeyType,
    /// Confidence in the recovered string (0–100).
    pub confidence: u8,
}

impl DecryptedString {
    /// Create a new `DecryptedString` record.
    #[must_use]
    pub fn new(
        addr: u64,
        ciphertext: Vec<u8>,
        plaintext: String,
        key: Vec<u8>,
        key_type: XorKeyType,
        confidence: u8,
    ) -> Self {
        Self {
            addr,
            ciphertext,
            plaintext,
            key,
            key_type,
            confidence,
        }
    }

    /// Length of the plaintext string.
    #[must_use]
    pub fn len(&self) -> usize {
        self.plaintext.len()
    }

    /// Returns `true` if the plaintext is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plaintext.is_empty()
    }

    /// Returns `true` if confidence is at or above 75.
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }
}

impl fmt::Display for DecryptedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DecryptedString@{:#x} [{:?}] conf={} : {:?}",
            self.addr, self.key_type, self.confidence, self.plaintext
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XorDecryptor — main entry point for XOR string recovery
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration options for the XOR decryptor.
#[derive(Debug, Clone)]
pub struct XorDecryptorConfig {
    /// Minimum printable ratio required to accept a decrypted candidate.
    pub min_printable_ratio: f64,
    /// Minimum plaintext length to be considered a valid string.
    pub min_string_length: usize,
    /// Maximum key length to try during cyclic key recovery.
    pub max_cyclic_key_len: usize,
    /// Whether to try rolling-XOR variants.
    pub try_rolling: bool,
    /// Whether to try null-terminated key strings found in the data.
    pub try_null_term_keys: bool,
}

impl Default for XorDecryptorConfig {
    fn default() -> Self {
        Self {
            min_printable_ratio: 0.70,
            min_string_length: 4,
            max_cyclic_key_len: 16,
            try_rolling: true,
            try_null_term_keys: true,
        }
    }
}

/// Main XOR string decryptor.
///
/// Accepts raw ciphertext buffers, scans for decode loops, extracts key
/// candidates, and returns recovered strings.
#[derive(Debug, Clone)]
pub struct XorDecryptor {
    config: XorDecryptorConfig,
    /// Cache: key bytes → list of successful decryptions.
    results_cache: HashMap<Vec<u8>, Vec<DecryptedString>>,
}

impl XorDecryptor {
    /// Create a decryptor with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: XorDecryptorConfig::default(),
            results_cache: HashMap::new(),
        }
    }

    /// Create a decryptor with a custom configuration.
    #[must_use]
    pub fn with_config(config: XorDecryptorConfig) -> Self {
        Self {
            config,
            results_cache: HashMap::new(),
        }
    }

    /// Clear the results cache.
    pub fn clear_cache(&mut self) {
        self.results_cache.clear();
    }

    // ── Single-buffer API ─────────────────────────────────────────────────────

    /// Try all 256 single-byte XOR keys on `ciphertext`, returning the top-N
    /// candidates sorted by confidence (highest first).
    #[must_use]
    pub fn try_single_byte(&self, ciphertext: &[u8], addr: u64) -> Vec<DecryptedString> {
        let mut results = Vec::new();
        for key in 1u8..=255 {
            let dec: Vec<u8> = ciphertext.iter().map(|&b| b ^ key).collect();
            let pr = compute_printable_ratio(&dec);
            if pr >= self.config.min_printable_ratio {
                if let Some(s) = maybe_utf8_string(&dec, self.config.min_string_length) {
                    let confidence = ((pr * 90.0) as u8).min(100);
                    results.push(DecryptedString::new(
                        addr, ciphertext.to_vec(), s, vec![key],
                        XorKeyType::SingleByte, confidence,
                    ));
                }
            }
        }
        results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        results
    }

    /// Try cyclic (multi-byte repeating) XOR keys of length 2–`max_key_len`.
    ///
    /// Uses index-of-coincidence to rank key lengths, then recovers each key
    /// byte via frequency analysis on the corresponding sub-stream.
    #[must_use]
    pub fn try_cyclic_key(
        &self,
        ciphertext: &[u8],
        addr: u64,
    ) -> Vec<DecryptedString> {
        let mut results = Vec::new();
        let max_len = self.config.max_cyclic_key_len.min(ciphertext.len() / 2).min(32);
        if max_len < 2 {
            return results;
        }

        // For each key length, recover key via per-byte frequency analysis.
        for key_len in 2..=max_len {
            let mut key = Vec::with_capacity(key_len);
            for offset in 0..key_len {
                let stream: Vec<u8> = ciphertext.iter().copied().skip(offset).step_by(key_len).collect();
                key.push(best_single_byte_key(&stream));
            }
            let dec: Vec<u8> = ciphertext
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ key[i % key_len])
                .collect();
            let pr = compute_printable_ratio(&dec);
            if pr >= self.config.min_printable_ratio {
                if let Some(s) = maybe_utf8_string(&dec, self.config.min_string_length) {
                    let confidence = ((pr * 85.0) as u8).min(100);
                    results.push(DecryptedString::new(
                        addr, ciphertext.to_vec(), s, key,
                        XorKeyType::Cyclic, confidence,
                    ));
                }
            }
        }
        results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        results
    }

    /// Try rolling XOR: each byte is XORed with `initial ^ (i & 0xff)`.
    #[must_use]
    pub fn try_rolling_key(&self, ciphertext: &[u8], addr: u64) -> Vec<DecryptedString> {
        if !self.config.try_rolling {
            return Vec::new();
        }
        let mut results = Vec::new();
        for init in 0u8..=255 {
            let dec: Vec<u8> = ciphertext
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ init.wrapping_add(i as u8))
                .collect();
            let pr = compute_printable_ratio(&dec);
            if pr >= self.config.min_printable_ratio {
                if let Some(s) = maybe_utf8_string(&dec, self.config.min_string_length) {
                    let confidence = ((pr * 75.0) as u8).min(100);
                    // Rank on how English the decoding looks, not on `pr`: every
                    // surviving candidate cleared the same printable threshold,
                    // so `pr` is near-constant here and cannot order them. Only
                    // eight are kept, and without a discriminating key the stable
                    // sort kept the eight lowest `init` values instead of the
                    // eight best decodings.
                    let rank = score_decoded(&dec);
                    results.push((rank, DecryptedString::new(
                        addr, ciphertext.to_vec(), s, vec![init],
                        XorKeyType::Rolling, confidence,
                    )));
                }
            }
        }
        results.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(8);
        results.into_iter().map(|(_, d)| d).collect()
    }

    /// Try using null-terminated strings found in `key_pool` as cyclic keys.
    #[must_use]
    pub fn try_null_terminated_keys(
        &self,
        ciphertext: &[u8],
        key_pool: &[u8],
        addr: u64,
    ) -> Vec<DecryptedString> {
        if !self.config.try_null_term_keys {
            return Vec::new();
        }
        let keys = extract_null_terminated_strings(key_pool, 2, 32);
        let mut results = Vec::new();
        for key in &keys {
            let dec: Vec<u8> = ciphertext
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ key[i % key.len()])
                .collect();
            let pr = compute_printable_ratio(&dec);
            if pr >= self.config.min_printable_ratio {
                if let Some(s) = maybe_utf8_string(&dec, self.config.min_string_length) {
                    let confidence = ((pr * 88.0) as u8).min(100);
                    results.push(DecryptedString::new(
                        addr, ciphertext.to_vec(), s, key.clone(),
                        XorKeyType::NullTerminated, confidence,
                    ));
                }
            }
        }
        results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        results
    }

    /// Batch-decrypt a list of `(addr, ciphertext)` tuples using all strategies.
    ///
    /// Returns all valid decryptions, deduplicated by (addr, plaintext).
    #[must_use]
    pub fn batch_decrypt(&mut self, buffers: &[(u64, Vec<u8>)]) -> Vec<DecryptedString> {
        let mut all = Vec::new();
        for (addr, ct) in buffers {
            let cache_key = ct.clone();
            if let Some(cached) = self.results_cache.get(&cache_key) {
                all.extend(cached.iter().cloned());
                continue;
            }
            let mut local = Vec::new();
            local.extend(self.try_single_byte(ct, *addr));
            local.extend(self.try_cyclic_key(ct, *addr));
            if self.config.try_rolling {
                local.extend(self.try_rolling_key(ct, *addr));
            }
            // Deduplicate by plaintext.
            local.sort_by(|a, b| b.confidence.cmp(&a.confidence));
            local.dedup_by(|a, b| a.plaintext == b.plaintext);
            self.results_cache.insert(cache_key, local.clone());
            all.extend(local);
        }
        all
    }

    // ── Loop detection ────────────────────────────────────────────────────────

    /// Heuristically detect XOR decode loops from a flat byte buffer of code.
    ///
    /// Looks for patterns matching: load → XOR → store → increment index → cmp/jnz.
    /// This is a byte-level heuristic (not full disassembly).
    #[must_use]
    pub fn detect_loops_heuristic(code: &[u8], base_addr: u64) -> Vec<XorLoop> {
        let mut loops = Vec::new();
        let len = code.len();
        if len < 8 {
            return loops;
        }
        // Scan for sequences that suggest xor mem, reg or xor reg, mem.
        // x86 XOR opcodes: 30-35, 66 30-35, REX 30-35, 80-81/0x6, F6/F7/0x6.
        let mut i = 0usize;
        while i + 4 < len {
            let b0 = code[i];
            let is_xor = matches!(b0, 0x30..=0x35 | 0x80 | 0x81 | 0xF6 | 0xF7)
                || (b0 == 0x48 && i + 1 < len && matches!(code[i + 1], 0x31 | 0x33 | 0x35));
            if is_xor {
                // Scan backwards 24 bytes for a loop context (MOV or INC near a JNZ).
                let scan_start = i.saturating_sub(24);
                let window = &code[scan_start..i + 4];
                let has_inc = window.iter().any(|&b| matches!(b, 0x40..=0x47 | 0xFE | 0xFF));
                let has_mov_load = window.windows(2).any(|w| matches!(w[0], 0x88..=0x8B));
                let has_jnz = window.iter().any(|&b| matches!(b, 0x75 | 0xEB | 0xE2));
                let mut lp = XorLoop::new(base_addr + scan_start as u64);
                lp.has_xor = true;
                lp.has_index_increment = has_inc;
                lp.has_mem_load = has_mov_load;
                lp.has_mem_store = has_mov_load;
                lp.body_insn_count = window.len() / 2; // rough estimate
                if has_jnz { lp.body_insn_count = lp.body_insn_count.min(15); }
                lp.confidence = lp.computed_confidence();
                if lp.confidence >= 30 {
                    loops.push(lp);
                }
                i += 4;
            } else {
                i += 1;
            }
        }
        // Deduplicate by loop_addr proximity.
        loops.dedup_by(|a, b| a.loop_addr.abs_diff(b.loop_addr) < 32);
        loops
    }

    // ── Key rotation / validation ─────────────────────────────────────────────

    /// Verify that decrypting `ciphertext` with the given cyclic key produces output
    /// with the required printable ratio. Returns the ratio.
    #[must_use]
    pub fn validate_key(ciphertext: &[u8], key: &[u8]) -> f64 {
        if key.is_empty() || ciphertext.is_empty() {
            return 0.0;
        }
        let dec: Vec<u8> = ciphertext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        compute_printable_ratio(&dec)
    }

    /// Extract all key candidates from a `ciphertext` buffer by trying all
    /// single-byte keys and returning the top-`n` sorted by printable ratio.
    #[must_use]
    pub fn top_single_byte_candidates(ciphertext: &[u8], n: usize) -> Vec<KeyCandidate> {
        let mut candidates: Vec<KeyCandidate> = (0u8..=255)
            .map(|key| {
                let dec: Vec<u8> = ciphertext.iter().map(|&b| b ^ key).collect();
                KeyCandidate::new(vec![key], XorKeyType::SingleByte, dec)
            })
            .collect();
        candidates.sort_by(|a, b| {
            b.printable_ratio
                .partial_cmp(&a.printable_ratio)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        candidates.truncate(n);
        candidates
    }

    /// Apply a key rotation schedule: `key[i % keylen] = key[(i + step) % keylen]`.
    ///
    /// Used for malware that scrambles its XOR key during the decrypt loop.
    #[must_use]
    pub fn decrypt_with_rotating_key(ciphertext: &[u8], key: &[u8], step: usize) -> Vec<u8> {
        if key.is_empty() {
            return ciphertext.to_vec();
        }
        let mut k = key.to_vec();
        ciphertext
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                let plain = b ^ k[i % k.len()];
                // Rotate key by step each time we wrap around.
                if i > 0 && i % k.len() == 0 {
                    let len = k.len();
                    k.rotate_left(step.min(len - 1));
                }
                plain
            })
            .collect()
    }

    /// Reference to the current configuration.
    #[must_use]
    pub const fn config(&self) -> &XorDecryptorConfig {
        &self.config
    }

    /// Number of entries in the results cache.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.results_cache.len()
    }
}

impl Default for XorDecryptor {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XOR statistics helper
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics about a batch XOR decryption run.
#[derive(Debug, Clone, Default)]
pub struct XorDecryptionStats {
    /// Number of buffers processed.
    pub buffers_processed: usize,
    /// Number of successfully decrypted strings.
    pub strings_recovered: usize,
    /// Number of unique keys discovered.
    pub unique_keys: usize,
    /// Distribution of key types found.
    pub key_type_counts: HashMap<String, usize>,
}

impl XorDecryptionStats {
    /// Build statistics from a list of decrypted strings.
    #[must_use]
    pub fn from_results(results: &[DecryptedString], buffers_processed: usize) -> Self {
        let mut key_type_counts: HashMap<String, usize> = HashMap::new();
        let mut keys_seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        for r in results {
            *key_type_counts.entry(r.key_type.to_string()).or_insert(0) += 1;
            keys_seen.insert(r.key.clone());
        }
        Self {
            buffers_processed,
            strings_recovered: results.len(),
            unique_keys: keys_seen.len(),
            key_type_counts,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal utility functions
// ─────────────────────────────────────────────────────────────────────────────

fn compute_printable_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let count = data.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ').count();
    count as f64 / data.len() as f64
}

fn compute_english_score(data: &[u8]) -> f64 {
    const FREQ: [f64; 26] = [
        0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609, 0.0697, 0.0015,
        0.0077, 0.0403, 0.0241, 0.0675, 0.0751, 0.0193, 0.0010, 0.0599, 0.0633, 0.0906,
        0.0276, 0.0098, 0.0236, 0.0015, 0.0197, 0.0007,
    ];
    if data.is_empty() {
        return 0.0;
    }
    let mut score = 0.0f64;
    for &b in data {
        if b.is_ascii_lowercase() {
            score += FREQ[(b - b'a') as usize];
        } else if b.is_ascii_uppercase() {
            score += FREQ[(b - b'A') as usize];
        } else if b == b' ' {
            score += 0.13;
        }
    }
    (score / data.len() as f64).min(1.0)
}

fn best_single_byte_key(stream: &[u8]) -> u8 {
    let mut best_key = 0u8;
    let mut best_score = 0.0f64;
    // Score directly on the strided stream without allocating a decoded Vec.
    for k in 0u8..=255 {
        // Inline score computation to avoid Vec allocation per key candidate.
        let score = score_xored_stream(stream, k);
        if score > best_score {
            best_score = score;
            best_key = k;
        }
    }
    best_key
}

const FREQ: [f64; 26] = [
    0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609, 0.0697, 0.0015,
    0.0077, 0.0403, 0.0241, 0.0675, 0.0751, 0.0193, 0.0010, 0.0599, 0.0633, 0.0906,
    0.0276, 0.0098, 0.0236, 0.0015, 0.0197, 0.0007,
];

/// How much does this decoded byte sequence look like English text?
///
/// The one definition in this module, over an iterator so callers can decode
/// on the fly instead of materialising a `Vec`. Ranges 0.0–1.5.
fn score_decoded_iter<I: Iterator<Item = u8>>(bytes: I, len: usize) -> f64 {
    if len == 0 {
        return 0.0;
    }
    let mut english_score = 0.0f64;
    let mut printable = 0usize;
    for b in bytes {
        if b.is_ascii_graphic() || b == b' ' {
            printable += 1;
        }
        if b.is_ascii_lowercase() {
            english_score += FREQ[(b - b'a') as usize];
        } else if b.is_ascii_uppercase() {
            english_score += FREQ[(b - b'A') as usize];
        } else if b == b' ' {
            english_score += 0.13;
        }
    }
    let n = len as f64;
    (english_score / n).min(1.0) + (printable as f64 / n) * 0.5
}

/// Score an already-decoded buffer.
///
/// Exists because every candidate-generating path in this module used to rank
/// by [`compute_printable_ratio`] alone, which assigns the *same* value to real
/// plaintext and to printable noise. With no signal in the ordering, the
/// stable sort fell back on insertion order and `truncate` kept whichever
/// candidates happened to be generated first — discarding correct answers the
/// code had already computed.
fn score_decoded(data: &[u8]) -> f64 {
    score_decoded_iter(data.iter().copied(), data.len())
}

/// Score `stream XOR k` inline without allocating a temporary `Vec<u8>`.
fn score_xored_stream(stream: &[u8], k: u8) -> f64 {
    score_decoded_iter(stream.iter().map(|&ct| ct ^ k), stream.len())
}

fn maybe_utf8_string(bytes: &[u8], min_len: usize) -> Option<String> {
    let trimmed = if bytes.last().copied() == Some(0) {
        &bytes[..bytes.len() - 1]
    } else {
        bytes
    };
    if trimmed.len() < min_len {
        return None;
    }
    std::str::from_utf8(trimmed).ok().map(std::borrow::ToOwned::to_owned)
}

/// Extract all null-terminated byte strings from a buffer.
fn extract_null_terminated_strings(data: &[u8], min_len: usize, max_len: usize) -> Vec<Vec<u8>> {
    let mut strings = Vec::new();
    let mut start = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if b == 0 {
            let s = &data[start..i];
            if s.len() >= min_len && s.len() <= max_len && s.iter().all(|&c| c >= 0x20 && c < 0x7F) {
                strings.push(s.to_vec());
            }
            start = i + 1;
        }
    }
    strings
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_byte_xor_roundtrip() {
        let key = 0x42u8;
        let plaintext = b"Hello, World!";
        let ct: Vec<u8> = plaintext.iter().map(|&b| b ^ key).collect();
        let dec = XorDecryptor::new();
        let results = dec.try_single_byte(&ct, 0x1000);
        assert!(results.iter().any(|r| r.plaintext == "Hello, World!"));
    }

    #[test]
    fn detect_loops_finds_xor_pattern() {
        // Construct a byte pattern: MOV + XOR + INC + JNZ.
        let code = [0x8A, 0x04, 0x0A, 0x30, 0x04, 0x0B, 0x41, 0x75, 0xF8];
        let loops = XorDecryptor::detect_loops_heuristic(&code, 0);
        assert!(!loops.is_empty());
    }

    #[test]
    fn key_candidate_confidence_single_byte() {
        let dec = b"printable ASCII text here".to_vec();
        let c = KeyCandidate::new(vec![0x41], XorKeyType::SingleByte, dec);
        assert!(c.confidence > 50);
    }

    #[test]
    fn validate_key_good() {
        let key = b"KEY".to_vec();
        let plain = b"Hello";
        let ct: Vec<u8> = plain.iter().enumerate().map(|(i, &b)| b ^ key[i % key.len()]).collect();
        let ratio = XorDecryptor::validate_key(&ct, &key);
        assert!(ratio > 0.8);
    }

    #[test]
    fn rolling_key_decrypt() {
        let init = 0x10u8;
        let plain = b"TestString";
        let ct: Vec<u8> = plain.iter().enumerate().map(|(i, &b)| b ^ init.wrapping_add(i as u8)).collect();
        let dec = XorDecryptor::new();
        let res = dec.try_rolling_key(&ct, 0);
        assert!(res.iter().any(|r| r.plaintext.contains("TestString")));
    }

    #[test]
    fn xor_loop_display() {
        let lp = XorLoop::new(0xDEAD);
        let s = lp.to_string();
        assert!(s.contains("0xdead") || s.contains("0xDEAD") || s.contains("dead") || s.contains("DEAD"));
    }

    #[test]
    fn stats_from_results() {
        let s = DecryptedString::new(0, vec![], "hi".into(), vec![1], XorKeyType::SingleByte, 80);
        let stats = XorDecryptionStats::from_results(&[s], 5);
        assert_eq!(stats.buffers_processed, 5);
        assert_eq!(stats.strings_recovered, 1);
    }
}
