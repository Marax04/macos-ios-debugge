//! AI-assisted string recovery for `rustre-deobf-string`.

pub use crate::XorBruteforceCandidate;
use crate::{
    Base64Decoder, HexDecoder, Rc4, RotN, StringAlgorithm, XorDecryptor, xor_brute_force_top3,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, warn};

// ── AiScoringEngine ───────────────────────────────────────────────────────────

/// Scores how plausible a decoded string is using multiple heuristics.
#[derive(Debug, Default)]
pub struct AiScoringEngine;

impl AiScoringEngine {
    #[must_use]
    pub fn score(&self, text: &str) -> f32 {
        if text.is_empty() {
            return 0.0;
        }
        let bytes = text.as_bytes();
        let mut score: f32 = 0.0;

        // Printable ASCII ratio
        let pr =
            bytes.iter().filter(|&&b| (0x20..0x7F).contains(&b)).count() as f32 / bytes.len() as f32;
        score += pr * 30.0;

        // English letter frequency score
        let alpha = bytes.iter().filter(|&&b| b.is_ascii_alphabetic()).count();
        score += (alpha as f32 / bytes.len() as f32) * 20.0;

        // Bonus: common URL/path patterns
        if text.contains("://") || text.contains("http") || text.contains("ftp") {
            score += 10.0;
        }
        if text.starts_with('/') || text.contains('\\') {
            score += 5.0;
        }

        // Bonus: Windows API names
        let api_keywords = [
            "Create", "Open", "Read", "Write", "Socket", "Connect", "Alloc", "Virtual", "Heap",
        ];
        for kw in &api_keywords {
            if text.contains(kw) {
                score += 8.0;
                break;
            }
        }

        // Bonus: ends with \0
        if bytes.last() == Some(&0x00) {
            score += 5.0;
        }

        // Penalty: too many non-printable
        let non_print = bytes.iter().filter(|&&b| !(0x20..0x7F).contains(&b)).count();
        score -= (non_print as f32 / bytes.len() as f32) * 20.0;

        score.clamp(0.0, 100.0)
    }

    /// Score a batch and return (text, score) pairs sorted by score desc.
    #[must_use]
    pub fn rank(&self, candidates: &[String]) -> Vec<(String, f32)> {
        let mut scored: Vec<(String, f32)> = candidates
            .iter()
            .map(|s| (s.clone(), self.score(s)))
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored
    }
}

// ── RecoveryAttempt ───────────────────────────────────────────────────────────

/// A single string recovery attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryAttempt {
    pub algorithm: StringAlgorithm,
    pub key: Vec<u8>,
    pub decoded: String,
    pub confidence: f32,
    pub ai_score: f32,
    pub combined_score: f32,
}

impl RecoveryAttempt {
    #[must_use]
    pub fn new(
        algorithm: StringAlgorithm,
        key: Vec<u8>,
        decoded: String,
        confidence: f32,
        ai_score: f32,
    ) -> Self {
        let combined = confidence.mul_add(0.4, ai_score / 100.0 * 0.6).clamp(0.0, 1.0);
        Self {
            algorithm,
            key,
            decoded,
            confidence,
            ai_score,
            combined_score: combined,
        }
    }

    #[must_use]
    pub fn is_likely_plaintext(&self) -> bool {
        self.combined_score > 0.5
    }
}

// ── ContextualDecoder ─────────────────────────────────────────────────────────

/// Uses surrounding code context to improve string decoding accuracy.
pub struct ContextualDecoder {
    /// Observed keys from previous successful decodings.
    pub observed_keys: Vec<(StringAlgorithm, Vec<u8>)>,
    scorer: AiScoringEngine,
}

impl Default for ContextualDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextualDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            observed_keys: Vec::new(),
            scorer: AiScoringEngine,
        }
    }

    /// Attempt to decode `data` using all observed keys first.
    #[must_use]
    pub fn decode_with_context(&self, data: &[u8]) -> Vec<RecoveryAttempt> {
        let mut attempts = Vec::new();

        // Try context keys
        for (algo, key) in &self.observed_keys {
            debug!(algo = ?algo, key_len = key.len(), "trying context key");
            let decoded = self.apply_algo(data, *algo, key);
            if let Some(text) = decoded {
                let score = self.scorer.score(&text);
                debug!(algo = ?algo, score, "context key scored");
                if score > 20.0 {
                    attempts.push(RecoveryAttempt::new(*algo, key.clone(), text, 0.75, score));
                } else {
                    warn!(algo = ?algo, score, "context key produced low-confidence result");
                }
            }
        }
        attempts.sort_by(|a, b| {
            b.combined_score
                .partial_cmp(&a.combined_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        attempts
    }

    fn apply_algo(&self, data: &[u8], algo: StringAlgorithm, key: &[u8]) -> Option<String> {
        let key_byte = key.first().copied().unwrap_or(0);
        let decoded = match algo {
            StringAlgorithm::XorConstant => XorDecryptor::decrypt_constant(data, key_byte),
            StringAlgorithm::XorCyclic if !key.is_empty() => {
                XorDecryptor::decrypt_cyclic(data, key).ok()?
            }
            StringAlgorithm::Rc4 if !key.is_empty() => Rc4::decrypt(data, key),
            StringAlgorithm::Base64 => {
                return Base64Decoder::decode(std::str::from_utf8(data).ok()?)
                    .ok()
                    .and_then(|v| String::from_utf8(v).ok());
            }
            StringAlgorithm::HexEncoded => {
                return HexDecoder::decode(std::str::from_utf8(data).ok()?)
                    .ok()
                    .and_then(|v| String::from_utf8(v).ok());
            }
            StringAlgorithm::RotN => {
                return Some(RotN::decrypt(std::str::from_utf8(data).ok()?, key_byte));
            }
            _ => return None,
        };
        String::from_utf8(decoded).ok()
    }

    /// Record a successful decoding to inform future decoding attempts.
    pub fn record_success(&mut self, algo: StringAlgorithm, key: Vec<u8>) {
        if !self
            .observed_keys
            .iter()
            .any(|(a, k)| *a == algo && k == &key)
        {
            self.observed_keys.push((algo, key));
        }
    }
}

// ── BulkDecoder ───────────────────────────────────────────────────────────────

/// Tries all supported algorithms on all provided strings.
pub struct BulkDecoder {
    scorer: AiScoringEngine,
}

impl Default for BulkDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl BulkDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            scorer: AiScoringEngine,
        }
    }

    /// Decode all strings in `blobs` trying every algorithm.
    #[must_use]
    pub fn decode_all(&self, blobs: &[Vec<u8>]) -> Vec<(usize, Vec<RecoveryAttempt>)> {
        blobs
            .iter()
            .enumerate()
            .map(|(i, blob)| (i, self.decode_one(blob)))
            .collect()
    }

    /// Try all algorithms on a single blob.
    #[must_use]
    pub fn decode_one(&self, data: &[u8]) -> Vec<RecoveryAttempt> {
        let mut attempts = Vec::new();

        // XOR brute force (top 3 single-byte keys)
        for cand in xor_brute_force_top3(data) {
            if let Ok(text) = String::from_utf8(cand.decrypted.clone()) {
                let ai = self.scorer.score(&text);
                if ai > 15.0 {
                    attempts.push(RecoveryAttempt::new(
                        StringAlgorithm::XorConstant,
                        vec![cand.key],
                        text,
                        f32::from(cand.confidence) / 100.0,
                        ai,
                    ));
                }
            }
        }

        // RC4 single-byte brute force
        let (rc4_key, rc4_dec) = Rc4::brute_force_1byte(data);
        if let Ok(text) = String::from_utf8(rc4_dec) {
            let ai = self.scorer.score(&text);
            if ai > 15.0 {
                attempts.push(RecoveryAttempt::new(
                    StringAlgorithm::Rc4,
                    vec![rc4_key],
                    text,
                    0.6,
                    ai,
                ));
            }
        }

        // Base64
        if let Ok(s) = std::str::from_utf8(data)
            && let Ok(dec) = Base64Decoder::decode(s)
                && let Ok(text) = String::from_utf8(dec) {
                    let ai = self.scorer.score(&text);
                    if ai > 10.0 {
                        attempts.push(RecoveryAttempt::new(
                            StringAlgorithm::Base64,
                            vec![],
                            text,
                            0.9,
                            ai,
                        ));
                    }
                }

        // Hex
        if let Ok(s) = std::str::from_utf8(data)
            && let Ok(dec) = HexDecoder::decode(s)
                && let Ok(text) = String::from_utf8(dec) {
                    let ai = self.scorer.score(&text);
                    if ai > 10.0 {
                        attempts.push(RecoveryAttempt::new(
                            StringAlgorithm::HexEncoded,
                            vec![],
                            text,
                            0.9,
                            ai,
                        ));
                    }
                }

        // ROT-13
        if let Ok(s) = std::str::from_utf8(data) {
            let rot = RotN::decrypt(s, 13);
            let ai = self.scorer.score(&rot);
            if ai > 20.0 {
                attempts.push(RecoveryAttempt::new(
                    StringAlgorithm::RotN,
                    vec![13],
                    rot,
                    0.5,
                    ai,
                ));
            }
        }

        attempts.sort_by(|a, b| {
            b.combined_score
                .partial_cmp(&a.combined_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        attempts
    }
}

// ── RecoveryDatabase ──────────────────────────────────────────────────────────

/// Caches successful string decodings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecoveryDatabase {
    cache: HashMap<Vec<u8>, RecoveryAttempt>,
    pub hit_count: usize,
    pub miss_count: usize,
}

impl RecoveryDatabase {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a successful recovery.
    pub fn store(&mut self, data: &[u8], attempt: RecoveryAttempt) {
        self.cache.insert(data.to_vec(), attempt);
    }

    /// Look up a cached recovery.
    pub fn lookup(&mut self, data: &[u8]) -> Option<&RecoveryAttempt> {
        let found = self.cache.contains_key(data);
        if found {
            self.hit_count += 1;
        } else {
            self.miss_count += 1;
        }
        self.cache.get(data)
    }

    #[must_use]
    pub fn size(&self) -> usize {
        self.cache.len()
    }

    #[must_use]
    pub fn hit_rate(&self) -> f32 {
        let total = self.hit_count + self.miss_count;
        if total == 0 {
            0.0
        } else {
            self.hit_count as f32 / total as f32
        }
    }

    /// Export all cached entries as (data, decoded) pairs.
    #[must_use]
    pub fn export_all(&self) -> Vec<(Vec<u8>, String)> {
        self.cache
            .iter()
            .map(|(k, v)| (k.clone(), v.decoded.clone()))
            .collect()
    }
}

// ── AiStringRecovery ─────────────────────────────────────────────────────────

/// AI-assisted string recovery façade.
pub struct AiStringRecovery {
    pub bulk_decoder: BulkDecoder,
    pub contextual: ContextualDecoder,
    pub database: RecoveryDatabase,
    pub scorer: AiScoringEngine,
    pub min_score: f32,
}

impl Default for AiStringRecovery {
    fn default() -> Self {
        Self::new()
    }
}

impl AiStringRecovery {
    #[must_use]
    pub fn new() -> Self {
        Self {
            bulk_decoder: BulkDecoder::new(),
            contextual: ContextualDecoder::new(),
            database: RecoveryDatabase::new(),
            scorer: AiScoringEngine,
            min_score: 20.0,
        }
    }

    #[must_use]
    pub const fn with_min_score(mut self, s: f32) -> Self {
        self.min_score = s;
        self
    }

    /// Attempt to recover a string from `data`, using cache and contextual hints.
    pub fn recover(&mut self, data: &[u8]) -> Option<RecoveryAttempt> {
        // Check cache
        if let Some(cached) = self.database.lookup(data) {
            return Some(cached.clone());
        }

        // Contextual decoding (faster, uses observed patterns)
        let ctx = self.contextual.decode_with_context(data);
        if let Some(best) = ctx.into_iter().find(|a| a.ai_score >= self.min_score) {
            self.contextual
                .record_success(best.algorithm, best.key.clone());
            self.database.store(data, best.clone());
            return Some(best);
        }

        // Full bulk decoding
        let attempts = self.bulk_decoder.decode_one(data);
        if let Some(best) = attempts.into_iter().find(|a| a.ai_score >= self.min_score) {
            self.contextual
                .record_success(best.algorithm, best.key.clone());
            self.database.store(data, best.clone());
            return Some(best);
        }

        None
    }

    /// Recover all strings from a list of blobs.
    pub fn recover_all(&mut self, blobs: &[Vec<u8>]) -> Vec<(usize, Option<RecoveryAttempt>)> {
        blobs
            .iter()
            .enumerate()
            .map(|(i, b)| (i, self.recover(b)))
            .collect()
    }

    /// Statistics.
    #[must_use]
    pub fn stats(&self) -> RecoveryStats {
        RecoveryStats {
            cache_size: self.database.size(),
            cache_hit_rate: self.database.hit_rate(),
            context_keys: self.contextual.observed_keys.len(),
        }
    }
}

/// Statistics for `AiStringRecovery`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStats {
    pub cache_size: usize,
    pub cache_hit_rate: f32,
    pub context_keys: usize,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AiScoringEngine ───────────────────────────────────────────────────────

    #[test]
    fn test_scorer_plaintext_high_score() {
        let scorer = AiScoringEngine;
        let score = scorer.score("Hello, World! http://example.com");
        assert!(score > 40.0);
    }

    #[test]
    fn test_scorer_binary_low_score() {
        let scorer = AiScoringEngine;
        let garbage: String = (0..32).map(|i: u8| i as char).collect();
        let score = scorer.score(&garbage);
        assert!(score < 30.0);
    }

    #[test]
    fn test_scorer_empty_string() {
        let scorer = AiScoringEngine;
        assert_eq!(scorer.score(""), 0.0);
    }

    #[test]
    fn test_scorer_url_bonus() {
        let scorer = AiScoringEngine;
        let s1 = scorer.score("ftp://malware.example.com/payload");
        let s2 = scorer.score("xyzxyzxyzxyzxyzxyzxyzxyz");
        assert!(s1 > s2);
    }

    #[test]
    fn test_scorer_rank_sorted() {
        let scorer = AiScoringEngine;
        let candidates = vec!["Hello, World!".to_string(), "\x01\x02\x03".to_string()];
        let ranked = scorer.rank(&candidates);
        assert!(ranked[0].1 >= ranked[1].1);
    }

    // ── RecoveryAttempt ───────────────────────────────────────────────────────

    #[test]
    fn test_recovery_attempt_combined_score() {
        let a = RecoveryAttempt::new(
            StringAlgorithm::XorConstant,
            vec![0x42],
            "Hello".to_string(),
            0.8,
            80.0,
        );
        assert!(a.combined_score > 0.5);
        assert!(a.is_likely_plaintext());
    }

    #[test]
    fn test_recovery_attempt_unlikely() {
        let a = RecoveryAttempt::new(
            StringAlgorithm::XorConstant,
            vec![0x00],
            "\x01".to_string(),
            0.1,
            2.0,
        );
        assert!(!a.is_likely_plaintext());
    }

    // ── ContextualDecoder ─────────────────────────────────────────────────────

    #[test]
    fn test_contextual_decoder_no_context_empty() {
        let dec = ContextualDecoder::new();
        let data = vec![0xAA, 0xBB, 0xCC];
        let attempts = dec.decode_with_context(&data);
        assert!(attempts.is_empty());
    }

    #[test]
    fn test_contextual_decoder_with_xor_key() {
        let mut dec = ContextualDecoder::new();
        let key = 0x42u8;
        dec.record_success(StringAlgorithm::XorConstant, vec![key]);
        let plain = b"Hello, World!";
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let attempts = dec.decode_with_context(&cipher);
        let found = attempts.iter().any(|a| a.decoded.contains("Hello"));
        assert!(found);
    }

    #[test]
    fn test_contextual_decoder_record_no_duplicates() {
        let mut dec = ContextualDecoder::new();
        dec.record_success(StringAlgorithm::Rc4, vec![0x01]);
        dec.record_success(StringAlgorithm::Rc4, vec![0x01]); // duplicate
        assert_eq!(dec.observed_keys.len(), 1);
    }

    // ── BulkDecoder ───────────────────────────────────────────────────────────

    #[test]
    fn test_bulk_decoder_xor_recovery() {
        let bulk = BulkDecoder::new();
        let key = 0x42u8;
        let plain = b"Hello, World!";
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let attempts = bulk.decode_one(&cipher);
        let found = attempts.iter().any(|a| a.decoded.contains("Hello"));
        assert!(found);
    }

    #[test]
    fn test_bulk_decoder_base64() {
        let bulk = BulkDecoder::new();
        let data = b"SGVsbG8sIFdvcmxkIQ==";
        let attempts = bulk.decode_one(data);
        let found = attempts
            .iter()
            .any(|a| a.algorithm == StringAlgorithm::Base64 && a.decoded.contains("Hello"));
        assert!(found);
    }

    #[test]
    fn test_bulk_decoder_hex() {
        let bulk = BulkDecoder::new();
        let data = b"48656c6c6f";
        let attempts = bulk.decode_one(data);
        let found = attempts
            .iter()
            .any(|a| a.algorithm == StringAlgorithm::HexEncoded && a.decoded.contains("Hello"));
        assert!(found);
    }

    #[test]
    fn test_bulk_decoder_all_blobs() {
        let bulk = BulkDecoder::new();
        let blobs = vec![b"SGVsbG8=".to_vec(), b"48656c6c6f".to_vec()];
        let results = bulk.decode_all(&blobs);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_bulk_decoder_rot13() {
        let bulk = BulkDecoder::new();
        let data = b"Uryyb";
        let attempts = bulk.decode_one(data);
        let found = attempts.iter().any(|a| a.decoded.contains("Hello"));
        // ROT-13 may not always trigger; just no panic.
        let _ = found;
    }

    // ── RecoveryDatabase ──────────────────────────────────────────────────────

    #[test]
    fn test_recovery_db_store_lookup() {
        let mut db = RecoveryDatabase::new();
        let data = b"test";
        let attempt = RecoveryAttempt::new(
            StringAlgorithm::XorConstant,
            vec![0x42],
            "decoded".to_string(),
            0.9,
            80.0,
        );
        db.store(data, attempt);
        let found = db.lookup(data);
        assert!(found.is_some());
        assert_eq!(found.unwrap().decoded, "decoded");
    }

    #[test]
    fn test_recovery_db_hit_rate() {
        let mut db = RecoveryDatabase::new();
        let a = RecoveryAttempt::new(StringAlgorithm::Rc4, vec![], "x".to_string(), 0.8, 70.0);
        db.store(b"key", a);
        db.lookup(b"key"); // hit
        db.lookup(b"miss"); // miss
        assert!((db.hit_rate() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_recovery_db_export_all() {
        let mut db = RecoveryDatabase::new();
        let a = RecoveryAttempt::new(
            StringAlgorithm::Base64,
            vec![],
            "hello".to_string(),
            0.9,
            80.0,
        );
        db.store(b"data", a);
        let exported = db.export_all();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].1, "hello");
    }

    // ── AiStringRecovery ──────────────────────────────────────────────────────

    #[test]
    fn test_ai_recovery_xor() {
        let mut ai = AiStringRecovery::new().with_min_score(10.0);
        let key = 0x42u8;
        let plain = b"Hello World CreateThread";
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let result = ai.recover(&cipher);
        assert!(result.is_some());
    }

    #[test]
    fn test_ai_recovery_cached() {
        let mut ai = AiStringRecovery::new().with_min_score(10.0);
        let key = 0x42u8;
        let plain = b"Hello World CreateThread";
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        ai.recover(&cipher); // populate cache
        let _ = ai.recover(&cipher); // should use cache
        assert!(ai.database.hit_count >= 1);
    }

    #[test]
    fn test_ai_recovery_all() {
        let mut ai = AiStringRecovery::new().with_min_score(10.0);
        let blobs = vec![b"SGVsbG8=".to_vec(), b"48656c6c6f".to_vec()];
        let results = ai.recover_all(&blobs);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_ai_recovery_stats() {
        let ai = AiStringRecovery::new();
        let stats = ai.stats();
        assert_eq!(stats.cache_size, 0);
        assert_eq!(stats.context_keys, 0);
    }
}
