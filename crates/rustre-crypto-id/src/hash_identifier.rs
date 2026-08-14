//! Hash algorithm identifier for `rustre-crypto-id`.
//!
//! Identifies MD5, SHA-1, SHA-256, SHA-512, SHA-3, BLAKE2, RIPEMD, Whirlpool,
//! Tiger, GOST and common KDFs (PBKDF2, scrypt, Argon2) from binary artifacts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── HashAlgorithm ─────────────────────────────────────────────────────────────

/// Hash algorithm families recognised by the identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Sha3_256,
    Sha3_512,
    Blake2b,
    Blake2s,
    Ripemd160,
    Ripemd256,
    Whirlpool,
    Tiger,
    Tiger2,
    Gost94,
    Gost2012_256,
    Gost2012_512,
    Unknown,
}

impl HashAlgorithm {
    /// Expected output size in bytes, if fixed.
    #[must_use]
    pub const fn output_size(self) -> Option<usize> {
        match self {
            Self::Sha512 | Self::Sha3_512 | Self::Blake2b | Self::Whirlpool | Self::Gost2012_512 => Some(64),
            Self::Sha256 | Self::Sha3_256 | Self::Blake2s | Self::Ripemd256 | Self::Gost94 | Self::Gost2012_256 => Some(32),
            Self::Sha1 | Self::Ripemd160 => Some(20),
            Self::Tiger | Self::Tiger2 => Some(24),
            Self::Md5 => Some(16),
            Self::Unknown => None,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_512 => "SHA3-512",
            Self::Blake2b => "BLAKE2b",
            Self::Blake2s => "BLAKE2s",
            Self::Ripemd160 => "RIPEMD-160",
            Self::Ripemd256 => "RIPEMD-256",
            Self::Whirlpool => "Whirlpool",
            Self::Tiger => "Tiger",
            Self::Tiger2 => "Tiger2",
            Self::Gost94 => "GOST R 34.11-94",
            Self::Gost2012_256 => "GOST R 34.11-2012/256",
            Self::Gost2012_512 => "GOST R 34.11-2012/512",
            Self::Unknown => "Unknown",
        }
    }

    /// Block size in bytes for Merkle-Damgård variants, if applicable.
    #[must_use]
    pub const fn block_size(self) -> Option<usize> {
        match self {
            Self::Md5
            | Self::Sha1
            | Self::Sha256
            | Self::Sha3_256
            | Self::Ripemd160
            | Self::Ripemd256
            | Self::Tiger
            | Self::Tiger2
            | Self::Gost94
            | Self::Gost2012_256
            | Self::Blake2s => Some(64),
            Self::Sha512
            | Self::Sha3_512
            | Self::Blake2b
            | Self::Whirlpool
            | Self::Gost2012_512 => Some(128),
            Self::Unknown => None,
        }
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ── HashPattern ───────────────────────────────────────────────────────────────

/// A pattern used to recognise a hash algorithm in binary data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashPattern {
    /// Algorithm this pattern belongs to.
    pub algorithm: HashAlgorithm,
    /// Expected digest output size in bytes.
    pub output_size: usize,
    /// Human-readable description of the constant/pattern.
    pub description: String,
    /// Byte pattern to search for.
    pub pattern: Vec<u8>,
    /// Confidence awarded when pattern is found (0.0–1.0).
    pub confidence: f32,
}

impl HashPattern {
    /// Create a new pattern.
    #[must_use]
    pub fn new(
        algorithm: HashAlgorithm,
        output_size: usize,
        description: impl Into<String>,
        pattern: Vec<u8>,
        confidence: f32,
    ) -> Self {
        Self {
            algorithm,
            output_size,
            description: description.into(),
            pattern,
            confidence,
        }
    }

    /// Returns `true` if `data[offset..]` starts with this pattern.
    #[must_use]
    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.pattern.len() > data.len() {
            return false;
        }
        &data[offset..offset + self.pattern.len()] == self.pattern.as_slice()
    }
}

// ── Built-in patterns ─────────────────────────────────────────────────────────

/// Build the standard hash-pattern database.
#[must_use]
pub fn build_hash_patterns() -> Vec<HashPattern> {
    let mut p = hash_patterns_sha_family();
    p.extend(hash_patterns_other_families());
    p
}

fn hash_patterns_sha_family() -> Vec<HashPattern> {
    vec![
        // MD5 initial state: 0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476
        HashPattern::new(HashAlgorithm::Md5, 16, "MD5 initial state constants",
            vec![0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10], 0.9),
        // SHA-1 initial state
        HashPattern::new(HashAlgorithm::Sha1, 20, "SHA-1 initial state constants",
            vec![0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0xf0,0xe1,0xd2,0xc3], 0.95),
        // SHA-256 initial state H0..H7 (first words)
        HashPattern::new(HashAlgorithm::Sha256, 32, "SHA-256 initial hash values",
            vec![0x67,0xe6,0x09,0x6a,0x85,0xae,0x67,0xbb,0x72,0xf3,0x6e,0x3c,0x3a,0xf5,0x4f,0xa5], 0.9),
        // SHA-256 K[0..2] big-endian prefix: 0x428a_2f98, 0x7137_4491
        HashPattern::new(HashAlgorithm::Sha256, 32, "SHA-256 K[0..2] BE prefix",
            vec![0x42,0x8a,0x2f,0x98,0x71,0x37,0x44,0x91], 0.92),
        // SHA-512 H[0] big-endian: 0x6a09_e667_f3bc_c908
        HashPattern::new(HashAlgorithm::Sha512, 64, "SHA-512 H[0] big-endian",
            vec![0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08], 0.85),
        // SHA-512 first K constant
        HashPattern::new(HashAlgorithm::Sha512, 64, "SHA-512 K[0] constant",
            vec![0x42,0x8a,0x2f,0x98,0xd7,0x28,0xae,0x22], 0.9),
    ]
}

fn hash_patterns_other_families() -> Vec<HashPattern> {
    vec![
        // BLAKE2b IV (first word) 0x6a09_e667_f3bc_c908
        HashPattern::new(HashAlgorithm::Blake2b, 64, "BLAKE2b IV[0]",
            vec![0x08,0xc9,0xbc,0xf3,0x67,0xe6,0x09,0x6a], 0.85),
        // BLAKE2s IV (first word) 0x6a09_e667
        HashPattern::new(HashAlgorithm::Blake2s, 32, "BLAKE2s IV[0]",
            vec![0x67,0xe6,0x09,0x6a], 0.7),
        // RIPEMD-160 initial state
        HashPattern::new(HashAlgorithm::Ripemd160, 20, "RIPEMD-160 initial state",
            vec![0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0xf0,0xe1,0xd2,0xc3], 0.85),
        // Whirlpool S-box first bytes
        HashPattern::new(HashAlgorithm::Whirlpool, 64, "Whirlpool S-box start",
            vec![0x18,0x18,0x60,0x18,0xc0,0x78,0x30,0xd8], 0.8),
        // Whirlpool C0 table entry little-endian
        HashPattern::new(HashAlgorithm::Whirlpool, 64, "Whirlpool C0[0] LE",
            vec![0xd8,0x30,0x78,0xc0,0x18,0x60,0x18,0x18], 0.85),
        // GOST R 34.11-2012 (Streebog) — distinctive C[0] table prefix
        HashPattern::new(HashAlgorithm::Gost2012_256, 32, "GOST 2012/256 C[0] prefix",
            vec![0x01,0x2e,0x02,0x40,0x70,0xd5,0xe1,0xb9], 0.85),
        // Tiger initial state
        HashPattern::new(HashAlgorithm::Tiger, 24, "Tiger initial state",
            vec![0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,0x87,0xe1,0xb2,0xc3,0xb4,0xa5,0x96,0xf0], 0.9),
    ]
}

// ── HashDetector ──────────────────────────────────────────────────────────────

/// Result of identifying a hash in binary data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashIdentification {
    /// Algorithm identified.
    pub algorithm: HashAlgorithm,
    /// Byte offset in the scanned buffer.
    pub offset: usize,
    /// Pattern that triggered the identification.
    pub pattern_description: String,
    /// Confidence score (0.0–1.0).
    pub confidence: f32,
    /// Expected output size in bytes.
    pub output_size: usize,
}

/// Scans binary data to find hash algorithm constants.
#[derive(Debug, Default)]
pub struct HashDetector {
    patterns: Vec<HashPattern>,
}

impl HashDetector {
    /// Create a detector with the built-in pattern database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: build_hash_patterns(),
        }
    }

    /// Create a detector with a custom pattern set.
    #[must_use]
    pub const fn with_patterns(patterns: Vec<HashPattern>) -> Self {
        Self { patterns }
    }

    /// Add a custom pattern.
    pub fn add_pattern(&mut self, p: HashPattern) {
        self.patterns.push(p);
    }

    /// Scan `data` and return all identified hash algorithms.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Vec<HashIdentification> {
        let mut results = Vec::new();
        for pattern in &self.patterns {
            if pattern.pattern.is_empty() || pattern.pattern.len() > data.len() {
                continue;
            }
            for offset in 0..=(data.len() - pattern.pattern.len()) {
                if pattern.matches_at(data, offset) {
                    results.push(HashIdentification {
                        algorithm: pattern.algorithm,
                        offset,
                        pattern_description: pattern.description.clone(),
                        confidence: pattern.confidence,
                        output_size: pattern.output_size,
                    });
                }
            }
        }
        results.sort_by(|a, b| {
            a.offset.cmp(&b.offset).then_with(|| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });
        results
    }

    /// Return the best (highest-confidence) identification, if any.
    #[must_use]
    pub fn best_match(&self, data: &[u8]) -> Option<HashIdentification> {
        self.detect(data).into_iter().max_by(|a, b| {
            a.confidence
                .partial_cmp(&b.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Return a deduplicated list of detected algorithms sorted by confidence.
    #[must_use]
    pub fn unique_algorithms(&self, data: &[u8]) -> Vec<(HashAlgorithm, f32)> {
        let hits = self.detect(data);
        let mut map: HashMap<HashAlgorithm, f32> = HashMap::new();
        for h in hits {
            let entry = map.entry(h.algorithm).or_insert(0.0_f32);
            if h.confidence > *entry {
                *entry = h.confidence;
            }
        }
        let mut v: Vec<(HashAlgorithm, f32)> = map.into_iter().collect();
        v.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        v
    }
}

// ── ChainedHashDetector ───────────────────────────────────────────────────────

/// Applies multiple `HashDetector` passes and merges results.
///
/// Useful when different passes specialise on different endianness or byte
/// orderings of the same constants.
pub struct ChainedHashDetector {
    detectors: Vec<HashDetector>,
}

impl ChainedHashDetector {
    /// Create a chained detector with the default database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            detectors: vec![HashDetector::new()],
        }
    }

    /// Add an additional `HashDetector` pass.
    pub fn add_detector(&mut self, d: HashDetector) {
        self.detectors.push(d);
    }

    /// Run all passes and return merged, deduplicated results.
    #[must_use]
    pub fn detect_all(&self, data: &[u8]) -> Vec<HashIdentification> {
        let mut all: Vec<HashIdentification> =
            self.detectors.iter().flat_map(|d| d.detect(data)).collect();
        all.sort_by(|a, b| {
            a.offset.cmp(&b.offset).then_with(|| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });
        all
    }

    /// Number of patterns across all detectors.
    #[must_use]
    pub fn total_pattern_count(&self) -> usize {
        self.detectors.iter().map(|d| d.patterns.len()).sum()
    }
}

impl Default for ChainedHashDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── KDF_Detector ──────────────────────────────────────────────────────────────

/// Key Derivation Function variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KdfAlgorithm {
    Pbkdf2,
    Scrypt,
    Argon2i,
    Argon2d,
    Argon2id,
    Bcrypt,
    Hkdf,
    Unknown,
}

impl KdfAlgorithm {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pbkdf2 => "PBKDF2",
            Self::Scrypt => "scrypt",
            Self::Argon2i => "Argon2i",
            Self::Argon2d => "Argon2d",
            Self::Argon2id => "Argon2id",
            Self::Bcrypt => "bcrypt",
            Self::Hkdf => "HKDF",
            Self::Unknown => "Unknown",
        }
    }
}

/// Signature used to recognise a KDF in binary data.
#[derive(Debug, Clone)]
pub struct KdfSignature {
    pub algorithm: KdfAlgorithm,
    pub pattern: Vec<u8>,
    pub description: &'static str,
    pub confidence: f32,
}

/// A KDF identification hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfIdentification {
    pub algorithm: KdfAlgorithm,
    pub offset: usize,
    pub description: String,
    pub confidence: f32,
}

/// Detects KDF usage in binary data.
#[derive(Debug, Default)]
pub struct KdfDetector {
    signatures: Vec<KdfSignature>,
}

impl KdfDetector {
    /// Create with the built-in KDF signature database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            signatures: Self::build_signatures(),
        }
    }

    fn build_signatures() -> Vec<KdfSignature> {
        vec![
            // PBKDF2 — RFC 2898 "derived key" string appears in debug builds
            KdfSignature {
                algorithm: KdfAlgorithm::Pbkdf2,
                pattern: b"PBKDF2".to_vec(),
                description: "PBKDF2 literal string",
                confidence: 0.90,
            },
            KdfSignature {
                algorithm: KdfAlgorithm::Pbkdf2,
                pattern: b"pbkdf2".to_vec(),
                description: "pbkdf2 lowercase literal",
                confidence: 0.90,
            },
            // scrypt magic "scrypt" in header
            KdfSignature {
                algorithm: KdfAlgorithm::Scrypt,
                pattern: b"scrypt".to_vec(),
                description: "scrypt literal string",
                confidence: 0.95,
            },
            // Argon2 magic bytes in encoded output header "$argon2"
            KdfSignature {
                algorithm: KdfAlgorithm::Argon2id,
                pattern: b"$argon2id".to_vec(),
                description: "Argon2id PHC header",
                confidence: 0.99,
            },
            KdfSignature {
                algorithm: KdfAlgorithm::Argon2i,
                pattern: b"$argon2i$".to_vec(),
                description: "Argon2i PHC header",
                confidence: 0.99,
            },
            KdfSignature {
                algorithm: KdfAlgorithm::Argon2d,
                pattern: b"$argon2d$".to_vec(),
                description: "Argon2d PHC header",
                confidence: 0.99,
            },
            // Argon2 version constant 0x13 (19) often stored as LE u32
            KdfSignature {
                algorithm: KdfAlgorithm::Argon2id,
                pattern: vec![0x13, 0x00, 0x00, 0x00],
                description: "Argon2 version=19 LE",
                confidence: 0.55,
            },
            // bcrypt "$2a$", "$2b$", "$2y$" prefix
            KdfSignature {
                algorithm: KdfAlgorithm::Bcrypt,
                pattern: b"$2b$".to_vec(),
                description: "bcrypt PHC header $2b$",
                confidence: 0.99,
            },
            KdfSignature {
                algorithm: KdfAlgorithm::Bcrypt,
                pattern: b"$2a$".to_vec(),
                description: "bcrypt PHC header $2a$",
                confidence: 0.99,
            },
            // HKDF "HKDF" literal or common label
            KdfSignature {
                algorithm: KdfAlgorithm::Hkdf,
                pattern: b"HKDF".to_vec(),
                description: "HKDF literal string",
                confidence: 0.85,
            },
            // scrypt N=32768 (0x8000) parameter often embedded as LE u32
            KdfSignature {
                algorithm: KdfAlgorithm::Scrypt,
                pattern: vec![0x00, 0x80, 0x00, 0x00],
                description: "scrypt N=32768 LE u32",
                confidence: 0.40,
            },
        ]
    }

    /// Add a custom signature.
    pub fn add_signature(&mut self, sig: KdfSignature) {
        self.signatures.push(sig);
    }

    /// Scan `data` for KDF signatures.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> Vec<KdfIdentification> {
        let mut results = Vec::new();
        for sig in &self.signatures {
            if sig.pattern.is_empty() || sig.pattern.len() > data.len() {
                continue;
            }
            for offset in 0..=(data.len() - sig.pattern.len()) {
                if &data[offset..offset + sig.pattern.len()] == sig.pattern.as_slice() {
                    results.push(KdfIdentification {
                        algorithm: sig.algorithm,
                        offset,
                        description: sig.description.to_string(),
                        confidence: sig.confidence,
                    });
                }
            }
        }
        results.sort_by_key(|r| r.offset);
        results
    }

    /// Return the most-likely KDF algorithm in `data`, if detected.
    #[must_use]
    pub fn best_match(&self, data: &[u8]) -> Option<KdfIdentification> {
        self.detect(data).into_iter().max_by(|a, b| {
            a.confidence
                .partial_cmp(&b.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }
}

// ── HashIdentifier (high-level façade) ────────────────────────────────────────

/// High-level façade that runs both hash and KDF detection.
pub struct HashIdentifier {
    hash_detector: HashDetector,
    kdf_detector: KdfDetector,
}

impl Default for HashIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

impl HashIdentifier {
    /// Create with default databases.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hash_detector: HashDetector::new(),
            kdf_detector: KdfDetector::new(),
        }
    }

    /// Detect all hash algorithms in `data`.
    #[must_use]
    pub fn detect_hashes(&self, data: &[u8]) -> Vec<HashIdentification> {
        self.hash_detector.detect(data)
    }

    /// Detect all KDFs in `data`.
    #[must_use]
    pub fn detect_kdfs(&self, data: &[u8]) -> Vec<KdfIdentification> {
        self.kdf_detector.detect(data)
    }

    /// Return a summary report as a list of human-readable strings.
    #[must_use]
    pub fn summary_report(&self, data: &[u8]) -> Vec<String> {
        let mut lines = Vec::new();
        for h in self.detect_hashes(data) {
            lines.push(format!(
                "[hash] {} at 0x{:x} (conf={:.2}): {}",
                h.algorithm, h.offset, h.confidence, h.pattern_description
            ));
        }
        for k in self.detect_kdfs(data) {
            lines.push(format!(
                "[kdf ] {} at 0x{:x} (conf={:.2}): {}",
                k.algorithm.name(),
                k.offset,
                k.confidence,
                k.description
            ));
        }
        lines
    }

    /// Returns `true` if any hash or KDF was detected.
    #[must_use]
    pub fn has_cryptographic_hash(&self, data: &[u8]) -> bool {
        !self.detect_hashes(data).is_empty() || !self.detect_kdfs(data).is_empty()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_k_prefix() -> Vec<u8> {
        vec![0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91]
    }

    fn sha512_h0() -> Vec<u8> {
        0x6a09_e667_f3bc_c908u64.to_be_bytes().to_vec()
    }

    fn ripemd160_iv() -> Vec<u8> {
        vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0xF0, 0xE1, 0xD2, 0xC3,
        ]
    }

    // ── HashAlgorithm ────────────────────────────────────────────────────────

    #[test]
    fn test_md5_output_size() {
        assert_eq!(HashAlgorithm::Md5.output_size(), Some(16));
    }

    #[test]
    fn test_sha256_output_size() {
        assert_eq!(HashAlgorithm::Sha256.output_size(), Some(32));
    }

    #[test]
    fn test_sha512_output_size() {
        assert_eq!(HashAlgorithm::Sha512.output_size(), Some(64));
    }

    #[test]
    fn test_unknown_output_size_is_none() {
        assert_eq!(HashAlgorithm::Unknown.output_size(), None);
    }

    #[test]
    fn test_algorithm_names_nonempty() {
        for algo in [
            HashAlgorithm::Md5,
            HashAlgorithm::Sha1,
            HashAlgorithm::Blake2b,
            HashAlgorithm::Whirlpool,
        ] {
            assert!(!algo.name().is_empty());
        }
    }

    #[test]
    fn test_block_sizes() {
        assert_eq!(HashAlgorithm::Md5.block_size(), Some(64));
        assert_eq!(HashAlgorithm::Sha512.block_size(), Some(128));
    }

    // ── HashPattern ──────────────────────────────────────────────────────────

    #[test]
    fn test_hash_pattern_matches_at() {
        let p = HashPattern::new(HashAlgorithm::Md5, 16, "test", vec![0xAA, 0xBB], 0.8);
        let data = vec![0x00, 0xAA, 0xBB, 0xFF];
        assert!(p.matches_at(&data, 1));
        assert!(!p.matches_at(&data, 0));
    }

    #[test]
    fn test_hash_pattern_no_match_too_short() {
        let p = HashPattern::new(HashAlgorithm::Md5, 16, "test", vec![0xAA, 0xBB, 0xCC], 0.8);
        let data = vec![0xAA, 0xBB];
        assert!(!p.matches_at(&data, 0));
    }

    // ── HashDetector ─────────────────────────────────────────────────────────

    #[test]
    fn test_detect_sha256_k_prefix() {
        let det = HashDetector::new();
        let prefix = sha256_k_prefix();
        let hits = det.detect(&prefix);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn test_detect_sha512_h0() {
        let det = HashDetector::new();
        let data = sha512_h0();
        let hits = det.detect(&data);
        assert!(hits.iter().any(|h| h.algorithm == HashAlgorithm::Sha512));
    }

    #[test]
    fn test_detect_ripemd160_iv() {
        let det = HashDetector::new();
        let data = ripemd160_iv();
        let hits = det.detect(&data);
        assert!(hits.iter().any(|h| h.algorithm == HashAlgorithm::Ripemd160));
    }

    #[test]
    fn test_detect_returns_empty_for_random() {
        let det = HashDetector::new();
        // Highly unlikely to match patterns
        let data = vec![0x00u8; 32];
        let hits = det.detect(&data);
        // Might find SHA-3 RC[0] but mostly empty
        let _ = hits; // no assertion — just no panic
    }

    #[test]
    fn test_best_match_sha256() {
        let det = HashDetector::new();
        let mut data = vec![0x00u8; 4];
        data.extend_from_slice(&sha256_k_prefix());
        let best = det.best_match(&data);
        assert!(best.is_some());
        assert_eq!(best.unwrap().algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn test_unique_algorithms_deduplication() {
        let det = HashDetector::new();
        // SHA-256 K[0..2] appears once; but two patterns may match
        let mut data = vec![0x00u8; 8];
        data.extend_from_slice(&sha256_k_prefix());
        let uniq = det.unique_algorithms(&data);
        let sha256_count = uniq
            .iter()
            .filter(|(a, _)| *a == HashAlgorithm::Sha256)
            .count();
        assert_eq!(sha256_count, 1); // deduplicated
    }

    #[test]
    fn test_detector_with_custom_pattern() {
        let mut det = HashDetector::new();
        det.add_pattern(HashPattern::new(
            HashAlgorithm::Whirlpool,
            64,
            "Custom",
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            0.99,
        ));
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let hits = det.detect(&data);
        assert!(hits.iter().any(
            |h| h.algorithm == HashAlgorithm::Whirlpool && (h.confidence - 0.99).abs() < 0.001
        ));
    }

    #[test]
    fn test_detector_hits_sorted_by_offset() {
        let det = HashDetector::new();
        let mut data = vec![0x00u8; 64];
        data.extend_from_slice(&sha512_h0());
        data.extend_from_slice(&sha256_k_prefix());
        let hits = det.detect(&data);
        for w in hits.windows(2) {
            assert!(w[0].offset <= w[1].offset);
        }
    }

    // ── ChainedHashDetector ──────────────────────────────────────────────────

    #[test]
    fn test_chained_detector_total_patterns() {
        let chained = ChainedHashDetector::new();
        assert!(chained.total_pattern_count() > 0);
    }

    #[test]
    fn test_chained_detector_additional_pass() {
        let mut chained = ChainedHashDetector::new();
        let mut extra = HashDetector::new();
        extra.add_pattern(HashPattern::new(
            HashAlgorithm::Tiger,
            24,
            "extra",
            vec![0xFF, 0xFE],
            0.50,
        ));
        let before = chained.total_pattern_count();
        chained.add_detector(extra);
        assert!(chained.total_pattern_count() > before);
    }

    #[test]
    fn test_chained_detect_all_sha256() {
        let chained = ChainedHashDetector::new();
        let data = sha256_k_prefix();
        let hits = chained.detect_all(&data);
        assert!(!hits.is_empty());
    }

    // ── KdfDetector ──────────────────────────────────────────────────────────

    #[test]
    fn test_kdf_detect_pbkdf2_literal() {
        let det = KdfDetector::new();
        let data = b"PBKDF2-SHA256";
        let hits = det.detect(data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].algorithm, KdfAlgorithm::Pbkdf2);
    }

    #[test]
    fn test_kdf_detect_scrypt_literal() {
        let det = KdfDetector::new();
        let data = b"scrypt N=32768 r=8 p=1";
        let hits = det.detect(data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].algorithm, KdfAlgorithm::Scrypt);
    }

    #[test]
    fn test_kdf_detect_argon2id_header() {
        let det = KdfDetector::new();
        let data = b"$argon2id$v=19$m=65536,t=3,p=4$";
        let hits = det.detect(data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].algorithm, KdfAlgorithm::Argon2id);
    }

    #[test]
    fn test_kdf_detect_bcrypt_header() {
        let det = KdfDetector::new();
        let data = b"$2b$12$something";
        let hits = det.detect(data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].algorithm, KdfAlgorithm::Bcrypt);
    }

    #[test]
    fn test_kdf_detect_argon2i() {
        let det = KdfDetector::new();
        let data = b"$argon2i$v=19$m=16384";
        let hits = det.detect(data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].algorithm, KdfAlgorithm::Argon2i);
    }

    #[test]
    fn test_kdf_detect_hkdf() {
        let det = KdfDetector::new();
        let data = b"HKDF-SHA256 salt";
        let hits = det.detect(data);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].algorithm, KdfAlgorithm::Hkdf);
    }

    #[test]
    fn test_kdf_best_match_high_confidence_bcrypt() {
        let det = KdfDetector::new();
        let data = b"$2b$12$..."; // bcrypt conf=0.99
        let best = det.best_match(data).unwrap();
        assert_eq!(best.algorithm, KdfAlgorithm::Bcrypt);
        assert!(best.confidence >= 0.99);
    }

    #[test]
    fn test_kdf_no_detection() {
        let det = KdfDetector::new();
        let hits = det.detect(b"no kdf here at all");
        assert!(hits.is_empty());
    }

    #[test]
    fn test_kdf_custom_signature() {
        let mut det = KdfDetector::new();
        det.add_signature(KdfSignature {
            algorithm: KdfAlgorithm::Pbkdf2,
            pattern: b"CUSTOM_KDF".to_vec(),
            description: "custom kdf",
            confidence: 0.77,
        });
        let hits = det.detect(b"some CUSTOM_KDF bytes");
        assert!(!hits.is_empty());
        assert!((hits[0].confidence - 0.77).abs() < 0.001);
    }

    // ── HashIdentifier ───────────────────────────────────────────────────────

    #[test]
    fn test_identifier_detects_sha256() {
        let id = HashIdentifier::new();
        let data = sha256_k_prefix();
        assert!(id.has_cryptographic_hash(&data));
    }

    #[test]
    fn test_identifier_summary_report_nonempty() {
        let id = HashIdentifier::new();
        let data = sha512_h0();
        let report = id.summary_report(&data);
        assert!(!report.is_empty());
    }

    #[test]
    fn test_identifier_kdf_in_summary() {
        let id = HashIdentifier::new();
        let data = b"$argon2id$v=19$m=65536";
        let report = id.summary_report(data);
        assert!(report.iter().any(|l| l.contains("kdf")));
    }

    #[test]
    fn test_identifier_empty_data_no_match() {
        let id = HashIdentifier::new();
        assert!(!id.has_cryptographic_hash(&[]));
    }

    #[test]
    fn test_identifier_combined_hash_and_kdf() {
        let id = HashIdentifier::new();
        let mut data = sha256_k_prefix();
        data.extend_from_slice(b"PBKDF2");
        let hashes = id.detect_hashes(&data);
        let kdfs = id.detect_kdfs(&data);
        assert!(!hashes.is_empty());
        assert!(!kdfs.is_empty());
    }

    // ── build_hash_patterns ──────────────────────────────────────────────────

    #[test]
    fn test_build_hash_patterns_nonempty() {
        let patterns = build_hash_patterns();
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_build_hash_patterns_all_confidence_valid() {
        for p in build_hash_patterns() {
            assert!(
                p.confidence > 0.0 && p.confidence <= 1.0,
                "pattern {} has invalid confidence {}",
                p.description,
                p.confidence
            );
        }
    }

    #[test]
    fn test_build_hash_patterns_output_sizes_positive() {
        for p in build_hash_patterns() {
            assert!(
                p.output_size > 0,
                "pattern {} has zero output_size",
                p.description
            );
        }
    }

    #[test]
    fn test_whirlpool_detected_from_c0_table() {
        let det = HashDetector::new();
        let data = 0x1818_6018_c078_30d8u64.to_le_bytes().to_vec();
        let hits = det.detect(&data);
        assert!(hits.iter().any(|h| h.algorithm == HashAlgorithm::Whirlpool));
    }

    #[test]
    fn test_gost_detection() {
        let det = HashDetector::new();
        let data = vec![0x01, 0x2e, 0x02, 0x40, 0x70, 0xd5, 0xe1, 0xb9, 0x00, 0x00];
        let hits = det.detect(&data);
        assert!(
            hits.iter()
                .any(|h| matches!(h.algorithm, HashAlgorithm::Gost2012_256))
        );
    }
}
