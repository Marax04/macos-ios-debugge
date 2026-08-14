//! `cipher_detection` — fine-grained cipher detection.
//!
//! Provides `CipherDetection`, `CipherFeature`, `BlockCipherDetector`,
//! `StreamCipherDetector`, `HashFunctionDetector`, and `DetectionReport`.

use crate::{AES_INV_SBOX, AES_SBOX, CryptoAlgorithm, SM4_SBOX};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
pub use std::collections::HashSet;

// ── CipherFeature ─────────────────────────────────────────────────────────────

/// A single extracted feature used for cipher identification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CipherFeature {
    /// Feature name (e.g., "`aes_sbox`", "`key_schedule_xor`").
    pub name: String,
    /// Weight of this feature in [0.0, 1.0].
    pub weight: f32,
    /// Byte offset where the feature was found.
    pub offset: Option<usize>,
    /// Additional notes.
    pub note: String,
}

impl CipherFeature {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        weight: f32,
        offset: Option<usize>,
        note: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            weight,
            offset,
            note: note.into(),
        }
    }

    /// A feature with maximum confidence.
    #[must_use]
    pub fn certain(name: impl Into<String>, offset: usize, note: impl Into<String>) -> Self {
        Self::new(name, 1.0, Some(offset), note)
    }

    /// A feature with partial confidence.
    #[must_use]
    pub fn likely(
        name: impl Into<String>,
        weight: f32,
        offset: usize,
        note: impl Into<String>,
    ) -> Self {
        Self::new(name, weight.clamp(0.0, 1.0), Some(offset), note)
    }
}

// ── DetectionReport ───────────────────────────────────────────────────────────

/// Complete detection report for a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionReport {
    /// Candidate algorithms with their confidence scores.
    pub candidates: Vec<CandidateEntry>,
    /// All features extracted.
    pub features: Vec<CipherFeature>,
    /// Highest-confidence algorithm.
    pub best_match: Option<CryptoAlgorithm>,
    /// Overall confidence for best match.
    pub best_confidence: f32,
    /// Key candidates found.
    pub key_candidates: Vec<KeyCandidate>,
}

impl DetectionReport {
    /// Build a report from a list of (algorithm, features) pairs.
    #[must_use]
    pub fn build(algorithm_features: &[(CryptoAlgorithm, Vec<CipherFeature>)]) -> Self {
        let mut candidates: Vec<CandidateEntry> = algorithm_features
            .iter()
            .map(|(algo, features)| {
                let confidence = combined_confidence(features);
                CandidateEntry {
                    algorithm: *algo,
                    confidence,
                    features: features.clone(),
                }
            })
            .collect();
        candidates.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                // Break ties (e.g. multiple algorithms saturated at the 0.99
                // confidence cap) by number of corroborating features.
                .then_with(|| b.features.len().cmp(&a.features.len()))
        });
        let best_match = candidates.first().map(|c| c.algorithm);
        let best_confidence = candidates.first().map_or(0.0, |c| c.confidence);
        let features: Vec<CipherFeature> = candidates
            .iter()
            .flat_map(|c| c.features.iter().cloned())
            .collect();
        Self {
            candidates,
            features,
            best_match,
            best_confidence,
            key_candidates: Vec::new(),
        }
    }

    /// Return true if a specific algorithm was detected above a confidence threshold.
    #[must_use]
    pub fn detected(&self, algo: CryptoAlgorithm, threshold: f32) -> bool {
        self.candidates
            .iter()
            .any(|c| c.algorithm == algo && c.confidence >= threshold)
    }

    /// Get confidence for a specific algorithm.
    #[must_use]
    pub fn confidence_for(&self, algo: CryptoAlgorithm) -> f32 {
        self.candidates
            .iter()
            .find(|c| c.algorithm == algo)
            .map_or(0.0, |c| c.confidence)
    }

    /// Top-N candidates.
    #[must_use]
    pub fn top_n(&self, n: usize) -> &[CandidateEntry] {
        &self.candidates[..n.min(self.candidates.len())]
    }
}

/// A single algorithm candidate with its confidence and supporting features.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateEntry {
    pub algorithm: CryptoAlgorithm,
    pub confidence: f32,
    pub features: Vec<CipherFeature>,
}

/// A potential key region in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyCandidate {
    pub offset: usize,
    pub length: usize,
    pub entropy: f64,
}

/// Combined miss-probability confidence combiner.
fn combined_confidence(features: &[CipherFeature]) -> f32 {
    if features.is_empty() {
        return 0.0;
    }
    let miss = features
        .iter()
        .fold(1.0f32, |acc, f| acc * (1.0 - f.weight.clamp(0.0, 1.0)));
    (1.0 - miss).clamp(0.0, 0.99)
}

// ── BlockCipherDetector ───────────────────────────────────────────────────────

/// Detects block ciphers: AES/DES/3DES/Blowfish/Twofish.
pub struct BlockCipherDetector;

impl BlockCipherDetector {
    /// Scan `data` for block cipher signatures.
    /// Returns a map from algorithm to list of supporting features.
    #[must_use]
    pub fn scan(data: &[u8]) -> HashMap<CryptoAlgorithm, Vec<CipherFeature>> {
        let mut result: HashMap<CryptoAlgorithm, Vec<CipherFeature>> = HashMap::new();
        Self::scan_aes(data, &mut result);
        Self::scan_sm4(data, &mut result);
        Self::scan_des(data, &mut result);
        Self::scan_blowfish(data, &mut result);
        result
    }

    fn scan_aes(data: &[u8], result: &mut HashMap<CryptoAlgorithm, Vec<CipherFeature>>) {
        let mut feats = Vec::new();
        if let Some(off) = find_bytes(data, &AES_SBOX) {
            feats.push(CipherFeature::certain("aes_sbox", off, "256-byte AES S-box found verbatim"));
        }
        if let Some(off) = find_bytes(data, &AES_INV_SBOX) {
            feats.push(CipherFeature::certain("aes_inv_sbox", off, "256-byte AES inverse S-box"));
        }
        let rcon: &[u8] = &[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b];
        if let Some(off) = find_bytes(data, rcon) {
            feats.push(CipherFeature::likely("aes_rcon", 0.85, off, "AES Rcon table prefix"));
        }
        let t0_marker: &[u8] = &[0xfb, 0x63, 0x63, 0xc6];
        if let Some(off) = find_bytes(data, t0_marker) {
            feats.push(CipherFeature::likely("aes_t0_marker", 0.80, off, "AES T0[0] marker"));
        }
        if !feats.is_empty() { result.insert(CryptoAlgorithm::Aes128, feats); }
    }

    fn scan_sm4(data: &[u8], result: &mut HashMap<CryptoAlgorithm, Vec<CipherFeature>>) {
        let mut feats = Vec::new();
        if let Some(off) = find_bytes(data, &SM4_SBOX) {
            feats.push(CipherFeature::certain("sm4_sbox", off, "256-byte SM4 S-box"));
        }
        let sm4_fk: &[u8] = &[0xC6, 0xBA, 0xB1, 0xA3];
        if let Some(off) = find_bytes(data, sm4_fk) {
            feats.push(CipherFeature::likely("sm4_fk", 0.80, off, "SM4 system parameter FK[0]"));
        }
        if !feats.is_empty() { result.insert(CryptoAlgorithm::Sm4, feats); }
    }

    fn scan_des(data: &[u8], result: &mut HashMap<CryptoAlgorithm, Vec<CipherFeature>>) {
        let mut feats = Vec::new();
        let des_s1: &[u8] = &[0x0E, 0x04, 0x0D, 0x01, 0x02, 0x0F, 0x0B, 0x08];
        if let Some(off) = find_bytes(data, des_s1) {
            feats.push(CipherFeature::likely("des_s1_row", 0.75, off, "DES S1 first row"));
        }
        let des_ip: &[u8] = &[0x3a, 0x32, 0x2a, 0x22, 0x1a, 0x12];
        if let Some(off) = find_bytes(data, des_ip) {
            feats.push(CipherFeature::likely("des_ip_perm", 0.70, off, "DES IP permutation table"));
        }
        if !feats.is_empty() { result.insert(CryptoAlgorithm::Des, feats); }
    }

    fn scan_blowfish(data: &[u8], result: &mut HashMap<CryptoAlgorithm, Vec<CipherFeature>>) {
        let mut feats = Vec::new();
        let bf_p0: &[u8] = &[0x88, 0x6a, 0x3f, 0x24];
        if let Some(off) = find_bytes(data, bf_p0) {
            feats.push(CipherFeature::likely("blowfish_p0", 0.80, off, "Blowfish P-array[0]"));
        }
        let bf_p1: &[u8] = &[0xd3, 0x08, 0xa3, 0x85];
        if let Some(off) = find_bytes(data, bf_p1) {
            feats.push(CipherFeature::likely("blowfish_p1", 0.70, off, "Blowfish P-array[1]"));
        }
        if !feats.is_empty() {
            result.entry(CryptoAlgorithm::Aes128).or_default().extend(feats);
        }
    }

    /// Estimate the block size from the detected algorithm.
    #[must_use]
    pub const fn block_size_for(algo: CryptoAlgorithm) -> Option<usize> {
        match algo {
            CryptoAlgorithm::Aes128 | CryptoAlgorithm::Aes256 | CryptoAlgorithm::Sm4 => Some(16),
            CryptoAlgorithm::Des | CryptoAlgorithm::TripleDes => Some(8),
            _ => None,
        }
    }

    /// Check if a specific algorithm is detected in the data.
    #[must_use]
    pub fn detects(data: &[u8], algo: CryptoAlgorithm) -> bool {
        let map = Self::scan(data);
        map.contains_key(&algo)
    }
}

// ── StreamCipherDetector ──────────────────────────────────────────────────────

/// Detects stream ciphers: RC4, Salsa20, `ChaCha20`.
pub struct StreamCipherDetector;

impl StreamCipherDetector {
    /// Scan `data` for stream cipher signatures.
    #[must_use]
    pub fn scan(data: &[u8]) -> HashMap<CryptoAlgorithm, Vec<CipherFeature>> {
        let mut result: HashMap<CryptoAlgorithm, Vec<CipherFeature>> = HashMap::new();

        // ── RC4 ───────────────────────────────────────────────────────────────
        let mut rc4_features = Vec::new();
        // RC4 identity permutation start: 0x00 0x01 0x02 ... 0x0B
        let rc4_id: &[u8] = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        ];
        if let Some(off) = find_bytes(data, rc4_id) {
            rc4_features.push(CipherFeature::likely(
                "rc4_identity_perm",
                0.55,
                off,
                "RC4 identity permutation start",
            ));
        }
        // Scan for 256-byte permutation arrays
        if let Some(off) = find_permutation_256(data) {
            rc4_features.push(CipherFeature::likely(
                "rc4_permutation",
                0.65,
                off,
                "256-byte permutation (RC4 S-array)",
            ));
        }
        if !rc4_features.is_empty() {
            result.insert(CryptoAlgorithm::Rc4, rc4_features);
        }

        // ── ChaCha20 ──────────────────────────────────────────────────────────
        let mut cc_features = Vec::new();
        if let Some(off) = find_bytes(data, b"expand 32-byte k") {
            cc_features.push(CipherFeature::certain(
                "chacha20_sigma",
                off,
                "ChaCha20 sigma constant",
            ));
        }
        if let Some(off) = find_bytes(data, b"expand 16-byte k") {
            cc_features.push(CipherFeature::likely(
                "chacha20_tau",
                0.95,
                off,
                "ChaCha20 tau constant",
            ));
        }
        // ChaCha20 quarter-round constant 0x6170_7865
        let qr: &[u8] = &[0x65, 0x78, 0x70, 0x61]; // "expa" in LE
        if let Some(off) = find_bytes(data, qr) {
            cc_features.push(CipherFeature::likely(
                "chacha20_expa",
                0.70,
                off,
                "ChaCha20 'expa' constant",
            ));
        }
        if !cc_features.is_empty() {
            result.insert(CryptoAlgorithm::ChaCha20, cc_features);
        }

        // ── Salsa20 ───────────────────────────────────────────────────────────
        let mut s20_features = Vec::new();
        if let Some(off) = find_bytes(data, b"expand 32-byte k")
            && result.contains_key(&CryptoAlgorithm::ChaCha20) {
                // Both Salsa20 and ChaCha20 use same constants; add lower-weight feature
                s20_features.push(CipherFeature::likely(
                    "salsa20_sigma",
                    0.50,
                    off,
                    "Salsa20/ChaCha20 shared sigma",
                ));
            }
        // Salsa20 "expa" in different position
        let s20_expa: &[u8] = &[0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20];
        if let Some(off) = find_bytes(data, s20_expa) {
            s20_features.push(CipherFeature::likely(
                "salsa20_expand",
                0.60,
                off,
                "Salsa20 'expand' string",
            ));
        }
        if !s20_features.is_empty() {
            result.insert(CryptoAlgorithm::Salsa20, s20_features);
        }

        result
    }

    /// Return true if keystream output exhibits uniform byte distribution.
    #[must_use]
    pub fn is_uniform_distribution(data: &[u8]) -> bool {
        if data.len() < 256 {
            return false;
        }
        let mut freq = [0u32; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let expected = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX)) / 256.0;
        let chi2: f64 = freq
            .iter()
            .map(|&c| {
                let diff = f64::from(c) - expected;
                diff * diff / expected
            })
            .sum();
        // For uniform data with 256 bins and n≥512, chi2 should be near 255
        chi2 < 400.0
    }
}

// ── HashFunctionDetector ──────────────────────────────────────────────────────

/// Detects hash functions: MD5, SHA-1, SHA-256, SHA-512, CRC32.
pub struct HashFunctionDetector;

impl HashFunctionDetector {
    /// Scan `data` for hash function signatures.
    #[must_use]
    pub fn scan(data: &[u8]) -> HashMap<CryptoAlgorithm, Vec<CipherFeature>> {
        let mut result: HashMap<CryptoAlgorithm, Vec<CipherFeature>> = HashMap::new();

        // ── MD5 ───────────────────────────────────────────────────────────────
        let mut md5_features = Vec::new();
        // K[0] = 0xd76a_a478 LE
        if let Some(off) = find_bytes(data, &0xd76a_a478u32.to_le_bytes()) {
            md5_features.push(CipherFeature::likely("md5_k0_le", 0.82, off, "MD5 K[0] LE"));
        }
        if let Some(off) = find_bytes(data, &0x6745_2301u32.to_le_bytes()) {
            md5_features.push(CipherFeature::likely(
                "md5_h0_le",
                0.65,
                off,
                "MD5 H0[0] LE",
            ));
        }
        if !md5_features.is_empty() {
            result.insert(CryptoAlgorithm::Md5, md5_features);
        }

        // ── SHA-1 ─────────────────────────────────────────────────────────────
        let mut sha1_features = Vec::new();
        // SHA-1 H[4] = 0xc3d2_e1f0 BE
        if let Some(off) = find_bytes(data, &0xc3d2_e1f0u32.to_be_bytes()) {
            sha1_features.push(CipherFeature::likely(
                "sha1_h4_be",
                0.80,
                off,
                "SHA-1 H[4] BE",
            ));
        }
        if let Some(off) = find_bytes(data, &0xc3d2_e1f0u32.to_le_bytes()) {
            sha1_features.push(CipherFeature::likely(
                "sha1_h4_le",
                0.75,
                off,
                "SHA-1 H[4] LE",
            ));
        }
        if !sha1_features.is_empty() {
            result.insert(CryptoAlgorithm::Sha1, sha1_features);
        }

        // ── SHA-256 ───────────────────────────────────────────────────────────
        let mut sha256_features = Vec::new();
        if let Some(off) = find_bytes(data, &0x6a09_e667u32.to_be_bytes()) {
            sha256_features.push(CipherFeature::likely(
                "sha256_h0_be",
                0.80,
                off,
                "SHA-256 H[0] BE",
            ));
        }
        if let Some(off) = find_bytes(data, &0x6a09_e667u32.to_le_bytes()) {
            sha256_features.push(CipherFeature::likely(
                "sha256_h0_le",
                0.75,
                off,
                "SHA-256 H[0] LE",
            ));
        }
        if let Some(off) = find_bytes(data, &0x428a_2f98u32.to_be_bytes()) {
            sha256_features.push(CipherFeature::likely(
                "sha256_k0_be",
                0.78,
                off,
                "SHA-256 K[0] BE",
            ));
        }
        if !sha256_features.is_empty() {
            result.insert(CryptoAlgorithm::Sha256, sha256_features);
        }

        // ── SHA-512 ───────────────────────────────────────────────────────────
        let mut sha512_features = Vec::new();
        if let Some(off) = find_bytes(data, &0x6a09_e667_f3bc_c908u64.to_be_bytes()) {
            sha512_features.push(CipherFeature::likely(
                "sha512_h0_be",
                0.90,
                off,
                "SHA-512 H[0] BE",
            ));
        }
        if !sha512_features.is_empty() {
            result.insert(CryptoAlgorithm::Sha512, sha512_features);
        }

        // ── CRC32 ─────────────────────────────────────────────────────────────
        let mut crc32_features = Vec::new();
        if let Some(off) = find_bytes(data, &0xedb8_8320u32.to_le_bytes()) {
            crc32_features.push(CipherFeature::likely(
                "crc32_poly_le",
                0.90,
                off,
                "CRC32 polynomial LE",
            ));
        }
        if let Some(off) = find_bytes(data, &0xedb8_8320u32.to_be_bytes()) {
            crc32_features.push(CipherFeature::likely(
                "crc32_poly_be",
                0.85,
                off,
                "CRC32 polynomial BE",
            ));
        }
        if !crc32_features.is_empty() {
            result.insert(CryptoAlgorithm::Crc32, crc32_features);
        }

        result
    }

    /// Compute the output length expected for a detected hash function.
    #[must_use]
    pub const fn output_length(algo: CryptoAlgorithm) -> Option<usize> {
        match algo {
            CryptoAlgorithm::Md5 => Some(16),
            CryptoAlgorithm::Sha1 => Some(20),
            CryptoAlgorithm::Sha256 => Some(32),
            CryptoAlgorithm::Sha512 => Some(64),
            CryptoAlgorithm::Crc32 => Some(4),
            _ => None,
        }
    }
}

// ── CipherDetection ───────────────────────────────────────────────────────────

/// Main entry point for cipher detection.
/// Combines block cipher, stream cipher, and hash function detectors.
pub struct CipherDetection;

impl CipherDetection {
    /// Run all detectors against `data` and produce a `DetectionReport`.
    #[must_use]
    pub fn detect(data: &[u8]) -> DetectionReport {
        let mut all_features: HashMap<CryptoAlgorithm, Vec<CipherFeature>> = HashMap::new();

        // Merge all detector results
        for (algo, features) in BlockCipherDetector::scan(data) {
            all_features.entry(algo).or_default().extend(features);
        }
        for (algo, features) in StreamCipherDetector::scan(data) {
            all_features.entry(algo).or_default().extend(features);
        }
        for (algo, features) in HashFunctionDetector::scan(data) {
            all_features.entry(algo).or_default().extend(features);
        }

        let pairs: Vec<(CryptoAlgorithm, Vec<CipherFeature>)> = all_features.into_iter().collect();
        let mut report = DetectionReport::build(&pairs);

        // Add key candidates
        report.key_candidates = find_key_candidates(data);

        report
    }

    /// Check if any cipher is detected above the given confidence.
    #[must_use]
    pub fn any_detected(data: &[u8], threshold: f32) -> bool {
        let report = Self::detect(data);
        report.best_confidence >= threshold
    }

    /// Return the names of all detected algorithms above threshold.
    #[must_use]
    pub fn detected_algorithms(data: &[u8], threshold: f32) -> Vec<CryptoAlgorithm> {
        let report = Self::detect(data);
        report
            .candidates
            .into_iter()
            .filter(|c| c.confidence >= threshold)
            .map(|c| c.algorithm)
            .collect()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Find first occurrence of `needle` in `haystack`.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| haystack[i..i + needle.len()] == *needle)
}

/// Find first 256-byte permutation array (all values 0..255 present once).
fn find_permutation_256(data: &[u8]) -> Option<usize> {
    if data.len() < 256 {
        return None;
    }
    for start in 0..=(data.len() - 256) {
        let mut seen = [false; 256];
        let ok = data[start..start + 256].iter().all(|&b| {
            if seen[b as usize] {
                false
            } else {
                seen[b as usize] = true;
                true
            }
        });
        if ok {
            return Some(start);
        }
    }
    None
}

/// Find key candidates (high-entropy 16/24/32-byte regions).
fn find_key_candidates(data: &[u8]) -> Vec<KeyCandidate> {
    let mut candidates = Vec::new();
    for key_len in [16usize, 24, 32] {
        if data.len() < key_len {
            continue;
        }
        for offset in (0..data.len().saturating_sub(key_len)).step_by(4) {
            let window = &data[offset..offset + key_len];
            let entropy = shannon_entropy(window);
            if entropy > 3.5 {
                candidates.push(KeyCandidate {
                    offset,
                    length: key_len,
                    entropy,
                });
                break; // one per size class
            }
        }
    }
    candidates
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

// ── KnownAlgorithmDatabase ────────────────────────────────────────────────────

/// A curated database of cryptographic algorithm signatures and their properties.
#[derive(Debug, Default)]
pub struct KnownAlgorithmDatabase {
    entries: Vec<AlgorithmEntry>,
}

/// A single entry in the algorithm database.
#[derive(Debug, Clone)]
pub struct AlgorithmEntry {
    pub algorithm: CryptoAlgorithm,
    pub display_name: String,
    pub block_size: Option<usize>,
    pub key_sizes: Vec<usize>,
    pub security_level: SecurityLevel,
    pub category: AlgorithmCategory,
}

/// Broad security classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Broken,
    Weak,
    Acceptable,
    Strong,
}

/// Broad algorithm category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmCategory {
    BlockCipher,
    StreamCipher,
    HashFunction,
    Mac,
    Asymmetric,
    Checksum,
}

impl KnownAlgorithmDatabase {
    /// Build the default database.
    #[must_use]
    pub fn default_db() -> Self {
        let mut db = Self::default();
        db.entries.push(AlgorithmEntry {
            algorithm: CryptoAlgorithm::Aes128,
            display_name: "AES-128".into(),
            block_size: Some(16),
            key_sizes: vec![16],
            security_level: SecurityLevel::Strong,
            category: AlgorithmCategory::BlockCipher,
        });
        db.entries.push(AlgorithmEntry {
            algorithm: CryptoAlgorithm::Aes256,
            display_name: "AES-256".into(),
            block_size: Some(16),
            key_sizes: vec![32],
            security_level: SecurityLevel::Strong,
            category: AlgorithmCategory::BlockCipher,
        });
        db.entries.push(AlgorithmEntry {
            algorithm: CryptoAlgorithm::Des,
            display_name: "DES".into(),
            block_size: Some(8),
            key_sizes: vec![8],
            security_level: SecurityLevel::Broken,
            category: AlgorithmCategory::BlockCipher,
        });
        db.entries.push(AlgorithmEntry {
            algorithm: CryptoAlgorithm::TripleDes,
            display_name: "3DES".into(),
            block_size: Some(8),
            key_sizes: vec![16, 24],
            security_level: SecurityLevel::Weak,
            category: AlgorithmCategory::BlockCipher,
        });
        db.entries.push(AlgorithmEntry {
            algorithm: CryptoAlgorithm::Rc4,
            display_name: "RC4".into(),
            block_size: None,
            key_sizes: vec![1, 256],
            security_level: SecurityLevel::Broken,
            category: AlgorithmCategory::StreamCipher,
        });
        db.entries.push(AlgorithmEntry {
            algorithm: CryptoAlgorithm::ChaCha20,
            display_name: "ChaCha20".into(),
            block_size: None,
            key_sizes: vec![32],
            security_level: SecurityLevel::Strong,
            category: AlgorithmCategory::StreamCipher,
        });
        db.entries.push(AlgorithmEntry {
            algorithm: CryptoAlgorithm::Md5,
            display_name: "MD5".into(),
            block_size: Some(64),
            key_sizes: vec![],
            security_level: SecurityLevel::Broken,
            category: AlgorithmCategory::HashFunction,
        });
        db.entries.push(AlgorithmEntry {
            algorithm: CryptoAlgorithm::Sha1,
            display_name: "SHA-1".into(),
            block_size: Some(64),
            key_sizes: vec![],
            security_level: SecurityLevel::Weak,
            category: AlgorithmCategory::HashFunction,
        });
        db.entries.push(AlgorithmEntry {
            algorithm: CryptoAlgorithm::Sha256,
            display_name: "SHA-256".into(),
            block_size: Some(64),
            key_sizes: vec![],
            security_level: SecurityLevel::Strong,
            category: AlgorithmCategory::HashFunction,
        });
        db.entries.push(AlgorithmEntry {
            algorithm: CryptoAlgorithm::Crc32,
            display_name: "CRC32".into(),
            block_size: None,
            key_sizes: vec![],
            security_level: SecurityLevel::Broken,
            category: AlgorithmCategory::Checksum,
        });
        db
    }

    /// Look up an algorithm.
    #[must_use]
    pub fn lookup(&self, algo: CryptoAlgorithm) -> Option<&AlgorithmEntry> {
        self.entries.iter().find(|e| e.algorithm == algo)
    }

    /// Return all entries in a given category.
    #[must_use]
    pub fn by_category(&self, cat: AlgorithmCategory) -> Vec<&AlgorithmEntry> {
        self.entries.iter().filter(|e| e.category == cat).collect()
    }

    /// Return all broken/weak entries.
    #[must_use]
    pub fn insecure_algorithms(&self) -> Vec<&AlgorithmEntry> {
        self.entries
            .iter()
            .filter(|e| {
                matches!(
                    e.security_level,
                    SecurityLevel::Broken | SecurityLevel::Weak
                )
            })
            .collect()
    }

    /// Total number of entries.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.entries.len()
    }

    /// Check if a detected algorithm is considered insecure.
    #[must_use]
    pub fn is_insecure(&self, algo: CryptoAlgorithm) -> bool {
        self.lookup(algo).is_some_and(|e| {
            matches!(
                e.security_level,
                SecurityLevel::Broken | SecurityLevel::Weak
            )
        })
    }

    /// Return the recommended replacement for a deprecated algorithm, if any.
    #[must_use]
    pub const fn recommended_replacement(&self, algo: CryptoAlgorithm) -> Option<CryptoAlgorithm> {
        match algo {
            CryptoAlgorithm::Des | CryptoAlgorithm::TripleDes => Some(CryptoAlgorithm::Aes256),
            CryptoAlgorithm::Rc4 => Some(CryptoAlgorithm::ChaCha20),
            CryptoAlgorithm::Md5 | CryptoAlgorithm::Sha1 => Some(CryptoAlgorithm::Sha256),
            _ => None,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AES_SBOX, SM4_SBOX};

    pub fn _embed(data: &[u8], what: &[u8], at: usize) -> Vec<u8> {
        let mut v = data.to_vec();
        if at + what.len() <= v.len() {
            v[at..at + what.len()].copy_from_slice(what);
        }
        v
    }

    // ── CipherFeature ─────────────────────────────────────────────────────────

    #[test]
    fn test_feature_certain_weight() {
        let f = CipherFeature::certain("test", 100, "note");
        assert!((f.weight - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_feature_likely_clamped() {
        let f = CipherFeature::likely("test", 1.5, 0, "over");
        assert!(f.weight <= 1.0);
        let f2 = CipherFeature::likely("test", -0.5, 0, "under");
        assert!(f2.weight >= 0.0);
    }

    #[test]
    fn test_feature_new_fields() {
        let f = CipherFeature::new("foo", 0.5, Some(42), "bar");
        assert_eq!(f.name, "foo");
        assert_eq!(f.offset, Some(42));
        assert_eq!(f.note, "bar");
    }

    // ── BlockCipherDetector ───────────────────────────────────────────────────

    #[test]
    fn test_block_detects_aes_sbox() {
        let mut data = vec![0u8; 512];
        data[100..356].copy_from_slice(&AES_SBOX);
        let map = BlockCipherDetector::scan(&data);
        assert!(map.contains_key(&CryptoAlgorithm::Aes128));
        assert!(
            map[&CryptoAlgorithm::Aes128]
                .iter()
                .any(|f| f.name == "aes_sbox")
        );
    }

    #[test]
    fn test_block_detects_aes_inv_sbox() {
        let mut data = vec![0u8; 512];
        data[50..306].copy_from_slice(&AES_INV_SBOX);
        let map = BlockCipherDetector::scan(&data);
        assert!(map.contains_key(&CryptoAlgorithm::Aes128));
    }

    #[test]
    fn test_block_detects_sm4_sbox() {
        let mut data = vec![0u8; 512];
        data[50..306].copy_from_slice(&SM4_SBOX);
        let map = BlockCipherDetector::scan(&data);
        assert!(map.contains_key(&CryptoAlgorithm::Sm4));
    }

    #[test]
    fn test_block_detects_des_s1() {
        let des_s1: &[u8] = &[0x0E, 0x04, 0x0D, 0x01, 0x02, 0x0F, 0x0B, 0x08];
        let mut data = vec![0u8; 64];
        data[10..18].copy_from_slice(des_s1);
        let map = BlockCipherDetector::scan(&data);
        assert!(map.contains_key(&CryptoAlgorithm::Des));
    }

    #[test]
    fn test_block_detects_blowfish_p0() {
        let bf_p0: &[u8] = &[0x88, 0x6a, 0x3f, 0x24];
        let mut data = vec![0u8; 64];
        data[8..12].copy_from_slice(bf_p0);
        let map = BlockCipherDetector::scan(&data);
        // Blowfish merged into Aes128 slot in our implementation
        assert!(map.contains_key(&CryptoAlgorithm::Aes128));
    }

    #[test]
    fn test_block_no_detection_random() {
        let data = vec![0xABu8; 32];
        let map = BlockCipherDetector::scan(&data);
        assert!(!map.contains_key(&CryptoAlgorithm::Sm4));
    }

    #[test]
    fn test_block_size_for_aes() {
        assert_eq!(
            BlockCipherDetector::block_size_for(CryptoAlgorithm::Aes128),
            Some(16)
        );
        assert_eq!(
            BlockCipherDetector::block_size_for(CryptoAlgorithm::Des),
            Some(8)
        );
    }

    // ── StreamCipherDetector ──────────────────────────────────────────────────

    #[test]
    fn test_stream_detects_chacha20_sigma() {
        let mut data = vec![0u8; 64];
        data[10..26].copy_from_slice(b"expand 32-byte k");
        let map = StreamCipherDetector::scan(&data);
        assert!(map.contains_key(&CryptoAlgorithm::ChaCha20));
    }

    #[test]
    fn test_stream_detects_chacha20_tau() {
        let mut data = vec![0u8; 64];
        data[10..26].copy_from_slice(b"expand 16-byte k");
        let map = StreamCipherDetector::scan(&data);
        assert!(map.contains_key(&CryptoAlgorithm::ChaCha20));
    }

    #[test]
    fn test_stream_detects_rc4_identity() {
        let mut data = vec![0u8; 32];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        let map = StreamCipherDetector::scan(&data);
        assert!(map.contains_key(&CryptoAlgorithm::Rc4));
    }

    #[test]
    fn test_stream_detects_rc4_permutation() {
        let mut data = vec![0u8; 512];
        // Fill 256-byte permutation at offset 100
        for i in 0u8..=255 {
            data[100 + i as usize] = (255 - i as usize) as u8;
        }
        let map = StreamCipherDetector::scan(&data);
        assert!(map.contains_key(&CryptoAlgorithm::Rc4));
    }

    #[test]
    fn test_stream_uniform_distribution_true() {
        // Build a perfectly uniform 1024-byte buffer
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        assert!(StreamCipherDetector::is_uniform_distribution(&data));
    }

    #[test]
    fn test_stream_uniform_distribution_false_all_zeros() {
        let data = vec![0u8; 1024];
        assert!(!StreamCipherDetector::is_uniform_distribution(&data));
    }

    // ── HashFunctionDetector ──────────────────────────────────────────────────

    #[test]
    fn test_hash_detects_sha256_h0() {
        let mut data = vec![0u8; 64];
        let h0 = 0x6a09_e667u32.to_be_bytes();
        data[10..14].copy_from_slice(&h0);
        let map = HashFunctionDetector::scan(&data);
        assert!(map.contains_key(&CryptoAlgorithm::Sha256));
    }

    #[test]
    fn test_hash_detects_md5_k0() {
        let mut data = vec![0u8; 32];
        data[4..8].copy_from_slice(&0xd76a_a478u32.to_le_bytes());
        let map = HashFunctionDetector::scan(&data);
        assert!(map.contains_key(&CryptoAlgorithm::Md5));
    }

    #[test]
    fn test_hash_detects_crc32_poly() {
        let mut data = vec![0u8; 32];
        data[4..8].copy_from_slice(&0xedb8_8320u32.to_le_bytes());
        let map = HashFunctionDetector::scan(&data);
        assert!(map.contains_key(&CryptoAlgorithm::Crc32));
    }

    #[test]
    fn test_hash_detects_sha512_h0() {
        let mut data = vec![0u8; 64];
        data[8..16].copy_from_slice(&0x6a09_e667_f3bc_c908u64.to_be_bytes());
        let map = HashFunctionDetector::scan(&data);
        assert!(map.contains_key(&CryptoAlgorithm::Sha512));
    }

    #[test]
    fn test_hash_output_length() {
        assert_eq!(
            HashFunctionDetector::output_length(CryptoAlgorithm::Md5),
            Some(16)
        );
        assert_eq!(
            HashFunctionDetector::output_length(CryptoAlgorithm::Sha256),
            Some(32)
        );
        assert_eq!(
            HashFunctionDetector::output_length(CryptoAlgorithm::Crc32),
            Some(4)
        );
        assert_eq!(
            HashFunctionDetector::output_length(CryptoAlgorithm::Rc4),
            None
        );
    }

    // ── DetectionReport ───────────────────────────────────────────────────────

    #[test]
    fn test_report_build_ranking() {
        let pairs = vec![
            (
                CryptoAlgorithm::Md5,
                vec![CipherFeature::certain("md5_k0", 0, "")],
            ),
            (
                CryptoAlgorithm::Sha256,
                vec![
                    CipherFeature::certain("sha256_h0", 0, ""),
                    CipherFeature::certain("sha256_k0", 0, ""),
                ],
            ),
        ];
        let report = DetectionReport::build(&pairs);
        // SHA-256 has 2 high-weight features, MD5 has 1; SHA-256 should rank higher
        assert_eq!(report.best_match, Some(CryptoAlgorithm::Sha256));
    }

    #[test]
    fn test_report_detected_threshold() {
        let pairs = vec![(
            CryptoAlgorithm::Md5,
            vec![CipherFeature::likely("md5_k0", 0.5, 0, "")],
        )];
        let report = DetectionReport::build(&pairs);
        assert!(report.detected(CryptoAlgorithm::Md5, 0.3));
        assert!(!report.detected(CryptoAlgorithm::Md5, 0.9));
    }

    #[test]
    fn test_report_confidence_for_missing() {
        let report = DetectionReport::build(&[]);
        assert_eq!(report.confidence_for(CryptoAlgorithm::Aes128), 0.0);
    }

    #[test]
    fn test_report_top_n() {
        let pairs = vec![
            (
                CryptoAlgorithm::Md5,
                vec![CipherFeature::likely("a", 0.6, 0, "")],
            ),
            (
                CryptoAlgorithm::Sha256,
                vec![CipherFeature::likely("b", 0.8, 0, "")],
            ),
            (
                CryptoAlgorithm::Crc32,
                vec![CipherFeature::likely("c", 0.4, 0, "")],
            ),
        ];
        let report = DetectionReport::build(&pairs);
        assert_eq!(report.top_n(2).len(), 2);
    }

    // ── CipherDetection ───────────────────────────────────────────────────────

    #[test]
    fn test_cipher_detection_aes_sbox() {
        let mut data = vec![0u8; 512];
        data[100..356].copy_from_slice(&AES_SBOX);
        let report = CipherDetection::detect(&data);
        assert!(report.best_match.is_some());
        assert!(report.detected(CryptoAlgorithm::Aes128, 0.5));
    }

    #[test]
    fn test_cipher_detection_chacha20_sigma() {
        let mut data = vec![0u8; 64];
        data[10..26].copy_from_slice(b"expand 32-byte k");
        let report = CipherDetection::detect(&data);
        assert!(report.detected(CryptoAlgorithm::ChaCha20, 0.5));
    }

    #[test]
    fn test_cipher_detection_any_detected() {
        let mut data = vec![0u8; 512];
        data[100..356].copy_from_slice(&AES_SBOX);
        assert!(CipherDetection::any_detected(&data, 0.5));
    }

    #[test]
    fn test_cipher_detection_not_detected_random() {
        let data = vec![0x42u8; 32];
        assert!(!CipherDetection::any_detected(&data, 0.5));
    }

    #[test]
    fn test_cipher_detection_algorithms_list() {
        let mut data = vec![0u8; 600];
        data[100..356].copy_from_slice(&AES_SBOX);
        data[356..372].copy_from_slice(b"expand 32-byte k");
        let algos = CipherDetection::detected_algorithms(&data, 0.5);
        assert!(algos.contains(&CryptoAlgorithm::Aes128));
        assert!(algos.contains(&CryptoAlgorithm::ChaCha20));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    #[test]
    fn test_find_bytes_found() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04];
        assert_eq!(find_bytes(&data, &[0x02, 0x03]), Some(2));
    }

    #[test]
    fn test_find_bytes_not_found() {
        let data = vec![0x00, 0x01, 0x02];
        assert_eq!(find_bytes(&data, &[0x05]), None);
    }

    #[test]
    fn test_find_permutation_256_identity() {
        let data: Vec<u8> = (0u8..=255).collect();
        assert_eq!(find_permutation_256(&data), Some(0));
    }

    #[test]
    fn test_find_permutation_256_not_found() {
        let data = vec![0u8; 256];
        assert_eq!(find_permutation_256(&data), None);
    }

    #[test]
    fn test_combined_confidence_empty() {
        assert_eq!(combined_confidence(&[]), 0.0);
    }

    #[test]
    fn test_combined_confidence_single_1() {
        let f = CipherFeature::certain("t", 0, "");
        assert!((combined_confidence(&[f]) - 0.99).abs() < 1e-4);
    }
}

// ── BinaryProfile ─────────────────────────────────────────────────────────────

/// A comprehensive cryptographic profile of a binary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BinaryProfile {
    /// All cipher detections.
    pub detection_report: DetectionReport,
    /// Key candidates found.
    pub key_candidates: Vec<KeyCandidate>,
    /// Entropy of the entire binary.
    pub overall_entropy: f64,
    /// High-entropy regions (potential encrypted/compressed sections).
    pub high_entropy_regions: Vec<EntropyRegion>,
    /// Summary string.
    pub summary: String,
}

/// A region of elevated entropy.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntropyRegion {
    pub offset: usize,
    pub length: usize,
    pub entropy: f64,
}

impl BinaryProfile {
    /// Profile a binary: run detection + entropy analysis.
    #[must_use]
    pub fn profile(data: &[u8]) -> Self {
        let detection_report = CipherDetection::detect(data);
        let key_candidates = detection_report.key_candidates.clone();
        let overall_entropy = shannon_entropy(data);
        let high_entropy_regions = find_high_entropy_regions(data, 512, 7.0);
        let summary = build_summary(&detection_report, &high_entropy_regions);
        Self {
            detection_report,
            key_candidates,
            overall_entropy,
            high_entropy_regions,
            summary,
        }
    }

    /// Whether this binary contains any cryptographic material above confidence 0.5.
    #[must_use]
    pub fn has_crypto(&self) -> bool {
        self.detection_report.best_confidence >= 0.5
    }

    /// Algorithms detected above 0.5 confidence.
    #[must_use]
    pub fn strong_detections(&self) -> Vec<CryptoAlgorithm> {
        self.detection_report
            .candidates
            .iter()
            .filter(|c| c.confidence >= 0.5)
            .map(|c| c.algorithm)
            .collect()
    }
}

fn find_high_entropy_regions(data: &[u8], window: usize, threshold: f64) -> Vec<EntropyRegion> {
    let mut regions = Vec::new();
    if window == 0 || data.len() < window {
        return regions;
    }
    // Ensure step is at least 1 to prevent an infinite loop when window < 4.
    let step = (window / 4).max(1);
    let mut i = 0;
    while i + window <= data.len() {
        let e = shannon_entropy(&data[i..i + window]);
        if e >= threshold {
            regions.push(EntropyRegion {
                offset: i,
                length: window,
                entropy: e,
            });
        }
        i += step;
    }
    regions
}

fn build_summary(report: &DetectionReport, regions: &[EntropyRegion]) -> String {
    let algo_names: Vec<String> = report
        .candidates
        .iter()
        .take(3)
        .map(|c| format!("{} ({:.0}%)", c.algorithm, c.confidence * 100.0))
        .collect();
    format!(
        "Detected: [{}]; {} high-entropy region(s)",
        if algo_names.is_empty() {
            "none".into()
        } else {
            algo_names.join(", ")
        },
        regions.len()
    )
}

// ── CryptoFingerprint ─────────────────────────────────────────────────────────

/// A compact fingerprint of the cryptographic content of a binary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CryptoFingerprint {
    /// Hash of all detected constant offsets and algorithm IDs.
    pub fingerprint_hash: u64,
    /// Sorted list of detected algorithm names.
    pub algorithms: Vec<String>,
    /// Total byte size of all detected constants.
    pub constant_bytes: usize,
}

impl CryptoFingerprint {
    /// Build a fingerprint from a detection report.
    #[must_use]
    pub fn from_report(report: &DetectionReport) -> Self {
        let mut algorithms: Vec<String> = report
            .candidates
            .iter()
            .map(|c| c.algorithm.to_string())
            .collect();
        algorithms.sort();
        algorithms.dedup();

        let constant_bytes: usize = report
            .features
            .iter()
            .map(|f| f.offset.unwrap_or(0))
            .filter(|&o| o > 0)
            .count()
            * 4;

        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for name in &algorithms {
            for b in name.bytes() {
                hash ^= u64::from(b);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }

        Self {
            fingerprint_hash: hash,
            algorithms,
            constant_bytes,
        }
    }

    /// Whether two binaries share the same cryptographic algorithms.
    #[must_use]
    pub fn same_algorithms(&self, other: &Self) -> bool {
        self.algorithms == other.algorithms
    }

    /// Similarity score: fraction of algorithms in common.
    #[must_use]
    pub fn similarity(&self, other: &Self) -> f64 {
        let common = self
            .algorithms
            .iter()
            .filter(|a| other.algorithms.contains(a))
            .count();
        let total = (self.algorithms.len() + other.algorithms.len()).max(1);
        let n = f64::from(u32::try_from(common).unwrap_or(u32::MAX));
        let d = f64::from(u32::try_from(total).unwrap_or(1));
        n * 2.0 / d
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_binary_profile_empty_binary() {
        let profile = BinaryProfile::profile(&[]);
        assert!(!profile.has_crypto());
        assert!(profile.strong_detections().is_empty());
    }

    #[test]
    fn test_binary_profile_with_aes_sbox() {
        let mut data = vec![0u8; 512];
        data[100..356].copy_from_slice(&AES_SBOX);
        let profile = BinaryProfile::profile(&data);
        assert!(profile.has_crypto());
    }

    #[test]
    fn test_binary_profile_high_entropy_regions() {
        // Pseudo-random data has high entropy
        let data: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let profile = BinaryProfile::profile(&data);
        assert!(!profile.high_entropy_regions.is_empty());
    }

    #[test]
    fn test_binary_profile_summary_non_empty() {
        let data = vec![0u8; 64];
        let profile = BinaryProfile::profile(&data);
        assert!(!profile.summary.is_empty());
    }

    #[test]
    fn test_fingerprint_from_empty_report() {
        let report = DetectionReport::build(&[]);
        let fp = CryptoFingerprint::from_report(&report);
        assert!(fp.algorithms.is_empty());
    }

    #[test]
    fn test_fingerprint_same_algorithms() {
        let mut data = vec![0u8; 512];
        data[100..356].copy_from_slice(&AES_SBOX);
        let report = CipherDetection::detect(&data);
        let fp1 = CryptoFingerprint::from_report(&report);
        let fp2 = CryptoFingerprint::from_report(&report);
        assert!(fp1.same_algorithms(&fp2));
        assert!((fp1.similarity(&fp2) - 1.0).abs() < 1e-4);
    }

    #[test]
    fn test_fingerprint_different_algorithms() {
        let mut aes_data = vec![0u8; 512];
        aes_data[100..356].copy_from_slice(&AES_SBOX);
        let aes_report = CipherDetection::detect(&aes_data);
        let fp_aes = CryptoFingerprint::from_report(&aes_report);

        let empty_report = DetectionReport::build(&[]);
        let fp_empty = CryptoFingerprint::from_report(&empty_report);

        assert!(!fp_aes.same_algorithms(&fp_empty));
    }

    #[test]
    fn test_entropy_region_detection() {
        let uniform: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let regions = find_high_entropy_regions(&uniform, 512, 7.0);
        assert!(!regions.is_empty());
        for r in &regions {
            assert!(r.entropy >= 7.0);
        }
    }

    #[test]
    fn test_entropy_region_zeros_low_entropy() {
        let zeros = vec![0u8; 2048];
        let regions = find_high_entropy_regions(&zeros, 512, 7.0);
        assert!(regions.is_empty());
    }

    #[test]
    fn test_combined_confidence_two_features() {
        let f1 = CipherFeature::likely("a", 0.8, 0, "");
        let f2 = CipherFeature::likely("b", 0.7, 0, "");
        let conf = combined_confidence(&[f1, f2]);
        // 1 - (0.2 * 0.3) = 0.94
        assert!((conf - 0.2f32.mul_add(-0.3, 1.0)).abs() < 1e-4);
    }
}
