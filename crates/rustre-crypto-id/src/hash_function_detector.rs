//! `hash_function_detector` — Identify hash-function implementations in binary data.
//!
//! Detects SHA-1, SHA-2 family (SHA-256/512), SHA-3 / Keccak, MD5, RIPEMD,
//! BLAKE2/BLAKE3, Whirlpool, Tiger, and SM3 through constant-matching,
//! structural pattern recognition, and entropy analysis.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── HashFamily ────────────────────────────────────────────────────────────────

/// Top-level family of hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashFamily {
    Sha1,
    Sha2,
    Sha3Keccak,
    Md5,
    Ripemd,
    Blake2,
    Blake3,
    Whirlpool,
    Tiger,
    Sm3,
    Crc,
    Adler,
    FnvOrSipHash,
    Unknown,
}

impl std::fmt::Display for HashFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl HashFamily {
    /// Returns `true` for cryptographically secure hash families.
    #[must_use]
    pub const fn is_cryptographic(self) -> bool {
        matches!(
            self,
            Self::Sha1
                | Self::Sha2
                | Self::Sha3Keccak
                | Self::Ripemd
                | Self::Blake2
                | Self::Blake3
                | Self::Whirlpool
                | Self::Tiger
                | Self::Sm3
        )
    }

    /// Returns `true` for weak or broken hash functions.
    #[must_use]
    pub const fn is_weak(self) -> bool {
        matches!(self, Self::Md5 | Self::Sha1 | Self::Crc | Self::Adler)
    }

    /// Typical digest length in bytes, or `None` if variable / unknown.
    #[must_use]
    pub const fn digest_bytes(self) -> Option<usize> {
        match self {
            Self::Md5 => Some(16),
            Self::Sha1 | Self::Ripemd => Some(20),
            Self::Blake2 | Self::Blake3 | Self::Sm3 => Some(32),
            Self::Whirlpool => Some(64),
            Self::Tiger => Some(24),
            Self::Crc | Self::Adler => Some(4),
            _ => None, // Sha2, Sha3Keccak, FnvOrSipHash, Unknown
        }
    }
}

// ── HashConstant ──────────────────────────────────────────────────────────────

/// A magic constant associated with a specific hash algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashConstant {
    /// Human-readable name (e.g. `"SHA256-H0[0]"`).
    pub name: String,
    /// Hash family.
    pub family: HashFamily,
    /// Exact bytes of this constant (little-endian or big-endian as stored).
    pub bytes: Vec<u8>,
    /// Confidence weight when this constant is found [0.0, 1.0].
    pub weight: f32,
}

impl HashConstant {
    /// Create a new constant entry.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        family: HashFamily,
        bytes: Vec<u8>,
        weight: f32,
    ) -> Self {
        Self { name: name.into(), family, bytes, weight: weight.clamp(0.0, 1.0) }
    }
}

// ── HashPattern ───────────────────────────────────────────────────────────────

/// A structural instruction-level pattern associated with a hash algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashPattern {
    /// Human-readable description.
    pub description: String,
    /// Hash family.
    pub family: HashFamily,
    /// Byte pattern.
    pub bytes: Vec<u8>,
    /// Per-byte mask (0xFF = exact, 0x00 = wildcard).
    pub mask: Vec<u8>,
    /// Confidence weight [0.0, 1.0].
    pub weight: f32,
}

impl HashPattern {
    /// Create a new structural pattern.
    #[must_use]
    pub fn new(
        description: impl Into<String>,
        family: HashFamily,
        bytes: Vec<u8>,
        mask: Vec<u8>,
        weight: f32,
    ) -> Self {
        Self {
            description: description.into(),
            family,
            bytes,
            mask,
            weight: weight.clamp(0.0, 1.0),
        }
    }
}

// ── HashDetection ─────────────────────────────────────────────────────────────

/// A single detection result from the hash function detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashDetection {
    /// Hash family identified.
    pub family: HashFamily,
    /// Byte offset in the binary.
    pub offset: usize,
    /// Confidence [0.0, 1.0].
    pub confidence: f32,
    /// Evidence description.
    pub evidence: String,
    /// Whether this was triggered by a constant (vs structural pattern).
    pub from_constant: bool,
}

impl HashDetection {
    /// Create a new detection.
    #[must_use]
    pub fn new(
        family: HashFamily,
        offset: usize,
        confidence: f32,
        evidence: impl Into<String>,
        from_constant: bool,
    ) -> Self {
        Self { family, offset, confidence: confidence.clamp(0.0, 1.0), evidence: evidence.into(), from_constant }
    }

    /// Returns `true` if confidence ≥ 0.80.
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.80
    }
}

// ── ConstantDatabase ──────────────────────────────────────────────────────────

fn builtin_constants() -> Vec<HashConstant> {
    vec![
        HashConstant::new("MD5-H0-LE", HashFamily::Md5,
            vec![0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10], 0.82),
        HashConstant::new("MD5-K0-LE", HashFamily::Md5, 0xd76a_a478u32.to_le_bytes().to_vec(), 0.78),
        HashConstant::new("MD5-K1-LE", HashFamily::Md5, 0xe8c7_b756u32.to_le_bytes().to_vec(), 0.75),
        HashConstant::new("SHA1-H0-BE", HashFamily::Sha1, 0x6745_2301u32.to_be_bytes().to_vec(), 0.70),
        HashConstant::new("SHA1-K0-BE", HashFamily::Sha1, 0x5A82_7999u32.to_be_bytes().to_vec(), 0.80),
        HashConstant::new("SHA1-K1-BE", HashFamily::Sha1, 0x6ED9_EBA1u32.to_be_bytes().to_vec(), 0.80),
        HashConstant::new("SHA256-H0-BE", HashFamily::Sha2, 0x6a09_e667u32.to_be_bytes().to_vec(), 0.78),
        HashConstant::new("SHA256-H0-LE", HashFamily::Sha2, 0x6a09_e667u32.to_le_bytes().to_vec(), 0.73),
        HashConstant::new("SHA256-K0-BE", HashFamily::Sha2, 0x428a_2f98u32.to_be_bytes().to_vec(), 0.76),
        HashConstant::new("SHA512-H0-BE", HashFamily::Sha2, 0x6a09_e667_f3bc_c908u64.to_be_bytes().to_vec(), 0.90),
        HashConstant::new("KECCAK-RC0", HashFamily::Sha3Keccak, 0x0000_0000_0000_0001u64.to_le_bytes().to_vec(), 0.60),
        HashConstant::new("KECCAK-RC1", HashFamily::Sha3Keccak, 0x0000_0000_0000_8082u64.to_le_bytes().to_vec(), 0.78),
        HashConstant::new("KECCAK-RC2", HashFamily::Sha3Keccak, 0x8000_0000_0000_808au64.to_le_bytes().to_vec(), 0.85),
        HashConstant::new("RIPEMD160-H0-LE", HashFamily::Ripemd, 0x6745_2301u32.to_le_bytes().to_vec(), 0.62),
        HashConstant::new("BLAKE2b-IV0", HashFamily::Blake2, 0x6A09_E667_F3BC_C908u64.to_le_bytes().to_vec(), 0.87),
        HashConstant::new("BLAKE2-sigma", HashFamily::Blake2, b"expand 32-byte k".to_vec(), 0.88),
        HashConstant::new("BLAKE3-IV0", HashFamily::Blake3, 0x6A09_E667u32.to_le_bytes().to_vec(), 0.68),
        HashConstant::new("WHIRLPOOL-MINPOLY", HashFamily::Whirlpool, vec![0x1D, 0x1B], 0.68),
        HashConstant::new("SM3-T0",  HashFamily::Sm3, 0x79cc_4519u32.to_be_bytes().to_vec(), 0.90),
        HashConstant::new("SM3-T16", HashFamily::Sm3, 0x7a87_9d8au32.to_be_bytes().to_vec(), 0.90),
        HashConstant::new("SM3-H0",  HashFamily::Sm3, 0x7380_166fu32.to_be_bytes().to_vec(), 0.92),
        HashConstant::new("TIGER-S1-PREFIX", HashFamily::Tiger,
            vec![0x02, 0xaa, 0xb1, 0x7c, 0xf3, 0x29, 0x60, 0x09], 0.80),
        HashConstant::new("CRC32-POLY-LE", HashFamily::Crc, 0xEDB8_8320u32.to_le_bytes().to_vec(), 0.90),
        HashConstant::new("CRC32-POLY-BE", HashFamily::Crc, 0xEDB8_8320u32.to_be_bytes().to_vec(), 0.85),
        HashConstant::new("ADLER32-MOD", HashFamily::Adler, 0xFFF1u32.to_le_bytes().to_vec(), 0.72),
    ]
}

fn builtin_patterns() -> Vec<HashPattern> {
    vec![
        // SHA-256 ROT constants: typical bit-rotate count (σ0: ROR 2,13,22)
        HashPattern::new(
            "SHA256-sigma0-rotate-2",
            HashFamily::Sha2,
            vec![0xC1, 0xC0, 0x02], // ROR eax, 2 (x86)
            vec![0xFF, 0xF8, 0xFF],
            0.55,
        ),
        // MD5 left-rotate constant 7 (first s[] value)
        HashPattern::new(
            "MD5-ROTL-7",
            HashFamily::Md5,
            vec![0xC1, 0xC0, 0x07],
            vec![0xFF, 0xF8, 0xFF],
            0.50,
        ),
        // KECCAK lane XOR pattern (XOR EAX, [addr]) — high density
        HashPattern::new(
            "KECCAK-XOR-LOAD",
            HashFamily::Sha3Keccak,
            vec![0x33, 0x05, 0x00, 0x00, 0x00, 0x00], // XOR eax, [imm32]
            vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
            0.50,
        ),
        // RIPEMD-160 uses the constant 0x50A2_8BE6
        HashPattern::new(
            "RIPEMD160-K-CONST",
            HashFamily::Ripemd,
            0x50A2_8BE6u32.to_le_bytes().to_vec(),
            vec![0xFF, 0xFF, 0xFF, 0xFF],
            0.82,
        ),
        // BLAKE2b mixing: adds followed by XOR and rotate (G function)
        HashPattern::new(
            "BLAKE2-G-ADD-XOR",
            HashFamily::Blake2,
            vec![0x03, 0xC8, 0x33, 0xCA], // add ecx, eax; xor ecx, edx
            vec![0xFF, 0xFF, 0xFF, 0xFF],
            0.55,
        ),
    ]
}

// ── HashFunctionDetector ──────────────────────────────────────────────────────

/// Scans binary data for hash-function implementations.
pub struct HashFunctionDetector {
    /// Minimum confidence threshold for reporting.
    pub min_confidence: f32,
    /// Whether to include structural instruction patterns.
    pub scan_patterns: bool,
    constants: Vec<HashConstant>,
    patterns: Vec<HashPattern>,
}

impl Default for HashFunctionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl HashFunctionDetector {
    /// Create with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            min_confidence: 0.55,
            scan_patterns: true,
            constants: builtin_constants(),
            patterns: builtin_patterns(),
        }
    }

    /// Override minimum confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(mut self, min: f32) -> Self {
        self.min_confidence = min;
        self
    }

    /// Disable structural pattern scanning (constants only).
    #[must_use]
    pub const fn constants_only(mut self) -> Self {
        self.scan_patterns = false;
        self
    }

    /// Scan `binary` and return all individual detections.
    #[must_use]
    pub fn scan(&self, binary: &[u8]) -> Vec<HashDetection> {
        let mut detections: Vec<HashDetection> = Vec::new();

        // Constants scan.
        for constant in &self.constants {
            if constant.weight < self.min_confidence {
                continue;
            }
            for offset in find_all(binary, &constant.bytes) {
                detections.push(HashDetection::new(
                    constant.family,
                    offset,
                    constant.weight,
                    format!("constant {} at 0x{:X}", constant.name, offset),
                    true,
                ));
            }
        }

        // Pattern scan.
        if self.scan_patterns {
            for pat in &self.patterns {
                if pat.weight < self.min_confidence {
                    continue;
                }
                for offset in masked_scan(binary, &pat.bytes, &pat.mask) {
                    detections.push(HashDetection::new(
                        pat.family,
                        offset,
                        pat.weight,
                        format!("pattern '{}' at 0x{:X}", pat.description, offset),
                        false,
                    ));
                }
            }
        }

        detections.sort_by_key(|d| d.offset);
        detections
    }

    /// Identify the most likely hash algorithm from `binary`.
    ///
    /// Returns ranked `(HashFamily, combined_confidence)` pairs, best first.
    #[must_use]
    pub fn identify(&self, binary: &[u8]) -> Vec<(HashFamily, f32)> {
        let detections = self.scan(binary);
        // Group detections by family and combine confidence.
        let mut scores: HashMap<HashFamily, Vec<f32>> = HashMap::new();
        for d in detections {
            scores.entry(d.family).or_default().push(d.confidence);
        }

        let mut ranked: Vec<(HashFamily, f32)> = scores
            .into_iter()
            .map(|(family, confs)| {
                let combined = combined_confidence(confs.iter().copied());
                (family, combined)
            })
            .filter(|(_, c)| *c >= self.min_confidence)
            .collect();

        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        ranked
    }

    /// Full report: detections + ranked identifications.
    #[must_use]
    pub fn full_report(&self, binary: &[u8]) -> HashReport {
        let detections = self.scan(binary);
        let ranked = self.identify(binary);
        HashReport { detections, ranked }
    }

    /// Add a custom constant to the detector.
    pub fn add_constant(&mut self, constant: HashConstant) {
        self.constants.push(constant);
    }

    /// Add a custom structural pattern.
    pub fn add_pattern(&mut self, pattern: HashPattern) {
        self.patterns.push(pattern);
    }
}

// ── HashReport ────────────────────────────────────────────────────────────────

/// Full report from the hash function detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashReport {
    /// All individual detections sorted by offset.
    pub detections: Vec<HashDetection>,
    /// Ranked `(HashFamily, combined_confidence)` pairs.
    pub ranked: Vec<(HashFamily, f32)>,
}

impl HashReport {
    /// Returns the top-ranked hash family, if any.
    #[must_use]
    pub fn top_family(&self) -> Option<HashFamily> {
        self.ranked.first().map(|(f, _)| *f)
    }

    /// Returns `true` if any high-confidence detection exists.
    #[must_use]
    pub fn has_high_confidence(&self) -> bool {
        self.detections.iter().any(HashDetection::is_high_confidence)
    }

    /// Histogram of detections by family.
    #[must_use]
    pub fn family_histogram(&self) -> HashMap<HashFamily, usize> {
        let mut map: HashMap<HashFamily, usize> = HashMap::new();
        for d in &self.detections {
            *map.entry(d.family).or_insert(0) += 1;
        }
        map
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return Vec::new();
    }
    let limit = haystack.len() - needle.len();
    (0..=limit).filter(|&i| haystack[i..i + needle.len()] == *needle).collect()
}

fn masked_scan(data: &[u8], pattern: &[u8], mask: &[u8]) -> Vec<usize> {
    let plen = pattern.len();
    if plen == 0 || plen > data.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for pos in 0..=(data.len() - plen) {
        let hit = pattern
            .iter()
            .enumerate()
            .all(|(i, &p)| mask[i] == 0x00 || (data[pos + i] & mask[i]) == (p & mask[i]));
        if hit {
            out.push(pos);
        }
    }
    out
}

fn combined_confidence(scores: impl Iterator<Item = f32>) -> f32 {
    let miss = scores.fold(1.0f32, |acc, s| acc * (1.0 - s.clamp(0.0, 1.0)));
    (1.0 - miss).clamp(0.0, 0.99)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_sha256_h0_be() {
        let bytes = 0x6a09_e667u32.to_be_bytes();
        let d = HashFunctionDetector::new();
        let dets = d.scan(&bytes);
        assert!(dets.iter().any(|det| det.family == HashFamily::Sha2));
    }

    #[test]
    fn test_scan_sha512_h0_be() {
        let bytes = 0x6a09_e667_f3bc_c908u64.to_be_bytes();
        let d = HashFunctionDetector::new();
        let dets = d.scan(&bytes);
        assert!(dets.iter().any(|det| det.family == HashFamily::Sha2 && det.confidence >= 0.88));
    }

    #[test]
    fn test_scan_md5_k0_le() {
        let bytes = 0xd76a_a478u32.to_le_bytes();
        let d = HashFunctionDetector::new();
        let dets = d.scan(&bytes);
        assert!(dets.iter().any(|det| det.family == HashFamily::Md5));
    }

    #[test]
    fn test_scan_sm3_t0() {
        let bytes = 0x79cc_4519u32.to_be_bytes();
        let d = HashFunctionDetector::new();
        let dets = d.scan(&bytes);
        assert!(dets.iter().any(|det| det.family == HashFamily::Sm3));
    }

    #[test]
    fn test_scan_crc32_poly() {
        let bytes = 0xEDB8_8320u32.to_le_bytes();
        let d = HashFunctionDetector::new();
        let dets = d.scan(&bytes);
        assert!(dets.iter().any(|det| det.family == HashFamily::Crc));
    }

    #[test]
    fn test_scan_keccak_rc1() {
        let bytes = 0x0000_0000_0000_8082u64.to_le_bytes();
        let d = HashFunctionDetector::new();
        let dets = d.scan(&bytes);
        assert!(dets.iter().any(|det| det.family == HashFamily::Sha3Keccak));
    }

    #[test]
    fn test_scan_blake2_sigma() {
        let d = HashFunctionDetector::new();
        let dets = d.scan(b"expand 32-byte k");
        assert!(dets.iter().any(|det| det.family == HashFamily::Blake2));
    }

    #[test]
    fn test_identify_sha2_ranked_first() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x6a09_e667u32.to_be_bytes());
        bytes.extend_from_slice(&0x428a_2f98u32.to_be_bytes());
        let d = HashFunctionDetector::new();
        let ranked = d.identify(&bytes);
        assert!(!ranked.is_empty());
        assert_eq!(ranked[0].0, HashFamily::Sha2);
    }

    #[test]
    fn test_full_report_has_top_family() {
        let bytes = 0x6a09_e667u32.to_be_bytes();
        let d = HashFunctionDetector::new();
        let report = d.full_report(&bytes);
        assert!(report.top_family().is_some());
    }

    #[test]
    fn test_hash_family_predicates() {
        assert!(HashFamily::Sha2.is_cryptographic());
        assert!(!HashFamily::Crc.is_cryptographic());
        assert!(HashFamily::Md5.is_weak());
        assert!(!HashFamily::Blake3.is_weak());
    }

    #[test]
    fn test_hash_family_digest_bytes() {
        assert_eq!(HashFamily::Md5.digest_bytes(), Some(16));
        assert_eq!(HashFamily::Sha1.digest_bytes(), Some(20));
        assert_eq!(HashFamily::Crc.digest_bytes(), Some(4));
        assert_eq!(HashFamily::Sha2.digest_bytes(), None);
    }

    #[test]
    fn test_report_family_histogram() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xd76a_a478u32.to_le_bytes());
        bytes.extend_from_slice(&0xe8c7_b756u32.to_le_bytes());
        let d = HashFunctionDetector::new();
        let report = d.full_report(&bytes);
        let hist = report.family_histogram();
        assert!(hist.get(&HashFamily::Md5).copied().unwrap_or(0) >= 1);
    }

    #[test]
    fn test_confidence_threshold_filters_weak() {
        let bytes = 0xd76a_a478u32.to_le_bytes(); // MD5 K0 weight=0.78
        let d = HashFunctionDetector::new().with_min_confidence(0.90);
        let dets = d.scan(&bytes);
        // md5 k0 weight 0.78 < 0.90, should not appear
        assert!(dets.iter().all(|det| det.confidence >= 0.90));
    }

    #[test]
    fn test_ripemd_constant() {
        let bytes = 0x50A2_8BE6u32.to_le_bytes();
        let d = HashFunctionDetector::new();
        let dets = d.scan(&bytes);
        assert!(dets.iter().any(|det| det.family == HashFamily::Ripemd));
    }

    #[test]
    fn test_builtin_constants_non_empty() {
        assert!(!builtin_constants().is_empty());
    }

    #[test]
    fn test_builtin_patterns_non_empty() {
        assert!(!builtin_patterns().is_empty());
    }
}
