//! Cryptographic constant finder.
//!
//! Scans binary data for well-known cryptographic constants such as SHA-1/SHA-256
//! initial hash values, AES S-box, MD5 table, and common prime values.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Well-known constant tables ────────────────────────────────────────────────

/// SHA-256 initial hash values (H0..H7).
pub const SHA256_INIT: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
    0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
];

/// SHA-256 round constants (first 8 of 64).
pub const SHA256_K_PARTIAL: [u32; 8] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5,
    0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
];

/// SHA-1 initial hash values.
pub const SHA1_INIT: [u32; 5] = [
    0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0,
];

/// SHA-1 round constants.
pub const SHA1_K: [u32; 4] = [
    0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xca62_c1d6,
];

/// MD5 magic constants (A, B, C, D initial values).
pub const MD5_INIT: [u32; 4] = [
    0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476,
];

/// CRC-32 polynomial.
pub const CRC32_POLY: u32 = 0xEDB8_8320;

/// TEA delta constant.
pub const TEA_DELTA: u32 = 0x9e37_79b9;

/// First 16 bytes of the AES S-box (same as `AES_SBOX[0..16]`).
pub const AES_SBOX_HEAD: [u8; 16] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
];

/// DES S-box 1 (first 8 bytes).
pub const DES_SBOX1_HEAD: [u8; 8] = [14, 4, 13, 1, 2, 15, 11, 8];

/// Diffie-Hellman 1024-bit MODP group 2 generator (just the value 2 as marker).
pub const DH_GENERATOR_2: u64 = 2u64;

// ── Enumerations ─────────────────────────────────────────────────────────────

/// Category of the cryptographic constant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConstantCategory {
    HashInitialValue,
    HashRoundConstant,
    SubstitutionBox,
    PermutationTable,
    BlockCipherConstant,
    StreamCipherConstant,
    PublicKeyParam,
    ChecksumPolynomial,
    MiscCryptoConstant,
}

impl ConstantCategory {
    #[must_use]
    pub const fn display_name(&self) -> &str {
        match self {
            Self::HashInitialValue => "Hash IV",
            Self::HashRoundConstant => "Hash Round Constant",
            Self::SubstitutionBox => "S-box",
            Self::PermutationTable => "Permutation Table",
            Self::BlockCipherConstant => "Block Cipher Constant",
            Self::StreamCipherConstant => "Stream Cipher Constant",
            Self::PublicKeyParam => "Public-Key Parameter",
            Self::ChecksumPolynomial => "Checksum Polynomial",
            Self::MiscCryptoConstant => "Miscellaneous",
        }
    }
}

/// Associated algorithm for a constant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoAlgorithm {
    Sha1,
    Sha256,
    Sha512,
    Md5,
    Aes,
    Des,
    Rc4,
    Blowfish,
    Tea,
    Xtea,
    Crc32,
    DiffieHellman,
    Rsa,
    Unknown(String),
}

impl CryptoAlgorithm {
    #[must_use]
    pub const fn display_name(&self) -> &str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
            Self::Md5 => "MD5",
            Self::Aes => "AES",
            Self::Des => "DES",
            Self::Rc4 => "RC4",
            Self::Blowfish => "Blowfish",
            Self::Tea => "TEA",
            Self::Xtea => "XTEA",
            Self::Crc32 => "CRC-32",
            Self::DiffieHellman => "Diffie-Hellman",
            Self::Rsa => "RSA",
            Self::Unknown(s) => s.as_str(),
        }
    }
}

// ── ConstantPattern ───────────────────────────────────────────────────────────

/// A known cryptographic constant pattern to search for in binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstantPattern {
    /// Unique identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Associated algorithm.
    pub algorithm: CryptoAlgorithm,
    /// Category.
    pub category: ConstantCategory,
    /// Byte sequence to search for (little-endian representation).
    pub bytes_le: Vec<u8>,
    /// Byte sequence in big-endian (if different).
    pub bytes_be: Option<Vec<u8>>,
    /// Minimum length of a match (may be shorter than full pattern for partial matches).
    pub min_match_len: usize,
    /// Confidence score if full pattern matches (0–100).
    pub full_match_confidence: u8,
    /// Notes about this constant.
    pub notes: String,
}

impl ConstantPattern {
    fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        algorithm: CryptoAlgorithm,
        category: ConstantCategory,
        bytes_le: Vec<u8>,
        confidence: u8,
    ) -> Self {
        let min_len = (bytes_le.len() / 2).max(4);
        Self {
            id: id.into(),
            name: name.into(),
            algorithm,
            category,
            bytes_le,
            bytes_be: None,
            min_match_len: min_len,
            full_match_confidence: confidence,
            notes: String::new(),
        }
    }

    fn with_be(mut self, bytes_be: Vec<u8>) -> Self {
        self.bytes_be = Some(bytes_be);
        self
    }

    fn with_notes(mut self, n: impl Into<String>) -> Self {
        self.notes = n.into();
        self
    }

    /// Build all built-in patterns.
    #[must_use]
    pub fn builtin_patterns() -> Vec<Self> {
        let mut v = Vec::new();

        // SHA-256 IV (little-endian word stream)
        let sha256_iv_little: Vec<u8> = SHA256_INIT.iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let sha256_iv_big: Vec<u8> = SHA256_INIT.iter()
            .flat_map(|w| w.to_be_bytes())
            .collect();
        v.push(Self::new(
            "sha256_iv", "SHA-256 Initial Hash Values",
            CryptoAlgorithm::Sha256, ConstantCategory::HashInitialValue,
            sha256_iv_little, 95,
        ).with_be(sha256_iv_big)
         .with_notes("FIPS 180-4 §5.3.3 — matches both LE and BE layouts"));

        // SHA-256 K[0..8] (partial, LE)
        let sha256_k_le: Vec<u8> = SHA256_K_PARTIAL.iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        v.push(Self::new(
            "sha256_k_partial", "SHA-256 Round Constants K[0..7]",
            CryptoAlgorithm::Sha256, ConstantCategory::HashRoundConstant,
            sha256_k_le, 90,
        ).with_notes("First 8 of 64 SHA-256 round constants"));

        // SHA-1 IV (LE)
        let sha1_iv_little: Vec<u8> = SHA1_INIT.iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let sha1_iv_big: Vec<u8> = SHA1_INIT.iter()
            .flat_map(|w| w.to_be_bytes())
            .collect();
        v.push(Self::new(
            "sha1_iv", "SHA-1 Initial Hash Values",
            CryptoAlgorithm::Sha1, ConstantCategory::HashInitialValue,
            sha1_iv_little, 95,
        ).with_be(sha1_iv_big));

        // SHA-1 K values (LE)
        let sha1_k_le: Vec<u8> = SHA1_K.iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        v.push(Self::new(
            "sha1_k", "SHA-1 Round Constants",
            CryptoAlgorithm::Sha1, ConstantCategory::HashRoundConstant,
            sha1_k_le, 85,
        ));

        // MD5 IV (same as SHA-1 A/B/C/D)
        let md5_iv_le: Vec<u8> = MD5_INIT.iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        v.push(Self::new(
            "md5_iv", "MD5 Initial Hash Values",
            CryptoAlgorithm::Md5, ConstantCategory::HashInitialValue,
            md5_iv_le, 85,
        ).with_notes("Shares first two words with SHA-1; look for nearby T-table for disambiguation"));

        // AES S-box head
        v.push(Self::new(
            "aes_sbox_head", "AES S-box (first 16 bytes)",
            CryptoAlgorithm::Aes, ConstantCategory::SubstitutionBox,
            AES_SBOX_HEAD.to_vec(), 90,
        ).with_notes("Start of the 256-byte AES forward S-box table"));

        // CRC-32 polynomial
        v.push(Self::new(
            "crc32_poly", "CRC-32 Polynomial",
            CryptoAlgorithm::Crc32, ConstantCategory::ChecksumPolynomial,
            CRC32_POLY.to_le_bytes().to_vec(), 80,
        ));

        // TEA delta
        v.push(Self::new(
            "tea_delta", "TEA/XTEA Delta Constant 0x9e3779b9",
            CryptoAlgorithm::Tea, ConstantCategory::BlockCipherConstant,
            TEA_DELTA.to_le_bytes().to_vec(), 75,
        ).with_notes("Derived from the golden ratio"));

        // DES S-box 1 head
        v.push(Self::new(
            "des_sbox1", "DES S-box 1 (first 8 entries)",
            CryptoAlgorithm::Des, ConstantCategory::SubstitutionBox,
            DES_SBOX1_HEAD.to_vec(), 70,
        ));

        v
    }
}

// ── ConstantMatch ─────────────────────────────────────────────────────────────

/// A match found in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstantMatch {
    /// Pattern that matched.
    pub pattern_id: String,
    /// Algorithm associated with the match.
    pub algorithm: CryptoAlgorithm,
    /// Category.
    pub category: ConstantCategory,
    /// Address in the binary where the match starts.
    pub address: u64,
    /// Length of the matched sequence.
    pub match_length: usize,
    /// Whether the full pattern matched (vs partial).
    pub is_full_match: bool,
    /// Endianness of the match.
    pub endian: Endian,
    /// Confidence score (0–100).
    pub confidence: u8,
    /// Pattern name.
    pub pattern_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endian {
    Little,
    Big,
}

impl ConstantMatch {
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} ({}) at 0x{:016x} — {} {} match, confidence {}%",
            self.pattern_name,
            self.algorithm.display_name(),
            self.address,
            if self.is_full_match { "full" } else { "partial" },
            match self.endian { Endian::Little => "LE", Endian::Big => "BE" },
            self.confidence,
        )
    }

    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 75
    }
}

// ── Finder ────────────────────────────────────────────────────────────────────

/// Searches binary data for known cryptographic constants.
#[derive(Debug)]
pub struct CryptoConstantFinder {
    patterns: Vec<ConstantPattern>,
    matches: Vec<ConstantMatch>,
    stats: FinderStats,
    min_confidence: u8,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FinderStats {
    pub bytes_scanned: u64,
    pub patterns_checked: u64,
    pub full_matches: u32,
    pub partial_matches: u32,
    pub unique_algorithms: u32,
}

impl CryptoConstantFinder {
    /// Create a finder pre-loaded with all built-in patterns.
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: ConstantPattern::builtin_patterns(),
            matches: Vec::new(),
            stats: FinderStats::default(),
            min_confidence: 60,
        }
    }

    /// Create a finder with no pre-loaded patterns.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            patterns: Vec::new(),
            matches: Vec::new(),
            stats: FinderStats::default(),
            min_confidence: 60,
        }
    }

    pub fn add_pattern(&mut self, pattern: ConstantPattern) {
        self.patterns.push(pattern);
    }

    pub const fn set_min_confidence(&mut self, c: u8) {
        self.min_confidence = c;
    }

    /// Scan a binary image. `base_address` is the load address of `data[0]`.
    pub fn scan(&mut self, data: &[u8], base_address: u64) {
        self.stats.bytes_scanned += data.len() as u64;

        let patterns = self.patterns.clone();
        for pattern in &patterns {
            self.stats.patterns_checked += 1;

            // Try little-endian match
            self.search_pattern(data, base_address, pattern, &pattern.bytes_le, Endian::Little);

            // Try big-endian match if available
            if let Some(be) = &pattern.bytes_be {
                let be_clone = be.clone();
                self.search_pattern(data, base_address, pattern, &be_clone, Endian::Big);
            }
        }

        // Update unique algorithm count
        let alg_set: std::collections::HashSet<String> = self.matches.iter()
            .map(|m| m.algorithm.display_name().to_string())
            .collect();
        self.stats.unique_algorithms = u32::try_from(alg_set.len()).unwrap_or(u32::MAX);
    }

    fn search_pattern(
        &mut self,
        data: &[u8],
        base_address: u64,
        pattern: &ConstantPattern,
        needle: &[u8],
        endian: Endian,
    ) {
        if needle.len() < pattern.min_match_len {
            return;
        }

        let mut offset = 0usize;
        while offset + pattern.min_match_len <= data.len() {
            // Try full match first
            if offset + needle.len() <= data.len()
                && data[offset..offset + needle.len()] == *needle
            {
                let confidence = pattern.full_match_confidence;
                if confidence >= self.min_confidence {
                    let addr = base_address + offset as u64;
                    if !self.already_recorded(addr, &pattern.id) {
                        self.stats.full_matches += 1;
                        self.matches.push(ConstantMatch {
                            pattern_id: pattern.id.clone(),
                            algorithm: pattern.algorithm.clone(),
                            category: pattern.category.clone(),
                            address: addr,
                            match_length: needle.len(),
                            is_full_match: true,
                            endian,
                            confidence,
                            pattern_name: pattern.name.clone(),
                        });
                    }
                    offset += needle.len();
                    continue;
                }
            }

            // Try partial match (min_match_len prefix)
            let partial = &needle[..pattern.min_match_len];
            if data[offset..offset + partial.len()] == *partial {
                let confidence = u8::try_from(u32::from(pattern.full_match_confidence) * 60 / 100).unwrap_or(u8::MAX);
                if confidence >= self.min_confidence {
                    let addr = base_address + offset as u64;
                    if !self.already_recorded(addr, &pattern.id) {
                        self.stats.partial_matches += 1;
                        self.matches.push(ConstantMatch {
                            pattern_id: pattern.id.clone(),
                            algorithm: pattern.algorithm.clone(),
                            category: pattern.category.clone(),
                            address: addr,
                            match_length: partial.len(),
                            is_full_match: false,
                            endian,
                            confidence,
                            pattern_name: pattern.name.clone(),
                        });
                    }
                }
            }

            offset += 1;
        }
    }

    fn already_recorded(&self, addr: u64, pattern_id: &str) -> bool {
        self.matches.iter().any(|m| m.address == addr && m.pattern_id == pattern_id)
    }

    #[must_use]
    pub fn matches(&self) -> &[ConstantMatch] {
        &self.matches
    }

    #[must_use]
    pub fn high_confidence_matches(&self) -> Vec<&ConstantMatch> {
        self.matches.iter().filter(|m| m.is_high_confidence()).collect()
    }

    /// Group matches by algorithm.
    #[must_use]
    pub fn by_algorithm(&self) -> HashMap<String, Vec<&ConstantMatch>> {
        let mut map: HashMap<String, Vec<&ConstantMatch>> = HashMap::new();
        for m in &self.matches {
            map.entry(m.algorithm.display_name().to_string())
               .or_default()
               .push(m);
        }
        map
    }

    /// Group matches by category.
    #[must_use]
    pub fn by_category(&self) -> HashMap<String, Vec<&ConstantMatch>> {
        let mut map: HashMap<String, Vec<&ConstantMatch>> = HashMap::new();
        for m in &self.matches {
            map.entry(m.category.display_name().to_string())
               .or_default()
               .push(m);
        }
        map
    }

    /// Return matches for a specific algorithm.
    #[must_use]
    pub fn for_algorithm(&self, alg: &CryptoAlgorithm) -> Vec<&ConstantMatch> {
        self.matches.iter().filter(|m| &m.algorithm == alg).collect()
    }

    #[must_use]
    pub const fn stats(&self) -> &FinderStats {
        &self.stats
    }

    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    pub fn clear_matches(&mut self) {
        self.matches.clear();
        self.stats = FinderStats::default();
    }

    /// Generate a human-readable summary report.
    #[must_use]
    pub fn report(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "Crypto Constant Finder — {} bytes scanned, {} patterns",
            self.stats.bytes_scanned,
            self.patterns.len(),
        ));
        lines.push(format!(
            "  Full matches: {}  Partial: {}  Unique algorithms: {}",
            self.stats.full_matches,
            self.stats.partial_matches,
            self.stats.unique_algorithms,
        ));

        let by_alg = self.by_algorithm();
        let mut alg_names: Vec<&String> = by_alg.keys().collect();
        alg_names.sort();
        for alg in alg_names {
            let ms = &by_alg[alg];
            lines.push(format!("  {alg}:"));
            for m in ms {
                lines.push(format!("    {}", m.summary()));
            }
        }

        lines.join("\n")
    }
}

impl Default for CryptoConstantFinder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Utility: build a binary blob containing a known constant ─────────────────

/// Build a test blob containing the SHA-256 IV at a given offset.
#[must_use]
pub fn test_blob_with_sha256_iv(offset: usize) -> Vec<u8> {
    let iv_bytes: Vec<u8> = SHA256_INIT.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut blob = vec![0xABu8; offset + iv_bytes.len() + 8];
    blob[offset..offset + iv_bytes.len()].copy_from_slice(&iv_bytes);
    blob
}

/// Build a test blob containing the SHA-1 IV at a given offset.
#[must_use]
pub fn test_blob_with_sha1_iv(offset: usize) -> Vec<u8> {
    let iv_bytes: Vec<u8> = SHA1_INIT.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut blob = vec![0xCDu8; offset + iv_bytes.len() + 8];
    blob[offset..offset + iv_bytes.len()].copy_from_slice(&iv_bytes);
    blob
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_iv_length() {
        assert_eq!(SHA256_INIT.len(), 8);
    }

    #[test]
    fn test_sha1_iv_length() {
        assert_eq!(SHA1_INIT.len(), 5);
    }

    #[test]
    fn test_sha1_k_length() {
        assert_eq!(SHA1_K.len(), 4);
    }

    #[test]
    fn test_builtin_patterns_non_empty() {
        let patterns = ConstantPattern::builtin_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.len() >= 6);
    }

    #[test]
    fn test_builtin_pattern_ids_unique() {
        let patterns = ConstantPattern::builtin_patterns();
        let ids: std::collections::HashSet<&str> = patterns.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids.len(), patterns.len(), "pattern IDs must be unique");
    }

    #[test]
    fn test_finder_has_builtin_patterns() {
        let f = CryptoConstantFinder::new();
        assert!(f.pattern_count() >= 6);
    }

    #[test]
    fn test_finder_empty_scan() {
        let mut f = CryptoConstantFinder::new();
        f.scan(&[], 0);
        assert_eq!(f.matches().len(), 0);
    }

    #[test]
    fn test_finder_detects_sha256_iv_le() {
        let blob = test_blob_with_sha256_iv(0);
        let mut f = CryptoConstantFinder::new();
        f.scan(&blob, 0x0040_0000);
        let sha_matches = f.for_algorithm(&CryptoAlgorithm::Sha256);
        assert!(!sha_matches.is_empty(), "should detect SHA-256 IV");
        assert!(sha_matches.iter().any(|m| m.is_full_match));
    }

    #[test]
    fn test_finder_detects_sha256_iv_at_offset() {
        let blob = test_blob_with_sha256_iv(32);
        let mut f = CryptoConstantFinder::new();
        f.scan(&blob, 0x1000);
        let sha_matches = f.for_algorithm(&CryptoAlgorithm::Sha256);
        assert!(!sha_matches.is_empty());
        assert!(sha_matches.iter().any(|m| m.address == 0x1020));
    }

    #[test]
    fn test_finder_detects_sha1_iv() {
        let blob = test_blob_with_sha1_iv(8);
        let mut f = CryptoConstantFinder::new();
        f.scan(&blob, 0);
        let sha1_matches = f.for_algorithm(&CryptoAlgorithm::Sha1);
        assert!(!sha1_matches.is_empty(), "should detect SHA-1 IV");
    }

    #[test]
    fn test_finder_no_false_positive_on_zeros() {
        let blob = vec![0u8; 256];
        let mut f = CryptoConstantFinder::new();
        f.scan(&blob, 0);
        // SHA-256 IV contains non-zero values, so no matches expected
        assert!(f.for_algorithm(&CryptoAlgorithm::Sha256).is_empty());
    }

    #[test]
    fn test_finder_by_algorithm_grouping() {
        let blob = test_blob_with_sha256_iv(0);
        let mut f = CryptoConstantFinder::new();
        f.scan(&blob, 0);
        let by_alg = f.by_algorithm();
        assert!(by_alg.contains_key("SHA-256"));
    }

    #[test]
    fn test_finder_by_category_grouping() {
        let blob = test_blob_with_sha256_iv(0);
        let mut f = CryptoConstantFinder::new();
        f.scan(&blob, 0);
        let by_cat = f.by_category();
        assert!(by_cat.contains_key("Hash IV") || by_cat.contains_key("Hash Round Constant"));
    }

    #[test]
    fn test_finder_clear_matches() {
        let blob = test_blob_with_sha256_iv(0);
        let mut f = CryptoConstantFinder::new();
        f.scan(&blob, 0);
        assert!(!f.matches().is_empty());
        f.clear_matches();
        assert!(f.matches().is_empty());
    }

    #[test]
    fn test_finder_stats_update() {
        let blob = test_blob_with_sha256_iv(0);
        let mut f = CryptoConstantFinder::new();
        f.scan(&blob, 0);
        assert_eq!(f.stats().bytes_scanned, blob.len() as u64);
        assert!(f.stats().patterns_checked > 0);
    }

    #[test]
    fn test_constant_match_summary() {
        let m = ConstantMatch {
            pattern_id: "sha256_iv".into(),
            algorithm: CryptoAlgorithm::Sha256,
            category: ConstantCategory::HashInitialValue,
            address: 0x5000,
            match_length: 32,
            is_full_match: true,
            endian: Endian::Little,
            confidence: 95,
            pattern_name: "SHA-256 Initial Hash Values".into(),
        };
        let s = m.summary();
        assert!(s.contains("SHA-256"));
        assert!(s.contains("full"));
        assert!(s.contains("95%"));
    }

    #[test]
    fn test_constant_match_high_confidence() {
        let m = ConstantMatch {
            pattern_id: "p".into(),
            algorithm: CryptoAlgorithm::Aes,
            category: ConstantCategory::SubstitutionBox,
            address: 0,
            match_length: 16,
            is_full_match: true,
            endian: Endian::Little,
            confidence: 90,
            pattern_name: "AES S-box".into(),
        };
        assert!(m.is_high_confidence());
    }

    #[test]
    fn test_constant_match_low_confidence() {
        let m = ConstantMatch {
            pattern_id: "p".into(),
            algorithm: CryptoAlgorithm::Des,
            category: ConstantCategory::SubstitutionBox,
            address: 0,
            match_length: 4,
            is_full_match: false,
            endian: Endian::Big,
            confidence: 50,
            pattern_name: "DES S-box 1".into(),
        };
        assert!(!m.is_high_confidence());
    }
}
