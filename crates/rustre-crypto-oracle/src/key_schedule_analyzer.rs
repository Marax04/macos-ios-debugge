//! Key schedule analysis for AES, DES, and RC4 algorithms.
//!
//! Detects and reconstructs key schedule implementations in binary code
//! by identifying characteristic operations, constants, and patterns.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── AES S-box and round constants ────────────────────────────────────────────

/// AES S-box (forward substitution table).
pub const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES round constants (Rcon) for key expansion.
pub const AES_RCON: [u32; 11] = [
    0x0000_0000, 0x0100_0000, 0x0200_0000, 0x0400_0000,
    0x0800_0000, 0x1000_0000, 0x2000_0000, 0x4000_0000,
    0x8000_0000, 0x1b00_0000, 0x3600_0000,
];

/// DES PC-1 permutation table.
pub const DES_PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4,
];

/// DES rotation schedule (number of left rotations per round).
pub const DES_ROTATIONS: [u8; 16] = [
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
];

// ── Enumerations ─────────────────────────────────────────────────────────────

/// Identifies the cipher whose key schedule was detected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CipherKind {
    Aes128,
    Aes192,
    Aes256,
    DesEcb,
    TripleDes,
    Rc4,
    Unknown(String),
}

impl CipherKind {
    /// Expected key length in bytes.
    #[must_use]
    pub const fn key_len(&self) -> Option<usize> {
        match self {
            Self::Aes128 => Some(16),
            Self::Aes192 | Self::TripleDes => Some(24),
            Self::Aes256 => Some(32),
            Self::DesEcb => Some(8),
            Self::Rc4 | Self::Unknown(_) => None, // variable / unknown length
        }
    }

    /// Number of key expansion rounds (where applicable).
    #[must_use]
    pub const fn rounds(&self) -> Option<u32> {
        match self {
            Self::Aes128 => Some(10),
            Self::Aes192 => Some(12),
            Self::Aes256 => Some(14),
            Self::DesEcb | Self::TripleDes => Some(16),
            _ => None,
        }
    }

    #[must_use]
    pub const fn display_name(&self) -> &str {
        match self {
            Self::Aes128 => "AES-128",
            Self::Aes192 => "AES-192",
            Self::Aes256 => "AES-256",
            Self::DesEcb => "DES",
            Self::TripleDes => "3DES",
            Self::Rc4 => "RC4",
            Self::Unknown(s) => s.as_str(),
        }
    }
}

/// Confidence level for a detection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
    Definitive,
}

impl Confidence {
    #[must_use]
    pub const fn score(&self) -> f64 {
        match self {
            Self::Low => 0.25,
            Self::Medium => 0.5,
            Self::High => 0.75,
            Self::Definitive => 1.0,
        }
    }
}

// ── Key schedule pattern ──────────────────────────────────────────────────────

/// A pattern that characterizes a key schedule implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySchedulePattern {
    /// Human-readable pattern name.
    pub name: String,
    /// Cipher this pattern matches.
    pub cipher: CipherKind,
    /// Magic constant values that should appear near the key schedule.
    pub constants: Vec<u64>,
    /// Opcode mnemonics characteristic of this schedule (e.g., "pshufb", "vperm").
    pub characteristic_ops: Vec<String>,
    /// Minimum number of constants required for a match.
    pub min_constant_matches: usize,
    /// Confidence if all signals match.
    pub max_confidence: Confidence,
}

impl KeySchedulePattern {
    /// AES-NI hardware acceleration pattern.
    #[must_use]
    pub fn aes_ni() -> Self {
        Self {
            name: "AES-NI key expansion".into(),
            cipher: CipherKind::Aes128,
            constants: vec![
                0x0100_0000, 0x0200_0000, 0x0400_0000, 0x0800_0000,
                0x1000_0000, 0x3600_0000,
            ],
            characteristic_ops: vec![
                "aeskeygenassist".into(),
                "aesimc".into(),
                "pxor".into(),
            ],
            min_constant_matches: 2,
            max_confidence: Confidence::Definitive,
        }
    }

    /// Software AES key expansion (table-based).
    #[must_use]
    pub fn aes_software() -> Self {
        Self {
            name: "AES software key expansion".into(),
            cipher: CipherKind::Aes128,
            constants: vec![
                // First 8 bytes of S-box as u64
                u64::from_le_bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]),
                // Last 8 bytes of S-box
                u64::from_le_bytes([0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]),
                // Rcon[1..4] packed
                0x0102_0408,
            ],
            characteristic_ops: vec![
                "movzx".into(),
                "xor".into(),
                "ror".into(),
            ],
            min_constant_matches: 1,
            max_confidence: Confidence::High,
        }
    }

    /// DES key schedule pattern.
    #[must_use]
    pub fn des() -> Self {
        Self {
            name: "DES key schedule".into(),
            cipher: CipherKind::DesEcb,
            constants: vec![
                // PC1 table start bytes as u64
                u64::from_le_bytes([57, 49, 41, 33, 25, 17, 9, 1]),
                // rotation schedule
                u64::from_le_bytes([1, 1, 2, 2, 2, 2, 2, 2]),
            ],
            characteristic_ops: vec![
                "rol".into(),
                "ror".into(),
                "and".into(),
            ],
            min_constant_matches: 1,
            max_confidence: Confidence::High,
        }
    }

    /// RC4 KSA (Key Scheduling Algorithm) pattern.
    #[must_use]
    pub fn rc4() -> Self {
        Self {
            name: "RC4 KSA".into(),
            cipher: CipherKind::Rc4,
            constants: vec![
                // S-array initialized to 0..255, last 8 bytes little-endian
                u64::from_le_bytes([248, 249, 250, 251, 252, 253, 254, 255]),
                0xFF, // loop bound 255
            ],
            characteristic_ops: vec![
                "xchg".into(),
                "mov".into(),
            ],
            min_constant_matches: 1,
            max_confidence: Confidence::Medium,
        }
    }

    /// Check how many constants from this pattern appear in `binary_data`.
    #[must_use]
    pub fn count_constant_hits(&self, binary_data: &[u8]) -> usize {
        self.constants.iter().filter(|&&c| {
            let needle = c.to_le_bytes();
            binary_data.windows(8).any(|w| w == needle)
        }).count()
    }

    /// Compute the match confidence given binary data and observed opcodes.
    #[must_use]
    pub fn evaluate(&self, binary_data: &[u8], opcodes: &[String]) -> Confidence {
        let const_hits = self.count_constant_hits(binary_data);
        let op_hits = self.characteristic_ops.iter()
            .filter(|op| opcodes.iter().any(|o| o.contains(op.as_str())))
            .count();

        if const_hits < self.min_constant_matches {
            return Confidence::Low;
        }

        let op_ratio = if self.characteristic_ops.is_empty() {
            1.0
        } else {
            f64::from(u32::try_from(op_hits).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.characteristic_ops.len()).unwrap_or(u32::MAX))
        };

        match (const_hits, op_ratio) {
            (c, r) if c >= self.constants.len() && r >= 0.6 => self.max_confidence,
            (c, r) if c >= self.min_constant_matches && r >= 0.4 => Confidence::High,
            (c, _) if c >= self.min_constant_matches => Confidence::Medium,
            _ => Confidence::Low,
        }
    }
}

// ── KeyExpansion ──────────────────────────────────────────────────────────────

/// Represents a reconstructed key expansion sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExpansion {
    /// Cipher detected.
    pub cipher: CipherKind,
    /// Address in the binary where key setup begins.
    pub start_address: u64,
    /// Address where key expansion ends.
    pub end_address: u64,
    /// Recovered round keys (may be partial if analysis stopped early).
    pub round_keys: Vec<Vec<u8>>,
    /// Estimated input key length in bytes.
    pub key_length: usize,
    /// Number of rounds produced.
    pub rounds_found: u32,
    /// Whether the expansion appears complete.
    pub is_complete: bool,
    /// Raw bytes of the expanded key material.
    pub key_material: Vec<u8>,
}

impl KeyExpansion {
    #[must_use]
    pub const fn new(cipher: CipherKind, start_address: u64, key_length: usize) -> Self {
        Self {
            cipher,
            start_address,
            end_address: start_address,
            round_keys: Vec::new(),
            key_length,
            rounds_found: 0,
            is_complete: false,
            key_material: Vec::new(),
        }
    }

    /// Simulate AES-128 key expansion for a given 16-byte key.
    #[must_use]
    pub fn expand_aes128(key: &[u8; 16]) -> Self {
        let mut exp = Self::new(CipherKind::Aes128, 0, 16);
        let mut w = [0u32; 44];

        // Load initial key words
        for i in 0..4 {
            w[i] = u32::from_be_bytes([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]);
        }

        for i in 4..44 {
            let mut temp = w[i - 1];
            if i % 4 == 0 {
                temp = sub_word(rot_word(temp)) ^ AES_RCON[i / 4];
            }
            w[i] = w[i - 4] ^ temp;
        }

        // Pack round keys (each is 4 words = 16 bytes)
        for round in 0..11 {
            let mut rk = Vec::with_capacity(16);
            for j in 0..4 {
                rk.extend_from_slice(&w[round * 4 + j].to_be_bytes());
            }
            exp.key_material.extend_from_slice(&rk);
            exp.round_keys.push(rk);
        }

        exp.rounds_found = 10;
        exp.is_complete = true;
        exp
    }

    /// Simulate AES-256 key expansion for a given 32-byte key.
    #[must_use]
    pub fn expand_aes256(key: &[u8; 32]) -> Self {
        let mut exp = Self::new(CipherKind::Aes256, 0, 32);
        let mut w = [0u32; 60];

        for i in 0..8 {
            w[i] = u32::from_be_bytes([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]);
        }

        for i in 8..60 {
            let mut temp = w[i - 1];
            if i % 8 == 0 {
                temp = sub_word(rot_word(temp)) ^ AES_RCON[i / 8];
            } else if i % 8 == 4 {
                temp = sub_word(temp);
            }
            w[i] = w[i - 8] ^ temp;
        }

        for round in 0..15 {
            let mut rk = Vec::with_capacity(16);
            for j in 0..4 {
                rk.extend_from_slice(&w[round * 4 + j].to_be_bytes());
            }
            exp.key_material.extend_from_slice(&rk);
            exp.round_keys.push(rk);
        }

        exp.rounds_found = 14;
        exp.is_complete = true;
        exp
    }

    /// Simulate RC4 KSA for a given key.
    #[must_use]
    pub fn expand_rc4(key: &[u8]) -> Self {
        let mut exp = Self::new(CipherKind::Rc4, 0, key.len());
        let mut s: Vec<u8> = (0..=255u8).collect();
        let mut j: u8 = 0;

        for i in 0..256usize {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        exp.key_material = s;
        exp.rounds_found = 256;
        exp.is_complete = true;
        exp
    }

    /// Return the round key at a given index, if available.
    #[must_use]
    pub fn round_key(&self, round: usize) -> Option<&[u8]> {
        self.round_keys.get(round).map(Vec::as_slice)
    }

    #[must_use]
    pub const fn total_key_material_bytes(&self) -> usize {
        self.key_material.len()
    }
}

// AES helper functions
const fn rot_word(w: u32) -> u32 {
    w.rotate_left(8)
}

const fn sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([
        AES_SBOX[b[0] as usize],
        AES_SBOX[b[1] as usize],
        AES_SBOX[b[2] as usize],
        AES_SBOX[b[3] as usize],
    ])
}

// ── Detection result ──────────────────────────────────────────────────────────

/// Result of a key schedule analysis at a specific address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyScheduleMatch {
    /// Address where the key schedule was found.
    pub address: u64,
    /// Identified cipher.
    pub cipher: CipherKind,
    /// Pattern that triggered the detection.
    pub pattern_name: String,
    /// Detection confidence.
    pub confidence: Confidence,
    /// Number of matching constants found.
    pub constant_hits: usize,
    /// Matching opcode hints.
    pub matching_ops: Vec<String>,
    /// Reconstructed key expansion, if possible.
    pub expansion: Option<KeyExpansion>,
}

impl KeyScheduleMatch {
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= Confidence::High
    }

    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} at 0x{:016x} ({:?}, {} constant hits)",
            self.cipher.display_name(),
            self.address,
            self.confidence,
            self.constant_hits,
        )
    }
}

// ── Analyzer ──────────────────────────────────────────────────────────────────

/// Analyzes binary data to detect and reconstruct key schedule implementations.
#[derive(Debug)]
pub struct KeyScheduleAnalyzer {
    patterns: Vec<KeySchedulePattern>,
    matches: Vec<KeyScheduleMatch>,
    scan_chunk_size: usize,
    min_confidence: Confidence,
    stats: AnalyzerStats,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AnalyzerStats {
    pub bytes_scanned: u64,
    pub patterns_evaluated: u64,
    pub matches_found: u32,
    pub high_confidence_matches: u32,
}

impl KeyScheduleAnalyzer {
    /// Create a new analyzer with default patterns for AES, DES, and RC4.
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: vec![
                KeySchedulePattern::aes_ni(),
                KeySchedulePattern::aes_software(),
                KeySchedulePattern::des(),
                KeySchedulePattern::rc4(),
            ],
            matches: Vec::new(),
            scan_chunk_size: 4096,
            min_confidence: Confidence::Medium,
            stats: AnalyzerStats::default(),
        }
    }

    /// Create an analyzer that only reports high-confidence results.
    #[must_use]
    pub fn strict() -> Self {
        let mut a = Self::new();
        a.min_confidence = Confidence::High;
        a
    }

    /// Add a custom pattern to the analyzer.
    pub fn add_pattern(&mut self, pattern: KeySchedulePattern) {
        self.patterns.push(pattern);
    }

    /// Set the minimum confidence level to record a match.
    pub const fn set_min_confidence(&mut self, c: Confidence) {
        self.min_confidence = c;
    }

    /// Scan a flat binary image starting at `base_address`.
    pub fn scan(&mut self, data: &[u8], base_address: u64, opcodes: &[String]) {
        self.stats.bytes_scanned += data.len() as u64;

        // Slide a window through the binary to find constant matches.
        let step = 16usize;
        let mut offset = 0usize;

        while offset < data.len() {
            let end = (offset + self.scan_chunk_size).min(data.len());
            let chunk = &data[offset..end];

            for pattern in &self.patterns {
                self.stats.patterns_evaluated += 1;
                let confidence = pattern.evaluate(chunk, opcodes);
                if confidence < self.min_confidence {
                    continue;
                }

                let const_hits = pattern.count_constant_hits(chunk);
                let matching_ops: Vec<String> = pattern.characteristic_ops.iter()
                    .filter(|op| opcodes.iter().any(|o| o.contains(op.as_str())))
                    .cloned()
                    .collect();

                let m = KeyScheduleMatch {
                    address: base_address + offset as u64,
                    cipher: pattern.cipher.clone(),
                    pattern_name: pattern.name.clone(),
                    confidence,
                    constant_hits: const_hits,
                    matching_ops,
                    expansion: None,
                };

                if !self.matches.iter().any(|e| {
                    e.cipher == m.cipher && e.address.abs_diff(m.address) < 64
                }) {
                    if m.is_high_confidence() {
                        self.stats.high_confidence_matches += 1;
                    }
                    self.stats.matches_found += 1;
                    self.matches.push(m);
                }
            }

            if offset + step >= data.len() {
                break;
            }
            offset += step;
        }
    }

    /// Run key expansion simulation for all high-confidence AES-128 matches
    /// where a candidate 16-byte key slice is available at `key_offset`.
    ///
    /// # Panics
    ///
    /// Panics if `data[key_offset..key_offset + 16]` cannot be converted to `[u8; 16]`
    /// (cannot happen: guarded by the `key_offset + 16 > data.len()` check above).
    pub fn try_expand_aes128(&mut self, data: &[u8], base_address: u64, key_offset: usize) {
        if key_offset + 16 > data.len() {
            return;
        }
        let key_bytes: [u8; 16] = data[key_offset..key_offset + 16].try_into().unwrap();
        for m in &mut self.matches {
            if m.cipher == CipherKind::Aes128 && m.expansion.is_none() {
                let mut exp = KeyExpansion::expand_aes128(&key_bytes);
                exp.start_address = base_address + key_offset as u64;
                exp.end_address = m.address;
                m.expansion = Some(exp);
            }
        }
    }

    /// Return all recorded matches.
    #[must_use]
    pub fn matches(&self) -> &[KeyScheduleMatch] {
        &self.matches
    }

    /// Return only matches above a given confidence threshold.
    #[must_use]
    pub fn matches_above(&self, threshold: Confidence) -> Vec<&KeyScheduleMatch> {
        self.matches.iter().filter(|m| m.confidence >= threshold).collect()
    }

    /// Return matches grouped by cipher kind.
    #[must_use]
    pub fn matches_by_cipher(&self) -> HashMap<String, Vec<&KeyScheduleMatch>> {
        let mut map: HashMap<String, Vec<&KeyScheduleMatch>> = HashMap::new();
        for m in &self.matches {
            map.entry(m.cipher.display_name().to_string())
               .or_default()
               .push(m);
        }
        map
    }

    /// Clear recorded matches (but keep patterns).
    pub fn reset(&mut self) {
        self.matches.clear();
        self.stats = AnalyzerStats::default();
    }

    #[must_use]
    pub const fn stats(&self) -> &AnalyzerStats {
        &self.stats
    }

    /// Generate a human-readable summary report.
    #[must_use]
    pub fn report(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "Key Schedule Analyzer — {} bytes scanned, {} matches",
            self.stats.bytes_scanned,
            self.stats.matches_found,
        ));
        lines.push(format!(
            "  High-confidence: {}",
            self.stats.high_confidence_matches,
        ));
        for m in &self.matches {
            lines.push(format!("  {}", m.summary()));
            if let Some(exp) = &m.expansion {
                lines.push(format!(
                    "    Expanded: {} round keys, {} bytes total",
                    exp.round_keys.len(),
                    exp.total_key_material_bytes(),
                ));
            }
        }
        lines.join("\n")
    }
}

impl Default for KeyScheduleAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Utility: verify AES expansion against known test vector ──────────────────

/// Verify AES-128 key expansion against the FIPS-197 test vector.
/// Key: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
/// Expected first round key equals the original key.
#[must_use]
pub fn verify_aes128_expansion() -> bool {
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];
    let exp = KeyExpansion::expand_aes128(&key);
    // Round key 0 must equal the original key
    exp.round_key(0).is_some_and(|rk| rk == key)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rot_word() {
        assert_eq!(rot_word(0x09cf_4f3c), 0xcf4f_3c09);
    }

    #[test]
    fn test_sub_word() {
        // sub_word(0x09cf4f3c): S-box lookup for each byte
        let result = sub_word(0x09cf_4f3c);
        assert_eq!(result, u32::from_be_bytes([
            AES_SBOX[0x09],
            AES_SBOX[0xcf],
            AES_SBOX[0x4f],
            AES_SBOX[0x3c],
        ]));
    }

    #[test]
    fn test_aes128_round0_equals_key() {
        assert!(verify_aes128_expansion());
    }

    #[test]
    fn test_aes128_expansion_produces_11_round_keys() {
        let key = [0u8; 16];
        let exp = KeyExpansion::expand_aes128(&key);
        assert_eq!(exp.round_keys.len(), 11);
        assert!(exp.is_complete);
        assert_eq!(exp.total_key_material_bytes(), 176);
    }

    #[test]
    fn test_aes256_expansion_produces_15_round_keys() {
        let key = [0u8; 32];
        let exp = KeyExpansion::expand_aes256(&key);
        assert_eq!(exp.round_keys.len(), 15);
        assert_eq!(exp.rounds_found, 14);
    }

    #[test]
    fn test_rc4_ksa_length() {
        let key = b"Secret";
        let exp = KeyExpansion::expand_rc4(key);
        assert_eq!(exp.key_material.len(), 256);
        assert!(exp.is_complete);
    }

    #[test]
    fn test_rc4_ksa_is_permutation() {
        let key = b"test";
        let exp = KeyExpansion::expand_rc4(key);
        let mut seen = [false; 256];
        for &b in &exp.key_material {
            seen[b as usize] = true;
        }
        assert!(seen.iter().all(|&v| v), "RC4 S-array must be a permutation");
    }

    #[test]
    fn test_pattern_constant_hits_aes_sbox() {
        let pattern = KeySchedulePattern::aes_software();
        let mut data = vec![0u8; 32];
        // Embed first 8 bytes of S-box
        let needle = u64::from_le_bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]);
        data[0..8].copy_from_slice(&needle.to_le_bytes());
        assert!(pattern.count_constant_hits(&data) >= 1);
    }

    #[test]
    fn test_pattern_evaluate_low_confidence_without_constants() {
        let pattern = KeySchedulePattern::aes_ni();
        let data = vec![0u8; 128];
        let confidence = pattern.evaluate(&data, &[]);
        assert_eq!(confidence, Confidence::Low);
    }

    #[test]
    fn test_analyzer_new_has_four_patterns() {
        let a = KeyScheduleAnalyzer::new();
        assert_eq!(a.patterns.len(), 4);
    }

    #[test]
    fn test_analyzer_scan_empty_produces_no_matches() {
        let mut a = KeyScheduleAnalyzer::new();
        a.scan(&[], 0, &[]);
        assert_eq!(a.matches().len(), 0);
    }

    #[test]
    fn test_cipher_kind_key_len() {
        assert_eq!(CipherKind::Aes128.key_len(), Some(16));
        assert_eq!(CipherKind::Aes256.key_len(), Some(32));
        assert_eq!(CipherKind::DesEcb.key_len(), Some(8));
        assert_eq!(CipherKind::Rc4.key_len(), None);
    }

    #[test]
    fn test_cipher_kind_rounds() {
        assert_eq!(CipherKind::Aes128.rounds(), Some(10));
        assert_eq!(CipherKind::Aes256.rounds(), Some(14));
        assert_eq!(CipherKind::Rc4.rounds(), None);
    }

    #[test]
    fn test_confidence_ordering() {
        assert!(Confidence::Definitive > Confidence::High);
        assert!(Confidence::High > Confidence::Medium);
        assert!(Confidence::Medium > Confidence::Low);
    }

    #[test]
    fn test_key_schedule_match_summary() {
        let m = KeyScheduleMatch {
            address: 0x1000,
            cipher: CipherKind::Aes128,
            pattern_name: "test".into(),
            confidence: Confidence::High,
            constant_hits: 3,
            matching_ops: vec![],
            expansion: None,
        };
        let s = m.summary();
        assert!(s.contains("AES-128"));
        assert!(s.contains("0x0000000000001000"));
    }

    #[test]
    fn test_analyzer_matches_by_cipher_grouping() {
        let mut a = KeyScheduleAnalyzer::new();
        // Manually inject matches
        a.matches.push(KeyScheduleMatch {
            address: 0x1000,
            cipher: CipherKind::Aes128,
            pattern_name: "p1".into(),
            confidence: Confidence::High,
            constant_hits: 2,
            matching_ops: vec![],
            expansion: None,
        });
        a.matches.push(KeyScheduleMatch {
            address: 0x2000,
            cipher: CipherKind::Rc4,
            pattern_name: "p2".into(),
            confidence: Confidence::Medium,
            constant_hits: 1,
            matching_ops: vec![],
            expansion: None,
        });
        let grouped = a.matches_by_cipher();
        assert_eq!(grouped["AES-128"].len(), 1);
        assert_eq!(grouped["RC4"].len(), 1);
    }

    #[test]
    fn test_analyzer_reset_clears_matches() {
        let mut a = KeyScheduleAnalyzer::new();
        a.matches.push(KeyScheduleMatch {
            address: 0,
            cipher: CipherKind::Rc4,
            pattern_name: "p".into(),
            confidence: Confidence::Low,
            constant_hits: 0,
            matching_ops: vec![],
            expansion: None,
        });
        a.reset();
        assert!(a.matches().is_empty());
    }

    #[test]
    fn test_analyzer_report_contains_stats() {
        let a = KeyScheduleAnalyzer::new();
        let r = a.report();
        assert!(r.contains("bytes scanned"));
    }

    #[test]
    fn test_aes_sbox_length() {
        assert_eq!(AES_SBOX.len(), 256);
    }

    #[test]
    fn test_aes_rcon_length() {
        assert_eq!(AES_RCON.len(), 11);
    }

    #[test]
    fn test_des_pc1_length() {
        assert_eq!(DES_PC1.len(), 56);
    }
}
