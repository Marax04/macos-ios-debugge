//! White-box AES analyzer: Chow/Karroumi encoding table detection, T-box
//! recovery, and statistical analysis of table distributions.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use rayon::prelude::*;

use crate::{AES_SBOX, AES_SBOX_INV, LookupTable, TablePurpose};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Expected byte frequency in a uniform 256-entry table: each value appears once.
const UNIFORM_FREQ: f64 = 1.0 / 256.0;

/// Standard AES `MixColumns` multiplication constants.
const GF_MUL2_TABLE: [u8; 256] = build_gf2_table();
const GF_MUL3_TABLE: [u8; 256] = build_gf3_table();

const fn build_gf2_table() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let a = i.to_le_bytes()[0];
        let hi = a & 0x80;
        let shifted = a << 1;
        t[i] = if hi != 0 { shifted ^ 0x1b } else { shifted };
        i += 1;
    }
    t
}

const fn build_gf3_table() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let a = i.to_le_bytes()[0];
        let hi = a & 0x80;
        let x2 = if hi != 0 { (a << 1) ^ 0x1b } else { a << 1 };
        t[i] = x2 ^ a;
        i += 1;
    }
    t
}

// ─── Encoding types ───────────────────────────────────────────────────────────

/// Type of white-box encoding detected in a T-box or T-table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WbEncoding {
    /// Chow et al. (2002) white-box AES with XOR-based external encodings.
    Chow,
    /// Karroumi (2010) dual-cipher white-box construction.
    Karroumi,
    /// Bringer, Chabanne, Dottax (2006) using randomized T-tables.
    Bcd,
    /// Unknown or unclassified encoding.
    Unknown,
}

impl std::fmt::Display for WbEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Chow => write!(f, "Chow"),
            Self::Karroumi => write!(f, "Karroumi"),
            Self::Bcd => write!(f, "BCD"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─── T-box representation ─────────────────────────────────────────────────────

/// A single decoded T-box entry (8→32 bit table used in Chow's construction).
///
/// In Chow's implementation the T-boxes are combined with `MixColumns` coefficients:
///   `Tbox_i(x) = MixCol_i(SBox(x ⊕ k_i))`
/// where the outer and inner encodings are bijective 8-bit functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TBoxEntry {
    /// Index of this T-box (0–3 for round 1, repeated for each round).
    pub box_index: usize,
    /// Round number (0-based).
    pub round: usize,
    /// 256-entry table data (one 32-bit word per input byte).
    pub table: Vec<u32>,
    /// Detected encoding type.
    pub encoding: WbEncoding,
    /// Estimated XOR key material embedded in this T-box.
    pub key_candidate: Option<u8>,
    /// Chi-squared statistic for distribution uniformity.
    pub chi_squared: f64,
    /// Whether this T-box passes the bijectivity test.
    pub is_bijective: bool,
}

impl TBoxEntry {
    /// Create a new T-box entry from 256 u32 words.
    #[must_use]
    pub fn new(box_index: usize, round: usize, table: Vec<u32>) -> Self {
        let chi_squared = chi_squared_uniformity_u32(&table);
        let is_bijective = {
            let bytes: Vec<u8> = table.iter().map(|&w| (w & 0xff) as u8).collect();
            is_permutation_bytes(&bytes)
        };
        Self {
            box_index,
            round,
            table,
            encoding: WbEncoding::Unknown,
            key_candidate: None,
            chi_squared,
            is_bijective,
        }
    }

    /// Extract the XOR encoding key candidate by comparing LSB column to AES S-box.
    #[must_use]
    pub fn extract_key_candidate(&self) -> Option<u8> {
        if self.table.len() != 256 {
            return None;
        }
        let mut score_map: HashMap<u8, usize> = HashMap::new();
        for (i, &word) in self.table.iter().enumerate() {
            let lsb = (word & 0xff) as u8;
            let sbox_out = AES_SBOX[i];
            let xor_k = lsb ^ sbox_out;
            *score_map.entry(xor_k).or_insert(0) += 1;
        }
        score_map.into_iter().max_by_key(|(_, cnt)| *cnt).map(|(k, _)| k)
    }

    /// Compute byte-column distribution entropy (0..8 bits).
    ///
    /// # Panics
    ///
    /// Panics if `byte_col >= 4`.
    #[must_use]
    pub fn column_entropy(&self, byte_col: usize) -> f64 {
        assert!(byte_col < 4, "byte_col must be 0–3");
        let mut freq = [0u32; 256];
        for &word in &self.table {
            let byte = ((word >> (byte_col * 8)) & 0xff) as usize;
            freq[byte] += 1;
        }
        shannon_entropy_u32(&freq, self.table.len())
    }
}

// ─── Chow encoding detector ───────────────────────────────────────────────────

/// Detector for Chow et al. (2002) white-box AES encoding tables.
///
/// Chow's construction replaces each T-table lookup with a two-layer encoded
/// lookup: an inner bijective encoding on the input followed by an outer
/// encoding on the output. The 16 T-boxes per round are 256-entry u32 tables.
#[derive(Debug)]
pub struct ChowEncodingDetector {
    /// Tolerance for chi-squared deviation (higher = more permissive).
    pub chi_threshold: f64,
    /// Minimum bijectivity score (0–1) to accept a T-box candidate.
    pub min_bijective_ratio: f64,
    /// Whether to use parallel scanning.
    pub parallel: bool,
}

impl Default for ChowEncodingDetector {
    fn default() -> Self {
        Self {
            chi_threshold: 400.0,
            min_bijective_ratio: 0.9,
            parallel: true,
        }
    }
}

/// Cap offsets to avoid OOM when an attacker supplies a very large binary.
const MAX_SCAN_OFFSETS: usize = 4_000_000;

impl ChowEncodingDetector {
    /// Create a detector with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan a binary and detect all candidate Chow T-boxes.
    ///
    /// Returns a list of detected T-box candidates sorted by offset.
    #[must_use]
    pub fn scan(&self, binary: &[u8]) -> Vec<TBoxCandidate> {
        if binary.len() < 1024 {
            return vec![];
        }
        let limit = binary.len() - 1024;
        let offsets: Vec<usize> = (0..=limit).step_by(4).take(MAX_SCAN_OFFSETS).collect();

        let scan_fn = |&off: &usize| -> Option<TBoxCandidate> {
            self.probe_tbox(binary, off)
        };

        if self.parallel {
            offsets.par_iter().filter_map(scan_fn).collect()
        } else {
            offsets.iter().filter_map(scan_fn).collect()
        }
    }

    /// Probe a single 1-KiB window for a valid T-box.
    fn probe_tbox(&self, binary: &[u8], offset: usize) -> Option<TBoxCandidate> {
        if offset + 1024 > binary.len() {
            return None;
        }
        let mut words = [0u32; 256];
        for (i, w) in words.iter_mut().enumerate() {
            let b = &binary[offset + i * 4..offset + i * 4 + 4];
            *w = u32::from_le_bytes(b.try_into().ok()?);
        }
        // Extract byte columns
        let col0: Vec<u8> = words.iter().map(|&w| (w & 0xff) as u8).collect();
        let col1: Vec<u8> = words.iter().map(|&w| ((w >> 8) & 0xff) as u8).collect();

        // Check bijectivity on at least one column
        let bij0 = is_permutation_bytes(&col0);
        let bij1 = is_permutation_bytes(&col1);
        if !bij0 && !bij1 {
            return None;
        }

        // Check distribution uniformity via chi-squared
        let chi = chi_squared_uniformity_u32(&words);
        if chi > self.chi_threshold * 100.0 {
            return None;
        }

        // Detect encoding type
        let encoding = Self::classify_encoding(&words);

        // Extract key candidate from column 0
        let key_candidate = if bij0 {
            let mut vote: HashMap<u8, usize> = HashMap::new();
            for (i, &b) in col0.iter().enumerate() {
                let xk = b ^ AES_SBOX[i];
                *vote.entry(xk).or_insert(0) += 1;
            }
            vote.into_iter().max_by_key(|(_, c)| *c).map(|(k, _)| k)
        } else {
            None
        };

        Some(TBoxCandidate {
            offset: offset as u64,
            words: words.to_vec(),
            encoding,
            key_candidate,
            chi_squared: chi,
            bijective_col0: bij0,
            bijective_col1: bij1,
        })
    }

    /// Classify the encoding type by checking known structural patterns.
    fn classify_encoding(words: &[u32; 256]) -> WbEncoding {
        // Chow: output XOR relationships match rotated T-tables
        if Self::matches_chow_pattern(words) {
            return WbEncoding::Chow;
        }
        // Karroumi: dual-cipher tables have specific differential patterns
        if Self::matches_karroumi_pattern(words) {
            return WbEncoding::Karroumi;
        }
        // BCD: randomized with minimal bias in all four bytes
        if Self::matches_bcd_pattern(words) {
            return WbEncoding::Bcd;
        }
        WbEncoding::Unknown
    }

    fn matches_chow_pattern(words: &[u32; 256]) -> bool {
        // Chow T-tables satisfy: for each pair (i, j) with i ^ j == const,
        // words[i] ^ words[j] has a fixed Hamming pattern related to the encoding.
        // Quick heuristic: count pairs with small XOR difference.
        let mut chow_score = 0usize;
        for i in 0..128usize {
            let a = words[i];
            let b = words[i ^ 1];
            let diff = a ^ b;
            // Chow encodings tend to preserve some column structure
            if diff.count_ones() >= 4 && diff.count_ones() <= 12 {
                chow_score += 1;
            }
        }
        chow_score > 80
    }

    fn matches_karroumi_pattern(words: &[u32; 256]) -> bool {
        // Karroumi adds a second dual-cipher layer, creating richer XOR differentials.
        let mut score = 0usize;
        for i in 0..128usize {
            let diff = words[i] ^ words[i ^ 0x0f];
            // Dual-cipher encoding tends to activate all four bytes
            if diff & 0xff != 0 && (diff >> 8) & 0xff != 0
                && (diff >> 16) & 0xff != 0 && (diff >> 24) & 0xff != 0
            {
                score += 1;
            }
        }
        score > 100
    }

    fn matches_bcd_pattern(words: &[u32; 256]) -> bool {
        // BCD: each byte column is close to uniform (low chi-squared).
        for col in 0..4usize {
            let mut freq = [0u32; 256];
            for &w in words {
                let b = ((w >> (col * 8)) & 0xff) as usize;
                freq[b] += 1;
            }
            let chi = compute_chi_squared(&freq, 256);
            if chi > 512.0 {
                return false;
            }
        }
        true
    }
}

/// A T-box candidate found by the Chow encoding detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TBoxCandidate {
    /// File offset of this T-box.
    pub offset: u64,
    /// 256 u32 words forming the table.
    pub words: Vec<u32>,
    /// Detected encoding type.
    pub encoding: WbEncoding,
    /// Estimated embedded key byte.
    pub key_candidate: Option<u8>,
    /// Chi-squared test statistic.
    pub chi_squared: f64,
    /// Whether column 0 is a permutation.
    pub bijective_col0: bool,
    /// Whether column 1 is a permutation.
    pub bijective_col1: bool,
}

impl TBoxCandidate {
    /// Convert to a `LookupTable` for unified handling.
    #[must_use]
    pub fn to_lookup_table(&self) -> LookupTable {
        let data: Vec<u8> = self
            .words
            .iter()
            .flat_map(|&w| w.to_le_bytes())
            .collect();
        LookupTable {
            offset: self.offset,
            size: 1024,
            data,
            purpose: TablePurpose::SubstitutionBox,
        }
    }

    /// Extract column `col` (0–3) as a byte slice.
    #[must_use]
    pub fn column(&self, col: usize) -> Vec<u8> {
        self.words
            .iter()
            .map(|&w| ((w >> (col * 8)) & 0xff) as u8)
            .collect()
    }

    /// Compute Shannon entropy of a specific byte column.
    #[must_use]
    pub fn column_entropy(&self, col: usize) -> f64 {
        let bytes = self.column(col);
        let mut freq = [0u32; 256];
        for b in &bytes {
            freq[*b as usize] += 1;
        }
        shannon_entropy_u32(&freq, bytes.len())
    }

    /// Estimate the round this T-box belongs to by comparing to standard T-table.
    #[must_use]
    pub fn estimate_round(&self, all_candidates: &[Self]) -> Option<usize> {
        // T-boxes typically appear in groups of 4 per round × 10 rounds.
        // Find the group this T-box belongs to by proximity.
        let pos = all_candidates.iter().position(|c| c.offset == self.offset)?;
        Some(pos / 4)
    }
}

// ─── Karroumi detector ────────────────────────────────────────────────────────

/// Detector for Karroumi (2010) dual-cipher white-box AES tables.
///
/// Karroumi's construction uses a secondary AES instance with a complementary
/// key to create tables with additional masking. The dual-cipher tables can be
/// detected by checking for correlated XOR-differential patterns in pairs of
/// T-boxes from the two cipher instances.
#[derive(Debug)]
pub struct KarroumiDetector {
    /// Maximum offset gap between paired T-box blocks.
    pub max_pair_gap: usize,
}

impl Default for KarroumiDetector {
    fn default() -> Self {
        Self { max_pair_gap: 4096 }
    }
}

impl KarroumiDetector {
    /// Create a detector with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if two T-box candidates form a Karroumi dual-cipher pair.
    ///
    /// In Karroumi's scheme, for any input x:
    ///   T1[x] ⊕ T2[x] = f(x)
    /// where f is a relatively simple function (often affine).
    #[must_use]
    pub fn is_dual_pair(&self, t1: &TBoxCandidate, t2: &TBoxCandidate) -> bool {
        if t1.words.len() != 256 || t2.words.len() != 256 {
            return false;
        }
        // Compute XOR differences between the two tables
        let xor_diffs: Vec<u32> = t1
            .words
            .iter()
            .zip(t2.words.iter())
            .map(|(&a, &b)| a ^ b)
            .collect();

        // In Karroumi dual construction, XOR differences have low entropy
        // (near-affine relationship means the top byte column varies predictably)
        let top_bytes: Vec<u8> = xor_diffs.iter().map(|&w| (w >> 24) as u8).collect();
        let ent = bytes_entropy(&top_bytes);
        ent < 5.5 // Below this threshold suggests structured (affine-like) relationship
    }

    /// Find all Karroumi dual pairs from a list of T-box candidates.
    #[must_use]
    pub fn find_pairs<'a>(
        &self,
        candidates: &'a [TBoxCandidate],
    ) -> Vec<(&'a TBoxCandidate, &'a TBoxCandidate)> {
        let mut pairs = Vec::new();
        for i in 0..candidates.len() {
            for j in (i + 1)..candidates.len() {
                let gap = usize::try_from((candidates[j].offset.cast_signed() - candidates[i].offset.cast_signed()).unsigned_abs()).unwrap_or(usize::MAX);
                if gap > self.max_pair_gap {
                    break;
                }
                if self.is_dual_pair(&candidates[i], &candidates[j]) {
                    pairs.push((&candidates[i], &candidates[j]));
                }
            }
        }
        pairs
    }

    /// Recover the Karroumi key material from a dual pair.
    ///
    /// Given pair (T1, T2) where T1[x] = E1(SBox(x ⊕ k1)) and
    /// T2[x] = E2(SBox(x ⊕ k2)), we estimate k1 ^ k2 from the XOR pattern.
    #[must_use]
    pub fn recover_key_xor(&self, t1: &TBoxCandidate, t2: &TBoxCandidate) -> Option<Vec<u8>> {
        if t1.words.len() != 256 || t2.words.len() != 256 {
            return None;
        }
        // For each byte column, find the most likely differential XOR constant
        let mut key_bytes = Vec::with_capacity(4);
        for col in 0..4usize {
            let bytes1: Vec<u8> = t1.words.iter().map(|&w| ((w >> (col * 8)) & 0xff) as u8).collect();
            let bytes2: Vec<u8> = t2.words.iter().map(|&w| ((w >> (col * 8)) & 0xff) as u8).collect();
            let mut vote: HashMap<u8, usize> = HashMap::new();
            for i in 0..256usize {
                let xk = AES_SBOX_INV[bytes1[i] as usize] ^ AES_SBOX_INV[bytes2[i] as usize];
                *vote.entry(xk).or_insert(0) += 1;
            }
            let best = vote.into_iter().max_by_key(|(_, c)| *c).map(|(k, _)| k)?;
            key_bytes.push(best);
        }
        Some(key_bytes)
    }
}

// ─── Statistical analysis ─────────────────────────────────────────────────────

/// Full statistical profile of a lookup table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableStats {
    /// Offset in the binary.
    pub offset: u64,
    /// Number of entries (should be 256).
    pub entry_count: usize,
    /// Shannon entropy in bits (0..8 for byte tables).
    pub entropy: f64,
    /// Chi-squared statistic (lower = more uniform).
    pub chi_squared: f64,
    /// Maximum frequency of any single byte value.
    pub max_freq: u32,
    /// Minimum frequency of any byte value (0 = missing values).
    pub min_freq: u32,
    /// Whether the table is a permutation (bijective).
    pub is_permutation: bool,
    /// Correlation coefficient with AES S-box (−1..1).
    pub sbox_correlation: f64,
    /// Correlation coefficient with AES inverse S-box.
    pub inv_sbox_correlation: f64,
    /// Number of fixed points (i where table[i] == i).
    pub fixed_points: usize,
    /// Number of entries matching AES S-box exactly.
    pub sbox_matches: usize,
}

impl TableStats {
    /// Compute full statistics for a 256-byte table.
    ///
    /// # Panics
    ///
    /// Panics if `data.len() != 256`.
    #[must_use]
    pub fn compute(offset: u64, data: &[u8]) -> Self {
        assert_eq!(data.len(), 256, "table must have exactly 256 bytes");
        let mut freq = [0u32; 256];
        for &b in data {
            freq[b as usize] += 1;
        }

        let max_freq = *freq.iter().max().unwrap_or(&0);
        let min_freq = *freq.iter().min().unwrap_or(&0);
        let entropy = shannon_entropy_u32(&freq, data.len());
        let chi_squared = compute_chi_squared(&freq, data.len());
        let is_permutation = is_permutation_bytes(data);

        let sbox_correlation = pearson_u8(data, &AES_SBOX);
        let inv_sbox_correlation = pearson_u8(data, &AES_SBOX_INV);
        let fixed_points = data.iter().enumerate().filter(|&(i, &v)| v == u8::try_from(i).unwrap_or(u8::MAX)).count();
        let sbox_matches = data.iter().zip(AES_SBOX.iter()).filter(|&(&a, &b)| a == b).count();

        Self {
            offset,
            entry_count: data.len(),
            entropy,
            chi_squared,
            max_freq,
            min_freq,
            is_permutation,
            sbox_correlation,
            inv_sbox_correlation,
            fixed_points,
            sbox_matches,
        }
    }

    /// Returns `true` if this table looks like it is the AES S-box.
    #[must_use]
    pub fn likely_sbox(&self) -> bool {
        self.sbox_matches > 240 || self.sbox_correlation > 0.98
    }

    /// Returns `true` if this table looks like a random bijection (likely encoded).
    #[must_use]
    pub fn likely_encoded_bijection(&self) -> bool {
        self.is_permutation && !self.likely_sbox() && self.entropy > 7.5
    }
}

// ─── AesWbAnalyzer ────────────────────────────────────────────────────────────

/// High-level white-box AES analyzer combining all sub-detectors.
pub struct AesWbAnalyzer {
    pub chow_detector: ChowEncodingDetector,
    pub karroumi_detector: KarroumiDetector,
}

impl Default for AesWbAnalyzer {
    fn default() -> Self {
        Self {
            chow_detector: ChowEncodingDetector::new(),
            karroumi_detector: KarroumiDetector::new(),
        }
    }
}

impl AesWbAnalyzer {
    /// Create a new analyzer with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Full analysis pipeline: scan binary for all white-box AES artifacts.
    #[must_use]
    pub fn analyze(&self, binary: &[u8]) -> WbAnalysisReport {
        let mut report = WbAnalysisReport::new();

        // 1. Find T-box candidates
        let candidates = self.chow_detector.scan(binary);
        report.tbox_count = candidates.len();
        report.chow_candidates = candidates
            .iter()
            .filter(|c| c.encoding == WbEncoding::Chow)
            .count();

        // 2. Check for Karroumi dual pairs
        let pairs = self.karroumi_detector.find_pairs(&candidates);
        report.karroumi_pairs = pairs.len();

        // 3. Collect key candidates (vote across all T-boxes)
        let mut key_votes: HashMap<u8, usize> = HashMap::new();
        for c in &candidates {
            if let Some(k) = c.key_candidate {
                *key_votes.entry(k).or_insert(0) += 1;
            }
        }
        if let Some((best_k, votes)) = key_votes.into_iter().max_by_key(|(_, c)| *c)
            && votes >= 4
        {
            report.most_likely_key_byte = Some(best_k);
        }

        // 4. Compute statistics for all 256-byte windows
        report.table_stats = scan_256_byte_tables(binary);

        // 5. Determine overall confidence
        report.confidence = compute_wb_confidence(&report);

        // 6. Identify encoding type
        if report.karroumi_pairs > 0 {
            report.detected_encoding = WbEncoding::Karroumi;
        } else if report.chow_candidates > 4 {
            report.detected_encoding = WbEncoding::Chow;
        } else if report.tbox_count > 0 {
            report.detected_encoding = WbEncoding::Bcd;
        }

        report.notes.push(format!(
            "Scanned {} bytes; found {} T-box candidates ({} Chow), {} Karroumi pairs",
            binary.len(),
            report.tbox_count,
            report.chow_candidates,
            report.karroumi_pairs
        ));

        report
    }

    /// Recover per-round key bytes from ordered T-box groups.
    ///
    /// Expects groups of 4 T-boxes per column, 16 per round, 10 rounds = 160 T-boxes.
    #[must_use]
    pub fn recover_key_schedule(&self, candidates: &[TBoxCandidate]) -> Option<Vec<u8>> {
        if candidates.len() < 16 {
            return None;
        }
        // The first 16 T-boxes (round 1) encode round-key bytes 0–15
        let key: Vec<u8> = candidates[..16]
            .iter()
            .filter_map(|c| c.key_candidate)
            .collect();
        if key.len() == 16 {
            Some(key)
        } else {
            None
        }
    }
}

/// Result of a full white-box AES analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WbAnalysisReport {
    pub tbox_count: usize,
    pub chow_candidates: usize,
    pub karroumi_pairs: usize,
    pub detected_encoding: WbEncoding,
    pub most_likely_key_byte: Option<u8>,
    pub table_stats: Vec<TableStats>,
    pub confidence: f32,
    pub notes: Vec<String>,
}

impl WbAnalysisReport {
    const fn new() -> Self {
        Self {
            tbox_count: 0,
            chow_candidates: 0,
            karroumi_pairs: 0,
            detected_encoding: WbEncoding::Unknown,
            most_likely_key_byte: None,
            table_stats: Vec::new(),
            confidence: 0.0,
            notes: Vec::new(),
        }
    }
}

fn compute_wb_confidence(report: &WbAnalysisReport) -> f32 {
    let mut score = 0.0f32;
    if report.tbox_count >= 160 { score += 0.4; }
    else if report.tbox_count >= 16 { score += 0.2; }
    if report.chow_candidates >= 16 { score += 0.3; }
    if report.karroumi_pairs >= 8 { score += 0.2; }
    if report.most_likely_key_byte.is_some() { score += 0.1; }
    if !report.table_stats.is_empty() { score += 0.05; }
    score.min(1.0)
}

// ─── Statistics helpers ───────────────────────────────────────────────────────

/// Hard-cap the number of 256-byte windows we examine to prevent memory exhaustion.
const MAX_WINDOWS: usize = 16_384;   // 4 MiB of binary covered
const MAX_RETAINED: usize = 4_096;

fn scan_256_byte_tables(binary: &[u8]) -> Vec<TableStats> {
    if binary.len() < 256 {
        return vec![];
    }
    let mut stats = Vec::new();
    let mut i = 0usize;
    let mut windows_checked = 0usize;
    while i + 256 <= binary.len() && windows_checked < MAX_WINDOWS && stats.len() < MAX_RETAINED {
        let window = &binary[i..i + 256];
        let s = TableStats::compute(i as u64, window);
        // Only keep interesting tables (bijective or S-box-like)
        if s.is_permutation || s.sbox_matches > 128 || s.entropy > 7.8 {
            stats.push(s);
        }
        i += 256;
        windows_checked += 1;
    }
    stats
}

/// Compute Shannon entropy from a frequency table.
#[must_use]
pub fn shannon_entropy_u32(freq: &[u32; 256], n: usize) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let n_f = f64::from(u32::try_from(n).unwrap_or(u32::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n_f;
            -p * p.log2()
        })
        .sum()
}

/// Compute Shannon entropy of a byte slice.
#[must_use]
pub fn bytes_entropy(data: &[u8]) -> f64 {
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    shannon_entropy_u32(&freq, data.len())
}

/// Chi-squared uniformity test for a 256-entry u32 table (using LSB column).
fn chi_squared_uniformity_u32(words: &[u32]) -> f64 {
    let mut freq = [0u32; 256];
    for &w in words {
        freq[(w & 0xff) as usize] += 1;
    }
    compute_chi_squared(&freq, words.len())
}

/// Chi-squared test against uniform distribution.
///
/// # Panics
///
/// Panics if `n` is 0 (division by zero in the chi-squared formula).
#[must_use]
pub fn compute_chi_squared(freq: &[u32; 256], n: usize) -> f64 {
    let expected = f64::from(u32::try_from(n).unwrap_or(u32::MAX)) / 256.0;
    freq.iter()
        .map(|&c| {
            let diff = f64::from(c) - expected;
            diff * diff / expected
        })
        .sum()
}

/// Check if a byte slice is a permutation of 0..=255.
#[must_use]
pub fn is_permutation_bytes(data: &[u8]) -> bool {
    if data.len() != 256 {
        return false;
    }
    let mut seen = [false; 256];
    for &b in data {
        if seen[b as usize] {
            return false;
        }
        seen[b as usize] = true;
    }
    true
}

/// Pearson correlation coefficient between two 256-byte tables.
fn pearson_u8(a: &[u8], b: &[u8]) -> f64 {
    assert_eq!(a.len(), b.len());
    let n = f64::from(u32::try_from(a.len()).unwrap_or(u32::MAX));
    let mean_a = a.iter().map(|&x| f64::from(x)).sum::<f64>() / n;
    let mean_b = b.iter().map(|&x| f64::from(x)).sum::<f64>() / n;
    let mut cov = 0.0f64;
    let mut var_a = 0.0f64;
    let mut var_b = 0.0f64;
    for (&ai, &bi) in a.iter().zip(b.iter()) {
        let da = f64::from(ai) - mean_a;
        let db = f64::from(bi) - mean_b;
        cov += da * db;
        var_a += da * da;
        var_b += db * db;
    }
    let denom = (var_a * var_b).sqrt();
    if denom < f64::EPSILON { 0.0 } else { cov / denom }
}

// ─── T-box recovery ───────────────────────────────────────────────────────────

/// Recover the plain T-box from an encoded T-box by stripping XOR encodings.
///
/// Given an encoded table where `T_enc[i] = E_out(T[E_in(i)])`, this function
/// attempts to recover `T[i] = SBox(i ^ k)` by exhaustively searching XOR keys.
#[must_use]
pub fn recover_tbox(encoded: &[u32; 256]) -> TBoxRecovery {
    // Extract LSB column (most information for subkey recovery)
    let lsb: Vec<u8> = encoded.iter().map(|&w| (w & 0xff) as u8).collect();

    let mut best_key = 0u8;
    let mut best_score = 0usize;
    let mut best_table = vec![0u8; 256];

    for k in 0u8..=255 {
        let candidate: Vec<u8> = (0usize..256)
            .map(|i| lsb[i ^ k as usize])
            .collect();
        let score = candidate
            .iter()
            .enumerate()
            .filter(|&(i, &v)| v == AES_SBOX[i])
            .count();
        if score > best_score {
            best_score = score;
            best_key = k;
            best_table = candidate;
        }
    }

    TBoxRecovery {
        key_byte: best_key,
        recovered_table: best_table,
        sbox_match_score: best_score,
        confidence: f32::from(u16::try_from(best_score).unwrap_or(u16::MAX)) / 256.0,
    }
}

/// Result of a T-box recovery attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TBoxRecovery {
    /// Recovered XOR key byte.
    pub key_byte: u8,
    /// Recovered (decoded) T-box bytes.
    pub recovered_table: Vec<u8>,
    /// Number of entries matching AES S-box after recovery.
    pub sbox_match_score: usize,
    /// Confidence in recovery (0..1).
    pub confidence: f32,
}

// ─── Round-key extraction from full T-box array ───────────────────────────────

/// Extract a full 16-byte AES round-1 key from 16 T-box candidates.
///
/// Each T-box encodes one key byte: `T_i[x]` ≈ `SBox(x ^ k_i)`.
/// We recover `k_i` for positions 0–15 and return the round-0 key.
#[must_use]
pub fn extract_round_key_from_tboxes(tboxes: &[TBoxCandidate]) -> Option<[u8; 16]> {
    if tboxes.len() < 16 {
        return None;
    }
    let mut key = [0u8; 16];
    for (i, tbox) in tboxes.iter().take(16).enumerate() {
        if tbox.words.len() != 256 {
            return None;
        }
        let words_arr: [u32; 256] = tbox.words.as_slice().try_into().ok()?;
        let recovery = recover_tbox(&words_arr);
        if recovery.confidence < 0.5 {
            return None;
        }
        key[i] = recovery.key_byte;
    }
    Some(key)
}

// ─── Batch analysis ───────────────────────────────────────────────────────────

// ─── MixColumns helpers and uniformity utilities ─────────────────────────────

/// Expected per-byte frequency of a perfectly uniform 256-entry table
/// (each value appears exactly once → probability `1/256`).
///
/// Exposed for callers that want to derive their own deviation metric instead
/// of relying on [`compute_chi_squared`] alone.
#[must_use]
pub const fn uniform_frequency() -> f64 {
    UNIFORM_FREQ
}

/// Total absolute deviation of a frequency histogram from a perfectly uniform
/// distribution (lower is more uniform). Uses [`uniform_frequency`] as the
/// reference.
#[must_use]
pub fn uniformity_deviation(freq: &[u32; 256], n: usize) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let n_f = f64::from(u32::try_from(n).unwrap_or(u32::MAX));
    freq.iter()
        .map(|&c| ((f64::from(c) / n_f) - UNIFORM_FREQ).abs())
        .sum()
}

/// GF(2^8) multiply-by-2 lookup used in AES `MixColumns`
/// (constant-time table lookup over the precomputed [`GF_MUL2_TABLE`]).
#[must_use]
pub const fn gf_mul_by_2(b: u8) -> u8 {
    GF_MUL2_TABLE[b as usize]
}

/// GF(2^8) multiply-by-3 lookup used in AES `MixColumns`.
#[must_use]
pub const fn gf_mul_by_3(b: u8) -> u8 {
    GF_MUL3_TABLE[b as usize]
}

/// Compute the AES `MixColumns` transform on a 4-byte column.
///
/// Uses the pre-built `GF_MUL2_TABLE` / `GF_MUL3_TABLE` to reconstruct
/// candidate plain T-tables when probing recovered round keys.
#[must_use]
pub const fn aes_mix_column(col: [u8; 4]) -> [u8; 4] {
    let m2 = [
        GF_MUL2_TABLE[col[0] as usize],
        GF_MUL2_TABLE[col[1] as usize],
        GF_MUL2_TABLE[col[2] as usize],
        GF_MUL2_TABLE[col[3] as usize],
    ];
    let m3 = [
        GF_MUL3_TABLE[col[0] as usize],
        GF_MUL3_TABLE[col[1] as usize],
        GF_MUL3_TABLE[col[2] as usize],
        GF_MUL3_TABLE[col[3] as usize],
    ];
    [
        m2[0] ^ m3[1] ^ col[2] ^ col[3],
        col[0] ^ m2[1] ^ m3[2] ^ col[3],
        col[0] ^ col[1] ^ m2[2] ^ m3[3],
        m3[0] ^ col[1] ^ col[2] ^ m2[3],
    ]
}

/// Build the reference AES T-table row 0 used to validate decoded T-boxes.
///
/// `T0[i] = MixColumns([2·s, s, s, 3·s])` where `s = AES_SBOX[i]`.
///
/// Re-derives the table at runtime using the public [`aes_mix_column`] /
/// [`gf_mul_by_2`] / [`gf_mul_by_3`] primitives so the GF tables stay wired
/// into the public surface.
#[must_use]
pub fn reference_t0_row() -> [u32; 256] {
    let mut t = [0u32; 256];
    for (i, slot) in t.iter_mut().enumerate() {
        let s = AES_SBOX[i];
        let x2 = gf_mul_by_2(s);
        let x3 = gf_mul_by_3(s);
        *slot = u32::from_be_bytes([x2, s, s, x3]);
    }
    t
}

/// Run a batch white-box analysis across multiple binary chunks.
#[must_use]
pub fn batch_analyze(chunks: &[(&[u8], u64)]) -> Vec<WbAnalysisReport> {
    let analyzer = AesWbAnalyzer::new();
    chunks.iter().map(|(data, _base)| analyzer.analyze(data)).collect()
}

/// Merge multiple reports from batch analysis into a single summary.
#[must_use]
pub fn merge_reports(reports: &[WbAnalysisReport]) -> WbAnalysisReport {
    let mut merged = WbAnalysisReport::new();
    for r in reports {
        merged.tbox_count += r.tbox_count;
        merged.chow_candidates += r.chow_candidates;
        merged.karroumi_pairs += r.karroumi_pairs;
        merged.table_stats.extend(r.table_stats.iter().cloned());
    }
    merged.confidence = compute_wb_confidence(&merged);
    if merged.karroumi_pairs > 0 {
        merged.detected_encoding = WbEncoding::Karroumi;
    } else if merged.chow_candidates > 4 {
        merged.detected_encoding = WbEncoding::Chow;
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permutation_check() {
        let perm: Vec<u8> = (0u8..=255).collect();
        assert!(is_permutation_bytes(&perm));
        let not_perm = vec![0u8; 256];
        assert!(!is_permutation_bytes(&not_perm));
    }

    #[test]
    fn test_sbox_detection() {
        let stats = TableStats::compute(0, &AES_SBOX);
        assert!(stats.likely_sbox());
        assert_eq!(stats.sbox_matches, 256);
    }

    #[test]
    fn test_entropy_uniform() {
        let perm: Vec<u8> = (0u8..=255).collect();
        let e = bytes_entropy(&perm);
        assert!((e - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_tbox_recovery_sbox() {
        // Identity-encoded T-box where key = 0x00
        let tbox: [u32; 256] = std::array::from_fn(|i| u32::from(AES_SBOX[i]));
        let recovery = recover_tbox(&tbox);
        assert_eq!(recovery.key_byte, 0x00);
        assert!(recovery.sbox_match_score > 200);
    }

    #[test]
    fn test_chow_detector_no_crash() {
        let data = vec![0u8; 4096];
        let detector = ChowEncodingDetector::new();
        let result = detector.scan(&data);
        // No crash; result may be empty for zero-filled data
        let _ = result;
    }

    #[test]
    fn test_chi_squared_uniform() {
        let freq = [1u32; 256];
        let chi = compute_chi_squared(&freq, 256);
        assert!(chi < 1e-6);
    }
}
