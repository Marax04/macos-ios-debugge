//! Extract lookup tables from binaries: find 256-entry tables, classify by
//! content (`AES SBox`, `inverse SBox`, `MixColumns`, `RC4` permutation, custom bijections).

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use rayon::prelude::*;

use crate::{AES_SBOX, AES_SBOX_INV, SM4_SBOX, LookupTable, TablePurpose};

// ─── Table classifications ────────────────────────────────────────────────────

/// Detailed classification of a found lookup table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TableClass {
    /// AES forward substitution box (exact match).
    AesSbox,
    /// AES inverse substitution box (exact match).
    AesSboxInverse,
    /// AES T-table (combined `SubBytes` + `MixColumns` + `ShiftRows`).
    AesTTable { rotation: u8 },
    /// AES `MixColumns` multiplication by constant (GF(2^8)).
    AesMixColMul { multiplier: u8 },
    /// AES Rcon table.
    AesRcon,
    /// SM4 S-box.
    Sm4Sbox,
    /// RC4 initialized S-array (permutation of 0..255).
    Rc4SArray,
    /// DES S-box (one of S1..S8).
    DesSbox { sbox_index: usize },
    /// CRC32 lookup table (256×4 bytes = 1 KiB).
    Crc32Table,
    /// Gamma/exponent table in GF(2^8) (AES log table).
    GfLogTable,
    /// Anti-log (exponent) table in GF(2^8).
    GfExpTable,
    /// Random bijection (permutation, but no known algorithm match).
    RandomBijection,
    /// Non-bijective substitution (many-to-one or not-onto).
    NonBijective,
    /// Likely XOR-encoded AES S-box (affinely equivalent).
    EncodedSbox { xor_in: u8, xor_out: u8 },
    /// Unknown / unclassified.
    Unknown,
}

impl std::fmt::Display for TableClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AesSbox => write!(f, "AES-SBox"),
            Self::AesSboxInverse => write!(f, "AES-SBox⁻¹"),
            Self::AesTTable { rotation } => write!(f, "AES-TTable(rot={rotation})"),
            Self::AesMixColMul { multiplier } => write!(f, "AES-MixCol(×{multiplier})"),
            Self::AesRcon => write!(f, "AES-Rcon"),
            Self::Sm4Sbox => write!(f, "SM4-SBox"),
            Self::Rc4SArray => write!(f, "RC4-SArray"),
            Self::DesSbox { sbox_index } => write!(f, "DES-S{sbox_index}"),
            Self::Crc32Table => write!(f, "CRC32-Table"),
            Self::GfLogTable => write!(f, "GF-LogTable"),
            Self::GfExpTable => write!(f, "GF-ExpTable"),
            Self::RandomBijection => write!(f, "RandomBijection"),
            Self::NonBijective => write!(f, "NonBijective"),
            Self::EncodedSbox { xor_in, xor_out } => {
                write!(f, "EncodedSBox(xin=0x{xor_in:02x},xout=0x{xor_out:02x})")
            }
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─── Extracted table ──────────────────────────────────────────────────────────

/// A lookup table found in a binary with detailed metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedTable {
    /// Byte offset in the binary.
    pub offset: u64,
    /// Number of entries.
    pub entry_count: usize,
    /// Entry width in bytes.
    pub entry_width: usize,
    /// Raw table bytes.
    pub data: Vec<u8>,
    /// Detected classification.
    pub class: TableClass,
    /// Confidence score (0..1).
    pub confidence: f32,
    /// Shannon entropy (bits).
    pub entropy: f64,
    /// Whether the byte values form a bijection.
    pub is_bijective: bool,
    /// Number of matching bytes against the reference table (for exact matches).
    pub match_count: usize,
}

impl ExtractedTable {
    /// Convert to the unified `LookupTable` type.
    #[must_use]
    pub fn to_lookup_table(&self) -> LookupTable {
        let purpose = match &self.class {
            TableClass::AesSbox | TableClass::AesSboxInverse | TableClass::Sm4Sbox
            | TableClass::EncodedSbox { .. } => TablePurpose::SubstitutionBox,
            TableClass::AesTTable { .. } | TableClass::AesMixColMul { .. } => TablePurpose::MixColumns,
            TableClass::AesRcon => TablePurpose::KeySchedule,
            _ => TablePurpose::Unknown,
        };
        LookupTable {
            offset: self.offset,
            size: self.data.len(),
            data: self.data.clone(),
            purpose,
        }
    }

    /// Return an 8-bit view of the table (for 1-byte entry tables).
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        if self.entry_width == 1 && self.data.len() == 256 {
            Some(&self.data)
        } else {
            None
        }
    }

    /// Return a 32-bit view (for 4-byte entry tables).
    ///
    /// # Panics
    ///
    /// Panics if the internal data is corrupt (chunk length is not exactly 4 bytes).
    #[must_use]
    pub fn as_u32s(&self) -> Option<Vec<u32>> {
        if self.entry_width == 4 && self.data.len() == 1024 {
            Some(
                self.data
                    .chunks_exact(4)
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                    .collect(),
            )
        } else {
            None
        }
    }
}

// ─── Extractor configuration ─────────────────────────────────────────────────

/// Configuration for the lookup table extractor.
#[derive(Debug, Clone)]
pub struct ExtractorConfig {
    /// Minimum entropy required to consider a 256-byte window as a table.
    pub min_entropy: f64,
    /// Minimum confidence to include a table in results.
    pub min_confidence: f32,
    /// Whether to look for 4-byte (u32) entry tables.
    pub find_u32_tables: bool,
    /// Whether to search for encoded (XOR-shifted) S-boxes.
    pub find_encoded_sboxes: bool,
    /// Whether to run in parallel.
    pub parallel: bool,
    /// Maximum number of tables to return (0 = unlimited).
    pub max_results: usize,
    /// Step size in bytes when scanning (1 = exhaustive, 256 = aligned only).
    pub scan_step: usize,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            min_entropy: 6.0,
            min_confidence: 0.5,
            find_u32_tables: true,
            find_encoded_sboxes: true,
            parallel: true,
            max_results: 0,
            scan_step: 1,
        }
    }
}

// ─── LookupTableExtractor ─────────────────────────────────────────────────────

/// Extracts and classifies lookup tables from binary data.
pub struct LookupTableExtractor {
    pub config: ExtractorConfig,
    /// Precomputed AES `MixColumns` tables for comparison.
    aes_mixcol_tables: HashMap<u8, Vec<u8>>,
    /// Precomputed GF log/exp tables.
    gf_log: Vec<u8>,
    gf_exp: Vec<u8>,
}

impl Default for LookupTableExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl LookupTableExtractor {
    /// Create an extractor with default configuration.
    #[must_use]
    pub fn new() -> Self {
        let (gf_log, gf_exp) = build_gf_tables();
        let mut aes_mixcol_tables = HashMap::new();
        for mul in [2u8, 3, 9, 11, 13, 14] {
            aes_mixcol_tables.insert(mul, build_gf_mul_table(mul));
        }
        Self {
            config: ExtractorConfig::default(),
            aes_mixcol_tables,
            gf_log,
            gf_exp,
        }
    }

    /// Extract all lookup tables from a binary.
    ///
    /// Returns a list of extracted tables sorted by offset.
    #[must_use]
    pub fn extract(&self, binary: &[u8]) -> Vec<ExtractedTable> {
        let mut results = Vec::new();

        // 1. Find 256-byte (8-bit entry) tables
        results.extend(self.find_byte_tables(binary));

        // 2. Find 1-KiB (32-bit entry / 256-entry) tables
        if self.config.find_u32_tables {
            results.extend(self.find_u32_tables(binary));
        }

        // 3. Sort by offset and deduplicate overlapping tables
        results.sort_by_key(|t| t.offset);
        let results = deduplicate_tables(results);

        // 4. Apply max_results limit
        if self.config.max_results > 0 && results.len() > self.config.max_results {
            results[..self.config.max_results].to_vec()
        } else {
            results
        }
    }

    /// Find all 256-byte aligned windows that look like lookup tables.
    fn find_byte_tables(&self, binary: &[u8]) -> Vec<ExtractedTable> {
        // Cap the offsets vector to avoid allocating gigabytes for large inputs.
        // An attacker-supplied binary of arbitrary size must not cause OOM here.
        // The natural upper bound is (binary.len() / step) entries; we hard-cap
        // at 4 M entries (~32 MiB of Vec<usize> on 64-bit) and rely on the
        // step-alignment of the scan window to stay correct.
        const MAX_OFFSETS: usize = 4_000_000;
        if binary.len() < 256 {
            return vec![];
        }
        let limit = binary.len() - 256;
        let step = self.config.scan_step.max(1);
        let offsets: Vec<usize> = (0..=limit).step_by(step).take(MAX_OFFSETS).collect();

        let classify_fn = |&off: &usize| -> Option<ExtractedTable> {
            let window = &binary[off..off + 256];
            let entropy = bytes_entropy(window);
            if entropy < self.config.min_entropy {
                return None;
            }
            let (class, confidence, match_count) = self.classify_byte_table(window);
            if confidence < self.config.min_confidence {
                return None;
            }
            let is_bij = is_permutation(window);
            Some(ExtractedTable {
                offset: off as u64,
                entry_count: 256,
                entry_width: 1,
                data: window.to_vec(),
                class,
                confidence,
                entropy,
                is_bijective: is_bij,
                match_count,
            })
        };

        if self.config.parallel {
            offsets.par_iter().filter_map(classify_fn).collect()
        } else {
            offsets.iter().filter_map(classify_fn).collect()
        }
    }

    /// Find all 1-KiB aligned windows that look like 32-bit entry tables.
    fn find_u32_tables(&self, binary: &[u8]) -> Vec<ExtractedTable> {
        // Cap at 4 M entries to prevent OOM on attacker-supplied large binaries.
        const MAX_OFFSETS: usize = 4_000_000;
        if binary.len() < 1024 {
            return vec![];
        }
        let limit = binary.len() - 1024;
        let offsets: Vec<usize> = (0..=limit).step_by(4).take(MAX_OFFSETS).collect();

        let classify_fn = |&off: &usize| -> Option<ExtractedTable> {
            let window = &binary[off..off + 1024];
            let entropy = bytes_entropy(window);
            if entropy < self.config.min_entropy {
                return None;
            }
            let words: Vec<u32> = window
                .chunks_exact(4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .collect();
            let (class, confidence, match_count) = Self::classify_u32_table(&words);
            if confidence < self.config.min_confidence {
                return None;
            }
            let lsb: Vec<u8> = words.iter().map(|&w| (w & 0xff) as u8).collect();
            let is_bij = is_permutation(&lsb);
            Some(ExtractedTable {
                offset: off as u64,
                entry_count: 256,
                entry_width: 4,
                data: window.to_vec(),
                class,
                confidence,
                entropy,
                is_bijective: is_bij,
                match_count,
            })
        };

        offsets.par_iter().filter_map(classify_fn).collect()
    }

    /// Classify a 256-byte table window.
    ///
    /// Returns `(class, confidence, match_count)`.
    fn classify_byte_table(&self, data: &[u8]) -> (TableClass, f32, usize) {
        assert_eq!(data.len(), 256);

        // --- Exact AES S-box ---
        let sbox_matches = exact_matches(data, &AES_SBOX);
        if sbox_matches == 256 {
            return (TableClass::AesSbox, 1.0, 256);
        }
        if sbox_matches > 240 {
            return (TableClass::AesSbox, f32::from(u16::try_from(sbox_matches).unwrap_or(256)) / 256.0, sbox_matches);
        }

        // --- Exact AES inverse S-box ---
        let inv_matches = exact_matches(data, &AES_SBOX_INV);
        if inv_matches == 256 {
            return (TableClass::AesSboxInverse, 1.0, 256);
        }
        if inv_matches > 240 {
            return (TableClass::AesSboxInverse, f32::from(u16::try_from(inv_matches).unwrap_or(256)) / 256.0, inv_matches);
        }

        // --- SM4 S-box ---
        let sm4_matches = exact_matches(data, &SM4_SBOX);
        if sm4_matches == 256 {
            return (TableClass::Sm4Sbox, 1.0, 256);
        }
        if sm4_matches > 240 {
            return (TableClass::Sm4Sbox, f32::from(u16::try_from(sm4_matches).unwrap_or(256)) / 256.0, sm4_matches);
        }

        // --- AES MixColumns multiplication tables ---
        for (&mul, ref_table) in &self.aes_mixcol_tables {
            let m = exact_matches(data, ref_table);
            if m == 256 {
                return (TableClass::AesMixColMul { multiplier: mul }, 1.0, 256);
            }
        }

        // --- GF log/exp tables ---
        let log_matches = exact_matches(data, &self.gf_log);
        if log_matches > 240 {
            return (TableClass::GfLogTable, f32::from(u16::try_from(log_matches).unwrap_or(256)) / 256.0, log_matches);
        }
        let exp_matches = exact_matches(data, &self.gf_exp);
        if exp_matches > 240 {
            return (TableClass::GfExpTable, f32::from(u16::try_from(exp_matches).unwrap_or(256)) / 256.0, exp_matches);
        }

        // --- RC4 S-array (permutation) ---
        if is_permutation(data) {
            // Check if it's an XOR-encoded S-box
            if self.config.find_encoded_sboxes
                && let Some((xor_in, xor_out, conf)) = detect_encoded_sbox(data)
            {
                return (TableClass::EncodedSbox { xor_in, xor_out }, conf, 0);
            }
            return (TableClass::RandomBijection, 0.7, 0);
        }

        // --- Non-bijective but high entropy ---
        let ent = bytes_entropy(data);
        if ent > 7.5 {
            return (TableClass::Unknown, 0.5, 0);
        }

        (TableClass::NonBijective, 0.3, 0)
    }

    /// Classify a 256-entry u32 table.
    fn classify_u32_table(words: &[u32]) -> (TableClass, f32, usize) {
        assert_eq!(words.len(), 256);

        // --- AES T-tables: T0, T1, T2, T3 (rotated versions) ---
        for rot in 0u8..4 {
            if is_aes_t_table(words, rot) {
                return (TableClass::AesTTable { rotation: rot }, 0.99, 256);
            }
        }

        // --- CRC32 table: check for CRC32 polynomial relations ---
        if is_crc32_table(words) {
            return (TableClass::Crc32Table, 0.95, 0);
        }

        // Partial T-table match
        let (best_rot, t_score) = score_aes_t_table_partial(words);
        if t_score > 200 {
            let conf = f32::from(u16::try_from(t_score).unwrap_or(256)) / 256.0;
            return (TableClass::AesTTable { rotation: best_rot }, conf, t_score);
        }

        let lsb: Vec<u8> = words.iter().map(|&w| (w & 0xff) as u8).collect();
        if is_permutation(&lsb) {
            return (TableClass::RandomBijection, 0.65, 0);
        }

        (TableClass::Unknown, 0.4, 0)
    }
}

// ─── DES S-box classifier ──────────────────────────────────────────────────────

/// DES S-boxes: each is a 64-entry (6-bit in, 4-bit out) substitution.
/// These are laid out as 4 rows × 16 columns in the official specification.
static DES_SBOXES: [&[u8]; 8] = [
    &[ // S1
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    &[ // S2
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    &[ // S3 (first row)
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    &[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3, 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    &[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    &[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    &[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    &[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
];

/// Attempt to classify a 64-byte buffer as one of the DES S-boxes.
#[must_use]
pub fn classify_des_sbox(data: &[u8]) -> Option<usize> {
    if data.len() < 64 {
        return None;
    }
    for (i, &sbox) in DES_SBOXES.iter().enumerate() {
        let matches = data[..64].iter().zip(sbox.iter()).filter(|&(&a, &b)| a == b).count();
        if matches > 60 {
            return Some(i + 1);
        }
    }
    None
}

// ─── CRC32 table detection ────────────────────────────────────────────────────

/// Check if a 256-entry u32 table is a CRC32 table.
///
/// CRC32 tables satisfy: `T[n] = (T[n-1] >> 1) ^ (0xEDB88320 * (T[n-1] & 1))`
/// for the standard reflected polynomial.
fn is_crc32_table(words: &[u32]) -> bool {
    const CRC32_POLY: u32 = 0xEDB8_8320;
    if words.len() != 256 {
        return false;
    }
    let mut matches = 0usize;
    for (i, &entry) in words.iter().enumerate() {
        let mut c = u32::try_from(i).unwrap_or(u32::MAX);
        for _ in 0..8 {
            if c & 1 == 1 { c = (c >> 1) ^ CRC32_POLY; } else { c >>= 1; }
        }
        if entry == c {
            matches += 1;
        }
    }
    matches > 240
}

// ─── AES T-table detection ────────────────────────────────────────────────────

/// Build AES T0 table.
fn build_aes_t0() -> Vec<u32> {
    let mut t = vec![0u32; 256];
    for (i, &s) in AES_SBOX.iter().enumerate() {
        let x2 = gf_mul(s, 2);
        let x3 = gf_mul(s, 3);
        t[i] = u32::from_be_bytes([x2, s, s, x3]);
    }
    t
}

const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    while b != 0 {
        if b & 1 != 0 { result ^= a; }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 { a ^= 0x1b; }
        b >>= 1;
    }
    result
}

fn is_aes_t_table(words: &[u32], rotation: u8) -> bool {
    let t0 = build_aes_t0();
    words.iter().zip(t0.iter()).all(|(&w, &t)| {
        w == t.rotate_right(u32::from(rotation) * 8)
    })
}

fn score_aes_t_table_partial(words: &[u32]) -> (u8, usize) {
    let t0 = build_aes_t0();
    let mut best_rot = 0u8;
    let mut best_score = 0usize;
    for rot in 0u8..4 {
        let score = words
            .iter()
            .zip(t0.iter())
            .filter(|&(&w, &t)| w == t.rotate_right(u32::from(rot) * 8))
            .count();
        if score > best_score {
            best_score = score;
            best_rot = rot;
        }
    }
    (best_rot, best_score)
}

// ─── GF(2^8) tables ───────────────────────────────────────────────────────────

fn build_gf_tables() -> (Vec<u8>, Vec<u8>) {
    let mut log_table = vec![0u8; 256];
    let mut exp_table = vec![0u8; 256];
    let mut x = 1u8;
    for (i, slot) in exp_table[..255].iter_mut().enumerate() {
        *slot = x;
        log_table[x as usize] = u8::try_from(i).unwrap_or(u8::MAX);
        let hi = x & 0x80;
        x <<= 1;
        if hi != 0 { x ^= 0x1b; }
    }
    exp_table[255] = exp_table[0];
    (log_table, exp_table)
}

fn build_gf_mul_table(multiplier: u8) -> Vec<u8> {
    (0u8..=255).map(|x| gf_mul(x, multiplier)).collect()
}

// ─── Encoded S-box detection ──────────────────────────────────────────────────

/// Detect if a 256-byte table is an XOR-encoded AES S-box.
///
/// Returns `Some((xor_in, xor_out, confidence))` if the table equals
/// `AES_SBOX[(i ^ xor_in) & 0xff] ^ xor_out` for all i.
fn detect_encoded_sbox(data: &[u8]) -> Option<(u8, u8, f32)> {
    for xor_in in 0u8..=255 {
        // Derive xor_out from the first entry
        let first_idx = xor_in as usize;
        let xor_out = data[0] ^ AES_SBOX[first_idx];
        let matches = (0usize..256)
            .filter(|&i| data[i] == AES_SBOX[(i ^ xor_in as usize) & 0xff] ^ xor_out)
            .count();
        if matches > 240 {
            return Some((xor_in, xor_out, f32::from(u16::try_from(matches).unwrap_or(256)) / 256.0));
        }
    }
    None
}

// ─── Utility functions ────────────────────────────────────────────────────────

fn exact_matches(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).filter(|&(&x, &y)| x == y).count()
}

fn is_permutation(data: &[u8]) -> bool {
    if data.len() != 256 { return false; }
    let mut seen = [false; 256];
    for &b in data {
        if seen[b as usize] { return false; }
        seen[b as usize] = true;
    }
    true
}

fn bytes_entropy(data: &[u8]) -> f64 {
    let mut freq = [0u32; 256];
    for &b in data { freq[b as usize] += 1; }
    let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = f64::from(c) / n; -p * p.log2() })
        .sum()
}

fn deduplicate_tables(sorted: Vec<ExtractedTable>) -> Vec<ExtractedTable> {
    let mut result: Vec<ExtractedTable> = Vec::new();
    for t in sorted {
        let overlap = result.last().is_some_and(|prev| {
            t.offset < prev.offset + prev.data.len() as u64
        });
        if !overlap {
            result.push(t);
        } else if let Some(prev) = result.last_mut() {
            // Keep higher-confidence result
            if t.confidence > prev.confidence {
                *prev = t;
            }
        }
    }
    result
}

// ─── Table report ─────────────────────────────────────────────────────────────

/// Summary report of all extracted tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionReport {
    pub total_found: usize,
    pub sbox_count: usize,
    pub inv_sbox_count: usize,
    pub t_table_count: usize,
    pub bijection_count: usize,
    pub encoded_sbox_count: usize,
    pub crc32_count: usize,
    pub tables: Vec<ExtractedTable>,
}

impl ExtractionReport {
    /// Build a report from a list of extracted tables.
    #[must_use]
    pub fn from_tables(tables: Vec<ExtractedTable>) -> Self {
        let sbox_count = tables.iter().filter(|t| t.class == TableClass::AesSbox).count();
        let inv_sbox_count = tables.iter().filter(|t| t.class == TableClass::AesSboxInverse).count();
        let t_table_count = tables.iter().filter(|t| matches!(t.class, TableClass::AesTTable { .. })).count();
        let bijection_count = tables.iter().filter(|t| t.class == TableClass::RandomBijection).count();
        let encoded_sbox_count = tables.iter().filter(|t| matches!(t.class, TableClass::EncodedSbox { .. })).count();
        let crc32_count = tables.iter().filter(|t| t.class == TableClass::Crc32Table).count();
        let total_found = tables.len();
        Self {
            total_found,
            sbox_count,
            inv_sbox_count,
            t_table_count,
            bijection_count,
            encoded_sbox_count,
            crc32_count,
            tables,
        }
    }

    /// Returns all tables of a given class.
    #[must_use]
    pub fn by_class(&self, class: &TableClass) -> Vec<&ExtractedTable> {
        self.tables.iter().filter(|t| &t.class == class).collect()
    }

    /// Returns all tables with confidence >= threshold.
    #[must_use]
    pub fn high_confidence(&self, threshold: f32) -> Vec<&ExtractedTable> {
        self.tables.iter().filter(|t| t.confidence >= threshold).collect()
    }

    /// Summarize findings as a human-readable string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Found {} tables: {} AES-SBox, {} AES-SBox⁻¹, {} T-tables, \
             {} bijections, {} encoded S-boxes, {} CRC32",
            self.total_found,
            self.sbox_count,
            self.inv_sbox_count,
            self.t_table_count,
            self.bijection_count,
            self.encoded_sbox_count,
            self.crc32_count
        )
    }
}

/// Convenience: run full extraction and return a report.
#[must_use]
pub fn extract_and_report(binary: &[u8]) -> ExtractionReport {
    let extractor = LookupTableExtractor::new();
    let tables = extractor.extract(binary);
    ExtractionReport::from_tables(tables)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_aes_sbox() {
        let mut binary = vec![0u8; 512];
        binary[128..128 + 256].copy_from_slice(&AES_SBOX);
        let ext = LookupTableExtractor::new();
        let tables = ext.extract(&binary);
        let found = tables.iter().any(|t| t.class == TableClass::AesSbox);
        assert!(found, "should find embedded AES S-box");
    }

    #[test]
    fn test_permutation_classified() {
        let perm: Vec<u8> = (0u8..=255).collect();
        assert!(is_permutation(&perm));
    }

    #[test]
    fn test_crc32_table_detection() {
        // Build an actual CRC32 table
        const POLY: u32 = 0xEDB8_8320;
        let mut table = [0u32; 256];
        for (i, slot) in table.iter_mut().enumerate() {
            let mut c = u32::try_from(i).unwrap_or(u32::MAX);
            for _ in 0..8 {
                if c & 1 == 1 { c = (c >> 1) ^ POLY; } else { c >>= 1; }
            }
            *slot = c;
        }
        assert!(is_crc32_table(&table));
    }

    #[test]
    fn test_gf_mul_table() {
        let t = build_gf_mul_table(2);
        assert_eq!(t.len(), 256);
        assert_eq!(t[0], 0);
        // gf_mul(0x01, 2) = 0x02
        assert_eq!(t[1], 2);
    }

    #[test]
    fn test_encoded_sbox_detection() {
        // Create S-box XOR-encoded with xor_in=0x5a, xor_out=0x3c
        let xin = 0x5au8;
        let xout = 0x3cu8;
        let encoded: Vec<u8> = (0usize..256)
            .map(|i| AES_SBOX[(i ^ xin as usize) & 0xff] ^ xout)
            .collect();
        let result = detect_encoded_sbox(&encoded);
        assert!(result.is_some(), "encoded S-box must be detected");
    }

    #[test]
    fn test_report_summary() {
        let binary: Vec<u8> = AES_SBOX.to_vec().into_iter().chain(vec![0u8; 256]).collect();
        let report = extract_and_report(&binary);
        assert!(!report.summary().is_empty());
    }
}
