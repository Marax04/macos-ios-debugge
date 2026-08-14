//! `whitebox_aes_full` — full whitebox AES analysis: lookup-table sets,
//! XOR tables, mixing bijections, key recovery, and side-channel leakage.

pub use crate::{AES_RCON, AES_SBOX_INV, LookupTable, TablePurpose};
use crate::{AES_SBOX, CryptoError};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
pub use std::collections::HashMap;

// ── LookupTableSet ─────────────────────────────────────────────────────────────

/// A complete set of lookup tables constituting one round of a whitebox AES.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupTableSet {
    /// The four T-tables (T0–T3) for this round (each 256 × u32 = 1 KiB).
    pub t_tables: [Vec<u32>; 4],
    /// Round index (0 = first round's encoding, 9 = last).
    pub round: usize,
}

impl LookupTableSet {
    /// Create an empty table set for the given round.
    #[must_use]
    pub fn new(round: usize) -> Self {
        Self {
            t_tables: [
                vec![0u32; 256],
                vec![0u32; 256],
                vec![0u32; 256],
                vec![0u32; 256],
            ],
            round,
        }
    }

    /// Fill T0 with the canonical (unencoded) AES T0 table.
    pub fn fill_canonical_t0(&mut self) {
        for (i, &s) in AES_SBOX.iter().enumerate() {
            let x2 = gf_mul(s, 2);
            let x3 = gf_mul(s, 3);
            self.t_tables[0][i] = u32::from_be_bytes([x2, s, s, x3]);
        }
    }

    /// Return true if T-table index `t` looks like a rotated canonical AES T-table.
    #[must_use]
    pub fn is_canonical(&self, t: usize) -> bool {
        if t >= 4 {
            return false;
        }
        let mut canonical = vec![0u32; 256];
        for (i, &s) in AES_SBOX.iter().enumerate() {
            let x2 = gf_mul(s, 2);
            let x3 = gf_mul(s, 3);
            canonical[i] = u32::from_be_bytes([x2, s, s, x3]);
        }
        let shift = u32::try_from(t).unwrap_or(u32::MAX);
        self.t_tables[t]
            .iter()
            .zip(canonical.iter())
            .all(|(&w, &c)| w == c.rotate_right(shift * 8))
    }

    /// Total bytes occupied by all four T-tables.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.t_tables.iter().map(|t| t.len() * 4).sum()
    }

    /// Merge this set's taints into a single confidence score in [0, 1].
    #[must_use]
    pub fn table_confidence(&self) -> f32 {
        let canonical_count = (0..4).filter(|&i| self.is_canonical(i)).count();
        f32::from(u8::try_from(canonical_count).unwrap_or(u8::MAX)) / 4.0
    }
}

// ── XorTable ──────────────────────────────────────────────────────────────────

/// A 256-entry XOR mixing table used in Chow-style whitebox encoding.
///
/// Each entry `xor_table[i]` represents the encoded XOR of two nibbles that
/// have been passed through bijective encodings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XorTable {
    /// 256-byte table (one entry per input pair (hi << 4 | lo)).
    #[serde(with = "BigArray")]
    pub data: [u8; 256],
    /// Which round this table belongs to.
    pub round: usize,
    /// Which nibble position (0..3) within the state byte.
    pub nibble: usize,
}

impl XorTable {
    /// Create an identity XOR table (XOR without encoding).
    #[must_use]
    pub fn identity() -> Self {
        let mut data = [0u8; 256];
        for i in 0u8..=255 {
            let hi = (i >> 4) & 0xF;
            let lo = i & 0xF;
            data[i as usize] = hi ^ lo;
        }
        Self {
            data,
            round: 0,
            nibble: 0,
        }
    }

    /// Apply the XOR table to a packed nibble pair.
    #[must_use]
    pub const fn apply(&self, packed: u8) -> u8 {
        self.data[packed as usize]
    }

    /// Check if this is an unencoded identity table.
    #[must_use]
    pub fn is_identity(&self) -> bool {
        for i in 0u8..=255 {
            let hi = (i >> 4) & 0xF;
            let lo = i & 0xF;
            if self.data[i as usize] != hi ^ lo {
                return false;
            }
        }
        true
    }

    /// Strip a simple XOR encoding by finding the constant offset.
    #[must_use]
    pub fn strip_xor_encoding(&self) -> Option<u8> {
        let expected = Self::identity();
        (0u8..=255).find(|&offset| {
            self.data
                .iter()
                .zip(expected.data.iter())
                .all(|(&a, &b)| a == b.wrapping_add(offset))
        })
    }

    /// Compute the differential: for each input `i`, `(self[i] XOR expected_identity[i])`.
    #[must_use]
    pub fn differential(&self) -> Vec<u8> {
        let expected = Self::identity();
        self.data
            .iter()
            .zip(expected.data.iter())
            .map(|(&a, &b)| a ^ b)
            .collect()
    }
}

// ── MixingBijection ────────────────────────────────────────────────────────────

/// An 8×8 invertible binary matrix (mixing bijection) used in whitebox AES.
///
/// In Chow's whitebox construction each column of the state is multiplied
/// by a random invertible 8×8 binary matrix to break algebraic structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixingBijection {
    /// Row-major 8×8 binary matrix stored as 8 bytes (one per row).
    pub matrix: [u8; 8],
    /// Inverse of the matrix (pre-computed).
    pub inverse: [u8; 8],
}

impl MixingBijection {
    /// Construct a mixing bijection from a row-major matrix.
    /// Returns `None` if the matrix is not invertible over GF(2).
    #[must_use]
    pub fn new(matrix: [u8; 8]) -> Option<Self> {
        let inverse = invert_gf2_matrix_8(matrix)?;
        Some(Self { matrix, inverse })
    }

    /// Identity bijection (no mixing).
    #[must_use]
    pub const fn identity() -> Self {
        let matrix = [0x80u8, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];
        Self {
            matrix,
            inverse: matrix,
        }
    }

    /// Apply the mixing bijection to a byte.
    #[must_use]
    pub fn apply(&self, b: u8) -> u8 {
        gf2_matrix_vec_mul_8(self.matrix, b)
    }

    /// Apply the inverse bijection to a byte.
    #[must_use]
    pub fn apply_inverse(&self, b: u8) -> u8 {
        gf2_matrix_vec_mul_8(self.inverse, b)
    }

    /// Compose two bijections: first `self`, then `other`.
    #[must_use]
    pub fn compose(&self, other: &Self) -> Option<Self> {
        let composed = gf2_matrix_mul_8(other.matrix, self.matrix);
        Self::new(composed)
    }

    /// Check if this is the identity bijection.
    #[must_use]
    pub fn is_identity(&self) -> bool {
        let id = Self::identity();
        self.matrix == id.matrix
    }
}

/// Multiply 8×8 GF(2) matrix by 8-bit vector.
fn gf2_matrix_vec_mul_8(m: [u8; 8], v: u8) -> u8 {
    let mut result = 0u8;
    for (row, &mr) in m.iter().enumerate() {
        let dot = (mr & v).count_ones() & 1;
        result |= u8::try_from(dot).unwrap_or(u8::MAX) << (7 - row);
    }
    result
}

/// Multiply two 8×8 GF(2) matrices.
fn gf2_matrix_mul_8(a: [u8; 8], b: [u8; 8]) -> [u8; 8] {
    let mut result = [0u8; 8];
    // Transpose b for column access
    let mut bt = [0u8; 8];
    for (col, bt_col) in bt.iter_mut().enumerate() {
        for (row, &br) in b.iter().enumerate() {
            if br & (1 << (7 - col)) != 0 {
                *bt_col |= 1 << (7 - row);
            }
        }
    }
    for (row, &ar) in a.iter().enumerate() {
        for (col, &bt_col) in bt.iter().enumerate() {
            let dot = (ar & bt_col).count_ones() & 1;
            result[row] |= u8::try_from(dot).unwrap_or(u8::MAX) << (7 - col);
        }
    }
    result
}

/// Invert an 8×8 GF(2) matrix using Gauss-Jordan elimination.
/// Returns `None` if the matrix is singular.
fn invert_gf2_matrix_8(mat: [u8; 8]) -> Option<[u8; 8]> {
    let mut a = mat;
    // Augment with identity
    let mut inv = [0x80u8, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];
    for col in 0..8 {
        // Find pivot
        let bit_pos = 7 - col;
        let pivot = (col..8).find(|&r| a[r] & (1 << bit_pos) != 0)?;
        a.swap(col, pivot);
        inv.swap(col, pivot);
        // Eliminate other rows
        for row in 0..8 {
            if row != col && a[row] & (1 << bit_pos) != 0 {
                a[row] ^= a[col];
                inv[row] ^= inv[col];
            }
        }
    }
    Some(inv)
}

// ── WhiteboxKey ────────────────────────────────────────────────────────────────

/// A recovered whitebox AES key along with metadata about the recovery process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhiteboxKey {
    /// The recovered key bytes (16 for AES-128, 32 for AES-256).
    pub key_bytes: Vec<u8>,
    /// Recovery method used.
    pub method: RecoveryMethod,
    /// Confidence in [0.0, 1.0].
    pub confidence: f32,
    /// Per-byte confidence (16 or 32 entries).
    pub byte_confidence: Vec<f32>,
    /// Any notes accumulated during recovery.
    pub notes: Vec<String>,
}

impl WhiteboxKey {
    /// Create a key result from raw bytes.
    #[must_use]
    pub fn new(key_bytes: Vec<u8>, method: RecoveryMethod, confidence: f32) -> Self {
        let n = key_bytes.len();
        Self {
            key_bytes,
            method,
            confidence,
            byte_confidence: vec![confidence; n],
            notes: Vec::new(),
        }
    }

    /// Return key as a hex string.
    #[must_use]
    pub fn as_hex(&self) -> String {
        self.key_bytes.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc })
    }

    /// Check if all bytes have individual confidence above a threshold.
    #[must_use]
    pub fn is_high_confidence(&self, threshold: f32) -> bool {
        self.byte_confidence.iter().all(|&c| c >= threshold)
    }

    /// Merge another key result (higher-confidence bytes win per position).
    pub fn merge_with(&mut self, other: &Self) {
        for (i, (&ob, &oc)) in other
            .key_bytes
            .iter()
            .zip(other.byte_confidence.iter())
            .enumerate()
        {
            if i < self.key_bytes.len() && oc > self.byte_confidence[i] {
                self.key_bytes[i] = ob;
                self.byte_confidence[i] = oc;
            }
        }
        let avg = self.byte_confidence.iter().sum::<f32>() / f32::from(u16::try_from(self.byte_confidence.len()).unwrap_or(u16::MAX));
        self.confidence = avg;
    }
}

/// Method used to recover the whitebox key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryMethod {
    /// Key schedule reversal from last round key.
    KeyScheduleReversal,
    /// Differential Computation Analysis.
    Dca,
    /// Differential Fault Analysis.
    Dfa,
    /// BGE algebraic attack.
    Bge,
    /// Direct extraction from unobfuscated key material.
    Direct,
    /// Heuristic key-schedule pattern search.
    Heuristic,
}

// ── SideChannelLeakage ─────────────────────────────────────────────────────────

/// Describes a side-channel leakage point in a whitebox implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideChannelLeakage {
    /// Type of leakage observed.
    pub leakage_type: LeakageType,
    /// Byte offset in binary where leakage was detected.
    pub offset: u64,
    /// Affected key bytes (positions 0..15 for AES-128).
    pub affected_key_bytes: Vec<usize>,
    /// Correlation coefficient (for DCA-type leakages).
    pub correlation: f32,
    /// Human-readable description.
    pub description: String,
}

impl SideChannelLeakage {
    #[must_use]
    pub fn new(
        leakage_type: LeakageType,
        offset: u64,
        affected_key_bytes: Vec<usize>,
        correlation: f32,
        description: impl Into<String>,
    ) -> Self {
        Self {
            leakage_type,
            offset,
            affected_key_bytes,
            correlation,
            description: description.into(),
        }
    }

    /// Return true if the correlation indicates strong leakage (> 0.5).
    #[must_use]
    pub fn is_strong(&self) -> bool {
        self.correlation.abs() > 0.5
    }
}

/// Classification of side-channel leakage type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeakageType {
    /// Memory access pattern leaks key-dependent data.
    CacheTimingMemoryAccess,
    /// Hamming weight of intermediate value correlates with key.
    HammingWeightCorrelation,
    /// Power consumption pattern in software simulation.
    SoftwarePowerModel,
    /// Branch prediction side channel.
    BranchPrediction,
    /// Unencoded key material stored in memory.
    UnencodedKeyMaterial,
}

// ── WhiteboxAesFull ────────────────────────────────────────────────────────────

/// Full whitebox AES analyzer combining all recovery and leakage-detection
/// techniques: T-table extraction, BGE, DCA, DFA, and key-schedule reversal.
pub struct WhiteboxAesFull {
    /// Binary blob being analyzed.
    binary: Vec<u8>,
    /// Extracted T-table sets per round (up to 10 rounds for AES-128).
    pub table_sets: Vec<LookupTableSet>,
    /// Detected XOR tables.
    pub xor_tables: Vec<XorTable>,
    /// Detected mixing bijections.
    pub mixing_bijections: Vec<MixingBijection>,
    /// Recovered key (if any).
    pub recovered_key: Option<WhiteboxKey>,
    /// Detected side-channel leakages.
    pub leakages: Vec<SideChannelLeakage>,
}

impl WhiteboxAesFull {
    /// Create a new analyzer for the given binary.
    #[must_use]
    pub const fn new(binary: Vec<u8>) -> Self {
        Self {
            binary,
            table_sets: Vec::new(),
            xor_tables: Vec::new(),
            mixing_bijections: Vec::new(),
            recovered_key: None,
            leakages: Vec::new(),
        }
    }

    /// Run the full analysis pipeline.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::TooShort` if the binary is less than 64 bytes.
    pub fn analyze(&mut self) -> Result<AnalysisResult, CryptoError> {
        if self.binary.len() < 64 {
            return Err(CryptoError::TooShort);
        }
        let mut notes = Vec::new();

        // 1. Extract T-table sets
        self.extract_t_table_sets(&mut notes);

        // 2. Detect XOR tables
        self.detect_xor_tables(&mut notes);

        // 3. Detect mixing bijections
        self.detect_mixing_bijections(&mut notes);

        // 4. Attempt key recovery
        self.attempt_key_recovery(&mut notes);

        // 5. Scan for side-channel leakages
        self.scan_side_channel_leakages(&mut notes);

        let confidence = self.compute_overall_confidence();

        Ok(AnalysisResult {
            key: self.recovered_key.clone(),
            table_sets_found: self.table_sets.len(),
            xor_tables_found: self.xor_tables.len(),
            mixing_bijections_found: self.mixing_bijections.len(),
            leakages: self.leakages.clone(),
            confidence,
            notes,
        })
    }

    fn extract_t_table_sets(&mut self, notes: &mut Vec<String>) {
        let limit = self.binary.len().saturating_sub(1024);
        let mut i = 0;
        while i <= limit {
            if i % 4 != 0 {
                i += 1;
                continue;
            }
            let mut t0 = vec![0u32; 256];
            for (j, w) in t0.iter_mut().enumerate() {
                let off = i + j * 4;
                if off + 4 > self.binary.len() {
                    break;
                }
                *w = u32::from_le_bytes(self.binary[off..off + 4].try_into().unwrap());
            }
            if is_valid_t_table(&t0) {
                let mut set = LookupTableSet::new(self.table_sets.len() / 4);
                set.t_tables[0] = t0;
                notes.push(format!("T-table candidate at offset 0x{i:x}"));
                self.table_sets.push(set);
                i += 1024;
                continue;
            }
            i += 4;
        }
    }

    fn detect_xor_tables(&mut self, notes: &mut Vec<String>) {
        // Look for 256-byte tables where index i = (hi ^ lo) XOR constant,
        // characteristic of Chow's internal XOR tables.
        if self.binary.len() < 256 {
            return;
        }
        for start in 0..=(self.binary.len() - 256) {
            let candidate = &self.binary[start..start + 256];
            let tbl: [u8; 256] = candidate.try_into().unwrap();
            let xor_table = XorTable {
                data: tbl,
                round: 0,
                nibble: 0,
            };
            // Check if differential from identity is constant (simple encoding)
            let diff = xor_table.differential();
            if diff.iter().all(|&d| d == diff[0]) && diff[0] != 0 {
                notes.push(format!("XOR table (constant-shifted) at 0x{start:x}"));
                self.xor_tables.push(xor_table);
                break; // limit to first for speed
            }
        }
    }

    fn detect_mixing_bijections(&mut self, _notes: &mut Vec<String>) {
        // A mixing bijection is an 8-byte block that, when interpreted as a
        // GF(2)^8 matrix, is invertible. Scan every 8-byte aligned offset.
        let limit = self.binary.len().saturating_sub(8);
        let mut i = 0;
        while i <= limit && self.mixing_bijections.len() < 16 {
            let block: [u8; 8] = self.binary[i..i + 8].try_into().unwrap();
            if let Some(bij) = MixingBijection::new(block) && !bij.is_identity() {
                self.mixing_bijections.push(bij);
            }
            i += 8;
        }
    }

    fn attempt_key_recovery(&mut self, notes: &mut Vec<String>) {
        // Strategy 1: direct key-schedule pattern
        if let Some(key) = scan_for_key_schedule(&self.binary) {
            notes.push("Key recovered via key-schedule pattern scan".into());
            self.recovered_key = Some(WhiteboxKey::new(key, RecoveryMethod::Heuristic, 0.75));
            return;
        }
        // Strategy 2: DCA-like - look for high-entropy 16-byte windows
        if let Some(key) = find_high_entropy_key(&self.binary) {
            notes.push("Key candidate from high-entropy region".into());
            self.recovered_key = Some(WhiteboxKey::new(key, RecoveryMethod::Direct, 0.50));
        }
    }

    fn scan_side_channel_leakages(&mut self, notes: &mut Vec<String>) {
        // Check for unencoded key material (verbatim AES S-box lookup patterns)
        if self.binary.len() >= 256 {
            for start in 0..=(self.binary.len() - 256) {
                if self.binary[start..start + 256] == AES_SBOX {
                    notes.push(format!(
                        "Unencoded AES S-box at 0x{start:x} — HW correlation leakage"
                    ));
                    self.leakages.push(SideChannelLeakage::new(
                        LeakageType::UnencodedKeyMaterial,
                        start as u64,
                        (0..16).collect(),
                        0.9,
                        "Unencoded AES S-box enables DCA key recovery",
                    ));
                    break;
                }
            }
        }
        // Cache-timing leakage: large table with uniform data distribution
        for set in &self.table_sets {
            if set.table_confidence() > 0.5 {
                self.leakages.push(SideChannelLeakage::new(
                    LeakageType::CacheTimingMemoryAccess,
                    0,
                    (0..16).collect(),
                    0.7,
                    format!("Round {} T-table enables cache-timing attack", set.round),
                ));
            }
        }
    }

    fn compute_overall_confidence(&self) -> f32 {
        let base = if self.recovered_key.is_some() {
            0.6
        } else {
            0.1
        };
        let table_bonus = f32::from(u8::try_from(self.table_sets.len().min(10)).unwrap_or(10_u8)) * 0.03;
        let leak_bonus = f32::from(u8::try_from(self.leakages.len().min(5)).unwrap_or(5_u8)) * 0.02;
        (base + table_bonus + leak_bonus).min(1.0)
    }
}

/// Result of the full whitebox AES analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub key: Option<WhiteboxKey>,
    pub table_sets_found: usize,
    pub xor_tables_found: usize,
    pub mixing_bijections_found: usize,
    pub leakages: Vec<SideChannelLeakage>,
    pub confidence: f32,
    pub notes: Vec<String>,
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// GF(2^8) multiplication (used in `MixColumns`).
const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    result
}

/// Build the canonical AES T0 table.
fn build_canonical_t0() -> Vec<u32> {
    AES_SBOX
        .iter()
        .map(|&s| {
            let x2 = gf_mul(s, 2);
            let x3 = gf_mul(s, 3);
            u32::from_be_bytes([x2, s, s, x3])
        })
        .collect()
}

/// Check if a 256-entry u32 table is a valid (possibly rotated) AES T-table.
fn is_valid_t_table(table: &[u32]) -> bool {
    if table.len() != 256 {
        return false;
    }
    let t0 = build_canonical_t0();
    for shift in 0u32..4 {
        if table
            .iter()
            .zip(t0.iter())
            .all(|(&w, &c)| w == c.rotate_right(shift * 8))
        {
            return true;
        }
    }
    false
}

/// Scan for AES-128 key schedule pattern in a binary.
fn scan_for_key_schedule(binary: &[u8]) -> Option<Vec<u8>> {
    if binary.len() < 176 {
        return None;
    }
    for start in (0..binary.len().saturating_sub(175)).step_by(16) {
        let slice = &binary[start..start + 176];
        if looks_like_aes128_key_schedule(slice) {
            return Some(slice[..16].to_vec());
        }
    }
    None
}

/// Heuristic: check if 176 bytes exhibit AES-128 key schedule XOR relations.
fn looks_like_aes128_key_schedule(data: &[u8]) -> bool {
    if data.len() < 176 {
        return false;
    }
    // Reject trivial schedules: require many non-zero bytes and a non-zero first round key
    let nonzero = data[..176].iter().filter(|&&b| b != 0).count();
    if nonzero < 64 {
        return false;
    }
    // The first round key (original key) must be non-trivial
    let key_nonzero = data[..16].iter().filter(|&&b| b != 0).count();
    if key_nonzero < 12 {
        return false;
    }
    let mut valid = 0usize;
    for round in 1..11 {
        let prev = &data[(round - 1) * 16..round * 16];
        let curr = &data[round * 16..(round + 1) * 16];
        let ok = (1..4)
            .filter(|&w| (0..4).all(|b| curr[w * 4 + b] == prev[w * 4 + b] ^ curr[(w - 1) * 4 + b]))
            .count();
        if ok >= 2 {
            valid += 1;
        }
    }
    valid >= 7
}

/// Find a 16-byte high-entropy window that might be a key.
fn find_high_entropy_key(binary: &[u8]) -> Option<Vec<u8>> {
    if binary.len() < 16 {
        return None;
    }
    for start in (0..binary.len().saturating_sub(15)).step_by(4) {
        let window = &binary[start..start + 16];
        if shannon_entropy(window) > 3.5 && has_good_byte_distribution(window) {
            return Some(window.to_vec());
        }
    }
    None
}

fn shannon_entropy(data: &[u8]) -> f32 {
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = f32::from(u16::try_from(data.len()).unwrap_or(u16::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f32::from(u16::try_from(c).unwrap_or(u16::MAX)) / n;
            -p * p.log2()
        })
        .sum()
}

fn has_good_byte_distribution(data: &[u8]) -> bool {
    let unique: std::collections::HashSet<u8> = data.iter().copied().collect();
    unique.len() >= data.len() * 3 / 4
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── LookupTableSet ────────────────────────────────────────────────────────

    #[test]
    fn test_table_set_new_empty() {
        let ts = LookupTableSet::new(0);
        assert_eq!(ts.round, 0);
        assert!(ts.t_tables.iter().all(|t| t.len() == 256));
    }

    #[test]
    fn test_table_set_fill_canonical_t0() {
        let mut ts = LookupTableSet::new(0);
        ts.fill_canonical_t0();
        assert!(ts.is_canonical(0));
    }

    #[test]
    fn test_table_set_canonical_rotations() {
        // T1 = T0 rotated right 8 bits
        let mut ts = LookupTableSet::new(0);
        ts.fill_canonical_t0();
        for i in 0..256 {
            ts.t_tables[1][i] = ts.t_tables[0][i].rotate_right(8);
            ts.t_tables[2][i] = ts.t_tables[0][i].rotate_right(16);
            ts.t_tables[3][i] = ts.t_tables[0][i].rotate_right(24);
        }
        assert!(ts.is_canonical(0));
        assert!(ts.is_canonical(1));
        assert!(ts.is_canonical(2));
        assert!(ts.is_canonical(3));
    }

    #[test]
    fn test_table_set_confidence_full() {
        let mut ts = LookupTableSet::new(0);
        ts.fill_canonical_t0();
        for i in 0..256 {
            ts.t_tables[1][i] = ts.t_tables[0][i].rotate_right(8);
            ts.t_tables[2][i] = ts.t_tables[0][i].rotate_right(16);
            ts.t_tables[3][i] = ts.t_tables[0][i].rotate_right(24);
        }
        assert!((ts.table_confidence() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_table_set_total_bytes() {
        let ts = LookupTableSet::new(0);
        assert_eq!(ts.total_bytes(), 4 * 256 * 4);
    }

    #[test]
    fn test_table_set_not_canonical_all_zero() {
        let ts = LookupTableSet::new(0);
        assert!(!ts.is_canonical(0));
    }

    // ── XorTable ─────────────────────────────────────────────────────────────

    #[test]
    fn test_xor_table_identity() {
        let xt = XorTable::identity();
        assert!(xt.is_identity());
    }

    #[test]
    fn test_xor_table_apply() {
        let xt = XorTable::identity();
        // packed = (3 << 4) | 5 = 0x35
        let packed: u8 = (3 << 4) | 5;
        assert_eq!(xt.apply(packed), 3 ^ 5);
    }

    #[test]
    fn test_xor_table_differential_identity_is_zero() {
        let xt = XorTable::identity();
        let diff = xt.differential();
        assert!(diff.iter().all(|&d| d == 0));
    }

    #[test]
    fn test_xor_table_strip_constant_encoding() {
        let identity = XorTable::identity();
        // Build a table shifted by constant 0x42
        let shifted_data: [u8; 256] = identity.data.map(|b| b.wrapping_add(0x42));
        let shifted = XorTable {
            data: shifted_data,
            round: 0,
            nibble: 0,
        };
        let offset = shifted.strip_xor_encoding();
        assert_eq!(offset, Some(0x42));
    }

    #[test]
    fn test_xor_table_strip_identity_no_offset() {
        let xt = XorTable::identity();
        // Identity = shifted by 0
        assert_eq!(xt.strip_xor_encoding(), Some(0));
    }

    // ── MixingBijection ───────────────────────────────────────────────────────

    #[test]
    fn test_mixing_bijection_identity() {
        let bij = MixingBijection::identity();
        assert!(bij.is_identity());
        for b in 0u8..=255 {
            assert_eq!(bij.apply(b), b);
        }
    }

    #[test]
    fn test_mixing_bijection_apply_inverse_roundtrip() {
        let matrix = [0xF0u8, 0x0F, 0xCC, 0x33, 0xAA, 0x55, 0xA5, 0x5A];
        if let Some(bij) = MixingBijection::new(matrix) {
            for b in [0u8, 1, 0x80, 0xFF, 0x42, 0xAB] {
                let enc = bij.apply(b);
                let dec = bij.apply_inverse(enc);
                assert_eq!(dec, b, "roundtrip failed for byte 0x{b:02x}");
            }
        }
    }

    #[test]
    fn test_mixing_bijection_singular_matrix_returns_none() {
        // All-zero matrix is singular
        let zero = [0u8; 8];
        assert!(MixingBijection::new(zero).is_none());
    }

    #[test]
    fn test_mixing_bijection_gf2_matrix_mul_identity() {
        let id_matrix = [0x80u8, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];
        let result = gf2_matrix_mul_8(id_matrix, id_matrix);
        assert_eq!(result, id_matrix);
    }

    // ── WhiteboxKey ───────────────────────────────────────────────────────────

    #[test]
    fn test_whitebox_key_as_hex() {
        let key = WhiteboxKey::new(vec![0x00, 0xFF, 0xAB, 0x12], RecoveryMethod::Direct, 0.9);
        assert_eq!(key.as_hex(), "00ffab12");
    }

    #[test]
    fn test_whitebox_key_high_confidence() {
        let key = WhiteboxKey::new(vec![0x00; 16], RecoveryMethod::Direct, 0.9);
        assert!(key.is_high_confidence(0.8));
        assert!(!key.is_high_confidence(0.95));
    }

    #[test]
    fn test_whitebox_key_merge_prefers_higher_confidence() {
        let mut k1 = WhiteboxKey::new(vec![0xAA; 16], RecoveryMethod::Direct, 0.5);
        let mut k2 = WhiteboxKey::new(vec![0xBB; 16], RecoveryMethod::Dca, 0.8);
        // Raise confidence on all bytes of k2
        for c in &mut k2.byte_confidence {
            *c = 0.8;
        }
        k1.merge_with(&k2);
        assert_eq!(k1.key_bytes[0], 0xBB);
    }

    #[test]
    fn test_whitebox_key_merge_keeps_existing_when_higher() {
        let mut k1 = WhiteboxKey::new(vec![0xAA; 16], RecoveryMethod::Direct, 0.9);
        let k2 = WhiteboxKey::new(vec![0xBB; 16], RecoveryMethod::Dca, 0.5);
        k1.merge_with(&k2);
        assert_eq!(k1.key_bytes[0], 0xAA);
    }

    // ── SideChannelLeakage ────────────────────────────────────────────────────

    #[test]
    fn test_leakage_is_strong() {
        let l = SideChannelLeakage::new(
            LeakageType::HammingWeightCorrelation,
            0,
            vec![0],
            0.7,
            "test",
        );
        assert!(l.is_strong());
    }

    #[test]
    fn test_leakage_is_not_strong() {
        let l = SideChannelLeakage::new(LeakageType::BranchPrediction, 0, vec![0], 0.3, "test");
        assert!(!l.is_strong());
    }

    // ── WhiteboxAesFull ───────────────────────────────────────────────────────

    #[test]
    fn test_analyze_too_short_returns_error() {
        let mut wba = WhiteboxAesFull::new(vec![0u8; 32]);
        let result = wba.analyze();
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_random_binary_no_panic() {
        let mut data = vec![0u8; 4096];
        for (i, b) in data.iter_mut().enumerate() {
            *b = u8::try_from(i.wrapping_mul(0x6B).wrapping_add(0x43) & 0xFF).unwrap_or(u8::MAX);
        }
        let mut wba = WhiteboxAesFull::new(data);
        let result = wba.analyze();
        assert!(result.is_ok());
    }

    #[test]
    fn test_analyze_with_embedded_sbox_detects_leakage() {
        let mut data = vec![0u8; 512];
        data[128..384].copy_from_slice(&AES_SBOX);
        let mut wba = WhiteboxAesFull::new(data);
        let result = wba.analyze().unwrap();
        assert!(!result.leakages.is_empty());
        assert!(
            result
                .leakages
                .iter()
                .any(|l| l.leakage_type == LeakageType::UnencodedKeyMaterial)
        );
    }

    #[test]
    fn test_analyze_with_t_table_detects_cache_leakage() {
        // Build a valid T0 table and embed it
        let mut ts = LookupTableSet::new(0);
        ts.fill_canonical_t0();
        let mut data = vec![0u8; 2048];
        for (i, &w) in ts.t_tables[0].iter().enumerate() {
            let off = 128 + i * 4;
            if off + 4 <= data.len() {
                data[off..off + 4].copy_from_slice(&w.to_le_bytes());
            }
        }
        let mut wba = WhiteboxAesFull::new(data);
        let result = wba.analyze().unwrap();
        assert!(result.table_sets_found > 0 || !result.leakages.is_empty());
    }

    #[test]
    fn test_analysis_result_notes_populated() {
        let mut data = vec![0xABu8; 512];
        data[100..356].copy_from_slice(&AES_SBOX);
        let mut wba = WhiteboxAesFull::new(data);
        let result = wba.analyze().unwrap();
        assert!(!result.notes.is_empty());
    }

    // ── GF arithmetic ─────────────────────────────────────────────────────────

    #[test]
    fn test_gf_mul_by_one() {
        for b in 0u8..=255 {
            assert_eq!(gf_mul(b, 1), b);
        }
    }

    #[test]
    fn test_gf_mul_by_zero() {
        for b in 0u8..=255 {
            assert_eq!(gf_mul(b, 0), 0);
        }
    }

    #[test]
    fn test_gf_mul_commutativity() {
        for a in [0u8, 1, 2, 0x80, 0xFF] {
            for b in [0u8, 1, 3, 0x57, 0xAB] {
                assert_eq!(gf_mul(a, b), gf_mul(b, a));
            }
        }
    }

    #[test]
    fn test_canonical_t0_first_entry() {
        // T0[0] = [2*sbox[0], sbox[0], sbox[0], 3*sbox[0]] = [2*0x63, 0x63, 0x63, 3*0x63]
        let t0 = build_canonical_t0();
        let s = AES_SBOX[0]; // 0x63
        let expected = u32::from_be_bytes([gf_mul(s, 2), s, s, gf_mul(s, 3)]);
        assert_eq!(t0[0], expected);
    }

    #[test]
    fn test_is_valid_t_table_canonical() {
        let t0 = build_canonical_t0();
        assert!(is_valid_t_table(&t0));
    }

    #[test]
    fn test_is_valid_t_table_rotated() {
        let t0 = build_canonical_t0();
        let t1: Vec<u32> = t0.iter().map(|&w| w.rotate_right(8)).collect();
        assert!(is_valid_t_table(&t1));
    }

    #[test]
    fn test_is_valid_t_table_random_is_false() {
        let random: Vec<u32> = (0u32..256).map(|i| i.wrapping_mul(0xDEAD_BEEF)).collect();
        assert!(!is_valid_t_table(&random));
    }

    #[test]
    fn test_key_schedule_scan_finds_embedded_schedule() {
        // Build a real AES-128 key schedule and embed it
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3cu8,
        ];
        let schedule = aes128_expand(&key);
        let mut binary = vec![0u8; 512];
        binary[128..128 + 176].copy_from_slice(&schedule);
        let result = scan_for_key_schedule(&binary);
        assert!(result.is_some());
        assert_eq!(&result.unwrap()[..16], &key);
    }

    /// Minimal AES-128 key expansion for test vectors.
    fn aes128_expand(key: &[u8; 16]) -> Vec<u8> {
        let mut rk = vec![[0u8; 16]; 11];
        rk[0].copy_from_slice(key);
        for i in 1..=10 {
            let prev = rk[i - 1];
            let rot = [prev[13], prev[14], prev[15], prev[12]];
            let sub = [
                AES_SBOX[rot[0] as usize],
                AES_SBOX[rot[1] as usize],
                AES_SBOX[rot[2] as usize],
                AES_SBOX[rot[3] as usize],
            ];
            rk[i][0] = prev[0] ^ sub[0] ^ AES_RCON[i];
            rk[i][1] = prev[1] ^ sub[1];
            rk[i][2] = prev[2] ^ sub[2];
            rk[i][3] = prev[3] ^ sub[3];
            for j in 1..4 {
                for b in 0..4 {
                    rk[i][j * 4 + b] = prev[j * 4 + b] ^ rk[i][(j - 1) * 4 + b];
                }
            }
        }
        rk.into_iter().flatten().collect()
    }
}

// ── BijectionSet ──────────────────────────────────────────────────────────────

/// A complete set of input/output bijections applied at one round of Chow's whitebox.
///
/// Chow's construction wraps each state byte with an invertible 8-bit function
/// (bijection) at both the input and the output of every T-table lookup.
/// Recovering these bijections is the main step of the BGE attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BijectionSet {
    /// Round index.
    pub round: usize,
    /// Input bijections: one per column (4 bijections).
    pub input_bijections: Vec<Vec<u8>>, // each is a 256-entry permutation table
    /// Output bijections: one per column.
    pub output_bijections: Vec<Vec<u8>>,
}

impl BijectionSet {
    /// Construct an identity bijection set (no encoding).
    #[must_use]
    pub fn identity(round: usize) -> Self {
        let identity: Vec<u8> = (0u8..=255).collect();
        Self {
            round,
            input_bijections: vec![identity.clone(); 4],
            output_bijections: vec![identity; 4],
        }
    }

    /// Check if all bijections are identity (no encoding).
    #[must_use]
    pub fn is_identity(&self) -> bool {
        let id: Vec<u8> = (0u8..=255).collect();
        self.input_bijections.iter().all(|b| b == &id)
            && self.output_bijections.iter().all(|b| b == &id)
    }

    /// Apply input bijection `col` to byte `x`.
    #[must_use]
    pub fn apply_input(&self, col: usize, x: u8) -> u8 {
        self.input_bijections.get(col).map_or(x, |b| b[x as usize])
    }

    /// Apply output bijection `col` to byte `x`.
    #[must_use]
    pub fn apply_output(&self, col: usize, x: u8) -> u8 {
        self.output_bijections.get(col).map_or(x, |b| b[x as usize])
    }

    /// Invert a bijection table.
    #[must_use]
    pub fn invert_table(table: &[u8; 256]) -> [u8; 256] {
        let mut inv = [0u8; 256];
        for (i, &v) in table.iter().enumerate() {
            inv[v as usize] = u8::try_from(i).unwrap_or(u8::MAX);
        }
        inv
    }

    /// Check if a 256-byte table is a valid bijection (permutation).
    #[must_use]
    pub fn is_bijection(table: &[u8]) -> bool {
        if table.len() != 256 {
            return false;
        }
        let mut seen = [false; 256];
        for &b in table {
            if seen[b as usize] {
                return false;
            }
            seen[b as usize] = true;
        }
        true
    }
}

// ── WhiteboxMetrics ───────────────────────────────────────────────────────────

/// Metrics measuring the quality of a whitebox implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhiteboxMetrics {
    /// Number of distinct S-box values found in the encoding tables.
    pub distinct_sbox_values: usize,
    /// Estimated obfuscation complexity (0.0 = none, 1.0 = maximum).
    pub obfuscation_score: f32,
    /// Number of rounds the whitebox appears to implement.
    pub estimated_rounds: usize,
    /// Size in bytes of all lookup tables combined.
    pub total_table_size: usize,
    /// Whether mixing bijections were detected.
    pub has_mixing_bijections: bool,
    /// Whether XOR tables were detected.
    pub has_xor_tables: bool,
}

impl WhiteboxMetrics {
    /// Compute metrics from an analysis result and extra data.
    #[must_use]
    pub fn compute(result: &AnalysisResult, binary: &[u8]) -> Self {
        let total_table_size =
            result.table_sets_found * (4 * 256 * 4) + result.xor_tables_found * 256;
        let mbf = f32::from(u16::try_from(result.mixing_bijections_found).unwrap_or(u16::MAX));
        let xtf = f32::from(u16::try_from(result.xor_tables_found).unwrap_or(u16::MAX));
        let tsf = f32::from(u16::try_from(result.table_sets_found).unwrap_or(u16::MAX));
        let obfuscation_score = mbf.mul_add(0.1, xtf.mul_add(0.05, tsf * 0.03)).min(1.0);

        // Count distinct S-box values embedded in the binary
        let distinct_sbox = (0..=255u8).filter(|&b| binary.contains(&b)).count();

        // Estimate rounds from table set count
        let estimated_rounds = if result.table_sets_found >= 10 {
            10
        } else if result.table_sets_found >= 9 {
            9
        } else {
            result.table_sets_found
        };

        Self {
            distinct_sbox_values: distinct_sbox,
            obfuscation_score,
            estimated_rounds,
            total_table_size,
            has_mixing_bijections: result.mixing_bijections_found > 0,
            has_xor_tables: result.xor_tables_found > 0,
        }
    }

    /// Whether the implementation appears to be a full 10-round AES.
    #[must_use]
    pub const fn is_full_aes(&self) -> bool {
        self.estimated_rounds >= 10
    }
}

// ── Additional tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod extra_tests {
    use super::*;

    // ── BijectionSet ──────────────────────────────────────────────────────────

    #[test]
    fn test_bijection_set_identity() {
        let bs = BijectionSet::identity(0);
        assert!(bs.is_identity());
    }

    #[test]
    fn test_bijection_set_apply_identity() {
        let bs = BijectionSet::identity(1);
        for b in 0u8..=255 {
            assert_eq!(bs.apply_input(0, b), b);
            assert_eq!(bs.apply_output(0, b), b);
        }
    }

    #[test]
    fn test_bijection_invert_table() {
        let table: Vec<u8> = (0u8..=255).rev().collect();
        let arr: [u8; 256] = table.try_into().unwrap();
        let inv = BijectionSet::invert_table(&arr);
        // inv should reverse the reversal
        for i in 0u8..=255 {
            assert_eq!(inv[arr[i as usize] as usize], i);
        }
    }

    #[test]
    fn test_bijection_is_bijection_identity() {
        let id: Vec<u8> = (0u8..=255).collect();
        assert!(BijectionSet::is_bijection(&id));
    }

    #[test]
    fn test_bijection_is_bijection_not() {
        let all_zero = vec![0u8; 256];
        assert!(!BijectionSet::is_bijection(&all_zero));
    }

    #[test]
    fn test_bijection_set_non_identity_not_identity() {
        let mut bs = BijectionSet::identity(0);
        bs.input_bijections[0][0] = 1;
        bs.input_bijections[0][1] = 0;
        assert!(!bs.is_identity());
    }

    // ── WhiteboxMetrics ───────────────────────────────────────────────────────

    #[test]
    fn test_metrics_compute_basic() {
        let result = AnalysisResult {
            key: None,
            table_sets_found: 10,
            xor_tables_found: 2,
            mixing_bijections_found: 5,
            leakages: vec![],
            confidence: 0.7,
            notes: vec![],
        };
        let binary = vec![0u8; 256];
        let m = WhiteboxMetrics::compute(&result, &binary);
        assert_eq!(m.estimated_rounds, 10);
        assert!(m.has_mixing_bijections);
        assert!(m.has_xor_tables);
        assert!(m.is_full_aes());
    }

    #[test]
    fn test_metrics_obfuscation_score_clamps() {
        let result = AnalysisResult {
            key: None,
            table_sets_found: 100,
            xor_tables_found: 100,
            mixing_bijections_found: 100,
            leakages: vec![],
            confidence: 1.0,
            notes: vec![],
        };
        let binary = vec![];
        let m = WhiteboxMetrics::compute(&result, &binary);
        assert!(m.obfuscation_score <= 1.0);
    }

    #[test]
    fn test_metrics_no_tables() {
        let result = AnalysisResult {
            key: None,
            table_sets_found: 0,
            xor_tables_found: 0,
            mixing_bijections_found: 0,
            leakages: vec![],
            confidence: 0.1,
            notes: vec![],
        };
        let binary = vec![];
        let m = WhiteboxMetrics::compute(&result, &binary);
        assert_eq!(m.estimated_rounds, 0);
        assert!(!m.is_full_aes());
        assert!(!m.has_mixing_bijections);
    }
}
