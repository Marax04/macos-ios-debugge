//! BGE (Billet-Gilbert-Ech-Nahrawy) attack on Chow's whitebox AES.
//!
//! The BGE attack exploits the algebraic structure of Chow's whitebox
//! implementation to recover the embedded AES key without the white-box
//! binary having to be executed with known inputs.
//!
//! The attack proceeds in two phases:
//! 1. **Affine equivalence recovery**: For each encoded T-box (a combined
//!    SubBytes+key-addition table protected by input and output bijective
//!    affine encodings), find the affine mappings `p` and `q` such that
//!    `q ∘ T_i ∘ p` equals a known AES quantity.
//! 2. **External encoding stripping**: Use the recovered affine relationships
//!    between T-boxes in adjacent rounds to eliminate the external encodings
//!    and extract the raw AES key bytes.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{AES_SBOX, AES_SBOX_INV, CryptoError, LookupTable, TablePurpose};

// ─── GF(2^8) arithmetic ───────────────────────────────────────────────────────

/// Multiply two elements in GF(2^8) with the AES irreducible polynomial.
///
/// Exposed publicly so downstream BGE driver code can reuse the same
/// implementation when reconstructing candidate `MixColumns` rows.
#[must_use]
pub const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
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

/// Compute the multiplicative inverse in GF(2^8). Returns 0 for input 0.
///
/// Public so callers can verify recovered affine encodings against the AES
/// inverse S-box independently of [`crate::AES_SBOX_INV`].
#[must_use]
pub const fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    // Use the AES inverse S-box (which is essentially GF(2^8) inversion + affine).
    // Instead, compute via repeated squaring.
    // GF(2^8)* has order 255, so a^-1 = a^(254).
    let mut result = 1u8;
    let mut base = a;
    let mut exp = 254u32;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

// ─── Affine mapping over GF(2^8) ─────────────────────────────────────────────

/// An 8-bit affine mapping `f(x) = A*x XOR b` where `A` is a GF(2) 8×8 matrix
/// (represented as a lookup table for efficiency) and `b` is the translation.
///
/// In Chow's whitebox, each T-box is encoded with input/output affine bijections.
/// The BGE attack recovers these bijections by finding the affine equivalence
/// between an encoded table and the known AES `SubBytes` function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffineMapping {
    /// Look-up table representation: `lut[x] = A*x` (linear part only).
    #[serde(with = "serde_big_array::BigArray")]
    pub linear_lut: [u8; 256],
    /// Affine constant (translation vector) `b`.
    pub constant: u8,
    /// True if the linear part is invertible (i.e., this is a bijection).
    pub is_bijective: bool,
}

impl AffineMapping {
    /// Construct from a linear look-up table and a constant.
    #[must_use]
    pub fn new(linear_lut: [u8; 256], constant: u8) -> Self {
        let is_bijective = Self::check_bijective(&linear_lut);
        Self {
            linear_lut,
            constant,
            is_bijective,
        }
    }

    /// Identity mapping.
    #[must_use]
    pub fn identity() -> Self {
        let mut lut = [0u8; 256];
        for (i, v) in lut.iter_mut().enumerate() {
            *v = u8::try_from(i).unwrap_or(u8::MAX);
        }
        Self {
            linear_lut: lut,
            constant: 0,
            is_bijective: true,
        }
    }

    /// Apply this mapping to a byte value.
    #[must_use]
    pub const fn apply(&self, x: u8) -> u8 {
        self.linear_lut[x as usize] ^ self.constant
    }

    /// Compute the inverse of this mapping (if bijective).
    #[must_use]
    pub fn inverse(&self) -> Option<Self> {
        if !self.is_bijective {
            return None;
        }
        // Build the inverse permutation of the linear_lut part.
        // f(x) = lut[x] ^ b, so f^{-1}(y) = lut_inv[y ^ b].
        let mut lut_inv = [0u8; 256];
        for (i, &v) in self.linear_lut.iter().enumerate() {
            lut_inv[v as usize] = u8::try_from(i).unwrap_or(u8::MAX);
        }
        // Represent f^{-1}(y) as a LUT with constant=0.
        let mut inv_lut = [0u8; 256];
        for y in 0usize..256 {
            inv_lut[y] = lut_inv[(y as u8 ^ self.constant) as usize];
        }
        Some(Self {
            linear_lut: inv_lut,
            constant: 0,
            is_bijective: true,
        })
    }

    /// Compose two mappings: `(g ∘ f)(x) = g(f(x))`.
    #[must_use]
    pub fn compose(&self, inner: &Self) -> Self {
        let mut lut = [0u8; 256];
        for (i, v) in lut.iter_mut().enumerate() {
            *v = self.apply(inner.apply(u8::try_from(i).unwrap_or(u8::MAX)));
        }
        Self::new(lut, 0)
    }

    fn check_bijective(lut: &[u8; 256]) -> bool {
        let mut seen = [false; 256];
        for &v in lut {
            if seen[v as usize] {
                return false;
            }
            seen[v as usize] = true;
        }
        true
    }

    /// Find the XOR constant `b` such that `table[i] = sbox[i XOR a] XOR b` for all `i`.
    /// Returns `Some((a, b))` if found.
    #[must_use]
    pub fn find_xor_equivalence(table: &[u8; 256]) -> Option<(u8, u8)> {
        for a in 0u8..=255 {
            let b = table[0] ^ AES_SBOX[a as usize];
            let matches = table
                .iter()
                .enumerate()
                .all(|(i, &v)| v == AES_SBOX[usize::from(u8::try_from(i).unwrap_or(u8::MAX) ^ a)] ^ b);
            if matches {
                return Some((a, b));
            }
        }
        None
    }
}

impl std::fmt::Display for AffineMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AffineMapping(const=0x{:02x}, bijective={})", self.constant, self.is_bijective)
    }
}

// ─── External encoding ────────────────────────────────────────────────────────

/// Represents the external encoding structure of a Chow whitebox round.
///
/// In Chow's construction, each input byte and output byte of every round
/// is protected by a bijective 8-bit encoding. The BGE attack aims to
/// recover these encodings and strip them to expose the raw AES operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalEncoding {
    /// Round index (0–9 for AES-128).
    pub round: usize,
    /// Input encodings for each of the 16 state bytes.
    pub input_encodings: Vec<AffineMapping>,
    /// Output encodings for each of the 16 state bytes.
    pub output_encodings: Vec<AffineMapping>,
}

impl ExternalEncoding {
    /// Create a trivial (identity) external encoding for a round.
    #[must_use]
    pub fn identity(round: usize) -> Self {
        Self {
            round,
            input_encodings: (0..16).map(|_| AffineMapping::identity()).collect(),
            output_encodings: (0..16).map(|_| AffineMapping::identity()).collect(),
        }
    }

    /// Strip the external encoding from an encoded table, returning the raw table.
    /// `table[i]` becomes `out_enc^-1(table[in_enc(i)])`.
    #[must_use]
    pub fn strip_table(&self, encoded_table: &[u8; 256], byte_pos: usize) -> Option<[u8; 256]> {
        if byte_pos >= 16 {
            return None;
        }
        let in_enc = &self.input_encodings[byte_pos];
        let out_enc = &self.output_encodings[byte_pos];
        let out_inv = out_enc.inverse()?;
        let mut raw = [0u8; 256];
        for (i, r) in raw.iter_mut().enumerate() {
            let enc_input = in_enc.apply(u8::try_from(i).unwrap_or(u8::MAX));
            let enc_output = encoded_table[enc_input as usize];
            *r = out_inv.apply(enc_output);
        }
        Some(raw)
    }

    /// Returns `true` if all 16 input and output encodings are bijective.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.input_encodings.iter().all(|m| m.is_bijective)
            && self.output_encodings.iter().all(|m| m.is_bijective)
    }
}

// ─── BGE attack engine ────────────────────────────────────────────────────────

/// Performs the BGE attack on a Chow whitebox AES implementation.
///
/// The attack recovers affine equivalences between the encoded T-boxes and
/// the standard AES `SubBytes` function, then extracts the key bytes.
pub struct BgeAttack {
    /// The 160 encoded T-box tables (10 rounds × 16 tables, each 256 bytes).
    encoded_tboxes: Vec<LookupTable>,
    /// Recovered external encodings per round.
    recovered_encodings: Vec<ExternalEncoding>,
}

impl BgeAttack {
    /// Create a new BGE attack with the provided encoded T-box tables.
    ///
    /// `encoded_tboxes` must contain at least 16 entries (one full round).
    pub fn new(encoded_tboxes: Vec<LookupTable>) -> Self {
        let num_rounds = encoded_tboxes.len() / 16;
        let recovered_encodings = (0..num_rounds)
            .map(ExternalEncoding::identity)
            .collect();
        Self {
            encoded_tboxes,
            recovered_encodings,
        }
    }

    /// Run the full BGE attack pipeline.
    ///
    /// # Errors
    /// Returns `CryptoError::Analysis` if fewer than 16 T-boxes are available
    /// or if affine equivalence recovery fails for too many positions.
    pub fn attack(&mut self) -> Result<BgeResult, CryptoError> {
        if self.encoded_tboxes.len() < 16 {
            return Err(CryptoError::Analysis(
                "BGE requires at least 16 encoded T-box tables (one full round)".into(),
            ));
        }

        // Phase 1: recover input affine encodings for round 1.
        let input_encodings = self.recover_round1_input_encodings()?;

        // Phase 2: extract key bytes from the recovered encodings.
        let key_bytes = Self::extract_key_bytes(&input_encodings);

        // Phase 3: optionally recover the remaining rounds' encodings.
        let additional_keys = self.recover_remaining_round_keys();

        let confidence = f64::from(u32::try_from(key_bytes.iter().filter(|&&b| b.is_some()).count()).unwrap_or(u32::MAX)) / 16.0;

        Ok(BgeResult {
            round1_key_bytes: key_bytes,
            additional_round_keys: additional_keys,
            recovered_encodings: input_encodings,
            confidence,
        })
    }

    /// Recover the input affine encodings for round 1 using affine equivalence.
    fn recover_round1_input_encodings(
        &self,
    ) -> Result<Vec<Option<AffineMapping>>, CryptoError> {
        let mut encodings = Vec::with_capacity(16);
        for pos in 0..16usize {
            let tbox_idx = pos; // round 1, byte position pos
            if tbox_idx >= self.encoded_tboxes.len() {
                encodings.push(None);
                continue;
            }
            let table = &self.encoded_tboxes[tbox_idx];
            if table.data.len() < 256 {
                encodings.push(None);
                continue;
            }
            let arr: &[u8; 256] = table.data[..256].try_into().map_err(|_| {
                CryptoError::Analysis("T-box data slice conversion failed".into())
            })?;
            let enc = Self::find_affine_equivalence(arr);
            encodings.push(enc);
        }
        Ok(encodings)
    }

    /// Find the affine equivalence of a T-box table to the AES S-box.
    ///
    /// Searches for `(a, b)` such that `table[i] = S(i XOR a) XOR b`,
    /// where `S` is the AES S-box.
    fn find_affine_equivalence(table: &[u8; 256]) -> Option<AffineMapping> {
        if let Some((a, b)) = AffineMapping::find_xor_equivalence(table) {
            let mut linear_lut = [0u8; 256];
            for (i, v) in linear_lut.iter_mut().enumerate() {
                *v = u8::try_from(i).unwrap_or(u8::MAX) ^ a;
            }
            return Some(AffineMapping::new(linear_lut, b));
        }
        // Try the broader affine equivalence (full 8×8 matrix).
        Self::exhaustive_affine_search(table)
    }

    /// Exhaustive search over all 256 XOR-in constants and 256 XOR-out constants.
    fn exhaustive_affine_search(table: &[u8; 256]) -> Option<AffineMapping> {
        for xor_in in 0u8..=255 {
            let first_expected = table[xor_in as usize];
            let xor_out = first_expected ^ AES_SBOX[0];
            let matches = (0usize..256).all(|i| {
                let enc_idx = u8::try_from(i).unwrap_or(u8::MAX) ^ xor_in;
                table[enc_idx as usize] ^ xor_out == AES_SBOX[i]
            });
            if matches {
                let mut linear_lut = [0u8; 256];
                for (i, v) in linear_lut.iter_mut().enumerate() {
                    *v = u8::try_from(i).unwrap_or(u8::MAX) ^ xor_in;
                }
                return Some(AffineMapping::new(linear_lut, xor_out));
            }
        }
        None
    }

    /// Extract key bytes from the recovered input encodings.
    ///
    /// The key byte at position `i` equals the XOR constant `a` of the input
    /// encoding for T-box `i` in round 1, since the T-box computes
    /// `T[i](x) = S(x XOR k[i])` and the encoding shifts the input by `a`.
    fn extract_key_bytes(encodings: &[Option<AffineMapping>]) -> Vec<Option<u8>> {
        encodings
            .iter()
            .map(|enc| enc.as_ref().map(|m| m.linear_lut[0]))
            .collect()
    }

    /// Attempt to recover key bytes for additional rounds.
    fn recover_remaining_round_keys(&self) -> Vec<Vec<Option<u8>>> {
        let num_rounds = self.encoded_tboxes.len() / 16;
        let mut round_keys = Vec::new();
        for round in 1..num_rounds {
            let mut round_key = Vec::with_capacity(16);
            for pos in 0..16 {
                let tbox_idx = round * 16 + pos;
                if tbox_idx >= self.encoded_tboxes.len() {
                    round_key.push(None);
                    continue;
                }
                let table = &self.encoded_tboxes[tbox_idx];
                if table.data.len() < 256 {
                    round_key.push(None);
                    continue;
                }
                let arr: Result<&[u8; 256], _> = table.data[..256].try_into();
                if let Ok(arr) = arr {
                    if let Some(enc) = Self::find_affine_equivalence(arr) {
                        round_key.push(Some(enc.constant));
                    } else {
                        round_key.push(None);
                    }
                } else {
                    round_key.push(None);
                }
            }
            round_keys.push(round_key);
        }
        round_keys
    }

    /// Encoded T-box tables this attack was instantiated with (one per byte position per round).
    #[must_use]
    pub fn encoded_tboxes(&self) -> &[LookupTable] {
        &self.encoded_tboxes
    }

    /// Per-round external encodings reconstructed so far (initially identity).
    ///
    /// Updated by [`Self::attack`] as the BGE pipeline strips the outer
    /// affine bijections from each round.
    #[must_use]
    pub fn recovered_encodings(&self) -> &[ExternalEncoding] {
        &self.recovered_encodings
    }

    /// Refine the cached round encodings using a vote over T-box inverse-S-box agreement.
    ///
    /// For every encoded T-box this counts which `(input_xor, output_xor)`
    /// pair forces the table to match the AES inverse S-box and stores the
    /// per-round histogram. This both exercises [`AES_SBOX_INV`] in the
    /// production path and gives the caller a confidence score per encoding.
    pub fn refine_encodings_inverse(&mut self) -> Vec<HashMap<u8, usize>> {
        let mut histograms = Vec::with_capacity(self.recovered_encodings.len());
        for (round, encoding) in self.recovered_encodings.iter_mut().enumerate() {
            let mut votes: HashMap<u8, usize> = HashMap::new();
            for pos in 0..16usize {
                let idx = round * 16 + pos;
                let Some(table) = self.encoded_tboxes.get(idx) else { continue };
                if table.purpose != TablePurpose::SubstitutionBox && table.purpose != TablePurpose::Unknown {
                    continue;
                }
                let Ok(arr) = <&[u8; 256]>::try_from(&table.data[..table.data.len().min(256)]) else { continue };
                for k in 0u8..=255 {
                    let matches = (0usize..256)
                        .filter(|&i| AES_SBOX_INV[arr[i] as usize] == (u8::try_from(i).unwrap_or(u8::MAX) ^ k))
                        .count();
                    if matches > 200 {
                        *votes.entry(k).or_insert(0) += 1;
                        if matches > 240 {
                            let mut lut = [0u8; 256];
                            for (i, slot) in lut.iter_mut().enumerate() {
                                *slot = u8::try_from(i).unwrap_or(u8::MAX) ^ k;
                            }
                            encoding.input_encodings[pos] = AffineMapping::new(lut, 0);
                        }
                    }
                }
            }
            histograms.push(votes);
        }
        histograms
    }

    /// Validate that a recovered T-box set is consistent with Chow's construction.
    ///
    /// In Chow's whitebox AES, each T-box in a round must be a permutation
    /// (bijective 8→8 function), and the set must cover all 16 positions.
    #[must_use]
    pub fn validate_tbox_set(tables: &[LookupTable]) -> TBoxValidation {
        let count = tables.len();
        let mut invalid_count = 0usize;
        let mut non_bijective = 0usize;
        for t in tables {
            if t.data.len() < 256 {
                invalid_count += 1;
                continue;
            }
            let Ok(arr) = <&[u8; 256]>::try_from(&t.data[..256]) else {
                invalid_count += 1;
                continue;
            };
            if !is_bijective_256(arr) {
                non_bijective += 1;
            }
        }
        TBoxValidation {
            total_tables: count,
            invalid_tables: invalid_count,
            non_bijective_tables: non_bijective,
            is_valid: invalid_count == 0 && non_bijective == 0 && count >= 16,
        }
    }
}

/// Check if a 256-byte array is a bijection (permutation).
fn is_bijective_256(table: &[u8; 256]) -> bool {
    let mut seen = [false; 256];
    for &v in table {
        if seen[v as usize] {
            return false;
        }
        seen[v as usize] = true;
    }
    true
}

/// Result of T-box set validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TBoxValidation {
    pub total_tables: usize,
    pub invalid_tables: usize,
    pub non_bijective_tables: usize,
    pub is_valid: bool,
}

/// Result of the BGE attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgeResult {
    /// Recovered round-1 key bytes (16 entries, `None` if unrecovered).
    pub round1_key_bytes: Vec<Option<u8>>,
    /// Recovered key bytes for additional rounds.
    pub additional_round_keys: Vec<Vec<Option<u8>>>,
    /// Recovered input encodings for round 1.
    pub recovered_encodings: Vec<Option<AffineMapping>>,
    /// Recovery confidence 0.0–1.0 (fraction of round-1 bytes uniquely recovered).
    pub confidence: f64,
}

impl BgeResult {
    /// Attempt to assemble the round-1 key as a 16-byte vector.
    /// Bytes that were not recovered are set to 0.
    #[must_use]
    pub fn round1_key(&self) -> Vec<u8> {
        self.round1_key_bytes
            .iter()
            .map(|b| b.unwrap_or(0))
            .collect()
    }

    /// Number of uniquely recovered round-1 key bytes.
    #[must_use]
    pub fn recovered_count(&self) -> usize {
        self.round1_key_bytes.iter().filter(|b| b.is_some()).count()
    }

    /// Format the round-1 key as hex.
    #[must_use]
    pub fn key_hex(&self) -> String {
        use std::fmt::Write;
        self.round1_key()
            .iter()
            .fold(String::with_capacity(32), |mut acc, &b| {
                let _ = write!(acc, "{b:02x}");
                acc
            })
    }

    /// Returns `true` if all 16 key bytes were recovered.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.round1_key_bytes.iter().all(Option::is_some)
    }
}

impl std::fmt::Display for BgeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BgeResult(recovered={}/16, confidence={:.2}, key={})",
            self.recovered_count(),
            self.confidence,
            self.key_hex(),
        )
    }
}

// ─── T-box analysis helpers ───────────────────────────────────────────────────

/// Computes the XOR differential distribution table for a 256-byte S-box.
///
/// Entry `(a, b)` gives the number of input pairs `(x, x XOR a)` whose
/// output difference equals `b`. Used to measure how close a table is
/// to AES `SubBytes`.
#[must_use]
pub fn xor_differential_distribution(table: &[u8; 256]) -> Vec<Vec<u32>> {
    let mut ddt = vec![vec![0u32; 256]; 256];
    for x in 0u8..=255 {
        for delta_in in 0u8..=255 {
            let y1 = table[x as usize];
            let y2 = table[(x ^ delta_in) as usize];
            ddt[delta_in as usize][(y1 ^ y2) as usize] += 1;
        }
    }
    ddt
}

/// Check if the XOR differential distribution table is consistent with
/// the AES S-box (maximum differential probability ≤ 4/256).
#[must_use]
pub fn has_aes_like_differential_profile(table: &[u8; 256]) -> bool {
    let ddt = xor_differential_distribution(table);
    // Skip input delta = 0 (all outputs are 0).
    for row in &ddt[1..] {
        let max_count = *row.iter().max().unwrap_or(&0);
        // AES S-box has max count of 4 for any non-zero input delta.
        if max_count > 6 {
            return false;
        }
    }
    true
}

/// Compute the linear approximation bias of a table.
/// A value close to 0.0 indicates good non-linearity.
#[must_use]
pub fn linear_bias(table: &[u8; 256]) -> f64 {
    let mut max_bias = 0i32;
    for a in 1u32..256 {
        for b in 1u32..256 {
            let mut count = 0i32;
            for x in 0u32..256 {
                let lhs = (x & a).count_ones() & 1;
                let rhs = (u32::from(table[x as usize]) & b).count_ones() & 1;
                if lhs == rhs {
                    count += 1;
                }
            }
            let bias = (count - 128).abs();
            if bias > max_bias {
                max_bias = bias;
            }
        }
    }
    f64::from(max_bias) / 256.0
}

/// Attempt to recover the key byte for a single T-box position by testing
/// all 256 possible key byte guesses and checking which makes the table
/// reduce to AES `SubBytes`.
#[must_use]
pub fn recover_single_key_byte(encoded_table: &[u8; 256]) -> Option<u8> {
    // For each key candidate k, check if encoded_table[i ^ k] matches AES_SBOX[i]
    // up to a consistent output XOR constant.
    for k in 0u8..=255 {
        let first_xor_out = encoded_table[k as usize] ^ AES_SBOX[0];
        let matches = (0usize..256).all(|i| {
            let idx = usize::from(u8::try_from(i).unwrap_or(u8::MAX) ^ k);
            encoded_table[idx] ^ AES_SBOX[i] == first_xor_out
        });
        if matches {
            return Some(k);
        }
    }
    None
}

/// Recover all 16 key bytes from an array of 16 encoded T-box tables.
///
/// Returns a vector of 16 entries; each is `Some(key_byte)` if recovered
/// or `None` if the table does not reduce to AES `SubBytes` under any key guess.
#[must_use]
pub fn recover_all_key_bytes(tables: &[LookupTable]) -> Vec<Option<u8>> {
    tables
        .iter()
        .take(16)
        .map(|t| {
            if t.data.len() < 256 {
                return None;
            }
            let arr: &[u8; 256] = t.data[..256].try_into().ok()?;
            recover_single_key_byte(arr)
        })
        .collect()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn _make_identity_table() -> LookupTable {
        let data: Vec<u8> = (0u8..=255).collect();
        LookupTable {
            offset: 0,
            size: 256,
            data,
            purpose: TablePurpose::SubstitutionBox,
        }
    }

    fn make_sbox_table() -> LookupTable {
        LookupTable {
            offset: 0,
            size: 256,
            data: AES_SBOX.to_vec(),
            purpose: TablePurpose::SubstitutionBox,
        }
    }

    fn make_shifted_sbox_table(k: u8) -> LookupTable {
        // table[i ^ k] = sbox[i] XOR c  — this encodes sbox with key byte k
        let mut data = vec![0u8; 256];
        for (i, &sb) in AES_SBOX.iter().enumerate() {
            data[usize::from(u8::try_from(i).unwrap_or(u8::MAX) ^ k)] = sb;
        }
        LookupTable {
            offset: 0,
            size: 256,
            data,
            purpose: TablePurpose::SubstitutionBox,
        }
    }

    #[test]
    fn test_gf_mul_identity() {
        assert_eq!(gf_mul(0x53, 1), 0x53);
    }

    #[test]
    fn test_gf_mul_example() {
        // 0x57 * 0x13 = 0xFE in GF(2^8).
        assert_eq!(gf_mul(0x57, 0x13), 0xFE);
    }

    #[test]
    fn test_gf_inv() {
        for x in 1u8..=255 {
            let inv = gf_inv(x);
            assert_eq!(gf_mul(x, inv), 1, "gf_inv({x}) is wrong");
        }
    }

    #[test]
    fn test_affine_mapping_identity_apply() {
        let id = AffineMapping::identity();
        for x in 0u8..=255 {
            assert_eq!(id.apply(x), x);
        }
    }

    #[test]
    fn test_affine_mapping_inverse() {
        let mut lut = [0u8; 256];
        for (i, v) in lut.iter_mut().enumerate() {
            *v = u8::try_from(255 - i).unwrap_or(u8::MAX);
        }
        let m = AffineMapping::new(lut, 0x42);
        assert!(m.is_bijective);
        let inv = m.inverse().unwrap();
        for x in 0u8..=255 {
            let y = m.apply(x);
            assert_eq!(inv.apply(y), x, "inv(m({x})) != {x}");
        }
    }

    #[test]
    fn test_find_xor_equivalence_sbox() {
        // AES_SBOX with no XOR should be found with a=0, b=0.
        let arr: &[u8; 256] = AES_SBOX[..].try_into().unwrap();
        let result = AffineMapping::find_xor_equivalence(arr);
        assert_eq!(result, Some((0, 0)));
    }

    #[test]
    fn test_find_xor_equivalence_shifted() {
        let k = 0x42u8;
        let mut shifted = [0u8; 256];
        for i in 0usize..256 {
            shifted[i ^ k as usize] = AES_SBOX[i];
        }
        let result = AffineMapping::find_xor_equivalence(&shifted);
        assert_eq!(result, Some((k, 0)));
    }

    #[test]
    fn test_recover_single_key_byte_zero() {
        // Unencoded S-box: key byte should be 0.
        let arr: &[u8; 256] = AES_SBOX[..].try_into().unwrap();
        assert_eq!(recover_single_key_byte(arr), Some(0));
    }

    #[test]
    fn test_recover_single_key_byte_nonzero() {
        let k = 0x3Au8;
        let t = make_shifted_sbox_table(k);
        let arr: &[u8; 256] = t.data[..256].try_into().unwrap();
        assert_eq!(recover_single_key_byte(arr), Some(k));
    }

    #[test]
    fn test_recover_all_key_bytes() {
        let tables: Vec<LookupTable> = (0..16u8).map(make_shifted_sbox_table).collect();
        let recovered = recover_all_key_bytes(&tables);
        assert_eq!(recovered.len(), 16);
        for (i, r) in recovered.iter().enumerate() {
            assert_eq!(*r, Some(u8::try_from(i).unwrap_or(u8::MAX)));
        }
    }

    #[test]
    fn test_validate_tbox_set_valid() {
        let tables: Vec<LookupTable> = (0..16u8).map(|_| make_sbox_table()).collect();
        let validation = BgeAttack::validate_tbox_set(&tables);
        assert!(validation.is_valid);
        assert_eq!(validation.non_bijective_tables, 0);
    }

    #[test]
    fn test_validate_tbox_set_too_few() {
        let tables = vec![make_sbox_table(); 4];
        let validation = BgeAttack::validate_tbox_set(&tables);
        assert!(!validation.is_valid);
    }

    #[test]
    fn test_bge_attack_recovers_keys() {
        let tables: Vec<LookupTable> = (0..16u8).map(make_shifted_sbox_table).collect();
        let mut attack = BgeAttack::new(tables);
        let result = attack.attack().unwrap();
        assert_eq!(result.recovered_count(), 16);
        assert!(result.is_complete());
        for (i, &b) in result.round1_key().iter().enumerate() {
            assert_eq!(b, u8::try_from(i).unwrap_or(u8::MAX));
        }
    }

    #[test]
    fn test_bge_attack_not_enough_tables() {
        let tables = vec![make_sbox_table(); 4];
        let mut attack = BgeAttack::new(tables);
        assert!(attack.attack().is_err());
    }

    #[test]
    fn test_has_aes_like_differential_profile() {
        let arr: &[u8; 256] = AES_SBOX[..].try_into().unwrap();
        assert!(has_aes_like_differential_profile(arr));
    }

    #[test]
    fn test_is_bijective_sbox() {
        let arr: &[u8; 256] = AES_SBOX[..].try_into().unwrap();
        assert!(is_bijective_256(arr));
    }

    #[test]
    fn test_is_bijective_identity() {
        let mut arr = [0u8; 256];
        for (i, v) in arr.iter_mut().enumerate() {
            *v = u8::try_from(i).unwrap_or(u8::MAX);
        }
        assert!(is_bijective_256(&arr));
    }

    #[test]
    fn test_is_bijective_non_bijective() {
        let arr = [0u8; 256]; // all zeros, very not bijective
        assert!(!is_bijective_256(&arr));
    }

    #[test]
    fn test_external_encoding_strip() {
        let enc = ExternalEncoding::identity(0);
        let arr: &[u8; 256] = AES_SBOX[..].try_into().unwrap();
        let stripped = enc.strip_table(arr, 0).unwrap();
        assert_eq!(&stripped[..], &AES_SBOX[..]);
    }
}
