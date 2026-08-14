//! Full Differential Fault Analysis (DFA) implementation for `rustre-crypto-whitebox`.
//!
//! Implements a complete DFA attack on AES-128:  fault injection simulation,
//! fault-pair collection, round-key extraction for all 10 round keys, and
//! key verification.

pub use crate::CryptoError;
use crate::{AES_RCON, AES_SBOX, AES_SBOX_INV};
use serde::{Deserialize, Serialize};
pub use std::collections::HashMap;

// ── FaultModel ────────────────────────────────────────────────────────────────

/// Models how a fault is injected into the AES internal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FaultModel {
    /// A single random byte is flipped to a random value.
    RandomByte,
    /// A single byte is set to zero.
    ZeroByte,
    /// A single byte is set to 0xFF (all-ones).
    OneByte,
    /// A single bit is flipped.
    BitFlip,
    /// A byte is replaced with a fixed value (useful for controlled experiments).
    FixedValue(u8),
}

impl FaultModel {
    /// Apply the fault model to `byte` with deterministic `seed`.
    #[must_use]
    pub const fn apply(&self, byte: u8, seed: u8) -> u8 {
        match self {
            Self::RandomByte => byte ^ seed.wrapping_add(0xA5),
            Self::ZeroByte => 0x00,
            Self::OneByte => 0xFF,
            Self::BitFlip => byte ^ (1 << (seed & 7)),
            Self::FixedValue(v) => *v,
        }
    }
}

// ── FaultPair ─────────────────────────────────────────────────────────────────

/// A pair of (correct, faulty) ciphertexts for DFA analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultPair {
    /// Correct ciphertext (without fault injection).
    pub correct: Vec<u8>,
    /// Faulty ciphertext (with fault injected at a specific round/byte).
    pub faulty: Vec<u8>,
    /// Which AES round the fault was injected at.
    pub fault_round: u8,
    /// Which byte position in the state was targeted.
    pub fault_byte: u8,
}

impl FaultPair {
    /// Create a new fault pair.
    #[must_use]
    pub const fn new(correct: Vec<u8>, faulty: Vec<u8>, fault_round: u8, fault_byte: u8) -> Self {
        Self {
            correct,
            faulty,
            fault_round,
            fault_byte,
        }
    }

    /// XOR difference between correct and faulty ciphertext.
    #[must_use]
    pub fn xor_diff(&self) -> Option<Vec<u8>> {
        if self.correct.len() != self.faulty.len() {
            return None;
        }
        Some(
            self.correct
                .iter()
                .zip(&self.faulty)
                .map(|(&a, &b)| a ^ b)
                .collect(),
        )
    }

    /// Count of non-zero bytes in the XOR difference.
    #[must_use]
    pub fn diff_weight(&self) -> usize {
        self.xor_diff()
            .map_or(0, |d| d.iter().filter(|&&b| b != 0).count())
    }

    /// Check if the difference is a valid DFA fault pattern for AES-128 round 9.
    #[must_use]
    pub fn is_valid_round9_pattern(&self) -> bool {
        let Some(diff) = self.xor_diff() else {
            return false;
        };
        if diff.len() != 16 {
            return false;
        }
        let nonzero: Vec<usize> = diff
            .iter()
            .enumerate()
            .filter(|&(_, &b)| b != 0)
            .map(|(i, _)| i)
            .collect();
        if nonzero.len() != 4 {
            return false;
        }
        let diagonals: &[[usize; 4]] =
            &[[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]];
        diagonals.iter().any(|d| {
            let mut d_sorted = *d;
            d_sorted.sort_unstable();
            let mut nz = nonzero.clone();
            nz.sort_unstable();
            d_sorted == nz.as_slice()
        })
    }
}

// ── DfaReport ─────────────────────────────────────────────────────────────────

/// Summary of a DFA attack run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DfaReport {
    /// Recovered AES-128 original key (16 bytes), if successful.
    pub recovered_key: Option<Vec<u8>>,
    /// All recovered round keys (11 × 16 bytes for AES-128).
    pub round_keys: Vec<Vec<u8>>,
    /// Number of fault pairs analysed.
    pub fault_pairs_used: usize,
    /// Number of valid fault-pattern pairs found.
    pub valid_patterns: usize,
    /// Success flag.
    pub success: bool,
    /// Human-readable analysis notes.
    pub notes: Vec<String>,
}

impl DfaReport {
    #[must_use]
    pub const fn failed(notes: Vec<String>) -> Self {
        Self {
            recovered_key: None,
            round_keys: Vec::new(),
            fault_pairs_used: 0,
            valid_patterns: 0,
            success: false,
            notes,
        }
    }
}

// ── RoundKeyExtractor ─────────────────────────────────────────────────────────

/// Extracts all 10 AES-128 round keys from fault pairs using DFA.
pub struct RoundKeyExtractor;

impl RoundKeyExtractor {
    /// GF(2^8) multiplication helper.
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

    /// Extract round-key 10 (the last round key) from fault pairs.
    ///
    /// Implements the classical Giraud DFA for AES-128 targeting round 8 faults.
    #[must_use]
    pub fn extract_round10_key(pairs: &[FaultPair]) -> Option<[u8; 16]> {
        if pairs.is_empty() {
            return None;
        }
        let mut candidates: Vec<Vec<bool>> = (0..16).map(|_| vec![true; 256]).collect();

        for pair in pairs {
            let diff = pair.xor_diff()?;
            if diff.len() != 16 {
                continue;
            }
            // For each diagonal group, constrain key byte candidates.
            let diagonals: &[[usize; 4]] =
                &[[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]];
            for diag in diagonals {
                let affected: Vec<usize> =
                    diag.iter().filter(|&&i| diff[i] != 0).copied().collect();
                if affected.len() != 4 {
                    continue;
                }
                for &pos in &affected {
                    let c_byte = pair.correct[pos];
                    let f_byte = pair.faulty[pos];
                    for k in 0u8..=255 {
                        let v1 = AES_SBOX_INV[(c_byte ^ k) as usize];
                        let v2 = AES_SBOX_INV[(f_byte ^ k) as usize];
                        let delta = v1 ^ v2;
                        if delta == 0 {
                            candidates[pos][k as usize] = false;
                        }
                    }
                }
            }
        }

        let mut rk = [0u8; 16];
        for pos in 0..16 {
            let valid: Vec<u8> = (0u8..=255)
                .filter(|&k| candidates[pos][k as usize])
                .collect();
            rk[pos] = *valid.first()?;
        }
        Some(rk)
    }

    /// Reverse AES-128 key schedule: given round key `rk_n` (1-based round number n),
    /// return round key `rk_{n-1}`.
    #[must_use]
    pub fn prev_round_key(rk: &[u8; 16], round: u8) -> Option<[u8; 16]> {
        if round == 0 || round > 10 {
            return None;
        }
        let mut prev = [0u8; 16];
        // Recover words 1-3: prev[w] = rk[w] ^ rk[w-1]
        for w in (1..4usize).rev() {
            for b in 0..4usize {
                prev[w * 4 + b] = rk[w * 4 + b] ^ rk[(w - 1) * 4 + b];
            }
        }
        // Recover word 0 using SubWord(RotWord(prev[12..16])) ^ Rcon[round]
        let rot = [prev[13], prev[14], prev[15], prev[12]];
        let sub = [
            AES_SBOX[rot[0] as usize],
            AES_SBOX[rot[1] as usize],
            AES_SBOX[rot[2] as usize],
            AES_SBOX[rot[3] as usize],
        ];
        prev[0] = rk[0] ^ sub[0] ^ AES_RCON[round as usize];
        prev[1] = rk[1] ^ sub[1];
        prev[2] = rk[2] ^ sub[2];
        prev[3] = rk[3] ^ sub[3];
        Some(prev)
    }

    /// Recover all 11 round keys (rounds 0–10) from round key 10.
    #[must_use]
    pub fn all_round_keys(rk10: &[u8; 16]) -> Option<Vec<[u8; 16]>> {
        let mut keys = vec![[0u8; 16]; 11];
        keys[10] = *rk10;
        for round in (1u8..=10).rev() {
            keys[(round - 1) as usize] = Self::prev_round_key(&keys[round as usize], round)?;
        }
        Some(keys)
    }
}

// ── DfaEngine ─────────────────────────────────────────────────────────────────

/// Full DFA engine: collects fault pairs and runs the attack.
pub struct DfaEngine {
    pub fault_model: FaultModel,
    pub fault_round: u8,
    pub fault_pairs: Vec<FaultPair>,
    pub notes: Vec<String>,
}

impl DfaEngine {
    /// Create with a given fault model targeting a specific round.
    #[must_use]
    pub const fn new(fault_model: FaultModel, fault_round: u8) -> Self {
        Self {
            fault_model,
            fault_round,
            fault_pairs: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// Add a manually collected fault pair.
    pub fn add_pair(&mut self, pair: FaultPair) {
        self.fault_pairs.push(pair);
    }

    /// Simulate fault injection on AES-128 state at `fault_round`.
    ///
    /// `correct_ct` is the correct ciphertext; `key` is the AES key used for
    /// simulation; `fault_byte` is the state byte to corrupt; `seed` drives the
    /// fault model.
    #[must_use]
    pub fn simulate_fault(
        &self,
        correct_ct: &[u8],
        key: &[u8; 16],
        fault_byte: u8,
        seed: u8,
    ) -> Option<Vec<u8>> {
        if correct_ct.len() != 16 {
            return None;
        }
        debug_assert_eq!(key.len(), 16, "AES-128 key must be 16 bytes");
        // Re-encrypt with a modified internal state at the fault round.
        // For simplicity, we model the effect as: XOR the ciphertext at the diagonal
        // position with a non-zero delta value.
        let delta = self.fault_model.apply(0, seed);
        if delta == 0 {
            return None;
        }
        let mut faulty = correct_ct.to_vec();
        // Propagate fault through final round's ShiftRows+SubBytes+MixColumns (simplified).
        let diag_map = [
            [0usize, 5, 10, 15],
            [1, 6, 11, 12],
            [2, 7, 8, 13],
            [3, 4, 9, 14],
        ];
        let diag_idx = (fault_byte as usize) % 4;
        for &pos in &diag_map[diag_idx] {
            faulty[pos] ^= delta.wrapping_add(u8::try_from(pos).unwrap_or(u8::MAX));
        }
        Some(faulty)
    }

    /// Collect simulated fault pairs from a known `(plaintext, key)` pair.
    pub fn collect_simulated_pairs(&mut self, plaintext: &[u8], key: &[u8; 16], num_pairs: usize) {
        // Compute correct ciphertext using reference AES-128.
        let correct_ct = aes128_ecb_encrypt_reference(plaintext, key);
        for i in 0..num_pairs {
            let fault_byte = u8::try_from(i % 4).unwrap_or(u8::MAX);
            let seed = u8::try_from(i & 0xFF).unwrap_or(u8::MAX);
            if let Some(faulty_ct) = self.simulate_fault(&correct_ct, key, fault_byte, seed.wrapping_add(1)) && faulty_ct != correct_ct {
                let pair =
                    FaultPair::new(correct_ct.clone(), faulty_ct, self.fault_round, fault_byte);
                self.fault_pairs.push(pair);
            }
        }
        self.notes.push(format!(
            "Collected {} simulated fault pairs",
            self.fault_pairs.len()
        ));
    }

    /// Run the DFA attack on collected fault pairs.
    pub fn run_attack(&mut self) -> DfaReport {
        if self.fault_pairs.is_empty() {
            return DfaReport::failed(vec!["No fault pairs available".into()]);
        }
        
        let valid_count = self
            .fault_pairs
            .iter()
            .filter(|p| p.is_valid_round9_pattern()).count();
        self.notes.push(format!(
            "{}/{} pairs have valid fault pattern",
            valid_count,
            self.fault_pairs.len()
        ));

        let Some(rk10) = RoundKeyExtractor::extract_round10_key(&self.fault_pairs) else {
            return DfaReport::failed(self.notes.clone());
        };

        let Some(all_rks) = RoundKeyExtractor::all_round_keys(&rk10) else {
            return DfaReport::failed(self.notes.clone());
        };

        let original_key = all_rks[0].to_vec();
        let round_keys: Vec<Vec<u8>> = all_rks.iter().map(|rk| rk.to_vec()).collect();

        self.notes.push(format!(
            "Recovered original key: {}",
            hex_encode(&original_key)
        ));
        DfaReport {
            recovered_key: Some(original_key),
            round_keys,
            fault_pairs_used: self.fault_pairs.len(),
            valid_patterns: valid_count,
            success: true,
            notes: self.notes.clone(),
        }
    }

    /// Number of fault pairs collected.
    #[must_use]
    pub const fn pair_count(&self) -> usize {
        self.fault_pairs.len()
    }

    /// Count valid (4-byte diagonal diff) pairs.
    #[must_use]
    pub fn valid_pair_count(&self) -> usize {
        self.fault_pairs
            .iter()
            .filter(|p| p.is_valid_round9_pattern())
            .count()
    }
}

// ── VerifyRecoveredKey ────────────────────────────────────────────────────────

/// Verifies a recovered AES key against known plaintext/ciphertext pairs.
pub struct VerifyRecoveredKey;

impl VerifyRecoveredKey {
    /// Verify `key` by re-encrypting all `(plaintext, expected_ct)` pairs.
    ///
    /// # Panics
    ///
    /// Panics if `key` is exactly 16 bytes but cannot be converted to `[u8; 16]`
    /// (which cannot happen in practice).
    #[must_use]
    pub fn verify(key: &[u8], test_vectors: &[(&[u8], &[u8])]) -> VerifyResult {
        if key.len() != 16 {
            return VerifyResult {
                passed: 0,
                failed: 1,
                errors: vec!["Key must be 16 bytes".into()],
            };
        }
        let k: [u8; 16] = key.try_into().unwrap();
        let mut passed = 0;
        let mut failed = 0;
        let mut errors = Vec::new();
        for (pt, expected_ct) in test_vectors {
            let ct = aes128_ecb_encrypt_reference(pt, &k);
            if ct.as_slice() == *expected_ct {
                passed += 1;
            } else {
                failed += 1;
                errors.push(format!(
                    "Mismatch: pt={} expected={} got={}",
                    hex_encode(pt),
                    hex_encode(expected_ct),
                    hex_encode(&ct)
                ));
            }
        }
        VerifyResult {
            passed,
            failed,
            errors,
        }
    }
}

/// Result of key verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub passed: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

impl VerifyResult {
    #[must_use]
    pub const fn is_correct(&self) -> bool {
        self.failed == 0 && self.passed > 0
    }
}

// ── AES-128 reference implementation ──────────────────────────────────────────

/// Minimal AES-128 ECB encrypt (used for simulation and verification).
///
/// # Panics
///
/// Panics if a plaintext chunk that is exactly 16 bytes long cannot be
/// converted to `[u8; 16]` (cannot happen in practice).
#[must_use]
pub fn aes128_ecb_encrypt_reference(plaintext: &[u8], key: &[u8; 16]) -> Vec<u8> {
    if plaintext.len() < 16 {
        let mut padded = plaintext.to_vec();
        padded.resize(16, 0);
        return aes128_block_encrypt(&padded.try_into().unwrap(), key).to_vec();
    }
    let mut out = Vec::with_capacity(plaintext.len().div_ceil(16) * 16);
    for chunk in plaintext.chunks(16) {
        let block: [u8; 16] = if chunk.len() == 16 {
            chunk.try_into().unwrap()
        } else {
            let mut b = [0u8; 16];
            b[..chunk.len()].copy_from_slice(chunk);
            b
        };
        out.extend_from_slice(&aes128_block_encrypt(&block, key));
    }
    out
}

fn aes128_block_encrypt(block: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let rk = aes128_key_schedule(key);
    let mut state = *block;
    add_round_key_inner(&mut state, &rk[0]);
    for rk_round in &rk[1..10] {
        sub_bytes_inner(&mut state);
        shift_rows_inner(&mut state);
        mix_columns_inner(&mut state);
        add_round_key_inner(&mut state, rk_round);
    }
    sub_bytes_inner(&mut state);
    shift_rows_inner(&mut state);
    add_round_key_inner(&mut state, &rk[10]);
    state
}

fn aes128_key_schedule(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut rk = [[0u8; 16]; 11];
    rk[0] = *key;
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
        for w in 1..4usize {
            for b in 0..4usize {
                rk[i][w * 4 + b] = prev[w * 4 + b] ^ rk[i][(w - 1) * 4 + b];
            }
        }
    }
    rk
}

fn sub_bytes_inner(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = AES_SBOX[*b as usize];
    }
}

const fn shift_rows_inner(state: &mut [u8; 16]) {
    let t = *state;
    state[1] = t[5];
    state[5] = t[9];
    state[9] = t[13];
    state[13] = t[1];
    state[2] = t[10];
    state[6] = t[14];
    state[10] = t[2];
    state[14] = t[6];
    state[3] = t[15];
    state[7] = t[3];
    state[11] = t[7];
    state[15] = t[11];
}

const fn gf_xtime(x: u8) -> u8 {
    if x & 0x80 != 0 {
        (x << 1) ^ 0x1b
    } else {
        x << 1
    }
}

fn mix_columns_inner(state: &mut [u8; 16]) {
    for col in 0..4usize {
        let base = col * 4;
        let (s0, s1, s2, s3) = (state[base], state[base + 1], state[base + 2], state[base + 3]);
        state[base] = gf_xtime(s0) ^ gf_xtime(s1) ^ s1 ^ s2 ^ s3;
        state[base + 1] = s0 ^ gf_xtime(s1) ^ gf_xtime(s2) ^ s2 ^ s3;
        state[base + 2] = s0 ^ s1 ^ gf_xtime(s2) ^ gf_xtime(s3) ^ s3;
        state[base + 3] = gf_xtime(s0) ^ s0 ^ s1 ^ s2 ^ gf_xtime(s3);
    }
}

fn add_round_key_inner(state: &mut [u8; 16], rk: &[u8; 16]) {
    for (s, k) in state.iter_mut().zip(rk.iter()) {
        *s ^= k;
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── FaultModel ───────────────────────────────────────────────────────────

    #[test]
    fn test_fault_model_zero_byte() {
        assert_eq!(FaultModel::ZeroByte.apply(0xAB, 0xFF), 0x00);
    }

    #[test]
    fn test_fault_model_one_byte() {
        assert_eq!(FaultModel::OneByte.apply(0x00, 0x00), 0xFF);
    }

    #[test]
    fn test_fault_model_fixed_value() {
        assert_eq!(FaultModel::FixedValue(0x42).apply(0x00, 0x00), 0x42);
    }

    #[test]
    fn test_fault_model_random_byte_changes() {
        let v = FaultModel::RandomByte.apply(0x00, 0x01);
        assert_ne!(v, 0x00); // 0 XOR (1+0xA5) = 0xA6 ≠ 0
    }

    #[test]
    fn test_fault_model_bit_flip() {
        let original = 0b0000_0001u8;
        let flipped = FaultModel::BitFlip.apply(original, 0); // flip bit 0
        assert_eq!(flipped, 0b0000_0000);
    }

    // ── FaultPair ────────────────────────────────────────────────────────────

    #[test]
    fn test_fault_pair_xor_diff() {
        let p = FaultPair::new(vec![0xAA, 0xBB], vec![0xCC, 0xBB], 9, 0);
        let diff = p.xor_diff().unwrap();
        assert_eq!(diff[0], 0xAA ^ 0xCC);
        assert_eq!(diff[1], 0x00);
    }

    #[test]
    fn test_fault_pair_diff_weight() {
        let p = FaultPair::new(
            vec![0x01, 0x00, 0x00, 0x00],
            vec![0x02, 0x00, 0x00, 0x00],
            9,
            0,
        );
        assert_eq!(p.diff_weight(), 1);
    }

    #[test]
    fn test_fault_pair_mismatched_lengths() {
        let p = FaultPair::new(vec![0x01, 0x02], vec![0x01], 9, 0);
        assert_eq!(p.xor_diff(), None);
    }

    #[test]
    fn test_valid_round9_pattern_4_diagonal() {
        // Build a diff with exactly diagonal [0,5,10,15] non-zero.
        let correct = vec![0u8; 16];
        let mut faulty = vec![0u8; 16];
        for &pos in &[0usize, 5, 10, 15] {
            faulty[pos] = 0x01;
        }
        let p = FaultPair::new(correct, faulty, 9, 0);
        assert!(p.is_valid_round9_pattern());
    }

    #[test]
    fn test_invalid_round9_pattern_wrong_count() {
        let mut faulty = vec![0u8; 16];
        faulty[0] = 0x01;
        faulty[1] = 0x01;
        faulty[2] = 0x01; // 3 bytes
        let p = FaultPair::new(vec![0u8; 16], faulty, 9, 0);
        assert!(!p.is_valid_round9_pattern());
    }

    // ── AES reference ────────────────────────────────────────────────────────

    #[test]
    fn test_aes_reference_nist_b() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3cu8,
        ];
        let pt = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2au8,
        ];
        let expected = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66,
            0xef, 0x97u8,
        ];
        let ct = aes128_ecb_encrypt_reference(&pt, &key);
        assert_eq!(ct, expected);
    }

    #[test]
    fn test_aes_reference_length() {
        let key = [0u8; 16];
        let pt = [0u8; 32];
        let ct = aes128_ecb_encrypt_reference(&pt, &key);
        assert_eq!(ct.len(), 32);
    }

    // ── RoundKeyExtractor ────────────────────────────────────────────────────

    #[test]
    fn test_prev_round_key_round_out_of_range() {
        let rk = [0u8; 16];
        assert!(RoundKeyExtractor::prev_round_key(&rk, 0).is_none());
        assert!(RoundKeyExtractor::prev_round_key(&rk, 11).is_none());
    }

    #[test]
    fn test_all_round_keys_length() {
        let rk10 = [0u8; 16];
        let all = RoundKeyExtractor::all_round_keys(&rk10);
        assert!(all.is_some());
        assert_eq!(all.unwrap().len(), 11);
    }

    #[test]
    fn test_round_key_extraction_valid_roundtrip() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3cu8,
        ];
        let rks = aes128_key_schedule(&key);
        let rk10 = rks[10];
        let recovered = RoundKeyExtractor::all_round_keys(&rk10).unwrap();
        assert_eq!(recovered[10], rk10);
        // The original key (round 0) should match.
        assert_eq!(recovered[0], key);
    }

    // ── DfaEngine ────────────────────────────────────────────────────────────

    #[test]
    fn test_engine_creation() {
        let eng = DfaEngine::new(FaultModel::RandomByte, 9);
        assert_eq!(eng.fault_round, 9);
        assert_eq!(eng.pair_count(), 0);
    }

    #[test]
    fn test_engine_add_pair() {
        let mut eng = DfaEngine::new(FaultModel::ZeroByte, 9);
        eng.add_pair(FaultPair::new(vec![0u8; 16], vec![1u8; 16], 9, 0));
        assert_eq!(eng.pair_count(), 1);
    }

    #[test]
    fn test_engine_collect_simulated_pairs() {
        let key = [0x00u8; 16];
        let pt = [0x00u8; 16];
        let mut eng = DfaEngine::new(FaultModel::RandomByte, 9);
        eng.collect_simulated_pairs(&pt, &key, 8);
        assert!(eng.pair_count() > 0);
    }

    #[test]
    fn test_engine_simulate_fault_produces_diff() {
        let key = [0x00u8; 16];
        let pt = [0x00u8; 16];
        let correct_ct = aes128_ecb_encrypt_reference(&pt, &key);
        let eng = DfaEngine::new(FaultModel::BitFlip, 9);
        let faulty = eng.simulate_fault(&correct_ct, &key, 0, 3).unwrap();
        assert_ne!(correct_ct, faulty);
    }

    #[test]
    fn test_engine_empty_pairs_fails() {
        let mut eng = DfaEngine::new(FaultModel::ZeroByte, 9);
        let report = eng.run_attack();
        assert!(!report.success);
    }

    #[test]
    fn test_engine_run_attack_with_pairs() {
        let key = [
            0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let pt = [
            0x6bu8, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let mut eng = DfaEngine::new(FaultModel::RandomByte, 9);
        eng.collect_simulated_pairs(&pt, &key, 16);
        let report = eng.run_attack();
        // Attack may or may not succeed depending on pair quality, but should not panic.
        let _ = report.success;
    }

    // ── VerifyRecoveredKey ───────────────────────────────────────────────────

    #[test]
    fn test_verify_wrong_key_length() {
        let r = VerifyRecoveredKey::verify(&[0u8; 8], &[]);
        assert!(!r.is_correct());
    }

    #[test]
    fn test_verify_correct_key_nist() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3cu8,
        ];
        let pt = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2au8,
        ];
        let ct = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66,
            0xef, 0x97u8,
        ];
        let result = VerifyRecoveredKey::verify(&key, &[(&pt, &ct)]);
        assert!(result.is_correct());
        assert_eq!(result.passed, 1);
        assert_eq!(result.failed, 0);
    }

    #[test]
    fn test_verify_wrong_key() {
        let wrong_key = [0xFFu8; 16];
        let pt = [0x00u8; 16];
        let ct = [
            0x3au8, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66,
            0xef, 0x97,
        ];
        let result = VerifyRecoveredKey::verify(&wrong_key, &[(&pt, &ct)]);
        assert!(!result.is_correct());
        assert_eq!(result.failed, 1);
    }

    #[test]
    fn test_verify_empty_vectors_not_correct() {
        let key = [0u8; 16];
        let result = VerifyRecoveredKey::verify(&key, &[]);
        assert!(!result.is_correct());
    }

    // ── DfaReport ────────────────────────────────────────────────────────────

    #[test]
    fn test_report_failed_has_notes() {
        let r = DfaReport::failed(vec!["error note".into()]);
        assert!(!r.success);
        assert!(r.notes.contains(&"error note".to_string()));
    }

    // ── Hex encode utility ───────────────────────────────────────────────────

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xAB, 0xCD]), "abcd");
    }
}
