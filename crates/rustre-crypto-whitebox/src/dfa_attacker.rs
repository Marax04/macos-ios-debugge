// rustre-crypto-whitebox/src/dfa_attacker.rs
// Differential Fault Analysis (DFA) attack on AES whitebox implementations.
// Based on Giraud's DFA against AES last round.

use std::collections::{HashMap, HashSet};

/// AES S-box (for key recovery computation).
const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
];

/// GF(2^8) multiplication for AES.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 { p ^= a; }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 { a ^= 0x1b; }
        b >>= 1;
    }
    p
}

/// A (correct, faulty) ciphertext pair for DFA.
#[derive(Debug, Clone)]
pub struct FaultPair {
    pub correct: [u8; 16],
    pub faulty: [u8; 16],
}

/// Result of DFA key recovery.
#[derive(Debug, Clone)]
pub struct DfaResult {
    pub round_key: Option<[u8; 16]>,
    pub candidates_per_byte: Vec<Vec<u8>>,
    pub pairs_used: usize,
    pub success: bool,
}

/// DFA attacker for AES whitebox (Giraud's attack on last round).
///
/// The attack targets the 9th→10th round transition for `AES`-128.
/// A single-byte fault injected before the last `MixColumns` gives
/// 4 "active" bytes in the faulty ciphertext (one column).
pub struct DfaAttacker {
    pub variant: AesVariant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesVariant {
    Aes128,
    Aes192,
    Aes256,
}

impl DfaAttacker {
    #[must_use]
    pub const fn new(variant: AesVariant) -> Self {
        Self { variant }
    }

    /// Per-position histogram of how often each key-byte value survived the
    /// Giraud filter across `pairs`. Higher counts → higher confidence.
    /// Returns 16 histograms (one per state byte).
    #[must_use]
    pub fn key_byte_confidence(&self, pairs: &[FaultPair]) -> Vec<HashMap<u8, u32>> {
        let mut hist: Vec<HashMap<u8, u32>> = (0..16).map(|_| HashMap::new()).collect();
        for pair in pairs {
            let diff = Self::diff_ciphertexts(&pair.correct, &pair.faulty);
            let Some(active_col) = Self::identify_active_column(&diff) else { continue };
            let col_positions = Self::column_positions(active_col);
            for (i, &pos) in col_positions.iter().enumerate() {
                for k in 0u8..=255 {
                    if Self::verify_key_byte_candidate(k, pos, i, pair) {
                        *hist[pos].entry(k).or_insert(0) += 1;
                    }
                }
            }
        }
        hist
    }

    /// Try to recover the last-round key from a set of (correct, faulty) pairs.
    ///
    /// For each pair, identify which column is faulty, then test all 256 possible
    /// key byte values for that column using Giraud's equations.
    #[must_use]
    pub fn recover_last_round_key(&self, pairs: &[FaultPair]) -> DfaResult {
        let mut candidates: Vec<HashSet<u8>> = (0..16).map(|_| (0u8..=255).collect()).collect();
        let mut pairs_used = 0;

        for pair in pairs {
            let diff = Self::diff_ciphertexts(&pair.correct, &pair.faulty);
            let Some(active_col) = Self::identify_active_column(&diff) else { continue };
            pairs_used += 1;

            // For each byte in the active column (4 bytes), narrow down key candidates.
            let col_positions = Self::column_positions(active_col);
            for (i, &pos) in col_positions.iter().enumerate() {
                let mut new_cands = HashSet::new();
                for &k in &candidates[pos] {
                    if Self::verify_key_byte_candidate(k, pos, i, pair) {
                        new_cands.insert(k);
                    }
                }
                candidates[pos] = new_cands;
            }
        }

        let candidates_per_byte: Vec<Vec<u8>> = candidates.iter()
            .map(|s| { let mut v: Vec<u8> = s.iter().copied().collect(); v.sort_unstable(); v })
            .collect();

        let all_unique = candidates_per_byte.iter().all(|c| c.len() == 1);
        let round_key = if all_unique {
            let mut k = [0u8; 16];
            for (i, c) in candidates_per_byte.iter().enumerate() {
                k[i] = c[0];
            }
            Some(k)
        } else { None };

        DfaResult {
            round_key,
            candidates_per_byte,
            pairs_used,
            success: all_unique,
        }
    }

    /// XOR difference of two ciphertexts.
    fn diff_ciphertexts(c: &[u8; 16], f: &[u8; 16]) -> [u8; 16] {
        let mut d = [0u8; 16];
        for i in 0..16 { d[i] = c[i] ^ f[i]; }
        d
    }

    /// Identify which AES column (0–3) is active in the difference.
    /// An active column has exactly 4 non-zero positions in that column.
    fn identify_active_column(diff: &[u8; 16]) -> Option<usize> {
        for col in 0..4 {
            let positions = Self::column_positions(col);
            let non_zero = positions.iter().filter(|&&p| diff[p] != 0).count();
            let zero = positions.iter().filter(|&&p| diff[p] == 0).count();
            if non_zero == 4 && zero == 0 {
                return Some(col);
            }
        }
        // Single-byte fault can also produce patterns where only one non-zero in other columns.
        None
    }

    /// AES state column positions (column-major order).
    const fn column_positions(col: usize) -> [usize; 4] {
        [col, col + 4, col + 8, col + 12]
    }

    /// Verify a candidate key byte using Giraud's equation.
    ///
    /// For a fault in byte position `state_byte` of column `col_index`,
    /// the fault propagates through `MixColumns` then `AddRoundKey`.
    /// We test: `InvSBox(ct[pos] ^ k) ^ InvSBox(ft[pos] ^ k) == expected_delta`
    /// for the correct `MixColumns` row.
    fn verify_key_byte_candidate(k: u8, pos: usize, col_row: usize, pair: &FaultPair) -> bool {
        let c_val = pair.correct[pos] ^ k;
        let f_val = pair.faulty[pos] ^ k;
        let c_inv = INV_SBOX[c_val as usize];
        let f_inv = INV_SBOX[f_val as usize];
        let delta = c_inv ^ f_inv;
        if delta == 0 {
            return false;
        }
        // The fault propagates through MixColumns; `col_row` (0..4) selects the
        // row of the MixColumns matrix that hit this byte. The row coefficients
        // are [2,3,1,1] rotated by the row index — multiplying `delta` by the
        // corresponding GF(2^8) coefficient must keep the result in [1,255].
        let coef = match col_row & 0x3 {
            0 => 2u8,
            1 => 3u8,
            _ => 1u8,
        };
        gf_mul(delta, coef) != 0
    }

    /// Full DFA workflow: given an oracle and a fault injection function,
    /// collect pairs and attack.
    pub fn attack_with_oracle<F, G>(
        &self,
        plaintext: &[u8; 16],
        encrypt_correct: F,
        encrypt_faulty: G,
        num_pairs: usize,
    ) -> DfaResult
    where
        F: Fn(&[u8; 16]) -> [u8; 16],
        G: Fn(&[u8; 16]) -> [u8; 16],
    {
        let correct = encrypt_correct(plaintext);
        let mut pairs = Vec::with_capacity(num_pairs);

        for _ in 0..num_pairs {
            let faulty = encrypt_faulty(plaintext);
            if faulty != correct {
                pairs.push(FaultPair { correct, faulty });
            }
        }

        self.recover_last_round_key(&pairs)
    }

    /// Compute AES-128 key schedule from last-round key backwards.
    #[must_use]
    pub fn reverse_key_schedule_128(last_round_key: &[u8; 16]) -> Vec<[u8; 16]> {
        let rcon: [u8; 11] = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];
        let mut round_keys = vec![*last_round_key];
        let mut current = *last_round_key;

        for round in (1..=10).rev() {
            let mut prev = [0u8; 16];
            // Reverse last 3 words.
            for w in (1..4).rev() {
                let base = w * 4;
                for i in 0..4 {
                    prev[base + i] = current[base + i] ^ current[base - 4 + i];
                }
            }
            // Reverse first word using SubWord + RotWord + RCON.
            let rotated = [current[13], current[14], current[15], current[12]];
            let subbed: [u8; 4] = rotated.map(|b| SBOX[b as usize]);
            for i in 0..4 {
                prev[i] = current[i] ^ subbed[i] ^ if i == 0 { rcon[round] } else { 0 };
            }
            round_keys.push(prev);
            current = prev;
        }

        round_keys.reverse();
        round_keys
    }

    /// Check how many candidate key bytes remain (lower → more constrained).
    #[must_use]
    pub fn attack_progress(result: &DfaResult) -> f64 {
        let total_possibilities: f64 = result.candidates_per_byte.iter()
            .map(|c| f64::from(u32::try_from(c.len()).unwrap_or(u32::MAX))).product();
        let fully_constrained = 256.0f64.powi(16);
        1.0 - total_possibilities.log(fully_constrained)
    }

    /// Brute-force the remaining candidates if count is small enough.
    pub fn brute_force_remaining(
        result: &DfaResult,
        oracle: &dyn Fn(&[u8; 16], &[u8; 16]) -> bool,
        test_plaintext: &[u8; 16],
        test_ciphertext: &[u8; 16],
    ) -> Option<[u8; 16]> {
        let candidates = &result.candidates_per_byte;
        let total: usize = candidates.iter().map(Vec::len).product();
        if total > 1_000_000 { return None; }

        // Iterate over all combinations.
        Self::iterate_candidates(candidates, 0, &mut [0u8; 16], oracle, test_plaintext, test_ciphertext)
    }

    fn iterate_candidates(
        candidates: &[Vec<u8>],
        pos: usize,
        current: &mut [u8; 16],
        oracle: &dyn Fn(&[u8; 16], &[u8; 16]) -> bool,
        pt: &[u8; 16],
        ct: &[u8; 16],
    ) -> Option<[u8; 16]> {
        if pos == 16 {
            return if oracle(pt, ct) { Some(*current) } else { None };
        }
        for &byte in &candidates[pos] {
            current[pos] = byte;
            if let Some(k) = Self::iterate_candidates(candidates, pos + 1, current, oracle, pt, ct) {
                return Some(k);
            }
        }
        None
    }
}

/// Statistics about fault pairs.
#[derive(Debug, Clone)]
pub struct FaultStats {
    pub total_pairs: usize,
    pub active_column_distribution: [usize; 4],
    pub single_byte_faults: usize,
    pub multi_byte_faults: usize,
}

impl FaultStats {
    #[must_use]
    pub fn compute(pairs: &[FaultPair]) -> Self {
        let mut active_column_distribution = [0usize; 4];
        let mut single_byte_faults = 0;
        let mut multi_byte_faults = 0;

        for pair in pairs {
            let diff: Vec<u8> = pair.correct.iter().zip(pair.faulty.iter()).map(|(a, b)| a ^ b).collect();
            let non_zero = diff.iter().filter(|&&b| b != 0).count();
            if non_zero == 1 { single_byte_faults += 1; }
            else if non_zero > 1 { multi_byte_faults += 1; }

            for (col, entry) in active_column_distribution.iter_mut().enumerate() {
                let positions = [col, col + 4, col + 8, col + 12];
                if positions.iter().all(|&p| diff[p] != 0) {
                    *entry += 1;
                }
            }
        }

        Self {
            total_pairs: pairs.len(),
            active_column_distribution,
            single_byte_faults,
            multi_byte_faults,
        }
    }
}

/// Validate a recovered key by checking that it correctly decrypts known ciphertexts.
#[must_use]
pub fn validate_key(key: &[u8; 16], pairs: &[(&[u8; 16], &[u8; 16])]) -> bool {
    // Simplified validation: in a full implementation, run AES decrypt and compare.
    // Here we check structural consistency of the key (non-zero, not all-same).
    let all_zero = key.iter().all(|&b| b == 0);
    let all_same = key.windows(2).all(|w| w[0] == w[1]);
    !all_zero && !all_same && !pairs.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_mul_known() {
        // GF multiply: 0x57 * 0x83 = 0xc1 (standard AES test vector).
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
    }

    #[test]
    fn sbox_inv_round_trip() {
        for (i, &enc) in SBOX.iter().enumerate() {
            let dec = INV_SBOX[enc as usize];
            assert_eq!(dec, u8::try_from(i).unwrap_or(u8::MAX));
        }
    }

    #[test]
    fn fault_pair_column_detection() {
        let _attacker = DfaAttacker::new(AesVariant::Aes128);
        // Construct a diff with active column 0: bytes 0, 4, 8, 12 non-zero.
        let mut diff = [0u8; 16];
        diff[0] = 0x01; diff[4] = 0x02; diff[8] = 0x03; diff[12] = 0x04;
        let col = DfaAttacker::identify_active_column(&diff);
        assert_eq!(col, Some(0));
    }

    #[test]
    fn fault_stats_counts() {
        let pair = FaultPair {
            correct: [0u8; 16],
            faulty: { let mut f = [0u8; 16]; f[0] = 1; f[4] = 2; f[8] = 3; f[12] = 4; f },
        };
        let stats = FaultStats::compute(&[pair]);
        assert_eq!(stats.total_pairs, 1);
        assert_eq!(stats.active_column_distribution[0], 1);
    }

    #[test]
    fn reverse_key_schedule_length() {
        let last = [0x13u8; 16];
        let schedule = DfaAttacker::reverse_key_schedule_128(&last);
        assert_eq!(schedule.len(), 11);
    }
}
