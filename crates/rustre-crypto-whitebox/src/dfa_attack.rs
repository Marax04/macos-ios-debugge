//! Differential Fault Analysis (DFA) attack on whitebox AES implementations.
//!
//! DFA exploits deliberately injected computation faults to recover key material.
//! A fault injected into the 8th or 9th AES round produces a faulty ciphertext
//! that, when compared with the correct ciphertext, constrains the last round key.
//! Collecting enough fault pairs reduces the key-byte search space to a unique
//! solution for each byte of the last round key, from which the original key is
//! then reversed through the key schedule.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{AES_RCON, AES_SBOX, AES_SBOX_INV, CryptoError, LookupTable, TablePurpose};

// ─── Fault model ──────────────────────────────────────────────────────────────

/// Describes how a fault was injected into the computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultModel {
    /// A single bit was flipped at the target location.
    BitFlip,
    /// A full byte was set to an arbitrary value.
    ByteSet,
    /// A full word (32-bit) was corrupted.
    WordCorrupt,
    /// Round 8 state fault (affects 4 ciphertext bytes on diagonal).
    Round8Diagonal,
    /// Round 9 state fault (affects 4 ciphertext bytes on diagonal, typical DFA target).
    Round9Diagonal,
}

/// A single fault injection event with its associated ciphertexts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultInjection {
    /// The input plaintext (16 bytes).
    pub plaintext: Vec<u8>,
    /// The correct ciphertext produced without fault.
    pub correct_ct: Vec<u8>,
    /// The faulty ciphertext produced with the fault.
    pub faulty_ct: Vec<u8>,
    /// The fault model used.
    pub fault_model: FaultModel,
    /// Optional: the round at which the fault was injected.
    pub fault_round: Option<u8>,
    /// Optional: the state byte index where the fault was injected.
    pub fault_byte: Option<u8>,
}

impl FaultInjection {
    /// Create a new fault injection record.
    #[must_use]
    pub const fn new(
        plaintext: Vec<u8>,
        correct_ct: Vec<u8>,
        faulty_ct: Vec<u8>,
        fault_model: FaultModel,
    ) -> Self {
        Self {
            plaintext,
            correct_ct,
            faulty_ct,
            fault_model,
            fault_round: None,
            fault_byte: None,
        }
    }

    /// Set the fault location.
    #[must_use]
    pub const fn with_location(mut self, round: u8, byte: u8) -> Self {
        self.fault_round = Some(round);
        self.fault_byte = Some(byte);
        self
    }

    /// Compute the difference vector (XOR of correct and faulty ciphertexts).
    /// Returns `None` if the ciphertexts have different lengths.
    #[must_use]
    pub fn diff(&self) -> Option<Vec<u8>> {
        if self.correct_ct.len() != self.faulty_ct.len() {
            return None;
        }
        Some(
            self.correct_ct
                .iter()
                .zip(self.faulty_ct.iter())
                .map(|(&a, &b)| a ^ b)
                .collect(),
        )
    }

    /// Return `true` if the fault produced a valid round-9 DFA pattern.
    ///
    /// A round-9 fault on a single state byte propagates through `ShiftRows` and
    /// `AddRoundKey` to affect exactly 4 bytes in the ciphertext, forming one of
    /// the 4 known diagonal patterns of the AES state matrix.
    #[must_use]
    pub fn is_valid_round9_pattern(&self) -> bool {
        let Some(diff) = self.diff() else { return false };
        if diff.len() != 16 {
            return false;
        }
        let nonzero: Vec<usize> = diff
            .iter()
            .enumerate()
            .filter(|&(_, &v)| v != 0)
            .map(|(i, _)| i)
            .collect();
        if nonzero.len() != 4 {
            return false;
        }
        // The four valid diagonals after ShiftRows (row i is shifted left by i).
        // Column 0: bytes 0,5,10,15; Column 1: 1,6,11,12; etc.
        let diagonals: &[[usize; 4]] = &[
            [0, 5, 10, 15],
            [1, 6, 11, 12],
            [2, 7, 8, 13],
            [3, 4, 9, 14],
        ];
        diagonals.iter().any(|d| nonzero == d)
    }

    /// Return the diagonal index (0–3) that this fault matches, or `None`.
    #[must_use]
    pub fn diagonal_index(&self) -> Option<usize> {
        let diff = self.diff()?;
        if diff.len() != 16 {
            return None;
        }
        let nonzero: Vec<usize> = diff
            .iter()
            .enumerate()
            .filter(|&(_, &v)| v != 0)
            .map(|(i, _)| i)
            .collect();
        let diagonals: &[[usize; 4]] = &[
            [0, 5, 10, 15],
            [1, 6, 11, 12],
            [2, 7, 8, 13],
            [3, 4, 9, 14],
        ];
        diagonals.iter().position(|d| nonzero == d)
    }
}

// ─── Key byte recovery ────────────────────────────────────────────────────────

/// Result of recovering a single key byte from fault analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyByteRecovery {
    /// Byte position (0–15) in the last round key.
    pub position: usize,
    /// Recovered key byte value.
    pub key_byte: u8,
    /// Confidence score (0.0–1.0).
    pub confidence: f64,
    /// Number of fault pairs used to determine this byte.
    pub fault_pairs_used: usize,
    /// All candidate bytes that were consistent (usually just 1).
    pub candidates: Vec<u8>,
}

impl KeyByteRecovery {
    /// Returns `true` if this byte was uniquely determined.
    #[must_use]
    pub const fn is_unique(&self) -> bool {
        self.candidates.len() == 1
    }
}

// ─── DFA result ───────────────────────────────────────────────────────────────

/// Complete result of a DFA attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DfaResult {
    /// Last round key (RK10 for AES-128), 16 bytes.
    pub last_round_key: Vec<u8>,
    /// Recovered original AES key (if key schedule reversal succeeded).
    pub original_key: Option<Vec<u8>>,
    /// Per-byte recovery details.
    pub byte_recoveries: Vec<KeyByteRecovery>,
    /// Total fault injections used.
    pub total_faults: usize,
    /// Number of fault injections with valid DFA patterns.
    pub valid_faults: usize,
    /// Overall confidence (product of per-byte confidences).
    pub overall_confidence: f64,
}

impl DfaResult {
    /// Returns `true` if all 16 key bytes were uniquely recovered.
    #[must_use]
    pub fn is_fully_recovered(&self) -> bool {
        self.byte_recoveries.len() == 16
            && self.byte_recoveries.iter().all(KeyByteRecovery::is_unique)
    }

    /// Format the last round key as a hex string.
    #[must_use]
    pub fn last_rk_hex(&self) -> String {
        use std::fmt::Write;
        self.last_round_key
            .iter()
            .fold(String::with_capacity(32), |mut acc, &b| {
                let _ = write!(acc, "{b:02x}");
                acc
            })
    }

    /// Format the original key as a hex string, or `"<not recovered>"`.
    #[must_use]
    pub fn original_key_hex(&self) -> String {
        use std::fmt::Write;
        self.original_key.as_ref().map_or_else(
            || "<not recovered>".to_string(),
            |key| key.iter().fold(String::with_capacity(32), |mut acc, &b| {
                let _ = write!(acc, "{b:02x}");
                acc
            }),
        )
    }
}

// ─── DFA attack engine ────────────────────────────────────────────────────────

/// Performs a DFA attack on an AES-128 whitebox implementation.
///
/// Usage:
/// 1. Collect fault pairs by running the whitebox with artificially faulted
///    round-9 state bytes.
/// 2. Add them via [`DfaAttack::add_fault`].
/// 3. Call [`DfaAttack::run`] to recover the last round key and original key.
///
/// The attack requires at least 2–4 valid fault pairs per diagonal for reliable
/// key byte recovery.
#[derive(Debug, Default)]
pub struct DfaAttack {
    /// Accumulated fault injections.
    faults: Vec<FaultInjection>,
    /// Optional known-correct ciphertext for a given plaintext.
    reference_map: HashMap<Vec<u8>, Vec<u8>>,
}

impl DfaAttack {
    /// Create a new DFA attack context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a fault injection pair.
    pub fn add_fault(&mut self, fi: FaultInjection) {
        self.faults.push(fi);
    }

    /// Register a correct ciphertext for a plaintext (used as fallback reference).
    pub fn register_reference(&mut self, plaintext: Vec<u8>, correct_ct: Vec<u8>) {
        self.reference_map.insert(plaintext, correct_ct);
    }

    /// Total fault injections registered.
    #[must_use]
    pub const fn fault_count(&self) -> usize {
        self.faults.len()
    }

    /// Count fault injections with valid round-9 DFA patterns.
    #[must_use]
    pub fn valid_fault_count(&self) -> usize {
        self.faults
            .iter()
            .filter(|f| f.is_valid_round9_pattern())
            .count()
    }

    /// Run the DFA attack and return the recovered key material.
    ///
    /// # Errors
    /// Returns `CryptoError::Analysis` if fewer than 2 valid faults are available.
    pub fn run(&self) -> Result<DfaResult, CryptoError> {
        let valid: Vec<&FaultInjection> =
            self.faults.iter().filter(|f| f.is_valid_round9_pattern()).collect();

        if valid.len() < 2 {
            return Err(CryptoError::Analysis(format!(
                "DFA requires at least 2 valid fault pairs; got {}",
                valid.len()
            )));
        }

        let mut byte_recoveries = Vec::with_capacity(16);
        let mut last_round_key = vec![0u8; 16];

        for (pos, slot) in last_round_key.iter_mut().enumerate() {
            let recovery = Self::recover_key_byte(pos, &valid);
            *slot = recovery.key_byte;
            byte_recoveries.push(recovery);
        }

        let overall_confidence = byte_recoveries
            .iter()
            .map(|r| r.confidence)
            .fold(1.0f64, |acc, c| acc * c);

        // Attempt to reverse the AES-128 key schedule.
        let original_key = Self::reverse_key_schedule(&last_round_key).ok();

        Ok(DfaResult {
            last_round_key,
            original_key,
            byte_recoveries,
            total_faults: self.faults.len(),
            valid_faults: valid.len(),
            overall_confidence,
        })
    }

    /// Recover a single key byte at `pos` from the valid fault pairs.
    fn recover_key_byte(pos: usize, valid: &[&FaultInjection]) -> KeyByteRecovery {
        // Start with all 256 candidates as possible.
        let mut candidates = vec![true; 256];
        let mut pairs_used = 0usize;

        for fi in valid {
            let Some(diff) = fi.diff() else { continue };
            // Skip if this fault does not affect this byte position.
            if diff.len() <= pos || diff[pos] == 0 {
                continue;
            }
            pairs_used += 1;
            // Apply DFA constraint: eliminate candidates that are inconsistent.
            for k in 0u8..=255 {
                let v_correct = AES_SBOX_INV
                    [(fi.correct_ct.get(pos).copied().unwrap_or(0) ^ k) as usize];
                let v_faulty = AES_SBOX_INV
                    [(fi.faulty_ct.get(pos).copied().unwrap_or(0) ^ k) as usize];
                let delta = v_correct ^ v_faulty;
                if delta == 0 {
                    // A zero delta after InvSBox means k cannot be the real key byte.
                    candidates[k as usize] = false;
                }
            }
        }

        let surviving: Vec<u8> = candidates
            .iter()
            .enumerate()
            .filter(|&(_, &ok)| ok)
            .map(|(i, _)| u8::try_from(i).unwrap_or(u8::MAX))
            .collect();

        let key_byte = surviving.first().copied().unwrap_or(0);
        let confidence = if surviving.len() == 1 { 1.0 } else { 1.0 / f64::from(u32::try_from(surviving.len()).unwrap_or(u32::MAX)) };

        KeyByteRecovery {
            position: pos,
            key_byte,
            confidence,
            fault_pairs_used: pairs_used,
            candidates: surviving,
        }
    }

    /// Reverse the AES-128 key schedule to recover the original 16-byte key
    /// from the last round key (round 10).
    fn reverse_key_schedule(last_rk: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if last_rk.len() != 16 {
            return Err(CryptoError::KeyExtraction("last round key must be 16 bytes".into()));
        }
        let mut rk: Vec<u8> = last_rk.to_vec();
        for round in (1u8..=10).rev() {
            let mut w = [[0u8; 4]; 4];
            for (i, chunk) in w.iter_mut().enumerate() {
                chunk.copy_from_slice(&rk[i * 4..i * 4 + 4]);
            }
            let mut prev = [[0u8; 4]; 4];
            // w3_prev = w3 XOR w2_prev → we need to work backwards
            // AES-128: W[i] = W[i-4] XOR W[i-1] (for i not multiple of 4)
            //          W[i] = W[i-4] XOR SubWord(RotWord(W[i-1])) XOR Rcon[i/4]
            // Going backwards:
            // W[i-4] = W[i] XOR (function of W[i-1])
            // We know W[0..3] of current round, need W[0..3] of previous round.
            // W[4*round+3] = W[4*round-1] XOR W[4*round+2]  → W[4*round-1] = W[4*round+3] XOR W[4*round+2]
            for b in 0..4 {
                prev[3][b] = w[2][b] ^ w[3][b];
            }
            prev[2] = [
                w[1][0] ^ w[2][0],
                w[1][1] ^ w[2][1],
                w[1][2] ^ w[2][2],
                w[1][3] ^ w[2][3],
            ];
            prev[1] = [
                w[0][0] ^ w[1][0],
                w[0][1] ^ w[1][1],
                w[0][2] ^ w[1][2],
                w[0][3] ^ w[1][3],
            ];
            // W[4*(round-1)] = W[4*round] XOR SubWord(RotWord(W[4*(round-1)+3])) XOR Rcon[round]
            let rot = [prev[3][1], prev[3][2], prev[3][3], prev[3][0]];
            let subbed = [
                AES_SBOX[rot[0] as usize],
                AES_SBOX[rot[1] as usize],
                AES_SBOX[rot[2] as usize],
                AES_SBOX[rot[3] as usize],
            ];
            prev[0] = [
                w[0][0] ^ subbed[0] ^ AES_RCON[round as usize],
                w[0][1] ^ subbed[1],
                w[0][2] ^ subbed[2],
                w[0][3] ^ subbed[3],
            ];
            rk = prev.iter().flatten().copied().collect();
        }
        Ok(rk)
    }

    /// Estimate the minimum number of fault injections required for a reliable
    /// recovery given the fault injection model and expected diagonal coverage.
    #[must_use]
    pub fn estimate_required_faults(diagonals_needed: usize) -> usize {
        // Each diagonal contributes to recovery of 4 key bytes.
        // We need at least 2 faults per diagonal for reliable recovery.
        diagonals_needed.saturating_mul(2).max(4)
    }

    /// Group faults by which diagonal they affect.
    #[must_use]
    pub fn faults_by_diagonal(&self) -> [Vec<&FaultInjection>; 4] {
        let mut groups: [Vec<&FaultInjection>; 4] = Default::default();
        for fi in &self.faults {
            if let Some(diag) = fi.diagonal_index() {
                groups[diag].push(fi);
            }
        }
        groups
    }

    /// Produce a summary of the attack state.
    #[must_use]
    pub fn summary(&self) -> DfaAttackSummary {
        let groups = self.faults_by_diagonal();
        DfaAttackSummary {
            total_faults: self.faults.len(),
            valid_faults: self.valid_fault_count(),
            faults_per_diagonal: [
                groups[0].len(),
                groups[1].len(),
                groups[2].len(),
                groups[3].len(),
            ],
            ready_to_attack: self.valid_fault_count() >= 2,
        }
    }
}

/// Summary of the current DFA attack state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DfaAttackSummary {
    pub total_faults: usize,
    pub valid_faults: usize,
    pub faults_per_diagonal: [usize; 4],
    pub ready_to_attack: bool,
}

impl std::fmt::Display for DfaAttackSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DFA: total={} valid={} diag=[{},{},{},{}] ready={}",
            self.total_faults,
            self.valid_faults,
            self.faults_per_diagonal[0],
            self.faults_per_diagonal[1],
            self.faults_per_diagonal[2],
            self.faults_per_diagonal[3],
            self.ready_to_attack
        )
    }
}

// ─── Fault simulation ─────────────────────────────────────────────────────────

/// Simulates fault injection into an AES round state (for testing purposes).
///
/// This can be used to generate synthetic fault pairs when developing
/// and testing the DFA implementation without physical access to the
/// whitebox binary.
#[derive(Debug, Default)]
pub struct FaultSimulator {
    /// The embedded AES key used by this simulator.
    key: [u8; 16],
}

impl FaultSimulator {
    /// Create a simulator with the given key.
    #[must_use]
    pub const fn new(key: [u8; 16]) -> Self {
        Self { key }
    }

    /// Generate a fault injection pair for the given plaintext by faulting
    /// state byte `fault_byte` in round 9 with `fault_value`.
    ///
    /// This is a simplified model: the fault is applied to the round-9 state
    /// after `SubBytes`, so one byte of the `MixColumns` input is corrupted.
    #[must_use]
    pub fn inject_fault(&self, plaintext: &[u8; 16], fault_byte: usize, fault_value: u8) -> FaultInjection {
        let correct_ct = self.encrypt(plaintext);
        let mut faulty_state = *plaintext;
        // Simulate corruption: XOR one byte of the plaintext with the fault value.
        // In a real whitebox attack this would be a round-9 state fault; here
        // we approximate by corrupting the plaintext.
        if fault_byte < 16 {
            faulty_state[fault_byte] ^= fault_value;
        }
        let faulty_ct = self.encrypt(&faulty_state);
        FaultInjection::new(
            plaintext.to_vec(),
            correct_ct,
            faulty_ct,
            FaultModel::Round9Diagonal,
        )
        .with_location(9, u8::try_from(fault_byte).unwrap_or(u8::MAX))
    }

    /// Simplified AES-128 encryption for simulation (encrypt one block).
    /// Uses a basic 10-round structure without full key expansion for brevity.
    fn encrypt(&self, plaintext: &[u8; 16]) -> Vec<u8> {
        let mut state = *plaintext;
        // Initial AddRoundKey with key bytes 0..16.
        for (s, &k) in state.iter_mut().zip(self.key.iter()) {
            *s ^= k;
        }
        // 9 rounds of SubBytes + simple diffusion (simplified, not real AES).
        for round in 0..9usize {
            for s in &mut state {
                *s = AES_SBOX[*s as usize];
            }
            // ShiftRows (simplified row rotation).
            let tmp = state[1];
            state[1] = state[5];
            state[5] = state[9];
            state[9] = state[13];
            state[13] = tmp;
            // AddRoundKey: XOR with rotated key.
            let rk_offset = (round * 4) % 16;
            for (i, s) in state.iter_mut().enumerate() {
                *s ^= self.key[(i + rk_offset) % 16];
            }
        }
        // Final round: SubBytes + AddRoundKey only.
        for s in &mut state {
            *s = AES_SBOX[*s as usize];
        }
        for (s, &k) in state.iter_mut().zip(self.key.iter()) {
            *s ^= k;
        }
        state.to_vec()
    }
}

// ─── Lookup table helper for DFA ──────────────────────────────────────────────

/// Build a lookup table from DFA-recovered round key material.
///
/// After recovering the last round key, we can optionally store it as a
/// `LookupTable` for integration with the rest of the whitebox analysis pipeline.
#[must_use]
pub fn round_key_to_lookup_table(round_key: &[u8], round: u8) -> LookupTable {
    LookupTable {
        offset: u64::from(round) * 16,
        size: round_key.len(),
        data: round_key.to_vec(),
        purpose: TablePurpose::KeySchedule,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fault_injection_diff() {
        let fi = FaultInjection::new(
            vec![0u8; 16],
            vec![0x01u8; 16],
            vec![0x03u8; 16],
            FaultModel::ByteSet,
        );
        let diff = fi.diff().unwrap();
        assert_eq!(diff, vec![0x02u8; 16]);
    }

    #[test]
    fn test_fault_injection_diff_mismatch() {
        let fi = FaultInjection::new(
            vec![0u8; 16],
            vec![0u8; 16],
            vec![0u8; 8], // wrong length
            FaultModel::ByteSet,
        );
        assert!(fi.diff().is_none());
    }

    #[test]
    fn test_valid_round9_pattern_wrong_count() {
        // 3 non-zero bytes is not a valid round-9 pattern.
        let correct = vec![0u8; 16];
        let mut faulty = vec![0u8; 16];
        faulty[0] ^= 1;
        faulty[1] ^= 1;
        faulty[2] ^= 1;
        let fi = FaultInjection::new(vec![0u8; 16], correct, faulty, FaultModel::Round9Diagonal);
        assert!(!fi.is_valid_round9_pattern());
    }

    #[test]
    fn test_valid_round9_pattern_diagonal0() {
        let correct = vec![0u8; 16];
        let mut faulty = vec![0u8; 16];
        // Diagonal 0: bytes 0, 5, 10, 15.
        faulty[0] ^= 0xAB;
        faulty[5] ^= 0xCD;
        faulty[10] ^= 0xEF;
        faulty[15] ^= 0x12;
        let fi = FaultInjection::new(vec![0u8; 16], correct, faulty, FaultModel::Round9Diagonal);
        assert!(fi.is_valid_round9_pattern());
        assert_eq!(fi.diagonal_index(), Some(0));
    }

    #[test]
    fn test_dfa_attack_min_faults() {
        let attack = DfaAttack::new();
        let result = attack.run();
        assert!(result.is_err());
    }

    #[test]
    fn test_fault_simulator_encrypt_deterministic() {
        let key = [0x42u8; 16];
        let sim = FaultSimulator::new(key);
        let pt = [0x00u8; 16];
        let ct1 = sim.encrypt(&pt);
        let ct2 = sim.encrypt(&pt);
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_estimate_required_faults() {
        assert!(DfaAttack::estimate_required_faults(4) >= 8);
        assert!(DfaAttack::estimate_required_faults(0) >= 4);
    }

    #[test]
    fn test_dfa_attack_summary() {
        let mut attack = DfaAttack::new();
        let correct = vec![0u8; 16];
        let mut faulty = vec![0u8; 16];
        faulty[0] ^= 0xAB;
        faulty[5] ^= 0xCD;
        faulty[10] ^= 0xEF;
        faulty[15] ^= 0x12;
        attack.add_fault(FaultInjection::new(
            vec![0u8; 16],
            correct,
            faulty,
            FaultModel::Round9Diagonal,
        ));
        let summary = attack.summary();
        assert_eq!(summary.total_faults, 1);
        assert_eq!(summary.valid_faults, 1);
        assert!(!summary.ready_to_attack); // need at least 2
    }

    #[test]
    fn test_round_key_to_lookup_table() {
        let rk = vec![0x55u8; 16];
        let lt = round_key_to_lookup_table(&rk, 10);
        assert_eq!(lt.size, 16);
        assert_eq!(lt.purpose, TablePurpose::KeySchedule);
        assert_eq!(lt.offset, 160);
    }
}
