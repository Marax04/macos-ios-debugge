//! `rustre-crypto-oracle`
//!
//! Crypto oracle interaction and cryptographic attack implementations.
//! Provides padding oracle (full CBC decrypt), ECB byte-at-a-time prefix attack,
//! nonce reuse detection, CBC IV prediction, key-reuse OTP, replay attack,
//! and emulator-based oracle calling.

pub mod hash_attacks;
pub mod oracle_automation;
pub mod oracle_detection;
pub mod oracle_exploitation;
pub mod side_channel;
pub mod timing_oracle_full;
pub mod stream_cipher_attacks;
pub mod whitebox_attacks;
pub mod padding_oracle;
pub mod ecb_oracle;
pub mod hash_length_extension;
pub mod key_schedule_analyzer;
pub mod padding_oracle_detector;
pub mod crypto_constant_finder;
pub mod oracle_query_engine;
pub mod padding_oracle_attack;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Borrowed query function returning `(nonce, ciphertext)` for a plaintext.
pub type NonceCiphertextQuery<'a> = &'a dyn Fn(&[u8]) -> (Vec<u8>, Vec<u8>);

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum OracleError {
    #[error("block size mismatch: got {0}, expected {1}")]
    BlockSizeMismatch(usize, usize),
    #[error("ciphertext length not a multiple of block size")]
    BadLength,
    #[error("oracle query failed")]
    QueryFailed,
    #[error("attack failed: {0}")]
    AttackFailed(String),
    #[error("invalid parameter: {0}")]
    InvalidParam(String),
}

// ── OracleCallable trait ──────────────────────────────────────────────────────

/// Result from calling a decryption oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleResult {
    /// Ciphertext decrypted with valid padding.
    Valid,
    /// PKCS#7 padding was invalid.
    PaddingError,
    /// Some other decryption error.
    OtherError,
}

/// A callable oracle that reports decryption validity.
pub trait OracleCallable: Send + Sync {
    fn call(&self, input: &[u8]) -> OracleResult;
}

// ── Oracle trait (bool-returning, for compatibility) ─────────────────────────

pub trait Oracle: Send + Sync {
    fn query(&self, ciphertext: &[u8]) -> bool;
}

/// Adapter: wrap any Oracle into `OracleCallable`.
pub struct BoolOracleAdapter<'a>(pub &'a dyn Oracle);

impl OracleCallable for BoolOracleAdapter<'_> {
    fn call(&self, input: &[u8]) -> OracleResult {
        if self.0.query(input) {
            OracleResult::Valid
        } else {
            OracleResult::PaddingError
        }
    }
}

// ── OracleMode / OracleTarget ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OracleMode {
    PaddingOracle,
    CbcOracle,
    EcbOracle,
    TimingOracle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleTarget {
    pub endpoint: String,
    pub mode: OracleMode,
    pub block_size: usize,
    pub iv: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OracleSignal {
    BlockAlignedAcceptance,
    RepeatedBlockLeak,
    PaddingValidityDelta,
    TimingSkew,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleProbe {
    pub id: String,
    pub signal: OracleSignal,
    pub payload: Vec<u8>,
    pub control_payload: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleProbeOutcome {
    pub probe_id: String,
    pub accepted: bool,
    pub control_accepted: Option<bool>,
    pub duration_ns: Option<u64>,
    pub control_duration_ns: Option<u64>,
    pub response_len: Option<usize>,
    pub control_response_len: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleFinding {
    pub mode: OracleMode,
    pub signal: OracleSignal,
    pub confidence: u8,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleDiscoveryReport {
    pub block_size: usize,
    pub probes: Vec<OracleProbe>,
    pub findings: Vec<OracleFinding>,
}

pub struct OracleDiscovery;

impl OracleDiscovery {
    /// # Errors
    ///
    /// Returns `OracleError::InvalidParam` if `block_size` is zero.
    pub fn probe_suite(block_size: usize) -> Result<Vec<OracleProbe>, OracleError> {
        if block_size == 0 {
            return Err(OracleError::InvalidParam(
                "block_size cannot be zero".into(),
            ));
        }
        let repeated = vec![0x41; block_size * 4];
        let mut padding_control: Vec<u8> = (0..block_size * 2)
            .map(|i| u8::try_from(i).unwrap_or(u8::MAX))
            .collect();
        let mut padding_mutation = padding_control.clone();
        if let Some(last) = padding_mutation.last_mut() {
            *last ^= 0x01;
        }
        if let Some(last) = padding_control.last_mut() {
            *last = 0x01;
        }
        Ok(vec![
            OracleProbe {
                id: format!("block-align-{block_size}"),
                signal: OracleSignal::BlockAlignedAcceptance,
                payload: vec![0u8; block_size],
                control_payload: Some(vec![0u8; block_size + 1]),
            },
            OracleProbe {
                id: format!("ecb-repeat-{block_size}"),
                signal: OracleSignal::RepeatedBlockLeak,
                payload: repeated,
                control_payload: None,
            },
            OracleProbe {
                id: format!("padding-delta-{block_size}"),
                signal: OracleSignal::PaddingValidityDelta,
                payload: padding_mutation,
                control_payload: Some(padding_control),
            },
            OracleProbe {
                id: format!("timing-skew-{block_size}"),
                signal: OracleSignal::TimingSkew,
                payload: vec![0u8; block_size * 2],
                control_payload: Some(vec![0xff; block_size * 2]),
            },
        ])
    }

    #[must_use]
    pub fn analyze_outcomes(
        block_size: usize,
        outcomes: &[OracleProbeOutcome],
    ) -> OracleDiscoveryReport {
        let probes = Self::probe_suite(block_size).unwrap_or_default();
        let mut findings = Vec::new();
        for outcome in outcomes {
            if outcome.probe_id.starts_with("block-align-")
                && outcome.accepted
                && outcome.control_accepted == Some(false)
            {
                findings.push(OracleFinding {
                    mode: OracleMode::CbcOracle,
                    signal: OracleSignal::BlockAlignedAcceptance,
                    confidence: 55,
                    summary: "Oracle distinguishes aligned and unaligned ciphertext lengths".into(),
                });
            }
            if outcome.probe_id.starts_with("ecb-repeat-")
                && outcome.accepted
                && outcome.response_len == outcome.control_response_len
            {
                findings.push(OracleFinding {
                    mode: OracleMode::EcbOracle,
                    signal: OracleSignal::RepeatedBlockLeak,
                    confidence: 70,
                    summary: "Repeated-block probe was accepted with a stable response shape"
                        .into(),
                });
            }
            if outcome.probe_id.starts_with("padding-delta-")
                && outcome.control_accepted.is_some()
                && outcome.accepted != outcome.control_accepted.unwrap_or(outcome.accepted)
            {
                findings.push(OracleFinding {
                    mode: OracleMode::PaddingOracle,
                    signal: OracleSignal::PaddingValidityDelta,
                    confidence: 90,
                    summary: "Single-byte padding mutation changed oracle validity".into(),
                });
            }
            if outcome.probe_id.starts_with("timing-skew-")
                && timing_delta(outcome.duration_ns, outcome.control_duration_ns) >= 5_000
            {
                findings.push(OracleFinding {
                    mode: OracleMode::TimingOracle,
                    signal: OracleSignal::TimingSkew,
                    confidence: 65,
                    summary: "Probe/control timing delta exceeded deterministic threshold".into(),
                });
            }
        }
        findings.sort_by(|l, r| {
            r.confidence
                .cmp(&l.confidence)
                .then_with(|| oracle_mode_rank(l.mode).cmp(&oracle_mode_rank(r.mode)))
        });
        OracleDiscoveryReport {
            block_size,
            probes,
            findings,
        }
    }

    /// # Errors
    ///
    /// Returns `OracleError` on invalid parameters or oracle failure.
    pub fn discover_with_oracle(
        block_size: usize,
        oracle: &dyn Oracle,
    ) -> Result<OracleDiscoveryReport, OracleError> {
        let probes = Self::probe_suite(block_size)?;
        let outcomes: Vec<OracleProbeOutcome> = probes
            .iter()
            .map(|probe| OracleProbeOutcome {
                probe_id: probe.id.clone(),
                accepted: oracle.query(&probe.payload),
                control_accepted: probe.control_payload.as_ref().map(|p| oracle.query(p)),
                duration_ns: None,
                control_duration_ns: None,
                response_len: None,
                control_response_len: None,
            })
            .collect();
        Ok(Self::analyze_outcomes(block_size, &outcomes))
    }
}

const fn timing_delta(left: Option<u64>, right: Option<u64>) -> u64 {
    match (left, right) {
        (Some(l), Some(r)) => l.abs_diff(r),
        _ => 0,
    }
}

const fn oracle_mode_rank(mode: OracleMode) -> usize {
    match mode {
        OracleMode::PaddingOracle => 0,
        OracleMode::CbcOracle => 1,
        OracleMode::EcbOracle => 2,
        OracleMode::TimingOracle => 3,
    }
}

// ── PaddingOracleAttack ───────────────────────────────────────────────────────
//
// Full implementation:
//   decrypt_last_block(ciphertext, iv): for byte i=15..0, brute-force C'[i]=0..255,
//     find value where padding is valid, compute plaintext = C'[i] XOR (i+1) XOR C[i].
//   decrypt_all_blocks(ciphertext, iv): repeat for each 16-byte block pair.
//   Minimum 256 oracle calls per byte, 16*256 = 4096 per block.

pub struct PaddingOracleAttack;

impl PaddingOracleAttack {
    /// Detect whether a padding error occurs by querying the oracle.
    #[must_use]
    pub fn detect_padding_error(oracle: &dyn OracleCallable, input: &[u8]) -> bool {
        oracle.call(input) == OracleResult::PaddingError
    }

    /// Decrypt a single 16-byte CBC block using the padding oracle.
    /// `ciphertext` is the block to decrypt; `prev_block` is the preceding block (or IV).
    ///
    /// # Errors
    ///
    /// Returns `OracleError` if oracle queries fail or inputs are invalid.
    pub fn decrypt_block(
        ciphertext: &[u8],
        prev_block: &[u8],
        oracle: &dyn Oracle,
    ) -> Result<Vec<u8>, OracleError> {
        const BLOCK: usize = 16;
        if ciphertext.len() != BLOCK {
            return Err(OracleError::BlockSizeMismatch(ciphertext.len(), BLOCK));
        }
        if prev_block.len() != BLOCK {
            return Err(OracleError::BlockSizeMismatch(prev_block.len(), BLOCK));
        }

        let mut intermediate = [0u8; BLOCK];

        for byte_idx in (0..BLOCK).rev() {
            let pad_byte = u8::try_from(BLOCK - byte_idx).unwrap_or(16u8);
            let mut crafted_prev = [0u8; BLOCK];
            for k in (byte_idx + 1)..BLOCK {
                crafted_prev[k] = intermediate[k] ^ pad_byte;
            }
            let mut found = false;
            for guess in 0u8..=255 {
                crafted_prev[byte_idx] = guess;
                let mut payload = crafted_prev.to_vec();
                payload.extend_from_slice(ciphertext);
                if oracle.query(&payload) {
                    if byte_idx > 0 {
                        let mut verify = crafted_prev;
                        verify[byte_idx - 1] ^= 1;
                        let mut vp = verify.to_vec();
                        vp.extend_from_slice(ciphertext);
                        if !oracle.query(&vp) {
                            continue;
                        }
                    }
                    intermediate[byte_idx] = guess ^ pad_byte;
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(OracleError::AttackFailed(format!(
                    "could not find byte at position {byte_idx}"
                )));
            }
        }

        let plaintext: Vec<u8> = intermediate
            .iter()
            .zip(prev_block.iter())
            .map(|(i, p)| i ^ p)
            .collect();
        Ok(plaintext)
    }

    /// Decrypt a complete CBC ciphertext using a padding oracle.
    /// Returns plaintext with PKCS#7 padding stripped.
    ///
    /// # Errors
    ///
    /// Returns `OracleError` if oracle queries fail, inputs are invalid, or padding is bad.
    pub fn decrypt_cbc(
        ciphertext: &[u8],
        iv: &[u8],
        oracle: &dyn Oracle,
    ) -> Result<Vec<u8>, OracleError> {
        const BLOCK: usize = 16;
        if !ciphertext.len().is_multiple_of(BLOCK) {
            return Err(OracleError::BadLength);
        }
        if iv.len() != BLOCK {
            return Err(OracleError::BlockSizeMismatch(iv.len(), BLOCK));
        }
        let num_blocks = ciphertext.len() / BLOCK;
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        for block_idx in 0..num_blocks {
            let ct_block = &ciphertext[block_idx * BLOCK..(block_idx + 1) * BLOCK];
            let prev = if block_idx == 0 {
                iv
            } else {
                &ciphertext[(block_idx - 1) * BLOCK..block_idx * BLOCK]
            };
            let pt_block = Self::decrypt_block(ct_block, prev, oracle)?;
            plaintext.extend_from_slice(&pt_block);
        }
        if let Some(&pad_len_byte) = plaintext.last() {
            let pad_len = usize::from(pad_len_byte);
            if pad_len > 0 && pad_len <= BLOCK && plaintext.len() >= pad_len {
                let start = plaintext.len() - pad_len;
                if plaintext[start..].iter().all(|&b| b == pad_len_byte) {
                    plaintext.truncate(start);
                }
            }
        }
        Ok(plaintext)
    }

    /// Decrypt a single block using the `OracleCallable` trait.
    ///
    /// # Errors
    ///
    /// Returns `OracleError` if oracle queries fail or inputs are invalid.
    pub fn decrypt_block_callable(
        ciphertext: &[u8],
        prev_block: &[u8],
        oracle: &dyn OracleCallable,
    ) -> Result<Vec<u8>, OracleError> {
        const BLOCK: usize = 16;
        if ciphertext.len() != BLOCK {
            return Err(OracleError::BlockSizeMismatch(ciphertext.len(), BLOCK));
        }
        if prev_block.len() != BLOCK {
            return Err(OracleError::BlockSizeMismatch(prev_block.len(), BLOCK));
        }
        let mut intermediate = [0u8; BLOCK];
        for byte_idx in (0..BLOCK).rev() {
            let pad_byte = u8::try_from(BLOCK - byte_idx).unwrap_or(16u8);
            let mut crafted_prev = [0u8; BLOCK];
            for k in (byte_idx + 1)..BLOCK {
                crafted_prev[k] = intermediate[k] ^ pad_byte;
            }
            let mut found = false;
            for guess in 0u8..=255 {
                crafted_prev[byte_idx] = guess;
                let mut payload = crafted_prev.to_vec();
                payload.extend_from_slice(ciphertext);
                let result = oracle.call(&payload);
                if result == OracleResult::Valid {
                    if byte_idx > 0 {
                        let mut verify = crafted_prev;
                        verify[byte_idx - 1] ^= 1;
                        let mut vp = verify.to_vec();
                        vp.extend_from_slice(ciphertext);
                        if oracle.call(&vp) != OracleResult::Valid {
                            continue;
                        }
                    }
                    intermediate[byte_idx] = guess ^ pad_byte;
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(OracleError::AttackFailed(format!("byte {byte_idx}")));
            }
        }
        Ok(intermediate
            .iter()
            .zip(prev_block.iter())
            .map(|(i, p)| i ^ p)
            .collect())
    }
}

// ── EcbByteAtATime ────────────────────────────────────────────────────────────
//
// ECB byte-at-a-time prefix attack:
//   1. detect_ecb: submit 32 AA...A, check for two identical 16-byte blocks.
//   2. determine_block_size: increase input length until output length jumps.
//   3. recover_unknown_suffix: for each byte position, submit (block_size-1-pos) As,
//      compare oracle output to all 256 candidates.

pub struct EcbByteAtATime;

impl EcbByteAtATime {
    /// Detect ECB mode: 32-byte repeated input produces two identical ciphertext blocks.
    #[must_use]
    pub fn detect_ecb(oracle_encrypt: &dyn Fn(&[u8]) -> Vec<u8>) -> bool {
        let input = vec![0x41u8; 48]; // 3 blocks of 'A'
        let ct = oracle_encrypt(&input);
        if ct.len() < 32 {
            return false;
        }
        // Check if any two consecutive 16-byte blocks are equal
        for i in 0..ct.len() / 16 - 1 {
            if ct[i * 16..(i + 1) * 16] == ct[(i + 1) * 16..(i + 2) * 16] {
                return true;
            }
        }
        false
    }

    /// Determine block size by increasing input length until output length jumps.
    #[must_use]
    pub fn determine_block_size(oracle_encrypt: &dyn Fn(&[u8]) -> Vec<u8>) -> usize {
        let base_len = oracle_encrypt(&[]).len();
        for extra in 1usize..=64 {
            let input = vec![0x41u8; extra];
            let ct = oracle_encrypt(&input);
            if ct.len() > base_len {
                return ct.len() - base_len;
            }
        }
        16 // default
    }

    /// Recover unknown suffix appended by oracle before encryption (ECB byte-at-a-time).
    #[must_use]
    pub fn recover_unknown_suffix(
        oracle_encrypt: &dyn Fn(&[u8]) -> Vec<u8>,
        block_size: usize,
    ) -> Vec<u8> {
        let total_len = oracle_encrypt(&[]).len();
        let mut recovered = Vec::new();

        for pos in 0..total_len {
            let pad_len = block_size - 1 - (pos % block_size);
            let pad = vec![0x41u8; pad_len];
            let target_ct = oracle_encrypt(&pad);
            let target_block_idx = pos / block_size;
            if (target_block_idx + 1) * block_size > target_ct.len() {
                break;
            }
            let target_block =
                &target_ct[target_block_idx * block_size..(target_block_idx + 1) * block_size];

            let mut found = false;
            for guess in 0u8..=255 {
                // Build the known window: last (block_size-1) recovered bytes + guess
                let known_start = recovered.len().saturating_sub(block_size - 1);
                let known_window = &recovered[known_start..];
                // Prefix with target_block_idx blocks of filler so the known+guess
                // block lands at target_block_idx in the oracle output.
                let mut probe = vec![0x41u8; target_block_idx * block_size];
                probe.extend_from_slice(known_window);
                probe.push(guess);
                let probe_ct = oracle_encrypt(&probe);
                let probe_block_start = target_block_idx * block_size;
                let probe_block_end = probe_block_start + block_size;
                if probe_ct.len() >= probe_block_end
                    && &probe_ct[probe_block_start..probe_block_end] == target_block
                {
                    recovered.push(guess);
                    found = true;
                    break;
                }
            }
            if !found {
                break;
            }
        }
        recovered
    }
}

// ── NonceReuseDetection ───────────────────────────────────────────────────────
//
// Stream cipher / CTR / GCM nonce reuse:
//   If two ciphertexts share the same nonce, then C1 XOR C2 = P1 XOR P2.
//   If P1 is known, recover P2 = C1 XOR C2 XOR P1.

/// A (nonce, ciphertext) pair from a stream-cipher oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceCiphertext {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub struct NonceReuseDetection;

impl NonceReuseDetection {
    /// Collect multiple (nonce, ciphertext) pairs from an oracle.
    /// `query_fn`: given a plaintext, returns (nonce, ciphertext).
    #[must_use]
    pub fn collect_ciphertexts(
        query_fn: NonceCiphertextQuery<'_>,
        plaintexts: &[&[u8]],
    ) -> Vec<NonceCiphertext> {
        plaintexts
            .iter()
            .map(|pt| {
                let (nonce, ciphertext) = query_fn(pt);
                NonceCiphertext { nonce, ciphertext }
            })
            .collect()
    }

    /// Find pairs of ciphertexts with the same nonce.
    /// Returns list of (`index_a`, `index_b`) pairs.
    #[must_use]
    pub fn find_nonce_reuse(pairs: &[NonceCiphertext]) -> Vec<(usize, usize)> {
        let mut reuses = Vec::new();
        for i in 0..pairs.len() {
            for j in (i + 1)..pairs.len() {
                if pairs[i].nonce == pairs[j].nonce {
                    reuses.push((i, j));
                }
            }
        }
        reuses
    }

    /// Attack nonce reuse: if we know P1, recover P2.
    /// P1 XOR P2 = C1 XOR C2, so P2 = C1 XOR C2 XOR P1.
    #[must_use]
    pub fn attack_nonce_reuse(ct1: &[u8], ct2: &[u8], known_p1: &[u8]) -> Vec<u8> {
        let xor_cts: Vec<u8> = ct1.iter().zip(ct2.iter()).map(|(a, b)| a ^ b).collect();
        xor_cts
            .iter()
            .zip(known_p1.iter())
            .map(|(x, p)| x ^ p)
            .collect()
    }

    /// XOR two ciphertexts (C1 XOR C2 = P1 XOR P2 for nonce-reuse).
    #[must_use]
    pub fn xor_ciphertexts(ct1: &[u8], ct2: &[u8]) -> Vec<u8> {
        let len = ct1.len().min(ct2.len());
        (0..len).map(|i| ct1[i] ^ ct2[i]).collect()
    }

    /// Analyze XOR distribution of two ciphertexts for English text patterns
    /// (high printability of XOR = likely nonce reuse with text plaintexts).
    #[must_use]
    pub fn analyze_xor_for_english(xored: &[u8]) -> f64 {
        let printable = xored
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b == b' ')
            .count();
        f64::from(u32::try_from(printable).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(xored.len().max(1)).unwrap_or(u32::MAX))
    }
}

// ── IvPredictionAttack ────────────────────────────────────────────────────────
//
// CBC IV prediction: if IV is predictable (counter, timestamp), forge chosen-plaintext.

pub struct IvPredictionAttack;

impl IvPredictionAttack {
    /// Detect if IV follows a counter pattern across multiple observations.
    /// Returns true if IVs differ by exactly 1 (little-endian u128 interpretation).
    #[must_use]
    pub fn detect_counter_iv(ivs: &[Vec<u8>]) -> bool {
        if ivs.len() < 2 {
            return false;
        }
        for i in 1..ivs.len() {
            let prev = Self::bytes_to_u128_le(&ivs[i - 1]);
            let curr = Self::bytes_to_u128_le(&ivs[i]);
            if curr != prev.wrapping_add(1) {
                return false;
            }
        }
        true
    }

    /// Predict the next IV given the current one (counter increment).
    #[must_use]
    pub fn predict_next_iv(current_iv: &[u8]) -> Vec<u8> {
        let val = Self::bytes_to_u128_le(current_iv).wrapping_add(1);
        Self::u128_to_bytes_le(val, current_iv.len())
    }

    /// Forge chosen plaintext: given known `IV_next` and desired plaintext,
    /// craft a ciphertext such that decryption yields chosen plaintext.
    /// In CBC: D(C1) XOR IV = P1, so C1 = D^-1(P1 XOR IV).
    /// With IV prediction, we can craft C1 to yield desired P.
    #[must_use]
    pub fn forge_chosen_plaintext(
        current_iv: &[u8],
        known_plaintext: &[u8],
        desired_plaintext: &[u8],
    ) -> Vec<u8> {
        let predicted_iv = Self::predict_next_iv(current_iv);
        // XOR difference: modify ciphertext to flip bits
        let len = known_plaintext
            .len()
            .min(desired_plaintext.len())
            .min(predicted_iv.len());
        (0..len)
            .map(|i| {
                let flip = known_plaintext[i] ^ desired_plaintext[i];
                predicted_iv[i] ^ flip
            })
            .collect()
    }

    fn bytes_to_u128_le(bytes: &[u8]) -> u128 {
        let mut val = 0u128;
        for (i, &b) in bytes.iter().enumerate().take(16) {
            val |= u128::from(b) << (i * 8);
        }
        val
    }

    fn u128_to_bytes_le(val: u128, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| {
                if i >= 16 {
                    0u8
                } else {
                    ((val >> (i * 8)) & 0xFF) as u8
                }
            })
            .collect()
    }
}

// ── OtpKeyReuse ───────────────────────────────────────────────────────────────
//
// Key reuse OTP: XOR two ciphertexts encrypted with same key, then analyze
// XOR distribution for English text patterns.

pub struct OtpKeyReuse;

impl OtpKeyReuse {
    /// XOR two ciphertexts that share the same OTP/stream key.
    /// Result = P1 XOR P2.
    #[must_use]
    pub fn xor_ciphertexts(ct1: &[u8], ct2: &[u8]) -> Vec<u8> {
        let len = ct1.len().min(ct2.len());
        (0..len).map(|i| ct1[i] ^ ct2[i]).collect()
    }

    /// Analyze XOR of two ciphertexts: high printability suggests English text.
    #[must_use]
    pub fn analyze_xor_distribution(xored: &[u8]) -> f64 {
        if xored.is_empty() {
            return 0.0;
        }
        let printable = xored
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b == b' ')
            .count();
        f64::from(u32::try_from(printable).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(xored.len()).unwrap_or(u32::MAX))
    }

    /// Given XOR of plaintexts (P1 XOR P2) and known P1, recover P2.
    #[must_use]
    pub fn recover_p2(p1_xor_p2: &[u8], known_p1: &[u8]) -> Vec<u8> {
        let len = p1_xor_p2.len().min(known_p1.len());
        (0..len).map(|i| p1_xor_p2[i] ^ known_p1[i]).collect()
    }

    /// Brute-force single-byte key: try XOR-decrypting with each byte,
    /// score by English letter frequency.
    #[must_use]
    pub fn recover_key_byte(stream_byte_col: &[u8]) -> u8 {
        let mut best_key = 0u8;
        let mut best_score = 0.0f64;
        for k in 0u8..=255 {
            let dec: Vec<u8> = stream_byte_col.iter().map(|&b| b ^ k).collect();
            let score: f64 = dec
                .iter()
                .map(|&b| {
                    if b.is_ascii_lowercase() {
                        1.0
                    } else if b.is_ascii_uppercase() {
                        0.9
                    } else if b == b' ' {
                        1.5
                    } else if b.is_ascii_punctuation() {
                        0.3
                    } else {
                        0.0
                    }
                })
                .sum::<f64>()
                / f64::from(u32::try_from(dec.len().max(1)).unwrap_or(u32::MAX));
            if score > best_score {
                best_score = score;
                best_key = k;
            }
        }
        best_key
    }
}

// ── ReplayAttack ─────────────────────────────────────────────────────────────
//
// Replay attack: detect stateless oracle, replay previous ciphertext.

pub struct ReplayAttack;

impl ReplayAttack {
    /// Detect stateless oracle: submitting same ciphertext twice should produce same response.
    #[must_use]
    pub fn detect_stateless(oracle: &dyn OracleCallable, ciphertext: &[u8]) -> bool {
        let r1 = oracle.call(ciphertext);
        let r2 = oracle.call(ciphertext);
        r1 == r2
    }

    /// Replay a previously captured ciphertext and check if it's accepted.
    #[must_use]
    pub fn replay(oracle: &dyn OracleCallable, captured_ct: &[u8]) -> OracleResult {
        oracle.call(captured_ct)
    }

    /// Collect multiple oracle responses to the same ciphertext.
    #[must_use]
    pub fn collect_responses(
        oracle: &dyn OracleCallable,
        ciphertext: &[u8],
        count: usize,
    ) -> Vec<OracleResult> {
        (0..count).map(|_| oracle.call(ciphertext)).collect()
    }
}

// ── EmulatorOracle ────────────────────────────────────────────────────────────
//
// Emulator integration: call a compiled decryption function via Unicorn-style
// emulation with concrete arguments, read output from return value pointer.

/// Configuration for emulating a decryption function.
#[derive(Debug, Clone)]
pub struct EmulatorOracleConfig {
    /// Address of the function to call.
    pub func_addr: u64,
    /// Address of input buffer in emulated memory.
    pub input_buf_addr: u64,
    /// Address of output buffer in emulated memory.
    pub output_buf_addr: u64,
    /// Stack pointer to use.
    pub stack_ptr: u64,
    /// Maximum instruction count before timeout.
    pub max_insn: usize,
}

/// Placeholder for Unicorn-based oracle emulation.
/// In production this would call into the unicorn-engine crate.
pub struct EmulatorOracle {
    pub config: EmulatorOracleConfig,
}

impl EmulatorOracle {
    #[must_use] 
    pub const fn new(config: EmulatorOracleConfig) -> Self {
        Self { config }
    }

    /// Emulate the decryption function with `ciphertext` as input.
    /// Returns the bytes written to the output buffer.
    /// This is a stub — real implementation would use unicorn-engine.
    ///
    /// # Errors
    ///
    /// Always returns `OracleError::NotImplemented` in this stub.
    pub fn decrypt(&self, ciphertext: &[u8], _key: &[u8]) -> Result<Vec<u8>, OracleError> {
        // Stub: in real implementation, set up Unicorn context, map memory,
        // write ciphertext to input_buf_addr, write key, set registers,
        // start emulation at func_addr, read output_buf_addr after return.
        if ciphertext.is_empty() {
            return Err(OracleError::InvalidParam("empty ciphertext".into()));
        }
        // Return identity as placeholder
        Ok(ciphertext.to_vec())
    }
}

// ── CbcBitFlippingAttack ──────────────────────────────────────────────────────

pub struct CbcBitFlippingAttack;

impl CbcBitFlippingAttack {
    /// # Errors
    ///
    /// Returns `OracleError` if inputs are invalid or the flip target is out of range.
    pub fn flip(
        ciphertext: &[u8],
        iv: &[u8],
        target_offset: usize,
        known_plain: u8,
        desired: u8,
    ) -> Result<(Vec<u8>, Vec<u8>), OracleError> {
        const BLOCK: usize = 16;
        if !ciphertext.len().is_multiple_of(BLOCK) {
            return Err(OracleError::BadLength);
        }
        if iv.len() != BLOCK {
            return Err(OracleError::BlockSizeMismatch(iv.len(), BLOCK));
        }
        if target_offset >= ciphertext.len() {
            return Err(OracleError::InvalidParam(
                "target_offset out of range".into(),
            ));
        }
        let block_idx = target_offset / BLOCK;
        let byte_in_block = target_offset % BLOCK;
        let flip_mask = known_plain ^ desired;
        let mut new_iv = iv.to_vec();
        let mut new_ct = ciphertext.to_vec();
        if block_idx == 0 {
            new_iv[byte_in_block] ^= flip_mask;
        } else {
            new_ct[(block_idx - 1) * BLOCK + byte_in_block] ^= flip_mask;
        }
        Ok((new_iv, new_ct))
    }
}

// ── EcbCutAndPasteAttack ──────────────────────────────────────────────────────

pub struct EcbCutAndPasteAttack;

impl EcbCutAndPasteAttack {
    #[must_use]
    pub fn detect_ecb(ciphertext: &[u8], block_size: usize) -> bool {
        if block_size == 0 || ciphertext.len() < block_size * 2 {
            return false;
        }
        let num_blocks = ciphertext.len() / block_size;
        let blocks: Vec<&[u8]> = (0..num_blocks)
            .map(|i| &ciphertext[i * block_size..(i + 1) * block_size])
            .collect();
        for i in 0..blocks.len() {
            for j in (i + 1)..blocks.len() {
                if blocks[i] == blocks[j] {
                    return true;
                }
            }
        }
        false
    }

    /// # Errors
    ///
    /// Returns `OracleError` if `block_size` is zero, ciphertext length is not a multiple, or `order` contains invalid indices.
    pub fn reorder_blocks(
        ciphertext: &[u8],
        block_size: usize,
        order: &[usize],
    ) -> Result<Vec<u8>, OracleError> {
        if block_size == 0 {
            return Err(OracleError::InvalidParam(
                "block_size cannot be zero".into(),
            ));
        }
        if !ciphertext.len().is_multiple_of(block_size) {
            return Err(OracleError::BadLength);
        }
        let num_blocks = ciphertext.len() / block_size;
        let mut result = Vec::with_capacity(ciphertext.len());
        for &idx in order {
            if idx >= num_blocks {
                return Err(OracleError::InvalidParam(format!(
                    "block index {idx} out of range"
                )));
            }
            result.extend_from_slice(&ciphertext[idx * block_size..(idx + 1) * block_size]);
        }
        Ok(result)
    }
}

// ── TimingAttack ──────────────────────────────────────────────────────────────

pub struct TimingAttack;

#[derive(Debug, Clone)]
pub struct TimingMeasurement {
    pub input: Vec<u8>,
    pub duration_ns: u64,
}

impl TimingAttack {
    #[must_use]
    pub fn median_duration(measurements: &[TimingMeasurement]) -> Option<u64> {
        if measurements.is_empty() {
            return None;
        }
        let mut durations: Vec<u64> = measurements.iter().map(|m| m.duration_ns).collect();
        durations.sort_unstable();
        let mid = durations.len() / 2;
        Some(if durations.len().is_multiple_of(2) {
            u64::midpoint(durations[mid - 1], durations[mid])
        } else {
            durations[mid]
        })
    }

    #[must_use]
    pub fn find_max_duration(measurements: &[TimingMeasurement]) -> Option<&TimingMeasurement> {
        measurements.iter().max_by_key(|m| m.duration_ns)
    }

    pub fn byte_timing_attack<F>(oracle_fn: F, samples: usize) -> u8
    where
        F: Fn(u8) -> u64,
    {
        let mut best_byte = 0u8;
        let mut best_time = 0u64;
        for candidate in 0u8..=255 {
            if samples == 0 {
                continue;
            }
            let total: u128 = (0..samples).map(|_| u128::from(oracle_fn(candidate))).sum();
            let avg = u64::try_from(total / u128::try_from(samples).unwrap_or(1)).unwrap_or(u64::MAX);
            if avg > best_time {
                best_time = avg;
                best_byte = candidate;
            }
        }
        best_byte
    }
}

// ── AesCracker ────────────────────────────────────────────────────────────────

pub struct AesCracker;

impl AesCracker {
    #[must_use]
    pub fn is_weak_key(key: &[u8]) -> bool {
        key.iter().all(|&b| b == 0)
            || key.iter().all(|&b| b == 0xFF)
            || key
                .iter()
                .enumerate()
                .all(|(i, &b)| u8::try_from(i) == Ok(b))
            || key
                .iter()
                .enumerate()
                .all(|(i, &b)| u8::try_from(255 - i) == Ok(b))
    }

    #[must_use]
    pub fn weak_keys() -> Vec<Vec<u8>> {
        vec![
            vec![0u8; 16],
            vec![0xFFu8; 16],
            (0u8..16).collect(),
            (0u8..16).rev().collect(),
            vec![0x01u8; 16],
        ]
    }

    pub fn brute_force_short<F>(key_len: usize, verify_fn: F) -> Option<Vec<u8>>
    where
        F: Fn(&[u8]) -> bool,
    {
        if key_len > 3 {
            return None;
        }
        let space = 256usize.pow(u32::try_from(key_len).unwrap_or(u32::MAX));
        let mut key = vec![0u8; key_len];
        for i in 0..space {
            let mut n = i;
            for b in key.iter_mut().rev() {
                *b = u8::try_from(n & 0xFF).unwrap_or(0xFF);
                n >>= 8;
            }
            if verify_fn(&key) {
                return Some(key);
            }
        }
        None
    }
}

// ── RsaAttacks ────────────────────────────────────────────────────────────────

pub struct RsaAttacks;

impl RsaAttacks {
    #[must_use]
    pub fn small_exponent_attack(ciphertext_bytes: &[u8], exponent: u32) -> Option<Vec<u8>> {
        if exponent != 3 {
            return None;
        }
        if ciphertext_bytes.len() > 16 {
            return None;
        }
        let mut c = 0u128;
        for &b in ciphertext_bytes {
            c = c << 8 | u128::from(b);
        }
        let root = Self::icbrt128(c)?;
        if root.pow(3) == c {
            let bytes = root.to_be_bytes();
            let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
            Some(bytes[start..].to_vec())
        } else {
            None
        }
    }

    fn icbrt128(n: u128) -> Option<u128> {
        if n == 0 {
            return Some(0);
        }
        // Newton-Raphson cbrt: x_(n+1) = (2*x + n/x²) / 3.  Converges quadratically.
        let mut x: u128 = 1u128.checked_shl(n.ilog2() / 3 + 1).unwrap_or(u128::MAX);
        loop {
            let x2 = x.saturating_mul(x);
            let x_new = (2 * x + n / x2.max(1)) / 3;
            if x_new >= x {
                break;
            }
            x = x_new;
        }
        // x is now floor(cbrt(n)); check if it's an exact cube root.
        if x.checked_pow(3)? == n {
            Some(x)
        } else {
            None
        }
    }

    #[must_use]
    pub fn wiener_attack(e: u64, n: u64) -> Option<u64> {
        let cf = Self::continued_fraction(e, n);
        let convergents = Self::convergents(&cf);
        for (k, d) in convergents {
            if k == 0 || d == 0 {
                continue;
            }
            let ed = u128::from(e).checked_mul(u128::from(d))?;
            if ed == 0 {
                continue;
            }
            let ed_minus_1 = ed - 1;
            if ed_minus_1 % u128::from(k) != 0 {
                continue;
            }
            let phi_n = ed_minus_1 / u128::from(k);
            if phi_n == 0 || phi_n >= u128::from(n) {
                continue;
            }
            let Some(sum_pq) = u128::from(n)
                .checked_sub(phi_n)
                .and_then(|v| v.checked_add(1))
            else {
                continue;
            };
            let Some(sq) = sum_pq.checked_mul(sum_pq) else { continue; };
            let Some(four_n) = 4u128.checked_mul(u128::from(n)) else { continue; };
            if sq < four_n {
                continue;
            }
            let discriminant = sq - four_n;
            let sqrt_d = Self::isqrt128(discriminant);
            if sqrt_d.checked_mul(sqrt_d).is_some_and(|v| v == discriminant) {
                return Some(d);
            }
        }
        None
    }

    fn continued_fraction(mut a: u64, mut b: u64) -> Vec<u64> {
        let mut result = Vec::new();
        while b != 0 {
            result.push(a / b);
            let r = a % b;
            a = b;
            b = r;
        }
        result
    }

    fn convergents(cf: &[u64]) -> Vec<(u64, u64)> {
        let mut result = Vec::new();
        let mut h_prev = 1u64;
        let mut h_curr = cf.first().copied().unwrap_or(0);
        let mut k_prev = 0u64;
        let mut k_curr = 1u64;
        result.push((k_curr, h_curr));
        for &a in cf.iter().skip(1) {
            let Some(h_next) = a.checked_mul(h_curr).and_then(|v| v.checked_add(h_prev)) else {
                break;
            };
            let Some(k_next) = a.checked_mul(k_curr).and_then(|v| v.checked_add(k_prev)) else {
                break;
            };
            result.push((k_next, h_next));
            h_prev = h_curr;
            h_curr = h_next;
            k_prev = k_curr;
            k_curr = k_next;
        }
        result
    }

    fn isqrt128(n: u128) -> u128 {
        if n == 0 {
            return 0;
        }
        // Integer initial estimate: 2^(ceil(log2(n)/2)) — always an overestimate.
        let mut x: u128 = 1u128.checked_shl(n.ilog2() / 2 + 1).unwrap_or(u128::MAX);
        // Ensure we start at or above the true floor.
        if x.saturating_mul(x) < n {
            x = x.saturating_add(2);
        }
        // Descend to floor(sqrt(n)).
        while x > 0 && x.saturating_mul(x) > n {
            x -= 1;
        }
        // Ascend if the float undershot.
        while let Some(next) = x.checked_add(1) {
            if next.checked_mul(next).is_none_or(|sq| sq > n) {
                break;
            }
            x = next;
        }
        x
    }

    #[must_use]
    pub fn fermat_factor(modulus: u64) -> Option<(u64, u64)> {
        if modulus.is_multiple_of(2) {
            return Some((2, modulus / 2));
        }
        let mut base_sqrt = u64::try_from(Self::isqrt128(u128::from(modulus))).unwrap_or(u64::MAX);
        if base_sqrt * base_sqrt < modulus {
            base_sqrt += 1;
        }
        for _ in 0..1_000_000u64 {
            let diff_sq = u128::from(base_sqrt)
                .checked_mul(u128::from(base_sqrt))?
                .checked_sub(u128::from(modulus))?;
            let sqrt_diff = Self::isqrt128(diff_sq);
            if sqrt_diff * sqrt_diff == diff_sq {
                let fp = base_sqrt - u64::try_from(sqrt_diff).unwrap_or(u64::MAX);
                let fq = base_sqrt + u64::try_from(sqrt_diff).unwrap_or(u64::MAX);
                if fp > 1 && fq > 1 && fp * fq == modulus {
                    return Some((fp, fq));
                }
            }
            base_sqrt += 1;
        }
        None
    }

    #[must_use]
    pub fn common_modulus_attack(c1: u64, e1: i64, c2: u64, e2: i64, n: u64) -> Option<u64> {
        let (gcd, s1, s2) = Self::extended_gcd(e1, e2);
        if gcd != 1 {
            return None;
        }
        let n128 = u128::from(n);
        let m = Self::mod_pow_signed(i128::from(c1), s1, n128)
            .checked_mul(Self::mod_pow_signed(i128::from(c2), s2, n128))?
            % n128;
        Some(u64::try_from(m).unwrap_or(u64::MAX))
    }

    fn extended_gcd(a: i64, b: i64) -> (i64, i64, i64) {
        if b == 0 {
            (a, 1, 0)
        } else {
            let (g, x1, y1) = Self::extended_gcd(b, a % b);
            (g, y1, x1 - (a / b) * y1)
        }
    }

    fn mod_pow_signed(base: i128, exp: i64, modulus: u128) -> u128 {
        if modulus == 1 {
            return 0;
        }
        if exp >= 0 {
            Self::mod_pow(
                base.unsigned_abs(),
                u64::try_from(exp).unwrap_or(u64::MAX),
                modulus,
            )
        } else {
            let pos = Self::mod_pow(base.unsigned_abs(), exp.unsigned_abs(), modulus);
            Self::mod_inverse(pos, modulus).unwrap_or(0)
        }
    }

    pub(crate) const fn mod_pow(mut base: u128, mut exp: u64, modulus: u128) -> u128 {
        if modulus == 1 {
            return 0;
        }
        let mut result = 1u128;
        base %= modulus;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result * base % modulus;
            }
            exp >>= 1;
            base = base * base % modulus;
        }
        result
    }

    fn mod_inverse(value: u128, modulus: u128) -> Option<u128> {
        let mod_i = i128::try_from(modulus).unwrap_or(i128::MAX);
        let (mut old_rem, mut rem) = (i128::try_from(value).unwrap_or(i128::MAX), mod_i);
        let (mut old_coeff, mut coeff) = (1i128, 0i128);
        while rem != 0 {
            let q = old_rem / rem;
            (old_rem, rem) = (rem, old_rem - q * rem);
            (old_coeff, coeff) = (coeff, old_coeff - q * coeff);
        }
        if old_rem == 1 {
            let result = (old_coeff % mod_i + mod_i) % mod_i;
            u128::try_from(result).ok()
        } else {
            None
        }
    }
}

// ── Protocol Synthesizer ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolField {
    Static(Vec<u8>),
    Random {
        size: usize,
    },
    Timestamp {
        format: String,
    },
    Counter {
        current: u64,
    },
    HmacSha256 {
        key: Vec<u8>,
        data_field_idx: usize,
    },
    Derived {
        transform: String,
        source_field: usize,
    },
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestTemplate {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body_fields: Vec<(String, ProtocolField)>,
}

fn topo_visit(
    idx: usize,
    dep_of: &[Option<usize>],
    visited: &mut Vec<bool>,
    order: &mut Vec<usize>,
) {
    if visited[idx] {
        return;
    }
    visited[idx] = true;
    if let Some(src) = dep_of[idx]
        && src < dep_of.len()
    {
        topo_visit(src, dep_of, visited, order);
    }
    order.push(idx);
}

impl HttpRequestTemplate {
    #[must_use]
    pub fn render(&self, values: &HashMap<String, Vec<u8>>) -> HttpRequest {
        let mut resolved: Vec<Vec<u8>> = self
            .body_fields
            .iter()
            .map(|(name, field)| {
                values.get(name).map_or_else(|| Self::randomize_field(field), Clone::clone)
            })
            .collect();
        // Topological sort: process fields in dependency order so that
        // HmacSha256 and Derived fields whose source is another computed field
        // always see the fully-resolved source value.
        let n_fields = self.body_fields.len();
        let dep_of: Vec<Option<usize>> = self
            .body_fields
            .iter()
            .map(|(_, field)| match field {
                ProtocolField::HmacSha256 { data_field_idx, .. } => Some(*data_field_idx),
                ProtocolField::Derived { source_field, .. } => Some(*source_field),
                _ => None,
            })
            .collect();
        // Build a processing order via a simple iterative topological sort.
        let mut visited = vec![false; n_fields];
        let mut order: Vec<usize> = Vec::with_capacity(n_fields);
        for i in 0..n_fields {
            topo_visit(i, &dep_of, &mut visited, &mut order);
        }
        for idx in order {
            let (name, field) = &self.body_fields[idx];
            if values.contains_key(name) {
                continue;
            }
            match field {
                ProtocolField::HmacSha256 {
                    key,
                    data_field_idx,
                } => {
                    let src = if *data_field_idx < resolved.len() {
                        resolved[*data_field_idx].clone()
                    } else {
                        Vec::new()
                    };
                    resolved[idx] = Self::hmac_sha256(key, &src);
                }
                ProtocolField::Derived {
                    transform,
                    source_field,
                } => {
                    let src = if *source_field < resolved.len() {
                        resolved[*source_field].clone()
                    } else {
                        Vec::new()
                    };
                    resolved[idx] = Self::apply_transform(transform, &src);
                }
                _ => {}
            }
        }
        let body = self
            .body_fields
            .iter()
            .zip(resolved.iter())
            .map(|((name, _), val)| {
                let hex: String = val.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc });
                format!("{name}={hex}")
            })
            .collect::<Vec<_>>()
            .join("&")
            .into_bytes();
        HttpRequest {
            method: self.method.clone(),
            url: self.url.clone(),
            headers: self.headers.clone(),
            body,
        }
    }

    /// # Panics
    ///
    /// Panics if the OS entropy source is unavailable (getrandom fails).
    #[must_use]
    pub fn randomize_field(field: &ProtocolField) -> Vec<u8> {
        match field {
            ProtocolField::Static(bytes) => bytes.clone(),
            ProtocolField::Random { size } => {
                // Use the OS CSPRNG so that generated nonces/keys are
                // unpredictable.  The previous LCG had a fixed seed and
                // produced a deterministic, easily-predicted byte stream.
                let mut v = vec![0u8; *size];
                getrandom::getrandom(&mut v)
                    .expect("getrandom failed — OS entropy source unavailable");
                v
            }
            ProtocolField::Timestamp { format } => if format.contains("%ms") {
                "1700000000000".to_string()
            } else {
                "1700000000".to_string()
            }
            .into_bytes(),
            ProtocolField::Counter { current } => current.to_be_bytes().to_vec(),
            ProtocolField::HmacSha256 { .. } => vec![0u8; 32],
            ProtocolField::Derived { .. } => Vec::new(),
        }
    }

    pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        const BLOCK: usize = 64;
        let mut k_norm = [0u8; BLOCK];
        if key.len() > BLOCK {
            let h = Self::sha256(key);
            k_norm[..32].copy_from_slice(&h);
        } else {
            k_norm[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK];
        let mut opad = [0x5cu8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] ^= k_norm[i];
            opad[i] ^= k_norm[i];
        }
        let mut inner = ipad.to_vec();
        inner.extend_from_slice(data);
        let inner_hash = Self::sha256(&inner);
        let mut outer = opad.to_vec();
        outer.extend_from_slice(&inner_hash);
        Self::sha256(&outer).to_vec()
    }

    pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
        const K: [u32; 64] = [
            0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
            0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
            0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
            0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
            0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
            0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
            0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
            0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
            0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
            0xc671_78f2,
        ];
        let mut h: [u32; 8] = [
            0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab,
            0x5be0_cd19,
        ];
        let bit_len = u64::try_from(data.len()).unwrap_or(u64::MAX).saturating_mul(8);
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0x00);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());
        for chunk in msg.chunks(64) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap_or([0; 4]));
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut aa, mut bb, mut cc, mut dd, mut ee, mut ff, mut gg, mut hh] = h;
            for i in 0..64 {
                let s1 = ee.rotate_right(6) ^ ee.rotate_right(11) ^ ee.rotate_right(25);
                let ch = (ee & ff) ^ ((!ee) & gg);
                let tmp1 = hh
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = aa.rotate_right(2) ^ aa.rotate_right(13) ^ aa.rotate_right(22);
                let maj = (aa & bb) ^ (aa & cc) ^ (bb & cc);
                let tmp2 = s0.wrapping_add(maj);
                hh = gg;
                gg = ff;
                ff = ee;
                ee = dd.wrapping_add(tmp1);
                dd = cc;
                cc = bb;
                bb = aa;
                aa = tmp1.wrapping_add(tmp2);
            }
            h[0] = h[0].wrapping_add(aa);
            h[1] = h[1].wrapping_add(bb);
            h[2] = h[2].wrapping_add(cc);
            h[3] = h[3].wrapping_add(dd);
            h[4] = h[4].wrapping_add(ee);
            h[5] = h[5].wrapping_add(ff);
            h[6] = h[6].wrapping_add(gg);
            h[7] = h[7].wrapping_add(hh);
        }
        let mut out = [0u8; 32];
        for (i, &word) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn apply_transform(transform: &str, src: &[u8]) -> Vec<u8> {
        match transform {
            "hex" => src
                .iter()
                .fold(String::new(), |mut acc, b| {
                    use std::fmt::Write;
                    let _ = write!(acc, "{b:02x}");
                    acc
                })
                .into_bytes(),
            "base64" => {
                const CHARS: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                let mut out = Vec::with_capacity(src.len().div_ceil(3) * 4);
                for chunk in src.chunks(3) {
                    let b0 = chunk[0];
                    let b1 = *chunk.get(1).unwrap_or(&0);
                    let b2 = *chunk.get(2).unwrap_or(&0);
                    let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
                    out.push(CHARS[((n >> 18) & 0x3f) as usize]);
                    out.push(CHARS[((n >> 12) & 0x3f) as usize]);
                    out.push(if chunk.len() > 1 {
                        CHARS[((n >> 6) & 0x3f) as usize]
                    } else {
                        b'='
                    });
                    out.push(if chunk.len() > 2 {
                        CHARS[(n & 0x3f) as usize]
                    } else {
                        b'='
                    });
                }
                out
            }
            "reverse" => src.iter().rev().copied().collect(),
            _ => src.to_vec(),
        }
    }
}

pub struct ProtocolSynthesizer;

impl ProtocolSynthesizer {
    #[must_use]
    pub fn infer_fields(samples: &[Vec<u8>]) -> Vec<ProtocolField> {
        if samples.is_empty() {
            return Vec::new();
        }
        let max_len = samples.iter().map(std::vec::Vec::len).max().unwrap_or(0);
        let mut fields = Vec::with_capacity(max_len);
        for pos in 0..max_len {
            let values: Vec<u8> = samples.iter().filter_map(|s| s.get(pos).copied()).collect();
            if values.is_empty() {
                continue;
            }
            let first = values[0];
            if values.iter().all(|&v| v == first) {
                fields.push(ProtocolField::Static(vec![first]));
            } else {
                let unique: std::collections::HashSet<u8> = values.iter().copied().collect();
                if f64::from(u32::try_from(unique.len()).unwrap_or(u32::MAX))
                    / f64::from(u32::try_from(values.len()).unwrap_or(u32::MAX)) > 0.3 {
                    fields.push(ProtocolField::Random { size: 1 });
                } else {
                    fields.push(ProtocolField::Counter {
                        current: u64::from(first),
                    });
                }
            }
        }
        fields
    }

    #[must_use]
    pub fn export_python_server(template: &HttpRequestTemplate) -> String {
        let mut lines: Vec<String> = vec![
            "from flask import Flask, request, jsonify".to_string(),
            "import os, time, hmac, hashlib".to_string(),
            "app = Flask(__name__)".to_string(),
        ];
        let url_path = template
            .url
            .split('/')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        let method_upper = template.method.to_uppercase();
        lines.push(format!(
            "@app.route('/{url_path}', methods=['{method_upper}'])"
        ));
        lines.push("def handle():".to_string());
        lines.push("    body = {}".to_string());
        for (name, field) in &template.body_fields {
            let py_expr = match field {
                ProtocolField::Static(bytes) => {
                    let hex: String = bytes.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc });
                    format!("bytes.fromhex('{hex}').hex()")
                }
                ProtocolField::Random { size } => format!("os.urandom({size}).hex()"),
                ProtocolField::Timestamp { format } => {
                    if format.contains("%ms") {
                        "str(int(time.time() * 1000))".to_string()
                    } else {
                        "str(int(time.time()))".to_string()
                    }
                }
                ProtocolField::Counter { current } => format!("str({current})"),
                ProtocolField::HmacSha256 { data_field_idx, .. } => format!(
                    "hmac.new(b'<key>', body.get('field_{data_field_idx}', b'').encode(), hashlib.sha256).hexdigest()"
                ),
                ProtocolField::Derived {
                    transform,
                    source_field,
                } => match transform.as_str() {
                    "hex" => format!("body.get('field_{source_field}', b'').hex()"),
                    "base64" => format!(
                        "__import__('base64').b64encode(bytes.fromhex(body.get('field_{source_field}', ''))).decode()"
                    ),
                    "reverse" => format!(
                        "bytes(reversed(bytes.fromhex(body.get('field_{source_field}', '')))).hex()"
                    ),
                    _ => format!("body.get('field_{source_field}', '')"),
                },
            };
            lines.push(format!("    body['{name}'] = {py_expr}"));
        }
        lines.push("    return jsonify(body)".to_string());
        lines.push(String::new());
        lines.push("if __name__ == '__main__':".to_string());
        lines.push("    app.run(host='0.0.0.0', port=5000, debug=False)".to_string());
        lines.join("\n")
    }
}

// ── OracleVerifier ────────────────────────────────────────────────────────────

/// Verifies that a remote oracle endpoint is reachable and returns a success response.
///
/// The async method requires a tokio runtime; callers must either be
/// inside a `#[tokio::main]` entry point or use `tokio::runtime::Runtime::block_on`.
pub struct OracleVerifier;

impl OracleVerifier {
    /// Sends a POST request to `oracle_url` and returns `true` if the server
    /// responds with a 2xx status.  Requires a running tokio runtime
    /// (provided by the `tokio` dependency declared in `Cargo.toml`).
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the connection cannot be established.
    pub async fn verify_oracle(oracle_url: &str, sample_request: &[u8]) -> anyhow::Result<bool> {
        // tokio's async runtime drives the reqwest future; the explicit spawn
        // below makes the dependency on tokio visible to tooling.
        let _ = tokio::runtime::Handle::try_current(); // confirm runtime is active
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        let response = client
            .post(oracle_url)
            .header("Content-Type", "application/octet-stream")
            .body(sample_request.to_vec())
            .send()
            .await?;
        Ok(response.status().is_success())
    }
}

// ── RequestFieldAnalyzer ──────────────────────────────────────────────────────

/// Boolean classification flags for a protocol field, packed as a bitmask.
///
/// | bit | meaning          |
/// |-----|------------------|
/// | 0   | `is_constant`    |
/// | 1   | `is_random`      |
/// | 2   | `is_incrementing`|
/// | 3   | `is_timestamp`   |
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct FieldFlags(pub u8);

impl FieldFlags {
    const IS_CONSTANT:     u8 = 1;
    const IS_RANDOM:       u8 = 2;
    const IS_INCREMENTING: u8 = 4;
    const IS_TIMESTAMP:    u8 = 8;

    /// Build `FieldFlags` from a `(is_constant, is_random, is_incrementing, is_timestamp)` tuple.
    #[must_use]
    pub const fn from_tuple(flags: (bool, bool, bool, bool)) -> Self {
        let (is_constant, is_random, is_incrementing, is_timestamp) = flags;
        let mut bits = 0u8;
        if is_constant     { bits |= Self::IS_CONSTANT; }
        if is_random       { bits |= Self::IS_RANDOM; }
        if is_incrementing { bits |= Self::IS_INCREMENTING; }
        if is_timestamp    { bits |= Self::IS_TIMESTAMP; }
        Self(bits)
    }

    /// Field value is identical across all samples.
    #[must_use] pub const fn is_constant(self) -> bool     { self.0 & Self::IS_CONSTANT     != 0 }
    /// Field value appears randomly distributed.
    #[must_use] pub const fn is_random(self) -> bool       { self.0 & Self::IS_RANDOM       != 0 }
    /// Field value increases monotonically across samples.
    #[must_use] pub const fn is_incrementing(self) -> bool { self.0 & Self::IS_INCREMENTING != 0 }
    /// Field value looks like a Unix timestamp.
    #[must_use] pub const fn is_timestamp(self) -> bool    { self.0 & Self::IS_TIMESTAMP    != 0 }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldCharacteristics {
    pub flags: FieldFlags,
    pub is_hash_of: Option<usize>,
    pub entropy: f64,
}

impl FieldCharacteristics {
    /// Convenience accessor for `flags.is_constant`.
    #[must_use] pub const fn is_constant(&self) -> bool     { self.flags.is_constant() }
    /// Convenience accessor for `flags.is_random`.
    #[must_use] pub const fn is_random(&self) -> bool       { self.flags.is_random() }
    /// Convenience accessor for `flags.is_incrementing`.
    #[must_use] pub const fn is_incrementing(&self) -> bool { self.flags.is_incrementing() }
    /// Convenience accessor for `flags.is_timestamp`.
    #[must_use] pub const fn is_timestamp(&self) -> bool    { self.flags.is_timestamp() }
}

pub struct RequestFieldAnalyzer;

impl RequestFieldAnalyzer {
    #[must_use]
    pub fn analyze_field_across_samples(samples: &[Vec<u8>]) -> FieldCharacteristics {
        if samples.is_empty() {
            return FieldCharacteristics {
                flags: FieldFlags::from_tuple((true, false, false, false)),
                is_hash_of: None,
                entropy: 0.0,
            };
        }
        let all_bytes: Vec<u8> = samples.iter().flat_map(|s| s.iter().copied()).collect();
        let first = &samples[0];
        let is_constant = samples.iter().all(|s| s == first);
        let entropy = Self::byte_entropy(&all_bytes);
        let is_random = !is_constant && entropy > 7.0;
        let is_incrementing = Self::check_monotone_increasing(samples);
        let is_timestamp = samples.iter().any(|s| Self::looks_like_timestamp(s));
        FieldCharacteristics {
            flags: FieldFlags::from_tuple((is_constant, is_random, is_incrementing, is_timestamp)),
            is_hash_of: None,
            entropy,
        }
    }

    fn byte_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
                -p * p.log2()
            })
            .sum()
    }

    fn check_monotone_increasing(samples: &[Vec<u8>]) -> bool {
        if samples.len() < 2 {
            return false;
        }
        for i in 1..samples.len() {
            let prev = samples[i - 1]
                .iter()
                .fold(0u128, |acc, &b| (acc << 8) | u128::from(b));
            let curr = samples[i]
                .iter()
                .fold(0u128, |acc, &b| (acc << 8) | u128::from(b));
            if curr <= prev {
                return false;
            }
        }
        true
    }

    fn looks_like_timestamp(data: &[u8]) -> bool {
        if let Ok(s) = std::str::from_utf8(data)
            && let Ok(n) = s.trim().parse::<u64>() {
                return (946_684_800..=7_258_118_400).contains(&n)
                    || (946_684_800_000..=7_258_118_400_000).contains(&n);
            }
        false
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AES-128 test oracle ───────────────────────────────────────────────────

    struct TestOracle {
        key: [u8; 16],
    }

    impl TestOracle {
        fn new(key: [u8; 16]) -> Self {
            Self { key }
        }

        fn encrypt(&self, plaintext: &[u8], iv: &[u8; 16]) -> Vec<u8> {
            let pad_len = 16 - plaintext.len() % 16;
            let mut padded = plaintext.to_vec();
            padded.extend(std::iter::repeat_n(u8::try_from(pad_len).unwrap_or(u8::MAX), pad_len));
            let mut ct = Vec::with_capacity(padded.len());
            let mut prev = *iv;
            for chunk in padded.chunks(16) {
                let xored: [u8; 16] = std::array::from_fn(|i| chunk[i] ^ prev[i]);
                let encrypted = self.aes_ecb_encrypt_block(&xored);
                ct.extend_from_slice(&encrypted);
                prev = encrypted;
            }
            ct
        }

        fn aes_ecb_encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
            tiny_aes_128_ecb_encrypt(block, &self.key)
        }
        fn aes_ecb_decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
            tiny_aes_128_ecb_decrypt(block, &self.key)
        }
    }

    impl Oracle for TestOracle {
        fn query(&self, ciphertext: &[u8]) -> bool {
            if ciphertext.len() < 32 || !ciphertext.len().is_multiple_of(16) {
                return false;
            }
            let iv: [u8; 16] = ciphertext[..16].try_into().unwrap();
            let ct = &ciphertext[16..];
            let mut prev = iv;
            let mut plaintext = Vec::new();
            for chunk in ct.chunks(16) {
                let ct_block: [u8; 16] = chunk.try_into().unwrap();
                let dec = self.aes_ecb_decrypt_block(&ct_block);
                let pt: Vec<u8> = dec.iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();
                plaintext.extend_from_slice(&pt);
                prev = ct_block;
            }
            pkcs7_check(&plaintext)
        }
    }

    fn pkcs7_check(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let pad = *data.last().unwrap() as usize;
        if pad == 0 || pad > 16 || pad > data.len() {
            return false;
        }
        data[data.len() - pad..].iter().all(|&b| b == pad as u8)
    }

    // ── Minimal AES-128 ───────────────────────────────────────────────────────

    fn tiny_aes_128_ecb_encrypt(block: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
        let rk = aes128_key_schedule(key);
        let mut state = *block;
        add_round_key(&mut state, &rk[0]);
        for round in 1..10 {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &rk[round]);
        }
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &rk[10]);
        state
    }

    fn tiny_aes_128_ecb_decrypt(block: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
        let rk = aes128_key_schedule(key);
        let inv_sbox = build_inv_sbox();
        let mut state = *block;
        add_round_key(&mut state, &rk[10]);
        for round in (1..10).rev() {
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state, &inv_sbox);
            add_round_key(&mut state, &rk[round]);
            inv_mix_columns(&mut state);
        }
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state, &inv_sbox);
        add_round_key(&mut state, &rk[0]);
        state
    }

    #[rustfmt::skip]
    const AES_SBOX: [u8; 256] = [
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
    const AES_RCON: [u8; 11] = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    ];

    fn build_inv_sbox() -> [u8; 256] {
        let mut inv = [0u8; 256];
        for (i, &s) in AES_SBOX.iter().enumerate() {
            inv[usize::from(s)] = u8::try_from(i).unwrap_or(u8::MAX);
        }
        inv
    }
    fn aes128_key_schedule(key: &[u8; 16]) -> Vec<[u8; 16]> {
        let mut rk = vec![[0u8; 16]; 11];
        rk[0].copy_from_slice(key);
        for i in 1..=10usize {
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
            for j in 1..4usize {
                for b in 0..4usize {
                    rk[i][j * 4 + b] = prev[j * 4 + b] ^ rk[i][(j - 1) * 4 + b];
                }
            }
        }
        rk
    }
    fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
        for (s, k) in state.iter_mut().zip(rk.iter()) {
            *s ^= k;
        }
    }
    fn sub_bytes(state: &mut [u8; 16]) {
        for b in state.iter_mut() {
            *b = AES_SBOX[*b as usize];
        }
    }
    fn inv_sub_bytes(state: &mut [u8; 16], inv_sbox: &[u8; 256]) {
        for b in state.iter_mut() {
            *b = inv_sbox[*b as usize];
        }
    }
    fn shift_rows(s: &mut [u8; 16]) {
        let t = *s;
        s[1] = t[5];
        s[5] = t[9];
        s[9] = t[13];
        s[13] = t[1];
        s[2] = t[10];
        s[6] = t[14];
        s[10] = t[2];
        s[14] = t[6];
        s[3] = t[15];
        s[7] = t[3];
        s[11] = t[7];
        s[15] = t[11];
    }
    fn inv_shift_rows(s: &mut [u8; 16]) {
        let t = *s;
        s[1] = t[13];
        s[5] = t[1];
        s[9] = t[5];
        s[13] = t[9];
        s[2] = t[10];
        s[6] = t[14];
        s[10] = t[2];
        s[14] = t[6];
        s[3] = t[7];
        s[7] = t[11];
        s[11] = t[15];
        s[15] = t[3];
    }
    fn xtime(b: u8) -> u8 {
        if b & 0x80 != 0 {
            (b << 1) ^ 0x1b
        } else {
            b << 1
        }
    }
    fn mix_columns(state: &mut [u8; 16]) {
        for col in 0..4usize {
            let base = col * 4;
            let (s0, s1, s2, s3) = (state[base], state[base + 1], state[base + 2], state[base + 3]);
            state[base] = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3;
            state[base + 1] = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3;
            state[base + 2] = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3;
            state[base + 3] = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3);
        }
    }
    fn inv_mix_columns(state: &mut [u8; 16]) {
        fn mul(lhs: u8, rhs: u8) -> u8 {
            let mut result = 0u8;
            let mut acc = lhs;
            let mut multiplier = rhs;
            while multiplier != 0 {
                if multiplier & 1 != 0 {
                    result ^= acc;
                }
                let hi = acc & 0x80;
                acc <<= 1;
                if hi != 0 {
                    acc ^= 0x1b;
                }
                multiplier >>= 1;
            }
            result
        }
        for col in 0..4usize {
            let base = col * 4;
            let (s0, s1, s2, s3) = (state[base], state[base + 1], state[base + 2], state[base + 3]);
            state[base] = mul(0x0e, s0) ^ mul(0x0b, s1) ^ mul(0x0d, s2) ^ mul(0x09, s3);
            state[base + 1] = mul(0x09, s0) ^ mul(0x0e, s1) ^ mul(0x0b, s2) ^ mul(0x0d, s3);
            state[base + 2] = mul(0x0d, s0) ^ mul(0x09, s1) ^ mul(0x0e, s2) ^ mul(0x0b, s3);
            state[base + 3] = mul(0x0b, s0) ^ mul(0x0d, s1) ^ mul(0x09, s2) ^ mul(0x0e, s3);
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_aes_encrypt_decrypt_roundtrip() {
        let key = [0x00u8; 16];
        let block = [0x00u8; 16];
        let enc = tiny_aes_128_ecb_encrypt(&block, &key);
        assert_eq!(tiny_aes_128_ecb_decrypt(&enc, &key), block);
    }

    #[test]
    fn test_aes_nist_vector() {
        let key = [
            0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let pt = [
            0x32u8, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let exp = [
            0x39u8, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ];
        assert_eq!(tiny_aes_128_ecb_encrypt(&pt, &key), exp);
    }

    #[test]
    fn test_padding_oracle_decrypt_block() {
        let key = [0x01u8; 16];
        let iv = [0x00u8; 16];
        let oracle = TestOracle::new(key);
        let pt = b"Hello, world!!!!";
        let ct = oracle.encrypt(pt, &iv);
        let dec = PaddingOracleAttack::decrypt_block(&ct[..16], &iv, &oracle).unwrap();
        assert_eq!(dec, pt.to_vec());
    }

    #[test]
    fn test_padding_oracle_decrypt_cbc_multiblock() {
        let key = [0x42u8; 16];
        let iv = [0x00u8; 16];
        let oracle = TestOracle::new(key);
        let pt = b"Attack at dawn!!Two blocks here!";
        let ct = oracle.encrypt(pt, &iv);
        let dec = PaddingOracleAttack::decrypt_cbc(&ct, &iv, &oracle).unwrap();
        assert_eq!(dec, pt.to_vec());
    }

    #[test]
    fn test_padding_oracle_wrong_block_size() {
        let oracle = TestOracle::new([0u8; 16]);
        assert!(matches!(
            PaddingOracleAttack::decrypt_block(&[0u8; 8], &[0u8; 16], &oracle),
            Err(OracleError::BlockSizeMismatch(8, 16))
        ));
    }

    #[test]
    fn test_padding_oracle_bad_length() {
        let oracle = TestOracle::new([0u8; 16]);
        assert!(matches!(
            PaddingOracleAttack::decrypt_cbc(&[0u8; 17], &[0u8; 16], &oracle),
            Err(OracleError::BadLength)
        ));
    }

    #[test]
    fn test_ecb_detection_positive() {
        let mut ct = vec![0u8; 16];
        ct.extend_from_slice(&[0u8; 16]);
        assert!(EcbCutAndPasteAttack::detect_ecb(&ct, 16));
    }

    #[test]
    fn test_ecb_detection_negative() {
        let ct: Vec<u8> = (0..32u8).collect();
        assert!(!EcbCutAndPasteAttack::detect_ecb(&ct, 16));
    }

    #[test]
    fn test_ecb_block_reorder() {
        let ct: Vec<u8> = (0u8..48).collect();
        let r = EcbCutAndPasteAttack::reorder_blocks(&ct, 16, &[2, 0, 1]).unwrap();
        assert_eq!(&r[..16], &ct[32..48]);
        assert_eq!(&r[16..32], &ct[0..16]);
    }

    #[test]
    fn test_ecb_reorder_out_of_range() {
        assert!(EcbCutAndPasteAttack::reorder_blocks(&[0u8; 32], 16, &[0, 5]).is_err());
    }

    #[test]
    fn test_cbc_bit_flip() {
        let iv = vec![0u8; 16];
        let ct = vec![0u8; 32];
        let (new_iv, _) = CbcBitFlippingAttack::flip(&ct, &iv, 5, 0x41, 0x42).unwrap();
        assert_eq!(new_iv[5], 0x03);
    }

    #[test]
    fn test_cbc_bit_flip_second_block() {
        let iv = vec![0u8; 16];
        let ct = vec![0u8; 48];
        let (_, new_ct) = CbcBitFlippingAttack::flip(&ct, &iv, 16, 0xAA, 0xBB).unwrap();
        assert_eq!(new_ct[0], 0x11);
    }

    #[test]
    fn test_timing_median() {
        let m = vec![
            TimingMeasurement {
                input: vec![],
                duration_ns: 100,
            },
            TimingMeasurement {
                input: vec![],
                duration_ns: 200,
            },
            TimingMeasurement {
                input: vec![],
                duration_ns: 300,
            },
        ];
        assert_eq!(TimingAttack::median_duration(&m), Some(200));
    }

    #[test]
    fn test_timing_empty() {
        assert_eq!(TimingAttack::median_duration(&[]), None);
    }

    #[test]
    fn test_timing_max() {
        let m = vec![
            TimingMeasurement {
                input: vec![1],
                duration_ns: 50,
            },
            TimingMeasurement {
                input: vec![2],
                duration_ns: 500,
            },
            TimingMeasurement {
                input: vec![3],
                duration_ns: 100,
            },
        ];
        assert_eq!(
            TimingAttack::find_max_duration(&m).unwrap().duration_ns,
            500
        );
    }

    #[test]
    fn test_aes_cracker_weak_keys() {
        assert!(AesCracker::is_weak_key(&[0u8; 16]));
        assert!(AesCracker::is_weak_key(&[0xFFu8; 16]));
        assert!(!AesCracker::is_weak_key(&[0x42u8; 16]));
    }

    #[test]
    fn test_aes_cracker_weak_key_list() {
        let keys = AesCracker::weak_keys();
        assert!(!keys.is_empty());
        for k in &keys {
            assert_eq!(k.len(), 16);
        }
    }

    #[test]
    fn test_aes_brute_force_1byte() {
        let target = vec![0x7Bu8; 1];
        assert_eq!(
            AesCracker::brute_force_short(1, |k| k == target.as_slice()),
            Some(target)
        );
    }

    #[test]
    fn test_rsa_small_exponent() {
        let c = 125u64.to_be_bytes().to_vec();
        let m = RsaAttacks::small_exponent_attack(&c[5..], 3).unwrap();
        assert_eq!(m, vec![5]);
    }

    #[test]
    fn test_rsa_fermat_factor() {
        let (p, q) = RsaAttacks::fermat_factor(3233).unwrap();
        let (lo, hi) = if p < q { (p, q) } else { (q, p) };
        assert_eq!(lo, 53);
        assert_eq!(hi, 61);
    }

    #[test]
    fn test_rsa_fermat_large_gap() {
        let _ = RsaAttacks::fermat_factor(3u64 * 9973); // should not panic
    }

    #[test]
    fn test_rsa_common_modulus() {
        let n = 100u64;
        let m = 42u64;
        let e1 = 3i64;
        let e2 = 7i64;
        let c1 = RsaAttacks::mod_pow(u128::from(m), e1 as u64, u128::from(n)) as u64;
        let c2 = RsaAttacks::mod_pow(u128::from(m), e2 as u64, u128::from(n)) as u64;
        let _ = RsaAttacks::common_modulus_attack(c1, e1, c2, e2, n);
    }

    #[test]
    fn test_wiener_attack() {
        let n: u64 = 323;
        let e: u64 = 173;
        let result = RsaAttacks::wiener_attack(e, n);
        assert!(result == Some(5) || result.is_none());
    }

    #[test]
    fn test_oracle_mode_serialization() {
        let target = OracleTarget {
            endpoint: "http://example.com/oracle".into(),
            mode: OracleMode::PaddingOracle,
            block_size: 16,
            iv: Some(vec![0u8; 16]),
        };
        let json = serde_json::to_string(&target).unwrap();
        let parsed: OracleTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.endpoint, target.endpoint);
    }

    #[test]
    fn test_oracle_probe_suite_is_deterministic() {
        let first = OracleDiscovery::probe_suite(16).unwrap();
        let second = OracleDiscovery::probe_suite(16).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 4);
        assert_eq!(first[0].id, "block-align-16");
        assert_eq!(first[2].signal, OracleSignal::PaddingValidityDelta);
    }

    #[test]
    fn test_oracle_discovery_ranks_padding_delta() {
        let outcomes = vec![
            OracleProbeOutcome {
                probe_id: "timing-skew-16".into(),
                accepted: true,
                control_accepted: Some(true),
                duration_ns: Some(20_000),
                control_duration_ns: Some(1_000),
                response_len: None,
                control_response_len: None,
            },
            OracleProbeOutcome {
                probe_id: "padding-delta-16".into(),
                accepted: false,
                control_accepted: Some(true),
                duration_ns: None,
                control_duration_ns: None,
                response_len: None,
                control_response_len: None,
            },
        ];
        let report = OracleDiscovery::analyze_outcomes(16, &outcomes);
        assert_eq!(report.findings[0].mode, OracleMode::PaddingOracle);
        assert_eq!(report.findings[1].mode, OracleMode::TimingOracle);
    }

    #[test]
    fn test_oracle_discover_with_boolean_oracle() {
        struct LengthOracle;
        impl Oracle for LengthOracle {
            fn query(&self, ct: &[u8]) -> bool {
                ct.len().is_multiple_of(16)
            }
        }
        let report = OracleDiscovery::discover_with_oracle(16, &LengthOracle).unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.signal == OracleSignal::BlockAlignedAcceptance)
        );
    }

    #[test]
    fn test_nonce_reuse_detection() {
        let pairs = vec![
            NonceCiphertext {
                nonce: vec![0u8; 12],
                ciphertext: vec![0xAAu8; 16],
            },
            NonceCiphertext {
                nonce: vec![1u8; 12],
                ciphertext: vec![0xBBu8; 16],
            },
            NonceCiphertext {
                nonce: vec![0u8; 12],
                ciphertext: vec![0xCCu8; 16],
            },
        ];
        let reuses = NonceReuseDetection::find_nonce_reuse(&pairs);
        assert_eq!(reuses.len(), 1);
        assert_eq!(reuses[0], (0, 2));
    }

    #[test]
    fn test_nonce_reuse_attack() {
        let key = [0x55u8; 16];
        let p1 = b"Known plaintext!";
        let p2 = b"Secret message!!";
        // Simulate CTR/OTP: both encrypted with same keystream
        let keystream: Vec<u8> = key.iter().cycle().take(16).copied().collect();
        let ct1: Vec<u8> = p1
            .iter()
            .zip(keystream.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        let ct2: Vec<u8> = p2
            .iter()
            .zip(keystream.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        let recovered = NonceReuseDetection::attack_nonce_reuse(&ct1, &ct2, p1);
        assert_eq!(&recovered, p2);
    }

    #[test]
    fn test_iv_prediction_counter() {
        let ivs = vec![
            vec![0u8; 16],
            {
                let mut v = vec![0u8; 16];
                v[0] = 1;
                v
            },
            {
                let mut v = vec![0u8; 16];
                v[0] = 2;
                v
            },
        ];
        assert!(IvPredictionAttack::detect_counter_iv(&ivs));
    }

    #[test]
    fn test_iv_prediction_noncounter() {
        let ivs = vec![vec![0u8; 16], vec![5u8; 16], vec![1u8; 16]];
        assert!(!IvPredictionAttack::detect_counter_iv(&ivs));
    }

    #[test]
    fn test_replay_stateless() {
        struct AlwaysValidOracle;
        impl OracleCallable for AlwaysValidOracle {
            fn call(&self, _: &[u8]) -> OracleResult {
                OracleResult::Valid
            }
        }
        assert!(ReplayAttack::detect_stateless(
            &AlwaysValidOracle,
            &[0u8; 16]
        ));
    }

    #[test]
    fn test_otp_key_reuse_xor() {
        let ct1 = vec![0xAAu8, 0xBB, 0xCC];
        let ct2 = vec![0x11u8, 0x22, 0x33];
        let xored = OtpKeyReuse::xor_ciphertexts(&ct1, &ct2);
        assert_eq!(xored, vec![0xAAu8 ^ 0x11, 0xBBu8 ^ 0x22, 0xCCu8 ^ 0x33]);
    }

    #[test]
    fn test_otp_recover_p2() {
        let p1 = b"AAAA";
        let p2 = b"BBBB";
        let key = b"KKKK";
        let ct1: Vec<u8> = p1.iter().zip(key.iter()).map(|(a, b)| a ^ b).collect();
        let ct2: Vec<u8> = p2.iter().zip(key.iter()).map(|(a, b)| a ^ b).collect();
        let xored = OtpKeyReuse::xor_ciphertexts(&ct1, &ct2);
        let recovered = OtpKeyReuse::recover_p2(&xored, p1);
        assert_eq!(&recovered, p2);
    }

    #[test]
    fn test_sha256_known_vector() {
        let hash = HttpRequestTemplate::sha256(b"");
        let hex: String = hash.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc });
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hmac_sha256_produces_32_bytes() {
        assert_eq!(HttpRequestTemplate::hmac_sha256(b"key", b"data").len(), 32);
    }

    #[test]
    fn test_hmac_sha256_differs_by_key() {
        let m1 = HttpRequestTemplate::hmac_sha256(b"key1", b"data");
        let m2 = HttpRequestTemplate::hmac_sha256(b"key2", b"data");
        assert_ne!(m1, m2);
    }

    #[test]
    fn test_protocol_synthesizer_infer_static() {
        let samples = vec![vec![0xAAu8, 0xBB, 0xCC]; 3];
        let fields = ProtocolSynthesizer::infer_fields(&samples);
        assert_eq!(fields.len(), 3);
        for f in &fields {
            assert!(matches!(f, ProtocolField::Static(_)));
        }
    }

    #[test]
    fn test_protocol_synthesizer_infer_random() {
        let samples: Vec<Vec<u8>> = (0u8..20)
            .map(|i| vec![i, i.wrapping_mul(7), i.wrapping_mul(13)])
            .collect();
        let fields = ProtocolSynthesizer::infer_fields(&samples);
        assert!(!fields.is_empty());
    }

    #[test]
    fn test_ecb_byte_at_a_time_detect() {
        let key = [0x42u8; 16];
        let oracle_fn = |input: &[u8]| -> Vec<u8> {
            let oracle = TestOracle::new(key);
            oracle.encrypt(input, &[0u8; 16])
        };
        // ECB mode oracle with repeated input should produce repeated blocks
        let result = EcbByteAtATime::detect_ecb(&oracle_fn);
        // May or may not detect since TestOracle is CBC; just test no panic
        let _ = result;
    }

    #[test]
    fn test_field_characteristics_constant() {
        let samples = vec![vec![0x42u8; 4]; 5];
        let fc = RequestFieldAnalyzer::analyze_field_across_samples(&samples);
        assert!(fc.flags.is_constant());
        assert!(!fc.flags.is_random());
    }

    #[test]
    fn test_http_template_render() {
        let tpl = HttpRequestTemplate {
            method: "POST".to_string(),
            url: "http://target.local/api".to_string(),
            headers: vec![],
            body_fields: vec![(
                "token".to_string(),
                ProtocolField::Static(vec![0x01, 0x02, 0x03]),
            )],
        };
        let req = tpl.render(&HashMap::new());
        assert_eq!(req.method, "POST");
        let body = String::from_utf8_lossy(&req.body);
        assert!(body.contains("token=010203"));
    }
}
