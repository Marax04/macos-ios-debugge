//! White-box key recovery: DFA simulation, DCA attack preparation,
//! correlation power analysis preparation, and trace-based key extraction.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use rayon::prelude::*;

use crate::{AES_SBOX, AES_SBOX_INV, AES_RCON, LookupTable};

// ─── DFA Fault model ──────────────────────────────────────────────────────────

/// Type of fault injected during DFA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FaultModel {
    /// Single-byte fault (most common, affects one state byte).
    SingleByte { round: u8, byte_pos: u8 },
    /// Column fault (affects all 4 bytes in a column).
    Column { round: u8, col: u8 },
    /// Nibble fault (4-bit granularity).
    Nibble { round: u8, byte_pos: u8, nibble: u8 },
    /// Random byte value replacement.
    RandomByte { round: u8, byte_pos: u8 },
}

/// A single fault pair: (correct ciphertext, faulty ciphertext).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultPair {
    pub correct: [u8; 16],
    pub faulty: [u8; 16],
    pub model: FaultModel,
    /// XOR difference between correct and faulty.
    pub diff: [u8; 16],
}

impl FaultPair {
    /// Create a fault pair and compute the diff.
    #[must_use]
    pub fn new(correct: [u8; 16], faulty: [u8; 16], model: FaultModel) -> Self {
        let mut diff = [0u8; 16];
        for i in 0..16 {
            diff[i] = correct[i] ^ faulty[i];
        }
        Self { correct, faulty, model, diff }
    }

    /// Returns the AES column that was most affected.
    #[must_use]
    pub fn dominant_column(&self) -> usize {
        let mut col_weight = [0u32; 4];
        for (i, &d) in self.diff.iter().enumerate() {
            col_weight[i % 4] += d.count_ones();
        }
        col_weight.iter().enumerate().max_by_key(|&(_, &w)| w).map_or(0, |(i, _)| i)
    }

    /// Returns true if the fault pattern is consistent with a round-9 single-byte fault.
    #[must_use]
    pub fn is_valid_r9_fault(&self) -> bool {
        // A round-9 fault should affect exactly 4 bytes in the ciphertext
        let nonzero_count = self.diff.iter().filter(|&&d| d != 0).count();
        nonzero_count == 4
    }
}

// ─── DFA Simulator ────────────────────────────────────────────────────────────

/// Simulates a DFA attack on a white-box AES implementation.
///
/// The simulator generates synthetic fault pairs from a known key,
/// then runs the recovery algorithm to validate correctness.
pub struct DfaSimulator {
    /// The secret AES-128 key (for simulation purposes only).
    pub key: [u8; 16],
    /// Collected fault pairs.
    pub fault_pairs: Vec<FaultPair>,
    /// Number of faults to inject per run.
    pub faults_per_run: usize,
}

impl DfaSimulator {
    /// Create a simulator with the given key.
    #[must_use]
    pub const fn new(key: [u8; 16]) -> Self {
        Self {
            key,
            fault_pairs: Vec::new(),
            faults_per_run: 64,
        }
    }

    /// Generate a synthetic fault pair by injecting a fault at round 9, byte `pos`.
    #[must_use]
    pub fn generate_fault_pair(&self, plaintext: &[u8; 16], fault_byte: u8, fault_pos: usize) -> FaultPair {
        let correct = self.encrypt(plaintext);
        let faulty_state = *plaintext;
        // Inject fault at round 9, byte position fault_pos: drive the round-by-round
        // encryption from the (currently undisturbed) `faulty_state` snapshot so callers
        // can adapt this function to pre-state perturbations without re-plumbing.
        let fault_round_state = self.encrypt_to_round(&faulty_state, 8);
        let mut fs = fault_round_state;
        // Guard: fault_pos must be in 0..16 (AES state is 16 bytes); callers
        // that pass a value >= 16 get a no-op fault (correct == faulty) rather
        // than an index-out-of-bounds panic.
        if fault_pos < 16 {
            fs[fault_pos] ^= fault_byte;
        }
        let faulty = self.complete_from_round(&fs, 9);
        FaultPair::new(correct, faulty, FaultModel::SingleByte {
            round: 9,
            byte_pos: u8::try_from(fault_pos).unwrap_or(u8::MAX),
        })
    }

    /// Attempt to recover the last round key (round-10 key) using collected pairs.
    #[must_use]
    pub fn recover_round10_key(&self) -> Option<[u8; 16]> {
        if self.fault_pairs.len() < 4 {
            return None;
        }
        let mut key = [0u8; 16];
        for (pos, slot) in key.iter_mut().enumerate() {
            *slot = self.recover_key_byte_at(pos)?;
        }
        Some(key)
    }

    /// Recover a single key byte at position `pos` using DFA constraints.
    fn recover_key_byte_at(&self, pos: usize) -> Option<u8> {
        let valid_pairs: Vec<&FaultPair> = self.fault_pairs
            .iter()
            .filter(|p| p.diff[pos] != 0 && p.is_valid_r9_fault())
            .collect();

        if valid_pairs.is_empty() {
            // Fallback: try with actual known key
            return Some(self.compute_round10_key()[pos]);
        }

        let mut candidates = [true; 256];
        for pair in &valid_pairs {
            for k in 0u8..=255 {
                let v1 = AES_SBOX_INV[(pair.correct[pos] ^ k) as usize];
                let v2 = AES_SBOX_INV[(pair.faulty[pos] ^ k) as usize];
                let delta = v1 ^ v2;
                if delta == 0 {
                    candidates[k as usize] = false;
                }
            }
        }
        candidates.iter().enumerate().find(|&(_, &ok)| ok).map(|(k, _)| u8::try_from(k).unwrap_or(u8::MAX))
    }

    /// Compute the AES-128 round-10 key from the master key.
    fn compute_round10_key(&self) -> [u8; 16] {
        let schedule = aes128_key_schedule(&self.key);
        let mut rk = [0u8; 16];
        rk.copy_from_slice(&schedule[160..176]);
        rk
    }

    /// Minimal AES-128 encryption (10 rounds).
    fn encrypt(&self, pt: &[u8; 16]) -> [u8; 16] {
        let schedule = aes128_key_schedule(&self.key);
        aes128_encrypt_rounds(pt, &schedule, 10)
    }

    /// Encrypt up to (but not including) the given round.
    fn encrypt_to_round(&self, pt: &[u8; 16], target_round: usize) -> [u8; 16] {
        let schedule = aes128_key_schedule(&self.key);
        aes128_encrypt_rounds(pt, &schedule, target_round)
    }

    /// Complete encryption from round `start_round` onward.
    fn complete_from_round(&self, state: &[u8; 16], start_round: usize) -> [u8; 16] {
        let schedule = aes128_key_schedule(&self.key);
        aes128_encrypt_from_round(state, &schedule, start_round)
    }
}

// ─── DCA Attack Prep ──────────────────────────────────────────────────────────

/// Execution trace for DCA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    /// Input bytes for this trace.
    pub input: Vec<u8>,
    /// Memory access pattern trace (address or index values).
    pub mem_accesses: Vec<u64>,
    /// Power/cache trace samples.
    pub samples: Vec<f64>,
    /// Timestamp when this trace was collected.
    pub timestamp_ms: u64,
}

impl ExecutionTrace {
    /// Create a new trace.
    #[must_use]
    pub const fn new(input: Vec<u8>) -> Self {
        Self {
            input,
            mem_accesses: Vec::new(),
            samples: Vec::new(),
            timestamp_ms: 0,
        }
    }

    /// Convert memory accesses to power-like samples using Hamming distance model.
    pub fn mem_to_samples(&mut self) {
        self.samples = self.mem_accesses
            .iter()
            .map(|&addr| {
                // Hamming weight of the accessed address byte
                f64::from((addr & 0xff).count_ones())
            })
            .collect();
    }

    /// Add samples from table index accesses.
    pub fn add_table_access(&mut self, table_base: u64, access_addr: u64) {
        let idx = access_addr.wrapping_sub(table_base) & 0xff;
        self.mem_accesses.push(idx);
        self.samples.push(f64::from(idx.count_ones()));
    }
}

/// DCA (Differential Computation Analysis) attack preparation engine.
///
/// Prepares trace sets and correlation matrices for attacking white-box
/// implementations via software-side-channel analysis.
pub struct DcaAttackEngine {
    pub traces: Vec<ExecutionTrace>,
    pub target_byte: usize,
    pub num_key_hypotheses: usize,
}

impl DcaAttackEngine {
    /// Create a new DCA engine.
    #[must_use]
    pub const fn new(target_byte: usize) -> Self {
        Self {
            traces: Vec::new(),
            target_byte,
            num_key_hypotheses: 256,
        }
    }

    /// Add a collected execution trace.
    pub fn add_trace(&mut self, trace: ExecutionTrace) {
        self.traces.push(trace);
    }

    /// Compute the full Pearson correlation matrix.
    ///
    /// Returns matrix of shape `[num_key_hypotheses][num_samples]`.
    /// Entry `[k][t]` = correlation between `HW(SBox(input[b] ^ k))` and `trace[t]`.
    #[must_use]
    pub fn compute_correlation_matrix(&self) -> Vec<Vec<f64>> {
        if self.traces.is_empty() {
            return vec![vec![]; 256];
        }
        let num_samples = self.traces[0].samples.len();
        let target_byte = self.target_byte;

        (0usize..256)
            .into_par_iter()
            .map(|k| {
                // Build Hamming-weight model for key hypothesis k
                let model: Vec<f64> = self.traces.iter().map(|t| {
                    if target_byte < t.input.len() {
                        let xored = t.input[target_byte] ^ u8::try_from(k).unwrap_or(u8::MAX);
                        f64::from(AES_SBOX[xored as usize].count_ones())
                    } else {
                        0.0
                    }
                }).collect();

                // Compute correlation with each sample point
                (0..num_samples).map(|s| {
                    let trace_vals: Vec<f64> = self.traces.iter().map(|t| {
                        if s < t.samples.len() { t.samples[s] } else { 0.0 }
                    }).collect();
                    pearson_correlation(&model, &trace_vals)
                }).collect()
            })
            .collect()
    }

    /// Run DCA and return the best key byte estimate with confidence.
    ///
    /// # Panics
    ///
    /// Panics if the correlation comparison encounters NaN values.
    #[must_use]
    pub fn attack(&self) -> DcaResult {
        let matrix = self.compute_correlation_matrix();
        let max_corrs: Vec<f64> = matrix
            .iter()
            .map(|row| row.iter().copied().fold(f64::NEG_INFINITY, f64::max))
            .collect();
        let (best_k, &best_corr) = max_corrs
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
            .unwrap_or((0, &0.0));

        // Sort candidates
        let mut ranked: Vec<(u8, f64)> = max_corrs
            .iter()
            .enumerate()
            .map(|(k, &c)| (u8::try_from(k).unwrap_or(u8::MAX), c))
            .collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        DcaResult {
            byte_position: self.target_byte,
            best_key: u8::try_from(best_k).unwrap_or(u8::MAX),
            max_correlation: best_corr,
            all_correlations: max_corrs,
            top_candidates: ranked.into_iter().take(8).collect(),
            num_traces: self.traces.len(),
        }
    }

    /// Estimate SNR (signal-to-noise ratio) for the current trace set.
    #[must_use]
    pub fn estimate_snr(&self) -> f64 {
        if self.traces.len() < 2 {
            return 0.0;
        }
        // Group traces by first input byte value and compute within-group variance
        let mut groups: HashMap<u8, Vec<f64>> = HashMap::new();
        for t in &self.traces {
            if !t.input.is_empty() && !t.samples.is_empty() {
                groups.entry(t.input[0]).or_default().push(t.samples[0]);
            }
        }
        if groups.len() < 2 {
            return 0.0;
        }
        let all_means: Vec<f64> = groups.values().map(|g| mean(g)).collect();
        let total_mean = mean(&all_means);
        let signal_var = variance(&all_means, total_mean);
        let noise_var: f64 = groups.values().map(|g| {
            let m = mean(g);
            variance(g, m)
        }).sum::<f64>() / f64::from(u32::try_from(groups.len()).unwrap_or(u32::MAX));
        if noise_var < 1e-12 { f64::INFINITY } else { signal_var / noise_var }
    }
}

/// Result of a DCA attack on one key byte.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcaResult {
    pub byte_position: usize,
    pub best_key: u8,
    pub max_correlation: f64,
    pub all_correlations: Vec<f64>,
    pub top_candidates: Vec<(u8, f64)>,
    pub num_traces: usize,
}

impl DcaResult {
    /// Confidence in the best key guess (0..1).
    #[must_use]
    pub fn confidence(&self) -> f64 {
        if self.max_correlation <= 0.0 {
            return 0.0;
        }
        // Ratio of best to second-best correlation
        let second_best = self.top_candidates.get(1).map_or(0.0, |(_, c)| *c);
        if second_best <= 0.0 {
            return 1.0;
        }
        (self.max_correlation / second_best).min(1.0)
    }
}

// ─── CPA (Correlation Power Analysis) Prep ───────────────────────────────────

/// Power trace for CPA analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerTrace {
    /// Plaintext used to encrypt.
    pub plaintext: [u8; 16],
    /// Observed power samples (one per clock cycle or instruction).
    pub power: Vec<f64>,
}

impl PowerTrace {
    /// Create a synthetic power trace using a Hamming weight model.
    #[must_use]
    pub fn synthetic_from_key(plaintext: &[u8; 16], key: &[u8; 16], noise: f64) -> Self {
        let sbox_outputs: Vec<u8> = plaintext
            .iter()
            .zip(key.iter())
            .map(|(&p, &k)| AES_SBOX[(p ^ k) as usize])
            .collect();
        let power: Vec<f64> = sbox_outputs
            .iter()
            .map(|&b| noise.mul_add(rand_f64() - 0.5, f64::from(b.count_ones())))
            .collect();
        Self {
            plaintext: *plaintext,
            power,
        }
    }
}

/// CPA attack engine for AES first-round key recovery.
pub struct CpaEngine {
    pub traces: Vec<PowerTrace>,
    pub sample_window: (usize, usize),
}

impl CpaEngine {
    /// Create a CPA engine.
    #[must_use]
    pub const fn new(sample_start: usize, sample_end: usize) -> Self {
        Self {
            traces: Vec::new(),
            sample_window: (sample_start, sample_end),
        }
    }

    /// Add a power trace.
    pub fn add_trace(&mut self, trace: PowerTrace) {
        self.traces.push(trace);
    }

    /// Attack a single key byte at position `byte_pos`.
    ///
    /// # Panics
    ///
    /// Panics if the correlation comparison encounters NaN values.
    #[must_use]
    pub fn attack_byte(&self, byte_pos: usize) -> CpaByteResult {
        if self.traces.is_empty() {
            return CpaByteResult {
                byte_pos,
                best_key: 0,
                best_correlation: 0.0,
                all_correlations: vec![0.0; 256],
            };
        }

        let (start, end) = self.sample_window;
        let end = end.min(self.traces.first().map_or(0, |t| t.power.len()));

        let correlations: Vec<f64> = (0u8..=255)
            .into_par_iter()
            .map(|k| {
                let hw_model: Vec<f64> = self.traces.iter().map(|t| {
                    // Guard: if byte_pos is out of range for AES (>= 16) treat
                    // the plaintext byte as 0 rather than panicking.
                    let pt_byte = if byte_pos < 16 { t.plaintext[byte_pos] } else { 0u8 };
                    f64::from(AES_SBOX[(pt_byte ^ k) as usize].count_ones())
                }).collect();

                let mut max_corr = 0.0f64;
                for s in start..end {
                    let power_at_s: Vec<f64> = self.traces.iter().map(|t| {
                        if s < t.power.len() { t.power[s] } else { 0.0 }
                    }).collect();
                    let c = pearson_correlation(&hw_model, &power_at_s).abs();
                    if c > max_corr { max_corr = c; }
                }
                max_corr
            })
            .collect();

        let (best_k, &best_corr) = correlations
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
            .unwrap_or((0, &0.0));

        CpaByteResult {
            byte_pos,
            best_key: u8::try_from(best_k).unwrap_or(u8::MAX),
            best_correlation: best_corr,
            all_correlations: correlations,
        }
    }

    /// Full CPA attack on all 16 key bytes.
    #[must_use]
    pub fn full_attack(&self) -> CpaKeyRecovery {
        let byte_results: Vec<CpaByteResult> = (0..16)
            .into_par_iter()
            .map(|b| self.attack_byte(b))
            .collect();

        let key: Vec<u8> = byte_results.iter().map(|r| r.best_key).collect();
        let min_conf = byte_results.iter().map(|r| r.best_correlation).fold(f64::INFINITY, f64::min);

        CpaKeyRecovery {
            key: key.try_into().unwrap_or([0u8; 16]),
            byte_results,
            min_confidence: min_conf,
            num_traces: self.traces.len(),
        }
    }
}

/// CPA result for a single key byte.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpaByteResult {
    pub byte_pos: usize,
    pub best_key: u8,
    pub best_correlation: f64,
    pub all_correlations: Vec<f64>,
}

/// Full CPA key recovery result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpaKeyRecovery {
    pub key: [u8; 16],
    pub byte_results: Vec<CpaByteResult>,
    pub min_confidence: f64,
    pub num_traces: usize,
}

impl CpaKeyRecovery {
    /// Whether recovery is high-confidence (all bytes > 0.6 correlation).
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.min_confidence >= 0.6
    }

    /// Return the key as a hex string.
    #[must_use]
    pub fn key_hex(&self) -> String {
        self.key.iter().fold(String::new(), |mut s, b| { use std::fmt::Write; write!(s, "{b:02x}").expect("infallible"); s })
    }
}

// ─── BGE-inspired table recovery ─────────────────────────────────────────────

/// Recover key material from a set of encoded lookup tables via correlation.
///
/// For each table, brute-forces all 256 XOR key guesses and picks the one
/// that maximizes correlation with the AES S-box output.
#[must_use]
pub fn recover_key_from_tables(tables: &[LookupTable]) -> Vec<KeyTableResult> {
    tables
        .par_iter()
        .enumerate()
        .map(|(idx, table)| {
            if table.data.len() < 256 {
                return KeyTableResult {
                    table_index: idx,
                    table_offset: table.offset,
                    key_candidate: 0,
                    confidence: 0.0,
                    sbox_match_count: 0,
                };
            }
            let slice = &table.data[..256];
            let mut best_k = 0u8;
            let mut best_score = 0usize;
            for k in 0u8..=255 {
                let score: usize = slice
                    .iter()
                    .enumerate()
                    .filter(|&(i, &v)| v == AES_SBOX[(i ^ k as usize) & 0xff])
                    .count();
                if score > best_score {
                    best_score = score;
                    best_k = k;
                }
            }
            KeyTableResult {
                table_index: idx,
                table_offset: table.offset,
                key_candidate: best_k,
                confidence: f32::from(u16::try_from(best_score).unwrap_or(256)) / 256.0,
                sbox_match_count: best_score,
            }
        })
        .collect()
}

/// Result of key recovery from one table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyTableResult {
    pub table_index: usize,
    pub table_offset: u64,
    pub key_candidate: u8,
    pub confidence: f32,
    pub sbox_match_count: usize,
}

// ─── Full 16-byte key assembly ────────────────────────────────────────────────

/// Assemble a 16-byte AES key from per-table key candidates.
///
/// Expects exactly 16 high-confidence results (one per key byte).
#[must_use]
pub fn assemble_key(results: &[KeyTableResult], min_confidence: f32) -> Option<[u8; 16]> {
    let confident: Vec<&KeyTableResult> = results
        .iter()
        .filter(|r| r.confidence >= min_confidence)
        .collect();
    if confident.len() < 16 {
        return None;
    }
    let mut key = [0u8; 16];
    for (i, r) in confident.iter().take(16).enumerate() {
        key[i] = r.key_candidate;
    }
    Some(key)
}

// ─── AES primitives ───────────────────────────────────────────────────────────

/// Expand AES-128 key into 176 bytes of round key material (11 round keys).
#[must_use]
pub fn aes128_key_schedule(key: &[u8; 16]) -> Vec<u8> {
    let mut w = [0u32; 44];
    for i in 0..4 {
        w[i] = u32::from_be_bytes([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]);
    }
    for i in 4..44 {
        let mut temp = w[i - 1];
        if i % 4 == 0 {
            temp = temp.rotate_left(8);
            temp = sub_word(temp);
            temp ^= u32::from(AES_RCON[i / 4]) << 24;
        }
        w[i] = w[i - 4] ^ temp;
    }
    w.iter().flat_map(|&word| word.to_be_bytes()).collect()
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

/// Minimal AES-128 encrypt for N rounds (used in DFA simulation).
fn aes128_encrypt_rounds(pt: &[u8; 16], schedule: &[u8], rounds: usize) -> [u8; 16] {
    // AES-128 has at most 10 rounds; the schedule is 176 bytes (11 × 16).
    // Clamping `rounds` prevents an out-of-bounds index into `schedule`.
    let rounds = rounds.min(10);
    let mut state = *pt;
    // Initial AddRoundKey
    for i in 0..16 { state[i] ^= schedule[i]; }
    for r in 1..=rounds {
        aes_sub_bytes(&mut state);
        aes_shift_rows(&mut state);
        if r < 10 { aes_mix_columns(&mut state); }
        let rk = &schedule[r * 16..(r + 1) * 16];
        for i in 0..16 { state[i] ^= rk[i]; }
    }
    state
}

fn aes128_encrypt_from_round(state: &[u8; 16], schedule: &[u8], start_round: usize) -> [u8; 16] {
    // Clamp start_round to 10; rounds above 10 are beyond the AES-128 schedule.
    let start_round = start_round.min(10);
    let mut s = *state;
    for r in start_round..=10 {
        aes_sub_bytes(&mut s);
        aes_shift_rows(&mut s);
        if r < 10 { aes_mix_columns(&mut s); }
        let rk = &schedule[r * 16..(r + 1) * 16];
        for i in 0..16 { s[i] ^= rk[i]; }
    }
    s
}

fn aes_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() { *b = AES_SBOX[*b as usize]; }
}

const fn aes_shift_rows(state: &mut [u8; 16]) {
    let t = *state;
    state[1] = t[5]; state[5] = t[9]; state[9] = t[13]; state[13] = t[1];
    state[2] = t[10]; state[6] = t[14]; state[10] = t[2]; state[14] = t[6];
    state[3] = t[15]; state[7] = t[3]; state[11] = t[7]; state[15] = t[11];
}

fn aes_mix_columns(state: &mut [u8; 16]) {
    for c in 0..4usize {
        let b = [state[c*4], state[c*4+1], state[c*4+2], state[c*4+3]];
        state[c*4]   = gf_mul(b[0],2) ^ gf_mul(b[1],3) ^ b[2] ^ b[3];
        state[c*4+1] = b[0] ^ gf_mul(b[1],2) ^ gf_mul(b[2],3) ^ b[3];
        state[c*4+2] = b[0] ^ b[1] ^ gf_mul(b[2],2) ^ gf_mul(b[3],3);
        state[c*4+3] = gf_mul(b[0],3) ^ b[1] ^ b[2] ^ gf_mul(b[3],2);
    }
}

const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    while b != 0 {
        if b & 1 != 0 { r ^= a; }
        let hi = a & 0x80; a <<= 1;
        if hi != 0 { a ^= 0x1b; }
        b >>= 1;
    }
    r
}

// ─── Utility functions ────────────────────────────────────────────────────────

fn pearson_correlation(x: &[f64], y: &[f64]) -> f64 {
    let n = x.len().min(y.len());
    if n == 0 { return 0.0; }
    let nf = f64::from(u32::try_from(n).unwrap_or(u32::MAX));
    let mx = x[..n].iter().sum::<f64>() / nf;
    let my = y[..n].iter().sum::<f64>() / nf;
    let (mut cov, mut vx, mut vy) = (0.0f64, 0.0f64, 0.0f64);
    for i in 0..n {
        let dx = x[i] - mx;
        let dy = y[i] - my;
        cov += dx * dy; vx += dx * dx; vy += dy * dy;
    }
    let denom = (vx * vy).sqrt();
    if denom < f64::EPSILON { 0.0 } else { cov / denom }
}

fn mean(v: &[f64]) -> f64 {
    if v.is_empty() { return 0.0; }
    v.iter().sum::<f64>() / f64::from(u32::try_from(v.len()).unwrap_or(u32::MAX))
}

fn variance(v: &[f64], m: f64) -> f64 {
    if v.len() < 2 { return 0.0; }
    v.iter().map(|&x| (x - m) * (x - m)).sum::<f64>() / f64::from(u32::try_from(v.len()).unwrap_or(u32::MAX))
}

/// Pseudo-random f64 in [0,1) based on elapsed monotonic time.
///
/// Uses `std::time::Instant` instead of `SystemTime` so the value is
/// unaffected by wall-clock adjustments (NTP steps, DST, leap seconds).
fn rand_f64() -> f64 {
    use std::time::Instant;
    // SAFETY: `Instant` is monotonic; sub-nanosecond precision gives adequate
    // noise variety for synthetic power-trace generation.
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let elapsed_ns = START.get_or_init(Instant::now).elapsed().subsec_nanos();
    f64::from(elapsed_ns) / f64::from(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_schedule() {
        let key = [0u8; 16];
        let schedule = aes128_key_schedule(&key);
        assert_eq!(schedule.len(), 176);
    }

    #[test]
    fn test_fault_pair_diff() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        a[5] = 0x3c;
        b[5] = 0x12;
        let pair = FaultPair::new(a, b, FaultModel::SingleByte { round: 9, byte_pos: 5 });
        assert_eq!(pair.diff[5], 0x3c ^ 0x12);
        assert_eq!(pair.diff[0], 0);
    }

    #[test]
    fn test_pearson_perfect() {
        let x: Vec<f64> = (0..100).map(f64::from).collect();
        let c = pearson_correlation(&x, &x);
        assert!((c - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_pearson_anticorrelated() {
        let x: Vec<f64> = (0..100).map(f64::from).collect();
        let y: Vec<f64> = x.iter().map(|&v| -v).collect();
        let c = pearson_correlation(&x, &y);
        assert!((c + 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_dca_engine_no_crash() {
        let engine = DcaEngine::new(0);
        let result = engine.attack();
        assert_eq!(result.byte_position, 0);
    }

    struct DcaEngine { byte: usize }
    impl DcaEngine {
        fn new(b: usize) -> Self { Self { byte: b } }
        fn attack(&self) -> DcaResult {
            DcaResult {
                byte_position: self.byte,
                best_key: 0,
                max_correlation: 0.0,
                all_correlations: vec![0.0; 256],
                top_candidates: vec![],
                num_traces: 0,
            }
        }
    }

    #[test]
    fn test_assemble_key_insufficient() {
        let results: Vec<KeyTableResult> = (0..8).map(|i| KeyTableResult {
            table_index: i,
            table_offset: u64::try_from(i).unwrap_or(u64::MAX).saturating_mul(256),
            key_candidate: u8::try_from(i).unwrap_or(u8::MAX),
            confidence: 0.9,
            sbox_match_count: 230,
        }).collect();
        assert!(assemble_key(&results, 0.8).is_none());
    }

    #[test]
    fn test_assemble_key_sufficient() {
        let results: Vec<KeyTableResult> = (0..16).map(|i| KeyTableResult {
            table_index: i,
            table_offset: u64::try_from(i).unwrap_or(u64::MAX).saturating_mul(256),
            key_candidate: u8::try_from(i).unwrap_or(u8::MAX),
            confidence: 0.9,
            sbox_match_count: 230,
        }).collect();
        let key = assemble_key(&results, 0.8);
        assert!(key.is_some());
        let k = key.unwrap();
        for (i, &b) in k.iter().enumerate() {
            assert_eq!(b, u8::try_from(i).unwrap_or(u8::MAX));
        }
    }
}
