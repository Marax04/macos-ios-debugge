// dca_fault_model.rs — Differential Computation Analysis (DCA) and fault
// models for whitebox AES implementations.
//
// DCA is a side-channel attack on whitebox implementations that treats the
// intermediate computation traces (e.g. power traces, cache-miss traces) as if
// they were physical side-channel measurements.  This module provides:
//
//   * `ComputationTrace`   — a sequence of intermediate values captured during
//                            one whitebox AES evaluation.
//   * `DcaAnalyzer`        — correlates traces against Hamming-weight
//                            hypotheses to recover key bytes.
//   * `FaultModel`         — describes the fault injection strategy (random,
//                            bit-flip, stuck-at) used in DFA.
//   * `FaultCampaign`      — manages a structured series of fault experiments.
//   * `TraceCorrelation`   — Pearson correlation result between a hypothesis
//                            vector and a trace column.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ────────────────────────────────────────────────────────────────────────────
// AES constants (minimal, self-contained)
// ────────────────────────────────────────────────────────────────────────────

/// Standard AES S-box.
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

fn hamming_weight(x: u8) -> u8 {
    u8::try_from(x.count_ones()).unwrap_or(u8::MAX)
}

const fn sbox(x: u8) -> u8 {
    SBOX[x as usize]
}

// ────────────────────────────────────────────────────────────────────────────
// Computation trace
// ────────────────────────────────────────────────────────────────────────────

/// A single execution trace: one entry per captured intermediate value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputationTrace {
    /// The known plaintext that was encrypted to produce this trace.
    pub plaintext: [u8; 16],
    /// Sequence of intermediate 8-bit values captured during encryption.
    pub samples: Vec<u8>,
    /// Optional label (e.g. a tag identifying which encryption pass).
    pub label: Option<String>,
}

impl ComputationTrace {
    #[must_use]
    pub const fn new(plaintext: [u8; 16], samples: Vec<u8>) -> Self {
        Self { plaintext, samples, label: None }
    }

    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    #[must_use]
    pub const fn sample_count(&self) -> usize {
        self.samples.len()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Hypothesis matrix
// ────────────────────────────────────────────────────────────────────────────

/// For a given key-byte position, compute the Hamming-weight hypothesis for
/// every possible key byte (0..=255) and every trace.
///
/// Returns a matrix of shape `[256][trace_count]`.
fn build_hw_hypothesis_matrix(
    traces: &[ComputationTrace],
    pt_byte: usize,
    round: u8,
) -> Vec<Vec<f64>> {
    let n = traces.len();
    let mut matrix: Vec<Vec<f64>> = vec![vec![0.0; n]; 256];

    for k in 0u8..=255 {
        for (t_idx, trace) in traces.iter().enumerate() {
            let pt = trace.plaintext[pt_byte];
            let intermediate = if round == 0 {
                // AddRoundKey then SubBytes at round 1.
                sbox(pt ^ k)
            } else {
                // Simplified model for later rounds.
                sbox(pt.wrapping_add(k))
            };
            matrix[usize::from(k)][t_idx] = f64::from(hamming_weight(intermediate));
        }
    }

    matrix
}

// ────────────────────────────────────────────────────────────────────────────
// Pearson correlation
// ────────────────────────────────────────────────────────────────────────────

/// Result of a Pearson correlation between a hypothesis vector and one column
/// of the trace matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCorrelation {
    /// The key-byte hypothesis (0..=255).
    pub key_hypothesis: u8,
    /// The sample index (column) in the trace matrix.
    pub sample_index: usize,
    /// Pearson correlation coefficient ∈ [-1, 1].
    pub correlation: f64,
}

fn pearson(xs: &[f64], ys: &[f64]) -> f64 {
    let n = f64::from(u32::try_from(xs.len()).unwrap_or(u32::MAX));
    if n == 0.0 {
        return 0.0;
    }
    let mx = xs.iter().sum::<f64>() / n;
    let my = ys.iter().sum::<f64>() / n;
    let num: f64 = xs.iter().zip(ys.iter()).map(|(x, y)| (x - mx) * (y - my)).sum();
    let dx: f64 = xs.iter().map(|x| (x - mx).powi(2)).sum::<f64>().sqrt();
    let dy: f64 = ys.iter().map(|y| (y - my).powi(2)).sum::<f64>().sqrt();
    if dx < 1e-12 || dy < 1e-12 {
        0.0
    } else {
        num / (dx * dy)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// DCA analyzer
// ────────────────────────────────────────────────────────────────────────────

/// Configuration for the DCA analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcaConfig {
    /// Number of traces to use for the analysis.
    pub trace_count: usize,
    /// Minimum absolute correlation to consider a hypothesis "significant".
    pub significance_threshold: f64,
    /// Which AES round to target (0 = first, 9 = last for AES-128).
    pub target_round: u8,
    /// Whether to use Hamming-weight (true) or Hamming-distance model (false).
    pub use_hamming_weight: bool,
}

impl Default for DcaConfig {
    fn default() -> Self {
        Self {
            trace_count: 1000,
            significance_threshold: 0.5,
            target_round: 0,
            use_hamming_weight: true,
        }
    }
}

/// Per-byte result of the DCA attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcaByteResult {
    /// Byte position in the key (0..15).
    pub byte_position: usize,
    /// Best key-byte candidate.
    pub best_key: u8,
    /// Correlation of the best candidate.
    pub best_correlation: f64,
    /// Sample index where the peak correlation was found.
    pub peak_sample: usize,
    /// Second-best correlation (useful to estimate distinguishability).
    pub second_best_correlation: f64,
    /// Whether the result crosses the significance threshold.
    pub significant: bool,
}

impl DcaByteResult {
    /// Ratio of best to second-best correlation — higher means more confident.
    #[must_use]
    pub fn distinguishing_ratio(&self) -> f64 {
        if self.second_best_correlation.abs() < 1e-12 {
            f64::INFINITY
        } else {
            self.best_correlation.abs() / self.second_best_correlation.abs()
        }
    }
}

/// Summary of a full DCA key-recovery run.
#[derive(Debug, Serialize, Deserialize)]
pub struct DcaResult {
    pub config: DcaConfig,
    pub per_byte: Vec<DcaByteResult>,
    pub traces_used: usize,
}

impl DcaResult {
    /// Extract the recovered key (None for each byte that is not significant).
    #[must_use]
    pub fn recovered_key(&self) -> [Option<u8>; 16] {
        let mut key = [None; 16];
        for r in &self.per_byte {
            if r.significant {
                key[r.byte_position] = Some(r.best_key);
            }
        }
        key
    }

    /// How many key bytes were recovered with significance.
    #[must_use]
    pub fn recovered_count(&self) -> usize {
        self.per_byte.iter().filter(|r| r.significant).count()
    }

    /// True when all 16 key bytes are recovered.
    #[must_use]
    pub fn full_key_recovered(&self) -> bool {
        self.recovered_count() == 16
    }
}

/// The main DCA engine.
pub struct DcaAnalyzer {
    config: DcaConfig,
}

impl DcaAnalyzer {
    #[must_use]
    pub const fn new(config: DcaConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DcaConfig::default())
    }

    /// Run DCA on the provided traces and return per-byte results.
    #[must_use]
    pub fn analyze(&self, traces: &[ComputationTrace]) -> DcaResult {
        let limit = traces.len().min(self.config.trace_count);
        let traces = &traces[..limit];

        let mut per_byte: Vec<DcaByteResult> = Vec::with_capacity(16);

        for byte_pos in 0..16 {
            let result = self.analyze_byte(traces, byte_pos);
            per_byte.push(result);
        }

        DcaResult {
            config: self.config.clone(),
            per_byte,
            traces_used: limit,
        }
    }

    fn analyze_byte(&self, traces: &[ComputationTrace], byte_pos: usize) -> DcaByteResult {
        let hyp_matrix =
            build_hw_hypothesis_matrix(traces, byte_pos, self.config.target_round);

        let sample_len = traces.iter().map(ComputationTrace::sample_count).min().unwrap_or(0);
        if sample_len == 0 {
            return DcaByteResult {
                byte_position: byte_pos,
                best_key: 0,
                best_correlation: 0.0,
                peak_sample: 0,
                second_best_correlation: 0.0,
                significant: false,
            };
        }

        let mut best_key = 0u8;
        let mut best_corr = f64::NEG_INFINITY;
        let mut peak_sample = 0;
        let mut second_best = f64::NEG_INFINITY;

        for k in 0u8..=255 {
            let hyp: Vec<f64> = hyp_matrix[k as usize].clone();
            // Correlate against each sample column.
            for s in 0..sample_len {
                let trace_col: Vec<f64> = traces.iter().map(|t| f64::from(t.samples[s])).collect();
                let c = pearson(&hyp, &trace_col).abs();
                if c > best_corr {
                    second_best = best_corr;
                    best_corr = c;
                    best_key = k;
                    peak_sample = s;
                } else if c > second_best {
                    second_best = c;
                }
            }
        }

        DcaByteResult {
            byte_position: byte_pos,
            best_key,
            best_correlation: best_corr,
            peak_sample,
            second_best_correlation: second_best,
            significant: best_corr >= self.config.significance_threshold,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Fault model
// ────────────────────────────────────────────────────────────────────────────

/// The type of fault injection applied in a DFA campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultKind {
    /// Randomise a byte to a uniformly random value.
    RandomByte,
    /// Flip exactly one random bit in a byte.
    BitFlip,
    /// Force a byte to zero (stuck-at-0).
    StuckAtZero,
    /// Force a byte to 0xFF (stuck-at-1).
    StuckAtOne,
    /// Increment a byte by 1 (mod 256).
    Increment,
}

impl FaultKind {
    /// Apply the fault to `original` using the provided random seed byte.
    #[must_use]
    pub const fn apply(self, original: u8, seed: u8) -> u8 {
        match self {
            Self::RandomByte => seed,
            Self::BitFlip => original ^ (1u8 << (seed & 7)),
            Self::StuckAtZero => 0x00,
            Self::StuckAtOne => 0xFF,
            Self::Increment => original.wrapping_add(1),
        }
    }
}

/// A model describing how and where faults should be injected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultModel {
    pub kind: FaultKind,
    /// AES round in which the fault is injected (0-indexed, 0..9 for AES-128).
    pub target_round: u8,
    /// Byte position within the state array (0..15).
    pub target_byte: u8,
    /// Whether faults should be injected before or after `SubBytes`.
    pub before_subbytes: bool,
}

impl FaultModel {
    #[must_use]
    pub const fn random_byte_round9(target_byte: u8) -> Self {
        Self {
            kind: FaultKind::RandomByte,
            target_round: 9,
            target_byte,
            before_subbytes: true,
        }
    }

    #[must_use]
    pub const fn bit_flip_round8(target_byte: u8) -> Self {
        Self {
            kind: FaultKind::BitFlip,
            target_round: 8,
            target_byte,
            before_subbytes: false,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Fault campaign
// ────────────────────────────────────────────────────────────────────────────

/// A single fault experiment: one faulty ciphertext and its reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultExperiment {
    pub id: u32,
    pub plaintext: [u8; 16],
    pub reference_ciphertext: [u8; 16],
    pub faulty_ciphertext: [u8; 16],
    pub model: FaultModel,
    /// Bit difference between reference and faulty ciphertext (HW of XOR).
    pub fault_hamming: u8,
}

impl FaultExperiment {
    #[must_use]
    pub fn new(
        id: u32,
        plaintext: [u8; 16],
        reference_ciphertext: [u8; 16],
        faulty_ciphertext: [u8; 16],
        model: FaultModel,
    ) -> Self {
        let hw: u8 = reference_ciphertext
            .iter()
            .zip(faulty_ciphertext.iter())
            .map(|(a, b)| hamming_weight(a ^ b))
            .sum();
        Self {
            id,
            plaintext,
            reference_ciphertext,
            faulty_ciphertext,
            model,
            fault_hamming: hw,
        }
    }

    /// True when the fault produced a visible difference.
    #[must_use]
    pub const fn is_effective(&self) -> bool {
        self.fault_hamming > 0
    }

    /// XOR difference in the ciphertext.
    #[must_use]
    pub fn delta(&self) -> [u8; 16] {
        let mut d = [0u8; 16];
        for (i, entry) in d.iter_mut().enumerate() {
            *entry = self.reference_ciphertext[i] ^ self.faulty_ciphertext[i];
        }
        d
    }
}

/// Manages a structured DFA fault campaign.
#[derive(Debug, Serialize, Deserialize)]
pub struct FaultCampaign {
    pub model: FaultModel,
    pub experiments: Vec<FaultExperiment>,
    pub target_key_bytes: Vec<u8>,
}

impl FaultCampaign {
    #[must_use]
    pub const fn new(model: FaultModel, target_key_bytes: Vec<u8>) -> Self {
        Self {
            model,
            experiments: Vec::new(),
            target_key_bytes,
        }
    }

    pub fn add_experiment(&mut self, exp: FaultExperiment) {
        self.experiments.push(exp);
    }

    #[must_use]
    pub fn effective_experiments(&self) -> Vec<&FaultExperiment> {
        self.experiments.iter().filter(|e| e.is_effective()).collect()
    }

    #[must_use]
    pub fn effective_count(&self) -> usize {
        self.experiments.iter().filter(|e| e.is_effective()).count()
    }

    /// Attempt to infer key bytes from the effective fault pairs.
    /// Uses a simplified differential table approach.
    #[must_use]
    pub fn infer_key_candidates(&self) -> HashMap<u8, Vec<u8>> {
        let mut candidates: HashMap<u8, Vec<u8>> = HashMap::new();

        for &pos in &self.target_key_bytes {
            let pos_usize = pos as usize;
            let mut possible: Vec<u8> = (0u8..=255).collect();

            for exp in self.effective_experiments() {
                let ct_ref = exp.reference_ciphertext[pos_usize];
                let ct_flt = exp.faulty_ciphertext[pos_usize];

                // Candidate k satisfies: sbox(ct_ref ^ k) ^ sbox(ct_flt ^ k) == expected_diff
                // For simplicity, use XOR diff as a filter.
                let diff = ct_ref ^ ct_flt;
                possible.retain(|&k| {
                    let d = SBOX[(ct_ref ^ k) as usize] ^ SBOX[(ct_flt ^ k) as usize];
                    d == diff
                });
            }

            candidates.insert(pos, possible);
        }

        candidates
    }

    /// Summary statistics.
    #[must_use]
    pub fn summary(&self) -> CampaignSummary {
        let total = self.experiments.len();
        let effective = self.effective_count();
        CampaignSummary {
            total_experiments: total,
            effective_experiments: effective,
            ineffective_experiments: total - effective,
            efficiency_pct: if total > 0 {
                (f64::from(u32::try_from(effective).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX))) * 100.0
            } else {
                0.0
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignSummary {
    pub total_experiments: usize,
    pub effective_experiments: usize,
    pub ineffective_experiments: usize,
    pub efficiency_pct: f64,
}

// ────────────────────────────────────────────────────────────────────────────
// Trace simulator (synthetic traces for testing)
// ────────────────────────────────────────────────────────────────────────────

/// Generates synthetic computation traces for a known AES-128 key.
pub struct TraceSimulator {
    pub key: [u8; 16],
    pub noise_level: u8,
    pub trace_length: usize,
}

impl TraceSimulator {
    #[must_use]
    pub const fn new(key: [u8; 16]) -> Self {
        Self { key, noise_level: 5, trace_length: 64 }
    }

    /// Generate `n` traces for the given plaintext sequence.
    #[must_use]
    pub fn generate(&self, plaintexts: &[[u8; 16]], rng_seed: u64) -> Vec<ComputationTrace> {
        let mut traces = Vec::with_capacity(plaintexts.len());
        let mut state = rng_seed;

        for pt in plaintexts {
            let mut samples = Vec::with_capacity(self.trace_length);
            for i in 0..self.trace_length {
                let byte_idx = i % 16;
                // First-round AddRoundKey + SubBytes intermediate.
                let intermediate = sbox(pt[byte_idx] ^ self.key[byte_idx]);
                let hw = hamming_weight(intermediate);
                // Additive noise via LCG.
                state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                let noise = u8::try_from((state >> 33) & 0xFF).unwrap_or(u8::MAX) % (self.noise_level + 1);
                samples.push(hw.wrapping_add(noise));
            }
            traces.push(ComputationTrace::new(*pt, samples));
        }

        traces
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_plaintext() -> [u8; 16] {
        [0u8; 16]
    }

    #[test]
    fn fault_kind_random_changes_byte() {
        let original = 0xAB_u8;
        let seed = 0x12_u8;
        let faulted = FaultKind::RandomByte.apply(original, seed);
        assert_eq!(faulted, seed);
    }

    #[test]
    fn fault_kind_bit_flip() {
        let original = 0b0000_1000_u8;
        let faulted = FaultKind::BitFlip.apply(original, 0); // flip bit 0
        assert_eq!(faulted, 0b0000_1001);
    }

    #[test]
    fn stuck_at_zero() {
        assert_eq!(FaultKind::StuckAtZero.apply(0xAA, 0xFF), 0x00);
    }

    #[test]
    fn stuck_at_one() {
        assert_eq!(FaultKind::StuckAtOne.apply(0x00, 0x00), 0xFF);
    }

    #[test]
    fn fault_experiment_delta() {
        let pt = zero_plaintext();
        let ref_ct = [0u8; 16];
        let mut flt_ct = [0u8; 16];
        flt_ct[0] = 0xFF;
        let model = FaultModel::random_byte_round9(0);
        let exp = FaultExperiment::new(1, pt, ref_ct, flt_ct, model);
        assert!(exp.is_effective());
        assert_eq!(exp.delta()[0], 0xFF);
    }

    #[test]
    fn trace_simulator_correct_length() {
        let key = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                   0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c];
        let sim = TraceSimulator::new(key);
        let pts: Vec<[u8; 16]> = (0..10).map(|i| [i; 16]).collect();
        let traces = sim.generate(&pts, 42);
        assert_eq!(traces.len(), 10);
        for t in &traces {
            assert_eq!(t.sample_count(), 64);
        }
    }

    #[test]
    fn dca_analyzer_runs_without_panic() {
        let key = [0u8; 16];
        let sim = TraceSimulator { key, noise_level: 0, trace_length: 32 };
        let pts: Vec<[u8; 16]> = (0..50u8).map(|i| [i; 16]).collect();
        let traces = sim.generate(&pts, 0);
        let config = DcaConfig {
            trace_count: 50,
            significance_threshold: 0.01,
            target_round: 0,
            use_hamming_weight: true,
        };
        let analyzer = DcaAnalyzer::new(config);
        let result = analyzer.analyze(&traces);
        assert_eq!(result.per_byte.len(), 16);
        assert_eq!(result.traces_used, 50);
    }

    #[test]
    fn campaign_summary_efficiency() {
        let model = FaultModel::random_byte_round9(0);
        let mut campaign = FaultCampaign::new(model.clone(), vec![0, 1]);
        let pt = zero_plaintext();
        let ref_ct = [0u8; 16];
        // Effective experiment.
        let mut flt1 = [0u8; 16]; flt1[0] = 0x01;
        campaign.add_experiment(FaultExperiment::new(1, pt, ref_ct, flt1, model.clone()));
        // Ineffective (same as reference).
        campaign.add_experiment(FaultExperiment::new(2, pt, ref_ct, ref_ct, model));

        let s = campaign.summary();
        assert_eq!(s.total_experiments, 2);
        assert_eq!(s.effective_experiments, 1);
        assert!((s.efficiency_pct - 50.0).abs() < 1e-9);
    }

    #[test]
    fn pearson_perfect_correlation() {
        let xs = vec![1.0, 2.0, 3.0, 4.0];
        let ys = vec![2.0, 4.0, 6.0, 8.0];
        let c = pearson(&xs, &ys);
        assert!((c - 1.0).abs() < 1e-10);
    }

    #[test]
    fn pearson_no_correlation() {
        let xs = vec![1.0, 1.0, 1.0, 1.0];
        let ys = vec![1.0, 2.0, 3.0, 4.0];
        let c = pearson(&xs, &ys);
        assert!(c.abs() < 1e-10);
    }
}
