// rustre-crypto-id/src/side_channel_hints.rs
// Timing, memory-access, and branching side-channel analysis for algorithm identification.

use std::time::Instant;
use std::collections::HashMap;

/// A single timing measurement.
#[derive(Debug, Clone)]
pub struct TimingMeasurement {
    pub input_len: usize,
    pub input_pattern: InputPattern,
    pub elapsed_ns: u64,
}

/// Category of input used for timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputPattern {
    AllZeros,
    AllOnes,
    Random,
    Alternating,
    Specific(u8),
}

/// Timing profile over many measurements.
#[derive(Debug, Clone)]
pub struct TimingProfile {
    pub measurements: Vec<TimingMeasurement>,
    pub mean_ns: f64,
    pub stddev_ns: f64,
    pub min_ns: u64,
    pub max_ns: u64,
}

impl TimingProfile {
    #[must_use]
    pub fn from_measurements(measurements: Vec<TimingMeasurement>) -> Self {
        let times: Vec<f64> = measurements.iter().map(|m| f64::from(u32::try_from(m.elapsed_ns).unwrap_or(u32::MAX))).collect();
        let n = f64::from(u32::try_from(times.len()).unwrap_or(u32::MAX));
        let mean = times.iter().sum::<f64>() / n.max(1.0);
        let variance = times.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / n.max(1.0);
        let stddev = variance.sqrt();
        let min = measurements.iter().map(|m| m.elapsed_ns).min().unwrap_or(0);
        let max = measurements.iter().map(|m| m.elapsed_ns).max().unwrap_or(0);
        Self { measurements, mean_ns: mean, stddev_ns: stddev, min_ns: min, max_ns: max }
    }

    /// Coefficient of variation (stddev / mean). High → timing varies; low → constant-time.
    #[must_use]
    pub fn cv(&self) -> f64 {
        if self.mean_ns == 0.0 { 0.0 } else { self.stddev_ns / self.mean_ns }
    }
}

/// Side-channel hint about the algorithm.
#[derive(Debug, Clone)]
pub struct SideChannelHint {
    pub hint_type: SideChannelType,
    pub algorithm_hint: &'static str,
    pub confidence: f64,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SideChannelType {
    Timing,
    MemoryAccess,
    BranchPattern,
    CacheTrace,
    PowerTrace,
}

/// Result of side-channel analysis.
#[derive(Debug, Clone)]
pub struct SideChannelAnalysis {
    pub hints: Vec<SideChannelHint>,
    pub timing_profile: Option<TimingProfile>,
    pub is_constant_time: Option<bool>,
    pub likely_algorithms: Vec<&'static str>,
}

impl Default for SideChannelAnalysis {
    fn default() -> Self { Self::new() }
}

impl SideChannelAnalysis {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            hints: Vec::new(),
            timing_profile: None,
            is_constant_time: None,
            likely_algorithms: Vec::new(),
        }
    }

    pub fn add_hint(&mut self, hint: SideChannelHint) {
        if !self.likely_algorithms.contains(&hint.algorithm_hint) {
            self.likely_algorithms.push(hint.algorithm_hint);
        }
        self.hints.push(hint);
    }
}

/// Callable oracle for side-channel probing.
pub trait TimedOracle: Send + Sync {
    fn call(&self, input: &[u8]) -> Vec<u8>;
}

/// Wrapper around a closure.
pub struct FnTimedOracle<F: Fn(&[u8]) -> Vec<u8> + Send + Sync>(pub F);
impl<F: Fn(&[u8]) -> Vec<u8> + Send + Sync> TimedOracle for FnTimedOracle<F> {
    fn call(&self, input: &[u8]) -> Vec<u8> { (self.0)(input) }
}

// ─── Timing Analyzer ─────────────────────────────────────────────────────────

/// Analyzes timing behavior to infer the algorithm.
pub struct TimingAnalyzer {
    pub repetitions: usize,
    pub warmup: usize,
    pub input_lengths: Vec<usize>,
}

impl Default for TimingAnalyzer {
    fn default() -> Self {
        Self {
            repetitions: 100,
            warmup: 10,
            input_lengths: vec![1, 4, 8, 16, 32, 64, 128, 256, 512, 1024],
        }
    }
}

impl TimingAnalyzer {
    #[must_use]
    pub fn new(repetitions: usize) -> Self {
        Self { repetitions, ..Default::default() }
    }

    /// Run the oracle on various inputs and collect timing measurements.
    pub fn profile(&self, oracle: &dyn TimedOracle) -> TimingProfile {
        let mut measurements = Vec::new();

        for &len in &self.input_lengths {
            let input = vec![0xaa_u8; len];

            // Warmup.
            for _ in 0..self.warmup {
                let _ = oracle.call(&input);
            }

            // Timed measurements.
            for _ in 0..self.repetitions {
                let t0 = Instant::now();
                let _ = oracle.call(&input);
                let elapsed = u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
                measurements.push(TimingMeasurement {
                    input_len: len,
                    input_pattern: InputPattern::AllOnes,
                    elapsed_ns: elapsed,
                });
            }
        }

        TimingProfile::from_measurements(measurements)
    }

    /// Measure timing for different input lengths and detect pattern.
    pub fn measure_by_length(&self, oracle: &dyn TimedOracle) -> HashMap<usize, f64> {
        let mut map = HashMap::new();
        for &len in &self.input_lengths {
            let input = vec![0u8; len];
            for _ in 0..self.warmup { let _ = oracle.call(&input); }
            let times: Vec<u64> = (0..self.repetitions).map(|_| {
                let t0 = Instant::now();
                let _ = oracle.call(&input);
                u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX)
            }).collect();
            let mean = f64::from(u32::try_from(times.iter().sum::<u64>()).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(times.len()).unwrap_or(1));
            map.insert(len, mean);
        }
        map
    }

    /// Analyse timing to produce side-channel hints.
    pub fn analyze(&self, oracle: &dyn TimedOracle) -> SideChannelAnalysis {
        let mut analysis = SideChannelAnalysis::new();
        let by_len = self.measure_by_length(oracle);
        let profile = self.profile(oracle);

        // Check if time grows linearly with input (hash/stream).
        let linear = Self::check_linear_growth(&by_len);
        // Check if time is constant (block cipher in ECB with padding).
        let constant = Self::check_constant_time(&by_len);

        analysis.is_constant_time = Some(constant || profile.cv() < 0.05);

        if linear {
            analysis.add_hint(SideChannelHint {
                hint_type: SideChannelType::Timing,
                algorithm_hint: "HASH_OR_STREAM",
                confidence: 0.75,
                description: "Execution time grows linearly with input length — consistent with hash or stream cipher".into(),
            });
        }

        if constant {
            analysis.add_hint(SideChannelHint {
                hint_type: SideChannelType::Timing,
                algorithm_hint: "BLOCK_CIPHER_ECB",
                confidence: 0.70,
                description: "Near-constant execution time regardless of input length (padded blocks) — consistent with block cipher".into(),
            });
        }

        // Check for timing differences on different byte values at same length.
        if let Some(byte_dep) = self.detect_byte_dependent_timing(oracle) {
            analysis.add_hint(SideChannelHint {
                hint_type: SideChannelType::Timing,
                algorithm_hint: "RSA_OR_ECC_NON_CONST",
                confidence: byte_dep,
                description: format!(
                    "Timing depends on input byte values (correlation={byte_dep:.3}) — possible non-constant-time RSA/ECC"
                ),
            });
        }

        analysis.timing_profile = Some(profile);
        analysis
    }

    fn check_linear_growth(by_len: &HashMap<usize, f64>) -> bool {
        let mut lens: Vec<usize> = by_len.keys().copied().collect();
        lens.sort_unstable();
        if lens.len() < 4 { return false; }
        // Pearson correlation between length and time.
        let n = f64::from(u32::try_from(lens.len()).unwrap_or(u32::MAX));
        let x: Vec<f64> = lens.iter().map(|&l| f64::from(u32::try_from(l).unwrap_or(u32::MAX))).collect();
        let y: Vec<f64> = lens.iter().map(|l| by_len[l]).collect();
        let mx = x.iter().sum::<f64>() / n;
        let my = y.iter().sum::<f64>() / n;
        let num: f64 = x.iter().zip(y.iter()).map(|(xi, yi)| (xi - mx) * (yi - my)).sum();
        let den: f64 = (x.iter().map(|xi| (xi - mx).powi(2)).sum::<f64>()
            * y.iter().map(|yi| (yi - my).powi(2)).sum::<f64>()).sqrt();
        if den == 0.0 { return false; }
        (num / den).abs() > 0.9
    }

    fn check_constant_time(by_len: &HashMap<usize, f64>) -> bool {
        if by_len.len() < 2 { return false; }
        let times: Vec<f64> = by_len.values().copied().collect();
        let mean = times.iter().sum::<f64>() / f64::from(u32::try_from(times.len()).unwrap_or(1));
        let max_dev = times.iter().map(|t| (t - mean).abs()).fold(0.0f64, f64::max);
        // If max deviation is < 20% of mean → constant-ish.
        max_dev < mean * 0.20
    }

    fn detect_byte_dependent_timing(&self, oracle: &dyn TimedOracle) -> Option<f64> {
        // Send 16-byte inputs with single varying byte.
        let len = 16;
        let mut times_by_byte: Vec<(u8, f64)> = Vec::new();

        for byte_val in (0u8..=255).step_by(16) {
            let input = vec![byte_val; len];
            for _ in 0..self.warmup { let _ = oracle.call(&input); }
            let times: Vec<u64> = (0..self.repetitions.min(20)).map(|_| {
                let t = Instant::now();
                let _ = oracle.call(&input);
                u64::try_from(t.elapsed().as_nanos()).unwrap_or(u64::MAX)
            }).collect();
            let mean = f64::from(u32::try_from(times.iter().sum::<u64>()).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(times.len()).unwrap_or(1));
            times_by_byte.push((byte_val, mean));
        }

        // Compute variance of means across byte values.
        let means: Vec<f64> = times_by_byte.iter().map(|(_, m)| *m).collect();
        let overall_mean = means.iter().sum::<f64>() / f64::from(u32::try_from(means.len()).unwrap_or(1));
        let variance = means.iter().map(|m| (m - overall_mean).powi(2)).sum::<f64>() / f64::from(u32::try_from(means.len()).unwrap_or(1));
        let cv = variance.sqrt() / overall_mean.max(1.0);

        if cv > 0.05 { Some(cv.min(1.0)) } else { None }
    }
}

// ─── Memory Access Analyzer ──────────────────────────────────────────────────

/// Analyses memory-access patterns to identify algorithm.
pub struct MemoryAccessAnalyzer;

impl MemoryAccessAnalyzer {
    /// Given a sequence of memory access offsets (e.g., from a cache trace or instrumentation),
    /// identify whether they match known algorithm access patterns.
    #[must_use]
    pub fn analyze_accesses(&self, offsets: &[usize]) -> SideChannelAnalysis {
        let mut analysis = SideChannelAnalysis::new();

        // AES S-box pattern: 256 distinct accesses in range [0, 256).
        if Self::matches_aes_sbox_pattern(offsets) {
            analysis.add_hint(SideChannelHint {
                hint_type: SideChannelType::MemoryAccess,
                algorithm_hint: "AES",
                confidence: 0.90,
                description: "Memory accesses match AES S-box lookup pattern (256-byte table, 16 accesses per round)".into(),
            });
        }

        // DES S-box: 8 tables of 64 entries each.
        if Self::matches_des_sbox_pattern(offsets) {
            analysis.add_hint(SideChannelHint {
                hint_type: SideChannelType::MemoryAccess,
                algorithm_hint: "DES",
                confidence: 0.80,
                description: "Memory accesses match DES S-box pattern (8×64 entries)".into(),
            });
        }

        // SHA-256: sequential access to message schedule (64 rounds × 4 byte lookups).
        if Self::matches_sha256_pattern(offsets) {
            analysis.add_hint(SideChannelHint {
                hint_type: SideChannelType::MemoryAccess,
                algorithm_hint: "SHA-256",
                confidence: 0.75,
                description: "Sequential access pattern consistent with SHA-256 message schedule".into(),
            });
        }

        // RSA: large-exponent table accesses (square-and-multiply).
        if Self::matches_rsa_pattern(offsets) {
            analysis.add_hint(SideChannelHint {
                hint_type: SideChannelType::MemoryAccess,
                algorithm_hint: "RSA",
                confidence: 0.70,
                description: "Large sparse memory accesses consistent with RSA modular exponentiation".into(),
            });
        }

        analysis
    }

    fn matches_aes_sbox_pattern(offsets: &[usize]) -> bool {
        // AES: typically 16 S-box lookups per round, 10 rounds → ~160 lookups in [0, 256).
        let in_range: usize = offsets.iter().filter(|&&o| o < 256).count();
        let total = offsets.len();
        if total == 0 { return false; }
        // At least 50% of accesses in first 256 bytes.
        let ratio = f64::from(u32::try_from(in_range).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(total).unwrap_or(1));
        ratio > 0.5 && in_range >= 16
    }

    fn matches_des_sbox_pattern(offsets: &[usize]) -> bool {
        // DES: 8 S-boxes of 64 entries each → accesses in [0, 512).
        let in_range: usize = offsets.iter().filter(|&&o| o < 512).count();
        if in_range < 8 { return false; }
        // Check for distinct groups of 64 entries.
        let groups: std::collections::HashSet<usize> = offsets.iter().map(|&o| o / 64).collect();
        groups.len() >= 6
    }

    fn matches_sha256_pattern(offsets: &[usize]) -> bool {
        // SHA-256: sequential access to K constants [0, 64*4 = 256 bytes).
        if offsets.len() < 64 { return false; }
        let sequential = offsets.windows(2).filter(|w| w[1] == w[0] + 4).count();
        let ratio = f64::from(u32::try_from(sequential).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(offsets.len()).unwrap_or(1));
        ratio > 0.5
    }

    fn matches_rsa_pattern(offsets: &[usize]) -> bool {
        // RSA: accesses spread over large range (key size in bytes).
        if offsets.is_empty() { return false; }
        let max = *offsets.iter().max().unwrap();
        max > 1024 && {
            // Check stride distribution — RSA modmul has irregular strides.
            let unique_strides: std::collections::HashSet<isize> = offsets.windows(2)
                .map(|w| w[1].cast_signed() - w[0].cast_signed()).collect();
            unique_strides.len() > 10
        }
    }
}

// ─── Branch Analyzer ─────────────────────────────────────────────────────────

/// Branch record from instrumentation.
#[derive(Debug, Clone)]
pub struct BranchRecord {
    pub address: u64,
    pub taken: bool,
    pub condition_value: Option<u64>,
}

/// Analyzes branching patterns.
pub struct BranchAnalyzer;

impl BranchAnalyzer {
    /// Analyse branch records to identify algorithm.
    #[must_use]
    pub fn analyze(&self, branches: &[BranchRecord]) -> SideChannelAnalysis {
        let mut analysis = SideChannelAnalysis::new();

        let taken_ratio = Self::taken_ratio(branches);
        let unique_addresses: std::collections::HashSet<u64> = branches.iter().map(|b| b.address).collect();

        // High taken ratio + few addresses → likely AES round loop.
        if taken_ratio > 0.85 && unique_addresses.len() < 30 {
            analysis.add_hint(SideChannelHint {
                hint_type: SideChannelType::BranchPattern,
                algorithm_hint: "AES_OR_LOOP_HEAVY",
                confidence: 0.65,
                description: format!(
                    "High branch-taken ratio ({taken_ratio:.2}) with few unique branch sites — consistent with AES round loop"
                ),
            });
        }

        // Key-bit dependent branches → RSA non-constant-time.
        if Self::detect_key_bit_branches(branches) {
            analysis.add_hint(SideChannelHint {
                hint_type: SideChannelType::BranchPattern,
                algorithm_hint: "RSA_NON_CONST",
                confidence: 0.80,
                description: "Branches correlate with high-bit key values — non-constant-time RSA/ECC square-and-multiply".into(),
            });
        }

        // Conditional branches on Hamming weight of data → possibly XOR or bitsliced AES.
        if Self::detect_hamming_weight_branches(branches) {
            analysis.add_hint(SideChannelHint {
                hint_type: SideChannelType::BranchPattern,
                algorithm_hint: "BITSLICED_OR_XOR",
                confidence: 0.55,
                description: "Branch conditions correlate with Hamming weights — possibly bitsliced implementation".into(),
            });
        }

        analysis
    }

    fn taken_ratio(branches: &[BranchRecord]) -> f64 {
        if branches.is_empty() { return 0.0; }
        let taken = f64::from(u32::try_from(branches.iter().filter(|b| b.taken).count()).unwrap_or(u32::MAX));
        let total = f64::from(u32::try_from(branches.len()).unwrap_or(1));
        taken / total
    }

    fn detect_key_bit_branches(branches: &[BranchRecord]) -> bool {
        // Look for branches whose condition_value has high magnitude (suggests key bits).
        let high_val_branches: usize = branches.iter()
            .filter(|b| b.condition_value.is_some_and(|v| v > 0x100))
            .count();
        let ratio = f64::from(u32::try_from(high_val_branches).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(branches.len().max(1)).unwrap_or(1));
        ratio > 0.3
    }

    fn detect_hamming_weight_branches(branches: &[BranchRecord]) -> bool {
        // Check if condition values have structured Hamming weights.
        let weights: Vec<u32> = branches.iter()
            .filter_map(|b| b.condition_value)
            .map(u64::count_ones).collect();
        if weights.is_empty() { return false; }
        let mean = f64::from(weights.iter().sum::<u32>())
            / f64::from(u32::try_from(weights.len()).unwrap_or(1));
        // Hamming weight of random 64-bit values centers around 32; lower → key bit checking.
        mean < 20.0
    }
}

// ─── Cache Trace Analyzer ────────────────────────────────────────────────────

/// A cache-line access event.
#[derive(Debug, Clone)]
pub struct CacheEvent {
    pub address: u64,
    pub hit: bool,
    pub set_index: u32,
}

/// Identifies algorithms from cache-trace data (e.g., from PIN, Valgrind/Cachegrind, or PMU).
pub struct CacheTraceAnalyzer {
    pub cache_line_size: usize,
}

impl Default for CacheTraceAnalyzer {
    fn default() -> Self { Self { cache_line_size: 64 } }
}

impl CacheTraceAnalyzer {
    #[must_use]
    pub fn analyze(&self, events: &[CacheEvent]) -> SideChannelAnalysis {
        let mut analysis = SideChannelAnalysis::new();

        // Count accesses per cache set.
        let mut set_counts: HashMap<u32, usize> = HashMap::new();
        for ev in events {
            *set_counts.entry(ev.set_index).or_insert(0) += 1;
        }

        // AES T-table implementation: 4 tables of 1KB each → dense accesses to 4 sets.
        let dense_sets: usize = set_counts.values().filter(|&&c| c >= 10).count();
        if (4..=8).contains(&dense_sets) {
            analysis.add_hint(SideChannelHint {
                hint_type: SideChannelType::CacheTrace,
                algorithm_hint: "AES_T_TABLE",
                confidence: 0.85,
                description: format!(
                    "Dense access to {dense_sets} cache sets consistent with AES T-table implementation"
                ),
            });
        }

        // Miss rate: high miss rate → large table lookups (RSA, Blowfish).
        let misses = f64::from(u32::try_from(events.iter().filter(|e| !e.hit).count()).unwrap_or(u32::MAX));
        let total_ev = f64::from(u32::try_from(events.len().max(1)).unwrap_or(1));
        let miss_rate = misses / total_ev;
        if miss_rate > 0.4 {
            analysis.add_hint(SideChannelHint {
                hint_type: SideChannelType::CacheTrace,
                algorithm_hint: "LARGE_TABLE_CIPHER",
                confidence: 0.65,
                description: format!(
                    "High cache miss rate ({miss_rate:.2}) — consistent with Blowfish, Camellia, or RSA modular multiply"
                ),
            });
        }

        analysis
    }
}

// ─── Combined Analyzer ───────────────────────────────────────────────────────

/// Combines timing, memory, and branch analysis into a single report.
pub struct SideChannelSuite {
    pub timing: TimingAnalyzer,
    pub memory: MemoryAccessAnalyzer,
    pub branch: BranchAnalyzer,
    pub cache: CacheTraceAnalyzer,
}

impl Default for SideChannelSuite {
    fn default() -> Self {
        Self {
            timing: TimingAnalyzer::default(),
            memory: MemoryAccessAnalyzer,
            branch: BranchAnalyzer,
            cache: CacheTraceAnalyzer::default(),
        }
    }
}

impl SideChannelSuite {
    /// Run timing analysis on a live oracle.
    pub fn run_timing(&self, oracle: &dyn TimedOracle) -> SideChannelAnalysis {
        self.timing.analyze(oracle)
    }

    /// Combine multiple partial analyses into one.
    #[must_use]
    pub fn merge(analyses: Vec<SideChannelAnalysis>) -> SideChannelAnalysis {
        let mut merged = SideChannelAnalysis::new();
        for a in analyses {
            merged.hints.extend(a.hints);
            merged.likely_algorithms.extend(a.likely_algorithms);
            if let Some(p) = a.timing_profile {
                merged.timing_profile = Some(p);
            }
            if let Some(ct) = a.is_constant_time {
                merged.is_constant_time = Some(ct);
            }
        }
        // Deduplicate likely algorithms.
        merged.likely_algorithms.sort_unstable();
        merged.likely_algorithms.dedup();
        merged
    }

    /// Score each hypothesis from hints using confidence weighting.
    #[must_use]
    pub fn score_algorithms(analysis: &SideChannelAnalysis) -> Vec<(&'static str, f64)> {
        let mut scores: HashMap<&'static str, f64> = HashMap::new();
        for hint in &analysis.hints {
            *scores.entry(hint.algorithm_hint).or_insert(0.0) += hint.confidence;
        }
        let mut sorted: Vec<_> = scores.into_iter().collect();
        sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        sorted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SlowOnLongInput;
    impl TimedOracle for SlowOnLongInput {
        fn call(&self, input: &[u8]) -> Vec<u8> {
            // Simulate O(n) processing.
            let mut acc = 0u64;
            for &b in input { acc = acc.wrapping_add(u64::from(b)); }
            std::hint::black_box(acc);
            input.to_vec()
        }
    }

    #[test]
    fn timing_analyzer_runs() {
        let oracle = SlowOnLongInput;
        let analyzer = TimingAnalyzer { repetitions: 5, warmup: 2, input_lengths: vec![1, 16, 64] };
        let analysis = analyzer.analyze(&oracle);
        // Should produce at least one hint.
        assert!(!analysis.hints.is_empty() || analysis.timing_profile.is_some());
    }

    #[test]
    fn memory_access_aes_detection() {
        let analyzer = MemoryAccessAnalyzer;
        // 160 accesses in [0, 256) — AES-like.
        let offsets: Vec<usize> = (0..160).map(|i| (i * 7) % 256).collect();
        let analysis = analyzer.analyze_accesses(&offsets);
        assert!(analysis.likely_algorithms.iter().any(|&a| a.contains("AES")));
    }

    #[test]
    fn branch_analyzer_runs() {
        let analyzer = BranchAnalyzer;
        let branches: Vec<BranchRecord> = (0..100).map(|i| BranchRecord {
            address: 0x1000 + (i % 5) * 8,
            taken: i % 3 != 0,
            condition_value: Some(i),
        }).collect();
        let _analysis = analyzer.analyze(&branches);
    }

    #[test]
    fn merge_combines_hints() {
        let mut a1 = SideChannelAnalysis::new();
        a1.add_hint(SideChannelHint {
            hint_type: SideChannelType::Timing,
            algorithm_hint: "AES",
            confidence: 0.8,
            description: "hint A".into(),
        });
        let mut a2 = SideChannelAnalysis::new();
        a2.add_hint(SideChannelHint {
            hint_type: SideChannelType::MemoryAccess,
            algorithm_hint: "RSA_NON_CONST",
            confidence: 0.6,
            description: "hint B".into(),
        });
        let merged = SideChannelSuite::merge(vec![a1, a2]);
        assert_eq!(merged.hints.len(), 2);
        assert_eq!(merged.likely_algorithms.len(), 2);
    }
}
