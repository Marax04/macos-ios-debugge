// coverage_guided_fuzzer.rs — Coverage-guided fuzzer core for RustRE

use std::collections::HashMap;

// ─── CoverageMap ──────────────────────────────────────────────────────────────

/// Tracks execution edges (`from_addr`, `to_addr`) and their hit counts.
#[derive(Debug, Clone, Default)]
pub struct CoverageMap {
    pub edges: HashMap<(u64, u64), u64>,
}

impl CoverageMap {
    #[must_use]
    pub fn new() -> Self {
        Self { edges: HashMap::new() }
    }

    pub fn record_edge(&mut self, from: u64, to: u64) {
        *self.edges.entry((from, to)).or_insert(0) += 1;
    }

    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn merge(&mut self, other: &Self) {
        for (&edge, &count) in &other.edges {
            *self.edges.entry(edge).or_insert(0) += count;
        }
    }

    /// Returns the set of edges not present in `other`.
    #[must_use]
    pub fn new_edges_vs(&self, other: &Self) -> Vec<(u64, u64)> {
        self.edges.keys().filter(|e| !other.edges.contains_key(e)).copied().collect()
    }

    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.edges.values().sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    #[must_use]
    pub fn coverage_percent(&self, total_known_edges: usize) -> f64 {
        if total_known_edges == 0 {
            return 0.0;
        }
        (self.edges.len() as f64 / total_known_edges as f64) * 100.0
    }
}

// ─── CrashInfo ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CrashInfo {
    pub signal: u32,
    pub fault_addr: u64,
    pub backtrace: Vec<u64>,
}

impl CrashInfo {
    #[must_use]
    pub const fn new(signal: u32, fault_addr: u64, backtrace: Vec<u64>) -> Self {
        Self { signal, fault_addr, backtrace }
    }

    #[must_use]
    pub fn crash_hash(&self) -> u64 {
        let mut h: u64 = self.fault_addr ^ u64::from(self.signal).wrapping_mul(0x9e3779b97f4a7c15);
        for &addr in &self.backtrace {
            h = h.wrapping_mul(6364136223846793005).wrapping_add(addr);
        }
        h
    }
}

// ─── FuzzerInput ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FuzzerInput {
    pub data: Vec<u8>,
    pub coverage: CoverageMap,
    pub execution_time_us: u64,
    pub crash: Option<CrashInfo>,
}

impl FuzzerInput {
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            coverage: CoverageMap::new(),
            execution_time_us: 0,
            crash: None,
        }
    }

    #[must_use]
    pub const fn is_crash(&self) -> bool {
        self.crash.is_some()
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ─── FuzzerConfig ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FuzzerConfig {
    pub max_input_size: usize,
    pub timeout_ms: u64,
    pub seed_inputs: Vec<Vec<u8>>,
    pub max_corpus_size: usize,
    pub total_known_edges: usize,
}

impl Default for FuzzerConfig {
    fn default() -> Self {
        Self {
            max_input_size: 4096,
            timeout_ms: 1000,
            seed_inputs: vec![vec![0u8; 16]],
            max_corpus_size: 1000,
            total_known_edges: 1000,
        }
    }
}

// ─── CorpusEntry ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CorpusEntry {
    pub input: Vec<u8>,
    pub coverage: CoverageMap,
    pub unique_edges: u32,
    pub priority: f64,
    pub hit_count: u64,
}

impl CorpusEntry {
    #[must_use]
    pub fn new(input: Vec<u8>, coverage: CoverageMap, unique_edges: u32) -> Self {
        let priority = compute_priority(unique_edges, 1);
        Self {
            input,
            coverage,
            unique_edges,
            priority,
            hit_count: 1,
        }
    }

    pub fn update_priority(&mut self) {
        self.hit_count += 1;
        self.priority = compute_priority(self.unique_edges, self.hit_count);
    }
}

/// Priority = `rare_edges` / `log2(hit_count` + 1)
#[must_use]
pub fn compute_priority(unique_edges: u32, hit_count: u64) -> f64 {
    let denom = ((hit_count + 1) as f64).log2().max(1.0);
    f64::from(unique_edges) / denom
}

// ─── Corpus ───────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct Corpus {
    pub entries: Vec<CorpusEntry>,
    pub total_coverage: CoverageMap,
}

impl Corpus {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            total_coverage: CoverageMap::new(),
        }
    }

    /// Add input to corpus only if it brings new coverage edges.
    pub fn add_to_corpus(&mut self, input: Vec<u8>, coverage: CoverageMap) -> bool {
        let new_edges = coverage.new_edges_vs(&self.total_coverage);
        if new_edges.is_empty() {
            return false;
        }
        let unique = new_edges.len() as u32;
        self.total_coverage.merge(&coverage);
        let entry = CorpusEntry::new(input, coverage, unique);
        self.entries.push(entry);
        true
    }

    #[must_use]
    pub const fn size(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn total_edges(&self) -> usize {
        self.total_coverage.edge_count()
    }

    /// Select entry by priority-weighted random selection.
    pub fn select_entry(&self, rng_state: &mut u64) -> Option<&CorpusEntry> {
        if self.entries.is_empty() {
            return None;
        }
        let total_priority: f64 = self.entries.iter().map(|e| e.priority).sum();
        let r = (xorshift64(rng_state) as f64 / u64::MAX as f64) * total_priority;
        let mut acc = 0.0;
        for entry in &self.entries {
            acc += entry.priority;
            if acc >= r {
                return Some(entry);
            }
        }
        self.entries.last()
    }

    pub fn trim_to(&mut self, max_size: usize) {
        if self.entries.len() <= max_size {
            return;
        }
        // Keep entries with highest priority
        self.entries.sort_by(|a, b| b.priority.partial_cmp(&a.priority).unwrap_or(std::cmp::Ordering::Equal));
        self.entries.truncate(max_size);
    }
}

// ─── InterestingValues ────────────────────────────────────────────────────────

pub const INTERESTING_U8: &[u8] = &[0, 1, 16, 32, 64, 127, 128, 255];
pub const INTERESTING_U16: &[u16] = &[0, 1, 256, 512, 1024, 32767, 32768, 65535];
pub const INTERESTING_U32: &[u32] = &[
    0, 1, 256, 65536, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff,
];

// ─── xorshift64 ───────────────────────────────────────────────────────────────

pub const fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

// ─── HavocMutator ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HavocMutator {
    pub rng_state: u64,
    pub dictionary: Vec<Vec<u8>>,
}

impl HavocMutator {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            rng_state: if seed == 0 { 0xdeadbeef_cafebabe } else { seed },
            dictionary: Vec::new(),
        }
    }

    pub fn add_dictionary_entry(&mut self, entry: Vec<u8>) {
        self.dictionary.push(entry);
    }

    const fn rand_below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        xorshift64(&mut self.rng_state) % n
    }

    /// Flip a single bit in data.
    pub fn bit_flip(&mut self, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        let idx = self.rand_below(data.len() as u64) as usize;
        let bit = self.rand_below(8) as u8;
        data[idx] ^= 1 << bit;
    }

    /// Flip a single byte to a random value.
    pub fn byte_flip(&mut self, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        let idx = self.rand_below(data.len() as u64) as usize;
        data[idx] = self.rand_below(256) as u8;
    }

    /// Add or subtract a small delta (arithmetic mutation).
    pub fn arithmetic(&mut self, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        let idx = self.rand_below(data.len() as u64) as usize;
        let delta = self.rand_below(35) as i16 - 17;
        data[idx] = (i16::from(data[idx]).wrapping_add(delta) & 0xff) as u8;
    }

    /// Replace a byte with an interesting value.
    pub fn interesting_byte(&mut self, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        let idx = self.rand_below(data.len() as u64) as usize;
        let iv_idx = self.rand_below(INTERESTING_U8.len() as u64) as usize;
        data[idx] = INTERESTING_U8[iv_idx];
    }

    /// Replace a 16-bit word with an interesting value.
    pub fn interesting_word(&mut self, data: &mut [u8]) {
        if data.len() < 2 {
            return;
        }
        let max_idx = (data.len() - 2) as u64;
        let idx = self.rand_below(max_idx + 1) as usize;
        let iv_idx = self.rand_below(INTERESTING_U16.len() as u64) as usize;
        let val = INTERESTING_U16[iv_idx];
        // LE
        data[idx] = (val & 0xff) as u8;
        data[idx + 1] = (val >> 8) as u8;
    }

    /// Replace a 32-bit dword with an interesting value.
    pub fn interesting_dword(&mut self, data: &mut [u8]) {
        if data.len() < 4 {
            return;
        }
        let max_idx = (data.len() - 4) as u64;
        let idx = self.rand_below(max_idx + 1) as usize;
        let iv_idx = self.rand_below(INTERESTING_U32.len() as u64) as usize;
        let val = INTERESTING_U32[iv_idx];
        data[idx] = (val & 0xff) as u8;
        data[idx + 1] = ((val >> 8) & 0xff) as u8;
        data[idx + 2] = ((val >> 16) & 0xff) as u8;
        data[idx + 3] = ((val >> 24) & 0xff) as u8;
    }

    /// Splice: take a random chunk from `other` and insert into `data`.
    pub fn splice(&mut self, data: &mut Vec<u8>, other: &[u8], max_size: usize) {
        if other.is_empty() || data.is_empty() {
            return;
        }
        let src_start = self.rand_below(other.len() as u64) as usize;
        let src_len = self.rand_below((other.len() - src_start).min(64) as u64 + 1) as usize;
        let dst_pos = self.rand_below(data.len() as u64) as usize;
        let chunk = &other[src_start..src_start + src_len];
        let new_len = data.len() + chunk.len();
        if new_len <= max_size {
            let tail: Vec<u8> = data[dst_pos..].to_vec();
            data.truncate(dst_pos);
            data.extend_from_slice(chunk);
            data.extend_from_slice(&tail);
        }
    }

    /// Insert bytes from the dictionary.
    pub fn dictionary_insert(&mut self, data: &mut Vec<u8>, max_size: usize) {
        if self.dictionary.is_empty() || data.is_empty() {
            return;
        }
        let dict_idx = self.rand_below(self.dictionary.len() as u64) as usize;
        let entry = self.dictionary[dict_idx].clone();
        let pos = self.rand_below(data.len() as u64) as usize;
        if data.len() + entry.len() <= max_size {
            let tail: Vec<u8> = data[pos..].to_vec();
            data.truncate(pos);
            data.extend_from_slice(&entry);
            data.extend_from_slice(&tail);
        }
    }

    /// Apply a random havoc mutation.
    pub fn mutate_one(&mut self, data: &mut Vec<u8>, max_size: usize) {
        let choice = self.rand_below(8);
        match choice {
            0 => self.bit_flip(data),
            1 => self.byte_flip(data),
            2 => self.arithmetic(data),
            3 => self.interesting_byte(data),
            4 => self.interesting_word(data),
            5 => self.interesting_dword(data),
            6 => {
                // Insert random byte
                if data.len() < max_size {
                    let pos = self.rand_below(data.len() as u64 + 1) as usize;
                    let b = self.rand_below(256) as u8;
                    data.insert(pos, b);
                }
            }
            _ => {
                // Delete a byte
                if !data.is_empty() {
                    let pos = self.rand_below(data.len() as u64) as usize;
                    data.remove(pos);
                }
            }
        }
    }

    /// Apply `n` random mutations.
    pub fn mutate_n(&mut self, data: &[u8], n: u32, max_size: usize) -> Vec<u8> {
        let mut result = data.to_vec();
        for _ in 0..n {
            self.mutate_one(&mut result, max_size);
        }
        result
    }
}

// ─── Simulated execution ──────────────────────────────────────────────────────

/// Simulate executing `data` against a pseudo-target and return a `FuzzerInput`.
/// In real use, this would fork/exec the target with instrumentation.
pub fn simulate_execution(data: &[u8], rng: &mut u64) -> FuzzerInput {
    let mut input = FuzzerInput::new(data.to_vec());
    // Simulate coverage: deterministic edges from data content
    let mut prev_pc: u64 = 0x1000;
    for (i, &b) in data.iter().enumerate().take(32) {
        let pc = 0x1000 + (u64::from(b) * 17) + (i as u64 * 3);
        input.coverage.record_edge(prev_pc, pc);
        prev_pc = pc;
    }
    // Add some noise
    let noise = xorshift64(rng) & 0xf;
    for _j in 0..noise {
        let a = xorshift64(rng) & 0xfff;
        let b = xorshift64(rng) & 0xfff;
        input.coverage.record_edge(a, b);
    }
    let _ = noise;
    input.execution_time_us = 100 + xorshift64(rng) % 900;

    // Simulate rare crash: if data starts with magic bytes
    if data.len() >= 4 && data[0] == 0xde && data[1] == 0xad && data[2] == 0xbe && data[3] == 0xef {
        input.crash = Some(CrashInfo::new(11, 0xdeadbeef, vec![0x1234, 0x5678]));
    }
    input
}

// ─── CoverageGuidedFuzzer ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct CoverageGuidedFuzzer {
    pub config: FuzzerConfig,
    pub corpus: Corpus,
    pub mutator: HavocMutator,
    pub iterations: u64,
    pub crashes: Vec<FuzzerInput>,
    pub rng_state: u64,
}

impl CoverageGuidedFuzzer {
    #[must_use]
    pub fn new(config: FuzzerConfig, seed: u64) -> Self {
        let mut fuzzer = Self {
            config: config.clone(),
            corpus: Corpus::new(),
            mutator: HavocMutator::new(seed),
            iterations: 0,
            crashes: Vec::new(),
            rng_state: if seed == 0 { 0xcafe_babe } else { seed },
        };
        // Seed corpus
        for seed_data in &config.seed_inputs {
            let mut cov = CoverageMap::new();
            for (i, &b) in seed_data.iter().enumerate() {
                cov.record_edge(i as u64, u64::from(b) + 0x1000);
            }
            fuzzer.corpus.add_to_corpus(seed_data.clone(), cov);
        }
        fuzzer
    }

    /// Mutate and simulate execution of one corpus entry.
    pub fn fuzz_one(&mut self, entry: &CorpusEntry) -> FuzzerInput {
        let mutations = 1 + self.mutator.rand_below(8) as u32;
        let mutated = self.mutator.mutate_n(&entry.input, mutations, self.config.max_input_size);
        let input = simulate_execution(&mutated, &mut self.rng_state);
        self.iterations += 1;
        input
    }

    /// Run one round: pick entry, fuzz it, add to corpus if interesting.
    pub fn run_one_round(&mut self) -> bool {
        let entry = match self.corpus.select_entry(&mut self.rng_state) {
            Some(e) => e.clone(),
            None => return false,
        };
        let result = self.fuzz_one(&entry);
        if result.is_crash() {
            self.crashes.push(result.clone());
        }
        let added = self.corpus.add_to_corpus(result.data.clone(), result.coverage);
        if self.corpus.size() > self.config.max_corpus_size {
            self.corpus.trim_to(self.config.max_corpus_size);
        }
        added
    }

    pub fn run_n_rounds(&mut self, n: u64) {
        for _ in 0..n {
            self.run_one_round();
        }
    }

    #[must_use]
    pub fn report(&self) -> FuzzReport {
        FuzzReport {
            iterations: self.iterations,
            corpus_size: self.corpus.size() as u32,
            crashes: self.crashes.len() as u32,
            coverage_percent: self.corpus.total_coverage.coverage_percent(self.config.total_known_edges),
        }
    }
}

// ─── FuzzReport ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FuzzReport {
    pub iterations: u64,
    pub corpus_size: u32,
    pub crashes: u32,
    pub coverage_percent: f64,
}

impl FuzzReport {
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Iterations: {} | Corpus: {} | Crashes: {} | Coverage: {:.2}%",
            self.iterations, self.corpus_size, self.crashes, self.coverage_percent
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> FuzzerConfig {
        FuzzerConfig {
            seed_inputs: vec![vec![1, 2, 3, 4]],
            max_input_size: 256,
            timeout_ms: 100,
            max_corpus_size: 100,
            total_known_edges: 100,
        }
    }

    #[test]
    fn test_coverage_map_new_empty() {
        let m = CoverageMap::new();
        assert_eq!(m.edge_count(), 0);
        assert!(m.is_empty());
    }

    #[test]
    fn test_coverage_map_record_edge() {
        let mut m = CoverageMap::new();
        m.record_edge(0x100, 0x200);
        m.record_edge(0x100, 0x200);
        assert_eq!(m.edge_count(), 1);
        assert_eq!(*m.edges.get(&(0x100, 0x200)).unwrap(), 2);
    }

    #[test]
    fn test_coverage_map_merge() {
        let mut a = CoverageMap::new();
        a.record_edge(1, 2);
        let mut b = CoverageMap::new();
        b.record_edge(3, 4);
        a.merge(&b);
        assert_eq!(a.edge_count(), 2);
    }

    #[test]
    fn test_coverage_map_new_edges_vs() {
        let mut a = CoverageMap::new();
        a.record_edge(1, 2);
        a.record_edge(3, 4);
        let mut b = CoverageMap::new();
        b.record_edge(1, 2);
        let new = a.new_edges_vs(&b);
        assert_eq!(new.len(), 1);
        assert_eq!(new[0], (3, 4));
    }

    #[test]
    fn test_coverage_percent() {
        let mut m = CoverageMap::new();
        for i in 0..50u64 {
            m.record_edge(i, i + 1);
        }
        let pct = m.coverage_percent(100);
        assert!((pct - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_crash_info_hash_stable() {
        let c = CrashInfo::new(11, 0xdeadbeef, vec![0x1000, 0x2000]);
        assert_eq!(c.crash_hash(), c.crash_hash());
    }

    #[test]
    fn test_crash_info_different_signals() {
        let c1 = CrashInfo::new(11, 0xdeadbeef, vec![]);
        let c2 = CrashInfo::new(6, 0xdeadbeef, vec![]);
        assert_ne!(c1.crash_hash(), c2.crash_hash());
    }

    #[test]
    fn test_xorshift64_not_zero() {
        let mut state = 12345u64;
        for _ in 0..100 {
            let v = xorshift64(&mut state);
            assert_ne!(v, 0);
        }
    }

    #[test]
    fn test_havoc_bit_flip_changes_data() {
        let mut m = HavocMutator::new(42);
        let orig = vec![0u8; 16];
        let mut data = orig.clone();
        m.bit_flip(&mut data);
        assert_ne!(data, orig);
    }

    #[test]
    fn test_havoc_interesting_byte_in_range() {
        let mut m = HavocMutator::new(99);
        let mut data = vec![0xAA; 8];
        for _ in 0..20 {
            m.interesting_byte(&mut data);
        }
        for b in &data {
            assert!(INTERESTING_U8.contains(b));
        }
    }

    #[test]
    fn test_compute_priority_decreases_with_hits() {
        let p1 = compute_priority(10, 1);
        let p2 = compute_priority(10, 100);
        assert!(p1 > p2);
    }

    #[test]
    fn test_corpus_add_new_edges() {
        let mut corpus = Corpus::new();
        let mut cov1 = CoverageMap::new();
        cov1.record_edge(1, 2);
        let added = corpus.add_to_corpus(vec![1], cov1);
        assert!(added);
        assert_eq!(corpus.size(), 1);
    }

    #[test]
    fn test_corpus_no_add_duplicate_edges() {
        let mut corpus = Corpus::new();
        let mut cov = CoverageMap::new();
        cov.record_edge(1, 2);
        corpus.add_to_corpus(vec![1], cov.clone());
        let added = corpus.add_to_corpus(vec![2], cov);
        assert!(!added);
        assert_eq!(corpus.size(), 1);
    }

    #[test]
    fn test_corpus_trim() {
        let mut corpus = Corpus::new();
        for i in 0..20u64 {
            let mut cov = CoverageMap::new();
            cov.record_edge(i * 10, i * 10 + 1);
            corpus.add_to_corpus(vec![i as u8], cov);
        }
        corpus.trim_to(10);
        assert!(corpus.size() <= 10);
    }

    #[test]
    fn test_fuzzer_init_seeds_corpus() {
        let config = make_config();
        let fuzzer = CoverageGuidedFuzzer::new(config, 1);
        assert!(fuzzer.corpus.size() >= 1);
    }

    #[test]
    fn test_fuzzer_run_rounds_increments_iterations() {
        let config = make_config();
        let mut fuzzer = CoverageGuidedFuzzer::new(config, 7);
        fuzzer.run_n_rounds(50);
        assert_eq!(fuzzer.iterations, 50);
    }

    #[test]
    fn test_fuzzer_report_summary_nonempty() {
        let config = make_config();
        let mut fuzzer = CoverageGuidedFuzzer::new(config, 3);
        fuzzer.run_n_rounds(10);
        let rep = fuzzer.report();
        assert!(!rep.summary().is_empty());
    }

    #[test]
    fn test_simulate_execution_crash_on_magic() {
        let mut rng = 0x1234u64;
        let data = vec![0xde, 0xad, 0xbe, 0xef, 0x00];
        let input = simulate_execution(&data, &mut rng);
        assert!(input.is_crash());
    }

    #[test]
    fn test_simulate_execution_no_crash_normal() {
        let mut rng = 0xabcdu64;
        let data = vec![1, 2, 3, 4];
        let input = simulate_execution(&data, &mut rng);
        assert!(!input.is_crash());
    }
}
