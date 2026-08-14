use std::cmp::Ordering;
use std::time::{Duration, Instant};

// ── Coverage bitmap ───────────────────────────────────────────────────────────

const MAP_SIZE: usize = 65536;

#[derive(Debug, Clone)]
pub struct CoverageBitmap {
    pub bits: Vec<u8>,
    pub hit_count: u64,
}

impl CoverageBitmap {
    pub fn new() -> Self {
        Self { bits: vec![0u8; MAP_SIZE], hit_count: 0 }
    }

    pub fn reset(&mut self) {
        self.bits.fill(0);
        self.hit_count = 0;
    }

    pub fn has_new_bits(&self, virgin_map: &[u8]) -> bool {
        for (i, &b) in self.bits.iter().enumerate() {
            if b != 0 && virgin_map[i] == 0 {
                return true;
            }
        }
        false
    }

    pub fn update_virgin_map(&self, virgin_map: &mut Vec<u8>) -> u32 {
        let mut new_bits = 0u32;
        for (i, &b) in self.bits.iter().enumerate() {
            if b != 0 && virgin_map[i] == 0 {
                virgin_map[i] = b;
                new_bits += 1;
            }
        }
        new_bits
    }

    pub fn count_bits(&self) -> usize {
        self.bits.iter().filter(|&&b| b != 0).count()
    }

    pub fn edge_count(&self) -> u64 {
        self.bits.iter().map(|&b| b as u64).sum()
    }

    pub fn merge(&mut self, other: &CoverageBitmap) {
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a |= b;
        }
    }

    pub fn classify_counts(&mut self) {
        for b in self.bits.iter_mut() {
            *b = count_class_lookup(*b);
        }
    }
}

fn count_class_lookup(n: u8) -> u8 {
    match n {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4..=7 => 8,
        8..=15 => 16,
        16..=31 => 32,
        32..=127 => 64,
        _ => 128,
    }
}

// ── Corpus entry ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CorpusEntry {
    pub id: u64,
    pub data: Vec<u8>,
    pub coverage: CoverageBitmap,
    pub unique_bits: u32,
    pub exec_time_us: u64,
    pub score: f64,
    pub mutations_performed: u64,
    pub mutations_found_new: u64,
    pub depth: u32,
    pub parent_id: Option<u64>,
    pub creation_time: Instant,
    pub last_fuzzed: Option<Instant>,
    pub tags: Vec<String>,
    pub crash_triggered: bool,
}

impl CorpusEntry {
    pub fn new(id: u64, data: Vec<u8>, coverage: CoverageBitmap, unique_bits: u32) -> Self {
        Self {
            id, data, coverage, unique_bits,
            exec_time_us: 0,
            score: 0.0,
            mutations_performed: 0,
            mutations_found_new: 0,
            depth: 0,
            parent_id: None,
            creation_time: Instant::now(),
            last_fuzzed: None,
            tags: Vec::new(),
            crash_triggered: false,
        }
    }

    pub fn compute_score(&mut self) {
        let coverage_score = self.unique_bits as f64 * 100.0;
        let perf_score = if self.exec_time_us == 0 { 1.0 } else { 1000.0 / self.exec_time_us as f64 };
        let depth_bonus = self.depth as f64 * 5.0;
        let mutation_efficiency = if self.mutations_performed > 0 {
            self.mutations_found_new as f64 / self.mutations_performed as f64
        } else { 0.0 };
        self.score = coverage_score + perf_score * 10.0 + depth_bonus + mutation_efficiency * 50.0;
    }

    pub fn is_favored(&self) -> bool {
        self.unique_bits > 0
    }
}

// ── Corpus queue ──────────────────────────────────────────────────────────────

pub struct CorpusQueue {
    entries: Vec<CorpusEntry>,
    virgin_map: Vec<u8>,
    current_index: usize,
    cycle_count: u64,
    next_id: u64,
    total_executions: u64,
    start_time: Instant,
}

impl CorpusQueue {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            virgin_map: vec![0u8; MAP_SIZE],
            current_index: 0,
            cycle_count: 0,
            next_id: 0,
            total_executions: 0,
            start_time: Instant::now(),
        }
    }

    pub fn add_initial(&mut self, data: Vec<u8>, coverage: CoverageBitmap) {
        let unique = coverage.update_virgin_map(&mut self.virgin_map);
        let mut entry = CorpusEntry::new(self.next_id, data, coverage, unique);
        entry.compute_score();
        self.next_id += 1;
        self.entries.push(entry);
    }

    pub fn add_from_mutation(&mut self, data: Vec<u8>, coverage: CoverageBitmap, parent_id: u64, depth: u32) -> Option<u64> {
        if coverage.has_new_bits(&self.virgin_map) {
            let unique = coverage.update_virgin_map(&mut self.virgin_map);
            let id = self.next_id;
            let mut entry = CorpusEntry::new(id, data, coverage, unique);
            entry.parent_id = Some(parent_id);
            entry.depth = depth;
            entry.compute_score();
            self.next_id += 1;
            self.entries.push(entry);
            return Some(id);
        }
        None
    }

    pub fn next_entry(&mut self) -> Option<&mut CorpusEntry> {
        if self.entries.is_empty() { return None; }
        if self.current_index >= self.entries.len() {
            self.current_index = 0;
            self.cycle_count += 1;
            self.recompute_scores();
            self.sort_by_score();
        }
        let entry = &mut self.entries[self.current_index];
        self.current_index += 1;
        Some(entry)
    }

    fn recompute_scores(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.compute_score();
        }
    }

    fn sort_by_score(&mut self) {
        self.entries.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal));
    }

    pub fn coverage_percentage(&self) -> f64 {
        let covered = self.virgin_map.iter().filter(|&&b| b != 0).count();
        covered as f64 / MAP_SIZE as f64 * 100.0
    }

    pub fn stats(&self) -> CorpusStats {
        CorpusStats {
            total_entries: self.entries.len(),
            total_executions: self.total_executions,
            cycle_count: self.cycle_count,
            coverage_percentage: self.coverage_percentage(),
            elapsed: self.start_time.elapsed(),
            paths_total: self.entries.len(),
            paths_favored: self.entries.iter().filter(|e| e.is_favored()).count(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CorpusStats {
    pub total_entries: usize,
    pub total_executions: u64,
    pub cycle_count: u64,
    pub coverage_percentage: f64,
    pub elapsed: Duration,
    pub paths_total: usize,
    pub paths_favored: usize,
}

// ── Energy scheduling ─────────────────────────────────────────────────────────

pub struct EnergyScheduler {
    base_mutations: u32,
    max_multiplier: f64,
}

impl EnergyScheduler {
    pub fn new() -> Self {
        Self { base_mutations: 64, max_multiplier: 16.0 }
    }

    pub fn compute_energy(&self, entry: &CorpusEntry, queue_cycle: u64) -> u32 {
        let mut perf_score = match entry.exec_time_us {
            0..=1000 => 300,
            1001..=5000 => 200,
            5001..=20000 => 100,
            20001..=100000 => 50,
            _ => 25,
        };
        match entry.data.len() {
            0..=128 => perf_score = perf_score * 3 / 2,
            129..=1024 => {},
            1025..=8192 => perf_score = perf_score * 3 / 4,
            _ => perf_score /= 2,
        }
        if entry.depth > 0 {
            perf_score = (perf_score as f64 * (1.0 + entry.depth as f64 * 0.1)).min(perf_score as f64 * self.max_multiplier) as u32;
        }
        let cycle_bonus = if queue_cycle <= 1 { 1.0 } else { 1.0 / (queue_cycle as f64).log2() };
        let energy = (self.base_mutations as f64 * perf_score as f64 / 100.0 * cycle_bonus) as u32;
        energy.max(1).min(1024)
    }
}

// ── Seed minimizer ────────────────────────────────────────────────────────────

pub struct SeedMinimizer {
    pub min_chunk: usize,
}

impl SeedMinimizer {
    pub fn new() -> Self { Self { min_chunk: 4 } }

    pub fn minimize<F>(&self, data: &[u8], mut test_fn: F) -> Vec<u8>
    where F: FnMut(&[u8]) -> CoverageBitmap
    {
        let original_cov = test_fn(data);
        let mut current = data.to_vec();
        let mut chunk_size = current.len() / 2;
        while chunk_size >= self.min_chunk {
            let mut i = 0;
            while i < current.len() {
                let end = (i + chunk_size).min(current.len());
                let candidate: Vec<u8> = current[..i].iter().chain(current[end..].iter()).cloned().collect();
                if candidate.is_empty() { i += chunk_size; continue; }
                let cov = test_fn(&candidate);
                if cov.count_bits() >= original_cov.count_bits() {
                    current = candidate;
                } else {
                    i += chunk_size;
                }
            }
            chunk_size /= 2;
        }
        current
    }
}

// ── Coverage-guided fuzzer ────────────────────────────────────────────────────

pub struct CoverageGuidedFuzzer {
    pub corpus: CorpusQueue,
    pub scheduler: EnergyScheduler,
    pub crashes: Vec<CrashEntry>,
    pub timeouts: Vec<Vec<u8>>,
    pub total_exec: u64,
    pub exec_per_sec: f64,
    pub last_new_path: Option<Instant>,
    pub last_crash: Option<Instant>,
    pub config: FuzzerConfig,
    pub rng: SimpleRng,
}

#[derive(Debug, Clone)]
pub struct FuzzerConfig {
    pub timeout_ms: u64,
    pub memory_limit_mb: u64,
    pub max_corpus_size: usize,
    pub minimize_crashes: bool,
    pub use_cmplog: bool,
    pub power_schedule: PowerSchedule,
    pub dict_tokens: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PowerSchedule {
    Fast,
    Explore,
    Exploit,
    Lin,
    Quad,
    Mmopt,
}

impl Default for FuzzerConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 1000,
            memory_limit_mb: 256,
            max_corpus_size: 10000,
            minimize_crashes: true,
            use_cmplog: false,
            power_schedule: PowerSchedule::Fast,
            dict_tokens: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CrashEntry {
    pub id: u64,
    pub data: Vec<u8>,
    pub crash_type: CrashType,
    pub signal: Option<i32>,
    pub address: Option<u64>,
    pub stack_hash: Option<u64>,
    pub is_unique: bool,
    pub parent_corpus_id: Option<u64>,
    pub minimized: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CrashType {
    SegFault,
    HeapOverflow,
    StackOverflow,
    UseAfterFree,
    DoubleFree,
    NullDeref,
    Abort,
    Timeout,
    OOM,
    Other(String),
}

pub struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    pub fn new(seed: u64) -> Self { Self { state: seed } }

    pub fn next_u64(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }

    pub fn next_usize(&mut self, max: usize) -> usize {
        if max == 0 { return 0; }
        (self.next_u64() % max as u64) as usize
    }

    pub fn next_u8(&mut self) -> u8 { self.next_u64() as u8 }
    pub fn next_bool(&mut self) -> bool { self.next_u64() & 1 == 0 }
    pub fn next_u16(&mut self) -> u16 { self.next_u64() as u16 }
    pub fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
}

impl CoverageGuidedFuzzer {
    pub fn new(config: FuzzerConfig) -> Self {
        Self {
            corpus: CorpusQueue::new(),
            scheduler: EnergyScheduler::new(),
            crashes: Vec::new(),
            timeouts: Vec::new(),
            total_exec: 0,
            exec_per_sec: 0.0,
            last_new_path: None,
            last_crash: None,
            config,
            rng: SimpleRng::new(0xdeadbeef),
        }
    }

    pub fn add_seed(&mut self, data: Vec<u8>, coverage: CoverageBitmap) {
        self.corpus.add_initial(data, coverage);
    }

    pub fn mutate(&mut self, entry_data: &[u8]) -> Vec<Vec<u8>> {
        let mut results = Vec::new();
        let energy = 32usize;
        for _ in 0..energy {
            let mutant = self.pick_and_apply_mutation(entry_data);
            results.push(mutant);
        }
        results
    }

    fn pick_and_apply_mutation(&mut self, data: &[u8]) -> Vec<u8> {
        let choice = self.rng.next_usize(10);
        match choice {
            0 => self.mutate_bit_flip(data),
            1 => self.mutate_byte_flip(data),
            2 => self.mutate_interesting_u8(data),
            3 => self.mutate_interesting_u16(data),
            4 => self.mutate_interesting_u32(data),
            5 => self.mutate_random_byte(data),
            6 => self.mutate_delete_bytes(data),
            7 => self.mutate_insert_bytes(data),
            8 => self.mutate_copy_part(data),
            _ => self.mutate_splice(data),
        }
    }

    fn mutate_bit_flip(&mut self, data: &[u8]) -> Vec<u8> {
        let mut result = data.to_vec();
        if result.is_empty() { return result; }
        let pos = self.rng.next_usize(result.len());
        let bit = self.rng.next_usize(8);
        result[pos] ^= 1 << bit;
        result
    }

    fn mutate_byte_flip(&mut self, data: &[u8]) -> Vec<u8> {
        let mut result = data.to_vec();
        if result.is_empty() { return result; }
        let pos = self.rng.next_usize(result.len());
        result[pos] ^= 0xff;
        result
    }

    fn mutate_interesting_u8(&mut self, data: &[u8]) -> Vec<u8> {
        const INTERESTING_8: &[u8] = &[0, 1, 0x7f, 0x80, 0xfe, 0xff];
        let mut result = data.to_vec();
        if result.is_empty() { return result; }
        let pos = self.rng.next_usize(result.len());
        let val = INTERESTING_8[self.rng.next_usize(INTERESTING_8.len())];
        result[pos] = val;
        result
    }

    fn mutate_interesting_u16(&mut self, data: &[u8]) -> Vec<u8> {
        const INTERESTING_16: &[u16] = &[0, 1, 0x7fff, 0x8000, 0xfffe, 0xffff, 0x100, 0x200];
        let mut result = data.to_vec();
        if result.len() < 2 { return result; }
        let pos = self.rng.next_usize(result.len() - 1);
        let val = INTERESTING_16[self.rng.next_usize(INTERESTING_16.len())].to_le_bytes();
        result[pos] = val[0];
        result[pos + 1] = val[1];
        result
    }

    fn mutate_interesting_u32(&mut self, data: &[u8]) -> Vec<u8> {
        const INTERESTING_32: &[u32] = &[0, 1, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff, 0x10000];
        let mut result = data.to_vec();
        if result.len() < 4 { return result; }
        let pos = self.rng.next_usize(result.len() - 3);
        let val = INTERESTING_32[self.rng.next_usize(INTERESTING_32.len())].to_le_bytes();
        result[pos..pos+4].copy_from_slice(&val);
        result
    }

    fn mutate_random_byte(&mut self, data: &[u8]) -> Vec<u8> {
        let mut result = data.to_vec();
        if result.is_empty() { return result; }
        let pos = self.rng.next_usize(result.len());
        result[pos] = self.rng.next_u8();
        result
    }

    fn mutate_delete_bytes(&mut self, data: &[u8]) -> Vec<u8> {
        if data.len() <= 1 { return data.to_vec(); }
        let start = self.rng.next_usize(data.len());
        let len = self.rng.next_usize((data.len() - start).max(1)) + 1;
        let end = (start + len).min(data.len());
        let mut result = data[..start].to_vec();
        result.extend_from_slice(&data[end..]);
        result
    }

    fn mutate_insert_bytes(&mut self, data: &[u8]) -> Vec<u8> {
        let pos = self.rng.next_usize(data.len() + 1);
        let count = self.rng.next_usize(32) + 1;
        let mut result = data[..pos].to_vec();
        for _ in 0..count { result.push(self.rng.next_u8()); }
        result.extend_from_slice(&data[pos..]);
        result
    }

    fn mutate_copy_part(&mut self, data: &[u8]) -> Vec<u8> {
        if data.len() < 2 { return data.to_vec(); }
        let src = self.rng.next_usize(data.len());
        let dst = self.rng.next_usize(data.len());
        let len = self.rng.next_usize((data.len() - src.max(dst)).max(1)) + 1;
        let mut result = data.to_vec();
        let src_end = (src + len).min(data.len());
        let chunk: Vec<u8> = result[src..src_end].to_vec();
        for (i, &b) in chunk.iter().enumerate() {
            if dst + i < result.len() { result[dst + i] = b; }
        }
        result
    }

    fn mutate_splice(&mut self, data: &[u8]) -> Vec<u8> {
        if self.corpus.entries.is_empty() { return data.to_vec(); }
        let other_idx = self.rng.next_usize(self.corpus.entries.len());
        let other = &self.corpus.entries[other_idx].data.clone();
        if other.is_empty() { return data.to_vec(); }
        let split = self.rng.next_usize(data.len() + 1);
        let other_split = self.rng.next_usize(other.len() + 1);
        let mut result = data[..split].to_vec();
        result.extend_from_slice(&other[other_split..]);
        result
    }

    pub fn record_crash(&mut self, data: Vec<u8>, crash_type: CrashType, parent_id: Option<u64>) {
        let stack_hash = Self::hash_data(&data);
        let is_unique = !self.crashes.iter().any(|c| c.stack_hash == Some(stack_hash));
        let id = self.crashes.len() as u64;
        self.crashes.push(CrashEntry {
            id, data, crash_type, signal: None, address: None,
            stack_hash: Some(stack_hash), is_unique, parent_corpus_id: parent_id, minimized: None,
        });
        self.last_crash = Some(Instant::now());
    }

    fn hash_data(data: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in data {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }

    pub fn stats(&self) -> FuzzerStats {
        let unique_crashes = self.crashes.iter().filter(|c| c.is_unique).count();
        FuzzerStats {
            total_executions: self.total_exec,
            corpus_size: self.corpus.entries.len(),
            unique_crashes,
            total_crashes: self.crashes.len(),
            timeouts: self.timeouts.len(),
            coverage_pct: self.corpus.coverage_percentage(),
            cycle: self.corpus.cycle_count,
            exec_per_sec: self.exec_per_sec,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FuzzerStats {
    pub total_executions: u64,
    pub corpus_size: usize,
    pub unique_crashes: usize,
    pub total_crashes: usize,
    pub timeouts: usize,
    pub coverage_pct: f64,
    pub cycle: u64,
    pub exec_per_sec: f64,
}

// ── Token-based mutation (dict) ───────────────────────────────────────────────

pub struct DictMutator {
    pub tokens: Vec<Vec<u8>>,
}

impl DictMutator {
    pub fn new(tokens: Vec<Vec<u8>>) -> Self { Self { tokens } }

    pub fn insert_token(&self, data: &[u8], pos: usize, rng: &mut SimpleRng) -> Vec<u8> {
        if self.tokens.is_empty() { return data.to_vec(); }
        let tok = &self.tokens[rng.next_usize(self.tokens.len())];
        let mut result = data[..pos].to_vec();
        result.extend_from_slice(tok);
        result.extend_from_slice(&data[pos..]);
        result
    }

    pub fn overwrite_token(&self, data: &[u8], pos: usize, rng: &mut SimpleRng) -> Vec<u8> {
        if self.tokens.is_empty() { return data.to_vec(); }
        let tok = &self.tokens[rng.next_usize(self.tokens.len())];
        let mut result = data.to_vec();
        for (i, &b) in tok.iter().enumerate() {
            if pos + i < result.len() { result[pos + i] = b; }
        }
        result
    }
}
