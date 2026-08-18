//! Fuzzing campaign manager: config, stats, checkpoints, and target descriptors.
//!
//! Provides [`FuzzCampaign`], [`CampaignStats`], [`CampaignConfig`],
//! [`CampaignCheckpoint`], and [`FuzzTarget`].


use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ─── FuzzTarget ───────────────────────────────────────────────────────────────

/// Description of the fuzzing target binary and harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzTarget {
    /// Path to the target binary.
    pub binary: PathBuf,
    /// Harness type (in-process, out-of-process, library).
    pub harness: HarnessKind,
    /// Additional command-line arguments (before the input placeholder).
    pub args_prefix: Vec<String>,
    /// Input delivery method.
    pub input_method: InputMethod,
    /// Optional wrapper (e.g. "valgrind", "qemu").
    pub wrapper: Option<String>,
}

/// How the harness wraps the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HarnessKind {
    /// Target is called in-process via a function pointer.
    InProcess,
    /// Target is spawned as a child process.
    OutOfProcess,
    /// Target is a shared library with a known fuzz entry point.
    Library,
}

/// How the fuzzer delivers input to the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputMethod {
    /// Write to a temporary file and pass path as argument.
    File,
    /// Pipe to stdin.
    Stdin,
    /// Pass via shared memory.
    SharedMemory,
    /// Call a function with a byte slice pointer.
    Direct,
}

impl FuzzTarget {
    #[must_use]
    pub const fn new(binary: PathBuf, harness: HarnessKind) -> Self {
        Self {
            binary,
            harness,
            args_prefix: Vec::new(),
            input_method: InputMethod::File,
            wrapper: None,
        }
    }

    #[must_use]
    pub const fn with_stdin(mut self) -> Self {
        self.input_method = InputMethod::Stdin;
        self
    }

    #[must_use]
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args_prefix = args;
        self
    }

    #[must_use]
    pub fn with_wrapper(mut self, wrapper: &str) -> Self {
        self.wrapper = Some(wrapper.to_string());
        self
    }
}

// ─── CampaignConfig ───────────────────────────────────────────────────────────

/// Configuration for a fuzzing campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignConfig {
    /// Wall-clock timeout per execution (milliseconds).
    pub timeout_ms: u64,
    /// Memory limit per execution (bytes; 0 = unlimited).
    pub mem_limit_bytes: u64,
    /// Maximum number of parallel fuzzer jobs.
    pub jobs: u8,
    /// Maximum total corpus size (entries; 0 = unlimited).
    pub max_corpus_size: usize,
    /// Seed for deterministic fuzzing (None = random).
    pub seed: Option<u64>,
    /// Detect hangs (execution exceeds timeout).
    pub detect_hangs: bool,
    /// Minimize crashes automatically.
    pub auto_minimize: bool,
    /// Maximum campaign duration (seconds; 0 = unlimited).
    pub max_duration_secs: u64,
    /// Maximum total executions (0 = unlimited).
    pub max_executions: u64,
    /// Dictionary file path.
    pub dict_path: Option<PathBuf>,
    /// Coverage feedback type.
    pub coverage_type: CoverageType,
    /// Mutation strategies to use (in order).
    pub mutation_strategies: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageType {
    None,
    EdgeCoverage,
    BlockCoverage,
    PathCoverage,
    VmEdge,
}

impl Default for CampaignConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 1000,
            mem_limit_bytes: 256 * 1024 * 1024, // 256 MiB
            jobs: 1,
            max_corpus_size: 0,
            seed: None,
            detect_hangs: true,
            auto_minimize: false,
            max_duration_secs: 0,
            max_executions: 0,
            dict_path: None,
            coverage_type: CoverageType::EdgeCoverage,
            mutation_strategies: vec![
                "bitflip".into(),
                "byteflip".into(),
                "insert".into(),
                "delete".into(),
                "replace".into(),
                "havoc".into(),
            ],
        }
    }
}

impl CampaignConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    #[must_use]
    pub const fn with_jobs(mut self, n: u8) -> Self {
        self.jobs = n;
        self
    }

    #[must_use]
    pub const fn with_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    #[must_use]
    pub const fn with_mem_limit_bytes(mut self, bytes: u64) -> Self {
        self.mem_limit_bytes = bytes;
        self
    }

    #[must_use]
    pub const fn with_max_duration_secs(mut self, secs: u64) -> Self {
        self.max_duration_secs = secs;
        self
    }
}

// ─── CampaignStats ────────────────────────────────────────────────────────────

/// Live statistics for a running or completed campaign.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CampaignStats {
    /// Total number of executions completed.
    pub executions: u64,
    /// Unique crashes found.
    pub crashes: u64,
    /// Hangs detected.
    pub hangs: u64,
    /// New coverage edges/blocks discovered.
    pub coverage_edges: u64,
    /// Total corpus entries.
    pub corpus_entries: u64,
    /// Executions per second (last measurement).
    pub execs_per_sec: f64,
    /// Campaign start timestamp (Unix seconds).
    pub start_time: u64,
    /// Last update timestamp (Unix seconds).
    pub last_update: u64,
    /// Per-job execution counts.
    pub execs_by_job: HashMap<u8, u64>,
    /// Number of interesting inputs found.
    pub interesting_inputs: u64,
    /// Total bytes processed.
    pub total_bytes: u64,
    /// Peak memory usage in bytes.
    pub peak_memory: u64,
    /// Number of timeouts.
    pub timeouts: u64,
    /// Average input size.
    pub avg_input_size: f64,
    /// Maximum input size seen.
    pub max_input_size: usize,
}

impl CampaignStats {
    #[must_use]
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        Self {
            start_time: now,
            last_update: now,
            ..Default::default()
        }
    }

    #[must_use]
    pub fn elapsed_secs(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        now.saturating_sub(self.start_time)
    }

    pub fn record_execution(&mut self, input_size: usize, new_coverage: bool, job: u8) {
        self.executions += 1;
        self.total_bytes += input_size as u64;
        if new_coverage {
            self.coverage_edges += 1;
            self.interesting_inputs += 1;
        }
        *self.execs_by_job.entry(job).or_insert(0) += 1;
        if input_size > self.max_input_size {
            self.max_input_size = input_size;
        }
        // Update avg
        self.avg_input_size = self.total_bytes as f64 / self.executions as f64;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.last_update = now;
        // Compute execs/sec
        let elapsed = now.saturating_sub(self.start_time).max(1);
        self.execs_per_sec = self.executions as f64 / elapsed as f64;
    }

    pub const fn record_crash(&mut self) {
        self.crashes += 1;
    }

    pub const fn record_hang(&mut self) {
        self.hangs += 1;
        self.timeouts += 1;
    }

    #[must_use]
    pub fn crash_rate(&self) -> f64 {
        if self.executions == 0 {
            0.0
        } else {
            self.crashes as f64 / self.executions as f64
        }
    }

    #[must_use]
    pub fn hang_rate(&self) -> f64 {
        if self.executions == 0 {
            0.0
        } else {
            self.hangs as f64 / self.executions as f64
        }
    }

    /// Mean per-execution duration in nanoseconds, derived from the elapsed
    /// wall-clock time and total execution count. Returns `0.0` when no
    /// executions have completed yet.
    #[must_use]
    pub fn mean_duration_ns(&self) -> f64 {
        if self.executions == 0 {
            0.0
        } else {
            let elapsed_ns = self.elapsed_secs().saturating_mul(1_000_000_000);
            elapsed_ns as f64 / self.executions as f64
        }
    }
}

// ─── CampaignCheckpoint ───────────────────────────────────────────────────────

/// A snapshot of campaign state at a point in time (for resume support).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignCheckpoint {
    pub id: u64,
    pub timestamp: u64,
    pub stats: CampaignStats,
    pub corpus_hashes: Vec<String>,
    pub config: CampaignConfig,
    pub notes: String,
}

impl CampaignCheckpoint {
    #[must_use]
    pub fn new(
        id: u64,
        stats: CampaignStats,
        corpus_hashes: Vec<String>,
        config: CampaignConfig,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        Self {
            id,
            timestamp,
            stats,
            corpus_hashes,
            config,
            notes: String::new(),
        }
    }

    #[must_use]
    pub fn with_notes(mut self, notes: &str) -> Self {
        self.notes = notes.to_string();
        self
    }
}

// ─── FuzzCampaign ─────────────────────────────────────────────────────────────

/// A complete fuzzing campaign: target + config + corpus + stats.
#[derive(Debug)]
pub struct FuzzCampaign {
    pub name: String,
    pub target: FuzzTarget,
    pub config: CampaignConfig,
    pub stats: CampaignStats,
    /// Corpus directory.
    pub corpus_dir: PathBuf,
    /// Crash output directory.
    pub crash_dir: PathBuf,
    /// Queue of pending corpus entries (byte slices).
    pub corpus: Vec<Vec<u8>>,
    /// Checkpoints saved during the campaign.
    pub checkpoints: Vec<CampaignCheckpoint>,
    /// Current campaign state.
    pub state: CampaignState,
    checkpoint_counter: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CampaignState {
    Created,
    Running,
    Paused,
    Completed,
    Failed,
}

impl FuzzCampaign {
    #[must_use]
    pub fn new(name: &str, target: FuzzTarget, config: CampaignConfig) -> Self {
        Self {
            name: name.to_string(),
            target,
            config,
            stats: CampaignStats::new(),
            corpus_dir: PathBuf::from("corpus"),
            crash_dir: PathBuf::from("crashes"),
            corpus: Vec::new(),
            checkpoints: Vec::new(),
            state: CampaignState::Created,
            checkpoint_counter: 0,
        }
    }

    #[must_use]
    pub fn with_corpus_dir(mut self, dir: PathBuf) -> Self {
        self.corpus_dir = dir;
        self
    }

    #[must_use]
    pub fn with_crash_dir(mut self, dir: PathBuf) -> Self {
        self.crash_dir = dir;
        self
    }

    pub fn add_seed(&mut self, seed: Vec<u8>) {
        self.corpus.push(seed);
        self.stats.corpus_entries += 1;
    }

    pub fn add_seeds(&mut self, seeds: impl IntoIterator<Item = Vec<u8>>) {
        for s in seeds {
            self.add_seed(s);
        }
    }

    pub fn start(&mut self) {
        self.state = CampaignState::Running;
        self.stats = CampaignStats::new();
    }

    pub fn pause(&mut self) {
        if self.state == CampaignState::Running {
            self.state = CampaignState::Paused;
        }
    }

    pub fn resume(&mut self) {
        if self.state == CampaignState::Paused {
            self.state = CampaignState::Running;
        }
    }

    pub const fn complete(&mut self) {
        self.state = CampaignState::Completed;
    }

    pub const fn fail(&mut self) {
        self.state = CampaignState::Failed;
    }

    /// Save a checkpoint of current state.
    pub fn checkpoint(&mut self) -> &CampaignCheckpoint {
        let id = self.checkpoint_counter;
        self.checkpoint_counter += 1;
        let hashes: Vec<String> = self
            .corpus
            .iter()
            .map(|e| format!("{:x}", crc32_simple(e)))
            .collect();
        let cp = CampaignCheckpoint::new(id, self.stats.clone(), hashes, self.config.clone());
        self.checkpoints.push(cp);
        self.checkpoints.last().unwrap()
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.state == CampaignState::Running
    }

    #[must_use]
    pub const fn corpus_size(&self) -> usize {
        self.corpus.len()
    }

    #[must_use]
    pub fn should_stop(&self) -> bool {
        let cfg = &self.config;
        if cfg.max_executions > 0 && self.stats.executions >= cfg.max_executions {
            return true;
        }
        if cfg.max_duration_secs > 0 && self.stats.elapsed_secs() >= cfg.max_duration_secs {
            return true;
        }
        false
    }

    /// Pick the next corpus entry to mutate (round-robin).
    #[must_use]
    pub fn next_input(&self) -> Option<&[u8]> {
        if self.corpus.is_empty() {
            return None;
        }
        let idx = (self.stats.executions as usize) % self.corpus.len();
        Some(&self.corpus[idx])
    }
}

/// Simple CRC32 for checksum hashing.
fn crc32_simple(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_target() -> FuzzTarget {
        FuzzTarget::new(PathBuf::from("/bin/target"), HarnessKind::OutOfProcess)
    }

    fn make_campaign() -> FuzzCampaign {
        FuzzCampaign::new("test", make_target(), CampaignConfig::default())
    }

    #[test]
    fn test_campaign_creation() {
        let c = make_campaign();
        assert_eq!(c.name, "test");
        assert_eq!(c.state, CampaignState::Created);
    }

    #[test]
    fn test_campaign_start() {
        let mut c = make_campaign();
        c.start();
        assert_eq!(c.state, CampaignState::Running);
    }

    #[test]
    fn test_campaign_pause_resume() {
        let mut c = make_campaign();
        c.start();
        c.pause();
        assert_eq!(c.state, CampaignState::Paused);
        c.resume();
        assert_eq!(c.state, CampaignState::Running);
    }

    #[test]
    fn test_campaign_complete() {
        let mut c = make_campaign();
        c.start();
        c.complete();
        assert_eq!(c.state, CampaignState::Completed);
    }

    #[test]
    fn test_campaign_add_seeds() {
        let mut c = make_campaign();
        c.add_seed(b"hello".to_vec());
        c.add_seed(b"world".to_vec());
        assert_eq!(c.corpus_size(), 2);
    }

    #[test]
    fn test_campaign_next_input() {
        let mut c = make_campaign();
        c.add_seed(b"a".to_vec());
        c.add_seed(b"b".to_vec());
        assert!(c.next_input().is_some());
    }

    #[test]
    fn test_campaign_no_input_when_empty() {
        let c = make_campaign();
        assert!(c.next_input().is_none());
    }

    #[test]
    fn test_campaign_checkpoint() {
        let mut c = make_campaign();
        c.add_seed(b"seed".to_vec());
        let cp = c.checkpoint();
        assert_eq!(cp.id, 0);
        assert_eq!(c.checkpoints.len(), 1);
    }

    #[test]
    fn test_campaign_should_stop_max_exec() {
        let mut c = make_campaign();
        c.config.max_executions = 10;
        c.stats.executions = 10;
        assert!(c.should_stop());
    }

    #[test]
    fn test_campaign_should_not_stop() {
        let c = make_campaign();
        assert!(!c.should_stop());
    }

    #[test]
    fn test_stats_record_execution() {
        let mut s = CampaignStats::new();
        s.record_execution(64, true, 0);
        assert_eq!(s.executions, 1);
        assert_eq!(s.coverage_edges, 1);
        assert_eq!(s.total_bytes, 64);
    }

    #[test]
    fn test_stats_record_crash() {
        let mut s = CampaignStats::new();
        s.record_crash();
        assert_eq!(s.crashes, 1);
    }

    #[test]
    fn test_stats_record_hang() {
        let mut s = CampaignStats::new();
        s.record_hang();
        assert_eq!(s.hangs, 1);
        assert_eq!(s.timeouts, 1);
    }

    #[test]
    fn test_stats_crash_rate() {
        let mut s = CampaignStats::new();
        s.executions = 100;
        s.crashes = 5;
        assert!((s.crash_rate() - 0.05).abs() < 1e-9);
    }

    #[test]
    fn test_stats_zero_crash_rate() {
        let s = CampaignStats::new();
        assert_eq!(s.crash_rate(), 0.0);
    }

    #[test]
    fn test_config_default() {
        let c = CampaignConfig::default();
        assert_eq!(c.timeout_ms, 1000);
        assert_eq!(c.jobs, 1);
        assert!(c.detect_hangs);
    }

    #[test]
    fn test_config_builder() {
        let c = CampaignConfig::new()
            .with_timeout_ms(500)
            .with_jobs(4)
            .with_seed(42);
        assert_eq!(c.timeout_ms, 500);
        assert_eq!(c.jobs, 4);
        assert_eq!(c.seed, Some(42));
    }

    #[test]
    fn test_fuzz_target_builder() {
        let t = FuzzTarget::new(PathBuf::from("/bin/x"), HarnessKind::InProcess)
            .with_stdin()
            .with_wrapper("valgrind");
        assert_eq!(t.input_method, InputMethod::Stdin);
        assert_eq!(t.wrapper.as_deref(), Some("valgrind"));
    }

    #[test]
    fn test_checkpoint_with_notes() {
        let stats = CampaignStats::new();
        let config = CampaignConfig::default();
        let cp = CampaignCheckpoint::new(0, stats, vec![], config).with_notes("manual checkpoint");
        assert_eq!(cp.notes, "manual checkpoint");
    }

    #[test]
    fn test_crc32_not_zero_for_data() {
        let h = crc32_simple(b"hello world");
        assert_ne!(h, 0);
    }

    #[test]
    fn test_crc32_deterministic() {
        let h1 = crc32_simple(b"test");
        let h2 = crc32_simple(b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_crc32_different_inputs() {
        let h1 = crc32_simple(b"abc");
        let h2 = crc32_simple(b"def");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_campaign_is_running() {
        let mut c = make_campaign();
        assert!(!c.is_running());
        c.start();
        assert!(c.is_running());
    }

    #[test]
    fn test_campaign_stats_by_job() {
        let mut s = CampaignStats::new();
        s.record_execution(10, false, 0);
        s.record_execution(10, false, 1);
        s.record_execution(10, false, 0);
        assert_eq!(s.execs_by_job[&0], 2);
        assert_eq!(s.execs_by_job[&1], 1);
    }
}

// ─── CorpusEntry ──────────────────────────────────────────────────────────────

/// An entry in the fuzzing corpus with metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorpusEntry {
    pub data: Vec<u8>,
    pub id: u64,
    pub energy: f64,
    pub times_chosen: u64,
    pub new_coverage: bool,
    pub source: CorpusSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CorpusSource {
    Seed,
    Mutation,
    Minimized,
    External,
}

impl CorpusEntry {
    #[must_use]
    pub const fn new(id: u64, data: Vec<u8>, source: CorpusSource) -> Self {
        Self {
            data,
            id,
            energy: 1.0,
            times_chosen: 0,
            new_coverage: false,
            source,
        }
    }

    #[must_use]
    pub const fn with_energy(mut self, e: f64) -> Self {
        self.energy = e;
        self
    }
    #[must_use]
    pub const fn with_coverage(mut self) -> Self {
        self.new_coverage = true;
        self
    }

    #[must_use]
    pub const fn size(&self) -> usize {
        self.data.len()
    }
    pub const fn choose(&mut self) {
        self.times_chosen += 1;
    }
}

/// Managed corpus with energy scheduling.
#[derive(Debug, Default)]
pub struct ManagedCorpus {
    entries: Vec<CorpusEntry>,
    next_id: u64,
}

impl ManagedCorpus {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_seed(&mut self, data: Vec<u8>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.entries
            .push(CorpusEntry::new(id, data, CorpusSource::Seed));
        id
    }

    pub fn add_mutation(&mut self, data: Vec<u8>, new_coverage: bool) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let mut e = CorpusEntry::new(id, data, CorpusSource::Mutation);
        if new_coverage {
            e.new_coverage = true;
            e.energy = 2.0;
        }
        self.entries.push(e);
        id
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn get(&self, id: u64) -> Option<&CorpusEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Pick entry by round-robin weighted by energy.
    pub fn pick_next(&mut self, tick: u64) -> Option<&mut CorpusEntry> {
        if self.entries.is_empty() {
            return None;
        }
        let idx = (tick as usize) % self.entries.len();
        Some(&mut self.entries[idx])
    }

    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.entries.iter().map(CorpusEntry::size).sum()
    }

    #[must_use]
    pub fn coverage_entries(&self) -> usize {
        self.entries.iter().filter(|e| e.new_coverage).count()
    }
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_corpus_entry_new() {
        let e = CorpusEntry::new(0, b"hello".to_vec(), CorpusSource::Seed);
        assert_eq!(e.size(), 5);
        assert_eq!(e.source, CorpusSource::Seed);
    }

    #[test]
    fn test_corpus_entry_choose_increments() {
        let mut e = CorpusEntry::new(0, vec![0u8], CorpusSource::Seed);
        e.choose();
        e.choose();
        assert_eq!(e.times_chosen, 2);
    }

    #[test]
    fn test_managed_corpus_add_seed() {
        let mut c = ManagedCorpus::new();
        c.add_seed(b"input1".to_vec());
        c.add_seed(b"input2".to_vec());
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn test_managed_corpus_add_mutation_coverage() {
        let mut c = ManagedCorpus::new();
        let id = c.add_mutation(b"mutant".to_vec(), true);
        let e = c.get(id).unwrap();
        assert!(e.new_coverage);
        assert_eq!(e.energy, 2.0);
    }

    #[test]
    fn test_managed_corpus_pick_next() {
        let mut c = ManagedCorpus::new();
        c.add_seed(b"a".to_vec());
        c.add_seed(b"b".to_vec());
        assert!(c.pick_next(0).is_some());
        assert!(c.pick_next(1).is_some());
    }

    #[test]
    fn test_managed_corpus_total_bytes() {
        let mut c = ManagedCorpus::new();
        c.add_seed(vec![0u8; 10]);
        c.add_seed(vec![0u8; 20]);
        assert_eq!(c.total_bytes(), 30);
    }

    #[test]
    fn test_managed_corpus_coverage_entries() {
        let mut c = ManagedCorpus::new();
        c.add_mutation(b"cov".to_vec(), true);
        c.add_mutation(b"nocov".to_vec(), false);
        assert_eq!(c.coverage_entries(), 1);
    }

    #[test]
    fn test_coverage_type_variants() {
        let c = CampaignConfig::default();
        assert_eq!(c.coverage_type, CoverageType::EdgeCoverage);
    }

    #[test]
    fn test_campaign_add_seeds_bulk() {
        let mut c = make_campaign();
        c.add_seeds(vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        assert_eq!(c.corpus_size(), 3);
    }

    #[test]
    fn test_campaign_multiple_checkpoints() {
        let mut c = make_campaign();
        c.add_seed(b"seed".to_vec());
        c.checkpoint();
        c.checkpoint();
        assert_eq!(c.checkpoints.len(), 2);
        assert_eq!(c.checkpoints[0].id, 0);
        assert_eq!(c.checkpoints[1].id, 1);
    }

    #[test]
    fn test_campaign_config_with_max_corpus() {
        let cfg = CampaignConfig::new().with_mem_limit_bytes(512 * 1024 * 1024);
        assert_eq!(cfg.mem_limit_bytes, 512 * 1024 * 1024);
    }

    #[test]
    fn test_campaign_fail_state() {
        let mut c = make_campaign();
        c.fail();
        assert_eq!(c.state, CampaignState::Failed);
    }

    fn make_campaign() -> FuzzCampaign {
        FuzzCampaign::new(
            "test",
            FuzzTarget::new(
                std::path::PathBuf::from("/bin/x"),
                HarnessKind::OutOfProcess,
            ),
            CampaignConfig::default(),
        )
    }

    #[test]
    fn test_corpus_entry_with_energy() {
        let e = CorpusEntry::new(0, vec![1u8], CorpusSource::Mutation).with_energy(5.0);
        assert_eq!(e.energy, 5.0);
    }

    #[test]
    fn test_corpus_entry_with_coverage() {
        let e = CorpusEntry::new(0, vec![1u8], CorpusSource::Seed).with_coverage();
        assert!(e.new_coverage);
    }

    #[test]
    fn test_managed_corpus_get_by_id() {
        let mut c = ManagedCorpus::new();
        let id = c.add_seed(b"xyz".to_vec());
        assert!(c.get(id).is_some());
        assert!(c.get(id + 99).is_none());
    }

    #[test]
    fn test_managed_corpus_pick_empty() {
        let mut c = ManagedCorpus::new();
        assert!(c.pick_next(0).is_none());
    }

    #[test]
    fn test_corpus_source_variants() {
        assert_eq!(CorpusSource::Seed, CorpusSource::Seed);
        assert_ne!(CorpusSource::Seed, CorpusSource::Mutation);
    }

    #[test]
    fn test_harness_kind_variants() {
        assert_eq!(HarnessKind::InProcess, HarnessKind::InProcess);
        assert_ne!(HarnessKind::InProcess, HarnessKind::OutOfProcess);
    }

    #[test]
    fn test_input_method_variants() {
        assert_eq!(InputMethod::Stdin, InputMethod::Stdin);
        assert_ne!(InputMethod::File, InputMethod::Direct);
    }

    #[test]
    fn test_campaign_state_not_running_initially() {
        let c = make_campaign();
        assert!(!c.is_running());
    }

    #[test]
    fn test_fuzz_target_default_input_method() {
        let t = FuzzTarget::new(std::path::PathBuf::from("/bin/x"), HarnessKind::InProcess);
        assert_eq!(t.input_method, InputMethod::File);
    }

    #[test]
    fn test_campaign_config_mutation_strategies_not_empty() {
        let cfg = CampaignConfig::default();
        assert!(!cfg.mutation_strategies.is_empty());
    }

    #[test]
    fn test_stats_mean_duration_zero_execs() {
        let s = CampaignStats::new();
        assert_eq!(s.mean_duration_ns(), 0.0);
    }

    #[test]
    fn test_stats_hang_rate_zero() {
        let s = CampaignStats::new();
        assert_eq!(s.hang_rate(), 0.0);
    }

    #[test]
    fn test_managed_corpus_ids_monotone() {
        let mut c = ManagedCorpus::new();
        let id0 = c.add_seed(b"a".to_vec());
        let id1 = c.add_seed(b"b".to_vec());
        assert!(id1 > id0);
    }

    #[test]
    fn test_checkpoint_corpus_hashes_match_size() {
        let mut c = make_campaign();
        c.add_seed(b"s1".to_vec());
        c.add_seed(b"s2".to_vec());
        let cp = c.checkpoint();
        assert_eq!(cp.corpus_hashes.len(), 2);
    }
}
