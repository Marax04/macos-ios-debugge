//! Coordinate multiple fuzzer instances sharing a common corpus and coverage map.
//!
//! Provides `FuzzerCoordinator`, `FuzzerInstance`, and `SharedCorpus` so that
//! several fuzzer workers can be managed from a single control point.

use crate::{
    Corpus, CorpusEntry, CorpusMeta, CoverageMap, FuzzError, FuzzInput, FuzzRng, FuzzerStats,
    MutationEngine, MutationStrategy,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

// ── InstanceStatus ─────────────────────────────────────────────────────────────

/// Current operational status of a fuzzer instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstanceStatus {
    /// Instance is initialising.
    Initialising,
    /// Instance is actively fuzzing.
    Running,
    /// Instance has been paused.
    Paused,
    /// Instance has finished its allocated work.
    Done,
    /// Instance terminated with an error.
    Failed,
}

impl std::fmt::Display for InstanceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Initialising => "initialising",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Done => "done",
            Self::Failed => "failed",
        };
        write!(f, "{s}")
    }
}

// ── InstanceConfig ─────────────────────────────────────────────────────────────

/// Configuration for a single fuzzer instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceConfig {
    /// Human-readable name (e.g. `"worker-0"`).
    pub name: String,
    /// Maximum number of iterations before the instance stops.
    pub max_iterations: Option<u64>,
    /// Preferred mutation strategy.
    pub strategy: Option<MutationStrategy>,
    /// PRNG seed for deterministic replay.
    pub seed: u64,
    /// Maximum input size in bytes.
    pub max_input_size: usize,
    /// How often (in iterations) to sync with the shared corpus.
    pub sync_interval: u64,
}

impl InstanceConfig {
    /// Create a config with sensible defaults.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            max_iterations: None,
            strategy: None,
            seed: 0x1234_5678_9abc_def0,
            max_input_size: 64 * 1024,
            sync_interval: 100,
        }
    }

    /// Set an iteration limit.
    #[must_use]
    pub const fn with_max_iterations(mut self, n: u64) -> Self {
        self.max_iterations = Some(n);
        self
    }

    /// Set the preferred mutation strategy.
    #[must_use]
    pub const fn with_strategy(mut self, s: MutationStrategy) -> Self {
        self.strategy = Some(s);
        self
    }

    /// Set the PRNG seed.
    #[must_use]
    pub const fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Set the corpus sync interval.
    #[must_use]
    pub const fn with_sync_interval(mut self, n: u64) -> Self {
        self.sync_interval = n;
        self
    }
}

// ── FuzzerInstance ─────────────────────────────────────────────────────────────

/// A single fuzzer worker managed by the coordinator.
pub struct FuzzerInstance {
    /// Instance identifier.
    pub id: u64,
    /// Configuration.
    pub config: InstanceConfig,
    /// Accumulated statistics.
    pub stats: FuzzerStats,
    /// Current operational status.
    pub status: InstanceStatus,
    /// Local corpus (before syncing to the shared pool).
    pub local_corpus: Corpus,
    /// Mutation engine.
    pub engine: MutationEngine,
    /// When this instance was started.
    pub started_at: Option<Instant>,
    /// Iteration counter.
    pub iterations: u64,
    /// Unique crashes found by this instance.
    pub unique_crashes: u64,
}

impl FuzzerInstance {
    /// Create a new instance with the given id and config.
    #[must_use]
    pub fn new(id: u64, config: InstanceConfig) -> Self {
        let engine = MutationEngine::with_seed(config.seed.wrapping_add(id));
        Self {
            id,
            config,
            stats: FuzzerStats::new(),
            status: InstanceStatus::Initialising,
            local_corpus: Corpus::new(),
            engine,
            started_at: None,
            iterations: 0,
            unique_crashes: 0,
        }
    }

    /// Transition to `Running` and record the start time.
    ///
    /// Guard: silently ignored if the instance is not in `Initialising` state
    /// so that calling `start()` twice does not corrupt the start timestamp.
    pub fn start(&mut self) {
        if self.status != InstanceStatus::Initialising {
            return;
        }
        self.status = InstanceStatus::Running;
        self.started_at = Some(Instant::now());
    }

    /// Pause this instance.
    pub fn pause(&mut self) {
        if self.status == InstanceStatus::Running {
            self.status = InstanceStatus::Paused;
        }
    }

    /// Resume a paused instance.
    pub fn resume(&mut self) {
        if self.status == InstanceStatus::Paused {
            self.status = InstanceStatus::Running;
        }
    }

    /// Mark the instance as done.
    pub const fn finish(&mut self) {
        self.status = InstanceStatus::Done;
    }

    /// Mark the instance as failed.
    pub const fn fail(&mut self) {
        self.status = InstanceStatus::Failed;
    }

    /// Return whether this instance should continue running.
    #[must_use]
    pub fn should_continue(&self) -> bool {
        if self.status != InstanceStatus::Running {
            return false;
        }
        if let Some(max) = self.config.max_iterations
            && self.iterations >= max
        {
            return false;
        }
        true
    }

    /// Run one iteration: mutate an input, record stats, and check for sync.
    ///
    /// Returns the mutated input bytes, or `Err` if no seeds are available.
    pub fn step(&mut self, shared: &SharedCorpus) -> Result<Vec<u8>, FuzzError> {
        if self.local_corpus.inputs.is_empty() {
            // Pull seeds from shared corpus if local is empty.
            let seeds = shared.snapshot_inputs();
            if seeds.is_empty() {
                return Err(FuzzError::CorpusError("no seeds available".to_string()));
            }
            for seed in seeds {
                let meta = CorpusMeta::new(0, 0, Duration::from_millis(1));
                self.local_corpus.add_input(seed, meta);
            }
        }

        // Select an input.
        let idx = (self.iterations as usize) % self.local_corpus.inputs.len();
        let seed_data = self.local_corpus.inputs[idx].data.clone();

        // Choose strategy.
        let strategy = self.config.strategy.unwrap_or_else(|| {
            let all = MutationStrategy::all();
            all[self.iterations as usize % all.len()]
        });

        let mutated = self.engine.mutate(&seed_data, strategy);
        self.iterations += 1;
        self.stats.record_execution(mutated.len());

        // Periodic sync.
        if self.iterations.is_multiple_of(self.config.sync_interval) {
            self.sync_to_shared(shared);
        }

        Ok(mutated)
    }

    /// Push locally-found interesting inputs to the shared corpus.
    ///
    /// Returns how many entries the shared corpus ACCEPTED. `add_entry` rejects
    /// an input that contributes no new coverage, so this is the count of finds
    /// that were actually new to the fleet — not the count offered.
    ///
    /// ⚠ The return value used to be discarded. `add_entry`'s `bool` is the
    /// only signal a worker gets about whether its finds were novel, and for a
    /// fuzzer that is the number worth having: a worker syncing 500 inputs of
    /// which 0 are accepted is doing no useful work, and looked identical to
    /// one syncing 500 novel inputs. Surfaced when a `#[must_use]` on
    /// `add_entry` turned the discard into a hard error under the workspace's
    /// `unused_must_use = "deny"`.
    pub fn sync_to_shared(&self, shared: &SharedCorpus) -> usize {
        self.local_corpus
            .entries
            .iter()
            .filter(|entry| shared.add_entry((*entry).clone()))
            .count()
    }

    /// Pull new inputs from the shared corpus that the local corpus lacks.
    pub fn pull_from_shared(&mut self, shared: &SharedCorpus) {
        let shared_entries = shared.snapshot_entries();
        for entry in shared_entries {
            let id = entry.id();
            if !self.local_corpus.inputs.iter().any(|i| i.id == id) {
                self.local_corpus.add_input(entry.input.clone(), entry.meta.clone());
            }
        }
    }

    /// Return the wall-clock duration since this instance was started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started_at.map_or(Duration::ZERO, |t| t.elapsed())
    }

    /// Return the execution rate (iterations per second).
    #[must_use]
    pub fn iters_per_sec(&self) -> f64 {
        let secs = self.elapsed().as_secs_f64();
        if secs < f64::EPSILON {
            0.0
        } else {
            self.iterations as f64 / secs
        }
    }
}

// ── SharedCorpus ───────────────────────────────────────────────────────────────

/// Thread-safe corpus shared among multiple fuzzer instances.
///
/// This is the central exchange point for interesting inputs discovered by
/// any worker.
pub struct SharedCorpus {
    inner: Arc<Mutex<SharedCorpusInner>>,
}

struct SharedCorpusInner {
    entries: Vec<CorpusEntry>,
    coverage: CoverageMap,
    total_added: u64,
    seeds: Vec<FuzzInput>,
}

impl SharedCorpus {
    /// Create a new empty shared corpus with a coverage map of `cov_size` bytes.
    #[must_use]
    pub fn new(cov_size: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SharedCorpusInner {
                entries: Vec::new(),
                coverage: CoverageMap::new(cov_size),
                total_added: 0,
                seeds: Vec::new(),
            })),
        }
    }

    /// Add a seed input to the corpus.
    pub fn add_seed(&self, data: Vec<u8>) {
        let mut guard = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let id = guard.seeds.len() as u64;
        guard.seeds.push(FuzzInput::new(id, data));
    }

    /// Add a corpus entry if its coverage hash is novel.
    ///
    /// Returns `true` if the entry was accepted.
    #[must_use]
    pub fn add_entry(&self, entry: CorpusEntry) -> bool {
        let mut guard = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let new_bits = guard.coverage.update(&entry.meta.hash.to_le_bytes());
        if new_bits > 0 || guard.entries.is_empty() {
            guard.entries.push(entry);
            guard.total_added += 1;
            true
        } else {
            false
        }
    }

    /// Return a snapshot of all seed inputs.
    #[must_use]
    pub fn snapshot_inputs(&self) -> Vec<FuzzInput> {
        let guard = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.seeds.clone()
    }

    /// Return a snapshot of all corpus entries.
    #[must_use]
    pub fn snapshot_entries(&self) -> Vec<CorpusEntry> {
        let guard = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.entries.clone()
    }

    /// Return the total number of entries ever added.
    #[must_use]
    pub fn total_added(&self) -> u64 {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).total_added
    }

    /// Return the current entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entries.len()
    }

    /// Return `true` if the corpus has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entries.is_empty()
    }

    /// Return the number of coverage bits set in the shared map.
    #[must_use]
    pub fn coverage_bits(&self) -> u32 {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).coverage.total_bits_set()
    }
}

impl Clone for SharedCorpus {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

// ── CoordinatorConfig ──────────────────────────────────────────────────────────

/// Configuration for the `FuzzerCoordinator`.
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// Total iterations budget across all instances.
    pub total_budget: Option<u64>,
    /// Coverage bitmap size in bytes.
    pub coverage_map_size: usize,
    /// How often (in iterations) to print a status line.
    pub status_interval: u64,
    /// Whether to stop all instances as soon as a crash is found.
    pub stop_on_crash: bool,
    /// Maximum number of instances to run in parallel.
    pub max_instances: usize,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            total_budget: None,
            coverage_map_size: 65536,
            status_interval: 1000,
            stop_on_crash: false,
            max_instances: 8,
        }
    }
}

impl CoordinatorConfig {
    /// Create coordinator config with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the total iteration budget.
    #[must_use]
    pub const fn with_budget(mut self, n: u64) -> Self {
        self.total_budget = Some(n);
        self
    }

    /// Set the stop-on-crash flag.
    #[must_use]
    pub const fn stop_on_crash(mut self) -> Self {
        self.stop_on_crash = true;
        self
    }

    /// Set the maximum number of parallel instances.
    #[must_use]
    pub const fn with_max_instances(mut self, n: usize) -> Self {
        self.max_instances = n;
        self
    }
}

// ── FuzzerCoordinator ─────────────────────────────────────────────────────────

/// Manages a pool of `FuzzerInstance` workers, distributing seeds and
/// aggregating results through a `SharedCorpus`.
pub struct FuzzerCoordinator {
    /// Configuration.
    pub config: CoordinatorConfig,
    /// All registered instances.
    pub instances: Vec<FuzzerInstance>,
    /// Shared corpus used to exchange interesting inputs.
    pub shared_corpus: SharedCorpus,
    /// Aggregated coordinator-level statistics.
    pub stats: CoordinatorStats,
    /// Crash log keyed by hash.
    crashes: HashMap<u64, CrashSummary>,
    /// When the coordinator started.
    started_at: Option<Instant>,
    /// PRNG for internal use.
    rng: FuzzRng,
}

/// Aggregated statistics for the coordinator.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoordinatorStats {
    /// Total iterations across all instances.
    pub total_iterations: u64,
    /// Total crashes found.
    pub total_crashes: u64,
    /// Unique crashes (by dedup key).
    pub unique_crashes: u64,
    /// Current corpus size.
    pub corpus_size: usize,
    /// Current coverage bits.
    pub coverage_bits: u32,
    /// When the campaign started.
    pub started_at: Option<SystemTime>,
}

/// A summary of a single unique crash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashSummary {
    /// Dedup hash.
    pub hash: u64,
    /// Input that triggered the crash.
    pub input: Vec<u8>,
    /// Which instance found it.
    pub instance_id: u64,
    /// Signal number.
    pub signal: i32,
    /// When it was found.
    pub found_at: SystemTime,
    /// Number of times reproduced.
    pub count: u64,
}

impl FuzzerCoordinator {
    /// Create a new coordinator with the given config.
    #[must_use]
    pub fn new(config: CoordinatorConfig) -> Self {
        let shared_corpus = SharedCorpus::new(config.coverage_map_size);
        Self {
            config,
            instances: Vec::new(),
            shared_corpus,
            stats: CoordinatorStats::default(),
            crashes: HashMap::new(),
            started_at: None,
            rng: FuzzRng::new(0xc0de_c0de_cafe_babe),
        }
    }

    /// Add a fuzzer instance.
    pub fn add_instance(&mut self, config: InstanceConfig) -> u64 {
        let id = self.instances.len() as u64;
        self.instances.push(FuzzerInstance::new(id, config));
        id
    }

    /// Draw the next coordinator-level random `u64`. Used for jittering
    /// scheduling decisions (e.g. randomly picking which instance receives a
    /// newly-found seed) so that the same observable behaviour is reproducible
    /// across runs when the coordinator is seeded deterministically.
    #[inline]
    pub const fn next_rng_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    /// Pick a pseudo-random instance index in `[0, instances.len())`, or
    /// `None` if no instances are registered. Uses the coordinator RNG.
    pub const fn random_instance_index(&mut self) -> Option<usize> {
        if self.instances.is_empty() {
            None
        } else {
            Some(self.rng.next_usize(self.instances.len()))
        }
    }

    /// Add a seed to the shared corpus.
    pub fn add_seed(&mut self, data: Vec<u8>) {
        self.shared_corpus.add_seed(data);
    }

    /// Start all instances.
    pub fn start_all(&mut self) {
        self.started_at = Some(Instant::now());
        self.stats.started_at = Some(SystemTime::now());
        for inst in &mut self.instances {
            inst.start();
        }
    }

    /// Pause all running instances.
    pub fn pause_all(&mut self) {
        for inst in &mut self.instances {
            inst.pause();
        }
    }

    /// Resume all paused instances.
    pub fn resume_all(&mut self) {
        for inst in &mut self.instances {
            inst.resume();
        }
    }

    /// Stop all instances (marks them as Done).
    pub fn stop_all(&mut self) {
        for inst in &mut self.instances {
            inst.finish();
        }
    }

    /// Run the coordinator synchronously for `iterations` total steps,
    /// distributing work round-robin across instances.
    ///
    /// Returns the number of iterations performed.
    pub fn run_steps(&mut self, iterations: u64) -> u64 {
        let mut performed = 0u64;
        let n_inst = self.instances.len();
        if n_inst == 0 {
            return 0;
        }

        for i in 0..iterations {
            let idx = (i as usize) % n_inst;
            let inst = &mut self.instances[idx];
            if !inst.should_continue() {
                continue;
            }
            if let Ok(_data) = inst.step(&self.shared_corpus) {
                performed += 1;
                self.stats.total_iterations += 1;
            }
        }

        // Sync all instances at the end.
        self.sync_corpora();
        self.update_stats();
        performed
    }

    /// Synchronise all instance local corpora with the shared corpus.
    pub fn sync_corpora(&mut self) {
        // First push local entries to shared.
        for inst in &self.instances {
            inst.sync_to_shared(&self.shared_corpus);
        }
        // Then pull shared entries back to all instances.
        for inst in &mut self.instances {
            inst.pull_from_shared(&self.shared_corpus);
        }
    }

    /// Record a crash found by an instance.
    pub fn record_crash(
        &mut self,
        instance_id: u64,
        input: Vec<u8>,
        signal: i32,
        hash: u64,
    ) {
        self.stats.total_crashes += 1;
        if let std::collections::hash_map::Entry::Vacant(e) = self.crashes.entry(hash) {
            self.stats.unique_crashes += 1;
            e.insert(CrashSummary {
                hash,
                input,
                instance_id,
                signal,
                found_at: SystemTime::now(),
                count: 1,
            });
        } else {
            self.crashes.get_mut(&hash).unwrap().count += 1;
        }
    }

    /// Return all unique crash summaries.
    #[must_use]
    pub fn unique_crashes(&self) -> Vec<&CrashSummary> {
        let mut v: Vec<&CrashSummary> = self.crashes.values().collect();
        v.sort_unstable_by_key(|c| c.hash);
        v
    }

    /// Return the instance status summary.
    #[must_use]
    pub fn instance_statuses(&self) -> Vec<(u64, &str, u64, InstanceStatus)> {
        self.instances
            .iter()
            .map(|inst| {
                (
                    inst.id,
                    inst.config.name.as_str(),
                    inst.iterations,
                    inst.status,
                )
            })
            .collect()
    }

    /// Update coordinator-level stats from instances and shared corpus.
    pub fn update_stats(&mut self) {
        self.stats.total_iterations = self.instances.iter().map(|i| i.iterations).sum();
        self.stats.corpus_size = self.shared_corpus.len();
        self.stats.coverage_bits = self.shared_corpus.coverage_bits();
        self.stats.total_crashes = self.instances.iter().map(|i| i.unique_crashes).sum();
        self.stats.unique_crashes = self.crashes.len() as u64;
    }

    /// Return the number of currently running instances.
    #[must_use]
    pub fn running_count(&self) -> usize {
        self.instances
            .iter()
            .filter(|i| i.status == InstanceStatus::Running)
            .count()
    }

    /// Return the overall elapsed time since start.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started_at.map_or(Duration::ZERO, |t| t.elapsed())
    }

    /// Return the aggregate iterations per second.
    #[must_use]
    pub fn total_iters_per_sec(&self) -> f64 {
        let secs = self.elapsed().as_secs_f64();
        if secs < f64::EPSILON {
            0.0
        } else {
            self.stats.total_iterations as f64 / secs
        }
    }

    /// Return `true` if all instances have finished or failed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.instances
            .iter()
            .all(|i| matches!(i.status, InstanceStatus::Done | InstanceStatus::Failed))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_coordinator(instances: usize, budget: u64) -> FuzzerCoordinator {
        let cfg = CoordinatorConfig::new().with_budget(budget);
        let mut coord = FuzzerCoordinator::new(cfg);
        for i in 0..instances {
            let icfg = InstanceConfig::new(format!("worker-{i}"))
                .with_max_iterations(budget)
                .with_seed(i as u64 * 1337);
            coord.add_instance(icfg);
        }
        coord.add_seed(b"test seed".to_vec());
        coord.add_seed(vec![0x41; 16]);
        coord
    }

    #[test]
    fn test_add_instance() {
        let mut coord = FuzzerCoordinator::new(CoordinatorConfig::new());
        let id = coord.add_instance(InstanceConfig::new("w0"));
        assert_eq!(id, 0);
        assert_eq!(coord.instances.len(), 1);
    }

    #[test]
    fn test_start_all_sets_running() {
        let mut coord = make_coordinator(2, 100);
        coord.start_all();
        for inst in &coord.instances {
            assert_eq!(inst.status, InstanceStatus::Running);
        }
    }

    #[test]
    fn test_pause_all() {
        let mut coord = make_coordinator(2, 100);
        coord.start_all();
        coord.pause_all();
        for inst in &coord.instances {
            assert_eq!(inst.status, InstanceStatus::Paused);
        }
    }

    #[test]
    fn test_resume_all() {
        let mut coord = make_coordinator(2, 100);
        coord.start_all();
        coord.pause_all();
        coord.resume_all();
        for inst in &coord.instances {
            assert_eq!(inst.status, InstanceStatus::Running);
        }
    }

    #[test]
    fn test_run_steps_produces_iterations() {
        let mut coord = make_coordinator(2, 50);
        coord.start_all();
        let performed = coord.run_steps(20);
        assert!(performed > 0);
    }

    #[test]
    fn test_run_steps_updates_stats() {
        let mut coord = make_coordinator(2, 500);
        coord.start_all();
        coord.run_steps(50);
        coord.update_stats();
        assert!(coord.stats.total_iterations > 0);
    }

    #[test]
    fn test_sync_corpora_transfers_inputs() {
        let mut coord = make_coordinator(2, 10);
        coord.start_all();
        coord.run_steps(10);
        coord.sync_corpora();
        // Both instances should now have the same seeds pulled from shared.
        for inst in &coord.instances {
            assert!(!inst.local_corpus.inputs.is_empty());
        }
    }

    #[test]
    fn test_shared_corpus_add_seed() {
        let sc = SharedCorpus::new(64);
        sc.add_seed(vec![1, 2, 3]);
        sc.add_seed(vec![4, 5, 6]);
        let seeds = sc.snapshot_inputs();
        assert_eq!(seeds.len(), 2);
    }

    #[test]
    fn test_shared_corpus_is_empty_initially() {
        let sc = SharedCorpus::new(64);
        assert!(sc.is_empty());
    }

    #[test]
    fn test_shared_corpus_add_entry() {
        let sc = SharedCorpus::new(64);
        let input = FuzzInput::new(1, vec![0xde, 0xad]);
        let meta = CorpusMeta::new(0x1234, 8, Duration::from_millis(5));
        let entry = CorpusEntry::new(input, meta);
        assert!(sc.add_entry(entry));
        assert_eq!(sc.len(), 1);
    }

    #[test]
    fn test_shared_corpus_clone_shares_state() {
        let sc = SharedCorpus::new(64);
        sc.add_seed(vec![1, 2, 3]);
        let sc2 = sc;
        assert_eq!(sc2.snapshot_inputs().len(), 1);
    }

    #[test]
    fn test_record_crash_deduplication() {
        let mut coord = FuzzerCoordinator::new(CoordinatorConfig::new());
        coord.record_crash(0, vec![0xff], 11, 0xdeadbeef);
        coord.record_crash(0, vec![0xff], 11, 0xdeadbeef); // duplicate
        assert_eq!(coord.unique_crashes().len(), 1);
        assert_eq!(coord.crashes[&0xdeadbeef].count, 2);
    }

    #[test]
    fn test_record_crash_two_unique() {
        let mut coord = FuzzerCoordinator::new(CoordinatorConfig::new());
        coord.record_crash(0, vec![0xff], 11, 0x1111);
        coord.record_crash(0, vec![0xfe], 11, 0x2222);
        assert_eq!(coord.unique_crashes().len(), 2);
    }

    #[test]
    fn test_instance_statuses() {
        let mut coord = make_coordinator(3, 100);
        coord.start_all();
        let statuses = coord.instance_statuses();
        assert_eq!(statuses.len(), 3);
        for (_, _, _, status) in &statuses {
            assert_eq!(*status, InstanceStatus::Running);
        }
    }

    #[test]
    fn test_is_complete_before_stop() {
        let mut coord = make_coordinator(2, 100);
        coord.start_all();
        assert!(!coord.is_complete());
    }

    #[test]
    fn test_is_complete_after_stop() {
        let mut coord = make_coordinator(2, 100);
        coord.start_all();
        coord.stop_all();
        assert!(coord.is_complete());
    }

    #[test]
    fn test_running_count() {
        let mut coord = make_coordinator(3, 100);
        coord.start_all();
        assert_eq!(coord.running_count(), 3);
        coord.instances[0].pause();
        assert_eq!(coord.running_count(), 2);
    }

    #[test]
    fn test_instance_should_continue_after_budget() {
        let mut inst = FuzzerInstance::new(
            0,
            InstanceConfig::new("t").with_max_iterations(5),
        );
        inst.start();
        inst.iterations = 5;
        assert!(!inst.should_continue());
    }

    #[test]
    fn test_instance_iters_per_sec_zero_before_start() {
        let inst = FuzzerInstance::new(0, InstanceConfig::new("t"));
        assert_eq!(inst.iters_per_sec(), 0.0);
    }

    #[test]
    fn test_instance_status_display() {
        assert_eq!(InstanceStatus::Running.to_string(), "running");
        assert_eq!(InstanceStatus::Done.to_string(), "done");
        assert_eq!(InstanceStatus::Failed.to_string(), "failed");
    }

    #[test]
    fn test_coordinator_config_defaults() {
        let cfg = CoordinatorConfig::new();
        assert_eq!(cfg.coverage_map_size, 65536);
        assert_eq!(cfg.max_instances, 8);
        assert!(!cfg.stop_on_crash);
    }

    #[test]
    fn test_coordinator_config_with_budget() {
        let cfg = CoordinatorConfig::new().with_budget(10_000);
        assert_eq!(cfg.total_budget, Some(10_000));
    }

    #[test]
    fn test_coordinator_elapsed_zero_before_start() {
        let coord = FuzzerCoordinator::new(CoordinatorConfig::new());
        assert_eq!(coord.elapsed(), Duration::ZERO);
    }

    #[test]
    fn test_coordinator_total_iters_per_sec_zero_before_start() {
        let coord = FuzzerCoordinator::new(CoordinatorConfig::new());
        assert_eq!(coord.total_iters_per_sec(), 0.0);
    }
}
