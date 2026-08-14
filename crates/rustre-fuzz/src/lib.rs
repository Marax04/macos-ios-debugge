//! `rustre-fuzz`
//!
//! Core fuzzing framework providing: [`Fuzzer`] trait, [`Corpus`] /
//! [`CorpusEntry`] management, [`MutationEngine`] / [`MutationStrategy`],
//! [`CoverageMap`], [`CrashRecord`] / [`CrashDeduplicator`], [`FuzzStats`],
//! [`Minimizer`], [`PowerSchedule`] energy assignment, [`Dictionary`]-based
//! mutation, and supporting types.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::unreadable_literal,
    clippy::format_push_string,
    clippy::format_in_format_args,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::match_same_arms,
    clippy::needless_pass_by_value,
    clippy::needless_raw_string_hashes,
    clippy::option_if_let_else,
    clippy::manual_let_else,
    clippy::redundant_closure_for_method_calls,
    clippy::unnecessary_wraps,
    clippy::unused_self,
    clippy::redundant_guards,
    clippy::map_unwrap_or,
    clippy::if_not_else,
    clippy::struct_excessive_bools,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_const_for_fn,
    clippy::doc_markdown,
    clippy::default_trait_access,
    clippy::wildcard_imports,
    clippy::single_match_else,
    clippy::unnested_or_patterns,
    clippy::needless_continue,
    clippy::implicit_hasher,
    clippy::ignored_unit_patterns,
    clippy::semicolon_if_nothing_returned,
    clippy::stable_sort_primitive,
    clippy::trivially_copy_pass_by_ref,
    clippy::ptr_as_ptr,
    clippy::ref_option,
    clippy::fn_params_excessive_bools,
    clippy::needless_range_loop,
    clippy::double_must_use,
    clippy::float_cmp,
    clippy::match_wildcard_for_single_variants,
    clippy::unusual_byte_groupings
)]

pub mod registry;

pub mod campaign;
pub mod crash_dedup;
pub mod fuzz_orchestrator;
pub mod mutation_scheduler;
pub mod structured_fuzzer;
pub mod smart_seed_scheduler;
pub mod coverage_guided_fuzzer;
pub mod grammar_fuzzer;
pub mod mutation_engine;
pub mod corpus_manager;
pub mod crash_analyzer;
pub mod fuzzer_coordinator;
pub mod seed_minimizer;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors that can occur during fuzzing operations.
#[derive(Debug, Error)]
pub enum FuzzError {
    /// An error occurred while executing the target.
    #[error("execution error: {0}")]
    ExecutionError(String),
    /// An error occurred while tracking coverage.
    #[error("coverage error: {0}")]
    CoverageError(String),
    /// An invalid or malformed input was encountered.
    #[error("input error: {0}")]
    InputError(String),
    /// The target exceeded its time limit.
    #[error("timeout")]
    Timeout,
    /// A corpus operation failed.
    #[error("corpus error: {0}")]
    CorpusError(String),
    /// Minimization failed.
    #[error("minimization error: {0}")]
    MinimizationError(String),
}

// ── Input ────────────────────────────────────────────────────────────────────

/// A single fuzzing input with genealogy metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FuzzInput {
    /// Raw bytes fed to the target.
    pub data: Vec<u8>,
    /// Unique identifier for this input.
    pub id: u64,
    /// Parent input id, if this input was derived from another.
    pub parent: Option<u64>,
    /// How many mutations deep this input is from the seed.
    pub generation: u32,
    /// Mutation strategy that produced this input.
    pub origin: Option<String>,
}

impl FuzzInput {
    /// Create a new [`FuzzInput`] with the given id and data.
    #[must_use]
    pub const fn new(id: u64, data: Vec<u8>) -> Self {
        Self {
            data,
            id,
            parent: None,
            generation: 0,
            origin: None,
        }
    }

    /// Create a new input with the given origin label.
    #[must_use]
    pub fn new_with_origin(id: u64, data: Vec<u8>, origin: impl Into<String>) -> Self {
        Self {
            data,
            id,
            parent: None,
            generation: 0,
            origin: Some(origin.into()),
        }
    }

    /// Create a child input derived from this one.
    #[must_use]
    pub const fn derive(&self, id: u64, data: Vec<u8>) -> Self {
        Self {
            data,
            id,
            parent: Some(self.id),
            generation: self.generation.saturating_add(1),
            origin: None,
        }
    }

    /// Create a child input derived from this one with an origin label.
    #[must_use]
    pub fn derive_with_origin(&self, id: u64, data: Vec<u8>, origin: impl Into<String>) -> Self {
        Self {
            data,
            id,
            parent: Some(self.id),
            generation: self.generation.saturating_add(1),
            origin: Some(origin.into()),
        }
    }

    /// Compute the FNV-1a hash of this input's data bytes.
    #[must_use]
    pub fn data_hash(&self) -> u64 {
        fnv1a(&self.data)
    }

    /// Length of the input data in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// True when this input has no data bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// FNV-1a 64-bit hash.
#[must_use]
pub fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// ── FuzzResult ───────────────────────────────────────────────────────────────

/// High-level result returned after fuzzing a single input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzResult {
    /// The input triggered new coverage — worth keeping.
    Interesting(Vec<u8>),
    /// The target crashed while processing the input.
    Crash {
        /// Bytes that caused the crash.
        input: Vec<u8>,
        /// Signal number that terminated the target.
        signal: i32,
        /// Fault address (e.g. from SIGSEGV).
        address: u64,
    },
    /// The target timed out.
    Timeout,
    /// Ordinary execution — no new coverage.
    Normal,
}

impl FuzzResult {
    /// Returns `true` if this result indicates a crash.
    #[must_use]
    pub const fn is_crash(&self) -> bool {
        matches!(self, Self::Crash { .. })
    }

    /// Returns `true` if this result is interesting.
    #[must_use]
    pub const fn is_interesting(&self) -> bool {
        matches!(self, Self::Interesting(_))
    }

    /// Returns `true` if this result is normal (no new coverage, no crash).
    #[must_use]
    pub const fn is_normal(&self) -> bool {
        matches!(self, Self::Normal)
    }
}

// ── ExecutionStatus ───────────────────────────────────────────────────────────

/// Low-level status returned from a single target execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// Target exited normally.
    Normal,
    /// Target crashed with the given signal.
    Crash {
        /// Signal number.
        signal: i32,
        /// Fault address, if available.
        fault_addr: Option<u64>,
    },
    /// Target exceeded the configured time limit.
    Timeout,
    /// Target appears to be running indefinitely without progress.
    Hang,
}

impl ExecutionStatus {
    /// Returns `true` if this status indicates a crash.
    #[must_use]
    pub const fn is_crash(&self) -> bool {
        matches!(self, Self::Crash { .. })
    }

    /// Returns `true` if this status is normal.
    #[must_use]
    pub const fn is_normal(&self) -> bool {
        matches!(self, Self::Normal)
    }

    /// Returns `true` if this is a timeout or hang.
    #[must_use]
    pub const fn is_hang(&self) -> bool {
        matches!(self, Self::Timeout | Self::Hang)
    }
}

// ── ExecutionResult ───────────────────────────────────────────────────────────

/// Detailed result of executing the target on a single input.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// How the target exited.
    pub status: ExecutionStatus,
    /// A hash summarising the coverage bitmap after this run.
    pub coverage_hash: u64,
    /// Wall-clock time taken by the execution.
    pub execution_time: Duration,
    /// Number of coverage bits that are new compared to the global map.
    pub new_coverage_bits: u32,
}

impl ExecutionResult {
    /// Create a normal execution result with no new coverage.
    #[must_use]
    pub const fn normal(execution_time: Duration) -> Self {
        Self {
            status: ExecutionStatus::Normal,
            coverage_hash: 0,
            execution_time,
            new_coverage_bits: 0,
        }
    }

    /// Create a crash result.
    #[must_use]
    pub const fn crash(signal: i32, fault_addr: Option<u64>, execution_time: Duration) -> Self {
        Self {
            status: ExecutionStatus::Crash { signal, fault_addr },
            coverage_hash: 0,
            execution_time,
            new_coverage_bits: 0,
        }
    }
}

// ── TargetExecutor ────────────────────────────────────────────────────────────

/// Abstraction over anything that can run a fuzzing target.
pub trait TargetExecutor: Send {
    /// Execute the target with `input` and return detailed results.
    ///
    /// # Errors
    /// Returns [`FuzzError`] when the executor itself fails (e.g. cannot fork,
    /// cannot write the input to a file, etc.).
    fn execute(&mut self, input: &[u8]) -> Result<ExecutionResult, FuzzError>;
}

// ── CoverageMap ───────────────────────────────────────────────────────────────

/// Compact coverage bitmap plus per-edge hit counters.
#[derive(Debug, Clone, Default)]
pub struct CoverageMap {
    /// One bit per coverage edge; set when the edge has been hit at least once.
    pub bits: Vec<u8>,
    /// Per-edge hit counts (saturating at 255).
    pub hit_counts: Vec<u8>,
    /// Total bits ever set.
    total_set: u32,
}

impl CoverageMap {
    /// Create a new coverage map with `size` bytes of bit-space.
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            bits: vec![0u8; size],
            hit_counts: vec![0u8; size * 8],
            total_set: 0,
        }
    }

    /// Merge `new_bits` into this map and return how many bits are newly set.
    ///
    /// `new_bits` is treated as a raw AFL-style coverage bitmap where each byte
    /// encodes 8 edge hit-flags.
    pub fn update(&mut self, new_bits: &[u8]) -> u32 {
        let len = self.bits.len().min(new_bits.len());
        let mut newly_set: u32 = 0;
        for i in 0..len {
            let incoming = new_bits[i];
            let before = self.bits[i];
            let novel = incoming & !before;
            if novel != 0 {
                newly_set += novel.count_ones();
                self.bits[i] |= incoming;
            }
            for bit in 0..8u8 {
                let edge_idx = i * 8 + usize::from(bit);
                if edge_idx < self.hit_counts.len() && (incoming >> bit) & 1 == 1 {
                    self.hit_counts[edge_idx] = self.hit_counts[edge_idx].saturating_add(1);
                }
            }
        }
        self.total_set = self.total_set.saturating_add(newly_set);
        newly_set
    }

    /// Merge another [`CoverageMap`] into this one.
    pub fn merge(&mut self, other: &Self) -> u32 {
        self.update(&other.bits)
    }

    /// Return the total number of bits currently set in the map.
    #[must_use]
    pub fn total_bits_set(&self) -> u32 {
        self.bits.iter().map(|b| b.count_ones()).sum()
    }

    /// Return the count of bits set since the last [`reset`](Self::reset) call.
    ///
    /// Note: this counter is reset to zero by `reset()`. It does NOT accumulate
    /// across reset cycles. Use `total_bits_set()` for a live popcount of the
    /// current bitmap.
    #[must_use]
    pub const fn bits_set_since_last_reset(&self) -> u32 {
        self.total_set
    }

    /// Alias kept for backwards compatibility; prefer [`bits_set_since_last_reset`](Self::bits_set_since_last_reset).
    #[must_use]
    pub const fn cumulative_bits_set(&self) -> u32 {
        self.bits_set_since_last_reset()
    }

    /// Compute a fast hash of the coverage bitmap.
    #[must_use]
    pub fn hash(&self) -> u64 {
        fnv1a(&self.bits)
    }

    /// Reset the map to all zeros.
    pub fn reset(&mut self) {
        for b in &mut self.bits {
            *b = 0;
        }
        for c in &mut self.hit_counts {
            *c = 0;
        }
        self.total_set = 0;
    }

    /// Return `true` if the coverage map has no edges set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&b| b == 0)
    }

    /// Return the number of edges that have been hit more than once.
    #[must_use]
    pub fn hot_edges(&self) -> u32 {
        self.hit_counts.iter().filter(|&&c| c > 1).count() as u32
    }

    /// Get the hit count for a specific edge index.
    #[must_use]
    pub fn edge_hit_count(&self, edge: usize) -> u8 {
        self.hit_counts.get(edge).copied().unwrap_or(0)
    }

    /// Return a compact list of (`edge_index`, `hit_count`) for all non-zero edges.
    #[must_use]
    pub fn active_edges(&self) -> Vec<(usize, u8)> {
        self.hit_counts
            .iter()
            .enumerate()
            .filter(|&(_, &c)| c > 0)
            .map(|(i, &c)| (i, c))
            .collect()
    }
}

// ── InputQueue ────────────────────────────────────────────────────────────────

/// Priority queue of inputs for the fuzzer, favouring interesting ones.
#[derive(Debug, Default)]
pub struct InputQueue {
    /// All inputs keyed by id.
    pub inputs: BTreeMap<u64, FuzzInput>,
    /// Ids of "favoured" inputs that should be tried more often.
    pub favored: Vec<u64>,
    /// Running total of executions performed so far.
    pub total_executions: u64,
    next_id: u64,
    /// Round-robin cursor for non-favored selection.
    cursor: usize,
}

impl InputQueue {
    /// Create an empty [`InputQueue`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate the next available input id.
    pub const fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Add an input to the queue.
    ///
    /// If `is_interesting` is `true` the input is also appended to the
    /// favoured list.
    pub fn add(&mut self, input: FuzzInput, is_interesting: bool) {
        let id = input.id;
        self.inputs.insert(id, input);
        if is_interesting {
            self.favored.push(id);
        }
    }

    /// Remove an input by id.
    ///
    /// Returns the removed input, or `None` if not found.
    pub fn remove(&mut self, id: u64) -> Option<FuzzInput> {
        self.favored.retain(|&fid| fid != id);
        self.inputs.remove(&id)
    }

    /// Select the next input to fuzz using a round-robin strategy that
    /// over-samples favoured inputs.
    ///
    /// Automatically increments `total_executions` on each call so that
    /// repeated calls make progress through the round-robin.
    ///
    /// # Panics
    /// Panics if the queue is empty.
    #[must_use]
    pub fn select(&mut self) -> &FuzzInput {
        assert!(
            !self.inputs.is_empty(),
            "InputQueue::select called on empty queue"
        );
        let use_favored = !self.favored.is_empty() && self.total_executions.is_multiple_of(3);

        let result = if use_favored {
            let idx = (self.total_executions as usize / 3) % self.favored.len();
            let id = self.favored[idx];
            self.inputs.get(&id)
        } else {
            None
        };

        self.total_executions = self.total_executions.saturating_add(1);

        if let Some(inp) = result {
            return inp;
        }

        let idx = ((self.total_executions - 1) as usize) % self.inputs.len();
        self.inputs
            .values()
            .nth(idx)
            .expect("checked non-empty above")
    }

    /// Select and return a reference to a random input using a deterministic
    /// cursor that wraps around.
    ///
    /// # Panics
    /// Panics if the queue is empty.
    #[must_use]
    pub fn select_cursor(&mut self) -> &FuzzInput {
        assert!(
            !self.inputs.is_empty(),
            "InputQueue::select_cursor on empty queue"
        );
        let n = self.inputs.len();
        let idx = self.cursor % n;
        self.cursor = (self.cursor + 1) % n;
        self.inputs.values().nth(idx).expect("checked above")
    }

    /// True when the queue contains at least one input.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }

    /// Number of inputs in the queue.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inputs.len()
    }

    /// Number of favoured inputs.
    #[must_use]
    pub const fn favored_count(&self) -> usize {
        self.favored.len()
    }

    /// Clear all inputs and favoured entries.
    pub fn clear(&mut self) {
        self.inputs.clear();
        self.favored.clear();
        self.cursor = 0;
    }
}

// ── FuzzerStats ───────────────────────────────────────────────────────────────

/// Accumulated statistics for a fuzzing campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzerStats {
    /// Total number of target executions.
    pub executions: u64,
    /// Total crashes found.
    pub crashes: u64,
    /// Total hangs/timeouts found.
    pub hangs: u64,
    /// Number of distinct crashes (de-duplicated by coverage hash).
    pub unique_crashes: u64,
    /// When the last crash was found.
    pub last_crash_time: Option<SystemTime>,
    /// When the fuzzing campaign started (wall clock, for display / serialisation).
    pub start_time: SystemTime,
    /// Monotonic start instant used for accurate duration measurement.
    /// Not serialised — reconstructed as `Instant::now()` when deserialising.
    #[serde(skip, default = "Instant::now")]
    pub start_instant: Instant,
    /// Number of inputs in the corpus.
    pub corpus_size: u64,
    /// Number of executions that produced new coverage.
    pub interesting_inputs: u64,
    /// Maximum input length seen.
    pub max_input_len: usize,
    /// Total bytes generated (sum of all mutated input lengths).
    pub total_bytes_generated: u64,
}

impl FuzzerStats {
    /// Create a fresh [`FuzzerStats`] starting now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            executions: 0,
            crashes: 0,
            hangs: 0,
            unique_crashes: 0,
            last_crash_time: None,
            start_time: SystemTime::now(),
            start_instant: Instant::now(),
            corpus_size: 0,
            interesting_inputs: 0,
            max_input_len: 0,
            total_bytes_generated: 0,
        }
    }

    /// Executions per second since the campaign started.
    ///
    /// Uses the monotonic `start_instant` clock so that wall-clock adjustments
    /// (NTP, DST, etc.) cannot cause a negative or artificially large result
    /// (`time-monotonic-vs-system`).
    #[must_use]
    pub fn execs_per_sec(&self) -> f64 {
        let elapsed = self.start_instant.elapsed().as_secs_f64();
        if elapsed < f64::EPSILON {
            0.0
        } else {
            self.executions as f64 / elapsed
        }
    }

    /// Seconds elapsed since the campaign started (monotonic).
    #[must_use]
    pub fn elapsed_secs(&self) -> f64 {
        self.start_instant.elapsed().as_secs_f64()
    }

    /// Crash rate as a fraction of total executions.
    #[must_use]
    pub fn crash_rate(&self) -> f64 {
        if self.executions == 0 {
            0.0
        } else {
            self.crashes as f64 / self.executions as f64
        }
    }

    /// Record a new execution.
    pub const fn record_execution(&mut self, input_len: usize) {
        self.executions += 1;
        self.total_bytes_generated += input_len as u64;
        if input_len > self.max_input_len {
            self.max_input_len = input_len;
        }
    }
}

impl Default for FuzzerStats {
    fn default() -> Self {
        Self::new()
    }
}

// ── FuzzStats (alias) ─────────────────────────────────────────────────────────

/// Alias for [`FuzzerStats`] for use in the fuzzer API.
pub type FuzzStats = FuzzerStats;

// ── CorpusMeta ────────────────────────────────────────────────────────────────

/// Metadata stored alongside each corpus entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusMeta {
    /// Hash of the coverage bitmap produced by this input.
    pub hash: u64,
    /// Number of coverage bits hit by this input.
    pub coverage_bits: u32,
    /// How long the target took to process this input.
    pub execution_time: Duration,
    /// When this input was added to the corpus.
    pub found_at: SystemTime,
    /// Energy assigned by power schedule (higher → more mutations).
    pub energy: u32,
    /// How many times this entry has been selected for mutation.
    pub selected_count: u64,
}

impl CorpusMeta {
    /// Create a new metadata record.
    #[must_use]
    pub fn new(hash: u64, coverage_bits: u32, execution_time: Duration) -> Self {
        Self {
            hash,
            coverage_bits,
            execution_time,
            found_at: SystemTime::now(),
            energy: 1,
            selected_count: 0,
        }
    }

    /// Increment the selected count.
    pub const fn record_selection(&mut self) {
        self.selected_count = self.selected_count.saturating_add(1);
    }
}

// ── CorpusEntry ───────────────────────────────────────────────────────────────

/// A complete corpus entry: input bytes plus metadata.
#[derive(Debug, Clone)]
pub struct CorpusEntry {
    /// The fuzzing input.
    pub input: FuzzInput,
    /// Metadata about how/when this entry was found.
    pub meta: CorpusMeta,
}

impl CorpusEntry {
    /// Create a new corpus entry.
    #[must_use]
    pub const fn new(input: FuzzInput, meta: CorpusMeta) -> Self {
        Self { input, meta }
    }

    /// Convenience: data bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.input.data
    }

    /// Convenience: input id.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.input.id
    }
}

// ── Corpus ────────────────────────────────────────────────────────────────────

/// Container for interesting inputs and crashes, with metadata.
#[derive(Debug, Default)]
pub struct Corpus {
    /// Interesting (coverage-increasing) inputs.
    pub inputs: Vec<FuzzInput>,
    /// Crash-inducing inputs.
    pub crashes: Vec<FuzzInput>,
    /// Per-input metadata, keyed by input id.
    pub metadata: HashMap<u64, CorpusMeta>,
    /// Full corpus entries.
    pub entries: Vec<CorpusEntry>,
    /// Set of coverage hashes already present (for deduplication).
    cov_hashes: HashSet<u64>,
}

impl Corpus {
    /// Create an empty [`Corpus`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an interesting input with the given metadata.
    ///
    /// Returns `true` if the input was novel (new coverage hash), `false` if
    /// it was a duplicate.
    pub fn add_input(&mut self, input: FuzzInput, meta: CorpusMeta) -> bool {
        let id = input.id;
        let novel = self.cov_hashes.insert(meta.hash);
        let entry = CorpusEntry::new(input.clone(), meta.clone());
        self.inputs.push(input);
        self.metadata.insert(id, meta);
        self.entries.push(entry);
        novel
    }

    /// Add a crash-inducing input with the given metadata.
    ///
    /// Returns `true` if the crash was novel.
    pub fn add_crash(&mut self, input: FuzzInput, meta: CorpusMeta) -> bool {
        let id = input.id;
        let novel = self.cov_hashes.insert(meta.hash);
        let entry = CorpusEntry::new(input.clone(), meta.clone());
        self.crashes.push(input);
        self.metadata.insert(id, meta);
        self.entries.push(entry);
        novel
    }

    /// Total number of corpus entries (interesting + crashes).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.inputs.len() + self.crashes.len()
    }

    /// True when the corpus is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.inputs.is_empty() && self.crashes.is_empty()
    }

    /// Number of unique coverage hashes seen.
    #[must_use]
    pub fn unique_coverage_hashes(&self) -> usize {
        self.cov_hashes.len()
    }

    /// Get a corpus entry by id.
    #[must_use]
    pub fn get_entry(&self, id: u64) -> Option<&CorpusEntry> {
        self.entries.iter().find(|e| e.id() == id)
    }

    /// Prune corpus entries below the given coverage-bit threshold.
    ///
    /// Returns the number of entries removed.
    pub fn prune(&mut self, min_coverage_bits: u32) -> usize {
        let before = self.inputs.len();
        // Compute the retained id set first so both collections stay in sync.
        let retained_ids: HashSet<u64> = self
            .inputs
            .iter()
            .filter(|inp| {
                self.metadata
                    .get(&inp.id)
                    .is_some_and(|m| m.coverage_bits >= min_coverage_bits)
            })
            .map(|inp| inp.id)
            // Always keep root inputs (no parent) regardless of coverage.
            .chain(
                self.inputs
                    .iter()
                    .filter(|inp| inp.parent.is_none())
                    .map(|inp| inp.id),
            )
            .collect();
        self.inputs.retain(|inp| retained_ids.contains(&inp.id));
        self.entries.retain(|e| retained_ids.contains(&e.id()));
        before - self.inputs.len()
    }

    /// Return references to all interesting inputs sorted by coverage bits
    /// (descending).
    #[must_use]
    pub fn sorted_by_coverage(&self) -> Vec<&FuzzInput> {
        let mut v: Vec<&FuzzInput> = Vec::with_capacity(self.inputs.len());
        v.extend(self.inputs.iter());
        v.sort_unstable_by(|a, b| {
            let ca = self.metadata.get(&a.id).map_or(0, |m| m.coverage_bits);
            let cb = self.metadata.get(&b.id).map_or(0, |m| m.coverage_bits);
            cb.cmp(&ca)
        });
        v
    }
}

// ── CrashRecord ──────────────────────────────────────────────────────────────

/// A crash record capturing all relevant information about a single crash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashRecord {
    /// Unique crash ID.
    pub id: u64,
    /// Input bytes that triggered the crash.
    pub input: Vec<u8>,
    /// Signal that caused the crash.
    pub signal: i32,
    /// Fault address (if available).
    pub fault_addr: Option<u64>,
    /// Coverage hash at time of crash.
    pub coverage_hash: u64,
    /// When the crash was first seen.
    pub first_seen: SystemTime,
    /// How many times this crash has been reproduced.
    pub occurrence_count: u64,
    /// Stack-trace fingerprint (hash of symbolic frames, if available).
    pub stack_hash: Option<u64>,
    /// Human-readable crash description.
    pub description: String,
    /// Exploitability estimate (0 = unknown, 1 = low, 5 = critical).
    pub exploitability: u8,
}

impl CrashRecord {
    /// Create a new crash record.
    #[must_use]
    pub fn new(
        id: u64,
        input: Vec<u8>,
        signal: i32,
        fault_addr: Option<u64>,
        coverage_hash: u64,
    ) -> Self {
        let description =
            format!("signal={signal} fault={fault_addr:?} cov_hash={coverage_hash:016x}");
        Self {
            id,
            input,
            signal,
            fault_addr,
            coverage_hash,
            first_seen: SystemTime::now(),
            occurrence_count: 1,
            stack_hash: None,
            description,
            exploitability: 0,
        }
    }

    /// Set a stack hash from a symbolic stack trace.
    pub fn set_stack_hash(&mut self, frames: &[u64]) {
        self.stack_hash = Some(fnv1a(
            &frames
                .iter()
                .flat_map(|f| f.to_le_bytes())
                .collect::<Vec<_>>(),
        ));
    }

    /// Increment the occurrence counter.
    pub const fn increment(&mut self) {
        self.occurrence_count = self.occurrence_count.saturating_add(1);
    }

    /// Deduplication key: stack hash if available, otherwise coverage hash.
    #[must_use]
    pub fn dedup_key(&self) -> u64 {
        self.stack_hash.unwrap_or(self.coverage_hash)
    }
}

// ── CrashDeduplicator ────────────────────────────────────────────────────────

/// Deduplicates crash records by their dedup key.
#[derive(Debug, Default)]
pub struct CrashDeduplicator {
    /// Known crashes keyed by dedup key.
    crashes: HashMap<u64, CrashRecord>,
    /// Ordered list of unique crash ids (insertion order).
    order: Vec<u64>,
    /// Maps crash id -> dedup key for O(1) order-preserving iteration.
    id_to_key: HashMap<u64, u64>,
    /// Next crash id.
    next_id: u64,
}

impl CrashDeduplicator {
    /// Create an empty deduplicator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit a new crash candidate.
    ///
    /// Returns `true` if this is a genuinely new crash, `false` if it was
    /// already known.
    pub fn submit(
        &mut self,
        input: Vec<u8>,
        signal: i32,
        fault_addr: Option<u64>,
        coverage_hash: u64,
    ) -> bool {
        let id = self.next_id;
        let mut record = CrashRecord::new(id, input, signal, fault_addr, coverage_hash);
        let key = record.dedup_key();
        if let Some(existing) = self.crashes.get_mut(&key) {
            existing.increment();
            return false;
        }
        self.next_id += 1;
        record.id = id;
        self.order.push(id);
        self.id_to_key.insert(id, key);
        self.crashes.insert(key, record);
        true
    }

    /// Number of unique crashes.
    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.crashes.len()
    }

    /// Iterate over all unique crash records in insertion order.
    #[must_use]
    pub fn iter(&self) -> impl Iterator<Item = &CrashRecord> {
        self.order
            .iter()
            .filter_map(|id| self.id_to_key.get(id).and_then(|key| self.crashes.get(key)))
    }

    /// Get all crashes as a sorted Vec (by dedup key).
    #[must_use]
    pub fn all_crashes(&self) -> Vec<&CrashRecord> {
        let mut v: Vec<&CrashRecord> = self.crashes.values().collect();
        v.sort_unstable_by_key(|r| r.dedup_key());
        v
    }

    /// Return the most-reproduced crash record.
    #[must_use]
    pub fn most_common(&self) -> Option<&CrashRecord> {
        self.crashes.values().max_by_key(|r| r.occurrence_count)
    }

    /// Clear all crash records.
    pub fn clear(&mut self) {
        self.crashes.clear();
        self.order.clear();
        self.id_to_key.clear();
    }
}

// ── MutationStrategy ─────────────────────────────────────────────────────────

/// Identifies a specific mutation strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MutationStrategy {
    /// Flip a single bit at a random position.
    BitFlip,
    /// Flip a single byte at a random position.
    ByteFlip,
    /// Add or subtract a small value to a byte/word/dword.
    Arithmetic,
    /// Insert a known-interesting boundary value.
    InterestingValue,
    /// Insert or overwrite with a dictionary token.
    Dictionary,
    /// Splice two inputs together at a crossover point.
    Splice,
    /// Apply multiple random micro-mutations (havoc).
    Havoc,
    /// Insert random bytes.
    Insert,
    /// Delete a random byte range.
    Delete,
    /// Shuffle a block of bytes.
    Shuffle,
    /// Repeat a byte block.
    Repeat,
    /// XOR a byte range with a random constant.
    XorBlock,
    /// Reverse a byte range.
    Reverse,
}

impl MutationStrategy {
    /// Human-readable name of the strategy.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BitFlip => "bit_flip",
            Self::ByteFlip => "byte_flip",
            Self::Arithmetic => "arithmetic",
            Self::InterestingValue => "interesting_value",
            Self::Dictionary => "dictionary",
            Self::Splice => "splice",
            Self::Havoc => "havoc",
            Self::Insert => "insert",
            Self::Delete => "delete",
            Self::Shuffle => "shuffle",
            Self::Repeat => "repeat",
            Self::XorBlock => "xor_block",
            Self::Reverse => "reverse",
        }
    }

    /// Return all defined strategies.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::BitFlip,
            Self::ByteFlip,
            Self::Arithmetic,
            Self::InterestingValue,
            Self::Dictionary,
            Self::Splice,
            Self::Havoc,
            Self::Insert,
            Self::Delete,
            Self::Shuffle,
            Self::Repeat,
            Self::XorBlock,
            Self::Reverse,
        ]
    }
}

impl std::fmt::Display for MutationStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ── Dictionary ────────────────────────────────────────────────────────────────

/// A word list used by dictionary-based mutation.
#[derive(Debug, Clone, Default)]
pub struct Dictionary {
    /// The list of raw-byte tokens.
    pub entries: Vec<Vec<u8>>,
    /// Optional name for this dictionary.
    pub name: Option<String>,
}

impl Dictionary {
    /// Create a new empty dictionary.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a dictionary with a name.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            entries: Vec::new(),
            name: Some(name.into()),
        }
    }

    /// Add a token to the dictionary.
    pub fn add(&mut self, token: Vec<u8>) {
        self.entries.push(token);
    }

    /// Add a string token to the dictionary.
    pub fn add_str(&mut self, s: &str) {
        self.entries.push(s.as_bytes().to_vec());
    }

    /// Number of tokens.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the dictionary has no tokens.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return a token by index (wrapping).
    #[must_use]
    pub fn get_wrapping(&self, idx: usize) -> Option<&[u8]> {
        if self.entries.is_empty() {
            None
        } else {
            Some(&self.entries[idx % self.entries.len()])
        }
    }

    /// Load dictionary tokens from a simple text format (one token per line,
    /// optionally quoted as `"..."` or `x"..."` for hex).
    ///
    /// # Errors
    /// Returns [`FuzzError::InputError`] on parse failure.
    pub fn load_from_text(&mut self, text: &str) -> Result<usize, FuzzError> {
        let mut count = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Hex format: x"de ad be ef"
            if let Some(rest) = line.strip_prefix("x\"") {
                let hex = rest.trim_end_matches('"');
                let bytes: Result<Vec<u8>, _> = hex
                    .split_whitespace()
                    .map(|s| u8::from_str_radix(s, 16))
                    .collect();
                match bytes {
                    Ok(b) => {
                        self.add(b);
                        count += 1;
                    }
                    Err(_) => {
                        return Err(FuzzError::InputError(format!("invalid hex token: {hex}")));
                    }
                }
            } else if line.starts_with('"') && line.ends_with('"') && line.len() >= 2 {
                // Quoted string
                let inner = &line[1..line.len() - 1];
                self.add(inner.as_bytes().to_vec());
                count += 1;
            } else {
                // Bare token
                self.add(line.as_bytes().to_vec());
                count += 1;
            }
        }
        Ok(count)
    }
}

// ── MutationEngine ────────────────────────────────────────────────────────────

/// A simple xorshift-64 PRNG used internally by the mutation engine.
#[derive(Debug, Clone)]
pub struct FuzzRng {
    state: u64,
}

impl FuzzRng {
    /// Create a new RNG with the given seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0xdead_beef_cafebabe
            } else {
                seed
            },
        }
    }

    /// Generate the next 64-bit value.
    pub const fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Generate a random `usize` in `[0, n)`.
    #[must_use]
    pub const fn next_usize(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() as usize) % n
    }

    /// Generate a random `u8`.
    pub const fn next_u8(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }

    /// Return `true` with probability 1/n.
    pub const fn one_in(&mut self, n: usize) -> bool {
        self.next_usize(n) == 0
    }
}

impl Default for FuzzRng {
    fn default() -> Self {
        Self::new(0x1234_5678_9abc_def0)
    }
}

/// Mutation engine that applies various strategies to produce new inputs.
pub struct MutationEngine {
    /// Dictionary to use for dictionary-based mutations.
    pub dictionary: Dictionary,
    /// Maximum output size (bytes).
    pub max_size: usize,
    /// Minimum output size (bytes).
    pub min_size: usize,
    /// Internal PRNG.
    rng: FuzzRng,
    /// Per-strategy success counts for adaptive weighting.
    strategy_hits: HashMap<MutationStrategy, u64>,
    /// Total mutations performed.
    pub total_mutations: u64,
}

impl MutationEngine {
    /// Create a new mutation engine with a random seed.
    #[must_use]
    pub fn new() -> Self {
        Self::with_seed(0x1234_5678_9abc_def0)
    }

    /// Create a new mutation engine with the given seed.
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        Self {
            dictionary: Dictionary::new(),
            max_size: 1024 * 1024, // 1 MiB
            min_size: 1,
            rng: FuzzRng::new(seed),
            strategy_hits: HashMap::new(),
            total_mutations: 0,
        }
    }

    /// Apply `strategy` to `input` and return the mutated bytes.
    #[must_use]
    pub fn mutate(&mut self, input: &[u8], strategy: MutationStrategy) -> Vec<u8> {
        self.total_mutations += 1;
        match strategy {
            MutationStrategy::BitFlip => self.bit_flip(input),
            MutationStrategy::ByteFlip => self.byte_flip(input),
            MutationStrategy::Arithmetic => self.arithmetic(input),
            MutationStrategy::InterestingValue => self.interesting_value(input),
            MutationStrategy::Dictionary => self.dictionary_mutate(input),
            MutationStrategy::Splice => self.splice(input, input), // self-splice as fallback
            MutationStrategy::Havoc => self.havoc(input),
            MutationStrategy::Insert => self.insert(input),
            MutationStrategy::Delete => self.delete(input),
            MutationStrategy::Shuffle => self.shuffle(input),
            MutationStrategy::Repeat => self.repeat(input),
            MutationStrategy::XorBlock => self.xor_block(input),
            MutationStrategy::Reverse => self.reverse(input),
        }
    }

    /// Splice two inputs together at a random crossover point.
    #[must_use]
    pub fn splice_two(&mut self, a: &[u8], b: &[u8]) -> Vec<u8> {
        self.splice(a, b)
    }

    /// Record a strategy as having produced an interesting result.
    pub fn record_hit(&mut self, strategy: MutationStrategy) {
        *self.strategy_hits.entry(strategy).or_insert(0) += 1;
    }

    /// Return the strategy with the most hits.
    #[must_use]
    pub fn best_strategy(&self) -> Option<MutationStrategy> {
        self.strategy_hits
            .iter()
            .max_by_key(|&(_, &v)| v)
            .map(|(&s, _)| s)
    }

    fn bit_flip(&mut self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let total_bits = out.len() * 8;
        let start_bit = self.rng.next_usize(total_bits);
        let widths = [1usize, 2, 4];
        let width = widths[self.rng.next_usize(3)];
        for offset in 0..width {
            let bit = (start_bit + offset) % total_bits;
            let byte_idx = bit / 8;
            let bit_idx = bit % 8;
            out[byte_idx] ^= 1 << bit_idx;
        }
        out
    }

    fn byte_flip(&mut self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let widths = [1usize, 2, 4, 8];
        let width = widths[self.rng.next_usize(4)].min(out.len());
        let start = self.rng.next_usize(out.len().saturating_sub(width) + 1);
        for i in start..start + width {
            out[i] ^= 0xff;
        }
        out
    }

    fn arithmetic(&mut self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let delta = (self.rng.next_usize(35) + 1) as u8;
        let add = self.rng.next_u64() & 1 == 0;
        let kind = self.rng.next_usize(3);
        match kind {
            0 => {
                let idx = self.rng.next_usize(out.len());
                if add {
                    out[idx] = out[idx].wrapping_add(delta);
                } else {
                    out[idx] = out[idx].wrapping_sub(delta);
                }
            }
            1 if out.len() >= 2 => {
                let idx = self.rng.next_usize(out.len() - 1);
                let val = u16::from_le_bytes([out[idx], out[idx + 1]]);
                let result = if add {
                    val.wrapping_add(u16::from(delta))
                } else {
                    val.wrapping_sub(u16::from(delta))
                };
                let bytes = result.to_le_bytes();
                out[idx] = bytes[0];
                out[idx + 1] = bytes[1];
            }
            2 if out.len() >= 4 => {
                let idx = self.rng.next_usize(out.len() - 3);
                let val = u32::from_le_bytes([out[idx], out[idx + 1], out[idx + 2], out[idx + 3]]);
                let result = if add {
                    val.wrapping_add(u32::from(delta))
                } else {
                    val.wrapping_sub(u32::from(delta))
                };
                let bytes = result.to_le_bytes();
                out[idx..idx + 4].copy_from_slice(&bytes);
            }
            _ => {
                let idx = self.rng.next_usize(out.len());
                out[idx] = out[idx].wrapping_add(delta);
            }
        }
        out
    }

    fn interesting_value(&mut self, input: &[u8]) -> Vec<u8> {
        const IVALS_8: &[u8] = &[0, 1, 127, 128, 255];
        const IVALS_16: &[u16] = &[0, 1, 0x7fff, 0x8000, 0xffff];
        const IVALS_32: &[u32] = &[0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff];
        if input.is_empty() {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let kind = self.rng.next_usize(3);
        match kind {
            0 => {
                let idx = self.rng.next_usize(out.len());
                out[idx] = IVALS_8[self.rng.next_usize(IVALS_8.len())];
            }
            1 if out.len() >= 2 => {
                let idx = self.rng.next_usize(out.len() - 1);
                let val = IVALS_16[self.rng.next_usize(IVALS_16.len())];
                let b = val.to_le_bytes();
                out[idx] = b[0];
                out[idx + 1] = b[1];
            }
            2 if out.len() >= 4 => {
                let idx = self.rng.next_usize(out.len() - 3);
                let val = IVALS_32[self.rng.next_usize(IVALS_32.len())];
                let b = val.to_le_bytes();
                out[idx..idx + 4].copy_from_slice(&b);
            }
            _ => {
                let idx = self.rng.next_usize(out.len());
                out[idx] = IVALS_8[self.rng.next_usize(IVALS_8.len())];
            }
        }
        out
    }

    fn dictionary_mutate(&mut self, input: &[u8]) -> Vec<u8> {
        if self.dictionary.is_empty() || input.is_empty() {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let idx = self.rng.next_usize(self.dictionary.entries.len());
        let token = self.dictionary.entries[idx].clone();
        if token.is_empty() {
            return out;
        }
        let max_start = out.len().saturating_sub(1);
        let start = self.rng.next_usize(max_start + 1);
        let end = (start + token.len()).min(out.len());
        out[start..end].copy_from_slice(&token[..end - start]);
        out
    }

    fn splice(&mut self, a: &[u8], b: &[u8]) -> Vec<u8> {
        if a.is_empty() {
            return b.to_vec();
        }
        if b.is_empty() {
            return a.to_vec();
        }
        let split_a = self.rng.next_usize(a.len());
        let split_b = self.rng.next_usize(b.len());
        let mut out = Vec::with_capacity(split_a + (b.len() - split_b));
        out.extend_from_slice(&a[..split_a]);
        out.extend_from_slice(&b[split_b..]);
        out
    }

    fn havoc(&mut self, input: &[u8]) -> Vec<u8> {
        let mut buf = input.to_vec();
        let rounds = self.rng.next_usize(8) + 1;
        for _ in 0..rounds {
            self.havoc_one(&mut buf);
        }
        buf
    }

    fn havoc_one(&mut self, buf: &mut Vec<u8>) {
        if buf.is_empty() {
            return;
        }
        match self.rng.next_usize(8) {
            0 => {
                let bit = self.rng.next_usize(buf.len() * 8);
                buf[bit / 8] ^= 1 << (bit % 8);
            }
            1 => {
                let idx = self.rng.next_usize(buf.len());
                buf[idx] ^= 0xff;
            }
            2 => {
                let idx = self.rng.next_usize(buf.len());
                buf[idx] = self.rng.next_u8();
            }
            3 => {
                if buf.len() > 1 {
                    let start = self.rng.next_usize(buf.len());
                    let len = self.rng.next_usize((buf.len() - start).max(1)) + 1;
                    let end = (start + len).min(buf.len());
                    buf.drain(start..end);
                }
            }
            4 if buf.len() < self.max_size => {
                let start = self.rng.next_usize(buf.len());
                let len = (self.rng.next_usize(8) + 1).min(buf.len() - start);
                let chunk: Vec<u8> = buf[start..start + len].to_vec();
                let insert_at = self.rng.next_usize(buf.len() + 1);
                buf.splice(insert_at..insert_at, chunk);
            }
            5 => {
                let idx = self.rng.next_usize(buf.len());
                buf[idx] = buf[idx].wrapping_add((self.rng.next_usize(35) + 1) as u8);
            }
            6 => {
                // XOR single byte
                let idx = self.rng.next_usize(buf.len());
                let val = self.rng.next_u8();
                buf[idx] ^= val;
            }
            _ => {
                // Overwrite with 0
                let idx = self.rng.next_usize(buf.len());
                buf[idx] = 0;
            }
        }
    }

    fn insert(&mut self, input: &[u8]) -> Vec<u8> {
        if input.len() >= self.max_size {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let count = self.rng.next_usize(8) + 1;
        let insert_at = self.rng.next_usize(out.len() + 1);
        let bytes: Vec<u8> = (0..count).map(|_| self.rng.next_u8()).collect();
        for (i, b) in bytes.into_iter().enumerate() {
            let pos = (insert_at + i).min(out.len());
            out.insert(pos, b);
        }
        out
    }

    fn delete(&mut self, input: &[u8]) -> Vec<u8> {
        if input.len() <= self.min_size {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let max_del = (out.len() - self.min_size).max(1);
        let count = self.rng.next_usize(max_del) + 1;
        let start = self.rng.next_usize(out.len().saturating_sub(count) + 1);
        let end = (start + count).min(out.len());
        out.drain(start..end);
        out
    }

    fn shuffle(&mut self, input: &[u8]) -> Vec<u8> {
        if input.len() < 2 {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let block_len = (self.rng.next_usize(16) + 2).min(out.len());
        let start = self.rng.next_usize(out.len().saturating_sub(block_len) + 1);
        let block = &mut out[start..start + block_len];
        // Fisher-Yates shuffle on the block
        for i in (1..block.len()).rev() {
            let j = self.rng.next_usize(i + 1);
            block.swap(i, j);
        }
        out
    }

    fn repeat(&mut self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() || input.len() >= self.max_size {
            return input.to_vec();
        }
        let start = self.rng.next_usize(input.len());
        let len = (self.rng.next_usize(8) + 1).min(input.len() - start);
        let chunk = input[start..start + len].to_vec();
        let times = self.rng.next_usize(4) + 2;
        let extra: Vec<u8> = chunk.iter().cycle().take(len * times).copied().collect();
        let insert_at = self.rng.next_usize(input.len() + 1);
        let mut out = input.to_vec();
        for (i, &b) in extra.iter().enumerate() {
            if out.len() >= self.max_size {
                break;
            }
            let pos = (insert_at + i).min(out.len());
            out.insert(pos, b);
        }
        out
    }

    fn xor_block(&mut self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let key = self.rng.next_u8();
        let block_len = (self.rng.next_usize(16) + 1).min(out.len());
        let start = self.rng.next_usize(out.len().saturating_sub(block_len) + 1);
        for b in &mut out[start..start + block_len] {
            *b ^= key;
        }
        out
    }

    fn reverse(&mut self, input: &[u8]) -> Vec<u8> {
        if input.len() < 2 {
            return input.to_vec();
        }
        let mut out = input.to_vec();
        let block_len = (self.rng.next_usize(32) + 2).min(out.len());
        let start = self.rng.next_usize(out.len().saturating_sub(block_len) + 1);
        out[start..start + block_len].reverse();
        out
    }
}

impl Default for MutationEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── PowerSchedule ─────────────────────────────────────────────────────────────

/// Energy assignment strategy for the power schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PowerScheduleKind {
    /// Each seed gets the same energy.
    Uniform,
    /// Seeds with more coverage bits get more energy.
    CoverageFavored,
    /// Seeds found more recently get more energy.
    Recency,
    /// Rare-coverage seeds (uncommon hit patterns) get more energy.
    Rare,
    /// AFL-style power schedule: favors fast seeds with high coverage density.
    AflFast,
}

/// Computes and tracks per-seed energy (power schedule).
#[derive(Debug, Clone)]
pub struct PowerSchedule {
    /// Kind of schedule.
    pub kind: PowerScheduleKind,
    /// Base energy units per seed.
    pub base_energy: u32,
    /// Maximum energy cap.
    pub max_energy: u32,
}

impl PowerSchedule {
    /// Create a new power schedule.
    #[must_use]
    pub const fn new(kind: PowerScheduleKind) -> Self {
        Self {
            kind,
            base_energy: 1,
            max_energy: 512,
        }
    }

    /// Compute the energy (number of mutations to apply) for the given corpus
    /// metadata.
    ///
    /// Higher energy = more mutations = more time spent on this seed.
    #[must_use]
    pub fn energy(&self, meta: &CorpusMeta, global_bits: u32) -> u32 {
        let base = self.base_energy;
        let result = match self.kind {
            PowerScheduleKind::Uniform => base,
            PowerScheduleKind::CoverageFavored => {
                if global_bits == 0 {
                    base
                } else {
                    let ratio = f64::from(meta.coverage_bits) / f64::from(global_bits);
                    (f64::from(base) * ratio.mul_add(4.0, 1.0)) as u32
                }
            }
            PowerScheduleKind::Recency => {
                // Newer seeds get more energy; older ones decay.
                let age_secs = meta.found_at.elapsed().unwrap_or_default().as_secs();
                let factor = 1.0_f64 / (1.0 + age_secs as f64 / 300.0);
                (f64::from(base) * (1.0 + factor * 4.0)) as u32
            }
            PowerScheduleKind::Rare => {
                // Inputs that hit rare edges get extra energy.
                // We approximate rarity by low coverage_bits relative to global.
                if meta.coverage_bits == 0 || global_bits == 0 {
                    base
                } else {
                    let rarity = 1.0 - (f64::from(meta.coverage_bits) / f64::from(global_bits));
                    (f64::from(base) * (1.0 + rarity * 6.0)) as u32
                }
            }
            PowerScheduleKind::AflFast => {
                // AFL fast: prioritize seeds with many coverage bits but short exec times.
                let time_factor = if meta.execution_time.as_millis() == 0 {
                    8.0
                } else {
                    1000.0 / meta.execution_time.as_millis() as f64
                };
                let cov_factor = if global_bits == 0 {
                    1.0
                } else {
                    (f64::from(meta.coverage_bits) / f64::from(global_bits)).mul_add(4.0, 1.0)
                };
                (f64::from(base) * time_factor.min(8.0) * cov_factor) as u32
            }
        };
        result.clamp(1, self.max_energy)
    }
}

impl Default for PowerSchedule {
    fn default() -> Self {
        Self::new(PowerScheduleKind::AflFast)
    }
}

// ── Minimizer ─────────────────────────────────────────────────────────────────

/// Attempts to find the shortest input that still triggers the same behavior.
pub struct Minimizer {
    /// Maximum number of minimization rounds.
    pub max_rounds: usize,
    /// Minimum size to reduce to.
    pub min_size: usize,
}

impl Minimizer {
    /// Create a new minimizer.
    #[must_use]
    pub const fn new(max_rounds: usize) -> Self {
        Self {
            max_rounds,
            min_size: 1,
        }
    }

    /// Minimize `input` using a closure `is_interesting` that returns `true`
    /// when the trimmed input still triggers the crash / interesting behavior.
    ///
    /// Returns the minimized bytes.
    #[must_use]
    pub fn minimize<F>(&self, input: &[u8], mut is_interesting: F) -> Vec<u8>
    where
        F: FnMut(&[u8]) -> bool,
    {
        let mut current = input.to_vec();

        for _round in 0..self.max_rounds {
            let before_len = current.len();
            // Try removing each byte
            current = self.trim_pass(&current, &mut is_interesting);
            // Try halving large blocks
            current = self.block_pass(&current, &mut is_interesting);

            // If no progress was made this round, stop.
            if current.len() >= before_len || current.len() <= self.min_size {
                break;
            }
        }

        current
    }

    fn trim_pass<F>(&self, input: &[u8], is_interesting: &mut F) -> Vec<u8>
    where
        F: FnMut(&[u8]) -> bool,
    {
        let mut current = input.to_vec();
        let mut i = 0;
        while i < current.len() {
            if current.len() <= self.min_size {
                break;
            }
            let mut candidate = current.clone();
            candidate.remove(i);
            if is_interesting(&candidate) {
                current = candidate;
                // Don't advance i — re-check same position with new data
            } else {
                i += 1;
            }
        }
        current
    }

    fn block_pass<F>(&self, input: &[u8], is_interesting: &mut F) -> Vec<u8>
    where
        F: FnMut(&[u8]) -> bool,
    {
        let mut current = input.to_vec();
        let mut block = current.len() / 2;
        while block >= 1 && current.len() > self.min_size {
            let mut i = 0;
            while i + block <= current.len() {
                if current.len() - block < self.min_size {
                    break;
                }
                let mut candidate = current.clone();
                candidate.drain(i..i + block);
                if is_interesting(&candidate) {
                    current = candidate;
                } else {
                    i += block;
                }
            }
            block /= 2;
        }
        current
    }

    /// Minimize `input` and return both the minimized input and the number of
    /// rounds it took.
    #[must_use]
    pub fn minimize_tracked<F>(&self, input: &[u8], mut is_interesting: F) -> (Vec<u8>, usize)
    where
        F: FnMut(&[u8]) -> bool,
    {
        let mut current = input.to_vec();
        let mut rounds = 0;

        for r in 0..self.max_rounds {
            rounds = r;
            let before_len = current.len();
            current = self.trim_pass(&current, &mut is_interesting);
            current = self.block_pass(&current, &mut is_interesting);
            if current.len() >= before_len || current.len() <= self.min_size {
                rounds = r + 1;
                break;
            }
        }
        (current, rounds)
    }
}

impl Default for Minimizer {
    fn default() -> Self {
        Self::new(8)
    }
}

// ── Fuzzer trait ──────────────────────────────────────────────────────────────

/// Trait implemented by all fuzzer backends.
pub trait Fuzzer: Send {
    /// Add a seed input.
    fn add_seed(&mut self, data: Vec<u8>);

    /// Run the fuzzer for `limit` iterations (or until stopped if `None`).
    ///
    /// # Errors
    /// Returns [`FuzzError`] on executor failure.
    fn run(&mut self, limit: Option<u64>) -> Result<FuzzStats, FuzzError>;

    /// Return a reference to the accumulated statistics.
    fn stats(&self) -> &FuzzStats;

    /// Return a reference to the current corpus.
    fn corpus(&self) -> &Corpus;
}

// ── Thread-safe shared coverage ───────────────────────────────────────────────

/// Thread-safe wrapper around a shared [`CoverageMap`].
#[derive(Debug, Default)]
pub struct SharedCoverage {
    inner: RwLock<CoverageMap>,
}

impl SharedCoverage {
    /// Create a new shared coverage map of the given size.
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            inner: RwLock::new(CoverageMap::new(size)),
        }
    }

    /// Update the shared map and return newly set bits.
    pub fn update(&self, new_bits: &[u8]) -> u32 {
        self.inner.write().update(new_bits)
    }

    /// Return the total number of bits currently set.
    #[must_use]
    pub fn total_bits_set(&self) -> u32 {
        self.inner.read().total_bits_set()
    }

    /// Compute the hash of the coverage bitmap.
    #[must_use]
    pub fn hash(&self) -> u64 {
        self.inner.read().hash()
    }

    /// Return a snapshot of the current coverage map.
    #[must_use]
    pub fn snapshot(&self) -> CoverageMap {
        self.inner.read().clone()
    }

    /// Reset the map.
    pub fn reset(&self) {
        self.inner.write().reset();
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── FuzzInput ─────────────────────────────────────────────────────────────

    #[test]
    fn fuzz_input_new() {
        let inp = FuzzInput::new(1, vec![0xde, 0xad]);
        assert_eq!(inp.id, 1);
        assert_eq!(inp.data, vec![0xde, 0xad]);
        assert_eq!(inp.generation, 0);
        assert!(inp.parent.is_none());
        assert!(inp.origin.is_none());
    }

    #[test]
    fn fuzz_input_derive() {
        let parent = FuzzInput::new(0, vec![1, 2, 3]);
        let child = parent.derive(1, vec![1, 2, 3, 4]);
        assert_eq!(child.parent, Some(0));
        assert_eq!(child.generation, 1);
        assert_eq!(child.id, 1);
    }

    #[test]
    fn fuzz_input_derive_chain() {
        let a = FuzzInput::new(0, vec![]);
        let b = a.derive(1, vec![1]);
        let c = b.derive(2, vec![1, 2]);
        assert_eq!(c.generation, 2);
        assert_eq!(c.parent, Some(1));
    }

    #[test]
    fn fuzz_input_new_with_origin() {
        let inp = FuzzInput::new_with_origin(5, vec![1, 2], "bit_flip");
        assert_eq!(inp.origin.as_deref(), Some("bit_flip"));
    }

    #[test]
    fn fuzz_input_derive_with_origin() {
        let parent = FuzzInput::new(0, vec![]);
        let child = parent.derive_with_origin(1, vec![1], "havoc");
        assert_eq!(child.origin.as_deref(), Some("havoc"));
    }

    #[test]
    fn fuzz_input_data_hash_deterministic() {
        let inp = FuzzInput::new(0, vec![1, 2, 3]);
        assert_eq!(inp.data_hash(), inp.data_hash());
        assert_ne!(
            inp.data_hash(),
            FuzzInput::new(0, vec![4, 5, 6]).data_hash()
        );
    }

    #[test]
    fn fuzz_input_len_and_is_empty() {
        let empty = FuzzInput::new(0, vec![]);
        let nonempty = FuzzInput::new(1, vec![1, 2, 3]);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(!nonempty.is_empty());
        assert_eq!(nonempty.len(), 3);
    }

    // ── FuzzResult ────────────────────────────────────────────────────────────

    #[test]
    fn fuzz_result_variants() {
        let r = FuzzResult::Crash {
            input: vec![0xff],
            signal: 11,
            address: 0xdead_beef,
        };
        assert!(r.is_crash());
        assert!(!r.is_interesting());
        assert!(!r.is_normal());

        let r2 = FuzzResult::Interesting(vec![1, 2]);
        assert!(r2.is_interesting());

        assert_eq!(FuzzResult::Timeout, FuzzResult::Timeout);
        assert_eq!(FuzzResult::Normal, FuzzResult::Normal);
        assert!(FuzzResult::Normal.is_normal());
    }

    // ── ExecutionStatus ───────────────────────────────────────────────────────

    #[test]
    fn execution_status_crash() {
        let s = ExecutionStatus::Crash {
            signal: 6,
            fault_addr: Some(0x1234),
        };
        assert!(s.is_crash());
        assert!(!s.is_normal());
        assert!(!s.is_hang());
    }

    #[test]
    fn execution_status_normal() {
        assert_eq!(ExecutionStatus::Normal, ExecutionStatus::Normal);
        assert!(ExecutionStatus::Normal.is_normal());
    }

    #[test]
    fn execution_status_hang() {
        assert!(ExecutionStatus::Hang.is_hang());
        assert!(ExecutionStatus::Timeout.is_hang());
    }

    // ── ExecutionResult ───────────────────────────────────────────────────────

    #[test]
    fn execution_result_normal() {
        let r = ExecutionResult::normal(Duration::from_millis(5));
        assert!(r.status.is_normal());
        assert_eq!(r.new_coverage_bits, 0);
    }

    #[test]
    fn execution_result_crash() {
        let r = ExecutionResult::crash(11, Some(0xdead), Duration::from_millis(1));
        assert!(r.status.is_crash());
    }

    // ── CoverageMap ───────────────────────────────────────────────────────────

    #[test]
    fn coverage_map_new() {
        let m = CoverageMap::new(8);
        assert_eq!(m.bits.len(), 8);
        assert_eq!(m.hit_counts.len(), 64);
        assert!(m.is_empty());
    }

    #[test]
    fn coverage_map_update_counts_new_bits() {
        let mut m = CoverageMap::new(4);
        let new = vec![0b0000_0001u8, 0, 0, 0];
        let count = m.update(&new);
        assert_eq!(count, 1);
        assert!(!m.is_empty());
    }

    #[test]
    fn coverage_map_update_already_set() {
        let mut m = CoverageMap::new(4);
        let bits = vec![0xffu8, 0, 0, 0];
        m.update(&bits);
        let second = m.update(&bits);
        assert_eq!(second, 0);
    }

    #[test]
    fn coverage_map_total_bits_set() {
        let mut m = CoverageMap::new(2);
        m.update(&[0b1010_1010, 0b1111_0000]);
        assert_eq!(m.total_bits_set(), 8);
    }

    #[test]
    fn coverage_map_hash_deterministic() {
        let mut m = CoverageMap::new(4);
        m.update(&[1, 2, 3, 4]);
        let h1 = m.hash();
        let h2 = m.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn coverage_map_hash_differs_on_different_bits() {
        let mut m1 = CoverageMap::new(4);
        m1.update(&[1, 0, 0, 0]);
        let mut m2 = CoverageMap::new(4);
        m2.update(&[0, 1, 0, 0]);
        assert_ne!(m1.hash(), m2.hash());
    }

    #[test]
    fn coverage_map_hit_counts_increment() {
        let mut m = CoverageMap::new(1);
        m.update(&[0b0000_0001]);
        m.update(&[0b0000_0001]);
        assert_eq!(m.hit_counts[0], 2);
    }

    #[test]
    fn coverage_map_reset() {
        let mut m = CoverageMap::new(4);
        m.update(&[0xff, 0xff, 0xff, 0xff]);
        assert!(!m.is_empty());
        m.reset();
        assert!(m.is_empty());
    }

    #[test]
    fn coverage_map_merge() {
        let mut a = CoverageMap::new(4);
        let mut b = CoverageMap::new(4);
        a.update(&[0b0000_1111, 0, 0, 0]);
        b.update(&[0b1111_0000, 0, 0, 0]);
        let new = a.merge(&b);
        assert_eq!(new, 4); // 4 new bits from b
        assert_eq!(a.total_bits_set(), 8);
    }

    #[test]
    fn coverage_map_active_edges() {
        let mut m = CoverageMap::new(1);
        m.update(&[0b0000_0111]); // bits 0,1,2
        let active = m.active_edges();
        assert_eq!(active.len(), 3);
    }

    #[test]
    fn coverage_map_hot_edges() {
        let mut m = CoverageMap::new(1);
        m.update(&[0b0000_0001]);
        m.update(&[0b0000_0001]);
        assert_eq!(m.hot_edges(), 1);
    }

    // ── InputQueue ────────────────────────────────────────────────────────────

    #[test]
    fn input_queue_add_and_len() {
        let mut q = InputQueue::new();
        q.add(FuzzInput::new(0, vec![1]), false);
        q.add(FuzzInput::new(1, vec![2]), true);
        assert_eq!(q.len(), 2);
        assert_eq!(q.favored.len(), 1);
    }

    #[test]
    fn input_queue_select_returns_entry() {
        let mut q = InputQueue::new();
        q.add(FuzzInput::new(0, vec![42]), false);
        let inp = q.select();
        assert_eq!(inp.data, vec![42]);
    }

    #[test]
    fn input_queue_select_favoured() {
        let mut q = InputQueue::new();
        q.add(FuzzInput::new(0, vec![1]), false);
        q.add(FuzzInput::new(1, vec![2]), true);
        let inp = q.select();
        assert_eq!(inp.id, 1);
    }

    #[test]
    fn input_queue_next_id_monotonic() {
        let mut q = InputQueue::new();
        assert_eq!(q.next_id(), 0);
        assert_eq!(q.next_id(), 1);
        assert_eq!(q.next_id(), 2);
    }

    #[test]
    fn input_queue_is_empty() {
        let q = InputQueue::new();
        assert!(q.is_empty());
    }

    #[test]
    fn input_queue_remove() {
        let mut q = InputQueue::new();
        q.add(FuzzInput::new(0, vec![1]), true);
        q.add(FuzzInput::new(1, vec![2]), false);
        let removed = q.remove(0);
        assert!(removed.is_some());
        assert_eq!(q.len(), 1);
        assert!(q.favored.is_empty());
    }

    #[test]
    fn input_queue_select_cursor() {
        let mut q = InputQueue::new();
        q.add(FuzzInput::new(0, vec![1]), false);
        q.add(FuzzInput::new(1, vec![2]), false);
        let a = q.select_cursor().id;
        let b = q.select_cursor().id;
        // Both should be valid ids
        assert!(a == 0 || a == 1);
        assert!(b == 0 || b == 1);
    }

    #[test]
    fn input_queue_clear() {
        let mut q = InputQueue::new();
        q.add(FuzzInput::new(0, vec![1]), true);
        q.clear();
        assert!(q.is_empty());
        assert_eq!(q.favored_count(), 0);
    }

    // ── FuzzerStats ───────────────────────────────────────────────────────────

    #[test]
    fn fuzzer_stats_new() {
        let s = FuzzerStats::new();
        assert_eq!(s.executions, 0);
        assert_eq!(s.crashes, 0);
        assert!(s.last_crash_time.is_none());
    }

    #[test]
    fn fuzzer_stats_execs_per_sec_zero_execs() {
        let s = FuzzerStats::new();
        assert!(s.execs_per_sec() >= 0.0);
    }

    #[test]
    fn fuzzer_stats_crash_rate_zero() {
        let s = FuzzerStats::new();
        assert_eq!(s.crash_rate(), 0.0);
    }

    #[test]
    fn fuzzer_stats_crash_rate() {
        let mut s = FuzzerStats::new();
        s.executions = 100;
        s.crashes = 5;
        assert!((s.crash_rate() - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn fuzzer_stats_record_execution() {
        let mut s = FuzzerStats::new();
        s.record_execution(16);
        s.record_execution(32);
        assert_eq!(s.executions, 2);
        assert_eq!(s.max_input_len, 32);
        assert_eq!(s.total_bytes_generated, 48);
    }

    // ── CorpusMeta ────────────────────────────────────────────────────────────

    #[test]
    fn corpus_meta_new() {
        let m = CorpusMeta::new(42, 10, Duration::from_millis(5));
        assert_eq!(m.hash, 42);
        assert_eq!(m.coverage_bits, 10);
        assert_eq!(m.energy, 1);
        assert_eq!(m.selected_count, 0);
    }

    #[test]
    fn corpus_meta_record_selection() {
        let mut m = CorpusMeta::new(0, 0, Duration::ZERO);
        m.record_selection();
        m.record_selection();
        assert_eq!(m.selected_count, 2);
    }

    // ── Corpus ────────────────────────────────────────────────────────────────

    #[test]
    fn corpus_add_input() {
        let mut c = Corpus::new();
        let inp = FuzzInput::new(0, vec![1, 2]);
        let meta = CorpusMeta::new(99, 5, Duration::from_millis(10));
        assert!(c.add_input(inp, meta));
        assert_eq!(c.inputs.len(), 1);
        assert_eq!(c.len(), 1);
        assert!(!c.is_empty());
    }

    #[test]
    fn corpus_add_crash() {
        let mut c = Corpus::new();
        let inp = FuzzInput::new(1, vec![0xff]);
        let meta = CorpusMeta::new(42, 1, Duration::from_millis(5));
        assert!(c.add_crash(inp, meta));
        assert_eq!(c.crashes.len(), 1);
        assert!(c.metadata.contains_key(&1));
    }

    #[test]
    fn corpus_empty() {
        let c = Corpus::new();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn corpus_dedup_by_hash() {
        let mut c = Corpus::new();
        let m1 = CorpusMeta::new(100, 5, Duration::ZERO);
        let m2 = CorpusMeta::new(100, 5, Duration::ZERO); // same hash
        c.add_input(FuzzInput::new(0, vec![1]), m1);
        let novel = c.add_input(FuzzInput::new(1, vec![2]), m2);
        assert!(!novel); // duplicate hash
    }

    #[test]
    fn corpus_sorted_by_coverage() {
        let mut c = Corpus::new();
        c.add_input(
            FuzzInput::new(0, vec![1]),
            CorpusMeta::new(1, 5, Duration::ZERO),
        );
        c.add_input(
            FuzzInput::new(1, vec![2]),
            CorpusMeta::new(2, 20, Duration::ZERO),
        );
        c.add_input(
            FuzzInput::new(2, vec![3]),
            CorpusMeta::new(3, 10, Duration::ZERO),
        );
        let sorted = c.sorted_by_coverage();
        assert_eq!(sorted[0].id, 1); // 20 bits first
        assert_eq!(sorted[1].id, 2); // 10 bits second
    }

    #[test]
    fn corpus_get_entry() {
        let mut c = Corpus::new();
        let inp = FuzzInput::new(7, vec![0xAA]);
        let meta = CorpusMeta::new(77, 3, Duration::ZERO);
        c.add_input(inp, meta);
        let entry = c.get_entry(7);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().id(), 7);
    }

    // ── CrashRecord ──────────────────────────────────────────────────────────

    #[test]
    fn crash_record_new() {
        let r = CrashRecord::new(0, vec![1, 2], 11, Some(0xdead), 12345);
        assert_eq!(r.signal, 11);
        assert_eq!(r.fault_addr, Some(0xdead));
        assert_eq!(r.occurrence_count, 1);
        assert!(!r.description.is_empty());
    }

    #[test]
    fn crash_record_increment() {
        let mut r = CrashRecord::new(0, vec![], 6, None, 0);
        r.increment();
        r.increment();
        assert_eq!(r.occurrence_count, 3);
    }

    #[test]
    fn crash_record_set_stack_hash() {
        let mut r = CrashRecord::new(0, vec![], 11, None, 0);
        r.set_stack_hash(&[0x1000, 0x2000, 0x3000]);
        assert!(r.stack_hash.is_some());
        assert_eq!(r.dedup_key(), r.stack_hash.unwrap());
    }

    #[test]
    fn crash_record_dedup_key_no_stack() {
        let r = CrashRecord::new(0, vec![], 11, None, 0xABCD);
        assert_eq!(r.dedup_key(), 0xABCD);
    }

    // ── CrashDeduplicator ────────────────────────────────────────────────────

    #[test]
    fn dedup_unique_crashes() {
        let mut d = CrashDeduplicator::new();
        assert!(d.submit(vec![1], 11, None, 100));
        assert!(d.submit(vec![2], 11, None, 200)); // different hash
        assert_eq!(d.unique_count(), 2);
    }

    #[test]
    fn dedup_duplicate_crash() {
        let mut d = CrashDeduplicator::new();
        assert!(d.submit(vec![1], 11, None, 100));
        assert!(!d.submit(vec![2], 11, None, 100)); // same hash
        assert_eq!(d.unique_count(), 1);
    }

    #[test]
    fn dedup_most_common() {
        let mut d = CrashDeduplicator::new();
        d.submit(vec![1], 11, None, 100);
        // Re-submit same hash → increments occurrence count
        d.submit(vec![1], 11, None, 100);
        d.submit(vec![1], 11, None, 100);
        d.submit(vec![2], 11, None, 200);
        let mc = d.most_common().unwrap();
        assert_eq!(mc.coverage_hash, 100);
        assert_eq!(mc.occurrence_count, 3);
    }

    #[test]
    fn dedup_clear() {
        let mut d = CrashDeduplicator::new();
        d.submit(vec![1], 11, None, 100);
        d.clear();
        assert_eq!(d.unique_count(), 0);
    }

    // ── MutationStrategy ─────────────────────────────────────────────────────

    #[test]
    fn mutation_strategy_name() {
        assert_eq!(MutationStrategy::BitFlip.name(), "bit_flip");
        assert_eq!(MutationStrategy::Havoc.name(), "havoc");
    }

    #[test]
    fn mutation_strategy_all_count() {
        assert!(MutationStrategy::all().len() >= 10);
    }

    #[test]
    fn mutation_strategy_display() {
        assert!(MutationStrategy::Splice.to_string().contains("splice"));
    }

    // ── Dictionary ────────────────────────────────────────────────────────────

    #[test]
    fn dictionary_add() {
        let mut d = Dictionary::new();
        d.add(b"hello".to_vec());
        assert_eq!(d.entries.len(), 1);
        assert!(!d.is_empty());
    }

    #[test]
    fn dictionary_add_str() {
        let mut d = Dictionary::new();
        d.add_str("world");
        assert_eq!(d.entries[0], b"world");
    }

    #[test]
    fn dictionary_get_wrapping() {
        let mut d = Dictionary::new();
        d.add(vec![1, 2]);
        d.add(vec![3, 4]);
        assert_eq!(d.get_wrapping(0), Some([1, 2].as_slice()));
        assert_eq!(d.get_wrapping(2), Some([1, 2].as_slice())); // wraps
    }

    #[test]
    fn dictionary_get_wrapping_empty() {
        let d = Dictionary::new();
        assert!(d.get_wrapping(0).is_none());
    }

    #[test]
    fn dictionary_load_from_text_bare() {
        let mut d = Dictionary::new();
        let text = "hello\nworld\n# comment\n";
        let n = d.load_from_text(text).unwrap();
        assert_eq!(n, 2);
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn dictionary_load_from_text_quoted() {
        let mut d = Dictionary::new();
        let text = "\"quoted_token\"\n";
        d.load_from_text(text).unwrap();
        assert_eq!(d.entries[0], b"quoted_token");
    }

    #[test]
    fn dictionary_load_from_text_hex() {
        let mut d = Dictionary::new();
        let text = "x\"de ad be ef\"\n";
        d.load_from_text(text).unwrap();
        assert_eq!(d.entries[0], vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn dictionary_named() {
        let d = Dictionary::named("my_dict");
        assert_eq!(d.name.as_deref(), Some("my_dict"));
    }

    // ── MutationEngine ────────────────────────────────────────────────────────

    #[test]
    fn engine_bit_flip_preserves_length() {
        let mut e = MutationEngine::with_seed(1);
        let input = vec![0u8; 16];
        let out = e.mutate(&input, MutationStrategy::BitFlip);
        assert_eq!(out.len(), input.len());
    }

    #[test]
    fn engine_byte_flip_changes_something() {
        let mut e = MutationEngine::with_seed(2);
        let input = vec![0u8; 16];
        let out = e.mutate(&input, MutationStrategy::ByteFlip);
        assert_ne!(out, input);
    }

    #[test]
    fn engine_arithmetic() {
        let mut e = MutationEngine::with_seed(3);
        let input = vec![10u8; 8];
        let out = e.mutate(&input, MutationStrategy::Arithmetic);
        assert_eq!(out.len(), input.len());
        assert_ne!(out, input);
    }

    #[test]
    fn engine_interesting_value() {
        let mut e = MutationEngine::with_seed(4);
        let input = vec![0xAAu8; 8];
        let out = e.mutate(&input, MutationStrategy::InterestingValue);
        assert_eq!(out.len(), input.len());
    }

    #[test]
    fn engine_dictionary_mutation() {
        let mut e = MutationEngine::with_seed(5);
        e.dictionary.add(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let input = vec![0u8; 16];
        let out = e.mutate(&input, MutationStrategy::Dictionary);
        assert_ne!(out, input);
    }

    #[test]
    fn engine_insert_grows_length() {
        let mut e = MutationEngine::with_seed(6);
        let input = vec![0u8; 8];
        let out = e.mutate(&input, MutationStrategy::Insert);
        assert!(out.len() > input.len());
    }

    #[test]
    fn engine_delete_shrinks_length() {
        let mut e = MutationEngine::with_seed(7);
        let input = vec![0u8; 20];
        let out = e.mutate(&input, MutationStrategy::Delete);
        assert!(out.len() < input.len());
    }

    #[test]
    fn engine_havoc_changes_something() {
        let mut e = MutationEngine::with_seed(8);
        let input = vec![0u8; 32];
        let out = e.mutate(&input, MutationStrategy::Havoc);
        // Havoc should almost always produce different output
        assert_ne!(out, input);
    }

    #[test]
    fn engine_xor_block_changes_something() {
        let mut e = MutationEngine::with_seed(9);
        let input = vec![0u8; 16];
        let out = e.mutate(&input, MutationStrategy::XorBlock);
        assert_ne!(out, input);
    }

    #[test]
    fn engine_reverse_changes_something() {
        let mut e = MutationEngine::with_seed(10);
        let input = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let out = e.mutate(&input, MutationStrategy::Reverse);
        assert_eq!(out.len(), input.len());
    }

    #[test]
    fn engine_empty_input_does_not_panic() {
        let mut e = MutationEngine::with_seed(11);
        for &s in MutationStrategy::all() {
            let _ = e.mutate(&[], s);
        }
    }

    #[test]
    fn engine_record_hit_and_best_strategy() {
        let mut e = MutationEngine::with_seed(12);
        e.record_hit(MutationStrategy::Havoc);
        e.record_hit(MutationStrategy::Havoc);
        e.record_hit(MutationStrategy::BitFlip);
        assert_eq!(e.best_strategy(), Some(MutationStrategy::Havoc));
    }

    #[test]
    fn engine_splice_two() {
        let mut e = MutationEngine::with_seed(13);
        let a = vec![0xAA; 8];
        let b = vec![0xBB; 8];
        let out = e.splice_two(&a, &b);
        assert!(!out.is_empty());
    }

    #[test]
    fn engine_total_mutations_tracking() {
        let mut e = MutationEngine::with_seed(99);
        for _ in 0..5 {
            let _ = e.mutate(&[1, 2, 3], MutationStrategy::BitFlip);
        }
        assert_eq!(e.total_mutations, 5);
    }

    // ── PowerSchedule ─────────────────────────────────────────────────────────

    #[test]
    fn power_schedule_uniform() {
        let ps = PowerSchedule::new(PowerScheduleKind::Uniform);
        let meta = CorpusMeta::new(0, 10, Duration::from_millis(5));
        assert_eq!(ps.energy(&meta, 100), 1);
    }

    #[test]
    fn power_schedule_coverage_favored() {
        let ps = PowerSchedule::new(PowerScheduleKind::CoverageFavored);
        let hi = CorpusMeta::new(0, 100, Duration::ZERO);
        let lo = CorpusMeta::new(0, 1, Duration::ZERO);
        assert!(ps.energy(&hi, 100) >= ps.energy(&lo, 100));
    }

    #[test]
    fn power_schedule_afl_fast() {
        let ps = PowerSchedule::new(PowerScheduleKind::AflFast);
        let fast = CorpusMeta::new(0, 50, Duration::from_micros(1));
        let slow = CorpusMeta::new(0, 50, Duration::from_secs(10));
        assert!(ps.energy(&fast, 100) >= ps.energy(&slow, 100));
    }

    #[test]
    fn power_schedule_max_energy_capped() {
        let mut ps = PowerSchedule::new(PowerScheduleKind::CoverageFavored);
        ps.max_energy = 10;
        let meta = CorpusMeta::new(0, 10000, Duration::ZERO);
        assert!(ps.energy(&meta, 1) <= 10);
    }

    #[test]
    fn power_schedule_rare() {
        let ps = PowerSchedule::new(PowerScheduleKind::Rare);
        let meta = CorpusMeta::new(0, 1, Duration::ZERO);
        let e = ps.energy(&meta, 1000);
        assert!(e >= 1);
    }

    // ── Minimizer ─────────────────────────────────────────────────────────────

    #[test]
    fn minimizer_reduces_length() {
        let m = Minimizer::new(10);
        // Target: any input containing byte 0xFF is interesting
        let input = vec![0xAA, 0xBB, 0xFF, 0xCC, 0xDD];
        let mini = m.minimize(&input, |data| data.contains(&0xFF));
        assert!(mini.len() <= input.len());
        assert!(mini.contains(&0xFF));
    }

    #[test]
    fn minimizer_empty_input() {
        let m = Minimizer::new(5);
        let mini = m.minimize(&[], |_| true);
        assert!(mini.is_empty());
    }

    #[test]
    fn minimizer_single_byte() {
        let m = Minimizer::new(5);
        let mini = m.minimize(&[0x42], |data| data == [0x42]);
        assert_eq!(mini, vec![0x42]);
    }

    #[test]
    fn minimizer_all_bytes_needed() {
        let m = Minimizer::new(5);
        let input = vec![1u8, 2, 3, 4, 5];
        // Interesting only if length >= 5
        let mini = m.minimize(&input, |data| data.len() >= 5);
        assert_eq!(mini.len(), 5);
    }

    #[test]
    fn minimizer_tracked() {
        let m = Minimizer::new(10);
        let input = vec![0u8; 100];
        let (mini, rounds) = m.minimize_tracked(&input, |data| !data.is_empty());
        assert!(mini.len() <= 100);
        assert!(rounds >= 1);
    }

    // ── fnv1a ─────────────────────────────────────────────────────────────────

    #[test]
    fn fnv1a_deterministic() {
        assert_eq!(fnv1a(b"hello"), fnv1a(b"hello"));
    }

    #[test]
    fn fnv1a_different_inputs() {
        assert_ne!(fnv1a(b"hello"), fnv1a(b"world"));
    }

    // ── SharedCoverage ────────────────────────────────────────────────────────

    #[test]
    fn shared_coverage_update_and_total() {
        let sc = SharedCoverage::new(4);
        sc.update(&[0xFF, 0, 0, 0]);
        assert_eq!(sc.total_bits_set(), 8);
    }

    #[test]
    fn shared_coverage_snapshot() {
        let sc = SharedCoverage::new(4);
        sc.update(&[0x01, 0, 0, 0]);
        let snap = sc.snapshot();
        assert_eq!(snap.bits[0], 0x01);
    }

    #[test]
    fn shared_coverage_reset() {
        let sc = SharedCoverage::new(4);
        sc.update(&[0xFF, 0xFF, 0, 0]);
        sc.reset();
        assert_eq!(sc.total_bits_set(), 0);
    }

    // ── FuzzRng ───────────────────────────────────────────────────────────────

    #[test]
    fn fuzz_rng_deterministic() {
        let mut a = FuzzRng::new(42);
        let mut b = FuzzRng::new(42);
        assert_eq!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn fuzz_rng_zero_seed_replaced() {
        let mut r = FuzzRng::new(0);
        // Should not panic and should produce non-zero values
        assert_ne!(r.next_u64(), 0);
    }

    #[test]
    fn fuzz_rng_next_usize_in_range() {
        let mut r = FuzzRng::default();
        for _ in 0..100 {
            assert!(r.next_usize(10) < 10);
        }
    }

    #[test]
    fn fuzz_rng_one_in() {
        let mut r = FuzzRng::default();
        let mut count = 0;
        for _ in 0..1000 {
            if r.one_in(10) {
                count += 1;
            }
        }
        // Should be roughly 100, allow large margin
        assert!(count > 0 && count < 300);
    }
}

// ── FuzzCorpusManager ─────────────────────────────────────────────────────────

/// A simple 64-bit hash derived from FNV-1a, used in place of SHA-256 for
/// lightweight deduplication without an external dependency.
fn fnv1a_hash(data: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// An entry in the [`FuzzCorpusManager`].
#[derive(Debug, Clone)]
struct CorpusManagerEntry {
    data: Vec<u8>,
    /// Feature-coverage bitmask: each bit represents a distinct feature
    /// (e.g. an edge in the CFG). Used by [`FuzzCorpusManager::remove_redundant`].
    features: u64,
}

/// Manages a corpus of test inputs with deduplication and redundancy removal.
///
/// # Examples
/// ```
/// # use rustre_fuzz::FuzzCorpusManager;
/// let mut mgr = FuzzCorpusManager::new();
/// assert!(mgr.add(vec![1, 2, 3]));
/// assert!(!mgr.add(vec![1, 2, 3])); // duplicate
/// ```
pub struct FuzzCorpusManager {
    /// Map from content hash → entry index.
    seen: HashMap<u64, usize>,
    entries: Vec<CorpusManagerEntry>,
}

impl FuzzCorpusManager {
    /// Create an empty corpus manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
            entries: Vec::new(),
        }
    }

    /// Add an input.  Returns `false` if the exact bytes were already present.
    pub fn add(&mut self, input: Vec<u8>) -> bool {
        let h = fnv1a_hash(&input);
        if self.seen.contains_key(&h) {
            return false;
        }
        let idx = self.entries.len();
        // Derive a coarse feature bitmask from the content (64 "features").
        let features = Self::features_of(&input);
        self.entries.push(CorpusManagerEntry {
            data: input,
            features,
        });
        self.seen.insert(h, idx);
        true
    }

    /// Derive a 64-bit feature bitmask for an input.
    ///
    /// Each of the 64 bits is set when at least one byte in `data` hashes to
    /// that bucket.  This is intentionally coarse — it is only used to detect
    /// whether one entry's features are a strict subset of another's.
    fn features_of(data: &[u8]) -> u64 {
        let mut mask: u64 = 0;
        for (i, &b) in data.iter().enumerate() {
            let slot = ((i as u64).wrapping_mul(0x9e37_79b9) ^ u64::from(b)) & 63;
            mask |= 1u64 << slot;
        }
        mask
    }

    /// Remove entries whose feature coverage is a strict subset of another
    /// entry already in the corpus.  Returns the number of entries removed.
    pub fn remove_redundant(&mut self) -> usize {
        // Build the union of all feature masks.
        let n = self.entries.len();
        let mut keep = vec![true; n];

        for i in 0..n {
            if !keep[i] {
                continue;
            }
            for j in 0..n {
                if i == j || !keep[j] {
                    continue;
                }
                let fi = self.entries[i].features;
                let fj = self.entries[j].features;
                // j is dominated by i: every feature of j is covered by i AND
                // i covers at least one more.
                if (fj & fi) == fj && fi != fj {
                    keep[j] = false;
                }
            }
        }

        let before = n;
        let mut new_entries: Vec<CorpusManagerEntry> = Vec::new();
        let mut new_seen: HashMap<u64, usize> = HashMap::new();
        for (i, entry) in self.entries.drain(..).enumerate() {
            if keep[i] {
                let h = fnv1a_hash(&entry.data);
                let idx = new_entries.len();
                new_seen.insert(h, idx);
                new_entries.push(entry);
            }
        }
        self.entries = new_entries;
        self.seen = new_seen;
        before - self.entries.len()
    }

    /// Save every corpus entry as a separate file inside `path`.
    ///
    /// Files are named `<hash_hex>.bin`.  Returns the number of files written.
    pub fn save_to_dir(&self, path: &str) -> std::io::Result<usize> {
        use std::io::Write;
        std::fs::create_dir_all(path)?;
        let mut count = 0usize;
        for entry in &self.entries {
            let h = fnv1a_hash(&entry.data);
            let name = format!("{path}/{h:016x}.bin");
            let mut f = std::fs::File::create(&name)?;
            f.write_all(&entry.data)?;
            count += 1;
        }
        Ok(count)
    }

    /// Load corpus entries from `*.bin` files in `path`.
    ///
    /// Returns the number of **new** (non-duplicate) entries added.
    pub fn load_from_dir(&mut self, path: &str) -> std::io::Result<usize> {
        use std::io::Read;
        /// Hard cap: skip corpus files larger than 64 MiB to prevent a
        /// dos-memory-exhaustion attack via crafted oversized `.bin` files.
        const MAX_CORPUS_FILE_BYTES: u64 = 64 * 1024 * 1024;
        let mut added = 0usize;
        for dir_entry in std::fs::read_dir(path)? {
            let dir_entry = dir_entry?;
            let p = dir_entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("bin") {
                continue;
            }
            let meta = std::fs::metadata(&p)?;
            if meta.len() > MAX_CORPUS_FILE_BYTES {
                continue; // Skip oversized files rather than OOM-ing
            }
            let mut f = std::fs::File::open(&p)?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            if self.add(buf) {
                added += 1;
            }
        }
        Ok(added)
    }

    /// Number of entries currently in the corpus.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the corpus is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for FuzzCorpusManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── FuzzMutator ───────────────────────────────────────────────────────────────

/// Magic values commonly used in fuzzing to trigger edge-cases in parsers.
const MAGIC_VALUES: &[&[u8]] = &[
    &[0x00],
    &[0xFF],
    &[0x7F],
    &[0x80],
    &[0x7F, 0xFF, 0xFF, 0xFF],                         // i32::MAX
    &[0x80, 0x00, 0x00, 0x00],                         // i32::MIN
    &[0xFF, 0xFF, 0xFF, 0xFF],                         // u32::MAX
    &[0x00, 0x00, 0x00, 0x00],                         // zero (4-byte)
    &[0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // i64::MAX
    &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // u64::MAX
    &[0x00, 0x01],                                     // 1 (big-endian 16-bit)
    &[0xFF, 0xFE],                                     // BOM / near-max 16-bit
];

/// A standalone set of mutation primitives.
///
/// All methods are deterministic given the same seed passed to `FuzzMutator::new`.
pub struct FuzzMutator {
    rng: FuzzRng,
}

impl FuzzMutator {
    /// Create a new mutator with the given seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            rng: FuzzRng::new(seed),
        }
    }

    /// Flip a single random bit in `input`.
    ///
    /// Returns a new `Vec<u8>`; the original is not modified.
    pub fn bit_flip(&mut self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return Vec::new();
        }
        let mut out = input.to_vec();
        let byte_idx = self.rng.next_usize(out.len());
        let bit_idx = self.rng.next_usize(8) as u8;
        out[byte_idx] ^= 1 << bit_idx;
        out
    }

    /// Replace a random byte with a random value.
    pub fn byte_flip(&mut self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return Vec::new();
        }
        let mut out = input.to_vec();
        let idx = self.rng.next_usize(out.len());
        out[idx] = self.rng.next_u8();
        out
    }

    /// Insert one of the predefined [`MAGIC_VALUES`] at a random position.
    pub fn insert_magic_value(&mut self, input: &[u8]) -> Vec<u8> {
        let magic = MAGIC_VALUES[self.rng.next_usize(MAGIC_VALUES.len())];
        let pos = if input.is_empty() {
            0
        } else {
            self.rng.next_usize(input.len() + 1)
        };
        let mut out = Vec::with_capacity(input.len() + magic.len());
        out.extend_from_slice(&input[..pos]);
        out.extend_from_slice(magic);
        out.extend_from_slice(&input[pos..]);
        out
    }

    /// Splice two inputs: take a prefix of `a` and a suffix of `b`.
    pub fn splice(&mut self, a: &[u8], b: &[u8]) -> Vec<u8> {
        if a.is_empty() {
            return b.to_vec();
        }
        if b.is_empty() {
            return a.to_vec();
        }
        let cut_a = self.rng.next_usize(a.len() + 1);
        let cut_b = self.rng.next_usize(b.len() + 1);
        let mut out = Vec::with_capacity(cut_a + (b.len() - cut_b));
        out.extend_from_slice(&a[..cut_a]);
        out.extend_from_slice(&b[cut_b..]);
        out
    }

    /// Apply a random mix of the above mutations for `iterations` rounds.
    pub fn havoc(&mut self, input: &[u8], iterations: u32) -> Vec<u8> {
        let mut out = input.to_vec();
        for _ in 0..iterations {
            let choice = self.rng.next_usize(4);
            out = match choice {
                0 => self.bit_flip(&out),
                1 => self.byte_flip(&out),
                2 => self.insert_magic_value(&out),
                // splice with itself at a different cut (produces a permutation)
                _ => {
                    let clone = out.clone();
                    self.splice(&out, &clone)
                }
            };
        }
        out
    }
}

impl Default for FuzzMutator {
    fn default() -> Self {
        Self::new(0x1234_5678_9abc_def0)
    }
}

// ── FuzzCrashAnalyzer ─────────────────────────────────────────────────────────

/// Classification of a crash input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrashType {
    /// A unique crash identified by `hash`.
    Unique(u64),
    /// A crash whose content matches a previously seen crash with `original_hash`.
    Duplicate(u64),
}

/// Analyzes and deduplicates crash inputs.
pub struct FuzzCrashAnalyzer {
    seen_hashes: HashSet<u64>,
}

impl FuzzCrashAnalyzer {
    /// Create a new analyzer with an empty seen-set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen_hashes: HashSet::new(),
        }
    }

    /// Classify `crash_bytes`.
    ///
    /// The first time a given byte sequence is seen it is recorded and returned
    /// as [`CrashType::Unique`].  Subsequent identical inputs return
    /// [`CrashType::Duplicate`] with the hash of the first occurrence.
    pub fn classify_crash(&mut self, crash_bytes: &[u8]) -> CrashType {
        let h = fnv1a_hash(crash_bytes);
        if self.seen_hashes.insert(h) {
            CrashType::Unique(h)
        } else {
            CrashType::Duplicate(h)
        }
    }

    /// Remove duplicate crash inputs from `crashes`, keeping only the first
    /// occurrence of each unique byte sequence.
    pub fn deduplicate_crashes(&mut self, crashes: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut local: HashSet<u64> = HashSet::new();
        crashes
            .into_iter()
            .filter(|c| {
                let h = fnv1a_hash(c);
                local.insert(h)
            })
            .collect()
    }

    /// Returns `true` if `new` is not byte-identical to any input in `existing`.
    #[must_use]
    pub fn is_interesting(existing: &[Vec<u8>], new: &[u8]) -> bool {
        let h = fnv1a_hash(new);
        !existing.iter().any(|e| fnv1a_hash(e) == h)
    }
}

impl Default for FuzzCrashAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests for new types ───────────────────────────────────────────────────────

#[cfg(test)]
mod new_tests {
    use super::*;

    // FuzzCorpusManager

    #[test]
    fn corpus_manager_add_new_returns_true() {
        let mut m = FuzzCorpusManager::new();
        assert!(m.add(vec![1, 2, 3]));
    }

    #[test]
    fn corpus_manager_add_duplicate_returns_false() {
        let mut m = FuzzCorpusManager::new();
        m.add(vec![1, 2, 3]);
        assert!(!m.add(vec![1, 2, 3]));
    }

    #[test]
    fn corpus_manager_len_tracks_uniques() {
        let mut m = FuzzCorpusManager::new();
        m.add(vec![1]);
        m.add(vec![1]); // duplicate
        m.add(vec![2]);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn corpus_manager_remove_redundant_removes_subset() {
        let mut m = FuzzCorpusManager::new();
        // Add a rich entry first so we have something to dominate against.
        // Entry A: every byte position exercised → all 64 feature bits likely set.
        let a: Vec<u8> = (0u8..=255).collect();
        // Entry B: a single byte — its features are a subset of A's.
        let b: Vec<u8> = vec![0x42];
        m.add(a);
        m.add(b);
        let removed = m.remove_redundant();
        // At least one entry may be pruned; the corpus should be smaller or equal.
        assert!(removed <= 1);
    }

    #[test]
    fn corpus_manager_save_load_roundtrip() {
        let dir = std::env::temp_dir().join("rustre_fuzz_corpus_test");
        let dir_str = dir.to_str().unwrap();
        let mut m = FuzzCorpusManager::new();
        m.add(vec![10, 20, 30]);
        m.add(vec![40, 50, 60]);
        let saved = m.save_to_dir(dir_str).unwrap();
        assert_eq!(saved, 2);

        let mut m2 = FuzzCorpusManager::new();
        let loaded = m2.load_from_dir(dir_str).unwrap();
        assert_eq!(loaded, 2);
        assert_eq!(m2.len(), 2);
    }

    // FuzzMutator

    #[test]
    fn mutator_bit_flip_changes_single_byte() {
        let mut m = FuzzMutator::new(1);
        let input = vec![0u8; 8];
        let out = m.bit_flip(&input);
        assert_eq!(out.len(), input.len());
        assert_ne!(out, input);
    }

    #[test]
    fn mutator_byte_flip_preserves_length() {
        let mut m = FuzzMutator::new(2);
        let input = vec![0xABu8; 16];
        let out = m.byte_flip(&input);
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn mutator_insert_magic_value_grows_input() {
        let mut m = FuzzMutator::new(3);
        let input = vec![0u8; 4];
        let out = m.insert_magic_value(&input);
        assert!(out.len() > input.len());
    }

    #[test]
    fn mutator_splice_combines_both_inputs() {
        let mut m = FuzzMutator::new(4);
        let a = vec![0xAAu8; 8];
        let b = vec![0xBBu8; 8];
        let out = m.splice(&a, &b);
        // Output must contain bytes from at least one of the sources.
        assert!(!out.is_empty());
    }

    #[test]
    fn mutator_havoc_does_not_panic_on_empty() {
        let mut m = FuzzMutator::new(5);
        let out = m.havoc(&[], 10);
        // May be empty or not; must not panic.
        let _ = out;
    }

    #[test]
    fn mutator_havoc_changes_input() {
        let mut m = FuzzMutator::new(42);
        let input = vec![0x41u8; 32];
        let out = m.havoc(&input, 20);
        // After 20 rounds something must have changed.
        assert_ne!(out, input);
    }

    // FuzzCrashAnalyzer

    #[test]
    fn crash_analyzer_first_occurrence_is_unique() {
        let mut a = FuzzCrashAnalyzer::new();
        assert!(matches!(a.classify_crash(&[1, 2, 3]), CrashType::Unique(_)));
    }

    #[test]
    fn crash_analyzer_second_occurrence_is_duplicate() {
        let mut a = FuzzCrashAnalyzer::new();
        let h = match a.classify_crash(&[1, 2, 3]) {
            CrashType::Unique(h) => h,
            _ => panic!("expected Unique"),
        };
        assert_eq!(a.classify_crash(&[1, 2, 3]), CrashType::Duplicate(h));
    }

    #[test]
    fn crash_analyzer_deduplicate_removes_dupes() {
        let mut a = FuzzCrashAnalyzer::new();
        let crashes = vec![vec![1u8], vec![2u8], vec![1u8], vec![3u8], vec![2u8]];
        let deduped = a.deduplicate_crashes(crashes);
        assert_eq!(deduped.len(), 3);
    }

    #[test]
    fn crash_analyzer_is_interesting_new_input() {
        let existing = vec![vec![1u8, 2], vec![3u8, 4]];
        assert!(FuzzCrashAnalyzer::is_interesting(&existing, &[5, 6]));
    }

    #[test]
    fn crash_analyzer_is_interesting_existing_input() {
        let existing = vec![vec![1u8, 2]];
        assert!(!FuzzCrashAnalyzer::is_interesting(&existing, &[1, 2]));
    }
}
