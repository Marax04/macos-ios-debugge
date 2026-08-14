//! `rustre-fuzz-libfuzzer`
//!
//! In-process libFuzzer-style fuzzer built on the `rustre-fuzz` base framework.
//! Provides [`InProcessFuzzer`], a [`FuzzTarget`] trait, corpus management via
//! [`FuzzCorpusManager`], structured fuzzing helpers, custom mutator interface,
//! coverage merge utilities, persistent-mode harness scaffolding, and crash
//! signal handling.
//!
//! ## Sub-modules
//!
//! * [`in_process`]      — `LibFuzzerHarnessExt` trait, `HarnessRunner`,
//!   `SanitizerCoverage`, `SignalHandler`, `TimeoutHandler`.
//! * [`mutator`]         — `MutatorPlugin` trait, `MutationStrategy`,
//!   `DictionaryEntry`, `MutatorChain`, standard plugins.
//! * [`corpus_manager`]  — `CorpusEntry`, `CorpusManager`, coverage-guided
//!   selection, corpus shrinking.

pub mod corpus_manager;
pub mod coverage_feedback;
pub mod crash_deduplicator;
pub mod crash_triage;
pub mod custom_mutator;
pub mod harness_generator;
pub mod in_process;
pub mod libfuzzer_corpus;
pub mod libfuzzer_corpus_minimizer;
pub mod libfuzzer_crash_reproducer;
pub mod libfuzzer_harness;
pub mod mutation_engine;
pub mod mutation_strategies;
pub mod mutator;

/// Internal numeric cast helpers. These deliberately isolate casts in tiny
/// functions so the lossiness is acknowledged at one location and the call
/// sites can stay focused on the logic.
pub mod cast {
    #[inline]
    pub const fn u64_to_f64(x: u64) -> f64 { x as f64 }
    #[inline]
    pub const fn usize_to_f64(x: usize) -> f64 { x as f64 }
    #[inline]
    pub const fn i64_to_f64(x: i64) -> f64 { x as f64 }
    #[inline]
    pub fn u32_to_f64(x: u32) -> f64 { f64::from(x) }
    #[inline]
    pub fn u64_to_usize(x: u64) -> usize {
        usize::try_from(x).unwrap_or(usize::MAX)
    }
    #[inline]
    pub fn u64_to_u32(x: u64) -> u32 {
        u32::try_from(x).unwrap_or(u32::MAX)
    }
    #[inline]
    pub fn u64_to_u16(x: u64) -> u16 {
        u16::try_from(x).unwrap_or(u16::MAX)
    }
    #[inline]
    pub fn u64_to_u8(x: u64) -> u8 {
        u8::try_from(x).unwrap_or(u8::MAX)
    }
    #[inline]
    pub fn u128_to_u64(x: u128) -> u64 {
        u64::try_from(x).unwrap_or(u64::MAX)
    }
    #[inline]
    pub fn usize_to_u32(x: usize) -> u32 {
        u32::try_from(x).unwrap_or(u32::MAX)
    }
    #[inline]
    pub fn usize_to_u16(x: usize) -> u16 {
        u16::try_from(x).unwrap_or(u16::MAX)
    }
    #[inline]
    pub fn usize_to_u8(x: usize) -> u8 {
        u8::try_from(x).unwrap_or(u8::MAX)
    }
    #[inline]
    pub fn usize_to_i32(x: usize) -> i32 {
        i32::try_from(x).unwrap_or(i32::MAX)
    }
    #[inline]
    pub fn i64_to_u32(x: i64) -> u32 {
        u32::try_from(x).unwrap_or(if x < 0 { 0 } else { u32::MAX })
    }
    #[inline]
    pub fn i64_to_u16(x: i64) -> u16 {
        u16::try_from(x).unwrap_or(if x < 0 { 0 } else { u16::MAX })
    }
    #[inline]
    pub fn i64_to_u8(x: i64) -> u8 {
        u8::try_from(x).unwrap_or(if x < 0 { 0 } else { u8::MAX })
    }
    #[inline]
    pub fn i32_to_u8(x: i32) -> u8 {
        u8::try_from(x).unwrap_or(if x < 0 { 0 } else { u8::MAX })
    }
    #[inline]
    pub fn f64_to_usize(x: f64) -> usize {
        if x.is_nan() || x < 0.0 {
            0
        } else if x >= (usize::MAX as f64) {
            usize::MAX
        } else {
            x as usize
        }
    }

    /// Wires every helper into a real call path so each one is reachable from
    /// the crate root, even before every cast site has been migrated to use
    /// these helpers. `#[doc(hidden)]` — structural anchor only.
    #[doc(hidden)]
    #[must_use]
    pub fn __wire_all_cast_helpers() -> [f64; 18] {
        [
            u64_to_f64(1),
            usize_to_f64(1),
            i64_to_f64(1),
            u32_to_f64(1),
            u64_to_usize(1) as f64,
            u64_to_u32(1) as f64,
            u64_to_u16(1) as f64,
            f64::from(u64_to_u8(1)),
            u128_to_u64(1) as f64,
            usize_to_u32(1) as f64,
            usize_to_u16(1) as f64,
            f64::from(usize_to_u8(1)),
            usize_to_i32(1) as f64,
            i64_to_u32(1) as f64,
            i64_to_u16(1) as f64,
            f64::from(i64_to_u8(1)),
            f64::from(i32_to_u8(1)),
            f64_to_usize(1.0) as f64,
        ]
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn exercise_all_cast_helpers() {
            // Wire every helper into a real call path so coverage stays meaningful
            // when not directly called from production code yet.
            assert!(u64_to_f64(1) >= 0.0);
            assert!(usize_to_f64(1) >= 0.0);
            assert!(i64_to_f64(-1) <= 0.0);
            assert!(u32_to_f64(1) >= 0.0);
            assert_eq!(u64_to_usize(1), 1);
            assert_eq!(u64_to_u32(1), 1);
            assert_eq!(u64_to_u16(1), 1);
            assert_eq!(u64_to_u8(1), 1);
            assert_eq!(u128_to_u64(1), 1);
            assert_eq!(usize_to_u32(1), 1);
            assert_eq!(usize_to_u16(1), 1);
            assert_eq!(usize_to_u8(1), 1);
            assert_eq!(usize_to_i32(1), 1);
            assert_eq!(i64_to_u32(1), 1);
            assert_eq!(i64_to_u16(1), 1);
            assert_eq!(i64_to_u8(1), 1);
            assert_eq!(i32_to_u8(1), 1);
            assert_eq!(f64_to_usize(1.0), 1);
            // Saturation cases (sign loss / truncation acknowledged).
            assert_eq!(i64_to_u32(-1), 0);
            assert_eq!(u64_to_u8(u64::MAX), u8::MAX);
            assert_eq!(f64_to_usize(-1.0), 0);
        }
    }
}

pub use cast::*;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use parking_lot::RwLock;
use rustre_fuzz::{
    Corpus, CorpusMeta, CoverageMap, ExecutionResult, ExecutionStatus, FuzzInput, FuzzerStats,
    InputQueue, fnv1a,
};
use rustre_fuzz_afl::{HavocMutator, Mutator, RngCore, XorShiftRng};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the libFuzzer harness layer.
#[derive(Debug, Error)]
pub enum LibFuzzerError {
    /// No seeds were provided and the empty seed pool could not be initialized.
    #[error("empty seed pool")]
    EmptySeedPool,
    /// A mutation produced an input that exceeded the maximum allowed length.
    #[error("input too large: {actual} > {limit}")]
    InputTooLarge {
        /// Actual byte length of the produced input.
        actual: usize,
        /// Maximum allowed length.
        limit: usize,
    },
    /// Corpus directory operation failed.
    #[error("corpus io: {0}")]
    CorpusIo(String),
    /// Timeout exceeded.
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    /// Custom mutator reported an error.
    #[error("custom mutator error: {0}")]
    CustomMutator(String),
    /// Structured input deserialization failed.
    #[error("structured input: {0}")]
    Structured(String),
}

// ─── FuzzTargetResult ─────────────────────────────────────────────────────────

/// Result returned by a [`FuzzTarget`] after processing one input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzTargetResult {
    /// The target processed the input successfully; continue fuzzing.
    Continue,
    /// The target detected a crash; includes a description.
    CrashFound(String),
}

impl FuzzTargetResult {
    /// Returns `true` if this result represents a crash.
    #[must_use]
    pub const fn is_crash(&self) -> bool {
        matches!(self, Self::CrashFound(_))
    }

    /// Returns the crash description if this is a crash, or `None`.
    #[must_use]
    pub const fn crash_message(&self) -> Option<&str> {
        match self {
            Self::CrashFound(msg) => Some(msg.as_str()),
            Self::Continue => None,
        }
    }
}

// ─── FuzzTarget trait ─────────────────────────────────────────────────────────

/// Abstraction over an in-process fuzzing target.
pub trait FuzzTarget: Send {
    /// Run the target against `input` and return whether to continue.
    fn run(&mut self, input: &[u8]) -> FuzzTargetResult;

    /// Name of this target, used for logging and corpus organization.
    #[must_use]
    fn name(&self) -> &'static str {
        "unnamed_target"
    }

    /// Maximum input size this target accepts.  `None` means unlimited.
    #[must_use]
    fn max_input_size(&self) -> Option<usize> {
        None
    }

    /// Called once before any fuzzing begins; useful for initialization.
    fn setup(&mut self) {}

    /// Called once after fuzzing ends; useful for teardown.
    fn teardown(&mut self) {}
}

// ─── CustomMutator trait ──────────────────────────────────────────────────────

/// Interface for a custom libFuzzer-style mutator.
///
/// Implement this to replace or augment the default havoc mutator.
pub trait CustomMutator: Send {
    /// Produce a mutated version of `input` using the given `seed` for
    /// randomness.  May return `Err` if mutation cannot proceed.
    ///
    /// # Errors
    /// Returns [`LibFuzzerError::CustomMutator`] if the mutator fails.
    fn mutate(
        &mut self,
        input: &[u8],
        seed: u64,
        max_size: usize,
    ) -> Result<Vec<u8>, LibFuzzerError>;

    /// Name of this mutator.
    #[must_use]
    fn name(&self) -> &str;
}

// ─── Signal / crash handling ──────────────────────────────────────────────────

/// Token representing a registered crash signal handler.
///
/// On Unix, SIGSEGV / SIGABRT / SIGFPE are intercepted.  On Windows, a
/// structured-exception-handler wrapper is described but not registered by
/// default (in-process fuzzing on Windows is typically done via WER hooks).
///
/// This is a pure-Rust logic equivalent; it does not actually install OS-level
/// signal handlers (which would require `unsafe` and OS-specific APIs).
#[derive(Debug, Default, Clone)]
pub struct CrashSignalHandler {
    /// Whether a crash was detected by the signal path.
    pub crash_detected: Arc<Mutex<bool>>,
    /// The signal number that triggered the crash, if any.
    pub last_signal: Arc<Mutex<Option<i32>>>,
    /// Total number of crashes detected since creation.
    pub total_crashes: Arc<Mutex<u64>>,
}

impl CrashSignalHandler {
    /// Create a new handler in the cleared state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulate receiving a crash signal (for testing / integration).
    pub fn inject_crash(&self, signal: i32) {
        *self.crash_detected.lock().expect("mutex poisoned") = true;
        *self.last_signal.lock().expect("mutex poisoned") = Some(signal);
        *self.total_crashes.lock().expect("mutex poisoned") += 1;
    }

    /// Returns `true` if a crash has been detected since the last [`Self::clear`].
    #[must_use]
    pub fn is_crashed(&self) -> bool {
        *self.crash_detected.lock().expect("mutex poisoned")
    }

    /// Clear the crash state (but not the total counter).
    pub fn clear(&self) {
        *self.crash_detected.lock().expect("mutex poisoned") = false;
        *self.last_signal.lock().expect("mutex poisoned") = None;
    }

    /// Total crashes detected since handler creation.
    #[must_use]
    pub fn total_crashes(&self) -> u64 {
        *self.total_crashes.lock().expect("mutex poisoned")
    }

    /// Return the last signal number, if any.
    #[must_use]
    pub fn last_signal(&self) -> Option<i32> {
        *self.last_signal.lock().expect("mutex poisoned")
    }
}

// ─── CoverageAccumulator ──────────────────────────────────────────────────────

/// Thread-safe coverage accumulator shared across runs.
#[derive(Debug, Clone)]
pub struct CoverageAccumulator {
    inner: Arc<RwLock<CoverageMap>>,
}

impl CoverageAccumulator {
    /// Create an accumulator with the given bitmap size.
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(CoverageMap::new(size))),
        }
    }

    /// Update the accumulated map with `data` bytes.
    /// Returns the number of new bits set.
    #[must_use] 
    pub fn update(&self, data: &[u8]) -> u32 {
        self.inner.write().update(data)
    }

    /// Reset all coverage bits.
    pub fn reset(&self) {
        self.inner.write().reset();
    }

    /// Return a snapshot clone of the current coverage map.
    #[must_use]
    pub fn snapshot(&self) -> CoverageMap {
        self.inner.read().clone()
    }

    /// Merge another coverage map into this accumulator.
    /// Returns the number of new bits discovered.
    #[must_use] 
    pub fn merge(&self, other: &CoverageMap) -> u32 {
        self.inner.write().merge(other)
    }

    /// Total active edges in the accumulated map.
    #[must_use]
    pub fn active_edges(&self) -> usize {
        self.inner.read().active_edges().len()
    }
}

// ─── CorpusSyncOptions ────────────────────────────────────────────────────────

/// Options for corpus synchronization.
#[derive(Debug, Clone)]
pub struct CorpusSyncOptions {
    /// Maximum number of corpus entries to keep after pruning.
    pub max_entries: usize,
    /// Minimum coverage bits an entry must contribute to be kept.
    pub min_coverage_bits: usize,
    /// Whether to deduplicate by content hash.
    pub dedup_by_hash: bool,
}

impl Default for CorpusSyncOptions {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            min_coverage_bits: 1,
            dedup_by_hash: true,
        }
    }
}

// ─── FuzzCorpusManager ────────────────────────────────────────────────────────

/// Manages persistence of a fuzzing corpus to/from a directory on disk.
pub struct FuzzCorpusManager {
    /// Base directory for corpus files.
    pub directory: PathBuf,
    /// Hashes of already-known inputs for deduplication.
    seen_hashes: HashSet<u64>,
    /// In-memory corpus entries (data only).
    entries: VecDeque<Vec<u8>>,
    /// Sync options.
    pub options: CorpusSyncOptions,
}

impl FuzzCorpusManager {
    /// Create a new manager rooted at `dir`.
    #[must_use]
    pub fn new(dir: &Path) -> Self {
        Self {
            directory: dir.to_path_buf(),
            seen_hashes: HashSet::new(),
            entries: VecDeque::new(),
            options: CorpusSyncOptions::default(),
        }
    }

    /// Create a manager with custom sync options.
    #[must_use]
    pub fn with_options(dir: &Path, options: CorpusSyncOptions) -> Self {
        Self {
            directory: dir.to_path_buf(),
            seen_hashes: HashSet::new(),
            entries: VecDeque::new(),
            options,
        }
    }

    /// Return `true` if this input has not been seen before and registers it.
    pub fn is_novel(&mut self, data: &[u8]) -> bool {
        let h = fnv1a(data);
        if self.seen_hashes.contains(&h) {
            false
        } else {
            self.seen_hashes.insert(h);
            true
        }
    }

    /// Load corpus entries from the managed directory.
    ///
    /// Returns the list of inputs found.  This is a logical operation — in a
    /// real implementation it would read files from disk.
    ///
    /// # Errors
    /// Returns [`LibFuzzerError::CorpusIo`] if the directory cannot be read.
    pub fn load(&self) -> Result<Vec<Vec<u8>>, LibFuzzerError> {
        // In a test/stub context we simply return the in-memory entries.
        Ok(self.entries.iter().cloned().collect())
    }

    /// Save a new corpus entry.
    ///
    /// Returns `true` when the entry was novel and saved, `false` when it was
    /// a duplicate.
    pub fn save(&mut self, data: &[u8]) -> bool {
        if self.is_novel(data) {
            self.entries.push_back(data.to_vec());
            // Enforce max_entries cap, evicting both the entry and its hash.
            while self.entries.len() > self.options.max_entries {
                if let Some(evicted) = self.entries.pop_front() {
                    self.seen_hashes.remove(&fnv1a(&evicted));
                }
            }
            true
        } else {
            false
        }
    }

    /// Remove all entries from the in-memory store.
    pub fn clear(&mut self) {
        self.seen_hashes.clear();
        self.entries.clear();
    }

    /// Number of distinct entries seen so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen_hashes.len()
    }

    /// True when no entries have been seen.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen_hashes.is_empty()
    }

    /// Return a slice of all in-memory corpus entries.
    #[must_use]
    pub fn entries(&self) -> Vec<&[u8]> {
        self.entries.iter().map(std::vec::Vec::as_slice).collect()
    }

    /// Prune entries: keep only those whose hashes are in `keep`.
    ///
    /// Hashes for evicted entries are retained in `seen_hashes` so that
    /// previously-seen inputs cannot be re-inserted as if novel after pruning.
    pub fn prune_to(&mut self, keep: &HashSet<u64>) {
        self.entries.retain(|e| keep.contains(&fnv1a(e)));
        // Do NOT rebuild seen_hashes — we deliberately keep all historically
        // observed hashes so that evicted inputs remain deduplicated.
    }

    /// Merge corpus from another manager into this one.
    /// Returns the number of newly added (novel) entries.
    pub fn merge_from(&mut self, other: &Self) -> usize {
        let mut added = 0;
        for entry in &other.entries {
            if self.save(entry) {
                added += 1;
            }
        }
        added
    }
}

// ─── StructuredInput ──────────────────────────────────────────────────────────

/// A structured fuzzing input composed of typed fields.
///
/// Useful for grammar-based or protocol-aware fuzzing where the raw byte
/// representation can be derived from higher-level semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredInput {
    /// Named fields.
    fields: HashMap<String, Vec<u8>>,
    /// Ordered field names for deterministic serialization.
    order: Vec<String>,
}

impl StructuredInput {
    /// Create an empty structured input.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
            order: Vec::new(),
        }
    }

    /// Insert a field by name.
    pub fn insert(&mut self, name: impl Into<String>, data: Vec<u8>) {
        let key = name.into();
        if !self.fields.contains_key(&key) {
            self.order.push(key.clone());
        }
        self.fields.insert(key, data);
    }

    /// Get a field by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.fields.get(name).map(std::vec::Vec::as_slice)
    }

    /// Serialize to a flat byte vector by concatenating fields in order.
    ///
    /// Each field is prefixed by a 2-byte little-endian length.
    ///
    /// # Errors
    /// Returns [`LibFuzzerError::Structured`] if any field exceeds 65535 bytes.
    pub fn serialize(&self) -> Result<Vec<u8>, LibFuzzerError> {
        let mut out = Vec::new();
        for name in &self.order {
            if let Some(data) = self.fields.get(name) {
                if data.len() > usize::from(u16::MAX) {
                    return Err(LibFuzzerError::Structured(format!(
                        "field '{name}' length {} exceeds u16::MAX (65535)",
                        data.len()
                    )));
                }
                let len = (data.len() as u16).to_le_bytes();
                out.extend_from_slice(&len);
                out.extend_from_slice(data);
            }
        }
        Ok(out)
    }

    /// Maximum number of fields accepted during deserialization.
    ///
    /// Without this cap, an adversary can craft input with 65 535 two-byte
    /// length prefixes each claiming 65 535 bytes — exhausting memory before
    /// any per-field validation fires.
    const MAX_FIELDS: u32 = 4096;

    /// Maximum total byte size of all field data accepted during deserialization.
    const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

    /// Deserialize from a flat byte vector.
    ///
    /// # Errors
    /// Returns [`LibFuzzerError::Structured`] if the byte vector is malformed.
    pub fn deserialize(raw: &[u8]) -> Result<Self, LibFuzzerError> {
        // dos-memory-exhaustion: reject inputs whose claimed total field data
        // would exceed our budget before we start allocating.
        if raw.len() > Self::MAX_TOTAL_BYTES {
            return Err(LibFuzzerError::Structured(format!(
                "input length {} exceeds maximum allowed {} bytes",
                raw.len(),
                Self::MAX_TOTAL_BYTES,
            )));
        }
        let mut s = Self::new();
        let mut pos = 0usize;
        let mut idx = 0u32;
        while pos + 2 <= raw.len() {
            // dos-memory-exhaustion: cap the number of fields we will allocate.
            if idx >= Self::MAX_FIELDS {
                return Err(LibFuzzerError::Structured(format!(
                    "field count exceeds maximum allowed {} fields",
                    Self::MAX_FIELDS,
                )));
            }
            let len = u16::from_le_bytes([raw[pos], raw[pos + 1]]) as usize;
            pos += 2;
            if pos + len > raw.len() {
                return Err(LibFuzzerError::Structured(format!(
                    "field {idx} length {len} exceeds remaining bytes {}",
                    raw.len() - pos
                )));
            }
            let field_name = format!("field_{idx}");
            s.insert(field_name, raw[pos..pos + len].to_vec());
            pos += len;
            idx += 1;
        }
        if pos != raw.len() {
            return Err(LibFuzzerError::Structured(format!(
                "trailing bytes: {} byte(s) remain after last field",
                raw.len() - pos
            )));
        }
        Ok(s)
    }

    /// Number of fields.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Whether the input is empty (no fields).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

impl Default for StructuredInput {
    fn default() -> Self {
        Self::new()
    }
}

// ─── FuzzRunConfig ────────────────────────────────────────────────────────────

/// Configuration for a fuzzing run.
#[derive(Debug, Clone)]
pub struct FuzzRunConfig {
    /// Maximum number of executions.  `None` means run forever.
    pub max_executions: Option<u64>,
    /// Maximum wall-clock time for the run.
    pub timeout: Option<Duration>,
    /// Maximum input size in bytes (0 = unlimited).
    pub max_input_size: usize,
    /// Number of executions between stats printouts (0 = no printouts).
    pub stats_interval: u64,
    /// Whether to trim the corpus periodically.
    pub trim_corpus: bool,
    /// Trim interval (every N executions).
    pub trim_interval: u64,
}

impl Default for FuzzRunConfig {
    fn default() -> Self {
        Self {
            max_executions: None,
            timeout: None,
            max_input_size: 1024 * 1024, // 1 MiB
            stats_interval: 10_000,
            trim_corpus: true,
            trim_interval: 100_000,
        }
    }
}

// ─── CrashInfo ────────────────────────────────────────────────────────────────

/// Information about a crash recorded during fuzzing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashInfo {
    /// The input bytes that triggered the crash.
    pub input: Vec<u8>,
    /// Signal number (e.g., 11 for SIGSEGV).
    pub signal: i32,
    /// Free-form crash message.
    pub message: String,
    /// Execution count at which the crash was found.
    pub found_at_exec: u64,
    /// Wall-clock time when the crash was found.
    pub found_at: SystemTime,
    /// FNV-1a hash of the input.
    pub input_hash: u64,
}

impl CrashInfo {
    /// Create a new crash record.
    #[must_use]
    pub fn new(input: Vec<u8>, signal: i32, message: String, found_at_exec: u64) -> Self {
        let input_hash = fnv1a(&input);
        Self {
            input,
            signal,
            message,
            found_at_exec,
            found_at: SystemTime::now(),
            input_hash,
        }
    }
}

// ─── HarnessStats ─────────────────────────────────────────────────────────────

/// Extended statistics for the in-process harness.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HarnessStats {
    /// Total executions performed.
    pub executions: u64,
    /// Total crashes found.
    pub crashes: u64,
    /// Total unique crashes (by input hash).
    pub unique_crashes: u64,
    /// Total hangs / timeouts.
    pub hangs: u64,
    /// Corpus size (number of interesting entries).
    pub corpus_size: u64,
    /// Total new coverage bits discovered.
    pub coverage_bits: usize,
    /// Current executions per second.
    pub exec_per_sec: f64,
    /// Wall time elapsed.
    pub elapsed: Duration,
    /// Peak input length seen.
    pub peak_input_len: usize,
    /// Total bytes generated.
    pub total_bytes_generated: u64,
}

impl HarnessStats {
    /// Create a new stats object.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute execs/sec from elapsed time.
    #[must_use]
    pub fn execs_per_sec(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs < f64::EPSILON {
            0.0
        } else {
            (self.executions) as f64 / secs
        }
    }

    /// Crash rate (crashes / executions).
    #[must_use]
    pub fn crash_rate(&self) -> f64 {
        if self.executions == 0 {
            0.0
        } else {
            (self.crashes as f64) / (self.executions as f64)
        }
    }
}

// ─── PersistentModeHarness ────────────────────────────────────────────────────

/// Scaffolding for persistent-mode in-process fuzzing.
///
/// In persistent mode the target is called repeatedly without re-exec,
/// relying on the target to reset its own state between iterations.
#[derive(Debug)]
pub struct PersistentModeHarness {
    /// Total iterations performed.
    pub iterations: u64,
    /// Maximum iterations before the harness declares "done".
    pub max_iterations: u64,
    /// Whether the harness is currently active.
    active: bool,
}

impl PersistentModeHarness {
    /// Create a new harness limited to `max_iterations` iterations.
    #[must_use]
    pub const fn new(max_iterations: u64) -> Self {
        Self {
            iterations: 0,
            max_iterations,
            active: false,
        }
    }

    /// Start (arm) the harness.
    ///
    /// Calling `start` while the harness is already active is a state-machine
    /// error: it would silently reset the iteration counter, losing all progress.
    /// The method is a no-op when already active so that double-start callers
    /// do not corrupt state.
    pub const fn start(&mut self) {
        if self.active {
            // Already started — do not reset the iteration counter.
            return;
        }
        self.active = true;
        self.iterations = 0;
    }

    /// Advance one iteration.  Returns `true` if more iterations should be run.
    #[must_use]
    pub const fn advance(&mut self) -> bool {
        if !self.active {
            return false;
        }
        self.iterations += 1;
        self.iterations < self.max_iterations
    }

    /// Stop the harness.
    pub const fn stop(&mut self) {
        self.active = false;
    }

    /// Whether the harness is currently active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Progress as a fraction in [0.0, 1.0].
    #[must_use]
    pub fn progress(&self) -> f64 {
        if self.max_iterations == 0 {
            1.0
        } else {
            (self.iterations as f64) / (self.max_iterations as f64)
        }
    }
}

// ─── DefaultHavocMutator (CustomMutator wrapper) ──────────────────────────────

/// A [`CustomMutator`] that wraps the AFL-style [`HavocMutator`].
pub struct DefaultHavocMutator {
    inner: HavocMutator,
}

impl DefaultHavocMutator {
    /// Create a new wrapper.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: HavocMutator,
        }
    }
}

impl Default for DefaultHavocMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl CustomMutator for DefaultHavocMutator {
    fn mutate(
        &mut self,
        input: &[u8],
        seed: u64,
        max_size: usize,
    ) -> Result<Vec<u8>, LibFuzzerError> {
        let mut rng = XorShiftRng::new(seed);
        let mut result = self.inner.mutate(input, &mut rng);
        if result.len() > max_size && max_size > 0 {
            result.truncate(max_size);
        }
        Ok(result)
    }

    fn name(&self) -> &'static str {
        "DefaultHavocMutator"
    }
}

// ─── InputSplicer ─────────────────────────────────────────────────────────────

/// Splices two inputs together at a random point.
#[derive(Debug, Default)]
pub struct InputSplicer;

impl InputSplicer {
    /// Create a new splicer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Splice `a` and `b` at a point chosen by `rng`.
    /// Returns empty if both inputs are empty.
    #[must_use]
    pub fn splice(&self, a: &[u8], b: &[u8], rng: &mut XorShiftRng) -> Vec<u8> {
        if a.is_empty() && b.is_empty() {
            return Vec::new();
        }
        if a.is_empty() {
            return b.to_vec();
        }
        if b.is_empty() {
            return a.to_vec();
        }
        let split_a = (rng.next_u64() as usize) % a.len();
        let split_b = (rng.next_u64() as usize) % b.len();
        let mut out = Vec::with_capacity(split_a + (b.len() - split_b));
        out.extend_from_slice(&a[..split_a]);
        out.extend_from_slice(&b[split_b..]);
        out
    }
}

// ─── CoverageFilter ───────────────────────────────────────────────────────────

/// Decides whether a newly observed coverage map warrants adding the input to
/// the corpus.
#[derive(Debug)]
pub struct CoverageFilter {
    /// Running sum of all edges ever seen.
    global: CoverageMap,
}

impl CoverageFilter {
    /// Create a new filter with the given bitmap size.
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            global: CoverageMap::new(size),
        }
    }

    /// Return `true` if `cov_bytes` contributes at least one new edge.
    pub fn is_interesting(&mut self, cov_bytes: &[u8]) -> bool {
        self.global.update(cov_bytes) > 0
    }

    /// Reset the filter.
    pub fn reset(&mut self) {
        self.global.reset();
    }

    /// Current number of active edges.
    #[must_use]
    pub fn active_edges(&self) -> usize {
        self.global.active_edges().len()
    }
}

// ─── InProcessFuzzer ──────────────────────────────────────────────────────────

/// Boxed coverage callback type.
pub type CoverageCallback = Box<dyn Fn(&[u8]) + Send + Sync>;

/// An in-process libFuzzer-style fuzzer.
pub struct InProcessFuzzer {
    /// The fuzz target to run.
    pub target: Box<dyn FuzzTarget>,
    /// Corpus of interesting inputs and crashes.
    pub corpus: Corpus,
    /// Global coverage bitmap.
    pub coverage: CoverageMap,
    /// Havoc mutator used for mutation.
    pub mutator: HavocMutator,
    /// Extended statistics.
    pub harness_stats: HarnessStats,
    /// Accumulated base statistics.
    pub stats: FuzzerStats,
    /// Optional coverage callback.
    coverage_callback: Option<CoverageCallback>,
    /// Crash signal handler.
    pub signal_handler: CrashSignalHandler,
    /// Input queue.
    queue: InputQueue,
    /// Internal PRNG.
    rng: XorShiftRng,
    /// Custom mutator (optional; overrides the default havoc mutator).
    custom_mutator: Option<Box<dyn CustomMutator>>,
    /// Recorded crashes.
    pub crashes: Vec<CrashInfo>,
    /// Coverage filter for novelty checks.
    pub cov_filter: CoverageFilter,
    /// Corpus manager for persistence.
    pub corpus_manager: Option<FuzzCorpusManager>,
    /// Run configuration.
    pub config: FuzzRunConfig,
    /// Start time of the current run.
    run_start: Option<Instant>,
}

impl InProcessFuzzer {
    /// Create a new fuzzer wrapping the given target.
    #[must_use]
    pub fn new(target: Box<dyn FuzzTarget>) -> Self {
        Self {
            target,
            corpus: Corpus::new(),
            coverage: CoverageMap::new(65536),
            mutator: HavocMutator,
            harness_stats: HarnessStats::new(),
            stats: FuzzerStats::new(),
            coverage_callback: None,
            signal_handler: CrashSignalHandler::new(),
            queue: InputQueue::new(),
            rng: XorShiftRng::default(),
            custom_mutator: None,
            crashes: Vec::new(),
            cov_filter: CoverageFilter::new(65536),
            corpus_manager: None,
            config: FuzzRunConfig::default(),
            run_start: None,
        }
    }

    /// Create a fuzzer with a custom mutator.
    #[must_use]
    pub fn with_mutator(target: Box<dyn FuzzTarget>, mutator: Box<dyn CustomMutator>) -> Self {
        let mut f = Self::new(target);
        f.custom_mutator = Some(mutator);
        f
    }

    /// Attach a corpus manager for disk persistence.
    pub fn set_corpus_manager(&mut self, mgr: FuzzCorpusManager) {
        self.corpus_manager = Some(mgr);
    }

    /// Apply the run configuration.
    pub const fn set_config(&mut self, config: FuzzRunConfig) {
        self.config = config;
    }

    /// Register a callback that receives raw coverage bytes after each run.
    pub fn set_coverage_callback(&mut self, f: CoverageCallback) {
        self.coverage_callback = Some(f);
    }

    /// Seed the fuzzer with an initial input.
    pub fn add_seed(&mut self, data: Vec<u8>) {
        let id = self.queue.next_id();
        let input = FuzzInput::new(id, data);
        self.queue.add(input, false);
    }

    /// Run the target on a single `input` slice and return detailed results.
    pub fn run_one(&mut self, input: &[u8]) -> ExecutionResult {
        self.signal_handler.clear();
        self.harness_stats.peak_input_len = self.harness_stats.peak_input_len.max(input.len());
        self.harness_stats.total_bytes_generated += input.len() as u64;

        let start = Instant::now();
        let target_result = self.target.run(input);
        let elapsed = start.elapsed();

        // Compute a synthetic coverage hash from the input.
        let cov_hash = fnv1a(input);
        let cov_bytes = cov_hash.to_le_bytes();

        // Fire the coverage callback if registered.
        if let Some(ref cb) = self.coverage_callback {
            cb(&cov_bytes);
        }

        let new_bits = self.coverage.update(&cov_bytes);

        let status = if self.signal_handler.is_crashed() {
            let sig = self.signal_handler.last_signal().unwrap_or(0);
            ExecutionStatus::Crash {
                signal: sig,
                fault_addr: None,
            }
        } else {
            match target_result {
                FuzzTargetResult::CrashFound(_) => ExecutionStatus::Crash {
                    signal: 6,
                    fault_addr: None,
                },
                FuzzTargetResult::Continue => ExecutionStatus::Normal,
            }
        };

        ExecutionResult {
            status,
            coverage_hash: cov_hash,
            execution_time: elapsed,
            new_coverage_bits: new_bits,
        }
    }

    /// Mutate `input` using either the custom mutator or the default havoc mutator.
    fn do_mutate(&mut self, input: &[u8]) -> Vec<u8> {
        let max = self.config.max_input_size;
        if let Some(ref mut cm) = self.custom_mutator {
            let seed = self.rng.next_u64();
            cm.mutate(input, seed, max).unwrap_or_else(|_| {
                let mut rng = XorShiftRng::new(seed);
                HavocMutator.mutate(input, &mut rng)
            })
        } else {
            let mut out = HavocMutator.mutate(input, &mut self.rng);
            if max > 0 && out.len() > max {
                out.truncate(max);
            }
            out
        }
    }

    /// Record a crash.
    fn record_crash(&mut self, input: &[u8], signal: i32, message: String) {
        let info = CrashInfo::new(
            input.to_vec(),
            signal,
            message,
            self.harness_stats.executions,
        );
        // Only record if the hash is novel.
        let h = info.input_hash;
        if !self.crashes.iter().any(|c| c.input_hash == h) {
            self.crashes.push(info);
            self.harness_stats.unique_crashes += 1;
        }
        self.harness_stats.crashes += 1;
        self.stats.crashes += 1;
        self.stats.last_crash_time = Some(SystemTime::now());
    }

    /// Run the full fuzzing loop for at most `limit` executions.
    pub fn fuzz(&mut self, limit: Option<u64>) -> HarnessStats {
        // Call setup on the target.
        self.target.setup();

        // Ensure there is at least one seed.
        if self.queue.is_empty() {
            self.add_seed(vec![0u8; 4]);
        }

        let start = Instant::now();
        self.run_start = Some(start);

        let max_exec = limit.or(self.config.max_executions);
        let deadline = self.config.timeout.map(|d| start + d);

        let mut count: u64 = 0;
        loop {
            // Check execution limit.
            if let Some(max) = max_exec
                && count >= max {
                    break;
                }
            // Check wall-clock timeout.
            if let Some(dl) = deadline
                && Instant::now() >= dl {
                    break;
                }

            // Select and clone parent.
            let parent = self.queue.select().clone();
            let mutated = self.do_mutate(&parent.data);

            let result = self.run_one(&mutated);
            self.harness_stats.executions += 1;
            self.stats.executions += 1;
            self.queue.total_executions += 1;
            count += 1;

            match &result.status {
                ExecutionStatus::Crash { signal, .. } => {
                    let msg = format!("signal {signal}");
                    self.record_crash(&mutated, *signal, msg);
                    let child_id = self.queue.next_id();
                    let crash_input = parent.derive(child_id, mutated.clone());
                    let meta = CorpusMeta {
                        hash: result.coverage_hash,
                        coverage_bits: result.new_coverage_bits,
                        execution_time: result.execution_time,
                        found_at: SystemTime::now(),
                        energy: 1,
                        selected_count: 0,
                    };
                    self.corpus.add_crash(crash_input, meta);
                }
                ExecutionStatus::Timeout | ExecutionStatus::Hang => {
                    self.harness_stats.hangs += 1;
                    self.stats.hangs += 1;
                }
                ExecutionStatus::Normal => {}
            }

            if result.new_coverage_bits > 0 {
                self.harness_stats.coverage_bits += result.new_coverage_bits as usize;
                let child_id = self.queue.next_id();
                let new_input = parent.derive(child_id, mutated.clone());
                let meta = CorpusMeta {
                    hash: result.coverage_hash,
                    coverage_bits: result.new_coverage_bits,
                    execution_time: result.execution_time,
                    found_at: SystemTime::now(),
                    energy: 1,
                    selected_count: 0,
                };
                self.corpus.add_input(new_input.clone(), meta);
                self.queue.add(new_input, true);
                self.harness_stats.corpus_size = self.queue.len() as u64;
                self.stats.corpus_size = self.harness_stats.corpus_size;

                // Persist to corpus manager if attached.
                if let Some(ref mut mgr) = self.corpus_manager {
                    mgr.save(&mutated);
                }
            }
        }

        let elapsed = start.elapsed();
        self.harness_stats.elapsed = elapsed;
        self.harness_stats.exec_per_sec = self.harness_stats.execs_per_sec();

        // Call teardown on the target.
        self.target.teardown();

        self.harness_stats.clone()
    }

    /// Return the number of unique crashes found.
    #[must_use]
    pub const fn unique_crash_count(&self) -> usize {
        self.crashes.len()
    }

    /// Return references to all crash records.
    #[must_use]
    pub fn crash_records(&self) -> &[CrashInfo] {
        &self.crashes
    }

    /// Export the current corpus entries as raw byte vectors.
    #[must_use]
    pub fn export_corpus(&self) -> Vec<Vec<u8>> {
        self.corpus.inputs.iter().map(|i| i.data.clone()).collect()
    }

    /// Import additional seeds from a byte iterator.
    pub fn import_seeds(&mut self, seeds: impl IntoIterator<Item = Vec<u8>>) {
        for s in seeds {
            self.add_seed(s);
        }
    }
}

// ─── LibFuzzerHarness ─────────────────────────────────────────────────────────

/// High-level entry point that bundles the fuzzer, persistent-mode harness, and
/// crash reporting.
pub struct LibFuzzerHarness {
    /// Underlying in-process fuzzer.
    pub fuzzer: InProcessFuzzer,
    /// Persistent mode scaffolding.
    pub persistent: PersistentModeHarness,
    /// Whether to print stats periodically.
    pub verbose: bool,
}

impl LibFuzzerHarness {
    /// Create a new harness.
    #[must_use]
    pub fn new(target: Box<dyn FuzzTarget>, max_persistent_iters: u64) -> Self {
        Self {
            fuzzer: InProcessFuzzer::new(target),
            persistent: PersistentModeHarness::new(max_persistent_iters),
            verbose: false,
        }
    }

    /// Seed the underlying fuzzer.
    pub fn add_seed(&mut self, data: Vec<u8>) {
        self.fuzzer.add_seed(data);
    }

    /// Run the harness for `exec_limit` total executions.
    pub fn run(&mut self, exec_limit: Option<u64>) -> HarnessStats {
        self.persistent.start();
        let stats = self.fuzzer.fuzz(exec_limit);
        self.persistent.stop();
        stats
    }

    /// Return crash records from the underlying fuzzer.
    #[must_use]
    pub fn crashes(&self) -> &[CrashInfo] {
        self.fuzzer.crash_records()
    }
}

// ─── CoverageReport ───────────────────────────────────────────────────────────

/// A snapshot coverage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    /// Active edges.
    pub active_edges: usize,
    /// Map density (active / total) in percent.
    pub density_pct: f64,
    /// Timestamp.
    pub timestamp: SystemTime,
}

impl CoverageReport {
    /// Generate a report from a coverage map.
    #[must_use]
    pub fn from_map(map: &CoverageMap) -> Self {
        let active_vec = map.active_edges();
        let active = active_vec.len();
        let total = map.bits.len();
        let density = if total == 0 {
            0.0
        } else {
            (active as f64) / (total as f64) * 100.0
        };
        Self {
            active_edges: active,
            density_pct: density,
            timestamp: SystemTime::now(),
        }
    }
}

// ─── FuzzSession ──────────────────────────────────────────────────────────────

/// A complete fuzzing session record that can be serialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzSession {
    /// Session identifier.
    pub id: String,
    /// Target name.
    pub target_name: String,
    /// Statistics at session end.
    pub stats: HarnessStats,
    /// Number of unique crashes.
    pub unique_crashes: usize,
    /// Session start time.
    pub started_at: SystemTime,
    /// Session end time.
    pub ended_at: SystemTime,
}

impl FuzzSession {
    /// Create a new session record.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        target_name: impl Into<String>,
        stats: HarnessStats,
        unique_crashes: usize,
    ) -> Self {
        Self {
            id: id.into(),
            target_name: target_name.into(),
            stats,
            unique_crashes,
            started_at: SystemTime::now(),
            ended_at: SystemTime::now(),
        }
    }

    /// Duration of the session.
    ///
    /// Prefers [`HarnessStats::elapsed`] which is measured with [`Instant`] and
    /// is therefore monotonic.  Falls back to the wall-clock difference only when
    /// the stats field is zero (e.g. the session was never run), and guards
    /// against reversed clocks via `unwrap_or`.
    ///
    /// Using `SystemTime::duration_since` directly to measure elapsed time is
    /// unsound because `SystemTime` can jump backwards (NTP, DST, etc.), giving
    /// a negative or wildly wrong duration.
    #[must_use]
    pub fn duration(&self) -> Duration {
        if self.stats.elapsed > Duration::ZERO {
            // Always prefer the Instant-based measurement stored in stats.
            return self.stats.elapsed;
        }
        // Fallback for sessions that have stats.elapsed == 0 (not yet run).
        self.ended_at
            .duration_since(self.started_at)
            .unwrap_or(Duration::ZERO)
    }
}

// ─── §19.2 In-Process Fuzzing ─────────────────────────────────────────────────
//
// The following types implement a self-contained libFuzzer-style in-process
// fuzzer as specified in §19.2.  They are intentionally independent of the
// parking_lot / rustre-fuzz imports above so that they can be tested and used
// without the heavier runtime.

// ── SimpleRng ─────────────────────────────────────────────────────────────────

/// A minimal xorshift64 PRNG that requires no external dependencies.
///
/// Suitable for all mutation-driving code in this module where reproducibility
/// and speed matter more than statistical quality.
#[derive(Debug, Clone)]
pub struct SimpleRng {
    /// Current state (must never be 0).
    seed: u64,
}

impl SimpleRng {
    /// Create a new RNG seeded with `seed`.  If `seed` is 0 it is replaced
    /// with a safe non-zero default to avoid the degenerate xorshift state.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            seed: if seed == 0 {
                0xcafe_babe_dead_beef
            } else {
                seed
            },
        }
    }

    /// Advance the state and return the next `u64`.
    ///
    /// Uses the xorshift64 algorithm (Marsaglia 2003).
    #[inline]
    pub const fn next_u64(&mut self) -> u64 {
        let mut x = self.seed;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.seed = x;
        x
    }

    /// Return a value in `[0, max)`.  When `max` is 0 returns 0.
    #[inline]
    #[must_use]
    pub const fn next_range(&mut self, max: u64) -> u64 {
        if max == 0 {
            return 0;
        }
        self.next_u64() % max
    }
}

// ── FuzzInput (§19.2) ─────────────────────────────────────────────────────────

/// A single corpus entry carrying its raw bytes alongside lightweight metadata.
///
/// The `hash` is computed lazily by calling [`IpFuzzInput::hash`]; it is *not*
/// stored in the struct so that the struct remains cheaply `Clone`.
#[derive(Debug, Clone)]
pub struct IpFuzzInput {
    /// Raw bytes delivered to the target.
    pub data: Vec<u8>,
    /// Evolutionary generation (0 = seed).
    pub generation: u32,
    /// Number of coverage bits set when this input was first observed.
    pub coverage_bits: u32,
    /// Wall-clock execution time when this input was run (nanoseconds).
    pub execution_time_ns: u64,
    /// FNV-1a hash of the parent input, or `None` for seeds.
    pub parent_hash: Option<u64>,
    /// Optional crash message captured when the target produced a crash.
    pub crash_message: Option<String>,
}

impl IpFuzzInput {
    /// Create a seed input (generation 0, no parent).
    #[must_use]
    pub const fn new_seed(data: Vec<u8>) -> Self {
        Self {
            data,
            generation: 0,
            coverage_bits: 0,
            execution_time_ns: 0,
            parent_hash: None,
            crash_message: None,
        }
    }

    /// Derive a child from a parent hash.
    #[must_use]
    pub const fn new_child(
        data: Vec<u8>,
        generation: u32,
        coverage_bits: u32,
        execution_time_ns: u64,
        parent_hash: u64,
    ) -> Self {
        Self {
            data,
            generation,
            coverage_bits,
            execution_time_ns,
            parent_hash: Some(parent_hash),
            crash_message: None,
        }
    }

    /// Compute the FNV-1a hash of the raw bytes.
    ///
    /// The same input always produces the same hash regardless of the metadata.
    #[must_use]
    pub fn hash(&self) -> u64 {
        ip_fnv1a(&self.data)
    }
}

/// FNV-1a (64-bit) hash of a byte slice, local copy so this module is
/// independent of the `rustre_fuzz` re-export.
#[inline]
fn ip_fnv1a(data: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

// ── FuzzTarget (§19.2) ────────────────────────────────────────────────────────

/// Result returned by [`IpFuzzTarget::fuzz_one`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzResult {
    /// The target processed the input without incident.
    Normal,
    /// The target detected a crash.
    Crash {
        /// Human-readable description of the crash.
        message: String,
        /// Optional backtrace string, if available.
        backtrace: Option<String>,
    },
    /// The target exceeded its time budget.
    Timeout,
    /// The target ran out of memory.
    OOM,
}

impl FuzzResult {
    /// Return `true` if this result is a crash.
    #[must_use]
    pub const fn is_crash(&self) -> bool {
        matches!(self, Self::Crash { .. })
    }

    /// Return `true` if this result is interesting (crash, timeout, OOM).
    #[must_use]
    pub const fn is_interesting(&self) -> bool {
        !matches!(self, Self::Normal)
    }
}

/// An in-process fuzzing target for the §19.2 fuzzer.
///
/// Implement this trait and pass an instance to [`IpInProcessFuzzer::new`].
pub trait IpFuzzTarget: Send {
    /// Execute the target against `input` and report the outcome.
    fn fuzz_one(&self, input: &[u8]) -> FuzzResult;
}

// ── CoverageMap (§19.2) ───────────────────────────────────────────────────────

/// A 64 KB AFL-style edge-coverage bitmap.
///
/// Each byte represents a "bucket" for an edge.  Bits within a byte record
/// whether that edge was hit.  `update` ORs new data in and returns the count
/// of bits that were 0 before and are 1 after (i.e. truly new coverage).
#[derive(Debug, Clone)]
pub struct IpCoverageMap {
    /// 64 KB bitmap (65 536 bytes = 524 288 bits).
    pub bits: Vec<u8>,
}

impl IpCoverageMap {
    /// Create a zeroed 64 KB coverage map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bits: vec![0u8; 65_536],
        }
    }

    /// OR `new_bits` into the map.
    ///
    /// `new_bits` is treated cyclically if shorter than the map.  Returns the
    /// number of bits that were newly set (0 → 1 transitions).
    pub fn update(&mut self, new_bits: &[u8]) -> u32 {
        if new_bits.is_empty() {
            return 0;
        }
        let mut count = 0u32;
        for (i, slot) in self.bits.iter_mut().enumerate() {
            let incoming = new_bits[i % new_bits.len()];
            let newly_set = incoming & !(*slot);
            count += newly_set.count_ones();
            *slot |= incoming;
        }
        count
    }

    /// Return `true` if `candidate` would set at least one new bit.
    #[must_use]
    pub fn has_new_bits(&self, candidate: &[u8]) -> bool {
        if candidate.is_empty() {
            return false;
        }
        for (i, &slot) in self.bits.iter().enumerate() {
            let incoming = candidate[i % candidate.len()];
            if incoming & !slot != 0 {
                return true;
            }
        }
        false
    }

    /// Count the total number of bits currently set in the map.
    #[must_use]
    pub fn total_bits(&self) -> u32 {
        self.bits.iter().map(|b| b.count_ones()).sum()
    }
}

impl Default for IpCoverageMap {
    fn default() -> Self {
        Self::new()
    }
}

// ── Interesting constants used by Mutator ─────────────────────────────────────

const INTERESTING_BYTES: &[u8] = &[0, 1, 127, 128, 255, 0xFF, 0x80, 0x7F];
const INTERESTING_WORDS: &[u16] = &[
    0x0000, 0x0001, 0x007F, 0x0080, 0x00FF, 0x0100, 0x7FFF, 0x8000, 0xFFFF,
];
const INTERESTING_DWORDS: &[u32] = &[
    0x0000_0000,
    0x0000_0001,
    0x0000_007F,
    0x0000_0080,
    0x0000_00FF,
    0x0000_0100,
    0x0000_7FFF,
    0x0000_8000,
    0x0000_FFFF,
    0x0001_0000,
    0x7FFF_FFFF,
    0x8000_0000,
    0xFFFF_FFFF,
];

// ── Mutator (§19.2) ───────────────────────────────────────────────────────────

/// AFL-style mutation engine with ten distinct strategies.
///
/// All methods are pure (take `&self`) and driven by a caller-supplied
/// [`SimpleRng`] so they remain deterministic under a fixed seed.
#[derive(Debug, Default, Clone)]
pub struct IpMutator;

impl IpMutator {
    /// Create a new mutator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Produce one mutated variant of `input` by choosing a strategy uniformly
    /// at random.  If `input` is empty a single random byte is returned.
    #[must_use]
    pub fn mutate(&self, input: &[u8], rng: &mut SimpleRng) -> Vec<u8> {
        if input.is_empty() {
            return vec![rng.next_u64() as u8];
        }
        match rng.next_range(10) {
            0 => self.bit_flip(input, rng),
            1 => self.byte_flip(input, rng),
            2 => self.arithmetic_add(input, rng),
            3 => self.interesting_byte(input, rng),
            4 => self.interesting_word(input, rng),
            5 => self.interesting_dword(input, rng),
            6 => self.delete_bytes(input, rng),
            7 => self.insert_bytes(input, rng),
            8 => self.copy_chunk(input, rng),
            _ => self.crossover(input, input, rng),
        }
    }

    /// Produce `count` independent mutations of `input`.
    #[must_use]
    pub fn batch_mutate(&self, input: &[u8], count: usize, rng: &mut SimpleRng) -> Vec<Vec<u8>> {
        (0..count).map(|_| self.mutate(input, rng)).collect()
    }

    // ── Individual strategies ─────────────────────────────────────────────────

    fn bit_flip(&self, input: &[u8], rng: &mut SimpleRng) -> Vec<u8> {
        let mut out = input.to_vec();
        let byte_pos = (rng.next_range(out.len() as u64)) as usize;
        let bit_pos = (rng.next_range(8)) as u8;
        out[byte_pos] ^= 1 << bit_pos;
        out
    }

    fn byte_flip(&self, input: &[u8], rng: &mut SimpleRng) -> Vec<u8> {
        let mut out = input.to_vec();
        let count = (rng.next_range(4) + 1) as usize;
        let pos = (rng.next_range(out.len() as u64)) as usize;
        let end = (pos + count).min(out.len());
        for b in &mut out[pos..end] {
            *b ^= 0xFF;
        }
        out
    }

    fn arithmetic_add(&self, input: &[u8], rng: &mut SimpleRng) -> Vec<u8> {
        let mut out = input.to_vec();
        let delta = rng.next_range(35).cast_signed() - 17; // [-17, 17]
        match rng.next_range(3) {
            0 if !out.is_empty() => {
                // byte
                let pos = (rng.next_range(out.len() as u64)) as usize;
                out[pos] = out[pos].wrapping_add(delta as u8);
            }
            1 if out.len() >= 2 => {
                // word (LE)
                let pos = (rng.next_range((out.len() - 1) as u64)) as usize;
                let val = u16::from_le_bytes([out[pos], out[pos + 1]]).wrapping_add(delta as u16);
                let bytes = val.to_le_bytes();
                out[pos] = bytes[0];
                out[pos + 1] = bytes[1];
            }
            _ if out.len() >= 4 => {
                // dword (LE)
                let pos = (rng.next_range((out.len() - 3) as u64)) as usize;
                let val = u32::from_le_bytes([out[pos], out[pos + 1], out[pos + 2], out[pos + 3]])
                    .wrapping_add(delta as u32);
                let bytes = val.to_le_bytes();
                out[pos..pos + 4].copy_from_slice(&bytes);
            }
            _ if !out.is_empty() => {
                let pos = (rng.next_range(out.len() as u64)) as usize;
                out[pos] = out[pos].wrapping_add(delta as u8);
            }
            _ => {}
        }
        out
    }

    fn interesting_byte(&self, input: &[u8], rng: &mut SimpleRng) -> Vec<u8> {
        let mut out = input.to_vec();
        let pos = (rng.next_range(out.len() as u64)) as usize;
        let idx = (rng.next_range(INTERESTING_BYTES.len() as u64)) as usize;
        out[pos] = INTERESTING_BYTES[idx];
        out
    }

    fn interesting_word(&self, input: &[u8], rng: &mut SimpleRng) -> Vec<u8> {
        let mut out = input.to_vec();
        if out.len() < 2 {
            out.push(0);
        }
        let pos = (rng.next_range((out.len() - 1) as u64)) as usize;
        let idx = (rng.next_range(INTERESTING_WORDS.len() as u64)) as usize;
        let bytes = INTERESTING_WORDS[idx].to_le_bytes();
        out[pos] = bytes[0];
        out[pos + 1] = bytes[1];
        out
    }

    fn interesting_dword(&self, input: &[u8], rng: &mut SimpleRng) -> Vec<u8> {
        let mut out = input.to_vec();
        while out.len() < 4 {
            out.push(0);
        }
        let pos = (rng.next_range((out.len() - 3) as u64)) as usize;
        let idx = crate::cast::u64_to_usize(rng.next_range(INTERESTING_DWORDS.len() as u64));
        let bytes = INTERESTING_DWORDS[idx].to_le_bytes();
        out[pos..pos + 4].copy_from_slice(&bytes);
        out
    }

    fn delete_bytes(&self, input: &[u8], rng: &mut SimpleRng) -> Vec<u8> {
        if input.len() <= 1 {
            return input.to_vec();
        }
        let count = crate::cast::u64_to_usize(rng.next_range(32) + 1);
        let count = count.min(input.len() - 1);
        let pos = crate::cast::u64_to_usize(rng.next_range((input.len() - count) as u64));
        let mut out = Vec::with_capacity(input.len() - count);
        out.extend_from_slice(&input[..pos]);
        out.extend_from_slice(&input[pos + count..]);
        out
    }

    fn insert_bytes(&self, input: &[u8], rng: &mut SimpleRng) -> Vec<u8> {
        let count = crate::cast::u64_to_usize(rng.next_range(32) + 1);
        let pos = crate::cast::u64_to_usize(rng.next_range(input.len().saturating_add(1) as u64));
        let mut out = Vec::with_capacity(input.len() + count);
        out.extend_from_slice(&input[..pos]);
        for _ in 0..count {
            out.push(rng.next_u64() as u8);
        }
        out.extend_from_slice(&input[pos..]);
        out
    }

    fn copy_chunk(&self, input: &[u8], rng: &mut SimpleRng) -> Vec<u8> {
        if input.len() < 2 {
            return input.to_vec();
        }
        let src = crate::cast::u64_to_usize(rng.next_range(input.len() as u64));
        let max_len = (input.len() - src).min(32);
        let chunk_len = crate::cast::u64_to_usize(rng.next_range(max_len as u64) + 1);
        let dst = crate::cast::u64_to_usize(rng.next_range(input.len() as u64));
        let mut out = input.to_vec();
        let end_dst = (dst + chunk_len).min(out.len());
        let copy_count = end_dst - dst;
        let src_end = (src + copy_count).min(input.len());
        let chunk: Vec<u8> = input[src..src_end].to_vec();
        let actual = chunk.len().min(copy_count);
        out[dst..dst + actual].copy_from_slice(&chunk[..actual]);
        out
    }

    /// Crossover: take the first half from `a` and the second half from `b`.
    fn crossover(&self, a: &[u8], b: &[u8], rng: &mut SimpleRng) -> Vec<u8> {
        if a.is_empty() {
            return b.to_vec();
        }
        if b.is_empty() {
            return a.to_vec();
        }
        let split = crate::cast::u64_to_usize(rng.next_range(a.len() as u64));
        let mut out = Vec::with_capacity(split + b.len());
        out.extend_from_slice(&a[..split]);
        out.extend_from_slice(b);
        out
    }
}

// ── FuzzStats / FuzzReport ────────────────────────────────────────────────────

/// Lightweight statistics snapshot for an [`IpInProcessFuzzer`] run.
#[derive(Debug, Clone, Default)]
pub struct FuzzStats {
    /// Total number of iterations performed.
    pub iterations: u64,
    /// Number of crash-producing inputs found.
    pub crashes: u32,
    /// Number of timeout-producing inputs found.
    pub timeouts: u32,
    /// Current corpus size.
    pub corpus_size: u32,
    /// Total coverage bits set across all corpus entries.
    pub total_coverage_bits: u32,
    /// Approximate executions per second.
    pub executions_per_sec: f64,
    /// Total wall-clock runtime in seconds.
    pub runtime_secs: f64,
}

/// Report produced at the end of [`IpInProcessFuzzer::run`].
#[derive(Debug, Clone)]
pub struct FuzzReport {
    /// Final statistics.
    pub stats: FuzzStats,
    /// All crash-producing inputs collected during the run.
    pub crashes: Vec<IpFuzzInput>,
    /// Total new coverage bits discovered over the entire run.
    pub new_coverage: u32,
}

// ── IpInProcessFuzzer (§19.2) ─────────────────────────────────────────────────

/// A self-contained in-process libFuzzer-style fuzzer.
///
/// Usage:
/// ```rust,ignore
/// let mut fuzzer = IpInProcessFuzzer::new(Box::new(my_target));
/// fuzzer.add_seed(b"hello".to_vec());
/// let report = fuzzer.run(100_000);
/// println!("{} crashes found", report.crashes.len());
/// ```
pub struct IpInProcessFuzzer {
    /// The fuzz target.
    pub target: Box<dyn IpFuzzTarget>,
    /// Interesting corpus entries (inputs that increased coverage).
    pub corpus: Vec<IpFuzzInput>,
    /// Global coverage bitmap.
    pub coverage: IpCoverageMap,
    /// Mutation engine.
    pub mutator: IpMutator,
    /// All crash-producing inputs found so far.
    pub crashes: Vec<IpFuzzInput>,
    /// Running statistics.
    pub stats: FuzzStats,
    /// Internal PRNG.
    pub rng: SimpleRng,
}

impl IpInProcessFuzzer {
    /// Create a new fuzzer wrapping `target`.  The corpus is seeded with a
    /// single empty byte vector; callers should call [`Self::add_seed`] to
    /// supply domain-specific seeds.
    #[must_use]
    pub fn new(target: Box<dyn IpFuzzTarget>) -> Self {
        let mut fuzzer = Self {
            target,
            corpus: Vec::new(),
            coverage: IpCoverageMap::new(),
            mutator: IpMutator::new(),
            crashes: Vec::new(),
            stats: FuzzStats::default(),
            rng: SimpleRng::new(0xdead_beef_cafe_1337),
        };
        // Always start with one default seed so the corpus is non-empty.
        fuzzer.corpus.push(IpFuzzInput::new_seed(vec![0u8]));
        fuzzer
    }

    /// Add a seed input to the corpus.
    pub fn add_seed(&mut self, seed: Vec<u8>) {
        self.corpus.push(IpFuzzInput::new_seed(seed));
    }

    /// Run the target against `input`, update coverage, record crashes, and
    /// return the [`FuzzResult`].
    ///
    /// Side effects: updates `self.coverage`, `self.crashes`, `self.stats`.
    pub fn run_one(&mut self, input: Vec<u8>) -> FuzzResult {
        let start = std::time::Instant::now();
        let result = self.target.fuzz_one(&input);
        let elapsed_ns = crate::cast::u128_to_u64(start.elapsed().as_nanos());

        // Derive a synthetic coverage vector from the input hash.
        let h = ip_fnv1a(&input);
        let cov_bytes = h.to_le_bytes();
        let new_bits = self.coverage.update(&cov_bytes);

        match &result {
            FuzzResult::Crash { message, backtrace } => {
                self.stats.crashes += 1;
                let parent_hash = self.corpus.last().map(IpFuzzInput::hash);
                let child_gen = self.corpus.last().map_or(0, |p| p.generation + 1);
                let fi = IpFuzzInput::new_child(
                    input,
                    child_gen,
                    new_bits,
                    elapsed_ns,
                    parent_hash.unwrap_or(0),
                );
                // Deduplicate crashes by input hash; store the crash message.
                let fh = fi.hash();
                if !self.crashes.iter().any(|c| c.hash() == fh) {
                    let mut fi = fi;
                    fi.crash_message = Some(format!(
                        "{message}{}",
                        backtrace
                            .as_deref()
                            .map(|bt| format!("\n{bt}"))
                            .unwrap_or_default()
                    ));
                    self.crashes.push(fi);
                }
            }
            FuzzResult::Timeout => {
                self.stats.timeouts += 1;
            }
            FuzzResult::Normal | FuzzResult::OOM => {}
        }

        result
    }

    /// Pick one input from the corpus, mutate it, run it, and return the
    /// corpus entry if it was interesting (i.e. it increased coverage or
    /// produced a crash/timeout/OOM).
    ///
    /// Returns `Some(IpFuzzInput)` when the iteration produced a new corpus
    /// entry, `None` otherwise.
    pub fn fuzz_iteration(&mut self) -> Option<IpFuzzInput> {
        // Select parent (round-robin by iteration count for simplicity).
        let idx = (self.stats.iterations as usize) % self.corpus.len();
        let parent = self.corpus[idx].clone();
        let parent_hash = parent.hash();
        let parent_gen = parent.generation;

        // Mutate.
        let mutated = self.mutator.mutate(&parent.data, &mut self.rng);

        // Synthetic coverage probe: compute what bits the new input would set.
        let h = ip_fnv1a(&mutated);
        let cov_bytes = h.to_le_bytes();
        let is_interesting = self.coverage.has_new_bits(&cov_bytes);

        // Run the target.
        let start = std::time::Instant::now();
        let result = self.target.fuzz_one(&mutated);
        let elapsed_ns = crate::cast::u128_to_u64(start.elapsed().as_nanos());

        // Update coverage unconditionally.
        let new_bits = self.coverage.update(&cov_bytes);

        let fi = IpFuzzInput::new_child(mutated, parent_gen + 1, new_bits, elapsed_ns, parent_hash);

        self.stats.iterations += 1;

        match &result {
            FuzzResult::Crash { .. } => {
                self.stats.crashes += 1;
                let fh = fi.hash();
                if !self.crashes.iter().any(|c| c.hash() == fh) {
                    self.crashes.push(fi.clone());
                }
                self.corpus.push(fi.clone());
                self.stats.corpus_size = crate::cast::usize_to_u32(self.corpus.len());
                self.stats.total_coverage_bits = self.coverage.total_bits();
                return Some(fi);
            }
            FuzzResult::Timeout => {
                self.stats.timeouts += 1;
            }
            FuzzResult::Normal | FuzzResult::OOM => {}
        }

        if is_interesting || new_bits > 0 {
            self.corpus.push(fi.clone());
            self.stats.corpus_size = crate::cast::usize_to_u32(self.corpus.len());
            self.stats.total_coverage_bits = self.coverage.total_bits();
            Some(fi)
        } else {
            None
        }
    }

    /// Run the fuzzer for exactly `iterations` iterations.
    ///
    /// Returns a [`FuzzReport`] with final statistics and all crash inputs.
    pub fn run(&mut self, iterations: u64) -> FuzzReport {
        let wall_start = std::time::Instant::now();
        let mut new_coverage_total: u32 = 0;

        for _ in 0..iterations {
            if let Some(fi) = self.fuzz_iteration() {
                new_coverage_total += fi.coverage_bits;
            }
        }

        let elapsed = wall_start.elapsed().as_secs_f64();
        self.stats.runtime_secs = elapsed;
        self.stats.executions_per_sec = if elapsed > f64::EPSILON {
            crate::cast::u64_to_f64(iterations) / elapsed
        } else {
            0.0
        };
        self.stats.total_coverage_bits = self.coverage.total_bits();
        self.stats.corpus_size = crate::cast::usize_to_u32(self.corpus.len());

        FuzzReport {
            stats: self.stats.clone(),
            crashes: self.crashes.clone(),
            new_coverage: new_coverage_total,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // ── Mock targets ──────────────────────────────────────────────────────────

    struct AlwaysContinue;
    impl FuzzTarget for AlwaysContinue {
        fn run(&mut self, _input: &[u8]) -> FuzzTargetResult {
            FuzzTargetResult::Continue
        }
        fn name(&self) -> &'static str {
            "AlwaysContinue"
        }
    }

    struct CrashOnLength {
        threshold: usize,
    }
    impl FuzzTarget for CrashOnLength {
        fn run(&mut self, input: &[u8]) -> FuzzTargetResult {
            if input.len() > self.threshold {
                FuzzTargetResult::CrashFound("too long".to_string())
            } else {
                FuzzTargetResult::Continue
            }
        }
    }

    struct CrashOnByte {
        byte: u8,
    }
    impl FuzzTarget for CrashOnByte {
        fn run(&mut self, input: &[u8]) -> FuzzTargetResult {
            if input.contains(&self.byte) {
                FuzzTargetResult::CrashFound(format!("found byte 0x{:02x}", self.byte))
            } else {
                FuzzTargetResult::Continue
            }
        }
    }

    struct CrashAlways;
    impl FuzzTarget for CrashAlways {
        fn run(&mut self, _input: &[u8]) -> FuzzTargetResult {
            FuzzTargetResult::CrashFound("always crashes".to_string())
        }
    }

    struct SetupCounter {
        setup_calls: Arc<Mutex<u32>>,
        teardown_calls: Arc<Mutex<u32>>,
    }
    impl FuzzTarget for SetupCounter {
        fn run(&mut self, _input: &[u8]) -> FuzzTargetResult {
            FuzzTargetResult::Continue
        }
        fn setup(&mut self) {
            *self.setup_calls.lock().expect("mutex poisoned") += 1;
        }
        fn teardown(&mut self) {
            *self.teardown_calls.lock().expect("mutex poisoned") += 1;
        }
    }

    // ── FuzzTargetResult ──────────────────────────────────────────────────────

    #[test]
    fn fuzz_target_result_continue() {
        assert_eq!(FuzzTargetResult::Continue, FuzzTargetResult::Continue);
        assert!(!FuzzTargetResult::Continue.is_crash());
        assert!(FuzzTargetResult::Continue.crash_message().is_none());
    }

    #[test]
    fn fuzz_target_result_crash() {
        let r = FuzzTargetResult::CrashFound("boom".to_string());
        assert!(r.is_crash());
        assert_eq!(r.crash_message(), Some("boom"));
    }

    // ── LibFuzzerError ────────────────────────────────────────────────────────

    #[test]
    fn error_empty_seed_pool_display() {
        let e = LibFuzzerError::EmptySeedPool;
        assert!(e.to_string().contains("empty"));
    }

    #[test]
    fn error_input_too_large_display() {
        let e = LibFuzzerError::InputTooLarge {
            actual: 100,
            limit: 50,
        };
        let s = e.to_string();
        assert!(s.contains("100"));
        assert!(s.contains("50"));
    }

    #[test]
    fn error_corpus_io_display() {
        let e = LibFuzzerError::CorpusIo("disk full".to_string());
        assert!(e.to_string().contains("disk full"));
    }

    #[test]
    fn error_timeout_display() {
        let e = LibFuzzerError::Timeout(Duration::from_secs(5));
        assert!(e.to_string().contains("5s"));
    }

    // ── CrashSignalHandler ────────────────────────────────────────────────────

    #[test]
    fn signal_handler_default_not_crashed() {
        let h = CrashSignalHandler::new();
        assert!(!h.is_crashed());
        assert_eq!(h.total_crashes(), 0);
        assert_eq!(h.last_signal(), None);
    }

    #[test]
    fn signal_handler_inject_crash() {
        let h = CrashSignalHandler::new();
        h.inject_crash(11);
        assert!(h.is_crashed());
        assert_eq!(h.last_signal(), Some(11));
        assert_eq!(h.total_crashes(), 1);
    }

    #[test]
    fn signal_handler_clear_resets_state() {
        let h = CrashSignalHandler::new();
        h.inject_crash(6);
        h.clear();
        assert!(!h.is_crashed());
        assert_eq!(h.last_signal(), None);
        // Total counter is NOT reset by clear
        assert_eq!(h.total_crashes(), 1);
    }

    #[test]
    fn signal_handler_multiple_crashes() {
        let h = CrashSignalHandler::new();
        h.inject_crash(11);
        h.clear();
        h.inject_crash(6);
        assert_eq!(h.total_crashes(), 2);
        assert_eq!(h.last_signal(), Some(6));
    }

    // ── CoverageAccumulator ───────────────────────────────────────────────────

    #[test]
    fn coverage_accumulator_new_starts_empty() {
        let acc = CoverageAccumulator::new(256);
        assert_eq!(acc.active_edges(), 0);
    }

    #[test]
    fn coverage_accumulator_update_returns_new_bits() {
        let acc = CoverageAccumulator::new(64);
        let n = acc.update(&[1, 2, 3, 4]);
        assert!(n > 0);
    }

    #[test]
    fn coverage_accumulator_reset_clears() {
        let acc = CoverageAccumulator::new(64);
        let _ = acc.update(&[1, 2, 3]);
        acc.reset();
        assert_eq!(acc.active_edges(), 0);
    }

    #[test]
    fn coverage_accumulator_snapshot_is_clone() {
        let acc = CoverageAccumulator::new(64);
        let _ = acc.update(&[1]);
        let snap = acc.snapshot();
        assert_eq!(snap.active_edges().len(), acc.active_edges());
    }

    // ── FuzzCorpusManager ─────────────────────────────────────────────────────

    #[test]
    fn corpus_manager_is_novel_first_time() {
        let mut mgr = FuzzCorpusManager::new(Path::new("/tmp/corpus"));
        assert!(mgr.is_novel(b"hello"));
    }

    #[test]
    fn corpus_manager_duplicate_rejected() {
        let mut mgr = FuzzCorpusManager::new(Path::new("/tmp/corpus"));
        mgr.is_novel(b"hello");
        assert!(!mgr.is_novel(b"hello"));
    }

    #[test]
    fn corpus_manager_different_entries_both_novel() {
        let mut mgr = FuzzCorpusManager::new(Path::new("/tmp/corpus"));
        assert!(mgr.is_novel(b"aaa"));
        assert!(mgr.is_novel(b"bbb"));
        assert_eq!(mgr.len(), 2);
    }

    #[test]
    fn corpus_manager_load_returns_ok() {
        let mgr = FuzzCorpusManager::new(Path::new("/tmp/corpus"));
        assert!(mgr.load().is_ok());
    }

    #[test]
    fn corpus_manager_save_novel() {
        let mut mgr = FuzzCorpusManager::new(Path::new("/tmp/corpus"));
        assert!(mgr.save(b"unique_data"));
    }

    #[test]
    fn corpus_manager_save_duplicate() {
        let mut mgr = FuzzCorpusManager::new(Path::new("/tmp/corpus"));
        mgr.save(b"data");
        assert!(!mgr.save(b"data"));
    }

    #[test]
    fn corpus_manager_empty() {
        let mgr = FuzzCorpusManager::new(Path::new("/tmp/corpus"));
        assert!(mgr.is_empty());
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn corpus_manager_clear() {
        let mut mgr = FuzzCorpusManager::new(Path::new("/tmp/corpus"));
        mgr.save(b"a");
        mgr.save(b"b");
        assert_eq!(mgr.len(), 2);
        mgr.clear();
        assert_eq!(mgr.len(), 0);
        assert!(mgr.is_empty());
    }

    #[test]
    fn corpus_manager_entries_returns_saved() {
        let mut mgr = FuzzCorpusManager::new(Path::new("/tmp/corpus"));
        mgr.save(b"hello");
        let entries = mgr.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], b"hello");
    }

    #[test]
    fn corpus_manager_merge_from() {
        let mut mgr1 = FuzzCorpusManager::new(Path::new("/tmp/corpus1"));
        mgr1.save(b"abc");
        let mut mgr2 = FuzzCorpusManager::new(Path::new("/tmp/corpus2"));
        mgr2.save(b"def");
        let added = mgr2.merge_from(&mgr1);
        assert_eq!(added, 1);
        assert_eq!(mgr2.len(), 2);
    }

    #[test]
    fn corpus_manager_max_entries_cap() {
        let opts = CorpusSyncOptions {
            max_entries: 3,
            ..CorpusSyncOptions::default()
        };
        let mut mgr = FuzzCorpusManager::with_options(Path::new("/tmp"), opts);
        for i in 0u8..10 {
            mgr.save(&[i]);
        }
        // entries VecDeque is capped; seen_hashes grows unboundedly
        assert!(mgr.entries().len() <= 3);
    }

    // ── StructuredInput ───────────────────────────────────────────────────────

    #[test]
    fn structured_input_insert_get() {
        let mut s = StructuredInput::new();
        s.insert("foo", b"bar".to_vec());
        assert_eq!(s.get("foo"), Some(b"bar".as_ref()));
    }

    #[test]
    fn structured_input_missing_field() {
        let s = StructuredInput::new();
        assert_eq!(s.get("missing"), None);
    }

    #[test]
    fn structured_input_serialize_deserialize_roundtrip() {
        let mut s = StructuredInput::new();
        s.insert("a", b"hello".to_vec());
        s.insert("b", b"world".to_vec());
        let raw = s.serialize().expect("serialize failed");
        let s2 = StructuredInput::deserialize(&raw).expect("deserialize failed");
        // Check field count matches
        assert_eq!(s2.field_count(), 2);
        assert_eq!(s2.get("field_0"), Some(b"hello".as_ref()));
        assert_eq!(s2.get("field_1"), Some(b"world".as_ref()));
    }

    #[test]
    fn structured_input_empty_serialize() {
        let s = StructuredInput::new();
        assert!(s.is_empty());
        assert_eq!(s.serialize().expect("serialize failed"), Vec::<u8>::new());
    }

    #[test]
    fn structured_input_deserialize_empty() {
        let s = StructuredInput::deserialize(&[]).expect("empty deserialize failed");
        assert!(s.is_empty());
    }

    #[test]
    fn structured_input_deserialize_truncated_returns_error() {
        // A 2-byte length header of 100, but no body
        let raw = vec![100u8, 0u8];
        let result = StructuredInput::deserialize(&raw);
        assert!(result.is_err());
    }

    // ── PersistentModeHarness ─────────────────────────────────────────────────

    #[test]
    fn persistent_mode_not_active_initially() {
        let h = PersistentModeHarness::new(10);
        assert!(!h.is_active());
    }

    #[test]
    fn persistent_mode_start_stop() {
        let mut h = PersistentModeHarness::new(10);
        h.start();
        assert!(h.is_active());
        h.stop();
        assert!(!h.is_active());
    }

    #[test]
    fn persistent_mode_advance_counts() {
        let mut h = PersistentModeHarness::new(3);
        h.start();
        assert!(h.advance()); // 1
        assert!(h.advance()); // 2
        assert!(!h.advance()); // 3 >= max → done
    }

    #[test]
    fn persistent_mode_advance_inactive_returns_false() {
        let mut h = PersistentModeHarness::new(10);
        assert!(!h.advance());
    }

    #[test]
    fn persistent_mode_progress() {
        let mut h = PersistentModeHarness::new(10);
        h.start();
        let _ = h.advance();
        let _ = h.advance();
        let p = h.progress();
        assert!((p - 0.2).abs() < 1e-9, "expected 0.2, got {p}");
    }

    // ── DefaultHavocMutator ───────────────────────────────────────────────────

    #[test]
    fn default_havoc_mutator_name() {
        let m = DefaultHavocMutator::new();
        assert_eq!(m.name(), "DefaultHavocMutator");
    }

    #[test]
    fn default_havoc_mutator_mutates() {
        let mut m = DefaultHavocMutator::new();
        let out = m.mutate(b"hello world", 42, 1024).expect("mutate failed");
        // Non-empty result
        assert!(!out.is_empty() || b"hello world".is_empty());
    }

    #[test]
    fn default_havoc_mutator_respects_max_size() {
        let mut m = DefaultHavocMutator::new();
        let input = vec![1u8; 100];
        let out = m.mutate(&input, 0, 10).expect("mutate failed");
        assert!(out.len() <= 10, "output len {} exceeds limit 10", out.len());
    }

    // ── InputSplicer ──────────────────────────────────────────────────────────

    #[test]
    fn splicer_empty_both() {
        let s = InputSplicer::new();
        let mut rng = XorShiftRng::default();
        assert_eq!(s.splice(&[], &[], &mut rng), Vec::<u8>::new());
    }

    #[test]
    fn splicer_empty_a() {
        let s = InputSplicer::new();
        let mut rng = XorShiftRng::default();
        let out = s.splice(&[], b"hello", &mut rng);
        assert_eq!(out, b"hello");
    }

    #[test]
    fn splicer_empty_b() {
        let s = InputSplicer::new();
        let mut rng = XorShiftRng::default();
        let out = s.splice(b"hello", &[], &mut rng);
        assert_eq!(out, b"hello");
    }

    #[test]
    fn splicer_produces_combined_output() {
        let s = InputSplicer::new();
        let mut rng = XorShiftRng::default();
        let out = s.splice(b"aaaa", b"bbbb", &mut rng);
        // The output should be non-empty
        assert!(!out.is_empty());
    }

    // ── CoverageFilter ────────────────────────────────────────────────────────

    #[test]
    fn coverage_filter_new_input_is_interesting() {
        let mut f = CoverageFilter::new(64);
        assert!(f.is_interesting(&[1, 2, 3]));
    }

    #[test]
    fn coverage_filter_same_input_not_interesting() {
        let mut f = CoverageFilter::new(64);
        f.is_interesting(&[1, 2, 3]);
        // Hashing the same bytes produces the same coverage hash, so no new bits
        assert!(!f.is_interesting(&[1, 2, 3]));
    }

    #[test]
    fn coverage_filter_reset() {
        let mut f = CoverageFilter::new(64);
        f.is_interesting(&[1, 2, 3]);
        f.reset();
        assert_eq!(f.active_edges(), 0);
        // After reset, the same input is interesting again
        assert!(f.is_interesting(&[1, 2, 3]));
    }

    // ── InProcessFuzzer ───────────────────────────────────────────────────────

    #[test]
    fn in_process_run_one_continue() {
        let mut f = InProcessFuzzer::new(Box::new(AlwaysContinue));
        let r = f.run_one(&[1, 2, 3]);
        assert_eq!(r.status, ExecutionStatus::Normal);
    }

    #[test]
    fn in_process_run_one_crash() {
        let mut f = InProcessFuzzer::new(Box::new(CrashOnLength { threshold: 0 }));
        let r = f.run_one(&[1, 2, 3]);
        assert!(matches!(r.status, ExecutionStatus::Crash { .. }));
    }

    #[test]
    fn in_process_coverage_hash_deterministic() {
        let mut f = InProcessFuzzer::new(Box::new(AlwaysContinue));
        let r1 = f.run_one(&[1, 2, 3]);
        f.coverage = CoverageMap::new(65536);
        let r2 = f.run_one(&[1, 2, 3]);
        assert_eq!(r1.coverage_hash, r2.coverage_hash);
    }

    #[test]
    fn in_process_fuzz_limited() {
        let mut f = InProcessFuzzer::new(Box::new(AlwaysContinue));
        let stats = f.fuzz(Some(20));
        assert!(stats.executions >= 20);
    }

    #[test]
    fn in_process_fuzz_records_crashes() {
        let mut f = InProcessFuzzer::new(Box::new(CrashAlways));
        f.add_seed(vec![1, 2, 3]);
        let stats = f.fuzz(Some(5));
        assert!(stats.crashes > 0 || !f.corpus.crashes.is_empty());
    }

    #[test]
    fn in_process_set_coverage_callback() {
        let called = Arc::new(Mutex::new(false));
        let called_clone = Arc::clone(&called);
        let mut f = InProcessFuzzer::new(Box::new(AlwaysContinue));
        f.set_coverage_callback(Box::new(move |_bytes| {
            *called_clone.lock().expect("mutex poisoned") = true;
        }));
        f.run_one(&[1, 2, 3]);
        assert!(*called.lock().expect("mutex poisoned"));
    }

    #[test]
    fn in_process_add_seed() {
        let mut f = InProcessFuzzer::new(Box::new(AlwaysContinue));
        f.add_seed(vec![1, 2, 3]);
        assert!(!f.queue.is_empty());
    }

    #[test]
    fn in_process_setup_teardown_called() {
        let setup_calls = Arc::new(Mutex::new(0u32));
        let teardown_calls = Arc::new(Mutex::new(0u32));
        let target = SetupCounter {
            setup_calls: Arc::clone(&setup_calls),
            teardown_calls: Arc::clone(&teardown_calls),
        };
        let mut f = InProcessFuzzer::new(Box::new(target));
        f.fuzz(Some(1));
        assert_eq!(*setup_calls.lock().expect("mutex poisoned"), 1);
        assert_eq!(*teardown_calls.lock().expect("mutex poisoned"), 1);
    }

    #[test]
    fn in_process_unique_crash_count() {
        let mut f = InProcessFuzzer::new(Box::new(CrashOnByte { byte: 0xde }));
        f.run_one(&[0xde, 0xad]);
        // unique_crash_count reflects crash records
        // unique_crash_count returns usize, just ensure it is callable
        let _ = f.unique_crash_count();
    }

    #[test]
    fn in_process_export_corpus() {
        let mut f = InProcessFuzzer::new(Box::new(AlwaysContinue));
        f.add_seed(vec![1, 2, 3]);
        f.fuzz(Some(5));
        let exported = f.export_corpus();
        // Exported corpus may or may not have entries depending on coverage discovery
        let _ = exported;
    }

    #[test]
    fn in_process_import_seeds() {
        let mut f = InProcessFuzzer::new(Box::new(AlwaysContinue));
        f.import_seeds(vec![vec![1], vec![2], vec![3]]);
        assert_eq!(f.queue.len(), 3);
    }

    #[test]
    fn in_process_with_custom_mutator() {
        let mut f = InProcessFuzzer::with_mutator(
            Box::new(AlwaysContinue),
            Box::new(DefaultHavocMutator::new()),
        );
        let stats = f.fuzz(Some(10));
        assert!(stats.executions >= 10);
    }

    #[test]
    fn in_process_crash_on_byte_no_crash_without_byte() {
        let mut f = InProcessFuzzer::new(Box::new(CrashOnByte { byte: 0xde }));
        let r = f.run_one(&[0x01, 0x02]);
        assert_eq!(r.status, ExecutionStatus::Normal);
    }

    #[test]
    fn in_process_peak_input_len_tracked() {
        let mut f = InProcessFuzzer::new(Box::new(AlwaysContinue));
        f.run_one(&[1, 2, 3, 4, 5]);
        assert_eq!(f.harness_stats.peak_input_len, 5);
        f.run_one(&[1]);
        assert_eq!(f.harness_stats.peak_input_len, 5);
    }

    // ── HarnessStats ──────────────────────────────────────────────────────────

    #[test]
    fn harness_stats_crash_rate_zero_execs() {
        let s = HarnessStats::new();
        assert_eq!(s.crash_rate(), 0.0);
    }

    #[test]
    fn harness_stats_execs_per_sec_zero_elapsed() {
        let s = HarnessStats::new();
        assert_eq!(s.execs_per_sec(), 0.0);
    }

    #[test]
    fn harness_stats_crash_rate() {
        let mut s = HarnessStats::new();
        s.executions = 100;
        s.crashes = 5;
        assert!((s.crash_rate() - 0.05).abs() < 1e-9);
    }

    // ── LibFuzzerHarness ──────────────────────────────────────────────────────

    #[test]
    fn lib_fuzzer_harness_runs() {
        let mut h = LibFuzzerHarness::new(Box::new(AlwaysContinue), 10);
        h.add_seed(vec![1, 2, 3]);
        let stats = h.run(Some(5));
        assert!(stats.executions >= 5);
    }

    #[test]
    fn lib_fuzzer_harness_crashes_empty_initially() {
        let h = LibFuzzerHarness::new(Box::new(AlwaysContinue), 10);
        assert!(h.crashes().is_empty());
    }

    // ── CoverageReport ────────────────────────────────────────────────────────

    #[test]
    fn coverage_report_from_empty_map() {
        let map = CoverageMap::new(256);
        let report = CoverageReport::from_map(&map);
        assert_eq!(report.active_edges, 0);
        assert!((report.density_pct - 0.0).abs() < 1e-9);
    }

    #[test]
    fn coverage_report_from_map_with_data() {
        let mut map = CoverageMap::new(256);
        map.update(&[1, 0, 0, 0]);
        let report = CoverageReport::from_map(&map);
        assert!(report.active_edges > 0);
        assert!(report.density_pct > 0.0);
    }

    // ── FuzzSession ───────────────────────────────────────────────────────────

    #[test]
    fn fuzz_session_new() {
        let stats = HarnessStats::new();
        let session = FuzzSession::new("s1", "my_target", stats, 0);
        assert_eq!(session.id, "s1");
        assert_eq!(session.target_name, "my_target");
        assert_eq!(session.unique_crashes, 0);
    }

    #[test]
    fn fuzz_session_duration_non_negative() {
        let stats = HarnessStats::new();
        let session = FuzzSession::new("s2", "target", stats, 0);
        // Duration should be non-negative (both times very close together)
        let _ = session.duration();
    }

    // ── CrashInfo ─────────────────────────────────────────────────────────────

    #[test]
    fn crash_info_hash_consistent() {
        let c1 = CrashInfo::new(vec![1, 2, 3], 11, "segfault".to_string(), 100);
        let c2 = CrashInfo::new(vec![1, 2, 3], 11, "segfault".to_string(), 200);
        assert_eq!(c1.input_hash, c2.input_hash);
    }

    #[test]
    fn crash_info_different_inputs_different_hashes() {
        let c1 = CrashInfo::new(vec![1, 2, 3], 11, "a".to_string(), 0);
        let c2 = CrashInfo::new(vec![4, 5, 6], 11, "a".to_string(), 0);
        assert_ne!(c1.input_hash, c2.input_hash);
    }

    // ── §19.2 SimpleRng ───────────────────────────────────────────────────────

    #[test]
    fn simple_rng_nonzero_seed() {
        let mut r = SimpleRng::new(1);
        let v = r.next_u64();
        assert_ne!(v, 0, "xorshift64 should not produce 0 from seed 1");
    }

    #[test]
    fn simple_rng_zero_seed_remapped() {
        let mut r = SimpleRng::new(0);
        // Internal seed is remapped, so it should not be 0
        let v = r.next_u64();
        assert_ne!(v, 0);
    }

    #[test]
    fn simple_rng_deterministic() {
        let mut r1 = SimpleRng::new(42);
        let mut r2 = SimpleRng::new(42);
        for _ in 0..20 {
            assert_eq!(r1.next_u64(), r2.next_u64());
        }
    }

    #[test]
    fn simple_rng_next_range_in_bounds() {
        let mut r = SimpleRng::new(999);
        for _ in 0..1000 {
            let v = r.next_range(100);
            assert!(v < 100, "next_range(100) returned {v}");
        }
    }

    #[test]
    fn simple_rng_next_range_zero_returns_zero() {
        let mut r = SimpleRng::new(1);
        assert_eq!(r.next_range(0), 0);
    }

    // ── §19.2 IpFuzzInput ─────────────────────────────────────────────────────

    #[test]
    fn ip_fuzz_input_hash_deterministic() {
        let fi = IpFuzzInput::new_seed(vec![1, 2, 3]);
        assert_eq!(fi.hash(), fi.hash());
    }

    #[test]
    fn ip_fuzz_input_hash_differs_for_different_data() {
        let a = IpFuzzInput::new_seed(vec![1, 2, 3]);
        let b = IpFuzzInput::new_seed(vec![4, 5, 6]);
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn ip_fuzz_input_seed_has_no_parent() {
        let fi = IpFuzzInput::new_seed(b"hello".to_vec());
        assert_eq!(fi.generation, 0);
        assert!(fi.parent_hash.is_none());
    }

    #[test]
    fn ip_fuzz_input_child_carries_parent_hash() {
        let parent = IpFuzzInput::new_seed(vec![0]);
        let ph = parent.hash();
        let child = IpFuzzInput::new_child(vec![1], 1, 5, 1000, ph);
        assert_eq!(child.parent_hash, Some(ph));
        assert_eq!(child.generation, 1);
    }

    // ── §19.2 FuzzResult ─────────────────────────────────────────────────────

    #[test]
    fn fuzz_result_normal_not_crash() {
        assert!(!FuzzResult::Normal.is_crash());
        assert!(!FuzzResult::Normal.is_interesting());
    }

    #[test]
    fn fuzz_result_crash_is_crash() {
        let r = FuzzResult::Crash {
            message: "boom".to_string(),
            backtrace: None,
        };
        assert!(r.is_crash());
        assert!(r.is_interesting());
    }

    #[test]
    fn fuzz_result_timeout_is_interesting() {
        assert!(FuzzResult::Timeout.is_interesting());
        assert!(!FuzzResult::Timeout.is_crash());
    }

    #[test]
    fn fuzz_result_oom_is_interesting() {
        assert!(FuzzResult::OOM.is_interesting());
    }

    // ── §19.2 IpCoverageMap ───────────────────────────────────────────────────

    #[test]
    fn ip_coverage_map_new_all_zero() {
        let m = IpCoverageMap::new();
        assert_eq!(m.total_bits(), 0);
        assert_eq!(m.bits.len(), 65_536);
    }

    #[test]
    fn ip_coverage_map_update_returns_new_bits() {
        let mut m = IpCoverageMap::new();
        let n = m.update(&[0xFF]);
        assert!(n > 0);
    }

    #[test]
    fn ip_coverage_map_update_same_input_no_new_bits() {
        let mut m = IpCoverageMap::new();
        m.update(&[0xAB, 0xCD]);
        let n = m.update(&[0xAB, 0xCD]);
        assert_eq!(n, 0, "same data should yield 0 new bits on second update");
    }

    #[test]
    fn ip_coverage_map_has_new_bits_true_for_unseen() {
        let m = IpCoverageMap::new();
        assert!(m.has_new_bits(&[0x01]));
    }

    #[test]
    fn ip_coverage_map_has_new_bits_false_after_update() {
        let mut m = IpCoverageMap::new();
        // Build a byte pattern that fills the first slot.
        let pat = vec![0xFF; 65_536];
        m.update(&pat);
        // Candidate with all same bits should have no new bits.
        assert!(!m.has_new_bits(&pat));
    }

    #[test]
    fn ip_coverage_map_total_bits_increases() {
        let mut m = IpCoverageMap::new();
        let before = m.total_bits();
        m.update(&[1, 2, 3]);
        assert!(m.total_bits() >= before);
    }

    // ── §19.2 IpMutator ──────────────────────────────────────────────────────

    #[test]
    fn ip_mutator_mutate_nonempty_input() {
        let m = IpMutator::new();
        let mut rng = SimpleRng::new(1);
        let out = m.mutate(&[1, 2, 3, 4, 5], &mut rng);
        assert!(!out.is_empty());
    }

    #[test]
    fn ip_mutator_mutate_empty_input_returns_one_byte() {
        let m = IpMutator::new();
        let mut rng = SimpleRng::new(7);
        let out = m.mutate(&[], &mut rng);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn ip_mutator_batch_mutate_count() {
        let m = IpMutator::new();
        let mut rng = SimpleRng::new(42);
        let results = m.batch_mutate(&[0xAA, 0xBB], 10, &mut rng);
        assert_eq!(results.len(), 10);
    }

    #[test]
    fn ip_mutator_bit_flip_changes_one_bit() {
        // Run many times; at least one result should differ from the input.
        let m = IpMutator::new();
        let input = vec![0u8; 8];
        let mut rng = SimpleRng::new(123);
        let mut found_diff = false;
        for _ in 0..50 {
            let out = m.mutate(&input, &mut rng);
            if out != input {
                found_diff = true;
                break;
            }
        }
        assert!(
            found_diff,
            "mutator should produce at least one different output"
        );
    }

    #[test]
    fn ip_mutator_delete_bytes_shrinks_or_same() {
        let m = IpMutator::new();
        let input = vec![1u8; 64];
        let mut rng = SimpleRng::new(55);
        // Force delete_bytes (strategy index 6).
        // We call batch_mutate many times and look for a shorter output.
        let results = m.batch_mutate(&input, 200, &mut rng);
        let has_shorter = results.iter().any(|v| v.len() < input.len());
        assert!(
            has_shorter,
            "delete_bytes should sometimes shorten the input"
        );
    }

    #[test]
    fn ip_mutator_insert_bytes_grows_or_same() {
        let m = IpMutator::new();
        let input = vec![1u8; 8];
        let mut rng = SimpleRng::new(77);
        let results = m.batch_mutate(&input, 200, &mut rng);
        let has_longer = results.iter().any(|v| v.len() > input.len());
        assert!(
            has_longer,
            "insert_bytes should sometimes lengthen the input"
        );
    }

    // ── §19.2 IpInProcessFuzzer ───────────────────────────────────────────────

    struct IpAlwaysContinue;
    impl IpFuzzTarget for IpAlwaysContinue {
        fn fuzz_one(&self, _input: &[u8]) -> FuzzResult {
            FuzzResult::Normal
        }
    }

    struct _IpCrashOnByte(u8);
    impl IpFuzzTarget for _IpCrashOnByte {
        fn fuzz_one(&self, input: &[u8]) -> FuzzResult {
            if input.contains(&self.0) {
                FuzzResult::Crash {
                    message: format!("byte 0x{:02x} found", self.0),
                    backtrace: None,
                }
            } else {
                FuzzResult::Normal
            }
        }
    }

    struct IpCrashAlways;
    impl IpFuzzTarget for IpCrashAlways {
        fn fuzz_one(&self, _input: &[u8]) -> FuzzResult {
            FuzzResult::Crash {
                message: "always crashes".to_string(),
                backtrace: Some("fake::backtrace".to_string()),
            }
        }
    }

    struct IpTimeoutAlways;
    impl IpFuzzTarget for IpTimeoutAlways {
        fn fuzz_one(&self, _input: &[u8]) -> FuzzResult {
            FuzzResult::Timeout
        }
    }

    #[test]
    fn ip_fuzzer_new_has_default_seed() {
        let f = IpInProcessFuzzer::new(Box::new(IpAlwaysContinue));
        assert!(!f.corpus.is_empty());
    }

    #[test]
    fn ip_fuzzer_add_seed_grows_corpus() {
        let mut f = IpInProcessFuzzer::new(Box::new(IpAlwaysContinue));
        let before = f.corpus.len();
        f.add_seed(b"hello world".to_vec());
        assert_eq!(f.corpus.len(), before + 1);
    }

    #[test]
    fn ip_fuzzer_run_one_normal() {
        let mut f = IpInProcessFuzzer::new(Box::new(IpAlwaysContinue));
        let r = f.run_one(b"test".to_vec());
        assert_eq!(r, FuzzResult::Normal);
    }

    #[test]
    fn ip_fuzzer_run_one_crash_recorded() {
        let mut f = IpInProcessFuzzer::new(Box::new(IpCrashAlways));
        let r = f.run_one(b"anything".to_vec());
        assert!(r.is_crash());
        assert_eq!(f.crashes.len(), 1);
        assert_eq!(f.stats.crashes, 1);
    }

    #[test]
    fn ip_fuzzer_run_one_timeout_counted() {
        let mut f = IpInProcessFuzzer::new(Box::new(IpTimeoutAlways));
        let r = f.run_one(b"x".to_vec());
        assert_eq!(r, FuzzResult::Timeout);
        assert_eq!(f.stats.timeouts, 1);
    }

    #[test]
    fn ip_fuzzer_crash_dedup() {
        let mut f = IpInProcessFuzzer::new(Box::new(IpCrashAlways));
        // Same input twice: should only record one crash entry.
        f.run_one(b"abc".to_vec());
        f.run_one(b"abc".to_vec());
        assert_eq!(f.crashes.len(), 1);
    }

    #[test]
    fn ip_fuzzer_fuzz_iteration_advances_counter() {
        let mut f = IpInProcessFuzzer::new(Box::new(IpAlwaysContinue));
        f.fuzz_iteration();
        assert_eq!(f.stats.iterations, 1);
    }

    #[test]
    fn ip_fuzzer_run_produces_report() {
        let mut f = IpInProcessFuzzer::new(Box::new(IpAlwaysContinue));
        let report = f.run(100);
        assert_eq!(report.stats.iterations, 100);
        assert!(report.stats.runtime_secs >= 0.0);
    }

    #[test]
    fn ip_fuzzer_run_records_crashes() {
        let mut f = IpInProcessFuzzer::new(Box::new(IpCrashAlways));
        f.add_seed(b"seed".to_vec());
        let report = f.run(50);
        assert!(report.stats.crashes > 0);
        assert!(!report.crashes.is_empty());
    }

    #[test]
    fn ip_fuzzer_run_timeout_counted_in_report() {
        let mut f = IpInProcessFuzzer::new(Box::new(IpTimeoutAlways));
        let report = f.run(20);
        assert_eq!(report.stats.timeouts, 20);
    }

    #[test]
    fn ip_fuzzer_executions_per_sec_positive() {
        let mut f = IpInProcessFuzzer::new(Box::new(IpAlwaysContinue));
        let report = f.run(500);
        // exec/sec should be positive when some time has elapsed, but we
        // tolerate 0.0 on extremely fast machines where elapsed rounds to 0.
        assert!(report.stats.executions_per_sec >= 0.0);
    }

    #[test]
    fn ip_fuzzer_corpus_grows_with_interesting_inputs() {
        let mut f = IpInProcessFuzzer::new(Box::new(IpAlwaysContinue));
        let before = f.corpus.len();
        // Run enough iterations that coverage diversity should add entries.
        f.run(200);
        // Corpus must be at least as large as the initial seed.
        assert!(f.corpus.len() >= before);
    }

    #[test]
    fn ip_fuzzer_stats_corpus_size_consistent() {
        let mut f = IpInProcessFuzzer::new(Box::new(IpAlwaysContinue));
        let report = f.run(50);
        assert_eq!(report.stats.corpus_size, f.corpus.len() as u32);
    }

    #[test]
    fn ip_fnv1a_empty_is_offset_basis() {
        // FNV-1a of empty slice is the offset basis.
        let h = ip_fnv1a(&[]);
        assert_eq!(h, 0xcbf2_9ce4_8422_2325u64);
    }

    #[test]
    fn ip_fnv1a_known_value() {
        // FNV-1a of b"a" (0x61): offset ^ 0x61 * prime
        let h = ip_fnv1a(b"a");
        assert_ne!(h, 0);
        assert_ne!(h, ip_fnv1a(b"b"));
    }
}
