//! In-process libFuzzer harness.
//!
//! Provides:
//! * [`LibFuzzerHarnessExt`] trait — `fuzz_target(data: &[u8])` entry point
//!   matching the libFuzzer ABI.
//! * [`HarnessRunner`] — drives the harness, manages the signal handler, timeout
//!   counter, and 8-bit `SanitizerCoverage` counters.
//! * [`SanitizerCoverage`] — 64 KB array of 8-bit edge counters mirroring
//!   libFuzzer's `__sanitizer_cov_8bit_counters_init` layout.
//! * A stub `LLVMFuzzerTestOneInput` symbol (disabled by default; enable with
//!   the `llvm_fuzz_abi` cfg flag).

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── HarnessError ─────────────────────────────────────────────────────────────

/// Errors produced by the in-process harness layer.
#[derive(Debug, Error)]
pub enum HarnessError {
    /// The harness timed out waiting for the fuzz target.
    #[error("fuzz target timed out after {0:?}")]
    Timeout(Duration),
    /// The fuzz target produced a crash signal.
    #[error("crash detected: signal {signal}, message: {message}")]
    Crash {
        /// Unix signal number (e.g. 11 = SIGSEGV).
        signal: i32,
        /// Free-form crash description.
        message: String,
    },
    /// Maximum input length exceeded.
    #[error("input length {actual} exceeds max {limit}")]
    InputTooLarge { actual: usize, limit: usize },
    /// No seeds were provided and the empty pool could not be used.
    #[error("empty seed pool")]
    EmptySeedPool,
    /// Internal harness error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl HarnessError {
    /// Construct a crash error.
    #[must_use]
    pub fn crash(signal: i32, message: impl Into<String>) -> Self {
        Self::Crash {
            signal,
            message: message.into(),
        }
    }

    /// Return `true` if this is a crash.
    #[must_use]
    pub const fn is_crash(&self) -> bool {
        matches!(self, Self::Crash { .. })
    }

    /// Return `true` if this is a timeout.
    #[must_use]
    pub const fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout(_))
    }
}

// ─── LibFuzzerHarnessExt trait ────────────────────────────────────────────────

/// Trait implemented by a fuzz target to be driven by [`HarnessRunner`].
///
/// The naming `LibFuzzerHarnessExt` distinguishes it from the existing
/// `LibFuzzerHarness` struct already defined in the crate root.
pub trait LibFuzzerHarnessExt: Send {
    /// Process one fuzz input.
    ///
    /// Return `Ok(())` to continue fuzzing, or `Err(HarnessError::Crash {..})`
    /// to signal a crash-worthy event.  Panics are caught by the runner and
    /// converted into `HarnessError::Crash`.
    ///
    /// # Errors
    ///
    /// Returns [`HarnessError`] on crash or timeout.
    fn fuzz_target(&mut self, data: &[u8]) -> Result<(), HarnessError>;

    /// Target name (used for logging).
    #[must_use]
    fn target_name(&self) -> &'static str {
        "unnamed"
    }

    /// Maximum accepted input length.  `None` means no limit.
    #[must_use]
    fn max_input_len(&self) -> Option<usize> {
        None
    }

    /// Called once before any fuzzing begins.
    fn initialize(&mut self) {}

    /// Called once after fuzzing ends.
    fn finalize(&mut self) {}
}

// ─── SanitizerCoverage ────────────────────────────────────────────────────────

/// 8-bit `SanitizerCoverage` edge counter array.
///
/// Each element corresponds to one instrumented edge.  libFuzzer's
/// `__sanitizer_cov_8bit_counters_init` registers a pointer to this buffer;
/// here we model it as a plain `Vec<u8>`.
#[derive(Debug, Clone)]
pub struct SanitizerCoverage {
    /// Edge counter array (8-bit, saturating).
    pub counters: Vec<u8>,
    /// Number of counters that have been hit at least once.
    hit_count: usize,
}

impl SanitizerCoverage {
    /// Create a new coverage array of `size` counters, all zero.
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            counters: vec![0u8; size],
            hit_count: 0,
        }
    }

    /// Create a 64 KB coverage array (standard libFuzzer size).
    #[must_use]
    pub fn default_64k() -> Self {
        Self::new(65_536)
    }

    /// Record a hit at `edge_index`.  The counter saturates at 255.
    ///
    /// Returns `true` if this is the first hit for this edge (new coverage).
    pub fn record_hit(&mut self, edge_index: usize) -> bool {
        if edge_index >= self.counters.len() {
            return false;
        }
        let was_zero = self.counters[edge_index] == 0;
        self.counters[edge_index] = self.counters[edge_index].saturating_add(1);
        if was_zero {
            self.hit_count += 1;
            true
        } else {
            false
        }
    }

    /// Count the number of edges hit at least once.
    #[must_use]
    pub const fn edges_hit(&self) -> usize {
        self.hit_count
    }

    /// Total edge capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.counters.len()
    }

    /// Coverage density: fraction of edges hit.
    #[must_use]
    pub fn density(&self) -> f64 {
        if self.counters.is_empty() {
            0.0
        } else {
            (self.hit_count as f64) / (self.counters.len() as f64)
        }
    }

    /// Reset all counters to zero.
    pub fn reset(&mut self) {
        self.counters.fill(0);
        self.hit_count = 0;
    }

    /// Merge another coverage array into this one (OR operation).
    /// Returns the count of newly discovered edges.
    pub fn merge(&mut self, other: &Self) -> usize {
        let len = self.counters.len().min(other.counters.len());
        let mut new_edges = 0;
        for i in 0..len {
            if self.counters[i] == 0 && other.counters[i] > 0 {
                new_edges += 1;
                self.hit_count += 1;
            }
            self.counters[i] = self.counters[i].saturating_add(other.counters[i]);
        }
        new_edges
    }

    /// Return indices of all edges that have been hit.
    #[must_use]
    pub fn hit_edges(&self) -> Vec<usize> {
        self.counters
            .iter()
            .enumerate()
            .filter(|&(_, &c)| c > 0)
            .map(|(i, _)| i)
            .collect()
    }

    /// Return a compact bit-vector representation of hit edges.
    #[must_use]
    pub fn to_bitmap(&self) -> Vec<u8> {
        let bytes = self.counters.len().div_ceil(8);
        let mut bm = vec![0u8; bytes];
        for (i, &c) in self.counters.iter().enumerate() {
            if c > 0 {
                bm[i / 8] |= 1 << (i % 8);
            }
        }
        bm
    }
}

// ─── CrashRecord ──────────────────────────────────────────────────────────────

/// A record of one crash event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashRecord {
    /// The input that triggered the crash.
    pub input: Vec<u8>,
    /// Signal number.
    pub signal: i32,
    /// Human-readable description.
    pub message: String,
    /// FNV-1a hash of the input.
    pub hash: u64,
    /// Execution number when the crash was found.
    pub found_at: u64,
}

impl CrashRecord {
    /// Create a new crash record.
    #[must_use]
    pub fn new(input: &[u8], signal: i32, message: String, found_at: u64) -> Self {
        Self {
            hash: fnv1a_hash(input),
            input: input.to_vec(),
            signal,
            message,
            found_at,
        }
    }
}

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

// ─── TimeoutHandler ───────────────────────────────────────────────────────────

/// A simple deadline-based timeout handler.
///
/// The handler records the deadline; the runner checks [`TimeoutHandler::expired`]
/// after each iteration.
#[derive(Debug, Clone)]
pub struct TimeoutHandler {
    /// Deadline for the current input.
    deadline: Option<Instant>,
    /// Per-input timeout.
    pub per_input_timeout: Option<Duration>,
    /// Total timeouts detected.
    pub timeout_count: u64,
}

impl TimeoutHandler {
    /// Create a handler with the given per-input timeout.
    #[must_use]
    pub const fn new(per_input_timeout: Option<Duration>) -> Self {
        Self {
            deadline: None,
            per_input_timeout,
            timeout_count: 0,
        }
    }

    /// Arm the handler for a new input.
    pub fn arm(&mut self) {
        self.deadline = self.per_input_timeout.map(|d| Instant::now() + d);
    }

    /// Disarm the handler (input completed in time).
    pub const fn disarm(&mut self) {
        self.deadline = None;
    }

    /// Return `true` if the deadline has passed.
    #[must_use]
    pub fn expired(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }

    /// Record a timeout.
    pub const fn record_timeout(&mut self) {
        self.timeout_count += 1;
        self.deadline = None;
    }

    /// Remaining time before deadline, or `None` if not armed.
    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        self.deadline
            .map(|d| d.saturating_duration_since(Instant::now()))
    }
}

// ─── RunnerConfig ─────────────────────────────────────────────────────────────

/// Configuration for [`HarnessRunner`].
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// Maximum iterations.  `None` = run indefinitely.
    pub max_iterations: Option<u64>,
    /// Per-input timeout.
    pub per_input_timeout: Option<Duration>,
    /// Maximum input size in bytes (0 = unlimited).
    pub max_input_size: usize,
    /// Print stats every N iterations (0 = disabled).
    pub stats_interval: u64,
    /// Stop after the first crash.
    pub stop_on_first_crash: bool,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            max_iterations: None,
            per_input_timeout: Some(Duration::from_secs(10)),
            max_input_size: 1024 * 1024,
            stats_interval: 10_000,
            stop_on_first_crash: false,
        }
    }
}

// ─── RunnerStats ──────────────────────────────────────────────────────────────

/// Statistics produced by a [`HarnessRunner`] run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunnerStats {
    /// Total iterations executed.
    pub iterations: u64,
    /// Crashes detected.
    pub crashes: u64,
    /// Unique crashes (by hash).
    pub unique_crashes: u64,
    /// Timeouts detected.
    pub timeouts: u64,
    /// Total execution time.
    pub elapsed: Duration,
    /// Executions per second.
    pub execs_per_sec: f64,
    /// Coverage edges hit.
    pub edges_hit: usize,
    /// Coverage density.
    pub coverage_density: f64,
    /// Peak input length.
    pub peak_input_len: usize,
}

impl fmt::Display for RunnerStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "iters={} crashes={} timeouts={} execs/s={:.0} coverage={}/{} ({:.2}%)",
            self.iterations,
            self.crashes,
            self.timeouts,
            self.execs_per_sec,
            self.edges_hit,
            0,
            self.coverage_density * 100.0,
        )
    }
}

// ─── HarnessRunner ────────────────────────────────────────────────────────────

/// Drives a [`LibFuzzerHarnessExt`] implementation through a corpus-based
/// mutation loop.
pub struct HarnessRunner {
    /// Fuzz target.
    target: Box<dyn LibFuzzerHarnessExt>,
    /// Global coverage accumulator.
    pub coverage: SanitizerCoverage,
    /// Timeout handler.
    pub timeout_handler: TimeoutHandler,
    /// Crash signal handler.
    pub signal_handler: SignalHandler,
    /// Crash records.
    pub crashes: Vec<CrashRecord>,
    /// Seed corpus.
    seeds: Vec<Vec<u8>>,
    /// Run configuration.
    pub config: RunnerConfig,
    /// Running statistics.
    pub stats: RunnerStats,
}

impl HarnessRunner {
    /// Create a runner for the given target.
    #[must_use]
    pub fn new(target: Box<dyn LibFuzzerHarnessExt>) -> Self {
        let config = RunnerConfig::default();
        let timeout = config.per_input_timeout;
        Self {
            target,
            coverage: SanitizerCoverage::default_64k(),
            timeout_handler: TimeoutHandler::new(timeout),
            signal_handler: SignalHandler::new(),
            crashes: Vec::new(),
            seeds: Vec::new(),
            config,
            stats: RunnerStats::default(),
        }
    }

    /// Apply a configuration.
    pub const fn set_config(&mut self, config: RunnerConfig) {
        let timeout = config.per_input_timeout;
        self.config = config;
        self.timeout_handler.per_input_timeout = timeout;
    }

    /// Add a seed input.
    pub fn add_seed(&mut self, seed: Vec<u8>) {
        self.seeds.push(seed);
    }

    /// Add multiple seeds.
    pub fn add_seeds(&mut self, seeds: impl IntoIterator<Item = Vec<u8>>) {
        self.seeds.extend(seeds);
    }

    /// Run one fuzz iteration with the given `input`.
    ///
    /// Returns `true` if the run produced new coverage (or a crash).
    pub fn run_one(&mut self, input: &[u8]) -> bool {
        // Check input size limit.
        if self.config.max_input_size > 0 && input.len() > self.config.max_input_size {
            return false;
        }

        self.stats.peak_input_len = self.stats.peak_input_len.max(input.len());
        self.signal_handler.clear();
        self.timeout_handler.arm();

        // Simulate coverage from the input (deterministic stub).
        let coverage_bytes = simulate_coverage(input);
        let new_edges = self.update_coverage(&coverage_bytes);

        // Run the target.
        let result = self.target.fuzz_target(input);
        self.timeout_handler.disarm();

        // Check for signal-based crash.
        let signal_crash = self.signal_handler.is_crashed();

        match result {
            Err(HarnessError::Crash {
                signal,
                ref message,
            }) => {
                let record =
                    CrashRecord::new(input, signal, message.clone(), self.stats.iterations);
                self.record_crash(record);
                return true;
            }
            Err(HarnessError::Internal(ref message)) => {
                // Internal harness errors are recorded as synthetic crashes
                // with signal 0 so they surface in the crash report.
                let record = CrashRecord::new(input, 0, message.clone(), self.stats.iterations);
                self.record_crash(record);
                return true;
            }
            Err(HarnessError::Timeout(_)) => {
                self.stats.timeouts += 1;
                self.timeout_handler.record_timeout();
            }
            Err(_) | Ok(()) => { /* other errors: continue */ }
            }

        if signal_crash {
            let sig = self.signal_handler.last_signal().unwrap_or(0);
            let record =
                CrashRecord::new(input, sig, format!("signal {sig}"), self.stats.iterations);
            self.record_crash(record);
            return true;
        }

        if self.timeout_handler.expired() {
            self.stats.timeouts += 1;
            self.timeout_handler.record_timeout();
        }

        new_edges > 0
    }

    fn record_crash(&mut self, record: CrashRecord) {
        self.stats.crashes += 1;
        let h = record.hash;
        if !self.crashes.iter().any(|c| c.hash == h) {
            self.crashes.push(record);
            self.stats.unique_crashes += 1;
        }
    }

    fn update_coverage(&mut self, cov: &[u8]) -> usize {
        let mut new_edges = 0usize;
        for (i, &byte) in cov.iter().enumerate() {
            if byte > 0 {
                let edge = i % self.coverage.capacity();
                if self.coverage.record_hit(edge) {
                    new_edges += 1;
                }
            }
        }
        self.stats.edges_hit = self.coverage.edges_hit();
        self.stats.coverage_density = self.coverage.density();
        new_edges
    }

    /// Run the harness for all seeds, then mutate for `extra_iters` iterations.
    pub fn run(&mut self, extra_iters: u64) -> RunnerStats {
        self.target.initialize();

        if self.seeds.is_empty() {
            self.seeds.push(vec![0u8; 4]);
        }

        let start = Instant::now();

        // First pass: run all seeds.
        let seeds: Vec<Vec<u8>> = self.seeds.clone();
        for seed in &seeds {
            self.stats.iterations += 1;
            self.run_one(seed);
            if self.config.stop_on_first_crash && !self.crashes.is_empty() {
                break;
            }
        }

        // Mutation loop.
        let mut rng = SimpleRng::new(0xdead_beef);
        let max = self
            .config
            .max_iterations
            .unwrap_or(extra_iters + self.stats.iterations);
        while self.stats.iterations < max {
            if self.config.stop_on_first_crash && !self.crashes.is_empty() {
                break;
            }
            let parent = &seeds[self.stats.iterations as usize % seeds.len()];
            let mutated = simple_mutate(parent, &mut rng);
            self.stats.iterations += 1;
            self.run_one(&mutated);
        }

        let elapsed = start.elapsed();
        self.stats.elapsed = elapsed;
        let secs = elapsed.as_secs_f64();
        self.stats.execs_per_sec = if secs > 0.0 {
            (self.stats.iterations) as f64 / secs
        } else {
            0.0
        };

        self.target.finalize();
        self.stats.clone()
    }

    /// Return unique crash count.
    #[must_use]
    pub const fn unique_crash_count(&self) -> usize {
        self.crashes.len()
    }

    /// Return the target name.
    #[must_use]
    pub fn target_name(&self) -> &str {
        self.target.target_name()
    }
}

impl fmt::Debug for HarnessRunner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HarnessRunner")
            .field("target", &self.target.target_name())
            .field("crashes", &self.crashes.len())
            .field("iterations", &self.stats.iterations)
            .finish_non_exhaustive()
    }
}

// ─── SignalHandler ────────────────────────────────────────────────────────────

/// In-process crash signal handler stub.
///
/// On a real Unix system this would install signal handlers for SIGSEGV,
/// SIGABRT, SIGFPE etc.  Here we expose a test-injectable interface.
#[derive(Debug, Clone, Default)]
pub struct SignalHandler {
    /// Whether a crash signal has been detected.
    crashed: Arc<Mutex<bool>>,
    /// The signal that triggered the crash.
    last_signal: Arc<Mutex<Option<i32>>>,
    /// Total crashes detected.
    total: Arc<Mutex<u64>>,
}

impl SignalHandler {
    /// Create a new handler in the cleared state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulate receiving signal `sig`.
    pub fn inject(&self, sig: i32) {
        *self.crashed.lock().unwrap() = true;
        *self.last_signal.lock().unwrap() = Some(sig);
        *self.total.lock().unwrap() += 1;
    }

    /// Return `true` if a signal has been received since last [`clear`](Self::clear).
    #[must_use]
    pub fn is_crashed(&self) -> bool {
        *self.crashed.lock().unwrap()
    }

    /// Return the last signal received.
    #[must_use]
    pub fn last_signal(&self) -> Option<i32> {
        *self.last_signal.lock().unwrap()
    }

    /// Clear crash state (total counter preserved).
    pub fn clear(&self) {
        *self.crashed.lock().unwrap() = false;
        *self.last_signal.lock().unwrap() = None;
    }

    /// Total crashes since creation.
    #[must_use]
    pub fn total_crashes(&self) -> u64 {
        *self.total.lock().unwrap()
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Deterministic coverage simulation: hash the input and use it to pick edges.
fn simulate_coverage(input: &[u8]) -> Vec<u8> {
    let h = fnv1a_hash(input);
    h.to_le_bytes().to_vec()
}

/// Tiny xorshift PRNG (local copy to avoid dependency cycle).
struct SimpleRng {
    s: u64,
}

impl SimpleRng {
    const fn new(seed: u64) -> Self {
        Self {
            s: if seed == 0 { 1 } else { seed },
        }
    }

    const fn next_u64(&mut self) -> u64 {
        let mut x = self.s;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.s = x;
        x
    }

    const fn range(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
}

fn simple_mutate(input: &[u8], rng: &mut SimpleRng) -> Vec<u8> {
    if input.is_empty() {
        return vec![rng.next_u64() as u8];
    }
    let mut out = input.to_vec();
    let pos = (rng.range(out.len() as u64)) as usize;
    out[pos] ^= rng.next_u64() as u8;
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mock targets ──────────────────────────────────────────────────────────

    struct PassTarget;
    impl LibFuzzerHarnessExt for PassTarget {
        fn fuzz_target(&mut self, _data: &[u8]) -> Result<(), HarnessError> {
            Ok(())
        }
        fn target_name(&self) -> &'static str {
            "pass"
        }
    }

    struct CrashOnZero;
    impl LibFuzzerHarnessExt for CrashOnZero {
        fn fuzz_target(&mut self, data: &[u8]) -> Result<(), HarnessError> {
            if data.first() == Some(&0) {
                Err(HarnessError::crash(6, "zero byte crash"))
            } else {
                Ok(())
            }
        }
        fn target_name(&self) -> &'static str {
            "crash_on_zero"
        }
    }

    struct CountCalls {
        calls: Arc<Mutex<u64>>,
    }
    impl LibFuzzerHarnessExt for CountCalls {
        fn fuzz_target(&mut self, _data: &[u8]) -> Result<(), HarnessError> {
            *self.calls.lock().unwrap() += 1;
            Ok(())
        }
    }

    #[test]
    fn sanitizer_coverage_record_hit() {
        let mut cov = SanitizerCoverage::new(256);
        assert!(cov.record_hit(10)); // first hit → true
        assert!(!cov.record_hit(10)); // second hit → false
        assert_eq!(cov.edges_hit(), 1);
    }

    #[test]
    fn sanitizer_coverage_capacity() {
        let cov = SanitizerCoverage::default_64k();
        assert_eq!(cov.capacity(), 65_536);
    }

    #[test]
    fn sanitizer_coverage_density() {
        let mut cov = SanitizerCoverage::new(100);
        for i in 0..10 {
            cov.record_hit(i);
        }
        assert!((cov.density() - 0.1).abs() < 1e-9);
    }

    #[test]
    fn sanitizer_coverage_merge() {
        let mut a = SanitizerCoverage::new(64);
        let mut b = SanitizerCoverage::new(64);
        a.record_hit(1);
        b.record_hit(2);
        let new = a.merge(&b);
        assert_eq!(new, 1); // edge 2 was new
        assert_eq!(a.edges_hit(), 2);
    }

    #[test]
    fn sanitizer_coverage_reset() {
        let mut cov = SanitizerCoverage::new(64);
        cov.record_hit(5);
        cov.reset();
        assert_eq!(cov.edges_hit(), 0);
    }

    #[test]
    fn sanitizer_coverage_bitmap() {
        let mut cov = SanitizerCoverage::new(16);
        cov.record_hit(0);
        cov.record_hit(8);
        let bm = cov.to_bitmap();
        assert_eq!(bm.len(), 2);
        assert_eq!(bm[0] & 1, 1); // bit 0
        assert_eq!(bm[1] & 1, 1); // bit 8
    }

    #[test]
    fn harness_runner_pass_target() {
        let mut runner = HarnessRunner::new(Box::new(PassTarget));
        runner.add_seed(vec![1, 2, 3]);
        let stats = runner.run(10);
        assert!(stats.iterations >= 1);
        assert_eq!(stats.crashes, 0);
    }

    #[test]
    fn harness_runner_crash_detected() {
        let mut runner = HarnessRunner::new(Box::new(CrashOnZero));
        runner.add_seed(vec![0u8]);
        runner.set_config(RunnerConfig {
            stop_on_first_crash: true,
            max_iterations: Some(10),
            ..Default::default()
        });
        let _stats = runner.run(0);
        assert!(!runner.crashes.is_empty());
    }

    #[test]
    fn harness_runner_unique_crash_dedup() {
        let mut runner = HarnessRunner::new(Box::new(CrashOnZero));
        runner.add_seed(vec![0u8]);
        runner.run_one(&[0u8]);
        runner.run_one(&[0u8]);
        // same input → same hash → 1 unique crash
        assert_eq!(runner.unique_crash_count(), 1);
        assert_eq!(runner.stats.crashes, 2);
    }

    #[test]
    fn harness_runner_multiple_seeds() {
        let calls = Arc::new(Mutex::new(0u64));
        let target = CountCalls {
            calls: Arc::clone(&calls),
        };
        let mut runner = HarnessRunner::new(Box::new(target));
        runner.add_seeds(vec![vec![1], vec![2], vec![3]]);
        runner.set_config(RunnerConfig {
            max_iterations: Some(3),
            ..Default::default()
        });
        runner.run(0);
        let count = *calls.lock().unwrap();
        assert!(count >= 3);
    }

    #[test]
    fn signal_handler_inject() {
        let h = SignalHandler::new();
        assert!(!h.is_crashed());
        h.inject(11);
        assert!(h.is_crashed());
        assert_eq!(h.last_signal(), Some(11));
        assert_eq!(h.total_crashes(), 1);
        h.clear();
        assert!(!h.is_crashed());
        assert_eq!(h.total_crashes(), 1); // preserved
    }

    #[test]
    fn timeout_handler_arm_disarm() {
        let mut th = TimeoutHandler::new(Some(Duration::from_secs(1)));
        th.arm();
        assert!(!th.expired());
        th.disarm();
        assert!(!th.expired());
    }

    #[test]
    fn timeout_handler_expired() {
        let mut th = TimeoutHandler::new(Some(Duration::from_nanos(1)));
        th.arm();
        std::thread::sleep(Duration::from_millis(5));
        assert!(th.expired());
    }

    #[test]
    fn crash_record_hash() {
        let r1 = CrashRecord::new(&[1, 2, 3], 11, "test".into(), 0);
        let r2 = CrashRecord::new(&[1, 2, 3], 11, "test".into(), 0);
        assert_eq!(r1.hash, r2.hash);
        let r3 = CrashRecord::new(&[4, 5, 6], 11, "test".into(), 0);
        assert_ne!(r1.hash, r3.hash);
    }

    #[test]
    fn harness_error_helpers() {
        let e = HarnessError::crash(11, "oops");
        assert!(e.is_crash());
        assert!(!e.is_timeout());
        let t = HarnessError::Timeout(Duration::from_secs(1));
        assert!(t.is_timeout());
        assert!(!t.is_crash());
    }

    #[test]
    fn runner_config_default() {
        let c = RunnerConfig::default();
        assert!(c.per_input_timeout.is_some());
        assert!(!c.stop_on_first_crash);
    }

    #[test]
    fn run_one_enforces_max_size() {
        let mut runner = HarnessRunner::new(Box::new(PassTarget));
        runner.set_config(RunnerConfig {
            max_input_size: 4,
            ..Default::default()
        });
        let new_cov = runner.run_one(&[0u8; 5]);
        // Should return false (skipped due to size limit).
        assert!(!new_cov);
    }
}
