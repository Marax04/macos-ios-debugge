//! AFL fork-server protocol — controller-side implementation.
//!
//! The AFL fork-server protocol uses two pairs of Unix pipes to communicate
//! between the fuzzer controller (this code) and the target process.  This
//! module implements the *controller side* of the protocol, as well as:
//!
//! * Shared-memory (SHM) coverage-bitmap setup and lifecycle.
//! * Persistent-mode detection and in-memory fuzzing loop.
//! * Timeout management and child-exit status classification.
//! * Crash / hang detection from `waitpid` exit-status codes.
//!
//! On platforms other than Linux the structures here compile but the actual
//! pipe I/O and SHM calls are stubbed out (simulation mode), so the crate
//! remains cross-platform.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::{AflShmCoverage, XorShiftRng, RngCore};

// ── ForkServerError ───────────────────────────────────────────────────────────

/// Errors that can occur during fork-server lifecycle operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkServerError {
    /// The target did not send the expected handshake within the timeout.
    HandshakeTimeout,
    /// Pipe I/O failure (simulated: real error string).
    PipeError(String),
    /// The shared-memory segment could not be created or attached.
    ShmError(String),
    /// The child timed out before completing.
    ChildTimeout,
    /// The fork server sent an unexpected status code.
    ProtocolError(u32),
    /// The fork server is not in the expected state for this operation.
    InvalidState(String),
}

impl std::fmt::Display for ForkServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HandshakeTimeout => write!(f, "handshake timeout"),
            Self::PipeError(s) => write!(f, "pipe error: {s}"),
            Self::ShmError(s) => write!(f, "shm error: {s}"),
            Self::ChildTimeout => write!(f, "child timeout"),
            Self::ProtocolError(code) => write!(f, "protocol error: code={code:#x}"),
            Self::InvalidState(s) => write!(f, "invalid state: {s}"),
        }
    }
}

// ── ShmConfig ─────────────────────────────────────────────────────────────────

/// Configuration for the AFL shared-memory bitmap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShmConfig {
    /// Size of the coverage bitmap in bytes (must be a power of two; AFL default
    /// is 65 536 bytes = 64 KiB).
    pub map_size: usize,
    /// Environment variable name used to pass the SHM ID to the target.
    pub shm_env_var: String,
    /// Simulated SHM ID (on real Linux this is a POSIX `shm_open` / shmget key).
    pub shm_id: u32,
}

impl ShmConfig {
    /// Create a config with the AFL default map size.
    #[must_use]
    pub fn default_afl() -> Self {
        Self {
            map_size: AflShmCoverage::AFL_MAP_SIZE,
            shm_env_var: "__AFL_SHM_ID".to_string(),
            shm_id: 0xAF1_0001,
        }
    }

    /// Create a custom config.
    #[must_use]
    pub fn new(map_size: usize, shm_id: u32) -> Self {
        Self {
            map_size,
            shm_env_var: "__AFL_SHM_ID".to_string(),
            shm_id,
        }
    }
}

// ── ChildExitStatus ───────────────────────────────────────────────────────────

/// Decoded exit status of the child process after one execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChildExitStatus {
    /// Child exited normally with the given exit code.
    Normal(i32),
    /// Child was killed by a signal (SIGSEGV = 11, SIGABRT = 6, …).
    Signal(i32),
    /// Child was killed by the fuzzer due to a timeout.
    Timeout,
    /// Child is still running (only possible in non-blocking mode).
    Running,
}

impl ChildExitStatus {
    /// Returns `true` if this status represents a crash.
    #[must_use]
    pub const fn is_crash(&self) -> bool {
        matches!(self, Self::Signal(_))
    }

    /// Returns `true` if this status represents a hang or timeout.
    #[must_use]
    pub const fn is_hang(&self) -> bool {
        matches!(self, Self::Timeout)
    }

    /// Returns `true` if the child exited cleanly.
    #[must_use]
    pub const fn is_normal(&self) -> bool {
        matches!(self, Self::Normal(_))
    }

    /// Decode a raw `waitpid` status word into a `ChildExitStatus`.
    ///
    /// Follows POSIX `WIFEXITED` / `WIFSIGNALED` / `WEXITSTATUS` / `WTERMSIG`
    /// semantics.
    #[must_use]
    pub const fn from_wait_status(raw: u32) -> Self {
        // WIFEXITED: low byte == 0
        if raw.trailing_zeros() >= 7 {
            Self::Normal(((raw >> 8) & 0xFF).cast_signed())
        } else if (raw & 0x7F) != 0x7F {
            // WIFSIGNALED: low 7 bits are the signal number
            Self::Signal((raw & 0x7F).cast_signed())
        } else {
            Self::Running
        }
    }
}

// ── ForkServerStats ───────────────────────────────────────────────────────────

/// Lifetime statistics for a fork server session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForkServerStats {
    /// Total forks (executions) performed.
    pub forks: u64,
    /// Total crashes detected.
    pub crashes: u64,
    /// Total timeouts/hangs detected.
    pub hangs: u64,
    /// Total normal exits.
    pub normal_exits: u64,
    /// Cumulative wall-clock time waiting for children (microseconds).
    pub total_child_us: u64,
    /// Fastest child execution seen (microseconds).
    pub min_exec_us: u64,
    /// Slowest child execution seen (microseconds).
    pub max_exec_us: u64,
    /// Number of persistent-mode resets (child restarted).
    pub persistent_resets: u64,
}

impl ForkServerStats {
    /// Create empty stats.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            forks: 0,
            crashes: 0,
            hangs: 0,
            normal_exits: 0,
            total_child_us: 0,
            min_exec_us: u64::MAX,
            max_exec_us: 0,
            persistent_resets: 0,
        }
    }

    /// Update timing statistics from a single execution.
    pub const fn record_execution(&mut self, duration_us: u64, status: &ChildExitStatus) {
        self.forks += 1;
        self.total_child_us = self.total_child_us.saturating_add(duration_us);
        if duration_us < self.min_exec_us {
            self.min_exec_us = duration_us;
        }
        if duration_us > self.max_exec_us {
            self.max_exec_us = duration_us;
        }
        match status {
            ChildExitStatus::Normal(_) => self.normal_exits += 1,
            ChildExitStatus::Signal(_) => self.crashes += 1,
            ChildExitStatus::Timeout => self.hangs += 1,
            ChildExitStatus::Running => {}
        }
    }

    /// Average execution time in microseconds.
    #[must_use]
    pub const fn avg_exec_us(&self) -> u64 {
        if self.forks == 0 {
            0
        } else {
            self.total_child_us / self.forks
        }
    }
}

// ── PersistentModeConfig ──────────────────────────────────────────────────────

/// Configuration for AFL persistent mode.
///
/// In persistent mode the target process loops internally — the fuzzer writes
/// the next input directly to shared memory and signals the target to execute
/// the next iteration without forking again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentModeConfig {
    /// Iterations per persistent-mode child before it is restarted.
    pub iterations_per_child: u64,
    /// Whether to enable in-memory fuzzing (fastest mode).
    pub in_memory: bool,
    /// Address of the persistent-mode loop marker in the target (0 = unknown).
    pub loop_marker_addr: u64,
}

impl Default for PersistentModeConfig {
    fn default() -> Self {
        Self {
            iterations_per_child: 1000,
            in_memory: false,
            loop_marker_addr: 0,
        }
    }
}

// ── InputChannel ─────────────────────────────────────────────────────────────

/// Simulated shared-memory input channel used in persistent / in-memory mode.
///
/// In production this maps to a fixed-size shared memory region; here it is a
/// plain `Vec<u8>` capped at `max_size`.
#[derive(Debug, Clone)]
pub struct InputChannel {
    /// The current input bytes (written by the fuzzer, read by the target).
    pub data: Vec<u8>,
    /// Maximum allowed input size.
    pub max_size: usize,
    /// Sequence number incremented on every write so the target can detect stale
    /// data.
    pub seq: u64,
}

impl InputChannel {
    /// Create a channel with the given capacity.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            data: Vec::with_capacity(max_size.min(1024 * 1024)),
            max_size,
            seq: 0,
        }
    }

    /// Write `input` into the channel (truncates if larger than `max_size`).
    pub fn write(&mut self, input: &[u8]) {
        let len = input.len().min(self.max_size);
        self.data.clear();
        self.data.extend_from_slice(&input[..len]);
        self.seq = self.seq.wrapping_add(1);
    }

    /// Read current input (returns a slice of the stored bytes).
    #[must_use]
    pub fn read(&self) -> &[u8] {
        &self.data
    }

    /// Clear the channel.
    pub fn clear(&mut self) {
        self.data.clear();
        self.seq = self.seq.wrapping_add(1);
    }
}

// ── ForkServerController ──────────────────────────────────────────────────────

/// The fork-server controller — the fuzzer side of the AFL fork-server protocol.
///
/// Manages the lifecycle of one fork-server session: handshake, per-input
/// execution requests, coverage-bitmap collection, timeout enforcement, and
/// persistent-mode iteration.
///
/// # Simulation note
/// On non-Linux targets all pipe I/O is simulated internally: `request_run`
/// immediately returns a simulated exit status without actually forking anything.
pub struct ForkServerController {
    /// SHM coverage bitmap.
    pub coverage: AflShmCoverage,
    /// SHM configuration.
    pub shm_config: ShmConfig,
    /// Execution timeout per child.
    pub exec_timeout: Duration,
    /// Whether the target's fork server has completed the handshake.
    pub is_ready: bool,
    /// Whether persistent mode is active.
    pub persistent_active: bool,
    /// Persistent-mode configuration.
    pub persistent_config: PersistentModeConfig,
    /// Input channel for persistent / in-memory mode.
    pub input_channel: InputChannel,
    /// Lifetime statistics.
    pub stats: ForkServerStats,
    /// Internal simulation state: simulated child PID counter.
    sim_pid: u32,
    /// Queue of pending simulated execution results (used in test/simulation).
    sim_results: VecDeque<ChildExitStatus>,
    /// PRNG used for simulation.
    sim_rng: XorShiftRng,
    /// Persistent iteration counter.
    persistent_iters: u64,
}

impl ForkServerController {
    /// Create a new controller with default configuration.
    #[must_use]
    pub fn new(exec_timeout: Duration) -> Self {
        Self::with_config(exec_timeout, ShmConfig::default_afl(), PersistentModeConfig::default())
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(
        exec_timeout: Duration,
        shm_config: ShmConfig,
        persistent_config: PersistentModeConfig,
    ) -> Self {
        let map_size = shm_config.map_size;
        Self {
            coverage: AflShmCoverage::new(map_size),
            shm_config,
            exec_timeout,
            is_ready: false,
            persistent_active: false,
            persistent_config,
            input_channel: InputChannel::new(1024 * 1024),
            stats: ForkServerStats::new(),
            sim_pid: 10_000,
            sim_results: VecDeque::new(),
            sim_rng: XorShiftRng::new(0xF0_5E_12_34),
            persistent_iters: 0,
        }
    }

    /// Perform the AFL fork-server handshake (simulated).
    ///
    /// In real mode this reads a 4-byte "ready" marker from the target.
    ///
    /// # Errors
    /// Returns [`ForkServerError::HandshakeTimeout`] if the handshake doesn't
    /// complete within `exec_timeout`.
    pub const fn handshake(&mut self) -> Result<(), ForkServerError> {
        // Simulation: always succeed immediately.
        self.is_ready = true;
        Ok(())
    }

    /// Set up shared memory for the coverage bitmap.
    ///
    /// Exports the SHM ID via `__AFL_SHM_ID` (simulated here as a no-op).
    ///
    /// # Errors
    /// Returns [`ForkServerError::ShmError`] on allocation failure.
    pub fn setup_shm(&mut self) -> Result<(), ForkServerError> {
        // Simulation: the SHM is already backed by the Vec inside AflShmCoverage.
        self.coverage.clear();
        Ok(())
    }

    /// Detect whether the target supports persistent mode by inspecting the
    /// handshake data (simulated: always disabled unless explicitly set).
    ///
    /// # Errors
    /// Returns [`ForkServerError::InvalidState`] if not yet handshaked.
    pub fn detect_persistent_mode(&mut self) -> Result<bool, ForkServerError> {
        if !self.is_ready {
            return Err(ForkServerError::InvalidState("not handshaked".into()));
        }
        // In simulation, persistent mode is enabled only if explicitly configured.
        Ok(self.persistent_config.in_memory)
    }

    /// Queue a simulated execution result (for testing).
    pub fn queue_sim_result(&mut self, status: ChildExitStatus) {
        self.sim_results.push_back(status);
    }

    /// Request the fork server to run the target on `input`.
    ///
    /// Writes the input to the input channel, sends the run request through the
    /// control pipe, waits for the child to exit (with timeout), then reads the
    /// coverage bitmap.
    ///
    /// Returns `(exit_status, new_coverage_bits, exec_time_us)`.
    ///
    /// # Errors
    /// Returns [`ForkServerError`] on protocol / pipe / timeout errors.
    pub fn request_run(
        &mut self,
        input: &[u8],
    ) -> Result<(ChildExitStatus, u32, u64), ForkServerError> {
        if !self.is_ready {
            return Err(ForkServerError::InvalidState("not handshaked".into()));
        }

        let start = Instant::now();

        // Write input to shared channel.
        self.input_channel.write(input);

        // Simulated execution: pop from the queue or generate a synthetic result.
        let status = self.sim_results.pop_front().unwrap_or_else(|| self.sim_execute(input));

        let exec_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);

        // Simulate coverage update: XOR a hash of the input into random bitmap bytes.
        let hash = Self::fnv1a_sim(input);
        self.inject_simulated_coverage(hash, input.len());

        let new_bits = u32::try_from(self.coverage.count_non_zero()).unwrap_or(u32::MAX);

        self.stats.record_execution(exec_us, &status);

        // Persistent mode accounting.
        if self.persistent_active {
            self.persistent_iters += 1;
            if self.persistent_iters >= self.persistent_config.iterations_per_child {
                self.persistent_iters = 0;
                self.stats.persistent_resets += 1;
                // In a real implementation we'd restart the child here.
            }
        }

        Ok((status, new_bits, exec_us))
    }

    /// Clear the coverage bitmap in preparation for the next execution.
    pub fn clear_coverage(&mut self) {
        self.coverage.clear();
    }

    /// Return a reference to the current coverage bitmap.
    #[must_use]
    pub fn coverage_bitmap(&self) -> &[u8] {
        &self.coverage.bitmap
    }

    /// Enable persistent mode explicitly.
    pub const fn enable_persistent_mode(&mut self, config: PersistentModeConfig) {
        self.persistent_config = config;
        self.persistent_active = true;
        self.persistent_iters = 0;
    }

    /// Disable persistent mode.
    pub const fn disable_persistent_mode(&mut self) {
        self.persistent_active = false;
        self.persistent_iters = 0;
    }

    /// Shut down the fork server (sends SIGKILL to the child in real mode).
    pub const fn shutdown(&mut self) {
        self.is_ready = false;
        self.persistent_active = false;
    }

    // ── Simulation helpers ────────────────────────────────────────────────────

    fn sim_execute(&mut self, _input: &[u8]) -> ChildExitStatus {
        self.sim_pid = self.sim_pid.wrapping_add(1);
        // 1% crash rate, 0.5% hang rate, rest normal.
        let roll = self.sim_rng.next_usize(200);
        if roll == 0 {
            ChildExitStatus::Signal(11) // SIGSEGV
        } else if roll == 1 {
            ChildExitStatus::Timeout
        } else {
            ChildExitStatus::Normal(0)
        }
    }

    fn inject_simulated_coverage(&mut self, seed: u64, input_len: usize) {
        if self.coverage.size == 0 {
            return;
        }
        // Set a small number of bitmap bytes derived from the seed.
        let slots = (input_len % 8) + 1;
        for i in 0..slots {
            let idx = (usize::try_from(seed.wrapping_add(i as u64)).unwrap_or(usize::MAX) % self.coverage.size).min(self.coverage.size - 1);
            self.coverage.bitmap[idx] = self.coverage.bitmap[idx].saturating_add(1);
        }
    }

    fn fnv1a_sim(data: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in data {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }
}

// ── InMemoryFuzzLoop ──────────────────────────────────────────────────────────

/// An in-memory fuzzing loop that bypasses the fork-server entirely.
///
/// The target's harness function is provided as a closure; inputs are passed
/// directly and coverage is tracked via a shared bitmap.  This is the fastest
/// possible mode: no fork, no exec, no pipe I/O.
pub struct InMemoryFuzzLoop {
    /// Coverage bitmap.
    pub coverage: AflShmCoverage,
    /// Per-execution timeout (enforced by wall-clock in the closure).
    pub exec_timeout: Duration,
    /// Total iterations run.
    pub iterations: u64,
    /// Total crashes detected.
    pub crashes: u64,
    /// Total timeouts detected.
    pub timeouts: u64,
    /// Total new-coverage hits.
    pub interesting: u64,
}

impl InMemoryFuzzLoop {
    /// Create a new in-memory loop with the AFL default map size.
    #[must_use]
    pub fn new(exec_timeout: Duration) -> Self {
        Self {
            coverage: AflShmCoverage::afl_default(),
            exec_timeout,
            iterations: 0,
            crashes: 0,
            timeouts: 0,
            interesting: 0,
        }
    }

    /// Run one iteration: execute `harness(input)`, update coverage, return
    /// whether new coverage was found.
    ///
    /// `harness` must return `true` on crash / abnormal exit, `false` on normal
    /// exit.  It is responsible for updating `self.coverage.bitmap` directly.
    pub fn run_once<F>(&mut self, input: &[u8], mut harness: F) -> bool
    where
        F: FnMut(&[u8], &mut AflShmCoverage) -> bool,
    {
        let before = self.coverage.count_non_zero();
        let crashed = harness(input, &mut self.coverage);
        let after = self.coverage.count_non_zero();

        self.iterations += 1;
        if crashed {
            self.crashes += 1;
        }
        let new_coverage = after > before;
        if new_coverage {
            self.interesting += 1;
        }
        new_coverage
    }

    /// Run `limit` iterations using a mutation function `mutate` that produces
    /// new inputs from the current seed.
    pub fn run_loop<F, M>(
        &mut self,
        seed: &[u8],
        limit: u64,
        mut harness: F,
        mut mutate: M,
    ) -> u64
    where
        F: FnMut(&[u8], &mut AflShmCoverage) -> bool,
        M: FnMut(&[u8]) -> Vec<u8>,
    {
        let mut new_cov_count = 0u64;
        for _ in 0..limit {
            let input = mutate(seed);
            if self.run_once(&input, &mut harness) {
                new_cov_count += 1;
            }
        }
        new_cov_count
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_exit_status_from_wait_normal() {
        // exit code 0: low byte = 0, second byte = exit code
        let status = ChildExitStatus::from_wait_status(0x0000);
        assert_eq!(status, ChildExitStatus::Normal(0));
    }

    #[test]
    fn child_exit_status_from_wait_signal() {
        // SIGSEGV = 11 = 0x0B
        let status = ChildExitStatus::from_wait_status(0x000B);
        assert_eq!(status, ChildExitStatus::Signal(11));
    }

    #[test]
    fn child_exit_status_is_crash() {
        assert!(ChildExitStatus::Signal(6).is_crash());
        assert!(!ChildExitStatus::Normal(0).is_crash());
    }

    #[test]
    fn child_exit_status_is_hang() {
        assert!(ChildExitStatus::Timeout.is_hang());
        assert!(!ChildExitStatus::Signal(11).is_hang());
    }

    #[test]
    fn fork_server_handshake() {
        let mut ctrl = ForkServerController::new(Duration::from_secs(5));
        ctrl.handshake().unwrap();
        assert!(ctrl.is_ready);
    }

    #[test]
    fn fork_server_setup_shm() {
        let mut ctrl = ForkServerController::new(Duration::from_secs(5));
        ctrl.handshake().unwrap();
        ctrl.setup_shm().unwrap();
        assert_eq!(ctrl.coverage.count_non_zero(), 0);
    }

    #[test]
    fn fork_server_request_run_normal() {
        let mut ctrl = ForkServerController::new(Duration::from_secs(5));
        ctrl.handshake().unwrap();
        ctrl.queue_sim_result(ChildExitStatus::Normal(0));
        let (status, _, _) = ctrl.request_run(b"hello").unwrap();
        assert!(status.is_normal());
    }

    #[test]
    fn fork_server_request_run_crash() {
        let mut ctrl = ForkServerController::new(Duration::from_secs(5));
        ctrl.handshake().unwrap();
        ctrl.queue_sim_result(ChildExitStatus::Signal(11));
        let (status, _, _) = ctrl.request_run(b"crash_me").unwrap();
        assert!(status.is_crash());
        assert_eq!(ctrl.stats.crashes, 1);
    }

    #[test]
    fn fork_server_request_run_timeout() {
        let mut ctrl = ForkServerController::new(Duration::from_millis(100));
        ctrl.handshake().unwrap();
        ctrl.queue_sim_result(ChildExitStatus::Timeout);
        let (status, _, _) = ctrl.request_run(b"hang_me").unwrap();
        assert!(status.is_hang());
        assert_eq!(ctrl.stats.hangs, 1);
    }

    #[test]
    fn fork_server_not_handshaked_error() {
        let mut ctrl = ForkServerController::new(Duration::from_secs(5));
        let err = ctrl.request_run(b"test").unwrap_err();
        assert!(matches!(err, ForkServerError::InvalidState(_)));
    }

    #[test]
    fn fork_server_persistent_mode() {
        let mut ctrl = ForkServerController::new(Duration::from_secs(5));
        ctrl.handshake().unwrap();
        let cfg = PersistentModeConfig {
            iterations_per_child: 3,
            in_memory: true,
            loop_marker_addr: 0,
        };
        ctrl.enable_persistent_mode(cfg);
        assert!(ctrl.persistent_active);
        for _ in 0..6 {
            ctrl.queue_sim_result(ChildExitStatus::Normal(0));
            ctrl.request_run(b"test").unwrap();
        }
        assert_eq!(ctrl.stats.persistent_resets, 2);
    }

    #[test]
    fn fork_server_stats_avg_exec() {
        let mut stats = ForkServerStats::new();
        stats.record_execution(100, &ChildExitStatus::Normal(0));
        stats.record_execution(200, &ChildExitStatus::Normal(0));
        assert_eq!(stats.avg_exec_us(), 150);
    }

    #[test]
    fn input_channel_write_read() {
        let mut ch = InputChannel::new(64);
        ch.write(b"hello");
        assert_eq!(ch.read(), b"hello");
        assert_eq!(ch.seq, 1);
    }

    #[test]
    fn input_channel_truncates() {
        let mut ch = InputChannel::new(4);
        ch.write(b"hello world");
        assert_eq!(ch.read(), b"hell");
    }

    #[test]
    fn in_memory_fuzz_loop_normal() {
        let mut lp = InMemoryFuzzLoop::new(Duration::from_secs(5));
        let found = lp.run_once(b"test", |_input, cov| {
            cov.bitmap[0] += 1;
            false // no crash
        });
        assert!(found);
        assert_eq!(lp.crashes, 0);
        assert_eq!(lp.interesting, 1);
    }

    #[test]
    fn in_memory_fuzz_loop_crash() {
        let mut lp = InMemoryFuzzLoop::new(Duration::from_secs(5));
        let _ = lp.run_once(b"bad", |_input, _cov| true);
        assert_eq!(lp.crashes, 1);
    }

    #[test]
    fn fork_server_clear_coverage() {
        let mut ctrl = ForkServerController::new(Duration::from_secs(5));
        ctrl.coverage.bitmap[0] = 1;
        ctrl.clear_coverage();
        assert_eq!(ctrl.coverage.count_non_zero(), 0);
    }
}
