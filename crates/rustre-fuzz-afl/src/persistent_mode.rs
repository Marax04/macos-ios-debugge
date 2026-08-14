//! AFL++ persistent mode.
//!
//! Persistent mode allows the fuzzer to call the target function many times
//! within a single process invocation, avoiding the overhead of fork+exec
//! for each test case.
//!
//! This module models the persistent-mode state machine, the fork-server
//! control protocol, and deferred fork-server support.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// ─── PersistentConfig ─────────────────────────────────────────────────────────

/// Configuration for AFL++ persistent mode.
#[derive(Debug, Clone)]
pub struct PersistentConfig {
    /// Maximum number of iterations per persistent session.
    pub max_iterations: u64,
    /// Whether the deferred fork-server is used.
    pub deferred_forkserver: bool,
    /// Signal number used to signal "test done" to the fuzzer (default 0).
    pub done_signal: i32,
    /// Address of the persistent loop start (if compile-time is unavailable).
    pub loop_addr: Option<u64>,
    /// Whether coverage is reset between iterations.
    pub reset_coverage_per_iter: bool,
    /// Timeout in milliseconds for a single iteration.
    pub timeout_ms: u64,
}

impl PersistentConfig {
    /// Create a default config with `max_iterations` iterations.
    #[must_use]
    pub const fn new(max_iterations: u64) -> Self {
        Self {
            max_iterations,
            deferred_forkserver: false,
            done_signal: 0,
            loop_addr: None,
            reset_coverage_per_iter: true,
            timeout_ms: 1000,
        }
    }

    /// Enable the deferred fork-server mode.
    #[must_use] 
    pub const fn with_deferred_forkserver(mut self) -> Self {
        self.deferred_forkserver = true;
        self
    }

    /// Set a timeout in milliseconds.
    #[must_use] 
    pub const fn with_timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }
}

// ─── IterationResult ──────────────────────────────────────────────────────────

/// Result of a single persistent-mode iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IterationResult {
    /// Test completed normally.
    Ok,
    /// Test triggered a crash.
    Crash,
    /// Test triggered a timeout.
    Timeout,
    /// Persistent loop exhausted (reached `max_iterations`).
    Exhausted,
}

impl fmt::Display for IterationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::Crash => write!(f, "crash"),
            Self::Timeout => write!(f, "timeout"),
            Self::Exhausted => write!(f, "exhausted"),
        }
    }
}

// ─── PersistentLoop ───────────────────────────────────────────────────────────

/// State machine modelling `__AFL_LOOP(count)`.
///
/// In the real AFL++ instrumented binary, `__AFL_LOOP` is a macro that
/// calls a function which handles forking and iteration counting.
/// Here we model the same semantics in pure Rust.
#[derive(Debug)]
pub struct PersistentLoop {
    /// Max iterations requested.
    pub max_iterations: u64,
    /// Current iteration (0-based).
    current: u64,
    /// Whether the loop has been started.
    running: bool,
    /// Shared counter (Arc allows cross-thread visibility).
    counter: Arc<AtomicU64>,
}

impl PersistentLoop {
    /// Create a loop that runs for at most `count` iterations.
    #[must_use]
    pub fn new(count: u64) -> Self {
        Self {
            max_iterations: count,
            current: 0,
            running: false,
            counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// `__AFL_LOOP(count)` equivalent.
    ///
    /// Returns `true` if the loop should continue, `false` when done.
    pub fn advance(&mut self) -> bool {
        if !self.running {
            self.running = true;
        }
        if self.current >= self.max_iterations {
            self.running = false;
            return false;
        }
        self.current += 1;
        self.counter.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Current iteration count (1-based when inside the loop).
    #[must_use]
    pub const fn iteration(&self) -> u64 {
        self.current
    }

    /// Whether the loop is still running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.running && self.current < self.max_iterations
    }

    /// Reset the loop to the beginning.
    pub const fn reset(&mut self) {
        self.current = 0;
        self.running = false;
    }

    /// Get a shared reference to the atomic counter.
    #[must_use]
    pub fn counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.counter)
    }

    /// Remaining iterations.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.max_iterations.saturating_sub(self.current)
    }
}

// ─── ForkServerProtocol ───────────────────────────────────────────────────────

/// Status codes sent/received over the fork-server pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ForkServerStatus {
    /// Fork-server is alive and ready.
    Ready = 0x00C0_FFEE,
    /// Child fork completed, status follows.
    ChildDone = 0,
    /// Child crashed.
    ChildCrash = 1,
    /// Waiting for fork.
    WaitingFork = 2,
    /// Forked child PID.
    ForkPid = 3,
}

impl ForkServerStatus {
    /// Parse from raw u32.
    #[must_use] 
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0x00C0_FFEE => Self::Ready,
            1 => Self::ChildCrash,
            2 => Self::WaitingFork,
            3 => Self::ForkPid,
            _ => Self::ChildDone,
        }
    }
}

impl fmt::Display for ForkServerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready => write!(f, "Ready(0x00C0_FFEE)"),
            Self::ChildDone => write!(f, "ChildDone"),
            Self::ChildCrash => write!(f, "ChildCrash"),
            Self::WaitingFork => write!(f, "WaitingFork"),
            Self::ForkPid => write!(f, "ForkPid"),
        }
    }
}

/// Simulated fork-server protocol state machine.
///
/// In production this communicates over two file descriptors (198 and 199).
/// Here we model the pipe as two in-memory queues.
#[derive(Debug, Default)]
pub struct ForkServerProtocol {
    /// Messages from fork-server → fuzzer (status pipe).
    pub status_pipe: std::collections::VecDeque<u32>,
    /// Messages from fuzzer → fork-server (control pipe).
    pub control_pipe: std::collections::VecDeque<u32>,
    /// Whether the handshake completed.
    pub handshaked: bool,
    /// Simulated child PID.
    pub child_pid: u32,
    /// Round count.
    pub rounds: u64,
}

impl ForkServerProtocol {
    /// Create a new protocol instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            child_pid: 10000,
            ..Default::default()
        }
    }

    /// Simulate the fork-server startup: push Ready message.
    pub fn start(&mut self) {
        self.status_pipe.push_back(ForkServerStatus::Ready as u32);
    }

    /// Simulate the fuzzer reading the Ready message and `ACKing`.
    pub fn handshake(&mut self) -> bool {
        if let Some(msg) = self.status_pipe.pop_front()
            && msg == ForkServerStatus::Ready as u32 {
                // Fuzzer sends go signal
                self.control_pipe.push_back(1);
                self.handshaked = true;
                return true;
            }
        false
    }

    /// Simulate one round: fuzzer sends fork command, server responds with PID
    /// then child status.
    pub fn run_round(&mut self, crash: bool) {
        // Fuzzer sends fork command
        self.control_pipe.push_back(1);
        // Server sends child PID
        let pid = self.child_pid;
        self.child_pid += 1;
        self.status_pipe.push_back(pid);
        // Server sends child exit status
        let status = u32::from(crash);
        self.status_pipe.push_back(status);
        self.rounds += 1;
    }

    /// Read next status value.
    pub fn read_status(&mut self) -> Option<u32> {
        self.status_pipe.pop_front()
    }

    /// Write a control value.
    pub fn write_control(&mut self, v: u32) {
        self.control_pipe.push_back(v);
    }
}

// ─── DeferredForkServer ───────────────────────────────────────────────────────

/// Models `AFL_DEFER_FORKSRV` / `__AFL_INIT()` deferred fork-server.
///
/// In deferred mode, the fork-server handshake is deferred until
/// `__AFL_INIT()` is called inside the target, allowing expensive
/// initialisation (loading DSOs, etc.) to happen once before any fork.
#[derive(Debug, Default)]
pub struct DeferredForkServer {
    /// Whether `__AFL_INIT()` has been called.
    pub initialized: bool,
    /// Underlying fork-server protocol (active after init).
    pub protocol: ForkServerProtocol,
    /// Number of iterations since init.
    pub iter_count: u64,
}

impl DeferredForkServer {
    /// Create in an uninitialised state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `__AFL_INIT()` — perform the deferred handshake.
    pub fn init(&mut self) {
        self.protocol.start();
        self.initialized = true;
    }

    /// Run one iteration (must be initialised first).
    pub fn run(&mut self, input: &[u8], crash: bool) -> IterationResult {
        if !self.initialized {
            return IterationResult::Crash; // misconfigured
        }
        self.protocol.run_round(crash);
        self.iter_count += 1;
        let _ = input;
        if crash {
            IterationResult::Crash
        } else {
            IterationResult::Ok
        }
    }

    /// Total iterations run.
    #[must_use]
    pub const fn iter_count(&self) -> u64 {
        self.iter_count
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PersistentConfig ──────────────────────────────────────────────────────

    #[test]
    fn config_defaults() {
        let cfg = PersistentConfig::new(1000);
        assert_eq!(cfg.max_iterations, 1000);
        assert!(!cfg.deferred_forkserver);
    }

    #[test]
    fn config_with_deferred() {
        let cfg = PersistentConfig::new(500).with_deferred_forkserver();
        assert!(cfg.deferred_forkserver);
    }

    #[test]
    fn config_with_timeout() {
        let cfg = PersistentConfig::new(100).with_timeout_ms(5000);
        assert_eq!(cfg.timeout_ms, 5000);
    }

    // ── IterationResult ───────────────────────────────────────────────────────

    #[test]
    fn iteration_result_display() {
        assert_eq!(IterationResult::Ok.to_string(), "ok");
        assert_eq!(IterationResult::Crash.to_string(), "crash");
        assert_eq!(IterationResult::Exhausted.to_string(), "exhausted");
    }

    // ── PersistentLoop ────────────────────────────────────────────────────────

    #[test]
    fn loop_runs_exactly_n_times() {
        let mut lp = PersistentLoop::new(3);
        let mut count = 0;
        while lp.advance() {
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn loop_iteration_counter() {
        let mut lp = PersistentLoop::new(5);
        lp.advance();
        lp.advance();
        assert_eq!(lp.iteration(), 2);
    }

    #[test]
    fn loop_remaining() {
        let mut lp = PersistentLoop::new(10);
        lp.advance();
        assert_eq!(lp.remaining(), 9);
    }

    #[test]
    fn loop_reset() {
        let mut lp = PersistentLoop::new(3);
        lp.advance();
        lp.advance();
        lp.reset();
        assert_eq!(lp.iteration(), 0);
        assert!(!lp.is_running());
    }

    #[test]
    fn loop_is_running_stops() {
        let mut lp = PersistentLoop::new(1);
        assert!(lp.advance()); // iteration 1
        assert!(!lp.advance()); // exhausted
        assert!(!lp.is_running());
    }

    #[test]
    fn loop_counter_shared() {
        let mut lp = PersistentLoop::new(5);
        let ctr = lp.counter();
        lp.advance();
        lp.advance();
        assert_eq!(ctr.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    // ── ForkServerStatus ──────────────────────────────────────────────────────

    #[test]
    fn fork_server_status_display() {
        assert!(ForkServerStatus::Ready.to_string().contains("0x00C0_FFEE"));
    }

    #[test]
    fn fork_server_status_from_u32() {
        assert_eq!(
            ForkServerStatus::from_u32(0x00C0_FFEE),
            ForkServerStatus::Ready
        );
        assert_eq!(ForkServerStatus::from_u32(0), ForkServerStatus::ChildDone);
    }

    // ── ForkServerProtocol ────────────────────────────────────────────────────

    #[test]
    fn protocol_handshake() {
        let mut p = ForkServerProtocol::new();
        p.start();
        assert!(p.handshake());
        assert!(p.handshaked);
    }

    #[test]
    fn protocol_run_round_ok() {
        let mut p = ForkServerProtocol::new();
        p.start();
        p.handshake();
        p.run_round(false);
        // Should have pid + 0 (ok status) in status pipe
        let pid = p.read_status().unwrap();
        assert!(pid >= 10000);
        let status = p.read_status().unwrap();
        assert_eq!(status, 0);
    }

    #[test]
    fn protocol_run_round_crash() {
        let mut p = ForkServerProtocol::new();
        p.start();
        p.handshake();
        p.run_round(true);
        let _pid = p.read_status().unwrap();
        let status = p.read_status().unwrap();
        assert_eq!(status, 1); // crash
    }

    #[test]
    fn protocol_round_count() {
        let mut p = ForkServerProtocol::new();
        p.start();
        p.handshake();
        p.run_round(false);
        p.run_round(false);
        assert_eq!(p.rounds, 2);
    }

    // ── DeferredForkServer ────────────────────────────────────────────────────

    #[test]
    fn deferred_init_and_run() {
        let mut d = DeferredForkServer::new();
        d.init();
        let r = d.run(b"test", false);
        assert_eq!(r, IterationResult::Ok);
        assert_eq!(d.iter_count(), 1);
    }

    #[test]
    fn deferred_run_before_init_returns_crash() {
        let mut d = DeferredForkServer::new();
        let r = d.run(b"data", false);
        assert_eq!(r, IterationResult::Crash);
    }

    #[test]
    fn deferred_run_crash_propagates() {
        let mut d = DeferredForkServer::new();
        d.init();
        let r = d.run(b"crash_input", true);
        assert_eq!(r, IterationResult::Crash);
    }
}
