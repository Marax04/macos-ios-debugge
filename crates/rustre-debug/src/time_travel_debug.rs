//! `time_travel_debug` — time-travel debugging (TTD) interface.
//!
//! Provides:
//! - `TtdSession` — wraps a real TTD trace (e.g. WinDbg TTD, rr, QEMU replay) or a
//!   snapshot-based simulation.
//! - Direction-aware stepping: `step_backward`, `reverse_continue`,
//!   `reverse_step_over`, `run_to_previous_call`.
//! - Snapshot-based simulation: if no TTD trace is available the engine takes
//!   periodic process snapshots and replays forward to reconstruct "past" states.
//! - Integration hooks for the `rustre-ttd` crate.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the TTD subsystem.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TtdError {
    #[error("no TTD trace loaded")]
    NoTrace,
    #[error("already at beginning of trace")]
    AtBeginning,
    #[error("already at end of trace")]
    AtEnd,
    #[error("position {0} is out of range [0, {1}]")]
    OutOfRange(u64, u64),
    #[error("no snapshot available before position {0}")]
    NoSnapshot(u64),
    #[error("replay failed at position {0}: {1}")]
    ReplayFailed(u64, String),
    #[error("trace backend error: {0}")]
    Backend(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// Prefix of [`TtdState::stop_reason`] on every state produced WITHOUT a
/// [`TtdBackend`], where `pc`/`sp`/`regs` are placeholders rather than
/// measurements. Callers that surface register state must test for it.
pub const SIMULATED_STOP_REASON_PREFIX: &str = "simulated_";

// ─────────────────────────────────────────────────────────────────────────────
// TracePosition — a monotonic cursor into the TTD trace
// ─────────────────────────────────────────────────────────────────────────────

/// A position within a TTD trace, combining a sequence number (coarse) and an
/// instruction offset (fine) within that sequence step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TracePosition {
    /// Coarse sequence number (incremented at breakpoints / events).
    pub sequence: u64,
    /// Fine instruction offset within the current sequence step.
    pub offset: u64,
}

impl TracePosition {
    /// The very beginning of the trace.
    pub const START: Self = Self { sequence: 0, offset: 0 };

    /// Create a new position.
    #[must_use]
    pub const fn new(sequence: u64, offset: u64) -> Self {
        Self { sequence, offset }
    }

    /// Advance by one instruction (within the same sequence step).
    #[must_use]
    pub const fn next_instruction(self) -> Self {
        Self { sequence: self.sequence, offset: self.offset + 1 }
    }

    /// Advance to the next sequence step.
    #[must_use]
    pub const fn next_sequence(self) -> Self {
        Self { sequence: self.sequence + 1, offset: 0 }
    }

    /// Step backward by one instruction (saturating at START).
    #[must_use]
    pub const fn prev_instruction(self) -> Option<Self> {
        if self.offset > 0 {
            Some(Self { sequence: self.sequence, offset: self.offset - 1 })
        } else if self.sequence > 0 {
            // Cannot easily go to end of previous sequence without trace metadata;
            // return the start of the previous sequence.
            Some(Self { sequence: self.sequence - 1, offset: 0 })
        } else {
            None
        }
    }
}

impl fmt::Display for TracePosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.sequence, self.offset)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProcessSnapshot — a complete process state checkpoint
// ─────────────────────────────────────────────────────────────────────────────

/// A saved snapshot of a process's state, used for snapshot-based TTD simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    /// The trace position at which this snapshot was taken.
    pub position: TracePosition,
    /// Register values for all threads at this position.
    ///
    /// `thread_regs[tid]` → map of register name → value.
    pub thread_regs: BTreeMap<u32, BTreeMap<String, u64>>,
    /// Memory pages saved as (`base_address` → bytes).
    ///
    /// In a real implementation this would be a delta/copy-on-write structure;
    /// here we store full pages (4 KiB each) for simplicity.
    pub memory_pages: BTreeMap<u64, Vec<u8>>,
    /// Sequence of events since the last snapshot (for replay validation).
    pub event_log: Vec<String>,
    /// Wall-clock time when the snapshot was taken.
    #[serde(skip)]
    pub taken_at: Option<Instant>,
}

impl ProcessSnapshot {
    /// Create an empty snapshot at `position`.
    #[must_use]
    pub fn new(position: TracePosition) -> Self {
        Self {
            position,
            thread_regs: BTreeMap::new(),
            memory_pages: BTreeMap::new(),
            event_log: Vec::new(),
            taken_at: Some(Instant::now()),
        }
    }

    /// Store a 4-KiB page worth of bytes at `base_addr`.
    pub fn save_page(&mut self, base_addr: u64, data: Vec<u8>) {
        self.memory_pages.insert(base_addr & !0xfff, data);
    }

    /// Look up a byte within a saved page.
    #[must_use]
    pub fn read_byte(&self, addr: u64) -> Option<u8> {
        let base = addr & !0xfff;
        let offset = (addr & 0xfff) as usize;
        self.memory_pages.get(&base)?.get(offset).copied()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TtdBackend — trait for actual TTD implementations
// ─────────────────────────────────────────────────────────────────────────────

/// Trait that a real TTD backend (rr, `WinDbg` TTD, QEMU replay, …) must implement.
pub trait TtdBackend: Send + Sync + fmt::Debug {
    /// Human-readable name of the backend (e.g. `"rr"`, `"WinDbg-TTD"`).
    fn name(&self) -> &str;

    /// Total extent of the trace (start and end position).
    fn trace_extent(&self) -> (TracePosition, TracePosition);

    /// Seek to `position` and return the resulting execution state.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the seek fails or the position is out of range.
    fn seek(&mut self, position: TracePosition) -> Result<TtdState, TtdError>;

    /// Step forward one instruction from `current`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the step fails or the end of the trace is reached.
    fn step_forward(&mut self, current: TracePosition) -> Result<TtdState, TtdError>;

    /// Step backward one instruction from `current`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the step fails or the beginning of the trace is reached.
    fn step_backward(&mut self, current: TracePosition) -> Result<TtdState, TtdError>;

    /// Continue backward until a stop condition is reached (reverse-continue).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the operation fails.
    fn reverse_continue(
        &mut self,
        from: TracePosition,
        stop_at: &[u64], // breakpoint PCs
    ) -> Result<TtdState, TtdError>;

    /// Step over the current call in reverse (run back to caller site).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the operation fails.
    fn reverse_step_over(&mut self, current: TracePosition) -> Result<TtdState, TtdError>;

    /// Find the most recent call site before `current` and go there.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the operation fails or the beginning is reached.
    fn run_to_previous_call(&mut self, current: TracePosition) -> Result<TtdState, TtdError>;
}

/// A snapshot of execution state at a particular trace position, returned by
/// TTD backend operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdState {
    /// The trace position.
    pub position: TracePosition,
    /// Program counter value.
    pub pc: u64,
    /// Stack pointer value.
    pub sp: u64,
    /// All register values.
    pub regs: BTreeMap<String, u64>,
    /// Reason execution stopped (e.g. "breakpoint", `end_of_trace`, `user_stop`).
    pub stop_reason: String,
}

impl TtdState {
    #[must_use]
    pub fn new(position: TracePosition, pc: u64, sp: u64) -> Self {
        Self {
            position,
            pc,
            sp,
            regs: BTreeMap::new(),
            stop_reason: String::from("unknown"),
        }
    }
}

impl fmt::Display for TtdState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TtdState @ {} pc={:#x} sp={:#x} ({})", self.position, self.pc, self.sp, self.stop_reason)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SnapshotSimulator — snapshot-based TTD when no real backend is available
// ─────────────────────────────────────────────────────────────────────────────

/// Simulates TTD by taking periodic snapshots of the process and replaying
/// forward.
///
/// Strategy:
/// 1. Every `snapshot_interval` instructions, capture the full process state.
/// 2. To "go backward" by N instructions: locate the nearest snapshot before
///    the target position and replay forward from it.
/// 3. Replay is exact for deterministic code; non-deterministic effects are
///    noted in the event log.
#[derive(Debug)]
pub struct SnapshotSimulator {
    /// Saved snapshots, ordered by position.
    snapshots: BTreeMap<TracePosition, ProcessSnapshot>,
    /// How many instructions between automatic snapshots.
    pub snapshot_interval: u64,
    /// Replay event log (most recent first).
    pub replay_log: VecDeque<String>,
    /// Maximum number of snapshots to retain (oldest are pruned).
    pub max_snapshots: usize,
    /// Current simulated position.
    pub current_position: TracePosition,
    /// Instruction counter since the last snapshot.
    insns_since_snapshot: u64,
}

impl SnapshotSimulator {
    /// Create a simulator with the given snapshot interval.
    #[must_use]
    pub const fn new(snapshot_interval: u64) -> Self {
        Self {
            snapshots: BTreeMap::new(),
            snapshot_interval,
            replay_log: VecDeque::new(),
            max_snapshots: 64,
            current_position: TracePosition::START,
            insns_since_snapshot: 0,
        }
    }

    /// Record a snapshot at the current position.
    pub fn take_snapshot(&mut self, snapshot: ProcessSnapshot) {
        let pos = snapshot.position;
        self.snapshots.insert(pos, snapshot);
        self.insns_since_snapshot = 0;
        // Prune oldest snapshots if over limit.
        while self.snapshots.len() > self.max_snapshots {
            if let Some(oldest_key) = self.snapshots.keys().next().copied() {
                self.snapshots.remove(&oldest_key);
            }
        }
    }

    /// Find the most recent snapshot at or before `position`.
    #[must_use]
    pub fn nearest_snapshot_before(&self, position: TracePosition) -> Option<&ProcessSnapshot> {
        self.snapshots.range(..=position).next_back().map(|(_, s)| s)
    }

    /// Notify the simulator that one instruction was executed (may trigger an
    /// automatic snapshot prompt).
    ///
    /// Returns `true` if a snapshot should be taken now.
    pub const fn on_instruction_executed(&mut self) -> bool {
        self.insns_since_snapshot += 1;
        self.current_position = self.current_position.next_instruction();
        if self.insns_since_snapshot >= self.snapshot_interval {
            self.insns_since_snapshot = 0;
            return true;
        }
        false
    }

    /// Simulate stepping backward by locating the nearest snapshot and
    /// returning the instructions that need to be replayed.
    ///
    /// Returns `(snapshot_position, steps_to_replay)`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the current position is the beginning or no snapshot exists.
    pub fn plan_backward_step(
        &self,
        from: TracePosition,
    ) -> Result<(TracePosition, u64), TtdError> {
        let target = from.prev_instruction().ok_or(TtdError::AtBeginning)?;
        let snap = self
            .nearest_snapshot_before(target)
            .ok_or(TtdError::NoSnapshot(target.sequence))?;
        let snap_pos = snap.position;
        // Distance in instructions (simplified: difference in offset field).
        let steps = target.offset.saturating_sub(snap_pos.offset)
            + (target.sequence.saturating_sub(snap_pos.sequence)) * self.snapshot_interval;
        Ok((snap_pos, steps))
    }

    /// Number of stored snapshots.
    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Discard all stored snapshots.
    pub fn clear_snapshots(&mut self) {
        self.snapshots.clear();
        self.insns_since_snapshot = 0;
    }

    /// Log a replay event.
    pub fn log_event(&mut self, event: impl Into<String>) {
        let e = event.into();
        self.replay_log.push_front(e);
        if self.replay_log.len() > 1000 {
            self.replay_log.pop_back();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TtdSession — the public-facing TTD session
// ─────────────────────────────────────────────────────────────────────────────

/// Session configuration for TTD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdConfig {
    /// Prefer hardware TTD backend if available.
    pub prefer_hardware_backend: bool,
    /// Snapshot interval for the simulation fallback (instructions).
    pub snapshot_interval: u64,
    /// Maximum number of reverse breakpoints to remember.
    pub max_reverse_breakpoints: usize,
    /// Enable instruction-level trace logging.
    pub trace_logging: bool,
}

impl Default for TtdConfig {
    fn default() -> Self {
        Self {
            prefer_hardware_backend: true,
            snapshot_interval: 10_000,
            max_reverse_breakpoints: 64,
            trace_logging: false,
        }
    }
}

/// The top-level TTD session, holding either a real backend or the snapshot
/// simulator.
pub struct TtdSession {
    /// Real TTD backend, if one was loaded.
    backend: Option<Box<dyn TtdBackend>>,
    /// Snapshot-based simulator (always present as fallback).
    simulator: SnapshotSimulator,
    /// Current trace position.
    current: TracePosition,
    /// Session configuration.
    pub config: TtdConfig,
    /// Reverse-execution breakpoints (PCs at which reverse-continue stops).
    reverse_breakpoints: Vec<u64>,
    /// History of visited positions for the "run to previous call" heuristic.
    position_history: VecDeque<(TracePosition, u64 /* pc */)>,
    /// Whether a trace is currently loaded.
    trace_loaded: bool,
}

impl TtdSession {
    /// Create a new TTD session without a loaded trace.
    #[must_use]
    pub fn new(config: TtdConfig) -> Self {
        let interval = config.snapshot_interval;
        Self {
            backend: None,
            simulator: SnapshotSimulator::new(interval),
            current: TracePosition::START,
            config,
            reverse_breakpoints: Vec::new(),
            position_history: VecDeque::new(),
            trace_loaded: false,
        }
    }

    /// Attach a real TTD backend (e.g. from `rustre-ttd`).
    pub fn attach_backend(&mut self, backend: Box<dyn TtdBackend>) {
        self.trace_loaded = true;
        self.backend = Some(backend);
    }

    /// Whether a trace (real or simulated) is available.
    #[must_use]
    pub fn is_trace_loaded(&self) -> bool {
        self.trace_loaded || !self.simulator.snapshots.is_empty()
    }

    /// Current position in the trace.
    #[must_use]
    pub const fn current_position(&self) -> TracePosition {
        self.current
    }

    // ── Reverse-breakpoints ───────────────────────────────────────────────────

    /// Add a reverse-execution breakpoint at `pc`.
    pub fn add_reverse_breakpoint(&mut self, pc: u64) {
        if !self.reverse_breakpoints.contains(&pc) {
            self.reverse_breakpoints.push(pc);
            if self.reverse_breakpoints.len() > self.config.max_reverse_breakpoints {
                self.reverse_breakpoints.remove(0);
            }
        }
    }

    /// Remove a reverse-execution breakpoint.
    pub fn remove_reverse_breakpoint(&mut self, pc: u64) {
        self.reverse_breakpoints.retain(|&p| p != pc);
    }

    // ── Core TTD operations ───────────────────────────────────────────────────

    /// Step backward one instruction.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the step fails or the beginning of the trace is reached.
    pub fn step_backward(&mut self) -> Result<TtdState, TtdError> {
        if let Some(backend) = &mut self.backend {
            let state = backend.step_backward(self.current)?;
            self.current = state.position;
            self.record_history(state.position, state.pc);
            Ok(state)
        } else {
            // Snapshot simulation: plan backward step.
            let (snap_pos, replay_steps) = self.simulator.plan_backward_step(self.current)?;
            let target = self.current.prev_instruction().ok_or(TtdError::AtBeginning)?;
            self.simulator
                .log_event(format!("backward_step: replay {replay_steps} insns from {snap_pos}"));
            self.current = target;
            self.record_history(target, 0 /* pc unknown without registers */);
            // Return a synthetic state — the caller must read registers from the snapshot.
            let state = TtdState {
                position: target,
                pc: 0,
                sp: 0,
                regs: BTreeMap::new(),
                stop_reason: "simulated_backward_step".into(),
            };
            Ok(state)
        }
    }

    // ── Provenance of the backend-less ("simulated") paths ───────────────────
    //
    // When no `TtdBackend` is attached, `step_backward` / `reverse_continue` /
    // `run_to_previous_call` / `seek` can still move the POSITION cursor — that
    // is real bookkeeping over recorded snapshots. What they cannot do is
    // measure registers, so the `pc`, `sp` and `regs` of the returned
    // [`TtdState`] are NOT measurements: `pc`/`sp` are 0 and `regs` is empty.
    //
    // `pc = 0` serialises indistinguishably from a real pc of 0, so the only
    // machine-readable signal is `stop_reason`, which on every such path starts
    // with [`SIMULATED_STOP_REASON_PREFIX`]. A caller that reports pc/registers
    // MUST either check that prefix or overlay a concrete backend (see
    // [`SnapshotReplayBackend`]); `debug.reverse_step` in `rustre-mcp-tools`
    // does the latter and emits `pc: null` when no recorded state exists.
    //
    // The properly honest shape is `pc: Option<u64>`. That is not done here
    // because `TtdState.pc` is read as a `u64` across crates this module does
    // not own; the prefix is pinned by a test below so the contract cannot rot
    // silently in the meantime.

    /// Reverse-continue: run backward until a reverse breakpoint is hit or
    /// the beginning of the trace is reached.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the operation fails or the beginning is reached.
    pub fn reverse_continue(&mut self) -> Result<TtdState, TtdError> {
        if let Some(backend) = &mut self.backend {
            let stop_pcs = self.reverse_breakpoints.clone();
            let state = backend.reverse_continue(self.current, &stop_pcs)?;
            self.current = state.position;
            self.record_history(state.position, state.pc);
            Ok(state)
        } else {
            // Without a backend this used to jump to the nearest snapshot
            // before the cursor and report a stop — ignoring the reverse
            // breakpoints ENTIRELY. A caller that asked "run backward until pc
            // 0x401000" was told it had stopped, at a position chosen by where
            // a snapshot happened to be taken. The stop_reason prefix marks
            // pc/regs as unmeasured, but the POSITION is documented as real
            // bookkeeping, and here it answered a question nobody asked.
            if self.current == TracePosition::START {
                return Err(TtdError::AtBeginning);
            }
            if self.reverse_breakpoints.is_empty() {
                // No breakpoints: reverse-continue means "run back to the
                // start", which is what a real backend does (see the
                // `SnapshotReplayBackend` test with an empty stop list).
                let new_pos = TracePosition::START;
                self.simulator
                    .log_event(format!("reverse_continue: no breakpoints, ran back to {new_pos}"));
                self.current = new_pos;
                self.record_history(new_pos, 0);
                return Ok(TtdState {
                    position: new_pos,
                    pc: 0,
                    sp: 0,
                    regs: BTreeMap::new(),
                    stop_reason: "simulated_reverse_continue_to_beginning".into(),
                });
            }
            // Breakpoints are set: the only evidence available without a
            // backend is the recorded history, whose pcs are real measurements
            // taken when those positions were visited. Land on the most recent
            // one that is strictly before the cursor and matches a breakpoint.
            let hit = self
                .position_history
                .iter()
                .copied()
                .find(|(pos, pc)| *pos < self.current && self.reverse_breakpoints.contains(pc));
            let Some((new_pos, _pc)) = hit else {
                // Nothing recorded proves a breakpoint was ever crossed. A
                // snapshot jump reported as a breakpoint stop would be a
                // fabricated answer to a precise question, so refuse instead.
                return Err(TtdError::Unsupported(format!(
                    "reverse_continue to one of {} reverse breakpoint(s) needs a TTD backend:                      no recorded position before {} matches one, and jumping to the nearest                      snapshot would report a stop that never happened",
                    self.reverse_breakpoints.len(),
                    self.current
                )));
            };
            self.simulator
                .log_event(format!("reverse_continue: recorded breakpoint hit at {new_pos}"));
            self.current = new_pos;
            self.record_history(new_pos, 0);
            Ok(TtdState {
                position: new_pos,
                pc: 0,
                sp: 0,
                regs: BTreeMap::new(),
                stop_reason: "simulated_reverse_continue_at_recorded_breakpoint".into(),
            })
        }
    }

    /// Reverse-step-over: step backward past the current call frame.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the operation fails.
    pub fn reverse_step_over(&mut self) -> Result<TtdState, TtdError> {
        if let Some(backend) = &mut self.backend {
            let state = backend.reverse_step_over(self.current)?;
            self.current = state.position;
            self.record_history(state.position, state.pc);
            Ok(state)
        } else {
            // Simulation: same as a single backward step (simplified).
            self.step_backward()
        }
    }

    /// Run to the previous call instruction before `current`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the beginning of the trace is reached.
    pub fn run_to_previous_call(&mut self) -> Result<TtdState, TtdError> {
        if let Some(backend) = &mut self.backend {
            let state = backend.run_to_previous_call(self.current)?;
            self.current = state.position;
            self.record_history(state.position, state.pc);
            Ok(state)
        } else {
            // Simulation: walk the position history to find a `call` event.
            let call_entry = self
                .position_history
                .iter()
                .skip(1) // skip current
                .find(|(pos, _)| pos.sequence < self.current.sequence)
                .copied();
            if let Some((pos, pc)) = call_entry {
                self.current = pos;
                self.simulator.log_event(format!("run_to_previous_call: jumped to {pos}"));
                Ok(TtdState {
                    position: pos,
                    pc,
                    sp: 0,
                    regs: BTreeMap::new(),
                    stop_reason: "simulated_previous_call".into(),
                })
            } else {
                Err(TtdError::AtBeginning)
            }
        }
    }

    /// Seek to an absolute trace position.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the position is out of range or the backend seek fails.
    pub fn seek(&mut self, position: TracePosition) -> Result<TtdState, TtdError> {
        if let Some(backend) = &mut self.backend {
            let (start, end) = backend.trace_extent();
            if position < start || position > end {
                return Err(TtdError::OutOfRange(position.sequence, end.sequence));
            }
            let state = backend.seek(position)?;
            self.current = state.position;
            self.record_history(state.position, state.pc);
            Ok(state)
        } else {
            self.current = position;
            Ok(TtdState {
                position,
                pc: 0,
                sp: 0,
                regs: BTreeMap::new(),
                stop_reason: "simulated_seek".into(),
            })
        }
    }

    // ── Snapshot management ───────────────────────────────────────────────────

    /// Record a process snapshot at the current position. Call this periodically
    /// during live execution to enable the simulation fallback.
    pub fn record_snapshot(&mut self, snapshot: ProcessSnapshot) {
        self.trace_loaded = true;
        self.simulator.take_snapshot(snapshot);
    }

    /// Check if a snapshot should be taken now (called after each instruction).
    pub const fn maybe_snapshot(&mut self) -> bool {
        self.simulator.on_instruction_executed()
    }

    /// Return the number of stored snapshots.
    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.simulator.snapshot_count()
    }

    // ── History ───────────────────────────────────────────────────────────────

    fn record_history(&mut self, pos: TracePosition, pc: u64) {
        self.position_history.push_front((pos, pc));
        if self.position_history.len() > 1024 {
            self.position_history.pop_back();
        }
    }

    /// Return the N most recently visited positions.
    #[must_use]
    pub fn recent_history(&self, n: usize) -> Vec<(TracePosition, u64)> {
        self.position_history.iter().take(n).copied().collect()
    }

    /// Clear all history.
    pub fn clear_history(&mut self) {
        self.position_history.clear();
    }

    // ── Backend info ──────────────────────────────────────────────────────────

    /// Return the name of the active backend, or `"snapshot-simulation"` if
    /// no real backend is attached.
    #[must_use]
    pub fn backend_name(&self) -> &str {
        self.backend.as_ref().map_or("snapshot-simulation", |b| b.name())
    }

    /// Return the trace extent from the backend, if any.
    #[must_use]
    pub fn trace_extent(&self) -> Option<(TracePosition, TracePosition)> {
        self.backend.as_ref().map(|b| b.trace_extent())
    }
}

impl fmt::Debug for TtdSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TtdSession")
            .field("backend", &self.backend_name())
            .field("current", &self.current)
            .field("trace_loaded", &self.trace_loaded)
            .field("snapshot_count", &self.simulator.snapshot_count())
            .field("reverse_breakpoints", &self.reverse_breakpoints.len())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Thread-safe shared session
// ─────────────────────────────────────────────────────────────────────────────

/// Thread-safe wrapper around a `TtdSession`.
#[derive(Clone)]
pub struct SharedTtdSession(Arc<RwLock<TtdSession>>);

impl SharedTtdSession {
    #[must_use]
    pub fn new(config: TtdConfig) -> Self {
        Self(Arc::new(RwLock::new(TtdSession::new(config))))
    }

    /// # Errors
    ///
    /// Returns `Err` if the step fails or the beginning of the trace is reached.
    pub fn step_backward(&self) -> Result<TtdState, TtdError> {
        self.0.write().step_backward()
    }

    /// # Errors
    ///
    /// Returns `Err` if the operation fails or the beginning is reached.
    pub fn reverse_continue(&self) -> Result<TtdState, TtdError> {
        self.0.write().reverse_continue()
    }

    /// # Errors
    ///
    /// Returns `Err` if the operation fails.
    pub fn reverse_step_over(&self) -> Result<TtdState, TtdError> {
        self.0.write().reverse_step_over()
    }

    /// # Errors
    ///
    /// Returns `Err` if the beginning of the trace is reached.
    pub fn run_to_previous_call(&self) -> Result<TtdState, TtdError> {
        self.0.write().run_to_previous_call()
    }

    /// # Errors
    ///
    /// Returns `Err` if the position is out of range or seek fails.
    pub fn seek(&self, pos: TracePosition) -> Result<TtdState, TtdError> {
        self.0.write().seek(pos)
    }

    pub fn record_snapshot(&self, snapshot: ProcessSnapshot) {
        self.0.write().record_snapshot(snapshot);
    }

    #[must_use]
    pub fn maybe_snapshot(&self) -> bool {
        self.0.write().maybe_snapshot()
    }

    pub fn add_reverse_breakpoint(&self, pc: u64) {
        self.0.write().add_reverse_breakpoint(pc);
    }

    pub fn remove_reverse_breakpoint(&self, pc: u64) {
        self.0.write().remove_reverse_breakpoint(pc);
    }

    #[must_use]
    pub fn current_position(&self) -> TracePosition {
        self.0.read().current_position()
    }

    #[must_use]
    pub fn backend_name(&self) -> String {
        self.0.read().backend_name().to_owned()
    }

    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.0.read().snapshot_count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SnapshotReplayBackend — the first concrete TtdBackend
// ─────────────────────────────────────────────────────────────────────────────

/// A concrete [`TtdBackend`] that replays an ordered log of recorded
/// [`TtdState`] snapshots — real captured register/pc/sp state, not the
/// position-only fallback simulation of a backend-less [`TtdSession`].
///
/// It is built by `record`ing a live session's state at successive positions
/// (e.g. from the MCP `debug.ttd_record` path). Unlike a proprietary replay
/// engine (WinDbg TTD, rr, QEMU), it needs no external trace format — it simply
/// serves the states it was given. This is the first concrete `TtdBackend` in
/// the crate, so `TtdSession::reverse_step`/`seek`/… can return real recorded
/// registers instead of a synthetic `pc=0` state.
#[derive(Debug, Default)]
pub struct SnapshotReplayBackend {
    /// Recorded states, kept sorted by `position` (ascending).
    states: Vec<TtdState>,
    /// Optional recorded memory windows per position: `position -> [(base, bytes)]`.
    /// Lets historical reads (e.g. a deref evaluated at a past position) resolve
    /// against the memory as it was, not current memory.
    memory: std::collections::BTreeMap<TracePosition, Vec<(u64, Vec<u8>)>>,
}

impl SnapshotReplayBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a captured state, keeping the log sorted by position. A state at
    /// an already-recorded position replaces the old one.
    pub fn record(&mut self, state: TtdState) {
        let pos = state.position;
        match self.states.binary_search_by(|s| s.position.cmp(&pos)) {
            Ok(i) => self.states[i] = state,
            Err(i) => self.states.insert(i, state),
        }
    }

    /// Record a memory window captured at `position` (e.g. the stack around rsp),
    /// so historical reads at that position can resolve.
    pub fn record_memory(&mut self, position: TracePosition, base: u64, bytes: Vec<u8>) {
        self.memory.entry(position).or_default().push((base, bytes));
    }

    /// Read `len` bytes at `addr` from the memory recorded at `position`, if any
    /// recorded window covers the whole range. `None` when unrecorded.
    #[must_use]
    pub fn read_memory_at(&self, position: TracePosition, addr: u64, len: usize) -> Option<Vec<u8>> {
        let windows = self.memory.get(&position)?;
        for (base, bytes) in windows {
            let end = base.checked_add(bytes.len() as u64)?;
            if addr >= *base && addr.checked_add(len as u64)? <= end {
                let off = (addr - base) as usize;
                return Some(bytes[off..off + len].to_vec());
            }
        }
        None
    }

    /// Number of recorded states.
    #[must_use]
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// True if nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Return the recorded state at or immediately before `position`, without
    /// mutating `self`.  This is the immutable counterpart of
    /// [`TtdBackend::seek`] used by the retroactive-print layer.
    #[must_use]
    pub fn seek_immutable(&self, position: TracePosition) -> Option<TtdState> {
        if self.states.is_empty() {
            return None;
        }
        let idx = self.states.partition_point(|s| s.position <= position);
        if idx > 0 {
            Some(self.states[idx - 1].clone())
        } else {
            self.states.first().cloned()
        }
    }
}

impl TtdBackend for SnapshotReplayBackend {
    fn name(&self) -> &str {
        "snapshot-replay"
    }

    fn trace_extent(&self) -> (TracePosition, TracePosition) {
        match (self.states.first(), self.states.last()) {
            (Some(f), Some(l)) => (f.position, l.position),
            _ => (TracePosition::START, TracePosition::START),
        }
    }

    fn seek(&mut self, position: TracePosition) -> Result<TtdState, TtdError> {
        if self.states.is_empty() {
            return Err(TtdError::NoTrace);
        }
        if let Ok(i) = self.states.binary_search_by(|s| s.position.cmp(&position)) {
            return Ok(self.states[i].clone());
        }
        // Nearest recorded state at or before `position`.
        let idx = self.states.partition_point(|s| s.position <= position);
        if idx == 0 {
            let (_, end) = self.trace_extent();
            return Err(TtdError::OutOfRange(position.sequence, end.sequence));
        }
        Ok(self.states[idx - 1].clone())
    }

    fn step_forward(&mut self, current: TracePosition) -> Result<TtdState, TtdError> {
        let idx = self.states.partition_point(|s| s.position <= current);
        self.states.get(idx).cloned().ok_or(TtdError::AtEnd)
    }

    fn step_backward(&mut self, current: TracePosition) -> Result<TtdState, TtdError> {
        let idx = self.states.partition_point(|s| s.position < current);
        if idx == 0 {
            return Err(TtdError::AtBeginning);
        }
        Ok(self.states[idx - 1].clone())
    }

    fn reverse_continue(
        &mut self,
        from: TracePosition,
        stop_at: &[u64],
    ) -> Result<TtdState, TtdError> {
        let start = self.states.partition_point(|s| s.position < from);
        if start == 0 {
            return Err(TtdError::AtBeginning);
        }
        // No reverse breakpoints → run all the way back to the beginning.
        if stop_at.is_empty() {
            return Ok(self.states[0].clone());
        }
        let mut idx = start;
        while idx > 0 {
            idx -= 1;
            if stop_at.contains(&self.states[idx].pc) {
                return Ok(self.states[idx].clone());
            }
        }
        // No breakpoint hit going back → stop at the beginning.
        Ok(self.states[0].clone())
    }

    fn reverse_step_over(&mut self, current: TracePosition) -> Result<TtdState, TtdError> {
        self.step_backward(current)
    }

    fn run_to_previous_call(&mut self, current: TracePosition) -> Result<TtdState, TtdError> {
        self.step_backward(current)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod live_provenance_guard {
    use super::*;

    /// Every state a backend-less session produces must be self-labelling: its
    /// `stop_reason` carries [`SIMULATED_STOP_REASON_PREFIX`], because its
    /// `pc`/`sp`/`regs` are placeholders and NOT measurements.
    ///
    /// Without this, `pc = 0` from a session with no trace is byte-identical to
    /// a real pc of 0 once serialised — the same defect that made
    /// `ttd_open::open_trace_or_mock` unsafe.
    #[test]
    fn backendless_states_label_themselves_as_not_measured() {
        let mut s = TtdSession::new(TtdConfig::default());
        assert!(s.backend_name().starts_with("snapshot"), "no backend expected here");

        // seek: position moves, registers are unknown.
        let st = s.seek(TracePosition::new(5, 0)).expect("position-only seek");
        assert!(
            st.stop_reason.starts_with(SIMULATED_STOP_REASON_PREFIX),
            "a state with unmeasured registers must say so, got {:?}",
            st.stop_reason
        );
        assert_eq!(st.pc, 0, "placeholder, not a measurement");
        assert!(st.regs.is_empty(), "no registers can be produced without a backend");
    }

    #[test]
    fn every_backendless_stop_reason_in_the_source_carries_the_prefix() {
        // A new backend-less branch that forgets the prefix would hand callers
        // an unlabelled pc=0. Pin it at the source level so adding one fails.
        let src = include_str!("time_travel_debug.rs");
        let production = src.split_once("#[cfg(test)]").map_or(src, |(h, _)| h);
        let mut checked = 0usize;
        for line in production.lines() {
            let t = line.trim();
            // Only a DIRECT string-literal assignment, which is what the
            // backend-less branches use (`"simulated_…".into()`). This used to
            // accept any line starting with `stop_reason:` and take its first
            // quoted substring, which caught `TtdState::new`'s
            // `String::from("unknown")` — and that one is not backend-less at
            // all: `new` receives measured `pc`/`sp` from its caller, so
            // "unknown" means "the reason is not known yet", not "these
            // numbers are invented". Relabelling it `simulated_` to appease
            // the guard would have been the one thing this guard exists to
            // prevent: a provenance claim that isn't true.
            if !t.starts_with("stop_reason: \"") || t.starts_with("stop_reason: state") {
                continue;
            }
            // Only literal assignments inside the backend-less branches.
            if let Some(open) = t.find('"') {
                let lit = &t[open + 1..];
                let Some(close) = lit.find('"') else { continue };
                let lit = &lit[..close];
                if lit.is_empty() {
                    continue;
                }
                checked += 1;
                assert!(
                    lit.starts_with(SIMULATED_STOP_REASON_PREFIX),
                    "stop_reason literal {lit:?} does not declare that its                      pc/sp/regs are unmeasured; prefix it with                      {SIMULATED_STOP_REASON_PREFIX:?} or supply a real backend"
                );
            }
        }
        assert!(checked >= 4, "expected the 4 known backend-less branches, saw {checked}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session() -> TtdSession {
        TtdSession::new(TtdConfig { snapshot_interval: 5, ..Default::default() })
    }

    fn make_snapshot(seq: u64, offset: u64) -> ProcessSnapshot {
        ProcessSnapshot::new(TracePosition::new(seq, offset))
    }

    #[test]
    fn test_snapshot_registration() {
        let mut s = make_session();
        s.record_snapshot(make_snapshot(0, 0));
        s.record_snapshot(make_snapshot(0, 5));
        assert_eq!(s.snapshot_count(), 2);
    }

    fn replay_state(seq: u64, pc: u64) -> TtdState {
        let mut st = TtdState::new(TracePosition::new(seq, 0), pc, 0x7000 + seq);
        st.regs.insert("rax".into(), pc + 1);
        st
    }

    #[test]
    fn snapshot_replay_backend_replays_real_state() {
        let mut b = SnapshotReplayBackend::new();
        // Record out of order to prove it keeps the log sorted.
        b.record(replay_state(2, 0x2000));
        b.record(replay_state(0, 0x1000));
        b.record(replay_state(1, 0x1500));
        assert_eq!(b.len(), 3);
        assert_eq!(b.trace_extent(), (TracePosition::new(0, 0), TracePosition::new(2, 0)));

        // seek returns the REAL recorded registers, not a synthetic pc=0.
        let s = b.seek(TracePosition::new(1, 0)).unwrap();
        assert_eq!(s.pc, 0x1500);
        assert_eq!(s.regs.get("rax"), Some(&0x1501));

        // step_backward from seq 2 → seq 1 (real state).
        let back = b.step_backward(TracePosition::new(2, 0)).unwrap();
        assert_eq!(back.position, TracePosition::new(1, 0));
        assert_eq!(back.pc, 0x1500);

        // step_forward from seq 0 → seq 1.
        assert_eq!(b.step_forward(TracePosition::new(0, 0)).unwrap().pc, 0x1500);

        // reverse_continue with a PC breakpoint stops at the matching state.
        let hit = b.reverse_continue(TracePosition::new(2, 0), &[0x1000]).unwrap();
        assert_eq!(hit.pc, 0x1000);
        // reverse_continue with no breakpoints runs to the beginning.
        assert_eq!(b.reverse_continue(TracePosition::new(2, 0), &[]).unwrap().pc, 0x1000);
        // stepping back from the first state is AtBeginning.
        assert!(matches!(b.step_backward(TracePosition::new(0, 0)), Err(TtdError::AtBeginning)));
    }

    #[test]
    fn snapshot_replay_backend_records_and_reads_historical_memory() {
        let mut b = SnapshotReplayBackend::new();
        let pos = TracePosition::new(1, 0);
        b.record(replay_state(1, 0x1500));
        b.record_memory(pos, 0x7000, vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        // A read fully inside the recorded window resolves.
        assert_eq!(b.read_memory_at(pos, 0x7000, 4), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(b.read_memory_at(pos, 0x7004, 2), Some(vec![0x01, 0x02]));
        // Out of the window, or an unrecorded position, is None.
        assert_eq!(b.read_memory_at(pos, 0x7007, 4), None);
        assert_eq!(b.read_memory_at(TracePosition::new(2, 0), 0x7000, 1), None);
    }

    #[test]
    fn ttd_session_with_replay_backend_returns_real_registers() {
        // A TtdSession with the concrete backend attached returns recorded
        // register state on reverse ops (vs the backend-less pc=0 simulation).
        let mut b = SnapshotReplayBackend::new();
        b.record(replay_state(0, 0x1000));
        b.record(replay_state(1, 0x1500));
        b.record(replay_state(2, 0x2000));
        let mut s = make_session();
        s.attach_backend(Box::new(b));
        s.seek(TracePosition::new(2, 0)).unwrap();
        let back = s.step_backward().unwrap();
        assert_eq!(back.pc, 0x1500, "reverse-step returns the real recorded pc");
        assert_eq!(back.regs.get("rax"), Some(&0x1501), "and real recorded registers");
    }

    #[test]
    fn test_step_backward_with_snapshot() {
        let mut s = make_session();
        s.record_snapshot(make_snapshot(0, 0));
        // Advance current position manually.
        s.current = TracePosition::new(0, 3);
        let result = s.step_backward().unwrap();
        assert_eq!(result.position, TracePosition::new(0, 2));
    }

    #[test]
    fn test_step_backward_at_beginning_errors() {
        let mut s = make_session();
        s.record_snapshot(make_snapshot(0, 0));
        s.current = TracePosition::START;
        let err = s.step_backward().unwrap_err();
        assert_eq!(err, TtdError::AtBeginning);
    }

    /// With no reverse breakpoints set, reverse-continue runs back to the
    /// START of the trace, which is what a real backend does.
    ///
    /// It used to land on whatever snapshot happened to precede the cursor —
    /// a position chosen by the recording cadence, not by the request.
    #[test]
    fn reverse_continue_without_breakpoints_runs_back_to_the_beginning() {
        let mut s = make_session();
        s.record_snapshot(make_snapshot(2, 0));
        s.current = TracePosition::new(5, 10);
        let result = s.reverse_continue().unwrap();
        assert_eq!(result.position, TracePosition::START);
        assert!(result.stop_reason.starts_with(SIMULATED_STOP_REASON_PREFIX));
    }

    /// A reverse breakpoint that nothing recorded ever crossed must be
    /// REFUSED, not answered with a snapshot jump.
    ///
    /// The simulated path ignored `reverse_breakpoints` completely: it jumped
    /// to the nearest snapshot before the cursor and reported a stop. A caller
    /// that asked "run backward until pc 0x401000" was told it had stopped —
    /// at a position that has nothing to do with the question, while the
    /// module documents the POSITION (unlike pc/regs) as real bookkeeping.
    #[test]
    fn reverse_continue_refuses_a_breakpoint_it_has_no_evidence_for() {
        let mut s = make_session();
        s.record_snapshot(make_snapshot(2, 0));
        s.current = TracePosition::new(5, 10);
        s.add_reverse_breakpoint(0x401000);

        let err = s.reverse_continue().unwrap_err();
        assert!(
            matches!(err, TtdError::Unsupported(_)),
            "a stop that never happened must not be reported as one: {err:?}"
        );
        assert_eq!(
            s.current,
            TracePosition::new(5, 10),
            "a refused reverse-continue must not move the cursor"
        );
    }

    /// ...and when the history DOES record a visit to that pc, it lands there.
    #[test]
    fn reverse_continue_stops_at_a_recorded_breakpoint_position() {
        let mut s = make_session();
        s.add_reverse_breakpoint(0x401000);
        // Walk forward through positions, recording the pc seen at each.
        s.record_history(TracePosition::new(1, 0), 0x400000);
        s.record_history(TracePosition::new(3, 0), 0x401000); // the breakpoint
        s.record_history(TracePosition::new(7, 0), 0x402000);
        s.current = TracePosition::new(9, 0);

        let state = s.reverse_continue().expect("the history proves this position was visited");
        assert_eq!(state.position, TracePosition::new(3, 0));
        assert_eq!(s.current, TracePosition::new(3, 0));
        assert!(state.stop_reason.starts_with(SIMULATED_STOP_REASON_PREFIX));
    }

    #[test]
    fn test_trace_position_ordering() {
        let a = TracePosition::new(0, 100);
        let b = TracePosition::new(1, 0);
        assert!(a < b);
    }

    #[test]
    fn test_snapshot_page_save_read() {
        let mut snap = ProcessSnapshot::new(TracePosition::START);
        snap.save_page(0x1000, vec![0xAB; 4096]);
        assert_eq!(snap.read_byte(0x1000), Some(0xAB));
        assert_eq!(snap.read_byte(0x1001), Some(0xAB));
        assert_eq!(snap.read_byte(0x2000), None);
    }

    #[test]
    fn test_reverse_breakpoint_management() {
        let mut s = make_session();
        s.add_reverse_breakpoint(0x0040_1000);
        s.add_reverse_breakpoint(0x0040_2000);
        assert_eq!(s.reverse_breakpoints.len(), 2);
        s.remove_reverse_breakpoint(0x0040_1000);
        assert_eq!(s.reverse_breakpoints.len(), 1);
        assert_eq!(s.reverse_breakpoints[0], 0x0040_2000);
    }

    #[test]
    fn test_backend_name_defaults_to_simulation() {
        let s = make_session();
        assert_eq!(s.backend_name(), "snapshot-simulation");
    }

    #[test]
    fn test_maybe_snapshot_triggers_at_interval() {
        let mut s = make_session(); // interval = 5
        let mut triggered = 0;
        for _ in 0..15 {
            if s.maybe_snapshot() {
                triggered += 1;
            }
        }
        assert_eq!(triggered, 3);
    }
}
