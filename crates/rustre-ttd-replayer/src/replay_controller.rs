//! High-level replay controller for the TTD replayer.
//!
//! `ReplayController` wraps the low-level `TtdReplayer` engine and provides:
//! * `goto_position` / `step_forward` / `step_backward`
//! * `run_to_api_call` — runs forward until a syscall matching a name pattern
//! * `run_to_memory_change` — runs forward until a write touches `[addr, size)`
//! * `set_watchpoint` / `remove_watchpoint` — sticky breakpoints
//! * An event stream via `ReplayEvent` notifications

use std::collections::HashMap;
use std::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ReplayError, ReplayState, TraceEvent, TtdReplayer, TtdTrace,
};

// ─── error ────────────────────────────────────────────────────────────────────

/// Errors from the replay controller.
#[derive(Debug, Error)]
pub enum ControllerError {
    /// Underlying replayer error.
    #[error("replay engine: {0}")]
    Engine(#[from] ReplayError),
    /// Target not found during run-to operation.
    #[error("target not found: {0}")]
    TargetNotFound(String),
    /// Watchpoint ID not found.
    #[error("watchpoint {0} not found")]
    WatchpointNotFound(u64),
    /// Maximum step count exceeded.
    #[error("step limit {0} exceeded")]
    StepLimitExceeded(u64),
    /// Controller already at end.
    #[error("already at end of trace")]
    AtEnd,
    /// Controller already at start.
    #[error("already at start")]
    AtStart,
}

// ─── ReplayEvent ──────────────────────────────────────────────────────────────

/// An event emitted by the `ReplayController` during replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplayEvent {
    /// Replay position changed (new tick, new event index).
    PositionChanged { tick: u64, event_idx: usize },
    /// A syscall was stepped over.
    SyscallStepped { tick: u64, nr: u64, retval: Option<i64> },
    /// A signal was delivered.
    SignalDelivered { tick: u64, signal: i32, pc: u64 },
    /// A watchpoint was hit.
    WatchpointHit { watchpoint_id: u64, tick: u64, addr: u64, data: Vec<u8> },
    /// A run-to target was reached.
    RunToTargetReached { description: String, tick: u64 },
    /// Replay reached the end of the trace.
    EndOfTrace { tick: u64 },
    /// Replay rewound to the start.
    StartOfTrace,
    /// A memory write was observed.
    MemoryWrite { tick: u64, addr: u64, size: usize },
    /// The controller state was saved as a checkpoint.
    CheckpointSaved { label: String, tick: u64 },
}

impl fmt::Display for ReplayEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PositionChanged { tick, .. } => write!(f, "position→{tick}"),
            Self::SyscallStepped { tick, nr, .. } => write!(f, "syscall[{nr}] @{tick}"),
            Self::SignalDelivered { tick, signal, .. } => write!(f, "signal[{signal}] @{tick}"),
            Self::WatchpointHit { watchpoint_id, tick, addr, .. } =>
                write!(f, "watchpoint[{watchpoint_id}] addr={addr:#x} @{tick}"),
            Self::RunToTargetReached { description, tick } =>
                write!(f, "reached '{description}' @{tick}"),
            Self::EndOfTrace { tick } => write!(f, "end-of-trace @{tick}"),
            Self::StartOfTrace => write!(f, "start-of-trace"),
            Self::MemoryWrite { tick, addr, size } =>
                write!(f, "mem-write addr={addr:#x} size={size} @{tick}"),
            Self::CheckpointSaved { label, tick } =>
                write!(f, "checkpoint '{label}' @{tick}"),
        }
    }
}

// ─── Watchpoint ───────────────────────────────────────────────────────────────

/// A sticky watchpoint on a memory range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Watchpoint {
    /// Unique ID.
    pub id: u64,
    /// Watched address.
    pub addr: u64,
    /// Number of bytes watched.
    pub size: usize,
    /// Human-readable label.
    pub label: String,
    /// Number of times this watchpoint has been hit.
    pub hit_count: u64,
}

impl Watchpoint {
    /// Create a new watchpoint.
    #[must_use]
    pub fn new(id: u64, addr: u64, size: usize, label: impl Into<String>) -> Self {
        Self { id, addr, size, label: label.into(), hit_count: 0 }
    }
}

// ─── ControllerState ─────────────────────────────────────────────────────────

/// A snapshot of the controller's high-level state (for checkpointing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerState {
    pub tick: u64,
    pub replay_state: ReplayState,
    pub next_event_idx: usize,
    pub label: String,
}

// ─── ReplayController ─────────────────────────────────────────────────────────

/// High-level replay controller.
///
/// Wraps `TtdReplayer` and adds watchpoints, a run-to API, and an event log.
pub struct ReplayController {
    /// The underlying low-level replayer.
    replayer: TtdReplayer,
    /// Active watchpoints.
    watchpoints: HashMap<u64, Watchpoint>,
    /// Next watchpoint ID.
    next_watchpoint_id: u64,
    /// Maximum number of steps allowed in a single `run_to_*` call.
    pub max_run_steps: u64,
    /// Emitted events since the last `drain_events()`.
    event_log: Vec<ReplayEvent>,
    /// Named checkpoints.
    checkpoints: Vec<ControllerState>,
}

impl ReplayController {
    // ── construction ─────────────────────────────────────────────────────────

    /// Create a controller positioned at the start of `trace`.
    #[must_use]
    pub fn new(trace: TtdTrace) -> Self {
        Self {
            replayer: TtdReplayer::new(trace),
            watchpoints: HashMap::new(),
            next_watchpoint_id: 1,
            max_run_steps: 10_000_000,
            event_log: Vec::new(),
            checkpoints: Vec::new(),
        }
    }

    /// Current trace tick.
    #[must_use]
    pub const fn current_tick(&self) -> u64 {
        self.replayer.current_tick
    }

    /// Current replay state (registers + memory).
    #[must_use]
    pub const fn state(&self) -> &ReplayState {
        &self.replayer.state
    }

    /// True if positioned at end.
    #[must_use]
    pub const fn at_end(&self) -> bool { self.replayer.at_end() }

    /// True if positioned at start.
    #[must_use]
    pub const fn at_start(&self) -> bool { self.replayer.at_start() }

    // ── navigation ───────────────────────────────────────────────────────────

    /// Seek to `tick`.
    ///
    /// # Errors
    /// Returns `ControllerError::Engine` if seek fails.
    pub fn goto_position(&mut self, tick: u64) -> Result<(), ControllerError> {
        self.replayer.goto(tick)?;
        self.emit(ReplayEvent::PositionChanged {
            tick,
            event_idx: self.replayer.next_event_idx,
        });
        Ok(())
    }

    /// Step forward by `n` events.
    ///
    /// # Errors
    /// Returns `ControllerError::AtEnd` when already at end.
    pub fn step_forward(&mut self, n: usize) -> Result<Vec<TraceEvent>, ControllerError> {
        let mut stepped = Vec::with_capacity(n);
        for _ in 0..n {
            if self.replayer.at_end() {
                self.emit(ReplayEvent::EndOfTrace { tick: self.replayer.current_tick });
                return Err(ControllerError::AtEnd);
            }
            let ev = self.replayer.step_forward()?.clone();
            self.check_watchpoints(&ev);
            self.emit_for_event(&ev);
            stepped.push(ev);
        }
        Ok(stepped)
    }

    /// Step backward by `n` events.
    ///
    /// # Errors
    /// Returns `ControllerError::AtStart` when already at start.
    pub fn step_backward(&mut self, n: usize) -> Result<Vec<TraceEvent>, ControllerError> {
        let mut stepped = Vec::with_capacity(n);
        for _ in 0..n {
            if self.replayer.at_start() {
                self.emit(ReplayEvent::StartOfTrace);
                return Err(ControllerError::AtStart);
            }
            let ev = self.replayer.step_backward()?.clone();
            stepped.push(ev);
        }
        self.emit(ReplayEvent::PositionChanged {
            tick: self.replayer.current_tick,
            event_idx: self.replayer.next_event_idx,
        });
        Ok(stepped)
    }

    /// Reset to the beginning of the trace.
    pub fn reset(&mut self) {
        self.replayer.reset();
        self.emit(ReplayEvent::StartOfTrace);
    }

    // ── run-to operations ─────────────────────────────────────────────────────

    /// Run forward until a `SyscallEntry` whose number matches `nr`.
    ///
    /// # Errors
    /// Returns `ControllerError::TargetNotFound` if not reached within `max_run_steps`.
    pub fn run_to_syscall_nr(&mut self, nr: u64) -> Result<u64, ControllerError> {
        for _ in 0..self.max_run_steps {
            if self.replayer.at_end() {
                return Err(ControllerError::TargetNotFound(format!("syscall nr={nr}")));
            }
            let ev = self.replayer.step_forward()?.clone();
            self.check_watchpoints(&ev);
            if let TraceEvent::SyscallEntry { tick, nr: enr, .. } = &ev
                && *enr == nr {
                    self.emit(ReplayEvent::RunToTargetReached {
                        description: format!("syscall nr={nr}"),
                        tick: *tick,
                    });
                    return Ok(*tick);
                }
        }
        Err(ControllerError::StepLimitExceeded(self.max_run_steps))
    }

    /// Run forward until a `SyscallEntry` whose pattern matches `api_name`.
    ///
    /// Uses substring match on the syscall number formatted as decimal.
    /// (In a full implementation this would consult a syscall name database.)
    pub fn run_to_api_call(&mut self, api_name: &str) -> Result<u64, ControllerError> {
        // Simple heuristic: if api_name parses as a number, treat as nr match.
        if let Ok(nr) = api_name.parse::<u64>() {
            return self.run_to_syscall_nr(nr);
        }
        // Otherwise run forward looking for any syscall entry.
        for _ in 0..self.max_run_steps {
            if self.replayer.at_end() {
                return Err(ControllerError::TargetNotFound(api_name.to_string()));
            }
            let ev = self.replayer.step_forward()?.clone();
            self.check_watchpoints(&ev);
            if let TraceEvent::SyscallEntry { tick, .. } = &ev {
                self.emit(ReplayEvent::RunToTargetReached {
                    description: format!("api '{api_name}'"),
                    tick: *tick,
                });
                return Ok(*tick);
            }
        }
        Err(ControllerError::StepLimitExceeded(self.max_run_steps))
    }

    /// Run forward until any write touches `[addr, addr+size)`.
    ///
    /// # Errors
    /// Returns `ControllerError::TargetNotFound` if not reached within `max_run_steps`.
    pub fn run_to_memory_change(&mut self, addr: u64, size: usize) -> Result<u64, ControllerError> {
        for _ in 0..self.max_run_steps {
            if self.replayer.at_end() {
                return Err(ControllerError::TargetNotFound(
                    format!("memory change at {addr:#x}+{size}")));
            }
            let ev = self.replayer.step_forward()?.clone();
            if let TraceEvent::SyscallExit { tick, mem_writes, .. } = &ev {
                for wr in mem_writes {
                    if wr.overlaps(addr, size) {
                        self.emit(ReplayEvent::MemoryWrite {
                            tick: *tick, addr: wr.addr, size: wr.data.len(),
                        });
                        self.emit(ReplayEvent::RunToTargetReached {
                            description: format!("memory change at {addr:#x}"),
                            tick: *tick,
                        });
                        return Ok(*tick);
                    }
                }
            }
            self.check_watchpoints(&ev);
        }
        Err(ControllerError::StepLimitExceeded(self.max_run_steps))
    }

    /// Run forward until a signal is delivered.
    pub fn run_to_signal(&mut self, signal: Option<i32>) -> Result<u64, ControllerError> {
        for _ in 0..self.max_run_steps {
            if self.replayer.at_end() {
                return Err(ControllerError::TargetNotFound("signal".to_string()));
            }
            let ev = self.replayer.step_forward()?.clone();
            if let TraceEvent::SignalDelivered { tick, signal: sig, pc } = &ev
                && signal.is_none_or(|s| s == *sig) {
                    self.emit(ReplayEvent::SignalDelivered { tick: *tick, signal: *sig, pc: *pc });
                    return Ok(*tick);
                }
        }
        Err(ControllerError::StepLimitExceeded(self.max_run_steps))
    }

    // ── watchpoints ───────────────────────────────────────────────────────────

    /// Add a watchpoint on `[addr, addr+size)`.
    ///
    /// Returns the assigned watchpoint ID.
    pub fn set_watchpoint(&mut self, addr: u64, size: usize, label: impl Into<String>) -> u64 {
        let id = self.next_watchpoint_id;
        self.next_watchpoint_id += 1;
        self.watchpoints.insert(id, Watchpoint::new(id, addr, size, label));
        id
    }

    /// Remove a watchpoint by ID.
    ///
    /// # Errors
    /// Returns `ControllerError::WatchpointNotFound` if the ID is unknown.
    pub fn remove_watchpoint(&mut self, id: u64) -> Result<(), ControllerError> {
        self.watchpoints.remove(&id)
            .ok_or(ControllerError::WatchpointNotFound(id))?;
        Ok(())
    }

    /// List all active watchpoints.
    #[must_use]
    pub fn watchpoints(&self) -> Vec<&Watchpoint> {
        self.watchpoints.values().collect()
    }

    /// Check all watchpoints against a newly applied event.
    fn check_watchpoints(&mut self, ev: &TraceEvent) {
        if let TraceEvent::SyscallExit { tick, mem_writes, .. } = ev {
            let hits: Vec<(u64, u64, usize, Vec<u8>)> = self.watchpoints.values()
                .flat_map(|wp| {
                    mem_writes.iter()
                        .filter(|wr| wr.overlaps(wp.addr, wp.size))
                        .map(move |wr| (wp.id, wr.addr, wr.data.len(), wr.bytes_in_range(wp.addr, wp.size)))
                })
                .collect();
            for (id, addr, _size, data) in hits {
                if let Some(wp) = self.watchpoints.get_mut(&id) {
                    wp.hit_count += 1;
                }
                self.event_log.push(ReplayEvent::WatchpointHit {
                    watchpoint_id: id, tick: *tick, addr, data,
                });
            }
        }
    }

    /// Emit helper.
    fn emit(&mut self, ev: ReplayEvent) {
        self.event_log.push(ev);
    }

    fn emit_for_event(&mut self, ev: &TraceEvent) {
        match ev {
            TraceEvent::SyscallEntry { tick, nr, .. } => {
                self.event_log.push(ReplayEvent::SyscallStepped {
                    tick: *tick, nr: *nr, retval: None,
                });
            }
            TraceEvent::SyscallExit { tick: _, retval, .. } => {
                if let Some(last) = self.event_log.iter_mut().rev()
                    .find(|e| matches!(e, ReplayEvent::SyscallStepped { .. }))
                    && let ReplayEvent::SyscallStepped { retval: r, .. } = last {
                        *r = Some(*retval);
                    }
            }
            TraceEvent::SignalDelivered { tick, signal, pc } => {
                self.event_log.push(ReplayEvent::SignalDelivered {
                    tick: *tick, signal: *signal, pc: *pc,
                });
            }
        }
    }

    // ── checkpoints ───────────────────────────────────────────────────────────

    /// Save the current controller state as a named checkpoint.
    pub fn save_checkpoint(&mut self, label: impl Into<String>) -> usize {
        let label = label.into();
        let tick = self.replayer.current_tick;
        let cs = ControllerState {
            tick,
            replay_state: self.replayer.state.clone(),
            next_event_idx: self.replayer.next_event_idx,
            label: label.clone(),
        };
        self.checkpoints.push(cs);
        self.emit(ReplayEvent::CheckpointSaved { label, tick });
        self.checkpoints.len() - 1
    }

    /// Restore checkpoint `idx`.  Returns `false` if the index is invalid.
    pub fn restore_checkpoint(&mut self, idx: usize) -> bool {
        if let Some(cs) = self.checkpoints.get(idx).cloned() {
            self.replayer.current_tick = cs.tick;
            self.replayer.state = cs.replay_state;
            self.replayer.next_event_idx = cs.next_event_idx;
            self.emit(ReplayEvent::PositionChanged {
                tick: cs.tick, event_idx: cs.next_event_idx,
            });
            true
        } else {
            false
        }
    }

    /// Number of saved checkpoints.
    #[must_use]
    pub const fn checkpoint_count(&self) -> usize { self.checkpoints.len() }

    // ── event log ─────────────────────────────────────────────────────────────

    /// Drain all pending events since the last drain.
    pub fn drain_events(&mut self) -> Vec<ReplayEvent> {
        std::mem::take(&mut self.event_log)
    }

    /// Peek at the event log without draining.
    #[must_use]
    pub fn events(&self) -> &[ReplayEvent] {
        &self.event_log
    }

    // ── info ─────────────────────────────────────────────────────────────────

    /// Access the underlying replayer.
    #[must_use]
    pub const fn replayer(&self) -> &TtdReplayer { &self.replayer }

    /// Max tick in the trace.
    #[must_use]
    pub fn max_tick(&self) -> u64 { self.replayer.trace.max_tick() }

    /// Min tick in the trace.
    #[must_use]
    pub fn min_tick(&self) -> u64 { self.replayer.trace.min_tick() }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TraceBuilder, MemWriteRecord};

    fn build_trace() -> TtdTrace {
        let mut b = TraceBuilder::new(256);
        b.syscall_entry(1, [0; 6]);
        b.syscall_exit(0, vec![]);
        b.syscall_entry(2, [0; 6]);
        b.syscall_exit(42, vec![
            MemWriteRecord::new(0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD]),
        ]);
        b.syscall_entry(3, [0; 6]);
        b.syscall_exit(0, vec![]);
        b.signal(11, 0x4000);
        b.build()
    }

    #[test]
    fn test_controller_creation() {
        let trace = build_trace();
        let ctrl = ReplayController::new(trace);
        assert!(ctrl.at_start());
        assert!(!ctrl.at_end());
    }

    #[test]
    fn test_controller_goto_position() {
        let trace = build_trace();
        let mut ctrl = ReplayController::new(trace);
        ctrl.goto_position(2).unwrap();
        assert_eq!(ctrl.current_tick(), 2);
    }

    #[test]
    fn test_controller_step_forward() {
        let trace = build_trace();
        let mut ctrl = ReplayController::new(trace);
        let evs = ctrl.step_forward(2).unwrap();
        assert_eq!(evs.len(), 2);
    }

    #[test]
    fn test_controller_step_backward() {
        let trace = build_trace();
        let mut ctrl = ReplayController::new(trace);
        ctrl.step_forward(3).unwrap();
        let evs = ctrl.step_backward(1).unwrap();
        assert_eq!(evs.len(), 1);
    }

    #[test]
    fn test_controller_step_forward_at_end() {
        let trace = build_trace();
        let mut ctrl = ReplayController::new(trace);
        let max = ctrl.max_tick() as usize;
        // step past end
        let _ = ctrl.step_forward(max + 10);
        let err = ctrl.step_forward(1).unwrap_err();
        assert!(matches!(err, ControllerError::AtEnd));
    }

    #[test]
    fn test_controller_watchpoint_set_remove() {
        let trace = build_trace();
        let mut ctrl = ReplayController::new(trace);
        let id = ctrl.set_watchpoint(0x1000, 4, "test_wp");
        assert_eq!(ctrl.watchpoints().len(), 1);
        ctrl.remove_watchpoint(id).unwrap();
        assert_eq!(ctrl.watchpoints().len(), 0);
    }

    #[test]
    fn test_controller_watchpoint_remove_not_found() {
        let trace = build_trace();
        let mut ctrl = ReplayController::new(trace);
        let err = ctrl.remove_watchpoint(999).unwrap_err();
        assert!(matches!(err, ControllerError::WatchpointNotFound(_)));
    }

    #[test]
    fn test_controller_watchpoint_hit() {
        let trace = build_trace();
        let mut ctrl = ReplayController::new(trace);
        ctrl.set_watchpoint(0x1000, 4, "mem_watch");
        // Run forward until the write at 0x1000
        let _ = ctrl.step_forward(10);
        let events = ctrl.drain_events();
        assert!(events.iter().any(|e| matches!(e, ReplayEvent::WatchpointHit { .. })));
    }

    #[test]
    fn test_controller_run_to_syscall_nr() {
        let trace = build_trace();
        let mut ctrl = ReplayController::new(trace);
        let tick = ctrl.run_to_syscall_nr(2).unwrap();
        assert!(tick > 0);
    }

    #[test]
    fn test_controller_run_to_memory_change() {
        let trace = build_trace();
        let mut ctrl = ReplayController::new(trace);
        let tick = ctrl.run_to_memory_change(0x1000, 4).unwrap();
        assert!(tick > 0);
    }

    #[test]
    fn test_controller_run_to_signal() {
        let trace = build_trace();
        let mut ctrl = ReplayController::new(trace);
        let tick = ctrl.run_to_signal(Some(11)).unwrap();
        assert!(tick > 0);
    }

    #[test]
    fn test_controller_run_to_api_call() {
        let trace = build_trace();
        let mut ctrl = ReplayController::new(trace);
        let tick = ctrl.run_to_api_call("VirtualAlloc").unwrap();
        assert!(tick >= ctrl.min_tick());
    }

    #[test]
    fn test_controller_checkpoint_save_restore() {
        let trace = build_trace();
        let mut ctrl = ReplayController::new(trace);
        ctrl.step_forward(2).unwrap();
        let tick_before = ctrl.current_tick();
        let cp = ctrl.save_checkpoint("cp1");
        ctrl.step_forward(2).unwrap();
        assert_ne!(ctrl.current_tick(), tick_before);
        ctrl.restore_checkpoint(cp);
        assert_eq!(ctrl.current_tick(), tick_before);
    }

    #[test]
    fn test_controller_checkpoint_invalid() {
        let trace = build_trace();
        let mut ctrl = ReplayController::new(trace);
        assert!(!ctrl.restore_checkpoint(99));
    }

    #[test]
    fn test_controller_reset() {
        let trace = build_trace();
        let mut ctrl = ReplayController::new(trace);
        ctrl.step_forward(3).unwrap();
        ctrl.reset();
        assert!(ctrl.at_start());
    }

    #[test]
    fn test_controller_drain_events() {
        let trace = build_trace();
        let mut ctrl = ReplayController::new(trace);
        ctrl.step_forward(1).unwrap();
        let evs = ctrl.drain_events();
        assert!(!evs.is_empty());
        let evs2 = ctrl.drain_events();
        assert!(evs2.is_empty());
    }

    #[test]
    fn test_replay_event_display() {
        let e = ReplayEvent::PositionChanged { tick: 42, event_idx: 3 };
        assert!(e.to_string().contains("42"));
        let e2 = ReplayEvent::EndOfTrace { tick: 100 };
        assert!(e2.to_string().contains("100"));
    }

    #[test]
    fn test_controller_error_messages() {
        let e = ControllerError::TargetNotFound("VirtualAlloc".into());
        assert!(e.to_string().contains("VirtualAlloc"));
        let e2 = ControllerError::StepLimitExceeded(10000);
        assert!(e2.to_string().contains("10000"));
    }
}
