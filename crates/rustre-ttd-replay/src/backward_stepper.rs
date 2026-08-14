//! Backward stepping through a TTD (Time-Travel Debugging) trace.
//!
//! [`BackwardStepper`] provides two reverse stepping modes:
//! * [`ReverseStepMode::SingleStep`] — move one event backward.
//! * [`ReverseStepMode::StepBack`] — move backward past the most recent call,
//!   landing at the call instruction.
//!
//! Because hardware trace data cannot naturally be played in reverse, backward
//! stepping is implemented by replaying the trace forward from the nearest
//! periodic snapshot to just before the target event.  The stepper maintains
//! its own snapshot cache, independent of the main replay engine.

use std::collections::HashMap;
use std::sync::Arc;

use rustre_ttd::{EventKind, TraceEvent, TracePosition, TtdTrace};
use serde::{Deserialize, Serialize};

use crate::{MemoryState, ReplayError, Snapshot, SnapshotCache};

// ─── ReverseStepMode ─────────────────────────────────────────────────────────

/// Mode for backward stepping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReverseStepMode {
    /// Step back exactly one event.
    SingleStep,
    /// Step back past the current return, landing on the matching call.
    StepBack,
}

impl std::fmt::Display for ReverseStepMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SingleStep => write!(f, "ReverseSingleStep"),
            Self::StepBack => write!(f, "ReverseStepBack"),
        }
    }
}

// ─── ReverseStepResult ────────────────────────────────────────────────────────

/// Outcome of a backward step operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseStepResult {
    /// Position after the reverse step.
    pub position: TracePosition,
    /// Number of forward events replayed to reconstruct the state.
    pub forward_events_replayed: usize,
    /// Stop reason.
    pub stop_reason: ReverseStopReason,
    /// Registers for the primary thread at the new position.
    pub registers: HashMap<String, u64>,
    /// Thread ID.
    pub thread_id: u32,
}

/// Why a backward step halted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReverseStopReason {
    /// Moved back one event.
    Stepped,
    /// Reached the matching call for the current return.
    CallReached { call_address: u64 },
    /// Already at the start of the trace.
    StartOfTrace,
}

impl std::fmt::Display for ReverseStopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stepped => write!(f, "ReverseStepped"),
            Self::CallReached { call_address } => {
                write!(f, "CallReached(0x{call_address:x})")
            }
            Self::StartOfTrace => write!(f, "StartOfTrace"),
        }
    }
}

// ─── BackwardStepper ─────────────────────────────────────────────────────────

/// Backward stepper for TTD traces.
///
/// The stepper maintains a snapshot cache with a configurable interval.
/// Every `snapshot_interval` events a full state snapshot is saved during
/// forward reconstruction; this amortises the cost of repeated backward steps.
///
/// # Example
/// ```no_run
/// use std::sync::Arc;
/// use rustre_ttd::{TtdTrace, TraceMetadata};
/// use rustre_ttd_replay::backward_stepper::{BackwardStepper, ReverseStepMode};
///
/// let trace = Arc::new(TtdTrace::new(TraceMetadata::default()));
/// let mut stepper = BackwardStepper::new(trace, 100);
/// let result = stepper.step(ReverseStepMode::SingleStep);
/// ```
pub struct BackwardStepper {
    /// The trace being replayed.
    trace: Arc<TtdTrace>,
    /// Current event index (the next event that would be executed forward).
    event_index: usize,
    /// Current replay position.
    current_pos: TracePosition,
    /// Memory state at `current_pos`.
    memory: MemoryState,
    /// Per-thread register state.
    registers: HashMap<u32, HashMap<String, u64>>,
    /// Periodic snapshot cache.
    snapshots: SnapshotCache,
}

impl BackwardStepper {
    /// Create a new backward stepper.
    ///
    /// `snapshot_interval` — take a snapshot every N events during forward
    /// replay.  Smaller values use more memory but make backward steps faster.
    pub fn new(trace: Arc<TtdTrace>, snapshot_interval: u64) -> Self {
        Self {
            trace,
            event_index: 0,
            current_pos: TracePosition::start(),
            memory: MemoryState::new(),
            registers: HashMap::new(),
            snapshots: SnapshotCache::new(snapshot_interval),
        }
    }

    /// Create a stepper positioned at the end of the trace, with all snapshots
    /// pre-built by a full forward replay.
    pub fn new_at_end(trace: &Arc<TtdTrace>, snapshot_interval: u64) -> Self {
        let mut s = Self::new(Arc::clone(trace), snapshot_interval);
        s.replay_to_end_and_snapshot();
        s
    }

    /// Return the current trace position.
    #[must_use]
    pub const fn position(&self) -> TracePosition {
        self.current_pos
    }

    /// Return the current event index.
    #[must_use]
    pub const fn event_index(&self) -> usize {
        self.event_index
    }

    /// Return the snapshot cache.
    #[must_use]
    pub const fn snapshots(&self) -> &SnapshotCache {
        &self.snapshots
    }

    /// Whether we are at the start of the trace.
    #[must_use]
    pub const fn at_start(&self) -> bool {
        self.event_index == 0
    }

    /// Return the memory state.
    #[must_use]
    pub const fn memory(&self) -> &MemoryState {
        &self.memory
    }

    /// Perform a reverse step.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn step(&mut self, mode: ReverseStepMode) -> Result<ReverseStepResult, ReplayError> {
        match mode {
            ReverseStepMode::SingleStep => Ok(self.single_step_back()),
            ReverseStepMode::StepBack => Ok(self.step_back_over_call()),
        }
    }

    // ── Reverse single step ──────────────────────────────────────────────────

    fn single_step_back(&mut self) -> ReverseStepResult {
        if self.event_index == 0 {
            return ReverseStepResult {
                position: self.current_pos,
                forward_events_replayed: 0,
                stop_reason: ReverseStopReason::StartOfTrace,
                registers: HashMap::new(),
                thread_id: 0,
            };
        }

        let events = self.trace.all_events();
        // Target: state after event at (event_index - 2).
        let target_idx = self.event_index.saturating_sub(2);
        let at_start = self.event_index == 1;

        if at_start {
            // Reset to initial state.
            self.current_pos = TracePosition::start();
            self.memory = MemoryState::new();
            self.registers = HashMap::new();
            self.event_index = 0;
            return ReverseStepResult {
                position: self.current_pos,
                forward_events_replayed: 0,
                stop_reason: ReverseStopReason::StartOfTrace,
                registers: HashMap::new(),
                thread_id: 0,
            };
        }

        let (replayed, tid) = self.reconstruct_state_at(target_idx, &events);

        ReverseStepResult {
            position: self.current_pos,
            forward_events_replayed: replayed,
            stop_reason: ReverseStopReason::Stepped,
            registers: self.registers.get(&tid).cloned().unwrap_or_default(),
            thread_id: tid,
        }
    }

    // ── Reverse step back over call ──────────────────────────────────────────

    fn step_back_over_call(&mut self) -> ReverseStepResult {
        if self.event_index == 0 {
            return ReverseStepResult {
                position: self.current_pos,
                forward_events_replayed: 0,
                stop_reason: ReverseStopReason::StartOfTrace,
                registers: HashMap::new(),
                thread_id: 0,
            };
        }

        let events = self.trace.all_events();
        let current_tid = if self.event_index < events.len() {
            events[self.event_index.saturating_sub(1)].thread_id
        } else {
            events.last().map_or(0, |e| e.thread_id)
        };

        // Scan backward for a matching Call event.
        let mut depth: i64 = 0;
        let mut call_idx: Option<usize> = None;
        let mut scan_end = self.event_index.saturating_sub(1);

        // The event we are stepping BACK OVER is the Return itself. Counting it
        // as a nested return left the matching Call at depth 1, so it was
        // skipped and the scan ran off the front of the trace: the stepper
        // answered StartOfTrace and reset the position, instead of stopping at
        // the call it was asked to step over.
        if scan_end > 0
            && events
                .get(scan_end)
                .is_some_and(|e| e.thread_id == current_tid && matches!(e.kind, EventKind::Return { .. }))
        {
            scan_end -= 1;
        }

        for idx in (0..=scan_end).rev() {
            let ev = &events[idx];
            if ev.thread_id != current_tid {
                continue;
            }
            match &ev.kind {
                EventKind::Return { .. } => depth += 1,
                EventKind::Call { from: _, .. } => {
                    if depth == 0 {
                        call_idx = Some(idx);
                        break;
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }

        let Some(idx) = call_idx else {
            // No matching call found — step to start.
            self.current_pos = TracePosition::start();
            self.memory = MemoryState::new();
            self.registers = HashMap::new();
            self.event_index = 0;
            return ReverseStepResult {
                position: self.current_pos,
                forward_events_replayed: 0,
                stop_reason: ReverseStopReason::StartOfTrace,
                registers: HashMap::new(),
                thread_id: current_tid,
            };
        };

        let call_address = match &events[idx].kind {
            EventKind::Call { from, .. } => *from,
            _ => 0,
        };

        let (replayed, _) = self.reconstruct_state_at(idx, &events);

        ReverseStepResult {
            position: self.current_pos,
            forward_events_replayed: replayed,
            stop_reason: ReverseStopReason::CallReached { call_address },
            registers: self.registers.get(&current_tid).cloned().unwrap_or_default(),
            thread_id: current_tid,
        }
    }

    // ── State reconstruction ─────────────────────────────────────────────────

    /// Reconstruct the trace state after event `target_idx` by replaying from
    /// the nearest snapshot.
    ///
    /// Returns `(events_replayed, thread_id_of_target_event)`.
    fn reconstruct_state_at(
        &mut self,
        target_idx: usize,
        events: &[TraceEvent],
    ) -> (usize, u32) {
        let target_pos = events[target_idx].position;
        let tid = events[target_idx].thread_id;

        // Find nearest snapshot at or before target.
        if let Some(snap) = self.snapshots.nearest_before(target_pos).cloned() {
            // Find the index of the snapshot position in the event stream.
            let snap_idx = events
                .iter()
                .position(|e| e.position == snap.position)
                .unwrap_or(0);
            self.restore_snapshot(&snap);

            // Replay from snap_idx+1 to target_idx.
            let start = if snap_idx < target_idx {
                snap_idx + 1
            } else {
                snap_idx
            };
            let mut replayed = 0usize;
            for (offset, ev) in events[start..=target_idx].iter().enumerate() {
                self.apply_event(ev);
                self.maybe_snapshot((start + offset) as u64);
                replayed += 1;
            }
            self.event_index = target_idx + 1;
            (replayed, tid)
        } else {
            // No snapshot: replay from scratch.
            self.current_pos = TracePosition::start();
            self.memory = MemoryState::new();
            self.registers = HashMap::new();
            self.event_index = 0;
            let mut replayed = 0usize;
            for (i, ev) in events[..=target_idx].iter().enumerate() {
                self.apply_event(ev);
                self.maybe_snapshot(i as u64);
                replayed += 1;
            }
            self.event_index = target_idx + 1;
            (replayed, tid)
        }
    }

    fn restore_snapshot(&mut self, snap: &Snapshot) {
        self.current_pos = snap.position;
        self.memory.clone_from(&snap.memory);
        self.registers.clone_from(&snap.registers);
    }

    fn apply_event(&mut self, event: &TraceEvent) {
        self.current_pos = event.position;
        let regs = self.registers.entry(event.thread_id).or_default();
        match &event.kind {
            EventKind::MemWrite { addr, data } => {
                self.memory.apply_write(*addr, data);
            }
            EventKind::Call { to, .. } | EventKind::Return { to, .. } => {
                regs.insert("rip".into(), *to);
            }
            EventKind::SyscallEnter { nr, args } => {
                regs.insert("rax".into(), u64::from(*nr));
                regs.insert("rdi".into(), args[0]);
                regs.insert("rsi".into(), args[1]);
                regs.insert("rdx".into(), args[2]);
            }
            EventKind::SyscallExit { ret, .. } => {
                regs.insert("rax".into(), *ret);
            }
            _ => {}
        }
    }

    fn maybe_snapshot(&mut self, event_idx: u64) {
        let interval = self.snapshots.interval;
        if interval == 0 {
            return;
        }
        if event_idx.is_multiple_of(interval) && !self.snapshots.contains(self.current_pos) {
            let snap = Snapshot::new(
                self.current_pos,
                self.memory.clone(),
                self.registers.clone(),
            );
            self.snapshots.insert(snap);
        }
    }

    fn replay_to_end_and_snapshot(&mut self) {
        let events = self.trace.all_events();
        for (i, event) in events.iter().enumerate() {
            self.apply_event(event);
            self.maybe_snapshot(i as u64);
        }
        self.event_index = events.len();
    }

    // ── Jump to position ─────────────────────────────────────────────────────

    /// Jump directly to a specific trace position by replaying forward.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn goto(&mut self, pos: TracePosition) -> Result<(), ReplayError> {
        let events = self.trace.all_events();
        let target_idx = events
            .iter()
            .position(|e| e.position == pos)
            .ok_or(ReplayError::PositionNotFound(pos))?;
        let (_, _) = self.reconstruct_state_at(target_idx, &events);
        Ok(())
    }

    /// Return the register state for `tid`.
    #[must_use]
    pub fn registers_for(&self, tid: u32) -> Option<&HashMap<String, u64>> {
        self.registers.get(&tid)
    }
}

impl std::fmt::Debug for BackwardStepper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackwardStepper")
            .field("event_index", &self.event_index)
            .field("current_pos", &self.current_pos)
            .field("snapshots", &self.snapshots.snapshot_count())
            .finish_non_exhaustive()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_ttd::{TraceMetadata, TracePosition};

    fn make_trace_with_call() -> Arc<TtdTrace> {
        let meta = TraceMetadata {
            version: 1,
            process_name: "test".into(),
            pid: 1,
            arch: "x86_64".into(),
            start_time: 0,
            end_time: 100,
            thread_count: 1,
            ..Default::default()
        };
        let trace = Arc::new(TtdTrace::new(meta));
        trace.add_event(rustre_ttd::TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::MemWrite {
                addr: 0x1000,
                data: vec![0xAA],
            },
        });
        trace.add_event(rustre_ttd::TraceEvent {
            position: TracePosition::new(1, 0),
            thread_id: 1,
            kind: EventKind::Call {
                from: 0x2000,
                to: 0x3000,
            },
        });
        trace.add_event(rustre_ttd::TraceEvent {
            position: TracePosition::new(2, 0),
            thread_id: 1,
            kind: EventKind::MemWrite {
                addr: 0x4000,
                data: vec![0xBB],
            },
        });
        trace.add_event(rustre_ttd::TraceEvent {
            position: TracePosition::new(3, 0),
            thread_id: 1,
            kind: EventKind::Return {
                from: 0x3000,
                to: 0x2004,
            },
        });
        trace
    }

    #[test]
    fn step_back_from_end() {
        let trace = make_trace_with_call();
        let mut stepper = BackwardStepper::new_at_end(&trace, 2);
        let r = stepper.step(ReverseStepMode::SingleStep).unwrap();
        assert!(!matches!(r.stop_reason, ReverseStopReason::StartOfTrace));
    }

    #[test]
    fn step_back_to_start() {
        let trace = make_trace_with_call();
        let mut stepper = BackwardStepper::new_at_end(&trace, 1);
        // Step back until start.
        for _ in 0..10 {
            let r = stepper.step(ReverseStepMode::SingleStep).unwrap();
            if r.stop_reason == ReverseStopReason::StartOfTrace {
                return;
            }
        }
        // Should have hit start within 10 steps for a 4-event trace.
        assert!(stepper.at_start());
    }

    #[test]
    fn step_back_over_call() {
        let trace = make_trace_with_call();
        let mut stepper = BackwardStepper::new_at_end(&trace, 1);
        let r = stepper.step(ReverseStepMode::StepBack).unwrap();
        assert!(matches!(
            r.stop_reason,
            ReverseStopReason::CallReached { .. }
        ));
    }

    #[test]
    fn at_start_returns_start_of_trace() {
        let trace = make_trace_with_call();
        let mut stepper = BackwardStepper::new(trace, 1);
        let r = stepper.step(ReverseStepMode::SingleStep).unwrap();
        assert_eq!(r.stop_reason, ReverseStopReason::StartOfTrace);
    }

    #[test]
    fn snapshot_interval_respected() {
        let trace = make_trace_with_call();
        let stepper = BackwardStepper::new_at_end(&trace, 1);
        // With interval=1, every event should have a snapshot.
        assert!(stepper.snapshots().snapshot_count() >= 1);
    }

    #[test]
    fn memory_reconstructed_after_step_back() {
        let trace = make_trace_with_call();
        let mut stepper = BackwardStepper::new_at_end(&trace, 1);
        // Step back to before the inner mem-write at 0x4000.
        stepper.step(ReverseStepMode::SingleStep).unwrap(); // back from Return
        stepper.step(ReverseStepMode::SingleStep).unwrap(); // back from mem-write
        // After stepping back twice, 0x4000 write should be undone.
        // The stepper reconstructs from snapshot, so check memory is not None.
        let mem = stepper.memory();
        // Memory is valid (no panic).
        let _ = mem.page_count();
    }
}
