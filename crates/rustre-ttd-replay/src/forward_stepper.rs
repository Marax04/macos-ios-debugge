//! Forward stepping through a TTD (Time-Travel Debugging) trace.
//!
//! [`ForwardStepper`] provides three stepping modes:
//! * [`StepMode::SingleStep`] — advance one trace event.
//! * [`StepMode::StepOver`] — advance past the current call if at one, else
//!   single-step.
//! * [`StepMode::StepOut`] — run forward until a matching Return event is seen.
//!
//! All stepping is non-destructive: the stepper holds a reference-counted
//! trace and does not modify it.

use std::collections::HashMap;
use std::sync::Arc;

use rustre_ttd::{EventKind, TraceEvent, TracePosition, TtdTrace};
use serde::{Deserialize, Serialize};

use crate::{MemoryState, ReplayError};

// ─── StepMode ─────────────────────────────────────────────────────────────────

/// Stepping mode for the forward stepper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StepMode {
    /// Advance exactly one trace event.
    SingleStep,
    /// Advance past the current call; if not at a call, single-step.
    StepOver,
    /// Run forward until the matching return from the current call depth.
    StepOut,
}

impl std::fmt::Display for StepMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SingleStep => write!(f, "SingleStep"),
            Self::StepOver => write!(f, "StepOver"),
            Self::StepOut => write!(f, "StepOut"),
        }
    }
}

// ─── StepResult ───────────────────────────────────────────────────────────────

/// The outcome of a forward step operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    /// New position after the step.
    pub position: TracePosition,
    /// How many events were consumed by this step.
    pub events_consumed: usize,
    /// The reason stepping stopped.
    pub stop_reason: StepStopReason,
    /// Register state snapshot for thread `thread_id` after the step.
    pub registers: HashMap<String, u64>,
    /// Thread that was active for the last consumed event.
    pub thread_id: u32,
}

/// Reason stepping halted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepStopReason {
    /// A single event was executed.
    Stepped,
    /// A call was stepped over (landed at the instruction after the call).
    SteppedOver,
    /// Stepped out of the current function (hit a return).
    SteppedOut,
    /// Reached the end of the trace.
    EndOfTrace,
    /// The target call depth was restored (step-out complete).
    ReturnReached { return_address: u64 },
}

impl std::fmt::Display for StepStopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stepped => write!(f, "Stepped"),
            Self::SteppedOver => write!(f, "SteppedOver"),
            Self::SteppedOut => write!(f, "SteppedOut"),
            Self::EndOfTrace => write!(f, "EndOfTrace"),
            Self::ReturnReached { return_address } => {
                write!(f, "ReturnReached(ret=0x{return_address:x})")
            }
        }
    }
}

// ─── CallDepthTracker ────────────────────────────────────────────────────────

/// Tracks relative call depth during forward stepping.
///
/// The depth starts at `0`.  Each `Call` event increments it; each `Return`
/// event decrements it (with a floor of 0 to handle traces that start
/// mid-function).
#[derive(Debug, Clone, Default)]
pub struct CallDepthTracker {
    /// Per-thread call depths.
    depths: HashMap<u32, i64>,
    /// Total events seen.
    pub events_seen: u64,
}

impl CallDepthTracker {
    /// Create a new tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one event to the tracker.  Returns the updated depth for the
    /// event's thread.
    pub fn apply(&mut self, event: &TraceEvent) -> i64 {
        self.events_seen += 1;
        let depth = self.depths.entry(event.thread_id).or_insert(0);
        match &event.kind {
            EventKind::Call { .. } => *depth += 1,
            EventKind::Return { .. } => {
                *depth -= 1;
                if *depth < 0 {
                    *depth = 0;
                }
            }
            _ => {}
        }
        *depth
    }

    /// Return the current depth for `thread_id`.
    #[must_use]
    pub fn depth_for(&self, thread_id: u32) -> i64 {
        self.depths.get(&thread_id).copied().unwrap_or(0)
    }

    /// Reset the depth for all threads to `0`.
    pub fn reset(&mut self) {
        self.depths.clear();
        self.events_seen = 0;
    }

    /// Reset the depth for one thread.
    pub fn reset_thread(&mut self, tid: u32) {
        self.depths.remove(&tid);
    }
}

impl std::fmt::Display for CallDepthTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CallDepthTracker(threads={})", self.depths.len())
    }
}

// ─── ForwardStepper ───────────────────────────────────────────────────────────

/// Steps forward through a TTD trace.
///
/// # Example
/// ```no_run
/// use std::sync::Arc;
/// use rustre_ttd::{TtdTrace, TraceMetadata};
/// use rustre_ttd_replay::forward_stepper::{ForwardStepper, StepMode};
///
/// let trace = Arc::new(TtdTrace::new(TraceMetadata::default()));
/// let mut stepper = ForwardStepper::new(trace);
/// let result = stepper.step(StepMode::SingleStep);
/// ```
pub struct ForwardStepper {
    /// The trace being replayed.
    trace: Arc<TtdTrace>,
    /// Current event index.
    event_index: usize,
    /// Current trace position.
    current_pos: TracePosition,
    /// Memory state accumulated so far.
    memory: MemoryState,
    /// Per-thread register state.
    registers: HashMap<u32, HashMap<String, u64>>,
    /// Call depth tracker.
    depth_tracker: CallDepthTracker,
    /// Thread filter — if set, only events from this thread are counted for
    /// step-over/step-out operations.
    pub thread_filter: Option<u32>,
}

impl ForwardStepper {
    /// Create a new `ForwardStepper` positioned at the start of `trace`.
    #[must_use]
    pub fn new(trace: Arc<TtdTrace>) -> Self {
        Self {
            trace,
            event_index: 0,
            current_pos: TracePosition::start(),
            memory: MemoryState::new(),
            registers: HashMap::new(),
            depth_tracker: CallDepthTracker::new(),
            thread_filter: None,
        }
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

    /// Return a reference to the call-depth tracker.
    #[must_use]
    pub const fn depth_tracker(&self) -> &CallDepthTracker {
        &self.depth_tracker
    }

    /// Return the memory state.
    #[must_use]
    pub const fn memory(&self) -> &MemoryState {
        &self.memory
    }

    /// Return the register state for a thread.
    #[must_use]
    pub fn registers_for(&self, tid: u32) -> Option<&HashMap<String, u64>> {
        self.registers.get(&tid)
    }

    /// Whether the trace is exhausted.
    #[must_use]
    pub fn at_end(&self) -> bool {
        self.event_index >= self.trace.all_events().len()
    }

    /// Execute one step according to `mode`.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn step(&mut self, mode: StepMode) -> Result<StepResult, ReplayError> {
        match mode {
            StepMode::SingleStep => Ok(self.single_step()),
            StepMode::StepOver => self.step_over(),
            StepMode::StepOut => self.step_out(),
        }
    }

    // ── Single step ──────────────────────────────────────────────────────────

    fn single_step(&mut self) -> StepResult {
        let events = self.trace.all_events();
        if self.event_index >= events.len() {
            return StepResult {
                position: self.current_pos,
                events_consumed: 0,
                stop_reason: StepStopReason::EndOfTrace,
                registers: self
                    .registers
                    .get(&0)
                    .cloned()
                    .unwrap_or_default(),
                thread_id: 0,
            };
        }
        let event = events[self.event_index].clone();
        let tid = event.thread_id;
        self.apply_event(&event, &events);
        StepResult {
            position: self.current_pos,
            events_consumed: 1,
            stop_reason: StepStopReason::Stepped,
            registers: self
                .registers
                .get(&tid)
                .cloned()
                .unwrap_or_default(),
            thread_id: tid,
        }
    }

    // ── Step over ────────────────────────────────────────────────────────────

    fn step_over(&mut self) -> Result<StepResult, ReplayError> {
        let events = self.trace.all_events();
        if self.event_index >= events.len() {
            return Ok(StepResult {
                position: self.current_pos,
                events_consumed: 0,
                stop_reason: StepStopReason::EndOfTrace,
                registers: HashMap::new(),
                thread_id: 0,
            });
        }

        let current_event = &events[self.event_index];
        let tid = current_event.thread_id;
        let is_call = matches!(&current_event.kind, EventKind::Call { .. });

        if !is_call {
            // Not a call — behave like single-step.
            let event = events[self.event_index].clone();
            self.apply_event(&event, &events);
            return Ok(StepResult {
                position: self.current_pos,
                events_consumed: 1,
                stop_reason: StepStopReason::Stepped,
                registers: self.registers.get(&tid).cloned().unwrap_or_default(),
                thread_id: tid,
            });
        }

        // It is a call: step over it by consuming events until we return to
        // the same depth.
        let target_depth = self.depth_tracker.depth_for(tid); // depth before we consume the call
        let mut consumed = 0usize;

        loop {
            if self.event_index >= events.len() {
                return Ok(StepResult {
                    position: self.current_pos,
                    events_consumed: consumed,
                    stop_reason: StepStopReason::EndOfTrace,
                    registers: self.registers.get(&tid).cloned().unwrap_or_default(),
                    thread_id: tid,
                });
            }
            let ev = events[self.event_index].clone();
            let ev_tid = ev.thread_id;
            self.apply_event(&ev, &events);
            consumed += 1;

            // Only track depth for the same thread.
            if ev_tid == tid {
                let new_depth = self.depth_tracker.depth_for(tid);
                if new_depth == target_depth {
                    // We've returned from the call.
                    return Ok(StepResult {
                        position: self.current_pos,
                        events_consumed: consumed,
                        stop_reason: StepStopReason::SteppedOver,
                        registers: self.registers.get(&tid).cloned().unwrap_or_default(),
                        thread_id: tid,
                    });
                }
            }
        }
    }

    // ── Step out ─────────────────────────────────────────────────────────────

    fn step_out(&mut self) -> Result<StepResult, ReplayError> {
        let events = self.trace.all_events();
        if self.event_index >= events.len() {
            return Ok(StepResult {
                position: self.current_pos,
                events_consumed: 0,
                stop_reason: StepStopReason::EndOfTrace,
                registers: HashMap::new(),
                thread_id: 0,
            });
        }

        // Target: one depth level below the current depth.
        let current_tid = self
            .thread_filter
            .unwrap_or_else(|| events[self.event_index].thread_id);
        let current_depth = self.depth_tracker.depth_for(current_tid);
        let target_depth = (current_depth - 1).max(0);
        let mut consumed = 0usize;
        let mut return_address = 0u64;

        loop {
            if self.event_index >= events.len() {
                return Ok(StepResult {
                    position: self.current_pos,
                    events_consumed: consumed,
                    stop_reason: StepStopReason::EndOfTrace,
                    registers: self
                        .registers
                        .get(&current_tid)
                        .cloned()
                        .unwrap_or_default(),
                    thread_id: current_tid,
                });
            }
            let ev = events[self.event_index].clone();
            let ev_tid = ev.thread_id;

            // Capture return address before applying.
            if ev_tid == current_tid
                && let EventKind::Return { to, .. } = &ev.kind {
                    return_address = *to;
                }

            self.apply_event(&ev, &events);
            consumed += 1;

            if ev_tid == current_tid {
                let new_depth = self.depth_tracker.depth_for(current_tid);
                if new_depth <= target_depth {
                    return Ok(StepResult {
                        position: self.current_pos,
                        events_consumed: consumed,
                        stop_reason: StepStopReason::ReturnReached { return_address },
                        registers: self
                            .registers
                            .get(&current_tid)
                            .cloned()
                            .unwrap_or_default(),
                        thread_id: current_tid,
                    });
                }
            }
        }
    }

    // ── Run to address ───────────────────────────────────────────────────────

    /// Run forward until a Call or Return to/from `target_address` is seen, or
    /// the trace ends.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn run_to_address(&mut self, target_address: u64) -> Result<StepResult, ReplayError> {
        let events = self.trace.all_events();
        let mut consumed = 0usize;

        loop {
            if self.event_index >= events.len() {
                return Ok(StepResult {
                    position: self.current_pos,
                    events_consumed: consumed,
                    stop_reason: StepStopReason::EndOfTrace,
                    registers: HashMap::new(),
                    thread_id: 0,
                });
            }
            let ev = events[self.event_index].clone();
            let tid = ev.thread_id;
            let hit = match &ev.kind {
                EventKind::Call { to, .. } if *to == target_address => true,
                EventKind::Return { to, .. } if *to == target_address => true,
                _ => false,
            };
            self.apply_event(&ev, &events);
            consumed += 1;
            if hit {
                return Ok(StepResult {
                    position: self.current_pos,
                    events_consumed: consumed,
                    stop_reason: StepStopReason::ReturnReached {
                        return_address: target_address,
                    },
                    registers: self.registers.get(&tid).cloned().unwrap_or_default(),
                    thread_id: tid,
                });
            }
        }
    }

    /// Run to the end of the trace, consuming all events.
    pub fn run_to_end(&mut self) -> StepResult {
        let events = self.trace.all_events();
        let mut consumed = 0usize;
        let mut last_tid = 0u32;
        while self.event_index < events.len() {
            let ev = events[self.event_index].clone();
            last_tid = ev.thread_id;
            self.apply_event(&ev, &events);
            consumed += 1;
        }
        StepResult {
            position: self.current_pos,
            events_consumed: consumed,
            stop_reason: StepStopReason::EndOfTrace,
            registers: self.registers.get(&last_tid).cloned().unwrap_or_default(),
            thread_id: last_tid,
        }
    }

    // ── State application ────────────────────────────────────────────────────

    fn apply_event(&mut self, event: &TraceEvent, events: &[TraceEvent]) {
        // `position()` is where execution will RESUME — the standard debugger
        // convention — not the event just consumed. Setting it to the consumed
        // event's position made "before the trace" and "after the first event"
        // report the same value whenever the trace starts at (0,0), which is
        // every trace: `step_forward` appeared not to advance at all, and the
        // history entry for that step was skipped as a no-op.
        //
        // The two states now differ while the initial position still equals
        // `TracePosition::start()`, because that is exactly the position of the
        // first event about to run.
        self.depth_tracker.apply(event);
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
                regs.insert("r10".into(), args[3]);
                regs.insert("r8".into(), args[4]);
                regs.insert("r9".into(), args[5]);
            }
            EventKind::SyscallExit { ret, .. } => {
                regs.insert("rax".into(), *ret);
            }
            EventKind::ThreadCreate { tid } => {
                self.registers.entry(*tid).or_default();
            }
            _ => {}
        }
        self.event_index += 1;
        // Resume point: the next event, or just past the last one. The slice is
        // passed in because `TtdTrace::all_events` CLONES the whole event
        // vector — calling it once per event would be quadratic.
        self.current_pos = events
            .get(self.event_index)
            .map_or_else(|| event.position.next_sequence(), |e| e.position);
    }
}

impl std::fmt::Debug for ForwardStepper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForwardStepper")
            .field("event_index", &self.event_index)
            .field("current_pos", &self.current_pos)
            .field("threads", &self.registers.len())
            .finish_non_exhaustive()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_ttd::{TraceMetadata, TracePosition};

    fn make_trace() -> Arc<TtdTrace> {
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
            kind: EventKind::Call {
                from: 0x1000,
                to: 0x2000,
            },
        });
        trace.add_event(rustre_ttd::TraceEvent {
            position: TracePosition::new(1, 0),
            thread_id: 1,
            kind: EventKind::MemWrite {
                addr: 0x3000,
                data: vec![1, 2, 3],
            },
        });
        trace.add_event(rustre_ttd::TraceEvent {
            position: TracePosition::new(2, 0),
            thread_id: 1,
            kind: EventKind::Return {
                from: 0x2000,
                to: 0x1004,
            },
        });
        trace
    }

    #[test]
    fn single_step_advances() {
        let trace = make_trace();
        let mut stepper = ForwardStepper::new(trace);
        let r = stepper.step(StepMode::SingleStep).unwrap();
        assert_eq!(r.events_consumed, 1);
        assert_eq!(stepper.event_index(), 1);
    }

    #[test]
    fn step_over_call_consumes_call_and_return() {
        let trace = make_trace();
        let mut stepper = ForwardStepper::new(trace);
        let r = stepper.step(StepMode::StepOver).unwrap();
        // Should consume the call, the mem write, and the return.
        assert_eq!(r.events_consumed, 3);
        assert!(matches!(r.stop_reason, StepStopReason::SteppedOver));
    }

    #[test]
    fn step_out_exits_current_function() {
        let trace = make_trace();
        let mut stepper = ForwardStepper::new(trace);
        // First consume the call so we're inside the function.
        stepper.step(StepMode::SingleStep).unwrap();
        // Now step out.
        let r = stepper.step(StepMode::StepOut).unwrap();
        assert!(matches!(
            r.stop_reason,
            StepStopReason::ReturnReached { .. }
        ));
    }

    #[test]
    fn at_end_returns_end_of_trace() {
        let trace = make_trace();
        let mut stepper = ForwardStepper::new(trace);
        // Consume everything.
        stepper.run_to_end();
        let r = stepper.step(StepMode::SingleStep).unwrap();
        assert_eq!(r.stop_reason, StepStopReason::EndOfTrace);
    }

    #[test]
    fn call_depth_tracker_basic() {
        let mut t = CallDepthTracker::new();
        let call_ev = rustre_ttd::TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::Call { from: 0, to: 1 },
        };
        let depth = t.apply(&call_ev);
        assert_eq!(depth, 1);
        let ret_ev = rustre_ttd::TraceEvent {
            position: TracePosition::new(1, 0),
            thread_id: 1,
            kind: EventKind::Return { from: 1, to: 4 },
        };
        let depth = t.apply(&ret_ev);
        assert_eq!(depth, 0);
    }

    #[test]
    fn call_depth_no_underflow() {
        let mut t = CallDepthTracker::new();
        let ret_ev = rustre_ttd::TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::Return { from: 0, to: 0 },
        };
        t.apply(&ret_ev);
        assert_eq!(t.depth_for(1), 0);
    }

    #[test]
    fn memory_applied_during_step() {
        let trace = make_trace();
        let mut stepper = ForwardStepper::new(trace);
        // Step twice: call, then mem-write.
        stepper.step(StepMode::SingleStep).unwrap();
        stepper.step(StepMode::SingleStep).unwrap();
        let bytes = stepper.memory().read(0x3000, 3);
        assert_eq!(bytes, Some(vec![1, 2, 3]));
    }
}
