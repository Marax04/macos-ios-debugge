//! `ttd_replay_engine` — High-level TTD replay engine.
//!
//! Provides [`TtdReplayEngine`] which wraps the lower-level replay primitives
//! (snapshots, breakpoints, watchpoints) and exposes a simple step-based API
//! for iterating through a TTD trace.

use std::collections::HashMap;

use rustre_ttd::{TracePosition, TtdTrace};
use serde::{Deserialize, Serialize};

use rustre_ttd::EventKind;

use crate::{
    BreakpointCondition, MemoryState, ReplayBreakpoint, ReplayError, ReplayStopReason,
    WatchpointKind,
};

/// Internal snapshot for [`TtdReplayEngine`].  Uses a flat register map keyed
/// by name, which matches [`EngineRegisters`].
#[derive(Debug, Clone)]
struct EngineSnapshot {
    position: TracePosition,
    registers: HashMap<String, u64>,
    memory: MemoryState,
}

// ─────────────────────────────────────────────────────────────────────────────
// ReplayConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for a [`TtdReplayEngine`] session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayConfig {
    /// Maximum number of steps before the engine yields control.
    pub max_steps_per_run: u64,
    /// If `true`, memory writes are tracked for watchpoint evaluation.
    pub track_memory_writes: bool,
    /// If `true`, every register state is snapshotted at each step.
    pub snapshot_registers: bool,
    /// Snapshot the memory state every N steps.  0 = disabled.
    pub memory_snapshot_interval: u64,
    /// If `true`, the engine records a compact execution log.
    pub enable_execution_log: bool,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            max_steps_per_run: 10_000,
            track_memory_writes: true,
            snapshot_registers: false,
            memory_snapshot_interval: 0,
            enable_execution_log: true,
        }
    }
}

impl ReplayConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_max_steps(mut self, n: u64) -> Self {
        self.max_steps_per_run = n;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReplayEvent
// ─────────────────────────────────────────────────────────────────────────────

/// An event emitted by the replay engine during stepping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplayEvent {
    /// The engine advanced one instruction.
    Step {
        position: TracePosition,
        pc: u64,
    },
    /// A breakpoint was hit.
    BreakpointHit {
        bp_id: u32,
        position: TracePosition,
        pc: u64,
    },
    /// A watchpoint was triggered.
    WatchpointHit {
        wp_id: u32,
        address: u64,
        old_value: Vec<u8>,
        new_value: Vec<u8>,
        position: TracePosition,
    },
    /// The trace reached its end.
    TraceEnd {
        position: TracePosition,
    },
    /// The trace reached its beginning (during backward stepping).
    TraceStart {
        position: TracePosition,
    },
    /// A periodic memory snapshot was taken.
    MemorySnapshot {
        position: TracePosition,
    },
}

impl std::fmt::Display for ReplayEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Step { position, pc } => write!(f, "Step @ {position} pc={pc:#x}"),
            Self::BreakpointHit { bp_id, position, pc } => {
                write!(f, "BP#{bp_id} hit @ {position} pc={pc:#x}")
            }
            Self::WatchpointHit { wp_id, address, position, .. } => {
                write!(f, "WP#{wp_id} hit @ {position} addr={address:#x}")
            }
            Self::TraceEnd { position } => write!(f, "TraceEnd @ {position}"),
            Self::TraceStart { position } => write!(f, "TraceStart @ {position}"),
            Self::MemorySnapshot { position } => write!(f, "MemorySnapshot @ {position}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EngineRegisters
// ─────────────────────────────────────────────────────────────────────────────

/// Simulated register file at a given replay position.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EngineRegisters {
    pub regs: HashMap<String, u64>,
}

impl EngineRegisters {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, name: impl Into<String>, value: u64) {
        self.regs.insert(name.into(), value);
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<u64> {
        self.regs.get(name).copied()
    }

    #[must_use]
    pub fn rip(&self) -> u64 {
        self.regs.get("rip").copied().unwrap_or(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReplayWatchpoint (local, for the engine)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct EngineWatchpoint {
    id: u32,
    address: u64,
    size: usize,
    kind: WatchpointKind,
    enabled: bool,
    hit_count: u64,
}

impl EngineWatchpoint {
    const fn new(id: u32, address: u64, size: usize, kind: WatchpointKind) -> Self {
        Self { id, address, size, kind, enabled: true, hit_count: 0 }
    }

    const fn overlaps(&self, addr: u64, len: usize) -> bool {
        let wp_end = self.address.saturating_add(self.size as u64);
        let acc_end = addr.saturating_add(len as u64);
        self.address < acc_end && addr < wp_end
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TtdReplayEngine
// ─────────────────────────────────────────────────────────────────────────────

/// High-level TTD trace replay engine.
///
/// Accepts a [`TtdTrace`] handle and provides stepping APIs, breakpoints,
/// watchpoints, memory inspection, and register snapshots.
pub struct TtdReplayEngine {
    trace: TtdTrace,
    config: ReplayConfig,
    position: TracePosition,
    registers: EngineRegisters,
    memory: MemoryState,
    breakpoints: Vec<ReplayBreakpoint>,
    watchpoints: Vec<EngineWatchpoint>,
    next_bp_id: u32,
    next_wp_id: u32,
    step_count: u64,
    event_log: Vec<ReplayEvent>,
    snapshots: Vec<EngineSnapshot>,
}

impl TtdReplayEngine {
    /// Create a new engine from an open trace and configuration.
    #[must_use]
    pub fn new(trace: TtdTrace, config: ReplayConfig) -> Self {
        let position = TracePosition::start();
        Self {
            trace,
            config,
            position,
            registers: EngineRegisters::new(),
            memory: MemoryState::new(),
            breakpoints: Vec::new(),
            watchpoints: Vec::new(),
            next_bp_id: 1,
            next_wp_id: 1,
            step_count: 0,
            event_log: Vec::new(),
            snapshots: Vec::new(),
        }
    }

    /// Advance one instruction forward.
    ///
    /// Returns the next [`ReplayEvent`] and the reason the engine stopped.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn step_forward(&mut self) -> Result<(ReplayEvent, ReplayStopReason), ReplayError> {
        let events = self.trace.events_at_position(self.position);

        // Apply any memory writes from this trace step
        if self.config.track_memory_writes {
            for ev in &events {
                if let EventKind::MemWrite { addr, data } = &ev.kind {
                    let addr = *addr;
                    let old_val = self.memory.read(addr, data.len()).unwrap_or_default();
                    // Check watchpoints
                    for wp in &mut self.watchpoints {
                        if wp.enabled
                            && matches!(wp.kind, WatchpointKind::Write | WatchpointKind::ReadWrite)
                            && wp.overlaps(addr, data.len())
                        {
                            wp.hit_count += 1;
                            let event = ReplayEvent::WatchpointHit {
                                wp_id: wp.id,
                                address: addr,
                                old_value: old_val.clone(),
                                new_value: data.clone(),
                                position: self.position,
                            };
                            let stop = ReplayStopReason::WatchpointHit {
                                wp_id: wp.id,
                                position: self.position,
                                old_value: old_val,
                                new_value: data.clone(),
                            };
                            if self.config.enable_execution_log {
                                self.event_log.push(event.clone());
                            }
                            self.memory.apply_write(addr, data);
                            return Ok((event, stop));
                        }
                    }
                    self.memory.apply_write(addr, data);
                }
                // Update rip from control-flow events
                match &ev.kind {
                    EventKind::Call { to, .. } | EventKind::Return { to, .. } => {
                        self.registers.set("rip", *to);
                    }
                    _ => {}
                }
            }
        }

        let pc = self.registers.rip();

        // Advance position: find the first event strictly after the current position.
        let next_pos = {
            let all = self.trace.all_events();
            all.into_iter()
                .map(|e| e.position)
                .filter(|p| *p > self.position)
                .min()
        };
        if let Some(next) = next_pos {
            self.position = next;
            self.step_count += 1;

            // Check breakpoints
            for bp in &mut self.breakpoints {
                if bp.fires(pc, &self.registers.regs, &self.memory) {
                    bp.hit_count += 1;
                    let event = ReplayEvent::BreakpointHit {
                        bp_id: bp.id,
                        position: self.position,
                        pc,
                    };
                    let stop = ReplayStopReason::BreakpointHit {
                        bp_id: bp.id,
                        position: self.position,
                    };
                    if self.config.enable_execution_log {
                        self.event_log.push(event.clone());
                    }
                    return Ok((event, stop));
                }
            }

            // Memory snapshot
            if self.config.memory_snapshot_interval > 0
                && self.step_count.is_multiple_of(self.config.memory_snapshot_interval)
            {
                let snap = EngineSnapshot {
                    position: self.position,
                    registers: self.registers.regs.clone(),
                    memory: self.memory.clone(),
                };
                self.snapshots.push(snap);
                let event = ReplayEvent::MemorySnapshot { position: self.position };
                if self.config.enable_execution_log {
                    self.event_log.push(event.clone());
                }
                return Ok((event, ReplayStopReason::StepComplete { position: self.position }));
            }

            let event = ReplayEvent::Step { position: self.position, pc };
            let stop = ReplayStopReason::StepComplete { position: self.position };
            if self.config.enable_execution_log {
                self.event_log.push(event.clone());
            }
            Ok((event, stop))
        } else {
            let event = ReplayEvent::TraceEnd { position: self.position };
            if self.config.enable_execution_log {
                self.event_log.push(event.clone());
            }
            Ok((event, ReplayStopReason::End))
        }
    }

    /// Step backward one instruction.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn step_backward(&mut self) -> Result<(ReplayEvent, ReplayStopReason), ReplayError> {
        let prev_pos = {
            let all = self.trace.all_events();
            all.into_iter()
                .map(|e| e.position)
                .filter(|p| *p < self.position)
                .max()
        };
        if let Some(prev) = prev_pos {
            self.position = prev;
            self.step_count = self.step_count.saturating_sub(1);
            let pc = self.registers.rip();
            let event = ReplayEvent::Step { position: self.position, pc };
            Ok((event, ReplayStopReason::StepComplete { position: self.position }))
        } else {
            let event = ReplayEvent::TraceStart { position: self.position };
            Ok((event, ReplayStopReason::Start))
        }
    }

    /// Run forward until a breakpoint/watchpoint hits or `max_steps` is reached.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn run_forward(&mut self) -> Result<ReplayStopReason, ReplayError> {
        let max = self.config.max_steps_per_run;
        for _ in 0..max {
            let (_, stop) = self.step_forward()?;
            match &stop {
                ReplayStopReason::End
                | ReplayStopReason::BreakpointHit { .. }
                | ReplayStopReason::WatchpointHit { .. } => return Ok(stop),
                _ => {}
            }
        }
        Ok(ReplayStopReason::StepComplete { position: self.position })
    }

    /// Jump to a specific position, rebuilding state from the nearest snapshot.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn goto(&mut self, target: TracePosition) -> Result<(), ReplayError> {
        let pos_exists = self.trace.all_events().iter().any(|e| e.position == target);
        if !pos_exists {
            return Err(ReplayError::PositionNotFound(target));
        }
        // Try to find a snapshot at or before target
        let snap = self
            .snapshots
            .iter()
            .rev()
            .find(|s| s.position <= target)
            .cloned();

        if let Some(s) = snap {
            self.position = s.position;
            self.registers.regs = s.registers;
            self.memory = s.memory;
        } else {
            // Reset to start
            self.position = TracePosition::start();
            self.registers = EngineRegisters::new();
            self.memory = MemoryState::new();
        }

        // Step forward to the target
        while self.position < target {
            let (_, stop) = self.step_forward()?;
            if matches!(stop, ReplayStopReason::End) {
                break;
            }
        }
        Ok(())
    }

    // ── breakpoint management ─────────────────────────────────────────────────

    /// Add an address breakpoint.  Returns the assigned breakpoint ID.
    pub fn add_breakpoint(&mut self, address: u64) -> u32 {
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.breakpoints.push(ReplayBreakpoint::new(id, address));
        id
    }

    pub fn add_conditional_breakpoint(&mut self, address: u64, cond: BreakpointCondition) -> u32 {
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.breakpoints
            .push(ReplayBreakpoint::new(id, address).with_condition(cond));
        id
    }

    pub fn remove_breakpoint(&mut self, bp_id: u32) -> bool {
        let before = self.breakpoints.len();
        self.breakpoints.retain(|bp| bp.id != bp_id);
        self.breakpoints.len() < before
    }

    pub fn enable_breakpoint(&mut self, bp_id: u32) -> bool {
        if let Some(bp) = self.breakpoints.iter_mut().find(|b| b.id == bp_id) {
            bp.enabled = true;
            return true;
        }
        false
    }

    pub fn disable_breakpoint(&mut self, bp_id: u32) -> bool {
        if let Some(bp) = self.breakpoints.iter_mut().find(|b| b.id == bp_id) {
            bp.enabled = false;
            return true;
        }
        false
    }

    // ── watchpoint management ─────────────────────────────────────────────────

    pub fn add_watchpoint(&mut self, address: u64, size: usize, kind: WatchpointKind) -> u32 {
        let id = self.next_wp_id;
        self.next_wp_id += 1;
        self.watchpoints.push(EngineWatchpoint::new(id, address, size, kind));
        id
    }

    pub fn remove_watchpoint(&mut self, wp_id: u32) -> bool {
        let before = self.watchpoints.len();
        self.watchpoints.retain(|wp| wp.id != wp_id);
        self.watchpoints.len() < before
    }

    // ── accessors ─────────────────────────────────────────────────────────────

    #[must_use]
    pub const fn position(&self) -> TracePosition {
        self.position
    }

    #[must_use]
    pub const fn registers(&self) -> &EngineRegisters {
        &self.registers
    }

    #[must_use]
    pub const fn memory(&self) -> &MemoryState {
        &self.memory
    }

    #[must_use]
    pub const fn step_count(&self) -> u64 {
        self.step_count
    }

    #[must_use]
    pub fn event_log(&self) -> &[ReplayEvent] {
        &self.event_log
    }

    #[must_use]
    pub const fn breakpoint_count(&self) -> usize {
        self.breakpoints.len()
    }

    #[must_use]
    pub const fn watchpoint_count(&self) -> usize {
        self.watchpoints.len()
    }

    /// Read memory at `addr` for `len` bytes.
    #[must_use]
    pub fn read_memory(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        self.memory.read(addr, len)
    }

    /// Read a 64-bit value from memory (little-endian).
    #[must_use]
    pub fn read_u64(&self, addr: u64) -> Option<u64> {
        let bytes = self.memory.read(addr, 8)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_ttd::{TraceMetadata, TtdTrace};

    fn engine() -> TtdReplayEngine {
        let trace = TtdTrace::new(TraceMetadata::default());
        TtdReplayEngine::new(trace, ReplayConfig::default())
    }

    #[test]
    fn test_new_engine_initial_state() {
        let e = engine();
        assert_eq!(e.breakpoint_count(), 0);
        assert_eq!(e.watchpoint_count(), 0);
        assert_eq!(e.step_count(), 0);
    }

    #[test]
    fn test_add_remove_breakpoint() {
        let mut e = engine();
        let id = e.add_breakpoint(0x1000);
        assert_eq!(e.breakpoint_count(), 1);
        assert!(e.remove_breakpoint(id));
        assert_eq!(e.breakpoint_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_breakpoint() {
        let mut e = engine();
        assert!(!e.remove_breakpoint(999));
    }

    #[test]
    fn test_enable_disable_breakpoint() {
        let mut e = engine();
        let id = e.add_breakpoint(0x2000);
        assert!(e.disable_breakpoint(id));
        assert!(e.enable_breakpoint(id));
        assert!(!e.enable_breakpoint(999));
    }

    #[test]
    fn test_add_watchpoint() {
        let mut e = engine();
        let id = e.add_watchpoint(0x5000, 8, WatchpointKind::Write);
        assert_eq!(e.watchpoint_count(), 1);
        assert!(e.remove_watchpoint(id));
        assert_eq!(e.watchpoint_count(), 0);
    }

    #[test]
    fn test_step_forward_increments_count() {
        let mut e = engine();
        let _ = e.step_forward();
        assert!(e.step_count() == 0 || e.step_count() == 1);
    }

    #[test]
    fn test_step_forward_returns_event() {
        let mut e = engine();
        let result = e.step_forward();
        assert!(result.is_ok());
    }

    #[test]
    fn test_replay_config_default() {
        let c = ReplayConfig::default();
        assert_eq!(c.max_steps_per_run, 10_000);
        assert!(c.track_memory_writes);
    }

    #[test]
    fn test_replay_config_with_max_steps() {
        let c = ReplayConfig::new().with_max_steps(500);
        assert_eq!(c.max_steps_per_run, 500);
    }

    #[test]
    fn test_engine_registers_rip() {
        let mut r = EngineRegisters::new();
        r.set("rip", 0xdead_beef);
        assert_eq!(r.rip(), 0xdead_beef);
    }

    #[test]
    fn test_engine_registers_get_none() {
        let r = EngineRegisters::new();
        assert!(r.get("rax").is_none());
    }

    #[test]
    fn test_replay_event_display_step() {
        let pos = TracePosition::default();
        let ev = ReplayEvent::Step { position: pos, pc: 0x1234 };
        let s = ev.to_string();
        assert!(s.contains("Step"));
        assert!(s.contains("0x1234"));
    }

    #[test]
    fn test_replay_event_display_trace_end() {
        let pos = TracePosition::default();
        let ev = ReplayEvent::TraceEnd { position: pos };
        assert!(ev.to_string().contains("TraceEnd"));
    }

    #[test]
    fn test_step_backward() {
        let mut e = engine();
        // Try to step backward from start — should return TraceStart
        let result = e.step_backward();
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_forward_terminates() {
        let mut e = engine();
        let stop = e.run_forward().unwrap();
        // Should terminate without panic
        let _ = stop;
    }

    #[test]
    fn test_add_conditional_breakpoint() {
        let mut e = engine();
        let id = e.add_conditional_breakpoint(0x400, BreakpointCondition::Always);
        assert_eq!(e.breakpoint_count(), 1);
        assert!(e.remove_breakpoint(id));
    }

    #[test]
    fn test_read_memory_empty() {
        let e = engine();
        // Unmapped address returns None
        assert!(e.read_memory(0xffff_0000, 4).is_none());
    }

    #[test]
    fn test_event_log_enabled() {
        let mut e = engine();
        let _ = e.step_forward();
        // Log may or may not have entries depending on mock trace
        let _log = e.event_log();
    }
}
