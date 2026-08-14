//! `rustre-ttd-replay::replay_engine`
//!
//! Trait-based replay engine abstraction and a concrete in-process implementation.
//!
//! # Design
//! [`ReplayEngine`] (trait) defines the minimum navigation surface:
//! forward/backward single stepping, run-to-position, run-to-breakpoint,
//! run-to-memory-write.  [`InProcessReplay`] implements it over an
//! in-memory [`TtdTrace`] with an integrated snapshot cache for efficient
//! backward navigation.
//!
//! The separation allows plugging in future implementations backed by an
//! out-of-process `WinDbg` TTD engine, a Unicorn emulator, or a remote gRPC
//! service without changing callers.

use std::collections::HashMap;
use std::sync::Arc;

use rustre_ttd::{EventKind, TraceEvent, TracePosition, TtdTrace};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{MemoryState, Snapshot, SnapshotCache, WatchpointKind};

// ─── EngineError ─────────────────────────────────────────────────────────────

/// Errors specific to the engine module (additional to `crate::ReplayError`).
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("position not found: {0}")]
    PositionNotFound(TracePosition),

    #[error("no snapshot available before {0}")]
    NoSnapshot(TracePosition),

    #[error("invalid state: {0}")]
    InvalidState(String),

    #[error("emulation backend error: {0}")]
    BackendError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ─── StepDirection ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepDirection {
    Forward,
    Backward,
}

impl std::fmt::Display for StepDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forward => write!(f, "forward"),
            Self::Backward => write!(f, "backward"),
        }
    }
}

// ─── EngineStopReason ─────────────────────────────────────────────────────────

/// Why the engine stopped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EngineStopReason {
    /// A single step completed.
    StepComplete { position: TracePosition },
    /// A breakpoint was hit (by address).
    BreakpointHit {
        address: u64,
        position: TracePosition,
    },
    /// A memory-write watchpoint fired.
    MemoryWrite {
        address: u64,
        size: usize,
        old_value: Vec<u8>,
        new_value: Vec<u8>,
        position: TracePosition,
    },
    /// A memory-read watchpoint fired.
    MemoryRead {
        address: u64,
        size: usize,
        position: TracePosition,
    },
    /// Reached the end of the trace.
    TraceEnd,
    /// Reached the start of the trace (during backward replay).
    TraceStart,
    /// A user condition evaluated to true.
    ConditionMet {
        position: TracePosition,
        description: String,
    },
}

impl std::fmt::Display for EngineStopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StepComplete { position } => write!(f, "StepComplete @ {position}"),
            Self::BreakpointHit { address, position } => {
                write!(f, "BreakpointHit @ {address:#x} ({position})")
            }
            Self::MemoryWrite {
                address,
                size,
                position,
                ..
            } => write!(f, "MemoryWrite @ {address:#x}+{size} ({position})"),
            Self::MemoryRead {
                address,
                size,
                position,
            } => write!(f, "MemoryRead @ {address:#x}+{size} ({position})"),
            Self::TraceEnd => write!(f, "TraceEnd"),
            Self::TraceStart => write!(f, "TraceStart"),
            Self::ConditionMet {
                position,
                description,
            } => write!(f, "ConditionMet({description}) @ {position}"),
        }
    }
}

// ─── ReplayPosition ───────────────────────────────────────────────────────────

/// The full observable state at a given trace position.
#[derive(Debug, Clone)]
pub struct ReplayPosition {
    pub position: TracePosition,
    pub registers: HashMap<u32, HashMap<String, u64>>,
    pub memory: MemoryState,
    pub active_threads: Vec<u32>,
}

impl ReplayPosition {
    /// Return the register file for `tid`, if any.
    #[must_use]
    pub fn thread_registers(&self, tid: u32) -> Option<&HashMap<String, u64>> {
        self.registers.get(&tid)
    }

    /// Read a named register for `tid`.
    #[must_use]
    pub fn reg(&self, tid: u32, name: &str) -> Option<u64> {
        self.registers.get(&tid)?.get(name).copied()
    }
}

// ─── ReplayEngine trait ───────────────────────────────────────────────────────

/// Abstract replay engine interface.
pub trait ReplayEngine: Send + Sync {
    /// Current position in the trace.
    fn current_position(&self) -> TracePosition;

    /// Step one event in `dir`.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    fn step(&mut self, dir: StepDirection) -> Result<EngineStopReason, EngineError>;

    /// Run until a breakpoint, watchpoint or end/start.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    fn run(&mut self, dir: StepDirection) -> Result<EngineStopReason, EngineError>;

    /// Jump to a specific position (may replay from scratch or use snapshots).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    fn goto(&mut self, pos: TracePosition) -> Result<(), EngineError>;

    /// Get the full observable state at the current position.
    fn get_state(&self) -> ReplayPosition;

    /// Read memory at the current position.
    fn read_memory(&self, addr: u64, len: usize) -> Option<Vec<u8>>;

    /// Read a register at the current position for `tid`.
    fn read_register(&self, tid: u32, name: &str) -> Option<u64>;

    /// Set an address breakpoint.  Returns breakpoint ID.
    fn set_breakpoint(&mut self, addr: u64) -> u32;

    /// Remove a breakpoint by ID.
    fn remove_breakpoint(&mut self, id: u32) -> bool;

    /// Set a memory watchpoint.  Returns watchpoint ID.
    fn set_watchpoint(&mut self, addr: u64, size: usize, kind: WatchpointKind) -> u32;

    /// Remove a watchpoint by ID.
    fn remove_watchpoint(&mut self, id: u32) -> bool;

    /// Rewind to the very start of the trace.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    fn go_to_start(&mut self) -> Result<(), EngineError>;

    /// Fast-forward to the very end of the trace.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    fn go_to_end(&mut self) -> Result<(), EngineError>;

    /// Run forward until the next write to `addr`.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    fn run_to_memory_write(
        &mut self,
        addr: u64,
        size: usize,
    ) -> Result<EngineStopReason, EngineError>;

    /// Run backward until the previous write to `addr`.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    fn run_backward_to_memory_write(
        &mut self,
        addr: u64,
        size: usize,
    ) -> Result<EngineStopReason, EngineError>;

    /// Run forward until any event matching `pred`.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    fn run_to_event<F>(&mut self, pred: F) -> Result<EngineStopReason, EngineError>
    where
        F: Fn(&TraceEvent) -> bool + Send + Sync;
}

// ─── InProcessReplay ─────────────────────────────────────────────────────────

/// Concrete in-process replay engine backed by an in-memory [`TtdTrace`].
pub struct InProcessReplay {
    trace: Arc<TtdTrace>,
    event_index: usize,
    current_pos: TracePosition,
    memory: MemoryState,
    registers: HashMap<u32, HashMap<String, u64>>,
    active_threads: Vec<u32>,
    snapshot_cache: SnapshotCache,
    breakpoints: Vec<(u32, u64)>,                        // (id, addr)
    watchpoints: Vec<(u32, u64, usize, WatchpointKind)>, // (id, addr, size, kind)
    next_bp_id: u32,
    next_wp_id: u32,
}

/// Hit returned by `check_write_watchpoints`: `(id, addr, size, old, new)`.
pub type WriteWatchHit = (u32, u64, usize, Vec<u8>, Vec<u8>);

impl InProcessReplay {
    /// Create with default snapshot interval (every 500 events).
    pub fn new(trace: Arc<TtdTrace>) -> Self {
        Self::with_snapshot_interval(trace, 500)
    }

    /// Create with a custom snapshot interval.
    pub fn with_snapshot_interval(trace: Arc<TtdTrace>, interval: u64) -> Self {
        Self {
            trace,
            event_index: 0,
            current_pos: TracePosition::start(),
            memory: MemoryState::new(),
            registers: HashMap::new(),
            active_threads: Vec::new(),
            snapshot_cache: SnapshotCache::new(interval),
            breakpoints: Vec::new(),
            watchpoints: Vec::new(),
            next_bp_id: 1,
            next_wp_id: 1,
        }
    }

    // ── private helpers ───────────────────────────────────────────────────────

    fn apply(&mut self, event: &TraceEvent) {
        self.current_pos = event.position;
        let regs = self.registers.entry(event.thread_id).or_default();
        match &event.kind {
            EventKind::MemWrite { addr, data } => self.memory.apply_write(*addr, data),
            EventKind::Call { to, from } => {
                regs.insert("rip".into(), *to);
                regs.insert("call_from".into(), *from);
            }
            EventKind::Return { to, .. } => {
                regs.insert("rip".into(), *to);
            }
            EventKind::SyscallEnter { nr, args } => {
                regs.insert("rax".into(), u64::from(*nr));
                for (i, &v) in args.iter().enumerate() {
                    let name = ["rdi", "rsi", "rdx", "r10", "r8", "r9"][i];
                    regs.insert(name.into(), v);
                }
            }
            EventKind::SyscallExit { ret, .. } => {
                regs.insert("rax".into(), *ret);
            }
            EventKind::ThreadCreate { tid } => {
                self.registers.entry(*tid).or_default();
                if !self.active_threads.contains(tid) {
                    self.active_threads.push(*tid);
                }
            }
            EventKind::ThreadExit { tid, .. } => {
                self.active_threads.retain(|&t| t != *tid);
            }
            EventKind::MemRead { .. }
            | EventKind::Exception { .. }
            | EventKind::Breakpoint { .. } => {}
        }
    }

    fn maybe_snapshot(&mut self, idx: usize) {
        let interval = self.snapshot_cache.interval;
        if interval > 0
            && (idx as u64).is_multiple_of(interval)
            && !self.snapshot_cache.contains(self.current_pos)
        {
            self.snapshot_cache.insert(Snapshot::new(
                self.current_pos,
                self.memory.clone(),
                self.registers.clone(),
            ));
        }
    }

    fn restore_to_start(&mut self) {
        self.event_index = 0;
        self.current_pos = TracePosition::start();
        self.memory = MemoryState::new();
        self.registers = HashMap::new();
        self.active_threads.clear();
    }

    fn index_of(&self, pos: TracePosition) -> Option<usize> {
        self.trace
            .all_events()
            .iter()
            .position(|e| e.position == pos)
    }

    fn replay_range(&mut self, from: usize, to: usize, events: &[TraceEvent]) {
        let mut i = from;
        while i <= to && i < events.len() {
            self.apply(&events[i]);
            self.maybe_snapshot(i);
            i += 1;
        }
        self.event_index = i;
    }

    fn check_write_watchpoints(
        &self,
        addr: u64,
        data: &[u8],
    ) -> Option<WriteWatchHit> {
        for &(id, wa, ws, ref kind) in &self.watchpoints {
            if matches!(kind, WatchpointKind::Read) {
                continue;
            }
            let wa_end = wa.saturating_add(ws as u64);
            let target_end = addr.saturating_add(data.len() as u64);
            if wa < target_end && addr < wa_end {
                let old = self.memory.read(wa, ws).unwrap_or_default();
                return Some((id, addr, data.len(), old, data.to_vec()));
            }
        }
        None
    }

    fn check_read_watchpoints(&self, addr: u64, len: usize) -> Option<(u32, u64, usize)> {
        for &(id, wa, ws, ref kind) in &self.watchpoints {
            if matches!(kind, WatchpointKind::Write) {
                continue;
            }
            let wa_end = wa.saturating_add(ws as u64);
            let target_end = addr.saturating_add(len as u64);
            if wa < target_end && addr < wa_end {
                return Some((id, addr, len));
            }
        }
        None
    }

    fn check_address_breakpoints(&self, event: &TraceEvent) -> Option<u64> {
        let addr = match &event.kind {
            EventKind::Call { to, .. } | EventKind::Return { to, .. } => *to,
            EventKind::Breakpoint { addr } => *addr,
            _ => return None,
        };
        for &(_, ba) in &self.breakpoints {
            if ba == addr {
                return Some(addr);
            }
        }
        None
    }

    /// Restore from the nearest snapshot and replay up to `target_idx`.
    /// Read `size` bytes at `addr` as they existed just *before* `target_idx` was applied.
    /// Replays the trace up to (but not including) `target_idx` in a temporary state.
    fn memory_read_at_idx(addr: u64, size: usize, target_idx: usize, events: &[TraceEvent]) -> Vec<u8> {
        let mut tmp = MemoryState::new();
        for e in events.iter().take(target_idx) {
            if let EventKind::MemWrite { addr: wa, data } = &e.kind {
                tmp.apply_write(*wa, data);
            }
        }
        tmp.read(addr, size).unwrap_or_default()
    }

    fn restore_and_replay(&mut self, target_idx: usize, events: &[TraceEvent]) {
        let target_pos = events[target_idx].position;
        if let Some(snap) = self.snapshot_cache.nearest_before(target_pos).cloned()
            && let Some(snap_idx) = self.index_of(snap.position)
        {
            self.current_pos = snap.position;
            self.memory = snap.memory;
            self.registers = snap.registers;
            self.event_index = snap_idx + 1;
            if self.event_index <= target_idx {
                self.replay_range(self.event_index, target_idx, events);
            }
            return;
        }
        // Fall back to replaying from scratch.
        self.restore_to_start();
        self.replay_range(0, target_idx, events);
    }

    /// Build the snapshot index by replaying the entire trace once.
    pub fn build_snapshot_index(&mut self) {
        let interval = self.snapshot_cache.interval;
        if interval == 0 {
            return;
        }
        let events = self.trace.all_events();
        let saved_pos = self.current_pos;
        let saved_idx = self.event_index;
        let saved_mem = self.memory.clone();
        let saved_regs = self.registers.clone();
        let saved_threads = self.active_threads.clone();

        self.restore_to_start();
        for (i, event) in events.iter().enumerate() {
            self.apply(event);
            if (i as u64 + 1).is_multiple_of(interval) {
                self.snapshot_cache.insert(Snapshot::new(
                    self.current_pos,
                    self.memory.clone(),
                    self.registers.clone(),
                ));
            }
        }

        self.current_pos = saved_pos;
        self.event_index = saved_idx;
        self.memory = saved_mem;
        self.registers = saved_regs;
        self.active_threads = saved_threads;
    }

    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.snapshot_cache.snapshot_count()
    }
    #[must_use]
    pub const fn event_index(&self) -> usize {
        self.event_index
    }
    #[must_use]
    pub fn total_events(&self) -> usize {
        self.trace.event_count()
    }
}

// ─── impl ReplayEngine ────────────────────────────────────────────────────────

impl ReplayEngine for InProcessReplay {
    fn current_position(&self) -> TracePosition {
        self.current_pos
    }

    fn step(&mut self, dir: StepDirection) -> Result<EngineStopReason, EngineError> {
        match dir {
            StepDirection::Forward => {
                let events = self.trace.all_events();
                if self.event_index >= events.len() {
                    return Ok(EngineStopReason::TraceEnd);
                }
                let event = events[self.event_index].clone();

                // Check watchpoints before applying
                if let EventKind::MemWrite { addr, data } = &event.kind
                    && let Some((_, wa, ws, old, new_val)) =
                        self.check_write_watchpoints(*addr, data)
                {
                    self.apply(&event);
                    self.maybe_snapshot(self.event_index);
                    self.event_index += 1;
                    return Ok(EngineStopReason::MemoryWrite {
                        address: wa,
                        size: ws,
                        old_value: old,
                        new_value: new_val,
                        position: self.current_pos,
                    });
                }
                if let EventKind::MemRead { addr, len } = &event.kind
                    && let Some((_, wa, ws)) = self.check_read_watchpoints(*addr, *len)
                {
                    self.apply(&event);
                    self.maybe_snapshot(self.event_index);
                    self.event_index += 1;
                    return Ok(EngineStopReason::MemoryRead {
                        address: wa,
                        size: ws,
                        position: self.current_pos,
                    });
                }

                self.apply(&event);
                self.maybe_snapshot(self.event_index);
                self.event_index += 1;

                if let Some(addr) = self.check_address_breakpoints(&event) {
                    return Ok(EngineStopReason::BreakpointHit {
                        address: addr,
                        position: self.current_pos,
                    });
                }
                Ok(EngineStopReason::StepComplete {
                    position: self.current_pos,
                })
            }
            StepDirection::Backward => {
                if self.event_index == 0 {
                    return Ok(EngineStopReason::TraceStart);
                }
                if self.event_index == 1 {
                    self.restore_to_start();
                    return Ok(EngineStopReason::TraceStart);
                }
                let target_idx = self.event_index.saturating_sub(2);
                let events = self.trace.all_events();
                self.restore_and_replay(target_idx, &events);
                Ok(EngineStopReason::StepComplete {
                    position: self.current_pos,
                })
            }
        }
    }

    fn run(&mut self, dir: StepDirection) -> Result<EngineStopReason, EngineError> {
        match dir {
            StepDirection::Forward => loop {
                let r = self.step(StepDirection::Forward)?;
                match &r {
                    EngineStopReason::TraceEnd
                    | EngineStopReason::BreakpointHit { .. }
                    | EngineStopReason::MemoryWrite { .. }
                    | EngineStopReason::MemoryRead { .. } => return Ok(r),
                    _ => {}
                }
            },
            StepDirection::Backward => {
                // Scan backward for the last breakpoint or watchpoint hit before current position.
                enum BackwardHit {
                    Breakpoint(u64, usize),
                    MemWrite { addr: u64, size: usize, target_idx: usize },
                }

                let events = self.trace.all_events();
                let start_idx = self.event_index.saturating_sub(1);
                let mut found: Option<BackwardHit> = None;

                'scan: for scan_idx in (0..start_idx).rev() {
                    let e = &events[scan_idx];
                    match &e.kind {
                        EventKind::MemWrite { addr, data } => {
                            for &(_, wa, ws, ref kind) in &self.watchpoints {
                                if matches!(kind, WatchpointKind::Read) {
                                    continue;
                                }
                                let wa_end = wa.saturating_add(ws as u64);
                                let target_end = addr.saturating_add(data.len() as u64);
                                if wa < target_end && *addr < wa_end {
                                    found = Some(BackwardHit::MemWrite {
                                        addr: *addr,
                                        size: data.len(),
                                        target_idx: scan_idx,
                                    });
                                    break 'scan;
                                }
                            }
                        }
                        EventKind::Call { to, .. } | EventKind::Return { to, .. } => {
                            for &(_, ba) in &self.breakpoints {
                                if ba == *to {
                                    found = Some(BackwardHit::Breakpoint(*to, scan_idx));
                                    break 'scan;
                                }
                            }
                        }
                        EventKind::Breakpoint { addr } => {
                            for &(_, ba) in &self.breakpoints {
                                if ba == *addr {
                                    found = Some(BackwardHit::Breakpoint(*addr, scan_idx));
                                    break 'scan;
                                }
                            }
                        }
                        _ => {}
                    }
                }

                match found {
                    Some(BackwardHit::Breakpoint(addr, target_idx)) => {
                        self.restore_and_replay(target_idx, &events);
                        let pos = self.current_pos;
                        return Ok(EngineStopReason::BreakpointHit {
                            address: addr,
                            position: pos,
                        });
                    }
                    Some(BackwardHit::MemWrite { addr, size, target_idx }) => {
                        // Capture old value before replaying to that position.
                        let old_value = Self::memory_read_at_idx(addr, size, target_idx, &events);
                        self.restore_and_replay(target_idx, &events);
                        // Capture new value from the event itself.
                        let new_value = if let EventKind::MemWrite { data, .. } = &events[target_idx].kind {
                            data.clone()
                        } else {
                            vec![]
                        };
                        let pos = self.current_pos;
                        return Ok(EngineStopReason::MemoryWrite {
                            address: addr,
                            size,
                            old_value,
                            new_value,
                            position: pos,
                        });
                    }
                    None => {}
                }
                self.restore_to_start();
                Ok(EngineStopReason::TraceStart)
            }
        }
    }

    fn goto(&mut self, pos: TracePosition) -> Result<(), EngineError> {
        let events = self.trace.all_events();
        let target_idx = events
            .iter()
            .position(|e| e.position == pos)
            .ok_or(EngineError::PositionNotFound(pos))?;
        self.restore_and_replay(target_idx, &events);
        Ok(())
    }

    fn get_state(&self) -> ReplayPosition {
        ReplayPosition {
            position: self.current_pos,
            registers: self.registers.clone(),
            memory: self.memory.clone(),
            active_threads: self.active_threads.clone(),
        }
    }

    fn read_memory(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        self.memory.read(addr, len)
    }

    fn read_register(&self, tid: u32, name: &str) -> Option<u64> {
        self.registers.get(&tid)?.get(name).copied()
    }

    fn set_breakpoint(&mut self, addr: u64) -> u32 {
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.breakpoints.push((id, addr));
        id
    }

    fn remove_breakpoint(&mut self, id: u32) -> bool {
        if let Some(pos) = self.breakpoints.iter().position(|&(i, _)| i == id) {
            self.breakpoints.remove(pos);
            true
        } else {
            false
        }
    }

    fn set_watchpoint(&mut self, addr: u64, size: usize, kind: WatchpointKind) -> u32 {
        let id = self.next_wp_id;
        self.next_wp_id += 1;
        self.watchpoints.push((id, addr, size, kind));
        id
    }

    fn remove_watchpoint(&mut self, id: u32) -> bool {
        if let Some(pos) = self.watchpoints.iter().position(|&(i, ..)| i == id) {
            self.watchpoints.remove(pos);
            true
        } else {
            false
        }
    }

    fn go_to_start(&mut self) -> Result<(), EngineError> {
        self.restore_to_start();
        Ok(())
    }

    fn go_to_end(&mut self) -> Result<(), EngineError> {
        let events = self.trace.all_events();
        while self.event_index < events.len() {
            let e = events[self.event_index].clone();
            self.apply(&e);
            self.maybe_snapshot(self.event_index);
            self.event_index += 1;
        }
        Ok(())
    }

    fn run_to_memory_write(
        &mut self,
        addr: u64,
        size: usize,
    ) -> Result<EngineStopReason, EngineError> {
        let events = self.trace.all_events();
        while self.event_index < events.len() {
            let event = events[self.event_index].clone();
            if let EventKind::MemWrite { addr: wa, data } = &event.kind {
                let wa_end = wa.saturating_add(data.len() as u64);
                let check_end = addr.saturating_add(size as u64);
                if *wa < check_end && addr < wa_end {
                    let old = self.memory.read(addr, size).unwrap_or_default();
                    let new_val = data.clone();
                    self.apply(&event);
                    self.maybe_snapshot(self.event_index);
                    self.event_index += 1;
                    return Ok(EngineStopReason::MemoryWrite {
                        address: addr,
                        size,
                        old_value: old,
                        new_value: new_val,
                        position: self.current_pos,
                    });
                }
            }
            self.apply(&event);
            self.maybe_snapshot(self.event_index);
            self.event_index += 1;
        }
        Ok(EngineStopReason::TraceEnd)
    }

    fn run_backward_to_memory_write(
        &mut self,
        addr: u64,
        size: usize,
    ) -> Result<EngineStopReason, EngineError> {
        let events = self.trace.all_events();
        let start = self.event_index.saturating_sub(1);
        for scan_idx in (0..start).rev() {
            let e = &events[scan_idx];
            if let EventKind::MemWrite { addr: wa, data } = &e.kind {
                let wa_end = wa.saturating_add(data.len() as u64);
                let check_end = addr.saturating_add(size as u64);
                if *wa < check_end && addr < wa_end {
                    let new_data = data.clone();
                    self.restore_and_replay(scan_idx, &events);
                    let old_value = self.memory.read(addr, size).unwrap_or_default();
                    return Ok(EngineStopReason::MemoryWrite {
                        address: addr,
                        size,
                        old_value,
                        new_value: new_data,
                        position: self.current_pos,
                    });
                }
            }
        }
        self.restore_to_start();
        Ok(EngineStopReason::TraceStart)
    }

    fn run_to_event<F>(&mut self, pred: F) -> Result<EngineStopReason, EngineError>
    where
        F: Fn(&TraceEvent) -> bool + Send + Sync,
    {
        let events = self.trace.all_events();
        while self.event_index < events.len() {
            let event = events[self.event_index].clone();
            let matches = pred(&event);
            self.apply(&event);
            self.maybe_snapshot(self.event_index);
            self.event_index += 1;
            if matches {
                return Ok(EngineStopReason::ConditionMet {
                    position: self.current_pos,
                    description: "event predicate matched".into(),
                });
            }
        }
        Ok(EngineStopReason::TraceEnd)
    }
}

impl std::fmt::Debug for InProcessReplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InProcessReplay")
            .field("event_index", &self.event_index)
            .field("current_pos", &self.current_pos)
            .field("breakpoints", &self.breakpoints.len())
            .field("watchpoints", &self.watchpoints.len())
            .field("snapshots", &self.snapshot_cache.snapshot_count())
            .finish_non_exhaustive()
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_ttd::{TraceEvent, TraceMetadata};

    fn meta() -> TraceMetadata {
        TraceMetadata {
            version: 1,
            process_name: "t".into(),
            pid: 1,
            arch: "x86_64".into(),
            start_time: 0,
            end_time: 0,
            thread_count: 1,
            ..Default::default()
        }
    }

    fn simple_trace(n: u64) -> Arc<TtdTrace> {
        let t = Arc::new(TtdTrace::new(meta()));
        for i in 0..n {
            let kind = match i % 4 {
                0 => EventKind::MemWrite {
                    addr: 0x1000 + i * 8,
                    data: vec![u8::try_from(i).unwrap_or(u8::MAX)],
                },
                1 => EventKind::Call {
                    from: 0x3000,
                    to: 0x4000 + i,
                },
                2 => EventKind::Return {
                    from: 0x4000 + i,
                    to: 0x3004,
                },
                _ => EventKind::MemRead {
                    addr: 0x2000 + i * 4,
                    len: 4,
                },
            };
            t.add_event(TraceEvent {
                position: TracePosition::new(i, 0),
                thread_id: 1,
                kind,
            });
        }
        t
    }

    fn call_trace() -> Arc<TtdTrace> {
        let t = Arc::new(TtdTrace::new(meta()));
        t.add_event(TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::Call {
                from: 0x1000,
                to: 0x2000,
            },
        });
        t
    }

    fn write_trace() -> Arc<TtdTrace> {
        let t = Arc::new(TtdTrace::new(meta()));
        t.add_event(TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::MemWrite {
                addr: 0x5000,
                data: vec![1, 2, 3, 4],
            },
        });
        t.add_event(TraceEvent {
            position: TracePosition::new(1, 0),
            thread_id: 1,
            kind: EventKind::MemWrite {
                addr: 0x5000,
                data: vec![5, 6, 7, 8],
            },
        });
        t
    }

    // ── construction ──────────────────────────────────────────────────────────

    #[test]
    fn new_engine_at_start() {
        let eng = InProcessReplay::new(simple_trace(10));
        assert_eq!(eng.current_position(), TracePosition::start());
        assert_eq!(eng.event_index(), 0);
    }

    #[test]
    fn debug_format() {
        let eng = InProcessReplay::new(simple_trace(3));
        assert!(format!("{eng:?}").contains("InProcessReplay"));
    }

    // ── step forward ──────────────────────────────────────────────────────────

    #[test]
    fn step_forward_basic() {
        let mut eng = InProcessReplay::new(simple_trace(5));
        let r = eng.step(StepDirection::Forward).unwrap();
        assert!(matches!(r, EngineStopReason::StepComplete { .. }));
        assert_eq!(eng.current_position(), TracePosition::new(0, 0));
    }

    #[test]
    fn step_forward_to_end() {
        let mut eng = InProcessReplay::new(simple_trace(3));
        for _ in 0..3 {
            eng.step(StepDirection::Forward).unwrap();
        }
        let r = eng.step(StepDirection::Forward).unwrap();
        assert!(matches!(r, EngineStopReason::TraceEnd));
    }

    #[test]
    fn step_forward_breakpoint() {
        let mut eng = InProcessReplay::new(call_trace());
        eng.set_breakpoint(0x2000);
        let r = eng.step(StepDirection::Forward).unwrap();
        assert!(matches!(
            r,
            EngineStopReason::BreakpointHit {
                address: 0x2000,
                ..
            }
        ));
    }

    #[test]
    fn step_forward_memory_write_watchpoint() {
        let mut eng = InProcessReplay::new(write_trace());
        eng.set_watchpoint(0x5000, 4, WatchpointKind::Write);
        let r = eng.step(StepDirection::Forward).unwrap();
        assert!(matches!(
            r,
            EngineStopReason::MemoryWrite {
                address: 0x5000,
                ..
            }
        ));
    }

    // ── step backward ─────────────────────────────────────────────────────────

    #[test]
    fn step_backward_at_start() {
        let mut eng = InProcessReplay::new(simple_trace(5));
        let r = eng.step(StepDirection::Backward).unwrap();
        assert!(matches!(r, EngineStopReason::TraceStart));
    }

    #[test]
    fn step_backward_after_forward_steps() {
        let mut eng = InProcessReplay::new(simple_trace(10));
        for _ in 0..5 {
            eng.step(StepDirection::Forward).unwrap();
        }
        let pos_before = eng.current_position();
        eng.step(StepDirection::Backward).unwrap();
        // Should have gone back one step
        assert!(
            eng.current_position() < pos_before
                || eng.current_position() == TracePosition::new(3, 0)
        );
    }

    // ── goto ──────────────────────────────────────────────────────────────────

    #[test]
    fn goto_valid_position() {
        let mut eng = InProcessReplay::new(simple_trace(10));
        eng.goto(TracePosition::new(5, 0)).unwrap();
        assert_eq!(eng.current_position(), TracePosition::new(5, 0));
    }

    #[test]
    fn goto_invalid_position() {
        let mut eng = InProcessReplay::new(simple_trace(5));
        let r = eng.goto(TracePosition::new(999, 0));
        assert!(r.is_err());
    }

    // ── run forward/backward ──────────────────────────────────────────────────

    #[test]
    fn run_forward_hits_breakpoint() {
        let mut eng = InProcessReplay::new(call_trace());
        eng.set_breakpoint(0x2000);
        let r = eng.run(StepDirection::Forward).unwrap();
        assert!(matches!(r, EngineStopReason::BreakpointHit { .. }));
    }

    #[test]
    fn run_forward_to_end() {
        let mut eng = InProcessReplay::new(simple_trace(5));
        let r = eng.run(StepDirection::Forward).unwrap();
        assert!(matches!(r, EngineStopReason::TraceEnd));
    }

    #[test]
    fn run_backward_no_bp_to_start() {
        let trace = simple_trace(10);
        let mut eng = InProcessReplay::new(trace);
        eng.go_to_end().unwrap();
        let r = eng.run(StepDirection::Backward).unwrap();
        assert!(matches!(r, EngineStopReason::TraceStart));
    }

    // ── memory / register reads ───────────────────────────────────────────────

    #[test]
    fn read_memory_after_write() {
        let mut eng = InProcessReplay::new(write_trace());
        eng.step(StepDirection::Forward).unwrap();
        let bytes = eng.read_memory(0x5000, 4).unwrap();
        assert_eq!(bytes, vec![1, 2, 3, 4]);
    }

    #[test]
    fn read_register_after_call() {
        let mut eng = InProcessReplay::new(call_trace());
        eng.step(StepDirection::Forward).unwrap();
        let rip = eng.read_register(1, "rip").unwrap();
        assert_eq!(rip, 0x2000);
    }

    // ── go_to_start / go_to_end ───────────────────────────────────────────────

    #[test]
    fn go_to_start_resets() {
        let mut eng = InProcessReplay::new(simple_trace(5));
        eng.go_to_end().unwrap();
        eng.go_to_start().unwrap();
        assert_eq!(eng.current_position(), TracePosition::start());
        assert_eq!(eng.event_index(), 0);
    }

    #[test]
    fn go_to_end_advances() {
        let mut eng = InProcessReplay::new(simple_trace(5));
        eng.go_to_end().unwrap();
        assert_eq!(eng.event_index(), 5);
    }

    // ── run_to_memory_write ───────────────────────────────────────────────────

    #[test]
    fn run_to_memory_write_finds_it() {
        let mut eng = InProcessReplay::new(write_trace());
        let r = eng.run_to_memory_write(0x5000, 4).unwrap();
        assert!(matches!(
            r,
            EngineStopReason::MemoryWrite {
                address: 0x5000,
                ..
            }
        ));
    }

    #[test]
    fn run_to_memory_write_no_write() {
        let mut eng = InProcessReplay::new(call_trace());
        let r = eng.run_to_memory_write(0xDEAD, 4).unwrap();
        assert!(matches!(r, EngineStopReason::TraceEnd));
    }

    #[test]
    fn run_backward_to_memory_write() {
        let mut eng = InProcessReplay::new(write_trace());
        eng.go_to_end().unwrap();
        let r = eng.run_backward_to_memory_write(0x5000, 4).unwrap();
        assert!(matches!(r, EngineStopReason::MemoryWrite { .. }));
    }

    // ── run_to_event ──────────────────────────────────────────────────────────

    #[test]
    fn run_to_event_call() {
        let mut eng = InProcessReplay::new(simple_trace(10));
        let r = eng
            .run_to_event(|e| matches!(e.kind, EventKind::Call { .. }))
            .unwrap();
        assert!(matches!(r, EngineStopReason::ConditionMet { .. }));
    }

    // ── breakpoint management ─────────────────────────────────────────────────

    #[test]
    fn breakpoint_add_remove() {
        let mut eng = InProcessReplay::new(simple_trace(5));
        let id = eng.set_breakpoint(0x1000);
        assert!(eng.remove_breakpoint(id));
        assert!(!eng.remove_breakpoint(id));
    }

    // ── watchpoint management ─────────────────────────────────────────────────

    #[test]
    fn watchpoint_add_remove() {
        let mut eng = InProcessReplay::new(simple_trace(5));
        let id = eng.set_watchpoint(0x1000, 4, WatchpointKind::ReadWrite);
        assert!(eng.remove_watchpoint(id));
        assert!(!eng.remove_watchpoint(id));
    }

    // ── snapshot index ────────────────────────────────────────────────────────

    #[test]
    fn build_snapshot_index() {
        let mut eng = InProcessReplay::with_snapshot_interval(simple_trace(50), 10);
        eng.build_snapshot_index();
        assert!(eng.snapshot_count() > 0);
    }

    #[test]
    fn snapshot_preserves_state_after_goto() {
        let trace = simple_trace(100);
        let mut eng = InProcessReplay::with_snapshot_interval(trace, 10);
        eng.go_to_end().unwrap();
        eng.goto(TracePosition::new(50, 0)).unwrap();
        assert_eq!(eng.current_position(), TracePosition::new(50, 0));
    }

    // ── EngineStopReason display ──────────────────────────────────────────────

    #[test]
    fn stop_reason_display() {
        let r = EngineStopReason::TraceEnd;
        assert_eq!(r.to_string(), "TraceEnd");
        let r2 = EngineStopReason::BreakpointHit {
            address: 0x1000,
            position: TracePosition::new(0, 0),
        };
        assert!(r2.to_string().contains("0x1000"));
    }

    // ── get_state ─────────────────────────────────────────────────────────────

    #[test]
    fn get_state_after_step() {
        let mut eng = InProcessReplay::new(call_trace());
        eng.step(StepDirection::Forward).unwrap();
        let state = eng.get_state();
        assert_eq!(state.position, TracePosition::new(0, 0));
        assert!(state.reg(1, "rip").is_some());
    }

    // ── EngineError display ───────────────────────────────────────────────────

    #[test]
    fn engine_error_display() {
        let e = EngineError::PositionNotFound(TracePosition::new(7, 0));
        assert!(e.to_string().contains('7'));
        let e2 = EngineError::InvalidState("oops".into());
        assert!(e2.to_string().contains("oops"));
    }
}
