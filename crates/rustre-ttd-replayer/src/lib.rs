//! `rustre-ttd-replayer`
//!
//! Time-Travel Debug replay engine.  Provides deterministic forward and
//! backward stepping over a recorded execution trace, memory and register
//! state reconstruction at arbitrary ticks, root-cause analysis, and a
//! simple query DSL for programmatic interrogation of traces.
//!
//! # Core types
//!
//! * [`TtdTrace`]          — immutable trace container (events + snapshots + tick index).
//! * [`TraceEvent`]        — a single recorded event (syscall entry/exit, signal).
//! * [`TraceSnapshot`]     — full register + memory state checkpoint at a tick.
//! * [`MemWriteRecord`]    — one contiguous memory write recorded inside a syscall exit.
//! * [`TtdReplayer`]       — stateful cursor over a [`TtdTrace`].
//! * [`ReplayState`]       — mutable register + memory view kept current by the replayer.
//! * [`TtdQuery`]          — parsed query against a trace; executed via [`TtdQuery::execute`].
//! * [`RootCauseReport`]   — result of [`find_root_cause`].

pub mod api_call_tracker;
pub mod memory_diff_viewer;
pub mod memory_reconstructor;
pub mod register_timeline;
pub mod replay_engine;
pub mod replay_stats;
pub mod differential_replay;
pub mod snapshot_manager;
pub mod replay_scheduler;
pub mod trace_diff;
pub mod ttd_call_recorder;
pub mod ttd_memory_provider;
pub mod ttd_trace_loader;
pub mod ttd_database;
pub mod position_engine;
pub mod replay_controller;
pub mod timeline;

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── constants ────────────────────────────────────────────────────────────────

/// Default snapshot interval: take a snapshot every N syscall events.
pub const DEFAULT_SNAPSHOT_INTERVAL: u64 = 256;

/// Maximum number of memory write records carried in one [`TraceEvent::SyscallExit`].
pub const MAX_MEM_WRITES_PER_EVENT: usize = 1024;

/// Page size used when reconstructing memory state.
pub const REPLAY_PAGE_SIZE: usize = 4096;

// ─── ReplayError ─────────────────────────────────────────────────────────────

/// All errors produced by the TTD replayer.
#[derive(Debug, Error)]
pub enum ReplayError {
    /// Requested tick is beyond the end of the trace.
    #[error("tick {0} is out of range (trace ends at tick {1})")]
    TickOutOfRange(u64, u64),

    /// No snapshot exists before the requested tick.
    #[error("no snapshot found for tick {0}")]
    NoSnapshot(u64),

    /// Memory at the requested address is not present in the reconstructed state.
    #[error("address {0:#x} not mapped at tick {1}")]
    AddressNotMapped(u64, u64),

    /// Attempt to read more bytes than are present in the mapped region.
    #[error("read of {size} bytes at {addr:#x} overflows mapped region (tick {tick})")]
    ReadOverflow { addr: u64, size: usize, tick: u64 },

    /// Replayer is already at the beginning of the trace.
    #[error("already at start of trace (tick 0)")]
    AtStart,

    /// Replayer is already at the end of the trace.
    #[error("already at end of trace")]
    AtEnd,

    /// Query parse error.
    #[error("query parse error: {0}")]
    QueryParse(String),

    /// Query execution error.
    #[error("query execution error: {0}")]
    QueryExec(String),

    /// The trace is malformed.
    #[error("malformed trace: {0}")]
    MalformedTrace(String),

    /// Internal replayer invariant violated.
    #[error("internal error: {0}")]
    Internal(String),
}

// ─── MemWriteRecord ───────────────────────────────────────────────────────────

/// A single contiguous memory write recorded at syscall exit time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemWriteRecord {
    /// Start virtual address of the write.
    pub addr: u64,
    /// Bytes written.
    pub data: Vec<u8>,
}

impl MemWriteRecord {
    /// Construct a new write record.
    #[must_use] 
    pub const fn new(addr: u64, data: Vec<u8>) -> Self {
        Self { addr, data }
    }

    /// Size (bytes) of this write.
    #[inline]
    #[must_use] 
    pub const fn size(&self) -> usize {
        self.data.len()
    }

    /// Last byte address (inclusive) of this write.
    #[inline]
    #[must_use] 
    pub const fn end_addr(&self) -> u64 {
        self.addr.saturating_add(self.data.len() as u64).saturating_sub(1)
    }

    /// Returns true when this write overlaps the range `[addr, addr+size)`.
    #[must_use] 
    pub const fn overlaps(&self, addr: u64, size: usize) -> bool {
        if size == 0 || self.data.is_empty() {
            return false;
        }
        // Use inclusive last-byte addresses so non-empty ranges that touch
        // u64::MAX are not collapsed by saturating_add.
        let self_last = self.addr.saturating_add((self.data.len() as u64) - 1);
        let range_last = addr.saturating_add((size as u64) - 1);
        self.addr <= range_last && addr <= self_last
    }

    /// Extract the bytes that overlap with `[addr, addr+size)`.
    #[must_use] 
    pub fn bytes_in_range(&self, addr: u64, size: usize) -> Vec<u8> {
        let range_end = addr.saturating_add(size as u64);
        let self_end = self.addr.saturating_add(self.data.len() as u64);
        let start = self.addr.max(addr);
        let end = self_end.min(range_end);
        if start >= end {
            return Vec::new();
        }
        let local_start = (start - self.addr) as usize;
        let local_end = (end - self.addr) as usize;
        self.data[local_start..local_end].to_vec()
    }
}

impl fmt::Display for MemWriteRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemWrite {{ addr: {:#x}, size: {} }}", self.addr, self.data.len())
    }
}

// ─── TraceEvent ───────────────────────────────────────────────────────────────

/// A single recorded event in a time-travel trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceEvent {
    /// A syscall was entered at `tick`.
    SyscallEntry {
        /// Monotonically increasing trace tick at entry.
        tick: u64,
        /// System call number.
        nr: u64,
        /// Up to six register arguments.
        args: [u64; 6],
    },

    /// A syscall returned at `tick`.
    SyscallExit {
        /// Tick at return.
        tick: u64,
        /// Return value (sign-extended).
        retval: i64,
        /// All memory writes performed by the kernel during this syscall.
        mem_writes: Vec<MemWriteRecord>,
    },

    /// A signal was delivered to the process.
    SignalDelivered {
        /// Tick when the signal was delivered.
        tick: u64,
        /// Signal number (POSIX).
        signal: i32,
        /// Program counter at delivery.
        pc: u64,
    },
}

impl TraceEvent {
    /// Return the tick associated with this event.
    #[inline]
    #[must_use] 
    pub const fn tick(&self) -> u64 {
        match self {
            Self::SyscallEntry { tick, .. } | Self::SyscallExit { tick, .. } | Self::SignalDelivered { tick, .. } => *tick,
        }
    }

    /// Return a short human-readable name for this event kind.
    #[must_use] 
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::SyscallEntry { .. } => "SyscallEntry",
            Self::SyscallExit { .. } => "SyscallExit",
            Self::SignalDelivered { .. } => "SignalDelivered",
        }
    }

    /// True if this event carries memory writes.
    #[must_use] 
    pub const fn has_mem_writes(&self) -> bool {
        match self {
            Self::SyscallExit { mem_writes, .. } => !mem_writes.is_empty(),
            _ => false,
        }
    }

    /// Collect all memory writes from this event (empty for non-exit events).
    #[must_use] 
    pub const fn mem_writes(&self) -> &[MemWriteRecord] {
        match self {
            Self::SyscallExit { mem_writes, .. } => mem_writes.as_slice(),
            _ => &[],
        }
    }

    /// Return syscall number if this is a `SyscallEntry` or `SyscallExit`.
    #[must_use] 
    pub const fn syscall_nr(&self) -> Option<u64> {
        match self {
            Self::SyscallEntry { nr, .. } => Some(*nr),
            _ => None,
        }
    }
}

impl fmt::Display for TraceEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SyscallEntry { tick, nr, args } => {
                write!(f, "[{tick}] SyscallEntry nr={nr} args={args:?}")
            }
            Self::SyscallExit { tick, retval, mem_writes } => {
                write!(f, "[{tick}] SyscallExit retval={retval} writes={}", mem_writes.len())
            }
            Self::SignalDelivered { tick, signal, pc } => {
                write!(f, "[{tick}] SignalDelivered signal={signal} pc={pc:#x}")
            }
        }
    }
}

// ─── TraceSnapshot ────────────────────────────────────────────────────────────

/// A full checkpoint of process register and memory state at a given tick.
///
/// Snapshots are taken periodically during recording so that forward replay
/// can start from the nearest earlier snapshot rather than replaying from
/// tick zero.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSnapshot {
    /// Tick at which this snapshot was taken.
    pub tick: u64,
    /// Register file: name -> value.
    pub regs: HashMap<String, u64>,
    /// Memory pages: page-aligned base address -> 4 KiB page contents.
    pub mem_pages: HashMap<u64, Vec<u8>>,
}

impl TraceSnapshot {
    /// Create an empty snapshot at `tick`.
    #[must_use] 
    pub fn new(tick: u64) -> Self {
        Self {
            tick,
            regs: HashMap::new(),
            mem_pages: HashMap::new(),
        }
    }

    /// Insert or update a register value.
    pub fn set_reg(&mut self, name: impl Into<String>, value: u64) {
        self.regs.insert(name.into(), value);
    }

    /// Read a register value; returns `None` if not recorded.
    #[must_use] 
    pub fn get_reg(&self, name: &str) -> Option<u64> {
        self.regs.get(name).copied()
    }

    /// Write `data` starting at virtual address `addr` into the page map.
    pub fn write_mem(&mut self, addr: u64, data: &[u8]) {
        let mut cursor = addr;
        let mut remaining = data;
        while !remaining.is_empty() {
            let page_base = cursor & !(REPLAY_PAGE_SIZE as u64 - 1);
            let page_off = (cursor - page_base) as usize;
            let page = self
                .mem_pages
                .entry(page_base)
                .or_insert_with(|| vec![0u8; REPLAY_PAGE_SIZE]);
            let space = REPLAY_PAGE_SIZE - page_off;
            let chunk = remaining.len().min(space);
            page[page_off..page_off + chunk].copy_from_slice(&remaining[..chunk]);
            cursor += chunk as u64;
            remaining = &remaining[chunk..];
        }
    }

    /// Read `size` bytes from virtual address `addr`; returns `None` if any
    /// byte is not covered by this snapshot.
    #[must_use] 
    pub fn read_mem(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(size);
        let mut cursor = addr;
        let mut remaining = size;
        while remaining > 0 {
            let page_base = cursor & !(REPLAY_PAGE_SIZE as u64 - 1);
            let page_off = (cursor - page_base) as usize;
            let page = self.mem_pages.get(&page_base)?;
            let chunk = remaining.min(REPLAY_PAGE_SIZE - page_off);
            out.extend_from_slice(&page[page_off..page_off + chunk]);
            cursor += chunk as u64;
            remaining -= chunk;
        }
        Some(out)
    }

    /// Number of 4 KiB pages stored in this snapshot.
    #[must_use] 
    pub fn page_count(&self) -> usize {
        self.mem_pages.len()
    }

    /// Estimated memory footprint of this snapshot in bytes.
    #[must_use] 
    pub fn memory_footprint(&self) -> usize {
        self.mem_pages.len() * REPLAY_PAGE_SIZE
            + self.regs.len() * (8 + 8) // key ptr + u64
    }
}

// ─── TtdTrace ─────────────────────────────────────────────────────────────────

/// An immutable in-memory time-travel trace.
///
/// Holds the flat event log, periodic snapshots, and a tick→event-index lookup
/// table so callers can seek to any tick in O(log n).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdTrace {
    /// Flat ordered list of events (sorted by tick, ascending).
    pub events: Vec<TraceEvent>,
    /// Periodic full-state snapshots ordered by tick ascending.
    pub snapshots: Vec<TraceSnapshot>,
    /// Sparse index: `(tick, event_index)` for fast tick-based seeks.
    pub tick_index: Vec<(u64, usize)>,
}

impl TtdTrace {
    /// Construct an empty trace.
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            events: Vec::new(),
            snapshots: Vec::new(),
            tick_index: Vec::new(),
        }
    }

    /// Construct a trace from raw components, rebuilding the tick index.
    #[must_use] 
    pub fn from_parts(events: Vec<TraceEvent>, snapshots: Vec<TraceSnapshot>) -> Self {
        let mut trace = Self {
            events,
            snapshots,
            tick_index: Vec::new(),
        };
        trace.rebuild_tick_index();
        trace
    }

    /// Add an event and update the tick index.
    pub fn push_event(&mut self, event: TraceEvent) {
        let idx = self.events.len();
        let tick = event.tick();
        self.events.push(event);
        // Keep tick_index sorted by tick.
        match self.tick_index.binary_search_by_key(&tick, |&(t, _)| t) {
            Ok(_) => {} // duplicate tick: index entry already exists
            Err(pos) => self.tick_index.insert(pos, (tick, idx)),
        }
    }

    /// Add a snapshot.
    pub fn push_snapshot(&mut self, snap: TraceSnapshot) {
        // Keep sorted by tick.
        let pos = self.snapshots.partition_point(|s| s.tick <= snap.tick);
        self.snapshots.insert(pos, snap);
    }

    /// Rebuild the full tick index from `self.events`.
    pub fn rebuild_tick_index(&mut self) {
        self.tick_index.clear();
        for (idx, ev) in self.events.iter().enumerate() {
            let tick = ev.tick();
            match self.tick_index.binary_search_by_key(&tick, |&(t, _)| t) {
                Ok(_) => {}
                Err(pos) => self.tick_index.insert(pos, (tick, idx)),
            }
        }
    }

    /// Return the tick of the last event, or 0 if the trace is empty.
    #[must_use] 
    pub fn max_tick(&self) -> u64 {
        self.events.last().map_or(0, TraceEvent::tick)
    }

    /// Return the tick of the first event, or 0 if the trace is empty.
    #[must_use] 
    pub fn min_tick(&self) -> u64 {
        self.events.first().map_or(0, TraceEvent::tick)
    }

    /// Find the index of the first event whose tick >= `target`.
    #[must_use] 
    pub fn first_event_at_or_after(&self, target: u64) -> Option<usize> {
        let pos = self.tick_index.partition_point(|&(t, _)| t < target);
        self.tick_index.get(pos).map(|&(_, idx)| idx)
    }

    /// Find the index of the last event whose tick <= `target`.
    #[must_use] 
    pub fn last_event_at_or_before(&self, target: u64) -> Option<usize> {
        let pos = self.tick_index.partition_point(|&(t, _)| t <= target);
        if pos == 0 { return None; }
        Some(self.tick_index[pos - 1].1)
    }

    /// Return the snapshot with the largest tick <= `target`, or `None`.
    #[must_use] 
    pub fn nearest_snapshot_before(&self, target: u64) -> Option<&TraceSnapshot> {
        let pos = self.snapshots.partition_point(|s| s.tick <= target);
        if pos == 0 { return None; }
        Some(&self.snapshots[pos - 1])
    }

    /// Iterate over all events in tick range `[from, to]`.
    pub fn events_in_range(&self, from: u64, to: u64) -> impl Iterator<Item = &TraceEvent> {
        self.events.iter().filter(move |e| {
            let t = e.tick();
            t >= from && t <= to
        })
    }

    /// Count events of each kind.
    #[must_use] 
    pub fn event_counts(&self) -> HashMap<&'static str, usize> {
        let mut m: HashMap<&'static str, usize> = HashMap::new();
        for ev in &self.events {
            *m.entry(ev.kind_name()).or_insert(0) += 1;
        }
        m
    }

    /// Return all memory writes across the entire trace that touch `[addr, addr+size)`.
    #[must_use] 
    pub fn all_writes_touching(&self, addr: u64, size: usize) -> Vec<(u64, &MemWriteRecord)> {
        let mut out = Vec::new();
        for ev in &self.events {
            if let TraceEvent::SyscallExit { tick, mem_writes, .. } = ev {
                for wr in mem_writes {
                    if wr.overlaps(addr, size) {
                        out.push((*tick, wr));
                    }
                }
            }
        }
        out
    }

    /// True if the trace is empty.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Number of events.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.events.len()
    }
}

impl Default for TtdTrace {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ReplayState ─────────────────────────────────────────────────────────────

/// The reconstructed process state at the current replayer tick.
///
/// Memory is stored as a flat page map keyed by page-aligned addresses.
/// Registers are stored as a name→value map (architecture-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayState {
    /// Register file: name -> value.
    pub regs: HashMap<String, u64>,
    /// Memory: page-aligned base -> 4 KiB page bytes.
    pub mem: HashMap<u64, Vec<u8>>,
}

impl ReplayState {
    /// Construct an empty state.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            regs: HashMap::new(),
            mem: HashMap::new(),
        }
    }

    /// Load state from a snapshot.
    pub fn load_snapshot(&mut self, snap: &TraceSnapshot) {
        self.regs = snap.regs.clone();
        self.mem = snap.mem_pages.clone();
    }

    /// Read a register; returns 0 if not present.
    #[inline]
    #[must_use] 
    pub fn reg(&self, name: &str) -> u64 {
        self.regs.get(name).copied().unwrap_or(0)
    }

    /// Write a register value.
    #[inline]
    pub fn set_reg(&mut self, name: impl Into<String>, value: u64) {
        self.regs.insert(name.into(), value);
    }

    /// Apply a [`MemWriteRecord`] to the state.
    pub fn apply_write(&mut self, wr: &MemWriteRecord) {
        let mut cursor = wr.addr;
        let mut remaining = wr.data.as_slice();
        while !remaining.is_empty() {
            let page_base = cursor & !(REPLAY_PAGE_SIZE as u64 - 1);
            let page_off = (cursor - page_base) as usize;
            let page = self
                .mem
                .entry(page_base)
                .or_insert_with(|| vec![0u8; REPLAY_PAGE_SIZE]);
            let space = REPLAY_PAGE_SIZE - page_off;
            let chunk = remaining.len().min(space);
            page[page_off..page_off + chunk].copy_from_slice(&remaining[..chunk]);
            cursor += chunk as u64;
            remaining = &remaining[chunk..];
        }
    }

    /// Read `size` bytes from virtual address `addr`.
    #[must_use] 
    pub fn read(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(size);
        let mut cursor = addr;
        let mut remaining = size;
        while remaining > 0 {
            let page_base = cursor & !(REPLAY_PAGE_SIZE as u64 - 1);
            let page_off = (cursor - page_base) as usize;
            let page = self.mem.get(&page_base)?;
            let chunk = remaining.min(REPLAY_PAGE_SIZE - page_off);
            out.extend_from_slice(&page[page_off..page_off + chunk]);
            cursor += chunk as u64;
            remaining -= chunk;
        }
        Some(out)
    }

    /// Estimate memory footprint in bytes.
    #[must_use] 
    pub fn footprint(&self) -> usize {
        self.mem.len() * REPLAY_PAGE_SIZE + self.regs.len() * 16
    }

    /// Return the program counter if register "rip", "pc", or "eip" is set.
    #[must_use] 
    pub fn program_counter(&self) -> Option<u64> {
        for name in &["rip", "pc", "eip", "ip"] {
            if let Some(&v) = self.regs.get(*name) {
                return Some(v);
            }
        }
        None
    }
}

impl Default for ReplayState {
    fn default() -> Self {
        Self::new()
    }
}

// ─── TtdReplayer ─────────────────────────────────────────────────────────────

/// Stateful cursor over a [`TtdTrace`].
///
/// The replayer maintains a [`ReplayState`] that always reflects the process
/// state at [`TtdReplayer::current_tick`].  Forward and backward stepping
/// update the state incrementally.
#[derive(Debug, Clone)]
pub struct TtdReplayer {
    /// The trace being replayed (shared reference).
    pub trace: TtdTrace,
    /// Current tick position in the trace.
    pub current_tick: u64,
    /// Reconstructed process state at `current_tick`.
    pub state: ReplayState,
    /// Index into `trace.events` of the *next* event to be applied when
    /// stepping forward, or `None` if we are at the end.
    next_event_idx: usize,
}

impl TtdReplayer {
    // ── construction ────────────────────────────────────────────────────────

    /// Create a new replayer positioned at the start of `trace`.
    ///
    /// If a snapshot exists at tick 0 the state is pre-loaded from it;
    /// otherwise the state is empty.
    #[must_use] 
    pub fn new(trace: TtdTrace) -> Self {
        let mut state = ReplayState::new();
        // Load the earliest snapshot if available.
        if let Some(snap) = trace.snapshots.first()
            && snap.tick == 0 {
                state.load_snapshot(snap);
            }
        let next_event_idx = 0;
        let current_tick = trace.min_tick();
        Self {
            trace,
            current_tick,
            state,
            next_event_idx,
        }
    }

    // ── navigation ──────────────────────────────────────────────────────────

    /// Jump to the nearest snapshot at or before `target_tick`, then replay
    /// forward event by event until `current_tick == target_tick`.
    ///
    /// This is the primary seek operation and runs in O(events since snapshot).
    pub fn goto(&mut self, target_tick: u64) -> Result<(), ReplayError> {
        let max = self.trace.max_tick();
        if target_tick > max {
            return Err(ReplayError::TickOutOfRange(target_tick, max));
        }

        // Find the best snapshot.
        let restarted_from_scratch = if let Some(snap) = self.trace.nearest_snapshot_before(target_tick) {
            self.state.load_snapshot(snap);
            self.current_tick = snap.tick;
            false
        } else {
            // No snapshot: start from scratch.
            self.state = ReplayState::new();
            self.current_tick = 0;
            true
        };

        // Position next_event_idx so that events already folded into the
        // snapshot are not applied a second time.  When starting from scratch
        // (no snapshot loaded) all events are still pending, including any at
        // tick 0, so we begin at index 0.
        self.next_event_idx = if restarted_from_scratch {
            0
        } else {
            self
                .trace
                .first_event_at_or_after(self.current_tick + 1)
                .unwrap_or(self.trace.events.len())
        };

        // Replay forward up to target_tick.
        while self.current_tick < target_tick {
            if self.next_event_idx >= self.trace.events.len() {
                break;
            }
            let ev = &self.trace.events[self.next_event_idx];
            if ev.tick() > target_tick {
                break;
            }
            self.apply_event_forward(self.next_event_idx);
            self.next_event_idx += 1;
            self.current_tick = self.trace.events[self.next_event_idx.saturating_sub(1)].tick();
        }

        // Only advance current_tick to target_tick if we actually consumed an
        // event at that tick during the forward replay loop.  If no event
        // exists at target_tick the replayer stays at the last applied tick,
        // which is the accurate representation of the reconstructed state.
        if self.current_tick < target_tick {
            // The loop exited because events ran out or the next event is
            // beyond target_tick.  Advance current_tick to the requested tick
            // so callers see the position they asked for.
            self.current_tick = target_tick;
        }
        Ok(())
    }

    /// Step forward by one event.  Returns the event that was applied.
    pub fn step_forward(&mut self) -> Result<&TraceEvent, ReplayError> {
        if self.next_event_idx >= self.trace.events.len() {
            return Err(ReplayError::AtEnd);
        }
        let idx = self.next_event_idx;
        self.apply_event_forward(idx);
        self.current_tick = self.trace.events[idx].tick();
        self.next_event_idx += 1;
        Ok(&self.trace.events[idx])
    }

    /// Step backward by one event.
    ///
    /// Because the trace is append-only and events are not individually
    /// invertible (memory writes are not stored with their old values),
    /// backward stepping is implemented by seeking to the snapshot before
    /// the previous event and replaying forward to that position.
    pub fn step_backward(&mut self) -> Result<&TraceEvent, ReplayError> {
        if self.next_event_idx == 0 {
            return Err(ReplayError::AtStart);
        }
        // We want to land at the event *before* the last applied one.
        let prev_applied = self.next_event_idx.saturating_sub(1);
        if prev_applied == 0 {
            return Err(ReplayError::AtStart);
        }
        let target_idx = prev_applied - 1;
        let target_tick = self.trace.events[target_idx].tick();
        // Seek backwards: reload snapshot then replay forward.
        self.goto(target_tick)?;
        // Derive the returned event from next_event_idx - 1 so that it
        // reflects the actual last-applied position after goto(), not the
        // pre-computed target_idx which may be stale if goto snapped to a
        // different boundary.
        let last_applied = self.next_event_idx.saturating_sub(1);
        Ok(&self.trace.events[last_applied])
    }

    // ── memory queries ──────────────────────────────────────────────────────

    /// Return every `(tick, bytes)` pair where a write touched address range
    /// `[addr, addr+size)` anywhere in the trace.
    #[must_use] 
    pub fn find_all_writes_to(&self, addr: u64, size: usize) -> Vec<(u64, Vec<u8>)> {
        let mut out = Vec::new();
        for ev in &self.trace.events {
            if let TraceEvent::SyscallExit { tick, mem_writes, .. } = ev {
                for wr in mem_writes {
                    if wr.overlaps(addr, size) {
                        out.push((*tick, wr.bytes_in_range(addr, size)));
                    }
                }
            }
        }
        out
    }

    /// Read `size` bytes from virtual address `addr` as they existed at
    /// exactly `tick`.  Replays state internally without modifying `self`.
    pub fn read_memory_at_tick(
        &self,
        tick: u64,
        addr: u64,
        size: usize,
    ) -> Result<Vec<u8>, ReplayError> {
        let max = self.trace.max_tick();
        if tick > max {
            return Err(ReplayError::TickOutOfRange(tick, max));
        }

        // Clone state from nearest snapshot.
        let mut state = ReplayState::new();
        if let Some(snap) = self.trace.nearest_snapshot_before(tick) {
            state.load_snapshot(snap);
            let snap_tick = snap.tick;
            // Apply all events from snap_tick to tick.
            for ev in self.trace.events_in_range(snap_tick, tick) {
                if let TraceEvent::SyscallExit { mem_writes, .. } = ev {
                    for wr in mem_writes {
                        state.apply_write(wr);
                    }
                }
            }
        } else {
            // No snapshot: apply all events up to tick.
            for ev in self.trace.events_in_range(0, tick) {
                if let TraceEvent::SyscallExit { mem_writes, .. } = ev {
                    for wr in mem_writes {
                        state.apply_write(wr);
                    }
                }
            }
        }

        state
            .read(addr, size)
            .ok_or(ReplayError::AddressNotMapped(addr, tick))
    }

    /// Return the most recent `(tick, bytes)` of a write to `[addr, addr+size)`
    /// that occurred strictly before `tick`.
    #[must_use] 
    pub fn find_last_write_before(
        &self,
        addr: u64,
        tick: u64,
    ) -> Option<(u64, Vec<u8>)> {
        let size = 1; // at least one byte overlap
        let mut best: Option<(u64, Vec<u8>)> = None;
        for ev in &self.trace.events {
            if let TraceEvent::SyscallExit { tick: ev_tick, mem_writes, .. } = ev {
                if *ev_tick >= tick {
                    continue;
                }
                for wr in mem_writes {
                    if wr.overlaps(addr, size)
                        && best.as_ref().is_none_or(|(b, _)| *ev_tick >= *b) {
                            best = Some((*ev_tick, wr.bytes_in_range(addr, size)));
                        }
                }
            }
        }
        best
    }

    /// Return the most recent write to exactly `size` bytes at `addr` before `tick`.
    #[must_use] 
    pub fn find_last_write_range_before(
        &self,
        addr: u64,
        size: usize,
        tick: u64,
    ) -> Option<(u64, Vec<u8>)> {
        let mut best: Option<(u64, Vec<u8>)> = None;
        for ev in &self.trace.events {
            if let TraceEvent::SyscallExit { tick: ev_tick, mem_writes, .. } = ev {
                if *ev_tick >= tick {
                    continue;
                }
                for wr in mem_writes {
                    if wr.overlaps(addr, size) {
                        let bytes = wr.bytes_in_range(addr, size);
                        if !bytes.is_empty()
                            && best.as_ref().is_none_or(|(b_tick, _)| *ev_tick >= *b_tick) {
                                best = Some((*ev_tick, bytes));
                            }
                    }
                }
            }
        }
        best
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    /// Apply the side-effects of event at `idx` to `self.state` (forward).
    fn apply_event_forward(&mut self, idx: usize) {
        if let TraceEvent::SyscallExit { mem_writes, .. } = &self.trace.events[idx] {
            for wr in mem_writes {
                self.state.apply_write(wr);
            }
        }
    }

    /// Current program counter from state.
    #[must_use] 
    pub fn pc(&self) -> Option<u64> {
        self.state.program_counter()
    }

    /// True when the replayer is positioned at the end of the trace.
    #[must_use] 
    pub const fn at_end(&self) -> bool {
        self.next_event_idx >= self.trace.events.len()
    }

    /// True when positioned at the start.
    #[must_use] 
    pub const fn at_start(&self) -> bool {
        self.next_event_idx == 0
    }

    /// Reset to the very beginning of the trace.
    pub fn reset(&mut self) {
        let _ = self.goto(self.trace.min_tick());
    }

    /// Number of events remaining from the current position.
    #[must_use] 
    pub const fn remaining_events(&self) -> usize {
        self.trace.events.len().saturating_sub(self.next_event_idx)
    }
}

// ─── QueryValue ──────────────────────────────────────────────────────────────

/// A value produced by query evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryValue {
    /// Unsigned 64-bit integer.
    Int(u64),
    /// Signed 64-bit integer.
    SignedInt(i64),
    /// Byte vector.
    Bytes(Vec<u8>),
    /// A list of (tick, bytes) pairs.
    WriteList(Vec<(u64, Vec<u8>)>),
    /// A list of trace events.
    EventList(Vec<TraceEvent>),
    /// A human-readable string.
    Text(String),
    /// Null / no result.
    Null,
}

impl fmt::Display for QueryValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(v) => write!(f, "{v}"),
            Self::SignedInt(v) => write!(f, "{v}"),
            Self::Bytes(b) => write!(f, "bytes(len={})", b.len()),
            Self::WriteList(l) => write!(f, "writes(count={})", l.len()),
            Self::EventList(l) => write!(f, "events(count={})", l.len()),
            Self::Text(s) => write!(f, "{s}"),
            Self::Null => write!(f, "null"),
        }
    }
}

// ─── QueryAst ────────────────────────────────────────────────────────────────

/// Parsed query AST node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryAst {
    /// Read `size` bytes from `addr` at `tick`.
    ReadMem { tick: u64, addr: u64, size: usize },
    /// Find all writes to `[addr, addr+size)`.
    FindWrites { addr: u64, size: usize },
    /// Find the last write to `addr` before `tick`.
    LastWrite { addr: u64, tick: u64 },
    /// List all syscall entries with number `nr`.
    ListSyscalls { nr: Option<u64> },
    /// List all signals delivered.
    ListSignals,
    /// Seek replayer to `tick` and read register `reg`.
    ReadReg { tick: u64, reg: String },
    /// Count events of kind (e.g., "`SyscallEntry`").
    CountEvents { kind: String },
    /// Dump the root-cause report for a crash at `tick`/`addr`.
    RootCause { crash_tick: u64, crash_addr: u64 },
    /// Return the max tick in the trace.
    MaxTick,
    /// Return the min tick in the trace.
    MinTick,
}

// ─── TtdQuery ────────────────────────────────────────────────────────────────

/// A parsed query that can be executed against a [`TtdReplayer`].
///
/// # Query DSL syntax
///
/// ```text
/// read_mem <tick> <addr_hex> <size>
/// find_writes <addr_hex> <size>
/// last_write <addr_hex> <tick>
/// list_syscalls [nr]
/// list_signals
/// read_reg <tick> <reg_name>
/// count_events <kind>
/// root_cause <crash_tick> <crash_addr_hex>
/// max_tick
/// min_tick
/// ```
#[derive(Debug, Clone)]
pub struct TtdQuery {
    /// Parsed AST of the query.
    pub ast: QueryAst,
    /// Original query text.
    pub text: String,
}

impl TtdQuery {
    /// Parse a query from text.
    pub fn parse(text: &str) -> Result<Self, ReplayError> {
        let trimmed = text.trim();
        let mut tokens = trimmed.splitn(10, char::is_whitespace).filter(|s| !s.is_empty());
        let cmd = tokens.next().ok_or_else(|| ReplayError::QueryParse("empty query".into()))?;

        let parse_u64 = |s: &str| -> Result<u64, ReplayError> {
            let s = s.trim();
            s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).map_or_else(|| s.parse::<u64>()
                    .map_err(|e| ReplayError::QueryParse(format!("bad int {s}: {e}"))), |hex| u64::from_str_radix(hex, 16)
                    .map_err(|e| ReplayError::QueryParse(format!("bad hex {s}: {e}"))))
        };

        let ast = match cmd {
            "read_mem" => {
                let tick = parse_u64(tokens.next().ok_or_else(|| ReplayError::QueryParse("missing tick".into()))?)?;
                let addr = parse_u64(tokens.next().ok_or_else(|| ReplayError::QueryParse("missing addr".into()))?)?;
                let size: usize = tokens.next().ok_or_else(|| ReplayError::QueryParse("missing size".into()))?.parse()
                    .map_err(|e| ReplayError::QueryParse(format!("bad size: {e}")))?;
                // Reject absurdly large reads to prevent OOM via Vec::with_capacity.
                const MAX_QUERY_READ: usize = 256 * 1024 * 1024; // 256 MiB
                if size > MAX_QUERY_READ {
                    return Err(ReplayError::QueryParse(format!(
                        "size {size} exceeds maximum allowed read size {MAX_QUERY_READ}"
                    )));
                }
                QueryAst::ReadMem { tick, addr, size }
            }
            "find_writes" => {
                let addr = parse_u64(tokens.next().ok_or_else(|| ReplayError::QueryParse("missing addr".into()))?)?;
                let size: usize = tokens.next().ok_or_else(|| ReplayError::QueryParse("missing size".into()))?.parse()
                    .map_err(|e| ReplayError::QueryParse(format!("bad size: {e}")))?;
                // Reject absurdly large scan ranges to prevent excessive work.
                const MAX_QUERY_FIND: usize = 256 * 1024 * 1024; // 256 MiB
                if size > MAX_QUERY_FIND {
                    return Err(ReplayError::QueryParse(format!(
                        "size {size} exceeds maximum allowed scan size {MAX_QUERY_FIND}"
                    )));
                }
                QueryAst::FindWrites { addr, size }
            }
            "last_write" => {
                let addr = parse_u64(tokens.next().ok_or_else(|| ReplayError::QueryParse("missing addr".into()))?)?;
                let tick = parse_u64(tokens.next().ok_or_else(|| ReplayError::QueryParse("missing tick".into()))?)?;
                QueryAst::LastWrite { addr, tick }
            }
            "list_syscalls" => {
                let nr = tokens.next().map(parse_u64).transpose()?;
                QueryAst::ListSyscalls { nr }
            }
            "list_signals" => QueryAst::ListSignals,
            "read_reg" => {
                let tick = parse_u64(tokens.next().ok_or_else(|| ReplayError::QueryParse("missing tick".into()))?)?;
                let reg = tokens.next().ok_or_else(|| ReplayError::QueryParse("missing reg".into()))?.to_string();
                QueryAst::ReadReg { tick, reg }
            }
            "count_events" => {
                let kind = tokens.next().ok_or_else(|| ReplayError::QueryParse("missing kind".into()))?.to_string();
                QueryAst::CountEvents { kind }
            }
            "root_cause" => {
                let crash_tick = parse_u64(tokens.next().ok_or_else(|| ReplayError::QueryParse("missing crash_tick".into()))?)?;
                let crash_addr = parse_u64(tokens.next().ok_or_else(|| ReplayError::QueryParse("missing crash_addr".into()))?)?;
                QueryAst::RootCause { crash_tick, crash_addr }
            }
            "max_tick" => QueryAst::MaxTick,
            "min_tick" => QueryAst::MinTick,
            other => return Err(ReplayError::QueryParse(format!("unknown command: {other}"))),
        };

        Ok(Self { ast, text: text.to_string() })
    }

    /// Execute this query against a replayer.  The replayer's position may be
    /// modified as a side-effect (e.g., for `read_reg`).
    pub fn execute(&self, replayer: &mut TtdReplayer) -> Result<QueryValue, ReplayError> {
        match &self.ast {
            QueryAst::ReadMem { tick, addr, size } => {
                let bytes = replayer.read_memory_at_tick(*tick, *addr, *size)?;
                Ok(QueryValue::Bytes(bytes))
            }
            QueryAst::FindWrites { addr, size } => {
                let writes = replayer.find_all_writes_to(*addr, *size);
                Ok(QueryValue::WriteList(writes))
            }
            QueryAst::LastWrite { addr, tick } => {
                match replayer.find_last_write_before(*addr, *tick) {
                    Some((t, b)) => Ok(QueryValue::WriteList(vec![(t, b)])),
                    None => Ok(QueryValue::Null),
                }
            }
            QueryAst::ListSyscalls { nr } => {
                let events: Vec<TraceEvent> = replayer
                    .trace
                    .events
                    .iter()
                    .filter(|e| match e {
                        TraceEvent::SyscallEntry { nr: enr, .. } => {
                            nr.is_none_or(|n| n == *enr)
                        }
                        _ => false,
                    })
                    .cloned()
                    .collect();
                Ok(QueryValue::EventList(events))
            }
            QueryAst::ListSignals => {
                let events: Vec<TraceEvent> = replayer
                    .trace
                    .events
                    .iter()
                    .filter(|e| matches!(e, TraceEvent::SignalDelivered { .. }))
                    .cloned()
                    .collect();
                Ok(QueryValue::EventList(events))
            }
            QueryAst::ReadReg { tick, reg } => {
                replayer.goto(*tick)?;
                let val = replayer.state.reg(reg);
                Ok(QueryValue::Int(val))
            }
            QueryAst::CountEvents { kind } => {
                let count = replayer
                    .trace
                    .events
                    .iter()
                    .filter(|e| e.kind_name() == kind.as_str())
                    .count();
                Ok(QueryValue::Int(count as u64))
            }
            QueryAst::RootCause { crash_tick, crash_addr } => {
                let report = find_root_cause(replayer, *crash_tick, *crash_addr)?;
                Ok(QueryValue::Text(format!("{report}")))
            }
            QueryAst::MaxTick => Ok(QueryValue::Int(replayer.trace.max_tick())),
            QueryAst::MinTick => Ok(QueryValue::Int(replayer.trace.min_tick())),
        }
    }
}

// ─── RootCauseReport ─────────────────────────────────────────────────────────

/// A single causal step traced backwards from the crash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalStep {
    /// Tick at which this step occurred.
    pub tick: u64,
    /// Human-readable description.
    pub description: String,
    /// Address involved (if any).
    pub addr: Option<u64>,
    /// Data written (if any).
    pub data: Option<Vec<u8>>,
}

impl CausalStep {
    pub fn new(tick: u64, description: impl Into<String>) -> Self {
        Self { tick, description: description.into(), addr: None, data: None }
    }

    #[must_use] 
    pub const fn with_addr(mut self, addr: u64) -> Self {
        self.addr = Some(addr);
        self
    }

    #[must_use] 
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }
}

/// Result of [`find_root_cause`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCauseReport {
    /// The tick at which the crash occurred.
    pub crash_tick: u64,
    /// The address that triggered the crash (e.g., faulting address).
    pub crash_addr: u64,
    /// Causal chain, newest first (crash → earliest cause).
    pub chain: Vec<CausalStep>,
    /// Summary string.
    pub summary: String,
    /// Confidence 0.0–1.0.
    pub confidence: f64,
}

impl RootCauseReport {
    #[must_use] 
    pub const fn new(crash_tick: u64, crash_addr: u64) -> Self {
        Self {
            crash_tick,
            crash_addr,
            chain: Vec::new(),
            summary: String::new(),
            confidence: 0.0,
        }
    }

    pub fn push_step(&mut self, step: CausalStep) {
        self.chain.push(step);
    }

    /// Return the earliest causal step in the chain.
    #[must_use] 
    pub fn earliest_cause(&self) -> Option<&CausalStep> {
        self.chain.last()
    }
}

impl fmt::Display for RootCauseReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Root Cause Report ===")?;
        writeln!(f, "Crash tick   : {}", self.crash_tick)?;
        writeln!(f, "Crash addr   : {:#x}", self.crash_addr)?;
        writeln!(f, "Confidence   : {:.1}%", self.confidence * 100.0)?;
        writeln!(f, "Summary      : {}", self.summary)?;
        writeln!(f, "Causal chain ({} steps):", self.chain.len())?;
        for (i, step) in self.chain.iter().enumerate() {
            write!(f, "  [{i}] tick={} {}", step.tick, step.description)?;
            if let Some(addr) = step.addr {
                write!(f, " addr={addr:#x}")?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

// ─── find_root_cause ─────────────────────────────────────────────────────────

/// Perform backward causal analysis starting from `crash_tick`/`crash_addr`.
///
/// The algorithm:
/// 1. Record the crash as step 0.
/// 2. Find the last write to `crash_addr` before `crash_tick`.
/// 3. Identify the syscall that performed that write.
/// 4. Walk back further looking for prior writes or signals that could have
///    corrupted the pointer chain.
/// 5. Assign a confidence score based on chain length and write coverage.
pub fn find_root_cause(
    replayer: &mut TtdReplayer,
    crash_tick: u64,
    crash_addr: u64,
) -> Result<RootCauseReport, ReplayError> {
    let mut report = RootCauseReport::new(crash_tick, crash_addr);

    // Step 0: the crash itself.
    report.push_step(
        CausalStep::new(crash_tick, format!("crash at {crash_addr:#x}"))
            .with_addr(crash_addr),
    );

    // Step 1: find the last write to crash_addr before crash_tick.
    let last_write = replayer.find_last_write_before(crash_addr, crash_tick);

    let follow_addr;
    if let Some((write_tick, write_data)) = last_write {
        let desc = format!(
            "last write to crash_addr ({crash_addr:#x}) was {} bytes at tick {write_tick}",
            write_data.len()
        );
        report.push_step(
            CausalStep::new(write_tick, desc)
                .with_addr(crash_addr)
                .with_data(write_data.clone()),
        );

        // Step 2: read the value that was written (treat as a pointer).
        follow_addr = if write_data.len() >= 8 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&write_data[..8]);
            Some(u64::from_le_bytes(buf))
        } else if write_data.len() >= 4 {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&write_data[..4]);
            Some(u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], 0, 0, 0, 0]))
        } else {
            None
        };

        // Step 3: look for the syscall that performed the write.
        for ev in replayer.trace.events.iter().rev() {
            if let TraceEvent::SyscallEntry { tick: entry_tick, nr, .. } = ev
                && *entry_tick < write_tick {
                    report.push_step(CausalStep::new(
                        *entry_tick,
                        format!("syscall nr={nr} preceded the corrupting write"),
                    ));
                    break;
                }
        }
    } else {
        follow_addr = None;
        report.push_step(CausalStep::new(
            crash_tick,
            "no prior write to crash_addr found; memory may have been uninitialized".to_string(),
        ));
    }

    // Step 4: optionally follow the written pointer to find its origin.
    if let Some(ptr) = follow_addr
        && let Some((ptr_write_tick, ptr_data)) =
            replayer.find_last_write_before(ptr, crash_tick)
        {
            report.push_step(
                CausalStep::new(
                    ptr_write_tick,
                    format!("pointer target {ptr:#x} was last written at tick {ptr_write_tick}"),
                )
                .with_addr(ptr)
                .with_data(ptr_data),
            );
        }

    // Step 5: check for signals delivered before the crash.
    for ev in replayer.trace.events.iter().rev() {
        if let TraceEvent::SignalDelivered { tick: sig_tick, signal, pc } = ev
            && *sig_tick < crash_tick {
                report.push_step(
                    CausalStep::new(
                        *sig_tick,
                        format!("signal {signal} delivered at pc={pc:#x} before crash"),
                    )
                    .with_addr(*pc),
                );
                break;
            }
    }

    // Compute confidence: longer chain with actual writes = higher confidence.
    let has_write = report.chain.len() > 2;
    report.confidence = if has_write {
        0.1f64.mul_add((report.chain.len() as f64 - 2.0).min(5.0), 0.5)
    } else {
        0.2
    };

    // Build summary.
    report.summary = report.earliest_cause().map_or_else(
        || format!("crash at tick {crash_tick} addr {crash_addr:#x}: no prior writes found"),
        |cause| format!("earliest cause at tick {} — {}", cause.tick, cause.description),
    );

    Ok(report)
}

// ─── TraceBuilder ────────────────────────────────────────────────────────────

/// Ergonomic builder for constructing a [`TtdTrace`] programmatically,
/// e.g., from a replay recorder or a test fixture.
#[derive(Debug, Default)]
pub struct TraceBuilder {
    events: Vec<TraceEvent>,
    snapshots: Vec<TraceSnapshot>,
    snapshot_interval: u64,
    tick_counter: u64,
}

impl TraceBuilder {
    /// Create a new builder with the given snapshot interval.
    #[must_use] 
    pub fn new(snapshot_interval: u64) -> Self {
        Self {
            snapshot_interval,
            ..Default::default()
        }
    }

    /// Emit a [`TraceEvent::SyscallEntry`].
    pub fn syscall_entry(&mut self, nr: u64, args: [u64; 6]) -> u64 {
        let tick = self.next_tick();
        self.events.push(TraceEvent::SyscallEntry { tick, nr, args });
        tick
    }

    /// Emit a [`TraceEvent::SyscallExit`].
    pub fn syscall_exit(&mut self, retval: i64, mem_writes: Vec<MemWriteRecord>) -> u64 {
        let tick = self.next_tick();
        self.events.push(TraceEvent::SyscallExit { tick, retval, mem_writes });
        tick
    }

    /// Emit a [`TraceEvent::SignalDelivered`].
    pub fn signal(&mut self, signal: i32, pc: u64) -> u64 {
        let tick = self.next_tick();
        self.events.push(TraceEvent::SignalDelivered { tick, signal, pc });
        tick
    }

    /// Attach a full snapshot at the current tick.
    pub fn snapshot(&mut self, regs: HashMap<String, u64>, mem_pages: HashMap<u64, Vec<u8>>) {
        self.snapshots.push(TraceSnapshot {
            tick: self.tick_counter,
            regs,
            mem_pages,
        });
    }

    /// Finalise and return the built trace.
    #[must_use] 
    pub fn build(self) -> TtdTrace {
        TtdTrace::from_parts(self.events, self.snapshots)
    }

    /// Configured snapshot interval (ticks between automatic snapshot slots).
    #[must_use] 
    pub const fn snapshot_interval(&self) -> u64 {
        self.snapshot_interval
    }

    /// True when the *next* emitted tick will be on a snapshot boundary.
    ///
    /// Callers driving the builder can use this to attach a [`TraceSnapshot`]
    /// at the appropriate cadence without tracking the counter themselves.
    #[must_use] 
    pub fn next_tick_is_snapshot_boundary(&self) -> bool {
        self.snapshot_interval != 0
            && self.tick_counter.checked_rem(self.snapshot_interval) == Some(0)
    }

    const fn next_tick(&mut self) -> u64 {
        let t = self.tick_counter;
        self.tick_counter += 1;
        t
    }
}

// ─── TraceStats ──────────────────────────────────────────────────────────────

/// Aggregate statistics computed over a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStats {
    /// Total number of events.
    pub total_events: usize,
    /// Number of `SyscallEntry` events.
    pub syscall_entries: usize,
    /// Number of `SyscallExit` events.
    pub syscall_exits: usize,
    /// Number of `SignalDelivered` events.
    pub signals: usize,
    /// Total bytes written across all `SyscallExit` events.
    pub total_bytes_written: usize,
    /// Number of unique write addresses.
    pub unique_write_addrs: usize,
    /// First tick in the trace.
    pub min_tick: u64,
    /// Last tick in the trace.
    pub max_tick: u64,
    /// Number of snapshots.
    pub snapshot_count: usize,
    /// Syscall frequency: nr -> count.
    pub syscall_freq: HashMap<u64, usize>,
}

impl TraceStats {
    /// Compute statistics from a trace.
    #[must_use] 
    pub fn compute(trace: &TtdTrace) -> Self {
        let mut stats = Self {
            total_events: trace.events.len(),
            syscall_entries: 0,
            syscall_exits: 0,
            signals: 0,
            total_bytes_written: 0,
            unique_write_addrs: 0,
            min_tick: trace.min_tick(),
            max_tick: trace.max_tick(),
            snapshot_count: trace.snapshots.len(),
            syscall_freq: HashMap::new(),
        };

        let mut write_addrs = std::collections::HashSet::new();

        for ev in &trace.events {
            match ev {
                TraceEvent::SyscallEntry { nr, .. } => {
                    stats.syscall_entries += 1;
                    *stats.syscall_freq.entry(*nr).or_insert(0) += 1;
                }
                TraceEvent::SyscallExit { mem_writes, .. } => {
                    stats.syscall_exits += 1;
                    for wr in mem_writes {
                        stats.total_bytes_written += wr.data.len();
                        write_addrs.insert(wr.addr);
                    }
                }
                TraceEvent::SignalDelivered { .. } => {
                    stats.signals += 1;
                }
            }
        }

        stats.unique_write_addrs = write_addrs.len();
        stats
    }
}

impl fmt::Display for TraceStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "TraceStats {{")?;
        writeln!(f, "  total_events     : {}", self.total_events)?;
        writeln!(f, "  syscall_entries  : {}", self.syscall_entries)?;
        writeln!(f, "  syscall_exits    : {}", self.syscall_exits)?;
        writeln!(f, "  signals          : {}", self.signals)?;
        writeln!(f, "  bytes_written    : {}", self.total_bytes_written)?;
        writeln!(f, "  unique_wr_addrs  : {}", self.unique_write_addrs)?;
        writeln!(f, "  tick_range       : {}..{}", self.min_tick, self.max_tick)?;
        writeln!(f, "  snapshots        : {}", self.snapshot_count)?;
        write!(f, "}}")
    }
}

// ─── MemoryDiff ───────────────────────────────────────────────────────────────

/// Difference between two memory states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDiff {
    /// Pages present in `new` but not in `old`.
    pub added_pages: Vec<u64>,
    /// Pages present in `old` but not in `new`.
    pub removed_pages: Vec<u64>,
    /// Pages whose content changed: `base_addr` -> (`old_bytes`, `new_bytes`).
    pub modified_pages: Vec<(u64, Vec<u8>, Vec<u8>)>,
}

impl MemoryDiff {
    /// Compute the diff between two [`ReplayState`]s.
    #[must_use] 
    pub fn compute(old: &ReplayState, new: &ReplayState) -> Self {
        let mut added_pages = Vec::new();
        let mut removed_pages = Vec::new();
        let mut modified_pages = Vec::new();
        added_pages.reserve(new.mem.len().saturating_sub(old.mem.len()));
        removed_pages.reserve(old.mem.len().saturating_sub(new.mem.len()));

        for (&base, new_page) in &new.mem {
            match old.mem.get(&base) {
                None => added_pages.push(base),
                Some(old_page) => {
                    if old_page != new_page {
                        modified_pages.push((base, old_page.clone(), new_page.clone()));
                    }
                }
            }
        }
        for &base in old.mem.keys() {
            if !new.mem.contains_key(&base) {
                removed_pages.push(base);
            }
        }

        Self { added_pages, removed_pages, modified_pages }
    }

    /// True if there are no differences.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.added_pages.is_empty()
            && self.removed_pages.is_empty()
            && self.modified_pages.is_empty()
    }

    /// Count of bytes that differ across all modified pages.
    #[must_use] 
    pub fn differing_bytes(&self) -> usize {
        self.modified_pages.iter().map(|(_, old, new)| {
            old.iter().zip(new.iter()).filter(|(a, b)| a != b).count()
        }).sum()
    }
}

// ─── ReplayIterator ───────────────────────────────────────────────────────────

/// Iterator that drives a replayer forward event-by-event.
///
/// Each call to `next()` advances the replayer by one event and returns
/// a reference to the event that was just applied.
pub struct ReplayIterator<'a> {
    replayer: &'a mut TtdReplayer,
}

impl<'a> ReplayIterator<'a> {
    /// Create an iterator from a replayer.
    pub const fn new(replayer: &'a mut TtdReplayer) -> Self {
        Self { replayer }
    }
}

impl Iterator for ReplayIterator<'_> {
    type Item = TraceEvent;

    fn next(&mut self) -> Option<Self::Item> {
        self.replayer.step_forward().ok().cloned()
    }
}

// ─── SyscallSummary ───────────────────────────────────────────────────────────

/// Per-syscall aggregate summary built by scanning the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallSummary {
    /// Syscall number.
    pub nr: u64,
    /// Number of times this syscall was entered.
    pub call_count: usize,
    /// Aggregate bytes written by this syscall across all invocations.
    pub total_bytes_written: usize,
    /// Return values observed, deduplicated.
    pub retvals: Vec<i64>,
    /// Ticks at which this syscall was entered.
    pub entry_ticks: Vec<u64>,
}

impl SyscallSummary {
    #[must_use] 
    pub const fn new(nr: u64) -> Self {
        Self {
            nr,
            call_count: 0,
            total_bytes_written: 0,
            retvals: Vec::new(),
            entry_ticks: Vec::new(),
        }
    }
}

/// Build a map of syscall summaries from a trace.
#[must_use] 
pub fn build_syscall_summaries(trace: &TtdTrace) -> HashMap<u64, SyscallSummary> {
    let mut map: HashMap<u64, SyscallSummary> = HashMap::new();

    // Pair up entry/exit events using a per-nr stack keyed on syscall number.
    // SyscallExit does not carry a nr field in this trace format, so we track
    // pending entries per-nr and rely on the nr from the entry.  A FIFO queue
    // (VecDeque) per nr correctly pairs nested/re-entrant calls of the same
    // syscall without mixing up entries from different syscall numbers.
    let mut pending: HashMap<u64, std::collections::VecDeque<u64>> = HashMap::new(); // nr -> entry_ticks

    for ev in &trace.events {
        match ev {
            TraceEvent::SyscallEntry { tick, nr, .. } => {
                let summary = map.entry(*nr).or_insert_with(|| SyscallSummary::new(*nr));
                summary.call_count += 1;
                summary.entry_ticks.push(*tick);
                pending.entry(*nr).or_default().push_back(*tick);
            }
            TraceEvent::SyscallExit { retval, mem_writes, .. } => {
                // We must match an exit to its entry.  Since SyscallExit has no
                // nr field, pop the oldest pending entry across all nrs (FIFO
                // insertion order preserves wall-clock ordering for single-threaded
                // traces and minimises mismatches for simple interleaving).
                let matched_nr = pending
                    .iter_mut()
                    .filter(|(_, q)| !q.is_empty())
                    .min_by_key(|(_, q)| *q.front().unwrap())
                    .map(|(nr, q)| { q.pop_front(); *nr });
                if let Some(nr) = matched_nr {
                    let summary = map.entry(nr).or_insert_with(|| SyscallSummary::new(nr));
                    summary.total_bytes_written +=
                        mem_writes.iter().map(|w| w.data.len()).sum::<usize>();
                    if !summary.retvals.contains(retval) {
                        summary.retvals.push(*retval);
                    }
                }
            }
            TraceEvent::SignalDelivered { .. } => {}
        }
    }

    map
}

// ─── WatchpointHit ───────────────────────────────────────────────────────────

/// A watchpoint hit recorded during a replay scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchpointHit {
    /// Tick when the hit occurred.
    pub tick: u64,
    /// Address that was accessed.
    pub addr: u64,
    /// Bytes written (empty for read watchpoints if no data available).
    pub data: Vec<u8>,
    /// Index of the event that triggered this hit.
    pub event_idx: usize,
}

/// Scan the entire trace for writes to `[addr, addr+size)` and return all hits.
#[must_use] 
pub fn scan_for_writes(trace: &TtdTrace, addr: u64, size: usize) -> Vec<WatchpointHit> {
    let mut hits = Vec::new();
    for (idx, ev) in trace.events.iter().enumerate() {
        if let TraceEvent::SyscallExit { tick, mem_writes, .. } = ev {
            for wr in mem_writes {
                if wr.overlaps(addr, size) {
                    hits.push(WatchpointHit {
                        tick: *tick,
                        addr: wr.addr,
                        data: wr.bytes_in_range(addr, size),
                        event_idx: idx,
                    });
                }
            }
        }
    }
    hits
}

// ─── TickRange ────────────────────────────────────────────────────────────────

/// A closed tick interval `[start, end]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TickRange {
    pub start: u64,
    pub end: u64,
}

impl TickRange {
    /// Construct a `TickRange`.  Returns `Err(ReplayError::QueryParse)` if
    /// `start > end` rather than panicking, so callers can handle bad input
    /// from the query DSL gracefully.
    pub fn new(start: u64, end: u64) -> Result<Self, ReplayError> {
        if start > end {
            return Err(ReplayError::QueryParse(format!(
                "TickRange start ({start}) > end ({end})"
            )));
        }
        Ok(Self { start, end })
    }

    #[must_use] 
    pub const fn contains(&self, tick: u64) -> bool {
        tick >= self.start && tick <= self.end
    }

    #[must_use] 
    pub const fn duration(&self) -> u64 {
        self.end - self.start
    }

    #[must_use] 
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

impl fmt::Display for TickRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}..{}]", self.start, self.end)
    }
}

// ─── EventFilter ─────────────────────────────────────────────────────────────

/// Composable predicate for filtering trace events.
#[derive(Debug, Clone)]
pub enum EventFilter {
    /// Accept any event.
    Any,
    /// Accept only `SyscallEntry` events.
    SyscallEntryOnly,
    /// Accept only `SyscallExit` events.
    SyscallExitOnly,
    /// Accept only `SignalDelivered` events.
    SignalOnly,
    /// Accept events whose tick is in `range`.
    TickInRange(TickRange),
    /// Accept `SyscallEntry` events with the given syscall number.
    SyscallNr(u64),
    /// Accept `SignalDelivered` events with the given signal number.
    SignalNr(i32),
    /// Accept `SyscallExit` events whose writes touch `addr`.
    WritesToAddr(u64),
    /// Logical AND of two filters.
    And(Box<Self>, Box<Self>),
    /// Logical OR of two filters.
    Or(Box<Self>, Box<Self>),
    /// Logical NOT of a filter.
    Not(Box<Self>),
}

impl EventFilter {
    #[must_use] 
    pub fn matches(&self, ev: &TraceEvent) -> bool {
        match self {
            Self::Any => true,
            Self::SyscallEntryOnly => matches!(ev, TraceEvent::SyscallEntry { .. }),
            Self::SyscallExitOnly => matches!(ev, TraceEvent::SyscallExit { .. }),
            Self::SignalOnly => matches!(ev, TraceEvent::SignalDelivered { .. }),
            Self::TickInRange(r) => r.contains(ev.tick()),
            Self::SyscallNr(n) => matches!(ev, TraceEvent::SyscallEntry { nr, .. } if nr == n),
            Self::SignalNr(s) => matches!(ev, TraceEvent::SignalDelivered { signal, .. } if signal == s),
            Self::WritesToAddr(a) => {
                if let TraceEvent::SyscallExit { mem_writes, .. } = ev {
                    mem_writes.iter().any(|wr| wr.overlaps(*a, 1))
                } else {
                    false
                }
            }
            Self::And(a, b) => a.matches(ev) && b.matches(ev),
            Self::Or(a, b) => a.matches(ev) || b.matches(ev),
            Self::Not(inner) => !inner.matches(ev),
        }
    }

    /// Filter a trace, returning all matching events.
    #[must_use] 
    pub fn apply<'a>(&self, trace: &'a TtdTrace) -> Vec<&'a TraceEvent> {
        trace.events.iter().filter(|e| self.matches(e)).collect()
    }
}

// ─── ReplayCheckpoint ─────────────────────────────────────────────────────────

/// A saved replayer position that can be restored quickly.
#[derive(Debug, Clone)]
pub struct ReplayCheckpoint {
    pub tick: u64,
    pub state: ReplayState,
    pub next_event_idx: usize,
    pub label: String,
}

impl ReplayCheckpoint {
    /// Save the current replayer state as a checkpoint.
    pub fn save(replayer: &TtdReplayer, label: impl Into<String>) -> Self {
        Self {
            tick: replayer.current_tick,
            state: replayer.state.clone(),
            next_event_idx: replayer.next_event_idx,
            label: label.into(),
        }
    }

    /// Restore a previously saved checkpoint into a replayer.
    pub fn restore(&self, replayer: &mut TtdReplayer) {
        replayer.current_tick = self.tick;
        replayer.state = self.state.clone();
        replayer.next_event_idx = self.next_event_idx;
    }
}

// ─── ReplaySession ────────────────────────────────────────────────────────────

/// High-level session wrapping a [`TtdReplayer`] with checkpoint management.
pub struct ReplaySession {
    pub replayer: TtdReplayer,
    checkpoints: Vec<ReplayCheckpoint>,
}

impl ReplaySession {
    #[must_use] 
    pub fn new(trace: TtdTrace) -> Self {
        Self {
            replayer: TtdReplayer::new(trace),
            checkpoints: Vec::new(),
        }
    }

    /// Save the current position as a named checkpoint.
    pub fn save_checkpoint(&mut self, label: impl Into<String>) -> usize {
        let cp = ReplayCheckpoint::save(&self.replayer, label);
        self.checkpoints.push(cp);
        self.checkpoints.len() - 1
    }

    /// Restore checkpoint by index.
    pub fn restore_checkpoint(&mut self, idx: usize) -> bool {
        if let Some(cp) = self.checkpoints.get(idx).cloned() {
            cp.restore(&mut self.replayer);
            true
        } else {
            false
        }
    }

    /// List all checkpoint labels.
    #[must_use] 
    pub fn checkpoint_labels(&self) -> Vec<&str> {
        self.checkpoints.iter().map(|c| c.label.as_str()).collect()
    }

    /// Go to a tick.
    pub fn goto(&mut self, tick: u64) -> Result<(), ReplayError> {
        self.replayer.goto(tick)
    }

    /// Step forward.
    pub fn step_forward(&mut self) -> Result<TraceEvent, ReplayError> {
        self.replayer.step_forward().cloned()
    }

    /// Step backward.
    pub fn step_backward(&mut self) -> Result<TraceEvent, ReplayError> {
        self.replayer.step_backward().cloned()
    }
}

// ─── MemoryRegion ─────────────────────────────────────────────────────────────

/// A virtual memory region with permission flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub label: String,
}

impl MemoryRegion {
    pub fn new(start: u64, end: u64, label: impl Into<String>) -> Self {
        Self {
            start,
            end,
            readable: true,
            writable: true,
            executable: false,
            label: label.into(),
        }
    }

    #[must_use] 
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    #[must_use] 
    pub const fn size(&self) -> u64 {
        self.end - self.start
    }
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rwx = format!(
            "{}{}{}",
            if self.readable { 'r' } else { '-' },
            if self.writable { 'w' } else { '-' },
            if self.executable { 'x' } else { '-' },
        );
        write!(f, "{:#x}-{:#x} {} {}", self.start, self.end, rwx, self.label)
    }
}

// ─── MemoryMap ────────────────────────────────────────────────────────────────

/// Reconstructed virtual address space map.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryMap {
    pub regions: Vec<MemoryRegion>,
}

impl MemoryMap {
    #[must_use] 
    pub const fn new() -> Self {
        Self { regions: Vec::new() }
    }

    pub fn add_region(&mut self, region: MemoryRegion) {
        self.regions.push(region);
        self.regions.sort_by_key(|r| r.start);
    }

    #[must_use] 
    pub fn find(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    #[must_use] 
    pub fn is_mapped(&self, addr: u64) -> bool {
        self.find(addr).is_some()
    }
}

// ─── QueryBatch ───────────────────────────────────────────────────────────────

/// Execute multiple queries against a single replayer.
pub struct QueryBatch {
    queries: Vec<TtdQuery>,
}

impl QueryBatch {
    #[must_use] 
    pub const fn new() -> Self {
        Self { queries: Vec::new() }
    }

    pub fn add(&mut self, query: TtdQuery) {
        self.queries.push(query);
    }

    pub fn parse_and_add(&mut self, text: &str) -> Result<(), ReplayError> {
        self.queries.push(TtdQuery::parse(text)?);
        Ok(())
    }

    pub fn execute_all(
        &self,
        replayer: &mut TtdReplayer,
    ) -> Vec<Result<QueryValue, ReplayError>> {
        self.queries
            .iter()
            .map(|q| q.execute(replayer))
            .collect()
    }
}

impl Default for QueryBatch {
    fn default() -> Self {
        Self::new()
    }
}

// ─── utils ────────────────────────────────────────────────────────────────────

/// Format a byte slice as a hex string (uppercase, space-separated bytes).
#[must_use] 
pub fn hex_dump(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

/// Parse a hex string (with or without "0x" prefix) to u64.
#[must_use] 
pub fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

/// Format a tick as a zero-padded decimal string.
#[must_use] 
pub fn format_tick(tick: u64) -> String {
    format!("{tick:016}")
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Build a simple trace with a handful of syscall entry/exit pairs and
    /// one signal, plus one snapshot mid-way through.
    fn build_test_trace() -> TtdTrace {
        let mut builder = TraceBuilder::new(DEFAULT_SNAPSHOT_INTERVAL);

        // tick 0: SyscallEntry nr=1 (write)
        builder.syscall_entry(1, [3, 0x1000, 8, 0, 0, 0]);

        // tick 1: SyscallExit — writes 8 bytes at 0x1000
        builder.syscall_exit(
            8,
            vec![MemWriteRecord::new(0x1000, b"DEADBEEF".to_vec())],
        );

        // tick 2: SyscallEntry nr=2 (read)
        builder.syscall_entry(2, [3, 0x2000, 16, 0, 0, 0]);

        // tick 3: SyscallExit — writes 16 bytes at 0x2000
        builder.syscall_exit(
            16,
            vec![MemWriteRecord::new(0x2000, vec![0xAA; 16])],
        );

        // Add snapshot after tick 3 at tick=3
        let mut regs = HashMap::new();
        regs.insert("rip".to_string(), 0xDEAD_0000_u64);
        regs.insert("rax".to_string(), 16u64);
        let mut snap = TraceSnapshot::new(3);
        snap.regs = regs.clone();
        snap.write_mem(0x1000, b"DEADBEEF");
        snap.write_mem(0x2000, &[0xAA; 16]);

        // tick 4: SyscallEntry nr=9 (mmap)
        builder.syscall_entry(9, [0, 0x1000, 7, 0x22, 0xFFFF_FFFF, 0]);

        // tick 5: SyscallExit — writes 4 bytes at 0x3000 (mapped page)
        builder.syscall_exit(
            0x3000i64,
            vec![MemWriteRecord::new(0x3000, vec![0x90; 4])],
        );

        // tick 6: SignalDelivered SIGSEGV at pc=0xBAD00000
        builder.signal(11, 0xBAD0_0000);

        // tick 7: SyscallEntry nr=60 (exit)
        builder.syscall_entry(60, [0, 0, 0, 0, 0, 0]);

        // tick 8: SyscallExit — no writes
        builder.syscall_exit(0, vec![]);

        let mut trace = builder.build();
        trace.push_snapshot(snap);
        trace
    }

    /// Build a trace with a write to a specific address used for testing
    /// memory reconstruction.
    fn build_memory_trace() -> TtdTrace {
        let mut events = Vec::new();

        // tick 0: entry
        events.push(TraceEvent::SyscallEntry { tick: 0, nr: 1, args: [0; 6] });

        // tick 10: write 8 bytes at 0xDEAD0000
        events.push(TraceEvent::SyscallExit {
            tick: 10,
            retval: 0,
            mem_writes: vec![MemWriteRecord::new(0xDEAD_0000, vec![1, 2, 3, 4, 5, 6, 7, 8])],
        });

        // tick 20: overwrite first 4 bytes
        events.push(TraceEvent::SyscallExit {
            tick: 20,
            retval: 0,
            mem_writes: vec![MemWriteRecord::new(0xDEAD_0000, vec![0xFF, 0xFF, 0xFF, 0xFF])],
        });

        // tick 30: write 8 bytes at 0xBEEF0000
        events.push(TraceEvent::SyscallExit {
            tick: 30,
            retval: 0,
            mem_writes: vec![MemWriteRecord::new(0xBEEF_0000, vec![0xAA; 8])],
        });

        let mut snap = TraceSnapshot::new(0);
        snap.write_mem(0xDEAD_0000, &[0u8; 8]);

        
        TtdTrace::from_parts(events, vec![snap])
    }

    // ── MemWriteRecord tests ─────────────────────────────────────────────────

    #[test]
    fn test_mem_write_record_overlaps() {
        let wr = MemWriteRecord::new(0x1000, vec![0u8; 64]);
        assert!(wr.overlaps(0x1000, 1));
        assert!(wr.overlaps(0x1020, 4));
        assert!(wr.overlaps(0x103F, 1));
        assert!(!wr.overlaps(0x1040, 1));
        assert!(!wr.overlaps(0x0FFF, 1));
        assert!(wr.overlaps(0x0FFF, 2)); // crosses into wr
    }

    #[test]
    fn test_mem_write_record_bytes_in_range() {
        let data = (0u8..16).collect::<Vec<u8>>();
        let wr = MemWriteRecord::new(0x1000, data.clone());

        // Exact range
        let result = wr.bytes_in_range(0x1000, 16);
        assert_eq!(result, data);

        // Sub-range
        let result = wr.bytes_in_range(0x1004, 4);
        assert_eq!(result, &data[4..8]);

        // Partial overlap at start
        let result = wr.bytes_in_range(0x0FFE, 4);
        assert_eq!(result, &data[0..2]);

        // No overlap
        let result = wr.bytes_in_range(0x2000, 4);
        assert!(result.is_empty());
    }

    #[test]
    fn test_mem_write_record_end_addr() {
        let wr = MemWriteRecord::new(0x1000, vec![0u8; 256]);
        assert_eq!(wr.end_addr(), 0x10FF);
    }

    // ── TraceEvent tests ─────────────────────────────────────────────────────

    #[test]
    fn test_trace_event_tick() {
        let e = TraceEvent::SyscallEntry { tick: 42, nr: 1, args: [0; 6] };
        assert_eq!(e.tick(), 42);

        let e = TraceEvent::SyscallExit { tick: 99, retval: 0, mem_writes: vec![] };
        assert_eq!(e.tick(), 99);

        let e = TraceEvent::SignalDelivered { tick: 7, signal: 11, pc: 0xDEAD };
        assert_eq!(e.tick(), 7);
    }

    #[test]
    fn test_trace_event_kind_name() {
        assert_eq!(
            TraceEvent::SyscallEntry { tick: 0, nr: 0, args: [0; 6] }.kind_name(),
            "SyscallEntry"
        );
        assert_eq!(
            TraceEvent::SyscallExit { tick: 0, retval: 0, mem_writes: vec![] }.kind_name(),
            "SyscallExit"
        );
        assert_eq!(
            TraceEvent::SignalDelivered { tick: 0, signal: 9, pc: 0 }.kind_name(),
            "SignalDelivered"
        );
    }

    #[test]
    fn test_trace_event_has_mem_writes() {
        let e = TraceEvent::SyscallExit {
            tick: 0,
            retval: 0,
            mem_writes: vec![MemWriteRecord::new(0, vec![1])],
        };
        assert!(e.has_mem_writes());

        let e = TraceEvent::SyscallExit { tick: 0, retval: 0, mem_writes: vec![] };
        assert!(!e.has_mem_writes());

        let e = TraceEvent::SyscallEntry { tick: 0, nr: 1, args: [0; 6] };
        assert!(!e.has_mem_writes());
    }

    // ── TraceSnapshot tests ───────────────────────────────────────────────────

    #[test]
    fn test_snapshot_write_and_read() {
        let mut snap = TraceSnapshot::new(0);
        snap.write_mem(0x1000, b"hello world!!");
        let result = snap.read_mem(0x1000, 13).unwrap();
        assert_eq!(result, b"hello world!!");
    }

    #[test]
    fn test_snapshot_cross_page_write() {
        let mut snap = TraceSnapshot::new(0);
        // Write straddling a 4 KiB page boundary.
        let page_boundary = REPLAY_PAGE_SIZE as u64;
        let data = vec![0xBB; 16];
        snap.write_mem(page_boundary - 8, &data);

        let result = snap.read_mem(page_boundary - 8, 16).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_snapshot_missing_page_returns_none() {
        let snap = TraceSnapshot::new(0);
        assert!(snap.read_mem(0xDEAD_0000, 4).is_none());
    }

    #[test]
    fn test_snapshot_reg_access() {
        let mut snap = TraceSnapshot::new(5);
        snap.set_reg("rip", 0x4141_4141);
        assert_eq!(snap.get_reg("rip"), Some(0x4141_4141));
        assert_eq!(snap.get_reg("rbx"), None);
    }

    // ── TtdTrace tests ────────────────────────────────────────────────────────

    #[test]
    fn test_trace_max_min_tick() {
        let trace = build_test_trace();
        assert_eq!(trace.min_tick(), 0);
        assert_eq!(trace.max_tick(), 8);
    }

    #[test]
    fn test_trace_event_counts() {
        let trace = build_test_trace();
        let counts = trace.event_counts();
        assert_eq!(counts.get("SyscallEntry"), Some(&4));
        assert_eq!(counts.get("SyscallExit"), Some(&4));
        assert_eq!(counts.get("SignalDelivered"), Some(&1));
    }

    #[test]
    fn test_trace_events_in_range() {
        let trace = build_test_trace();
        let in_range: Vec<_> = trace.events_in_range(2, 5).collect();
        // ticks 2, 3, 4, 5
        assert_eq!(in_range.len(), 4);
    }

    #[test]
    fn test_trace_all_writes_touching() {
        let trace = build_test_trace();
        let writes = trace.all_writes_touching(0x1000, 8);
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, 1); // tick 1
    }

    #[test]
    fn test_trace_nearest_snapshot_before() {
        let trace = build_test_trace();
        let snap = trace.nearest_snapshot_before(5);
        assert!(snap.is_some());
        assert_eq!(snap.unwrap().tick, 3);

        let snap = trace.nearest_snapshot_before(0);
        // There is a snapshot at tick 3 and nothing at 0.
        // nearest_snapshot_before(0) should return None or snapshot at tick<=0.
        // Our test snapshot is at tick 3 so this should be None.
        assert!(snap.is_none());
    }

    // ── TtdReplayer::goto tests ───────────────────────────────────────────────

    #[test]
    fn test_goto_start() {
        let trace = build_test_trace();
        let mut replayer = TtdReplayer::new(trace);
        replayer.goto(0).unwrap();
        assert_eq!(replayer.current_tick, 0);
    }

    #[test]
    fn test_goto_middle() {
        let trace = build_test_trace();
        let mut replayer = TtdReplayer::new(trace);
        replayer.goto(5).unwrap();
        assert_eq!(replayer.current_tick, 5);
        // After tick 5, SyscallExit at tick 5 wrote 4 bytes at 0x3000.
        // We expect those bytes to be visible in state.
        let bytes = replayer.state.read(0x3000, 4);
        assert_eq!(bytes, Some(vec![0x90; 4]));
    }

    #[test]
    fn test_goto_end() {
        let trace = build_test_trace();
        let max = trace.max_tick();
        let mut replayer = TtdReplayer::new(trace);
        replayer.goto(max).unwrap();
        assert_eq!(replayer.current_tick, max);
    }

    #[test]
    fn test_goto_out_of_range() {
        let trace = build_test_trace();
        let max = trace.max_tick();
        let mut replayer = TtdReplayer::new(trace);
        let result = replayer.goto(max + 100);
        assert!(matches!(result, Err(ReplayError::TickOutOfRange(_, _))));
    }

    #[test]
    fn test_goto_then_goto_earlier() {
        let trace = build_test_trace();
        let mut replayer = TtdReplayer::new(trace);
        replayer.goto(5).unwrap();
        replayer.goto(2).unwrap();
        assert_eq!(replayer.current_tick, 2);
        // At tick 2, only the write at tick 1 has been applied.
        let bytes = replayer.state.read(0x1000, 8);
        assert_eq!(bytes, Some(b"DEADBEEF".to_vec()));
        // Write at tick 3 (0x2000) should NOT be present yet.
        assert!(replayer.state.read(0x2000, 1).is_none()
            || replayer.state.read(0x2000, 1) == Some(vec![0]));
    }

    // ── TtdReplayer::step_forward tests ──────────────────────────────────────

    #[test]
    fn test_step_forward_advances_tick() {
        let trace = build_test_trace();
        let mut replayer = TtdReplayer::new(trace);
        let ev = replayer.step_forward().unwrap().clone();
        assert_eq!(ev.tick(), 0);
        assert_eq!(replayer.current_tick, 0);
    }

    #[test]
    fn test_step_forward_to_end() {
        let trace = build_test_trace();
        let n = trace.len();
        let mut replayer = TtdReplayer::new(trace);
        for _ in 0..n {
            replayer.step_forward().unwrap();
        }
        assert!(replayer.at_end());
        assert!(matches!(replayer.step_forward(), Err(ReplayError::AtEnd)));
    }

    #[test]
    fn test_step_forward_applies_writes() {
        let trace = build_memory_trace();
        let mut replayer = TtdReplayer::new(trace);
        // Step over event[0] (SyscallEntry tick=0)
        replayer.step_forward().unwrap();
        // Step over event[1] (SyscallExit tick=10, writes [1..8] at 0xDEAD0000)
        replayer.step_forward().unwrap();
        let bytes = replayer.state.read(0xDEAD_0000, 8).unwrap();
        assert_eq!(bytes, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    // ── TtdReplayer::step_backward tests ─────────────────────────────────────

    #[test]
    fn test_step_backward_from_end() {
        let trace = build_test_trace();
        let max = trace.max_tick();
        let mut replayer = TtdReplayer::new(trace);
        replayer.goto(max).unwrap();
        // Step backward once: should land at tick just before max.
        let result = replayer.step_backward();
        assert!(result.is_ok(), "step_backward should succeed: {result:?}");
    }

    #[test]
    fn test_step_backward_at_start_returns_error() {
        let trace = build_test_trace();
        let mut replayer = TtdReplayer::new(trace);
        let result = replayer.step_backward();
        assert!(matches!(result, Err(ReplayError::AtStart)));
    }

    #[test]
    fn test_step_backward_undoes_write() {
        let trace = build_memory_trace();
        let mut replayer = TtdReplayer::new(trace);
        // Go to tick 20 (after the second write: 0xDEAD0000 = [0xFF;4] ++ [5,6,7,8])
        replayer.goto(20).unwrap();
        let after = replayer.state.read(0xDEAD_0000, 4).unwrap();
        assert_eq!(after, vec![0xFF, 0xFF, 0xFF, 0xFF]);

        // Step backward: should land at tick 10, where only the first write is applied.
        replayer.step_backward().unwrap();
        let before = replayer.state.read(0xDEAD_0000, 4).unwrap();
        assert_eq!(before, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_step_backward_multiple_times() {
        let trace = build_test_trace();
        let mut replayer = TtdReplayer::new(trace);
        replayer.goto(6).unwrap(); // after signal

        // Step backward 3 times; each should succeed.
        for _ in 0..3 {
            let r = replayer.step_backward();
            assert!(r.is_ok(), "step_backward failed: {r:?}");
        }
    }

    // ── find_all_writes_to tests ──────────────────────────────────────────────

    #[test]
    fn test_find_all_writes_to() {
        let trace = build_memory_trace();
        let replayer = TtdReplayer::new(trace);

        // Address 0xDEAD0000 was written at ticks 10 and 20.
        let writes = replayer.find_all_writes_to(0xDEAD_0000, 4);
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].0, 10);
        assert_eq!(writes[1].0, 20);
    }

    #[test]
    fn test_find_all_writes_to_no_match() {
        let trace = build_memory_trace();
        let replayer = TtdReplayer::new(trace);
        let writes = replayer.find_all_writes_to(0x1234_5678, 8);
        assert!(writes.is_empty());
    }

    #[test]
    fn test_find_all_writes_cross_page() {
        let mut events = Vec::new();
        let page = REPLAY_PAGE_SIZE as u64;
        events.push(TraceEvent::SyscallExit {
            tick: 1,
            retval: 0,
            mem_writes: vec![MemWriteRecord::new(page - 4, vec![0xAA; 8])],
        });
        let trace = TtdTrace::from_parts(events, vec![]);
        let replayer = TtdReplayer::new(trace);

        // Query should find the write for both the pre-boundary and post-boundary address.
        let w1 = replayer.find_all_writes_to(page - 4, 4);
        let w2 = replayer.find_all_writes_to(page, 4);
        assert_eq!(w1.len(), 1);
        assert_eq!(w2.len(), 1);
    }

    // ── read_memory_at_tick tests ─────────────────────────────────────────────

    #[test]
    fn test_read_memory_at_tick_before_write() {
        let trace = build_memory_trace();
        let replayer = TtdReplayer::new(trace);

        // At tick 5 (before the write at tick 10), the snapshot at tick=0 has
        // 0xDEAD0000 zeroed.
        let bytes = replayer.read_memory_at_tick(5, 0xDEAD_0000, 4).unwrap();
        assert_eq!(bytes, vec![0u8; 4]);
    }

    #[test]
    fn test_read_memory_at_tick_after_first_write() {
        let trace = build_memory_trace();
        let replayer = TtdReplayer::new(trace);

        let bytes = replayer.read_memory_at_tick(15, 0xDEAD_0000, 8).unwrap();
        assert_eq!(bytes, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_read_memory_at_tick_after_overwrite() {
        let trace = build_memory_trace();
        let replayer = TtdReplayer::new(trace);

        let bytes = replayer.read_memory_at_tick(25, 0xDEAD_0000, 4).unwrap();
        assert_eq!(bytes, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_read_memory_at_tick_out_of_range() {
        let trace = build_memory_trace();
        let replayer = TtdReplayer::new(trace);
        let result = replayer.read_memory_at_tick(9999, 0x1000, 4);
        assert!(matches!(result, Err(ReplayError::TickOutOfRange(_, _))));
    }

    // ── find_last_write_before tests ─────────────────────────────────────────

    #[test]
    fn test_find_last_write_before_finds_latest() {
        let trace = build_memory_trace();
        let replayer = TtdReplayer::new(trace);

        // Before tick 25: last write to 0xDEAD0000 was at tick 20.
        let result = replayer.find_last_write_before(0xDEAD_0000, 25);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, 20);
    }

    #[test]
    fn test_find_last_write_before_no_prior_write() {
        let trace = build_memory_trace();
        let replayer = TtdReplayer::new(trace);

        // No write to 0xBEEF0000 before tick 25 (the write is at tick 30).
        let result = replayer.find_last_write_before(0xBEEF_0000, 25);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_last_write_before_at_boundary() {
        let trace = build_memory_trace();
        let replayer = TtdReplayer::new(trace);

        // find_last_write_before(addr, tick) is strictly before tick=10.
        let result = replayer.find_last_write_before(0xDEAD_0000, 10);
        assert!(result.is_none(), "tick 10 write should be excluded");
    }

    // ── TtdQuery tests ────────────────────────────────────────────────────────

    #[test]
    fn test_query_parse_read_mem() {
        let q = TtdQuery::parse("read_mem 100 0x1000 8").unwrap();
        assert_eq!(q.ast, QueryAst::ReadMem { tick: 100, addr: 0x1000, size: 8 });
    }

    #[test]
    fn test_query_parse_find_writes() {
        let q = TtdQuery::parse("find_writes 0xDEAD0000 16").unwrap();
        assert_eq!(q.ast, QueryAst::FindWrites { addr: 0xDEAD_0000, size: 16 });
    }

    #[test]
    fn test_query_parse_last_write() {
        let q = TtdQuery::parse("last_write 0x1234 50").unwrap();
        assert_eq!(q.ast, QueryAst::LastWrite { addr: 0x1234, tick: 50 });
    }

    #[test]
    fn test_query_parse_list_syscalls_no_nr() {
        let q = TtdQuery::parse("list_syscalls").unwrap();
        assert_eq!(q.ast, QueryAst::ListSyscalls { nr: None });
    }

    #[test]
    fn test_query_parse_list_syscalls_with_nr() {
        let q = TtdQuery::parse("list_syscalls 9").unwrap();
        assert_eq!(q.ast, QueryAst::ListSyscalls { nr: Some(9) });
    }

    #[test]
    fn test_query_parse_invalid_command() {
        let result = TtdQuery::parse("bogus_command 1 2 3");
        assert!(matches!(result, Err(ReplayError::QueryParse(_))));
    }

    #[test]
    fn test_query_execute_find_writes() {
        let trace = build_memory_trace();
        let mut replayer = TtdReplayer::new(trace);
        let q = TtdQuery::parse("find_writes 0xDEAD0000 4").unwrap();
        let result = q.execute(&mut replayer).unwrap();
        match result {
            QueryValue::WriteList(list) => assert_eq!(list.len(), 2),
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn test_query_execute_max_tick() {
        let trace = build_test_trace();
        let max = trace.max_tick();
        let mut replayer = TtdReplayer::new(trace);
        let q = TtdQuery::parse("max_tick").unwrap();
        let result = q.execute(&mut replayer).unwrap();
        assert_eq!(result, QueryValue::Int(max));
    }

    #[test]
    fn test_query_execute_list_signals() {
        let trace = build_test_trace();
        let mut replayer = TtdReplayer::new(trace);
        let q = TtdQuery::parse("list_signals").unwrap();
        let result = q.execute(&mut replayer).unwrap();
        match result {
            QueryValue::EventList(evs) => {
                assert_eq!(evs.len(), 1);
                assert!(matches!(evs[0], TraceEvent::SignalDelivered { signal: 11, .. }));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_query_execute_count_events() {
        let trace = build_test_trace();
        let mut replayer = TtdReplayer::new(trace);
        let q = TtdQuery::parse("count_events SyscallEntry").unwrap();
        let result = q.execute(&mut replayer).unwrap();
        assert_eq!(result, QueryValue::Int(4));
    }

    // ── find_root_cause tests ─────────────────────────────────────────────────

    #[test]
    fn test_find_root_cause_basic() {
        let trace = build_memory_trace();
        let mut replayer = TtdReplayer::new(trace);
        let report = find_root_cause(&mut replayer, 25, 0xDEAD_0000).unwrap();
        // Chain should have at least 2 steps (crash + last write).
        assert!(report.chain.len() >= 2);
        assert_eq!(report.crash_tick, 25);
        assert_eq!(report.crash_addr, 0xDEAD_0000);
        assert!(!report.summary.is_empty());
        assert!(report.confidence > 0.0);
    }

    #[test]
    fn test_find_root_cause_no_prior_write() {
        let trace = build_test_trace();
        let mut replayer = TtdReplayer::new(trace);
        // Address that was never written.
        let report = find_root_cause(&mut replayer, 5, 0xFFFF_0000).unwrap();
        assert_eq!(report.crash_tick, 5);
        assert!(!report.chain.is_empty());
        // Confidence should be lower when no write was found.
        assert!(report.confidence <= 0.3);
    }

    #[test]
    fn test_find_root_cause_with_signal() {
        let trace = build_test_trace();
        let mut replayer = TtdReplayer::new(trace);
        // Crash at tick 8 at addr that was written.
        let report = find_root_cause(&mut replayer, 8, 0x3000).unwrap();
        assert!(report.chain.iter().any(|s| s.description.contains("signal")));
    }

    // ── ReplayState tests ─────────────────────────────────────────────────────

    #[test]
    fn test_replay_state_apply_write_and_read() {
        let mut state = ReplayState::new();
        let wr = MemWriteRecord::new(0x8000, vec![1, 2, 3, 4]);
        state.apply_write(&wr);
        let result = state.read(0x8000, 4).unwrap();
        assert_eq!(result, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_replay_state_read_unmapped_returns_none() {
        let state = ReplayState::new();
        assert!(state.read(0xDEAD_BEEF, 8).is_none());
    }

    #[test]
    fn test_replay_state_load_snapshot() {
        let mut snap = TraceSnapshot::new(0);
        snap.set_reg("rip", 0x4000);
        snap.write_mem(0x5000, &[0xAA; 8]);

        let mut state = ReplayState::new();
        state.load_snapshot(&snap);

        assert_eq!(state.reg("rip"), 0x4000);
        assert_eq!(state.read(0x5000, 8), Some(vec![0xAA; 8]));
    }

    #[test]
    fn test_replay_state_program_counter() {
        let mut state = ReplayState::new();
        assert_eq!(state.program_counter(), None);
        state.set_reg("rip", 0x1234);
        assert_eq!(state.program_counter(), Some(0x1234));
    }

    // ── TraceStats tests ─────────────────────────────────────────────────────

    #[test]
    fn test_trace_stats_compute() {
        let trace = build_test_trace();
        let stats = TraceStats::compute(&trace);
        assert_eq!(stats.syscall_entries, 4);
        assert_eq!(stats.syscall_exits, 4);
        assert_eq!(stats.signals, 1);
        assert!(stats.total_bytes_written > 0);
    }

    // ── EventFilter tests ─────────────────────────────────────────────────────

    #[test]
    fn test_event_filter_syscall_nr() {
        let trace = build_test_trace();
        let filter = EventFilter::SyscallNr(1);
        let matched = filter.apply(&trace);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].tick(), 0);
    }

    #[test]
    fn test_event_filter_tick_in_range() {
        let trace = build_test_trace();
        let filter = EventFilter::TickInRange(TickRange::new(2, 4).unwrap());
        let matched = filter.apply(&trace);
        assert_eq!(matched.len(), 3); // ticks 2, 3, 4
    }

    #[test]
    fn test_event_filter_and() {
        let trace = build_test_trace();
        let filter = EventFilter::And(
            Box::new(EventFilter::SyscallEntryOnly),
            Box::new(EventFilter::TickInRange(TickRange::new(0, 3).unwrap())),
        );
        let matched = filter.apply(&trace);
        // SyscallEntry at ticks 0, 2 => 2 events
        assert_eq!(matched.len(), 2);
    }

    #[test]
    fn test_event_filter_not() {
        let trace = build_test_trace();
        let filter = EventFilter::Not(Box::new(EventFilter::SyscallEntryOnly));
        let matched = filter.apply(&trace);
        // 9 total - 4 SyscallEntry = 5
        assert_eq!(matched.len(), 5);
    }

    // ── MemoryDiff tests ─────────────────────────────────────────────────────

    #[test]
    fn test_memory_diff_identical() {
        let mut state = ReplayState::new();
        state.apply_write(&MemWriteRecord::new(0x1000, vec![0xAA; 16]));
        let diff = MemoryDiff::compute(&state, &state.clone());
        assert!(diff.is_empty());
    }

    #[test]
    fn test_memory_diff_added_page() {
        let old = ReplayState::new();
        let mut new = ReplayState::new();
        new.apply_write(&MemWriteRecord::new(0x1000, vec![1, 2, 3, 4]));
        let diff = MemoryDiff::compute(&old, &new);
        assert_eq!(diff.added_pages.len(), 1);
        assert!(diff.removed_pages.is_empty());
    }

    #[test]
    fn test_memory_diff_modified_page() {
        let mut old = ReplayState::new();
        old.apply_write(&MemWriteRecord::new(0x1000, vec![0u8; 4]));
        let mut new = old.clone();
        new.apply_write(&MemWriteRecord::new(0x1000, vec![0xFF; 4]));
        let diff = MemoryDiff::compute(&old, &new);
        assert!(!diff.modified_pages.is_empty());
        assert!(diff.differing_bytes() >= 4);
    }

    // ── QueryBatch tests ──────────────────────────────────────────────────────

    #[test]
    fn test_query_batch_execute_all() {
        let trace = build_test_trace();
        let mut replayer = TtdReplayer::new(trace);
        let mut batch = QueryBatch::new();
        batch.parse_and_add("max_tick").unwrap();
        batch.parse_and_add("min_tick").unwrap();
        batch.parse_and_add("count_events SyscallEntry").unwrap();
        let results = batch.execute_all(&mut replayer);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(std::result::Result::is_ok));
    }

    // ── ReplaySession + checkpoint tests ─────────────────────────────────────

    #[test]
    fn test_replay_session_checkpoint_save_restore() {
        let trace = build_test_trace();
        let mut session = ReplaySession::new(trace);
        session.goto(3).unwrap();
        let cp_idx = session.save_checkpoint("after_tick_3");
        session.goto(7).unwrap();
        assert_eq!(session.replayer.current_tick, 7);
        session.restore_checkpoint(cp_idx);
        assert_eq!(session.replayer.current_tick, 3);
    }

    // ── scan_for_writes tests ─────────────────────────────────────────────────

    #[test]
    fn test_scan_for_writes() {
        let trace = build_memory_trace();
        let hits = scan_for_writes(&trace, 0xDEAD_0000, 8);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].tick, 10);
        assert_eq!(hits[1].tick, 20);
    }

    // ── build_syscall_summaries tests ─────────────────────────────────────────

    #[test]
    fn test_build_syscall_summaries() {
        let trace = build_test_trace();
        let summaries = build_syscall_summaries(&trace);
        // syscall 1 was entered once
        let s1 = summaries.get(&1).unwrap();
        assert_eq!(s1.call_count, 1);
        // syscall 60 was entered once with no writes
        let s60 = summaries.get(&60).unwrap();
        assert_eq!(s60.total_bytes_written, 0);
    }

    // ── util tests ────────────────────────────────────────────────────────────

    #[test]
    fn test_hex_dump() {
        assert_eq!(hex_dump(&[0xDE, 0xAD, 0xBE, 0xEF]), "DE AD BE EF");
    }

    #[test]
    fn test_parse_hex_with_prefix() {
        assert_eq!(parse_hex("0xDEAD"), Some(0xDEAD));
        assert_eq!(parse_hex("0XBEEF"), Some(0xBEEF));
    }

    #[test]
    fn test_parse_hex_without_prefix() {
        assert_eq!(parse_hex("1234"), Some(0x1234));
    }

    #[test]
    fn test_parse_hex_invalid() {
        assert_eq!(parse_hex("ZZZZ"), None);
    }

    // ── TickRange tests ───────────────────────────────────────────────────────

    #[test]
    fn test_tick_range_contains() {
        let r = TickRange::new(10, 20).unwrap();
        assert!(r.contains(10));
        assert!(r.contains(15));
        assert!(r.contains(20));
        assert!(!r.contains(9));
        assert!(!r.contains(21));
    }

    #[test]
    fn test_tick_range_overlaps() {
        let a = TickRange::new(0, 10).unwrap();
        let b = TickRange::new(5, 15).unwrap();
        let c = TickRange::new(11, 20).unwrap();
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    // ── integration: replay full trace step by step ───────────────────────────

    #[test]
    fn test_replay_full_trace_forward() {
        let trace = build_test_trace();
        let n = trace.len();
        let mut replayer = TtdReplayer::new(trace);
        let mut count = 0;
        while !replayer.at_end() {
            replayer.step_forward().unwrap();
            count += 1;
        }
        assert_eq!(count, n);
    }

    #[test]
    fn test_replay_iterator() {
        let trace = build_test_trace();
        let n = trace.len();
        let mut replayer = TtdReplayer::new(trace);
        let events: Vec<_> = ReplayIterator::new(&mut replayer).collect();
        assert_eq!(events.len(), n);
    }

    #[test]
    fn test_goto_idempotent() {
        let trace = build_memory_trace();
        let mut replayer = TtdReplayer::new(trace);
        replayer.goto(20).unwrap();
        let state_a = replayer.state.clone();
        replayer.goto(20).unwrap();
        let state_b = replayer.state.clone();
        // Both reads of 0xDEAD0000 should match.
        assert_eq!(
            state_a.read(0xDEAD_0000, 4),
            state_b.read(0xDEAD_0000, 4)
        );
    }

    #[test]
    fn test_snapshot_page_count() {
        let mut snap = TraceSnapshot::new(0);
        snap.write_mem(0x1000, &[0u8; 4]);
        snap.write_mem(0x2000, &[0u8; 4]);
        assert_eq!(snap.page_count(), 2);
    }

    #[test]
    fn test_memory_region_contains() {
        let r = MemoryRegion::new(0x1000, 0x2000, "stack");
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1FFF));
        assert!(!r.contains(0x2000));
    }

    #[test]
    fn test_memory_map_find() {
        let mut map = MemoryMap::new();
        map.add_region(MemoryRegion::new(0x1000, 0x2000, "heap"));
        map.add_region(MemoryRegion::new(0x4000, 0x8000, "stack"));
        assert!(map.find(0x1500).is_some());
        assert!(map.find(0x3000).is_none());
        assert!(map.find(0x4000).is_some());
    }

    #[test]
    fn test_query_execute_root_cause() {
        let trace = build_memory_trace();
        let mut replayer = TtdReplayer::new(trace);
        let q = TtdQuery::parse("root_cause 25 0xDEAD0000").unwrap();
        let result = q.execute(&mut replayer).unwrap();
        match result {
            QueryValue::Text(s) => assert!(s.contains("Root Cause")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_trace_builder_round_trip() {
        let mut b = TraceBuilder::new(100);
        b.syscall_entry(1, [0; 6]);
        b.syscall_exit(0, vec![MemWriteRecord::new(0x4000, vec![42; 4])]);
        let trace = b.build();
        assert_eq!(trace.len(), 2);
        assert_eq!(trace.max_tick(), 1);
    }

    #[test]
    fn test_causal_step_builder() {
        let step = CausalStep::new(100, "test step")
            .with_addr(0xDEAD)
            .with_data(vec![1, 2, 3]);
        assert_eq!(step.tick, 100);
        assert_eq!(step.addr, Some(0xDEAD));
        assert_eq!(step.data, Some(vec![1, 2, 3]));
    }

    #[test]
    fn test_root_cause_report_display() {
        let mut report = RootCauseReport::new(100, 0xDEAD);
        report.push_step(CausalStep::new(100, "crash"));
        report.push_step(CausalStep::new(50, "prior write"));
        report.summary = "test summary".into();
        report.confidence = 0.75;
        let s = format!("{report}");
        assert!(s.contains("Root Cause"));
        assert!(s.contains("0xdead"));
        assert!(s.contains("75.0%"));
    }

    // ── additional edge-case tests ────────────────────────────────────────────

    #[test]
    fn test_empty_trace_max_min_tick() {
        let trace = TtdTrace::new();
        assert_eq!(trace.max_tick(), 0);
        assert_eq!(trace.min_tick(), 0);
        assert!(trace.is_empty());
    }

    #[test]
    fn test_replayer_new_empty_trace() {
        let trace = TtdTrace::new();
        let replayer = TtdReplayer::new(trace);
        assert_eq!(replayer.current_tick, 0);
        assert!(replayer.at_end());
        assert!(replayer.at_start());
    }

    #[test]
    fn test_replayer_remaining_events() {
        let trace = build_test_trace();
        let n = trace.len();
        let mut replayer = TtdReplayer::new(trace);
        assert_eq!(replayer.remaining_events(), n);
        replayer.step_forward().unwrap();
        assert_eq!(replayer.remaining_events(), n - 1);
    }

    #[test]
    fn test_trace_rebuild_tick_index() {
        let mut trace = build_test_trace();
        let old_len = trace.tick_index.len();
        trace.rebuild_tick_index();
        assert_eq!(trace.tick_index.len(), old_len);
    }

    #[test]
    fn test_trace_first_event_at_or_after() {
        let trace = build_test_trace();
        let idx = trace.first_event_at_or_after(0).unwrap();
        assert_eq!(idx, 0);
        let idx = trace.first_event_at_or_after(100);
        assert!(idx.is_none());
    }

    #[test]
    fn test_trace_last_event_at_or_before() {
        let trace = build_test_trace();
        let idx = trace.last_event_at_or_before(8).unwrap();
        // Should be the last event.
        assert_eq!(trace.events[idx].tick(), 8);
        let none = trace.last_event_at_or_before(0);
        // tick_index has an entry at 0, so this should be Some(0).
        assert!(none.is_some());
        let really_none = trace.last_event_at_or_before(0_u64.wrapping_sub(1));
        // That is u64::MAX, so this returns last event.
        assert!(really_none.is_some());
    }

    #[test]
    fn test_mem_write_record_size() {
        let wr = MemWriteRecord::new(0x1000, vec![0u8; 128]);
        assert_eq!(wr.size(), 128);
    }

    #[test]
    fn test_replay_state_footprint() {
        let mut state = ReplayState::new();
        assert_eq!(state.footprint(), 0);
        state.apply_write(&MemWriteRecord::new(0x1000, vec![0u8; 4]));
        assert_eq!(state.footprint(), REPLAY_PAGE_SIZE);
    }

    #[test]
    fn test_trace_snapshot_memory_footprint() {
        let mut snap = TraceSnapshot::new(0);
        snap.write_mem(0x1000, &[0u8; 4]);
        snap.write_mem(0x2000, &[0u8; 4]);
        assert!(snap.memory_footprint() >= 2 * REPLAY_PAGE_SIZE);
    }

    #[test]
    fn test_tick_range_duration() {
        let r = TickRange::new(10, 20).unwrap();
        assert_eq!(r.duration(), 10);
    }

    #[test]
    fn test_syscall_summary_new() {
        let s = SyscallSummary::new(99);
        assert_eq!(s.nr, 99);
        assert_eq!(s.call_count, 0);
    }

    #[test]
    fn test_query_parse_read_reg() {
        let q = TtdQuery::parse("read_reg 5 rsp").unwrap();
        assert_eq!(q.ast, QueryAst::ReadReg { tick: 5, reg: "rsp".to_string() });
    }

    #[test]
    fn test_query_parse_root_cause() {
        let q = TtdQuery::parse("root_cause 0x64 0xDEAD").unwrap();
        assert_eq!(q.ast, QueryAst::RootCause { crash_tick: 100, crash_addr: 0xDEAD });
    }

    #[test]
    fn test_query_parse_count_events() {
        let q = TtdQuery::parse("count_events SignalDelivered").unwrap();
        assert_eq!(q.ast, QueryAst::CountEvents { kind: "SignalDelivered".into() });
    }

    #[test]
    fn test_format_tick() {
        assert_eq!(format_tick(0), "0000000000000000");
        assert_eq!(format_tick(255), "0000000000000255");
    }

    #[test]
    fn test_query_value_display() {
        assert_eq!(format!("{}", QueryValue::Int(42)), "42");
        assert_eq!(format!("{}", QueryValue::Null), "null");
        assert_eq!(format!("{}", QueryValue::Text("hi".into())), "hi");
    }

    #[test]
    fn test_watchpoint_hit_fields() {
        let hit = WatchpointHit {
            tick: 7,
            addr: 0x1000,
            data: vec![0xAA; 4],
            event_idx: 3,
        };
        assert_eq!(hit.tick, 7);
        assert_eq!(hit.data.len(), 4);
    }

    #[test]
    fn test_memory_map_is_mapped() {
        let mut map = MemoryMap::new();
        map.add_region(MemoryRegion::new(0x7FFF_0000, 0x8000_0000, "stack"));
        assert!(map.is_mapped(0x7FFF_8000));
        assert!(!map.is_mapped(0x9000_0000));
    }

    #[test]
    fn test_replay_session_step_operations() {
        let trace = build_test_trace();
        let mut session = ReplaySession::new(trace);
        // Forward
        let ev = session.step_forward().unwrap();
        assert_eq!(ev.tick(), 0);
        // Forward again
        session.step_forward().unwrap();
        // Backward
        let rev = session.step_backward().unwrap();
        assert!(rev.tick() <= 1);
    }

    #[test]
    fn test_replay_session_checkpoint_labels() {
        let trace = build_test_trace();
        let mut session = ReplaySession::new(trace);
        session.save_checkpoint("alpha");
        session.save_checkpoint("beta");
        let labels = session.checkpoint_labels();
        assert_eq!(labels, vec!["alpha", "beta"]);
    }

    #[test]
    fn test_replay_checkpoint_restore() {
        let trace = build_memory_trace();
        let mut replayer = TtdReplayer::new(trace);
        replayer.goto(15).unwrap();
        let cp = ReplayCheckpoint::save(&replayer, "mid");
        replayer.goto(25).unwrap();
        cp.restore(&mut replayer);
        assert_eq!(replayer.current_tick, 15);
        // Memory at 0xDEAD0000 should reflect tick 15 (after first write).
        let bytes = replayer.state.read(0xDEAD_0000, 4).unwrap();
        assert_eq!(bytes, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_event_filter_writes_to_addr() {
        let trace = build_memory_trace();
        let filter = EventFilter::WritesToAddr(0xDEAD_0000);
        let matched = filter.apply(&trace);
        // Two SyscallExit events write to 0xDEAD0000.
        assert_eq!(matched.len(), 2);
    }

    #[test]
    fn test_event_filter_or() {
        let trace = build_test_trace();
        let filter = EventFilter::Or(
            Box::new(EventFilter::SignalOnly),
            Box::new(EventFilter::SyscallNr(60)),
        );
        let matched = filter.apply(&trace);
        // 1 signal + 1 syscall(60) = 2
        assert_eq!(matched.len(), 2);
    }

    #[test]
    fn test_trace_stats_display() {
        let trace = build_test_trace();
        let stats = TraceStats::compute(&trace);
        let s = format!("{stats}");
        assert!(s.contains("TraceStats"));
        assert!(s.contains("total_events"));
    }

    #[test]
    fn test_memory_diff_removed_page() {
        let mut old = ReplayState::new();
        old.apply_write(&MemWriteRecord::new(0x9000, vec![1, 2, 3, 4]));
        let new = ReplayState::new();
        let diff = MemoryDiff::compute(&old, &new);
        assert_eq!(diff.removed_pages.len(), 1);
    }

    #[test]
    fn test_memory_region_size() {
        let r = MemoryRegion::new(0x1000, 0x3000, "test");
        assert_eq!(r.size(), 0x2000);
    }

    #[test]
    fn test_memory_region_display() {
        let r = MemoryRegion::new(0x1000, 0x2000, "heap");
        let s = format!("{r}");
        assert!(s.contains("heap"));
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn test_query_batch_default() {
        let batch = QueryBatch::default();
        assert_eq!(batch.queries.len(), 0);
    }

    #[test]
    fn test_trace_from_parts_rebuilds_index() {
        let events = vec![
            TraceEvent::SyscallEntry { tick: 5, nr: 1, args: [0; 6] },
            TraceEvent::SyscallExit { tick: 10, retval: 0, mem_writes: vec![] },
        ];
        let trace = TtdTrace::from_parts(events, vec![]);
        assert!(!trace.tick_index.is_empty());
        assert_eq!(trace.max_tick(), 10);
        assert_eq!(trace.min_tick(), 5);
    }

    #[test]
    fn test_replay_state_set_reg_overwrite() {
        let mut state = ReplayState::new();
        state.set_reg("rax", 42);
        state.set_reg("rax", 99);
        assert_eq!(state.reg("rax"), 99);
    }

    #[test]
    fn test_find_last_write_range_before() {
        let trace = build_memory_trace();
        let replayer = TtdReplayer::new(trace);
        let result = replayer.find_last_write_range_before(0xDEAD_0000, 4, 30);
        assert!(result.is_some());
        let (tick, bytes) = result.unwrap();
        assert_eq!(tick, 20);
        assert_eq!(bytes, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_goto_uses_nearest_snapshot() {
        // Build a trace with a snapshot at tick 50 and events from 0..100.
        let mut events = Vec::new();
        for i in 0u64..100 {
            events.push(TraceEvent::SyscallExit {
                tick: i,
                retval: 0,
                mem_writes: vec![MemWriteRecord::new(0x1000 + i * 8, vec![i as u8; 8])],
            });
        }
        let mut snap = TraceSnapshot::new(50);
        // Snapshot has all writes up to tick 50 applied.
        for i in 0u64..=50 {
            snap.write_mem(0x1000 + i * 8, &[i as u8; 8]);
        }
        let trace = TtdTrace::from_parts(events, vec![snap]);
        let mut replayer = TtdReplayer::new(trace);
        replayer.goto(75).unwrap();
        // Bytes at 0x1000 should be the value written at tick 0.
        let bytes = replayer.state.read(0x1000, 1).unwrap();
        assert_eq!(bytes, vec![0u8]);
    }

    #[test]
    fn test_scan_for_writes_empty() {
        let trace = TtdTrace::new();
        let hits = scan_for_writes(&trace, 0x1000, 8);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_trace_push_event_ordering() {
        let mut trace = TtdTrace::new();
        trace.push_event(TraceEvent::SyscallEntry { tick: 10, nr: 1, args: [0; 6] });
        trace.push_event(TraceEvent::SyscallEntry { tick: 5, nr: 2, args: [0; 6] });
        // Events are stored in push order, not tick order.
        assert_eq!(trace.events[0].tick(), 10);
        assert_eq!(trace.events[1].tick(), 5);
        // Tick index should have both entries.
        assert_eq!(trace.tick_index.len(), 2);
    }

    #[test]
    fn test_causal_step_display_in_report() {
        let mut report = RootCauseReport::new(0, 0);
        report.push_step(
            CausalStep::new(1, "write to heap")
                .with_addr(0xCAFE)
                .with_data(vec![0xAA; 4]),
        );
        assert_eq!(report.chain.len(), 1);
        assert_eq!(report.earliest_cause().unwrap().addr, Some(0xCAFE));
    }

    #[test]
    fn test_replay_state_cross_page_write_and_read() {
        let mut state = ReplayState::new();
        let boundary = REPLAY_PAGE_SIZE as u64;
        state.apply_write(&MemWriteRecord::new(boundary - 4, vec![1, 2, 3, 4, 5, 6, 7, 8]));
        let bytes = state.read(boundary - 4, 8).unwrap();
        assert_eq!(bytes, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_query_parse_list_signals() {
        let q = TtdQuery::parse("list_signals").unwrap();
        assert_eq!(q.ast, QueryAst::ListSignals);
    }

    #[test]
    fn test_query_parse_min_tick() {
        let q = TtdQuery::parse("min_tick").unwrap();
        assert_eq!(q.ast, QueryAst::MinTick);
    }

    #[test]
    fn test_query_execute_min_tick() {
        let trace = build_test_trace();
        let min = trace.min_tick();
        let mut replayer = TtdReplayer::new(trace);
        let q = TtdQuery::parse("min_tick").unwrap();
        let result = q.execute(&mut replayer).unwrap();
        assert_eq!(result, QueryValue::Int(min));
    }

    #[test]
    fn test_replay_reset() {
        let trace = build_test_trace();
        let mut replayer = TtdReplayer::new(trace);
        replayer.goto(6).unwrap();
        replayer.reset();
        assert_eq!(replayer.current_tick, replayer.trace.min_tick());
    }
}
