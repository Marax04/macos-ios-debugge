//! `rustre-ttd`
//!
//! TTD (Time Travel Debugging) core — like `WinDbg` TTD or Mozilla rr.
//! Records a process execution to a trace, allows deterministic replay.
//!
//! # Feature overview
//!
//! * [`TracePosition`] — lexicographically ordered `seq:step` cursor.
//! * [`TtdTrace`] — in-memory trace with thread-safe event log.
//! * [`TtdSession`] — forward/backward cursor over a trace.
//! * [`TtdIndex`] — SQLite-backed index for fast position and range queries.
//! * [`MemoryMap`] — address-space map reconstructed from trace events.
//! * [`CallStack`] — per-thread call-stack reconstructed from call/return events.
//! * [`TraceFilter`] — composable predicate filters for events.
//! * [`TraceStats`] — aggregate statistics computed over a trace.
//! * [`TraceExporter`] — serialise a trace to newline-delimited JSON.
//! * [`TraceImporter`] — deserialise a trace from newline-delimited JSON.
//! * [`Watchpoint`] — data-access watchpoint fired against recorded events.
//! * [`SyscallSummary`] — aggregate syscall usage from a trace.

pub mod call_monitor;
pub mod nirvana_format;
pub mod position;
pub mod replay_position;
pub mod replay_query_lang;
pub mod trace_index;
pub mod ttd_index;
pub mod ttd_query_language;
pub mod ttd_index_builder;
pub mod ttd_position;
pub mod ttd_thread_context;
pub mod ttd_breakpoint_engine;
pub mod ttd_heap_tracker;

use std::collections::HashMap;
use std::fmt;
use std::io::{BufRead, Write as IoWrite};
use std::ops::Not;
use std::sync::Arc;

use parking_lot::RwLock;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── errors ──────────────────────────────────────────────────────────────────

/// Errors for TTD operations.
#[derive(Debug, Error)]
pub enum TtdError {
    /// The trace is not open.
    #[error("trace not open")]
    TraceNotOpen,
    /// The requested position is not valid.
    #[error("invalid position: seq={seq} step={step}")]
    InvalidPosition {
        /// Sequence number.
        seq: u64,
        /// Step number.
        step: u64,
    },
    /// A read error occurred.
    #[error("read error: {0}")]
    ReadError(String),
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    /// The trace is corrupt.
    #[error("corrupt trace: {0}")]
    CorruptTrace(String),
    /// The trace version is not supported.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u32),
    /// A database error occurred.
    #[error("database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),
    /// A serialization error occurred.
    #[error("serialization error: {0}")]
    SerdeError(#[from] serde_json::Error),
}

// ─── TracePosition ────────────────────────────────────────────────────────────

/// Identifies a position in a TTD trace (like `WinDbg`'s `seq:step` notation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TracePosition {
    /// Sequence number (instruction count across threads).
    pub sequence: u64,
    /// Sub-step within a sequence.
    pub step: u64,
}

impl TracePosition {
    /// Create a new `TracePosition`.
    #[must_use]
    pub const fn new(sequence: u64, step: u64) -> Self {
        Self { sequence, step }
    }

    /// Return the starting position `(0, 0)`.
    #[must_use]
    pub const fn start() -> Self {
        Self::new(0, 0)
    }

    /// Return the position at the next sequence number, resetting step to zero.
    /// Saturates at `u64::MAX` rather than wrapping or panicking.
    #[must_use]
    pub const fn next_sequence(&self) -> Self {
        Self::new(self.sequence.saturating_add(1), 0)
    }

    /// Return the position at the next step within the same sequence.
    /// Saturates at `u64::MAX` rather than wrapping or panicking.
    #[must_use]
    pub const fn next_step(&self) -> Self {
        Self::new(self.sequence, self.step.saturating_add(1))
    }

    /// Return `true` if `self` is strictly before `other`.
    #[must_use]
    pub fn is_before(&self, other: &Self) -> bool {
        self < other
    }

    /// Return `true` if `self` is strictly after `other`.
    #[must_use]
    pub fn is_after(&self, other: &Self) -> bool {
        self > other
    }

    /// Return `true` if `self` is in the half-open interval `[start, end)`.
    #[must_use]
    pub fn in_range(&self, start: &Self, end: &Self) -> bool {
        self >= start && self < end
    }

    /// Encode as a single monotonic `u128` for compact storage.
    #[must_use]
    pub fn as_u128(&self) -> u128 {
        (u128::from(self.sequence) << 64) | u128::from(self.step)
    }

    /// Reconstruct a `TracePosition` from a value previously returned by
    /// [`Self::as_u128`].
    #[must_use]
    pub fn from_u128(v: u128) -> Self {
        let sequence = u64::try_from(v >> 64).unwrap_or(u64::MAX);
        let step = u64::try_from(v & u128::from(u64::MAX)).unwrap_or(u64::MAX);
        Self::new(sequence, step)
    }
}

impl fmt::Display for TracePosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.sequence, self.step)
    }
}

impl Default for TracePosition {
    fn default() -> Self {
        Self::start()
    }
}

// ─── MemorySnapshot ───────────────────────────────────────────────────────────

/// Memory snapshot at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySnapshot {
    /// Base address of the snapshot.
    pub address: u64,
    /// Raw bytes of the snapshot.
    pub data: Vec<u8>,
}

impl MemorySnapshot {
    /// Create a new `MemorySnapshot` at `address` with the given `data`.
    #[must_use]
    pub const fn new(address: u64, data: Vec<u8>) -> Self {
        Self { address, data }
    }

    /// Return the exclusive end address of this snapshot.
    #[must_use]
    pub const fn end_address(&self) -> u64 {
        self.address.saturating_add(self.data.len() as u64)
    }

    /// Return `true` if `addr` falls within this snapshot's range.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.address && addr < self.end_address()
    }

    /// Read a `u8` at `addr`, or `None` if out of range.
    #[must_use]
    pub fn read_u8(&self, addr: u64) -> Option<u8> {
        if !self.contains(addr) {
            return None;
        }
        let off = usize::try_from(addr - self.address).ok()?;
        self.data.get(off).copied()
    }

    /// Read a little-endian `u16` at `addr`, or `None` if out of range.
    #[must_use]
    pub fn read_u16_le(&self, addr: u64) -> Option<u16> {
        let lo = u16::from(self.read_u8(addr)?);
        let hi = u16::from(self.read_u8(addr + 1)?);
        Some(lo | (hi << 8))
    }

    /// Read a little-endian `u32` at `addr`, or `None` if out of range.
    #[must_use]
    pub fn read_u32_le(&self, addr: u64) -> Option<u32> {
        let lo = u32::from(self.read_u16_le(addr)?);
        let hi = u32::from(self.read_u16_le(addr + 2)?);
        Some(lo | (hi << 16))
    }

    /// Read a little-endian `u64` at `addr`, or `None` if out of range.
    #[must_use]
    pub fn read_u64_le(&self, addr: u64) -> Option<u64> {
        let lo = u64::from(self.read_u32_le(addr)?);
        let hi = u64::from(self.read_u32_le(addr + 4)?);
        Some(lo | (hi << 32))
    }

    /// Apply a write patch: overwrite bytes starting at `write_addr` with
    /// `new_data`.  Returns the number of bytes patched (may be less than
    /// `new_data.len()` if the write extends beyond the snapshot).
    pub fn apply_write(&mut self, write_addr: u64, new_data: &[u8]) -> usize {
        if write_addr >= self.end_address() || write_addr < self.address {
            return 0;
        }
        let Ok(start_off) = usize::try_from(write_addr - self.address) else {
            return 0;
        };
        let available = self.data.len() - start_off;
        let count = new_data.len().min(available);
        self.data[start_off..start_off + count].copy_from_slice(&new_data[..count]);
        count
    }
}

impl fmt::Display for MemorySnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemorySnapshot {{ address: {:#x}, len: {} }}",
            self.address,
            self.data.len()
        )
    }
}

// ─── ThreadState ──────────────────────────────────────────────────────────────

/// CPU register state for a single thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadState {
    /// Thread identifier.
    pub tid: u32,
    /// Named register values.
    pub registers: HashMap<String, u64>,
    /// Current stack pointer.
    pub stack_pointer: u64,
    /// Current instruction pointer.
    pub instruction_pointer: u64,
}

impl ThreadState {
    /// Create a new `ThreadState` for `tid` with all fields zeroed.
    #[must_use]
    pub fn new(tid: u32) -> Self {
        Self {
            tid,
            registers: HashMap::new(),
            stack_pointer: 0,
            instruction_pointer: 0,
        }
    }

    /// Set a named register value.
    pub fn set_register(&mut self, name: impl Into<String>, value: u64) {
        self.registers.insert(name.into(), value);
    }

    /// Get a named register value, returning `None` if not set.
    #[must_use]
    pub fn get_register(&self, name: &str) -> Option<u64> {
        self.registers.get(name).copied()
    }
}

impl fmt::Display for ThreadState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ThreadState {{ tid: {}, ip: {:#x}, sp: {:#x}, regs: {} }}",
            self.tid,
            self.instruction_pointer,
            self.stack_pointer,
            self.registers.len()
        )
    }
}

// ─── EventKind ────────────────────────────────────────────────────────────────

/// Kinds of events recorded in a TTD trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventKind {
    /// A memory read at `addr` of `len` bytes.
    MemRead {
        /// Address being read.
        addr: u64,
        /// Number of bytes read.
        len: usize,
    },
    /// A memory write at `addr` with `data`.
    MemWrite {
        /// Address being written.
        addr: u64,
        /// Bytes written.
        data: Vec<u8>,
    },
    /// A call from `from` to `to`.
    Call {
        /// Call site address.
        from: u64,
        /// Call target address.
        to: u64,
    },
    /// A return from `from` to `to`.
    Return {
        /// Return site address.
        from: u64,
        /// Return destination address.
        to: u64,
    },
    /// A syscall entry with number `nr` and six arguments.
    SyscallEnter {
        /// Syscall number.
        nr: u32,
        /// Syscall arguments.
        args: [u64; 6],
    },
    /// A syscall exit with return value.
    SyscallExit {
        /// Syscall number.
        nr: u32,
        /// Return value.
        ret: u64,
    },
    /// An exception with code and faulting address.
    Exception {
        /// Exception code.
        code: u32,
        /// Faulting address.
        addr: u64,
    },
    /// A new thread was created.
    ThreadCreate {
        /// New thread identifier.
        tid: u32,
    },
    /// A thread exited with the given code.
    ThreadExit {
        /// Thread identifier.
        tid: u32,
        /// Exit code.
        code: u32,
    },
    /// A software breakpoint was hit.
    Breakpoint {
        /// Address of the breakpoint.
        addr: u64,
    },
}

impl EventKind {
    /// Return `true` if this event involves a memory access (read or write).
    #[must_use]
    pub const fn is_memory_access(&self) -> bool {
        matches!(self, Self::MemRead { .. } | Self::MemWrite { .. })
    }

    /// Return `true` if this event is a control-flow transfer (call/return).
    #[must_use]
    pub const fn is_control_flow(&self) -> bool {
        matches!(self, Self::Call { .. } | Self::Return { .. })
    }

    /// Return `true` if this event is a syscall entry or exit.
    #[must_use]
    pub const fn is_syscall(&self) -> bool {
        matches!(self, Self::SyscallEnter { .. } | Self::SyscallExit { .. })
    }

    /// Return `true` if this event is thread lifecycle (create/exit).
    #[must_use]
    pub const fn is_thread_lifecycle(&self) -> bool {
        matches!(self, Self::ThreadCreate { .. } | Self::ThreadExit { .. })
    }

    /// Return the memory address relevant to this event, if any.
    #[must_use]
    pub const fn address(&self) -> Option<u64> {
        match self {
            Self::MemRead { addr, .. }
            | Self::MemWrite { addr, .. }
            | Self::Exception { addr, .. }
            | Self::Breakpoint { addr } => Some(*addr),
            Self::Call { from, .. } | Self::Return { from, .. } => Some(*from),
            _ => None,
        }
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemRead { addr, len } => write!(f, "MemRead({addr:#x}, {len}B)"),
            Self::MemWrite { addr, data } => write!(f, "MemWrite({addr:#x}, {}B)", data.len()),
            Self::Call { from, to } => write!(f, "Call({from:#x} -> {to:#x})"),
            Self::Return { from, to } => write!(f, "Return({from:#x} -> {to:#x})"),
            Self::SyscallEnter { nr, .. } => write!(f, "SyscallEnter(nr={nr})"),
            Self::SyscallExit { nr, ret } => write!(f, "SyscallExit(nr={nr}, ret={ret:#x})"),
            Self::Exception { code, addr } => {
                write!(f, "Exception(code={code:#x}, addr={addr:#x})")
            }
            Self::ThreadCreate { tid } => write!(f, "ThreadCreate(tid={tid})"),
            Self::ThreadExit { tid, code } => write!(f, "ThreadExit(tid={tid}, code={code})"),
            Self::Breakpoint { addr } => write!(f, "Breakpoint({addr:#x})"),
        }
    }
}

// ─── TraceEvent ───────────────────────────────────────────────────────────────

/// A single recorded event in a TTD trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Position in the trace.
    pub position: TracePosition,
    /// Thread that generated this event.
    pub thread_id: u32,
    /// The kind of event.
    pub kind: EventKind,
}

impl TraceEvent {
    /// Create a new `TraceEvent`.
    #[must_use]
    pub const fn new(position: TracePosition, thread_id: u32, kind: EventKind) -> Self {
        Self {
            position,
            thread_id,
            kind,
        }
    }
}

impl fmt::Display for TraceEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] tid={} {}",
            self.position, self.thread_id, self.kind
        )
    }
}

// ─── TraceMetadata ────────────────────────────────────────────────────────────

/// Metadata about a TTD trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMetadata {
    /// Trace format version.
    pub version: u32,
    /// Name of the recorded process.
    pub process_name: String,
    /// PID of the recorded process.
    pub pid: u32,
    /// Target architecture string, e.g. `"x86_64"`.
    pub arch: String,
    /// Unix timestamp when recording started.
    pub start_time: u64,
    /// Unix timestamp when recording ended.
    pub end_time: u64,
    /// Number of recorded threads.
    pub thread_count: u32,
    /// Position at which recording started (defaults to `TracePosition::start()`).
    #[serde(default = "TracePosition::start")]
    pub start_position: TracePosition,
    /// Position at which recording ended (defaults to `TracePosition::start()`).
    #[serde(default = "TracePosition::start")]
    pub end_position: TracePosition,
    /// Identifiers of all threads recorded in the trace.
    #[serde(default)]
    pub thread_ids: Vec<u32>,
}

impl Default for TraceMetadata {
    fn default() -> Self {
        Self {
            version: 1,
            process_name: String::from("unknown"),
            pid: 0,
            arch: String::from("x86_64"),
            start_time: 0,
            end_time: 0,
            thread_count: 1,
            start_position: TracePosition::start(),
            end_position: TracePosition::start(),
            thread_ids: Vec::new(),
        }
    }
}

impl fmt::Display for TraceMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TraceMetadata {{ process: {}, pid: {}, arch: {}, version: {} }}",
            self.process_name, self.pid, self.arch, self.version
        )
    }
}

// ─── TtdTrace ─────────────────────────────────────────────────────────────────

/// A complete TTD trace holding metadata and an ordered list of events.
pub struct TtdTrace {
    /// Metadata about the trace.
    pub metadata: TraceMetadata,
    events: RwLock<Vec<TraceEvent>>,
}

impl TtdTrace {
    /// Create a new, empty `TtdTrace` with the given metadata.
    #[must_use]
    pub const fn new(metadata: TraceMetadata) -> Self {
        Self {
            metadata,
            events: RwLock::new(Vec::new()),
        }
    }

    /// Append an event to the trace.
    pub fn add_event(&self, event: TraceEvent) {
        self.events.write().push(event);
    }

    /// Append an event to the trace (alias for [`Self::add_event`] taking
    /// `&mut self` for ergonomic chained construction in tests/builders).
    pub fn push_event(&mut self, event: TraceEvent) {
        self.events.write().push(event);
    }

    /// Return all events at exactly `pos`.
    #[must_use]
    pub fn events_at_position(&self, pos: TracePosition) -> Vec<TraceEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| e.position == pos)
            .cloned()
            .collect()
    }

    /// Return all events emitted by thread `tid`.
    #[must_use]
    pub fn events_for_thread(&self, tid: u32) -> Vec<TraceEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| e.thread_id == tid)
            .cloned()
            .collect()
    }

    /// Return all events whose positions fall in `[start, end)`.
    #[must_use]
    pub fn events_in_range(&self, start: TracePosition, end: TracePosition) -> Vec<TraceEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| e.position.in_range(&start, &end))
            .cloned()
            .collect()
    }

    /// Return all events whose [`EventKind`] matches the given discriminant
    /// name (e.g. `"Call"`, `"MemWrite"`).
    #[must_use]
    pub fn events_of_kind(&self, kind_name: &str) -> Vec<TraceEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| event_kind_name(&e.kind) == kind_name)
            .cloned()
            .collect()
    }

    /// Return a clone of all events in insertion order.
    #[must_use]
    pub fn all_events(&self) -> Vec<TraceEvent> {
        self.events.read().clone()
    }

    /// Return the number of events in the trace.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.read().len()
    }

    /// Return the position of the last event, or `None` if the trace is empty.
    #[must_use]
    pub fn last_position(&self) -> Option<TracePosition> {
        self.events.read().last().map(|e| e.position)
    }

    /// Return the set of thread IDs that appear in the trace.
    #[must_use]
    pub fn thread_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.events.read().iter().map(|e| e.thread_id).collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Sort events in-place by position.  Use this if events were added
    /// out-of-order (e.g. merged from multiple sources).
    pub fn sort_events(&self) {
        self.events.write().sort_by_key(|e| e.position);
    }
}

impl fmt::Debug for TtdTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TtdTrace")
            .field("metadata", &self.metadata)
            .field("event_count", &self.events.read().len())
            .finish_non_exhaustive()
    }
}

// ─── TtdSession ───────────────────────────────────────────────────────────────

/// An open TTD session that maintains a cursor over a trace.
pub struct TtdSession {
    trace: Arc<TtdTrace>,
    current_position: TracePosition,
    event_index: usize,
    /// Cached owned copy of the most recently visited event, kept so callers
    /// can borrow it without holding the trace's `RwLock` guard.
    last_event: Option<TraceEvent>,
}

impl TtdSession {
    /// Open a session at the start of the given trace.
    #[must_use]
    pub const fn open(trace: Arc<TtdTrace>) -> Self {
        Self {
            trace,
            current_position: TracePosition::start(),
            event_index: 0,
            last_event: None,
        }
    }

    /// Advance to the next event and return a reference to it.
    ///
    /// # Errors
    ///
    /// Returns [`TtdError::InvalidPosition`] if there are no more events.
    ///
    /// # Panics
    ///
    /// Panics if the just-stored last event slot is `None`; this cannot
    /// happen because the success path of this function always stores a
    /// fresh event into `last_event` before reading it.
    pub fn step_forward(&mut self) -> Result<&TraceEvent, TtdError> {
        let events = self.trace.events.read();
        if self.event_index >= events.len() {
            let pos = self.current_position;
            return Err(TtdError::InvalidPosition {
                seq: pos.sequence,
                step: pos.step,
            });
        }
        // Clone the event under the read guard, then drop it.  The clone is
        // stored in `self.last_event` so we can return a stable borrow without
        // any `unsafe` pointer juggling.
        let idx = self.event_index;
        let event = events[idx].clone();
        drop(events);
        self.current_position = event.position;
        self.event_index = idx + 1;
        self.last_event = Some(event);
        Ok(self.last_event.as_ref().expect("just stored"))
    }

    /// Step backward: decrease the event index and return the new position.
    ///
    /// # Errors
    ///
    /// Returns [`TtdError::InvalidPosition`] if already at the start.
    pub fn step_back(&mut self) -> Result<TracePosition, TtdError> {
        if self.event_index == 0 {
            return Err(TtdError::InvalidPosition { seq: 0, step: 0 });
        }
        self.event_index -= 1;
        let events = self.trace.events.read();
        let pos = if self.event_index == 0 {
            TracePosition::start()
        } else {
            events[self.event_index - 1].position
        };
        drop(events);
        self.current_position = pos;
        Ok(pos)
    }

    /// Seek to the given position.
    ///
    /// # Errors
    ///
    /// Returns [`TtdError::InvalidPosition`] if the position is not found.
    pub fn goto_position(&mut self, pos: TracePosition) -> Result<(), TtdError> {
        let events = self.trace.events.read();
        let idx =
            events
                .iter()
                .position(|e| e.position == pos)
                .ok_or(TtdError::InvalidPosition {
                    seq: pos.sequence,
                    step: pos.step,
                })?;
        drop(events);
        self.event_index = idx;
        self.current_position = pos;
        Ok(())
    }

    /// Return the current position in the trace.
    #[must_use]
    pub const fn current_position(&self) -> TracePosition {
        self.current_position
    }

    /// Return `true` if there are no more events to step forward into.
    #[must_use]
    pub fn is_at_end(&self) -> bool {
        self.event_index >= self.trace.event_count()
    }

    /// Return `true` if the session is at the very beginning of the trace.
    #[must_use]
    pub const fn is_at_start(&self) -> bool {
        self.event_index == 0
    }

    /// Peek at the next event without advancing the cursor.
    ///
    /// Returns `None` if the session is at the end.
    #[must_use]
    pub fn peek_next(&self) -> Option<TraceEvent> {
        let events = self.trace.events.read();
        events.get(self.event_index).cloned()
    }

    /// Step forward while `predicate` returns `true`, consuming all matching
    /// events. Returns the number of events skipped.
    ///
    /// # Errors
    ///
    /// Returns [`TtdError::InvalidPosition`] forwarded from [`step_forward`].
    pub fn skip_while<F>(&mut self, mut predicate: F) -> Result<usize, TtdError>
    where
        F: FnMut(&TraceEvent) -> bool,
    {
        let mut count = 0usize;
        loop {
            match self.peek_next() {
                Some(ref e) if predicate(e) => {
                    self.step_forward()?;
                    count += 1;
                }
                _ => break,
            }
        }
        Ok(count)
    }

    /// Collect all events from the current cursor position to the end of the
    /// trace, without advancing the cursor.
    #[must_use]
    pub fn remaining_events(&self) -> Vec<TraceEvent> {
        let events = self.trace.events.read();
        events[self.event_index..].to_vec()
    }

    /// Return the underlying trace.
    #[must_use]
    pub const fn trace(&self) -> &Arc<TtdTrace> {
        &self.trace
    }
}

impl fmt::Debug for TtdSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TtdSession")
            .field("current_position", &self.current_position)
            .field("event_index", &self.event_index)
            .field("at_end", &self.is_at_end())
            .finish_non_exhaustive()
    }
}

// ─── TtdIndex ─────────────────────────────────────────────────────────────────

/// SQLite-backed index for fast position lookups in large traces.
pub struct TtdIndex {
    conn: RwLock<Connection>,
}

impl TtdIndex {
    /// Open an in-memory `SQLite` database and create the schema.
    ///
    /// # Errors
    ///
    /// Returns [`TtdError::DatabaseError`] if the database cannot be opened or
    /// the schema cannot be created.
    pub fn open_in_memory() -> Result<Self, TtdError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                seq       INTEGER NOT NULL,
                step      INTEGER NOT NULL,
                thread_id INTEGER NOT NULL,
                kind      TEXT    NOT NULL,
                payload   TEXT    NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_pos ON events (seq, step);
            CREATE INDEX IF NOT EXISTS idx_tid ON events (thread_id);
            CREATE INDEX IF NOT EXISTS idx_kind ON events (kind);",
        )?;
        Ok(Self {
            conn: RwLock::new(conn),
        })
    }

    /// Index all events from `trace` into the `SQLite` database.
    ///
    /// # Errors
    ///
    /// Returns [`TtdError::DatabaseError`] or [`TtdError::SerdeError`] on
    /// failure.
    pub fn index_trace(&self, trace: &TtdTrace) -> Result<(), TtdError> {
        let events = trace.all_events();
        // Serialize payloads outside the DB lock so we minimise lock-hold time.
        let mut rows: Vec<(u64, u64, u32, &'static str, String)> = Vec::with_capacity(events.len());
        for event in &events {
            let kind_str = event_kind_name(&event.kind);
            let payload = serde_json::to_string(&event.kind)?;
            rows.push((
                event.position.sequence,
                event.position.step,
                event.thread_id,
                kind_str,
                payload,
            ));
        }
        let conn = self.conn.write();
        let mut stmt = conn.prepare(
            "INSERT INTO events (seq, step, thread_id, kind, payload) VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for (seq, step, tid, kind_str, payload) in &rows {
            stmt.execute(params![seq, step, tid, kind_str, payload])?;
        }
        drop(stmt);
        drop(conn);
        Ok(())
    }

    /// Find all events near `pos` (same sequence number).
    ///
    /// # Errors
    ///
    /// Returns [`TtdError::DatabaseError`] or [`TtdError::SerdeError`] on
    /// failure.
    pub fn find_events_near(&self, pos: &TracePosition) -> Result<Vec<TraceEvent>, TtdError> {
        let raw_rows: Vec<(u64, u64, u32, String)> = self
            .conn
            .read()
            .prepare(
                "SELECT seq, step, thread_id, payload FROM events WHERE seq = ?1 ORDER BY step",
            )?
            .query_map(params![pos.sequence], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut result = Vec::with_capacity(raw_rows.len());
        for (seq, step, tid, payload) in raw_rows {
            let kind: EventKind = serde_json::from_str(&payload).map_err(TtdError::SerdeError)?;
            result.push(TraceEvent {
                position: TracePosition::new(seq, step),
                thread_id: tid,
                kind,
            });
        }
        Ok(result)
    }

    /// Return all events of `kind_name` within `[start_seq, end_seq)`.
    ///
    /// # Errors
    ///
    /// Returns [`TtdError::DatabaseError`] or [`TtdError::SerdeError`] on
    /// failure.
    pub fn find_events_by_kind_in_range(
        &self,
        kind_name: &str,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<TraceEvent>, TtdError> {
        let raw_rows: Vec<(u64, u64, u32, String)> = self
            .conn
            .read()
            .prepare(
                "SELECT seq, step, thread_id, payload FROM events \
                 WHERE kind = ?1 AND seq >= ?2 AND seq < ?3 \
                 ORDER BY seq, step",
            )?
            .query_map(params![kind_name, start_seq, end_seq], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut result = Vec::with_capacity(raw_rows.len());
        for (seq, step, tid, payload) in raw_rows {
            let kind: EventKind = serde_json::from_str(&payload).map_err(TtdError::SerdeError)?;
            result.push(TraceEvent {
                position: TracePosition::new(seq, step),
                thread_id: tid,
                kind,
            });
        }
        Ok(result)
    }

    /// Return the count of events grouped by thread id.
    ///
    /// # Errors
    ///
    /// Returns [`TtdError::DatabaseError`] on failure.
    pub fn event_count_by_thread(&self) -> Result<HashMap<u32, u64>, TtdError> {
        let raw_rows: Vec<(u32, u64)> = self
            .conn
            .read()
            .prepare("SELECT thread_id, COUNT(*) FROM events GROUP BY thread_id")?
            .query_map([], |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u64>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(raw_rows.into_iter().collect())
    }

    /// Return the count of events grouped by kind name.
    ///
    /// # Errors
    ///
    /// Returns [`TtdError::DatabaseError`] on failure.
    pub fn event_count_by_kind(&self) -> Result<HashMap<String, u64>, TtdError> {
        let raw_rows: Vec<(String, u64)> = self
            .conn
            .read()
            .prepare("SELECT kind, COUNT(*) FROM events GROUP BY kind")?
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(raw_rows.into_iter().collect())
    }

    /// Return the total number of indexed events.
    ///
    /// # Errors
    ///
    /// Returns [`TtdError::DatabaseError`] on failure.
    pub fn total_event_count(&self) -> Result<u64, TtdError> {
        let count: u64 = self
            .conn
            .read()
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Clear all indexed events.
    ///
    /// # Errors
    ///
    /// Returns [`TtdError::DatabaseError`] on failure.
    pub fn clear(&self) -> Result<(), TtdError> {
        self.conn.write().execute("DELETE FROM events", [])?;
        Ok(())
    }
}

impl fmt::Debug for TtdIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TtdIndex").finish_non_exhaustive()
    }
}

// ─── MemoryMap ────────────────────────────────────────────────────────────────

/// A single mapped region in an address space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Start address (inclusive).
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Human-readable label (e.g. module name or `"[stack]"`).
    pub label: String,
    /// Whether this region is executable.
    pub executable: bool,
    /// Whether this region is writable.
    pub writable: bool,
}

impl MemoryRegion {
    /// Create a new `MemoryRegion`.
    #[must_use]
    pub fn new(start: u64, end: u64, label: impl Into<String>) -> Self {
        Self {
            start,
            end,
            label: label.into(),
            executable: false,
            writable: true,
        }
    }

    /// Return `true` if `addr` falls within this region.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Return the size of this region in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#018x}-{:#018x} {} {}{}",
            self.start,
            self.end,
            self.label,
            if self.executable { "x" } else { "-" },
            if self.writable { "w" } else { "-" },
        )
    }
}

/// Address-space map reconstructed from a TTD trace.
///
/// Builds the map by walking memory-write events and inferring regions.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MemoryMap {
    regions: Vec<MemoryRegion>,
}

impl MemoryMap {
    /// Create an empty `MemoryMap`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a region to the map.
    pub fn add_region(&mut self, region: MemoryRegion) {
        self.regions.push(region);
        self.regions.sort_by_key(|r| r.start);
    }

    /// Return the region containing `addr`, if any.
    #[must_use]
    pub fn region_at(&self, addr: u64) -> Option<&MemoryRegion> {
        // Binary search for the candidate region.
        let idx = self.regions.partition_point(|r| r.start <= addr);
        if idx == 0 {
            return None;
        }
        let r = &self.regions[idx - 1];
        if r.contains(addr) { Some(r) } else { None }
    }

    /// Return all regions.
    #[must_use]
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Build a `MemoryMap` by scanning write events in `trace`.  Each unique
    /// 4 KiB page touched by a write is recorded as a separate region.
    #[must_use]
    pub fn from_trace(trace: &TtdTrace) -> Self {
        const PAGE_SIZE: u64 = 4096;
        let mut pages: Vec<u64> = trace
            .all_events()
            .iter()
            .filter_map(|e| {
                if let EventKind::MemWrite { addr, .. } = e.kind {
                    Some(addr & !(PAGE_SIZE - 1))
                } else {
                    None
                }
            })
            .collect();
        pages.sort_unstable();
        pages.dedup();
        let mut map = Self::new();
        for page in pages {
            map.add_region(MemoryRegion {
                start: page,
                end: page + PAGE_SIZE,
                label: String::from("[data]"),
                executable: false,
                writable: true,
            });
        }
        map
    }
}

// ─── CallStack ────────────────────────────────────────────────────────────────

/// A frame on the reconstructed call stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFrame {
    /// Address of the call site.
    pub call_site: u64,
    /// Address of the called function.
    pub callee: u64,
    /// Position at which this frame was pushed.
    pub position: TracePosition,
}

impl fmt::Display for CallFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CallFrame {{ call_site: {:#x}, callee: {:#x}, at: {} }}",
            self.call_site, self.callee, self.position
        )
    }
}

/// Per-thread call-stack reconstructed by replaying call/return events.
#[derive(Debug, Default, Clone)]
pub struct CallStack {
    frames: Vec<CallFrame>,
}

impl CallStack {
    /// Create an empty `CallStack`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a frame (called when a `Call` event is seen).
    pub fn push(&mut self, frame: CallFrame) {
        self.frames.push(frame);
    }

    /// Pop a frame (called when a `Return` event is seen).
    /// Returns the popped frame, or `None` if the stack is empty.
    pub fn pop(&mut self) -> Option<CallFrame> {
        self.frames.pop()
    }

    /// Return the current depth of the call stack.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Return the top-most frame, if any.
    #[must_use]
    pub fn top(&self) -> Option<&CallFrame> {
        self.frames.last()
    }

    /// Return all frames from innermost to outermost (index 0 is the bottom).
    #[must_use]
    pub fn frames(&self) -> &[CallFrame] {
        &self.frames
    }

    /// Reconstruct the call stack for thread `tid` up to (and including)
    /// `up_to_pos` by replaying events from `trace`.
    #[must_use]
    pub fn from_trace(trace: &TtdTrace, tid: u32, up_to_pos: TracePosition) -> Self {
        let mut stack = Self::new();
        for event in trace.events_for_thread(tid) {
            if event.position > up_to_pos {
                break;
            }
            match event.kind {
                EventKind::Call { from, to } => {
                    stack.push(CallFrame {
                        call_site: from,
                        callee: to,
                        position: event.position,
                    });
                }
                EventKind::Return { .. } => {
                    stack.pop();
                }
                _ => {}
            }
        }
        stack
    }
}

// ─── TraceFilter ──────────────────────────────────────────────────────────────

/// A composable predicate for filtering [`TraceEvent`]s.
#[derive(Debug, Clone)]
pub enum TraceFilter {
    /// Accept all events from thread `tid`.
    ByThread(u32),
    /// Accept all events whose kind name matches the given string.
    ByKind(String),
    /// Accept events whose position is in `[start, end)`.
    ByRange(TracePosition, TracePosition),
    /// Accept events that touch an address in `[addr_start, addr_end)`.
    ByAddressRange(u64, u64),
    /// Logical AND of two sub-filters.
    And(Box<Self>, Box<Self>),
    /// Logical OR of two sub-filters.
    Or(Box<Self>, Box<Self>),
    /// Logical NOT of a sub-filter.
    Not(Box<Self>),
}

impl TraceFilter {
    /// Return `true` if `event` passes this filter.
    #[must_use]
    pub fn matches(&self, event: &TraceEvent) -> bool {
        match self {
            Self::ByThread(tid) => event.thread_id == *tid,
            Self::ByKind(k) => event_kind_name(&event.kind) == k.as_str(),
            Self::ByRange(start, end) => event.position.in_range(start, end),
            Self::ByAddressRange(lo, hi) => {
                event.kind.address().is_some_and(|a| a >= *lo && a < *hi)
            }
            Self::And(a, b) => a.matches(event) && b.matches(event),
            Self::Or(a, b) => a.matches(event) || b.matches(event),
            Self::Not(inner) => !inner.matches(event),
        }
    }

    /// Apply this filter to `events` and return matching events.
    #[must_use]
    pub fn apply(&self, events: &[TraceEvent]) -> Vec<TraceEvent> {
        events.iter().filter(|e| self.matches(e)).cloned().collect()
    }

    /// Convenience: combine `self AND other`.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        Self::And(Box::new(self), Box::new(other))
    }

    /// Convenience: combine `self OR other`.
    #[must_use]
    pub fn or(self, other: Self) -> Self {
        Self::Or(Box::new(self), Box::new(other))
    }

}

impl Not for TraceFilter {
    type Output = Self;
    /// Convenience: negate this filter.
    fn not(self) -> Self {
        Self::Not(Box::new(self))
    }
}

// ─── TraceStats ───────────────────────────────────────────────────────────────

/// Aggregate statistics over a `TtdTrace`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceStats {
    /// Total number of events.
    pub total_events: u64,
    /// Number of memory-read events.
    pub mem_reads: u64,
    /// Number of memory-write events.
    pub mem_writes: u64,
    /// Number of call events.
    pub calls: u64,
    /// Number of return events.
    pub returns: u64,
    /// Number of syscall-enter events.
    pub syscall_enters: u64,
    /// Number of exception events.
    pub exceptions: u64,
    /// Total bytes written across all `MemWrite` events.
    pub bytes_written: u64,
    /// Total bytes read across all `MemRead` events.
    pub bytes_read: u64,
    /// Number of distinct threads seen.
    pub thread_count: u64,
}

impl TraceStats {
    /// Compute statistics from a `TtdTrace`.
    #[must_use]
    pub fn compute(trace: &TtdTrace) -> Self {
        let events = trace.all_events();
        let mut stats = Self::default();
        let mut tids: Vec<u32> = Vec::new();
        for event in &events {
            stats.total_events += 1;
            if !tids.contains(&event.thread_id) {
                tids.push(event.thread_id);
            }
            match &event.kind {
                EventKind::MemRead { len, .. } => {
                    stats.mem_reads += 1;
                    stats.bytes_read += *len as u64;
                }
                EventKind::MemWrite { data, .. } => {
                    stats.mem_writes += 1;
                    stats.bytes_written += data.len() as u64;
                }
                EventKind::Call { .. } => stats.calls += 1,
                EventKind::Return { .. } => stats.returns += 1,
                EventKind::SyscallEnter { .. } => stats.syscall_enters += 1,
                EventKind::Exception { .. } => stats.exceptions += 1,
                _ => {}
            }
        }
        stats.thread_count = tids.len() as u64;
        stats
    }
}

impl fmt::Display for TraceStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TraceStats {{ total={}, reads={}, writes={}, calls={}, returns={}, \
             syscalls={}, exceptions={}, threads={} }}",
            self.total_events,
            self.mem_reads,
            self.mem_writes,
            self.calls,
            self.returns,
            self.syscall_enters,
            self.exceptions,
            self.thread_count,
        )
    }
}

// ─── TraceExporter ────────────────────────────────────────────────────────────

/// Serialise a `TtdTrace` to newline-delimited JSON (NDJSON).
///
/// The first line is the serialised [`TraceMetadata`].  Each subsequent line
/// is one serialised [`TraceEvent`].
pub struct TraceExporter;

impl TraceExporter {
    /// Write `trace` to `writer` in NDJSON format.
    ///
    /// # Errors
    ///
    /// Returns [`TtdError::SerdeError`] or [`TtdError::IoError`] on failure.
    pub fn export<W: IoWrite>(trace: &TtdTrace, mut writer: W) -> Result<(), TtdError> {
        let meta_json = serde_json::to_string(&trace.metadata)?;
        writeln!(writer, "{meta_json}")?;
        for event in trace.all_events() {
            let line = serde_json::to_string(&event)?;
            writeln!(writer, "{line}")?;
        }
        Ok(())
    }

    /// Export `trace` to a `String`.
    ///
    /// # Errors
    ///
    /// Returns [`TtdError::SerdeError`] or [`TtdError::IoError`] on failure.
    pub fn export_to_string(trace: &TtdTrace) -> Result<String, TtdError> {
        let mut buf = Vec::new();
        Self::export(trace, &mut buf)?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }
}

// ─── TraceImporter ────────────────────────────────────────────────────────────

/// Deserialise a `TtdTrace` from NDJSON written by [`TraceExporter`].
pub struct TraceImporter;

impl TraceImporter {
    /// Read NDJSON from `reader` and reconstruct a `TtdTrace`.
    ///
    /// # Errors
    ///
    /// Returns [`TtdError::CorruptTrace`] if the first line is missing or
    /// malformed, and [`TtdError::SerdeError`] for malformed event lines.
    pub fn import<R: BufRead>(reader: R) -> Result<TtdTrace, TtdError> {
        let mut lines = reader.lines();
        let first = lines
            .next()
            .ok_or_else(|| TtdError::CorruptTrace(String::from("empty input")))?
            .map_err(TtdError::IoError)?;
        let metadata: TraceMetadata = serde_json::from_str(&first).map_err(TtdError::SerdeError)?;
        let trace = TtdTrace::new(metadata);
        for line_result in lines {
            let line = line_result.map_err(TtdError::IoError)?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let event: TraceEvent = serde_json::from_str(line).map_err(TtdError::SerdeError)?;
            trace.add_event(event);
        }
        Ok(trace)
    }

    /// Parse a previously exported string.
    ///
    /// # Errors
    ///
    /// See [`Self::import`].
    pub fn import_from_str(s: &str) -> Result<TtdTrace, TtdError> {
        Self::import(s.as_bytes())
    }
}

// ─── Watchpoint ───────────────────────────────────────────────────────────────

/// Trigger condition for a [`Watchpoint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WatchpointKind {
    /// Trigger on memory reads.
    Read,
    /// Trigger on memory writes.
    Write,
    /// Trigger on both reads and writes.
    ReadWrite,
}

/// A data-access watchpoint that can be tested against recorded events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Watchpoint {
    /// Address to watch.
    pub address: u64,
    /// Size of the watched region in bytes.
    pub size: u64,
    /// Trigger condition.
    pub kind: WatchpointKind,
    /// Optional human-readable label.
    pub label: Option<String>,
}

impl Watchpoint {
    /// Create a new `Watchpoint`.
    #[must_use]
    pub const fn new(address: u64, size: u64, kind: WatchpointKind) -> Self {
        Self {
            address,
            size,
            kind,
            label: None,
        }
    }

    /// Attach a human-readable label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Return `true` if `event` triggers this watchpoint.
    #[must_use]
    pub const fn triggered_by(&self, event: &TraceEvent) -> bool {
        let (access_addr, access_len, is_write) = match &event.kind {
            EventKind::MemRead { addr, len } => (*addr, *len as u64, false),
            EventKind::MemWrite { addr, data } => (*addr, data.len() as u64, true),
            _ => return false,
        };
        // Check overlap: [access_addr, access_addr+access_len) ∩ [self.address, self.address+self.size)
        // Use saturating_add to avoid u64 wrapping when addresses or sizes are near u64::MAX.
        let overlaps = access_addr < self.address.saturating_add(self.size)
            && access_addr.saturating_add(access_len) > self.address;
        if !overlaps {
            return false;
        }
        match self.kind {
            WatchpointKind::Read => !is_write,
            WatchpointKind::Write => is_write,
            WatchpointKind::ReadWrite => true,
        }
    }

    /// Find all events in `trace` that trigger this watchpoint.
    #[must_use]
    pub fn find_hits(&self, trace: &TtdTrace) -> Vec<TraceEvent> {
        trace
            .all_events()
            .into_iter()
            .filter(|e| self.triggered_by(e))
            .collect()
    }
}

impl fmt::Display for Watchpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = self.label.as_deref().unwrap_or("(unlabelled)");
        write!(
            f,
            "Watchpoint {{ addr: {:#x}, size: {}, kind: {:?}, label: {} }}",
            self.address, self.size, self.kind, label
        )
    }
}

// ─── SyscallSummary ───────────────────────────────────────────────────────────

/// Aggregate information about a single syscall number observed in a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallInfo {
    /// Syscall number.
    pub nr: u32,
    /// Number of times this syscall was called.
    pub call_count: u64,
    /// All observed return values (deduplicated).
    pub return_values: Vec<u64>,
}

/// Aggregate syscall usage extracted from a `TtdTrace`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyscallSummary {
    /// Per-syscall information, indexed by syscall number.
    pub by_nr: HashMap<u32, SyscallInfo>,
}

impl SyscallSummary {
    /// Build a `SyscallSummary` from a trace by pairing `SyscallEnter` /
    /// `SyscallExit` events.
    #[must_use]
    pub fn from_trace(trace: &TtdTrace) -> Self {
        // Collect all syscall events per thread.
        let mut pending: HashMap<u32, Vec<u32>> = HashMap::new(); // tid -> stack of nr
        let mut summary = Self::default();

        for event in trace.all_events() {
            match event.kind {
                EventKind::SyscallEnter { nr, .. } => {
                    summary
                        .by_nr
                        .entry(nr)
                        .or_insert_with(|| SyscallInfo {
                            nr,
                            call_count: 0,
                            return_values: Vec::new(),
                        })
                        .call_count += 1;
                    pending.entry(event.thread_id).or_default().push(nr);
                }
                EventKind::SyscallExit { nr, ret } => {
                    if let Some(stack) = pending.get_mut(&event.thread_id) {
                        // Match by nr to handle nested / mismatched traces.
                        if let Some(pos) = stack.iter().rposition(|&n| n == nr) {
                            stack.remove(pos);
                        }
                    }
                    if let Some(info) = summary.by_nr.get_mut(&nr)
                        && !info.return_values.contains(&ret)
                    {
                        info.return_values.push(ret);
                    }
                }
                _ => {}
            }
        }
        summary
    }

    /// Return the total number of syscall invocations recorded.
    #[must_use]
    pub fn total_calls(&self) -> u64 {
        self.by_nr.values().map(|i| i.call_count).sum()
    }

    /// Return syscall numbers sorted by call count, descending.
    #[must_use]
    pub fn top_syscalls(&self) -> Vec<&SyscallInfo> {
        let mut v: Vec<&SyscallInfo> = self.by_nr.values().collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.call_count));
        v
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Return a short name string for the discriminant of an [`EventKind`].
const fn event_kind_name(kind: &EventKind) -> &'static str {
    match kind {
        EventKind::MemRead { .. } => "MemRead",
        EventKind::MemWrite { .. } => "MemWrite",
        EventKind::Call { .. } => "Call",
        EventKind::Return { .. } => "Return",
        EventKind::SyscallEnter { .. } => "SyscallEnter",
        EventKind::SyscallExit { .. } => "SyscallExit",
        EventKind::Exception { .. } => "Exception",
        EventKind::ThreadCreate { .. } => "ThreadCreate",
        EventKind::ThreadExit { .. } => "ThreadExit",
        EventKind::Breakpoint { .. } => "Breakpoint",
    }
}

/// Build a minimal synthetic trace with `n` events for testing.
#[must_use]
pub fn build_test_trace(n: u64) -> Arc<TtdTrace> {
    let meta = TraceMetadata {
        version: 1,
        process_name: String::from("test"),
        pid: 1234,
        arch: String::from("x86_64"),
        start_time: 0,
        end_time: n,
        thread_count: 1,
        start_position: TracePosition::start(),
        end_position: TracePosition::new(n, 0),
        thread_ids: vec![1],
    };
    let trace = Arc::new(TtdTrace::new(meta));
    for i in 0..n {
        let kind = if i.is_multiple_of(2) {
            EventKind::MemRead {
                addr: 0x1000 + i * 4,
                len: 4,
            }
        } else {
            EventKind::MemWrite {
                addr: 0x2000 + i * 4,
                data: vec![0xde, 0xad, 0xbe, 0xef],
            }
        };
        trace.add_event(TraceEvent {
            position: TracePosition::new(i, 0),
            thread_id: 1,
            kind,
        });
    }
    trace
}

/// Build a multi-thread synthetic trace for testing.
///
/// Thread 1 emits even-indexed events; thread 2 emits odd-indexed events.
#[must_use]
pub fn build_multi_thread_trace(n: u64) -> Arc<TtdTrace> {
    let meta = TraceMetadata {
        version: 1,
        process_name: String::from("mt-test"),
        pid: 5678,
        arch: String::from("x86_64"),
        start_time: 0,
        end_time: n,
        thread_count: 2,
        start_position: TracePosition::start(),
        end_position: TracePosition::new(n, 0),
        thread_ids: vec![1, 2],
    };
    let trace = Arc::new(TtdTrace::new(meta));
    for i in 0..n {
        let tid = if i.is_multiple_of(2) { 1u32 } else { 2u32 };
        trace.add_event(TraceEvent {
            position: TracePosition::new(i, 0),
            thread_id: tid,
            kind: EventKind::MemRead {
                addr: 0x4000 + i * 8,
                len: 8,
            },
        });
    }
    trace
}

// ─── TtdSequenceId ───────────────────────────────────────────────────────────

/// A position in a TTD trace expressed as `(major, minor)`.
///
/// `major` is the primary sequence counter (monotonically increasing with each
/// recorded instruction); `minor` is a sub-step within that instruction used
/// to disambiguate events that share the same major tick.
///
/// Implements [`Ord`] lexicographically so positions can be compared and sorted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TtdSequenceId {
    /// Primary (major) sequence counter.
    pub major: u64,
    /// Sub-step (minor) within the major tick.
    pub minor: u32,
}

impl TtdSequenceId {
    /// Construct a new `TtdSequenceId`.
    #[must_use]
    pub const fn new(major: u64, minor: u32) -> Self {
        Self { major, minor }
    }

    /// The canonical start-of-trace position `(0, 0)`.
    #[must_use]
    pub const fn start() -> Self {
        Self::new(0, 0)
    }

    /// Convert to a [`TracePosition`] (lossy: `minor` is widened to `u64`).
    #[must_use]
    pub fn to_trace_position(self) -> TracePosition {
        TracePosition::new(self.major, u64::from(self.minor))
    }
}

impl PartialOrd for TtdSequenceId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TtdSequenceId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
    }
}

impl fmt::Display for TtdSequenceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}

impl From<TracePosition> for TtdSequenceId {
    fn from(p: TracePosition) -> Self {
        Self::new(p.sequence, u32::try_from(p.step).unwrap_or(u32::MAX))
    }
}

// ─── TtdEventType ────────────────────────────────────────────────────────────

/// High-level category of a [`TraceEvent`], used by [`TtdEventFilter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TtdEventType {
    /// Any memory-read event.
    MemRead,
    /// Any memory-write event.
    MemWrite,
    /// A control-flow call.
    Call,
    /// A control-flow return.
    Return,
    /// Syscall entry.
    SyscallEnter,
    /// Syscall exit.
    SyscallExit,
    /// Hardware/software exception.
    Exception,
    /// Thread creation.
    ThreadCreate,
    /// Thread exit.
    ThreadExit,
    /// Software breakpoint.
    Breakpoint,
}

impl TtdEventType {
    /// Return `true` when `kind` matches this category.
    #[must_use]
    pub const fn matches_kind(&self, kind: &EventKind) -> bool {
        matches!(
            (self, kind),
            (Self::MemRead, EventKind::MemRead { .. })
                | (Self::MemWrite, EventKind::MemWrite { .. })
                | (Self::Call, EventKind::Call { .. })
                | (Self::Return, EventKind::Return { .. })
                | (Self::SyscallEnter, EventKind::SyscallEnter { .. })
                | (Self::SyscallExit, EventKind::SyscallExit { .. })
                | (Self::Exception, EventKind::Exception { .. })
                | (Self::ThreadCreate, EventKind::ThreadCreate { .. })
                | (Self::ThreadExit, EventKind::ThreadExit { .. })
                | (Self::Breakpoint, EventKind::Breakpoint { .. })
        )
    }
}

// ─── TtdEventFilter ──────────────────────────────────────────────────────────

/// A fluent, composable filter for [`TraceEvent`] slices.
///
/// Build it with method chaining:
///
/// ```ignore
/// let filter = TtdEventFilter::new()
///     .at_address(0x401000)
///     .of_type(TtdEventType::Call);
/// let hits = filter.apply(&events);
/// ```
#[derive(Debug, Clone, Default)]
pub struct TtdEventFilter {
    address: Option<u64>,
    event_type: Option<TtdEventType>,
    range: Option<(TtdSequenceId, TtdSequenceId)>,
}

impl TtdEventFilter {
    /// Create a new filter that accepts every event.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict to events whose primary address equals `addr`.
    ///
    /// For `Call`/`Return` the *from* address is used as the primary address,
    /// consistent with [`EventKind::address`].
    #[must_use]
    pub const fn at_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    /// Restrict to events of the given [`TtdEventType`].
    #[must_use]
    pub const fn of_type(mut self, t: TtdEventType) -> Self {
        self.event_type = Some(t);
        self
    }

    /// Restrict to events whose position falls in `[start, end]` (inclusive).
    #[must_use]
    pub const fn in_range(mut self, start: TtdSequenceId, end: TtdSequenceId) -> Self {
        self.range = Some((start, end));
        self
    }

    /// Return `true` if `event` passes all active constraints.
    #[must_use]
    pub fn matches(&self, event: &TraceEvent) -> bool {
        if let Some(addr) = self.address
            && event.kind.address() != Some(addr) {
                return false;
            }
        if let Some(ref et) = self.event_type
            && !et.matches_kind(&event.kind) {
                return false;
            }
        if let Some((ref start, ref end)) = self.range {
            let pos = TtdSequenceId::from(event.position);
            if pos < *start || pos > *end {
                return false;
            }
        }
        true
    }

    /// Filter `events` and return references to the matching ones.
    #[must_use]
    pub fn apply<'a>(&self, events: &'a [TraceEvent]) -> Vec<&'a TraceEvent> {
        events.iter().filter(|e| self.matches(e)).collect()
    }
}

// ─── TtdFunctionCall ─────────────────────────────────────────────────────────

/// A reconstructed function call extracted from a TTD trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdFunctionCall {
    /// Address of the call site (caller).
    pub caller_addr: u64,
    /// Address of the call target (callee).
    pub callee_addr: u64,
    /// Position in the trace at which the `Call` event occurred.
    pub sequence: TtdSequenceId,
    /// Return address (the `to` field of the matching `Return` event, if found).
    pub return_addr: u64,
    /// Return value, if the matching `Return` event could be resolved to a value.
    ///
    /// This crate records raw trace events and does not model registers, so
    /// `return_value` is populated only when a `SyscallExit` whose `nr` matches
    /// a preceding `SyscallEnter` is found at the same depth.  For ordinary
    /// `Call`/`Return` pairs this is `None`.
    pub return_value: Option<u64>,
}

impl fmt::Display for TtdFunctionCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TtdFunctionCall {{ caller: {:#x}, callee: {:#x}, seq: {}, ret_addr: {:#x} }}",
            self.caller_addr, self.callee_addr, self.sequence, self.return_addr,
        )
    }
}

/// Extracts [`TtdFunctionCall`] records by replaying `Call`/`Return` pairs in
/// the event stream.
pub struct TtdCallExtractor;

impl TtdCallExtractor {
    /// Walk `events` in order and pair each `Call` with its nearest following
    /// `Return` that unwinds the stack by one frame.
    ///
    /// Calls that have no matching return (e.g. tail calls or truncated traces)
    /// are still emitted with `return_addr = 0`.
    #[must_use]
    pub fn extract_calls(events: &[TraceEvent]) -> Vec<TtdFunctionCall> {
        // Stack of (TtdFunctionCall-in-progress, depth) entries.
        let mut stack: Vec<TtdFunctionCall> = Vec::new();
        let mut completed: Vec<TtdFunctionCall> = Vec::new();

        for event in events {
            match &event.kind {
                EventKind::Call { from, to } => {
                    stack.push(TtdFunctionCall {
                        caller_addr: *from,
                        callee_addr: *to,
                        sequence: TtdSequenceId::from(event.position),
                        return_addr: 0,
                        return_value: None,
                    });
                }
                EventKind::Return { from: _, to } => {
                    if let Some(mut call) = stack.pop() {
                        call.return_addr = *to;
                        completed.push(call);
                    }
                }
                EventKind::SyscallExit { nr, ret } => {
                    // Pair with the most recent SyscallEnter of the same nr on the
                    // stack.  We represent syscalls as synthetic calls whose
                    // `caller_addr` and `callee_addr` are both `0` and whose
                    // `return_value` holds the syscall return value.
                    if let Some(pos) = stack.iter().rposition(|c| {
                        // We stored nr in callee_addr for syscall synthetic entries.
                        c.caller_addr == u64::MAX && c.callee_addr == u64::from(*nr)
                    }) {
                        let mut call = stack.remove(pos);
                        call.return_value = Some(*ret);
                        completed.push(call);
                    }
                }
                EventKind::SyscallEnter { nr, .. } => {
                    // Push a synthetic entry; caller_addr = u64::MAX signals syscall.
                    stack.push(TtdFunctionCall {
                        caller_addr: u64::MAX,
                        callee_addr: u64::from(*nr),
                        sequence: TtdSequenceId::from(event.position),
                        return_addr: 0,
                        return_value: None,
                    });
                }
                _ => {}
            }
        }

        // Emit any unmatched calls (no return seen before end of trace).
        for call in stack {
            completed.push(call);
        }

        completed.sort_by_key(|c| c.sequence);
        completed
    }
}

// ─── TtdMemoryTimeline ───────────────────────────────────────────────────────

/// Tracks memory writes to individual addresses over trace time.
///
/// Each `MemWrite` event is recorded as a `(TtdSequenceId, bytes)` entry
/// associated with the written address.  The timeline can then answer
/// questions like "what are all the values that were written to `0xdeadbeef`?"
/// and "at what position was `0xdeadbeef` first written after sequence X?".
#[derive(Debug, Default)]
pub struct TtdMemoryTimeline {
    // addr -> sorted vec of (seq, bytes)
    writes: HashMap<u64, Vec<(TtdSequenceId, Vec<u8>)>>,
}

impl TtdMemoryTimeline {
    /// Create an empty `TtdMemoryTimeline`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a write of `bytes` to `addr` at position `seq`.
    ///
    /// Entries are kept in insertion order; call [`Self::sort`] afterwards if
    /// you need history queries to work correctly on out-of-order inserts.
    pub fn add_write(&mut self, seq: TtdSequenceId, addr: u64, bytes: Vec<u8>) {
        self.writes.entry(addr).or_default().push((seq, bytes));
    }

    /// Populate the timeline from all `MemWrite` events in `trace`.
    #[must_use]
    pub fn from_trace(trace: &TtdTrace) -> Self {
        let mut timeline = Self::new();
        for event in trace.all_events() {
            if let EventKind::MemWrite { addr, data } = event.kind {
                timeline.add_write(TtdSequenceId::from(event.position), addr, data);
            }
        }
        timeline.sort();
        timeline
    }

    /// Sort all per-address write histories by sequence position.
    pub fn sort(&mut self) {
        for vec in self.writes.values_mut() {
            vec.sort_by_key(|(seq, _)| *seq);
        }
    }

    /// Return all writes to `addr` in chronological order, as
    /// `(sequence, bytes)` pairs.  Returns an empty `Vec` when the address
    /// has never been written.
    #[must_use]
    pub fn history_at(&self, addr: u64) -> Vec<(TtdSequenceId, Vec<u8>)> {
        self.writes.get(&addr).cloned().unwrap_or_default()
    }

    /// Return the sequence ID of the first write to `addr` that occurs
    /// **strictly after** `seq`, or `None` when no such write exists.
    #[must_use]
    pub fn find_first_write_after(&self, addr: u64, seq: TtdSequenceId) -> Option<TtdSequenceId> {
        let history = self.writes.get(&addr)?;
        history.iter().find(|(s, _)| *s > seq).map(|(s, _)| *s)
    }

    /// Return the set of addresses that have at least one recorded write.
    #[must_use]
    pub fn written_addresses(&self) -> Vec<u64> {
        let mut addrs: Vec<u64> = self.writes.keys().copied().collect();
        addrs.sort_unstable();
        addrs
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use super::*;

    // ── TracePosition ─────────────────────────────────────────────────────────

    #[test]
    fn trace_position_new() {
        let p = TracePosition::new(3, 7);
        assert_eq!(p.sequence, 3);
        assert_eq!(p.step, 7);
    }

    #[test]
    fn trace_position_start_is_zero() {
        let p = TracePosition::start();
        assert_eq!(p.sequence, 0);
        assert_eq!(p.step, 0);
    }

    #[test]
    fn trace_position_next_sequence() {
        let p = TracePosition::new(4, 9).next_sequence();
        assert_eq!(p.sequence, 5);
        assert_eq!(p.step, 0);
    }

    #[test]
    fn trace_position_next_step() {
        let p = TracePosition::new(4, 9).next_step();
        assert_eq!(p.sequence, 4);
        assert_eq!(p.step, 10);
    }

    #[test]
    fn trace_position_display() {
        let p = TracePosition::new(1, 2);
        assert_eq!(p.to_string(), "1:2");
    }

    #[test]
    fn trace_position_ordering() {
        let a = TracePosition::new(1, 0);
        let b = TracePosition::new(1, 1);
        let c = TracePosition::new(2, 0);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn trace_position_is_before_after() {
        let a = TracePosition::new(1, 0);
        let b = TracePosition::new(2, 0);
        assert!(a.is_before(&b));
        assert!(b.is_after(&a));
    }

    #[test]
    fn trace_position_in_range() {
        let start = TracePosition::new(2, 0);
        let end = TracePosition::new(5, 0);
        assert!(TracePosition::new(3, 0).in_range(&start, &end));
        assert!(!TracePosition::new(1, 0).in_range(&start, &end));
        assert!(!TracePosition::new(5, 0).in_range(&start, &end)); // exclusive
    }

    #[test]
    fn trace_position_u128_roundtrip() {
        let p = TracePosition::new(0xDEAD, 0xBEEF);
        let v = p.as_u128();
        let p2 = TracePosition::from_u128(v);
        assert_eq!(p, p2);
    }

    // ── MemorySnapshot ────────────────────────────────────────────────────────

    #[test]
    fn memory_snapshot_display() {
        let s = MemorySnapshot {
            address: 0x1000,
            data: vec![0u8; 16],
        };
        let d = s.to_string();
        assert!(d.contains("0x1000"));
        assert!(d.contains("16"));
    }

    #[test]
    fn memory_snapshot_read_u8() {
        let s = MemorySnapshot::new(0x100, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(s.read_u8(0x100), Some(0xAA));
        assert_eq!(s.read_u8(0x102), Some(0xCC));
        assert_eq!(s.read_u8(0x103), None);
    }

    #[test]
    fn memory_snapshot_read_u32_le() {
        let s = MemorySnapshot::new(0x0, vec![0x01, 0x00, 0x00, 0x00]);
        assert_eq!(s.read_u32_le(0x0), Some(1));
    }

    #[test]
    fn memory_snapshot_apply_write() {
        let mut s = MemorySnapshot::new(0x0, vec![0u8; 8]);
        let n = s.apply_write(0x2, &[0xDE, 0xAD]);
        assert_eq!(n, 2);
        assert_eq!(s.data[2], 0xDE);
        assert_eq!(s.data[3], 0xAD);
    }

    #[test]
    fn memory_snapshot_apply_write_out_of_range() {
        let mut s = MemorySnapshot::new(0x100, vec![0u8; 4]);
        let n = s.apply_write(0x200, &[0xFF]);
        assert_eq!(n, 0);
    }

    // ── ThreadState ──────────────────────────────────────────────────────────

    #[test]
    fn thread_state_display() {
        let ts = ThreadState {
            tid: 42,
            registers: HashMap::new(),
            stack_pointer: 0xffff_0000,
            instruction_pointer: 0x4000,
        };
        let d = ts.to_string();
        assert!(d.contains("42"));
        assert!(d.contains("0x4000"));
    }

    #[test]
    fn thread_state_set_get_register() {
        let mut ts = ThreadState::new(1);
        ts.set_register("rax", 0xDEAD);
        assert_eq!(ts.get_register("rax"), Some(0xDEAD));
        assert_eq!(ts.get_register("rbx"), None);
    }

    // ── EventKind ────────────────────────────────────────────────────────────

    #[test]
    fn event_kind_display_mem_read() {
        let k = EventKind::MemRead {
            addr: 0x100,
            len: 8,
        };
        assert!(k.to_string().contains("MemRead"));
    }

    #[test]
    fn event_kind_display_mem_write() {
        let k = EventKind::MemWrite {
            addr: 0x200,
            data: vec![1, 2, 3],
        };
        assert!(k.to_string().contains("MemWrite"));
        assert!(k.to_string().contains("3B"));
    }

    #[test]
    fn event_kind_display_call() {
        let k = EventKind::Call {
            from: 0x10,
            to: 0x20,
        };
        assert!(k.to_string().contains("Call"));
    }

    #[test]
    fn event_kind_display_syscall() {
        let k = EventKind::SyscallEnter {
            nr: 1,
            args: [0; 6],
        };
        assert!(k.to_string().contains("SyscallEnter"));
        assert!(k.to_string().contains("nr=1"));
    }

    #[test]
    fn event_kind_display_exception() {
        let k = EventKind::Exception {
            code: 0xc000_0005,
            addr: 0xdead_beef,
        };
        assert!(k.to_string().contains("Exception"));
    }

    #[test]
    fn event_kind_display_thread_create() {
        let k = EventKind::ThreadCreate { tid: 7 };
        assert!(k.to_string().contains("ThreadCreate"));
        assert!(k.to_string().contains('7'));
    }

    #[test]
    fn event_kind_display_thread_exit() {
        let k = EventKind::ThreadExit { tid: 7, code: 0 };
        assert!(k.to_string().contains("ThreadExit"));
    }

    #[test]
    fn event_kind_display_breakpoint() {
        let k = EventKind::Breakpoint { addr: 0x5000 };
        assert!(k.to_string().contains("Breakpoint"));
        assert!(k.to_string().contains("0x5000"));
    }

    #[test]
    fn event_kind_predicates() {
        assert!(EventKind::MemRead { addr: 0, len: 0 }.is_memory_access());
        assert!(
            EventKind::MemWrite {
                addr: 0,
                data: vec![]
            }
            .is_memory_access()
        );
        assert!(EventKind::Call { from: 0, to: 0 }.is_control_flow());
        assert!(EventKind::Return { from: 0, to: 0 }.is_control_flow());
        assert!(
            EventKind::SyscallEnter {
                nr: 0,
                args: [0; 6]
            }
            .is_syscall()
        );
        assert!(EventKind::SyscallExit { nr: 0, ret: 0 }.is_syscall());
        assert!(EventKind::ThreadCreate { tid: 0 }.is_thread_lifecycle());
        assert!(EventKind::ThreadExit { tid: 0, code: 0 }.is_thread_lifecycle());
    }

    #[test]
    fn event_kind_address() {
        assert_eq!(
            EventKind::MemRead {
                addr: 0x1234,
                len: 4
            }
            .address(),
            Some(0x1234)
        );
        assert_eq!(
            EventKind::Call {
                from: 0xAB,
                to: 0xCD
            }
            .address(),
            Some(0xAB)
        );
        assert_eq!(
            EventKind::SyscallEnter {
                nr: 0,
                args: [0; 6]
            }
            .address(),
            None
        );
    }

    // ── TraceEvent ───────────────────────────────────────────────────────────

    #[test]
    fn trace_event_display() {
        let e = TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::Breakpoint { addr: 0x1234 },
        };
        let d = e.to_string();
        assert!(d.contains("0:0"));
        assert!(d.contains("tid=1"));
    }

    // ── TraceMetadata ────────────────────────────────────────────────────────

    #[test]
    fn trace_metadata_default() {
        let m = TraceMetadata::default();
        assert_eq!(m.version, 1);
        assert_eq!(m.thread_count, 1);
        assert_eq!(m.arch, "x86_64");
    }

    #[test]
    fn trace_metadata_display() {
        let m = TraceMetadata::default();
        let d = m.to_string();
        assert!(d.contains("TraceMetadata"));
    }

    // ── TtdTrace ─────────────────────────────────────────────────────────────

    #[test]
    fn ttd_trace_empty() {
        let t = TtdTrace::new(TraceMetadata::default());
        assert_eq!(t.event_count(), 0);
        assert!(t.last_position().is_none());
    }

    #[test]
    fn ttd_trace_add_and_query() {
        let t = TtdTrace::new(TraceMetadata::default());
        t.add_event(TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::MemRead {
                addr: 0x100,
                len: 4,
            },
        });
        t.add_event(TraceEvent {
            position: TracePosition::new(1, 0),
            thread_id: 2,
            kind: EventKind::MemWrite {
                addr: 0x200,
                data: vec![0],
            },
        });
        assert_eq!(t.event_count(), 2);
        assert_eq!(t.last_position(), Some(TracePosition::new(1, 0)));
    }

    #[test]
    fn ttd_trace_events_at_position() {
        let t = build_test_trace(5);
        let evts = t.events_at_position(TracePosition::new(2, 0));
        assert_eq!(evts.len(), 1);
        assert_eq!(evts[0].position.sequence, 2);
    }

    #[test]
    fn ttd_trace_events_for_thread() {
        let t = build_test_trace(10);
        // All events use tid=1 in build_test_trace
        let evts = t.events_for_thread(1);
        assert_eq!(evts.len(), 10);
        let none = t.events_for_thread(999);
        assert!(none.is_empty());
    }

    #[test]
    fn ttd_trace_debug() {
        let t = build_test_trace(3);
        let d = format!("{t:?}");
        assert!(d.contains("TtdTrace"));
        assert!(d.contains("event_count"));
    }

    #[test]
    fn ttd_trace_events_in_range() {
        let t = build_test_trace(10);
        let start = TracePosition::new(2, 0);
        let end = TracePosition::new(5, 0);
        let evts = t.events_in_range(start, end);
        assert_eq!(evts.len(), 3); // seq 2, 3, 4
    }

    #[test]
    fn ttd_trace_events_of_kind() {
        let t = build_test_trace(10);
        let reads = t.events_of_kind("MemRead");
        let writes = t.events_of_kind("MemWrite");
        assert_eq!(reads.len() + writes.len(), 10);
    }

    #[test]
    fn ttd_trace_thread_ids() {
        let t = build_multi_thread_trace(6);
        let mut ids = t.thread_ids();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn ttd_trace_sort_events() {
        let t = TtdTrace::new(TraceMetadata::default());
        t.add_event(TraceEvent::new(
            TracePosition::new(5, 0),
            1,
            EventKind::Breakpoint { addr: 0 },
        ));
        t.add_event(TraceEvent::new(
            TracePosition::new(1, 0),
            1,
            EventKind::Breakpoint { addr: 0 },
        ));
        t.sort_events();
        let all = t.all_events();
        assert!(all[0].position <= all[1].position);
    }

    // ── TtdSession ───────────────────────────────────────────────────────────

    #[test]
    fn ttd_session_open() {
        let trace = build_test_trace(3);
        let sess = TtdSession::open(trace);
        assert!(sess.is_at_start());
        assert!(!sess.is_at_end());
        assert_eq!(sess.current_position(), TracePosition::start());
    }

    #[test]
    fn ttd_session_step_forward() {
        let trace = build_test_trace(3);
        let mut sess = TtdSession::open(trace);
        let e = sess.step_forward().expect("step forward");
        assert_eq!(e.position, TracePosition::new(0, 0));
    }

    #[test]
    fn ttd_session_step_to_end() {
        let trace = build_test_trace(3);
        let mut sess = TtdSession::open(trace);
        for _ in 0..3 {
            sess.step_forward().expect("step");
        }
        assert!(sess.is_at_end());
        assert!(sess.step_forward().is_err());
    }

    #[test]
    fn ttd_session_step_back_at_start_is_err() {
        let trace = build_test_trace(3);
        let mut sess = TtdSession::open(trace);
        assert!(sess.step_back().is_err());
    }

    #[test]
    fn ttd_session_step_back() {
        let trace = build_test_trace(5);
        let mut sess = TtdSession::open(trace);
        sess.step_forward().unwrap();
        sess.step_forward().unwrap();
        let pos = sess.step_back().expect("step back");
        assert_eq!(pos, TracePosition::new(0, 0));
    }

    #[test]
    fn ttd_session_goto_position() {
        let trace = build_test_trace(10);
        let mut sess = TtdSession::open(trace);
        sess.goto_position(TracePosition::new(5, 0)).expect("goto");
        assert_eq!(sess.current_position(), TracePosition::new(5, 0));
    }

    #[test]
    fn ttd_session_goto_invalid_position() {
        let trace = build_test_trace(3);
        let mut sess = TtdSession::open(trace);
        assert!(sess.goto_position(TracePosition::new(999, 0)).is_err());
    }

    #[test]
    fn ttd_session_debug() {
        let trace = build_test_trace(2);
        let sess = TtdSession::open(trace);
        let d = format!("{sess:?}");
        assert!(d.contains("TtdSession"));
    }

    #[test]
    fn ttd_session_peek_next() {
        let trace = build_test_trace(4);
        let sess = TtdSession::open(trace);
        let peeked = sess.peek_next();
        assert!(peeked.is_some());
        assert_eq!(peeked.unwrap().position, TracePosition::new(0, 0));
    }

    #[test]
    fn ttd_session_skip_while() {
        let trace = build_test_trace(10);
        let mut sess = TtdSession::open(trace);
        let skipped = sess
            .skip_while(|e| e.kind.is_memory_access())
            .expect("skip_while");
        assert_eq!(skipped, 10); // all events are memory accesses in build_test_trace
        assert!(sess.is_at_end());
    }

    #[test]
    fn ttd_session_remaining_events() {
        let trace = build_test_trace(5);
        let mut sess = TtdSession::open(trace);
        sess.step_forward().unwrap();
        sess.step_forward().unwrap();
        let remaining = sess.remaining_events();
        assert_eq!(remaining.len(), 3);
    }

    // ── TtdIndex ─────────────────────────────────────────────────────────────

    #[test]
    fn ttd_index_open_in_memory() {
        let idx = TtdIndex::open_in_memory().expect("open");
        let _ = format!("{idx:?}"); // exercise Debug
    }

    #[test]
    fn ttd_index_index_and_find() {
        let trace = build_test_trace(10);
        let idx = TtdIndex::open_in_memory().unwrap();
        idx.index_trace(&trace).unwrap();
        let evts = idx.find_events_near(&TracePosition::new(3, 0)).unwrap();
        assert!(!evts.is_empty());
        assert_eq!(evts[0].position.sequence, 3);
    }

    #[test]
    fn ttd_index_event_count_by_thread() {
        let trace = build_test_trace(10);
        let idx = TtdIndex::open_in_memory().unwrap();
        idx.index_trace(&trace).unwrap();
        let counts = idx.event_count_by_thread().unwrap();
        assert_eq!(counts.get(&1).copied().unwrap_or(0), 10);
    }

    #[test]
    fn ttd_index_find_empty_sequence() {
        let trace = build_test_trace(5);
        let idx = TtdIndex::open_in_memory().unwrap();
        idx.index_trace(&trace).unwrap();
        let evts = idx.find_events_near(&TracePosition::new(999, 0)).unwrap();
        assert!(evts.is_empty());
    }

    #[test]
    fn ttd_index_event_count_by_kind() {
        let trace = build_test_trace(10);
        let idx = TtdIndex::open_in_memory().unwrap();
        idx.index_trace(&trace).unwrap();
        let counts = idx.event_count_by_kind().unwrap();
        assert_eq!(
            counts.get("MemRead").copied().unwrap_or(0)
                + counts.get("MemWrite").copied().unwrap_or(0),
            10
        );
    }

    #[test]
    fn ttd_index_total_event_count() {
        let trace = build_test_trace(7);
        let idx = TtdIndex::open_in_memory().unwrap();
        idx.index_trace(&trace).unwrap();
        assert_eq!(idx.total_event_count().unwrap(), 7);
    }

    #[test]
    fn ttd_index_clear() {
        let trace = build_test_trace(5);
        let idx = TtdIndex::open_in_memory().unwrap();
        idx.index_trace(&trace).unwrap();
        idx.clear().unwrap();
        assert_eq!(idx.total_event_count().unwrap(), 0);
    }

    #[test]
    fn ttd_index_find_events_by_kind_in_range() {
        let trace = build_test_trace(10);
        let idx = TtdIndex::open_in_memory().unwrap();
        idx.index_trace(&trace).unwrap();
        let evts = idx.find_events_by_kind_in_range("MemRead", 0, 6).unwrap();
        // Even sequences 0,2,4 => 3 MemRead events in [0,6)
        assert_eq!(evts.len(), 3);
    }

    // ── TtdError ─────────────────────────────────────────────────────────────

    #[test]
    fn ttd_error_display_trace_not_open() {
        let e = TtdError::TraceNotOpen;
        assert_eq!(e.to_string(), "trace not open");
    }

    #[test]
    fn ttd_error_display_invalid_position() {
        let e = TtdError::InvalidPosition { seq: 1, step: 2 };
        assert!(e.to_string().contains("seq=1"));
        assert!(e.to_string().contains("step=2"));
    }

    #[test]
    fn ttd_error_display_corrupt_trace() {
        let e = TtdError::CorruptTrace(String::from("bad magic"));
        assert!(e.to_string().contains("bad magic"));
    }

    #[test]
    fn ttd_error_display_unsupported_version() {
        let e = TtdError::UnsupportedVersion(99);
        assert!(e.to_string().contains("99"));
    }

    // ── Serde round-trip ──────────────────────────────────────────────────────

    #[test]
    fn trace_position_serde_roundtrip() {
        let p = TracePosition::new(7, 3);
        let json = serde_json::to_string(&p).unwrap();
        let p2: TracePosition = serde_json::from_str(&json).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn trace_event_serde_roundtrip() {
        let e = TraceEvent {
            position: TracePosition::new(1, 0),
            thread_id: 5,
            kind: EventKind::Call {
                from: 0x100,
                to: 0x200,
            },
        };
        let json = serde_json::to_string(&e).unwrap();
        let e2: TraceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e2.position, e.position);
        assert_eq!(e2.thread_id, e.thread_id);
    }

    #[test]
    fn event_kind_name_all_variants() {
        let variants: Vec<(&'static str, EventKind)> = vec![
            ("MemRead", EventKind::MemRead { addr: 0, len: 0 }),
            (
                "MemWrite",
                EventKind::MemWrite {
                    addr: 0,
                    data: vec![],
                },
            ),
            ("Call", EventKind::Call { from: 0, to: 0 }),
            ("Return", EventKind::Return { from: 0, to: 0 }),
            (
                "SyscallEnter",
                EventKind::SyscallEnter {
                    nr: 0,
                    args: [0; 6],
                },
            ),
            ("SyscallExit", EventKind::SyscallExit { nr: 0, ret: 0 }),
            ("Exception", EventKind::Exception { code: 0, addr: 0 }),
            ("ThreadCreate", EventKind::ThreadCreate { tid: 0 }),
            ("ThreadExit", EventKind::ThreadExit { tid: 0, code: 0 }),
            ("Breakpoint", EventKind::Breakpoint { addr: 0 }),
        ];
        for (expected, kind) in &variants {
            assert_eq!(event_kind_name(kind), *expected);
        }
    }

    #[test]
    fn build_test_trace_helper() {
        let t = build_test_trace(20);
        assert_eq!(t.event_count(), 20);
        let all = t.all_events();
        assert_eq!(all.len(), 20);
    }

    // ── MemoryMap ─────────────────────────────────────────────────────────────

    #[test]
    fn memory_region_contains() {
        let r = MemoryRegion::new(0x1000, 0x2000, "test");
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1FFF));
        assert!(!r.contains(0x2000));
    }

    #[test]
    fn memory_region_size() {
        let r = MemoryRegion::new(0x1000, 0x3000, "test");
        assert_eq!(r.size(), 0x2000);
    }

    #[test]
    fn memory_region_display() {
        let r = MemoryRegion::new(0x1000, 0x2000, "heap");
        let s = r.to_string();
        assert!(s.contains("heap"));
    }

    #[test]
    fn memory_map_region_at() {
        let mut map = MemoryMap::new();
        map.add_region(MemoryRegion::new(0x1000, 0x2000, "a"));
        map.add_region(MemoryRegion::new(0x3000, 0x4000, "b"));
        assert!(map.region_at(0x1500).is_some());
        assert_eq!(map.region_at(0x1500).unwrap().label, "a");
        assert!(map.region_at(0x2500).is_none());
    }

    #[test]
    fn memory_map_from_trace() {
        let t = build_test_trace(10);
        let map = MemoryMap::from_trace(&t);
        // Some write events should have produced pages.
        assert!(!map.regions().is_empty());
    }

    // ── CallStack ─────────────────────────────────────────────────────────────

    #[test]
    fn call_stack_push_pop() {
        let mut cs = CallStack::new();
        cs.push(CallFrame {
            call_site: 0x100,
            callee: 0x200,
            position: TracePosition::new(0, 0),
        });
        assert_eq!(cs.depth(), 1);
        assert_eq!(cs.top().unwrap().callee, 0x200);
        let f = cs.pop().unwrap();
        assert_eq!(f.call_site, 0x100);
        assert_eq!(cs.depth(), 0);
        assert!(cs.pop().is_none());
    }

    #[test]
    fn call_stack_from_trace() {
        let trace = TtdTrace::new(TraceMetadata::default());
        trace.add_event(TraceEvent::new(
            TracePosition::new(0, 0),
            1,
            EventKind::Call {
                from: 0x100,
                to: 0x200,
            },
        ));
        trace.add_event(TraceEvent::new(
            TracePosition::new(1, 0),
            1,
            EventKind::Call {
                from: 0x210,
                to: 0x300,
            },
        ));
        trace.add_event(TraceEvent::new(
            TracePosition::new(2, 0),
            1,
            EventKind::Return {
                from: 0x300,
                to: 0x215,
            },
        ));
        let cs = CallStack::from_trace(&trace, 1, TracePosition::new(2, 0));
        assert_eq!(cs.depth(), 1);
        assert_eq!(cs.top().unwrap().callee, 0x200);
    }

    // ── TraceFilter ───────────────────────────────────────────────────────────

    #[test]
    fn trace_filter_by_thread() {
        let trace = build_multi_thread_trace(10);
        let all = trace.all_events();
        let f = TraceFilter::ByThread(1);
        let filtered = f.apply(&all);
        assert!(filtered.iter().all(|e| e.thread_id == 1));
    }

    #[test]
    fn trace_filter_by_kind() {
        let trace = build_test_trace(10);
        let all = trace.all_events();
        let f = TraceFilter::ByKind(String::from("MemRead"));
        let filtered = f.apply(&all);
        assert!(
            filtered
                .iter()
                .all(|e| matches!(e.kind, EventKind::MemRead { .. }))
        );
    }

    #[test]
    fn trace_filter_by_range() {
        let trace = build_test_trace(10);
        let all = trace.all_events();
        let f = TraceFilter::ByRange(TracePosition::new(2, 0), TracePosition::new(5, 0));
        let filtered = f.apply(&all);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn trace_filter_and_not() {
        let trace = build_test_trace(10);
        let all = trace.all_events();
        let f = TraceFilter::ByThread(1).and(TraceFilter::ByKind(String::from("MemRead")).not());
        let filtered = f.apply(&all);
        assert!(
            filtered
                .iter()
                .all(|e| !matches!(e.kind, EventKind::MemRead { .. }))
        );
    }

    #[test]
    fn trace_filter_or() {
        let trace = TtdTrace::new(TraceMetadata::default());
        trace.add_event(TraceEvent::new(
            TracePosition::new(0, 0),
            1,
            EventKind::Breakpoint { addr: 0xA },
        ));
        trace.add_event(TraceEvent::new(
            TracePosition::new(1, 0),
            2,
            EventKind::Breakpoint { addr: 0xB },
        ));
        let all = trace.all_events();
        let f = TraceFilter::ByThread(1).or(TraceFilter::ByThread(2));
        assert_eq!(f.apply(&all).len(), 2);
    }

    // ── TraceStats ────────────────────────────────────────────────────────────

    #[test]
    fn trace_stats_compute() {
        let t = build_test_trace(10);
        let stats = TraceStats::compute(&t);
        assert_eq!(stats.total_events, 10);
        assert_eq!(stats.mem_reads + stats.mem_writes, 10);
        assert_eq!(stats.thread_count, 1);
        assert_eq!(stats.bytes_read, 5 * 4); // 5 reads of 4 bytes
        assert_eq!(stats.bytes_written, 5 * 4); // 5 writes of 4 bytes
    }

    #[test]
    fn trace_stats_display() {
        let t = build_test_trace(4);
        let stats = TraceStats::compute(&t);
        let s = stats.to_string();
        assert!(s.contains("TraceStats"));
    }

    // ── TraceExporter / TraceImporter ─────────────────────────────────────────

    #[test]
    fn trace_export_import_roundtrip() {
        let original = build_test_trace(8);
        let ndjson = TraceExporter::export_to_string(&original).unwrap();
        let imported = TraceImporter::import_from_str(&ndjson).unwrap();
        assert_eq!(imported.event_count(), 8);
        assert_eq!(imported.metadata.process_name, "test");
    }

    #[test]
    fn trace_importer_empty_input() {
        let result = TraceImporter::import_from_str("");
        assert!(result.is_err());
    }

    #[test]
    fn trace_exporter_to_buf_reader() {
        let trace = build_test_trace(3);
        let mut buf = Vec::new();
        TraceExporter::export(&trace, &mut buf).unwrap();
        let reader = BufReader::new(buf.as_slice());
        let imported = TraceImporter::import(reader).unwrap();
        assert_eq!(imported.event_count(), 3);
    }

    // ── Watchpoint ────────────────────────────────────────────────────────────

    #[test]
    fn watchpoint_triggered_by_write() {
        let wp = Watchpoint::new(0x1000, 8, WatchpointKind::Write);
        let hit = TraceEvent::new(
            TracePosition::new(0, 0),
            1,
            EventKind::MemWrite {
                addr: 0x1004,
                data: vec![0x01, 0x02],
            },
        );
        let miss = TraceEvent::new(
            TracePosition::new(1, 0),
            1,
            EventKind::MemWrite {
                addr: 0x2000,
                data: vec![0xFF],
            },
        );
        assert!(wp.triggered_by(&hit));
        assert!(!wp.triggered_by(&miss));
    }

    #[test]
    fn watchpoint_triggered_read_only() {
        let wp = Watchpoint::new(0x100, 4, WatchpointKind::Read);
        let read_ev = TraceEvent::new(
            TracePosition::new(0, 0),
            1,
            EventKind::MemRead {
                addr: 0x100,
                len: 4,
            },
        );
        let write_ev = TraceEvent::new(
            TracePosition::new(1, 0),
            1,
            EventKind::MemWrite {
                addr: 0x100,
                data: vec![0x00; 4],
            },
        );
        assert!(wp.triggered_by(&read_ev));
        assert!(!wp.triggered_by(&write_ev));
    }

    #[test]
    fn watchpoint_find_hits() {
        let trace = build_test_trace(10);
        // All writes go to 0x2000 + i*4 for odd i in 1..10
        let wp = Watchpoint::new(0x2004, 4, WatchpointKind::Write).with_label("test wp");
        let hits = wp.find_hits(&trace);
        // seq=1: addr = 0x2000 + 1*4 = 0x2004 -> hit
        assert!(!hits.is_empty());
    }

    #[test]
    fn watchpoint_display() {
        let wp = Watchpoint::new(0x1000, 8, WatchpointKind::ReadWrite).with_label("my_var");
        let s = wp.to_string();
        assert!(s.contains("my_var"));
        assert!(s.contains("0x1000"));
    }

    // ── SyscallSummary ────────────────────────────────────────────────────────

    #[test]
    fn syscall_summary_from_trace() {
        let trace = TtdTrace::new(TraceMetadata::default());
        for i in 0u64..5 {
            trace.add_event(TraceEvent::new(
                TracePosition::new(i * 2, 0),
                1,
                EventKind::SyscallEnter {
                    nr: 1,
                    args: [0; 6],
                },
            ));
            trace.add_event(TraceEvent::new(
                TracePosition::new(i * 2 + 1, 0),
                1,
                EventKind::SyscallExit { nr: 1, ret: 0 },
            ));
        }
        let summary = SyscallSummary::from_trace(&trace);
        assert_eq!(summary.total_calls(), 5);
        let info = summary.by_nr.get(&1).unwrap();
        assert_eq!(info.call_count, 5);
    }

    #[test]
    fn syscall_summary_top_syscalls() {
        let trace = TtdTrace::new(TraceMetadata::default());
        for i in 0u64..3 {
            trace.add_event(TraceEvent::new(
                TracePosition::new(i, 0),
                1,
                EventKind::SyscallEnter {
                    nr: 2,
                    args: [0; 6],
                },
            ));
        }
        trace.add_event(TraceEvent::new(
            TracePosition::new(10, 0),
            1,
            EventKind::SyscallEnter {
                nr: 7,
                args: [0; 6],
            },
        ));
        let summary = SyscallSummary::from_trace(&trace);
        let top = summary.top_syscalls();
        assert_eq!(top[0].nr, 2);
        assert_eq!(top[0].call_count, 3);
    }

    // ── TtdSequenceId ─────────────────────────────────────────────────────────

    #[test]
    fn ttd_sequence_id_ordering() {
        let a = TtdSequenceId::new(1, 0);
        let b = TtdSequenceId::new(1, 1);
        let c = TtdSequenceId::new(2, 0);
        assert!(a < b);
        assert!(b < c);
        let mut v = vec![c, a, b];
        v.sort();
        assert_eq!(v, vec![a, b, c]);
    }

    #[test]
    fn ttd_sequence_id_display() {
        let s = TtdSequenceId::new(5, 3);
        assert_eq!(s.to_string(), "5:3");
    }

    #[test]
    fn ttd_sequence_id_from_trace_position() {
        let p = TracePosition::new(10, 2);
        let s = TtdSequenceId::from(p);
        assert_eq!(s.major, 10);
        assert_eq!(s.minor, 2);
    }

    // ── TtdEventFilter ────────────────────────────────────────────────────────

    #[test]
    fn ttd_event_filter_by_address() {
        let events = vec![
            TraceEvent::new(
                TracePosition::new(0, 0),
                1,
                EventKind::MemRead {
                    addr: 0x1000,
                    len: 4,
                },
            ),
            TraceEvent::new(
                TracePosition::new(1, 0),
                1,
                EventKind::MemRead {
                    addr: 0x2000,
                    len: 4,
                },
            ),
        ];
        let f = TtdEventFilter::new().at_address(0x1000);
        let hits = f.apply(&events);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind.address(), Some(0x1000));
    }

    #[test]
    fn ttd_event_filter_by_type() {
        let events = vec![
            TraceEvent::new(
                TracePosition::new(0, 0),
                1,
                EventKind::MemRead {
                    addr: 0x1000,
                    len: 4,
                },
            ),
            TraceEvent::new(
                TracePosition::new(1, 0),
                1,
                EventKind::Call {
                    from: 0x100,
                    to: 0x200,
                },
            ),
        ];
        let f = TtdEventFilter::new().of_type(TtdEventType::Call);
        let hits = f.apply(&events);
        assert_eq!(hits.len(), 1);
        assert!(matches!(hits[0].kind, EventKind::Call { .. }));
    }

    #[test]
    fn ttd_event_filter_by_range() {
        let events: Vec<TraceEvent> = (0u64..10)
            .map(|i| {
                TraceEvent::new(
                    TracePosition::new(i, 0),
                    1,
                    EventKind::Breakpoint { addr: i * 4 },
                )
            })
            .collect();
        let f = TtdEventFilter::new().in_range(TtdSequenceId::new(3, 0), TtdSequenceId::new(6, 0));
        let hits = f.apply(&events);
        // positions 3, 4, 5, 6 → 4 events
        assert_eq!(hits.len(), 4);
    }

    // ── TtdCallExtractor ─────────────────────────────────────────────────────

    #[test]
    fn ttd_call_extractor_basic() {
        let events = vec![
            TraceEvent::new(
                TracePosition::new(0, 0),
                1,
                EventKind::Call {
                    from: 0x100,
                    to: 0x200,
                },
            ),
            TraceEvent::new(
                TracePosition::new(1, 0),
                1,
                EventKind::MemRead {
                    addr: 0x300,
                    len: 4,
                },
            ),
            TraceEvent::new(
                TracePosition::new(2, 0),
                1,
                EventKind::Return {
                    from: 0x200,
                    to: 0x105,
                },
            ),
        ];
        let calls = TtdCallExtractor::extract_calls(&events);
        // Filter out synthetic syscall entries.
        let real: Vec<_> = calls.iter().filter(|c| c.caller_addr != u64::MAX).collect();
        assert_eq!(real.len(), 1);
        assert_eq!(real[0].caller_addr, 0x100);
        assert_eq!(real[0].callee_addr, 0x200);
        assert_eq!(real[0].return_addr, 0x105);
    }

    #[test]
    fn ttd_call_extractor_unmatched_call() {
        let events = vec![TraceEvent::new(
            TracePosition::new(0, 0),
            1,
            EventKind::Call {
                from: 0x100,
                to: 0x200,
            },
        )];
        let calls = TtdCallExtractor::extract_calls(&events);
        let real: Vec<_> = calls.iter().filter(|c| c.caller_addr != u64::MAX).collect();
        assert_eq!(real.len(), 1);
        assert_eq!(real[0].return_addr, 0); // no return seen
    }

    // ── TtdMemoryTimeline ─────────────────────────────────────────────────────

    #[test]
    fn ttd_memory_timeline_history_at() {
        let mut tl = TtdMemoryTimeline::new();
        tl.add_write(TtdSequenceId::new(1, 0), 0x1000, vec![0xAA]);
        tl.add_write(TtdSequenceId::new(3, 0), 0x1000, vec![0xBB]);
        tl.add_write(TtdSequenceId::new(2, 0), 0x2000, vec![0xCC]);
        tl.sort();
        let h = tl.history_at(0x1000);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].1, vec![0xAA]);
        assert_eq!(h[1].1, vec![0xBB]);
        let h2 = tl.history_at(0xFFFF);
        assert!(h2.is_empty());
    }

    #[test]
    fn ttd_memory_timeline_find_first_write_after() {
        let mut tl = TtdMemoryTimeline::new();
        tl.add_write(TtdSequenceId::new(1, 0), 0x1000, vec![1]);
        tl.add_write(TtdSequenceId::new(5, 0), 0x1000, vec![2]);
        tl.add_write(TtdSequenceId::new(9, 0), 0x1000, vec![3]);
        tl.sort();
        let found = tl.find_first_write_after(0x1000, TtdSequenceId::new(4, 0));
        assert_eq!(found, Some(TtdSequenceId::new(5, 0)));
        let none = tl.find_first_write_after(0x1000, TtdSequenceId::new(10, 0));
        assert!(none.is_none());
    }

    #[test]
    fn ttd_memory_timeline_from_trace() {
        let trace = TtdTrace::new(TraceMetadata::default());
        trace.add_event(TraceEvent::new(
            TracePosition::new(0, 0),
            1,
            EventKind::MemWrite {
                addr: 0xABCD,
                data: vec![0xDE, 0xAD],
            },
        ));
        let tl = TtdMemoryTimeline::from_trace(&trace);
        let h = tl.history_at(0xABCD);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].1, vec![0xDE, 0xAD]);
    }
}
