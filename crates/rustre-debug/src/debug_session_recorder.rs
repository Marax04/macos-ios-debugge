//! Debug session recorder: captures events from a debug session and replays
//! them deterministically for post-mortem analysis.
//!
//! **Intentionally distinct from [`crate::debug_session_manager`].**
//! This module is the *capture/replay subsystem*.  It records events to a
//! bounded, seekable [`SessionLog`] (backed by a `VecDeque`) and exposes a
//! replay cursor with `replay_step`, `replay_n`, `replay_to_next_stop`, and
//! `seek_to_sequence`.  Its `SessionEvent` type is richer than the manager's —
//! it includes `RegisterSnapshot`, `MemorySnapshot`, and `Annotation` variants
//! needed for faithful replay.
//!
//! [`crate::debug_session_manager`] is the *live session controller*: it owns
//! the set of active sessions, handles the event bus in real time, and provides
//! `open_session`/`close_session` lifecycle management.  The two modules operate
//! at different layers and intentionally define their own `SessionEvent` types
//! to avoid coupling their respective concerns.

use std::collections::VecDeque;
use std::fmt;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ── Opt-1: bump-arena for high-frequency annotation string allocation ─────────

/// A bump allocator that hands out `&str` slices for annotation messages,
/// avoiding a `String` heap allocation per event when recording thousands of
/// trace annotations per second.
///
/// Call [`ArenaAnnotationBuffer::alloc_str`] to store a string in the arena;
/// the returned `&str` is valid for the lifetime of `self`.  When the arena is
/// full or no longer needed, call [`clear`](ArenaAnnotationBuffer::clear) to
/// reset and reuse its memory.
///
/// # Example
/// ```rust
/// # use rustre_debug::debug_session_recorder::ArenaAnnotationBuffer;
/// let mut arena = ArenaAnnotationBuffer::new(4096);
/// let s: &str = arena.alloc_str("hit breakpoint 0x1000");
/// assert_eq!(s, "hit breakpoint 0x1000");
/// arena.clear();
/// ```
pub struct ArenaAnnotationBuffer {
    bump: bumpalo::Bump,
}

impl ArenaAnnotationBuffer {
    /// Create an arena pre-allocated with `capacity` bytes of memory.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let bump = bumpalo::Bump::with_capacity(capacity);
        Self { bump }
    }

    /// Allocate `s` in the arena and return a reference valid for `&self`.
    ///
    /// This is `O(len(s))` with no system `malloc` call as long as the current
    /// chunk has space: the bump pointer simply advances.
    #[must_use]
    pub fn alloc_str<'a>(&'a self, s: &str) -> &'a str {
        bumpalo::collections::String::from_str_in(s, &self.bump).into_bump_str()
    }

    /// Reset the arena, freeing all allocations in O(1).  References previously
    /// handed out by [`alloc_str`](Self::alloc_str) are invalidated; callers
    /// must ensure no outstanding references survive this call.
    pub fn clear(&mut self) {
        self.bump.reset();
    }

    /// Total bytes currently allocated inside this arena.
    #[must_use]
    pub fn allocated_bytes(&self) -> usize {
        self.bump.allocated_bytes()
    }
}

use rustre_core::address::Address;

use crate::{ProcessId, RegisterSet, StopReason, ThreadId};

// ── Timestamp ────────────────────────────────────────────────────────────────

/// Process-start anchor used for monotonic elapsed-time calculations.
static RECORDER_START: OnceLock<Instant> = OnceLock::new();

/// Milliseconds since UNIX epoch (for display) **and** a monotonic elapsed-ms
/// offset from process start (for duration arithmetic).
///
/// The `u64` field stores wall-clock ms-since-epoch so that timestamps remain
/// human-readable across display/serialisation.  Duration arithmetic
/// (`elapsed_since`, `SessionLog::duration`) uses the monotonic offset stored
/// in `monotonic_ms` to avoid wrong results when the system clock is adjusted
/// by NTP or DST transitions (`time-monotonic-vs-system`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    /// Wall-clock milliseconds since UNIX epoch — for display only.
    pub wall_ms: u64,
    /// Monotonic milliseconds since process start — for duration arithmetic.
    monotonic_ms: u64,
}

// Keep the public tuple field `0` accessible as an alias for wall_ms so that
// existing code that reads `ts.0` continues to compile.
impl std::ops::Deref for Timestamp {
    type Target = u64;
    fn deref(&self) -> &u64 { &self.wall_ms }
}

impl Timestamp {
    /// Opt-8: this branch is taken only when the system clock pre-dates the
    /// UNIX epoch (impossible on well-configured hardware), so mark it cold
    /// to let the compiler keep it out of the hot path.
    #[cold]
    const fn zero_wall() -> Duration { Duration::ZERO }

    #[must_use]
    pub fn now() -> Self {
        let start = RECORDER_START.get_or_init(Instant::now);
        let wall_dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Self::zero_wall());
        let wall_ms = wall_dur.as_secs()
            .saturating_mul(1000)
            .saturating_add(u64::from(wall_dur.subsec_millis()));
        let elapsed = start.elapsed();
        let monotonic_ms = elapsed.as_secs()
            .saturating_mul(1000)
            .saturating_add(u64::from(elapsed.subsec_millis()));
        Self { wall_ms, monotonic_ms }
    }

    #[must_use]
    pub const fn zero() -> Self {
        Self { wall_ms: 0, monotonic_ms: 0 }
    }

    /// Duration between two timestamps using the monotonic clock, so that NTP
    /// adjustments or DST transitions do not produce negative or wildly wrong
    /// durations.
    #[must_use]
    pub const fn elapsed_since(&self, earlier: Self) -> Duration {
        Duration::from_millis(self.monotonic_ms.saturating_sub(earlier.monotonic_ms))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "T+{}ms", self.wall_ms)
    }
}

// ── SessionEvent ─────────────────────────────────────────────────────────────

/// A single recorded event in a debug session.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// The target process was launched or attached.
    ProcessStarted {
        pid: ProcessId,
        image_path: String,
    },
    /// The target process exited.
    ProcessExited {
        pid: ProcessId,
        exit_code: i32,
    },
    /// A thread was created.
    ThreadCreated {
        tid: ThreadId,
        start_address: Address,
    },
    /// A thread exited.
    ThreadExited {
        tid: ThreadId,
        exit_code: i32,
    },
    /// The target stopped (breakpoint, single-step, exception, …).
    Stopped {
        tid: ThreadId,
        reason: StopReason,
        address: Address,
    },
    /// The target was resumed.
    Resumed {
        tid: ThreadId,
    },
    /// A module was loaded.
    ModuleLoaded {
        name: String,
        base: Address,
        size: u64,
    },
    /// A module was unloaded.
    ModuleUnloaded {
        name: String,
        base: Address,
    },
    /// Registers were captured at a stop point.
    RegisterSnapshot {
        tid: ThreadId,
        registers: RegisterSet,
    },
    /// A memory region was read and the bytes captured.
    MemorySnapshot {
        address: Address,
        bytes: Vec<u8>,
    },
    /// A user-defined annotation.
    Annotation {
        message: String,
    },
    /// A breakpoint was hit.
    BreakpointHit {
        id: u32,
        tid: ThreadId,
        address: Address,
    },
    /// A watchpoint was hit.
    WatchpointHit {
        id: u32,
        tid: ThreadId,
        address: Address,
        access_kind: String,
    },
    /// Output written to stdout/stderr by the target.
    OutputText {
        text: String,
    },
}

impl SessionEvent {
    /// Short human-readable label for the event kind.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::ProcessStarted { .. } => "ProcessStarted",
            Self::ProcessExited { .. } => "ProcessExited",
            Self::ThreadCreated { .. } => "ThreadCreated",
            Self::ThreadExited { .. } => "ThreadExited",
            Self::Stopped { .. } => "Stopped",
            Self::Resumed { .. } => "Resumed",
            Self::ModuleLoaded { .. } => "ModuleLoaded",
            Self::ModuleUnloaded { .. } => "ModuleUnloaded",
            Self::RegisterSnapshot { .. } => "RegisterSnapshot",
            Self::MemorySnapshot { .. } => "MemorySnapshot",
            Self::Annotation { .. } => "Annotation",
            Self::BreakpointHit { .. } => "BreakpointHit",
            Self::WatchpointHit { .. } => "WatchpointHit",
            Self::OutputText { .. } => "OutputText",
        }
    }

    /// Returns `true` for events that represent a stop (breakpoint, step, etc.).
    #[must_use]
    pub const fn is_stop(&self) -> bool {
        matches!(self, Self::Stopped { .. } | Self::BreakpointHit { .. } | Self::WatchpointHit { .. })
    }
}

impl fmt::Display for SessionEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.kind_name())
    }
}

// ── SessionLogEntry ───────────────────────────────────────────────────────────

/// A timestamped wrapper around a [`crate::debug_session_manager::SessionEvent`].
#[derive(Debug, Clone)]
pub struct SessionLogEntry {
    pub timestamp: Timestamp,
    pub sequence: u64,
    pub event: SessionEvent,
}

impl SessionLogEntry {
    #[must_use]
    pub const fn new(seq: u64, ts: Timestamp, event: SessionEvent) -> Self {
        Self {
            timestamp: ts,
            sequence: seq,
            event,
        }
    }
}

impl fmt::Display for SessionLogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{} {} {}", self.sequence, self.timestamp, self.event)
    }
}

// ── SessionLog ────────────────────────────────────────────────────────────────

const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// An ordered, bounded log of [`SessionLogEntry`]s.
#[derive(Debug)]
pub struct SessionLog {
    entries: VecDeque<SessionLogEntry>,
    max_entries: usize,
    dropped: u64,
    /// Timestamp of the first entry ever pushed, kept after that entry has been
    /// evicted.
    ///
    /// Without it `duration()` measured the span of what SURVIVED in the ring,
    /// not of the session: an hour-long session that had dropped its early
    /// entries reported the span of the last few thousand events — perhaps
    /// thirty seconds — under a method documented as "duration of the session".
    first_ever: Option<Timestamp>,
}

impl SessionLog {
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_entries.min(4096)),
            max_entries: max_entries.max(1),
            dropped: 0,
            first_ever: None,
        }
    }

    #[must_use]
    pub fn default_capacity() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES)
    }

    pub fn push(&mut self, entry: SessionLogEntry) {
        if self.first_ever.is_none() {
            self.first_ever = Some(entry.timestamp);
        }
        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
            self.dropped += 1;
        }
        self.entries.push_back(entry);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Iterate entries in order (oldest first).
    pub fn iter(&self) -> impl Iterator<Item = &SessionLogEntry> {
        self.entries.iter()
    }

    /// Iterate entries in reverse order (newest first).
    pub fn iter_rev(&self) -> impl Iterator<Item = &SessionLogEntry> {
        self.entries.iter().rev()
    }

    /// Return the last `n` entries.
    #[must_use]
    pub fn tail(&self, n: usize) -> Vec<&SessionLogEntry> {
        self.entries.iter().rev().take(n).collect::<Vec<_>>().into_iter().rev().collect()
    }

    /// Filter entries by event kind name.
    #[must_use]
    pub fn filter_by_kind<'a>(&'a self, kind: &'a str) -> Vec<&'a SessionLogEntry> {
        self.entries
            .iter()
            .filter(|e| e.event.kind_name() == kind)
            .collect()
    }

    /// Find all stop events.
    #[must_use]
    pub fn stop_events(&self) -> Vec<&SessionLogEntry> {
        self.entries.iter().filter(|e| e.event.is_stop()).collect()
    }

    /// Duration of the SESSION: last entry minus the first ever recorded, even
    /// if that first entry has since been evicted.
    ///
    /// It used to take the front of the ring as the start, so once the buffer
    /// wrapped the answer silently became "how long the surviving entries
    /// span" — a much smaller number, under a name that promises the session.
    #[must_use]
    pub fn duration(&self) -> Duration {
        match (self.first_ever, self.entries.back().map(|e| e.timestamp)) {
            (Some(f), Some(l)) => l.elapsed_since(f),
            _ => Duration::ZERO,
        }
    }

    /// Span of the entries STILL HELD, which is shorter than [`Self::duration`]
    /// once the ring has wrapped.
    #[must_use]
    pub fn retained_span(&self) -> Duration {
        match (
            self.entries.front().map(|e| e.timestamp),
            self.entries.back().map(|e| e.timestamp),
        ) {
            (Some(f), Some(l)) => l.elapsed_since(f),
            _ => Duration::ZERO,
        }
    }

    /// Whether the entries still held cover the whole session.
    ///
    /// `false` means events were evicted: anything derived from `iter()` — a
    /// heatmap, a first-occurrence search, "the breakpoint was never hit" — is
    /// a statement about the tail, not about the run.
    #[must_use]
    pub const fn covers_whole_session(&self) -> bool {
        self.dropped == 0
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.dropped = 0;
        // The next push starts a new session as far as this log is concerned.
        self.first_ever = None;
    }
}

// ── ReplayState ───────────────────────────────────────────────────────────────

/// Tracks the position of a replay cursor over a [`SessionLog`].
#[derive(Debug, Clone)]
pub struct ReplayState {
    /// Current position in the log (index into `SessionLog::entries`).
    pub position: usize,
    /// Total entries available.
    pub total: usize,
    /// Sequence number of the entry at `position`.
    pub current_sequence: Option<u64>,
}

impl ReplayState {
    #[must_use]
    pub const fn at_start(&self) -> bool {
        self.position == 0
    }

    #[must_use]
    pub const fn at_end(&self) -> bool {
        self.position >= self.total
    }

    #[must_use]
    pub fn progress_pct(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            let pos = u32::try_from(self.position).unwrap_or(u32::MAX);
            let tot = u32::try_from(self.total).unwrap_or(u32::MAX);
            f64::from(pos) / f64::from(tot) * 100.0
        }
    }
}

// ── DebugSessionRecorder ─────────────────────────────────────────────────────

/// Records events during a live debug session and supports replaying them.
pub struct DebugSessionRecorder {
    pub log: SessionLog,
    sequence: u64,
    recording: bool,
    start_time: Option<Timestamp>,
    /// For replay: current position.
    replay_pos: usize,
}

impl DebugSessionRecorder {
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            log: SessionLog::new(max_entries),
            sequence: 0,
            recording: false,
            start_time: None,
            replay_pos: 0,
        }
    }

    /// Create with the default log capacity.
    #[must_use]
    pub fn default_capacity() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES)
    }

    // ── Recording lifecycle ───────────────────────────────────────────────────

    /// Start recording.
    ///
    /// If recording is already active this is a no-op; callers must call
    /// [`Self::stop`] before restarting to avoid silently resetting the sequence
    /// counter and corrupting the replay log.
    pub fn start(&mut self) {
        if self.recording {
            return;
        }
        self.recording = true;
        self.start_time = Some(Timestamp::now());
        self.sequence = 0;
    }

    /// Stop recording.
    pub const fn stop(&mut self) {
        self.recording = false;
    }

    #[must_use]
    pub const fn is_recording(&self) -> bool {
        self.recording
    }

    /// Record an event (only when recording is active).
    pub fn record(&mut self, event: SessionEvent) {
        if !self.recording {
            return;
        }
        let ts = Timestamp::now();
        let seq = self.sequence;
        self.sequence += 1;
        self.log.push(SessionLogEntry::new(seq, ts, event));
    }

    /// Record an event unconditionally (bypasses the `recording` guard).
    pub fn record_always(&mut self, event: SessionEvent) {
        let ts = Timestamp::now();
        let seq = self.sequence;
        self.sequence += 1;
        self.log.push(SessionLogEntry::new(seq, ts, event));
    }

    /// Add a user annotation to the log.
    pub fn annotate(&mut self, msg: impl Into<String>) {
        self.record_always(SessionEvent::Annotation { message: msg.into() });
    }

    // ── Replay ────────────────────────────────────────────────────────────────

    /// Reset the replay cursor to the start.
    pub const fn rewind(&mut self) {
        self.replay_pos = 0;
    }

    /// Advance the replay cursor by one step.
    ///
    /// Returns the next [`SessionLogEntry`], or `None` at end.
    pub fn replay_step(&mut self) -> Option<&SessionLogEntry> {
        let entry = self.log.entries.get(self.replay_pos);
        if entry.is_some() {
            self.replay_pos += 1;
        }
        entry
    }

    /// Advance `n` steps, returning the entries consumed.
    pub fn replay_n(&mut self, n: usize) -> Vec<&SessionLogEntry> {
        let start = self.replay_pos;
        let available = self.log.entries.len().saturating_sub(start);
        let count = n.min(available);
        self.replay_pos += count;
        self.log.entries.iter().skip(start).take(count).collect()
    }

    /// Skip forward to the next stop event.  Returns that entry if found.
    pub fn replay_to_next_stop(&mut self) -> Option<&SessionLogEntry> {
        while self.replay_pos < self.log.len() {
            let entry = &self.log.entries[self.replay_pos];
            self.replay_pos += 1;
            if entry.event.is_stop() {
                return Some(&self.log.entries[self.replay_pos - 1]);
            }
        }
        None
    }

    /// Seek to a specific sequence number.  Returns `false` if not found.
    pub fn seek_to_sequence(&mut self, seq: u64) -> bool {
        for (i, entry) in self.log.entries.iter().enumerate() {
            if entry.sequence == seq {
                self.replay_pos = i;
                return true;
            }
        }
        false
    }

    /// Current replay state.
    #[must_use]
    pub fn replay_state(&self) -> ReplayState {
        let current_sequence = self.log.entries.get(self.replay_pos).map(|e| e.sequence);
        ReplayState {
            position: self.replay_pos,
            total: self.log.len(),
            current_sequence,
        }
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    #[must_use]
    pub fn event_count(&self) -> usize {
        self.log.entries.len()
    }

    #[must_use]
    pub fn stop_count(&self) -> usize {
        self.log.stop_events().len()
    }

    #[must_use]
    pub fn session_duration(&self) -> Duration {
        self.log.duration()
    }
}

impl fmt::Debug for DebugSessionRecorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DebugSessionRecorder")
            .field("events", &self.log.len())
            .field("sequence", &self.sequence)
            .field("recording", &self.recording)
            .field("start_time", &self.start_time)
            .field("replay_pos", &self.replay_pos)
            .finish()
    }
}

// ── replay_session ────────────────────────────────────────────────────────────

/// Replay all events from `log` in order, calling `handler` for each entry.
///
/// If `handler` returns `false`, replay is stopped early.  Returns the number
/// of entries processed.
pub fn replay_session<F>(log: &SessionLog, mut handler: F) -> usize
where
    F: FnMut(&SessionLogEntry) -> bool,
{
    let mut count = 0;
    for entry in log.iter() {
        count += 1;
        if !handler(entry) {
            break;
        }
    }
    count
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_recorder() -> DebugSessionRecorder {
        let mut r = DebugSessionRecorder::new(1000);
        r.start();
        r
    }

    fn pid() -> ProcessId {
        ProcessId(42)
    }

    fn tid() -> ThreadId {
        ThreadId(1)
    }

    fn addr(v: u64) -> Address {
        Address::from(v)
    }

    fn bp_hit(id: u32) -> SessionEvent {
        SessionEvent::BreakpointHit {
            id,
            tid: tid(),
            address: addr(0x1000),
        }
    }

    #[test]
    fn record_and_count_events() {
        let mut r = make_recorder();
        r.record(SessionEvent::ProcessStarted {
            pid: pid(),
            image_path: "/bin/ls".into(),
        });
        r.record(bp_hit(0));
        assert_eq!(r.event_count(), 2);
    }

    #[test]
    fn not_recorded_when_stopped() {
        let mut r = DebugSessionRecorder::new(100);
        // not started
        r.record(bp_hit(0));
        assert_eq!(r.event_count(), 0);
    }

    #[test]
    fn stop_prevents_further_recording() {
        let mut r = make_recorder();
        r.record(bp_hit(0));
        r.stop();
        r.record(bp_hit(1));
        assert_eq!(r.event_count(), 1);
    }

    #[test]
    fn replay_step_advances() {
        let mut r = make_recorder();
        r.record(bp_hit(0));
        r.record(bp_hit(1));
        r.rewind();
        let e1 = r.replay_step().unwrap();
        assert_eq!(e1.sequence, 0);
        let e2 = r.replay_step().unwrap();
        assert_eq!(e2.sequence, 1);
        assert!(r.replay_step().is_none());
    }

    #[test]
    fn replay_n_returns_n_entries() {
        let mut r = make_recorder();
        for i in 0..5u32 {
            r.record(bp_hit(i));
        }
        r.rewind();
        let entries = r.replay_n(3);
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn replay_to_next_stop() {
        let mut r = make_recorder();
        r.record(SessionEvent::Resumed { tid: tid() });
        r.record(bp_hit(1));
        r.record(SessionEvent::Resumed { tid: tid() });
        r.rewind();
        let stop = r.replay_to_next_stop().unwrap();
        assert!(stop.event.is_stop());
    }

    #[test]
    fn seek_to_sequence() {
        let mut r = make_recorder();
        for i in 0..10u32 {
            r.record(bp_hit(i));
        }
        assert!(r.seek_to_sequence(5));
        let e = r.replay_step().unwrap();
        assert_eq!(e.sequence, 5);
    }

    #[test]
    fn seek_unknown_sequence_returns_false() {
        let mut r = make_recorder();
        r.record(bp_hit(0));
        assert!(!r.seek_to_sequence(999));
    }

    #[test]
    fn stop_count() {
        let mut r = make_recorder();
        r.record(bp_hit(0));
        r.record(SessionEvent::Resumed { tid: tid() });
        r.record(bp_hit(1));
        assert_eq!(r.stop_count(), 2);
    }

    #[test]
    fn log_capacity_evicts_oldest() {
        let mut r = DebugSessionRecorder::new(3);
        r.start();
        for i in 0..5u32 {
            r.record(bp_hit(i));
        }
        assert_eq!(r.log.len(), 3);
        assert_eq!(r.log.dropped(), 2);
    }

    #[test]
    fn annotate_adds_annotation_event() {
        let mut r = make_recorder();
        r.annotate("test note");
        let anns = r.log.filter_by_kind("Annotation");
        assert_eq!(anns.len(), 1);
        if let SessionEvent::Annotation { message } = &anns[0].event {
            assert_eq!(message, "test note");
        } else {
            panic!("wrong event kind");
        }
    }

    #[test]
    fn replay_session_calls_handler() {
        let mut r = make_recorder();
        for i in 0..5u32 {
            r.record(bp_hit(i));
        }
        let mut count = 0usize;
        let processed = replay_session(&r.log, |_| {
            count += 1;
            true
        });
        assert_eq!(processed, 5);
        assert_eq!(count, 5);
    }

    #[test]
    fn replay_session_early_stop() {
        let mut r = make_recorder();
        for i in 0..5u32 {
            r.record(bp_hit(i));
        }
        let processed = replay_session(&r.log, |e| e.sequence < 2);
        assert_eq!(processed, 3); // stops after processing seq 2
    }

    #[test]
    fn tail_returns_last_n() {
        let mut r = make_recorder();
        for i in 0..10u32 {
            r.record(bp_hit(i));
        }
        let tail = r.log.tail(3);
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].sequence, 7);
        assert_eq!(tail[2].sequence, 9);
    }

    // ── Opt-1: arena annotation buffer tests ─────────────────────────────────

    #[test]
    fn arena_alloc_str_roundtrip() {
        let arena = ArenaAnnotationBuffer::new(1024);
        let s = arena.alloc_str("breakpoint 0x4000");
        assert_eq!(s, "breakpoint 0x4000");
    }

    #[test]
    fn arena_allocated_bytes_grows() {
        let arena = ArenaAnnotationBuffer::new(512);
        let _ = arena.alloc_str("hello");
        assert!(arena.allocated_bytes() > 0);
    }

    #[test]
    fn arena_clear_resets() {
        let mut arena = ArenaAnnotationBuffer::new(512);
        let _ = arena.alloc_str("data");
        arena.clear();
        // After reset the arena is reusable.
        let s = arena.alloc_str("new data");
        assert_eq!(s, "new data");
    }

    /// Throughput sanity: allocating 10 000 annotation strings via the arena
    /// must all succeed (this exercises the fast path with no malloc calls
    /// after the first chunk is handed out).
    #[test]
    fn arena_bulk_alloc_throughput() {
        let arena = ArenaAnnotationBuffer::new(256 * 1024);
        for i in 0u32..10_000 {
            let msg = format!("event {i}");
            let _ = arena.alloc_str(&msg);
        }
        assert!(arena.allocated_bytes() > 0);
    }

    #[test]
    fn replay_state_progress() {
        let mut r = make_recorder();
        for i in 0..4u32 {
            r.record(bp_hit(i));
        }
        r.rewind();
        r.replay_step();
        r.replay_step();
        let state = r.replay_state();
        assert_eq!(state.position, 2);
        assert!((state.progress_pct() - 50.0).abs() < 0.01);
    }

    /// `duration()` must measure the SESSION, not what survived in the ring.
    ///
    /// The log is bounded, so a long session drops its early entries. The old
    /// implementation took the front of the ring as the start, so once the
    /// buffer wrapped the answer silently became "how long the surviving
    /// entries span" — a much smaller number, under a method whose own doc
    /// says "duration of the session". An hour-long run could report thirty
    /// seconds.
    #[test]
    fn duration_measures_the_session_even_after_entries_are_evicted() {
        let ts = |ms: u64| Timestamp { wall_ms: ms, monotonic_ms: ms };
        let mut log = SessionLog::new(3);
        for (i, ms) in [0u64, 10, 20, 30, 40, 50].into_iter().enumerate() {
            log.push(SessionLogEntry::new(i as u64, ts(ms), SessionEvent::ProcessExited { pid: ProcessId(1), exit_code: 0 }));
        }

        assert_eq!(log.len(), 3, "the ring holds only the last three");
        assert_eq!(
            log.duration(),
            Duration::from_millis(50),
            "the session ran from the first event ever recorded to the last"
        );
        assert_eq!(
            log.retained_span(),
            Duration::from_millis(20),
            "the entries still held span only the tail"
        );
        assert!(
            !log.covers_whole_session(),
            "events were evicted, so anything derived from iter() describes the tail"
        );

        // A log that never wrapped answers the same either way, and says it is
        // complete - so the two methods are not simply always different.
        let mut short = SessionLog::new(8);
        short.push(SessionLogEntry::new(0, ts(5), SessionEvent::ProcessExited { pid: ProcessId(1), exit_code: 0 }));
        short.push(SessionLogEntry::new(1, ts(25), SessionEvent::ProcessExited { pid: ProcessId(1), exit_code: 0 }));
        assert_eq!(short.duration(), Duration::from_millis(20));
        assert_eq!(short.retained_span(), short.duration());
        assert!(short.covers_whole_session());

        // After clear() the next push starts a new session.
        short.clear();
        assert_eq!(short.duration(), Duration::ZERO);
        short.push(SessionLogEntry::new(2, ts(100), SessionEvent::ProcessExited { pid: ProcessId(1), exit_code: 0 }));
        short.push(SessionLogEntry::new(3, ts(110), SessionEvent::ProcessExited { pid: ProcessId(1), exit_code: 0 }));
        assert_eq!(short.duration(), Duration::from_millis(10));
    }

}
