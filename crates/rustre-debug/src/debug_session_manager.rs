//! `debug_session_manager` — Debug session manager for RustRE.
//!
//! Provides [`DebugSessionManager`], [`DebugSession`], [`SessionPool`],
//! [`SessionEvent`], [`crate::cross_platform_debug::DebugTarget`], and [`SessionRecorder`].
//!
//! **Intentionally distinct from [`crate::debug_session_recorder`].**
//! This module is the *live session controller*: it manages the set of active
//! debug sessions, their lifecycle (open/close), an event bus, and a global log
//! across all sessions.  Its `SessionEvent` type describes high-level session
//! lifecycle events (breakpoint hit, exception, module load, …) dispatched in
//! real time.
//!
//! [`crate::debug_session_recorder`] is the *deterministic capture/replay
//! subsystem*: it records every event to a bounded, seekable `VecDeque`-backed
//! log so that a session can be rewound and replayed step-by-step for post-mortem
//! analysis.  Its own `SessionEvent` type models a richer set of events including
//! register snapshots, memory snapshots, and user annotations — it is a
//! superset tailored for replay fidelity rather than real-time dispatch.

use std::collections::HashMap;
use std::fmt;
/// Re-export of [`std::sync::Arc`] so callers can build shared session
/// handles without importing `std::sync` directly.
pub use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// ── DebugTarget ───────────────────────────────────────────────────────────────

/// A target that can be debugged.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DebugTarget {
    /// Attach to a running process by PID.
    Process { pid: u32, process_name: String },
    /// Attach to a remote gdbserver / debugserver.
    Remote {
        host: String,
        port: u16,
        arch: String,
    },
    /// Load a core dump file.
    CoreFile { path: String, arch: String },
    /// Launch a new process.
    Launch {
        binary: String,
        args: Vec<String>,
        env: Vec<(String, String)>,
    },
}

impl DebugTarget {
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::Process { pid, process_name } => format!("{process_name}[{pid}]"),
            Self::Remote { host, port, .. } => format!("{host}:{port}"),
            Self::CoreFile { path, .. } => path.clone(),
            Self::Launch { binary, .. } => binary.clone(),
        }
    }

    #[must_use]
    pub const fn arch(&self) -> Option<&str> {
        match self {
            Self::Remote { arch, .. } | Self::CoreFile { arch, .. } => Some(arch.as_str()),
            _ => None,
        }
    }
}

impl fmt::Display for DebugTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name())
    }
}

// ── SessionId ─────────────────────────────────────────────────────────────────

/// Unique identifier for a debug session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session-{}", self.0)
    }
}

// opt-9: pad the hot atomic to a full cache line so it does not share a cache
// line with other data — eliminates false sharing when multiple threads
// allocate session IDs concurrently.
#[repr(align(64))]
struct AlignedAtomicU64(AtomicU64);
static NEXT_SESSION_ID: AlignedAtomicU64 = AlignedAtomicU64(AtomicU64::new(1));

fn alloc_session_id() -> SessionId {
    SessionId(NEXT_SESSION_ID.0.fetch_add(1, Ordering::Relaxed))
}

// ── SessionState ──────────────────────────────────────────────────────────────

/// The current state of a debug session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Connecting,
    Connected,
    Running,
    Stopped,
    Stepping,
    Terminated,
    Error,
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Stepping => "stepping",
            Self::Terminated => "terminated",
            Self::Error => "error",
        };
        f.write_str(s)
    }
}

// ── SessionEvent ─────────────────────────────────────────────────────────────

/// An event produced by a debug session.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// A breakpoint was hit.
    BreakpointHit {
        session_id: SessionId,
        bp_id: u64,
        address: u64,
        thread_id: u64,
    },
    /// An exception occurred.
    Exception {
        session_id: SessionId,
        exception_code: u32,
        address: u64,
        thread_id: u64,
    },
    /// A single-step completed.
    StepDone {
        session_id: SessionId,
        address: u64,
        thread_id: u64,
    },
    /// The process exited.
    ProcessExit {
        session_id: SessionId,
        exit_code: i32,
    },
    /// A new thread was created.
    ThreadCreated {
        session_id: SessionId,
        thread_id: u64,
    },
    /// A thread exited.
    ThreadExited {
        session_id: SessionId,
        thread_id: u64,
        exit_code: i32,
    },
    /// A module was loaded.
    ModuleLoaded {
        session_id: SessionId,
        name: String,
        base: u64,
        size: u64,
    },
    /// A module was unloaded.
    ModuleUnloaded { session_id: SessionId, name: String },
    /// Session state changed.
    StateChanged {
        session_id: SessionId,
        new_state: SessionState,
    },
    /// A watchpoint was triggered.
    WatchpointHit {
        session_id: SessionId,
        wp_id: u64,
        address: u64,
        access: &'static str,
    },
    /// Console / output event.
    Output { session_id: SessionId, text: String },
}

impl SessionEvent {
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        match self {
            Self::BreakpointHit { session_id, .. }
            | Self::Exception { session_id, .. }
            | Self::StepDone { session_id, .. }
            | Self::ProcessExit { session_id, .. }
            | Self::ThreadCreated { session_id, .. }
            | Self::ThreadExited { session_id, .. }
            | Self::ModuleLoaded { session_id, .. }
            | Self::ModuleUnloaded { session_id, .. }
            | Self::StateChanged { session_id, .. }
            | Self::WatchpointHit { session_id, .. }
            | Self::Output { session_id, .. } => *session_id,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::BreakpointHit { .. } => "breakpoint_hit",
            Self::Exception { .. } => "exception",
            Self::StepDone { .. } => "step_done",
            Self::ProcessExit { .. } => "process_exit",
            Self::ThreadCreated { .. } => "thread_created",
            Self::ThreadExited { .. } => "thread_exited",
            Self::ModuleLoaded { .. } => "module_loaded",
            Self::ModuleUnloaded { .. } => "module_unloaded",
            Self::StateChanged { .. } => "state_changed",
            Self::WatchpointHit { .. } => "watchpoint_hit",
            Self::Output { .. } => "output",
        }
    }
}

impl fmt::Display for SessionEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.session_id(), self.kind())
    }
}

// ── RecordedEvent ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RecordedEvent {
    pub timestamp_ms: u64,
    pub event: SessionEvent,
}

// ── SessionRecorder ───────────────────────────────────────────────────────────

/// How many events one session keeps before the oldest are evicted.
///
/// Sized like [`GLOBAL_LOG_CAP`]'s smaller sibling: a session that single-steps
/// or hits a hot watchpoint produces events without limit, and this used to be
/// an unbounded `Vec`. `dispatch_event` pushes the SAME event into the global
/// log, which has been bounded with a dropped counter all along, and then into
/// this one, which was not — two lines apart, one careful and one not.
pub const SESSION_RECORDER_CAP: usize = 100_000;

/// Records the events produced by a session, keeping the most recent
/// [`SESSION_RECORDER_CAP`] of them.
#[derive(Debug, Clone, Default)]
pub struct SessionRecorder {
    pub events: Vec<RecordedEvent>,
    /// Events evicted because the log was full.
    ///
    /// Published rather than merely counted internally: a caller reading
    /// `events` otherwise cannot tell a complete history from a truncated one,
    /// and "the breakpoint was never hit before this point" is exactly the kind
    /// of conclusion a debugger must not let someone draw from a missing tail.
    dropped: u64,
}

impl SessionRecorder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: SessionEvent) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        if self.events.len() >= SESSION_RECORDER_CAP {
            self.events.remove(0);
            self.dropped += 1;
        }
        self.events.push(RecordedEvent {
            timestamp_ms: ts,
            event,
        });
    }

    /// How many events were evicted to stay within the cap.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Whether `events` is the session's WHOLE history.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.dropped == 0
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Filter events by kind.
    #[must_use]
    pub fn filter_by_kind(&self, kind: &str) -> Vec<&RecordedEvent> {
        self.events
            .iter()
            .filter(|e| e.event.kind() == kind)
            .collect()
    }

    /// Return the most recent event.
    #[must_use]
    pub fn last(&self) -> Option<&RecordedEvent> {
        self.events.last()
    }

    /// Clear all recorded events.
    ///
    /// The dropped counter is cleared too: after this the log genuinely is the
    /// whole history again, which is what `is_complete` must then report.
    pub fn clear(&mut self) {
        self.events.clear();
        self.dropped = 0;
    }
}

// ── DebugSession ──────────────────────────────────────────────────────────────

/// A single active debug session.
#[derive(Debug)]
pub struct DebugSession {
    pub id: SessionId,
    pub target: DebugTarget,
    pub arch: String,
    pub state: SessionState,
    pub recorder: SessionRecorder,
    /// Active breakpoints: id → address.
    pub breakpoints: HashMap<u64, u64>,
    /// Active watchpoints: id → (address, kind).
    pub watchpoints: HashMap<u64, (u64, &'static str)>,
    /// Thread list.
    pub threads: Vec<u64>,
    /// Loaded modules.
    pub modules: Vec<(String, u64, u64)>, // (name, base, size)
    /// Next breakpoint ID.
    next_bp_id: u64,
    /// Next watchpoint ID.
    next_wp_id: u64,
}

impl DebugSession {
    #[must_use]
    pub fn new(target: DebugTarget, arch: String) -> Self {
        Self {
            id: alloc_session_id(),
            target,
            arch,
            state: SessionState::Connecting,
            recorder: SessionRecorder::new(),
            breakpoints: HashMap::new(),
            watchpoints: HashMap::new(),
            threads: Vec::new(),
            modules: Vec::new(),
            next_bp_id: 1,
            next_wp_id: 1,
        }
    }

    /// Transition to a new state.
    pub fn set_state(&mut self, new_state: SessionState) {
        self.state = new_state;
        self.recorder.record(SessionEvent::StateChanged {
            session_id: self.id,
            new_state,
        });
    }

    /// Add a breakpoint at `address`.
    pub fn add_breakpoint(&mut self, address: u64) -> u64 {
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.breakpoints.insert(id, address);
        id
    }

    /// Remove a breakpoint by ID.
    pub fn remove_breakpoint(&mut self, id: u64) -> bool {
        self.breakpoints.remove(&id).is_some()
    }

    /// Add a watchpoint.
    pub fn add_watchpoint(&mut self, address: u64, kind: &'static str) -> u64 {
        let id = self.next_wp_id;
        self.next_wp_id += 1;
        self.watchpoints.insert(id, (address, kind));
        id
    }

    // ── Test-only event injection ────────────────────────────────────────────
    //
    // These three fabricate `SessionEvent`s and flip `state` without any
    // target having stopped. `debug.session_events` and `debug.session_status`
    // read exactly those fields, so a production caller of `simulate_bp_hit`
    // would be told a breakpoint was hit that never was. They are used only by
    // this file's own tests, so they are gated: the honest way for production
    // to get a BreakpointHit is for a live backend to report one.

    /// Inject a breakpoint-hit event. **Test-only.**
    #[cfg(test)]
    pub fn simulate_bp_hit(&mut self, bp_id: u64, thread_id: u64) {
        if let Some(&address) = self.breakpoints.get(&bp_id) {
            self.state = SessionState::Stopped;
            self.recorder.record(SessionEvent::BreakpointHit {
                session_id: self.id,
                bp_id,
                address,
                thread_id,
            });
        }
    }

    /// Inject a step-done event. **Test-only.**
    #[cfg(test)]
    pub fn simulate_step_done(&mut self, address: u64, thread_id: u64) {
        self.state = SessionState::Stopped;
        self.recorder.record(SessionEvent::StepDone {
            session_id: self.id,
            address,
            thread_id,
        });
    }

    /// Inject a process-exit event. **Test-only.**
    #[cfg(test)]
    pub fn simulate_exit(&mut self, code: i32) {
        self.state = SessionState::Terminated;
        self.recorder.record(SessionEvent::ProcessExit {
            session_id: self.id,
            exit_code: code,
        });
    }
}

// ── SessionPool ───────────────────────────────────────────────────────────────

/// A pool of concurrent debug sessions.
pub struct SessionPool {
    pub max_sessions: usize,
    sessions: HashMap<SessionId, DebugSession>,
}

impl SessionPool {
    #[must_use]
    pub fn new(max_sessions: usize) -> Self {
        Self {
            max_sessions,
            sessions: HashMap::new(),
        }
    }

    #[must_use]
    pub fn can_add(&self) -> bool {
        self.sessions.len() < self.max_sessions
    }

    /// # Errors
    ///
    /// Returns `Err` if the session pool is full.
    pub fn add(&mut self, session: DebugSession) -> Result<SessionId, &'static str> {
        if !self.can_add() {
            return Err("session pool is full");
        }
        let id = session.id;
        // A duplicate id used to be inserted straight over the existing entry:
        // `insert` returned the old session, it was dropped on the spot, and
        // the call reported `Ok(id)`. The pool length did not move, the
        // previous session's recorded history vanished, and `get(id)` answered
        // with the newcomer — a destructive operation reported as an addition.
        // Ids come from a global counter so this needs a caller that built one
        // by hand, which the `pub id` field allows.
        if self.sessions.contains_key(&id) {
            return Err("a session with this id is already in the pool");
        }
        self.sessions.insert(id, session);
        Ok(id)
    }

    pub fn remove(&mut self, id: SessionId) -> Option<DebugSession> {
        self.sessions.remove(&id)
    }

    #[must_use]
    pub fn get(&self, id: SessionId) -> Option<&DebugSession> {
        self.sessions.get(&id)
    }
    pub fn get_mut(&mut self, id: SessionId) -> Option<&mut DebugSession> {
        self.sessions.get_mut(&id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Every session in the pool, whatever its state.
    #[must_use]
    pub fn all_sessions(&self) -> Vec<&DebugSession> {
        self.sessions.values().collect()
    }

    /// Sessions that are still live — i.e. not `Terminated` and not `Error`.
    ///
    /// This used to return the whole pool, corpses included, while
    /// `sessions_in_state` right below it filtered properly. "How many sessions
    /// are live?" is an operational question for a multi-target debugger, and
    /// counting finished ones makes an idle pool look busy. Use
    /// [`Self::all_sessions`] for the unfiltered view.
    #[must_use]
    pub fn active_sessions(&self) -> Vec<&DebugSession> {
        self.sessions
            .values()
            .filter(|s| !matches!(s.state, SessionState::Terminated | SessionState::Error))
            .collect()
    }

    #[must_use]
    pub fn sessions_in_state(&self, state: SessionState) -> Vec<&DebugSession> {
        self.sessions
            .values()
            .filter(|s| s.state == state)
            .collect()
    }
}

impl Default for SessionPool {
    fn default() -> Self {
        Self::new(16)
    }
}

impl fmt::Debug for SessionPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SessionPool {{ {}/{} sessions }}",
            self.sessions.len(),
            self.max_sessions
        )
    }
}

// ── DebugSessionManager ───────────────────────────────────────────────────────

/// Maximum number of events retained in the global log of a
/// [`DebugSessionManager`].  Once this limit is reached the oldest entry is
/// dropped on each new `dispatch_event` call, bounding memory use regardless
/// of how many events the traced process generates
/// (`dos-memory-exhaustion`).
const GLOBAL_LOG_CAP: usize = 1_000_000;

/// Top-level manager for all debug sessions.
pub struct DebugSessionManager {
    pub pool: SessionPool,
    /// Global event log across all sessions (bounded to [`GLOBAL_LOG_CAP`]).
    global_log: std::collections::VecDeque<SessionEvent>,
    /// Number of events that were dropped due to the capacity limit.
    global_log_dropped: u64,
}

impl DebugSessionManager {
    #[must_use]
    pub fn new(max_sessions: usize) -> Self {
        Self {
            pool: SessionPool::new(max_sessions),
            global_log: std::collections::VecDeque::new(),
            global_log_dropped: 0,
        }
    }

    /// Number of global-log entries that were silently dropped because the log
    /// reached its capacity of [`GLOBAL_LOG_CAP`] entries.
    #[must_use]
    pub const fn global_log_dropped(&self) -> u64 {
        self.global_log_dropped
    }

    /// Open a new debug session.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the session pool is full.
    pub fn open_session(
        &mut self,
        target: DebugTarget,
        arch: &str,
    ) -> Result<SessionId, &'static str> {
        let session = DebugSession::new(target, arch.to_owned());
        self.pool.add(session)
    }

    /// Close a session.
    pub fn close_session(&mut self, id: SessionId) -> bool {
        self.pool.remove(id).is_some()
    }

    /// Get a session by ID.
    #[must_use]
    pub fn session(&self, id: SessionId) -> Option<&DebugSession> {
        self.pool.get(id)
    }

    /// Get a mutable session.
    pub fn session_mut(&mut self, id: SessionId) -> Option<&mut DebugSession> {
        self.pool.get_mut(id)
    }

    /// Receive an event and dispatch it.
    ///
    /// The event is appended to the bounded global log (oldest entry evicted
    /// when the log is full) and forwarded to the per-session recorder.
    pub fn dispatch_event(&mut self, event: SessionEvent) {
        let id = event.session_id();
        if self.global_log.len() >= GLOBAL_LOG_CAP {
            self.global_log.pop_front();
            self.global_log_dropped += 1;
        }
        self.global_log.push_back(event.clone());
        if let Some(session) = self.pool.get_mut(id) {
            session.recorder.record(event);
        }
    }

    /// Return the total number of events currently in the global log.
    #[must_use]
    pub fn total_events(&self) -> usize {
        self.global_log.len()
    }

    /// Return all events for a given session from the global log.
    #[must_use]
    pub fn events_for_session(&self, id: SessionId) -> Vec<&SessionEvent> {
        self.global_log
            .iter()
            .filter(|e| e.session_id() == id)
            .collect()
    }

    /// Return all session IDs.
    #[must_use]
    pub fn session_ids(&self) -> Vec<SessionId> {
        self.pool.sessions.keys().copied().collect()
    }
}

impl Default for DebugSessionManager {
    fn default() -> Self {
        Self::new(16)
    }
}

impl fmt::Debug for DebugSessionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DebugSessionManager {{ {:?} }}", self.pool)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_target() -> DebugTarget {
        DebugTarget::Process {
            pid: 1234,
            process_name: "test".into(),
        }
    }

    // ── DebugTarget ───────────────────────────────────────────────────────────

    /// `active_sessions` must exclude the ones that are over.
    ///
    /// It returned every session in the pool, terminated and errored included,
    /// while `sessions_in_state` right beside it does filter. For a multi-target
    /// debugger "how many sessions are live?" is an operational question, and
    /// the answer counted the dead ones: a pool that looks busy may hold
    /// nothing but corpses.
    ///
    /// `all_sessions` is added alongside so nothing is lost for a caller that
    /// really did want the whole pool.
    #[test]
    fn active_sessions_excludes_terminated_and_errored_ones() {
        let mut pool = SessionPool::new(8);
        let mut live = DebugSession::new(make_target(), "x86_64".into());
        live.set_state(SessionState::Stopped); // at a breakpoint: still alive
        let mut dead = DebugSession::new(make_target(), "x86_64".into());
        dead.set_state(SessionState::Terminated);
        let mut broken = DebugSession::new(make_target(), "x86_64".into());
        broken.set_state(SessionState::Error);

        let live_id = pool.add(live).unwrap();
        pool.add(dead).unwrap();
        pool.add(broken).unwrap();

        let active = pool.active_sessions();
        assert_eq!(active.len(), 1, "only the stopped session is still live");
        assert_eq!(active[0].id, live_id);

        // The whole pool is still reachable, just under a name that says so.
        assert_eq!(pool.all_sessions().len(), 3);
        assert_eq!(pool.len(), 3, "`len` still counts everything in the pool");
    }

    #[test]
    fn test_target_name_process() {
        let t = DebugTarget::Process {
            pid: 42,
            process_name: "foo".into(),
        };
        assert_eq!(t.name(), "foo[42]");
    }

    #[test]
    fn test_target_name_remote() {
        let t = DebugTarget::Remote {
            host: "localhost".into(),
            port: 1234,
            arch: "x86".into(),
        };
        assert_eq!(t.name(), "localhost:1234");
        assert_eq!(t.arch(), Some("x86"));
    }

    #[test]
    fn test_target_name_core() {
        let t = DebugTarget::CoreFile {
            path: "/tmp/core".into(),
            arch: "amd64".into(),
        };
        assert_eq!(t.name(), "/tmp/core");
    }

    #[test]
    fn test_target_display() {
        let t = DebugTarget::Launch {
            binary: "prog".into(),
            args: vec![],
            env: vec![],
        };
        assert_eq!(t.to_string(), "prog");
    }

    // ── SessionRecorder ───────────────────────────────────────────────────────

    #[test]
    fn test_recorder_empty() {
        let r = SessionRecorder::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn test_recorder_record() {
        let mut r = SessionRecorder::new();
        let id = alloc_session_id();
        r.record(SessionEvent::ProcessExit {
            session_id: id,
            exit_code: 0,
        });
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn test_recorder_filter_by_kind() {
        let mut r = SessionRecorder::new();
        let id = alloc_session_id();
        r.record(SessionEvent::ProcessExit {
            session_id: id,
            exit_code: 0,
        });
        r.record(SessionEvent::StepDone {
            session_id: id,
            address: 0x1000,
            thread_id: 1,
        });
        let exits = r.filter_by_kind("process_exit");
        assert_eq!(exits.len(), 1);
        let steps = r.filter_by_kind("step_done");
        assert_eq!(steps.len(), 1);
    }

    #[test]
    fn test_recorder_clear() {
        let mut r = SessionRecorder::new();
        let id = alloc_session_id();
        r.record(SessionEvent::Output {
            session_id: id,
            text: "hi".into(),
        });
        r.clear();
        assert!(r.is_empty());
    }

    // ── DebugSession ──────────────────────────────────────────────────────────

    #[test]
    fn test_session_initial_state() {
        let s = DebugSession::new(make_target(), "x86_64".into());
        assert_eq!(s.state, SessionState::Connecting);
        assert!(s.breakpoints.is_empty());
    }

    #[test]
    fn test_session_add_remove_breakpoint() {
        let mut s = DebugSession::new(make_target(), "x86_64".into());
        let id = s.add_breakpoint(0xDEAD_BEEF);
        assert_eq!(id, 1);
        assert!(s.breakpoints.contains_key(&id));
        assert!(s.remove_breakpoint(id));
        assert!(!s.breakpoints.contains_key(&id));
    }

    #[test]
    fn test_session_add_watchpoint() {
        let mut s = DebugSession::new(make_target(), "x86_64".into());
        let id = s.add_watchpoint(0x1000, "write");
        assert_eq!(id, 1);
        assert_eq!(s.watchpoints[&id].1, "write");
    }

    #[test]
    fn test_session_simulate_bp_hit() {
        let mut s = DebugSession::new(make_target(), "x86_64".into());
        let bp_id = s.add_breakpoint(0x4000);
        s.set_state(SessionState::Running);
        s.simulate_bp_hit(bp_id, 1);
        assert_eq!(s.state, SessionState::Stopped);
        let hits = s.recorder.filter_by_kind("breakpoint_hit");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_session_simulate_step_done() {
        let mut s = DebugSession::new(make_target(), "x86_64".into());
        s.set_state(SessionState::Stepping);
        s.simulate_step_done(0x1004, 2);
        assert_eq!(s.state, SessionState::Stopped);
        assert!(!s.recorder.filter_by_kind("step_done").is_empty());
    }

    #[test]
    fn test_session_simulate_exit() {
        let mut s = DebugSession::new(make_target(), "x86_64".into());
        s.simulate_exit(0);
        assert_eq!(s.state, SessionState::Terminated);
    }

    #[test]
    fn test_session_state_change_recorded() {
        let mut s = DebugSession::new(make_target(), "x86_64".into());
        s.set_state(SessionState::Connected);
        assert!(!s.recorder.filter_by_kind("state_changed").is_empty());
    }

    // ── SessionPool ───────────────────────────────────────────────────────────

    #[test]
    fn test_pool_add_and_get() {
        let mut pool = SessionPool::new(4);
        let s = DebugSession::new(make_target(), "arm".into());
        let id = pool.add(s).unwrap();
        assert!(pool.get(id).is_some());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_pool_full_returns_error() {
        let mut pool = SessionPool::new(1);
        let s1 = DebugSession::new(make_target(), "x86".into());
        let s2 = DebugSession::new(make_target(), "x86".into());
        pool.add(s1).unwrap();
        assert!(pool.add(s2).is_err());
    }

    #[test]
    fn test_pool_remove() {
        let mut pool = SessionPool::new(4);
        let s = DebugSession::new(make_target(), "arm64".into());
        let id = pool.add(s).unwrap();
        assert!(pool.remove(id).is_some());
        assert!(pool.get(id).is_none());
    }

    #[test]
    fn test_pool_sessions_in_state() {
        let mut pool = SessionPool::new(4);
        let mut s = DebugSession::new(make_target(), "x86_64".into());
        s.state = SessionState::Stopped;
        let id = pool.add(s).unwrap();
        let stopped = pool.sessions_in_state(SessionState::Stopped);
        assert_eq!(stopped.len(), 1);
        assert_eq!(stopped[0].id, id);
    }

    // ── DebugSessionManager ───────────────────────────────────────────────────

    #[test]
    fn test_manager_open_close_session() {
        let mut mgr = DebugSessionManager::new(4);
        let id = mgr.open_session(make_target(), "x86_64").unwrap();
        assert!(mgr.session(id).is_some());
        assert!(mgr.close_session(id));
        assert!(mgr.session(id).is_none());
    }

    #[test]
    fn test_manager_dispatch_event() {
        let mut mgr = DebugSessionManager::new(4);
        let id = mgr.open_session(make_target(), "arm64").unwrap();
        mgr.dispatch_event(SessionEvent::Output {
            session_id: id,
            text: "hello".into(),
        });
        assert_eq!(mgr.total_events(), 1);
        assert_eq!(mgr.events_for_session(id).len(), 1);
    }

    #[test]
    fn test_manager_max_sessions() {
        let mut mgr = DebugSessionManager::new(2);
        mgr.open_session(make_target(), "x86").unwrap();
        mgr.open_session(make_target(), "x86").unwrap();
        assert!(mgr.open_session(make_target(), "x86").is_err());
    }

    #[test]
    fn test_manager_session_ids() {
        let mut mgr = DebugSessionManager::new(4);
        let id1 = mgr.open_session(make_target(), "arm").unwrap();
        let id2 = mgr.open_session(make_target(), "arm64").unwrap();
        let ids = mgr.session_ids();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn test_event_kind_names() {
        let id = alloc_session_id();
        let events = vec![
            SessionEvent::BreakpointHit {
                session_id: id,
                bp_id: 1,
                address: 0,
                thread_id: 1,
            },
            SessionEvent::Exception {
                session_id: id,
                exception_code: 0,
                address: 0,
                thread_id: 1,
            },
            SessionEvent::StepDone {
                session_id: id,
                address: 0,
                thread_id: 1,
            },
            SessionEvent::ProcessExit {
                session_id: id,
                exit_code: 0,
            },
            SessionEvent::ThreadCreated {
                session_id: id,
                thread_id: 1,
            },
            SessionEvent::ThreadExited {
                session_id: id,
                thread_id: 1,
                exit_code: 0,
            },
            SessionEvent::ModuleLoaded {
                session_id: id,
                name: "libc".into(),
                base: 0,
                size: 0,
            },
            SessionEvent::ModuleUnloaded {
                session_id: id,
                name: "libc".into(),
            },
            SessionEvent::StateChanged {
                session_id: id,
                new_state: SessionState::Running,
            },
            SessionEvent::WatchpointHit {
                session_id: id,
                wp_id: 1,
                address: 0,
                access: "write",
            },
            SessionEvent::Output {
                session_id: id,
                text: "x".into(),
            },
        ];
        for e in &events {
            assert!(!e.kind().is_empty(), "{e:?} has empty kind");
        }
    }

    #[test]
    fn test_session_id_display() {
        let id = SessionId(42);
        assert_eq!(id.to_string(), "session-42");
    }

    #[test]
    fn test_session_state_display() {
        assert_eq!(SessionState::Running.to_string(), "running");
        assert_eq!(SessionState::Stopped.to_string(), "stopped");
        assert_eq!(SessionState::Terminated.to_string(), "terminated");
    }

    #[test]
    fn test_pool_default() {
        let pool = SessionPool::default();
        assert_eq!(pool.max_sessions, 16);
        assert!(pool.is_empty());
    }

    /// The per-session recorder must be bounded, and must SAY when it dropped.
    ///
    /// `dispatch_event` pushes the same event into the global log - bounded,
    /// with a dropped counter - and then into this recorder, which was an
    /// unbounded Vec. A session that single-steps or hits a hot watchpoint
    /// produces events without limit, so the memory grew for as long as the
    /// session lived.
    ///
    /// Bounding alone would not be enough: a caller reading `events` could not
    /// tell a complete history from a truncated one, and "the breakpoint was
    /// never hit before this point" is exactly the conclusion a debugger must
    /// not let anyone draw from a missing tail.
    #[test]
    fn the_session_recorder_is_bounded_and_reports_what_it_dropped() {
        let mut r = SessionRecorder::new();
        assert!(r.is_complete(), "an empty log is a complete history");

        for i in 0..(SESSION_RECORDER_CAP + 25) {
            r.record(SessionEvent::StateChanged {
                session_id: SessionId(1),
                new_state: if i % 2 == 0 { SessionState::Running } else { SessionState::Stopped },
            });
        }
        assert_eq!(r.len(), SESSION_RECORDER_CAP, "the log must stop growing at the cap");
        assert_eq!(r.dropped(), 25, "every evicted event must be counted");
        assert!(!r.is_complete(), "a truncated log must not pass for a whole one");

        // The events kept are the MOST RECENT ones: a debugger reading the tail
        // of a session needs what just happened, not what happened first.
        assert!(matches!(
            r.last().map(|e| &e.event),
            Some(SessionEvent::StateChanged { .. })
        ));

        r.clear();
        assert!(r.is_complete(), "after clear the log is again the whole history");
        assert_eq!(r.dropped(), 0);
    }

    /// Adding a session whose id is already in the pool must be REFUSED, not
    /// silently swallowed.
    ///
    /// `insert` replaced the existing entry, dropped it on the spot and
    /// returned `Ok(id)`: the pool length did not move, the previous session
    /// history vanished, and `get(id)` answered with the newcomer. A
    /// destructive operation reported as an addition.
    #[test]
    fn adding_a_duplicate_session_id_is_refused_and_keeps_the_original() {
        let mut pool = SessionPool::new(8);
        let mut first = DebugSession::new(DebugTarget::Process { pid: 1234, process_name: "first".to_string() }, "x86_64".to_string());
        first.set_state(SessionState::Running);
        let id = first.id;
        let recorded = first.recorder.len();
        assert!(recorded > 0, "the fixture must have some history to lose");
        pool.add(first).expect("the first session must be accepted");

        let mut clash = DebugSession::new(DebugTarget::Process { pid: 5678, process_name: "clash".to_string() }, "x86_64".to_string());
        clash.id = id;
        assert!(pool.add(clash).is_err(), "a duplicate id must be refused");
        assert_eq!(pool.len(), 1);
        let kept = pool.get(id).expect("the original session must still be there");
        assert_eq!(kept.recorder.len(), recorded, "the original history must survive");
    }

}
