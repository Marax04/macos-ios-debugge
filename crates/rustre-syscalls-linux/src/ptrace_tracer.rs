//! ptrace-based syscall tracing model.
//!
//! Provides an abstraction layer that models Linux ptrace syscall tracing:
//! session management, per-thread tracking, entry/exit event emission, and
//! the traced-process lifecycle.  Platform-specific ptrace calls are
//! represented as a trait so that the model compiles and tests on all platforms
//! while the real implementation can be provided on Linux.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub use crate::LinuxSyscall;
use crate::LinuxSyscallDb;
use rustre_syscalls::SyscallArch;

// ─── Pid / Tid ────────────────────────────────────────────────────────────────

/// A process ID.
pub type Pid = u32;

/// A thread ID (same namespace as `Pid` on Linux).
pub type Tid = u32;


// ─── SyscallEntry ─────────────────────────────────────────────────────────────

/// Event emitted when a thread is about to enter a syscall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEntry {
    /// Thread that is entering the syscall.
    pub tid: Tid,
    /// Syscall number.
    pub nr: u32,
    /// Raw argument registers (up to 6 for x86-64).
    pub args: [u64; 6],
    /// Architecture of the process.
    pub arch: SyscallArch,
    /// Instruction pointer at the syscall entry.
    pub ip: u64,
    /// Monotonic timestamp (nanoseconds since tracer start).
    pub timestamp_ns: u64,
}

impl SyscallEntry {
    /// Build a new entry event with the given fields.
    #[must_use]
    pub const fn new(
        tid: Tid,
        nr: u32,
        args: [u64; 6],
        arch: SyscallArch,
        ip: u64,
        ts: u64,
    ) -> Self {
        Self {
            tid,
            nr,
            args,
            arch,
            ip,
            timestamp_ns: ts,
        }
    }

    /// Convenience: return `args[0]` (first argument).
    #[must_use]
    pub const fn arg0(&self) -> u64 {
        self.args[0]
    }
    #[must_use]
    pub const fn arg1(&self) -> u64 {
        self.args[1]
    }
    #[must_use]
    pub const fn arg2(&self) -> u64 {
        self.args[2]
    }
    #[must_use]
    pub const fn arg3(&self) -> u64 {
        self.args[3]
    }
    #[must_use]
    pub const fn arg4(&self) -> u64 {
        self.args[4]
    }
    #[must_use]
    pub const fn arg5(&self) -> u64 {
        self.args[5]
    }
}

// ─── SyscallExit ──────────────────────────────────────────────────────────────

/// Event emitted when a syscall has returned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallExit {
    /// Thread that is exiting the syscall.
    pub tid: Tid,
    /// Syscall number (matches the preceding `SyscallEntry`).
    pub nr: u32,
    /// Return value (negative = errno-encoded error).
    pub retval: i64,
    /// Elapsed kernel time for this syscall in nanoseconds.
    pub elapsed_ns: u64,
    /// Monotonic timestamp at exit.
    pub timestamp_ns: u64,
}

impl SyscallExit {
    #[must_use]
    pub const fn new(tid: Tid, nr: u32, retval: i64, elapsed_ns: u64, ts: u64) -> Self {
        Self {
            tid,
            nr,
            retval,
            elapsed_ns,
            timestamp_ns: ts,
        }
    }

    /// Return `true` if the syscall returned an error (retval < 0).
    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.retval < 0
    }

    /// Return the positive errno value if the syscall failed, else `None`.
    #[must_use]
    pub fn errno(&self) -> Option<u32> {
        if self.retval < 0 {
            let abs = self.retval.unsigned_abs();
            let v = u32::try_from(abs).unwrap_or(u32::MAX);
            Some(v)
        } else {
            None
        }
    }
}

// ─── TracedThread ─────────────────────────────────────────────────────────────

/// State tracked per thread during a trace session.
#[derive(Debug, Clone)]
pub struct TracedThread {
    /// Thread ID.
    pub tid: Tid,
    /// Whether this thread is currently inside a syscall (between entry and exit).
    pub in_syscall: bool,
    /// The pending entry event while waiting for the corresponding exit.
    pub pending_entry: Option<SyscallEntry>,
    /// Total number of syscalls completed by this thread.
    pub syscall_count: u64,
    /// Whether this thread is a clone of another (is a true thread, not process).
    pub is_thread: bool,
}

impl TracedThread {
    #[must_use]
    pub const fn new(tid: Tid, is_thread: bool) -> Self {
        Self {
            tid,
            in_syscall: false,
            pending_entry: None,
            syscall_count: 0,
            is_thread,
        }
    }
}

// ─── ThreadTracker ────────────────────────────────────────────────────────────

/// Tracks all threads in a traced process.
#[derive(Debug, Default)]
pub struct ThreadTracker {
    threads: HashMap<Tid, TracedThread>,
}

impl ThreadTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new thread.
    pub fn add_thread(&mut self, tid: Tid, is_thread: bool) {
        self.threads.insert(tid, TracedThread::new(tid, is_thread));
    }

    /// Remove a thread from tracking.
    pub fn remove_thread(&mut self, tid: Tid) {
        self.threads.remove(&tid);
    }

    /// Record a syscall entry for the thread.  Returns `false` if the thread is
    /// not tracked.
    pub fn on_entry(&mut self, entry: SyscallEntry) -> bool {
        if let Some(t) = self.threads.get_mut(&entry.tid) {
            t.in_syscall = true;
            t.pending_entry = Some(entry);
            true
        } else {
            false
        }
    }

    /// Record a syscall exit for the thread.  Returns the matching entry if one
    /// was pending.
    pub fn on_exit(&mut self, exit: &SyscallExit) -> Option<SyscallEntry> {
        let t = self.threads.get_mut(&exit.tid)?;
        t.in_syscall = false;
        t.syscall_count += 1;
        t.pending_entry.take()
    }

    /// Return the tracked thread state for `tid`.
    #[must_use]
    pub fn get(&self, tid: Tid) -> Option<&TracedThread> {
        self.threads.get(&tid)
    }

    /// Total number of tracked threads.
    #[must_use]
    pub fn len(&self) -> usize {
        self.threads.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.threads.is_empty()
    }

    /// Iterate over all tracked threads.
    pub fn iter(&self) -> impl Iterator<Item = &TracedThread> {
        self.threads.values()
    }

    /// Sum of syscall counts across all threads.
    #[must_use]
    pub fn total_syscall_count(&self) -> u64 {
        self.threads.values().map(|t| t.syscall_count).sum()
    }
}

// ─── TracedProcess ────────────────────────────────────────────────────────────

/// Represents the traced process and holds its associated metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracedProcess {
    /// The main process PID.
    pub pid: Pid,
    /// Process name (if known).
    pub name: Option<String>,
    /// Architecture.
    pub arch: SyscallArch,
    /// Whether the process has exited.
    pub exited: bool,
    /// Exit code (valid if `exited` is `true`).
    pub exit_code: Option<i32>,
}

impl TracedProcess {
    #[must_use]
    pub const fn new(pid: Pid, arch: SyscallArch) -> Self {
        Self {
            pid,
            name: None,
            arch,
            exited: false,
            exit_code: None,
        }
    }

    /// Mark the process as exited with the given exit code.
    pub const fn mark_exited(&mut self, code: i32) {
        self.exited = true;
        self.exit_code = Some(code);
    }
}

// ─── TraceEvent ───────────────────────────────────────────────────────────────

/// A union type for all events emitted by the tracer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TraceEvent {
    /// Syscall entry.
    Entry(SyscallEntry),
    /// Syscall exit.
    Exit(SyscallExit),
    /// Process/thread spawned.
    Spawn {
        parent: Pid,
        child: Pid,
        is_thread: bool,
    },
    /// Thread exited.
    ThreadExit { tid: Tid, code: i32 },
    /// Signal delivered to the process.
    Signal { tid: Tid, signum: u32 },
    /// Trace ended (process exited or detached).
    End { pid: Pid, exit_code: Option<i32> },
}

impl TraceEvent {
    /// Return the tid/pid this event is associated with.
    #[must_use]
    pub const fn tid(&self) -> Option<Tid> {
        match self {
            Self::Entry(e) => Some(e.tid),
            Self::Exit(e) => Some(e.tid),
            Self::ThreadExit { tid, .. } | Self::Signal { tid, .. } => Some(*tid),
            _ => None,
        }
    }

    /// Whether the event represents a syscall entry.
    #[must_use]
    pub const fn is_entry(&self) -> bool {
        matches!(self, Self::Entry(_))
    }

    /// Whether the event represents a syscall exit.
    #[must_use]
    pub const fn is_exit(&self) -> bool {
        matches!(self, Self::Exit(_))
    }
}

// ─── TraceSession ─────────────────────────────────────────────────────────────

/// An active ptrace trace session.
#[derive(Debug)]
pub struct TraceSession {
    /// The process under trace.
    pub process: TracedProcess,
    /// Per-thread state.
    pub threads: ThreadTracker,
    /// Syscall database for annotation.
    db: LinuxSyscallDb,
    /// All events received during this session.
    events: Vec<TraceEvent>,
    /// Wall-clock start time.
    start: Instant,
    /// Whether follow-fork mode is active.
    pub follow_fork: bool,
    /// Whether to annotate events with syscall names.
    pub annotate: bool,
}

impl TraceSession {
    /// Start a new session for `process`.
    #[must_use]
    pub fn new(process: TracedProcess) -> Self {
        let mut threads = ThreadTracker::new();
        threads.add_thread(process.pid, false);
        Self {
            process,
            threads,
            db: LinuxSyscallDb::new(),
            events: Vec::new(),
            start: Instant::now(),
            follow_fork: false,
            annotate: true,
        }
    }

    /// Feed a raw entry event into the session; returns the resolved syscall
    /// name if annotation is enabled.
    pub fn push_entry(&mut self, entry: SyscallEntry) -> Option<String> {
        let name = if self.annotate {
            self.db.lookup(entry.arch, entry.nr).map(|s| s.name.clone())
        } else {
            None
        };
        self.threads.on_entry(entry.clone());
        self.events.push(TraceEvent::Entry(entry));
        name
    }

    /// Feed a raw exit event into the session.
    pub fn push_exit(&mut self, exit: SyscallExit) {
        self.threads.on_exit(&exit);
        self.events.push(TraceEvent::Exit(exit));
    }

    /// Inject a spawn event (new process or thread).
    pub fn push_spawn(&mut self, parent: Pid, child: Pid, is_thread: bool) {
        self.threads.add_thread(child, is_thread);
        self.events.push(TraceEvent::Spawn {
            parent,
            child,
            is_thread,
        });
    }

    /// Mark the process as ended.
    pub fn end(&mut self, exit_code: Option<i32>) {
        if let Some(code) = exit_code {
            self.process.mark_exited(code);
        }
        self.events.push(TraceEvent::End {
            pid: self.process.pid,
            exit_code,
        });
    }

    /// Elapsed time since the session started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// All events in chronological order.
    #[must_use]
    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }

    /// Total syscall event count (entries + exits).
    #[must_use]
    pub fn syscall_event_count(&self) -> usize {
        self.events
            .iter()
            .filter(|e| e.is_entry() || e.is_exit())
            .count()
    }

    /// Return all entry events.
    #[must_use]
    pub fn entries(&self) -> Vec<&SyscallEntry> {
        self.events
            .iter()
            .filter_map(|e| {
                if let TraceEvent::Entry(en) = e {
                    Some(en)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return all exit events.
    #[must_use]
    pub fn exits(&self) -> Vec<&SyscallExit> {
        self.events
            .iter()
            .filter_map(|e| {
                if let TraceEvent::Exit(ex) = e {
                    Some(ex)
                } else {
                    None
                }
            })
            .collect()
    }
}

// ─── PtraceTracer ─────────────────────────────────────────────────────────────

/// High-level ptrace tracer.  Manages one or more [`TraceSession`]s and routes
/// raw ptrace stop events to the appropriate session.
#[derive(Debug, Default)]
pub struct PtraceTracer {
    sessions: HashMap<Pid, TraceSession>,
    next_ts: u64,
}

impl PtraceTracer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach to a new process and start a session.
    pub fn attach(&mut self, pid: Pid, arch: SyscallArch) {
        let proc = TracedProcess::new(pid, arch);
        self.sessions.insert(pid, TraceSession::new(proc));
    }

    /// Detach from a process, ending its session.
    pub fn detach(&mut self, pid: Pid, exit_code: Option<i32>) {
        if let Some(sess) = self.sessions.get_mut(&pid) {
            sess.end(exit_code);
        }
    }

    /// Notify the tracer of a syscall-stop entry.
    pub fn on_syscall_entry(&mut self, pid: Pid, tid: Tid, nr: u32, args: [u64; 6], ip: u64) {
        let ts = self.next_ts;
        self.next_ts += 1;
        if let Some(sess) = self.sessions.get_mut(&pid) {
            let arch = sess.process.arch;
            sess.push_entry(SyscallEntry::new(tid, nr, args, arch, ip, ts));
        }
    }

    /// Notify the tracer of a syscall-stop exit.
    pub fn on_syscall_exit(&mut self, pid: Pid, tid: Tid, nr: u32, retval: i64, elapsed_ns: u64) {
        let ts = self.next_ts;
        self.next_ts += 1;
        if let Some(sess) = self.sessions.get_mut(&pid) {
            sess.push_exit(SyscallExit::new(tid, nr, retval, elapsed_ns, ts));
        }
    }

    /// Return the session for `pid` if it exists.
    #[must_use]
    pub fn session(&self, pid: Pid) -> Option<&TraceSession> {
        self.sessions.get(&pid)
    }

    /// Total number of active sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Collect all events across all sessions in the order they arrived.
    ///
    /// Events are sorted by their embedded monotonic timestamp. Non-syscall
    /// events (`Spawn`, `Signal`, `ThreadExit`, `End`) carry no timestamp and sort
    /// after all timestamped events (timestamp treated as `u64::MAX`).
    #[must_use]
    pub fn all_events(&self) -> Vec<&TraceEvent> {
        let mut v: Vec<&TraceEvent> = self
            .sessions
            .values()
            .flat_map(TraceSession::events)
            .collect();
        v.sort_by_key(|ev| match ev {
            TraceEvent::Entry(e) => e.timestamp_ns,
            TraceEvent::Exit(e) => e.timestamp_ns,
            _ => u64::MAX,
        });
        v
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_syscalls::SyscallArch;

    fn zero_args() -> [u64; 6] {
        [0u64; 6]
    }

    // --- SyscallEntry ---

    #[test]
    fn entry_arg_accessors() {
        let args = [1, 2, 3, 4, 5, 6];
        let e = SyscallEntry::new(100, 0, args, SyscallArch::X86_64, 0x7fff, 0);
        assert_eq!(e.arg0(), 1);
        assert_eq!(e.arg5(), 6);
    }

    #[test]
    fn entry_serialise() {
        let e = SyscallEntry::new(1, 42, zero_args(), SyscallArch::Arm64, 0, 0);
        let json = serde_json::to_string(&e).unwrap();
        let back: SyscallEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.nr, 42);
    }

    // --- SyscallExit ---

    #[test]
    fn exit_not_error_on_success() {
        let ex = SyscallExit::new(1, 0, 5, 100, 1);
        assert!(!ex.is_error());
        assert_eq!(ex.errno(), None);
    }

    #[test]
    fn exit_error_on_negative_retval() {
        let ex = SyscallExit::new(1, 0, -2, 0, 2);
        assert!(ex.is_error());
        assert_eq!(ex.errno(), Some(2));
    }

    // --- ThreadTracker ---

    #[test]
    fn tracker_add_remove() {
        let mut tr = ThreadTracker::new();
        tr.add_thread(10, false);
        assert_eq!(tr.len(), 1);
        tr.remove_thread(10);
        assert!(tr.is_empty());
    }

    #[test]
    fn tracker_on_entry_sets_in_syscall() {
        let mut tr = ThreadTracker::new();
        tr.add_thread(10, false);
        let e = SyscallEntry::new(10, 0, zero_args(), SyscallArch::X86_64, 0, 0);
        assert!(tr.on_entry(e));
        assert!(tr.get(10).unwrap().in_syscall);
    }

    #[test]
    fn tracker_on_entry_unknown_thread_returns_false() {
        let mut tr = ThreadTracker::new();
        let e = SyscallEntry::new(99, 0, zero_args(), SyscallArch::X86_64, 0, 0);
        assert!(!tr.on_entry(e));
    }

    #[test]
    fn tracker_on_exit_clears_in_syscall() {
        let mut tr = ThreadTracker::new();
        tr.add_thread(10, false);
        let e = SyscallEntry::new(10, 0, zero_args(), SyscallArch::X86_64, 0, 0);
        tr.on_entry(e);
        let ex = SyscallExit::new(10, 0, 0, 0, 1);
        tr.on_exit(&ex);
        assert!(!tr.get(10).unwrap().in_syscall);
    }

    #[test]
    fn tracker_total_syscall_count() {
        let mut tr = ThreadTracker::new();
        tr.add_thread(1, false);
        tr.add_thread(2, false);
        for _ in 0..3 {
            let e = SyscallEntry::new(1, 0, zero_args(), SyscallArch::X86_64, 0, 0);
            tr.on_entry(e);
            let ex = SyscallExit::new(1, 0, 0, 0, 0);
            tr.on_exit(&ex);
        }
        for _ in 0..2 {
            let e = SyscallEntry::new(2, 1, zero_args(), SyscallArch::X86_64, 0, 0);
            tr.on_entry(e);
            let ex = SyscallExit::new(2, 1, 0, 0, 0);
            tr.on_exit(&ex);
        }
        assert_eq!(tr.total_syscall_count(), 5);
    }

    // --- TracedProcess ---

    #[test]
    fn traced_process_mark_exited() {
        let mut p = TracedProcess::new(42, SyscallArch::X86_64);
        assert!(!p.exited);
        p.mark_exited(0);
        assert!(p.exited);
        assert_eq!(p.exit_code, Some(0));
    }

    // --- TraceEvent ---

    #[test]
    fn trace_event_is_entry() {
        let e = SyscallEntry::new(1, 0, zero_args(), SyscallArch::X86_64, 0, 0);
        let ev = TraceEvent::Entry(e);
        assert!(ev.is_entry());
        assert!(!ev.is_exit());
    }

    #[test]
    fn trace_event_tid_entry() {
        let e = SyscallEntry::new(7, 0, zero_args(), SyscallArch::X86_64, 0, 0);
        let ev = TraceEvent::Entry(e);
        assert_eq!(ev.tid(), Some(7));
    }

    #[test]
    fn trace_event_spawn_no_tid() {
        let ev = TraceEvent::Spawn {
            parent: 1,
            child: 2,
            is_thread: false,
        };
        assert_eq!(ev.tid(), None);
    }

    // --- TraceSession ---

    #[test]
    fn session_push_entry_and_exit() {
        let proc = TracedProcess::new(1, SyscallArch::X86_64);
        let mut sess = TraceSession::new(proc);
        let e = SyscallEntry::new(1, 0, zero_args(), SyscallArch::X86_64, 0, 0);
        sess.push_entry(e);
        let ex = SyscallExit::new(1, 0, 10, 0, 1);
        sess.push_exit(ex);
        assert_eq!(sess.syscall_event_count(), 2);
    }

    #[test]
    fn session_push_spawn() {
        let proc = TracedProcess::new(1, SyscallArch::X86_64);
        let mut sess = TraceSession::new(proc);
        sess.push_spawn(1, 2, true);
        assert_eq!(sess.threads.len(), 2);
    }

    #[test]
    fn session_entries_exits() {
        let proc = TracedProcess::new(1, SyscallArch::X86_64);
        let mut sess = TraceSession::new(proc);
        sess.push_entry(SyscallEntry::new(
            1,
            0,
            zero_args(),
            SyscallArch::X86_64,
            0,
            0,
        ));
        sess.push_exit(SyscallExit::new(1, 0, 0, 0, 0));
        assert_eq!(sess.entries().len(), 1);
        assert_eq!(sess.exits().len(), 1);
    }

    #[test]
    fn session_end_marks_process_exited() {
        let proc = TracedProcess::new(1, SyscallArch::X86_64);
        let mut sess = TraceSession::new(proc);
        sess.end(Some(0));
        assert!(sess.process.exited);
    }

    // --- PtraceTracer ---

    #[test]
    fn tracer_attach_creates_session() {
        let mut tr = PtraceTracer::new();
        tr.attach(100, SyscallArch::X86_64);
        assert_eq!(tr.session_count(), 1);
        assert!(tr.session(100).is_some());
    }

    #[test]
    fn tracer_on_entry_exit() {
        let mut tr = PtraceTracer::new();
        tr.attach(1, SyscallArch::X86_64);
        tr.on_syscall_entry(1, 1, 0, zero_args(), 0);
        tr.on_syscall_exit(1, 1, 0, 10, 100);
        let sess = tr.session(1).unwrap();
        assert_eq!(sess.syscall_event_count(), 2);
    }

    #[test]
    fn tracer_detach_ends_session() {
        let mut tr = PtraceTracer::new();
        tr.attach(5, SyscallArch::X86_64);
        tr.detach(5, Some(0));
        assert!(tr.session(5).unwrap().process.exited);
    }

    #[test]
    fn tracer_unknown_pid_entry_noop() {
        let mut tr = PtraceTracer::new();
        // Should not panic.
        tr.on_syscall_entry(999, 999, 0, zero_args(), 0);
    }
}
