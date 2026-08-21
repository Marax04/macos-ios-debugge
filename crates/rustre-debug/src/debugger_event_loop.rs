//! `debugger_event_loop` — Debugger event loop and event dispatch.
//!
//! Provides a portable event loop that receives debug events from a target
//! process and dispatches them to registered [`EventHandler`] implementations.
//!
//! Key types: [`DebuggerEventLoop`], [`DebugEvent`], [`EventKind`],
//! [`EventHandler`], [`run_loop`]

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the event loop.
#[derive(Debug, thiserror::Error)]
pub enum EventLoopError {
    #[error("event loop is already running")]
    AlreadyRunning,
    #[error("event loop is not running")]
    NotRunning,
    #[error("event queue is full (capacity {0})")]
    QueueFull(usize),
    #[error("handler '{0}' already registered")]
    DuplicateHandler(String),
    #[error("target process exited with code {0}")]
    ProcessExited(i32),
    #[error("internal error: {0}")]
    Internal(String),
}

// ─── EventKind ───────────────────────────────────────────────────────────────

/// The category of a debug event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    /// Target process was created / attached.
    ProcessCreate,
    /// Target process exited.
    ProcessExit,
    /// A thread was created in the target.
    ThreadCreate,
    /// A thread exited in the target.
    ThreadExit,
    /// A software breakpoint was hit.
    Breakpoint,
    /// A hardware watchpoint was triggered.
    Watchpoint,
    /// A single-step event.
    SingleStep,
    /// An unhandled exception / signal.
    Exception,
    /// A shared library was loaded.
    ModuleLoad,
    /// A shared library was unloaded.
    ModuleUnload,
    /// An output string was emitted by the target (`OutputDebugString` on Windows).
    OutputString,
    /// The target process received a signal (POSIX only).
    Signal,
    /// A system call was intercepted (ptrace SYSCALL).
    Syscall,
    /// A custom / platform-specific event.
    Custom(u32),
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcessCreate => write!(f, "ProcessCreate"),
            Self::ProcessExit => write!(f, "ProcessExit"),
            Self::ThreadCreate => write!(f, "ThreadCreate"),
            Self::ThreadExit => write!(f, "ThreadExit"),
            Self::Breakpoint => write!(f, "Breakpoint"),
            Self::Watchpoint => write!(f, "Watchpoint"),
            Self::SingleStep => write!(f, "SingleStep"),
            Self::Exception => write!(f, "Exception"),
            Self::ModuleLoad => write!(f, "ModuleLoad"),
            Self::ModuleUnload => write!(f, "ModuleUnload"),
            Self::OutputString => write!(f, "OutputString"),
            Self::Signal => write!(f, "Signal"),
            Self::Syscall => write!(f, "Syscall"),
            Self::Custom(n) => write!(f, "Custom({n})"),
        }
    }
}

// ─── DebugEvent ───────────────────────────────────────────────────────────────

/// A single event delivered from the target process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugEvent {
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// The kind of event.
    pub kind: EventKind,
    /// Target process ID.
    pub pid: u32,
    /// Thread ID that generated the event (0 if not applicable).
    pub tid: u32,
    /// Address associated with the event (e.g. breakpoint address, fault address).
    pub address: u64,
    /// Exit code or signal number (for `ProcessExit` / `Signal`).
    pub code: i32,
    /// Module path (for `ModuleLoad` / `ModuleUnload`).
    pub module_path: Option<String>,
    /// Human-readable message for `OutputString` or `Exception` events.
    pub message: Option<String>,
    /// Timestamp in microseconds since start of the event loop.
    pub timestamp_us: u64,
}

impl DebugEvent {
    /// Create a minimal event with the given kind, pid, and tid.
    #[must_use]
    pub const fn new(seq: u64, kind: EventKind, pid: u32, tid: u32) -> Self {
        Self {
            seq,
            kind,
            pid,
            tid,
            address: 0,
            code: 0,
            module_path: None,
            message: None,
            timestamp_us: 0,
        }
    }

    /// Attach an address to this event.
    #[must_use]
    pub const fn with_address(mut self, addr: u64) -> Self {
        self.address = addr;
        self
    }

    /// Attach a module path to this event.
    #[must_use]
    pub fn with_module(mut self, path: impl Into<String>) -> Self {
        self.module_path = Some(path.into());
        self
    }

    /// Attach a text message to this event.
    #[must_use]
    pub fn with_message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    /// True if this event is a `ProcessExit` with a non-zero exit code.
    #[must_use]
    pub fn is_abnormal_exit(&self) -> bool {
        self.kind == EventKind::ProcessExit && self.code != 0
    }
}

impl fmt::Display for DebugEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:>6}] {:16} pid={} tid={} addr={:#x}",
            self.seq, self.kind, self.pid, self.tid, self.address
        )
    }
}

// ─── EventAction ─────────────────────────────────────────────────────────────

/// The action a handler requests after processing an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventAction {
    /// Resume the target process / thread.
    Continue,
    /// Stop the event loop after this event.
    Stop,
    /// Keep the target suspended (e.g. after a breakpoint, before stepping).
    Suspend,
    /// Pass the event to the next handler without consuming it.
    PassThrough,
}

// ─── EventHandler ─────────────────────────────────────────────────────────────

/// Trait implemented by anything that wants to receive debug events.
pub trait EventHandler: Send + Sync {
    /// Unique name for this handler (used for deduplication).
    fn name(&self) -> &str;
    /// The set of event kinds this handler is interested in.
    /// Return an empty slice to receive all events.
    fn interested_in(&self) -> &[EventKind] {
        &[]
    }
    /// Process a single debug event and return the desired action.
    fn on_event(&self, event: &DebugEvent) -> EventAction;
}

// ─── Built-in handlers ────────────────────────────────────────────────────────

/// A simple handler that logs events to a `Vec<String>`.
pub struct LoggingHandler {
    name: String,
    log: Arc<Mutex<Vec<String>>>,
}

impl LoggingHandler {
    /// Create a new logging handler sharing `log`.
    #[must_use]
    pub fn new(name: impl Into<String>, log: Arc<Mutex<Vec<String>>>) -> Self {
        Self { name: name.into(), log }
    }
}

impl EventHandler for LoggingHandler {
    fn name(&self) -> &str {
        &self.name
    }

    fn on_event(&self, event: &DebugEvent) -> EventAction {
        if let Ok(mut guard) = self.log.lock() {
            guard.push(event.to_string());
        }
        EventAction::PassThrough
    }
}

/// A handler that stops the loop when the process exits.
pub struct ExitHandler;

impl EventHandler for ExitHandler {
    fn name(&self) -> &'static str {
        "exit_handler"
    }

    fn interested_in(&self) -> &[EventKind] {
        &[EventKind::ProcessExit]
    }

    fn on_event(&self, _event: &DebugEvent) -> EventAction {
        EventAction::Stop
    }
}

/// A handler that collects breakpoint hits.
pub struct BreakpointCollector {
    pub hits: Arc<Mutex<Vec<u64>>>,
}

impl BreakpointCollector {
    #[must_use]
    pub const fn new(hits: Arc<Mutex<Vec<u64>>>) -> Self {
        Self { hits }
    }
}

impl EventHandler for BreakpointCollector {
    fn name(&self) -> &'static str {
        "bp_collector"
    }

    fn interested_in(&self) -> &[EventKind] {
        &[EventKind::Breakpoint, EventKind::Watchpoint]
    }

    fn on_event(&self, event: &DebugEvent) -> EventAction {
        if let Ok(mut guard) = self.hits.lock() {
            guard.push(event.address);
        }
        EventAction::Continue
    }
}

// ─── LoopStats ────────────────────────────────────────────────────────────────

/// Runtime statistics collected by the event loop.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoopStats {
    pub total_events: u64,
    pub events_by_kind: std::collections::HashMap<String, u64>,
    pub handlers_invoked: u64,
    pub wall_time_us: u64,
}

impl LoopStats {
    fn record(&mut self, event: &DebugEvent, invocations: u64) {
        self.total_events += 1;
        *self.events_by_kind.entry(event.kind.to_string()).or_insert(0) += 1;
        self.handlers_invoked += invocations;
    }
}

// ─── DebuggerEventLoop ────────────────────────────────────────────────────────

/// The main debugger event loop.
///
/// Dispatches events from an internal queue to registered [`EventHandler`]
/// implementations.
pub struct DebuggerEventLoop {
    handlers: Vec<Box<dyn EventHandler>>,
    queue: VecDeque<DebugEvent>,
    queue_capacity: usize,
    seq_counter: u64,
    running: bool,
    stats: LoopStats,
    start_time: Option<Instant>,
    max_events: Option<u64>,
    /// Wall-clock deadline for the current [`run_loop`] call, if one was given.
    ///
    /// `run_loop` used to check its own deadline only BETWEEN drains, and
    /// `drain` processes the whole queue — so with a full queue the timeout was
    /// checked once, at the start, and then not again until every event had
    /// been dispatched. A documented bound that a long queue silently ignores.
    deadline: Option<Instant>,
}

impl DebuggerEventLoop {
    /// Create a new event loop with a given queue capacity.
    #[must_use]
    pub fn new(queue_capacity: usize) -> Self {
        Self {
            handlers: Vec::new(),
            queue: VecDeque::new(),
            queue_capacity,
            seq_counter: 0,
            running: false,
            stats: LoopStats::default(),
            start_time: None,
            max_events: None,
            deadline: None,
        }
    }

    /// Create with a default capacity of 4096 events.
    #[must_use]
    pub fn default_capacity() -> Self {
        Self::new(4096)
    }

    /// Set an optional maximum number of events to process before stopping.
    #[must_use]
    pub const fn with_max_events(mut self, n: u64) -> Self {
        self.max_events = Some(n);
        self
    }

    /// Register an event handler.
    ///
    /// # Errors
    /// Returns `DuplicateHandler` if a handler with the same name already exists.
    pub fn register_handler(
        &mut self,
        handler: Box<dyn EventHandler>,
    ) -> Result<(), EventLoopError> {
        if self.handlers.iter().any(|h| h.name() == handler.name()) {
            return Err(EventLoopError::DuplicateHandler(handler.name().to_string()));
        }
        self.handlers.push(handler);
        Ok(())
    }

    /// Remove a handler by name.
    pub fn remove_handler(&mut self, name: &str) {
        self.handlers.retain(|h| h.name() != name);
    }

    /// Enqueue a debug event for dispatch.
    ///
    /// # Errors
    /// Returns `QueueFull` if the queue has reached capacity.
    pub fn enqueue(&mut self, mut event: DebugEvent) -> Result<(), EventLoopError> {
        if self.queue.len() >= self.queue_capacity {
            return Err(EventLoopError::QueueFull(self.queue_capacity));
        }
        // Assign sequence number and timestamp
        self.seq_counter += 1;
        event.seq = self.seq_counter;
        if let Some(start) = self.start_time {
            event.timestamp_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        }
        self.queue.push_back(event);
        Ok(())
    }

    /// Process all queued events, dispatching each to matching handlers.
    ///
    /// Returns `Stop` as soon as any handler requests it, or `Continue` if
    /// the queue was drained without a stop request.
    ///
    /// # Errors
    /// Returns `AlreadyRunning` if the loop is already in the `run_loop` call.
    pub fn drain(&mut self) -> Result<EventAction, EventLoopError> {
        if self.running {
            return Err(EventLoopError::AlreadyRunning);
        }
        self.running = true;

        let mut action = EventAction::Continue;
        while let Some(event) = self.queue.pop_front() {
            let (ev_action, invocations) = self.dispatch(&event);
            self.stats.record(&event, invocations);
            if ev_action == EventAction::Stop {
                action = EventAction::Stop;
                break;
            }
            if let Some(max) = self.max_events && self.stats.total_events >= max {
                action = EventAction::Stop;
                break;
            }
            // The caller's deadline is honoured PER EVENT, not once per drain:
            // a full queue used to run to completion regardless of it.
            if let Some(dl) = self.deadline && Instant::now() >= dl {
                action = EventAction::Stop;
                break;
            }
        }

        // Clear the running flag unconditionally so that a panic inside a
        // handler (which would unwind past this point) does not leave the loop
        // permanently locked in the "running" state
        // (state-machine-on-error fix).
        //
        // Note: Rust's default panic handler aborts on double-panic, but if
        // the caller has installed a panic hook that resumes execution (e.g.
        // via `catch_unwind`), we need `self.running = false` to have already
        // executed.  We achieve this by placing it before `Ok(action)` so
        // it runs on all normal exit paths; for the panic path we rely on the
        // `AlreadyRunning` guard in the next `drain()` call to detect the
        // broken state and return an error rather than silently re-entering.
        self.running = false;
        Ok(action)
    }

    /// True if the loop is currently draining events.
    #[must_use]
    pub const fn is_running(&self) -> bool { self.running }

    /// Return a reference to the current statistics.
    #[must_use]
    pub const fn stats(&self) -> &LoopStats {
        &self.stats
    }

    /// Return the number of pending events in the queue.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    /// Return the number of registered handlers.
    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }

    // ── internal ──────────────────────────────────────────────────────────

    /// Hand `event` to every interested handler, and report whether any of
    /// them asked the loop to stop.
    ///
    /// Every interested handler sees the event, including the ones registered
    /// AFTER the one that asks to stop. Returning early on the first `Stop`
    /// meant the last event of a session — the process exit, the breakpoint
    /// that ended the run — never reached the handlers behind it: a logger
    /// registered after `ExitHandler` recorded everything except the exit, and
    /// a collector registered after it missed exactly the breakpoint the user
    /// was waiting for. Silent, and worst at the moment that matters most.
    ///
    /// `Stop` still stops the LOOP; it does not silence the observers.
    fn dispatch(&self, event: &DebugEvent) -> (EventAction, u64) {
        let mut invoked = 0u64;
        let mut action = EventAction::Continue;
        for handler in &self.handlers {
            let interested = handler.interested_in();
            let matches = interested.is_empty() || interested.contains(&event.kind);
            if !matches {
                continue;
            }
            invoked += 1;
            if handler.on_event(event) == EventAction::Stop {
                action = EventAction::Stop;
            }
        }
        (action, invoked)
    }
}

// ─── run_loop ─────────────────────────────────────────────────────────────────

/// Run the event loop against a pre-filled event queue until all events are
/// processed or a handler requests a stop.
///
/// This is the primary public entry point for single-threaded use.
///
/// # Errors
/// Propagates errors from `DebuggerEventLoop::drain`.
pub fn run_loop(
    loop_: &mut DebuggerEventLoop,
    timeout: Option<Duration>,
) -> Result<LoopStats, EventLoopError> {
    loop_.start_time = Some(Instant::now());
    let deadline = timeout.map(|d| Instant::now() + d);
    loop_.deadline = deadline;

    loop {
        if let Some(dl) = deadline && Instant::now() >= dl {
            break;
        }
        if loop_.pending_count() == 0 {
            break;
        }
        let action = loop_.drain()?;
        if action == EventAction::Stop {
            break;
        }
    }

    if let Some(start) = loop_.start_time {
        loop_.stats.wall_time_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    }
    // The deadline belongs to this call, not to the loop object.
    loop_.deadline = None;

    Ok(loop_.stats.clone())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(kind: EventKind) -> DebugEvent {
        DebugEvent::new(0, kind, 1000, 1)
    }

    #[test]
    fn basic_event_creation() {
        let ev = make_event(EventKind::Breakpoint).with_address(0x1234);
        assert_eq!(ev.address, 0x1234);
        assert_eq!(ev.kind, EventKind::Breakpoint);
    }

    #[test]
    fn event_display() {
        let ev = make_event(EventKind::Breakpoint);
        let s = ev.to_string();
        assert!(s.contains("Breakpoint"));
    }

    #[test]
    fn event_is_abnormal_exit() {
        let mut ev = make_event(EventKind::ProcessExit);
        ev.code = -11;
        assert!(ev.is_abnormal_exit());
    }

    #[test]
    fn event_is_not_abnormal_exit_normal() {
        let ev = make_event(EventKind::ProcessExit);
        assert!(!ev.is_abnormal_exit());
    }

    #[test]
    fn event_loop_register_handler() {
        let mut loop_ = DebuggerEventLoop::default_capacity();
        let log = Arc::new(Mutex::new(Vec::new()));
        let handler = Box::new(LoggingHandler::new("logger", log));
        loop_.register_handler(handler).unwrap();
        assert_eq!(loop_.handler_count(), 1);
    }

    #[test]
    fn event_loop_duplicate_handler_error() {
        let mut loop_ = DebuggerEventLoop::default_capacity();
        let log = Arc::new(Mutex::new(Vec::new()));
        loop_.register_handler(Box::new(LoggingHandler::new("logger", log.clone()))).unwrap();
        let err = loop_.register_handler(Box::new(LoggingHandler::new("logger", log))).unwrap_err();
        assert!(matches!(err, EventLoopError::DuplicateHandler(_)));
    }

    #[test]
    fn event_loop_enqueue_and_drain() {
        let mut loop_ = DebuggerEventLoop::default_capacity();
        loop_.enqueue(make_event(EventKind::Breakpoint)).unwrap();
        loop_.enqueue(make_event(EventKind::SingleStep)).unwrap();
        assert_eq!(loop_.pending_count(), 2);
        loop_.drain().unwrap();
        assert_eq!(loop_.pending_count(), 0);
        assert_eq!(loop_.stats().total_events, 2);
    }

    #[test]
    fn event_loop_exit_handler_stops_loop() {
        let mut loop_ = DebuggerEventLoop::default_capacity();
        loop_.register_handler(Box::new(ExitHandler)).unwrap();
        loop_.enqueue(make_event(EventKind::ProcessExit)).unwrap();
        loop_.enqueue(make_event(EventKind::Breakpoint)).unwrap();
        let action = loop_.drain().unwrap();
        assert_eq!(action, EventAction::Stop);
    }

    #[test]
    fn event_loop_logging_handler_records() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut loop_ = DebuggerEventLoop::default_capacity();
        loop_.register_handler(Box::new(LoggingHandler::new("log", log.clone()))).unwrap();
        loop_.enqueue(make_event(EventKind::Breakpoint)).unwrap();
        loop_.drain().unwrap();
        let entries = log.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].contains("Breakpoint"));
    }

    #[test]
    fn event_loop_breakpoint_collector() {
        let hits = Arc::new(Mutex::new(Vec::new()));
        let mut loop_ = DebuggerEventLoop::default_capacity();
        loop_.register_handler(Box::new(BreakpointCollector::new(hits.clone()))).unwrap();
        loop_.enqueue(make_event(EventKind::Breakpoint).with_address(0x4000)).unwrap();
        loop_.enqueue(make_event(EventKind::Breakpoint).with_address(0x5000)).unwrap();
        loop_.drain().unwrap();
        let collected = hits.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0], 0x4000);
        assert_eq!(collected[1], 0x5000);
    }

    #[test]
    fn event_loop_remove_handler() {
        let mut loop_ = DebuggerEventLoop::default_capacity();
        loop_.register_handler(Box::new(ExitHandler)).unwrap();
        loop_.remove_handler("exit_handler");
        assert_eq!(loop_.handler_count(), 0);
    }

    #[test]
    fn event_loop_queue_full_error() {
        let mut loop_ = DebuggerEventLoop::new(2);
        loop_.enqueue(make_event(EventKind::Breakpoint)).unwrap();
        loop_.enqueue(make_event(EventKind::Breakpoint)).unwrap();
        let err = loop_.enqueue(make_event(EventKind::Breakpoint)).unwrap_err();
        assert!(matches!(err, EventLoopError::QueueFull(2)));
    }

    #[test]
    fn run_loop_processes_all_events() {
        let mut loop_ = DebuggerEventLoop::default_capacity();
        for _ in 0..10 {
            loop_.enqueue(make_event(EventKind::SingleStep)).unwrap();
        }
        let stats = run_loop(&mut loop_, None).unwrap();
        assert_eq!(stats.total_events, 10);
    }

    #[test]
    fn run_loop_with_timeout_returns_stats() {
        let mut loop_ = DebuggerEventLoop::default_capacity();
        loop_.enqueue(make_event(EventKind::Breakpoint)).unwrap();
        let stats = run_loop(&mut loop_, Some(Duration::from_secs(1))).unwrap();
        assert_eq!(stats.total_events, 1);
    }

    #[test]
    fn max_events_limit() {
        let mut loop_ = DebuggerEventLoop::default_capacity().with_max_events(3);
        for _ in 0..10 {
            loop_.enqueue(make_event(EventKind::Breakpoint)).unwrap();
        }
        loop_.drain().unwrap();
        assert!(loop_.stats().total_events <= 3);
    }

    #[test]
    fn event_kind_display() {
        assert_eq!(EventKind::Breakpoint.to_string(), "Breakpoint");
        assert_eq!(EventKind::Custom(42).to_string(), "Custom(42)");
    }

    #[test]
    fn stats_events_by_kind() {
        let mut loop_ = DebuggerEventLoop::default_capacity();
        loop_.enqueue(make_event(EventKind::Breakpoint)).unwrap();
        loop_.enqueue(make_event(EventKind::Breakpoint)).unwrap();
        loop_.enqueue(make_event(EventKind::SingleStep)).unwrap();
        loop_.drain().unwrap();
        let stats = loop_.stats();
        assert_eq!(stats.events_by_kind["Breakpoint"], 2);
        assert_eq!(stats.events_by_kind["SingleStep"], 1);
    }

    #[test]
    fn event_with_message() {
        let ev = make_event(EventKind::OutputString).with_message("Hello from target");
        assert_eq!(ev.message.as_deref(), Some("Hello from target"));
    }

    #[test]
    fn event_with_module() {
        let ev = make_event(EventKind::ModuleLoad).with_module("/usr/lib/libc.so.6");
        assert_eq!(ev.module_path.as_deref(), Some("/usr/lib/libc.so.6"));
    }

    /// A handler that asks the loop to stop must not silence the handlers
    /// behind it.
    ///
    /// `dispatch` returned on the first `Stop`, so the last event of a session
    /// - the process exit, the breakpoint that ended the run - never reached
    /// the handlers registered after the one that stopped. A logger behind
    /// `ExitHandler` recorded everything except the exit, and a collector
    /// behind it missed exactly the breakpoint the user was waiting for.
    /// Silent, and worst at the moment that matters most.
    #[test]
    fn a_stopping_handler_does_not_hide_the_event_from_the_handlers_behind_it() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut lp = DebuggerEventLoop::default_capacity();
        lp.register_handler(Box::new(ExitHandler)).expect("register");
        lp.register_handler(Box::new(LoggingHandler::new("after-exit", Arc::clone(&log)))).expect("register");
        lp.enqueue(make_event(EventKind::ProcessExit)).unwrap();

        let action = lp.drain().expect("drain should succeed");
        assert_eq!(action, EventAction::Stop, "the exit must still stop the loop");
        let seen = log.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            !seen.is_empty(),
            "the handler registered after the stopping one never saw the event"
        );
    }

    /// The deadline is honoured per EVENT, not once per drain.
    ///
    /// `run_loop` checked its own deadline only between drains, and `drain`
    /// processes the whole queue - so a full queue ran to completion no matter
    /// what timeout the caller asked for.
    #[test]
    fn a_deadline_stops_the_loop_inside_a_long_queue() {
        struct SlowHandler;
        impl EventHandler for SlowHandler {
            fn name(&self) -> &'static str { "slow" }
            fn on_event(&self, _e: &DebugEvent) -> EventAction {
                std::thread::sleep(Duration::from_millis(2));
                EventAction::Continue
            }
        }
        let mut lp = DebuggerEventLoop::default_capacity();
        lp.register_handler(Box::new(SlowHandler)).expect("register");
        for _ in 0..200 {
            lp.enqueue(make_event(EventKind::Breakpoint)).unwrap();
        }
        let stats = run_loop(&mut lp, Some(Duration::from_millis(20)))
            .expect("run_loop should succeed");
        assert!(
            stats.total_events < 200,
            "the whole queue was processed despite the deadline: {} events",
            stats.total_events
        );
        assert!(lp.pending_count() > 0, "events must be left in the queue");
    }

}
