//! `syscall_dispatcher` — dispatch syscall events to registered handlers.
//!
//! Provides a [`SyscallDispatcher`] that routes each [`SyscallEvent`] to all
//! [`SyscallHandler`]s registered in the [`HandlerRegistry`] for the matching
//! syscall number, OS family, and architecture.
//!
//! # Design
//!
//! Handlers are stored in a [`HandlerRegistry`] keyed by a [`DispatchKey`].
//! The dispatcher calls handlers in registration order.  Each handler returns
//! a [`HandlerOutcome`] which can be `Continue` (pass the event to the next
//! handler) or `Halt` (stop dispatch for this event).
//!
//! Thread-safety: the registry is wrapped in a `parking_lot::RwLock`.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{OsFamily, SyscallArch, SyscallCategory};

// ── SyscallEvent ──────────────────────────────────────────────────────────────

/// A single syscall event passed to the dispatcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// Syscall number.
    pub nr: u64,
    /// Syscall name, if resolved.
    pub name: Option<String>,
    /// OS family that generated the event.
    pub os: OsFamily,
    /// CPU architecture.
    pub arch: SyscallArch,
    /// Syscall category.
    pub category: SyscallCategory,
    /// Entry arguments (up to 6).
    pub args: [u64; 6],
    /// Return value (`None` if the event is an entry-only record).
    pub retval: Option<i64>,
    /// Process identifier.
    pub pid: u32,
    /// Thread identifier.
    pub tid: u32,
    /// Wall-clock timestamp (milliseconds since Unix epoch).
    pub timestamp_ms: u64,
    /// Free-form metadata key-value pairs.
    pub metadata: HashMap<String, String>,
}

impl SyscallEvent {
    /// Create a minimal syscall event.
    #[must_use]
    pub fn new(seq: u64, nr: u64, os: OsFamily, arch: SyscallArch) -> Self {
        Self {
            seq,
            nr,
            name: None,
            os,
            arch,
            category: SyscallCategory::Unknown,
            args: [0; 6],
            retval: None,
            pid: 0,
            tid: 0,
            timestamp_ms: 0,
            metadata: HashMap::new(),
        }
    }

    /// Return `true` if the event carries a return value.
    #[must_use]
    pub const fn has_retval(&self) -> bool {
        self.retval.is_some()
    }

    /// Return `true` if the return value indicates an error (retval < 0).
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.retval.is_some_and(|r| r < 0)
    }

    /// Return a short display label.
    #[must_use]
    pub fn label(&self) -> String {
        self.name.as_ref().map_or_else(|| format!("syscall_{}", self.nr), Clone::clone)
    }
}

impl fmt::Display for SyscallEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}({:?}/{:?}) args={:?} retval={:?} pid={}",
            self.seq, self.label(), self.os, self.arch, &self.args[..3], self.retval, self.pid
        )
    }
}

// ── HandlerOutcome ────────────────────────────────────────────────────────────

/// The outcome returned by a [`SyscallHandler`] after processing an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerOutcome {
    /// Continue dispatching to the next registered handler.
    Continue,
    /// Stop dispatching; no further handlers are called for this event.
    Halt,
}

// ── SyscallHandler trait ──────────────────────────────────────────────────────

/// A handler that processes [`SyscallEvent`]s.
///
/// Implementors receive events and can perform any action: logging, filtering,
/// alerting, state updates, etc.
pub trait SyscallHandler: fmt::Debug + Send + Sync {
    /// Called for each dispatched event.
    ///
    /// Return [`HandlerOutcome::Continue`] to allow subsequent handlers to
    /// run, or [`HandlerOutcome::Halt`] to stop the dispatch chain.
    fn handle(&self, event: &SyscallEvent) -> HandlerOutcome;

    /// Human-readable name for this handler.
    fn name(&self) -> &str;

    /// Return `true` if this handler is currently active.
    fn is_active(&self) -> bool {
        true
    }
}

// ── DispatchKey ───────────────────────────────────────────────────────────────

/// Key used to index handlers in the [`HandlerRegistry`].
///
/// A `None` component is a wildcard that matches any value for that field.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DispatchKey {
    /// Syscall number, or `None` to match all numbers.
    pub syscall_nr: Option<u64>,
    /// OS family, or `None` to match all families.
    pub os: Option<OsFamily>,
    /// Architecture, or `None` to match all architectures.
    pub arch: Option<SyscallArch>,
}

impl DispatchKey {
    /// Create a key that matches only the given syscall number, OS, and arch.
    #[must_use]
    pub const fn exact(nr: u64, os: OsFamily, arch: SyscallArch) -> Self {
        Self { syscall_nr: Some(nr), os: Some(os), arch: Some(arch) }
    }

    /// Create a wildcard key that matches all events.
    #[must_use]
    pub const fn wildcard() -> Self {
        Self { syscall_nr: None, os: None, arch: None }
    }

    /// Create a key matching all syscalls on a specific OS.
    #[must_use]
    pub const fn for_os(os: OsFamily) -> Self {
        Self { syscall_nr: None, os: Some(os), arch: None }
    }

    /// Return `true` if this key matches `event`.
    #[must_use]
    pub fn matches(&self, event: &SyscallEvent) -> bool {
        self.syscall_nr.is_none_or(|n| n == event.nr)
            && self.os.is_none_or(|o| o == event.os)
            && self.arch.is_none_or(|a| a == event.arch)
    }
}

impl fmt::Display for DispatchKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let nr = self.syscall_nr.map_or_else(|| "*".to_string(), |n| n.to_string());
        let os = self.os.map_or_else(|| "*".to_string(), |o| format!("{o:?}"));
        let arch = self.arch.map_or_else(|| "*".to_string(), |a| format!("{a:?}"));
        write!(f, "DispatchKey({nr}, {os}, {arch})")
    }
}

// ── HandlerEntry ──────────────────────────────────────────────────────────────

/// A registered handler with its key and priority.
#[derive(Debug)]
struct HandlerEntry {
    key: DispatchKey,
    handler: Arc<dyn SyscallHandler>,
    /// Lower value = higher priority (called first).
    priority: i32,
}

// ── HandlerRegistry ───────────────────────────────────────────────────────────

/// Thread-safe registry of [`SyscallHandler`]s.
///
/// Handlers are stored as a flat list and matched against each event by
/// iterating all entries.  This approach is simple and fast enough for the
/// typical case of <100 registered handlers.
#[derive(Debug)]
pub struct HandlerRegistry {
    entries: RwLock<Vec<HandlerEntry>>,
}

impl HandlerRegistry {
    /// Create an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self { entries: RwLock::new(Vec::new()) }
    }

    /// Register a handler with default priority (0).
    pub fn register(&self, key: DispatchKey, handler: Arc<dyn SyscallHandler>) {
        self.register_with_priority(key, handler, 0);
    }

    /// Register a handler with the given priority.
    ///
    /// Lower `priority` values are called first.  Handlers with the same
    /// priority are called in registration order.
    pub fn register_with_priority(
        &self,
        key: DispatchKey,
        handler: Arc<dyn SyscallHandler>,
        priority: i32,
    ) {
        let mut entries = self.entries.write();
        let entry = HandlerEntry { key, handler, priority };
        // Insert in priority order (stable sort on insertion).
        let pos = entries.partition_point(|e| e.priority <= priority);
        entries.insert(pos, entry);
    }

    /// Remove all handlers whose name equals `name`.
    pub fn deregister(&self, name: &str) {
        self.entries.write().retain(|e| e.handler.name() != name);
    }

    /// Return the number of registered handlers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Return `true` if no handlers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Return the names of all registered handlers.
    #[must_use]
    pub fn handler_names(&self) -> Vec<String> {
        self.entries
            .read()
            .iter()
            .map(|e| e.handler.name().to_string())
            .collect()
    }

    /// Iterate over all handlers whose key matches `event`, in priority order.
    ///
    /// This method takes a snapshot of the entries under a read lock and
    /// returns the matching handlers as `Arc`s.
    fn matching_handlers(&self, event: &SyscallEvent) -> Vec<Arc<dyn SyscallHandler>> {
        self.entries
            .read()
            .iter()
            .filter(|e| e.key.matches(event) && e.handler.is_active())
            .map(|e| Arc::clone(&e.handler))
            .collect()
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── DispatchError ─────────────────────────────────────────────────────────────

/// Errors produced by [`SyscallDispatcher::dispatch`].
#[derive(Debug, Error)]
pub enum DispatchError {
    /// A handler panicked during event processing.
    #[error("handler panic for event seq={0}")]
    HandlerPanic(u64),

    /// No handlers are registered.
    #[error("no handlers registered for event seq={0}")]
    NoHandlers(u64),
}

// ── DispatchResult ────────────────────────────────────────────────────────────

/// Result of dispatching a single [`SyscallEvent`].
#[derive(Debug, Clone)]
pub struct DispatchResult {
    /// Number of handlers that processed this event.
    pub handlers_called: usize,
    /// Whether dispatch was halted early.
    pub halted: bool,
    /// Wall-clock time spent in handlers.
    pub elapsed: Duration,
}

// ── SyscallDispatcher ─────────────────────────────────────────────────────────

/// Dispatches [`SyscallEvent`]s to registered handlers.
///
/// # Example
///
/// ```no_run
/// use rustre_syscalls::syscall_dispatcher::{
///     SyscallDispatcher, SyscallEvent, HandlerRegistry, DispatchKey,
///     SyscallHandler, HandlerOutcome,
/// };
/// use rustre_syscalls::{OsFamily, SyscallArch};
/// use std::sync::Arc;
///
/// #[derive(Debug)]
/// struct LogHandler;
/// impl SyscallHandler for LogHandler {
///     fn handle(&self, ev: &SyscallEvent) -> HandlerOutcome {
///         println!("{ev}");
///         HandlerOutcome::Continue
///     }
///     fn name(&self) -> &str { "log" }
/// }
///
/// let registry = Arc::new(HandlerRegistry::new());
/// registry.register(DispatchKey::wildcard(), Arc::new(LogHandler));
/// let dispatcher = SyscallDispatcher::new(Arc::clone(&registry));
///
/// let event = SyscallEvent::new(1, 60, OsFamily::Linux, SyscallArch::X86_64);
/// dispatcher.dispatch(&event).unwrap();
/// ```
pub struct SyscallDispatcher {
    registry: Arc<HandlerRegistry>,
    /// Whether to return `Err` when no handlers match.
    pub require_handler: bool,
}

impl SyscallDispatcher {
    /// Create a dispatcher backed by `registry`.
    #[must_use]
    pub const fn new(registry: Arc<HandlerRegistry>) -> Self {
        Self { registry, require_handler: false }
    }

    /// Create a dispatcher with a new empty registry.
    #[must_use]
    pub fn with_new_registry() -> Self {
        Self::new(Arc::new(HandlerRegistry::new()))
    }

    /// Return a reference to the underlying registry.
    #[must_use]
    pub const fn registry(&self) -> &Arc<HandlerRegistry> {
        &self.registry
    }

    /// Dispatch `event` to all matching handlers in priority order.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError::NoHandlers`] when `require_handler` is `true`
    /// and no handlers match the event.
    pub fn dispatch(&self, event: &SyscallEvent) -> Result<DispatchResult, DispatchError> {
        let handlers = self.registry.matching_handlers(event);

        if handlers.is_empty() && self.require_handler {
            return Err(DispatchError::NoHandlers(event.seq));
        }

        let start = Instant::now();
        let mut handlers_called = 0usize;
        let mut halted = false;

        for handler in &handlers {
            let outcome = handler.handle(event);
            handlers_called += 1;
            if outcome == HandlerOutcome::Halt {
                halted = true;
                break;
            }
        }

        Ok(DispatchResult {
            handlers_called,
            halted,
            elapsed: start.elapsed(),
        })
    }

    /// Dispatch a batch of events; return one result per event.
    #[must_use] 
    pub fn dispatch_batch(
        &self,
        events: &[SyscallEvent],
    ) -> Vec<Result<DispatchResult, DispatchError>> {
        events.iter().map(|e| self.dispatch(e)).collect()
    }

    /// Dispatch events from an iterator.
    pub fn dispatch_iter(
        &self,
        events: impl Iterator<Item = SyscallEvent>,
    ) -> Vec<Result<DispatchResult, DispatchError>> {
        events.map(|e| self.dispatch(&e)).collect()
    }
}

// ── Built-in handlers ─────────────────────────────────────────────────────────

/// A handler that collects all events into an internal buffer.
///
/// Useful for testing and for post-processing pipelines.
#[derive(Debug, Default)]
pub struct CollectingHandler {
    events: parking_lot::Mutex<Vec<SyscallEvent>>,
    name: String,
}

impl CollectingHandler {
    /// Create a collector with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { events: parking_lot::Mutex::new(Vec::new()), name: name.into() }
    }

    /// Return the collected events (cloned).
    #[must_use]
    pub fn collected(&self) -> Vec<SyscallEvent> {
        self.events.lock().clone()
    }

    /// Return the number of collected events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.lock().len()
    }

    /// Return `true` if no events have been collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.lock().is_empty()
    }

    /// Clear all collected events.
    pub fn clear(&self) {
        self.events.lock().clear();
    }
}

impl SyscallHandler for CollectingHandler {
    fn handle(&self, event: &SyscallEvent) -> HandlerOutcome {
        self.events.lock().push(event.clone());
        HandlerOutcome::Continue
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// A handler that counts how many events it has received.
#[derive(Debug)]
pub struct CountingHandler {
    count: std::sync::atomic::AtomicU64,
    name: String,
}

impl CountingHandler {
    /// Create a counting handler with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            count: std::sync::atomic::AtomicU64::new(0),
            name: name.into(),
        }
    }

    /// Return the current count.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl SyscallHandler for CountingHandler {
    fn handle(&self, _event: &SyscallEvent) -> HandlerOutcome {
        self.count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        HandlerOutcome::Continue
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// A handler that halts dispatch on the first event matching a predicate.
pub struct HaltingHandler<F>
where
    F: Fn(&SyscallEvent) -> bool + Send + Sync,
{
    predicate: F,
    name: String,
}

impl<F> fmt::Debug for HaltingHandler<F>
where
    F: Fn(&SyscallEvent) -> bool + Send + Sync,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HaltingHandler")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl<F> HaltingHandler<F>
where
    F: Fn(&SyscallEvent) -> bool + Send + Sync,
{
    /// Create a halting handler.
    #[must_use]
    pub fn new(name: impl Into<String>, predicate: F) -> Self {
        Self { predicate, name: name.into() }
    }
}

impl<F> SyscallHandler for HaltingHandler<F>
where
    F: Fn(&SyscallEvent) -> bool + Send + Sync,
{
    fn handle(&self, event: &SyscallEvent) -> HandlerOutcome {
        if (self.predicate)(event) {
            HandlerOutcome::Halt
        } else {
            HandlerOutcome::Continue
        }
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OsFamily, SyscallArch};

    fn linux_event(seq: u64, nr: u64) -> SyscallEvent {
        SyscallEvent::new(seq, nr, OsFamily::Linux, SyscallArch::X86_64)
    }

    // ── SyscallEvent ──────────────────────────────────────────────────────────

    #[test]
    fn test_event_label_with_name() {
        let mut ev = linux_event(1, 60);
        ev.name = Some("exit_group".to_string());
        assert_eq!(ev.label(), "exit_group");
    }

    #[test]
    fn test_event_label_without_name() {
        let ev = linux_event(1, 60);
        assert!(ev.label().contains("60"));
    }

    #[test]
    fn test_event_is_error() {
        let mut ev = linux_event(1, 1);
        ev.retval = Some(-1);
        assert!(ev.is_error());
    }

    #[test]
    fn test_event_not_error_positive() {
        let mut ev = linux_event(1, 1);
        ev.retval = Some(0);
        assert!(!ev.is_error());
    }

    // ── DispatchKey ───────────────────────────────────────────────────────────

    #[test]
    fn test_dispatch_key_exact_match() {
        let key = DispatchKey::exact(60, OsFamily::Linux, SyscallArch::X86_64);
        let ev = linux_event(1, 60);
        assert!(key.matches(&ev));
    }

    #[test]
    fn test_dispatch_key_exact_no_match() {
        let key = DispatchKey::exact(1, OsFamily::Linux, SyscallArch::X86_64);
        let ev = linux_event(1, 60);
        assert!(!key.matches(&ev));
    }

    #[test]
    fn test_dispatch_key_wildcard_matches_all() {
        let key = DispatchKey::wildcard();
        let ev = linux_event(1, 9999);
        assert!(key.matches(&ev));
    }

    #[test]
    fn test_dispatch_key_for_os() {
        let key = DispatchKey::for_os(OsFamily::Linux);
        let ev = linux_event(1, 1);
        assert!(key.matches(&ev));
    }

    // ── HandlerRegistry ───────────────────────────────────────────────────────

    #[test]
    fn test_registry_register_len() {
        let reg = HandlerRegistry::new();
        assert_eq!(reg.len(), 0);
        reg.register(DispatchKey::wildcard(), Arc::new(CountingHandler::new("c1")));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn test_registry_deregister() {
        let reg = HandlerRegistry::new();
        reg.register(DispatchKey::wildcard(), Arc::new(CountingHandler::new("to_remove")));
        assert_eq!(reg.len(), 1);
        reg.deregister("to_remove");
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn test_registry_handler_names() {
        let reg = HandlerRegistry::new();
        reg.register(DispatchKey::wildcard(), Arc::new(CountingHandler::new("alpha")));
        reg.register(DispatchKey::wildcard(), Arc::new(CountingHandler::new("beta")));
        let names = reg.handler_names();
        assert!(names.contains(&"alpha".to_string()));
        assert!(names.contains(&"beta".to_string()));
    }

    // ── SyscallDispatcher ─────────────────────────────────────────────────────

    #[test]
    fn test_dispatch_calls_handler() {
        let counter = Arc::new(CountingHandler::new("c"));
        let reg = Arc::new(HandlerRegistry::new());
        reg.register(DispatchKey::wildcard(), counter.clone());
        let dispatcher = SyscallDispatcher::new(reg);
        let ev = linux_event(1, 1);
        dispatcher.dispatch(&ev).unwrap();
        assert_eq!(counter.count(), 1);
    }

    #[test]
    fn test_dispatch_multiple_handlers() {
        let c1 = Arc::new(CountingHandler::new("c1"));
        let c2 = Arc::new(CountingHandler::new("c2"));
        let reg = Arc::new(HandlerRegistry::new());
        reg.register(DispatchKey::wildcard(), c1.clone());
        reg.register(DispatchKey::wildcard(), c2.clone());
        let dispatcher = SyscallDispatcher::new(reg);
        dispatcher.dispatch(&linux_event(1, 1)).unwrap();
        assert_eq!(c1.count(), 1);
        assert_eq!(c2.count(), 1);
    }

    #[test]
    fn test_dispatch_halt_stops_chain() {
        let halter = Arc::new(HaltingHandler::new("halt", |_| true));
        let counter = Arc::new(CountingHandler::new("should_not_run"));
        let reg = Arc::new(HandlerRegistry::new());
        // halter has lower priority (called first)
        reg.register_with_priority(DispatchKey::wildcard(), halter, -10);
        reg.register_with_priority(DispatchKey::wildcard(), counter.clone(), 10);
        let dispatcher = SyscallDispatcher::new(reg);
        let res = dispatcher.dispatch(&linux_event(1, 1)).unwrap();
        assert!(res.halted);
        assert_eq!(counter.count(), 0);
    }

    #[test]
    fn test_dispatch_no_matching_handler_ok() {
        let reg = Arc::new(HandlerRegistry::new());
        // Register for Windows only, but send a Linux event.
        reg.register(
            DispatchKey::for_os(OsFamily::Windows),
            Arc::new(CountingHandler::new("win")),
        );
        let dispatcher = SyscallDispatcher::new(reg);
        let ev = linux_event(1, 1);
        let result = dispatcher.dispatch(&ev).unwrap();
        assert_eq!(result.handlers_called, 0);
    }

    #[test]
    fn test_dispatch_require_handler_error() {
        let reg = Arc::new(HandlerRegistry::new());
        let mut dispatcher = SyscallDispatcher::new(reg);
        dispatcher.require_handler = true;
        assert!(matches!(
            dispatcher.dispatch(&linux_event(1, 1)),
            Err(DispatchError::NoHandlers(_))
        ));
    }

    #[test]
    fn test_collect_handler_stores_events() {
        let collector = Arc::new(CollectingHandler::new("col"));
        let reg = Arc::new(HandlerRegistry::new());
        reg.register(DispatchKey::wildcard(), collector.clone());
        let dispatcher = SyscallDispatcher::new(reg);
        dispatcher.dispatch(&linux_event(1, 60)).unwrap();
        dispatcher.dispatch(&linux_event(2, 1)).unwrap();
        assert_eq!(collector.len(), 2);
    }

    #[test]
    fn test_dispatch_batch() {
        let counter = Arc::new(CountingHandler::new("batch"));
        let reg = Arc::new(HandlerRegistry::new());
        reg.register(DispatchKey::wildcard(), counter.clone());
        let dispatcher = SyscallDispatcher::new(reg);
        let events: Vec<SyscallEvent> = (1u64..=5).map(|i| linux_event(i, i)).collect();
        let results = dispatcher.dispatch_batch(&events);
        assert_eq!(results.len(), 5);
        assert_eq!(counter.count(), 5);
    }

    #[test]
    fn test_dispatch_result_elapsed() {
        let reg = Arc::new(HandlerRegistry::new());
        reg.register(DispatchKey::wildcard(), Arc::new(CountingHandler::new("t")));
        let dispatcher = SyscallDispatcher::new(reg);
        let res = dispatcher.dispatch(&linux_event(1, 1)).unwrap();
        // Duration should be non-negative (always true, but verifies the field exists).
        assert!(res.elapsed.as_nanos() < u128::MAX);
    }
}
