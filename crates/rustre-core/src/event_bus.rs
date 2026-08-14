//! Event bus for platform-wide change notifications.
//!
//! Provides [`EventBus`], [`Event`] trait, [`EventKind`], [`Subscription`],
//! [`subscribe()`], and [`publish()`] so that any component in the platform
//! can broadcast or observe typed events without hard-wiring dependencies.

use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

// ─────────────────────────────────────────────────────────────────────────────
// EventKind
// ─────────────────────────────────────────────────────────────────────────────

/// Enumeration of every event category the platform can emit.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EventKind {
    /// A new binary view was opened.
    ViewOpened,
    /// A binary view was closed.
    ViewClosed,
    /// The analysis pipeline started on a view.
    AnalysisStarted,
    /// The analysis pipeline finished on a view.
    AnalysisFinished,
    /// A function was added to the function table.
    FunctionAdded,
    /// A function was removed from the function table.
    FunctionRemoved,
    /// A function's metadata was updated.
    FunctionUpdated,
    /// A symbol was added to the symbol index.
    SymbolAdded,
    /// A symbol was removed.
    SymbolRemoved,
    /// A type definition was added or updated.
    TypeChanged,
    /// A memory patch was applied.
    PatchApplied,
    /// A memory patch was reverted.
    PatchReverted,
    /// A comment was added or modified.
    CommentChanged,
    /// A bookmark was created or moved.
    BookmarkChanged,
    /// A cross-reference was recorded.
    XrefAdded,
    /// A cross-reference was removed.
    XrefRemoved,
    /// The active UI selection changed.
    SelectionChanged,
    /// A plugin was loaded.
    PluginLoaded,
    /// A plugin was unloaded.
    PluginUnloaded,
    /// An error or warning was generated.
    Diagnostic,
    /// Any application-defined event not covered by the variants above.
    Custom(String),
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "custom:{s}"),
            other => write!(f, "{other:?}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Event trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait that every event payload must implement.
///
/// The trait is object-safe so that heterogeneous events can be stored as
/// `Box<dyn Event>` and dispatched through a single bus.
pub trait Event: Any + Send + Sync + fmt::Debug {
    /// Returns the category of this event.
    fn kind(&self) -> EventKind;

    /// Optional human-readable summary for logging / diagnostics.
    fn summary(&self) -> String {
        format!("{:?}", self.kind())
    }

    /// Cast back to `Any` for downcasting in subscribers.
    fn as_any(&self) -> &dyn Any;
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in concrete event types
// ─────────────────────────────────────────────────────────────────────────────

/// A generic event carrying a textual message and an [`EventKind`].
#[derive(Debug, Clone)]
pub struct SimpleEvent {
    pub kind: EventKind,
    pub message: String,
}

impl SimpleEvent {
    pub fn new(kind: EventKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }
}

impl Event for SimpleEvent {
    fn kind(&self) -> EventKind {
        self.kind.clone()
    }

    fn summary(&self) -> String {
        format!("[{}] {}", self.kind, self.message)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Event fired when a function is added, removed, or updated.
#[derive(Debug, Clone)]
pub struct FunctionEvent {
    pub kind: EventKind,
    pub address: u64,
    pub name: Option<String>,
}

impl FunctionEvent {
    pub fn added(address: u64, name: impl Into<String>) -> Self {
        Self {
            kind: EventKind::FunctionAdded,
            address,
            name: Some(name.into()),
        }
    }

    #[must_use] 
    pub const fn removed(address: u64) -> Self {
        Self { kind: EventKind::FunctionRemoved, address, name: None }
    }
}

impl Event for FunctionEvent {
    fn kind(&self) -> EventKind {
        self.kind.clone()
    }

    fn summary(&self) -> String {
        self.name.as_ref().map_or_else(|| format!("{} @ {:#x}", self.kind, self.address), |n| format!("{} {} @ {:#x}", self.kind, n, self.address))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Event fired when a patch is applied or reverted.
#[derive(Debug, Clone)]
pub struct PatchEvent {
    pub kind: EventKind,
    pub address: u64,
    pub byte_count: usize,
}

impl PatchEvent {
    #[must_use] 
    pub const fn applied(address: u64, byte_count: usize) -> Self {
        Self { kind: EventKind::PatchApplied, address, byte_count }
    }

    #[must_use] 
    pub const fn reverted(address: u64, byte_count: usize) -> Self {
        Self { kind: EventKind::PatchReverted, address, byte_count }
    }
}

impl Event for PatchEvent {
    fn kind(&self) -> EventKind {
        self.kind.clone()
    }

    fn summary(&self) -> String {
        format!("{} {} bytes @ {:#x}", self.kind, self.byte_count, self.address)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Event fired when a diagnostic message is produced.
#[derive(Debug, Clone)]
pub struct DiagnosticEvent {
    pub level: DiagnosticLevel,
    pub message: String,
    pub source: Option<String>,
}

/// Severity of a diagnostic event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticLevel {
    Info,
    Warning,
    Error,
}

impl DiagnosticEvent {
    pub fn info(message: impl Into<String>) -> Self {
        Self { level: DiagnosticLevel::Info, message: message.into(), source: None }
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self { level: DiagnosticLevel::Warning, message: message.into(), source: None }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self { level: DiagnosticLevel::Error, message: message.into(), source: None }
    }

    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }
}

impl Event for DiagnosticEvent {
    fn kind(&self) -> EventKind {
        EventKind::Diagnostic
    }

    fn summary(&self) -> String {
        let prefix = match self.level {
            DiagnosticLevel::Info => "INFO",
            DiagnosticLevel::Warning => "WARN",
            DiagnosticLevel::Error => "ERROR",
        };
        self.source.as_ref().map_or_else(|| format!("[{prefix}] {}", self.message), |src| format!("[{prefix}][{src}] {}", self.message))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SubscriptionId
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque handle returned by [`EventBus::subscribe`].
///
/// Dropping a `Subscription` automatically unsubscribes via `Drop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriptionId(u64);

impl SubscriptionId {
    const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[must_use] 
    pub const fn raw(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sub#{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Subscription
// ─────────────────────────────────────────────────────────────────────────────

/// RAII guard that unsubscribes from the bus when dropped.
pub struct Subscription {
    id: SubscriptionId,
    bus: Arc<EventBusInner>,
}

impl Subscription {
    /// The unique ID assigned to this subscription.
    #[must_use] 
    pub const fn id(&self) -> SubscriptionId {
        self.id
    }

    /// Keep this subscription alive without consuming it (useful in tests).
    pub const fn keep_alive(&self) {}
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Subscription({})", self.id)
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.bus.unsubscribe(self.id);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Handler type alias
// ─────────────────────────────────────────────────────────────────────────────

/// Type of a subscriber callback.
///
/// Using `Arc` rather than `Box` so the handler can be cloned out of the
/// subscriber table before the lock is released, preventing the dangling-pointer
/// UB that would occur if a concurrent `unsubscribe` freed the `Box` while
/// publish was still holding a raw pointer into it.
type HandlerFn = std::sync::Arc<dyn Fn(&dyn Event) + Send + Sync>;

// ─────────────────────────────────────────────────────────────────────────────
// KindFilter
// ─────────────────────────────────────────────────────────────────────────────

/// Determines which events a subscription receives.
#[derive(Debug, Clone)]
pub enum KindFilter {
    /// Receive every event regardless of kind.
    All,
    /// Receive only events whose kind matches one of these.
    Only(Vec<EventKind>),
    /// Receive every event except those in this set.
    Except(Vec<EventKind>),
}

impl KindFilter {
    #[must_use] 
    pub fn matches(&self, kind: &EventKind) -> bool {
        match self {
            Self::All => true,
            Self::Only(list) => list.contains(kind),
            Self::Except(list) => !list.contains(kind),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal state
// ─────────────────────────────────────────────────────────────────────────────

struct SubscriberEntry {
    filter: KindFilter,
    handler: HandlerFn,
}

struct EventBusInner {
    next_id: Mutex<u64>,
    subscribers: Mutex<HashMap<SubscriptionId, SubscriberEntry>>,
    published_count: Mutex<u64>,
    dropped_count: Mutex<u64>,
}

impl std::fmt::Debug for EventBusInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBusInner")
            .field("next_id", &self.next_id)
            .field("published_count", &self.published_count)
            .field("dropped_count", &self.dropped_count)
            .finish_non_exhaustive()
    }
}

impl EventBusInner {
    fn new() -> Self {
        Self {
            next_id: Mutex::new(1),
            subscribers: Mutex::new(HashMap::new()),
            published_count: Mutex::new(0),
            dropped_count: Mutex::new(0),
        }
    }

    fn next_id(&self) -> SubscriptionId {
        let mut guard = self.next_id.lock().unwrap();
        let id = *guard;
        *guard += 1;
        drop(guard);
        SubscriptionId::new(id)
    }

    fn subscribe(&self, filter: KindFilter, handler: HandlerFn) -> SubscriptionId {
        let id = self.next_id();
        self.subscribers.lock().unwrap().insert(id, SubscriberEntry { filter, handler });
        id
    }

    fn unsubscribe(&self, id: SubscriptionId) {
        self.subscribers.lock().unwrap().remove(&id);
        *self.dropped_count.lock().unwrap() += 1;
    }

    fn publish(&self, event: &dyn Event) {
        *self.published_count.lock().unwrap() += 1;
        let kind = event.kind();
        // Clone the Arc handles before releasing the lock so that a concurrent
        // `unsubscribe` cannot free a handler while we are still calling it
        // (fixes dangling-reference UB: lifetime-escape via raw *const ptr).
        let handlers: Vec<HandlerFn> = {
            let guard = self.subscribers.lock().unwrap();
            guard
                .values()
                .filter(|e| e.filter.matches(&kind))
                .map(|e| std::sync::Arc::clone(&e.handler))
                .collect()
        };
        for handler in &handlers {
            handler(event);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EventBus
// ─────────────────────────────────────────────────────────────────────────────

/// Thread-safe, reference-counted event bus.
///
/// All clones of the same `EventBus` share the same underlying subscription
/// table, so publishing from one clone reaches subscribers registered on any
/// other.
///
/// # Example
/// ```
/// use rustre_core::event_bus::{EventBus, EventKind, KindFilter, SimpleEvent};
///
/// let bus = EventBus::new();
/// let _sub = bus.subscribe(KindFilter::All, |ev| {
///     println!("got: {}", ev.summary());
/// });
/// bus.publish(&SimpleEvent::new(EventKind::ViewOpened, "my_binary.elf"));
/// ```
#[derive(Debug, Clone)]
pub struct EventBus {
    inner: Arc<EventBusInner>,
}

impl EventBus {
    /// Create a new, empty event bus.
    #[must_use] 
    pub fn new() -> Self {
        Self { inner: Arc::new(EventBusInner::new()) }
    }

    /// Subscribe to events matching `filter`.
    ///
    /// Returns a [`Subscription`] whose `Drop` implementation automatically
    /// cancels the subscription.
    pub fn subscribe(
        &self,
        filter: KindFilter,
        handler: impl Fn(&dyn Event) + Send + Sync + 'static,
    ) -> Subscription {
        let id = self.inner.subscribe(filter, std::sync::Arc::new(handler));
        Subscription { id, bus: Arc::clone(&self.inner) }
    }

    /// Subscribe to all events, receiving every kind.
    pub fn subscribe_all(
        &self,
        handler: impl Fn(&dyn Event) + Send + Sync + 'static,
    ) -> Subscription {
        self.subscribe(KindFilter::All, handler)
    }

    /// Subscribe to a single specific event kind.
    pub fn subscribe_one(
        &self,
        kind: EventKind,
        handler: impl Fn(&dyn Event) + Send + Sync + 'static,
    ) -> Subscription {
        self.subscribe(KindFilter::Only(vec![kind]), handler)
    }

    /// Publish an event to all matching subscribers.
    pub fn publish(&self, event: &dyn Event) {
        self.inner.publish(event);
    }

    /// Convenience: publish a [`SimpleEvent`] with the given kind and message.
    pub fn emit(&self, kind: EventKind, message: impl Into<String>) {
        let ev = SimpleEvent::new(kind, message);
        self.publish(&ev);
    }

    /// Number of events published so far (including ones with no subscribers).
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn published_count(&self) -> u64 {
        *self.inner.published_count.lock().unwrap()
    }

    /// Number of subscriptions currently active.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.inner.subscribers.lock().unwrap().len()
    }

    /// Number of subscriptions that have been dropped since the bus was created.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        *self.inner.dropped_count.lock().unwrap()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Free-function helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Subscribe to `bus` using a handler closure; returns a [`Subscription`].
///
/// This is a convenience wrapper around [`EventBus::subscribe`].
pub fn subscribe(
    bus: &EventBus,
    filter: KindFilter,
    handler: impl Fn(&dyn Event) + Send + Sync + 'static,
) -> Subscription {
    bus.subscribe(filter, handler)
}

/// Publish `event` to all subscribers of `bus`.
pub fn publish(bus: &EventBus, event: &dyn Event) {
    bus.publish(event);
}

// ─────────────────────────────────────────────────────────────────────────────
// EventRecorder — collects events for testing / replay
// ─────────────────────────────────────────────────────────────────────────────

/// Collects published events into an in-memory list for inspection.
///
/// Intended for unit tests and audit logging.
#[derive(Debug, Clone)]
pub struct EventRecorder {
    records: Arc<Mutex<Vec<EventRecord>>>,
}

/// A single recorded event snapshot.
#[derive(Debug, Clone)]
pub struct EventRecord {
    pub kind: EventKind,
    pub summary: String,
    pub sequence: u64,
}

impl EventRecorder {
    /// Create a new, empty recorder.
    #[must_use] 
    pub fn new() -> Self {
        Self { records: Arc::new(Mutex::new(Vec::new())) }
    }

    /// Attach the recorder to `bus` and return the [`Subscription`] guard.
    ///
    /// The recorder is a shared handle — the subscription holds a clone so
    /// recorded events are accessible after the subscription is dropped.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn attach(&self, bus: &EventBus) -> Subscription {
        let records = Arc::clone(&self.records);
        bus.subscribe_all(move |ev| {
            let mut guard = records.lock().unwrap();
            let seq = guard.len() as u64;
            guard.push(EventRecord {
                kind: ev.kind(),
                summary: ev.summary(),
                sequence: seq,
            });
        })
    }

    /// All events recorded so far.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn records(&self) -> Vec<EventRecord> {
        self.records.lock().unwrap().clone()
    }

    /// Number of events recorded.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.lock().unwrap().len()
    }

    /// Returns `true` if no events have been recorded.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.lock().unwrap().is_empty()
    }

    /// Clear all recorded events.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn clear(&self) {
        self.records.lock().unwrap().clear();
    }

    /// Returns recorded events whose kind matches `kind`.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn by_kind(&self, kind: &EventKind) -> Vec<EventRecord> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .filter(|r| &r.kind == kind)
            .cloned()
            .collect()
    }
}

impl Default for EventRecorder {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn subscribe_and_receive_all() {
        let bus = EventBus::new();
        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);
        let _sub = bus.subscribe_all(move |_ev| {
            c.fetch_add(1, Ordering::Relaxed);
        });
        bus.emit(EventKind::ViewOpened, "test.bin");
        bus.emit(EventKind::AnalysisStarted, "");
        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn filter_only_receives_matching() {
        let bus = EventBus::new();
        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);
        let _sub = bus.subscribe(
            KindFilter::Only(vec![EventKind::FunctionAdded]),
            move |_ev| {
                c.fetch_add(1, Ordering::Relaxed);
            },
        );
        bus.emit(EventKind::FunctionAdded, "fn_a");
        bus.emit(EventKind::ViewOpened, "v");
        bus.emit(EventKind::FunctionAdded, "fn_b");
        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn filter_except_skips_excluded() {
        let bus = EventBus::new();
        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);
        let _sub = bus.subscribe(
            KindFilter::Except(vec![EventKind::Diagnostic]),
            move |_ev| {
                c.fetch_add(1, Ordering::Relaxed);
            },
        );
        bus.emit(EventKind::Diagnostic, "warn");
        bus.emit(EventKind::ViewOpened, "v");
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn subscription_drop_unsubscribes() {
        let bus = EventBus::new();
        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);
        {
            let _sub = bus.subscribe_all(move |_ev| {
                c.fetch_add(1, Ordering::Relaxed);
            });
            bus.emit(EventKind::ViewOpened, "");
            assert_eq!(counter.load(Ordering::Relaxed), 1);
        }
        // _sub dropped here — no more events
        bus.emit(EventKind::ViewClosed, "");
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn published_count_increments() {
        let bus = EventBus::new();
        assert_eq!(bus.published_count(), 0);
        bus.emit(EventKind::ViewOpened, "a");
        bus.emit(EventKind::ViewClosed, "b");
        assert_eq!(bus.published_count(), 2);
    }

    #[test]
    fn subscriber_count_tracks_subs() {
        let bus = EventBus::new();
        assert_eq!(bus.subscriber_count(), 0);
        let _s1 = bus.subscribe_all(|_| {});
        let _s2 = bus.subscribe_all(|_| {});
        assert_eq!(bus.subscriber_count(), 2);
    }

    #[test]
    fn recorder_captures_events() {
        let bus = EventBus::new();
        let rec = EventRecorder::new();
        let _sub = rec.attach(&bus);
        bus.publish(&FunctionEvent::added(0x1000, "main"));
        bus.publish(&PatchEvent::applied(0x1010, 4));
        assert_eq!(rec.len(), 2);
        let fn_evs = rec.by_kind(&EventKind::FunctionAdded);
        assert_eq!(fn_evs.len(), 1);
    }

    #[test]
    fn recorder_clear_resets() {
        let bus = EventBus::new();
        let rec = EventRecorder::new();
        let _sub = rec.attach(&bus);
        bus.emit(EventKind::ViewOpened, "");
        rec.clear();
        assert!(rec.is_empty());
    }

    #[test]
    fn diagnostic_event_levels() {
        let info = DiagnosticEvent::info("all good").with_source("loader");
        assert_eq!(info.level, DiagnosticLevel::Info);
        assert!(info.summary().contains("loader"));

        let warn = DiagnosticEvent::warning("suspicious bytes");
        assert_eq!(warn.level, DiagnosticLevel::Warning);
        assert_eq!(warn.kind(), EventKind::Diagnostic);
    }

    #[test]
    fn function_event_variants() {
        let added = FunctionEvent::added(0x400, "sub_400");
        assert_eq!(added.kind(), EventKind::FunctionAdded);
        assert_eq!(added.address, 0x400);

        let removed = FunctionEvent::removed(0x400);
        assert_eq!(removed.kind(), EventKind::FunctionRemoved);
        assert!(removed.name.is_none());
    }

    #[test]
    fn patch_event_variants() {
        let p = PatchEvent::applied(0x8000, 8);
        assert_eq!(p.kind(), EventKind::PatchApplied);
        assert_eq!(p.byte_count, 8);

        let r = PatchEvent::reverted(0x8000, 8);
        assert_eq!(r.kind(), EventKind::PatchReverted);
    }

    #[test]
    fn kind_filter_all_passes_everything() {
        let f = KindFilter::All;
        assert!(f.matches(&EventKind::ViewOpened));
        assert!(f.matches(&EventKind::Custom("x".into())));
    }

    #[test]
    fn kind_filter_only_rejects_others() {
        let f = KindFilter::Only(vec![EventKind::SymbolAdded]);
        assert!(f.matches(&EventKind::SymbolAdded));
        assert!(!f.matches(&EventKind::SymbolRemoved));
    }

    #[test]
    fn multiple_buses_are_independent() {
        let b1 = EventBus::new();
        let b2 = EventBus::new();
        let c1 = Arc::new(AtomicU32::new(0));
        let c2 = Arc::new(AtomicU32::new(0));
        let cc1 = Arc::clone(&c1);
        let cc2 = Arc::clone(&c2);
        let _s1 = b1.subscribe_all(move |_| { cc1.fetch_add(1, Ordering::Relaxed); });
        let _s2 = b2.subscribe_all(move |_| { cc2.fetch_add(1, Ordering::Relaxed); });
        b1.emit(EventKind::ViewOpened, "");
        assert_eq!(c1.load(Ordering::Relaxed), 1);
        assert_eq!(c2.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn free_function_subscribe_and_publish() {
        let bus = EventBus::new();
        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);
        let _sub = subscribe(&bus, KindFilter::All, move |_| {
            c.fetch_add(1, Ordering::Relaxed);
        });
        publish(&bus, &SimpleEvent::new(EventKind::XrefAdded, ""));
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }
}
