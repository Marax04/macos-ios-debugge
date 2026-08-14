//! `event_bus` — publish-subscribe event bus with topic routing,
//! subscriber lifecycle, back-pressure signaling, and event batching.
//!
//! This module provides a full pub/sub infrastructure on top of `std` channels
//! (no `tokio` dependency).  Subscribers register with optional filter
//! predicates; the bus routes events and enforces bounded queue capacity.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

// ── EventPayload ──────────────────────────────────────────────────────────────

/// The payload carried by a bus event.
#[derive(Debug, Clone)]
pub struct EventPayload {
    /// Event topic (e.g. `"analysis.function_found"`).
    pub topic: String,
    /// Arbitrary byte payload.
    pub body: Vec<u8>,
    /// Optional string body for text-oriented events.
    pub text: Option<String>,
    /// Monotonically increasing sequence number assigned by the bus.
    pub seq: u64,
}

impl EventPayload {
    /// Create a payload with a byte body.
    #[must_use]
    pub fn new(topic: impl Into<String>, body: Vec<u8>) -> Self {
        Self {
            topic: topic.into(),
            body,
            text: None,
            seq: 0,
        }
    }

    /// Create a payload with a text body.
    #[must_use]
    pub fn text(topic: impl Into<String>, text: impl Into<String>) -> Self {
        let text = text.into();
        Self {
            topic: topic.into(),
            body: text.as_bytes().to_vec(),
            text: Some(text),
            seq: 0,
        }
    }
}

impl fmt::Display for EventPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref t) = self.text {
            write!(f, "[seq={}] {} «{}»", self.seq, self.topic, t)
        } else {
            write!(f, "[seq={}] {} bytes={}", self.seq, self.topic, self.body.len())
        }
    }
}

// ── TopicPattern ─────────────────────────────────────────────────────────────

/// A topic pattern for subscriber routing.
///
/// Supports simple glob-like matching:
/// - `"*"` matches everything.
/// - `"analysis.*"` matches any topic starting with `"analysis."`.
/// - `"analysis.function_found"` matches exactly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TopicPattern(pub String);

impl TopicPattern {
    /// Create a pattern.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self(pattern.into())
    }

    /// Wildcard matching: `*` or exact prefix with `.*`.
    #[must_use]
    pub fn matches(&self, topic: &str) -> bool {
        let p = self.0.as_str();
        if p == "*" {
            return true;
        }
        if let Some(prefix) = p.strip_suffix(".*") {
            return topic.starts_with(prefix) && topic.len() > prefix.len();
        }
        p == topic
    }
}

impl fmt::Display for TopicPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── EventFilter ───────────────────────────────────────────────────────────────

/// A filter predicate for subscriber event selection.
pub struct EventFilter {
    inner: Box<dyn Fn(&EventPayload) -> bool + Send + Sync + 'static>,
    description: String,
}

impl EventFilter {
    /// Create a filter from a closure.
    pub fn new(
        desc: impl Into<String>,
        f: impl Fn(&EventPayload) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Box::new(f),
            description: desc.into(),
        }
    }

    /// Accept all events (no filter).
    #[must_use]
    pub fn accept_all() -> Self {
        Self::new("accept_all", |_| true)
    }

    /// Accept only events matching a topic pattern.
    #[must_use]
    pub fn by_topic(pattern: TopicPattern) -> Self {
        let desc = format!("topic={pattern}");
        Self::new(desc, move |e| pattern.matches(&e.topic))
    }

    /// Accept events whose payload text contains `needle`.
    #[must_use]
    pub fn text_contains(needle: impl Into<String>) -> Self {
        let needle = needle.into();
        let desc = format!("text_contains={needle}");
        Self::new(desc, move |e| {
            e.text.as_ref().is_some_and(|t| t.contains(needle.as_str()))
        })
    }

    /// Test a payload against this filter.
    #[must_use]
    pub fn matches(&self, payload: &EventPayload) -> bool {
        (self.inner)(payload)
    }
}

impl fmt::Debug for EventFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventFilter({})", self.description)
    }
}

// ── SubscriberId ─────────────────────────────────────────────────────────────

/// Unique identifier for a subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubscriberId(pub u64);

impl fmt::Display for SubscriberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sub#{}", self.0)
    }
}

// ── SubscriberState ───────────────────────────────────────────────────────────

/// Lifecycle state of a [`Subscriber`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriberState {
    /// Receiving events normally.
    Active,
    /// Temporarily paused; events are not delivered but the subscriber is still registered.
    Paused,
    /// Permanently removed from the bus.
    Unregistered,
}

// ── BackPressure ──────────────────────────────────────────────────────────────

/// Back-pressure signaling result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendResult {
    /// Event was delivered to all active subscribers.
    Delivered,
    /// At least one subscriber queue was full; event was dropped for that subscriber.
    BackPressure,
    /// No subscribers are active.
    NoSubscribers,
}

// ── Subscriber ────────────────────────────────────────────────────────────────

/// A registered subscriber.
pub struct Subscriber {
    pub id: SubscriberId,
    pub label: String,
    filter: EventFilter,
    queue: Mutex<std::collections::VecDeque<EventPayload>>,
    capacity: usize,
    state: AtomicBool, // true = paused
    unregistered: AtomicBool,
    delivered: AtomicU64,
    dropped: AtomicU64,
}

impl Subscriber {
    fn new(id: SubscriberId, label: impl Into<String>, filter: EventFilter, capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            id,
            label: label.into(),
            filter,
            queue: Mutex::new(std::collections::VecDeque::with_capacity(capacity.min(1024))),
            capacity,
            state: AtomicBool::new(false),
            unregistered: AtomicBool::new(false),
            delivered: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        })
    }

    fn is_paused(&self) -> bool {
        self.state.load(Ordering::Relaxed)
    }

    fn is_unregistered(&self) -> bool {
        self.unregistered.load(Ordering::Relaxed)
    }

    /// Return the current lifecycle state of this subscriber.
    #[must_use]
    pub fn state(&self) -> SubscriberState {
        if self.is_unregistered() {
            SubscriberState::Unregistered
        } else if self.is_paused() {
            SubscriberState::Paused
        } else {
            SubscriberState::Active
        }
    }

    fn try_deliver(&self, payload: &EventPayload) -> bool {
        if self.is_paused() || self.is_unregistered() {
            return false;
        }
        if !self.filter.matches(payload) {
            return false;
        }
        let mut q = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if q.len() >= self.capacity {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        q.push_back(payload.clone());
        drop(q);
        self.delivered.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Drain all pending events from this subscriber's queue.
    #[must_use]
    pub fn drain(&self) -> Vec<EventPayload> {
        let mut q = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        q.drain(..).collect()
    }

    /// Pop a single event (oldest first), or `None` if queue is empty.
    #[must_use]
    pub fn recv(&self) -> Option<EventPayload> {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
    }

    /// Number of events waiting in the queue.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Total events delivered to this subscriber.
    #[must_use]
    pub fn delivered_count(&self) -> u64 {
        self.delivered.load(Ordering::Relaxed)
    }

    /// Total events dropped due to back-pressure.
    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl fmt::Debug for Subscriber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subscriber")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("pending", &self.pending())
            .field("paused", &self.is_paused())
            .finish_non_exhaustive()
    }
}

// ── EventBatch ────────────────────────────────────────────────────────────────

/// A batch of events that can be published atomically.
#[derive(Debug, Default)]
pub struct EventBatch {
    events: Vec<EventPayload>,
}

impl EventBatch {
    /// Create an empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an event to the batch.
    pub fn push(&mut self, payload: EventPayload) {
        self.events.push(payload);
    }

    /// Number of events in the batch.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns `true` if the batch is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

// ── EventBus ─────────────────────────────────────────────────────────────────

/// Publish-subscribe event bus with topic routing and back-pressure.
///
/// Multiple threads may publish events and register/query subscribers
/// concurrently.  The bus is safe to share via `Arc<EventBus>`.
pub struct EventBus {
    subscribers: Mutex<HashMap<SubscriberId, Arc<Subscriber>>>,
    next_id: AtomicU64,
    next_seq: AtomicU64,
    published: AtomicU64,
    dropped: AtomicU64,
    /// Default queue capacity for new subscribers.
    default_capacity: usize,
}

impl EventBus {
    /// Create a new bus with the given default subscriber queue capacity.
    #[must_use]
    pub fn new(default_capacity: usize) -> Self {
        Self {
            subscribers: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            next_seq: AtomicU64::new(1),
            published: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            default_capacity,
        }
    }

    /// Create a bus with a default capacity of 1 024.
    #[must_use]
    pub fn new_default() -> Self {
        Self::new(1024)
    }

    // ── Subscriber registration ──────────────────────────────────────────────

    /// Register a new subscriber with a topic pattern filter.
    ///
    /// Returns the subscriber's ID and a handle to the [`Subscriber`].
    pub fn subscribe_topic(
        &self,
        label: impl Into<String>,
        pattern: TopicPattern,
    ) -> (SubscriberId, Arc<Subscriber>) {
        self.subscribe_filtered(label, EventFilter::by_topic(pattern))
    }

    /// Register a subscriber that accepts all events.
    pub fn subscribe_all(&self, label: impl Into<String>) -> (SubscriberId, Arc<Subscriber>) {
        self.subscribe_filtered(label, EventFilter::accept_all())
    }

    /// Register a subscriber with a custom filter and capacity.
    pub fn subscribe_with_capacity(
        &self,
        label: impl Into<String>,
        filter: EventFilter,
        capacity: usize,
    ) -> (SubscriberId, Arc<Subscriber>) {
        let id = SubscriberId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let sub = Subscriber::new(id, label, filter, capacity);
        self.subscribers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, Arc::clone(&sub));
        (id, sub)
    }

    /// Register a subscriber with a custom filter.
    pub fn subscribe_filtered(
        &self,
        label: impl Into<String>,
        filter: EventFilter,
    ) -> (SubscriberId, Arc<Subscriber>) {
        self.subscribe_with_capacity(label, filter, self.default_capacity)
    }

    // ── Lifecycle ────────────────────────────────────────────────────────────

    /// Pause delivery for subscriber `id`.  Returns `false` if not found.
    pub fn pause(&self, id: SubscriberId) -> bool {
        let guard = self.subscribers.lock().unwrap_or_else(PoisonError::into_inner);
        guard.get(&id).is_some_and(|sub| {
            sub.state.store(true, Ordering::Relaxed);
            true
        })
    }

    /// Resume delivery for subscriber `id`.
    pub fn resume(&self, id: SubscriberId) -> bool {
        let guard = self.subscribers.lock().unwrap_or_else(PoisonError::into_inner);
        guard.get(&id).is_some_and(|sub| {
            sub.state.store(false, Ordering::Relaxed);
            true
        })
    }

    /// Unregister subscriber `id` and remove it from routing.
    pub fn unregister(&self, id: SubscriberId) -> bool {
        let mut guard = self.subscribers.lock().unwrap_or_else(PoisonError::into_inner);
        guard.remove(&id).is_some_and(|sub| {
            sub.unregistered.store(true, Ordering::Relaxed);
            true
        })
    }

    // ── Publishing ───────────────────────────────────────────────────────────

    /// Publish a single event payload.
    pub fn publish(&self, mut payload: EventPayload) -> SendResult {
        payload.seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        self.published.fetch_add(1, Ordering::Relaxed);
        let guard = self.subscribers.lock().unwrap_or_else(PoisonError::into_inner);
        if guard.is_empty() {
            return SendResult::NoSubscribers;
        }
        let mut any_dropped = false;
        let mut any_delivered = false;
        for sub in guard.values() {
            let ok = sub.try_deliver(&payload);
            if ok {
                any_delivered = true;
            } else if !sub.is_paused()
                && !sub.is_unregistered()
                && sub.filter.matches(&payload)
            {
                any_dropped = true;
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        drop(guard);
        if any_dropped {
            SendResult::BackPressure
        } else if any_delivered {
            SendResult::Delivered
        } else {
            SendResult::NoSubscribers
        }
    }

    /// Publish a batch of events atomically (in order).
    pub fn publish_batch(&self, batch: EventBatch) -> usize {
        let mut delivered = 0usize;
        for payload in batch.events {
            if self.publish(payload) == SendResult::Delivered {
                delivered += 1;
            }
        }
        delivered
    }

    /// Publish a text event on `topic`.
    pub fn emit_text(&self, topic: impl Into<String>, text: impl Into<String>) -> SendResult {
        self.publish(EventPayload::text(topic, text))
    }

    /// Publish a binary event on `topic`.
    pub fn emit(&self, topic: impl Into<String>, body: Vec<u8>) -> SendResult {
        self.publish(EventPayload::new(topic, body))
    }

    // ── Query ────────────────────────────────────────────────────────────────

    /// Return a handle to subscriber `id`.
    #[must_use]
    pub fn get_subscriber(&self, id: SubscriberId) -> Option<Arc<Subscriber>> {
        self.subscribers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .cloned()
    }

    /// Number of active subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.subscribers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Total events published since the bus was created.
    #[must_use]
    pub fn published_count(&self) -> u64 {
        self.published.load(Ordering::Relaxed)
    }

    /// Total events dropped due to back-pressure across all subscribers.
    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Return all subscriber IDs.
    #[must_use]
    pub fn subscriber_ids(&self) -> Vec<SubscriberId> {
        let guard = self.subscribers.lock().unwrap_or_else(PoisonError::into_inner);
        guard.keys().copied().collect()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new_default()
    }
}

impl fmt::Debug for EventBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventBus")
            .field("subscribers", &self.subscriber_count())
            .field("published", &self.published_count())
            .field("dropped", &self.dropped_count())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for EventBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EventBus {{ subs={}, published={}, dropped={} }}",
            self.subscriber_count(),
            self.published_count(),
            self.dropped_count(),
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TopicPattern ─────────────────────────────────────────────────────────

    #[test]
    fn test_pattern_wildcard() {
        let p = TopicPattern::new("*");
        assert!(p.matches("anything"));
        assert!(p.matches("a.b.c"));
    }

    #[test]
    fn test_pattern_exact() {
        let p = TopicPattern::new("analysis.done");
        assert!(p.matches("analysis.done"));
        assert!(!p.matches("analysis.start"));
    }

    #[test]
    fn test_pattern_prefix() {
        let p = TopicPattern::new("analysis.*");
        assert!(p.matches("analysis.done"));
        assert!(p.matches("analysis.start"));
        assert!(!p.matches("debug.step"));
        assert!(!p.matches("analysis")); // no trailing component
    }

    #[test]
    fn test_pattern_display() {
        let p = TopicPattern::new("foo.*");
        assert_eq!(p.to_string(), "foo.*");
    }

    // ── EventPayload ─────────────────────────────────────────────────────────

    #[test]
    fn test_payload_new() {
        let p = EventPayload::new("test.topic", vec![1, 2, 3]);
        assert_eq!(p.topic, "test.topic");
        assert_eq!(p.body, vec![1, 2, 3]);
        assert!(p.text.is_none());
    }

    #[test]
    fn test_payload_text() {
        let p = EventPayload::text("msg", "hello world");
        assert_eq!(p.text.as_deref(), Some("hello world"));
        assert!(!p.body.is_empty());
    }

    #[test]
    fn test_payload_display() {
        let p = EventPayload::text("t", "hi");
        let s = p.to_string();
        assert!(s.contains("hi"));
        assert!(s.contains("t"));
    }

    // ── EventFilter ──────────────────────────────────────────────────────────

    #[test]
    fn test_filter_accept_all() {
        let f = EventFilter::accept_all();
        let p = EventPayload::new("x", vec![]);
        assert!(f.matches(&p));
    }

    #[test]
    fn test_filter_by_topic() {
        let f = EventFilter::by_topic(TopicPattern::new("analysis.*"));
        let yes = EventPayload::new("analysis.done", vec![]);
        let no = EventPayload::new("debug.step", vec![]);
        assert!(f.matches(&yes));
        assert!(!f.matches(&no));
    }

    #[test]
    fn test_filter_text_contains() {
        let f = EventFilter::text_contains("error");
        let yes = EventPayload::text("log", "an error occurred");
        let no = EventPayload::text("log", "all good");
        assert!(f.matches(&yes));
        assert!(!f.matches(&no));
    }

    // ── SubscriberId ─────────────────────────────────────────────────────────

    #[test]
    fn test_subscriber_id_display() {
        let id = SubscriberId(42);
        assert_eq!(id.to_string(), "Sub#42");
    }

    // ── EventBus ─────────────────────────────────────────────────────────────

    #[test]
    fn test_bus_no_subscribers() {
        let bus = EventBus::new_default();
        let r = bus.emit("t", vec![]);
        assert_eq!(r, SendResult::NoSubscribers);
    }

    #[test]
    fn test_bus_subscribe_and_receive() {
        let bus = EventBus::new_default();
        let (_id, sub) = bus.subscribe_all("test");
        bus.emit_text("greet", "hello");
        let events = sub.drain();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].text.as_deref(), Some("hello"));
    }

    #[test]
    fn test_bus_topic_filter() {
        let bus = EventBus::new_default();
        let (_id, sub) = bus.subscribe_topic("t", TopicPattern::new("a.*"));
        bus.emit("a.done", vec![]);
        bus.emit("b.done", vec![]);
        let events = sub.drain();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].topic, "a.done");
    }

    #[test]
    fn test_bus_multiple_subscribers() {
        let bus = EventBus::new_default();
        let (_id1, sub1) = bus.subscribe_all("s1");
        let (_id2, sub2) = bus.subscribe_all("s2");
        bus.emit("t", vec![42]);
        assert_eq!(sub1.drain().len(), 1);
        assert_eq!(sub2.drain().len(), 1);
    }

    #[test]
    fn test_bus_pause_resume() {
        let bus = EventBus::new_default();
        let (id, sub) = bus.subscribe_all("paused");
        bus.pause(id);
        bus.emit("t", vec![]);
        assert_eq!(sub.drain().len(), 0);
        bus.resume(id);
        bus.emit("t", vec![]);
        assert_eq!(sub.drain().len(), 1);
    }

    #[test]
    fn test_bus_unregister() {
        let bus = EventBus::new_default();
        let (id, _sub) = bus.subscribe_all("gone");
        assert_eq!(bus.subscriber_count(), 1);
        bus.unregister(id);
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[test]
    fn test_bus_back_pressure() {
        let bus = EventBus::new(2); // capacity = 2
        let (_id, sub) = bus.subscribe_all("bp");
        bus.emit("t", vec![1]);
        bus.emit("t", vec![2]);
        let r = bus.emit("t", vec![3]); // queue full
        assert_eq!(r, SendResult::BackPressure);
        assert_eq!(sub.pending(), 2);
        assert_eq!(sub.dropped_count(), 1);
    }

    #[test]
    fn test_bus_sequence_numbers() {
        let bus = EventBus::new_default();
        let (_id, sub) = bus.subscribe_all("seq");
        bus.emit("t", vec![]);
        bus.emit("t", vec![]);
        let events = sub.drain();
        assert_eq!(events.len(), 2);
        assert!(events[0].seq < events[1].seq);
    }

    #[test]
    fn test_bus_publish_batch() {
        let bus = EventBus::new_default();
        let (_id, sub) = bus.subscribe_all("batch");
        let mut batch = EventBatch::new();
        batch.push(EventPayload::text("a", "x"));
        batch.push(EventPayload::text("b", "y"));
        bus.publish_batch(batch);
        assert_eq!(sub.drain().len(), 2);
    }

    #[test]
    fn test_bus_statistics() {
        let bus = EventBus::new_default();
        let (_id, _sub) = bus.subscribe_all("s");
        bus.emit("t", vec![]);
        bus.emit("t", vec![]);
        assert_eq!(bus.published_count(), 2);
    }

    #[test]
    fn test_bus_debug_display() {
        let bus = EventBus::new_default();
        let dbg = format!("{bus:?}");
        assert!(dbg.contains("EventBus"));
        let disp = format!("{bus}");
        assert!(disp.contains("subs=0"));
    }

    #[test]
    fn test_batch_len_is_empty() {
        let batch = EventBatch::new();
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
    }
}
