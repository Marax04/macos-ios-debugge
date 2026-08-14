//! Plugin event bus — typed publish/subscribe system for inter-plugin communication.
//!
//! Supports:
//! - Typed events with topic-based routing
//! - Subscribe / unsubscribe / publish
//! - Async delivery via a pending queue
//! - Priority queuing (Critical > High > Normal > Low)
//! - Wildcard topic subscriptions (`"analysis.*"`)

use serde::{Deserialize, Serialize};
use std::collections::{BinaryHeap, HashMap};
use std::fmt;
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ─── EventPriority ────────────────────────────────────────────────────────────

/// Priority level for event delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EventPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl Default for EventPriority {
    fn default() -> Self {
        Self::Normal
    }
}

impl fmt::Display for EventPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Normal => write!(f, "Normal"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

// ─── BusEvent ─────────────────────────────────────────────────────────────────

/// A typed event on the plugin event bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusEvent {
    /// Hierarchical topic string (e.g. `"analysis.started"`, `"ui.menu.clicked"`).
    pub topic: String,
    /// Plugin or host component that published this event.
    pub publisher: String,
    /// Event payload as JSON value.
    pub payload: serde_json::Value,
    /// Delivery priority.
    pub priority: EventPriority,
    /// Unix timestamp (seconds) when the event was created.
    pub created_at: u64,
    /// Monotonically increasing event sequence number.
    pub seq: u64,
}

impl BusEvent {
    /// Create a new event with the given topic and JSON payload.
    #[must_use]
    pub fn new(
        topic: impl Into<String>,
        publisher: impl Into<String>,
        payload: serde_json::Value,
        priority: EventPriority,
        seq: u64,
    ) -> Self {
        Self {
            topic: topic.into(),
            publisher: publisher.into(),
            payload,
            priority,
            created_at: unix_now_secs(),
            seq,
        }
    }

    /// Convenience builder for a Normal-priority event with a string payload.
    #[must_use]
    pub fn simple(
        topic: impl Into<String>,
        publisher: impl Into<String>,
        message: impl Into<String>,
        seq: u64,
    ) -> Self {
        Self::new(
            topic,
            publisher,
            serde_json::Value::String(message.into()),
            EventPriority::Normal,
            seq,
        )
    }

    /// Convenience builder for a Critical-priority event.
    #[must_use]
    pub fn critical(
        topic: impl Into<String>,
        publisher: impl Into<String>,
        payload: serde_json::Value,
        seq: u64,
    ) -> Self {
        Self::new(topic, publisher, payload, EventPriority::Critical, seq)
    }
}

impl fmt::Display for BusEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BusEvent[{}] topic={} from={} priority={}",
            self.seq, self.topic, self.publisher, self.priority
        )
    }
}

// ─── Priority queue support ───────────────────────────────────────────────────

/// Wrapper that makes `BusEvent` orderable for `BinaryHeap` (max-heap by priority then seq).
#[derive(Debug, Clone)]
struct PrioritizedEvent(BusEvent);

impl PartialEq for PrioritizedEvent {
    fn eq(&self, other: &Self) -> bool {
        self.0.priority == other.0.priority && self.0.seq == other.0.seq
    }
}
impl Eq for PrioritizedEvent {}

impl PartialOrd for PrioritizedEvent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedEvent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher priority first; for equal priority, lower seq first (FIFO).
        self.0
            .priority
            .cmp(&other.0.priority)
            .then_with(|| other.0.seq.cmp(&self.0.seq))
    }
}

// ─── Subscription ─────────────────────────────────────────────────────────────

/// Type alias for an event handler callback.
pub type EventHandler = Arc<dyn Fn(&BusEvent) + Send + Sync>;

/// A single subscription to a topic pattern.
pub struct Subscription {
    /// Unique subscription ID.
    pub id: SubscriptionId,
    /// Topic pattern to match (exact or prefix with `*`).
    pub pattern: String,
    /// The subscribing plugin or component.
    pub subscriber: String,
    /// Minimum priority level to receive.
    pub min_priority: EventPriority,
    /// Callback invoked on each matching event.
    handler: EventHandler,
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Subscription {{ id={:?}, pattern={}, subscriber={} }}",
            self.id, self.pattern, self.subscriber
        )
    }
}

/// Opaque subscription identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubscriptionId(u64);

impl SubscriptionId {
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SubId({})", self.0)
    }
}

// ─── Topic matching ───────────────────────────────────────────────────────────

/// Match `topic` against `pattern`.
///
/// Rules:
/// - Exact match: `"analysis.started"` matches `"analysis.started"`.
/// - Trailing `*`: `"analysis.*"` matches any topic starting with `"analysis."`.
/// - Single `*`: matches everything.
#[must_use]
pub fn topic_matches(pattern: &str, topic: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        return topic == prefix || topic.starts_with(&format!("{prefix}."));
    }
    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        return topic.starts_with(prefix);
    }
    pattern == topic
}

// ─── DeliveryStats ───────────────────────────────────────────────────────────

/// Statistics tracked by the event bus.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeliveryStats {
    pub published: u64,
    pub delivered: u64,
    pub dropped: u64,
    pub pending: usize,
    pub by_priority: HashMap<String, u64>,
}

impl DeliveryStats {
    fn record_publish(&mut self, priority: EventPriority) {
        self.published += 1;
        *self
            .by_priority
            .entry(priority.to_string())
            .or_insert(0) += 1;
    }

    fn record_deliver(&mut self) {
        self.delivered += 1;
    }

    fn record_drop(&mut self) {
        self.dropped += 1;
    }
}

impl fmt::Display for DeliveryStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeliveryStats {{ published={}, delivered={}, dropped={}, pending={} }}",
            self.published, self.delivered, self.dropped, self.pending
        )
    }
}

// ─── EventBus ─────────────────────────────────────────────────────────────────

/// Typed event bus with priority queuing and wildcard subscriptions.
pub struct EventBus {
    subscriptions: RwLock<HashMap<SubscriptionId, Subscription>>,
    /// Priority queue of undelivered events.
    queue: Mutex<BinaryHeap<PrioritizedEvent>>,
    /// Condvar to wake up delivery threads.
    notify: Condvar,
    next_sub_id: Mutex<u64>,
    next_seq: Mutex<u64>,
    stats: Mutex<DeliveryStats>,
    /// Maximum events to keep in the pending queue before dropping oldest.
    max_queue_len: usize,
    /// Dead-letter queue for undelivered events.
    dead_letter: Mutex<Vec<BusEvent>>,
}

impl EventBus {
    /// Create a new event bus with a maximum queue depth of `max_queue_len`.
    #[must_use]
    pub fn new(max_queue_len: usize) -> Self {
        Self {
            subscriptions: RwLock::new(HashMap::new()),
            queue: Mutex::new(BinaryHeap::new()),
            notify: Condvar::new(),
            next_sub_id: Mutex::new(1),
            next_seq: Mutex::new(1),
            stats: Mutex::new(DeliveryStats::default()),
            max_queue_len: max_queue_len.max(1),
            dead_letter: Mutex::new(Vec::new()),
        }
    }

    /// Create with default queue depth of 4096.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(4096)
    }

    // ── Subscribe / Unsubscribe ───────────────────────────────────────────

    /// Subscribe to events matching `pattern` with the given `handler`.
    ///
    /// Returns the `SubscriptionId` which can be used to unsubscribe later.
    pub fn subscribe(
        &self,
        pattern: impl Into<String>,
        subscriber: impl Into<String>,
        min_priority: EventPriority,
        handler: impl Fn(&BusEvent) + Send + Sync + 'static,
    ) -> SubscriptionId {
        let id = self.alloc_sub_id();
        let sub = Subscription {
            id,
            pattern: pattern.into(),
            subscriber: subscriber.into(),
            min_priority,
            handler: Arc::new(handler),
        };
        self.subscriptions.write().unwrap().insert(id, sub);
        id
    }

    /// Unsubscribe by `SubscriptionId`.
    ///
    /// Returns `true` if the subscription existed.
    pub fn unsubscribe(&self, id: SubscriptionId) -> bool {
        self.subscriptions.write().unwrap().remove(&id).is_some()
    }

    /// Number of active subscriptions.
    #[must_use]
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.read().unwrap().len()
    }

    /// Return all subscriptions for a specific subscriber.
    #[must_use]
    pub fn subscriptions_for(&self, subscriber: &str) -> Vec<SubscriptionId> {
        self.subscriptions
            .read()
            .unwrap()
            .values()
            .filter(|s| s.subscriber == subscriber)
            .map(|s| s.id)
            .collect()
    }

    // ── Publish ───────────────────────────────────────────────────────────

    /// Publish an event synchronously — calls all matching handlers immediately.
    ///
    /// Returns the number of subscribers that received the event.
    pub fn publish_sync(
        &self,
        topic: impl Into<String>,
        publisher: impl Into<String>,
        payload: serde_json::Value,
        priority: EventPriority,
    ) -> usize {
        let seq = self.alloc_seq();
        let event = BusEvent::new(topic, publisher, payload, priority, seq);
        self.stats.lock().unwrap().record_publish(priority);

        let subs = self.subscriptions.read().unwrap();
        let matching: Vec<EventHandler> = subs
            .values()
            .filter(|s| {
                priority >= s.min_priority && topic_matches(&s.pattern, &event.topic)
            })
            .map(|s| Arc::clone(&s.handler))
            .collect();
        drop(subs);

        let delivered = matching.len();
        for handler in &matching {
            handler(&event);
        }

        let mut stats = self.stats.lock().unwrap();
        for _ in 0..delivered {
            stats.record_deliver();
        }
        if delivered == 0 {
            stats.record_drop();
            self.dead_letter.lock().unwrap().push(event);
        }
        delivered
    }

    /// Enqueue an event for asynchronous delivery (lazy / batched).
    ///
    /// If the queue is full the event is dropped and recorded in dead-letter.
    pub fn publish_async(
        &self,
        topic: impl Into<String>,
        publisher: impl Into<String>,
        payload: serde_json::Value,
        priority: EventPriority,
    ) {
        let seq = self.alloc_seq();
        let event = BusEvent::new(topic, publisher, payload, priority, seq);
        let mut queue = self.queue.lock().unwrap();
        self.stats.lock().unwrap().record_publish(priority);

        if queue.len() >= self.max_queue_len {
            self.stats.lock().unwrap().record_drop();
            self.dead_letter.lock().unwrap().push(event);
        } else {
            queue.push(PrioritizedEvent(event));
            self.notify.notify_one();
        }
    }

    /// Drain and deliver all pending async events.
    ///
    /// Returns the number of events processed.
    pub fn flush(&self) -> usize {
        let mut count = 0;
        loop {
            let event = {
                let mut queue = self.queue.lock().unwrap();
                queue.pop().map(|pe| pe.0)
            };
            match event {
                Some(ev) => {
                    let subs = self.subscriptions.read().unwrap();
                    let matching: Vec<EventHandler> = subs
                        .values()
                        .filter(|s| {
                            ev.priority >= s.min_priority
                                && topic_matches(&s.pattern, &ev.topic)
                        })
                        .map(|s| Arc::clone(&s.handler))
                        .collect();
                    drop(subs);
                    let delivered = matching.len();
                    for handler in &matching {
                        handler(&ev);
                    }
                    let mut stats = self.stats.lock().unwrap();
                    for _ in 0..delivered {
                        stats.record_deliver();
                    }
                    if delivered == 0 {
                        stats.record_drop();
                        self.dead_letter.lock().unwrap().push(ev);
                    }
                    count += 1;
                }
                None => break,
            }
        }
        // Update pending count.
        self.stats.lock().unwrap().pending = self.queue.lock().unwrap().len();
        count
    }

    /// Wait for at least one async event to arrive, flush, and return the count.
    ///
    /// Times out after `timeout` and returns 0 if nothing arrived.
    pub fn flush_with_timeout(&self, timeout: Duration) -> usize {
        let queue = self.queue.lock().unwrap();
        let (_q, result) = self
            .notify
            .wait_timeout_while(queue, timeout, |q| q.is_empty())
            .unwrap();
        // If the wait timed out (no event ever arrived), do not attempt to
        // flush — the queue is guaranteed still empty.
        if result.timed_out() {
            return 0;
        }
        self.flush()
    }

    // ── Queries ───────────────────────────────────────────────────────────

    /// Current statistics.
    #[must_use]
    pub fn stats(&self) -> DeliveryStats {
        self.stats.lock().unwrap().clone()
    }

    /// Number of events currently in the async queue.
    #[must_use]
    pub fn queue_depth(&self) -> usize {
        self.queue.lock().unwrap().len()
    }

    /// Dead-letter queue (events that had no subscribers).
    #[must_use]
    pub fn dead_letter_queue(&self) -> Vec<BusEvent> {
        self.dead_letter.lock().unwrap().clone()
    }

    /// Clear the dead-letter queue.
    pub fn clear_dead_letter(&self) {
        self.dead_letter.lock().unwrap().clear();
    }

    /// Reset statistics.
    pub fn reset_stats(&self) {
        *self.stats.lock().unwrap() = DeliveryStats::default();
    }

    // ── Internals ─────────────────────────────────────────────────────────

    fn alloc_sub_id(&self) -> SubscriptionId {
        let mut id = self.next_sub_id.lock().unwrap();
        let v = *id;
        *id += 1;
        SubscriptionId(v)
    }

    fn alloc_seq(&self) -> u64 {
        let mut s = self.next_seq.lock().unwrap();
        let v = *s;
        *s += 1;
        v
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl fmt::Debug for EventBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EventBus {{ subs={}, queue={}, stats={} }}",
            self.subscription_count(),
            self.queue_depth(),
            self.stats()
        )
    }
}

// ─── TypedChannel ────────────────────────────────────────────────────────────

/// A typed channel layered on top of `EventBus` for a specific topic.
///
/// Serialises/deserialises payload via `serde_json` automatically.
pub struct TypedChannel<T> {
    bus: Arc<EventBus>,
    topic: String,
    publisher_name: String,
    _marker: std::marker::PhantomData<T>,
}

impl<T: Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static> TypedChannel<T> {
    /// Create a new typed channel for `topic` on `bus`.
    #[must_use]
    pub fn new(
        bus: Arc<EventBus>,
        topic: impl Into<String>,
        publisher_name: impl Into<String>,
    ) -> Self {
        Self {
            bus,
            topic: topic.into(),
            publisher_name: publisher_name.into(),
            _marker: std::marker::PhantomData,
        }
    }

    /// Publish a value synchronously.
    ///
    /// # Errors
    /// Returns `serde_json::Error` if serialisation fails.
    pub fn send(&self, value: &T, priority: EventPriority) -> Result<usize, serde_json::Error> {
        let payload = serde_json::to_value(value)?;
        Ok(self.bus.publish_sync(
            self.topic.clone(),
            self.publisher_name.clone(),
            payload,
            priority,
        ))
    }

    /// Subscribe to this channel, deserialising payloads automatically.
    ///
    /// The handler receives `Option<T>` (None if deserialisation fails).
    pub fn subscribe<F>(&self, subscriber: impl Into<String>, handler: F) -> SubscriptionId
    where
        F: Fn(Option<T>) + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        self.bus.subscribe(
            self.topic.clone(),
            subscriber,
            EventPriority::Normal,
            move |ev| {
                let val: Option<T> = serde_json::from_value(ev.payload.clone()).ok();
                handler(val);
            },
        )
    }

    /// Topic string this channel publishes to.
    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // ── topic_matches ─────────────────────────────────────────────────────

    #[test]
    fn test_topic_exact() {
        assert!(topic_matches("analysis.started", "analysis.started"));
        assert!(!topic_matches("analysis.started", "analysis.stopped"));
    }

    #[test]
    fn test_topic_wildcard_all() {
        assert!(topic_matches("*", "anything.at.all"));
    }

    #[test]
    fn test_topic_prefix_wildcard() {
        assert!(topic_matches("analysis.*", "analysis.started"));
        assert!(topic_matches("analysis.*", "analysis.pass.done"));
        assert!(!topic_matches("analysis.*", "ui.menu.clicked"));
        // Exact prefix also matches
        assert!(topic_matches("analysis.*", "analysis"));
    }

    #[test]
    fn test_topic_trailing_star() {
        assert!(topic_matches("ui*", "ui.menu.clicked"));
        assert!(topic_matches("ui*", "uidialog"));
        assert!(!topic_matches("ui*", "backend.thing"));
    }

    // ── EventPriority ─────────────────────────────────────────────────────

    #[test]
    fn test_priority_ordering() {
        assert!(EventPriority::Critical > EventPriority::High);
        assert!(EventPriority::High > EventPriority::Normal);
        assert!(EventPriority::Normal > EventPriority::Low);
    }

    #[test]
    fn test_priority_display() {
        assert_eq!(EventPriority::Low.to_string(), "Low");
        assert_eq!(EventPriority::Critical.to_string(), "Critical");
    }

    // ── BusEvent ──────────────────────────────────────────────────────────

    #[test]
    fn test_bus_event_simple() {
        let ev = BusEvent::simple("test.topic", "pub", "hello", 1);
        assert_eq!(ev.topic, "test.topic");
        assert_eq!(ev.publisher, "pub");
        assert_eq!(ev.priority, EventPriority::Normal);
    }

    #[test]
    fn test_bus_event_critical() {
        let ev = BusEvent::critical("alert", "host", serde_json::json!({"code": 500}), 2);
        assert_eq!(ev.priority, EventPriority::Critical);
    }

    #[test]
    fn test_bus_event_display() {
        let ev = BusEvent::simple("t", "p", "m", 42);
        let s = format!("{ev}");
        assert!(s.contains("42"));
        assert!(s.contains("t"));
    }

    // ── Subscribe / Publish sync ──────────────────────────────────────────

    #[test]
    fn test_subscribe_and_publish_sync() {
        let bus = EventBus::with_defaults();
        let count = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&count);
        bus.subscribe("test.*", "sub-a", EventPriority::Low, move |_ev| {
            c.fetch_add(1, Ordering::Relaxed);
        });
        let delivered =
            bus.publish_sync("test.event", "publisher", serde_json::json!({}), EventPriority::Normal);
        assert_eq!(delivered, 1);
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_unsubscribe() {
        let bus = EventBus::with_defaults();
        let count = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&count);
        let id = bus.subscribe("*", "sub", EventPriority::Low, move |_| {
            c.fetch_add(1, Ordering::Relaxed);
        });
        bus.unsubscribe(id);
        bus.publish_sync("any", "pub", serde_json::json!({}), EventPriority::Normal);
        assert_eq!(count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_publish_no_subscribers_goes_dead_letter() {
        let bus = EventBus::with_defaults();
        let delivered =
            bus.publish_sync("orphan.event", "pub", serde_json::json!({}), EventPriority::Normal);
        assert_eq!(delivered, 0);
        assert_eq!(bus.dead_letter_queue().len(), 1);
    }

    #[test]
    fn test_min_priority_filter() {
        let bus = EventBus::with_defaults();
        let count = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&count);
        // Subscribe with High minimum — should not receive Normal events.
        bus.subscribe("*", "high-only", EventPriority::High, move |_| {
            c.fetch_add(1, Ordering::Relaxed);
        });
        bus.publish_sync("topic", "pub", serde_json::json!({}), EventPriority::Normal);
        assert_eq!(count.load(Ordering::Relaxed), 0);
        bus.publish_sync("topic", "pub", serde_json::json!({}), EventPriority::Critical);
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    // ── Async publish / flush ─────────────────────────────────────────────

    #[test]
    fn test_publish_async_and_flush() {
        let bus = EventBus::with_defaults();
        let count = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&count);
        bus.subscribe("async.*", "sub", EventPriority::Low, move |_| {
            c.fetch_add(1, Ordering::Relaxed);
        });
        bus.publish_async("async.event", "pub", serde_json::json!({}), EventPriority::Normal);
        assert_eq!(bus.queue_depth(), 1);
        let processed = bus.flush();
        assert_eq!(processed, 1);
        assert_eq!(bus.queue_depth(), 0);
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_async_queue_overflow() {
        let bus = EventBus::new(2);
        // Fill queue.
        bus.publish_async("t", "p", serde_json::json!({}), EventPriority::Normal);
        bus.publish_async("t", "p", serde_json::json!({}), EventPriority::Normal);
        // Third event should be dropped.
        bus.publish_async("t", "p", serde_json::json!({}), EventPriority::Normal);
        assert_eq!(bus.queue_depth(), 2);
        assert_eq!(bus.dead_letter_queue().len(), 1);
    }

    #[test]
    fn test_priority_ordering_in_queue() {
        let bus = EventBus::with_defaults();
        let received = Arc::new(Mutex::new(Vec::new()));
        let r = Arc::clone(&received);
        bus.subscribe("*", "sub", EventPriority::Low, move |ev| {
            r.lock().unwrap().push(ev.priority);
        });
        // Publish in Low → Normal → Critical order.
        bus.publish_async("t", "p", serde_json::json!({}), EventPriority::Low);
        bus.publish_async("t", "p", serde_json::json!({}), EventPriority::Normal);
        bus.publish_async("t", "p", serde_json::json!({}), EventPriority::Critical);
        bus.flush();
        let order = received.lock().unwrap().clone();
        assert_eq!(order.len(), 3);
        // Highest priority should be delivered first.
        assert_eq!(order[0], EventPriority::Critical);
        assert_eq!(order[1], EventPriority::Normal);
        assert_eq!(order[2], EventPriority::Low);
    }

    // ── Stats ─────────────────────────────────────────────────────────────

    #[test]
    fn test_stats_published() {
        let bus = EventBus::with_defaults();
        bus.subscribe("*", "s", EventPriority::Low, |_| {});
        bus.publish_sync("t", "p", serde_json::json!({}), EventPriority::Normal);
        bus.publish_sync("t", "p", serde_json::json!({}), EventPriority::High);
        let stats = bus.stats();
        assert_eq!(stats.published, 2);
        assert_eq!(stats.delivered, 2);
    }

    #[test]
    fn test_stats_dropped() {
        let bus = EventBus::with_defaults();
        // No subscribers → drop
        bus.publish_sync("nope", "p", serde_json::json!({}), EventPriority::Normal);
        let stats = bus.stats();
        assert_eq!(stats.dropped, 1);
    }

    #[test]
    fn test_stats_reset() {
        let bus = EventBus::with_defaults();
        bus.subscribe("*", "s", EventPriority::Low, |_| {});
        bus.publish_sync("t", "p", serde_json::json!({}), EventPriority::Normal);
        bus.reset_stats();
        assert_eq!(bus.stats().published, 0);
    }

    // ── SubscriptionId ────────────────────────────────────────────────────

    #[test]
    fn test_subscription_id_display() {
        let id = SubscriptionId(42);
        assert_eq!(id.to_string(), "SubId(42)");
        assert_eq!(id.as_u64(), 42);
    }

    // ── subscriptions_for ─────────────────────────────────────────────────

    #[test]
    fn test_subscriptions_for() {
        let bus = EventBus::with_defaults();
        bus.subscribe("a", "plugin-x", EventPriority::Low, |_| {});
        bus.subscribe("b", "plugin-x", EventPriority::Low, |_| {});
        bus.subscribe("c", "plugin-y", EventPriority::Low, |_| {});
        let ids = bus.subscriptions_for("plugin-x");
        assert_eq!(ids.len(), 2);
    }

    // ── Clear dead letter ─────────────────────────────────────────────────

    #[test]
    fn test_clear_dead_letter() {
        let bus = EventBus::with_defaults();
        bus.publish_sync("t", "p", serde_json::json!({}), EventPriority::Normal);
        assert!(!bus.dead_letter_queue().is_empty());
        bus.clear_dead_letter();
        assert!(bus.dead_letter_queue().is_empty());
    }

    // ── DeliveryStats display ─────────────────────────────────────────────

    #[test]
    fn test_delivery_stats_display() {
        let s = DeliveryStats {
            published: 10,
            delivered: 8,
            dropped: 2,
            pending: 0,
            by_priority: HashMap::new(),
        };
        let out = format!("{s}");
        assert!(out.contains("published=10"));
        assert!(out.contains("dropped=2"));
    }

    // ── TypedChannel ──────────────────────────────────────────────────────

    #[test]
    fn test_typed_channel_send_receive() {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        struct Msg {
            value: i32,
        }

        let bus = Arc::new(EventBus::with_defaults());
        let ch: TypedChannel<Msg> = TypedChannel::new(Arc::clone(&bus), "msg.channel", "producer");
        let received = Arc::new(Mutex::new(Vec::new()));
        let r = Arc::clone(&received);
        ch.subscribe("consumer", move |msg: Option<Msg>| {
            if let Some(m) = msg {
                r.lock().unwrap().push(m.value);
            }
        });
        ch.send(&Msg { value: 99 }, EventPriority::Normal).unwrap();
        let got = received.lock().unwrap().clone();
        assert_eq!(got, vec![99]);
    }

    #[test]
    fn test_typed_channel_topic() {
        let bus = Arc::new(EventBus::with_defaults());
        let ch: TypedChannel<i32> = TypedChannel::new(Arc::clone(&bus), "my.topic", "p");
        assert_eq!(ch.topic(), "my.topic");
    }

    // ── Debug / display ───────────────────────────────────────────────────

    #[test]
    fn test_event_bus_debug() {
        let bus = EventBus::with_defaults();
        let s = format!("{bus:?}");
        assert!(s.contains("EventBus"));
    }
}
