//! `event_dispatcher.rs` — Publish/subscribe event dispatcher with priority
//! queues, topic routing, back-pressure handling, and subscriber lifecycle.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::event_types::{
    AnalysisEvent, AnalysisEventFilter, EventBatch, EventPayload, EventPriority,
};

/// Cast helper: isolates usize→f64 precision-loss cast in one place.
#[inline]
fn cast_usize_f64(v: usize) -> f64 { v as f64 }

// ---------------------------------------------------------------------------
// SubscriberId
// ---------------------------------------------------------------------------

/// Opaque handle returned when subscribing.  Used to unsubscribe later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriberId(u64);

impl fmt::Display for SubscriberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sub#{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Subscription
// ---------------------------------------------------------------------------

/// A subscriber registration held by the dispatcher.
pub struct Subscription {
    /// Unique ID for this subscription.
    pub id: SubscriberId,
    /// Optional topic filter; `None` means all topics.
    pub topic: Option<String>,
    /// Optional priority threshold; events below this priority are dropped.
    pub min_priority: EventPriority,
    /// Optional additional filter predicate.
    pub filter: Option<AnalysisEventFilter>,
    /// Maximum number of events the subscriber's queue can hold (back-pressure).
    pub queue_capacity: usize,
    /// Pending events for this subscriber.
    pub queue: std::collections::VecDeque<EventPayload>,
    /// Total events delivered to this subscription.
    pub delivered: u64,
    /// Total events dropped due to full queue.
    pub dropped: u64,
    /// Whether the subscription is still active.
    pub active: bool,
    /// Human-readable label.
    pub label: String,
    /// When the subscription was created.
    pub created_at: SystemTime,
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subscription")
            .field("id", &self.id)
            .field("topic", &self.topic)
            .field("label", &self.label)
            .field("active", &self.active)
            .field("min_priority", &self.min_priority)
            .field("filter", &self.filter.as_ref().map(|_| "<filter>"))
            .field("queue_capacity", &self.queue_capacity)
            .field("queue_len", &self.queue.len())
            .field("delivered", &self.delivered)
            .field("dropped", &self.dropped)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl Subscription {
    fn new(id: SubscriberId, label: impl Into<String>, config: &SubscribeConfig) -> Self {
        Self {
            id,
            topic: config.topic.clone(),
            min_priority: config.min_priority,
            filter: None,
            queue_capacity: config.queue_capacity,
            queue: std::collections::VecDeque::with_capacity(
                config.queue_capacity.min(1024),
            ),
            delivered: 0,
            dropped: 0,
            active: true,
            label: label.into(),
            created_at: SystemTime::now(),
        }
    }

    /// Try to enqueue `payload`, applying back-pressure by dropping the
    /// oldest event when the queue is full.
    fn try_enqueue(&mut self, payload: EventPayload) -> EnqueueResult {
        // Priority check
        if payload.priority < self.min_priority {
            return EnqueueResult::Filtered;
        }
        // Topic check
        if let Some(ref topic) = self.topic
            && payload_topic(&payload) != *topic {
                return EnqueueResult::Filtered;
            }
        // Custom filter
        if let Some(ref flt) = self.filter
            && !flt.matches(&payload) {
                return EnqueueResult::Filtered;
            }
        // Back-pressure
        if self.queue.len() >= self.queue_capacity {
            self.queue.pop_front(); // drop oldest
            self.dropped += 1;
        }
        self.queue.push_back(payload);
        self.delivered += 1;
        EnqueueResult::Delivered
    }

    /// Drain all pending events up to `max_count`.
    pub fn drain(&mut self, max_count: usize) -> Vec<EventPayload> {
        let take = max_count.min(self.queue.len());
        self.queue.drain(..take).collect()
    }

    /// Peek at the next pending event without removing it.
    #[must_use]
    pub fn peek(&self) -> Option<&EventPayload> {
        self.queue.front()
    }

    /// Number of events pending.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.queue.len()
    }

    /// Queue utilisation in [0.0, 1.0].
    #[must_use]
    pub fn queue_utilisation(&self) -> f64 {
        if self.queue_capacity == 0 {
            return 0.0;
        }
        cast_usize_f64(self.queue.len()) / cast_usize_f64(self.queue_capacity)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnqueueResult {
    Delivered,
    Filtered,
}

/// Derive a topic string from an event payload (based on variant family).
fn payload_topic(p: &EventPayload) -> std::string::String {
    match &p.event {
            AnalysisEvent::FileOpened(_) | AnalysisEvent::FileAnalyzed(_) => "file",
            AnalysisEvent::FunctionFound(_) => "function",
            AnalysisEvent::StringFound(_) => "string",
            AnalysisEvent::SymbolResolved(_) => "symbol",
            AnalysisEvent::CrossRefAdded(_) => "xref",
            AnalysisEvent::PatternMatched(_) => "pattern",
            AnalysisEvent::AlertTriggered(_) => "alert",
            AnalysisEvent::PluginStarted(_) => "plugin",
            AnalysisEvent::ProgressUpdate(_) => "progress",
            AnalysisEvent::AnalysisComplete(_) => "analysis",
            AnalysisEvent::ErrorOccurred(_) => "error",
        }
        .to_owned()
}

// ---------------------------------------------------------------------------
// SubscribeConfig
// ---------------------------------------------------------------------------

/// Configuration for a new subscription.
#[derive(Debug, Clone)]
pub struct SubscribeConfig {
    /// Optional topic filter.
    pub topic: Option<String>,
    /// Minimum priority to receive.
    pub min_priority: EventPriority,
    /// Subscriber queue capacity.
    pub queue_capacity: usize,
}

impl Default for SubscribeConfig {
    fn default() -> Self {
        Self {
            topic: None,
            min_priority: EventPriority::Low,
            queue_capacity: 512,
        }
    }
}

impl SubscribeConfig {
    /// Subscribe to all events.
    #[must_use]
    pub fn all() -> Self {
        Self::default()
    }

    /// Subscribe only to events on a given topic.
    #[must_use]
    pub fn topic(topic: impl Into<String>) -> Self {
        Self {
            topic: Some(topic.into()),
            ..Self::default()
        }
    }

    /// Subscribe only to events at or above `min_priority`.
    #[must_use]
    pub const fn with_min_priority(mut self, min: EventPriority) -> Self {
        self.min_priority = min;
        self
    }

    /// Set queue capacity.
    #[must_use]
    pub const fn with_capacity(mut self, cap: usize) -> Self {
        self.queue_capacity = cap;
        self
    }
}

// ---------------------------------------------------------------------------
// EventQueue — priority-ordered outbox
// ---------------------------------------------------------------------------

/// A priority-ordered event queue.  Critical events are always at the front.
#[derive(Debug, Default)]
pub struct EventQueue {
    /// Events grouped by priority, highest index = highest priority.
    lanes: [std::collections::VecDeque<EventPayload>; 4],
    /// Total events across all lanes.
    total: usize,
    /// Maximum total capacity (0 = unlimited).
    capacity: usize,
}

impl EventQueue {
    /// Create a queue with optional capacity limit.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            lanes: Default::default(),
            total: 0,
            capacity,
        }
    }

    const fn lane_index(p: EventPriority) -> usize {
        p as usize
    }

    /// Enqueue `payload`.  When at capacity, drops the lowest-priority event.
    pub fn push(&mut self, payload: EventPayload) {
        if self.capacity > 0 && self.total >= self.capacity {
            // Drop the oldest lowest-priority event.
            for lane in &mut self.lanes {
                let lane: &mut std::collections::VecDeque<EventPayload> = lane;
                if !lane.is_empty() {
                    lane.pop_front();
                    self.total -= 1;
                    break;
                }
            }
        }
        let idx = Self::lane_index(payload.priority);
        self.lanes[idx].push_back(payload);
        self.total += 1;
    }

    /// Pop the highest-priority event.
    pub fn pop(&mut self) -> Option<EventPayload> {
        for lane in self.lanes.iter_mut().rev() {
            let lane: &mut std::collections::VecDeque<EventPayload> = lane;
            if let Some(p) = lane.pop_front() {
                self.total -= 1;
                return Some(p);
            }
        }
        None
    }

    /// Peek at the highest-priority pending event.
    #[must_use]
    pub fn peek(&self) -> Option<&EventPayload> {
        for lane in self.lanes.iter().rev() {
            let lane: &std::collections::VecDeque<EventPayload> = lane;
            if let Some(p) = lane.front() {
                return Some(p);
            }
        }
        None
    }

    /// Return total number of enqueued events.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.total
    }

    /// Return `true` if no events are pending.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Drain up to `n` events, highest priority first.
    pub fn drain_n(&mut self, n: usize) -> Vec<EventPayload> {
        let mut out = Vec::with_capacity(n.min(self.total));
        for _ in 0..n {
            match self.pop() {
                Some(p) => out.push(p),
                None => break,
            }
        }
        out
    }

    /// Drain all events, returning them highest-priority first.
    pub fn drain_all(&mut self) -> Vec<EventPayload> {
        self.drain_n(self.total)
    }
}

// ---------------------------------------------------------------------------
// DispatchConfig
// ---------------------------------------------------------------------------

/// Configuration for the [`EventDispatcher`].
#[derive(Debug, Clone)]
pub struct DispatchConfig {
    /// Maximum number of subscribers.
    pub max_subscribers: usize,
    /// Default queue capacity for new subscriptions.
    pub default_queue_capacity: usize,
    /// Enable event batching: buffer events and deliver in bulk.
    pub batching_enabled: bool,
    /// Flush the batch after this many events.
    pub batch_size: usize,
    /// Flush the batch after this duration even if `batch_size` not reached.
    pub batch_flush_interval: Duration,
    /// Drop events with priority below this threshold when under pressure.
    pub drop_below_priority: EventPriority,
}

impl Default for DispatchConfig {
    fn default() -> Self {
        Self {
            max_subscribers: 256,
            default_queue_capacity: 512,
            batching_enabled: false,
            batch_size: 64,
            batch_flush_interval: Duration::from_millis(50),
            drop_below_priority: EventPriority::Low,
        }
    }
}

// ---------------------------------------------------------------------------
// DispatchStats
// ---------------------------------------------------------------------------

/// Live statistics tracked by the dispatcher.
#[derive(Debug, Clone, Default)]
pub struct DispatchStats {
    /// Total events published.
    pub total_published: u64,
    /// Total events delivered to at least one subscriber.
    pub total_delivered: u64,
    /// Total events dropped (no subscribers or all queues full).
    pub total_dropped: u64,
    /// Per-topic publish counts.
    pub by_topic: HashMap<String, u64>,
    /// Per-variant publish counts.
    pub by_variant: HashMap<&'static str, u64>,
    /// Current number of active subscribers.
    pub active_subscribers: usize,
}

impl DispatchStats {
    fn record_published(&mut self, payload: &EventPayload) {
        self.total_published += 1;
        *self
            .by_variant
            .entry(payload.variant_name())
            .or_insert(0) += 1;
        let t = payload_topic(payload);
        *self.by_topic.entry(t).or_insert(0) += 1;
    }
}

// ---------------------------------------------------------------------------
// EventDispatcher
// ---------------------------------------------------------------------------

/// Thread-safe event dispatcher supporting publish/subscribe, topic routing,
/// priority queues, back-pressure, and event batching.
pub struct EventDispatcher {
    inner: Arc<Mutex<DispatcherInner>>,
    seq: Arc<AtomicU64>,
}

struct DispatcherInner {
    subscriptions: HashMap<SubscriberId, Subscription>,
    next_id: u64,
    config: DispatchConfig,
    stats: DispatchStats,
    /// Pending batch (used when `batching_enabled`).
    pending_batch: EventBatch,
    /// Monotonic instant of last batch flush (time-monotonic-vs-system: use
    /// Instant instead of `SystemTime` so wall-clock jumps cannot cause spurious
    /// early or late flushes).
    last_flush: Instant,
}

impl DispatcherInner {
    fn new(config: DispatchConfig) -> Self {
        Self {
            subscriptions: HashMap::new(),
            next_id: 1,
            config,
            stats: DispatchStats::default(),
            pending_batch: EventBatch::new(),
            last_flush: Instant::now(),
        }
    }

    const fn next_subscriber_id(&mut self) -> SubscriberId {
        let id = SubscriberId(self.next_id);
        self.next_id += 1;
        id
    }

    fn dispatch_payload(&mut self, payload: &EventPayload) {
        self.stats.record_published(payload);
        let mut any_delivered = false;

        if self.config.batching_enabled {
            self.pending_batch.push(payload.clone());
            // Use Instant::elapsed() — infallible and monotonic (no unwrap_or
            // needed; avoids time-monotonic-vs-system issue).
            let should_flush = self.pending_batch.len() >= self.config.batch_size
                || self.last_flush.elapsed() >= self.config.batch_flush_interval;
            if should_flush {
                let batch = std::mem::take(&mut self.pending_batch);
                self.last_flush = Instant::now();
                for p in batch.events {
                    any_delivered |= self.deliver_one(&p);
                }
            }
        } else {
            any_delivered = self.deliver_one(payload);
        }

        if !any_delivered {
            self.stats.total_dropped += 1;
        }
    }

    fn deliver_one(&mut self, payload: &EventPayload) -> bool {
        let mut any = false;
        for sub in self.subscriptions.values_mut() {
            if !sub.active {
                continue;
            }
            let result = sub.try_enqueue(payload.clone());
            if result == EnqueueResult::Delivered {
                any = true;
                self.stats.total_delivered += 1;
            }
        }
        any
    }

    fn flush_pending(&mut self) {
        if !self.config.batching_enabled {
            return;
        }
        let batch = std::mem::take(&mut self.pending_batch);
        self.last_flush = Instant::now();
        for p in batch.events {
            self.deliver_one(&p);
        }
    }
}

impl EventDispatcher {
    /// Create a new dispatcher with the given configuration.
    #[must_use]
    pub fn new(config: DispatchConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DispatcherInner::new(config))),
            seq: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Create a dispatcher with default settings.
    #[must_use]
    pub fn new_default() -> Self {
        Self::new(DispatchConfig::default())
    }

    /// Subscribe with a configuration, returning the subscriber ID.
    ///
    /// # Errors
    /// Returns `Err` when the maximum subscriber limit is reached.
    ///
    /// # Panics
    /// Panics if the dispatcher's internal mutex is poisoned.
    pub fn subscribe(
        &self,
        label: impl Into<String>,
        config: &SubscribeConfig,
    ) -> Result<SubscriberId, DispatchError> {
        let mut inner = self.inner.lock().expect("dispatcher lock");
        if inner.subscriptions.len() >= inner.config.max_subscribers {
            return Err(DispatchError::TooManySubscribers);
        }
        let id = inner.next_subscriber_id();
        let sub = Subscription::new(id, label, config);
        inner.subscriptions.insert(id, sub);
        inner.stats.active_subscribers = inner
            .subscriptions
            .values()
            .filter(|s| s.active)
            .count();
        drop(inner);
        Ok(id)
    }

    /// Subscribe to all events without topic or priority filters.
    ///
    /// # Errors
    /// Returns `Err` when the maximum subscriber limit is reached.
    ///
    /// # Panics
    /// Panics if the dispatcher's internal mutex is poisoned.
    pub fn subscribe_all(&self, label: impl Into<String>) -> Result<SubscriberId, DispatchError> {
        self.subscribe(label, &SubscribeConfig::all())
    }

    /// Add an extra filter predicate to an existing subscription.
    ///
    /// # Errors
    /// Returns `Err(DispatchError::UnknownSubscriber)` when the ID is invalid.
    ///
    /// # Panics
    /// Panics if the dispatcher's internal mutex is poisoned.
    pub fn add_filter(
        &self,
        id: SubscriberId,
        filter: AnalysisEventFilter,
    ) -> Result<(), DispatchError> {
        let mut inner = self.inner.lock().expect("dispatcher lock");
        let sub = inner
            .subscriptions
            .get_mut(&id)
            .ok_or(DispatchError::UnknownSubscriber)?;
        sub.filter = Some(filter);
        drop(inner);
        Ok(())
    }

    /// Unsubscribe by ID.  Events already in the queue are discarded.
    ///
    /// # Errors
    /// Returns `Err(DispatchError::UnknownSubscriber)` when the ID is invalid.
    ///
    /// # Panics
    /// Panics if the dispatcher's internal mutex is poisoned.
    pub fn unsubscribe(&self, id: SubscriberId) -> Result<(), DispatchError> {
        let mut inner = self.inner.lock().expect("dispatcher lock");
        inner
            .subscriptions
            .remove(&id)
            .ok_or(DispatchError::UnknownSubscriber)?;
        inner.stats.active_subscribers = inner
            .subscriptions
            .values()
            .filter(|s| s.active)
            .count();
        drop(inner);
        Ok(())
    }

    /// Pause a subscription (events are not queued while paused).
    ///
    /// # Errors
    /// Returns `Err(DispatchError::UnknownSubscriber)` when the ID is invalid.
    ///
    /// # Panics
    /// Panics if the dispatcher's internal mutex is poisoned.
    pub fn pause(&self, id: SubscriberId) -> Result<(), DispatchError> {
        let mut inner = self.inner.lock().expect("dispatcher lock");
        let sub = inner
            .subscriptions
            .get_mut(&id)
            .ok_or(DispatchError::UnknownSubscriber)?;
        // Guard: only decrement when transitioning from active → inactive.
        // Calling pause() twice on the same subscription must not underflow the
        // counter (state-machine-double-enter / state-machine-on-error).
        if sub.active {
            sub.active = false;
            inner.stats.active_subscribers =
                inner.stats.active_subscribers.saturating_sub(1);
            drop(inner);
        }
        Ok(())
    }

    /// Resume a paused subscription.
    ///
    /// # Errors
    /// Returns `Err(DispatchError::UnknownSubscriber)` when the ID is invalid.
    ///
    /// # Panics
    /// Panics if the dispatcher's internal mutex is poisoned.
    pub fn resume(&self, id: SubscriberId) -> Result<(), DispatchError> {
        let mut inner = self.inner.lock().expect("dispatcher lock");
        let sub = inner
            .subscriptions
            .get_mut(&id)
            .ok_or(DispatchError::UnknownSubscriber)?;
        if !sub.active {
            sub.active = true;
            inner.stats.active_subscribers += 1;
            drop(inner);
        }
        Ok(())
    }

    /// Publish an event to all matching subscribers.
    ///
    /// # Panics
    /// Panics if the dispatcher's internal mutex is poisoned.
    pub fn publish(&self, event: AnalysisEvent) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let payload = EventPayload::with_default_priority(event, seq);
        let mut inner = self.inner.lock().expect("dispatcher lock");
        inner.dispatch_payload(&payload);
    }

    /// Publish an event with an explicit priority.
    ///
    /// # Panics
    /// Panics if the dispatcher's internal mutex is poisoned.
    pub fn publish_with_priority(&self, event: AnalysisEvent, priority: EventPriority) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let payload = EventPayload::new(event, priority, seq);
        let mut inner = self.inner.lock().expect("dispatcher lock");
        inner.dispatch_payload(&payload);
    }

    /// Poll for pending events for `subscriber`, draining up to `max_count`.
    ///
    /// # Errors
    /// Returns `Err(DispatchError::UnknownSubscriber)` when the ID is invalid.
    ///
    /// # Panics
    /// Panics if the dispatcher's internal mutex is poisoned.
    pub fn poll(
        &self,
        id: SubscriberId,
        max_count: usize,
    ) -> Result<Vec<EventPayload>, DispatchError> {
        let mut inner = self.inner.lock().expect("dispatcher lock");
        let sub = inner
            .subscriptions
            .get_mut(&id)
            .ok_or(DispatchError::UnknownSubscriber)?;
        let result = sub.drain(max_count);
        drop(inner);
        Ok(result)
    }

    /// Flush any pending batch and deliver to all subscribers.
    ///
    /// # Panics
    /// Panics if the dispatcher's internal mutex is poisoned.
    pub fn flush(&self) {
        let mut inner = self.inner.lock().expect("dispatcher lock");
        inner.flush_pending();
    }

    /// Return a snapshot of current dispatch statistics.
    ///
    /// # Panics
    /// Panics if the dispatcher's internal mutex is poisoned.
    #[must_use]
    pub fn stats(&self) -> DispatchStats {
        self.inner.lock().expect("dispatcher lock").stats.clone()
    }

    /// Return diagnostics about a specific subscription.
    ///
    /// # Errors
    /// Returns `Err(DispatchError::UnknownSubscriber)` when the ID is invalid.
    ///
    /// # Panics
    /// Panics if the dispatcher's internal mutex is poisoned.
    pub fn subscription_info(&self, id: SubscriberId) -> Result<SubscriptionInfo, DispatchError> {
        let inner = self.inner.lock().expect("dispatcher lock");
        let sub = inner
            .subscriptions
            .get(&id)
            .ok_or(DispatchError::UnknownSubscriber)?;
        let info = SubscriptionInfo {
            id: sub.id,
            label: sub.label.clone(),
            active: sub.active,
            pending: sub.pending(),
            delivered: sub.delivered,
            dropped: sub.dropped,
            queue_utilisation: sub.queue_utilisation(),
        };
        drop(inner);
        Ok(info)
    }

    /// Return info for all subscriptions.
    ///
    /// # Panics
    /// Panics if the dispatcher's internal mutex is poisoned.
    #[must_use]
    pub fn all_subscription_info(&self) -> Vec<SubscriptionInfo> {
        let inner = self.inner.lock().expect("dispatcher lock");
        inner
            .subscriptions
            .values()
            .map(|sub| SubscriptionInfo {
                id: sub.id,
                label: sub.label.clone(),
                active: sub.active,
                pending: sub.pending(),
                delivered: sub.delivered,
                dropped: sub.dropped,
                queue_utilisation: sub.queue_utilisation(),
            })
            .collect()
    }

    /// Number of currently active subscribers.
    ///
    /// # Panics
    /// Panics if the dispatcher's internal mutex is poisoned.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.inner
            .lock()
            .expect("dispatcher lock")
            .stats
            .active_subscribers
    }
}

impl Default for EventDispatcher {
    fn default() -> Self {
        Self::new_default()
    }
}

impl fmt::Debug for EventDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock().expect("lock");
        f.debug_struct("EventDispatcher")
            .field("subscribers", &inner.subscriptions.len())
            .field("total_published", &inner.stats.total_published)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// SubscriptionInfo
// ---------------------------------------------------------------------------

/// Public snapshot of a subscription's state.
#[derive(Debug, Clone)]
pub struct SubscriptionInfo {
    pub id: SubscriberId,
    pub label: String,
    pub active: bool,
    pub pending: usize,
    pub delivered: u64,
    pub dropped: u64,
    pub queue_utilisation: f64,
}

// ---------------------------------------------------------------------------
// DispatchError
// ---------------------------------------------------------------------------

/// Errors produced by the dispatcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    /// The subscriber ID was not found.
    UnknownSubscriber,
    /// The maximum number of subscribers has been reached.
    TooManySubscribers,
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSubscriber => write!(f, "unknown subscriber"),
            Self::TooManySubscribers => write!(f, "too many subscribers"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_types::{make_function_found, AnalysisEvent};

    fn fn_event(view_id: u64) -> AnalysisEvent {
        AnalysisEvent::FunctionFound(make_function_found(view_id, 0x1000, "test"))
    }

    #[test]
    fn subscribe_and_receive_event() {
        let d = EventDispatcher::new_default();
        let id = d.subscribe_all("test").unwrap();
        d.publish(fn_event(1));
        let events = d.poll(id, 10).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn multiple_subscribers_receive_same_event() {
        let d = EventDispatcher::new_default();
        let id1 = d.subscribe_all("s1").unwrap();
        let id2 = d.subscribe_all("s2").unwrap();
        d.publish(fn_event(1));
        assert_eq!(d.poll(id1, 10).unwrap().len(), 1);
        assert_eq!(d.poll(id2, 10).unwrap().len(), 1);
    }

    #[test]
    fn unsubscribe_stops_delivery() {
        let d = EventDispatcher::new_default();
        let id = d.subscribe_all("test").unwrap();
        d.unsubscribe(id).unwrap();
        d.publish(fn_event(1));
        assert!(d.poll(id, 10).is_err());
    }

    #[test]
    fn topic_filter_receives_only_matching() {
        let d = EventDispatcher::new_default();
        let id = d.subscribe("fn_only", &SubscribeConfig::topic("function")).unwrap();
        d.publish(fn_event(1)); // topic = "function" → delivered
        d.publish(AnalysisEvent::PluginStarted(crate::event_types::PluginStartedPayload {
            plugin_id: "p".into(),
            plugin_name: "p".into(),
            version: "1".into(),
            capabilities: vec![],
            started_at: SystemTime::now(),
        })); // topic = "plugin" → filtered
        let events = d.poll(id, 10).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn pause_and_resume() {
        let d = EventDispatcher::new_default();
        let id = d.subscribe_all("test").unwrap();
        d.pause(id).unwrap();
        d.publish(fn_event(1));
        assert_eq!(d.poll(id, 10).unwrap().len(), 0);
        d.resume(id).unwrap();
        d.publish(fn_event(1));
        assert_eq!(d.poll(id, 10).unwrap().len(), 1);
    }

    #[test]
    fn priority_filter_drops_low_priority() {
        let d = EventDispatcher::new_default();
        let id = d
            .subscribe(
                "high_only",
                &SubscribeConfig::all().with_min_priority(EventPriority::High),
            )
            .unwrap();
        d.publish(fn_event(1)); // Normal priority → filtered
        d.publish_with_priority(fn_event(1), EventPriority::High);
        let events = d.poll(id, 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].priority, EventPriority::High);
    }

    #[test]
    fn back_pressure_drops_oldest_when_full() {
        let d = EventDispatcher::new_default();
        let id = d
            .subscribe("small_q", &SubscribeConfig::all().with_capacity(2))
            .unwrap();
        // Fill beyond capacity
        for i in 0..5u64 {
            d.publish(AnalysisEvent::FunctionFound(make_function_found(1, i, "f")));
        }
        let info = d.subscription_info(id).unwrap();
        assert!(info.dropped > 0);
    }

    #[test]
    fn stats_track_published_count() {
        let d = EventDispatcher::new_default();
        let _id = d.subscribe_all("s").unwrap();
        d.publish(fn_event(1));
        d.publish(fn_event(2));
        let stats = d.stats();
        assert_eq!(stats.total_published, 2);
    }

    #[test]
    fn event_queue_priority_ordering() {
        let mut q = EventQueue::new(0);
        let make = |prio: EventPriority, seq: u64| {
            let e = AnalysisEvent::FunctionFound(make_function_found(1, 0, "f"));
            EventPayload::new(e, prio, seq)
        };
        q.push(make(EventPriority::Low, 1));
        q.push(make(EventPriority::Critical, 2));
        q.push(make(EventPriority::Normal, 3));
        let first = q.pop().unwrap();
        assert_eq!(first.priority, EventPriority::Critical);
        let second = q.pop().unwrap();
        assert_eq!(second.priority, EventPriority::Normal);
    }

    #[test]
    fn event_queue_capacity_drops_lowest() {
        let mut q = EventQueue::new(2);
        let make = |prio: EventPriority, seq: u64| {
            let e = AnalysisEvent::FunctionFound(make_function_found(1, 0, "f"));
            EventPayload::new(e, prio, seq)
        };
        q.push(make(EventPriority::Low, 1));
        q.push(make(EventPriority::Low, 2));
        q.push(make(EventPriority::High, 3)); // causes eviction
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn subscriber_count_tracking() {
        let d = EventDispatcher::new_default();
        assert_eq!(d.subscriber_count(), 0);
        let id1 = d.subscribe_all("a").unwrap();
        let _id2 = d.subscribe_all("b").unwrap();
        assert_eq!(d.subscriber_count(), 2);
        d.unsubscribe(id1).unwrap();
        assert_eq!(d.subscriber_count(), 1);
    }

    #[test]
    fn subscription_info_reflects_state() {
        let d = EventDispatcher::new_default();
        let id = d.subscribe_all("tracked").unwrap();
        d.publish(fn_event(1));
        d.publish(fn_event(2));
        let info = d.subscription_info(id).unwrap();
        assert_eq!(info.pending, 2);
        assert_eq!(info.label, "tracked");
        assert!(info.active);
    }

    #[test]
    fn too_many_subscribers_error() {
        let mut cfg = DispatchConfig::default();
        cfg.max_subscribers = 2;
        let d = EventDispatcher::new(cfg);
        d.subscribe_all("a").unwrap();
        d.subscribe_all("b").unwrap();
        let result = d.subscribe_all("c");
        assert_eq!(result, Err(DispatchError::TooManySubscribers));
    }

    #[test]
    fn unknown_subscriber_poll_returns_err() {
        let d = EventDispatcher::new_default();
        let fake_id = SubscriberId(9999);
        assert_eq!(d.poll(fake_id, 10).unwrap_err(), DispatchError::UnknownSubscriber);
    }

    #[test]
    fn sequence_numbers_are_monotonic() {
        let d = EventDispatcher::new_default();
        let id = d.subscribe_all("seq_test").unwrap();
        for _ in 0..5 {
            d.publish(fn_event(1));
        }
        let events = d.poll(id, 10).unwrap();
        let seqs: Vec<u64> = events.iter().map(|e| e.sequence).collect();
        for w in seqs.windows(2) {
            assert!(w[1] > w[0]);
        }
    }
}
