//! Event filter and subscription system for the `rustre-events` bus.
//!
//! Provides:
//! * [`EventPredicate`] — composable filter predicates.
//! * [`EventSubscription`] — typed subscription with predicate, priority, and throttle.
//! * [`EventThrottle`] — rate limiter per event type (max N events/sec).
//! * [`EventBatcher`] — collect high-frequency events into batches.
//! * [`FilteredReceiver`] — wraps a bus receiver and applies filters transparently.
//! * Priority levels for ensuring critical events (e.g. `BreakpointHit`) bypass throttles.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ── Priority ──────────────────────────────────────────────────────────────────

/// Priority level for an event subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[derive(Default)]
pub enum EventPriority {
    /// Low-priority background events (e.g. progress updates).
    Low = 0,
    /// Normal operational events (default).
    #[default]
    Normal = 1,
    /// High-priority events that should be processed before others.
    High = 2,
    /// Critical events (e.g. `BreakpointHit`) — bypass throttles.
    Critical = 3,
}


// ── Event kind discriminant ───────────────────────────────────────────────────

/// Lightweight discriminant for categorising events without owning the full payload.
/// This mirrors the variants of `CoreEvent` and `SpecCoreEvent`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    // Binary lifecycle
    BinaryOpened,
    BinaryClosed,
    // Function events
    FunctionDiscovered,
    FunctionRenamed,
    FunctionDeleted,
    // Type events
    TypeDefined,
    TypeDeleted,
    // Analysis events
    AnalysisProgress,
    AnalysisComplete,
    // Debugger events
    BreakpointHit,
    StepComplete,
    ProcessLaunched,
    ProcessExited,
    // Threat intel / sandbox
    SandboxAlert,
    ThreatIntelMatch,
    // Patch events
    PatchApplied,
    PatchReverted,
    // Custom / plugin
    Custom(String),
    /// Matches any event kind.
    Wildcard,
}

impl EventKind {
    /// Default priority for this event kind.
    #[must_use] 
    pub const fn default_priority(&self) -> EventPriority {
        match self {
            Self::BreakpointHit => EventPriority::Critical,
            Self::SandboxAlert | Self::ThreatIntelMatch | Self::PatchApplied | Self::PatchReverted => EventPriority::High,
            Self::AnalysisProgress => EventPriority::Low,
            _ => EventPriority::Normal,
        }
    }
}

// ── Event predicate ───────────────────────────────────────────────────────────

/// A composable, cloneable predicate evaluated against a generic event envelope.
///
/// Because the actual `CoreEvent` type lives in the bus crate, predicates operate
/// on a lightweight [`EventEnvelope`] that carries the kind and optional metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventPredicate {
    /// Accept only events of a specific kind.
    Kind(EventKind),
    /// Accept only events whose `source_module` field matches.
    SourceModule(String),
    /// Accept only events with a specific tag.
    HasTag(String),
    /// Accept events where a named numeric field exceeds a threshold.
    FieldAbove { field: String, threshold: f64 },
    /// Accept events where a named string field matches a value.
    FieldEquals { field: String, value: String },
    /// Logical AND of two predicates.
    And(Box<Self>, Box<Self>),
    /// Logical OR of two predicates.
    Or(Box<Self>, Box<Self>),
    /// Logical NOT.
    Not(Box<Self>),
    /// Accept all events.
    Any,
}

impl EventPredicate {
    #[must_use] 
    pub fn and(self, other: Self) -> Self {
        Self::And(Box::new(self), Box::new(other))
    }

    #[must_use] 
    pub fn or(self, other: Self) -> Self {
        Self::Or(Box::new(self), Box::new(other))
    }

    #[must_use] 
    pub fn negate(self) -> Self {
        Self::Not(Box::new(self))
    }

    /// Evaluate the predicate against an event envelope.
    #[must_use] 
    pub fn matches(&self, env: &EventEnvelope) -> bool {
        match self {
            Self::Any => true,
            Self::Kind(k) => k == &EventKind::Wildcard || &env.kind == k,
            Self::SourceModule(m) => env.source_module.as_deref() == Some(m.as_str()),
            Self::HasTag(t) => env.tags.contains(t),
            Self::FieldAbove { field, threshold } => env
                .numeric_fields
                .get(field.as_str())
                .is_some_and(|v| v > threshold),
            Self::FieldEquals { field, value } => env
                .string_fields
                .get(field.as_str())
                .is_some_and(|v| v == value),
            Self::And(a, b) => a.matches(env) && b.matches(env),
            Self::Or(a, b) => a.matches(env) || b.matches(env),
            Self::Not(inner) => !inner.matches(env),
        }
    }
}

// ── Event envelope ────────────────────────────────────────────────────────────

/// A thin envelope that wraps any platform event for filtering purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Discriminant kind.
    pub kind: EventKind,
    /// Module or subsystem that emitted the event.
    pub source_module: Option<String>,
    /// Free-form tags attached to the event.
    pub tags: Vec<String>,
    /// Named numeric fields (e.g. `progress: 0.75`, `address: 0x401000`).
    pub numeric_fields: HashMap<String, f64>,
    /// Named string fields (e.g. `function_name: "sub_401000"`, `section: ".text"`).
    pub string_fields: HashMap<String, String>,
    /// UNIX timestamp (milliseconds).
    pub timestamp_ms: u64,
    /// Sequence number for ordering.
    pub seq: u64,
}

impl EventEnvelope {
    #[must_use] 
    pub fn new(kind: EventKind) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now_ms = u64::try_from(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis())
            .unwrap_or(u64::MAX);
        Self {
            kind,
            source_module: None,
            tags: vec![],
            numeric_fields: HashMap::new(),
            string_fields: HashMap::new(),
            timestamp_ms: now_ms,
            seq: 0,
        }
    }

    #[must_use]
    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.source_module = Some(module.into());
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    #[must_use]
    pub fn with_numeric(mut self, key: impl Into<String>, value: f64) -> Self {
        self.numeric_fields.insert(key.into(), value);
        self
    }

    #[must_use]
    pub fn with_string(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.string_fields.insert(key.into(), value.into());
        self
    }
}

// ── Throttle ──────────────────────────────────────────────────────────────────

/// Token-bucket rate limiter for a specific event kind.
#[derive(Debug)]
pub struct EventThrottle {
    /// Max tokens (burst capacity).
    capacity: u32,
    /// Current token count.
    tokens: u32,
    /// Tokens added per second.
    refill_rate: u32,
    last_refill: Instant,
}

impl EventThrottle {
    #[must_use] 
    pub fn new(max_per_sec: u32) -> Self {
        Self {
            capacity: max_per_sec,
            tokens: max_per_sec,
            refill_rate: max_per_sec,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns `true` if the event should be passed through.
    pub fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        let new_tokens = u32::try_from((elapsed * f64::from(self.refill_rate)).max(0.0).min(f64::from(u32::MAX)) as u64).unwrap_or(u32::MAX);
        if new_tokens > 0 {
            self.tokens = (self.tokens + new_tokens).min(self.capacity);
            self.last_refill = Instant::now();
        }
    }

    /// Reset the throttle to full capacity.
    pub fn reset(&mut self) {
        self.tokens = self.capacity;
        self.last_refill = Instant::now();
    }
}

// ── Throttle registry ─────────────────────────────────────────────────────────

/// Per-kind throttle registry.
pub struct ThrottleRegistry {
    throttles: HashMap<String, EventThrottle>,
    default_max_per_sec: u32,
}

impl ThrottleRegistry {
    #[must_use] 
    pub fn new(default_max_per_sec: u32) -> Self {
        Self {
            throttles: HashMap::new(),
            default_max_per_sec,
        }
    }

    pub fn set_limit(&mut self, kind_key: impl Into<String>, max_per_sec: u32) {
        self.throttles
            .insert(kind_key.into(), EventThrottle::new(max_per_sec));
    }

    /// Returns `true` if the event for `kind_key` should pass through.
    pub fn allow(&mut self, kind_key: &str, priority: EventPriority) -> bool {
        // Critical events always pass
        if priority == EventPriority::Critical {
            return true;
        }
        let default_max = self.default_max_per_sec;
        self.throttles
            .entry(kind_key.to_string())
            .or_insert_with(|| EventThrottle::new(default_max))
            .try_consume()
    }
}

// ── Event batcher ─────────────────────────────────────────────────────────────

/// Accumulates high-frequency events into batches.
pub struct EventBatcher {
    /// Max batch size before flush.
    max_batch_size: usize,
    /// Max time before flush.
    max_batch_duration: Duration,
    buffer: VecDeque<EventEnvelope>,
    batch_start: Instant,
}

impl EventBatcher {
    #[must_use] 
    pub fn new(max_size: usize, max_duration: Duration) -> Self {
        Self {
            max_batch_size: max_size,
            max_batch_duration: max_duration,
            buffer: VecDeque::new(),
            batch_start: Instant::now(),
        }
    }

    /// Push an event into the batcher.
    pub fn push(&mut self, env: EventEnvelope) {
        self.buffer.push_back(env);
    }

    /// Check if the batch should be flushed.
    #[must_use] 
    pub fn should_flush(&self) -> bool {
        self.buffer.len() >= self.max_batch_size
            || (!self.buffer.is_empty()
                && self.batch_start.elapsed() >= self.max_batch_duration)
    }

    /// Drain and return the current batch.
    pub fn flush(&mut self) -> Vec<EventEnvelope> {
        let batch: Vec<EventEnvelope> = self.buffer.drain(..).collect();
        self.batch_start = Instant::now();
        batch
    }

    #[must_use] 
    pub fn pending_count(&self) -> usize {
        self.buffer.len()
    }
}

// ── Subscription ──────────────────────────────────────────────────────────────

/// A named subscription with predicate, priority, and optional throttle config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionConfig {
    pub name: String,
    pub predicate: EventPredicate,
    pub priority: EventPriority,
    /// Max events per second to pass through (None = unlimited).
    pub max_events_per_sec: Option<u32>,
    /// If true, collect into batches instead of forwarding individually.
    pub batching: bool,
    /// Max batch size when `batching = true`.
    pub max_batch_size: usize,
    /// Max ms before a batch is flushed even if not full.
    pub max_batch_ms: u64,
}

impl SubscriptionConfig {
    pub fn new(name: impl Into<String>, predicate: EventPredicate) -> Self {
        Self {
            name: name.into(),
            predicate,
            priority: EventPriority::Normal,
            max_events_per_sec: None,
            batching: false,
            max_batch_size: 100,
            max_batch_ms: 100,
        }
    }

    #[must_use] 
    pub const fn with_priority(mut self, p: EventPriority) -> Self {
        self.priority = p;
        self
    }

    #[must_use] 
    pub const fn with_throttle(mut self, max_per_sec: u32) -> Self {
        self.max_events_per_sec = Some(max_per_sec);
        self
    }

    #[must_use] 
    pub const fn with_batching(mut self, max_size: usize, max_ms: u64) -> Self {
        self.batching = true;
        self.max_batch_size = max_size;
        self.max_batch_ms = max_ms;
        self
    }
}

// ── Filtered receiver ─────────────────────────────────────────────────────────

/// Stateful receiver that applies a [`SubscriptionConfig`] to a stream of [`EventEnvelope`]s.
pub struct FilteredReceiver {
    config: SubscriptionConfig,
    throttle: Option<EventThrottle>,
    batcher: Option<EventBatcher>,
    accepted: u64,
    rejected_filter: u64,
    rejected_throttle: u64,
}

impl FilteredReceiver {
    pub fn new(config: SubscriptionConfig) -> Self {
        let throttle = config
            .max_events_per_sec
            .map(EventThrottle::new);
        let batcher = if config.batching {
            Some(EventBatcher::new(
                config.max_batch_size,
                Duration::from_millis(config.max_batch_ms),
            ))
        } else {
            None
        };
        Self {
            config,
            throttle,
            batcher,
            accepted: 0,
            rejected_filter: 0,
            rejected_throttle: 0,
        }
    }

    /// Process an incoming event. Returns events that should be forwarded.
    /// When batching is enabled, returns an empty vec until flush threshold is reached.
    pub fn process(&mut self, env: EventEnvelope) -> Vec<EventEnvelope> {
        // Step 1: predicate filter
        if !self.config.predicate.matches(&env) {
            self.rejected_filter += 1;
            return vec![];
        }

        // Step 2: throttle (Critical bypasses)
        if let Some(ref mut throttle) = self.throttle
            && self.config.priority != EventPriority::Critical && !throttle.try_consume() {
                self.rejected_throttle += 1;
                return vec![];
            }

        self.accepted += 1;

        // Step 3: batching or direct forward
        if let Some(ref mut batcher) = self.batcher {
            batcher.push(env);
            if batcher.should_flush() {
                return batcher.flush();
            }
            return vec![];
        }

        vec![env]
    }

    /// Force-flush any pending batch.
    pub fn flush_batch(&mut self) -> Vec<EventEnvelope> {
        self.batcher.as_mut().map(EventBatcher::flush).unwrap_or_default()
    }

    /// Stats for this subscription.
    #[must_use] 
    pub fn stats(&self) -> SubscriptionStats {
        SubscriptionStats {
            name: self.config.name.clone(),
            accepted: self.accepted,
            rejected_filter: self.rejected_filter,
            rejected_throttle: self.rejected_throttle,
            pending_batch: self.batcher.as_ref().map_or(0, EventBatcher::pending_count),
        }
    }
}

/// Runtime statistics for a filtered receiver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionStats {
    pub name: String,
    pub accepted: u64,
    pub rejected_filter: u64,
    pub rejected_throttle: u64,
    pub pending_batch: usize,
}

// ── Subscription manager ──────────────────────────────────────────────────────

/// Manages multiple named subscriptions and routes envelopes to them.
pub struct SubscriptionManager {
    receivers: Vec<FilteredReceiver>,
}

impl SubscriptionManager {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            receivers: Vec::new(),
        }
    }

    pub fn subscribe(&mut self, config: SubscriptionConfig) -> usize {
        let idx = self.receivers.len();
        self.receivers.push(FilteredReceiver::new(config));
        idx
    }

    /// Dispatch an event to all subscriptions.
    /// Returns a map `subscription_index → Vec<events forwarded>`.
    pub fn dispatch(&mut self, env: &EventEnvelope) -> HashMap<usize, Vec<EventEnvelope>> {
        let mut out = HashMap::new();
        for (i, recv) in self.receivers.iter_mut().enumerate() {
            let forwarded = recv.process(env.clone());
            if !forwarded.is_empty() {
                out.insert(i, forwarded);
            }
        }
        out
    }

    pub fn flush_all(&mut self) -> HashMap<usize, Vec<EventEnvelope>> {
        let mut out = HashMap::new();
        for (i, recv) in self.receivers.iter_mut().enumerate() {
            let flushed = recv.flush_batch();
            if !flushed.is_empty() {
                out.insert(i, flushed);
            }
        }
        out
    }

    #[must_use] 
    pub fn stats(&self) -> Vec<SubscriptionStats> {
        self.receivers.iter().map(FilteredReceiver::stats).collect()
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_env(kind: EventKind) -> EventEnvelope {
        EventEnvelope::new(kind)
            .with_module("test_module")
            .with_tag("test")
    }

    #[test]
    fn predicate_kind_match() {
        let pred = EventPredicate::Kind(EventKind::FunctionDiscovered);
        let env = make_env(EventKind::FunctionDiscovered);
        assert!(pred.matches(&env));
    }

    #[test]
    fn predicate_kind_no_match() {
        let pred = EventPredicate::Kind(EventKind::BinaryOpened);
        let env = make_env(EventKind::FunctionDiscovered);
        assert!(!pred.matches(&env));
    }

    #[test]
    fn predicate_and() {
        let pred = EventPredicate::Kind(EventKind::FunctionDiscovered)
            .and(EventPredicate::SourceModule("test_module".into()));
        let env = make_env(EventKind::FunctionDiscovered).with_module("test_module");
        assert!(pred.matches(&env));
    }

    #[test]
    fn predicate_not() {
        let pred = EventPredicate::Not(Box::new(EventPredicate::Kind(EventKind::BinaryOpened)));
        let env = make_env(EventKind::FunctionDiscovered);
        assert!(pred.matches(&env));
    }

    #[test]
    fn throttle_limits() {
        let mut t = EventThrottle::new(3);
        assert!(t.try_consume());
        assert!(t.try_consume());
        assert!(t.try_consume());
        assert!(!t.try_consume(), "4th consume should fail");
    }

    #[test]
    fn filtered_receiver_basic() {
        let cfg = SubscriptionConfig::new(
            "func_events",
            EventPredicate::Kind(EventKind::FunctionDiscovered),
        );
        let mut recv = FilteredReceiver::new(cfg);

        let env1 = make_env(EventKind::FunctionDiscovered);
        let env2 = make_env(EventKind::BinaryOpened);

        let out1 = recv.process(env1);
        let out2 = recv.process(env2);

        assert_eq!(out1.len(), 1, "FunctionDiscovered should pass");
        assert_eq!(out2.len(), 0, "BinaryOpened should be filtered");
    }

    #[test]
    fn batcher_flushes_at_max_size() {
        let cfg = SubscriptionConfig::new(
            "batch_test",
            EventPredicate::Any,
        )
        .with_batching(3, 10000);
        let mut recv = FilteredReceiver::new(cfg);

        let mut forwarded = vec![];
        for _ in 0..3 {
            forwarded.extend(recv.process(make_env(EventKind::AnalysisProgress)));
        }
        assert_eq!(forwarded.len(), 3, "batch should flush at size 3");
    }

    #[test]
    fn subscription_manager_routes() {
        let mut mgr = SubscriptionManager::new();
        let _sub0 = mgr.subscribe(SubscriptionConfig::new(
            "func",
            EventPredicate::Kind(EventKind::FunctionDiscovered),
        ));
        let _sub1 = mgr.subscribe(SubscriptionConfig::new(
            "binary",
            EventPredicate::Kind(EventKind::BinaryOpened),
        ));

        let dispatch = mgr.dispatch(&make_env(EventKind::FunctionDiscovered));
        assert!(dispatch.contains_key(&0));
        assert!(!dispatch.contains_key(&1));
    }

    #[test]
    fn critical_priority_bypasses_throttle() {
        let cfg = SubscriptionConfig::new("bp", EventPredicate::Any)
            .with_priority(EventPriority::Critical)
            .with_throttle(0); // 0 tokens/sec — would always throttle non-critical
        let mut recv = FilteredReceiver::new(cfg);
        let env = EventEnvelope::new(EventKind::BreakpointHit);
        let out = recv.process(env);
        assert_eq!(out.len(), 1, "critical should bypass throttle");
    }
}
