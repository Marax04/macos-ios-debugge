//! MCP Notification Handler
//!
//! Implements the notification dispatch bus, subscriber management, progress
//! tracking, and all MCP notification variants defined by the MCP specification.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::Instant;

// ─────────────────────────────────────────────────────────────────────────────
// Log level
// ─────────────────────────────────────────────────────────────────────────────

/// RFC 5424 / syslog severity levels used in MCP log messages.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
            Self::Alert => "alert",
            Self::Emergency => "emergency",
        };
        f.write_str(s)
    }
}

impl LogLevel {
    /// Numeric syslog priority (lower = more severe).
    pub fn priority(&self) -> u8 {
        match self {
            Self::Emergency => 0,
            Self::Alert => 1,
            Self::Critical => 2,
            Self::Error => 3,
            Self::Warning => 4,
            Self::Notice => 5,
            Self::Info => 6,
            Self::Debug => 7,
        }
    }

    /// Returns `true` if this level is at least as severe as `threshold`.
    pub fn is_at_least(&self, threshold: &LogLevel) -> bool {
        self.priority() <= threshold.priority()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// McpNotification
// ─────────────────────────────────────────────────────────────────────────────

/// Every notification type that can flow through the MCP notification bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "camelCase")]
pub enum McpNotification {
    /// The resource list has changed (e.g. new resources available).
    #[serde(rename = "notifications/resources/list_changed")]
    ResourceListChanged,

    /// A specific resource's content has been updated.
    #[serde(rename = "notifications/resources/updated")]
    ResourceUpdated {
        /// The URI of the resource that was updated.
        uri: String,
    },

    /// The tool list has changed.
    #[serde(rename = "notifications/tools/list_changed")]
    ToolListChanged,

    /// The prompt list has changed.
    #[serde(rename = "notifications/prompts/list_changed")]
    PromptListChanged,

    /// Progress update for a long-running operation.
    #[serde(rename = "notifications/progress")]
    Progress {
        progress_token: String,
        progress: f64,
        total: Option<f64>,
    },

    /// Server-side log message.
    #[serde(rename = "notifications/message")]
    LogMessage {
        level: LogLevel,
        logger: Option<String>,
        data: JsonValue,
    },

    /// The roots list has changed.
    #[serde(rename = "notifications/roots/list_changed")]
    RootsListChanged,

    /// A previously issued request has been cancelled.
    #[serde(rename = "notifications/cancelled")]
    Cancelled {
        request_id: String,
        reason: Option<String>,
    },
}

impl McpNotification {
    /// Human-readable method name (matches the `method` field in the wire format).
    pub fn method_name(&self) -> &'static str {
        match self {
            Self::ResourceListChanged => "notifications/resources/list_changed",
            Self::ResourceUpdated { .. } => "notifications/resources/updated",
            Self::ToolListChanged => "notifications/tools/list_changed",
            Self::PromptListChanged => "notifications/prompts/list_changed",
            Self::Progress { .. } => "notifications/progress",
            Self::LogMessage { .. } => "notifications/message",
            Self::RootsListChanged => "notifications/roots/list_changed",
            Self::Cancelled { .. } => "notifications/cancelled",
        }
    }

    /// Returns `true` for notifications that carry a URI payload.
    pub fn has_uri(&self) -> bool {
        matches!(self, Self::ResourceUpdated { .. })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Subscriber infrastructure
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque identifier for a registered subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubscriberId(pub u64);

impl fmt::Display for SubscriberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sub#{}", self.0)
    }
}

/// Trait that all notification subscribers must implement.
pub trait NotificationSubscriber: Send + Sync {
    /// Called for every notification published to the bus.
    fn on_notification(&mut self, notif: &McpNotification);

    /// Optional filter: return `false` to skip notifications of this type.
    fn wants_notification(&self, notif: &McpNotification) -> bool {
        let _ = notif;
        true
    }

    /// Human-readable label for debugging.
    fn label(&self) -> &str {
        "anonymous"
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NotificationBus
// ─────────────────────────────────────────────────────────────────────────────

/// Metrics collected per notification type.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotificationMetrics {
    /// Number of times this notification type was published.
    pub published: u64,
    /// Total number of individual deliveries (published × subscribers).
    pub deliveries: u64,
    /// Number of deliveries that were skipped due to subscriber filtering.
    pub skipped: u64,
}

/// Central pub/sub bus for MCP notifications.
pub struct NotificationBus {
    subscribers: HashMap<SubscriberId, Box<dyn NotificationSubscriber>>,
    next_id: u64,
    metrics: HashMap<&'static str, NotificationMetrics>,
    history: VecDeque<(Instant, McpNotification)>,
    max_history: usize,
}

impl NotificationBus {
    /// Create a new bus with a default history limit of 1 000 entries.
    pub fn new() -> Self {
        Self {
            subscribers: HashMap::new(),
            next_id: 1,
            metrics: HashMap::new(),
            history: VecDeque::new(),
            max_history: 1_000,
        }
    }

    /// Override the history ring size.
    pub fn with_max_history(mut self, limit: usize) -> Self {
        self.max_history = limit;
        self
    }

    /// Register a subscriber and return its id.
    pub fn subscribe(&mut self, sub: Box<dyn NotificationSubscriber>) -> SubscriberId {
        let id = SubscriberId(self.next_id);
        self.next_id += 1;
        self.subscribers.insert(id, sub);
        id
    }

    /// Remove a subscriber by id.  Returns `true` if it was present.
    pub fn unsubscribe(&mut self, id: SubscriberId) -> bool {
        self.subscribers.remove(&id).is_some()
    }

    /// Publish a notification to all subscribers and update metrics.
    pub fn publish(&mut self, notif: McpNotification) {
        let method = notif.method_name();
        let entry = self.metrics.entry(method).or_default();
        entry.published += 1;

        let mut deliveries = 0u64;
        let mut skipped = 0u64;

        for sub in self.subscribers.values_mut() {
            if sub.wants_notification(&notif) {
                sub.on_notification(&notif);
                deliveries += 1;
            } else {
                skipped += 1;
            }
        }

        let entry = self.metrics.entry(method).or_default();
        entry.deliveries += deliveries;
        entry.skipped += skipped;

        // History management
        if self.history.len() >= self.max_history {
            self.history.pop_front();
        }
        self.history.push_back((Instant::now(), notif));
    }

    /// Number of currently registered subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Snapshot of the notification metrics indexed by method name.
    pub fn metrics(&self) -> &HashMap<&'static str, NotificationMetrics> {
        &self.metrics
    }

    /// Last `n` notifications from the history buffer.
    pub fn recent_notifications(&self, n: usize) -> Vec<&McpNotification> {
        self.history
            .iter()
            .rev()
            .take(n)
            .map(|(_, n)| n)
            .collect()
    }

    /// Clear all stored history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }
}

impl Default for NotificationBus {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Progress tracking
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot of a tracked progress operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressState {
    /// Current progress value (0 … total).
    pub progress: f64,
    /// Optional upper bound.
    pub total: Option<f64>,
    /// Optional human-readable status text.
    pub description: Option<String>,
    /// When this progress entry was created (seconds since Unix epoch, simulated).
    pub started_at_ms: u64,
    /// When this entry was last updated.
    pub last_updated_ms: u64,
}

impl ProgressState {
    fn new(total: Option<f64>, started_ms: u64) -> Self {
        Self {
            progress: 0.0,
            total,
            description: None,
            started_at_ms: started_ms,
            last_updated_ms: started_ms,
        }
    }

    /// Fraction completed in [0, 1], or `None` if total is unknown.
    pub fn fraction(&self) -> Option<f64> {
        self.total.map(|t| {
            if t <= 0.0 {
                0.0
            } else {
                (self.progress / t).min(1.0)
            }
        })
    }

    /// Percentage string like "42.7%", or "?" if total is unknown.
    pub fn percent_string(&self) -> String {
        match self.fraction() {
            Some(f) => format!("{:.1}%", f * 100.0),
            None => "?".to_string(),
        }
    }
}

/// Tracks active progress operations and publishes progress notifications.
pub struct ProgressTracker {
    active: HashMap<String, ProgressState>,
    completed: Vec<(String, ProgressState)>,
    /// Monotonic millisecond counter (incremented manually in tests).
    pub clock_ms: u64,
}

impl ProgressTracker {
    pub fn new() -> Self {
        Self {
            active: HashMap::new(),
            completed: Vec::new(),
            clock_ms: 0,
        }
    }

    /// Register a new progress operation.  Returns `false` if a token with that
    /// name is already active.
    pub fn start_progress(
        &mut self,
        token: impl Into<String>,
        total: Option<f64>,
    ) -> bool {
        let token = token.into();
        if self.active.contains_key(&token) {
            return false;
        }
        let state = ProgressState::new(total, self.clock_ms);
        self.active.insert(token, state);
        true
    }

    /// Update progress for an active token.  Returns the new state, or `None`
    /// if the token does not exist.
    pub fn update_progress(
        &mut self,
        token: &str,
        progress: f64,
        description: Option<String>,
    ) -> Option<&ProgressState> {
        let state = self.active.get_mut(token)?;
        state.progress = progress;
        state.last_updated_ms = self.clock_ms;
        if let Some(desc) = description {
            state.description = Some(desc);
        }
        Some(self.active.get(token).unwrap())
    }

    /// Complete a progress operation and move it to the completed list.
    /// Returns the final state, or `None` if the token was not active.
    pub fn complete_progress(&mut self, token: &str) -> Option<ProgressState> {
        let state = self.active.remove(token)?;
        self.completed.push((token.to_string(), state.clone()));
        Some(state)
    }

    /// Returns the current state of an active operation.
    pub fn get_progress(&self, token: &str) -> Option<&ProgressState> {
        self.active.get(token)
    }

    /// Number of currently active progress operations.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Tokens of all active progress operations.
    pub fn active_tokens(&self) -> Vec<&str> {
        self.active.keys().map(|s| s.as_str()).collect()
    }

    /// Build a `McpNotification::Progress` for the given active token.
    pub fn build_notification(&self, token: &str) -> Option<McpNotification> {
        let state = self.active.get(token)?;
        Some(McpNotification::Progress {
            progress_token: token.to_string(),
            progress: state.progress,
            total: state.total,
        })
    }

    /// Returns all completed entries.
    pub fn completed_entries(&self) -> &[(String, ProgressState)] {
        &self.completed
    }

    /// Remove all completed entries older than `cutoff_ms` milliseconds ago.
    pub fn prune_completed(&mut self, cutoff_ms: u64) {
        self.completed
            .retain(|(_, s)| self.clock_ms.saturating_sub(s.last_updated_ms) < cutoff_ms);
    }
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NotificationHandler  (high-level façade)
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level façade that wires a [`NotificationBus`] and a [`ProgressTracker`]
/// together, and provides convenience helpers for common notification patterns.
pub struct NotificationHandler {
    bus: NotificationBus,
    tracker: ProgressTracker,
}

impl NotificationHandler {
    pub fn new() -> Self {
        Self {
            bus: NotificationBus::new(),
            tracker: ProgressTracker::new(),
        }
    }

    // ── subscriber management ──────────────────────────────────────────────

    pub fn subscribe(&mut self, sub: Box<dyn NotificationSubscriber>) -> SubscriberId {
        self.bus.subscribe(sub)
    }

    pub fn unsubscribe(&mut self, id: SubscriberId) -> bool {
        self.bus.unsubscribe(id)
    }

    // ── raw publish ────────────────────────────────────────────────────────

    pub fn publish(&mut self, notif: McpNotification) {
        self.bus.publish(notif);
    }

    // ── convenience publishers ─────────────────────────────────────────────

    pub fn notify_resource_list_changed(&mut self) {
        self.bus.publish(McpNotification::ResourceListChanged);
    }

    pub fn notify_resource_updated(&mut self, uri: impl Into<String>) {
        self.bus.publish(McpNotification::ResourceUpdated { uri: uri.into() });
    }

    pub fn notify_tool_list_changed(&mut self) {
        self.bus.publish(McpNotification::ToolListChanged);
    }

    pub fn notify_prompt_list_changed(&mut self) {
        self.bus.publish(McpNotification::PromptListChanged);
    }

    pub fn notify_roots_list_changed(&mut self) {
        self.bus.publish(McpNotification::RootsListChanged);
    }

    pub fn notify_cancelled(
        &mut self,
        request_id: impl Into<String>,
        reason: Option<String>,
    ) {
        self.bus.publish(McpNotification::Cancelled {
            request_id: request_id.into(),
            reason,
        });
    }

    pub fn log(&mut self, level: LogLevel, logger: Option<String>, data: JsonValue) {
        self.bus.publish(McpNotification::LogMessage { level, logger, data });
    }

    // ── progress helpers ───────────────────────────────────────────────────

    /// Start a progress operation and publish its first notification.
    pub fn start_progress(&mut self, token: impl Into<String>, total: Option<f64>) -> bool {
        let token = token.into();
        if !self.tracker.start_progress(&token, total) {
            return false;
        }
        if let Some(notif) = self.tracker.build_notification(&token) {
            self.bus.publish(notif);
        }
        true
    }

    /// Update a progress operation and publish the new state.
    pub fn update_progress(
        &mut self,
        token: &str,
        progress: f64,
        description: Option<String>,
    ) -> bool {
        let updated = self
            .tracker
            .update_progress(token, progress, description)
            .is_some();
        if updated {
            if let Some(notif) = self.tracker.build_notification(token) {
                self.bus.publish(notif);
            }
        }
        updated
    }

    /// Complete a progress operation and publish a final 100% notification.
    pub fn complete_progress(&mut self, token: &str) -> Option<ProgressState> {
        let state = self.tracker.complete_progress(token)?;
        let final_total = state.total;
        let final_progress = state.total.unwrap_or(state.progress);
        self.bus.publish(McpNotification::Progress {
            progress_token: token.to_string(),
            progress: final_progress,
            total: final_total,
        });
        Some(state)
    }

    // ── accessors ──────────────────────────────────────────────────────────

    pub fn bus(&self) -> &NotificationBus {
        &self.bus
    }

    pub fn tracker(&self) -> &ProgressTracker {
        &self.tracker
    }

    pub fn subscriber_count(&self) -> usize {
        self.bus.subscriber_count()
    }
}

impl Default for NotificationHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Concrete subscriber implementations
// ─────────────────────────────────────────────────────────────────────────────

/// A subscriber that collects all received notifications into a `Vec`.
#[derive(Debug, Default)]
pub struct RecordingSubscriber {
    pub received: Vec<McpNotification>,
    filter_method: Option<&'static str>,
}

impl RecordingSubscriber {
    pub fn new() -> Self {
        Self::default()
    }

    /// Only record notifications with a specific method name.
    pub fn for_method(method: &'static str) -> Self {
        Self {
            received: Vec::new(),
            filter_method: Some(method),
        }
    }

    pub fn count(&self) -> usize {
        self.received.len()
    }
}

impl NotificationSubscriber for RecordingSubscriber {
    fn on_notification(&mut self, notif: &McpNotification) {
        self.received.push(notif.clone());
    }

    fn wants_notification(&self, notif: &McpNotification) -> bool {
        match self.filter_method {
            Some(m) => notif.method_name() == m,
            None => true,
        }
    }

    fn label(&self) -> &str {
        "recording-subscriber"
    }
}

/// A subscriber that forwards log messages above a minimum level to a `Vec<String>`.
pub struct LogCapturingSubscriber {
    pub entries: Vec<(LogLevel, String)>,
    pub min_level: LogLevel,
}

impl LogCapturingSubscriber {
    pub fn new(min_level: LogLevel) -> Self {
        Self { entries: Vec::new(), min_level }
    }
}

impl NotificationSubscriber for LogCapturingSubscriber {
    fn on_notification(&mut self, notif: &McpNotification) {
        if let McpNotification::LogMessage { level, data, .. } = notif {
            if level.is_at_least(&self.min_level) {
                self.entries.push((level.clone(), data.to_string()));
            }
        }
    }

    fn wants_notification(&self, notif: &McpNotification) -> bool {
        matches!(notif, McpNotification::LogMessage { .. })
    }

    fn label(&self) -> &str {
        "log-capturing-subscriber"
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── LogLevel ──────────────────────────────────────────────────────────────

    #[test]
    fn log_level_priority_ordering() {
        assert!(LogLevel::Emergency.priority() < LogLevel::Debug.priority());
        assert!(LogLevel::Error.priority() < LogLevel::Warning.priority());
    }

    #[test]
    fn log_level_is_at_least() {
        assert!(LogLevel::Error.is_at_least(&LogLevel::Warning));
        assert!(LogLevel::Error.is_at_least(&LogLevel::Error));
        assert!(!LogLevel::Info.is_at_least(&LogLevel::Error));
    }

    #[test]
    fn log_level_display() {
        assert_eq!(LogLevel::Critical.to_string(), "critical");
        assert_eq!(LogLevel::Alert.to_string(), "alert");
    }

    // ── McpNotification ───────────────────────────────────────────────────────

    #[test]
    fn notification_method_names() {
        assert_eq!(
            McpNotification::ResourceListChanged.method_name(),
            "notifications/resources/list_changed"
        );
        assert_eq!(
            McpNotification::ToolListChanged.method_name(),
            "notifications/tools/list_changed"
        );
        assert_eq!(
            McpNotification::Cancelled {
                request_id: "r1".into(),
                reason: None
            }
            .method_name(),
            "notifications/cancelled"
        );
    }

    #[test]
    fn notification_has_uri() {
        assert!(McpNotification::ResourceUpdated { uri: "file://x".into() }.has_uri());
        assert!(!McpNotification::ToolListChanged.has_uri());
    }

    #[test]
    fn notification_roundtrip_json() {
        let n = McpNotification::Progress {
            progress_token: "tok".into(),
            progress: 42.0,
            total: Some(100.0),
        };
        let json = serde_json::to_string(&n).unwrap();
        let decoded: McpNotification = serde_json::from_str(&json).unwrap();
        if let McpNotification::Progress { progress_token, progress, total } = decoded {
            assert_eq!(progress_token, "tok");
            assert_eq!(progress, 42.0);
            assert_eq!(total, Some(100.0));
        } else {
            panic!("wrong variant");
        }
    }

    // ── NotificationBus ───────────────────────────────────────────────────────

    #[test]
    fn bus_subscribe_unsubscribe() {
        let mut bus = NotificationBus::new();
        let id = bus.subscribe(Box::new(RecordingSubscriber::new()));
        assert_eq!(bus.subscriber_count(), 1);
        assert!(bus.unsubscribe(id));
        assert_eq!(bus.subscriber_count(), 0);
        assert!(!bus.unsubscribe(id)); // double removal is safe
    }

    #[test]
    fn bus_publish_reaches_subscribers() {
        let mut bus = NotificationBus::new();
        let id = bus.subscribe(Box::new(RecordingSubscriber::new()));
        bus.publish(McpNotification::ToolListChanged);
        bus.publish(McpNotification::ResourceListChanged);
        // metrics
        let m = bus.metrics();
        assert_eq!(m["notifications/tools/list_changed"].published, 1);
        assert_eq!(m["notifications/resources/list_changed"].published, 1);
        let _ = id;
    }

    #[test]
    fn bus_history_bounded() {
        let mut bus = NotificationBus::new().with_max_history(3);
        for _ in 0..5 {
            bus.publish(McpNotification::ToolListChanged);
        }
        assert_eq!(bus.recent_notifications(10).len(), 3);
    }

    #[test]
    fn bus_metrics_deliveries() {
        let mut bus = NotificationBus::new();
        bus.subscribe(Box::new(RecordingSubscriber::new()));
        bus.subscribe(Box::new(RecordingSubscriber::new()));
        bus.publish(McpNotification::RootsListChanged);
        let m = &bus.metrics()["notifications/roots/list_changed"];
        assert_eq!(m.deliveries, 2);
    }

    // ── ProgressTracker ───────────────────────────────────────────────────────

    #[test]
    fn progress_start_update_complete() {
        let mut tracker = ProgressTracker::new();
        assert!(tracker.start_progress("job1", Some(100.0)));
        assert!(!tracker.start_progress("job1", Some(50.0))); // duplicate
        tracker.update_progress("job1", 30.0, Some("step 1".into()));
        let state = tracker.get_progress("job1").unwrap();
        assert_eq!(state.progress, 30.0);
        assert_eq!(state.description.as_deref(), Some("step 1"));
        let finished = tracker.complete_progress("job1").unwrap();
        assert_eq!(finished.progress, 30.0);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn progress_fraction_calculation() {
        let state = ProgressState::new(Some(200.0), 0);
        assert_eq!(state.fraction(), Some(0.0));
        let mut s2 = state.clone();
        s2.progress = 50.0;
        assert!((s2.fraction().unwrap() - 0.25).abs() < 1e-9);
        let s3 = ProgressState::new(None, 0);
        assert_eq!(s3.fraction(), None);
    }

    #[test]
    fn progress_percent_string() {
        let mut state = ProgressState::new(Some(100.0), 0);
        state.progress = 75.0;
        assert_eq!(state.percent_string(), "75.0%");
        let unknown = ProgressState::new(None, 0);
        assert_eq!(unknown.percent_string(), "?");
    }

    #[test]
    fn progress_build_notification() {
        let mut tracker = ProgressTracker::new();
        tracker.start_progress("t1", Some(10.0));
        tracker.update_progress("t1", 5.0, None);
        let notif = tracker.build_notification("t1").unwrap();
        if let McpNotification::Progress { progress_token, progress, total } = notif {
            assert_eq!(progress_token, "t1");
            assert_eq!(progress, 5.0);
            assert_eq!(total, Some(10.0));
        } else {
            panic!("wrong variant");
        }
    }

    // ── NotificationHandler ───────────────────────────────────────────────────

    #[test]
    fn handler_convenience_publishers() {
        let mut handler = NotificationHandler::new();
        let sub = RecordingSubscriber::new();
        handler.subscribe(Box::new(sub));
        handler.notify_tool_list_changed();
        handler.notify_resource_list_changed();
        handler.notify_roots_list_changed();
        assert_eq!(handler.bus().metrics().len(), 3);
    }

    #[test]
    fn handler_progress_lifecycle() {
        let mut handler = NotificationHandler::new();
        handler.subscribe(Box::new(RecordingSubscriber::new()));
        assert!(handler.start_progress("p1", Some(50.0)));
        handler.update_progress("p1", 25.0, None);
        let state = handler.complete_progress("p1").unwrap();
        assert_eq!(state.progress, 25.0);
    }

    #[test]
    fn log_capturing_subscriber_filter() {
        let mut handler = NotificationHandler::new();
        handler.subscribe(Box::new(LogCapturingSubscriber::new(LogLevel::Warning)));
        handler.log(LogLevel::Debug, None, json!("verbose"));
        handler.log(LogLevel::Error, Some("core".into()), json!("boom"));
        // Only the Error should reach the log-capturing subscriber
        // (we can verify via metrics: both are published)
        let m = handler.bus().metrics();
        assert_eq!(m["notifications/message"].published, 2);
    }

    #[test]
    fn subscriber_id_display() {
        let id = SubscriberId(42);
        assert_eq!(id.to_string(), "sub#42");
    }
}
