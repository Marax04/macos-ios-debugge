// plugin_event_bus_v2.rs — Typed event bus for plugin-to-plugin communication

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use serde::{Deserialize, Serialize};

// ─── Event trait ─────────────────────────────────────────────────────────────

/// Marker trait for all events that can flow through the bus.
pub trait BusEvent: Any + Send + Sync + 'static {
    /// Short human-readable name for logging.
    fn event_name(&self) -> &'static str;
}

// ─── Plugin event variants ────────────────────────────────────────────────────

/// Concrete events emitted by the plugin system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginEvent {
    /// A plugin was loaded and activated.
    PluginLoaded { plugin_id: String },
    /// A plugin was unloaded.
    PluginUnloaded { plugin_id: String },
    /// A plugin emitted a log message.
    PluginLog {
        plugin_id: String,
        level: LogLevel,
        message: String,
    },
    /// A plugin reports an error.
    PluginError {
        plugin_id: String,
        error: String,
    },
    /// A plugin raised a user-facing notification.
    Notification {
        plugin_id: String,
        title: String,
        body: String,
        severity: NotificationSeverity,
    },
    /// A plugin requests a capability from another plugin.
    CapabilityRequest {
        requester_id: String,
        capability: String,
    },
    /// Analysis progress update.
    AnalysisProgress {
        plugin_id: String,
        task: String,
        percent: f32,
    },
    /// Custom JSON-payload event for plugin-defined messages.
    Custom {
        plugin_id: String,
        tag: String,
        payload: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationSeverity {
    Info,
    Warning,
    Critical,
}

impl BusEvent for PluginEvent {
    fn event_name(&self) -> &'static str {
        match self {
            PluginEvent::PluginLoaded { .. } => "PluginLoaded",
            PluginEvent::PluginUnloaded { .. } => "PluginUnloaded",
            PluginEvent::PluginLog { .. } => "PluginLog",
            PluginEvent::PluginError { .. } => "PluginError",
            PluginEvent::Notification { .. } => "Notification",
            PluginEvent::CapabilityRequest { .. } => "CapabilityRequest",
            PluginEvent::AnalysisProgress { .. } => "AnalysisProgress",
            PluginEvent::Custom { .. } => "Custom",
        }
    }
}

// ─── Subscription handle ──────────────────────────────────────────────────────

/// Identifies a single subscription. Drop or pass to `unsubscribe` to remove it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriptionId(u64);

/// A subscription handle; unsubscribes when dropped if wired to a bus.
pub struct EventSubscription {
    pub id: SubscriptionId,
    pub plugin_id: String,
    pub event_type: &'static str,
    /// Bus reference for auto-unsubscribe on drop.
    bus: Option<Arc<EventBusInner>>,
}

impl Drop for EventSubscription {
    fn drop(&mut self) {
        if let Some(bus) = self.bus.take() {
            bus.remove_subscription(self.id);
        }
    }
}

// ─── Subscriber callback ──────────────────────────────────────────────────────

type HandlerFn = Box<dyn Fn(&PluginEvent) + Send + Sync>;

struct SubscriberEntry {
    id: SubscriptionId,
    plugin_id: String,
    handler: HandlerFn,
    /// If Some, only fire for this specific tag (Custom events).
    tag_filter: Option<String>,
    /// Count of times this handler has been invoked.
    invoke_count: u64,
}

// ─── Bus inner ────────────────────────────────────────────────────────────────

struct EventBusInner {
    /// Per-event-name subscriber lists.
    subscribers: RwLock<HashMap<String, Vec<Arc<Mutex<SubscriberEntry>>>>>,
    /// Global (catch-all) subscribers.
    global_subscribers: RwLock<Vec<Arc<Mutex<SubscriberEntry>>>>,
    /// Event history (most-recent-first, capped).
    history: Mutex<Vec<PluginEvent>>,
    history_limit: usize,
    sub_counter: Mutex<u64>,
}

impl EventBusInner {
    fn next_id(&self) -> SubscriptionId {
        let mut c = self.sub_counter.lock().unwrap();
        let id = SubscriptionId(*c);
        *c += 1;
        id
    }

    fn remove_subscription(&self, id: SubscriptionId) {
        {
            let mut subs = self.subscribers.write().unwrap();
            for list in subs.values_mut() {
                list.retain(|entry| entry.lock().unwrap().id != id);
            }
        }
        {
            let mut global = self.global_subscribers.write().unwrap();
            global.retain(|entry| entry.lock().unwrap().id != id);
        }
    }

    fn publish(&self, event: &PluginEvent) {
        // Store in history.
        {
            let mut hist = self.history.lock().unwrap();
            hist.push(event.clone());
            if hist.len() > self.history_limit {
                hist.remove(0);
            }
        }

        // Dispatch to per-event subscribers.
        let event_name = event.event_name().to_string();
        let targeted: Vec<Arc<Mutex<SubscriberEntry>>> = {
            let subs = self.subscribers.read().unwrap();
            subs.get(&event_name).cloned().unwrap_or_default()
        };
        for entry_arc in targeted {
            let mut entry = entry_arc.lock().unwrap();
            // Apply tag filter for Custom events.
            if let Some(ref tag) = entry.tag_filter {
                if let PluginEvent::Custom { tag: event_tag, .. } = event {
                    if event_tag != tag {
                        continue;
                    }
                }
            }
            (entry.handler)(event);
            entry.invoke_count += 1;
        }

        // Dispatch to global subscribers.
        let globals: Vec<Arc<Mutex<SubscriberEntry>>> = {
            self.global_subscribers.read().unwrap().clone()
        };
        for entry_arc in globals {
            let mut entry = entry_arc.lock().unwrap();
            (entry.handler)(event);
            entry.invoke_count += 1;
        }
    }
}

// ─── Public EventBus ─────────────────────────────────────────────────────────

/// Thread-safe synchronous event bus for plugin communication.
pub struct EventBus {
    inner: Arc<EventBusInner>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::with_history_limit(1024)
    }

    pub fn with_history_limit(limit: usize) -> Self {
        Self {
            inner: Arc::new(EventBusInner {
                subscribers: RwLock::new(HashMap::new()),
                global_subscribers: RwLock::new(vec![]),
                history: Mutex::new(Vec::new()),
                history_limit: limit,
                sub_counter: Mutex::new(0),
            }),
        }
    }

    /// Subscribe to a specific named event type.
    pub fn subscribe<F>(
        &self,
        plugin_id: impl Into<String>,
        event_type: &'static str,
        handler: F,
    ) -> EventSubscription
    where
        F: Fn(&PluginEvent) + Send + Sync + 'static,
    {
        let id = self.inner.next_id();
        let entry = Arc::new(Mutex::new(SubscriberEntry {
            id,
            plugin_id: plugin_id.into(),
            handler: Box::new(handler),
            tag_filter: None,
            invoke_count: 0,
        }));
        self.inner
            .subscribers
            .write()
            .unwrap()
            .entry(event_type.to_string())
            .or_default()
            .push(Arc::clone(&entry));

        EventSubscription {
            id,
            plugin_id: entry.lock().unwrap().plugin_id.clone(),
            event_type,
            bus: Some(Arc::clone(&self.inner)),
        }
    }

    /// Subscribe to Custom events with a specific tag.
    pub fn subscribe_custom<F>(
        &self,
        plugin_id: impl Into<String>,
        tag: impl Into<String>,
        handler: F,
    ) -> EventSubscription
    where
        F: Fn(&PluginEvent) + Send + Sync + 'static,
    {
        let id = self.inner.next_id();
        let tag_str = tag.into();
        let entry = Arc::new(Mutex::new(SubscriberEntry {
            id,
            plugin_id: plugin_id.into(),
            handler: Box::new(handler),
            tag_filter: Some(tag_str),
            invoke_count: 0,
        }));
        self.inner
            .subscribers
            .write()
            .unwrap()
            .entry("Custom".to_string())
            .or_default()
            .push(Arc::clone(&entry));

        EventSubscription {
            id,
            plugin_id: entry.lock().unwrap().plugin_id.clone(),
            event_type: "Custom",
            bus: Some(Arc::clone(&self.inner)),
        }
    }

    /// Subscribe to ALL events.
    pub fn subscribe_all<F>(&self, plugin_id: impl Into<String>, handler: F) -> EventSubscription
    where
        F: Fn(&PluginEvent) + Send + Sync + 'static,
    {
        let id = self.inner.next_id();
        let entry = Arc::new(Mutex::new(SubscriberEntry {
            id,
            plugin_id: plugin_id.into(),
            handler: Box::new(handler),
            tag_filter: None,
            invoke_count: 0,
        }));
        self.inner
            .global_subscribers
            .write()
            .unwrap()
            .push(Arc::clone(&entry));

        EventSubscription {
            id,
            plugin_id: entry.lock().unwrap().plugin_id.clone(),
            event_type: "*",
            bus: Some(Arc::clone(&self.inner)),
        }
    }

    /// Manually unsubscribe without relying on Drop.
    pub fn unsubscribe(&self, id: SubscriptionId) {
        self.inner.remove_subscription(id);
    }

    /// Publish an event synchronously.
    pub fn publish(&self, event: PluginEvent) {
        self.inner.publish(&event);
    }

    /// Number of active subscriptions for a given event type.
    pub fn subscriber_count(&self, event_type: &str) -> usize {
        self.inner
            .subscribers
            .read()
            .unwrap()
            .get(event_type)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Total global subscriber count.
    pub fn global_subscriber_count(&self) -> usize {
        self.inner.global_subscribers.read().unwrap().len()
    }

    /// Recent event history.
    pub fn history(&self) -> Vec<PluginEvent> {
        self.inner.history.lock().unwrap().clone()
    }

    /// Clear the event history.
    pub fn clear_history(&self) {
        self.inner.history.lock().unwrap().clear();
    }

    /// Events from a specific plugin.
    pub fn history_for(&self, plugin_id: &str) -> Vec<PluginEvent> {
        self.inner
            .history
            .lock()
            .unwrap()
            .iter()
            .filter(|e| event_plugin_id(e).map(|id| id == plugin_id).unwrap_or(false))
            .cloned()
            .collect()
    }

    /// Clone the inner bus reference (lightweight).
    pub fn handle(&self) -> EventBusHandle {
        EventBusHandle {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// A lightweight cloneable handle to the bus (no subscription API).
#[derive(Clone)]
pub struct EventBusHandle {
    inner: Arc<EventBusInner>,
}

impl EventBusHandle {
    pub fn publish(&self, event: PluginEvent) {
        self.inner.publish(&event);
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn event_plugin_id(e: &PluginEvent) -> Option<&str> {
    match e {
        PluginEvent::PluginLoaded { plugin_id }
        | PluginEvent::PluginUnloaded { plugin_id }
        | PluginEvent::PluginLog { plugin_id, .. }
        | PluginEvent::PluginError { plugin_id, .. }
        | PluginEvent::Notification { plugin_id, .. }
        | PluginEvent::CapabilityRequest { requester_id: plugin_id, .. }
        | PluginEvent::AnalysisProgress { plugin_id, .. }
        | PluginEvent::Custom { plugin_id, .. } => Some(plugin_id.as_str()),
    }
}

// ─── Bus statistics ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusStats {
    pub history_len: usize,
    pub global_subscriber_count: usize,
    pub event_type_counts: HashMap<String, usize>,
}

impl BusStats {
    pub fn from(bus: &EventBus) -> Self {
        let hist = bus.history();
        let mut type_counts: HashMap<String, usize> = HashMap::new();
        for e in &hist {
            *type_counts.entry(e.event_name().to_string()).or_insert(0) += 1;
        }
        Self {
            history_len: hist.len(),
            global_subscriber_count: bus.global_subscriber_count(),
            event_type_counts: type_counts,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_publish_received_by_subscriber() {
        let bus = EventBus::new();
        let received: Arc<Mutex<Vec<PluginEvent>>> = Arc::new(Mutex::new(vec![]));
        let rx = Arc::clone(&received);
        let _sub = bus.subscribe("test_plugin", "PluginLoaded", move |e| {
            rx.lock().unwrap().push(e.clone());
        });
        bus.publish(PluginEvent::PluginLoaded { plugin_id: "foo".to_string() });
        assert_eq!(received.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_subscriber_not_called_for_other_event() {
        let bus = EventBus::new();
        let count = Arc::new(Mutex::new(0u32));
        let cnt = Arc::clone(&count);
        let _sub = bus.subscribe("p", "PluginLoaded", move |_| {
            *cnt.lock().unwrap() += 1;
        });
        bus.publish(PluginEvent::PluginUnloaded { plugin_id: "bar".to_string() });
        assert_eq!(*count.lock().unwrap(), 0);
    }

    #[test]
    fn test_global_subscriber_receives_all() {
        let bus = EventBus::new();
        let count = Arc::new(Mutex::new(0u32));
        let cnt = Arc::clone(&count);
        let _sub = bus.subscribe_all("p", move |_| {
            *cnt.lock().unwrap() += 1;
        });
        bus.publish(PluginEvent::PluginLoaded { plugin_id: "a".to_string() });
        bus.publish(PluginEvent::PluginUnloaded { plugin_id: "b".to_string() });
        assert_eq!(*count.lock().unwrap(), 2);
    }

    #[test]
    fn test_unsubscribe_stops_delivery() {
        let bus = EventBus::new();
        let count = Arc::new(Mutex::new(0u32));
        let cnt = Arc::clone(&count);
        let sub = bus.subscribe("p", "PluginLoaded", move |_| {
            *cnt.lock().unwrap() += 1;
        });
        bus.publish(PluginEvent::PluginLoaded { plugin_id: "a".to_string() });
        bus.unsubscribe(sub.id);
        bus.publish(PluginEvent::PluginLoaded { plugin_id: "b".to_string() });
        assert_eq!(*count.lock().unwrap(), 1);
    }

    #[test]
    fn test_drop_subscription_unsubscribes() {
        let bus = EventBus::new();
        let count = Arc::new(Mutex::new(0u32));
        let cnt = Arc::clone(&count);
        {
            let _sub = bus.subscribe("p", "PluginLoaded", move |_| {
                *cnt.lock().unwrap() += 1;
            });
            bus.publish(PluginEvent::PluginLoaded { plugin_id: "a".to_string() });
        }
        // _sub dropped here.
        bus.publish(PluginEvent::PluginLoaded { plugin_id: "b".to_string() });
        assert_eq!(*count.lock().unwrap(), 1);
    }

    #[test]
    fn test_history_records_events() {
        let bus = EventBus::new();
        bus.publish(PluginEvent::PluginLoaded { plugin_id: "x".to_string() });
        assert_eq!(bus.history().len(), 1);
    }

    #[test]
    fn test_history_limit_respected() {
        let bus = EventBus::with_history_limit(3);
        for i in 0..5 {
            bus.publish(PluginEvent::PluginLoaded { plugin_id: format!("p{i}") });
        }
        assert_eq!(bus.history().len(), 3);
    }

    #[test]
    fn test_history_for_plugin() {
        let bus = EventBus::new();
        bus.publish(PluginEvent::PluginLoaded { plugin_id: "foo".to_string() });
        bus.publish(PluginEvent::PluginLoaded { plugin_id: "bar".to_string() });
        let foo_hist = bus.history_for("foo");
        assert_eq!(foo_hist.len(), 1);
    }

    #[test]
    fn test_custom_tag_filter() {
        let bus = EventBus::new();
        let count = Arc::new(Mutex::new(0u32));
        let cnt = Arc::clone(&count);
        let _sub = bus.subscribe_custom("p", "my_tag", move |_| {
            *cnt.lock().unwrap() += 1;
        });
        bus.publish(PluginEvent::Custom {
            plugin_id: "p".to_string(),
            tag: "my_tag".to_string(),
            payload: "{}".to_string(),
        });
        bus.publish(PluginEvent::Custom {
            plugin_id: "p".to_string(),
            tag: "other_tag".to_string(),
            payload: "{}".to_string(),
        });
        assert_eq!(*count.lock().unwrap(), 1);
    }

    #[test]
    fn test_subscriber_count() {
        let bus = EventBus::new();
        let _s1 = bus.subscribe("p1", "PluginLoaded", |_| {});
        let _s2 = bus.subscribe("p2", "PluginLoaded", |_| {});
        assert_eq!(bus.subscriber_count("PluginLoaded"), 2);
    }

    #[test]
    fn test_bus_stats() {
        let bus = EventBus::new();
        bus.publish(PluginEvent::PluginLoaded { plugin_id: "a".to_string() });
        bus.publish(PluginEvent::PluginLoaded { plugin_id: "b".to_string() });
        let stats = BusStats::from(&bus);
        assert_eq!(stats.history_len, 2);
        assert_eq!(*stats.event_type_counts.get("PluginLoaded").unwrap(), 2);
    }

    #[test]
    fn test_bus_handle_publish() {
        let bus = EventBus::new();
        let handle = bus.handle();
        handle.publish(PluginEvent::PluginLoaded { plugin_id: "via_handle".to_string() });
        assert_eq!(bus.history().len(), 1);
    }

    #[test]
    fn test_clear_history() {
        let bus = EventBus::new();
        bus.publish(PluginEvent::PluginLoaded { plugin_id: "x".to_string() });
        bus.clear_history();
        assert!(bus.history().is_empty());
    }
}
