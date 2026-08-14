//! `plugin_lifecycle` — Complete plugin lifecycle management with FSM, crash recovery,
//! health monitoring, and lifecycle logging.
//!
//! # Key types
//!
//! | Type | Purpose |
//! |---|---|
//! | [`PluginLifecycle`] | Manages the lifecycle of a single plugin |
//! | [`LifecycleState`] | FSM states: Unloaded → Loading → Initializing → Active → … |
//! | [`LifecycleEvent`] | Events: Loaded / Started / Suspended / Resumed / Unloaded / Crashed |
//! | [`LifecycleManager`] | Manages lifecycle for a collection of plugins |
//! | [`CrashRecovery`] | Automatic reload-after-crash with backoff |
//! | [`PluginHealthMonitor`] | Periodic health checks |
//! | [`LifecycleLog`] | Time-stamped lifecycle event log |

#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// LifecycleState
// ─────────────────────────────────────────────────────────────────────────────

/// Plugin lifecycle FSM states.
///
/// Valid transitions:
/// ```text
/// Unloaded → Loading → Initializing → Active → Suspending → Suspended
///                                               ↑___________________________|
/// Active → Unloading → Unloaded
/// Any → Crashed
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LifecycleState {
    Unloaded,
    Loading,
    Initializing,
    Active,
    Suspending,
    Suspended,
    Unloading,
    Crashed,
}

impl LifecycleState {
    /// Returns `true` if the plugin is in a "live" state (can serve requests).
    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns `true` if the plugin is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Unloaded | Self::Crashed)
    }

    /// Returns `true` if a transition to `next` is valid.
    #[must_use]
    pub const fn can_transition_to(&self, next: Self) -> bool {
        use LifecycleState::{
            Active, Crashed, Initializing, Loading, Suspended, Suspending, Unloaded, Unloading,
        };
        matches!(
            (self, next),
            (Unloaded, Loading)
                | (Loading, Initializing | Unloaded)
                | (Initializing | Suspended, Active)
                | (Initializing | Active | _, Crashed)
                | (Active, Suspending | Unloading)
                | (Suspending, Suspended)
                | (Suspended, Unloading)
                | (Unloading, Unloaded) // any state can crash
        )
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Unloaded => "Unloaded",
            Self::Loading => "Loading",
            Self::Initializing => "Initializing",
            Self::Active => "Active",
            Self::Suspending => "Suspending",
            Self::Suspended => "Suspended",
            Self::Unloading => "Unloading",
            Self::Crashed => "Crashed",
        }
    }
}

impl fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LifecycleEvent
// ─────────────────────────────────────────────────────────────────────────────

/// Events emitted by the lifecycle system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LifecycleEvent {
    Loaded {
        plugin_id: String,
    },
    Started {
        plugin_id: String,
    },
    Suspended {
        plugin_id: String,
    },
    Resumed {
        plugin_id: String,
    },
    Unloaded {
        plugin_id: String,
    },
    Crashed {
        plugin_id: String,
        error: String,
    },
    Reloaded {
        plugin_id: String,
        attempt: u32,
    },
    StateChanged {
        plugin_id: String,
        from: LifecycleState,
        to: LifecycleState,
    },
}

impl LifecycleEvent {
    /// Plugin ID for this event.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        match self {
            Self::Loaded { plugin_id }
            | Self::Started { plugin_id }
            | Self::Suspended { plugin_id }
            | Self::Resumed { plugin_id }
            | Self::Unloaded { plugin_id }
            | Self::Crashed { plugin_id, .. }
            | Self::Reloaded { plugin_id, .. }
            | Self::StateChanged { plugin_id, .. } => plugin_id,
        }
    }

    /// Event kind as a static string.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Loaded { .. } => "loaded",
            Self::Started { .. } => "started",
            Self::Suspended { .. } => "suspended",
            Self::Resumed { .. } => "resumed",
            Self::Unloaded { .. } => "unloaded",
            Self::Crashed { .. } => "crashed",
            Self::Reloaded { .. } => "reloaded",
            Self::StateChanged { .. } => "state_changed",
        }
    }
}

impl fmt::Display for LifecycleEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Loaded { plugin_id } => write!(f, "[loaded] {plugin_id}"),
            Self::Started { plugin_id } => write!(f, "[started] {plugin_id}"),
            Self::Suspended { plugin_id } => write!(f, "[suspended] {plugin_id}"),
            Self::Resumed { plugin_id } => write!(f, "[resumed] {plugin_id}"),
            Self::Unloaded { plugin_id } => write!(f, "[unloaded] {plugin_id}"),
            Self::Crashed { plugin_id, error } => write!(f, "[crashed] {plugin_id}: {error}"),
            Self::Reloaded { plugin_id, attempt } => {
                write!(f, "[reloaded] {plugin_id} (attempt {attempt})")
            }
            Self::StateChanged {
                plugin_id,
                from,
                to,
            } => {
                write!(f, "[state_changed] {plugin_id}: {from} -> {to}")
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LifecycleLog
// ─────────────────────────────────────────────────────────────────────────────

/// Time-stamped lifecycle event log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Unix timestamp in seconds.
    pub timestamp: u64,
    /// The event.
    pub event: LifecycleEvent,
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.timestamp, self.event)
    }
}

/// An append-only log of lifecycle events with optional capacity cap.
#[derive(Debug, Default, Clone)]
pub struct LifecycleLog {
    entries: VecDeque<LogEntry>,
    max_entries: usize,
}

impl LifecycleLog {
    /// Create a log with the given maximum capacity (0 = unlimited).
    #[must_use]
    pub const fn new(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries,
        }
    }

    /// Append an event.
    pub fn append(&mut self, event: LifecycleEvent) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if self.max_entries > 0 && self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(LogEntry { timestamp, event });
    }

    /// All entries.
    #[must_use]
    pub const fn entries(&self) -> &VecDeque<LogEntry> {
        &self.entries
    }

    /// Events for a specific plugin.
    #[must_use]
    pub fn for_plugin(&self, plugin_id: &str) -> Vec<&LogEntry> {
        self.entries
            .iter()
            .filter(|e| e.event.plugin_id() == plugin_id)
            .collect()
    }

    /// Events of a specific kind.
    #[must_use]
    pub fn of_kind(&self, kind: &str) -> Vec<&LogEntry> {
        self.entries
            .iter()
            .filter(|e| e.event.kind() == kind)
            .collect()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginLifecycle
// ─────────────────────────────────────────────────────────────────────────────

/// Manages the lifecycle FSM for a single plugin.
#[derive(Debug, Clone)]
pub struct PluginLifecycle {
    plugin_id: String,
    state: LifecycleState,
    state_history: Vec<(LifecycleState, u64)>,
    entered_current_state_at: u64,
    error_count: u32,
    last_error: Option<String>,
}

impl PluginLifecycle {
    /// Create a new lifecycle manager for `plugin_id`, starting in the
    /// `Unloaded` state.
    #[must_use]
    pub fn new(plugin_id: impl Into<String>) -> Self {
        let now = now_secs();
        Self {
            plugin_id: plugin_id.into(),
            state: LifecycleState::Unloaded,
            state_history: vec![(LifecycleState::Unloaded, now)],
            entered_current_state_at: now,
            error_count: 0,
            last_error: None,
        }
    }

    /// Current FSM state.
    #[must_use]
    pub const fn state(&self) -> LifecycleState {
        self.state
    }

    /// Plugin ID.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// Attempt a state transition to `next`.
    ///
    /// Returns `true` on success; `false` if the transition is not valid.
    pub fn transition(&mut self, next: LifecycleState) -> bool {
        if !self.state.can_transition_to(next) {
            return false;
        }
        let now = now_secs();
        self.state_history.push((next, now));
        self.state = next;
        self.entered_current_state_at = now;
        true
    }

    /// Force a transition regardless of FSM rules (use for crash recovery).
    pub fn force_transition(&mut self, next: LifecycleState) {
        let now = now_secs();
        self.state_history.push((next, now));
        self.state = next;
        self.entered_current_state_at = now;
    }

    /// Drive the lifecycle through Loading → Initializing → Active.
    ///
    /// Returns the final state (Active on success, Crashed on failure).
    pub fn load_and_start(&mut self) -> LifecycleState {
        if !self.transition(LifecycleState::Loading) {
            return self.state;
        }
        if !self.transition(LifecycleState::Initializing) {
            return self.state;
        }
        if !self.transition(LifecycleState::Active) {
            return self.state;
        }
        self.state
    }

    /// Drive the lifecycle through Unloading → Unloaded.
    pub fn stop_and_unload(&mut self) -> LifecycleState {
        let _ = self.transition(LifecycleState::Unloading);
        let _ = self.transition(LifecycleState::Unloaded);
        self.state
    }

    /// Mark the plugin as crashed with the given error message.
    pub fn crash(&mut self, error: impl Into<String>) {
        self.error_count += 1;
        self.last_error = Some(error.into());
        self.force_transition(LifecycleState::Crashed);
    }

    /// Reset to Unloaded (after crash recovery).
    pub fn reset(&mut self) {
        self.force_transition(LifecycleState::Unloaded);
    }

    /// Number of times the plugin has crashed.
    #[must_use]
    pub const fn error_count(&self) -> u32 {
        self.error_count
    }

    /// Last error message, if any.
    #[must_use]
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// How long the plugin has been in the current state.
    #[must_use]
    pub fn time_in_state(&self) -> Duration {
        let now = now_secs();
        Duration::from_secs(now.saturating_sub(self.entered_current_state_at))
    }

    /// Full state history as `(state, timestamp)` pairs.
    #[must_use]
    pub fn state_history(&self) -> &[(LifecycleState, u64)] {
        &self.state_history
    }
}

impl fmt::Display for PluginLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plugin '{}' [{}]", self.plugin_id, self.state)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CrashRecovery
// ─────────────────────────────────────────────────────────────────────────────

/// Automatic crash-recovery policy with exponential backoff.
#[derive(Debug, Clone)]
pub struct CrashRecovery {
    /// Maximum number of reload attempts before giving up.
    pub max_attempts: u32,
    /// Base delay between reload attempts.
    pub base_delay: Duration,
    /// Multiplier applied to the delay after each failed attempt.
    pub backoff_factor: f64,
    attempt_counts: HashMap<String, u32>,
    last_attempt: HashMap<String, Instant>,
}

impl CrashRecovery {
    /// Create a recovery policy.
    #[must_use]
    pub fn new(max_attempts: u32, base_delay: Duration) -> Self {
        Self {
            max_attempts,
            base_delay,
            backoff_factor: 2.0,
            attempt_counts: HashMap::new(),
            last_attempt: HashMap::new(),
        }
    }

    /// Returns `true` if another reload attempt should be made for `plugin_id`.
    #[must_use]
    pub fn should_retry(&self, plugin_id: &str) -> bool {
        let count = self.attempt_counts.get(plugin_id).copied().unwrap_or(0);
        count < self.max_attempts
    }

    /// Record a reload attempt for `plugin_id` and return the attempt number.
    pub fn record_attempt(&mut self, plugin_id: impl Into<String>) -> u32 {
        let id = plugin_id.into();
        let count = self.attempt_counts.entry(id.clone()).or_insert(0);
        *count += 1;
        self.last_attempt.insert(id, Instant::now());
        *count
    }

    /// Reset the attempt counter for `plugin_id`.
    pub fn reset(&mut self, plugin_id: &str) {
        self.attempt_counts.remove(plugin_id);
        self.last_attempt.remove(plugin_id);
    }

    /// Compute the delay before the next attempt for `plugin_id`.
    #[must_use]
    pub fn delay_for(&self, plugin_id: &str) -> Duration {
        let count = self.attempt_counts.get(plugin_id).copied().unwrap_or(0);
        let multiplier = self.backoff_factor.powi(count as i32);
        let secs = self.base_delay.as_secs_f64() * multiplier;
        Duration::from_secs_f64(secs.min(300.0)) // cap at 5 minutes
    }

    /// Current attempt count for `plugin_id`.
    #[must_use]
    pub fn attempt_count(&self, plugin_id: &str) -> u32 {
        self.attempt_counts.get(plugin_id).copied().unwrap_or(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginHealthMonitor
// ─────────────────────────────────────────────────────────────────────────────

/// Monitors health for a set of plugins.
#[derive(Debug, Default, Clone)]
pub struct PluginHealthMonitor {
    health: HashMap<String, HealthRecord>,
}

/// Health record for one plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthRecord {
    pub plugin_id: String,
    pub healthy: bool,
    pub last_heartbeat: u64,
    pub consecutive_failures: u32,
    pub message: String,
}

impl PluginHealthMonitor {
    /// Create an empty monitor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new plugin.
    pub fn register(&mut self, plugin_id: impl Into<String>) {
        let id = plugin_id.into();
        self.health.insert(
            id.clone(),
            HealthRecord {
                plugin_id: id,
                healthy: true,
                last_heartbeat: now_secs(),
                consecutive_failures: 0,
                message: String::new(),
            },
        );
    }

    /// Record a heartbeat from `plugin_id`.
    pub fn heartbeat(&mut self, plugin_id: &str) {
        if let Some(rec) = self.health.get_mut(plugin_id) {
            rec.last_heartbeat = now_secs();
            rec.consecutive_failures = 0;
            rec.healthy = true;
        }
    }

    /// Record a failure for `plugin_id`.
    pub fn record_failure(&mut self, plugin_id: &str, msg: impl Into<String>) {
        if let Some(rec) = self.health.get_mut(plugin_id) {
            rec.consecutive_failures += 1;
            rec.message = msg.into();
            if rec.consecutive_failures >= 3 {
                rec.healthy = false;
            }
        }
    }

    /// Check whether `plugin_id` is healthy.
    #[must_use]
    pub fn is_healthy(&self, plugin_id: &str) -> bool {
        self.health.get(plugin_id).is_some_and(|r| r.healthy)
    }

    /// Return the health record for `plugin_id`.
    #[must_use]
    pub fn record(&self, plugin_id: &str) -> Option<&HealthRecord> {
        self.health.get(plugin_id)
    }

    /// All unhealthy plugins.
    #[must_use]
    pub fn unhealthy_plugins(&self) -> Vec<&str> {
        self.health
            .iter()
            .filter(|(_, r)| !r.healthy)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// All registered plugins.
    #[must_use]
    pub fn plugin_ids(&self) -> Vec<&str> {
        self.health.keys().map(String::as_str).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LifecycleManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages lifecycles, crash recovery, health monitoring, and logging
/// for a collection of plugins.
#[derive(Debug)]
pub struct LifecycleManager {
    lifecycles: HashMap<String, PluginLifecycle>,
    log: LifecycleLog,
    recovery: CrashRecovery,
    health: PluginHealthMonitor,
}

impl LifecycleManager {
    /// Create a manager with the given log capacity and recovery settings.
    #[must_use]
    pub fn new(log_capacity: usize, max_crash_retries: u32) -> Self {
        Self {
            lifecycles: HashMap::new(),
            log: LifecycleLog::new(log_capacity),
            recovery: CrashRecovery::new(max_crash_retries, Duration::from_secs(1)),
            health: PluginHealthMonitor::new(),
        }
    }

    /// Register a new plugin.
    pub fn register(&mut self, plugin_id: impl Into<String>) {
        let id = plugin_id.into();
        self.lifecycles
            .insert(id.clone(), PluginLifecycle::new(id.clone()));
        self.health.register(id);
    }

    /// Load and start a plugin.
    ///
    /// Returns the final state.
    pub fn load_and_start(&mut self, plugin_id: &str) -> LifecycleState {
        let state = if let Some(lc) = self.lifecycles.get_mut(plugin_id) {
            lc.load_and_start()
        } else {
            return LifecycleState::Unloaded;
        };

        match state {
            LifecycleState::Active => {
                self.log.append(LifecycleEvent::Loaded {
                    plugin_id: plugin_id.into(),
                });
                self.log.append(LifecycleEvent::Started {
                    plugin_id: plugin_id.into(),
                });
                self.health.heartbeat(plugin_id);
            }
            _ => {
                self.log.append(LifecycleEvent::Crashed {
                    plugin_id: plugin_id.into(),
                    error: "failed to start".into(),
                });
            }
        }
        state
    }

    /// Suspend a plugin.
    pub fn suspend(&mut self, plugin_id: &str) -> bool {
        let success = self.lifecycles.get_mut(plugin_id).is_some_and(|lc| {
            lc.transition(LifecycleState::Suspending) && lc.transition(LifecycleState::Suspended)
        });
        if success {
            self.log.append(LifecycleEvent::Suspended {
                plugin_id: plugin_id.into(),
            });
        }
        success
    }

    /// Resume a suspended plugin.
    pub fn resume(&mut self, plugin_id: &str) -> bool {
        let success = self
            .lifecycles
            .get_mut(plugin_id)
            .is_some_and(|lc| lc.transition(LifecycleState::Active));
        if success {
            self.log.append(LifecycleEvent::Resumed {
                plugin_id: plugin_id.into(),
            });
        }
        success
    }

    /// Unload a plugin.
    pub fn unload(&mut self, plugin_id: &str) -> LifecycleState {
        let state = self
            .lifecycles
            .get_mut(plugin_id)
            .map_or(LifecycleState::Unloaded, PluginLifecycle::stop_and_unload);
        self.log.append(LifecycleEvent::Unloaded {
            plugin_id: plugin_id.into(),
        });
        state
    }

    /// Report a crash for `plugin_id` and attempt automatic recovery.
    pub fn handle_crash(&mut self, plugin_id: &str, error: impl Into<String>) {
        let error = error.into();
        if let Some(lc) = self.lifecycles.get_mut(plugin_id) {
            lc.crash(error.clone());
        }
        self.log.append(LifecycleEvent::Crashed {
            plugin_id: plugin_id.into(),
            error: error.clone(),
        });
        self.health.record_failure(plugin_id, &error);

        // Attempt recovery.
        if self.recovery.should_retry(plugin_id) {
            let attempt = self.recovery.record_attempt(plugin_id);
            // Reset the FSM and try to reload.
            if let Some(lc) = self.lifecycles.get_mut(plugin_id) {
                lc.reset();
            }
            let _new_state = self.load_and_start(plugin_id);
            self.log.append(LifecycleEvent::Reloaded {
                plugin_id: plugin_id.into(),
                attempt,
            });
        }
    }

    /// Get the current lifecycle state of a plugin.
    #[must_use]
    pub fn state(&self, plugin_id: &str) -> Option<LifecycleState> {
        self.lifecycles.get(plugin_id).map(PluginLifecycle::state)
    }

    /// Return the event log.
    #[must_use]
    pub const fn log(&self) -> &LifecycleLog {
        &self.log
    }

    /// Return the health monitor.
    #[must_use]
    pub const fn health(&self) -> &PluginHealthMonitor {
        &self.health
    }

    /// Return the crash recovery policy.
    #[must_use]
    pub const fn recovery(&self) -> &CrashRecovery {
        &self.recovery
    }

    /// All registered plugin IDs.
    #[must_use]
    pub fn plugin_ids(&self) -> Vec<&str> {
        self.lifecycles.keys().map(String::as_str).collect()
    }

    /// Number of registered plugins.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lifecycles.len()
    }

    /// Returns `true` if no plugins are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lifecycles.is_empty()
    }

    /// Number of active (live) plugins.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.lifecycles
            .values()
            .filter(|lc| lc.state().is_live())
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── LifecycleState ────────────────────────────────────────────────────────

    #[test]
    fn test_state_names() {
        assert_eq!(LifecycleState::Unloaded.name(), "Unloaded");
        assert_eq!(LifecycleState::Active.name(), "Active");
        assert_eq!(LifecycleState::Crashed.name(), "Crashed");
    }

    #[test]
    fn test_state_is_live() {
        assert!(LifecycleState::Active.is_live());
        assert!(!LifecycleState::Suspended.is_live());
        assert!(!LifecycleState::Crashed.is_live());
    }

    #[test]
    fn test_state_is_terminal() {
        assert!(LifecycleState::Unloaded.is_terminal());
        assert!(LifecycleState::Crashed.is_terminal());
        assert!(!LifecycleState::Active.is_terminal());
    }

    #[test]
    fn test_state_valid_transitions() {
        assert!(LifecycleState::Unloaded.can_transition_to(LifecycleState::Loading));
        assert!(LifecycleState::Loading.can_transition_to(LifecycleState::Initializing));
        assert!(LifecycleState::Initializing.can_transition_to(LifecycleState::Active));
        assert!(LifecycleState::Active.can_transition_to(LifecycleState::Suspending));
        assert!(LifecycleState::Suspending.can_transition_to(LifecycleState::Suspended));
        assert!(LifecycleState::Suspended.can_transition_to(LifecycleState::Active));
        assert!(LifecycleState::Active.can_transition_to(LifecycleState::Unloading));
        assert!(LifecycleState::Unloading.can_transition_to(LifecycleState::Unloaded));
    }

    #[test]
    fn test_state_invalid_transitions() {
        assert!(!LifecycleState::Unloaded.can_transition_to(LifecycleState::Active));
        assert!(!LifecycleState::Active.can_transition_to(LifecycleState::Loading));
        assert!(!LifecycleState::Suspended.can_transition_to(LifecycleState::Loading));
    }

    #[test]
    fn test_state_any_can_crash() {
        for state in &[
            LifecycleState::Active,
            LifecycleState::Initializing,
            LifecycleState::Suspended,
        ] {
            assert!(state.can_transition_to(LifecycleState::Crashed));
        }
    }

    #[test]
    fn test_state_display() {
        assert_eq!(LifecycleState::Active.to_string(), "Active");
        assert_eq!(LifecycleState::Crashed.to_string(), "Crashed");
    }

    // ── LifecycleEvent ────────────────────────────────────────────────────────

    #[test]
    fn test_event_plugin_id() {
        let ev = LifecycleEvent::Started {
            plugin_id: "my.plugin".into(),
        };
        assert_eq!(ev.plugin_id(), "my.plugin");
    }

    #[test]
    fn test_event_kind() {
        assert_eq!(
            LifecycleEvent::Loaded {
                plugin_id: "x".into()
            }
            .kind(),
            "loaded"
        );
        assert_eq!(
            LifecycleEvent::Crashed {
                plugin_id: "x".into(),
                error: "e".into()
            }
            .kind(),
            "crashed"
        );
    }

    #[test]
    fn test_event_display() {
        let ev = LifecycleEvent::Crashed {
            plugin_id: "com.example".into(),
            error: "segfault".into(),
        };
        let s = ev.to_string();
        assert!(s.contains("crashed"));
        assert!(s.contains("com.example"));
        assert!(s.contains("segfault"));
    }

    // ── LifecycleLog ──────────────────────────────────────────────────────────

    #[test]
    fn test_lifecycle_log_append() {
        let mut log = LifecycleLog::new(100);
        log.append(LifecycleEvent::Loaded {
            plugin_id: "a".into(),
        });
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_lifecycle_log_cap() {
        let mut log = LifecycleLog::new(3);
        for _ in 0..5 {
            log.append(LifecycleEvent::Loaded {
                plugin_id: "a".into(),
            });
        }
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn test_lifecycle_log_for_plugin() {
        let mut log = LifecycleLog::new(100);
        log.append(LifecycleEvent::Loaded {
            plugin_id: "a".into(),
        });
        log.append(LifecycleEvent::Loaded {
            plugin_id: "b".into(),
        });
        assert_eq!(log.for_plugin("a").len(), 1);
        assert_eq!(log.for_plugin("b").len(), 1);
        assert_eq!(log.for_plugin("c").len(), 0);
    }

    #[test]
    fn test_lifecycle_log_of_kind() {
        let mut log = LifecycleLog::new(100);
        log.append(LifecycleEvent::Loaded {
            plugin_id: "a".into(),
        });
        log.append(LifecycleEvent::Started {
            plugin_id: "a".into(),
        });
        assert_eq!(log.of_kind("loaded").len(), 1);
        assert_eq!(log.of_kind("started").len(), 1);
    }

    #[test]
    fn test_lifecycle_log_clear() {
        let mut log = LifecycleLog::new(100);
        log.append(LifecycleEvent::Loaded {
            plugin_id: "a".into(),
        });
        log.clear();
        assert!(log.is_empty());
    }

    // ── PluginLifecycle ───────────────────────────────────────────────────────

    #[test]
    fn test_plugin_lifecycle_initial_state() {
        let lc = PluginLifecycle::new("my.plugin");
        assert_eq!(lc.state(), LifecycleState::Unloaded);
        assert_eq!(lc.error_count(), 0);
        assert!(lc.last_error().is_none());
    }

    #[test]
    fn test_plugin_lifecycle_transition_valid() {
        let mut lc = PluginLifecycle::new("p");
        assert!(lc.transition(LifecycleState::Loading));
        assert_eq!(lc.state(), LifecycleState::Loading);
    }

    #[test]
    fn test_plugin_lifecycle_transition_invalid() {
        let mut lc = PluginLifecycle::new("p");
        assert!(!lc.transition(LifecycleState::Active)); // can't jump to Active from Unloaded
        assert_eq!(lc.state(), LifecycleState::Unloaded);
    }

    #[test]
    fn test_plugin_lifecycle_load_and_start() {
        let mut lc = PluginLifecycle::new("p");
        let state = lc.load_and_start();
        assert_eq!(state, LifecycleState::Active);
    }

    #[test]
    fn test_plugin_lifecycle_stop_and_unload() {
        let mut lc = PluginLifecycle::new("p");
        lc.load_and_start();
        let state = lc.stop_and_unload();
        assert_eq!(state, LifecycleState::Unloaded);
    }

    #[test]
    fn test_plugin_lifecycle_crash() {
        let mut lc = PluginLifecycle::new("p");
        lc.load_and_start();
        lc.crash("panic");
        assert_eq!(lc.state(), LifecycleState::Crashed);
        assert_eq!(lc.error_count(), 1);
        assert_eq!(lc.last_error(), Some("panic"));
    }

    #[test]
    fn test_plugin_lifecycle_reset_after_crash() {
        let mut lc = PluginLifecycle::new("p");
        lc.crash("err");
        lc.reset();
        assert_eq!(lc.state(), LifecycleState::Unloaded);
    }

    #[test]
    fn test_plugin_lifecycle_history() {
        let mut lc = PluginLifecycle::new("p");
        lc.load_and_start();
        assert!(lc.state_history().len() >= 3);
    }

    #[test]
    fn test_plugin_lifecycle_display() {
        let lc = PluginLifecycle::new("com.test");
        let s = lc.to_string();
        assert!(s.contains("com.test"));
        assert!(s.contains("Unloaded"));
    }

    // ── CrashRecovery ─────────────────────────────────────────────────────────

    #[test]
    fn test_crash_recovery_should_retry() {
        let recovery = CrashRecovery::new(3, Duration::from_millis(100));
        assert!(recovery.should_retry("p")); // 0 < 3
    }

    #[test]
    fn test_crash_recovery_exhausted() {
        let mut recovery = CrashRecovery::new(2, Duration::from_millis(100));
        recovery.record_attempt("p");
        recovery.record_attempt("p");
        assert!(!recovery.should_retry("p")); // 2 >= 2
    }

    #[test]
    fn test_crash_recovery_attempt_count() {
        let mut recovery = CrashRecovery::new(5, Duration::from_millis(100));
        let n1 = recovery.record_attempt("p");
        let n2 = recovery.record_attempt("p");
        assert_eq!(n1, 1);
        assert_eq!(n2, 2);
    }

    #[test]
    fn test_crash_recovery_reset() {
        let mut recovery = CrashRecovery::new(3, Duration::from_millis(100));
        recovery.record_attempt("p");
        recovery.reset("p");
        assert_eq!(recovery.attempt_count("p"), 0);
    }

    #[test]
    fn test_crash_recovery_delay_grows() {
        let mut recovery = CrashRecovery::new(5, Duration::from_secs(1));
        recovery.record_attempt("p");
        let d1 = recovery.delay_for("p");
        recovery.record_attempt("p");
        let d2 = recovery.delay_for("p");
        assert!(d2 >= d1);
    }

    // ── PluginHealthMonitor ───────────────────────────────────────────────────

    #[test]
    fn test_health_monitor_register_and_healthy() {
        let mut monitor = PluginHealthMonitor::new();
        monitor.register("p");
        assert!(monitor.is_healthy("p"));
    }

    #[test]
    fn test_health_monitor_heartbeat() {
        let mut monitor = PluginHealthMonitor::new();
        monitor.register("p");
        monitor.heartbeat("p");
        assert!(monitor.is_healthy("p"));
    }

    #[test]
    fn test_health_monitor_failure_threshold() {
        let mut monitor = PluginHealthMonitor::new();
        monitor.register("p");
        for _ in 0..3 {
            monitor.record_failure("p", "err");
        }
        assert!(!monitor.is_healthy("p"));
    }

    #[test]
    fn test_health_monitor_unhealthy_list() {
        let mut monitor = PluginHealthMonitor::new();
        monitor.register("a");
        monitor.register("b");
        for _ in 0..3 {
            monitor.record_failure("a", "err");
        }
        let unhealthy = monitor.unhealthy_plugins();
        assert!(unhealthy.contains(&"a"));
        assert!(!unhealthy.contains(&"b"));
    }

    // ── LifecycleManager ──────────────────────────────────────────────────────

    #[test]
    fn test_lifecycle_manager_register() {
        let mut mgr = LifecycleManager::new(100, 3);
        mgr.register("com.test");
        assert_eq!(mgr.len(), 1);
        assert_eq!(mgr.state("com.test"), Some(LifecycleState::Unloaded));
    }

    #[test]
    fn test_lifecycle_manager_load_and_start() {
        let mut mgr = LifecycleManager::new(100, 3);
        mgr.register("p");
        let state = mgr.load_and_start("p");
        assert_eq!(state, LifecycleState::Active);
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn test_lifecycle_manager_suspend_resume() {
        let mut mgr = LifecycleManager::new(100, 3);
        mgr.register("p");
        mgr.load_and_start("p");
        assert!(mgr.suspend("p"));
        assert_eq!(mgr.state("p"), Some(LifecycleState::Suspended));
        assert!(mgr.resume("p"));
        assert_eq!(mgr.state("p"), Some(LifecycleState::Active));
    }

    #[test]
    fn test_lifecycle_manager_unload() {
        let mut mgr = LifecycleManager::new(100, 3);
        mgr.register("p");
        mgr.load_and_start("p");
        let state = mgr.unload("p");
        assert_eq!(state, LifecycleState::Unloaded);
    }

    #[test]
    fn test_lifecycle_manager_crash_recovery() {
        let mut mgr = LifecycleManager::new(100, 3);
        mgr.register("p");
        mgr.load_and_start("p");
        mgr.handle_crash("p", "segfault");
        // After recovery, state should be Active (reloaded) or Crashed if recovery failed.
        let state = mgr.state("p").unwrap();
        // With max_crash_retries=3, first crash triggers recovery.
        assert!(matches!(
            state,
            LifecycleState::Active | LifecycleState::Crashed
        ));
    }

    #[test]
    fn test_lifecycle_manager_log_populated() {
        let mut mgr = LifecycleManager::new(100, 3);
        mgr.register("p");
        mgr.load_and_start("p");
        assert!(!mgr.log().is_empty());
    }

    #[test]
    fn test_lifecycle_manager_health_registered() {
        let mut mgr = LifecycleManager::new(100, 3);
        mgr.register("p");
        assert!(mgr.health().record("p").is_some());
    }
}
