//! `hot_reload_engine` — Filesystem-driven plugin hot reload.
//!
//! Provides [`HotReloadEngine`] which coordinates [`PluginWatcher`] (file
//! system events), [`ReloadTrigger`], [`GracefulReload`], [`StateTransfer`],
//! [`ReloadReport`], and [`PluginDependencyGraph`].

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────────────────
// File system events (abstracted)
// ─────────────────────────────────────────────────────────────────────────────

/// A filesystem event relevant to plugin hot-reload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FsEvent {
    Created(PathBuf),
    Modified(PathBuf),
    Removed(PathBuf),
    Renamed { from: PathBuf, to: PathBuf },
}

impl FsEvent {
    /// Return the affected path.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Created(p) | Self::Modified(p) | Self::Removed(p) => p,
            Self::Renamed { to, .. } => to,
        }
    }

    /// Return true if this event involves a dynamic library.
    #[must_use]
    pub fn is_dylib(&self) -> bool {
        let p = self.path();
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        matches!(ext, "so" | "dylib" | "dll")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginWatcher — filesystem watching
// ─────────────────────────────────────────────────────────────────────────────

/// Watches a set of directories for plugin file changes.
#[derive(Debug)]
pub struct PluginWatcher {
    watched_dirs: Vec<PathBuf>,
    pending_events: VecDeque<FsEvent>,
    debounce_ms: u64,
    last_event_time: HashMap<PathBuf, u64>,
}

impl PluginWatcher {
    /// Create a new plugin watcher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            watched_dirs: Vec::new(),
            pending_events: VecDeque::new(),
            debounce_ms: 300,
            last_event_time: HashMap::new(),
        }
    }

    /// Add a directory to watch.
    pub fn watch(&mut self, dir: impl Into<PathBuf>) {
        let d: PathBuf = dir.into();
        if !self.watched_dirs.contains(&d) {
            self.watched_dirs.push(d);
        }
    }

    /// Remove a watched directory.
    pub fn unwatch(&mut self, dir: &Path) {
        self.watched_dirs.retain(|d| d != dir);
    }

    /// Inject a synthetic event (used in tests / cross-platform stubs).
    pub fn inject(&mut self, event: FsEvent) {
        let path = event.path().to_path_buf();
        let now = now_ms();
        let last = self.last_event_time.get(&path).copied().unwrap_or(0);
        if now.saturating_sub(last) >= self.debounce_ms {
            self.pending_events.push_back(event);
            self.last_event_time.insert(path, now);
        }
    }

    /// Drain pending events.
    #[must_use]
    pub fn drain(&mut self) -> Vec<FsEvent> {
        self.pending_events.drain(..).collect()
    }

    /// Return the number of pending events.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending_events.len()
    }

    /// Return the watched directory list.
    #[must_use]
    pub fn watched_dirs(&self) -> &[PathBuf] {
        &self.watched_dirs
    }

    /// Set the debounce window.
    pub const fn set_debounce_ms(&mut self, ms: u64) {
        self.debounce_ms = ms;
    }

    /// Set the debounce window from a [`Duration`].
    pub const fn set_debounce(&mut self, dur: Duration) {
        let ms = dur.as_millis();
        self.debounce_ms = if ms > u64::MAX as u128 { u64::MAX } else { ms as u64 };
    }

    /// Current debounce window as a [`Duration`].
    #[must_use]
    pub const fn debounce(&self) -> Duration {
        Duration::from_millis(self.debounce_ms)
    }
}

impl Default for PluginWatcher {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// ReloadTrigger — decides when to reload
// ─────────────────────────────────────────────────────────────────────────────

/// Source of a reload trigger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriggerSource {
    FileChange(PathBuf),
    Manual,
    Scheduled,
    ApiRequest,
    DependencyChanged(String),
}

/// A pending reload request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadTrigger {
    pub plugin_id: String,
    pub source: TriggerSource,
    pub priority: u8,
    pub timestamp: u64,
}

impl ReloadTrigger {
    /// Create a new reload trigger.
    #[must_use]
    pub fn new(plugin_id: impl Into<String>, source: TriggerSource) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            source,
            priority: 50,
            timestamp: now_ms(),
        }
    }

    /// Create a high-priority manual trigger.
    #[must_use]
    pub fn manual(plugin_id: impl Into<String>) -> Self {
        Self {
            priority: 100,
            ..Self::new(plugin_id, TriggerSource::Manual)
        }
    }

    /// Create a file-change trigger.
    #[must_use]
    pub fn file_change(plugin_id: impl Into<String>, path: PathBuf) -> Self {
        Self::new(plugin_id, TriggerSource::FileChange(path))
    }

    /// Return true if this is a high-priority trigger.
    #[must_use]
    pub const fn is_high_priority(&self) -> bool {
        self.priority >= 80
    }
}

/// Queue of pending reload triggers.
#[derive(Debug, Default)]
pub struct TriggerQueue {
    pending: VecDeque<ReloadTrigger>,
}

impl TriggerQueue {
    /// Create a new trigger queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueue a trigger.
    pub fn enqueue(&mut self, trigger: ReloadTrigger) {
        self.pending.push_back(trigger);
    }

    /// Dequeue the highest-priority trigger.
    #[must_use]
    pub fn dequeue(&mut self) -> Option<ReloadTrigger> {
        if self.pending.is_empty() {
            return None;
        }
        // Find the highest-priority item.
        let idx = self
            .pending
            .iter()
            .enumerate()
            .max_by_key(|(_, t)| t.priority)
            .map(|(i, _)| i)?;
        self.pending.remove(idx)
    }

    /// Return pending count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Return whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateTransfer — plugin state serialization
// ─────────────────────────────────────────────────────────────────────────────

/// Saved plugin state for hot-reload continuity.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PluginState {
    pub plugin_id: String,
    pub version: String,
    pub settings: HashMap<String, serde_json::Value>,
    pub runtime_data: HashMap<String, serde_json::Value>,
    pub saved_at: u64,
}

/// Manages state capture and restoration across reloads.
#[derive(Debug, Default)]
pub struct StateTransfer {
    pub snapshots: HashMap<String, PluginState>,
}

impl StateTransfer {
    /// Create a new state transfer manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Save state for a plugin.
    pub fn save(&mut self, plugin_id: impl Into<String>, state: PluginState) {
        self.snapshots.insert(plugin_id.into(), state);
    }

    /// Restore state for a plugin.
    #[must_use]
    pub fn restore(&self, plugin_id: &str) -> Option<&PluginState> {
        self.snapshots.get(plugin_id)
    }

    /// Remove saved state for a plugin.
    pub fn discard(&mut self, plugin_id: &str) {
        self.snapshots.remove(plugin_id);
    }

    /// Return the number of saved states.
    #[must_use]
    pub fn count(&self) -> usize {
        self.snapshots.len()
    }

    /// Check if state exists for a plugin.
    #[must_use]
    pub fn has_state(&self, plugin_id: &str) -> bool {
        self.snapshots.contains_key(plugin_id)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GracefulReload — coordinated plugin swap
// ─────────────────────────────────────────────────────────────────────────────

/// The phases of a graceful reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReloadPhase {
    Idle,
    Pausing,
    Unloading,
    Loading,
    Restoring,
    Verifying,
    Complete,
    Failed,
}

/// Coordinates a graceful plugin reload.
#[derive(Debug)]
pub struct GracefulReload {
    pub plugin_id: String,
    pub phase: ReloadPhase,
    pub old_path: Option<PathBuf>,
    pub new_path: PathBuf,
    pub error: Option<String>,
    pub start_time: u64,
    pub timeout_ms: u64,
}

impl GracefulReload {
    /// Create a new graceful reload context.
    #[must_use]
    pub fn new(plugin_id: impl Into<String>, new_path: impl Into<PathBuf>) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            phase: ReloadPhase::Idle,
            old_path: None,
            new_path: new_path.into(),
            error: None,
            start_time: now_ms(),
            timeout_ms: 5_000,
        }
    }

    /// Advance to the next phase.
    pub const fn advance(&mut self) {
        self.phase = match self.phase {
            ReloadPhase::Idle => ReloadPhase::Pausing,
            ReloadPhase::Pausing => ReloadPhase::Unloading,
            ReloadPhase::Unloading => ReloadPhase::Loading,
            ReloadPhase::Loading => ReloadPhase::Restoring,
            ReloadPhase::Restoring => ReloadPhase::Verifying,
            ReloadPhase::Verifying => ReloadPhase::Complete,
            _ => self.phase,
        };
    }

    /// Fail the reload with an error message.
    pub fn fail(&mut self, error: impl Into<String>) {
        self.phase = ReloadPhase::Failed;
        self.error = Some(error.into());
    }

    /// Return true if the reload is complete.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        matches!(self.phase, ReloadPhase::Complete | ReloadPhase::Failed)
    }

    /// Return true if the reload has timed out.
    #[must_use]
    pub fn is_timed_out(&self) -> bool {
        now_ms().saturating_sub(self.start_time) > self.timeout_ms
    }

    /// Simulate a complete reload (for testing).
    pub fn run_all_phases(&mut self) {
        while !self.is_done() && !self.is_timed_out() {
            self.advance();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReloadReport
// ─────────────────────────────────────────────────────────────────────────────

/// The outcome of a reload attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReloadOutcome {
    Success,
    PartialSuccess,
    Failed,
    Skipped,
    Timeout,
}

/// A report of a completed reload attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadReport {
    pub plugin_id: String,
    pub outcome: ReloadOutcome,
    pub duration_ms: u64,
    pub phases_completed: usize,
    pub error: Option<String>,
    pub timestamp: u64,
    pub triggered_by: TriggerSource,
}

impl ReloadReport {
    /// Create a success report.
    #[must_use]
    pub fn success(plugin_id: impl Into<String>, duration_ms: u64, source: TriggerSource) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            outcome: ReloadOutcome::Success,
            duration_ms,
            phases_completed: 6,
            error: None,
            timestamp: now_ms(),
            triggered_by: source,
        }
    }

    /// Create a failure report.
    #[must_use]
    pub fn failure(
        plugin_id: impl Into<String>,
        error: impl Into<String>,
        source: TriggerSource,
    ) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            outcome: ReloadOutcome::Failed,
            duration_ms: 0,
            phases_completed: 0,
            error: Some(error.into()),
            timestamp: now_ms(),
            triggered_by: source,
        }
    }

    /// Return true if the reload succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.outcome == ReloadOutcome::Success
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginDependencyGraph
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks dependencies between plugins for cascade-reload decisions.
#[derive(Debug, Default)]
pub struct PluginDependencyGraph {
    dependents: HashMap<String, HashSet<String>>,
    dependencies: HashMap<String, HashSet<String>>,
}

impl PluginDependencyGraph {
    /// Create a new dependency graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `dependent` depends on `dependency`.
    pub fn add_dependency(&mut self, dependent: impl Into<String>, dependency: impl Into<String>) {
        let dep: String = dependent.into();
        let on: String = dependency.into();
        self.dependents
            .entry(on.clone())
            .or_default()
            .insert(dep.clone());
        self.dependencies.entry(dep).or_default().insert(on);
    }

    /// Return all plugins that depend (directly or transitively) on `plugin_id`.
    #[must_use]
    pub fn transitive_dependents(&self, plugin_id: &str) -> Vec<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(plugin_id.to_string());
        let mut result = Vec::new();
        while let Some(id) = queue.pop_front() {
            if let Some(deps) = self.dependents.get(&id) {
                for d in deps {
                    if visited.insert(d.clone()) {
                        result.push(d.clone());
                        queue.push_back(d.clone());
                    }
                }
            }
        }
        result
    }

    /// Return all direct dependencies of `plugin_id`.
    #[must_use]
    pub fn direct_dependencies(&self, plugin_id: &str) -> Vec<&str> {
        self.dependencies
            .get(plugin_id)
            .map(|s| s.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Return whether `a` depends on `b` (directly).
    #[must_use]
    pub fn depends_on(&self, a: &str, b: &str) -> bool {
        self.dependencies.get(a).is_some_and(|d| d.contains(b))
    }

    /// Return the number of plugins in the graph.
    #[must_use]
    pub fn plugin_count(&self) -> usize {
        let mut all: HashSet<&str> = HashSet::new();
        for k in self.dependents.keys() {
            all.insert(k.as_str());
        }
        for k in self.dependencies.keys() {
            all.insert(k.as_str());
        }
        all.len()
    }

    /// Detect if adding `dependent → dependency` would create a cycle.
    #[must_use]
    pub fn would_create_cycle(&self, dependent: &str, dependency: &str) -> bool {
        // If dependency already (transitively) depends on dependent, adding this edge creates a cycle.
        self.transitive_dependents(dependent)
            .iter()
            .any(|d| d == dependency)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HotReloadEngine — top-level orchestration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the hot reload engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotReloadConfig {
    pub enabled: bool,
    pub cascade_reload: bool,
    pub max_concurrent_reloads: usize,
    pub debounce_ms: u64,
    pub timeout_ms: u64,
    pub preserve_state: bool,
}

impl Default for HotReloadConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cascade_reload: true,
            max_concurrent_reloads: 2,
            debounce_ms: 300,
            timeout_ms: 5_000,
            preserve_state: true,
        }
    }
}

/// Top-level hot-reload orchestration engine.
#[derive(Debug)]
pub struct HotReloadEngine {
    pub config: HotReloadConfig,
    pub watcher: PluginWatcher,
    pub trigger_queue: TriggerQueue,
    pub state_transfer: StateTransfer,
    pub dep_graph: PluginDependencyGraph,
    pub reload_history: Vec<ReloadReport>,
    pub active_reloads: HashMap<String, ReloadPhase>,
}

impl HotReloadEngine {
    /// Create a new hot reload engine.
    #[must_use]
    pub fn new(config: HotReloadConfig) -> Self {
        let mut watcher = PluginWatcher::new();
        watcher.set_debounce_ms(config.debounce_ms);
        Self {
            config,
            watcher,
            trigger_queue: TriggerQueue::new(),
            state_transfer: StateTransfer::new(),
            dep_graph: PluginDependencyGraph::new(),
            reload_history: Vec::new(),
            active_reloads: HashMap::new(),
        }
    }

    /// Create a default hot reload engine.
    #[must_use]
    pub fn default_engine() -> Self {
        Self::new(HotReloadConfig::default())
    }

    /// Watch a plugin directory.
    pub fn watch_dir(&mut self, dir: impl Into<PathBuf>) {
        self.watcher.watch(dir);
    }

    /// Process pending file events and enqueue reload triggers.
    pub fn process_fs_events(&mut self) {
        let events = self.watcher.drain();
        for event in events {
            if !event.is_dylib() {
                continue;
            }
            if let Some(name) = event.path().file_stem().and_then(|n| n.to_str()) {
                let trigger = ReloadTrigger::file_change(name, event.path().to_path_buf());
                self.trigger_queue.enqueue(trigger);
            }
        }
    }

    /// Attempt to process the next queued reload.
    ///
    /// Returns a [`ReloadReport`] if a reload was processed.
    pub fn process_next(&mut self) -> Option<ReloadReport> {
        if !self.config.enabled {
            return None;
        }
        let trigger = self.trigger_queue.dequeue()?;
        let plugin_id = trigger.plugin_id.clone();

        // Simulate a graceful reload.
        let start = now_ms();
        let mut reload = GracefulReload::new(&plugin_id, PathBuf::from(format!("{plugin_id}.dll")));
        reload.run_all_phases();

        let duration = now_ms().saturating_sub(start);
        let report = if reload.phase == ReloadPhase::Complete {
            // Optionally cascade to dependents.
            if self.config.cascade_reload {
                let dependents = self.dep_graph.transitive_dependents(&plugin_id);
                for dep in dependents {
                    self.trigger_queue.enqueue(ReloadTrigger::new(
                        dep,
                        TriggerSource::DependencyChanged(plugin_id.clone()),
                    ));
                }
            }
            ReloadReport::success(&plugin_id, duration, trigger.source)
        } else {
            ReloadReport::failure(&plugin_id, reload.error.unwrap_or_default(), trigger.source)
        };

        self.active_reloads.remove(&plugin_id);
        self.reload_history.push(report.clone());
        Some(report)
    }

    /// Manually trigger a reload for a plugin.
    pub fn trigger_manual(&mut self, plugin_id: impl Into<String>) {
        self.trigger_queue.enqueue(ReloadTrigger::manual(plugin_id));
    }

    /// Return the reload history.
    #[must_use]
    pub fn history(&self) -> &[ReloadReport] {
        &self.reload_history
    }

    /// Return the number of successful reloads in history.
    #[must_use]
    pub fn success_count(&self) -> usize {
        self.reload_history
            .iter()
            .filter(|r| r.is_success())
            .count()
    }

    /// Return the failure count.
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.reload_history
            .iter()
            .filter(|r| !r.is_success())
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── FsEvent ───────────────────────────────────────────────────────────────

    #[test]
    fn test_fs_event_path_created() {
        let e = FsEvent::Created(PathBuf::from("/tmp/plugin.so"));
        assert_eq!(e.path(), Path::new("/tmp/plugin.so"));
    }

    #[test]
    fn test_fs_event_is_dylib_so() {
        let e = FsEvent::Modified(PathBuf::from("lib/plugin.so"));
        assert!(e.is_dylib());
    }

    #[test]
    fn test_fs_event_is_dylib_dll() {
        let e = FsEvent::Created(PathBuf::from("plugins/my_plugin.dll"));
        assert!(e.is_dylib());
    }

    #[test]
    fn test_fs_event_not_dylib() {
        let e = FsEvent::Modified(PathBuf::from("config.json"));
        assert!(!e.is_dylib());
    }

    #[test]
    fn test_fs_event_renamed_path() {
        let e = FsEvent::Renamed {
            from: PathBuf::from("old.dll"),
            to: PathBuf::from("new.dll"),
        };
        assert_eq!(e.path(), Path::new("new.dll"));
    }

    // ── PluginWatcher ─────────────────────────────────────────────────────────

    #[test]
    fn test_plugin_watcher_watch() {
        let mut w = PluginWatcher::new();
        w.watch("/tmp/plugins");
        assert_eq!(w.watched_dirs().len(), 1);
    }

    #[test]
    fn test_plugin_watcher_no_duplicates() {
        let mut w = PluginWatcher::new();
        w.watch("/tmp/plugins");
        w.watch("/tmp/plugins");
        assert_eq!(w.watched_dirs().len(), 1);
    }

    #[test]
    fn test_plugin_watcher_unwatch() {
        let mut w = PluginWatcher::new();
        w.watch("/tmp/plugins");
        w.unwatch(Path::new("/tmp/plugins"));
        assert!(w.watched_dirs().is_empty());
    }

    #[test]
    fn test_plugin_watcher_inject_and_drain() {
        let mut w = PluginWatcher::new();
        w.inject(FsEvent::Modified(PathBuf::from("plugin.so")));
        assert_eq!(w.pending_count(), 1);
        let events = w.drain();
        assert_eq!(events.len(), 1);
        assert_eq!(w.pending_count(), 0);
    }

    #[test]
    fn test_plugin_watcher_debounce() {
        let mut w = PluginWatcher::new();
        w.set_debounce_ms(1000); // very long debounce
        w.inject(FsEvent::Modified(PathBuf::from("plugin.so")));
        w.inject(FsEvent::Modified(PathBuf::from("plugin.so"))); // should be blocked
        assert_eq!(w.pending_count(), 1);
    }

    // ── ReloadTrigger ─────────────────────────────────────────────────────────

    #[test]
    fn test_reload_trigger_manual_high_priority() {
        let t = ReloadTrigger::manual("my_plugin");
        assert!(t.is_high_priority());
        assert_eq!(t.source, TriggerSource::Manual);
    }

    #[test]
    fn test_reload_trigger_file_change() {
        let t = ReloadTrigger::file_change("plugin_a", PathBuf::from("plugin_a.dll"));
        assert!(!t.is_high_priority());
        assert!(matches!(t.source, TriggerSource::FileChange(_)));
    }

    // ── TriggerQueue ──────────────────────────────────────────────────────────

    #[test]
    fn test_trigger_queue_priority_order() {
        let mut q = TriggerQueue::new();
        q.enqueue(ReloadTrigger::new("low", TriggerSource::Scheduled));
        let mut high = ReloadTrigger::manual("high");
        high.priority = 100;
        q.enqueue(high);
        let first = q.dequeue().unwrap();
        assert_eq!(first.plugin_id, "high");
    }

    #[test]
    fn test_trigger_queue_empty_dequeue() {
        let mut q = TriggerQueue::new();
        assert!(q.dequeue().is_none());
    }

    #[test]
    fn test_trigger_queue_len() {
        let mut q = TriggerQueue::new();
        q.enqueue(ReloadTrigger::manual("a"));
        q.enqueue(ReloadTrigger::manual("b"));
        assert_eq!(q.len(), 2);
    }

    // ── StateTransfer ─────────────────────────────────────────────────────────

    #[test]
    fn test_state_transfer_save_restore() {
        let mut st = StateTransfer::new();
        let state = PluginState {
            plugin_id: "p1".to_string(),
            ..Default::default()
        };
        st.save("p1", state);
        assert!(st.restore("p1").is_some());
        assert!(st.restore("missing").is_none());
    }

    #[test]
    fn test_state_transfer_discard() {
        let mut st = StateTransfer::new();
        st.save("p1", PluginState::default());
        st.discard("p1");
        assert!(!st.has_state("p1"));
    }

    #[test]
    fn test_state_transfer_count() {
        let mut st = StateTransfer::new();
        st.save("a", PluginState::default());
        st.save("b", PluginState::default());
        assert_eq!(st.count(), 2);
    }

    // ── GracefulReload ────────────────────────────────────────────────────────

    #[test]
    fn test_graceful_reload_phase_progression() {
        let mut r = GracefulReload::new("p1", "/tmp/p1.dll");
        assert_eq!(r.phase, ReloadPhase::Idle);
        r.advance();
        assert_eq!(r.phase, ReloadPhase::Pausing);
        r.advance();
        assert_eq!(r.phase, ReloadPhase::Unloading);
    }

    #[test]
    fn test_graceful_reload_run_all_phases() {
        let mut r = GracefulReload::new("p1", "/tmp/p1.dll");
        r.run_all_phases();
        assert_eq!(r.phase, ReloadPhase::Complete);
        assert!(r.is_done());
    }

    #[test]
    fn test_graceful_reload_fail() {
        let mut r = GracefulReload::new("p1", "/tmp/p1.dll");
        r.advance(); // Pausing
        r.fail("lib not found");
        assert_eq!(r.phase, ReloadPhase::Failed);
        assert!(r.error.is_some());
    }

    // ── ReloadReport ──────────────────────────────────────────────────────────

    #[test]
    fn test_reload_report_success() {
        let r = ReloadReport::success("p1", 100, TriggerSource::Manual);
        assert!(r.is_success());
        assert_eq!(r.outcome, ReloadOutcome::Success);
    }

    #[test]
    fn test_reload_report_failure() {
        let r = ReloadReport::failure("p2", "dlopen failed", TriggerSource::Manual);
        assert!(!r.is_success());
        assert!(r.error.is_some());
    }

    // ── PluginDependencyGraph ─────────────────────────────────────────────────

    #[test]
    fn test_dep_graph_add_dependency() {
        let mut g = PluginDependencyGraph::new();
        g.add_dependency("b", "a");
        assert!(g.depends_on("b", "a"));
        assert!(!g.depends_on("a", "b"));
    }

    #[test]
    fn test_dep_graph_transitive_dependents() {
        let mut g = PluginDependencyGraph::new();
        g.add_dependency("b", "a");
        g.add_dependency("c", "b");
        let deps = g.transitive_dependents("a");
        assert!(deps.contains(&"b".to_string()));
        assert!(deps.contains(&"c".to_string()));
    }

    #[test]
    fn test_dep_graph_direct_dependencies() {
        let mut g = PluginDependencyGraph::new();
        g.add_dependency("x", "y");
        g.add_dependency("x", "z");
        let mut deps = g.direct_dependencies("x");
        deps.sort_unstable();
        assert!(deps.contains(&"y") && deps.contains(&"z"));
    }

    #[test]
    fn test_dep_graph_plugin_count() {
        let mut g = PluginDependencyGraph::new();
        g.add_dependency("b", "a");
        assert_eq!(g.plugin_count(), 2);
    }

    #[test]
    fn test_dep_graph_cycle_detection() {
        let mut g = PluginDependencyGraph::new();
        g.add_dependency("b", "a");
        g.add_dependency("c", "b");
        // Adding a → c would create a cycle a → c → b → a.
        // Actually, the edge would be a depends on c (a → c).
        // c depends on b depends on a = a is a transitive dependent of a.
        // The check: would_create_cycle("a", "c") → transitive_dependents("a") includes c? yes. So cycle.
        assert!(g.would_create_cycle("a", "c"));
    }

    // ── HotReloadEngine ───────────────────────────────────────────────────────

    #[test]
    fn test_hot_reload_engine_manual_reload() {
        let mut eng = HotReloadEngine::default_engine();
        eng.trigger_manual("my_plugin");
        let report = eng.process_next().unwrap();
        assert_eq!(report.plugin_id, "my_plugin");
        assert!(report.is_success());
    }

    #[test]
    fn test_hot_reload_engine_disabled() {
        let mut eng = HotReloadEngine::new(HotReloadConfig {
            enabled: false,
            ..Default::default()
        });
        eng.trigger_manual("p1");
        assert!(eng.process_next().is_none());
    }

    #[test]
    fn test_hot_reload_engine_fs_event_processing() {
        let mut eng = HotReloadEngine::default_engine();
        eng.watcher
            .inject(FsEvent::Modified(PathBuf::from("my_plugin.dll")));
        eng.process_fs_events();
        assert!(!eng.trigger_queue.is_empty());
    }

    #[test]
    fn test_hot_reload_engine_history() {
        let mut eng = HotReloadEngine::default_engine();
        eng.trigger_manual("p1");
        eng.process_next();
        assert_eq!(eng.history().len(), 1);
        assert_eq!(eng.success_count(), 1);
    }

    #[test]
    fn test_hot_reload_engine_cascade() {
        let mut eng = HotReloadEngine::default_engine();
        eng.dep_graph.add_dependency("plugin_b", "plugin_a");
        eng.trigger_manual("plugin_a");
        eng.process_next();
        // Should have enqueued a reload for plugin_b.
        assert!(!eng.trigger_queue.is_empty());
    }

    #[test]
    fn test_hot_reload_engine_watch_dir() {
        let mut eng = HotReloadEngine::default_engine();
        eng.watch_dir("/tmp/plugins");
        assert!(!eng.watcher.watched_dirs().is_empty());
    }

    #[test]
    fn test_hot_reload_engine_failure_count() {
        let mut eng = HotReloadEngine::default_engine();
        eng.trigger_manual("ok_plugin");
        eng.process_next();
        assert_eq!(eng.failure_count(), 0);
    }
}
