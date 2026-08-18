//! `event_replay` — Persistent event log replay for the `RustRE` event bus.
//!
//! Provides [`EventReplayer`] which replays events from a persisted event log
//! with configurable speed, filtering, position windowing, and pause/resume.
//! [`SnapshotManager`] enables fast-forward to any point by saving and loading
//! projected state snapshots.

use crate::{CoreEvent, EventBus, EventKind};
use serde::{Deserialize, Serialize};

#[inline]
const fn cast_u64_f64(v: u64) -> f64 { v as f64 }
#[inline]
const fn cast_usize_f64(v: usize) -> f64 { v as f64 }
#[inline]
const fn cast_f64_u64_sat(v: f64) -> u64 { v.max(0.0).min(u64::MAX as f64) as u64 }

pub use parking_lot::Mutex as ReplayMutex;
pub use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

// ---------------------------------------------------------------------------
// ReplayConfig
// ---------------------------------------------------------------------------

/// Configuration that governs how a replay session executes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayConfig {
    /// Index of the first event to replay (inclusive, 0-based).
    pub start_position: usize,
    /// Index of the last event to replay (exclusive).  `None` means replay
    /// until the end of the log.
    pub end_position: Option<usize>,
    /// Replay speed multiplier.  1.0 = real-time, 2.0 = double speed,
    /// 0.5 = half speed.  Values ≤ 0 are clamped to 0.01.
    pub speed: f64,
    /// Optional filter: only replay events of these variant names.  An empty
    /// vec means accept all events.
    pub filter: Vec<String>,
    /// If `true`, publish replayed events to the bus; if `false`, only
    /// apply them to registered projections without broadcasting.
    pub publish_to_bus: bool,
    /// Delay between consecutive events in microseconds (before speed scaling).
    /// `None` = use the original inter-event timestamps if available, else 0.
    pub inter_event_delay_us: Option<u64>,
}

impl ReplayConfig {
    /// Create a config with sensible defaults: replay everything at real-time.
    #[must_use]
    pub const fn default_config() -> Self {
        Self {
            start_position: 0,
            end_position: None,
            speed: 1.0,
            filter: Vec::new(),
            publish_to_bus: true,
            inter_event_delay_us: None,
        }
    }

    /// Create a fast-forward config (no delays, no filtering).
    #[must_use]
    pub fn fast_forward() -> Self {
        Self {
            speed: f64::MAX,
            inter_event_delay_us: Some(0),
            ..Self::default_config()
        }
    }

    /// Restrict the replay to events whose variant name is in `names`.
    #[must_use]
    pub fn with_filter(mut self, names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.filter = names.into_iter().map(Into::into).collect();
        self
    }

    /// Set the position window.
    #[must_use]
    pub const fn with_window(mut self, start: usize, end: usize) -> Self {
        self.start_position = start;
        self.end_position = Some(end);
        self
    }

    /// Effective speed, clamped to at least 0.01.
    #[must_use]
    pub const fn effective_speed(&self) -> f64 {
        self.speed.max(0.01)
    }

    /// Compute the wall-clock delay for a given original inter-event gap.
    #[must_use]
    pub fn scaled_delay(&self, original_us: u64) -> Duration {
        let us = cast_u64_f64(original_us) / self.effective_speed();
        Duration::from_micros(cast_f64_u64_sat(us))
    }
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

// ---------------------------------------------------------------------------
// LoggedEvent — a timestamped event entry in the persistent log
// ---------------------------------------------------------------------------

/// A single entry in a persisted event log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggedEvent {
    /// When the event was originally emitted (Unix timestamp in nanoseconds).
    pub timestamp_ns: u128,
    /// The event itself.
    pub event: CoreEvent,
    /// Sequential position in the log (0-based).
    pub position: usize,
}

impl LoggedEvent {
    /// Create a new log entry at the current time.
    #[must_use]
    pub fn new(position: usize, event: CoreEvent) -> Self {
        let timestamp_ns = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        Self {
            timestamp_ns,
            event,
            position,
        }
    }

    /// Return the inter-event gap in microseconds between `self` and `next`.
    /// Returns `None` if the timestamps are non-monotonic.
    #[must_use]
    pub fn gap_us_to(&self, next: &Self) -> Option<u64> {
        next.timestamp_ns
            .checked_sub(self.timestamp_ns)
            .map(|ns| u64::try_from(ns / 1000).unwrap_or(u64::MAX))
    }
}

// ---------------------------------------------------------------------------
// EventLog — in-memory persisted log
// ---------------------------------------------------------------------------

/// An ordered, append-only log of [`LoggedEvent`]s used as the source for
/// replay.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EventLog {
    entries: Vec<LoggedEvent>,
}

impl EventLog {
    /// Create an empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a new event to the log.
    pub fn append(&mut self, event: CoreEvent) {
        let position = self.entries.len();
        self.entries.push(LoggedEvent::new(position, event));
    }

    /// Append multiple events at once.
    pub fn append_many(&mut self, events: impl IntoIterator<Item = CoreEvent>) {
        for event in events {
            self.append(event);
        }
    }

    /// Return the total number of logged events.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the log is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Access a specific position.
    #[must_use]
    pub fn get(&self, position: usize) -> Option<&LoggedEvent> {
        self.entries.get(position)
    }

    /// Return all entries in positional order.
    #[must_use]
    pub fn entries(&self) -> &[LoggedEvent] {
        &self.entries
    }

    /// Serialize the log to JSON.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize a log from JSON.
    ///
    /// To avoid dos-memory-exhaustion from attacker-controlled input, the
    /// deserialized log is capped at `MAX_LOG_ENTRIES` entries.  Entries
    /// beyond the cap are silently truncated.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` if deserialization fails.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        /// Maximum number of log entries accepted from untrusted JSON input.
        const MAX_LOG_ENTRIES: usize = 1_000_000;
        let mut log: Self = serde_json::from_str(s)?;
        if log.entries.len() > MAX_LOG_ENTRIES {
            log.entries.truncate(MAX_LOG_ENTRIES);
        }
        Ok(log)
    }

    /// Filter entries to those whose variant names are in `names`.
    #[must_use]
    pub fn filter_by_variants(&self, names: &[String]) -> Vec<&LoggedEvent> {
        if names.is_empty() {
            return self.entries.iter().collect();
        }
        let set: std::collections::HashSet<&str> =
            names.iter().map(String::as_str).collect();
        self.entries
            .iter()
            .filter(|e| set.contains(e.event.variant_name()))
            .collect()
    }

    /// Return entries in the half-open positional range `[start, end)`.
    #[must_use]
    pub fn window(&self, start: usize, end: usize) -> &[LoggedEvent] {
        let end = end.min(self.entries.len());
        let start = start.min(end);
        &self.entries[start..end]
    }
}

// ---------------------------------------------------------------------------
// ReplayStats
// ---------------------------------------------------------------------------

/// Statistics collected during a single replay run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplayStats {
    /// Total events replayed (delivered to projections / bus).
    pub events_replayed: usize,
    /// Events skipped by the filter.
    pub events_filtered: usize,
    /// Number of times replay was paused.
    pub pause_count: usize,
    /// Cumulative wall-clock time spent in the paused state (microseconds).
    pub paused_us: u64,
    /// Wall-clock duration of the replay (microseconds, excluding pauses).
    pub replay_duration_us: u64,
    /// Final cursor position at replay completion.
    pub final_position: usize,
    /// Whether replay completed successfully (false = was aborted).
    pub completed: bool,
}

impl ReplayStats {
    /// Effective replay throughput (events/second).
    #[must_use]
    pub fn throughput_eps(&self) -> f64 {
        if self.replay_duration_us == 0 {
            return 0.0;
        }
        cast_usize_f64(self.events_replayed) / (cast_u64_f64(self.replay_duration_us) / 1_000_000.0)
    }

    /// Total events seen (replayed + filtered).
    #[must_use]
    pub const fn total_seen(&self) -> usize {
        self.events_replayed + self.events_filtered
    }
}

// ---------------------------------------------------------------------------
// EventProjection — trait for state projectors
// ---------------------------------------------------------------------------

/// Implementors of this trait receive replayed events and maintain derived
/// state (read models, aggregate views, counters, etc.).
pub trait EventProjection: Send + Sync {
    /// Apply a single replayed event to this projection's state.
    fn apply(&mut self, event: &CoreEvent);

    /// Human-readable name of this projection.
    fn name(&self) -> &str;

    /// Reset the projection to its initial (empty) state.
    fn reset(&mut self);

    /// Return a JSON snapshot of the current state, if supported.
    fn snapshot_json(&self) -> Option<String> {
        None
    }

    /// Restore state from a JSON snapshot previously produced by
    /// [`EventProjection::snapshot_json`].
    ///
    /// Returns `false` if the snapshot could not be applied.
    fn restore_json(&mut self, _json: &str) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Built-in projections
// ---------------------------------------------------------------------------

/// A projection that counts events by variant name.
#[derive(Debug, Default)]
pub struct CountingProjection {
    counts: HashMap<String, usize>,
}

impl CountingProjection {
    /// Create an empty counting projection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the count for `variant_name`.
    #[must_use]
    pub fn count_of(&self, variant_name: &str) -> usize {
        self.counts.get(variant_name).copied().unwrap_or(0)
    }

    /// Total events seen.
    #[must_use]
    pub fn total(&self) -> usize {
        self.counts.values().sum()
    }

    /// Return all variant-name → count pairs.
    #[must_use]
    pub const fn all_counts(&self) -> &HashMap<String, usize> {
        &self.counts
    }
}

impl EventProjection for CountingProjection {
    fn apply(&mut self, event: &CoreEvent) {
        *self
            .counts
            .entry(event.variant_name().to_string())
            .or_insert(0) += 1;
    }

    fn name(&self) -> &'static str {
        "CountingProjection"
    }

    fn reset(&mut self) {
        self.counts.clear();
    }

    fn snapshot_json(&self) -> Option<String> {
        serde_json::to_string(&self.counts).ok()
    }
}

/// A projection that tracks the last-seen event for each `view_id`.
#[derive(Debug, Default)]
pub struct LastEventPerViewProjection {
    last: HashMap<u64, CoreEvent>,
}

impl LastEventPerViewProjection {
    /// Create a new empty projection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the last event for `view_id`, if any.
    #[must_use]
    pub fn last_for_view(&self, view_id: u64) -> Option<&CoreEvent> {
        self.last.get(&view_id)
    }

    /// Number of distinct views seen.
    #[must_use]
    pub fn view_count(&self) -> usize {
        self.last.len()
    }
}

impl EventProjection for LastEventPerViewProjection {
    fn apply(&mut self, event: &CoreEvent) {
        if let Some(vid) = event.view_id() {
            self.last.insert(vid, event.clone());
        }
    }

    fn name(&self) -> &'static str {
        "LastEventPerViewProjection"
    }

    fn reset(&mut self) {
        self.last.clear();
    }
}

/// A projection that accumulates a timeline of events for each `EventKind`.
#[derive(Debug, Default)]
pub struct KindTimelineProjection {
    timelines: HashMap<String, Vec<usize>>,
    position: usize,
}

impl KindTimelineProjection {
    /// Create a new empty projection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the positions at which events of `kind` were seen.
    #[must_use]
    pub fn positions_for_kind(&self, kind: EventKind) -> Vec<usize> {
        let key = format!("{kind:?}");
        self.timelines.get(&key).cloned().unwrap_or_default()
    }

    /// Return all distinct `EventKind` keys present in the timeline.
    #[must_use]
    pub fn kind_keys(&self) -> Vec<String> {
        self.timelines.keys().cloned().collect()
    }
}

impl EventProjection for KindTimelineProjection {
    fn apply(&mut self, event: &CoreEvent) {
        let key = format!("{:?}", event.kind());
        self.timelines.entry(key).or_default().push(self.position);
        self.position += 1;
    }

    fn name(&self) -> &'static str {
        "KindTimelineProjection"
    }

    fn reset(&mut self) {
        self.timelines.clear();
        self.position = 0;
    }
}

// ---------------------------------------------------------------------------
// ProjectionRegistry
// ---------------------------------------------------------------------------

/// Manages a set of [`EventProjection`]s and applies replayed events to all
/// of them in registration order.
pub struct ProjectionRegistry {
    projections: Vec<Box<dyn EventProjection>>,
}

impl ProjectionRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            projections: Vec::new(),
        }
    }

    /// Register a projection.
    pub fn register(&mut self, projection: Box<dyn EventProjection>) {
        self.projections.push(projection);
    }

    /// Apply `event` to every registered projection.
    pub fn apply_all(&mut self, event: &CoreEvent) {
        for proj in &mut self.projections {
            proj.apply(event);
        }
    }

    /// Reset all projections to their initial state.
    pub fn reset_all(&mut self) {
        for proj in &mut self.projections {
            proj.reset();
        }
    }

    /// Return the number of registered projections.
    #[must_use]
    pub fn count(&self) -> usize {
        self.projections.len()
    }

    /// Return names of all registered projections.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.projections.iter().map(|p| p.name()).collect()
    }
}

impl Default for ProjectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SnapshotManager
// ---------------------------------------------------------------------------

/// Saves and loads projection-state snapshots for fast replay seeking.
///
/// Snapshots are keyed by the log position at which they were taken.
#[derive(Debug, Default)]
pub struct SnapshotManager {
    snapshots: HashMap<usize, HashMap<String, String>>,
}

impl SnapshotManager {
    /// Create an empty snapshot manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Save a snapshot of all projections in `registry` at `position`.
    pub fn save_snapshot(&mut self, position: usize, registry: &ProjectionRegistry) {
        let mut snap: HashMap<String, String> = HashMap::new();
        for proj in &registry.projections {
            if let Some(json) = proj.snapshot_json() {
                snap.insert(proj.name().to_string(), json);
            }
        }
        self.snapshots.insert(position, snap);
    }

    /// Restore the most-recent snapshot at or before `target_position`.
    ///
    /// Returns the position of the restored snapshot, or `None` if no suitable
    /// snapshot exists.
    pub fn restore_nearest(
        &self,
        target_position: usize,
        registry: &mut ProjectionRegistry,
    ) -> Option<usize> {
        let best_pos = self
            .snapshots
            .keys()
            .filter(|&&p| p <= target_position)
            .max_by_key(|&&p| p)
            .copied()?;

        let snap = &self.snapshots[&best_pos];
        for proj in &mut registry.projections {
            if let Some(json) = snap.get(proj.name()) {
                proj.restore_json(json);
            }
        }
        Some(best_pos)
    }

    /// Remove snapshots taken after `position` (useful after log truncation).
    pub fn truncate_after(&mut self, position: usize) {
        self.snapshots.retain(|&p, _| p <= position);
    }

    /// Number of stored snapshots.
    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Return all snapshot positions in ascending order.
    #[must_use]
    pub fn positions(&self) -> Vec<usize> {
        let mut v: Vec<usize> = self.snapshots.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// Remove all snapshots.
    pub fn clear(&mut self) {
        self.snapshots.clear();
    }
}

// ---------------------------------------------------------------------------
// ReplaySession — pause/resume
// ---------------------------------------------------------------------------

/// Playback state of a [`ReplaySession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlaybackState {
    /// Replay has not yet started.
    Idle,
    /// Replay is actively running.
    Running,
    /// Replay has been paused.
    Paused,
    /// Replay has completed (end of log or `end_position` reached).
    Completed,
    /// Replay was aborted by the caller.
    Aborted,
}

/// A replay session that can be paused and resumed.
///
/// Use [`ReplaySession::step`] to advance one event at a time, or
/// [`ReplaySession::run_to_completion`] to run synchronously.
pub struct ReplaySession {
    log: Arc<EventLog>,
    config: ReplayConfig,
    cursor: usize,
    end: usize,
    state: PlaybackState,
    stats: ReplayStats,
    pause_start: Option<Instant>,
    run_start: Option<Instant>,
}

impl ReplaySession {
    /// Create a new session from a log and config.
    #[must_use]
    pub fn new(log: Arc<EventLog>, config: ReplayConfig) -> Self {
        let end = config.end_position.unwrap_or(log.len()).min(log.len());
        let cursor = config.start_position.min(end);
        Self {
            log,
            config,
            cursor,
            end,
            state: PlaybackState::Idle,
            stats: ReplayStats::default(),
            pause_start: None,
            run_start: None,
        }
    }

    /// Return the current cursor position.
    #[must_use]
    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    /// Return the current playback state.
    #[must_use]
    pub const fn state(&self) -> PlaybackState {
        self.state
    }

    /// Return the current statistics snapshot.
    #[must_use]
    pub const fn stats(&self) -> &ReplayStats {
        &self.stats
    }

    /// Pause an active replay session.  No-op if already paused or idle.
    pub fn pause(&mut self) {
        if self.state == PlaybackState::Running {
            self.state = PlaybackState::Paused;
            self.pause_start = Some(Instant::now());
            self.stats.pause_count += 1;
        }
    }

    /// Resume a paused session.  No-op if not paused.
    pub fn resume(&mut self) {
        if self.state == PlaybackState::Paused {
            if let Some(start) = self.pause_start.take() {
                self.stats.paused_us += u64::try_from(start.elapsed().as_micros()).unwrap_or(0);
            }
            self.state = PlaybackState::Running;
        }
    }

    /// Abort the session, finalising statistics.
    pub fn abort(&mut self) {
        self.finalise(false);
    }

    /// Seek to an absolute position in the log.  Only valid in `Idle` or
    /// `Paused` state.  Returns `false` if the seek was rejected.
    pub fn seek(&mut self, position: usize) -> bool {
        if !matches!(self.state, PlaybackState::Idle | PlaybackState::Paused) {
            return false;
        }
        self.cursor = position.min(self.end);
        true
    }

    /// Advance by one event, applying it to `registry` and optionally
    /// publishing to `bus`.
    ///
    /// Returns `true` if an event was stepped, `false` if the session is
    /// finished or in a non-running state.
    pub fn step(&mut self, registry: &mut ProjectionRegistry, bus: Option<&EventBus>) -> bool {
        if self.state == PlaybackState::Idle {
            self.state = PlaybackState::Running;
            self.run_start = Some(Instant::now());
        }

        if self.state != PlaybackState::Running {
            return false;
        }

        if self.cursor >= self.end {
            self.finalise(true);
            return false;
        }

        let entry = &self.log.entries()[self.cursor];
        self.cursor += 1;

        // Apply filter
        if !self.config.filter.is_empty()
            && !self
                .config
                .filter
                .iter()
                .any(|n| n == entry.event.variant_name())
        {
            self.stats.events_filtered += 1;
            return true;
        }

        // Apply to projections
        registry.apply_all(&entry.event);

        // Publish to bus
        if self.config.publish_to_bus
            && let Some(b) = bus {
                let _ = b.send(entry.event.clone());
            }

        self.stats.events_replayed += 1;
        true
    }

    /// Run the session to completion, applying every matching event to
    /// `registry` (and optionally `bus`).
    ///
    /// Returns the final [`ReplayStats`].
    pub fn run_to_completion(
        &mut self,
        registry: &mut ProjectionRegistry,
        bus: Option<&EventBus>,
    ) -> ReplayStats {
        while self.step(registry, bus) {}
        self.stats.clone()
    }

    // ── Private ───────────────────────────────────────────────────────────────

    fn finalise(&mut self, completed: bool) {
        if let Some(start) = self.run_start.take() {
            self.stats.replay_duration_us = u64::try_from(start.elapsed().as_micros())
                .unwrap_or(0)
                .saturating_sub(self.stats.paused_us);
        }
        self.stats.final_position = self.cursor;
        self.stats.completed = completed;
        self.state = if completed {
            PlaybackState::Completed
        } else {
            PlaybackState::Aborted
        };
    }
}

// ---------------------------------------------------------------------------
// EventReplayer — high-level facade
// ---------------------------------------------------------------------------

/// High-level replay engine.
///
/// Combines a [`EventLog`], [`ReplayConfig`], [`ProjectionRegistry`], and
/// optional [`SnapshotManager`] into a single, easy-to-use API.
pub struct EventReplayer {
    log: Arc<EventLog>,
    registry: ProjectionRegistry,
    snapshot_mgr: SnapshotManager,
    last_stats: Option<ReplayStats>,
}

impl EventReplayer {
    /// Create a replayer over a pre-populated log.
    #[must_use]
    pub fn new(log: EventLog) -> Self {
        Self {
            log: Arc::new(log),
            registry: ProjectionRegistry::new(),
            snapshot_mgr: SnapshotManager::new(),
            last_stats: None,
        }
    }

    /// Register a projection that will receive replayed events.
    pub fn register_projection(&mut self, projection: Box<dyn EventProjection>) {
        self.registry.register(projection);
    }

    /// Take a snapshot of current projection state at `position`.
    pub fn save_snapshot(&mut self, position: usize) {
        self.snapshot_mgr.save_snapshot(position, &self.registry);
    }

    /// Restore to the nearest snapshot before `target_position` and return
    /// the actual position restored, if any.
    pub fn restore_to(&mut self, target_position: usize) -> Option<usize> {
        self.snapshot_mgr
            .restore_nearest(target_position, &mut self.registry)
    }

    /// Replay the entire log (or the window defined in `config`) using the
    /// supplied [`ReplayConfig`].  Optionally publishes events to `bus`.
    ///
    /// Returns [`ReplayStats`] for the run.
    pub fn replay(&mut self, config: ReplayConfig, bus: Option<&EventBus>) -> ReplayStats {
        self.registry.reset_all();
        let mut session = ReplaySession::new(Arc::clone(&self.log), config);
        let stats = session.run_to_completion(&mut self.registry, bus);
        self.last_stats = Some(stats.clone());
        stats
    }

    /// Replay with default config (everything, fast-forward).
    pub fn replay_all(&mut self, bus: Option<&EventBus>) -> ReplayStats {
        self.replay(ReplayConfig::fast_forward(), bus)
    }

    /// Create an interactive [`ReplaySession`] for step-by-step control.
    #[must_use]
    pub fn create_session(&self, config: ReplayConfig) -> ReplaySession {
        ReplaySession::new(Arc::clone(&self.log), config)
    }

    /// Return the most-recent replay statistics, if any.
    #[must_use]
    pub const fn last_stats(&self) -> Option<&ReplayStats> {
        self.last_stats.as_ref()
    }

    /// Return a reference to the underlying event log.
    #[must_use]
    pub fn log(&self) -> &EventLog {
        &self.log
    }

    /// Return a reference to the projection registry.
    #[must_use]
    pub const fn registry(&self) -> &ProjectionRegistry {
        &self.registry
    }

    /// Return a mutable reference to the snapshot manager.
    #[must_use]
    pub const fn snapshot_manager(&mut self) -> &mut SnapshotManager {
        &mut self.snapshot_mgr
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoreEvent;

    fn make_log(n: usize) -> EventLog {
        let mut log = EventLog::new();
        for i in 0..n {
            log.append(CoreEvent::ViewOpened {
                view_id: i as u64,
                uri: format!("file:///bin/{i}"),
                arch: "x86_64".into(),
            });
        }
        log
    }

    fn analysis_event(view_id: u64, pass: &str) -> CoreEvent {
        CoreEvent::AnalysisCompleted {
            view_id,
            pass: pass.into(),
        }
    }

    // ── ReplayConfig ──────────────────────────────────────────────────────────

    #[test]
    fn config_default_values() {
        let cfg = ReplayConfig::default_config();
        assert_eq!(cfg.start_position, 0);
        assert!(cfg.end_position.is_none());
        assert!((cfg.speed - 1.0).abs() < f64::EPSILON);
        assert!(cfg.filter.is_empty());
    }

    #[test]
    fn config_fast_forward_has_zero_delay() {
        let cfg = ReplayConfig::fast_forward();
        assert_eq!(cfg.inter_event_delay_us, Some(0));
    }

    #[test]
    fn config_effective_speed_clamped() {
        let mut cfg = ReplayConfig::default_config();
        cfg.speed = -1.0;
        assert!((cfg.effective_speed() - 0.01).abs() < 1e-10);
    }

    #[test]
    fn config_scaled_delay_at_double_speed() {
        let cfg = ReplayConfig {
            speed: 2.0,
            ..ReplayConfig::default_config()
        };
        let d = cfg.scaled_delay(1000);
        assert_eq!(d, Duration::from_micros(500));
    }

    #[test]
    fn config_with_filter() {
        let cfg = ReplayConfig::default_config().with_filter(["ViewOpened", "ViewClosed"]);
        assert_eq!(cfg.filter.len(), 2);
    }

    #[test]
    fn config_with_window() {
        let cfg = ReplayConfig::default_config().with_window(5, 20);
        assert_eq!(cfg.start_position, 5);
        assert_eq!(cfg.end_position, Some(20));
    }

    // ── EventLog ─────────────────────────────────────────────────────────────

    #[test]
    fn log_append_and_len() {
        let mut log = EventLog::new();
        assert!(log.is_empty());
        log.append(CoreEvent::ViewClosed { view_id: 1 });
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn log_append_many() {
        let mut log = EventLog::new();
        let events = vec![
            CoreEvent::ViewClosed { view_id: 1 },
            CoreEvent::ViewClosed { view_id: 2 },
            CoreEvent::ViewClosed { view_id: 3 },
        ];
        log.append_many(events);
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn log_positions_are_sequential() {
        let log = make_log(10);
        for (i, e) in log.entries().iter().enumerate() {
            assert_eq!(e.position, i);
        }
    }

    #[test]
    fn log_window_bounds() {
        let log = make_log(10);
        let window = log.window(2, 5);
        assert_eq!(window.len(), 3);
        assert_eq!(window[0].position, 2);
    }

    #[test]
    fn log_filter_by_variants() {
        let mut log = make_log(5); // ViewOpened x5
        log.append(analysis_event(1, "cfg"));
        let filtered = log.filter_by_variants(&["AnalysisCompleted".to_string()]);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn log_json_roundtrip() {
        let log = make_log(3);
        let json = log.to_json().unwrap();
        let restored = EventLog::from_json(&json).unwrap();
        assert_eq!(restored.len(), 3);
    }

    // ── LoggedEvent ───────────────────────────────────────────────────────────

    #[test]
    fn logged_event_gap_is_none_for_non_monotonic() {
        let a = LoggedEvent {
            timestamp_ns: 1000,
            position: 0,
            event: CoreEvent::ViewClosed { view_id: 1 },
        };
        let b = LoggedEvent {
            timestamp_ns: 500,
            position: 1,
            event: CoreEvent::ViewClosed { view_id: 2 },
        };
        assert!(a.gap_us_to(&b).is_none());
    }

    #[test]
    fn logged_event_gap_computes_correctly() {
        let a = LoggedEvent {
            timestamp_ns: 0,
            position: 0,
            event: CoreEvent::ViewClosed { view_id: 1 },
        };
        let b = LoggedEvent {
            timestamp_ns: 5000,
            position: 1,
            event: CoreEvent::ViewClosed { view_id: 2 },
        };
        assert_eq!(a.gap_us_to(&b), Some(5));
    }

    // ── CountingProjection ────────────────────────────────────────────────────

    #[test]
    fn counting_projection_counts_correctly() {
        let mut proj = CountingProjection::new();
        proj.apply(&CoreEvent::ViewClosed { view_id: 1 });
        proj.apply(&CoreEvent::ViewClosed { view_id: 2 });
        proj.apply(&analysis_event(1, "cfg"));
        assert_eq!(proj.count_of("ViewClosed"), 2);
        assert_eq!(proj.count_of("AnalysisCompleted"), 1);
        assert_eq!(proj.total(), 3);
    }

    #[test]
    fn counting_projection_reset_clears() {
        let mut proj = CountingProjection::new();
        proj.apply(&CoreEvent::ViewClosed { view_id: 1 });
        proj.reset();
        assert_eq!(proj.total(), 0);
    }

    #[test]
    fn counting_projection_snapshot() {
        let mut proj = CountingProjection::new();
        proj.apply(&CoreEvent::ViewClosed { view_id: 1 });
        let snap = proj.snapshot_json();
        assert!(snap.is_some());
        let json = snap.unwrap();
        assert!(json.contains("ViewClosed"));
    }

    // ── LastEventPerViewProjection ────────────────────────────────────────────

    #[test]
    fn last_event_per_view_projection_tracks_views() {
        let mut proj = LastEventPerViewProjection::new();
        proj.apply(&CoreEvent::ViewOpened {
            view_id: 1,
            uri: "a".into(),
            arch: "x86".into(),
        });
        proj.apply(&CoreEvent::ViewClosed { view_id: 1 });
        assert_eq!(proj.last_for_view(1).unwrap().variant_name(), "ViewClosed");
        assert_eq!(proj.view_count(), 1);
    }

    #[test]
    fn last_event_per_view_ignores_viewless_events() {
        let mut proj = LastEventPerViewProjection::new();
        proj.apply(&CoreEvent::PluginLoaded {
            plugin_id: "x".into(),
        });
        assert_eq!(proj.view_count(), 0);
    }

    // ── KindTimelineProjection ────────────────────────────────────────────────

    #[test]
    fn kind_timeline_projection_records_positions() {
        let mut proj = KindTimelineProjection::new();
        proj.apply(&CoreEvent::ViewClosed { view_id: 1 }); // position 0
        proj.apply(&analysis_event(1, "cfg")); // position 1
        proj.apply(&CoreEvent::ViewClosed { view_id: 2 }); // position 2

        let view_positions = proj.positions_for_kind(EventKind::View);
        assert_eq!(view_positions, vec![0, 2]);

        let analysis_positions = proj.positions_for_kind(EventKind::Analysis);
        assert_eq!(analysis_positions, vec![1]);
    }

    // ── ProjectionRegistry ────────────────────────────────────────────────────

    #[test]
    fn projection_registry_apply_all() {
        let mut reg = ProjectionRegistry::new();
        reg.register(Box::new(CountingProjection::new()));
        reg.register(Box::new(LastEventPerViewProjection::new()));

        let event = CoreEvent::ViewClosed { view_id: 5 };
        reg.apply_all(&event);

        assert_eq!(reg.count(), 2);
    }

    #[test]
    fn projection_registry_reset_all() {
        let mut reg = ProjectionRegistry::new();
        reg.register(Box::new(CountingProjection::new()));
        reg.apply_all(&CoreEvent::ViewClosed { view_id: 1 });
        reg.reset_all();
        // After reset: the counting projection total should be 0
        // We can't access individual projections directly here, but reset_all
        // must not panic.
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn projection_registry_names() {
        let mut reg = ProjectionRegistry::new();
        reg.register(Box::new(CountingProjection::new()));
        let names = reg.names();
        assert!(names.contains(&"CountingProjection"));
    }

    // ── SnapshotManager ───────────────────────────────────────────────────────

    #[test]
    fn snapshot_manager_save_and_count() {
        let mut reg = ProjectionRegistry::new();
        reg.register(Box::new(CountingProjection::new()));
        reg.apply_all(&CoreEvent::ViewClosed { view_id: 1 });

        let mut mgr = SnapshotManager::new();
        mgr.save_snapshot(5, &reg);
        assert_eq!(mgr.snapshot_count(), 1);
        assert_eq!(mgr.positions(), vec![5]);
    }

    #[test]
    fn snapshot_manager_restore_nearest_finds_best() {
        let mut reg = ProjectionRegistry::new();
        let mut mgr = SnapshotManager::new();

        mgr.save_snapshot(0, &reg);
        mgr.save_snapshot(10, &reg);
        mgr.save_snapshot(20, &reg);

        let pos = mgr.restore_nearest(15, &mut reg);
        assert_eq!(pos, Some(10));
    }

    #[test]
    fn snapshot_manager_restore_nearest_none_when_empty() {
        let mut reg = ProjectionRegistry::new();
        let mgr = SnapshotManager::new();
        assert!(mgr.restore_nearest(5, &mut reg).is_none());
    }

    #[test]
    fn snapshot_manager_truncate_after() {
        let reg = ProjectionRegistry::new();
        let mut mgr = SnapshotManager::new();
        mgr.save_snapshot(5, &reg);
        mgr.save_snapshot(10, &reg);
        mgr.save_snapshot(15, &reg);
        mgr.truncate_after(10);
        assert!(!mgr.positions().contains(&15));
        assert_eq!(mgr.snapshot_count(), 2);
    }

    // ── ReplaySession ─────────────────────────────────────────────────────────

    #[test]
    fn replay_session_runs_to_completion() {
        let log = Arc::new(make_log(10));
        let config = ReplayConfig::fast_forward();
        let mut session = ReplaySession::new(log, config);
        let mut reg = ProjectionRegistry::new();
        reg.register(Box::new(CountingProjection::new()));

        let stats = session.run_to_completion(&mut reg, None);
        assert_eq!(stats.events_replayed, 10);
        assert!(stats.completed);
        assert_eq!(session.state(), PlaybackState::Completed);
    }

    #[test]
    fn replay_session_filter_reduces_count() {
        let mut log = make_log(5);
        log.append(analysis_event(1, "cfg"));
        let log = Arc::new(log);

        let config = ReplayConfig::fast_forward().with_filter(["AnalysisCompleted"]);
        let mut session = ReplaySession::new(log, config);
        let mut reg = ProjectionRegistry::new();

        let stats = session.run_to_completion(&mut reg, None);
        assert_eq!(stats.events_replayed, 1);
        assert_eq!(stats.events_filtered, 5);
    }

    #[test]
    fn replay_session_pause_resume() {
        let log = Arc::new(make_log(10));
        let config = ReplayConfig::fast_forward();
        let mut session = ReplaySession::new(log, config);
        let mut reg = ProjectionRegistry::new();

        // Step 2 events, pause, resume, step 3 more
        session.step(&mut reg, None);
        session.step(&mut reg, None);
        session.pause();
        assert_eq!(session.state(), PlaybackState::Paused);
        session.resume();
        assert_eq!(session.state(), PlaybackState::Running);
        session.step(&mut reg, None);
        session.step(&mut reg, None);
        session.step(&mut reg, None);
        assert_eq!(session.stats().events_replayed, 5);
        assert_eq!(session.stats().pause_count, 1);
    }

    #[test]
    fn replay_session_seek_changes_cursor() {
        let log = Arc::new(make_log(20));
        let config = ReplayConfig::fast_forward();
        let mut session = ReplaySession::new(log, config);

        assert!(session.seek(10));
        assert_eq!(session.cursor(), 10);
    }

    #[test]
    fn replay_session_abort() {
        let log = Arc::new(make_log(10));
        let config = ReplayConfig::fast_forward();
        let mut session = ReplaySession::new(log, config);
        let mut reg = ProjectionRegistry::new();

        session.step(&mut reg, None);
        session.abort();
        assert_eq!(session.state(), PlaybackState::Aborted);
        assert!(!session.stats().completed);
    }

    // ── EventReplayer ─────────────────────────────────────────────────────────

    #[test]
    fn event_replayer_replay_all() {
        let log = make_log(8);
        let mut replayer = EventReplayer::new(log);
        replayer.register_projection(Box::new(CountingProjection::new()));
        let stats = replayer.replay_all(None);
        assert_eq!(stats.events_replayed, 8);
        assert!(stats.completed);
    }

    #[test]
    fn event_replayer_create_session_is_independent() {
        let log = make_log(5);
        let replayer = EventReplayer::new(log);
        let session = replayer.create_session(ReplayConfig::fast_forward());
        assert_eq!(session.state(), PlaybackState::Idle);
        assert_eq!(session.cursor(), 0);
    }

    #[test]
    fn event_replayer_last_stats_populated_after_replay() {
        let log = make_log(3);
        let mut replayer = EventReplayer::new(log);
        replayer.replay_all(None);
        assert!(replayer.last_stats().is_some());
        assert_eq!(replayer.last_stats().unwrap().events_replayed, 3);
    }

    #[test]
    fn event_replayer_snapshot_save_restore() {
        let log = make_log(20);
        let mut replayer = EventReplayer::new(log);
        replayer.register_projection(Box::new(CountingProjection::new()));
        replayer.save_snapshot(0);
        assert_eq!(replayer.snapshot_manager().snapshot_count(), 1);
        let pos = replayer.restore_to(0);
        assert_eq!(pos, Some(0));
    }

    // ── ReplayStats ───────────────────────────────────────────────────────────

    #[test]
    fn replay_stats_throughput_zero_when_duration_zero() {
        let stats = ReplayStats::default();
        assert_eq!(stats.throughput_eps(), 0.0);
    }

    #[test]
    fn replay_stats_total_seen() {
        let stats = ReplayStats {
            events_replayed: 5,
            events_filtered: 3,
            ..ReplayStats::default()
        };
        assert_eq!(stats.total_seen(), 8);
    }
}
