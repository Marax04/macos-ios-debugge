// rustre-plugin-api/src/hot_reload.rs
// Plugin hot-reload support: filesystem polling, state migration, graceful reload.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crate::{PluginContext, PluginResult, Version};
// Re-exported so callers of the hot-reload module can construct or match
// on plugin errors without importing the crate root separately.
pub use crate::PluginError;

// ─── Reload Event ────────────────────────────────────────────────────────────

/// Describes what happened to a plugin file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadEvent {
    Added {
        path: PathBuf,
    },
    Modified {
        path: PathBuf,
        old_modified: Option<SystemTime>,
        new_modified: SystemTime,
    },
    Removed {
        path: PathBuf,
    },
}

impl ReloadEvent {
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Added { path } | Self::Modified { path, .. } | Self::Removed { path } => path,
        }
    }

    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Added { .. } => "added",
            Self::Modified { .. } => "modified",
            Self::Removed { .. } => "removed",
        }
    }

    #[must_use]
    pub const fn is_removal(&self) -> bool {
        matches!(self, Self::Removed { .. })
    }
}

// ─── Reload Policy ───────────────────────────────────────────────────────────

/// Controls when the hot-reloader will act on a detected change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadPolicy {
    Always,
    OnChange,
    Never,
    Debounced(u64),
}

impl ReloadPolicy {
    #[must_use]
    pub const fn should_reload(&self, event: &ReloadEvent) -> bool {
        match self {
            Self::OnChange => matches!(
                event,
                ReloadEvent::Added { .. } | ReloadEvent::Modified { .. }
            ),
            Self::Never => false,
            Self::Always | Self::Debounced(_) => !event.is_removal(),
        }
    }
}

// ─── Plugin Reload State ─────────────────────────────────────────────────────

/// Tracks the reload lifecycle of a single plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginReloadState {
    Loading,
    Active,
    Unloading,
    Error(String),
    Removed,
}

impl PluginReloadState {
    #[must_use]
    pub fn is_active(&self) -> bool {
        *self == Self::Active
    }
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }
}

impl std::fmt::Display for PluginReloadState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Loading => write!(f, "loading"),
            Self::Active => write!(f, "active"),
            Self::Unloading => write!(f, "unloading"),
            Self::Error(e) => write!(f, "error({e})"),
            Self::Removed => write!(f, "removed"),
        }
    }
}

// ─── Plugin State Migrator ───────────────────────────────────────────────────

/// Allows transferring state from an old plugin instance to the new one.
pub trait PluginStateMigrator: Send + Sync {
    ///
    /// # Errors
    ///
    /// Returns an error if migration fails.
    fn migrate(
        &self,
        old_state: &[u8],
        from_version: &Version,
        to_version: &Version,
    ) -> PluginResult<Vec<u8>>;

    /// Serialise the live state of the old plugin instance.
    fn extract_state(&self, ctx: &PluginContext) -> Vec<u8>;

    ///
    /// # Errors
    ///
    /// Returns an error if restoring state fails.
    fn restore_state(&self, ctx: &mut PluginContext, state: &[u8]) -> PluginResult<()>;
}

/// Default no-op migrator — state is simply discarded on reload.
pub struct NullMigrator;

impl PluginStateMigrator for NullMigrator {
    fn migrate(&self, _old: &[u8], _from: &Version, _to: &Version) -> PluginResult<Vec<u8>> {
        Ok(Vec::new())
    }
    fn extract_state(&self, _ctx: &PluginContext) -> Vec<u8> {
        Vec::new()
    }
    fn restore_state(&self, _ctx: &mut PluginContext, _state: &[u8]) -> PluginResult<()> {
        Ok(())
    }
}

/// Key–value based migrator that copies matching context storage keys.
pub struct KeyValueMigrator {
    pub preserve_keys: Vec<String>,
}

impl KeyValueMigrator {
    #[must_use]
    pub fn new(keys: Vec<&str>) -> Self {
        Self {
            preserve_keys: keys
                .into_iter()
                .map(std::string::ToString::to_string)
                .collect(),
        }
    }
}

impl PluginStateMigrator for KeyValueMigrator {
    fn migrate(&self, old_state: &[u8], _from: &Version, _to: &Version) -> PluginResult<Vec<u8>> {
        // State format: repeated (key_len:u32, key bytes, val_len:u32, val bytes)
        Ok(old_state.to_vec())
    }

    fn extract_state(&self, ctx: &PluginContext) -> Vec<u8> {
        let mut out = Vec::new();
        for key in &self.preserve_keys {
            if let Some(val) = ctx.storage.get(key) {
                let k = key.as_bytes();
                let klen = u32::try_from(k.len()).unwrap_or(u32::MAX);
                let vlen = u32::try_from(val.len()).unwrap_or(u32::MAX);
                out.extend_from_slice(&klen.to_le_bytes());
                out.extend_from_slice(k);
                out.extend_from_slice(&vlen.to_le_bytes());
                out.extend_from_slice(val);
            }
        }
        out
    }

    fn restore_state(&self, ctx: &mut PluginContext, state: &[u8]) -> PluginResult<()> {
        let mut pos = 0;
        while pos + 8 <= state.len() {
            let klen = u32::from_le_bytes(state[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + klen > state.len() {
                break;
            }
            let key = String::from_utf8_lossy(&state[pos..pos + klen]).to_string();
            pos += klen;
            if pos + 4 > state.len() {
                break;
            }
            let vlen = u32::from_le_bytes(state[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + vlen > state.len() {
                break;
            }
            let val = state[pos..pos + vlen].to_vec();
            pos += vlen;
            ctx.storage.set(&key, val);
        }
        Ok(())
    }
}

// ─── Branch History ──────────────────────────────────────────────────────────

/// Records the history of reload events for a specific plugin path.
#[derive(Debug, Clone)]
pub struct BranchHistory {
    pub path: PathBuf,
    pub events: Vec<ReloadHistoryEntry>,
}

#[derive(Debug, Clone)]
pub struct ReloadHistoryEntry {
    pub timestamp: Instant,
    pub event_kind: String,
    pub success: bool,
    pub old_version: Option<Version>,
    pub new_version: Option<Version>,
    pub error: Option<String>,
}

impl BranchHistory {
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self {
            path,
            events: Vec::new(),
        }
    }

    pub fn record(
        &mut self,
        kind: &str,
        success: bool,
        old_ver: Option<Version>,
        new_ver: Option<Version>,
        error: Option<String>,
    ) {
        self.events.push(ReloadHistoryEntry {
            timestamp: Instant::now(),
            event_kind: kind.to_string(),
            success,
            old_version: old_ver,
            new_version: new_ver,
            error,
        });
    }

    #[must_use]
    pub fn successful_reloads(&self) -> usize {
        self.events.iter().filter(|e| e.success).count()
    }

    #[must_use]
    pub fn failed_reloads(&self) -> usize {
        self.events.iter().filter(|e| !e.success).count()
    }

    #[must_use]
    pub fn last_event(&self) -> Option<&ReloadHistoryEntry> {
        self.events.last()
    }
}

// ─── Watched File Entry ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct WatchedFile {
    path: PathBuf,
    last_modified: Option<SystemTime>,
    last_size: Option<u64>,
    reload_state: PluginReloadState,
}

impl WatchedFile {
    fn new(path: PathBuf) -> Self {
        let (modified, size) = Self::probe(&path);
        Self {
            path,
            last_modified: modified,
            last_size: size,
            reload_state: PluginReloadState::Loading,
        }
    }

    fn probe(path: &Path) -> (Option<SystemTime>, Option<u64>) {
        std::fs::metadata(path).map_or((None, None), |meta| {
            (meta.modified().ok(), Some(meta.len()))
        })
    }

    /// Check for changes and return an event if any.
    fn poll(&mut self) -> Option<ReloadEvent> {
        let (new_modified, new_size) = Self::probe(&self.path);
        if new_modified.is_none() && self.last_modified.is_some() {
            // File disappeared.
            self.last_modified = None;
            self.last_size = None;
            self.reload_state = PluginReloadState::Removed;
            return Some(ReloadEvent::Removed {
                path: self.path.clone(),
            });
        }
        new_modified?; // still missing

        if new_modified != self.last_modified || new_size != self.last_size {
            let old = self.last_modified;
            self.last_modified = new_modified;
            self.last_size = new_size;
            return Some(ReloadEvent::Modified {
                path: self.path.clone(),
                old_modified: old,
                new_modified: new_modified.unwrap(),
            });
        }
        None
    }
}

// ─── Hot Reloader ────────────────────────────────────────────────────────────

/// Watches plugin directories via filesystem polling and detects changes.
pub struct HotReloader {
    watch_dirs: Vec<PathBuf>,
    policy: ReloadPolicy,
    watched_files: HashMap<PathBuf, WatchedFile>,
    pending_events: Vec<ReloadEvent>,
    histories: HashMap<PathBuf, BranchHistory>,
    debounce_timers: HashMap<PathBuf, Instant>,
    reload_states: HashMap<PathBuf, PluginReloadState>,
    /// How often the reloader polls (minimum interval).
    pub poll_interval: Duration,
    last_poll: Option<Instant>,
}

impl HotReloader {
    #[must_use]
    pub fn new(policy: ReloadPolicy) -> Self {
        Self {
            watch_dirs: Vec::new(),
            policy,
            watched_files: HashMap::new(),
            pending_events: Vec::new(),
            histories: HashMap::new(),
            debounce_timers: HashMap::new(),
            reload_states: HashMap::new(),
            poll_interval: Duration::from_millis(500),
            last_poll: None,
        }
    }

    /// Create a reloader that polls every `interval_ms` milliseconds.
    #[must_use]
    pub fn with_interval(policy: ReloadPolicy, interval_ms: u64) -> Self {
        let mut r = Self::new(policy);
        r.poll_interval = Duration::from_millis(interval_ms);
        r
    }

    // ── Watch directories ──────────────────────────────────────────────

    /// Add a directory to watch for plugin files.
    pub fn add_watch_dir(&mut self, dir: &Path) {
        if !self.watch_dirs.iter().any(|d| d == dir) {
            self.watch_dirs.push(dir.to_path_buf());
            self.scan_dir(dir);
        }
    }

    /// Remove a directory from the watch list.
    pub fn remove_watch_dir(&mut self, dir: &Path) {
        self.watch_dirs.retain(|d| d != dir);
        // Drop watched files belonging to this directory.
        self.watched_files.retain(|p, _| !p.starts_with(dir));
    }

    fn scan_dir(&mut self, dir: &Path) {
        if !dir.exists() {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if Self::is_plugin_file(&path) && !self.watched_files.contains_key(&path) {
                let history = BranchHistory::new(path.clone());
                self.histories.insert(path.clone(), history);
                self.reload_states
                    .insert(path.clone(), PluginReloadState::Loading);
                self.watched_files
                    .insert(path.clone(), WatchedFile::new(path.clone()));
                self.pending_events.push(ReloadEvent::Added { path });
            }
        }
    }

    fn is_plugin_file(path: &Path) -> bool {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        matches!(ext, "dll" | "so" | "dylib")
    }

    // ── Polling ────────────────────────────────────────────────────────

    /// Poll all watched files. Returns events that occurred since last poll.
    pub fn poll(&mut self) -> Vec<ReloadEvent> {
        let now = Instant::now();
        if let Some(last) = self.last_poll
            && now.duration_since(last) < self.poll_interval
        {
            return Vec::new();
        }
        self.last_poll = Some(now);

        // Rescan directories for new files.
        let dirs = self.watch_dirs.clone();
        for dir in &dirs {
            self.scan_dir(dir);
        }

        // Poll existing watched files.
        let mut new_events = Vec::with_capacity(self.watched_files.len());
        for wf in self.watched_files.values_mut() {
            if let Some(event) = wf.poll() {
                new_events.push(event);
            }
        }

        // Apply debounce filtering.
        let mut result_events = Vec::new();
        for event in new_events {
            match &self.policy {
                ReloadPolicy::Debounced(delay_ms) => {
                    let delay = Duration::from_millis(*delay_ms);
                    let timer = self
                        .debounce_timers
                        .entry(event.path().to_path_buf())
                        .or_insert(now);
                    if now.duration_since(*timer) >= delay {
                        *timer = now;
                        result_events.push(event);
                    }
                }
                _ => result_events.push(event),
            }
        }

        // Drain pre-queued events (from initial scan).
        result_events.append(&mut self.pending_events);
        result_events
    }

    // ── State management ───────────────────────────────────────────────

    /// Set the reload state for a specific plugin path.
    pub fn set_state(&mut self, path: &Path, state: PluginReloadState) {
        self.reload_states.insert(path.to_path_buf(), state.clone());
        if let Some(wf) = self.watched_files.get_mut(path) {
            wf.reload_state = state;
        }
    }

    /// Get the current reload state for a plugin path.
    #[must_use]
    pub fn get_state(&self, path: &Path) -> Option<&PluginReloadState> {
        self.reload_states.get(path)
    }

    /// Return all paths currently in a given state.
    #[must_use]
    pub fn paths_in_state(&self, state: &PluginReloadState) -> Vec<&Path> {
        self.reload_states
            .iter()
            .filter(|(_, s)| *s == state)
            .map(|(p, _)| p.as_path())
            .collect()
    }

    // ── Reload orchestration ───────────────────────────────────────────

    ///
    /// # Errors
    ///
    /// Returns an error if the reload pipeline (unload/load) fails.
    pub fn reload<F, G>(
        &mut self,
        path: &Path,
        old_ctx: &mut PluginContext,
        new_ctx: &mut PluginContext,
        migrator: &dyn PluginStateMigrator,
        unload_fn: F,
        load_fn: G,
    ) -> PluginResult<()>
    where
        F: FnOnce(&mut PluginContext),
        G: FnOnce(&mut PluginContext) -> PluginResult<()>,
    {
        self.set_state(path, PluginReloadState::Unloading);

        // Step 1: Extract live state from old plugin.
        let state_bytes = migrator.extract_state(old_ctx);

        // Step 2: Unload old plugin.
        unload_fn(old_ctx);

        self.set_state(path, PluginReloadState::Loading);

        // Step 3: Migrate the state bytes.
        let old_ver = old_ctx.plugin_version().clone();
        let new_ver = new_ctx.plugin_version().clone();
        let migrated = migrator.migrate(&state_bytes, &old_ver, &new_ver)?;

        // Step 4: Load new plugin.
        if let Err(e) = load_fn(new_ctx) {
            let msg = e.to_string();
            self.set_state(path, PluginReloadState::Error(msg.clone()));
            if let Some(h) = self.histories.get_mut(path) {
                h.record("reload", false, Some(old_ver), Some(new_ver), Some(msg));
            }
            return Err(e);
        }

        // Step 5: Restore migrated state.
        migrator.restore_state(new_ctx, &migrated)?;

        self.set_state(path, PluginReloadState::Active);

        if let Some(h) = self.histories.get_mut(path) {
            h.record(
                "reload",
                true,
                Some(old_ctx.plugin_version().clone()),
                Some(new_ctx.plugin_version().clone()),
                None,
            );
        }

        Ok(())
    }

    // ── Accessors ──────────────────────────────────────────────────────

    #[must_use]
    pub fn watch_dirs(&self) -> &[PathBuf] {
        &self.watch_dirs
    }

    #[must_use]
    pub fn watched_count(&self) -> usize {
        self.watched_files.len()
    }

    #[must_use]
    pub fn history(&self, path: &Path) -> Option<&BranchHistory> {
        self.histories.get(path)
    }

    #[must_use]
    pub const fn policy(&self) -> &ReloadPolicy {
        &self.policy
    }

    pub const fn set_policy(&mut self, policy: ReloadPolicy) {
        self.policy = policy;
    }
}

// ─── Reload Manager ──────────────────────────────────────────────────────────

/// Manages multiple `HotReloader` instances for different plugin directories.
pub struct ReloadManager {
    reloaders: Vec<HotReloader>,
    event_log: Vec<ReloadEvent>,
    max_log_size: usize,
}

impl ReloadManager {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reloaders: Vec::new(),
            event_log: Vec::new(),
            max_log_size: 1000,
        }
    }

    pub fn add_reloader(&mut self, reloader: HotReloader) {
        self.reloaders.push(reloader);
    }

    /// Poll all reloaders and collect events.
    pub fn poll_all(&mut self) -> Vec<ReloadEvent> {
        let mut all = Vec::new();
        for r in &mut self.reloaders {
            all.extend(r.poll());
        }
        // Log events.
        for e in &all {
            if self.event_log.len() >= self.max_log_size {
                self.event_log.remove(0);
            }
            self.event_log.push(e.clone());
        }
        all
    }

    #[must_use]
    pub fn event_log(&self) -> &[ReloadEvent] {
        &self.event_log
    }

    pub fn clear_log(&mut self) {
        self.event_log.clear();
    }

    #[must_use]
    pub const fn reloader_count(&self) -> usize {
        self.reloaders.len()
    }
}

impl Default for ReloadManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventBus, PluginManifest, PluginPermissions};
    use std::sync::Arc;

    fn make_ctx(name: &str) -> PluginContext {
        let events = Arc::new(EventBus::new());
        let m = PluginManifest::new(name, Version::new(0, 1, 0));
        PluginContext::new(m, PluginPermissions::all(), events)
    }

    // ── ReloadEvent ──────────────────────────────────────────────────────

    #[test]
    fn test_reload_event_kind_str() {
        let e = ReloadEvent::Added {
            path: PathBuf::from("/a.so"),
        };
        assert_eq!(e.kind_str(), "added");
        let e2 = ReloadEvent::Removed {
            path: PathBuf::from("/b.so"),
        };
        assert_eq!(e2.kind_str(), "removed");
    }

    #[test]
    fn test_reload_event_path() {
        let p = PathBuf::from("/plugins/test.dll");
        let e = ReloadEvent::Added { path: p.clone() };
        assert_eq!(e.path(), p.as_path());
    }

    #[test]
    fn test_reload_event_is_removal() {
        let rem = ReloadEvent::Removed {
            path: PathBuf::from("/a.so"),
        };
        assert!(rem.is_removal());
        let add = ReloadEvent::Added {
            path: PathBuf::from("/a.so"),
        };
        assert!(!add.is_removal());
    }

    // ── ReloadPolicy ─────────────────────────────────────────────────────

    #[test]
    fn test_policy_always_reloads_added() {
        let policy = ReloadPolicy::Always;
        let e = ReloadEvent::Added {
            path: PathBuf::from("/a.so"),
        };
        assert!(policy.should_reload(&e));
    }

    #[test]
    fn test_policy_always_does_not_reload_removed() {
        let policy = ReloadPolicy::Always;
        let e = ReloadEvent::Removed {
            path: PathBuf::from("/a.so"),
        };
        assert!(!policy.should_reload(&e));
    }

    #[test]
    fn test_policy_never() {
        let policy = ReloadPolicy::Never;
        let e = ReloadEvent::Added {
            path: PathBuf::from("/a.so"),
        };
        assert!(!policy.should_reload(&e));
    }

    #[test]
    fn test_policy_on_change_modified() {
        let policy = ReloadPolicy::OnChange;
        let e = ReloadEvent::Modified {
            path: PathBuf::from("/a.so"),
            old_modified: None,
            new_modified: SystemTime::now(),
        };
        assert!(policy.should_reload(&e));
    }

    #[test]
    fn test_policy_on_change_removed() {
        let policy = ReloadPolicy::OnChange;
        let e = ReloadEvent::Removed {
            path: PathBuf::from("/a.so"),
        };
        assert!(!policy.should_reload(&e));
    }

    // ── PluginReloadState ────────────────────────────────────────────────

    #[test]
    fn test_reload_state_is_active() {
        assert!(PluginReloadState::Active.is_active());
        assert!(!PluginReloadState::Loading.is_active());
    }

    #[test]
    fn test_reload_state_is_error() {
        assert!(PluginReloadState::Error("oops".into()).is_error());
        assert!(!PluginReloadState::Active.is_error());
    }

    #[test]
    fn test_reload_state_display() {
        assert_eq!(PluginReloadState::Active.to_string(), "active");
        assert_eq!(PluginReloadState::Loading.to_string(), "loading");
        assert!(
            PluginReloadState::Error("bad".into())
                .to_string()
                .contains("bad")
        );
    }

    // ── NullMigrator ─────────────────────────────────────────────────────

    #[test]
    fn test_null_migrator_extract_empty() {
        let m = NullMigrator;
        let ctx = make_ctx("p");
        assert!(m.extract_state(&ctx).is_empty());
    }

    #[test]
    fn test_null_migrator_migrate() {
        let m = NullMigrator;
        let result = m
            .migrate(b"old_state", &Version::new(0, 1, 0), &Version::new(0, 2, 0))
            .unwrap();
        assert!(result.is_empty());
    }

    // ── KeyValueMigrator ─────────────────────────────────────────────────

    #[test]
    fn test_kv_migrator_roundtrip() {
        let migrator = KeyValueMigrator::new(vec!["key1", "key2"]);
        let mut ctx_old = make_ctx("p");
        ctx_old.storage.set("key1", b"value1".to_vec());
        ctx_old.storage.set("key2", b"value2".to_vec());
        ctx_old.storage.set("other", b"secret".to_vec());

        let state = migrator.extract_state(&ctx_old);
        let migrated = migrator
            .migrate(&state, &Version::new(0, 1, 0), &Version::new(0, 2, 0))
            .unwrap();

        let mut ctx_new = make_ctx("p");
        migrator.restore_state(&mut ctx_new, &migrated).unwrap();

        assert_eq!(ctx_new.storage.get("key1"), Some(b"value1".as_ref()));
        assert_eq!(ctx_new.storage.get("key2"), Some(b"value2".as_ref()));
        assert!(ctx_new.storage.get("other").is_none());
    }

    #[test]
    fn test_kv_migrator_missing_key() {
        let migrator = KeyValueMigrator::new(vec!["nonexistent"]);
        let ctx = make_ctx("p");
        let state = migrator.extract_state(&ctx);
        assert!(state.is_empty());
    }

    // ── BranchHistory ────────────────────────────────────────────────────

    #[test]
    fn test_branch_history_record() {
        let mut h = BranchHistory::new(PathBuf::from("/plugins/p.so"));
        h.record(
            "reload",
            true,
            Some(Version::new(0, 1, 0)),
            Some(Version::new(0, 2, 0)),
            None,
        );
        h.record("reload", false, None, None, Some("error".to_string()));
        assert_eq!(h.successful_reloads(), 1);
        assert_eq!(h.failed_reloads(), 1);
    }

    #[test]
    fn test_branch_history_last_event() {
        let mut h = BranchHistory::new(PathBuf::from("/p.so"));
        assert!(h.last_event().is_none());
        h.record("add", true, None, None, None);
        assert!(h.last_event().is_some());
        assert_eq!(h.last_event().unwrap().event_kind, "add");
    }

    // ── HotReloader ──────────────────────────────────────────────────────

    #[test]
    fn test_hot_reloader_add_watch_dir_nonexistent() {
        let mut r = HotReloader::new(ReloadPolicy::Always);
        r.add_watch_dir(Path::new("/nonexistent_path_xyz_12345"));
        assert_eq!(r.watched_count(), 0);
    }

    #[test]
    fn test_hot_reloader_watch_dirs() {
        let mut r = HotReloader::new(ReloadPolicy::OnChange);
        r.add_watch_dir(Path::new("/a"));
        r.add_watch_dir(Path::new("/b"));
        assert_eq!(r.watch_dirs().len(), 2);
    }

    #[test]
    fn test_hot_reloader_dedup_dirs() {
        let mut r = HotReloader::new(ReloadPolicy::Always);
        r.add_watch_dir(Path::new("/a"));
        r.add_watch_dir(Path::new("/a")); // duplicate
        assert_eq!(r.watch_dirs().len(), 1);
    }

    #[test]
    fn test_hot_reloader_set_get_state() {
        let mut r = HotReloader::new(ReloadPolicy::Always);
        let path = PathBuf::from("/plugins/test.so");
        r.set_state(&path, PluginReloadState::Active);
        assert_eq!(r.get_state(&path), Some(&PluginReloadState::Active));
    }

    #[test]
    fn test_hot_reloader_paths_in_state() {
        let mut r = HotReloader::new(ReloadPolicy::Always);
        let p1 = PathBuf::from("/a.so");
        let p2 = PathBuf::from("/b.so");
        r.set_state(&p1, PluginReloadState::Active);
        r.set_state(&p2, PluginReloadState::Error("fail".into()));
        let active = r.paths_in_state(&PluginReloadState::Active);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0], p1.as_path());
    }

    #[test]
    fn test_hot_reloader_remove_watch_dir() {
        let mut r = HotReloader::new(ReloadPolicy::Always);
        r.add_watch_dir(Path::new("/a"));
        r.add_watch_dir(Path::new("/b"));
        r.remove_watch_dir(Path::new("/a"));
        assert_eq!(r.watch_dirs().len(), 1);
        assert_eq!(r.watch_dirs()[0], PathBuf::from("/b"));
    }

    #[test]
    fn test_hot_reloader_set_policy() {
        let mut r = HotReloader::new(ReloadPolicy::Always);
        r.set_policy(ReloadPolicy::Never);
        assert_eq!(*r.policy(), ReloadPolicy::Never);
    }

    #[test]
    fn test_hot_reloader_reload_success() {
        let mut r = HotReloader::new(ReloadPolicy::Always);
        let path = PathBuf::from("/plugins/test.so");
        let mut old_ctx = make_ctx("test");
        old_ctx.storage.set("k", b"v".to_vec());
        let mut new_ctx = make_ctx("test");

        let result = r.reload(
            &path,
            &mut old_ctx,
            &mut new_ctx,
            &KeyValueMigrator::new(vec!["k"]),
            |_ctx| {},
            |_ctx| Ok(()),
        );
        assert!(result.is_ok());
        assert_eq!(r.get_state(&path), Some(&PluginReloadState::Active));
        assert_eq!(new_ctx.storage.get("k"), Some(b"v".as_ref()));
    }

    #[test]
    fn test_hot_reloader_reload_fail() {
        let mut r = HotReloader::new(ReloadPolicy::Always);
        let path = PathBuf::from("/plugins/bad.so");
        let mut old_ctx = make_ctx("bad");
        let mut new_ctx = make_ctx("bad");

        let result = r.reload(
            &path,
            &mut old_ctx,
            &mut new_ctx,
            &NullMigrator,
            |_| {},
            |_| Err(PluginError::InitFailed("forced failure".to_string())),
        );
        assert!(result.is_err());
        assert!(r.get_state(&path).unwrap().is_error());
    }

    // ── ReloadManager ────────────────────────────────────────────────────

    #[test]
    fn test_reload_manager_add_reloader() {
        let mut mgr = ReloadManager::new();
        mgr.add_reloader(HotReloader::new(ReloadPolicy::Always));
        mgr.add_reloader(HotReloader::new(ReloadPolicy::Never));
        assert_eq!(mgr.reloader_count(), 2);
    }

    #[test]
    fn test_reload_manager_poll_all_empty() {
        let mut mgr = ReloadManager::new();
        mgr.add_reloader(HotReloader::new(ReloadPolicy::Always));
        let events = mgr.poll_all();
        // No watch dirs → no events initially (empty pending)
        assert!(events.is_empty());
    }

    #[test]
    fn test_reload_manager_event_log() {
        let mut mgr = ReloadManager::new();
        let _ = mgr.poll_all();
        mgr.clear_log();
        assert!(mgr.event_log().is_empty());
    }
}
