//! Workspace management for the RustRE platform.
//!
//! Provides [`WorkspaceManager`], [`Workspace`], and [`WorkspaceConfig`] so
//! that multiple reverse-engineering sessions can be grouped, persisted, and
//! restored as a single unit of work.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────────────────
// WorkspaceId
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque, unique workspace identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkspaceId(String);

impl WorkspaceId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use] 
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Generate a time-based workspace ID.
    #[must_use] 
    pub fn generate() -> Self {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_micros();
        Self(format!("ws-{micros:016x}"))
    }
}

impl fmt::Display for WorkspaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkspaceConfig
// ─────────────────────────────────────────────────────────────────────────────

/// User-visible configuration options attached to a workspace.
#[derive(Debug, Clone)]
pub struct WorkspaceConfig {
    /// Human-readable name shown in the UI.
    pub name: String,
    /// Optional directory where workspace files are stored.
    pub root_path: Option<PathBuf>,
    /// Whether to auto-save on significant changes.
    pub auto_save: bool,
    /// Maximum number of undo steps retained.
    pub max_undo_steps: usize,
    /// Freeform key→value settings specific to this workspace.
    pub extra: HashMap<String, String>,
}

impl WorkspaceConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            root_path: None,
            auto_save: true,
            max_undo_steps: 100,
            extra: HashMap::new(),
        }
    }

    pub fn with_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.root_path = Some(path.into());
        self
    }

    #[must_use] 
    pub const fn with_auto_save(mut self, enabled: bool) -> Self {
        self.auto_save = enabled;
        self
    }

    #[must_use] 
    pub const fn with_max_undo(mut self, steps: usize) -> Self {
        self.max_undo_steps = steps;
        self
    }

    pub fn set(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.extra.get(key).map(String::as_str)
    }
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self::new("Untitled Workspace")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkspaceState
// ─────────────────────────────────────────────────────────────────────────────

/// Lifecycle state of a workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceState {
    /// Open and fully loaded.
    Open,
    /// In the process of being saved.
    Saving,
    /// In the process of being loaded.
    Loading,
    /// Closed but metadata still in memory.
    Closed,
    /// An error was encountered.
    Error(String),
}

impl fmt::Display for WorkspaceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Saving => write!(f, "saving"),
            Self::Loading => write!(f, "loading"),
            Self::Closed => write!(f, "closed"),
            Self::Error(msg) => write!(f, "error: {msg}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BinaryEntry — reference to a binary inside the workspace
// ─────────────────────────────────────────────────────────────────────────────

/// Record of a binary that belongs to a workspace.
#[derive(Debug, Clone)]
pub struct BinaryEntry {
    /// URI or file path of the binary.
    pub uri: String,
    /// Short label shown in the UI.
    pub label: String,
    /// Whether this binary is the primary target.
    pub is_primary: bool,
    /// Optional hash of the binary for integrity checks.
    pub sha256: Option<String>,
}

impl BinaryEntry {
    pub fn new(uri: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            label: label.into(),
            is_primary: false,
            sha256: None,
        }
    }

    #[must_use] 
    pub const fn primary(mut self) -> Self {
        self.is_primary = true;
        self
    }

    pub fn with_hash(mut self, hash: impl Into<String>) -> Self {
        self.sha256 = Some(hash.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkspaceNote
// ─────────────────────────────────────────────────────────────────────────────

/// A timestamped analyst note attached to a workspace.
#[derive(Debug, Clone)]
pub struct WorkspaceNote {
    pub id: u64,
    pub text: String,
    pub timestamp_secs: u64,
    pub author: Option<String>,
}

impl WorkspaceNote {
    fn new(id: u64, text: impl Into<String>) -> Self {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        Self { id, text: text.into(), timestamp_secs: secs, author: None }
    }

    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Workspace
// ─────────────────────────────────────────────────────────────────────────────

/// A single workspace session grouping binaries, notes, and configuration.
#[derive(Debug)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub config: WorkspaceConfig,
    state: Mutex<WorkspaceState>,
    binaries: RwLock<Vec<BinaryEntry>>,
    notes: RwLock<Vec<WorkspaceNote>>,
    note_id_counter: Mutex<u64>,
    created_at_secs: u64,
    modified_at_secs: Mutex<u64>,
}

impl Workspace {
    /// Create a new workspace with the given configuration.
    #[must_use] 
    pub fn new(id: WorkspaceId, config: WorkspaceConfig) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        Self {
            id,
            config,
            state: Mutex::new(WorkspaceState::Open),
            binaries: RwLock::new(Vec::new()),
            notes: RwLock::new(Vec::new()),
            note_id_counter: Mutex::new(1),
            created_at_secs: now,
            modified_at_secs: Mutex::new(now),
        }
    }

    // ── State ──────────────────────────────────────────────────────────────

    pub fn state(&self) -> WorkspaceState {
        self.state.lock().unwrap().clone()
    }

    pub fn is_open(&self) -> bool {
        *self.state.lock().unwrap() == WorkspaceState::Open
    }

    fn set_state(&self, s: WorkspaceState) {
        *self.state.lock().unwrap() = s;
    }

    fn touch(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        *self.modified_at_secs.lock().unwrap() = now;
    }

    // ── Timestamps ─────────────────────────────────────────────────────────

    pub const fn created_at(&self) -> u64 {
        self.created_at_secs
    }

    pub fn modified_at(&self) -> u64 {
        *self.modified_at_secs.lock().unwrap()
    }

    // ── Binaries ───────────────────────────────────────────────────────────

    /// Add a binary to this workspace.
    pub fn add_binary(&self, entry: BinaryEntry) {
        self.binaries.write().unwrap().push(entry);
        self.touch();
    }

    /// Remove a binary by URI; returns `true` if it was present.
    pub fn remove_binary(&self, uri: &str) -> bool {
        let mut guard = self.binaries.write().unwrap();
        let before = guard.len();
        guard.retain(|b| b.uri != uri);
        let removed = guard.len() < before;
        drop(guard);
        if removed {
            self.touch();
        }
        removed
    }

    /// All binaries currently associated with this workspace.
    pub fn binaries(&self) -> Vec<BinaryEntry> {
        self.binaries.read().unwrap().clone()
    }

    /// Returns the primary binary if one has been marked.
    pub fn primary_binary(&self) -> Option<BinaryEntry> {
        self.binaries.read().unwrap().iter().find(|b| b.is_primary).cloned()
    }

    /// Number of binaries.
    pub fn binary_count(&self) -> usize {
        self.binaries.read().unwrap().len()
    }

    // ── Notes ──────────────────────────────────────────────────────────────

    /// Append a note; returns the new note's ID.
    pub fn add_note(&self, text: impl Into<String>) -> u64 {
        let mut counter = self.note_id_counter.lock().unwrap();
        let id = *counter;
        *counter += 1;
        drop(counter);
        let note = WorkspaceNote::new(id, text);
        self.notes.write().unwrap().push(note);
        self.touch();
        id
    }

    /// Remove a note by ID; returns `true` if it existed.
    pub fn remove_note(&self, id: u64) -> bool {
        let mut guard = self.notes.write().unwrap();
        let before = guard.len();
        guard.retain(|n| n.id != id);
        let removed = guard.len() < before;
        drop(guard);
        if removed {
            self.touch();
        }
        removed
    }

    /// All notes in insertion order.
    pub fn notes(&self) -> Vec<WorkspaceNote> {
        self.notes.read().unwrap().clone()
    }

    /// Number of notes.
    pub fn note_count(&self) -> usize {
        self.notes.read().unwrap().len()
    }

    // ── Persistence stubs ──────────────────────────────────────────────────

    /// Simulate persisting the workspace to `path`.
    ///
    /// In a real implementation this would serialise all state to disk.
    pub fn save_to(&self, path: &Path) -> Result<(), WorkspaceError> {
        self.set_state(WorkspaceState::Saving);
        // Validate that we have a sensible path.
        if path.as_os_str().is_empty() {
            // state-machine-on-error: always restore state on every error path
            // so the workspace is never permanently stuck in `Saving`.
            self.set_state(WorkspaceState::Error("empty path".to_string()));
            return Err(WorkspaceError::SaveFailed("empty path".to_string()));
        }
        // In production: write JSON/CBOR to path.
        // Any I/O error here would previously leave the state as `Saving`
        // forever; we catch that and set Error so callers see a consistent state.
        self.touch();
        self.set_state(WorkspaceState::Open);
        Ok(())
    }

    /// Summary line for display purposes.
    pub fn summary(&self) -> String {
        format!(
            "{} [{}] — {} binaries, {} notes",
            self.config.name,
            self.state(),
            self.binary_count(),
            self.note_count(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkspaceError
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceError {
    NotFound(WorkspaceId),
    AlreadyOpen(WorkspaceId),
    SaveFailed(String),
    LoadFailed(String),
    InvalidPath(String),
}

impl fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "workspace '{id}' not found"),
            Self::AlreadyOpen(id) => write!(f, "workspace '{id}' is already open"),
            Self::SaveFailed(msg) => write!(f, "save failed: {msg}"),
            Self::LoadFailed(msg) => write!(f, "load failed: {msg}"),
            Self::InvalidPath(msg) => write!(f, "invalid path: {msg}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkspaceManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages the collection of open and recently-closed workspaces.
#[derive(Debug)]
pub struct WorkspaceManager {
    workspaces: RwLock<HashMap<WorkspaceId, Arc<Workspace>>>,
    active_id: Mutex<Option<WorkspaceId>>,
    recent: Mutex<Vec<WorkspaceId>>,
    max_recent: usize,
}

impl WorkspaceManager {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            workspaces: RwLock::new(HashMap::new()),
            active_id: Mutex::new(None),
            recent: Mutex::new(Vec::new()),
            max_recent: 10,
        }
    }

    pub const fn with_max_recent(mut self, n: usize) -> Self {
        self.max_recent = n;
        self
    }

    // ── Open / create ──────────────────────────────────────────────────────

    /// Open a new workspace from a config, assigning a fresh [`WorkspaceId`].
    pub fn open_workspace(&self, config: WorkspaceConfig) -> Arc<Workspace> {
        let id = WorkspaceId::generate();
        let ws = Arc::new(Workspace::new(id.clone(), config));
        self.workspaces.write().unwrap().insert(id.clone(), Arc::clone(&ws));
        *self.active_id.lock().unwrap() = Some(id.clone());
        self.push_recent(id);
        ws
    }

    /// Open a workspace with an explicit ID (for restored sessions).
    pub fn open_with_id(
        &self,
        id: WorkspaceId,
        config: WorkspaceConfig,
    ) -> Result<Arc<Workspace>, WorkspaceError> {
        if self.workspaces.read().unwrap().contains_key(&id) {
            return Err(WorkspaceError::AlreadyOpen(id));
        }
        let ws = Arc::new(Workspace::new(id.clone(), config));
        self.workspaces.write().unwrap().insert(id.clone(), Arc::clone(&ws));
        *self.active_id.lock().unwrap() = Some(id.clone());
        self.push_recent(id);
        Ok(ws)
    }

    // ── Close ──────────────────────────────────────────────────────────────

    /// Close the workspace with `id`.
    pub fn close_workspace(&self, id: &WorkspaceId) -> Result<(), WorkspaceError> {
        let mut guard = self.workspaces.write().unwrap();
        let ws = guard.get(id).ok_or_else(|| WorkspaceError::NotFound(id.clone()))?;
        ws.set_state(WorkspaceState::Closed);
        guard.remove(id);
        drop(guard);

        let mut active = self.active_id.lock().unwrap();
        if active.as_ref() == Some(id) {
            *active = None;
            drop(active);
        }
        Ok(())
    }

    // ── Save ───────────────────────────────────────────────────────────────

    /// Persist the workspace with `id` to `path`.
    pub fn save_workspace(
        &self,
        id: &WorkspaceId,
        path: &Path,
    ) -> Result<(), WorkspaceError> {
        
        let guard = self.workspaces.read().unwrap();
        let ws = guard
            .get(id)
            .ok_or_else(|| WorkspaceError::NotFound(id.clone()))?;
        ws.save_to(path)
    }

    // ── Query ──────────────────────────────────────────────────────────────

    /// Retrieve a workspace by ID.
    pub fn get(&self, id: &WorkspaceId) -> Option<Arc<Workspace>> {
        self.workspaces.read().unwrap().get(id).cloned()
    }

    /// The currently active workspace, if any.
    pub fn active(&self) -> Option<Arc<Workspace>> {
        let id = self.active_id.lock().unwrap().clone()?;
        self.workspaces.read().unwrap().get(&id).cloned()
    }

    /// Switch the active workspace to `id`.
    pub fn set_active(&self, id: &WorkspaceId) -> Result<(), WorkspaceError> {
        if !self.workspaces.read().unwrap().contains_key(id) {
            return Err(WorkspaceError::NotFound(id.clone()));
        }
        *self.active_id.lock().unwrap() = Some(id.clone());
        Ok(())
    }

    /// IDs of all open workspaces.
    pub fn open_ids(&self) -> Vec<WorkspaceId> {
        self.workspaces.read().unwrap().keys().cloned().collect()
    }

    /// Number of open workspaces.
    pub fn open_count(&self) -> usize {
        self.workspaces.read().unwrap().len()
    }

    /// IDs of the most recently opened workspaces (most recent first).
    pub fn recent_ids(&self) -> Vec<WorkspaceId> {
        self.recent.lock().unwrap().clone()
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    fn push_recent(&self, id: WorkspaceId) {
        let mut recent = self.recent.lock().unwrap();
        recent.retain(|r| r != &id);
        recent.insert(0, id);
        recent.truncate(self.max_recent);
    }
}

impl Default for WorkspaceManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Free-function helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Open a new workspace in `manager` with the given configuration.
pub fn open_workspace(manager: &WorkspaceManager, config: WorkspaceConfig) -> Arc<Workspace> {
    manager.open_workspace(config)
}

/// Save the workspace identified by `id` to `path`.
pub fn save_workspace(
    manager: &WorkspaceManager,
    id: &WorkspaceId,
    path: &Path,
) -> Result<(), WorkspaceError> {
    manager.save_workspace(id, path)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_and_retrieve() {
        let mgr = WorkspaceManager::new();
        let cfg = WorkspaceConfig::new("My Workspace").with_auto_save(false);
        let ws = mgr.open_workspace(cfg);
        assert!(ws.is_open());
        let retrieved = mgr.get(&ws.id).unwrap();
        assert_eq!(retrieved.id, ws.id);
    }

    #[test]
    fn active_workspace_set_on_open() {
        let mgr = WorkspaceManager::new();
        let ws = mgr.open_workspace(WorkspaceConfig::new("ws"));
        let active = mgr.active().unwrap();
        assert_eq!(active.id, ws.id);
    }

    #[test]
    fn close_workspace() {
        let mgr = WorkspaceManager::new();
        let ws = mgr.open_workspace(WorkspaceConfig::new("temp"));
        let id = ws.id.clone();
        mgr.close_workspace(&id).unwrap();
        assert!(mgr.get(&id).is_none());
        assert!(mgr.active().is_none());
    }

    #[test]
    fn close_missing_returns_error() {
        let mgr = WorkspaceManager::new();
        let id = WorkspaceId::new("nonexistent");
        assert!(matches!(
            mgr.close_workspace(&id),
            Err(WorkspaceError::NotFound(_))
        ));
    }

    #[test]
    fn save_workspace_to_valid_path() {
        let mgr = WorkspaceManager::new();
        let ws = mgr.open_workspace(WorkspaceConfig::new("save-test"));
        let path = PathBuf::from("/tmp/test.rwspc");
        assert!(mgr.save_workspace(&ws.id, &path).is_ok());
    }

    #[test]
    fn save_to_empty_path_fails() {
        let mgr = WorkspaceManager::new();
        let ws = mgr.open_workspace(WorkspaceConfig::new("save-fail"));
        let result = ws.save_to(Path::new(""));
        assert!(matches!(result, Err(WorkspaceError::SaveFailed(_))));
    }

    #[test]
    fn add_and_remove_binaries() {
        let mgr = WorkspaceManager::new();
        let ws = mgr.open_workspace(WorkspaceConfig::new("bins"));
        ws.add_binary(BinaryEntry::new("/bin/ls", "ls").primary());
        ws.add_binary(BinaryEntry::new("/bin/cat", "cat"));
        assert_eq!(ws.binary_count(), 2);
        assert_eq!(ws.primary_binary().unwrap().label, "ls");
        ws.remove_binary("/bin/cat");
        assert_eq!(ws.binary_count(), 1);
    }

    #[test]
    fn add_and_remove_notes() {
        let mgr = WorkspaceManager::new();
        let ws = mgr.open_workspace(WorkspaceConfig::new("notes"));
        let id1 = ws.add_note("First note");
        let id2 = ws.add_note("Second note");
        assert_eq!(ws.note_count(), 2);
        ws.remove_note(id1);
        assert_eq!(ws.note_count(), 1);
        assert_eq!(ws.notes()[0].text, "Second note");
        let _ = id2;
    }

    #[test]
    fn recent_ids_track_opens() {
        let mgr = WorkspaceManager::new().with_max_recent(3);
        for n in 0..4 {
            mgr.open_workspace(WorkspaceConfig::new(format!("ws{n}")));
        }
        let recent = mgr.recent_ids();
        // Most recent should be first.
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn set_active_switches_workspace() {
        let mgr = WorkspaceManager::new();
        let ws1 = mgr.open_workspace(WorkspaceConfig::new("first"));
        let ws2 = mgr.open_workspace(WorkspaceConfig::new("second"));
        mgr.set_active(&ws1.id).unwrap();
        assert_eq!(mgr.active().unwrap().id, ws1.id);
        mgr.set_active(&ws2.id).unwrap();
        assert_eq!(mgr.active().unwrap().id, ws2.id);
    }

    #[test]
    fn workspace_config_extra_settings() {
        let cfg = WorkspaceConfig::new("cfg-test")
            .set("theme", "dark")
            .set("zoom", "150");
        assert_eq!(cfg.get("theme"), Some("dark"));
        assert_eq!(cfg.get("zoom"), Some("150"));
        assert!(cfg.get("missing").is_none());
    }

    #[test]
    fn workspace_summary_string() {
        let ws = Workspace::new(
            WorkspaceId::new("test"),
            WorkspaceConfig::new("Summary Test"),
        );
        ws.add_binary(BinaryEntry::new("/tmp/a", "a"));
        ws.add_note("note1");
        let s = ws.summary();
        assert!(s.contains("Summary Test"));
        assert!(s.contains("1 binaries"));
        assert!(s.contains("1 notes"));
    }

    #[test]
    fn free_functions_work() {
        let mgr = WorkspaceManager::new();
        let ws = open_workspace(&mgr, WorkspaceConfig::new("free-fn"));
        let path = PathBuf::from("/tmp/free.rwspc");
        assert!(save_workspace(&mgr, &ws.id, &path).is_ok());
    }
}
