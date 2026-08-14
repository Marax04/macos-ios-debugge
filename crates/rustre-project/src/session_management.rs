//! Session management for RustRE projects — **in-memory lifecycle layer**.
//!
//! # Layer distinction
//! This module manages the runtime lifecycle of open sessions: state
//! transitions (active / background / suspended / closed), locking,
//! in-memory snapshots, history logging, and multi-session coordination
//! ([`MultiSession`]).  It does **not** own any SQLite tables.
//!
//! The **SQLite persistence layer** (save/load sessions across restarts) lives
//! in [`crate::session`].  The **annotation-focused extended DB** with
//! undo/redo and collaboration change tracking lives in
//! [`crate::project_db_extended`].
//!
//! This module's types are the ones re-exported at the crate root.
//!
//! Provides `SessionManagement`, `ActiveSession`, `SessionRestore`,
//! `SessionHistory`, `SessionExport`, and `MultiSession` for
//! persisting, restoring, and managing multiple concurrent
//! analysis sessions.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
pub use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn gen_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(1);
    format!("sess-{:016x}", CTR.fetch_add(1, Ordering::Relaxed))
}

// ── SessionError ──────────────────────────────────────────────────────────────

/// Errors from the session management subsystem.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session not found: {0}")]
    NotFound(String),
    #[error("session already exists: {0}")]
    AlreadyExists(String),
    #[error("session is locked by another user: {0}")]
    Locked(String),
    #[error("session restore failed: {0}")]
    RestoreFailed(String),
    #[error("export failed: {0}")]
    ExportFailed(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("max session limit ({0}) reached")]
    MaxSessionsReached(usize),
}

pub type SessionResult<T> = Result<T, SessionError>;

// ── SessionState ──────────────────────────────────────────────────────────────

/// High-level state of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session is open and active.
    Active,
    /// Session is open but in the background.
    Background,
    /// Session has been suspended to disk.
    Suspended,
    /// Session has been closed and archived.
    Closed,
    /// Session encountered an error.
    Error,
}

impl SessionState {
    /// Return `true` if the session is usable (active or background).
    #[must_use]
    pub fn is_usable(self) -> bool {
        matches!(self, Self::Active | Self::Background)
    }

    /// Return `true` if the session is closed/suspended.
    #[must_use]
    pub fn is_dormant(self) -> bool {
        matches!(self, Self::Suspended | Self::Closed)
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Active => "active",
            Self::Background => "background",
            Self::Suspended => "suspended",
            Self::Closed => "closed",
            Self::Error => "error",
        };
        f.write_str(s)
    }
}

// ── OpenView ──────────────────────────────────────────────────────────────────

/// A view open within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenView {
    /// Binary or file ID.
    pub binary_id: u64,
    /// Display title.
    pub title: String,
    /// Last focused address.
    pub cursor_addr: Option<u64>,
    /// Scroll position.
    pub scroll_pos: Option<u64>,
    /// Whether this is the primary (focused) view.
    pub is_primary: bool,
}

impl OpenView {
    /// Create a minimal open view.
    #[must_use]
    pub fn new(binary_id: u64, title: impl Into<String>) -> Self {
        Self {
            binary_id,
            title: title.into(),
            cursor_addr: None,
            scroll_pos: None,
            is_primary: false,
        }
    }

    /// Set the cursor address.
    #[must_use]
    pub fn with_cursor(mut self, addr: u64) -> Self {
        self.cursor_addr = Some(addr);
        self
    }
}

// ── SessionBookmark ───────────────────────────────────────────────────────────

/// A user-defined bookmark stored in a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBookmark {
    /// Bookmark label.
    pub label: String,
    /// Binary ID.
    pub binary_id: u64,
    /// Address.
    pub addr: u64,
    /// Optional colour.
    pub color: String,
    /// Timestamp when bookmark was created.
    pub created_at: u64,
}

impl SessionBookmark {
    /// Create a new bookmark.
    #[must_use]
    pub fn new(label: impl Into<String>, binary_id: u64, addr: u64) -> Self {
        Self {
            label: label.into(),
            binary_id,
            addr,
            color: "#ffff00".into(),
            created_at: unix_now(),
        }
    }
}

// ── ActiveSession ─────────────────────────────────────────────────────────────

/// A live analysis session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSession {
    /// Unique session identifier.
    pub id: String,
    /// Human-readable session name.
    pub name: String,
    /// Path to the project this session is associated with.
    pub project_path: PathBuf,
    /// Current state.
    pub state: SessionState,
    /// Open binary views.
    pub open_views: Vec<OpenView>,
    /// Session bookmarks.
    pub bookmarks: Vec<SessionBookmark>,
    /// Active script names.
    pub active_scripts: Vec<String>,
    /// Session-level notes.
    pub notes: String,
    /// Key-value session metadata.
    pub metadata: HashMap<String, String>,
    /// Session creation timestamp.
    pub created_at: u64,
    /// Last access timestamp.
    pub last_accessed: u64,
    /// Owner/user label.
    pub owner: Option<String>,
    /// Lock token (if session is locked).
    pub lock_token: Option<String>,
}

impl ActiveSession {
    /// Create a new session.
    #[must_use]
    pub fn new(name: impl Into<String>, project_path: impl Into<PathBuf>) -> Self {
        let now = unix_now();
        Self {
            id: gen_id(),
            name: name.into(),
            project_path: project_path.into(),
            state: SessionState::Active,
            open_views: Vec::new(),
            bookmarks: Vec::new(),
            active_scripts: Vec::new(),
            notes: String::new(),
            metadata: HashMap::new(),
            created_at: now,
            last_accessed: now,
            owner: None,
            lock_token: None,
        }
    }

    /// Open a binary view in this session.
    pub fn open_view(&mut self, view: OpenView) {
        if !self
            .open_views
            .iter()
            .any(|v| v.binary_id == view.binary_id)
        {
            self.open_views.push(view);
        }
        self.touch();
    }

    /// Close a binary view.
    pub fn close_view(&mut self, binary_id: u64) -> bool {
        let before = self.open_views.len();
        self.open_views.retain(|v| v.binary_id != binary_id);
        self.touch();
        self.open_views.len() < before
    }

    /// Add a bookmark.
    pub fn add_bookmark(&mut self, bm: SessionBookmark) {
        self.bookmarks.push(bm);
        self.touch();
    }

    /// Remove a bookmark by label.
    pub fn remove_bookmark(&mut self, label: &str) -> bool {
        let before = self.bookmarks.len();
        self.bookmarks.retain(|b| b.label != label);
        self.bookmarks.len() < before
    }

    /// Activate a script.
    pub fn activate_script(&mut self, name: impl Into<String>) {
        let n = name.into();
        if !self.active_scripts.contains(&n) {
            self.active_scripts.push(n);
        }
        self.touch();
    }

    /// Deactivate a script.
    pub fn deactivate_script(&mut self, name: &str) -> bool {
        let before = self.active_scripts.len();
        self.active_scripts.retain(|s| s != name);
        self.active_scripts.len() < before
    }

    /// Set a metadata key.
    pub fn set_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
        self.touch();
    }

    /// Touch the last_accessed timestamp.
    pub fn touch(&mut self) {
        self.last_accessed = unix_now();
    }

    /// Lock the session with a token.
    pub fn lock(&mut self, token: impl Into<String>) {
        self.lock_token = Some(token.into());
    }

    /// Unlock the session if the token matches.
    pub fn unlock(&mut self, token: &str) -> bool {
        if self.lock_token.as_deref() == Some(token) {
            self.lock_token = None;
            true
        } else {
            false
        }
    }

    /// Return `true` if this session is locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.lock_token.is_some()
    }

    /// Age of this session in seconds.
    #[must_use]
    pub fn age_secs(&self) -> u64 {
        unix_now().saturating_sub(self.created_at)
    }

    /// Idle time since last access.
    #[must_use]
    pub fn idle_secs(&self) -> u64 {
        unix_now().saturating_sub(self.last_accessed)
    }

    /// Summarise this session.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Session[id={}, name='{}', state={}, views={}, bookmarks={}]",
            self.id,
            self.name,
            self.state,
            self.open_views.len(),
            self.bookmarks.len(),
        )
    }
}

// ── SessionRestore ────────────────────────────────────────────────────────────

/// A saved snapshot of a session for restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    /// Source session ID.
    pub session_id: String,
    /// Snapshot creation timestamp.
    pub created_at: u64,
    /// Serialised session data.
    pub data: String,
    /// Description.
    pub description: Option<String>,
    /// Snapshot index (1-based).
    pub index: u32,
}

/// Manages session snapshots and restoration.
#[derive(Debug, Default)]
pub struct SessionRestore {
    snapshots: HashMap<String, Vec<SessionSnapshot>>,
    max_snapshots: usize,
}

/// Configuration for session restore behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRestoreConfig {
    /// Maximum snapshots to keep per session.
    pub max_snapshots_per_session: usize,
    /// Whether to auto-snapshot on close.
    pub auto_snapshot_on_close: bool,
    /// Whether to restore the last snapshot automatically on open.
    pub auto_restore_on_open: bool,
    /// Snapshot compression (mock, always none for now).
    pub compress: bool,
}

impl Default for SessionRestoreConfig {
    fn default() -> Self {
        Self {
            max_snapshots_per_session: 10,
            auto_snapshot_on_close: true,
            auto_restore_on_open: false,
            compress: false,
        }
    }
}

impl SessionRestoreConfig {
    /// Create with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate the config.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.max_snapshots_per_session > 0
    }
}

impl SessionRestore {
    /// Create a new restore manager with a given snapshot limit.
    #[must_use]
    pub fn with_limit(max_snapshots: usize) -> Self {
        Self {
            snapshots: HashMap::new(),
            max_snapshots: max_snapshots.max(1),
        }
    }

    /// Create with a default limit of 10.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limit(10)
    }

    /// Save a snapshot of `session`.
    pub fn save(
        &mut self,
        session: &ActiveSession,
        description: Option<&str>,
    ) -> SessionResult<SessionSnapshot> {
        let data = serde_json::to_string(session)
            .map_err(|e| SessionError::Serialization(e.to_string()))?;
        let snaps = self.snapshots.entry(session.id.clone()).or_default();
        let index = snaps.iter().map(|s| s.index).max().unwrap_or(0) + 1;
        let snap = SessionSnapshot {
            session_id: session.id.clone(),
            created_at: unix_now(),
            data,
            description: description.map(str::to_string),
            index,
        };
        snaps.push(snap.clone());
        if snaps.len() > self.max_snapshots {
            snaps.remove(0);
        }
        Ok(snap)
    }

    /// Restore the most recent snapshot for a session ID.
    pub fn restore_latest(&self, session_id: &str) -> SessionResult<ActiveSession> {
        let snaps = self
            .snapshots
            .get(session_id)
            .ok_or_else(|| SessionError::NotFound(session_id.to_string()))?;
        let snap = snaps
            .last()
            .ok_or_else(|| SessionError::RestoreFailed("no snapshots".into()))?;
        serde_json::from_str(&snap.data).map_err(|e| SessionError::RestoreFailed(e.to_string()))
    }

    /// Restore a specific snapshot by index.
    pub fn restore_by_index(&self, session_id: &str, index: u32) -> SessionResult<ActiveSession> {
        let snaps = self
            .snapshots
            .get(session_id)
            .ok_or_else(|| SessionError::NotFound(session_id.to_string()))?;
        let snap = snaps
            .iter()
            .find(|s| s.index == index)
            .ok_or_else(|| SessionError::RestoreFailed(format!("snapshot {index} not found")))?;
        serde_json::from_str(&snap.data).map_err(|e| SessionError::RestoreFailed(e.to_string()))
    }

    /// List snapshots for a session.
    #[must_use]
    pub fn list(&self, session_id: &str) -> Vec<&SessionSnapshot> {
        self.snapshots
            .get(session_id)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Clear all snapshots for a session.
    pub fn clear(&mut self, session_id: &str) -> usize {
        self.snapshots
            .remove(session_id)
            .map_or(0, |v| v.len())
    }

    /// Return the total number of stored snapshots.
    #[must_use]
    pub fn total_snapshots(&self) -> usize {
        self.snapshots.values().map(std::vec::Vec::len).sum()
    }
}

// ── SessionHistory ────────────────────────────────────────────────────────────

/// An entry in the session history log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub timestamp: u64,
    pub session_id: String,
    pub action: String,
    pub detail: String,
}

/// Per-project session history log.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SessionHistory {
    pub entries: Vec<HistoryEntry>,
    pub max_entries: usize,
}

impl SessionHistory {
    /// Create with a given capacity.
    #[must_use]
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries: max_entries.max(1),
        }
    }

    /// Create with a default capacity of 1 000.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(1_000)
    }

    /// Record an event.
    pub fn record(
        &mut self,
        session_id: impl Into<String>,
        action: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.entries.push(HistoryEntry {
            timestamp: unix_now(),
            session_id: session_id.into(),
            action: action.into(),
            detail: detail.into(),
        });
        if self.entries.len() > self.max_entries {
            self.entries.remove(0);
        }
    }

    /// Return events for a specific session.
    #[must_use]
    pub fn for_session(&self, session_id: &str) -> Vec<&HistoryEntry> {
        self.entries
            .iter()
            .filter(|e| e.session_id == session_id)
            .collect()
    }

    /// Return events matching an action type.
    #[must_use]
    pub fn by_action(&self, action: &str) -> Vec<&HistoryEntry> {
        self.entries.iter().filter(|e| e.action == action).collect()
    }

    /// Number of history entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear the history.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ── SessionExport ─────────────────────────────────────────────────────────────

/// Export format for session data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    Json,
    Toml,
    CompressedJson,
}

impl ExportFormat {
    /// Return the file extension for this format.
    #[must_use]
    pub fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Toml => "toml",
            Self::CompressedJson => "json.gz",
        }
    }
}

/// Session export/import utilities.
#[derive(Debug, Default)]
pub struct SessionExport;

impl SessionExport {
    /// Create a new exporter.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Serialise a session to JSON bytes.
    pub fn to_json(&self, session: &ActiveSession) -> SessionResult<Vec<u8>> {
        serde_json::to_vec_pretty(session).map_err(|e| SessionError::ExportFailed(e.to_string()))
    }

    /// Deserialise a session from JSON bytes.
    pub fn from_json(&self, data: &[u8]) -> SessionResult<ActiveSession> {
        serde_json::from_slice(data).map_err(|e| SessionError::ExportFailed(e.to_string()))
    }

    /// Serialise to JSON string.
    pub fn to_json_string(&self, session: &ActiveSession) -> SessionResult<String> {
        serde_json::to_string_pretty(session).map_err(|e| SessionError::ExportFailed(e.to_string()))
    }

    /// Deserialise from JSON string.
    pub fn from_json_string(&self, s: &str) -> SessionResult<ActiveSession> {
        serde_json::from_str(s).map_err(|e| SessionError::ExportFailed(e.to_string()))
    }

    /// Round-trip a session: serialise and immediately deserialise.
    pub fn round_trip(&self, session: &ActiveSession) -> SessionResult<ActiveSession> {
        let bytes = self.to_json(session)?;
        self.from_json(&bytes)
    }

    /// Validate that exported data can be re-imported.
    #[must_use] 
 
        pub fn validate(&self, data: &[u8]) -> bool {
        serde_json::from_slice::<ActiveSession>(data).is_ok()
    }
}

// ── MultiSession ──────────────────────────────────────────────────────────────

/// Manager for multiple concurrent sessions.
#[derive(Debug)]
pub struct MultiSession {
    sessions: Arc<Mutex<HashMap<String, ActiveSession>>>,
    max_sessions: usize,
    history: SessionHistory,
    restore: SessionRestore,
}

impl Default for MultiSession {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiSession {
    /// Create a new multi-session manager.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(32, 20)
    }

    /// Create with custom limits.
    #[must_use]
    pub fn with_limits(max_sessions: usize, max_snapshots_per_session: usize) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            max_sessions,
            history: SessionHistory::new(),
            restore: SessionRestore::with_limit(max_snapshots_per_session),
        }
    }

    /// Create a new session and register it.
    pub fn create(
        &mut self,
        name: impl Into<String>,
        project_path: impl Into<PathBuf>,
    ) -> SessionResult<String> {
        let mut guard = self.sessions.lock().unwrap();
        if guard.len() >= self.max_sessions {
            return Err(SessionError::MaxSessionsReached(self.max_sessions));
        }
        let session = ActiveSession::new(name, project_path);
        let id = session.id.clone();
        self.history.record(&id, "created", &session.name);
        guard.insert(id.clone(), session);
        Ok(id)
    }

    /// Get a clone of a session.
    pub fn get(&self, id: &str) -> SessionResult<ActiveSession> {
        self.sessions
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| SessionError::NotFound(id.to_string()))
    }

    /// Update a session in-place.
    pub fn update(&self, id: &str, f: impl FnOnce(&mut ActiveSession)) -> SessionResult<()> {
        let mut guard = self.sessions.lock().unwrap();
        let session = guard
            .get_mut(id)
            .ok_or_else(|| SessionError::NotFound(id.to_string()))?;
        f(session);
        Ok(())
    }

    /// Remove a session.
    pub fn remove(&mut self, id: &str) -> SessionResult<ActiveSession> {
        self.sessions
            .lock()
            .unwrap()
            .remove(id)
            .ok_or_else(|| SessionError::NotFound(id.to_string()))
            .inspect(|s| {
                self.history.record(id, "closed", &s.name);
            })
    }

    /// Suspend a session (change state but keep in memory).
    pub fn suspend(&self, id: &str) -> SessionResult<()> {
        self.update(id, |s| s.state = SessionState::Suspended)
    }

    /// Resume a suspended session.
    pub fn resume(&self, id: &str) -> SessionResult<()> {
        self.update(id, |s| {
            if s.state == SessionState::Suspended {
                s.state = SessionState::Active;
            }
            s.touch();
        })
    }

    /// Take a snapshot of a session.
    pub fn snapshot(
        &mut self,
        id: &str,
        description: Option<&str>,
    ) -> SessionResult<SessionSnapshot> {
        let session = self.get(id)?;
        let snap = self.restore.save(&session, description)?;
        self.history
            .record(id, "snapshot", format!("index={}", snap.index));
        Ok(snap)
    }

    /// Restore a session from its latest snapshot.
    pub fn restore_latest(&mut self, id: &str) -> SessionResult<()> {
        let restored = self.restore.restore_latest(id)?;
        let mut guard = self.sessions.lock().unwrap();
        guard.insert(id.to_string(), restored);
        self.history.record(id, "restored", "latest");
        Ok(())
    }

    /// List all session IDs, sorted.
    #[must_use]
    pub fn session_ids(&self) -> Vec<String> {
        let mut ids: Vec<_> = self.sessions.lock().unwrap().keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Number of sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// Return sessions in a given state.
    #[must_use]
    pub fn sessions_in_state(&self, state: SessionState) -> Vec<ActiveSession> {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .filter(|s| s.state == state)
            .cloned()
            .collect()
    }

    /// Return all sessions idle for more than `secs`.
    #[must_use]
    pub fn idle_sessions(&self, secs: u64) -> Vec<String> {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .filter(|s| s.idle_secs() >= secs)
            .map(|s| s.id.clone())
            .collect()
    }

    /// Return a reference to the history.
    #[must_use]
    pub fn history(&self) -> &SessionHistory {
        &self.history
    }

    /// Return a reference to the restore manager.
    #[must_use]
    pub fn restore_manager(&self) -> &SessionRestore {
        &self.restore
    }
}

// ── SessionStats ──────────────────────────────────────────────────────────────

/// Aggregate statistics for a `MultiSession` instance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionStats {
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub suspended_sessions: usize,
    pub total_open_views: usize,
    pub total_bookmarks: usize,
    pub total_snapshots: usize,
    pub sessions_with_scripts: usize,
}

impl SessionStats {
    /// Compute stats from a `MultiSession`.
    #[must_use]
    pub fn from_multi(ms: &MultiSession) -> Self {
        let guard = ms.sessions.lock().unwrap();
        let active = guard
            .values()
            .filter(|s| s.state == SessionState::Active)
            .count();
        let suspended = guard
            .values()
            .filter(|s| s.state == SessionState::Suspended)
            .count();
        let views: usize = guard.values().map(|s| s.open_views.len()).sum();
        let bookmarks: usize = guard.values().map(|s| s.bookmarks.len()).sum();
        let with_scripts = guard
            .values()
            .filter(|s| !s.active_scripts.is_empty())
            .count();
        let snaps = ms.restore_manager().total_snapshots();
        Self {
            total_sessions: guard.len(),
            active_sessions: active,
            suspended_sessions: suspended,
            total_open_views: views,
            total_bookmarks: bookmarks,
            total_snapshots: snaps,
            sessions_with_scripts: with_scripts,
        }
    }

    /// Return `true` if there are any active sessions.
    #[must_use]
    pub fn has_active(&self) -> bool {
        self.active_sessions > 0
    }
}

// ── SessionSearchQuery ────────────────────────────────────────────────────────

/// Query for searching across sessions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionSearchQuery {
    /// Filter by session name substring.
    pub name_contains: Option<String>,
    /// Filter by state.
    pub state: Option<SessionState>,
    /// Filter by owner.
    pub owner: Option<String>,
    /// Filter to sessions with open views for this binary ID.
    pub has_binary: Option<u64>,
    /// Filter by metadata key presence.
    pub has_meta_key: Option<String>,
}

impl SessionSearchQuery {
    /// Create an empty query.
    #[must_use]
    pub fn all() -> Self {
        Self::default()
    }

    /// Filter by name substring.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name_contains = Some(name.into());
        self
    }

    /// Filter by state.
    #[must_use]
    pub fn in_state(mut self, state: SessionState) -> Self {
        self.state = Some(state);
        self
    }

    /// Apply this query to a list of sessions.
    #[must_use]
    pub fn apply<'a>(&self, sessions: &'a [ActiveSession]) -> Vec<&'a ActiveSession> {
        sessions
            .iter()
            .filter(|s| {
                if let Some(n) = &self.name_contains
                    && !s.name.contains(n.as_str()) {
                        return false;
                    }
                if let Some(st) = &self.state
                    && s.state != *st {
                        return false;
                    }
                if let Some(owner) = &self.owner
                    && s.owner.as_deref() != Some(owner.as_str()) {
                        return false;
                    }
                if let Some(bid) = self.has_binary
                    && !s.open_views.iter().any(|v| v.binary_id == bid) {
                        return false;
                    }
                if let Some(key) = &self.has_meta_key
                    && !s.metadata.contains_key(key) {
                        return false;
                    }
                true
            })
            .collect()
    }
}

/// Top-level session management coordinator.
#[derive(Debug)]
pub struct SessionManagement {
    multi: MultiSession,
    export: SessionExport,
}

impl Default for SessionManagement {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManagement {
    /// Create a new session management coordinator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            multi: MultiSession::new(),
            export: SessionExport::new(),
        }
    }

    /// Create a session.
    pub fn create_session(&mut self, name: &str, project: &Path) -> SessionResult<String> {
        self.multi.create(name, project)
    }

    /// Get a session.
    pub fn get_session(&self, id: &str) -> SessionResult<ActiveSession> {
        self.multi.get(id)
    }

    /// Export a session to JSON.
    pub fn export_session(&self, id: &str) -> SessionResult<String> {
        let session = self.get_session(id)?;
        self.export.to_json_string(&session)
    }

    /// Import a session from JSON.
    pub fn import_session(&mut self, json: &str) -> SessionResult<String> {
        let session = self.export.from_json_string(json)?;
        let id = session.id.clone();
        {
            let mut guard = self.multi.sessions.lock().unwrap();
            guard.insert(id.clone(), session);
        }
        Ok(id)
    }

    /// Snapshot a session.
    pub fn snapshot(&mut self, id: &str) -> SessionResult<SessionSnapshot> {
        self.multi.snapshot(id, None)
    }

    /// Remove a session.
    pub fn remove_session(&mut self, id: &str) -> SessionResult<()> {
        self.multi.remove(id).map(|_| ())
    }

    /// List all session IDs.
    #[must_use]
    pub fn list_sessions(&self) -> Vec<String> {
        self.multi.session_ids()
    }

    /// Number of sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.multi.session_count()
    }

    /// Access the underlying multi-session manager.
    #[must_use]
    pub fn multi(&self) -> &MultiSession {
        &self.multi
    }

    /// Access the multi-session manager mutably.
    pub fn multi_mut(&mut self) -> &mut MultiSession {
        &mut self.multi
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn proj() -> PathBuf {
        PathBuf::from("/tmp/test_project")
    }

    fn make_session(name: &str) -> ActiveSession {
        ActiveSession::new(name, proj())
    }

    // ── SessionState ─────────────────────────────────────────────────────────

    #[test]
    fn test_state_usable() {
        assert!(SessionState::Active.is_usable());
        assert!(SessionState::Background.is_usable());
        assert!(!SessionState::Suspended.is_usable());
        assert!(!SessionState::Closed.is_usable());
    }

    #[test]
    fn test_state_dormant() {
        assert!(SessionState::Suspended.is_dormant());
        assert!(SessionState::Closed.is_dormant());
        assert!(!SessionState::Active.is_dormant());
    }

    #[test]
    fn test_state_display() {
        assert_eq!(SessionState::Active.to_string(), "active");
        assert_eq!(SessionState::Error.to_string(), "error");
    }

    // ── OpenView ─────────────────────────────────────────────────────────────

    #[test]
    fn test_open_view_new() {
        let v = OpenView::new(1, "binary.exe").with_cursor(0x1400);
        assert_eq!(v.binary_id, 1);
        assert_eq!(v.cursor_addr, Some(0x1400));
    }

    // ── SessionBookmark ───────────────────────────────────────────────────────

    #[test]
    fn test_session_bookmark_new() {
        let bm = SessionBookmark::new("entry", 1, 0x1400);
        assert_eq!(bm.label, "entry");
        assert_eq!(bm.addr, 0x1400);
    }

    // ── ActiveSession ─────────────────────────────────────────────────────────

    #[test]
    fn test_session_created_state() {
        let s = make_session("test");
        assert_eq!(s.state, SessionState::Active);
        assert!(!s.id.is_empty());
    }

    #[test]
    fn test_session_open_view() {
        let mut s = make_session("test");
        s.open_view(OpenView::new(1, "binary"));
        assert_eq!(s.open_views.len(), 1);
    }

    #[test]
    fn test_session_open_view_dedup() {
        let mut s = make_session("test");
        s.open_view(OpenView::new(1, "binary"));
        s.open_view(OpenView::new(1, "binary"));
        assert_eq!(s.open_views.len(), 1);
    }

    #[test]
    fn test_session_close_view() {
        let mut s = make_session("test");
        s.open_view(OpenView::new(1, "binary"));
        assert!(s.close_view(1));
        assert!(s.open_views.is_empty());
    }

    #[test]
    fn test_session_add_and_remove_bookmark() {
        let mut s = make_session("test");
        s.add_bookmark(SessionBookmark::new("entry", 1, 0x1400));
        assert_eq!(s.bookmarks.len(), 1);
        assert!(s.remove_bookmark("entry"));
        assert!(s.bookmarks.is_empty());
    }

    #[test]
    fn test_session_activate_deactivate_script() {
        let mut s = make_session("test");
        s.activate_script("analysis.py");
        assert!(s.active_scripts.contains(&"analysis.py".to_string()));
        assert!(s.deactivate_script("analysis.py"));
        assert!(s.active_scripts.is_empty());
    }

    #[test]
    fn test_session_metadata() {
        let mut s = make_session("test");
        s.set_meta("tool", "RustRE");
        assert_eq!(s.metadata.get("tool").map(String::as_str), Some("RustRE"));
    }

    #[test]
    fn test_session_lock_unlock() {
        let mut s = make_session("test");
        s.lock("token123");
        assert!(s.is_locked());
        assert!(!s.unlock("wrong_token"));
        assert!(s.unlock("token123"));
        assert!(!s.is_locked());
    }

    #[test]
    fn test_session_summary() {
        let s = make_session("MySession");
        let sum = s.summary();
        assert!(sum.contains("MySession"));
        assert!(sum.contains("active"));
    }

    // ── SessionRestore ────────────────────────────────────────────────────────

    #[test]
    fn test_restore_save_and_list() {
        let mut r = SessionRestore::new();
        let s = make_session("test");
        r.save(&s, None).unwrap();
        assert_eq!(r.list(&s.id).len(), 1);
    }

    #[test]
    fn test_restore_restore_latest() {
        let mut r = SessionRestore::new();
        let mut s = make_session("test");
        s.notes = "original notes".into();
        r.save(&s, None).unwrap();
        let restored = r.restore_latest(&s.id).unwrap();
        assert_eq!(restored.notes, "original notes");
    }

    #[test]
    fn test_restore_by_index() {
        let mut r = SessionRestore::new();
        let s = make_session("test");
        let snap = r.save(&s, Some("snap1")).unwrap();
        let restored = r.restore_by_index(&s.id, snap.index).unwrap();
        assert_eq!(restored.id, s.id);
    }

    #[test]
    fn test_restore_pruning() {
        let mut r = SessionRestore::with_limit(3);
        let s = make_session("test");
        for _ in 0..5 {
            r.save(&s, None).unwrap();
        }
        assert_eq!(r.list(&s.id).len(), 3);
    }

    #[test]
    fn test_restore_clear() {
        let mut r = SessionRestore::new();
        let s = make_session("test");
        r.save(&s, None).unwrap();
        assert_eq!(r.clear(&s.id), 1);
        assert_eq!(r.total_snapshots(), 0);
    }

    #[test]
    fn test_restore_not_found() {
        let r = SessionRestore::new();
        assert!(matches!(
            r.restore_latest("missing"),
            Err(SessionError::NotFound(_))
        ));
    }

    // ── SessionHistory ────────────────────────────────────────────────────────

    #[test]
    fn test_history_record() {
        let mut h = SessionHistory::new();
        h.record("sess-1", "open", "binary.exe");
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn test_history_for_session() {
        let mut h = SessionHistory::new();
        h.record("sess-1", "open", "a");
        h.record("sess-2", "open", "b");
        h.record("sess-1", "close", "a");
        assert_eq!(h.for_session("sess-1").len(), 2);
    }

    #[test]
    fn test_history_by_action() {
        let mut h = SessionHistory::new();
        h.record("s1", "created", "");
        h.record("s2", "created", "");
        h.record("s1", "closed", "");
        assert_eq!(h.by_action("created").len(), 2);
    }

    #[test]
    fn test_history_pruning() {
        let mut h = SessionHistory::with_capacity(3);
        for i in 0..5 {
            h.record("s", "action", format!("detail-{i}"));
        }
        assert_eq!(h.len(), 3);
    }

    // ── SessionExport ─────────────────────────────────────────────────────────

    #[test]
    fn test_export_round_trip() {
        let exp = SessionExport::new();
        let original = make_session("export_test");
        let restored = exp.round_trip(&original).unwrap();
        assert_eq!(restored.name, original.name);
    }

    #[test]
    fn test_export_to_json_string() {
        let exp = SessionExport::new();
        let s = make_session("test");
        let json = exp.to_json_string(&s).unwrap();
        assert!(json.contains("test"));
    }

    #[test]
    fn test_export_from_json_string() {
        let exp = SessionExport::new();
        let original = make_session("round_trip");
        let json = exp.to_json_string(&original).unwrap();
        let restored = exp.from_json_string(&json).unwrap();
        assert_eq!(restored.id, original.id);
    }

    #[test]
    fn test_export_validate_ok() {
        let exp = SessionExport::new();
        let s = make_session("test");
        let bytes = exp.to_json(&s).unwrap();
        assert!(exp.validate(&bytes));
    }

    #[test]
    fn test_export_validate_bad() {
        let exp = SessionExport::new();
        assert!(!exp.validate(b"not valid json"));
    }

    // ── MultiSession ──────────────────────────────────────────────────────────

    #[test]
    fn test_multi_create_and_get() {
        let mut ms = MultiSession::new();
        let id = ms.create("test", proj()).unwrap();
        let session = ms.get(&id).unwrap();
        assert_eq!(session.name, "test");
    }

    #[test]
    fn test_multi_session_count() {
        let mut ms = MultiSession::new();
        ms.create("a", proj()).unwrap();
        ms.create("b", proj()).unwrap();
        assert_eq!(ms.session_count(), 2);
    }

    #[test]
    fn test_multi_remove() {
        let mut ms = MultiSession::new();
        let id = ms.create("test", proj()).unwrap();
        ms.remove(&id).unwrap();
        assert_eq!(ms.session_count(), 0);
    }

    #[test]
    fn test_multi_suspend_and_resume() {
        let mut ms = MultiSession::new();
        let id = ms.create("test", proj()).unwrap();
        ms.suspend(&id).unwrap();
        let s = ms.get(&id).unwrap();
        assert_eq!(s.state, SessionState::Suspended);
        ms.resume(&id).unwrap();
        let s = ms.get(&id).unwrap();
        assert_eq!(s.state, SessionState::Active);
    }

    #[test]
    fn test_multi_snapshot_and_restore() {
        let mut ms = MultiSession::new();
        let id = ms.create("test", proj()).unwrap();
        // Set notes before snapshotting.
        ms.update(&id, |s| s.notes = "before snapshot".into())
            .unwrap();
        ms.snapshot(&id, Some("test snap")).unwrap();
        // Change notes after snapshot.
        ms.update(&id, |s| s.notes = "after snapshot".into())
            .unwrap();
        // Restore from snapshot.
        ms.restore_latest(&id).unwrap();
        let restored = ms.get(&id).unwrap();
        assert_eq!(restored.notes, "before snapshot");
    }

    #[test]
    fn test_multi_max_sessions() {
        let mut ms = MultiSession::with_limits(2, 5);
        ms.create("a", proj()).unwrap();
        ms.create("b", proj()).unwrap();
        assert!(matches!(
            ms.create("c", proj()),
            Err(SessionError::MaxSessionsReached(2))
        ));
    }

    #[test]
    fn test_multi_sessions_in_state() {
        let mut ms = MultiSession::new();
        let id1 = ms.create("a", proj()).unwrap();
        let id2 = ms.create("b", proj()).unwrap();
        ms.suspend(&id1).unwrap();
        let active = ms.sessions_in_state(SessionState::Active);
        assert!(active.iter().any(|s| s.id == id2));
        assert!(!active.iter().any(|s| s.id == id1));
    }

    #[test]
    fn test_multi_history_populated() {
        let mut ms = MultiSession::new();
        let id = ms.create("test", proj()).unwrap();
        ms.remove(&id).unwrap();
        assert!(ms.history().len() >= 2);
    }

    // ── SessionManagement ─────────────────────────────────────────────────────

    #[test]
    fn test_session_management_create_and_list() {
        let mut sm = SessionManagement::new();
        let id = sm.create_session("test", &proj()).unwrap();
        assert!(sm.list_sessions().contains(&id));
    }

    #[test]
    fn test_session_management_export_import() {
        let mut sm = SessionManagement::new();
        let id = sm.create_session("export_test", &proj()).unwrap();
        let json = sm.export_session(&id).unwrap();
        let _ = sm.remove_session(&id);
        let new_id = sm.import_session(&json).unwrap();
        assert!(sm.list_sessions().contains(&new_id));
    }

    #[test]
    fn test_session_management_snapshot() {
        let mut sm = SessionManagement::new();
        let id = sm.create_session("snap_test", &proj()).unwrap();
        let snap = sm.snapshot(&id).unwrap();
        assert_eq!(snap.session_id, id);
    }

    #[test]
    fn test_session_management_count() {
        let mut sm = SessionManagement::new();
        assert_eq!(sm.session_count(), 0);
        sm.create_session("a", &proj()).unwrap();
        assert_eq!(sm.session_count(), 1);
    }

    #[test]
    fn test_session_management_remove() {
        let mut sm = SessionManagement::new();
        let id = sm.create_session("test", &proj()).unwrap();
        assert!(sm.remove_session(&id).is_ok());
        assert_eq!(sm.session_count(), 0);
    }

    // ── SessionRestoreConfig ──────────────────────────────────────────────────

    #[test]
    fn test_restore_config_defaults() {
        let cfg = SessionRestoreConfig::new();
        assert!(cfg.auto_snapshot_on_close);
        assert!(!cfg.auto_restore_on_open);
        assert!(cfg.is_valid());
    }

    #[test]
    fn test_restore_config_invalid_zero_snapshots() {
        let mut cfg = SessionRestoreConfig::new();
        cfg.max_snapshots_per_session = 0;
        assert!(!cfg.is_valid());
    }

    // ── SessionStats ──────────────────────────────────────────────────────────

    #[test]
    fn test_session_stats_empty() {
        let ms = MultiSession::new();
        let stats = SessionStats::from_multi(&ms);
        assert_eq!(stats.total_sessions, 0);
        assert!(!stats.has_active());
    }

    #[test]
    fn test_session_stats_with_sessions() {
        let mut ms = MultiSession::new();
        ms.create("a", proj()).unwrap();
        ms.create("b", proj()).unwrap();
        let stats = SessionStats::from_multi(&ms);
        assert_eq!(stats.total_sessions, 2);
        assert!(stats.has_active());
    }

    #[test]
    fn test_session_stats_suspended() {
        let mut ms = MultiSession::new();
        let id = ms.create("s", proj()).unwrap();
        ms.suspend(&id).unwrap();
        let stats = SessionStats::from_multi(&ms);
        assert_eq!(stats.suspended_sessions, 1);
        assert_eq!(stats.active_sessions, 0);
    }

    #[test]
    fn test_session_stats_views_and_bookmarks() {
        let mut ms = MultiSession::new();
        let id = ms.create("s", proj()).unwrap();
        ms.update(&id, |s| {
            s.open_view(OpenView::new(1, "binary"));
            s.add_bookmark(SessionBookmark::new("bp", 1, 0x1400));
        })
        .unwrap();
        let stats = SessionStats::from_multi(&ms);
        assert_eq!(stats.total_open_views, 1);
        assert_eq!(stats.total_bookmarks, 1);
    }

    // ── SessionSearchQuery ────────────────────────────────────────────────────

    #[test]
    fn test_search_query_all() {
        let sessions = vec![make_session("alpha"), make_session("beta")];
        let results = SessionSearchQuery::all().apply(&sessions);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_search_query_by_name() {
        let sessions = vec![make_session("alpha"), make_session("beta")];
        let results = SessionSearchQuery::all().name("alp").apply(&sessions);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "alpha");
    }

    #[test]
    fn test_search_query_by_state() {
        let mut suspended = make_session("suspended");
        suspended.state = SessionState::Suspended;
        let active = make_session("active");
        let sessions = vec![suspended, active];
        let results = SessionSearchQuery::all()
            .in_state(SessionState::Suspended)
            .apply(&sessions);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_query_by_binary() {
        let mut s = make_session("s");
        s.open_view(OpenView::new(42, "binary"));
        let sessions = vec![s, make_session("other")];
        let query = SessionSearchQuery {
            has_binary: Some(42),
            ..Default::default()
        };
        let results = query.apply(&sessions);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_query_by_meta_key() {
        let mut s = make_session("s");
        s.set_meta("tool", "RustRE");
        let sessions = vec![s, make_session("other")];
        let query = SessionSearchQuery {
            has_meta_key: Some("tool".into()),
            ..Default::default()
        };
        let results = query.apply(&sessions);
        assert_eq!(results.len(), 1);
    }
}
