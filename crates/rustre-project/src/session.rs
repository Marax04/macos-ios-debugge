//! `session.rs` — **Persistent** (SQLite-backed) analysis sessions for RustRE.
//!
//! # Layer distinction
//! This module is the **low-level persistence layer**: every session is stored
//! as a JSON blob in a SQLite database (via [`SessionStore`]).  It owns the
//! wire format ([`SessionExportPayload`]) and the collaboration delta type
//! ([`SessionDiff`]).
//!
//! The **in-memory lifecycle layer** lives in [`crate::session_management`]
//! (`ActiveSession`, `MultiSession`, suspend/resume, snapshots, history).
//! The **annotation-focused extended DB** with undo/redo and collaboration
//! change tracking lives in [`crate::project_db_extended`].
//!
//! Do not merge these modules — they serve distinct, complementary roles.
//!
//!
//! An [`AnalysisSession`] captures everything needed to restore a user's exact
//! workspace state: which binary views are open, which scripts are active,
//! per-view scroll/zoom/selection state, bookmarks, free-form notes, and
//! creation/update timestamps.
//!
//! [`SessionStore`] persists sessions in a SQLite database (the project DB can
//! be re-used by passing the same path, or a dedicated path).
//!
//! Sessions can be exported to / imported from a self-contained
//! `.rustre-session` JSON file that embeds both the session state and a SHA-256
//! hash of the analysed binary so the receiver can verify compatibility.
//!
//! [`SessionDiff`] captures the delta of bookmarks and comments that have
//! changed since a given Unix timestamp and is designed for lightweight
//! collaboration sync.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, Result as SqlResult, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const SESSION_FILE_EXT: &str = "rustre-session";
pub const SESSION_FORMAT_VERSION: u32 = 1;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session not found: {0}")]
    NotFound(String),
    #[error("session already exists: {0}")]
    AlreadyExists(String),
    #[error("serialization error: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("binary hash mismatch: expected {expected}, got {actual}")]
    BinaryHashMismatch { expected: String, actual: String },
    #[error("unsupported format version: {0}")]
    UnsupportedVersion(u32),
    #[error("view not found: {0}")]
    ViewNotFound(String),
}

pub type Result<T> = std::result::Result<T, SessionError>;

// ── ViewId / ViewState ────────────────────────────────────────────────────────

/// Opaque identifier for an open view.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ViewId(pub String);

impl ViewId {
    /// Create a new `ViewId` from a binary id + optional suffix.
    #[must_use]
    pub fn new(binary_id: u64, suffix: Option<&str>) -> Self {
        suffix.map_or_else(|| Self(format!("view-{binary_id}")), |s| Self(format!("view-{binary_id}-{s}")))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ViewId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Per-view rendering state that is persisted with the session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ViewState {
    /// Unique identifier for this view.
    pub view_id: ViewId,
    /// Horizontal scroll offset in bytes from binary base.
    pub scroll_offset: u64,
    /// Zoom factor (1.0 = normal, > 1 = zoomed in).
    pub zoom: f64,
    /// Currently selected / highlighted address, if any.
    pub selected_address: Option<u64>,
    /// Free-form extra data (e.g. column widths, display mode).
    #[serde(default)]
    pub extra: HashMap<String, String>,
}

impl ViewState {
    #[must_use]
    pub fn new(view_id: ViewId) -> Self {
        Self {
            view_id,
            scroll_offset: 0,
            zoom: 1.0,
            selected_address: None,
            extra: HashMap::new(),
        }
    }

    #[must_use] 
    pub fn with_scroll(mut self, offset: u64) -> Self {
        self.scroll_offset = offset;
        self
    }
    #[must_use] 
    pub fn with_zoom(mut self, zoom: f64) -> Self {
        self.zoom = zoom.max(0.01);
        self
    }
    #[must_use] 
    pub fn with_selection(mut self, addr: u64) -> Self {
        self.selected_address = Some(addr);
        self
    }
    pub fn set_extra(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.extra.insert(key.into(), value.into());
    }
}

impl Default for ViewState {
    fn default() -> Self {
        Self::new(ViewId("default".into()))
    }
}

// ── SessionBookmark ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionBookmark {
    pub address: u64,
    pub label: String,
    pub color: String,
    pub created_at: u64,
}

impl SessionBookmark {
    pub fn new(address: u64, label: impl Into<String>) -> Self {
        Self {
            address,
            label: label.into(),
            color: "#ffff00".into(),
            created_at: unix_now(),
        }
    }
    pub fn with_color(mut self, color: impl Into<String>) -> Self {
        self.color = color.into();
        self
    }
}

// ── AnalysisSession ───────────────────────────────────────────────────────────

/// A persistent analysis session.
///
/// One project can have many sessions (e.g. one per analyst, one per day).
/// Sessions are independent: each has its own view states, active scripts,
/// bookmarks and notes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSession {
    /// UUID-style identifier (generated as hex timestamp + entropy).
    pub id: String,
    /// The binary being analysed (foreign key to `binaries.id`).
    pub binary_id: u64,
    /// Human-readable display name.
    pub name: String,
    /// Open view states indexed by [`ViewId`].
    pub open_views: HashMap<String, ViewState>,
    /// Names of scripts that were active when the session was last saved.
    pub active_scripts: Vec<String>,
    /// Session-level bookmarks (may overlap with project bookmarks).
    pub bookmarks: Vec<SessionBookmark>,
    /// Free-form analyst notes.
    pub notes: String,
    /// Unix timestamp of creation.
    pub created_at: u64,
    /// Unix timestamp of last update.
    pub updated_at: u64,
    /// Analyst / author tag.
    pub author: Option<String>,
}

impl AnalysisSession {
    /// Create a new session for the given binary.
    pub fn new(binary_id: u64, name: impl Into<String>) -> Self {
        let now = unix_now();
        Self {
            id: generate_session_id(binary_id, now),
            binary_id,
            name: name.into(),
            open_views: HashMap::new(),
            active_scripts: Vec::new(),
            bookmarks: Vec::new(),
            notes: String::new(),
            created_at: now,
            updated_at: now,
            author: None,
        }
    }

    /// Create a session with explicit id (for import/restore).
    pub fn with_id(id: impl Into<String>, binary_id: u64, name: impl Into<String>) -> Self {
        let mut s = Self::new(binary_id, name);
        s.id = id.into();
        s
    }

    // ── View management ───────────────────────────────────────────────────────

    /// Open (or replace) a view.
    pub fn open_view(&mut self, state: ViewState) {
        self.open_views.insert(state.view_id.0.clone(), state);
        self.touch();
    }

    /// Close a view; returns true if the view existed.
    pub fn close_view(&mut self, view_id: &ViewId) -> bool {
        let removed = self.open_views.remove(&view_id.0).is_some();
        if removed {
            self.touch();
        }
        removed
    }

    /// Return a mutable reference to a view state, if open.
    pub fn view_state_mut(&mut self, view_id: &ViewId) -> Option<&mut ViewState> {
        self.open_views.get_mut(&view_id.0)
    }

    #[must_use] 
    /// Return an immutable reference to a view state, if open.
     
    pub fn view_state(&self, view_id: &ViewId) -> Option<&ViewState> {
        self.open_views.get(&view_id.0)
    }

    /// Return all currently open views sorted by view_id for determinism.
    #[must_use] 
    pub fn open_view_ids(&self) -> Vec<ViewId> {
        let mut ids: Vec<ViewId> = self.open_views.keys().map(|k| ViewId(k.clone())).collect();
        ids.sort_by(|a, b| a.0.cmp(&b.0));
        ids
    }

    #[must_use] 
    pub fn view_count(&self) -> usize {
        self.open_views.len()
    }

    // ── Script management ─────────────────────────────────────────────────────

    pub fn activate_script(&mut self, name: impl Into<String>) {
        let n = name.into();
        if !self.active_scripts.contains(&n) {
            self.active_scripts.push(n);
            self.touch();
        }
    }

    pub fn deactivate_script(&mut self, name: &str) {
        let before = self.active_scripts.len();
        self.active_scripts.retain(|s| s != name);
        if self.active_scripts.len() != before {
            self.touch();
        }
    }

    // ── Bookmarks ─────────────────────────────────────────────────────────────

    pub fn add_bookmark(&mut self, bm: SessionBookmark) {
        self.bookmarks.retain(|b| b.address != bm.address);
        self.bookmarks.push(bm);
        self.bookmarks.sort_by_key(|b| b.address);
        self.touch();
    }

    pub fn remove_bookmark(&mut self, address: u64) -> bool {
        let before = self.bookmarks.len();
        self.bookmarks.retain(|b| b.address != address);
        let removed = self.bookmarks.len() != before;
        if removed {
            self.touch();
        }
        removed
    }

    #[must_use] 
    pub fn bookmark_at(&self, address: u64) -> Option<&SessionBookmark> {
        self.bookmarks.iter().find(|b| b.address == address)
    }

    // ── Notes ─────────────────────────────────────────────────────────────────

    pub fn set_notes(&mut self, notes: impl Into<String>) {
        self.notes = notes.into();
        self.touch();
    }

    pub fn append_note(&mut self, text: &str) {
        if !self.notes.is_empty() {
            self.notes.push('\n');
        }
        self.notes.push_str(text);
        self.touch();
    }

    // ── Misc ──────────────────────────────────────────────────────────────────

    pub fn set_author(&mut self, author: impl Into<String>) {
        self.author = Some(author.into());
    }

    fn touch(&mut self) {
        self.updated_at = unix_now();
    }

    /// Serialize to a pretty-printed JSON string.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(SessionError::Serialization)
    }

    /// Deserialize from JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(SessionError::Serialization)
    }
}

// ── SessionExportPayload ──────────────────────────────────────────────────────

/// The content of a `.rustre-session` file.
///
/// Carries the session itself plus a SHA-256 binary hash for compatibility
/// checking and the format version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionExportPayload {
    pub format_version: u32,
    pub binary_sha256: String,
    pub session: AnalysisSession,
    pub exported_at: u64,
}

impl SessionExportPayload {
    pub fn new(session: AnalysisSession, binary_sha256: impl Into<String>) -> Self {
        Self {
            format_version: SESSION_FORMAT_VERSION,
            binary_sha256: binary_sha256.into(),
            session,
            exported_at: unix_now(),
        }
    }

    /// Serialise to the `.rustre-session` wire format (JSON).
    pub fn to_file_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(SessionError::Serialization)
    }

    /// Parse a `.rustre-session` payload.
    ///
    /// Rejects payloads larger than 64 MiB to prevent unbounded memory
    /// allocation from adversarially crafted session files.
    pub fn from_file_bytes(bytes: &[u8]) -> Result<Self> {
        const MAX_SESSION_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
        if bytes.len() > MAX_SESSION_BYTES {
            return Err(SessionError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "session payload exceeds 64 MiB size limit",
            )));
        }
        let payload: Self = serde_json::from_slice(bytes).map_err(SessionError::Serialization)?;
        if payload.format_version > SESSION_FORMAT_VERSION {
            return Err(SessionError::UnsupportedVersion(payload.format_version));
        }
        Ok(payload)
    }

    /// Verify that the binary SHA-256 matches; returns `Err` on mismatch.
    pub fn verify_binary(&self, actual_sha256: &str) -> Result<()> {
        if self.binary_sha256 != actual_sha256 {
            return Err(SessionError::BinaryHashMismatch {
                expected: self.binary_sha256.clone(),
                actual: actual_sha256.to_string(),
            });
        }
        Ok(())
    }

    /// Write to a file at `path`.
    pub fn write_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let bytes = self.to_file_bytes()?;
        std::fs::write(path, bytes).map_err(SessionError::Io)
    }

    /// Read from a `.rustre-session` file.
    pub fn read_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(SessionError::Io)?;
        Self::from_file_bytes(&bytes)
    }
}

// ── SessionDiff ───────────────────────────────────────────────────────────────

/// Delta of bookmarks and view-notes that changed since `since_ts`.
///
/// Used for lightweight multi-analyst collaboration: one analyst exports their
/// delta since the last sync and sends it to colleagues who merge it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionDiff {
    pub since_ts: u64,
    pub binary_id: u64,
    pub added_bookmarks: Vec<SessionBookmark>,
    pub removed_bookmark_addrs: Vec<u64>,
    pub note_patch: Option<String>,
    
     pub activated_scripts: Vec<String>,
    pub deactivated_scripts: Vec<String>,
    pub generated_at: u64,
}

impl SessionDiff {
    #[must_use] 
    pub fn new(binary_id: u64, since_ts: u64) -> Self {
        Self {
            since_ts,
            binary_id,
            generated_at: unix_now(),
            ..Default::default()
        }
    }

    /// Compute the diff between `old` and `new` sessions.
    pub fn compute(
        binary_id: u64,
        since_ts: u64,
        old: &AnalysisSession,
        new: &AnalysisSession,
    ) -> Self {
        let mut diff = Self::new(binary_id, since_ts);

        let old_addrs: std::collections::HashSet<u64> =
            old.bookmarks.iter().map(|b| b.address).collect();
        let new_addrs: std::collections::HashSet<u64> =
            new.bookmarks.iter().map(|b| b.address).collect();

        // bookmarks added
        diff.added_bookmarks = new
            .bookmarks
            .iter()
            .filter(|b| !old_addrs.contains(&b.address) && b.created_at >= since_ts)
            .cloned()
            .collect();

        // bookmarks removed
        diff.removed_bookmark_addrs = old_addrs.difference(&new_addrs).copied().collect();

        // note delta
        if new.notes != old.notes {
            diff.note_patch = Some(new.notes.clone());
        }

        // scripts
        let old_scripts: std::collections::HashSet<&str> =
            old.active_scripts.iter().map(String::as_str).collect();
        let new_scripts: std::collections::HashSet<&str> =
            new.active_scripts.iter().map(String::as_str).collect();
        diff.activated_scripts = new_scripts
            .difference(&old_scripts)
            .map(|&s| s.to_string())
            .collect();
        diff.deactivated_scripts = old_scripts
            .difference(&new_scripts)
            .map(|&s| s.to_string())
            .collect();

        diff
    }

    /// Apply this diff to `target` session, mutating it in place.
    pub fn apply_to(&self, target: &mut AnalysisSession) {
        // remove
        for &addr in &self.removed_bookmark_addrs {
            target.remove_bookmark(addr);
        }
        // add
        for bm in &self.added_bookmarks {
            target.add_bookmark(bm.clone());
        }
        // note
        if let Some(note) = &self.note_patch {
            target.set_notes(note.clone());
        }
        // scripts
        for s in &self.deactivated_scripts {
            target.deactivate_script(s);
        }
        for s in &self.activated_scripts {
            target.activate_script(s.clone());
        }
    }

    /// Serialise to JSON.
    pub fn to_json(&self) -> std::result::Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialise from JSON.
    pub fn from_json(s: &str) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.added_bookmarks.is_empty()
            && self.removed_bookmark_addrs.is_empty()
            && self.note_patch.is_none()
            && self.activated_scripts.is_empty()
            && self.deactivated_scripts.is_empty()
    }
}

// ── SessionStore ──────────────────────────────────────────────────────────────

/// SQLite-backed persistent store for [`AnalysisSession`]s.
///
/// Sessions are stored as JSON blobs; the store maintains a metadata index for
/// fast listing without deserialising every blob.
pub struct SessionStore {
    db_path: PathBuf,
}

impl SessionStore {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Open (or create) a session store at `db_path`.
    pub fn open(db_path: impl Into<PathBuf>) -> Result<Self> {
        let db_path = db_path.into();
        let store = Self { db_path };
        store.migrate()?;
        Ok(store)
    }

    // ── Schema ────────────────────────────────────────────────────────────────

    fn connect(&self) -> Result<Connection> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        Ok(conn)
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.connect()?;
        conn.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    binary_id   INTEGER NOT NULL,
    name        TEXT NOT NULL,
    author      TEXT,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    blob        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_binary ON sessions(binary_id);
CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated_at);
"#,
        )?;
        Ok(())
    }

    // ── CRUD ─────────────────────────────────────────────────────────────────

    /// Insert a new session. Returns `Err(AlreadyExists)` if the id is taken.
    pub fn insert(&self, session: &AnalysisSession) -> Result<()> {
        let conn = self.connect()?;
        let blob = session.to_json()?;
        let affected = conn.execute(
            "INSERT OR IGNORE INTO sessions (id,binary_id,name,author,created_at,updated_at,blob)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                &session.id,
                session.binary_id as i64,
                &session.name,
                &session.author,
                session.created_at as i64,
                session.updated_at as i64,
                &blob,
            ],
        )?;
        if affected == 0 {
            return Err(SessionError::AlreadyExists(session.id.clone()));
        }
        Ok(())
    }

    /// Update an existing session (full replacement).
    pub fn update(&self, session: &AnalysisSession) -> Result<()> {
        let conn = self.connect()?;
        let blob = session.to_json()?;
        let affected = conn.execute(
            "UPDATE sessions SET binary_id=?1,name=?2,author=?3,updated_at=?4,blob=?5 WHERE id=?6",
            params![
                session.binary_id as i64,
                &session.name,
                &session.author,
                session.updated_at as i64,
                &blob,
                &session.id,
            ],
        )?;
        if affected == 0 {
            return Err(SessionError::NotFound(session.id.clone()));
        }
        Ok(())
    }

    /// Insert or update (upsert).
    pub fn save(&self, session: &AnalysisSession) -> Result<()> {
        match self.insert(session) {
            Ok(()) => Ok(()),
            Err(SessionError::AlreadyExists(_)) => self.update(session),
            Err(e) => Err(e),
        }
    }

    /// Load a session by id.
    pub fn load(&self, id: &str) -> Result<AnalysisSession> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare("SELECT blob FROM sessions WHERE id=?1")?;
        let mut rows = stmt.query(params![id])?;
        match rows.next()? {
            Some(row) => {
                let blob: String = row.get(0)?;
                AnalysisSession::from_json(&blob)
            }
            None => Err(SessionError::NotFound(id.to_string())),
        }
    }

    /// Delete a session by id. Returns true if a row was deleted.
    pub fn delete(&self, id: &str) -> Result<bool> {
        let conn = self.connect()?;
        Ok(conn.execute("DELETE FROM sessions WHERE id=?1", params![id])? > 0)
    }

    /// List all sessions for a binary, ordered by `updated_at` descending.
    pub fn list_for_binary(&self, binary_id: u64) -> Result<Vec<SessionSummary>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT id,name,author,created_at,updated_at FROM sessions WHERE binary_id=?1 ORDER BY updated_at DESC"
        )?;
        let rows = stmt.query_map(params![binary_id as i64], |r| {
            Ok(SessionSummary {
                id: r.get(0)?,
                name: r.get(1)?,
                author: r.get(2)?,
                created_at: r.get::<_, i64>(3)? as u64,
                updated_at: r.get::<_, i64>(4)? as u64,
                binary_id,
            })
        })?;
        Ok(rows.collect::<SqlResult<Vec<_>>>()?)
    }

    /// List all sessions regardless of binary.
    pub fn list_all(&self) -> Result<Vec<SessionSummary>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT id,binary_id,name,author,created_at,updated_at FROM sessions ORDER BY updated_at DESC"
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(SessionSummary {
                id: r.get(0)?,
                binary_id: r.get::<_, i64>(1)? as u64,
                name: r.get(2)?,
                author: r.get(3)?,
                created_at: r.get::<_, i64>(4)? as u64,
                updated_at: r.get::<_, i64>(5)? as u64,
            })
        })?;
        Ok(rows.collect::<SqlResult<Vec<_>>>()?)
    }

    /// Load all sessions for a binary as full `AnalysisSession` objects.
    pub fn load_all_for_binary(&self, binary_id: u64) -> Result<Vec<AnalysisSession>> {
        let summaries = self.list_for_binary(binary_id)?;
        summaries.iter().map(|s| self.load(&s.id)).collect()
    }

    /// Count sessions for a binary.
    pub fn count_for_binary(&self, binary_id: u64) -> Result<u64> {
        let conn = self.connect()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE binary_id=?1",
            params![binary_id as i64],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    /// Delete all sessions for a binary.
    pub fn delete_for_binary(&self, binary_id: u64) -> Result<u64> {
        let conn = self.connect()?;
        let n = conn.execute(
            "DELETE FROM sessions WHERE binary_id=?1",
            params![binary_id as i64],
        )?;
        Ok(n as u64)
    }
}

// ── SessionSummary ────────────────────────────────────────────────────────────

/// Lightweight session record for listing without loading full blobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: String,
    pub binary_id: u64,
    pub name: String,
    pub author: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn generate_session_id(binary_id: u64, ts: u64) -> String {
    // Deterministic-ish "UUID-style" id from timestamp + binary id, with a
    // monotonically increasing counter so two sessions created within the same
    // second never collide.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("sess-{ts:016x}-{binary_id:016x}-{n:08x}")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn store(dir: &TempDir) -> SessionStore {
        SessionStore::open(dir.path().join("sessions.db")).expect("open store")
    }

    fn sess(binary_id: u64, name: &str) -> AnalysisSession {
        AnalysisSession::new(binary_id, name)
    }

    // ── ViewId ─────────────────────────────────────────────────────────────────

    #[test]
    fn viewid_new_no_suffix() {
        let v = ViewId::new(1, None);
        assert_eq!(v.as_str(), "view-1");
    }
    #[test]
    fn viewid_new_suffix() {
        let v = ViewId::new(1, Some("hex"));
        assert_eq!(v.as_str(), "view-1-hex");
    }
    #[test]
    fn viewid_display() {
        let v = ViewId("foo".into());
        assert_eq!(format!("{v}"), "foo");
    }

    // ── ViewState ─────────────────────────────────────────────────────────────

    #[test]
    fn viewstate_defaults() {
        let v = ViewState::new(ViewId("x".into()));
        assert_eq!(v.scroll_offset, 0);
        assert!((v.zoom - 1.0).abs() < 1e-9);
    }
    #[test]
    fn viewstate_builders() {
        let v = ViewState::new(ViewId("x".into()))
            .with_scroll(0x1000)
            .with_zoom(2.0)
            .with_selection(0x2000);
        assert_eq!(v.scroll_offset, 0x1000);
        assert!((v.zoom - 2.0).abs() < 1e-9);
        assert_eq!(v.selected_address, Some(0x2000));
    }
    #[test]
    fn viewstate_zoom_clamp() {
        let v = ViewState::new(ViewId("x".into())).with_zoom(-5.0);
        assert!(v.zoom > 0.0);
    }
    #[test]
    fn viewstate_extra() {
        let mut v = ViewState::default();
        v.set_extra("mode", "hex");
        assert_eq!(v.extra.get("mode").unwrap(), "hex");
    }

    // ── SessionBookmark ────────────────────────────────────────────────────────

    #[test]
    fn bookmark_new() {
        let b = SessionBookmark::new(0x1000, "entry");
        assert_eq!(b.address, 0x1000);
        assert_eq!(b.label, "entry");
    }
    #[test]
    fn bookmark_color() {
        let b = SessionBookmark::new(0x1000, "x").with_color("#ff0000");
        assert_eq!(b.color, "#ff0000");
    }

    // ── AnalysisSession ────────────────────────────────────────────────────────

    #[test]
    fn session_new_defaults() {
        let s = sess(1, "test");
        assert_eq!(s.binary_id, 1);
        assert_eq!(s.name, "test");
        assert!(s.open_views.is_empty());
        assert!(s.active_scripts.is_empty());
    }
    #[test]
    fn session_id_not_empty() {
        let s = sess(1, "x");
        assert!(!s.id.is_empty());
    }
    #[test]
    fn session_open_close_view() {
        let mut s = sess(1, "x");
        let vid = ViewId::new(1, None);
        let state = ViewState::new(vid.clone());
        s.open_view(state);
        assert_eq!(s.view_count(), 1);
        assert!(s.close_view(&vid));
        assert_eq!(s.view_count(), 0);
    }
    #[test]
    fn session_close_missing_view() {
        let mut s = sess(1, "x");
        assert!(!s.close_view(&ViewId("nope".into())));
    }
    #[test]
    fn session_view_state_access() {
        let mut s = sess(1, "x");
        let vid = ViewId::new(1, None);
        s.open_view(ViewState::new(vid.clone()).with_scroll(0x500));
        assert_eq!(s.view_state(&vid).unwrap().scroll_offset, 0x500);
    }
    #[test]
    fn session_activate_deactivate_script() {
        let mut s = sess(1, "x");
        s.activate_script("foo.py");
        s.activate_script("foo.py"); // dedup
        assert_eq!(s.active_scripts.len(), 1);
        s.deactivate_script("foo.py");
        assert!(s.active_scripts.is_empty());
    }
    #[test]
    fn session_bookmarks() {
        let mut s = sess(1, "x");
        s.add_bookmark(SessionBookmark::new(0x1000, "entry"));
        s.add_bookmark(SessionBookmark::new(0x2000, "exit"));
        assert_eq!(s.bookmarks.len(), 2);
        assert!(s.remove_bookmark(0x1000));
        assert_eq!(s.bookmarks.len(), 1);
    }
    #[test]
    fn session_bookmark_at() {
        let mut s = sess(1, "x");
        s.add_bookmark(SessionBookmark::new(0x1000, "e"));
        assert!(s.bookmark_at(0x1000).is_some());
        assert!(s.bookmark_at(0x9999).is_none());
    }
    #[test]
    fn session_notes() {
        let mut s = sess(1, "x");
        s.set_notes("hello world");
        assert_eq!(s.notes, "hello world");
        s.append_note("line2");
        assert!(s.notes.contains("line2"));
    }
    #[test]
    fn session_json_roundtrip() {
        let mut s = sess(1, "rtrip");
        s.add_bookmark(SessionBookmark::new(0x1000, "e"));
        let json = s.to_json().unwrap();
        let s2 = AnalysisSession::from_json(&json).unwrap();
        assert_eq!(s2.id, s.id);
        assert_eq!(s2.bookmarks.len(), 1);
    }
    #[test]
    fn session_open_view_ids_sorted() {
        let mut s = sess(1, "x");
        s.open_view(ViewState::new(ViewId("b".into())));
        s.open_view(ViewState::new(ViewId("a".into())));
        let ids = s.open_view_ids();
        assert_eq!(ids[0].0, "a");
        assert_eq!(ids[1].0, "b");
    }
    #[test]
    fn session_view_state_mut() {
        let mut s = sess(1, "x");
        let vid = ViewId::new(1, None);
        s.open_view(ViewState::new(vid.clone()));
        s.view_state_mut(&vid).unwrap().scroll_offset = 0xdeadbeef;
        assert_eq!(s.view_state(&vid).unwrap().scroll_offset, 0xdeadbeef);
    }

    // ── SessionExportPayload ───────────────────────────────────────────────────

    #[test]
    fn export_roundtrip() {
        let s = sess(1, "export-test");
        let payload = SessionExportPayload::new(s, "aabbcc");
        let bytes = payload.to_file_bytes().unwrap();
        let p2 = SessionExportPayload::from_file_bytes(&bytes).unwrap();
        assert_eq!(p2.binary_sha256, "aabbcc");
        assert_eq!(p2.format_version, SESSION_FORMAT_VERSION);
    }
    #[test]
    fn export_verify_ok() {
        let s = sess(1, "x");
        let p = SessionExportPayload::new(s, "abc123");
        assert!(p.verify_binary("abc123").is_ok());
    }
    #[test]
    fn export_verify_fail() {
        let s = sess(1, "x");
        let p = SessionExportPayload::new(s, "abc123");
        assert!(matches!(
            p.verify_binary("different"),
            Err(SessionError::BinaryHashMismatch { .. })
        ));
    }
    #[test]
    fn export_write_read_file() {
        let dir = tmp();
        let path = dir.path().join("test.rustre-session");
        let s = sess(2, "filetest");
        let p = SessionExportPayload::new(s, "hash1");
        p.write_to_file(&path).unwrap();
        let p2 = SessionExportPayload::read_from_file(&path).unwrap();
        assert_eq!(p2.session.name, "filetest");
    }
    #[test]
    fn export_unsupported_version() {
        let mut p = SessionExportPayload::new(sess(1, "x"), "h");
        p.format_version = 999;
        let bytes = p.to_file_bytes().unwrap();
        let err = SessionExportPayload::from_file_bytes(&bytes);
        assert!(matches!(err, Err(SessionError::UnsupportedVersion(999))));
    }

    // ── SessionDiff ────────────────────────────────────────────────────────────

    #[test]
    fn diff_empty() {
        let s = sess(1, "x");
        let d = SessionDiff::compute(1, 0, &s, &s);
        assert!(d.is_empty());
    }
    #[test]
    fn diff_added_bookmark() {
        let old = sess(1, "x");
        let mut new = old.clone();
        new.add_bookmark(SessionBookmark::new(0x1000, "e"));
        let diff = SessionDiff::compute(1, 0, &old, &new);
        assert_eq!(diff.added_bookmarks.len(), 1);
    }
    #[test]
    fn diff_removed_bookmark() {
        let mut old = sess(1, "x");
        old.add_bookmark(SessionBookmark::new(0x1000, "e"));
        let mut new = old.clone();
        new.remove_bookmark(0x1000);
        let diff = SessionDiff::compute(1, 0, &old, &new);
        assert!(diff.removed_bookmark_addrs.contains(&0x1000));
    }
    #[test]
    fn diff_note_patch() {
        let old = sess(1, "x");
        let mut new = old.clone();
        new.set_notes("new note");
        let diff = SessionDiff::compute(1, 0, &old, &new);
        assert!(diff.note_patch.is_some());
    }
    #[test]
    fn diff_apply() {
        let old = sess(1, "x");
        let mut new = old.clone();
        new.add_bookmark(SessionBookmark::new(0x2000, "b"));
        new.set_notes("n");
        let diff = SessionDiff::compute(1, 0, &old, &new);
        let mut target = old;
        diff.apply_to(&mut target);
        assert_eq!(target.bookmarks.len(), 1);
        assert_eq!(target.notes, "n");
    }
    #[test]
    fn diff_json_roundtrip() {
        let d = SessionDiff::new(1, 0);
        let j = d.to_json().unwrap();
        let d2 = SessionDiff::from_json(&j).unwrap();
        assert_eq!(d2.binary_id, 1);
    }

    // ── SessionStore ───────────────────────────────────────────────────────────

    #[test]
    fn store_insert_load() {
        let d = tmp();
        let s = store(&d);
        let sess = sess(1, "alpha");
        s.insert(&sess).unwrap();
        let loaded = s.load(&sess.id).unwrap();
        assert_eq!(loaded.name, "alpha");
    }
    #[test]
    fn store_insert_duplicate_err() {
        let d = tmp();
        let st = store(&d);
        let sess = sess(1, "dup");
        st.insert(&sess).unwrap();
        assert!(matches!(
            st.insert(&sess),
            Err(SessionError::AlreadyExists(_))
        ));
    }
    #[test]
    fn store_load_missing_err() {
        let d = tmp();
        let st = store(&d);
        assert!(matches!(st.load("missing"), Err(SessionError::NotFound(_))));
    }
    #[test]
    fn store_update() {
        let d = tmp();
        let st = store(&d);
        let mut sess = sess(1, "old");
        st.insert(&sess).unwrap();
        sess.name = "new".into();
        st.update(&sess).unwrap();
        let loaded = st.load(&sess.id).unwrap();
        assert_eq!(loaded.name, "new");
    }
    #[test]
    fn store_save_upsert() {
        let d = tmp();
        let st = store(&d);
        let mut sess = sess(1, "s");
        st.save(&sess).unwrap(); // insert
        sess.name = "updated".into();
        st.save(&sess).unwrap(); // update
        assert_eq!(st.load(&sess.id).unwrap().name, "updated");
    }
    #[test]
    fn store_delete() {
        let d = tmp();
        let st = store(&d);
        let sess = sess(1, "del");
        st.insert(&sess).unwrap();
        assert!(st.delete(&sess.id).unwrap());
        assert!(!st.delete(&sess.id).unwrap());
    }
    #[test]
    fn store_list_for_binary() {
        let d = tmp();
        let st = store(&d);
        st.save(&sess(1, "a")).unwrap();
        st.save(&sess(1, "b")).unwrap();
        st.save(&sess(2, "c")).unwrap();
        let list = st.list_for_binary(1).unwrap();
        assert_eq!(list.len(), 2);
    }
    #[test]
    fn store_list_all() {
        let d = tmp();
        let st = store(&d);
        st.save(&sess(1, "x")).unwrap();
        st.save(&sess(2, "y")).unwrap();
        assert_eq!(st.list_all().unwrap().len(), 2);
    }
    #[test]
    fn store_count_for_binary() {
        let d = tmp();
        let st = store(&d);
        st.save(&sess(1, "a")).unwrap();
        st.save(&sess(1, "b")).unwrap();
        assert_eq!(st.count_for_binary(1).unwrap(), 2);
        assert_eq!(st.count_for_binary(99).unwrap(), 0);
    }
    #[test]
    fn store_delete_for_binary() {
        let d = tmp();
        let st = store(&d);
        st.save(&sess(1, "a")).unwrap();
        st.save(&sess(1, "b")).unwrap();
        st.save(&sess(2, "c")).unwrap();
        assert_eq!(st.delete_for_binary(1).unwrap(), 2);
        assert_eq!(st.count_for_binary(1).unwrap(), 0);
        assert_eq!(st.count_for_binary(2).unwrap(), 1);
    }
    #[test]
    fn store_load_all_for_binary() {
        let d = tmp();
        let st = store(&d);
        st.save(&sess(1, "p")).unwrap();
        st.save(&sess(1, "q")).unwrap();
        let sessions = st.load_all_for_binary(1).unwrap();
        assert_eq!(sessions.len(), 2);
    }
    #[test]
    fn store_summary_fields() {
        let d = tmp();
        let st = store(&d);
        let mut s = sess(1, "named");
        s.author = Some("alice".into());
        st.save(&s).unwrap();
        let sums = st.list_for_binary(1).unwrap();
        assert_eq!(sums[0].author.as_deref(), Some("alice"));
    }
}
