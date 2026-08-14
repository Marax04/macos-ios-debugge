//! Session manager for the `rustre` CLI binary.
//!
//! Manages the lifecycle of analysis sessions: creation, persistence across
//! invocations, enumeration, and removal.  Each [`Session`] is identified by a
//! [`SessionId`] (a UUID-style hex string) and carries metadata such as the
//! binary under analysis, the start time, and user-defined labels.
//!
//! Sessions are serialised to `~/.rustre/sessions/` as JSON files so they
//! survive process restarts.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── SessionId ─────────────────────────────────────────────────────────────────

/// Opaque session identifier (hex-encoded 16-byte value).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl SessionId {
    /// Generate a new session ID from a combination of the current timestamp
    /// and a simple counter (no external crate dependency).
    pub fn generate() -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let ts = unix_now_millis();
        let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Simple deterministic mix — not cryptographic.
        let a = ts ^ (counter.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let b = ts.wrapping_add(counter).wrapping_mul(0x6C62_272E_07BB_0142);
        Self(format!("{a:016x}{b:016x}"))
    }

    /// Create a `SessionId` from a known string (e.g., loaded from disk).
    ///
    /// # Errors
    ///
    /// Returns `Err` if `s` is not exactly 32 lowercase hex characters.
    pub fn from_str(s: &str) -> Result<Self, SessionError> {
        if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Ok(Self(s.to_owned()))
        } else {
            Err(SessionError::InvalidSessionId(s.to_owned()))
        }
    }

    /// Return the raw string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Pretty-print as 8-4-4-4-12 UUID-like format.
        let s = &self.0;
        if s.len() == 32 {
            write!(
                f,
                "{}-{}-{}-{}-{}",
                &s[0..8],
                &s[8..12],
                &s[12..16],
                &s[16..20],
                &s[20..32]
            )
        } else {
            write!(f, "{s}")
        }
    }
}

// ── SessionStatus ─────────────────────────────────────────────────────────────

/// Lifecycle state of a session.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Session is actively being used.
    Active,
    /// Session is paused but can be resumed.
    Paused,
    /// Session has completed normally.
    Completed,
    /// Session was abandoned without explicit completion.
    Abandoned,
}

impl fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Paused => write!(f, "paused"),
            Self::Completed => write!(f, "completed"),
            Self::Abandoned => write!(f, "abandoned"),
        }
    }
}

// ── Session ───────────────────────────────────────────────────────────────────

/// A persistent analysis session.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    /// Unique identifier.
    pub id: String,
    /// Path to the primary binary under analysis.
    pub binary_path: Option<PathBuf>,
    /// User-assigned label for quick identification.
    pub label: String,
    /// Current lifecycle status.
    pub status: SessionStatus,
    /// Unix timestamp (seconds) when the session was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) of the last activity.
    pub last_active_at: u64,
    /// Accumulated analysis time in seconds (excludes paused intervals).
    pub total_active_secs: u64,
    /// Notes entered by the user during the session.
    pub notes: String,
    /// Arbitrary key-value tags for filtering.
    pub tags: Vec<String>,
    /// Extra metadata (plugin-supplied fields, etc.).
    #[serde(default)]
    pub extra: HashMap<String, String>,
}

impl Session {
    fn new(id: &SessionId, binary_path: Option<PathBuf>, label: impl Into<String>) -> Self {
        let now = unix_now();
        Self {
            id: id.0.clone(),
            binary_path,
            label: label.into(),
            status: SessionStatus::Active,
            created_at: now,
            last_active_at: now,
            total_active_secs: 0,
            notes: String::new(),
            tags: Vec::new(),
            extra: HashMap::new(),
        }
    }

    /// Return the session age in seconds.
    pub fn age_secs(&self) -> u64 {
        unix_now().saturating_sub(self.created_at)
    }

    /// Return seconds since last activity.
    pub fn idle_secs(&self) -> u64 {
        unix_now().saturating_sub(self.last_active_at)
    }

    /// Touch the `last_active_at` timestamp.
    pub fn touch(&mut self) {
        self.last_active_at = unix_now();
    }

    /// Return `true` if the session is currently active.
    pub fn is_active(&self) -> bool {
        self.status == SessionStatus::Active
    }

    /// Add a tag if it is not already present.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let t = tag.into();
        if !self.tags.contains(&t) {
            self.tags.push(t);
        }
    }

    /// Remove a tag.
    pub fn remove_tag(&mut self, tag: &str) {
        self.tags.retain(|t| t != tag);
    }
}

// ── SessionError ──────────────────────────────────────────────────────────────

/// Errors produced by [`SessionManager`].
#[derive(Debug)]
pub enum SessionError {
    InvalidSessionId(String),
    SessionNotFound(String),
    Io(std::io::Error),
    Serialization(serde_json::Error),
    DirectorySetup(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSessionId(s) => write!(f, "invalid session id: '{s}'"),
            Self::SessionNotFound(id) => write!(f, "session not found: {id}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Serialization(e) => write!(f, "serialization error: {e}"),
            Self::DirectorySetup(msg) => write!(f, "directory setup failed: {msg}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<std::io::Error> for SessionError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for SessionError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e)
    }
}

// ── SessionFilter ─────────────────────────────────────────────────────────────

/// Criteria for filtering sessions returned by [`SessionManager::list`].
#[derive(Debug, Clone, Default)]
pub struct SessionFilter {
    /// If set, only sessions with this status are returned.
    pub status: Option<SessionStatus>,
    /// If set, only sessions whose label contains this substring are returned.
    pub label_contains: Option<String>,
    /// If set, only sessions with all these tags are returned.
    pub tags: Vec<String>,
    /// If set, only sessions created after this Unix timestamp are returned.
    pub created_after: Option<u64>,
}

impl SessionFilter {
    /// Return `true` when `session` satisfies all filter criteria.
    pub fn matches(&self, session: &Session) -> bool {
        if let Some(ref status) = self.status {
            if &session.status != status {
                return false;
            }
        }
        if let Some(ref label) = self.label_contains {
            if !session.label.to_lowercase().contains(&label.to_lowercase()) {
                return false;
            }
        }
        for tag in &self.tags {
            if !session.tags.contains(tag) {
                return false;
            }
        }
        if let Some(after) = self.created_after {
            if session.created_at <= after {
                return false;
            }
        }
        true
    }
}

// ── SessionManager ────────────────────────────────────────────────────────────

/// Manages the set of all analysis sessions.
///
/// Sessions are stored as JSON files in `<sessions_dir>/<id>.json`.
pub struct SessionManager {
    sessions_dir: PathBuf,
    /// In-memory cache.
    cache: HashMap<String, Session>,
}

impl SessionManager {
    /// Create a `SessionManager` backed by `sessions_dir`.
    ///
    /// The directory is created if it does not already exist.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::DirectorySetup`] when the directory cannot be
    /// created.
    pub fn open(sessions_dir: impl AsRef<Path>) -> Result<Self, SessionError> {
        let sessions_dir = sessions_dir.as_ref().to_path_buf();
        fs::create_dir_all(&sessions_dir).map_err(|e| {
            SessionError::DirectorySetup(format!(
                "cannot create {}: {e}",
                sessions_dir.display()
            ))
        })?;
        let mut mgr = Self {
            sessions_dir,
            cache: HashMap::new(),
        };
        mgr.reload_cache()?;
        Ok(mgr)
    }

    /// Open the default sessions directory (`~/.rustre/sessions/`).
    ///
    /// Falls back to `.rustre/sessions/` in the current directory if the home
    /// directory cannot be determined.
    pub fn open_default() -> Result<Self, SessionError> {
        let dir = home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".rustre")
            .join("sessions");
        Self::open(dir)
    }

    // ── CRUD ──────────────────────────────────────────────────────────────────

    /// Create a new session and persist it to disk.
    pub fn create(
        &mut self,
        binary_path: Option<PathBuf>,
        label: impl Into<String>,
    ) -> Result<Session, SessionError> {
        let id = SessionId::generate();
        let session = Session::new(&id, binary_path, label);
        self.save_session(&session)?;
        self.cache.insert(session.id.clone(), session.clone());
        Ok(session)
    }

    /// Look up a session by its ID string.
    pub fn get(&self, id: &str) -> Result<&Session, SessionError> {
        self.cache
            .get(id)
            .ok_or_else(|| SessionError::SessionNotFound(id.to_owned()))
    }

    /// Return a mutable reference to a session.
    pub fn get_mut(&mut self, id: &str) -> Result<&mut Session, SessionError> {
        self.cache
            .get_mut(id)
            .ok_or_else(|| SessionError::SessionNotFound(id.to_owned()))
    }

    /// Persist current in-memory state of a session to disk.
    pub fn update(&mut self, id: &str) -> Result<(), SessionError> {
        let session = self
            .cache
            .get(id)
            .ok_or_else(|| SessionError::SessionNotFound(id.to_owned()))?
            .clone();
        self.save_session(&session)
    }

    /// Remove a session from both disk and the in-memory cache.
    pub fn remove(&mut self, id: &str) -> Result<(), SessionError> {
        if self.cache.remove(id).is_none() {
            return Err(SessionError::SessionNotFound(id.to_owned()));
        }
        let path = self.session_path(id);
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    // ── Query ─────────────────────────────────────────────────────────────────

    /// Return all sessions matching the optional filter.
    pub fn list(&self, filter: Option<&SessionFilter>) -> Vec<&Session> {
        let mut sessions: Vec<&Session> = self
            .cache
            .values()
            .filter(|s| filter.map_or(true, |f| f.matches(s)))
            .collect();
        sessions.sort_by_key(|s| std::cmp::Reverse(s.last_active_at));
        sessions
    }

    /// Return all session IDs.
    pub fn ids(&self) -> Vec<&str> {
        self.cache.keys().map(|s| s.as_str()).collect()
    }

    /// Return the number of sessions in the cache.
    pub fn count(&self) -> usize {
        self.cache.len()
    }

    /// Return the number of currently active sessions.
    pub fn active_count(&self) -> usize {
        self.cache
            .values()
            .filter(|s| s.status == SessionStatus::Active)
            .count()
    }

    // ── Status transitions ────────────────────────────────────────────────────

    /// Mark a session as paused and persist.
    pub fn pause(&mut self, id: &str) -> Result<(), SessionError> {
        let session = self.get_mut(id)?;
        session.status = SessionStatus::Paused;
        session.touch();
        self.update(id)
    }

    /// Resume a paused session.
    ///
    /// # Errors
    /// Returns `SessionError::InvalidSessionId` if the session is not currently
    /// `Paused`.  Resuming a `Completed` or `Abandoned` session would silently
    /// corrupt the lifecycle state-machine.
    pub fn resume(&mut self, id: &str) -> Result<(), SessionError> {
        let session = self.get_mut(id)?;
        if session.status != SessionStatus::Paused {
            return Err(SessionError::InvalidSessionId(format!(
                "cannot resume session {id}: expected Paused, found {}",
                session.status
            )));
        }
        session.status = SessionStatus::Active;
        session.touch();
        self.update(id)
    }

    /// Mark a session as completed.
    ///
    /// # Errors
    /// Returns `SessionError::InvalidSessionId` if the session is already in a
    /// terminal state (`Completed` or `Abandoned`).
    pub fn complete(&mut self, id: &str) -> Result<(), SessionError> {
        let session = self.get_mut(id)?;
        if matches!(session.status, SessionStatus::Completed | SessionStatus::Abandoned) {
            return Err(SessionError::InvalidSessionId(format!(
                "cannot complete session {id}: already in terminal state {}",
                session.status
            )));
        }
        session.status = SessionStatus::Completed;
        session.touch();
        self.update(id)
    }

    /// Mark a session as abandoned.
    ///
    /// # Errors
    /// Returns `SessionError::InvalidSessionId` if the session is already in a
    /// terminal state (`Completed` or `Abandoned`).
    pub fn abandon(&mut self, id: &str) -> Result<(), SessionError> {
        let session = self.get_mut(id)?;
        if matches!(session.status, SessionStatus::Completed | SessionStatus::Abandoned) {
            return Err(SessionError::InvalidSessionId(format!(
                "cannot abandon session {id}: already in terminal state {}",
                session.status
            )));
        }
        session.status = SessionStatus::Abandoned;
        session.touch();
        self.update(id)
    }

    // ── Housekeeping ──────────────────────────────────────────────────────────

    /// Remove all sessions that have been idle for longer than `max_idle`.
    pub fn prune_idle(&mut self, max_idle: Duration) -> Result<usize, SessionError> {
        let max_secs = max_idle.as_secs();
        let stale: Vec<String> = self
            .cache
            .values()
            .filter(|s| s.idle_secs() >= max_secs)
            .map(|s| s.id.clone())
            .collect();
        let count = stale.len();
        for id in stale {
            self.remove(&id)?;
        }
        Ok(count)
    }

    /// Export all sessions to a JSON array string.
    pub fn export_all_json(&self) -> Result<String, SessionError> {
        let all: Vec<&Session> = self.cache.values().collect();
        serde_json::to_string_pretty(&all).map_err(SessionError::Serialization)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn session_path(&self, id: &str) -> PathBuf {
        self.sessions_dir.join(format!("{id}.json"))
    }

    fn save_session(&self, session: &Session) -> Result<(), SessionError> {
        let path = self.session_path(&session.id);
        let json = serde_json::to_string_pretty(session)?;
        fs::write(&path, json)?;
        Ok(())
    }

    fn reload_cache(&mut self) -> Result<(), SessionError> {
        self.cache.clear();
        for entry in fs::read_dir(&self.sessions_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = match fs::read_to_string(&path) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let session: Session = match serde_json::from_str(&text) {
                Ok(s) => s,
                Err(_) => continue,
            };
            self.cache.insert(session.id.clone(), session);
        }
        Ok(())
    }
}

// ── session_list convenience function ─────────────────────────────────────────

/// Return a formatted table of all sessions from the default session directory.
///
/// Each row contains: id, label, status, idle time, binary path.
///
/// # Errors
///
/// Propagates any [`SessionError`] from opening the session directory.
pub fn session_list(filter: Option<&SessionFilter>) -> Result<Vec<SessionSummary>, SessionError> {
    let mgr = SessionManager::open_default()?;
    let summaries = mgr
        .list(filter)
        .into_iter()
        .map(|s| SessionSummary {
            id: s.id.clone(),
            label: s.label.clone(),
            status: s.status.clone(),
            idle_secs: s.idle_secs(),
            age_secs: s.age_secs(),
            binary_path: s.binary_path.clone(),
            tags: s.tags.clone(),
        })
        .collect();
    Ok(summaries)
}

/// Lightweight session summary returned by [`session_list`].
#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub id: String,
    pub label: String,
    pub status: SessionStatus,
    pub idle_secs: u64,
    pub age_secs: u64,
    pub binary_path: Option<PathBuf>,
    pub tags: Vec<String>,
}

impl fmt::Display for SessionSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<8}  {:<20}  {:<10}  idle={:>5}s  {}",
            &self.id[..8.min(self.id.len())],
            if self.label.len() > 20 {
                &self.label[..20]
            } else {
                &self.label
            },
            self.status,
            self.idle_secs,
            self.binary_path
                .as_deref()
                .and_then(|p| p.to_str())
                .unwrap_or("—"),
        )
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unix_now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn tmp_mgr() -> (SessionManager, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mgr = SessionManager::open(dir.path()).unwrap();
        (mgr, dir)
    }

    #[test]
    fn test_session_id_generate_length() {
        let id = SessionId::generate();
        assert_eq!(id.as_str().len(), 32);
    }

    #[test]
    fn test_session_id_from_str_valid() {
        let id = SessionId::from_str("aabbccddeeff00112233445566778899").unwrap();
        assert_eq!(id.as_str(), "aabbccddeeff00112233445566778899");
    }

    #[test]
    fn test_session_id_from_str_invalid_length() {
        assert!(SessionId::from_str("short").is_err());
    }

    #[test]
    fn test_session_id_from_str_invalid_chars() {
        assert!(SessionId::from_str("ggbbccddeeff00112233445566778899").is_err());
    }

    #[test]
    fn test_session_id_display_has_dashes() {
        let id = SessionId::generate();
        let s = id.to_string();
        assert_eq!(s.chars().filter(|&c| c == '-').count(), 4);
    }

    #[test]
    fn test_session_id_uniqueness() {
        let ids: Vec<_> = (0..20).map(|_| SessionId::generate().0).collect();
        let set: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(set.len(), 20);
    }

    #[test]
    fn test_session_status_display() {
        assert_eq!(SessionStatus::Active.to_string(), "active");
        assert_eq!(SessionStatus::Paused.to_string(), "paused");
        assert_eq!(SessionStatus::Completed.to_string(), "completed");
        assert_eq!(SessionStatus::Abandoned.to_string(), "abandoned");
    }

    #[test]
    fn test_manager_create_session() {
        let (mut mgr, _dir) = tmp_mgr();
        let s = mgr.create(None, "test session").unwrap();
        assert_eq!(s.label, "test session");
        assert_eq!(s.status, SessionStatus::Active);
    }

    #[test]
    fn test_manager_get_session() {
        let (mut mgr, _dir) = tmp_mgr();
        let s = mgr.create(None, "get me").unwrap();
        let got = mgr.get(&s.id).unwrap();
        assert_eq!(got.label, "get me");
    }

    #[test]
    fn test_manager_remove_session() {
        let (mut mgr, _dir) = tmp_mgr();
        let s = mgr.create(None, "remove me").unwrap();
        mgr.remove(&s.id).unwrap();
        assert!(mgr.get(&s.id).is_err());
    }

    #[test]
    fn test_manager_list_all() {
        let (mut mgr, _dir) = tmp_mgr();
        mgr.create(None, "a").unwrap();
        mgr.create(None, "b").unwrap();
        assert_eq!(mgr.list(None).len(), 2);
    }

    #[test]
    fn test_manager_count() {
        let (mut mgr, _dir) = tmp_mgr();
        assert_eq!(mgr.count(), 0);
        mgr.create(None, "x").unwrap();
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_manager_active_count() {
        let (mut mgr, _dir) = tmp_mgr();
        let s = mgr.create(None, "y").unwrap();
        assert_eq!(mgr.active_count(), 1);
        mgr.complete(&s.id).unwrap();
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_manager_pause_resume() {
        let (mut mgr, _dir) = tmp_mgr();
        let s = mgr.create(None, "p").unwrap();
        mgr.pause(&s.id).unwrap();
        assert_eq!(mgr.get(&s.id).unwrap().status, SessionStatus::Paused);
        mgr.resume(&s.id).unwrap();
        assert_eq!(mgr.get(&s.id).unwrap().status, SessionStatus::Active);
    }

    #[test]
    fn test_manager_complete() {
        let (mut mgr, _dir) = tmp_mgr();
        let s = mgr.create(None, "c").unwrap();
        mgr.complete(&s.id).unwrap();
        assert_eq!(mgr.get(&s.id).unwrap().status, SessionStatus::Completed);
    }

    #[test]
    fn test_manager_abandon() {
        let (mut mgr, _dir) = tmp_mgr();
        let s = mgr.create(None, "d").unwrap();
        mgr.abandon(&s.id).unwrap();
        assert_eq!(mgr.get(&s.id).unwrap().status, SessionStatus::Abandoned);
    }

    #[test]
    fn test_manager_persist_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let id = {
            let mut mgr = SessionManager::open(dir.path()).unwrap();
            let s = mgr.create(None, "persist me").unwrap();
            s.id.clone()
        };
        let mgr2 = SessionManager::open(dir.path()).unwrap();
        let s = mgr2.get(&id).unwrap();
        assert_eq!(s.label, "persist me");
    }

    #[test]
    fn test_session_filter_by_status() {
        let (mut mgr, _dir) = tmp_mgr();
        let a = mgr.create(None, "a").unwrap();
        let _b = mgr.create(None, "b").unwrap();
        mgr.complete(&a.id).unwrap();
        let filter = SessionFilter {
            status: Some(SessionStatus::Completed),
            ..Default::default()
        };
        let list = mgr.list(Some(&filter));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].label, "a");
    }

    #[test]
    fn test_session_filter_by_label() {
        let (mut mgr, _dir) = tmp_mgr();
        mgr.create(None, "hello world").unwrap();
        mgr.create(None, "goodbye").unwrap();
        let filter = SessionFilter {
            label_contains: Some("hello".into()),
            ..Default::default()
        };
        let list = mgr.list(Some(&filter));
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_session_prune_idle_zero_threshold() {
        let (mut mgr, _dir) = tmp_mgr();
        mgr.create(None, "a").unwrap();
        mgr.create(None, "b").unwrap();
        // Threshold of 0 seconds — all sessions are idle ≥ 0 s.
        let pruned = mgr.prune_idle(Duration::from_secs(0)).unwrap();
        assert_eq!(pruned, 2);
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_session_prune_idle_large_threshold() {
        let (mut mgr, _dir) = tmp_mgr();
        mgr.create(None, "keep me").unwrap();
        let pruned = mgr.prune_idle(Duration::from_secs(86400)).unwrap();
        assert_eq!(pruned, 0);
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_export_all_json() {
        let (mut mgr, _dir) = tmp_mgr();
        mgr.create(None, "export test").unwrap();
        let json = mgr.export_all_json().unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn test_session_tags() {
        let (mut mgr, _dir) = tmp_mgr();
        let s = mgr.create(None, "tagged").unwrap();
        let id = s.id.clone();
        mgr.get_mut(&id).unwrap().add_tag("malware");
        mgr.get_mut(&id).unwrap().add_tag("ransomware");
        mgr.get_mut(&id).unwrap().remove_tag("malware");
        let s = mgr.get(&id).unwrap();
        assert!(!s.tags.contains(&"malware".to_owned()));
        assert!(s.tags.contains(&"ransomware".to_owned()));
    }

    #[test]
    fn test_session_summary_display() {
        let summary = SessionSummary {
            id: "aabbccddeeff00112233445566778899".into(),
            label: "my session".into(),
            status: SessionStatus::Active,
            idle_secs: 42,
            age_secs: 300,
            binary_path: Some(PathBuf::from("/bin/ls")),
            tags: vec![],
        };
        let s = summary.to_string();
        assert!(s.contains("active"));
        assert!(s.contains("42"));
    }

    #[test]
    fn test_get_nonexistent_session() {
        let (mgr, _dir) = tmp_mgr();
        assert!(matches!(
            mgr.get("nonexistent"),
            Err(SessionError::SessionNotFound(_))
        ));
    }

    #[test]
    fn test_remove_nonexistent_session() {
        let (mut mgr, _dir) = tmp_mgr();
        assert!(matches!(
            mgr.remove("nonexistent"),
            Err(SessionError::SessionNotFound(_))
        ));
    }
}
