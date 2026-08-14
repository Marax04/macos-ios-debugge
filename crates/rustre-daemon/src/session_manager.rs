//! `session_manager` — Analysis session lifecycle management.
//!
//! A *session* represents one opened binary undergoing analysis.  The
//! [`SessionPool`] enforces a maximum concurrency limit and provides
//! thread-safe create / open / close / cleanup operations.
//!
//! # Session lifecycle
//!
//! ```text
//!  SessionPool::create()
//!      │
//!      ▼
//!  Session { status: Created }
//!      │
//!      ▼  (analysis starts)
//!  Session { status: Analysing }
//!      │
//!      ├─► Session { status: Ready }   (analysis done)
//!      └─► Session { status: Failed }  (analysis error)
//!      │
//!      ▼  SessionPool::close()
//!  Session { status: Closed }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

// ── SessionId ─────────────────────────────────────────────────────────────────

/// Opaque session identifier (cheaply cloneable).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    /// Create a new session id from a string.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generate a pseudo-unique session id from the current nanosecond clock.
    #[must_use]
    pub fn generate() -> Self {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        Self(format!("sess-{ns:x}"))
    }

    /// Return the inner string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for SessionId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SessionId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

// ── SessionStatus ─────────────────────────────────────────────────────────────

/// Current lifecycle status of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    /// Session created; no analysis started yet.
    Created,
    /// Background analysis is in progress.
    Analysing,
    /// Analysis complete; ready for queries.
    Ready,
    /// Analysis failed with an error.
    Failed,
    /// Session has been closed and resources released.
    Closed,
}

impl fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Created => "created",
            Self::Analysing => "analysing",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Closed => "closed",
        };
        write!(f, "{s}")
    }
}

impl SessionStatus {
    /// Return `true` if the session is still alive (not closed).
    #[must_use]
    pub const fn is_alive(self) -> bool {
        !matches!(self, Self::Closed)
    }

    /// Return `true` if the session is ready to accept analysis queries.
    #[must_use]
    pub const fn is_queryable(self) -> bool {
        matches!(self, Self::Ready)
    }
}

// ── SessionEvent ─────────────────────────────────────────────────────────────

/// An entry in a session's event log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEvent {
    /// Wall-clock timestamp (seconds since UNIX epoch).
    pub timestamp: u64,
    /// Human-readable description.
    pub message: String,
    /// Optional structured payload.
    pub data: Option<serde_json::Value>,
}

impl SessionEvent {
    /// Create a new event with the current timestamp.
    #[must_use]
    pub fn now(message: impl Into<String>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            timestamp,
            message: message.into(),
            data: None,
        }
    }

    /// Attach structured data to the event.
    #[must_use]
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }
}

// ── Session ───────────────────────────────────────────────────────────────────

/// A single binary analysis session.
#[derive(Debug)]
pub struct Session {
    /// Unique session identifier.
    pub id: SessionId,
    /// Path to the binary being analysed.
    pub binary_path: PathBuf,
    /// Current lifecycle status.
    pub status: SessionStatus,
    /// Epoch timestamp when the session was created.
    pub created_at: u64,
    /// Monotonic instant when the session was created (for duration maths).
    created_instant: Instant,
    /// Human-readable error message if `status == Failed`.
    pub error: Option<String>,
    /// Ordered event log.
    pub events: Vec<SessionEvent>,
    /// Arbitrary key-value metadata set by callers.
    pub metadata: HashMap<String, String>,
}

impl Session {
    /// Create a new session for the given binary path.
    #[must_use]
    pub fn new(id: SessionId, binary_path: PathBuf) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut s = Self {
            id: id.clone(),
            binary_path,
            status: SessionStatus::Created,
            created_at,
            created_instant: Instant::now(),
            error: None,
            events: Vec::new(),
            metadata: HashMap::new(),
        };
        s.log_event(format!("session {id} created"));
        s
    }

    /// Record an event in the session log.
    pub fn log_event(&mut self, message: impl Into<String>) {
        self.events.push(SessionEvent::now(message));
    }

    /// Record an event with structured data.
    pub fn log_event_data(&mut self, message: impl Into<String>, data: serde_json::Value) {
        self.events.push(SessionEvent::now(message).with_data(data));
    }

    /// Transition to `Analysing`.
    ///
    /// # Errors
    /// Returns an error string if the session is not in `Created` status.
    pub fn begin_analysis(&mut self) -> Result<(), String> {
        if self.status != SessionStatus::Created {
            return Err(format!("cannot begin analysis in status '{}'", self.status));
        }
        self.status = SessionStatus::Analysing;
        self.log_event("analysis started");
        Ok(())
    }

    /// Transition to `Ready`.
    ///
    /// # Errors
    /// Returns an error string if the session is not `Analysing`.
    pub fn complete_analysis(&mut self) -> Result<(), String> {
        if self.status != SessionStatus::Analysing {
            return Err(format!(
                "cannot complete analysis in status '{}'",
                self.status
            ));
        }
        self.status = SessionStatus::Ready;
        self.log_event("analysis complete");
        Ok(())
    }

    /// Transition to `Failed` with an error message.
    pub fn fail(&mut self, reason: impl Into<String>) {
        let msg = reason.into();
        self.error = Some(msg.clone());
        self.status = SessionStatus::Failed;
        self.log_event(format!("session failed: {msg}"));
    }

    /// Transition to `Closed`.
    pub fn close(&mut self) {
        self.status = SessionStatus::Closed;
        self.log_event("session closed");
    }

    /// Return how long the session has been open.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.created_instant.elapsed()
    }

    /// Return `true` if this session is still alive (not closed).
    #[must_use]
    pub const fn is_alive(&self) -> bool {
        self.status.is_alive()
    }

    /// Return a serialisable summary of the session state.
    #[must_use]
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id.as_str(),
            "binary_path": self.binary_path,
            "status": self.status.to_string(),
            "created_at": self.created_at,
            "age_secs": self.age().as_secs(),
            "event_count": self.events.len(),
            "error": self.error,
        })
    }
}

// ── SessionPool ───────────────────────────────────────────────────────────────

/// Error type for session pool operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    /// The pool is at capacity.
    AtCapacity(usize),
    /// No session with the given id exists.
    NotFound(SessionId),
    /// The session is in an incompatible state for the requested operation.
    InvalidState { id: SessionId, state: String },
    /// The binary path does not exist.
    PathNotFound(PathBuf),
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtCapacity(n) => write!(f, "session pool at capacity ({n})"),
            Self::NotFound(id) => write!(f, "session not found: {id}"),
            Self::InvalidState { id, state } => {
                write!(
                    f,
                    "session {id} in invalid state '{state}' for this operation"
                )
            }
            Self::PathNotFound(p) => write!(f, "binary path not found: {}", p.display()),
        }
    }
}

impl std::error::Error for PoolError {}

/// Manages a bounded collection of concurrent analysis sessions.
///
/// All public methods are thread-safe; internally the sessions map is
/// protected by a [`RwLock`] while mutating operations on individual sessions
/// are serialised via an inner [`Mutex`].
pub struct SessionPool {
    sessions: RwLock<HashMap<SessionId, Arc<Mutex<Session>>>>,
    max_sessions: usize,
    require_path_exists: bool,
}

impl SessionPool {
    /// Create a pool with the given maximum concurrent session limit.
    #[must_use]
    pub fn new(max_sessions: usize) -> Self {
        assert!(max_sessions > 0, "max_sessions must be > 0");
        Self {
            sessions: RwLock::new(HashMap::new()),
            max_sessions,
            require_path_exists: true,
        }
    }

    /// Disable the "path must exist" check (useful in tests).
    #[must_use]
    pub const fn without_path_check(mut self) -> Self {
        self.require_path_exists = false;
        self
    }

    /// Return the configured maximum number of concurrent sessions.
    #[must_use]
    pub const fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    /// Return the number of currently open (non-closed) sessions.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.sessions
            .read()
            .values()
            .filter(|s| s.lock().is_alive())
            .count()
    }

    /// Return the total number of sessions in the pool (including closed).
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.sessions.read().len()
    }

    /// Create a new session for `binary_path`.
    ///
    /// # Errors
    /// - [`PoolError::AtCapacity`] if the active session count equals `max_sessions`.
    /// - [`PoolError::PathNotFound`] if path validation is enabled and the path does not exist.
    pub fn create(&self, binary_path: PathBuf) -> Result<SessionId, PoolError> {
        if self.require_path_exists && !binary_path.exists() {
            return Err(PoolError::PathNotFound(binary_path));
        }

        if self.active_count() >= self.max_sessions {
            return Err(PoolError::AtCapacity(self.max_sessions));
        }

        let id = SessionId::generate();
        let session = Session::new(id.clone(), binary_path);
        self.sessions
            .write()
            .insert(id.clone(), Arc::new(Mutex::new(session)));
        Ok(id)
    }

    /// Create a session with an explicit id (used in tests or for deterministic ids).
    ///
    /// # Errors
    /// See [`SessionPool::create`].
    pub fn create_with_id(
        &self,
        id: SessionId,
        binary_path: PathBuf,
    ) -> Result<SessionId, PoolError> {
        if self.require_path_exists && !binary_path.exists() {
            return Err(PoolError::PathNotFound(binary_path));
        }
        if self.active_count() >= self.max_sessions {
            return Err(PoolError::AtCapacity(self.max_sessions));
        }
        let session = Session::new(id.clone(), binary_path);
        self.sessions
            .write()
            .insert(id.clone(), Arc::new(Mutex::new(session)));
        Ok(id)
    }

    /// Retrieve a shared handle to a session.
    ///
    /// # Errors
    /// Returns [`PoolError::NotFound`] if no session with `id` exists.
    pub fn get(&self, id: &SessionId) -> Result<Arc<Mutex<Session>>, PoolError> {
        self.sessions
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| PoolError::NotFound(id.clone()))
    }

    /// Close a session by id.
    ///
    /// # Errors
    /// Returns [`PoolError::NotFound`] if the session does not exist.
    pub fn close(&self, id: &SessionId) -> Result<(), PoolError> {
        let handle = self.get(id)?;
        handle.lock().close();
        Ok(())
    }

    /// Remove all closed sessions from the pool.  Returns the count removed.
    pub fn cleanup(&self) -> usize {
        let mut map = self.sessions.write();
        let before = map.len();
        map.retain(|_, s| s.lock().is_alive());
        before - map.len()
    }

    /// Return summaries of all live (non-closed) sessions.
    #[must_use]
    pub fn list_active(&self) -> Vec<serde_json::Value> {
        self.sessions
            .read()
            .values()
            .filter_map(|s| {
                let guard = s.lock();
                if guard.is_alive() {
                    Some(guard.summary())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return summaries of all sessions, including closed ones.
    #[must_use]
    pub fn list_all(&self) -> Vec<serde_json::Value> {
        self.sessions
            .read()
            .values()
            .map(|s| s.lock().summary())
            .collect()
    }

    /// Transition a session to `Analysing`.
    ///
    /// # Errors
    /// - [`PoolError::NotFound`] if the session does not exist.
    /// - [`PoolError::InvalidState`] if the transition is not allowed.
    pub fn begin_analysis(&self, id: &SessionId) -> Result<(), PoolError> {
        let handle = self.get(id)?;
        handle
            .lock()
            .begin_analysis()
            .map_err(|e| PoolError::InvalidState {
                id: id.clone(),
                state: e,
            })
    }

    /// Transition a session to `Ready`.
    ///
    /// # Errors
    /// See [`SessionPool::begin_analysis`].
    pub fn complete_analysis(&self, id: &SessionId) -> Result<(), PoolError> {
        let handle = self.get(id)?;
        handle
            .lock()
            .complete_analysis()
            .map_err(|e| PoolError::InvalidState {
                id: id.clone(),
                state: e,
            })
    }

    /// Mark a session as failed.
    ///
    /// # Errors
    /// Returns [`PoolError::NotFound`] if the session does not exist.
    pub fn fail_session(&self, id: &SessionId, reason: impl Into<String>) -> Result<(), PoolError> {
        let handle = self.get(id)?;
        handle.lock().fail(reason);
        Ok(())
    }

    /// Append a log event to a session.
    ///
    /// # Errors
    /// Returns [`PoolError::NotFound`] if the session does not exist.
    pub fn log_event(&self, id: &SessionId, message: impl Into<String>) -> Result<(), PoolError> {
        let handle = self.get(id)?;
        handle.lock().log_event(message);
        Ok(())
    }

    /// Return the status of a session.
    ///
    /// # Errors
    /// Returns [`PoolError::NotFound`] if the session does not exist.
    pub fn status(&self, id: &SessionId) -> Result<SessionStatus, PoolError> {
        let handle = self.get(id)?;
        Ok(handle.lock().status)
    }

    /// Return the event log of a session.
    ///
    /// # Errors
    /// Returns [`PoolError::NotFound`] if the session does not exist.
    pub fn events(&self, id: &SessionId) -> Result<Vec<SessionEvent>, PoolError> {
        let handle = self.get(id)?;
        Ok(handle.lock().events.clone())
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path() -> PathBuf {
        // In tests we disable path existence checks, so the path itself is
        // arbitrary.
        PathBuf::from("/nonexistent/binary.exe")
    }

    fn pool() -> SessionPool {
        SessionPool::new(4).without_path_check()
    }

    // ── SessionId ─────────────────────────────────────────────────────────────

    #[test]
    fn test_session_id_display() {
        let id = SessionId::new("abc");
        assert_eq!(id.to_string(), "abc");
        assert_eq!(id.as_str(), "abc");
    }

    #[test]
    fn test_session_id_generate_unique() {
        let a = SessionId::generate();
        std::thread::sleep(std::time::Duration::from_nanos(100));
        let b = SessionId::generate();
        // Not strictly guaranteed but virtually always true.
        assert_ne!(a, b);
    }

    // ── SessionStatus ─────────────────────────────────────────────────────────

    #[test]
    fn test_session_status_is_alive() {
        assert!(SessionStatus::Created.is_alive());
        assert!(SessionStatus::Analysing.is_alive());
        assert!(SessionStatus::Ready.is_alive());
        assert!(SessionStatus::Failed.is_alive());
        assert!(!SessionStatus::Closed.is_alive());
    }

    #[test]
    fn test_session_status_is_queryable() {
        assert!(SessionStatus::Ready.is_queryable());
        assert!(!SessionStatus::Created.is_queryable());
        assert!(!SessionStatus::Analysing.is_queryable());
    }

    // ── Session lifecycle ─────────────────────────────────────────────────────

    #[test]
    fn test_session_lifecycle_happy_path() {
        let id = SessionId::new("test-1");
        let mut s = Session::new(id, tmp_path());
        assert_eq!(s.status, SessionStatus::Created);
        s.begin_analysis().unwrap();
        assert_eq!(s.status, SessionStatus::Analysing);
        s.complete_analysis().unwrap();
        assert_eq!(s.status, SessionStatus::Ready);
        s.close();
        assert_eq!(s.status, SessionStatus::Closed);
        assert!(!s.is_alive());
    }

    #[test]
    fn test_session_fail() {
        let id = SessionId::new("test-fail");
        let mut s = Session::new(id, tmp_path());
        s.begin_analysis().unwrap();
        s.fail("unexpected EOF");
        assert_eq!(s.status, SessionStatus::Failed);
        assert!(s.error.as_deref().unwrap().contains("unexpected EOF"));
    }

    #[test]
    fn test_session_invalid_transition_err() {
        let id = SessionId::new("test-invalid");
        let mut s = Session::new(id, tmp_path());
        // Cannot complete without beginning.
        assert!(s.complete_analysis().is_err());
    }

    #[test]
    fn test_session_event_log() {
        let id = SessionId::new("test-events");
        let mut s = Session::new(id, tmp_path());
        s.log_event("custom event");
        // Created event + custom event = 2.
        assert_eq!(s.events.len(), 2);
        assert!(s.events[1].message.contains("custom event"));
    }

    #[test]
    fn test_session_summary_keys() {
        let id = SessionId::new("test-summary");
        let s = Session::new(id, tmp_path());
        let v = s.summary();
        assert!(v["id"].is_string());
        assert!(v["status"].is_string());
        assert!(v["created_at"].is_number());
    }

    // ── SessionPool ───────────────────────────────────────────────────────────

    #[test]
    fn test_pool_create_and_status() {
        let p = pool();
        let id = p.create(tmp_path()).unwrap();
        assert_eq!(p.status(&id).unwrap(), SessionStatus::Created);
        assert_eq!(p.active_count(), 1);
    }

    #[test]
    fn test_pool_capacity_enforced() {
        let p = SessionPool::new(2).without_path_check();
        p.create(tmp_path()).unwrap();
        p.create(tmp_path()).unwrap();
        let err = p.create(tmp_path()).unwrap_err();
        assert!(matches!(err, PoolError::AtCapacity(2)));
    }

    #[test]
    fn test_pool_close_reduces_active() {
        let p = pool();
        let id = p.create(tmp_path()).unwrap();
        assert_eq!(p.active_count(), 1);
        p.close(&id).unwrap();
        assert_eq!(p.active_count(), 0);
    }

    #[test]
    fn test_pool_cleanup_removes_closed() {
        let p = pool();
        let id = p.create(tmp_path()).unwrap();
        p.close(&id).unwrap();
        assert_eq!(p.total_count(), 1);
        let removed = p.cleanup();
        assert_eq!(removed, 1);
        assert_eq!(p.total_count(), 0);
    }

    #[test]
    fn test_pool_not_found_err() {
        let p = pool();
        let err = p.status(&SessionId::new("ghost")).unwrap_err();
        assert!(matches!(err, PoolError::NotFound(_)));
    }

    #[test]
    fn test_pool_begin_complete_analysis() {
        let p = pool();
        let id = p.create(tmp_path()).unwrap();
        p.begin_analysis(&id).unwrap();
        assert_eq!(p.status(&id).unwrap(), SessionStatus::Analysing);
        p.complete_analysis(&id).unwrap();
        assert_eq!(p.status(&id).unwrap(), SessionStatus::Ready);
    }

    #[test]
    fn test_pool_fail_session() {
        let p = pool();
        let id = p.create(tmp_path()).unwrap();
        p.begin_analysis(&id).unwrap();
        p.fail_session(&id, "parse error").unwrap();
        assert_eq!(p.status(&id).unwrap(), SessionStatus::Failed);
    }

    #[test]
    fn test_pool_log_event() {
        let p = pool();
        let id = p.create(tmp_path()).unwrap();
        p.log_event(&id, "custom log").unwrap();
        let events = p.events(&id).unwrap();
        assert!(events.iter().any(|e| e.message.contains("custom log")));
    }

    #[test]
    fn test_pool_list_active_excludes_closed() {
        let p = pool();
        let id1 = p.create(tmp_path()).unwrap();
        let id2 = p.create(tmp_path()).unwrap();
        p.close(&id1).unwrap();
        let active = p.list_active();
        assert_eq!(active.len(), 1);
        let _ = id2; // keep alive
    }

    #[test]
    fn test_pool_create_after_cleanup() {
        let p = SessionPool::new(1).without_path_check();
        let id = p.create(tmp_path()).unwrap();
        p.close(&id).unwrap();
        p.cleanup();
        // Now we can create again.
        p.create(tmp_path()).unwrap();
    }

    #[test]
    fn test_pool_error_display() {
        let e = PoolError::AtCapacity(8);
        assert!(e.to_string().contains('8'));

        let e2 = PoolError::NotFound(SessionId::new("x"));
        assert!(e2.to_string().contains('x'));

        let e3 = PoolError::PathNotFound(PathBuf::from("/missing"));
        assert!(e3.to_string().contains("/missing"));
    }
}
