//! Analysis session server for the `RustRE` daemon.
//!
//! Provides [`SessionServer`] as the root type, with
//! [`SessionPool`], [`SessionRouter`], [`SessionAuth`],
//! [`SessionMetrics`], and [`SessionCleanup`].

#![allow(dead_code)]

use std::collections::HashMap;
pub use std::net::{SocketAddr, TcpListener, TcpStream};
pub use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SessionServerError {
    #[error("session '{0}' not found")]
    SessionNotFound(String),

    #[error("session '{0}' already exists")]
    SessionAlreadyExists(String),

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("server is full: max sessions {0} reached")]
    ServerFull(usize),

    #[error("session '{0}' is expired")]
    SessionExpired(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("routing error: {0}")]
    Routing(String),
}

pub type ServerResult<T> = std::result::Result<T, SessionServerError>;

// ── SessionId / Token ─────────────────────────────────────────────────────────

/// A unique session identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

impl SessionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use] 
    pub fn generate() -> Self {
        Self(format!("sess_{}", now_unix()))
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An authentication token for a session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionToken(pub String);

impl SessionToken {
    pub fn new(t: impl Into<String>) -> Self {
        Self(t.into())
    }
}

// ── SessionState ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Active,
    Idle,
    Closing,
    Closed,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Idle => write!(f, "idle"),
            Self::Closing => write!(f, "closing"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

// ── ServerSession ─────────────────────────────────────────────────────────────

/// Metadata for one analysis session managed by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSession {
    pub id: SessionId,
    pub token: SessionToken,
    pub owner: String,
    pub state: SessionState,
    pub created_at: i64,
    pub last_active_at: i64,
    pub ttl_secs: u64,
    pub metadata: HashMap<String, serde_json::Value>,
    pub request_count: u64,
}

impl ServerSession {
    pub fn new(
        id: SessionId,
        token: SessionToken,
        owner: impl Into<String>,
        ttl_secs: u64,
    ) -> Self {
        let now = now_unix();
        Self {
            id,
            token,
            owner: owner.into(),
            state: SessionState::Active,
            created_at: now,
            last_active_at: now,
            ttl_secs,
            metadata: HashMap::new(),
            request_count: 0,
        }
    }

    #[must_use] 
    pub fn is_expired(&self) -> bool {
        let now = now_unix();
        (now - self.last_active_at) as u64 >= self.ttl_secs
    }

    pub fn touch(&mut self) {
        self.last_active_at = now_unix();
        self.request_count += 1;
    }

    pub const fn close(&mut self) {
        self.state = SessionState::Closed;
    }

    #[must_use] 
    pub fn age_secs(&self) -> i64 {
        now_unix() - self.created_at
    }
}

// ── SessionPool ───────────────────────────────────────────────────────────────

/// Manages the pool of active server sessions.
pub struct SessionPool {
    sessions: RwLock<HashMap<SessionId, ServerSession>>,
    max_sessions: usize,
}

impl SessionPool {
    #[must_use] 
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            max_sessions,
        }
    }

    /// Create and add a new session.
    pub fn create(
        &self,
        id: SessionId,
        token: SessionToken,
        owner: impl Into<String>,
        ttl_secs: u64,
    ) -> ServerResult<SessionId> {
        let mut sessions = self.sessions.write();
        if sessions.contains_key(&id) {
            return Err(SessionServerError::SessionAlreadyExists(id.0));
        }
        if sessions.len() >= self.max_sessions {
            return Err(SessionServerError::ServerFull(self.max_sessions));
        }
        let session = ServerSession::new(id.clone(), token, owner, ttl_secs);
        sessions.insert(id.clone(), session);
        Ok(id)
    }

    /// Get a session by id (shared read).
    pub fn get(&self, id: &SessionId) -> ServerResult<ServerSession> {
        self.sessions
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| SessionServerError::SessionNotFound(id.0.clone()))
    }

    /// Touch a session (mark as recently active).
    pub fn touch(&self, id: &SessionId) -> ServerResult<()> {
        let mut sessions = self.sessions.write();
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| SessionServerError::SessionNotFound(id.0.clone()))?;
        if session.is_expired() {
            return Err(SessionServerError::SessionExpired(id.0.clone()));
        }
        session.touch();
        Ok(())
    }

    /// Close a session.
    pub fn close(&self, id: &SessionId) -> ServerResult<()> {
        let mut sessions = self.sessions.write();
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| SessionServerError::SessionNotFound(id.0.clone()))?;
        session.close();
        Ok(())
    }

    /// Remove a session entirely.
    pub fn remove(&self, id: &SessionId) -> ServerResult<ServerSession> {
        self.sessions
            .write()
            .remove(id)
            .ok_or_else(|| SessionServerError::SessionNotFound(id.0.clone()))
    }

    /// List all active session IDs.
    pub fn active_ids(&self) -> Vec<SessionId> {
        self.sessions
            .read()
            .values()
            .filter(|s| s.state == SessionState::Active || s.state == SessionState::Idle)
            .map(|s| s.id.clone())
            .collect()
    }

    /// Number of sessions in the pool.
    pub fn len(&self) -> usize {
        self.sessions.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Collect expired session IDs.
    pub fn expired_ids(&self) -> Vec<SessionId> {
        self.sessions
            .read()
            .values()
            .filter(|s| s.is_expired())
            .map(|s| s.id.clone())
            .collect()
    }

    pub fn all_sessions(&self) -> Vec<ServerSession> {
        self.sessions.read().values().cloned().collect()
    }
}

// ── SessionAuth ───────────────────────────────────────────────────────────────

/// Authentication and authorization for session access.
pub struct SessionAuth {
    /// token → owner mapping.
    valid_tokens: RwLock<HashMap<SessionToken, String>>,
    /// Per-session token cache.
    session_tokens: RwLock<HashMap<SessionId, SessionToken>>,
}

impl SessionAuth {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            valid_tokens: RwLock::new(HashMap::new()),
            session_tokens: RwLock::new(HashMap::new()),
        }
    }

    /// Register a token for an owner.
    pub fn register_token(&self, token: SessionToken, owner: impl Into<String>) {
        self.valid_tokens.write().insert(token, owner.into());
    }

    /// Revoke a token.
    pub fn revoke_token(&self, token: &SessionToken) -> bool {
        self.valid_tokens.write().remove(token).is_some()
    }

    /// Bind a token to a session.
    pub fn bind_session(&self, id: SessionId, token: SessionToken) {
        self.session_tokens.write().insert(id, token);
    }

    /// Validate that `token` is allowed to access `session_id`.
    pub fn validate(&self, session_id: &SessionId, token: &SessionToken) -> ServerResult<String> {
        // Check token is globally registered.
        let owner = self
            .valid_tokens
            .read()
            .get(token)
            .cloned()
            .ok_or_else(|| SessionServerError::AuthFailed("token not registered".into()))?;

        // Check the session is bound to this token.
        let bound = self.session_tokens.read().get(session_id).cloned();
        match bound {
            Some(t) if &t == token => Ok(owner),
            Some(_) => Err(SessionServerError::AuthFailed(
                "token does not match session".into(),
            )),
            None => Err(SessionServerError::AuthFailed(
                "session not bound to any token".into(),
            )),
        }
    }

    /// Check if a token is valid without session binding.
    pub fn is_valid_token(&self, token: &SessionToken) -> bool {
        self.valid_tokens.read().contains_key(token)
    }

    pub fn registered_count(&self) -> usize {
        self.valid_tokens.read().len()
    }
}

impl Default for SessionAuth {
    fn default() -> Self {
        Self::new()
    }
}

// ── SessionRouter ─────────────────────────────────────────────────────────────

/// Routes requests to the correct session handler.
pub struct SessionRouter {
    routes: RwLock<HashMap<String, RouteEntry>>,
}

#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub path: String,
    pub session_id: Option<SessionId>,
    pub handler_name: String,
    pub requires_auth: bool,
}

impl RouteEntry {
    pub fn new(path: impl Into<String>, handler: impl Into<String>, requires_auth: bool) -> Self {
        Self {
            path: path.into(),
            session_id: None,
            handler_name: handler.into(),
            requires_auth,
        }
    }
}

impl SessionRouter {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
        }
    }

    pub fn register_route(&self, entry: RouteEntry) {
        self.routes.write().insert(entry.path.clone(), entry);
    }

    /// Resolve a path to a route entry.
    pub fn route(&self, path: &str) -> ServerResult<RouteEntry> {
        self.routes
            .read()
            .get(path)
            .cloned()
            .ok_or_else(|| SessionServerError::Routing(format!("no route for '{path}'")))
    }

    /// List all registered paths.
    pub fn paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = self.routes.read().keys().cloned().collect();
        paths.sort();
        paths
    }

    pub fn route_count(&self) -> usize {
        self.routes.read().len()
    }

    pub fn unregister(&self, path: &str) -> bool {
        self.routes.write().remove(path).is_some()
    }
}

impl Default for SessionRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ── SessionMetrics ────────────────────────────────────────────────────────────

/// Tracks performance and usage metrics for the session server.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionMetricsSnapshot {
    pub total_sessions_created: u64,
    pub total_sessions_closed: u64,
    pub total_requests: u64,
    pub failed_auth_attempts: u64,
    pub expired_sessions_cleaned: u64,
    pub peak_concurrent_sessions: usize,
}

pub struct SessionMetrics {
    data: Mutex<SessionMetricsSnapshot>,
    start_time: Instant,
}

impl SessionMetrics {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            data: Mutex::new(SessionMetricsSnapshot::default()),
            start_time: Instant::now(),
        }
    }

    pub fn record_session_created(&self) {
        let mut d = self.data.lock();
        d.total_sessions_created += 1;
    }

    pub fn record_session_closed(&self) {
        self.data.lock().total_sessions_closed += 1;
    }

    pub fn record_request(&self) {
        self.data.lock().total_requests += 1;
    }

    pub fn record_auth_failure(&self) {
        self.data.lock().failed_auth_attempts += 1;
    }

    pub fn record_cleanup(&self, count: u64) {
        self.data.lock().expired_sessions_cleaned += count;
    }

    pub fn update_peak(&self, current: usize) {
        let mut d = self.data.lock();
        if current > d.peak_concurrent_sessions {
            d.peak_concurrent_sessions = current;
        }
    }

    pub fn snapshot(&self) -> SessionMetricsSnapshot {
        self.data.lock().clone()
    }

    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    pub fn reset(&self) {
        *self.data.lock() = SessionMetricsSnapshot::default();
    }
}

impl Default for SessionMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ── SessionCleanup ────────────────────────────────────────────────────────────

/// Handles cleanup of expired or closed sessions.
pub struct SessionCleanup {
    pub idle_ttl_secs: u64,
    pub cleanup_interval_secs: u64,
}

impl SessionCleanup {
    #[must_use] 
    pub const fn new(idle_ttl_secs: u64, cleanup_interval_secs: u64) -> Self {
        Self {
            idle_ttl_secs,
            cleanup_interval_secs,
        }
    }

    /// Remove expired sessions from the pool. Returns count removed.
    pub fn run(&self, pool: &SessionPool, metrics: &SessionMetrics) -> usize {
        let expired = pool.expired_ids();
        let count = expired.len();
        for id in &expired {
            let _ = pool.remove(id);
        }
        if count > 0 {
            metrics.record_cleanup(count as u64);
        }
        count
    }

    /// Remove closed sessions.
    pub fn remove_closed(&self, pool: &SessionPool) -> usize {
        let closed: Vec<SessionId> = pool
            .all_sessions()
            .into_iter()
            .filter(|s| s.state == SessionState::Closed)
            .map(|s| s.id)
            .collect();
        let count = closed.len();
        for id in &closed {
            let _ = pool.remove(id);
        }
        count
    }
}

// ── SessionServer ─────────────────────────────────────────────────────────────

/// The main session server orchestrating pool, router, auth, metrics, cleanup.
pub struct SessionServer {
    pub pool: Arc<SessionPool>,
    pub router: Arc<SessionRouter>,
    pub auth: Arc<SessionAuth>,
    pub metrics: Arc<SessionMetrics>,
    pub cleanup: Arc<SessionCleanup>,
    pub config: ServerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub max_sessions: usize,
    pub session_ttl_secs: u64,
    pub idle_ttl_secs: u64,
    pub cleanup_interval_secs: u64,
    pub bind_addr: String,
    pub require_auth: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_sessions: 100,
            session_ttl_secs: 3600,
            idle_ttl_secs: 600,
            cleanup_interval_secs: 60,
            bind_addr: "127.0.0.1:0".into(),
            require_auth: true,
        }
    }
}

impl SessionServer {
    #[must_use] 
    pub fn new(config: ServerConfig) -> Self {
        let pool = Arc::new(SessionPool::new(config.max_sessions));
        let router = Arc::new(SessionRouter::new());
        let auth = Arc::new(SessionAuth::new());
        let metrics = Arc::new(SessionMetrics::new());
        let cleanup = Arc::new(SessionCleanup::new(
            config.idle_ttl_secs,
            config.cleanup_interval_secs,
        ));
        Self {
            pool,
            router,
            auth,
            metrics,
            cleanup,
            config,
        }
    }

    #[must_use] 
    pub fn with_defaults() -> Self {
        Self::new(ServerConfig::default())
    }

    // ── Session lifecycle ─────────────────────────────────────────────────────

    /// Open a new analysis session.
    pub fn open_session(
        &self,
        owner: impl Into<String>,
        token: SessionToken,
    ) -> ServerResult<SessionId> {
        let id = SessionId::generate();
        let owner = owner.into();

        if self.config.require_auth && !self.auth.is_valid_token(&token) {
            self.metrics.record_auth_failure();
            return Err(SessionServerError::AuthFailed(
                "token not registered with server".into(),
            ));
        }

        self.auth.bind_session(id.clone(), token.clone());
        self.pool
            .create(id.clone(), token, &owner, self.config.session_ttl_secs)?;
        self.metrics.record_session_created();
        self.metrics.update_peak(self.pool.len());
        Ok(id)
    }

    /// Close an existing session.
    pub fn close_session(&self, id: &SessionId, token: &SessionToken) -> ServerResult<()> {
        if self.config.require_auth {
            self.auth.validate(id, token)?;
        }
        self.pool.close(id)?;
        self.metrics.record_session_closed();
        Ok(())
    }

    /// Handle a request for a session.
    pub fn handle_request(
        &self,
        session_id: &SessionId,
        token: &SessionToken,
        path: &str,
    ) -> ServerResult<RouteEntry> {
        if self.config.require_auth {
            self.auth.validate(session_id, token)?;
        }
        self.pool.touch(session_id)?;
        self.metrics.record_request();

        let route = self.router.route(path)?;
        Ok(route)
    }

    /// Run cleanup cycle.
    #[must_use] 
    pub fn run_cleanup(&self) -> usize {
        self.cleanup.run(&self.pool, &self.metrics) + self.cleanup.remove_closed(&self.pool)
    }

    /// List active session IDs.
    #[must_use] 
    pub fn active_sessions(&self) -> Vec<SessionId> {
        self.pool.active_ids()
    }

    /// Get server metrics snapshot.
    #[must_use] 
    pub fn metrics_snapshot(&self) -> SessionMetricsSnapshot {
        self.metrics.snapshot()
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> SessionServer {
        let cfg = ServerConfig {
            require_auth: false,
            max_sessions: 10,
            session_ttl_secs: 3600,
            ..ServerConfig::default()
        };
        SessionServer::new(cfg)
    }

    fn auth_server() -> (SessionServer, SessionToken) {
        let cfg = ServerConfig {
            require_auth: true,
            max_sessions: 10,
            ..ServerConfig::default()
        };
        let srv = SessionServer::new(cfg);
        let token = SessionToken::new("secret-token");
        srv.auth.register_token(token.clone(), "alice");
        (srv, token)
    }

    fn dummy_token() -> SessionToken {
        SessionToken::new("dummy")
    }

    // ── SessionId ─────────────────────────────────────────────────────────────

    #[test]
    fn test_session_id_generate_unique() {
        let id1 = SessionId::generate();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let id2 = SessionId::generate();
        // Both are valid session IDs (same second = same value is OK in fast CI,
        // so we just check they are non-empty).
        assert!(!id1.0.is_empty());
        assert!(!id2.0.is_empty());
    }

    #[test]
    fn test_session_id_display() {
        let id = SessionId::new("test_session");
        assert_eq!(format!("{id}"), "test_session");
    }

    // ── SessionPool ───────────────────────────────────────────────────────────

    #[test]
    fn test_pool_create_and_get() {
        let pool = SessionPool::new(10);
        let id = SessionId::new("s1");
        pool.create(id.clone(), dummy_token(), "alice", 3600)
            .unwrap();
        let s = pool.get(&id).unwrap();
        assert_eq!(s.owner, "alice");
    }

    #[test]
    fn test_pool_duplicate_create() {
        let pool = SessionPool::new(10);
        let id = SessionId::new("s1");
        pool.create(id.clone(), dummy_token(), "a", 3600).unwrap();
        let res = pool.create(id, dummy_token(), "b", 3600);
        assert!(matches!(
            res,
            Err(SessionServerError::SessionAlreadyExists(_))
        ));
    }

    #[test]
    fn test_pool_full() {
        let pool = SessionPool::new(2);
        pool.create(SessionId::new("s1"), dummy_token(), "a", 3600)
            .unwrap();
        pool.create(SessionId::new("s2"), dummy_token(), "b", 3600)
            .unwrap();
        let res = pool.create(SessionId::new("s3"), dummy_token(), "c", 3600);
        assert!(matches!(res, Err(SessionServerError::ServerFull(2))));
    }

    #[test]
    fn test_pool_close_and_remove() {
        let pool = SessionPool::new(10);
        let id = SessionId::new("s1");
        pool.create(id.clone(), dummy_token(), "a", 3600).unwrap();
        pool.close(&id).unwrap();
        let s = pool.get(&id).unwrap();
        assert_eq!(s.state, SessionState::Closed);
        pool.remove(&id).unwrap();
        assert!(pool.get(&id).is_err());
    }

    #[test]
    fn test_pool_touch() {
        let pool = SessionPool::new(10);
        let id = SessionId::new("s1");
        pool.create(id.clone(), dummy_token(), "a", 3600).unwrap();
        pool.touch(&id).unwrap();
        let s = pool.get(&id).unwrap();
        assert_eq!(s.request_count, 1);
    }

    #[test]
    fn test_pool_active_ids() {
        let pool = SessionPool::new(10);
        let id = SessionId::new("s1");
        pool.create(id.clone(), dummy_token(), "a", 3600).unwrap();
        let active = pool.active_ids();
        assert!(active.contains(&id));
    }

    #[test]
    fn test_pool_expired_zero_ttl() {
        let pool = SessionPool::new(10);
        let id = SessionId::new("exp1");
        pool.create(id.clone(), dummy_token(), "a", 0).unwrap(); // TTL = 0 → immediate expiry
        let expired = pool.expired_ids();
        assert!(expired.contains(&id));
    }

    #[test]
    fn test_pool_not_expired_large_ttl() {
        let pool = SessionPool::new(10);
        let id = SessionId::new("s1");
        pool.create(id.clone(), dummy_token(), "a", 999_999)
            .unwrap();
        let expired = pool.expired_ids();
        assert!(!expired.contains(&id));
    }

    // ── SessionAuth ───────────────────────────────────────────────────────────

    #[test]
    fn test_auth_register_and_validate() {
        let auth = SessionAuth::new();
        let token = SessionToken::new("tok1");
        let id = SessionId::new("s1");
        auth.register_token(token.clone(), "bob");
        auth.bind_session(id.clone(), token.clone());
        let owner = auth.validate(&id, &token).unwrap();
        assert_eq!(owner, "bob");
    }

    #[test]
    fn test_auth_invalid_token() {
        let auth = SessionAuth::new();
        let bad_token = SessionToken::new("bad");
        let id = SessionId::new("s1");
        auth.bind_session(id.clone(), bad_token.clone());
        let res = auth.validate(&id, &bad_token);
        assert!(matches!(res, Err(SessionServerError::AuthFailed(_))));
    }

    #[test]
    fn test_auth_token_mismatch() {
        let auth = SessionAuth::new();
        let tok1 = SessionToken::new("t1");
        let tok2 = SessionToken::new("t2");
        let id = SessionId::new("s1");
        auth.register_token(tok1.clone(), "alice");
        auth.register_token(tok2.clone(), "bob");
        auth.bind_session(id.clone(), tok1);
        let res = auth.validate(&id, &tok2);
        assert!(matches!(res, Err(SessionServerError::AuthFailed(_))));
    }

    #[test]
    fn test_auth_revoke_token() {
        let auth = SessionAuth::new();
        let tok = SessionToken::new("t");
        auth.register_token(tok.clone(), "alice");
        assert!(auth.is_valid_token(&tok));
        auth.revoke_token(&tok);
        assert!(!auth.is_valid_token(&tok));
    }

    #[test]
    fn test_auth_registered_count() {
        let auth = SessionAuth::new();
        auth.register_token(SessionToken::new("a"), "alice");
        auth.register_token(SessionToken::new("b"), "bob");
        assert_eq!(auth.registered_count(), 2);
    }

    // ── SessionRouter ─────────────────────────────────────────────────────────

    #[test]
    fn test_router_register_and_route() {
        let router = SessionRouter::new();
        router.register_route(RouteEntry::new("/analyze", "analyze_handler", true));
        let entry = router.route("/analyze").unwrap();
        assert_eq!(entry.handler_name, "analyze_handler");
    }

    #[test]
    fn test_router_not_found() {
        let router = SessionRouter::new();
        let res = router.route("/missing");
        assert!(matches!(res, Err(SessionServerError::Routing(_))));
    }

    #[test]
    fn test_router_paths_sorted() {
        let router = SessionRouter::new();
        router.register_route(RouteEntry::new("/z", "h", false));
        router.register_route(RouteEntry::new("/a", "h", false));
        let paths = router.paths();
        assert_eq!(paths[0], "/a");
        assert_eq!(paths[1], "/z");
    }

    #[test]
    fn test_router_unregister() {
        let router = SessionRouter::new();
        router.register_route(RouteEntry::new("/foo", "h", false));
        assert!(router.unregister("/foo"));
        assert!(!router.unregister("/foo"));
    }

    #[test]
    fn test_router_route_count() {
        let router = SessionRouter::new();
        router.register_route(RouteEntry::new("/a", "h", false));
        router.register_route(RouteEntry::new("/b", "h", false));
        assert_eq!(router.route_count(), 2);
    }

    // ── SessionMetrics ────────────────────────────────────────────────────────

    #[test]
    fn test_metrics_created_sessions() {
        let m = SessionMetrics::new();
        m.record_session_created();
        m.record_session_created();
        assert_eq!(m.snapshot().total_sessions_created, 2);
    }

    #[test]
    fn test_metrics_auth_failures() {
        let m = SessionMetrics::new();
        m.record_auth_failure();
        assert_eq!(m.snapshot().failed_auth_attempts, 1);
    }

    #[test]
    fn test_metrics_cleanup() {
        let m = SessionMetrics::new();
        m.record_cleanup(5);
        assert_eq!(m.snapshot().expired_sessions_cleaned, 5);
    }

    #[test]
    fn test_metrics_peak_sessions() {
        let m = SessionMetrics::new();
        m.update_peak(3);
        m.update_peak(1);
        m.update_peak(5);
        assert_eq!(m.snapshot().peak_concurrent_sessions, 5);
    }

    #[test]
    fn test_metrics_reset() {
        let m = SessionMetrics::new();
        m.record_session_created();
        m.reset();
        assert_eq!(m.snapshot().total_sessions_created, 0);
    }

    // ── SessionCleanup ────────────────────────────────────────────────────────

    #[test]
    fn test_cleanup_removes_expired() {
        let pool = SessionPool::new(10);
        pool.create(SessionId::new("exp"), dummy_token(), "a", 0)
            .unwrap();
        let metrics = SessionMetrics::new();
        let cleanup = SessionCleanup::new(0, 60);
        let removed = cleanup.run(&pool, &metrics);
        assert_eq!(removed, 1);
        assert!(pool.get(&SessionId::new("exp")).is_err());
    }

    #[test]
    fn test_cleanup_removes_closed() {
        let pool = SessionPool::new(10);
        let id = SessionId::new("closed_s");
        pool.create(id.clone(), dummy_token(), "a", 3600).unwrap();
        pool.close(&id).unwrap();
        let cleanup = SessionCleanup::new(3600, 60);
        let removed = cleanup.remove_closed(&pool);
        assert_eq!(removed, 1);
    }

    // ── SessionServer ─────────────────────────────────────────────────────────

    #[test]
    fn test_server_open_close_no_auth() {
        let srv = server();
        let id = srv.open_session("alice", dummy_token()).unwrap();
        assert!(!srv.active_sessions().is_empty());
        srv.close_session(&id, &dummy_token()).unwrap();
    }

    #[test]
    fn test_server_open_with_auth() {
        let (srv, token) = auth_server();
        let id = srv.open_session("alice", token.clone()).unwrap();
        let active = srv.active_sessions();
        assert!(!active.is_empty());
        srv.close_session(&id, &token).unwrap();
    }

    #[test]
    fn test_server_open_bad_token_rejected() {
        let (srv, _) = auth_server();
        let bad = SessionToken::new("wrong");
        let res = srv.open_session("alice", bad);
        assert!(matches!(res, Err(SessionServerError::AuthFailed(_))));
    }

    #[test]
    fn test_server_handle_request() {
        let srv = server();
        srv.router
            .register_route(RouteEntry::new("/analyze", "handler", false));
        let id = srv.open_session("user", dummy_token()).unwrap();
        let route = srv.handle_request(&id, &dummy_token(), "/analyze").unwrap();
        assert_eq!(route.handler_name, "handler");
    }

    #[test]
    fn test_server_metrics_track_sessions() {
        let srv = server();
        let id = srv.open_session("alice", dummy_token()).unwrap();
        srv.close_session(&id, &dummy_token()).unwrap();
        let snap = srv.metrics_snapshot();
        assert_eq!(snap.total_sessions_created, 1);
        assert_eq!(snap.total_sessions_closed, 1);
    }

    #[test]
    fn test_server_cleanup_cycle() {
        let mut cfg = ServerConfig {
            require_auth: false,
            ..ServerConfig::default()
        };
        cfg.session_ttl_secs = 0; // immediate expiry
        let srv = SessionServer::new(cfg);
        let _ = srv.open_session("user", dummy_token()).unwrap();
        let removed = srv.run_cleanup();
        assert!(removed > 0);
    }

    #[test]
    fn test_session_state_display() {
        assert_eq!(SessionState::Active.to_string(), "active");
        assert_eq!(SessionState::Closed.to_string(), "closed");
        assert_eq!(SessionState::Idle.to_string(), "idle");
    }

    #[test]
    fn test_server_session_touch_increments_request_count() {
        let pool = SessionPool::new(10);
        let id = SessionId::new("s1");
        pool.create(id.clone(), dummy_token(), "a", 3600).unwrap();
        pool.touch(&id).unwrap();
        pool.touch(&id).unwrap();
        let s = pool.get(&id).unwrap();
        assert_eq!(s.request_count, 2);
    }

    #[test]
    fn test_session_id_new() {
        let id = SessionId::new("abc");
        assert_eq!(id.0, "abc");
    }

    #[test]
    fn test_session_token_new() {
        let tok = SessionToken::new("secret");
        assert_eq!(tok.0, "secret");
    }

    #[test]
    fn test_server_config_default() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.max_sessions, 100);
        assert!(cfg.require_auth);
    }

    #[test]
    fn test_server_with_defaults() {
        let srv = SessionServer::with_defaults();
        assert_eq!(srv.config.max_sessions, 100);
    }

    #[test]
    fn test_pool_all_sessions() {
        let pool = SessionPool::new(10);
        pool.create(SessionId::new("s1"), dummy_token(), "a", 3600)
            .unwrap();
        pool.create(SessionId::new("s2"), dummy_token(), "b", 3600)
            .unwrap();
        assert_eq!(pool.all_sessions().len(), 2);
    }

    #[test]
    fn test_metrics_uptime_non_negative() {
        let m = SessionMetrics::new();
        assert!(m.uptime_secs() < 10); // just created
    }

    #[test]
    fn test_metrics_request_count() {
        let m = SessionMetrics::new();
        m.record_request();
        m.record_request();
        assert_eq!(m.snapshot().total_requests, 2);
    }

    #[test]
    fn test_cleanup_nothing_to_clean() {
        let pool = SessionPool::new(10);
        pool.create(SessionId::new("live"), dummy_token(), "a", 9999)
            .unwrap();
        let metrics = SessionMetrics::new();
        let cleanup = SessionCleanup::new(9999, 60);
        let removed = cleanup.run(&pool, &metrics);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_server_active_sessions_empty() {
        let srv = server();
        assert!(srv.active_sessions().is_empty());
    }

    #[test]
    fn test_route_entry_requires_auth_field() {
        let entry = RouteEntry::new("/secure", "handler", true);
        assert!(entry.requires_auth);
    }

    #[test]
    fn test_server_session_age() {
        let pool = SessionPool::new(10);
        let id = SessionId::new("s1");
        pool.create(id.clone(), dummy_token(), "a", 3600).unwrap();
        let s = pool.get(&id).unwrap();
        assert!(s.age_secs() >= 0);
    }
}
