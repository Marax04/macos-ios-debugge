//! `mitm_engine` — Full MITM proxy engine.
//!
//! Provides [`MitmEngine`] which orchestrates interception of TCP/HTTP traffic
//! through a chain of [`Interceptor`] handlers.  Requests and responses flow
//! through [`RequestQueue`] / [`ResponseQueue`] before being forwarded.
//! [`SessionTracker`] maintains per-connection state.  [`InterceptorChain`]
//! lets multiple interceptors collaborate.  [`MitmStats`] / [`MitmReport`]
//! expose aggregated metrics.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the MITM engine.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MitmError {
    #[error("session not found: {0}")]
    SessionNotFound(u64),
    #[error("queue full (capacity {0})")]
    QueueFull(usize),
    #[error("queue empty")]
    QueueEmpty,
    #[error("interceptor error: {0}")]
    InterceptorError(String),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("engine not running")]
    NotRunning,
    #[error("engine already running")]
    AlreadyRunning,
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("session limit reached ({0})")]
    SessionLimit(usize),
}

// ─── Direction ────────────────────────────────────────────────────────────────

/// Flow direction for a captured message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientToServer => write!(f, "C→S"),
            Self::ServerToClient => write!(f, "S→C"),
        }
    }
}

// ─── InterceptAction ──────────────────────────────────────────────────────────

/// Decision returned by an interceptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptAction {
    /// Forward the message unchanged.
    Forward,
    /// Forward a modified copy of the message.
    Modify(Vec<u8>),
    /// Drop the message silently.
    Drop,
    /// Respond directly to the client without forwarding upstream.
    Respond(Vec<u8>),
    /// Redirect to a different address.
    Redirect(SocketAddr),
}

// ─── HttpRequest ──────────────────────────────────────────────────────────────

/// Minimal parsed HTTP request — an internal message carrier used within the
/// MITM engine's queue and session machinery.
///
/// Intentionally distinct from [`crate::http_interceptor::HttpRequest`], which
/// is the full-featured typed model (with [`crate::http_interceptor::HttpMethod`],
/// [`crate::http_interceptor::HttpVersion`], and [`crate::http_interceptor::HeaderMap`])
/// used for rule-based transformation.  This struct keeps method/version as
/// raw strings and headers as a flat `Vec` to minimise allocation overhead in
/// the hot forwarding path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(method: impl Into<String>, uri: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            uri: uri.into(),
            version: "HTTP/1.1".into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[must_use] 
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn add_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.push((name.into(), value.into()));
    }

    /// Serialize to bytes.
    #[must_use] 
    pub fn to_bytes(&self) -> Vec<u8> {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = write!(out, "{} {} {}\r\n", self.method, self.uri, self.version);
        for (k, v) in &self.headers {
            let _ = write!(out, "{k}: {v}\r\n");
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }

    /// Parse from raw bytes (minimal parser).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn from_bytes(data: &[u8]) -> Result<Self, MitmError> {
        let text = std::str::from_utf8(data).map_err(|e| MitmError::ParseError(e.to_string()))?;
        let mut lines = text.splitn(2, "\r\n\r\n");
        let head = lines
            .next()
            .ok_or_else(|| MitmError::ParseError("no head".into()))?;
        let body_str = lines.next().unwrap_or("");
        let mut head_lines = head.lines();
        let request_line = head_lines
            .next()
            .ok_or_else(|| MitmError::ParseError("empty".into()))?;
        let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
        if parts.len() < 3 {
            return Err(MitmError::ParseError("bad request line".into()));
        }
        let mut headers = Vec::new();
        for line in head_lines {
            if let Some(pos) = line.find(':') {
                let key = line[..pos].trim().to_string();
                let val = line[pos + 1..].trim().to_string();
                headers.push((key, val));
            }
        }
        Ok(Self {
            method: parts[0].to_string(),
            uri: parts[1].to_string(),
            version: parts[2].to_string(),
            headers,
            body: body_str.as_bytes().to_vec(),
        })
    }
}

// ─── HttpResponse ─────────────────────────────────────────────────────────────

/// Minimal parsed HTTP response — the counterpart to [`HttpRequest`] above.
///
/// Distinct from [`crate::http_interceptor::HttpResponse`]; see that type's
/// docs for the full-featured version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status_code: u16, reason: impl Into<String>) -> Self {
        Self {
            version: "HTTP/1.1".into(),
            status_code,
            reason: reason.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[must_use] 
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[must_use] 
    pub fn to_bytes(&self) -> Vec<u8> {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = write!(out, "{} {} {}\r\n", self.version, self.status_code, self.reason);
        for (k, v) in &self.headers {
            let _ = write!(out, "{k}: {v}\r\n");
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

// ─── MitmMessage ──────────────────────────────────────────────────────────────

/// A single intercepted message (request or response payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitmMessage {
    pub session_id: u64,
    pub direction: Direction,
    pub raw: Vec<u8>,
    pub timestamp_ms: u64,
}

impl MitmMessage {
    #[must_use] 
    pub fn new(session_id: u64, direction: Direction, raw: Vec<u8>) -> Self {
        let ts = u64::try_from(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis()).unwrap_or(u64::MAX);
        Self {
            session_id,
            direction,
            raw,
            timestamp_ms: ts,
        }
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.raw.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}

// ─── RequestQueue ─────────────────────────────────────────────────────────────

/// Bounded FIFO queue for intercepted requests.
#[derive(Debug)]
pub struct RequestQueue {
    capacity: usize,
    inner: Mutex<std::collections::VecDeque<MitmMessage>>,
    total_enqueued: AtomicU64,
    total_dropped: AtomicU64,
}

impl RequestQueue {
    #[must_use] 
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Mutex::new(std::collections::VecDeque::with_capacity(capacity.min(4096))),
            total_enqueued: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
        }
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn enqueue(&self, msg: MitmMessage) -> Result<(), MitmError> {
        let mut q = self.inner.lock();
        if q.len() >= self.capacity {
            self.total_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(MitmError::QueueFull(self.capacity));
        }
        q.push_back(msg);
        self.total_enqueued.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn dequeue(&self) -> Option<MitmMessage> {
        self.inner.lock().pop_front()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn total_enqueued(&self) -> u64 {
        self.total_enqueued.load(Ordering::Relaxed)
    }

    pub fn total_dropped(&self) -> u64 {
        self.total_dropped.load(Ordering::Relaxed)
    }

    pub fn drain(&self) -> Vec<MitmMessage> {
        self.inner.lock().drain(..).collect()
    }

    pub const fn capacity(&self) -> usize {
        self.capacity
    }
}

// ─── ResponseQueue ────────────────────────────────────────────────────────────

/// Bounded FIFO queue for intercepted responses.
#[derive(Debug)]
pub struct ResponseQueue {
    inner: RequestQueue, // reuse same logic
}

impl ResponseQueue {
    #[must_use] 
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: RequestQueue::new(capacity),
        }
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn enqueue(&self, msg: MitmMessage) -> Result<(), MitmError> {
        self.inner.enqueue(msg)
    }

    pub fn dequeue(&self) -> Option<MitmMessage> {
        self.inner.dequeue()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn total_enqueued(&self) -> u64 {
        self.inner.total_enqueued()
    }

    pub fn drain(&self) -> Vec<MitmMessage> {
        self.inner.drain()
    }
}

// ─── SessionState ─────────────────────────────────────────────────────────────

/// Lifecycle state of a MITM session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Handshaking,
    Active,
    Draining,
    Closed,
}

// ─── SessionRecord ────────────────────────────────────────────────────────────

/// Per-session metadata kept by [`SessionTracker`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub id: u64,
    pub client_addr: SocketAddr,
    pub target_addr: SocketAddr,
    pub state: SessionState,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub messages_up: u64,
    pub messages_down: u64,
    pub created_ms: u64,
    pub last_activity_ms: u64,
    pub tls: bool,
    pub sni: Option<String>,
}

impl SessionRecord {
    fn now_ms() -> u64 {
        u64::try_from(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis()).unwrap_or(u64::MAX)
    }

    #[must_use] 
    pub fn new(id: u64, client: SocketAddr, target: SocketAddr) -> Self {
        let now = Self::now_ms();
        Self {
            id,
            client_addr: client,
            target_addr: target,
            state: SessionState::Handshaking,
            bytes_up: 0,
            bytes_down: 0,
            messages_up: 0,
            messages_down: 0,
            created_ms: now,
            last_activity_ms: now,
            tls: false,
            sni: None,
        }
    }

    pub fn record_upstream(&mut self, bytes: u64) {
        self.bytes_up += bytes;
        self.messages_up += 1;
        self.last_activity_ms = Self::now_ms();
    }

    pub fn record_downstream(&mut self, bytes: u64) {
        self.bytes_down += bytes;
        self.messages_down += 1;
        self.last_activity_ms = Self::now_ms();
    }

    #[must_use] 
    pub fn duration_ms(&self) -> u64 {
        Self::now_ms().saturating_sub(self.created_ms)
    }

    #[must_use] 
    pub const fn total_bytes(&self) -> u64 {
        self.bytes_up + self.bytes_down
    }
}

// ─── SessionTracker ───────────────────────────────────────────────────────────

/// Thread-safe store of active MITM sessions.
#[derive(Debug)]
pub struct SessionTracker {
    sessions: RwLock<HashMap<u64, SessionRecord>>,
    next_id: AtomicU64,
    max_sessions: usize,
}

impl SessionTracker {
    #[must_use] 
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            max_sessions,
        }
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn create_session(&self, client: SocketAddr, target: SocketAddr) -> Result<u64, MitmError> {
        let mut sessions = self.sessions.write();
        if sessions.len() >= self.max_sessions {
            return Err(MitmError::SessionLimit(self.max_sessions));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        sessions.insert(id, SessionRecord::new(id, client, target));
        Ok(id)
    }

    pub fn get(&self, id: u64) -> Option<SessionRecord> {
        self.sessions.read().get(&id).cloned()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn update<F>(&self, id: u64, f: F) -> Result<(), MitmError>
    where
        F: FnOnce(&mut SessionRecord),
    {
        let mut sessions = self.sessions.write();
        let rec = sessions
            .get_mut(&id)
            .ok_or(MitmError::SessionNotFound(id))?;
        f(rec);
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn close_session(&self, id: u64) -> Result<(), MitmError> {
        self.update(id, |r| r.state = SessionState::Closed)
    }

    pub fn remove_session(&self, id: u64) -> Option<SessionRecord> {
        self.sessions.write().remove(&id)
    }

    pub fn active_count(&self) -> usize {
        self.sessions
            .read()
            .values()
            .filter(|r| r.state == SessionState::Active)
            .count()
    }

    pub fn all_sessions(&self) -> Vec<SessionRecord> {
        self.sessions.read().values().cloned().collect()
    }

    pub fn closed_sessions(&self) -> Vec<SessionRecord> {
        self.sessions
            .read()
            .values()
            .filter(|r| r.state == SessionState::Closed)
            .cloned()
            .collect()
    }

    pub fn purge_closed(&self) -> usize {
        let mut sessions = self.sessions.write();
        let before = sessions.len();
        sessions.retain(|_, r| r.state != SessionState::Closed);
        before - sessions.len()
    }
}

// ─── Interceptor trait ────────────────────────────────────────────────────────

/// Trait implemented by components that can inspect/modify traffic.
pub trait Interceptor: Send + Sync + fmt::Debug {
    /// Name of this interceptor (for logging).
    fn name(&self) -> &str;
    /// Called when a request arrives from the client.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    fn on_request(
        &self,
        session: &SessionRecord,
        data: &[u8],
    ) -> Result<InterceptAction, MitmError>;
    /// Called when a response arrives from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    fn on_response(
        &self,
        session: &SessionRecord,
        data: &[u8],
    ) -> Result<InterceptAction, MitmError>;
}

// ─── LoggingInterceptor ───────────────────────────────────────────────────────

/// Simple interceptor that logs traffic but never modifies it.
#[derive(Debug, Default)]
pub struct LoggingInterceptor {
    log: Mutex<Vec<String>>,
}

impl LoggingInterceptor {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> Vec<String> {
        self.log.lock().clone()
    }
}

impl Interceptor for LoggingInterceptor {
    fn name(&self) -> &'static str {
        "logging"
    }

    fn on_request(
        &self,
        session: &SessionRecord,
        data: &[u8],
    ) -> Result<InterceptAction, MitmError> {
        self.log.lock().push(format!(
            "[REQ] sid={} {} → {} {} bytes",
            session.id,
            session.client_addr,
            session.target_addr,
            data.len()
        ));
        Ok(InterceptAction::Forward)
    }

    fn on_response(
        &self,
        session: &SessionRecord,
        data: &[u8],
    ) -> Result<InterceptAction, MitmError> {
        self.log.lock().push(format!(
            "[RES] sid={} {} ← {} {} bytes",
            session.id,
            session.client_addr,
            session.target_addr,
            data.len()
        ));
        Ok(InterceptAction::Forward)
    }
}

// ─── HeaderInjector ───────────────────────────────────────────────────────────

/// Interceptor that injects an HTTP header into every request.
#[derive(Debug)]
pub struct HeaderInjector {
    header_name: String,
    header_value: String,
}

impl HeaderInjector {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            header_name: name.into(),
            header_value: value.into(),
        }
    }
}

impl Interceptor for HeaderInjector {
    fn name(&self) -> &'static str {
        "header_injector"
    }

    fn on_request(
        &self,
        _session: &SessionRecord,
        data: &[u8],
    ) -> Result<InterceptAction, MitmError> {
        // Insert header before the blank line
        if let Ok(text) = std::str::from_utf8(data) && let Some(pos) = text.find("\r\n\r\n") {
            let inject = format!("{}: {}\r\n", self.header_name, self.header_value);
            let mut modified = text[..pos].to_string();
            modified.push_str("\r\n");
            modified.push_str(&inject);
            modified.push_str("\r\n");
            modified.push_str(&text[pos + 4..]);
            return Ok(InterceptAction::Modify(modified.into_bytes()));
        }
        Ok(InterceptAction::Forward)
    }

    fn on_response(
        &self,
        _session: &SessionRecord,
        _data: &[u8],
    ) -> Result<InterceptAction, MitmError> {
        Ok(InterceptAction::Forward)
    }
}

// ─── BlocklistInterceptor ─────────────────────────────────────────────────────

/// Interceptor that drops requests to blocked hosts.
#[derive(Debug)]
pub struct BlocklistInterceptor {
    blocked: Vec<String>,
}

impl BlocklistInterceptor {
    #[must_use] 
    pub const fn new(blocked: Vec<String>) -> Self {
        Self { blocked }
    }

    pub fn add(&mut self, host: impl Into<String>) {
        self.blocked.push(host.into());
    }

    fn is_blocked(&self, data: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(data) {
            for b in &self.blocked {
                if text.contains(b.as_str()) {
                    return true;
                }
            }
        }
        false
    }
}

impl Interceptor for BlocklistInterceptor {
    fn name(&self) -> &'static str {
        "blocklist"
    }

    fn on_request(
        &self,
        _session: &SessionRecord,
        data: &[u8],
    ) -> Result<InterceptAction, MitmError> {
        if self.is_blocked(data) {
            Ok(InterceptAction::Drop)
        } else {
            Ok(InterceptAction::Forward)
        }
    }

    fn on_response(
        &self,
        _session: &SessionRecord,
        _data: &[u8],
    ) -> Result<InterceptAction, MitmError> {
        Ok(InterceptAction::Forward)
    }
}

// ─── InterceptorChain ─────────────────────────────────────────────────────────

/// Ordered sequence of interceptors; the first non-Forward action wins.
#[derive(Debug, Default)]
pub struct InterceptorChain {
    interceptors: Vec<Box<dyn Interceptor>>,
}

impl InterceptorChain {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add<I: Interceptor + 'static>(&mut self, interceptor: I) {
        self.interceptors.push(Box::new(interceptor));
    }

    #[must_use] 
    pub fn len(&self) -> usize {
        self.interceptors.len()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.interceptors.is_empty()
    }

    #[must_use] 
    pub fn names(&self) -> Vec<&str> {
        self.interceptors.iter().map(|i| i.name()).collect()
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn process_request(
        &self,
        session: &SessionRecord,
        data: &[u8],
    ) -> Result<InterceptAction, MitmError> {
        for interceptor in &self.interceptors {
            let action = interceptor.on_request(session, data)?;
            if action != InterceptAction::Forward {
                return Ok(action);
            }
        }
        Ok(InterceptAction::Forward)
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn process_response(
        &self,
        session: &SessionRecord,
        data: &[u8],
    ) -> Result<InterceptAction, MitmError> {
        for interceptor in &self.interceptors {
            let action = interceptor.on_response(session, data)?;
            if action != InterceptAction::Forward {
                return Ok(action);
            }
        }
        Ok(InterceptAction::Forward)
    }
}

// ─── MitmStats ────────────────────────────────────────────────────────────────

/// Aggregated statistics for the MITM engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MitmStats {
    pub sessions_total: u64,
    pub sessions_active: u64,
    pub sessions_closed: u64,
    pub requests_total: u64,
    pub responses_total: u64,
    pub requests_dropped: u64,
    pub responses_dropped: u64,
    pub requests_modified: u64,
    pub responses_modified: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub interceptor_errors: u64,
}

impl MitmStats {
    #[must_use] 
    pub const fn total_bytes(&self) -> u64 {
        self.bytes_up + self.bytes_down
    }

    #[must_use] 
    pub fn drop_rate_requests(&self) -> f64 {
        if self.requests_total == 0 {
            0.0
        } else {
            self.requests_dropped as f64 / self.requests_total as f64
        }
    }
}

// ─── MitmReport ───────────────────────────────────────────────────────────────

/// Human-readable report generated from [`MitmStats`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitmReport {
    pub generated_at_ms: u64,
    pub stats: MitmStats,
    pub top_sessions: Vec<SessionRecord>,
    pub summary: String,
}

impl MitmReport {
    #[must_use] 
    pub fn new(stats: MitmStats, top_sessions: Vec<SessionRecord>) -> Self {
        let summary = format!(
            "Sessions: {} active / {} total | Traffic: {} up / {} down | Drop rate: {:.1}%",
            stats.sessions_active,
            stats.sessions_total,
            stats.bytes_up,
            stats.bytes_down,
            stats.drop_rate_requests() * 100.0,
        );
        let ts = u64::try_from(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis()).unwrap_or(u64::MAX);
        Self {
            generated_at_ms: ts,
            stats,
            top_sessions,
            summary,
        }
    }
}

// ─── MitmConfig ───────────────────────────────────────────────────────────────

/// Configuration for [`MitmEngine`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitmConfig {
    pub listen_addr: SocketAddr,
    pub max_sessions: usize,
    pub request_queue_capacity: usize,
    pub response_queue_capacity: usize,
    pub enable_tls_interception: bool,
    pub idle_timeout_secs: u64,
}

impl Default for MitmConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            max_sessions: 1024,
            request_queue_capacity: 4096,
            response_queue_capacity: 4096,
            enable_tls_interception: false,
            idle_timeout_secs: 120,
        }
    }
}

impl MitmConfig {
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn validate(&self) -> Result<(), MitmError> {
        if self.max_sessions == 0 {
            return Err(MitmError::InvalidConfig("max_sessions must be > 0".into()));
        }
        if self.request_queue_capacity == 0 {
            return Err(MitmError::InvalidConfig(
                "request_queue_capacity must be > 0".into(),
            ));
        }
        Ok(())
    }
}

// ─── MitmEngine ───────────────────────────────────────────────────────────────

/// Full MITM proxy engine.
///
/// Manages sessions, queues, interceptor chains, and statistics.  In a real
/// deployment the engine would drive async I/O loops; here the API surface is
/// synchronous so it can be used in tests without a runtime.
#[derive(Debug)]
pub struct MitmEngine {
    config: MitmConfig,
    running: Mutex<bool>,
    session_tracker: Arc<SessionTracker>,
    request_queue: Arc<RequestQueue>,
    response_queue: Arc<ResponseQueue>,
    chain: RwLock<InterceptorChain>,
    stats: Mutex<MitmStats>,
}

impl MitmEngine {
    /// Create a new engine with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn new(config: MitmConfig) -> Result<Self, MitmError> {
        config.validate()?;
        Ok(Self {
            session_tracker: Arc::new(SessionTracker::new(config.max_sessions)),
            request_queue: Arc::new(RequestQueue::new(config.request_queue_capacity)),
            response_queue: Arc::new(ResponseQueue::new(config.response_queue_capacity)),
            chain: RwLock::new(InterceptorChain::new()),
            stats: Mutex::new(MitmStats::default()),
            running: Mutex::new(false),
            config,
        })
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn with_defaults() -> Result<Self, MitmError> {
        Self::new(MitmConfig::default())
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn start(&self) -> Result<(), MitmError> {
        let mut running = self.running.lock();
        if *running {
            return Err(MitmError::AlreadyRunning);
        }
        *running = true;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn stop(&self) -> Result<(), MitmError> {
        let mut running = self.running.lock();
        if !*running {
            return Err(MitmError::NotRunning);
        }
        *running = false;
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        *self.running.lock()
    }

    // ── Interceptors ───────────────────────────────────────────────────────

    pub fn add_interceptor<I: Interceptor + 'static>(&self, interceptor: I) {
        self.chain.write().add(interceptor);
    }

    pub fn interceptor_count(&self) -> usize {
        self.chain.read().len()
    }

    pub fn interceptor_names(&self) -> Vec<String> {
        self.chain
            .read()
            .names()
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    // ── Sessions ───────────────────────────────────────────────────────────

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn open_session(&self, client: SocketAddr, target: SocketAddr) -> Result<u64, MitmError> {
        if !self.is_running() {
            return Err(MitmError::NotRunning);
        }
        let id = self.session_tracker.create_session(client, target)?;
        self.session_tracker
            .update(id, |r| r.state = SessionState::Active)?;
        let mut stats = self.stats.lock();
        stats.sessions_total += 1;
        stats.sessions_active += 1;
        Ok(id)
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn close_session(&self, id: u64) -> Result<(), MitmError> {
        self.session_tracker.close_session(id)?;
        let mut stats = self.stats.lock();
        stats.sessions_active = stats.sessions_active.saturating_sub(1);
        stats.sessions_closed += 1;
        Ok(())
    }

    pub fn get_session(&self, id: u64) -> Option<SessionRecord> {
        self.session_tracker.get(id)
    }

    pub fn active_session_count(&self) -> usize {
        self.session_tracker.active_count()
    }

    // ── Traffic handling ───────────────────────────────────────────────────

    /// Submit a request from the client; returns the action to take.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn handle_request(
        &self,
        session_id: u64,
        data: Vec<u8>,
    ) -> Result<InterceptAction, MitmError> {
        let session = self
            .session_tracker
            .get(session_id)
            .ok_or(MitmError::SessionNotFound(session_id))?;
        let msg = MitmMessage::new(session_id, Direction::ClientToServer, data.clone());
        let _ = self.request_queue.enqueue(msg);

        let action = self
            .chain
            .read()
            .process_request(&session, &data)
            .inspect_err(|_e| {
                self.stats.lock().interceptor_errors += 1;
            })?;

        {
            let mut stats = self.stats.lock();
            stats.requests_total += 1;
            stats.bytes_up += data.len() as u64;
            match &action {
                InterceptAction::Drop => stats.requests_dropped += 1,
                InterceptAction::Modify(_) => stats.requests_modified += 1,
                _ => {}
            }
        }

        self.session_tracker
            .update(session_id, |r| r.record_upstream(data.len() as u64))?;

        Ok(action)
    }

    /// Submit a response from the server; returns the action to take.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn handle_response(
        &self,
        session_id: u64,
        data: Vec<u8>,
    ) -> Result<InterceptAction, MitmError> {
        let session = self
            .session_tracker
            .get(session_id)
            .ok_or(MitmError::SessionNotFound(session_id))?;
        let msg = MitmMessage::new(session_id, Direction::ServerToClient, data.clone());
        let _ = self.response_queue.enqueue(msg);

        let action = self
            .chain
            .read()
            .process_response(&session, &data)
            .inspect_err(|_e| {
                self.stats.lock().interceptor_errors += 1;
            })?;

        {
            let mut stats = self.stats.lock();
            stats.responses_total += 1;
            stats.bytes_down += data.len() as u64;
            match &action {
                InterceptAction::Drop => stats.responses_dropped += 1,
                InterceptAction::Modify(_) => stats.responses_modified += 1,
                _ => {}
            }
        }

        self.session_tracker
            .update(session_id, |r| r.record_downstream(data.len() as u64))?;

        Ok(action)
    }

    // ── Queues ─────────────────────────────────────────────────────────────

    pub fn request_queue(&self) -> &RequestQueue {
        &self.request_queue
    }

    pub fn response_queue(&self) -> &ResponseQueue {
        &self.response_queue
    }

    // ── Reporting ──────────────────────────────────────────────────────────

    pub fn stats(&self) -> MitmStats {
        self.stats.lock().clone()
    }

    pub fn report(&self) -> MitmReport {
        let stats = self.stats();
        let mut sessions = self.session_tracker.all_sessions();
        // top 5 by bytes
        sessions.sort_by_key(|b| std::cmp::Reverse(b.total_bytes()));
        sessions.truncate(5);
        MitmReport::new(stats, sessions)
    }

    pub const fn config(&self) -> &MitmConfig {
        &self.config
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn local_addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn make_engine() -> MitmEngine {
        let cfg = MitmConfig {
            max_sessions: 100,
            request_queue_capacity: 64,
            response_queue_capacity: 64,
            ..MitmConfig::default()
        };
        let engine = MitmEngine::new(cfg).unwrap();
        engine.start().unwrap();
        engine
    }

    // --- MitmError ---

    #[test]
    fn test_error_display_session_not_found() {
        let e = MitmError::SessionNotFound(42);
        assert!(e.to_string().contains("42"));
    }

    #[test]
    fn test_error_display_queue_full() {
        let e = MitmError::QueueFull(100);
        assert!(e.to_string().contains("100"));
    }

    #[test]
    fn test_error_display_session_limit() {
        let e = MitmError::SessionLimit(10);
        assert!(e.to_string().contains("10"));
    }

    // --- Direction ---

    #[test]
    fn test_direction_display() {
        assert_eq!(Direction::ClientToServer.to_string(), "C→S");
        assert_eq!(Direction::ServerToClient.to_string(), "S→C");
    }

    // --- HttpRequest ---

    #[test]
    fn test_http_request_new() {
        let req = HttpRequest::new("GET", "/index.html");
        assert_eq!(req.method, "GET");
        assert_eq!(req.uri, "/index.html");
        assert!(req.body.is_empty());
    }

    #[test]
    fn test_http_request_header_lookup() {
        let mut req = HttpRequest::new("GET", "/");
        req.add_header("Content-Type", "text/plain");
        assert_eq!(req.header("content-type"), Some("text/plain"));
        assert!(req.header("x-missing").is_none());
    }

    #[test]
    fn test_http_request_to_bytes_round_trip() {
        let mut req = HttpRequest::new("POST", "/submit");
        req.add_header("Host", "example.com");
        req.body = b"hello".to_vec();
        let bytes = req.to_bytes();
        assert!(bytes.starts_with(b"POST /submit HTTP/1.1\r\n"));
    }

    #[test]
    fn test_http_request_from_bytes() {
        let raw = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let req = HttpRequest::from_bytes(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.uri, "/path");
    }

    #[test]
    fn test_http_request_from_bytes_invalid() {
        assert!(HttpRequest::from_bytes(b"\xff\xfe").is_err());
    }

    // --- HttpResponse ---

    #[test]
    fn test_http_response_new() {
        let resp = HttpResponse::new(200, "OK");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.reason, "OK");
    }

    #[test]
    fn test_http_response_to_bytes() {
        let mut resp = HttpResponse::new(404, "Not Found");
        resp.headers.push(("Content-Length".into(), "0".into()));
        let bytes = resp.to_bytes();
        assert!(bytes.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
    }

    // --- MitmMessage ---

    #[test]
    fn test_mitm_message_len() {
        let msg = MitmMessage::new(1, Direction::ClientToServer, vec![1, 2, 3]);
        assert_eq!(msg.len(), 3);
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_mitm_message_empty() {
        let msg = MitmMessage::new(1, Direction::ServerToClient, vec![]);
        assert!(msg.is_empty());
    }

    // --- RequestQueue ---

    #[test]
    fn test_request_queue_enqueue_dequeue() {
        let q = RequestQueue::new(4);
        let msg = MitmMessage::new(1, Direction::ClientToServer, b"data".to_vec());
        q.enqueue(msg).unwrap();
        assert_eq!(q.len(), 1);
        let dequeued = q.dequeue().unwrap();
        assert_eq!(dequeued.raw, b"data");
        assert!(q.is_empty());
    }

    #[test]
    fn test_request_queue_full() {
        let q = RequestQueue::new(2);
        for i in 0..2u8 {
            q.enqueue(MitmMessage::new(1, Direction::ClientToServer, vec![i]))
                .unwrap();
        }
        assert!(matches!(
            q.enqueue(MitmMessage::new(1, Direction::ClientToServer, vec![99])),
            Err(MitmError::QueueFull(2))
        ));
        assert_eq!(q.total_dropped(), 1);
    }

    #[test]
    fn test_request_queue_drain() {
        let q = RequestQueue::new(10);
        for i in 0..5u8 {
            q.enqueue(MitmMessage::new(1, Direction::ClientToServer, vec![i]))
                .unwrap();
        }
        let drained = q.drain();
        assert_eq!(drained.len(), 5);
        assert!(q.is_empty());
    }

    #[test]
    fn test_request_queue_capacity() {
        let q = RequestQueue::new(32);
        assert_eq!(q.capacity(), 32);
    }

    // --- ResponseQueue ---

    #[test]
    fn test_response_queue_basic() {
        let q = ResponseQueue::new(4);
        let msg = MitmMessage::new(2, Direction::ServerToClient, b"resp".to_vec());
        q.enqueue(msg).unwrap();
        assert_eq!(q.total_enqueued(), 1);
        let out = q.dequeue().unwrap();
        assert_eq!(out.direction, Direction::ServerToClient);
    }

    // --- SessionTracker ---

    #[test]
    fn test_session_tracker_create_and_get() {
        let tracker = SessionTracker::new(10);
        let id = tracker
            .create_session(local_addr(1000), local_addr(80))
            .unwrap();
        let rec = tracker.get(id).unwrap();
        assert_eq!(rec.id, id);
        assert_eq!(rec.state, SessionState::Handshaking);
    }

    #[test]
    fn test_session_tracker_limit() {
        let tracker = SessionTracker::new(2);
        tracker
            .create_session(local_addr(1), local_addr(80))
            .unwrap();
        tracker
            .create_session(local_addr(2), local_addr(80))
            .unwrap();
        assert!(matches!(
            tracker.create_session(local_addr(3), local_addr(80)),
            Err(MitmError::SessionLimit(2))
        ));
    }

    #[test]
    fn test_session_tracker_close_and_purge() {
        let tracker = SessionTracker::new(10);
        let id = tracker
            .create_session(local_addr(5000), local_addr(443))
            .unwrap();
        tracker.close_session(id).unwrap();
        assert_eq!(tracker.closed_sessions().len(), 1);
        let purged = tracker.purge_closed();
        assert_eq!(purged, 1);
        assert_eq!(tracker.all_sessions().len(), 0);
    }

    #[test]
    fn test_session_record_bytes() {
        let mut rec = SessionRecord::new(1, local_addr(1000), local_addr(80));
        rec.record_upstream(512);
        rec.record_downstream(1024);
        assert_eq!(rec.total_bytes(), 1536);
        assert_eq!(rec.messages_up, 1);
        assert_eq!(rec.messages_down, 1);
    }

    // --- InterceptorChain ---

    #[test]
    fn test_chain_empty_forwards() {
        let chain = InterceptorChain::new();
        let rec = SessionRecord::new(1, local_addr(1), local_addr(80));
        let action = chain
            .process_request(&rec, b"GET / HTTP/1.1\r\n\r\n")
            .unwrap();
        assert_eq!(action, InterceptAction::Forward);
    }

    #[test]
    fn test_chain_with_logging_interceptor() {
        let mut chain = InterceptorChain::new();
        let logger = LoggingInterceptor::new();
        chain.add(logger);
        assert_eq!(chain.len(), 1);
        assert!(chain.names().contains(&"logging"));
    }

    #[test]
    fn test_chain_blocklist_drops() {
        let mut chain = InterceptorChain::new();
        chain.add(BlocklistInterceptor::new(vec!["evil.com".into()]));
        let rec = SessionRecord::new(1, local_addr(1), local_addr(80));
        let action = chain
            .process_request(&rec, b"GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n")
            .unwrap();
        assert_eq!(action, InterceptAction::Drop);
    }

    #[test]
    fn test_chain_header_injector_modifies() {
        let mut chain = InterceptorChain::new();
        chain.add(HeaderInjector::new("X-Injected", "yes"));
        let rec = SessionRecord::new(1, local_addr(1), local_addr(80));
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let action = chain.process_request(&rec, data).unwrap();
        if let InterceptAction::Modify(body) = action {
            let s = String::from_utf8(body).unwrap();
            assert!(s.contains("X-Injected: yes"));
        } else {
            panic!("expected Modify");
        }
    }

    // --- MitmEngine ---

    #[test]
    fn test_engine_start_stop() {
        let engine = MitmEngine::with_defaults().unwrap();
        assert!(!engine.is_running());
        engine.start().unwrap();
        assert!(engine.is_running());
        engine.stop().unwrap();
        assert!(!engine.is_running());
    }

    #[test]
    fn test_engine_double_start_errors() {
        let engine = make_engine();
        assert!(matches!(engine.start(), Err(MitmError::AlreadyRunning)));
    }

    #[test]
    fn test_engine_stop_when_not_running_errors() {
        let engine = MitmEngine::with_defaults().unwrap();
        assert!(matches!(engine.stop(), Err(MitmError::NotRunning)));
    }

    #[test]
    fn test_engine_open_close_session() {
        let engine = make_engine();
        let id = engine
            .open_session(local_addr(5000), local_addr(80))
            .unwrap();
        assert_eq!(engine.active_session_count(), 1);
        engine.close_session(id).unwrap();
        assert_eq!(engine.stats().sessions_closed, 1);
    }

    #[test]
    fn test_engine_open_session_not_running() {
        let engine = MitmEngine::with_defaults().unwrap();
        assert!(matches!(
            engine.open_session(local_addr(1), local_addr(80)),
            Err(MitmError::NotRunning)
        ));
    }

    #[test]
    fn test_engine_handle_request_forward() {
        let engine = make_engine();
        let id = engine
            .open_session(local_addr(5000), local_addr(80))
            .unwrap();
        let action = engine
            .handle_request(id, b"GET / HTTP/1.1\r\n\r\n".to_vec())
            .unwrap();
        assert_eq!(action, InterceptAction::Forward);
        assert_eq!(engine.stats().requests_total, 1);
    }

    #[test]
    fn test_engine_handle_request_enqueues() {
        let engine = make_engine();
        let id = engine
            .open_session(local_addr(5000), local_addr(80))
            .unwrap();
        engine.handle_request(id, b"test data".to_vec()).unwrap();
        assert_eq!(engine.request_queue().len(), 1);
    }

    #[test]
    fn test_engine_handle_response() {
        let engine = make_engine();
        let id = engine
            .open_session(local_addr(5000), local_addr(80))
            .unwrap();
        engine
            .handle_response(id, b"HTTP/1.1 200 OK\r\n\r\n".to_vec())
            .unwrap();
        assert_eq!(engine.stats().responses_total, 1);
    }

    #[test]
    fn test_engine_bytes_tracked() {
        let engine = make_engine();
        let id = engine
            .open_session(local_addr(5000), local_addr(80))
            .unwrap();
        engine.handle_request(id, vec![0u8; 100]).unwrap();
        engine.handle_response(id, vec![0u8; 200]).unwrap();
        let stats = engine.stats();
        assert_eq!(stats.bytes_up, 100);
        assert_eq!(stats.bytes_down, 200);
    }

    #[test]
    fn test_engine_with_blocklist() {
        let engine = make_engine();
        engine.add_interceptor(BlocklistInterceptor::new(vec!["blocked".into()]));
        let id = engine
            .open_session(local_addr(5000), local_addr(80))
            .unwrap();
        let action = engine
            .handle_request(id, b"GET /blocked HTTP/1.1\r\n\r\n".to_vec())
            .unwrap();
        assert_eq!(action, InterceptAction::Drop);
        assert_eq!(engine.stats().requests_dropped, 1);
    }

    #[test]
    fn test_engine_report_summary() {
        let engine = make_engine();
        let report = engine.report();
        assert!(!report.summary.is_empty());
    }

    #[test]
    fn test_engine_interceptor_count() {
        let engine = make_engine();
        engine.add_interceptor(LoggingInterceptor::new());
        engine.add_interceptor(LoggingInterceptor::new());
        assert_eq!(engine.interceptor_count(), 2);
    }

    #[test]
    fn test_engine_session_not_found_request() {
        let engine = make_engine();
        assert!(matches!(
            engine.handle_request(9999, b"data".to_vec()),
            Err(MitmError::SessionNotFound(9999))
        ));
    }

    #[test]
    fn test_mitm_stats_total_bytes() {
        let stats = MitmStats {
            bytes_up: 100,
            bytes_down: 200,
            ..MitmStats::default()
        };
        assert_eq!(stats.total_bytes(), 300);
    }

    #[test]
    fn test_mitm_stats_drop_rate_zero() {
        let stats = MitmStats::default();
        assert_eq!(stats.drop_rate_requests(), 0.0);
    }

    #[test]
    fn test_mitm_config_validate_ok() {
        assert!(MitmConfig::default().validate().is_ok());
    }

    #[test]
    fn test_mitm_config_validate_zero_sessions() {
        let cfg = MitmConfig {
            max_sessions: 0,
            ..MitmConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_logging_interceptor_records_entries() {
        let logger = LoggingInterceptor::new();
        let rec = SessionRecord::new(1, local_addr(1), local_addr(80));
        logger.on_request(&rec, b"GET / HTTP/1.1\r\n\r\n").unwrap();
        logger
            .on_response(&rec, b"HTTP/1.1 200 OK\r\n\r\n")
            .unwrap();
        assert_eq!(logger.entries().len(), 2);
    }

    #[test]
    fn test_blocklist_no_block() {
        let bl = BlocklistInterceptor::new(vec!["bad.com".into()]);
        let rec = SessionRecord::new(1, local_addr(1), local_addr(80));
        let action = bl
            .on_request(&rec, b"GET / HTTP/1.1\r\nHost: good.com\r\n\r\n")
            .unwrap();
        assert_eq!(action, InterceptAction::Forward);
    }

    #[test]
    fn test_session_state_transitions() {
        let tracker = SessionTracker::new(10);
        let id = tracker
            .create_session(local_addr(2000), local_addr(443))
            .unwrap();
        tracker
            .update(id, |r| r.state = SessionState::Active)
            .unwrap();
        assert_eq!(tracker.get(id).unwrap().state, SessionState::Active);
        tracker
            .update(id, |r| r.state = SessionState::Draining)
            .unwrap();
        assert_eq!(tracker.get(id).unwrap().state, SessionState::Draining);
    }

    #[test]
    fn test_engine_config_access() {
        let engine = make_engine();
        assert_eq!(engine.config().max_sessions, 100);
    }

    #[test]
    fn test_mitm_report_fields() {
        let stats = MitmStats {
            sessions_total: 5,
            sessions_active: 2,
            bytes_up: 1024,
            bytes_down: 2048,
            ..Default::default()
        };
        let report = MitmReport::new(stats, vec![]);
        assert_eq!(report.stats.sessions_total, 5);
        assert!(report.summary.contains("5 total"));
    }
}
