//! MCP session handler: lifecycle management, request routing, and response building.
//!
//! Each client connection is represented by an `McpSession`. The `RequestRouter`
//! dispatches incoming JSON-RPC 2.0 messages to the appropriate subsystem, and
//! `ResponseBuilder` formats the results into spec-compliant response objects.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ─── SessionId ────────────────────────────────────────────────────────────────

/// Unique session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);

impl SessionId {
    /// Allocate a new unique session ID.
    pub fn next() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session-{}", self.0)
    }
}

// ─── SessionState ─────────────────────────────────────────────────────────────

/// Lifecycle state of an MCP session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Connection established, waiting for `initialize`.
    Initializing,
    /// Successfully initialized; ready for tool calls.
    Ready,
    /// Session is shutting down gracefully.
    ShuttingDown,
    /// Session has ended.
    Closed,
    /// Session was aborted due to an error.
    Error,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initializing => write!(f, "Initializing"),
            Self::Ready => write!(f, "Ready"),
            Self::ShuttingDown => write!(f, "ShuttingDown"),
            Self::Closed => write!(f, "Closed"),
            Self::Error => write!(f, "Error"),
        }
    }
}

// ─── ClientInfo ───────────────────────────────────────────────────────────────

/// Metadata about the connected MCP client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
    pub protocol_version: String,
    pub capabilities: HashMap<String, Value>,
}

impl ClientInfo {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            protocol_version: "2024-11-05".into(),
            capabilities: HashMap::new(),
        }
    }
}

// ─── McpSession ───────────────────────────────────────────────────────────────

/// Represents one active client session.
pub struct McpSession {
    pub id: SessionId,
    pub state: SessionState,
    pub client_info: Option<ClientInfo>,
    /// Cumulative request counter for this session.
    pub request_count: u64,
    /// When the session was opened.
    pub opened_at: Instant,
    /// When the last request was handled.
    pub last_active: Instant,
    /// Session-local key/value store (for per-session context).
    pub context: HashMap<String, Value>,
    /// Pending request IDs that have been sent but not yet answered.
    pending_requests: HashMap<Value, String>,
    /// Error messages accumulated during the session.
    errors: Vec<String>,
}

impl McpSession {
    /// Create a new session in the `Initializing` state.
    #[must_use] 
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            id: SessionId::next(),
            state: SessionState::Initializing,
            client_info: None,
            request_count: 0,
            opened_at: now,
            last_active: now,
            context: HashMap::new(),
            pending_requests: HashMap::new(),
            errors: Vec::new(),
        }
    }

    /// Handle the `initialize` message. Transitions to `Ready`.
    pub fn initialize(&mut self, client_info: ClientInfo) -> Result<Value, SessionError> {
        if self.state != SessionState::Initializing {
            return Err(SessionError::InvalidState {
                current: self.state,
                expected: SessionState::Initializing,
            });
        }
        self.client_info = Some(client_info);
        self.state = SessionState::Ready;
        self.last_active = Instant::now();
        Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": { "listChanged": false },
                "resources": { "subscribe": false, "listChanged": false }
            },
            "serverInfo": {
                "name": "rustre-mcp-server",
                "version": env!("CARGO_PKG_VERSION")
            }
        }))
    }

    /// Begin graceful shutdown.
    pub const fn shutdown(&mut self) -> Result<(), SessionError> {
        if matches!(self.state, SessionState::Closed | SessionState::Error) {
            return Err(SessionError::AlreadyClosed(self.id));
        }
        self.state = SessionState::ShuttingDown;
        Ok(())
    }

    /// Close the session completely.
    pub const fn close(&mut self) {
        self.state = SessionState::Closed;
    }

    /// Mark the session as errored.
    pub fn mark_error(&mut self, reason: impl Into<String>) {
        self.errors.push(reason.into());
        self.state = SessionState::Error;
    }

    /// Return true if the session can accept new requests.
    #[must_use] 
    pub fn is_ready(&self) -> bool {
        self.state == SessionState::Ready
    }

    /// Record that a request is in-flight.
    pub fn track_request(&mut self, id: Value, method: impl Into<String>) {
        self.pending_requests.insert(id, method.into());
        self.request_count += 1;
        self.last_active = Instant::now();
    }

    /// Mark a pending request as completed.
    pub fn complete_request(&mut self, id: &Value) -> Option<String> {
        self.pending_requests.remove(id)
    }

    /// Number of pending requests.
    #[must_use] 
    pub fn pending_count(&self) -> usize {
        self.pending_requests.len()
    }

    /// How long the session has been open.
    #[must_use] 
    pub fn age(&self) -> Duration {
        self.opened_at.elapsed()
    }

    /// How long since the last activity.
    #[must_use] 
    pub fn idle_time(&self) -> Duration {
        self.last_active.elapsed()
    }

    /// Store a context value.
    pub fn set_context(&mut self, key: impl Into<String>, value: Value) {
        self.context.insert(key.into(), value);
    }

    /// Retrieve a context value.
    #[must_use] 
    pub fn get_context(&self, key: &str) -> Option<&Value> {
        self.context.get(key)
    }

    /// All error messages.
    #[must_use] 
    pub fn errors(&self) -> &[String] {
        &self.errors
    }
}

impl Default for McpSession {
    fn default() -> Self {
        Self::new()
    }
}

// ─── SessionError ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("session {0} is already closed")]
    AlreadyClosed(SessionId),
    #[error("invalid state: current={current}, expected={expected}")]
    InvalidState {
        current: SessionState,
        expected: SessionState,
    },
    #[error("session {0} not found")]
    NotFound(SessionId),
    #[error("session {0} is not ready (state: {1})")]
    NotReady(SessionId, SessionState),
    #[error("request routing error: {0}")]
    RoutingError(String),
}

// ─── JsonRpcRequest ───────────────────────────────────────────────────────────

/// A parsed JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    /// Parse from a raw JSON value.
    pub fn parse(raw: &Value) -> Result<Self, SessionError> {
        let jsonrpc = raw["jsonrpc"]
            .as_str()
            .ok_or_else(|| SessionError::RoutingError("missing jsonrpc field".into()))?
            .to_string();
        if jsonrpc != "2.0" {
            return Err(SessionError::RoutingError(format!(
                "unsupported jsonrpc version: {jsonrpc}"
            )));
        }
        let method = raw["method"]
            .as_str()
            .ok_or_else(|| SessionError::RoutingError("missing method field".into()))?
            .to_string();
        Ok(Self {
            jsonrpc,
            id: raw.get("id").cloned(),
            method,
            params: raw.get("params").cloned(),
        })
    }

    /// Whether this is a notification (no id).
    #[must_use] 
    pub const fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

// ─── RequestRouter ────────────────────────────────────────────────────────────

/// Dispatches incoming JSON-RPC messages to the correct handler.
pub struct RequestRouter {
    /// Tool dispatcher reference (opaque here; in real use, pass Arc<ToolDispatcher>).
    tool_handler: Arc<dyn Fn(&str, Value) -> Value + Send + Sync>,
    resource_handler: Arc<dyn Fn(&str, Value) -> Value + Send + Sync>,
}

impl RequestRouter {
    /// Create a router with explicit handler closures.
    pub fn new(
        tool_handler: impl Fn(&str, Value) -> Value + Send + Sync + 'static,
        resource_handler: impl Fn(&str, Value) -> Value + Send + Sync + 'static,
    ) -> Self {
        Self {
            tool_handler: Arc::new(tool_handler),
            resource_handler: Arc::new(resource_handler),
        }
    }

    /// Create a router with no-op handlers (useful for testing).
    #[must_use] 
    pub fn noop() -> Self {
        Self::new(
            |method, _params| json!({ "stub": method }),
            |uri, _params| json!({ "uri": uri, "contents": [] }),
        )
    }

    /// Route a parsed request to the appropriate subsystem.
    pub fn route(&self, session: &mut McpSession, req: &JsonRpcRequest) -> Value {
        if !session.is_ready() && req.method != "initialize" {
            return ResponseBuilder::error_response(
                req.id.clone(),
                -32002,
                "session not ready",
            );
        }
        let params = req.params.clone().unwrap_or(json!({}));
        match req.method.as_str() {
            "initialize" => {
                let name = params["clientInfo"]["name"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string();
                let version = params["clientInfo"]["version"]
                    .as_str()
                    .unwrap_or("0.0.0")
                    .to_string();
                let info = ClientInfo::new(name, version);
                match session.initialize(info) {
                    Ok(result) => ResponseBuilder::success_response(req.id.clone(), result),
                    Err(e) => ResponseBuilder::error_response(req.id.clone(), -32603, &e.to_string()),
                }
            }
            "notifications/initialized" => {
                // Notification — no response needed.
                json!(null)
            }
            "tools/list" => {
                let result = (self.tool_handler)("list", params);
                ResponseBuilder::success_response(req.id.clone(), result)
            }
            "tools/call" => {
                let result = (self.tool_handler)("call", params);
                ResponseBuilder::success_response(req.id.clone(), result)
            }
            "resources/list" => {
                let result = (self.resource_handler)("list", params);
                ResponseBuilder::success_response(req.id.clone(), result)
            }
            "resources/read" => {
                let uri = params["uri"].as_str().unwrap_or("").to_string();
                let result = (self.resource_handler)(&uri, params);
                ResponseBuilder::success_response(req.id.clone(), result)
            }
            "ping" => ResponseBuilder::success_response(req.id.clone(), json!({})),
            _ => ResponseBuilder::error_response(
                req.id.clone(),
                -32601,
                &format!("method not found: {}", req.method),
            ),
        }
    }

    /// Process a raw JSON body, parsing the request and routing it.
    pub fn handle_raw(&self, session: &mut McpSession, raw: &Value) -> Value {
        match JsonRpcRequest::parse(raw) {
            Ok(req) => {
                if !req.is_notification() {
                    session.track_request(req.id.clone().unwrap_or(json!(null)), req.method.clone());
                }
                let resp = self.route(session, &req);
                if !req.is_notification() {
                    session.complete_request(&req.id.clone().unwrap_or(json!(null)));
                }
                resp
            }
            Err(e) => ResponseBuilder::error_response(None, -32700, &e.to_string()),
        }
    }
}

// ─── ResponseBuilder ─────────────────────────────────────────────────────────

/// Constructs spec-compliant JSON-RPC 2.0 response objects.
pub struct ResponseBuilder;

impl ResponseBuilder {
    /// Build a successful response.
    #[must_use] 
    pub fn success_response(id: Option<Value>, result: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        })
    }

    /// Build an error response.
    #[must_use] 
    pub fn error_response(id: Option<Value>, code: i64, message: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": message
            }
        })
    }

    /// Build an error response with additional data.
    #[must_use] 
    pub fn error_response_with_data(
        id: Option<Value>,
        code: i64,
        message: &str,
        data: Value,
    ) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": message,
                "data": data
            }
        })
    }

    /// Build a parse error response.
    #[must_use] 
    pub fn parse_error() -> Value {
        Self::error_response(None, -32700, "Parse error")
    }

    /// Build an invalid request response.
    #[must_use] 
    pub fn invalid_request(id: Option<Value>, detail: &str) -> Value {
        Self::error_response(id, -32600, &format!("Invalid Request: {detail}"))
    }

    /// Build a method-not-found response.
    #[must_use] 
    pub fn method_not_found(id: Option<Value>, method: &str) -> Value {
        Self::error_response(id, -32601, &format!("Method not found: {method}"))
    }

    /// Build an invalid-params response.
    #[must_use] 
    pub fn invalid_params(id: Option<Value>, detail: &str) -> Value {
        Self::error_response(id, -32602, &format!("Invalid params: {detail}"))
    }

    /// Build an internal error response.
    #[must_use] 
    pub fn internal_error(id: Option<Value>, detail: &str) -> Value {
        Self::error_response(id, -32603, &format!("Internal error: {detail}"))
    }
}

// ─── SessionManager ───────────────────────────────────────────────────────────

/// Manages multiple concurrent MCP sessions.
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<SessionId, McpSession>>>,
    router: Arc<RequestRouter>,
    /// Maximum idle duration before a session is considered stale.
    pub idle_timeout: Duration,
}

impl SessionManager {
    #[must_use] 
    pub fn new(router: RequestRouter) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            router: Arc::new(router),
            idle_timeout: Duration::from_secs(300),
        }
    }

    /// Open a new session and return its ID.
    #[must_use] 
    pub fn open_session(&self) -> SessionId {
        let session = McpSession::new();
        let id = session.id;
        self.sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(id, session);
        id
    }

    /// Close a session by ID.
    pub fn close_session(&self, id: SessionId) -> Result<(), SessionError> {
        let mut sessions = self.sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let session = sessions.get_mut(&id).ok_or(SessionError::NotFound(id))?;
        session.close();
        sessions.remove(&id);
        Ok(())
    }

    /// Handle a raw request on a specific session.
    pub fn handle(&self, session_id: SessionId, raw: &Value) -> Result<Value, SessionError> {
        let mut sessions = self.sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let session = sessions
            .get_mut(&session_id)
            .ok_or(SessionError::NotFound(session_id))?;
        Ok(self.router.handle_raw(session, raw))
    }

    /// Number of active sessions.
    #[must_use] 
    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
    }

    /// Collect and close all sessions that have been idle beyond the timeout.
    #[must_use] 
    pub fn reap_idle_sessions(&self) -> Vec<SessionId> {
        let mut sessions = self.sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let timeout = self.idle_timeout;
        let stale: Vec<SessionId> = sessions
            .iter()
            .filter(|(_, s)| s.idle_time() > timeout)
            .map(|(id, _)| *id)
            .collect();
        for id in &stale {
            sessions.remove(id);
        }
        stale
    }

    /// Collect IDs and states of all sessions.
    #[must_use] 
    pub fn session_snapshot(&self) -> Vec<(SessionId, SessionState)> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(&id, s)| (id, s.state))
            .collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_unique() {
        let a = SessionId::next();
        let b = SessionId::next();
        assert_ne!(a, b);
    }

    #[test]
    fn test_session_initial_state() {
        let s = McpSession::new();
        assert_eq!(s.state, SessionState::Initializing);
        assert!(s.client_info.is_none());
        assert_eq!(s.request_count, 0);
        assert!(!s.is_ready());
    }

    #[test]
    fn test_session_initialize_transitions_to_ready() {
        let mut s = McpSession::new();
        let info = ClientInfo::new("test-client", "1.0");
        let result = s.initialize(info).unwrap();
        assert_eq!(s.state, SessionState::Ready);
        assert!(s.is_ready());
        assert!(result["serverInfo"].is_object());
    }

    #[test]
    fn test_session_double_initialize_fails() {
        let mut s = McpSession::new();
        s.initialize(ClientInfo::new("c", "1")).unwrap();
        let err = s.initialize(ClientInfo::new("c2", "2"));
        assert!(err.is_err());
    }

    #[test]
    fn test_session_shutdown() {
        let mut s = McpSession::new();
        s.initialize(ClientInfo::new("c", "1")).unwrap();
        s.shutdown().unwrap();
        assert_eq!(s.state, SessionState::ShuttingDown);
    }

    #[test]
    fn test_session_mark_error() {
        let mut s = McpSession::new();
        s.mark_error("something broke");
        assert_eq!(s.state, SessionState::Error);
        assert_eq!(s.errors().len(), 1);
    }

    #[test]
    fn test_session_context_storage() {
        let mut s = McpSession::new();
        s.set_context("binary_path", json!("/tmp/test.bin"));
        assert_eq!(s.get_context("binary_path").unwrap(), "/tmp/test.bin");
        assert!(s.get_context("missing").is_none());
    }

    #[test]
    fn test_session_pending_request_tracking() {
        let mut s = McpSession::new();
        s.state = SessionState::Ready;
        s.track_request(json!(1), "tools/call");
        assert_eq!(s.pending_count(), 1);
        assert_eq!(s.request_count, 1);
        let method = s.complete_request(&json!(1));
        assert_eq!(method.as_deref(), Some("tools/call"));
        assert_eq!(s.pending_count(), 0);
    }

    #[test]
    fn test_jsonrpc_request_parse_valid() {
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        });
        let req = JsonRpcRequest::parse(&raw).unwrap();
        assert_eq!(req.method, "tools/list");
        assert!(!req.is_notification());
    }

    #[test]
    fn test_jsonrpc_request_parse_notification() {
        let raw = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        let req = JsonRpcRequest::parse(&raw).unwrap();
        assert!(req.is_notification());
    }

    #[test]
    fn test_jsonrpc_request_parse_missing_method() {
        let raw = json!({ "jsonrpc": "2.0", "id": 1 });
        assert!(JsonRpcRequest::parse(&raw).is_err());
    }

    #[test]
    fn test_router_initialize() {
        let router = RequestRouter::noop();
        let mut session = McpSession::new();
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": { "name": "test", "version": "1.0" }
            }
        });
        let resp = router.handle_raw(&mut session, &raw);
        assert_eq!(resp["result"]["serverInfo"]["name"], "rustre-mcp-server");
        assert_eq!(session.state, SessionState::Ready);
    }

    #[test]
    fn test_router_ping() {
        let router = RequestRouter::noop();
        let mut session = McpSession::new();
        session.state = SessionState::Ready;
        let raw = json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" });
        let resp = router.handle_raw(&mut session, &raw);
        assert!(resp["result"].is_object());
    }

    #[test]
    fn test_router_method_not_found() {
        let router = RequestRouter::noop();
        let mut session = McpSession::new();
        session.state = SessionState::Ready;
        let raw = json!({ "jsonrpc": "2.0", "id": 3, "method": "nonexistent/method" });
        let resp = router.handle_raw(&mut session, &raw);
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn test_router_not_ready_rejects() {
        let router = RequestRouter::noop();
        let mut session = McpSession::new(); // Initializing state
        let raw = json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/list" });
        let resp = router.handle_raw(&mut session, &raw);
        assert_eq!(resp["error"]["code"], -32002);
    }

    #[test]
    fn test_response_builder_success() {
        let resp = ResponseBuilder::success_response(Some(json!(1)), json!({"result": "ok"}));
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 1);
        assert!(resp["result"].is_object());
    }

    #[test]
    fn test_response_builder_error() {
        let resp = ResponseBuilder::error_response(Some(json!(2)), -32600, "bad request");
        assert_eq!(resp["error"]["code"], -32600);
        assert_eq!(resp["error"]["message"], "bad request");
    }

    #[test]
    fn test_session_manager_open_close() {
        let mgr = SessionManager::new(RequestRouter::noop());
        let id = mgr.open_session();
        assert_eq!(mgr.session_count(), 1);
        mgr.close_session(id).unwrap();
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_session_manager_handle_request() {
        let mgr = SessionManager::new(RequestRouter::noop());
        let id = mgr.open_session();
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": { "name": "c", "version": "1" }
            }
        });
        let resp = mgr.handle(id, &raw).unwrap();
        assert!(resp["result"]["serverInfo"].is_object());
    }

    #[test]
    fn test_session_age_and_idle() {
        let s = McpSession::new();
        assert!(s.age() < Duration::from_secs(1));
        assert!(s.idle_time() < Duration::from_secs(1));
    }
}
