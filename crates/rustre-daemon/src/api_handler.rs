//! `api_handler` — HTTP/JSON-RPC/WebSocket API handler for the `RustRE` daemon.
//!
//! Provides [`ApiHandler`], [`ApiRequest`], [`ApiResponse`], [`ApiError`],
//! [`JsonRpcHandler`], [`WebSocketHandler`], and [`AuthHandler`].

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
pub use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── ApiError ─────────────────────────────────────────────────────────────────

/// Errors produced by the API subsystem.
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum ApiError {
    #[error("authentication required")]
    Unauthorized,

    #[error("permission denied: {0}")]
    Forbidden(String),

    #[error("resource not found: {0}")]
    NotFound(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("internal server error: {0}")]
    Internal(String),

    #[error("method not allowed: {0}")]
    MethodNotAllowed(String),

    #[error("rate limit exceeded")]
    RateLimited,

    #[error("service unavailable")]
    ServiceUnavailable,

    #[error("timeout after {0}ms")]
    Timeout(u64),

    #[error("JSON-RPC error {code}: {message}")]
    JsonRpc { code: i32, message: String },

    #[error("WebSocket error: {0}")]
    WebSocket(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

impl ApiError {
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        match self {
            Self::Unauthorized => 401,
            Self::Forbidden(_) => 403,
            Self::NotFound(_) => 404,
            Self::MethodNotAllowed(_) => 405,
            Self::BadRequest(_) => 400,
            Self::RateLimited => 429,
            Self::ServiceUnavailable => 503,
            Self::Timeout(_) => 504,
            _ => 500,
        }
    }

    #[must_use]
    pub const fn json_rpc_code(&self) -> i32 {
        match self {
            Self::JsonRpc { code, .. } => *code,
            Self::BadRequest(_) => -32600,
            Self::NotFound(_) => -32601,
            Self::Internal(_) => -32603,
            _ => -32000,
        }
    }
}

// ─── ApiRequest ───────────────────────────────────────────────────────────────

/// HTTP method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Options,
    Head,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// An incoming API request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRequest {
    pub method: HttpMethod,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body: Option<serde_json::Value>,
    pub request_id: String,
    pub timestamp_ms: u64,
}

impl ApiRequest {
    #[must_use]
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body: None,
            request_id: gen_id(),
            timestamp_ms: epoch_ms(),
        }
    }

    #[must_use]
    pub fn with_body(mut self, body: serde_json::Value) -> Self {
        self.body = Some(body);
        self
    }

    #[must_use]
    pub fn with_header(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.headers.insert(key.into(), val.into());
        self
    }

    #[must_use]
    pub fn with_query(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.query_params.insert(key.into(), val.into());
        self
    }

    /// Get the `Authorization: Bearer <token>` value, if present.
    #[must_use]
    pub fn bearer_token(&self) -> Option<&str> {
        self.headers
            .get("Authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
    }

    /// Get a required body field.
    pub fn require_field(&self, key: &str) -> Result<&serde_json::Value, ApiError> {
        self.body
            .as_ref()
            .and_then(|b| b.get(key))
            .ok_or_else(|| ApiError::BadRequest(format!("missing field '{key}'")))
    }
}

// ─── ApiResponse ──────────────────────────────────────────────────────────────

/// An outgoing API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse {
    pub status: u16,
    pub body: serde_json::Value,
    pub headers: HashMap<String, String>,
    pub request_id: String,
    pub duration_ms: u64,
}

impl ApiResponse {
    #[must_use]
    pub fn ok(body: serde_json::Value, request_id: impl Into<String>) -> Self {
        Self {
            status: 200,
            body,
            headers: HashMap::from([("Content-Type".to_string(), "application/json".to_string())]),
            request_id: request_id.into(),
            duration_ms: 0,
        }
    }

    #[must_use]
    pub fn error(err: &ApiError, request_id: impl Into<String>) -> Self {
        Self {
            status: err.http_status(),
            body: serde_json::json!({ "error": err.to_string(), "code": err.http_status() }),
            headers: HashMap::from([("Content-Type".to_string(), "application/json".to_string())]),
            request_id: request_id.into(),
            duration_ms: 0,
        }
    }

    #[must_use]
    pub const fn with_duration(mut self, ms: u64) -> Self {
        self.duration_ms = ms;
        self
    }

    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

// ─── JsonRpcRequest / JsonRpcResponse ────────────────────────────────────────

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<serde_json::Value>,
    pub id: serde_json::Value,
}

impl JsonRpcRequest {
    #[must_use]
    pub fn new(method: impl Into<String>, params: Option<serde_json::Value>, id: u64) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params,
            id: serde_json::json!(id),
        }
    }

    /// Get a required param by name.
    pub fn require_param(&self, key: &str) -> Result<&serde_json::Value, ApiError> {
        self.params
            .as_ref()
            .and_then(|p| p.get(key))
            .ok_or_else(|| ApiError::BadRequest(format!("missing param '{key}'")))
    }
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<JsonRpcError>,
    pub id: serde_json::Value,
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    #[must_use]
    pub fn success(result: serde_json::Value, id: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    #[must_use]
    pub fn error(code: i32, message: impl Into<String>, id: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }

    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.error.is_none()
    }
}

// ─── JsonRpcHandler ───────────────────────────────────────────────────────────

/// Callback type for a JSON-RPC method implementation.
pub type JsonRpcMethodFn =
    Arc<dyn Fn(JsonRpcRequest) -> Result<serde_json::Value, ApiError> + Send + Sync>;

/// Dispatches JSON-RPC 2.0 method calls to registered handlers.
pub struct JsonRpcHandler {
    methods: RwLock<HashMap<String, JsonRpcMethodFn>>,
    call_count: Mutex<u64>,
    error_count: Mutex<u64>,
}

impl JsonRpcHandler {
    #[must_use]
    pub fn new() -> Self {
        Self {
            methods: RwLock::new(HashMap::new()),
            call_count: Mutex::new(0),
            error_count: Mutex::new(0),
        }
    }

    /// Register a method handler.
    pub fn register<F>(&self, method: impl Into<String>, handler: F)
    where
        F: Fn(JsonRpcRequest) -> Result<serde_json::Value, ApiError> + Send + Sync + 'static,
    {
        self.methods
            .write()
            .insert(method.into(), Arc::new(handler));
    }

    /// Dispatch a request.
    pub fn handle(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        *self.call_count.lock() += 1;
        let id = req.id.clone();
        let handler = {
            let guard = self.methods.read();
            guard.get(&req.method).cloned()
        };
        match handler {
            None => {
                *self.error_count.lock() += 1;
                JsonRpcResponse::error(-32601, format!("Method not found: {}", req.method), id)
            }
            Some(f) => match f(req) {
                Ok(result) => JsonRpcResponse::success(result, id),
                Err(e) => {
                    *self.error_count.lock() += 1;
                    JsonRpcResponse::error(e.json_rpc_code(), e.to_string(), id)
                }
            },
        }
    }

    #[must_use]
    pub fn registered_methods(&self) -> Vec<String> {
        self.methods.read().keys().cloned().collect()
    }

    #[must_use]
    pub fn call_count(&self) -> u64 {
        *self.call_count.lock()
    }

    #[must_use]
    pub fn error_count(&self) -> u64 {
        *self.error_count.lock()
    }
}

impl Default for JsonRpcHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ─── WebSocketHandler ─────────────────────────────────────────────────────────

/// Status of a WebSocket connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WsConnectionStatus {
    Connected,
    Disconnected,
    Error(String),
}

/// A WebSocket message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessage {
    pub connection_id: String,
    pub payload: serde_json::Value,
    pub message_type: WsMessageType,
    pub timestamp_ms: u64,
}

/// Type of WebSocket message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WsMessageType {
    Text,
    Binary,
    Ping,
    Pong,
    Close,
}

impl WsMessage {
    #[must_use]
    pub fn text(connection_id: impl Into<String>, payload: serde_json::Value) -> Self {
        Self {
            connection_id: connection_id.into(),
            payload,
            message_type: WsMessageType::Text,
            timestamp_ms: epoch_ms(),
        }
    }

    #[must_use]
    pub fn ping(connection_id: impl Into<String>) -> Self {
        Self {
            connection_id: connection_id.into(),
            payload: serde_json::Value::Null,
            message_type: WsMessageType::Ping,
            timestamp_ms: epoch_ms(),
        }
    }
}

/// Manages WebSocket connections and message routing.
pub struct WebSocketHandler {
    connections: RwLock<HashMap<String, WsConnectionStatus>>,
    message_log: Mutex<VecDeque<WsMessage>>,
    max_log_size: usize,
}

impl WebSocketHandler {
    #[must_use]
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            message_log: Mutex::new(VecDeque::with_capacity(1000)),
            max_log_size: 1000,
        }
    }

    /// Register a new connection.
    pub fn connect(&self, id: impl Into<String>) {
        let id = id.into();
        self.connections
            .write()
            .insert(id, WsConnectionStatus::Connected);
    }

    /// Disconnect a connection.
    pub fn disconnect(&self, id: &str) {
        if let Some(status) = self.connections.write().get_mut(id) {
            *status = WsConnectionStatus::Disconnected;
        }
    }

    /// Check connection status.
    #[must_use]
    pub fn status(&self, id: &str) -> Option<WsConnectionStatus> {
        self.connections.read().get(id).cloned()
    }

    /// Handle an incoming message.
    pub fn handle_message(&self, msg: WsMessage) -> Result<Option<WsMessage>, ApiError> {
        let status = self
            .connections
            .read()
            .get(&msg.connection_id)
            .cloned()
            .ok_or_else(|| ApiError::NotFound(msg.connection_id.clone()))?;

        if status != WsConnectionStatus::Connected {
            return Err(ApiError::WebSocket(format!(
                "connection '{}' is not connected",
                msg.connection_id
            )));
        }

        {
            let mut log = self.message_log.lock();
            if log.len() >= self.max_log_size {
                log.pop_front();
            }
            log.push_back(msg.clone());
        }

        let response = match msg.message_type {
            WsMessageType::Ping => Some(WsMessage {
                connection_id: msg.connection_id,
                payload: serde_json::Value::Null,
                message_type: WsMessageType::Pong,
                timestamp_ms: epoch_ms(),
            }),
            _ => None,
        };

        Ok(response)
    }

    #[must_use]
    pub fn active_connection_count(&self) -> usize {
        self.connections
            .read()
            .values()
            .filter(|s| **s == WsConnectionStatus::Connected)
            .count()
    }

    #[must_use]
    pub fn message_count(&self) -> usize {
        self.message_log.lock().len()
    }

    #[must_use]
    pub fn all_connection_ids(&self) -> Vec<String> {
        self.connections.read().keys().cloned().collect()
    }
}

impl Default for WebSocketHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ─── AuthHandler ─────────────────────────────────────────────────────────────

/// Authentication scheme.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthScheme {
    Bearer,
    ApiKey,
    Basic,
    None,
}

/// An authenticated session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub session_id: String,
    pub user_id: String,
    pub roles: Vec<String>,
    pub expires_at: u64,
    pub created_at: u64,
}

impl AuthSession {
    #[must_use]
    pub fn new(user_id: impl Into<String>, roles: Vec<String>, ttl_secs: u64) -> Self {
        let now = epoch_ms();
        Self {
            session_id: gen_id(),
            user_id: user_id.into(),
            roles,
            expires_at: now + ttl_secs * 1000,
            created_at: now,
        }
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        epoch_ms() > self.expires_at
    }

    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// Handles authentication, token validation, and session management.
pub struct AuthHandler {
    sessions: RwLock<HashMap<String, AuthSession>>,
    api_keys: RwLock<HashMap<String, String>>, // key -> user_id
    scheme: AuthScheme,
    session_ttl_secs: u64,
}

impl AuthHandler {
    #[must_use]
    pub fn new(scheme: AuthScheme) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            api_keys: RwLock::new(HashMap::new()),
            scheme,
            session_ttl_secs: 3600,
        }
    }

    /// Register an API key for a user.
    pub fn register_api_key(&self, key: impl Into<String>, user_id: impl Into<String>) {
        self.api_keys.write().insert(key.into(), user_id.into());
    }

    /// Create a session for a user.
    #[must_use]
    pub fn create_session(&self, user_id: impl Into<String>, roles: Vec<String>) -> AuthSession {
        let session = AuthSession::new(user_id, roles, self.session_ttl_secs);
        self.sessions
            .write()
            .insert(session.session_id.clone(), session.clone());
        session
    }

    /// Validate a bearer token / API key and return the session.
    pub fn validate(&self, token: &str) -> Result<AuthSession, ApiError> {
        match self.scheme {
            AuthScheme::None => Ok(AuthSession::new(
                "anonymous",
                vec!["read".to_string()],
                3600,
            )),
            AuthScheme::Bearer => {
                let session = self
                    .sessions
                    .read()
                    .get(token)
                    .cloned()
                    .ok_or(ApiError::Unauthorized)?;
                if session.is_expired() {
                    Err(ApiError::Unauthorized)
                } else {
                    Ok(session)
                }
            }
            AuthScheme::ApiKey => {
                let user_id = self
                    .api_keys
                    .read()
                    .get(token)
                    .cloned()
                    .ok_or(ApiError::Unauthorized)?;
                Ok(self.create_session(user_id, vec!["read".to_string(), "write".to_string()]))
            }
            AuthScheme::Basic => {
                // In a real impl, decode base64 and check credentials
                if token.is_empty() {
                    Err(ApiError::Unauthorized)
                } else {
                    Ok(AuthSession::new(
                        "basic_user",
                        vec!["read".to_string()],
                        3600,
                    ))
                }
            }
        }
    }

    /// Revoke a session.
    pub fn revoke(&self, session_id: &str) -> bool {
        self.sessions.write().remove(session_id).is_some()
    }

    #[must_use]
    pub fn active_session_count(&self) -> usize {
        self.sessions
            .read()
            .values()
            .filter(|s| !s.is_expired())
            .count()
    }
}

// ─── ApiHandler ───────────────────────────────────────────────────────────────

/// Top-level API handler that combines REST, JSON-RPC, WebSocket, and auth.
pub struct ApiHandler {
    pub rpc: Arc<JsonRpcHandler>,
    pub ws: Arc<WebSocketHandler>,
    pub auth: Arc<AuthHandler>,
    routes: RwLock<Vec<ApiRoute>>,
    request_count: Mutex<u64>,
    error_count: Mutex<u64>,
}

/// A registered REST route.
#[derive(Clone)]
pub struct ApiRoute {
    pub method: HttpMethod,
    pub path: String,
    pub description: String,
    handler: Arc<dyn Fn(ApiRequest) -> Result<ApiResponse, ApiError> + Send + Sync>,
}

impl ApiHandler {
    #[must_use]
    pub fn new(auth_scheme: AuthScheme) -> Self {
        let handler = Self {
            rpc: Arc::new(JsonRpcHandler::new()),
            ws: Arc::new(WebSocketHandler::new()),
            auth: Arc::new(AuthHandler::new(auth_scheme)),
            routes: RwLock::new(Vec::new()),
            request_count: Mutex::new(0),
            error_count: Mutex::new(0),
        };
        handler.register_default_rpc_methods();
        handler
    }

    /// Register a REST route.
    pub fn route<F>(
        &self,
        method: HttpMethod,
        path: impl Into<String>,
        description: impl Into<String>,
        handler: F,
    ) where
        F: Fn(ApiRequest) -> Result<ApiResponse, ApiError> + Send + Sync + 'static,
    {
        self.routes.write().push(ApiRoute {
            method,
            path: path.into(),
            description: description.into(),
            handler: Arc::new(handler),
        });
    }

    /// Dispatch a REST request.
    pub fn dispatch(&self, req: ApiRequest) -> ApiResponse {
        *self.request_count.lock() += 1;
        let start = Instant::now();
        let request_id = req.request_id.clone();

        // Authenticate if the route is not public
        if req.path != "/health" && req.path != "/version"
            && let Some(token) = req.bearer_token()
                && let Err(e) = self.auth.validate(token) {
                    *self.error_count.lock() += 1;
                    return ApiResponse::error(&e, &request_id)
                        .with_duration(start.elapsed().as_millis() as u64);
                }

        let route = {
            let guard = self.routes.read();
            guard
                .iter()
                .find(|r| r.method == req.method && r.path == req.path)
                .map(|r| r.handler.clone())
        };

        match route {
            None => {
                *self.error_count.lock() += 1;
                ApiResponse::error(&ApiError::NotFound(req.path.clone()), &request_id)
                    .with_duration(start.elapsed().as_millis() as u64)
            }
            Some(handler) => match handler(req) {
                Ok(mut resp) => {
                    resp.duration_ms = start.elapsed().as_millis() as u64;
                    resp
                }
                Err(e) => {
                    *self.error_count.lock() += 1;
                    ApiResponse::error(&e, &request_id)
                        .with_duration(start.elapsed().as_millis() as u64)
                }
            },
        }
    }

    fn register_default_rpc_methods(&self) {
        let rpc = self.rpc.clone();
        rpc.register("ping", |_req| Ok(serde_json::json!("pong")));
        rpc.register("version", |_req| {
            Ok(serde_json::json!({ "version": "1.0.0", "api": "rustre-daemon" }))
        });
        rpc.register("list_sessions", |_req| {
            Ok(serde_json::json!(Vec::<serde_json::Value>::new()))
        });
    }

    #[must_use]
    pub fn request_count(&self) -> u64 {
        *self.request_count.lock()
    }

    #[must_use]
    pub fn error_count(&self) -> u64 {
        *self.error_count.lock()
    }

    #[must_use]
    pub fn route_count(&self) -> usize {
        self.routes.read().len()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn gen_id() -> String {
    static CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    format!(
        "req-{}",
        CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn handler() -> ApiHandler {
        ApiHandler::new(AuthScheme::None)
    }

    fn _auth_handler() -> ApiHandler {
        ApiHandler::new(AuthScheme::Bearer)
    }

    // ── ApiError ──────────────────────────────────────────────────────────────

    #[test]
    fn test_api_error_http_status() {
        assert_eq!(ApiError::Unauthorized.http_status(), 401);
        assert_eq!(ApiError::NotFound("x".into()).http_status(), 404);
        assert_eq!(ApiError::RateLimited.http_status(), 429);
        assert_eq!(ApiError::Internal("x".into()).http_status(), 500);
    }

    #[test]
    fn test_api_error_json_rpc_code() {
        assert_eq!(ApiError::BadRequest("x".into()).json_rpc_code(), -32600);
        assert_eq!(ApiError::NotFound("x".into()).json_rpc_code(), -32601);
        assert_eq!(ApiError::Internal("x".into()).json_rpc_code(), -32603);
    }

    #[test]
    fn test_api_error_display() {
        assert!(
            ApiError::Unauthorized
                .to_string()
                .contains("authentication")
        );
        assert!(
            ApiError::Forbidden("admin".into())
                .to_string()
                .contains("admin")
        );
        assert!(ApiError::Timeout(5000).to_string().contains("5000"));
    }

    // ── ApiRequest ────────────────────────────────────────────────────────────

    #[test]
    fn test_api_request_new() {
        let req = ApiRequest::new(HttpMethod::Get, "/api/status");
        assert_eq!(req.path, "/api/status");
        assert_eq!(req.method, HttpMethod::Get);
    }

    #[test]
    fn test_api_request_bearer_token() {
        let req =
            ApiRequest::new(HttpMethod::Get, "/").with_header("Authorization", "Bearer my_token");
        assert_eq!(req.bearer_token(), Some("my_token"));
    }

    #[test]
    fn test_api_request_bearer_token_none() {
        let req = ApiRequest::new(HttpMethod::Get, "/");
        assert!(req.bearer_token().is_none());
    }

    #[test]
    fn test_api_request_require_field_ok() {
        let req =
            ApiRequest::new(HttpMethod::Post, "/").with_body(serde_json::json!({"name": "test"}));
        assert!(req.require_field("name").is_ok());
    }

    #[test]
    fn test_api_request_require_field_missing() {
        let req = ApiRequest::new(HttpMethod::Post, "/").with_body(serde_json::json!({}));
        let err = req.require_field("missing").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    // ── ApiResponse ───────────────────────────────────────────────────────────

    #[test]
    fn test_api_response_ok() {
        let r = ApiResponse::ok(serde_json::json!({"ok": true}), "req-1");
        assert!(r.is_ok());
        assert_eq!(r.status, 200);
    }

    #[test]
    fn test_api_response_error() {
        let r = ApiResponse::error(&ApiError::Unauthorized, "req-2");
        assert!(!r.is_ok());
        assert_eq!(r.status, 401);
    }

    #[test]
    fn test_api_response_with_duration() {
        let r = ApiResponse::ok(serde_json::json!({}), "r").with_duration(42);
        assert_eq!(r.duration_ms, 42);
    }

    // ── JsonRpcHandler ────────────────────────────────────────────────────────

    #[test]
    fn test_jsonrpc_dispatch_ok() {
        let h = JsonRpcHandler::new();
        h.register("greet", |_| Ok(serde_json::json!("hello")));
        let req = JsonRpcRequest::new("greet", None, 1);
        let resp = h.handle(req);
        assert!(resp.is_success());
        assert_eq!(resp.result, Some(serde_json::json!("hello")));
    }

    #[test]
    fn test_jsonrpc_dispatch_not_found() {
        let h = JsonRpcHandler::new();
        let req = JsonRpcRequest::new("unknown_method", None, 1);
        let resp = h.handle(req);
        assert!(!resp.is_success());
        assert_eq!(resp.error.as_ref().unwrap().code, -32601);
    }

    #[test]
    fn test_jsonrpc_dispatch_error() {
        let h = JsonRpcHandler::new();
        h.register("fail", |_| Err(ApiError::Internal("oops".into())));
        let req = JsonRpcRequest::new("fail", None, 1);
        let resp = h.handle(req);
        assert!(!resp.is_success());
        assert_eq!(h.error_count(), 1);
    }

    #[test]
    fn test_jsonrpc_registered_methods() {
        let h = JsonRpcHandler::new();
        h.register("method_a", |_| Ok(serde_json::json!(null)));
        assert!(h.registered_methods().contains(&"method_a".to_string()));
    }

    #[test]
    fn test_jsonrpc_call_count() {
        let h = JsonRpcHandler::new();
        h.register("ping", |_| Ok(serde_json::json!("pong")));
        h.handle(JsonRpcRequest::new("ping", None, 1));
        h.handle(JsonRpcRequest::new("ping", None, 2));
        assert_eq!(h.call_count(), 2);
    }

    // ── WebSocketHandler ──────────────────────────────────────────────────────

    #[test]
    fn test_ws_connect_disconnect() {
        let ws = WebSocketHandler::new();
        ws.connect("conn-1");
        assert_eq!(ws.status("conn-1"), Some(WsConnectionStatus::Connected));
        ws.disconnect("conn-1");
        assert_eq!(ws.status("conn-1"), Some(WsConnectionStatus::Disconnected));
    }

    #[test]
    fn test_ws_active_connection_count() {
        let ws = WebSocketHandler::new();
        ws.connect("a");
        ws.connect("b");
        ws.disconnect("a");
        assert_eq!(ws.active_connection_count(), 1);
    }

    #[test]
    fn test_ws_ping_returns_pong() {
        let ws = WebSocketHandler::new();
        ws.connect("c1");
        let msg = WsMessage::ping("c1");
        let resp = ws.handle_message(msg).unwrap();
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().message_type, WsMessageType::Pong);
    }

    #[test]
    fn test_ws_message_count() {
        let ws = WebSocketHandler::new();
        ws.connect("c2");
        let msg = WsMessage::text("c2", serde_json::json!({"data": "x"}));
        ws.handle_message(msg).ok();
        assert_eq!(ws.message_count(), 1);
    }

    #[test]
    fn test_ws_unknown_connection() {
        let ws = WebSocketHandler::new();
        let msg = WsMessage::text("unknown", serde_json::json!({}));
        let err = ws.handle_message(msg).unwrap_err();
        assert!(matches!(err, ApiError::NotFound(_)));
    }

    // ── AuthHandler ───────────────────────────────────────────────────────────

    #[test]
    fn test_auth_none_scheme() {
        let auth = AuthHandler::new(AuthScheme::None);
        let session = auth.validate("any_token").unwrap();
        assert_eq!(session.user_id, "anonymous");
    }

    #[test]
    fn test_auth_api_key_valid() {
        let auth = AuthHandler::new(AuthScheme::ApiKey);
        auth.register_api_key("secret-key", "user1");
        let session = auth.validate("secret-key").unwrap();
        assert_eq!(session.user_id, "user1");
    }

    #[test]
    fn test_auth_api_key_invalid() {
        let auth = AuthHandler::new(AuthScheme::ApiKey);
        let err = auth.validate("bad-key").unwrap_err();
        assert!(matches!(err, ApiError::Unauthorized));
    }

    #[test]
    fn test_auth_bearer_valid() {
        let auth = AuthHandler::new(AuthScheme::Bearer);
        let session = auth.create_session("alice", vec!["admin".to_string()]);
        let validated = auth.validate(&session.session_id).unwrap();
        assert_eq!(validated.user_id, "alice");
    }

    #[test]
    fn test_auth_bearer_invalid() {
        let auth = AuthHandler::new(AuthScheme::Bearer);
        let err = auth.validate("bad_token").unwrap_err();
        assert!(matches!(err, ApiError::Unauthorized));
    }

    #[test]
    fn test_auth_session_roles() {
        let session = AuthSession::new("bob", vec!["admin".to_string(), "write".to_string()], 3600);
        assert!(session.has_role("admin"));
        assert!(!session.has_role("superadmin"));
    }

    #[test]
    fn test_auth_revoke() {
        let auth = AuthHandler::new(AuthScheme::Bearer);
        let session = auth.create_session("user", vec![]);
        assert_eq!(auth.active_session_count(), 1);
        auth.revoke(&session.session_id);
        assert_eq!(auth.active_session_count(), 0);
    }

    // ── ApiHandler ────────────────────────────────────────────────────────────

    #[test]
    fn test_api_handler_dispatch_not_found() {
        let h = handler();
        let req = ApiRequest::new(HttpMethod::Get, "/no/such/route");
        let resp = h.dispatch(req);
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn test_api_handler_dispatch_ok() {
        let h = handler();
        h.route(HttpMethod::Get, "/test", "test route", |req| {
            Ok(ApiResponse::ok(
                serde_json::json!({"path": req.path}),
                &req.request_id,
            ))
        });
        let req = ApiRequest::new(HttpMethod::Get, "/test");
        let resp = h.dispatch(req);
        assert!(resp.is_ok());
        assert_eq!(
            resp.body.get("path").and_then(|v| v.as_str()),
            Some("/test")
        );
    }

    #[test]
    fn test_api_handler_request_count() {
        let h = handler();
        h.route(HttpMethod::Get, "/x", "x", |req| {
            Ok(ApiResponse::ok(serde_json::json!({}), &req.request_id))
        });
        h.dispatch(ApiRequest::new(HttpMethod::Get, "/x"));
        h.dispatch(ApiRequest::new(HttpMethod::Get, "/missing"));
        assert_eq!(h.request_count(), 2);
    }

    #[test]
    fn test_api_handler_default_rpc_ping() {
        let h = handler();
        let req = JsonRpcRequest::new("ping", None, 1);
        let resp = h.rpc.handle(req);
        assert!(resp.is_success());
    }

    #[test]
    fn test_api_handler_route_count() {
        let h = handler();
        assert_eq!(h.route_count(), 0);
        h.route(HttpMethod::Get, "/a", "a", |req| {
            Ok(ApiResponse::ok(serde_json::json!({}), &req.request_id))
        });
        assert_eq!(h.route_count(), 1);
    }

    #[test]
    fn test_http_method_display() {
        assert_eq!(HttpMethod::Get.to_string(), "Get");
        assert_eq!(HttpMethod::Post.to_string(), "Post");
    }
}
