//! MCP JSON-RPC 2.0 protocol handler.
//!
//! Provides [`McpProtocolHandler`], [`JsonRpcRequest`], [`JsonRpcResponse`],
//! and the central [`McpProtocolHandler::dispatch_method`] function that routes
//! an incoming JSON-RPC request to the appropriate handler.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── JSON-RPC 2.0 types ───────────────────────────────────────────────────────

/// JSON-RPC 2.0 request object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Protocol version — must be `"2.0"`.
    pub jsonrpc: String,
    /// Method name to invoke.
    pub method: String,
    /// Optional parameters (object or array).
    pub params: Option<serde_json::Value>,
    /// Request identifier (string, number, or null).
    pub id: serde_json::Value,
}

impl JsonRpcRequest {
    /// Construct a standard 2.0 request.
    #[must_use]
    pub fn new(
        method: impl Into<String>,
        params: Option<serde_json::Value>,
        id: serde_json::Value,
    ) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params,
            id,
        }
    }

    /// Construct a notification (no `id`).
    #[must_use]
    pub fn notification(method: impl Into<String>, params: Option<serde_json::Value>) -> Self {
        Self::new(method, params, serde_json::Value::Null)
    }

    /// Returns `true` if this is a notification (no response expected).
    #[must_use]
    pub fn is_notification(&self) -> bool {
        self.id.is_null()
    }

    /// Return the params as an object, or an empty map if absent.
    #[must_use]
    pub fn params_obj(&self) -> serde_json::Map<String, serde_json::Value> {
        match &self.params {
            Some(serde_json::Value::Object(m)) => m.clone(),
            _ => serde_json::Map::new(),
        }
    }

    /// Validate that the `jsonrpc` field equals `"2.0"`.
    ///
    /// # Errors
    /// Returns [`ProtocolError::InvalidVersion`] when the version is wrong.
    pub fn validate_version(&self) -> Result<(), ProtocolError> {
        if self.jsonrpc != "2.0" {
            return Err(ProtocolError::InvalidVersion(self.jsonrpc.clone()));
        }
        Ok(())
    }
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonRpcError {
    /// Numeric error code.
    pub code: i32,
    /// Short, human-readable message.
    pub message: String,
    /// Optional additional data.
    pub data: Option<serde_json::Value>,
}

impl JsonRpcError {
    /// Construct an error.
    #[must_use]
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Parse error (-32700).
    #[must_use]
    pub fn parse_error() -> Self {
        Self::new(-32700, "Parse error")
    }

    /// Invalid request (-32600).
    #[must_use]
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self::new(-32600, msg)
    }

    /// Method not found (-32601).
    #[must_use]
    pub fn method_not_found(method: &str) -> Self {
        Self::new(-32601, format!("Method not found: {method}"))
    }

    /// Invalid params (-32602).
    #[must_use]
    pub fn invalid_params(detail: impl Into<String>) -> Self {
        Self::new(-32602, detail)
    }

    /// Internal error (-32603).
    #[must_use]
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(-32603, detail)
    }

    /// Application-level error in the range [-32000, -32099].
    #[must_use]
    pub fn application(code: i32, msg: impl Into<String>) -> Self {
        debug_assert!((-32099..=-32000).contains(&code), "application code out of range");
        Self::new(code, msg)
    }
}

impl fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

/// JSON-RPC 2.0 response object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Protocol version — always `"2.0"`.
    pub jsonrpc: String,
    /// Successful result (mutually exclusive with `error`).
    pub result: Option<serde_json::Value>,
    /// Error object (mutually exclusive with `result`).
    pub error: Option<JsonRpcError>,
    /// Correlates to the originating request `id`.
    pub id: serde_json::Value,
}

impl JsonRpcResponse {
    /// Successful response.
    #[must_use]
    pub fn ok(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Error response.
    #[must_use]
    pub fn err(id: serde_json::Value, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }

    /// Returns `true` if this is a successful response.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }

    /// Serialize this response to a JSON string.
    ///
    /// # Errors
    /// Returns [`ProtocolError::Serialization`] if serialization fails.
    pub fn to_json(&self) -> Result<String, ProtocolError> {
        serde_json::to_string(self).map_err(|e| ProtocolError::Serialization(e.to_string()))
    }
}

// ─── Protocol errors ──────────────────────────────────────────────────────────

/// Errors produced by the protocol handler layer.
#[derive(Debug, Error, Clone)]
pub enum ProtocolError {
    #[error("invalid JSON-RPC version: {0}")]
    InvalidVersion(String),

    #[error("parse error: {0}")]
    ParseError(String),

    #[error("method not found: {0}")]
    MethodNotFound(String),

    #[error("invalid params: {0}")]
    InvalidParams(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("handler returned error [{code}]: {message}")]
    HandlerError { code: i32, message: String },

    #[error("timeout after {0:?}")]
    Timeout(Duration),

    #[error("batch too large: {count} > {limit}")]
    BatchTooLarge { count: usize, limit: usize },
}

impl ProtocolError {
    /// Convert this error into a [`JsonRpcError`].
    #[must_use]
    pub fn to_rpc_error(&self) -> JsonRpcError {
        match self {
            Self::InvalidVersion(_) | Self::ParseError(_) => {
                JsonRpcError::new(-32700, self.to_string())
            }
            Self::MethodNotFound(m) => JsonRpcError::method_not_found(m),
            Self::InvalidParams(d) => JsonRpcError::invalid_params(d.clone()),
            Self::Serialization(_) => JsonRpcError::new(-32700, self.to_string()),
            Self::HandlerError { code, message } => JsonRpcError::new(*code, message.clone()),
            _ => JsonRpcError::internal(self.to_string()),
        }
    }
}

// ─── MethodHandler trait ──────────────────────────────────────────────────────

/// A handler for a single JSON-RPC method.
pub trait MethodHandler: Send + Sync {
    /// Method name this handler serves.
    fn method_name(&self) -> &str;

    /// Handle the call and return a JSON value or an error.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if the handler fails.
    fn handle(
        &self,
        params: serde_json::Value,
        ctx: &HandlerContext,
    ) -> Result<serde_json::Value, ProtocolError>;

    /// Human-readable description of this method.
    fn description(&self) -> &str {
        ""
    }

    /// Whether this method may be called as a notification (no response).
    fn supports_notification(&self) -> bool {
        false
    }
}

// ─── HandlerContext ───────────────────────────────────────────────────────────

/// Contextual data passed to every [`MethodHandler::handle`] call.
#[derive(Debug, Clone)]
pub struct HandlerContext {
    /// Remote peer identifier (e.g. IP address, session id).
    pub peer: Option<String>,
    /// Trace / correlation ID.
    pub trace_id: Option<String>,
    /// Arbitrary key/value metadata.
    pub metadata: HashMap<String, String>,
    /// Timestamp when the request arrived (for latency tracking).
    pub received_at: Instant,
}

impl HandlerContext {
    /// Create a plain context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            peer: None,
            trace_id: None,
            metadata: HashMap::new(),
            received_at: Instant::now(),
        }
    }

    /// Attach a peer label.
    #[must_use]
    pub fn with_peer(mut self, peer: impl Into<String>) -> Self {
        self.peer = Some(peer.into());
        self
    }

    /// Attach a trace ID.
    #[must_use]
    pub fn with_trace(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    /// Insert an arbitrary metadata key.
    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// How many milliseconds since the context was created.
    #[must_use]
    pub fn age_ms(&self) -> u64 {
        self.received_at.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
}

impl Default for HandlerContext {
    fn default() -> Self {
        Self::new()
    }
}

// ─── DispatchStats ────────────────────────────────────────────────────────────

/// Per-method invocation statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DispatchStats {
    /// Total calls handled.
    pub calls: u64,
    /// Total successful calls.
    pub successes: u64,
    /// Total failed calls.
    pub failures: u64,
    /// Accumulated execution microseconds.
    pub total_us: u64,
    /// Fastest call in microseconds.
    pub min_us: u64,
    /// Slowest call in microseconds.
    pub max_us: u64,
}

impl DispatchStats {
    /// Record one invocation.
    pub fn record(&mut self, elapsed: Duration, ok: bool) {
        let us = elapsed.as_micros().min(u64::MAX as u128) as u64;
        self.calls += 1;
        self.total_us = self.total_us.saturating_add(us);
        if self.min_us == 0 || us < self.min_us {
            self.min_us = us;
        }
        if us > self.max_us {
            self.max_us = us;
        }
        if ok {
            self.successes += 1;
        } else {
            self.failures += 1;
        }
    }

    /// Average latency in microseconds.
    #[must_use]
    pub fn avg_us(&self) -> u64 {
        if self.calls == 0 { 0 } else { self.total_us / self.calls }
    }

    /// Error rate in [0.0, 1.0].
    #[must_use]
    pub fn error_rate(&self) -> f64 {
        if self.calls == 0 { 0.0 } else { self.failures as f64 / self.calls as f64 }
    }
}

// ─── McpProtocolHandler ───────────────────────────────────────────────────────

/// Central JSON-RPC 2.0 protocol handler for the MCP layer.
///
/// Maintains a registry of [`MethodHandler`] implementations and routes
/// incoming requests to the correct one.  Provides batch dispatch, per-method
/// statistics, optional timeout enforcement, and hook points for pre/post
/// processing.
pub struct McpProtocolHandler {
    handlers: RwLock<HashMap<String, Arc<dyn MethodHandler>>>,
    stats: RwLock<HashMap<String, DispatchStats>>,
    /// Maximum number of requests in a batch.
    pub batch_limit: usize,
    /// Optional global per-call timeout.
    pub timeout: Option<Duration>,
}

impl McpProtocolHandler {
    /// Create an empty handler with the given limits.
    #[must_use]
    pub fn new(batch_limit: usize, timeout: Option<Duration>) -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
            stats: RwLock::new(HashMap::new()),
            batch_limit,
            timeout,
        }
    }

    /// Register a method handler.
    pub fn register(&self, handler: Arc<dyn MethodHandler>) {
        let name = handler.method_name().to_string();
        self.handlers.write().insert(name, handler);
    }

    /// Unregister a method by name.  Returns `true` if it was present.
    pub fn unregister(&self, method: &str) -> bool {
        self.handlers.write().remove(method).is_some()
    }

    /// Return whether a method is registered.
    #[must_use]
    pub fn has_method(&self, method: &str) -> bool {
        self.handlers.read().contains_key(method)
    }

    /// Return names of all registered methods (sorted).
    #[must_use]
    pub fn method_names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.handlers.read().keys().cloned().collect();
        names.sort();
        names
    }

    /// Retrieve a snapshot of per-method statistics.
    #[must_use]
    pub fn all_stats(&self) -> HashMap<String, DispatchStats> {
        self.stats.read().clone()
    }

    /// Retrieve stats for a single method.
    #[must_use]
    pub fn stats_for(&self, method: &str) -> Option<DispatchStats> {
        self.stats.read().get(method).cloned()
    }

    /// Dispatch a single [`JsonRpcRequest`] and produce a [`JsonRpcResponse`].
    ///
    /// This is the main entry point — it validates the request, looks up the
    /// handler, enforces the timeout, records stats, and builds the response.
    pub fn dispatch_method(
        &self,
        request: JsonRpcRequest,
        ctx: &HandlerContext,
    ) -> JsonRpcResponse {
        let id = request.id.clone();
        let method = request.method.clone();

        // Validate protocol version.
        if let Err(e) = request.validate_version() {
            return JsonRpcResponse::err(id, e.to_rpc_error());
        }

        // Look up the handler.
        let handler = match self.handlers.read().get(&method).cloned() {
            Some(h) => h,
            None => {
                return JsonRpcResponse::err(
                    id,
                    ProtocolError::MethodNotFound(method.clone()).to_rpc_error(),
                );
            }
        };

        let params = request.params.unwrap_or(serde_json::Value::Object(Default::default()));

        // Execute the handler with optional timeout enforcement.
        //
        // Note: `MethodHandler::handle` is a synchronous call; we cannot
        // interrupt it mid-execution.  We therefore let it run to completion
        // and report a timeout if it exceeded the deadline.  The handler result
        // is preserved in the timeout branch so that metrics can be updated
        // correctly (the call *did* complete, just too slowly).
        let start = Instant::now();
        let result = if let Some(timeout) = self.timeout {
            let res = handler.handle(params, ctx);
            let elapsed = start.elapsed();
            if elapsed > timeout {
                // The handler finished but exceeded the allowed wall-time.
                // Return a timeout error; the actual handler result is dropped.
                Err(ProtocolError::Timeout(timeout))
            } else {
                res
            }
        } else {
            handler.handle(params, ctx)
        };
        let elapsed = start.elapsed();

        // Record stats.
        let ok = result.is_ok();
        self.stats
            .write()
            .entry(method.clone())
            .or_default()
            .record(elapsed, ok);

        // Build response.
        match result {
            Ok(value) => JsonRpcResponse::ok(id, value),
            Err(e) => JsonRpcResponse::err(id, e.to_rpc_error()),
        }
    }

    /// Dispatch a batch of requests, honouring [`Self::batch_limit`].
    ///
    /// Notifications (null `id`) are processed but produce no entry in the
    /// returned vector.
    ///
    /// # Errors
    /// Returns [`ProtocolError::BatchTooLarge`] if the batch exceeds the limit.
    pub fn dispatch_batch(
        &self,
        requests: Vec<JsonRpcRequest>,
        ctx: &HandlerContext,
    ) -> Result<Vec<JsonRpcResponse>, ProtocolError> {
        let count = requests.len();
        if count > self.batch_limit {
            return Err(ProtocolError::BatchTooLarge {
                count,
                limit: self.batch_limit,
            });
        }

        let mut responses = Vec::new();
        for req in requests {
            let is_notif = req.is_notification();
            let resp = self.dispatch_method(req, ctx);
            if !is_notif {
                responses.push(resp);
            }
        }
        Ok(responses)
    }

    /// Parse a raw JSON string as a request and dispatch it.
    ///
    /// # Errors
    /// Returns [`ProtocolError::ParseError`] if the JSON is malformed.
    pub fn dispatch_raw(
        &self,
        json: &str,
        ctx: &HandlerContext,
    ) -> Result<String, ProtocolError> {
        let request: JsonRpcRequest = serde_json::from_str(json)
            .map_err(|e| ProtocolError::ParseError(e.to_string()))?;
        let response = self.dispatch_method(request, ctx);
        response.to_json()
    }
}

impl fmt::Debug for McpProtocolHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpProtocolHandler")
            .field("method_count", &self.handlers.read().len())
            .field("batch_limit", &self.batch_limit)
            .finish_non_exhaustive()
    }
}

// ─── Built-in handlers ────────────────────────────────────────────────────────

/// Echo handler — returns its params unchanged.
#[derive(Debug, Clone)]
pub struct EchoHandler;

impl MethodHandler for EchoHandler {
    fn method_name(&self) -> &str {
        "echo"
    }
    fn description(&self) -> &str {
        "Returns the supplied params unchanged"
    }
    fn handle(
        &self,
        params: serde_json::Value,
        _ctx: &HandlerContext,
    ) -> Result<serde_json::Value, ProtocolError> {
        Ok(params)
    }
}

/// Ping handler — returns `{"pong": true}`.
#[derive(Debug, Clone)]
pub struct PingHandler;

impl MethodHandler for PingHandler {
    fn method_name(&self) -> &str {
        "ping"
    }
    fn description(&self) -> &str {
        "Responds with pong"
    }
    fn supports_notification(&self) -> bool {
        true
    }
    fn handle(
        &self,
        _params: serde_json::Value,
        _ctx: &HandlerContext,
    ) -> Result<serde_json::Value, ProtocolError> {
        Ok(serde_json::json!({"pong": true}))
    }
}

/// Version handler — returns the server version string.
#[derive(Debug, Clone)]
pub struct VersionHandler {
    version: String,
}

impl VersionHandler {
    /// Create with an explicit version string.
    #[must_use]
    pub fn new(version: impl Into<String>) -> Self {
        Self { version: version.into() }
    }
}

impl MethodHandler for VersionHandler {
    fn method_name(&self) -> &str {
        "version"
    }
    fn description(&self) -> &str {
        "Returns the server version"
    }
    fn handle(
        &self,
        _params: serde_json::Value,
        _ctx: &HandlerContext,
    ) -> Result<serde_json::Value, ProtocolError> {
        Ok(serde_json::json!({"version": self.version}))
    }
}

/// List-methods handler — returns all registered method names.
#[derive(Debug)]
pub struct ListMethodsHandler {
    handler_ref: Arc<McpProtocolHandler>,
}

impl ListMethodsHandler {
    /// Create a handler that introspects `handler`.
    #[must_use]
    pub fn new(handler_ref: Arc<McpProtocolHandler>) -> Self {
        Self { handler_ref }
    }
}

impl MethodHandler for ListMethodsHandler {
    fn method_name(&self) -> &str {
        "rpc.list_methods"
    }
    fn description(&self) -> &str {
        "Returns all registered method names"
    }
    fn handle(
        &self,
        _params: serde_json::Value,
        _ctx: &HandlerContext,
    ) -> Result<serde_json::Value, ProtocolError> {
        let names = self.handler_ref.method_names();
        Ok(serde_json::json!({"methods": names}))
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Parse `raw` as a [`JsonRpcRequest`] or a batch of them.
///
/// Returns `Ok(Vec<…>)` with one or more requests.
///
/// # Errors
/// Returns [`ProtocolError::ParseError`] on malformed JSON.
pub fn parse_request_or_batch(raw: &str) -> Result<Vec<JsonRpcRequest>, ProtocolError> {
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| ProtocolError::ParseError(e.to_string()))?;
    if let serde_json::Value::Array(arr) = v {
        let reqs: Result<Vec<JsonRpcRequest>, _> = arr
            .into_iter()
            .map(serde_json::from_value)
            .collect();
        reqs.map_err(|e| ProtocolError::ParseError(e.to_string()))
    } else {
        let req: JsonRpcRequest =
            serde_json::from_value(v).map_err(|e| ProtocolError::ParseError(e.to_string()))?;
        Ok(vec![req])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_handler() -> McpProtocolHandler {
        McpProtocolHandler::new(100, None)
    }

    #[test]
    fn test_echo_handler_roundtrip() {
        let h = make_handler();
        h.register(Arc::new(EchoHandler));
        let req = JsonRpcRequest::new(
            "echo",
            Some(serde_json::json!({"hello": "world"})),
            serde_json::json!(1),
        );
        let resp = h.dispatch_method(req, &HandlerContext::new());
        assert!(resp.is_ok());
        assert_eq!(resp.result, Some(serde_json::json!({"hello": "world"})));
    }

    #[test]
    fn test_ping_handler() {
        let h = make_handler();
        h.register(Arc::new(PingHandler));
        let req = JsonRpcRequest::new("ping", None, serde_json::json!(2));
        let resp = h.dispatch_method(req, &HandlerContext::new());
        assert!(resp.is_ok());
        assert_eq!(resp.result, Some(serde_json::json!({"pong": true})));
    }

    #[test]
    fn test_method_not_found() {
        let h = make_handler();
        let req = JsonRpcRequest::new("ghost", None, serde_json::json!(3));
        let resp = h.dispatch_method(req, &HandlerContext::new());
        assert!(!resp.is_ok());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[test]
    fn test_invalid_version() {
        let h = make_handler();
        h.register(Arc::new(EchoHandler));
        let mut req = JsonRpcRequest::new("echo", None, serde_json::json!(4));
        req.jsonrpc = "1.0".to_string();
        let resp = h.dispatch_method(req, &HandlerContext::new());
        assert!(!resp.is_ok());
    }

    #[test]
    fn test_batch_dispatch() {
        let h = make_handler();
        h.register(Arc::new(EchoHandler));
        h.register(Arc::new(PingHandler));
        let reqs = vec![
            JsonRpcRequest::new("echo", Some(serde_json::json!({"a": 1})), serde_json::json!(1)),
            JsonRpcRequest::new("ping", None, serde_json::json!(2)),
        ];
        let responses = h.dispatch_batch(reqs, &HandlerContext::new()).unwrap();
        assert_eq!(responses.len(), 2);
        assert!(responses[0].is_ok());
        assert!(responses[1].is_ok());
    }

    #[test]
    fn test_batch_too_large() {
        let h = McpProtocolHandler::new(2, None);
        h.register(Arc::new(EchoHandler));
        let reqs = vec![
            JsonRpcRequest::new("echo", None, serde_json::json!(1)),
            JsonRpcRequest::new("echo", None, serde_json::json!(2)),
            JsonRpcRequest::new("echo", None, serde_json::json!(3)),
        ];
        let err = h.dispatch_batch(reqs, &HandlerContext::new()).unwrap_err();
        assert!(matches!(err, ProtocolError::BatchTooLarge { .. }));
    }

    #[test]
    fn test_stats_recording() {
        let h = make_handler();
        h.register(Arc::new(PingHandler));
        for _ in 0..5 {
            let req = JsonRpcRequest::new("ping", None, serde_json::json!(0));
            h.dispatch_method(req, &HandlerContext::new());
        }
        let s = h.stats_for("ping").unwrap();
        assert_eq!(s.calls, 5);
        assert_eq!(s.successes, 5);
        assert_eq!(s.failures, 0);
    }

    #[test]
    fn test_version_handler() {
        let h = make_handler();
        h.register(Arc::new(VersionHandler::new("1.2.3")));
        let req = JsonRpcRequest::new("version", None, serde_json::json!(1));
        let resp = h.dispatch_method(req, &HandlerContext::new());
        assert!(resp.is_ok());
        let r = resp.result.unwrap();
        assert_eq!(r["version"], "1.2.3");
    }

    #[test]
    fn test_parse_request_or_batch_single() {
        let raw = r#"{"jsonrpc":"2.0","method":"ping","id":1}"#;
        let reqs = parse_request_or_batch(raw).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "ping");
    }

    #[test]
    fn test_parse_request_or_batch_array() {
        let raw = r#"[{"jsonrpc":"2.0","method":"ping","id":1},{"jsonrpc":"2.0","method":"echo","id":2}]"#;
        let reqs = parse_request_or_batch(raw).unwrap();
        assert_eq!(reqs.len(), 2);
    }

    #[test]
    fn test_notification_excluded_from_batch_response() {
        let h = make_handler();
        h.register(Arc::new(PingHandler));
        let notif = JsonRpcRequest::notification("ping", None);
        let normal = JsonRpcRequest::new("ping", None, serde_json::json!(99));
        let responses = h.dispatch_batch(vec![notif, normal], &HandlerContext::new()).unwrap();
        // Only the non-notification should appear
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].id, serde_json::json!(99));
    }

    #[test]
    fn test_handler_context_age() {
        let ctx = HandlerContext::new();
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(ctx.age_ms() >= 5);
    }

    #[test]
    fn test_unregister_method() {
        let h = make_handler();
        h.register(Arc::new(EchoHandler));
        assert!(h.has_method("echo"));
        assert!(h.unregister("echo"));
        assert!(!h.has_method("echo"));
    }
}
