//! `mcp_protocol` — Full JSON-RPC 2.0 / MCP protocol message types.
//!
//! Provides complete serializable types for all MCP wire messages including
//! requests, responses, notifications, errors, batches, and protocol versioning.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Protocol version
// ─────────────────────────────────────────────────────────────────────────────

/// The MCP / JSON-RPC protocol version string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub jsonrpc: String,
    pub mcp: String,
}

impl ProtocolVersion {
    /// The standard JSON-RPC 2.0 version.
    pub const JSONRPC_VERSION: &'static str = "2.0";
    /// Current MCP protocol version.
    pub const MCP_VERSION: &'static str = "2024-11-05";

    /// Return the current protocol version.
    #[must_use]
    pub fn current() -> Self {
        Self {
            jsonrpc: Self::JSONRPC_VERSION.to_string(),
            mcp: Self::MCP_VERSION.to_string(),
        }
    }

    /// Check if the given JSON-RPC version string is valid.
    #[must_use]
    pub fn is_valid_jsonrpc(version: &str) -> bool {
        version == Self::JSONRPC_VERSION
    }

    /// Check if the given MCP version is supported.
    #[must_use]
    pub fn is_supported_mcp(version: &str) -> bool {
        // Support current and previous version.
        matches!(version, "2024-11-05" | "2024-10-07")
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::current()
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "jsonrpc={} mcp={}", self.jsonrpc, self.mcp)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Request ID
// ─────────────────────────────────────────────────────────────────────────────

/// A JSON-RPC request ID (string, number, or null).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    String(String),
    Number(i64),
    Null,
}

impl RequestId {
    /// Create a string ID.
    #[must_use]
    pub fn string(s: impl Into<String>) -> Self {
        Self::String(s.into())
    }

    /// Create a numeric ID.
    #[must_use]
    pub fn number(n: i64) -> Self {
        Self::Number(n)
    }

    /// Create a null ID.
    #[must_use]
    pub fn null() -> Self {
        Self::Null
    }

    /// Return true if this is a null ID.
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => write!(f, "\"{s}\""),
            Self::Number(n) => write!(f, "{n}"),
            Self::Null => write!(f, "null"),
        }
    }
}

impl From<i64> for RequestId {
    fn from(n: i64) -> Self {
        Self::Number(n)
    }
}

impl From<String> for RequestId {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&str> for RequestId {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// McpError codes
// ─────────────────────────────────────────────────────────────────────────────

/// Standard JSON-RPC 2.0 error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    ParseError = -32700,
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParams = -32602,
    InternalError = -32603,
    /// Server-defined errors start at -32000.
    ServerError = -32000,
}

impl ErrorCode {
    /// Return the error code as an integer.
    #[must_use]
    pub const fn code(self) -> i64 {
        self as i64
    }

    /// Return a default message for the error code.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::ParseError => "Parse error",
            Self::InvalidRequest => "Invalid Request",
            Self::MethodNotFound => "Method not found",
            Self::InvalidParams => "Invalid params",
            Self::InternalError => "Internal error",
            Self::ServerError => "Server error",
        }
    }
}

/// An MCP/JSON-RPC error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpErrorObject {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl McpErrorObject {
    /// Create an error object with an integer code.
    #[must_use]
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Create an error from an [`ErrorCode`].
    #[must_use]
    pub fn from_code(code: ErrorCode) -> Self {
        Self::new(code.code(), code.message())
    }

    /// Attach additional data.
    #[must_use]
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    /// Return a parse error.
    #[must_use]
    pub fn parse_error() -> Self {
        Self::from_code(ErrorCode::ParseError)
    }

    /// Return a method-not-found error.
    #[must_use]
    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            ErrorCode::MethodNotFound.code(),
            format!("Method not found: {method}"),
        )
    }

    /// Return an invalid-params error.
    #[must_use]
    pub fn invalid_params(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidParams.code(), detail)
    }
}

impl fmt::Display for McpErrorObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// McpRequest
// ─────────────────────────────────────────────────────────────────────────────

/// A JSON-RPC 2.0 request message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    pub jsonrpc: String,
    pub id: RequestId,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl McpRequest {
    /// Create a new request.
    #[must_use]
    pub fn new(id: impl Into<RequestId>, method: impl Into<String>) -> Self {
        Self {
            jsonrpc: ProtocolVersion::JSONRPC_VERSION.to_string(),
            id: id.into(),
            method: method.into(),
            params: None,
        }
    }

    /// Attach parameters.
    #[must_use]
    pub fn with_params(mut self, params: Value) -> Self {
        self.params = Some(params);
        self
    }

    /// Return true if the jsonrpc field is valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        ProtocolVersion::is_valid_jsonrpc(&self.jsonrpc) && !self.method.is_empty()
    }

    /// Serialize to a JSON string.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Deserialize from a JSON string.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` if parsing fails.
    pub fn from_json(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// McpResponse
// ─────────────────────────────────────────────────────────────────────────────

/// A JSON-RPC 2.0 response message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    pub jsonrpc: String,
    pub id: RequestId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpErrorObject>,
}

impl McpResponse {
    /// Create a successful response.
    #[must_use]
    pub fn success(id: impl Into<RequestId>, result: Value) -> Self {
        Self {
            jsonrpc: ProtocolVersion::JSONRPC_VERSION.to_string(),
            id: id.into(),
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response.
    #[must_use]
    pub fn error_response(id: impl Into<RequestId>, error: McpErrorObject) -> Self {
        Self {
            jsonrpc: ProtocolVersion::JSONRPC_VERSION.to_string(),
            id: id.into(),
            result: None,
            error: Some(error),
        }
    }

    /// Return true if this is a success response.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.result.is_some() && self.error.is_none()
    }

    /// Return true if this is an error response.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }

    /// Serialize to JSON string.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Deserialize from a JSON string.
    pub fn from_json(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// McpNotification
// ─────────────────────────────────────────────────────────────────────────────

/// A JSON-RPC 2.0 notification (no `id`, no reply expected).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl McpNotification {
    /// Create a new notification.
    #[must_use]
    pub fn new(method: impl Into<String>) -> Self {
        Self {
            jsonrpc: ProtocolVersion::JSONRPC_VERSION.to_string(),
            method: method.into(),
            params: None,
        }
    }

    /// Attach parameters.
    #[must_use]
    pub fn with_params(mut self, params: Value) -> Self {
        self.params = Some(params);
        self
    }

    /// Is this a progress notification?
    #[must_use]
    pub fn is_progress(&self) -> bool {
        self.method == "notifications/progress"
    }

    /// Is this a log notification?
    #[must_use]
    pub fn is_log(&self) -> bool {
        self.method == "notifications/message"
    }

    /// Serialize to JSON string.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Common MCP notification types.
pub mod notifications {
    use super::*;

    /// Create a `notifications/initialized` notification.
    #[must_use]
    pub fn initialized() -> McpNotification {
        McpNotification::new("notifications/initialized")
    }

    /// Create a `notifications/progress` notification.
    #[must_use]
    pub fn progress(
        token: impl Into<String>,
        progress: f64,
        total: Option<f64>,
    ) -> McpNotification {
        let params = serde_json::json!({
            "progressToken": token.into(),
            "progress": progress,
            "total": total,
        });
        McpNotification::new("notifications/progress").with_params(params)
    }

    /// Create a `notifications/message` (log) notification.
    #[must_use]
    pub fn log(level: &str, message: &str) -> McpNotification {
        let params = serde_json::json!({ "level": level, "data": message });
        McpNotification::new("notifications/message").with_params(params)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// McpBatch
// ─────────────────────────────────────────────────────────────────────────────

/// A JSON-RPC 2.0 batch request or response.
#[derive(Debug, Clone)]
pub struct McpBatch {
    pub requests: Vec<McpRequest>,
    pub notifications: Vec<McpNotification>,
}

impl McpBatch {
    /// Create a new empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            requests: Vec::new(),
            notifications: Vec::new(),
        }
    }

    /// Add a request to the batch.
    pub fn add_request(&mut self, req: McpRequest) {
        self.requests.push(req);
    }

    /// Add a notification to the batch.
    pub fn add_notification(&mut self, notif: McpNotification) {
        self.notifications.push(notif);
    }

    /// Return the total item count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.requests.len() + self.notifications.len()
    }

    /// Return whether the batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Serialize the batch to a JSON array.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut items: Vec<Value> = Vec::with_capacity(self.requests.len() + self.notifications.len());
        for req in &self.requests {
            items.push(serde_json::to_value(req).unwrap_or(Value::Null));
        }
        for notif in &self.notifications {
            items.push(serde_json::to_value(notif).unwrap_or(Value::Null));
        }
        serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string())
    }
}

impl Default for McpBatch {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// McpMessage — a discriminated union of all message types
// ─────────────────────────────────────────────────────────────────────────────

/// Any MCP protocol message.
#[derive(Debug, Clone)]
pub enum McpMessage {
    Request(McpRequest),
    Response(McpResponse),
    Notification(McpNotification),
    Batch(McpBatch),
}

impl McpMessage {
    /// Return the method name if this is a request or notification.
    #[must_use]
    pub fn method(&self) -> Option<&str> {
        match self {
            Self::Request(r) => Some(&r.method),
            Self::Notification(n) => Some(&n.method),
            _ => None,
        }
    }

    /// Return the request ID if present.
    #[must_use]
    pub fn id(&self) -> Option<&RequestId> {
        match self {
            Self::Request(r) => Some(&r.id),
            Self::Response(r) => Some(&r.id),
            _ => None,
        }
    }

    /// Return true if this is a request.
    #[must_use]
    pub fn is_request(&self) -> bool {
        matches!(self, Self::Request(_))
    }

    /// Return true if this is a response.
    #[must_use]
    pub fn is_response(&self) -> bool {
        matches!(self, Self::Response(_))
    }

    /// Return true if this is a notification.
    #[must_use]
    pub fn is_notification(&self) -> bool {
        matches!(self, Self::Notification(_))
    }

    /// Parse a JSON string into an McpMessage.
    #[must_use]
    pub fn parse(json: &str) -> Option<Self> {
        // Try as request.
        if let Ok(req) = serde_json::from_str::<McpRequest>(json)
            && (!req.id.is_null() || !req.method.is_empty()) {
                return Some(Self::Request(req));
            }
        // Try as response.
        if let Ok(resp) = serde_json::from_str::<McpResponse>(json)
            && (resp.result.is_some() || resp.error.is_some()) {
                return Some(Self::Response(resp));
            }
        // Try as notification.
        if let Ok(notif) = serde_json::from_str::<McpNotification>(json) {
            return Some(Self::Notification(notif));
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Initialize / capabilities
// ─────────────────────────────────────────────────────────────────────────────

/// Client capabilities sent in `initialize`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientCapabilities {
    pub roots: Option<RootsCapability>,
    pub sampling: Option<SamplingCapability>,
    pub experimental: Option<HashMap<String, Value>>,
}

/// Roots capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootsCapability {
    pub list_changed: bool,
}

/// Sampling capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingCapability {}

/// Server capabilities returned in `initialize`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerCapabilities {
    pub tools: Option<ToolsCapability>,
    pub resources: Option<ResourcesCapability>,
    pub prompts: Option<PromptsCapability>,
    pub logging: Option<LoggingCapability>,
    pub experimental: Option<HashMap<String, Value>>,
}

/// Tools capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsCapability {
    pub list_changed: bool,
}

/// Resources capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesCapability {
    pub subscribe: bool,
    pub list_changed: bool,
}

/// Prompts capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptsCapability {
    pub list_changed: bool,
}

/// Logging capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingCapability {}

/// The `initialize` request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    pub client_info: ClientInfo,
}

/// Client identification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

/// The `initialize` response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    pub server_info: ServerInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

/// Server identification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

/// Build the standard `InitializeResult` for the RustRE MCP server.
#[must_use]
pub fn rustre_initialize_result() -> InitializeResult {
    InitializeResult {
        protocol_version: ProtocolVersion::MCP_VERSION.to_string(),
        capabilities: ServerCapabilities {
            tools: Some(ToolsCapability {
                list_changed: false,
            }),
            resources: None,
            prompts: None,
            logging: Some(LoggingCapability {}),
            experimental: None,
        },
        server_info: ServerInfo {
            name: "rustre-mcp".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        instructions: Some("Use the available tools to analyze binaries.".to_string()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// McpProtocol — state machine
// ─────────────────────────────────────────────────────────────────────────────

/// Current state of an MCP session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Uninitialized,
    Initializing,
    Ready,
    Closing,
}

/// MCP protocol handler (state machine).
#[derive(Debug)]
pub struct McpProtocol {
    pub state: SessionState,
    pub client_info: Option<ClientInfo>,
    pub capabilities: ServerCapabilities,
    pub next_id: i64,
    pub pending: HashMap<RequestId, String>,
}

impl McpProtocol {
    /// Create a new protocol handler.
    #[must_use]
    pub fn new(capabilities: ServerCapabilities) -> Self {
        Self {
            state: SessionState::Uninitialized,
            client_info: None,
            capabilities,
            next_id: 1,
            pending: HashMap::new(),
        }
    }

    /// Create a handler with default server capabilities.
    #[must_use]
    pub fn default_server() -> Self {
        Self::new(ServerCapabilities {
            tools: Some(ToolsCapability {
                list_changed: false,
            }),
            logging: Some(LoggingCapability {}),
            ..Default::default()
        })
    }

    /// Generate the next request ID.
    pub fn next_id(&mut self) -> RequestId {
        let id = RequestId::Number(self.next_id);
        self.next_id += 1;
        id
    }

    /// Process an incoming JSON string and return an optional response.
    pub fn handle(&mut self, json: &str) -> Option<McpResponse> {
        let msg = McpMessage::parse(json)?;
        match msg {
            McpMessage::Request(req) => Some(self.handle_request(req)),
            McpMessage::Notification(notif) => {
                self.handle_notification(notif);
                None
            }
            _ => None,
        }
    }

    fn handle_request(&mut self, req: McpRequest) -> McpResponse {
        match req.method.as_str() {
            "initialize" => {
                self.state = SessionState::Initializing;
                if let Some(params) = req.params
                    && let Ok(init_params) = serde_json::from_value::<InitializeParams>(params) {
                        self.client_info = Some(init_params.client_info);
                        self.state = SessionState::Ready;
                    }
                let result = rustre_initialize_result();
                McpResponse::success(req.id, serde_json::to_value(result).unwrap())
            }
            "ping" => McpResponse::success(req.id, Value::Object(serde_json::Map::new())),
            method => McpResponse::error_response(req.id, McpErrorObject::method_not_found(method)),
        }
    }

    fn handle_notification(&mut self, notif: McpNotification) {
        if notif.method == "notifications/initialized" {
            self.state = SessionState::Ready;
        }
    }

    /// Build an error response for the given request ID.
    #[must_use]
    pub fn error_response(
        &self,
        id: RequestId,
        code: ErrorCode,
        message: impl Into<String>,
    ) -> McpResponse {
        McpResponse::error_response(id, McpErrorObject::new(code.code(), message))
    }

    /// Is the session ready to receive tool calls?
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state == SessionState::Ready
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ProtocolVersion ───────────────────────────────────────────────────────

    #[test]
    fn test_protocol_version_current() {
        let v = ProtocolVersion::current();
        assert_eq!(v.jsonrpc, "2.0");
        assert!(!v.mcp.is_empty());
    }

    #[test]
    fn test_protocol_version_is_valid_jsonrpc() {
        assert!(ProtocolVersion::is_valid_jsonrpc("2.0"));
        assert!(!ProtocolVersion::is_valid_jsonrpc("1.0"));
        assert!(!ProtocolVersion::is_valid_jsonrpc(""));
    }

    #[test]
    fn test_protocol_version_is_supported_mcp() {
        assert!(ProtocolVersion::is_supported_mcp("2024-11-05"));
        assert!(ProtocolVersion::is_supported_mcp("2024-10-07"));
        assert!(!ProtocolVersion::is_supported_mcp("2020-01-01"));
    }

    #[test]
    fn test_protocol_version_display() {
        let v = ProtocolVersion::current();
        let s = v.to_string();
        assert!(s.contains("jsonrpc=2.0"));
    }

    // ── RequestId ─────────────────────────────────────────────────────────────

    #[test]
    fn test_request_id_string() {
        let id = RequestId::string("req-1");
        assert!(!id.is_null());
        assert_eq!(id.to_string(), "\"req-1\"");
    }

    #[test]
    fn test_request_id_number() {
        let id = RequestId::number(42);
        assert_eq!(id.to_string(), "42");
    }

    #[test]
    fn test_request_id_null() {
        let id = RequestId::null();
        assert!(id.is_null());
    }

    #[test]
    fn test_request_id_from_i64() {
        let id: RequestId = 99i64.into();
        assert_eq!(id, RequestId::Number(99));
    }

    #[test]
    fn test_request_id_from_string() {
        let id: RequestId = "hello".into();
        assert_eq!(id, RequestId::String("hello".to_string()));
    }

    #[test]
    fn test_request_id_serde_roundtrip() {
        let id = RequestId::number(7);
        let s = serde_json::to_string(&id).unwrap();
        let back: RequestId = serde_json::from_str(&s).unwrap();
        assert_eq!(id, back);
    }

    // ── ErrorCode ─────────────────────────────────────────────────────────────

    #[test]
    fn test_error_code_values() {
        assert_eq!(ErrorCode::ParseError.code(), -32700);
        assert_eq!(ErrorCode::MethodNotFound.code(), -32601);
        assert_eq!(ErrorCode::InvalidParams.code(), -32602);
    }

    #[test]
    fn test_error_code_messages() {
        assert_eq!(ErrorCode::ParseError.message(), "Parse error");
        assert_eq!(ErrorCode::MethodNotFound.message(), "Method not found");
    }

    // ── McpErrorObject ────────────────────────────────────────────────────────

    #[test]
    fn test_error_object_new() {
        let e = McpErrorObject::new(-32700, "Parse error");
        assert_eq!(e.code, -32700);
        assert_eq!(e.message, "Parse error");
        assert!(e.data.is_none());
    }

    #[test]
    fn test_error_object_from_code() {
        let e = McpErrorObject::from_code(ErrorCode::InvalidRequest);
        assert_eq!(e.code, -32600);
    }

    #[test]
    fn test_error_object_with_data() {
        let e = McpErrorObject::new(-32000, "test").with_data(serde_json::json!({"detail": "foo"}));
        assert!(e.data.is_some());
    }

    #[test]
    fn test_error_object_parse_error() {
        let e = McpErrorObject::parse_error();
        assert_eq!(e.code, -32700);
    }

    #[test]
    fn test_error_object_method_not_found() {
        let e = McpErrorObject::method_not_found("tools/call");
        assert!(e.message.contains("tools/call"));
    }

    #[test]
    fn test_error_object_display() {
        let e = McpErrorObject::new(-32700, "oops");
        assert!(e.to_string().contains("-32700"));
    }

    // ── McpRequest ────────────────────────────────────────────────────────────

    #[test]
    fn test_request_new() {
        let req = McpRequest::new(1i64, "tools/list");
        assert_eq!(req.method, "tools/list");
        assert!(req.is_valid());
    }

    #[test]
    fn test_request_with_params() {
        let req = McpRequest::new(1i64, "tools/call")
            .with_params(serde_json::json!({"name": "analyze_function"}));
        assert!(req.params.is_some());
    }

    #[test]
    fn test_request_serde_roundtrip() {
        let req = McpRequest::new("abc", "ping");
        let json = req.to_json();
        let back = McpRequest::from_json(&json).unwrap();
        assert_eq!(back.method, "ping");
    }

    #[test]
    fn test_request_invalid_jsonrpc() {
        let mut req = McpRequest::new(1i64, "test");
        req.jsonrpc = "1.0".to_string();
        assert!(!req.is_valid());
    }

    // ── McpResponse ───────────────────────────────────────────────────────────

    #[test]
    fn test_response_success() {
        let r = McpResponse::success(1i64, serde_json::json!({"ok": true}));
        assert!(r.is_success());
        assert!(!r.is_error());
    }

    #[test]
    fn test_response_error() {
        let r = McpResponse::error_response(1i64, McpErrorObject::parse_error());
        assert!(!r.is_success());
        assert!(r.is_error());
    }

    #[test]
    fn test_response_serde_roundtrip() {
        let r = McpResponse::success("x", serde_json::json!(42));
        let json = r.to_json();
        let back = McpResponse::from_json(&json).unwrap();
        assert!(back.is_success());
    }

    // ── McpNotification ───────────────────────────────────────────────────────

    #[test]
    fn test_notification_new() {
        let n = McpNotification::new("notifications/initialized");
        assert_eq!(n.method, "notifications/initialized");
    }

    #[test]
    fn test_notification_is_progress() {
        let n = McpNotification::new("notifications/progress");
        assert!(n.is_progress());
    }

    #[test]
    fn test_notification_is_log() {
        let n = McpNotification::new("notifications/message");
        assert!(n.is_log());
    }

    #[test]
    fn test_notification_helpers() {
        let p = notifications::progress("tok1", 0.5, Some(1.0));
        assert!(p.is_progress());
        let log = notifications::log("info", "test message");
        assert!(log.is_log());
        let init = notifications::initialized();
        assert!(!init.is_progress());
    }

    #[test]
    fn test_notification_serde() {
        let n = notifications::progress("t", 0.75, None);
        let json = n.to_json();
        assert!(json.contains("notifications/progress"));
    }

    // ── McpBatch ──────────────────────────────────────────────────────────────

    #[test]
    fn test_batch_new_empty() {
        let b = McpBatch::new();
        assert!(b.is_empty());
        assert_eq!(b.len(), 0);
    }

    #[test]
    fn test_batch_add_request() {
        let mut b = McpBatch::new();
        b.add_request(McpRequest::new(1i64, "ping"));
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn test_batch_add_notification() {
        let mut b = McpBatch::new();
        b.add_notification(McpNotification::new("test/event"));
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn test_batch_mixed() {
        let mut b = McpBatch::new();
        b.add_request(McpRequest::new(1i64, "a"));
        b.add_request(McpRequest::new(2i64, "b"));
        b.add_notification(McpNotification::new("c"));
        assert_eq!(b.len(), 3);
        assert!(!b.is_empty());
    }

    #[test]
    fn test_batch_to_json_array() {
        let mut b = McpBatch::new();
        b.add_request(McpRequest::new(1i64, "ping"));
        let json = b.to_json();
        assert!(json.starts_with('['));
    }

    // ── McpMessage ────────────────────────────────────────────────────────────

    #[test]
    fn test_message_is_request() {
        let m = McpMessage::Request(McpRequest::new(1i64, "test"));
        assert!(m.is_request());
        assert!(!m.is_response());
        assert!(!m.is_notification());
    }

    #[test]
    fn test_message_method() {
        let m = McpMessage::Request(McpRequest::new(1i64, "tools/call"));
        assert_eq!(m.method(), Some("tools/call"));
    }

    #[test]
    fn test_message_id() {
        let m = McpMessage::Request(McpRequest::new(42i64, "ping"));
        assert_eq!(m.id(), Some(&RequestId::Number(42)));
    }

    #[test]
    fn test_message_parse_request() {
        let req = McpRequest::new(1i64, "ping");
        let json = req.to_json();
        let parsed = McpMessage::parse(&json);
        assert!(parsed.is_some());
        assert!(parsed.unwrap().is_request());
    }

    // ── McpProtocol ───────────────────────────────────────────────────────────

    #[test]
    fn test_protocol_initial_state() {
        let p = McpProtocol::default_server();
        assert_eq!(p.state, SessionState::Uninitialized);
        assert!(!p.is_ready());
    }

    #[test]
    fn test_protocol_initialize() {
        let mut p = McpProtocol::default_server();
        let req = McpRequest::new(1i64, "initialize").with_params(serde_json::json!({
            "protocolVersion": ProtocolVersion::MCP_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "test_client", "version": "1.0" },
        }));
        let resp = p.handle(&req.to_json());
        assert!(resp.is_some());
        assert!(resp.unwrap().is_success());
        assert!(p.is_ready());
    }

    #[test]
    fn test_protocol_ping() {
        let mut p = McpProtocol::default_server();
        p.state = SessionState::Ready;
        let req = McpRequest::new(2i64, "ping");
        let resp = p.handle(&req.to_json()).unwrap();
        assert!(resp.is_success());
    }

    #[test]
    fn test_protocol_unknown_method() {
        let mut p = McpProtocol::default_server();
        let req = McpRequest::new(3i64, "no_such_method");
        let resp = p.handle(&req.to_json()).unwrap();
        assert!(resp.is_error());
    }

    #[test]
    fn test_protocol_next_id_increments() {
        let mut p = McpProtocol::default_server();
        let id1 = p.next_id();
        let id2 = p.next_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_rustre_initialize_result() {
        let r = rustre_initialize_result();
        assert_eq!(r.protocol_version, ProtocolVersion::MCP_VERSION);
        assert_eq!(r.server_info.name, "rustre-mcp");
        assert!(r.capabilities.tools.is_some());
    }
}
