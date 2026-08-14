//! MCP client implementation: connections, tool invocation, resource reading,
//! prompt management, sampling, reconnect strategy.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum McpClientError {
    #[error("connection error: {0}")]
    Connection(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("tool not found: {0}")]
    ToolNotFound(String),
    #[error("resource not found: {0}")]
    ResourceNotFound(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("timeout after {0}ms")]
    Timeout(u64),
    #[error("reconnect limit reached: {0} attempts")]
    ReconnectLimitReached(u32),
}

// ─── ConnectionState ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disconnected => write!(f, "disconnected"),
            Self::Connecting => write!(f, "connecting"),
            Self::Connected => write!(f, "connected"),
            Self::Reconnecting => write!(f, "reconnecting"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

// ─── ConnectionKind ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionKind {
    WebSocket { url: String },
    Stdio,
    InProcess,
}

impl fmt::Display for ConnectionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WebSocket { url } => write!(f, "websocket:{url}"),
            Self::Stdio => write!(f, "stdio"),
            Self::InProcess => write!(f, "in-process"),
        }
    }
}

// ─── ReconnectStrategy ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconnectStrategy {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_factor: f64,
    pub jitter: bool,
}

impl ReconnectStrategy {
    #[must_use]
    pub fn exponential(max_attempts: u32) -> Self {
        Self {
            max_attempts,
            initial_delay_ms: 100,
            max_delay_ms: 30_000,
            backoff_factor: 2.0,
            jitter: true,
        }
    }

    #[must_use]
    pub fn no_reconnect() -> Self {
        Self {
            max_attempts: 0,
            initial_delay_ms: 0,
            max_delay_ms: 0,
            backoff_factor: 1.0,
            jitter: false,
        }
    }

    /// Compute the delay for attempt number `n` (0-based).
    #[must_use]
    pub fn delay_for_attempt(&self, n: u32) -> Duration {
        let base = self.initial_delay_ms as f64 * self.backoff_factor.powi(n as i32);
        let capped = base.min(self.max_delay_ms as f64);
        Duration::from_millis(capped as u64)
    }
}

impl Default for ReconnectStrategy {
    fn default() -> Self {
        Self::exponential(5)
    }
}

// ─── ClientCapabilities ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientCapabilities {
    pub tools: bool,
    pub resources: bool,
    pub prompts: bool,
    pub sampling: bool,
    pub experimental: HashMap<String, Value>,
}

impl ClientCapabilities {
    #[must_use]
    pub fn full() -> Self {
        Self {
            tools: true,
            resources: true,
            prompts: true,
            sampling: true,
            experimental: HashMap::new(),
        }
    }
}

// ─── ServerInfo ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub protocol_version: String,
    pub capabilities: HashMap<String, Value>,
}

// ─── ToolInvocation ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocation {
    pub tool_name: String,
    pub params: Value,
    pub timeout_ms: Option<u64>,
    pub trace_id: Option<String>,
}

impl ToolInvocation {
    #[must_use]
    pub fn new(tool: impl Into<String>, params: Value) -> Self {
        Self {
            tool_name: tool.into(),
            params,
            timeout_ms: None,
            trace_id: None,
        }
    }

    #[must_use]
    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = Some(ms);
        self
    }
}

// ─── ToolResult ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub content: Vec<ToolContent>,
    pub is_error: bool,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolContent {
    pub content_type: String,
    pub text: Option<String>,
    pub data: Option<String>,
    pub mime_type: Option<String>,
}

impl ToolContent {
    #[must_use]
    pub fn text(t: impl Into<String>) -> Self {
        Self {
            content_type: "text".into(),
            text: Some(t.into()),
            data: None,
            mime_type: None,
        }
    }
}

// ─── ResourceReader ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceReadResult {
    pub uri: String,
    pub content: Vec<ToolContent>,
    pub mime_type: Option<String>,
}

// ─── PromptManager ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptTemplate {
    pub name: String,
    pub description: String,
    pub arguments: Vec<PromptArgument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptArgument {
    pub name: String,
    pub description: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptResult {
    pub messages: Vec<PromptMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptMessage {
    pub role: String,
    pub content: String,
}

// ─── SamplingRequest ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingRequest {
    pub messages: Vec<SamplingMessage>,
    pub max_tokens: u32,
    pub temperature: Option<f32>,
    pub stop_sequences: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingResult {
    pub content: String,
    pub model: String,
    pub stop_reason: String,
    pub tokens_used: u32,
}

// ─── McpConnection ────────────────────────────────────────────────────────────

/// Represents a logical connection to an MCP server.
#[derive(Debug, Clone)]
pub struct McpConnection {
    pub kind: ConnectionKind,
    pub state: ConnectionState,
    pub server_info: Option<ServerInfo>,
    pub reconnect: ReconnectStrategy,
    pub connect_attempts: u32,
    pub connected_at: Option<Instant>,
}

impl McpConnection {
    #[must_use]
    pub fn websocket(url: impl Into<String>) -> Self {
        Self {
            kind: ConnectionKind::WebSocket { url: url.into() },
            state: ConnectionState::Disconnected,
            server_info: None,
            reconnect: ReconnectStrategy::default(),
            connect_attempts: 0,
            connected_at: None,
        }
    }

    #[must_use]
    pub fn stdio() -> Self {
        Self {
            kind: ConnectionKind::Stdio,
            state: ConnectionState::Disconnected,
            server_info: None,
            reconnect: ReconnectStrategy::no_reconnect(),
            connect_attempts: 0,
            connected_at: None,
        }
    }

    /// Simulate connecting (synchronous mock).
    pub fn connect(&mut self) -> Result<(), McpClientError> {
        self.state = ConnectionState::Connecting;
        self.connect_attempts += 1;
        // Mock: always succeeds
        self.state = ConnectionState::Connected;
        self.connected_at = Some(Instant::now());
        self.server_info = Some(ServerInfo {
            name: "MockMcpServer".into(),
            version: "1.0.0".into(),
            protocol_version: "2024-11-05".into(),
            capabilities: HashMap::new(),
        });
        Ok(())
    }

    /// Disconnect.
    pub fn disconnect(&mut self) {
        self.state = ConnectionState::Disconnected;
        self.connected_at = None;
    }

    /// Returns `true` when connected.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    /// Uptime since connection was established.
    #[must_use]
    pub fn uptime(&self) -> Option<Duration> {
        self.connected_at.map(|t| t.elapsed())
    }
}

// ─── ToolInvoker ─────────────────────────────────────────────────────────────

/// Invokes tools on a connected MCP server.
pub struct ToolInvoker {
    conn: McpConnection,
}

impl ToolInvoker {
    #[must_use]
    pub fn new(conn: McpConnection) -> Self {
        Self { conn }
    }

    /// Invoke a tool and return a mock result.
    pub fn invoke(&self, inv: ToolInvocation) -> Result<ToolResult, McpClientError> {
        if !self.conn.is_connected() {
            return Err(McpClientError::Connection("not connected".into()));
        }
        Ok(ToolResult {
            content: vec![ToolContent::text(format!(
                "result for tool '{}'",
                inv.tool_name
            ))],
            is_error: false,
            elapsed_ms: 5,
        })
    }

    /// Return the connection state.
    #[must_use]
    pub fn state(&self) -> ConnectionState {
        self.conn.state
    }
}

// ─── McpClient ────────────────────────────────────────────────────────────────

/// Full MCP client with connection management, tool invocation, resource reading,
/// prompt management, and sampling.
pub struct McpClient {
    pub connection: McpConnection,
    pub capabilities: ClientCapabilities,
    pub tool_cache: HashMap<String, Value>,
    pub prompt_cache: HashMap<String, PromptTemplate>,
}

impl McpClient {
    #[must_use]
    pub fn new(kind: ConnectionKind, caps: ClientCapabilities) -> Self {
        let conn = match &kind {
            ConnectionKind::WebSocket { url } => McpConnection::websocket(url.clone()),
            ConnectionKind::Stdio => McpConnection::stdio(),
            ConnectionKind::InProcess => McpConnection::stdio(),
        };
        Self {
            connection: conn,
            capabilities: caps,
            tool_cache: HashMap::new(),
            prompt_cache: HashMap::new(),
        }
    }

    /// Connect to the server.
    pub fn connect(&mut self) -> Result<(), McpClientError> {
        self.connection.connect()
    }

    /// Disconnect.
    pub fn disconnect(&mut self) {
        self.connection.disconnect();
    }

    /// Invoke a tool by name with JSON params.
    pub fn invoke_tool(&self, name: &str, params: Value) -> Result<ToolResult, McpClientError> {
        if !self.connection.is_connected() {
            return Err(McpClientError::Connection("not connected".into()));
        }
        let inv = ToolInvocation::new(name, params);
        Ok(ToolResult {
            content: vec![ToolContent::text(format!(
                "mock result for {} ({})",
                inv.tool_name, name
            ))],
            is_error: false,
            elapsed_ms: 3,
        })
        // In a real impl: serialize to JSON-RPC, send over connection, await response
    }

    /// Read a resource by URI.
    pub fn read_resource(&self, uri: &str) -> Result<ResourceReadResult, McpClientError> {
        if !self.connection.is_connected() {
            return Err(McpClientError::Connection("not connected".into()));
        }
        Ok(ResourceReadResult {
            uri: uri.to_string(),
            content: vec![ToolContent::text(format!("content of {uri}"))],
            mime_type: Some("text/plain".into()),
        })
    }

    /// Get a prompt template by name.
    pub fn get_prompt(
        &self,
        name: &str,
        args: HashMap<String, String>,
    ) -> Result<PromptResult, McpClientError> {
        Ok(PromptResult {
            messages: vec![PromptMessage {
                role: "user".into(),
                content: format!("prompt '{name}' with {} args", args.len()),
            }],
        })
    }

    /// Send a sampling request.
    pub fn sample(&self, req: SamplingRequest) -> Result<SamplingResult, McpClientError> {
        if !self.capabilities.sampling {
            return Err(McpClientError::Protocol("sampling not enabled".into()));
        }
        Ok(SamplingResult {
            content: format!("sampled {} messages", req.messages.len()),
            model: "mock-model".into(),
            stop_reason: "end_turn".into(),
            tokens_used: req.max_tokens / 2,
        })
    }

    /// List available tools (cached from server capabilities).
    #[must_use]
    pub fn list_tools(&self) -> Vec<String> {
        self.tool_cache.keys().cloned().collect()
    }

    /// Returns `true` when connected.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connection.is_connected()
    }

    /// Server info, if available.
    #[must_use]
    pub fn server_info(&self) -> Option<&ServerInfo> {
        self.connection.server_info.as_ref()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ConnectionState ───────────────────────────────────────────────────────

    #[test]
    fn test_connection_state_display() {
        assert_eq!(ConnectionState::Connected.to_string(), "connected");
        assert_eq!(ConnectionState::Reconnecting.to_string(), "reconnecting");
    }

    // ── ReconnectStrategy ─────────────────────────────────────────────────────

    #[test]
    fn test_reconnect_strategy_delay_for_attempt() {
        let s = ReconnectStrategy::exponential(5);
        let d0 = s.delay_for_attempt(0);
        let d1 = s.delay_for_attempt(1);
        assert!(d1 > d0);
    }

    #[test]
    fn test_reconnect_strategy_no_reconnect() {
        let s = ReconnectStrategy::no_reconnect();
        assert_eq!(s.max_attempts, 0);
    }

    #[test]
    fn test_reconnect_strategy_cap_at_max() {
        let s = ReconnectStrategy {
            max_delay_ms: 1000,
            ..ReconnectStrategy::exponential(10)
        };
        let d_large = s.delay_for_attempt(20);
        assert!(d_large.as_millis() <= 1000);
    }

    // ── McpConnection ─────────────────────────────────────────────────────────

    #[test]
    fn test_connection_websocket_initially_disconnected() {
        let c = McpConnection::websocket("ws://localhost:3000");
        assert_eq!(c.state, ConnectionState::Disconnected);
    }

    #[test]
    fn test_connection_connect_succeeds() {
        let mut c = McpConnection::websocket("ws://localhost:3000");
        c.connect().unwrap();
        assert!(c.is_connected());
    }

    #[test]
    fn test_connection_disconnect() {
        let mut c = McpConnection::websocket("ws://localhost");
        c.connect().unwrap();
        c.disconnect();
        assert!(!c.is_connected());
    }

    #[test]
    fn test_connection_server_info_after_connect() {
        let mut c = McpConnection::websocket("ws://localhost");
        c.connect().unwrap();
        assert!(c.server_info.is_some());
        assert_eq!(c.server_info.as_ref().unwrap().name, "MockMcpServer");
    }

    #[test]
    fn test_connection_uptime_none_before_connect() {
        let c = McpConnection::websocket("ws://localhost");
        assert!(c.uptime().is_none());
    }

    #[test]
    fn test_connection_uptime_some_after_connect() {
        let mut c = McpConnection::websocket("ws://localhost");
        c.connect().unwrap();
        assert!(c.uptime().is_some());
    }

    // ── ToolInvoker ───────────────────────────────────────────────────────────

    #[test]
    fn test_invoker_returns_error_when_disconnected() {
        let c = McpConnection::websocket("ws://localhost");
        let inv = ToolInvoker::new(c);
        let result = inv.invoke(ToolInvocation::new("foo", serde_json::json!({})));
        assert!(result.is_err());
    }

    #[test]
    fn test_invoker_succeeds_when_connected() {
        let mut c = McpConnection::websocket("ws://localhost");
        c.connect().unwrap();
        let inv = ToolInvoker::new(c);
        let result = inv.invoke(ToolInvocation::new("foo", serde_json::json!({})));
        assert!(result.is_ok());
    }

    // ── McpClient ─────────────────────────────────────────────────────────────

    #[test]
    fn test_client_connect_succeeds() {
        let mut client = McpClient::new(ConnectionKind::Stdio, ClientCapabilities::full());
        client.connect().unwrap();
        assert!(client.is_connected());
    }

    #[test]
    fn test_client_invoke_tool_requires_connection() {
        let client = McpClient::new(ConnectionKind::Stdio, ClientCapabilities::full());
        let result = client.invoke_tool("test", serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn test_client_invoke_tool_connected() {
        let mut client = McpClient::new(ConnectionKind::Stdio, ClientCapabilities::full());
        client.connect().unwrap();
        let result = client.invoke_tool("analyze_binary", serde_json::json!({"path": "/bin/ls"}));
        assert!(result.is_ok());
        assert!(!result.unwrap().is_error);
    }

    #[test]
    fn test_client_read_resource_connected() {
        let mut client = McpClient::new(ConnectionKind::Stdio, ClientCapabilities::full());
        client.connect().unwrap();
        let result = client.read_resource("rustre://binary/1/info");
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_get_prompt() {
        let mut client = McpClient::new(ConnectionKind::Stdio, ClientCapabilities::full());
        client.connect().unwrap();
        let mut args = HashMap::new();
        args.insert("binary_id".into(), "abc".into());
        let result = client.get_prompt("analyze_binary", args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_sample_requires_capability() {
        let mut client = McpClient::new(ConnectionKind::Stdio, ClientCapabilities::default());
        client.connect().unwrap();
        let req = SamplingRequest {
            messages: vec![],
            max_tokens: 100,
            temperature: None,
            stop_sequences: vec![],
        };
        let result = client.sample(req);
        assert!(result.is_err()); // sampling not enabled
    }

    #[test]
    fn test_client_sample_with_capability() {
        let mut client = McpClient::new(ConnectionKind::Stdio, ClientCapabilities::full());
        client.connect().unwrap();
        let req = SamplingRequest {
            messages: vec![SamplingMessage {
                role: "user".into(),
                content: "hello".into(),
            }],
            max_tokens: 100,
            temperature: Some(0.7),
            stop_sequences: vec![],
        };
        let result = client.sample(req);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().model, "mock-model");
    }

    #[test]
    fn test_client_server_info() {
        let mut client = McpClient::new(ConnectionKind::Stdio, ClientCapabilities::full());
        client.connect().unwrap();
        assert!(client.server_info().is_some());
    }

    #[test]
    fn test_client_capabilities_full() {
        let caps = ClientCapabilities::full();
        assert!(caps.tools);
        assert!(caps.resources);
        assert!(caps.sampling);
    }

    #[test]
    fn test_connection_kind_display() {
        assert_eq!(ConnectionKind::Stdio.to_string(), "stdio");
        let ws = ConnectionKind::WebSocket {
            url: "ws://localhost".into(),
        };
        assert!(ws.to_string().contains("ws://localhost"));
    }
    #[test]
    fn test_connection_state_disconnected_display() {
        assert_eq!(ConnectionState::Disconnected.to_string(), "disconnected");
    }
    #[test]
    fn test_connection_state_failed() {
        let c = McpConnection::websocket("ws://localhost");
        assert_ne!(c.state, ConnectionState::Failed);
    }
    #[test]
    fn test_reconnect_strategy_default_max() {
        let s = ReconnectStrategy::default();
        assert_eq!(s.max_attempts, 5);
    }
    #[test]
    fn test_reconnect_strategy_delay_zero_for_no_reconnect() {
        let s = ReconnectStrategy::no_reconnect();
        assert_eq!(s.delay_for_attempt(0).as_millis(), 0);
    }
    #[test]
    fn test_client_caps_default_no_tools() {
        let caps = ClientCapabilities::default();
        assert!(!caps.tools);
    }
    #[test]
    fn test_tool_invocation_new() {
        let inv = ToolInvocation::new("test", serde_json::json!({}));
        assert_eq!(inv.tool_name, "test");
        assert!(inv.timeout_ms.is_none());
    }
    #[test]
    fn test_tool_invocation_with_timeout() {
        let inv = ToolInvocation::new("t", serde_json::json!({})).with_timeout(5000);
        assert_eq!(inv.timeout_ms, Some(5000));
    }
    #[test]
    fn test_tool_content_text() {
        let c = ToolContent::text("hello");
        assert_eq!(c.content_type, "text");
        assert_eq!(c.text.as_deref(), Some("hello"));
    }
    #[test]
    fn test_tool_result_not_error() {
        let mut c = McpConnection::websocket("ws://localhost");
        c.connect().unwrap();
        let inv = ToolInvoker::new(c);
        let r = inv
            .invoke(ToolInvocation::new("test", serde_json::json!({})))
            .unwrap();
        assert!(!r.is_error);
    }
    #[test]
    fn test_client_disconnect_makes_not_connected() {
        let mut c = McpClient::new(ConnectionKind::Stdio, ClientCapabilities::full());
        c.connect().unwrap();
        assert!(c.is_connected());
        c.disconnect();
        assert!(!c.is_connected());
    }
    #[test]
    fn test_resource_read_has_content() {
        let mut c = McpClient::new(ConnectionKind::Stdio, ClientCapabilities::full());
        c.connect().unwrap();
        let r = c.read_resource("rustre://project/current").unwrap();
        assert!(!r.content.is_empty());
    }
    #[test]
    fn test_sampling_result_tokens_used() {
        let mut c = McpClient::new(ConnectionKind::Stdio, ClientCapabilities::full());
        c.connect().unwrap();
        let req = SamplingRequest {
            messages: vec![],
            max_tokens: 200,
            temperature: None,
            stop_sequences: vec![],
        };
        let r = c.sample(req).unwrap();
        assert_eq!(r.tokens_used, 100);
    }
    #[test]
    fn test_invoker_state() {
        let mut conn = McpConnection::websocket("ws://localhost");
        conn.connect().unwrap();
        let inv = ToolInvoker::new(conn);
        assert_eq!(inv.state(), ConnectionState::Connected);
    }
    #[test]
    fn test_server_info_version() {
        let mut c = McpClient::new(ConnectionKind::Stdio, ClientCapabilities::full());
        c.connect().unwrap();
        assert_eq!(c.server_info().unwrap().name, "MockMcpServer");
    }
    #[test]
    fn test_client_list_tools_empty_initially() {
        let c = McpClient::new(ConnectionKind::Stdio, ClientCapabilities::full());
        assert!(c.list_tools().is_empty());
    }
    #[test]
    fn test_connection_attempts_after_connect() {
        let mut c = McpConnection::websocket("ws://localhost");
        c.connect().unwrap();
        assert_eq!(c.connect_attempts, 1);
    }
    #[test]
    fn test_in_process_connection_kind() {
        let k = ConnectionKind::InProcess;
        assert_eq!(k.to_string(), "in-process");
    }
    #[test]
    fn test_reconnect_exponential_base_delay() {
        let s = ReconnectStrategy::exponential(3);
        assert_eq!(s.delay_for_attempt(0).as_millis(), 100);
    }
    #[test]
    fn test_server_info_default() {
        let si = ServerInfo::default();
        assert!(si.name.is_empty());
    }
}
