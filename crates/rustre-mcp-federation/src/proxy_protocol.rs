//! `rustre-mcp-federation::proxy_protocol`
//!
//! MCP proxy protocol types and routing engine.
//!
//! This module implements the message types and routing logic needed to forward
//! JSON-RPC 2.0 tool calls from a client through the federation layer to the
//! correct upstream MCP server.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// McpProxyMessage
// ─────────────────────────────────────────────────────────────────────────────

/// A JSON-RPC 2.0 message wrapper used by the proxy layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpProxyMessage {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// Request ID (may be null for notifications).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    /// Method name (e.g. `"tools/call"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Request parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Response result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Response error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ProxyError>,
}

impl McpProxyMessage {
    /// Create a new request message.
    #[must_use]
    pub fn request(id: impl Into<Value>, method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: Some(id.into()),
            method: Some(method.into()),
            params,
            result: None,
            error: None,
        }
    }

    /// Create a successful response message.
    #[must_use]
    pub fn success(id: impl Into<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: Some(id.into()),
            method: None,
            params: None,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response message.
    #[must_use]
    pub fn error_response(id: impl Into<Value>, error: ProxyError) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: Some(id.into()),
            method: None,
            params: None,
            result: None,
            error: Some(error),
        }
    }

    /// Create a notification (no id, no response expected).
    #[must_use]
    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: None,
            method: Some(method.into()),
            params,
            result: None,
            error: None,
        }
    }

    /// Returns `true` when this is a request (has method + id).
    #[must_use]
    pub const fn is_request(&self) -> bool {
        self.method.is_some() && self.id.is_some()
    }

    /// Returns `true` when this is a response (has result or error, no method).
    #[must_use]
    pub const fn is_response(&self) -> bool {
        self.method.is_none() && (self.result.is_some() || self.error.is_some())
    }

    /// Returns `true` when this is a notification (has method, no id).
    #[must_use]
    pub const fn is_notification(&self) -> bool {
        self.method.is_some() && self.id.is_none()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProxyError
// ─────────────────────────────────────────────────────────────────────────────

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyError {
    /// Error code (standard JSON-RPC codes or MCP-specific).
    pub code: i32,
    /// Human-readable error message.
    pub message: String,
    /// Optional additional error data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl ProxyError {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    pub const SERVER_ERROR: i32 = -32000;
    pub const TIMEOUT_ERROR: i32 = -32001;
    pub const UPSTREAM_ERROR: i32 = -32002;

    #[must_use]
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    #[must_use]
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    #[must_use]
    pub fn method_not_found(name: &str) -> Self {
        Self::new(Self::METHOD_NOT_FOUND, format!("Method not found: {name}"))
    }

    #[must_use]
    pub fn upstream(server: &str, msg: &str) -> Self {
        Self::new(Self::UPSTREAM_ERROR, format!("{server}: {msg}"))
    }

    #[must_use]
    pub fn timeout(server: &str) -> Self {
        Self::new(
            Self::TIMEOUT_ERROR,
            format!("Timeout communicating with {server}"),
        )
    }

    #[must_use]
    pub fn internal(msg: &str) -> Self {
        Self::new(Self::INTERNAL_ERROR, msg)
    }
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProxyRequest / ProxyResponse
// ─────────────────────────────────────────────────────────────────────────────

/// A structured proxy request targeting an upstream server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRequest {
    /// The JSON-RPC request to be forwarded.
    pub message: McpProxyMessage,
    /// Name of the upstream server to forward to.
    pub target_server: String,
    /// Whether to retry on failure.
    pub retry_on_error: bool,
    /// Maximum number of retries.
    pub max_retries: u32,
}

impl ProxyRequest {
    /// Create a new proxy request targeting `server`.
    #[must_use]
    pub fn new(message: McpProxyMessage, server: impl Into<String>) -> Self {
        Self {
            message,
            target_server: server.into(),
            retry_on_error: false,
            max_retries: 0,
        }
    }

    #[must_use]
    pub const fn with_retry(mut self, max: u32) -> Self {
        self.retry_on_error = max > 0;
        self.max_retries = max;
        self
    }
}

/// A response from an upstream server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyResponse {
    /// The upstream server that produced this response.
    pub server: String,
    /// The JSON-RPC response.
    pub message: McpProxyMessage,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u64,
}

impl ProxyResponse {
    #[must_use]
    pub fn new(server: impl Into<String>, message: McpProxyMessage, latency_ms: u64) -> Self {
        Self {
            server: server.into(),
            message,
            latency_ms,
        }
    }

    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.message.error.is_none()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UpstreamServer
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for a single upstream MCP server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpstreamServer {
    /// Unique name for this server.
    pub name: String,
    /// Base URL (e.g. `"http://localhost:18080"`) or empty for stdio.
    pub url: String,
    /// Optional bearer token for authentication.
    pub auth_token: Option<String>,
    /// List of capability names exported by this server.
    pub capabilities: Vec<String>,
    /// Whether this server is currently enabled.
    pub enabled: bool,
    /// Connection timeout in seconds.
    pub timeout_secs: u64,
}

impl UpstreamServer {
    /// Create a minimal upstream server config.
    #[must_use]
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            auth_token: None,
            capabilities: Vec::new(),
            enabled: true,
            timeout_secs: 30,
        }
    }

    #[must_use]
    pub fn with_auth(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    #[must_use]
    pub fn with_capability(mut self, cap: impl Into<String>) -> Self {
        self.capabilities.push(cap.into());
        self
    }

    #[must_use]
    pub const fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Returns `true` when this server advertises `cap`.
    #[must_use]
    pub fn has_capability(&self, cap: &str) -> bool {
        self.capabilities.iter().any(|c| c == cap)
    }

    /// Returns `true` when this server requires authentication.
    #[must_use]
    pub const fn requires_auth(&self) -> bool {
        self.auth_token.is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CapabilityMerger
// ─────────────────────────────────────────────────────────────────────────────

/// Merges tool lists from multiple upstream servers into a single unified
/// tool surface, with server attribution.
pub struct CapabilityMerger {
    /// Merged tool entries: `tool_name → [server_name]`
    pub tool_map: HashMap<String, Vec<String>>,
}

impl CapabilityMerger {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tool_map: HashMap::new(),
        }
    }

    /// Register tools from `server_name`.
    pub fn add_tools(&mut self, server_name: &str, tools: &[String]) {
        for tool in tools {
            self.tool_map
                .entry(tool.clone())
                .or_default()
                .push(server_name.to_string());
        }
    }

    /// Return all unique tool names across all servers.
    #[must_use]
    pub fn all_tools(&self) -> Vec<&str> {
        self.tool_map.keys().map(String::as_str).collect()
    }

    /// Return which servers provide `tool`.
    #[must_use]
    pub fn servers_for_tool(&self, tool: &str) -> Vec<&str> {
        self.tool_map
            .get(tool)
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Returns `true` when the tool exists on at least one server.
    #[must_use]
    pub fn has_tool(&self, tool: &str) -> bool {
        self.tool_map.contains_key(tool)
    }

    /// Number of unique tools across all servers.
    #[must_use]
    pub fn tool_count(&self) -> usize {
        self.tool_map.len()
    }

    /// Find conflicts: tools provided by more than one server.
    #[must_use]
    pub fn conflicts(&self) -> Vec<(&str, Vec<&str>)> {
        self.tool_map
            .iter()
            .filter(|(_, servers)| servers.len() > 1)
            .map(|(t, servers)| (t.as_str(), servers.iter().map(String::as_str).collect()))
            .collect()
    }
}

impl Default for CapabilityMerger {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AuthForwarder
// ─────────────────────────────────────────────────────────────────────────────

/// Manages authentication forwarding from clients to upstream servers.
///
/// Supports bearer tokens and per-server API keys.
pub struct AuthForwarder {
    /// Per-server auth tokens.
    server_tokens: HashMap<String, String>,
    /// Default token applied to all servers that don't have a specific entry.
    default_token: Option<String>,
}

impl AuthForwarder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            server_tokens: HashMap::new(),
            default_token: None,
        }
    }

    /// Set the auth token for a specific server.
    pub fn set_token(&mut self, server: impl Into<String>, token: impl Into<String>) {
        self.server_tokens.insert(server.into(), token.into());
    }

    /// Set a fallback token used when no server-specific token is registered.
    pub fn set_default_token(&mut self, token: impl Into<String>) {
        self.default_token = Some(token.into());
    }

    /// Return the auth token for `server`, or the default token.
    #[must_use]
    pub fn token_for(&self, server: &str) -> Option<&str> {
        self.server_tokens
            .get(server)
            .map(String::as_str)
            .or(self.default_token.as_deref())
    }

    /// Build an HTTP `Authorization: Bearer <token>` header value for `server`.
    #[must_use]
    pub fn bearer_header(&self, server: &str) -> Option<String> {
        self.token_for(server).map(|t| format!("Bearer {t}"))
    }

    /// Returns `true` when authentication is configured for `server`.
    #[must_use]
    pub fn has_auth(&self, server: &str) -> bool {
        self.token_for(server).is_some()
    }

    /// Remove the token for `server`.
    pub fn remove_token(&mut self, server: &str) {
        self.server_tokens.remove(server);
    }
}

impl Default for AuthForwarder {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProxyRouter
// ─────────────────────────────────────────────────────────────────────────────

/// Routes tool calls to the correct upstream server.
///
/// Routing rules (in priority order):
/// 1. Explicit per-tool server assignments.
/// 2. Prefix-based routing (tool name starts with `"<server>."` pattern).
/// 3. Capability-based routing via the [`CapabilityMerger`].
/// 4. Fallback server.
pub struct ProxyRouter {
    /// Upstream servers.
    pub servers: Vec<UpstreamServer>,
    /// Explicit tool → server assignments.
    tool_assignments: HashMap<String, String>,
    /// Capability merger for capability-based routing.
    merger: CapabilityMerger,
    /// Default fallback server name.
    fallback: Option<String>,
}

impl ProxyRouter {
    #[must_use]
    pub fn new(servers: Vec<UpstreamServer>) -> Self {
        Self {
            servers,
            tool_assignments: HashMap::new(),
            merger: CapabilityMerger::new(),
            fallback: None,
        }
    }

    /// Assign `tool` to `server` explicitly.
    pub fn assign(&mut self, tool: impl Into<String>, server: impl Into<String>) {
        self.tool_assignments.insert(tool.into(), server.into());
    }

    /// Set the fallback server name.
    pub fn set_fallback(&mut self, server: impl Into<String>) {
        self.fallback = Some(server.into());
    }

    /// Register tools from a server in the capability merger.
    pub fn register_tools(&mut self, server_name: &str, tools: &[String]) {
        self.merger.add_tools(server_name, tools);
    }

    /// Route `tool_name` to the best upstream server.
    ///
    /// Returns `Some(server_name)` when a route is found, `None` otherwise.
    #[must_use]
    pub fn route(&self, tool_name: &str) -> Option<&str> {
        // 1. Explicit assignment.
        if let Some(s) = self.tool_assignments.get(tool_name)
            && self.server_is_active(s) {
                return Some(s.as_str());
            }
        // 2. Prefix routing: `server_name.tool_name`
        for server in &self.servers {
            if !server.enabled {
                continue;
            }
            let prefix = format!("{}.", server.name);
            if tool_name.starts_with(&prefix) {
                return Some(server.name.as_str());
            }
        }
        // 3. Capability merger.
        let candidates = self.merger.servers_for_tool(tool_name);
        for c in candidates {
            if self.server_is_active(c) {
                return Some(c);
            }
        }
        // 4. Fallback.
        if let Some(ref fb) = self.fallback
            && self.server_is_active(fb) {
                return Some(fb.as_str());
            }
        None
    }

    /// Returns `true` when `server` exists and is enabled.
    #[must_use]
    pub fn server_is_active(&self, server: &str) -> bool {
        self.servers.iter().any(|s| s.name == server && s.enabled)
    }

    /// List active (enabled) servers.
    #[must_use]
    pub fn active_servers(&self) -> Vec<&UpstreamServer> {
        self.servers.iter().filter(|s| s.enabled).collect()
    }

    /// Returns `true` when a route exists for `tool_name`.
    #[must_use]
    pub fn can_route(&self, tool_name: &str) -> bool {
        self.route(tool_name).is_some()
    }

    /// Number of upstream servers (including disabled).
    #[must_use]
    pub const fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// Number of active (enabled) servers.
    #[must_use]
    pub fn active_server_count(&self) -> usize {
        self.active_servers().len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── McpProxyMessage ───────────────────────────────────────────────────────

    #[test]
    fn test_proxy_message_request() {
        let m = McpProxyMessage::request(1, "tools/call", None);
        assert!(m.is_request());
        assert!(!m.is_response());
        assert!(!m.is_notification());
        assert_eq!(m.jsonrpc, "2.0");
    }

    #[test]
    fn test_proxy_message_success() {
        let m = McpProxyMessage::success(1, serde_json::json!({"ok": true}));
        assert!(m.is_response());
        assert!(!m.is_request());
        assert!(m.result.is_some());
        assert!(m.error.is_none());
    }

    #[test]
    fn test_proxy_message_error_response() {
        let err = ProxyError::timeout("server1");
        let m = McpProxyMessage::error_response(1, err);
        assert!(m.is_response());
        assert!(m.error.is_some());
        assert!(m.result.is_none());
    }

    #[test]
    fn test_proxy_message_notification() {
        let m = McpProxyMessage::notification("server/event", None);
        assert!(m.is_notification());
        assert!(m.id.is_none());
        assert!(!m.is_request());
    }

    #[test]
    fn test_proxy_message_serde_roundtrip() {
        let m = McpProxyMessage::request(42, "tools/list", None);
        let json = serde_json::to_string(&m).unwrap();
        let m2: McpProxyMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(m, m2);
    }

    // ── ProxyError ────────────────────────────────────────────────────────────

    #[test]
    fn test_proxy_error_method_not_found() {
        let e = ProxyError::method_not_found("foo");
        assert_eq!(e.code, ProxyError::METHOD_NOT_FOUND);
        assert!(e.message.contains("foo"));
    }

    #[test]
    fn test_proxy_error_upstream() {
        let e = ProxyError::upstream("server1", "connection refused");
        assert_eq!(e.code, ProxyError::UPSTREAM_ERROR);
    }

    #[test]
    fn test_proxy_error_timeout() {
        let e = ProxyError::timeout("server2");
        assert_eq!(e.code, ProxyError::TIMEOUT_ERROR);
        assert!(e.message.contains("server2"));
    }

    #[test]
    fn test_proxy_error_display() {
        let e = ProxyError::internal("oops");
        assert!(e.to_string().contains("-32603"));
        assert!(e.to_string().contains("oops"));
    }

    #[test]
    fn test_proxy_error_with_data() {
        let e = ProxyError::internal("err").with_data(serde_json::json!({"detail": "x"}));
        assert!(e.data.is_some());
    }

    // ── UpstreamServer ────────────────────────────────────────────────────────

    #[test]
    fn test_upstream_server_new() {
        let s = UpstreamServer::new("ghidra", "http://localhost:18080");
        assert_eq!(s.name, "ghidra");
        assert!(s.enabled);
        assert!(!s.requires_auth());
    }

    #[test]
    fn test_upstream_server_with_auth() {
        let s = UpstreamServer::new("s", "u").with_auth("token123");
        assert!(s.requires_auth());
    }

    #[test]
    fn test_upstream_server_with_capability() {
        let s = UpstreamServer::new("s", "u")
            .with_capability("decompile")
            .with_capability("disasm");
        assert!(s.has_capability("decompile"));
        assert!(!s.has_capability("other"));
    }

    #[test]
    fn test_upstream_server_disabled() {
        let s = UpstreamServer::new("s", "u").disabled();
        assert!(!s.enabled);
    }

    // ── CapabilityMerger ──────────────────────────────────────────────────────

    #[test]
    fn test_capability_merger_add_tools() {
        let mut m = CapabilityMerger::new();
        m.add_tools("server1", &["tool_a".into(), "tool_b".into()]);
        m.add_tools("server2", &["tool_b".into(), "tool_c".into()]);
        assert_eq!(m.tool_count(), 3);
        assert!(m.has_tool("tool_a"));
        assert!(m.has_tool("tool_b"));
    }

    #[test]
    fn test_capability_merger_servers_for_tool() {
        let mut m = CapabilityMerger::new();
        m.add_tools("s1", &["foo".into()]);
        m.add_tools("s2", &["foo".into()]);
        let servers = m.servers_for_tool("foo");
        assert_eq!(servers.len(), 2);
    }

    #[test]
    fn test_capability_merger_conflicts() {
        let mut m = CapabilityMerger::new();
        m.add_tools("a", &["shared".into()]);
        m.add_tools("b", &["shared".into()]);
        assert_eq!(m.conflicts().len(), 1);
    }

    #[test]
    fn test_capability_merger_no_tools() {
        let m = CapabilityMerger::new();
        assert_eq!(m.tool_count(), 0);
        assert!(!m.has_tool("anything"));
        assert!(m.all_tools().is_empty());
    }

    // ── AuthForwarder ─────────────────────────────────────────────────────────

    #[test]
    fn test_auth_forwarder_set_and_get() {
        let mut af = AuthForwarder::new();
        af.set_token("server1", "secret123");
        assert_eq!(af.token_for("server1"), Some("secret123"));
        assert!(af.has_auth("server1"));
    }

    #[test]
    fn test_auth_forwarder_fallback() {
        let mut af = AuthForwarder::new();
        af.set_default_token("global-token");
        assert_eq!(af.token_for("any_server"), Some("global-token"));
    }

    #[test]
    fn test_auth_forwarder_specific_overrides_default() {
        let mut af = AuthForwarder::new();
        af.set_default_token("default");
        af.set_token("server1", "specific");
        assert_eq!(af.token_for("server1"), Some("specific"));
        assert_eq!(af.token_for("other"), Some("default"));
    }

    #[test]
    fn test_auth_forwarder_bearer_header() {
        let mut af = AuthForwarder::new();
        af.set_token("s", "tok");
        assert_eq!(af.bearer_header("s"), Some("Bearer tok".into()));
        assert_eq!(af.bearer_header("other"), None);
    }

    #[test]
    fn test_auth_forwarder_remove_token() {
        let mut af = AuthForwarder::new();
        af.set_token("s", "tok");
        af.remove_token("s");
        assert!(!af.has_auth("s"));
    }

    // ── ProxyRouter ───────────────────────────────────────────────────────────

    fn make_servers() -> Vec<UpstreamServer> {
        vec![
            UpstreamServer::new("ghidra", "http://localhost:18080"),
            UpstreamServer::new("frida", "stdio://frida-mcp"),
            UpstreamServer::new("yara", "stdio://yara-mcp").disabled(),
        ]
    }

    #[test]
    fn test_proxy_router_active_servers() {
        let r = ProxyRouter::new(make_servers());
        assert_eq!(r.active_server_count(), 2);
        assert_eq!(r.server_count(), 3);
    }

    #[test]
    fn test_proxy_router_explicit_assignment() {
        let mut r = ProxyRouter::new(make_servers());
        r.assign("decompile", "ghidra");
        assert_eq!(r.route("decompile"), Some("ghidra"));
    }

    #[test]
    fn test_proxy_router_prefix_routing() {
        let r = ProxyRouter::new(make_servers());
        // ghidra.list_functions should route to ghidra
        assert_eq!(r.route("ghidra.list_functions"), Some("ghidra"));
        assert_eq!(r.route("frida.attach"), Some("frida"));
    }

    #[test]
    fn test_proxy_router_capability_routing() {
        let mut r = ProxyRouter::new(make_servers());
        r.register_tools("frida", &["hook_function".into()]);
        assert_eq!(r.route("hook_function"), Some("frida"));
    }

    #[test]
    fn test_proxy_router_fallback() {
        let mut r = ProxyRouter::new(make_servers());
        r.set_fallback("ghidra");
        assert_eq!(r.route("unknown_tool"), Some("ghidra"));
    }

    #[test]
    fn test_proxy_router_no_route() {
        let r = ProxyRouter::new(make_servers());
        assert!(r.route("totally_unknown").is_none());
        assert!(!r.can_route("totally_unknown"));
    }

    #[test]
    fn test_proxy_router_disabled_server_not_routed() {
        let mut r = ProxyRouter::new(make_servers());
        r.assign("yara_scan", "yara"); // yara is disabled
        // Should fall back or return None since yara is disabled
        assert!(r.route("yara_scan").is_none());
    }

    // ── ProxyRequest / ProxyResponse ──────────────────────────────────────────

    #[test]
    fn test_proxy_request_new() {
        let msg = McpProxyMessage::request(1, "tools/call", None);
        let req = ProxyRequest::new(msg, "server1");
        assert_eq!(req.target_server, "server1");
        assert!(!req.retry_on_error);
    }

    #[test]
    fn test_proxy_request_with_retry() {
        let msg = McpProxyMessage::request(1, "tools/call", None);
        let req = ProxyRequest::new(msg, "server1").with_retry(3);
        assert!(req.retry_on_error);
        assert_eq!(req.max_retries, 3);
    }

    #[test]
    fn test_proxy_response_success() {
        let msg = McpProxyMessage::success(1, serde_json::json!({"ok": true}));
        let resp = ProxyResponse::new("server1", msg, 50);
        assert!(resp.is_success());
        assert_eq!(resp.latency_ms, 50);
    }

    #[test]
    fn test_proxy_response_error() {
        let msg = McpProxyMessage::error_response(1, ProxyError::internal("fail"));
        let resp = ProxyResponse::new("server1", msg, 0);
        assert!(!resp.is_success());
    }
}
