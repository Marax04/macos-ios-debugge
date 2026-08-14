//! `mcp_server_impl` — Core MCP server implementation types.
//!
//! Provides [`McpServerImpl`], [`ServerCapabilities`], [`ToolDefinition`],
//! [`ResourceDefinition`], [`PromptDefinition`], [`RequestHandler`],
//! [`ResponseBuilder`], and [`McpSession`].

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
pub use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the MCP server implementation.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("method not found: {0}")]
    MethodNotFound(String),
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("tool not found: {0}")]
    ToolNotFound(String),
    #[error("resource not found: {0}")]
    ResourceNotFound(String),
    #[error("prompt not found: {0}")]
    PromptNotFound(String),
    #[error("session expired: {0}")]
    SessionExpired(String),
    #[error("serialization: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("handler error: {0}")]
    Handler(String),
    #[error("capability not supported: {0}")]
    UnsupportedCapability(String),
}

impl ServerError {
    /// JSON-RPC error code.
    pub fn code(&self) -> i32 {
        match self {
            Self::MethodNotFound(_) => -32601,
            Self::InvalidParams(_) => -32602,
            Self::Serialization(_) => -32700,
            Self::ToolNotFound(_) | Self::ResourceNotFound(_) | Self::PromptNotFound(_) => -32000,
            Self::SessionExpired(_) => -32001,
            Self::Handler(_) => -32002,
            Self::UnsupportedCapability(_) => -32003,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ServerCapabilities
// ─────────────────────────────────────────────────────────────────────────────

/// Capability flags advertised during the `initialize` handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilities {
    /// Whether `tools/list` and `tools/call` are supported.
    pub tools: bool,
    /// Whether `resources/list` and `resources/read` are supported.
    pub resources: bool,
    /// Whether `prompts/list` and `prompts/get` are supported.
    pub prompts: bool,
    /// Whether streaming (progress notifications) are supported.
    pub streaming: bool,
    /// Whether the server supports batch requests.
    pub batch: bool,
    /// Protocol version this server speaks.
    pub protocol_version: String,
    /// Server name/identifier.
    pub server_name: String,
    /// Server version string.
    pub server_version: String,
}

impl Default for ServerCapabilities {
    fn default() -> Self {
        Self {
            tools: true,
            resources: true,
            prompts: true,
            streaming: false,
            batch: false,
            protocol_version: "2024-11-05".into(),
            server_name: "rustre-mcp".into(),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

impl ServerCapabilities {
    pub fn to_json(&self) -> Value {
        let mut cap = json!({});
        if self.tools {
            cap["tools"] = json!({"listChanged": false});
        }
        if self.resources {
            cap["resources"] = json!({"subscribe": false, "listChanged": false});
        }
        if self.prompts {
            cap["prompts"] = json!({"listChanged": false});
        }
        cap
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolDefinition
// ─────────────────────────────────────────────────────────────────────────────

/// Definition of a single MCP tool exposed by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub category: Option<String>,
    pub version: String,
    pub deprecated: bool,
}

impl ToolDefinition {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema: json!({"type": "object", "properties": {}}),
            category: None,
            version: "1.0.0".into(),
            deprecated: false,
        }
    }

    pub fn with_schema(mut self, schema: Value) -> Self {
        self.input_schema = schema;
        self
    }

    pub fn with_category(mut self, cat: impl Into<String>) -> Self {
        self.category = Some(cat.into());
        self
    }

    pub fn to_mcp_json(&self) -> Value {
        json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResourceDefinition
// ─────────────────────────────────────────────────────────────────────────────

/// Definition of a resource exposed by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDefinition {
    pub uri: String,
    pub name: String,
    pub description: Option<String>,
    pub mime_type: Option<String>,
}

impl ResourceDefinition {
    pub fn new(uri: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            name: name.into(),
            description: None,
            mime_type: None,
        }
    }

    pub fn with_mime(mut self, mime: impl Into<String>) -> Self {
        self.mime_type = Some(mime.into());
        self
    }

    pub fn to_mcp_json(&self) -> Value {
        let mut v = json!({ "uri": self.uri, "name": self.name });
        if let Some(d) = &self.description {
            v["description"] = json!(d);
        }
        if let Some(m) = &self.mime_type {
            v["mimeType"] = json!(m);
        }
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PromptDefinition
// ─────────────────────────────────────────────────────────────────────────────

/// A single argument for a [`PromptDefinition`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptArgument {
    pub name: String,
    pub description: Option<String>,
    pub required: bool,
}

/// Definition of an MCP prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptDefinition {
    pub name: String,
    pub description: Option<String>,
    pub arguments: Vec<PromptArgument>,
    pub template: String,
}

impl PromptDefinition {
    pub fn new(name: impl Into<String>, template: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            arguments: Vec::new(),
            template: template.into(),
        }
    }

    pub fn add_arg(mut self, name: &str, desc: Option<&str>, required: bool) -> Self {
        self.arguments.push(PromptArgument {
            name: name.into(),
            description: desc.map(|s| s.into()),
            required,
        });
        self
    }

    /// Render the template, substituting `{{key}}` with values from `args`.
    pub fn render(&self, args: &HashMap<String, String>) -> String {
        let mut out = self.template.clone();
        for (k, v) in args {
            out = out.replace(&format!("{{{{{k}}}}}"), v);
        }
        out
    }

    pub fn to_mcp_json(&self) -> Value {
        let args: Vec<Value> = self
            .arguments
            .iter()
            .map(|a| {
                let mut v = json!({ "name": a.name, "required": a.required });
                if let Some(d) = &a.description {
                    v["description"] = json!(d);
                }
                v
            })
            .collect();
        json!({ "name": self.name, "arguments": args })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResponseBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Fluent builder for MCP JSON-RPC responses.
#[derive(Debug)]
pub struct ResponseBuilder {
    id: Value,
    result: Option<Value>,
    error: Option<(i32, String)>,
}

impl ResponseBuilder {
    pub fn new(id: Value) -> Self {
        Self {
            id,
            result: None,
            error: None,
        }
    }

    pub fn success(mut self, result: Value) -> Self {
        self.result = Some(result);
        self
    }

    pub fn error(mut self, code: i32, message: impl Into<String>) -> Self {
        self.error = Some((code, message.into()));
        self
    }

    pub fn from_server_error(id: Value, err: &ServerError) -> Self {
        Self::new(id).error(err.code(), err.to_string())
    }

    pub fn build(self) -> Value {
        let mut v = json!({ "jsonrpc": "2.0", "id": self.id });
        if let Some(result) = self.result {
            v["result"] = result;
        } else if let Some((code, msg)) = self.error {
            v["error"] = json!({ "code": code, "message": msg });
        }
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RequestHandler
// ─────────────────────────────────────────────────────────────────────────────

/// A boxed async-like handler function for a method.
pub type HandlerFn = Arc<dyn Fn(Value) -> Result<Value, ServerError> + Send + Sync>;

/// Registry of method name → handler.
#[derive(Clone, Default)]
pub struct RequestHandler {
    handlers: HashMap<String, HandlerFn>,
}

impl RequestHandler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, method: impl Into<String>, handler: HandlerFn) {
        self.handlers.insert(method.into(), handler);
    }

    pub fn dispatch(&self, method: &str, params: Value) -> Result<Value, ServerError> {
        let handler = self
            .handlers
            .get(method)
            .ok_or_else(|| ServerError::MethodNotFound(method.to_string()))?;
        handler(params)
    }

    pub fn method_count(&self) -> usize {
        self.handlers.len()
    }

    pub fn has_method(&self, method: &str) -> bool {
        self.handlers.contains_key(method)
    }
}

impl fmt::Debug for RequestHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestHandler")
            .field("methods", &self.handlers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// McpSession
// ─────────────────────────────────────────────────────────────────────────────

/// State tracked for a single MCP client session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpSession {
    /// Unique session id.
    pub id: String,
    /// Whether the initialize handshake has completed.
    pub initialized: bool,
    /// Client-reported capabilities (from initialize params).
    pub client_capabilities: Value,
    /// Number of requests handled in this session.
    pub request_count: u64,
    /// Timestamp of session creation (seconds since Unix epoch).
    pub created_at: u64,
    /// Timestamp of last activity.
    pub last_active: u64,
    /// Optional session-level metadata.
    pub metadata: HashMap<String, String>,
}

impl McpSession {
    pub fn new(id: impl Into<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            id: id.into(),
            initialized: false,
            client_capabilities: json!({}),
            request_count: 0,
            created_at: now,
            last_active: now,
            metadata: HashMap::new(),
        }
    }

    pub fn touch(&mut self) {
        self.last_active = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.request_count += 1;
    }

    pub fn age_secs(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.created_at)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// McpServerImpl
// ─────────────────────────────────────────────────────────────────────────────

/// The core MCP server implementation.
pub struct McpServerImpl {
    pub capabilities: ServerCapabilities,
    pub tools: HashMap<String, ToolDefinition>,
    pub resources: HashMap<String, ResourceDefinition>,
    pub prompts: HashMap<String, PromptDefinition>,
    pub handler: RequestHandler,
    pub sessions: Arc<RwLock<HashMap<String, McpSession>>>,
}

impl McpServerImpl {
    pub fn new(caps: ServerCapabilities) -> Self {
        let mut handler = RequestHandler::new();
        // Register built-in methods
        let caps_clone = caps.clone();
        handler.register("initialize", Arc::new(move |params: Value| {
            let session_id = params.get("clientInfo")
                .and_then(|c| c.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            tracing::debug!(target: "mcp::initialize", %session_id, "initializing session");
            Ok(json!({
                "protocolVersion": caps_clone.protocol_version,
                "serverInfo": { "name": caps_clone.server_name, "version": caps_clone.server_version },
                "capabilities": caps_clone.to_json(),
            }))
        }));
        handler.register("ping", Arc::new(|_| Ok(json!({}))));
        Self {
            capabilities: caps,
            tools: HashMap::new(),
            resources: HashMap::new(),
            prompts: HashMap::new(),
            handler,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn register_tool(&mut self, tool: ToolDefinition) {
        self.tools.insert(tool.name.clone(), tool);
    }

    pub fn register_resource(&mut self, res: ResourceDefinition) {
        self.resources.insert(res.uri.clone(), res);
    }

    pub fn register_prompt(&mut self, prompt: PromptDefinition) {
        self.prompts.insert(prompt.name.clone(), prompt);
    }

    pub fn handle_request(&self, raw: &Value) -> Value {
        let id = raw.get("id").cloned().unwrap_or(Value::Null);
        let method = raw.get("method").and_then(Value::as_str).unwrap_or("");
        let params = raw.get("params").cloned().unwrap_or(json!({}));

        let compute = || -> Result<Value, ServerError> {
            match method {
                "tools/list" => {
                    let list: Vec<Value> = self.tools.values().map(|t| t.to_mcp_json()).collect();
                    Ok(json!({ "tools": list }))
                }
                "tools/call" => {
                    let name = params
                        .get("name")
                        .and_then(Value::as_str)
                        .ok_or_else(|| ServerError::InvalidParams("missing 'name'".into()))?;
                    if !self.tools.contains_key(name) {
                        Err(ServerError::ToolNotFound(name.to_string()))
                    } else {
                        Ok(
                            json!({ "content": [{ "type": "text", "text": format!("Tool '{}' executed", name) }] }),
                        )
                    }
                }
                "resources/list" => {
                    let list: Vec<Value> =
                        self.resources.values().map(|r| r.to_mcp_json()).collect();
                    Ok(json!({ "resources": list }))
                }
                "resources/read" => {
                    let uri = params
                        .get("uri")
                        .and_then(Value::as_str)
                        .ok_or_else(|| ServerError::InvalidParams("missing 'uri'".into()))?;
                    if !self.resources.contains_key(uri) {
                        Err(ServerError::ResourceNotFound(uri.to_string()))
                    } else {
                        Ok(json!({ "contents": [] }))
                    }
                }
                "prompts/list" => {
                    let list: Vec<Value> = self.prompts.values().map(|p| p.to_mcp_json()).collect();
                    Ok(json!({ "prompts": list }))
                }
                "prompts/get" => {
                    let name = params
                        .get("name")
                        .and_then(Value::as_str)
                        .ok_or_else(|| ServerError::InvalidParams("missing 'name'".into()))?;
                    let prompt = self
                        .prompts
                        .get(name)
                        .ok_or_else(|| ServerError::PromptNotFound(name.to_string()))?;
                    let args: HashMap<String, String> = params
                        .get("arguments")
                        .and_then(|a| serde_json::from_value(a.clone()).ok())
                        .unwrap_or_default();
                    Ok(
                        json!({ "messages": [{ "role": "user", "content": { "type": "text", "text": prompt.render(&args) } }] }),
                    )
                }
                other => self.handler.dispatch(other, params.clone()),
            }
        };

        match compute() {
            Ok(v) => ResponseBuilder::new(id).success(v).build(),
            Err(e) => ResponseBuilder::new(id)
                .error(e.code(), e.to_string())
                .build(),
        }
    }

    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }
    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }
    pub fn prompt_count(&self) -> usize {
        self.prompts.len()
    }

    pub fn create_session(&self, id: impl Into<String>) -> McpSession {
        let session = McpSession::new(id);
        self.sessions
            .write()
            .insert(session.id.clone(), session.clone());
        session
    }

    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }
}

impl Default for McpServerImpl {
    fn default() -> Self {
        Self::new(ServerCapabilities::default())
    }
}

impl fmt::Debug for McpServerImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpServerImpl")
            .field("tools", &self.tools.len())
            .field("resources", &self.resources.len())
            .field("prompts", &self.prompts.len())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> McpServerImpl {
        McpServerImpl::default()
    }

    // ── ServerCapabilities ───────────────────────────────────────────────────

    #[test]
    fn capabilities_default_tools_enabled() {
        assert!(ServerCapabilities::default().tools);
    }

    #[test]
    fn capabilities_to_json_contains_tools() {
        let caps = ServerCapabilities::default();
        let j = caps.to_json();
        assert!(j.get("tools").is_some());
    }

    #[test]
    fn capabilities_protocol_version() {
        assert!(!ServerCapabilities::default().protocol_version.is_empty());
    }

    // ── ToolDefinition ───────────────────────────────────────────────────────

    #[test]
    fn tool_definition_new() {
        let t = ToolDefinition::new("my_tool", "Does stuff");
        assert_eq!(t.name, "my_tool");
        assert!(!t.deprecated);
    }

    #[test]
    fn tool_definition_with_schema() {
        let t = ToolDefinition::new("t", "d").with_schema(json!({"type": "object"}));
        assert_eq!(t.input_schema["type"], "object");
    }

    #[test]
    fn tool_definition_to_mcp_json() {
        let t = ToolDefinition::new("foo", "bar");
        let j = t.to_mcp_json();
        assert_eq!(j["name"], "foo");
    }

    #[test]
    fn tool_definition_category() {
        let t = ToolDefinition::new("t", "d").with_category("analysis");
        assert_eq!(t.category.as_deref(), Some("analysis"));
    }

    // ── ResourceDefinition ───────────────────────────────────────────────────

    #[test]
    fn resource_definition_new() {
        let r = ResourceDefinition::new("rustre://binary/pe", "PE binary");
        assert_eq!(r.uri, "rustre://binary/pe");
    }

    #[test]
    fn resource_definition_with_mime() {
        let r = ResourceDefinition::new("uri", "name").with_mime("application/octet-stream");
        assert_eq!(r.mime_type.as_deref(), Some("application/octet-stream"));
    }

    #[test]
    fn resource_definition_to_mcp_json() {
        let r = ResourceDefinition::new("u", "n");
        let j = r.to_mcp_json();
        assert_eq!(j["uri"], "u");
    }

    // ── PromptDefinition ─────────────────────────────────────────────────────

    #[test]
    fn prompt_render_substitutes() {
        let p = PromptDefinition::new("greet", "Hello {{name}}!");
        let mut args = HashMap::new();
        args.insert("name".to_string(), "World".to_string());
        assert_eq!(p.render(&args), "Hello World!");
    }

    #[test]
    fn prompt_render_no_args() {
        let p = PromptDefinition::new("plain", "No substitution");
        assert_eq!(p.render(&HashMap::new()), "No substitution");
    }

    #[test]
    fn prompt_add_arg() {
        let p = PromptDefinition::new("p", "t").add_arg("x", Some("desc"), true);
        assert_eq!(p.arguments.len(), 1);
        assert!(p.arguments[0].required);
    }

    #[test]
    fn prompt_to_mcp_json() {
        let p = PromptDefinition::new("foo", "bar");
        let j = p.to_mcp_json();
        assert_eq!(j["name"], "foo");
    }

    // ── ResponseBuilder ──────────────────────────────────────────────────────

    #[test]
    fn response_builder_success() {
        let r = ResponseBuilder::new(json!(1))
            .success(json!({"ok": true}))
            .build();
        assert!(r["result"].is_object());
        assert!(r.get("error").is_none());
    }

    #[test]
    fn response_builder_error() {
        let r = ResponseBuilder::new(json!(2))
            .error(-32601, "not found")
            .build();
        assert!(r["error"].is_object());
        assert_eq!(r["error"]["code"], -32601);
    }

    #[test]
    fn response_builder_from_server_error() {
        let err = ServerError::ToolNotFound("x".into());
        let r = ResponseBuilder::from_server_error(json!(3), &err).build();
        assert!(r["error"].is_object());
    }

    #[test]
    fn response_builder_id_preserved() {
        let r = ResponseBuilder::new(json!("my-id"))
            .success(json!({}))
            .build();
        assert_eq!(r["id"], "my-id");
    }

    // ── RequestHandler ───────────────────────────────────────────────────────

    #[test]
    fn request_handler_dispatch_known() {
        let mut h = RequestHandler::new();
        h.register("hello", Arc::new(|_| Ok(json!({"reply": "hi"}))));
        let r = h.dispatch("hello", json!({})).unwrap();
        assert_eq!(r["reply"], "hi");
    }

    #[test]
    fn request_handler_dispatch_unknown_error() {
        let h = RequestHandler::new();
        let err = h.dispatch("unknown", json!({})).unwrap_err();
        assert!(matches!(err, ServerError::MethodNotFound(_)));
    }

    #[test]
    fn request_handler_method_count() {
        let mut h = RequestHandler::new();
        h.register("a", Arc::new(|_| Ok(json!({}))));
        h.register("b", Arc::new(|_| Ok(json!({}))));
        assert_eq!(h.method_count(), 2);
    }

    #[test]
    fn request_handler_has_method() {
        let mut h = RequestHandler::new();
        h.register("ping", Arc::new(|_| Ok(json!({}))));
        assert!(h.has_method("ping"));
        assert!(!h.has_method("pong"));
    }

    // ── McpSession ───────────────────────────────────────────────────────────

    #[test]
    fn session_new_not_initialized() {
        let s = McpSession::new("abc");
        assert!(!s.initialized);
    }

    #[test]
    fn session_touch_increments_count() {
        let mut s = McpSession::new("x");
        s.touch();
        assert_eq!(s.request_count, 1);
    }

    #[test]
    fn session_id_preserved() {
        let s = McpSession::new("my-session");
        assert_eq!(s.id, "my-session");
    }

    // ── McpServerImpl ────────────────────────────────────────────────────────

    #[test]
    fn server_register_tool() {
        let mut s = server();
        s.register_tool(ToolDefinition::new("tool1", "desc"));
        assert_eq!(s.tool_count(), 1);
    }

    #[test]
    fn server_register_resource() {
        let mut s = server();
        s.register_resource(ResourceDefinition::new("rustre://x", "X"));
        assert_eq!(s.resource_count(), 1);
    }

    #[test]
    fn server_register_prompt() {
        let mut s = server();
        s.register_prompt(PromptDefinition::new("p", "t"));
        assert_eq!(s.prompt_count(), 1);
    }

    #[test]
    fn server_handle_initialize() {
        let s = server();
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} });
        let r = s.handle_request(&req);
        assert!(r["result"].get("serverInfo").is_some() || r.get("error").is_none());
    }

    #[test]
    fn server_handle_tools_list() {
        let mut s = server();
        s.register_tool(ToolDefinition::new("t", "d"));
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} });
        let r = s.handle_request(&req);
        assert!(r["result"]["tools"].is_array());
    }

    #[test]
    fn server_handle_unknown_method_error() {
        let s = server();
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "no_such_method", "params": {} });
        let r = s.handle_request(&req);
        assert!(r.get("error").is_some());
    }

    #[test]
    fn server_handle_tools_call_not_found() {
        let s = server();
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "ghost"} });
        let r = s.handle_request(&req);
        assert!(r.get("error").is_some());
    }

    #[test]
    fn server_create_session() {
        let s = server();
        let session = s.create_session("s1");
        assert_eq!(session.id, "s1");
        assert_eq!(s.session_count(), 1);
    }

    #[test]
    fn server_ping() {
        let s = server();
        let req = json!({ "jsonrpc": "2.0", "id": 99, "method": "ping", "params": {} });
        let r = s.handle_request(&req);
        assert!(r.get("error").is_none());
    }
}
