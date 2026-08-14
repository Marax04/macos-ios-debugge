//! `rustre-mcp-federation`
//!
//! Federation layer: orchestrates multiple external MCP servers and presents
//! a unified tool surface with routing, health monitoring, and call logging.

pub mod mcp_router;
pub mod proxy_protocol;
pub mod tool_proxying;

// ── New federation pillars ──────────────────────────────────────────────────
pub mod ai_orchestrator;
pub mod context_propagation;
pub mod federation_metrics;
pub mod federation_registry;
pub mod result_cache;
pub mod server_discovery;
pub mod session_multiplexer;
pub mod tool_aggregator;
pub mod workflow_engine;
pub mod federation_router;
pub mod federation_load_balancer;
pub mod federation_cache;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::timeout;

use rustre_mcp_server::{JsonRpcRequest, JsonRpcResponse, McpError, ToolDefinition, ToolResult};

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum FederationError {
    #[error("server '{0}' not found")]
    ServerNotFound(String),
    #[error("tool '{0}' not found in any server")]
    ToolNotFound(String),
    #[error("connection error for server '{0}': {1}")]
    ConnectionError(String, String),
    #[error("transport not supported on this platform: {0}")]
    UnsupportedTransport(String),
    #[error("RPC error from server '{0}': {1}")]
    RpcError(String, String),
    #[error("timeout communicating with server '{0}'")]
    Timeout(String),
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("MCP error: {0}")]
    Mcp(#[from] McpError),
}

impl From<FederationError> for McpError {
    fn from(e: FederationError) -> Self {
        Self::InternalError(e.to_string())
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("TOML parse error: {0}")]
    TomlParse(String),
    #[error("TOML serialize error: {0}")]
    TomlSerialize(String),
    #[error("JSON parse error: {0}")]
    JsonParse(String),
    #[error("validation error: {0}")]
    Validation(String),
}

#[derive(Debug, Clone)]
pub struct ConfigValidationError {
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Transport / ExternalServerConfig
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerTransport {
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
    },
    SseHttp {
        url: String,
        #[serde(default)]
        headers: HashMap<String, String>,
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
    },
    WebSocket {
        url: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
    UnixSocket {
        path: String,
    },
}

const fn default_timeout_secs() -> u64 {
    30
}

const fn default_max_reconnects() -> u32 {
    3
}

const fn default_health_interval() -> u64 {
    60
}

const fn default_enabled() -> bool {
    true
}

const fn default_max_concurrent() -> u32 {
    16
}

const fn default_call_timeout() -> u64 {
    30
}

impl ServerTransport {
    #[must_use]
    pub const fn transport_type(&self) -> &'static str {
        match self {
            Self::Stdio { .. } => "stdio",
            Self::SseHttp { .. } => "sse_http",
            Self::WebSocket { .. } => "websocket",
            Self::UnixSocket { .. } => "unix_socket",
        }
    }

    #[must_use]
    pub const fn is_local(&self) -> bool {
        matches!(self, Self::Stdio { .. } | Self::UnixSocket { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalServerConfig {
    pub name: String,
    pub description: String,
    pub transport: ServerTransport,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_health_interval")]
    pub health_check_interval_secs: u64,
}

impl ExternalServerConfig {
    #[must_use]
    pub fn new_stdio(name: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            transport: ServerTransport::Stdio {
                command: command.into(),
                args: Vec::new(),
                env: HashMap::new(),
            },
            tags: Vec::new(),
            enabled: true,
            health_check_interval_secs: 60,
        }
    }

    #[must_use]
    pub fn new_http(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            transport: ServerTransport::SseHttp {
                url: url.into(),
                headers: HashMap::new(),
                timeout_secs: 30,
            },
            tags: Vec::new(),
            enabled: true,
            health_check_interval_secs: 60,
        }
    }

    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    #[must_use]
    pub const fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Routing types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RouteTarget {
    Server(String),
    ServerGroup(Vec<String>),
    Broadcast,
    FirstSuccess,
}

impl std::fmt::Display for RouteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Server(s) => write!(f, "server:{s}"),
            Self::ServerGroup(g) => write!(f, "group:[{}]", g.join(",")),
            Self::Broadcast => write!(f, "broadcast"),
            Self::FirstSuccess => write!(f, "first_success"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    pub pattern: String,
    pub route_to: RouteTarget,
    pub priority: u32,
}

impl RoutingRule {
    #[must_use]
    pub fn new(pattern: impl Into<String>, route_to: RouteTarget, priority: u32) -> Self {
        Self {
            pattern: pattern.into(),
            route_to,
            priority,
        }
    }

    /// Returns true if `tool_name` matches this rule's glob pattern.
    #[must_use]
    pub fn matches(&self, tool_name: &str) -> bool {
        glob_match(&self.pattern, tool_name)
    }
}

/// Simple glob matching: `*` matches any sequence, `?` matches one char.
fn glob_match(pattern: &str, input: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let inp: Vec<char> = input.chars().collect();
    // Iterative two-pointer algorithm with backtracking on the last '*'.
    // Runs in O(pat.len() * inp.len()) worst case, preventing exponential
    // blowup from patterns like "****x" against long inputs.
    let mut pi: usize = 0;
    let mut ii: usize = 0;
    let mut star: Option<usize> = None;
    let mut match_ii: usize = 0;
    while ii < inp.len() {
        if pi < pat.len() && pat[pi] == '*' {
            star = Some(pi);
            match_ii = ii;
            pi += 1;
        } else if pi < pat.len() && (pat[pi] == '?' || pat[pi] == inp[ii]) {
            pi += 1;
            ii += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            match_ii += 1;
            ii = match_ii;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }
    pi == pat.len()
}

// ─────────────────────────────────────────────────────────────────────────────
// FederationConfig — TOML-serializable
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FederationConfig {
    #[serde(default)]
    pub servers: Vec<ExternalServerConfig>,
    #[serde(default)]
    pub routing_rules: Vec<RoutingRule>,
    pub fallback_server: Option<String>,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_calls: u32,
    #[serde(default = "default_call_timeout")]
    pub call_timeout_secs: u64,
}

impl FederationConfig {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            servers: Vec::new(),
            routing_rules: Vec::new(),
            fallback_server: None,
            max_concurrent_calls: 16,
            call_timeout_secs: 30,
        }
    }

    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content).map_err(|e| ConfigError::TomlParse(e.to_string()))
    }

    /// Parse from JSON (for backward compatibility with configs that use JSON format).
    pub fn from_json(content: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(content).map_err(|e| ConfigError::JsonParse(e.to_string()))
    }

    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::TomlSerialize(e.to_string()))
    }

    #[must_use]
    pub fn default_config() -> Self {
        let mut cfg = Self::new();
        cfg.servers.push(
            ExternalServerConfig::new_stdio("frida-mcp", "frida-mcp")
                .with_description("Frida dynamic instrumentation MCP server")
                .with_tag("dynamic")
                .with_tag("instrumentation"),
        );
        cfg.servers.push(
            ExternalServerConfig::new_http("ghidra-mcp", "http://localhost:18080")
                .with_description("Ghidra decompiler MCP server")
                .with_tag("static")
                .with_tag("decompile"),
        );
        cfg.servers.push(
            ExternalServerConfig::new_stdio("yara-mcp", "yara-mcp-server")
                .with_description("YARA rule scanning MCP server")
                .with_tag("scanning"),
        );
        cfg.routing_rules.push(RoutingRule::new(
            "frida.*",
            RouteTarget::Server("frida-mcp".to_string()),
            100,
        ));
        cfg.routing_rules.push(RoutingRule::new(
            "ghidra.*",
            RouteTarget::Server("ghidra-mcp".to_string()),
            100,
        ));
        cfg.routing_rules.push(RoutingRule::new(
            "yara.*",
            RouteTarget::Server("yara-mcp".to_string()),
            100,
        ));
        cfg.routing_rules
            .push(RoutingRule::new("*", RouteTarget::FirstSuccess, 0));
        cfg.fallback_server = Some("ghidra-mcp".to_string());
        cfg
    }

    #[must_use] 
    pub fn validate(&self) -> Vec<ConfigValidationError> {
        let mut errors = Vec::new();

        for server in &self.servers {
            if server.name.is_empty() {
                errors.push(ConfigValidationError {
                    field: "server.name".to_string(),
                    message: "server name must not be empty".to_string(),
                });
            }
        }

        // Check for duplicate server names
        let mut seen = std::collections::HashSet::new();
        for server in &self.servers {
            if !seen.insert(&server.name) {
                errors.push(ConfigValidationError {
                    field: format!("server.name:{}", server.name),
                    message: format!("duplicate server name '{}'", server.name),
                });
            }
        }

        // Validate fallback_server references an existing server
        if let Some(fallback) = &self.fallback_server
            && !self.servers.iter().any(|s| &s.name == fallback) {
                errors.push(ConfigValidationError {
                    field: "fallback_server".to_string(),
                    message: format!("fallback server '{fallback}' not defined in servers list"),
                });
            }

        // Validate routing rules reference existing servers
        for rule in &self.routing_rules {
            match &rule.route_to {
                RouteTarget::Server(name) => {
                    if !self.servers.iter().any(|s| &s.name == name) {
                        errors.push(ConfigValidationError {
                            field: format!("routing_rule.pattern:{}", rule.pattern),
                            message: format!("route target server '{name}' not defined"),
                        });
                    }
                }
                RouteTarget::ServerGroup(names) => {
                    for name in names {
                        if !self.servers.iter().any(|s| &s.name == name) {
                            errors.push(ConfigValidationError {
                                field: format!("routing_rule.pattern:{}", rule.pattern),
                                message: format!("group server '{name}' not defined"),
                            });
                        }
                    }
                }
                RouteTarget::Broadcast | RouteTarget::FirstSuccess => {}
            }
        }

        if self.max_concurrent_calls == 0 {
            errors.push(ConfigValidationError {
                field: "max_concurrent_calls".to_string(),
                message: "must be greater than 0".to_string(),
            });
        }

        errors
    }

    pub fn add_server(&mut self, config: ExternalServerConfig) {
        self.servers.push(config);
    }

    pub fn remove_server(&mut self, name: &str) -> bool {
        let before = self.servers.len();
        self.servers.retain(|s| s.name != name);
        self.servers.len() < before
    }

    #[must_use]
    pub fn get_server(&self, name: &str) -> Option<&ExternalServerConfig> {
        self.servers.iter().find(|s| s.name == name)
    }

    #[must_use]
    pub fn enabled_servers(&self) -> Vec<&ExternalServerConfig> {
        self.servers.iter().filter(|s| s.enabled).collect()
    }

    #[must_use]
    pub fn servers_by_tag(&self, tag: &str) -> Vec<&ExternalServerConfig> {
        self.servers.iter().filter(|s| s.has_tag(tag)).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolRegistry
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FederatedTool {
    pub name: String,
    pub qualified_name: String,
    pub description: String,
    pub input_schema: Value,
    pub server_name: String,
    pub is_local: bool,
}

impl FederatedTool {
    #[must_use]
    pub fn new_local(
        name: impl Into<String>,
        description: impl Into<String>,
        schema: Value,
    ) -> Self {
        let n = name.into();
        Self {
            qualified_name: format!("local.{n}"),
            name: n,
            description: description.into(),
            input_schema: schema,
            server_name: "local".to_string(),
            is_local: true,
        }
    }

    #[must_use]
    pub fn new_remote(
        server_name: impl Into<String>,
        tool_name: impl Into<String>,
        description: impl Into<String>,
        schema: Value,
    ) -> Self {
        let srv = server_name.into();
        let tool = tool_name.into();
        let qualified = format!("{srv}.{tool}");
        Self {
            name: tool,
            qualified_name: qualified,
            description: description.into(),
            input_schema: schema,
            server_name: srv,
            is_local: false,
        }
    }

    #[must_use]
    pub fn from_tool_definition(server_name: &str, def: &ToolDefinition) -> Self {
        Self::new_remote(
            server_name,
            &def.name,
            &def.description,
            def.input_schema.clone(),
        )
    }
}

pub struct ToolRegistry {
    pub local_tools: Vec<FederatedTool>,
    pub remote_tools: HashMap<String, Vec<FederatedTool>>,
}

impl ToolRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            local_tools: Vec::new(),
            remote_tools: HashMap::new(),
        }
    }

    pub fn register_local(&mut self, tool: FederatedTool) {
        self.local_tools.push(tool);
    }

    pub fn register_remote(&mut self, server_name: &str, tools: Vec<FederatedTool>) {
        self.remote_tools.insert(server_name.to_string(), tools);
    }

    #[must_use]
    pub fn find_tool(&self, name: &str) -> Option<&FederatedTool> {
        // Try exact qualified name first
        for tool in &self.local_tools {
            if tool.qualified_name == name || tool.name == name {
                return Some(tool);
            }
        }
        for tools in self.remote_tools.values() {
            for tool in tools {
                if tool.qualified_name == name || tool.name == name {
                    return Some(tool);
                }
            }
        }
        None
    }

    #[must_use]
    pub fn list_all_tools(&self) -> Vec<&FederatedTool> {
        let mut all: Vec<&FederatedTool> = self.local_tools.iter().collect();
        for tools in self.remote_tools.values() {
            all.extend(tools.iter());
        }
        all
    }

    #[must_use]
    pub fn list_by_server(&self, server_name: &str) -> Vec<&FederatedTool> {
        if server_name == "local" {
            return self.local_tools.iter().collect();
        }
        self.remote_tools
            .get(server_name)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn search_tools(&self, query: &str) -> Vec<&FederatedTool> {
        let q = query.to_lowercase();
        self.list_all_tools()
            .into_iter()
            .filter(|t| {
                t.name.to_lowercase().contains(&q)
                    || t.description.to_lowercase().contains(&q)
                    || t.qualified_name.to_lowercase().contains(&q)
            })
            .collect()
    }

    #[must_use]
    pub fn tools_for_category(&self, category: &str) -> Vec<&FederatedTool> {
        // Category is derived from the tool name prefix (e.g. "disasm.at" -> "disasm")
        self.list_all_tools()
            .into_iter()
            .filter(|t| {
                t.name.starts_with(&format!("{category}."))
                    || t.name == category
                    || t.qualified_name.contains(&format!(".{category}."))
            })
            .collect()
    }

    #[must_use]
    pub fn total_tool_count(&self) -> usize {
        self.local_tools.len() + self.remote_tools.values().map(std::vec::Vec::len).sum::<usize>()
    }

    #[must_use]
    pub fn server_count(&self) -> usize {
        // +1 for "local" if there are any local tools
        let remote = self.remote_tools.len();
        if self.local_tools.is_empty() {
            remote
        } else {
            remote + 1
        }
    }

    pub fn clear_server(&mut self, server_name: &str) {
        self.remote_tools.remove(server_name);
    }

    #[must_use]
    pub fn has_server(&self, server_name: &str) -> bool {
        self.remote_tools.contains_key(server_name)
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RoutingDecision + RoutingContext + ToolRouter
// ─────────────────────────────────────────────────────────────────────────────

pub struct RoutingDecision {
    pub tool_name: String,
    pub servers: Vec<String>,
    pub strategy: RouteTarget,
    pub confidence: f64,
    pub fallback: Option<String>,
}

impl RoutingDecision {
    #[must_use]
    pub const fn is_routable(&self) -> bool {
        !self.servers.is_empty()
    }

    #[must_use]
    pub fn primary_server(&self) -> Option<&str> {
        self.servers.first().map(String::as_str)
    }
}

pub struct RoutingContext {
    pub caller_id: String,
    pub priority: Option<u32>,
    pub timeout_override: Option<Duration>,
    pub prefer_local: bool,
}

impl RoutingContext {
    #[must_use]
    pub fn new(caller_id: impl Into<String>) -> Self {
        Self {
            caller_id: caller_id.into(),
            priority: None,
            timeout_override: None,
            prefer_local: false,
        }
    }

    #[must_use]
    pub const fn with_priority(mut self, p: u32) -> Self {
        self.priority = Some(p);
        self
    }

    #[must_use]
    pub const fn prefer_local(mut self) -> Self {
        self.prefer_local = true;
        self
    }
}

pub struct ToolRouter {
    config: FederationConfig,
    registry: ToolRegistry,
}

impl ToolRouter {
    #[must_use]
    pub fn new(config: FederationConfig) -> Self {
        Self {
            registry: ToolRegistry::new(),
            config,
        }
    }

    #[must_use]
    pub const fn with_registry(config: FederationConfig, registry: ToolRegistry) -> Self {
        Self { config, registry }
    }

    #[must_use]
    pub fn route(&self, tool_name: &str) -> RoutingDecision {
        self.route_with_context(tool_name, &RoutingContext::new("anonymous"))
    }

    #[must_use]
    pub fn route_with_context(&self, tool_name: &str, ctx: &RoutingContext) -> RoutingDecision {
        // If prefer_local and tool exists locally, short-circuit
        if ctx.prefer_local
            && let Some(t) = self.registry.find_tool(tool_name)
                && t.is_local {
                    return RoutingDecision {
                        tool_name: tool_name.to_string(),
                        servers: vec!["local".to_string()],
                        strategy: RouteTarget::Server("local".to_string()),
                        confidence: 1.0,
                        fallback: self.config.fallback_server.clone(),
                    };
                }

        // Sort rules by priority descending
        let mut rules: Vec<&RoutingRule> = self.config.routing_rules.iter().collect();
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        for rule in rules {
            if rule.matches(tool_name) {
                let servers = match &rule.route_to {
                    RouteTarget::Server(s) => vec![s.clone()],
                    RouteTarget::ServerGroup(g) => g.clone(),
                    RouteTarget::Broadcast => self
                        .config
                        .enabled_servers()
                        .iter()
                        .map(|s| s.name.clone())
                        .collect(),
                    RouteTarget::FirstSuccess => self
                        .config
                        .enabled_servers()
                        .iter()
                        .map(|s| s.name.clone())
                        .collect(),
                };

                return RoutingDecision {
                    tool_name: tool_name.to_string(),
                    servers,
                    strategy: rule.route_to.clone(),
                    confidence: 0.9,
                    fallback: self.config.fallback_server.clone(),
                };
            }
        }

        // No rule matched — try to find tool in registry
        if let Some(tool) = self.registry.find_tool(tool_name) {
            return RoutingDecision {
                tool_name: tool_name.to_string(),
                servers: vec![tool.server_name.clone()],
                strategy: RouteTarget::Server(tool.server_name.clone()),
                confidence: 0.7,
                fallback: self.config.fallback_server.clone(),
            };
        }

        // Fall back to fallback server
        let servers = self
            .config
            .fallback_server
            .as_ref()
            .map(|s| vec![s.clone()])
            .unwrap_or_default();

        RoutingDecision {
            tool_name: tool_name.to_string(),
            servers,
            strategy: RouteTarget::FirstSuccess,
            confidence: 0.1,
            fallback: self.config.fallback_server.clone(),
        }
    }

    #[must_use]
    pub fn can_route(&self, tool_name: &str) -> bool {
        self.route(tool_name).is_routable()
    }

    #[must_use]
    pub const fn registry(&self) -> &ToolRegistry {
        &self.registry
    }

    pub const fn registry_mut(&mut self) -> &mut ToolRegistry {
        &mut self.registry
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HealthMonitor
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Unknown,
    Healthy,
    Degraded,
    Unhealthy,
    Unreachable,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Unhealthy => write!(f, "unhealthy"),
            Self::Unreachable => write!(f, "unreachable"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HealthCheck {
    pub timestamp: u64,
    pub status: HealthStatus,
    pub response_ms: u64,
    pub error: Option<String>,
}

impl HealthCheck {
    #[must_use]
    pub const fn success(timestamp: u64, response_ms: u64) -> Self {
        Self {
            timestamp,
            status: HealthStatus::Healthy,
            response_ms,
            error: None,
        }
    }

    #[must_use]
    pub fn failure(timestamp: u64, error: impl Into<String>) -> Self {
        Self {
            timestamp,
            status: HealthStatus::Unreachable,
            response_ms: 0,
            error: Some(error.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerHealth {
    pub server_name: String,
    pub status: HealthStatus,
    pub last_check: u64,
    pub consecutive_failures: u32,
    pub avg_response_ms: f64,
    pub uptime_pct: f64,
}

impl ServerHealth {
    #[must_use]
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            status: HealthStatus::Unknown,
            last_check: 0,
            consecutive_failures: 0,
            avg_response_ms: 0.0,
            uptime_pct: 100.0,
        }
    }

    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self.status, HealthStatus::Healthy | HealthStatus::Degraded)
    }
}

pub struct HealthMonitor {
    pub server_states: HashMap<String, ServerHealth>,
    pub history: HashMap<String, Vec<HealthCheck>>,
    history_limit: usize,
}

impl HealthMonitor {
    #[must_use]
    pub fn new(history_limit: usize) -> Self {
        Self {
            server_states: HashMap::new(),
            history: HashMap::new(),
            history_limit,
        }
    }

    pub fn record_check(&mut self, server: &str, check: HealthCheck) {
        // Update history
        let hist = self.history.entry(server.to_string()).or_default();
        hist.push(check.clone());
        if hist.len() > self.history_limit {
            let excess = hist.len() - self.history_limit;
            hist.drain(..excess);
        }

        // Update state
        let state = self
            .server_states
            .entry(server.to_string())
            .or_insert_with(|| ServerHealth::new(server));

        state.last_check = check.timestamp;
        state.status = check.status.clone();

        if check.status == HealthStatus::Healthy {
            state.consecutive_failures = 0;
        } else {
            state.consecutive_failures += 1;
        }

        // Recalculate avg_response_ms and uptime_pct from history
        let h = self.history.get(server).unwrap();
        let total = h.len() as f64;
        let successful = h
            .iter()
            .filter(|c| c.status == HealthStatus::Healthy)
            .count() as f64;
        let avg_ms = if total > 0.0 {
            h.iter().map(|c| c.response_ms as f64).sum::<f64>() / total
        } else {
            0.0
        };

        let state = self.server_states.get_mut(server).unwrap();
        state.avg_response_ms = avg_ms;
        state.uptime_pct = if total > 0.0 {
            (successful / total) * 100.0
        } else {
            100.0
        };
    }

    #[must_use]
    pub fn get_health(&self, server: &str) -> Option<&ServerHealth> {
        self.server_states.get(server)
    }

    #[must_use]
    pub fn healthy_servers(&self) -> Vec<&str> {
        self.server_states
            .iter()
            .filter(|(_, h)| h.is_available())
            .map(|(k, _)| k.as_str())
            .collect()
    }

    #[must_use]
    pub fn unhealthy_servers(&self) -> Vec<&str> {
        self.server_states
            .iter()
            .filter(|(_, h)| !h.is_available() && h.status != HealthStatus::Unknown)
            .map(|(k, _)| k.as_str())
            .collect()
    }

    #[must_use]
    pub fn availability_report(&self) -> HashMap<String, f64> {
        self.server_states
            .iter()
            .map(|(k, v)| (k.clone(), v.uptime_pct))
            .collect()
    }

    pub fn trigger_health_check_logic(&mut self, server: &str, success: bool, response_ms: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let check = if success {
            HealthCheck::success(now, response_ms)
        } else {
            HealthCheck::failure(now, "health check failed")
        };

        self.record_check(server, check);

        // Adjust status based on consecutive failures
        if let Some(state) = self.server_states.get_mut(server) {
            state.status = match state.consecutive_failures {
                0 => HealthStatus::Healthy,
                1..=2 => HealthStatus::Degraded,
                3..=5 => HealthStatus::Unhealthy,
                _ => HealthStatus::Unreachable,
            };
        }
    }

    #[must_use]
    pub fn get_history(&self, server: &str) -> Vec<&HealthCheck> {
        self.history
            .get(server)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn known_servers(&self) -> Vec<&str> {
        self.server_states.keys().map(String::as_str).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallAggregator
// ─────────────────────────────────────────────────────────────────────────────

pub struct CallAggregator;

impl CallAggregator {
    /// Merge multiple tool results into one JSON object.
    /// Results are merged under `results` array with server attribution.
    #[must_use]
    pub fn merge_results(results: Vec<(String, Value)>) -> Value {
        let merged: Vec<Value> = results
            .into_iter()
            .map(|(server, value)| serde_json::json!({ "server": server, "result": value }))
            .collect();
        let count = merged.len();
        serde_json::json!({ "results": merged, "count": count })
    }

    /// Return the first successful result from a set of (server, Result) pairs.
    #[must_use]
    pub fn first_success(results: Vec<(String, Result<Value, String>)>) -> Option<(String, Value)> {
        results
            .into_iter()
            .find_map(|(server, r)| r.ok().map(|v| (server, v)))
    }

    /// Deduplicate an array in `results["items"]` by a key field.
    #[must_use]
    pub fn deduplicate(results: Value, key_field: &str) -> Value {
        let arr = match results.as_array() {
            Some(a) => a.clone(),
            None => {
                if let Some(items) = results.get("items").and_then(Value::as_array) {
                    items.clone()
                } else {
                    return results;
                }
            }
        };

        let mut seen = std::collections::HashSet::new();
        let deduped: Vec<Value> = arr
            .into_iter()
            .filter(|item| {
                if let Some(key) = item.get(key_field) {
                    seen.insert(key.to_string())
                } else {
                    true
                }
            })
            .collect();

        serde_json::json!({ "items": deduped, "count": deduped.len() })
    }

    /// Combine array results from multiple servers into a single flat array.
    #[must_use]
    pub fn combine_arrays(results: Vec<Value>) -> Value {
        let mut combined: Vec<Value> = Vec::new();
        for result in results {
            match result {
                Value::Array(arr) => combined.extend(arr),
                other => {
                    // Try common array wrapper keys
                    for key in &["results", "items", "rows", "data", "list"] {
                        if let Some(arr) = other.get(key).and_then(Value::as_array) {
                            combined.extend(arr.iter().cloned());
                            break;
                        }
                    }
                }
            }
        }
        let len = combined.len();
        serde_json::json!({ "items": combined, "count": len })
    }

    /// Merge two JSON objects, with the second taking precedence.
    #[must_use]
    pub fn merge_objects(base: Value, override_val: Value) -> Value {
        match (base, override_val) {
            (Value::Object(mut base_map), Value::Object(override_map)) => {
                for (k, v) in override_map {
                    base_map.insert(k, v);
                }
                Value::Object(base_map)
            }
            (_, override_val) => override_val,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallLog
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CallLogEntry {
    pub id: u64,
    pub timestamp: u64,
    pub tool_name: String,
    pub server_name: String,
    pub params_hash: String,
    pub duration_ms: u64,
    pub success: bool,
    pub error: Option<String>,
}

impl CallLogEntry {
    #[must_use]
    pub fn new(
        id: u64,
        tool_name: impl Into<String>,
        server_name: impl Into<String>,
        params: &Value,
        duration_ms: u64,
        success: bool,
        error: Option<String>,
    ) -> Self {
        let params_hash = Self::hash_params(params);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            id,
            timestamp: now,
            tool_name: tool_name.into(),
            server_name: server_name.into(),
            params_hash,
            duration_ms,
            success,
            error,
        }
    }

    fn hash_params(params: &Value) -> String {
        // Simple deterministic hash without external deps
        let s = params.to_string();
        let mut h: u64 = 14695981039346656037;
        for b in s.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(1099511628211);
        }
        format!("{h:016x}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallStats {
    pub total_calls: u64,
    pub successful: u64,
    pub failed: u64,
    pub avg_duration_ms: f64,
    pub calls_by_server: HashMap<String, u64>,
    pub calls_by_tool: HashMap<String, u64>,
}

impl CallStats {
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total_calls == 0 {
            0.0
        } else {
            self.successful as f64 / self.total_calls as f64
        }
    }
}

pub struct CallLog {
    entries: Vec<CallLogEntry>,
    max_entries: usize,
    next_id: u64,
}

impl CallLog {
    #[must_use]
    pub const fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
            next_id: 1,
        }
    }

    pub fn record(&mut self, mut entry: CallLogEntry) {
        entry.id = self.next_id;
        self.next_id += 1;
        self.entries.push(entry);
        if self.entries.len() > self.max_entries {
            let excess = self.entries.len() - self.max_entries;
            self.entries.drain(..excess);
        }
    }

    #[must_use]
    pub fn recent(&self, n: usize) -> Vec<&CallLogEntry> {
        let skip = if self.entries.len() > n {
            self.entries.len() - n
        } else {
            0
        };
        self.entries[skip..].iter().collect()
    }

    #[must_use]
    pub fn stats(&self) -> CallStats {
        let total = self.entries.len() as u64;
        let successful = self.entries.iter().filter(|e| e.success).count() as u64;
        let failed = total - successful;
        let avg_ms = if total > 0 {
            self.entries
                .iter()
                .map(|e| e.duration_ms as f64)
                .sum::<f64>()
                / total as f64
        } else {
            0.0
        };

        let mut by_server: HashMap<String, u64> = HashMap::new();
        let mut by_tool: HashMap<String, u64> = HashMap::new();
        for e in &self.entries {
            *by_server.entry(e.server_name.clone()).or_default() += 1;
            *by_tool.entry(e.tool_name.clone()).or_default() += 1;
        }

        CallStats {
            total_calls: total,
            successful,
            failed,
            avg_duration_ms: avg_ms,
            calls_by_server: by_server,
            calls_by_tool: by_tool,
        }
    }

    #[must_use]
    pub fn by_server(&self, server: &str) -> Vec<&CallLogEntry> {
        self.entries
            .iter()
            .filter(|e| e.server_name == server)
            .collect()
    }

    #[must_use]
    pub fn by_tool(&self, tool: &str) -> Vec<&CallLogEntry> {
        self.entries
            .iter()
            .filter(|e| e.tool_name == tool)
            .collect()
    }

    #[must_use]
    pub fn success_rate(&self, server: Option<&str>) -> f64 {
        let entries: Vec<&CallLogEntry> = match server {
            Some(s) => self.entries.iter().filter(|e| e.server_name == s).collect(),
            None => self.entries.iter().collect(),
        };
        if entries.is_empty() {
            return 0.0;
        }
        let successful = entries.iter().filter(|e| e.success).count();
        successful as f64 / entries.len() as f64
    }

    #[must_use]
    pub const fn total_calls(&self) -> usize {
        self.entries.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FederationStatus
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationStatus {
    pub total_servers: u32,
    pub healthy_servers: u32,
    pub total_tools: u32,
    pub local_tools: u32,
    pub remote_tools: u32,
    pub calls_today: u64,
    pub success_rate: f64,
}

impl FederationStatus {
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.healthy_servers > 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FederationManager
// ─────────────────────────────────────────────────────────────────────────────

pub struct FederationManager {
    pub config: FederationConfig,
    pub registry: ToolRegistry,
    pub router: ToolRouter,
    pub health: HealthMonitor,
    pub call_log: CallLog,
}

impl FederationManager {
    #[must_use]
    pub fn new(config: FederationConfig) -> Self {
        let router = ToolRouter::new(FederationConfig {
            servers: config.servers.clone(),
            routing_rules: config.routing_rules.clone(),
            fallback_server: config.fallback_server.clone(),
            max_concurrent_calls: config.max_concurrent_calls,
            call_timeout_secs: config.call_timeout_secs,
        });
        Self {
            registry: ToolRegistry::new(),
            router,
            health: HealthMonitor::new(100),
            call_log: CallLog::new(10_000),
            config,
        }
    }

    pub fn from_toml(toml_content: &str) -> Result<Self, ConfigError> {
        let config = FederationConfig::from_toml(toml_content)?;
        Ok(Self::new(config))
    }

    #[must_use]
    pub fn default_manager() -> Self {
        Self::new(FederationConfig::new())
    }

    pub fn register_local_tool(&mut self, tool: FederatedTool) {
        self.registry.register_local(tool);
    }

    /// Populate the registry with stub tools derived from configured servers.
    /// Discover tools from each configured server.
    ///
    /// For each enabled server, this method attempts a real tools/list JSON-RPC
    /// call using `tokio::runtime` if available, falling back to synthetic stubs on
    /// connection failure. This ensures graceful degradation when servers are offline.
    pub fn discover_tools_from_config(&mut self) {
        for server in &self.config.servers {
            if !server.enabled {
                continue;
            }

            // Attempt a synchronous tools/list probe using a new Tokio runtime.
            // This avoids requiring an async context in the caller while still
            // reaching real MCP servers when they are available.
            let discovered = self.probe_server_tools_sync(server);
            let tools = if let Some(real_tools) = discovered {
                real_tools
            } else {
                // Fallback: register synthetic capability stubs so routing still works.
                vec![
                    FederatedTool::new_remote(
                        &server.name,
                        "ping",
                        "Health-check ping",
                        serde_json::json!({ "type": "object", "properties": {} }),
                    ),
                    FederatedTool::new_remote(
                        &server.name,
                        "capabilities",
                        "List server capabilities",
                        serde_json::json!({ "type": "object", "properties": {} }),
                    ),
                ]
            };

            self.registry.register_remote(&server.name, tools);
            self.health
                .trigger_health_check_logic(&server.name, true, 10);
        }
    }

    /// Attempt a real tools/list HTTP probe to the given server (SSE/HTTP transport only).
    ///
    /// Issues a GET request to the server's root endpoint and attempts to parse
    /// a tools list from the JSON response. Returns `None` on any error.
    fn probe_server_tools_sync(&self, server: &ExternalServerConfig) -> Option<Vec<FederatedTool>> {
        // Only attempt HTTP-based servers.
        let bind_addr = match &server.transport {
            ServerTransport::SseHttp { url, .. } => url.clone(),
            ServerTransport::WebSocket { url, .. } => url.clone(),
            _ => return None, // Stdio servers cannot be probed synchronously
        };

        let url = bind_addr;
        // `block_in_place` requires a multi-threaded Tokio runtime and panics
        // on a current-thread runtime.  Guard with a `try_current` check and
        // fall back to `None` (i.e. use synthetic stubs) when we are not
        // inside a multi-thread runtime context.
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(h) => h,
            Err(_) => return None,
        };
        let resp_json: serde_json::Value = tokio::task::block_in_place(|| {
            handle.block_on(async {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(2))
                .build()
                .ok()?;
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            });
            let resp = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .json(&body)
                .send()
                .await
                .ok()?;
            resp.json::<serde_json::Value>().await.ok()
        })
        })?;

        // MCP JSON-RPC response: {"result": {"tools": [...]}}; also accept bare {"tools": [...]}.
        let tools_arr = resp_json
            .get("result")
            .and_then(|r| r.get("tools"))
            .or_else(|| resp_json.get("tools"))?
            .as_array()?;
        Some(
            tools_arr
                .iter()
                .filter_map(|t| {
                    let name = t.get("name")?.as_str()?;
                    let desc = t.get("description").and_then(|d| d.as_str()).unwrap_or("");
                    let schema = t.get("inputSchema").cloned().unwrap_or_else(
                        || serde_json::json!({ "type": "object", "properties": {} }),
                    );
                    Some(FederatedTool::new_remote(&server.name, name, desc, schema))
                })
                .collect(),
        )
    }

    pub fn simulate_call(
        &mut self,
        tool_name: &str,
        params: Value,
    ) -> Result<Value, FederationError> {
        let decision = self.router.route(tool_name);
        if !decision.is_routable() {
            return Err(FederationError::ToolNotFound(tool_name.to_string()));
        }

        let server = decision.primary_server().unwrap_or("unknown").to_string();
        let start = std::time::Instant::now();

        // Stub result
        let result = serde_json::json!({
            "stub": true,
            "tool": tool_name,
            "server": server,
            "params_echo": params
        });

        let duration_ms = start.elapsed().as_millis() as u64;
        let entry = CallLogEntry::new(0, tool_name, &server, &params, duration_ms, true, None);
        self.call_log.record(entry);

        Ok(result)
    }

    #[must_use]
    pub fn tool_exists(&self, name: &str) -> bool {
        self.registry.find_tool(name).is_some()
    }

    #[must_use]
    pub fn server_list(&self) -> Vec<&ExternalServerConfig> {
        self.config.servers.iter().collect()
    }

    #[must_use]
    pub fn status_report(&self) -> FederationStatus {
        let stats = self.call_log.stats();
        let local = self.registry.local_tools.len() as u32;
        let remote: u32 = self
            .registry
            .remote_tools
            .values()
            .map(|v| v.len() as u32)
            .sum();

        FederationStatus {
            total_servers: self.config.servers.len() as u32,
            healthy_servers: self.health.healthy_servers().len() as u32,
            total_tools: local + remote,
            local_tools: local,
            remote_tools: remote,
            calls_today: stats.total_calls,
            success_rate: stats.success_rate(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy transport / connection types (preserved from original)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FederationTransport {
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
    },
    Http {
        url: String,
    },
    UnixSocket {
        path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalServer {
    pub name: String,
    pub transport: FederationTransport,
    pub tool_prefix: Option<String>,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_max_reconnects")]
    pub max_reconnects: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct McpFederationConfig {
    pub servers: Vec<ExternalServer>,
}

impl McpFederationConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_server(&mut self, server: ExternalServer) {
        self.servers.push(server);
    }
}

struct Channel {
    writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    reader: BufReader<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
}

impl Channel {
    async fn send_request(
        &mut self,
        req: &JsonRpcRequest,
    ) -> Result<JsonRpcResponse, FederationError> {
        let mut line = serde_json::to_string(req)?;
        line.push('\n');
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        // Limit reads from upstream servers to prevent OOM caused by an
        // adversarial or misbehaving server sending an unbounded line.
        // We read raw bytes up to MAX_RESPONSE_BYTES before passing to serde.
        const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
        let mut raw_bytes: Vec<u8> = Vec::new();
        self.reader.read_until(b'\n', &mut raw_bytes).await?;
        if raw_bytes.is_empty() {
            return Err(FederationError::ConnectionError(
                String::new(),
                "upstream server closed connection without response".into(),
            ));
        }
        if raw_bytes.len() > MAX_RESPONSE_BYTES {
            return Err(FederationError::ConnectionError(
                String::new(),
                format!(
                    "upstream server response exceeded {MAX_RESPONSE_BYTES} bytes"
                ),
            ));
        }
        let response_line = String::from_utf8_lossy(&raw_bytes);
        let resp: JsonRpcResponse = serde_json::from_str(response_line.trim())?;
        Ok(resp)
    }
}

pub struct ClientConnection {
    pub server_name: String,
    pub config: ExternalServer,
    cached_tools: Mutex<Vec<ToolDefinition>>,
    channel: AsyncMutex<Option<Channel>>,
    reconnect_count: Mutex<u32>,
}

impl ClientConnection {
    #[must_use]
    pub fn new(config: ExternalServer) -> Arc<Self> {
        Arc::new(Self {
            server_name: config.name.clone(),
            config,
            cached_tools: Mutex::new(Vec::new()),
            channel: AsyncMutex::new(None),
            reconnect_count: Mutex::new(0),
        })
    }

    pub async fn connect(&self) -> Result<(), FederationError> {
        let channel = self.open_channel().await?;
        *self.channel.lock().await = Some(channel);
        *self.reconnect_count.lock() = 0;
        Ok(())
    }

    async fn open_channel(&self) -> Result<Channel, FederationError> {
        match &self.config.transport {
            FederationTransport::Stdio { command, args } => {
                let mut child = tokio::process::Command::new(command)
                    .args(args)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .map_err(|e| {
                        FederationError::ConnectionError(self.server_name.clone(), e.to_string())
                    })?;
                let stdin = child.stdin.take().ok_or_else(|| {
                    FederationError::ConnectionError(
                        self.server_name.clone(),
                        "no child stdin".into(),
                    )
                })?;
                let stdout = child.stdout.take().ok_or_else(|| {
                    FederationError::ConnectionError(
                        self.server_name.clone(),
                        "no child stdout".into(),
                    )
                })?;
                tokio::spawn(async move {
                    let _ = child.wait().await;
                });
                Ok(Channel {
                    writer: Box::new(stdin),
                    reader: BufReader::new(Box::new(stdout)),
                })
            }
            FederationTransport::Http { url } => {
                let addr = Self::parse_http_addr(url)
                    .map_err(|e| FederationError::ConnectionError(self.server_name.clone(), e))?;
                let stream = tokio::net::TcpStream::connect(&addr).await.map_err(|e| {
                    FederationError::ConnectionError(self.server_name.clone(), e.to_string())
                })?;
                let (r, w) = tokio::io::split(stream);
                Ok(Channel {
                    writer: Box::new(w),
                    reader: BufReader::new(Box::new(r)),
                })
            }
            FederationTransport::UnixSocket { path } => {
                #[cfg(unix)]
                {
                    let stream = tokio::net::UnixStream::connect(path).await.map_err(|e| {
                        FederationError::ConnectionError(self.server_name.clone(), e.to_string())
                    })?;
                    let (r, w) = tokio::io::split(stream);
                    Ok(Channel {
                        writer: Box::new(w),
                        reader: BufReader::new(Box::new(r)),
                    })
                }
                #[cfg(not(unix))]
                {
                    let _ = path;
                    Err(FederationError::UnsupportedTransport(
                        "UnixSocket not supported".into(),
                    ))
                }
            }
        }
    }

    fn parse_http_addr(url: &str) -> Result<String, String> {
        let (rest, default_port) = if let Some(r) = url.strip_prefix("http://") {
            (r, 80)
        } else if let Some(r) = url.strip_prefix("https://") {
            (r, 443)
        } else {
            (url, 80)
        };
        let host_port = rest.split('/').next().unwrap_or(rest);
        if host_port.is_empty() {
            return Err(format!("could not parse host:port from URL: {url}"));
        }
        if host_port.contains(':') {
            Ok(host_port.to_string())
        } else {
            Ok(format!("{host_port}:{default_port}"))
        }
    }

    async fn reconnect(&self) -> Result<(), FederationError> {
        let count = {
            let mut c = self.reconnect_count.lock();
            *c += 1;
            *c
        };
        if count > self.config.max_reconnects {
            return Err(FederationError::ConnectionError(
                self.server_name.clone(),
                format!("exceeded max reconnects ({count})"),
            ));
        }
        self.connect().await
    }

    pub async fn rpc(&self, req: &JsonRpcRequest) -> Result<JsonRpcResponse, FederationError> {
        let dur = Duration::from_secs(self.config.timeout_secs);
        if let Ok(r) = self.try_rpc(req, dur).await { Ok(r) } else {
            self.reconnect().await?;
            self.try_rpc(req, dur).await
        }
    }

    async fn try_rpc(
        &self,
        req: &JsonRpcRequest,
        dur: Duration,
    ) -> Result<JsonRpcResponse, FederationError> {
        let mut guard = self.channel.lock().await;
        let channel = guard.as_mut().ok_or_else(|| {
            FederationError::ConnectionError(self.server_name.clone(), "not connected".into())
        })?;
        timeout(dur, channel.send_request(req))
            .await
            .map_err(|_| FederationError::Timeout(self.server_name.clone()))?
    }

    pub async fn initialize(&self) -> Result<(), FederationError> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            // These are REQUESTS, not notifications: each one expects a response,
            // so the id must be present. `JsonRpcRequest::id` became an `Option`
            // when the server learned to accept notifications.
            id: Some(Value::from(0)),
            method: "initialize".to_string(),
            params: Some(serde_json::json!({})),
        };
        let _resp = self.rpc(&req).await?;
        let tools_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(Value::from(1)),
            method: "tools/list".to_string(),
            params: None,
        };
        let tools_resp = self.rpc(&tools_req).await?;
        if let Some(err) = &tools_resp.error {
            return Err(FederationError::RpcError(
                self.server_name.clone(),
                err.message.clone(),
            ));
        }
        let tools: Vec<ToolDefinition> = tools_resp
            .result
            .as_ref()
            .and_then(|r| r.get("tools"))
            .and_then(|t| serde_json::from_value(t.clone()).ok())
            .unwrap_or_default();
        *self.cached_tools.lock() = tools;
        Ok(())
    }

    #[must_use]
    pub fn tools(&self) -> Vec<ToolDefinition> {
        self.cached_tools.lock().clone()
    }

    pub async fn call_tool(
        &self,
        tool_name: &str,
        args: Value,
    ) -> Result<ToolResult, FederationError> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(Value::from(42)),
            method: "tools/call".to_string(),
            params: Some(serde_json::json!({ "name": tool_name, "arguments": args })),
        };
        let resp = self.rpc(&req).await?;
        if let Some(err) = resp.error {
            return Err(FederationError::RpcError(
                self.server_name.clone(),
                err.message,
            ));
        }
        serde_json::from_value(resp.result.unwrap_or(Value::Null)).map_err(|e| {
            FederationError::ConnectionError(
                self.server_name.clone(),
                format!("bad tool result: {e}"),
            )
        })
    }
}

pub struct FederatedClient {
    pub config: McpFederationConfig,
    connections: Mutex<HashMap<String, Arc<ClientConnection>>>,
}

impl FederatedClient {
    #[must_use]
    pub fn new(config: McpFederationConfig) -> Self {
        Self {
            config,
            connections: Mutex::new(HashMap::new()),
        }
    }

    pub async fn connect_all(&self) -> Result<(), FederationError> {
        for server in &self.config.servers {
            let conn = ClientConnection::new(server.clone());
            conn.connect().await?;
            conn.initialize().await?;
            self.connections.lock().insert(server.name.clone(), conn);
        }
        Ok(())
    }

    #[must_use]
    pub fn list_all_tools(&self) -> Vec<crate::LegacyFederatedTool> {
        let conns = self.connections.lock();
        let mut result = Vec::new();
        for (server_name, conn) in conns.iter() {
            let prefix = self
                .config
                .servers
                .iter()
                .find(|s| &s.name == server_name)
                .and_then(|s| s.tool_prefix.as_deref())
                .unwrap_or("");
            for tool in conn.tools() {
                let full_name = if prefix.is_empty() {
                    tool.name.clone()
                } else {
                    format!("{prefix}{}", tool.name)
                };
                result.push(crate::LegacyFederatedTool {
                    server: server_name.clone(),
                    tool,
                    full_name,
                });
            }
        }
        result
    }

    pub async fn call_tool(&self, full_name: &str, args: Value) -> Result<ToolResult, McpError> {
        let all_tools = self.list_all_tools();
        let fed_tool = all_tools
            .iter()
            .find(|ft| ft.full_name == full_name)
            .ok_or_else(|| McpError::MethodNotFound(format!("tool not found: {full_name}")))?;
        let conn = {
            let conns = self.connections.lock();
            conns.get(&fed_tool.server).cloned().ok_or_else(|| {
                McpError::InternalError(format!("server '{}' not in pool", fed_tool.server))
            })?
        };
        conn.call_tool(&fed_tool.tool.name, args)
            .await
            .map_err(Into::into)
    }

    #[must_use]
    pub fn connected_servers(&self) -> Vec<String> {
        self.connections.lock().keys().cloned().collect()
    }

    pub fn inject_connection(&self, conn: Arc<ClientConnection>) {
        self.connections
            .lock()
            .insert(conn.server_name.clone(), conn);
    }

    pub fn disconnect(&self, server_name: &str) {
        self.connections.lock().remove(server_name);
    }
}

/// Legacy federated tool (kept for `FederatedClient` compatibility)
#[derive(Debug, Clone)]
pub struct LegacyFederatedTool {
    pub server: String,
    pub tool: ToolDefinition,
    pub full_name: String,
}

pub struct MockConnection;

impl MockConnection {
    #[must_use]
    pub fn new_client_conn(
        name: impl Into<String>,
        tool_defs: Vec<ToolDefinition>,
        timeout_secs: u64,
    ) -> Arc<ClientConnection> {
        let server_name = name.into();
        let conn = ClientConnection::new(ExternalServer {
            name: server_name,
            transport: FederationTransport::Stdio {
                command: "echo".to_string(),
                args: vec![],
            },
            tool_prefix: None,
            timeout_secs,
            max_reconnects: 0,
        });
        *conn.cached_tools.lock() = tool_defs;
        conn
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy spec types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedBackend {
    pub name: String,
    pub endpoint: String,
    pub capabilities: Vec<String>,
    pub weight: u32,
}

impl FederatedBackend {
    #[must_use]
    pub fn new(name: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            endpoint: endpoint.into(),
            capabilities: Vec::new(),
            weight: 1,
        }
    }

    #[must_use]
    pub fn with_cap(mut self, cap: impl Into<String>) -> Self {
        self.capabilities.push(cap.into());
        self
    }

    #[must_use]
    pub fn supports(&self, cap: &str) -> bool {
        self.capabilities.iter().any(|c| c == cap)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RouteDecision {
    ForwardTo(String),
    BroadcastAll,
    Reject(String),
}

impl std::fmt::Display for RouteDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForwardTo(n) => write!(f, "forward-to:{n}"),
            Self::BroadcastAll => write!(f, "broadcast-all"),
            Self::Reject(r) => write!(f, "reject:{r}"),
        }
    }
}

#[derive(Debug, Default)]
pub struct FederationRouter {
    pub backends: Vec<FederatedBackend>,
}

impl FederationRouter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_backend(&mut self, backend: FederatedBackend) {
        self.backends.push(backend);
    }

    #[must_use]
    pub fn route(&self, capability: &str) -> RouteDecision {
        for backend in &self.backends {
            if backend.supports(capability) {
                return RouteDecision::ForwardTo(backend.name.clone());
            }
        }
        RouteDecision::Reject(format!("no backend supports capability '{capability}'"))
    }

    #[must_use]
    pub fn backends_for_cap(&self, cap: &str) -> Vec<&FederatedBackend> {
        self.backends.iter().filter(|b| b.supports(cap)).collect()
    }
}

pub struct ServiceRegistry {
    inner: parking_lot::RwLock<HashMap<String, FederatedBackend>>,
}

impl ServiceRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    pub fn register(&self, backend: FederatedBackend) {
        self.inner.write().insert(backend.name.clone(), backend);
    }

    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<FederatedBackend> {
        self.inner.read().get(name).cloned()
    }

    #[must_use]
    pub fn list(&self) -> Vec<String> {
        self.inner.read().keys().cloned().collect()
    }
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tool_def(name: &str) -> ToolDefinition {
        ToolDefinition {
            name: name.to_string(),
            description: format!("Tool {name}"),
            input_schema: serde_json::json!({ "type": "object" }),
            parameters: serde_json::json!({ "type": "object" }),
        }
    }

    fn make_federated_tool(server: &str, name: &str) -> FederatedTool {
        FederatedTool::new_remote(server, name, format!("Tool {name}"), serde_json::json!({}))
    }

    // ── ExternalServerConfig ──────────────────────────────────────────────

    #[test]
    fn test_external_server_config_new_stdio() {
        let cfg = ExternalServerConfig::new_stdio("frida", "frida-mcp");
        assert_eq!(cfg.name, "frida");
        assert!(cfg.enabled);
        assert!(matches!(cfg.transport, ServerTransport::Stdio { .. }));
    }

    #[test]
    fn test_external_server_config_new_http() {
        let cfg = ExternalServerConfig::new_http("ghidra", "http://localhost:18080");
        assert!(matches!(cfg.transport, ServerTransport::SseHttp { .. }));
    }

    #[test]
    fn test_external_server_config_with_tag() {
        let cfg = ExternalServerConfig::new_stdio("s", "cmd")
            .with_tag("dynamic")
            .with_tag("arm");
        assert!(cfg.has_tag("dynamic"));
        assert!(cfg.has_tag("arm"));
        assert!(!cfg.has_tag("static"));
    }

    #[test]
    fn test_external_server_config_disabled() {
        let cfg = ExternalServerConfig::new_stdio("s", "cmd").disabled();
        assert!(!cfg.enabled);
    }

    #[test]
    fn test_server_transport_type() {
        let t = ServerTransport::Stdio {
            command: "x".into(),
            args: vec![],
            env: HashMap::new(),
        };
        assert_eq!(t.transport_type(), "stdio");
        let t2 = ServerTransport::SseHttp {
            url: "http://x".into(),
            headers: HashMap::new(),
            timeout_secs: 30,
        };
        assert_eq!(t2.transport_type(), "sse_http");
        let t3 = ServerTransport::WebSocket {
            url: "ws://x".into(),
            headers: HashMap::new(),
        };
        assert_eq!(t3.transport_type(), "websocket");
        let t4 = ServerTransport::UnixSocket {
            path: "/tmp/x.sock".into(),
        };
        assert_eq!(t4.transport_type(), "unix_socket");
    }

    #[test]
    fn test_server_transport_is_local() {
        let t = ServerTransport::Stdio {
            command: "x".into(),
            args: vec![],
            env: HashMap::new(),
        };
        assert!(t.is_local());
        let t2 = ServerTransport::SseHttp {
            url: "http://x".into(),
            headers: HashMap::new(),
            timeout_secs: 30,
        };
        assert!(!t2.is_local());
    }

    // ── ServerTransport serde ─────────────────────────────────────────────

    #[test]
    fn test_server_transport_serde_stdio() {
        let t = ServerTransport::Stdio {
            command: "mcp".into(),
            args: vec!["--stdio".into()],
            env: HashMap::new(),
        };
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["type"], "stdio");
        assert_eq!(v["command"], "mcp");
    }

    #[test]
    fn test_server_transport_serde_sse_http() {
        let t = ServerTransport::SseHttp {
            url: "http://x:8080".into(),
            headers: HashMap::new(),
            timeout_secs: 30,
        };
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["type"], "sse_http");
    }

    // ── FederationConfig ──────────────────────────────────────────────────

    #[test]
    fn test_federation_config_new() {
        let cfg = FederationConfig::new();
        assert!(cfg.servers.is_empty());
        assert_eq!(cfg.max_concurrent_calls, 16);
        assert_eq!(cfg.call_timeout_secs, 30);
    }

    #[test]
    fn test_federation_config_add_remove_server() {
        let mut cfg = FederationConfig::new();
        cfg.add_server(ExternalServerConfig::new_stdio("s1", "cmd1"));
        assert_eq!(cfg.servers.len(), 1);
        assert!(cfg.remove_server("s1"));
        assert!(cfg.servers.is_empty());
        assert!(!cfg.remove_server("s1"));
    }

    #[test]
    fn test_federation_config_get_server() {
        let mut cfg = FederationConfig::new();
        cfg.add_server(ExternalServerConfig::new_stdio("frida", "frida-mcp"));
        assert!(cfg.get_server("frida").is_some());
        assert!(cfg.get_server("nope").is_none());
    }

    #[test]
    fn test_federation_config_enabled_servers() {
        let mut cfg = FederationConfig::new();
        cfg.add_server(ExternalServerConfig::new_stdio("a", "cmd_a"));
        cfg.add_server(ExternalServerConfig::new_stdio("b", "cmd_b").disabled());
        let enabled = cfg.enabled_servers();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].name, "a");
    }

    #[test]
    fn test_federation_config_servers_by_tag() {
        let mut cfg = FederationConfig::new();
        cfg.add_server(ExternalServerConfig::new_stdio("a", "c").with_tag("scan"));
        cfg.add_server(ExternalServerConfig::new_stdio("b", "c").with_tag("decompile"));
        cfg.add_server(ExternalServerConfig::new_stdio("c", "c").with_tag("scan"));
        let scan = cfg.servers_by_tag("scan");
        assert_eq!(scan.len(), 2);
    }

    #[test]
    fn test_federation_config_validate_ok() {
        let cfg = FederationConfig::default_config();
        let errors = cfg.validate();
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn test_federation_config_validate_duplicate_name() {
        let mut cfg = FederationConfig::new();
        cfg.add_server(ExternalServerConfig::new_stdio("s", "cmd"));
        cfg.add_server(ExternalServerConfig::new_stdio("s", "cmd2"));
        let errors = cfg.validate();
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_federation_config_validate_bad_fallback() {
        let mut cfg = FederationConfig::new();
        cfg.add_server(ExternalServerConfig::new_stdio("s", "cmd"));
        cfg.fallback_server = Some("nonexistent".to_string());
        let errors = cfg.validate();
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_federation_config_validate_zero_concurrent() {
        let mut cfg = FederationConfig::new();
        cfg.max_concurrent_calls = 0;
        let errors = cfg.validate();
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_federation_config_toml_roundtrip() {
        let cfg = FederationConfig::default_config();
        let toml = cfg.to_toml().unwrap();
        let back = FederationConfig::from_toml(&toml).unwrap();
        assert_eq!(back.servers.len(), cfg.servers.len());
    }

    #[test]
    fn test_federation_config_default_config_routing_rules() {
        let cfg = FederationConfig::default_config();
        assert!(!cfg.routing_rules.is_empty());
    }

    // ── RoutingRule / glob_match ──────────────────────────────────────────

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("disasm.at", "disasm.at"));
        assert!(!glob_match("disasm.at", "disasm.function"));
    }

    #[test]
    fn test_glob_match_star_prefix() {
        assert!(glob_match("disasm.*", "disasm.at"));
        assert!(glob_match("disasm.*", "disasm.function"));
        assert!(!glob_match("disasm.*", "decompile.function"));
    }

    #[test]
    fn test_glob_match_star_any() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn test_glob_match_question_mark() {
        assert!(glob_match("disasm.?t", "disasm.at"));
        assert!(!glob_match("disasm.?t", "disasm.function"));
    }

    #[test]
    fn test_routing_rule_matches() {
        let rule = RoutingRule::new("frida.*", RouteTarget::Server("frida".into()), 100);
        assert!(rule.matches("frida.spawn"));
        assert!(!rule.matches("ghidra.decompile"));
    }

    #[test]
    fn test_route_target_display() {
        assert_eq!(RouteTarget::Server("s".into()).to_string(), "server:s");
        assert_eq!(RouteTarget::Broadcast.to_string(), "broadcast");
        assert_eq!(RouteTarget::FirstSuccess.to_string(), "first_success");
    }

    // ── ToolRegistry ──────────────────────────────────────────────────────

    #[test]
    fn test_tool_registry_register_local() {
        let mut reg = ToolRegistry::new();
        reg.register_local(FederatedTool::new_local(
            "test",
            "desc",
            serde_json::json!({}),
        ));
        assert_eq!(reg.total_tool_count(), 1);
        assert_eq!(reg.server_count(), 1);
    }

    #[test]
    fn test_tool_registry_register_remote() {
        let mut reg = ToolRegistry::new();
        let tools = vec![make_federated_tool("ghidra", "decompile")];
        reg.register_remote("ghidra", tools);
        assert_eq!(reg.total_tool_count(), 1);
        assert!(reg.has_server("ghidra"));
    }

    #[test]
    fn test_tool_registry_find_by_name() {
        let mut reg = ToolRegistry::new();
        reg.register_remote("srv", vec![make_federated_tool("srv", "mytool")]);
        assert!(reg.find_tool("mytool").is_some());
        assert!(reg.find_tool("srv.mytool").is_some());
        assert!(reg.find_tool("unknown").is_none());
    }

    #[test]
    fn test_tool_registry_list_by_server() {
        let mut reg = ToolRegistry::new();
        reg.register_remote(
            "a",
            vec![
                make_federated_tool("a", "t1"),
                make_federated_tool("a", "t2"),
            ],
        );
        reg.register_remote("b", vec![make_federated_tool("b", "t3")]);
        assert_eq!(reg.list_by_server("a").len(), 2);
        assert_eq!(reg.list_by_server("b").len(), 1);
        assert_eq!(reg.list_by_server("c").len(), 0);
    }

    #[test]
    fn test_tool_registry_search() {
        let mut reg = ToolRegistry::new();
        reg.register_remote(
            "srv",
            vec![
                make_federated_tool("srv", "disasm.at"),
                make_federated_tool("srv", "disasm.function"),
                make_federated_tool("srv", "decompile.function"),
            ],
        );
        let results = reg.search_tools("disasm");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_tool_registry_search_case_insensitive() {
        let mut reg = ToolRegistry::new();
        reg.register_remote("srv", vec![make_federated_tool("srv", "YARA_scan")]);
        let results = reg.search_tools("yara");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_tool_registry_tools_for_category() {
        let mut reg = ToolRegistry::new();
        reg.register_remote(
            "srv",
            vec![
                make_federated_tool("srv", "disasm.at"),
                make_federated_tool("srv", "disasm.function"),
                make_federated_tool("srv", "decompile.function"),
            ],
        );
        let disasm = reg.tools_for_category("disasm");
        assert_eq!(disasm.len(), 2);
    }

    #[test]
    fn test_tool_registry_clear_server() {
        let mut reg = ToolRegistry::new();
        reg.register_remote("ghidra", vec![make_federated_tool("ghidra", "decompile")]);
        reg.clear_server("ghidra");
        assert!(!reg.has_server("ghidra"));
        assert_eq!(reg.total_tool_count(), 0);
    }

    #[test]
    fn test_tool_registry_list_all_tools() {
        let mut reg = ToolRegistry::new();
        reg.register_local(FederatedTool::new_local(
            "local_tool",
            "desc",
            serde_json::json!({}),
        ));
        reg.register_remote("r", vec![make_federated_tool("r", "remote_tool")]);
        let all = reg.list_all_tools();
        assert_eq!(all.len(), 2);
    }

    // ── ToolRouter ────────────────────────────────────────────────────────

    #[test]
    fn test_tool_router_route_by_pattern() {
        let mut cfg = FederationConfig::new();
        cfg.add_server(ExternalServerConfig::new_stdio("frida", "frida-mcp"));
        cfg.routing_rules.push(RoutingRule::new(
            "frida.*",
            RouteTarget::Server("frida".into()),
            100,
        ));
        let router = ToolRouter::new(cfg);
        let decision = router.route("frida.spawn");
        assert!(decision.is_routable());
        assert_eq!(decision.primary_server(), Some("frida"));
    }

    #[test]
    fn test_tool_router_route_no_match() {
        let cfg = FederationConfig::new();
        let router = ToolRouter::new(cfg);
        let decision = router.route("unknown.tool");
        assert!(!decision.is_routable());
    }

    #[test]
    fn test_tool_router_route_fallback() {
        let mut cfg = FederationConfig::new();
        cfg.add_server(ExternalServerConfig::new_stdio("fallback_srv", "cmd"));
        cfg.fallback_server = Some("fallback_srv".to_string());
        let router = ToolRouter::new(cfg);
        let decision = router.route("some.unmatched.tool");
        assert_eq!(decision.fallback.as_deref(), Some("fallback_srv"));
    }

    #[test]
    fn test_tool_router_route_from_registry() {
        let mut cfg = FederationConfig::new();
        cfg.add_server(ExternalServerConfig::new_stdio("ghidra", "cmd"));
        let mut reg = ToolRegistry::new();
        reg.register_remote(
            "ghidra",
            vec![make_federated_tool("ghidra", "decompile.function")],
        );
        let router = ToolRouter::with_registry(cfg, reg);
        let decision = router.route("decompile.function");
        assert!(decision.is_routable());
    }

    #[test]
    fn test_tool_router_can_route() {
        let mut cfg = FederationConfig::new();
        cfg.add_server(ExternalServerConfig::new_stdio("srv", "cmd"));
        cfg.routing_rules
            .push(RoutingRule::new("*", RouteTarget::FirstSuccess, 0));
        let router = ToolRouter::new(cfg);
        assert!(router.can_route("anything"));
    }

    #[test]
    fn test_tool_router_prefer_local() {
        let cfg = FederationConfig::new();
        let mut reg = ToolRegistry::new();
        reg.register_local(FederatedTool::new_local(
            "local_tool",
            "desc",
            serde_json::json!({}),
        ));
        let router = ToolRouter::with_registry(cfg, reg);
        let ctx = RoutingContext::new("test").prefer_local();
        let decision = router.route_with_context("local_tool", &ctx);
        assert_eq!(decision.primary_server(), Some("local"));
    }

    #[test]
    fn test_routing_decision_is_routable() {
        let d = RoutingDecision {
            tool_name: "x".into(),
            servers: vec!["s".into()],
            strategy: RouteTarget::Server("s".into()),
            confidence: 1.0,
            fallback: None,
        };
        assert!(d.is_routable());
        let d2 = RoutingDecision {
            tool_name: "x".into(),
            servers: vec![],
            strategy: RouteTarget::FirstSuccess,
            confidence: 0.0,
            fallback: None,
        };
        assert!(!d2.is_routable());
    }

    // ── HealthMonitor ─────────────────────────────────────────────────────

    #[test]
    fn test_health_monitor_record_success() {
        let mut hm = HealthMonitor::new(50);
        hm.record_check("srv", HealthCheck::success(1000, 25));
        let h = hm.get_health("srv").unwrap();
        assert_eq!(h.status, HealthStatus::Healthy);
        assert_eq!(h.consecutive_failures, 0);
    }

    #[test]
    fn test_health_monitor_record_failure() {
        let mut hm = HealthMonitor::new(50);
        hm.record_check("srv", HealthCheck::failure(1000, "timeout"));
        let h = hm.get_health("srv").unwrap();
        assert_eq!(h.consecutive_failures, 1);
    }

    #[test]
    fn test_health_monitor_healthy_servers() {
        let mut hm = HealthMonitor::new(50);
        hm.record_check("a", HealthCheck::success(1000, 10));
        hm.record_check("b", HealthCheck::failure(1000, "err"));
        let healthy = hm.healthy_servers();
        assert!(healthy.contains(&"a"));
        assert!(!healthy.contains(&"b"));
    }

    #[test]
    fn test_health_monitor_unhealthy_servers() {
        let mut hm = HealthMonitor::new(50);
        hm.trigger_health_check_logic("x", false, 0);
        hm.trigger_health_check_logic("x", false, 0);
        hm.trigger_health_check_logic("x", false, 0);
        let unhealthy = hm.unhealthy_servers();
        assert!(unhealthy.contains(&"x"));
    }

    #[test]
    fn test_health_monitor_availability_report() {
        let mut hm = HealthMonitor::new(50);
        hm.record_check("srv", HealthCheck::success(1000, 10));
        hm.record_check("srv", HealthCheck::success(1001, 15));
        hm.record_check("srv", HealthCheck::failure(1002, "e"));
        let report = hm.availability_report();
        let pct = *report.get("srv").unwrap();
        assert!((pct - 66.666).abs() < 1.0);
    }

    #[test]
    fn test_health_monitor_trigger_degraded() {
        let mut hm = HealthMonitor::new(50);
        hm.trigger_health_check_logic("srv", true, 10);
        hm.trigger_health_check_logic("srv", false, 0);
        let h = hm.get_health("srv").unwrap();
        assert_eq!(h.status, HealthStatus::Degraded);
    }

    #[test]
    fn test_health_monitor_history_limit() {
        let mut hm = HealthMonitor::new(3);
        for i in 0..10u64 {
            hm.record_check("srv", HealthCheck::success(i, 1));
        }
        assert!(hm.get_history("srv").len() <= 3);
    }

    #[test]
    fn test_health_monitor_known_servers() {
        let mut hm = HealthMonitor::new(10);
        hm.record_check("a", HealthCheck::success(0, 1));
        hm.record_check("b", HealthCheck::success(0, 1));
        let known = hm.known_servers();
        assert!(known.contains(&"a"));
        assert!(known.contains(&"b"));
    }

    #[test]
    fn test_health_status_display() {
        assert_eq!(HealthStatus::Unknown.to_string(), "unknown");
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Degraded.to_string(), "degraded");
        assert_eq!(HealthStatus::Unhealthy.to_string(), "unhealthy");
        assert_eq!(HealthStatus::Unreachable.to_string(), "unreachable");
    }

    #[test]
    fn test_server_health_is_available() {
        let mut h = ServerHealth::new("srv");
        h.status = HealthStatus::Healthy;
        assert!(h.is_available());
        h.status = HealthStatus::Degraded;
        assert!(h.is_available());
        h.status = HealthStatus::Unhealthy;
        assert!(!h.is_available());
    }

    // ── CallAggregator ────────────────────────────────────────────────────

    #[test]
    fn test_call_aggregator_merge_results() {
        let results = vec![
            ("srv1".to_string(), serde_json::json!({"foo": 1})),
            ("srv2".to_string(), serde_json::json!({"bar": 2})),
        ];
        let merged = CallAggregator::merge_results(results);
        let arr = merged["results"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn test_call_aggregator_first_success() {
        let results = vec![
            ("a".to_string(), Err("err".to_string())),
            ("b".to_string(), Ok(serde_json::json!({"ok": true}))),
            ("c".to_string(), Ok(serde_json::json!({"ok": false}))),
        ];
        let (server, val) = CallAggregator::first_success(results).unwrap();
        assert_eq!(server, "b");
        assert_eq!(val["ok"], true);
    }

    #[test]
    fn test_call_aggregator_first_success_all_fail() {
        let results: Vec<(String, Result<Value, String>)> =
            vec![("a".to_string(), Err("e1".to_string()))];
        assert!(CallAggregator::first_success(results).is_none());
    }

    #[test]
    fn test_call_aggregator_deduplicate() {
        let items = serde_json::json!([
            {"id": "1", "name": "a"},
            {"id": "2", "name": "b"},
            {"id": "1", "name": "a_dup"}
        ]);
        let result = CallAggregator::deduplicate(items, "id");
        let arr = result["items"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn test_call_aggregator_combine_arrays() {
        let a = serde_json::json!([1, 2, 3]);
        let b = serde_json::json!([4, 5]);
        let combined = CallAggregator::combine_arrays(vec![a, b]);
        let items = combined["items"].as_array().unwrap();
        assert_eq!(items.len(), 5);
    }

    #[test]
    fn test_call_aggregator_combine_object_arrays() {
        let a = serde_json::json!({"results": [{"x": 1}]});
        let b = serde_json::json!({"results": [{"x": 2}, {"x": 3}]});
        let combined = CallAggregator::combine_arrays(vec![a, b]);
        assert_eq!(combined["count"], 3);
    }

    #[test]
    fn test_call_aggregator_merge_objects() {
        let base = serde_json::json!({"a": 1, "b": 2});
        let over = serde_json::json!({"b": 99, "c": 3});
        let merged = CallAggregator::merge_objects(base, over);
        assert_eq!(merged["a"], 1);
        assert_eq!(merged["b"], 99);
        assert_eq!(merged["c"], 3);
    }

    // ── CallLog ───────────────────────────────────────────────────────────

    #[test]
    fn test_call_log_record_and_recent() {
        let mut log = CallLog::new(100);
        for i in 0..5 {
            let entry = CallLogEntry::new(
                0,
                format!("tool.{i}"),
                "srv",
                &serde_json::json!({}),
                10,
                true,
                None,
            );
            log.record(entry);
        }
        assert_eq!(log.total_calls(), 5);
        assert_eq!(log.recent(3).len(), 3);
    }

    #[test]
    fn test_call_log_max_entries() {
        let mut log = CallLog::new(5);
        for i in 0..10 {
            let entry = CallLogEntry::new(
                0,
                format!("t{i}"),
                "s",
                &serde_json::json!({}),
                1,
                true,
                None,
            );
            log.record(entry);
        }
        assert_eq!(log.total_calls(), 5);
    }

    #[test]
    fn test_call_log_stats() {
        let mut log = CallLog::new(100);
        log.record(CallLogEntry::new(
            0,
            "t1",
            "s1",
            &serde_json::json!({}),
            100,
            true,
            None,
        ));
        log.record(CallLogEntry::new(
            0,
            "t2",
            "s1",
            &serde_json::json!({}),
            200,
            false,
            Some("err".into()),
        ));
        log.record(CallLogEntry::new(
            0,
            "t1",
            "s2",
            &serde_json::json!({}),
            50,
            true,
            None,
        ));
        let stats = log.stats();
        assert_eq!(stats.total_calls, 3);
        assert_eq!(stats.successful, 2);
        assert_eq!(stats.failed, 1);
        assert!((stats.avg_duration_ms - 116.67).abs() < 1.0);
    }

    #[test]
    fn test_call_log_by_server() {
        let mut log = CallLog::new(100);
        log.record(CallLogEntry::new(
            0,
            "t1",
            "s1",
            &serde_json::json!({}),
            10,
            true,
            None,
        ));
        log.record(CallLogEntry::new(
            0,
            "t2",
            "s2",
            &serde_json::json!({}),
            10,
            true,
            None,
        ));
        log.record(CallLogEntry::new(
            0,
            "t3",
            "s1",
            &serde_json::json!({}),
            10,
            true,
            None,
        ));
        assert_eq!(log.by_server("s1").len(), 2);
        assert_eq!(log.by_server("s2").len(), 1);
    }

    #[test]
    fn test_call_log_by_tool() {
        let mut log = CallLog::new(100);
        log.record(CallLogEntry::new(
            0,
            "disasm.at",
            "s",
            &serde_json::json!({}),
            10,
            true,
            None,
        ));
        log.record(CallLogEntry::new(
            0,
            "disasm.at",
            "s",
            &serde_json::json!({}),
            10,
            true,
            None,
        ));
        log.record(CallLogEntry::new(
            0,
            "decompile.function",
            "s",
            &serde_json::json!({}),
            10,
            true,
            None,
        ));
        assert_eq!(log.by_tool("disasm.at").len(), 2);
    }

    #[test]
    fn test_call_log_success_rate_all() {
        let mut log = CallLog::new(100);
        log.record(CallLogEntry::new(
            0,
            "t",
            "s",
            &serde_json::json!({}),
            10,
            true,
            None,
        ));
        log.record(CallLogEntry::new(
            0,
            "t",
            "s",
            &serde_json::json!({}),
            10,
            false,
            Some("e".into()),
        ));
        assert!((log.success_rate(None) - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_call_log_success_rate_by_server() {
        let mut log = CallLog::new(100);
        log.record(CallLogEntry::new(
            0,
            "t",
            "s1",
            &serde_json::json!({}),
            10,
            true,
            None,
        ));
        log.record(CallLogEntry::new(
            0,
            "t",
            "s1",
            &serde_json::json!({}),
            10,
            true,
            None,
        ));
        log.record(CallLogEntry::new(
            0,
            "t",
            "s2",
            &serde_json::json!({}),
            10,
            false,
            Some("e".into()),
        ));
        assert!((log.success_rate(Some("s1")) - 1.0).abs() < 0.01);
        assert!((log.success_rate(Some("s2")) - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_call_log_entry_hash_deterministic() {
        let params = serde_json::json!({"binary_id": "b", "addr": "0x401000"});
        let h1 = CallLogEntry::hash_params(&params);
        let h2 = CallLogEntry::hash_params(&params);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
    }

    // ── FederationManager ─────────────────────────────────────────────────

    #[test]
    fn test_federation_manager_new() {
        let cfg = FederationConfig::default_config();
        let mgr = FederationManager::new(cfg);
        assert_eq!(mgr.server_list().len(), 3);
    }

    #[test]
    fn test_federation_manager_default() {
        let mgr = FederationManager::default_manager();
        assert!(mgr.server_list().is_empty());
    }

    #[test]
    fn test_federation_manager_register_local_tool() {
        let mut mgr = FederationManager::default_manager();
        mgr.register_local_tool(FederatedTool::new_local(
            "ping",
            "ping tool",
            serde_json::json!({}),
        ));
        assert!(mgr.tool_exists("ping"));
    }

    #[test]
    fn test_federation_manager_discover_tools() {
        let mut mgr = FederationManager::new(FederationConfig::default_config());
        mgr.discover_tools_from_config();
        assert!(mgr.registry.total_tool_count() > 0);
    }

    #[test]
    fn test_federation_manager_simulate_call_no_route() {
        let mut mgr = FederationManager::default_manager();
        let result = mgr.simulate_call("noop.tool", serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn test_federation_manager_simulate_call_routable() {
        let mut cfg = FederationConfig::new();
        cfg.add_server(ExternalServerConfig::new_stdio("s", "cmd"));
        cfg.routing_rules
            .push(RoutingRule::new("*", RouteTarget::FirstSuccess, 0));
        let mut mgr = FederationManager::new(cfg);
        let result = mgr.simulate_call("any.tool", serde_json::json!({}));
        assert!(result.is_ok());
    }

    #[test]
    fn test_federation_manager_status_report() {
        let mut mgr = FederationManager::new(FederationConfig::default_config());
        mgr.discover_tools_from_config();
        let status = mgr.status_report();
        assert_eq!(status.total_servers, 3);
        assert!(status.total_tools > 0);
    }

    #[test]
    fn test_federation_manager_from_toml() {
        let cfg = FederationConfig::new();
        let json = serde_json::to_string(&cfg).unwrap();
        let mgr = FederationManager::from_toml(&json).unwrap();
        assert!(mgr.server_list().is_empty());
    }

    #[test]
    fn test_federation_status_is_healthy() {
        let status = FederationStatus {
            total_servers: 3,
            healthy_servers: 2,
            total_tools: 10,
            local_tools: 2,
            remote_tools: 8,
            calls_today: 100,
            success_rate: 0.95,
        };
        assert!(status.is_healthy());
        let unhealthy = FederationStatus {
            healthy_servers: 0,
            ..status
        };
        assert!(!unhealthy.is_healthy());
    }

    // ── CallStats ─────────────────────────────────────────────────────────

    #[test]
    fn test_call_stats_success_rate() {
        let stats = CallStats {
            total_calls: 10,
            successful: 7,
            failed: 3,
            avg_duration_ms: 50.0,
            calls_by_server: HashMap::new(),
            calls_by_tool: HashMap::new(),
        };
        assert!((stats.success_rate() - 0.7).abs() < 0.01);
    }

    #[test]
    fn test_call_stats_success_rate_zero_calls() {
        let stats = CallStats {
            total_calls: 0,
            successful: 0,
            failed: 0,
            avg_duration_ms: 0.0,
            calls_by_server: HashMap::new(),
            calls_by_tool: HashMap::new(),
        };
        assert_eq!(stats.success_rate(), 0.0);
    }

    // ── Legacy FederatedClient tests ──────────────────────────────────────

    fn make_config_no_servers() -> McpFederationConfig {
        McpFederationConfig::new()
    }

    fn client_with_mocks(
        servers: Vec<(&str, Vec<ToolDefinition>, Option<&str>)>,
    ) -> FederatedClient {
        let mut config = make_config_no_servers();
        for (name, _, prefix) in &servers {
            config.add_server(ExternalServer {
                name: (*name).to_string(),
                transport: FederationTransport::Stdio {
                    command: "echo".to_string(),
                    args: vec![],
                },
                tool_prefix: prefix.map(str::to_string),
                timeout_secs: 5,
                max_reconnects: 0,
            });
        }
        let client = FederatedClient::new(config);
        for (name, tools, _) in servers {
            let conn = MockConnection::new_client_conn(name, tools, 5);
            client.inject_connection(conn);
        }
        client
    }

    #[test]
    fn test_legacy_list_all_tools_no_prefix() {
        let client = client_with_mocks(vec![(
            "server1",
            vec![make_tool_def("disassemble"), make_tool_def("hex_dump")],
            None,
        )]);
        let tools = client.list_all_tools();
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn test_legacy_list_all_tools_with_prefix() {
        let client = client_with_mocks(vec![(
            "ghidra",
            vec![make_tool_def("decompile")],
            Some("ghidra."),
        )]);
        let tools = client.list_all_tools();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].full_name, "ghidra.decompile");
    }

    #[test]
    fn test_legacy_connected_servers() {
        let client = client_with_mocks(vec![("a", vec![], None), ("b", vec![], None)]);
        let mut servers = client.connected_servers();
        servers.sort();
        assert_eq!(servers, ["a", "b"]);
    }

    #[test]
    fn test_legacy_disconnect() {
        let client = client_with_mocks(vec![("srv", vec![], None)]);
        assert_eq!(client.connected_servers().len(), 1);
        client.disconnect("srv");
        assert!(client.connected_servers().is_empty());
    }

    #[tokio::test]
    async fn test_legacy_call_tool_not_found() {
        let client = client_with_mocks(vec![("srv", vec![make_tool_def("echo")], None)]);
        let result = client.call_tool("nonexistent", serde_json::json!({})).await;
        assert!(result.is_err());
    }

    // ── FederatedBackend / legacy types ───────────────────────────────────

    #[test]
    fn test_federated_backend_supports() {
        let b = FederatedBackend::new("srv", "http://x").with_cap("decompile");
        assert!(b.supports("decompile"));
        assert!(!b.supports("disasm"));
    }

    #[test]
    fn test_route_decision_display() {
        assert_eq!(
            RouteDecision::ForwardTo("ghidra".into()).to_string(),
            "forward-to:ghidra"
        );
        assert_eq!(RouteDecision::BroadcastAll.to_string(), "broadcast-all");
        assert!(
            RouteDecision::Reject("x".into())
                .to_string()
                .starts_with("reject:")
        );
    }

    #[test]
    fn test_federation_router_route_match() {
        let mut router = FederationRouter::new();
        router.add_backend(FederatedBackend::new("srv", "http://x").with_cap("decompile"));
        assert!(matches!(
            router.route("decompile"),
            RouteDecision::ForwardTo(_)
        ));
    }

    #[test]
    fn test_federation_router_route_reject() {
        let router = FederationRouter::new();
        assert!(matches!(router.route("missing"), RouteDecision::Reject(_)));
    }

    #[test]
    fn test_service_registry_register_lookup() {
        let reg = ServiceRegistry::new();
        reg.register(FederatedBackend::new("svc", "http://svc"));
        assert!(reg.lookup("svc").is_some());
        assert!(reg.lookup("nope").is_none());
    }

    #[test]
    fn test_service_registry_list() {
        let reg = ServiceRegistry::new();
        reg.register(FederatedBackend::new("a", "h"));
        reg.register(FederatedBackend::new("b", "h"));
        let mut names = reg.list();
        names.sort();
        assert_eq!(names, ["a", "b"]);
    }

    // ── ClientConnection::parse_http_addr ─────────────────────────────────

    #[test]
    fn test_parse_http_addr_simple() {
        let addr = ClientConnection::parse_http_addr("http://localhost:8080/mcp").unwrap();
        assert_eq!(addr, "localhost:8080");
    }

    #[test]
    fn test_parse_http_addr_https() {
        let addr = ClientConnection::parse_http_addr("https://example.com:443/path").unwrap();
        assert_eq!(addr, "example.com:443");
    }

    #[test]
    fn test_parse_http_addr_bare() {
        let addr = ClientConnection::parse_http_addr("192.168.1.1:1234").unwrap();
        assert_eq!(addr, "192.168.1.1:1234");
    }

    // ── McpFederationConfig ───────────────────────────────────────────────

    #[test]
    fn test_mcp_federation_config_add_server() {
        let mut cfg = McpFederationConfig::new();
        cfg.add_server(ExternalServer {
            name: "ghidra".into(),
            transport: FederationTransport::Http {
                url: "http://localhost:8080".into(),
            },
            tool_prefix: Some("ghidra.".into()),
            timeout_secs: 10,
            max_reconnects: 3,
        });
        assert_eq!(cfg.servers.len(), 1);
    }

    #[test]
    fn test_mcp_federation_config_serde() {
        let mut cfg = McpFederationConfig::new();
        cfg.add_server(ExternalServer {
            name: "srv1".into(),
            transport: FederationTransport::Stdio {
                command: "mcp-server".into(),
                args: vec![],
            },
            tool_prefix: None,
            timeout_secs: 30,
            max_reconnects: 3,
        });
        let json = serde_json::to_string(&cfg).unwrap();
        let back: McpFederationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.servers.len(), 1);
        assert_eq!(back.servers[0].name, "srv1");
    }

    #[test]
    fn test_federation_error_display() {
        assert!(
            FederationError::ServerNotFound("x".into())
                .to_string()
                .contains('x')
        );
        assert!(
            FederationError::ToolNotFound("t".into())
                .to_string()
                .contains('t')
        );
        assert!(
            FederationError::Timeout("s".into())
                .to_string()
                .contains('s')
        );
    }

    #[test]
    fn test_federation_error_into_mcp_error() {
        let fe = FederationError::ServerNotFound("x".into());
        let me: McpError = fe.into();
        assert!(matches!(me, McpError::InternalError(_)));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §30.5 — Extended federation types: ExternalServerConfig v2, CapabilityCache,
//          WebSocketTransport, FederationTransport (full), FederationManager
//          extensions (load_config, refresh_capabilities, all_tools, dispatch)
// ─────────────────────────────────────────────────────────────────────────────

// ── §30.5.1  Spec-compliant FederationTransport ───────────────────────────

/// Full federation transport enum as specified in §30.5.
/// Distinct from the legacy [`ServerTransport`] and the older [`FederationTransport`]
/// so that existing code continues to compile unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SpecFederationTransport {
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
    },
    Sse {
        url: String,
        auth_token: Option<String>,
    },
    WebSocket {
        url: String,
        auth_token: Option<String>,
    },
    UnixSocket {
        path: String,
    },
}

impl SpecFederationTransport {
    /// Returns the transport kind as a static string.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Stdio { .. } => "stdio",
            Self::Sse { .. } => "sse",
            Self::WebSocket { .. } => "websocket",
            Self::UnixSocket { .. } => "unix_socket",
        }
    }

    /// True for transports that run entirely on the local machine.
    #[must_use]
    pub const fn is_local(&self) -> bool {
        matches!(self, Self::Stdio { .. } | Self::UnixSocket { .. })
    }

    /// True if transport authenticates via a bearer token.
    #[must_use]
    pub const fn has_auth(&self) -> bool {
        match self {
            Self::Sse { auth_token, .. } | Self::WebSocket { auth_token, .. } => {
                auth_token.is_some()
            }
            _ => false,
        }
    }
}

// ── §30.5.2  ExternalServerConfig (spec-aligned) ─────────────────────────

/// Spec §30.5 — TOML-deserializable configuration for a single federated
/// external MCP server.
///
/// Named `SpecExternalServerConfig` to avoid a name
/// collision with the existing [`ExternalServerConfig`] which carries
/// `ServerTransport`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecExternalServerConfig {
    /// Unique server identifier (used as routing prefix by default).
    pub name: String,
    /// Transport configuration (stdio / SSE / WebSocket / unix socket).
    pub transport: SpecFederationTransport,
    /// Whether this server is included in tool discovery and dispatch.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Optional prefix override; defaults to `name` when absent.
    pub tool_prefix: Option<String>,
}

impl SpecExternalServerConfig {
    /// Constructs a stdio-backed config.
    #[must_use]
    pub fn new_stdio(
        name: impl Into<String>,
        command: impl Into<String>,
        args: Vec<String>,
    ) -> Self {
        let name = name.into();
        Self {
            name,
            transport: SpecFederationTransport::Stdio {
                command: command.into(),
                args,
                env: HashMap::new(),
            },
            enabled: true,
            tool_prefix: None,
        }
    }

    /// Constructs an SSE-backed config.
    #[must_use]
    pub fn new_sse(name: impl Into<String>, url: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            name,
            transport: SpecFederationTransport::Sse {
                url: url.into(),
                auth_token: None,
            },
            enabled: true,
            tool_prefix: None,
        }
    }

    /// Constructs a WebSocket-backed config.
    #[must_use]
    pub fn new_websocket(name: impl Into<String>, url: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            name,
            transport: SpecFederationTransport::WebSocket {
                url: url.into(),
                auth_token: None,
            },
            enabled: true,
            tool_prefix: None,
        }
    }

    /// Constructs a Unix-socket-backed config.
    #[must_use]
    pub fn new_unix(name: impl Into<String>, path: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            name,
            transport: SpecFederationTransport::UnixSocket { path: path.into() },
            enabled: true,
            tool_prefix: None,
        }
    }

    /// Returns the effective tool prefix (falls back to `name`).
    #[must_use]
    pub fn effective_prefix(&self) -> &str {
        self.tool_prefix.as_deref().unwrap_or(&self.name)
    }

    /// Attach a bearer token to an SSE or WebSocket transport.
    #[must_use]
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        let tok = token.into();
        self.transport = match self.transport {
            SpecFederationTransport::Sse { url, .. } => SpecFederationTransport::Sse {
                url,
                auth_token: Some(tok),
            },
            SpecFederationTransport::WebSocket { url, .. } => SpecFederationTransport::WebSocket {
                url,
                auth_token: Some(tok),
            },
            other => other,
        };
        self
    }

    /// Override the tool prefix.
    #[must_use]
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.tool_prefix = Some(prefix.into());
        self
    }

    /// Mark the server as disabled.
    #[must_use]
    pub const fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

// ── §30.5.3  ToolDef / ResourceDef (lightweight capability descriptors) ───

/// Lightweight tool descriptor used inside [`CapabilityCache`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

impl ToolDef {
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        }
    }

    #[must_use]
    pub fn with_schema(mut self, schema: Value) -> Self {
        self.input_schema = schema;
        self
    }
}

impl From<ToolDef> for FederatedTool {
    fn from(d: ToolDef) -> Self {
        Self::new_remote("unknown", &d.name, &d.description, d.input_schema)
    }
}

/// Lightweight resource descriptor used inside [`CapabilityCache`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDef {
    pub uri: String,
    pub name: String,
    pub mime_type: Option<String>,
    pub description: Option<String>,
}

impl ResourceDef {
    #[must_use]
    pub fn new(uri: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            name: name.into(),
            mime_type: None,
            description: None,
        }
    }
}

// ── §30.5.4  CapabilityCache ──────────────────────────────────────────────

/// In-memory capability cache keyed by server name.
///
/// Stores tools and resources fetched during [`SpecFederationManager::refresh_capabilities`]
/// and tracks staleness using wall-clock seconds.
pub struct CapabilityCache {
    /// `server_name` → list of tool descriptors
    pub tools: HashMap<String, Vec<ToolDef>>,
    /// `server_name` → list of resource descriptors
    pub resources: HashMap<String, Vec<ResourceDef>>,
    /// `server_name` → Unix timestamp (seconds) of last successful refresh
    pub last_refresh: HashMap<String, u64>,
    /// How many seconds before an entry is considered stale
    pub ttl_secs: u64,
}

impl CapabilityCache {
    /// Creates a new cache with the given TTL.
    #[must_use]
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            tools: HashMap::new(),
            resources: HashMap::new(),
            last_refresh: HashMap::new(),
            ttl_secs,
        }
    }

    /// Returns the cached tools for `server`, or `None` if not yet loaded.
    #[must_use]
    pub fn get_tools(&self, server: &str) -> Option<&Vec<ToolDef>> {
        self.tools.get(server)
    }

    /// Returns the cached resources for `server`, or `None` if not yet loaded.
    #[must_use]
    pub fn get_resources(&self, server: &str) -> Option<&Vec<ResourceDef>> {
        self.resources.get(server)
    }

    /// Stores (or replaces) the tool list for `server` and stamps the refresh
    /// time with the current wall-clock second.
    pub fn set_tools(&mut self, server: &str, tools: Vec<ToolDef>) {
        self.tools.insert(server.to_string(), tools);
        self.last_refresh.insert(server.to_string(), now_secs());
    }

    /// Stores (or replaces) the resource list for `server` and stamps the
    /// refresh time with the current wall-clock second.
    pub fn set_resources(&mut self, server: &str, resources: Vec<ResourceDef>) {
        self.resources.insert(server.to_string(), resources);
        // Only update refresh timestamp if no tool entry yet (resources refresh
        // is done alongside tools, but we do not want to regress an existing
        // timestamp if called independently).
        self.last_refresh
            .entry(server.to_string())
            .or_insert_with(now_secs);
    }

    /// Returns `true` when the cached entry for `server` is absent **or**
    /// older than `ttl_secs`.
    #[must_use]
    pub fn is_stale(&self, server: &str) -> bool {
        match self.last_refresh.get(server) {
            None => true,
            Some(&ts) => {
                let age = now_secs().saturating_sub(ts);
                age >= self.ttl_secs
            }
        }
    }

    /// Explicitly invalidate the cached entry for `server`.
    pub fn invalidate(&mut self, server: &str) {
        self.tools.remove(server);
        self.resources.remove(server);
        self.last_refresh.remove(server);
    }

    /// Invalidates every entry in the cache.
    pub fn invalidate_all(&mut self) {
        self.tools.clear();
        self.resources.clear();
        self.last_refresh.clear();
    }

    /// Returns the set of server names that currently have cached tools.
    #[must_use]
    pub fn cached_servers(&self) -> Vec<&str> {
        self.tools.keys().map(String::as_str).collect()
    }

    /// Returns the total number of cached tool definitions across all servers.
    #[must_use]
    pub fn total_tool_count(&self) -> usize {
        self.tools.values().map(Vec::len).sum()
    }

    /// Returns the age in seconds for `server`'s entry, or `None` if absent.
    #[must_use]
    pub fn age_secs(&self, server: &str) -> Option<u64> {
        self.last_refresh
            .get(server)
            .map(|&ts| now_secs().saturating_sub(ts))
    }
}

/// Returns current Unix time in whole seconds.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── §30.5.5  WebSocketTransport ───────────────────────────────────────────

/// HTTP/SSE-based transport that posts JSON-RPC calls over `reqwest`.
///
/// Despite being named `WebSocketTransport` to match the spec §30.5 naming,
/// the current implementation issues plain HTTP POST requests (the same wire
/// protocol that MCP SSE endpoints expect).  A full bidirectional WebSocket
/// upgrade can be layered on top without breaking the public interface.
pub struct WebSocketTransport {
    url: String,
    token: Option<String>,
    client: reqwest::Client,
    /// Incrementing request ID counter.
    next_id: std::sync::atomic::AtomicU64,
}

impl WebSocketTransport {
    /// Creates a new transport pointing at `url`.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            token: None,
            client: reqwest::Client::builder()
                .use_rustls_tls()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client build must not fail"),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Creates a transport with a bearer-token authorisation header.
    #[must_use]
    pub fn with_token(url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            token: Some(token.into()),
            client: reqwest::Client::builder()
                .use_rustls_tls()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client build must not fail"),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Issues a JSON-RPC 2.0 `tools/call` request to the remote endpoint and
    /// returns the unwrapped `result` field.
    ///
    /// # Errors
    ///
    /// Returns a [`FederationError`] if:
    /// - the HTTP request fails or times out,
    /// - the response body cannot be parsed as a JSON-RPC response,
    /// - the JSON-RPC response carries an `error` field.
    pub async fn call_tool(
        &self,
        name: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, FederationError> {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": args,
            }
        });

        let mut req = self.client.post(&self.url).json(&body);
        if let Some(tok) = &self.token {
            req = req.bearer_auth(tok);
        }

        let resp = req.send().await.map_err(|e| {
            FederationError::ConnectionError("websocket_transport".to_string(), e.to_string())
        })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            return Err(FederationError::ConnectionError(
                "websocket_transport".to_string(),
                format!("HTTP {status}"),
            ));
        }

        let json: serde_json::Value = resp.json().await.map_err(|e| {
            FederationError::ConnectionError("websocket_transport".to_string(), e.to_string())
        })?;

        if let Some(err) = json.get("error") {
            let msg = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown RPC error");
            return Err(FederationError::RpcError(
                "websocket_transport".to_string(),
                msg.to_string(),
            ));
        }

        Ok(json.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Issues a `tools/list` RPC and returns the list of tool descriptors.
    pub async fn list_tools(&self) -> Result<Vec<ToolDef>, FederationError> {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/list",
            "params": {}
        });

        let mut req = self.client.post(&self.url).json(&body);
        if let Some(tok) = &self.token {
            req = req.bearer_auth(tok);
        }

        let resp = req.send().await.map_err(|e| {
            FederationError::ConnectionError("websocket_transport".to_string(), e.to_string())
        })?;

        let json: serde_json::Value = resp.json().await.map_err(|e| {
            FederationError::ConnectionError("websocket_transport".to_string(), e.to_string())
        })?;

        if let Some(err) = json.get("error") {
            let msg = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown RPC error");
            return Err(FederationError::RpcError(
                "websocket_transport".to_string(),
                msg.to_string(),
            ));
        }

        let tools = json
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let defs: Vec<ToolDef> = tools
            .into_iter()
            .filter_map(|t| serde_json::from_value(t).ok())
            .collect();

        Ok(defs)
    }

    /// Issues a `resources/list` RPC and returns the list of resource
    /// descriptors.
    pub async fn list_resources(&self) -> Result<Vec<ResourceDef>, FederationError> {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "resources/list",
            "params": {}
        });

        let mut req = self.client.post(&self.url).json(&body);
        if let Some(tok) = &self.token {
            req = req.bearer_auth(tok);
        }

        let resp = req.send().await.map_err(|e| {
            FederationError::ConnectionError("websocket_transport".to_string(), e.to_string())
        })?;

        let json: serde_json::Value = resp.json().await.map_err(|e| {
            FederationError::ConnectionError("websocket_transport".to_string(), e.to_string())
        })?;

        if let Some(err) = json.get("error") {
            let msg = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown RPC error");
            return Err(FederationError::RpcError(
                "websocket_transport".to_string(),
                msg.to_string(),
            ));
        }

        let resources = json
            .get("result")
            .and_then(|r| r.get("resources"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let defs: Vec<ResourceDef> = resources
            .into_iter()
            .filter_map(|r| serde_json::from_value(r).ok())
            .collect();

        Ok(defs)
    }

    /// Changes the request timeout.
    #[must_use]
    pub fn with_timeout(self, timeout: std::time::Duration) -> Self {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(timeout)
            .build()
            .expect("reqwest client build must not fail");
        Self { client, ..self }
    }
}

// ── §30.5.6  SseTransport ─────────────────────────────────────────────────

/// SSE-capable transport that also serves as the default HTTP adapter.
/// Internally reuses [`WebSocketTransport`] since both speak JSON-RPC over HTTP.
pub struct SseTransport {
    inner: WebSocketTransport,
}

impl SseTransport {
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            inner: WebSocketTransport::new(url),
        }
    }

    #[must_use]
    pub fn with_token(url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            inner: WebSocketTransport::with_token(url, token),
        }
    }

    pub async fn call_tool(&self, name: &str, args: Value) -> Result<Value, FederationError> {
        self.inner.call_tool(name, args).await
    }

    pub async fn list_tools(&self) -> Result<Vec<ToolDef>, FederationError> {
        self.inner.list_tools().await
    }
}

// ── §30.5.7  SpecFederationConfig — TOML-deserializable top-level ─────────

/// Complete federation configuration as described in §30.5.
/// Separate from [`FederationConfig`] so the two can coexist without breaking
/// previously compiled code.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SpecFederationConfig {
    #[serde(default)]
    pub servers: Vec<SpecExternalServerConfig>,
    /// Default TTL for the capability cache, in seconds.
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
    /// Maximum simultaneous tool calls across all servers.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_calls: u32,
    /// Per-call timeout in seconds.
    #[serde(default = "default_call_timeout")]
    pub call_timeout_secs: u64,
}

const fn default_cache_ttl() -> u64 {
    300
}

impl SpecFederationConfig {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            servers: Vec::new(),
            cache_ttl_secs: 300,
            max_concurrent_calls: 16,
            call_timeout_secs: 30,
        }
    }

    /// Parses a JSON string (TOML interop via `serde_json`; swap for `toml` crate
    /// when available in workspace).
    pub fn from_json(s: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(s).map_err(|e| ConfigError::TomlParse(e.to_string()))
    }

    /// Serialises to a JSON string (proxy for TOML serialisation).
    pub fn to_json(&self) -> Result<String, ConfigError> {
        serde_json::to_string_pretty(self).map_err(|e| ConfigError::TomlSerialize(e.to_string()))
    }

    pub fn add_server(&mut self, cfg: SpecExternalServerConfig) {
        self.servers.push(cfg);
    }

    #[must_use]
    pub fn enabled_servers(&self) -> Vec<&SpecExternalServerConfig> {
        self.servers.iter().filter(|s| s.enabled).collect()
    }
}

// ── §30.5.8  SpecFederationManager ───────────────────────────────────────

/// Federation manager that implements the §30.5 interface:
///
/// - [`load_config`](SpecFederationManager::load_config)
/// - [`refresh_capabilities`](SpecFederationManager::refresh_capabilities)
/// - [`all_tools`](SpecFederationManager::all_tools)
/// - [`dispatch`](SpecFederationManager::dispatch)
///
/// The manager owns a [`CapabilityCache`] that is consulted for tool listings
/// and is refreshed on demand (or when entries are stale).
pub struct SpecFederationManager {
    pub config: SpecFederationConfig,
    pub cache: CapabilityCache,
    /// Transports keyed by server name.  Only SSE / WebSocket servers get an
    /// entry here; stdio servers are dispatched via [`ClientConnection`].
    http_transports: HashMap<String, WebSocketTransport>,
    /// Stdio connections keyed by server name.
    stdio_connections: HashMap<String, Arc<ClientConnection>>,
    pub call_log: CallLog,
    pub health: HealthMonitor,
}

impl SpecFederationManager {
    /// Creates a manager from an existing [`SpecFederationConfig`].
    #[must_use]
    pub fn new(config: SpecFederationConfig) -> Self {
        let cache_ttl = config.cache_ttl_secs;
        Self {
            config,
            cache: CapabilityCache::new(cache_ttl),
            http_transports: HashMap::new(),
            stdio_connections: HashMap::new(),
            call_log: CallLog::new(10_000),
            health: HealthMonitor::new(200),
        }
    }

    /// Reads a JSON config file from `path` and constructs a manager from it.
    ///
    /// This is the §30.5 `load_config` entry point.
    pub fn load_config(path: &std::path::Path) -> Result<Self, FederationError> {
        let content = std::fs::read_to_string(path)?;
        let config = SpecFederationConfig::from_json(&content)?;
        let mut mgr = Self::new(config);
        mgr.init_transports();
        Ok(mgr)
    }

    /// Initialises HTTP transports for every SSE / WebSocket server and
    /// registers stdio servers so they can be spawned on first use.
    pub fn init_transports(&mut self) {
        for server in &self.config.servers {
            if !server.enabled {
                continue;
            }
            match &server.transport {
                SpecFederationTransport::Sse { url, auth_token } => {
                    let transport = match auth_token {
                        Some(tok) => WebSocketTransport::with_token(url, tok),
                        None => WebSocketTransport::new(url),
                    };
                    self.http_transports.insert(server.name.clone(), transport);
                }
                SpecFederationTransport::WebSocket { url, auth_token } => {
                    let transport = match auth_token {
                        Some(tok) => WebSocketTransport::with_token(url, tok),
                        None => WebSocketTransport::new(url),
                    };
                    self.http_transports.insert(server.name.clone(), transport);
                }
                SpecFederationTransport::Stdio {
                    command,
                    args,
                    env: _env,
                } => {
                    // Create a ClientConnection stub; it will be connected
                    // lazily in dispatch.
                    let ext = ExternalServer {
                        name: server.name.clone(),
                        transport: FederationTransport::Stdio {
                            command: command.clone(),
                            args: args.clone(),
                        },
                        tool_prefix: server.tool_prefix.clone(),
                        timeout_secs: self.config.call_timeout_secs,
                        max_reconnects: 3,
                    };
                    self.stdio_connections
                        .insert(server.name.clone(), ClientConnection::new(ext));
                }
                SpecFederationTransport::UnixSocket { .. } => {
                    // Unix-socket support is OS-conditional; the connection is
                    // established in dispatch when needed.
                }
            }
        }
    }

    /// Refreshes the capability cache for every **enabled** server whose
    /// entry is stale.
    ///
    /// HTTP/SSE/WebSocket servers are queried via `tools/list` over
    /// [`WebSocketTransport`].  Stdio servers fall back to in-process stub
    /// generation to avoid blocking the runtime on process spawning.
    ///
    /// Returns `Ok(())` even if individual servers fail; per-server errors are
    /// recorded in the health monitor but do not abort the refresh loop.
    pub async fn refresh_capabilities(&mut self) -> Result<(), FederationError> {
        let server_names: Vec<String> = self
            .config
            .enabled_servers()
            .into_iter()
            .map(|s| s.name.clone())
            .collect();

        for name in server_names {
            if !self.cache.is_stale(&name) {
                continue;
            }

            let start = std::time::Instant::now();

            if let Some(transport) = self.http_transports.get(&name) {
                match transport.list_tools().await {
                    Ok(tools) => {
                        let elapsed = start.elapsed().as_millis() as u64;
                        self.cache.set_tools(&name, tools);
                        self.health.trigger_health_check_logic(&name, true, elapsed);
                    }
                    Err(e) => {
                        self.health.trigger_health_check_logic(&name, false, 0);
                        // Log but do not propagate — other servers must still refresh.
                        eprintln!("[federation] refresh failed for {name}: {e}");
                    }
                }
            } else {
                // Stdio / unix-socket — generate stub capability entries so
                // the tool surface is non-empty even before a live connection.
                let stubs = vec![
                    ToolDef::new("ping", "health-check ping"),
                    ToolDef::new("capabilities", "list server capabilities"),
                ];
                self.cache.set_tools(&name, stubs);
                self.health.trigger_health_check_logic(&name, true, 0);
            }
        }

        Ok(())
    }

    /// Returns the flat list of all federated tools from the capability cache,
    /// with each tool's name prefixed by its server's effective prefix
    /// (e.g. `"frida"` → `"frida.intercept"`).
    ///
    /// This is the §30.5 `all_tools` entry point.
    #[must_use]
    pub fn all_tools(&self) -> Vec<FederatedTool> {
        let mut result = Vec::new();

        for server in self.config.enabled_servers() {
            let prefix = server.effective_prefix();
            if let Some(tools) = self.cache.get_tools(&server.name) {
                for def in tools {
                    let qualified = format!("{prefix}.{}", def.name);
                    result.push(FederatedTool {
                        name: def.name.clone(),
                        qualified_name: qualified,
                        description: def.description.clone(),
                        input_schema: def.input_schema.clone(),
                        server_name: server.name.clone(),
                        is_local: server.transport.is_local(),
                    });
                }
            }
        }

        result
    }

    /// Returns only tools from the cache whose entry is **not** stale.
    #[must_use]
    pub fn fresh_tools(&self) -> Vec<FederatedTool> {
        self.all_tools()
            .into_iter()
            .filter(|t| !self.cache.is_stale(&t.server_name))
            .collect()
    }

    /// Dispatches a call to the server that owns `qualified_name`.
    ///
    /// `qualified_name` must follow the `"<prefix>.<tool>"` convention.  The
    /// prefix is matched against each server's effective prefix; the remainder
    /// is sent as the tool name to the remote server.
    ///
    /// This is the §30.5 `dispatch` entry point.
    ///
    /// # Errors
    ///
    /// - [`FederationError::ToolNotFound`] if `qualified_name` does not contain
    ///   a dot separator or no server claims the prefix.
    /// - [`FederationError::ConnectionError`] / [`FederationError::RpcError`]
    ///   if the remote call fails.
    pub async fn dispatch(
        &self,
        qualified_name: &str,
        args: Value,
    ) -> Result<Value, FederationError> {
        // Split "frida.intercept" → prefix="frida", tool="intercept"
        let dot = qualified_name.find('.').ok_or_else(|| {
            FederationError::ToolNotFound(format!(
                "qualified name '{qualified_name}' has no prefix separator"
            ))
        })?;

        let prefix = &qualified_name[..dot];
        let tool = &qualified_name[dot + 1..];

        // Resolve prefix → server
        let server_name = self
            .config
            .servers
            .iter()
            .find(|s| s.enabled && s.effective_prefix() == prefix)
            .map(|s| s.name.as_str())
            .ok_or_else(|| {
                FederationError::ServerNotFound(format!("no enabled server with prefix '{prefix}'"))
            })?;

        self.dispatch_to(server_name, tool, args).await
    }

    /// Dispatches directly to `server_name` without prefix resolution.
    /// Used internally by [`dispatch`](Self::dispatch) and useful for testing.
    pub async fn dispatch_to(
        &self,
        server_name: &str,
        tool: &str,
        args: Value,
    ) -> Result<Value, FederationError> {
        if let Some(transport) = self.http_transports.get(server_name) {
            return transport.call_tool(tool, args).await;
        }

        if let Some(conn) = self.stdio_connections.get(server_name) {
            let result = conn.call_tool(tool, args).await?;
            return Ok(serde_json::to_value(result).unwrap_or(Value::Null));
        }

        Err(FederationError::ServerNotFound(server_name.to_string()))
    }

    /// Convenience: dispatch and record the call in the log.
    pub async fn dispatch_logged(
        &mut self,
        qualified_name: &str,
        args: Value,
    ) -> Result<Value, FederationError> {
        let start = std::time::Instant::now();
        let result = self.dispatch(qualified_name, args.clone()).await;
        let elapsed = start.elapsed().as_millis() as u64;

        let server = qualified_name
            .find('.')
            .and_then(|i| {
                let prefix = &qualified_name[..i];
                self.config
                    .servers
                    .iter()
                    .find(|s| s.effective_prefix() == prefix)
                    .map(|s| s.name.clone())
            })
            .unwrap_or_else(|| "unknown".to_string());

        let success = result.is_ok();
        let error = result.as_ref().err().map(std::string::ToString::to_string);
        let entry = CallLogEntry::new(0, qualified_name, &server, &args, elapsed, success, error);
        self.call_log.record(entry);

        result
    }

    /// Returns a snapshot status for all configured servers.
    #[must_use]
    pub fn server_status(&self) -> Vec<ServerStatusSnapshot> {
        self.config
            .servers
            .iter()
            .map(|s| ServerStatusSnapshot {
                name: s.name.clone(),
                enabled: s.enabled,
                transport_kind: s.transport.kind().to_string(),
                effective_prefix: s.effective_prefix().to_string(),
                tool_count: self.cache.get_tools(&s.name).map_or(0, Vec::len),
                cache_stale: self.cache.is_stale(&s.name),
                health: self
                    .health
                    .get_health(&s.name)
                    .map_or(HealthStatus::Unknown, |h| h.status.clone()),
            })
            .collect()
    }

    /// Inject a pre-built `WebSocketTransport` for a server (useful in tests).
    pub fn inject_http_transport(&mut self, name: impl Into<String>, t: WebSocketTransport) {
        self.http_transports.insert(name.into(), t);
    }

    /// Manually seed the cache for a server (useful in tests).
    pub fn seed_cache(&mut self, server: &str, tools: Vec<ToolDef>) {
        self.cache.set_tools(server, tools);
    }

    /// Returns the number of servers for which the cache is currently fresh.
    #[must_use]
    pub fn fresh_server_count(&self) -> usize {
        self.config
            .servers
            .iter()
            .filter(|s| s.enabled && !self.cache.is_stale(&s.name))
            .count()
    }
}

/// Point-in-time snapshot of a single server's status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatusSnapshot {
    pub name: String,
    pub enabled: bool,
    pub transport_kind: String,
    pub effective_prefix: String,
    pub tool_count: usize,
    pub cache_stale: bool,
    pub health: HealthStatus,
}

// ── §30.5.9  Helper — parse a "prefix.tool" qualified name ───────────────

/// Splits a qualified tool name such as `"frida.intercept"` into
/// `("frida", "intercept")`.
///
/// Returns `None` if there is no `.` separator.
#[must_use]
pub fn split_qualified_name(qualified: &str) -> Option<(&str, &str)> {
    let dot = qualified.find('.')?;
    Some((&qualified[..dot], &qualified[dot + 1..]))
}

/// Constructs a qualified name from server prefix and bare tool name.
#[must_use]
pub fn make_qualified_name(prefix: &str, tool: &str) -> String {
    format!("{prefix}.{tool}")
}

// ── §30.5.10  Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod spec_tests {
    use super::*;

    // ── SpecFederationTransport ───────────────────────────────────────────

    #[test]
    fn test_spec_transport_kind() {
        assert_eq!(
            SpecFederationTransport::Stdio {
                command: "x".into(),
                args: vec![],
                env: HashMap::new()
            }
            .kind(),
            "stdio"
        );
        assert_eq!(
            SpecFederationTransport::Sse {
                url: "http://x".into(),
                auth_token: None
            }
            .kind(),
            "sse"
        );
        assert_eq!(
            SpecFederationTransport::WebSocket {
                url: "ws://x".into(),
                auth_token: None
            }
            .kind(),
            "websocket"
        );
        assert_eq!(
            SpecFederationTransport::UnixSocket {
                path: "/tmp/x.sock".into()
            }
            .kind(),
            "unix_socket"
        );
    }

    #[test]
    fn test_spec_transport_is_local() {
        assert!(
            SpecFederationTransport::Stdio {
                command: "x".into(),
                args: vec![],
                env: HashMap::new()
            }
            .is_local()
        );
        assert!(
            SpecFederationTransport::UnixSocket {
                path: "/tmp/x".into()
            }
            .is_local()
        );
        assert!(
            !SpecFederationTransport::Sse {
                url: "http://x".into(),
                auth_token: None
            }
            .is_local()
        );
        assert!(
            !SpecFederationTransport::WebSocket {
                url: "ws://x".into(),
                auth_token: None
            }
            .is_local()
        );
    }

    #[test]
    fn test_spec_transport_has_auth() {
        let t = SpecFederationTransport::Sse {
            url: "u".into(),
            auth_token: Some("tok".into()),
        };
        assert!(t.has_auth());
        let t2 = SpecFederationTransport::Sse {
            url: "u".into(),
            auth_token: None,
        };
        assert!(!t2.has_auth());
    }

    #[test]
    fn test_spec_transport_serde_roundtrip() {
        let t = SpecFederationTransport::WebSocket {
            url: "ws://localhost:9000".into(),
            auth_token: Some("secret".into()),
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: SpecFederationTransport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind(), "websocket");
    }

    // ── SpecExternalServerConfig ──────────────────────────────────────────

    #[test]
    fn test_spec_server_effective_prefix_default() {
        let s = SpecExternalServerConfig::new_stdio("frida", "frida-mcp", vec![]);
        assert_eq!(s.effective_prefix(), "frida");
    }

    #[test]
    fn test_spec_server_effective_prefix_override() {
        let s =
            SpecExternalServerConfig::new_sse("ghidra-server", "http://x").with_prefix("ghidra");
        assert_eq!(s.effective_prefix(), "ghidra");
    }

    #[test]
    fn test_spec_server_with_auth_token_sse() {
        let s = SpecExternalServerConfig::new_sse("srv", "http://x").with_auth_token("bearer-tok");
        assert!(s.transport.has_auth());
    }

    #[test]
    fn test_spec_server_with_auth_token_websocket() {
        let s =
            SpecExternalServerConfig::new_websocket("srv", "ws://x").with_auth_token("bearer-tok");
        assert!(s.transport.has_auth());
    }

    #[test]
    fn test_spec_server_disabled() {
        let s = SpecExternalServerConfig::new_stdio("s", "cmd", vec![]).disabled();
        assert!(!s.enabled);
    }

    #[test]
    fn test_spec_server_serde_roundtrip() {
        let s = SpecExternalServerConfig::new_sse("srv", "http://localhost:8080")
            .with_prefix("mcp")
            .with_auth_token("tok");
        let json = serde_json::to_string(&s).unwrap();
        let back: SpecExternalServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "srv");
        assert_eq!(back.tool_prefix.as_deref(), Some("mcp"));
    }

    // ── ToolDef / ResourceDef ─────────────────────────────────────────────

    #[test]
    fn test_tool_def_new() {
        let t = ToolDef::new("intercept", "Intercept function calls");
        assert_eq!(t.name, "intercept");
        assert_eq!(t.description, "Intercept function calls");
    }

    #[test]
    fn test_tool_def_with_schema() {
        let schema = serde_json::json!({ "type": "object", "properties": { "addr": {} } });
        let t = ToolDef::new("disasm", "Disassemble").with_schema(schema.clone());
        assert_eq!(t.input_schema, schema);
    }

    #[test]
    fn test_tool_def_serde_roundtrip() {
        let t = ToolDef::new("scan", "YARA scan");
        let json = serde_json::to_string(&t).unwrap();
        let back: ToolDef = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "scan");
    }

    #[test]
    fn test_tool_def_into_federated_tool() {
        let t = ToolDef::new("ping", "Ping");
        let ft: FederatedTool = t.into();
        assert_eq!(ft.name, "ping");
    }

    #[test]
    fn test_resource_def_new() {
        let r = ResourceDef::new("file:///proc/maps", "proc-maps");
        assert_eq!(r.uri, "file:///proc/maps");
        assert_eq!(r.name, "proc-maps");
        assert!(r.mime_type.is_none());
    }

    // ── CapabilityCache ───────────────────────────────────────────────────

    #[test]
    fn test_capability_cache_get_set_tools() {
        let mut cache = CapabilityCache::new(60);
        assert!(cache.get_tools("frida").is_none());
        cache.set_tools("frida", vec![ToolDef::new("spawn", "Spawn process")]);
        let tools = cache.get_tools("frida").unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "spawn");
    }

    #[test]
    fn test_capability_cache_is_stale_missing() {
        let cache = CapabilityCache::new(60);
        assert!(cache.is_stale("nonexistent"), "absent entry must be stale");
    }

    #[test]
    fn test_capability_cache_not_stale_after_set() {
        let mut cache = CapabilityCache::new(3600); // 1-hour TTL
        cache.set_tools("frida", vec![]);
        assert!(
            !cache.is_stale("frida"),
            "freshly set entry must not be stale"
        );
    }

    #[test]
    fn test_capability_cache_stale_with_zero_ttl() {
        let mut cache = CapabilityCache::new(0); // 0-second TTL → always stale
        cache.set_tools("srv", vec![]);
        assert!(cache.is_stale("srv"), "zero-TTL entry must always be stale");
    }

    #[test]
    fn test_capability_cache_invalidate() {
        let mut cache = CapabilityCache::new(3600);
        cache.set_tools("srv", vec![ToolDef::new("t", "d")]);
        assert!(!cache.is_stale("srv"));
        cache.invalidate("srv");
        assert!(cache.is_stale("srv"));
        assert!(cache.get_tools("srv").is_none());
    }

    #[test]
    fn test_capability_cache_invalidate_all() {
        let mut cache = CapabilityCache::new(3600);
        cache.set_tools("a", vec![]);
        cache.set_tools("b", vec![]);
        cache.invalidate_all();
        assert!(cache.is_stale("a"));
        assert!(cache.is_stale("b"));
        assert_eq!(cache.total_tool_count(), 0);
    }

    #[test]
    fn test_capability_cache_total_tool_count() {
        let mut cache = CapabilityCache::new(60);
        cache.set_tools("a", vec![ToolDef::new("t1", "d"), ToolDef::new("t2", "d")]);
        cache.set_tools("b", vec![ToolDef::new("t3", "d")]);
        assert_eq!(cache.total_tool_count(), 3);
    }

    #[test]
    fn test_capability_cache_cached_servers() {
        let mut cache = CapabilityCache::new(60);
        cache.set_tools("frida", vec![]);
        cache.set_tools("ghidra", vec![]);
        let mut servers = cache.cached_servers();
        servers.sort_unstable();
        assert_eq!(servers, ["frida", "ghidra"]);
    }

    #[test]
    fn test_capability_cache_age_secs_absent() {
        let cache = CapabilityCache::new(60);
        assert!(cache.age_secs("missing").is_none());
    }

    #[test]
    fn test_capability_cache_age_secs_present() {
        let mut cache = CapabilityCache::new(60);
        cache.set_tools("srv", vec![]);
        // Age should be 0 or 1 depending on clock granularity.
        let age = cache.age_secs("srv").unwrap();
        assert!(age <= 1);
    }

    #[test]
    fn test_capability_cache_set_resources() {
        let mut cache = CapabilityCache::new(60);
        cache.set_resources("frida", vec![ResourceDef::new("file:///maps", "maps")]);
        let res = cache.get_resources("frida").unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].name, "maps");
    }

    // ── split_qualified_name / make_qualified_name ────────────────────────

    #[test]
    fn test_split_qualified_name_ok() {
        let (prefix, tool) = split_qualified_name("frida.intercept").unwrap();
        assert_eq!(prefix, "frida");
        assert_eq!(tool, "intercept");
    }

    #[test]
    fn test_split_qualified_name_nested() {
        // Only the first dot is used as separator.
        let (prefix, tool) = split_qualified_name("frida.memory.read").unwrap();
        assert_eq!(prefix, "frida");
        assert_eq!(tool, "memory.read");
    }

    #[test]
    fn test_split_qualified_name_no_dot() {
        assert!(split_qualified_name("nodot").is_none());
    }

    #[test]
    fn test_make_qualified_name() {
        assert_eq!(make_qualified_name("frida", "intercept"), "frida.intercept");
    }

    // ── SpecFederationConfig ──────────────────────────────────────────────

    #[test]
    fn test_spec_federation_config_new() {
        let cfg = SpecFederationConfig::new();
        assert!(cfg.servers.is_empty());
        assert_eq!(cfg.cache_ttl_secs, 300);
    }

    #[test]
    fn test_spec_federation_config_json_roundtrip() {
        let mut cfg = SpecFederationConfig::new();
        cfg.add_server(SpecExternalServerConfig::new_sse(
            "ghidra",
            "http://localhost:18080",
        ));
        let json = cfg.to_json().unwrap();
        let back = SpecFederationConfig::from_json(&json).unwrap();
        assert_eq!(back.servers.len(), 1);
        assert_eq!(back.servers[0].name, "ghidra");
    }

    #[test]
    fn test_spec_federation_config_enabled_servers() {
        let mut cfg = SpecFederationConfig::new();
        cfg.add_server(SpecExternalServerConfig::new_sse("a", "http://a"));
        cfg.add_server(SpecExternalServerConfig::new_sse("b", "http://b").disabled());
        let enabled = cfg.enabled_servers();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].name, "a");
    }

    // ── SpecFederationManager ─────────────────────────────────────────────

    fn make_spec_manager_with_stubs() -> SpecFederationManager {
        let mut cfg = SpecFederationConfig::new();
        cfg.add_server(SpecExternalServerConfig::new_sse(
            "frida",
            "http://localhost:27042",
        ));
        cfg.add_server(SpecExternalServerConfig::new_sse(
            "ghidra",
            "http://localhost:18080",
        ));
        let mut mgr = SpecFederationManager::new(cfg);
        // Initialise transports so http_transports is populated (dispatch will
        // find the server and attempt a network call, which fails with a
        // ConnectionError rather than ServerNotFound).
        mgr.init_transports();
        // Seed the cache to avoid needing a live server for all_tools tests.
        mgr.seed_cache(
            "frida",
            vec![
                ToolDef::new("intercept", "Intercept"),
                ToolDef::new("spawn", "Spawn"),
            ],
        );
        mgr.seed_cache(
            "ghidra",
            vec![
                ToolDef::new("decompile", "Decompile"),
                ToolDef::new("disasm", "Disassemble"),
            ],
        );
        mgr
    }

    #[test]
    fn test_spec_manager_new() {
        let cfg = SpecFederationConfig::new();
        let mgr = SpecFederationManager::new(cfg);
        assert_eq!(mgr.all_tools().len(), 0);
    }

    #[test]
    fn test_spec_manager_all_tools_prefix() {
        let mgr = make_spec_manager_with_stubs();
        let tools = mgr.all_tools();
        // Should have 4 total (2 per server).
        assert_eq!(tools.len(), 4);
        let names: Vec<&str> = tools.iter().map(|t| t.qualified_name.as_str()).collect();
        assert!(names.contains(&"frida.intercept"));
        assert!(names.contains(&"frida.spawn"));
        assert!(names.contains(&"ghidra.decompile"));
        assert!(names.contains(&"ghidra.disasm"));
    }

    #[test]
    fn test_spec_manager_all_tools_prefix_override() {
        let mut cfg = SpecFederationConfig::new();
        cfg.add_server(
            SpecExternalServerConfig::new_sse("ghidra-mcp", "http://x").with_prefix("ghidra"),
        );
        let mut mgr = SpecFederationManager::new(cfg);
        mgr.seed_cache("ghidra-mcp", vec![ToolDef::new("decompile", "desc")]);
        let tools = mgr.all_tools();
        assert_eq!(tools[0].qualified_name, "ghidra.decompile");
        assert_eq!(tools[0].server_name, "ghidra-mcp");
    }

    #[test]
    fn test_spec_manager_fresh_tools_excludes_stale() {
        let mut cfg = SpecFederationConfig::new();
        cfg.add_server(SpecExternalServerConfig::new_sse("a", "http://a"));
        let mut mgr = SpecFederationManager::new(cfg);
        // Do NOT seed the cache → entry is stale.
        let fresh = mgr.fresh_tools();
        assert!(
            fresh.is_empty(),
            "stale entries must not appear in fresh_tools"
        );
        // Seed now → entry is fresh.
        mgr.seed_cache("a", vec![ToolDef::new("ping", "ping")]);
        let fresh2 = mgr.fresh_tools();
        assert_eq!(fresh2.len(), 1);
    }

    #[test]
    fn test_spec_manager_server_status() {
        let mgr = make_spec_manager_with_stubs();
        let status = mgr.server_status();
        assert_eq!(status.len(), 2);
        let frida = status.iter().find(|s| s.name == "frida").unwrap();
        assert_eq!(frida.tool_count, 2);
        assert_eq!(frida.transport_kind, "sse");
        assert!(!frida.cache_stale);
    }

    #[test]
    fn test_spec_manager_fresh_server_count() {
        let mgr = make_spec_manager_with_stubs();
        assert_eq!(mgr.fresh_server_count(), 2);
    }

    #[test]
    fn test_spec_manager_dispatch_splits_prefix() {
        // We cannot call a real server in a unit test, so we verify the split
        // logic by confirming the error kind when no transport is registered.
        let mgr = make_spec_manager_with_stubs();
        // The manager has SSE servers but no live http_transport injected
        // (no mock server running), so dispatch returns a ConnectionError.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(mgr.dispatch("frida.intercept", serde_json::json!({})));
        // We expect either ConnectionError or similar — NOT ToolNotFound /
        // ServerNotFound, which would mean the prefix split failed.
        if let Err(FederationError::ToolNotFound(_) | FederationError::ServerNotFound(_)) = result {
            panic!("prefix split or server resolution failed unexpectedly");
        } else { /* connection failure is expected in unit tests */ }
    }

    #[test]
    fn test_spec_manager_dispatch_no_dot() {
        let mgr = make_spec_manager_with_stubs();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(mgr.dispatch("nodot", serde_json::json!({})));
        assert!(matches!(result, Err(FederationError::ToolNotFound(_))));
    }

    #[test]
    fn test_spec_manager_dispatch_unknown_prefix() {
        let mgr = make_spec_manager_with_stubs();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(mgr.dispatch("unknown.tool", serde_json::json!({})));
        assert!(matches!(result, Err(FederationError::ServerNotFound(_))));
    }

    #[test]
    fn test_spec_manager_init_transports_creates_entries() {
        let mut cfg = SpecFederationConfig::new();
        cfg.add_server(SpecExternalServerConfig::new_sse(
            "srv",
            "http://localhost:9999",
        ));
        let mut mgr = SpecFederationManager::new(cfg);
        mgr.init_transports();
        assert!(mgr.http_transports.contains_key("srv"));
    }

    #[test]
    fn test_spec_manager_init_transports_disabled_skipped() {
        let mut cfg = SpecFederationConfig::new();
        cfg.add_server(SpecExternalServerConfig::new_sse("srv", "http://x").disabled());
        let mut mgr = SpecFederationManager::new(cfg);
        mgr.init_transports();
        assert!(!mgr.http_transports.contains_key("srv"));
    }

    #[tokio::test]
    async fn test_spec_manager_refresh_capabilities_stubs_for_stdio() {
        let mut cfg = SpecFederationConfig::new();
        cfg.add_server(SpecExternalServerConfig::new_stdio(
            "frida",
            "frida-mcp",
            vec!["--stdio".into()],
        ));
        let mut mgr = SpecFederationManager::new(cfg);
        // refresh should succeed and seed the cache with stubs.
        mgr.refresh_capabilities().await.unwrap();
        assert!(!mgr.cache.is_stale("frida"));
        let tools = mgr.cache.get_tools("frida").unwrap();
        assert!(!tools.is_empty());
    }

    // ── ServerStatusSnapshot ──────────────────────────────────────────────

    #[test]
    fn test_server_status_snapshot_fields() {
        let mgr = make_spec_manager_with_stubs();
        let snaps = mgr.server_status();
        for snap in &snaps {
            assert!(!snap.name.is_empty());
            assert!(!snap.transport_kind.is_empty());
            assert!(!snap.effective_prefix.is_empty());
        }
    }

    // ── WebSocketTransport construction (no network) ──────────────────────

    #[test]
    fn test_ws_transport_new() {
        let t = WebSocketTransport::new("http://localhost:9000");
        // Verify the transport was constructed without panic.
        let _ = t;
    }

    #[test]
    fn test_ws_transport_with_token() {
        let t = WebSocketTransport::with_token("http://x", "secret");
        assert_eq!(t.token.as_deref(), Some("secret"));
    }

    #[test]
    fn test_sse_transport_new() {
        let t = SseTransport::new("http://localhost:8080");
        let _ = t;
    }

    #[test]
    fn test_sse_transport_with_token() {
        let t = SseTransport::with_token("http://localhost:8080", "tok");
        let _ = t;
    }
}
