//! MCP federation layer — proxy and aggregate multiple upstream MCP servers.
//!
//! [`FederatedServer`] holds a list of [`UpstreamServer`] descriptors.
//! When a tool call arrives it:
//! 1. Checks the local [`crate::tool_registry::ToolRegistry`] first.
//! 2. If not found locally, routes to the first upstream that advertises the
//!    tool.
//! 3. Merges tool lists from all upstreams on `list_tools`.
//! 4. Forwards auth tokens if configured.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

// ─── FederationError ──────────────────────────────────────────────────────────

/// Errors produced by the federation layer.
#[derive(Debug, Error)]
pub enum FederationError {
    /// No upstream server advertises the requested tool.
    #[error("tool '{0}' not found in any upstream")]
    ToolNotFound(String),
    /// An upstream server returned an error.
    #[error("upstream '{server}' error for tool '{tool}': {detail}")]
    UpstreamError {
        /// Upstream server ID.
        server: String,
        /// Tool name.
        tool: String,
        /// Error detail.
        detail: String,
    },
    /// Connection to an upstream server failed.
    #[error("cannot connect to upstream '{0}'")]
    ConnectionFailed(String),
    /// Auth token required but not provided.
    #[error("auth token required for upstream '{0}'")]
    AuthRequired(String),
    /// Serialization error.
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    /// Timeout waiting for upstream.
    #[error("timeout contacting upstream '{0}'")]
    Timeout(String),
    /// The upstream's tool list could not be merged (duplicate names).
    #[error("tool name conflict: '{0}' exists in multiple upstreams")]
    ToolConflict(String),
}

impl FederationError {
    /// Construct an upstream error.
    #[must_use]
    pub fn upstream(
        server: impl Into<String>,
        tool: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self::UpstreamError {
            server: server.into(),
            tool: tool.into(),
            detail: detail.into(),
        }
    }

    /// Return `true` if this is a not-found error.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::ToolNotFound(_))
    }
}

// ─── UpstreamTool ─────────────────────────────────────────────────────────────

/// A tool advertisement from an upstream server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamTool {
    /// Tool name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for the input.
    pub input_schema: Value,
    /// ID of the upstream server that provides this tool.
    pub upstream_id: String,
}

impl UpstreamTool {
    /// Create a new upstream tool advertisement.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        input_schema: Value,
        upstream_id: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema,
            upstream_id: upstream_id.into(),
        }
    }
}

impl fmt::Display for UpstreamTool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (from {})", self.name, self.upstream_id)
    }
}

// ─── UpstreamHealth ───────────────────────────────────────────────────────────

/// Current health status of an upstream server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpstreamHealth {
    /// Unknown (not yet checked).
    Unknown,
    /// Server is reachable and responding.
    Healthy,
    /// Server responded with errors (degraded).
    Degraded,
    /// Server is unreachable.
    Unreachable,
}

impl fmt::Display for UpstreamHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unknown => "unknown",
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unreachable => "unreachable",
        };
        write!(f, "{s}")
    }
}

// ─── UpstreamServer ───────────────────────────────────────────────────────────

/// Descriptor for one upstream MCP server.
#[derive(Debug, Clone)]
pub struct UpstreamServer {
    /// Stable identifier for this upstream (e.g. `"ghidra"`, `"ida"`).
    pub id: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Base URL of the upstream server (e.g. `"http://127.0.0.1:8080"`).
    pub base_url: String,
    /// Optional bearer token for auth.
    pub auth_token: Option<String>,
    /// Request timeout.
    pub timeout: Duration,
    /// Whether this upstream is enabled.
    pub enabled: bool,
    /// Current health status (updated by health checks).
    health: Arc<RwLock<UpstreamHealth>>,
    /// Tools advertised by this server (cached after last sync).
    tools_cache: Arc<RwLock<Vec<UpstreamTool>>>,
    /// Monotonic timestamp of last tool list sync.
    last_synced: Arc<RwLock<Option<Instant>>>,
    /// Total successful proxy calls.
    pub success_count: Arc<RwLock<u64>>,
    /// Total failed proxy calls.
    pub error_count: Arc<RwLock<u64>>,
}

impl UpstreamServer {
    /// Create a new upstream server descriptor.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        display_name: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            display_name: display_name.into(),
            base_url: base_url.into(),
            auth_token: None,
            timeout: Duration::from_secs(30),
            enabled: true,
            health: Arc::new(RwLock::new(UpstreamHealth::Unknown)),
            tools_cache: Arc::new(RwLock::new(Vec::new())),
            last_synced: Arc::new(RwLock::new(None)),
            success_count: Arc::new(RwLock::new(0)),
            error_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Set the auth token.
    #[must_use]
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Set the timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the enabled flag.
    #[must_use]
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Inject a tool list into the cache (for testing / manual federation).
    pub fn set_tools(&self, tools: Vec<UpstreamTool>) {
        *self.tools_cache.write() = tools;
        *self.last_synced.write() = Some(Instant::now());
    }

    /// Mark this upstream as healthy.
    pub fn mark_healthy(&self) {
        *self.health.write() = UpstreamHealth::Healthy;
    }

    /// Mark this upstream as unreachable.
    pub fn mark_unreachable(&self) {
        *self.health.write() = UpstreamHealth::Unreachable;
    }

    /// Mark this upstream as degraded.
    pub fn mark_degraded(&self) {
        *self.health.write() = UpstreamHealth::Degraded;
    }

    /// Return the current health status.
    #[must_use]
    pub fn health(&self) -> UpstreamHealth {
        *self.health.read()
    }

    /// Return cached tools.
    #[must_use]
    pub fn cached_tools(&self) -> Vec<UpstreamTool> {
        self.tools_cache.read().clone()
    }

    /// Whether the tool cache has been populated.
    #[must_use]
    pub fn has_tool_cache(&self) -> bool {
        !self.tools_cache.read().is_empty()
    }

    /// Return `true` if this upstream advertises the given tool name.
    #[must_use]
    pub fn has_tool(&self, name: &str) -> bool {
        self.tools_cache.read().iter().any(|t| t.name == name)
    }

    /// Increment the success counter and return the new value.
    pub fn inc_success(&self) -> u64 {
        let mut c = self.success_count.write();
        *c += 1;
        *c
    }

    /// Increment the error counter and return the new value.
    pub fn inc_error(&self) -> u64 {
        let mut c = self.error_count.write();
        *c += 1;
        *c
    }

    /// Current success count.
    #[must_use]
    pub fn get_success_count(&self) -> u64 {
        *self.success_count.read()
    }

    /// Current error count.
    #[must_use]
    pub fn get_error_count(&self) -> u64 {
        *self.error_count.read()
    }
}

impl fmt::Display for UpstreamServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.display_name, self.base_url)
    }
}

// ─── ProxyCall ────────────────────────────────────────────────────────────────

/// A simulated proxy call to an upstream server.
///
/// In production this would make an HTTP/JSON-RPC request.  In the current
/// in-process implementation it looks up the tool in the upstream's cached
/// tool list and invokes a registered stub handler if one exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyCall {
    /// Target upstream server ID.
    pub upstream_id: String,
    /// Tool name.
    pub tool_name: String,
    /// Parameters.
    pub params: Value,
    /// Auth token forwarded (redacted in display).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

impl ProxyCall {
    /// Create a proxy call.
    #[must_use]
    pub fn new(
        upstream_id: impl Into<String>,
        tool_name: impl Into<String>,
        params: Value,
    ) -> Self {
        Self {
            upstream_id: upstream_id.into(),
            tool_name: tool_name.into(),
            params,
            auth_token: None,
        }
    }

    /// Attach an auth token.
    #[must_use]
    pub fn with_auth(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }
}

impl fmt::Display for ProxyCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProxyCall({} -> {})", self.upstream_id, self.tool_name)
    }
}

// ─── FederationStats ──────────────────────────────────────────────────────────

/// Aggregate statistics for the federated server.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FederationStats {
    /// Total tools visible across all upstreams.
    pub total_tools: usize,
    /// Number of upstream servers.
    pub upstream_count: usize,
    /// Number of healthy upstreams.
    pub healthy_upstreams: usize,
    /// Total successful proxied calls.
    pub total_success: u64,
    /// Total failed proxied calls.
    pub total_errors: u64,
    /// Per-upstream stats.
    pub per_upstream: Vec<UpstreamStats>,
}

/// Statistics for a single upstream server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamStats {
    /// Upstream ID.
    pub id: String,
    /// Display name.
    pub display_name: String,
    /// Health status.
    pub health: String,
    /// Tool count.
    pub tool_count: usize,
    /// Success count.
    pub success_count: u64,
    /// Error count.
    pub error_count: u64,
}

// ─── ProxyHandler ─────────────────────────────────────────────────────────────

/// A stub proxy handler registered for an upstream + tool combination.
///
/// In production code the handler would serialize `ProxyCall` to JSON and
/// send it over HTTP/stdio transport to the upstream server.
type ProxyHandlerFn = Arc<dyn Fn(ProxyCall) -> Result<Value, FederationError> + Send + Sync>;

// ─── FederatedServer ─────────────────────────────────────────────────────────

/// Federated MCP server that aggregates multiple upstream MCP servers.
pub struct FederatedServer {
    /// Registered upstream servers.
    upstreams: Arc<RwLock<Vec<UpstreamServer>>>,
    /// Stub proxy handlers: `"upstream_id::tool_name"` → handler.
    proxy_handlers: Arc<RwLock<HashMap<String, ProxyHandlerFn>>>,
    /// Whether to allow tool name conflicts across upstreams.
    pub allow_conflicts: bool,
    /// Whether to forward the caller's auth token to upstreams.
    pub forward_auth: bool,
    /// Default auth token used when forwarding is enabled and no per-call token
    /// is provided.
    pub default_auth_token: Option<String>,
}

impl FederatedServer {
    /// Create a new empty federated server.
    #[must_use]
    pub fn new() -> Self {
        Self {
            upstreams: Arc::new(RwLock::new(Vec::new())),
            proxy_handlers: Arc::new(RwLock::new(HashMap::new())),
            allow_conflicts: false,
            forward_auth: false,
            default_auth_token: None,
        }
    }

    /// Add an upstream server.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError::ToolConflict`] if `allow_conflicts` is
    /// `false` and one of the upstream's tools is already advertised by an
    /// existing upstream.
    pub fn add_upstream(&self, server: UpstreamServer) -> Result<(), FederationError> {
        if !self.allow_conflicts {
            let existing_tools: std::collections::HashSet<String> = self
                .upstreams
                .read()
                .iter()
                .flat_map(|u| u.cached_tools().into_iter().map(|t| t.name))
                .collect();
            for tool in server.cached_tools() {
                if existing_tools.contains(&tool.name) {
                    return Err(FederationError::ToolConflict(tool.name));
                }
            }
        }
        self.upstreams.write().push(server);
        Ok(())
    }

    /// Add an upstream, ignoring any tool conflicts.
    pub fn add_upstream_force(&self, server: UpstreamServer) {
        self.upstreams.write().push(server);
    }

    /// Remove an upstream by ID.  Returns `true` if found and removed.
    pub fn remove_upstream(&self, id: &str) -> bool {
        let mut upstreams = self.upstreams.write();
        let before = upstreams.len();
        upstreams.retain(|u| u.id != id);
        upstreams.len() < before
    }

    /// Return the number of registered upstreams.
    #[must_use]
    pub fn upstream_count(&self) -> usize {
        self.upstreams.read().len()
    }

    /// Return a snapshot of all upstream IDs.
    #[must_use]
    pub fn upstream_ids(&self) -> Vec<String> {
        self.upstreams.read().iter().map(|u| u.id.clone()).collect()
    }

    /// Register a stub proxy handler for a specific upstream + tool pair.
    ///
    /// The key is `"{upstream_id}::{tool_name}"`.
    pub fn register_proxy_handler<F>(&self, upstream_id: &str, tool_name: &str, handler: F)
    where
        F: Fn(ProxyCall) -> Result<Value, FederationError> + Send + Sync + 'static,
    {
        let key = format!("{upstream_id}::{tool_name}");
        self.proxy_handlers.write().insert(key, Arc::new(handler));
    }

    /// Return the merged list of all tools from all enabled, healthy(ish)
    /// upstreams.  Conflicts are resolved by first-upstream-wins.
    #[must_use]
    pub fn list_tools(&self) -> Vec<UpstreamTool> {
        let upstreams = self.upstreams.read();
        let cap_hint: usize = upstreams.iter().filter(|u| u.enabled).map(|u| u.cached_tools().len()).sum();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::with_capacity(cap_hint);
        let mut out = Vec::with_capacity(cap_hint);

        for upstream in upstreams.iter() {
            if !upstream.enabled {
                continue;
            }
            for tool in upstream.cached_tools() {
                if seen.insert(tool.name.clone()) {
                    out.push(tool);
                }
            }
        }
        out
    }

    /// Return the list of tools advertised by a specific upstream.
    #[must_use]
    pub fn tools_for_upstream(&self, upstream_id: &str) -> Vec<UpstreamTool> {
        self.upstreams
            .read()
            .iter()
            .find(|u| u.id == upstream_id)
            .map(|u| u.cached_tools())
            .unwrap_or_default()
    }

    /// Find which upstream provides the given tool.
    ///
    /// Returns the upstream's ID, or `None`.
    #[must_use]
    pub fn upstream_for_tool(&self, tool_name: &str) -> Option<String> {
        self.upstreams
            .read()
            .iter()
            .find(|u| u.enabled && u.has_tool(tool_name))
            .map(|u| u.id.clone())
    }

    /// Route a tool call to the appropriate upstream.
    ///
    /// Resolution order:
    /// 1. Find the first enabled upstream that advertises `tool_name`.
    /// 2. Look up a registered proxy handler for `"{upstream_id}::{tool_name}"`.
    /// 3. If no specific handler, fall back to the generic upstream handler for
    ///    `"{upstream_id}::*"` (wildcard).
    /// 4. If still nothing, return a stub response with metadata.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError::ToolNotFound`] if no upstream knows the tool.
    pub fn route(
        &self,
        tool_name: &str,
        params: Value,
        caller_token: Option<&str>,
    ) -> Result<Value, FederationError> {
        let upstream_id = self
            .upstream_for_tool(tool_name)
            .ok_or_else(|| FederationError::ToolNotFound(tool_name.to_string()))?;

        // Determine auth token to forward.
        let auth_token = if self.forward_auth {
            caller_token
                .map(|s| s.to_string())
                .or_else(|| self.default_auth_token.clone())
                .or_else(|| {
                    self.upstreams
                        .read()
                        .iter()
                        .find(|u| u.id == upstream_id)
                        .and_then(|u| u.auth_token.clone())
                })
        } else {
            self.upstreams
                .read()
                .iter()
                .find(|u| u.id == upstream_id)
                .and_then(|u| u.auth_token.clone())
        };

        let call = {
            let c = ProxyCall::new(upstream_id.clone(), tool_name, params);
            if let Some(tok) = auth_token {
                c.with_auth(tok)
            } else {
                c
            }
        };

        // Try specific handler.
        let specific_key = format!("{upstream_id}::{tool_name}");
        let wildcard_key = format!("{upstream_id}::*");

        let handler = {
            let handlers = self.proxy_handlers.read();
            handlers
                .get(&specific_key)
                .or_else(|| handlers.get(&wildcard_key))
                .cloned()
        };
        let result = if let Some(handler) = handler {
            handler(call.clone())
        } else {
            // Stub response.
            Ok(serde_json::json!({
                "proxied": true,
                "upstream": upstream_id,
                "tool": tool_name,
                "stub": true,
            }))
        };

        // Update counters.
        let upstreams = self.upstreams.read();
        if let Some(upstream) = upstreams.iter().find(|u| u.id == upstream_id) {
            match &result {
                Ok(_) => {
                    upstream.inc_success();
                }
                Err(_) => {
                    upstream.inc_error();
                }
            }
        }

        result
    }

    /// Route a call with no caller auth token.
    ///
    /// # Errors
    ///
    /// See [`Self::route`].
    pub fn route_anon(&self, tool_name: &str, params: Value) -> Result<Value, FederationError> {
        self.route(tool_name, params, None)
    }

    /// Produce aggregate federation statistics.
    #[must_use]
    pub fn stats(&self) -> FederationStats {
        let upstreams = self.upstreams.read();
        let total_tools = {
            let mut seen = std::collections::HashSet::new();
            for u in upstreams.iter() {
                for t in u.cached_tools() {
                    seen.insert(t.name);
                }
            }
            seen.len()
        };

        let healthy_upstreams = upstreams
            .iter()
            .filter(|u| u.health() == UpstreamHealth::Healthy)
            .count();

        let mut total_success = 0u64;
        let mut total_errors = 0u64;
        let per_upstream: Vec<UpstreamStats> = upstreams
            .iter()
            .map(|u| {
                let s = u.get_success_count();
                let e = u.get_error_count();
                total_success += s;
                total_errors += e;
                UpstreamStats {
                    id: u.id.clone(),
                    display_name: u.display_name.clone(),
                    health: u.health().to_string(),
                    tool_count: u.cached_tools().len(),
                    success_count: s,
                    error_count: e,
                }
            })
            .collect();

        FederationStats {
            total_tools,
            upstream_count: upstreams.len(),
            healthy_upstreams,
            total_success,
            total_errors,
            per_upstream,
        }
    }

    /// Check whether the federated server can find the given tool.
    #[must_use]
    pub fn can_route(&self, tool_name: &str) -> bool {
        self.upstream_for_tool(tool_name).is_some()
    }

    /// Mark all upstreams with the given ID as healthy.
    pub fn mark_upstream_healthy(&self, upstream_id: &str) {
        for u in self.upstreams.read().iter() {
            if u.id == upstream_id {
                u.mark_healthy();
            }
        }
    }

    /// Mark all upstreams with the given ID as unreachable.
    pub fn mark_upstream_unreachable(&self, upstream_id: &str) {
        for u in self.upstreams.read().iter() {
            if u.id == upstream_id {
                u.mark_unreachable();
            }
        }
    }

    /// Disable an upstream server by ID.
    pub fn disable_upstream(&self, id: &str) {
        // We need mutable access to the UpstreamServer.enabled field.
        // Since UpstreamServer.enabled is not behind a lock itself, we need
        // to hold the write lock on the vec.
        let mut upstreams = self.upstreams.write();
        for u in upstreams.iter_mut() {
            if u.id == id {
                u.enabled = false;
            }
        }
    }

    /// Enable an upstream server by ID.
    pub fn enable_upstream(&self, id: &str) {
        let mut upstreams = self.upstreams.write();
        for u in upstreams.iter_mut() {
            if u.id == id {
                u.enabled = true;
            }
        }
    }
}

impl Default for FederatedServer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FederatedServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FederatedServer")
            .field("upstream_count", &self.upstream_count())
            .field("total_tools", &self.list_tools().len())
            .finish_non_exhaustive()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_upstream(id: &str, tools: &[&str]) -> UpstreamServer {
        let srv = UpstreamServer::new(id, id, format!("http://127.0.0.1/{id}"));
        let tool_list: Vec<UpstreamTool> = tools
            .iter()
            .map(|name| {
                UpstreamTool::new(
                    *name,
                    format!("Tool {name}"),
                    serde_json::json!({"type":"object"}),
                    id,
                )
            })
            .collect();
        srv.set_tools(tool_list);
        srv.mark_healthy();
        srv
    }

    #[test]
    fn add_and_list_upstreams() {
        let fed = FederatedServer::new();
        fed.add_upstream(make_upstream("ghidra", &["disasm", "decompile"]))
            .expect("add ghidra");
        assert_eq!(fed.upstream_count(), 1);
        let tools = fed.list_tools();
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn tool_conflict_detected() {
        let fed = FederatedServer::new();
        fed.add_upstream(make_upstream("a", &["shared_tool"]))
            .expect("a");
        let err = fed.add_upstream(make_upstream("b", &["shared_tool"]));
        assert!(matches!(err, Err(FederationError::ToolConflict(_))));
    }

    #[test]
    fn tool_conflict_allowed() {
        let mut fed = FederatedServer::new();
        fed.allow_conflicts = true;
        fed.add_upstream(make_upstream("a", &["shared_tool"]))
            .expect("a");
        fed.add_upstream(make_upstream("b", &["shared_tool"]))
            .expect("b");
        // list_tools should return 1 (first-wins).
        assert_eq!(fed.list_tools().len(), 1);
    }

    #[test]
    fn route_to_upstream() {
        let fed = FederatedServer::new();
        let upstream = make_upstream("ida", &["analyze"]);
        fed.add_upstream(upstream).expect("add");

        fed.register_proxy_handler("ida", "analyze", |call| {
            Ok(serde_json::json!({"proxied": true, "tool": call.tool_name}))
        });

        let result = fed
            .route_anon("analyze", serde_json::json!({}))
            .expect("route");
        assert_eq!(result["proxied"], true);
        assert_eq!(result["tool"], "analyze");
    }

    #[test]
    fn route_stub_fallback() {
        let fed = FederatedServer::new();
        fed.add_upstream(make_upstream("frida", &["hook"]))
            .expect("add");
        // No handler registered → stub response.
        let result = fed
            .route_anon("hook", serde_json::json!({}))
            .expect("route");
        assert_eq!(result["stub"], true);
        assert_eq!(result["upstream"], "frida");
    }

    #[test]
    fn route_tool_not_found() {
        let fed = FederatedServer::new();
        let err = fed.route_anon("ghost", serde_json::json!({}));
        assert!(matches!(err, Err(FederationError::ToolNotFound(_))));
    }

    #[test]
    fn remove_upstream() {
        let fed = FederatedServer::new();
        fed.add_upstream(make_upstream("x86dbg", &["step"]))
            .expect("add");
        assert!(fed.remove_upstream("x86dbg"));
        assert_eq!(fed.upstream_count(), 0);
        assert!(!fed.remove_upstream("x86dbg")); // not found
    }

    #[test]
    fn upstream_for_tool() {
        let fed = FederatedServer::new();
        fed.add_upstream(make_upstream("binja", &["lift"]))
            .expect("add");
        assert_eq!(fed.upstream_for_tool("lift"), Some("binja".to_string()));
        assert_eq!(fed.upstream_for_tool("unknown"), None);
    }

    #[test]
    fn stats_aggregation() {
        let fed = FederatedServer::new();
        let up = make_upstream("cutter", &["cfg", "strings"]);
        fed.add_upstream(up).expect("add");
        fed.register_proxy_handler("cutter", "cfg", |_| Ok(serde_json::json!({})));
        fed.route_anon("cfg", serde_json::json!({})).expect("route");
        let stats = fed.stats();
        assert_eq!(stats.upstream_count, 1);
        assert_eq!(stats.total_tools, 2);
        assert_eq!(stats.total_success, 1);
        assert_eq!(stats.healthy_upstreams, 1);
    }

    #[test]
    fn disable_and_enable_upstream() {
        let fed = FederatedServer::new();
        fed.add_upstream(make_upstream("radare2", &["pdg"]))
            .expect("add");
        fed.disable_upstream("radare2");
        // Tool should no longer be reachable.
        assert!(!fed.can_route("pdg"));
        fed.enable_upstream("radare2");
        assert!(fed.can_route("pdg"));
    }

    #[test]
    fn wildcard_handler() {
        let fed = FederatedServer::new();
        fed.add_upstream(make_upstream("dynamic", &["run"]))
            .expect("add");
        fed.register_proxy_handler("dynamic", "*", |call| {
            Ok(serde_json::json!({"wildcard": true, "tool": call.tool_name}))
        });
        let result = fed.route_anon("run", serde_json::json!({})).expect("route");
        assert_eq!(result["wildcard"], true);
    }

    #[test]
    fn auth_token_forwarding() {
        let fed = FederatedServer::new();
        let mut fed = fed;
        fed.forward_auth = true;
        let up = make_upstream("secure_server", &["secret_tool"]);
        fed.add_upstream(up).expect("add");
        fed.register_proxy_handler("secure_server", "secret_tool", |call| {
            let tok = call.auth_token.unwrap_or_default();
            Ok(serde_json::json!({"token": tok}))
        });
        let result = fed
            .route(
                "secret_tool",
                serde_json::json!({}),
                Some("bearer-token-123"),
            )
            .expect("route");
        assert_eq!(result["token"], "bearer-token-123");
    }

    #[test]
    fn tools_for_upstream() {
        let fed = FederatedServer::new();
        fed.add_upstream(make_upstream("u1", &["t1", "t2"]))
            .expect("add");
        let tools = fed.tools_for_upstream("u1");
        assert_eq!(tools.len(), 2);
        let empty = fed.tools_for_upstream("nonexistent");
        assert!(empty.is_empty());
    }

    #[test]
    fn upstream_health_display() {
        assert_eq!(UpstreamHealth::Healthy.to_string(), "healthy");
        assert_eq!(UpstreamHealth::Unreachable.to_string(), "unreachable");
        assert_eq!(UpstreamHealth::Unknown.to_string(), "unknown");
    }

    #[test]
    fn federation_error_helpers() {
        let e = FederationError::upstream("ida", "decompile", "timeout");
        assert!(e.to_string().contains("ida"));
        assert!(!FederationError::Timeout("x".into()).is_not_found());
        assert!(FederationError::ToolNotFound("y".into()).is_not_found());
    }

    #[test]
    fn upstream_counters() {
        let srv = UpstreamServer::new("test", "Test", "http://localhost");
        assert_eq!(srv.inc_success(), 1);
        assert_eq!(srv.inc_success(), 2);
        assert_eq!(srv.inc_error(), 1);
        assert_eq!(srv.get_success_count(), 2);
        assert_eq!(srv.get_error_count(), 1);
    }
}
