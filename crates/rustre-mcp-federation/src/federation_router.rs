//! MCP federation router: `FederationRouter`, `RouteTable`, `ServerEntry`,
//! `route_request()`.
//!
//! The router decides which backend MCP server should handle each incoming
//! tool call.  It supports both static rules (explicit tool→server mappings)
//! and dynamic rules (prefix / glob matching).

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

// ── RouteError ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteError {
    /// No route matched the requested tool name.
    NoRoute(String),
    /// The matched server is currently marked unavailable.
    ServerUnavailable(String),
    /// The route table is empty.
    EmptyTable,
    /// A wildcard route exists but has no server assigned.
    WildcardUnresolved,
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoute(t) => write!(f, "no route for tool '{t}'"),
            Self::ServerUnavailable(s) => write!(f, "server '{s}' is unavailable"),
            Self::EmptyTable => write!(f, "route table is empty"),
            Self::WildcardUnresolved => write!(f, "wildcard route has no server assigned"),
        }
    }
}

impl std::error::Error for RouteError {}

// ── ServerEntry ───────────────────────────────────────────────────────────────

/// A backend MCP server known to the federation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    /// Unique server identifier / name.
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Endpoint URL or socket path.
    pub endpoint: String,
    /// Whether this server is currently considered healthy.
    pub available: bool,
    /// Tools explicitly provided by this server (may be empty if dynamic).
    pub tool_names: Vec<String>,
    /// Priority (lower = higher priority when multiple servers match).
    pub priority: u8,
    /// Timestamp (Unix seconds) when this entry was registered.
    pub registered_at: u64,
    /// Cumulative request count routed to this server.
    pub request_count: u64,
    /// Cumulative error count for this server.
    pub error_count: u64,
    /// Rolling average latency in milliseconds.
    pub avg_latency_ms: f64,
}

impl ServerEntry {
    /// Construct a new server entry.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        label: impl Into<String>,
        endpoint: impl Into<String>,
        priority: u8,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        Self {
            id: id.into(),
            label: label.into(),
            endpoint: endpoint.into(),
            available: true,
            tool_names: Vec::new(),
            priority,
            registered_at: now,
            request_count: 0,
            error_count: 0,
            avg_latency_ms: 0.0,
        }
    }

    /// Add tools that this server provides.
    pub fn with_tools(mut self, tools: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.tool_names.extend(tools.into_iter().map(Into::into));
        self
    }

    /// Return `true` if this server declares support for `tool_name`.
    #[must_use]
    pub fn supports_tool(&self, tool_name: &str) -> bool {
        self.tool_names.iter().any(|t| t == tool_name)
    }

    /// Record a successful call with the given latency.
    pub fn record_success(&mut self, latency_ms: f64) {
        self.request_count += 1;
        // Exponential moving average (α = 0.2).
        self.avg_latency_ms = 0.8 * self.avg_latency_ms + 0.2 * latency_ms;
    }

    /// Record a failed call.
    pub fn record_error(&mut self) {
        self.request_count += 1;
        self.error_count += 1;
    }

    /// Return the error rate as a fraction in [0.0, 1.0].
    #[must_use]
    pub fn error_rate(&self) -> f64 {
        if self.request_count == 0 {
            0.0
        } else {
            self.error_count as f64 / self.request_count as f64
        }
    }
}

impl fmt::Display for ServerEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.available { "UP" } else { "DOWN" };
        write!(f, "[{status}] {} ({}) pri={} tools={}", self.id, self.endpoint, self.priority, self.tool_names.len())
    }
}

// ── RouteRule ─────────────────────────────────────────────────────────────────

/// A single routing rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RouteRule {
    /// Exact match on tool name.
    Exact { tool: String, server_id: String },
    /// Prefix match: all tools whose name starts with `prefix`.
    Prefix { prefix: String, server_id: String },
    /// Namespace match: tools of the form `namespace::*`.
    Namespace { namespace: String, server_id: String },
    /// Wildcard / catch-all.
    Wildcard { server_id: String },
}

impl RouteRule {
    /// Return the server ID this rule routes to.
    #[must_use]
    pub fn server_id(&self) -> &str {
        match self {
            Self::Exact { server_id, .. }
            | Self::Prefix { server_id, .. }
            | Self::Namespace { server_id, .. }
            | Self::Wildcard { server_id } => server_id,
        }
    }

    /// Return `true` if this rule matches `tool_name`.
    #[must_use]
    pub fn matches(&self, tool_name: &str) -> bool {
        match self {
            Self::Exact { tool, .. } => tool == tool_name,
            Self::Prefix { prefix, .. } => tool_name.starts_with(prefix.as_str()),
            Self::Namespace { namespace, .. } => {
                tool_name.starts_with(&format!("{namespace}::"))
            }
            Self::Wildcard { .. } => true,
        }
    }

    /// Return the priority of this rule type (lower = evaluated first).
    #[must_use]
    pub const fn rule_priority(&self) -> u8 {
        match self {
            Self::Exact { .. } => 0,
            Self::Namespace { .. } => 1,
            Self::Prefix { .. } => 2,
            Self::Wildcard { .. } => 3,
        }
    }
}

// ── RouteTable ────────────────────────────────────────────────────────────────

/// A collection of routing rules evaluated in priority order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteTable {
    /// Rules sorted by priority (lowest priority value = checked first).
    pub rules: Vec<RouteRule>,
}

impl RouteTable {
    /// Construct an empty route table.
    #[must_use]
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule; the table stays sorted by rule priority.
    pub fn add_rule(&mut self, rule: RouteRule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.rule_priority());
    }

    /// Add an exact mapping.
    pub fn add_exact(&mut self, tool: impl Into<String>, server_id: impl Into<String>) {
        self.add_rule(RouteRule::Exact { tool: tool.into(), server_id: server_id.into() });
    }

    /// Add a prefix mapping.
    pub fn add_prefix(&mut self, prefix: impl Into<String>, server_id: impl Into<String>) {
        self.add_rule(RouteRule::Prefix { prefix: prefix.into(), server_id: server_id.into() });
    }

    /// Add a namespace mapping.
    pub fn add_namespace(&mut self, namespace: impl Into<String>, server_id: impl Into<String>) {
        self.add_rule(RouteRule::Namespace { namespace: namespace.into(), server_id: server_id.into() });
    }

    /// Add a catch-all / wildcard mapping.
    pub fn add_wildcard(&mut self, server_id: impl Into<String>) {
        self.add_rule(RouteRule::Wildcard { server_id: server_id.into() });
    }

    /// Return the server ID for the first matching rule, or `None`.
    #[must_use]
    pub fn lookup(&self, tool_name: &str) -> Option<&str> {
        self.rules.iter().find(|r| r.matches(tool_name)).map(|r| r.server_id())
    }

    /// Return all server IDs that appear in the table (deduplicated).
    #[must_use]
    pub fn referenced_servers(&self) -> Vec<&str> {
        let mut seen = Vec::new();
        for rule in &self.rules {
            let id = rule.server_id();
            if !seen.contains(&id) {
                seen.push(id);
            }
        }
        seen
    }

    /// Return the number of rules in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Return `true` if the table has no rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl Default for RouteTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── RouteDecision ─────────────────────────────────────────────────────────────

/// Result of a routing decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteDecision {
    /// The tool name that was routed.
    pub tool_name: String,
    /// The server ID selected.
    pub server_id: String,
    /// The endpoint URL of the selected server.
    pub endpoint: String,
    /// Whether the route came from a wildcard rule.
    pub is_wildcard: bool,
    /// Timestamp of the decision.
    pub decided_at: u64,
}

// ── FederationRouter ──────────────────────────────────────────────────────────

/// Top-level federation router.
///
/// Holds a route table and a registry of known servers.  Thread-safe via
/// interior `RwLock`.
#[derive(Debug)]
pub struct FederationRouter {
    inner: Arc<RwLock<RouterInner>>,
}

#[derive(Debug)]
struct RouterInner {
    table: RouteTable,
    servers: HashMap<String, ServerEntry>,
    decision_log: Vec<RouteDecision>,
    max_log: usize,
}

impl FederationRouter {
    /// Construct a new router with an empty table and no servers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(RouterInner {
                table: RouteTable::new(),
                servers: HashMap::new(),
                decision_log: Vec::new(),
                max_log: 1024,
            })),
        }
    }

    /// Register a backend server.
    pub fn register_server(&self, server: ServerEntry) {
        let mut g = self.inner.write();
        // Auto-add exact rules for each tool the server declares.
        for tool in &server.tool_names.clone() {
            g.table.add_exact(tool.clone(), server.id.clone());
        }
        g.servers.insert(server.id.clone(), server);
    }

    /// Remove a server by ID.
    pub fn unregister_server(&self, server_id: &str) {
        let mut g = self.inner.write();
        g.servers.remove(server_id);
        g.table.rules.retain(|r| r.server_id() != server_id);
    }

    /// Add a routing rule directly.
    pub fn add_rule(&self, rule: RouteRule) {
        self.inner.write().table.add_rule(rule);
    }

    /// Mark a server available or unavailable.
    pub fn set_server_available(&self, server_id: &str, available: bool) {
        let mut g = self.inner.write();
        if let Some(s) = g.servers.get_mut(server_id) {
            s.available = available;
        }
    }

    /// Return a snapshot of the current route table.
    #[must_use]
    pub fn route_table(&self) -> RouteTable {
        self.inner.read().table.clone()
    }

    /// Return a snapshot of all registered servers.
    #[must_use]
    pub fn servers(&self) -> Vec<ServerEntry> {
        self.inner.read().servers.values().cloned().collect()
    }

    /// Return recent routing decisions (up to `max_log`).
    #[must_use]
    pub fn decision_log(&self) -> Vec<RouteDecision> {
        self.inner.read().decision_log.clone()
    }

    /// Record a success/error against a server.
    pub fn record_outcome(&self, server_id: &str, latency_ms: f64, is_error: bool) {
        let mut g = self.inner.write();
        if let Some(s) = g.servers.get_mut(server_id) {
            if is_error {
                s.record_error();
            } else {
                s.record_success(latency_ms);
            }
        }
    }
}

impl Default for FederationRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ── route_request ─────────────────────────────────────────────────────────────

/// Route a tool request to a backend server.
///
/// Returns a [`RouteDecision`] on success or a [`RouteError`] if no
/// healthy server could be found.
///
/// # Algorithm
/// 1. Consult the route table to find the first matching rule.
/// 2. Verify the matched server is registered and marked available.
/// 3. If the server is unavailable, search for an alternative server that
///    declares the tool in its `tool_names`.
/// 4. If no alternative is found, return `RouteError::ServerUnavailable`.
pub fn route_request(
    router: &FederationRouter,
    tool_name: &str,
) -> Result<RouteDecision, RouteError> {
    let mut g = router.inner.write();
    if g.table.is_empty() && g.servers.is_empty() {
        return Err(RouteError::EmptyTable);
    }

    // Step 1: find the rule-based server.
    let candidate_id = g.table.lookup(tool_name).map(str::to_string);

    let is_wildcard = candidate_id.as_deref().map_or(false, |id| {
        // Only consider the rule a wildcard if it both matches `tool_name`
        // *and* resolves to the candidate server `id` we just selected; this
        // guards against picking up a wildcard that points elsewhere.
        g.table
            .rules
            .iter()
            .find(|r| r.matches(tool_name) && r.server_id() == id)
            .map_or(false, |r| matches!(r, RouteRule::Wildcard { .. }))
    });

    // Step 2: verify availability.
    let selected = if let Some(ref id) = candidate_id {
        if let Some(s) = g.servers.get(id) {
            if s.available {
                Some(s.clone())
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Step 3: fallback — find any available server that supports the tool.
    let selected = if let Some(s) = selected {
        s
    } else {
        let fallback = g.servers.values()
            .filter(|s| s.available && s.supports_tool(tool_name))
            .min_by_key(|s| s.priority)
            .cloned();
        match fallback {
            Some(s) => s,
            None => {
                return Err(match candidate_id {
                    Some(id) => RouteError::ServerUnavailable(id),
                    None => RouteError::NoRoute(tool_name.to_string()),
                });
            }
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();

    let decision = RouteDecision {
        tool_name: tool_name.to_string(),
        server_id: selected.id.clone(),
        endpoint: selected.endpoint.clone(),
        is_wildcard,
        decided_at: now,
    };

    // Step 4: log the decision.
    let max = g.max_log;
    if g.decision_log.len() >= max {
        g.decision_log.remove(0);
    }
    g.decision_log.push(decision.clone());

    Ok(decision)
}

/// Like [`route_request`], but also measures and returns the monotonic wall
/// time taken by the routing decision (using [`Instant`]). Useful for
/// dashboards, hot-path tracing, and SLO monitoring.
pub fn route_request_timed(
    router: &FederationRouter,
    tool_name: &str,
) -> (Result<RouteDecision, RouteError>, Duration) {
    let started = Instant::now();
    let res = route_request(router, tool_name);
    (res, started.elapsed())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_router() -> FederationRouter {
        let r = FederationRouter::new();
        let mut srv = ServerEntry::new("srv1", "Server 1", "http://localhost:9001", 1);
        srv.tool_names = vec!["file_read".to_string(), "file_write".to_string()];
        r.register_server(srv);
        let mut srv2 = ServerEntry::new("srv2", "Server 2", "http://localhost:9002", 2);
        srv2.tool_names = vec!["search".to_string()];
        r.register_server(srv2);
        r
    }

    #[test]
    fn test_route_exact_match() {
        let router = make_router();
        let d = route_request(&router, "file_read").unwrap();
        assert_eq!(d.server_id, "srv1");
    }

    #[test]
    fn test_route_no_match() {
        let router = make_router();
        let e = route_request(&router, "nonexistent_tool").unwrap_err();
        assert!(matches!(e, RouteError::NoRoute(_)));
    }

    #[test]
    fn test_route_server_unavailable_fallback() {
        let router = make_router();
        router.set_server_available("srv1", false);
        // srv2 doesn't support file_read so we get unavailable.
        let e = route_request(&router, "file_read").unwrap_err();
        assert!(matches!(e, RouteError::ServerUnavailable(_) | RouteError::NoRoute(_)));
    }

    #[test]
    fn test_route_wildcard() {
        let router = FederationRouter::new();
        router.add_rule(RouteRule::Wildcard { server_id: "catch_all".to_string() });
        let mut srv = ServerEntry::new("catch_all", "Catch-all", "http://localhost:9999", 10);
        srv.tool_names = vec!["anything".to_string()];
        router.register_server(srv);
        // Re-add wildcard because register_server adds exact rules.
        router.add_rule(RouteRule::Wildcard { server_id: "catch_all".to_string() });
        let d = route_request(&router, "anything").unwrap();
        assert_eq!(d.server_id, "catch_all");
    }

    #[test]
    fn test_route_table_prefix() {
        let mut t = RouteTable::new();
        t.add_prefix("file_", "file_server");
        assert_eq!(t.lookup("file_read"), Some("file_server"));
        assert_eq!(t.lookup("search"), None);
    }

    #[test]
    fn test_route_table_namespace() {
        let mut t = RouteTable::new();
        t.add_namespace("ghidra", "ghidra_srv");
        assert_eq!(t.lookup("ghidra::decompile"), Some("ghidra_srv"));
        assert_eq!(t.lookup("ida::decompile"), None);
    }

    #[test]
    fn test_server_entry_error_rate() {
        let mut s = ServerEntry::new("s", "S", "http://x", 1);
        s.record_success(10.0);
        s.record_error();
        assert!((s.error_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_decision_log_recorded() {
        let router = make_router();
        route_request(&router, "search").unwrap();
        assert_eq!(router.decision_log().len(), 1);
    }

    #[test]
    fn test_unregister_server() {
        let router = make_router();
        router.unregister_server("srv1");
        assert!(route_request(&router, "file_read").is_err());
    }
}
