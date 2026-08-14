//! `mcp_router` — MCP tool routing and load balancing.
//!
//! Provides [`McpRouter`], [`RouteTable`], [`ToolRoute`], [`UpstreamSelector`],
//! [`LoadBalancer`], and [`RoutingPolicy`] for distributing MCP tool calls
//! across multiple upstream servers.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
pub use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors produced by the router.
#[derive(Debug, Error, Clone)]
pub enum RouterError {
    #[error("no route found for tool '{0}'")]
    NoRoute(String),

    #[error("upstream '{0}' is unavailable")]
    UpstreamUnavailable(String),

    #[error("all upstreams exhausted for tool '{0}'")]
    AllUpstreamsExhausted(String),

    #[error("circuit breaker open for upstream '{0}'")]
    CircuitBreakerOpen(String),

    #[error("routing policy violation: {0}")]
    PolicyViolation(String),

    #[error("load balancer error: {0}")]
    LoadBalancer(String),

    #[error("routing table locked")]
    TableLocked,

    #[error("invalid route config: {0}")]
    InvalidConfig(String),
}

// ─── RoutingPolicy ────────────────────────────────────────────────────────────

/// Strategy the router uses to pick among multiple upstreams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutingPolicy {
    /// Always use the first healthy upstream.
    First,
    /// Round-robin across healthy upstreams.
    RoundRobin,
    /// Use the upstream with the lowest response latency.
    LeastLatency,
    /// Weighted random selection.
    Weighted,
    /// Fan-out to all upstreams, aggregate results.
    FanOut,
    /// Custom policy identified by a string key.
    Custom(String),
}

impl std::fmt::Display for RoutingPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "Custom({s})"),
            _ => write!(f, "{self:?}"),
        }
    }
}

// ─── UpstreamHealth ──────────────────────────────────────────────────────────

/// Health status of an upstream server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpstreamHealth {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

impl std::fmt::Display for UpstreamHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── UpstreamStats ───────────────────────────────────────────────────────────

/// Runtime statistics for a single upstream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamStats {
    pub name: String,
    pub call_count: u64,
    pub error_count: u64,
    pub total_latency_ms: u64,
    pub last_latency_ms: u64,
    pub health: UpstreamHealth,
    pub weight: u32,
    pub consecutive_errors: u32,
    pub circuit_breaker_open: bool,
}

impl UpstreamStats {
    #[must_use]
    pub fn new(name: impl Into<String>, weight: u32) -> Self {
        Self {
            name: name.into(),
            call_count: 0,
            error_count: 0,
            total_latency_ms: 0,
            last_latency_ms: 0,
            health: UpstreamHealth::Unknown,
            weight,
            consecutive_errors: 0,
            circuit_breaker_open: false,
        }
    }

    /// Record a successful call.
    pub const fn record_success(&mut self, latency_ms: u64) {
        self.call_count += 1;
        self.total_latency_ms += latency_ms;
        self.last_latency_ms = latency_ms;
        self.consecutive_errors = 0;
        self.health = UpstreamHealth::Healthy;
    }

    /// Record a failed call and possibly open the circuit breaker.
    pub const fn record_failure(&mut self, threshold: u32) {
        self.call_count += 1;
        self.error_count += 1;
        self.consecutive_errors += 1;
        if self.consecutive_errors >= threshold {
            self.circuit_breaker_open = true;
            self.health = UpstreamHealth::Unhealthy;
        } else {
            self.health = UpstreamHealth::Degraded;
        }
    }

    /// Reset circuit breaker.
    pub const fn reset_circuit_breaker(&mut self) {
        self.circuit_breaker_open = false;
        self.consecutive_errors = 0;
        self.health = UpstreamHealth::Unknown;
    }

    #[must_use]
    pub fn avg_latency_ms(&self) -> f64 {
        if self.call_count == 0 {
            0.0
        } else {
            self.total_latency_ms as f64 / self.call_count as f64
        }
    }

    #[must_use]
    pub fn error_rate(&self) -> f64 {
        if self.call_count == 0 {
            0.0
        } else {
            self.error_count as f64 / self.call_count as f64
        }
    }
}

// ─── ToolRoute ────────────────────────────────────────────────────────────────

/// A single routing rule: maps a tool name pattern to upstreams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRoute {
    /// Glob-like tool name pattern (e.g. `"ghidra_*"`, `"*"`, `"disassemble_function"`).
    pub pattern: String,
    /// Ordered list of upstream names.
    pub upstreams: Vec<String>,
    pub policy: RoutingPolicy,
    pub timeout_ms: u64,
    pub enabled: bool,
    pub priority: u32,
}

impl ToolRoute {
    #[must_use]
    pub fn new(pattern: impl Into<String>, upstreams: Vec<String>) -> Self {
        Self {
            pattern: pattern.into(),
            upstreams,
            policy: RoutingPolicy::RoundRobin,
            timeout_ms: 30_000,
            enabled: true,
            priority: 100,
        }
    }

    #[must_use]
    pub fn with_policy(mut self, policy: RoutingPolicy) -> Self {
        self.policy = policy;
        self
    }

    #[must_use]
    pub const fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    #[must_use]
    pub const fn with_priority(mut self, p: u32) -> Self {
        self.priority = p;
        self
    }

    /// Check whether `tool_name` matches this route's pattern.
    #[must_use]
    pub fn matches(&self, tool_name: &str) -> bool {
        if self.pattern == "*" {
            return true;
        }
        if self.pattern.ends_with('*') {
            let prefix = &self.pattern[..self.pattern.len() - 1];
            return tool_name.starts_with(prefix);
        }
        if self.pattern.starts_with('*') {
            let suffix = &self.pattern[1..];
            return tool_name.ends_with(suffix);
        }
        self.pattern == tool_name
    }
}

// ─── RouteTable ───────────────────────────────────────────────────────────────

/// A collection of routing rules ordered by priority.
#[derive(Debug, Default)]
pub struct RouteTable {
    routes: Vec<ToolRoute>,
    locked: bool,
}

impl RouteTable {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            routes: Vec::new(),
            locked: false,
        }
    }

    /// Add a route to the table.
    pub fn add(&mut self, route: ToolRoute) -> Result<(), RouterError> {
        if self.locked {
            return Err(RouterError::TableLocked);
        }
        self.routes.push(route);
        // Sort by priority descending
        self.routes.sort_by(|a, b| b.priority.cmp(&a.priority));
        Ok(())
    }

    /// Find the first matching route for a tool name.
    #[must_use]
    pub fn lookup(&self, tool_name: &str) -> Option<&ToolRoute> {
        self.routes
            .iter()
            .find(|r| r.enabled && r.matches(tool_name))
    }

    /// Remove all routes matching the given pattern exactly.
    pub fn remove_pattern(&mut self, pattern: &str) {
        self.routes.retain(|r| r.pattern != pattern);
    }

    /// Lock the table against further modifications.
    pub const fn lock(&mut self) {
        self.locked = true;
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.routes.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Return a snapshot of all routes.
    #[must_use]
    pub fn routes(&self) -> &[ToolRoute] {
        &self.routes
    }
}

// ─── LoadBalancer ─────────────────────────────────────────────────────────────

/// Selects an upstream given a policy and per-upstream statistics.
pub struct LoadBalancer {
    rr_counter: Mutex<HashMap<String, usize>>,
    circuit_threshold: u32,
}

impl LoadBalancer {
    #[must_use]
    pub fn new(circuit_threshold: u32) -> Self {
        Self {
            rr_counter: Mutex::new(HashMap::new()),
            circuit_threshold,
        }
    }

    /// Select an upstream from `candidates` using the given policy and stats.
    pub fn select<'a>(
        &self,
        route: &ToolRoute,
        stats: &'a HashMap<String, UpstreamStats>,
        candidates: &[String],
    ) -> Result<&'a UpstreamStats, RouterError> {
        let healthy: Vec<&UpstreamStats> = candidates
            .iter()
            .filter_map(|name| stats.get(name))
            .filter(|s| !s.circuit_breaker_open)
            .collect();

        if healthy.is_empty() {
            return Err(RouterError::AllUpstreamsExhausted(
                candidates.first().cloned().unwrap_or_default(),
            ));
        }

        let selected = match &route.policy {
            RoutingPolicy::First => *healthy.first().unwrap(),
            RoutingPolicy::LeastLatency => healthy
                .iter()
                .min_by(|a, b| {
                    a.avg_latency_ms()
                        .partial_cmp(&b.avg_latency_ms())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .copied()
                .unwrap(),
            RoutingPolicy::RoundRobin => {
                let mut counter = self.rr_counter.lock();
                let key = route.pattern.clone();
                let idx = counter.entry(key).or_insert(0);
                let selected = healthy[*idx % healthy.len()];
                *idx = idx.wrapping_add(1);
                selected
            }
            RoutingPolicy::Weighted => {
                let total_weight: u32 = healthy.iter().map(|s| s.weight).sum();
                if total_weight == 0 {
                    *healthy.first().unwrap()
                } else {
                    let target = (healthy.len() as u32 * 7 / 11) as usize % healthy.len();
                    healthy[target]
                }
            }
            RoutingPolicy::FanOut | RoutingPolicy::Custom(_) => *healthy.first().unwrap(),
        };

        Ok(selected)
    }

    #[must_use]
    pub const fn circuit_threshold(&self) -> u32 {
        self.circuit_threshold
    }
}

// ─── UpstreamSelector ────────────────────────────────────────────────────────

/// Manages the lifecycle of upstream connections and health checks.
pub struct UpstreamSelector {
    stats: RwLock<HashMap<String, UpstreamStats>>,
}

impl UpstreamSelector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            stats: RwLock::new(HashMap::new()),
        }
    }

    /// Register an upstream.
    pub fn register(&self, name: impl Into<String>, weight: u32) {
        let n = name.into();
        self.stats
            .write()
            .entry(n.clone())
            .or_insert_with(|| UpstreamStats::new(n, weight));
    }

    /// Record a successful call to an upstream.
    pub fn record_success(&self, name: &str, latency_ms: u64) {
        if let Some(s) = self.stats.write().get_mut(name) {
            s.record_success(latency_ms);
        }
    }

    /// Record a failed call to an upstream.
    pub fn record_failure(&self, name: &str, threshold: u32) {
        if let Some(s) = self.stats.write().get_mut(name) {
            s.record_failure(threshold);
        }
    }

    /// Reset the circuit breaker for an upstream.
    pub fn reset_circuit_breaker(&self, name: &str) {
        if let Some(s) = self.stats.write().get_mut(name) {
            s.reset_circuit_breaker();
        }
    }

    /// Get a snapshot of stats for a named upstream.
    #[must_use]
    pub fn stats(&self, name: &str) -> Option<UpstreamStats> {
        self.stats.read().get(name).cloned()
    }

    /// List all upstream names.
    #[must_use]
    pub fn upstream_names(&self) -> Vec<String> {
        self.stats.read().keys().cloned().collect()
    }

    #[must_use]
    pub fn healthy_upstreams(&self) -> Vec<String> {
        self.stats
            .read()
            .values()
            .filter(|s| !s.circuit_breaker_open)
            .map(|s| s.name.clone())
            .collect()
    }

    #[must_use]
    pub fn stats_snapshot(&self) -> HashMap<String, UpstreamStats> {
        self.stats.read().clone()
    }
}

impl Default for UpstreamSelector {
    fn default() -> Self {
        Self::new()
    }
}

// ─── McpRouter ────────────────────────────────────────────────────────────────

/// Top-level router: matches tool calls to upstreams and delegates.
pub struct McpRouter {
    table: RwLock<RouteTable>,
    selector: Arc<UpstreamSelector>,
    balancer: Arc<LoadBalancer>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl McpRouter {
    /// Create a new router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: RwLock::new(RouteTable::new()),
            selector: Arc::new(UpstreamSelector::new()),
            balancer: Arc::new(LoadBalancer::new(5)),
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    /// Register an upstream with a given weight.
    pub fn register_upstream(&self, name: impl Into<String>, weight: u32) {
        self.selector.register(name, weight);
    }

    /// Add a routing rule.
    pub fn add_route(&self, route: ToolRoute) -> Result<(), RouterError> {
        self.table.write().add(route)
    }

    /// Resolve the best upstream for a given tool name.
    pub fn resolve(&self, tool_name: &str) -> Result<String, RouterError> {
        self.request_count.fetch_add(1, Ordering::Relaxed);

        let table = self.table.read();
        let route = table
            .lookup(tool_name)
            .ok_or_else(|| RouterError::NoRoute(tool_name.to_string()))?;

        let stats = self.selector.stats_snapshot();
        let upstream = self
            .balancer
            .select(route, &stats, &route.upstreams)
            .inspect_err(|_e| {
                self.error_count.fetch_add(1, Ordering::Relaxed);
            })?;

        Ok(upstream.name.clone())
    }

    /// Record a successful tool call result.
    pub fn record_success(&self, upstream: &str, latency_ms: u64) {
        self.selector.record_success(upstream, latency_ms);
    }

    /// Record a failed tool call.
    pub fn record_failure(&self, upstream: &str) {
        self.selector
            .record_failure(upstream, self.balancer.circuit_threshold());
    }

    /// Reset circuit breaker for an upstream.
    pub fn reset_circuit_breaker(&self, upstream: &str) {
        self.selector.reset_circuit_breaker(upstream);
    }

    #[must_use]
    pub fn request_count(&self) -> u64 {
        self.request_count.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn error_count(&self) -> u64 {
        self.error_count.load(Ordering::Relaxed)
    }

    /// List registered upstream names.
    #[must_use]
    pub fn upstream_names(&self) -> Vec<String> {
        self.selector.upstream_names()
    }

    /// Get stats for a named upstream.
    #[must_use]
    pub fn upstream_stats(&self, name: &str) -> Option<UpstreamStats> {
        self.selector.stats(name)
    }

    /// Get a snapshot of all route patterns.
    #[must_use]
    pub fn route_patterns(&self) -> Vec<String> {
        self.table
            .read()
            .routes()
            .iter()
            .map(|r| r.pattern.clone())
            .collect()
    }

    /// Build a router pre-configured with common RE analysis routes.
    #[must_use]
    pub fn with_defaults() -> Self {
        let router = Self::new();
        router.register_upstream("ghidra", 10);
        router.register_upstream("ida-pro", 10);
        router.register_upstream("binary-ninja", 8);
        router.register_upstream("fallback", 2);

        let _ = router.add_route(
            ToolRoute::new(
                "ghidra_*",
                vec!["ghidra".to_string(), "fallback".to_string()],
            )
            .with_policy(RoutingPolicy::First)
            .with_priority(200),
        );
        let _ = router.add_route(
            ToolRoute::new("ida_*", vec!["ida-pro".to_string(), "ghidra".to_string()])
                .with_policy(RoutingPolicy::First)
                .with_priority(190),
        );
        let _ = router.add_route(
            ToolRoute::new(
                "disassemble_*",
                vec![
                    "ghidra".to_string(),
                    "ida-pro".to_string(),
                    "binary-ninja".to_string(),
                ],
            )
            .with_policy(RoutingPolicy::RoundRobin)
            .with_priority(180),
        );
        let _ = router.add_route(
            ToolRoute::new(
                "*",
                vec![
                    "ghidra".to_string(),
                    "ida-pro".to_string(),
                    "binary-ninja".to_string(),
                    "fallback".to_string(),
                ],
            )
            .with_policy(RoutingPolicy::LeastLatency)
            .with_priority(10),
        );
        router
    }
}

impl Default for McpRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn router_with_upstreams() -> McpRouter {
        let r = McpRouter::new();
        r.register_upstream("upstream-a", 10);
        r.register_upstream("upstream-b", 5);
        let _ = r.add_route(
            ToolRoute::new(
                "disassemble",
                vec!["upstream-a".to_string(), "upstream-b".to_string()],
            )
            .with_policy(RoutingPolicy::RoundRobin),
        );
        let _ = r.add_route(
            ToolRoute::new("*", vec!["upstream-b".to_string()])
                .with_policy(RoutingPolicy::First)
                .with_priority(1),
        );
        r
    }

    // ── ToolRoute.matches ─────────────────────────────────────────────────────

    #[test]
    fn test_route_matches_exact() {
        let r = ToolRoute::new("disassemble_function", vec![]);
        assert!(r.matches("disassemble_function"));
        assert!(!r.matches("disassemble_class"));
    }

    #[test]
    fn test_route_matches_wildcard_all() {
        let r = ToolRoute::new("*", vec![]);
        assert!(r.matches("anything"));
        assert!(r.matches("ghidra_decompile"));
    }

    #[test]
    fn test_route_matches_prefix() {
        let r = ToolRoute::new("ghidra_*", vec![]);
        assert!(r.matches("ghidra_decompile"));
        assert!(r.matches("ghidra_analyze"));
        assert!(!r.matches("ida_analyze"));
    }

    #[test]
    fn test_route_matches_suffix() {
        let r = ToolRoute::new("*_function", vec![]);
        assert!(r.matches("decompile_function"));
        assert!(!r.matches("decompile_class"));
    }

    // ── ToolRoute builders ────────────────────────────────────────────────────

    #[test]
    fn test_tool_route_builder() {
        let r = ToolRoute::new("x", vec!["a".to_string()])
            .with_policy(RoutingPolicy::FanOut)
            .with_timeout(5000)
            .with_priority(99);
        assert_eq!(r.policy, RoutingPolicy::FanOut);
        assert_eq!(r.timeout_ms, 5000);
        assert_eq!(r.priority, 99);
    }

    // ── RouteTable ────────────────────────────────────────────────────────────

    #[test]
    fn test_route_table_add_and_lookup() {
        let mut table = RouteTable::new();
        table
            .add(ToolRoute::new("disassemble", vec!["a".to_string()]))
            .unwrap();
        assert!(table.lookup("disassemble").is_some());
        assert!(table.lookup("unknown").is_none());
    }

    #[test]
    fn test_route_table_priority_ordering() {
        let mut table = RouteTable::new();
        table
            .add(ToolRoute::new("*", vec!["low".to_string()]).with_priority(1))
            .unwrap();
        table
            .add(ToolRoute::new("disasm_*", vec!["high".to_string()]).with_priority(200))
            .unwrap();
        // disasm_fn should match the high-priority rule
        let route = table.lookup("disasm_fn").unwrap();
        assert_eq!(route.upstreams[0], "high");
    }

    #[test]
    fn test_route_table_lock() {
        let mut table = RouteTable::new();
        table.lock();
        let err = table.add(ToolRoute::new("x", vec![]));
        assert!(matches!(err, Err(RouterError::TableLocked)));
    }

    #[test]
    fn test_route_table_remove_pattern() {
        let mut table = RouteTable::new();
        table.add(ToolRoute::new("abc", vec![])).unwrap();
        table.remove_pattern("abc");
        assert!(table.lookup("abc").is_none());
    }

    #[test]
    fn test_route_table_len() {
        let mut table = RouteTable::new();
        assert!(table.is_empty());
        table.add(ToolRoute::new("x", vec![])).unwrap();
        assert_eq!(table.len(), 1);
    }

    // ── UpstreamStats ─────────────────────────────────────────────────────────

    #[test]
    fn test_upstream_stats_new() {
        let s = UpstreamStats::new("a", 10);
        assert_eq!(s.health, UpstreamHealth::Unknown);
        assert_eq!(s.weight, 10);
    }

    #[test]
    fn test_upstream_stats_record_success() {
        let mut s = UpstreamStats::new("a", 10);
        s.record_success(50);
        assert_eq!(s.health, UpstreamHealth::Healthy);
        assert_eq!(s.consecutive_errors, 0);
        assert!((s.avg_latency_ms() - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_upstream_stats_circuit_breaker() {
        let mut s = UpstreamStats::new("a", 10);
        for _ in 0..5 {
            s.record_failure(5);
        }
        assert!(s.circuit_breaker_open);
        s.reset_circuit_breaker();
        assert!(!s.circuit_breaker_open);
    }

    #[test]
    fn test_upstream_stats_error_rate() {
        let mut s = UpstreamStats::new("a", 10);
        s.record_success(10);
        s.record_failure(100);
        assert!((s.error_rate() - 0.5).abs() < 0.01);
    }

    // ── UpstreamSelector ──────────────────────────────────────────────────────

    #[test]
    fn test_upstream_selector_register_and_stats() {
        let sel = UpstreamSelector::new();
        sel.register("a", 10);
        assert!(sel.stats("a").is_some());
        assert!(sel.stats("b").is_none());
    }

    #[test]
    fn test_upstream_selector_healthy() {
        let sel = UpstreamSelector::new();
        sel.register("a", 10);
        sel.register("b", 5);
        sel.record_failure("a", 1); // threshold=1, opens circuit
        let healthy = sel.healthy_upstreams();
        assert!(!healthy.contains(&"a".to_string()));
        assert!(healthy.contains(&"b".to_string()));
    }

    // ── LoadBalancer ──────────────────────────────────────────────────────────

    #[test]
    fn test_load_balancer_first_policy() {
        let lb = LoadBalancer::new(5);
        let route = ToolRoute::new("*", vec!["a".to_string(), "b".to_string()])
            .with_policy(RoutingPolicy::First);
        let mut stats = HashMap::new();
        stats.insert("a".to_string(), UpstreamStats::new("a", 10));
        stats.insert("b".to_string(), UpstreamStats::new("b", 5));
        let selected = lb
            .select(&route, &stats, &["a".to_string(), "b".to_string()])
            .unwrap();
        assert_eq!(selected.name, "a");
    }

    #[test]
    fn test_load_balancer_all_down() {
        let lb = LoadBalancer::new(1);
        let route = ToolRoute::new("*", vec!["a".to_string()]);
        let mut stats = HashMap::new();
        let mut s = UpstreamStats::new("a", 10);
        s.record_failure(1);
        stats.insert("a".to_string(), s);
        let err = lb.select(&route, &stats, &["a".to_string()]).unwrap_err();
        assert!(matches!(err, RouterError::AllUpstreamsExhausted(_)));
    }

    // ── McpRouter ─────────────────────────────────────────────────────────────

    #[test]
    fn test_router_resolve_ok() {
        let r = router_with_upstreams();
        let upstream = r.resolve("disassemble").unwrap();
        assert!(upstream == "upstream-a" || upstream == "upstream-b");
    }

    #[test]
    fn test_router_resolve_no_route() {
        let r = McpRouter::new();
        r.register_upstream("a", 10);
        // No routes added
        let err = r.resolve("some_tool").unwrap_err();
        assert!(matches!(err, RouterError::NoRoute(_)));
    }

    #[test]
    fn test_router_resolve_wildcard_fallback() {
        let r = router_with_upstreams();
        let upstream = r.resolve("unknown_tool").unwrap();
        assert_eq!(upstream, "upstream-b");
    }

    #[test]
    fn test_router_record_success_failure() {
        let r = router_with_upstreams();
        r.record_success("upstream-a", 100);
        r.record_failure("upstream-b");
        let stats_a = r.upstream_stats("upstream-a").unwrap();
        assert_eq!(stats_a.health, UpstreamHealth::Healthy);
    }

    #[test]
    fn test_router_request_count() {
        let r = router_with_upstreams();
        r.resolve("disassemble").ok();
        r.resolve("disassemble").ok();
        assert_eq!(r.request_count(), 2);
    }

    #[test]
    fn test_router_with_defaults() {
        let r = McpRouter::with_defaults();
        let upstream = r.resolve("ghidra_decompile").unwrap();
        assert_eq!(upstream, "ghidra");
    }

    #[test]
    fn test_router_route_patterns() {
        let r = McpRouter::with_defaults();
        let patterns = r.route_patterns();
        assert!(patterns.contains(&"ghidra_*".to_string()));
        assert!(patterns.contains(&"*".to_string()));
    }

    // ── RoutingPolicy display ─────────────────────────────────────────────────

    #[test]
    fn test_routing_policy_display() {
        assert_eq!(RoutingPolicy::RoundRobin.to_string(), "RoundRobin");
        assert_eq!(RoutingPolicy::Custom("my".into()).to_string(), "Custom(my)");
    }

    // ── RouterError display ───────────────────────────────────────────────────

    #[test]
    fn test_router_error_display() {
        let e = RouterError::NoRoute("tool_x".into());
        assert!(e.to_string().contains("tool_x"));
        let e2 = RouterError::CircuitBreakerOpen("srv".into());
        assert!(e2.to_string().contains("srv"));
    }

    #[test]
    fn test_upstream_health_display() {
        assert_eq!(UpstreamHealth::Healthy.to_string(), "Healthy");
        assert_eq!(UpstreamHealth::Degraded.to_string(), "Degraded");
    }
}
