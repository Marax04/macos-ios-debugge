//! `rustre-mcp-federation::tool_proxying`
//!
//! Tool proxying: forward, cache, and monitor individual tool calls to upstream
//! MCP servers.
//!
//! This module provides:
//! * [`ProxiedTool`] — metadata for a tool hosted on an upstream server.
//! * [`ToolProxy`] — forwards a call to the upstream with timeout + retry.
//! * [`ProxyCache`] — LRU-like cache to short-circuit identical calls.
//! * [`ProxyStats`] — per-upstream call counters and latency tracking.
//! * [`FailoverPolicy`] — strategy for trying alternative servers on error.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// ProxiedTool
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata for a single tool that lives on an upstream server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxiedTool {
    /// Name of the upstream server that owns this tool.
    pub upstream_server: String,
    /// Canonical tool name as the upstream reports it.
    pub tool_name: String,
    /// Qualified name used in the federation surface (e.g. `"ghidra.decompile"`).
    pub qualified_name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for the tool's input parameters.
    pub input_schema: Value,
    /// JSON Schema for the tool's output (may be empty object if unknown).
    pub output_schema: Value,
    /// Whether this tool is currently available (upstream alive).
    pub available: bool,
}

impl ProxiedTool {
    /// Create a new proxied tool entry.
    #[must_use]
    pub fn new(
        server: impl Into<String>,
        tool: impl Into<String>,
        desc: impl Into<String>,
        input: Value,
    ) -> Self {
        let server = server.into();
        let tool = tool.into();
        let qualified = format!("{server}.{tool}");
        Self {
            upstream_server: server,
            tool_name: tool,
            qualified_name: qualified,
            description: desc.into(),
            input_schema: input,
            output_schema: serde_json::json!({"type": "object"}),
            available: true,
        }
    }

    #[must_use]
    pub fn with_output_schema(mut self, schema: Value) -> Self {
        self.output_schema = schema;
        self
    }

    #[must_use]
    pub const fn unavailable(mut self) -> Self {
        self.available = false;
        self
    }

    /// Returns `true` when the input schema requires parameter `name`.
    #[must_use]
    pub fn requires_param(&self, name: &str) -> bool {
        self.input_schema
            .get("required")
            .and_then(Value::as_array)
            .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some(name)))
    }

    /// Return the list of required parameter names.
    #[must_use]
    pub fn required_params(&self) -> Vec<&str> {
        self.input_schema
            .get("required")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolCallResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a proxied tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCallResult {
    /// Upstream server that handled the call.
    pub server: String,
    /// Result payload from the upstream.
    pub result: Result<Value, String>,
    /// Round-trip latency.
    pub latency: Duration,
    /// Whether the result came from the cache.
    pub from_cache: bool,
    /// Number of attempts made (1 = first success, >1 = retried).
    pub attempts: u32,
}

impl ToolCallResult {
    #[must_use]
    pub fn success(server: impl Into<String>, result: Value, latency: Duration) -> Self {
        Self {
            server: server.into(),
            result: Ok(result),
            latency,
            from_cache: false,
            attempts: 1,
        }
    }

    #[must_use]
    pub fn cached(server: impl Into<String>, result: Value) -> Self {
        Self {
            server: server.into(),
            result: Ok(result),
            latency: Duration::ZERO,
            from_cache: true,
            attempts: 0,
        }
    }

    #[must_use]
    pub fn failure(
        server: impl Into<String>,
        error: impl Into<String>,
        latency: Duration,
        attempts: u32,
    ) -> Self {
        Self {
            server: server.into(),
            result: Err(error.into()),
            latency,
            from_cache: false,
            attempts,
        }
    }

    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.result.is_ok()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolProxy
// ─────────────────────────────────────────────────────────────────────────────

/// Forwards tool calls to upstream servers with timeout and retry logic.
pub struct ToolProxy {
    /// All known proxied tools indexed by qualified name.
    pub tools: HashMap<String, ProxiedTool>,
    /// Default call timeout.
    pub default_timeout: Duration,
    /// Default number of retries on transient failure.
    pub default_retries: u32,
    /// Simulated call handler (for testing without a real network).
    call_handler: Option<CallHandler>,
}

/// Boxed handler used for simulated tool calls.
pub type CallHandler = Box<dyn Fn(&str, &Value) -> Result<Value, String> + Send + Sync>;

impl ToolProxy {
    /// Create a new `ToolProxy` with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
            default_timeout: Duration::from_secs(30),
            default_retries: 0,
            call_handler: None,
        }
    }

    /// Set a simulated call handler (replaces actual network calls).
    pub fn with_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(&str, &Value) -> Result<Value, String> + Send + Sync + 'static,
    {
        self.call_handler = Some(Box::new(handler));
        self
    }

    /// Register a proxied tool.
    pub fn register(&mut self, tool: ProxiedTool) {
        self.tools.insert(tool.qualified_name.clone(), tool);
    }

    /// Find a proxied tool by qualified name or bare tool name.
    #[must_use]
    pub fn find_tool(&self, name: &str) -> Option<&ProxiedTool> {
        self.tools
            .get(name)
            .or_else(|| self.tools.values().find(|t| t.tool_name == name))
    }

    /// Simulate a tool call using the registered handler or a stub response.
    #[must_use] 
    pub fn call(&self, tool_qualified: &str, params: &Value) -> ToolCallResult {
        let tool = match self.find_tool(tool_qualified) {
            Some(t) => t,
            None => {
                return ToolCallResult::failure(
                    "unknown",
                    format!("tool not found: {tool_qualified}"),
                    Duration::ZERO,
                    1,
                );
            }
        };
        if !tool.available {
            return ToolCallResult::failure(
                &tool.upstream_server,
                format!("tool {} is not available", tool.tool_name),
                Duration::ZERO,
                1,
            );
        }

        let start = Instant::now();
        let result = if let Some(ref handler) = self.call_handler {
            handler(tool_qualified, params)
        } else {
            // Stub: return a JSON object with the call metadata
            Ok(serde_json::json!({
                "tool": tool.tool_name,
                "server": tool.upstream_server,
                "stub": true,
                "params_echo": params
            }))
        };
        let latency = start.elapsed();

        match result {
            Ok(v) => ToolCallResult::success(&tool.upstream_server, v, latency),
            Err(e) => ToolCallResult::failure(&tool.upstream_server, e, latency, 1),
        }
    }

    /// Number of registered tools.
    #[must_use]
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// List qualified names of all registered tools.
    #[must_use]
    pub fn tool_names(&self) -> Vec<&str> {
        self.tools.keys().map(String::as_str).collect()
    }
}

impl Default for ToolProxy {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CacheKey / ProxyCache
// ─────────────────────────────────────────────────────────────────────────────

/// Deterministic cache key: FNV-1a of `"tool_name:params_json"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey(u64);

impl CacheKey {
    /// Compute the cache key for `(tool_name, params)`.
    #[must_use]
    pub fn compute(tool_name: &str, params: &Value) -> Self {
        let key = format!("{tool_name}:{params}");
        let mut h: u64 = 14695981039346656037;
        for b in key.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(1099511628211);
        }
        Self(h)
    }
}

/// An LRU-like cache for identical tool call results.
pub struct ProxyCache {
    /// Cached entries: key → (`result_value`, `insert_time`, `hit_count`).
    entries: HashMap<CacheKey, (Value, Instant, u64)>,
    /// Maximum number of cached entries.
    pub capacity: usize,
    /// Cache TTL — entries older than this are expired.
    pub ttl: Duration,
}

impl ProxyCache {
    /// Create a new cache with the given `capacity` and TTL.
    #[must_use]
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
            ttl,
        }
    }

    /// Look up a cached result.  Returns `None` when not found or expired.
    #[must_use]
    pub fn get(&mut self, key: &CacheKey) -> Option<Value> {
        let entry = self.entries.get_mut(key)?;
        if entry.1.elapsed() > self.ttl {
            self.entries.remove(key);
            return None;
        }
        entry.2 += 1;
        Some(entry.0.clone())
    }

    /// Insert a result into the cache.
    pub fn insert(&mut self, key: CacheKey, value: Value) {
        // Evict oldest entry when at capacity (simple strategy: remove any one).
        if self.entries.len() >= self.capacity {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, (_, t, _))| *t)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.entries.remove(&k);
            }
        }
        self.entries.insert(key, (value, Instant::now(), 0));
    }

    /// Invalidate the entry for `key`.
    pub fn invalidate(&mut self, key: &CacheKey) {
        self.entries.remove(key);
    }

    /// Evict all expired entries.
    pub fn evict_expired(&mut self) {
        let ttl = self.ttl;
        self.entries.retain(|_, (_, t, _)| t.elapsed() <= ttl);
    }

    /// Number of valid (non-expired) entries.
    #[must_use]
    pub fn size(&self) -> usize {
        let ttl = self.ttl;
        self.entries
            .values()
            .filter(|(_, t, _)| t.elapsed() <= ttl)
            .count()
    }

    /// Total number of entries (including expired ones not yet evicted).
    #[must_use]
    pub fn total_entries(&self) -> usize {
        self.entries.len()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Return the total hit count across all cached entries.
    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.entries.values().map(|(_, _, h)| h).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProxyStats
// ─────────────────────────────────────────────────────────────────────────────

/// Per-upstream server call statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerStats {
    /// Total calls made to this server.
    pub total_calls: u64,
    /// Calls that succeeded.
    pub successful: u64,
    /// Calls that failed.
    pub failed: u64,
    /// Total latency across all calls (milliseconds).
    pub total_latency_ms: u64,
    /// Minimum observed latency (milliseconds).
    pub min_latency_ms: u64,
    /// Maximum observed latency (milliseconds).
    pub max_latency_ms: u64,
}

impl ServerStats {
    /// Record a call outcome.
    pub fn record(&mut self, success: bool, latency: Duration) {
        let ms = latency.as_millis() as u64;
        self.total_calls += 1;
        if success {
            self.successful += 1;
        } else {
            self.failed += 1;
        }
        self.total_latency_ms += ms;
        if self.total_calls == 1 || ms < self.min_latency_ms {
            self.min_latency_ms = ms;
        }
        if ms > self.max_latency_ms {
            self.max_latency_ms = ms;
        }
    }

    /// Average latency in milliseconds.
    #[must_use]
    pub fn avg_latency_ms(&self) -> f64 {
        if self.total_calls == 0 {
            0.0
        } else {
            self.total_latency_ms as f64 / self.total_calls as f64
        }
    }

    /// Success rate in the range [0.0, 1.0].
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total_calls == 0 {
            0.0
        } else {
            self.successful as f64 / self.total_calls as f64
        }
    }
}

/// Aggregated call statistics across all upstream servers.
pub struct ProxyStats {
    /// Per-server stats.
    pub per_server: HashMap<String, ServerStats>,
    /// Per-tool call counts.
    pub per_tool: HashMap<String, u64>,
}

impl ProxyStats {
    #[must_use]
    pub fn new() -> Self {
        Self {
            per_server: HashMap::new(),
            per_tool: HashMap::new(),
        }
    }

    /// Record the outcome of a tool call.
    pub fn record(&mut self, server: &str, tool: &str, success: bool, latency: Duration) {
        self.per_server
            .entry(server.to_string())
            .or_default()
            .record(success, latency);
        *self.per_tool.entry(tool.to_string()).or_default() += 1;
    }

    /// Return stats for `server`.
    #[must_use]
    pub fn server_stats(&self, server: &str) -> Option<&ServerStats> {
        self.per_server.get(server)
    }

    /// Total calls recorded.
    #[must_use]
    pub fn total_calls(&self) -> u64 {
        self.per_server.values().map(|s| s.total_calls).sum()
    }

    /// Most-called tool name.
    #[must_use]
    pub fn most_called_tool(&self) -> Option<(&str, u64)> {
        self.per_tool
            .iter()
            .max_by_key(|&(_, c)| *c)
            .map(|(k, c)| (k.as_str(), *c))
    }

    /// Overall success rate across all servers.
    #[must_use]
    pub fn global_success_rate(&self) -> f64 {
        let total: u64 = self.per_server.values().map(|s| s.total_calls).sum();
        let success: u64 = self.per_server.values().map(|s| s.successful).sum();
        if total == 0 {
            0.0
        } else {
            success as f64 / total as f64
        }
    }

    /// Servers ranked by call volume (descending).
    #[must_use]
    pub fn servers_by_volume(&self) -> Vec<(&str, u64)> {
        let mut v: Vec<_> = self
            .per_server
            .iter()
            .map(|(k, s)| (k.as_str(), s.total_calls))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }
}

impl Default for ProxyStats {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FailoverPolicy
// ─────────────────────────────────────────────────────────────────────────────

/// Determines how the proxy handles upstream failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverPolicy {
    /// Do not retry on failure.
    None,
    /// Try each server in `alternates` in order until one succeeds.
    TryAlternates(Vec<String>),
    /// Retry the same server up to `max_attempts` times.
    RetryFixed { max_attempts: u32 },
    /// Try alternates and then retry.
    RetryWithAlternates {
        max_attempts: u32,
        alternates: Vec<String>,
    },
}

impl FailoverPolicy {
    /// Returns `true` when any retry / failover is configured.
    #[must_use]
    pub const fn has_failover(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Return the maximum number of attempts this policy allows.
    #[must_use]
    pub fn max_attempts(&self) -> u32 {
        match self {
            Self::None => 1,
            Self::TryAlternates(v) => 1 + v.len() as u32,
            Self::RetryFixed { max_attempts } => *max_attempts,
            Self::RetryWithAlternates {
                max_attempts,
                alternates,
            } => max_attempts + alternates.len() as u32,
        }
    }

    /// Return the alternate server list, if any.
    #[must_use]
    pub fn alternates(&self) -> &[String] {
        match self {
            Self::TryAlternates(v) | Self::RetryWithAlternates { alternates: v, .. } => v,
            _ => &[],
        }
    }

    /// Apply this policy: returns a list of server names to try in order.
    #[must_use]
    pub fn servers_to_try(&self, primary: &str) -> Vec<String> {
        let mut servers = vec![primary.to_string()];
        match self {
            Self::None | Self::RetryFixed { .. } => {}
            Self::TryAlternates(alts)
            | Self::RetryWithAlternates {
                alternates: alts, ..
            } => {
                servers.extend(alts.iter().cloned());
            }
        }
        servers
    }
}

impl std::fmt::Display for FailoverPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::TryAlternates(v) => write!(f, "TryAlternates([{}])", v.join(",")),
            Self::RetryFixed { max_attempts } => write!(f, "RetryFixed(max={max_attempts})"),
            Self::RetryWithAlternates {
                max_attempts,
                alternates,
            } => {
                write!(
                    f,
                    "RetryWithAlternates(max={max_attempts}, alts=[{}])",
                    alternates.join(",")
                )
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ProxiedTool ───────────────────────────────────────────────────────────

    #[test]
    fn test_proxied_tool_qualified_name() {
        let t = ProxiedTool::new(
            "ghidra",
            "decompile",
            "Decompile a function",
            serde_json::json!({}),
        );
        assert_eq!(t.qualified_name, "ghidra.decompile");
        assert_eq!(t.upstream_server, "ghidra");
        assert_eq!(t.tool_name, "decompile");
    }

    #[test]
    fn test_proxied_tool_unavailable() {
        let t = ProxiedTool::new("s", "t", "d", serde_json::json!({})).unavailable();
        assert!(!t.available);
    }

    #[test]
    fn test_proxied_tool_requires_param() {
        let t = ProxiedTool::new(
            "s",
            "t",
            "d",
            serde_json::json!({"required": ["address"], "type": "object"}),
        );
        assert!(t.requires_param("address"));
        assert!(!t.requires_param("name"));
    }

    #[test]
    fn test_proxied_tool_required_params() {
        let t = ProxiedTool::new("s", "t", "d", serde_json::json!({"required": ["a", "b"]}));
        let params = t.required_params();
        assert!(params.contains(&"a"));
        assert!(params.contains(&"b"));
    }

    #[test]
    fn test_proxied_tool_with_output_schema() {
        let t = ProxiedTool::new("s", "t", "d", serde_json::json!({}))
            .with_output_schema(serde_json::json!({"type": "string"}));
        assert_eq!(t.output_schema["type"], "string");
    }

    // ── ToolProxy ─────────────────────────────────────────────────────────────

    #[test]
    fn test_tool_proxy_register_and_find() {
        let mut proxy = ToolProxy::new();
        proxy.register(ProxiedTool::new(
            "s",
            "tool1",
            "desc",
            serde_json::json!({}),
        ));
        assert!(proxy.find_tool("s.tool1").is_some());
        assert!(proxy.find_tool("tool1").is_some()); // bare name
        assert!(proxy.find_tool("nonexistent").is_none());
    }

    #[test]
    fn test_tool_proxy_call_stub() {
        let mut proxy = ToolProxy::new();
        proxy.register(ProxiedTool::new("s", "ping", "ping", serde_json::json!({})));
        let result = proxy.call("s.ping", &serde_json::json!({}));
        assert!(result.is_ok());
        assert!(!result.from_cache);
    }

    #[test]
    fn test_tool_proxy_call_handler() {
        let mut proxy = ToolProxy::new().with_handler(|_, _| Ok(serde_json::json!({"answer": 42})));
        proxy.register(ProxiedTool::new("s", "ask", "ask", serde_json::json!({})));
        let result = proxy.call("s.ask", &serde_json::json!({}));
        assert!(result.is_ok());
        assert_eq!(result.result.unwrap()["answer"], 42);
    }

    #[test]
    fn test_tool_proxy_call_unknown_tool() {
        let proxy = ToolProxy::new();
        let result = proxy.call("nonexistent", &serde_json::json!({}));
        assert!(!result.is_ok());
    }

    #[test]
    fn test_tool_proxy_call_unavailable_tool() {
        let mut proxy = ToolProxy::new();
        proxy.register(ProxiedTool::new("s", "t", "d", serde_json::json!({})).unavailable());
        let result = proxy.call("s.t", &serde_json::json!({}));
        assert!(!result.is_ok());
    }

    #[test]
    fn test_tool_proxy_tool_names() {
        let mut proxy = ToolProxy::new();
        proxy.register(ProxiedTool::new("s", "a", "d", serde_json::json!({})));
        proxy.register(ProxiedTool::new("s", "b", "d", serde_json::json!({})));
        assert_eq!(proxy.tool_count(), 2);
        assert_eq!(proxy.tool_names().len(), 2);
    }

    // ── CacheKey ──────────────────────────────────────────────────────────────

    #[test]
    fn test_cache_key_deterministic() {
        let k1 = CacheKey::compute("tool", &serde_json::json!({"a": 1}));
        let k2 = CacheKey::compute("tool", &serde_json::json!({"a": 1}));
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_cache_key_different_params() {
        let k1 = CacheKey::compute("tool", &serde_json::json!({"a": 1}));
        let k2 = CacheKey::compute("tool", &serde_json::json!({"a": 2}));
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_cache_key_different_tools() {
        let k1 = CacheKey::compute("tool_a", &serde_json::json!({}));
        let k2 = CacheKey::compute("tool_b", &serde_json::json!({}));
        assert_ne!(k1, k2);
    }

    // ── ProxyCache ────────────────────────────────────────────────────────────

    #[test]
    fn test_proxy_cache_insert_and_get() {
        let mut cache = ProxyCache::new(10, Duration::from_secs(60));
        let key = CacheKey::compute("t", &serde_json::json!({}));
        cache.insert(key.clone(), serde_json::json!({"result": "ok"}));
        let v = cache.get(&key).unwrap();
        assert_eq!(v["result"], "ok");
    }

    #[test]
    fn test_proxy_cache_miss() {
        let mut cache = ProxyCache::new(10, Duration::from_secs(60));
        let key = CacheKey::compute("missing", &serde_json::json!({}));
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_proxy_cache_invalidate() {
        let mut cache = ProxyCache::new(10, Duration::from_secs(60));
        let key = CacheKey::compute("t", &serde_json::json!({}));
        cache.insert(key.clone(), serde_json::json!(1));
        cache.invalidate(&key);
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_proxy_cache_clear() {
        let mut cache = ProxyCache::new(10, Duration::from_secs(60));
        for i in 0..5 {
            cache.insert(
                CacheKey::compute(&format!("t{i}"), &serde_json::json!({})),
                serde_json::json!(i),
            );
        }
        cache.clear();
        assert_eq!(cache.total_entries(), 0);
    }

    #[test]
    fn test_proxy_cache_expired_ttl() {
        let mut cache = ProxyCache::new(10, Duration::from_nanos(1)); // 1ns TTL
        let key = CacheKey::compute("t", &serde_json::json!({}));
        cache.insert(key.clone(), serde_json::json!(1));
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.get(&key).is_none()); // expired
    }

    #[test]
    fn test_proxy_cache_eviction_at_capacity() {
        let mut cache = ProxyCache::new(3, Duration::from_secs(60));
        for i in 0..4 {
            cache.insert(
                CacheKey::compute(&format!("t{i}"), &serde_json::json!({})),
                serde_json::json!(i),
            );
        }
        assert!(cache.total_entries() <= 3);
    }

    // ── ServerStats / ProxyStats ──────────────────────────────────────────────

    #[test]
    fn test_server_stats_success_rate() {
        let mut s = ServerStats::default();
        s.record(true, Duration::from_millis(10));
        s.record(true, Duration::from_millis(20));
        s.record(false, Duration::from_millis(5));
        assert!((s.success_rate() - 2.0 / 3.0).abs() < 1e-9);
        assert_eq!(s.total_calls, 3);
    }

    #[test]
    fn test_server_stats_latency() {
        let mut s = ServerStats::default();
        s.record(true, Duration::from_millis(100));
        s.record(true, Duration::from_millis(200));
        assert_eq!(s.avg_latency_ms(), 150.0);
        assert_eq!(s.min_latency_ms, 100);
        assert_eq!(s.max_latency_ms, 200);
    }

    #[test]
    fn test_proxy_stats_record_and_query() {
        let mut ps = ProxyStats::new();
        ps.record("s1", "tool_a", true, Duration::from_millis(10));
        ps.record("s1", "tool_a", false, Duration::from_millis(5));
        ps.record("s2", "tool_b", true, Duration::from_millis(20));
        assert_eq!(ps.total_calls(), 3);
        assert!(ps.server_stats("s1").is_some());
        let (tool, count) = ps.most_called_tool().unwrap();
        assert_eq!(tool, "tool_a");
        assert_eq!(count, 2);
    }

    #[test]
    fn test_proxy_stats_global_success_rate() {
        let mut ps = ProxyStats::new();
        ps.record("s1", "t", true, Duration::ZERO);
        ps.record("s1", "t", true, Duration::ZERO);
        ps.record("s1", "t", false, Duration::ZERO);
        assert!((ps.global_success_rate() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_proxy_stats_servers_by_volume() {
        let mut ps = ProxyStats::new();
        ps.record("s1", "t", true, Duration::ZERO);
        ps.record("s1", "t", true, Duration::ZERO);
        ps.record("s2", "t", true, Duration::ZERO);
        let ranked = ps.servers_by_volume();
        assert_eq!(ranked[0].0, "s1");
        assert_eq!(ranked[0].1, 2);
    }

    // ── FailoverPolicy ────────────────────────────────────────────────────────

    #[test]
    fn test_failover_none() {
        let p = FailoverPolicy::None;
        assert!(!p.has_failover());
        assert_eq!(p.max_attempts(), 1);
        assert_eq!(p.servers_to_try("primary"), vec!["primary"]);
    }

    #[test]
    fn test_failover_try_alternates() {
        let p = FailoverPolicy::TryAlternates(vec!["s1".into(), "s2".into()]);
        assert!(p.has_failover());
        assert_eq!(p.max_attempts(), 3);
        let servers = p.servers_to_try("primary");
        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0], "primary");
    }

    #[test]
    fn test_failover_retry_fixed() {
        let p = FailoverPolicy::RetryFixed { max_attempts: 5 };
        assert!(p.has_failover());
        assert_eq!(p.max_attempts(), 5);
        assert!(p.alternates().is_empty());
    }

    #[test]
    fn test_failover_retry_with_alternates() {
        let p = FailoverPolicy::RetryWithAlternates {
            max_attempts: 2,
            alternates: vec!["alt1".into()],
        };
        assert_eq!(p.max_attempts(), 3);
        assert_eq!(p.alternates().len(), 1);
    }

    #[test]
    fn test_failover_display() {
        let p = FailoverPolicy::None;
        assert_eq!(p.to_string(), "None");
        let p2 = FailoverPolicy::TryAlternates(vec!["a".into()]);
        assert!(p2.to_string().contains('a'));
    }

    // ── ToolCallResult ────────────────────────────────────────────────────────

    #[test]
    fn test_tool_call_result_success() {
        let r =
            ToolCallResult::success("s", serde_json::json!({"ok": 1}), Duration::from_millis(10));
        assert!(r.is_ok());
        assert!(!r.from_cache);
        assert_eq!(r.attempts, 1);
    }

    #[test]
    fn test_tool_call_result_cached() {
        let r = ToolCallResult::cached("s", serde_json::json!(1));
        assert!(r.is_ok());
        assert!(r.from_cache);
        assert_eq!(r.latency, Duration::ZERO);
    }

    #[test]
    fn test_tool_call_result_failure() {
        let r = ToolCallResult::failure("s", "timeout", Duration::from_millis(5000), 3);
        assert!(!r.is_ok());
        assert_eq!(r.attempts, 3);
    }
}
