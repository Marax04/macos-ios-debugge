//! `federation_metrics` — Latency, error-rate, cache-hit, and session metrics.
//!
//! Provides per-tool/server counters, a rolling histogram, and a
//! Prometheus-compatible text-format exporter.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// HistogramBucket
// ─────────────────────────────────────────────────────────────────────────────

/// Fixed-width histogram with configurable bucket boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Histogram {
    /// Upper bounds of each bucket (ms).
    pub bounds: Vec<u64>,
    /// Count of observations falling into each bucket (cumulative ≤ bound).
    pub counts: Vec<u64>,
    /// Observations exceeding all bounds.
    pub inf_count: u64,
    /// Sum of all observations.
    pub sum: u64,
    /// Total number of observations.
    pub total: u64,
}

impl Histogram {
    /// Create a histogram with the given upper-bound thresholds (ms).
    #[must_use]
    pub fn new(bounds: Vec<u64>) -> Self {
        let n = bounds.len();
        Self {
            bounds,
            counts: vec![0; n],
            inf_count: 0,
            sum: 0,
            total: 0,
        }
    }

    /// Standard RE-suitable buckets: 1, 5, 10, 50, 100, 500, 1000, 5000, +Inf ms.
    #[must_use]
    pub fn re_buckets() -> Self {
        Self::new(vec![1, 5, 10, 50, 100, 500, 1_000, 5_000])
    }

    /// Record a single observation in milliseconds.
    pub fn observe(&mut self, ms: u64) {
        self.sum += ms;
        self.total += 1;
        for (i, &bound) in self.bounds.iter().enumerate() {
            if ms <= bound {
                self.counts[i] += 1;
                return;
            }
        }
        self.inf_count += 1;
    }

    #[must_use]
    pub fn mean_ms(&self) -> f64 {
        if self.total == 0 { 0.0 } else { self.sum as f64 / self.total as f64 }
    }

    /// Approximate p50 / p95 / p99 from the histogram.
    #[must_use]
    pub fn percentile(&self, p: f64) -> u64 {
        if self.total == 0 { return 0; }
        let target = (self.total as f64 * p / 100.0) as u64;
        let mut acc = 0u64;
        for (i, &count) in self.counts.iter().enumerate() {
            acc += count;
            if acc >= target {
                return self.bounds[i];
            }
        }
        // In +Inf bucket — return 2× the last bound as a proxy
        self.bounds.last().copied().unwrap_or(0) * 2
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolMetrics — per-tool counters
// ─────────────────────────────────────────────────────────────────────────────

/// Metrics for a single (tool, server) pair.
#[derive(Debug)]
pub struct ToolMetrics {
    pub tool_name: String,
    pub server_name: String,
    calls: AtomicU64,
    errors: AtomicU64,
    cache_hits: AtomicU64,
    total_latency_ms: AtomicU64,
    min_latency_ms: AtomicU64,
    max_latency_ms: AtomicU64,
}

impl ToolMetrics {
    #[must_use]
    pub fn new(tool_name: impl Into<String>, server_name: impl Into<String>) -> Self {
        Self {
            tool_name: tool_name.into(),
            server_name: server_name.into(),
            calls: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            min_latency_ms: AtomicU64::new(u64::MAX),
            max_latency_ms: AtomicU64::new(0),
        }
    }

    /// Record a call outcome.
    pub fn record(&self, latency_ms: u64, success: bool, from_cache: bool) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
        if from_cache {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
        }
        self.total_latency_ms.fetch_add(latency_ms, Ordering::Relaxed);
        // Update min
        let mut cur_min = self.min_latency_ms.load(Ordering::Relaxed);
        while latency_ms < cur_min {
            match self.min_latency_ms.compare_exchange_weak(
                cur_min, latency_ms, Ordering::Relaxed, Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(v) => cur_min = v,
            }
        }
        // Update max
        let mut cur_max = self.max_latency_ms.load(Ordering::Relaxed);
        while latency_ms > cur_max {
            match self.max_latency_ms.compare_exchange_weak(
                cur_max, latency_ms, Ordering::Relaxed, Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(v) => cur_max = v,
            }
        }
    }

    #[must_use]
    pub fn calls(&self) -> u64 { self.calls.load(Ordering::Relaxed) }
    #[must_use]
    pub fn errors(&self) -> u64 { self.errors.load(Ordering::Relaxed) }
    #[must_use]
    pub fn cache_hits(&self) -> u64 { self.cache_hits.load(Ordering::Relaxed) }

    #[must_use]
    pub fn error_rate(&self) -> f64 {
        let c = self.calls();
        if c == 0 { 0.0 } else { self.errors() as f64 / c as f64 }
    }

    #[must_use]
    pub fn cache_hit_rate(&self) -> f64 {
        let c = self.calls();
        if c == 0 { 0.0 } else { self.cache_hits() as f64 / c as f64 }
    }

    #[must_use]
    pub fn avg_latency_ms(&self) -> f64 {
        let c = self.calls();
        if c == 0 { 0.0 } else { self.total_latency_ms.load(Ordering::Relaxed) as f64 / c as f64 }
    }

    #[must_use]
    pub fn min_latency_ms(&self) -> u64 {
        let v = self.min_latency_ms.load(Ordering::Relaxed);
        if v == u64::MAX { 0 } else { v }
    }

    #[must_use]
    pub fn max_latency_ms(&self) -> u64 {
        self.max_latency_ms.load(Ordering::Relaxed)
    }

    /// Serialise to a snapshot value.
    #[must_use]
    pub fn snapshot(&self) -> ToolMetricsSnapshot {
        ToolMetricsSnapshot {
            tool_name: self.tool_name.clone(),
            server_name: self.server_name.clone(),
            calls: self.calls(),
            errors: self.errors(),
            cache_hits: self.cache_hits(),
            error_rate: self.error_rate(),
            cache_hit_rate: self.cache_hit_rate(),
            avg_latency_ms: self.avg_latency_ms(),
            min_latency_ms: self.min_latency_ms(),
            max_latency_ms: self.max_latency_ms(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMetricsSnapshot {
    pub tool_name: String,
    pub server_name: String,
    pub calls: u64,
    pub errors: u64,
    pub cache_hits: u64,
    pub error_rate: f64,
    pub cache_hit_rate: f64,
    pub avg_latency_ms: f64,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// ServerMetrics — aggregated per-server counters
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ServerMetrics {
    pub name: String,
    pub active_sessions: AtomicU64,
    pub total_calls: AtomicU64,
    pub total_errors: AtomicU64,
    pub total_latency_ms: AtomicU64,
    pub reconnects: AtomicU64,
    pub health_checks_ok: AtomicU64,
    pub health_checks_fail: AtomicU64,
}

impl ServerMetrics {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            ..Default::default()
        })
    }

    pub fn record_call(&self, latency_ms: u64, ok: bool) {
        self.total_calls.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms.fetch_add(latency_ms, Ordering::Relaxed);
        if !ok {
            self.total_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_health_check(&self, ok: bool) {
        if ok {
            self.health_checks_ok.fetch_add(1, Ordering::Relaxed);
        } else {
            self.health_checks_fail.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn avg_latency_ms(&self) -> f64 {
        let c = self.total_calls.load(Ordering::Relaxed);
        if c == 0 { 0.0 } else { self.total_latency_ms.load(Ordering::Relaxed) as f64 / c as f64 }
    }

    #[must_use]
    pub fn error_rate(&self) -> f64 {
        let c = self.total_calls.load(Ordering::Relaxed);
        if c == 0 { 0.0 } else { self.total_errors.load(Ordering::Relaxed) as f64 / c as f64 }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FederationMetrics — central registry
// ─────────────────────────────────────────────────────────────────────────────

/// Central metrics registry for the federation layer.
pub struct FederationMetrics {
    /// Per (tool, server) metrics.
    tool_metrics: DashMap<(String, String), Arc<ToolMetrics>>,
    /// Per-server aggregated metrics.
    server_metrics: DashMap<String, Arc<ServerMetrics>>,
    /// Per-tool latency histograms.
    histograms: DashMap<String, parking_lot::Mutex<Histogram>>,
    /// Global counters.
    global_calls: AtomicU64,
    global_errors: AtomicU64,
    global_cache_hits: AtomicU64,
    /// When metrics collection started.
    started_at: Instant,
}

impl FederationMetrics {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tool_metrics: DashMap::new(),
            server_metrics: DashMap::new(),
            histograms: DashMap::new(),
            global_calls: AtomicU64::new(0),
            global_errors: AtomicU64::new(0),
            global_cache_hits: AtomicU64::new(0),
            started_at: Instant::now(),
        })
    }

    // ── Recording ───────────────────────────────────────────────────────────

    /// Record a completed tool call.
    pub fn record_call(
        &self,
        tool_name: &str,
        server_name: &str,
        latency_ms: u64,
        success: bool,
        from_cache: bool,
    ) {
        // Global counters
        self.global_calls.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.global_errors.fetch_add(1, Ordering::Relaxed);
        }
        if from_cache {
            self.global_cache_hits.fetch_add(1, Ordering::Relaxed);
        }

        // Per-(tool, server) metrics
        let key = (tool_name.to_string(), server_name.to_string());
        let m = self.tool_metrics.entry(key).or_insert_with(|| {
            Arc::new(ToolMetrics::new(tool_name, server_name))
        });
        m.record(latency_ms, success, from_cache);

        // Per-server metrics
        self.server_metrics
            .entry(server_name.to_string())
            .or_insert_with(|| ServerMetrics::new(server_name))
            .record_call(latency_ms, success);

        // Histogram
        self.histograms
            .entry(tool_name.to_string())
            .or_insert_with(|| parking_lot::Mutex::new(Histogram::re_buckets()))
            .lock()
            .observe(latency_ms);
    }

    /// Record a health-check result for a server.
    pub fn record_health_check(&self, server_name: &str, ok: bool) {
        self.server_metrics
            .entry(server_name.to_string())
            .or_insert_with(|| ServerMetrics::new(server_name))
            .record_health_check(ok);
    }

    /// Update active session count for a server.
    pub fn set_active_sessions(&self, server_name: &str, count: u64) {
        self.server_metrics
            .entry(server_name.to_string())
            .or_insert_with(|| ServerMetrics::new(server_name))
            .active_sessions
            .store(count, Ordering::Relaxed);
    }

    // ── Queries ─────────────────────────────────────────────────────────────

    #[must_use]
    pub fn global_calls(&self) -> u64 { self.global_calls.load(Ordering::Relaxed) }
    #[must_use]
    pub fn global_errors(&self) -> u64 { self.global_errors.load(Ordering::Relaxed) }
    #[must_use]
    pub fn global_cache_hits(&self) -> u64 { self.global_cache_hits.load(Ordering::Relaxed) }

    #[must_use]
    pub fn global_error_rate(&self) -> f64 {
        let c = self.global_calls();
        if c == 0 { 0.0 } else { self.global_errors() as f64 / c as f64 }
    }

    #[must_use]
    pub fn global_cache_hit_rate(&self) -> f64 {
        let c = self.global_calls();
        if c == 0 { 0.0 } else { self.global_cache_hits() as f64 / c as f64 }
    }

    /// Snapshot all tool metrics.
    #[must_use]
    pub fn tool_snapshots(&self) -> Vec<ToolMetricsSnapshot> {
        self.tool_metrics.iter().map(|e| e.value().snapshot()).collect()
    }

    /// Get histogram for a tool.
    #[must_use]
    pub fn histogram_snapshot(&self, tool_name: &str) -> Option<Histogram> {
        self.histograms.get(tool_name).map(|h| h.lock().clone())
    }

    /// Uptime since metrics were initialised.
    #[must_use]
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    // ── Prometheus export ───────────────────────────────────────────────────

    /// Export all metrics in Prometheus text exposition format.
    #[must_use]
    pub fn export_prometheus(&self) -> String {
        let mut out = String::with_capacity(4096);

        // Helper macro-like closure
        let mut g = |name: &str, help: &str, value: f64| {
            out.push_str(&format!("# HELP {name} {help}\n"));
            out.push_str(&format!("# TYPE {name} gauge\n"));
            out.push_str(&format!("{name} {value}\n"));
        };

        g("rustre_mcp_calls_total", "Total MCP tool calls", self.global_calls() as f64);
        g("rustre_mcp_errors_total", "Total MCP tool errors", self.global_errors() as f64);
        g("rustre_mcp_cache_hits_total", "Total cache hits", self.global_cache_hits() as f64);
        g("rustre_mcp_error_rate", "Global error rate", self.global_error_rate());
        g("rustre_mcp_cache_hit_rate", "Global cache hit rate", self.global_cache_hit_rate());
        g("rustre_mcp_uptime_seconds", "Federation uptime in seconds", self.uptime().as_secs_f64());

        // Per-tool metrics
        out.push_str("# HELP rustre_mcp_tool_calls_total Per-tool call count\n");
        out.push_str("# TYPE rustre_mcp_tool_calls_total counter\n");
        for snap in self.tool_snapshots() {
            out.push_str(&format!(
                "rustre_mcp_tool_calls_total{{tool=\"{}\",server=\"{}\"}} {}\n",
                snap.tool_name, snap.server_name, snap.calls
            ));
        }

        out.push_str("# HELP rustre_mcp_tool_errors_total Per-tool error count\n");
        out.push_str("# TYPE rustre_mcp_tool_errors_total counter\n");
        for snap in self.tool_snapshots() {
            out.push_str(&format!(
                "rustre_mcp_tool_errors_total{{tool=\"{}\",server=\"{}\"}} {}\n",
                snap.tool_name, snap.server_name, snap.errors
            ));
        }

        out.push_str("# HELP rustre_mcp_tool_avg_latency_ms Average tool latency (ms)\n");
        out.push_str("# TYPE rustre_mcp_tool_avg_latency_ms gauge\n");
        for snap in self.tool_snapshots() {
            out.push_str(&format!(
                "rustre_mcp_tool_avg_latency_ms{{tool=\"{}\",server=\"{}\"}} {:.2}\n",
                snap.tool_name, snap.server_name, snap.avg_latency_ms
            ));
        }

        // Per-server
        out.push_str("# HELP rustre_mcp_server_active_sessions Active sessions per server\n");
        out.push_str("# TYPE rustre_mcp_server_active_sessions gauge\n");
        for entry in self.server_metrics.iter() {
            let n = entry.active_sessions.load(Ordering::Relaxed);
            out.push_str(&format!(
                "rustre_mcp_server_active_sessions{{server=\"{}\"}} {n}\n",
                entry.name
            ));
        }

        out.push_str("# HELP rustre_mcp_server_error_rate Error rate per server\n");
        out.push_str("# TYPE rustre_mcp_server_error_rate gauge\n");
        for entry in self.server_metrics.iter() {
            out.push_str(&format!(
                "rustre_mcp_server_error_rate{{server=\"{}\"}} {:.4}\n",
                entry.name,
                entry.error_rate()
            ));
        }

        // Histograms
        out.push_str("# HELP rustre_mcp_tool_latency_ms Tool call latency histogram (ms)\n");
        out.push_str("# TYPE rustre_mcp_tool_latency_ms histogram\n");
        for kv in self.histograms.iter() {
            let tool = kv.key();
            let h = kv.value().lock().clone();
            let mut cum = 0u64;
            for (i, &bound) in h.bounds.iter().enumerate() {
                cum += h.counts[i];
                out.push_str(&format!(
                    "rustre_mcp_tool_latency_ms_bucket{{tool=\"{tool}\",le=\"{bound}\"}} {cum}\n"
                ));
            }
            cum += h.inf_count;
            out.push_str(&format!(
                "rustre_mcp_tool_latency_ms_bucket{{tool=\"{tool}\",le=\"+Inf\"}} {cum}\n"
            ));
            out.push_str(&format!(
                "rustre_mcp_tool_latency_ms_sum{{tool=\"{tool}\"}} {}\n", h.sum
            ));
            out.push_str(&format!(
                "rustre_mcp_tool_latency_ms_count{{tool=\"{tool}\"}} {}\n", h.total
            ));
        }

        out
    }

    /// Export a compact JSON summary.
    #[must_use]
    pub fn export_json(&self) -> serde_json::Value {
        serde_json::json!({
            "global": {
                "calls": self.global_calls(),
                "errors": self.global_errors(),
                "cache_hits": self.global_cache_hits(),
                "error_rate": self.global_error_rate(),
                "cache_hit_rate": self.global_cache_hit_rate(),
                "uptime_secs": self.uptime().as_secs(),
            },
            "tools": self.tool_snapshots(),
        })
    }
}

impl Default for FederationMetrics {
    fn default() -> Self {
        Self {
            tool_metrics: DashMap::new(),
            server_metrics: DashMap::new(),
            histograms: DashMap::new(),
            global_calls: AtomicU64::new(0),
            global_errors: AtomicU64::new(0),
            global_cache_hits: AtomicU64::new(0),
            started_at: Instant::now(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_query() {
        let m = FederationMetrics::new();
        m.record_call("decompile", "ghidra", 50, true, false);
        m.record_call("decompile", "ghidra", 100, false, false);
        m.record_call("disasm", "ghidra", 10, true, true);
        assert_eq!(m.global_calls(), 3);
        assert_eq!(m.global_errors(), 1);
        assert_eq!(m.global_cache_hits(), 1);
        assert!((m.global_error_rate() - 1.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_tool_metrics_snapshot() {
        let m = FederationMetrics::new();
        m.record_call("decompile", "ghidra", 42, true, false);
        let snaps = m.tool_snapshots();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].tool_name, "decompile");
        assert_eq!(snaps[0].calls, 1);
        assert_eq!(snaps[0].avg_latency_ms, 42.0);
    }

    #[test]
    fn test_histogram_observe() {
        let mut h = Histogram::re_buckets();
        h.observe(5);
        h.observe(50);
        h.observe(10_000);
        assert_eq!(h.total, 3);
        assert!(h.inf_count > 0);
        let p50 = h.percentile(50.0);
        assert!(p50 > 0);
    }

    #[test]
    fn test_prometheus_export_contains_keys() {
        let m = FederationMetrics::new();
        m.record_call("ping", "ghidra", 5, true, false);
        let prom = m.export_prometheus();
        assert!(prom.contains("rustre_mcp_calls_total"));
        assert!(prom.contains("rustre_mcp_tool_calls_total"));
        assert!(prom.contains("rustre_mcp_tool_latency_ms_bucket"));
        assert!(prom.contains("ghidra"));
    }

    #[test]
    fn test_json_export() {
        let m = FederationMetrics::new();
        m.record_call("tool", "srv", 10, true, false);
        let json = m.export_json();
        assert_eq!(json["global"]["calls"], 1);
    }

    #[test]
    fn test_active_sessions() {
        let m = FederationMetrics::new();
        m.set_active_sessions("ghidra", 5);
        let entry = m.server_metrics.get("ghidra").unwrap();
        assert_eq!(entry.active_sessions.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn test_health_check_metrics() {
        let m = FederationMetrics::new();
        m.record_health_check("ghidra", true);
        m.record_health_check("ghidra", false);
        let entry = m.server_metrics.get("ghidra").unwrap();
        assert_eq!(entry.health_checks_ok.load(Ordering::Relaxed), 1);
        assert_eq!(entry.health_checks_fail.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_histogram_percentile_empty() {
        let h = Histogram::re_buckets();
        assert_eq!(h.percentile(99.0), 0);
        assert_eq!(h.mean_ms(), 0.0);
    }

    #[test]
    fn test_tool_metrics_min_max() {
        let tm = ToolMetrics::new("t", "s");
        tm.record(10, true, false);
        tm.record(50, true, false);
        tm.record(30, false, false);
        assert_eq!(tm.min_latency_ms(), 10);
        assert_eq!(tm.max_latency_ms(), 50);
    }

    #[test]
    fn test_cache_hit_rate() {
        let m = FederationMetrics::new();
        m.record_call("t", "s", 5, true, true);
        m.record_call("t", "s", 100, true, false);
        assert!((m.global_cache_hit_rate() - 0.5).abs() < 1e-9);
    }
}
