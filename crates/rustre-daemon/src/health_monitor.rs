//! `health_monitor` — continuous daemon health monitoring.
//!
//! Tracks memory usage, connected-client count, work-queue depth, and any
//! user-defined probes.  A background task (driven by the caller's tokio
//! runtime) can fire periodic checks and publish results to a broadcast
//! channel so consumers (e.g. the REST `/health` endpoint) can read the
//! most recent snapshot without waiting.
//!
//! # Notes
//! All `pub fn` returning `Result` carry `/// # Errors`.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors from the health monitor.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MonitorError {
    /// A probe function panicked.
    #[error("probe '{name}' panicked: {detail}")]
    ProbePanic { name: String, detail: String },

    /// The monitor channel was closed.
    #[error("health monitor channel closed")]
    ChannelClosed,

    /// Configuration is invalid.
    #[error("monitor config error: {0}")]
    Config(String),
}

// ── HealthStatus ──────────────────────────────────────────────────────────────

/// Overall health status of the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HealthStatus {
    /// All probes pass.
    Healthy,
    /// One or more probes are degraded but not critical.
    Degraded,
    /// One or more critical probes have failed.
    Unhealthy,
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

// ── ProbeResult ───────────────────────────────────────────────────────────────

/// The result of a single named health probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Probe name.
    pub name: String,
    /// Whether the probe passed.
    pub passed: bool,
    /// Human-readable detail message.
    pub detail: String,
    /// Latency of this probe in milliseconds.
    pub latency_ms: u64,
    /// Whether this probe is critical (failure → `Unhealthy`).
    pub critical: bool,
}

impl ProbeResult {
    /// Create a passing probe result.
    #[must_use]
    pub fn pass(name: impl Into<String>, detail: impl Into<String>, latency_ms: u64) -> Self {
        Self {
            name: name.into(),
            passed: true,
            detail: detail.into(),
            latency_ms,
            critical: false,
        }
    }

    /// Create a failing probe result.
    #[must_use]
    pub fn fail(name: impl Into<String>, detail: impl Into<String>, latency_ms: u64) -> Self {
        Self {
            name: name.into(),
            passed: false,
            detail: detail.into(),
            latency_ms,
            critical: false,
        }
    }

    /// Mark this probe as critical.
    #[must_use]
    pub const fn critical(mut self) -> Self {
        self.critical = true;
        self
    }
}

// ── ResourceSnapshot ─────────────────────────────────────────────────────────

/// Point-in-time resource usage snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    /// Approximate resident set size in bytes (0 if not measurable on platform).
    pub rss_bytes: u64,
    /// Number of currently connected clients.
    pub connected_clients: u64,
    /// Current work-queue depth.
    pub queue_depth: u64,
    /// Number of pending requests (may differ from queue_depth on some implementations).
    pub pending_requests: u64,
    /// CPU percentage as an integer (0–100, approximate).
    pub cpu_percent: u8,
    /// Uptime in seconds.
    pub uptime_secs: u64,
}

impl ResourceSnapshot {
    /// Create a snapshot with all counters supplied.
    #[must_use]
    pub const fn new(
        rss_bytes: u64,
        connected_clients: u64,
        queue_depth: u64,
        pending_requests: u64,
        cpu_percent: u8,
        uptime_secs: u64,
    ) -> Self {
        Self {
            rss_bytes,
            connected_clients,
            queue_depth,
            pending_requests,
            cpu_percent,
            uptime_secs,
        }
    }

    /// Zero snapshot (useful as a default when platform metrics are unavailable).
    #[must_use]
    pub const fn zero() -> Self {
        Self::new(0, 0, 0, 0, 0, 0)
    }
}

// ── HealthReport ──────────────────────────────────────────────────────────────

/// A complete health report produced by one monitoring cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    /// Aggregate health status.
    pub status: HealthStatus,
    /// Individual probe results.
    pub probes: Vec<ProbeResult>,
    /// Resource snapshot at report time.
    pub resources: ResourceSnapshot,
    /// Epoch-seconds when the report was generated.
    pub timestamp: u64,
    /// Total time taken to run all probes in milliseconds.
    pub total_latency_ms: u64,
    /// Monotonic check sequence number.
    pub check_number: u64,
}

impl HealthReport {
    /// Build a report from probe results and a resource snapshot.
    #[must_use]
    pub fn build(probes: Vec<ProbeResult>, resources: ResourceSnapshot, check_number: u64, start: Instant) -> Self {
        let status = aggregate_status(&probes);
        let total_latency_ms = start.elapsed().as_millis() as u64;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self {
            status,
            probes,
            resources,
            timestamp,
            total_latency_ms,
            check_number,
        }
    }

    /// Return `true` if all probes passed.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.status == HealthStatus::Healthy
    }

    /// Return all failing probe names.
    #[must_use]
    pub fn failing_probes(&self) -> Vec<&str> {
        self.probes.iter()
            .filter(|p| !p.passed)
            .map(|p| p.name.as_str())
            .collect()
    }

    /// Render a compact human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let failures = self.failing_probes();
        if failures.is_empty() {
            format!("[{}] all {} probes passed in {}ms",
                self.status, self.probes.len(), self.total_latency_ms)
        } else {
            format!("[{}] {} probes failed: {} — {}ms",
                self.status, failures.len(), failures.join(", "), self.total_latency_ms)
        }
    }
}

impl fmt::Display for HealthReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "HealthReport #{} — {}", self.check_number, self.status)?;
        writeln!(f, "  RSS: {} KiB  clients: {}  queue: {}",
            self.resources.rss_bytes / 1024,
            self.resources.connected_clients,
            self.resources.queue_depth)?;
        for p in &self.probes {
            let icon = if p.passed { "OK  " } else { "FAIL" };
            writeln!(f, "  [{icon}] {} ({}ms) — {}", p.name, p.latency_ms, p.detail)?;
        }
        Ok(())
    }
}

fn aggregate_status(probes: &[ProbeResult]) -> HealthStatus {
    let has_critical_fail = probes.iter().any(|p| p.critical && !p.passed);
    let has_any_fail = probes.iter().any(|p| !p.passed);
    if has_critical_fail {
        HealthStatus::Unhealthy
    } else if has_any_fail {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    }
}

// ── ProbeFn ───────────────────────────────────────────────────────────────────

/// A registered probe entry.
struct ProbeEntry {
    name: String,
    critical: bool,
    func: Box<dyn Fn() -> ProbeResult + Send + Sync + 'static>,
}

// ── MonitorConfig ─────────────────────────────────────────────────────────────

/// Configuration for [`HealthMonitor`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    /// How often periodic checks fire (seconds).
    pub check_interval_secs: u64,
    /// Maximum history depth kept in the ring buffer.
    pub history_depth: usize,
    /// Whether to log each report to stderr.
    pub log_reports: bool,
    /// RSS warning threshold (bytes; 0 = disabled).
    pub rss_warn_bytes: u64,
    /// Queue depth warning threshold (0 = disabled).
    pub queue_warn_depth: u64,
    /// Maximum clients warning threshold (0 = disabled).
    pub max_clients_warn: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 30,
            history_depth: 100,
            log_reports: false,
            rss_warn_bytes: 512 * 1024 * 1024, // 512 MiB
            queue_warn_depth: 1000,
            max_clients_warn: 50,
        }
    }
}

// ── Counters ──────────────────────────────────────────────────────────────────

/// Shared atomic counters injected into the monitor by the daemon.
///
/// The daemon increments these as work arrives/completes and clients connect/
/// disconnect.  The monitor reads them atomically during each check cycle.
#[derive(Debug, Default)]
pub struct DaemonCounters {
    /// Currently connected clients.
    pub connected_clients: AtomicU64,
    /// Pending items in the work queue.
    pub queue_depth: AtomicU64,
    /// Pending request count.
    pub pending_requests: AtomicU64,
    /// Total checks performed by the monitor.
    pub check_count: AtomicU64,
}

impl DaemonCounters {
    /// Create zeroed counters.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Increment the connected client counter by 1.
    pub fn client_connected(&self) {
        self.connected_clients.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the connected client counter by 1 (floor 0).
    pub fn client_disconnected(&self) {
        self.connected_clients.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(1))
        }).ok();
    }

    /// Enqueue one work item.
    pub fn enqueue(&self) {
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    /// Dequeue one work item.
    pub fn dequeue(&self) {
        self.queue_depth.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(1))
        }).ok();
    }

    /// Read current values.
    pub fn read(&self) -> (u64, u64, u64) {
        (
            self.connected_clients.load(Ordering::Relaxed),
            self.queue_depth.load(Ordering::Relaxed),
            self.pending_requests.load(Ordering::Relaxed),
        )
    }
}

// ── HealthMonitor ─────────────────────────────────────────────────────────────

/// Coordinates all health probes and maintains a history ring buffer.
///
/// Call [`periodic_check`] in a loop (or drive it from a tokio task) to
/// execute all registered probes and update the internal history.
pub struct HealthMonitor {
    config: MonitorConfig,
    probes: RwLock<Vec<ProbeEntry>>,
    history: Mutex<VecDeque<HealthReport>>,
    counters: Arc<DaemonCounters>,
    start_time: Instant,
    check_sequence: AtomicU64,
    /// Most recent report, readable without locking the full history.
    latest: RwLock<Option<HealthReport>>,
}

impl HealthMonitor {
    /// Create a monitor with the given config and counters.
    #[must_use]
    pub fn new(config: MonitorConfig, counters: Arc<DaemonCounters>) -> Arc<Self> {
        Arc::new(Self {
            config,
            probes: RwLock::new(Vec::new()),
            history: Mutex::new(VecDeque::new()),
            counters,
            start_time: Instant::now(),
            check_sequence: AtomicU64::new(0),
            latest: RwLock::new(None),
        })
    }

    /// Register a health probe.
    ///
    /// If `critical` is `true`, a failure from this probe sets the overall
    /// status to [`HealthStatus::Unhealthy`] rather than [`HealthStatus::Degraded`].
    pub fn add_probe(
        &self,
        name: impl Into<String>,
        critical: bool,
        func: impl Fn() -> ProbeResult + Send + Sync + 'static,
    ) {
        self.probes.write().push(ProbeEntry {
            name: name.into(),
            critical,
            func: Box::new(func),
        });
    }

    /// Run all registered probes once, store the result in history, and return
    /// the fresh [`HealthReport`].
    ///
    /// Also runs built-in resource probes (RSS threshold, queue depth, client count).
    pub fn periodic_check(&self) -> HealthReport {
        let start = Instant::now();
        let seq = self.check_sequence.fetch_add(1, Ordering::Relaxed);

        // Build resource snapshot.
        let (clients, queue, pending) = self.counters.read();
        let uptime = self.start_time.elapsed().as_secs();
        let rss = current_rss_bytes();
        let resources = ResourceSnapshot::new(rss, clients, queue, pending, 0, uptime);

        // Run built-in probes.
        let mut results: Vec<ProbeResult> = Vec::new();

        // RSS probe.
        if self.config.rss_warn_bytes > 0 {
            let t = Instant::now();
            let r = if rss > self.config.rss_warn_bytes {
                ProbeResult::fail(
                    "rss",
                    format!("RSS {rss} B > threshold {}", self.config.rss_warn_bytes),
                    t.elapsed().as_millis() as u64,
                )
            } else {
                ProbeResult::pass("rss", format!("RSS {rss} B"), t.elapsed().as_millis() as u64)
            };
            results.push(r);
        }

        // Queue depth probe.
        if self.config.queue_warn_depth > 0 {
            let t = Instant::now();
            let r = if queue > self.config.queue_warn_depth {
                ProbeResult::fail(
                    "queue_depth",
                    format!("queue {queue} > threshold {}", self.config.queue_warn_depth),
                    t.elapsed().as_millis() as u64,
                )
            } else {
                ProbeResult::pass("queue_depth", format!("queue {queue}"), t.elapsed().as_millis() as u64)
            };
            results.push(r);
        }

        // Client count probe.
        if self.config.max_clients_warn > 0 {
            let t = Instant::now();
            let r = if clients > self.config.max_clients_warn {
                ProbeResult::fail(
                    "client_count",
                    format!("{clients} clients > threshold {}", self.config.max_clients_warn),
                    t.elapsed().as_millis() as u64,
                )
            } else {
                ProbeResult::pass("client_count", format!("{clients} clients"), t.elapsed().as_millis() as u64)
            };
            results.push(r);
        }

        // User-defined probes.
        {
            let probes = self.probes.read();
            for entry in probes.iter() {
                let t = Instant::now();
                let mut res = (entry.func)();
                res.latency_ms = t.elapsed().as_millis() as u64;
                res.critical = entry.critical;
                // If the probe closure returned an empty name, fall back to
                // the name supplied at registration time so the report is
                // always self-describing.
                if res.name.is_empty() {
                    res.name = entry.name.clone();
                }
                results.push(res);
            }
        }

        let report = HealthReport::build(results, resources, seq, start);

        if self.config.log_reports {
            eprintln!("[health_monitor] {}", report.summary());
        }

        // Store in history.
        let mut hist = self.history.lock();
        if hist.len() >= self.config.history_depth {
            hist.pop_front();
        }
        hist.push_back(report.clone());

        // Update latest.
        *self.latest.write() = Some(report.clone());

        self.counters.check_count.fetch_add(1, Ordering::Relaxed);
        report
    }

    /// Return the most recent health report without running a new check.
    #[must_use]
    pub fn latest_report(&self) -> Option<HealthReport> {
        self.latest.read().clone()
    }

    /// Return the last N reports from the history ring buffer.
    #[must_use]
    pub fn history(&self, last_n: usize) -> Vec<HealthReport> {
        let hist = self.history.lock();
        hist.iter().rev().take(last_n).cloned().collect()
    }

    /// Clear the history buffer.
    pub fn clear_history(&self) {
        self.history.lock().clear();
    }

    /// Number of probes registered.
    #[must_use]
    pub fn probe_count(&self) -> usize {
        self.probes.read().len()
    }

    /// Return the daemon uptime.
    #[must_use]
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Return the total number of checks performed.
    #[must_use]
    pub fn check_count(&self) -> u64 {
        self.counters.check_count.load(Ordering::Relaxed)
    }
}

/// Attempt to read the resident-set size of the current process in bytes.
///
/// Returns 0 on platforms where this is not implemented.
fn current_rss_bytes() -> u64 {
    // On Linux, parse /proc/self/status VmRSS.
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    let kb: u64 = rest
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    return kb * 1024;
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_monitor() -> Arc<HealthMonitor> {
        let config = MonitorConfig {
            log_reports: false,
            rss_warn_bytes: 0,     // disable built-in probes for most tests
            queue_warn_depth: 0,
            max_clients_warn: 0,
            ..Default::default()
        };
        HealthMonitor::new(config, DaemonCounters::new())
    }

    // ── HealthStatus ──────────────────────────────────────────────────────────

    #[test]
    fn test_status_display() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Degraded.to_string(), "degraded");
        assert_eq!(HealthStatus::Unhealthy.to_string(), "unhealthy");
    }

    #[test]
    fn test_status_ordering() {
        assert!(HealthStatus::Unhealthy > HealthStatus::Degraded);
        assert!(HealthStatus::Degraded > HealthStatus::Healthy);
    }

    // ── ProbeResult ───────────────────────────────────────────────────────────

    #[test]
    fn test_probe_pass() {
        let p = ProbeResult::pass("disk", "ok", 1);
        assert!(p.passed);
        assert!(!p.critical);
    }

    #[test]
    fn test_probe_fail_critical() {
        let p = ProbeResult::fail("db", "timeout", 50).critical();
        assert!(!p.passed);
        assert!(p.critical);
    }

    // ── aggregate_status ──────────────────────────────────────────────────────

    #[test]
    fn test_aggregate_all_pass() {
        let probes = vec![
            ProbeResult::pass("a", "ok", 1),
            ProbeResult::pass("b", "ok", 2),
        ];
        assert_eq!(aggregate_status(&probes), HealthStatus::Healthy);
    }

    #[test]
    fn test_aggregate_non_critical_fail() {
        let probes = vec![
            ProbeResult::pass("a", "ok", 1),
            ProbeResult::fail("b", "slow", 100),
        ];
        assert_eq!(aggregate_status(&probes), HealthStatus::Degraded);
    }

    #[test]
    fn test_aggregate_critical_fail() {
        let probes = vec![
            ProbeResult::pass("a", "ok", 1),
            ProbeResult::fail("b", "dead", 100).critical(),
        ];
        assert_eq!(aggregate_status(&probes), HealthStatus::Unhealthy);
    }

    // ── HealthMonitor::periodic_check ─────────────────────────────────────────

    #[test]
    fn test_monitor_no_probes_healthy() {
        let m = make_monitor();
        let report = m.periodic_check();
        assert_eq!(report.status, HealthStatus::Healthy);
        assert!(report.is_healthy());
    }

    #[test]
    fn test_monitor_passing_probe() {
        let m = make_monitor();
        m.add_probe("disk", false, || ProbeResult::pass("disk", "ok", 0));
        let report = m.periodic_check();
        assert_eq!(report.status, HealthStatus::Healthy);
        assert_eq!(report.probes.len(), 1);
    }

    #[test]
    fn test_monitor_failing_probe_degraded() {
        let m = make_monitor();
        m.add_probe("net", false, || ProbeResult::fail("net", "timeout", 100));
        let report = m.periodic_check();
        assert_eq!(report.status, HealthStatus::Degraded);
    }

    #[test]
    fn test_monitor_critical_probe_unhealthy() {
        let m = make_monitor();
        m.add_probe("db", true, || ProbeResult::fail("db", "gone", 200));
        let report = m.periodic_check();
        assert_eq!(report.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_monitor_history_accumulates() {
        let m = make_monitor();
        m.periodic_check();
        m.periodic_check();
        m.periodic_check();
        assert_eq!(m.history(10).len(), 3);
    }

    #[test]
    fn test_monitor_history_cap() {
        let config = MonitorConfig {
            history_depth: 3,
            rss_warn_bytes: 0,
            queue_warn_depth: 0,
            max_clients_warn: 0,
            ..Default::default()
        };
        let m = HealthMonitor::new(config, DaemonCounters::new());
        for _ in 0..5 {
            m.periodic_check();
        }
        assert_eq!(m.history(10).len(), 3);
    }

    #[test]
    fn test_monitor_latest_report() {
        let m = make_monitor();
        assert!(m.latest_report().is_none());
        m.periodic_check();
        assert!(m.latest_report().is_some());
    }

    #[test]
    fn test_monitor_check_sequence() {
        let m = make_monitor();
        let r0 = m.periodic_check();
        let r1 = m.periodic_check();
        assert!(r1.check_number > r0.check_number);
    }

    // ── DaemonCounters ────────────────────────────────────────────────────────

    #[test]
    fn test_counters_client_connect_disconnect() {
        let c = DaemonCounters::new();
        c.client_connected();
        c.client_connected();
        let (clients, _, _) = c.read();
        assert_eq!(clients, 2);
        c.client_disconnected();
        let (clients, _, _) = c.read();
        assert_eq!(clients, 1);
    }

    #[test]
    fn test_counters_queue() {
        let c = DaemonCounters::new();
        c.enqueue();
        c.enqueue();
        c.dequeue();
        let (_, q, _) = c.read();
        assert_eq!(q, 1);
    }

    #[test]
    fn test_counters_no_underflow() {
        let c = DaemonCounters::new();
        c.client_disconnected(); // already 0
        let (clients, _, _) = c.read();
        assert_eq!(clients, 0);
    }

    // ── HealthReport helpers ──────────────────────────────────────────────────

    #[test]
    fn test_report_failing_probes() {
        let m = make_monitor();
        m.add_probe("x", false, || ProbeResult::fail("x", "bad", 0));
        m.add_probe("y", false, || ProbeResult::pass("y", "ok", 0));
        let report = m.periodic_check();
        let failing = report.failing_probes();
        assert_eq!(failing, vec!["x"]);
    }

    #[test]
    fn test_report_summary_all_pass() {
        let m = make_monitor();
        let report = m.periodic_check();
        assert!(report.summary().contains("healthy") || report.summary().contains("passed"));
    }

    #[test]
    fn test_report_display() {
        let m = make_monitor();
        m.add_probe("p1", false, || ProbeResult::pass("p1", "fine", 1));
        let report = m.periodic_check();
        let text = report.to_string();
        assert!(text.contains("p1"));
    }

    // ── resource snapshot ─────────────────────────────────────────────────────

    #[test]
    fn test_resource_snapshot_contains_counters() {
        let counters = DaemonCounters::new();
        counters.client_connected();
        counters.enqueue();
        let config = MonitorConfig {
            rss_warn_bytes: 0,
            queue_warn_depth: 0,
            max_clients_warn: 0,
            ..Default::default()
        };
        let m = HealthMonitor::new(config, counters);
        let report = m.periodic_check();
        assert_eq!(report.resources.connected_clients, 1);
        assert_eq!(report.resources.queue_depth, 1);
    }
}
