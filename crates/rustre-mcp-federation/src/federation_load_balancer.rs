//! MCP federation load balancer: `FederationLoadBalancer`, `LoadStrategy`,
//! `ServerHealth`, `select_server()`.
//!
//! Implements several load-balancing strategies (round-robin, least-latency,
//! weighted-random, consistent-hash) on top of a pool of backend servers.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

// ── LoadStrategy ──────────────────────────────────────────────────────────────

/// Strategy used by the load balancer to pick a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoadStrategy {
    /// Distribute requests evenly in rotation.
    RoundRobin,
    /// Send each request to the server with the lowest current latency.
    LeastLatency,
    /// Choose a server pseudo-randomly weighted by `ServerHealth::weight`.
    WeightedRandom,
    /// Consistent hashing: same tool name always goes to the same server.
    ConsistentHash,
    /// Always pick the server with the lowest error rate.
    LeastErrors,
}

impl fmt::Display for LoadStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::RoundRobin => "round-robin",
            Self::LeastLatency => "least-latency",
            Self::WeightedRandom => "weighted-random",
            Self::ConsistentHash => "consistent-hash",
            Self::LeastErrors => "least-errors",
        };
        f.write_str(s)
    }
}

// ── ServerHealth ──────────────────────────────────────────────────────────────

/// Runtime health and telemetry for a single backend server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHealth {
    /// Server identifier.
    pub server_id: String,
    /// Whether the server is accepting requests.
    pub available: bool,
    /// Total requests dispatched to this server.
    pub total_requests: u64,
    /// Total successful responses.
    pub total_successes: u64,
    /// Total failed responses (timeouts, errors).
    pub total_errors: u64,
    /// Exponential moving average of response latency in milliseconds.
    pub avg_latency_ms: f64,
    /// Current number of in-flight requests.
    pub in_flight: u32,
    /// Relative weight for weighted-random selection (default: 100).
    pub weight: u32,
    /// Consecutive health-check failures since last recovery.
    pub consecutive_failures: u32,
    /// Unix timestamp (seconds) of the last successful response.
    pub last_success_at: u64,
    /// Unix timestamp (seconds) of the last failure.
    pub last_failure_at: u64,
    /// Endpoint URL.
    pub endpoint: String,
}

impl ServerHealth {
    /// Construct a new healthy server.
    #[must_use]
    pub fn new(server_id: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            server_id: server_id.into(),
            endpoint: endpoint.into(),
            available: true,
            total_requests: 0,
            total_successes: 0,
            total_errors: 0,
            avg_latency_ms: 0.0,
            in_flight: 0,
            weight: 100,
            consecutive_failures: 0,
            last_success_at: 0,
            last_failure_at: 0,
        }
    }

    /// Return the error rate in [0.0, 1.0].
    #[must_use]
    pub fn error_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.total_errors as f64 / self.total_requests as f64
        }
    }

    /// Return the success rate in [0.0, 1.0].
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        1.0 - self.error_rate()
    }

    /// A composite score for ranking (lower is better).
    ///
    /// Score = avg_latency_ms * (1 + 5 * error_rate)
    #[must_use]
    pub fn composite_score(&self) -> f64 {
        if !self.available {
            return f64::MAX;
        }
        let lat = if self.avg_latency_ms == 0.0 { 1.0 } else { self.avg_latency_ms };
        lat * (1.0 + 5.0 * self.error_rate())
    }

    /// Record that a request has started (increment in-flight).
    pub fn start_request(&mut self) {
        self.total_requests += 1;
        self.in_flight = self.in_flight.saturating_add(1);
    }

    /// Record a successful response.
    pub fn record_success(&mut self, latency_ms: f64) {
        self.in_flight = self.in_flight.saturating_sub(1);
        self.total_successes += 1;
        self.consecutive_failures = 0;
        // EMA α = 0.1
        self.avg_latency_ms = 0.9 * self.avg_latency_ms + 0.1 * latency_ms;
        self.last_success_at = unix_now();
    }

    /// Record a failed response.
    pub fn record_failure(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
        self.total_errors += 1;
        self.consecutive_failures += 1;
        self.last_failure_at = unix_now();
        // After 5 consecutive failures, mark unavailable.
        if self.consecutive_failures >= 5 {
            self.available = false;
        }
    }

    /// Attempt to recover an unavailable server.
    pub fn try_recover(&mut self) {
        self.available = true;
        self.consecutive_failures = 0;
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs()
}

impl fmt::Display for ServerHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.available { "UP" } else { "DOWN" };
        write!(
            f,
            "[{status}] {} lat={:.1}ms err={:.1}% in_flight={}",
            self.server_id,
            self.avg_latency_ms,
            self.error_rate() * 100.0,
            self.in_flight
        )
    }
}

// ── BalancerError ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BalancerError {
    /// No servers are registered.
    NoServers,
    /// All servers are marked unavailable.
    AllServersDown,
    /// The requested server ID was not found.
    ServerNotFound(String),
}

impl fmt::Display for BalancerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoServers => write!(f, "no servers registered"),
            Self::AllServersDown => write!(f, "all servers are unavailable"),
            Self::ServerNotFound(id) => write!(f, "server '{id}' not found"),
        }
    }
}

impl std::error::Error for BalancerError {}

// ── FederationLoadBalancer ────────────────────────────────────────────────────

/// Load balancer for MCP federation backend servers.
#[derive(Debug)]
pub struct FederationLoadBalancer {
    inner: Arc<Mutex<BalancerInner>>,
}

#[derive(Debug)]
struct BalancerInner {
    servers: Vec<ServerHealth>,
    strategy: LoadStrategy,
    rr_index: usize,
    /// Counter used as a simple pseudo-random seed.
    rng_state: u64,
}

impl BalancerInner {
    fn available_servers(&self) -> Vec<usize> {
        self.servers
            .iter()
            .enumerate()
            .filter(|(_, s)| s.available)
            .map(|(i, _)| i)
            .collect()
    }

    /// Cheap xorshift64 pseudo-random number generator.
    fn next_random(&mut self) -> u64 {
        let mut x = self.rng_state.wrapping_add(1);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng_state = x;
        x
    }
}

impl FederationLoadBalancer {
    /// Construct a new load balancer with the given strategy.
    #[must_use]
    pub fn new(strategy: LoadStrategy) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BalancerInner {
                servers: Vec::new(),
                strategy,
                rr_index: 0,
                rng_state: 0xDEAD_BEEF_CAFE_1234,
            })),
        }
    }

    /// Add a server to the pool.
    pub fn add_server(&self, health: ServerHealth) {
        self.inner.lock().servers.push(health);
    }

    /// Remove a server by ID.
    pub fn remove_server(&self, server_id: &str) {
        self.inner.lock().servers.retain(|s| s.server_id != server_id);
    }

    /// Change the balancing strategy at runtime.
    pub fn set_strategy(&self, strategy: LoadStrategy) {
        self.inner.lock().strategy = strategy;
    }

    /// Return a snapshot of all server health records.
    #[must_use]
    pub fn servers(&self) -> Vec<ServerHealth> {
        self.inner.lock().servers.clone()
    }

    /// Mark a server available or unavailable.
    pub fn set_available(&self, server_id: &str, available: bool) {
        let mut g = self.inner.lock();
        if let Some(s) = g.servers.iter_mut().find(|s| s.server_id == server_id) {
            if available {
                s.try_recover();
            } else {
                s.available = false;
            }
        }
    }

    /// Record outcome for a server.
    pub fn record_outcome(&self, server_id: &str, latency_ms: f64, is_error: bool) {
        let mut g = self.inner.lock();
        if let Some(s) = g.servers.iter_mut().find(|s| s.server_id == server_id) {
            if is_error {
                s.record_failure();
            } else {
                s.record_success(latency_ms);
            }
        }
    }

    /// Return the current strategy.
    #[must_use]
    pub fn strategy(&self) -> LoadStrategy {
        self.inner.lock().strategy
    }

    /// Return a summary string of the pool state.
    #[must_use]
    pub fn summary(&self) -> String {
        let g = self.inner.lock();
        let up = g.servers.iter().filter(|s| s.available).count();
        format!("strategy={} servers={} up={}", g.strategy, g.servers.len(), up)
    }
}

// ── select_server ─────────────────────────────────────────────────────────────

/// Select a backend server for the given `tool_name` using the balancer's
/// configured strategy.
///
/// Returns the `server_id` and `endpoint` of the chosen server, or a
/// [`BalancerError`] if no healthy server is available.
pub fn select_server(
    balancer: &FederationLoadBalancer,
    tool_name: &str,
) -> Result<(String, String), BalancerError> {
    let mut g = balancer.inner.lock();

    if g.servers.is_empty() {
        return Err(BalancerError::NoServers);
    }

    let available: Vec<usize> = g.available_servers();
    if available.is_empty() {
        return Err(BalancerError::AllServersDown);
    }

    let chosen_idx = match g.strategy {
        LoadStrategy::RoundRobin => {
            let idx = available[g.rr_index % available.len()];
            g.rr_index = g.rr_index.wrapping_add(1);
            idx
        }
        LoadStrategy::LeastLatency => {
            available
                .iter()
                .copied()
                .min_by(|&a, &b| {
                    g.servers[a]
                        .composite_score()
                        .partial_cmp(&g.servers[b].composite_score())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .unwrap()
        }
        LoadStrategy::WeightedRandom => {
            let total_weight: u64 = available.iter().map(|&i| g.servers[i].weight as u64).sum();
            if total_weight == 0 {
                available[0]
            } else {
                let pick = g.next_random() % total_weight;
                let mut cumulative = 0u64;
                let mut chosen = available[0];
                for &i in &available {
                    cumulative += g.servers[i].weight as u64;
                    if pick < cumulative {
                        chosen = i;
                        break;
                    }
                }
                chosen
            }
        }
        LoadStrategy::ConsistentHash => {
            // Simple FNV-1a hash of tool_name, mapped into available pool.
            let hash = fnv1a(tool_name.as_bytes());
            available[hash as usize % available.len()]
        }
        LoadStrategy::LeastErrors => {
            available
                .iter()
                .copied()
                .min_by(|&a, &b| {
                    g.servers[a]
                        .error_rate()
                        .partial_cmp(&g.servers[b].error_rate())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .unwrap()
        }
    };

    // Mark in-flight.
    g.servers[chosen_idx].start_request();

    let s = &g.servers[chosen_idx];
    Ok((s.server_id.clone(), s.endpoint.clone()))
}

/// Like [`select_server`], but also returns the monotonic wall time taken by
/// the selection (using [`Instant`]). Useful for back-pressure heuristics.
pub fn select_server_timed(
    balancer: &FederationLoadBalancer,
    tool_name: &str,
) -> (Result<(String, String), BalancerError>, Duration) {
    let started = Instant::now();
    let res = select_server(balancer, tool_name);
    (res, started.elapsed())
}

/// Group the current in-flight load by server ID. The returned map is keyed by
/// `server_id` and gives the current in-flight request count for each.
pub fn in_flight_by_server(balancer: &FederationLoadBalancer) -> HashMap<String, u32> {
    let g = balancer.inner.lock();
    g.servers
        .iter()
        .map(|s| (s.server_id.clone(), s.in_flight))
        .collect()
}

/// FNV-1a 64-bit hash.
fn fnv1a(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_balancer(n: usize) -> FederationLoadBalancer {
        let b = FederationLoadBalancer::new(LoadStrategy::RoundRobin);
        for i in 0..n {
            b.add_server(ServerHealth::new(format!("srv{i}"), format!("http://localhost:{}", 9000 + i)));
        }
        b
    }

    #[test]
    fn test_select_round_robin() {
        let b = make_balancer(3);
        let ids: Vec<_> = (0..6).map(|_| select_server(&b, "tool").unwrap().0).collect();
        assert_eq!(ids[0], ids[3]);
        assert_eq!(ids[1], ids[4]);
        assert_eq!(ids[2], ids[5]);
    }

    #[test]
    fn test_select_no_servers() {
        let b = FederationLoadBalancer::new(LoadStrategy::RoundRobin);
        assert!(matches!(select_server(&b, "tool"), Err(BalancerError::NoServers)));
    }

    #[test]
    fn test_select_all_down() {
        let b = make_balancer(2);
        b.set_available("srv0", false);
        b.set_available("srv1", false);
        assert!(matches!(select_server(&b, "tool"), Err(BalancerError::AllServersDown)));
    }

    #[test]
    fn test_select_least_latency() {
        let b = FederationLoadBalancer::new(LoadStrategy::LeastLatency);
        b.add_server(ServerHealth::new("fast", "http://fast"));
        b.add_server(ServerHealth::new("slow", "http://slow"));
        b.record_outcome("slow", 500.0, false);
        let (id, _) = select_server(&b, "tool").unwrap();
        // fast has 0ms latency, slow has 50ms avg → fast wins.
        assert_eq!(id, "fast");
    }

    #[test]
    fn test_select_consistent_hash_same_tool() {
        let b = FederationLoadBalancer::new(LoadStrategy::ConsistentHash);
        b.add_server(ServerHealth::new("srv0", "http://0"));
        b.add_server(ServerHealth::new("srv1", "http://1"));
        let id1 = select_server(&b, "decompile").unwrap().0;
        let id2 = select_server(&b, "decompile").unwrap().0;
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_server_health_error_rate() {
        let mut h = ServerHealth::new("s", "http://s");
        h.record_success(10.0);
        h.record_failure();
        assert!((h.error_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_server_becomes_unavailable_after_5_failures() {
        let mut h = ServerHealth::new("s", "http://s");
        for _ in 0..5 {
            h.record_failure();
        }
        assert!(!h.available);
    }

    #[test]
    fn test_server_recovery() {
        let b = make_balancer(1);
        b.set_available("srv0", false);
        b.set_available("srv0", true);
        assert!(select_server(&b, "tool").is_ok());
    }

    #[test]
    fn test_in_flight_incremented() {
        let b = make_balancer(1);
        select_server(&b, "tool").unwrap();
        let servers = b.servers();
        assert_eq!(servers[0].in_flight, 1);
    }

    #[test]
    fn test_summary() {
        let b = make_balancer(2);
        let s = b.summary();
        assert!(s.contains("servers=2"));
    }

    #[test]
    fn test_fnv1a_deterministic() {
        assert_eq!(fnv1a(b"hello"), fnv1a(b"hello"));
        assert_ne!(fnv1a(b"hello"), fnv1a(b"world"));
    }
}
